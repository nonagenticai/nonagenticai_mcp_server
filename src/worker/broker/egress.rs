//! Egress for tenant-registered sources: resolve, validate every address, pin the connection.
//!
//! Port of the reference `src/broker/egress.py` (plus the `RateLimitedError`/`SourceLimiter`
//! names it defines there, which live in [`super::limits`] in this port and are re-exported
//! below). The reference pins a connection by replacing httpx's network backend; reqwest has no
//! pluggable backend, so the equivalent mechanism is
//! [`reqwest::ClientBuilder::resolve`]: a client is built for **one** host and **one** already
//! validated [`SocketAddr`], and reqwest consults that override before the system resolver. The
//! client therefore cannot re-resolve the host: the only address it can dial is the one the
//! policy validated. TLS SNI, the certificate name and the `Host` header stay on the hostname,
//! exactly as in the reference.
//!
//! Every tenant client is one per `(host, address, ca_file)` behind a mutex
//! ([`PinnedClients`]), mirroring the reference's "validate once, open only validated
//! addresses". Where a host has several validated answers the caller gets one client per
//! answer, in order, and may retry the next — the reference's `PinnedBackend.connect_tcp`
//! loop, without a second DNS answer ever being consulted.
//!
//! Two reference behaviours have no reqwest counterpart and are documented at their function:
//! a connection-count pool cap, and the `httpx` redirect refusal becoming a `reqwest` redirect
//! policy error.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock, Mutex};

use async_trait::async_trait;
use regex::Regex;
use reqwest::redirect::Policy as RedirectPolicy;
use reqwest::{Certificate, Client, ClientBuilder};
use thiserror::Error;

use crate::config::WorkerSettings;

pub use super::limits::{RateLimitedError, SourceLimiter};

/// The ports a tenant source may use when nothing narrower is configured (`config.py:160`).
pub const DEFAULT_PORTS: [u16; 1] = [443];
/// Extra CIDRs tenant egress must refuse (`config.py:162` defaults to none; non-global
/// addresses are refused by [`address_allowed`] regardless).
pub const DEFAULT_DENY_CIDRS: [&str; 0] = [];

/// The metadata endpoints a tenant may never reach (`egress.py:34-37`).
const METADATA_ADDRESSES: [IpAddr; 5] = [
    IpAddr::V4(Ipv4Addr::new(169, 254, 169, 254)),
    IpAddr::V4(Ipv4Addr::new(169, 254, 170, 2)),
    IpAddr::V4(Ipv4Addr::new(100, 100, 100, 200)),
    IpAddr::V4(Ipv4Addr::new(192, 0, 0, 192)),
    IpAddr::V6(Ipv6Addr::new(0xfd00, 0xec2, 0, 0, 0, 0, 0, 0x254)),
];

/// Hostnames a tenant may never register (`sources/models.py:123`).
const INTERNAL_SUFFIXES: [&str; 6] = [
    ".local",
    ".internal",
    ".svc",
    ".cluster.local",
    ".localhost",
    ".lan",
];

/// The longest DNS name, in code points, as Python's `len()` counts it.
const MAX_HOSTNAME: usize = 253;

/// A public DNS label sequence (`egress.py:46`), applied with `fullmatch` semantics.
static HOSTNAME: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?)+\z",
    )
    .expect("hostname pattern is valid")
});

/// Parse an address the way `ipaddress.ip_address` does after stripping a zone and brackets.
pub fn parse_address(text: &str) -> Option<IpAddr> {
    let without_zone = text.split('%').next().unwrap_or(text);
    without_zone
        .trim_matches(|character| character == '[' || character == ']')
        .parse()
        .ok()
}

/// One IPv4 or IPv6 network, parsed like `ipaddress.ip_network(value, strict=False)`: host
/// bits are masked off rather than refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNetwork {
    network: IpAddr,
    prefix: u8,
}

impl IpNetwork {
    /// Parse `address/prefix` (a bare address is a full-length prefix).
    pub fn parse(text: &str) -> Result<Self, EgressError> {
        let (address, prefix) = match text.split_once('/') {
            Some((address, prefix)) => (address, Some(prefix)),
            None => (text, None),
        };
        let network: IpAddr = address.parse().map_err(|_| EgressError::SsrfBlocked)?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix {
            Some(prefix) => prefix.parse::<u8>().map_err(|_| EgressError::SsrfBlocked)?,
            None => maximum,
        };
        if prefix > maximum {
            return Err(EgressError::SsrfBlocked);
        }
        Ok(Self { network, prefix })
    }

    /// Whether `address` falls inside this network; families never match cross-family.
    pub fn contains(&self, address: IpAddr) -> bool {
        match (self.network, address) {
            (IpAddr::V4(network), IpAddr::V4(address)) => {
                let mask = v4_mask(self.prefix);
                (u32::from(network) & mask) == (u32::from(address) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(address)) => {
                let mask = v6_mask(self.prefix);
                (u128::from(network) & mask) == (u128::from(address) & mask)
            }
            _ => false,
        }
    }
}

/// A prefix mask with the low bits cleared; a zero prefix matches everything.
fn v4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - u32::from(prefix))
    }
}

/// The IPv6 equivalent; `prefix` is never above 128.
fn v6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - u32::from(prefix))
    }
}

const fn net4(a: u8, b: u8, c: u8, d: u8, prefix: u8) -> IpNetwork {
    IpNetwork {
        network: IpAddr::V4(Ipv4Addr::new(a, b, c, d)),
        prefix,
    }
}

const fn net6(segments: [u16; 8], prefix: u8) -> IpNetwork {
    IpNetwork {
        network: IpAddr::V6(Ipv6Addr::new(
            segments[0],
            segments[1],
            segments[2],
            segments[3],
            segments[4],
            segments[5],
            segments[6],
            segments[7],
        )),
        prefix,
    }
}

// `ipaddress`'s IPv4 tables, Python 3.14 (`IPv4Address._constants`).
const V4_PRIVATE: [IpNetwork; 14] = [
    net4(0, 0, 0, 0, 8),
    net4(10, 0, 0, 0, 8),
    net4(127, 0, 0, 0, 8),
    net4(169, 254, 0, 0, 16),
    net4(172, 16, 0, 0, 12),
    net4(192, 0, 0, 0, 24),
    net4(192, 0, 0, 170, 31),
    net4(192, 0, 2, 0, 24),
    net4(192, 168, 0, 0, 16),
    net4(198, 18, 0, 0, 15),
    net4(198, 51, 100, 0, 24),
    net4(203, 0, 113, 0, 24),
    net4(240, 0, 0, 0, 4),
    net4(255, 255, 255, 255, 32),
];
const V4_PRIVATE_EXCEPTIONS: [IpNetwork; 2] = [net4(192, 0, 0, 9, 32), net4(192, 0, 0, 10, 32)];
/// Neither private nor global: the IANA shared address space (`IPv4Address._public_network`).
const V4_SHARED: IpNetwork = net4(100, 64, 0, 0, 10);
const V4_MULTICAST: IpNetwork = net4(224, 0, 0, 0, 4);
const V4_LOOPBACK: IpNetwork = net4(127, 0, 0, 0, 8);
const V4_LINK_LOCAL: IpNetwork = net4(169, 254, 0, 0, 16);
const V4_RESERVED: IpNetwork = net4(240, 0, 0, 0, 4);

// `ipaddress`'s IPv6 tables, Python 3.14 (`IPv6Address._constants`).
const V6_PRIVATE: [IpNetwork; 11] = [
    net6([0, 0, 0, 0, 0, 0, 0, 1], 128),
    net6([0, 0, 0, 0, 0, 0, 0, 0], 128),
    net6([0, 0, 0, 0, 0, 0xffff, 0, 0], 96),
    net6([0x64, 0xff9b, 1, 0, 0, 0, 0, 0], 48),
    net6([0x100, 0, 0, 0, 0, 0, 0, 0], 64),
    net6([0x2001, 0, 0, 0, 0, 0, 0, 0], 23),
    net6([0x2001, 0xdb8, 0, 0, 0, 0, 0, 0], 32),
    net6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16),
    net6([0x3fff, 0, 0, 0, 0, 0, 0, 0], 20),
    net6([0xfc00, 0, 0, 0, 0, 0, 0, 0], 7),
    net6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10),
];
const V6_PRIVATE_EXCEPTIONS: [IpNetwork; 6] = [
    net6([0x2001, 1, 0, 0, 0, 0, 0, 1], 128),
    net6([0x2001, 1, 0, 0, 0, 0, 0, 2], 128),
    net6([0x2001, 3, 0, 0, 0, 0, 0, 0], 32),
    net6([0x2001, 4, 0x112, 0, 0, 0, 0, 0], 48),
    net6([0x2001, 0x20, 0, 0, 0, 0, 0, 0], 28),
    net6([0x2001, 0x30, 0, 0, 0, 0, 0, 0], 28),
];
const V6_RESERVED: [IpNetwork; 15] = [
    net6([0, 0, 0, 0, 0, 0, 0, 0], 8),
    net6([0x100, 0, 0, 0, 0, 0, 0, 0], 8),
    net6([0x200, 0, 0, 0, 0, 0, 0, 0], 7),
    net6([0x400, 0, 0, 0, 0, 0, 0, 0], 6),
    net6([0x800, 0, 0, 0, 0, 0, 0, 0], 5),
    net6([0x1000, 0, 0, 0, 0, 0, 0, 0], 4),
    net6([0x4000, 0, 0, 0, 0, 0, 0, 0], 3),
    net6([0x6000, 0, 0, 0, 0, 0, 0, 0], 3),
    net6([0x8000, 0, 0, 0, 0, 0, 0, 0], 3),
    net6([0xa000, 0, 0, 0, 0, 0, 0, 0], 3),
    net6([0xc000, 0, 0, 0, 0, 0, 0, 0], 3),
    net6([0xe000, 0, 0, 0, 0, 0, 0, 0], 4),
    net6([0xf000, 0, 0, 0, 0, 0, 0, 0], 5),
    net6([0xf800, 0, 0, 0, 0, 0, 0, 0], 6),
    net6([0xfe00, 0, 0, 0, 0, 0, 0, 0], 9),
];
const V6_MULTICAST: IpNetwork = net6([0xff00, 0, 0, 0, 0, 0, 0, 0], 8);
const V6_LOOPBACK: IpNetwork = net6([0, 0, 0, 0, 0, 0, 0, 1], 128);
const V6_LINK_LOCAL: IpNetwork = net6([0xfe80, 0, 0, 0, 0, 0, 0, 0], 10);

/// Tunnelling / translation prefixes (`egress.py:39-44`).
const NAT64: IpNetwork = net6([0x64, 0xff9b, 0, 0, 0, 0, 0, 0], 96);
const TEREDO: IpNetwork = net6([0x2001, 0, 0, 0, 0, 0, 0, 0], 32);
const SIXTOFOUR: IpNetwork = net6([0x2002, 0, 0, 0, 0, 0, 0, 0], 16);
const V4_COMPAT: IpNetwork = net6([0, 0, 0, 0, 0, 0, 0, 0], 96);

/// Deprecated ranges the stdlib still reports as global (`egress.py:45`).
const DEPRECATED: [IpNetwork; 2] = [
    net6([0xfec0, 0, 0, 0, 0, 0, 0, 0], 10),
    net4(192, 88, 99, 0, 24),
];

/// The destination (host, port, address, scheme or redirect) is refused. `reason` is the fixed
/// trace kind, and the message never names the target.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum EgressError {
    /// `ssrf_blocked`: the hostname, port, scheme or resolved address is not permitted.
    #[error("ssrf blocked")]
    SsrfBlocked,
    /// `redirect`: an upstream answered 3xx, which a tenant call never follows.
    #[error("redirect")]
    Redirect,
    /// `transport`: resolution failed, or nothing usable came back.
    #[error("transport")]
    Transport,
}

impl EgressError {
    /// The reference's trace `reason` value.
    pub const fn reason(self) -> &'static str {
        match self {
            Self::SsrfBlocked => "ssrf_blocked",
            Self::Redirect => "redirect",
            Self::Transport => "transport",
        }
    }
}

/// An injectable resolver (`egress.py:32,127-129`). A lookup that cannot run returns an empty
/// answer, which [`EgressPolicy::validated`] refuses as a transport failure.
#[async_trait]
pub trait Resolver: Send + Sync {
    /// Every address the host currently resolves to.
    async fn resolve(&self, host: &str, port: u16) -> Vec<IpAddr>;
}

/// The system resolver (the default), via tokio's blocking-pool `getaddrinfo`.
pub struct SystemResolver;

#[async_trait]
impl Resolver for SystemResolver {
    async fn resolve(&self, host: &str, port: u16) -> Vec<IpAddr> {
        match tokio::net::lookup_host((host, port)).await {
            Ok(addresses) => addresses.map(|address| address.ip()).collect(),
            Err(_) => Vec::new(),
        }
    }
}

fn any(networks: &[IpNetwork], address: IpAddr) -> bool {
    networks.iter().any(|network| network.contains(address))
}

fn private_v4(address: Ipv4Addr) -> bool {
    let address = IpAddr::V4(address);
    any(&V4_PRIVATE, address) && !any(&V4_PRIVATE_EXCEPTIONS, address)
}

fn global_v4(address: Ipv4Addr) -> bool {
    !V4_SHARED.contains(IpAddr::V4(address)) && !private_v4(address)
}

fn private_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return private_v4(mapped);
    }
    let address = IpAddr::V6(address);
    any(&V6_PRIVATE, address) && !any(&V6_PRIVATE_EXCEPTIONS, address)
}

fn global_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return global_v4(mapped);
    }
    !private_v6(address)
}

fn reserved_v4(address: Ipv4Addr) -> bool {
    V4_RESERVED.contains(IpAddr::V4(address))
}

fn reserved_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return reserved_v4(mapped);
    }
    any(&V6_RESERVED, IpAddr::V6(address))
}

/// The IPv4 addresses an IPv6 address carries (`egress.py:65-79`): mapped, NAT64,
/// IPv4-compatible, 6to4 and Teredo. An embedded private address poisons the address.
pub fn embedded_addresses(address: IpAddr) -> Vec<IpAddr> {
    let IpAddr::V6(ip) = address else {
        return Vec::new();
    };
    let bits = u128::from(ip);
    let mut found = Vec::new();
    if let Some(mapped) = ip.to_ipv4_mapped() {
        found.push(IpAddr::V4(mapped));
    }
    if NAT64.contains(address) || V4_COMPAT.contains(address) {
        found.push(IpAddr::V4(Ipv4Addr::from((bits & 0xffff_ffff) as u32)));
    }
    if SIXTOFOUR.contains(address) {
        found.push(IpAddr::V4(Ipv4Addr::from((bits >> 80) as u32)));
    }
    if TEREDO.contains(address) {
        // Bytes 4..8 are the server; the last four bytes are the client, complemented.
        found.push(IpAddr::V4(Ipv4Addr::from((bits >> 64) as u32)));
        found.push(IpAddr::V4(Ipv4Addr::from((bits as u32) ^ 0xffff_ffff)));
    }
    found
}

/// Whether a connection to `address` is permitted: global unicast only, outside `deny`, and
/// with every address it embeds also permitted (`egress.py:82-108`).
pub fn address_allowed(address: IpAddr, deny: &[IpNetwork]) -> bool {
    if METADATA_ADDRESSES.contains(&address) {
        return false;
    }
    if embedded_addresses(address)
        .into_iter()
        .any(|embedded| !address_allowed(embedded, deny))
    {
        return false;
    }
    let (global, private, reserved, multicast, loopback, link_local, unspecified) = match address {
        IpAddr::V4(ip) => (
            global_v4(ip),
            private_v4(ip),
            reserved_v4(ip),
            V4_MULTICAST.contains(address),
            V4_LOOPBACK.contains(address),
            V4_LINK_LOCAL.contains(address),
            ip == Ipv4Addr::UNSPECIFIED,
        ),
        IpAddr::V6(ip) => (
            global_v6(ip),
            private_v6(ip),
            reserved_v6(ip),
            V6_MULTICAST.contains(address),
            V6_LOOPBACK.contains(address),
            V6_LINK_LOCAL.contains(address),
            ip == Ipv6Addr::UNSPECIFIED,
        ),
    };
    if !global || multicast || unspecified || loopback || link_local || private || reserved {
        return false;
    }
    if any(&DEPRECATED, address) {
        return false;
    }
    // The tunnelling prefixes carry their own target, which was checked above; the prefix
    // itself is never an address we should talk to directly.
    if address.is_ipv6()
        && (V4_COMPAT.contains(address)
            || NAT64.contains(address)
            || TEREDO.contains(address)
            || SIXTOFOUR.contains(address))
    {
        return false;
    }
    !any(deny, address)
}

/// Address-like hosts (`sources/guard.py:43-52`), replicated here because the reference helper
/// is private to its module. Numeric last labels are resolved as addresses by some stacks.
fn is_ip_literal(host: &str) -> bool {
    let bare = host.trim_matches(|character| character == '[' || character == ']');
    if bare.parse::<IpAddr>().is_ok() {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or(host);
    last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x")
}

/// A public DNS name or [`EgressError::SsrfBlocked`] (`egress.py:111-124`).
///
/// Applied at registration and again on every call. The returned name is the reference's
/// normalized form (lowercased, trailing dots removed).
pub fn check_hostname(host: &str) -> Result<String, EgressError> {
    let lowered = host.to_lowercase();
    let name = lowered.trim_end_matches('.');
    if name.is_empty()
        || name.chars().count() > MAX_HOSTNAME
        || is_ip_literal(name)
        || !name.contains('.')
        || !HOSTNAME.is_match(name)
        || name == "localhost"
        || INTERNAL_SUFFIXES
            .iter()
            .any(|suffix| name.ends_with(suffix))
    {
        Err(EgressError::SsrfBlocked)
    } else {
        Ok(name.to_owned())
    }
}

/// The address predicate a policy applies. The production predicate is [`address_allowed`];
/// the seam exists so a test can place a listener on loopback (which the real predicate
/// correctly refuses) and still exercise the pin. Tenant input never selects it.
pub type AddressCheck = Arc<dyn Fn(IpAddr, &[IpNetwork]) -> bool + Send + Sync>;

/// The egress policy for tenant sources (`egress.py:132-165`).
pub struct EgressPolicy {
    ports: Vec<u16>,
    deny: Vec<IpNetwork>,
    resolver: Arc<dyn Resolver>,
    check: AddressCheck,
}

impl EgressPolicy {
    /// Build a policy from an explicit port allow-list and extra deny networks.
    pub fn new(
        ports: &[u16],
        deny_cidrs: &[&str],
        resolver: Arc<dyn Resolver>,
    ) -> Result<Self, EgressError> {
        let deny = deny_cidrs
            .iter()
            .map(|cidr| IpNetwork::parse(cidr))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            ports: ports.to_vec(),
            deny,
            resolver,
            check: Arc::new(address_allowed),
        })
    }

    /// The policy from service settings (`egress.py:143-145`).
    ///
    /// The reference reads `builder_allowed_ports` and `builder_deny_cidrs` from its settings.
    /// This port's [`WorkerSettings`] does not carry those fields yet (config is not this
    /// slice's file), so the reference's documented defaults are used: port 443 only, no extra
    /// deny networks. The composition root uses [`Self::new`] when the settings land; a
    /// malformed deny CIDR can never be silently ignored because it is parsed here, fail-closed.
    pub fn from_settings(_settings: &WorkerSettings, resolver: Arc<dyn Resolver>) -> Self {
        Self::new(&DEFAULT_PORTS, &DEFAULT_DENY_CIDRS, resolver)
            .expect("the default egress policy is valid")
    }

    /// Replace the address predicate (a test seam; production uses [`address_allowed`]).
    pub fn with_address_check(mut self, check: AddressCheck) -> Self {
        self.check = check;
        self
    }

    /// Every resolved address, all of which pass the policy (`egress.py:147-165`). One bad
    /// answer poisons the whole set: a DNS answer that includes a private address is refused
    /// entirely rather than filtered.
    pub async fn validated(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, EgressError> {
        check_hostname(host)?;
        if !self.ports.contains(&port) {
            return Err(EgressError::SsrfBlocked);
        }
        let answers = self.resolver.resolve(host, port).await;
        let mut addresses: Vec<IpAddr> = Vec::with_capacity(answers.len());
        for address in answers {
            if !(self.check)(address, &self.deny) {
                return Err(EgressError::SsrfBlocked);
            }
            if !addresses.contains(&address) {
                addresses.push(address);
            }
        }
        if addresses.is_empty() {
            return Err(EgressError::Transport);
        }
        Ok(addresses
            .into_iter()
            .map(|address| SocketAddr::new(address, port))
            .collect())
    }
}

/// The reference's `httpx.Limits(max_connections, max_keepalive_connections, keepalive_expiry)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PoolLimits {
    /// Total connections the pool may open. reqwest has no equivalent cap; the caller's
    /// in-flight bound (`api_max_inflight` / [`SourceLimiter`]) is what enforces this.
    pub max_connections: usize,
    /// Idle connections kept per host.
    pub max_keepalive_connections: usize,
    /// How long an idle connection is kept.
    pub keepalive_expiry: std::time::Duration,
}

impl Default for PoolLimits {
    fn default() -> Self {
        Self {
            max_connections: 64,
            max_keepalive_connections: 8,
            keepalive_expiry: std::time::Duration::from_secs(15),
        }
    }
}

/// The one client shape for tenant sources (`egress.py:243-252`): no redirect following, no
/// environment proxy, https only.
///
/// The reference's transport raises `EgressDeniedError("redirect")` on a 3xx; reqwest's custom
/// redirect policy returns the same refusal as a request error carrying [`EgressError::Redirect`]
/// (`reqwest::Error::is_redirect()` is true), so the Location is never followed.
///
/// The returned builder has no pin yet: egress pinning is per host and is installed by
/// [`PinnedClients`] with `ClientBuilder::resolve` **after** [`EgressPolicy::validated`].
pub fn tenant_client(_policy: &EgressPolicy, limits: Option<PoolLimits>) -> ClientBuilder {
    let limits = limits.unwrap_or_default();
    Client::builder()
        .redirect(RedirectPolicy::custom(|attempt| {
            attempt.error(EgressError::Redirect)
        }))
        .https_only(true)
        .no_proxy()
        .pool_max_idle_per_host(limits.max_keepalive_connections)
        .pool_idle_timeout(limits.keepalive_expiry)
}

/// One cache identity: the host, the validated address, and the CA bundle.
type PinnedKey = (String, SocketAddr, Option<PathBuf>);
/// The process-wide cache of pinned tenant clients.
type PinnedCache = HashMap<PinnedKey, Arc<PinnedClient>>;

/// One client per `(host, validated address, ca_file)`: the pin point.
///
/// The reference replaces the connection pool's network backend; here each client carries a
/// single `resolve` override, so reqwest cannot consult a second DNS answer. A host with
/// several validated addresses yields one client per address, in the resolver's order — the
/// caller may try the next on a connect failure, as `PinnedBackend.connect_tcp` does.
///
/// The raw [`Client`] is never handed out: [`PinnedClient::execute`] repeats the transport's
/// per-request checks (https, no userinfo, the pinned hostname, the pinned port), so this
/// client cannot be pointed at another destination either.
pub struct PinnedClients {
    policy: Arc<EgressPolicy>,
    limits: PoolLimits,
    cache: Mutex<PinnedCache>,
}

/// A tenant client pinned to exactly one validated address for one host and port.
pub struct PinnedClient {
    client: Client,
    /// The host as handed to `ClientBuilder::resolve`, lowercased (reqwest's override key).
    host: String,
    /// The validated port; a request naming another port is refused before any I/O.
    port: u16,
}

impl PinnedClient {
    /// Send one request after repeating the transport's per-request checks.
    ///
    /// A refusal happens before a byte is written; a redirect answer never comes back as a
    /// response because the client's redirect policy refuses to follow it.
    pub async fn execute(
        &self,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, EgressError> {
        let url = request.url();
        if url.scheme() != "https" || !url.username().is_empty() || url.password().is_some() {
            return Err(EgressError::SsrfBlocked);
        }
        let host = url.host_str().ok_or(EgressError::SsrfBlocked)?;
        check_hostname(host)?;
        // Exact (case-insensitive) match against the override key, trailing dot included:
        // `host.` is a different key to reqwest and would fall through to the system resolver.
        if host.to_ascii_lowercase() != self.host {
            return Err(EgressError::SsrfBlocked);
        }
        if url.port_or_known_default() != Some(self.port) {
            return Err(EgressError::SsrfBlocked);
        }
        let response = self.client.execute(request).await.map_err(|error| {
            if error.is_redirect() {
                EgressError::Redirect
            } else {
                EgressError::Transport
            }
        })?;
        if response.status().is_redirection() {
            return Err(EgressError::Redirect);
        }
        Ok(response)
    }
}

impl PinnedClients {
    /// A cache of pinned clients for one policy.
    pub fn new(policy: Arc<EgressPolicy>, limits: PoolLimits) -> Self {
        Self {
            policy,
            limits,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, PinnedCache> {
        self.cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    fn build(
        &self,
        host: &str,
        address: SocketAddr,
        ca_file: Option<&Path>,
    ) -> Result<PinnedClient, EgressError> {
        let mut builder = tenant_client(&self.policy, Some(self.limits));
        if let Some(path) = ca_file {
            builder = builder.tls_certs_only(root_certificates(path)?);
        }
        let client = builder
            .resolve(host, address)
            .build()
            .map_err(|_| EgressError::Transport)?;
        Ok(PinnedClient {
            client,
            host: host.to_ascii_lowercase(),
            port: address.port(),
        })
    }

    /// Validate `(host, port)` once and return one pinned client per validated address.
    pub async fn clients(
        &self,
        host: &str,
        port: u16,
        ca_file: Option<&Path>,
    ) -> Result<Vec<(SocketAddr, Arc<PinnedClient>)>, EgressError> {
        let addresses = self.policy.validated(host, port).await?;
        let cache_key_host = host.to_ascii_lowercase();
        let mut clients = Vec::with_capacity(addresses.len());
        for address in addresses {
            let key = (
                cache_key_host.clone(),
                address,
                ca_file.map(Path::to_path_buf),
            );
            let cached = self.cache().get(&key).cloned();
            let client = match cached {
                Some(client) => client,
                None => {
                    let built = Arc::new(self.build(host, address, ca_file)?);
                    self.cache().entry(key).or_insert(built).clone()
                }
            };
            clients.push((address, client));
        }
        Ok(clients)
    }
}

/// The CA certificates of one PEM bundle; a file that cannot be read or parsed is a transport
/// refusal, never a reason to fall back to the system roots.
fn root_certificates(path: &Path) -> Result<Vec<Certificate>, EgressError> {
    let pem = std::fs::read(path).map_err(|_| EgressError::Transport)?;
    Certificate::from_pem_bundle(&pem).map_err(|_| EgressError::Transport)
}

/// The platform client pool (`src/broker/client.py:148-159`): one pooled client per CA bundle,
/// destinations without a `ca_file` sharing the default. Never redirects, never uses the
/// environment proxy.
pub struct PlatformClients {
    limits: PoolLimits,
    cache: Mutex<HashMap<Option<PathBuf>, Arc<Client>>>,
}

impl PlatformClients {
    /// A cache of platform clients for one pool shape.
    pub fn new(limits: PoolLimits) -> Self {
        Self {
            limits,
            cache: Mutex::new(HashMap::new()),
        }
    }

    fn cache(&self) -> std::sync::MutexGuard<'_, HashMap<Option<PathBuf>, Arc<Client>>> {
        self.cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// The pooled client for `ca_file`; `None` is the default-trust client.
    pub fn client_for(&self, ca_file: Option<&Path>) -> Result<Arc<Client>, EgressError> {
        let key = ca_file.map(Path::to_path_buf);
        if let Some(client) = self.cache().get(&key).cloned() {
            return Ok(client);
        }
        let mut builder = Client::builder()
            .redirect(RedirectPolicy::none())
            .no_proxy()
            .pool_max_idle_per_host(self.limits.max_keepalive_connections)
            .pool_idle_timeout(self.limits.keepalive_expiry);
        if let Some(path) = ca_file {
            builder = builder.tls_certs_only(root_certificates(path)?);
        }
        let client = Arc::new(builder.build().map_err(|_| EgressError::Transport)?);
        Ok(self.cache().entry(key).or_insert(client).clone())
    }
}
