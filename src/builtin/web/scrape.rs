//! `web_scrape`: fetch one public web page through the internal webscraper service.
//!
//! Contract (webscraper_service `src/routers/scrape.py`): `POST {WEBSCRAPER_URL}/api/scrape/url`
//! with `{"url", "scraper_type", "timeout"}` -> `ScrapeResponse {url, final_url, title,
//! text_content, markdown_content, status, error, ...}`. Auth there is a licence token in
//! `X-Tenant-Id: Bearer` or a trusted-network (RFC1918) peer; `WEBSCRAPER_TOKEN` is sent when
//! set.
//!
//! The URL comes from an LLM, so it is checked here before the request leaves (the webscraper
//! has its own guard as well): http/https only, no credentials in the URL, and the host —
//! literal or every address it resolves to — must be a public address. The classification is
//! Python's `ipaddress.is_global` on the archive's Python 3.14: `is_global` is `not is_private`
//! by the IANA special-purpose registries, with the reference's two exceptions (the
//! `100.64.0.0/10` shared range is neither global nor private; `192.0.0.9` and `192.0.0.10` are
//! public), plus `not is_multicast`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::builtin::legal::{
    PublicClient, RequestOptions, argument, child, python_repr, python_str, schema, success,
    truncate, truthy,
};
use crate::builtin::research::int_or;
use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

/// The webscraper's own per-page timeout is 30 s; this is the client's bound on one call.
pub const DEFAULT_TIMEOUT_S: f64 = 45.0;
/// The per-page timeout sent with every scrape request (the reference's `"timeout": 30.0`).
pub const SCRAPE_TIMEOUT_S: f64 = 30.0;
/// A longer URL than this is refused before parsing.
pub const MAX_URL_CHARS: usize = 2000;
/// Internal names that never reach the resolver.
pub const BLOCKED_SUFFIXES: &[&str] = &[
    ".local",
    ".localhost",
    ".internal",
    ".cluster.local",
    ".svc",
    ".lan",
    ".home",
];
/// The only ports a public page may name (the reference's own allow-list).
pub const ALLOWED_PORTS: &[i64] = &[80, 443, 8080, 8443];

/// A DNS answer pinned by a test (the reference's `set_client(scrape._resolve)` seam).
#[derive(Clone, Debug)]
pub enum Resolution {
    /// The addresses the name resolves to.
    Addresses(Vec<IpAddr>),
    /// `getaddrinfo` failed.
    Unresolvable,
}

/// The webscraper client and the guard's DNS seam. `Default` reads `WEBSCRAPER_URL`,
/// `WEBSCRAPER_TOKEN` and `WEBSCRAPER_TIMEOUT_S` at call time, as the reference does.
#[derive(Clone, Default)]
pub struct Clients {
    client: Option<PublicClient>,
    /// `None` = read `WEBSCRAPER_TOKEN`; `Some(None)` forces no identity header (the test seam).
    token: Option<Option<String>>,
    /// `None` = read `WEBSCRAPER_URL`; `Some(None)` forces it unset (the test seam).
    url: Option<Option<String>>,
    resolution: Option<Resolution>,
}

impl Clients {
    /// A resolver that reads every setting from the environment.
    pub fn from_env() -> Self {
        Self::default()
    }

    /// A resolver with an explicit client (the test seam).
    pub fn with(mut self, client: PublicClient) -> Self {
        self.client = Some(client);
        self
    }

    /// A resolver with the licence token pinned (`None` forces no identity header).
    pub fn with_token(mut self, token: Option<String>) -> Self {
        self.token = Some(token);
        self
    }

    /// A resolver with `WEBSCRAPER_URL` pinned (`None` forces the unset refusal).
    pub fn with_url(mut self, url: Option<String>) -> Self {
        self.url = Some(url);
        self
    }

    /// A resolver whose DNS answers are pinned (the guard never calls the real resolver).
    pub fn with_resolved(mut self, addresses: Vec<IpAddr>) -> Self {
        self.resolution = Some(Resolution::Addresses(addresses));
        self
    }

    /// A resolver whose every lookup fails.
    pub fn with_unresolvable_host(mut self) -> Self {
        self.resolution = Some(Resolution::Unresolvable);
        self
    }

    /// The webscraper client: the explicit one, else `WEBSCRAPER_URL` with the configured
    /// timeout. A missing URL is the reference's permanent refusal, never a panic.
    pub fn webscraper(&self) -> Result<PublicClient, String> {
        if let Some(client) = &self.client {
            return Ok(client.clone());
        }
        let url = match &self.url {
            Some(url) => url.clone(),
            None => std::env::var("WEBSCRAPER_URL").ok(),
        };
        let url = url
            .filter(|url| !url.trim().is_empty())
            .ok_or_else(|| "[permanent] WEBSCRAPER_URL is not set on the MCP server".to_owned())?;
        let timeout = timeout_from(std::env::var("WEBSCRAPER_TIMEOUT_S").ok());
        Ok(PublicClient::new(url, timeout, Duration::ZERO, None))
    }

    /// The webscraper's licence token: the pinned override, else `WEBSCRAPER_TOKEN` when set and
    /// non-empty. Identities are never forwarded from the MCP caller.
    pub fn token(&self) -> Option<String> {
        match &self.token {
            Some(token) => token.clone(),
            None => std::env::var("WEBSCRAPER_TOKEN")
                .ok()
                .filter(|token| !token.is_empty()),
        }
    }

    /// The name's addresses: the pinned answer, else a real `getaddrinfo` over SOCK_STREAM.
    async fn resolve(&self, host: &str) -> Result<Vec<IpAddr>, ()> {
        if let Some(resolution) = &self.resolution {
            return match resolution {
                Resolution::Addresses(addresses) => Ok(addresses.clone()),
                Resolution::Unresolvable => Err(()),
            };
        }
        match tokio::net::lookup_host((host, 0)).await {
            Ok(addresses) => Ok(addresses.map(|address| address.ip()).collect()),
            Err(_) => Err(()),
        }
    }
}

/// `WEBSCRAPER_TIMEOUT_S` (default 45): an unparseable, non-finite or non-positive value takes
/// the reference's default rather than a duration that would panic or disable the bound.
fn timeout_from(raw: Option<String>) -> Duration {
    match raw.and_then(|value| value.trim().parse::<f64>().ok()) {
        Some(seconds) if seconds.is_finite() && seconds > 0.0 => Duration::from_secs_f64(seconds),
        _ => Duration::from_secs_f64(DEFAULT_TIMEOUT_S),
    }
}

// ── the URL split (Python's urllib.parse.urlsplit, as check_url reads it) ──────────────────

/// The parts `check_url` reads: the lowercased scheme, the hostname (lowercased before any
/// IPv6 zone), the parsed port, and whether an `@` userinfo was present.
#[derive(Debug, PartialEq, Eq)]
pub struct ParsedUrl {
    pub scheme: String,
    pub host: Option<String>,
    pub port: Option<i64>,
    pub has_userinfo: bool,
}

/// `text.partition(separator)`: `(before, found, after)`.
fn partition(text: &str, separator: char) -> (&str, bool, &str) {
    match text.split_once(separator) {
        Some((before, after)) => (before, true, after),
        None => (text, false, ""),
    }
}

/// The text after the last `separator` (Python's `text.rpartition(separator)[2]`).
fn after_last(text: &str, separator: char) -> &str {
    match text.rfind(separator) {
        Some(index) => &text[index + separator.len_utf8()..],
        None => text,
    }
}

/// Python's `_check_bracketed_host`: an IPvFuture literal (`v<hex>.<rest>`) or an IPv6 address;
/// an IPv4 address in brackets is malformed.
fn check_bracketed_host(host: &str) -> Result<(), ()> {
    if let Some(rest) = host.strip_prefix('v') {
        let (hex, found, suffix) = partition(rest, '.');
        let valid = found
            && !hex.is_empty()
            && !suffix.is_empty()
            && hex.bytes().all(|byte| byte.is_ascii_hexdigit());
        return if valid { Ok(()) } else { Err(()) };
    }
    if let Ok(IpAddr::V6(_)) = host.parse::<IpAddr>() {
        return Ok(());
    }
    // Python's ipaddress accepts a scoped IPv6 literal (`fe80::1%eth0`).
    if let Some((address, zone)) = host.split_once('%')
        && !zone.is_empty()
        && address.parse::<Ipv6Addr>().is_ok()
    {
        return Ok(());
    }
    Err(())
}

/// Python's `_check_bracketed_netloc`, reached only when the netloc carries both brackets.
fn check_bracketed_netloc(netloc: &str) -> Result<(), ()> {
    let hostinfo = after_last(netloc, '@');
    let (before, has_open, bracketed) = partition(hostinfo, '[');
    if !has_open {
        return Err(());
    }
    if !before.is_empty() {
        return Err(());
    }
    let (hostname, has_close, rest) = partition(bracketed, ']');
    if !has_close || (!rest.is_empty() && !rest.starts_with(':')) {
        return Err(());
    }
    check_bracketed_host(hostname)
}

/// The reference's `urlsplit(...)` for the parts `check_url` reads. `Err(())` is the Python
/// `ValueError` that `check_url` maps to its `malformed` refusal — one refusal, no detail, so a
/// unit error type is the honest shape rather than an enum with a single variant.
#[allow(clippy::result_unit_err)]
pub fn urlsplit(input: &str) -> Result<ParsedUrl, ()> {
    // `url.strip()` ran in the caller; urlsplit then drops C0 controls and spaces at the edges
    // and every tab, CR and LF anywhere (Python's `_UNSAFE_URL_BYTES_TO_REMOVE`).
    let mut url: String = input
        .trim_start_matches(|character: char| (character as u32) <= 0x20)
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();

    let mut scheme = String::new();
    if let Some(index) = url.find(':')
        && index > 0
    {
        let candidate = &url[..index];
        let mut characters = candidate.chars();
        let first = characters.next().is_some_and(|c| c.is_ascii_alphabetic());
        let rest = characters.all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
        if first && rest {
            scheme = candidate.to_ascii_lowercase();
            url = url[index + 1..].to_owned();
        }
    }

    let mut netloc = String::new();
    if let Some(rest) = url.strip_prefix("//") {
        let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        netloc = rest[..end].to_owned();
    }
    let has_open = netloc.contains('[');
    let has_close = netloc.contains(']');
    if has_open != has_close {
        return Err(());
    }
    if has_open && has_close {
        check_bracketed_netloc(&netloc)?;
    }

    let hostinfo = after_last(&netloc, '@');
    let (hostname, port_text) = if let Some(open) = hostinfo.find('[') {
        let bracketed = &hostinfo[open + 1..];
        let (hostname, has_close, rest) = partition(bracketed, ']');
        let port = if has_close {
            partition(rest, ':').2
        } else {
            ""
        };
        (hostname, port)
    } else {
        let (hostname, _has_colon, port) = partition(hostinfo, ':');
        (hostname, port)
    };
    let port = if port_text.is_empty() {
        None
    } else {
        if !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(());
        }
        let port: i64 = port_text.parse().map_err(|_| ())?;
        if !(0..=65535).contains(&port) {
            return Err(());
        }
        Some(port)
    };
    let host = if hostname.is_empty() {
        None
    } else {
        let (address, zone) = match hostname.split_once('%') {
            Some((address, zone)) => (address, Some(zone)),
            None => (hostname, None),
        };
        let mut host = address.to_ascii_lowercase();
        if let Some(zone) = zone {
            host.push('%');
            host.push_str(zone);
        }
        Some(host)
    };
    Ok(ParsedUrl {
        scheme,
        host,
        port,
        has_userinfo: netloc.contains('@'),
    })
}

// ── Python's ipaddress.is_global for the guard ─────────────────────────────────────────────

/// The reference's `_is_public`: Python's `is_global` and not multicast, with an IPv4-mapped
/// IPv6 address classified by the IPv4 address it carries.
pub fn is_public(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(address) => is_global_v4(address) && !address.is_multicast(),
        IpAddr::V6(address) => match address.to_ipv4_mapped() {
            Some(mapped) => is_global_v4(mapped) && !mapped.is_multicast(),
            None => is_global_v6(address) && !address.is_multicast(),
        },
    }
}

/// IPv4 networks Python's `is_private` covers (`_private_networks`).
const V4_PRIVATE: &[(u32, u8)] = &[
    (0x0000_0000, 8),  // 0.0.0.0/8
    (0x0a00_0000, 8),  // 10.0.0.0/8
    (0x7f00_0000, 8),  // 127.0.0.0/8
    (0xa9fe_0000, 16), // 169.254.0.0/16
    (0xac10_0000, 12), // 172.16.0.0/12
    (0xc000_0000, 24), // 192.0.0.0/24
    (0xc000_00aa, 31), // 192.0.0.170/31
    (0xc000_0200, 24), // 192.0.2.0/24
    (0xc0a8_0000, 16), // 192.168.0.0/16
    (0xc612_0000, 15), // 198.18.0.0/15
    (0xc633_6400, 24), // 198.51.100.0/24
    (0xcb00_7100, 24), // 203.0.113.0/24
    (0xf000_0000, 4),  // 240.0.0.0/4
    (0xffff_ffff, 32), // 255.255.255.255/32
];
/// `192.0.0.9` and `192.0.0.10`: in the special registry but publicly reachable.
const V4_PUBLIC: &[(u32, u8)] = &[(0xc000_0009, 32), (0xc000_000a, 32)];
/// `100.64.0.0/10`: neither private nor global (Python's `is_global` exception).
const V4_SHARED: (u32, u8) = (0x6440_0000, 10);

/// IPv6 networks Python's `is_private` covers.
const V6_PRIVATE: &[(u128, u8)] = &[
    (0x0000_0000_0000_0000_0000_0000_0000_0000, 128), // ::/128
    (0x0000_0000_0000_0000_0000_0000_0000_0001, 128), // ::1/128
    (0x0000_ffff_0000_0000_0000_0000_0000_0000, 96),  // ::ffff:0:0/96
    (0x0064_ff9b_0001_0000_0000_0000_0000_0000, 48),  // 64:ff9b:1::/48
    (0x0100_0000_0000_0000_0000_0000_0000_0000, 64),  // 100::/64
    (0x2001_0000_0000_0000_0000_0000_0000_0000, 23),  // 2001::/23
    (0x2001_0db8_0000_0000_0000_0000_0000_0000, 32),  // 2001:db8::/32
    (0x2002_0000_0000_0000_0000_0000_0000_0000, 16),  // 2002::/16
    (0x3fff_0000_0000_0000_0000_0000_0000_0000, 20),  // 3fff::/20
    (0xfc00_0000_0000_0000_0000_0000_0000_0000, 7),   // fc00::/7
    (0xfe80_0000_0000_0000_0000_0000_0000_0000, 10),  // fe80::/10
];
/// Global exceptions inside `2001::/23`.
const V6_PRIVATE_EXCEPTIONS: &[(u128, u8)] = &[
    (0x2001_0001_0000_0000_0000_0000_0000_0001, 128), // 2001:1::1/128
    (0x2001_0001_0000_0000_0000_0000_0000_0002, 128), // 2001:1::2/128
    (0x2001_0003_0000_0000_0000_0000_0000_0000, 32),  // 2001:3::/32
    (0x2001_0004_0112_0000_0000_0000_0000_0000, 48),  // 2001:4:112::/48
    (0x2001_0020_0000_0000_0000_0000_0000_0000, 28),  // 2001:20::/28
    (0x2001_0030_0000_0000_0000_0000_0000_0000, 28),  // 2001:30::/28
];

/// `ip in network` over a `(network, prefix length)` pair.
fn in_v4(address: Ipv4Addr, (network, bits): (u32, u8)) -> bool {
    let mask = match bits {
        0 => 0,
        bits => u32::MAX << (32 - u32::from(bits)),
    };
    u32::from(address) & mask == network
}

fn in_v6(address: Ipv6Addr, (network, bits): (u128, u8)) -> bool {
    let mask = match bits {
        0 => 0,
        bits => u128::MAX << (128 - u32::from(bits)),
    };
    u128::from(address) & mask == network
}

fn is_private_v4(address: Ipv4Addr) -> bool {
    V4_PRIVATE.iter().any(|network| in_v4(address, *network))
        && !V4_PUBLIC.iter().any(|network| in_v4(address, *network))
}

fn is_global_v4(address: Ipv4Addr) -> bool {
    !in_v4(address, V4_SHARED) && !is_private_v4(address)
}

fn is_private_v6(address: Ipv6Addr) -> bool {
    V6_PRIVATE.iter().any(|network| in_v6(address, *network))
        && !V6_PRIVATE_EXCEPTIONS
            .iter()
            .any(|network| in_v6(address, *network))
}

fn is_global_v6(address: Ipv6Addr) -> bool {
    !is_private_v6(address)
}

// ── the guard and the tool ─────────────────────────────────────────────────────────────────

/// The reference's `_reject`: `[permanent] url not allowed ({why}): {url[:100]!r}`.
fn reject(url: &str, why: &str) -> String {
    let shown: String = url.chars().take(100).collect();
    format!(
        "[permanent] url not allowed ({why}): {}",
        python_repr(&Value::String(shown))
    )
}

/// Return the URL if it may be fetched, else `[permanent] url not allowed (...)`.
pub async fn check_url(clients: &Clients, url: &Value) -> Result<String, String> {
    let Some(raw) = url.as_str() else {
        return Err("[permanent] url must be a string of at most 2000 chars".to_owned());
    };
    if raw.chars().count() > MAX_URL_CHARS {
        return Err("[permanent] url must be a string of at most 2000 chars".to_owned());
    }
    let parsed = urlsplit(raw).map_err(|()| reject(raw, "malformed"))?;
    if parsed.scheme != "http" && parsed.scheme != "https" {
        return Err(reject(raw, "scheme must be http or https"));
    }
    if parsed.has_userinfo {
        return Err(reject(raw, "credentials in url"));
    }
    let host = parsed
        .host
        .map(|host| host.to_lowercase())
        .map(|host| host.trim_end_matches('.').to_owned())
        .unwrap_or_default();
    if host.is_empty() {
        return Err(reject(raw, "no host"));
    }
    if let Some(port) = parsed.port
        && !ALLOWED_PORTS.contains(&port)
    {
        return Err(reject(raw, "non-standard port"));
    }
    let single_label = !host.contains('.') && !host.contains(':');
    if host == "localhost"
        || BLOCKED_SUFFIXES.iter().any(|suffix| host.ends_with(suffix))
        || single_label
    {
        return Err(reject(raw, "internal host name"));
    }
    if let Ok(literal) = host.parse::<IpAddr>() {
        if !is_public(literal) {
            return Err(reject(raw, "private, loopback or link-local address"));
        }
        return Ok(raw.trim().to_owned());
    }
    let addresses = match clients.resolve(&host).await {
        Ok(addresses) => addresses,
        Err(()) => return Err(reject(raw, "host does not resolve")),
    };
    if addresses.is_empty() || !addresses.iter().all(|address| is_public(*address)) {
        return Err(reject(
            raw,
            "host resolves to a private, loopback or link-local address",
        ));
    }
    Ok(raw.trim().to_owned())
}

/// Fetch one public web page and return its title and readable text.
pub async fn scrape(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let url = check_url(clients, &argument(arguments, "url")).await?;
    let max_chars = int_or(arguments, "max_chars", 30_000)?.clamp(500, 200_000);
    let max_chars = usize::try_from(max_chars).unwrap_or(500);
    let client = clients.webscraper()?;
    let mut headers: Vec<(&'static str, String)> = Vec::new();
    if let Some(token) = clients.token() {
        headers.push(("X-Tenant-Id", format!("Bearer {token}")));
    }
    let reply = client
        .request(
            "POST",
            "/api/scrape/url",
            RequestOptions {
                json: Some(json!({
                    "url": url,
                    "scraper_type": "auto",
                    "timeout": SCRAPE_TIMEOUT_S,
                })),
                headers,
                ..RequestOptions::default()
            },
        )
        .await?;
    let body: Value = serde_json::from_slice(&reply.body)
        .map_err(|_| "[retryable] non-JSON answer from the webscraper".to_owned())?;
    if child(&body, "status").as_str() == Some("failed") {
        let error = child(&body, "error");
        let reason = if truthy(error) {
            python_str(error)
        } else {
            "unknown".to_owned()
        };
        let reason: String = reason.chars().take(200).collect();
        return Err(format!("[permanent] scrape failed: {reason}"));
    }
    let text = [
        child(&body, "text_content"),
        child(&body, "markdown_content"),
    ]
    .into_iter()
    .find_map(|value| value.as_str().filter(|text| !text.is_empty()))
    .unwrap_or_default();
    let (text, truncated) = truncate(text, max_chars);
    let requested = Value::String(url);
    let body_url = child(&body, "url");
    let url_value = if truthy(body_url) {
        body_url.clone()
    } else {
        requested.clone()
    };
    let final_url = if truthy(child(&body, "final_url")) {
        child(&body, "final_url").clone()
    } else if truthy(body_url) {
        body_url.clone()
    } else {
        requested
    };
    let mut out = Map::new();
    out.insert("url".to_owned(), url_value);
    out.insert("final_url".to_owned(), final_url);
    out.insert("title".to_owned(), child(&body, "title").clone());
    out.insert("text".to_owned(), Value::String(text));
    out.insert("truncated".to_owned(), Value::Bool(truncated));
    Ok(Value::Object(out))
}

/// Register the single web tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "web",
        "scrape",
        "Fetch one public web page (http/https) and return its title and readable text.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "url": {"type": "string"},
                "max_chars": {"default": 30000, "type": "integer"},
            },
            "required": ["url"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(scrape(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parsed(url: &str) -> ParsedUrl {
        urlsplit(url).expect("a parseable url")
    }

    #[test]
    fn urlsplit_matches_the_reference_reads() {
        let url = parsed("HTTP://Example.COM./x?q#f");
        assert_eq!(url.scheme, "http");
        assert_eq!(url.host.as_deref(), Some("example.com."));
        assert_eq!(url.port, None);
        assert!(!url.has_userinfo);
        assert_eq!(
            parsed("http://user:pw@example.com/").host.as_deref(),
            Some("example.com")
        );
        assert!(parsed("http://user:pw@example.com/").has_userinfo);
        assert_eq!(parsed("http://[::1]/").host.as_deref(), Some("::1"));
        assert_eq!(parsed("http://host:/").port, None);
        assert_eq!(parsed("http://host:8080/").port, Some(8080));
        assert!(urlsplit("https://example.com:99999/").is_err());
        assert!(urlsplit("http://host:abc/").is_err());
        assert!(urlsplit("http:///nohost").unwrap().host.is_none());
        assert!(urlsplit("http://[::1]x/").is_err());
        assert!(urlsplit("http://[127.0.0.1]/").is_err());
    }

    #[test]
    fn is_public_matches_pythons_is_global_without_multicast() {
        let public = [
            "8.8.8.8",
            "192.0.0.9",
            "192.0.0.10",
            "4000::1",
            "::ffff:8.8.8.8",
        ];
        for address in public {
            assert!(is_public(address.parse().unwrap()), "{address}");
        }
        let private = [
            "0.0.0.0",
            "10.0.0.1",
            "100.64.0.1",
            "127.0.0.1",
            "169.254.169.254",
            "172.16.0.1",
            "192.0.0.8",
            "192.0.2.1",
            "192.168.1.1",
            "198.18.0.1",
            "198.51.100.1",
            "203.0.113.1",
            "240.0.0.1",
            "255.255.255.255",
            "224.0.0.1",
            "::",
            "::1",
            "2001:db8::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
            "2001:2::1",
            "ff02::1",
        ];
        for address in private {
            assert!(!is_public(address.parse().unwrap()), "{address}");
        }
        // The registry's public exceptions.
        assert!(is_public("2001:1::1".parse().unwrap()));
        assert!(is_public("2001:3::1".parse().unwrap()));
        assert!(is_public("2001:20::1".parse().unwrap()));
    }

    #[test]
    fn timeouts_take_the_reference_default_when_unusable() {
        assert_eq!(timeout_from(Some("12".to_owned())), Duration::from_secs(12));
        for value in ["", "nope", "0", "-1", "NaN", "inf"] {
            assert_eq!(
                timeout_from(Some(value.to_owned())),
                Duration::from_secs(45),
                "{value}"
            );
        }
        assert_eq!(timeout_from(None), Duration::from_secs(45));
    }
}
