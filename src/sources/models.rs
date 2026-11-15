//! Tool-source contracts: the authentication union, the writer models and the read-back view.
//!
//! Port of the reference `src/sources/models.py`. Every model mirrors the reference's Pydantic
//! configuration: unknown fields are refused (`extra="forbid"`), JSON types are never coerced
//! (`strict=True`), and the cross-field validators run during deserialization, so a contract the
//! reference would refuse cannot be constructed from a request body. Field shapes are checked by
//! field deserializers and the model validators by a `TryFrom`, the same split the catalog models
//! use ([`crate::catalog::models`]).
//!
//! A token is write-only. [`Secret`] accepts a credential on deserialization, serialises as the
//! reference's redaction ([`SECRET_REDACTION`], `SecretStr`'s wire form), and its `Debug` never
//! prints the value; [`SourceView`] has no token field at all. Nothing here logs credential
//! material.

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::catalog::ids::{AppKey, AuthorityId, Name, Uuid7};
use crate::catalog::models::AuthAdapter;
use crate::sources::crypto::{SourceCryptoError, valid_secret, valid_token};
use crate::sources::guard::{GuardError, checked_base_url, is_ip_literal};

// ── fixed sets ──────────────────────────────────────────────────────────────────────────────

/// Headers a static source may not set: framing and routing belong to the HTTP client
/// (`models.py:22-36`). `authorization` is refused separately by [`StaticHeaderAuth`], because
/// the licence and static-bearer kinds own it.
pub const FORBIDDEN_HEADERS: [&str; 11] = [
    "host",
    "content-length",
    "content-type",
    "transfer-encoding",
    "connection",
    "te",
    "upgrade",
    "cookie",
    "proxy-authorization",
    "idempotency-key",
    "x-idempotency-key",
];

/// Kinds that need no stored secret; every other kind has exactly one (`models.py:117-118`).
pub const SECRETLESS_KINDS: [&str; 2] = ["licence", "none"];

/// Hostnames a tenant may never register (cluster-internal names); the egress layer re-checks at
/// call time (`models.py:122-123`).
pub const INTERNAL_SUFFIXES: [&str; 6] = [
    ".local",
    ".internal",
    ".svc",
    ".cluster.local",
    ".localhost",
    ".lan",
];

/// The reference's `SecretStr` serialisation (`model_dump_json` renders every stored secret as
/// this constant, never as the value).
pub const SECRET_REDACTION: &str = "**********";

// ── the tenant URL syntax check ────────────────────────────────────────────────────────────

/// Why a tenant-registered URL was refused. Each message is exactly the reference's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum TenantUrlError {
    /// `urlsplit` or `url.port` raised `ValueError` (an unparseable or out-of-range port, or
    /// unbalanced/misplaced IPv6 brackets). The reference reports that as `invalid URL`.
    #[error("invalid URL")]
    InvalidUrl,
    /// The value is not a public https origin in the accepted shape.
    #[error("a public https URL is required")]
    NotPublicHttps,
}

/// The syntax of a tenant-registered HTTPS URL (`models.py:130-162`); the reference's refusal.
///
/// Public DNS names only: no address literal, userinfo, query, fragment, or single-label or
/// internal host. This is the registration-time half; the egress layer re-checks (and pins the
/// resolved address) on every call. Returns `value` unchanged.
///
/// The value is split the way CPython's `urlsplit` splits it, not with the WHATWG parser: the
/// reference's accept-set depends on the un-normalised path (`…/../x` is refused here, where the
/// WHATWG parser would have resolved the dot segment away first). For the same reason the WHATWG
/// removals are applied first — tab, CR and LF anywhere, and leading C0 controls and spaces —
/// exactly as `_urlsplit` applies them. The port is checked the way `url.port` checks it: ASCII
/// digits only, at most 65535. Bracket structure and bracketed hosts are checked as `_urlsplit`
/// checks them: only an IPv6 or an IPvFuture address may be bracketed. A zoned IPv6 address
/// (`[fe80::1%eth0]`) is the one form Python's `ipaddress` accepts and this port refuses; it
/// fails the host-shape rule either way, so the verdict is the same and only the refusal message
/// differs on that refused input.
pub fn checked_tenant_url(value: &str, allow_path: bool) -> Result<&str, TenantUrlError> {
    let cleaned: String = value
        .chars()
        .filter(|character| !matches!(character, '\t' | '\r' | '\n'))
        .collect();
    let cleaned = cleaned.trim_start_matches(|character: char| character <= ' ');

    let parts = split_url(cleaned);
    if !parts.scheme.eq_ignore_ascii_case("https") {
        return Err(TenantUrlError::NotPublicHttps);
    }
    check_brackets(parts.netloc)?;

    let (hostname, port) = hostname_and_port(parts.netloc);
    let port = match port {
        Some(text) if text.bytes().all(|byte| byte.is_ascii_digit()) => {
            let port: u32 = text.parse().map_err(|_| TenantUrlError::InvalidUrl)?;
            if port > 65_535 {
                return Err(TenantUrlError::InvalidUrl);
            }
            Some(port)
        }
        Some(_) => return Err(TenantUrlError::InvalidUrl),
        None => None,
    };

    static HOST: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$").expect("the host pattern compiles")
    });
    static PATH_ANY: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^(?:/[A-Za-z0-9._~-]+)*/?$").expect("the tenant path pattern compiles")
    });
    static PATH_ONLY: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^/?$").expect("the bare path pattern compiles"));

    let host = hostname.to_ascii_lowercase();
    let path_ok = if allow_path {
        PATH_ANY.is_match(parts.path)
    } else {
        PATH_ONLY.is_match(parts.path)
    };
    let internal = INTERNAL_SUFFIXES
        .iter()
        .any(|suffix| host.ends_with(*suffix));
    let dot_segment = parts
        .path
        .split('/')
        .any(|segment| segment == "." || segment == "..");

    if !HOST.is_match(&host)
        || parts.netloc.contains('@')
        || !parts.query.is_empty()
        || !parts.fragment.is_empty()
        || port == Some(0)
        || is_ip_literal(&host)
        || !host.contains('.')
        || host.contains("..")
        || host == "localhost"
        || internal
        || !path_ok
        || dot_segment
        || value.chars().count() > 512
    {
        return Err(TenantUrlError::NotPublicHttps);
    }
    Ok(value)
}

/// The five components of a split URL. The slices borrow from the cleaned input.
struct UrlParts<'a> {
    scheme: &'a str,
    netloc: &'a str,
    path: &'a str,
    query: &'a str,
    fragment: &'a str,
}

/// CPython's `urlsplit` for the components the policy reads: a scheme is recognised only when
/// the colon-prefix is a valid scheme token, a netloc only after `//`, then the fragment is split
/// before the query (the reference calls `urlsplit` with the default `allow_fragments=True`).
fn split_url(value: &str) -> UrlParts<'_> {
    let mut scheme = "";
    let mut rest = value;
    if let Some(colon) = value.find(':') {
        let candidate = &value[..colon];
        let first_is_alpha = candidate
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic());
        let scheme_token = candidate
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.'));
        if colon > 0 && first_is_alpha && scheme_token {
            scheme = candidate;
            rest = &value[colon + 1..];
        }
    }
    let mut netloc = "";
    if let Some(after) = rest.strip_prefix("//") {
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        netloc = &after[..end];
        rest = &after[end..];
    }
    let (rest, fragment) = match rest.split_once('#') {
        Some((before, fragment)) => (before, fragment),
        None => (rest, ""),
    };
    let (path, query) = match rest.split_once('?') {
        Some((path, query)) => (path, query),
        None => (rest, ""),
    };
    UrlParts {
        scheme,
        netloc,
        path,
        query,
        fragment,
    }
}

/// The bracket rules `_urlsplit` applies: an unbalanced bracket, data before `[`, data after `]`
/// that does not start a port, or a bracketed host that is neither an IPv6 address nor an
/// IPvFuture address (`_check_bracketed_netloc`, `_check_bracketed_host`). All of them raise
/// `ValueError`, which the reference reports as `invalid URL`.
fn check_brackets(netloc: &str) -> Result<(), TenantUrlError> {
    let has_open = netloc.contains('[');
    if has_open != netloc.contains(']') {
        return Err(TenantUrlError::InvalidUrl);
    }
    if !has_open {
        return Ok(());
    }
    let hostinfo = netloc
        .rsplit_once('@')
        .map_or(netloc, |(_, hostinfo)| hostinfo);
    let hostname = if let Some((before, bracketed)) = hostinfo.split_once('[') {
        if !before.is_empty() {
            return Err(TenantUrlError::InvalidUrl);
        }
        let (hostname, after) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        if !after.is_empty() && !after.starts_with(':') {
            return Err(TenantUrlError::InvalidUrl);
        }
        hostname
    } else {
        // A balanced bracket outside the host part still makes `_urlsplit` validate the
        // hostinfo as a bracketed host, which a DNS name is not.
        hostinfo
            .split_once(':')
            .map_or(hostinfo, |(hostname, _)| hostname)
    };
    check_bracketed_host(hostname)
}

/// The reference's `_check_bracketed_host`: an IPvFuture address (`v` then hex digits, a dot and
/// at least one more character) passes; so does an IPv6 address; an IPv4 address in brackets and
/// anything else raise `ValueError` (`models.py` version of `urlsplit`).
///
/// A zoned IPv6 address (`[fe80::1%eth0]`) is accepted by Python's `ipaddress` but refused here:
/// it fails the host-shape rule either way, so the verdict is unchanged and only the message
/// differs on that refused input.
fn check_bracketed_host(hostname: &str) -> Result<(), TenantUrlError> {
    if hostname.starts_with('v') || hostname.starts_with('V') {
        let bytes = hostname.as_bytes();
        let mut index = 1;
        while index < bytes.len() && bytes[index].is_ascii_hexdigit() {
            index += 1;
        }
        // `[vV][a-fA-F0-9]+\..+`: at least one hex digit, a dot, then at least one more char.
        if index == 1 || index + 1 >= bytes.len() || bytes[index] != b'.' {
            return Err(TenantUrlError::InvalidUrl);
        }
        Ok(())
    } else if hostname.parse::<std::net::Ipv6Addr>().is_err() {
        Err(TenantUrlError::InvalidUrl)
    } else {
        Ok(())
    }
}

/// The reference's `_hostinfo`: the hostname before the first `:` (or between the brackets of an
/// IPv6 literal), and the port text after it when non-empty. A trailing `:` carries no port.
fn hostname_and_port(netloc: &str) -> (&str, Option<&str>) {
    let hostinfo = netloc
        .rsplit_once('@')
        .map_or(netloc, |(_, hostinfo)| hostinfo);
    if let Some((_, bracketed)) = hostinfo.split_once('[') {
        let (hostname, remainder) = bracketed.split_once(']').unwrap_or((bracketed, ""));
        let port = remainder.split_once(':').map(|(_, port)| port);
        (hostname, port.filter(|port| !port.is_empty()))
    } else {
        let (hostname, port) = hostinfo.split_once(':').unwrap_or((hostinfo, ""));
        (hostname, Some(port).filter(|port| !port.is_empty()))
    }
}

// ── the write-only secret ──────────────────────────────────────────────────────────────────

/// A write-only credential. Accepted on deserialization, never rendered back.
///
/// The reference's `SecretStr` serialises as [`SECRET_REDACTION`] and its `repr` hides the value;
/// [`Debug`] and [`Serialize`] here do the same, so the owning models derive them safely.
/// [`expose_secret`](Self::expose_secret) is the only way to read the credential.
#[derive(Clone, PartialEq, Eq)]
pub struct Secret(String);

impl Secret {
    /// Wrap a credential. The owning model checks its charset for the auth kind
    /// ([`checked_secret`]), exactly as the reference validates the stored secret per kind.
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The plaintext credential. A caller must never log it or format it with `Debug`.
    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("Secret")
            .field(&SECRET_REDACTION)
            .finish()
    }
}

impl Serialize for Secret {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(SECRET_REDACTION)
    }
}

impl<'de> Deserialize<'de> for Secret {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(Self)
    }
}

// ── the auth contract ─────────────────────────────────────────────────────────────────────

/// The `kind` literal of [`NoAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum NoAuthKind {
    /// `none`
    #[serde(rename = "none")]
    None,
}

/// The `kind` literal of [`LicenceAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LicenceKind {
    /// `licence`
    #[serde(rename = "licence")]
    Licence,
}

/// The `kind` literal of [`StaticBearerAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticBearerKind {
    /// `static_bearer`
    #[serde(rename = "static_bearer")]
    StaticBearer,
}

/// The `kind` literal of [`StaticHeaderAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum StaticHeaderKind {
    /// `static_header`
    #[serde(rename = "static_header")]
    StaticHeader,
}

/// The `kind` literal of [`QueryParamAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum QueryParamKind {
    /// `query_param`
    #[serde(rename = "query_param")]
    QueryParam,
}

/// The `kind` literal of [`BasicAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BasicKind {
    /// `basic`
    #[serde(rename = "basic")]
    Basic,
}

/// The `kind` literal of [`OAuth2ClientCredentialsAuth`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OAuth2Kind {
    /// `oauth2_client_credentials`
    #[serde(rename = "oauth2_client_credentials")]
    OAuth2ClientCredentials,
}

/// How a tenant licence is presented (`models.py:50`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum LicenceScheme {
    /// `Authorization: Bearer <licence>`.
    #[default]
    #[serde(rename = "bearer")]
    Bearer,
    /// `X-Tenant-Id: Bearer <licence>`.
    #[serde(rename = "x_tenant_id_bearer")]
    XTenantIdBearer,
}

/// How the OAuth2 client authenticates at its token endpoint (`models.py:99`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ClientAuth {
    /// HTTP Basic with the client id and secret.
    #[default]
    #[serde(rename = "basic")]
    Basic,
    /// The credentials in the form body.
    #[serde(rename = "post")]
    Post,
}

/// The two literals an `idempotency_header` may name (`models.py:119`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IdempotencyHeader {
    /// `Idempotency-Key`
    #[serde(rename = "Idempotency-Key")]
    IdempotencyKey,
    /// `X-Idempotency-Key`
    #[serde(rename = "X-Idempotency-Key")]
    XIdempotencyKey,
}

impl IdempotencyHeader {
    /// The header name as it is written on the wire.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::IdempotencyKey => "Idempotency-Key",
            Self::XIdempotencyKey => "X-Idempotency-Key",
        }
    }
}

/// A source's lifecycle status (`models.py:271`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceStatus {
    /// `active`
    #[serde(rename = "active")]
    Active,
    /// `disabled`
    #[serde(rename = "disabled")]
    Disabled,
}

/// A public API: nothing is sent and nothing is stored (`models.py:39-42`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NoAuth {
    /// Always `none`.
    pub kind: NoAuthKind,
}

/// The tenant's licence for `app_key`, minted per call (`models.py:45-57`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LicenceAuth {
    /// Always `licence`.
    pub kind: LicenceKind,
    /// The licence application key.
    pub app_key: AppKey,
    /// How the licence is presented.
    #[serde(default)]
    pub scheme: LicenceScheme,
    /// The licences bundle the minter names explicitly; none lets licences pick the app's.
    #[serde(default, deserialize_with = "optional_bundle")]
    pub bundle: Option<String>,
}

impl LicenceAuth {
    /// The service-manifest adapter this licence source rides (`models.py:54-57`).
    pub fn adapter(&self) -> AuthAdapter {
        match self.scheme {
            LicenceScheme::Bearer => AuthAdapter::LicenseBearer,
            LicenceScheme::XTenantIdBearer => AuthAdapter::LicenseHeader,
        }
    }
}

/// `Authorization: Bearer <secret>` (`models.py:59-61`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticBearerAuth {
    /// Always `static_bearer`.
    pub kind: StaticBearerKind,
}

/// One checked header set to the stored secret (`models.py:63-72`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StaticHeaderAuth {
    /// Always `static_header`.
    pub kind: StaticHeaderKind,
    /// The header name; reserved framing/routing headers are refused.
    #[serde(deserialize_with = "static_header_name")]
    pub header: String,
}

/// The stored secret is sent as `?<param>=<secret>` (`models.py:75-79`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QueryParamAuth {
    /// Always `query_param`.
    pub kind: QueryParamKind,
    /// The query parameter name.
    #[serde(deserialize_with = "query_param_name")]
    pub param: String,
}

/// HTTP Basic: `username` is stored in the clear, the password is the stored secret
/// (`models.py:82-87`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BasicAuth {
    /// Always `basic`.
    pub kind: BasicKind,
    /// The username, printable ASCII without a colon.
    #[serde(deserialize_with = "basic_username")]
    pub username: String,
}

/// RFC 6749 client-credentials grant; the stored secret is the client secret
/// (`models.py:89-104`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuth2ClientCredentialsAuth {
    /// Always `oauth2_client_credentials`.
    pub kind: OAuth2Kind,
    /// The token endpoint; a public https URL.
    #[serde(deserialize_with = "oauth_token_url")]
    pub token_url: String,
    /// The client id, printable ASCII without spaces.
    #[serde(deserialize_with = "oauth_client_id")]
    pub client_id: String,
    /// The requested scope, space-separated tokens.
    #[serde(default, deserialize_with = "optional_scope")]
    pub scope: Option<String>,
    /// The requested audience, printable ASCII without spaces.
    #[serde(default, deserialize_with = "optional_audience")]
    pub audience: Option<String>,
    /// How the client authenticates at the token endpoint.
    #[serde(default)]
    pub client_auth: ClientAuth,
}

/// The source's authentication contract, discriminated on `kind` (`models.py:107-116`).
///
/// This is the reference's `Annotated[NoAuth | …, Field(discriminator="kind")]`: serialization
/// delegates to the variant, and deserialization dispatches on `kind` before applying that
/// variant's own strict shape and validators.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceAuth {
    /// `none`
    None(NoAuth),
    /// `licence`
    Licence(LicenceAuth),
    /// `static_bearer`
    StaticBearer(StaticBearerAuth),
    /// `static_header`
    StaticHeader(StaticHeaderAuth),
    /// `query_param`
    QueryParam(QueryParamAuth),
    /// `basic`
    Basic(BasicAuth),
    /// `oauth2_client_credentials`
    OAuth2ClientCredentials(OAuth2ClientCredentialsAuth),
}

impl SourceAuth {
    /// The reference's `kind` discriminator.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None(_) => "none",
            Self::Licence(_) => "licence",
            Self::StaticBearer(_) => "static_bearer",
            Self::StaticHeader(_) => "static_header",
            Self::QueryParam(_) => "query_param",
            Self::Basic(_) => "basic",
            Self::OAuth2ClientCredentials(_) => "oauth2_client_credentials",
        }
    }
}

impl Serialize for SourceAuth {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::None(value) => value.serialize(serializer),
            Self::Licence(value) => value.serialize(serializer),
            Self::StaticBearer(value) => value.serialize(serializer),
            Self::StaticHeader(value) => value.serialize(serializer),
            Self::QueryParam(value) => value.serialize(serializer),
            Self::Basic(value) => value.serialize(serializer),
            Self::OAuth2ClientCredentials(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SourceAuth {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Some(kind) = value.get("kind").and_then(Value::as_str).map(str::to_owned) else {
            return Err(D::Error::custom("source auth requires a kind"));
        };
        match kind.as_str() {
            "none" => serde_json::from_value(value)
                .map(Self::None)
                .map_err(D::Error::custom),
            "licence" => serde_json::from_value(value)
                .map(Self::Licence)
                .map_err(D::Error::custom),
            "static_bearer" => serde_json::from_value(value)
                .map(Self::StaticBearer)
                .map_err(D::Error::custom),
            "static_header" => serde_json::from_value(value)
                .map(Self::StaticHeader)
                .map_err(D::Error::custom),
            "query_param" => serde_json::from_value(value)
                .map(Self::QueryParam)
                .map_err(D::Error::custom),
            "basic" => serde_json::from_value(value)
                .map(Self::Basic)
                .map_err(D::Error::custom),
            "oauth2_client_credentials" => serde_json::from_value(value)
                .map(Self::OAuth2ClientCredentials)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("unsupported source auth kind")),
        }
    }
}

/// Whether this auth kind needs a stored secret (`models.py:126-127`).
pub fn needs_secret(auth: &SourceAuth) -> bool {
    !SECRETLESS_KINDS.contains(&auth.kind())
}

/// The stored secret's charset for this kind (`models.py:165-167`): a basic password may contain
/// spaces; every other kind is a token (printable ASCII without spaces).
pub fn checked_secret<'a>(kind: &str, value: &'a str) -> Result<&'a str, SourceCryptoError> {
    if kind == "basic" {
        valid_secret(value)
    } else {
        valid_token(value)
    }
}

// ── the auth contract's field shapes ───────────────────────────────────────────────────────

/// `Field(pattern=r"^[a-z][a-z0-9_-]{0,63}$")` for the optional licence bundle.
fn optional_bundle<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z][a-z0-9_-]{0,63}$").expect("the bundle pattern compiles")
    });
    optional_matching(deserializer, &PATTERN, "invalid licence bundle")
}

/// One optional string that must match `pattern`.
fn optional_matching<'de, D: Deserializer<'de>>(
    deserializer: D,
    pattern: &'static LazyLock<Regex>,
    message: &'static str,
) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(value) if pattern.is_match(&value) => Ok(Some(value)),
        Some(_) => Err(D::Error::custom(message)),
        None => Ok(None),
    }
}

/// A static header: the reference's name pattern, then its reserved-name rule
/// (`models.py:64-72`). Both are reported with the reference's message for the reserved case.
fn static_header_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z][A-Za-z0-9-]{0,63}$").expect("the header pattern compiles")
    });
    let value = String::deserialize(deserializer)?;
    if !PATTERN.is_match(&value) {
        return Err(D::Error::custom("invalid header name"));
    }
    let lowered = value.to_ascii_lowercase();
    if lowered == "authorization" || FORBIDDEN_HEADERS.contains(&lowered.as_str()) {
        return Err(D::Error::custom("header is reserved"));
    }
    Ok(value)
}

/// `Field(pattern=r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$")` (`models.py:79`).
fn query_param_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$").expect("the query param pattern compiles")
    });
    let value = String::deserialize(deserializer)?;
    if PATTERN.is_match(&value) {
        Ok(value)
    } else {
        Err(D::Error::custom("invalid query parameter name"))
    }
}

/// `Field(pattern=r"^[\x20-\x39\x3b-\x7e]{1,128}$")`: printable ASCII, no colon
/// (`models.py:86`).
fn basic_username<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[\x20-\x39\x3b-\x7e]{1,128}$").expect("the username pattern compiles")
    });
    let value = String::deserialize(deserializer)?;
    if PATTERN.is_match(&value) {
        Ok(value)
    } else {
        Err(D::Error::custom("invalid basic username"))
    }
}

/// `Field(pattern=r"^[\x21-\x7e]{1,256}$")` for the OAuth client id (`models.py:94`).
fn oauth_client_id<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[\x21-\x7e]{1,256}$").expect("the client id pattern compiles")
    });
    let value = String::deserialize(deserializer)?;
    if PATTERN.is_match(&value) {
        Ok(value)
    } else {
        Err(D::Error::custom("invalid oauth client id"))
    }
}

/// `Field(pattern=r"^[\x21-\x7e]+( [\x21-\x7e]+)*$", max_length=256)` (`models.py:95-97`).
fn optional_scope<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[\x21-\x7e]+( [\x21-\x7e]+)*$").expect("the scope pattern compiles")
    });
    match Option::<String>::deserialize(deserializer)? {
        Some(value) if value.chars().count() <= 256 && PATTERN.is_match(&value) => Ok(Some(value)),
        Some(_) => Err(D::Error::custom("invalid oauth scope")),
        None => Ok(None),
    }
}

/// `Field(pattern=r"^[\x21-\x7e]{1,256}$")` for the OAuth audience (`models.py:98`).
fn optional_audience<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[\x21-\x7e]{1,256}$").expect("the audience pattern compiles")
    });
    optional_matching(deserializer, &PATTERN, "invalid oauth audience")
}

/// The token endpoint: `Field(min_length=1, max_length=512)` then
/// [`checked_tenant_url`] with `allow_path=True` (`models.py:93,101-104`).
fn oauth_token_url<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    let length = value.chars().count();
    if !(1..=512).contains(&length) {
        return Err(D::Error::custom("token_url must be 1 to 512 characters"));
    }
    checked_tenant_url(&value, true).map_err(|error| D::Error::custom(error.to_string()))?;
    Ok(value)
}

// ── shared writer-model validators ────────────────────────────────────────────────────────

/// [`SourceModelError`] is one of the three refusals a writer model can raise beyond serde's own
/// field errors.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum SourceModelError {
    /// A contract rule the reference states with exactly this message.
    #[error("{0}")]
    Refused(&'static str),
    /// [`checked_tenant_url`] refused the URL.
    #[error(transparent)]
    TenantUrl(#[from] TenantUrlError),
    /// The destination guard refused the origin.
    #[error(transparent)]
    Guard(#[from] GuardError),
    /// The stored-secret charset check refused the credential.
    #[error(transparent)]
    Secret(#[from] SourceCryptoError),
}

/// The reference's `token_matches_kind` (`models.py:183-189`): a present token must satisfy the
/// kind's charset, and a secretless kind carries no token at all.
fn validate_core(auth: &SourceAuth, token: Option<&Secret>) -> Result<(), SourceModelError> {
    if let Some(token) = token {
        checked_secret(auth.kind(), token.expose_secret())?;
        if !needs_secret(auth) {
            return Err(SourceModelError::Refused(
                "this source kind carries no stored secret",
            ));
        }
    }
    Ok(())
}

/// The reference's `SourceBody.consistent` (`models.py:200-205`): the guard's origin policy and
/// an absolute PEM CA path.
fn validate_source_body(
    base_url: &str,
    allow_internal_http: bool,
    ca_file: Option<&str>,
) -> Result<(), SourceModelError> {
    checked_base_url(base_url, allow_internal_http)?;
    if let Some(ca_file) = ca_file {
        static CA_FILE: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^/[A-Za-z0-9_./-]{1,511}$").expect("the ca_file pattern compiles")
        });
        if !CA_FILE.is_match(ca_file) {
            return Err(SourceModelError::Refused(
                "ca_file must be an absolute path",
            ));
        }
    }
    Ok(())
}

/// The reference's `TenantSourceBody.public_https` (`models.py:227-230`).
fn validate_tenant_body(base_url: &str) -> Result<(), SourceModelError> {
    checked_tenant_url(base_url, true)?;
    Ok(())
}

// ── writer models ─────────────────────────────────────────────────────────────────────────

/// An operator (platform) source create (`models.py:208-215`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::SourceCreate")]
pub struct SourceCreate {
    /// How the source authenticates.
    pub auth: SourceAuth,
    /// The retry idempotency header, one of the two literals.
    pub idempotency_header: Option<IdempotencyHeader>,
    /// Maximum request bytes, 1 to 10485760.
    pub max_request_bytes: Option<u32>,
    /// Maximum response bytes, 1 to 10485760.
    pub max_response_bytes: Option<u32>,
    /// The OpenAPI document path, relative to `base_url` (same origin only).
    pub spec_path: Option<String>,
    /// The stored secret: write-only, present exactly when the kind needs one.
    pub token: Option<Secret>,
    /// The approved origin, with an optional fixed path prefix.
    pub base_url: String,
    /// Whether a plain-http internal upstream is approved.
    pub allow_internal_http: bool,
    /// PEM CA bundle path on the broker host; never disables TLS checks.
    pub ca_file: Option<String>,
    /// The source key, unique per owner.
    pub source_key: Name,
}

impl SourceCreate {
    fn validate(&self) -> Result<(), SourceModelError> {
        validate_core(&self.auth, self.token.as_ref())?;
        validate_source_body(
            &self.base_url,
            self.allow_internal_http,
            self.ca_file.as_deref(),
        )?;
        if needs_secret(&self.auth) && self.token.is_none() {
            return Err(SourceModelError::Refused(
                "a source of this kind needs its secret",
            ));
        }
        Ok(())
    }
}

/// An operator (platform) source update (`models.py:218-219`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::SourceUpdate")]
pub struct SourceUpdate {
    /// How the source authenticates.
    pub auth: SourceAuth,
    /// The retry idempotency header, one of the two literals.
    pub idempotency_header: Option<IdempotencyHeader>,
    /// Maximum request bytes, 1 to 10485760.
    pub max_request_bytes: Option<u32>,
    /// Maximum response bytes, 1 to 10485760.
    pub max_response_bytes: Option<u32>,
    /// The OpenAPI document path, relative to `base_url` (same origin only).
    pub spec_path: Option<String>,
    /// The stored secret: write-only, present exactly when the kind needs one.
    pub token: Option<Secret>,
    /// The approved origin, with an optional fixed path prefix.
    pub base_url: String,
    /// Whether a plain-http internal upstream is approved.
    pub allow_internal_http: bool,
    /// PEM CA bundle path on the broker host; never disables TLS checks.
    pub ca_file: Option<String>,
    /// The revision the caller read, at least 1.
    pub expected_revision: u64,
}

impl SourceUpdate {
    fn validate(&self) -> Result<(), SourceModelError> {
        validate_core(&self.auth, self.token.as_ref())?;
        validate_source_body(
            &self.base_url,
            self.allow_internal_http,
            self.ca_file.as_deref(),
        )
    }
}

/// A tenant's own source create: public https only, no private CA, no plain http
/// (`models.py:233-240`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::TenantSourceCreate")]
pub struct TenantSourceCreate {
    /// How the source authenticates.
    pub auth: SourceAuth,
    /// The retry idempotency header, one of the two literals.
    pub idempotency_header: Option<IdempotencyHeader>,
    /// Maximum request bytes, 1 to 10485760.
    pub max_request_bytes: Option<u32>,
    /// Maximum response bytes, 1 to 10485760.
    pub max_response_bytes: Option<u32>,
    /// The OpenAPI document path, relative to `base_url` (same origin only).
    pub spec_path: Option<String>,
    /// The stored secret: write-only, present exactly when the kind needs one.
    pub token: Option<Secret>,
    /// The public https origin, with an optional path prefix.
    pub base_url: String,
    /// The source key, unique per owner.
    pub source_key: Name,
}

impl TenantSourceCreate {
    fn validate(&self) -> Result<(), SourceModelError> {
        validate_core(&self.auth, self.token.as_ref())?;
        validate_tenant_body(&self.base_url)?;
        if needs_secret(&self.auth) && self.token.is_none() {
            return Err(SourceModelError::Refused(
                "a source of this kind needs its secret",
            ));
        }
        Ok(())
    }
}

/// A tenant's own source update (`models.py:243-244`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::TenantSourceUpdate")]
pub struct TenantSourceUpdate {
    /// How the source authenticates.
    pub auth: SourceAuth,
    /// The retry idempotency header, one of the two literals.
    pub idempotency_header: Option<IdempotencyHeader>,
    /// Maximum request bytes, 1 to 10485760.
    pub max_request_bytes: Option<u32>,
    /// Maximum response bytes, 1 to 10485760.
    pub max_response_bytes: Option<u32>,
    /// The OpenAPI document path, relative to `base_url` (same origin only).
    pub spec_path: Option<String>,
    /// The stored secret: write-only, present exactly when the kind needs one.
    pub token: Option<Secret>,
    /// The public https origin, with an optional path prefix.
    pub base_url: String,
    /// The revision the caller read, at least 1.
    pub expected_revision: u64,
}

impl TenantSourceUpdate {
    fn validate(&self) -> Result<(), SourceModelError> {
        validate_core(&self.auth, self.token.as_ref())?;
        validate_tenant_body(&self.base_url)
    }
}

/// Replace one source's stored secret (`models.py:247-257`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TokenUpdate {
    /// The new secret; `valid_secret`'s charset, because a basic password may contain spaces.
    #[serde(deserialize_with = "stored_secret")]
    pub token: Secret,
    /// The revision the caller read, at least 1.
    #[serde(deserialize_with = "revision_at_least_one")]
    pub expected_revision: u64,
}

/// A state change guarded only by the revision the caller read (`models.py:260-261`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionOnly {
    /// The revision the caller read, at least 1.
    #[serde(deserialize_with = "revision_at_least_one")]
    pub expected_revision: u64,
}

/// Everything an operator may read back: no token, no ciphertext (`models.py:264-285`).
///
/// The view's bounds and paths are plain values, as the reference declares them, because a
/// stored row was validated at write time. `created_by` and `updated_by` are free-form objects.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceView {
    /// A UUIDv7 identity.
    pub source_id: Uuid7,
    /// The owning tenant.
    pub owner_tenant_id: AuthorityId,
    /// The source key.
    pub source_key: Name,
    /// The row's revision.
    pub revision: i64,
    /// The lifecycle status.
    pub status: SourceStatus,
    /// The registered origin.
    pub base_url: String,
    /// Whether a plain-http internal upstream was approved.
    pub allow_internal_http: bool,
    /// How the source authenticates.
    pub auth: SourceAuth,
    /// Whether a sealed secret is stored.
    pub has_token: bool,
    /// When the secret was last set.
    pub token_set_at: Option<String>,
    /// The OpenAPI document path, when one was registered.
    pub spec_path: Option<String>,
    /// The retry idempotency header, when one was registered.
    pub idempotency_header: Option<IdempotencyHeader>,
    /// The PEM CA bundle path, when one was registered.
    pub ca_file: Option<String>,
    /// Maximum request bytes, when a source-specific bound was registered.
    pub max_request_bytes: Option<i64>,
    /// Maximum response bytes, when a source-specific bound was registered.
    pub max_response_bytes: Option<i64>,
    /// Who created the source.
    pub created_by: Map<String, Value>,
    /// Who last changed the source.
    pub updated_by: Map<String, Value>,
    /// Creation instant.
    pub created_at: String,
    /// Last-change instant.
    pub updated_at: String,
}

// ── shared field shapes ───────────────────────────────────────────────────────────────────

fn bounded_text<'de, D: Deserializer<'de>>(
    deserializer: D,
    min: usize,
    max: usize,
    message: &'static str,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    let length = value.chars().count();
    if length < min || length > max {
        Err(D::Error::custom(message))
    } else {
        Ok(value)
    }
}

/// `Field(min_length=1, max_length=512)` for a source `base_url` (`models.py:195,225`).
fn text_1_512<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 512, "base_url must be 1 to 512 characters")
}

/// `Field(max_length=512)` for an optional `ca_file` (`models.py:198`).
fn optional_text_512<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => {
            if value.chars().count() <= 512 {
                Ok(Some(value))
            } else {
                Err(D::Error::custom("ca_file must be at most 512 characters"))
            }
        }
        None => Ok(None),
    }
}

/// `Limit = Annotated[int, Field(gt=0, le=10485760)]` as an optional field (`models.py:120`).
fn optional_bytes_10m<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u32>, D::Error> {
    match Option::<u64>::deserialize(deserializer)? {
        Some(value) if (1..=10_485_760).contains(&value) => Ok(Some(value as u32)),
        Some(_) => Err(D::Error::custom("byte limit must be 1 to 10485760")),
        None => Ok(None),
    }
}

/// `SpecPath = Annotated[str, Field(pattern=r"^/[A-Za-z0-9._~/-]{0,255}$")]` (`models.py:121`).
fn optional_spec_path<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^/[A-Za-z0-9._~/-]{0,255}$").expect("the spec path pattern compiles")
    });
    match Option::<String>::deserialize(deserializer)? {
        Some(value) if PATTERN.is_match(&value) => Ok(Some(value)),
        Some(_) => Err(D::Error::custom("invalid spec path")),
        None => Ok(None),
    }
}

/// `Annotated[int, Field(gt=0)]` for `expected_revision` (`models.py:219,244,251,261`).
fn revision_at_least_one<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value >= 1 {
        Ok(value)
    } else {
        Err(D::Error::custom("expected_revision must be greater than 0"))
    }
}

/// The reference's `TokenUpdate.printable` (`models.py:253-257`): `valid_secret`, because a
/// replacement secret is not yet tied to a kind.
fn stored_secret<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Secret, D::Error> {
    let value = String::deserialize(deserializer)?;
    valid_secret(&value).map_err(|error| D::Error::custom(error.to_string()))?;
    Ok(Secret::new(value))
}

// ── wire models: strict field shapes, then the model validators ────────────────────────────

mod wire {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SourceCreate {
        pub auth: SourceAuth,
        #[serde(default)]
        pub idempotency_header: Option<IdempotencyHeader>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_request_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_response_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_spec_path")]
        pub spec_path: Option<String>,
        #[serde(default)]
        pub token: Option<Secret>,
        #[serde(deserialize_with = "text_1_512")]
        pub base_url: String,
        #[serde(default)]
        pub allow_internal_http: bool,
        #[serde(default, deserialize_with = "optional_text_512")]
        pub ca_file: Option<String>,
        pub source_key: Name,
    }

    impl TryFrom<SourceCreate> for super::SourceCreate {
        type Error = SourceModelError;

        fn try_from(wire: SourceCreate) -> Result<Self, Self::Error> {
            let model = Self {
                auth: wire.auth,
                idempotency_header: wire.idempotency_header,
                max_request_bytes: wire.max_request_bytes,
                max_response_bytes: wire.max_response_bytes,
                spec_path: wire.spec_path,
                token: wire.token,
                base_url: wire.base_url,
                allow_internal_http: wire.allow_internal_http,
                ca_file: wire.ca_file,
                source_key: wire.source_key,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct SourceUpdate {
        pub auth: SourceAuth,
        #[serde(default)]
        pub idempotency_header: Option<IdempotencyHeader>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_request_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_response_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_spec_path")]
        pub spec_path: Option<String>,
        #[serde(default)]
        pub token: Option<Secret>,
        #[serde(deserialize_with = "text_1_512")]
        pub base_url: String,
        #[serde(default)]
        pub allow_internal_http: bool,
        #[serde(default, deserialize_with = "optional_text_512")]
        pub ca_file: Option<String>,
        #[serde(deserialize_with = "revision_at_least_one")]
        pub expected_revision: u64,
    }

    impl TryFrom<SourceUpdate> for super::SourceUpdate {
        type Error = SourceModelError;

        fn try_from(wire: SourceUpdate) -> Result<Self, Self::Error> {
            let model = Self {
                auth: wire.auth,
                idempotency_header: wire.idempotency_header,
                max_request_bytes: wire.max_request_bytes,
                max_response_bytes: wire.max_response_bytes,
                spec_path: wire.spec_path,
                token: wire.token,
                base_url: wire.base_url,
                allow_internal_http: wire.allow_internal_http,
                ca_file: wire.ca_file,
                expected_revision: wire.expected_revision,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TenantSourceCreate {
        pub auth: SourceAuth,
        #[serde(default)]
        pub idempotency_header: Option<IdempotencyHeader>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_request_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_response_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_spec_path")]
        pub spec_path: Option<String>,
        #[serde(default)]
        pub token: Option<Secret>,
        #[serde(deserialize_with = "text_1_512")]
        pub base_url: String,
        pub source_key: Name,
    }

    impl TryFrom<TenantSourceCreate> for super::TenantSourceCreate {
        type Error = SourceModelError;

        fn try_from(wire: TenantSourceCreate) -> Result<Self, Self::Error> {
            let model = Self {
                auth: wire.auth,
                idempotency_header: wire.idempotency_header,
                max_request_bytes: wire.max_request_bytes,
                max_response_bytes: wire.max_response_bytes,
                spec_path: wire.spec_path,
                token: wire.token,
                base_url: wire.base_url,
                source_key: wire.source_key,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct TenantSourceUpdate {
        pub auth: SourceAuth,
        #[serde(default)]
        pub idempotency_header: Option<IdempotencyHeader>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_request_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_bytes_10m")]
        pub max_response_bytes: Option<u32>,
        #[serde(default, deserialize_with = "optional_spec_path")]
        pub spec_path: Option<String>,
        #[serde(default)]
        pub token: Option<Secret>,
        #[serde(deserialize_with = "text_1_512")]
        pub base_url: String,
        #[serde(deserialize_with = "revision_at_least_one")]
        pub expected_revision: u64,
    }

    impl TryFrom<TenantSourceUpdate> for super::TenantSourceUpdate {
        type Error = SourceModelError;

        fn try_from(wire: TenantSourceUpdate) -> Result<Self, Self::Error> {
            let model = Self {
                auth: wire.auth,
                idempotency_header: wire.idempotency_header,
                max_request_bytes: wire.max_request_bytes,
                max_response_bytes: wire.max_response_bytes,
                spec_path: wire.spec_path,
                token: wire.token,
                base_url: wire.base_url,
                expected_revision: wire.expected_revision,
            };
            model.validate()?;
            Ok(model)
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use crate::catalog::models::AuthAdapter;

    use super::{
        FORBIDDEN_HEADERS, INTERNAL_SUFFIXES, IdempotencyHeader, LicenceAuth, SECRET_REDACTION,
        SECRETLESS_KINDS, SourceAuth, SourceCreate, SourceUpdate, SourceView, TenantSourceCreate,
        TenantSourceUpdate, TenantUrlError, TokenUpdate, checked_secret, checked_tenant_url,
        needs_secret,
    };

    fn parse_create(body: serde_json::Value) -> Result<SourceCreate, serde_json::Error> {
        serde_json::from_value(body)
    }

    fn create_body(auth: serde_json::Value) -> serde_json::Value {
        json!({
            "auth": auth,
            "base_url": "https://api.example.com",
            "source_key": "billing",
        })
    }

    #[test]
    fn every_auth_kind_round_trips_and_keeps_its_discriminator() {
        let cases = [
            (json!({"kind": "none"}), "none"),
            (json!({"kind": "licence", "app_key": "coding"}), "licence"),
            (json!({"kind": "static_bearer"}), "static_bearer"),
            (
                json!({"kind": "static_header", "header": "X-Api-Key"}),
                "static_header",
            ),
            (
                json!({"kind": "query_param", "param": "api_key"}),
                "query_param",
            ),
            (json!({"kind": "basic", "username": "svc"}), "basic"),
            (
                json!({
                    "kind": "oauth2_client_credentials",
                    "token_url": "https://auth.example.com/token",
                    "client_id": "client-1",
                }),
                "oauth2_client_credentials",
            ),
        ];
        for (body, kind) in cases {
            let auth: SourceAuth = serde_json::from_value(body).expect("the auth kind parses");
            assert_eq!(auth.kind(), kind);
            let value = serde_json::to_value(&auth).expect("the auth kind serialises");
            assert_eq!(value["kind"], kind);
            let reparsed: SourceAuth =
                serde_json::from_value(value).expect("the auth kind round-trips");
            assert_eq!(reparsed, auth);
        }
    }

    #[test]
    fn the_auth_defaults_are_the_references() {
        let licence: SourceAuth = serde_json::from_value(json!({
            "kind": "licence",
            "app_key": "coding",
            "bundle": "coding-bundle",
        }))
        .expect("licence");
        assert_eq!(
            serde_json::to_value(&licence).expect("serialise"),
            json!({
                "kind": "licence",
                "app_key": "coding",
                "scheme": "bearer",
                "bundle": "coding-bundle",
            })
        );

        let oauth: SourceAuth = serde_json::from_value(json!({
            "kind": "oauth2_client_credentials",
            "token_url": "https://auth.example.com/token",
            "client_id": "client-1",
        }))
        .expect("oauth");
        assert_eq!(
            serde_json::to_value(&oauth).expect("serialise"),
            json!({
                "kind": "oauth2_client_credentials",
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "scope": null,
                "audience": null,
                "client_auth": "basic",
            })
        );
    }

    #[test]
    fn a_static_header_is_pattern_checked_and_reserved_names_are_refused() {
        for header in [
            "Host",
            "Content-Type",
            "Transfer-Encoding",
            "Authorization",
            "aUtHoRiZaTiOn",
            "X-Idempotency-Key",
            "Idempotency-Key",
        ] {
            assert!(
                serde_json::from_value::<SourceAuth>(
                    json!({"kind": "static_header", "header": header})
                )
                .is_err(),
                "{header} must be reserved"
            );
        }
        for header in ["X-Api-Key", "x-api-key", "A1"] {
            assert!(
                serde_json::from_value::<SourceAuth>(
                    json!({"kind": "static_header", "header": header})
                )
                .is_ok(),
                "{header} must be accepted"
            );
        }
        for header in ["1bad", "a b", "x_underscore"] {
            assert!(
                serde_json::from_value::<SourceAuth>(
                    json!({"kind": "static_header", "header": header})
                )
                .is_err(),
                "{header} must be refused"
            );
        }
    }

    #[test]
    fn query_params_and_basic_usernames_are_pattern_checked() {
        assert!(
            serde_json::from_value::<SourceAuth>(
                json!({"kind": "query_param", "param": "api_key"})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<SourceAuth>(json!({"kind": "query_param", "param": "1key"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<SourceAuth>(json!({"kind": "query_param", "param": "a b"}))
                .is_err()
        );
        // Space is allowed; `:` is not (the username is the Basic user-id).
        assert!(
            serde_json::from_value::<SourceAuth>(json!({"kind": "basic", "username": "svc user"}))
                .is_ok()
        );
        assert!(
            serde_json::from_value::<SourceAuth>(json!({"kind": "basic", "username": "a:b"}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<SourceAuth>(json!({"kind": "basic", "username": ""})).is_err()
        );
    }

    #[test]
    fn an_oauth_token_endpoint_is_a_public_https_url() {
        let oauth = |extra: serde_json::Value| {
            let mut body = json!({"kind": "oauth2_client_credentials"});
            for (key, value) in extra.as_object().expect("object") {
                body[key.as_str()] = value.clone();
            }
            serde_json::from_value::<SourceAuth>(body)
        };
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
            }))
            .is_ok()
        );
        assert!(
            oauth(json!({
                "token_url": "http://auth.example.com/token",
                "client_id": "client-1",
            }))
            .is_err()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.internal/token",
                "client_id": "client-1",
            }))
            .is_err()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client id",
            }))
            .is_err()
        );
        // A scope is one or more space-separated printable tokens; a double space is refused.
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "scope": "read write offline_access",
            }))
            .is_ok()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "scope": "read  write",
            }))
            .is_err()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "audience": "api audience",
            }))
            .is_err()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "client_auth": "post",
            }))
            .is_ok()
        );
        assert!(
            oauth(json!({
                "token_url": "https://auth.example.com/token",
                "client_id": "client-1",
                "client_auth": "digest",
            }))
            .is_err()
        );
    }

    #[test]
    fn a_token_is_write_only() {
        let mut body = create_body(json!({"kind": "static_bearer"}));
        body["token"] = json!("synthetic-token");
        let create = parse_create(body).expect("a static bearer source");
        assert_eq!(
            serde_json::to_value(&create).expect("serialise")["token"],
            SECRET_REDACTION
        );
        let debug = format!("{create:?}");
        assert!(!debug.contains("synthetic-token"), "{debug}");
        assert!(debug.contains(SECRET_REDACTION), "{debug}");

        // Absent stays null, exactly as the reference's `None` does.
        let create = parse_create(create_body(json!({"kind": "none"}))).expect("a public source");
        assert_eq!(
            serde_json::to_value(&create).expect("serialise")["token"],
            serde_json::Value::Null
        );
    }

    #[test]
    fn the_token_rule_follows_the_auth_kind() {
        // A secret-bearing kind needs one.
        assert!(parse_create(create_body(json!({"kind": "static_bearer"}))).is_err());
        // A secretless kind carries none.
        let mut body = create_body(json!({"kind": "none"}));
        body["token"] = json!("synthetic-token");
        assert!(parse_create(body).is_err());
        // A licence source needs no stored secret.
        assert!(parse_create(create_body(json!({"kind": "licence", "app_key": "coding"}))).is_ok());
        // A basic password may contain spaces; every other kind's secret may not.
        let mut body = create_body(json!({"kind": "basic", "username": "svc"}));
        body["token"] = json!("pa ss");
        assert!(parse_create(body).is_ok());
        let mut body = create_body(json!({"kind": "static_bearer"}));
        body["token"] = json!("pa ss");
        assert!(parse_create(body).is_err());
        // A control character is refused for every kind.
        let mut body = create_body(json!({"kind": "basic", "username": "svc"}));
        body["token"] = json!("tab\there");
        assert!(parse_create(body).is_err());
    }

    #[test]
    fn checked_secret_uses_the_basic_charset_only_for_basic() {
        assert_eq!(checked_secret("basic", "pa ss"), Ok("pa ss"));
        assert!(checked_secret("basic", "tab\there").is_err());
        assert!(checked_secret("static_bearer", "pa ss").is_err());
        assert!(checked_secret("query_param", "").is_err());
    }

    #[test]
    fn a_platform_source_accepts_the_guard_origin_and_its_bounds() {
        let mut body = create_body(json!({"kind": "none"}));
        body["allow_internal_http"] = json!(true);
        body["ca_file"] = json!("/etc/ssl/internal-ca.pem");
        body["base_url"] = json!("http://api.cluster.local:8080");
        let create = parse_create(body).expect("an approved internal origin");
        assert!(create.allow_internal_http);
        assert_eq!(create.ca_file.as_deref(), Some("/etc/ssl/internal-ca.pem"));

        let mut body = create_body(json!({"kind": "none"}));
        body["base_url"] = json!("https://api.example.com/v1");
        body["idempotency_header"] = json!("X-Idempotency-Key");
        body["max_request_bytes"] = json!(10_485_760);
        body["max_response_bytes"] = json!(1);
        body["spec_path"] = json!("/openapi.json");
        let create = parse_create(body).expect("a bounded source");
        assert_eq!(create.max_request_bytes, Some(10_485_760));
        assert_eq!(create.max_response_bytes, Some(1));
        assert_eq!(create.spec_path.as_deref(), Some("/openapi.json"));
        assert_eq!(
            create.idempotency_header,
            Some(IdempotencyHeader::XIdempotencyKey)
        );

        for (field, value) in [
            ("max_request_bytes", json!(0)),
            ("max_request_bytes", json!(10_485_761)),
            ("max_response_bytes", json!(0)),
            ("spec_path", json!("openapi.json")),
            ("idempotency_header", json!("idempotency-key")),
            ("ca_file", json!("relative/ca.pem")),
            ("base_url", json!("http://api.example.com")),
            ("base_url", json!("ftp://api.example.com")),
        ] {
            let mut body = create_body(json!({"kind": "none"}));
            body[field] = value;
            assert!(parse_create(body).is_err(), "{field} must be refused");
        }
    }

    #[test]
    fn a_tenant_source_is_public_https_only() {
        let mut body = json!({
            "auth": {"kind": "none"},
            "base_url": "https://api.example.com/a/b",
            "source_key": "public",
        });
        assert!(serde_json::from_value::<TenantSourceCreate>(body.clone()).is_ok());

        for base_url in [
            "http://api.example.com",
            "https://api.internal",
            "https://api.svc",
            "https://api.cluster.local",
            "https://localhost",
            "https://10.0.0.1",
            "https://api",
            "https://api..example.com",
            "https://api.example.com/../x",
            "https://api.example.com#f",
        ] {
            body["base_url"] = json!(base_url);
            assert!(
                serde_json::from_value::<TenantSourceCreate>(body.clone()).is_err(),
                "{base_url} must be refused"
            );
        }

        // No platform-only fields: a tenant may not approve private http or a private CA.
        let mut extras = json!({
            "auth": {"kind": "none"},
            "base_url": "https://api.example.com",
            "source_key": "public",
            "allow_internal_http": true,
        });
        assert!(serde_json::from_value::<TenantSourceCreate>(extras.clone()).is_err());
        let _ = extras
            .as_object_mut()
            .expect("object")
            .remove("allow_internal_http");
        extras["ca_file"] = json!("/etc/ssl/ca.pem");
        assert!(serde_json::from_value::<TenantSourceCreate>(extras).is_err());

        // A tenant source needs its secret exactly like a platform one.
        let mut body = json!({
            "auth": {"kind": "static_bearer"},
            "base_url": "https://api.example.com",
            "source_key": "billing",
        });
        assert!(serde_json::from_value::<TenantSourceCreate>(body.clone()).is_err());
        body["token"] = json!("synthetic-token");
        assert!(serde_json::from_value::<TenantSourceCreate>(body).is_ok());

        // An update carries the revision and the same public-https rule.
        let update = json!({
            "auth": {"kind": "none"},
            "base_url": "https://api.example.com",
            "expected_revision": 2,
        });
        assert!(serde_json::from_value::<TenantSourceUpdate>(update.clone()).is_ok());
        let mut bad = update;
        bad["base_url"] = json!("https://api.internal");
        assert!(serde_json::from_value::<TenantSourceUpdate>(bad).is_err());
    }

    #[test]
    fn an_update_carries_the_revision_it_read() {
        let update = json!({
            "auth": {"kind": "none"},
            "base_url": "https://api.example.com",
            "expected_revision": 3,
        });
        let parsed: SourceUpdate = serde_json::from_value(update).expect("a revisioned update");
        assert_eq!(parsed.expected_revision, 3);

        // The update body has no `source_key`; adding one is an unknown field.
        let mut body = json!({
            "auth": {"kind": "none"},
            "base_url": "https://api.example.com",
            "expected_revision": 3,
            "source_key": "billing",
        });
        assert!(serde_json::from_value::<SourceUpdate>(body.clone()).is_err());
        let _ = body.as_object_mut().expect("object").remove("source_key");
        body["expected_revision"] = json!(0);
        assert!(serde_json::from_value::<SourceUpdate>(body).is_err());
    }

    #[test]
    fn a_token_update_validates_the_secret_and_the_revision() {
        assert!(
            serde_json::from_value::<TokenUpdate>(
                json!({"token": "a b c", "expected_revision": 2})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<TokenUpdate>(json!({"token": "a\tb", "expected_revision": 2}))
                .is_err()
        );
        assert!(
            serde_json::from_value::<TokenUpdate>(json!({"token": "tok", "expected_revision": 0}))
                .is_err()
        );
        assert!(serde_json::from_value::<TokenUpdate>(json!({"token": "tok"})).is_err());

        let update: TokenUpdate =
            serde_json::from_value(json!({"token": "synthetic-token", "expected_revision": 2}))
                .expect("a token update");
        assert_eq!(
            serde_json::to_value(&update).expect("serialise"),
            json!({"token": SECRET_REDACTION, "expected_revision": 2})
        );
        assert!(!format!("{update:?}").contains("synthetic-token"));
    }

    #[test]
    fn a_source_view_carries_no_token() {
        let view = json!({
            "source_id": "0190b6e2-1234-7abc-8def-0123456789ab",
            "owner_tenant_id": "0190b6e2-1234-7abc-8def-0123456789ac",
            "source_key": "billing",
            "revision": 3,
            "status": "active",
            "base_url": "https://api.example.com",
            "allow_internal_http": false,
            "auth": {"kind": "static_bearer"},
            "has_token": true,
            "token_set_at": "2026-11-15T10:00:00Z",
            "spec_path": "/openapi.json",
            "idempotency_header": "Idempotency-Key",
            "ca_file": null,
            "max_request_bytes": 1024,
            "max_response_bytes": null,
            "created_by": {"subject": "operator"},
            "updated_by": {},
            "created_at": "2026-11-15T10:00:00Z",
            "updated_at": "2026-11-15T10:00:00Z",
        });
        let parsed: SourceView = serde_json::from_value(view.clone()).expect("a source view");
        assert!(parsed.has_token);
        let mut with_token = view;
        with_token["token"] = json!("synthetic-token");
        assert!(serde_json::from_value::<SourceView>(with_token).is_err());
    }

    #[test]
    fn the_licence_adapter_follows_the_scheme() {
        let bearer: LicenceAuth =
            serde_json::from_value(json!({"kind": "licence", "app_key": "coding"}))
                .expect("a bearer licence");
        assert_eq!(bearer.adapter(), AuthAdapter::LicenseBearer);
        let header: LicenceAuth = serde_json::from_value(json!({
            "kind": "licence",
            "app_key": "coding",
            "scheme": "x_tenant_id_bearer",
        }))
        .expect("a header licence");
        assert_eq!(header.adapter(), AuthAdapter::LicenseHeader);
    }

    #[test]
    fn the_fixed_sets_are_the_references() {
        assert_eq!(SECRETLESS_KINDS, ["licence", "none"]);
        assert_eq!(INTERNAL_SUFFIXES.len(), 6);
        assert_eq!(FORBIDDEN_HEADERS.len(), 11);
        assert!(!FORBIDDEN_HEADERS.contains(&"authorization"));
        let bearer: SourceAuth =
            serde_json::from_value(json!({"kind": "static_bearer"})).expect("bearer");
        assert!(needs_secret(&bearer));
        let public: SourceAuth =
            serde_json::from_value(json!({"kind": "licence", "app_key": "coding"}))
                .expect("licence");
        assert!(!needs_secret(&public));
    }

    #[test]
    fn a_tenant_url_is_split_like_urlsplit() {
        // Accepted shapes: case-insensitive scheme and host, a path when allowed, and empty
        // delimiters (the reference tests `url.query`/`url.fragment` for truthiness).
        for value in [
            "https://api.example.com",
            "https://API.Example.COM",
            " https://api.example.com",
            "https://api.example.com\t",
            "https://api.example.com/a\tb",
            "https://api.example.com?",
            "https://api.example.com#",
            "https://api.example.com:",
            "https://api.example.com:8443/a/b/",
        ] {
            assert_eq!(checked_tenant_url(value, true), Ok(value), "{value}");
        }
        assert!(checked_tenant_url("https://api.example.com/a", false).is_err());
        assert_eq!(
            checked_tenant_url("https://api.example.com/a", false),
            Err(TenantUrlError::NotPublicHttps)
        );

        // `url.port` refuses a port it cannot cast, or one above 65535; zero reaches the policy.
        assert_eq!(
            checked_tenant_url("https://api.example.com:65536", true),
            Err(TenantUrlError::InvalidUrl)
        );
        assert_eq!(
            checked_tenant_url("https://api.example.com:abc", true),
            Err(TenantUrlError::InvalidUrl)
        );
        assert_eq!(
            checked_tenant_url("https://api.example.com:0", true),
            Err(TenantUrlError::NotPublicHttps)
        );
        assert_eq!(
            checked_tenant_url("https://[::1", true),
            Err(TenantUrlError::InvalidUrl)
        );
        assert_eq!(
            checked_tenant_url("https://[::1]", true),
            Err(TenantUrlError::NotPublicHttps)
        );
        // Only an IPv6 or IPvFuture host may be bracketed (`_check_bracketed_host`); a bracketed
        // DNS name or IPv4 address makes `urlsplit` itself raise.
        assert_eq!(
            checked_tenant_url("https://[api.example.com]", true),
            Err(TenantUrlError::InvalidUrl)
        );
        assert_eq!(
            checked_tenant_url("https://[10.0.0.1]", true),
            Err(TenantUrlError::InvalidUrl)
        );
        assert_eq!(
            checked_tenant_url("https://[zz]", true),
            Err(TenantUrlError::InvalidUrl)
        );
        // IPvFuture is bracketable, and its text is then a legal public host.
        assert_eq!(
            checked_tenant_url("https://[v1.example]", true),
            Ok("https://[v1.example]")
        );

        for value in [
            "https://api%2Eexample.com",
            "https://api.example.com\\x",
            "https://例え.jp",
            "https://api.example.com/../x",
            "https://api.example.com/./x",
            "https:////api.example.com",
            "https://api.example.com/path with space",
        ] {
            assert_eq!(
                checked_tenant_url(value, true),
                Err(TenantUrlError::NotPublicHttps),
                "{value}"
            );
        }
    }
}
