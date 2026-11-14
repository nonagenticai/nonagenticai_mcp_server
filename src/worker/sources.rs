//! Registered downstream sources and their sealed secrets (slice S5).
//!
//! Port of the reference `src/sources/registry.py`, the `auth` contract and its field checks in
//! `src/sources/models.py`, the tenant URL syntax check in the same file, and
//! `src/sources/crypto.py`. The registry is read at call time, never from a file: a source is
//! identified by `(owner, key)`, so a tenant source that reuses a platform key is never used for
//! a platform service and vice versa. A stored secret is decrypted only in this process, per
//! call, with the source id as associated data — a ciphertext copied onto another source row
//! fails authentication instead of silently sending one upstream's credential to another.
//!
//! Two reference behaviours are deliberately NOT ported here and belong to the slice that owns
//! the egress client: the operator host allow-list (`MCP_SOURCE_ALLOWED_HOSTS`, absent from
//! [`crate::config::WorkerSettings`]) and the resolved-address pinning of `src/broker/egress.py`.
//! The tenant-side syntax check the reference performs before those (`checked_tenant_url`) is
//! ported, because it needs no settings. The reference's short-TTL row cache is not ported
//! either: every call reads the row, so a disabled source is denied immediately.
//!
//! Unlike the reference this port has no `secrecy` crate: the token is a `String` in
//! [`ResolvedSource`], whose `Debug` implementation redacts it. Nothing here logs a secret.

use std::fmt;
use std::sync::OnceLock;

use regex::Regex;
use serde_json::{Map, Value};
use sqlx::{PgPool, Row};

use crate::auth::Rfc4122Uuid;

/// Headers a static source may not set: framing and routing belong to the HTTP client
/// (`models.py:22-36`).
const FORBIDDEN_HEADERS: [&str; 11] = [
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

/// Hostnames a tenant may never register (cluster-internal names), `models.py:123`.
const INTERNAL_SUFFIXES: [&str; 6] = [
    ".local",
    ".internal",
    ".svc",
    ".cluster.local",
    ".localhost",
    ".lan",
];

/// The token blob's nonce prefix (`crypto.py:19`). The remainder is the AES-GCM sealing.
const NONCE_BYTES: usize = 12;

/// The stored secret of one source, sealed with AES-256-GCM (`src/sources/crypto.py`).
///
/// The associated data is the source id's 16 bytes, so a row whose ciphertext was swapped in
/// from another source fails authentication. Kept as a submodule of this file: the write path
/// (registration) is a different slice; only [`encrypt`] and [`decrypt`] are needed here.
pub mod crypto {
    // `aes-gcm` 0.10 is the latest release and still exposes its nonce through
    // `generic_array`, which upstream has deprecated ahead of 0.11. The alternative (moving to
    // an unreleased 0.11) would put an RC in the runtime image; the type is stable and the
    // dependency is pinned, so the deprecation is accepted here and nowhere else.
    #![allow(deprecated)]

    use super::{NONCE_BYTES, SourceError, valid_secret};
    use aes_gcm::aead::generic_array::GenericArray;
    use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
    use aes_gcm::{AeadCore as _, Aes256Gcm};
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE;

    use crate::auth::Rfc4122Uuid;

    /// A 32-byte key from unpadded or padded base64url; raises like `decode_key`.
    ///
    /// The alphabet is the base64url one, exactly as `config.rs` already validates
    /// `MCP_SOURCE_SECRET_KEY`, so a key accepted at startup is accepted here.
    pub fn decode_key(value: &str) -> Result<[u8; 32], SourceError> {
        let mut padded = value.trim().to_owned();
        match padded.len() % 4 {
            0 => {}
            2 => padded.push_str("=="),
            3 => padded.push('='),
            _ => return Err(SourceError::Denied("source secret key must be base64url")),
        }
        let key = URL_SAFE
            .decode(padded.as_bytes())
            .map_err(|_| SourceError::Denied("source secret key must be base64url"))?;
        <[u8; 32]>::try_from(key.as_slice())
            .map_err(|_| SourceError::Denied("source secret key must be 32 bytes"))
    }

    /// The source id's 16 bytes, the AEAD's associated data (`uuid.UUID.bytes`).
    fn associated(source_id: &Rfc4122Uuid) -> [u8; 16] {
        // `Rfc4122Uuid` only exists through its canonical parser, whose `Display` is the
        // lowercase hyphenated form `uuid::Uuid` also parses.
        *uuid::Uuid::parse_str(&source_id.to_string())
            .expect("a parsed identity renders canonically")
            .as_bytes()
    }

    /// Seal `token` for `source_id`, nonce-prefixed. The registration slice writes these; the
    /// tests use it to build negative cases beside the oracle's own fixture.
    pub fn encrypt(
        key: &[u8; 32],
        source_id: &Rfc4122Uuid,
        token: &str,
    ) -> Result<Vec<u8>, SourceError> {
        if !valid_secret(token) {
            return Err(SourceError::Denied("invalid credential material"));
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SourceError::Crypto)?;
        let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
        let sealed = cipher
            .encrypt(
                &nonce,
                Payload {
                    msg: token.as_bytes(),
                    aad: &associated(source_id),
                },
            )
            .map_err(|_| SourceError::Crypto)?;
        let mut blob = nonce.to_vec();
        blob.extend_from_slice(&sealed);
        Ok(blob)
    }

    /// Open one stored secret. Fails closed for a swapped row, a truncated blob or any
    /// corruption (`crypto.py:55-65`); a missing key never reaches here.
    pub fn decrypt(
        key: &[u8; 32],
        source_id: &Rfc4122Uuid,
        blob: &[u8],
    ) -> Result<String, SourceError> {
        if blob.len() <= NONCE_BYTES {
            return Err(SourceError::Denied("source credential unavailable"));
        }
        let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SourceError::Crypto)?;
        let (nonce, sealed) = blob.split_at(NONCE_BYTES);
        let plain = cipher
            .decrypt(
                GenericArray::from_slice(nonce),
                Payload {
                    msg: sealed,
                    aad: &associated(source_id),
                },
            )
            .map_err(|_| SourceError::Crypto)?;
        let text = std::str::from_utf8(&plain).map_err(|_| SourceError::Crypto)?;
        if !valid_secret(text) {
            return Err(SourceError::Denied("source credential unavailable"));
        }
        Ok(text.to_owned())
    }
}

/// Why a source could not be resolved. Never carries credential material.
#[derive(Debug)]
pub enum SourceError {
    /// Missing, disabled, not owned by the caller, or a credential that cannot be used.
    Denied(&'static str),
    /// The registry read failed.
    Store(sqlx::Error),
    /// The stored blob failed authentication (a swapped row or corruption).
    Crypto,
}

impl fmt::Display for SourceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "source denied: {reason}"),
            Self::Store(error) => write!(f, "source store: {error}"),
            Self::Crypto => write!(f, "source credential unavailable"),
        }
    }
}

impl std::error::Error for SourceError {}

impl From<sqlx::Error> for SourceError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error)
    }
}

/// A stored secret's charset: printable ASCII without spaces (`crypto.py:33-38`).
pub(crate) fn valid_token(value: &str) -> bool {
    (1..=4096).contains(&value.len()) && value.bytes().all(|byte| (33..=126).contains(&byte))
}

/// A stored secret's charset for a basic password: printable ASCII, spaces allowed
/// (`crypto.py:40-44`).
pub(crate) fn valid_secret(value: &str) -> bool {
    (1..=4096).contains(&value.len()) && value.bytes().all(|byte| (32..=126).contains(&byte))
}

/// The licence scheme a licence-kind source uses (`models.py:45-57`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LicenceScheme {
    /// `Authorization: Bearer <licence>`.
    Bearer,
    /// `X-Tenant-Id: Bearer <licence>`.
    XTenantIdBearer,
}

impl LicenceScheme {
    /// The header the broker sets for this scheme (`broker/client.py:402-404`).
    pub fn header(self) -> &'static str {
        match self {
            Self::Bearer => "Authorization",
            Self::XTenantIdBearer => "X-Tenant-Id",
        }
    }
}

/// How the OAuth2 client authenticates at its token endpoint (`models.py:99`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientAuth {
    /// HTTP Basic with `client_id` and `client_secret`.
    Basic,
    /// The credentials in the form body.
    Post,
}

/// The `mcp_sources.auth` contract, as `models.py:39-116` declares it.
///
/// `alias` is not part of the reference's stored JSON (its contract forbids unknown fields);
/// it is carried here for the broker's credential-profile lookup and defaults to `None`.
/// `StaticHeader.name`, `QueryParam.name` and `OAuth2ClientCredentials.scopes` are the Rust
/// spellings of the JSON `header`, `param` and `scope` fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceAuth {
    /// A public API: nothing is sent and nothing is stored.
    None,
    /// The tenant's licence minted per call.
    Licence {
        alias: Option<String>,
        app_key: String,
        bundle: Option<String>,
        scheme: LicenceScheme,
    },
    /// `Authorization: Bearer <secret>`.
    StaticBearer,
    /// One reserved-name-checked header set to `<secret>`.
    StaticHeader { name: String },
    /// `?<name>=<secret>`.
    QueryParam { name: String },
    /// HTTP Basic: `username` in the clear, the secret is the password.
    Basic { username: String },
    /// RFC 6749 client-credentials grant; the stored secret is the client secret.
    OAuth2ClientCredentials {
        token_url: String,
        client_id: String,
        scopes: Option<String>,
        /// `audience`, accepted by the token endpoint when present.
        audience: Option<String>,
        client_auth: ClientAuth,
    },
}

impl SourceAuth {
    /// Kinds that need no stored secret (`models.py:117-128`).
    pub fn needs_secret(&self) -> bool {
        !matches!(self, Self::None | Self::Licence { .. })
    }

    /// The reference's `kind` discriminator.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::None => "none",
            Self::Licence { .. } => "licence",
            Self::StaticBearer => "static_bearer",
            Self::StaticHeader { .. } => "static_header",
            Self::QueryParam { .. } => "query_param",
            Self::Basic { .. } => "basic",
            Self::OAuth2ClientCredentials { .. } => "oauth2_client_credentials",
        }
    }

    /// Parse one stored `auth` object. Unknown keys deny, exactly as the reference's
    /// `Contract` (`extra="forbid"`) refuses them on read.
    pub fn parse(value: &Value) -> Result<Self, SourceError> {
        let object = value
            .as_object()
            .ok_or(SourceError::Denied("source auth is not an object"))?;
        let kind = field(object, "kind")?;
        let auth = match kind {
            "none" => {
                only(object, &["kind"])?;
                Self::None
            }
            "licence" => {
                only(object, &["kind", "app_key", "scheme", "bundle", "alias"])?;
                let app_key = field(object, "app_key")?.to_owned();
                if !app_key_pattern(&app_key) {
                    return Err(SourceError::Denied("invalid licence app key"));
                }
                let scheme = match optional(object, "scheme")?.unwrap_or("bearer") {
                    "bearer" => LicenceScheme::Bearer,
                    "x_tenant_id_bearer" => LicenceScheme::XTenantIdBearer,
                    _ => return Err(SourceError::Denied("invalid licence scheme")),
                };
                let bundle = optional(object, "bundle")?.map(str::to_owned);
                if let Some(bundle) = &bundle
                    && !bundle_pattern(bundle)
                {
                    return Err(SourceError::Denied("invalid licence bundle"));
                }
                let alias = optional(object, "alias")?.map(str::to_owned);
                if let Some(alias) = &alias
                    && !name_pattern(alias)
                {
                    return Err(SourceError::Denied("invalid licence alias"));
                }
                Self::Licence {
                    alias,
                    app_key,
                    bundle,
                    scheme,
                }
            }
            "static_bearer" => {
                only(object, &["kind"])?;
                Self::StaticBearer
            }
            "static_header" => {
                only(object, &["kind", "header"])?;
                let name = field(object, "header")?.to_owned();
                let lowered = name.to_ascii_lowercase();
                if !header_pattern(&name)
                    || lowered == "authorization"
                    || FORBIDDEN_HEADERS.contains(&lowered.as_str())
                {
                    return Err(SourceError::Denied("reserved source header"));
                }
                Self::StaticHeader { name }
            }
            "query_param" => {
                only(object, &["kind", "param"])?;
                let name = field(object, "param")?.to_owned();
                if !query_param_pattern(&name) {
                    return Err(SourceError::Denied("invalid query parameter name"));
                }
                Self::QueryParam { name }
            }
            "basic" => {
                only(object, &["kind", "username"])?;
                let username = field(object, "username")?.to_owned();
                if !basic_username_pattern(&username) {
                    return Err(SourceError::Denied("invalid basic username"));
                }
                Self::Basic { username }
            }
            "oauth2_client_credentials" => {
                only(
                    object,
                    &[
                        "kind",
                        "token_url",
                        "client_id",
                        "scope",
                        "audience",
                        "client_auth",
                    ],
                )?;
                let token_url = field(object, "token_url")?.to_owned();
                checked_tenant_url(&token_url, true)?;
                let client_id = field(object, "client_id")?.to_owned();
                if !client_id_pattern(&client_id) {
                    return Err(SourceError::Denied("invalid oauth client id"));
                }
                let scopes = optional(object, "scope")?.map(str::to_owned);
                if let Some(scopes) = &scopes
                    && !scope_pattern(scopes)
                {
                    return Err(SourceError::Denied("invalid oauth scope"));
                }
                let audience = optional(object, "audience")?.map(str::to_owned);
                if let Some(audience) = &audience
                    && !client_id_pattern(audience)
                {
                    return Err(SourceError::Denied("invalid oauth audience"));
                }
                let client_auth = match optional(object, "client_auth")?.unwrap_or("basic") {
                    "basic" => ClientAuth::Basic,
                    "post" => ClientAuth::Post,
                    _ => return Err(SourceError::Denied("invalid oauth client auth")),
                };
                Self::OAuth2ClientCredentials {
                    token_url,
                    client_id,
                    scopes,
                    audience,
                    client_auth,
                }
            }
            _ => return Err(SourceError::Denied("unknown source auth kind")),
        };
        Ok(auth)
    }
}

/// A source resolved for one call (`registry.py:29-44`).
///
/// `max_request_bytes` / `max_response_bytes` are the row's nullable bounds; a `NULL` column
/// (the reference's `x or service_limit` fallback, `broker/client.py:445,474`) is represented
/// as [`NO_SOURCE_BOUND`], the identity of `min`, so a caller combining limits with `min`
/// reproduces the reference exactly.
pub struct ResolvedSource {
    pub source_id: Rfc4122Uuid,
    pub owner_tenant_id: Rfc4122Uuid,
    pub source_key: String,
    pub base_url: String,
    pub auth: SourceAuth,
    /// The decrypted secret, present exactly when [`SourceAuth::needs_secret`] holds.
    pub token: Option<String>,
    pub idempotency_header: Option<String>,
    pub ca_file: Option<String>,
    pub max_request_bytes: u64,
    pub max_response_bytes: u64,
    /// The row's revision; the auth-token cache is keyed by `(source_id, revision)`.
    pub revision: i64,
    /// True for tenant-owned sources: egressed through the pinned tenant transport.
    pub tenant_owned: bool,
}

/// A source row without a source-specific bound (the column is `NULL`).
pub const NO_SOURCE_BOUND: u64 = u64::MAX;

impl fmt::Debug for ResolvedSource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResolvedSource")
            .field("source_id", &self.source_id)
            .field("owner_tenant_id", &self.owner_tenant_id)
            .field("source_key", &self.source_key)
            .field("base_url", &self.base_url)
            .field("auth", &self.auth)
            .field("token", &self.token.as_ref().map(|_| "[redacted]"))
            .field("idempotency_header", &self.idempotency_header)
            .field("ca_file", &self.ca_file)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .field("revision", &self.revision)
            .field("tenant_owned", &self.tenant_owned)
            .finish()
    }
}

/// The registered sources, read per call (`registry.py:46-113`).
pub struct SourceRegistry {
    pool: PgPool,
    key: Option<[u8; 32]>,
}

impl SourceRegistry {
    /// Bind the registry to a pool and the configured `MCP_SOURCE_SECRET_KEY` (already
    /// validated by [`crate::config::WorkerSettings`]; decoded here, fail-closed when absent).
    pub fn new(pool: PgPool, source_secret_key: Option<&str>) -> Result<Self, SourceError> {
        let key = source_secret_key.map(crypto::decode_key).transpose()?;
        Ok(Self { pool, key })
    }

    /// The active source `(owner, key)`, or a denial: missing, disabled, owned by someone else,
    /// a tenant origin that is not public https, or a credential that cannot be decrypted.
    /// The error never includes row content.
    pub async fn get(&self, owner: &Rfc4122Uuid, key: &str) -> Result<ResolvedSource, SourceError> {
        let row = sqlx::query(
            "SELECT source_id::text AS source_id, \
                    owner_tenant_id::text AS owner_tenant_id, \
                    source_key, revision, status, base_url, auth, token_ciphertext, \
                    idempotency_header, ca_file, max_request_bytes, max_response_bytes, \
                    (owner_tenant_id <> public.mcp_platform_tenant()) AS tenant_owned \
             FROM public.mcp_sources WHERE owner_tenant_id = $1::uuid AND source_key = $2",
        )
        .bind(owner.to_string())
        .bind(key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(SourceError::Denied("source not found"));
        };
        let source_id = identity(&row, "source_id")?;
        let owner_tenant_id = identity(&row, "owner_tenant_id")?;
        if owner_tenant_id != *owner {
            return Err(SourceError::Denied("source is not owned by the caller"));
        }
        let status: String = row.try_get("status")?;
        if status != "active" {
            return Err(SourceError::Denied("source is not active"));
        }
        let auth = SourceAuth::parse(&row.try_get::<Value, _>("auth")?)?;
        let base_url: String = row.try_get("base_url")?;
        let tenant_owned: bool = row.try_get("tenant_owned")?;
        if tenant_owned {
            // The reference's tenant-side half of `get` (`registry.py:72-79`); the operator
            // allow-list and the port bound are re-checked by the egress client.
            checked_tenant_url(&base_url, true)?;
        }
        let token = if auth.needs_secret() {
            let Some(key) = self.key.as_ref() else {
                return Err(SourceError::Denied("source credential unavailable"));
            };
            let blob: Option<Vec<u8>> = row.try_get("token_ciphertext")?;
            let Some(blob) = blob else {
                return Err(SourceError::Denied("source credential unavailable"));
            };
            Some(crypto::decrypt(key, &source_id, &blob)?)
        } else {
            None
        };
        Ok(ResolvedSource {
            source_id,
            owner_tenant_id,
            source_key: row.try_get("source_key")?,
            base_url,
            auth,
            token,
            idempotency_header: row.try_get("idempotency_header")?,
            ca_file: row.try_get("ca_file")?,
            max_request_bytes: bound(row.try_get::<Option<i32>, _>("max_request_bytes")?),
            max_response_bytes: bound(row.try_get::<Option<i32>, _>("max_response_bytes")?),
            revision: row.try_get("revision")?,
            tenant_owned,
        })
    }
}

/// A nullable row bound as the `min`-identity [`NO_SOURCE_BOUND`]. A value the schema forbids
/// (zero or negative) becomes `0`, which refuses every request — never a wider bound.
fn bound(value: Option<i32>) -> u64 {
    value.map_or(NO_SOURCE_BOUND, |value| u64::try_from(value).unwrap_or(0))
}

/// One identity column, in the authority's text form.
fn identity(row: &sqlx::postgres::PgRow, column: &'static str) -> Result<Rfc4122Uuid, SourceError> {
    Rfc4122Uuid::parse(&row.try_get::<String, _>(column)?).ok_or(SourceError::Denied(
        "source row carries an invalid identity",
    ))
}

// ── the auth contract's field checks (`models.py`) ──────────────────────────────────────────

fn field<'a>(object: &'a Map<String, Value>, name: &'static str) -> Result<&'a str, SourceError> {
    object
        .get(name)
        .and_then(Value::as_str)
        .ok_or(SourceError::Denied("source auth field is required"))
}

fn optional<'a>(
    object: &'a Map<String, Value>,
    name: &'static str,
) -> Result<Option<&'a str>, SourceError> {
    match object.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text)),
        Some(_) => Err(SourceError::Denied("source auth field is invalid")),
    }
}

/// The reference's `extra="forbid"`: any key outside the variant's contract denies the row.
fn only(object: &Map<String, Value>, allowed: &[&str]) -> Result<(), SourceError> {
    if object.keys().any(|key| !allowed.contains(&key.as_str())) {
        return Err(SourceError::Denied("source auth carries an unknown field"));
    }
    Ok(())
}

fn compiled(slot: &'static OnceLock<Regex>, pattern: &'static str) -> &'static Regex {
    slot.get_or_init(|| Regex::new(pattern).expect("static pattern"))
}

fn name_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[a-z][a-z0-9_]{0,63}$").is_match(value)
}

fn app_key_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[a-z][a-z0-9_-]{0,63}$").is_match(value)
}

fn bundle_pattern(value: &str) -> bool {
    app_key_pattern(value)
}

fn header_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[A-Za-z][A-Za-z0-9-]{0,63}$").is_match(value)
}

fn query_param_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}$").is_match(value)
}

fn basic_username_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[\x20-\x39\x3b-\x7e]{1,128}$").is_match(value)
}

fn client_id_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[\x21-\x7e]{1,256}$").is_match(value)
}

fn scope_pattern(value: &str) -> bool {
    static RE: OnceLock<Regex> = OnceLock::new();
    compiled(&RE, r"^[\x21-\x7e]+( [\x21-\x7e]+)*$").is_match(value) && value.len() <= 256
}

/// The syntax of a tenant-registered HTTPS URL (`models.py:130-162`): public DNS names only,
/// no IP literal, userinfo, query, fragment or single-label/internal host. The port bound and
/// the operator allow-list are the egress slice's job.
pub(crate) fn checked_tenant_url(value: &str, allow_path: bool) -> Result<(), SourceError> {
    let deny = || SourceError::Denied("a public https URL is required");
    if value.len() > 512 {
        return Err(deny());
    }
    let url = reqwest::Url::parse(value).map_err(|_| deny())?;
    if url.scheme() != "https"
        || !url.username().is_empty()
        || url.password().is_some()
        || value.contains('@')
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some_and(|port| !(1..=65535).contains(&port))
    {
        return Err(deny());
    }
    let host = url.host_str().ok_or_else(deny)?;
    static HOST: OnceLock<Regex> = OnceLock::new();
    static PATH: OnceLock<Regex> = OnceLock::new();
    static PATH_ANY: OnceLock<Regex> = OnceLock::new();
    let host_ok = compiled(&HOST, r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$").is_match(host);
    let path = url.path();
    let path_ok = if allow_path {
        compiled(&PATH_ANY, r"^(?:/[A-Za-z0-9._~-]+)*/?$").is_match(path)
    } else {
        compiled(&PATH, r"^/?$").is_match(path)
    };
    if !host_ok
        || is_ip_literal(host)
        || !host.contains('.')
        || host.contains("..")
        || host == "localhost"
        || INTERNAL_SUFFIXES
            .iter()
            .any(|suffix| host.ends_with(*suffix))
        || !path_ok
        || path
            .split('/')
            .any(|segment| segment == "." || segment == "..")
    {
        return Err(deny());
    }
    Ok(())
}

/// Address-like hosts (`guard.py:43-52`): an IP literal, or a numeric/hex last label.
fn is_ip_literal(host: &str) -> bool {
    let bare = host.trim_matches(|c| c == '[' || c == ']');
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or(host);
    last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x")
}
