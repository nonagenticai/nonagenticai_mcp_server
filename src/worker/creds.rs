//! Credential resolution: the mounted bundle and the licence minter (slice S5).
//!
//! Ports the reference `src/credentials/resolver.py` and `src/credentials/minter.py`. A resolver
//! answers one question — the token for a `(tenant, profile, reference)` credential — either
//! from an atomically mounted bundle file ([`FileResolver`]) or by minting the tenant's own
//! licence through the licences service ([`Minter`]). The gateway (mcp) licence is the caller's,
//! authenticated on the request that created the run; only the file resolver holds it
//! (`gateway_credentials()`), and the minter refuses to mint it at all.
//!
//! Every refusal, outage or malformed answer fails closed. A minted credential is verified with
//! the same introspection the reference's broker performs (`broker/client.py:136-138,180-182`):
//! the authority must report the minting tenant and the minted licence id, or the credential is
//! discarded.

use std::collections::HashMap;
use std::io::Read as _;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use async_trait::async_trait;
use serde::Deserialize;
use serde_json::Value;
use thiserror::Error;

use crate::auth::AuthError as LicenceError;
use crate::auth::licenses::LicenceAuthority;
use crate::auth::time::parse_iso8601_epoch_seconds;
use crate::auth::uuid::Rfc4122Uuid;
use crate::config::{MinterSettings, WorkerSettings};
use crate::worker::sources::valid_token;

/// The bundle file's bound (`resolver.py:72`): 1 MiB.
const MAX_BUNDLE_BYTES: u64 = 1_048_576;
/// The mint response's bound (`minter.py:38`).
const MAX_RESPONSE_BYTES: usize = 65_536;
/// The minted-credential cache bound (`minter.py:39`).
const CACHE_ENTRIES: usize = 1_024;
/// The default bound on one licences/Keycloak call. The reference uses
/// `license_timeout_seconds`; that setting is not part of [`MinterSettings`].
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);

/// A clock in seconds since the Unix epoch, injectable so a test can prove expiry without
/// sleeping. Production uses [`system_clock`].
pub type Clock = Arc<dyn Fn() -> f64 + Send + Sync>;

/// The wall clock, seconds since the Unix epoch.
pub fn system_clock() -> Clock {
    Arc::new(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0.0, |elapsed| elapsed.as_secs_f64())
    })
}

/// Why a credential could not be resolved. Never carries credential material.
#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum CredentialError {
    /// The reference's `ExecutionDeniedError`: no credential for this reference, a refusal, or
    /// an answer that does not prove the identity it claims.
    #[error("credential denied: {0}")]
    Denied(&'static str),
    /// The reference's `MinterUnavailableError`: the authority was unreachable or answered
    /// unexpectedly; retryable.
    #[error("credential authority unavailable: {0}")]
    Unavailable(&'static str),
}

/// One credential a call names (`resolver.py:14-23`, `broker/client.py:139-145`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialReference {
    /// The catalog service key.
    pub service: String,
    /// The service's destination alias within the profile.
    pub alias: String,
    /// The licence the caller holds for [`Self::app_key`].
    pub license_id: Rfc4122Uuid,
    /// The application key the credential is a licence of.
    pub app_key: String,
}

/// A freshly minted credential (`minter.py:50-54`).
pub struct MintedCredential {
    /// The bearer token. Redacted by [`fmt::Debug`].
    pub token: String,
    /// The licence the token was minted on.
    pub license_id: Rfc4122Uuid,
}

impl std::fmt::Debug for MintedCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MintedCredential")
            .field("token", &"[redacted]")
            .field("license_id", &self.license_id)
            .finish()
    }
}

/// The OAuth material a resolver may carry beside the credential (`resolver.py:22`).
#[derive(Clone, PartialEq, Eq, Default)]
pub struct CredentialEntry {
    /// Operator-provisioned upstream OAuth, independent of the application's licence.
    pub oauth_bearer: Option<String>,
}

impl std::fmt::Debug for CredentialEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("CredentialEntry")
            .field(
                "oauth_bearer",
                &self.oauth_bearer.as_ref().map(|_| "[redacted]"),
            )
            .finish()
    }
}

/// A source of per-tenant backend credentials (`credentials/resolver.py`,
/// `credentials/minter.py`).
#[async_trait]
pub trait CredentialResolver: Send + Sync {
    /// Whether this resolver holds the gateway (mcp) licence. A minting resolver does not.
    fn gateway_credentials(&self) -> bool;

    /// The token for one credential reference.
    async fn resolve(
        &self,
        tenant: &Rfc4122Uuid,
        profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<String, CredentialError>;

    /// A short-lived token on `tenant`'s licence for `app` (in `bundle`). Unavailable unless
    /// the resolver mints.
    async fn mint(
        &self,
        _tenant: &Rfc4122Uuid,
        _app: &str,
        _bundle: Option<&str>,
    ) -> Result<MintedCredential, CredentialError> {
        Err(CredentialError::Denied("mint unavailable"))
    }

    /// The credential's OAuth material, if any.
    async fn entry(
        &self,
        tenant: &Rfc4122Uuid,
        profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<CredentialEntry, CredentialError>;

    /// Readiness: the mounted material is still present and well formed.
    fn read(&self) -> Result<(), CredentialError>;
}

// ── the mounted bundle (`credentials/resolver.py`) ─────────────────────────────────────────

/// One file entry. `deny_unknown_fields` is the reference contract's `extra="forbid"`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleEntry {
    tenant_id: String,
    profile_id: String,
    service: String,
    alias: String,
    license_id: String,
    app_key: String,
    token: String,
    #[serde(default)]
    oauth_bearer: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BundleFile {
    schema_version: u32,
    entries: Vec<BundleEntry>,
}

/// One validated bundle entry.
#[derive(Debug, Clone)]
struct Entry {
    tenant_id: Rfc4122Uuid,
    profile_id: Rfc4122Uuid,
    service: String,
    alias: String,
    license_id: Rfc4122Uuid,
    app_key: String,
    token: String,
    oauth_bearer: Option<String>,
}

/// The mounted, read-only bundle (`resolver.py:56-92`).
pub struct FileResolver {
    path: PathBuf,
}

impl FileResolver {
    pub fn new(path: impl Into<PathBuf>) -> Self {
        Self { path: path.into() }
    }

    /// The configured `MCP_CREDENTIAL_BUNDLE_FILE`; a worker without one denies every read.
    pub fn from_settings(settings: &WorkerSettings) -> Result<Self, CredentialError> {
        settings
            .credential_bundle_file
            .clone()
            .map(Self::new)
            .ok_or(CredentialError::Denied("credential bundle unavailable"))
    }

    /// Read and validate one complete snapshot.
    ///
    /// The file must be a regular file, not group- or world-writable, and at most 1 MiB. The
    /// reference additionally requires the owner to be root or the process's effective uid; this
    /// crate has no `libc` dependency, so that clause is left to the mount's ownership (the
    /// remaining checks still hold).
    fn load(&self) -> Result<Vec<Entry>, CredentialError> {
        let unavailable = || CredentialError::Denied("credential bundle unavailable");
        let file = std::fs::File::open(&self.path).map_err(|_| unavailable())?;
        let metadata = file.metadata().map_err(|_| unavailable())?;
        if !metadata.is_file() || metadata.mode() & 0o022 != 0 || metadata.len() > MAX_BUNDLE_BYTES
        {
            return Err(unavailable());
        }
        let mut payload = String::new();
        file.take(MAX_BUNDLE_BYTES + 1)
            .read_to_string(&mut payload)
            .map_err(|_| unavailable())?;
        let bundle: BundleFile = serde_json::from_str(&payload).map_err(|_| unavailable())?;
        if bundle.schema_version != 1 || bundle.entries.len() > CACHE_ENTRIES {
            return Err(unavailable());
        }
        let mut entries = Vec::with_capacity(bundle.entries.len());
        for entry in bundle.entries {
            entries.push(validate_entry(entry)?);
        }
        let mut seen = std::collections::HashSet::new();
        for entry in &entries {
            if !seen.insert((
                entry.tenant_id,
                entry.profile_id,
                entry.service.clone(),
                entry.alias.clone(),
            )) {
                return Err(CredentialError::Denied("duplicate credential identity"));
            }
        }
        Ok(entries)
    }

    /// The exactly-one entry for `(tenant, profile, service, alias)`, with the reference's
    /// licence and app-key equality check (`resolver.py:81-92`).
    fn find(
        &self,
        tenant: &Rfc4122Uuid,
        profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<Entry, CredentialError> {
        for entry in self.load()? {
            if entry.tenant_id == *tenant
                && entry.profile_id == *profile
                && entry.service == reference.service
                && entry.alias == reference.alias
            {
                if entry.license_id != reference.license_id || entry.app_key != reference.app_key {
                    return Err(CredentialError::Denied("credential reference unavailable"));
                }
                return Ok(entry);
            }
        }
        Err(CredentialError::Denied("credential reference unavailable"))
    }
}

fn validate_entry(entry: BundleEntry) -> Result<Entry, CredentialError> {
    let invalid = || CredentialError::Denied("invalid credential bundle");
    let tenant_id = Rfc4122Uuid::parse(&entry.tenant_id).ok_or_else(invalid)?;
    let license_id = Rfc4122Uuid::parse(&entry.license_id).ok_or_else(invalid)?;
    let profile_id = Rfc4122Uuid::parse(&entry.profile_id).ok_or_else(invalid)?;
    // `profile_id` is a `UUID7` in the reference contract; identities mcp mints stay v7.
    if uuid::Uuid::parse_str(&profile_id.to_string())
        .map(|parsed| parsed.get_version_num())
        .ok()
        != Some(7)
    {
        return Err(invalid());
    }
    if !name(&entry.service) || !name(&entry.alias) || !app_key(&entry.app_key) {
        return Err(invalid());
    }
    if !valid_token(&entry.token) {
        return Err(invalid());
    }
    if let Some(bearer) = &entry.oauth_bearer
        && !valid_token(bearer)
    {
        return Err(invalid());
    }
    Ok(Entry {
        tenant_id,
        profile_id,
        service: entry.service,
        alias: entry.alias,
        license_id,
        app_key: entry.app_key,
        token: entry.token,
        oauth_bearer: entry.oauth_bearer,
    })
}

/// The catalog `Name` pattern (`^[a-z][a-z0-9_]{0,63}$`).
fn name(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// The `AppKey` pattern (`^[a-z][a-z0-9_-]{0,63}$`).
fn app_key(value: &str) -> bool {
    let mut bytes = value.bytes();
    matches!(bytes.next(), Some(b'a'..=b'z'))
        && value.len() <= 64
        && bytes.all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_' || byte == b'-'
        })
}

#[async_trait]
impl CredentialResolver for FileResolver {
    /// The mounted bundle is the profile's credentials, gateway licence included.
    fn gateway_credentials(&self) -> bool {
        true
    }

    async fn resolve(
        &self,
        tenant: &Rfc4122Uuid,
        profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<String, CredentialError> {
        Ok(self.find(tenant, profile, reference)?.token)
    }

    async fn entry(
        &self,
        tenant: &Rfc4122Uuid,
        profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<CredentialEntry, CredentialError> {
        Ok(CredentialEntry {
            oauth_bearer: self.find(tenant, profile, reference)?.oauth_bearer,
        })
    }

    fn read(&self) -> Result<(), CredentialError> {
        self.load().map(|_| ())
    }
}

// ── the licence minter (`credentials/minter.py`) ───────────────────────────────────────────

#[derive(Debug, Clone)]
struct Cached {
    token: String,
    license_id: Rfc4122Uuid,
    /// Epoch seconds after which the credential is not reused; `None` is perpetual.
    valid_until: Option<i64>,
}

impl Cached {
    fn live_at(&self, now: f64) -> bool {
        self.valid_until.is_none_or(|until| now < until as f64)
    }

    fn minted(&self) -> MintedCredential {
        MintedCredential {
            token: self.token.clone(),
            license_id: self.license_id,
        }
    }
}

type CacheKey = (Rfc4122Uuid, String, Option<String>);

/// Mints per-tenant backend credentials from licences (`minter.py:76-245`).
pub struct Minter {
    base_url: String,
    token_url: String,
    client_id: String,
    secret_file: PathBuf,
    ttl_minutes: u64,
    skew_seconds: i64,
    /// The gateway (mcp) application key: never minted.
    gateway_app_key: Option<String>,
    licences: Arc<dyn LicenceAuthority>,
    client: reqwest::Client,
    timeout: Duration,
    clock: Clock,
    secret: RwLock<String>,
    /// The Keycloak client-credentials token, with its expiry.
    service_token: tokio::sync::Mutex<Option<(f64, String)>>,
    /// Successfully minted credentials, until expiry minus skew.
    cache: tokio::sync::Mutex<HashMap<CacheKey, Cached>>,
}

impl Minter {
    /// Build the minter from the `MCP_LICENCE_MINTER_*` settings. The HTTP client is supplied so
    /// the caller owns connection pools and egress pinning.
    pub fn new(
        settings: &MinterSettings,
        gateway_app_key: Option<String>,
        licences: Arc<dyn LicenceAuthority>,
        client: reqwest::Client,
    ) -> Result<Self, CredentialError> {
        let (Some(url), Some(token_url), Some(secret_file)) = (
            settings.url.clone(),
            settings.token_url.clone(),
            settings.secret_file.clone(),
        ) else {
            return Err(CredentialError::Denied("licence minting is not configured"));
        };
        if !settings.enabled {
            return Err(CredentialError::Denied("licence minting is not configured"));
        }
        let secret = read_secret(&secret_file)?;
        Ok(Self {
            base_url: url.trim_end_matches('/').to_owned(),
            token_url,
            client_id: settings.client_id.clone(),
            secret_file,
            ttl_minutes: settings.ttl.as_secs() / 60,
            skew_seconds: i64::try_from(settings.skew.as_secs()).unwrap_or(i64::MAX),
            gateway_app_key,
            licences,
            client,
            timeout: DEFAULT_TIMEOUT,
            clock: system_clock(),
            secret: RwLock::new(secret),
            service_token: tokio::sync::Mutex::new(None),
            cache: tokio::sync::Mutex::new(HashMap::new()),
        })
    }

    /// The worker settings' minter section.
    pub fn from_settings(
        settings: &WorkerSettings,
        gateway_app_key: Option<String>,
        licences: Arc<dyn LicenceAuthority>,
        client: reqwest::Client,
    ) -> Result<Self, CredentialError> {
        Self::new(&settings.licence_minter, gateway_app_key, licences, client)
    }

    /// Replace the clock (tests prove expiry without sleeping).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    /// Replace the per-request bound.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    /// The tenant's licence id for `app` in `bundle` (`minter.py:227-228`).
    pub async fn licence_id(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        bundle: Option<&str>,
    ) -> Result<Rfc4122Uuid, CredentialError> {
        Ok(self.mint(tenant, app, bundle).await?.license_id)
    }

    /// `POST {token_url}` as the Keycloak client, cached until `expires_in` minus skew
    /// (`minter.py:129-165`).
    async fn access_token(&self) -> Result<String, CredentialError> {
        let mut slot = self.service_token.lock().await;
        let now = self.now();
        if let Some((until, token)) = slot.as_ref()
            && now < *until
        {
            return Ok(token.clone());
        }
        *slot = None;
        let secret = self
            .secret
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        let form = format!(
            "grant_type=client_credentials&client_id={}&client_secret={}",
            form_encode(&self.client_id),
            form_encode(&secret),
        );
        let response = self
            .client
            .post(&self.token_url)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(form)
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| {
                CredentialError::Unavailable("minter client authentication unavailable")
            })?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(CredentialError::Unavailable(
                "minter client authentication failed",
            ));
        }
        let payload = bounded(response).await?;
        let payload: Value = serde_json::from_slice(&payload)
            .map_err(|_| CredentialError::Unavailable("minter client token rejected"))?;
        let token = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| valid_token(token))
            .ok_or(CredentialError::Unavailable("minter client token rejected"))?
            .to_owned();
        let lifetime = payload
            .get("expires_in")
            .and_then(Value::as_i64)
            .filter(|lifetime| *lifetime > 0)
            .ok_or(CredentialError::Unavailable("minter client token rejected"))?;
        let until = now + lifetime as f64 - self.skew_seconds as f64;
        if until > self.now() {
            *slot = Some((until, token.clone()));
        }
        Ok(token)
    }

    /// `POST {base}/internal/tenants/{tenant}/bundle-token?app=…&ttl_minutes=…[&bundle=…]`
    /// (`minter.py:167-225`). Fails closed; only successful mints are cached. The flag says
    /// whether this call minted (a fresh credential still has to be proven).
    async fn mint_inner(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        bundle: Option<&str>,
    ) -> Result<(Cached, bool), CredentialError> {
        if self.gateway_app_key.as_deref() == Some(app) {
            return Err(CredentialError::Denied(
                "mcp never mints its own application licence",
            ));
        }
        let key = (tenant.to_owned(), app.to_owned(), bundle.map(str::to_owned));
        if let Some(cached) = self.cache.lock().await.get(&key)
            && cached.live_at(self.now())
        {
            return Ok((cached.clone(), false));
        }
        let bearer = self.access_token().await?;
        let mut url = format!(
            "{}/internal/tenants/{}/bundle-token?app={}&ttl_minutes={}",
            self.base_url,
            tenant,
            form_encode(app),
            self.ttl_minutes,
        );
        if let Some(bundle) = bundle {
            url.push_str("&bundle=");
            url.push_str(&form_encode(bundle));
        }
        let response = self
            .client
            .post(url)
            .header("Authorization", format!("Bearer {bearer}"))
            .timeout(self.timeout)
            .send()
            .await
            .map_err(|_| CredentialError::Unavailable("licence authority unavailable"))?;
        let status = response.status();
        let payload = bounded(response).await?;
        let payload: Option<Value> = serde_json::from_slice(&payload).ok();
        if status == reqwest::StatusCode::UNAUTHORIZED {
            // The cached client token was rejected (rotated realm key, revoked client).
            *self.service_token.lock().await = None;
            return Err(CredentialError::Unavailable("minter client token rejected"));
        }
        if status == reqwest::StatusCode::FORBIDDEN {
            let scoped = payload
                .as_ref()
                .and_then(|payload| payload.get("detail"))
                .and_then(|detail| detail.get("error"))
                .and_then(Value::as_str)
                == Some("dependency_grant_scope");
            if scoped {
                return Err(CredentialError::Denied(
                    "app outside the tenant's dependency grants",
                ));
            }
            return Err(CredentialError::Denied("licence minting refused"));
        }
        if status.is_client_error() {
            return Err(CredentialError::Denied("licence minting refused"));
        }
        if status != reqwest::StatusCode::CREATED {
            return Err(CredentialError::Unavailable(
                "licence authority unavailable",
            ));
        }
        let cached = self.parse_minted(tenant, app, bundle, payload.as_ref())?;
        let mut cache = self.cache.lock().await;
        while cache.len() >= CACHE_ENTRIES {
            let Some(victim) = cache.keys().next().cloned() else {
                break;
            };
            cache.remove(&victim);
        }
        cache.insert(key, cached.clone());
        Ok((cached, true))
    }

    /// One mint response (`minter.py:207-225`), then the broker's identity check
    /// (`broker/client.py:136-138`).
    fn parse_minted(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        bundle: Option<&str>,
        payload: Option<&Value>,
    ) -> Result<Cached, CredentialError> {
        let rejected = || CredentialError::Denied("licence authority response rejected");
        let payload = payload.and_then(Value::as_object).ok_or_else(rejected)?;
        let minted_tenant = payload
            .get("tenant_id")
            .and_then(Value::as_str)
            .and_then(Rfc4122Uuid::parse)
            .ok_or_else(rejected)?;
        if minted_tenant != *tenant || payload.get("app").and_then(Value::as_str) != Some(app) {
            return Err(CredentialError::Denied("minted for another tenant or app"));
        }
        if let Some(bundle) = bundle
            && payload.get("bundle").and_then(Value::as_str) != Some(bundle)
        {
            return Err(CredentialError::Denied("minted in another bundle"));
        }
        let license_id = payload
            .get("license_id")
            .and_then(Value::as_str)
            .and_then(Rfc4122Uuid::parse)
            .ok_or_else(rejected)?;
        let token = payload
            .get("token")
            .and_then(Value::as_str)
            .filter(|token| valid_token(token))
            .ok_or_else(rejected)?
            .to_owned();
        // Missing `expires_at` is malformed; an explicit null is perpetual (`licenses.py:63-72`).
        let valid_until = match payload.get("expires_at") {
            None => return Err(rejected()),
            Some(Value::Null) => None,
            Some(Value::String(text)) => {
                Some(parse_iso8601_epoch_seconds(text).ok_or_else(rejected)? - self.skew_seconds)
            }
            Some(_) => return Err(rejected()),
        };
        if valid_until.is_some_and(|until| self.now() >= until as f64) {
            return Err(CredentialError::Denied("minted credential already expired"));
        }
        Ok(Cached {
            token,
            license_id,
            valid_until,
        })
    }

    /// Prove the minted credential is the tenant's licence for `app`: the same introspection
    /// the reference's broker performs before using a minted token.
    async fn verify(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        minted: &Cached,
    ) -> Result<(), CredentialError> {
        match self.licences.authenticate_for_app(&minted.token, app).await {
            Ok(identity) => {
                if identity.tenant_id != *tenant || identity.license_id != minted.license_id {
                    return Err(CredentialError::Denied(
                        "licence identity does not match the mint",
                    ));
                }
                Ok(())
            }
            Err(LicenceError::Unavailable) => Err(CredentialError::Unavailable(
                "licence authority unavailable",
            )),
            Err(_) => Err(CredentialError::Denied(
                "licence authority rejected the minted credential",
            )),
        }
    }

    /// The credential for `(tenant, app, bundle)`, minting on a miss and proving a freshly
    /// minted token.
    ///
    /// The reference re-introspects on every `source_licence` call, but its licence client
    /// caches identities; this crate's introspection client deliberately does not, so the
    /// identity is proven once per mint and the token is then reused for at most its TTL minus
    /// skew (15 minutes by default) — the window a cached identity would cover.
    async fn resolved(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        bundle: Option<&str>,
    ) -> Result<Cached, CredentialError> {
        let (cached, fresh) = self.mint_inner(tenant, app, bundle).await?;
        if fresh {
            self.verify(tenant, app, &cached).await?;
        }
        Ok(cached)
    }
}

#[async_trait]
impl CredentialResolver for Minter {
    /// The gateway licence is the caller's; this resolver never holds it (`minter.py:18`).
    fn gateway_credentials(&self) -> bool {
        false
    }

    async fn resolve(
        &self,
        tenant: &Rfc4122Uuid,
        _profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<String, CredentialError> {
        let minted = self.resolved(tenant, &reference.app_key, None).await?;
        if minted.license_id != reference.license_id {
            return Err(CredentialError::Denied("credential reference unavailable"));
        }
        Ok(minted.token)
    }

    async fn mint(
        &self,
        tenant: &Rfc4122Uuid,
        app: &str,
        bundle: Option<&str>,
    ) -> Result<MintedCredential, CredentialError> {
        Ok(self.resolved(tenant, app, bundle).await?.minted())
    }

    /// A mint response carries no upstream OAuth material (`minter.py` has no `entry`); the
    /// reference's broker therefore skips this resolver's entry. Answer empty, after proving
    /// the reference resolves.
    async fn entry(
        &self,
        tenant: &Rfc4122Uuid,
        _profile: &Rfc4122Uuid,
        reference: &CredentialReference,
    ) -> Result<CredentialEntry, CredentialError> {
        self.resolved(tenant, &reference.app_key, None).await?;
        Ok(CredentialEntry::default())
    }

    fn read(&self) -> Result<(), CredentialError> {
        let secret = read_secret(&self.secret_file)?;
        *self
            .secret
            .write()
            .unwrap_or_else(|poison| poison.into_inner()) = secret;
        Ok(())
    }
}

/// The mounted client secret: trimmed, printable ASCII, at most 4096 bytes (`minter.py:67-73`).
fn read_secret(path: &Path) -> Result<String, CredentialError> {
    let unavailable = || CredentialError::Denied("minter client secret unavailable");
    let file = std::fs::File::open(path).map_err(|_| unavailable())?;
    let mut raw = Vec::new();
    file.take(4097)
        .read_to_end(&mut raw)
        .map_err(|_| unavailable())?;
    let text = String::from_utf8(raw).map_err(|_| unavailable())?;
    let trimmed = text.trim();
    if !valid_token(trimmed) {
        return Err(unavailable());
    }
    Ok(trimmed.to_owned())
}

/// Stream one response body, refusing anything larger than [`MAX_RESPONSE_BYTES`].
async fn bounded(mut response: reqwest::Response) -> Result<Vec<u8>, CredentialError> {
    let mut body = Vec::new();
    loop {
        match response.chunk().await {
            Ok(Some(chunk)) => {
                body.extend_from_slice(&chunk);
                if body.len() > MAX_RESPONSE_BYTES {
                    return Err(CredentialError::Unavailable(
                        "licence authority response rejected",
                    ));
                }
            }
            Ok(None) => return Ok(body),
            Err(_) => {
                return Err(CredentialError::Unavailable(
                    "licence authority unavailable",
                ));
            }
        }
    }
}

/// `application/x-www-form-urlencoded` (the reference's `urlencode`/`httpx data=`): the
/// unreserved set stays literal, space becomes `+`.
pub(crate) fn form_encode(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            b' ' => encoded.push('+'),
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}

/// Kept because the broker's OAuth client authentication quotes the same way (`auth.py:42-43`).
pub(crate) fn quote(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            }
            _ => encoded.push_str(&format!("%{byte:02X}")),
        }
    }
    encoded
}
