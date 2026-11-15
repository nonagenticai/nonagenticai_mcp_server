//! The tenant builder application service: one implementation behind the builder routes and
//! the `builder_*` tools.
//!
//! Port of the reference `src/builder/service.py`. Every method takes the authenticated
//! [`AuthorPrincipal`] first and acts only for its tenant; nothing accepts a tenant from a
//! request. It orchestrates the source repository, the builder catalog (sources, operations,
//! tools, toolkits, quotas), the document fetch and the existing catalog/toolkit services, and
//! returns JSON-ready values.
//!
//! The reference's `@authoring` decorator is [`authoring`] here: a request-level `ValueError`
//! raised by authored content (a schema, a package, a manifest, an OpenAPI selection) is an
//! `invalid_request` with its message; lifecycle conflicts, quotas, not-found and permission
//! refusals keep their own status.
//!
//! # Where the port cannot be literal
//!
//! - **Shared transactions.** The reference runs `operations_import` (ensure the service, then
//!   every operation) in one transaction through `conn=` support. This crate's storage methods
//!   own their transactions, so the import is one call per storage method: a failure part-way
//!   leaves the service and the operations already imported. Tool create/publish and toolkit
//!   writes keep their single transaction because the storage methods implement it.
//! - **Spec fetch transport.** The reference composes a reduced `Broker` for document fetches.
//!   This port exposes the reference's `DocumentFetcher` protocol as a trait and provides
//!   [`PinnedEgressFetcher`], which uses the same public broker pieces (source registry,
//!   credential injection, egress policy, per-address pinned clients). The tenant transport is
//!   https-only, exactly as the reference's; the trait seam is what lets a deployment or a test
//!   supply the fetch without weakening that transport.
//! - **Process-wide installation.** The reference's `runtime.py` installs one service per
//!   process and answers `404 not_found` for every builder route while the builder is disabled.
//!   Installation belongs to the composition root here; [`BuilderService::ensure_enabled`]
//!   reproduces the reference's `BuilderUnavailableError("the tool builder is not enabled")`
//!   for a caller that has a service but must not use it.

use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{Arc, LazyLock, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use url::Url;

use crate::auth::{AuthorPrincipal, Rfc4122Uuid};
use crate::builder::models::{
    BindRequest, BuilderInputError, ImportRequest, OperationOverride, OperationPatch,
    SpecFetchRequest, SpecPath, ToolCreate, ToolPublishRequest, ToolTestRequest, ToolUpdate,
    ToolkitPublishRequest, ToolkitRequest,
};
use crate::builder::openapi::{
    OpenApiImportError, OperationListing, Selection, import_openapi, list_operations,
};
use crate::builder::packaging::{self, OpRefs};
use crate::builder::spec::{
    RateLimit, SPEC_TIMEOUT_SECONDS, checked_spec_path, digest, parse_document, title_version,
};
use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    Attribution, ExactReference, Runtime, ServiceManifest, VersionDescriptor,
};
use crate::catalog::package::PackageFile;
use crate::catalog::service::{CatalogService, CatalogServiceError};
use crate::catalog::toolkit_models::ToolkitManifest;
use crate::catalog::validation::SchemaLimits;
use crate::config::BuilderSettings;
use crate::sources::models::{
    RevisionOnly, SourceStatus, TenantSourceCreate, TenantSourceUpdate, TokenUpdate,
};
use crate::sources::tenant_repository::{SpecRecord, TenantSourceError, TenantSourceRepository};
use crate::storage::bindings_ensure::{
    BindingEnsureService, EnsureError, RebindEntry, rebind_failed_report,
};
use crate::storage::builder::{
    BuilderCatalogRepository, BuilderStoreError, DraftLicenceLookup, DraftRunSettings,
    OperationRecord, ServiceRecord, Usage,
};
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::ToolkitServiceError;
use crate::worker::broker::auth::AuthAdapters;
use crate::worker::broker::egress::{
    EgressError, EgressPolicy, PinnedClients, PlatformClients, PoolLimits, tenant_client,
};
use crate::worker::creds::CredentialResolver;
use crate::worker::sources::{ResolvedSource, SourceAuth, SourceError, SourceRegistry};

/// A builder failure, in the reference's exception shapes.
///
/// `status`/`code` are the reference's pairs for the `BuilderError` family; the other variants
/// keep the ASGI surface's rendering (`invalid_request`, `quota_exceeded` + `resource`,
/// `not_found`, `revision_or_lifecycle_conflict`, `forbidden`). `detail` is present only where
/// the reference shows a message.
#[derive(Debug, thiserror::Error)]
pub enum BuilderError {
    /// The reference's `BuilderError` (500, `builder_error`).
    #[error("{0}")]
    Failed(String),
    /// The reference's `BuilderUnavailableError` (503, `builder_unavailable`).
    #[error("{0}")]
    Unavailable(String),
    /// The reference's `BuilderRateLimitError` (429, `rate_limited`).
    #[error("{0}")]
    RateLimited(String),
    /// The reference's `BuilderUpstreamError` (502, `upstream_failed`).
    #[error("{0}")]
    Upstream(String),
    /// The reference's `BuilderInputError` (422 `invalid_request`, message shown).
    #[error("{0}")]
    Input(String),
    /// A request-level `ValueError` from a non-authoring call (422 `invalid_request`, no
    /// message in the body).
    #[error("{0}")]
    Invalid(String),
    /// The reference's `QuotaExceededError` (409 `quota_exceeded` with `resource`).
    #[error("{0} quota exceeded")]
    Quota(&'static str),
    /// The reference's `CatalogNotFoundError` (404 `not_found`).
    #[error("{0}")]
    NotFound(String),
    /// The reference's `CatalogConflictError` (409 `revision_or_lifecycle_conflict`).
    #[error("{0}")]
    Conflict(String),
    /// The reference's `PermissionError`/`ExecutionDeniedError` (403 `forbidden`).
    #[error("{0}")]
    Forbidden(String),
}

impl BuilderError {
    /// The HTTP status the reference's ASGI surface answers with.
    pub const fn status(&self) -> u16 {
        match self {
            Self::Failed(_) => 500,
            Self::Unavailable(_) => 503,
            Self::RateLimited(_) => 429,
            Self::Upstream(_) => 502,
            Self::Input(_) | Self::Invalid(_) => 422,
            Self::Quota(_) | Self::Conflict(_) => 409,
            Self::NotFound(_) => 404,
            Self::Forbidden(_) => 403,
        }
    }

    /// The body's `error` code.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::Failed(_) => "builder_error",
            Self::Unavailable(_) => "builder_unavailable",
            Self::RateLimited(_) => "rate_limited",
            Self::Upstream(_) => "upstream_failed",
            Self::Input(_) | Self::Invalid(_) => "invalid_request",
            Self::Quota(_) => "quota_exceeded",
            Self::NotFound(_) => "not_found",
            Self::Conflict(_) => "revision_or_lifecycle_conflict",
            Self::Forbidden(_) => "forbidden",
        }
    }

    /// The `quota_exceeded` body's resource, when this is a quota refusal.
    pub const fn resource(&self) -> Option<&'static str> {
        match self {
            Self::Quota(resource) => Some(resource),
            _ => None,
        }
    }

    /// The message the reference shows in the body, when it shows one.
    pub fn detail(&self) -> Option<&str> {
        match self {
            Self::Failed(message)
            | Self::Unavailable(message)
            | Self::RateLimited(message)
            | Self::Upstream(message)
            | Self::Input(message) => Some(message),
            Self::Invalid(_)
            | Self::Quota(_)
            | Self::NotFound(_)
            | Self::Conflict(_)
            | Self::Forbidden(_) => None,
        }
    }
}

/// Python's `text[:maximum]` (characters, not bytes).
fn truncated(text: &str, maximum: usize) -> String {
    text.chars().take(maximum).collect()
}

/// The reference's `@authoring`: a storage `ValueError` from authored content becomes a
/// `BuilderInputError` (422 with the message, truncated to the reference's 500 characters).
fn authoring(error: BuilderStoreError) -> BuilderError {
    match error {
        BuilderStoreError::Invalid(message) => BuilderError::Input(truncated(&message, 500)),
        other => BuilderError::from(other),
    }
}

/// The same rule for a catalog-service refusal.
fn authoring_catalog(error: CatalogServiceError) -> BuilderError {
    match error {
        CatalogServiceError::Invalid(error) => {
            BuilderError::Input(truncated(&error.to_string(), 500))
        }
        CatalogServiceError::Store(error) => BuilderError::from(error),
    }
}

/// A database failure is a 500: never the SQL text, never a bound value.
fn storage_failed(error: sqlx::Error) -> BuilderError {
    tracing::error!(error = %error, "builder storage failed");
    BuilderError::Failed("builder storage failed".to_owned())
}

fn from_catalog_store(error: CatalogStoreError) -> BuilderError {
    match error {
        CatalogStoreError::Conflict(message) => BuilderError::Conflict(message.to_owned()),
        CatalogStoreError::NotFound(message) => BuilderError::NotFound(message.to_owned()),
        CatalogStoreError::Corrupt(message) => {
            BuilderError::Failed(format!("stored catalog row is invalid: {message}"))
        }
        CatalogStoreError::Database(error) => storage_failed(error),
    }
}

fn from_toolkit_service(error: ToolkitServiceError) -> BuilderError {
    match error {
        ToolkitServiceError::Forbidden(message) => BuilderError::Forbidden(message.to_owned()),
        ToolkitServiceError::Invalid(message) => BuilderError::Invalid(message.to_owned()),
        ToolkitServiceError::Conflict(message) => BuilderError::Conflict(message.to_owned()),
        ToolkitServiceError::Store(error) => from_catalog_store(error),
    }
}

impl From<BuilderStoreError> for BuilderError {
    fn from(error: BuilderStoreError) -> Self {
        match error {
            BuilderStoreError::Conflict(message) => Self::Conflict(message),
            BuilderStoreError::NotFound(message) => Self::NotFound(message),
            BuilderStoreError::Quota(resource) => Self::Quota(resource),
            BuilderStoreError::Forbidden(message) => Self::Forbidden(message),
            BuilderStoreError::Unavailable(message) => Self::Unavailable(message.to_owned()),
            BuilderStoreError::Invalid(message) => Self::Invalid(message),
            BuilderStoreError::Corrupt(message) => {
                Self::Failed(format!("stored builder row is invalid: {message}"))
            }
            BuilderStoreError::Database(error) => storage_failed(error),
        }
    }
}

impl From<TenantSourceError> for BuilderError {
    fn from(error: TenantSourceError) -> Self {
        match error {
            TenantSourceError::NotFound(message) => Self::NotFound(message),
            TenantSourceError::Conflict(message) => Self::Conflict(message),
            TenantSourceError::Invalid(message) => Self::Invalid(message),
            TenantSourceError::Quota(resource) => Self::Quota(resource),
            TenantSourceError::Forbidden(message) => Self::Forbidden(message),
            TenantSourceError::SecretUnavailable => {
                Self::Failed("source secret key is not configured".to_owned())
            }
            TenantSourceError::Guard(error) => Self::Invalid(error.to_string()),
            TenantSourceError::Corrupt(message) => {
                Self::Failed(format!("stored source row is invalid: {message}"))
            }
            TenantSourceError::Database(error) => storage_failed(error),
        }
    }
}

impl From<CatalogServiceError> for BuilderError {
    fn from(error: CatalogServiceError) -> Self {
        match error {
            CatalogServiceError::Invalid(error) => Self::Invalid(error.to_string()),
            CatalogServiceError::Store(error) => Self::from(error),
        }
    }
}

/// A tenant catalog refusal keeps the reference's class: a missing row is 404, a conflict 409,
/// a drifted row and a broken statement are 500 (never the SQL text or a bound value).
impl From<CatalogStoreError> for BuilderError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(message) => Self::NotFound(message.to_owned()),
            CatalogStoreError::Conflict(message) => Self::Conflict(message.to_owned()),
            CatalogStoreError::Corrupt(kind) => {
                Self::Failed(format!("stored catalog row is invalid: {kind}"))
            }
            CatalogStoreError::Database(error) => storage_failed(error),
        }
    }
}

impl From<BuilderInputError> for BuilderError {
    fn from(error: BuilderInputError) -> Self {
        Self::Input(error.message().to_owned())
    }
}

impl From<OpenApiImportError> for BuilderError {
    fn from(error: OpenApiImportError) -> Self {
        // The reference's `OpenApiImportError` is a `ValueError`; outside `@authoring` the
        // surface renders it as `invalid_request` without the message.
        Self::Invalid(error.reason)
    }
}

impl From<EnsureError> for BuilderError {
    fn from(error: EnsureError) -> Self {
        match error {
            EnsureError::Forbidden(message) => Self::Forbidden(message.to_owned()),
            EnsureError::NotFound(message) => Self::NotFound(message.to_owned()),
            EnsureError::Conflict(message) => Self::Conflict(message.to_owned()),
            EnsureError::Invalid(message) => Self::Invalid(message.to_owned()),
            // A `RuntimeError` in the reference: an unhandled 500, never a caller refusal.
            EnsureError::Unavailable(message) => Self::Failed(message.to_owned()),
            EnsureError::Corrupt(message) => {
                Self::Failed(format!("stored binding-ensure row is invalid: {message}"))
            }
            EnsureError::Database(error) => storage_failed(error),
            EnsureError::Store(error) => from_catalog_store(error),
            EnsureError::Toolkit(error) => from_toolkit_service(error),
        }
    }
}

// ── the document fetch ──────────────────────────────────────────────────────────────────────

/// Why one document fetch failed, in the reference's exception classes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchError {
    /// The reference's `ExecutionDeniedError`: the egress policy, the credential, the licence
    /// mint or the body's secret check refused the fetch.
    Denied,
    /// The reference's `(ValueError, TimeoutError, OSError)`, carrying the class name the
    /// fetch-failure message reports.
    Failed(&'static str),
}

/// The reference's `DocumentFetcher` protocol (`src/builder/spec.py`): the broker's
/// `fetch_document`. `source` is the resolved source, `path` is relative to its origin.
#[async_trait]
pub trait DocumentFetcher: Send + Sync {
    /// The raw document body, or the refusal class.
    async fn fetch_document(
        &self,
        source: &ResolvedSource,
        path: &str,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, FetchError>;
}

/// The reference's broker `fetch_document`, over this crate's pinned egress: the source's own
/// credential, no redirects, bounded size and time, and a body that echoes a secret refused.
///
/// Tenant-owned sources go through [`PinnedClients`] (one client per validated address; a
/// connection failure may try the next, a policy refusal never is); platform sources through
/// [`PlatformClients`]. The tenant transport is https-only, exactly as the reference's.
pub struct PinnedEgressFetcher {
    egress: Arc<EgressPolicy>,
    limits: PoolLimits,
    pins: PinnedClients,
    platform: PlatformClients,
    auth: AuthAdapters,
    credentials: Option<Arc<dyn CredentialResolver>>,
}

impl PinnedEgressFetcher {
    /// Bind the fetcher to one egress policy and the broker's credential machinery.
    ///
    /// `credentials` mints the licence a licence-kind source sends; a deployment without a
    /// minter refuses those sources (`ExecutionDeniedError`), as the reference does.
    pub fn new(
        egress: Arc<EgressPolicy>,
        limits: PoolLimits,
        auth: AuthAdapters,
        credentials: Option<Arc<dyn CredentialResolver>>,
    ) -> Self {
        let pins = PinnedClients::new(Arc::clone(&egress), limits);
        let platform = PlatformClients::new(limits);
        Self {
            egress,
            limits,
            pins,
            platform,
            auth,
            credentials,
        }
    }

    /// The pinned client an OAuth token fetch for a tenant source runs through (reqwest pins
    /// one client per `(host, validated address)`; the adapter caches the token).
    async fn pinned_client(&self, endpoint: &str) -> Result<reqwest::Client, FetchError> {
        let url = Url::parse(endpoint).map_err(|_| FetchError::Failed("ValueError"))?;
        let host = url.host_str().ok_or(FetchError::Denied)?.to_owned();
        let port = url.port_or_known_default().ok_or(FetchError::Denied)?;
        let addresses = self
            .egress
            .validated(&host, port)
            .await
            .map_err(egress_error)?;
        let address = *addresses.first().ok_or(FetchError::Denied)?;
        tenant_client(&self.egress, Some(self.limits))
            .resolve(&host, address)
            .build()
            .map_err(|_| FetchError::Denied)
    }

    /// Send one request through the destination's transport.
    async fn send(
        &self,
        source: &ResolvedSource,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, FetchError> {
        let ca_file = source.ca_file.as_deref().map(Path::new);
        if source.tenant_owned {
            let (host, port) = endpoint(source)?;
            let clients = self
                .pins
                .clients(&host, port, ca_file)
                .await
                .map_err(egress_error)?;
            let mut transport_failed = false;
            for (_, client) in clients {
                let Some(clone) = request.try_clone() else {
                    break;
                };
                match client.execute(clone).await {
                    Ok(response) => return Ok(response),
                    Err(EgressError::Transport) => transport_failed = true,
                    // A request that may have been delivered is never replayed on another
                    // address; the reference reports the transport failure instead.
                    Err(EgressError::TransportSent) => {
                        return Err(FetchError::Failed("OSError"));
                    }
                    Err(EgressError::SsrfBlocked | EgressError::Redirect) => {
                        return Err(FetchError::Denied);
                    }
                }
            }
            return Err(if transport_failed {
                FetchError::Failed("OSError")
            } else {
                FetchError::Denied
            });
        }
        let client = self.platform.client_for(ca_file).map_err(egress_error)?;
        match client.execute(request).await {
            Ok(response) => Ok(response),
            Err(error) if error.is_timeout() => Err(FetchError::Failed("TimeoutError")),
            Err(_) => Err(FetchError::Failed("OSError")),
        }
    }
}

/// A policy refusal is a denial; a resolution or connect failure is the reference's `OSError`.
fn egress_error(error: EgressError) -> FetchError {
    match error {
        EgressError::SsrfBlocked | EgressError::Redirect => FetchError::Denied,
        EgressError::Transport | EgressError::TransportSent => FetchError::Failed("OSError"),
    }
}

/// The document path rule the reference repeats in the fetch: a same-origin absolute path with
/// no `..` segment (`ValueError` otherwise).
fn checked_document_path(path: &str) -> Result<(), FetchError> {
    static DOCUMENT_PATH: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\A/[A-Za-z0-9._~/-]{0,255}\z").expect("the document path pattern is valid")
    });
    if DOCUMENT_PATH.is_match(path) && !path.split('/').any(|segment| segment == "..") {
        Ok(())
    } else {
        Err(FetchError::Failed("ValueError"))
    }
}

/// `encoded(secret)[1:-1]`: the JSON string without its quotes, which is the escaped form a
/// body would carry (`storage/executions.py:15-18`).
fn encoded_inner(secret: &str) -> String {
    let encoded = serde_json::to_string(secret).unwrap_or_default();
    let bytes = encoded.as_bytes();
    if bytes.len() >= 2 {
        String::from_utf8_lossy(&bytes[1..bytes.len() - 1]).into_owned()
    } else {
        String::new()
    }
}

#[async_trait]
impl DocumentFetcher for PinnedEgressFetcher {
    async fn fetch_document(
        &self,
        source: &ResolvedSource,
        path: &str,
        max_bytes: usize,
        timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        checked_document_path(path)?;
        // The reference builds the URL from the source's origin only (`parts.netloc` + path),
        // so a base_url path prefix is NOT part of the document URL.
        let mut url = Url::parse(&source.base_url).map_err(|_| FetchError::Failed("ValueError"))?;
        url.set_path(path);
        url.set_query(None);
        url.set_fragment(None);
        let mut headers: HashMap<String, String> = HashMap::new();
        headers.insert("Accept".to_owned(), "application/json".to_owned());
        let mut query: HashMap<String, String> = HashMap::new();
        let mut secrets: Vec<String> = Vec::new();
        match &source.auth {
            SourceAuth::Licence {
                app_key,
                bundle,
                scheme,
                ..
            } => {
                let Some(credentials) = &self.credentials else {
                    return Err(FetchError::Denied);
                };
                let minted = credentials
                    .mint(&source.owner_tenant_id, app_key, bundle.as_deref())
                    .await
                    .map_err(|_| FetchError::Denied)?;
                headers.insert(
                    scheme.header().to_owned(),
                    format!("Bearer {}", minted.token),
                );
                secrets.push(minted.token);
            }
            _ => {
                // A tenant source whose OAuth token endpoint is itself a tenant host must be
                // reached through the same pin; every other kind needs no client here.
                let client = match (&source.auth, source.tenant_owned) {
                    (SourceAuth::OAuth2ClientCredentials { token_url, .. }, true) => {
                        Some(self.pinned_client(token_url).await?)
                    }
                    _ => None,
                };
                let applied = self
                    .auth
                    .apply(source, &mut headers, &mut query, client.as_ref())
                    .await
                    .map_err(|_| FetchError::Denied)?;
                secrets.extend(applied);
            }
        }
        if !query.is_empty() {
            let mut names: Vec<&String> = query.keys().collect();
            names.sort();
            let mut pairs = url.query_pairs_mut();
            for name in names {
                pairs.append_pair(name, &query[name]);
            }
        }
        let mut request = reqwest::Request::new(reqwest::Method::GET, url);
        request.timeout_mut().replace(timeout);
        {
            let mut map = reqwest::header::HeaderMap::new();
            let mut names: Vec<&String> = headers.keys().collect();
            names.sort();
            for name in names {
                let header = HeaderName::from_bytes(name.as_bytes())
                    .map_err(|_| FetchError::Failed("ValueError"))?;
                let value = HeaderValue::from_str(&headers[name])
                    .map_err(|_| FetchError::Failed("ValueError"))?;
                map.append(header, value);
            }
            *request.headers_mut() = map;
        }
        let mut response = self.send(source, request).await?;
        if !response.status().is_success() {
            // The reference's message carries the status, but the service reports only the
            // exception class; nothing from the upstream reaches the author.
            return Err(FetchError::Failed("ValueError"));
        }
        let mut data: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    data.extend_from_slice(&chunk);
                    if data.len() > max_bytes {
                        return Err(FetchError::Failed("ValueError"));
                    }
                }
                Ok(None) => break,
                Err(_) => return Err(FetchError::Failed("OSError")),
            }
        }
        let text = String::from_utf8_lossy(&data);
        if secrets.iter().any(|secret| {
            !secret.is_empty()
                && (text.contains(secret.as_str()) || text.contains(&encoded_inner(secret)))
        }) {
            return Err(FetchError::Denied);
        }
        Ok(data)
    }
}

fn endpoint(source: &ResolvedSource) -> Result<(String, u16), FetchError> {
    let url = Url::parse(&source.base_url).map_err(|_| FetchError::Failed("ValueError"))?;
    let host = url
        .host_str()
        .ok_or(FetchError::Failed("ValueError"))?
        .to_owned();
    let port = url
        .port_or_known_default()
        .ok_or(FetchError::Failed("ValueError"))?;
    Ok((host, port))
}

// ── the service ─────────────────────────────────────────────────────────────────────────────

/// Every collaborator the service orchestrates. The reference's `runtime.build` composes the
/// same set from the lifespan's `app.state`.
pub struct BuilderServiceDependencies {
    /// The tenant's own sources.
    pub sources: TenantSourceRepository,
    /// The builder catalog's SQL half.
    pub builder: BuilderCatalogRepository,
    /// Complete-package validation and the tenant lifecycle.
    pub catalog: CatalogService,
    /// Exact-selection resolution for toolkit writes.
    pub resolver: SelectionResolver,
    /// The execution settings a draft test run needs; `None` matches the reference's
    /// `execution=None` (`test runs are not available`).
    pub draft: Option<DraftRunSettings>,
    /// The backend-licence minter a licence-kind dependency needs.
    pub minter: Option<Arc<dyn DraftLicenceLookup>>,
    /// The document fetcher; `None` makes every spec fetch unavailable.
    pub fetcher: Option<Arc<dyn DocumentFetcher>>,
    /// The source registry the fetcher resolves through; `None` makes fetches unavailable.
    pub registry: Option<SourceRegistry>,
    /// The binding provisioner a toolkit publish re-binds through.
    pub ensure: Option<BindingEnsureService>,
}

/// The tenant builder application service.
pub struct BuilderService {
    settings: BuilderSettings,
    /// The schema bounds the importer applies (the reference passes its whole `Settings`).
    schemas: SchemaLimits,
    /// `MCP_APPROVED_RUNNER_IMAGES`: the runner digest a new tool pins.
    approved_runner_images: Vec<String>,
    pool: PgPool,
    sources: TenantSourceRepository,
    builder: BuilderCatalogRepository,
    catalog: CatalogService,
    resolver: SelectionResolver,
    draft: Option<DraftRunSettings>,
    minter: Option<Arc<dyn DraftLicenceLookup>>,
    fetcher: Option<Arc<dyn DocumentFetcher>>,
    registry: Option<SourceRegistry>,
    ensure: Option<BindingEnsureService>,
    /// The reference's per-tenant spec-fetch window, process-wide.
    fetch_limit: Mutex<RateLimit>,
}

impl BuilderService {
    /// Bind the service to its settings and collaborators. Nothing is read from the environment
    /// here; the composition root builds every value first.
    pub fn new(
        pool: PgPool,
        settings: BuilderSettings,
        schemas: SchemaLimits,
        approved_runner_images: Vec<String>,
        dependencies: BuilderServiceDependencies,
    ) -> Self {
        let fetch_limit = Mutex::new(RateLimit::new(settings.spec_fetches_per_hour));
        Self {
            settings,
            schemas,
            approved_runner_images,
            pool,
            sources: dependencies.sources,
            builder: dependencies.builder,
            catalog: dependencies.catalog,
            resolver: dependencies.resolver,
            draft: dependencies.draft,
            minter: dependencies.minter,
            fetcher: dependencies.fetcher,
            registry: dependencies.registry,
            ensure: dependencies.ensure,
            fetch_limit,
        }
    }

    /// The reference's `runtime.get`: a service that exists while the builder is disabled must
    /// refuse with `BuilderUnavailableError` rather than act.
    pub fn ensure_enabled(&self) -> Result<(), BuilderError> {
        if self.settings.enabled {
            Ok(())
        } else {
            Err(BuilderError::Unavailable(
                "the tool builder is not enabled".to_owned(),
            ))
        }
    }

    // ── sources ────────────────────────────────────────────────────────────────────────────

    /// Create a tenant source (the reference's `source_create`).
    pub async fn source_create(
        &self,
        author: &AuthorPrincipal,
        body: &TenantSourceCreate,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let view = self
            .sources
            .create(&author.tenant, body, &author.actor)
            .await?;
        to_value(&view)
    }

    /// Update a tenant source (the reference's `source_update`).
    pub async fn source_update(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        body: &TenantSourceUpdate,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let view = self
            .sources
            .update(&author.tenant, key, body, &author.actor)
            .await?;
        to_value(&view)
    }

    /// Rotate a source's stored secret; the response never carries it.
    pub async fn source_set_secret(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        body: &TokenUpdate,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let view = self
            .sources
            .set_secret(&author.tenant, key, body, &author.actor)
            .await?;
        to_value(&view)
    }

    /// One source owned by the tenant.
    pub async fn source_get(
        &self,
        author: &AuthorPrincipal,
        key: &str,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        to_value(&self.sources.get(&author.tenant, key).await?)
    }

    /// The tenant's sources, ordered by key.
    pub async fn source_list(
        &self,
        author: &AuthorPrincipal,
        limit: u32,
        offset: u32,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let items = self.sources.page(&author.tenant, limit, offset).await?;
        Ok(json!({"items": items, "limit": limit, "offset": offset}))
    }

    /// `POST /sources/{key}/disable` and `/enable`: one revision-guarded state change.
    pub async fn source_set_status(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        body: &RevisionOnly,
        status: SourceStatus,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let expected = i64::try_from(body.expected_revision)
            .map_err(|_| BuilderError::Invalid("invalid expected revision".to_owned()))?;
        let status = match status {
            SourceStatus::Active => "active",
            SourceStatus::Disabled => "disabled",
        };
        let view = self
            .sources
            .set_status(&author.tenant, key, expected, status, &author.actor)
            .await?;
        to_value(&view)
    }

    /// The reference's `usage`: the four quota counts and the configured limits.
    pub async fn usage(&self, author: &AuthorPrincipal) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let used: Usage = self.builder.usage(&author.tenant).await?;
        Ok(json!({
            "used": {
                "sources": used.sources,
                "operations": used.operations,
                "tools": used.tools,
                "toolkits": used.toolkits,
            },
            "limits": {
                "sources": self.settings.max_sources,
                "operations": self.settings.max_operations,
                "tools": self.settings.max_tools,
                "toolkits": self.settings.max_toolkits,
            },
        }))
    }

    // ── specs ──────────────────────────────────────────────────────────────────────────────

    /// The reference's `operations_of`: every operation of a spec, for the preview.
    fn operations_of(
        &self,
        document: &Map<String, Value>,
    ) -> Result<Vec<OperationListing>, BuilderError> {
        list_operations(&Value::Object(document.clone()), None).map_err(BuilderError::from)
    }

    /// Fetch the source's OpenAPI document through its credential and the pinned egress, cache
    /// it by content hash and list what can be imported.
    pub async fn spec_fetch(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        body: &SpecFetchRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let view = self.sources.get(&author.tenant, key).await?;
        if view.status != SourceStatus::Active {
            return Err(BuilderError::Conflict("the source is disabled".to_owned()));
        }
        let (Some(fetcher), Some(registry)) = (&self.fetcher, &self.registry) else {
            return Err(BuilderError::Unavailable(
                "spec fetching is not available".to_owned(),
            ));
        };
        let path = checked_spec_path(
            body.path.as_ref().map(SpecPath::as_str),
            view.spec_path.as_deref(),
        )?;
        let allowed = self
            .fetch_limit
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .take(author.rate_tenant);
        if !allowed {
            return Err(BuilderError::RateLimited(
                "too many spec fetches this hour".to_owned(),
            ));
        }
        let limit = self.settings.spec_max_bytes;
        let source = match registry.get(&author.raw_tenant, key).await {
            Ok(source) => source,
            Err(error) => return Err(source_error(error)),
        };
        let raw = match fetcher
            .fetch_document(
                &source,
                &path,
                limit,
                Duration::from_secs_f64(SPEC_TIMEOUT_SECONDS),
            )
            .await
        {
            Ok(raw) => raw,
            Err(FetchError::Denied) => return Err(BuilderError::Upstream(unreachable())),
            Err(FetchError::Failed(kind)) => {
                tracing::info!(source_key = key, kind, "spec fetch failed");
                return Err(BuilderError::Upstream(format!(
                    "spec fetch failed ({kind}): check the base_url, spec path, the source \
                     credential and that the document is JSON under the size limit"
                )));
            }
        };
        let document = parse_document(&raw, limit)?;
        let sha = digest(&raw);
        let bytes = i32::try_from(raw.len()).map_err(|_| {
            BuilderError::Invalid("the spec is larger than the allowed size".to_owned())
        })?;
        self.sources
            .put_spec(
                &author.tenant,
                key,
                &sha,
                &Value::Object(document.clone()),
                bytes,
            )
            .await?;
        let (title, version) = title_version(&document);
        let operations = self.operations_of(&document)?;
        Ok(json!({
            "sha256": sha,
            "bytes": raw.len(),
            "title": title,
            "version": version,
            "operations": operations,
        }))
    }

    /// The cached document's operations (the reference's `spec_operations`).
    pub async fn spec_operations(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        sha256: &str,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let Some(spec) = self
            .sources
            .get_spec(&author.tenant, key, Some(sha256))
            .await?
        else {
            return Err(BuilderError::NotFound(
                "spec not found; fetch it first".to_owned(),
            ));
        };
        let document = spec_document(&spec)?;
        let (title, version) = title_version(&document);
        let operations = self.operations_of(&document)?;
        Ok(json!({
            "sha256": spec.sha256,
            "bytes": spec.bytes,
            "fetched_at": spec.fetched_at,
            "title": title,
            "version": version,
            "operations": operations,
        }))
    }

    // ── services and operations ────────────────────────────────────────────────────────────

    /// The tenant's service for `key`, created as v1, draft, on first use (the reference's
    /// `ensure_service`).
    async fn ensure_service(
        &self,
        author: &Author,
        key: &str,
    ) -> Result<ServiceRecord, BuilderError> {
        if let Some(record) = self.builder.service_for_source(&author.tenant, key).await? {
            return Ok(record);
        }
        let view = self.sources.get(&author.tenant, key).await?;
        if view.status != SourceStatus::Active {
            return Err(BuilderError::Conflict("the source is disabled".to_owned()));
        }
        let identity = uuid::Uuid::now_v7().to_string();
        let service_id = Uuid7::new(identity.clone())
            .map_err(|_| BuilderError::Failed("cannot mint a service identity".to_owned()))?;
        let hex = identity.replace('-', "");
        let suffix = &hex[hex.len() - 12..];
        let service_key = Name::new(truncated(&format!("t{suffix}_{key}"), 64))
            .map_err(|_| BuilderError::Invalid("invalid service key".to_owned()))?;
        let alias =
            Name::new(key).map_err(|_| BuilderError::Invalid("invalid source key".to_owned()))?;
        let manifest: ServiceManifest = serde_json::from_value(json!({
            "schema_version": 1,
            "service_id": service_id,
            "version": 1,
            "service_key": service_key,
            "destination_alias": alias,
            "auth_adapter": "source",
            "credential_profile_key": alias,
            "max_request_bytes":
                bound_or(view.max_request_bytes, DEFAULT_SERVICE_REQUEST_BYTES),
            "max_response_bytes":
                bound_or(view.max_response_bytes, DEFAULT_SERVICE_RESPONSE_BYTES),
        }))
        .map_err(|error| BuilderError::Failed(format!("invalid service manifest: {error}")))?;
        self.builder
            .create_service(&author.tenant, &manifest, &author.actor)
            .await?;
        self.builder
            .service_for_source(&author.tenant, key)
            .await?
            .ok_or_else(|| BuilderError::Failed("the created service disappeared".to_owned()))
    }

    /// Create draft operations from a cached spec; a re-import of a key adds a version.
    pub async fn operations_import(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        body: &ImportRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let Some(spec) = self
            .sources
            .get_spec(&author.tenant, key, Some(body.spec_sha256.as_str()))
            .await?
        else {
            return Err(BuilderError::NotFound(
                "spec not found; fetch it first".to_owned(),
            ));
        };
        let document = spec_document(&spec)?;
        let service = self.ensure_service(&author, key).await?;
        let reference = ExactReference {
            id: service.service_id.clone(),
            version: service.version,
        };
        let selection: Vec<Selection> = body.select.iter().map(Selection::from_entry).collect();
        let overrides = override_map(&body.overrides)?;
        let imported = import_openapi(
            &Value::Object(document),
            &reference,
            &selection,
            Some(&self.schemas),
            Some(&overrides),
        )
        .map_err(|error| BuilderError::Input(truncated(&error.reason, 500)))?;
        let existing: BTreeMap<String, OperationRecord> = self
            .builder
            .operations(&author.tenant, key)
            .await
            .map_err(authoring)?
            .into_iter()
            .map(|record| (record.op_key.as_str().to_owned(), record))
            .collect();
        let mut done: Vec<Value> = Vec::with_capacity(imported.len());
        for item in imported {
            let mut manifest = item.manifest;
            if let Some(prior) = existing.get(&item.op_key) {
                manifest.operation_id = prior.operation_id.clone();
                manifest.version = PositiveVersion::new(u64::from(prior.version.get()) + 1)
                    .map_err(|_| BuilderError::Conflict("operation version overflow".to_owned()))?;
            }
            self.builder
                .create_operation(
                    &author.tenant,
                    &manifest,
                    &author.actor,
                    Some(item.op_key.as_str()),
                    self.settings.max_operations,
                )
                .await
                .map_err(authoring)?;
            done.push(json!({
                "op_key": item.op_key,
                "operation_id": manifest.operation_id,
                "version": manifest.version,
                "method": manifest.method,
                "path": manifest.path_template,
                "effect": manifest.effect,
            }));
        }
        Ok(json!({"source_key": key, "imported": done}))
    }

    /// Every keyed operation of the source's service (the reference's `operation_list`).
    pub async fn operation_list(
        &self,
        author: &AuthorPrincipal,
        key: &str,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let records = self.builder.operation_list(&author.tenant, key).await?;
        Ok(json!({
            "source_key": key,
            "operations": records.iter().map(operation_view).collect::<Vec<_>>(),
        }))
    }

    /// A new draft version of an imported operation, with the patch's present fields replaced.
    pub async fn operation_update(
        &self,
        author: &AuthorPrincipal,
        key: &str,
        op_key: &str,
        body: &OperationPatch,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let record = self
            .builder
            .operation_update(
                &author.tenant,
                key,
                op_key,
                body,
                &author.actor,
                self.settings.max_operations,
            )
            .await
            .map_err(authoring)?;
        Ok(operation_view(&record))
    }

    // ── tools ──────────────────────────────────────────────────────────────────────────────

    /// The first operator-approved runner image, or the reference's unavailable refusal.
    fn runner_image(&self) -> Result<&str, BuilderError> {
        self.approved_runner_images
            .first()
            .map(String::as_str)
            .ok_or_else(|| {
                BuilderError::Unavailable(
                    "no runner image is approved on this deployment".to_owned(),
                )
            })
    }

    /// The reference's `tool_view`: the stored version, and for an authored package its
    /// non-host files and script keys.
    fn tool_view(
        descriptor: &VersionDescriptor,
        files: Option<&[PackageFile]>,
    ) -> Result<Value, BuilderError> {
        let mut out = to_value(descriptor)?;
        if let Some(files) = files {
            let user = packaging::user_files(files);
            let ops = packaging::parse_ops(files)?;
            let Value::Object(object) = &mut out else {
                return Err(BuilderError::Failed(
                    "tool descriptor is not an object".to_owned(),
                ));
            };
            object.insert("files".to_owned(), to_value(&user)?);
            object.insert("ops".to_owned(), to_value(&ops.keys().collect::<Vec<_>>())?);
        }
        Ok(out)
    }

    /// Create a draft tool (the reference's `tool_create`).
    pub async fn tool_create(
        &self,
        author: &AuthorPrincipal,
        body: &ToolCreate,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let references = self
            .builder
            .resolve_operations(&author.tenant, &body.ops)
            .await
            .map_err(authoring)?;
        let op_refs = op_refs(&references);
        let files = packaging::build_package(&body.files, &op_refs);
        let fields = packaging::manifest_fields(packaging::ManifestFieldArgs {
            public_name: &body.public_name,
            operation: &body.operation,
            description: &body.description,
            entrypoint: &body.entrypoint,
            input_schema: &body.input_schema,
            result_schema: body.result_schema.as_ref(),
            context_schema: None,
            effect: body.effect,
            limits: body.limits.as_ref(),
        });
        let tool_id = Uuid7::new(uuid::Uuid::now_v7().to_string())
            .map_err(|_| BuilderError::Failed("cannot mint a tool identity".to_owned()))?;
        let pinned: Vec<ExactReference> = references.values().cloned().collect();
        let manifest = packaging::tool_manifest(packaging::ToolManifestInput {
            tool_id: &tool_id,
            tenant_id: &author.tenant,
            version: PositiveVersion::new(1).expect("one is a positive version"),
            fields: &fields,
            files: &files,
            refs: &pinned,
            runner_image_digest: self.runner_image()?,
        })?;
        self.catalog
            .validate(&manifest, &files)
            .await
            .map_err(authoring_catalog)?;
        let descriptor = self
            .builder
            .create_tool(
                &author.tenant,
                &manifest,
                &files,
                &author.actor,
                self.settings.max_tools,
            )
            .await
            .map_err(authoring)?;
        Self::tool_view(&descriptor, Some(files.as_slice()))
    }

    /// Append the next draft version of an owned `kata_python` tool (the reference's
    /// `tool_update`).
    pub async fn tool_update(
        &self,
        author: &AuthorPrincipal,
        tool_id: &Uuid7,
        body: &ToolUpdate,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let (latest, stored) = self
            .builder
            .tool_get(&author.tenant, tool_id, None)
            .await
            .map_err(authoring)?;
        let old = &latest.manifest;
        if old.runtime != Runtime::KataPython || old.entrypoint.is_none() {
            // External runtimes (n8n_workflow, fr_project) have no authored package to edit.
            return Err(BuilderError::Input(
                "only kata_python tools can be edited".to_owned(),
            ));
        }
        let references = match &body.ops {
            Some(ops) => self
                .builder
                .resolve_operations(&author.tenant, ops)
                .await
                .map_err(authoring)?,
            // Re-pin each operation the tool already uses to its newest version.
            None => self
                .builder
                .repin(&author.tenant, &stored)
                .await
                .map_err(authoring)?,
        };
        let op_refs = op_refs(&references);
        let authored = match &body.files {
            Some(files) => files.clone(),
            None => packaging::user_files(&stored)
                .into_iter()
                .cloned()
                .collect(),
        };
        let files = packaging::build_package(&authored, &op_refs);
        // The reference's `body.field or old.field`: an empty schema is the old one.
        let input_schema = body
            .input_schema
            .as_ref()
            .filter(|schema| !schema.is_empty())
            .unwrap_or(&old.input_schema);
        let result_schema = body
            .result_schema
            .as_ref()
            .filter(|schema| !schema.is_empty())
            .unwrap_or(&old.result_schema);
        let entrypoint = old.entrypoint.as_deref().ok_or_else(|| {
            BuilderError::Input("only kata_python tools can be edited".to_owned())
        })?;
        let fields = packaging::manifest_fields(packaging::ManifestFieldArgs {
            public_name: &old.public_name,
            operation: &old.operation,
            description: body.description.as_deref().unwrap_or(&old.description),
            entrypoint,
            input_schema,
            result_schema: Some(result_schema),
            context_schema: Some(&old.context_schema),
            effect: body.effect.unwrap_or(old.effect),
            limits: Some(body.limits.as_ref().unwrap_or(&old.limits)),
        });
        let pinned: Vec<ExactReference> = references.values().cloned().collect();
        let manifest = packaging::tool_manifest(packaging::ToolManifestInput {
            tool_id,
            tenant_id: &author.tenant,
            version: PositiveVersion::new(u64::from(latest.version.get()) + 1)
                .map_err(|_| BuilderError::Conflict("tool version overflow".to_owned()))?,
            fields: &fields,
            files: &files,
            refs: &pinned,
            runner_image_digest: self.runner_image()?,
        })?;
        self.catalog
            .validate(&manifest, &files)
            .await
            .map_err(authoring_catalog)?;
        let descriptor = self
            .builder
            .append_tool(
                &author.tenant,
                tool_id,
                &manifest,
                &files,
                &author.actor,
                body.expected_revision,
            )
            .await
            .map_err(authoring)?;
        Self::tool_view(&descriptor, Some(files.as_slice()))
    }

    /// One tool version with its package, or the newest one when `version` is omitted.
    pub async fn tool_get(
        &self,
        author: &AuthorPrincipal,
        tool_id: &Uuid7,
        version: Option<PositiveVersion>,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let (descriptor, files) = self
            .builder
            .tool_get(&author.tenant, tool_id, version)
            .await?;
        Self::tool_view(&descriptor, Some(files.as_slice()))
    }

    /// The tenant's tool versions (the reference's `tool_list`).
    pub async fn tool_list(
        &self,
        author: &AuthorPrincipal,
        limit: u32,
        offset: u32,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let items: Vec<Value> = self
            .builder
            .tool_list(&author.tenant, limit, offset)
            .await?
            .iter()
            .map(|definition| {
                json!({
                    "tool_id": definition.tool_id,
                    "version": definition.version,
                    "public_name": definition.public_name,
                    "revision": definition.revision,
                    "status": definition.status,
                })
            })
            .collect();
        Ok(json!({"items": items, "limit": limit, "offset": offset}))
    }

    /// The reference's `count_test_runs`: draft admissions in the trailing hour.
    async fn count_test_runs(&self, tenant: &AuthorityId) -> Result<i64, BuilderError> {
        sqlx::query_scalar(
            "SELECT count(*) FROM public.mcp_runs WHERE tenant_id=$1::uuid AND mode='draft' \
             AND created_at > clock_timestamp() - interval '1 hour'",
        )
        .bind(tenant.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_failed)
    }

    /// Run an owned draft or published tool version once, with no binding. A tool whose effect
    /// is `writes` needs `confirm_writes`.
    pub async fn tool_test(
        &self,
        author: &AuthorPrincipal,
        tool_id: &Uuid7,
        version: PositiveVersion,
        body: &ToolTestRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let Some(settings) = &self.draft else {
            return Err(BuilderError::Unavailable(
                "test runs are not available: execution is disabled".to_owned(),
            ));
        };
        if !settings.execution_enabled {
            return Err(BuilderError::Unavailable(
                "test runs are not available: execution is disabled".to_owned(),
            ));
        }
        if self.count_test_runs(&author.tenant).await?
            >= i64::try_from(self.settings.test_runs_per_hour).unwrap_or(i64::MAX)
        {
            return Err(BuilderError::RateLimited(
                "too many test runs this hour".to_owned(),
            ));
        }
        let inputs = Value::Object(body.inputs.clone());
        self.builder
            .submit_draft(
                &author.tenant,
                &author.license_id,
                tool_id,
                version,
                &inputs,
                body.confirm_writes,
                None,
                settings,
                self.minter.as_deref(),
            )
            .await
            .map_err(BuilderError::from)
    }

    /// The run envelope plus the call trace of a draft test run.
    pub async fn run_get(
        &self,
        author: &AuthorPrincipal,
        run_id: &Uuid7,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        if self.draft.is_none() {
            return Err(BuilderError::Unavailable(
                "runs are not available".to_owned(),
            ));
        }
        self.builder
            .draft_run(&author.tenant, run_id)
            .await
            .map_err(BuilderError::from)
    }

    /// Publish a tool version together with the draft service and operation versions it pins,
    /// in one transaction (the reference's `tool_publish`).
    pub async fn tool_publish(
        &self,
        author: &AuthorPrincipal,
        tool_id: &Uuid7,
        version: PositiveVersion,
        body: &ToolPublishRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let (descriptor, files) = self
            .builder
            .tool_get(&author.tenant, tool_id, Some(version))
            .await
            .map_err(authoring)?;
        self.catalog
            .validate(&descriptor.manifest, &files)
            .await
            .map_err(authoring_catalog)?;
        let result = self
            .builder
            .publish_tool(
                &author.tenant,
                tool_id,
                version,
                &author.actor,
                body.expected_revision,
            )
            .await
            .map_err(authoring)?;
        Self::tool_view(&result, None)
    }

    /// Disable or retire a tool version (the reference's `tool_set_status`).
    pub async fn tool_set_status(
        &self,
        author: &AuthorPrincipal,
        tool_id: &Uuid7,
        version: PositiveVersion,
        status: VersionStatus,
        revision: PositiveVersion,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let result = self
            .catalog
            .transition(
                &author.tenant,
                tool_id,
                version,
                status,
                &author.actor,
                revision,
            )
            .await?;
        Self::tool_view(&result, None)
    }

    // ── toolkits ───────────────────────────────────────────────────────────────────────────

    /// The newest published version of an owned tool (the reference's `published_version`).
    async fn published_version(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
    ) -> Result<PositiveVersion, BuilderError> {
        let version: Option<i32> = sqlx::query_scalar(
            "SELECT max(version) FROM public.mcp_tool_versions \
             WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND status='published'",
        )
        .bind(tenant.as_str())
        .bind(tool_id.as_str())
        .fetch_one(&self.pool)
        .await
        .map_err(storage_failed)?;
        let Some(version) = version else {
            return Err(BuilderError::Conflict(format!(
                "tool {tool_id} has no published version; publish it first"
            )));
        };
        let version = u64::try_from(version)
            .map_err(|_| BuilderError::Failed("invalid published version".to_owned()))?;
        PositiveVersion::new(version)
            .map_err(|_| BuilderError::Failed("invalid published version".to_owned()))
    }

    /// Create a draft toolkit at version one, or append its next draft version.
    pub async fn toolkit_create(
        &self,
        author: &AuthorPrincipal,
        body: &ToolkitRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let toolkit_id = match body.toolkit_id.clone() {
            Some(identity) => identity,
            None => Uuid7::new(uuid::Uuid::now_v7().to_string())
                .map_err(|_| BuilderError::Failed("cannot mint a toolkit identity".to_owned()))?,
        };
        let mut selections: Vec<Value> = Vec::with_capacity(body.tools.len());
        for entry in &body.tools {
            let version = match entry.version {
                Some(version) => version,
                None => {
                    self.published_version(&author.tenant, &entry.tool_id)
                        .await?
                }
            };
            let (descriptor, _files) = self
                .builder
                .tool_get(&author.tenant, &entry.tool_id, Some(version))
                .await
                .map_err(authoring)?;
            // The selection keeps the tool's own limits; only the binding's ceiling narrows them.
            selections.push(json!({
                "tool": {
                    "id": entry.tool_id,
                    "version": version,
                    "tenant_id": author.tenant,
                },
                "limits": descriptor.manifest.limits,
            }));
        }
        let manifest: ToolkitManifest = serde_json::from_value(json!({
            "schema_version": 1,
            "toolkit_id": toolkit_id,
            "tenant_id": author.tenant,
            "version": 1,
            "name": body.name,
            "description": body.description,
            "tools": selections,
        }))
        .map_err(|error| BuilderError::Input(truncated(&error.to_string(), 500)))?;
        let result = self
            .builder
            .write_toolkit(
                &self.resolver,
                &author.tenant,
                &author.actor,
                &manifest,
                body.expected_revision,
                Some(self.settings.max_toolkits),
            )
            .await
            .map_err(authoring)?;
        to_value(&result)
    }

    /// Publish a toolkit version, then re-bind the tenant's product bindings so they include it;
    /// a re-bind problem is reported, it does not undo the publication.
    pub async fn toolkit_publish(
        &self,
        author: &AuthorPrincipal,
        toolkit_id: &Uuid7,
        version: PositiveVersion,
        body: &ToolkitPublishRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        let result = self
            .builder
            .publish_toolkit(
                &self.resolver,
                &author.tenant,
                &author.actor,
                toolkit_id,
                version,
                body.expected_revision,
            )
            .await
            .map_err(toolkit_publish_error)?;
        let mut out = to_value(&result)?;
        let bindings = match self.rebind_products(&author, None).await {
            Ok(bindings) => bindings,
            Err(error) => {
                // Report, never undo the publication (the reference's `toolkit_publish`).
                tracing::warn!(%error, "rebind after toolkit publish failed");
                rebind_failed_report()
            }
        };
        if let Value::Object(object) = &mut out {
            object.insert("bindings".to_owned(), bindings);
        }
        Ok(out)
    }

    /// Re-provision the tenant's existing product bindings so they pin its published toolkits.
    pub async fn rebind(
        &self,
        author: &AuthorPrincipal,
        body: &BindRequest,
    ) -> Result<Value, BuilderError> {
        let author = author_of(author)?;
        self.rebind_products(&author, body.product.as_deref()).await
    }

    async fn rebind_products(
        &self,
        author: &Author,
        product: Option<&str>,
    ) -> Result<Value, BuilderError> {
        let Some(ensure) = &self.ensure else {
            return Err(BuilderError::Unavailable(
                "binding provisioning is not available".to_owned(),
            ));
        };
        let products: Vec<RebindEntry> = ensure
            .rebind(&author.tenant, &author.actor, &author.license_id, product)
            .await?;
        Ok(json!({
            "products": products.iter().map(RebindEntry::as_json).collect::<Vec<_>>(),
        }))
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────

/// The reference's `DEFAULT_SERVICE_REQUEST_BYTES`.
const DEFAULT_SERVICE_REQUEST_BYTES: u32 = 1_048_576;
/// The reference's `DEFAULT_SERVICE_RESPONSE_BYTES`.
const DEFAULT_SERVICE_RESPONSE_BYTES: u32 = 10_485_760;

/// The reference's "not reachable" upstream message.
fn unreachable() -> String {
    "the source is not reachable: it was refused by the egress policy, is disabled or its \
     credential is unavailable"
        .to_owned()
}

/// A resolved author: the tenant, the proven licence and its attribution.
struct Author {
    tenant: AuthorityId,
    license_id: AuthorityId,
    raw_tenant: Rfc4122Uuid,
    rate_tenant: uuid::Uuid,
    actor: Attribution,
}

/// The reference's `AuthorPrincipal` conversion: the tenant and licence become the storage
/// authority identities, and the attribution's subject is bounded to 256 characters.
fn author_of(principal: &AuthorPrincipal) -> Result<Author, BuilderError> {
    let tenant = AuthorityId::new(principal.tenant_id.to_string())
        .map_err(|_| BuilderError::Forbidden("invalid tenant identity".to_owned()))?;
    let license_id = AuthorityId::new(principal.license_id.to_string())
        .map_err(|_| BuilderError::Forbidden("invalid licence identity".to_owned()))?;
    let rate_tenant = uuid::Uuid::parse_str(&principal.tenant_id.to_string())
        .map_err(|_| BuilderError::Forbidden("invalid tenant identity".to_owned()))?;
    let subject = truncated(&principal.subject, 256);
    Ok(Author {
        tenant,
        license_id: license_id.clone(),
        raw_tenant: principal.tenant_id,
        rate_tenant,
        actor: Attribution {
            subject,
            license_id: Some(license_id),
        },
    })
}

/// A source registry refusal: a denial is the reference's "not reachable" upstream; a database
/// failure is this server's problem.
fn source_error(error: SourceError) -> BuilderError {
    match error {
        SourceError::Store(error) => storage_failed(error),
        SourceError::Denied(_) | SourceError::Crypto => BuilderError::Upstream(unreachable()),
    }
}

fn to_value<T: serde::Serialize>(value: &T) -> Result<Value, BuilderError> {
    serde_json::to_value(value)
        .map_err(|_| BuilderError::Failed("a builder value is not serialisable".to_owned()))
}

/// A source-specific bound, or the reference's default when the row carries none.
fn bound_or(value: Option<i64>, default: u32) -> u32 {
    value
        .and_then(|value| u32::try_from(value).ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// One operation record as the reference's `operation_view`.
fn operation_view(record: &OperationRecord) -> Value {
    let manifest = &record.manifest;
    json!({
        "op_key": record.op_key,
        "operation_id": record.operation_id,
        "version": record.version,
        "status": record.status,
        "method": manifest.method,
        "path_template": manifest.path_template,
        "effect": manifest.effect,
        "idempotency": manifest.idempotency,
        "timeout_seconds": manifest.timeout_seconds,
        "expected_error_statuses": manifest.expected_error_statuses,
        "empty_response": manifest.empty_response,
        "response_projection": manifest.response_projection,
        "redact_fields": manifest.redact_fields,
        "input_schema": manifest.input_schema,
        "output_schema": manifest.output_schema,
    })
}

/// A stored document as the object the importers read.
fn spec_document(spec: &SpecRecord) -> Result<Map<String, Value>, BuilderError> {
    match &spec.document {
        Value::Object(document) => Ok(document.clone()),
        _ => Err(BuilderError::Failed(
            "the stored spec is not a JSON object".to_owned(),
        )),
    }
}

/// The reference's `{k: v.model_dump(exclude_none=True)}` for the import overrides.
fn override_map(
    overrides: &BTreeMap<String, OperationOverride>,
) -> Result<Map<String, Value>, BuilderError> {
    let mut out = Map::new();
    for (key, override_value) in overrides {
        let mut value = serde_json::to_value(override_value).map_err(|_| {
            BuilderError::Failed("an operation override is not serialisable".to_owned())
        })?;
        if let Value::Object(fields) = &mut value {
            fields.retain(|_, field| !field.is_null());
        }
        out.insert(key.clone(), value);
    }
    Ok(out)
}

/// The resolved operations as the package's `ops.py` table.
fn op_refs(references: &BTreeMap<String, ExactReference>) -> OpRefs {
    references
        .iter()
        .map(|(key, reference)| (key.clone(), (reference.id.clone(), reference.version)))
        .collect()
}

/// The reference's `CheckViolation` boundary for a toolkit publication: a deferred dependency
/// check that fires at COMMIT is the dependencies refusal, never a 500.
fn toolkit_publish_error(error: BuilderStoreError) -> BuilderError {
    if let BuilderStoreError::Database(sqlx::Error::Database(database)) = &error
        && database.code().as_deref() == Some("23514")
    {
        return BuilderError::Conflict("toolkit dependencies unavailable".to_owned());
    }
    BuilderError::from(error)
}
