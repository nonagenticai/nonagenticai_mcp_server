//! The fourteen platform-authoring operations under `/mcp/services` and `/mcp/operations`.
//!
//! Ported from the reference `src/routers/operations.py`. That router reads every body through
//! `Depends(json_contract(Model))`, so FastAPI declares NO request body and NO response model:
//! the OpenAPI annotations below carry no `request_body`, every success response declares the
//! empty `{}` schema (`AnyJson`), and each operation with a path or query parameter declares
//! the reference's 422 `HTTPValidationError`. Handlers return JSON at runtime exactly as the
//! reference does.
//!
//! Authorization is two-layered, as in the reference: the caller must be a management
//! principal (`get_operator`) and must have presented the platform operator key
//! (`principal.platform`). A missing platform pool is the reference's
//! `503 {"detail": "platform_authoring_unavailable"}`. Every other refusal is
//! `{"error": <code>}` with `Cache-Control: no-store`: permission is `403 forbidden`, a missing
//! row `404 not_found`, a conflict `409 revision_or_lifecycle_conflict`, a source that cannot
//! serve the service `409 source_unavailable` and every validation refusal
//! `422 invalid_request`.

use axum::Json;
use axum::body::Bytes as RawBody;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use utoipa::IntoParams;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::error::CatalogError;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::importer::{OperationImport, import_drafts};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{Attribution, ExactReference, OperationManifest, ServiceManifest};
use crate::catalog::service::{CatalogService, PlatformCatalogService, PlatformServiceError};
use crate::catalog::validation::SchemaLimits;
use crate::config::PackageLimits;
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::catalog::{
    CatalogRepository, CatalogStoreError, PlatformCatalogRepository, PlatformKind,
    PlatformStoreError,
};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A platform-authoring refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformError {
    /// `PermissionError`: the caller is not a platform operator.
    Forbidden,
    /// The reference's `HTTPException(503, "platform_authoring_unavailable")`.
    Unavailable,
    /// `CatalogNotFoundError`: no such exact platform version.
    NotFound,
    /// `CatalogConflictError` / a check or unique violation.
    Conflict,
    /// `SourceUnavailableError`: the service's source is missing, inactive or disagrees.
    SourceUnavailable,
    /// A validation refusal (`ValueError`, the request model, the path/query bounds).
    Invalid,
    /// The database failed; a 422 would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for PlatformError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_or_lifecycle_conflict"),
            Self::SourceUnavailable => (StatusCode::CONFLICT, "source_unavailable"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            // The reference raises `HTTPException`, which FastAPI renders as `{"detail": …}`.
            Self::Unavailable => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "detail": "platform_authoring_unavailable" })),
                )
                    .into_response();
            }
        };
        let mut response = (status, Json(json!({ "error": code }))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl From<PlatformServiceError> for PlatformError {
    fn from(error: PlatformServiceError) -> Self {
        match error {
            PlatformServiceError::Invalid(_) => Self::Invalid,
            PlatformServiceError::Store(error) => error.into(),
        }
    }
}

impl From<PlatformStoreError> for PlatformError {
    fn from(error: PlatformStoreError) -> Self {
        match error {
            PlatformStoreError::Conflict(_) => Self::Conflict,
            PlatformStoreError::NotFound(_) => Self::NotFound,
            PlatformStoreError::SourceUnavailable(_) => Self::SourceUnavailable,
            PlatformStoreError::Invalid(_) => Self::Invalid,
            // A stored row the model can no longer parse: the reference's validation error
            // on that read.
            PlatformStoreError::Corrupt(_) => Self::Invalid,
            PlatformStoreError::Database(error) => {
                tracing::error!(%error, "platform catalog database failure");
                Self::Internal
            }
        }
    }
}

impl From<CatalogStoreError> for PlatformError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            CatalogStoreError::Corrupt(_) => Self::Invalid,
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "platform catalog database failure");
                Self::Internal
            }
        }
    }
}

impl From<CatalogError> for PlatformError {
    fn from(_error: CatalogError) -> Self {
        Self::Invalid
    }
}

// ── request models ────────────────────────────────────────────────────────────────────────

/// The reference's `ServiceAppend`: a service manifest and the revision the caller last saw.
///
/// `expected_revision` is a plain `int` in the reference (not a `PositiveVersion`), so a
/// non-positive value is simply a stale revision — a 409, not a validation refusal.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAppend {
    manifest: ServiceManifest,
    expected_revision: i64,
}

/// The reference's query bounds for `GET /mcp/services` and `GET /mcp/operations`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PlatformListQuery {
    /// Maximum number of versions to return.
    #[param(minimum = 1, maximum = 100, default = 50)]
    pub limit: Option<u32>,
    /// Versions to skip.
    #[param(minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

// ── handlers: services ────────────────────────────────────────────────────────────────────

/// Create a platform service identity at version 1.
#[utoipa::path(
    post,
    path = "/mcp/services",
    tag = "services",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let manifest: ServiceManifest = parse_body(&body)?;
    if manifest.version.get() != 1 {
        return Err(CatalogError::new("first version required").into());
    }
    service
        .add_service(&manifest, &actor(&principal), None)
        .await?;
    Ok(draft_response(StatusCode::CREATED, &manifest))
}

/// Append the next draft version to a platform service identity.
#[utoipa::path(
    post,
    path = "/mcp/services/{identity}/versions",
    tag = "services",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn append_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let identity = Uuid7::new(identity).map_err(|_| PlatformError::Invalid)?;
    let payload: ServiceAppend = parse_body(&body)?;
    if payload.manifest.service_id != identity {
        return Err(CatalogError::new("identity mismatch").into());
    }
    service
        .add_service(
            &payload.manifest,
            &actor(&principal),
            Some(payload.expected_revision),
        )
        .await?;
    Ok(draft_response(StatusCode::CREATED, &payload.manifest))
}

/// Every platform service version, ordered by identity then version.
#[utoipa::path(
    get,
    path = "/mcp/services",
    tag = "services",
    params(PlatformListQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_services(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    query: Result<Query<PlatformListQuery>, QueryRejection>,
) -> Result<Response, PlatformError> {
    listing(state, principal, query, PlatformKind::Service).await
}

/// One exact platform service version.
#[utoipa::path(
    get,
    path = "/mcp/services/{identity}/versions/{version}",
    tag = "services",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    detail(state, principal, identity, version, PlatformKind::Service).await
}

/// Re-run the platform service validation with no lifecycle change.
#[utoipa::path(
    post,
    path = "/mcp/services/{identity}/versions/{version}/validate",
    tag = "services",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn validate_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Service,
        None,
    )
    .await
}

/// Publish a platform service version. The named source must exist and agree.
#[utoipa::path(
    post,
    path = "/mcp/services/{identity}/versions/{version}/publish",
    tag = "services",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Service,
        Some(VersionStatus::Published),
    )
    .await
}

/// Disable a platform service version.
#[utoipa::path(
    post,
    path = "/mcp/services/{identity}/versions/{version}/disable",
    tag = "services",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_service(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Service,
        Some(VersionStatus::Disabled),
    )
    .await
}

// ── handlers: operations ──────────────────────────────────────────────────────────────────

/// Append the next draft version to a platform operation identity.
#[utoipa::path(
    post,
    path = "/mcp/operations/{identity}/versions",
    tag = "operations",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn append_operation(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let identity = Uuid7::new(identity).map_err(|_| PlatformError::Invalid)?;
    let manifest: OperationManifest = parse_body(&body)?;
    if manifest.operation_id != identity {
        return Err(CatalogError::new("identity mismatch").into());
    }
    service.add_operation(&manifest, &actor(&principal)).await?;
    Ok(draft_response(StatusCode::CREATED, &manifest))
}

/// Import bounded OpenAPI 3.1 drafts as version-1 platform operations.
#[utoipa::path(
    post,
    path = "/mcp/operations/import",
    tag = "operations",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn import_operations(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let payload: OperationImport = parse_body(&body)?;
    let operations = import_drafts(&payload, service.limits())?;
    let (parent, _status) = service.service(&payload.service).await?;
    if operations
        .iter()
        .any(|operation| operation.max_response_bytes > parent.max_response_bytes)
    {
        return Err(CatalogError::new("import response limit exceeds service ceiling").into());
    }
    service
        .insert_drafts(&operations, &actor(&principal))
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "items": operations, "status": "draft" })),
    )
        .into_response())
}

/// Every platform operation version, ordered by identity then version.
#[utoipa::path(
    get,
    path = "/mcp/operations",
    tag = "operations",
    params(PlatformListQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_operations(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    query: Result<Query<PlatformListQuery>, QueryRejection>,
) -> Result<Response, PlatformError> {
    listing(state, principal, query, PlatformKind::Operation).await
}

/// One exact platform operation version.
#[utoipa::path(
    get,
    path = "/mcp/operations/{identity}/versions/{version}",
    tag = "operations",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect_operation(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    detail(state, principal, identity, version, PlatformKind::Operation).await
}

/// Re-run the platform operation validation (schemas and ownership reads).
#[utoipa::path(
    post,
    path = "/mcp/operations/{identity}/versions/{version}/validate",
    tag = "operations",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn validate_operation(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Operation,
        None,
    )
    .await
}

/// Publish a platform operation version. Its service version must be published.
#[utoipa::path(
    post,
    path = "/mcp/operations/{identity}/versions/{version}/publish",
    tag = "operations",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_operation(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Operation,
        Some(VersionStatus::Published),
    )
    .await
}

/// Disable a platform operation version.
#[utoipa::path(
    post,
    path = "/mcp/operations/{identity}/versions/{version}/disable",
    tag = "operations",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_operation(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, PlatformError> {
    lifecycle(
        state,
        principal,
        identity,
        version,
        PlatformKind::Operation,
        Some(VersionStatus::Disabled),
    )
    .await
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, PlatformError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(PlatformError::Forbidden)
    }
}

/// The reference's `platform` dependency: platform authorization first, then the pool.
fn platform(
    state: &AppState,
    principal: &Principal,
) -> Result<PlatformCatalogService, PlatformError> {
    if !principal.platform {
        return Err(PlatformError::Forbidden);
    }
    let Some(pool) = state.platform.clone() else {
        return Err(PlatformError::Unavailable);
    };
    Ok(PlatformCatalogService::new(
        PlatformCatalogRepository::new(pool),
        CatalogService::new(
            CatalogRepository::new(state.pool.clone()),
            SchemaLimits::default(),
            PackageLimits::default(),
        ),
    ))
}

fn actor(principal: &Principal) -> Attribution {
    Attribution {
        subject: principal.subject.clone(),
        license_id: AuthorityId::new(principal.license_id.to_string()).ok(),
    }
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, PlatformError> {
    serde_json::from_slice(body).map_err(|_| PlatformError::Invalid)
}

/// Parse one path `version` into the reference's `PositiveVersion`: the route's `int` is
/// unbounded, but the `ExactReference` it feeds is not.
fn version_parameter(value: &str) -> Result<PositiveVersion, PlatformError> {
    let value: i64 = value.parse().map_err(|_| PlatformError::Invalid)?;
    if value < 1 {
        return Err(PlatformError::Invalid);
    }
    PositiveVersion::new(u64::try_from(value).expect("a positive integer fits u64"))
        .map_err(|_| PlatformError::Invalid)
}

/// The reference's create/append body: the submitted manifest and its draft status.
fn draft_response<T: serde::Serialize>(status: StatusCode, manifest: &T) -> Response {
    (
        status,
        Json(json!({ "manifest": manifest, "status": "draft" })),
    )
        .into_response()
}

async fn listing(
    state: AppState,
    principal: AuthPrincipal,
    query: Result<Query<PlatformListQuery>, QueryRejection>,
    kind: PlatformKind,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let Query(query) = query.map_err(|_| PlatformError::Invalid)?;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) {
        return Err(PlatformError::Invalid);
    }
    let definitions = service.definitions(kind, limit, offset).await?;
    let items: Vec<Value> = definitions
        .iter()
        .map(|definition| match kind {
            PlatformKind::Service => json!({
                "service_id": definition.id,
                "version": definition.version,
                "status": definition.status,
            }),
            PlatformKind::Operation => json!({
                "operation_id": definition.id,
                "version": definition.version,
                "status": definition.status,
            }),
        })
        .collect();
    Ok(Json(json!({ "items": items })).into_response())
}

async fn detail(
    state: AppState,
    principal: AuthPrincipal,
    identity: String,
    version: String,
    kind: PlatformKind,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let reference = ExactReference {
        id: Uuid7::new(identity).map_err(|_| PlatformError::Invalid)?,
        version: version_parameter(&version)?,
    };
    let value = match kind {
        PlatformKind::Service => {
            let (manifest, status) = service.service(&reference).await?;
            json!({ "manifest": manifest, "status": status })
        }
        PlatformKind::Operation => {
            let (manifest, status) = service.operation(&reference).await?;
            json!({ "manifest": manifest, "status": status })
        }
    };
    Ok(Json(value).into_response())
}

async fn lifecycle(
    state: AppState,
    principal: AuthPrincipal,
    identity: String,
    version: String,
    kind: PlatformKind,
    status: Option<VersionStatus>,
) -> Result<Response, PlatformError> {
    let principal = require_management(principal)?;
    let service = platform(&state, &principal)?;
    let reference = ExactReference {
        id: Uuid7::new(identity).map_err(|_| PlatformError::Invalid)?,
        version: version_parameter(&version)?,
    };
    match kind {
        PlatformKind::Operation => {
            let (manifest, _status) = service.operation(&reference).await?;
            service.validate_schemas(&manifest)?;
            service.ownership_reads(&manifest.scope_rules).await?;
        }
        PlatformKind::Service => {
            service.service(&reference).await?;
        }
    }
    if let Some(status) = status {
        service
            .transition(kind, &reference, status, &actor(&principal))
            .await?;
    }
    let label = status.map_or("valid", status_text);
    Ok((
        StatusCode::OK,
        Json(json!({
            "id": reference.id,
            "version": reference.version,
            "status": label,
            "credentials_verified": false,
        })),
    )
        .into_response())
}

fn status_text(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "draft",
        VersionStatus::Published => "published",
        VersionStatus::Disabled => "disabled",
        VersionStatus::Retired => "retired",
    }
}
