//! The six tenant toolkit operations under `/mcp/toolkits`.
//!
//! Ported from the reference `src/routers/bindings.py`. The reference reads every body through
//! `Depends(json_contract(Model))`, so FastAPI declares NO request body and NO response model:
//! the OpenAPI annotations below carry no `request_body`, every success response declares the
//! empty `{}` schema (`AnyJson`), and each operation with a path or query parameter declares the
//! reference's 422 `HTTPValidationError`. The request models are deserialized from the raw bytes
//! exactly as `parse_body` does in [`crate::routes::tools`].
//!
//! A refusal is `{"error": <code>}` with `Cache-Control: no-store`: permission is
//! `403 forbidden`, a missing row `404 not_found`, a revision/lifecycle conflict
//! `409 revision_or_lifecycle_conflict` and every other refusal `422 invalid_request`.

use axum::Json;
use axum::body::Bytes as RawBody;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::json;
use utoipa::IntoParams;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::toolkit_models::{ToolkitDescriptor, ToolkitManifest};
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::catalog::CatalogStoreError;
use crate::storage::toolkits as toolkit_store;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::{ToolkitService, ToolkitServiceError};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A toolkit refusal, rendered as the reference's `{"error": <code>}` with `no-store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolkitError {
    /// `PermissionError`: the caller may not perform this operation, or the manifest is not
    /// the caller's tenant's.
    Forbidden,
    /// `CatalogNotFoundError`: no such tenant-owned identity or version.
    NotFound,
    /// `CatalogConflictError`: a stale revision, a lifecycle refusal or a unique violation.
    Conflict,
    /// A validation refusal (`ValueError`, the pydantic request model, the path/query bounds).
    Invalid,
    /// The database failed; a 422 would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for ToolkitError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_or_lifecycle_conflict"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let mut response = (status, Json(json!({ "error": code }))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl From<ToolkitServiceError> for ToolkitError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Forbidden,
            ToolkitServiceError::Invalid(_) => Self::Invalid,
            ToolkitServiceError::Conflict(_) => Self::Conflict,
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for ToolkitError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            // A stored row the model can no longer parse: the reference's ValidationError on
            // that read, which its exception handler maps to 422.
            CatalogStoreError::Corrupt(_) => Self::Invalid,
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "toolkit database failure");
                Self::Internal
            }
        }
    }
}

// ── request models ────────────────────────────────────────────────────────────────────────
//
// `utoipa`'s axum resolver treats any handler argument whose type is literally named `Bytes`
// as a declared request body. The reference reads every body through
// `Depends(json_contract(Model))`, so its document declares NO request body on these
// operations; the `RawBody` alias below keeps the raw-bytes extraction without the document
// growing a body the reference does not have.

/// The reference's `ToolkitUpdate`: the manifest plus the revision the caller last saw.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ToolkitUpdate {
    manifest: ToolkitManifest,
    expected_revision: PositiveVersion,
}

/// The reference's `RevisionRequest`: the revision the caller last saw.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionRequest {
    expected_revision: PositiveVersion,
}

/// The reference's query bounds for `GET /mcp/toolkits`.
///
/// The reference handler declares plain `int` parameters with defaults, so its generated
/// document carries `{"type": "integer", "default": …}` and no minimum/maximum; the handler
/// itself performs the bounds check. `u32` would add an implicit `minimum: 0`, so the fields
/// mirror the reference's signed `int`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ToolkitsQuery {
    /// Maximum number of toolkits to return.
    #[param(default = 50)]
    pub limit: Option<i32>,
    /// Toolkits to skip.
    #[param(default = 0)]
    pub offset: Option<i32>,
}

// ── success responses ─────────────────────────────────────────────────────────────────────

/// One row of the reference's `GET /mcp/toolkits` query.
#[derive(Debug, Serialize)]
struct ToolkitItem<'a> {
    toolkit_id: &'a Uuid7,
    name: &'a Name,
    revision: PositiveVersion,
}

/// The reference's list envelope: the page plus the window it answered for.
#[derive(Debug, Serialize)]
struct ToolkitPage<'a> {
    items: Vec<ToolkitItem<'a>>,
    limit: u32,
    offset: u32,
}

/// A successful write: the reference returns the affected `ToolkitDescriptor`.
fn descriptor_response(status: StatusCode, descriptor: ToolkitDescriptor) -> Response {
    (status, Json(descriptor)).into_response()
}

// ── handlers ──────────────────────────────────────────────────────────────────────────────

/// Create a tenant toolkit identity at version 1.
#[utoipa::path(
    post,
    path = "/mcp/toolkits",
    tag = "toolkits",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, ToolkitError> {
    let principal = require_management(principal)?;
    let manifest: ToolkitManifest = parse_body(&body)?;
    let descriptor = service(&state).write(&principal, &manifest, None).await?;
    Ok(descriptor_response(StatusCode::CREATED, descriptor))
}

/// Append the next draft version to an owned toolkit identity.
#[utoipa::path(
    post,
    path = "/mcp/toolkits/{identity}/versions",
    tag = "toolkits",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn append_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, ToolkitError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolkitError::Invalid)?;
    let payload: ToolkitUpdate = parse_body(&body)?;
    if payload.manifest.toolkit_id != identity {
        return Err(ToolkitError::Invalid);
    }
    let descriptor = service(&state)
        .write(
            &principal,
            &payload.manifest,
            Some(payload.expected_revision),
        )
        .await?;
    Ok(descriptor_response(StatusCode::CREATED, descriptor))
}

/// Every tenant toolkit identity, ordered by identity.
#[utoipa::path(
    get,
    path = "/mcp/toolkits",
    tag = "toolkits",
    params(ToolkitsQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_toolkits(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    query: Result<Query<ToolkitsQuery>, QueryRejection>,
) -> Result<Response, ToolkitError> {
    let principal = require_management(principal)?;
    let Query(query) = query.map_err(|_| ToolkitError::Invalid)?;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) || offset < 0 {
        return Err(ToolkitError::Invalid);
    }
    let limit = u32::try_from(limit).expect("a checked limit fits u32");
    let offset = u32::try_from(offset).expect("a non-negative signed offset fits u32");
    let listings = service(&state).list(&principal, limit, offset).await?;
    Ok(Json(ToolkitPage {
        items: listings
            .iter()
            .map(|listing| ToolkitItem {
                toolkit_id: &listing.toolkit_id,
                name: &listing.name,
                revision: listing.revision,
            })
            .collect(),
        limit,
        offset,
    })
    .into_response())
}

/// One exact toolkit version as stored.
#[utoipa::path(
    get,
    path = "/mcp/toolkits/{identity}/versions/{version}",
    tag = "toolkits",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, ToolkitError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolkitError::Invalid)?;
    let version = version_parameter(&version)?;
    let mut connection = state.pool.acquire().await.map_err(|error| {
        tracing::error!(%error, "toolkit database failure");
        ToolkitError::Internal
    })?;
    let descriptor =
        toolkit_store::get_toolkit(&mut connection, &tenant_id(&principal), &identity, version)
            .await?;
    Ok(Json(descriptor).into_response())
}

/// Publish a draft toolkit version.
#[utoipa::path(
    post,
    path = "/mcp/toolkits/{identity}/versions/{version}/publish",
    tag = "toolkits",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
    body: RawBody,
) -> Result<Response, ToolkitError> {
    transition(
        state,
        principal,
        identity,
        version,
        body,
        VersionStatus::Published,
    )
    .await
}

/// Disable a toolkit version.
#[utoipa::path(
    post,
    path = "/mcp/toolkits/{identity}/versions/{version}/disable",
    tag = "toolkits",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
    body: RawBody,
) -> Result<Response, ToolkitError> {
    transition(
        state,
        principal,
        identity,
        version,
        body,
        VersionStatus::Disabled,
    )
    .await
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

async fn transition(
    state: AppState,
    principal: AuthPrincipal,
    identity: String,
    version: String,
    body: RawBody,
    status: VersionStatus,
) -> Result<Response, ToolkitError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolkitError::Invalid)?;
    let version = version_parameter(&version)?;
    let payload: RevisionRequest = parse_body(&body)?;
    let descriptor = service(&state)
        .transition(
            &principal,
            &identity,
            version,
            status,
            payload.expected_revision,
        )
        .await?;
    Ok(descriptor_response(StatusCode::OK, descriptor))
}

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, ToolkitError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(ToolkitError::Forbidden)
    }
}

fn tenant_id(principal: &Principal) -> AuthorityId {
    AuthorityId::new(principal.tenant_id.to_string()).expect("licence identity is an RFC 4122 UUID")
}

fn service(state: &AppState) -> ToolkitService {
    ToolkitService::new(
        state.pool.clone(),
        SelectionResolver {
            platform_tenant_id: platform_tenant(),
        },
    )
}

/// The reserved platform tenant that owns platform toolkits.
///
/// These six operations resolve only the caller's own tools and included toolkits, so the
/// resolver never consults this owner here; the value follows the configuration default so a
/// later bindings route cannot inherit a different one.
fn platform_tenant() -> AuthorityId {
    AuthorityId::new(crate::config::default_platform_tenant_id().to_string())
        .expect("the default platform tenant is an RFC 4122 UUID")
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, ToolkitError> {
    serde_json::from_slice(body).map_err(|_| ToolkitError::Invalid)
}

/// Parse one path `version`. The route declares a bare `int`, so a negative value is not a
/// validation refusal: it simply finds no row, which is a 404. A non-integer is a 422, exactly
/// as FastAPI's path parsing refuses it.
fn version_parameter(value: &str) -> Result<PositiveVersion, ToolkitError> {
    let value: i64 = value.parse().map_err(|_| ToolkitError::Invalid)?;
    if value < 1 {
        return Err(ToolkitError::NotFound);
    }
    PositiveVersion::new(u64::try_from(value).expect("a positive integer fits u64"))
        .map_err(|_| ToolkitError::Invalid)
}
