//! The catalog projection operations: `GET /mcp/available-tools` and
//! `GET /mcp/bindings/{identity}/effective-tools`.
//!
//! Ported from the reference `src/routers/bindings.py` (`available_tools`, `preview_binding`).
//! Neither operation reads a body or declares a response model in the reference, so the
//! OpenAPI annotations below declare none: a success response is the empty `{}` schema
//! (`AnyJson`), and the preview operation with its path parameter declares the reference's 422
//! `HTTPValidationError`.
//!
//! A refusal is `{"error": <code>}` with `Cache-Control: no-store`: permission is
//! `403 forbidden`, a missing binding `404 not_found`, a catalog conflict
//! `409 revision_or_lifecycle_conflict` and an invalid path identity `422 invalid_request`.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde_json::json;

use crate::AppState;
use crate::auth::AuthPrincipal;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::resolver::{CatalogResolver, CatalogResolverError, ResolvedTool};
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::{ToolkitService, ToolkitServiceError};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A projection refusal, rendered as the reference's `{"error": <code>}` with `no-store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AvailableError {
    /// `PermissionError`: the caller lacks binding or management authority, or a selected
    /// tool may not be served.
    Forbidden,
    /// `CatalogNotFoundError`: no such tenant-owned binding.
    NotFound,
    /// `CatalogConflictError`: the catalog changed during resolution.
    Conflict,
    /// The path identity is not a UUIDv7.
    Invalid,
    /// A stored row or the database failed; a 4xx would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for AvailableError {
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

impl From<CatalogResolverError> for AvailableError {
    fn from(error: CatalogResolverError) -> Self {
        match error {
            CatalogResolverError::Forbidden(_) => Self::Forbidden,
            CatalogResolverError::Conflict(_) => Self::Conflict,
            CatalogResolverError::Store(error)
            | CatalogResolverError::Service(ToolkitServiceError::Store(error)) => error.into(),
            CatalogResolverError::Service(error) => error.into(),
        }
    }
}

impl From<ToolkitServiceError> for AvailableError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Forbidden,
            ToolkitServiceError::Conflict(_) | ToolkitServiceError::Invalid(_) => Self::Conflict,
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for AvailableError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            CatalogStoreError::Corrupt(message) => {
                tracing::error!(message, "catalog resolver corrupt row");
                Self::Internal
            }
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "catalog resolver database failure");
                Self::Internal
            }
        }
    }
}

// ── handlers ──────────────────────────────────────────────────────────────────────────────

/// The calling binding's live public tool projection.
#[utoipa::path(
    get,
    path = "/mcp/available-tools",
    tag = "available",
    responses((status = 200, description = "Successful Response", body = AnyJson))
)]
pub async fn available_tools(
    State(state): State<AppState>,
    principal: AuthPrincipal,
) -> Result<Response, AvailableError> {
    let tools = resolver(&state).resolve(&principal.0).await?;
    Ok(projection(&state, &tools))
}

/// Any tenant-owned binding's public tool projection, for a management principal.
#[utoipa::path(
    get,
    path = "/mcp/bindings/{identity}/effective-tools",
    tag = "available",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn effective_tools(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
) -> Result<Response, AvailableError> {
    let identity = Uuid7::new(identity).map_err(|_| AvailableError::Invalid)?;
    let tools = resolver(&state).preview(&principal.0, &identity).await?;
    Ok(projection(&state, &tools))
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────

/// The reference's response body: the public projection plus the execution flag.
fn projection(state: &AppState, tools: &[ResolvedTool]) -> Response {
    (
        StatusCode::OK,
        Json(json!({
            "tools": tools.iter().map(ResolvedTool::public).collect::<Vec<_>>(),
            "execution": if state.execution_enabled { "enabled" } else { "unavailable" },
        })),
    )
        .into_response()
}

/// The live resolver for this request. The toolkit service carries the configured gateway
/// application key because `effective` re-validates the binding's credential profile.
fn resolver(state: &AppState) -> CatalogResolver {
    CatalogResolver::new(
        state.pool.clone(),
        ToolkitService::new(
            state.pool.clone(),
            SelectionResolver {
                platform_tenant_id: platform_tenant(),
            },
            state.license_app_key.clone(),
        ),
        state.approved_runner_images.clone(),
    )
}

/// The reserved platform tenant that owns platform toolkits.
fn platform_tenant() -> AuthorityId {
    AuthorityId::new(crate::config::default_platform_tenant_id().to_string())
        .expect("the default platform tenant is an RFC 4122 UUID")
}
