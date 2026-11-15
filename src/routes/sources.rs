//! The seven platform-operator tool-source operations under `/mcp/sources`.
//!
//! Ported from the reference `src/routers/sources.py`. That router reads every body through
//! `Depends(json_contract(Model))`, so FastAPI declares NO request body and NO response model:
//! the OpenAPI annotations below carry no `request_body`, every success response declares the
//! empty `{}` schema (`AnyJson`), and each operation with a path or query parameter declares
//! the reference's 422 `HTTPValidationError`. Handlers return JSON at runtime exactly as the
//! reference does.
//!
//! Authorization is the reference's two-layered `sources` dependency: the caller must be a
//! management principal (`get_operator`) and must have presented the platform operator key
//! (`principal.platform`). A missing platform pool is the reference's
//! `503 {"detail": "platform_authoring_unavailable"}`. The repository is bound per request from
//! [`AppState::platform`] and [`AppState::sources`], exactly as the reference builds it from
//! `state.platform_sources`.
//!
//! Every refusal follows the repo's rendering: `{"error": <code>}` with
//! `Cache-Control: no-store` — permission is `403 forbidden`, a missing row `404 not_found`, a
//! stale revision or a state the row is already in `409 revision_or_lifecycle_conflict` and
//! every validation refusal `422 invalid_request`. A sealing write without a configured
//! `MCP_SOURCE_SECRET_KEY` is the reference's `secret_guard`: `503 {"detail":
//! "source_secret_unavailable"}`.
//!
//! Token material is write-only. No handler reads a token out of the repository, no response
//! carries one, and nothing here logs or formats a request body.

use std::future::Future;

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
use serde_json::json;
use utoipa::IntoParams;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::AuthorityId;
use crate::catalog::models::Attribution;
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::sources::models::{RevisionOnly, SourceCreate, SourceUpdate, SourceView, TokenUpdate};
use crate::sources::repository::{SourceRepository, SourceStoreError};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A `/mcp/sources` refusal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceError {
    /// The caller is not a platform operator (the reference's `PermissionError`).
    Forbidden,
    /// The reference's `HTTPException(503, "platform_authoring_unavailable")`.
    Unavailable,
    /// The reference's `HTTPException(503, "source_secret_unavailable")` (`secret_guard`).
    SecretUnavailable,
    /// `CatalogNotFoundError`: no platform source with that key.
    NotFound,
    /// A stale expected revision, a state the row is already in, or a duplicate key.
    Conflict,
    /// A validation refusal (`ValueError`, the request model, the path/query bounds).
    Invalid,
    /// The database failed; a 422 would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for SourceError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_or_lifecycle_conflict"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            // Both are `HTTPException`, which FastAPI renders as `{"detail": …}`.
            Self::Unavailable => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "detail": "platform_authoring_unavailable" })),
                )
                    .into_response();
            }
            Self::SecretUnavailable => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    Json(json!({ "detail": "source_secret_unavailable" })),
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

impl From<SourceStoreError> for SourceError {
    fn from(error: SourceStoreError) -> Self {
        match error {
            SourceStoreError::NotFound(_) => Self::NotFound,
            SourceStoreError::Conflict(_) => Self::Conflict,
            // The reference's `ValueError`, including the destination guard's refusal: the
            // operator's request names an origin the policy does not approve.
            SourceStoreError::Invalid(_) => Self::Invalid,
            SourceStoreError::Guard(_) => Self::Invalid,
            SourceStoreError::SecretUnavailable => Self::SecretUnavailable,
            // A stored row the model can no longer parse: the reference's validation error on
            // that read.
            SourceStoreError::Corrupt(_) => Self::Invalid,
            SourceStoreError::Database(error) => {
                tracing::error!(%error, "source storage database failure");
                Self::Internal
            }
        }
    }
}

// ── request models ────────────────────────────────────────────────────────────────────────

/// The reference's query bounds for `GET /mcp/sources`
/// (`limit: Query(ge=1, le=100) = 50`, `offset: Query(ge=0) = 0`).
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct SourceListQuery {
    /// Maximum number of sources to return.
    #[param(minimum = 1, maximum = 100, default = 50)]
    pub limit: Option<u32>,
    /// Sources to skip.
    #[param(minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

// ── handlers ─────────────────────────────────────────────────────────────────────────────

/// Register one platform tool source and its stored secret.
#[utoipa::path(
    post,
    path = "/mcp/sources",
    tag = "sources",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_source(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let payload: SourceCreate = parse_body(&body)?;
    let view = guard_secret(repository.create(&payload, &actor(&principal))).await?;
    Ok((StatusCode::CREATED, Json(view)).into_response())
}

/// Every platform tool source, ordered by key.
#[utoipa::path(
    get,
    path = "/mcp/sources",
    tag = "sources",
    params(SourceListQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_sources(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    query: Result<Query<SourceListQuery>, QueryRejection>,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let Query(query) = query.map_err(|_| SourceError::Invalid)?;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) {
        return Err(SourceError::Invalid);
    }
    let items = repository.page(limit, offset).await?;
    Ok(Json(json!({ "items": items, "limit": limit, "offset": offset })).into_response())
}

/// One platform tool source by key.
#[utoipa::path(
    get,
    path = "/mcp/sources/{key}",
    tag = "sources",
    params(("key" = String, Path)),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn get_source(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(key): Path<String>,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    Ok(Json(repository.get(&key).await?).into_response())
}

/// Replace a platform tool source's contract, retaining its stored secret unless one is given.
#[utoipa::path(
    put,
    path = "/mcp/sources/{key}",
    tag = "sources",
    params(("key" = String, Path)),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_source(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(key): Path<String>,
    body: RawBody,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let payload: SourceUpdate = parse_body(&body)?;
    let view = guard_secret(repository.update(&key, &payload, &actor(&principal))).await?;
    Ok(Json(view).into_response())
}

/// Rotate a platform tool source's stored secret.
#[utoipa::path(
    put,
    path = "/mcp/sources/{key}/token",
    tag = "sources",
    params(("key" = String, Path)),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn rotate_source_token(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(key): Path<String>,
    body: RawBody,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let payload: TokenUpdate = parse_body(&body)?;
    let view = guard_secret(repository.set_token(&key, &payload, &actor(&principal))).await?;
    Ok(Json(view).into_response())
}

/// Disable a platform tool source.
#[utoipa::path(
    post,
    path = "/mcp/sources/{key}/disable",
    tag = "sources",
    params(("key" = String, Path)),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_source(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(key): Path<String>,
    body: RawBody,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let payload: RevisionOnly = parse_body(&body)?;
    let view = repository
        .set_status(
            &key,
            expected_revision(payload.expected_revision)?,
            "disabled",
            &actor(&principal),
        )
        .await?;
    Ok(Json(view).into_response())
}

/// Re-enable a platform tool source.
#[utoipa::path(
    post,
    path = "/mcp/sources/{key}/enable",
    tag = "sources",
    params(("key" = String, Path)),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn enable_source(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(key): Path<String>,
    body: RawBody,
) -> Result<Response, SourceError> {
    let principal = require_management(principal)?;
    let repository = platform(&state, &principal)?;
    let payload: RevisionOnly = parse_body(&body)?;
    let view = repository
        .set_status(
            &key,
            expected_revision(payload.expected_revision)?,
            "active",
            &actor(&principal),
        )
        .await?;
    Ok(Json(view).into_response())
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, SourceError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(SourceError::Forbidden)
    }
}

/// The reference's `sources` dependency: platform authorization first, then the pool.
///
/// The repository is bound per request, as the reference binds `state.platform_sources` to the
/// platform pool and the `MCP_SOURCE_*` settings.
fn platform(state: &AppState, principal: &Principal) -> Result<SourceRepository, SourceError> {
    if !principal.platform {
        return Err(SourceError::Forbidden);
    }
    let Some(pool) = state.platform.clone() else {
        return Err(SourceError::Unavailable);
    };
    Ok(SourceRepository::from_settings(pool, &state.sources))
}

fn actor(principal: &Principal) -> Attribution {
    Attribution {
        subject: principal.subject.clone(),
        license_id: AuthorityId::new(principal.license_id.to_string()).ok(),
    }
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, SourceError> {
    serde_json::from_slice(body).map_err(|_| SourceError::Invalid)
}

/// The reference's `secret_guard` (`sources.py:94-98`): only a missing sealing key is the 503;
/// every other storage refusal keeps its own rendering.
async fn guard_secret(
    result: impl Future<Output = Result<SourceView, SourceStoreError>>,
) -> Result<SourceView, SourceError> {
    match result.await {
        Ok(view) => Ok(view),
        Err(SourceStoreError::SecretUnavailable) => Err(SourceError::SecretUnavailable),
        Err(error) => Err(error.into()),
    }
}

/// A revision no `i64` can hold is a revision the row cannot have, which is the reference's
/// stale-revision conflict rather than a validation refusal (`expected_revision` is only
/// bounded below).
fn expected_revision(value: u64) -> Result<i64, SourceError> {
    i64::try_from(value).map_err(|_| SourceError::Conflict)
}
