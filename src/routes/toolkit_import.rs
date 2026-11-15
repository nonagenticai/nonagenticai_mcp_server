//! `POST /mcp/toolkits/import`: publish one toolkit bundle under the platform tenant.
//!
//! Ported from the reference `src/routers/sources.py:101-122`. Authorization is the
//! reference's two layers: the caller must be a management principal (`get_operator`) and must
//! have presented the platform operator key (`principal.platform`). The platform pool is
//! required; without it the reference answers `503 {"detail": "platform_authoring_unavailable"}`.
//!
//! The import runs the same content-addressed path as the binary's `--seed-platform` mode:
//! `201` with `{actions, versions, tools_skipped, changed}`, or the reference's
//! `HTTPException(409, {"error": "import_failed", "detail": …})`, which FastAPI renders as
//! `{"detail": {"error": "import_failed", "detail": …}}`. Every other refusal follows the repo's
//! `{"error": <code>}` rendering. A request the bundle contract refuses is a 422, exactly as the
//! reference's `json_contract` dependency renders it.
//!
//! Nothing here logs a document or a token: a storage failure is reported as an opaque 500.

use axum::Json;
use axum::body::Bytes as RawBody;
use axum::extract::State;
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::AuthorityId;
use crate::platform::seed::{SeedError, SeedSettings, ToolkitBundle, import_bundle};
use crate::routes::health::AnyJson;

/// A `/mcp/toolkits/import` refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ImportError {
    /// The caller is not a platform operator (the reference's `PermissionError`).
    Forbidden,
    /// The reference's `HTTPException(503, "platform_authoring_unavailable")`.
    Unavailable,
    /// The bundle contract refused the request (`json_contract`'s validation error).
    Invalid,
    /// The reference's `SeedError`, rendered inside the `409` detail object.
    ImportFailed(String),
    /// A storage or model failure the reference would surface as a 500.
    Internal,
}

impl IntoResponse for ImportError {
    fn into_response(self) -> Response {
        match self {
            Self::Forbidden => error(StatusCode::FORBIDDEN, "forbidden"),
            Self::Invalid => error(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => error(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
            // Both are `HTTPException`, which FastAPI renders as `{"detail": …}`.
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "detail": "platform_authoring_unavailable" })),
            )
                .into_response(),
            // The reference nests its 409 detail object one level down: FastAPI's handler
            // serializes the exception's `detail` as the response body's `detail`.
            Self::ImportFailed(detail) => (
                StatusCode::CONFLICT,
                Json(json!({
                    "detail": { "error": "import_failed", "detail": detail },
                })),
            )
                .into_response(),
        }
    }
}

impl From<SeedError> for ImportError {
    fn from(error: SeedError) -> Self {
        match error {
            SeedError::Refused(detail) => Self::ImportFailed(detail),
            // Never echo a storage message: it can quote row content.
            SeedError::Failed(_) => {
                tracing::error!("platform toolkit import failed");
                Self::Internal
            }
        }
    }
}

fn error(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// Import one toolkit bundle under the platform tenant.
#[utoipa::path(
    post,
    path = "/mcp/toolkits/import",
    tag = "sources",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn import_toolkit(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, ImportError> {
    let principal = require_management(principal)?;
    if !principal.platform {
        return Err(ImportError::Forbidden);
    }
    let Some(platform) = state.platform.clone() else {
        return Err(ImportError::Unavailable);
    };
    let payload: ToolkitBundle = parse_body(&body)?;
    payload.validate().map_err(|_| ImportError::Invalid)?;
    let settings = seed_settings(&state)?;
    let report = import_bundle(&state.pool, &settings, &payload, &platform).await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "actions": report.actions,
            "versions": report.versions,
            "tools_skipped": report.tools_skipped,
            "changed": report.changed(),
        })),
    )
        .into_response())
}

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, ImportError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(ImportError::Forbidden)
    }
}

/// The seed settings the reference reads from its single `Settings` object.
///
/// [`AppState`] carries the platform tenant and the approved image list, but not the worker's
/// `MCP_RUNNER_IMAGE_DIGEST`; the import therefore reads that one variable, the same value the
/// reference's settings parsed at startup. Unset means tools and toolkits are skipped.
fn seed_settings(state: &AppState) -> Result<SeedSettings, ImportError> {
    let platform_tenant_id = AuthorityId::new(state.platform_tenant_id.to_string())
        .map_err(|_| ImportError::Internal)?;
    Ok(SeedSettings {
        platform_tenant_id,
        runner_image_digest: std::env::var("MCP_RUNNER_IMAGE_DIGEST")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        approved_runner_images: state.approved_runner_images.clone(),
    })
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, ImportError> {
    serde_json::from_slice(body).map_err(|_| ImportError::Invalid)
}
