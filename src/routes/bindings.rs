//! The five tenant binding operations under `/mcp/bindings` and the three credential-profile
//! operations under `/mcp/credential-profiles`.
//!
//! Ported from the reference `src/routers/bindings.py` (`create_binding`, `inspect_binding`,
//! `update_binding`, `rotate_binding`, `revoke_binding`, `create_profile`, `update_profile`,
//! `validate_profile`). The reference reads every body through
//! `Depends(json_contract(Model))`, so FastAPI declares NO request body and NO response model:
//! the OpenAPI annotations below carry no `request_body`, every success response declares the
//! empty `{}` schema (`AnyJson`), and each operation with a path parameter declares the
//! reference's 422 `HTTPValidationError`. The request models are deserialized from the raw bytes
//! exactly as in [`crate::routes::toolkits`].
//!
//! `effective-tools` stays out of this slice: it serves the catalog projection.
//!
//! A refusal is `{"error": <code>}` with `Cache-Control: no-store`: permission is
//! `403 forbidden`, a missing row `404 not_found`, a revision/lifecycle conflict
//! `409 revision_or_lifecycle_conflict` and every other refusal `422 invalid_request`.

use axum::Json;
use axum::body::Bytes as RawBody;
use axum::extract::{Path, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde::de::DeserializeOwned;
use serde_json::json;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::toolkit_models::{
    BindingDescriptor, BindingSpec, BindingUpdate, CredentialProfile, ProfileUpdate,
    RevisionRequest,
};
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::bindings as binding_store;
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::{ToolkitService, ToolkitServiceError};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A binding refusal, rendered as the reference's `{"error": <code>}` with `no-store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BindingError {
    /// `PermissionError`: the caller may not perform this operation.
    Forbidden,
    /// `CatalogNotFoundError`: no such tenant-owned binding.
    NotFound,
    /// `CatalogConflictError`: a stale revision, a revoked binding or a unique violation.
    Conflict,
    /// A validation refusal (`ValueError`, the pydantic request model, the path identity).
    Invalid,
    /// The database failed; a 422 would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for BindingError {
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

impl From<ToolkitServiceError> for BindingError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Forbidden,
            ToolkitServiceError::Invalid(_) => Self::Invalid,
            ToolkitServiceError::Conflict(_) => Self::Conflict,
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for BindingError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            // A stored row the model can no longer parse: the reference's ValidationError on
            // that read, which its exception handler maps to 422.
            CatalogStoreError::Corrupt(_) => Self::Invalid,
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "binding database failure");
                Self::Internal
            }
        }
    }
}

// ── success responses ─────────────────────────────────────────────────────────────────────

/// A successful write: the reference returns the affected `BindingDescriptor`.
fn descriptor_response(status: StatusCode, descriptor: BindingDescriptor) -> Response {
    (status, Json(descriptor)).into_response()
}

/// A create or rotation: the reference returns the descriptor and the one plaintext token.
fn token_response(status: StatusCode, descriptor: BindingDescriptor, token: String) -> Response {
    (
        status,
        Json(json!({ "binding": descriptor, "token": token })),
    )
        .into_response()
}

/// A successful profile write: the reference returns the profile, its new revision and the
/// constant (credentials are never verified by this service).
#[derive(Debug, Serialize)]
struct ProfileWriteResponse<'a> {
    profile: &'a CredentialProfile,
    revision: PositiveVersion,
    credentials_verified: bool,
}

/// The reference's `validate_profile` result: the stored revision, never a credential value.
#[derive(Debug, Serialize)]
struct ProfileValidation<'a> {
    profile_id: &'a Uuid7,
    revision: PositiveVersion,
    metadata_valid: bool,
    credentials_verified: bool,
}

// ── handlers ──────────────────────────────────────────────────────────────────────────────

/// Create a tenant binding and return its one plaintext token.
#[utoipa::path(
    post,
    path = "/mcp/bindings",
    tag = "bindings",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_binding(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let spec: BindingSpec = parse_body(&body)?;
    let (descriptor, token) = service(&state)
        .binding_write(&principal, &spec, None, None)
        .await?;
    let token = token.expect("a create mints a token");
    Ok(token_response(StatusCode::CREATED, descriptor, token))
}

/// One tenant-owned binding as stored.
#[utoipa::path(
    get,
    path = "/mcp/bindings/{identity}",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect_binding(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let descriptor = binding_store::inspect(&state.pool, &tenant_id(&principal), &identity).await?;
    Ok(Json(descriptor).into_response())
}

/// Replace a binding's spec at an expected revision. A token is never reissued here.
#[utoipa::path(
    patch,
    path = "/mcp/bindings/{identity}",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_binding(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let payload: BindingUpdate = parse_body(&body)?;
    let (descriptor, token) = service(&state)
        .binding_write(
            &principal,
            &payload.spec,
            Some(identity),
            Some(payload.expected_revision),
        )
        .await?;
    assert!(token.is_none(), "a binding update never mints a token");
    Ok(descriptor_response(StatusCode::OK, descriptor))
}

/// Issue a new token for a binding; the previous token stops authenticating.
#[utoipa::path(
    post,
    path = "/mcp/bindings/{identity}/rotate-token",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn rotate_binding(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let payload: RevisionRequest = parse_body(&body)?;
    let (descriptor, token) = service(&state)
        .binding_action(&principal, &identity, payload.expected_revision, false)
        .await?;
    let token = token.expect("a rotation mints a token");
    Ok(token_response(StatusCode::OK, descriptor, token))
}

/// Revoke a binding; revocation is terminal.
#[utoipa::path(
    post,
    path = "/mcp/bindings/{identity}/revoke",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn revoke_binding(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let payload: RevisionRequest = parse_body(&body)?;
    let (descriptor, token) = service(&state)
        .binding_action(&principal, &identity, payload.expected_revision, true)
        .await?;
    assert!(token.is_none(), "a revoke mints no token");
    Ok(descriptor_response(StatusCode::OK, descriptor))
}

/// Create a tenant credential profile at revision one.
#[utoipa::path(
    post,
    path = "/mcp/credential-profiles",
    tag = "bindings",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_profile(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let profile: CredentialProfile = parse_body(&body)?;
    let (profile, revision) = service(&state)
        .profile_write(&principal, &profile, None)
        .await?;
    Ok((
        StatusCode::CREATED,
        Json(ProfileWriteResponse {
            profile: &profile,
            revision,
            credentials_verified: false,
        }),
    )
        .into_response())
}

/// Replace a credential profile at an expected revision. A name change is refused.
#[utoipa::path(
    put,
    path = "/mcp/credential-profiles/{identity}",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_profile(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: RawBody,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let payload: ProfileUpdate = parse_body(&body)?;
    if payload.profile.profile_id != identity {
        return Err(ToolkitServiceError::Invalid("profile identity mismatch").into());
    }
    let (profile, revision) = service(&state)
        .profile_write(
            &principal,
            &payload.profile,
            Some(payload.expected_revision),
        )
        .await?;
    Ok((
        StatusCode::OK,
        Json(ProfileWriteResponse {
            profile: &profile,
            revision,
            credentials_verified: false,
        }),
    )
        .into_response())
}

/// Revalidate a stored credential profile. Credential values are never read or returned.
#[utoipa::path(
    post,
    path = "/mcp/credential-profiles/{identity}/validate",
    tag = "bindings",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn validate_profile(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
) -> Result<Response, BindingError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| BindingError::Invalid)?;
    let mut connection = state.pool.acquire().await.map_err(|error| {
        tracing::error!(%error, "credential profile database failure");
        BindingError::Internal
    })?;
    let row = binding_store::profile_row(
        &mut connection,
        &tenant_id(&principal),
        &identity,
        false,
        false,
    )
    .await?;
    if state.license_app_key.as_deref() != Some(row.profile.gateway.app_key.as_str()) {
        return Err(ToolkitServiceError::Invalid("gateway application mismatch").into());
    }
    Ok(Json(ProfileValidation {
        profile_id: &identity,
        revision: stored_revision(row.revision)?,
        metadata_valid: true,
        credentials_verified: false,
    })
    .into_response())
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, BindingError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(BindingError::Forbidden)
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
        // The binding routes validate the credential profile: its gateway application
        // reference must name the configured `MCP_LICENSE_APP_KEY`.
        state.license_app_key.clone(),
    )
}

/// The reserved platform tenant that owns platform toolkits.
fn platform_tenant() -> AuthorityId {
    AuthorityId::new(crate::config::default_platform_tenant_id().to_string())
        .expect("the default platform tenant is an RFC 4122 UUID")
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, BindingError> {
    serde_json::from_slice(body).map_err(|_| BindingError::Invalid)
}

/// A stored revision as the model type. The column is `bigint`; a value outside the positive
/// range is a corrupt row, never the caller's mistake.
fn stored_revision(value: i64) -> Result<PositiveVersion, BindingError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(BindingError::Internal)
}
