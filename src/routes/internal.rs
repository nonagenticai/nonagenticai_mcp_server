//! Service-to-service routes under `/mcp/internal` (Keycloak service JWT, `azp` allow-list).
//!
//! Ported from the reference `src/routers/internal.py` and the `/mcp/internal/` branch of its
//! authentication middleware (`src/auth/protocol.py:290-319,616-655`).
//!
//! `POST /mcp/internal/tenants/{tenant_id}/bindings/ensure` provisions the one binding of a
//! product for a tenant. Product provisioning calls it on approval with the tenant's mcp licence
//! (id and token) and stores the returned binding token; the token is in the response only when
//! it was issued.
//!
//! Authentication order — the reference's — is: the service JWT first (`401` when absent or
//! invalid), then the `azp` allow-list (`403` `client may not call internal routes`), then the
//! tenant licence in the body (introspected by the service, never stored or logged). A caller
//! presenting a licence, binding or operator credential header is refused `401`: these routes
//! accept a service token only. Until the Keycloak block is configured the route answers `503
//! authority_unavailable`, never "any realm token".
//!
//! Refusals render the repo's `{"error": <code>}` with `Cache-Control: no-store`.

use std::fmt;
use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::Bytes as RawBody;
use axum::extract::rejection::BytesRejection;
use axum::extract::{DefaultBodyLimit, Extension, FromRequest, Path, Request, State};
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::{Auth, KeycloakError, KeycloakVerifier, ServicePrincipal};
use crate::catalog::ids::AuthorityId;
use crate::config::{AuthConfig, BindingEnsureSettings, ConfigError};
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::bindings_ensure::{
    BindingEnsureService, EnsureError, EnsureResult, LicenceLookup,
};
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::ToolkitServiceError;
use crate::worker::creds::Minter;

/// The one internal operation.
pub const ENSURE_PATH: &str = "/mcp/internal/tenants/{tenant_id}/bindings/ensure";

/// Everything `/mcp/internal/*` needs, resolved once at startup: the binding-provisioning
/// service, the Keycloak service-token verifier (absent = the routes answer 503) and the body
/// bound the reference reads under. Handlers share it through an `Arc`.
pub struct InternalRuntime {
    service: BindingEnsureService,
    keycloak: Option<Arc<KeycloakVerifier>>,
    max_body_bytes: usize,
}

impl fmt::Debug for InternalRuntime {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InternalRuntime")
            .field("service", &self.service)
            .field("keycloak", &self.keycloak.is_some())
            .field("max_body_bytes", &self.max_body_bytes)
            .finish()
    }
}

impl InternalRuntime {
    pub fn new(
        service: BindingEnsureService,
        keycloak: Option<Arc<KeycloakVerifier>>,
        max_body_bytes: usize,
    ) -> Self {
        Self {
            service,
            keycloak,
            max_body_bytes,
        }
    }

    /// The runtime a `/mcp`-only application carries: the verifier is off (every internal
    /// request is `503 authority_unavailable`), the minter is off and the product table is the
    /// reference's default. Used by [`crate::app_with_auth`], which has no auth config.
    pub fn unavailable(state: &AppState, auth: &Auth) -> Self {
        Self::new(
            BindingEnsureService::new(
                state.pool.clone(),
                SelectionResolver {
                    platform_tenant_id: platform_tenant(state),
                },
                state.license_app_key.clone(),
                auth.licences.clone(),
                None,
                &BindingEnsureSettings::default(),
                platform_tenant(state),
            ),
            None,
            // `MCP_MAX_MANAGEMENT_BYTES`'s default: the reference reads this route's body under
            // the management bound.
            262_144,
        )
    }

    /// The deployed runtime: the configured Keycloak verifier and — when the licence minter is
    /// enabled — the minter backend credentials are established with.
    pub fn from_config(
        state: &AppState,
        auth: &Auth,
        config: &AuthConfig,
    ) -> Result<Self, ConfigError> {
        let keycloak = match &config.keycloak {
            Some(settings) => Some(Arc::new(KeycloakVerifier::from_settings(settings)?)),
            None => None,
        };
        let minter: Option<Arc<dyn LicenceLookup>> = if config.binding_ensure.minter.enabled {
            let client =
                reqwest::Client::builder()
                    .build()
                    .map_err(|error| ConfigError::Invalid {
                        name: "MCP_LICENCE_MINTER_URL",
                        reason: format!("cannot build the minter client: {error}"),
                    })?;
            let minter = Minter::new(
                &config.binding_ensure.minter,
                state.license_app_key.clone(),
                auth.licences.clone(),
                client,
            )
            .map_err(|_| ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_SECRET_FILE",
                reason: "the minter client secret is unavailable".into(),
            })?;
            Some(Arc::new(minter) as Arc<dyn LicenceLookup>)
        } else {
            None
        };
        Ok(Self::new(
            BindingEnsureService::new(
                state.pool.clone(),
                SelectionResolver {
                    platform_tenant_id: platform_tenant(state),
                },
                state.license_app_key.clone(),
                auth.licences.clone(),
                minter,
                &config.binding_ensure,
                platform_tenant(state),
            ),
            keycloak,
            config.max_management_bytes,
        ))
    }
}

/// The internal router, mounted OUTSIDE the `/mcp` authentication middleware: these paths carry
/// a service JWT, which the `/mcp` middleware would read as a tenant licence. Its own middleware
/// authenticates before the body is read, exactly like the reference's interceptor.
pub fn router(runtime: Arc<InternalRuntime>) -> Router<AppState> {
    let body_limit = runtime.max_body_bytes;
    Router::new()
        .route(ENSURE_PATH, post(ensure_binding))
        .route_layer(middleware::from_fn_with_state(
            runtime.clone(),
            require_service,
        ))
        .layer(middleware::from_fn_with_state(runtime, provide_runtime))
        .layer(DefaultBodyLimit::max(body_limit))
}

// ── refusals ───────────────────────────────────────────────────────────────────────────────

/// An internal-route refusal, rendered as `{"error": <code>}` with `no-store` (the reference's
/// `call_internal` wrapper adds the header to every response, refusals included).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InternalError {
    /// No service token, an invalid token, or a licence/binding/operator header on the path.
    Unauthorized,
    /// A valid token whose `azp` may not call internal routes.
    Forbidden,
    /// `CatalogNotFoundError`: unknown product.
    NotFound,
    /// `CatalogConflictError`: the ensure row or profile could not be written.
    Conflict,
    /// A validation refusal (the request body, the path identity).
    Invalid,
    /// `AuthorityUnavailableError`: the licence authority cannot answer, or Keycloak is off.
    Unavailable,
    /// The body exceeded `MCP_MAX_MANAGEMENT_BYTES`.
    TooLarge,
    /// The database failed; a 4xx would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for InternalError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, "unauthorized"),
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_or_lifecycle_conflict"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Unavailable => (StatusCode::SERVICE_UNAVAILABLE, "authority_unavailable"),
            Self::TooLarge => (StatusCode::PAYLOAD_TOO_LARGE, "request_too_large"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let mut response = (status, Json(json!({ "error": code }))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self == Self::Unauthorized {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}

impl From<EnsureError> for InternalError {
    fn from(error: EnsureError) -> Self {
        match error {
            EnsureError::Forbidden(message) => {
                tracing::warn!(detail = %message, "binding ensure refused");
                Self::Forbidden
            }
            EnsureError::NotFound(message) => {
                tracing::info!(detail = %message, "binding ensure not found");
                Self::NotFound
            }
            EnsureError::Conflict(message) => {
                tracing::warn!(detail = %message, "binding ensure conflict");
                Self::Conflict
            }
            EnsureError::Invalid(message) => {
                tracing::warn!(detail = %message, "binding ensure invalid");
                Self::Invalid
            }
            EnsureError::Unavailable(message) => {
                tracing::warn!(detail = %message, "binding ensure authority unavailable");
                Self::Unavailable
            }
            EnsureError::Corrupt(message) => {
                tracing::error!(detail = message, "stored binding-ensure row is invalid");
                Self::Internal
            }
            EnsureError::Database(error) => {
                tracing::error!(%error, "binding ensure database failure");
                Self::Internal
            }
            EnsureError::Store(error) => error.into(),
            EnsureError::Toolkit(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for InternalError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            CatalogStoreError::Corrupt(message) => {
                tracing::error!(detail = message, "stored binding-ensure row is invalid");
                Self::Internal
            }
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "binding ensure database failure");
                Self::Internal
            }
        }
    }
}

impl From<ToolkitServiceError> for InternalError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Forbidden,
            ToolkitServiceError::Invalid(_) => Self::Invalid,
            ToolkitServiceError::Conflict(_) => Self::Conflict,
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

// ── request extraction ────────────────────────────────────────────────────────────────────

/// The bounded raw body: the reference's `buffer` reads at most `MCP_MAX_MANAGEMENT_BYTES` and
/// answers `413 request_too_large` beyond it. A newtype keeps utoipa from declaring a request
/// body the reference's document does not have.
struct BoundedBody(RawBody);

impl<S: Send + Sync> FromRequest<S> for BoundedBody {
    type Rejection = InternalError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        RawBody::from_request(request, state)
            .await
            .map(Self)
            .map_err(|_: BytesRejection| InternalError::TooLarge)
    }
}

/// The reference's `EnsureRequest`: the product, and the tenant's mcp licence the calling
/// product holds. The token is introspected (never stored or logged).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnsureRequest {
    product: String,
    licence_id: String,
    licence_token: String,
    #[serde(default)]
    rotate: bool,
}

/// A stray `?request` must never print the licence token.
impl fmt::Debug for EnsureRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnsureRequest")
            .field("product", &self.product)
            .field("licence_id", &self.licence_id)
            .field("licence_token", &"<redacted>")
            .field("rotate", &self.rotate)
            .finish()
    }
}

/// The reference's request contract: the product pattern, an RFC 4122 licence id and a
/// 1-to-4096-character token (its `SecretStr` bounds), strict about unknown fields.
fn parse_request(body: &[u8]) -> Result<EnsureRequest, InternalError> {
    let request: EnsureRequest =
        serde_json::from_slice(body).map_err(|_| InternalError::Invalid)?;
    if !crate::config::product_name(&request.product)
        || !(1..=4096).contains(&request.licence_token.chars().count())
    {
        return Err(InternalError::Invalid);
    }
    Ok(request)
}

// ── the handler ───────────────────────────────────────────────────────────────────────────

/// Provision the one binding of a product for a tenant.
#[utoipa::path(
    post,
    path = "/mcp/internal/tenants/{tenant_id}/bindings/ensure",
    tag = "internal",
    params(("tenant_id" = String, Path, format = "uuid")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn ensure_binding(
    Extension(runtime): Extension<Arc<InternalRuntime>>,
    Extension(principal): Extension<ServicePrincipal>,
    Path(tenant_id): Path<String>,
    body: BoundedBody,
) -> Response {
    match provision(runtime, principal, tenant_id, body).await {
        Ok(response) => response,
        Err(error) => error.into_response(),
    }
}

async fn provision(
    runtime: Arc<InternalRuntime>,
    principal: ServicePrincipal,
    tenant_id: String,
    body: BoundedBody,
) -> Result<Response, InternalError> {
    let tenant = AuthorityId::new(&tenant_id).map_err(|_| InternalError::Invalid)?;
    let request = parse_request(&body.0)?;
    let licence_id = AuthorityId::new(&request.licence_id).map_err(|_| InternalError::Invalid)?;
    let result: EnsureResult = runtime
        .service
        .ensure(
            &tenant,
            &request.product,
            &principal.azp,
            &licence_id,
            &request.licence_token,
            request.rotate,
        )
        .await?;
    // `201` only when the response carries a token (create or explicit rotate); the reference
    // computes this from the result body.
    let status = if result.token.is_some() {
        StatusCode::CREATED
    } else {
        StatusCode::OK
    };
    let value = serde_json::to_value(&result).expect("an ensure result is JSON-serializable");
    let mut response = (status, Json(value)).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    Ok(response)
}

// ── authentication ────────────────────────────────────────────────────────────────────────

/// Insert the runtime before the route's authentication middleware runs.
async fn provide_runtime(
    State(runtime): State<Arc<InternalRuntime>>,
    mut request: Request,
    next: Next,
) -> Response {
    request.extensions_mut().insert(runtime);
    next.run(request).await
}

/// The reference's `call_internal`: a service JWT (azp on the allow-list) and nothing else.
/// Runs before the body is read, so a bad caller never gets its body parsed.
async fn require_service(
    State(runtime): State<Arc<InternalRuntime>>,
    mut request: Request,
    next: Next,
) -> Response {
    let authenticated = authenticate(&runtime, request.headers()).await;
    match authenticated {
        Ok(principal) => {
            request.extensions_mut().insert(principal);
            next.run(request).await
        }
        Err(error) => error.into_response(),
    }
}

async fn authenticate(
    runtime: &InternalRuntime,
    headers: &HeaderMap,
) -> Result<ServicePrincipal, InternalError> {
    // The reference: "internal routes accept a service token only". Any licence, binding or
    // operator credential on these paths is ambiguous and refused 401.
    for name in ["x-tenant-id", "x-mcp-binding", "x-mcp-admin-key"] {
        if headers.contains_key(name) {
            return Err(InternalError::Unauthorized);
        }
    }
    // `internal_config(settings)` is None or the allow-list is empty: 503, never a bypass.
    let Some(verifier) = runtime.keycloak.as_deref() else {
        return Err(InternalError::Unavailable);
    };
    let token = bearer(headers)?;
    match verifier.validate(&token).await {
        Ok(claims) => match verifier.service_principal(&claims) {
            Ok(principal) => Ok(principal),
            Err(_) => {
                tracing::warn!("client may not call internal routes");
                Err(InternalError::Forbidden)
            }
        },
        // A valid token issued to a client outside the allow-list: the reference's 403
        // (`protocol.py:317-318`). Any other validation failure is 401.
        Err(KeycloakError::ClientNotAllowed(azp)) => {
            tracing::warn!(azp = %azp, "client may not call internal routes");
            Err(InternalError::Forbidden)
        }
        Err(error) => {
            tracing::warn!(%error, "Keycloak token rejected");
            Err(InternalError::Unauthorized)
        }
    }
}

/// The reference's `bearer`: one printable-ASCII `Authorization` value (at most 8192 bytes)
/// with an optional, case-insensitive `Bearer ` prefix.
fn bearer(headers: &HeaderMap) -> Result<String, InternalError> {
    let mut values = headers.get_all("authorization").iter();
    let Some(value) = values.next() else {
        return Err(InternalError::Unauthorized);
    };
    if values.next().is_some() {
        return Err(InternalError::Unauthorized);
    }
    let bytes = value.as_bytes();
    if !(1..=8192).contains(&bytes.len()) || !bytes.iter().all(|byte| (32..=126).contains(byte)) {
        return Err(InternalError::Unauthorized);
    }
    let text = std::str::from_utf8(bytes).map_err(|_| InternalError::Unauthorized)?;
    let text = text.trim();
    let token = if text
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
    {
        text[7..].trim()
    } else {
        text
    };
    if token.is_empty() {
        return Err(InternalError::Unauthorized);
    }
    Ok(token.to_owned())
}

fn platform_tenant(state: &AppState) -> AuthorityId {
    AuthorityId::new(state.platform_tenant_id.to_string())
        .expect("the platform tenant is an RFC 4122 UUID")
}
