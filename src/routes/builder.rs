//! The 26 tenant tool-builder operations under `/mcp/builder`, and their tenant-scoped mirror
//! under `/mcp/internal/tenants/{tenant_id}/builder`.
//!
//! Ported from the reference `src/routers/builder.py`, whose `build_router(prefix)` is mounted
//! twice (`src/asgi.py:157-173`). One route set is built here and mounted at both prefixes, so
//! every handler describes the same operation — path suffix, method, status codes and body
//! shape — for both callers; only the authority differs:
//!
//! - `/mcp/builder/*` authenticates the tenant's own tenant-level mcp licence presented as
//!   `X-Tenant-Id: Bearer <licence>` and nothing else. An operator key, a platform operator key
//!   or a binding token makes the request ambiguous and is refused `401`.
//! - `/mcp/internal/tenants/{tenant_id}/builder/*` authenticates a Keycloak service JWT whose
//!   `azp` is on the internal allow-list first, and then — after the bounded body has been
//!   read — the *path tenant's* tenant-level mcp licence: `X-Tenant-Id: Bearer <licence>` with
//!   `X-MCP-Licence-Id: <uuid>`, or the same pair as `licence_id` / `licence_token` inside the
//!   JSON body (which is stripped before the handler sees it). The resulting author's
//!   [`AuthorPrincipal::via`] is the service JWT's `azp`. A path tenant never chooses the acting
//!   tenant: a licence for any other tenant, a member (per-login) licence, a licence id that
//!   differs from the licence's, or the reserved platform tenant is refused `403`.
//!
//! Both mounts reproduce the reference's ordering and bodies: while the builder is disabled the
//! middleware answers `404 {"error": "not_found"}` *before any credential is read*; an
//! authentication failure is `401 {"error": "unauthorized"}` (plus `WWW-Authenticate: Bearer`),
//! a forbidden caller `403 {"error": "forbidden"}`, and a licence authority that cannot answer
//! `503 {"error": "authority_unavailable"}`. A body larger than `MCP_MAX_MANAGEMENT_BYTES` is
//! `413 {"error": "request_too_large"}`. Every response after authentication carries
//! `Cache-Control: no-store`, exactly the reference's `no_store_send`.
//!
//! The reference reads every body through `Depends(body_of(Model))`, so FastAPI declares NO
//! request body and NO response model: the OpenAPI annotations below carry no `request_body`,
//! every success response declares the empty `{}` schema ([`AnyJson`]), and each operation with
//! a path or query parameter declares the reference's 422 `HTTPValidationError`. Handlers parse
//! the raw bytes strictly. A domain refusal renders the reference's `builder_failure` /
//! `invalid_request` shapes: `{"error": code}` plus `detail` (the message) or `resource` (the
//! quota's), with `Cache-Control: no-store`.
//!
//! # Where the port cannot be literal
//!
//! - **The OpenAPI mirror is generated.** `utoipa` binds one path to one handler, so the
//!   handlers describe the `/mcp/builder/*` mount and [`mirror_product_paths`] derives the
//!   product paths from them at document time — same operations, parameters and responses,
//!   with the reference's generated operation ids for the second mount. The reference's
//!   FastAPI app gets both sets from one router mounted twice.
//! - **Body-validation messages.** A body that is not the model is `422
//!   {"error": "invalid_request", "detail": "invalid request body"}`; the reference shows
//!   Pydantic's `field: message` list instead. The fixed text never echoes a value.
//! - **Path patterns.** The reference's `Key` (`^[a-z][a-z0-9_]{0,63}$`) and the spec digest
//!   (`^[a-f0-9]{64}$`) are enforced in the handler; `utoipa` parameters have no `pattern`
//!   attribute, so the document's path-parameter schemas omit it.
//! - **Installation.** The reference installs one service per process from `app.state`. The
//!   runtime is injected through [`BuilderRuntime`] instead — the composition root owns it.
//!   [`BuilderRuntime::disabled`] is the reference's `install` returning `None`.

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::body::{Body, Bytes as RawBody};
use axum::extract::rejection::QueryRejection;
use axum::extract::{Extension, OriginalUri, Path, Query, Request, State};
use axum::http::header::CACHE_CONTROL;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, patch, post, put};
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use utoipa::IntoParams;
use utoipa::openapi::path::{Operation, PathItem, Paths};

use crate::AppState;
use crate::auth::keycloak::{
    AuthorPrincipal, KeycloakError, KeycloakVerifier, ServicePrincipal, author_principal,
};
use crate::auth::{Auth, AuthError, LicenceAuthority, Rfc4122Uuid};
use crate::builder::models::{
    BindRequest, ImportRequest, OperationPatch, SpecFetchRequest, ToolCreate, ToolPublishRequest,
    ToolTestRequest, ToolUpdate, ToolkitPublishRequest, ToolkitRequest,
};
use crate::builder::service::{BuilderError, BuilderService};
use crate::catalog::ids::{Digest, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::sources::models::{
    RevisionOnly, SourceStatus, TenantSourceCreate, TenantSourceUpdate, TokenUpdate,
};

/// The tenant's own mount: a tenant-level mcp licence is the only credential.
pub const AUTHOR_MOUNT: &str = "/mcp/builder";
/// The product platform's mount: a service JWT plus the path tenant's licence.
pub const PRODUCT_MOUNT: &str = "/mcp/internal/tenants/{tenant_id}/builder";

/// The upper bound the reference applies to a builder request header (`x-tenant-id`).
const TENANT_HEADER_BYTES: usize = 4_103;
/// The bound on `X-MCP-Licence-Id` (`header(scope, b"x-mcp-licence-id", 64)`).
const LICENCE_ID_HEADER_BYTES: usize = 64;
/// The bound on the `Authorization` header the service JWT arrives in.
const AUTHORIZATION_BYTES: usize = 8_192;
/// The reference bounds a principal subject to 256 characters.
const MAX_SUBJECT: usize = 256;

// ── runtime ────────────────────────────────────────────────────────────────────────────────

/// Everything the two builder mounts need, resolved once by the composition root.
///
/// `service` is the reference's `app.state.builder`: `None` means the builder is disabled and
/// every builder path answers `404 not_found` before any credential is read. `keycloak` is the
/// `/mcp/internal/*` service-token verifier (`None` makes the product mount answer
/// `503 authority_unavailable`, exactly the reference's unconfigured internal auth).
pub struct BuilderRuntime {
    service: Option<Arc<BuilderService>>,
    keycloak: Option<Arc<KeycloakVerifier>>,
    licences: Arc<dyn LicenceAuthority>,
    platform_tenant_id: Rfc4122Uuid,
    license_app_key: Option<String>,
    max_body_bytes: usize,
}

impl BuilderRuntime {
    /// The enabled runtime. The `licences` authority is the same one `/mcp` uses.
    pub fn new(
        service: Arc<BuilderService>,
        keycloak: Option<Arc<KeycloakVerifier>>,
        licences: Arc<dyn LicenceAuthority>,
        platform_tenant_id: Rfc4122Uuid,
        license_app_key: Option<String>,
        max_body_bytes: usize,
    ) -> Self {
        Self {
            service: Some(service),
            keycloak,
            licences,
            platform_tenant_id,
            license_app_key,
            max_body_bytes,
        }
    }

    /// The disabled runtime: the reference's `install` when `MCP_BUILDER_ENABLED` is off —
    /// nothing installed, and every builder path is the same `404 not_found`.
    pub fn disabled(state: &AppState, auth: &Auth) -> Self {
        Self {
            service: None,
            keycloak: None,
            licences: auth.licences.clone(),
            platform_tenant_id: state.platform_tenant_id,
            license_app_key: state.license_app_key.clone(),
            max_body_bytes: auth.max_management_bytes,
        }
    }

    /// The service, when the builder is installed. The middleware has already answered the
    /// disabled case, so this refusal is only a wiring-fault fallback.
    fn service(&self) -> Result<&BuilderService, BuilderError> {
        self.service
            .as_deref()
            .ok_or_else(|| BuilderError::NotFound("not_found".to_owned()))
    }
}

// ── router ─────────────────────────────────────────────────────────────────────────────────

/// Mount the one route set at both prefixes.
///
/// The mounts are nested OUTSIDE the `/mcp` authentication middleware (which authenticates
/// management and binding callers), because these paths carry their own credentials: each
/// mount installs [`authenticate`] over its whole subtree — matched routes and the fallback
/// alike — so an unknown builder path is authenticated before it is refused, exactly like the
/// reference's middleware branch.
pub fn router(runtime: BuilderRuntime) -> Router<AppState> {
    let runtime = Arc::new(runtime);
    Router::new()
        .nest(AUTHOR_MOUNT, mount(runtime.clone(), Mount::Author))
        .nest(PRODUCT_MOUNT, mount(runtime, Mount::Product))
}

/// One mount: the reference's `build_router(prefix)` body. Its handlers are the same functions
/// for both prefixes; the prefix only changes the authority.
fn mount(runtime: Arc<BuilderRuntime>, authority: Mount) -> Router<AppState> {
    Router::new()
        .route("/usage", get(usage))
        // sources
        .route("/sources", get(list_sources).post(create_source))
        .route("/sources/{key}", get(get_source).put(update_source))
        .route("/sources/{key}/secret", put(set_secret))
        .route("/sources/{key}/disable", post(disable_source))
        .route("/sources/{key}/enable", post(enable_source))
        // spec and operations
        .route("/sources/{key}/spec/fetch", post(fetch_spec))
        .route("/sources/{key}/spec/{sha}/operations", get(spec_operations))
        .route("/sources/{key}/operations/import", post(import_operations))
        .route("/sources/{key}/operations", get(list_operations))
        .route(
            "/sources/{key}/operations/{op_key}",
            patch(update_operation),
        )
        // tools
        .route("/tools", get(list_tools).post(create_tool))
        .route("/tools/{identity}", get(get_tool))
        .route("/tools/{identity}/versions", post(update_tool))
        .route("/tools/{identity}/versions/{version}/test", post(test_tool))
        .route(
            "/tools/{identity}/versions/{version}/publish",
            post(publish_tool),
        )
        .route(
            "/tools/{identity}/versions/{version}/disable",
            post(disable_tool),
        )
        .route(
            "/tools/{identity}/versions/{version}/retire",
            post(retire_tool),
        )
        // runs
        .route("/runs/{run_id}", get(get_run))
        // toolkits
        .route("/toolkits", post(create_toolkit))
        .route("/toolkits/bind", post(bind_toolkits))
        .route("/toolkits/{identity}/versions", post(append_toolkit))
        .route(
            "/toolkits/{identity}/versions/{version}/publish",
            post(publish_toolkit),
        )
        .method_not_allowed_fallback(method_not_allowed)
        .fallback(unknown_path)
        .layer(middleware::from_fn_with_state(
            (runtime, authority),
            authenticate,
        ))
}

// ── authentication ─────────────────────────────────────────────────────────────────────────

/// Which credential surface a mount accepts.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mount {
    /// `/mcp/builder/*`: the tenant's own licence.
    Author,
    /// `/mcp/internal/tenants/{tenant_id}/builder/*`: a service JWT plus that tenant's licence.
    Product,
}

/// The builder mounts' authentication middleware: the reference's `call_author` branch of the
/// ASGI middleware, run before any handler or body parse.
async fn authenticate(
    State((runtime, authority)): State<(Arc<BuilderRuntime>, Mount)>,
    mut request: Request,
    next: Next,
) -> Response {
    // Disabled builder: one consistent answer, before any credential is read. Both shapes of
    // "not installed" — no service, or a service whose settings disable it — are the reference's
    // 404, exactly its `install` returning `None`.
    let disabled = match runtime.service.as_ref() {
        Some(service) => service.ensure_enabled().is_err(),
        None => true,
    };
    if disabled {
        return error_response(StatusCode::NOT_FOUND, "not_found");
    }
    let headers = request.headers().clone();
    let author = match authority {
        Mount::Author => {
            let author = match authorize_author(&runtime, &headers).await {
                Ok(author) => author,
                Err(error) => return error.into_response(),
            };
            // The reference's `buffer`: the body is bounded after the licence is proven and
            // before the handler runs.
            let (parts, body) = request.into_parts();
            let bounded = match axum::body::to_bytes(body, runtime.max_body_bytes).await {
                Ok(bytes) => bytes,
                Err(_) => return AuthError::TooLarge.into_response(),
            };
            request = Request::from_parts(parts, Body::from(bounded));
            author
        }
        Mount::Product => {
            // The path tenant is parsed first: an unparseable one is the reference's
            // `invalid tenant` 403, before the service token is even looked at.
            let Some(tenant) = tenant_in_path(original_path(&request)) else {
                return AuthError::Forbidden.into_response();
            };
            // Step 1: the service JWT, before the body is read.
            let service = match authorize_service(&runtime, &headers).await {
                Ok(service) => service,
                Err(error) => return error.into_response(),
            };
            // The bounded body, exactly the reference's `read_body`.
            let (parts, body) = request.into_parts();
            let bounded = match axum::body::to_bytes(body, runtime.max_body_bytes).await {
                Ok(bytes) => bytes,
                Err(_) => return AuthError::TooLarge.into_response(),
            };
            // Step 2: the path tenant's licence, from the headers or (stripped) from the body.
            let (author, body) =
                match authorize_product(&runtime, &headers, bounded, tenant, &service).await {
                    Ok(pair) => pair,
                    Err(error) => return error.into_response(),
                };
            request = Request::from_parts(parts, Body::from(body));
            author
        }
    };
    request.extensions_mut().insert(runtime.clone());
    request.extensions_mut().insert(author);
    no_store(next.run(request).await)
}

/// The reference's `authenticate_author`: `X-Tenant-Id: Bearer <tenant-level mcp licence>` and
/// nothing else. An operator, platform or binding header is ambiguous and refused `401`.
async fn authorize_author(
    runtime: &BuilderRuntime,
    headers: &HeaderMap,
) -> Result<AuthorPrincipal, AuthError> {
    refuse_author_headers(headers)?;
    let gateway = header(headers, "x-tenant-id", TENANT_HEADER_BYTES)?;
    let token = gateway
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or(AuthError::Unauthorized)?;
    let identity = runtime.licences.authenticate(token).await?;
    author_principal(&identity, runtime.platform_tenant_id)
}

/// The reference's `authenticate_product_service`: a service token only, and the verifier must
/// be configured (`503 authority_unavailable` otherwise — never "any realm token").
async fn authorize_service(
    runtime: &BuilderRuntime,
    headers: &HeaderMap,
) -> Result<ServicePrincipal, AuthError> {
    refuse_author_headers(headers)?;
    let Some(verifier) = runtime.keycloak.as_deref() else {
        return Err(AuthError::Unavailable);
    };
    let token =
        bearer(headers, "authorization", AUTHORIZATION_BYTES)?.ok_or(AuthError::Unauthorized)?;
    match verifier.validate(&token).await {
        Ok(claims) => verifier.service_principal(&claims),
        // A valid token issued to a client outside the allow-list is the reference's 403
        // (`protocol.py:317-318`); any other validation failure is 401.
        Err(KeycloakError::ClientNotAllowed(_)) => Err(AuthError::Forbidden),
        Err(_) => Err(AuthError::Unauthorized),
    }
}

/// The reference's `authenticate_product_author`: THAT tenant's tenant-level mcp licence, with
/// exactly the licence id it asserts. The body is returned with `licence_id` / `licence_token`
/// removed when the licence came from it.
async fn authorize_product(
    runtime: &BuilderRuntime,
    headers: &HeaderMap,
    body: RawBody,
    tenant: Rfc4122Uuid,
    service: &ServicePrincipal,
) -> Result<(AuthorPrincipal, RawBody), AuthError> {
    let gateway = header(headers, "x-tenant-id", TENANT_HEADER_BYTES)?;
    let mut licence_id = header(headers, "x-mcp-licence-id", LICENCE_ID_HEADER_BYTES)?;
    let mut token = match gateway.as_deref() {
        Some(value) => Some(
            value
                .strip_prefix("Bearer ")
                .ok_or(AuthError::Unauthorized)?
                .to_owned(),
        ),
        None => None,
    };
    let mut body = body;
    if token.is_none() {
        // No licence header pair: the reference takes both from the body, replacing whatever
        // `X-MCP-Licence-Id` carried.
        let (stripped, body_id, body_token) = licence_from_body(&body);
        body = stripped;
        licence_id = body_id;
        token = body_token;
    }
    let token = token.filter(|token| !token.is_empty());
    let licence_id = licence_id.filter(|value| !value.is_empty());
    let (Some(token), Some(licence_id)) = (token, licence_id) else {
        return Err(AuthError::Unauthorized);
    };
    let Some(app) = runtime.license_app_key.as_deref() else {
        return Err(AuthError::Unavailable);
    };
    let identity = runtime.licences.authenticate_for_app(&token, app).await?;
    let matches = Rfc4122Uuid::parse(&licence_id) == Some(identity.license_id);
    if identity.tenant_id != tenant || !identity.tenant_level() || !matches {
        return Err(AuthError::Forbidden);
    }
    if tenant == runtime.platform_tenant_id {
        return Err(AuthError::Forbidden);
    }
    let azp: String = service.azp.chars().take(MAX_SUBJECT).collect();
    let subject: String = format!("service:{azp}").chars().take(MAX_SUBJECT).collect();
    let author = AuthorPrincipal {
        tenant_id: tenant,
        license_id: identity.license_id,
        subject,
        via: Some(azp),
    };
    Ok((author, body))
}

/// The reference's `AUTHOR_FORBIDDEN_HEADERS`: an operator key, a platform operator key or a
/// binding token on a builder path is ambiguous and refused `401`.
fn refuse_author_headers(headers: &HeaderMap) -> Result<(), AuthError> {
    for name in [
        "x-mcp-admin-key",
        "x-mcp-platform-admin-key",
        "x-mcp-binding",
    ] {
        if headers.contains_key(name) {
            return Err(AuthError::Unauthorized);
        }
    }
    Ok(())
}

/// The reference's `licence_from_body`: split `licence_id` / `licence_token` out of a JSON
/// object body. A body that is blank, not JSON, not an object, or names neither field is
/// returned unchanged with no licence (`None`); otherwise the remaining object is re-serialized
/// and each field is `Some` (a non-string value is the empty string, the reference's `""`).
fn licence_from_body(body: &RawBody) -> (RawBody, Option<String>, Option<String>) {
    let unchanged = |body: &RawBody| (body.clone(), None, None);
    if body.iter().all(u8::is_ascii_whitespace) {
        return unchanged(body);
    }
    let Ok(Value::Object(mut document)) = serde_json::from_slice::<Value>(body) else {
        return unchanged(body);
    };
    let licence_id = document.remove("licence_id");
    let licence_token = document.remove("licence_token");
    if licence_id.is_none() && licence_token.is_none() {
        return unchanged(body);
    }
    let string = |value: Option<Value>| match value {
        Some(Value::String(text)) => text,
        _ => String::new(),
    };
    let stripped = serde_json::to_vec(&Value::Object(document)).unwrap_or_default();
    (
        RawBody::from(stripped),
        Some(string(licence_id)),
        Some(string(licence_token)),
    )
}

/// The full request path (nesting strips the prefix the handler and this middleware see).
fn original_path(request: &Request) -> &str {
    request
        .extensions()
        .get::<OriginalUri>()
        .map(|original| original.0.path())
        .unwrap_or_else(|| request.uri().path())
}

/// The `tenant_id` of `/mcp/internal/tenants/{tenant_id}/builder/...`; `None` when the path is
/// not that shape or the segment is not an RFC 4122 UUID (the reference's `uuid.UUID`).
fn tenant_in_path(path: &str) -> Option<Rfc4122Uuid> {
    let rest = path.strip_prefix("/mcp/internal/tenants/")?;
    let (tenant, tail) = rest.split_once('/')?;
    if tail != "builder" && !tail.starts_with("builder/") {
        return None;
    }
    Rfc4122Uuid::parse(tenant)
}

/// The reference's `header()`: at most one printable-ASCII value in `1..=maximum`, with the
/// single `Bearer ` space allowed for the licence-bearing headers.
fn header(
    headers: &HeaderMap,
    name: &'static str,
    maximum: usize,
) -> Result<Option<String>, AuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let bytes = value.as_bytes();
    let printable = |byte: &u8| (33..=126).contains(byte);
    let valid = (1..=maximum).contains(&bytes.len()) && bytes.iter().all(printable);
    if !valid {
        let bearer_value = matches!(name, "x-tenant-id" | "authorization")
            && bytes.starts_with(b"Bearer ")
            && bytes.len() <= maximum
            && bytes[7..].iter().all(printable);
        if !bearer_value {
            return Err(AuthError::Unauthorized);
        }
    }
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|_| AuthError::Unauthorized)
}

/// The reference's `bearer()`: one printable value, an optional case-insensitive `Bearer `
/// prefix removed, trimmed; empty is `None`.
fn bearer(
    headers: &HeaderMap,
    name: &'static str,
    maximum: usize,
) -> Result<Option<String>, AuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let bytes = value.as_bytes();
    if !(1..=maximum).contains(&bytes.len()) || bytes.iter().any(|byte| !(32..=126).contains(byte))
    {
        return Err(AuthError::Unauthorized);
    }
    let text = std::str::from_utf8(bytes)
        .map_err(|_| AuthError::Unauthorized)?
        .trim();
    let token = if text
        .get(..7)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("bearer "))
    {
        text[7..].trim()
    } else {
        text
    };
    Ok((!token.is_empty()).then(|| token.to_owned()))
}

// ── refusals and response helpers ──────────────────────────────────────────────────────────

/// Render the builder's own error family exactly as the reference's exception handlers do:
/// `{"error": code}` plus `detail` (the safe message) or `resource` (a quota's), never cached.
impl IntoResponse for BuilderError {
    fn into_response(self) -> Response {
        let status =
            StatusCode::from_u16(self.status()).expect("every builder status is a valid status");
        let mut body = Map::new();
        body.insert("error".to_owned(), Value::String(self.code().to_owned()));
        if let Some(resource) = self.resource() {
            body.insert("resource".to_owned(), Value::String(resource.to_owned()));
        }
        if let Some(detail) = self.detail() {
            body.insert("detail".to_owned(), Value::String(detail.to_owned()));
        }
        let mut response = (status, Json(Value::Object(body))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

/// An authenticated request for a builder path no route knows is FastAPI's own 404.
async fn unknown_path() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "detail": "Not Found" })),
    )
        .into_response()
}

/// A method a builder path does not serve is FastAPI's own 405.
async fn method_not_allowed() -> Response {
    (
        StatusCode::METHOD_NOT_ALLOWED,
        Json(json!({ "detail": "Method Not Allowed" })),
    )
        .into_response()
}

/// The reference's `{"error": <code>}` body, never cached.
fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The reference's `no_store_send`: every response of an authenticated builder request.
fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

fn ok(value: Value) -> Response {
    Json(value).into_response()
}

fn created(value: Value) -> Response {
    (StatusCode::CREATED, Json(value)).into_response()
}

// ── request parsing ────────────────────────────────────────────────────────────────────────

/// The stricter of the two: a body that is not the model is `422 invalid_request`. The message
/// is fixed — never a serde message, which can echo the offending value.
fn parse_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, BuilderError> {
    serde_json::from_slice(body).map_err(|_| invalid_body())
}

/// The reference's `body_of(..., optional=True)`: a blank body is `{}`.
fn parse_optional_body<T: DeserializeOwned>(body: &[u8]) -> Result<T, BuilderError> {
    if body.iter().all(u8::is_ascii_whitespace) {
        serde_json::from_str("{}").map_err(|_| invalid_body())
    } else {
        parse_body(body)
    }
}

fn invalid_body() -> BuilderError {
    BuilderError::Input("invalid request body".to_owned())
}

/// The reference's `Key`: `NAME_PATTERN`.
fn name_parameter(value: &str) -> Result<Name, BuilderError> {
    Name::new(value).map_err(|_| BuilderError::Invalid("invalid source key".to_owned()))
}

/// The reference's spec path parameter: `^[a-f0-9]{64}$`.
fn digest_parameter(value: &str) -> Result<Digest, BuilderError> {
    Digest::new(value).map_err(|_| BuilderError::Invalid("invalid spec digest".to_owned()))
}

/// The reference's `UUID7` path parameter.
fn identity_parameter(value: &str) -> Result<Uuid7, BuilderError> {
    Uuid7::new(value).map_err(|_| BuilderError::Invalid("invalid identity".to_owned()))
}

/// The reference's `Path(ge=1)` version parameter.
fn version_parameter(value: &str) -> Result<PositiveVersion, BuilderError> {
    let parsed: u32 = value
        .parse()
        .map_err(|_| BuilderError::Invalid("invalid version".to_owned()))?;
    PositiveVersion::new(u64::from(parsed))
        .map_err(|_| BuilderError::Invalid("invalid version".to_owned()))
}

/// The reference's `RevisionRequest` (`src/toolkits/models.py`): `expected_revision` alone.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RevisionRequest {
    expected_revision: PositiveVersion,
}

/// `GET /sources` and `GET /tools`: `limit: Query(ge=1, le=100) = 50`, `offset: Query(ge=0) = 0`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PageQuery {
    /// Maximum number of rows to return.
    #[param(minimum = 1, maximum = 100, default = 50)]
    pub limit: Option<u32>,
    /// Rows to skip.
    #[param(minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

impl PageQuery {
    /// The reference's handler bounds; a value outside them is the 422 validation refusal.
    fn bounds(&self) -> Result<(u32, u32), BuilderError> {
        let limit = self.limit.unwrap_or(50);
        let offset = self.offset.unwrap_or(0);
        if !(1..=100).contains(&limit) {
            return Err(BuilderError::Invalid("invalid pagination".to_owned()));
        }
        Ok((limit, offset))
    }
}

/// `GET /tools/{identity}`: `version: Query(ge=1) = None`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ToolQuery {
    /// A published or draft version; omitted means the newest one.
    #[param(minimum = 1)]
    pub version: Option<u32>,
}

// ── path parameter shapes ─────────────────────────────────────────────────────────────────
//
// Each mount's route has the same trailing segments; the product mount adds `{tenant_id}`.
// A struct ignores the keys it does not name, so the one handler serves both mounts.

/// `/sources/{key}` and every `/sources/{key}/…` path.
#[derive(Debug, Deserialize)]
pub struct KeyPath {
    /// The source key (`NAME_PATTERN`).
    pub key: String,
}

/// `/sources/{key}/spec/{sha}/operations`.
#[derive(Debug, Deserialize)]
pub struct KeyShaPath {
    /// The source key.
    pub key: String,
    /// The cached document's SHA-256.
    pub sha: String,
}

/// `/sources/{key}/operations/{op_key}`.
#[derive(Debug, Deserialize)]
pub struct OperationPath {
    /// The source key.
    pub key: String,
    /// The imported operation's key.
    pub op_key: String,
}

/// `/toolkits/{identity}/…` and `/tools/{identity}/…`.
#[derive(Debug, Deserialize)]
pub struct IdentityPath {
    /// The UUID7 identity.
    pub identity: String,
}

/// `…/{identity}/versions/{version}/…`.
#[derive(Debug, Deserialize)]
pub struct IdentityVersionPath {
    /// The UUID7 identity.
    pub identity: String,
    /// The positive version.
    pub version: String,
}

/// `/runs/{run_id}`.
#[derive(Debug, Deserialize)]
pub struct RunPath {
    /// The UUID7 run identity.
    pub run_id: String,
}

// ── handlers ─────────────────────────────────────────────────────────────────────────────

/// The tenant's builder quotas and what it has used.
#[utoipa::path(
    get,
    path = "/mcp/builder/usage",
    operation_id = "usage_mcp_builder_usage_get",
    tag = "builder",
    responses((status = 200, description = "Successful Response", body = AnyJson))
)]
pub async fn usage(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
) -> Result<Response, BuilderError> {
    Ok(ok(runtime.service()?.usage(&author).await?))
}

/// Register a tenant source and its stored secret.
#[utoipa::path(
    post,
    path = "/mcp/builder/sources",
    operation_id = "create_source_mcp_builder_sources_post",
    tag = "builder",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_source(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let payload: TenantSourceCreate = parse_body(&body)?;
    Ok(created(
        runtime.service()?.source_create(&author, &payload).await?,
    ))
}

/// Every source the tenant owns, ordered by key.
#[utoipa::path(
    get,
    path = "/mcp/builder/sources",
    operation_id = "list_sources_mcp_builder_sources_get",
    tag = "builder",
    params(PageQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_sources(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Response, BuilderError> {
    let Query(query) = query.map_err(|_| BuilderError::Invalid("invalid pagination".to_owned()))?;
    let (limit, offset) = query.bounds()?;
    Ok(ok(runtime
        .service()?
        .source_list(&author, limit, offset)
        .await?))
}

/// One source the tenant owns.
#[utoipa::path(
    get,
    path = "/mcp/builder/sources/{key}",
    operation_id = "get_source_mcp_builder_sources__key__get",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn get_source(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    Ok(ok(runtime
        .service()?
        .source_get(&author, key.as_str())
        .await?))
}

/// Replace a source's contract, retaining its stored secret unless one is given.
#[utoipa::path(
    put,
    path = "/mcp/builder/sources/{key}",
    operation_id = "update_source_mcp_builder_sources__key__put",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_source(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: TenantSourceUpdate = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .source_update(&author, key.as_str(), &payload)
        .await?))
}

/// Rotate a source's stored secret; the response never carries it.
#[utoipa::path(
    put,
    path = "/mcp/builder/sources/{key}/secret",
    operation_id = "set_secret_mcp_builder_sources__key__secret_put",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn set_secret(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: TokenUpdate = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .source_set_secret(&author, key.as_str(), &payload)
        .await?))
}

/// Disable a source.
#[utoipa::path(
    post,
    path = "/mcp/builder/sources/{key}/disable",
    operation_id = "disable_source_mcp_builder_sources__key__disable_post",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_source(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: RevisionOnly = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .source_set_status(&author, key.as_str(), &payload, SourceStatus::Disabled)
        .await?))
}

/// Re-enable a source.
#[utoipa::path(
    post,
    path = "/mcp/builder/sources/{key}/enable",
    operation_id = "enable_source_mcp_builder_sources__key__enable_post",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn enable_source(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: RevisionOnly = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .source_set_status(&author, key.as_str(), &payload, SourceStatus::Active)
        .await?))
}

/// Fetch the source's OpenAPI document and list what can be imported.
#[utoipa::path(
    post,
    path = "/mcp/builder/sources/{key}/spec/fetch",
    operation_id = "fetch_spec_mcp_builder_sources__key__spec_fetch_post",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn fetch_spec(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: SpecFetchRequest = parse_optional_body(&body)?;
    Ok(ok(runtime
        .service()?
        .spec_fetch(&author, key.as_str(), &payload)
        .await?))
}

/// The cached document's operations.
#[utoipa::path(
    get,
    path = "/mcp/builder/sources/{key}/spec/{sha}/operations",
    operation_id = "spec_operations_mcp_builder_sources__key__spec__sha__operations_get",
    tag = "builder",
    params(
        ("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$"),
        ("sha" = String, Path, pattern = "^[a-f0-9]{64}$")
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn spec_operations(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyShaPath>,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let sha = digest_parameter(&path.sha)?;
    Ok(ok(runtime
        .service()?
        .spec_operations(&author, key.as_str(), sha.as_str())
        .await?))
}

/// Create draft operations from a cached spec.
#[utoipa::path(
    post,
    path = "/mcp/builder/sources/{key}/operations/import",
    operation_id = "import_operations_mcp_builder_sources__key__operations_import_post",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn import_operations(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let payload: ImportRequest = parse_body(&body)?;
    Ok(created(
        runtime
            .service()?
            .operations_import(&author, key.as_str(), &payload)
            .await?,
    ))
}

/// Every keyed operation of the source's service.
#[utoipa::path(
    get,
    path = "/mcp/builder/sources/{key}/operations",
    operation_id = "list_operations_mcp_builder_sources__key__operations_get",
    tag = "builder",
    params(("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_operations(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<KeyPath>,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    Ok(ok(runtime
        .service()?
        .operation_list(&author, key.as_str())
        .await?))
}

/// A new draft version of an imported operation.
#[utoipa::path(
    patch,
    path = "/mcp/builder/sources/{key}/operations/{op_key}",
    operation_id = "update_operation_mcp_builder_sources__key__operations__op_key__patch",
    tag = "builder",
    params(
        ("key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$"),
        ("op_key" = String, Path, pattern = "^[a-z][a-z0-9_]{0,63}$")
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_operation(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<OperationPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let key = name_parameter(&path.key)?;
    let op_key = name_parameter(&path.op_key)?;
    let payload: OperationPatch = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .operation_update(&author, key.as_str(), op_key.as_str(), &payload)
        .await?))
}

/// Create a draft tool.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools",
    operation_id = "create_tool_mcp_builder_tools_post",
    tag = "builder",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let payload: ToolCreate = parse_body(&body)?;
    Ok(created(
        runtime.service()?.tool_create(&author, &payload).await?,
    ))
}

/// The tenant's tool versions.
#[utoipa::path(
    get,
    path = "/mcp/builder/tools",
    operation_id = "list_tools_mcp_builder_tools_get",
    tag = "builder",
    params(PageQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn list_tools(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    query: Result<Query<PageQuery>, QueryRejection>,
) -> Result<Response, BuilderError> {
    let Query(query) = query.map_err(|_| BuilderError::Invalid("invalid pagination".to_owned()))?;
    let (limit, offset) = query.bounds()?;
    Ok(ok(runtime
        .service()?
        .tool_list(&author, limit, offset)
        .await?))
}

/// One tool version with its package, or the newest one.
#[utoipa::path(
    get,
    path = "/mcp/builder/tools/{identity}",
    operation_id = "get_tool_mcp_builder_tools__identity__get",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ToolQuery
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn get_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityPath>,
    query: Result<Query<ToolQuery>, QueryRejection>,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let Query(query) = query.map_err(|_| BuilderError::Invalid("invalid version".to_owned()))?;
    let version = match query.version {
        Some(version) => Some(version_parameter(&version.to_string())?),
        None => None,
    };
    Ok(ok(runtime
        .service()?
        .tool_get(&author, &identity, version)
        .await?))
}

/// Append the next draft version of an owned tool.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools/{identity}/versions",
    operation_id = "update_tool_mcp_builder_tools__identity__versions_post",
    tag = "builder",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn update_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let payload: ToolUpdate = parse_body(&body)?;
    Ok(created(
        runtime
            .service()?
            .tool_update(&author, &identity, &payload)
            .await?,
    ))
}

/// Run one tool version once as a draft test run.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools/{identity}/versions/{version}/test",
    operation_id = "test_tool_mcp_builder_tools__identity__versions__version__test_post",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn test_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityVersionPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let version = version_parameter(&path.version)?;
    let payload: ToolTestRequest = parse_optional_body(&body)?;
    Ok(ok(runtime
        .service()?
        .tool_test(&author, &identity, version, &payload)
        .await?))
}

/// Publish a draft tool version and the draft service and operations it pins.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools/{identity}/versions/{version}/publish",
    operation_id = "publish_tool_mcp_builder_tools__identity__versions__version__publish_post",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityVersionPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let version = version_parameter(&path.version)?;
    let payload: ToolPublishRequest = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .tool_publish(&author, &identity, version, &payload)
        .await?))
}

/// Disable a tool version.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools/{identity}/versions/{version}/disable",
    operation_id = "disable_builder_tool_mcp_builder_tools__identity__versions__version__disable_post",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityVersionPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    transition_tool(runtime, author, path, body, VersionStatus::Disabled).await
}

/// Retire a tool version.
#[utoipa::path(
    post,
    path = "/mcp/builder/tools/{identity}/versions/{version}/retire",
    operation_id = "retire_builder_tool_mcp_builder_tools__identity__versions__version__retire_post",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn retire_tool(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityVersionPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    transition_tool(runtime, author, path, body, VersionStatus::Retired).await
}

/// The reference's `disable_tool` / `retire_tool` loop: one revision-guarded transition.
async fn transition_tool(
    runtime: Arc<BuilderRuntime>,
    author: AuthorPrincipal,
    path: IdentityVersionPath,
    body: RawBody,
    status: VersionStatus,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let version = version_parameter(&path.version)?;
    let payload: RevisionRequest = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .tool_set_status(
            &author,
            &identity,
            version,
            status,
            payload.expected_revision,
        )
        .await?))
}

/// One draft test run with its call trace.
#[utoipa::path(
    get,
    path = "/mcp/builder/runs/{run_id}",
    operation_id = "get_run_mcp_builder_runs__run_id__get",
    tag = "builder",
    params(("run_id" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn get_run(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<RunPath>,
) -> Result<Response, BuilderError> {
    let run_id = identity_parameter(&path.run_id)?;
    Ok(ok(runtime.service()?.run_get(&author, &run_id).await?))
}

/// Create a draft toolkit at version one.
#[utoipa::path(
    post,
    path = "/mcp/builder/toolkits",
    operation_id = "create_toolkit_mcp_builder_toolkits_post",
    tag = "builder",
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_toolkit(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let payload: ToolkitRequest = parse_body(&body)?;
    if payload.toolkit_id.is_some() {
        return Err(BuilderError::Input(
            "use POST /toolkits/{id}/versions for a new version".to_owned(),
        ));
    }
    Ok(created(
        runtime.service()?.toolkit_create(&author, &payload).await?,
    ))
}

/// Re-bind the tenant's product bindings so they pin its published toolkits.
#[utoipa::path(
    post,
    path = "/mcp/builder/toolkits/bind",
    operation_id = "bind_toolkits_mcp_builder_toolkits_bind_post",
    tag = "builder",
    responses((status = 200, description = "Successful Response", body = AnyJson))
)]
pub async fn bind_toolkits(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let payload: BindRequest = parse_optional_body(&body)?;
    Ok(ok(runtime.service()?.rebind(&author, &payload).await?))
}

/// Append the next draft version of a toolkit.
#[utoipa::path(
    post,
    path = "/mcp/builder/toolkits/{identity}/versions",
    operation_id = "append_toolkit_mcp_builder_toolkits__identity__versions_post",
    tag = "builder",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn append_toolkit(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let payload: ToolkitRequest = parse_body(&body)?;
    if payload.toolkit_id.as_ref() != Some(&identity) {
        return Err(BuilderError::Input(
            "toolkit_id must equal the path identity".to_owned(),
        ));
    }
    Ok(created(
        runtime.service()?.toolkit_create(&author, &payload).await?,
    ))
}

/// Publish a draft toolkit version and re-bind the tenant's product bindings.
#[utoipa::path(
    post,
    path = "/mcp/builder/toolkits/{identity}/versions/{version}/publish",
    operation_id = "publish_toolkit_mcp_builder_toolkits__identity__versions__version__publish_post",
    tag = "builder",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_toolkit(
    Extension(runtime): Extension<Arc<BuilderRuntime>>,
    Extension(author): Extension<AuthorPrincipal>,
    Path(path): Path<IdentityVersionPath>,
    body: RawBody,
) -> Result<Response, BuilderError> {
    let identity = identity_parameter(&path.identity)?;
    let version = version_parameter(&path.version)?;
    let payload: ToolkitPublishRequest = parse_body(&body)?;
    Ok(ok(runtime
        .service()?
        .toolkit_publish(&author, &identity, version, &payload)
        .await?))
}

// ── the OpenAPI mirror ────────────────────────────────────────────────────────────────────

/// The reference mounts ONE router at both prefixes, so its OpenAPI document carries both path
/// sets, byte-identical apart from the path templates and FastAPI's generated operation ids.
/// `utoipa` binds one path to one handler, so the product paths are mirrored here from the
/// documented tenant ones: the same operations, the same parameters, the same responses, with
/// the prefix rewritten and each operation id transformed exactly as FastAPI's
/// `generate_unique_id` does for the second mount.
///
/// The reference declares no `tenant_id` parameter: the segment is an untyped router-prefix
/// capture, so the mirrored operations carry exactly the tenant mount's parameters.
pub fn mirror_product_paths(paths: &mut Paths) {
    let mirrored: Vec<(String, PathItem)> = paths
        .paths
        .iter()
        .filter_map(|(path, item)| {
            let suffix = path.strip_prefix(AUTHOR_MOUNT)?;
            if !suffix.is_empty() && !suffix.starts_with('/') {
                return None;
            }
            Some((format!("{PRODUCT_MOUNT}{suffix}"), mirror_item(item)))
        })
        .collect();
    for (path, item) in mirrored {
        paths.paths.insert(path, item);
    }
}

/// One documented path item under the product prefix.
fn mirror_item(item: &PathItem) -> PathItem {
    let mut item = item.clone();
    // Disjoint field borrows, so the nine operations can be mirrored in one pass.
    for operation in [
        &mut item.get,
        &mut item.put,
        &mut item.post,
        &mut item.delete,
        &mut item.options,
        &mut item.head,
        &mut item.patch,
        &mut item.trace,
        &mut item.query,
    ] {
        if let Some(operation) = operation {
            mirror_operation(operation);
        }
    }
    for operation in item.additional_operations.values_mut() {
        mirror_operation(operation);
    }
    item
}

/// `usage_mcp_builder_usage_get` becomes
/// `usage_mcp_internal_tenants__tenant_id__builder_usage_get`.
fn mirror_operation(operation: &mut Operation) {
    if let Some(id) = operation.operation_id.as_mut() {
        *id = id.replacen(
            "_mcp_builder",
            "_mcp_internal_tenants__tenant_id__builder",
            1,
        );
    }
}
