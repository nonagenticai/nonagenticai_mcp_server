#![forbid(unsafe_code)]
//! Service library: router, OpenAPI document, configuration, database and the reusable
//! trusted-header tenant extractor. `main.rs` is a thin wrapper so integration tests can
//! build the exact router the binary serves.

pub mod auth;
pub mod builder;
pub mod catalog;
pub mod config;
pub mod db;
pub mod error;
pub mod execution;
pub mod external;
pub mod mcp;
pub mod routes;
pub mod sources;
pub mod storage;
pub mod tasks;
pub mod telemetry;
pub mod tenant;
pub mod toolkits;
pub mod worker;

/// Select the process-level `rustls` provider, once per process.
///
/// Both providers end up in the dependency graph — `aws-lc-rs` through kube and reqwest's
/// `rustls` feature, `ring` through sqlx's TLS — so rustls cannot infer one from its features
/// and panics on the first `ClientConfig` with "could not automatically determine the
/// process-level CryptoProvider". Every binary and every test that builds a TLS client calls
/// this first; installing a provider twice is a no-op error that is deliberately ignored.
pub fn install_crypto_provider() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    });
}

use axum::Router;
use sqlx::PgPool;
use tower_http::trace::TraceLayer;
use utoipa::OpenApi;
use utoipa_axum::router::OpenApiRouter;
use utoipa_axum::routes;

/// Shared state handed to every handler.
#[derive(Clone)]
pub struct AppState {
    pub pool: PgPool,
    /// Whether this build can run tools. Reported by the health endpoints; false until the
    /// execution slice lands.
    pub execution_enabled: bool,
    /// `MCP_LICENSE_APP_KEY`: the gateway application key a binding's credential profile must
    /// name. Parsed once at startup, from the same [`config::AuthConfig`] the auth layer uses.
    pub license_app_key: Option<String>,
    /// `MCP_APPROVED_RUNNER_IMAGES`: the runner image digests a `kata_python` tool may name.
    pub approved_runner_images: Vec<String>,
    /// `PLATFORM_TENANT_ID`: the reserved platform tenant that owns platform toolkits.
    pub platform_tenant_id: auth::Rfc4122Uuid,
    /// `CATALOG_PAGE_SIZE`: the page bound for `tools/list` and the catalog projection.
    pub catalog_page_size: u32,
    /// `MCP_PLATFORM_DATABASE_URL`: the platform-authoring pool — the same database under the
    /// elevated `mcp_platform` role. `None` makes the platform-authoring routes answer
    /// `503 platform_authoring_unavailable`, the reference's behaviour when the pool is unset.
    pub platform: Option<PgPool>,
    /// `MCP_SOURCE_*`: the tool-source authoring settings (sealing key and host allow-list).
    pub sources: config::SourceSettings,
    /// The `MCP_*` execution queue, timeout and retention bounds.
    pub execution: config::ExecutionSettings,
}

/// Document-level OpenAPI metadata. `info` (title, version, description) comes from
/// Cargo.toml, so renaming the crate renames the spec.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "health", description = "Liveness"),
        (name = "tools", description = "Tenant tool catalog"),
        (name = "toolkits", description = "Tenant toolkits"),
        (name = "bindings", description = "Tenant bindings"),
        (name = "available", description = "Live catalog projection"),
        (name = "runs", description = "Durable execution runs"),
        (name = "services", description = "Platform service contracts"),
        (name = "operations", description = "Platform operation contracts"),
        (name = "sources", description = "Platform tool sources"),
        (name = "internal", description = "Service-to-service provisioning")
    ),
    // `/mcp/internal/*` is not mounted through `api_router()`: it has its own credential
    // surface and is merged outside the `/mcp` middleware (see [`app_with_internal`]). The
    // path is still documented here, exactly as the reference's FastAPI app documents it.
    paths(routes::internal::ensure_binding),
    components(schemas(routes::tools::ValidationError))
)]
struct ApiDoc;

/// Every route is registered here, through `routes!`, so the served router and the
/// OpenAPI document cannot drift: a handler without `#[utoipa::path]` does not compile here.
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(routes::health::health))
        .routes(routes!(routes::health::live))
        .routes(routes!(routes::health::ready))
        .routes(routes!(routes::health::api_health))
        .routes(routes!(routes::tools::create_tool))
        .routes(routes!(routes::tools::append_tool))
        .routes(routes!(routes::tools::definitions))
        .routes(routes!(routes::tools::inspect))
        .routes(routes!(routes::tools::validate))
        .routes(routes!(routes::tools::publish_tool))
        .routes(routes!(routes::tools::disable_tool))
        .routes(routes!(routes::tools::retire_tool))
        .routes(routes!(routes::toolkits::create_toolkit))
        .routes(routes!(routes::toolkits::append_toolkit))
        .routes(routes!(routes::toolkits::list_toolkits))
        .routes(routes!(routes::toolkits::inspect_toolkit))
        .routes(routes!(routes::toolkits::publish_toolkit))
        .routes(routes!(routes::toolkits::disable_toolkit))
        .routes(routes!(routes::bindings::create_binding))
        .routes(routes!(routes::bindings::inspect_binding))
        .routes(routes!(routes::bindings::update_binding))
        .routes(routes!(routes::bindings::rotate_binding))
        .routes(routes!(routes::bindings::revoke_binding))
        .routes(routes!(routes::bindings::create_profile))
        .routes(routes!(routes::bindings::update_profile))
        .routes(routes!(routes::bindings::validate_profile))
        .routes(routes!(routes::available::available_tools))
        .routes(routes!(routes::available::effective_tools))
        .routes(routes!(routes::runs::submit_run))
        .routes(routes!(routes::runs::inspect_run))
        .routes(routes!(routes::runs::run_events))
        .routes(routes!(routes::runs::cancel_run))
        .routes(routes!(routes::operations::create_service))
        .routes(routes!(routes::operations::append_service))
        .routes(routes!(routes::operations::list_services))
        .routes(routes!(routes::operations::inspect_service))
        .routes(routes!(routes::operations::validate_service))
        .routes(routes!(routes::operations::publish_service))
        .routes(routes!(routes::operations::disable_service))
        .routes(routes!(routes::operations::append_operation))
        .routes(routes!(routes::operations::import_operations))
        .routes(routes!(routes::operations::list_operations))
        .routes(routes!(routes::operations::inspect_operation))
        .routes(routes!(routes::operations::validate_operation))
        .routes(routes!(routes::operations::publish_operation))
        .routes(routes!(routes::operations::disable_operation))
        .routes(routes!(routes::sources::create_source))
        .routes(routes!(routes::sources::list_sources))
        .routes(routes!(routes::sources::get_source))
        .routes(routes!(routes::sources::update_source))
        .routes(routes!(routes::sources::rotate_source_token))
        .routes(routes!(routes::sources::disable_source))
        .routes(routes!(routes::sources::enable_source))
}

/// The OpenAPI document of this service (what `--print-openapi` writes). Needs no env and no DB.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let (_, spec) = api_router().split_for_parts();
    spec
}

/// The HTTP application the binary serves.
///
/// Authentication settings are read and validated once, before the listener is bound: an
/// invalid configuration must stop the process rather than serve a `/mcp` surface whose
/// operator keys or authority are misconfigured (the reference service refuses startup for the
/// same reasons). The error is returned, never panicked on.
pub fn app(
    state: AppState,
    auth_config: &config::AuthConfig,
) -> Result<Router, error::StartupError> {
    // One parse of the authentication settings feeds both the middleware and the state's
    // gateway application key, so the two can never disagree.
    let auth = auth::Auth::from_config(auth_config)?;
    let internal = routes::internal::InternalRuntime::from_config(&state, &auth, auth_config)?;
    Ok(app_with_internal(state, auth, internal))
}

/// The application with the `/mcp/internal/*` runtime supplied explicitly (tests, and the
/// binary through [`app`]).
///
/// The `/mcp` auth layer is installed after the `/mcp` routes are registered and **before**
/// the internal router is merged, so it covers `/mcp` and every `/mcp/...` path except
/// `/mcp/internal/*`: those carry a Keycloak service JWT, which that middleware would read as a
/// tenant licence. The internal router authenticates in its own middleware instead
/// (`routes::internal`), exactly as the reference's `/mcp/internal/` interceptor does.
pub fn app_with_internal(
    state: AppState,
    auth: auth::Auth,
    internal: routes::internal::InternalRuntime,
) -> Router {
    let (router, _) = api_router().split_for_parts();
    // `/mcp` is rmcp's tower service, not an axum handler: it has its own JSON-RPC
    // envelope, so it is not part of the utoipa OpenAPI document.
    router
        .route_service("/mcp", mcp::service(&state))
        .layer(axum::middleware::from_fn_with_state(auth, auth::protect))
        .merge(routes::internal::router(std::sync::Arc::new(internal)))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}

/// The same application with an explicit [`auth::Auth`] (tests, and any caller that serves
/// `/mcp` only). The internal runtime has no service-token verifier, so `/mcp/internal/*`
/// answers `503 authority_unavailable`.
pub fn app_with_auth(state: AppState, auth: auth::Auth) -> Router {
    let internal = routes::internal::InternalRuntime::unavailable(&state, &auth);
    app_with_internal(state, auth, internal)
}
