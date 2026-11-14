#![forbid(unsafe_code)]
//! Service library: router, OpenAPI document, configuration, database and the reusable
//! trusted-header tenant extractor. `main.rs` is a thin wrapper so integration tests can
//! build the exact router the binary serves.

pub mod auth;
pub mod catalog;
pub mod config;
pub mod db;
pub mod error;
pub mod mcp;
pub mod routes;
pub mod storage;
pub mod telemetry;
pub mod tenant;
pub mod toolkits;

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
}

/// Document-level OpenAPI metadata. `info` (title, version, description) comes from
/// Cargo.toml, so renaming the crate renames the spec.
#[derive(OpenApi)]
#[openapi(
    tags(
        (name = "health", description = "Liveness"),
        (name = "tools", description = "Tenant tool catalog"),
        (name = "toolkits", description = "Tenant toolkits")
    ),
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
pub fn app(state: AppState) -> Result<Router, error::StartupError> {
    let auth = auth::Auth::from_env()?;
    Ok(app_with_auth(state, auth))
}

/// The same application with an explicit [`auth::Auth`] (tests, and the binary through
/// [`app`]).
///
/// The auth layer is installed here, after every route is registered and before
/// `with_state`, so it covers `/mcp` and every `/mcp/...` path — including paths no route
/// knows yet, which the reference middleware also protects.
pub fn app_with_auth(state: AppState, auth: auth::Auth) -> Router {
    let (router, _) = api_router().split_for_parts();
    // `/mcp` is rmcp's tower service, not an axum handler: it has its own JSON-RPC
    // envelope, so it is not part of the utoipa OpenAPI document.
    router
        .route_service("/mcp", mcp::service())
        .layer(axum::middleware::from_fn_with_state(auth, auth::protect))
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
