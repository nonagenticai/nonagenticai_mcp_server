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
#[openapi(tags((name = "health", description = "Liveness")))]
struct ApiDoc;

/// Every route is registered here, through `routes!`, so the served router and the
/// OpenAPI document cannot drift: a handler without `#[utoipa::path]` does not compile here.
fn api_router() -> OpenApiRouter<AppState> {
    OpenApiRouter::with_openapi(ApiDoc::openapi())
        .routes(routes!(routes::health::health))
        .routes(routes!(routes::health::live))
        .routes(routes!(routes::health::ready))
        .routes(routes!(routes::health::api_health))
}

/// The OpenAPI document of this service (what `--print-openapi` writes). Needs no env and no DB.
pub fn openapi() -> utoipa::openapi::OpenApi {
    let (_, spec) = api_router().split_for_parts();
    spec
}

/// The HTTP application the binary serves.
pub fn app(state: AppState) -> Router {
    let (router, _) = api_router().split_for_parts();
    // `/mcp` is rmcp's tower service, not an axum handler: it has its own JSON-RPC
    // envelope, so it is not part of the utoipa OpenAPI document.
    router
        .route_service("/mcp", mcp::service())
        .layer(TraceLayer::new_for_http())
        .with_state(state)
}
