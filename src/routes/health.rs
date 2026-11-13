//! Health endpoints, shaped like the Python source's (`src/asgi.py`): `/health` and
//! `/health/live` are liveness, `/health/ready` is readiness, `/api/health` is the care-bus
//! overview probe. The bodies are the wire contract consumers already read, so they are
//! ported verbatim — including the `execution` field, which reports whether this build can
//! run tools (false until the execution slice lands).
//!
//! The OpenAPI annotations deliberately mirror what the source's own document declares: the
//! three dict handlers as `dict[str, str]` (an object with string values, no fixed
//! properties) and `/health/ready` with an empty schema and no 503 — FastAPI does not
//! introspect a `JSONResponse`. The served JSON is the contract (asserted in `tests/http.rs`);
//! the document is held to the source so every later phase's `openapi-diff` compares like
//! with like.

use std::collections::BTreeMap;
use std::fmt;

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use utoipa::openapi::RefOr;
use utoipa::openapi::schema::{AdditionalProperties, Object, Schema, SchemaType, Type};
use utoipa::{PartialSchema, ToSchema};

use crate::AppState;

/// The source's `dict[str, str]` response body: an object whose values are strings.
pub struct StringMap;

impl PartialSchema for StringMap {
    fn schema() -> RefOr<Schema> {
        // Exactly the source's document: {"type": "object", "additionalProperties":
        // {"type": "string"}}. utoipa's map impl adds `propertyNames`, which the source does
        // not declare, so the object is built by hand.
        let mut object = Object::with_type(Type::Object);
        object.additional_properties = Some(Box::new(AdditionalProperties::from(Schema::Object(
            Object::with_type(Type::String),
        ))));
        RefOr::T(Schema::Object(object))
    }
}

impl ToSchema for StringMap {}

impl fmt::Debug for StringMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StringMap")
    }
}

/// The empty schema the source's OpenAPI carries for `/health/ready`'s 200.
pub struct AnyJson;

impl PartialSchema for AnyJson {
    fn schema() -> RefOr<Schema> {
        // `AnyValue` omits the `type` keyword, which is what the source's empty schema is.
        let mut object = Object::new();
        object.schema_type = SchemaType::AnyValue;
        RefOr::T(Schema::Object(object))
    }
}

impl ToSchema for AnyJson {}

impl fmt::Debug for AnyJson {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AnyJson")
    }
}

fn body(pairs: impl IntoIterator<Item = (&'static str, String)>) -> BTreeMap<String, String> {
    pairs.into_iter().map(|(k, v)| (k.to_owned(), v)).collect()
}

fn execution(state: &AppState) -> String {
    if state.execution_enabled {
        "enabled".to_owned()
    } else {
        "unavailable".to_owned()
    }
}

/// Liveness probe.
///
/// Answers 200 while the HTTP server runs. It does not touch the database, so a DB outage
/// does not make the orchestrator restart a healthy process.
#[utoipa::path(
    get,
    path = "/health",
    tag = "health",
    responses((status = 200, description = "Service is up", body = StringMap))
)]
pub async fn health(State(state): State<AppState>) -> Json<BTreeMap<String, String>> {
    Json(body([
        ("status", "alive".to_owned()),
        ("execution", execution(&state)),
    ]))
}

/// The source serves liveness on two paths; `/health/live` is the one the probes use.
#[utoipa::path(
    get,
    path = "/health/live",
    tag = "health",
    responses((status = 200, description = "Service is up", body = StringMap))
)]
pub async fn live(State(state): State<AppState>) -> Json<BTreeMap<String, String>> {
    health(State(state)).await
}

/// Public overview probe used by care-bus-api: `{MCP_URL minus /mcp}/api/health`.
#[utoipa::path(
    get,
    path = "/api/health",
    tag = "health",
    responses((status = 200, description = "Service is healthy", body = StringMap))
)]
pub async fn api_health() -> Json<BTreeMap<String, String>> {
    // The source serves exactly `{"status": "healthy"}` on this path; it carries no
    // `execution` field (asserted in tests/http.rs).
    Json(body([("status", "healthy".to_owned())]))
}

/// Readiness probe.
///
/// Answers 200 only when a `SELECT 1` succeeds on the runtime pool. A database outage makes
/// the pod NotReady (so traffic is withdrawn) without restarting a healthy process. The 503
/// branch is real and asserted in `tests/http.rs`; the source's document does not declare it.
#[utoipa::path(
    get,
    path = "/health/ready",
    tag = "health",
    responses((status = 200, description = "Ready", body = AnyJson))
)]
pub async fn ready(State(state): State<AppState>) -> (StatusCode, Json<BTreeMap<String, String>>) {
    let execution = execution(&state);
    match sqlx::query("SELECT 1").execute(&state.pool).await {
        Ok(_) => (
            StatusCode::OK,
            Json(body([
                ("status", "ready".to_owned()),
                ("execution", execution),
            ])),
        ),
        Err(error) => {
            tracing::warn!(%error, "readiness: database did not answer");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(body([
                    ("status", "not_ready".to_owned()),
                    ("execution", execution),
                ])),
            )
        }
    }
}
