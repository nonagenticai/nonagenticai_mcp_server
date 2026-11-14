//! HTTP-level tests that need no database: the pool is lazy and never connects.

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use axum::routing::get;
use http_body_util::BodyExt;
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, Binding, BindingAuthority, BoxFuture, LicenceAuthority,
    LicenseIdentity, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::tenant::TenantId;
use mcp_server_rs::{AppState, app_with_auth, openapi};

const TENANT: &str = "5f868d42-03f8-51f0-a93c-3e83070dc196";
const LICENCE_TOKEN: &str = "licence-token";
const BINDING_TOKEN: &str = "binding-token";

fn state() -> AppState {
    // The readiness test expects this connection to FAIL; the short acquire timeout keeps
    // that failure instant instead of sqlx's 30 s default.
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    AppState {
        pool,
        execution_enabled: false,
        license_app_key: None,
        approved_runner_images: Vec::new(),
    }
}

/// A valid tenant-level licence for the fixed test token (the licence authority is another
/// test file's subject; these tests only need an authenticated caller).
struct TestLicence;

impl LicenceAuthority for TestLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            if token != LICENCE_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(LicenseIdentity {
                tenant_id: Rfc4122Uuid::parse(TENANT).expect("static uuid"),
                license_id: Rfc4122Uuid::parse("01900000-0000-7000-8000-0000000000aa")
                    .expect("static uuid"),
                subject: "svc:test:mcp".into(),
                subject_kind: Some(SubjectKind::Tenant),
            })
        })
    }
}

struct TestBindings;

impl BindingAuthority for TestBindings {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async move {
            if token != BINDING_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(Binding {
                binding_id: Rfc4122Uuid::parse("01900000-0000-7000-8000-0000000000bb")
                    .expect("static uuid"),
                revision: 1,
            })
        })
    }
}

/// The real router with authentication wired the way the binary wires it (from the
/// environment) — here with a deterministic licence and binding authority.
fn authed_app() -> Router {
    let mut auth = Auth::from_config(&AuthConfig::default()).expect("empty auth config is valid");
    auth.licences = Arc::new(TestLicence);
    auth.bindings = Arc::new(TestBindings);
    app_with_auth(state(), auth)
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = resp.into_body().collect().await.expect("body").to_bytes();
    serde_json::from_slice(&bytes).expect("json body")
}

#[tokio::test]
async fn health_returns_ok() {
    let resp = authed_app()
        .oneshot(Request::get("/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "status": "alive", "execution": "unavailable" })
    );
}

#[tokio::test]
async fn api_health_matches_the_overview_probe() {
    let resp = authed_app()
        .oneshot(Request::get("/api/health").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        body_json(resp).await,
        serde_json::json!({ "status": "healthy" })
    );
}

#[tokio::test]
async fn unknown_route_is_404() {
    let resp = authed_app()
        .oneshot(Request::get("/nope").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

#[test]
fn openapi_documents_health() {
    let spec = serde_json::to_value(openapi()).unwrap();
    assert!(spec["openapi"].as_str().unwrap().starts_with("3."));
    assert!(spec["paths"]["/health"]["get"].is_object(), "{spec:#}");
    assert_eq!(spec["info"]["title"], env!("CARGO_PKG_NAME"));
}

fn tenant_app() -> Router {
    Router::new().route("/t", get(|t: TenantId| async move { t.0 }))
}

async fn tenant_call(header: Option<&str>) -> (StatusCode, Vec<u8>) {
    let mut req = Request::get("/t");
    if let Some(h) = header {
        req = req.header("x-tenant-id", h);
    }
    let resp = tenant_app()
        .oneshot(req.body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = resp.status();
    let body = resp
        .into_body()
        .collect()
        .await
        .unwrap()
        .to_bytes()
        .to_vec();
    (status, body)
}

#[tokio::test]
async fn tenant_extractor_accepts_trusted_header() {
    let (status, body) = tenant_call(Some("5f868d42-aaaa-bbbb")).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, b"5f868d42-aaaa-bbbb");
}

#[tokio::test]
async fn tenant_extractor_rejects_missing_or_invalid_header() {
    for h in [None, Some(""), Some("  "), Some("a b"), Some("../x")] {
        let (status, body) = tenant_call(h).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "header {h:?}");
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["detail"].as_str().unwrap().contains("X-Tenant-Id"), "{v}");
    }
    let long = "a".repeat(129);
    assert_eq!(tenant_call(Some(&long)).await.0, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn readiness_is_503_when_the_database_is_unreachable() {
    let resp = authed_app()
        .oneshot(Request::get("/health/ready").body(Body::empty()).unwrap())
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = body_json(resp).await;
    assert_eq!(body["status"], "not_ready");
    assert_eq!(body["execution"], "unavailable");
}

/// POST one JSON-RPC message to `/mcp` the way the Python source is called: stateless
/// streamable HTTP, both content types accepted, loopback Host (rmcp's default allowlist).
/// The request carries the binding credentials the `/mcp` middleware requires.
async fn mcp_call(message: serde_json::Value) -> (StatusCode, String, String) {
    let req = Request::post("/mcp")
        .header("host", "127.0.0.1")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", BINDING_TOKEN)
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .body(Body::from(serde_json::to_vec(&message).unwrap()))
        .unwrap();
    let resp = authed_app().oneshot(req).await.unwrap();
    let status = resp.status();
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = resp.into_body().collect().await.unwrap().to_bytes();
    (
        status,
        content_type,
        String::from_utf8_lossy(&bytes).into_owned(),
    )
}

/// The JSON-RPC message carried by an SSE frame (`json_response=False`, like fastmcp) or,
/// when the transport answered plainly, the body itself.
fn rpc_payload(body: &str) -> serde_json::Value {
    let data = body
        .lines()
        .find_map(|l| l.strip_prefix("data:"))
        .map(str::trim)
        .unwrap_or(body);
    serde_json::from_str(data).unwrap_or_else(|e| panic!("not JSON ({e}): {body:?}"))
}

#[tokio::test]
async fn mcp_requires_authentication_before_any_jsonrpc() {
    let resp = authed_app()
        .oneshot(
            Request::post("/mcp")
                .header("host", "127.0.0.1")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::to_vec(&serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 0,
                        "method": "initialize",
                        "params": {}
                    }))
                    .unwrap(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_eq!(resp.headers().get("www-authenticate").unwrap(), "Bearer");
}

#[tokio::test]
async fn mcp_initialize_negotiates_a_protocol_version() {
    let (status, content_type, body) = mcp_call(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-06-18",
            "capabilities": {},
            "clientInfo": {"name": "parity", "version": "0"}
        }
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE framing, got {content_type}: {body}"
    );
    // Captured from the Python source's own transport at the pinned SHA
    // (fastmcp `http_app(path="/", stateless_http=True, json_response=False)`).
    // The whole envelope is the contract, not just the fields this test names.
    let expected = serde_json::json!({
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2025-06-18",
            "capabilities": {"tools": {"listChanged": false}},
            "serverInfo": {"name": "Executable catalog", "version": "2.0.0"}
        }
    });
    assert_eq!(rpc_payload(&body), expected, "{body}");
}

#[tokio::test]
async fn mcp_tools_list_is_empty_phase_0() {
    let (status, _content_type, body) = mcp_call(serde_json::json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
        "params": {}
    }))
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let reply = rpc_payload(&body);
    assert_eq!(reply["id"], 2);
    assert_eq!(reply["result"]["tools"], serde_json::json!([]), "{reply}");
}
