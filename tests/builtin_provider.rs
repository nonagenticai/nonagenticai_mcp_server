//! The builtin provider core over the real `/mcp` transport and the real test harness.
//!
//! Covers the reference's provider/dispatch contract with an empty registry and with a
//! synthetic tool: a principal with no catalog binding is served the builtin provider (and a
//! cursor is refused); a binding principal keeps the catalog path; a call with no provider
//! installed is the reference's denial; a scope refusal and an unknown tool are the same
//! denial; and every call writes one `mcp_tool_call_audit` row with the reference's columns.
//!
//! The `/mcp` authentication layer does not yet admit non-binding callers (a separate card),
//! so these tests mount the real [`mcp::service`] behind a middleware that inserts the
//! principal the reference's authenticator would have inserted — the exact seam the auth card
//! will use. The binding case runs the unmodified real router.

use std::sync::Arc;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use rmcp::model::{CallToolResult, ContentBlock};
use serde_json::{Value, json};
use sqlx::Row;

use mcp_server_rs::AppState;
use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::builtin::audit::{AuditError, AuditFuture, AuditSink};
use mcp_server_rs::builtin::{
    BuiltinCaller, BuiltinProvider, BuiltinTool, DENIED_MESSAGE, DatabaseAuditSink, Handler, boxed,
};
use mcp_server_rs::mcp;

mod support;

use support::{Fixture, mcp_post};

// ── the real transport with a resolved principal ─────────────────────────────────────────

/// Inserts the principal the `/mcp` authenticator resolved, exactly as the real middleware
/// does. The builtin caller kinds are not yet authenticated on this surface; this is the seam.
async fn inject(State(principal): State<Principal>, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(principal);
    next.run(request).await
}

/// The real `/mcp` service (real transport, real handler, real resolver) behind one resolved
/// principal. `provider = None` is a deployment with no builtin provider installed.
fn builtin_app(state: AppState, principal: Principal, provider: Option<BuiltinProvider>) -> Router {
    Router::new()
        .route_service("/mcp", mcp::service_with_builtin(&state, provider))
        .layer(from_fn_with_state(principal, inject))
}

fn principal(subject: &str) -> Principal {
    Principal {
        tenant_id: Rfc4122Uuid::parse(support::TENANT_A).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(support::LICENCE_ID).expect("licence identity"),
        subject: subject.to_owned(),
        binding_id: None,
        binding_revision: None,
        management: false,
        platform: false,
    }
}

/// A tenant-level care-bus licence subject: the licence-only caller the reference serves.
fn carebus_licence() -> Principal {
    principal(&format!("svc:{}:care-bus", support::TENANT_A))
}

// ── requests ──────────────────────────────────────────────────────────────────────────────

fn tools_list(cursor: Option<&str>) -> Value {
    match cursor {
        Some(cursor) => json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {"cursor": cursor}
        }),
        None => json!({
            "jsonrpc": "2.0",
            "id": 7,
            "method": "tools/list",
            "params": {}
        }),
    }
}

fn tools_call(name: &str, arguments: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": {"name": name, "arguments": arguments}
    })
}

// ── synthetic builtin tools ───────────────────────────────────────────────────────────────

fn empty_schema() -> serde_json::Map<String, Value> {
    json!({"type": "object", "properties": {}, "additionalProperties": false})
        .as_object()
        .cloned()
        .expect("schema object")
}

/// A handler that answers one fixed text.
fn text_handler(text: &'static str) -> Handler {
    Arc::new(move |_caller: BuiltinCaller, _arguments| {
        boxed(async move { Ok(CallToolResult::success(vec![ContentBlock::text(text)])) })
    })
}

/// A provider with one `crm_demo` tool in the care-bus `crm` namespace.
fn one_crm_tool() -> BuiltinProvider {
    let mut provider = BuiltinProvider::new();
    provider.register(BuiltinTool::new(
        "crm",
        "demo",
        "Synthetic builtin",
        empty_schema(),
        text_handler("ok"),
    ));
    provider
}

/// A sink whose write always fails: the reference swallows it and the call still succeeds.
struct BrokenSink;

impl AuditSink for BrokenSink {
    fn write<'a>(
        &'a self,
        _caller: &'a BuiltinCaller,
        _tool: &'a str,
        _status: &'a str,
        _details: &'a Value,
    ) -> AuditFuture<'a> {
        Box::pin(async {
            let error: AuditError = Box::new(std::io::Error::other("audit down"));
            Err::<(), AuditError>(error)
        })
    }
}

// ── dispatch: no binding -> builtin; binding -> catalog ───────────────────────────────────

#[tokio::test]
async fn a_licence_only_principal_gets_the_builtin_listing() {
    let fixture = Fixture::new().await;
    // The registry is empty in this card, so the caller's scope lists no tools at all.
    let app = builtin_app(
        fixture.state(),
        carebus_licence(),
        Some(BuiltinProvider::new()),
    );

    let (status, content_type, reply) = mcp_post(&app, None, tools_list(None)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE framing, got {content_type}: {reply}"
    );
    assert_eq!(reply["id"], 7);
    assert_eq!(reply["result"]["tools"], json!([]), "{reply}");
    assert!(reply["result"]["nextCursor"].is_null(), "{reply}");
    fixture.finish().await;
}

#[tokio::test]
async fn a_binding_principal_never_sees_the_builtin_listing() {
    let fixture = Fixture::new().await;
    support::binding_fixture(&fixture).await;
    let app = fixture.app();
    let created = support::create_binding(&app).await;
    let token = created["token"].as_str().expect("binding token").to_owned();

    // The unmodified real router: the catalog projection, never the (empty) builtin page.
    let (status, _, reply) = mcp_post(&app, Some(&token), tools_list(None)).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(
        reply["result"]["tools"].as_array().map(Vec::len),
        Some(1),
        "{reply}"
    );
    assert_eq!(
        reply["result"]["tools"][0]["name"],
        json!("alpha_tool"),
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_cursor_in_a_builtin_listing_is_refused() {
    let fixture = Fixture::new().await;
    let app = builtin_app(
        fixture.state(),
        carebus_licence(),
        Some(BuiltinProvider::new()),
    );

    let (status, _, reply) = mcp_post(&app, None, tools_list(Some("next-page"))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(reply["result"].is_null(), "{reply}");
    assert_eq!(reply["error"]["code"], json!(-32602), "{reply}");
    assert_eq!(
        reply["error"]["message"],
        json!("catalog_unavailable_or_invalid_cursor"),
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn no_provider_installed_answers_the_reference_denial() {
    let fixture = Fixture::new().await;
    let app = builtin_app(fixture.state(), carebus_licence(), None);

    // A call is the reference's tool-level denial, never a JSON-RPC error.
    let (status, _, reply) = mcp_post(&app, None, tools_call("crm_demo", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!(DENIED_MESSAGE),
        "{reply}"
    );

    // A listing without a provider is the catalog refusal.
    let (_, _, listing) = mcp_post(&app, None, tools_list(None)).await;
    assert_eq!(listing["error"]["code"], json!(-32602), "{listing}");
    fixture.finish().await;
}

// ── the provider's scope filter ───────────────────────────────────────────────────────────

#[tokio::test]
async fn the_listing_is_the_callers_scope_only() {
    let fixture = Fixture::new().await;
    let mut provider = BuiltinProvider::new();
    provider.register(BuiltinTool::new(
        "crm",
        "demo",
        "Synthetic crm tool",
        empty_schema(),
        text_handler("crm"),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "statute",
        "Synthetic legal tool",
        empty_schema(),
        text_handler("legal"),
    ));

    let researcher = builtin_app(
        fixture.state(),
        principal("carebus-researcher"),
        Some(provider.clone()),
    );
    let (_, _, reply) = mcp_post(&researcher, None, tools_list(None)).await;
    assert_eq!(reply["result"]["tools"][0]["name"], json!("legal_statute"));
    assert_eq!(reply["result"]["tools"].as_array().map(Vec::len), Some(1));

    let executor = builtin_app(
        fixture.state(),
        principal("carebus-tool-executor"),
        Some(provider),
    );
    let (_, _, reply) = mcp_post(&executor, None, tools_list(None)).await;
    assert_eq!(reply["result"]["tools"][0]["name"], json!("crm_demo"));
    assert_eq!(reply["result"]["tools"].as_array().map(Vec::len), Some(1));
    fixture.finish().await;
}

#[tokio::test]
async fn an_unknown_builtin_tool_is_denied() {
    let fixture = Fixture::new().await;
    let app = builtin_app(
        fixture.state(),
        carebus_licence(),
        Some(BuiltinProvider::new()),
    );

    let (status, _, reply) = mcp_post(
        &app,
        None,
        tools_call("crm_verify_customer", json!({"customer_id": "C-1"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!(DENIED_MESSAGE),
        "{reply}"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_call_outside_the_scope_is_denied() {
    let fixture = Fixture::new().await;
    let app = builtin_app(
        fixture.state(),
        principal("carebus-researcher"),
        Some(one_crm_tool()),
    );

    let (_, _, reply) = mcp_post(&app, None, tools_call("crm_demo", json!({}))).await;
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!(DENIED_MESSAGE),
        "{reply}"
    );
    fixture.finish().await;
}

// ── the audit row ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn one_call_writes_one_audit_row_with_the_reference_columns() {
    let fixture = Fixture::new().await;
    let provider = one_crm_tool().with_sink(Arc::new(DatabaseAuditSink::new(fixture.pool.clone())));
    let app = builtin_app(fixture.state(), carebus_licence(), Some(provider));

    let (status, _, reply) = mcp_post(&app, None, tools_call("crm_demo", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!("ok"),
        "{reply}"
    );

    let rows = sqlx::query(
        "SELECT tool,status,principal_kind,auth_method,principal,tenant_id,latency_ms,details \
         FROM public.mcp_tool_call_audit",
    )
    .fetch_all(&fixture.pool)
    .await
    .expect("audit rows");
    assert_eq!(rows.len(), 1, "one row per call");
    let row = &rows[0];
    let tool: String = row.try_get("tool").expect("tool");
    let status: String = row.try_get("status").expect("status");
    let principal_kind: String = row.try_get("principal_kind").expect("principal_kind");
    let auth_method: String = row.try_get("auth_method").expect("auth_method");
    let principal: String = row.try_get("principal").expect("principal");
    let tenant_id: Option<String> = row.try_get("tenant_id").expect("tenant_id");
    let latency_ms: i32 = row.try_get("latency_ms").expect("latency_ms");
    let details: Value = row.try_get("details").expect("details");

    assert_eq!(tool, "crm_demo");
    assert_eq!(status, "success");
    assert_eq!(principal_kind, "carebus_licence");
    assert_eq!(auth_method, "license");
    let subject = format!("svc:{}:care-bus", support::TENANT_A);
    assert_eq!(principal, subject);
    assert_eq!(tenant_id.as_deref(), Some(support::TENANT_A));
    assert!(latency_ms >= 0, "latency_ms {latency_ms}");

    assert_eq!(details["tool"], json!("crm_demo"));
    assert_eq!(details["ok"], json!(true));
    assert_eq!(details["error"], Value::Null);
    assert_eq!(details["auth_method"], json!("license"));
    assert_eq!(details["principal"], json!(subject));
    assert_eq!(details["tenant_id"], json!(support::TENANT_A));
    assert!(details["latency_ms"].is_number(), "{details}");
    assert!(details.get("denied").is_none(), "{details}");
    assert!(details.get("cancelled").is_none(), "{details}");

    fixture.finish().await;
}

#[tokio::test]
async fn a_scope_refusal_is_audited_as_denied() {
    let fixture = Fixture::new().await;
    let provider = one_crm_tool().with_sink(Arc::new(DatabaseAuditSink::new(fixture.pool.clone())));
    let app = builtin_app(
        fixture.state(),
        principal("carebus-researcher"),
        Some(provider),
    );

    let (_, _, reply) = mcp_post(&app, None, tools_call("crm_demo", json!({}))).await;
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!(DENIED_MESSAGE),
        "{reply}"
    );

    let rows = sqlx::query("SELECT status,latency_ms,details FROM public.mcp_tool_call_audit")
        .fetch_all(&fixture.pool)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "one row per call");
    let status: String = rows[0].try_get("status").expect("status");
    let latency_ms: i32 = rows[0].try_get("latency_ms").expect("latency_ms");
    let details: Value = rows[0].try_get("details").expect("details");
    assert_eq!(status, "denied");
    assert_eq!(
        latency_ms, 0,
        "the reference records a refusal at zero latency"
    );
    assert_eq!(details["denied"], json!(true));
    assert_eq!(details["ok"], json!(false));
    assert_eq!(details["error"], json!(DENIED_MESSAGE));
    fixture.finish().await;
}

#[tokio::test]
async fn an_audit_failure_never_fails_the_tool_call() {
    let fixture = Fixture::new().await;
    let provider = one_crm_tool().with_sink(Arc::new(BrokenSink));
    let app = builtin_app(
        fixture.state(),
        principal("carebus-tool-executor"),
        Some(provider),
    );

    let (status, _, reply) = mcp_post(&app, None, tools_call("crm_demo", json!({}))).await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
    assert_eq!(
        reply["result"]["content"][0]["text"],
        json!("ok"),
        "{reply}"
    );
    fixture.finish().await;
}
