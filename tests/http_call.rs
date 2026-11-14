//! `tools/call` over the real `/mcp` transport, a real Postgres 18 and the real catalog.
//!
//! Ported from the reference `src/catalog/provider.py` (`CatalogTool.run`) and
//! `src/protocol.py` (`calling`). Every test fails if the behaviour it covers is removed: a
//! call is admitted as a durable run and answered with the reference's envelope; the caller's
//! `_meta` actor is stored on that run; invalid arguments are a readable tool-level error; and
//! every other refusal is the reference's single `tool_request_denied` — or its two named
//! execution errors — as a tool RESULT carrying `isError: true`, never a JSON-RPC error.
//!
//! Server selection mirrors `tests/runs.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL`, else an
//! ephemeral `postgres:18` container started with docker and removed afterwards, else FAIL
//! (never skip). Each test gets its own fresh database.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::http::StatusCode;
use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::app_with_auth;
use mcp_server_rs::auth::pg_bindings::PgBindingAuthority;
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::ToolManifest;
use mcp_server_rs::catalog::toolkit_models::ToolkitManifest;
use mcp_server_rs::config::ExecutionSettings;

use support::{
    Fixture, LICENCE_ID, TENANT_A, TOOL_ALPHA, TOOLKIT_1, create_binding, kata_manifest,
    tool_manifest,
};

// ── the bound fixture ─────────────────────────────────────────────────────────────────────

struct Bound {
    fixture: Fixture,
    app: Router,
    token: String,
}

/// The app served over a fixture that is already seeded: a real binding created through the
/// HTTP surface, and the execution settings under test.
async fn bind(fixture: Fixture, settings: ExecutionSettings, enabled: bool) -> Bound {
    let created = create_binding(&fixture.app()).await;
    let token = created["token"].as_str().expect("binding token").to_owned();
    let app = app_with_auth(
        fixture.state_with_execution(settings, enabled),
        fixture
            .auth()
            .with_bindings(Arc::new(PgBindingAuthority::new(fixture.pool.clone()))),
    );
    Bound {
        fixture,
        app,
        token,
    }
}

/// A published catalog, a real binding created through the HTTP surface, and the app served
/// with the given execution settings.
async fn bound(manifests: &[ToolManifest], settings: ExecutionSettings, enabled: bool) -> Bound {
    let fixture = Fixture::new().await;
    support::binding_fixture_with_tools(&fixture, manifests).await;
    bind(fixture, settings, enabled).await
}

// ── the JSON-RPC call and its result ─────────────────────────────────────────────────────

fn call_message(name: &str, arguments: Value, meta: Option<Value>) -> Value {
    let mut params = json!({"name": name, "arguments": arguments});
    if let Some(meta) = meta {
        params["_meta"] = meta;
    }
    json!({"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": params})
}

/// The one text block every reference result carries.
fn text_of(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_else(|| panic!("no text content in {reply}"))
}

/// The text is the envelope itself, not a rendering of it.
fn envelope_of(reply: &Value) -> Value {
    let text = text_of(reply);
    let envelope: Value = serde_json::from_str(text).unwrap_or_else(|e| panic!("{e}: {text:?}"));
    assert_eq!(
        reply["result"]["structuredContent"], envelope,
        "the text and the structured content disagree: {reply}"
    );
    envelope
}

/// The failure vocabulary of every refusal but `invalid_arguments`.
fn assert_call_refusal(reply: &Value, expected: &str) {
    assert!(
        reply["error"].is_null(),
        "a refusal must be a tool result, never a JSON-RPC error: {reply}"
    );
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    assert_eq!(text_of(reply), expected, "{reply}");
}

// ── a successful call ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_call_returns_the_run_envelope_in_text_and_structured_content() {
    let bound = bound(&[kata_manifest()], ExecutionSettings::default(), true).await;
    let (status, content_type, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(
        content_type.starts_with("text/event-stream"),
        "expected SSE framing, got {content_type}: {reply}"
    );
    assert_eq!(reply["id"], 11, "{reply}");

    let envelope = envelope_of(&reply);
    assert_eq!(reply["result"]["isError"], json!(false), "{reply}");
    assert_eq!(envelope["status"], "queued", "{reply}");
    assert_eq!(envelope["result"], Value::Null, "{reply}");
    assert_eq!(envelope["error"], Value::Null, "{reply}");
    assert_eq!(envelope["payload_expired"], json!(false), "{reply}");

    // The envelope's identity is the run the queue stored, a UUIDv7.
    let run_id = envelope["run_id"].as_str().expect("run identity");
    assert_eq!(run_id.len(), 36);
    assert_eq!(&run_id[14..15], "7", "a run identity is UUIDv7: {run_id}");
    let stored: Option<String> = sqlx::query_scalar(
        "SELECT run_id::text FROM public.mcp_runs \
         WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .fetch_optional(&bound.fixture.pool)
    .await
    .expect("the run is durable");
    assert_eq!(stored.as_deref(), Some(run_id), "{reply}");

    // The text is exactly the serialised envelope.
    assert_eq!(
        serde_json::to_string(&envelope).expect("json"),
        text_of(&reply),
        "{reply}"
    );
    bound.fixture.finish().await;
}

#[tokio::test]
async fn the_meta_actor_is_stored_on_the_run() {
    let bound = bound(&[kata_manifest()], ExecutionSettings::default(), true).await;
    let actor = json!({"ai.nonagentic/actor": {"channel": "mcp", "address": "agent-09"}});
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), Some(actor)),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    let envelope = envelope_of(&reply);
    let run_id = envelope["run_id"].as_str().expect("run identity");

    let stored: Option<Value> = sqlx::query_scalar(
        "SELECT actor FROM public.mcp_runs \
         WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .fetch_one(&bound.fixture.pool)
    .await
    .expect("the run is durable");
    assert_eq!(
        stored,
        Some(json!({"channel": "mcp", "address": "agent-09"})),
        "{reply}"
    );
    bound.fixture.finish().await;
}

// ── refusals ─────────────────────────────────────────────────────────────────────────────

/// The fixture manifest whose input schema requires one property.
fn required_manifest() -> ToolManifest {
    let mut value =
        serde_json::to_value(tool_manifest("alpha_tool", TOOL_ALPHA)).expect("manifest json");
    value["input_schema"] = json!({
        "type": "object",
        "properties": {"count": {"type": "integer"}},
        "required": ["count"],
        "additionalProperties": false
    });
    serde_json::from_value(value).expect("required manifest")
}

#[tokio::test]
async fn invalid_arguments_are_a_readable_tool_error() {
    let bound = bound(&[required_manifest()], ExecutionSettings::default(), true).await;
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(reply["error"].is_null(), "{reply}");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    // Paths and keywords only, never an instance value: the caller can fix its own call.
    let problems: Value = serde_json::from_str(text_of(&reply)).expect("problems json");
    assert_eq!(
        problems,
        json!({
            "error": "invalid_arguments",
            "problems": [{"path": "/count", "rule": "required"}]
        }),
        "{reply}"
    );
    // No run was admitted: validation precedes durable acceptance.
    let runs: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_runs")
        .fetch_one(&bound.fixture.pool)
        .await
        .expect("run count");
    assert_eq!(runs, 0, "{reply}");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn an_unknown_tool_is_a_tool_level_denial() {
    let bound = bound(&[kata_manifest()], ExecutionSettings::default(), true).await;
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("missing_tool", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_call_refusal(&reply, "tool_request_denied");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_deployment_without_execution_is_unavailable() {
    let bound = bound(&[kata_manifest()], ExecutionSettings::default(), false).await;
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_call_refusal(&reply, "execution_unavailable");
    bound.fixture.finish().await;
}

/// The full fixture with a toolkit whose selection narrows the tool's aggregate output to one
/// byte: the reference's size check must refuse even an empty envelope.
async fn narrow_output_toolkit(fixture: &Fixture) {
    support::insert_profile_with(fixture, support::PROFILE, "synthetic_profile", LICENCE_ID).await;
    support::seed_service(fixture).await;
    support::seed_operation(fixture).await;
    support::insert_published_tool(fixture, &tool_manifest("alpha_tool", TOOL_ALPHA)).await;
    let mut value = serde_json::to_value(support::toolkit_manifest(&[(TOOL_ALPHA, "alpha_tool")]))
        .expect("toolkit json");
    // `frame_bytes <= output_bytes` is the limits' own rule; both are one byte.
    value["tools"][0]["limits"] = json!({"frame_bytes": 1, "output_bytes": 1});
    let toolkit: ToolkitManifest = serde_json::from_value(value).expect("narrow toolkit");
    let service = fixture.service();
    let operator = support::principal();
    let drafted = service
        .write(&operator, &toolkit, None)
        .await
        .expect("create toolkit");
    service
        .transition(
            &operator,
            &support::uuid7(TOOLKIT_1),
            support::version(1),
            VersionStatus::Published,
            drafted.revision,
        )
        .await
        .expect("publish toolkit");
}

#[tokio::test]
async fn an_envelope_over_the_effective_output_bound_is_refused() {
    let fixture = Fixture::new().await;
    narrow_output_toolkit(&fixture).await;
    let bound = bind(fixture, ExecutionSettings::default(), true).await;
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert_call_refusal(&reply, "tool_request_denied");
    bound.fixture.finish().await;
}

// ── a run that ends badly ────────────────────────────────────────────────────────────────

/// Walk the newest queued run to a failed terminal state, through the guard's transition
/// matrix (`mcp_guard_run`), from a second connection — the worker's own path.
async fn walk_queued_run_to_failed(pool: &PgPool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let run: Option<String> = sqlx::query_scalar(
            "SELECT run_id::text FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND status = 'queued' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(TENANT_A)
        .fetch_optional(pool)
        .await
        .expect("find the queued run");
        if let Some(run) = run {
            for statement in [
                "UPDATE public.mcp_runs SET status = 'starting', started_at = clock_timestamp() \
                 WHERE run_id = $1::uuid",
                "UPDATE public.mcp_runs SET status = 'running' WHERE run_id = $1::uuid",
                "UPDATE public.mcp_runs SET status = 'failed', finished_at = clock_timestamp() \
                 WHERE run_id = $1::uuid",
            ] {
                sqlx::query(statement)
                    .bind(&run)
                    .execute(pool)
                    .await
                    .expect("walk the run");
            }
            return;
        }
        assert!(Instant::now() < deadline, "no queued run appeared");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

#[tokio::test]
async fn a_failed_run_is_a_tool_error_carrying_its_envelope() {
    // The wait polls inline for the synchronous window; the walker finishes inside it.
    let bound = bound(
        &[kata_manifest()],
        ExecutionSettings {
            sync_wait: Duration::from_millis(300),
            ..ExecutionSettings::default()
        },
        true,
    )
    .await;
    let pool = bound.fixture.pool.clone();
    let walker = tokio::spawn(async move { walk_queued_run_to_failed(&pool).await });
    let (status, _, reply) = support::mcp_post(
        &bound.app,
        Some(&bound.token),
        call_message("alpha_tool", json!({}), None),
    )
    .await;
    walker.await.expect("walker");
    assert_eq!(status, StatusCode::OK, "{reply}");
    assert!(reply["error"].is_null(), "{reply}");
    assert_eq!(reply["result"]["isError"], json!(true), "{reply}");
    let envelope = envelope_of(&reply);
    assert_eq!(envelope["status"], "failed", "{reply}");
    bound.fixture.finish().await;
}
