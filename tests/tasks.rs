//! The SEP-2663 tasks extension: the pure projection against the pinned golden fixture, and
//! `tools/call` / `tasks/*` over the real `/mcp` transport with a real Postgres 18.
//!
//! Ported from the reference `src/tasks/{mapping,severity,extension}.py`. The fixture
//! (`tests/fixtures/phase3a/oracle.json`) was generated from the reference itself, so every
//! projection case is compared field for field — the task handle, the status walk, the poll
//! interval and the Python `isoformat()` timestamps included.
//!
//! The transport is the stateless `2026-07-28` path: each request carries
//! `io.modelcontextprotocol/protocolVersion` and `clientCapabilities` in `_meta`, the matching
//! `MCP-Protocol-Version` header, and the SEP-2243 `Mcp-Method` / `Mcp-Name` headers that
//! version requires. Server selection mirrors `tests/http_call.rs`; each test gets its own
//! fresh database.

mod support;

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use chrono::{DateTime, Utc};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use mcp_server_rs::app_with_auth;
use mcp_server_rs::auth::pg_bindings::PgBindingAuthority;
use mcp_server_rs::auth::{
    AuthError, BoxFuture, LicenceAuthority, LicenseIdentity, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, Uuid7};
use mcp_server_rs::config::ExecutionSettings;
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::storage::task_inputs::TaskInputRow;
use mcp_server_rs::tasks::{create_task_result, task_status, task_view};

use support::{Fixture, LICENCE_ID, LICENCE_TOKEN, TENANT_A, TENANT_PLATFORM};

// ── the golden fixture ─────────────────────────────────────────────────────────────────────

/// The pinned reference's own output.
fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/phase3a/oracle.json")).expect("oracle json")
}

/// The instant the fixture cases are read at.
///
/// It is deliberately before `2026-11-14T11:59:59`, the expiry of the `running_open_input`
/// case's second approval: the reference generated that case at its own wall clock, so the
/// approval counted as still open, and the fixture only reproduces under a read instant that
/// is also before it. `lastUpdatedAt` never depends on the read instant.
fn read_at() -> DateTime<Utc> {
    DateTime::parse_from_rfc3339("2026-11-14T11:00:00+00:00")
        .expect("fixture instant")
        .with_timezone(&Utc)
}

fn moment(value: &Value) -> Option<DateTime<Utc>> {
    value.as_str().map(|text| {
        DateTime::parse_from_rfc3339(text)
            .expect("fixture instant")
            .with_timezone(&Utc)
    })
}

fn instant(value: &Value) -> DateTime<Utc> {
    moment(value).expect("fixture instant")
}

fn identity(value: &Value) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(value.as_str().expect("fixture identity")).expect("fixture identity")
}

/// The fixture's `settings` block as the service's settings.
fn settings_of(oracle: &Value) -> ExecutionSettings {
    let settings = &oracle["settings"];
    ExecutionSettings {
        retention_days: settings["execution_retention_days"]
            .as_u64()
            .expect("retention days"),
        task_poll_interval_ms: settings["task_poll_interval_ms"]
            .as_u64()
            .expect("task poll interval"),
        external_poll_seconds: settings["external_poll_seconds"]
            .as_f64()
            .expect("external poll seconds"),
        ..ExecutionSettings::default()
    }
}

/// One run-shaped fixture object as the row the mapping reads.
fn run_row(value: &Value) -> RunRow {
    RunRow {
        run_id: identity(&value["run_id"]),
        tenant_id: identity(&value["tenant_id"]),
        gateway_license_id: identity(&value["gateway_license_id"]),
        owner_tenant_id: identity(&value["owner_tenant_id"]),
        tool_id: identity(&value["tool_id"]),
        binding_id: value["binding_id"]
            .as_str()
            .map(|_| identity(&value["binding_id"])),
        binding_revision: Some(1),
        credential_profile_id: None,
        profile_snapshot: value["profile_snapshot"].clone(),
        tool_version: i32::try_from(value["tool_version"].as_i64().expect("tool version"))
            .expect("tool version"),
        authority: value["authority"].clone(),
        inputs: value["inputs"].clone(),
        input_hash: value["input_hash"].as_str().expect("input hash").to_owned(),
        idempotency_key: value["idempotency_key"].as_str().map(str::to_owned),
        created_by: value["created_by"].clone(),
        status: RunStatus::parse(value["status"].as_str().expect("run status"))
            .expect("run status"),
        created_at: instant(&value["created_at"]),
        queue_deadline: instant(&value["queue_deadline"]),
        started_at: moment(&value["started_at"]),
        finished_at: moment(&value["finished_at"]),
        cancel_requested: value["cancel_requested"].as_bool().expect("cancel flag"),
        result: (!value["result"].is_null()).then(|| value["result"].clone()),
        error: (!value["error"].is_null()).then(|| value["error"].clone()),
        payload_expired_at: moment(&value["payload_expired_at"]),
        mode: value["mode"].as_str().expect("run mode").to_owned(),
        runtime: serde_json::from_value(value["runtime"].clone()).expect("run runtime"),
        external_ref: (!value["external_ref"].is_null()).then(|| value["external_ref"].clone()),
        status_message: value["status_message"].as_str().map(str::to_owned),
        actor: (!value["actor"].is_null()).then(|| value["actor"].clone()),
    }
}

/// One fixture input object as the stored row it stands for.
fn input_row(row: &RunRow, value: &Value) -> TaskInputRow {
    TaskInputRow {
        input_key: value["input_key"].as_str().expect("input key").to_owned(),
        tenant_id: AuthorityId::new(row.tenant_id.to_string()).expect("tenant"),
        run_id: Uuid7::new(row.run_id.to_string()).expect("run"),
        source_ref: value["source_ref"].as_str().unwrap_or_default().to_owned(),
        request: value["request"].clone(),
        state: value["state"].as_str().expect("input state").to_owned(),
        response: (!value["response"].is_null()).then(|| value["response"].clone()),
        actor: (!value["actor"].is_null()).then(|| value["actor"].clone()),
        created_at: instant(&value["created_at"]),
        answered_at: moment(&value["answered_at"]),
        closed_at: moment(&value["closed_at"]),
        expires_at: moment(&value["expires_at"]),
    }
}

fn inputs_of(row: &RunRow, case: &Value) -> Vec<TaskInputRow> {
    case["inputs"]
        .as_array()
        .map(|inputs| inputs.iter().map(|input| input_row(row, input)).collect())
        .unwrap_or_default()
}

fn fr_meta_of(case: &Value) -> Option<&Value> {
    case.get("fr_meta").filter(|block| !block.is_null())
}

#[test]
fn every_task_view_fixture_case_matches_field_for_field() {
    let oracle = oracle();
    let settings = settings_of(&oracle);
    let now = read_at();
    let cases = oracle["task_view"].as_array().expect("task view cases");
    assert_eq!(cases.len(), 7, "the fixture ships seven views");
    for case in cases {
        let row = run_row(&case["row"]);
        let inputs = inputs_of(&row, case);
        let view = task_view(&row, &inputs, &settings, fr_meta_of(case), now);
        assert_eq!(view, case["expected"], "case {}", case["name"]);
    }
}

#[test]
fn every_create_task_result_fixture_case_matches_field_for_field() {
    let oracle = oracle();
    let settings = settings_of(&oracle);
    let cases = oracle["create_task_result"]
        .as_array()
        .expect("task handle cases");
    assert_eq!(cases.len(), 2, "the fixture ships two handles");
    for case in cases {
        let row = run_row(&case["row"]);
        let handle = create_task_result(&row, &settings, fr_meta_of(case));
        assert_eq!(handle, case["expected"], "case {}", case["name"]);
    }
}

#[test]
fn status_follows_the_run_and_never_asks_a_cancelling_run() {
    let oracle = oracle();
    let settings = settings_of(&oracle);
    let now = read_at();
    let base = run_row(&oracle["task_view"][0]["row"]);
    let question = json!({
        "input_key": "k1",
        "state": "open",
        "request": {"method": "elicitation/create", "params": {"message": "approve?"}},
        "created_at": "2026-11-14T12:00:00+00:00",
    });

    // Working while no input is open, whatever the working status is.
    for status in [RunStatus::Queued, RunStatus::Starting, RunStatus::Running] {
        let mut row = base.clone();
        row.status = status;
        assert_eq!(task_status(&row, 0), "working");
        assert_eq!(task_status(&row, 1), "input_required");
    }
    // A pending cancel wins over open inputs: working, and no requests are surfaced.
    let mut cancelling = base.clone();
    cancelling.status = RunStatus::Cancelling;
    let open = input_row(&cancelling, &question);
    assert_eq!(task_status(&cancelling, 1), "working");
    let view = task_view(&cancelling, &[open], &settings, None, now);
    assert_eq!(view["status"], json!("working"));
    assert!(view.get("inputRequests").is_none(), "{view}");

    // An expired approval is not a question any more; an unexpired one is.
    let mut running = base.clone();
    running.status = RunStatus::Running;
    let mut expired = question.clone();
    expired["expires_at"] = json!("2026-11-14T10:59:59+00:00");
    let expired = input_row(&running, &expired);
    let view = task_view(&running, &[expired], &settings, None, now);
    assert_eq!(view["status"], json!("working"));
    assert!(view.get("inputRequests").is_none(), "{view}");
    let open = input_row(&running, &question);
    let view = task_view(&running, &[open], &settings, None, now);
    assert_eq!(view["status"], json!("input_required"));
    assert_eq!(
        view["inputRequests"]["k1"], question["request"],
        "the stored request is served verbatim"
    );

    // Terminal runs: cancelled reports itself, every other ending is a completed task.
    let mut cancelled = base.clone();
    cancelled.status = RunStatus::Cancelled;
    assert_eq!(task_status(&cancelled, 0), "cancelled");
    for status in [
        RunStatus::Succeeded,
        RunStatus::Failed,
        RunStatus::TimedOut,
        RunStatus::Interrupted,
    ] {
        let mut row = base.clone();
        row.status = status;
        assert_eq!(task_status(&row, 0), "completed");
    }
}

#[test]
fn a_kata_run_polls_on_the_task_interval_and_an_external_one_on_its_seconds() {
    let oracle = oracle();
    let settings = settings_of(&oracle);
    let now = read_at();
    let mut row = run_row(&oracle["task_view"][0]["row"]);
    row.status = RunStatus::Running;
    assert_eq!(
        task_view(&row, &[], &settings, None, now)["pollIntervalMs"],
        json!(2_000)
    );
    row.runtime = mcp_server_rs::catalog::models::Runtime::FrProject;
    assert_eq!(
        task_view(&row, &[], &settings, None, now)["pollIntervalMs"],
        json!(5_000)
    );
    // The TTL is the retention window in milliseconds, always present.
    assert_eq!(
        task_view(&row, &[], &settings, None, now)["ttlMs"],
        json!(604_800_000)
    );
}

#[test]
fn timestamps_are_python_isoformat_and_last_updated_is_the_newest_stamp() {
    let oracle = oracle();
    let settings = settings_of(&oracle);
    let now = read_at();
    let mut row = run_row(&oracle["task_view"][0]["row"]);
    row.status = RunStatus::Running;

    // Whole seconds carry no fractional part, exactly like `datetime.isoformat()`.
    let view = task_view(&row, &[], &settings, None, now);
    assert_eq!(view["createdAt"], json!("2026-11-14T12:00:00+00:00"));

    // A sub-second instant keeps six digits.
    row.created_at = DateTime::parse_from_rfc3339("2026-11-14T12:00:00.123456+00:00")
        .expect("instant")
        .with_timezone(&Utc);
    let view = task_view(&row, &[], &settings, None, now);
    assert_eq!(view["createdAt"], json!("2026-11-14T12:00:00.123456+00:00"));

    // An answered input later than every run stamp is the last update.
    let answered = json!({
        "input_key": "k1",
        "state": "answered",
        "request": {"method": "elicitation/create", "params": {}},
        "created_at": "2026-11-14T12:00:01+00:00",
        "answered_at": "2026-11-14T12:00:09+00:00",
    });
    let input = input_row(&row, &answered);
    let view = task_view(&row, &[input], &settings, None, now);
    assert_eq!(view["lastUpdatedAt"], json!("2026-11-14T12:00:09+00:00"));
}

// ── the protocol surface ──────────────────────────────────────────────────────────────────

const PROTOCOL_VERSION: &str = "2026-07-28";
const TASKS_EXTENSION: &str = "io.modelcontextprotocol/tasks";

struct Bound {
    fixture: Fixture,
    app: Router,
    token: String,
}

fn tasks_on() -> ExecutionSettings {
    ExecutionSettings {
        tasks_enabled: true,
        ..ExecutionSettings::default()
    }
}

/// A published Kata tool, a real binding created through the HTTP surface, and the app served
/// with the settings under test.
async fn serve(settings: ExecutionSettings, enabled: bool) -> Bound {
    let fixture = Fixture::new().await;
    support::binding_fixture_with_tools(&fixture, &[support::kata_manifest()]).await;
    let created = support::create_binding(&fixture.app()).await;
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

/// The per-request context every `2026-07-28` request carries; `actor` adds the caller's
/// `ai.nonagentic/actor` entry. The tasks extension is declared, as a client polling a task
/// must declare it.
fn call_meta(actor: bool) -> Value {
    let mut meta = json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {
            "extensions": {"io.modelcontextprotocol/tasks": {}},
        },
    });
    if actor {
        meta["ai.nonagentic/actor"] = json!({"channel": "mcp", "address": "agent-09"});
    }
    meta
}

/// The same context from a client that declared no extensions at all.
fn plain_meta() -> Value {
    json!({
        "io.modelcontextprotocol/protocolVersion": PROTOCOL_VERSION,
        "io.modelcontextprotocol/clientCapabilities": {},
    })
}

/// The SEP-2243 `Mcp-Name` a method carries, if any.
fn header_name(message: &Value) -> Option<String> {
    let method = message["method"].as_str()?;
    let params = message.get("params")?;
    match method {
        "tools/call" => params["name"].as_str().map(str::to_owned),
        "tasks/get" | "tasks/update" | "tasks/cancel" => {
            params["taskId"].as_str().map(str::to_owned)
        }
        _ => None,
    }
}

/// POST one JSON-RPC message the way a `2026-07-28` client does, and return its reply.
async fn post(app: &Router, token: Option<&str>, message: Value) -> Value {
    let method = message["method"].as_str().expect("method").to_owned();
    let mut request = Request::post("/mcp")
        .header("host", "127.0.0.1")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream")
        .header("mcp-protocol-version", PROTOCOL_VERSION);
    if method != "initialize" {
        request = request.header("mcp-method", &method);
        if let Some(name) = header_name(&message) {
            request = request.header("mcp-name", name);
        }
    }
    if let Some(token) = token {
        request = request.header("x-mcp-binding", token);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(&message).expect("json body")))
                .expect("request"),
        )
        .await
        .expect("router");
    assert_eq!(response.status(), StatusCode::OK, "transport status");
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    support::rpc_payload(&String::from_utf8_lossy(&bytes))
}

fn initialize_message() -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {"name": "tasks-test", "version": "1"},
        },
    })
}

fn call_message(meta: Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/call",
        "params": {"name": "alpha_tool", "arguments": {}, "_meta": meta},
    })
}

fn task_message(
    method: &str,
    id: u64,
    task_id: &str,
    extra: Option<(&str, Value)>,
    meta: Value,
) -> Value {
    let mut params = json!({"taskId": task_id, "_meta": meta});
    if let Some((key, value)) = extra {
        params[key] = value;
    }
    json!({"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

async fn task_request(bound: &Bound, message: Value) -> Value {
    post(&bound.app, Some(&bound.token), message).await
}

/// A queued run admitted through `tools/call`, answered as a task handle.
async fn create_task(bound: &Bound) -> String {
    let reply = task_request(bound, call_message(call_meta(true))).await;
    assert_eq!(reply["result"]["resultType"], json!("task"), "{reply}");
    reply["result"]["taskId"]
        .as_str()
        .expect("task identity")
        .to_owned()
}

/// One step of the reference's run transition matrix, asserted to have applied.
async fn transition(pool: &PgPool, run_id: &str, from: &str, to: &str) {
    let changed = sqlx::query(
        "UPDATE public.mcp_runs SET status = $3 \
         WHERE run_id = $1::uuid AND status = $2",
    )
    .bind(run_id)
    .bind(from)
    .bind(to)
    .execute(pool)
    .await
    .expect("run transition")
    .rows_affected();
    assert_eq!(changed, 1, "{from} → {to}");
}

async fn finish_run(pool: &PgPool, run_id: &str, result: Option<Value>) {
    let changed = sqlx::query(
        "UPDATE public.mcp_runs SET status = 'succeeded', result = $2, \
         finished_at = clock_timestamp() WHERE run_id = $1::uuid AND status = 'running'",
    )
    .bind(run_id)
    .bind(result)
    .execute(pool)
    .await
    .expect("run finishes")
    .rows_affected();
    assert_eq!(changed, 1, "running → succeeded");
}

fn assert_task_not_found(reply: &Value) {
    assert_eq!(reply["error"]["code"], json!(-32602), "{reply}");
    assert_eq!(
        reply["error"]["message"],
        json!("task not found"),
        "{reply}"
    );
}

#[tokio::test]
async fn initialize_advertises_the_tasks_extension_only_when_it_is_enabled() {
    let enabled = serve(tasks_on(), true).await;
    let reply = post(&enabled.app, Some(&enabled.token), initialize_message()).await;
    assert_eq!(
        reply["result"]["capabilities"]["extensions"][TASKS_EXTENSION],
        json!({}),
        "{reply}"
    );
    enabled.fixture.finish().await;

    let disabled = serve(ExecutionSettings::default(), true).await;
    let reply = post(&disabled.app, Some(&disabled.token), initialize_message()).await;
    assert!(
        reply["result"]["capabilities"]["extensions"][TASKS_EXTENSION].is_null(),
        "a deployment without tasks must not advertise the extension: {reply}"
    );
    disabled.fixture.finish().await;
}

#[tokio::test]
async fn a_non_terminal_call_is_a_task_handle_only_for_a_client_that_declares_it() {
    let bound = serve(tasks_on(), true).await;

    // Declared: the run is handed back as a task handle, not as an envelope.
    let declared = task_request(&bound, call_message(call_meta(true))).await;
    assert_eq!(
        declared["result"]["resultType"],
        json!("task"),
        "{declared}"
    );
    assert_eq!(declared["result"]["status"], json!("working"), "{declared}");
    assert_eq!(
        declared["result"]["ttlMs"],
        json!(604_800_000),
        "{declared}"
    );
    assert_eq!(
        declared["result"]["pollIntervalMs"],
        json!(2_000),
        "{declared}"
    );
    let task_id = declared["result"]["taskId"].as_str().expect("task id");
    let stored: Option<String> =
        sqlx::query_scalar("SELECT binding_id::text FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(task_id)
            .fetch_optional(&bound.fixture.pool)
            .await
            .expect("the run is durable");
    assert!(
        stored.is_some(),
        "the handle names an admitted run: {declared}"
    );

    // Not declared: the same call is the plain envelope.
    let plain = task_request(&bound, call_message(plain_meta())).await;
    assert_ne!(plain["result"]["resultType"], json!("task"), "{plain}");
    assert_eq!(
        plain["result"]["structuredContent"]["status"],
        json!("queued")
    );
    bound.fixture.finish().await;

    // Tasks off: even a declaring client gets the envelope.
    let off = serve(ExecutionSettings::default(), true).await;
    let reply = task_request(&off, call_message(call_meta(true))).await;
    assert_ne!(reply["result"]["resultType"], json!("task"), "{reply}");
    off.fixture.finish().await;
}

#[tokio::test]
async fn tasks_get_reports_working_and_then_the_completed_result() {
    let bound = serve(tasks_on(), true).await;
    let task_id = create_task(&bound).await;
    let pool = bound.fixture.pool.clone();

    transition(&pool, &task_id, "queued", "starting").await;
    transition(&pool, &task_id, "starting", "running").await;
    let reply = task_request(
        &bound,
        task_message("tasks/get", 3, &task_id, None, call_meta(false)),
    )
    .await;
    assert!(reply["error"].is_null(), "{reply}");
    assert_eq!(reply["result"]["resultType"], json!("complete"), "{reply}");
    assert_eq!(reply["result"]["taskId"], json!(task_id), "{reply}");
    assert_eq!(reply["result"]["status"], json!("working"), "{reply}");
    assert!(reply["result"]["result"].is_null(), "{reply}");

    finish_run(&pool, &task_id, Some(json!({"ok": true}))).await;
    let reply = task_request(
        &bound,
        task_message("tasks/get", 4, &task_id, None, call_meta(false)),
    )
    .await;
    assert_eq!(reply["result"]["status"], json!("completed"), "{reply}");
    let result = &reply["result"]["result"];
    assert_eq!(result["isError"], json!(false), "{reply}");
    assert_eq!(
        result["structuredContent"]["status"],
        json!("succeeded"),
        "{reply}"
    );
    assert_eq!(result["structuredContent"]["result"], json!({"ok": true}));
    let text = result["content"][0]["text"]
        .as_str()
        .expect("envelope text");
    let parsed: Value = serde_json::from_str(text).expect("the text is the envelope");
    assert_eq!(parsed, result["structuredContent"], "{reply}");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn another_bindings_task_and_an_unknown_task_are_both_not_found() {
    let bound = serve(tasks_on(), true).await;
    let task_id = create_task(&bound).await;

    // A second binding of the same tenant never owns the first binding's run.
    let other = support::create_binding(&bound.fixture.app()).await;
    let other_token = other["token"].as_str().expect("binding token");
    let reply = post(
        &bound.app,
        Some(other_token),
        task_message("tasks/get", 5, &task_id, None, call_meta(false)),
    )
    .await;
    assert_task_not_found(&reply);

    // An id that is not a UUID, and one that is but names no run.
    for unknown in ["not-a-uuid", "018f0000-0000-7000-8000-0000000000ff"] {
        let reply = task_request(
            &bound,
            task_message("tasks/get", 6, unknown, None, call_meta(false)),
        )
        .await;
        assert_task_not_found(&reply);
    }
    bound.fixture.finish().await;
}

#[tokio::test]
async fn another_tenants_call_and_an_expired_payload_are_not_found() {
    let bound = serve(tasks_on(), true).await;
    let task_id = create_task(&bound).await;
    let pool = bound.fixture.pool.clone();

    // The same binding id, a caller from another tenant.
    let binding_id: String =
        sqlx::query_scalar("SELECT binding_id::text FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&task_id)
            .fetch_one(&pool)
            .await
            .expect("the run's binding");
    let mut auth = bound.fixture.auth();
    auth.licences = Arc::new(PlatformLicence);
    let app = app_with_auth(
        bound.fixture.state_with_execution(tasks_on(), true),
        auth.with_bindings(Arc::new(support::FixedBindings {
            id: Rfc4122Uuid::parse(&binding_id).expect("binding identity"),
            revision: 1,
        })),
    );
    let reply = post(
        &app,
        Some(&bound.token),
        task_message("tasks/get", 7, &task_id, None, call_meta(false)),
    )
    .await;
    assert_task_not_found(&reply);

    // A run whose payload retention has expired is not served any more. The guard only lets a
    // terminal run expire, and only after its payload is blanked.
    transition(&pool, &task_id, "queued", "failed").await;
    sqlx::query(
        "UPDATE public.mcp_runs SET finished_at = clock_timestamp() \
         WHERE run_id = $1::uuid AND status = 'failed'",
    )
    .bind(&task_id)
    .execute(&pool)
    .await
    .expect("finish the run");
    sqlx::query(
        "UPDATE public.mcp_runs SET inputs = '{}'::jsonb, authority = '{}'::jsonb, \
         profile_snapshot = '{}'::jsonb, payload_expired_at = clock_timestamp() \
         WHERE run_id = $1::uuid",
    )
    .bind(&task_id)
    .execute(&pool)
    .await
    .expect("expire the payload");
    let reply = task_request(
        &bound,
        task_message("tasks/get", 8, &task_id, None, call_meta(false)),
    )
    .await;
    assert_task_not_found(&reply);
    bound.fixture.finish().await;
}

#[tokio::test]
async fn tasks_cancel_requests_cancellation_and_acknowledges() {
    let bound = serve(tasks_on(), true).await;
    let task_id = create_task(&bound).await;
    let reply = task_request(
        &bound,
        task_message("tasks/cancel", 9, &task_id, None, call_meta(false)),
    )
    .await;
    assert!(reply["error"].is_null(), "{reply}");
    assert_eq!(reply["result"]["resultType"], json!("complete"), "{reply}");
    let requested: bool =
        sqlx::query_scalar("SELECT cancel_requested FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&task_id)
            .fetch_one(&bound.fixture.pool)
            .await
            .expect("the run's flag");
    assert!(requested, "cancel is recorded: {reply}");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn tasks_update_answers_an_open_input_and_the_question_disappears() {
    let bound = serve(tasks_on(), true).await;
    let task_id = create_task(&bound).await;
    let pool = bound.fixture.pool.clone();
    transition(&pool, &task_id, "queued", "starting").await;
    transition(&pool, &task_id, "starting", "running").await;
    sqlx::query(
        "INSERT INTO public.mcp_task_inputs(input_key,tenant_id,run_id,source_ref,request,state) \
         VALUES ('k1',$1::uuid,$2::uuid,'approval',$3,'open')",
    )
    .bind(TENANT_A)
    .bind(&task_id)
    .bind(json!({
        "method": "elicitation/create",
        "params": {
            "message": "approve the start?",
            "requestedSchema": {
                "type": "object",
                "required": ["decision"],
                "properties": {"decision": {"type": "string", "enum": ["approved", "rejected"]}},
            },
        },
    }))
    .execute(&pool)
    .await
    .expect("open an approval");

    // The open approval is surfaced as the task's question.
    let reply = task_request(
        &bound,
        task_message("tasks/get", 10, &task_id, None, call_meta(false)),
    )
    .await;
    assert_eq!(
        reply["result"]["status"],
        json!("input_required"),
        "{reply}"
    );
    assert_eq!(
        reply["result"]["inputRequests"]["k1"]["method"],
        json!("elicitation/create"),
        "{reply}"
    );

    // An answer without an actor is refused before anything is stored.
    let responses = json!({"k1": {"action": "accept", "content": {"decision": "approved"}}});
    let reply = task_request(
        &bound,
        task_message(
            "tasks/update",
            11,
            &task_id,
            Some(("inputResponses", responses.clone())),
            call_meta(false),
        ),
    )
    .await;
    assert_eq!(reply["error"]["code"], json!(-32602), "{reply}");
    assert_eq!(
        reply["error"]["message"],
        json!("actor required"),
        "{reply}"
    );

    // With the actor, the answer is recorded and the question is gone.
    let reply = task_request(
        &bound,
        task_message(
            "tasks/update",
            12,
            &task_id,
            Some(("inputResponses", responses)),
            call_meta(true),
        ),
    )
    .await;
    assert!(reply["error"].is_null(), "{reply}");
    assert_eq!(reply["result"]["resultType"], json!("complete"), "{reply}");
    let answered: String =
        sqlx::query_scalar("SELECT state FROM public.mcp_task_inputs WHERE input_key = 'k1'")
            .fetch_one(&pool)
            .await
            .expect("the input's state");
    assert_eq!(answered, "answered");
    let reply = task_request(
        &bound,
        task_message("tasks/get", 13, &task_id, None, call_meta(false)),
    )
    .await;
    assert_eq!(reply["result"]["status"], json!("working"), "{reply}");
    assert!(reply["result"]["inputRequests"].is_null(), "{reply}");
    bound.fixture.finish().await;
}

/// The same licence, a caller from another tenant (`_owned` reads the run under its tenant).
struct PlatformLicence;

impl LicenceAuthority for PlatformLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            if token != LICENCE_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(LicenseIdentity {
                tenant_id: Rfc4122Uuid::parse(TENANT_PLATFORM).expect("platform tenant"),
                license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("licence identity"),
                subject: "svc:test:other-tenant".into(),
                subject_kind: Some(SubjectKind::Tenant),
            })
        })
    }
}
