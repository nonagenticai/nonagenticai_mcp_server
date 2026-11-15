//! fr's inbound channel, `POST /api/channels/fr/events`: the signature first, then the envelope,
//! then its effect.
//!
//! Ported from the reference `src/routers/fr_channel.py`. Every test runs the real router
//! (including the real `/mcp` middleware, which must NOT touch this path) against a real
//! Postgres 18 through [`support::Fixture`], and signs its bodies with the pinned reference's own
//! channel key from the phase 3C oracle — never a key written into source.
//!
//! The channel key is the ORACLE's: `tests/fixtures/phase3c/oracle.json` ships the value the
//! pinned reference used, so it is the only authority for it here.

mod support;

use axum::Router;
use axum::body::Body;
use axum::http::{Request, StatusCode};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::PgPool;
use tower::ServiceExt;

use mcp_server_rs::app_with_channel_secret;
use mcp_server_rs::external::signing::{SIGNATURE_HEADER, TIMESTAMP_HEADER, sign};
use mcp_server_rs::routes::fr_channel::MAX_BODY_BYTES;

use support::{Fixture, LICENCE_ID, TENANT_A, TOOL_ALPHA, binding_fixture};

/// The channel route the reference mounts (`router = APIRouter(prefix="/api/channels/fr")`).
const CHANNEL: &str = "/api/channels/fr/events";

/// A project id and an approval id, the two names the route resolves runs by.
const PROJECT: &str = "018f0000-0000-7000-8000-0000000000cc";
const APPROVAL: &str = "018f0000-0000-7000-8000-0000000000dd";

// ── the harness ─────────────────────────────────────────────────────────────────────────────

/// The reference's own channel key, read from the oracle it produced.
fn secret() -> String {
    let oracle: Value =
        serde_json::from_str(include_str!("fixtures/phase3c/oracle.json")).expect("oracle json");
    oracle["signatures"][0]["secret"]
        .as_str()
        .expect("the oracle's channel secret")
        .to_owned()
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// The real application with an explicit channel key.
fn app(fixture: &Fixture, secret: Option<String>) -> Router {
    app_with_channel_secret(fixture.state(), fixture.auth(), secret)
}

/// One signed POST: the reference's three headers over `<timestamp>.<body>`.
fn signed(body: &str, key: &str, timestamp: i64) -> Request<Body> {
    let mut request = Request::post(CHANNEL);
    for (name, value) in sign(body.as_bytes(), key, timestamp) {
        request = request.header(name, value);
    }
    request.body(Body::from(body.to_owned())).expect("request")
}

/// A POST carrying exactly the headers given (a missing one is the point).
fn with_headers(body: &str, headers: &[(&str, &str)]) -> Request<Body> {
    let mut request = Request::post(CHANNEL);
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    request.body(Body::from(body.to_owned())).expect("request")
}

/// A POST with no channel headers at all.
fn unsigned(body: &str) -> Request<Body> {
    with_headers(body, &[])
}

struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

impl Reply {
    fn json(&self) -> Value {
        serde_json::from_slice(&self.body).expect("json body")
    }
}

async fn send(app: &Router, request: Request<Body>) -> Reply {
    let response = app.clone().oneshot(request).await.expect("router");
    let status = response.status();
    let body = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes()
        .to_vec();
    Reply { status, body }
}

/// The reference's accepted event: an empty 204.
fn assert_no_content(reply: &Reply) {
    assert_eq!(reply.status, StatusCode::NO_CONTENT, "{:?}", reply.body);
    assert!(reply.body.is_empty(), "a 204 carries no body");
}

/// A refusal is `{"error": <code>}` and nothing else — the reference's `JSONResponse`.
fn assert_refused(reply: &Reply, status: StatusCode, code: &str) {
    assert_eq!(reply.status, status, "{:?}", reply.body);
    assert_eq!(reply.json(), json!({ "error": code }));
}

// ── database fixtures ───────────────────────────────────────────────────────────────────────

/// One live run of the given runtime, parked on the given external reference.
async fn seed_run(pool: &PgPool, runtime: &str, external_ref: Option<Value>) -> String {
    sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,\
         mode,status,runtime,external_ref) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}','{}','{}',$4,'{}', \
         clock_timestamp() + interval '1 hour','draft','running',$5,$6) RETURNING run_id::text",
    )
    .bind(TENANT_A)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind("d".repeat(64))
    .bind(runtime)
    .bind(external_ref)
    .fetch_one(pool)
    .await
    .expect("run row")
}

/// The run parked on this approval, as the reference's driver writes it.
async fn seed_start(fixture: &Fixture) -> String {
    seed_run(
        &fixture.pool,
        "fr_project",
        Some(json!({"kind": "fr", "id": APPROVAL})),
    )
    .await
}

async fn input_rows(pool: &PgPool, run: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM public.mcp_task_inputs WHERE run_id = $1::uuid")
        .bind(run)
        .fetch_one(pool)
        .await
        .expect("input rows")
}

async fn activity_count(pool: &PgPool, run: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM public.mcp_run_activity WHERE run_id = $1::uuid")
        .bind(run)
        .fetch_one(pool)
        .await
        .expect("activity rows")
}

async fn external_ref(pool: &PgPool, run: &str) -> Value {
    sqlx::query_scalar::<_, Option<Value>>(
        "SELECT external_ref FROM public.mcp_runs WHERE run_id = $1::uuid",
    )
    .bind(run)
    .fetch_one(pool)
    .await
    .expect("run row")
    .expect("external reference")
}

async fn status_message(pool: &PgPool, run: &str) -> Option<String> {
    sqlx::query_scalar("SELECT status_message FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run)
        .fetch_one(pool)
        .await
        .expect("run row")
}

// ── the accepted event ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_signed_approval_request_opens_one_input_and_records_the_project() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    // The reference correlates by correlation_id first, then project_id, then the approval id.
    // A start approval raised inside a project carries the run AND the project, so the run is
    // found by id and adopts the project id it did not have when it parked.
    let event = json!({
        "type": "approval.requested",
        "approval_id": APPROVAL,
        "correlation_id": run,
        "description": "approve the start?",
        "change_summary": "2 files changed",
        "project_id": PROJECT,
        "expires_at": "2030-01-01T00:00:00Z",
    });
    assert_no_content(&send(&app, signed(&event.to_string(), &key, now())).await);

    // The approval surfaces as the section 5 `elicitation/create` request, open.
    let (source_ref, state, request): (String, String, Value) = sqlx::query_as(
        "SELECT source_ref, state, request FROM public.mcp_task_inputs WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("input row");
    assert_eq!(source_ref, APPROVAL);
    assert_eq!(state, "open");
    assert_eq!(
        request,
        json!({
            "method": "elicitation/create",
            "params": {
                "message": "approve the start?\n\n2 files changed",
                "requestedSchema": {
                    "type": "object",
                    "required": ["decision"],
                    "properties": {
                        "decision": {"type": "string", "enum": ["approved", "rejected"]},
                        "reason": {"type": "string"},
                        "comment": {"type": "string"},
                    },
                },
            },
        })
    );

    // The project id is adopted — the run was started before the project existed — and the start
    // approval it already carried is untouched (stored keys only ever grow).
    let reference = external_ref(&fixture.pool, &run).await;
    assert_eq!(reference["project_id"], json!(PROJECT));
    assert_eq!(reference["id"], json!(APPROVAL));
    assert_eq!(reference["kind"], json!("fr"));

    // One feed row for `tasks/get`.
    let (kind, text, severity, source): (String, String, String, Option<String>) = sqlx::query_as(
        "SELECT kind, text, severity, source_ref FROM public.mcp_run_activity \
         WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("activity row");
    assert_eq!(kind, "approval_requested");
    assert_eq!(text, "approve the start?");
    assert_eq!(severity, "high");
    assert_eq!(source.as_deref(), Some(APPROVAL));

    fixture.finish().await;
}

// ── signature refusals ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_unsigned_or_stale_request_is_refused_and_writes_nothing() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));
    let body = json!({
        "type": "approval.requested",
        "approval_id": APPROVAL,
        "description": "approve the start?",
    })
    .to_string();

    // No headers at all, then each one alone.
    assert_refused(
        &send(&app, unsigned(&body)).await,
        StatusCode::UNAUTHORIZED,
        "invalid_signature",
    );
    let headers = sign(body.as_bytes(), &key, now());
    let signature = headers[SIGNATURE_HEADER].clone();
    let timestamp = headers[TIMESTAMP_HEADER].clone();
    for only in [
        vec![(TIMESTAMP_HEADER, timestamp.as_str())],
        vec![(SIGNATURE_HEADER, signature.as_str())],
    ] {
        assert_refused(
            &send(&app, with_headers(&body, &only)).await,
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
        );
    }

    // A signature over a different body.
    let other = json!({"type": "approval.requested", "approval_id": APPROVAL}).to_string();
    let mut forged = sign(body.as_bytes(), &key, now());
    forged.insert(
        SIGNATURE_HEADER.to_owned(),
        sign(other.as_bytes(), &key, now())[SIGNATURE_HEADER].clone(),
    );
    let pairs: Vec<(&str, &str)> = forged
        .iter()
        .map(|(name, value)| (name.as_str(), value.as_str()))
        .collect();
    assert_refused(
        &send(&app, with_headers(&body, &pairs)).await,
        StatusCode::UNAUTHORIZED,
        "invalid_signature",
    );

    // A signature from outside the 300 s window, in both directions. The exact edge is the
    // signing helper's own test; here the margins are wide enough that no clock tick matters.
    for offset in [-400, 400] {
        assert_refused(
            &send(&app, signed(&body, &key, now() + offset)).await,
            StatusCode::UNAUTHORIZED,
            "invalid_signature",
        );
    }
    assert_eq!(input_rows(&fixture.pool, &run).await, 0);
    assert_eq!(activity_count(&fixture.pool, &run).await, 0);

    // Just inside the window: this is the same body, accepted.
    assert_no_content(&send(&app, signed(&body, &key, now() - 290)).await);
    assert_eq!(input_rows(&fixture.pool, &run).await, 1);

    fixture.finish().await;
}

// ── the other two refusals ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_oversized_body_is_refused_and_the_cap_itself_is_not() {
    let fixture = Fixture::new().await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    let oversized = json!({"type": "message", "text": "a".repeat(MAX_BODY_BYTES)}).to_string();
    assert!(oversized.len() > MAX_BODY_BYTES);
    assert_refused(
        &send(&app, signed(&oversized, &key, now())).await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );

    // A declared length over the cap is refused without reading the body.
    let small = json!({"type": "unknown"}).to_string();
    let mut declared =
        Request::post(CHANNEL).header("content-length", format!("{}", MAX_BODY_BYTES + 1));
    for (name, value) in sign(small.as_bytes(), &key, now()) {
        declared = declared.header(name, value);
    }
    assert_refused(
        &send(
            &app,
            declared.body(Body::from(small.clone())).expect("request"),
        )
        .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "payload_too_large",
    );

    // Exactly at the cap is accepted (and then ignored: the type is not one fr posts).
    let base = json!({"type": "unknown", "pad": ""}).to_string();
    let exact =
        json!({"type": "unknown", "pad": "a".repeat(MAX_BODY_BYTES - base.len())}).to_string();
    assert_eq!(exact.len(), MAX_BODY_BYTES);
    assert_no_content(&send(&app, signed(&exact, &key, now())).await);

    fixture.finish().await;
}

#[tokio::test]
async fn an_unconfigured_channel_is_unavailable() {
    let fixture = Fixture::new().await;
    let key = secret();
    let app = app(&fixture, None);
    let body = json!({"type": "message", "correlation_id": "x"}).to_string();

    // The key is checked before the signature: even a correctly signed body cannot be served.
    assert_refused(
        &send(&app, unsigned(&body)).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "channel_unconfigured",
    );
    assert_refused(
        &send(&app, signed(&body, &key, now())).await,
        StatusCode::SERVICE_UNAVAILABLE,
        "channel_unconfigured",
    );

    fixture.finish().await;
}

// ── duplicates and replay ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_replayed_approval_opens_once_and_a_close_leaves_a_tombstone() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    // Routed by the approval id alone: the event names neither a run nor a project.
    let requested = json!({
        "type": "approval.requested",
        "approval_id": APPROVAL,
        "description": "approve the start?",
    });
    assert_no_content(&send(&app, signed(&requested.to_string(), &key, now())).await);
    assert_no_content(&send(&app, signed(&requested.to_string(), &key, now())).await);
    assert_eq!(
        input_rows(&fixture.pool, &run).await,
        1,
        "one input per (run, source ref), however many times the approval arrives"
    );
    assert_eq!(
        activity_count(&fixture.pool, &run).await,
        1,
        "the feed deduplicates against the newest row, so a replay adds no line"
    );

    // fr closes the approval: every run it was surfaced on, plus the parked start's outcome.
    let closed = json!({
        "type": "approval.closed",
        "approval_id": APPROVAL,
        "final_status": "rejected",
    });
    assert_no_content(&send(&app, signed(&closed.to_string(), &key, now())).await);
    assert_eq!(
        external_ref(&fixture.pool, &run).await["start_outcome"],
        json!("rejected")
    );
    let (state, stamped): (String, bool) = sqlx::query_as(
        "SELECT state, closed_at IS NOT NULL FROM public.mcp_task_inputs WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("input row");
    assert_eq!(state, "closed");
    assert!(stamped, "the close stamps the tombstone");

    // A late replay of the approval cannot reopen it: the tombstone holds.
    assert_no_content(&send(&app, signed(&requested.to_string(), &key, now())).await);
    let state: String =
        sqlx::query_scalar("SELECT state FROM public.mcp_task_inputs WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("input row");
    assert_eq!(state, "closed");

    // The close is a feed line of its own.
    let texts: Vec<String> = sqlx::query_scalar(
        "SELECT text FROM public.mcp_run_activity WHERE run_id = $1::uuid ORDER BY seq",
    )
    .bind(&run)
    .fetch_all(&fixture.pool)
    .await
    .expect("activity rows");
    assert!(
        texts.iter().any(|text| text == "approval closed: rejected"),
        "{texts:?}"
    );

    fixture.finish().await;
}

#[tokio::test]
async fn an_approval_close_without_a_final_status_still_closes_everywhere() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    let closed = json!({"type": "approval.closed", "approval_id": APPROVAL});
    assert_no_content(&send(&app, signed(&closed.to_string(), &key, now())).await);

    // A tombstone even though no input was ever opened.
    let (state, source): (String, String) = sqlx::query_as(
        "SELECT state, source_ref FROM public.mcp_task_inputs WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("input row");
    assert_eq!(state, "closed");
    assert_eq!(source, APPROVAL);

    let reference = external_ref(&fixture.pool, &run).await;
    assert!(
        reference.get("start_outcome").is_none(),
        "no final status means no start outcome: {reference}"
    );
    let text: String =
        sqlx::query_scalar("SELECT text FROM public.mcp_run_activity WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("activity row");
    assert_eq!(text, "approval closed");

    fixture.finish().await;
}

// ── the ignored branches ──────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_approval_without_an_id_or_already_expired_is_acknowledged_and_dropped() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    let no_id = json!({"type": "approval.requested", "description": "approve?"});
    assert_no_content(&send(&app, signed(&no_id.to_string(), &key, now())).await);

    let expired = json!({
        "type": "approval.requested",
        "approval_id": APPROVAL,
        "description": "approve?",
        "expires_at": "2020-01-01T00:00:00+00:00",
    });
    assert_no_content(&send(&app, signed(&expired.to_string(), &key, now())).await);

    assert_eq!(input_rows(&fixture.pool, &run).await, 0);
    assert_eq!(activity_count(&fixture.pool, &run).await, 0);

    // An unparsable `expires_at` is "no expiry" (`_expires_at` -> None), so the input opens and
    // carries none.
    let unparsable = json!({
        "type": "approval.requested",
        "approval_id": APPROVAL,
        "description": "approve?",
        "expires_at": "soon",
    });
    assert_no_content(&send(&app, signed(&unparsable.to_string(), &key, now())).await);
    let open_ended: bool = sqlx::query_scalar(
        "SELECT expires_at IS NULL FROM public.mcp_task_inputs WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("input row");
    assert!(open_ended, "an unparsable expiry is no expiry");

    fixture.finish().await;
}

#[tokio::test]
async fn the_envelope_is_validated_before_any_database_work() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_start(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    for body in [
        "",
        "not json at all",
        "[]",
        "5",
        r#"{"type": 5}"#,
        r#"{"type": "unknown"}"#,
        r#"{"no": "type"}"#,
    ] {
        assert_no_content(&send(&app, signed(body, &key, now())).await);
    }
    // Bytes that are not UTF-8 are the reference's `UnicodeDecodeError` — a `ValueError` too.
    let raw: &[u8] = &[0xff, 0xfe, 0x00];
    let mut request = Request::post(CHANNEL);
    for (name, value) in sign(raw, &key, now()) {
        request = request.header(name, value);
    }
    let reply = send(
        &app,
        request.body(Body::from(raw.to_vec())).expect("request"),
    )
    .await;
    assert_no_content(&reply);

    assert_eq!(input_rows(&fixture.pool, &run).await, 0);
    assert_eq!(activity_count(&fixture.pool, &run).await, 0);

    fixture.finish().await;
}

// ── messages ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_message_routes_by_its_correlation_and_applies_its_kind() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    // Our own poll echoed back: fr replays "<run>:<poll>" and it is dropped before any query.
    let echo = json!({
        "type": "message",
        "correlation_id": "018f0000-0000-7000-8000-00000000aaaa:poll",
        "kind": "text",
        "text": "ignored",
    });
    assert_no_content(&send(&app, signed(&echo.to_string(), &key, now())).await);

    // An unknown run: acknowledged, nothing written.
    let unknown = json!({
        "type": "message",
        "correlation_id": "018f0000-0000-7000-8000-00000000ffff",
        "kind": "text",
        "text": "nowhere",
    });
    assert_no_content(&send(&app, signed(&unknown.to_string(), &key, now())).await);

    // `approval-request`: the start parked an approval on this run.
    let run = seed_start(&fixture).await;
    let parked = json!({
        "type": "message",
        "correlation_id": run,
        "kind": "approval-request",
        "meta": {"approvalId": APPROVAL},
        "text": "approve the start?",
    });
    assert_no_content(&send(&app, signed(&parked.to_string(), &key, now())).await);
    let (state, request): (String, Value) =
        sqlx::query_as("SELECT state, request FROM public.mcp_task_inputs WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("input row");
    assert_eq!(state, "open");
    assert_eq!(request["params"]["message"], json!("approve the start?"));

    // `action-result` approved: the project id fr created.
    let approved = seed_start(&fixture).await;
    let result = json!({
        "type": "message",
        "correlation_id": approved,
        "kind": "action-result",
        "meta": {
            "actionName": "projects.create",
            "outcome": "approved",
            "result": {"project_id": PROJECT},
        },
    });
    assert_no_content(&send(&app, signed(&result.to_string(), &key, now())).await);
    assert_eq!(
        external_ref(&fixture.pool, &approved).await["project_id"],
        json!(PROJECT)
    );

    // `action-result` rejected, and `action-error`: the start ends without a project.
    let rejected = seed_start(&fixture).await;
    let refused = json!({
        "type": "message",
        "correlation_id": rejected,
        "kind": "action-result",
        "meta": {"actionName": "projects.create", "outcome": "rejected"},
    });
    assert_no_content(&send(&app, signed(&refused.to_string(), &key, now())).await);
    assert_eq!(
        external_ref(&fixture.pool, &rejected).await["start_outcome"],
        json!("rejected")
    );

    let errored = seed_start(&fixture).await;
    let error = json!({
        "type": "message",
        "correlation_id": errored,
        "kind": "action-error",
        "meta": {"actionName": "projects.create"},
    });
    assert_no_content(&send(&app, signed(&error.to_string(), &key, now())).await);
    assert_eq!(
        external_ref(&fixture.pool, &errored).await["start_outcome"],
        json!("failed")
    );

    // `text` and `report`: the run's own progress line, capped at the status-message column.
    let chatting = seed_start(&fixture).await;
    let phase = json!({
        "type": "message",
        "correlation_id": chatting,
        "kind": "text",
        "text": "building the site",
    });
    assert_no_content(&send(&app, signed(&phase.to_string(), &key, now())).await);
    assert_eq!(
        status_message(&fixture.pool, &chatting).await.as_deref(),
        Some("building the site")
    );

    let long = "x".repeat(600);
    let report = json!({
        "type": "message",
        "correlation_id": chatting,
        "kind": "report",
        "text": long,
    });
    assert_no_content(&send(&app, signed(&report.to_string(), &key, now())).await);
    let message = status_message(&fixture.pool, &chatting)
        .await
        .expect("status message");
    assert_eq!(message.chars().count(), 512);

    fixture.finish().await;
}

#[tokio::test]
async fn a_message_for_a_kata_run_is_ignored() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    // `runtime <> 'kata_python'` is part of every live-run read: the channel never answers for
    // a tool execution.
    let run = seed_run(&fixture.pool, "kata_python", None).await;
    let key = secret();
    let app = app(&fixture, Some(key.clone()));

    let reply = json!({
        "type": "message",
        "correlation_id": run,
        "kind": "text",
        "text": "not for you",
    });
    assert_no_content(&send(&app, signed(&reply.to_string(), &key, now())).await);
    assert!(status_message(&fixture.pool, &run).await.is_none());

    fixture.finish().await;
}

// ── mounting ──────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_route_is_signature_authenticated_and_outside_the_mcp_middleware() {
    let fixture = Fixture::new().await;
    let app = app(&fixture, Some(secret()));

    // The `/mcp` surface still demands its licence and binding.
    let mcp = send(
        &app,
        Request::post("/mcp/runs")
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(mcp.status, StatusCode::UNAUTHORIZED);

    // The channel route answers with its OWN 401 — the signature refusal, not the middleware's.
    // It is mounted outside `/mcp`, which is the only prefix `auth::protect` covers.
    assert_refused(
        &send(&app, unsigned("{}")).await,
        StatusCode::UNAUTHORIZED,
        "invalid_signature",
    );

    fixture.finish().await;
}

#[test]
fn the_openapi_document_declares_the_channel_operation() {
    let spec = serde_json::to_value(mcp_server_rs::openapi()).expect("openapi json");
    let operation = &spec["paths"][CHANNEL]["post"];
    assert!(operation.is_object(), "{spec:#}");
    assert_eq!(operation["tags"], json!(["channel"]));
    assert!(
        operation.get("requestBody").is_none(),
        "the reference reads the raw body, so it declares none"
    );
    assert_eq!(
        operation["responses"]["200"]["content"]["application/json"]["schema"],
        json!({"$ref": "#/components/schemas/AnyJson"}),
        "the reference declares the empty schema"
    );
    assert!(
        spec["components"]["schemas"]["AnyJson"].is_object(),
        "every schema the document references is defined in it"
    );
    assert!(
        spec["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag["name"] == json!("channel")),
        "the channel tag is declared"
    );
}
