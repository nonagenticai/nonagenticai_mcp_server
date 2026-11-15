//! The fr project and one-shot command adapters: the pure projections against the pinned
//! oracle fixture, and the wire behaviour against a local axum server. No database.
//!
//! The fixture (`tests/fixtures/phase3c/oracle.json`) was generated from the reference itself,
//! so signatures, decisions, sanitised codes, project/close views and the four `fr_start` wire
//! cases are compared field for field.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::post;
use axum::{Json, Router};
use chrono::{DateTime, Utc};
use serde_json::{Value, json};

use mcp_server_rs::auth::Rfc4122Uuid;
use mcp_server_rs::catalog::ids::{AuthorityId, Uuid7};
use mcp_server_rs::config::ExternalDriverSettings;
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::external::fr::{
    FrAdapter, FrCommandAdapter, FrSettings, close_view, decision_text, project_view, sanitize_code,
};
use mcp_server_rs::external::signing::{SIGNATURE_HEADER, TIMESTAMP_HEADER, sign, verify};
use mcp_server_rs::external::{AnswerForwarder, ExternalAdapter, ExternalState, ExternalStatus};
use mcp_server_rs::storage::task_inputs::TaskInputRow;
use mcp_server_rs::worker::row::WorkerRow;

const SECRET: &str = "synthetic-channel-secret";
const TENANT: &str = "10000000-0000-7000-8000-000000000001";
const OTHER_TENANT: &str = "10000000-0000-7000-8000-000000000002";
const RUN: &str = "018f0000-0000-7000-8000-00000000aaaa";
const PROJECT: &str = "018f0000-0000-7000-8000-0000000000cc";
const APPROVAL: &str = "018f0000-0000-7000-8000-0000000000dd";
const JOB: &str = "018f0000-0000-7000-8000-0000000000bb";
const LICENCE: &str = "10000000-0000-7000-8000-0000000c0001";
const OWNER: &str = "10000000-0000-7000-8000-000000000003";
const TOOL: &str = "018f0000-0000-7000-8000-0000000000ee";

// ── the golden fixture ─────────────────────────────────────────────────────────────────────

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/phase3c/oracle.json")).expect("oracle json")
}

fn named<'a>(cases: &'a Value, name: &str) -> &'a Value {
    cases
        .as_array()
        .expect("fixture cases")
        .iter()
        .find(|entry| entry["name"].as_str() == Some(name))
        .unwrap_or_else(|| panic!("fixture case {name}"))
}

// ── rows the adapters read ─────────────────────────────────────────────────────────────────

fn instant(text: &str) -> DateTime<Utc> {
    DateTime::parse_from_rfc3339(text)
        .expect("instant")
        .with_timezone(&Utc)
}

fn identity(text: &str) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(text).expect("identity")
}

/// The authority snapshot: the manifest is a JSON string, as the reference stores it.
fn authority(target: Value) -> Value {
    json!({
        "manifest": serde_json::to_string(&json!({ "target": target })).expect("manifest json"),
        "effective": "{}",
        "context": "{}",
    })
}

fn project_authority() -> Value {
    authority(json!({ "project_type": "it" }))
}

fn actor(address: &str, job: Option<&str>) -> Value {
    let mut map = serde_json::Map::new();
    map.insert("channel".to_owned(), json!("mcp"));
    map.insert("address".to_owned(), json!(address));
    if let Some(job) = job {
        map.insert("job".to_owned(), json!(job));
    }
    Value::Object(map)
}

fn agent() -> Value {
    actor(&format!("agent:{TENANT}"), Some(JOB))
}

fn worker_row(
    run_id: &str,
    tenant: &str,
    inputs: Value,
    actor: Option<Value>,
    authority: Value,
    external_ref: Option<Value>,
    status: RunStatus,
) -> WorkerRow {
    WorkerRow {
        run: RunRow {
            run_id: identity(run_id),
            tenant_id: identity(tenant),
            gateway_license_id: identity(LICENCE),
            owner_tenant_id: identity(OWNER),
            tool_id: identity(TOOL),
            binding_id: None,
            binding_revision: None,
            credential_profile_id: None,
            profile_snapshot: json!({}),
            tool_version: 1,
            authority,
            inputs,
            input_hash: "0".repeat(64),
            idempotency_key: None,
            created_by: json!({ "subject": "test", "license_id": LICENCE }),
            status,
            created_at: instant("2026-11-15T00:00:00+00:00"),
            queue_deadline: instant("2026-11-15T00:05:00+00:00"),
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            result: None,
            error: None,
            payload_expired_at: None,
            mode: "bound".to_owned(),
            runtime: serde_json::from_value(json!("fr_project")).expect("runtime"),
            external_ref,
            status_message: None,
            actor,
        },
        worker_id: None,
        fence: 1,
        lease_until: None,
        heartbeat_at: None,
        start_deadline: None,
        deadline: None,
        pod_name: None,
        pod_uid: None,
        api_calls: 0,
    }
}

fn project_run(external_ref: Option<Value>, status: RunStatus) -> WorkerRow {
    worker_row(
        RUN,
        TENANT,
        json!({}),
        Some(agent()),
        project_authority(),
        external_ref,
        status,
    )
}

fn input_row(
    run: &WorkerRow,
    source_ref: &str,
    actor: Option<Value>,
    response: Option<Value>,
) -> TaskInputRow {
    TaskInputRow {
        input_key: "input-1".to_owned(),
        tenant_id: AuthorityId::new(run.run.tenant_id.to_string()).expect("tenant"),
        run_id: Uuid7::new(run.run.run_id.to_string()).expect("run"),
        source_ref: source_ref.to_owned(),
        request: json!({}),
        state: "answered".to_owned(),
        response,
        actor,
        created_at: instant("2026-11-15T00:00:00+00:00"),
        answered_at: None,
        closed_at: None,
        expires_at: None,
    }
}

// ── the local fr backend ──────────────────────────────────────────────────────────────────

#[derive(Clone, Debug)]
struct Captured {
    body: Vec<u8>,
    headers: BTreeMap<String, String>,
}

#[derive(Clone)]
struct Shared {
    requests: Arc<Mutex<Vec<Captured>>>,
    responses: Arc<Mutex<VecDeque<(StatusCode, Value)>>>,
}

async fn inbound(
    State(shared): State<Shared>,
    headers: HeaderMap,
    body: Bytes,
) -> (StatusCode, Json<Value>) {
    let captured = Captured {
        body: body.to_vec(),
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect(),
    };
    shared.requests.lock().expect("requests").push(captured);
    let (status, body) = shared
        .responses
        .lock()
        .expect("responses")
        .pop_front()
        .unwrap_or((StatusCode::OK, json!({ "status": "result" })));
    (status, Json(body))
}

struct TestServer {
    base: String,
    shared: Shared,
}

impl TestServer {
    async fn start(responses: Vec<(StatusCode, Value)>) -> Self {
        let shared = Shared {
            requests: Arc::new(Mutex::new(Vec::new())),
            responses: Arc::new(Mutex::new(responses.into())),
        };
        let app = Router::new()
            .route("/api/webhooks/mcp/incoming", post(inbound))
            .with_state(shared.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("listener");
        let base = format!("http://{}", listener.local_addr().expect("address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Self { base, shared }
    }

    fn settings(&self) -> FrSettings {
        FrSettings {
            base_url: Some(self.base.clone()),
            channel_secret: Some(SECRET.to_owned()),
        }
    }

    fn requests(&self) -> Vec<Captured> {
        self.shared.requests.lock().expect("requests").clone()
    }

    fn envelope(&self, index: usize) -> Value {
        serde_json::from_slice(&self.requests()[index].body).expect("envelope json")
    }
}

fn settings(base: &str) -> FrSettings {
    FrSettings {
        base_url: Some(base.to_owned()),
        channel_secret: Some(SECRET.to_owned()),
    }
}

// ── pure rows: signatures, decisions, codes, views ───────────────────────────────────────

#[test]
fn signature_matches_the_oracle() {
    let fixture = oracle();
    for entry in fixture["signatures"].as_array().expect("signature cases") {
        let name = entry["name"].as_str().expect("name");
        let body = entry["body"].as_str().expect("body").as_bytes();
        let secret = entry["secret"].as_str().expect("secret");
        let now = entry["now"].as_i64().expect("now");
        let headers = sign(body, secret, now);
        assert_eq!(
            headers.get(SIGNATURE_HEADER).map(String::as_str),
            entry["headers"]["X-Channel-Signature"].as_str(),
            "{name}"
        );
        assert_eq!(
            headers.get(TIMESTAMP_HEADER).map(String::as_str),
            entry["headers"]["X-Channel-Timestamp"].as_str(),
            "{name}"
        );
        let idempotency = headers.get("Idempotency-Key").expect("idempotency");
        assert_eq!(
            uuid::Uuid::parse_str(idempotency)
                .expect("uuid")
                .get_version_num(),
            4,
            "{name}"
        );
        assert!(verify(body, &headers, secret, now), "{name}");
        assert!(verify(body, &headers, secret, now + 300), "{name}");
        assert!(!verify(body, &headers, secret, now + 301), "{name}");
        assert!(!verify(body, &headers, secret, now - 301), "{name}");
    }
}

#[test]
fn verify_is_total_over_malformed_input() {
    let body = b"{}";
    let now = 1_000_i64;
    let good = sign(body, SECRET, now);
    assert!(verify(body, &good, SECRET, now));

    let lowered: BTreeMap<String, String> = good
        .iter()
        .map(|(name, value)| (name.to_lowercase(), value.clone()))
        .collect();
    assert!(
        verify(body, &lowered, SECRET, now),
        "header lookup is lowercase"
    );

    assert!(!verify(body, &good, "another-secret", now));
    assert!(!verify(b"{ }", &good, SECRET, now));

    let mut missing_signature = good.clone();
    missing_signature.remove(SIGNATURE_HEADER);
    assert!(!verify(body, &missing_signature, SECRET, now));

    let mut missing_timestamp = good.clone();
    missing_timestamp.remove(TIMESTAMP_HEADER);
    assert!(!verify(body, &missing_timestamp, SECRET, now));

    let mut wrong_signature = good.clone();
    wrong_signature.insert(SIGNATURE_HEADER.to_owned(), "sha256=00".to_owned());
    assert!(!verify(body, &wrong_signature, SECRET, now));

    for timestamp in [
        String::new(),
        "12x".to_owned(),
        "+1000".to_owned(),
        " 1000".to_owned(),
        "1 000".to_owned(),
        "\u{0661}\u{0660}\u{0660}\u{0660}".to_owned(),
        "9".repeat(200),
    ] {
        let mut headers = good.clone();
        headers.insert(TIMESTAMP_HEADER.to_owned(), timestamp.clone());
        assert!(
            !verify(body, &headers, SECRET, now),
            "timestamp {timestamp:?}"
        );
    }
}

#[test]
fn projections_match_the_oracle() {
    let fixture = oracle();

    for entry in fixture["sanitize_code"].as_array().expect("sanitize cases") {
        assert_eq!(
            sanitize_code(
                &entry["value"],
                entry["default"].as_str().unwrap_or("external_start_failed")
            ),
            entry["code"].as_str().expect("code"),
            "{}",
            entry["name"]
        );
    }

    for entry in fixture["decision_text"].as_array().expect("decision cases") {
        assert_eq!(
            decision_text(
                entry["approval_id"].as_str().expect("approval id"),
                &entry["content"]
            ),
            entry["text"].as_str().map(str::to_owned),
            "{}",
            entry["name"]
        );
    }

    for entry in fixture["project_views"].as_array().expect("project views") {
        assert_eq!(
            project_view(&entry["project"]),
            entry["view"],
            "{}",
            entry["name"]
        );
    }

    let closed = &fixture["close_view"];
    assert_eq!(
        close_view(closed),
        *closed,
        "every present field is kept, the closure fields included"
    );
}

// ── the wire: fr_start cases ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn fr_start_matches_the_oracle_wire_and_outcome() {
    let fixture = oracle();
    for entry in fixture["fr_start"].as_array().expect("fr_start cases") {
        let name = entry["name"].as_str().expect("name");
        let expected_content = entry["request"]["content"].as_str().expect("content");
        let expected_body: Value = serde_json::from_str(expected_content).expect("envelope");
        let run_id = expected_body["correlation_id"]
            .as_str()
            .expect("correlation id");
        let address = expected_body["address"].as_str().expect("address");
        let tenant = address.strip_prefix("agent:").unwrap_or(TENANT);
        let job = expected_body.get("job").and_then(Value::as_str);
        let text = expected_body["text"].as_str().expect("text");

        let (command, inputs) = if let Some(payload) = text.strip_prefix("projects.create ") {
            let payload: Value = serde_json::from_str(payload).expect("create payload");
            (None, payload)
        } else {
            let (command, payload) = text.split_once(' ').expect("command text");
            let payload: Value = serde_json::from_str(payload).expect("command payload");
            (Some(command.to_owned()), json!({ "id": payload["id"] }))
        };

        let expected = &entry["outcome"];
        let response = match expected.get("ref") {
            Some(reference) => {
                if reference["kind"].as_str() == Some("fr_command") {
                    let project = if command.as_deref() == Some("projects.close") {
                        fixture["close_view"].clone()
                    } else {
                        named(&fixture["project_views"], "small")["project"].clone()
                    };
                    (
                        StatusCode::OK,
                        json!({ "status": "result", "result": project }),
                    )
                } else if reference["project_id"].is_null() {
                    (
                        StatusCode::OK,
                        json!({
                            "status": "pending-approval",
                            "approvalId": reference["id"].clone(),
                        }),
                    )
                } else {
                    (
                        StatusCode::OK,
                        json!({ "status": "result", "result": { "project_id": reference["id"].clone() } }),
                    )
                }
            }
            None => {
                let code = expected["code"].as_str().expect("code");
                if code == "fr_unavailable" {
                    (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        json!({ "status": "error" }),
                    )
                } else {
                    (
                        StatusCode::OK,
                        json!({ "status": "no-action", "code": code }),
                    )
                }
            }
        };

        let server = TestServer::start(vec![response]).await;
        let client = reqwest::Client::new();
        let row = if let Some(command) = &command {
            worker_row(
                run_id,
                tenant,
                inputs,
                Some(actor(address, job)),
                authority(json!({ "command": command })),
                None,
                RunStatus::Starting,
            )
        } else {
            worker_row(
                run_id,
                tenant,
                inputs,
                Some(actor(address, job)),
                project_authority(),
                None,
                RunStatus::Starting,
            )
        };
        let started = if command.is_some() {
            FrCommandAdapter::new(client, server.settings())
                .start(&row)
                .await
        } else {
            FrAdapter::new(client, server.settings()).start(&row).await
        };

        // The outgoing message is the oracle's, byte for byte.
        let requests = server.requests();
        assert_eq!(requests.len(), 1, "{name}");
        assert_eq!(
            std::str::from_utf8(&requests[0].body).expect("utf8"),
            expected_content,
            "{name}"
        );
        let headers = &requests[0].headers;
        assert_eq!(
            headers.get("content-type").map(String::as_str),
            Some("application/json"),
            "{name}"
        );
        let timestamp: i64 = headers
            .get("x-channel-timestamp")
            .expect("timestamp")
            .parse()
            .expect("timestamp digits");
        assert!(
            verify(&requests[0].body, headers, SECRET, timestamp),
            "{name}"
        );
        let signed = sign(&requests[0].body, SECRET, timestamp);
        assert_eq!(
            headers.get("x-channel-signature"),
            signed.get(SIGNATURE_HEADER),
            "{name}"
        );
        assert!(
            uuid::Uuid::parse_str(headers.get("idempotency-key").expect("idempotency")).is_ok(),
            "{name}"
        );

        match expected.get("ref") {
            Some(expected_ref) => {
                let reference = started.expect("start succeeds");
                assert_eq!(
                    reference.kind.as_str(),
                    expected_ref["kind"].as_str().expect("kind"),
                    "{name}"
                );
                assert_eq!(
                    reference.id,
                    expected_ref["id"].as_str().expect("id"),
                    "{name}"
                );
                assert_eq!(
                    reference.project_id.as_deref(),
                    expected_ref["project_id"].as_str(),
                    "{name}"
                );
                let result = if expected_ref["result"].is_null() {
                    None
                } else {
                    Some(expected_ref["result"].clone())
                };
                assert_eq!(reference.result, result, "{name}");
            }
            None => {
                let error = started.expect_err("start is refused");
                assert_eq!(
                    error.code,
                    expected["code"].as_str().expect("code"),
                    "{name}"
                );
            }
        }
    }
}

// ── the wire: polling, cancelling, forwarding, commands ─────────────────────────────────

#[tokio::test]
async fn poll_maps_the_project_state() {
    let fixture = oracle();
    let closed = named(&fixture["project_views"], "closed");
    let server = TestServer::start(vec![
        (
            StatusCode::OK,
            json!({ "status": "result", "result": closed["project"].clone() }),
        ),
        (
            StatusCode::OK,
            json!({ "status": "result", "result": { "id": PROJECT, "status": "cancelled" } }),
        ),
        (
            StatusCode::OK,
            json!({ "status": "result", "result": { "id": PROJECT, "status": "failed" } }),
        ),
        (
            StatusCode::OK,
            json!({ "status": "result", "result": { "id": PROJECT, "status": "running", "phase": "build" } }),
        ),
    ])
    .await;
    let adapter = FrAdapter::new(reqwest::Client::new(), server.settings());
    let row = project_run(
        Some(json!({ "kind": "fr", "id": PROJECT, "project_id": PROJECT })),
        RunStatus::Running,
    );

    let delivered = adapter.poll(&row).await.expect("delivered");
    assert_eq!(
        delivered,
        ExternalState::succeeded(Some(closed["view"].clone()))
    );
    assert_eq!(
        adapter.poll(&row).await.expect("cancelled"),
        ExternalState::cancelled()
    );
    assert_eq!(
        adapter.poll(&row).await.expect("failed"),
        ExternalState::failed("project_failed")
    );
    let running = adapter.poll(&row).await.expect("running");
    assert_eq!(running.status, ExternalStatus::Running);
    assert_eq!(running.message.as_deref(), Some("build"));

    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    let envelope = server.envelope(0);
    assert_eq!(
        envelope["text"],
        format!("projects.get {{\"id\":\"{PROJECT}\"}}")
    );
    assert_eq!(envelope["correlation_id"], format!("{RUN}:poll"));
}

#[tokio::test]
async fn poll_reads_the_recorded_start_outcome() {
    let adapter = FrAdapter::new(reqwest::Client::new(), settings("http://127.0.0.1:1"));
    let outcomes = [
        ("rejected", ExternalState::cancelled()),
        ("voided", ExternalState::cancelled()),
        ("expired", ExternalState::failed("project_start_expired")),
        ("failed", ExternalState::failed("project_start_failed")),
        (
            "pending",
            ExternalState::running_with("waiting for the project start to be approved"),
        ),
    ];
    for (outcome, expected) in outcomes {
        let row = project_run(
            Some(json!({ "kind": "fr", "id": APPROVAL, "start_outcome": outcome })),
            RunStatus::Running,
        );
        assert_eq!(
            adapter.poll(&row).await.expect("poll"),
            expected,
            "{outcome}"
        );
    }

    let cancelling = project_run(
        Some(json!({ "kind": "fr", "id": APPROVAL })),
        RunStatus::Cancelling,
    );
    assert_eq!(
        adapter.poll(&cancelling).await.expect("cancelling"),
        ExternalState::cancelled()
    );
}

#[tokio::test]
async fn cancel_withdraws_only_a_pending_start() {
    let server = TestServer::start(vec![
        (StatusCode::OK, json!({ "status": "result" })),
        (
            StatusCode::OK,
            json!({ "status": "error", "code": "fr_nope" }),
        ),
    ])
    .await;
    let adapter = FrAdapter::new(reqwest::Client::new(), server.settings());
    let pending = project_run(
        Some(json!({ "kind": "fr", "id": APPROVAL })),
        RunStatus::Cancelling,
    );

    adapter.cancel(&pending).await.expect("withdraw");
    assert_eq!(server.requests().len(), 1);
    let envelope = server.envelope(0);
    assert_eq!(
        envelope["text"],
        format!("reject {APPROVAL} cancelled by the client")
    );
    assert_eq!(envelope["correlation_id"], format!("{RUN}:cancel"));

    // fr's refusal is logged as a code and swallowed.
    adapter
        .cancel(&pending)
        .await
        .expect("refusal is swallowed");
    assert_eq!(server.requests().len(), 2);

    // A project that already exists is not withdrawn.
    let running = project_run(
        Some(json!({ "kind": "fr", "id": APPROVAL, "project_id": PROJECT })),
        RunStatus::Cancelling,
    );
    adapter.cancel(&running).await.expect("no withdrawal");
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn forward_relays_a_human_decision() {
    let fixture = oracle();
    let approved = named(&fixture["decision_text"], "approve_with_comment");
    let server = TestServer::start(vec![
        (StatusCode::OK, json!({ "status": "result" })),
        (
            StatusCode::OK,
            json!({ "status": "error", "code": "fr_nope" }),
        ),
    ])
    .await;
    let adapter = FrAdapter::new(reqwest::Client::new(), server.settings());
    let run = project_run(
        Some(json!({ "kind": "fr", "id": APPROVAL })),
        RunStatus::Running,
    );
    let item = input_row(
        &run,
        approved["approval_id"].as_str().expect("approval id"),
        Some(agent()),
        Some(json!({ "action": "accept", "content": approved["content"] })),
    );

    assert_eq!(adapter.forward(&run, &item).await.expect("forward"), None);
    let envelope = server.envelope(0);
    assert_eq!(envelope["text"].as_str(), approved["text"].as_str());
    assert_eq!(
        envelope["correlation_id"],
        format!("{RUN}:{}", item.input_key)
    );

    // fr's answered refusal is shown to the client as its code.
    assert_eq!(
        adapter.forward(&run, &item).await.expect("refusal"),
        Some("fr_nope".to_owned())
    );

    // Another tenant's agent member may not speak for this run.
    let mut foreign = item.clone();
    foreign.actor = Some(actor(&format!("agent:{OTHER_TENANT}"), None));
    assert_eq!(
        adapter.forward(&run, &foreign).await.expect("tenant"),
        Some("actor_tenant_mismatch".to_owned())
    );
    assert_eq!(server.requests().len(), 2);

    // A declined answer sends nothing: the approval stays open in fr's other channels.
    let mut declined = item.clone();
    declined.response = Some(json!({ "action": "decline" }));
    assert_eq!(
        adapter.forward(&run, &declined).await.expect("decline"),
        None
    );
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn command_start_checks_the_catalog_target() {
    let adapter = FrCommandAdapter::new(reqwest::Client::new(), settings("http://127.0.0.1:1"));
    let run = |inputs: Value, target: Value, actor: Option<Value>| {
        worker_row(
            RUN,
            TENANT,
            inputs,
            actor,
            authority(target),
            None,
            RunStatus::Starting,
        )
    };

    let unsupported = run(
        json!({ "id": PROJECT }),
        json!({ "command": "projects.create" }),
        Some(agent()),
    );
    assert_eq!(
        adapter
            .start(&unsupported)
            .await
            .expect_err("unsupported")
            .code,
        "unsupported_command"
    );

    let missing = run(
        json!({}),
        json!({ "command": "projects.get" }),
        Some(agent()),
    );
    assert_eq!(
        adapter.start(&missing).await.expect_err("missing id").code,
        "invalid_project_id"
    );

    let no_actor = run(
        json!({ "id": PROJECT }),
        json!({ "command": "projects.get" }),
        None,
    );
    assert_eq!(
        adapter.start(&no_actor).await.expect_err("actor").code,
        "actor_required"
    );
}

#[tokio::test]
async fn command_poll_replays_the_stored_answer() {
    let fixture = oracle();
    let answer = project_view(&named(&fixture["project_views"], "small")["project"]);
    let adapter = FrCommandAdapter::new(reqwest::Client::new(), settings("http://127.0.0.1:1"));
    let row = worker_row(
        RUN,
        TENANT,
        json!({ "id": PROJECT }),
        None,
        authority(json!({ "command": "projects.get" })),
        Some(json!({
            "kind": "fr_command",
            "id": PROJECT,
            "project_id": PROJECT,
            "result": answer.clone(),
        })),
        RunStatus::Running,
    );
    let state = adapter.poll(&row).await.expect("poll");
    assert_eq!(state.status, ExternalStatus::Succeeded);
    assert_eq!(state.result, Some(answer));
    adapter
        .cancel(&row)
        .await
        .expect("a read has nothing to withdraw");
}

#[tokio::test]
async fn project_start_validates_the_actor_and_inputs() {
    let adapter = FrAdapter::new(reqwest::Client::new(), settings("http://127.0.0.1:1"));
    let run = |inputs: Value, actor: Option<Value>| {
        worker_row(
            RUN,
            TENANT,
            inputs,
            actor,
            project_authority(),
            None,
            RunStatus::Starting,
        )
    };

    let no_actor = run(json!({ "title": "Synthetic project" }), None);
    assert_eq!(
        adapter.start(&no_actor).await.expect_err("actor").code,
        "actor_required"
    );

    let foreign = run(
        json!({ "title": "Synthetic project" }),
        Some(actor(&format!("agent:{OTHER_TENANT}"), None)),
    );
    assert_eq!(
        adapter.start(&foreign).await.expect_err("tenant").code,
        "actor_tenant_mismatch"
    );

    let blank_title = run(json!({ "title": "   " }), Some(agent()));
    assert_eq!(
        adapter.start(&blank_title).await.expect_err("title").code,
        "title_required"
    );

    let bad_type = run(
        json!({ "title": "Synthetic project", "project_type": "IT" }),
        Some(agent()),
    );
    assert_eq!(
        adapter.start(&bad_type).await.expect_err("type").code,
        "invalid_project_type"
    );

    let oversized = run(json!({ "title": "x".repeat(4001) }), Some(agent()));
    assert_eq!(
        adapter.start(&oversized).await.expect_err("large").code,
        "inputs_too_large"
    );
}

#[tokio::test]
async fn unconfigured_adapters_refuse() {
    let adapter = FrAdapter::new(
        reqwest::Client::new(),
        FrSettings {
            base_url: None,
            channel_secret: None,
        },
    );
    assert!(!adapter.configured());
    let row = project_run(None, RunStatus::Running);
    assert_eq!(
        adapter.start(&row).await.expect_err("start").code,
        "external_unconfigured"
    );
    assert_eq!(
        adapter.poll(&row).await.expect_err("poll").code,
        "external_unconfigured"
    );
}

#[test]
fn settings_read_the_driver_configuration() {
    let driver = ExternalDriverSettings {
        fr_base_url: Some("http://fr.test/".to_owned()),
        fr_channel_secret: Some(SECRET.to_owned()),
        ..ExternalDriverSettings::default()
    };
    let settings = FrSettings::from(&driver);
    assert_eq!(settings.base_url.as_deref(), Some("http://fr.test/"));
    assert_eq!(settings.channel_secret.as_deref(), Some(SECRET));
    assert!(FrAdapter::new(reqwest::Client::new(), settings).configured());
}

// ── the two start outcomes the reference distinguishes ───────────────────────────────────

/// A transport failure is NOT a refusal: the message may have reached fr, so the run is
/// `interrupted` (`external_start_unknown`), never `failed`. The reference lets it escape
/// `start` into the driver's generic handler for exactly this reason.
#[tokio::test]
async fn a_transport_failure_on_start_is_an_unknown_outcome() {
    // Port 1 is closed: connecting fails before anything can be delivered.
    let adapter = FrAdapter::new(reqwest::Client::new(), settings("http://127.0.0.1:1"));
    let row = worker_row(
        RUN,
        TENANT,
        json!({ "title": "Synthetic project" }),
        Some(agent()),
        project_authority(),
        None,
        RunStatus::Starting,
    );
    let error = adapter.start(&row).await.expect_err("transport failure");
    assert!(
        error.outcome_unknown,
        "a transport failure may have been delivered: {error:?}"
    );
    assert_eq!(error.code, "external_start_unknown");
}

/// The envelope is `json.dumps(..., sort_keys=True)` with Python's DEFAULT `ensure_ascii=True`,
/// so a non-ASCII character travels escaped and the signature is over those bytes. (The
/// `projects.create` text inside it is `ensure_ascii=False`, which is why only the envelope
/// escapes.)
#[tokio::test]
async fn the_envelope_escapes_non_ascii_like_the_reference() {
    let server = TestServer::start(vec![(
        StatusCode::OK,
        json!({ "status": "pending-approval", "approvalId": PROJECT }),
    )])
    .await;
    let adapter = FrAdapter::new(reqwest::Client::new(), server.settings());
    let row = worker_row(
        RUN,
        TENANT,
        json!({ "title": "café ☕\u{7f}🙂" }),
        Some(agent()),
        project_authority(),
        None,
        RunStatus::Starting,
    );
    adapter.start(&row).await.expect("start");

    let body = &server.requests()[0].body;
    let text = String::from_utf8(body.clone()).expect("the envelope is ASCII on the wire");
    // `[^\x20-\x7e]` escaped, lowercase hex: BMP as one unit, DEL as \u007f (serde would have
    // left it raw), and the astral character as its UTF-16 surrogate pair.
    assert!(
        text.contains("caf\\u00e9 \\u2615\\u007f\\ud83d\\ude42"),
        "the envelope escapes non-ASCII: {text}"
    );
    // The text inside the envelope is `ensure_ascii=False`, so it is escaped by the envelope
    // pass only — never twice, and never left raw on the wire.
    assert!(!text.contains("café"), "{text}");
    // What fr receives still decodes to the same value.
    let envelope: Value = serde_json::from_slice(body).expect("envelope json");
    assert_eq!(
        envelope["text"],
        json!("projects.create {\"title\":\"café ☕\u{7f}🙂\",\"project_type\":\"it\"}")
    );
}

/// The channel secret is a secret: `Debug` must not print it.
#[test]
fn the_fr_settings_redact_the_channel_secret() {
    let settings = FrSettings {
        base_url: Some("http://fr.test/".to_owned()),
        channel_secret: Some(SECRET.to_owned()),
    };
    let debug = format!("{settings:?}");
    assert!(!debug.contains(SECRET), "{debug}");
    assert!(debug.contains("<redacted>"), "{debug}");
}
