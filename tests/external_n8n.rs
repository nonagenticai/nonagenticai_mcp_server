//! The n8n workflow adapter against the pinned oracle and a loopback n8n.
//!
//! Every expected value is read from `tests/fixtures/phase3c/oracle.json`, which was produced by
//! executing the archive's `src/external/n8n.py` (commit `22ac1ce4`) — the token encoding, the
//! start request and the result extraction are compared against its output, never against a
//! transcription in this file. The status table, the 4 MiB body cap and the unknown-status limit
//! are driven through the same HTTP surface with a local axum server, the way `tests/auth.rs`
//! drives the licence authority: no database, no network, no fixture rewritten.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use mcp_server_rs::auth::Rfc4122Uuid;
use mcp_server_rs::catalog::models::Runtime;
use mcp_server_rs::config::ExternalDriverSettings;
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::external::n8n::{N8nAdapter, N8nSettings, webhook_token};
use mcp_server_rs::external::{
    AdapterError, ExternalAdapter, ExternalStartError, ExternalState, ExternalStatus,
};
use mcp_server_rs::worker::row::WorkerRow;
use serde_json::{Value, json};

const FIXTURE: &str = include_str!("fixtures/phase3c/oracle.json");

/// The oracle's webhook base, kept only to rewrite the loopback path back onto the fixture's URL.
const FIXTURE_BASE: &str = "http://n8n.test:5678";
const RUN_ID: &str = "018f0000-0000-7000-8000-00000000aaaa";
const TENANT_ID: &str = "10000000-0000-7000-8000-000000000001";
const WEBHOOK_SECRET: &str = "synthetic-webhook-secret";
const API_KEY: &str = "test-api-key";
const EXECUTION_ID: &str = "1216762";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the oracle parses")
}

/// The JWT is byte-exact: the fixture's tokens came out of PyJWT, so a padding, key-order or
/// claim-value difference is a real semantic difference.
#[test]
fn webhook_token_matches_every_fixture_token() {
    let fixture = fixture();
    for entry in fixture["webhook_tokens"].as_array().expect("tokens") {
        let secret = entry["secret"].as_str().expect("a secret");
        let run_id = entry["run_id"].as_str().expect("a run id");
        let now = entry["now"].as_i64().expect("an instant");
        assert_eq!(
            webhook_token(secret, run_id, now),
            entry["token"].as_str().expect("a token"),
            "{}",
            entry["name"].as_str().expect("a name"),
        );
    }
}

#[test]
fn settings_come_from_the_driver_settings() {
    let driver = ExternalDriverSettings {
        n8n_base_url: Some("http://api.test:5678".to_owned()),
        n8n_webhook_base_url: Some("http://hooks.test:5678".to_owned()),
        n8n_api_key: Some("key".to_owned()),
        n8n_webhook_secret: Some("secret".to_owned()),
        n8n_unknown_status_limit: 7,
        ..ExternalDriverSettings::default()
    };
    assert_eq!(
        N8nSettings::from(&driver),
        N8nSettings {
            base_url: Some("http://api.test:5678".to_owned()),
            webhook_base_url: Some("http://hooks.test:5678".to_owned()),
            api_key: Some("key".to_owned()),
            webhook_secret: Some("secret".to_owned()),
            unknown_status_limit: 7,
        }
    );
}

/// `start` sends exactly the oracle's request and reports exactly the oracle's outcome.
#[tokio::test]
async fn start_matches_the_oracle() {
    let fixture = fixture();
    let entries = fixture["n8n_start"].as_array().expect("starts");
    assert_eq!(entries.len(), 3, "the fixture's three start cases");
    for entry in entries {
        let name = entry["name"].as_str().expect("a name");
        let (base, server) = local_server().await;
        let reply = match entry["outcome"].get("ref") {
            Some(reference) => json!({"executionId": reference["id"]}),
            None => json!({}),
        };
        server.reply(StatusCode::OK, serde_json::to_vec(&reply).expect("a body"));
        let secret = entry["request"]["headers"]
            .get("Authorization")
            .and_then(Value::as_str)
            .map(|_| WEBHOOK_SECRET.to_owned());
        let adapter = N8nAdapter::new(
            client(),
            N8nSettings {
                // The trailing slash proves the base is right-stripped, not concatenated.
                webhook_base_url: Some(format!("{base}/")),
                webhook_secret: secret,
                ..api_settings(None, None, 10)
            },
        );

        let outcome = adapter.start(&row()).await;

        let requests = server.requested();
        assert_eq!(requests.len(), 1, "{name}: one request");
        let request = &requests[0];
        assert_eq!(request.method, "POST", "{name}");
        assert_eq!(
            format!("{FIXTURE_BASE}{}", request.path),
            entry["request"]["url"].as_str().expect("a url"),
            "{name}: the URL"
        );
        assert_eq!(request.query, None, "{name}: no query");
        assert_eq!(
            serde_json::from_slice::<Value>(&request.body).expect("a JSON body"),
            entry["request"]["json"],
            "{name}: the body"
        );
        match entry["request"]["headers"]
            .get("Authorization")
            .and_then(Value::as_str)
        {
            None => assert!(
                !request.headers.contains_key("authorization"),
                "{name}: no Authorization without a secret"
            ),
            Some(_) => {
                let header = request
                    .headers
                    .get("authorization")
                    .expect("an Authorization header");
                let token = header.strip_prefix("Bearer ").expect("a bearer token");
                let claims = claims_of(token);
                assert_eq!(claims["sub"], json!(RUN_ID), "{name}: the subject");
                let issued = claims["iat"].as_i64().expect("iat");
                assert_eq!(
                    claims["exp"].as_i64(),
                    Some(issued + 120),
                    "{name}: a two-minute token"
                );
                assert_eq!(
                    header,
                    &format!("Bearer {}", webhook_token(WEBHOOK_SECRET, RUN_ID, issued)),
                    "{name}: the token"
                );
            }
        }
        match entry["outcome"].get("ref") {
            Some(reference) => {
                let started = outcome.expect("a started run");
                assert_eq!(&started.stored(), reference, "{name}: the reference");
            }
            None => {
                let refused = outcome.expect_err("a refusal");
                assert_eq!(
                    refused,
                    ExternalStartError::new(entry["outcome"]["code"].as_str().expect("a code")),
                    "{name}: the refusal"
                );
            }
        }
    }
}

#[tokio::test]
async fn start_refuses_what_the_reference_refuses() {
    // No webhook base: nothing is sent at all.
    let unconfigured = N8nAdapter::new(client(), api_settings(None, None, 10));
    assert_eq!(
        unconfigured.start(&row()).await.expect_err("unconfigured"),
        ExternalStartError::new("external_unconfigured")
    );

    let cases = [
        (StatusCode::INTERNAL_SERVER_ERROR, b"{}".to_vec()),
        (StatusCode::OK, b"not json".to_vec()),
        (StatusCode::OK, b"{}".to_vec()),
        (StatusCode::OK, br#"{"executionId":""}"#.to_vec()),
        (StatusCode::OK, br#"{"executionId":7}"#.to_vec()),
    ];
    let (base, server) = local_server().await;
    for (status, body) in &cases {
        server.reply(*status, body.clone());
    }
    let adapter = N8nAdapter::new(
        client(),
        N8nSettings {
            webhook_base_url: Some(base),
            ..api_settings(None, None, 10)
        },
    );
    for (status, body) in &cases {
        assert_eq!(
            adapter.start(&row()).await.expect_err("a refusal"),
            ExternalStartError::new("external_start_failed"),
            "{status} {}",
            String::from_utf8_lossy(body)
        );
    }
}

/// Every `n8n_results` entry, name for name, through the real poll path.
#[tokio::test]
async fn poll_matches_the_oracle() {
    let fixture = fixture();
    let entries = fixture["n8n_results"].as_array().expect("results");
    let (base, server) = local_server().await;
    for entry in entries {
        server.reply(
            StatusCode::OK,
            serde_json::to_vec(&entry["payload"]).expect("a payload"),
        );
    }
    let adapter = N8nAdapter::new(client(), api_settings(Some(&base), Some(API_KEY), 10));
    let row = parked_row();
    for entry in entries {
        let state = adapter.poll(&row).await.expect("a poll");
        assert_eq!(
            state_json(&state),
            entry["state"],
            "{}",
            entry["name"].as_str().expect("a name")
        );
    }
    let requests = server.requested();
    assert_eq!(requests.len(), entries.len());
    for request in &requests {
        assert_eq!(request.method, "GET");
        assert_eq!(request.path, format!("/api/v1/executions/{EXECUTION_ID}"));
        assert_eq!(
            request.query.as_deref(),
            Some("includeData=true&ignoreDataSizeLimit=true")
        );
        assert_eq!(
            request.headers.get("x-n8n-api-key").map(String::as_str),
            Some(API_KEY)
        );
    }
}

#[tokio::test]
async fn poll_status_table_matches_the_reference() {
    let (base, server) = local_server().await;
    let cases = [
        (json!({"status": "new"}), ExternalState::running()),
        (json!({"status": "running"}), ExternalState::running()),
        (
            json!({"status": "waiting"}),
            ExternalState::running_with("waiting for approval in fr"),
        ),
        (json!({"status": "canceled"}), ExternalState::cancelled()),
        (
            json!({"status": "crashed"}),
            ExternalState::failed("external_failed"),
        ),
        (json!({}), ExternalState::failed("external_failed")),
        (json!([1, 2]), ExternalState::failed("external_failed")),
        (
            json!({"status": 7}),
            ExternalState::failed("external_failed"),
        ),
    ];
    for (payload, _) in &cases {
        server.reply(
            StatusCode::OK,
            serde_json::to_vec(payload).expect("a payload"),
        );
    }
    let adapter = N8nAdapter::new(client(), api_settings(Some(&base), Some(API_KEY), 10));
    let row = parked_row();
    for (payload, expected) in &cases {
        assert_eq!(
            adapter.poll(&row).await.expect("a poll"),
            *expected,
            "{payload}"
        );
    }
}

/// 4 MiB exactly is read; one byte more is refused before the body is even finished.
#[tokio::test]
async fn poll_caps_the_body_at_four_mebibytes() {
    const LIMIT: usize = 4 * 1024 * 1024;
    let body = json!({"status": "success", "data": {"resultData": {"runData": {}}}});
    let mut at_limit = serde_json::to_vec(&body).expect("a body");
    at_limit.resize(LIMIT, b' ');
    let mut over_limit = at_limit.clone();
    over_limit.push(b' ');

    let (base, server) = local_server().await;
    server.reply(StatusCode::OK, at_limit);
    server.reply(StatusCode::OK, over_limit);
    let adapter = N8nAdapter::new(client(), api_settings(Some(&base), Some(API_KEY), 10));
    let row = parked_row();
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::succeeded(Some(json!({}))),
        "exactly the cap is read"
    );
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::failed("external_result_invalid"),
        "past the cap is refused"
    );
}

/// `unknown` counts per run, a non-unknown status resets it, and the limit fails exactly once.
#[tokio::test]
async fn unknown_status_counts_then_fails_and_resets() {
    let (base, server) = local_server().await;
    server.reply(
        StatusCode::OK,
        serde_json::to_vec(&json!({"status": "unknown"})).expect("a payload"),
    );
    server.reply(StatusCode::NOT_FOUND, Vec::new());
    server.reply(
        StatusCode::OK,
        serde_json::to_vec(&json!({"status": "unknown"})).expect("a payload"),
    );
    server.reply(
        StatusCode::OK,
        serde_json::to_vec(&json!({"status": "unknown"})).expect("a payload"),
    );
    server.reply(
        StatusCode::OK,
        serde_json::to_vec(&json!({"status": "unknown"})).expect("a payload"),
    );
    // A second run must not inherit or reset the first one's count.
    server.reply(
        StatusCode::OK,
        serde_json::to_vec(&json!({"status": "running"})).expect("a payload"),
    );
    let adapter = N8nAdapter::new(client(), api_settings(Some(&base), Some(API_KEY), 2));
    let row = parked_row();
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::running(),
        "one unknown"
    );
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::failed("external_missing"),
        "a 404 is missing, and resets the count"
    );
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::running(),
        "unknown again counts from one"
    );
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::failed("external_status_unknown"),
        "the limit fails the run"
    );
    assert_eq!(
        adapter.poll(&row).await.expect("a poll"),
        ExternalState::running(),
        "failing resets the count"
    );
    assert_eq!(
        adapter.poll(&other_parked_row()).await.expect("a poll"),
        ExternalState::running(),
        "another run starts at zero"
    );
}

/// `n8n_base_url` and `n8n_api_key` are both required; without either, no request is made.
#[tokio::test]
async fn poll_is_unconfigured_without_both_api_settings() {
    let (base, server) = local_server().await;
    for settings in [
        api_settings(None, Some(API_KEY), 10),
        api_settings(Some(&base), None, 10),
        api_settings(Some(""), Some(API_KEY), 10),
    ] {
        let adapter = N8nAdapter::new(client(), settings);
        assert_eq!(
            adapter.poll(&parked_row()).await.expect("a poll"),
            ExternalState::failed("external_unconfigured")
        );
        adapter
            .cancel(&parked_row())
            .await
            .expect("nothing to cancel");
    }
    assert!(
        server.requested().is_empty(),
        "no request without both settings"
    );
}

#[tokio::test]
async fn cancel_matches_the_oracle() {
    let (base, server) = local_server().await;
    let adapter = N8nAdapter::new(client(), api_settings(Some(&base), Some(API_KEY), 10));

    // A run with no external ref has nothing upstream to stop.
    adapter.cancel(&row()).await.expect("nothing to cancel");
    assert!(server.requested().is_empty());

    server.reply(StatusCode::OK, b"{}".to_vec());
    adapter.cancel(&parked_row()).await.expect("cancelled");
    let requests = server.requested();
    let request = requests.last().expect("a request");
    assert_eq!(request.method, "POST");
    assert_eq!(
        request.path,
        format!("/api/v1/executions/{EXECUTION_ID}/stop")
    );
    assert_eq!(
        request.headers.get("x-n8n-api-key").map(String::as_str),
        Some(API_KEY)
    );

    // A finished-and-retentioned execution answers 404: tolerated.
    server.reply(StatusCode::NOT_FOUND, Vec::new());
    adapter.cancel(&parked_row()).await.expect("already gone");

    // Anything else is a refusal the driver retries.
    server.reply(StatusCode::INTERNAL_SERVER_ERROR, Vec::new());
    assert_eq!(
        adapter.cancel(&parked_row()).await.expect_err("a refusal"),
        AdapterError::new("external_cancel_failed")
    );

    // The execution id is a path segment: `quote(safe="")`, not interpolation.
    server.reply(StatusCode::OK, b"{}".to_vec());
    adapter
        .cancel(&row_with_ref(json!({"kind": "n8n", "id": "12/34 56"})))
        .await
        .expect("cancelled");
    let requests = server.requested();
    assert_eq!(
        requests.last().expect("a request").path,
        "/api/v1/executions/12%2F34%2056/stop"
    );
}

// ── the row, the settings and the loopback n8n ──────────────────────────────────────────────

fn instant() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("an instant")
}

fn uuid(value: &str) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(value).expect("an RFC 4122 UUID")
}

/// The run's authority snapshot as the API stores it: `manifest` is a JSON **string**.
fn authority(manifest: Value) -> Value {
    json!({
        "manifest": manifest.to_string(),
        "effective": "{}",
        "context": "{}",
    })
}

/// The manifest the fixture's rows use: the workflow's webhook path, no custom result node.
fn manifest() -> Value {
    json!({"target": {"webhook_path": "mcp/demo"}})
}

fn worker_row(authority: Value, external_ref: Option<Value>) -> WorkerRow {
    WorkerRow {
        run: RunRow {
            run_id: uuid(RUN_ID),
            tenant_id: uuid(TENANT_ID),
            gateway_license_id: uuid("30000000-0000-4000-8000-000000000001"),
            owner_tenant_id: uuid(TENANT_ID),
            tool_id: uuid("20000000-0000-7000-8000-000000000001"),
            binding_id: None,
            binding_revision: None,
            credential_profile_id: None,
            profile_snapshot: json!({}),
            tool_version: 1,
            authority,
            inputs: json!({"a": 1}),
            input_hash: "b".repeat(64),
            idempotency_key: None,
            created_by: json!({"subject": "phase3c"}),
            status: RunStatus::Running,
            created_at: instant(),
            queue_deadline: instant(),
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            result: None,
            error: None,
            payload_expired_at: None,
            mode: "bound".to_owned(),
            runtime: Runtime::N8nWorkflow,
            external_ref,
            status_message: None,
            actor: None,
        },
        worker_id: Some("30000000-0000-4000-8000-000000000002".to_owned()),
        fence: 3,
        lease_until: None,
        heartbeat_at: None,
        start_deadline: None,
        deadline: None,
        pod_name: None,
        pod_uid: None,
        api_calls: 0,
    }
}

/// The dispatchable run: no external ref yet.
fn row() -> WorkerRow {
    worker_row(authority(manifest()), None)
}

fn row_with_ref(external_ref: Value) -> WorkerRow {
    worker_row(authority(manifest()), Some(external_ref))
}

/// The run as the fixture's polls see it: parked on execution `1216762`.
fn parked_row() -> WorkerRow {
    row_with_ref(json!({"kind": "n8n", "id": EXECUTION_ID}))
}

fn other_parked_row() -> WorkerRow {
    let mut row = parked_row();
    row.run.run_id = uuid("018f0000-0000-7000-8000-00000000bbbb");
    row
}

fn api_settings(
    base_url: Option<&str>,
    api_key: Option<&str>,
    unknown_status_limit: u32,
) -> N8nSettings {
    N8nSettings {
        base_url: base_url.map(str::to_owned),
        webhook_base_url: None,
        api_key: api_key.map(str::to_owned),
        webhook_secret: None,
        unknown_status_limit,
    }
}

/// A plain client. The library installs the process-default crypto provider exactly once; tests
/// that build a client do the same, or two compiled rustls providers would panic on selection.
fn client() -> reqwest::Client {
    static INSTALL: std::sync::Once = std::sync::Once::new();
    INSTALL.call_once(mcp_server_rs::install_crypto_provider);
    reqwest::Client::new()
}

fn state_json(state: &ExternalState) -> Value {
    let status = match state.status {
        ExternalStatus::Running => "running",
        ExternalStatus::Succeeded => "succeeded",
        ExternalStatus::Failed => "failed",
        ExternalStatus::Cancelled => "cancelled",
    };
    json!({
        "status": status,
        "result": state.result,
        "code": state.code,
        "message": state.message,
    })
}

fn claims_of(token: &str) -> Value {
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3, "a JWT has three parts");
    let header = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("a base64url header");
    assert_eq!(
        String::from_utf8(header).expect("utf-8"),
        r#"{"alg":"HS256","typ":"JWT"}"#,
        "the header is exactly the oracle's"
    );
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("base64url claims"))
        .expect("claims json")
}

#[derive(Clone)]
struct Stub {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
}

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    query: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Stub {
    fn reply(&self, status: StatusCode, body: Vec<u8>) {
        self.replies
            .lock()
            .expect("an unpoisoned stub")
            .push_back(Reply { status, body });
    }

    fn requested(&self) -> Vec<Recorded> {
        self.requests.lock().expect("an unpoisoned stub").clone()
    }
}

/// Queue one reply per expected request; every request is recorded before it is answered.
async fn local_server() -> (String, Stub) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let address = listener.local_addr().expect("an address");
    let stub = Stub {
        replies: Arc::default(),
        requests: Arc::default(),
    };
    let app = Router::new().fallback(any(handle)).with_state(stub.clone());
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    (format!("http://{address}"), stub)
}

async fn handle(State(stub): State<Stub>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024)
        .await
        .expect("the request body")
        .to_vec();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    stub.requests
        .lock()
        .expect("an unpoisoned stub")
        .push(Recorded {
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers,
            body,
        });
    let reply = stub
        .replies
        .lock()
        .expect("an unpoisoned stub")
        .pop_front()
        .expect("a queued reply");
    (reply.status, reply.body).into_response()
}
