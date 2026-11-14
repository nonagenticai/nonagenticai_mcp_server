//! The Kata backend against the pinned Python oracle and a local mock of the Kubernetes API.
//!
//! Two things are proven here and one is deliberately not:
//!
//! * The pod manifest is compared **value-for-value** with `tests/fixtures/phase3b/pod.json`,
//!   which `generate_pod.py` produced by executing the archive's `kata.pod_manifest` (commit
//!   `22ac1ce4`) on the inputs recorded beside it. The test rebuilds the same inputs in Rust.
//! * Every pod-CRUD rule — the 404-to-`None` inspection, the deterministic-name resolution of an
//!   ambiguous create, the identity fence, the UID-preconditioned delete, the confirm-by-
//!   inspection loop and the one-page inventory — runs against a real HTTP server that speaks
//!   the Kubernetes core API's shapes on loopback.
//! * The attach **websocket handshake** is not exercised: `KataAttach`'s buffered-read rules are
//!   driven over `tokio::io::simplex`, and the websocket leg is proven at the in-cluster cutover.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, Utc};
use k8s_openapi::api::core::v1::Pod as KubePod;
use mcp_server_rs::auth::Rfc4122Uuid;
use mcp_server_rs::catalog::models::{Runtime, ToolLimits};
use mcp_server_rs::config::WorkerSettings;
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::worker::backend::{AttachChannel, Backend, BackendError, Pod};
use mcp_server_rs::worker::kata::{Kata, KataAttach};
use mcp_server_rs::worker::row::WorkerRow;
use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const FIXTURE: &str = include_str!("fixtures/phase3b/pod.json");

/// The fixture's run and fence; its pod name is derived from them.
const RUN_ID: &str = "0190b0b0-0000-7000-8000-0000000b0001";
const FENCE: i64 = 3;
/// `mcp-<run hex>-<fence>`, as `kata.pod_name` spells it.
const NAME: &str = "mcp-0190b0b00000700080000000000b0001-3";
const POD_UID: &str = "0f1e2d3c-4b5a-6978-8a9b-0c1d2e3f4a5b";
const NAMESPACE: &str = "mcp-runs";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the fixture parses")
}

fn worker_settings(value: &Value) -> WorkerSettings {
    let seconds = |name: &str| {
        Duration::from_secs(
            value[name]
                .as_u64()
                .unwrap_or_else(|| panic!("settings.{name}")),
        )
    };
    let mi = |name: &str| {
        u32::try_from(
            value[name]
                .as_u64()
                .unwrap_or_else(|| panic!("settings.{name}")),
        )
        .unwrap_or_else(|_| panic!("settings.{name} fits in u32"))
    };
    WorkerSettings {
        run_namespace: value["run_namespace"]
            .as_str()
            .expect("namespace")
            .to_owned(),
        kata_runtime_class: value["kata_runtime_class"].as_str().map(str::to_owned),
        runner_image_digest: value["runner_image_digest"].as_str().map(str::to_owned),
        approved_runner_images: value["approved_runner_images"]
            .as_array()
            .expect("approved images")
            .iter()
            .map(|image| image.as_str().expect("image").to_owned())
            .collect(),
        run_start_timeout: seconds("run_start_timeout_seconds"),
        run_max: seconds("run_max_seconds"),
        run_memory_request_mi: mi("run_memory_request_mi"),
        run_memory_limit_mi: mi("run_memory_limit_mi"),
        run_cpu_request: mi("run_cpu_request"),
        run_cpu_limit: mi("run_cpu_limit"),
        ..WorkerSettings::default()
    }
}

fn instant() -> DateTime<Utc> {
    DateTime::<Utc>::from_timestamp(1_700_000_000, 0).expect("a timestamp")
}

fn uuid(value: &str) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(value).expect("an RFC 4122 UUID")
}

/// One run row whose authority snapshot is the fixture's; only the worker columns vary.
fn worker_row(authority: Value, pod_uid: Option<&str>) -> WorkerRow {
    WorkerRow {
        run: RunRow {
            run_id: uuid(RUN_ID),
            tenant_id: uuid("10000000-0000-7000-8000-000000000001"),
            gateway_license_id: uuid("30000000-0000-4000-8000-000000000001"),
            owner_tenant_id: uuid("10000000-0000-7000-8000-000000000001"),
            tool_id: uuid("20000000-0000-7000-8000-000000000001"),
            binding_id: None,
            binding_revision: None,
            credential_profile_id: None,
            profile_snapshot: json!({}),
            tool_version: 1,
            authority,
            inputs: json!({}),
            input_hash: "b".repeat(64),
            idempotency_key: None,
            created_by: json!({"subject": "phase3b"}),
            status: RunStatus::Queued,
            created_at: instant(),
            queue_deadline: instant(),
            started_at: None,
            finished_at: None,
            cancel_requested: false,
            result: None,
            error: None,
            payload_expired_at: None,
            mode: "bound".to_owned(),
            runtime: Runtime::KataPython,
            external_ref: None,
            status_message: None,
            actor: None,
        },
        worker_id: Some("30000000-0000-4000-8000-000000000002".to_owned()),
        fence: FENCE,
        lease_until: None,
        heartbeat_at: None,
        start_deadline: None,
        deadline: None,
        pod_name: None,
        pod_uid: pod_uid.map(str::to_owned),
        api_calls: 0,
    }
}

fn fixture_limits() -> ToolLimits {
    serde_json::from_value(fixture()["limits"].clone()).expect("limits")
}

/// A pod object as the API server reports it.
fn pod_json(name: &str, uid: &str, run_id: &str, fence: i64) -> Value {
    json!({
        "apiVersion": "v1",
        "kind": "Pod",
        "metadata": {
            "name": name,
            "uid": uid,
            "labels": {
                "app.kubernetes.io/managed-by": "mcp-executor",
                "mcp.run-id": run_id,
                "mcp.fence": fence.to_string(),
            },
        },
        "status": {"phase": "Pending"},
    })
}

fn kube_pod(value: Value) -> KubePod {
    serde_json::from_value(value).expect("a pod object")
}

/// The reason of a denial. Deliberately not generic over `Debug`: `Box<dyn AttachChannel>` has
/// no `Debug` implementation, and the attach test must be able to assert its denial too.
fn denial<T>(result: Result<T, BackendError>) -> &'static str {
    match result {
        Err(BackendError::Denied(reason)) => reason,
        Err(BackendError::Transport(reason)) => {
            panic!("expected a denial, got a transport failure: {reason}")
        }
        Ok(_) => panic!("expected a denial, got an accepted value"),
    }
}

// ── the local Kubernetes API ──────────────────────────────────────────────────────────────

/// The scripted reply queue for one endpoint.
type Script = HashMap<String, VecDeque<Reply>>;
/// Every request the mock has served, in arrival order.
type Requests = Vec<Recorded>;

#[derive(Clone)]
struct MockApi {
    /// One scripted reply queue per `METHOD /path`. The last reply repeats forever.
    script: Arc<Mutex<Script>>,
    requests: Arc<Mutex<Requests>>,
}

#[derive(Clone, Debug)]
struct Reply {
    status: u16,
    body: Value,
}

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    query: String,
    body: Vec<u8>,
}

impl MockApi {
    fn new() -> Self {
        Self {
            script: Arc::new(Mutex::new(HashMap::new())),
            requests: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Script the reply sequence for one endpoint. A single entry answers every request.
    fn reply(&self, method: &str, path: &str, status: u16, body: Value) {
        self.script
            .lock()
            .expect("script")
            .entry(format!("{method} {path}"))
            .or_default()
            .push_back(Reply { status, body });
    }

    fn scripted(&self, method: &str, path: &str, replies: &[(u16, Value)]) {
        for (status, body) in replies {
            self.reply(method, path, *status, body.clone());
        }
    }

    async fn start(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the mock API");
        let address = listener.local_addr().expect("mock address");
        let router = Router::new().fallback(handle).with_state(self.clone());
        tokio::spawn(async move {
            axum::serve(listener, router).await.expect("mock server");
        });
        format!("http://{address}")
    }

    fn recorded(&self, method: &str, path: &str) -> Vec<Recorded> {
        self.requests
            .lock()
            .expect("requests")
            .iter()
            .filter(|record| record.method == method && record.path == path)
            .cloned()
            .collect()
    }

    fn total(&self) -> usize {
        self.requests.lock().expect("requests").len()
    }
}

async fn handle(State(state): State<MockApi>, request: Request) -> Response {
    let method = request.method().to_string();
    let path = request.uri().path().to_owned();
    let query = request.uri().query().unwrap_or_default().to_owned();
    let body = axum::body::to_bytes(request.into_body(), 1 << 20)
        .await
        .unwrap_or_default()
        .to_vec();
    state.requests.lock().expect("requests").push(Recorded {
        method: method.clone(),
        path: path.clone(),
        query,
        body,
    });
    let key = format!("{method} {path}");
    let reply = {
        let mut script = state.script.lock().expect("script");
        match script.get_mut(&key) {
            Some(queue) if queue.len() > 1 => queue.pop_front(),
            Some(queue) => queue.front().cloned(),
            None => None,
        }
    };
    let reply = reply.unwrap_or(Reply {
        status: 404,
        body: status_body(404, "NotFound", "the mock has no script for this request"),
    });
    (
        StatusCode::from_u16(reply.status).expect("a status"),
        axum::Json(reply.body),
    )
        .into_response()
}

fn status_body(code: u16, reason: &str, message: &str) -> Value {
    json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Failure",
        "message": message,
        "reason": reason,
        "code": code,
    })
}

fn success_status() -> Value {
    json!({
        "kind": "Status",
        "apiVersion": "v1",
        "metadata": {},
        "status": "Success",
        "code": 200,
    })
}

fn backend(url: &str, settings: WorkerSettings) -> Kata {
    mcp_server_rs::install_crypto_provider();
    let config = kube::Config::new(url.parse().expect("a cluster url"));
    let client = kube::Client::try_from(config).expect("a kube client");
    Kata::new(client, settings).expect("the Kata backend")
}

// ── the manifest golden ───────────────────────────────────────────────────────────────────

#[test]
fn manifest_matches_the_python_oracle() {
    let fixture = fixture();
    assert_eq!(fixture["run_id"].as_str(), Some(RUN_ID));
    assert_eq!(fixture["fence"].as_i64(), Some(FENCE));
    assert_eq!(fixture["pod"]["metadata"]["name"].as_str(), Some(NAME));
    let settings = worker_settings(&fixture["settings"]);
    let row = worker_row(fixture["authority"].clone(), None);
    let built = Kata::pod_manifest(&row, &settings, &fixture_limits())
        .unwrap_or_else(|error| panic!("manifest refused: {error}"));
    assert_eq!(built, fixture["pod"], "the manifest is not the oracle's");
}

#[test]
fn manifest_refuses_an_unapproved_runner_image() {
    let fixture = fixture();
    let row = worker_row(fixture["authority"].clone(), None);
    let limits = fixture_limits();

    // The manifest's digest is approved and configured: the baseline is accepted.
    let mut settings = worker_settings(&fixture["settings"]);
    assert!(Kata::pod_manifest(&row, &settings, &limits).is_ok());

    settings.approved_runner_images =
        vec![format!("registry.example/other@sha256:{}", "c".repeat(64))];
    assert_eq!(
        denial(Kata::pod_manifest(&row, &settings, &limits)),
        "the run's runner image is not the approved digest"
    );

    // The configured digest must agree too: an approved-but-rotated deployment is refused.
    settings = worker_settings(&fixture["settings"]);
    settings.runner_image_digest =
        Some(format!("registry.example/other@sha256:{}", "c".repeat(64)));
    assert_eq!(
        denial(Kata::pod_manifest(&row, &settings, &limits)),
        "the run's runner image is not the approved digest"
    );

    // No runtime class is a denial before the image is ever considered.
    settings = worker_settings(&fixture["settings"]);
    settings.kata_runtime_class = None;
    assert_eq!(
        denial(Kata::pod_manifest(&row, &settings, &limits)),
        "the run needs a Kata runtime class and a runner image digest"
    );
}

// ── record parsing ────────────────────────────────────────────────────────────────────────

#[test]
fn record_parses_the_fence_phase_and_exit_code() {
    let mut value = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    value["status"] = json!({
        "phase": "Failed",
        "containerStatuses": [{
            "name": "runner",
            "image": "registry.example/runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "imageID": "sha256:beef",
            "ready": false,
            "restartCount": 0,
            "state": {"terminated": {"exitCode": 7, "reason": "Error"}},
        }],
    });
    assert_eq!(
        Kata::record(&kube_pod(value)).expect("record"),
        Pod {
            name: NAME.to_owned(),
            uid: POD_UID.to_owned(),
            run_id: RUN_ID.to_owned(),
            fence: 3,
            phase: "Failed".to_owned(),
            exit_code: Some(7),
        }
    );

    // A running container has no terminated state, so no exit code.
    let mut value = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    value["status"] = json!({
        "phase": "Running",
        "containerStatuses": [{
            "name": "runner",
            "image": "registry.example/runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "imageID": "sha256:beef",
            "ready": true,
            "restartCount": 0,
            "state": {"running": {"startedAt": "2026-11-14T00:00:00Z"}},
        }],
    });
    let record = Kata::record(&kube_pod(value)).expect("record");
    assert_eq!(record.phase, "Running");
    assert_eq!(record.exit_code, None);
    assert_eq!(record.fence, FENCE);
}

#[test]
fn record_refuses_labels_that_are_not_the_executors() {
    let mut foreign = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    foreign["metadata"]["labels"]["app.kubernetes.io/managed-by"] = json!("someone-else");
    assert_eq!(
        denial(Kata::record(&kube_pod(foreign))),
        "the pod is not managed by this executor"
    );

    let mut unlabelled = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    unlabelled["metadata"]
        .as_object_mut()
        .expect("metadata")
        .remove("labels");
    assert_eq!(
        denial(Kata::record(&kube_pod(unlabelled))),
        "the pod carries no executor labels"
    );

    let mut fencefree = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    fencefree["metadata"]["labels"]
        .as_object_mut()
        .expect("labels")
        .remove("mcp.fence");
    assert_eq!(
        denial(Kata::record(&kube_pod(fencefree))),
        "the pod carries no fence"
    );

    let mut mistyped = pod_json(NAME, POD_UID, RUN_ID, FENCE);
    mistyped["metadata"]["labels"]["mcp.fence"] = json!("three");
    assert_eq!(
        denial(Kata::record(&kube_pod(mistyped))),
        "the pod's fence is not an integer"
    );
}

// ── inspection, readiness and adoption ───────────────────────────────────────────────────

#[tokio::test]
async fn inspect_answers_none_for_a_missing_pod() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        &pod_path(NAME),
        404,
        status_body(404, "NotFound", "not found"),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    assert_eq!(kata.inspect(NAME).await.expect("inspect"), None);
    assert_eq!(mock.recorded("GET", &pod_path(NAME)).len(), 1);
}

#[tokio::test]
async fn ready_reads_the_runtime_class_and_the_inventory() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        RUNTIME_CLASS_PATH,
        200,
        json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "kata-qemu"},
            "handler": "kata-qemu",
        }),
    );
    mock.reply(
        "GET",
        &pods_path(),
        200,
        json!({"apiVersion": "v1", "kind": "PodList", "metadata": {}, "items": []}),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    kata.ready().await.expect("ready");
    assert_eq!(mock.recorded("GET", RUNTIME_CLASS_PATH).len(), 1);
    assert_eq!(mock.recorded("GET", &pods_path()).len(), 1);
}

#[tokio::test]
async fn ready_refuses_without_configuration_or_a_handler() {
    let mock = MockApi::new();
    let url = mock.start().await;

    // Nothing configured: refused before the first API call.
    let unconfigured = backend(&url, WorkerSettings::default());
    assert_eq!(
        denial(unconfigured.ready().await),
        "execution requires a Kata runtime class"
    );
    assert_eq!(
        mock.total(),
        0,
        "an unconfigured backend must not call the API"
    );

    // A RuntimeClass with no handler cannot sandbox anything.
    mock.reply(
        "GET",
        RUNTIME_CLASS_PATH,
        200,
        json!({
            "apiVersion": "node.k8s.io/v1",
            "kind": "RuntimeClass",
            "metadata": {"name": "kata-qemu"},
            "handler": "",
        }),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    assert_eq!(
        denial(kata.ready().await),
        "the Kata RuntimeClass carries no handler"
    );
}

#[tokio::test]
async fn create_failure_is_resolved_by_inspecting_the_deterministic_name() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.scripted(
        "POST",
        &pods_path(),
        &[(
            500,
            status_body(500, "InternalError", "the create was lost"),
        )],
    );
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, POD_UID, RUN_ID, FENCE),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let row = worker_row(fixture()["authority"].clone(), None);
    let adopted = kata.start(&row, &fixture_limits()).await.expect("adopted");
    assert_eq!(adopted.name, NAME);
    assert_eq!(adopted.uid, POD_UID);
    assert_eq!(adopted.run_id, RUN_ID);
    assert_eq!(adopted.fence, FENCE);
    assert_eq!(
        mock.recorded("POST", &pods_path()).len(),
        1,
        "a failed create must never be retried"
    );
}

#[tokio::test]
async fn create_conflict_adopts_only_this_runs_pod() {
    // A 409 (AlreadyExists) with a pod that matches the row is adopted.
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "POST",
        &pods_path(),
        409,
        status_body(409, "AlreadyExists", "the pod already exists"),
    );
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, POD_UID, RUN_ID, FENCE),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let row = worker_row(fixture()["authority"].clone(), None);
    let adopted = kata.start(&row, &fixture_limits()).await.expect("adopted");
    assert_eq!(adopted.uid, POD_UID);
    assert_eq!(mock.recorded("POST", &pods_path()).len(), 1);

    // The same conflict where the pod names another generation is refused.
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "POST",
        &pods_path(),
        409,
        status_body(409, "AlreadyExists", "the pod already exists"),
    );
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, POD_UID, RUN_ID, FENCE - 1),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    assert_eq!(
        denial(kata.start(&row, &fixture_limits()).await),
        "the runner pod does not belong to this run and fence"
    );

    // A row that recorded a UID refuses a pod with a different one.
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "POST",
        &pods_path(),
        409,
        status_body(409, "AlreadyExists", "the pod already exists"),
    );
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, POD_UID, RUN_ID, FENCE),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let row = worker_row(fixture()["authority"].clone(), Some("another-uid"));
    assert_eq!(
        denial(kata.start(&row, &fixture_limits()).await),
        "the runner pod does not belong to this run and fence"
    );
}

#[tokio::test]
async fn attach_refuses_a_pod_that_was_replaced() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, "another-uid", RUN_ID, FENCE),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    assert_eq!(
        denial(kata.attach(&recorded).await),
        "the runner pod is gone or was replaced"
    );
    assert_eq!(
        mock.total(),
        1,
        "a replaced pod must not reach the attach websocket"
    );
}

// ── the stop protocol ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn stop_deletes_with_a_uid_precondition_and_confirms_absence() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.scripted(
        "GET",
        &pod_path(NAME),
        &[
            (200, pod_json(NAME, POD_UID, RUN_ID, FENCE)),
            (404, status_body(404, "NotFound", "not found")),
        ],
    );
    mock.reply("DELETE", &pod_path(NAME), 200, success_status());
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    assert!(
        kata.stop(&recorded).await.expect("stop"),
        "absence confirmed"
    );

    let deletes = mock.recorded("DELETE", &pod_path(NAME));
    assert_eq!(deletes.len(), 1, "one delete, no retry");
    let body: Value = serde_json::from_slice(&deletes[0].body).expect("delete body");
    assert_eq!(body["gracePeriodSeconds"], json!(0));
    assert_eq!(body["preconditions"]["uid"], json!(POD_UID));
    assert_eq!(
        mock.recorded("GET", &pod_path(NAME)).len(),
        2,
        "one inspection before the delete, one to confirm"
    );
}

#[tokio::test]
async fn stop_reports_unconfirmed_absence_after_the_reference_attempts() {
    let mock = MockApi::new();
    let url = mock.start().await;
    // Every inspection still sees the pod, so the 20-attempt loop never confirms.
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, POD_UID, RUN_ID, FENCE),
    );
    mock.reply("DELETE", &pod_path(NAME), 200, success_status());
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    let stopped = kata
        .stop_with_interval(&recorded, Duration::from_millis(1))
        .await
        .expect("stop");
    assert!(!stopped, "unconfirmed absence keeps capacity quarantined");
    assert_eq!(
        mock.recorded("GET", &pod_path(NAME)).len(),
        21,
        "one inspection before the delete plus the reference's twenty attempts"
    );
}

#[tokio::test]
async fn stop_treats_a_missing_delete_as_success() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.scripted(
        "GET",
        &pod_path(NAME),
        &[
            (200, pod_json(NAME, POD_UID, RUN_ID, FENCE)),
            (404, status_body(404, "NotFound", "not found")),
        ],
    );
    // The pod was collected between the inspection and the delete.
    mock.reply(
        "DELETE",
        &pod_path(NAME),
        404,
        status_body(404, "NotFound", "already gone"),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    assert!(
        kata.stop(&recorded).await.expect("stop"),
        "a 404 delete is the same outcome as an absent pod"
    );
}

#[tokio::test]
async fn stop_refuses_a_pod_that_is_not_the_recorded_one() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        &pod_path(NAME),
        200,
        pod_json(NAME, "another-uid", RUN_ID, FENCE),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    assert_eq!(
        denial(kata.stop(&recorded).await),
        "the runner pod is not the one this run recorded"
    );
    assert!(
        mock.recorded("DELETE", &pod_path(NAME)).is_empty(),
        "a foreign pod must never be deleted"
    );
}

#[tokio::test]
async fn stop_of_an_absent_pod_is_success() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        &pod_path(NAME),
        404,
        status_body(404, "NotFound", "not found"),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let recorded = Pod {
        name: NAME.to_owned(),
        uid: POD_UID.to_owned(),
        run_id: RUN_ID.to_owned(),
        fence: FENCE,
        phase: "Running".to_owned(),
        exit_code: None,
    };
    assert!(
        kata.stop(&recorded).await.expect("stop"),
        "an absent pod is already stopped"
    );
    assert!(
        mock.recorded("DELETE", &pod_path(NAME)).is_empty(),
        "nothing to delete"
    );
}

// ── the inventory ───────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn list_maps_every_item_through_the_record_parser() {
    let mock = MockApi::new();
    let url = mock.start().await;
    mock.reply(
        "GET",
        &pods_path(),
        200,
        json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [
                pod_json("mcp-one", POD_UID, RUN_ID, 1),
                pod_json("mcp-two", "uid-two", RUN_ID, 2),
            ],
        }),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    let pods = kata.list().await.expect("list");
    assert_eq!(pods.len(), 2);
    assert_eq!(pods[0].name, "mcp-one");
    assert_eq!(pods[1].fence, 2);

    // A single foreign pod in the page refuses the whole inventory: the executor cannot tell
    // which pods it owns, so it must not treat the page as its own.
    let mock = MockApi::new();
    let url = mock.start().await;
    let mut foreign = pod_json("mcp-foreign", "uid-three", RUN_ID, 3);
    foreign["metadata"]["labels"]["app.kubernetes.io/managed-by"] = json!("someone-else");
    mock.reply(
        "GET",
        &pods_path(),
        200,
        json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {},
            "items": [pod_json("mcp-one", POD_UID, RUN_ID, 1), foreign],
        }),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    assert_eq!(
        denial(kata.list().await),
        "the pod is not managed by this executor"
    );
}

#[tokio::test]
async fn list_refuses_an_inventory_it_cannot_page() {
    let mock = MockApi::new();
    let url = mock.start().await;
    let items: Vec<Value> = (0..200)
        .map(|index| pod_json(&format!("mcp-run-{index}"), POD_UID, RUN_ID, FENCE))
        .collect();
    mock.reply(
        "GET",
        &pods_path(),
        200,
        json!({
            "apiVersion": "v1",
            "kind": "PodList",
            "metadata": {"continue": "page-two"},
            "items": items,
        }),
    );
    let kata = backend(&url, worker_settings(&fixture()["settings"]));
    assert_eq!(
        denial(kata.list().await),
        "runner pod inventory exceeds capacity"
    );
    let lists = mock.recorded("GET", &pods_path());
    assert_eq!(lists.len(), 1, "a paged inventory is refused, not followed");
    assert!(
        lists[0].query.contains("limit=200"),
        "the inventory page is bounded: {}",
        lists[0].query
    );
    assert!(
        lists[0].query.contains("managed-by%3Dmcp-executor"),
        "the inventory is this executor's: {}",
        lists[0].query
    );
}

// ── the attach channel's buffered reads ─────────────────────────────────────────────────

#[tokio::test]
async fn receive_drains_only_bytes_already_written() {
    let (stdout_reader, mut stdout_writer) = tokio::io::simplex(1024);
    let (stderr_reader, mut stderr_writer) = tokio::io::simplex(1024);
    let mut channel = KataAttach::from_streams(None, Some(stdout_reader), Some(stderr_reader));

    // Open pipes with nothing written: the reference's `(b"", b"")`, never `None`. The call
    // returns immediately because each read is raced against a zero-duration deadline; if it
    // blocked, this test would never finish.
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((Vec::new(), Vec::new()))
    );

    stdout_writer
        .write_all(b"{\"type\":\"ready\"}\n")
        .await
        .expect("write stdout");
    stderr_writer
        .write_all(b"runner warning\n")
        .await
        .expect("write stderr");
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((
            b"{\"type\":\"ready\"}\n".to_vec(),
            b"runner warning\n".to_vec()
        ))
    );
    // Everything buffered has been drained; the stream is still open.
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((Vec::new(), Vec::new()))
    );

    // Split `simplex` halves share one stream, so dropping the writer does not surface EOF on
    // the reader; closure comes from the attach status (the websocket ending) or an explicit
    // close, exactly like the reference's `is_open()`.
    drop(stdout_writer);
    drop(stderr_writer);
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((Vec::new(), Vec::new())),
        "an open attach with no bytes is the reference's (b\"\", b\"\")"
    );
    channel.close().await;
    channel.close().await; // idempotent
    assert_eq!(channel.receive().await.expect("receive"), None);
}

#[tokio::test]
async fn the_attach_status_is_the_closure_signal() {
    let (stdout_reader, mut stdout_writer) = tokio::io::simplex(1024);
    let (stderr_reader, _stderr_writer) = tokio::io::simplex(1024);
    let (closed_tx, closed_rx) = tokio::sync::oneshot::channel::<()>();
    let status = Box::pin(async move {
        let _ = closed_rx.await;
    });
    let mut channel =
        KataAttach::from_streams_with_close(Some(stdout_reader), Some(stderr_reader), status);

    stdout_writer
        .write_all(b"{\"type\":\"result\",\"result\":{}}\n")
        .await
        .expect("write stdout");
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((
            b"{\"type\":\"result\",\"result\":{}}\n".to_vec(),
            Vec::new()
        ))
    );
    assert_eq!(
        channel.receive().await.expect("receive"),
        Some((Vec::new(), Vec::new())),
        "the attach is still open"
    );
    closed_tx.send(()).expect("close the attach");
    // The status future resolves on its next poll; a zero-budget poll sees it immediately.
    let mut closed = false;
    for _ in 0..10 {
        let answer = channel.receive().await.expect("receive");
        if answer.is_none() {
            closed = true;
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(closed, "a closed attach answers None");
}

#[tokio::test]
async fn send_writes_the_frame_to_stdin() {
    let (stdin_reader, stdin_writer) = tokio::io::simplex(1024);
    let mut channel = KataAttach::from_streams(Some(stdin_writer), None, None);
    channel
        .send(b"{\"type\":\"api_result\"}\n")
        .await
        .expect("send");
    let mut reader = stdin_reader;
    let mut buffer = vec![0u8; 64];
    let read = tokio::time::timeout(Duration::from_secs(1), reader.read(&mut buffer))
        .await
        .expect("the write reached stdin")
        .expect("read");
    assert_eq!(&buffer[..read], b"{\"type\":\"api_result\"}\n");
}

// ── paths ────────────────────────────────────────────────────────────────────────────────

const RUNTIME_CLASS_PATH: &str = "/apis/node.k8s.io/v1/runtimeclasses/kata-qemu";

fn pods_path() -> String {
    format!("/api/v1/namespaces/{NAMESPACE}/pods")
}

fn pod_path(name: &str) -> String {
    format!("{}/{name}", pods_path())
}
