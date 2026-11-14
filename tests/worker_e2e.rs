//! The controller end to end: a real Postgres 18, a real broker against a real local upstream,
//! the real claim scheduler and the real controller.
//!
//! Kubernetes is the one external boundary, so the backend is a fake that speaks runner
//! protocol v1 over a `tokio` duplex channel: the controller's side is an [`AttachChannel`],
//! the runner's side is a scripted peer that reads and writes the same wire frames the live
//! runner image does. Everything else — the fenced run store, the lease, the frame decoder, the
//! broker's journal, policy and HTTP call, and the terminal classification — is production
//! code.

mod support;

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::net::TcpListener;
use tokio::sync::watch;

use mcp_server_rs::auth::licenses::LicenceAuthority;
use mcp_server_rs::auth::{
    AuthError, BoxFuture, LicenseIdentity, Principal, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::Name;
use mcp_server_rs::catalog::models::{ToolLimits, ToolManifest};
use mcp_server_rs::catalog::resolver::{CatalogResolver, ResolvedTool};
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use mcp_server_rs::config::{ExecutionSettings, WorkerSettings};
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::storage::executions::ExecutionRepository;
use mcp_server_rs::worker::backend::{AttachChannel, Backend, BackendError, Pod, pod_name};
use mcp_server_rs::worker::broker::Broker;
use mcp_server_rs::worker::broker::auth::AuthAdapters;
use mcp_server_rs::worker::broker::egress::{
    EgressPolicy, PlatformClients, PoolLimits, SystemResolver, tenant_client,
};
use mcp_server_rs::worker::broker::limits::SourceLimiter;
use mcp_server_rs::worker::controller::Controller;
use mcp_server_rs::worker::creds::{CredentialResolver, FileResolver};
use mcp_server_rs::worker::protocol::{Frame, decode, encode};
use mcp_server_rs::worker::recovery::Recovery;
use mcp_server_rs::worker::row::WorkerRow;
use mcp_server_rs::worker::scheduler::Scheduler;
use mcp_server_rs::worker::sources::SourceRegistry;
use mcp_server_rs::worker::store::WorkerStore;

use support::{
    Fixture, GATEWAY_APP_KEY, LICENCE_ID, OPERATION_ALPHA, PROFILE, SERVICE_ID, TENANT_A,
    TOOL_ALPHA, authority, binding_fixture_with_tools, create_binding, uuid7, version,
};

/// The one worker slot every test provisions.
const SLOT: i32 = 1;

/// The two credentials the mounted bundle carries. The licence authority is an external
/// boundary (the licences service), so the test fixes its answers; the broker's preflight
/// introspects both before a pod is allocated.
const GATEWAY_TOKEN: &str = "gateway-token-0123456789";
const SERVICE_TOKEN: &str = "service-token-0123456789";

struct Tokens;

impl LicenceAuthority for Tokens {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move { identity_for(token) })
    }

    fn authenticate_for_app<'a>(
        &'a self,
        token: &'a str,
        _app_key: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move { identity_for(token) })
    }
}

fn identity_for(token: &str) -> Result<LicenseIdentity, AuthError> {
    if token != GATEWAY_TOKEN && token != SERVICE_TOKEN {
        return Err(AuthError::Unauthorized);
    }
    Ok(LicenseIdentity {
        tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("licence identity"),
        subject: "svc:test:mcp".to_owned(),
        subject_kind: Some(SubjectKind::Tenant),
    })
}

// ── settings ──────────────────────────────────────────────────────────────────────────────

/// Short, whole-second timings: the lease, the heartbeat and the start allowance are all
/// settings, so no test waits on a production interval.
fn settings(start_timeout_secs: u64) -> WorkerSettings {
    WorkerSettings {
        global_slots: 1,
        per_tenant_slots: 1,
        run_start_timeout: Duration::from_secs(start_timeout_secs),
        run_max: Duration::from_secs(5),
        lease: Duration::from_secs(6),
        heartbeat: Duration::from_secs(1),
        reconcile: Duration::from_secs(1),
        ..WorkerSettings::default()
    }
}

// ── the sandbox boundary (the one legitimate fake) ────────────────────────────────────────

/// What the scripted runner does once the executor attaches.
#[derive(Debug, Clone, Copy)]
enum Script {
    /// Read `init`, `ready`, one `api_call`, echo the call back, result, exit 0.
    Succeed,
    /// Read `init` and never send `ready`.
    Silent,
    /// Read `init`, send `ready` and a valid result, then exit non-zero.
    NonZero,
    /// Read `init`, send `ready`, then hold the channel until the executor stops it.
    Hold,
}

#[derive(Clone, Default)]
struct FakeBackend {
    pods: Arc<Mutex<HashMap<String, Pod>>>,
    scripts: Arc<Mutex<HashMap<String, Script>>>,
    /// The executor's half of each channel, present between `start` and `attach`.
    channels: Arc<Mutex<HashMap<String, DuplexStream>>>,
    attached: Arc<Mutex<Vec<String>>>,
    stopped: Arc<Mutex<Vec<String>>>,
}

impl FakeBackend {
    fn new() -> Self {
        Self::default()
    }

    /// The script the next pod for `run_id` behaves as.
    fn script(&self, run_id: &str, script: Script) {
        self.scripts
            .lock()
            .expect("scripts")
            .insert(run_id.to_owned(), script);
    }

    fn stopped(&self) -> Vec<String> {
        self.stopped.lock().expect("stopped").clone()
    }

    fn attached(&self) -> Vec<String> {
        self.attached.lock().expect("attached").clone()
    }

    fn terminate(&self, name: &str, phase: &str, exit_code: Option<i32>) {
        if let Some(pod) = self.pods.lock().expect("pods").get_mut(name) {
            pod.phase = phase.to_owned();
            pod.exit_code = exit_code;
        }
    }
}

#[async_trait]
impl Backend for FakeBackend {
    async fn ready(&self) -> Result<(), BackendError> {
        Ok(())
    }

    async fn inspect(&self, name: &str) -> Result<Option<Pod>, BackendError> {
        Ok(self.pods.lock().expect("pods").get(name).cloned())
    }

    async fn start(&self, row: &WorkerRow, _limits: &ToolLimits) -> Result<Pod, BackendError> {
        let name = pod_name(&row.run.run_id, row.fence);
        let pod = Pod {
            name: name.clone(),
            uid: format!("uid-{name}"),
            run_id: row.run.run_id.to_string(),
            fence: row.fence,
            phase: "Running".to_owned(),
            exit_code: None,
        };
        self.pods
            .lock()
            .expect("pods")
            .insert(name.clone(), pod.clone());

        let script = self
            .scripts
            .lock()
            .expect("scripts")
            .get(&row.run.run_id.to_string())
            .copied()
            .unwrap_or(Script::Hold);
        let (executor, runner) = tokio::io::duplex(1 << 20);
        self.channels
            .lock()
            .expect("channels")
            .insert(name.clone(), executor);
        let backend = self.clone();
        let pod_for_task = pod.clone();
        tokio::spawn(async move {
            run_script(script, runner, pod_for_task, backend).await;
        });
        Ok(pod)
    }

    async fn attach(&self, pod: &Pod) -> Result<Box<dyn AttachChannel>, BackendError> {
        self.attached
            .lock()
            .expect("attached")
            .push(pod.name.clone());
        let stream = self
            .channels
            .lock()
            .expect("channels")
            .remove(&pod.name)
            .ok_or(BackendError::Denied("no attachable channel"))?;
        Ok(Box::new(Attached { stream }))
    }

    async fn stop(&self, pod: &Pod) -> Result<bool, BackendError> {
        self.stopped.lock().expect("stopped").push(pod.name.clone());
        self.pods.lock().expect("pods").remove(&pod.name);
        Ok(true)
    }

    async fn list(&self) -> Result<Vec<Pod>, BackendError> {
        Ok(self.pods.lock().expect("pods").values().cloned().collect())
    }
}

/// The executor's end of the runner channel.
struct Attached {
    stream: DuplexStream,
}

#[async_trait]
impl AttachChannel for Attached {
    async fn send(&mut self, data: &[u8]) -> Result<(), BackendError> {
        self.stream
            .write_all(data)
            .await
            .map_err(|_| BackendError::Transport("runner write".to_owned()))
    }

    async fn receive(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, BackendError> {
        let mut chunk = [0u8; 8192];
        match self.stream.read(&mut chunk).await {
            Ok(0) => Ok(None),
            Ok(read) => Ok(Some((chunk[..read].to_vec(), Vec::new()))),
            Err(_) => Ok(None),
        }
    }

    async fn close(&mut self) {
        let _ = self.stream.shutdown().await;
    }
}

/// One scripted runner: a line-buffered protocol peer.
struct Runner {
    stream: DuplexStream,
    buffer: Vec<u8>,
}

impl Runner {
    async fn read(&mut self) -> Option<Frame> {
        loop {
            if let Some(end) = self.buffer.iter().position(|byte| *byte == b'\n') {
                let wire: Vec<u8> = self.buffer.drain(..=end).collect();
                return Some(decode(&wire, 1 << 20).expect("the runner receives valid frames"));
            }
            let mut chunk = [0u8; 8192];
            match self.stream.read(&mut chunk).await {
                Ok(0) => return None,
                Ok(read) => self.buffer.extend_from_slice(&chunk[..read]),
                Err(_) => return None,
            }
        }
    }

    async fn write(&mut self, frame: &Frame) {
        let wire = encode(frame, 1 << 20).expect("the runner writes valid frames");
        let _ = self.stream.write_all(&wire).await;
    }

    async fn drain_until_closed(&mut self) {
        let mut chunk = [0u8; 4096];
        while matches!(self.stream.read(&mut chunk).await, Ok(read) if read > 0) {}
    }
}

async fn run_script(script: Script, stream: DuplexStream, pod: Pod, backend: FakeBackend) {
    let mut runner = Runner {
        stream,
        buffer: Vec::new(),
    };
    let init = runner.read().await.expect("init");
    assert!(
        matches!(init, Frame::Init { protocol: 1, .. }),
        "the first frame is a protocol-1 init"
    );
    match script {
        Script::Silent => runner.drain_until_closed().await,
        Script::Hold => {
            runner.write(&Frame::Ready { protocol: 1 }).await;
            runner.drain_until_closed().await;
        }
        Script::Succeed => {
            runner.write(&Frame::Ready { protocol: 1 }).await;
            runner
                .write(&Frame::ApiCall {
                    sequence: 1,
                    operation_id: OPERATION_ALPHA.to_owned(),
                    arguments: Map::new(),
                    idempotency_key: None,
                })
                .await;
            let answer = runner.read().await.expect("the api result");
            match answer {
                Frame::ApiResult {
                    sequence: 1,
                    result: Some(value),
                    error: None,
                } => assert_eq!(value["id"], "up-1"),
                other => panic!("unexpected api result: {other:?}"),
            }
            runner
                .write(&Frame::Result {
                    result: json!({"id": "up-1"}),
                })
                .await;
            backend.terminate(&pod.name, "Succeeded", Some(0));
            let _ = runner.stream.shutdown().await;
        }
        Script::NonZero => {
            runner.write(&Frame::Ready { protocol: 1 }).await;
            runner
                .write(&Frame::Result {
                    result: json!({"id": "up-1"}),
                })
                .await;
            backend.terminate(&pod.name, "Failed", Some(1));
            let _ = runner.stream.shutdown().await;
        }
    }
}

// ── the harness ───────────────────────────────────────────────────────────────────────────

struct Harness {
    fixture: Fixture,
    store: WorkerStore,
    resolver: CatalogResolver,
    principal: Principal,
    resolved: ResolvedTool,
    worker: String,
    settings: WorkerSettings,
    broker: Arc<Broker>,
    backend: Arc<FakeBackend>,
    shutdown: watch::Sender<bool>,
    bundle: PathBuf,
    upstream_hits: Arc<AtomicUsize>,
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.bundle);
    }
}

impl Harness {
    async fn new(start_timeout_secs: u64) -> Self {
        let fixture = Fixture::new().await;
        let settings = settings(start_timeout_secs);

        // A real local upstream. The registered source is platform-owned and unauthenticated,
        // so the broker calls it through the platform client with no credential material.
        let (base_url, upstream_hits) = upstream().await;

        // The tool is a `kata_python` tool whose operation is the fixture's published one; its
        // result schema is narrowed so a wrong result would be refused.
        let mut value = serde_json::to_value(support::kata_manifest()).expect("kata manifest json");
        value["result_schema"] = json!({
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
            "additionalProperties": false
        });
        let manifest: ToolManifest = serde_json::from_value(value).expect("kata manifest");
        binding_fixture_with_tools(&fixture, std::slice::from_ref(&manifest)).await;
        seed_source(&fixture.pool, &base_url).await;
        // The service is platform-owned and the run's tenant may use it.
        sqlx::query(
            "INSERT INTO public.mcp_service_grants(service_id, grantee_tenant_id, granted_by) \
             VALUES ($1::uuid, $2::uuid, $3)",
        )
        .bind(SERVICE_ID)
        .bind(TENANT_A)
        .bind(support::actor_snapshot())
        .execute(&fixture.pool)
        .await
        .expect("service grant");

        let created = create_binding(&fixture.app()).await;
        let binding = created["binding"]["binding_id"]
            .as_str()
            .expect("binding identity")
            .to_owned();
        let revision = created["binding"]["revision"]
            .as_i64()
            .expect("binding revision");
        let principal = Principal {
            tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("tenant identity"),
            license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("licence identity"),
            subject: "agent-09".to_owned(),
            binding_id: Some(Rfc4122Uuid::parse(&binding).expect("binding identity")),
            binding_revision: Some(revision),
            management: false,
            platform: false,
        };
        let resolved = ResolvedTool {
            manifest: manifest.clone(),
            effective: EffectiveTool {
                tool: ToolReference {
                    id: uuid7(TOOL_ALPHA),
                    version: version(1),
                    tenant_id: authority(TENANT_A),
                },
                operation_constraints: Vec::new(),
                limits: ToolLimits::default(),
                public_name: Name::new("alpha_tool").expect("public name"),
            },
            context: BoundContext {
                tenant_id: authority(TENANT_A),
                project_id: None,
                workspace_id: None,
                project_phase: None,
                work_type: None,
                card_stage: None,
                responsibility: None,
                test_command: None,
                reviewed_commit: None,
            },
        };

        let bundle = write_bundle();
        let credentials: Arc<dyn CredentialResolver> = Arc::new(FileResolver::new(&bundle));
        let resolver = CatalogResolver::new(
            fixture.pool.clone(),
            fixture.service(),
            vec![
                manifest
                    .runner_image_digest
                    .as_ref()
                    .expect("runner digest")
                    .as_str()
                    .to_owned(),
            ],
        );

        let egress = Arc::new(EgressPolicy::from_settings(
            &settings,
            Arc::new(SystemResolver),
        ));
        let platform_http = PlatformClients::new(PoolLimits::default());
        let platform_client = platform_http.client_for(None).expect("platform client");
        let tenant_http = tenant_client(&egress, Some(PoolLimits::default()))
            .build()
            .expect("tenant client");
        let limiter = SourceLimiter::new(
            settings.builder_source_calls_per_minute,
            settings.builder_source_concurrency,
        );
        let auth = AuthAdapters::new(
            (*platform_client).clone(),
            tenant_http,
            settings.builder_oauth_token_max_ttl,
        );
        let licences: Arc<dyn LicenceAuthority> = Arc::new(Tokens);
        let sources = SourceRegistry::new(fixture.pool.clone(), None).expect("source registry");
        let store = WorkerStore::new(
            fixture.pool.clone(),
            settings.clone(),
            ExecutionSettings::default(),
        );
        let broker = Arc::new(Broker::new(
            fixture.pool.clone(),
            store.clone(),
            settings.clone(),
            ExecutionSettings::default(),
            CatalogRepository::new(fixture.pool.clone()),
            resolver.clone(),
            credentials,
            licences,
            sources,
            auth,
            egress,
            limiter,
            platform_http,
            Some(GATEWAY_APP_KEY.to_owned()),
            // The reserved tenant the database itself calls the platform tenant.
            authority("01900000-0000-7000-8000-00000000f001"),
        ));

        let (shutdown, _) = watch::channel(false);
        Self {
            fixture,
            store,
            resolver,
            principal,
            resolved,
            worker: uuid::Uuid::now_v7().to_string(),
            settings,
            broker,
            backend: Arc::new(FakeBackend::new()),
            shutdown,
            bundle,
            upstream_hits,
        }
    }

    fn controller(&self) -> Controller {
        Controller::new(
            self.store.clone(),
            self.resolver.clone(),
            self.broker.clone(),
            self.backend.clone(),
            self.fixture.pool.clone(),
            self.settings.clone(),
            ExecutionSettings::default(),
            self.shutdown.subscribe(),
        )
    }

    /// Accept one run through the real execution repository.
    async fn accepted(&self) -> RunRow {
        let generation: i64 =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_one(&self.fixture.pool)
                .await
                .expect("catalog generation");
        ExecutionRepository::new(self.fixture.pool.clone(), ExecutionSettings::default())
            .accept(
                &self.principal,
                &self.resolved,
                &json!({}),
                None,
                generation,
                None,
            )
            .await
            .expect("accept")
    }

    /// Provision the one slot and claim the accepted run for this worker.
    async fn claimed(&self) -> WorkerRow {
        provision(&self.fixture.pool, self.settings.global_slots).await;
        self.accepted().await;
        Scheduler::new(self.store.clone())
            .claim(&self.worker)
            .await
            .expect("claim")
            .expect("a claimed run")
    }

    fn script(&self, row: &WorkerRow, script: Script) {
        self.backend.script(&row.run.run_id.to_string(), script);
    }
}

/// The real local upstream: one `GET /synthetic` answering the fixture operation's projection.
async fn upstream() -> (String, Arc<AtomicUsize>) {
    let hits = Arc::new(AtomicUsize::new(0));
    let listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    let counter = hits.clone();
    let router = axum::Router::new().route(
        "/synthetic",
        axum::routing::get(move || {
            let counter = counter.clone();
            async move {
                counter.fetch_add(1, Ordering::SeqCst);
                axum::Json(json!({"id": "up-1"}))
            }
        }),
    );
    tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });
    (format!("http://{address}"), hits)
}

/// The platform-owned, unauthenticated source the fixture service names.
async fn seed_source(pool: &PgPool, base_url: &str) {
    // Platform-owned, so the table's tenant-https check does not apply and the broker calls it
    // through the platform client. `kind: none` sends no credential.
    sqlx::query(
        "INSERT INTO public.mcp_sources(source_id, owner_tenant_id, source_key, base_url, auth, \
         created_by, updated_by) \
         VALUES (uuidv7(), '01900000-0000-7000-8000-00000000f001', 'synthetic_destination', \
         $1, $2, $3, $3)",
    )
    .bind(base_url)
    .bind(json!({"kind": "none"}))
    .bind(support::actor_snapshot())
    .execute(pool)
    .await
    .expect("source");
}

/// The mounted credential bundle the profile's references resolve from.
fn write_bundle() -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!(
        "mcp-worker-e2e-bundle-{}-{nanos}.json",
        std::process::id()
    ));
    let bundle = json!({
        "schema_version": 1,
        "entries": [
            {
                "tenant_id": TENANT_A,
                "profile_id": PROFILE,
                "service": "gateway",
                "alias": "gateway",
                "license_id": LICENCE_ID,
                "app_key": GATEWAY_APP_KEY,
                "token": GATEWAY_TOKEN
            },
            {
                "tenant_id": TENANT_A,
                "profile_id": PROFILE,
                "service": "synthetic_service",
                "alias": "synthetic",
                "license_id": LICENCE_ID,
                "app_key": GATEWAY_APP_KEY,
                "token": SERVICE_TOKEN
            }
        ]
    });
    std::fs::write(&path, serde_json::to_vec(&bundle).expect("bundle json")).expect("bundle file");
    path
}

async fn provision(pool: &PgPool, slots: u32) {
    for slot in 1..=i32::try_from(slots).expect("slot count") {
        sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id) VALUES ($1)")
            .bind(slot)
            .execute(pool)
            .await
            .expect("provision slot");
    }
}

// ── assertions ────────────────────────────────────────────────────────────────────────────

async fn run_state(pool: &PgPool, run_id: &str) -> (String, Option<Value>) {
    let row = sqlx::query("SELECT status, error FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("run state");
    (
        row.try_get("status").expect("status"),
        row.try_get("error").expect("error"),
    )
}

async fn run_result(pool: &PgPool, run_id: &str) -> Option<Value> {
    // The reference stores `Jsonb(None)` for a run with no result, which is JSON `null`, not SQL
    // NULL. Normalise it here so "no result was finalized" is one check.
    let stored: Option<Value> =
        sqlx::query_scalar("SELECT result FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(run_id)
            .fetch_one(pool)
            .await
            .expect("run result");
    stored.filter(|value| !value.is_null())
}

async fn events(pool: &PgPool, run_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT kind FROM public.mcp_run_events WHERE run_id = $1::uuid ORDER BY event_id",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("events")
}

async fn slot_run(pool: &PgPool) -> Option<String> {
    sqlx::query_scalar("SELECT run_id::text FROM public.mcp_execution_slots WHERE slot_id = $1")
        .bind(SLOT)
        .fetch_one(pool)
        .await
        .expect("slot")
}

async fn api_calls(pool: &PgPool, run_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT status FROM public.mcp_run_api_calls WHERE run_id = $1::uuid ORDER BY sequence",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("api calls")
}

fn error_code(error: &Option<Value>) -> Option<String> {
    error
        .as_ref()
        .and_then(|value| value.get("code"))
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Wait until the run reaches `status`, or panic after a bounded poll.
async fn await_status(pool: &PgPool, run_id: &str, expected: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (status, _) = run_state(pool, run_id).await;
        if status == expected {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "run {run_id} never reached {expected}; it is {status}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

// ── the controller's outcomes ─────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_claimed_run_starts_runs_and_succeeds_through_a_real_upstream_call() {
    let harness = Harness::new(5).await;
    let row = harness.claimed().await;
    harness.script(&row, Script::Succeed);

    harness.controller().execute(row.clone()).await;

    let run_id = row.run.run_id.to_string();
    let (status, error) = run_state(&harness.fixture.pool, &run_id).await;
    assert_eq!(status, RunStatus::Succeeded.as_str());
    assert!(
        error.is_none(),
        "a succeeded run carries no error: {error:?}"
    );
    assert_eq!(
        run_result(&harness.fixture.pool, &run_id).await,
        Some(json!({"id": "up-1"}))
    );
    // The lifecycle is the reference's, in order.
    let kinds = events(&harness.fixture.pool, &run_id).await;
    let tail = &kinds[kinds.len() - 3..];
    assert_eq!(tail, &["starting", "running", "succeeded"][..]);
    // One real upstream call, journalled and completed.
    assert_eq!(harness.upstream_hits.load(Ordering::SeqCst), 1);
    assert_eq!(api_calls(&harness.fixture.pool, &run_id).await.len(), 1);
    assert_ne!(api_calls(&harness.fixture.pool, &run_id).await[0], "intent");
    // The pod was attached (the same UID ran) and stopped.
    assert_eq!(harness.backend.attached().len(), 1);
    assert_eq!(harness.backend.stopped().len(), 1);
    // Absence was proved, so the slot is free again.
    assert_eq!(slot_run(&harness.fixture.pool).await, None);
}

#[tokio::test]
async fn a_runner_that_never_sends_ready_times_out_at_the_start_deadline() {
    let harness = Harness::new(1).await;
    let row = harness.claimed().await;
    harness.script(&row, Script::Silent);

    harness.controller().execute(row.clone()).await;

    let run_id = row.run.run_id.to_string();
    let (status, error) = run_state(&harness.fixture.pool, &run_id).await;
    assert_eq!(status, RunStatus::TimedOut.as_str());
    assert_eq!(error_code(&error).as_deref(), Some("deadline_exceeded"));
    // No result was ever finalized, and the pod was still stopped.
    assert!(run_result(&harness.fixture.pool, &run_id).await.is_none());
    assert_eq!(harness.backend.stopped().len(), 1);
    assert_eq!(slot_run(&harness.fixture.pool).await, None);
}

#[tokio::test]
async fn a_runner_that_exits_non_zero_interrupts_the_run() {
    let harness = Harness::new(5).await;
    let row = harness.claimed().await;
    harness.script(&row, Script::NonZero);

    harness.controller().execute(row.clone()).await;

    let run_id = row.run.run_id.to_string();
    let (status, error) = run_state(&harness.fixture.pool, &run_id).await;
    // A pod existed and may have acted: the reference never requeues or replays it.
    assert_eq!(status, RunStatus::Interrupted.as_str());
    assert_eq!(error_code(&error).as_deref(), Some("execution_interrupted"));
    assert!(run_result(&harness.fixture.pool, &run_id).await.is_none());
    assert_eq!(harness.backend.stopped().len(), 1);
}

#[tokio::test]
async fn worker_shutdown_interrupts_a_live_run_as_worker_stopped() {
    let harness = Harness::new(5).await;
    let row = harness.claimed().await;
    harness.script(&row, Script::Hold);
    let run_id = row.run.run_id.to_string();

    let controller = harness.controller();
    let execution = tokio::spawn(async move { controller.execute(row).await });
    await_status(&harness.fixture.pool, &run_id, RunStatus::Running.as_str()).await;

    harness.shutdown.send(true).expect("shutdown");
    execution
        .await
        .expect("the controller finishes its cleanup");

    let (status, error) = run_state(&harness.fixture.pool, &run_id).await;
    assert_eq!(status, RunStatus::Interrupted.as_str());
    assert_eq!(error_code(&error).as_deref(), Some("worker_stopped"));
    assert_eq!(harness.backend.stopped().len(), 1);
    assert_eq!(slot_run(&harness.fixture.pool).await, None);
}

#[tokio::test]
async fn a_second_workers_claim_cannot_take_a_live_run() {
    let harness = Harness::new(5).await;
    let row = harness.claimed().await;
    let first = row.worker_id.clone().expect("the claiming worker");

    // The live run owns the only slot; a second worker's claim finds nothing.
    let other = uuid::Uuid::now_v7().to_string();
    let stolen = Scheduler::new(harness.store.clone())
        .claim(&other)
        .await
        .expect("claim");
    assert!(stolen.is_none(), "a live run cannot be claimed twice");

    // The run is untouched: still the first worker's, same fence.
    let current: (Option<String>, i64) = sqlx::query_as(
        "SELECT worker_id::text, fence FROM public.mcp_runs WHERE run_id = $1::uuid",
    )
    .bind(row.run.run_id.to_string())
    .fetch_one(&harness.fixture.pool)
    .await
    .expect("run ownership");
    assert_eq!(current.0.as_deref(), Some(first.as_str()));
    assert_eq!(current.1, row.fence);
}

#[tokio::test]
async fn recovery_takes_over_a_dead_workers_run() {
    let harness = Harness::new(5).await;
    // A claimed run whose lease expired with the worker gone: interrupted/worker_lost, and the
    // slot freed once the pod is confirmed absent.
    let run_id = dead_claimed_run(&harness.fixture.pool, SLOT).await;

    Recovery::new(harness.store.clone(), harness.backend.clone())
        .reconcile(&uuid::Uuid::now_v7().to_string())
        .await
        .expect("reconcile");

    let (status, error) = run_state(&harness.fixture.pool, &run_id).await;
    assert_eq!(status, RunStatus::Interrupted.as_str());
    assert_eq!(error_code(&error).as_deref(), Some("worker_lost"));
    assert_eq!(slot_run(&harness.fixture.pool).await, None);
}

/// A `starting`/`running` run whose lease is already expired and which owns the slot: exactly
/// what a worker that died mid-run leaves behind.
async fn dead_claimed_run(pool: &PgPool, slot: i32) -> String {
    let authority = json!({
        "manifest": "{}",
        "effective": serde_json::to_string(&json!({"limits": ToolLimits::default()}))
            .expect("limits json"),
        "context": "{}",
    });
    let run_id: String = sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,mode) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}'::jsonb,$4,'{}'::jsonb,$5, \
         '{}'::jsonb, clock_timestamp() + interval '60 seconds','draft') \
         RETURNING run_id::text",
    )
    .bind(TENANT_A)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind(authority)
    .bind("c".repeat(64))
    .fetch_one(pool)
    .await
    .expect("queue run");
    // `mcp_guard_run` only permits queued → starting → running, so the dead claim is two
    // statements, exactly the path a worker takes.
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, fence = 1, \
         lease_until = clock_timestamp() - interval '1 second', heartbeat_at = clock_timestamp(), \
         start_deadline = clock_timestamp() - interval '1 minute' WHERE run_id = $2::uuid",
    )
    .bind(uuid::Uuid::now_v7().to_string())
    .bind(&run_id)
    .execute(pool)
    .await
    .expect("dead claim");
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'running', \
         started_at = clock_timestamp() - interval '1 minute', \
         deadline = clock_timestamp() + interval '10 minutes' WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .execute(pool)
    .await
    .expect("dead running");
    sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id, run_id) VALUES ($1, $2::uuid)")
        .bind(slot)
        .bind(&run_id)
        .execute(pool)
        .await
        .expect("attach slot");
    run_id
}
