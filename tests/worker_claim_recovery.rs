//! The claim scheduler and lease recovery against a real Postgres 18.
//!
//! Every run is accepted by the real `ExecutionRepository` or seeded through the same tables the
//! repository writes, so the authority snapshot, the fence and the deadlines have production
//! shape. The runner backend is the one legitimate fake: Kubernetes is an external boundary, and
//! the recovery semantics under test are exactly what the worker asks a backend to prove (the
//! pod's identity, whether a delete was confirmed, and the managed inventory).

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::catalog::ids::Name;
use mcp_server_rs::catalog::models::{ToolLimits, ToolManifest};
use mcp_server_rs::catalog::resolver::ResolvedTool;
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use mcp_server_rs::config::{ExecutionSettings, WorkerSettings};
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::storage::executions::ExecutionRepository;
use mcp_server_rs::worker::backend::{AttachChannel, Backend, BackendError, Pod, pod_name};
use mcp_server_rs::worker::recovery::Recovery;
use mcp_server_rs::worker::row::WorkerRow;
use mcp_server_rs::worker::scheduler::Scheduler;
use mcp_server_rs::worker::store::{WorkerStore, WorkerStoreError};

use support::{
    Fixture, LICENCE_ID, OPERATION_ALPHA, TENANT_A, TOOL_ALPHA, authority,
    binding_fixture_with_tools, create_binding, insert_published_tool, kata_manifest,
    tool_manifest, uuid7, version,
};

const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const TENANT_C: &str = "10000000-0000-7000-8000-000000000003";

/// The reference's lease and start/wall bounds, with the capacity the test varies.
fn settings(global_slots: u32, per_tenant_slots: u32) -> WorkerSettings {
    WorkerSettings {
        global_slots,
        per_tenant_slots,
        run_start_timeout: Duration::from_secs(20),
        lease: Duration::from_secs(30),
        run_max: Duration::from_secs(60),
        ..WorkerSettings::default()
    }
}

/// One fixture with the catalog a `kata_python` run needs, plus a claimed worker identity.
struct Harness {
    fixture: Fixture,
    store: WorkerStore,
    principal: Principal,
    resolved: ResolvedTool,
    /// A real executor identity: the DDL requires a version-7 worker id.
    worker: String,
}

impl Harness {
    async fn new(limits: ToolLimits, settings: WorkerSettings) -> Self {
        let fixture = Fixture::new().await;
        // The claim only considers `kata_python` runs; the shared fixture's default manifest is
        // an n8n tool, so this harness accepts through the Kata variant.
        let manifest = kata_manifest();
        binding_fixture_with_tools(&fixture, std::slice::from_ref(&manifest)).await;
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
            manifest,
            effective: EffectiveTool {
                tool: ToolReference {
                    id: uuid7(TOOL_ALPHA),
                    version: version(1),
                    tenant_id: authority(TENANT_A),
                },
                operation_constraints: Vec::new(),
                limits,
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
        Self {
            store: WorkerStore::new(fixture.pool.clone(), settings, ExecutionSettings::default()),
            fixture,
            principal,
            resolved,
            worker: uuid::Uuid::now_v7().to_string(),
        }
    }

    /// One accepted run through the real `ExecutionRepository::accept`.
    async fn accept(&self) -> RunRow {
        let generation: i64 =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_one(&self.fixture.pool)
                .await
                .expect("catalog generation");
        ExecutionRepository::new(self.fixture.pool.clone(), ExecutionSettings::default())
            .accept(
                &self.principal,
                &self.resolved,
                &json!({"query": "hello"}),
                None,
                generation,
                None,
            )
            .await
            .expect("accept")
    }

    /// A published tool version for another tenant: an accepted run's tool must be owned by the
    /// run's own tenant, and the DDL's foreign key proves it exists.
    async fn seed_tenant_tool(&self, tenant: &str) {
        let mut value =
            serde_json::to_value(tool_manifest("alpha_tool", TOOL_ALPHA)).expect("manifest json");
        value["tenant_id"] = json!(tenant);
        let manifest: ToolManifest = serde_json::from_value(value).expect("tenant manifest");
        insert_published_tool(&self.fixture, &manifest).await;
    }
}

// ── the sandbox boundary (the one legitimate fake) ────────────────────────────────────────

/// What the fake `stop` reports for one pod.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Stop {
    /// The delete was issued and absence confirmed.
    Confirmed,
    /// The delete was issued but absence could not be confirmed.
    Unconfirmed,
    /// The cluster did not answer.
    Failed,
}

#[derive(Clone, Default)]
struct FakeBackend {
    pods: Arc<Mutex<HashMap<String, Pod>>>,
    outcomes: Arc<Mutex<HashMap<String, Stop>>>,
    inventory: Arc<Mutex<Vec<Pod>>>,
    stopped: Arc<Mutex<Vec<String>>>,
    inspected: Arc<Mutex<Vec<String>>>,
}

impl FakeBackend {
    fn new() -> Self {
        Self::default()
    }

    fn add_pod(&self, pod: Pod, outcome: Stop) {
        let name = pod.name.clone();
        self.pods.lock().expect("pods").insert(name.clone(), pod);
        self.outcomes
            .lock()
            .expect("outcomes")
            .insert(name, outcome);
    }

    fn set_inventory(&self, pods: Vec<Pod>) {
        *self.inventory.lock().expect("inventory") = pods;
    }

    fn stopped(&self) -> Vec<String> {
        self.stopped.lock().expect("stopped").clone()
    }

    fn inspected(&self) -> Vec<String> {
        self.inspected.lock().expect("inspected").clone()
    }
}

#[async_trait]
impl Backend for FakeBackend {
    async fn ready(&self) -> Result<(), BackendError> {
        Ok(())
    }

    async fn inspect(&self, name: &str) -> Result<Option<Pod>, BackendError> {
        self.inspected
            .lock()
            .expect("inspected")
            .push(name.to_owned());
        Ok(self.pods.lock().expect("pods").get(name).cloned())
    }

    async fn start(&self, _row: &WorkerRow, _limits: &ToolLimits) -> Result<Pod, BackendError> {
        Err(BackendError::Denied("start is not used by reconciliation"))
    }

    async fn attach(&self, _pod: &Pod) -> Result<Box<dyn AttachChannel>, BackendError> {
        Err(BackendError::Denied("attach is not used by reconciliation"))
    }

    async fn stop(&self, pod: &Pod) -> Result<bool, BackendError> {
        self.stopped.lock().expect("stopped").push(pod.name.clone());
        let outcome = self
            .outcomes
            .lock()
            .expect("outcomes")
            .get(&pod.name)
            .copied()
            .unwrap_or(Stop::Confirmed);
        match outcome {
            Stop::Confirmed => Ok(true),
            Stop::Unconfirmed => Ok(false),
            Stop::Failed => Err(BackendError::Transport("delete did not answer".to_owned())),
        }
    }

    async fn list(&self) -> Result<Vec<Pod>, BackendError> {
        Ok(self.inventory.lock().expect("inventory").clone())
    }
}

// ── seeding helpers ──────────────────────────────────────────────────────────────────────

async fn provision(pool: &PgPool, slots: i32) {
    for slot in 1..=slots {
        sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id) VALUES ($1)")
            .bind(slot)
            .execute(pool)
            .await
            .expect("provision slot");
    }
}

/// Set a tenant's `last_claimed_at` relative to now.
async fn tenant_lock(pool: &PgPool, tenant: &str, seconds_ago: f64) {
    sqlx::query(
        "INSERT INTO public.mcp_tenant_execution_locks(tenant_id, last_claimed_at) \
         VALUES ($1::uuid, clock_timestamp() - make_interval(secs => $2::double precision)) \
         ON CONFLICT (tenant_id) DO UPDATE SET last_claimed_at = EXCLUDED.last_claimed_at",
    )
    .bind(tenant)
    .bind(seconds_ago)
    .execute(pool)
    .await
    .expect("tenant lock");
}

async fn tenant_claim_time(pool: &PgPool, tenant: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT (extract(epoch FROM last_claimed_at)*1000000)::bigint \
         FROM public.mcp_tenant_execution_locks WHERE tenant_id = $1::uuid",
    )
    .bind(tenant)
    .fetch_one(pool)
    .await
    .expect("tenant claim time")
}

/// The database's clock, so the deadline assertions never depend on the test process's clock.
async fn db_now(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT (extract(epoch FROM clock_timestamp())*1000000)::bigint")
        .fetch_one(pool)
        .await
        .expect("database clock")
}

/// The authority snapshot the worker reads its limits from, exactly the reference's shape: each
/// member is a JSON string.
fn authority_with(limits: ToolLimits) -> Value {
    json!({
        "manifest": "{}",
        "effective": serde_json::to_string(&json!({"limits": limits})).expect("limits json"),
        "context": "{}",
    })
}

/// A queued run with a synthesized authority, for the tenants the catalog fixture does not own.
async fn queue_run(pool: &PgPool, tenant: &str, authority: &Value, queue_seconds: f64) -> String {
    sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,mode) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}'::jsonb,$4,'{}'::jsonb,$5, \
         '{}'::jsonb, clock_timestamp() + make_interval(secs => $6::double precision),'draft') \
         RETURNING run_id::text",
    )
    .bind(tenant)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind(authority.clone())
    .bind("c".repeat(64))
    .bind(queue_seconds)
    .fetch_one(pool)
    .await
    .expect("queue run")
}

/// A claimed run: it starts, optionally runs, and owns one slot. The lease is relative to now,
/// so a negative value is already expired.
async fn claimed_run(
    pool: &PgPool,
    tenant: &str,
    authority: &Value,
    started: bool,
    lease_seconds: f64,
    slot: i32,
) -> String {
    let run_id = queue_run(pool, tenant, authority, 60.0).await;
    let worker = uuid::Uuid::now_v7().to_string();
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, fence = 1, \
         lease_until = clock_timestamp() + make_interval(secs => $2::double precision), \
         heartbeat_at = clock_timestamp(), \
         start_deadline = clock_timestamp() - interval '1 minute', \
         deadline = clock_timestamp() + interval '10 minutes' \
         WHERE run_id = $3::uuid",
    )
    .bind(&worker)
    .bind(lease_seconds)
    .bind(&run_id)
    .execute(pool)
    .await
    .expect("claim the run");
    if started {
        sqlx::query(
            "UPDATE public.mcp_runs SET status = 'running', \
             started_at = clock_timestamp() - interval '1 minute' \
             WHERE run_id = $1::uuid",
        )
        .bind(&run_id)
        .execute(pool)
        .await
        .expect("start the run");
    }
    sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id, run_id) VALUES ($1, $2::uuid)")
        .bind(slot)
        .bind(&run_id)
        .execute(pool)
        .await
        .expect("attach the slot");
    sqlx::query(
        "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) VALUES ($1::uuid,$2::uuid,'starting')",
    )
    .bind(tenant)
    .bind(&run_id)
    .execute(pool)
    .await
    .expect("starting event");
    run_id
}

async fn record_pod(pool: &PgPool, run_id: &str, name: &str, uid: Option<&str>) {
    sqlx::query("UPDATE public.mcp_runs SET pod_name = $1, pod_uid = $2 WHERE run_id = $3::uuid")
        .bind(name)
        .bind(uid)
        .bind(run_id)
        .execute(pool)
        .await
        .expect("record the pod");
}

async fn intent(pool: &PgPool, run_id: &str) {
    sqlx::query(
        "INSERT INTO public.mcp_run_api_calls(tenant_id,run_id,sequence,operation_id,\
         operation_version,request_hash,license_id,effect) \
         VALUES ($1::uuid,$2::uuid,1,$3::uuid,1,$4,$5::uuid,'read_only')",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .bind(OPERATION_ALPHA)
    .bind("e".repeat(64))
    .bind(LICENCE_ID)
    .execute(pool)
    .await
    .expect("journalled intent");
}

fn pod_for(name: &str, run_id: &str, fence: i64, uid: &str) -> Pod {
    Pod {
        name: name.to_owned(),
        uid: uid.to_owned(),
        run_id: run_id.to_owned(),
        fence,
        phase: "Running".to_owned(),
        exit_code: None,
    }
}

struct RunState {
    status: String,
    worker_id: Option<String>,
    fence: i64,
    lease: Option<i64>,
    heartbeat: Option<i64>,
    start_deadline: Option<i64>,
    deadline: Option<i64>,
    started_at: Option<i64>,
    finished_at: Option<i64>,
    error: Option<Value>,
}

async fn run_state(pool: &PgPool, run_id: &str) -> RunState {
    let row = sqlx::query(
        "SELECT status, worker_id::text AS worker_id, fence, \
         (extract(epoch FROM lease_until)*1000000)::bigint AS lease_us, \
         (extract(epoch FROM heartbeat_at)*1000000)::bigint AS heartbeat_us, \
         (extract(epoch FROM start_deadline)*1000000)::bigint AS start_deadline_us, \
         (extract(epoch FROM deadline)*1000000)::bigint AS deadline_us, \
         (extract(epoch FROM started_at)*1000000)::bigint AS started_at_us, \
         (extract(epoch FROM finished_at)*1000000)::bigint AS finished_at_us, error \
         FROM public.mcp_runs WHERE run_id = $1::uuid",
    )
    .bind(run_id)
    .fetch_one(pool)
    .await
    .expect("run state");
    RunState {
        status: row.try_get("status").expect("status"),
        worker_id: row.try_get("worker_id").expect("worker"),
        fence: row.try_get("fence").expect("fence"),
        lease: row.try_get("lease_us").expect("lease"),
        heartbeat: row.try_get("heartbeat_us").expect("heartbeat"),
        start_deadline: row.try_get("start_deadline_us").expect("start deadline"),
        deadline: row.try_get("deadline_us").expect("deadline"),
        started_at: row.try_get("started_at_us").expect("started at"),
        finished_at: row.try_get("finished_at_us").expect("finished at"),
        error: row.try_get("error").expect("error"),
    }
}

async fn slot_state(pool: &PgPool, slot: i32) -> (Option<String>, bool) {
    sqlx::query_as(
        "SELECT run_id::text, quarantined FROM public.mcp_execution_slots WHERE slot_id = $1",
    )
    .bind(slot)
    .fetch_one(pool)
    .await
    .expect("slot state")
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

// ── capacity ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn verify_capacity_requires_the_exact_provisioned_slot_set() {
    let harness = Harness::new(ToolLimits::default(), settings(2, 1)).await;
    let scheduler = Scheduler::new(harness.store.clone());
    let pool = &harness.fixture.pool;

    let absent = scheduler.verify_capacity().await.expect_err("no slots");
    assert!(matches!(absent, WorkerStoreError::Denied));

    provision(pool, 1).await;
    let short = scheduler
        .verify_capacity()
        .await
        .expect_err("one slot short");
    assert!(matches!(short, WorkerStoreError::Denied));

    sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id) VALUES (2)")
        .execute(pool)
        .await
        .expect("second slot");
    scheduler
        .verify_capacity()
        .await
        .expect("the exact provisioned set");

    // Same count, wrong range: the reference refuses rather than inventing capacity.
    sqlx::query("DELETE FROM public.mcp_execution_slots WHERE slot_id = 1")
        .execute(pool)
        .await
        .expect("drop slot 1");
    sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id) VALUES (3)")
        .execute(pool)
        .await
        .expect("slot 3");
    let off_range = scheduler
        .verify_capacity()
        .await
        .expect_err("slots 2 and 3");
    assert!(matches!(off_range, WorkerStoreError::Denied));

    // A draining slot is not capacity.
    sqlx::query("UPDATE public.mcp_execution_slots SET draining = true WHERE slot_id = 3")
        .execute(pool)
        .await
        .expect("drain slot 3");
    let draining = scheduler.verify_capacity().await.expect_err("draining");
    assert!(matches!(draining, WorkerStoreError::Denied));
    harness.fixture.finish().await;
}

// ── the claim ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn claim_takes_the_run_of_the_tenant_with_the_oldest_last_claim() {
    let harness = Harness::new(ToolLimits::default(), settings(2, 1)).await;
    let accepted = harness.accept().await;
    harness.seed_tenant_tool(TENANT_B).await;
    harness.seed_tenant_tool(TENANT_C).await;
    let pool = &harness.fixture.pool;
    provision(pool, 2).await;
    let b = queue_run(pool, TENANT_B, &accepted.authority, 60.0).await;
    let c = queue_run(pool, TENANT_C, &accepted.authority, 60.0).await;
    tenant_lock(pool, TENANT_A, 7_200.0).await;
    tenant_lock(pool, TENANT_B, 3_600.0).await;
    tenant_lock(pool, TENANT_C, 60.0).await;

    let scheduler = Scheduler::new(harness.store.clone());
    let first = scheduler
        .claim(&harness.worker)
        .await
        .expect("claim")
        .expect("a run");
    assert_eq!(first.run.run_id, accepted.run_id, "the oldest claim wins");
    assert_eq!(first.run.tenant_id.to_string(), TENANT_A);

    // Tenant A now holds its one per-tenant slot; the next-oldest tenant wins the second slot.
    let second = scheduler
        .claim(&harness.worker)
        .await
        .expect("claim")
        .expect("a run");
    assert_eq!(second.run.run_id.to_string(), b);
    assert_eq!(second.run.tenant_id.to_string(), TENANT_B);
    assert_eq!(run_state(pool, &c).await.status, "queued");
    harness.fixture.finish().await;
}

#[tokio::test]
async fn claim_refuses_a_tenant_that_already_holds_its_per_tenant_slots() {
    let harness = Harness::new(ToolLimits::default(), settings(2, 1)).await;
    let accepted = harness.accept().await;
    let pool = &harness.fixture.pool;
    provision(pool, 2).await;
    let second_run = queue_run(pool, TENANT_A, &accepted.authority, 60.0).await;
    tenant_lock(pool, TENANT_A, 3_600.0).await;

    let scheduler = Scheduler::new(harness.store.clone());
    let claimed = scheduler
        .claim(&harness.worker)
        .await
        .expect("claim")
        .expect("a run");
    assert_eq!(claimed.run.run_id, accepted.run_id);

    assert!(
        scheduler
            .claim(&harness.worker)
            .await
            .expect("claim")
            .is_none(),
        "the tenant already holds its one slot"
    );
    assert_eq!(run_state(pool, &second_run).await.status, "queued");
    assert_eq!(
        slot_state(pool, 2).await.0,
        None,
        "a slot is free; the tenant bound refused the claim"
    );
    harness.fixture.finish().await;
}

#[tokio::test]
async fn claim_expires_cancelled_and_overdue_queued_runs_before_choosing() {
    let harness = Harness::new(ToolLimits::default(), settings(1, 1)).await;
    let cancelled = harness.accept().await;
    let pool = &harness.fixture.pool;
    // `mcp_guard_run` refuses to rewrite a queued run's snapshot ("run snapshot is immutable"),
    // so the overdue run is inserted with its deadline already in the past — the sweep's own
    // condition, not a mutation it would never see in production.
    let overdue = queue_run(pool, TENANT_A, &cancelled.authority, -1.0).await;
    sqlx::query("UPDATE public.mcp_runs SET cancel_requested = true WHERE run_id = $1::uuid")
        .bind(cancelled.run_id.to_string())
        .execute(pool)
        .await
        .expect("cancel request");

    // No slot is provisioned: the sweep must still be committed before the claim reports no work.
    let scheduler = Scheduler::new(harness.store.clone());
    assert!(
        scheduler
            .claim(&harness.worker)
            .await
            .expect("claim")
            .is_none()
    );

    let cancelled_state = run_state(pool, &cancelled.run_id.to_string()).await;
    assert_eq!(cancelled_state.status, "cancelled");
    assert_eq!(cancelled_state.fence, 0, "an expired run was never claimed");
    assert_eq!(cancelled_state.worker_id, None);
    assert!(cancelled_state.finished_at.is_some());
    let overdue_state = run_state(pool, &overdue).await;
    assert_eq!(overdue_state.status, "timed_out");
    assert!(overdue_state.finished_at.is_some());

    let cancelled_events = events(pool, &cancelled.run_id.to_string()).await;
    assert!(
        cancelled_events.contains(&"cancelled".to_owned()),
        "{cancelled_events:?}"
    );
    let overdue_events = events(pool, &overdue).await;
    assert!(
        overdue_events.contains(&"timed_out".to_owned()),
        "{overdue_events:?}"
    );
    harness.fixture.finish().await;
}

#[tokio::test]
async fn claim_returns_none_when_every_slot_is_occupied() {
    let harness = Harness::new(ToolLimits::default(), settings(1, 1)).await;
    let accepted = harness.accept().await;
    harness.seed_tenant_tool(TENANT_B).await;
    let pool = &harness.fixture.pool;
    provision(pool, 1).await;
    let b = queue_run(pool, TENANT_B, &accepted.authority, 60.0).await;
    tenant_lock(pool, TENANT_A, 7_200.0).await;
    tenant_lock(pool, TENANT_B, 3_600.0).await;

    let scheduler = Scheduler::new(harness.store.clone());
    let first = scheduler
        .claim(&harness.worker)
        .await
        .expect("claim")
        .expect("a run");
    assert_eq!(first.run.run_id, accepted.run_id);

    assert!(
        scheduler
            .claim(&harness.worker)
            .await
            .expect("claim")
            .is_none(),
        "the only slot is occupied"
    );
    assert_eq!(run_state(pool, &b).await.status, "queued");
    let expected = accepted.run_id.to_string();
    assert_eq!(
        slot_state(pool, 1).await.0.as_deref(),
        Some(expected.as_str())
    );
    harness.fixture.finish().await;
}

#[tokio::test]
async fn claim_starts_the_run_from_the_limits_and_settings_and_attaches_the_slot() {
    let limits = ToolLimits {
        wall_seconds: 45,
        ..ToolLimits::default()
    };
    let harness = Harness::new(limits, settings(2, 1)).await;
    let accepted = harness.accept().await;
    let pool = &harness.fixture.pool;
    provision(pool, 2).await;
    tenant_lock(pool, TENANT_A, 3_600.0).await;

    let scheduler = Scheduler::new(harness.store.clone());
    let claimed = scheduler
        .claim(&harness.worker)
        .await
        .expect("claim")
        .expect("a run");
    assert_eq!(claimed.run.status, RunStatus::Starting);
    assert_eq!(claimed.run.run_id, accepted.run_id);
    assert_eq!(claimed.worker_id.as_deref(), Some(harness.worker.as_str()));
    assert_eq!(claimed.fence, 1, "the claim opens a new generation");
    assert!(
        claimed.run.started_at.is_none(),
        "claiming does not start the runner"
    );

    let state = run_state(pool, &accepted.run_id.to_string()).await;
    let now = db_now(pool).await;
    let lease = state.lease.expect("lease");
    let start = state.start_deadline.expect("start deadline");
    let deadline = state.deadline.expect("deadline");
    assert!(
        (now + 25_000_000..=now + 35_000_000).contains(&lease),
        "the 30-second lease: {lease} vs now {now}"
    );
    assert!(
        (now + 15_000_000..=now + 25_000_000).contains(&start),
        "the 20-second start allowance: {start} vs now {now}"
    );
    assert!(
        (44_000_000..=46_000_000).contains(&(deadline - start)),
        "the run's own 45-second wall limit outlives the 60-second run_max: {}",
        deadline - start
    );
    assert!(state.heartbeat.is_some());
    assert_eq!(state.fence, 1);

    let (attached, quarantined) = slot_state(pool, 1).await;
    assert_eq!(attached, Some(accepted.run_id.to_string()));
    assert!(!quarantined);
    assert_eq!(slot_state(pool, 2).await.0, None);
    let run_events = events(pool, &accepted.run_id.to_string()).await;
    assert!(
        run_events.contains(&"starting".to_owned()),
        "{run_events:?}"
    );
    assert!(
        tenant_claim_time(pool, TENANT_A).await > now - 60_000_000,
        "the tenant's last claim was bumped"
    );
    harness.fixture.finish().await;
}

// ── lease recovery ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn reconcile_requeues_a_run_that_never_started() {
    let harness = Harness::new(ToolLimits::default(), settings(1, 1)).await;
    let pool = &harness.fixture.pool;
    let run = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        false,
        -1.0,
        1,
    )
    .await;
    let backend = Arc::new(FakeBackend::new());
    Recovery::new(harness.store.clone(), backend.clone())
        .reconcile(&harness.worker)
        .await
        .expect("reconcile");

    let state = run_state(pool, &run).await;
    assert_eq!(state.status, "queued");
    assert_eq!(state.worker_id, None);
    assert_eq!(state.lease, None);
    assert_eq!(state.start_deadline, None);
    assert_eq!(state.deadline, None);
    assert!(state.started_at.is_none(), "nothing ever started");
    assert_eq!(state.fence, 2, "the old channel is fenced out");
    assert_eq!(slot_state(pool, 1).await, (None, false));
    let run_events = events(pool, &run).await;
    assert!(
        run_events.contains(&"requeued_unstarted".to_owned()),
        "{run_events:?}"
    );
    assert!(backend.inspected().is_empty(), "no pod was ever recorded");
    assert!(backend.stopped().is_empty());
    harness.fixture.finish().await;
}

#[tokio::test]
async fn reconcile_takes_over_a_started_run_and_finishes_it_when_the_pod_is_gone() {
    let harness = Harness::new(ToolLimits::default(), settings(1, 1)).await;
    let pool = &harness.fixture.pool;
    let run = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        true,
        -1.0,
        1,
    )
    .await;
    let name = pod_name(&Rfc4122Uuid::parse(&run).expect("run identity"), 1);
    record_pod(pool, &run, &name, Some("uid-1")).await;
    sqlx::query("UPDATE public.mcp_runs SET api_calls = 1 WHERE run_id = $1::uuid")
        .bind(&run)
        .execute(pool)
        .await
        .expect("api counter");
    intent(pool, &run).await;

    let backend = Arc::new(FakeBackend::new());
    Recovery::new(harness.store.clone(), backend.clone())
        .reconcile(&harness.worker)
        .await
        .expect("reconcile");

    let state = run_state(pool, &run).await;
    assert_eq!(state.status, "interrupted");
    assert_eq!(
        state.error,
        Some(json!({"code": "worker_lost", "message": "worker lost"}))
    );
    assert_eq!(state.worker_id, None, "an absent pod frees ownership");
    assert_eq!(state.lease, None);
    assert!(state.started_at.is_some(), "the run had started");
    assert_eq!(state.fence, 2);
    assert_eq!(slot_state(pool, 1).await, (None, false));
    let (call, finished): (String, bool) = sqlx::query_as(
        "SELECT status, finished_at IS NOT NULL FROM public.mcp_run_api_calls \
         WHERE run_id = $1::uuid AND sequence = 1",
    )
    .bind(&run)
    .fetch_one(pool)
    .await
    .expect("journalled call");
    assert_eq!(call, "outcome_unknown");
    assert!(finished);
    assert_eq!(backend.inspected(), vec![name]);
    assert!(backend.stopped().is_empty(), "a missing pod is not stopped");
    let run_events = events(pool, &run).await;
    assert!(
        run_events.contains(&"interrupted".to_owned()),
        "{run_events:?}"
    );
    harness.fixture.finish().await;
}

#[tokio::test]
async fn reconcile_keeps_ownership_and_quarantines_when_absence_is_unconfirmed() {
    let harness = Harness::new(ToolLimits::default(), settings(2, 1)).await;
    let pool = &harness.fixture.pool;
    let unconfirmed = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        true,
        -10.0,
        1,
    )
    .await;
    let failed = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        true,
        -20.0,
        2,
    )
    .await;
    let unconfirmed_pod = pod_name(&Rfc4122Uuid::parse(&unconfirmed).expect("run"), 1);
    let failed_pod = pod_name(&Rfc4122Uuid::parse(&failed).expect("run"), 1);
    record_pod(pool, &unconfirmed, &unconfirmed_pod, None).await;
    record_pod(pool, &failed, &failed_pod, None).await;

    let backend = Arc::new(FakeBackend::new());
    backend.add_pod(
        pod_for(&unconfirmed_pod, &unconfirmed, 1, "uid-1"),
        Stop::Unconfirmed,
    );
    backend.add_pod(pod_for(&failed_pod, &failed, 1, "uid-2"), Stop::Failed);
    Recovery::new(harness.store.clone(), backend.clone())
        .reconcile(&harness.worker)
        .await
        .expect("reconcile");

    // `stop` answering false is not an exception: the reference finishes the run worker_lost
    // with `absent=false`, which keeps the slot quarantined and the ownership in place.
    let unconfirmed_state = run_state(pool, &unconfirmed).await;
    assert_eq!(unconfirmed_state.status, "interrupted");
    assert_eq!(
        unconfirmed_state.error,
        Some(json!({"code": "worker_lost", "message": "worker lost"}))
    );
    assert_eq!(
        unconfirmed_state.worker_id.as_deref(),
        Some(harness.worker.as_str()),
        "the reconciler keeps what it cannot prove gone"
    );
    assert!(unconfirmed_state.lease.is_some());
    assert_eq!(
        slot_state(pool, 1).await,
        (Some(unconfirmed.clone()), true),
        "capacity stays out of service"
    );

    // An erroring `stop` is an exception: the run is settled cleanup_unconfirmed, quarantined too.
    let failed_state = run_state(pool, &failed).await;
    assert_eq!(failed_state.status, "interrupted");
    assert_eq!(
        failed_state.error,
        Some(json!({
            "code": "cleanup_unconfirmed",
            "message": "cleanup unconfirmed"
        }))
    );
    assert_eq!(
        failed_state.worker_id.as_deref(),
        Some(harness.worker.as_str())
    );
    assert_eq!(slot_state(pool, 2).await, (Some(failed.clone()), true));

    let mut stopped = backend.stopped();
    stopped.sort();
    let mut expected = vec![unconfirmed_pod, failed_pod];
    expected.sort();
    assert_eq!(stopped, expected);
    harness.fixture.finish().await;
}

#[tokio::test]
async fn reconcile_never_adopts_a_pod_whose_label_identity_disagrees() {
    let harness = Harness::new(ToolLimits::default(), settings(2, 1)).await;
    let pool = &harness.fixture.pool;
    let wrong_fence = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        true,
        -10.0,
        1,
    )
    .await;
    let wrong_uid = claimed_run(
        pool,
        TENANT_A,
        &authority_with(ToolLimits::default()),
        true,
        -20.0,
        2,
    )
    .await;
    let fence_pod = pod_name(&Rfc4122Uuid::parse(&wrong_fence).expect("run"), 1);
    let uid_pod = pod_name(&Rfc4122Uuid::parse(&wrong_uid).expect("run"), 1);
    record_pod(pool, &wrong_fence, &fence_pod, None).await;
    record_pod(pool, &wrong_uid, &uid_pod, Some("uid-recorded")).await;

    let backend = Arc::new(FakeBackend::new());
    // Same name and run, but the label names a later generation than the recorded one.
    backend.add_pod(
        pod_for(&fence_pod, &wrong_fence, 2, "uid-1"),
        Stop::Confirmed,
    );
    // Same name, generation and run, but the immutable UID moved.
    backend.add_pod(
        pod_for(&uid_pod, &wrong_uid, 1, "uid-other"),
        Stop::Confirmed,
    );
    Recovery::new(harness.store.clone(), backend.clone())
        .reconcile(&harness.worker)
        .await
        .expect("reconcile");

    for run in [&wrong_fence, &wrong_uid] {
        let state = run_state(pool, run).await;
        assert_eq!(state.status, "interrupted");
        assert_eq!(
            state.error,
            Some(json!({
                "code": "cleanup_unconfirmed",
                "message": "cleanup unconfirmed"
            })),
            "a disagreed pod is a denial, not a confirmation"
        );
        assert_eq!(state.worker_id.as_deref(), Some(harness.worker.as_str()));
    }
    assert_eq!(slot_state(pool, 1).await, (Some(wrong_fence.clone()), true));
    assert_eq!(slot_state(pool, 2).await, (Some(wrong_uid.clone()), true));
    assert!(
        backend.stopped().is_empty(),
        "a pod whose identity disagrees is never touched"
    );
    harness.fixture.finish().await;
}

#[tokio::test]
async fn reconcile_stops_pods_whose_runs_are_missing_or_finished() {
    let harness = Harness::new(ToolLimits::default(), settings(1, 1)).await;
    let pool = &harness.fixture.pool;
    let authority = authority_with(ToolLimits::default());
    let finished = queue_run(pool, TENANT_A, &authority, 60.0).await;
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'failed', finished_at = clock_timestamp() \
         WHERE run_id = $1::uuid",
    )
    .bind(&finished)
    .execute(pool)
    .await
    .expect("finish the run");
    let live = queue_run(pool, TENANT_A, &authority, 60.0).await;
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'failed', finished_at = clock_timestamp(), \
         lease_until = clock_timestamp() + interval '1 hour' WHERE run_id = $1::uuid",
    )
    .bind(&live)
    .execute(pool)
    .await
    .expect("a terminal run that still holds a lease");
    let missing = uuid::Uuid::now_v7().to_string();

    let backend = Arc::new(FakeBackend::new());
    backend.set_inventory(vec![
        pod_for("mcp-orphan-1", &finished, 1, "uid-a"),
        pod_for("mcp-leftover-1", &missing, 1, "uid-b"),
        pod_for("mcp-live-1", &live, 1, "uid-c"),
    ]);
    Recovery::new(harness.store.clone(), backend.clone())
        .reconcile(&harness.worker)
        .await
        .expect("reconcile");

    assert_eq!(
        backend.stopped(),
        vec!["mcp-orphan-1".to_owned(), "mcp-leftover-1".to_owned()],
        "the terminal pod without a lease and the pod with no run are removed; the live one stays"
    );
    harness.fixture.finish().await;
}
