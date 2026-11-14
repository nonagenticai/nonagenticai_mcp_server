//! The worker half of the run store against a real Postgres 18 and the reference's schema.
//!
//! Ported from the reference `src/storage/executions.py` (`owned` … `release_permit`). Every test
//! drives the production path: a run is accepted by the real `ExecutionRepository::accept`, then
//! claimed exactly as the reference scheduler claims it (the claim itself is a later slice), so
//! the authority snapshot, the fence and the deadlines have the shapes a live worker sees.
//!
//! Server selection mirrors `tests/execution_storage.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL`, else an ephemeral `postgres:18` container started with docker and removed
//! afterwards, else FAIL (never skip). Each test gets its own fresh database.

mod support;

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::catalog::ids::Name;
use mcp_server_rs::catalog::models::ToolLimits;
use mcp_server_rs::catalog::resolver::ResolvedTool;
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use mcp_server_rs::config::{ExecutionSettings, WorkerSettings};
use mcp_server_rs::execution::{RunRow, RunStatus};
use mcp_server_rs::storage::executions::ExecutionRepository;
use mcp_server_rs::worker::row::WorkerRow;
use mcp_server_rs::worker::store::{JournalOperation, WorkerStore, WorkerStoreError};

use support::{
    Fixture, LICENCE_ID, SERVICE_ID, TENANT_A, TOOL_ALPHA, authority, binding_fixture_with_tools,
    create_binding, tool_manifest, uuid7, version,
};

/// The reference's lease and run bounds, plus the permit ceilings the tests vary.
fn settings() -> WorkerSettings {
    WorkerSettings {
        lease: Duration::from_secs(30),
        run_max: Duration::from_secs(60),
        api_max_inflight: 8,
        api_concurrency_global: 8,
        api_concurrency_per_service: 8,
        api_max_calls_per_minute: 60,
        service_limits_file: None,
        ..WorkerSettings::default()
    }
}

/// One accepted, claimed run and the store that owns it.
struct Worker {
    fixture: Fixture,
    store: WorkerStore,
    principal: Principal,
    resolved: ResolvedTool,
    worker_id: String,
}

impl Worker {
    async fn new(limits: ToolLimits, settings: WorkerSettings) -> Self {
        let fixture = Fixture::new().await;
        let manifest = tool_manifest("alpha_tool", TOOL_ALPHA);
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
            // A real executor identity: the DDL requires a version-7 worker id.
            worker_id: uuid::Uuid::now_v7().to_string(),
        }
    }

    async fn accept(&self) -> RunRow {
        let generation: i64 =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_one(&self.fixture.pool)
                .await
                .expect("catalog generation");
        let repository =
            ExecutionRepository::new(self.fixture.pool.clone(), ExecutionSettings::default());
        repository
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

    /// Claim the run the way the reference scheduler claims it, then read it back through the
    /// store's own `owned` so the row has production shape.
    async fn claim(&self, run: &RunRow, deadline_seconds: f64) -> WorkerRow {
        let pool = &self.fixture.pool;
        sqlx::query(
            "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, \
             fence = fence + 1, \
             lease_until = clock_timestamp() + make_interval(secs => 30), \
             heartbeat_at = clock_timestamp(), \
             start_deadline = clock_timestamp() + make_interval(secs => 30), \
             deadline = clock_timestamp() + make_interval(secs => $2) \
             WHERE run_id = $3::uuid",
        )
        .bind(&self.worker_id)
        .bind(deadline_seconds)
        .bind(run.run_id.to_string())
        .execute(pool)
        .await
        .expect("claim");
        sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id,run_id) VALUES (1,$1::uuid)")
            .bind(run.run_id.to_string())
            .execute(pool)
            .await
            .expect("slot");
        sqlx::query(
            "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) VALUES ($1::uuid,$2::uuid,'starting')",
        )
        .bind(TENANT_A)
        .bind(run.run_id.to_string())
        .execute(pool)
        .await
        .expect("starting event");
        self.row(run, 1).await
    }

    async fn row(&self, run: &RunRow, fence: i64) -> WorkerRow {
        let mut tx = self.fixture.pool.begin().await.expect("transaction");
        let row = self
            .store
            .owned(&mut tx, &run.run_id, &self.worker_id, fence, true)
            .await
            .expect("owned");
        tx.commit().await.expect("commit");
        row
    }

    async fn events(&self, run: &RunRow) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT kind FROM public.mcp_run_events WHERE run_id = $1::uuid ORDER BY event_id",
        )
        .bind(run.run_id.to_string())
        .fetch_all(&self.fixture.pool)
        .await
        .expect("events")
    }
}

fn operation(id: &str, pagination_limit: i64) -> JournalOperation {
    JournalOperation {
        id: Rfc4122Uuid::parse(id).expect("operation identity"),
        version: 1,
        effect: "read_only".to_owned(),
        pagination_limit,
    }
}

const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
const OPERATION_BETA: &str = "40000000-0000-7000-8000-000000000002";
const FOREIGN_TENANT: &str = "20000000-0000-4000-8000-000000000001";

/// A run owned by another tenant that journalled the same operation. Every shared counter must
/// ignore it: the journal is tenant-explicit on both its count and its finalization.
async fn foreign_intent(pool: &PgPool) -> String {
    // A draft run must be owned by its own tenant, and the tool-version FK is
    // `(owner_tenant_id, tool_id, tool_version)` — so the foreign tenant needs its own copy of
    // the fixture's tool identity and version before it can own a run at all. The copy follows
    // `insert_published_tool`: tool, draft version, its package file and operation references,
    // then publish — all in one transaction, because `mcp_check_package_complete` and
    // `mcp_check_publication` validate the snapshot as a whole.
    let mut tx = pool.begin().await.expect("foreign transaction");
    sqlx::query(
        "INSERT INTO public.mcp_tools(tenant_id,tool_id,public_name,created_by) \
         SELECT $1::uuid,tool_id,public_name,created_by FROM public.mcp_tools \
         WHERE tenant_id = $2::uuid AND tool_id = $3::uuid",
    )
    .bind(FOREIGN_TENANT)
    .bind(TENANT_A)
    .bind(TOOL_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("foreign tool identity");
    sqlx::query(
        "INSERT INTO public.mcp_tool_versions(tenant_id,tool_id,version,manifest,\
         package_sha256,file_count,operation_count,status,created_by,updated_by) \
         SELECT $1::uuid,tool_id,version,\
         jsonb_set(manifest,'{tenant_id}',to_jsonb($1::text)),package_sha256,file_count,\
         operation_count,'draft',created_by,updated_by FROM public.mcp_tool_versions \
         WHERE tenant_id = $2::uuid AND tool_id = $3::uuid",
    )
    .bind(FOREIGN_TENANT)
    .bind(TENANT_A)
    .bind(TOOL_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("foreign tool version");
    sqlx::query(
        "INSERT INTO public.mcp_tool_version_files(tenant_id,tool_id,version,path,content) \
         SELECT $1::uuid,tool_id,version,path,content FROM public.mcp_tool_version_files \
         WHERE tenant_id = $2::uuid AND tool_id = $3::uuid",
    )
    .bind(FOREIGN_TENANT)
    .bind(TENANT_A)
    .bind(TOOL_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("foreign tool package file");
    sqlx::query(
        "INSERT INTO public.mcp_tool_version_operations(tenant_id,tool_id,version,\
         operation_id,operation_version) \
         SELECT $1::uuid,tool_id,version,operation_id,operation_version \
         FROM public.mcp_tool_version_operations \
         WHERE tenant_id = $2::uuid AND tool_id = $3::uuid",
    )
    .bind(FOREIGN_TENANT)
    .bind(TENANT_A)
    .bind(TOOL_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("foreign tool operation references");
    // `mcp_check_publication` refuses a new snapshot that is already published; the fixture's
    // own helper inserts as draft and publishes in a second statement for the same reason.
    sqlx::query(
        "UPDATE public.mcp_tool_versions SET status='published' \
         WHERE tenant_id = $1::uuid AND tool_id = $2::uuid AND version = 1",
    )
    .bind(FOREIGN_TENANT)
    .bind(TOOL_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("publish the foreign tool version");
    tx.commit().await.expect("commit the foreign tool");
    let run_id: String = sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,mode) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}','{}','{}',$4,'{}', \
         clock_timestamp() + interval '1 hour','draft') RETURNING run_id::text",
    )
    .bind(FOREIGN_TENANT)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind("d".repeat(64))
    .fetch_one(pool)
    .await
    .expect("foreign run");
    sqlx::query(
        "INSERT INTO public.mcp_run_api_calls(tenant_id,run_id,sequence,operation_id,\
         operation_version,request_hash,license_id,effect) \
         VALUES ($1::uuid,$2::uuid,1,$3::uuid,1,$4,$5::uuid,'read_only')",
    )
    .bind(FOREIGN_TENANT)
    .bind(&run_id)
    .bind(OPERATION_ALPHA)
    .bind("e".repeat(64))
    .bind(LICENCE_ID)
    .execute(pool)
    .await
    .expect("foreign intent");
    run_id
}

async fn call_status(pool: &PgPool, run_id: &str, sequence: i32) -> String {
    sqlx::query_scalar(
        "SELECT status FROM public.mcp_run_api_calls WHERE run_id = $1::uuid AND sequence = $2",
    )
    .bind(run_id)
    .bind(sequence)
    .fetch_one(pool)
    .await
    .expect("call status")
}

async fn pod_identity(pool: &PgPool, run_id: &str) -> (Option<String>, Option<String>) {
    sqlx::query_as("SELECT pod_name, pod_uid FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("pod identity")
}

// ── ownership ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn owned_refuses_a_foreign_fence_a_terminal_status_a_cancelled_run_and_an_expired_lease() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id;

    // A fence the run never had, and a lease that lapsed, are both denials.
    let mut tx = worker.fixture.pool.begin().await.expect("transaction");
    let error = worker
        .store
        .owned(&mut tx, &run_id, &worker.worker_id, 2, true)
        .await
        .expect_err("a stale fence is denied");
    assert!(matches!(error, WorkerStoreError::Denied));
    drop(tx);

    sqlx::query(
        "UPDATE public.mcp_runs SET lease_until = clock_timestamp() - interval '1 second' \
         WHERE run_id = $1::uuid",
    )
    .bind(run_id.to_string())
    .execute(&worker.fixture.pool)
    .await
    .expect("expire the lease");
    let mut tx = worker.fixture.pool.begin().await.expect("transaction");
    let error = worker
        .store
        .owned(&mut tx, &run_id, &worker.worker_id, 1, true)
        .await
        .expect_err("an expired lease is denied");
    assert!(matches!(error, WorkerStoreError::Denied));
    drop(tx);
    sqlx::query(
        "UPDATE public.mcp_runs SET lease_until = clock_timestamp() + make_interval(secs => 30) \
         WHERE run_id = $1::uuid",
    )
    .bind(run_id.to_string())
    .execute(&worker.fixture.pool)
    .await
    .expect("restore the lease");

    // A status outside `starting`/`running` is refused unless the operation may run for a
    // cancelled run (`allow_cancel`), which heartbeat, finish and a journalled outcome may.
    sqlx::query("UPDATE public.mcp_runs SET status = 'cancelling' WHERE run_id = $1::uuid")
        .bind(run_id.to_string())
        .execute(&worker.fixture.pool)
        .await
        .expect("cancelling");
    let mut tx = worker.fixture.pool.begin().await.expect("transaction");
    let error = worker
        .store
        .owned(&mut tx, &run_id, &worker.worker_id, 1, false)
        .await
        .expect_err("cancelling is not owned without allow_cancel");
    assert!(matches!(error, WorkerStoreError::Denied));
    drop(tx);
    assert!(
        worker.row(&run, 1).await.run.status == RunStatus::Cancelling,
        "allow_cancel still owns a cancelled run"
    );

    sqlx::query("UPDATE public.mcp_runs SET cancel_requested = true WHERE run_id = $1::uuid")
        .bind(run_id.to_string())
        .execute(&worker.fixture.pool)
        .await
        .expect("cancel request");
    let mut tx = worker.fixture.pool.begin().await.expect("transaction");
    let error = worker
        .store
        .owned(&mut tx, &run_id, &worker.worker_id, 1, false)
        .await
        .expect_err("a cancelled run is denied");
    assert!(matches!(error, WorkerStoreError::Denied));
    // The transaction owns the row lock until it ends; `finish` closes the pool and would wait
    // forever for a connection the leaked transaction still holds.
    drop(tx);

    assert_eq!(claimed.fence, 1, "the claim increments the fence");
    assert_eq!(
        claimed.worker_id.as_deref(),
        Some(worker.worker_id.as_str())
    );
    assert!(claimed.lease_until.is_some() && claimed.deadline.is_some());
    worker.fixture.finish().await;
}

// ── lease ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn heartbeat_extends_the_lease_and_every_permit_of_the_fence() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id.to_string();
    sqlx::query(
        "INSERT INTO public.mcp_api_permits(permit_id,tenant_id,run_id,fence,service_id,expires_at) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,1,$3::uuid, clock_timestamp() + interval '1 second')",
    )
    .bind(TENANT_A)
    .bind(&run_id)
    .bind(SERVICE_ID)
    .execute(&worker.fixture.pool)
    .await
    .expect("permit");

    let before = claimed.lease_until.expect("a claimed run carries a lease");
    let refreshed = worker.store.heartbeat(&claimed).await.expect("heartbeat");
    assert!(refreshed.lease_until.expect("lease") > before);
    assert!(refreshed.heartbeat_at.is_some());

    // The returned row is the stored row: the database agrees with it.
    let stored: i64 = sqlx::query_scalar(
        "SELECT (extract(epoch FROM lease_until) * 1000000)::bigint FROM public.mcp_runs \
         WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("stored lease");
    assert_eq!(
        refreshed.lease_until.map(|lease| lease.timestamp_micros()),
        Some(stored)
    );
    // The permit this run's fence holds expires with the same lease; nothing shortens it.
    let permits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_api_permits \
         WHERE run_id = $1::uuid AND fence = 1 AND expires_at > clock_timestamp() + interval '20 seconds'",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("permit expiry");
    assert_eq!(permits, 1);

    // A heartbeat after the lease lapsed is a denial: the run is no longer this worker's.
    sqlx::query(
        "UPDATE public.mcp_runs SET lease_until = clock_timestamp() - interval '1 second' \
         WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .execute(&worker.fixture.pool)
    .await
    .expect("expire the lease");
    let error = worker
        .store
        .heartbeat(&refreshed)
        .await
        .expect_err("an expired lease cannot be extended");
    assert!(matches!(error, WorkerStoreError::Denied));
    worker.fixture.finish().await;
}

// ── pod identity ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn pod_records_the_intent_then_the_immutable_uid() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id.to_string();

    worker
        .store
        .pod(&claimed, "mcp-run-1", None)
        .await
        .expect("pod intent");
    assert_eq!(
        pod_identity(&worker.fixture.pool, &run_id).await,
        (Some("mcp-run-1".to_owned()), None)
    );

    worker
        .store
        .pod(&claimed, "mcp-run-1", Some("uid-1"))
        .await
        .expect("pod uid");
    assert_eq!(
        pod_identity(&worker.fixture.pool, &run_id).await,
        (Some("mcp-run-1".to_owned()), Some("uid-1".to_owned()))
    );

    // A later intent write carries no UID and must not clear the recorded one: the reference is
    // `pod_uid = coalesce($new, pod_uid)`.
    worker
        .store
        .pod(&claimed, "mcp-run-1", None)
        .await
        .expect("pod intent");
    assert_eq!(
        pod_identity(&worker.fixture.pool, &run_id).await,
        (Some("mcp-run-1".to_owned()), Some("uid-1".to_owned()))
    );
    // A non-null UID does replace it — `coalesce` gives the argument priority. Only the
    // controller writes this, always with the pod it just created.
    worker
        .store
        .pod(&claimed, "mcp-run-1", Some("uid-2"))
        .await
        .expect("pod uid");
    assert_eq!(
        pod_identity(&worker.fixture.pool, &run_id).await,
        (Some("mcp-run-1".to_owned()), Some("uid-2".to_owned()))
    );

    // A stale fence writes nothing at all.
    let stale = WorkerRow {
        fence: 9,
        ..claimed.clone()
    };
    let error = worker
        .store
        .pod(&stale, "mcp-run-9", None)
        .await
        .expect_err("a stale fence is denied");
    assert!(matches!(error, WorkerStoreError::Denied));
    assert_eq!(
        pod_identity(&worker.fixture.pool, &run_id).await.0,
        Some("mcp-run-1".to_owned())
    );
    worker.fixture.finish().await;
}

// ── lifecycle ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn running_starts_the_run_and_narrows_the_deadline_to_the_wall_bound() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    assert!(claimed.run.started_at.is_none(), "not started yet");

    let started = worker.store.running(&claimed).await.expect("running");
    assert_eq!(started.run.status, RunStatus::Running);
    let started_at = started.run.started_at.expect("started_at");
    let deadline = started.deadline.expect("deadline");
    // `least(deadline, now + min(wall_seconds, run_max))`: the claim's hour is narrowed to the
    // 60-second wall bound both settings agree on.
    let remaining = deadline.timestamp_micros() - started_at.timestamp_micros();
    assert!(
        remaining <= 61_000_000,
        "deadline kept the claim's hour: {remaining}us"
    );
    assert!(remaining > 55_000_000, "deadline {remaining}us");
    assert!(worker.events(&run).await.contains(&"running".to_owned()));

    // Running again appends the event but cannot restart the clock.
    let again = worker.store.running(&started).await.expect("running again");
    assert_eq!(again.run.started_at, Some(started_at));
    worker.fixture.finish().await;
}

#[tokio::test]
async fn finish_absent_frees_the_slot_permits_and_ownership_and_finalizes_intents() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let running = worker.store.running(&claimed).await.expect("running");
    let run_id = run.run_id.to_string();
    worker
        .store
        .journal_intent(
            &running,
            &operation(OPERATION_ALPHA, 10),
            &"a".repeat(64),
            None,
            &worker.principal.license_id,
            None,
            Some("GET"),
            Some("/synthetic"),
        )
        .await
        .expect("intent");
    worker
        .store
        .permit(&running, &Rfc4122Uuid::parse(SERVICE_ID).expect("service"))
        .await
        .expect("permit");

    worker
        .store
        .finish(&running, "interrupted", None, Some("channel_lost"), true)
        .await
        .expect("finish absent");

    let (status, error, worker_id, lease): (String, Option<Value>, Option<String>, Option<String>) =
        sqlx::query_as(
            "SELECT status, error, worker_id::text, lease_until::text FROM public.mcp_runs \
             WHERE run_id = $1::uuid",
        )
        .bind(&run_id)
        .fetch_one(&worker.fixture.pool)
        .await
        .expect("finished run");
    assert_eq!(status, "interrupted");
    assert_eq!(
        error,
        Some(json!({"code": "channel_lost", "message": "channel lost"}))
    );
    assert_eq!(worker_id, None, "ownership is released");
    assert_eq!(lease, None, "the lease is released");

    let (slot_run, quarantined): (Option<String>, bool) = sqlx::query_as(
        "SELECT run_id::text, quarantined FROM public.mcp_execution_slots WHERE slot_id = 1",
    )
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("slot");
    assert_eq!(slot_run, None, "the slot is free");
    assert!(!quarantined, "a freed slot is not quarantined");

    let permits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_api_permits WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("permits");
    assert_eq!(permits, 0, "every permit is released");

    let (call, finished): (String, bool) = sqlx::query_as(
        "SELECT status, finished_at IS NOT NULL FROM public.mcp_run_api_calls \
         WHERE run_id = $1::uuid AND sequence = 1",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("intent");
    assert_eq!(call, "outcome_unknown", "an unfinished intent is finalized");
    assert!(finished);

    let events = worker.events(&run).await;
    assert!(events.contains(&"interrupted".to_owned()), "{events:?}");
    worker.fixture.finish().await;
}

#[tokio::test]
async fn finish_without_absence_quarantines_the_slot_and_keeps_ownership() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let running = worker.store.running(&claimed).await.expect("running");
    let run_id = run.run_id.to_string();

    let result = json!({"ok": true});
    worker
        .store
        .finish(&running, "succeeded", Some(&result), None, false)
        .await
        .expect("finish");

    let (status, stored, error): (String, Option<Value>, Option<Value>) =
        sqlx::query_as("SELECT status, result, error FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("finished run");
    assert_eq!(status, "succeeded");
    assert_eq!(stored, Some(result));
    assert_eq!(error, None);

    let (slot_run, quarantined): (Option<String>, bool) = sqlx::query_as(
        "SELECT run_id::text, quarantined FROM public.mcp_execution_slots WHERE slot_id = 1",
    )
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("slot");
    assert_eq!(
        slot_run,
        Some(run_id.clone()),
        "the slot still names the run"
    );
    assert!(quarantined, "capacity stays out of service");

    // Ownership is NOT released: the pod may still be running, so the worker keeps its lease.
    let worker_id: Option<String> =
        sqlx::query_scalar("SELECT worker_id::text FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("worker id");
    assert_eq!(worker_id.as_deref(), Some(worker.worker_id.as_str()));

    let events = worker.events(&run).await;
    assert!(events.contains(&"succeeded".to_owned()), "{events:?}");
    assert!(
        events.contains(&"slot_quarantined".to_owned()),
        "{events:?}"
    );
    worker.fixture.finish().await;
}

#[tokio::test]
async fn a_cancelled_run_finishes_with_the_reference_status_never_the_callers() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let running = worker.store.running(&claimed).await.expect("running");
    let run_id = run.run_id.to_string();
    sqlx::query("UPDATE public.mcp_runs SET cancel_requested = true WHERE run_id = $1::uuid")
        .bind(&run_id)
        .execute(&worker.fixture.pool)
        .await
        .expect("cancel request");

    // The caller reports success; the run was cancelled, so the reference overrides the status,
    // the result and the code, and routes the transition through `cancelling`.
    worker
        .store
        .finish(
            &running,
            "succeeded",
            Some(&json!({"ok": true})),
            Some("late"),
            false,
        )
        .await
        .expect("finish");

    let (status, result, error): (String, Value, Option<Value>) =
        sqlx::query_as("SELECT status, result, error FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("finished run");
    assert_eq!(status, "interrupted", "a present worker is interrupted");
    assert_eq!(result, Value::Null, "the reference stores a null result");
    assert_eq!(error, None, "the caller's code is dropped");
    assert!(
        worker
            .events(&run)
            .await
            .contains(&"interrupted".to_owned())
    );
    worker.fixture.finish().await;
}

// ── the upstream-call journal ───────────────────────────────────────────────────────────

#[tokio::test]
async fn journal_intent_enforces_the_run_cap_and_the_pagination_limit_per_tenant() {
    let worker = Worker::new(
        ToolLimits {
            api_calls: 2,
            ..ToolLimits::default()
        },
        settings(),
    )
    .await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id.to_string();
    let alpha = operation(OPERATION_ALPHA, 1);
    let beta = operation(OPERATION_BETA, 5);
    // `mcp_run_api_calls` has a FK on `(operation_id, operation_version)`, and the fixture seeds
    // only alpha. Copy alpha's contract under beta's identity, exactly as a second published
    // operation would look.
    let mut operations = worker.fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) \
         SELECT $1::uuid,version,service_id,service_version,\
         jsonb_set(manifest,'{operation_id}',to_jsonb($1::text)),created_by,updated_by \
         FROM public.mcp_operation_versions WHERE operation_id = $2::uuid AND version = 1",
    )
    .bind(OPERATION_BETA)
    .bind(OPERATION_ALPHA)
    .execute(&mut *operations)
    .await
    .expect("beta operation");
    sqlx::query(
        "UPDATE public.mcp_operation_versions SET status='published' \
         WHERE operation_id = $1::uuid AND version = 1",
    )
    .bind(OPERATION_BETA)
    .execute(&mut *operations)
    .await
    .expect("publish beta");
    operations.commit().await.expect("commit beta");
    let licence = Rfc4122Uuid::parse(LICENCE_ID).expect("licence");
    // Another tenant journalled the same operation: the pagination count must ignore it.
    let foreign = foreign_intent(&worker.fixture.pool).await;

    let first = worker
        .store
        .journal_intent(
            &claimed,
            &alpha,
            &"a".repeat(64),
            Some("intent-key"),
            &licence,
            None,
            Some("GET"),
            Some("/synthetic"),
        )
        .await
        .expect("first intent");
    assert_eq!(first, 1);

    let error = worker
        .store
        .journal_intent(
            &claimed,
            &alpha,
            &"b".repeat(64),
            None,
            &licence,
            None,
            Some("GET"),
            Some("/synthetic"),
        )
        .await
        .expect_err("one call per operation is the pagination limit");
    assert!(matches!(error, WorkerStoreError::Denied));

    // A second operation is still allowed until the run's own cap is reached, and a long path
    // is stored bounded to the DDL's 1024 characters.
    let long_path = "p".repeat(1100);
    let second = worker
        .store
        .journal_intent(
            &claimed,
            &beta,
            &"c".repeat(64),
            None,
            &licence,
            None,
            Some("POST"),
            Some(&long_path),
        )
        .await
        .expect("second intent");
    assert_eq!(second, 2);

    let error = worker
        .store
        .journal_intent(
            &claimed,
            &beta,
            &"d".repeat(64),
            None,
            &licence,
            None,
            Some("POST"),
            Some("/synthetic"),
        )
        .await
        .expect_err("the run's api_calls cap is reached");
    assert!(matches!(error, WorkerStoreError::Denied));

    let api_calls: i32 =
        sqlx::query_scalar("SELECT api_calls FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("api_calls");
    assert_eq!(api_calls, 2);

    let (effect, method, length, key): (String, String, i32, Option<String>) = sqlx::query_as(
        "SELECT effect, method, char_length(path), idempotency_key FROM public.mcp_run_api_calls \
         WHERE run_id = $1::uuid AND sequence = 2",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("journalled call");
    assert_eq!(effect, "read_only");
    assert_eq!(method, "POST");
    assert_eq!(length, 1024, "the path is stored bounded");
    assert_eq!(key, None);

    // The denied attempts wrote nothing, and the foreign tenant's run is untouched.
    let ours: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_run_api_calls WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("our calls");
    assert_eq!(ours, 2);
    assert_eq!(
        call_status(&worker.fixture.pool, &foreign, 1).await,
        "intent"
    );
    worker.fixture.finish().await;
}

#[tokio::test]
async fn journal_outcome_finalizes_an_intent_once_and_only_for_its_own_tenant() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id.to_string();
    let licence = Rfc4122Uuid::parse(LICENCE_ID).expect("licence");
    let foreign = foreign_intent(&worker.fixture.pool).await;
    worker
        .store
        .journal_intent(
            &claimed,
            &operation(OPERATION_ALPHA, 10),
            &"a".repeat(64),
            None,
            &licence,
            None,
            Some("GET"),
            Some("/synthetic"),
        )
        .await
        .expect("intent");

    worker
        .store
        .journal_outcome(&claimed, 1, "succeeded", Some(200), Some(12), None, None)
        .await
        .expect("outcome");
    let (status, http, duration, finished): (String, Option<i32>, Option<i32>, bool) =
        sqlx::query_as(
            "SELECT status, http_status, duration_ms, finished_at IS NOT NULL \
         FROM public.mcp_run_api_calls WHERE run_id = $1::uuid AND sequence = 1",
        )
        .bind(&run_id)
        .fetch_one(&worker.fixture.pool)
        .await
        .expect("outcome row");
    assert_eq!(status, "succeeded");
    assert_eq!(http, Some(200));
    assert_eq!(duration, Some(12));
    assert!(finished);

    // Only an `intent` is finalized: a second outcome changes nothing, and a sequence the run
    // never journalled matches no row.
    worker
        .store
        .journal_outcome(
            &claimed,
            1,
            "failed",
            Some(500),
            Some(99),
            Some("status"),
            None,
        )
        .await
        .expect("second outcome");
    worker
        .store
        .journal_outcome(
            &claimed,
            99,
            "failed",
            Some(500),
            Some(1),
            Some("status"),
            None,
        )
        .await
        .expect("unknown sequence");
    let (status, http): (String, Option<i32>) = sqlx::query_as(
        "SELECT status, http_status FROM public.mcp_run_api_calls \
         WHERE run_id = $1::uuid AND sequence = 1",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("outcome row");
    assert_eq!(status, "succeeded");
    assert_eq!(http, Some(200));

    // The foreign tenant's identically numbered intent is still open.
    assert_eq!(
        call_status(&worker.fixture.pool, &foreign, 1).await,
        "intent"
    );
    worker.fixture.finish().await;
}

// ── permits ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn permit_denies_on_the_concurrency_ceiling_and_emits_the_fixed_event() {
    let worker = Worker::new(
        ToolLimits::default(),
        WorkerSettings {
            api_concurrency_global: 1,
            api_max_calls_per_minute: 60,
            ..settings()
        },
    )
    .await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let run_id = run.run_id.to_string();
    let service = Rfc4122Uuid::parse(SERVICE_ID).expect("service");

    let permit = worker
        .store
        .permit(&claimed, &service)
        .await
        .expect("permit");
    let error = worker
        .store
        .permit(&claimed, &service)
        .await
        .expect_err("the global ceiling is one");
    assert!(matches!(error, WorkerStoreError::Denied));

    let permits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_api_permits WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("permits");
    assert_eq!(permits, 1, "a denied permit does not exist");
    let events = worker.events(&run).await;
    assert!(
        events.contains(&"api_concurrency_denied".to_owned()),
        "{events:?}"
    );

    // A release is scoped to the permit, the run and the fence: a stale fence releases nothing.
    let stale = WorkerRow {
        fence: 9,
        ..claimed.clone()
    };
    worker
        .store
        .release_permit(&stale, &permit)
        .await
        .expect("release");
    let permits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_api_permits WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("permits");
    assert_eq!(permits, 1, "a stale generation cannot release a permit");

    worker
        .store
        .release_permit(&claimed, &permit)
        .await
        .expect("release");
    let permits: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_api_permits WHERE run_id = $1::uuid")
            .bind(&run_id)
            .fetch_one(&worker.fixture.pool)
            .await
            .expect("permits");
    assert_eq!(permits, 0);
    worker.fixture.finish().await;
}

#[tokio::test]
async fn permit_denies_on_the_per_minute_rate_ceiling_and_emits_the_fixed_event() {
    let worker = Worker::new(
        ToolLimits::default(),
        WorkerSettings {
            api_max_calls_per_minute: 1,
            ..settings()
        },
    )
    .await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let service = Rfc4122Uuid::parse(SERVICE_ID).expect("service");

    let permit = worker
        .store
        .permit(&claimed, &service)
        .await
        .expect("permit");
    worker
        .store
        .release_permit(&claimed, &permit)
        .await
        .expect("release");
    let error = worker
        .store
        .permit(&claimed, &service)
        .await
        .expect_err("one call per minute");
    assert!(matches!(error, WorkerStoreError::Denied));

    // The denied attempt consumed no call: the window still records exactly one.
    let calls: i32 = sqlx::query_scalar(
        "SELECT calls FROM public.mcp_api_rate_windows \
         WHERE tenant_id = $1::uuid AND service_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(SERVICE_ID)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("rate window");
    assert_eq!(calls, 1);
    let events = worker.events(&run).await;
    assert!(events.contains(&"api_rate_denied".to_owned()), "{events:?}");
    worker.fixture.finish().await;
}

// ── retention ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn expire_payloads_reports_the_batch_it_expired() {
    let worker = Worker::new(ToolLimits::default(), settings()).await;
    let run = worker.accept().await;
    let claimed = worker.claim(&run, 3600.0).await;
    let running = worker.store.running(&claimed).await.expect("running");
    let run_id = run.run_id.to_string();
    worker
        .store
        .finish(
            &running,
            "failed",
            Some(&json!({"ok": false})),
            Some("runner_crashed"),
            true,
        )
        .await
        .expect("finish absent");
    sqlx::query(
        "UPDATE public.mcp_runs SET finished_at = clock_timestamp() - interval '30 days' \
         WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .execute(&worker.fixture.pool)
    .await
    .expect("age the run");

    let expired = worker.store.expire_payloads().await.expect("expire");
    assert_eq!(expired, 1);

    let (inputs, authority, profile, result, expired_at): (
        Value,
        Value,
        Value,
        Option<Value>,
        Option<String>,
    ) = sqlx::query_as(
        "SELECT inputs, authority, profile_snapshot, result, payload_expired_at::text \
         FROM public.mcp_runs WHERE run_id = $1::uuid",
    )
    .bind(&run_id)
    .fetch_one(&worker.fixture.pool)
    .await
    .expect("expired run");
    assert_eq!(inputs, json!({}));
    assert_eq!(authority, json!({}));
    assert_eq!(profile, json!({}));
    assert_eq!(result, None);
    assert!(expired_at.is_some());

    assert_eq!(worker.store.expire_payloads().await.expect("expire"), 0);
    worker.fixture.finish().await;
}
