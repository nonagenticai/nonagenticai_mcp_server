//! The external driver loop against a real Postgres 18.
//!
//! Ported from the reference `tests/test_external_driver.py`. Every test here fails if the
//! behaviour it covers is removed: the dispatch event is committed before the upstream call, a
//! recovered run that may already have been sent is `interrupted` rather than re-sent, the
//! deadline and a cancel request both go through the legal transitions, a poll failure is not the
//! run's outcome, the lease survives a slow adapter call, and an answered task input is relayed
//! to fr exactly once (a refusal reopens it).
//!
//! Server selection mirrors `tests/tasks.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL`, else an
//! ephemeral `postgres:18` container that is removed afterwards, else FAIL (never skip).

mod support;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::config::ExternalDriverSettings;
use mcp_server_rs::external::driver::ExternalDriver;
use mcp_server_rs::external::store::ExternalStore;
use mcp_server_rs::external::{
    AdapterError, AnswerForwarder, ExternalAdapter, ExternalRef, ExternalStartError, ExternalState,
    RefKind,
};
use mcp_server_rs::storage::task_inputs::TaskInputRepository;
use mcp_server_rs::worker::row::WorkerRow;

use support::{Fixture, LICENCE_ID, TENANT_A, TOOL_ALPHA, binding_fixture};

// ── a scripted adapter ───────────────────────────────────────────────────────────────────

/// What one scripted `poll` should do.
#[derive(Clone)]
enum Poll {
    State(ExternalState),
    Fail(&'static str),
}

/// An adapter that records what the driver asked it to do and answers from a script.
#[derive(Default)]
struct Fake {
    calls: Mutex<Vec<String>>,
    start: Mutex<Option<Result<ExternalRef, &'static str>>>,
    polls: Mutex<Vec<Poll>>,
    cancels: Mutex<u32>,
    slow_start: Mutex<Option<Duration>>,
}

impl Fake {
    fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    fn calls(&self) -> Vec<String> {
        self.calls.lock().expect("calls").clone()
    }

    fn with_start(self: &Arc<Self>, reference: ExternalRef) -> Arc<Self> {
        *self.start.lock().expect("start") = Some(Ok(reference));
        Arc::clone(self)
    }

    fn with_polls(&self, polls: Vec<Poll>) {
        *self.polls.lock().expect("polls") = polls;
    }

    fn slow(&self, delay: Duration) {
        *self.slow_start.lock().expect("slow") = Some(delay);
    }
}

#[async_trait]
impl ExternalAdapter for Fake {
    async fn start(&self, _row: &WorkerRow) -> Result<ExternalRef, ExternalStartError> {
        self.calls.lock().expect("calls").push("start".to_owned());
        let delay = *self.slow_start.lock().expect("slow");
        if let Some(delay) = delay {
            tokio::time::sleep(delay).await;
        }
        match self.start.lock().expect("start").clone() {
            Some(Ok(reference)) => Ok(reference),
            Some(Err(code)) => Err(ExternalStartError::new(code)),
            None => Ok(ExternalRef::new(RefKind::N8n, "exec-1")),
        }
    }

    async fn poll(&self, _row: &WorkerRow) -> Result<ExternalState, AdapterError> {
        self.calls.lock().expect("calls").push("poll".to_owned());
        let mut polls = self.polls.lock().expect("polls");
        if polls.is_empty() {
            return Ok(ExternalState::running());
        }
        match polls.remove(0) {
            Poll::State(state) => Ok(state),
            Poll::Fail(code) => Err(AdapterError::new(code)),
        }
    }

    async fn cancel(&self, _row: &WorkerRow) -> Result<(), AdapterError> {
        self.calls.lock().expect("calls").push("cancel".to_owned());
        *self.cancels.lock().expect("cancels") += 1;
        Ok(())
    }
}

/// A forwarder that refuses with the scripted code, or accepts.
struct Forwarder {
    refusal: Option<&'static str>,
    calls: Mutex<u32>,
}

#[async_trait]
impl AnswerForwarder for Forwarder {
    async fn forward(
        &self,
        _row: &WorkerRow,
        _item: &mcp_server_rs::storage::task_inputs::TaskInputRow,
    ) -> Result<Option<String>, AdapterError> {
        *self.calls.lock().expect("calls") += 1;
        Ok(self.refusal.map(str::to_owned))
    }
}

// ── fixtures ─────────────────────────────────────────────────────────────────────────────

fn settings() -> ExternalDriverSettings {
    let mut settings =
        ExternalDriverSettings::from_lookup(|_| None).expect("default driver settings");
    settings.worker.max_inflight = 8;
    settings.active_max = 100;
    settings
}

fn driver_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

fn driver(
    fixture: &Fixture,
    fake: Arc<Fake>,
    settings: ExternalDriverSettings,
    forwarder: Option<Arc<Forwarder>>,
) -> ExternalDriver {
    let store = ExternalStore::new(fixture.pool.clone(), settings.clone(), driver_id());
    let mut adapters: HashMap<&'static str, Arc<dyn ExternalAdapter>> = HashMap::new();
    let catalogue: Arc<dyn ExternalAdapter> = fake.clone();
    adapters.insert("n8n_workflow", catalogue);
    // The one-shot `fr_command` path is the same adapter call with a result already in hand.
    adapters.insert("fr_command", fake);
    ExternalDriver::new(
        store,
        TaskInputRepository::new(fixture.pool.clone()),
        adapters,
        forwarder.map(|forwarder| forwarder as Arc<dyn AnswerForwarder>),
        settings,
    )
}

/// One draft run of the fixture tool, in the given status and runtime.
#[allow(clippy::too_many_arguments)]
async fn seed_run(
    pool: &PgPool,
    status: &str,
    runtime: &str,
    worker: Option<&str>,
    fence: i64,
    lease_seconds: i64,
    deadline_seconds: i64,
    cancel_requested: bool,
) -> String {
    sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,\
         mode,status,runtime,worker_id,fence,lease_until,deadline,start_deadline,\
         cancel_requested) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}','{}','{}',$4,'{}', \
         clock_timestamp() + interval '1 hour','draft',$5,$6,$7::uuid,$8, \
         clock_timestamp() + make_interval(secs => $9::double precision), \
         clock_timestamp() + make_interval(secs => $10::double precision), \
         clock_timestamp() + interval '30 seconds',$11) RETURNING run_id::text",
    )
    .bind(TENANT_A)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind("d".repeat(64))
    .bind(status)
    .bind(runtime)
    .bind(worker)
    .bind(fence)
    .bind(lease_seconds as f64)
    .bind(deadline_seconds as f64)
    .bind(cancel_requested)
    .fetch_one(pool)
    .await
    .expect("run row")
}

async fn status_of(pool: &PgPool, run_id: &str) -> String {
    sqlx::query_scalar("SELECT status FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("run status")
}

async fn event_kinds(pool: &PgPool, run_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT kind FROM public.mcp_run_events WHERE run_id = $1::uuid ORDER BY event_id",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("run events")
}

async fn external_ref(pool: &PgPool, run_id: &str) -> Option<Value> {
    sqlx::query_scalar("SELECT external_ref FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("external ref")
}

async fn result_of(pool: &PgPool, run_id: &str) -> Option<Value> {
    sqlx::query_scalar("SELECT result FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("run result")
}

async fn activity_kinds(pool: &PgPool, run_id: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT kind FROM public.mcp_run_activity WHERE run_id = $1::uuid ORDER BY seq",
    )
    .bind(run_id)
    .fetch_all(pool)
    .await
    .expect("activity rows")
}

// ── start ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_queued_external_run_is_dispatched_once_and_recorded() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "queued",
        "n8n_workflow",
        None,
        0,
        0,
        60,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "running");
    // The dispatch event is committed before the upstream call, so recovery can tell
    // "maybe sent" from "never sent".
    let kinds = event_kinds(&fixture.pool, &run).await;
    assert!(kinds.contains(&"dispatch".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"starting".to_owned()), "{kinds:?}");
    assert!(kinds.contains(&"running".to_owned()), "{kinds:?}");
    assert_eq!(
        external_ref(&fixture.pool, &run).await,
        Some(json!({"kind": "n8n", "id": "exec-1"}))
    );
    assert_eq!(fake.calls(), vec!["start".to_owned(), "poll".to_owned()]);
    assert_eq!(activity_kinds(&fixture.pool, &run).await, vec!["started"]);
    fixture.finish().await;
}

#[tokio::test]
async fn a_run_dispatched_before_the_crash_is_interrupted_not_resent() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    // Adopted (lapsed lease) while `starting`, with a dispatch event and no external reference:
    // the upstream may have it, so it must never be sent again.
    let run = seed_run(
        &fixture.pool,
        "starting",
        "n8n_workflow",
        None,
        3,
        -5,
        60,
        false,
    )
    .await;
    sqlx::query(
        "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) VALUES ($1::uuid,$2::uuid,'dispatch')",
    )
    .bind(TENANT_A)
    .bind(&run)
    .execute(&fixture.pool)
    .await
    .expect("dispatch event");

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "interrupted");
    assert!(!fake.calls().contains(&"start".to_owned()));
    let error: Option<Value> =
        sqlx::query_scalar("SELECT error FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("error column");
    assert_eq!(
        error.and_then(|error| error["code"].as_str().map(str::to_owned)),
        Some("external_start_unknown".to_owned())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_run_that_never_dispatched_is_started_again() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "starting",
        "n8n_workflow",
        None,
        1,
        -5,
        60,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "running");
    assert_eq!(fake.calls().first().map(String::as_str), Some("start"));
    fixture.finish().await;
}

#[tokio::test]
async fn a_start_refusal_fails_the_run_with_its_public_code() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    *fake.start.lock().expect("start") = Some(Err("external_unconfigured"));
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "queued",
        "n8n_workflow",
        None,
        0,
        0,
        60,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "failed");
    let error: Option<Value> =
        sqlx::query_scalar("SELECT error FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("error column");
    assert_eq!(
        error.and_then(|error| error["code"].as_str().map(str::to_owned)),
        Some("external_unconfigured".to_owned())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_one_shot_result_finishes_in_the_same_tick() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let mut reference = ExternalRef::new(RefKind::FrCommand, "project-1");
    reference.project_id = Some("project-1".to_owned());
    reference.result = Some(json!({"id": "project-1", "status": "delivered"}));
    fake.with_start(reference);
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(&fixture.pool, "queued", "fr_command", None, 0, 0, 60, false).await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "succeeded");
    assert_eq!(
        result_of(&fixture.pool, &run).await,
        Some(json!({"id": "project-1", "status": "delivered"}))
    );
    // A one-shot command has its answer already: nothing is polled.
    assert!(!fake.calls().contains(&"poll".to_owned()));
    fixture.finish().await;
}

// ── drive ───────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_succeeded_poll_finishes_the_run_and_records_delivery() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        Some(driver.driver_id()),
        1,
        30,
        600,
        false,
    )
    .await;
    fake.with_polls(vec![Poll::State(ExternalState::succeeded(Some(
        json!({"answer": 42}),
    )))]);

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "succeeded");
    assert_eq!(
        result_of(&fixture.pool, &run).await,
        Some(json!({"answer": 42}))
    );
    assert!(
        activity_kinds(&fixture.pool, &run)
            .await
            .contains(&"delivered".to_owned())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_poll_failure_is_not_the_runs_outcome() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        Some(driver.driver_id()),
        1,
        30,
        600,
        false,
    )
    .await;
    fake.with_polls(vec![Poll::Fail("external_result_invalid")]);

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "running");
    fixture.finish().await;
}

#[tokio::test]
async fn a_cancel_request_goes_through_cancelling() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        Some(driver.driver_id()),
        1,
        30,
        600,
        true,
    )
    .await;
    fake.with_polls(vec![Poll::State(ExternalState::cancelled())]);

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "cancelled");
    assert!(*fake.cancels.lock().expect("cancels") >= 1);
    assert!(
        event_kinds(&fixture.pool, &run)
            .await
            .contains(&"cancelling".to_owned())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_deadline_withdraws_upstream_and_times_out() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let driver = driver(&fixture, Arc::clone(&fake), settings(), None);
    // `deadline_seconds` negative puts the deadline in the past; the lease is still live.
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        Some(driver.driver_id()),
        1,
        30,
        -1,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &run).await, "timed_out");
    assert_eq!(*fake.cancels.lock().expect("cancels"), 1);
    assert!(!fake.calls().contains(&"poll".to_owned()));
    fixture.finish().await;
}

#[tokio::test]
async fn the_lease_survives_a_slow_start() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    fake.slow(Duration::from_millis(2_500));
    let mut settings = settings();
    settings.worker.heartbeat = Duration::from_secs(1);
    settings.worker.lease = Duration::from_secs(10);
    let driver = driver(&fixture, Arc::clone(&fake), settings, None);
    let run = seed_run(
        &fixture.pool,
        "queued",
        "n8n_workflow",
        None,
        0,
        0,
        60,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    // Two seconds of upstream latency against a one-second heartbeat: the driver still owns it.
    assert_eq!(status_of(&fixture.pool, &run).await, "running");
    let leased: bool = sqlx::query_scalar(
        "SELECT lease_until > clock_timestamp() FROM public.mcp_runs WHERE run_id = $1::uuid",
    )
    .bind(&run)
    .fetch_one(&fixture.pool)
    .await
    .expect("lease");
    assert!(leased);
    fixture.finish().await;
}

#[tokio::test]
async fn the_active_cap_stops_the_claim() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let mut settings = settings();
    settings.active_max = 1;
    let driver = driver(&fixture, Arc::clone(&fake), settings, None);
    let busy = Some(driver.driver_id());
    seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        busy,
        1,
        30,
        600,
        false,
    )
    .await;
    let queued = seed_run(
        &fixture.pool,
        "queued",
        "n8n_workflow",
        None,
        0,
        0,
        600,
        false,
    )
    .await;

    driver.tick().await.expect("tick");

    assert_eq!(status_of(&fixture.pool, &queued).await, "queued");
    fixture.finish().await;
}

// ── forward ─────────────────────────────────────────────────────────────────────────────

async fn seed_input(pool: &PgPool, run_id: &str) -> String {
    sqlx::query_scalar(
        "INSERT INTO public.mcp_task_inputs(input_key,tenant_id,run_id,source_ref,request,state,\
         response,actor,answered_at) \
         VALUES ('key-1',$1::uuid,$2::uuid,'approval-1','{}','answered', \
         '{\"action\":\"accept\",\"content\":{\"decision\":\"approved\"}}', \
         '{\"address\":\"a@b\"}', clock_timestamp()) RETURNING input_key",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .fetch_one(pool)
    .await
    .expect("task input")
}

async fn input_state(pool: &PgPool) -> String {
    sqlx::query_scalar("SELECT state FROM public.mcp_task_inputs WHERE input_key = 'key-1'")
        .fetch_one(pool)
        .await
        .expect("input state")
}

#[tokio::test]
async fn an_answered_input_is_forwarded_once() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let forwarder = Arc::new(Forwarder {
        refusal: None,
        calls: Mutex::new(0),
    });
    let driver = driver(
        &fixture,
        Arc::clone(&fake),
        settings(),
        Some(Arc::clone(&forwarder)),
    );
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        None,
        0,
        30,
        600,
        false,
    )
    .await;
    seed_input(&fixture.pool, &run).await;

    driver.tick().await.expect("tick");

    assert_eq!(input_state(&fixture.pool).await, "forwarded");
    assert_eq!(*forwarder.calls.lock().expect("calls"), 1);
    fixture.finish().await;
}

#[tokio::test]
async fn a_refused_answer_reopens_the_input_with_the_refusal() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let fake = Fake::new();
    let forwarder = Arc::new(Forwarder {
        refusal: Some("actor_unresolved"),
        calls: Mutex::new(0),
    });
    let driver = driver(
        &fixture,
        Arc::clone(&fake),
        settings(),
        Some(Arc::clone(&forwarder)),
    );
    let run = seed_run(
        &fixture.pool,
        "running",
        "n8n_workflow",
        None,
        0,
        30,
        600,
        false,
    )
    .await;
    seed_input(&fixture.pool, &run).await;

    driver.tick().await.expect("tick");

    assert_eq!(input_state(&fixture.pool).await, "open");
    let message: Option<String> =
        sqlx::query_scalar("SELECT status_message FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run)
            .fetch_one(&fixture.pool)
            .await
            .expect("status message");
    assert_eq!(
        message.as_deref(),
        Some("fr refused the answer: actor_unresolved")
    );
    fixture.finish().await;
}
