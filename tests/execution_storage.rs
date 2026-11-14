//! Execution storage against a real Postgres 18 and the reference's schema.
//!
//! Ported from the reference `src/storage/executions.py` and `src/storage/task_inputs.py`.
//! Every test fails if the behaviour it covers is removed: acceptance writes exactly the run
//! the Python worker reads back, the queue bounds and the recovery generation are enforced in
//! one transaction, and the inspection surface is tenant-scoped and bounded.
//!
//! Server selection mirrors `tests/routes_available.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL`, else an ephemeral `postgres:18` container started with docker and removed
//! afterwards, else FAIL (never skip). Each test gets its own fresh database.

mod support;

use std::time::Duration;

use serde_json::{Map, Value, json};
use sqlx::PgPool;

use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::catalog::ids::{Name, Uuid7};
use mcp_server_rs::catalog::models::{Runtime, ToolLimits};
use mcp_server_rs::catalog::resolver::ResolvedTool;
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use mcp_server_rs::config::ExecutionSettings;
use mcp_server_rs::execution::{RunRow, RunStatus, attribution, authority_snapshot, value_hash};
use mcp_server_rs::storage::executions::{ExecutionRepository, ExecutionStoreError};
use mcp_server_rs::storage::run_activity;
use mcp_server_rs::storage::task_inputs::TaskInputRepository;

use support::{
    Fixture, LICENCE_ID, PROFILE, TENANT_A, TENANT_PLATFORM, TOOL_ALPHA, authority,
    binding_fixture_with_tools, create_binding, tool_manifest, uuid7, version,
};

// ── the bound fixture ─────────────────────────────────────────────────────────────────────

struct Bound {
    fixture: Fixture,
    repository: ExecutionRepository,
    principal: Principal,
    resolved: ResolvedTool,
    binding: String,
    revision: i64,
}

/// A published catalog, a real binding created through the HTTP surface, and a bound principal.
async fn bound_fixture(queue_seconds: u32, settings: ExecutionSettings) -> Bound {
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
        effective: effective(queue_seconds),
        context: context(),
    };
    Bound {
        repository: ExecutionRepository::new(fixture.pool.clone(), settings),
        fixture,
        principal,
        resolved,
        binding,
        revision,
    }
}

fn effective(queue_seconds: u32) -> EffectiveTool {
    EffectiveTool {
        tool: ToolReference {
            id: uuid7(TOOL_ALPHA),
            version: version(1),
            tenant_id: authority(TENANT_A),
        },
        operation_constraints: Vec::new(),
        limits: ToolLimits {
            queue_seconds,
            ..ToolLimits::default()
        },
        public_name: Name::new("alpha_tool").expect("public name"),
    }
}

fn context() -> BoundContext {
    BoundContext {
        tenant_id: authority(TENANT_A),
        project_id: None,
        workspace_id: None,
        project_phase: None,
        work_type: None,
        card_stage: None,
        responsibility: None,
        test_command: None,
        reviewed_commit: None,
    }
}

async fn generation(pool: &PgPool) -> i64 {
    sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
        .fetch_one(pool)
        .await
        .expect("catalog generation")
}

async fn accept(
    bound: &Bound,
    inputs: &Value,
    key: Option<&str>,
) -> Result<RunRow, ExecutionStoreError> {
    let generation = generation(&bound.fixture.pool).await;
    bound
        .repository
        .accept(
            &bound.principal,
            &bound.resolved,
            inputs,
            key,
            generation,
            None,
        )
        .await
}

async fn open_input(pool: &PgPool, run_id: &str, key: &str, source_ref: &str) {
    sqlx::query(
        "INSERT INTO public.mcp_task_inputs(input_key,tenant_id,run_id,source_ref,request) \
         VALUES ($1,$2::uuid,$3::uuid,$4,$5)",
    )
    .bind(key)
    .bind(TENANT_A)
    .bind(run_id)
    .bind(source_ref)
    .bind(json!({"kind": "approval", "title": "Approve the delivered work"}))
    .execute(pool)
    .await
    .expect("task input row");
}

async fn input_state(pool: &PgPool, key: &str) -> String {
    sqlx::query_scalar("SELECT state FROM public.mcp_task_inputs WHERE input_key = $1")
        .bind(key)
        .fetch_one(pool)
        .await
        .expect("input state")
}

// ── acceptance ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn accept_writes_the_queued_run_snapshot_authority_and_event() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let inputs = json!({"query": "hello", "limit": 3});
    let actor = json!({"channel": "mcp", "address": "agent-09"});
    let generation = generation(&bound.fixture.pool).await;
    let run = bound
        .repository
        .accept(
            &bound.principal,
            &bound.resolved,
            &inputs,
            Some("accept-key"),
            generation,
            Some(&actor),
        )
        .await
        .expect("accept");

    assert_eq!(run.status, RunStatus::Queued);
    assert_eq!(run.mode, "bound");
    assert_eq!(run.runtime, Runtime::N8nWorkflow);
    assert_eq!(run.tenant_id.to_string(), TENANT_A);
    assert_eq!(run.owner_tenant_id.to_string(), TENANT_A);
    assert_eq!(
        run.binding_id.as_ref().map(|id| id.to_string()),
        Some(bound.binding.clone())
    );
    assert_eq!(run.binding_revision, Some(bound.revision));
    assert_eq!(run.inputs, inputs);
    assert_eq!(run.input_hash, value_hash(&inputs));
    assert_eq!(
        run.authority,
        authority_snapshot(&bound.resolved).expect("authority snapshot")
    );
    assert_eq!(run.created_by, attribution(&bound.principal));
    assert_eq!(run.actor, Some(actor));
    assert_eq!(run.idempotency_key.as_deref(), Some("accept-key"));
    assert!(!run.cancel_requested);
    assert!(run.started_at.is_none());
    assert!(run.finished_at.is_none());
    assert!(
        Uuid7::new(run.run_id.to_string()).is_ok(),
        "the database mints a version-7 run identity"
    );

    let profile: Value = sqlx::query_scalar(
        "SELECT manifest FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_one(&bound.fixture.pool)
    .await
    .expect("profile manifest");
    assert_eq!(run.profile_snapshot, profile);

    let run_id = uuid7(&run.run_id.to_string());
    let events = bound
        .repository
        .events(&authority(TENANT_A), &run_id, 0, 100)
        .await
        .expect("events");
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].kind, "queued");

    let locks: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tenant_execution_locks WHERE tenant_id = $1::uuid",
    )
    .bind(TENANT_A)
    .fetch_one(&bound.fixture.pool)
    .await
    .expect("tenant execution lock");
    assert_eq!(locks, 1);

    bound.fixture.finish().await;
}

#[tokio::test]
async fn accept_is_idempotent_for_the_same_key_and_refuses_a_different_input() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let inputs = json!({"query": "hello"});
    let first = accept(&bound, &inputs, Some("replay-key"))
        .await
        .expect("first accept");
    let replay = accept(&bound, &inputs, Some("replay-key"))
        .await
        .expect("replayed accept");
    assert_eq!(replay.run_id.to_string(), first.run_id.to_string());
    assert_eq!(replay.created_at, first.created_at);
    assert_eq!(replay.input_hash, first.input_hash);

    let error = accept(&bound, &json!({"query": "different"}), Some("replay-key"))
        .await
        .expect_err("a different input conflicts");
    assert!(matches!(
        error,
        ExecutionStoreError::Conflict("idempotency input conflict")
    ));
    bound.fixture.finish().await;
}

/// Mutate one binding the way the schema allows: `binding_update_guard` refuses an update that
/// does not bump the revision, and `mcp_bindings_check` requires the stored spec to agree with
/// the row's `enabled` and `expires_at`, so an assignment that changes either must carry the
/// matching spec patch. Revocation is terminal. The bound principal follows the revision so each
/// denial is tested for its own reason, never for a stale revision.
async fn mutate_binding(bound: &mut Bound, assignment: &str) {
    let statement = format!(
        "UPDATE public.mcp_bindings SET {assignment}, revision = revision + 1 \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid"
    );
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(TENANT_A)
        .bind(&bound.binding)
        .execute(&bound.fixture.pool)
        .await
        .expect("binding update");
    bound.revision += 1;
    bound.principal.binding_revision = Some(bound.revision);
}

#[tokio::test]
async fn accept_denies_a_changed_revision_revoked_disabled_expired_or_foreign_licence_binding() {
    let inputs = json!({"query": "hello"});

    // A revision that moved since authentication.
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let stale = Principal {
        binding_revision: Some(bound.revision + 1),
        ..bound.principal.clone()
    };
    let error = bound
        .repository
        .accept(
            &stale,
            &bound.resolved,
            &inputs,
            None,
            generation(&bound.fixture.pool).await,
            None,
        )
        .await
        .expect_err("a stale revision is denied");
    assert!(matches!(error, ExecutionStoreError::Denied));
    bound.fixture.finish().await;

    // Revoked: terminal in the schema, so it gets a binding of its own.
    let mut bound = bound_fixture(60, ExecutionSettings::default()).await;
    mutate_binding(&mut bound, "revoked = true").await;
    let error = accept(&bound, &inputs, None)
        .await
        .expect_err("a revoked binding is denied");
    assert!(matches!(error, ExecutionStoreError::Denied));
    bound.fixture.finish().await;

    // Disabled.
    let mut bound = bound_fixture(60, ExecutionSettings::default()).await;
    mutate_binding(
        &mut bound,
        "enabled = false, spec = jsonb_set(spec, '{enabled}', 'false'::jsonb)",
    )
    .await;
    let error = accept(&bound, &inputs, None)
        .await
        .expect_err("a disabled binding is denied");
    assert!(matches!(error, ExecutionStoreError::Denied));
    bound.fixture.finish().await;

    // Expired.
    let mut bound = bound_fixture(60, ExecutionSettings::default()).await;
    mutate_binding(
        &mut bound,
        "expires_at = timestamptz '2000-01-01 00:00:00+00', \
         spec = jsonb_set(spec, '{expires_at}', \
         to_jsonb(timestamptz '2000-01-01 00:00:00+00'))",
    )
    .await;
    let error = accept(&bound, &inputs, None)
        .await
        .expect_err("an expired binding is denied");
    assert!(matches!(error, ExecutionStoreError::Denied));
    bound.fixture.finish().await;

    // A licence the binding was not issued for; the control shows the healthy binding admits.
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let foreign = Principal {
        license_id: Rfc4122Uuid::parse("30000000-0000-4000-8000-000000000002")
            .expect("licence identity"),
        ..bound.principal.clone()
    };
    let error = bound
        .repository
        .accept(
            &foreign,
            &bound.resolved,
            &inputs,
            None,
            generation(&bound.fixture.pool).await,
            None,
        )
        .await
        .expect_err("a foreign licence is denied");
    assert!(matches!(error, ExecutionStoreError::Denied));
    accept(&bound, &inputs, None)
        .await
        .expect("the healthy binding still admits its own caller");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn accept_refuses_a_stale_catalog_generation() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let generation = generation(&bound.fixture.pool).await;
    let error = bound
        .repository
        .accept(
            &bound.principal,
            &bound.resolved,
            &json!({"query": "hello"}),
            None,
            generation + 1,
            None,
        )
        .await
        .expect_err("a moved catalog is refused");
    match error {
        ExecutionStoreError::Conflict(message) => {
            assert_eq!(message, "authority changed during acceptance");
        }
        other => panic!("unexpected error: {other:?}"),
    }
    bound.fixture.finish().await;
}

#[tokio::test]
async fn accept_refuses_a_full_global_and_per_tenant_queue() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let generation = generation(&bound.fixture.pool).await;

    let global = ExecutionRepository::new(
        bound.fixture.pool.clone(),
        ExecutionSettings {
            queue_global_max: 1,
            queue_per_tenant_max: 20,
            ..ExecutionSettings::default()
        },
    );
    global
        .accept(
            &bound.principal,
            &bound.resolved,
            &json!({"n": 1}),
            None,
            generation,
            None,
        )
        .await
        .expect("the first queued run fits");
    let error = global
        .accept(
            &bound.principal,
            &bound.resolved,
            &json!({"n": 2}),
            None,
            generation,
            None,
        )
        .await
        .expect_err("the global bound is reached");
    assert!(matches!(error, ExecutionStoreError::QueueFull));

    let tenant = ExecutionRepository::new(
        bound.fixture.pool.clone(),
        ExecutionSettings {
            queue_global_max: 100,
            queue_per_tenant_max: 1,
            ..ExecutionSettings::default()
        },
    );
    let error = tenant
        .accept(
            &bound.principal,
            &bound.resolved,
            &json!({"n": 3}),
            None,
            generation,
            None,
        )
        .await
        .expect_err("the per-tenant bound is reached");
    assert!(matches!(error, ExecutionStoreError::QueueFull));
    bound.fixture.finish().await;
}

#[tokio::test]
async fn queue_deadline_is_created_at_plus_the_narrower_queue_bound() {
    let bound = bound_fixture(
        5,
        ExecutionSettings {
            run_queue_timeout: Duration::from_secs(2),
            ..ExecutionSettings::default()
        },
    )
    .await;
    let run = accept(&bound, &json!({"n": 1}), None)
        .await
        .expect("accept");
    let window = (run.queue_deadline - run.created_at).num_milliseconds();
    assert!(
        (1400..=2600).contains(&window),
        "the run queue timeout wins over the tool's 5 s: {window} ms"
    );

    let roomy = ExecutionRepository::new(bound.fixture.pool.clone(), ExecutionSettings::default());
    let narrow = ResolvedTool {
        manifest: bound.resolved.manifest.clone(),
        effective: effective(1),
        context: context(),
    };
    let generation = generation(&bound.fixture.pool).await;
    let run = roomy
        .accept(
            &bound.principal,
            &narrow,
            &json!({"n": 2}),
            None,
            generation,
            None,
        )
        .await
        .expect("accept");
    let window = (run.queue_deadline - run.created_at).num_milliseconds();
    assert!(
        (500..=1500).contains(&window),
        "the tool's 1 s queue bound wins over the 240 s timeout: {window} ms"
    );
    bound.fixture.finish().await;
}

// ── inspection ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn get_events_and_cancel_are_tenant_scoped_ordered_and_idempotent() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let tenant = authority(TENANT_A);
    let run = accept(&bound, &json!({"n": 1}), None)
        .await
        .expect("accept");
    let run_text = run.run_id.to_string();
    let run_id = uuid7(&run_text);

    let fetched = bound.repository.get(&tenant, &run_id).await.expect("get");
    assert_eq!(fetched.run_id.to_string(), run_text);
    let error = bound
        .repository
        .get(&authority(TENANT_PLATFORM), &run_id)
        .await
        .expect_err("another tenant's run is not found");
    assert!(matches!(error, ExecutionStoreError::NotFound));

    for kind in ["running", "succeeded"] {
        sqlx::query(
            "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) \
             VALUES ($1::uuid,$2::uuid,$3)",
        )
        .bind(TENANT_A)
        .bind(&run_text)
        .bind(kind)
        .execute(&bound.fixture.pool)
        .await
        .expect("event row");
    }
    let events = bound
        .repository
        .events(&tenant, &run_id, 0, 2)
        .await
        .expect("events");
    assert_eq!(
        events
            .iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        ["queued", "running"]
    );
    let tail = bound
        .repository
        .events(&tenant, &run_id, events[0].event_id, 100)
        .await
        .expect("events after");
    assert_eq!(
        tail.iter()
            .map(|event| event.kind.as_str())
            .collect::<Vec<_>>(),
        ["running", "succeeded"]
    );
    assert!(
        bound
            .repository
            .events(&authority(TENANT_PLATFORM), &run_id, 0, 100)
            .await
            .expect("scoped events")
            .is_empty()
    );

    let cancelled = bound
        .repository
        .cancel(&tenant, &run_id)
        .await
        .expect("cancel");
    assert!(cancelled.cancel_requested);
    let flag: bool = sqlx::query_scalar(
        "SELECT cancel_requested FROM public.mcp_runs \
         WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(&run_text)
    .fetch_one(&bound.fixture.pool)
    .await
    .expect("cancel flag");
    assert!(flag);
    let requested = |pool: PgPool, run: String| async move {
        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.mcp_run_events \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND kind = 'cancel_requested'",
        )
        .bind(TENANT_A)
        .bind(run)
        .fetch_one(&pool)
        .await
        .expect("cancel events");
        count
    };
    assert_eq!(
        requested(bound.fixture.pool.clone(), run_text.clone()).await,
        1
    );

    let again = bound
        .repository
        .cancel(&tenant, &run_id)
        .await
        .expect("cancel again");
    assert!(again.cancel_requested);
    assert_eq!(
        requested(bound.fixture.pool.clone(), run_text.clone()).await,
        1,
        "a repeated cancel appends no event"
    );

    // Only the worker transitions an active run: a terminal run is never flagged in storage,
    // but the reference's response still reports the request.
    let terminal = accept(&bound, &json!({"n": 2}), None)
        .await
        .expect("accept");
    let terminal_id = terminal.run_id.to_string();
    // `mcp_guard_run` only permits the worker's transition matrix, so walk it: a direct
    // queued → succeeded update is refused by the schema, which is the point of the guard.
    for statement in [
        "UPDATE public.mcp_runs SET status = 'starting', started_at = clock_timestamp() \
         WHERE run_id = $1::uuid",
        "UPDATE public.mcp_runs SET status = 'running' WHERE run_id = $1::uuid",
        "UPDATE public.mcp_runs SET status = 'succeeded', finished_at = clock_timestamp() \
         WHERE run_id = $1::uuid",
    ] {
        sqlx::query(statement)
            .bind(&terminal_id)
            .execute(&bound.fixture.pool)
            .await
            .expect("finish the run");
    }
    let returned = bound
        .repository
        .cancel(&tenant, &uuid7(&terminal_id))
        .await
        .expect("cancel a terminal run");
    assert!(returned.cancel_requested);
    let stored: bool =
        sqlx::query_scalar("SELECT cancel_requested FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&terminal_id)
            .fetch_one(&bound.fixture.pool)
            .await
            .expect("stored flag");
    assert!(!stored, "a terminal run's flag is never written");
    let appended: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_run_events \
         WHERE run_id = $1::uuid AND kind = 'cancel_requested'",
    )
    .bind(&terminal_id)
    .fetch_one(&bound.fixture.pool)
    .await
    .expect("terminal events");
    assert_eq!(appended, 0);
    bound.fixture.finish().await;
}

#[tokio::test]
async fn task_input_answers_follow_the_reference_rules() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let tenant = authority(TENANT_A);
    let inputs = TaskInputRepository::new(bound.fixture.pool.clone());
    let run = accept(&bound, &json!({"n": 1}), None)
        .await
        .expect("accept");
    let run_text = run.run_id.to_string();
    let run_id = uuid7(&run_text);

    open_input(&bound.fixture.pool, &run_text, "input-a", "approval-a").await;
    open_input(&bound.fixture.pool, &run_text, "input-b", "approval-b").await;
    open_input(&bound.fixture.pool, &run_text, "input-c", "approval-c").await;
    let rows = inputs
        .open_for(&tenant, &run_id)
        .await
        .expect("open inputs");
    assert_eq!(rows.len(), 3);
    assert!(rows.iter().all(|row| row.state == "open"));

    let mut responses = Map::new();
    responses.insert(
        "input-a".into(),
        json!({"action": "accept", "content": {"decision": "approved"}}),
    );
    responses.insert(
        "input-b".into(),
        json!({"action": "accept", "content": {"decision": "rejected"}}),
    );
    responses.insert("input-c".into(), json!("not an object"));
    responses.insert("unknown".into(), json!({"action": "accept"}));
    let answered = inputs
        .answer(
            &tenant,
            &run_id,
            &responses,
            &json!({"subject": "agent-09"}),
        )
        .await
        .expect("answer");
    assert_eq!(answered, 1);
    assert_eq!(
        input_state(&bound.fixture.pool, "input-a").await,
        "answered"
    );
    assert_eq!(input_state(&bound.fixture.pool, "input-b").await, "open");
    assert_eq!(input_state(&bound.fixture.pool, "input-c").await, "open");
    let message: Option<String> =
        sqlx::query_scalar("SELECT status_message FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_text)
            .fetch_one(&bound.fixture.pool)
            .await
            .expect("status message");
    assert_eq!(message.as_deref(), Some("reason required"));

    let mut retry = Map::new();
    retry.insert("input-b".into(), json!({"action": "decline"}));
    let answered = inputs
        .answer(&tenant, &run_id, &retry, &json!({"subject": "agent-09"}))
        .await
        .expect("answer");
    assert_eq!(answered, 1);
    assert_eq!(
        input_state(&bound.fixture.pool, "input-b").await,
        "answered"
    );
    let message: Option<String> =
        sqlx::query_scalar("SELECT status_message FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(&run_text)
            .fetch_one(&bound.fixture.pool)
            .await
            .expect("status message");
    assert_eq!(message, None, "a valid answer clears the stale hint");

    // A terminal run accepts no answer at all.
    let terminal = accept(&bound, &json!({"n": 2}), None)
        .await
        .expect("accept");
    let terminal_id = terminal.run_id.to_string();
    sqlx::query(
        "UPDATE public.mcp_runs SET status = 'failed', finished_at = clock_timestamp() \
         WHERE run_id = $1::uuid",
    )
    .bind(&terminal_id)
    .execute(&bound.fixture.pool)
    .await
    .expect("finish the run");
    open_input(&bound.fixture.pool, &terminal_id, "input-d", "approval-d").await;
    let mut late = Map::new();
    late.insert("input-d".into(), json!({"action": "accept"}));
    let answered = inputs
        .answer(
            &tenant,
            &uuid7(&terminal_id),
            &late,
            &json!({"subject": "agent-09"}),
        )
        .await
        .expect("answer");
    assert_eq!(answered, 0);
    assert_eq!(input_state(&bound.fixture.pool, "input-d").await, "open");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn activity_recent_is_newest_last_and_wire_is_the_contract() {
    let bound = bound_fixture(60, ExecutionSettings::default()).await;
    let run = accept(&bound, &json!({"n": 1}), None)
        .await
        .expect("accept");
    let run_text = run.run_id.to_string();
    let run_id = uuid7(&run_text);

    for (kind, text) in [
        ("phase", "planning"),
        ("started", "project started"),
        ("delivered", "handed over"),
    ] {
        sqlx::query(
            "INSERT INTO public.mcp_run_activity(tenant_id,run_id,kind,text,severity) \
             VALUES ($1::uuid,$2::uuid,$3,$4,'info')",
        )
        .bind(TENANT_A)
        .bind(&run_text)
        .bind(kind)
        .bind(text)
        .execute(&bound.fixture.pool)
        .await
        .expect("activity row");
    }

    let rows = run_activity::recent(&bound.fixture.pool, &authority(TENANT_A), &run_id, 2)
        .await
        .expect("recent activity");
    assert_eq!(rows.len(), 2);
    assert!(rows[0].seq < rows[1].seq, "newest last, ascending seq");
    assert_eq!(rows[1].text, "handed over");
    let wire = run_activity::wire(&rows);
    assert_eq!(wire.len(), 2);
    assert_eq!(wire[1]["kind"], json!("delivered"));
    assert_eq!(wire[1]["severity"], json!("info"));
    assert_eq!(wire[1]["seq"], json!(rows[1].seq));
    assert!(wire[1].get("source_ref").is_none());
    let at = wire[1]["at"].as_str().expect("iso-8601 at");
    assert!(at.contains('T') && at.ends_with("+00:00"), "{at}");
    assert!(
        run_activity::recent(
            &bound.fixture.pool,
            &authority(TENANT_PLATFORM),
            &run_id,
            50
        )
        .await
        .expect("scoped activity")
        .is_empty()
    );
    bound.fixture.finish().await;
}
