//! Forwarding a verified answer upstream: `claim_answered`, `reopen` and `mark_forwarded`.
//!
//! Ported from the reference `src/storage/task_inputs.py`. Delivery is at-least-once (the locks
//! are released when the claim returns), a refusal reopens the input and tells the client why,
//! and a terminal run is never given a hint nothing will read. Every test runs against a real
//! Postgres 18 through [`support::Fixture`], exactly as `tests/execution_storage.rs` does.

mod support;

use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::storage::task_inputs::TaskInputRepository;

use support::{Fixture, LICENCE_ID, TENANT_A, TOOL_ALPHA, binding_fixture};

/// One draft run of the fixture tool in the given status; returns its id.
async fn seed_run(fixture: &Fixture, status: &str) -> String {
    sqlx::query_scalar(
        "INSERT INTO public.mcp_runs(run_id,tenant_id,gateway_license_id,owner_tenant_id,tool_id,\
         tool_version,profile_snapshot,authority,inputs,input_hash,created_by,queue_deadline,\
         mode,status) \
         VALUES (uuidv7(),$1::uuid,$2::uuid,$1::uuid,$3::uuid,1,'{}','{}','{}',$4,'{}', \
         clock_timestamp() + interval '1 hour','draft',$5) RETURNING run_id::text",
    )
    .bind(TENANT_A)
    .bind(LICENCE_ID)
    .bind(TOOL_ALPHA)
    .bind("d".repeat(64))
    .bind(status)
    .fetch_one(&fixture.pool)
    .await
    .expect("run row")
}

/// One task input in a given state; an `answered` row carries a response, an actor and an
/// `answered_at` that many minutes in the past.
async fn seed_input(pool: &PgPool, run_id: &str, key: &str, state: &str, minutes_ago: i32) {
    let answered = state == "answered";
    sqlx::query(
        "INSERT INTO public.mcp_task_inputs(input_key,tenant_id,run_id,source_ref,request,state,\
         response,actor,answered_at) \
         VALUES ($1,$2::uuid,$3::uuid,$4,$5,$6,$7,$8, \
         CASE WHEN $6 = 'answered' THEN now() - make_interval(mins => $9::int) END)",
    )
    .bind(key)
    .bind(TENANT_A)
    .bind(run_id)
    .bind(format!("approval-{key}"))
    .bind(json!({"kind": "approval", "title": "Approve the delivered work"}))
    .bind(state)
    .bind(answered.then(|| json!({"action": "accept"})))
    .bind(answered.then(|| json!({"subject": "agent-09"})))
    .bind(minutes_ago)
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

async fn status_message(pool: &PgPool, run_id: &str) -> Option<String> {
    sqlx::query_scalar("SELECT status_message FROM public.mcp_runs WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("run status message")
}

#[tokio::test]
async fn claim_answered_returns_only_answered_rows_oldest_first_and_honours_the_limit() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    seed_input(&fixture.pool, &run, "k_new", "answered", 1).await;
    seed_input(&fixture.pool, &run, "k_old", "answered", 9).await;
    seed_input(&fixture.pool, &run, "k_mid", "answered", 5).await;
    seed_input(&fixture.pool, &run, "k_open", "open", 0).await;
    seed_input(&fixture.pool, &run, "k_forwarded", "forwarded", 0).await;
    seed_input(&fixture.pool, &run, "k_closed", "closed", 0).await;
    let repository = TaskInputRepository::new(fixture.pool.clone());

    let claimed = repository.claim_answered(10).await.expect("claim answered");
    let keys: Vec<&str> = claimed.iter().map(|row| row.input_key.as_str()).collect();
    assert_eq!(keys, ["k_old", "k_mid", "k_new"], "{keys:?}");
    assert!(claimed.iter().all(|row| row.state == "answered"));
    assert_eq!(claimed[0].tenant_id.as_str(), TENANT_A);
    assert_eq!(claimed[0].run_id.as_str(), run.as_str());
    assert_eq!(claimed[0].response, Some(json!({"action": "accept"})));
    assert_eq!(claimed[0].actor, Some(json!({"subject": "agent-09"})));
    assert!(claimed[0].answered_at.is_some());

    let limited: Vec<String> = repository
        .claim_answered(2)
        .await
        .expect("claim answered")
        .into_iter()
        .map(|row| row.input_key)
        .collect();
    assert_eq!(limited, ["k_old", "k_mid"], "{limited:?}");

    assert!(
        repository
            .claim_answered(2)
            .await
            .expect("claim answered")
            .len()
            == 2,
        "the locks of the first claim are released, so the rows are claimed again"
    );

    fixture.finish().await;
}

#[tokio::test]
async fn mark_forwarded_moves_an_answered_row_and_leaves_other_states_alone() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    seed_input(&fixture.pool, &run, "k_answered", "answered", 1).await;
    seed_input(&fixture.pool, &run, "k_open", "open", 0).await;
    seed_input(&fixture.pool, &run, "k_closed", "closed", 0).await;
    let repository = TaskInputRepository::new(fixture.pool.clone());

    repository
        .mark_forwarded("k_answered")
        .await
        .expect("mark forwarded");
    assert_eq!(input_state(&fixture.pool, "k_answered").await, "forwarded");

    repository
        .mark_forwarded("k_open")
        .await
        .expect("mark forwarded");
    assert_eq!(input_state(&fixture.pool, "k_open").await, "open");

    repository
        .mark_forwarded("k_closed")
        .await
        .expect("mark forwarded");
    assert_eq!(input_state(&fixture.pool, "k_closed").await, "closed");

    repository
        .mark_forwarded("k_answered")
        .await
        .expect("mark forwarded");
    assert_eq!(input_state(&fixture.pool, "k_answered").await, "forwarded");

    repository
        .mark_forwarded("k_missing")
        .await
        .expect("an unknown key is a no-op, not an error");

    fixture.finish().await;
}

#[tokio::test]
async fn reopen_returns_the_row_to_open_and_sets_the_run_status_message() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    seed_input(&fixture.pool, &run, "k1", "answered", 1).await;
    seed_input(&fixture.pool, &run, "k_open", "open", 0).await;
    let repository = TaskInputRepository::new(fixture.pool.clone());
    let message = "fr refused the answer: the approval expired";

    repository.reopen("k1", message).await.expect("reopen");

    let row: (String, Option<Value>, Option<Value>, Option<String>) = sqlx::query_as(
        "SELECT state, response, actor, answered_at::text \
         FROM public.mcp_task_inputs WHERE input_key = $1",
    )
    .bind("k1")
    .fetch_one(&fixture.pool)
    .await
    .expect("reopened input");
    assert_eq!(row.0, "open");
    assert_eq!(row.1, None, "the refused response is dropped");
    assert_eq!(row.2, None, "the refused actor is dropped");
    assert_eq!(row.3, None, "the answer instant is dropped");
    assert_eq!(
        status_message(&fixture.pool, &run).await.as_deref(),
        Some(message)
    );

    // Only an answered row changes: an open input leaves the run's message where it was.
    let untouched = seed_run(&fixture, "running").await;
    seed_input(&fixture.pool, &untouched, "k_b", "open", 0).await;
    repository
        .reopen("k_b", "this must not land")
        .await
        .expect("reopen");
    assert_eq!(input_state(&fixture.pool, "k_b").await, "open");
    assert_eq!(status_message(&fixture.pool, &untouched).await, None);

    // A long refusal keeps its first 512 characters, which is what the column accepts.
    let long = "r".repeat(600);
    let answered = seed_run(&fixture, "running").await;
    seed_input(&fixture.pool, &answered, "k_c", "answered", 1).await;
    repository.reopen("k_c", &long).await.expect("reopen");
    assert_eq!(
        status_message(&fixture.pool, &answered).await,
        Some("r".repeat(512))
    );

    fixture.finish().await;
}

#[tokio::test]
async fn reopen_does_not_touch_a_terminal_run() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "succeeded").await;
    seed_input(&fixture.pool, &run, "k1", "answered", 1).await;
    sqlx::query("UPDATE public.mcp_runs SET status_message = 'finished' WHERE run_id = $1::uuid")
        .bind(&run)
        .execute(&fixture.pool)
        .await
        .expect("seed status message");
    let repository = TaskInputRepository::new(fixture.pool.clone());

    repository
        .reopen("k1", "fr refused the answer: too late")
        .await
        .expect("reopen");

    assert_eq!(input_state(&fixture.pool, "k1").await, "open");
    assert_eq!(
        status_message(&fixture.pool, &run).await.as_deref(),
        Some("finished"),
        "a terminal run keeps its message: nothing will read the hint"
    );

    fixture.finish().await;
}
