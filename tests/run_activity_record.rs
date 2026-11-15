//! Appending run activity: the newest-row dedupe, the tenant-scoped run check, and the text and
//! severity rules.
//!
//! Ported from the reference `src/tasks/activity.py` (`record`). A write is best effort, so it
//! reports `None` instead of failing when the row is not there; it is deduplicated against the
//! newest row only, because a driver that sees the same phase on many ticks records it once.
//! Every test runs against a real Postgres 18 through [`support::Fixture`].

mod support;

use sqlx::PgPool;

use mcp_server_rs::storage::run_activity::{self, ACTIVITY_LIMIT, TEXT_LIMIT};
use mcp_server_rs::tasks::severity_for;

use support::{Fixture, LICENCE_ID, TENANT_A, TOOL_ALPHA, authority, binding_fixture, uuid7};

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

/// The reference's `record` for the fixture tenant: the caller's `expect` is the test's.
async fn record(
    pool: &PgPool,
    run_id: &str,
    kind: &str,
    text: &str,
    severity: Option<&str>,
    source_ref: Option<&str>,
) -> Option<i64> {
    run_activity::record(
        pool,
        &authority(TENANT_A),
        &uuid7(run_id),
        kind,
        text,
        severity,
        source_ref,
    )
    .await
    .expect("record")
}

async fn row_count(pool: &PgPool, run_id: &str) -> i64 {
    sqlx::query_scalar("SELECT count(*) FROM public.mcp_run_activity WHERE run_id = $1::uuid")
        .bind(run_id)
        .fetch_one(pool)
        .await
        .expect("activity rows")
}

#[tokio::test]
async fn record_writes_one_row() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    let tenant = authority(TENANT_A);
    let run_id = uuid7(&run);

    let seq = run_activity::record(
        &fixture.pool,
        &tenant,
        &run_id,
        "phase",
        "building the site",
        None,
        Some("fr-project-1"),
    )
    .await
    .expect("record")
    .expect("the run exists, so the row is written");

    let rows = run_activity::recent(&fixture.pool, &tenant, &run_id, ACTIVITY_LIMIT)
        .await
        .expect("recent");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].seq, seq);
    assert_eq!(rows[0].kind, "phase");
    assert_eq!(rows[0].text, "building the site");
    assert_eq!(rows[0].severity, severity_for("phase"));

    fixture.finish().await;
}

#[tokio::test]
async fn record_dedupes_against_the_newest_row_only() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;

    assert!(
        record(&fixture.pool, &run, "phase", "building", None, None)
            .await
            .is_some()
    );
    assert!(
        record(&fixture.pool, &run, "phase", "building", None, None)
            .await
            .is_none(),
        "the newest row already says exactly this"
    );
    assert_eq!(row_count(&fixture.pool, &run).await, 1);

    assert!(
        record(&fixture.pool, &run, "phase", "testing", None, None)
            .await
            .is_some()
    );
    assert_eq!(row_count(&fixture.pool, &run).await, 2);

    assert!(
        record(&fixture.pool, &run, "phase", "building", None, None)
            .await
            .is_some(),
        "only the newest row dedupes: the one before it said something else"
    );
    assert_eq!(row_count(&fixture.pool, &run).await, 3);

    assert!(
        record(
            &fixture.pool,
            &run,
            "phase",
            "building",
            None,
            Some("fr-project-2")
        )
        .await
        .is_some(),
        "a different source ref is a different line"
    );
    assert_eq!(row_count(&fixture.pool, &run).await, 4);

    fixture.finish().await;
}

#[tokio::test]
async fn record_writes_nothing_for_an_unknown_run() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let unknown: String = sqlx::query_scalar("SELECT uuidv7()::text")
        .fetch_one(&fixture.pool)
        .await
        .expect("uuid");

    assert_eq!(
        record(
            &fixture.pool,
            &unknown,
            "phase",
            "building the site",
            None,
            None
        )
        .await,
        None,
        "record is best effort: an unknown run writes nothing and does not error"
    );
    assert_eq!(row_count(&fixture.pool, &unknown).await, 0);

    fixture.finish().await;
}

#[tokio::test]
async fn record_collapses_and_caps_the_text() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    let tenant = authority(TENANT_A);
    let run_id = uuid7(&run);

    record(
        &fixture.pool,
        &run,
        "phase",
        "  building \n\t the   site  ",
        None,
        None,
    )
    .await;
    let long = "x".repeat(600);
    record(&fixture.pool, &run, "failed", &long, None, None).await;
    record(&fixture.pool, &run, "delivered", "   \n ", None, None).await;

    let rows = run_activity::recent(&fixture.pool, &tenant, &run_id, ACTIVITY_LIMIT)
        .await
        .expect("recent");
    assert_eq!(rows.len(), 3);
    assert_eq!(
        rows[0].text, "building the site",
        "every whitespace run collapses to one space"
    );
    assert_eq!(rows[1].text.chars().count(), TEXT_LIMIT);
    assert!(rows[1].text.chars().all(|character| character == 'x'));
    assert_eq!(
        rows[2].text, "delivered",
        "a blank body falls back to the kind"
    );

    fixture.finish().await;
}

#[tokio::test]
async fn record_defaults_the_severity_from_the_kind() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let run = seed_run(&fixture, "running").await;
    let tenant = authority(TENANT_A);
    let run_id = uuid7(&run);

    record(
        &fixture.pool,
        &run,
        "failed",
        "the project failed",
        None,
        None,
    )
    .await;
    record(
        &fixture.pool,
        &run,
        "phase",
        "building the site",
        Some("critical"),
        None,
    )
    .await;
    record(
        &fixture.pool,
        &run,
        "refused",
        "the start was refused",
        Some(""),
        None,
    )
    .await;

    let rows = run_activity::recent(&fixture.pool, &tenant, &run_id, ACTIVITY_LIMIT)
        .await
        .expect("recent");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0].severity, severity_for("failed"));
    assert_eq!(
        rows[1].severity, "critical",
        "an explicit severity wins over the kind's default"
    );
    assert_eq!(
        rows[2].severity,
        severity_for("refused"),
        "an empty severity is the reference's falsy value, so the kind decides"
    );

    fixture.finish().await;
}
