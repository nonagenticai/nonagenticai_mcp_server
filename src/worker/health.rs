//! The worker's internal probes and metrics (slice S8).
//!
//! Ported from the reference `src/execution/health.py`. Nothing here is reachable from the
//! public API surface: the probe listener is bound on `MCP_WORKER_PROBE_PORT` and restricted by
//! the worker's NetworkPolicy, exactly as the reference's deployment does.
//!
//! `/health/live` proves the process is up. `/health/ready` proves the worker can actually take
//! work — mounted credentials readable, the expected relations present, the operator's capacity
//! provisioned, and the sandbox backend usable — inside the reference's 8-second budget, and
//! answers 503 with `{"status":"not_ready"}` for every refusal. `/metrics` renders the
//! reference's low-cardinality families in Prometheus 0.0.4 text.

use std::sync::Arc;
use std::time::Duration;

use axum::extract::State;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};
use sqlx::PgPool;

use crate::worker::backend::Backend;
use crate::worker::creds::CredentialResolver;
use crate::worker::scheduler::Scheduler;
use crate::worker::store::WorkerStore;

/// The readiness budget (`health.py:21`).
pub const READY_BUDGET: Duration = Duration::from_secs(8);

/// The relations a ready worker must be able to reach. Readiness never reads package content or
/// mutates data: `LIMIT 0` resolves every name through the planner and returns nothing.
const REQUIRED_RELATIONS: &str = "SELECT 1 FROM public.mcp_runs, public.mcp_run_events, \
     public.mcp_run_api_calls, public.mcp_task_inputs, public.mcp_execution_slots, \
     public.mcp_tools, public.mcp_tool_versions, public.mcp_tool_version_files, \
     public.mcp_services, public.mcp_service_versions, public.mcp_operation_versions, \
     public.mcp_sources, public.mcp_credential_profiles, public.mcp_credential_refs LIMIT 0";

/// The recent-sample bound both metric families share (`health.py:52`).
const RECENT_SAMPLE: i64 = 10_000;

/// Everything the probe surface reads.
#[derive(Clone)]
struct Probes {
    store: WorkerStore,
    scheduler: Arc<Scheduler>,
    backend: Arc<dyn Backend>,
    credentials: Arc<dyn CredentialResolver>,
}

/// The worker's probe and metrics router.
pub fn app(
    store: WorkerStore,
    scheduler: Arc<Scheduler>,
    backend: Arc<dyn Backend>,
    credentials: Arc<dyn CredentialResolver>,
) -> Router {
    let probes = Probes {
        store,
        scheduler,
        backend,
        credentials,
    };
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .route("/metrics", get(metrics))
        .with_state(probes)
}

/// `GET /health/live`
async fn live() -> Json<Value> {
    Json(json!({"status": "alive"}))
}

/// `GET /health/ready`
///
/// Every dependency is checked inside one budget; a timeout is a refusal like any other.
async fn ready(State(probes): State<Probes>) -> Response {
    match tokio::time::timeout(READY_BUDGET, ready_within_budget(&probes)).await {
        Ok(Ok(())) => Json(json!({"status": "ready"})).into_response(),
        Ok(Err(NotReady)) | Err(_) => (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
            .into_response(),
    }
}

/// One readiness refusal. The probe's body is fixed either way; nothing about the failure is
/// exposed on the unauthenticated listener.
#[derive(Debug)]
struct NotReady;

async fn ready_within_budget(probes: &Probes) -> Result<(), NotReady> {
    // The mounted material is still present and well formed.
    probes.credentials.read().map_err(|_| NotReady)?;
    verify_schema(probes.store.pool())
        .await
        .map_err(|_| NotReady)?;
    probes
        .scheduler
        .verify_capacity()
        .await
        .map_err(|_| NotReady)?;
    probes.backend.ready().await.map_err(|_| NotReady)?;
    Ok(())
}

/// The reference's `verify_schema` with the worker's least privilege (`require_audit=False`):
/// one round trip, the application's expected relations, and a populated catalog state.
///
/// The Rust service has no `alembic_version` table (sqlx owns its migrations), so the revision
/// check is the catalog state row plus the relation set rather than a stored revision string.
pub async fn verify_schema(pool: &PgPool) -> Result<(), sqlx::Error> {
    let generation: Option<i64> =
        sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
            .fetch_optional(pool)
            .await?;
    generation.ok_or(sqlx::Error::RowNotFound)?;
    sqlx::query(REQUIRED_RELATIONS).execute(pool).await?;
    Ok(())
}

/// `GET /metrics`
///
/// A database failure is a 500, never a stale or partial render: an operator reading a zero is
/// worse than an operator reading an error.
async fn metrics(State(probes): State<Probes>) -> Response {
    match metrics_body(probes.store.pool()).await {
        Ok(body) => {
            let mut response = body.into_response();
            response.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("text/plain; version=0.0.4"),
            );
            response
        }
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "metrics unavailable\n").into_response(),
    }
}

/// Render the reference's exact metric names, in its order.
async fn metrics_body(pool: &PgPool) -> Result<String, sqlx::Error> {
    let (queued, starting, running, queue_age): (i64, i64, i64, f64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE status = 'queued') AS queued, \
         count(*) FILTER (WHERE status = 'starting') AS starting, \
         count(*) FILTER (WHERE status = 'running') AS running, \
         coalesce(extract(epoch FROM clock_timestamp() - min(created_at) \
             FILTER (WHERE status = 'queued')), 0)::double precision AS queue_age_seconds \
         FROM public.mcp_runs WHERE status IN ('queued', 'starting', 'running')",
    )
    .fetch_one(pool)
    .await?;
    let (slots_used, slots_quarantined, slots_draining): (i64, i64, i64) = sqlx::query_as(
        "SELECT count(*) FILTER (WHERE run_id IS NOT NULL) AS slots_used, \
         count(*) FILTER (WHERE quarantined) AS slots_quarantined, \
         count(*) FILTER (WHERE draining) AS slots_draining \
         FROM public.mcp_execution_slots",
    )
    .fetch_one(pool)
    .await?;
    let (api_duration,): (f64,) = sqlx::query_as(
        "SELECT coalesce(avg(extract(epoch FROM finished_at - started_at)), 0)::double precision \
         AS api_duration_seconds \
         FROM (SELECT started_at, finished_at FROM public.mcp_run_api_calls \
               ORDER BY started_at DESC LIMIT $1) recent WHERE finished_at IS NOT NULL",
    )
    .bind(RECENT_SAMPLE)
    .fetch_one(pool)
    .await?;
    let (run_duration, cold_start): (f64, f64) = sqlx::query_as(
        "SELECT coalesce(avg(extract(epoch FROM finished_at - started_at)), 0)::double precision \
         AS run_duration_seconds, \
         coalesce(avg(extract(epoch FROM started_at - created_at)), 0)::double precision \
         AS cold_start_seconds \
         FROM (SELECT created_at, started_at, finished_at FROM public.mcp_runs \
               ORDER BY run_id DESC LIMIT $1) recent WHERE started_at IS NOT NULL",
    )
    .bind(RECENT_SAMPLE)
    .fetch_one(pool)
    .await?;
    let recent_runs: Vec<(String, i64)> = sqlx::query_as(
        "SELECT status, count(*) AS n FROM (SELECT status FROM public.mcp_runs \
         ORDER BY run_id DESC LIMIT $1) recent GROUP BY status",
    )
    .bind(RECENT_SAMPLE)
    .fetch_all(pool)
    .await?;
    let recent_events: Vec<(String, i64)> = sqlx::query_as(
        "SELECT kind, count(*) AS n FROM (SELECT kind FROM public.mcp_run_events \
         ORDER BY event_id DESC LIMIT $1) recent \
         WHERE kind IN ('broker_denied', 'api_concurrency_denied', 'api_rate_denied', \
         'slot_quarantined', 'orphan_cleaned', 'requeued_unstarted', 'interrupted', \
         'cancel_requested') GROUP BY kind",
    )
    .bind(RECENT_SAMPLE)
    .fetch_all(pool)
    .await?;

    let mut lines = Vec::with_capacity(12 + recent_runs.len() + recent_events.len());
    lines.push(format!("mcp_execution_queued {queued}"));
    lines.push(format!("mcp_execution_starting {starting}"));
    lines.push(format!("mcp_execution_running {running}"));
    lines.push(format!("mcp_execution_queue_age_seconds {queue_age:?}"));
    lines.push(format!("mcp_execution_slots_used {slots_used}"));
    lines.push(format!(
        "mcp_execution_slots_quarantined {slots_quarantined}"
    ));
    lines.push(format!("mcp_execution_slots_draining {slots_draining}"));
    lines.push(format!(
        "mcp_execution_api_duration_seconds {api_duration:?}"
    ));
    lines.push(format!(
        "mcp_execution_run_duration_seconds {run_duration:?}"
    ));
    lines.push(format!("mcp_execution_cold_start_seconds {cold_start:?}"));
    for (status, count) in recent_runs {
        lines.push(format!(
            "mcp_execution_recent_runs{{status=\"{status}\"}} {count}"
        ));
    }
    for (kind, count) in recent_events {
        lines.push(format!(
            "mcp_execution_recent_events{{kind=\"{kind}\"}} {count}"
        ));
    }
    Ok(lines.join("\n") + "\n")
}
