//! The worker half of the run store: fenced ownership, the lease, the pod identity, the
//! lifecycle transitions, the upstream-call journal and the API permits.
//!
//! Ported from the reference `src/storage/executions.py` (`owned` … `release_permit`, lines
//! 270-533). Every statement that mutates a run re-proves ownership inside the same transaction
//! ([`WorkerStore::owned`]): a worker whose lease expired, whose fence moved or whose run was
//! cancelled can never write. A denial is raised before anything is committed, so a lost race
//! persists nothing.
//!
//! Transactions stay short deliberately — no connection is held across the network calls the
//! worker brokers (the journal's whole point is that the intent commits *before* the upstream
//! call and the outcome commits after it).
//!
//! Two bounds are deployment-owned rather than per-run: per-service call and concurrency
//! ceilings come from `WorkerSettings::service_limits_file` (the reference's `RateLimits.read`),
//! and the permit table is itself the shared counter, so the global ceiling holds across worker
//! replicas without any in-process state.

use std::path::Path;

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::postgres::Postgres;
use sqlx::{AssertSqlSafe, PgPool, Transaction};
use uuid::Uuid;

use crate::auth::Rfc4122Uuid;
use crate::config::{ExecutionSettings, WorkerSettings};
use crate::execution::RunStatus;
use crate::storage::catalog::CatalogStoreError;
use crate::storage::executions::ExecutionStoreError;
use crate::worker::row::{WorkerRow, decode_worker, worker_projection};

/// The reference's permit lock: one advisory transaction lock serializes the global permit
/// tally, so the concurrency ceiling is race-free across replicas.
const PERMIT_LOCK: i64 = 72_441_003;

/// `mcp_run_events` is capped at 256 rows per run — the reference's per-run lifecycle bound.
const EVENT_LIMIT: i64 = 256;

/// The retention function's declared batch bound (`mcp_expire_run_payloads`).
const EXPIRE_BATCH: i32 = 128;

/// `RateLimits.read`: deployment-owned overrides of one service's upstream ceilings.
const SERVICE_LIMITS_MAX_BYTES: u64 = 262_144;

/// `RateLimits.limits`: at most 1024 per-service entries.
const SERVICE_LIMITS_MAX_ENTRIES: usize = 1024;

/// A refused or impossible worker storage operation.
#[derive(Debug, thiserror::Error)]
pub enum WorkerStoreError {
    /// The worker does not own the run (wrong fence, expired lease, cancelled, terminal, or past
    /// its deadline), or a bound would be exceeded. The reference's `ExecutionDeniedError`.
    #[error("worker operation denied")]
    Denied,
    /// A storage failure, or a stored value the worker refuses to interpret.
    #[error(transparent)]
    Store(sqlx::Error),
}

impl From<sqlx::Error> for WorkerStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(error)
    }
}

/// A row the shared decoder rejected carries no `sqlx` type, so it travels as a decode failure;
/// a database failure keeps its own error.
impl From<ExecutionStoreError> for WorkerStoreError {
    fn from(error: ExecutionStoreError) -> Self {
        match error {
            ExecutionStoreError::Store(CatalogStoreError::Database(error)) => Self::Store(error),
            other => Self::Store(sqlx::Error::Decode(Box::new(other))),
        }
    }
}

/// Every worker storage call's result.
pub type Result<T> = std::result::Result<T, WorkerStoreError>;

/// One held API permit.
#[derive(Debug, Clone)]
pub struct Permit {
    /// `mcp_api_permits.permit_id`, a version-7 UUID.
    pub id: Uuid,
}

/// The broker's operation model, reduced to what the journal stores.
#[derive(Debug, Clone)]
pub struct JournalOperation {
    /// The upstream operation's identity.
    pub id: Rfc4122Uuid,
    /// The operation contract's version.
    pub version: i32,
    /// `read_only` or `writes` (the DDL's `mcp_run_api_calls_effect_check`).
    pub effect: String,
    /// How many calls one run may journal against this operation.
    pub pagination_limit: i64,
}

/// The worker-side run store: one pool, the worker settings, the retention bound, and the
/// deployment's per-service ceilings.
///
/// The ceilings are read once, at construction, exactly as the reference reads them in
/// `ExecutionRepository.__init__`. A file that fails to parse is not ignored: [`WorkerStore::permit`]
/// refuses every new permit until the deployment is fixed (fail closed).
#[derive(Clone)]
pub struct WorkerStore {
    pool: PgPool,
    settings: WorkerSettings,
    execution: ExecutionSettings,
    service_limits: std::result::Result<ServiceLimits, String>,
}

impl WorkerStore {
    /// Bind the store to a pool and the configured worker and retention settings.
    pub fn new(pool: PgPool, settings: WorkerSettings, execution: ExecutionSettings) -> Self {
        // `service_limits_file` is the reference's `api_rate_limits_file`: absent by default.
        let service_limits = ServiceLimits::read(settings.service_limits_file.as_deref());
        Self {
            pool,
            settings,
            execution,
            service_limits,
        }
    }

    /// The worker settings this store was built with.
    pub fn settings(&self) -> &WorkerSettings {
        &self.settings
    }

    /// The worker's pool, for the two statements that own their own transaction boundaries:
    /// the claim scheduler and lease recovery. Everything else goes through a method above so
    /// ownership is proven in the same transaction as the write.
    pub(crate) fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// Append one run event, bounded to `EVENT_LIMIT` rows per run.
    pub async fn event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        row: &WorkerRow,
        kind: &str,
    ) -> Result<()> {
        // No untrusted logs or credentials are persisted. Each run has a bounded lifecycle.
        sqlx::query(
            "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) \
             SELECT $1::uuid,$2::uuid,$3 \
             WHERE (SELECT count(*) FROM public.mcp_run_events \
                    WHERE tenant_id = $1::uuid AND run_id = $2::uuid) < $4",
        )
        .bind(row.run.tenant_id.to_string())
        .bind(row.run.run_id.to_string())
        .bind(kind)
        .bind(EVENT_LIMIT)
        .execute(&mut **tx)
        .await?;
        Ok(())
    }

    /// The reference's `owned`: lock the run and prove this worker still owns it.
    ///
    /// One `SELECT … FOR UPDATE` keyed on the run, the worker and the fence, with the lease
    /// unexpired — the exact conditions the reference uses — so the row is locked for the rest of
    /// the caller's transaction. `allow_cancel` is set only by the operations a cancelled run must
    /// still perform (heartbeat, finish, a journalled outcome).
    pub async fn owned(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        run_id: &Rfc4122Uuid,
        worker: &str,
        fence: i64,
        allow_cancel: bool,
    ) -> Result<WorkerRow> {
        let statement = format!(
            "SELECT {} FROM public.mcp_runs \
             WHERE run_id = $1::uuid AND worker_id = $2::uuid AND fence = $3 \
             AND lease_until > clock_timestamp() FOR UPDATE",
            worker_projection()
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(run_id.to_string())
            .bind(worker)
            .bind(fence)
            .fetch_optional(&mut **tx)
            .await?
            .ok_or(WorkerStoreError::Denied)?;
        let row: WorkerRow = decode_worker(&row)?;
        if allow_cancel {
            return Ok(row);
        }
        // A claimed run always carries a deadline (both claim paths set it). A null one is
        // outside the domain: the reference's comparison would abort, so the worker refuses
        // rather than let an unbounded run proceed.
        let expired = row.deadline.is_none_or(|deadline| deadline <= Utc::now());
        if row.run.cancel_requested
            || !matches!(row.run.status, RunStatus::Starting | RunStatus::Running)
            || expired
        {
            return Err(WorkerStoreError::Denied);
        }
        Ok(row)
    }

    /// Extend the lease and every permit this run's fence holds.
    ///
    /// Returns the row as the database now has it (the reference returns the pre-update row and
    /// keeps it as the caller's working row; the fence and worker are unchanged either way).
    pub async fn heartbeat(&self, row: &WorkerRow) -> Result<WorkerRow> {
        let worker = row.worker()?;
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, &row.run.run_id, worker, row.fence, true)
            .await?;
        let (lease_until_us, heartbeat_at_us): (i64, i64) = sqlx::query_as(
            "UPDATE public.mcp_runs \
             SET lease_until = clock_timestamp() + make_interval(secs => $1::double precision), \
             heartbeat_at = clock_timestamp() \
             WHERE run_id = $2::uuid \
             RETURNING (extract(epoch FROM lease_until) * 1000000)::bigint AS lease_until_us, \
             (extract(epoch FROM heartbeat_at) * 1000000)::bigint AS heartbeat_at_us",
        )
        .bind(self.settings.lease.as_secs_f64())
        .bind(row.run.run_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE public.mcp_api_permits \
             SET expires_at = clock_timestamp() + make_interval(secs => $1::double precision) \
             WHERE run_id = $2::uuid AND fence = $3",
        )
        .bind(self.settings.lease.as_secs_f64())
        .bind(row.run.run_id.to_string())
        .bind(row.fence)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        let mut refreshed = row.clone();
        refreshed.lease_until = Some(instant(lease_until_us)?);
        refreshed.heartbeat_at = Some(instant(heartbeat_at_us)?);
        Ok(refreshed)
    }

    /// Record the runner pod: the intent first (name alone), then the immutable UID.
    ///
    /// The UID only ever fills in — `coalesce` keeps the first one written, so a recreate can
    /// never move the run onto a second pod.
    pub async fn pod(&self, row: &WorkerRow, name: &str, uid: Option<&str>) -> Result<()> {
        let worker = row.worker()?;
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, &row.run.run_id, worker, row.fence, false)
            .await?;
        sqlx::query(
            "UPDATE public.mcp_runs SET pod_name = $1, pod_uid = coalesce($2, pod_uid) \
             WHERE run_id = $3::uuid",
        )
        .bind(name)
        .bind(uid)
        .bind(row.run.run_id.to_string())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The reference's `running`: start the run and narrow its deadline to the wall bound.
    ///
    /// The deadline becomes `least(deadline, now + min(wall_seconds, run_max))`, so the claim's
    /// start allowance can never extend a run past its wall limit. The transition only applies
    /// while the run is `starting`; the event is appended either way, exactly as the reference
    /// does.
    pub async fn running(&self, row: &WorkerRow) -> Result<WorkerRow> {
        let worker = row.worker()?;
        let wall = row
            .limits()?
            .wall_seconds
            .min(u32::try_from(self.settings.run_max.as_secs()).unwrap_or(u32::MAX));
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, &row.run.run_id, worker, row.fence, false)
            .await?;
        let started: Option<(i64, Option<i64>)> = sqlx::query_as(
            "UPDATE public.mcp_runs SET status = 'running', started_at = clock_timestamp(), \
             deadline = least(deadline, clock_timestamp() + make_interval(secs => $2::double precision)) \
             WHERE run_id = $1::uuid AND status = 'starting' \
             RETURNING (extract(epoch FROM started_at) * 1000000)::bigint AS started_at_us, \
             (extract(epoch FROM deadline) * 1000000)::bigint AS deadline_us",
        )
        .bind(row.run.run_id.to_string())
        .bind(f64::from(wall))
        .fetch_optional(&mut *tx)
        .await?;
        self.event(&mut tx, row, "running").await?;
        tx.commit().await?;
        let mut refreshed = row.clone();
        if let Some((started_at_us, deadline_us)) = started {
            refreshed.run.started_at = Some(instant(started_at_us)?);
            refreshed.deadline = deadline_us.map(instant).transpose()?;
            refreshed.run.status = RunStatus::Running;
        }
        Ok(refreshed)
    }

    /// The reference's `finish`: the terminal transition, then either quarantine the slot or
    /// release everything the run holds.
    ///
    /// `absent` means the run's channel is gone (graceful shutdown, lost worker, cancellation):
    /// the outcome of any in-flight upstream call is unknown, so it is finalized as
    /// `outcome_unknown`, the slot is freed and the permits and ownership are cleared. Without
    /// `absent` the slot is quarantined instead — capacity stays out of service until the
    /// reconciler proves the run over, because the pod may still be running.
    ///
    /// A run whose cancel was requested finishes as `cancelled` (absent) or `interrupted`, never
    /// with the caller's status: the reference overrides it the same way.
    pub async fn finish(
        &self,
        row: &WorkerRow,
        status: &str,
        result: Option<&Value>,
        code: Option<&str>,
        absent: bool,
    ) -> Result<()> {
        let worker = row.worker()?;
        let run_id = row.run.run_id.to_string();
        let mut tx = self.pool.begin().await?;
        let current = self
            .owned(&mut tx, &row.run.run_id, worker, row.fence, true)
            .await?;
        if !current.run.status.is_terminal() {
            let mut status = status.to_owned();
            let mut result = result.cloned();
            let mut code = code.map(str::to_owned);
            if current.run.cancel_requested {
                if current.run.status != RunStatus::Cancelling {
                    sqlx::query(
                        "UPDATE public.mcp_runs SET status = 'cancelling' WHERE run_id = $1::uuid",
                    )
                    .bind(&run_id)
                    .execute(&mut *tx)
                    .await?;
                }
                status = if absent { "cancelled" } else { "interrupted" }.to_owned();
                result = None;
                code = None;
            }
            // The reference binds `Jsonb(result)` unconditionally, so a missing result is the
            // JSON literal `null`, never SQL NULL.
            sqlx::query(
                "UPDATE public.mcp_runs SET status = $1, result = $2, error = $3, \
                 finished_at = clock_timestamp() WHERE run_id = $4::uuid",
            )
            .bind(&status)
            .bind(result.unwrap_or(Value::Null))
            .bind(
                code.as_deref()
                    .map(|code| json!({"code": code, "message": code.replace('_', " ")})),
            )
            .bind(&run_id)
            .execute(&mut *tx)
            .await?;
            self.event(&mut tx, row, &status).await?;
        }
        if absent {
            // Channel loss/cancellation can leave an intent without an outcome. Finalize it
            // before freeing ownership, even on graceful shutdown.
            sqlx::query(
                "UPDATE public.mcp_run_api_calls SET status = 'outcome_unknown', \
                 finished_at = clock_timestamp() \
                 WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND status = 'intent'",
            )
            .bind(row.run.tenant_id.to_string())
            .bind(&run_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE public.mcp_execution_slots SET run_id = NULL, quarantined = false \
                 WHERE run_id = $1::uuid",
            )
            .bind(&run_id)
            .execute(&mut *tx)
            .await?;
            sqlx::query("DELETE FROM public.mcp_api_permits WHERE run_id = $1::uuid")
                .bind(&run_id)
                .execute(&mut *tx)
                .await?;
            sqlx::query(
                "UPDATE public.mcp_runs SET worker_id = NULL, lease_until = NULL WHERE run_id = $1::uuid",
            )
            .bind(&run_id)
            .execute(&mut *tx)
            .await?;
        } else {
            sqlx::query(
                "UPDATE public.mcp_execution_slots SET quarantined = true WHERE run_id = $1::uuid",
            )
            .bind(&run_id)
            .execute(&mut *tx)
            .await?;
            self.event(&mut tx, row, "slot_quarantined").await?;
        }
        tx.commit().await?;
        Ok(())
    }

    /// Commit the intent to make one upstream call, before any network I/O.
    ///
    /// `method` and `path` (the concrete request path, no query string, no credential) are
    /// written here and are immutable afterwards — the schema's journal guard only ever allows
    /// the outcome columns to change. Returns the run's sequence number for this call.
    ///
    /// Two bounds apply: the run's total calls (`api_calls` against the authority's limit,
    /// the worker-wide `max_api_calls_per_run`, and an optional `call_limit`) and this
    /// operation's pagination allowance.
    ///
    /// The argument list is the reference's `journal_intent` signature; the last four are the
    /// immutable request trace the schema stores beside the intent.
    #[allow(clippy::too_many_arguments)]
    pub async fn journal_intent(
        &self,
        row: &WorkerRow,
        operation: &JournalOperation,
        request_hash: &str,
        key: Option<&str>,
        license_id: &Rfc4122Uuid,
        call_limit: Option<u32>,
        method: Option<&str>,
        path: Option<&str>,
    ) -> Result<i64> {
        let worker = row.worker()?;
        let mut tx = self.pool.begin().await?;
        let current = self
            .owned(&mut tx, &row.run.run_id, worker, row.fence, false)
            .await?;
        let mut limit = i64::from(current.limits()?.api_calls)
            .min(i64::from(self.settings.max_api_calls_per_run));
        if let Some(call_limit) = call_limit {
            limit = limit.min(i64::from(call_limit));
        }
        if i64::from(current.api_calls) >= limit {
            return Err(WorkerStoreError::Denied);
        }
        let journalled: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.mcp_run_api_calls \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid \
             AND operation_id = $3::uuid AND operation_version = $4",
        )
        .bind(current.run.tenant_id.to_string())
        .bind(current.run.run_id.to_string())
        .bind(operation.id.to_string())
        .bind(operation.version)
        .fetch_one(&mut *tx)
        .await?;
        if journalled >= operation.pagination_limit {
            return Err(WorkerStoreError::Denied);
        }
        let sequence = i64::from(current.api_calls) + 1;
        sqlx::query("UPDATE public.mcp_runs SET api_calls = $1 WHERE run_id = $2::uuid")
            .bind(bounded_i32(sequence))
            .bind(current.run.run_id.to_string())
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "INSERT INTO public.mcp_run_api_calls(tenant_id,run_id,sequence,operation_id,\
             operation_version,request_hash,idempotency_key,license_id,effect,method,path) \
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5,$6,$7,$8::uuid,$9,$10,$11)",
        )
        .bind(current.run.tenant_id.to_string())
        .bind(current.run.run_id.to_string())
        .bind(bounded_i32(sequence))
        .bind(operation.id.to_string())
        .bind(operation.version)
        .bind(request_hash)
        .bind(key)
        .bind(license_id.to_string())
        .bind(operation.effect.as_str())
        .bind(method)
        .bind(path.map(truncate_path))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(sequence)
    }

    /// Finalize one journalled intent. Only the outcome columns are updatable, and only while the
    /// row is still `intent`: a second outcome for the same sequence changes nothing.
    ///
    /// The argument list is the reference's `journal_outcome` signature.
    #[allow(clippy::too_many_arguments)]
    pub async fn journal_outcome(
        &self,
        row: &WorkerRow,
        sequence: i64,
        status: &str,
        http_status: Option<i32>,
        duration_ms: Option<i64>,
        reason: Option<&str>,
        error_excerpt: Option<&str>,
    ) -> Result<()> {
        let worker = row.worker()?;
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, &row.run.run_id, worker, row.fence, true)
            .await?;
        sqlx::query(
            "UPDATE public.mcp_run_api_calls SET status = $1, finished_at = clock_timestamp(), \
             http_status = $2, duration_ms = $3, reason = $4, error_excerpt = $5 \
             WHERE tenant_id = $6::uuid AND run_id = $7::uuid AND sequence = $8 \
             AND status = 'intent'",
        )
        .bind(status)
        .bind(http_status)
        .bind(duration_ms.map(bounded_i32))
        .bind(reason)
        .bind(
            error_excerpt
                .filter(|excerpt| !excerpt.is_empty())
                .map(|excerpt| excerpt.chars().take(2048).collect::<String>()),
        )
        .bind(row.run.tenant_id.to_string())
        .bind(row.run.run_id.to_string())
        .bind(bounded_i32(sequence))
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// Take one upstream-call permit for this run, or deny it.
    ///
    /// The permit table is the shared counter: one advisory lock serializes the tally, expired
    /// permits and stale rate windows are swept first, and both denials are committed as the
    /// reference's fixed events (`api_concurrency_denied`, `api_rate_denied`) before the denial
    /// is raised — raising inside the transaction would roll the event back with it.
    pub async fn permit(&self, row: &WorkerRow, service_id: &Rfc4122Uuid) -> Result<Permit> {
        let worker = row.worker()?;
        let limits = match &self.service_limits {
            Ok(limits) => limits,
            Err(reason) => {
                return Err(WorkerStoreError::Store(sqlx::Error::Configuration(
                    reason.clone().into(),
                )));
            }
        };
        let mut tx = self.pool.begin().await?;
        let current = self
            .owned(&mut tx, &row.run.run_id, worker, row.fence, false)
            .await?;
        // A common lock serializes the global count across different services.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(PERMIT_LOCK)
            .execute(&mut *tx)
            .await?;
        sqlx::query("DELETE FROM public.mcp_api_permits WHERE expires_at <= clock_timestamp()")
            .execute(&mut *tx)
            .await?;
        sqlx::query(
            "DELETE FROM public.mcp_api_rate_windows \
             WHERE window_start < date_trunc('minute', clock_timestamp()) - interval '1 minute'",
        )
        .execute(&mut *tx)
        .await?;
        let (calls, concurrency) = limits.ceiling(
            &current.run.tenant_id,
            service_id,
            self.settings.api_max_calls_per_minute.count(),
            min_count(
                self.settings.api_max_inflight,
                self.settings.api_concurrency_per_service,
            ),
        );
        let (total, service): (i64, i64) = sqlx::query_as(
            "SELECT count(*) AS total, count(*) FILTER (WHERE service_id = $1::uuid) AS service \
             FROM public.mcp_api_permits",
        )
        .bind(service_id.to_string())
        .fetch_one(&mut *tx)
        .await?;
        let mut denied = false;
        if total >= self.settings.api_concurrency_global.count() || service >= concurrency {
            self.event(&mut tx, &current, "api_concurrency_denied")
                .await?;
            denied = true;
        }
        let counter: Option<i32> = sqlx::query_scalar(
            "SELECT calls FROM public.mcp_api_rate_windows \
             WHERE tenant_id = $1::uuid AND service_id = $2::uuid \
             AND window_start = date_trunc('minute', clock_timestamp())",
        )
        .bind(current.run.tenant_id.to_string())
        .bind(service_id.to_string())
        .fetch_optional(&mut *tx)
        .await?;
        if counter.is_some_and(|counter| i64::from(counter) >= calls) {
            self.event(&mut tx, &current, "api_rate_denied").await?;
            denied = true;
        }
        let permit = if denied {
            None
        } else {
            let id = Uuid::now_v7();
            sqlx::query(
                "INSERT INTO public.mcp_api_rate_windows(tenant_id,service_id,window_start,calls) \
                 VALUES ($1::uuid,$2::uuid,date_trunc('minute', clock_timestamp()),1) \
                 ON CONFLICT (tenant_id,service_id,window_start) \
                 DO UPDATE SET calls = mcp_api_rate_windows.calls + 1",
            )
            .bind(current.run.tenant_id.to_string())
            .bind(service_id.to_string())
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "INSERT INTO public.mcp_api_permits(\
                 permit_id,tenant_id,run_id,fence,service_id,expires_at) \
                 VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid, \
                 clock_timestamp() + make_interval(secs => $6::double precision))",
            )
            .bind(id.to_string())
            .bind(current.run.tenant_id.to_string())
            .bind(current.run.run_id.to_string())
            .bind(current.fence)
            .bind(service_id.to_string())
            .bind(self.settings.lease.as_secs_f64())
            .execute(&mut *tx)
            .await?;
            Some(Permit { id })
        };
        tx.commit().await?;
        permit.ok_or(WorkerStoreError::Denied)
    }

    /// Release one held permit. Scoped to the permit, the run and the fence, so a stale worker
    /// can never release a permit the run's current generation holds.
    pub async fn release_permit(&self, row: &WorkerRow, permit: &Permit) -> Result<()> {
        sqlx::query(
            "DELETE FROM public.mcp_api_permits \
             WHERE permit_id = $1::uuid AND run_id = $2::uuid AND fence = $3",
        )
        .bind(permit.id.to_string())
        .bind(row.run.run_id.to_string())
        .bind(row.fence)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Expire finished runs' payloads under the retention bound, one bounded batch, and report
    /// how many were expired. The function itself refuses anything a worker could still touch.
    pub async fn expire_payloads(&self) -> Result<i64> {
        let days = i32::try_from(self.execution.retention_days).unwrap_or(i32::MAX);
        let expired: i32 =
            sqlx::query_scalar("SELECT public.mcp_expire_run_payloads($1, $2) AS expired")
                .bind(days)
                .bind(EXPIRE_BATCH)
                .fetch_one(&self.pool)
                .await?;
        Ok(i64::from(expired))
    }
}

/// An epoch-microsecond column as an instant.
fn instant(micros: i64) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp_micros(micros)
        .ok_or_else(|| WorkerStoreError::Store(sqlx::Error::Decode("worker instant".into())))
}

/// A counted bound as the `integer` column or compare it is used against.
///
/// The counts are bounded by the settings' own validation, so the conversion cannot lose a
/// value in practice; a clamped value only makes a bound unreachable, never wider.
fn bounded_i32(value: i64) -> i32 {
    i32::try_from(value).unwrap_or(i32::MAX)
}

/// The concrete integer widths the settings slice chooses are not this module's contract, so
/// every counted bound is read through this conversion rather than pinned to one type.
trait Count {
    fn count(self) -> i64;
}

impl Count for i32 {
    fn count(self) -> i64 {
        i64::from(self)
    }
}

impl Count for i64 {
    fn count(self) -> i64 {
        self
    }
}

impl Count for u16 {
    fn count(self) -> i64 {
        i64::from(self)
    }
}

impl Count for u32 {
    fn count(self) -> i64 {
        i64::from(self)
    }
}

impl Count for u64 {
    fn count(self) -> i64 {
        i64::try_from(self).unwrap_or(i64::MAX)
    }
}

impl Count for usize {
    fn count(self) -> i64 {
        i64::try_from(self).unwrap_or(i64::MAX)
    }
}

/// Two settings bounds read as one ceiling: the per-service concurrency is the smaller of the
/// two, exactly as the reference computes it before the file override.
fn min_count<A: Count, B: Count>(left: A, right: B) -> i64 {
    left.count().min(right.count())
}

/// The stored path is the concrete request path, bounded to the DDL's 1024 characters.
fn truncate_path(path: &str) -> String {
    path.chars().take(1024).collect()
}

// ── deployment-owned upstream ceilings ───────────────────────────────────────────────────

/// The reference's `RateLimits`: a per-service cap on calls per minute and concurrency.
///
/// Read once from `service_limits_file`. A tenant-specific entry overrides a global one, and a
/// service may carry both — every matching entry tightens the ceiling.
#[derive(Debug, Clone, Default)]
struct ServiceLimits {
    limits: Vec<ServiceLimit>,
}

/// One entry of the limits file.
#[derive(Debug, Clone)]
struct ServiceLimit {
    service_id: Rfc4122Uuid,
    tenant_id: Option<Rfc4122Uuid>,
    calls_per_minute: i64,
    concurrency: i64,
}

impl ServiceLimits {
    /// The reference's `RateLimits.read`: absent means no overrides; anything malformed is an
    /// error the store surfaces instead of guessing.
    fn read<P: AsRef<Path>>(path: Option<P>) -> std::result::Result<Self, String> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let path = path.as_ref();
        let bytes = std::fs::read(path)
            .map_err(|error| format!("service limits file {path:?}: {error}"))?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > SERVICE_LIMITS_MAX_BYTES {
            return Err(format!("service limits file {path:?} exceeds its bound"));
        }
        let value: Value = serde_json::from_slice(&bytes)
            .map_err(|error| format!("service limits file {path:?}: {error}"))?;
        let object = value
            .as_object()
            .ok_or_else(|| "service limits file is not an object".to_owned())?;
        for name in object.keys() {
            if name != "schema_version" && name != "limits" {
                return Err(format!("service limits file carries {name:?}"));
            }
        }
        if object.get("schema_version").and_then(Value::as_u64) != Some(1) {
            return Err("service limits file requires schema_version 1".to_owned());
        }
        let entries = match object.get("limits") {
            None => Vec::new(),
            Some(Value::Array(entries)) => entries.clone(),
            Some(_) => return Err("service limits file: limits is not a list".to_owned()),
        };
        if entries.len() > SERVICE_LIMITS_MAX_ENTRIES {
            return Err("service limits file carries too many entries".to_owned());
        }
        let mut limits: Vec<ServiceLimit> = Vec::with_capacity(entries.len());
        for entry in entries {
            let limit = ServiceLimit::read(&entry)?;
            if limits.iter().any(|existing| {
                existing.service_id == limit.service_id && existing.tenant_id == limit.tenant_id
            }) {
                return Err("service limits file repeats one service and tenant".to_owned());
            }
            limits.push(limit);
        }
        Ok(Self { limits })
    }

    /// The ceiling for one call: the settings' default, tightened by every matching entry.
    fn ceiling(
        &self,
        tenant: &Rfc4122Uuid,
        service: &Rfc4122Uuid,
        calls: i64,
        concurrency: i64,
    ) -> (i64, i64) {
        let mut calls = calls;
        let mut concurrency = concurrency;
        for limit in &self.limits {
            if limit.service_id == *service
                && (limit.tenant_id.is_none() || limit.tenant_id.as_ref() == Some(tenant))
            {
                calls = calls.min(limit.calls_per_minute);
                concurrency = concurrency.min(limit.concurrency);
            }
        }
        (calls, concurrency)
    }
}

impl ServiceLimit {
    /// One entry: `{service_id, tenant_id?, calls_per_minute, concurrency}` with the reference's
    /// bounds (1 to 10000 calls, 1 to 100 concurrent).
    fn read(value: &Value) -> std::result::Result<Self, String> {
        let object = value
            .as_object()
            .ok_or_else(|| "service limits entry is not an object".to_owned())?;
        for name in object.keys() {
            if !matches!(
                name.as_str(),
                "service_id" | "tenant_id" | "calls_per_minute" | "concurrency"
            ) {
                return Err(format!("service limits entry carries {name:?}"));
            }
        }
        let identity = |name: &str| -> std::result::Result<Rfc4122Uuid, String> {
            object
                .get(name)
                .and_then(Value::as_str)
                .and_then(Rfc4122Uuid::parse)
                .ok_or_else(|| format!("service limits entry: {name} is not a UUID"))
        };
        let bounded = |name: &str, maximum: i64| -> std::result::Result<i64, String> {
            object
                .get(name)
                .and_then(Value::as_i64)
                .filter(|bound| (1..=maximum).contains(bound))
                .ok_or_else(|| format!("service limits entry: {name} is not 1 to {maximum}"))
        };
        let tenant_id = match object.get("tenant_id") {
            None | Some(Value::Null) => None,
            Some(_) => Some(identity("tenant_id")?),
        };
        Ok(Self {
            service_id: identity("service_id")?,
            tenant_id,
            calls_per_minute: bounded("calls_per_minute", 10_000)?,
            concurrency: bounded("concurrency", 100)?,
        })
    }
}
