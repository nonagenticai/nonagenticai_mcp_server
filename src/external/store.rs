//! The external driver's database half: the queued expiry, the claim, lease recovery and the
//! two mid-flight writes (`cancelling`, `status_message`).
//!
//! Ported from the database half of the reference `src/external/driver.py`. Everything that is
//! shared with the Kata executor — `owned`, `event`, `heartbeat`, `finish` — is the
//! [`WorkerStore`] method unchanged: the reference's `ExecutionRepository` is one class for both
//! processes, and an external run is an ordinary `mcp_runs` row that never takes a slot.
//!
//! Two invariants this file exists to keep:
//!
//! - **Only non-Kata rows.** Every statement carries `runtime <> 'kata_python'`: the external
//!   driver and the Kata worker claim disjoint halves of the queue.
//! - **Two separate limits.** `worker_max_inflight` bounds runs being *dispatched* (an external
//!   project can run for days and costs only a poll), while `external_active_max` is the load
//!   guard for everything this process owns.

use serde_json::Value;
use sqlx::{AssertSqlSafe, PgPool, Postgres, Transaction};

use crate::config::ExternalDriverSettings;
use crate::execution::RunStatus;
use crate::worker::row::{WorkerRow, decode_worker, worker_projection};
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// The statuses a live external run may be in (the reference's `ACTIVE`).
pub const ACTIVE: [&str; 3] = ["starting", "running", "cancelling"];

/// The recovery scan's bound, exactly the reference's `LIMIT 128`.
const RECOVERY_LIMIT: i64 = 128;

/// What one recovery pass found: runs to dispatch for the first time, and runs whose dispatch
/// may already have reached the upstream (they are `interrupted`, never re-sent).
#[derive(Debug, Default)]
pub struct Recovered {
    /// `starting` with no `dispatch` event: never sent upstream, so it is safe to start.
    pub start: Vec<WorkerRow>,
    /// `starting` with a `dispatch` event and no external reference: the outcome is unknown.
    pub interrupt: Vec<WorkerRow>,
}

/// The external driver's storage.
#[derive(Clone)]
pub struct ExternalStore {
    pool: PgPool,
    store: WorkerStore,
    settings: ExternalDriverSettings,
    driver: String,
}

impl ExternalStore {
    /// Bind the store to a pool, the driver's settings and this process's worker id.
    pub fn new(pool: PgPool, settings: ExternalDriverSettings, driver: String) -> Self {
        let store = WorkerStore::new(
            pool.clone(),
            settings.worker.clone(),
            settings.execution.clone(),
        );
        Self {
            pool,
            store,
            settings,
            driver,
        }
    }

    /// This process's UUIDv7 identity.
    pub fn driver(&self) -> &str {
        &self.driver
    }

    /// The pool, for the probe's schema check.
    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    /// The shared store, for the lifecycle calls the driver makes on a row it owns.
    pub fn worker_store(&self) -> &WorkerStore {
        &self.store
    }

    /// Append one run event.
    pub async fn event(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        row: &WorkerRow,
        kind: &str,
    ) -> Result<(), WorkerStoreError> {
        self.store.event(tx, row, kind).await
    }

    /// Lock a run and prove this process still owns it.
    pub async fn owned(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        row: &WorkerRow,
        allow_cancel: bool,
    ) -> Result<WorkerRow, WorkerStoreError> {
        self.store
            .owned(tx, &row.run.run_id, &self.driver, row.fence, allow_cancel)
            .await
    }

    /// Extend the lease (and return the refreshed row).
    pub async fn heartbeat(&self, row: &WorkerRow) -> Result<WorkerRow, WorkerStoreError> {
        self.store.heartbeat(row).await
    }

    /// The terminal transition. External runs never hold a slot, so `absent = true` is the only
    /// mode the driver uses: the reference's `finish(..., absent=True)`.
    pub async fn finish(
        &self,
        row: &WorkerRow,
        status: &str,
        result: Option<&Value>,
        code: Option<&str>,
    ) -> Result<(), WorkerStoreError> {
        self.store.finish(row, status, result, code, true).await
    }

    /// The reference's `_expire_queued`: a queued external run that was cancelled, or whose queue
    /// deadline passed, is finished — the driver is the only process that would ever claim it.
    pub async fn expire_queued(&self) -> Result<Vec<WorkerRow>, WorkerStoreError> {
        let statement = format!(
            "UPDATE public.mcp_runs \
             SET status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'timed_out' END, \
             finished_at = clock_timestamp() \
             WHERE status = 'queued' AND runtime <> 'kata_python' \
             AND (cancel_requested OR queue_deadline <= clock_timestamp()) \
             RETURNING {}",
            worker_projection()
        );
        let mut tx = self.pool.begin().await?;
        let rows = sqlx::query(AssertSqlSafe(statement))
            .fetch_all(&mut *tx)
            .await?;
        let mut expired = Vec::with_capacity(rows.len());
        for row in &rows {
            let row = decode_worker(row)?;
            self.store
                .event(&mut tx, &row, row.run.status.as_str())
                .await?;
            expired.push(row);
        }
        tx.commit().await?;
        Ok(expired)
    }

    /// The reference's `_claim`: take up to the free dispatch room, oldest first.
    pub async fn claim(&self) -> Result<Vec<WorkerRow>, WorkerStoreError> {
        let mut tx = self.pool.begin().await?;
        let (starting, active): (i64, i64) = sqlx::query_as(
            "SELECT count(*) FILTER (WHERE status = 'starting') AS starting, count(*) AS active \
             FROM public.mcp_runs \
             WHERE worker_id = $1::uuid AND runtime <> 'kata_python' AND status = ANY($2)",
        )
        .bind(&self.driver)
        .bind(ACTIVE.map(str::to_owned).to_vec())
        .fetch_one(&mut *tx)
        .await?;
        // `max_inflight` bounds runs being *dispatched*, not runs that already started.
        let room = std::cmp::min(
            i64::from(self.settings.worker.max_inflight) - starting,
            i64::from(self.settings.active_max) - active,
        );
        if room <= 0 {
            tx.commit().await?;
            return Ok(Vec::new());
        }
        let picked: Vec<(String,)> = sqlx::query_as(
            "SELECT run_id::text FROM public.mcp_runs \
             WHERE status = 'queued' AND runtime <> 'kata_python' AND NOT cancel_requested \
             AND queue_deadline > clock_timestamp() \
             ORDER BY created_at, run_id LIMIT $1 FOR UPDATE SKIP LOCKED",
        )
        .bind(room)
        .fetch_all(&mut *tx)
        .await?;
        let statement = format!(
            "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, \
             fence = fence + 1, \
             lease_until = clock_timestamp() + make_interval(secs => $2::double precision), \
             heartbeat_at = clock_timestamp(), \
             start_deadline = clock_timestamp() + make_interval(secs => $3::double precision), \
             deadline = clock_timestamp() + make_interval(secs => $4::double precision) \
             WHERE run_id = $5::uuid RETURNING {}",
            worker_projection()
        );
        let mut claimed = Vec::with_capacity(picked.len());
        for (run_id,) in picked {
            let row = sqlx::query(AssertSqlSafe(statement.as_str()))
                .bind(&self.driver)
                .bind(self.settings.worker.lease.as_secs_f64())
                .bind(self.settings.worker.run_start_timeout.as_secs_f64())
                .bind(self.settings.run_max.as_secs_f64())
                .bind(&run_id)
                .fetch_one(&mut *tx)
                .await?;
            let row = decode_worker(&row)?;
            self.store.event(&mut tx, &row, "starting").await?;
            claimed.push(row);
        }
        tx.commit().await?;
        Ok(claimed)
    }

    /// The reference's `_recover`: adopt external runs whose lease lapsed.
    ///
    /// Adoption happens inside the transaction; the returned split is decided afterwards from
    /// the adopted row and its `dispatch` event, exactly as the reference decides it.
    pub async fn recover(&self) -> Result<Recovered, WorkerStoreError> {
        let mut tx = self.pool.begin().await?;
        let picked: Vec<(String,)> = sqlx::query_as(
            "SELECT run_id::text FROM public.mcp_runs \
             WHERE status = ANY($1) AND runtime <> 'kata_python' \
             AND (lease_until IS NULL OR lease_until <= clock_timestamp()) \
             ORDER BY created_at, run_id LIMIT $2 FOR UPDATE SKIP LOCKED",
        )
        .bind(ACTIVE.map(str::to_owned).to_vec())
        .bind(RECOVERY_LIMIT)
        .fetch_all(&mut *tx)
        .await?;
        let statement = format!(
            "UPDATE public.mcp_runs SET worker_id = $1::uuid, fence = fence + 1, \
             lease_until = clock_timestamp() + make_interval(secs => $2::double precision), \
             heartbeat_at = clock_timestamp() \
             WHERE run_id = $3::uuid RETURNING {}",
            worker_projection()
        );
        let mut adopted = Vec::with_capacity(picked.len());
        for (run_id,) in picked {
            let row = sqlx::query(AssertSqlSafe(statement.as_str()))
                .bind(&self.driver)
                .bind(self.settings.worker.lease.as_secs_f64())
                .bind(&run_id)
                .fetch_one(&mut *tx)
                .await?;
            let row = decode_worker(&row)?;
            let dispatched = if row.run.status == RunStatus::Starting {
                let (sent,): (bool,) = sqlx::query_as(
                    "SELECT EXISTS(SELECT 1 FROM public.mcp_run_events \
                     WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND kind = 'dispatch')",
                )
                .bind(row.run.tenant_id.to_string())
                .bind(row.run.run_id.to_string())
                .fetch_one(&mut *tx)
                .await?;
                sent
            } else {
                false
            };
            adopted.push((row, dispatched));
        }
        tx.commit().await?;

        let mut recovered = Recovered::default();
        for (row, dispatched) in adopted {
            if row.run.status != RunStatus::Starting {
                // `running`/`cancelling`: the drive step keeps polling it.
                continue;
            }
            if row.run.external_ref.is_none() {
                if dispatched {
                    recovered.interrupt.push(row);
                } else {
                    recovered.start.push(row);
                }
            }
        }
        Ok(recovered)
    }

    /// The reference's `_drive` listing: every run this process owns that is running or
    /// cancelling with a live lease, oldest first.
    pub async fn drive_listing(&self) -> Result<Vec<WorkerRow>, WorkerStoreError> {
        let statement = format!(
            "SELECT {} FROM public.mcp_runs \
             WHERE worker_id = $1::uuid AND runtime <> 'kata_python' \
             AND status IN ('running', 'cancelling') AND lease_until > clock_timestamp() \
             ORDER BY created_at, run_id",
            worker_projection()
        );
        let rows = sqlx::query(AssertSqlSafe(statement))
            .bind(&self.driver)
            .fetch_all(&self.pool)
            .await?;
        let mut mine = Vec::with_capacity(rows.len());
        for row in &rows {
            mine.push(decode_worker(row)?);
        }
        Ok(mine)
    }

    /// The reference's post-start write: merge the external reference and move the run `running`.
    ///
    /// `COALESCE(external_ref, '{}') || $1` is the reference's merge, not a replace: an fr event
    /// may already have recorded the project id while the start was in flight, and stored keys
    /// only ever grow (migration 0011's guard).
    pub async fn record_started(
        &self,
        row: &WorkerRow,
        reference: &Value,
    ) -> Result<(), WorkerStoreError> {
        let mut tx = self.pool.begin().await?;
        // `allow_cancel`: a cancel that arrived during the start must not lose the reference.
        self.owned(&mut tx, row, true).await?;
        sqlx::query(
            "UPDATE public.mcp_runs \
             SET external_ref = COALESCE(external_ref, '{}'::jsonb) || $1::jsonb, \
             status = 'running', started_at = clock_timestamp() \
             WHERE run_id = $2::uuid AND status = 'starting'",
        )
        .bind(reference.clone())
        .bind(row.run.run_id.to_string())
        .execute(&mut *tx)
        .await?;
        self.store.event(&mut tx, row, "running").await?;
        tx.commit().await?;
        Ok(())
    }

    /// Begin a transaction on the driver's pool.
    pub async fn begin(&self) -> Result<Transaction<'_, Postgres>, sqlx::Error> {
        self.pool.begin().await
    }

    /// One run by (tenant, run id), for the forward step that relays an answer.
    pub async fn get(
        &self,
        tenant: &str,
        run_id: &str,
    ) -> Result<Option<WorkerRow>, WorkerStoreError> {
        let statement = format!(
            "SELECT {} FROM public.mcp_runs WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
            worker_projection()
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant)
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(decode_worker).transpose()
    }

    /// The run's status, when it exists for this tenant.
    pub async fn run_status(
        &self,
        tenant: &str,
        run_id: &str,
    ) -> Result<Option<RunStatus>, WorkerStoreError> {
        let status: Option<(String,)> = sqlx::query_as(
            "SELECT status FROM public.mcp_runs WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
        )
        .bind(tenant)
        .bind(run_id)
        .fetch_optional(&self.pool)
        .await?;
        Ok(status.and_then(|(status,)| RunStatus::parse(&status)))
    }

    /// The reference's `_set_cancelling`: a legal `running -> cancelling` step, with its event.
    pub async fn set_cancelling(&self, row: &WorkerRow) -> Result<WorkerRow, WorkerStoreError> {
        let statement = format!(
            "UPDATE public.mcp_runs SET status = 'cancelling' \
             WHERE run_id = $1::uuid AND status = 'running' RETURNING {}",
            worker_projection()
        );
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, row, true).await?;
        let changed = sqlx::query(AssertSqlSafe(statement.as_str()))
            .bind(row.run.run_id.to_string())
            .fetch_optional(&mut *tx)
            .await?;
        let changed = match changed {
            Some(changed) => Some(decode_worker(&changed)?),
            None => None,
        };
        if let Some(changed) = &changed {
            self.store.event(&mut tx, changed, "cancelling").await?;
        }
        tx.commit().await?;
        Ok(changed.unwrap_or_else(|| row.clone()))
    }

    /// The reference's status-message write: an answer-again hint stands until a valid answer
    /// clears it, so a hint is never overwritten and never floods the feed.
    ///
    /// Returns whether the message actually changed.
    pub async fn set_status_message(
        &self,
        row: &WorkerRow,
        message: &str,
    ) -> Result<bool, WorkerStoreError> {
        let mut tx = self.pool.begin().await?;
        self.owned(&mut tx, row, true).await?;
        let changed: Option<(String,)> = sqlx::query_as(
            "UPDATE public.mcp_runs SET status_message = $1 \
             WHERE run_id = $2::uuid AND status_message IS DISTINCT FROM $1 \
             AND COALESCE(status_message, '') NOT LIKE $3 \
             AND COALESCE(status_message, '') NOT LIKE $4 \
             RETURNING run_id::text",
        )
        .bind(message)
        .bind(row.run.run_id.to_string())
        .bind(crate::storage::task_inputs::REASON_REQUIRED)
        .bind(format!("{}%", crate::storage::task_inputs::REFUSED_PREFIX))
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(changed.is_some())
    }
}
