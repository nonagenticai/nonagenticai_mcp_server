//! The fair, slot-owning claim (slice S3).
//!
//! Ported from the reference `src/execution/scheduler.py`. Every worker replica of every
//! tenant claims through this one short transaction: a global advisory lock makes the tenant and
//! global decisions atomic, queued runs that can never start are finalized first, then the
//! lowest free slot is locked, then the fairest eligible run is locked, started, attached to the
//! slot and given a `starting` event.
//!
//! Ordering is load-bearing. The expiry sweep runs before the slot is chosen — and its writes
//! are committed even when the claim itself finds nothing (`return None` leaves the Python
//! `async with conn.transaction()` block normally, which commits). The run order is
//! `last_claimed_at, created_at, run_id`, so a tenant that has not been served recently goes
//! first and one tenant cannot starve the others. Pod and HTTP work never happens here: the
//! transaction holds row locks only and no pool connection outlives it.

use sqlx::AssertSqlSafe;

use crate::worker::row::{WorkerRow, decode_worker, worker_projection};
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// The reference's global claim lock (`scheduler.py:30`): one advisory transaction lock makes
/// the tenant and global slot decisions atomic across replicas.
const CLAIM_LOCK: i64 = 72_441_002;

/// The fair, slot-owning claim.
pub struct Scheduler {
    store: WorkerStore,
}

impl Scheduler {
    /// Bind the scheduler to the worker store it claims through.
    pub fn new(store: WorkerStore) -> Self {
        Self { store }
    }

    /// Prove the operator provisioned exactly the configured capacity.
    ///
    /// The reference refuses to start rather than inventing capacity: an operator who provisioned
    /// the wrong number of slots, or a range that does not start at one, gets a denial and the
    /// worker does not claim anything.
    pub async fn verify_capacity(&self) -> std::result::Result<(), WorkerStoreError> {
        let slots = self.store.settings().global_slots;
        let last = i32::try_from(slots).unwrap_or(i32::MAX);
        let (count, first, maximum): (i64, Option<i32>, Option<i32>) = sqlx::query_as(
            "SELECT count(*) AS n, min(slot_id) AS first, max(slot_id) AS last \
             FROM public.mcp_execution_slots WHERE NOT draining",
        )
        .fetch_one(self.store.pool())
        .await?;
        if count != i64::from(slots) || first != Some(1) || maximum != Some(last) {
            return Err(WorkerStoreError::Denied);
        }
        Ok(())
    }

    /// Claim the fairest eligible run onto the lowest free slot, or `None` when there is no free
    /// slot or no eligible run.
    ///
    /// One transaction, exactly the reference's order: the global claim lock, the expiry sweep,
    /// the free slot, the fair run, the tenant's `last_claimed_at`, the run's `starting` update
    /// and the slot attachment. Both "nothing to do" returns commit — the expiry sweep must not
    /// be rolled back just because this replica found no work.
    pub async fn claim(
        &self,
        worker: &str,
    ) -> std::result::Result<Option<WorkerRow>, WorkerStoreError> {
        let settings = self.store.settings();
        let projection = worker_projection();
        let mut tx = self.store.pool().begin().await?;

        // One short global claim lock makes tenant/global decisions atomic. Pod/HTTP operations
        // never occur while this or any row lock is held.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(CLAIM_LOCK)
            .execute(&mut *tx)
            .await?;

        let expire = format!(
            "UPDATE public.mcp_runs \
             SET status = CASE WHEN cancel_requested THEN 'cancelled' ELSE 'timed_out' END, \
             finished_at = clock_timestamp() \
             WHERE status = 'queued' \
             AND (cancel_requested OR queue_deadline <= clock_timestamp()) \
             RETURNING {projection}"
        );
        let expired = sqlx::query(AssertSqlSafe(expire))
            .fetch_all(&mut *tx)
            .await?;
        for row in &expired {
            let row = decode_worker(row)?;
            self.store
                .event(&mut tx, &row, row.run.status.as_str())
                .await?;
        }

        let slot: Option<i32> = sqlx::query_scalar(
            "SELECT slot_id FROM public.mcp_execution_slots \
             WHERE run_id IS NULL AND NOT quarantined AND NOT draining \
             ORDER BY slot_id LIMIT 1 FOR UPDATE SKIP LOCKED",
        )
        .fetch_optional(&mut *tx)
        .await?;
        let Some(slot) = slot else {
            tx.commit().await?;
            return Ok(None);
        };

        // Fairness: the tenant served longest ago wins, then the oldest run, then the identity.
        // A tenant already holding its configured slots is invisible to this claim.
        let select_run = format!(
            "SELECT {projection} FROM public.mcp_runs r \
             JOIN public.mcp_tenant_execution_locks t USING (tenant_id) \
             WHERE r.status = 'queued' AND r.runtime = 'kata_python' AND NOT r.cancel_requested \
             AND r.queue_deadline > clock_timestamp() \
             AND (SELECT count(*) FROM public.mcp_execution_slots s \
                  JOIN public.mcp_runs a ON a.run_id = s.run_id \
                  WHERE a.tenant_id = r.tenant_id) < $1 \
             ORDER BY t.last_claimed_at, r.created_at, r.run_id \
             LIMIT 1 FOR UPDATE OF r, t SKIP LOCKED"
        );
        let Some(row) = sqlx::query(AssertSqlSafe(select_run))
            .bind(i64::from(settings.per_tenant_slots))
            .fetch_optional(&mut *tx)
            .await?
        else {
            tx.commit().await?;
            return Ok(None);
        };
        let row = decode_worker(&row)?;

        sqlx::query(
            "UPDATE public.mcp_tenant_execution_locks SET last_claimed_at = clock_timestamp() \
             WHERE tenant_id = $1::uuid",
        )
        .bind(row.run.tenant_id.to_string())
        .execute(&mut *tx)
        .await?;

        // The run's own wall limit is capped by the deployment's `run_max`; the start allowance
        // is added on top so a slow start can never eat the run's whole lifetime.
        let limits = row.limits()?;
        let run_max = u32::try_from(settings.run_max.as_secs()).unwrap_or(u32::MAX);
        let start_seconds = settings.run_start_timeout.as_secs_f64();
        let deadline_seconds = start_seconds + f64::from(limits.wall_seconds.min(run_max));

        let update_run = format!(
            "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, \
             fence = fence + 1, \
             lease_until = clock_timestamp() + make_interval(secs => $2::double precision), \
             heartbeat_at = clock_timestamp(), \
             start_deadline = clock_timestamp() + make_interval(secs => $3::double precision), \
             deadline = clock_timestamp() + make_interval(secs => $4::double precision) \
             WHERE run_id = $5::uuid \
             RETURNING {projection}"
        );
        let claimed = sqlx::query(AssertSqlSafe(update_run))
            .bind(worker)
            .bind(settings.lease.as_secs_f64())
            .bind(start_seconds)
            .bind(deadline_seconds)
            .bind(row.run.run_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        let claimed = decode_worker(&claimed)?;

        sqlx::query("UPDATE public.mcp_execution_slots SET run_id = $1::uuid WHERE slot_id = $2")
            .bind(claimed.run.run_id.to_string())
            .bind(slot)
            .execute(&mut *tx)
            .await?;
        self.store.event(&mut tx, &claimed, "starting").await?;
        tx.commit().await?;
        Ok(Some(claimed))
    }
}
