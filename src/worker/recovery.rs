//! Lease takeover and pod reconciliation (slice S3).
//!
//! Ported from the reference `src/execution/recovery.py`. Absence is confirmed before capacity
//! is released: a run whose worker stopped heartbeating is fenced out first, then either
//! requeued (it never started anything) or finished `interrupted`. The run's slot is freed only
//! when the pod is gone (or was never recorded). When the sandbox boundary cannot prove the pod
//! absent — `stop` returned `false`, errored, or the pod's labels name a different generation —
//! the slot stays quarantined and this worker keeps ownership so a later pass can settle it.
//!
//! Every transaction here is short. The pods are inspected and stopped *outside* any transaction;
//! the database work is the fence bump, the intent finalization and the terminal transition.

use std::sync::Arc;

use sqlx::AssertSqlSafe;

use crate::execution::RunStatus;
use crate::worker::backend::{Backend, BackendError};
use crate::worker::row::{WorkerRow, decode_worker, worker_projection};
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// The reference's bound on one reconciliation pass (`recovery.py:14`).
const RECOVERY_BATCH: i64 = 128;

/// Lease takeover and pod reconciliation.
pub struct Recovery {
    store: WorkerStore,
    backend: Arc<dyn Backend>,
}

impl Recovery {
    /// Bind reconciliation to the worker store and the sandbox backend.
    pub fn new(store: WorkerStore, backend: Arc<dyn Backend>) -> Self {
        Self { store, backend }
    }

    /// Take over every run whose lease expired, then stop managed pods whose runs are missing or
    /// finished.
    pub async fn reconcile(&self, worker: &str) -> std::result::Result<(), WorkerStoreError> {
        let projection = worker_projection();
        let mut pairs: Vec<(WorkerRow, WorkerRow)> = Vec::new();
        {
            let mut tx = self.store.pool().begin().await?;
            let select = format!(
                "SELECT {projection} FROM public.mcp_runs r \
                 JOIN public.mcp_execution_slots s USING (run_id) \
                 WHERE r.lease_until <= clock_timestamp() \
                 ORDER BY r.lease_until LIMIT {RECOVERY_BATCH} \
                 FOR UPDATE OF r SKIP LOCKED"
            );
            let rows = sqlx::query(AssertSqlSafe(select))
                .fetch_all(&mut *tx)
                .await?;
            for row in &rows {
                let old = decode_worker(row)?;
                // Fence out all old broker channels before touching their pods.
                let bump = format!(
                    "UPDATE public.mcp_runs SET worker_id = $1::uuid, fence = fence + 1, \
                     lease_until = clock_timestamp() + make_interval(secs => $2::double precision) \
                     WHERE run_id = $3::uuid \
                     RETURNING {projection}"
                );
                let claimed = sqlx::query(AssertSqlSafe(bump))
                    .bind(worker)
                    .bind(self.store.settings().lease.as_secs_f64())
                    .bind(old.run.run_id.to_string())
                    .fetch_one(&mut *tx)
                    .await?;
                pairs.push((old, decode_worker(&claimed)?));
            }
            tx.commit().await?;
        }

        for (old, claimed) in pairs {
            if self.take_over(worker, &old, &claimed).await.is_err() {
                // Keep ownership/slot until a subsequent reconciliation can prove absence. No
                // delete response or API timeout frees capacity.
                match self
                    .store
                    .finish(
                        &claimed,
                        "interrupted",
                        None,
                        Some("cleanup_unconfirmed"),
                        false,
                    )
                    .await
                {
                    Ok(()) | Err(WorkerStoreError::Denied) => {}
                    Err(error) => return Err(error),
                }
            }
        }

        // Remove genuinely orphaned managed pods and pods left after terminal runs.
        for pod in self.backend.list().await.map_err(backend_failure)? {
            let row: Option<(String, Option<bool>)> = sqlx::query_as(
                "SELECT status, lease_until > clock_timestamp() AS live \
                 FROM public.mcp_runs WHERE run_id = $1::uuid",
            )
            .bind(&pod.run_id)
            .fetch_optional(self.store.pool())
            .await?;
            let stop = match row {
                None => true,
                Some((status, live)) => {
                    RunStatus::parse(&status).is_some_and(RunStatus::is_terminal)
                        && !live.unwrap_or(false)
                }
            };
            if stop {
                self.backend.stop(&pod).await.map_err(backend_failure)?;
            }
        }
        Ok(())
    }

    /// Settle one fenced-out run: requeue it when it never started, otherwise finish it and free
    /// the slot only if its pod is confirmed absent.
    async fn take_over(
        &self,
        worker: &str,
        old: &WorkerRow,
        claimed: &WorkerRow,
    ) -> std::result::Result<(), WorkerStoreError> {
        let run_id = claimed.run.run_id.to_string();
        if old.run.status == RunStatus::Starting
            && old.pod_name.is_none()
            && old.run.started_at.is_none()
            && old.api_calls == 0
            && !old.run.cancel_requested
        {
            let mut tx = self.store.pool().begin().await?;
            self.store
                .owned(&mut tx, &claimed.run.run_id, worker, claimed.fence, true)
                .await?;
            sqlx::query(
                "UPDATE public.mcp_runs SET status = 'queued', worker_id = NULL, \
                 lease_until = NULL, start_deadline = NULL, deadline = NULL \
                 WHERE run_id = $1::uuid",
            )
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
            self.store
                .event(&mut tx, claimed, "requeued_unstarted")
                .await?;
            tx.commit().await?;
            return Ok(());
        }

        // `if old["pod_name"]` in the reference: an absent or empty name means no pod.
        let pod = match old.pod_name.as_deref().filter(|name| !name.is_empty()) {
            None => None,
            Some(name) => self.backend.inspect(name).await.map_err(backend_failure)?,
        };
        if let Some(pod) = &pod {
            // A pod whose labels do not name this run, this generation and the recorded UID is
            // never adopted or stopped: it may belong to a later generation.
            let recorded_fence = old
                .pod_name
                .as_deref()
                .and_then(|name| name.rsplit_once('-'))
                .and_then(|(_, fence)| fence.parse::<i64>().ok());
            let uid_agrees = match old.pod_uid.as_deref() {
                None | Some("") => true,
                Some(uid) => uid == pod.uid,
            };
            if recorded_fence != Some(pod.fence)
                || pod.run_id != claimed.run.run_id.to_string()
                || !uid_agrees
            {
                return Err(WorkerStoreError::Denied);
            }
        }
        let absent = match &pod {
            None => true,
            Some(pod) => self.backend.stop(pod).await.map_err(backend_failure)?,
        };

        let mut tx = self.store.pool().begin().await?;
        self.store
            .owned(&mut tx, &claimed.run.run_id, worker, claimed.fence, true)
            .await?;
        sqlx::query(
            "UPDATE public.mcp_run_api_calls SET status = 'outcome_unknown', \
             finished_at = clock_timestamp() \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND status = 'intent'",
        )
        .bind(claimed.run.tenant_id.to_string())
        .bind(&run_id)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;

        self.store
            .finish(claimed, "interrupted", None, Some("worker_lost"), absent)
            .await?;
        Ok(())
    }
}

/// A sandbox-boundary failure as the store's error type. The store has no backend variant, and
/// neither the per-row cleanup nor `reconcile` may report success while a pod could not be
/// listed or stopped, so the message is carried rather than dropped.
fn backend_failure(error: BackendError) -> WorkerStoreError {
    WorkerStoreError::Store(sqlx::Error::Protocol(format!("runner backend: {error}")))
}
