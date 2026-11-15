//! The external driver loop and the binary's entry point.
//!
//! Ported from the reference `src/external/driver.py`. One process is one worker id; it is the
//! single writer of `mcp_runs` rows for the non-Kata runtimes. The adapters speak HTTP only.
//!
//! The tick order is load-bearing and is the reference's:
//! **expire queued → recover → claim → start → drive → forward**.
//!
//! - A run is dispatched **at most once**: the `dispatch` event is committed before
//!   `adapter.start`, and a run found `starting` with that event but no `external_ref` is
//!   `interrupted`, never re-sent.
//! - Every adapter call runs under [`ExternalDriver::renewing`], which keeps the run's lease alive
//!   while the call is in flight — an fr answer may take minutes against a 30-second lease.
//! - Logs carry run ids and public codes only: never settings, inputs, request or response
//!   bodies, nor exception messages (transport errors embed URLs).

use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::MissedTickBehavior;

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::models::Runtime;
use crate::config::ExternalDriverSettings;
use crate::db;
use crate::execution::RunStatus;
use crate::external::fr::{FrAdapter, FrCommandAdapter};
use crate::external::health::Liveness;
use crate::external::n8n::N8nAdapter;
use crate::external::store::ExternalStore;
use crate::external::{
    AdapterError, AnswerForwarder, ExternalAdapter, ExternalState, ExternalStatus,
};
use crate::storage::run_activity;
use crate::storage::task_inputs::{REFUSED_PREFIX, TaskInputRepository};
use crate::worker::health::verify_schema;
use crate::worker::row::WorkerRow;
use crate::worker::store::WorkerStoreError;

/// The bound on `status_message` (the reference's `MESSAGE_LIMIT`).
pub const MESSAGE_LIMIT: usize = 512;

/// Why the driver could not run, or stopped running.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] crate::config::ConfigError),
    /// The driver is not enabled (the reference's `DriverConfigError`).
    #[error("{0}")]
    Refused(&'static str),
    #[error("DATABASE_URL is not set")]
    MissingDatabaseUrl,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("driver storage: {0}")]
    Store(#[from] WorkerStoreError),
    #[error("http client: {0}")]
    Http(#[from] reqwest::Error),
    #[error("driver io: {0}")]
    Io(#[from] std::io::Error),
}

/// The stored text of one runtime, for the adapter map.
pub const fn runtime_key(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::KataPython => "kata_python",
        Runtime::N8nWorkflow => "n8n_workflow",
        Runtime::FrProject => "fr_project",
        Runtime::FrCommand => "fr_command",
    }
}

/// What one step's own failure means.
#[derive(Debug)]
enum StepError {
    /// The lease was lost: another driver owns the run now, so this step writes nothing.
    Lost,
    /// A storage failure.
    Store(WorkerStoreError),
}

impl From<WorkerStoreError> for StepError {
    fn from(error: WorkerStoreError) -> Self {
        match error {
            WorkerStoreError::Denied => Self::Lost,
            other => Self::Store(other),
        }
    }
}

impl From<sqlx::Error> for StepError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(WorkerStoreError::Store(error))
    }
}

/// The outcome of one adapter call run under the lease heartbeat.
enum Renewal<T, E> {
    /// The call returned.
    Done(Result<T, E>),
    /// The lease was lost while the call was in flight; the call was dropped.
    Lost,
}

/// The external driver: one process, one worker id, one writer.
#[derive(Clone)]
pub struct ExternalDriver {
    store: ExternalStore,
    inputs: TaskInputRepository,
    adapters: HashMap<&'static str, Arc<dyn ExternalAdapter>>,
    forwarder: Option<Arc<dyn AnswerForwarder>>,
    settings: ExternalDriverSettings,
    /// Bounds adapter calls (start, poll) in flight in this process.
    calls: Arc<Semaphore>,
    /// The probe server's liveness window, marked after every completed tick.
    liveness: Option<Arc<Liveness>>,
}

impl ExternalDriver {
    /// Build the driver from its parts.
    pub fn new(
        store: ExternalStore,
        inputs: TaskInputRepository,
        adapters: HashMap<&'static str, Arc<dyn ExternalAdapter>>,
        forwarder: Option<Arc<dyn AnswerForwarder>>,
        settings: ExternalDriverSettings,
    ) -> Self {
        let calls = Arc::new(Semaphore::new(settings.concurrency as usize));
        Self {
            store,
            inputs,
            adapters,
            forwarder,
            settings,
            calls,
            liveness: None,
        }
    }

    /// Attach the probe server's liveness window; a completed tick marks it.
    pub fn with_liveness(mut self, liveness: Arc<Liveness>) -> Self {
        self.liveness = Some(liveness);
        self
    }

    /// Record a completed tick on the liveness window, when one is attached.
    pub fn mark_alive(&self) {
        if let Some(liveness) = &self.liveness {
            liveness.mark();
        }
    }

    /// This process's worker id: the `worker_id` every run it owns carries.
    pub fn driver_id(&self) -> &str {
        self.store.driver()
    }

    /// The adapter that owns a runtime, if this process is configured for it.
    fn adapter(&self, runtime: Runtime) -> Option<&Arc<dyn ExternalAdapter>> {
        self.adapters.get(runtime_key(runtime))
    }

    /// One tick: expire, recover, claim, start, drive, forward.
    pub async fn tick(&self) -> Result<(), WorkerStoreError> {
        self.store.expire_queued().await?;
        // Recovery first: runs a dead driver abandoned are this worker's work now, and they must
        // count against the dispatch room before any new run is claimed.
        let recovered = self.store.recover().await?;
        for row in &recovered.interrupt {
            self.interrupt_unknown(row).await;
        }
        let claimed = self.store.claim().await?;
        let mut to_start = recovered.start;
        to_start.extend(claimed);
        self.start_many(to_start).await;
        self.drive().await;
        self.forward().await;
        Ok(())
    }

    /// A recovered run whose dispatch may already have reached the upstream.
    async fn interrupt_unknown(&self, row: &WorkerRow) {
        if let Err(error) = self
            .store
            .finish(row, "interrupted", None, Some("external_start_unknown"))
            .await
        {
            log_store("interrupt", row, &error);
        }
    }

    /// Start every run concurrently, one task each, under the process's adapter budget.
    async fn start_many(&self, rows: Vec<WorkerRow>) {
        let mut set = JoinSet::new();
        for row in rows {
            let driver = self.clone();
            set.spawn(async move { driver.start_run(&row).await });
        }
        while let Some(joined) = set.join_next().await {
            if joined.is_err() {
                tracing::error!("external start task failed");
            }
        }
    }

    /// Start one run: commit the dispatch intent, then dispatch, then record the reference.
    async fn start_run(&self, row: &WorkerRow) {
        let Some(adapter) = self.adapter(row.run.runtime) else {
            self.finish(row, "failed", None, Some("external_unconfigured"))
                .await;
            return;
        };
        let cancelled = match self.dispatch_intent(row).await {
            Ok(cancelled) => cancelled,
            Err(StepError::Lost) => return,
            Err(StepError::Store(error)) => {
                log_store("dispatch", row, &error);
                return;
            }
        };
        if cancelled {
            self.finish(row, "cancelled", None, None).await;
            return;
        }
        let Ok(_permit) = self.calls.acquire().await else {
            return;
        };
        match self.renewing(row, adapter.start(row)).await {
            // Another driver owns the run; it will start or recover it.
            Renewal::Lost => {}
            // The upstream may have the work (a transport failure after the request was sent):
            // `interrupted`, never `failed`, and never re-sent.
            Renewal::Done(Err(error)) if error.outcome_unknown => {
                self.finish(row, "interrupted", None, Some(&error.code))
                    .await;
            }
            Renewal::Done(Err(error)) => {
                self.finish(row, "failed", None, Some(&error.code)).await;
            }
            Renewal::Done(Ok(reference)) => {
                if let Err(error) = self.store.record_started(row, &reference.stored()).await {
                    log_store("start", row, &error);
                    return;
                }
                // One feed row per start, never per tick: the client's progress panel starts here.
                let started = if row.run.runtime == Runtime::FrProject {
                    "The project has started."
                } else {
                    "The run has started."
                };
                self.activity(row, "started", started).await;
                if let Some(result) = &reference.result {
                    // A one-shot channel command answered inside the start: finish the same tick.
                    self.finish(row, "succeeded", Some(result), None).await;
                }
            }
        }
    }

    /// Commit the `dispatch` event before any network I/O, so recovery can tell "maybe sent" from
    /// "never sent". Returns whether a cancel arrived while the run was being started.
    async fn dispatch_intent(&self, row: &WorkerRow) -> Result<bool, StepError> {
        let mut tx = self.store.begin().await?;
        let current = self.store.owned(&mut tx, row, true).await?;
        let cancelled = current.run.cancel_requested;
        if !cancelled {
            self.store.event(&mut tx, row, "dispatch").await?;
        }
        tx.commit().await?;
        Ok(cancelled)
    }

    /// Await one adapter call while keeping the run's lease alive.
    ///
    /// An adapter call may take far longer than a lease, so a slow fr answer must not let the
    /// driver lose a run it still owns. Losing the lease cancels the call and propagates it: the
    /// upstream may already have started, and recovery is what decides.
    async fn renewing<T, E, F>(&self, row: &WorkerRow, call: F) -> Renewal<T, E>
    where
        F: Future<Output = Result<T, E>>,
    {
        let mut call = std::pin::pin!(call);
        let mut ticker = tokio::time::interval(self.settings.worker.heartbeat);
        ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);
        // The first interval tick completes immediately; skip it so the first heartbeat comes one
        // interval after the call started, exactly as the reference's wait loop does.
        ticker.tick().await;
        loop {
            tokio::select! {
                result = &mut call => return Renewal::Done(result),
                _ = ticker.tick() => match self.store.heartbeat(row).await {
                    Ok(_) => {}
                    Err(WorkerStoreError::Denied) => return Renewal::Lost,
                    Err(_) => tracing::warn!(run = %row.run.run_id, "external heartbeat failed"),
                },
            }
        }
    }

    /// Renew every owned run's lease first, then poll them all.
    async fn drive(&self) {
        let listing = match self.store.drive_listing().await {
            Ok(listing) => listing,
            Err(error) => {
                tracing::warn!(code = %store_code(&error), "external drive listing failed");
                return;
            }
        };
        let mut fresh = Vec::with_capacity(listing.len());
        // Renew first, so a slow external call cannot expire the others' leases.
        for row in listing {
            match self.store.heartbeat(&row).await {
                Ok(row) => fresh.push(row),
                Err(WorkerStoreError::Denied) => {
                    tracing::info!(run = %row.run.run_id, "external run lost its lease; skipped");
                }
                Err(_) => tracing::warn!(run = %row.run.run_id, "external heartbeat failed"),
            }
        }
        let mut set = JoinSet::new();
        for row in fresh {
            let driver = self.clone();
            set.spawn(async move { driver.drive_one(&row).await });
        }
        while let Some(joined) = set.join_next().await {
            if joined.is_err() {
                tracing::error!("external drive task failed");
            }
        }
    }

    /// Poll one owned run, honouring its deadline and its cancel request first.
    async fn drive_one(&self, row: &WorkerRow) {
        let Some(adapter) = self.adapter(row.run.runtime) else {
            self.finish(row, "failed", None, Some("external_unconfigured"))
                .await;
            return;
        };
        let Ok(_permit) = self.calls.acquire().await else {
            return;
        };
        if row.deadline.is_some_and(|deadline| deadline <= Utc::now()) {
            if adapter.cancel(row).await.is_err() {
                tracing::warn!(run = %row.run.run_id, "external cancel failed");
            }
            self.finish(row, "timed_out", None, None).await;
            return;
        }
        let mut current = row.clone();
        if current.run.cancel_requested && current.run.status == RunStatus::Running {
            // An error here retries on the next tick, exactly as the reference does.
            if adapter.cancel(&current).await.is_err() {
                tracing::warn!(run = %current.run.run_id, "external cancel failed");
            }
            match self.store.set_cancelling(&current).await {
                Ok(changed) => current = changed,
                Err(WorkerStoreError::Denied) => return,
                Err(error) => {
                    log_store("cancelling", &current, &error);
                    return;
                }
            }
        }
        match self.renewing(&current, adapter.poll(&current)).await {
            Renewal::Lost => {}
            Renewal::Done(Ok(state)) => self.apply(&current, state).await,
            Renewal::Done(Err(error)) => {
                // A poll failure is not the run's outcome: it retries on the next tick.
                log_adapter("poll", &current, &error);
            }
        }
    }

    /// Record what one poll found.
    async fn apply(&self, row: &WorkerRow, state: ExternalState) {
        match state.status {
            ExternalStatus::Running => {
                let Some(message) = state.message else {
                    return;
                };
                let message = truncate(&message, MESSAGE_LIMIT);
                // The reference's falsy check: an empty progress text writes nothing — it must
                // not clear a standing message or append an empty feed row.
                if message.is_empty() {
                    return;
                }
                match self.store.set_status_message(row, &message).await {
                    // A new phase is one feed row. When the update was refused (an answer-again
                    // hint stands) nothing is recorded, so a hint never floods the feed.
                    Ok(true) => self.activity(row, "phase", &message).await,
                    Ok(false) => {}
                    Err(error) => log_store("status_message", row, &error),
                }
            }
            ExternalStatus::Succeeded => {
                self.finish(row, "succeeded", state.result.as_ref(), None)
                    .await;
                self.activity(row, "delivered", "delivered").await;
            }
            ExternalStatus::Failed => {
                let code = state.code.unwrap_or_else(|| "external_failed".to_owned());
                self.finish(row, "failed", None, Some(&code)).await;
                self.activity(row, "failed", &code).await;
            }
            ExternalStatus::Cancelled => {
                let mut current = row.clone();
                if current.run.status == RunStatus::Running && !current.run.cancel_requested {
                    // `running -> cancelled` is not a legal transition; go through cancelling.
                    match self.store.set_cancelling(&current).await {
                        Ok(changed) => current = changed,
                        Err(WorkerStoreError::Denied) => return,
                        Err(error) => {
                            log_store("cancelling", &current, &error);
                            return;
                        }
                    }
                }
                self.finish(&current, "cancelled", None, None).await;
                // The contract has no "cancelled" kind; a withdrawn run is reported as refused.
                self.activity(&current, "refused", "cancelled").await;
            }
        }
    }

    /// Relay answered task inputs back to fr — the driver is the single forwarder.
    async fn forward(&self) {
        let limit = i64::from(self.settings.worker.max_inflight) * 4;
        let items = match self.inputs.claim_answered(limit).await {
            Ok(items) => items,
            Err(_) => {
                tracing::warn!("task input claim failed");
                return;
            }
        };
        for item in items {
            let tenant = item.tenant_id.to_string();
            let run_id = item.run_id.to_string();
            let run = match self.store.get(&tenant, &run_id).await {
                Ok(Some(run)) => run,
                // An unknown run leaves the input answered: nothing can be relayed for it.
                Ok(None) => continue,
                Err(_) => {
                    tracing::warn!(run = %run_id, "task input run read failed");
                    continue;
                }
            };
            if !run.run.status.is_terminal() {
                let Some(forwarder) = &self.forwarder else {
                    continue;
                };
                match forwarder.forward(&run, &item).await {
                    Ok(Some(refused)) => {
                        // The human can answer again (e.g. after linking their address in fr).
                        let message = format!("{REFUSED_PREFIX}{refused}");
                        if self.inputs.reopen(&item.input_key, &message).await.is_err() {
                            tracing::warn!(run = %run_id, "task input reopen failed");
                        }
                        continue;
                    }
                    Ok(None) => {}
                    Err(error) => {
                        log_adapter("forward", &run, &error);
                        continue;
                    }
                }
            }
            if self.inputs.mark_forwarded(&item.input_key).await.is_err() {
                tracing::warn!(run = %run_id, "task input forward mark failed");
            }
        }
    }

    /// Append one activity row; a feed failure never fails the run.
    async fn activity(&self, row: &WorkerRow, kind: &str, text: &str) {
        let (Ok(tenant), Ok(run_id)) = (
            AuthorityId::new(row.run.tenant_id.to_string()),
            Uuid7::new(row.run.run_id.to_string()),
        ) else {
            return;
        };
        if run_activity::record(self.store.pool(), &tenant, &run_id, kind, text, None, None)
            .await
            .is_err()
        {
            tracing::warn!(run = %row.run.run_id, "activity record failed");
        }
    }

    /// The reference's finish, with a storage failure logged rather than propagated: a lost lease
    /// is a no-op and a transient failure is retried by the next tick's recovery.
    async fn finish(
        &self,
        row: &WorkerRow,
        status: &str,
        result: Option<&serde_json::Value>,
        code: Option<&str>,
    ) {
        match self.store.finish(row, status, result, code).await {
            // The one per-run success line, with the status the store actually wrote. The result
            // and the error stay in the database.
            Ok(Some(written)) => tracing::info!(
                run = %row.run.run_id,
                runtime = ?row.run.runtime,
                status = %written,
                "external run finished"
            ),
            Ok(None) => {}
            Err(error) => log_store("finish", row, &error),
        }
    }
}

/// A storage failure's log line: the run and the class, never the statement or its values.
fn log_store(step: &'static str, row: &WorkerRow, error: &WorkerStoreError) {
    match error {
        WorkerStoreError::Denied => {
            tracing::info!(run = %row.run.run_id, step, "external run no longer owned");
        }
        WorkerStoreError::Store(_) => {
            tracing::warn!(run = %row.run.run_id, step, "external storage failed");
        }
    }
}

/// An adapter failure's log line: the run and the public code only.
fn log_adapter(step: &'static str, row: &WorkerRow, error: &AdapterError) {
    tracing::warn!(run = %row.run.run_id, step, code = %error.code, "external adapter failed");
}

/// A storage error's public class, for the one log line that has no run.
fn store_code(error: &WorkerStoreError) -> &'static str {
    match error {
        WorkerStoreError::Denied => "denied",
        WorkerStoreError::Store(_) => "store",
    }
}

/// Python's `message[:limit]`: a character bound, not a byte one.
fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The driver binary's entry point: load settings, refuse an unusable configuration, and serve
/// until a signal.
pub async fn run() -> Result<(), RuntimeError> {
    let settings = ExternalDriverSettings::from_env()?;
    // The reference's `DriverConfigError`: merely installing runtime code cannot enable execution.
    if !settings.execution_enabled {
        return Err(RuntimeError::Refused(
            "external driver requires explicit execution enablement",
        ));
    }
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(RuntimeError::MissingDatabaseUrl)?;
    let pool = db::connect(&database_url).await?;
    let served = serve(settings, pool.clone()).await;
    pool.close().await;
    served
}

/// Build the driver and run the tick loop until shutdown.
async fn serve(settings: ExternalDriverSettings, pool: sqlx::PgPool) -> Result<(), RuntimeError> {
    verify_schema(&pool).await?;
    let driver_id = uuid::Uuid::now_v7().to_string();
    let store = ExternalStore::new(pool.clone(), settings.clone(), driver_id.clone());
    let inputs = TaskInputRepository::new(pool);
    let client = reqwest::Client::builder()
        .timeout(settings.worker.api_timeout)
        .build()?;
    let n8n = Arc::new(N8nAdapter::new(client.clone(), (&settings).into()));
    let fr = Arc::new(FrAdapter::new(client.clone(), (&settings).into()));
    let command = Arc::new(FrCommandAdapter::new(client, (&settings).into()));
    let mut adapters: HashMap<&'static str, Arc<dyn ExternalAdapter>> = HashMap::new();
    adapters.insert("n8n_workflow", n8n);
    adapters.insert("fr_project", fr.clone());
    adapters.insert("fr_command", command);
    let forwarder: Arc<dyn AnswerForwarder> = fr;
    let driver = ExternalDriver::new(store, inputs, adapters, Some(forwarder), settings.clone());

    let window = Duration::from_secs_f64(settings.execution.external_poll_seconds * 3.0);
    let liveness = Arc::new(Liveness::new(window));
    let driver = driver.with_liveness(liveness.clone());
    let listener = tokio::net::TcpListener::bind(("0.0.0.0", settings.probe_port)).await?;
    let probes = tokio::spawn(async move {
        let _ = axum::serve(listener, crate::external::health::app(liveness)).await;
    });

    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
    let stop = async {
        tokio::select! {
            _ = terminate.recv() => {}
            _ = tokio::signal::ctrl_c() => {}
        }
    };
    tokio::pin!(stop);

    let poll = Duration::from_secs_f64(settings.execution.external_poll_seconds);
    tracing::info!(driver = %driver_id, "external driver started");
    loop {
        match driver.tick().await {
            Ok(()) => driver.mark_alive(),
            Err(error) => {
                tracing::error!(code = %store_code(&error), "external driver tick failed");
            }
        }
        tokio::select! {
            _ = &mut stop => break,
            _ = tokio::time::sleep(poll) => {}
        }
    }
    probes.abort();
    Ok(())
}
