//! One fenced controller per claimed run (slice S8).
//!
//! Ported from the reference `src/execution/controller.py` at commit `22ac1ce4`. One controller
//! drives exactly one claimed run: a guard that keeps the lease alive and re-proves the run's
//! live authority, a pump that owns the runner's stdin/stdout protocol, and an outcome that is
//! always persisted together with the proof that the runner pod is gone.
//!
//! Three properties are load-bearing and are preserved exactly:
//!
//! * **The pod intent is durable before the pod exists.** `store.pod(row, name, None)` commits
//!   first, so a worker that dies between create and the UID write still leaves the reconciler a
//!   name to inspect. A failed create response can still have created the pod, so cleanup
//!   inspects the deterministic name even when no `Pod` was ever returned.
//! * **EOF is not success.** The runner's channel closing only ends the frame stream; the run
//!   succeeds only when the *same immutable pod UID* is observed terminating with exit code 0.
//! * **The claimed row's deadlines are the deadlines.** The reference keeps the row it claimed
//!   and never re-reads the narrowed stored deadline (`running()` narrows only the database
//!   row); the guard, the pump and the overall timeout all use the same claimed values here.
//!
//! Cancellation is cooperative, not a dropped future: the worker's shutdown is a
//! [`tokio::sync::watch`] flag the guard and the pump select on, so a stopped worker still
//! stops its pod and persists `interrupted`/`worker_stopped` before returning. (The reference's
//! `asyncio.CancelledError` path does the same through its `finally`.)

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{Map, Value, json};
use sqlx::PgPool;
use tokio::sync::watch;
use tokio::time::{Instant, sleep};

use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::instance::validate_instance;
use crate::catalog::models::ToolLimits;
use crate::catalog::package::PackageFile;
use crate::catalog::resolver::CatalogResolver;
use crate::catalog::validation::SchemaLimits;
use crate::config::{ExecutionSettings, WorkerSettings};
use crate::storage::catalog::CatalogRepository;
use crate::worker::authority::{AuthorityError, live, resolved_snapshot};
use crate::worker::backend::{AttachChannel, Backend, BackendError, Pod, pod_name};
use crate::worker::broker::{Broker, BrokerError, CallOutcome};
use crate::worker::protocol::{Decoder, Frame, VERSION, encode};
use crate::worker::row::WorkerRow;
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// `init` has an independent package bound (`controller.py:63`): 8 MiB, wider than every
/// subsequent frame. Package content remains off all public APIs.
const INIT_FRAME_BYTES: usize = 8_388_608;

/// The pod-phase poll interval (`controller.py`'s `asyncio.sleep(0.1)`).
const INSPECT_INTERVAL: Duration = Duration::from_millis(100);

/// One fenced controller. Cloneable so the worker loop can spawn one execution per claimed run;
/// every clone shares the same store, resolver, broker, backend and shutdown signal.
#[derive(Clone)]
pub struct Controller {
    store: WorkerStore,
    resolver: CatalogResolver,
    broker: Arc<Broker>,
    backend: Arc<dyn Backend>,
    catalog_pool: PgPool,
    settings: WorkerSettings,
    execution: ExecutionSettings,
    /// The worker's graceful-shutdown flag. `true` means "stop now".
    shutdown: watch::Receiver<bool>,
}

impl Controller {
    /// Bind the controller to the worker's assembled dependencies.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        store: WorkerStore,
        resolver: CatalogResolver,
        broker: Arc<Broker>,
        backend: Arc<dyn Backend>,
        catalog_pool: PgPool,
        settings: WorkerSettings,
        execution: ExecutionSettings,
        shutdown: watch::Receiver<bool>,
    ) -> Self {
        Self {
            store,
            resolver,
            broker,
            backend,
            catalog_pool,
            settings,
            execution,
            shutdown,
        }
    }

    /// Drive one claimed run to a terminal state.
    ///
    /// The outcome — and only the outcome — is persisted: `succeeded` with the runner's result,
    /// or a failure class with no host text in it. A denial from `finish` (an expired or
    /// replaced owner) is swallowed: reconciliation owns that decision now. Any other storage
    /// failure is logged; the worker loop treats a failed run as a run, not as a worker exit.
    pub async fn execute(&self, row: WorkerRow) {
        let mut pod: Option<Pod> = None;

        let (status, code, result) = match self.run(&row, &mut pod).await {
            Ok(value) => ("succeeded", None, Some(value)),
            Err(failure) => {
                let (status, code) = failure.classify(pod.is_some());
                (status, code, None)
            }
        };

        // Always stop the pod (confirming absence) and persist the terminal state.
        let absent = self.confirm_absent(&row, pod.as_ref()).await;
        match self
            .store
            .finish(&row, status, result.as_ref(), code, absent)
            .await
        {
            Ok(()) | Err(WorkerStoreError::Denied) => {}
            Err(error) => tracing::error!(
                run_id = %row.run.run_id,
                error = %error,
                "controller could not persist the run's outcome"
            ),
        }
    }

    /// The reference's `execute` body, up to (but excluding) the terminal persistence.
    async fn run(&self, row: &WorkerRow, pod_slot: &mut Option<Pod>) -> Result<Value, RunFailure> {
        let deadline = row.deadline.ok_or(RunFailure::Denied)?;
        let start_deadline = row.start_deadline.ok_or(RunFailure::Denied)?;

        // The guard starts with the attempt: it renews the lease and re-proves the authority
        // while preflight and the pod start run, exactly as the reference's task does.
        let guard = self.guard(row, deadline);
        tokio::pin!(guard);

        // Preflight is bounded by the sooner of the start and run deadlines.
        let budget = start_deadline.min(deadline);
        let preflight_budget = remaining(budget).max(Duration::from_millis(1));
        let setup = async {
            let preflight = self.broker.preflight(row);
            tokio::time::timeout(preflight_budget, preflight)
                .await
                .map_err(|_| RunFailure::Deadline)?
                .map_err(RunFailure::Broker)?;
            let authority = live(&self.store, &self.resolver, row)
                .await
                .map_err(RunFailure::Authority)?;
            let limits = authority.effective.limits;
            let name = pod_name(&row.run.run_id, row.fence);
            // Durable intent before create: a crash here still leaves the reconciler a name.
            self.store
                .pod(row, &name, None)
                .await
                .map_err(RunFailure::Store)?;
            let pod = self
                .backend
                .start(row, &limits)
                .await
                .map_err(RunFailure::Backend)?;
            self.store
                .pod(row, &name, Some(pod.uid.as_str()))
                .await
                .map_err(RunFailure::Store)?;
            Ok::<(Pod, ToolLimits), RunFailure>((pod, limits))
        };
        tokio::pin!(setup);

        // The guard races setup so a lost lease aborts the attempt instead of creating a pod
        // for an owner the database has already fenced out.
        let (pod, limits) = tokio::select! {
            started = &mut setup => started?,
            guard_result = &mut guard => {
                guard_result?;
                return Err(RunFailure::Denied);
            }
        };
        *pod_slot = Some(pod.clone());

        let pump = self.pump(row, &pod, &limits, start_deadline, deadline);
        tokio::pin!(pump);

        let finish = async {
            let result = tokio::select! {
                pumped = &mut pump => pumped?,
                guard_result = &mut guard => {
                    guard_result?;
                    return Err(RunFailure::Denied);
                }
            };
            // Recheck cancellation, lease and live revocation before success.
            live(&self.store, &self.resolver, row)
                .await
                .map_err(RunFailure::Authority)?;
            Ok::<Value, RunFailure>(result)
        };

        match tokio::time::timeout_at(instant_at(deadline), finish).await {
            Ok(outcome) => outcome,
            Err(_) => Err(RunFailure::Deadline),
        }
    }

    /// The reference's `guard`: renew the lease and re-prove the live authority every interval,
    /// and fail the attempt the moment the wall deadline passes.
    async fn guard(&self, row: &WorkerRow, deadline: DateTime<Utc>) -> Result<(), RunFailure> {
        let mut shutdown = self.shutdown.clone();
        loop {
            tokio::select! {
                () = sleep(self.settings.heartbeat) => {}
                () = stopped(&mut shutdown) => return Err(RunFailure::Stopped),
            }
            if Utc::now() >= deadline {
                return Err(RunFailure::Deadline);
            }
            self.store.heartbeat(row).await.map_err(RunFailure::Store)?;
            live(&self.store, &self.resolver, row)
                .await
                .map_err(RunFailure::Authority)?;
        }
    }

    /// The reference's `pump`: wait for the pod to run, speak the runner protocol over the
    /// attached channel, and require the same pod UID to terminate successfully.
    async fn pump(
        &self,
        row: &WorkerRow,
        pod: &Pod,
        limits: &ToolLimits,
        start_deadline: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Result<Value, RunFailure> {
        // Wait for this exact pod (same immutable UID) to reach Running.
        loop {
            match self
                .backend
                .inspect(&pod.name)
                .await
                .map_err(RunFailure::Backend)?
            {
                None => return Err(RunFailure::Denied),
                Some(current) if current.uid != pod.uid => return Err(RunFailure::Denied),
                Some(current) if current.phase == "Failed" || current.phase == "Succeeded" => {
                    return Err(RunFailure::Denied);
                }
                Some(current) if current.phase == "Running" => break,
                Some(_) => {
                    if Utc::now() >= start_deadline {
                        return Err(RunFailure::Deadline);
                    }
                    sleep(INSPECT_INTERVAL).await;
                }
            }
        }

        let mut channel = self
            .backend
            .attach(pod)
            .await
            .map_err(RunFailure::Backend)?;
        let session = self
            .session(row, channel.as_mut(), limits, start_deadline, deadline)
            .await;
        channel.close().await;
        let result = session?;

        // Attach EOF alone does not establish success. Wait for the actual pod termination
        // status and require the same immutable UID with exit 0.
        loop {
            match self
                .backend
                .inspect(&pod.name)
                .await
                .map_err(RunFailure::Backend)?
            {
                None => return Err(RunFailure::Denied),
                Some(current) if current.uid != pod.uid => return Err(RunFailure::Denied),
                Some(current) if current.phase == "Failed" || current.phase == "Succeeded" => {
                    return if current.phase == "Succeeded" && current.exit_code == Some(0) {
                        Ok(result)
                    } else {
                        Err(RunFailure::Denied)
                    };
                }
                Some(_) => sleep(INSPECT_INTERVAL).await,
            }
        }
    }

    /// Send `init`, then run the strict frame loop: `ready` first, ordered `api_call`s within
    /// the run's allowance, one validated `result`, bounded logs and a bounded frame stream.
    async fn session(
        &self,
        row: &WorkerRow,
        channel: &mut dyn AttachChannel,
        limits: &ToolLimits,
        start_deadline: DateTime<Utc>,
        deadline: DateTime<Utc>,
    ) -> Result<Value, RunFailure> {
        let resolved = resolved_snapshot(&row.run).map_err(RunFailure::Authority)?;
        let files = self.package_files(row).await?;
        let entrypoint = resolved
            .manifest
            .entrypoint
            .clone()
            .ok_or(RunFailure::Denied)?;
        let inputs = row
            .run
            .inputs
            .as_object()
            .cloned()
            .ok_or(RunFailure::Denied)?;
        let context = public_context(&resolved.context.public_values())?;
        let limits_value = match serde_json::to_value(limits) {
            Ok(Value::Object(limits)) => limits,
            _ => return Err(RunFailure::Denied),
        };

        let init = Frame::Init {
            protocol: VERSION,
            files,
            digest: resolved.manifest.package_sha256.as_str().to_owned(),
            entrypoint,
            inputs,
            context,
            limits: limits_value,
        };
        let init = encode(&init, INIT_FRAME_BYTES)
            .map_err(|error| RunFailure::Protocol(error.to_string()))?;
        channel.send(&init).await.map_err(RunFailure::Backend)?;

        let frame_bytes = usize::try_from(limits.frame_bytes)
            .unwrap_or(usize::MAX)
            .min(self.settings.max_frame_bytes);
        let mut decoder = Decoder::new(
            frame_bytes,
            self.settings.max_output_bytes,
            usize::try_from(self.settings.max_frames).unwrap_or(usize::MAX),
        );

        let mut shutdown = self.shutdown.clone();
        let mut ready = false;
        let mut finalized = false;
        let mut result: Option<Value> = None;
        let mut sequence: u32 = 0;
        let mut logs: usize = 0;

        loop {
            let now = Utc::now();
            // A silent Running pod must not consume the entire run deadline before
            // init/ready completes.
            let wait = if ready {
                // `max(0.001, remaining)`: after `ready` the run deadline is a hard bound.
                remaining(deadline).max(Duration::from_millis(1))
            } else {
                if now >= start_deadline {
                    return Err(RunFailure::Deadline);
                }
                remaining(start_deadline)
            };
            let chunk = tokio::select! {
                received = channel.receive() => received.map_err(RunFailure::Backend)?,
                () = sleep(wait) => return Err(RunFailure::Deadline),
                () = stopped(&mut shutdown) => return Err(RunFailure::Stopped),
            };
            let Some((output, stderr)) = chunk else {
                break;
            };
            logs += stderr.len();
            if logs > self.settings.max_log_bytes {
                return Err(RunFailure::protocol("diagnostics limit"));
            }

            for frame in decoder
                .feed(&output)
                .map_err(|error| RunFailure::Protocol(error.to_string()))?
            {
                if finalized {
                    return Err(RunFailure::protocol("frame after final"));
                }
                if !ready {
                    match frame {
                        Frame::Ready { .. } => {
                            if Utc::now() >= start_deadline {
                                return Err(RunFailure::Deadline);
                            }
                            ready = true;
                            // `running` is emitted exactly once, when the runner acknowledges.
                            self.store.running(row).await.map_err(RunFailure::Store)?;
                        }
                        _ => return Err(RunFailure::protocol("ready required")),
                    }
                    continue;
                }
                match frame {
                    Frame::ApiCall {
                        sequence: number,
                        operation_id,
                        arguments,
                        idempotency_key,
                    } => {
                        if number != sequence + 1 {
                            return Err(RunFailure::protocol("repeated or unordered sequence"));
                        }
                        sequence = number;
                        if sequence > limits.api_calls {
                            return Err(RunFailure::Denied);
                        }
                        let (call_result, error) = match self
                            .broker
                            .call(row, &operation_id, &arguments, idempotency_key.as_deref())
                            .await
                        {
                            Ok(CallOutcome::Value(value)) => (Some(value), None),
                            // A declared, expected upstream status is a result for the tool.
                            Ok(CallOutcome::Expected { status, body }) => (
                                None,
                                Some(
                                    json!({"code": "http_status", "status": status, "body": body}),
                                ),
                            ),
                            // The upstream may have acted: never requeue or replay.
                            Err(BrokerError::OutcomeUnknown) => {
                                return Err(RunFailure::OutcomeUnknown);
                            }
                            // The reference propagates a broker denial out of the pump (only a
                            // declared expected status becomes an `api_result` error), so the
                            // run ends `interrupted`/`execution_interrupted` with a pod.
                            Err(error) => return Err(RunFailure::Broker(error)),
                        };
                        let answer = Frame::ApiResult {
                            sequence,
                            result: call_result,
                            error,
                        };
                        let answer = encode(&answer, frame_bytes)
                            .map_err(|error| RunFailure::Protocol(error.to_string()))?;
                        channel.send(&answer).await.map_err(RunFailure::Backend)?;
                    }
                    Frame::Result { result: value } => {
                        validate_instance(
                            &Value::Object(resolved.manifest.result_schema.clone()),
                            &value,
                            &SchemaLimits::default(),
                        )
                        .map_err(|_| RunFailure::protocol("result schema"))?;
                        let encoded = encode(
                            &Frame::Result {
                                result: value.clone(),
                            },
                            usize::try_from(limits.frame_bytes).unwrap_or(usize::MAX),
                        )
                        .map_err(|error| RunFailure::Protocol(error.to_string()))?;
                        if encoded.len()
                            > usize::try_from(limits.output_bytes)
                                .unwrap_or(usize::MAX)
                                .min(self.execution.max_result_bytes)
                        {
                            return Err(RunFailure::protocol("result size"));
                        }
                        result = Some(value);
                        finalized = true;
                    }
                    Frame::Log { message } => {
                        logs += message.len();
                        if logs > self.settings.max_log_bytes {
                            return Err(RunFailure::protocol("diagnostics limit"));
                        }
                    }
                    _ => return Err(RunFailure::protocol("unexpected runner frame")),
                }
            }
            if !ready && Utc::now() >= start_deadline {
                return Err(RunFailure::Deadline);
            }
        }

        if !decoder.buffer_is_empty() || !finalized {
            return Err(RunFailure::protocol("incomplete result"));
        }
        result.ok_or_else(|| RunFailure::protocol("incomplete result"))
    }

    /// The package the runner receives, in the catalog's path order.
    async fn package_files(&self, row: &WorkerRow) -> Result<Vec<Value>, RunFailure> {
        let tenant = AuthorityId::new(row.run.owner_tenant_id.to_string())
            .map_err(|_| RunFailure::Denied)?;
        let tool = Uuid7::new(row.run.tool_id.to_string()).map_err(|_| RunFailure::Denied)?;
        let version = PositiveVersion::new(
            u64::try_from(row.run.tool_version).map_err(|_| RunFailure::Denied)?,
        )
        .map_err(|_| RunFailure::Denied)?;
        let files: Vec<PackageFile> = CatalogRepository::new(self.catalog_pool.clone())
            .files(&tenant, &tool, version)
            .await
            .map_err(|error| RunFailure::Catalog(error.to_string()))?;
        files
            .iter()
            .map(|file| {
                serde_json::to_value(file)
                    .map_err(|error| RunFailure::Catalog(format!("package file: {error}")))
            })
            .collect()
    }

    /// Confirm the attempt's pod is gone (the reference's `finally` block). `true` means
    /// absence was proved; only then may `finish` free the slot.
    async fn confirm_absent(&self, row: &WorkerRow, pod: Option<&Pod>) -> bool {
        let current = match pod {
            Some(pod) => Some(pod.clone()),
            // A failed create response can still have created the pod.
            None => match self
                .backend
                .inspect(&pod_name(&row.run.run_id, row.fence))
                .await
            {
                Ok(current) => current,
                Err(_) => return false,
            },
        };
        let Some(current) = current else {
            return true;
        };
        // A pod that names another run or generation is never adopted or stopped.
        if current.run_id != row.run.run_id.to_string() || current.fence != row.fence {
            return false;
        }
        self.backend.stop(&current).await.unwrap_or(false)
    }
}

/// Why one attempt failed. Only the variant matters publicly: no host text ever reaches a run.
enum RunFailure {
    /// The wall deadline or the start allowance passed.
    Deadline,
    /// The upstream outcome cannot be known (a crash or channel loss mid-call).
    OutcomeUnknown,
    /// The worker is shutting down.
    Stopped,
    /// An authority, fence or protocol rule refused the step.
    Denied,
    Broker(BrokerError),
    Backend(BackendError),
    Protocol(String),
    Store(WorkerStoreError),
    Authority(AuthorityError),
    Catalog(String),
}

impl RunFailure {
    /// The reference's protocol refusals carry a fixed message; none of it is public.
    fn protocol(message: &'static str) -> Self {
        Self::Protocol(message.to_owned())
    }

    /// The terminal status and code the reference assigns this failure.
    fn classify(&self, pod_existed: bool) -> (&'static str, Option<&'static str>) {
        match self {
            Self::Deadline => ("timed_out", Some("deadline_exceeded")),
            Self::OutcomeUnknown => ("interrupted", Some("outcome_unknown")),
            Self::Stopped => ("interrupted", Some("worker_stopped")),
            // Any authority/channel loss after execution may include a completed side effect.
            // Never requeue or import/replay the package.
            _ if pod_existed => ("interrupted", Some("execution_interrupted")),
            _ => ("failed", Some("preflight_failed")),
        }
    }
}

impl std::fmt::Display for RunFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Deadline => formatter.write_str("deadline exceeded"),
            Self::OutcomeUnknown => formatter.write_str("upstream outcome unknown"),
            Self::Stopped => formatter.write_str("worker stopped"),
            Self::Denied => formatter.write_str("execution denied"),
            Self::Broker(error) => write!(formatter, "broker refusal: {error}"),
            Self::Backend(error) => write!(formatter, "backend: {error}"),
            Self::Protocol(error) => write!(formatter, "protocol: {error}"),
            Self::Store(error) => write!(formatter, "store: {error}"),
            Self::Authority(error) => write!(formatter, "authority: {error}"),
            Self::Catalog(error) => write!(formatter, "catalog: {error}"),
        }
    }
}

impl std::fmt::Debug for RunFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for RunFailure {}

/// The reference's `public_values()` result as the frame's object.
fn public_context(value: &Value) -> Result<Map<String, Value>, RunFailure> {
    match value {
        Value::Object(values) => Ok(values.clone()),
        _ => Err(RunFailure::Denied),
    }
}

/// How long remains until `deadline`; already-past is zero.
fn remaining(deadline: DateTime<Utc>) -> Duration {
    deadline
        .signed_duration_since(Utc::now())
        .to_std()
        .unwrap_or(Duration::ZERO)
}

/// A wall-clock deadline as a tokio instant (already-past deadlines fire immediately).
fn instant_at(deadline: DateTime<Utc>) -> Instant {
    Instant::now() + remaining(deadline)
}

/// Resolve when the worker's shutdown flag is set. A dropped sender never stops a run by
/// itself: the worker keeps the sender alive until every controller has finished.
async fn stopped(shutdown: &mut watch::Receiver<bool>) {
    if *shutdown.borrow() {
        return;
    }
    loop {
        match shutdown.changed().await {
            Ok(()) if *shutdown.borrow() => return,
            Ok(()) => {}
            Err(_) => std::future::pending::<()>().await,
        }
    }
}
