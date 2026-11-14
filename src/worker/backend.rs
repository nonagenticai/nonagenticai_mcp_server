//! The sandbox boundary: what the controller may ask of a runner backend.
//!
//! The trait exists so the controller's semantics (fencing, deadlines, frame order, result
//! validation) can be exercised end to end without a cluster. The real implementation
//! ([`crate::worker::kata`]) is the only code that talks to the Kubernetes API; tests substitute
//! a backend that speaks the runner protocol over an in-memory channel. Kubernetes is an external
//! boundary, which is the only place this project permits a fake.

use std::fmt;
use std::time::Duration;

use async_trait::async_trait;

use crate::auth::Rfc4122Uuid;
use crate::catalog::models::ToolLimits;
use crate::worker::row::WorkerRow;

/// The deterministic pod name for one fencing generation of a run.
///
/// The reference builds `mcp-<runhex>-<fence>` (`kata.py:11-12`). Determinism is load-bearing:
/// an ambiguous `create` response is resolved by inspecting this exact name, never by starting a
/// second pod.
pub fn pod_name(run: &Rfc4122Uuid, fence: i64) -> String {
    format!("mcp-{}-{fence}", run.to_string().replace('-', ""))
}

/// One runner pod as the cluster reports it. The identity fields are the fence: a pod whose
/// labels do not name this run and this generation is never adopted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pod {
    /// `metadata.name`.
    pub name: String,
    /// `metadata.uid` — immutable for the pod's whole life; a recreate gets a new one.
    pub uid: String,
    /// `mcp.run-id` label.
    pub run_id: String,
    /// `mcp.fence` label.
    pub fence: i64,
    /// `status.phase` as the API spells it (`Pending`, `Running`, `Succeeded`, `Failed`).
    pub phase: String,
    /// The runner container's exit code once terminated.
    pub exit_code: Option<i32>,
}

/// A refusal or transport failure at the sandbox boundary.
///
/// Every variant is a denial for the current attempt: the controller classifies it as
/// `failed`/`preflight_failed` before a pod exists and `interrupted`/`execution_interrupted`
/// after, and never retries the run.
#[derive(Debug)]
pub enum BackendError {
    /// The cluster said no, or said something we refuse to adopt.
    Denied(&'static str),
    /// The API could not be reached or did not answer in time.
    Transport(String),
}

impl fmt::Display for BackendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Denied(reason) => write!(f, "backend denied: {reason}"),
            Self::Transport(reason) => write!(f, "backend transport: {reason}"),
        }
    }
}

impl std::error::Error for BackendError {}

/// One attached runner process: stdin writes, per-channel buffered stdout/stderr drains.
///
/// `receive` deliberately returns only what has already arrived. The reference's attach poll
/// used `timeout=0` for the same reason: blocking until the runner speaks again would hold the
/// executor past its deadline while the runner waits for an `api_result`.
#[async_trait]
pub trait AttachChannel: Send {
    /// Write one frame to the runner's stdin.
    async fn send(&mut self, data: &[u8]) -> Result<(), BackendError>;
    /// Drain bytes already received. `Ok(None)` means the channel closed (EOF).
    async fn receive(&mut self) -> Result<Option<(Vec<u8>, Vec<u8>)>, BackendError>;
    /// Close the attach stream; idempotent.
    async fn close(&mut self);
}

/// The sandbox backend the controller drives.
#[async_trait]
pub trait Backend: Send + Sync {
    /// Prove the backend itself is usable (runtime class present, inventory readable).
    async fn ready(&self) -> Result<(), BackendError>;
    /// The pod for `name`, or `None` when the API answers 404.
    async fn inspect(&self, name: &str) -> Result<Option<Pod>, BackendError>;
    /// Create the run's pod from the run's snapshotted manifest. Must resolve an ambiguous
    /// create by inspecting the deterministic name, never by creating twice, and must refuse a
    /// pod whose run id, fence or recorded UID disagrees with `row`.
    async fn start(&self, row: &WorkerRow, limits: &ToolLimits) -> Result<Pod, BackendError>;
    /// Attach to the runner container's stdio.
    async fn attach(&self, pod: &Pod) -> Result<Box<dyn AttachChannel>, BackendError>;
    /// Delete the pod (UID precondition) and confirm it is gone. `Ok(false)` means the delete
    /// was issued but absence could not be confirmed — capacity must stay quarantined.
    async fn stop(&self, pod: &Pod) -> Result<bool, BackendError>;
    /// Every pod this executor manages, refusing an inventory larger than one page.
    async fn list(&self) -> Result<Vec<Pod>, BackendError>;
}

/// How long `stop` waits for the pod to disappear after a successful delete (`kata.py:282-286`).
pub const STOP_CONFIRM_ATTEMPTS: u32 = 20;
/// The interval between those confirmations.
pub const STOP_CONFIRM_INTERVAL: Duration = Duration::from_millis(250);
