//! One `mcp_runs` row as the worker sees it: the public run plus the fenced-ownership columns.
//!
//! The row is decoded from the same projection `src/storage/executions.rs` uses (`RUN_COLUMNS`)
//! extended with the worker columns (`WORKER_COLUMNS`), so a run read here and a run read
//! through the execution repository carry identical values. Instants are epoch microseconds for
//! the same reason: this crate's `sqlx` build maps no `chrono` type, and `decode_run` already
//! rebuilds them by hand.
//!
//! The authority snapshot is the reference's shape — `{"manifest","effective","context"}`, each
//! member a JSON **string** holding that model's own JSON. [`limits_from_authority`] is the one
//! place the worker reads runner limits, and a mistyped member is an error, never a default: a
//! defaulted limit would let a run outlive the contract it was accepted under.

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::Row;
use sqlx::postgres::PgRow;

use crate::catalog::models::ToolLimits;
use crate::execution::RunRow;
use crate::storage::executions::{RUN_COLUMNS, decode_run, optional_instant};
use crate::worker::store::WorkerStoreError;

/// The worker-owned columns, aliased exactly as `decode_worker` reads them.
///
/// `api_calls` is the run's monotone upstream-call counter: the journal writes it, never the API.
pub(crate) const WORKER_COLUMNS: &str = "worker_id::text AS worker_id, fence, \
     (extract(epoch FROM lease_until) * 1000000)::bigint AS lease_until_us, \
     (extract(epoch FROM heartbeat_at) * 1000000)::bigint AS heartbeat_at_us, \
     (extract(epoch FROM start_deadline) * 1000000)::bigint AS start_deadline_us, \
     (extract(epoch FROM deadline) * 1000000)::bigint AS deadline_us, \
     pod_name, pod_uid, api_calls";

/// The columns a worker statement projects: the public run, then the fencing columns.
pub(crate) fn worker_projection() -> String {
    format!("{RUN_COLUMNS}, {WORKER_COLUMNS}")
}

/// One `mcp_runs` row with the columns only a worker may read or write.
#[derive(Debug, Clone)]
pub struct WorkerRow {
    /// Every column the execution API also reads.
    pub run: RunRow,
    /// The claiming executor's identity (`mcp_runs.worker_id`), a version-7 UUID as text.
    pub worker_id: Option<String>,
    /// The claim generation; every write re-proves it.
    pub fence: i64,
    /// Until when this worker owns the run without a heartbeat.
    pub lease_until: Option<DateTime<Utc>>,
    /// When the worker last extended the lease.
    pub heartbeat_at: Option<DateTime<Utc>>,
    /// By when the worker must have reported the run `running`.
    pub start_deadline: Option<DateTime<Utc>>,
    /// By when the run must be finished.
    pub deadline: Option<DateTime<Utc>>,
    /// The runner pod the worker created for this fence.
    pub pod_name: Option<String>,
    /// The pod's immutable UID. The reference writes it with `coalesce($new, pod_uid)`: an
    /// intent write (no UID) preserves it, the controller's post-create write sets it.
    pub pod_uid: Option<String>,
    /// Upstream calls journalled so far; the next sequence is this plus one.
    pub api_calls: i32,
}

impl WorkerRow {
    /// The run's runner limits, from the authority snapshot it was accepted with.
    pub fn limits(&self) -> Result<ToolLimits, WorkerStoreError> {
        limits_from_authority(&self.run.authority)
    }

    /// The claiming worker's identity, or a denial: a row without one is owned by nobody.
    pub(crate) fn worker(&self) -> Result<&str, WorkerStoreError> {
        self.worker_id.as_deref().ok_or(WorkerStoreError::Denied)
    }
}

/// The runner limits stored in a run's authority snapshot.
///
/// `authority` is `{"manifest": <JSON string>, "effective": <JSON string>, "context": <JSON
/// string>}`: the members are strings because the reference stores pydantic
/// `model_dump_json` output, and the Python worker re-parses them with `model_validate_json`.
/// A missing or mistyped member is an error — the limits can never be defaulted, or the run
/// would outlive the contract it was accepted under.
pub fn limits_from_authority(authority: &Value) -> Result<ToolLimits, WorkerStoreError> {
    for name in ["manifest", "effective", "context"] {
        member(authority, name)?;
    }
    let effective: Value = serde_json::from_str(member(authority, "effective")?)
        .map_err(|error| broken(format!("authority.effective is not JSON: {error}")))?;
    let limits = effective
        .get("limits")
        .ok_or_else(|| broken("authority.effective carries no limits"))?;
    serde_json::from_value(limits.clone())
        .map_err(|error| broken(format!("authority.effective limits are invalid: {error}")))
}

/// One authority member as the JSON string it must be.
fn member<'a>(authority: &'a Value, name: &str) -> Result<&'a str, WorkerStoreError> {
    authority
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| broken(format!("authority.{name} is not a JSON string")))
}

/// Decode one row selected with `worker_projection`.
pub(crate) fn decode_worker(row: &PgRow) -> Result<WorkerRow, WorkerStoreError> {
    Ok(WorkerRow {
        run: decode_run(row)?,
        worker_id: row.try_get("worker_id")?,
        fence: row.try_get("fence")?,
        lease_until: optional_instant(row.try_get("lease_until_us")?)?,
        heartbeat_at: optional_instant(row.try_get("heartbeat_at_us")?)?,
        start_deadline: optional_instant(row.try_get("start_deadline_us")?)?,
        deadline: optional_instant(row.try_get("deadline_us")?)?,
        pod_name: row.try_get("pod_name")?,
        pod_uid: row.try_get("pod_uid")?,
        api_calls: row.try_get("api_calls")?,
    })
}

/// A stored value the worker refuses to interpret, as the store's error type.
fn broken(reason: impl Into<String>) -> WorkerStoreError {
    let reason: Box<dyn std::error::Error + Send + Sync> =
        Box::new(std::io::Error::other(reason.into()));
    WorkerStoreError::Store(sqlx::Error::Decode(reason))
}
