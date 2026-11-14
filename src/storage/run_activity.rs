//! Run activity feed reads: the progress rows as the protocol's `activity` array.
//!
//! Ported from the reference `src/tasks/activity.py` (`recent`, `wire`). `recent` returns rows
//! **newest-last** (ascending `seq`): the newest entry is the last row. That is the order an
//! operator reads a log in, and it makes a signal scan a plain walk of recent history.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::storage::executions::{ExecutionStoreError, instant};

/// Rows a task carries: enough for a progress panel, never unbounded.
pub const ACTIVITY_LIMIT: u32 = 50;

/// One `mcp_run_activity` row as the feed reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActivityRow {
    /// The run-scoped ascending sequence.
    pub seq: i64,
    /// The phase kind (`phase`, `started`, `approval_requested`, …).
    pub kind: String,
    /// The rendered line, at most 512 characters.
    pub text: String,
    /// `info`, `low`, `medium`, `high` or `critical`.
    pub severity: String,
    /// When it was appended.
    pub created_at: DateTime<Utc>,
}

/// The newest `limit` rows of the run, NEWEST-LAST (ascending `seq`).
pub async fn recent(
    pool: &PgPool,
    tenant: &AuthorityId,
    run_id: &Uuid7,
    limit: u32,
) -> Result<Vec<ActivityRow>, ExecutionStoreError> {
    let rows = sqlx::query(
        "SELECT seq, kind, text, severity, \
         (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us \
         FROM (SELECT seq, kind, text, severity, created_at \
               FROM public.mcp_run_activity \
               WHERE tenant_id = $1::uuid AND run_id = $2::uuid \
               ORDER BY seq DESC LIMIT $3) newest \
         ORDER BY seq",
    )
    .bind(tenant.as_str())
    .bind(run_id.as_str())
    .bind(i64::from(limit.max(1)))
    .fetch_all(pool)
    .await?;
    rows.iter()
        .map(|row| {
            Ok(ActivityRow {
                seq: row.try_get("seq")?,
                kind: row.try_get("kind")?,
                text: row.try_get("text")?,
                severity: row.try_get("severity")?,
                created_at: instant(row.try_get("created_at_us")?)?,
            })
        })
        .collect()
}

/// The contract's `activity` array: no tenant, no source ref, ISO-8601 `at`.
pub fn wire(rows: &[ActivityRow]) -> Vec<Value> {
    rows.iter()
        .map(|row| {
            json!({
                "seq": row.seq,
                "at": iso8601(row.created_at),
                "kind": row.kind,
                "text": row.text,
                "severity": row.severity,
            })
        })
        .collect()
}

/// Python's `datetime.isoformat()` for a UTC instant: a `+00:00` offset and a six-digit
/// fraction only when the instant has one, exactly what the reference writes on the wire.
fn iso8601(instant: DateTime<Utc>) -> String {
    if instant.timestamp_subsec_micros() == 0 {
        instant.format("%Y-%m-%dT%H:%M:%S+00:00").to_string()
    } else {
        instant.format("%Y-%m-%dT%H:%M:%S%.6f+00:00").to_string()
    }
}
