//! Run activity feed: the progress rows and their writes.
//!
//! Ported from the reference `src/tasks/activity.py` (`record`, `recent`, `wire`). The feed is
//! advisory and append-only, and a write is best effort: the caller must never fail a poll or
//! an event because the feed could not be written. A write is deduplicated against the newest
//! row, so a driver that sees the same phase on many ticks records it once. `recent` returns
//! rows **newest-last** (ascending `seq`): the newest entry is the last row. That is the order
//! an operator reads a log in, and it makes a signal scan a plain walk of recent history.

use chrono::{DateTime, Utc};
use serde_json::{Value, json};
use sqlx::{PgPool, Row};

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::storage::executions::{ExecutionStoreError, instant};
use crate::tasks::severity_for;

/// Rows a task carries: enough for a progress panel, never unbounded.
pub const ACTIVITY_LIMIT: u32 = 50;

/// The `activity[].text` cap (matches the column check in the baseline migration).
pub const TEXT_LIMIT: usize = 512;

/// The `source_ref` cap (matches the column check in the baseline migration).
const SOURCE_REF_LIMIT: usize = 200;

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

/// The reference's `record`: append one activity row; returns its `seq`, or `None` when it was
/// not written.
///
/// It is not written when the newest row of the run already has the same kind, text and source
/// ref (a poll repeating a phase) or the run is unknown to this tenant. Concurrent writers may
/// both pass the dedupe check; a repeated feed line is harmless, a missing one is not.
pub async fn record(
    pool: &PgPool,
    tenant: &AuthorityId,
    run_id: &Uuid7,
    kind: &str,
    text: &str,
    severity: Option<&str>,
    source_ref: Option<&str>,
) -> Result<Option<i64>, sqlx::Error> {
    let collapsed = collapse(text);
    let body = if collapsed.is_empty() {
        kind.to_owned()
    } else {
        collapsed
    };
    let level = severity
        .filter(|severity| !severity.is_empty())
        .unwrap_or_else(|| severity_for(kind));
    let source: Option<String> = source_ref
        .filter(|source| !source.is_empty())
        .map(|source| source.chars().take(SOURCE_REF_LIMIT).collect());
    let seq: Option<i64> = sqlx::query_scalar(
        "INSERT INTO public.mcp_run_activity(tenant_id,run_id,kind,text,severity,source_ref) \
         SELECT $1::uuid,$2::uuid,$3,$4,$5,$6 \
         WHERE EXISTS(SELECT 1 FROM public.mcp_runs \
                      WHERE tenant_id = $7::uuid AND run_id = $8::uuid) \
         AND NOT EXISTS(SELECT 1 FROM public.mcp_run_activity \
                        WHERE run_id = $9::uuid \
                        AND seq = (SELECT max(seq) FROM public.mcp_run_activity \
                                   WHERE run_id = $10::uuid) \
                        AND kind = $11 AND text = $12 \
                        AND source_ref IS NOT DISTINCT FROM $13) \
         RETURNING seq",
    )
    .bind(tenant.as_str())
    .bind(run_id.as_str())
    .bind(kind)
    .bind(&body)
    .bind(level)
    .bind(source.as_deref())
    .bind(tenant.as_str())
    .bind(run_id.as_str())
    .bind(run_id.as_str())
    .bind(run_id.as_str())
    .bind(kind)
    .bind(&body)
    .bind(source.as_deref())
    .fetch_optional(pool)
    .await?;
    Ok(seq)
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

/// Python's `" ".join(str(text or "").split())` followed by `[:TEXT_LIMIT]`: every whitespace
/// run collapses to one space, then the body is capped by characters, exactly as the reference.
fn collapse(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .take(TEXT_LIMIT)
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
