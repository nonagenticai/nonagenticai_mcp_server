//! The tasks extension's wire projection: the pure run→task mapping (reference
//! `src/tasks/mapping.py`), the severity vocabulary and the advisory signals
//! (`src/tasks/severity.py`) and the fr activity block (`src/tasks/activity.py`).
//!
//! Everything here is a function of its arguments, plus one bounded feed read in [`fr_meta`].
//! `tests/fixtures/phase3a/oracle.json`, generated from the pinned reference, is the
//! specification for the two projections: the tests compare them field for field, which is why
//! the two shapes the reference writes verbatim are reproduced by hand — Python's
//! `datetime.isoformat()` (`+00:00`, six fractional digits only when nonzero) and Python's
//! `json.dumps` (`, ` / `: ` separators in the envelope's own key order) for a completed
//! task's `content[0].text`.
//!
//! `storage::run_activity` reads the feed without `source_ref`; the closed-approval rule needs
//! it, so this module carries the reference's `recent` query itself and reuses that module's
//! `wire` for the contract's array.

use std::io;

use chrono::{DateTime, SecondsFormat, Utc};
use serde::Serialize as _;
use serde_json::{Map, Value, json};
use sqlx::{PgPool, Row};

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::models::Runtime;
use crate::config::ExecutionSettings;
use crate::execution::{RunRow, RunStatus, envelope};
use crate::storage::executions::{ExecutionStoreError, corrupt, instant};
use crate::storage::run_activity::{self, ActivityRow};
use crate::storage::task_inputs::TaskInputRow;

/// The `_meta` key an fr run's project, activity and signals travel under. rmcp drops unknown
/// TOP-LEVEL task fields, so nothing fr-specific may be one.
pub const FR_META_KEY: &str = "ai.nonagentic/fr";

/// Every severity an activity entry or a signal may name.
pub const SEVERITIES: [&str; 5] = ["info", "low", "medium", "high", "critical"];

/// Activity kind and signal code → severity. A kind the platform does not know is `info`: a new
/// feed entry must never be presented as alarming by an older server.
pub const SEVERITY: [(&str, &str); 11] = [
    ("started", "low"),
    ("phase", "low"),
    ("approval_requested", "high"),
    ("approval_closed", "info"),
    ("refused", "medium"),
    ("failed", "critical"),
    ("delivered", "info"),
    ("approval_waiting", "high"),
    ("phase_stalled", "medium"),
    ("project_failed", "critical"),
    ("start_refused", "critical"),
];

/// The severity of a kind the platform does not know.
pub const DEFAULT_SEVERITY: &str = "info";

/// `signals[].detail` on the wire.
pub const DETAIL_LIMIT: usize = 200;

/// Run statuses whose work may still move; wait and stall signals make no sense when it cannot.
pub const ACTIVE_STATUSES: [&str; 4] = ["queued", "starting", "running", "cancelling"];

/// Terminal failure kinds. `interrupted` is a terminal failure whose outcome is unknown — the
/// most ambiguous one, so it must never be the silent one.
pub const FAILED_STATUSES: [&str; 3] = ["failed", "timed_out", "interrupted"];

/// `external_ref.start_outcome` values that mean fr never created the project.
pub const START_REFUSED_OUTCOMES: [&str; 3] = ["rejected", "voided", "expired"];

/// Kinds that report progress of the project itself, for `phase_stalled`.
pub const PROGRESS_KINDS: [&str; 2] = ["phase", "started"];

/// Rows `tasks/get` carries: enough for a progress panel, never unbounded.
pub const ACTIVITY_LIMIT: u32 = 50;

/// Rows the SIGNALS look at. Deliberately wider than the wire: a stall or a waiting approval is
/// usually the oldest thing in the feed, and a busy project's rows hide it.
pub const ACTIVITY_SIGNAL_WINDOW: u32 = 500;

/// Milliseconds in one day, the retention TTL's unit.
const MS_PER_DAY: u64 = 86_400_000;

/// One `mcp_run_activity` row as the feed reads it, `source_ref` included: the closed-approval
/// rule needs it and the contract never puts it on the wire.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeedRow {
    /// The run-scoped ascending sequence.
    pub seq: i64,
    /// The phase kind (`phase`, `started`, `approval_requested`, …).
    pub kind: String,
    /// The rendered line.
    pub text: String,
    /// The entry's severity.
    pub severity: String,
    /// The upstream record the entry is about.
    pub source_ref: Option<String>,
    /// When it was appended.
    pub created_at: DateTime<Utc>,
}

impl FeedRow {
    /// The row as the wire contract's reader sees it (`storage::run_activity::ActivityRow`).
    fn activity(&self) -> ActivityRow {
        ActivityRow {
            seq: self.seq,
            kind: self.kind.clone(),
            text: self.text.clone(),
            severity: self.severity.clone(),
            created_at: self.created_at,
        }
    }
}

// ── the mapping (`src/tasks/mapping.py`) ──────────────────────────────────────────────────

/// The task status one run reports, given how many of its inputs are still open.
pub fn task_status(row: &RunRow, open_inputs: usize) -> &'static str {
    match row.status {
        // A pending cancel wins over open inputs.
        RunStatus::Queued | RunStatus::Starting | RunStatus::Running => {
            if open_inputs > 0 {
                "input_required"
            } else {
                "working"
            }
        }
        RunStatus::Cancelling => "working",
        RunStatus::Cancelled => "cancelled",
        // Succeeded, and every failure kind (a failed run is JSON-RPC-only).
        RunStatus::Succeeded | RunStatus::Failed | RunStatus::TimedOut | RunStatus::Interrupted => {
            "completed"
        }
    }
}

/// Open inputs that have not expired; an expired approval is not a question any more.
pub fn open_inputs(inputs: &[TaskInputRow], now: DateTime<Utc>) -> Vec<&TaskInputRow> {
    inputs
        .iter()
        .filter(|input| {
            input.state == "open" && input.expires_at.is_none_or(|expires_at| expires_at > now)
        })
        .collect()
}

/// The newest stamp on the run or on any of its inputs.
pub fn last_updated(row: &RunRow, inputs: &[TaskInputRow]) -> DateTime<Utc> {
    let mut latest = row.created_at;
    for stamp in [row.finished_at, row.started_at].into_iter().flatten() {
        latest = latest.max(stamp);
    }
    for input in inputs {
        latest = latest.max(input.created_at);
        if let Some(answered_at) = input.answered_at {
            latest = latest.max(answered_at);
        }
    }
    latest
}

/// The poll hint a task returns: the task interval for a Kata run, the external one otherwise.
pub fn poll_interval_ms(row: &RunRow, settings: &ExecutionSettings) -> u64 {
    if row.runtime == Runtime::KataPython {
        settings.task_poll_interval_ms
    } else {
        (settings.external_poll_seconds * 1000.0) as u64
    }
}

/// The base task fields every view carries.
pub fn task_fields(
    row: &RunRow,
    inputs: &[TaskInputRow],
    settings: &ExecutionSettings,
    now: DateTime<Utc>,
) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("taskId".to_owned(), json!(row.run_id.to_string()));
    fields.insert(
        "status".to_owned(),
        json!(task_status(row, open_inputs(inputs, now).len())),
    );
    fields.insert("createdAt".to_owned(), json!(iso8601(row.created_at)));
    fields.insert(
        "lastUpdatedAt".to_owned(),
        json!(iso8601(last_updated(row, inputs))),
    );
    fields.insert(
        "ttlMs".to_owned(),
        json!(settings.retention_days.saturating_mul(MS_PER_DAY)),
    );
    fields.insert(
        "pollIntervalMs".to_owned(),
        json!(poll_interval_ms(row, settings)),
    );
    if let Some(message) = row.status_message.as_deref().filter(|m| !m.is_empty()) {
        fields.insert("statusMessage".to_owned(), json!(message));
    }
    fields
}

/// The `tasks/get` view: the base fields plus `resultType`, and the outstanding questions or
/// the final result, with the fr block under `_meta`.
pub fn task_view(
    row: &RunRow,
    inputs: &[TaskInputRow],
    settings: &ExecutionSettings,
    fr_meta: Option<&Value>,
    now: DateTime<Utc>,
) -> Value {
    let open = open_inputs(inputs, now);
    let status = task_status(row, open.len());
    let mut fields = task_fields(row, inputs, settings, now);
    fields.insert("resultType".to_owned(), json!("complete"));
    if status == "input_required" {
        let mut requests = Map::new();
        for input in open {
            requests.insert(input.input_key.clone(), input.request.clone());
        }
        fields.insert("inputRequests".to_owned(), Value::Object(requests));
    } else if status == "completed" {
        fields.insert("result".to_owned(), task_result(row));
    }
    attach_meta(fields, fr_meta)
}

/// The `tools/call` task handle: the base fields with `resultType: "task"` and no inputs.
pub fn create_task_result(
    row: &RunRow,
    settings: &ExecutionSettings,
    fr_meta: Option<&Value>,
) -> Value {
    let mut fields = task_fields(row, &[], settings, Utc::now());
    fields.insert("resultType".to_owned(), json!("task"));
    attach_meta(fields, fr_meta)
}

/// The `CallToolResult` shaping a completed task carries: the envelope as text and as the
/// structured value, with `isError` for the failure kinds.
pub fn task_result(row: &RunRow) -> Value {
    let body = envelope(row);
    json!({
        "content": [{"type": "text", "text": envelope_text(&body)}],
        "structuredContent": body,
        "isError": FAILED_STATUSES.contains(&row.status.as_str()),
    })
}

/// The fr block rides under `_meta`; a non-fr run carries none.
fn attach_meta(mut fields: Map<String, Value>, fr_meta: Option<&Value>) -> Value {
    if let Some(block) = fr_meta {
        let mut meta = Map::new();
        meta.insert(FR_META_KEY.to_owned(), block.clone());
        fields.insert("_meta".to_owned(), Value::Object(meta));
    }
    Value::Object(fields)
}

/// `json.dumps(envelope, ensure_ascii=False, allow_nan=False)` in the reference's key order —
/// the text a client reads, byte for byte.
pub(crate) fn envelope_text(body: &Value) -> String {
    let mut out = String::from("{\"run_id\": ");
    out.push_str(&python_json(&body["run_id"]));
    out.push_str(", \"status\": ");
    out.push_str(&python_json(&body["status"]));
    out.push_str(", \"result\": ");
    out.push_str(&python_json(&body["result"]));
    out.push_str(", \"error\": ");
    out.push_str(&python_json(&body["error"]));
    out.push_str(", \"payload_expired\": ");
    out.push_str(&python_json(&body["payload_expired"]));
    out.push('}');
    out
}

/// One JSON value with Python's `json.dumps` separators (`", "` between items, `": "` after a
/// key). `serde_json`'s compact writer produces neither, and the text is compared verbatim.
fn python_json(value: &Value) -> String {
    /// `json.dumps`' default separators.
    struct Python;

    impl serde_json::ser::Formatter for Python {
        fn begin_array_value<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
        where
            W: ?Sized + io::Write,
        {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }

        fn begin_object_key<W>(&mut self, writer: &mut W, first: bool) -> io::Result<()>
        where
            W: ?Sized + io::Write,
        {
            if first {
                Ok(())
            } else {
                writer.write_all(b", ")
            }
        }

        fn begin_object_value<W>(&mut self, writer: &mut W) -> io::Result<()>
        where
            W: ?Sized + io::Write,
        {
            writer.write_all(b": ")
        }

        /// Python's `repr(float)` (`1e+16`, `1e-05`), not serde's (`1e16`, `1e-5`).
        fn write_f64<W>(&mut self, writer: &mut W, value: f64) -> io::Result<()>
        where
            W: ?Sized + io::Write,
        {
            writer.write_all(crate::execution::python_float_repr(value).as_bytes())
        }
    }

    let mut out = Vec::new();
    let mut serializer = serde_json::Serializer::with_formatter(&mut out, Python);
    if value.serialize(&mut serializer).is_err() {
        return String::new();
    }
    String::from_utf8(out).unwrap_or_default()
}

/// Python's `datetime.isoformat()` for a UTC instant: a `+00:00` offset and six fractional
/// digits only when the instant carries sub-second precision.
pub(crate) fn iso8601(at: DateTime<Utc>) -> String {
    let format = if at.timestamp_subsec_micros() == 0 {
        SecondsFormat::Secs
    } else {
        SecondsFormat::Micros
    };
    at.to_rfc3339_opts(format, false)
}

// ── the severity vocabulary and its signals (`src/tasks/severity.py`) ─────────────────────

/// The severity of one activity kind or signal code.
pub fn severity_for(kind: &str) -> &'static str {
    SEVERITY
        .iter()
        .find(|(code, _)| *code == kind)
        .map_or(DEFAULT_SEVERITY, |(_, severity)| *severity)
}

/// The advisory signals for one run, in a stable order (most severe first).
///
/// `activity` are feed rows, newest last; `now` is the read time, so tests and a clock-skewed
/// poller see the same rule.
pub fn signals(
    row: &RunRow,
    activity: &[FeedRow],
    settings: &ExecutionSettings,
    now: DateTime<Utc>,
) -> Vec<Value> {
    let status = row.status.as_str();
    let mut found = Vec::new();
    if FAILED_STATUSES.contains(&status) {
        let detail = text(row.error.as_ref().and_then(|error| error.get("code")))
            .or_else(|| row.status_message.as_deref().filter(|m| !m.is_empty()))
            .unwrap_or("the run failed");
        found.push(signal("project_failed", detail));
    }
    let outcome = text(
        row.external_ref
            .as_ref()
            .and_then(|r| r.get("start_outcome")),
    )
    .filter(|outcome| START_REFUSED_OUTCOMES.contains(outcome));
    if let Some(outcome) = outcome {
        found.push(signal(
            "start_refused",
            &format!("the project start was {outcome}"),
        ));
    }
    if ACTIVE_STATUSES.contains(&status) {
        if let Some(waiting) = waiting_approval(activity) {
            let age = age_seconds(now, waiting.created_at);
            if age >= settings.fr_approval_wait_seconds as f64 {
                found.push(signal(
                    "approval_waiting",
                    &format!("an approval has waited {}", minutes(age)),
                ));
            }
        }
        if let Some(progress) = last_progress(activity) {
            let age = age_seconds(now, progress.created_at);
            if age >= settings.fr_phase_stall_seconds as f64 {
                found.push(signal(
                    "phase_stalled",
                    &format!("no progress for {}", minutes(age)),
                ));
            }
        }
    }
    found
}

/// The newest `approval_requested` that no `approval_closed` for the same ref followed.
fn waiting_approval(activity: &[FeedRow]) -> Option<&FeedRow> {
    let closed: Vec<Option<&str>> = activity
        .iter()
        .filter(|row| row.kind == "approval_closed")
        .map(|row| row.source_ref.as_deref())
        .collect();
    activity.iter().rev().find(|row| {
        row.kind == "approval_requested" && !closed.contains(&row.source_ref.as_deref())
    })
}

/// The newest entry that reports progress of the project itself.
fn last_progress(activity: &[FeedRow]) -> Option<&FeedRow> {
    activity
        .iter()
        .rev()
        .find(|row| PROGRESS_KINDS.contains(&row.kind.as_str()))
}

/// One signal in the contract's shape.
fn signal(code: &str, detail: &str) -> Value {
    json!({"code": code, "severity": severity_for(code), "detail": detail_text(detail)})
}

/// `" ".join(text.split())[:200] or "signal"`.
fn detail_text(text: &str) -> String {
    let collapsed = text.split_whitespace().collect::<Vec<_>>().join(" ");
    let detail: String = collapsed.chars().take(DETAIL_LIMIT).collect();
    if detail.is_empty() {
        "signal".to_owned()
    } else {
        detail
    }
}

/// The age of one stamp, in (possibly fractional) seconds.
fn age_seconds(now: DateTime<Utc>, at: DateTime<Utc>) -> f64 {
    (now - at)
        .num_microseconds()
        .map_or(f64::MAX, |micros| micros as f64 / 1_000_000.0)
}

/// `f"{max(0, int(seconds // 60))} min"`.
fn minutes(seconds: f64) -> String {
    format!("{} min", (seconds / 60.0).floor().max(0.0) as i64)
}

/// A JSON string value, unless it is absent or empty (`x or y` in the reference).
fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

// ── the activity feed (`src/tasks/activity.py`) ───────────────────────────────────────────

/// The newest `limit` rows of the run, NEWEST-LAST (ascending `seq`).
pub async fn feed(
    pool: &PgPool,
    tenant: &AuthorityId,
    run_id: &Uuid7,
    limit: u32,
) -> Result<Vec<FeedRow>, ExecutionStoreError> {
    let rows = sqlx::query(
        "SELECT seq, kind, text, severity, source_ref, \
         (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us \
         FROM (SELECT seq, kind, text, severity, source_ref, created_at \
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
            Ok(FeedRow {
                seq: row.try_get("seq")?,
                kind: row.try_get("kind")?,
                text: row.try_get("text")?,
                severity: row.try_get("severity")?,
                source_ref: row.try_get("source_ref")?,
                created_at: instant(row.try_get("created_at_us")?)?,
            })
        })
        .collect()
}

/// The `ai.nonagentic/fr` block of one run, or `None` when the run is not an fr project.
///
/// `project_id` is always present (null until fr reports it): the client must be able to tell
/// "not known yet" from "no such field". Signals are not bounded by the wire's window; only a
/// full first page can hide older rows, so the wider read is skipped otherwise.
pub async fn fr_meta(
    pool: &PgPool,
    tenant: &AuthorityId,
    row: &RunRow,
    settings: &ExecutionSettings,
    now: DateTime<Utc>,
) -> Result<Option<Value>, ExecutionStoreError> {
    if row.runtime != Runtime::FrProject {
        return Ok(None);
    }
    let run_id = Uuid7::new(row.run_id.to_string()).map_err(|_| corrupt("task run identity"))?;
    let rows = feed(pool, tenant, &run_id, ACTIVITY_LIMIT).await?;
    let history = if rows.len() >= ACTIVITY_LIMIT as usize {
        feed(pool, tenant, &run_id, ACTIVITY_SIGNAL_WINDOW).await?
    } else {
        rows.clone()
    };
    let project_id = row
        .external_ref
        .as_ref()
        .and_then(|reference| reference.get("project_id"))
        .cloned()
        .unwrap_or(Value::Null);
    let activity = run_activity::wire(&rows.iter().map(FeedRow::activity).collect::<Vec<_>>());
    Ok(Some(json!({
        "project_id": project_id,
        "activity": activity,
        "signals": signals(row, &history, settings, now),
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// The text a client reads must be `json.dumps` exactly, floats included: serde's own
    /// writer spells `1e16` and Python spells `1e+16`.
    #[test]
    fn the_python_json_writer_matches_json_dumps() {
        assert_eq!(
            python_json(&json!({"a": 1, "b": [1.5, 1e16, 1e-5], "c": "x"})),
            "{\"a\": 1, \"b\": [1.5, 1e+16, 1e-05], \"c\": \"x\"}"
        );
    }

    /// Python's `datetime.isoformat()`: a whole second carries no fractional part, anything
    /// finer carries six digits.
    #[test]
    fn iso8601_matches_python_isoformat() {
        let whole = DateTime::parse_from_rfc3339("2026-11-14T12:00:00Z")
            .expect("an instant")
            .with_timezone(&Utc);
        let micros = DateTime::parse_from_rfc3339("2026-11-14T12:00:00.123000Z")
            .expect("an instant")
            .with_timezone(&Utc);
        assert_eq!(iso8601(whole), "2026-11-14T12:00:00+00:00");
        assert_eq!(iso8601(micros), "2026-11-14T12:00:00.123000+00:00");
    }
}
