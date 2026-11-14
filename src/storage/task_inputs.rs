//! Durable inputs a task is waiting on (approvals surfaced as MCP task input requests).
//!
//! Ported from the reference `src/storage/task_inputs.py` (`open_for`, `answer` and the
//! rejection-hint helpers). The answer rules are the reference's exactly: unknown or non-open
//! keys and malformed responses are ignored; a rejection without a non-blank reason leaves its
//! input open and sets the run's status message; a valid answer clears a stale hint.

use chrono::{DateTime, Utc};
use serde_json::{Map, Value};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::execution::RunStatus;
use crate::storage::executions::{ExecutionStoreError, corrupt, instant, optional_instant};

/// The actions a task input response may carry.
pub const ACTIONS: [&str; 3] = ["accept", "decline", "cancel"];

/// The message set when an `accept` rejects without a reason; it stands until a valid answer.
pub const REASON_REQUIRED: &str = "reason required";

/// Prefix of the message set when an upstream refuses a forwarded answer.
pub const REFUSED_PREFIX: &str = "fr refused the answer: ";

/// Whether a run's status message tells the client to answer again; it stands until a valid
/// answer clears it.
pub fn is_hint(message: &str) -> bool {
    message == REASON_REQUIRED || message.starts_with(REFUSED_PREFIX)
}

/// One `mcp_task_inputs` row.
#[derive(Debug, Clone)]
pub struct TaskInputRow {
    /// The input's identity (unique across runs).
    pub input_key: String,
    /// The tenant that owns the run.
    pub tenant_id: AuthorityId,
    /// The run the input belongs to.
    pub run_id: Uuid7,
    /// The upstream record the input surfaces.
    pub source_ref: String,
    /// The request object served to the client.
    pub request: Value,
    /// `open`, `answered`, `forwarded` or `closed`.
    pub state: String,
    /// The client's response, once answered.
    pub response: Option<Value>,
    /// Who answered.
    pub actor: Option<Value>,
    /// When the input was opened.
    pub created_at: DateTime<Utc>,
    /// When it was answered.
    pub answered_at: Option<DateTime<Utc>>,
    /// When it was closed without an answer.
    pub closed_at: Option<DateTime<Utc>>,
    /// The upstream approval's expiry.
    pub expires_at: Option<DateTime<Utc>>,
}

/// The task input store: every call names its tenant, exactly as the reference.
#[derive(Debug, Clone)]
pub struct TaskInputRepository {
    pool: PgPool,
}

impl TaskInputRepository {
    /// Bind the repository to a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// The reference's `open_for`: every input row of the run in any state; callers filter.
    pub async fn open_for(
        &self,
        tenant: &AuthorityId,
        run_id: &Uuid7,
    ) -> Result<Vec<TaskInputRow>, ExecutionStoreError> {
        let rows = sqlx::query(
            "SELECT input_key, tenant_id::text AS tenant_id, run_id::text AS run_id, source_ref, \
             request, state, response, actor, \
             (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us, \
             (extract(epoch FROM answered_at) * 1000000)::bigint AS answered_at_us, \
             (extract(epoch FROM closed_at) * 1000000)::bigint AS closed_at_us, \
             (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_us \
             FROM public.mcp_task_inputs \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid \
             ORDER BY created_at, input_key",
        )
        .bind(tenant.as_str())
        .bind(run_id.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(decode_input).collect()
    }

    /// The reference's `answer`: record valid responses for open inputs; returns how many were
    /// answered.
    ///
    /// Unknown or non-open keys and malformed responses are ignored. A rejection without a
    /// reason leaves its input open and sets the run's status message.
    pub async fn answer(
        &self,
        tenant: &AuthorityId,
        run_id: &Uuid7,
        responses: &Map<String, Value>,
        actor: &Value,
    ) -> Result<u64, ExecutionStoreError> {
        let mut tx = self.pool.begin().await?;
        let run: Option<(String, Option<String>)> = sqlx::query_as(
            "SELECT status, status_message FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(run_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let Some((status, status_message)) = run else {
            return Ok(0);
        };
        let status = RunStatus::parse(&status).ok_or_else(|| corrupt("run status"))?;
        if status.is_terminal() {
            return Ok(0);
        }

        let open_keys: Vec<String> = sqlx::query_scalar(
            "SELECT input_key FROM public.mcp_task_inputs \
             WHERE run_id = $1::uuid AND tenant_id = $2::uuid AND state = 'open' \
             ORDER BY input_key FOR UPDATE",
        )
        .bind(run_id.as_str())
        .bind(tenant.as_str())
        .fetch_all(&mut *tx)
        .await?;

        let mut answered: u64 = 0;
        let mut needs_reason = false;
        for (key, value) in responses {
            if !open_keys.contains(key) {
                continue;
            }
            let Value::Object(response) = value else {
                continue;
            };
            let action = response.get("action").and_then(Value::as_str);
            if !action.is_some_and(|action| ACTIONS.contains(&action)) {
                continue;
            }
            if rejected_without_reason(response) {
                needs_reason = true;
                continue;
            }
            sqlx::query(
                "UPDATE public.mcp_task_inputs \
                 SET state = 'answered', response = $1, actor = $2, answered_at = now() \
                 WHERE input_key = $3 AND state = 'open'",
            )
            .bind(value.clone())
            .bind(actor.clone())
            .bind(key.as_str())
            .execute(&mut *tx)
            .await?;
            answered += 1;
        }

        if needs_reason {
            sqlx::query(
                "UPDATE public.mcp_runs SET status_message = $1 \
                 WHERE tenant_id = $2::uuid AND run_id = $3::uuid",
            )
            .bind(REASON_REQUIRED)
            .bind(tenant.as_str())
            .bind(run_id.as_str())
            .execute(&mut *tx)
            .await?;
        } else if answered > 0 && status_message.as_deref().is_some_and(is_hint) {
            sqlx::query(
                "UPDATE public.mcp_runs SET status_message = NULL \
                 WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
            )
            .bind(tenant.as_str())
            .bind(run_id.as_str())
            .execute(&mut *tx)
            .await?;
        }
        tx.commit().await?;
        Ok(answered)
    }
}

/// The reference's `rejected_without_reason`: an `accept` whose content rejects without a
/// non-blank reason.
fn rejected_without_reason(response: &Map<String, Value>) -> bool {
    if response.get("action").and_then(Value::as_str) != Some("accept") {
        return false;
    }
    let Some(Value::Object(content)) = response.get("content") else {
        return false;
    };
    if content.get("decision").and_then(Value::as_str) != Some("rejected") {
        return false;
    }
    !content
        .get("reason")
        .and_then(Value::as_str)
        .is_some_and(|reason| !reason.trim().is_empty())
}

fn decode_input(row: &PgRow) -> Result<TaskInputRow, ExecutionStoreError> {
    Ok(TaskInputRow {
        input_key: row.try_get("input_key")?,
        tenant_id: AuthorityId::new(row.try_get::<String, _>("tenant_id")?)
            .map_err(|_| corrupt("task input tenant"))?,
        run_id: Uuid7::new(row.try_get::<String, _>("run_id")?)
            .map_err(|_| corrupt("task input run"))?,
        source_ref: row.try_get("source_ref")?,
        request: row.try_get("request")?,
        state: row.try_get("state")?,
        response: row.try_get("response")?,
        actor: row.try_get("actor")?,
        created_at: instant(row.try_get("created_at_us")?)?,
        answered_at: optional_instant(row.try_get("answered_at_us")?)?,
        closed_at: optional_instant(row.try_get("closed_at_us")?)?,
        expires_at: optional_instant(row.try_get("expires_at_us")?)?,
    })
}
