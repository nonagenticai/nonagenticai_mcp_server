//! One `mcp_tool_call_audit` row per builtin tool call.
//!
//! Ported from the reference `src/builtin/audit.py`. Same semantics: every way out of the tool
//! that is not a return is a failure; a call refused by scope is `denied`; a success is
//! `success`. The row carries the reference's columns and truncation rules — the tool name,
//! principal subject and tenant are cut to their column bounds by CHARACTERS (Python slicing),
//! and the error text to [`MAX_ERROR_CHARS`].
//!
//! The write runs as its own task, bounded by [`AUDIT_WRITE_TIMEOUT`], so a slow database can
//! neither hold the tool response past the executor's budget nor fail the tool call. Once
//! started, the write survives the caller dropping the provider's future. One reference
//! behaviour this port cannot reproduce: a call cancelled INSIDE its handler (a dropped Rust
//! future) records no row, because there is no `finally` to run.
//!
//! An audit failure is logged and swallowed: it never fails the tool call. The log names the
//! tool only — never the arguments, the result or the details — because a call may carry
//! personal data.
//!
//! Table: `public.mcp_tool_call_audit` (baseline migration; runtime role: INSERT only).

use std::error::Error;
use std::sync::Arc;
use std::time::Duration;

use serde_json::{Map, Value};
use sqlx::PgPool;

use crate::auth::BoxFuture;

use super::scope::BuiltinCaller;

/// The reference's bound on one audit write.
pub const AUDIT_WRITE_TIMEOUT: Duration = Duration::from_millis(500);
/// The reference's cap on the stored error text.
pub const MAX_ERROR_CHARS: usize = 2000;
/// The `tool` column's bound.
const MAX_TOOL_CHARS: usize = 256;
/// The `principal` column's bound.
const MAX_PRINCIPAL_CHARS: usize = 256;
/// The `tenant_id` column's bound.
const MAX_TENANT_CHARS: usize = 256;

/// One failed audit write; the caller of [`record`] never sees it.
pub type AuditError = Box<dyn Error + Send + Sync>;

/// One sink write as an object-safe future.
pub type AuditFuture<'a> = BoxFuture<'a, Result<(), AuditError>>;

/// The audit destination. The reference's `AuditSink`; a test may record rows in memory.
pub trait AuditSink: Send + Sync {
    /// Write one row. `details` is the reference's JSON document, already bounded.
    fn write<'a>(
        &'a self,
        caller: &'a BuiltinCaller,
        tool: &'a str,
        status: &'a str,
        details: &'a Value,
    ) -> AuditFuture<'a>;
}

/// Inserts into `public.mcp_tool_call_audit` through the service pool.
#[derive(Debug, Clone)]
pub struct DatabaseAuditSink {
    pool: PgPool,
}

impl DatabaseAuditSink {
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl AuditSink for DatabaseAuditSink {
    fn write<'a>(
        &'a self,
        caller: &'a BuiltinCaller,
        tool: &'a str,
        status: &'a str,
        details: &'a Value,
    ) -> AuditFuture<'a> {
        Box::pin(async move {
            // The reference binds `int(details["latency_ms"])`; `record` already clamped it.
            let latency = details
                .get("latency_ms")
                .and_then(Value::as_i64)
                .unwrap_or(0);
            let latency_ms = i32::try_from(latency.max(0)).unwrap_or(i32::MAX);
            sqlx::query(
                "INSERT INTO public.mcp_tool_call_audit \
                 (tool,status,principal_kind,auth_method,principal,tenant_id,latency_ms,details) \
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8::jsonb)",
            )
            .bind(truncate(tool, MAX_TOOL_CHARS))
            .bind(status)
            .bind(caller.kind.as_str())
            .bind(caller.kind.auth_method())
            .bind(truncate(&caller.subject, MAX_PRINCIPAL_CHARS))
            .bind(
                caller
                    .tenant_id
                    .as_deref()
                    // Python's `if principal.tenant_id`: the empty string is absent.
                    .filter(|tenant| !tenant.is_empty())
                    .map(|tenant| truncate(tenant, MAX_TENANT_CHARS)),
            )
            .bind(latency_ms)
            .bind(details.clone())
            .execute(&self.pool)
            .await
            .map(|_| ())
            .map_err(|error| -> AuditError { Box::new(error) })
        })
    }
}

/// Write one row, bounded and shielded, never raising.
///
/// `latency_ms` is the elapsed call time except for a scope refusal, which the reference
/// records as `0`. `error` is the original caller-visible text, stored unchanged (truncated to
/// [`MAX_ERROR_CHARS`]).
pub async fn record(
    sink: Option<Arc<dyn AuditSink>>,
    caller: &BuiltinCaller,
    tool: &str,
    latency_ms: i64,
    error: Option<&str>,
    cancelled: bool,
    denied: bool,
) {
    let Some(sink) = sink else {
        return;
    };
    let failed = error.is_some() || cancelled || denied;
    let mut details = Map::new();
    details.insert("tool".to_owned(), Value::String(tool.to_owned()));
    details.insert("latency_ms".to_owned(), Value::from(latency_ms.max(0)));
    details.insert("ok".to_owned(), Value::Bool(!failed));
    details.insert(
        "error".to_owned(),
        error
            .map(|error| Value::String(truncate(error, MAX_ERROR_CHARS)))
            .unwrap_or(Value::Null),
    );
    details.insert(
        "auth_method".to_owned(),
        Value::String(caller.kind.auth_method().to_owned()),
    );
    details.insert(
        "principal".to_owned(),
        Value::String(caller.subject.clone()),
    );
    if let Some(tenant) = caller
        .tenant_id
        .as_deref()
        .filter(|tenant| !tenant.is_empty())
    {
        details.insert("tenant_id".to_owned(), Value::String(tenant.to_owned()));
    }
    if cancelled {
        details.insert("cancelled".to_owned(), Value::Bool(true));
    }
    if denied {
        details.insert("denied".to_owned(), Value::Bool(true));
    }
    let status = if denied {
        "denied"
    } else if failed {
        "failure"
    } else {
        "success"
    };

    // Its own task: a dropped caller still gets the row, exactly the reference's shield.
    let tool = tool.to_owned();
    let caller = caller.clone();
    let details = Value::Object(details);
    let task = tokio::spawn(async move {
        let write = sink.write(&caller, &tool, status, &details);
        match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => tracing::warn!(tool = %tool, "audit write failed: {error}"),
            Err(_) => tracing::warn!(
                tool = %tool,
                "audit write timed out after {AUDIT_WRITE_TIMEOUT:?}"
            ),
        }
    });
    let _ = task.await;
}

/// Python's `value[:max]`: a CHARACTER slice, never a byte slice.
fn truncate(value: &str, max: usize) -> String {
    value.chars().take(max).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncation_counts_characters_not_bytes() {
        let value = "é".repeat(300);
        assert_eq!(truncate(&value, 256).chars().count(), 256);
        assert_eq!(truncate("short", 256), "short");
    }
}
