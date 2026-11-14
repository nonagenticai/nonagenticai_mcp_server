//! The pure execution domain: the `mcp_runs` row shape, its public envelope, the canonical
//! JSON hash the worker compares, the stored authority snapshot and the caller attribution.
//!
//! Ported from the reference service's `src/execution/models.py`, `src/storage/executions.py`,
//! `src/tasks/extension.py` and `src/auth/principal.py`. Everything here is a pure function of
//! its arguments; the queue, the repository and the protocol surface are later slices.
//!
//! Wire compatibility is the point. The Python worker reads the stored `authority` column with
//! `ToolManifest.model_validate_json` and friends, so each member is that model's own JSON
//! *string* and must carry the reference's content (key order is not part of the contract; a
//! parsed-value comparison is). `input_hash` is the reference's canonical JSON digest and must
//! match exactly — the worker compares it to decide an idempotent replay. Both are pinned by
//! `tests/fixtures/phase3a/oracle.json`, generated from the pinned reference.

pub mod service;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use crate::auth::Principal;
use crate::auth::uuid::Rfc4122Uuid;
use crate::catalog::models::Runtime;
use crate::catalog::resolver::ResolvedTool;

/// The `_meta` key a caller uses to name itself.
pub const ACTOR_META_KEY: &str = "ai.nonagentic/actor";

/// One `mcp_runs.status` value, exactly the DDL's `mcp_runs_status_check` set.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunStatus {
    /// Accepted, waiting for a worker.
    Queued,
    /// A worker claimed the run.
    Starting,
    /// The runner is executing.
    Running,
    /// A cancel was requested and the run is winding down.
    Cancelling,
    /// Finished successfully.
    Succeeded,
    /// Finished with an error.
    Failed,
    /// Cancelled before completion.
    Cancelled,
    /// Exceeded its deadline.
    TimedOut,
    /// The worker died; the run's outcome is unknown.
    Interrupted,
}

impl RunStatus {
    /// Every status the DDL accepts, in the DDL's order.
    pub const ALL: [Self; 9] = [
        Self::Queued,
        Self::Starting,
        Self::Running,
        Self::Cancelling,
        Self::Succeeded,
        Self::Failed,
        Self::Cancelled,
        Self::TimedOut,
        Self::Interrupted,
    ];

    /// The status's stored text.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Starting => "starting",
            Self::Running => "running",
            Self::Cancelling => "cancelling",
            Self::Succeeded => "succeeded",
            Self::Failed => "failed",
            Self::Cancelled => "cancelled",
            Self::TimedOut => "timed_out",
            Self::Interrupted => "interrupted",
        }
    }

    /// Parse a stored status; anything outside the DDL's set is `None`.
    pub fn parse(value: &str) -> Option<Self> {
        Some(match value {
            "queued" => Self::Queued,
            "starting" => Self::Starting,
            "running" => Self::Running,
            "cancelling" => Self::Cancelling,
            "succeeded" => Self::Succeeded,
            "failed" => Self::Failed,
            "cancelled" => Self::Cancelled,
            "timed_out" => Self::TimedOut,
            "interrupted" => Self::Interrupted,
            _ => return None,
        })
    }

    /// No further transition is possible; the reference's `TERMINAL`.
    pub const fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::Succeeded | Self::Failed | Self::Cancelled | Self::TimedOut | Self::Interrupted
        )
    }
}

/// One `mcp_runs` row: the columns the execution API reads.
///
/// Plain struct by design. This crate's sqlx has neither the `chrono` nor the `uuid` feature
/// (the storage layer reads instants as epoch microseconds and identities as text — see
/// `src/storage/bindings.rs`), so no `sqlx::FromRow` derive would compile here; the storage
/// slice constructs this row with a hand-written decoder, exactly as the other repositories do.
#[derive(Debug, Clone)]
pub struct RunRow {
    /// The run's UUIDv7 identity.
    pub run_id: Rfc4122Uuid,
    /// The calling tenant.
    pub tenant_id: Rfc4122Uuid,
    /// The licence that authorised the run.
    pub gateway_license_id: Rfc4122Uuid,
    /// The tool's owning tenant (the platform tenant for platform tools).
    pub owner_tenant_id: Rfc4122Uuid,
    /// The exact tool version.
    pub tool_id: Rfc4122Uuid,
    /// The binding the run was made through; absent for a draft run.
    pub binding_id: Option<Rfc4122Uuid>,
    /// The binding's revision at submission.
    pub binding_revision: Option<i64>,
    /// The credential profile the runtime resolves service credentials from.
    pub credential_profile_id: Option<Rfc4122Uuid>,
    /// The credential profile's manifest at submission.
    pub profile_snapshot: Value,
    /// The tool's version.
    pub tool_version: i32,
    /// `{"manifest","effective","context"}` as resolved at submission.
    pub authority: Value,
    /// The caller's input arguments.
    pub inputs: Value,
    /// SHA-256 of the canonical input arguments.
    pub input_hash: String,
    /// The caller's idempotency key, when one was supplied.
    pub idempotency_key: Option<String>,
    /// Who submitted the run.
    pub created_by: Value,
    /// The run's state.
    pub status: RunStatus,
    /// When the run was accepted.
    pub created_at: DateTime<Utc>,
    /// By when a worker must have claimed it.
    pub queue_deadline: DateTime<Utc>,
    /// When a worker claimed it.
    pub started_at: Option<DateTime<Utc>>,
    /// When it reached a terminal state.
    pub finished_at: Option<DateTime<Utc>>,
    /// Whether a cancel was asked for.
    pub cancel_requested: bool,
    /// The stored result, when there is one.
    pub result: Option<Value>,
    /// The stored error, when there is one.
    pub error: Option<Value>,
    /// When the payload was expired by retention.
    pub payload_expired_at: Option<DateTime<Utc>>,
    /// `bound` or `draft` (the DDL's `mcp_runs_mode_check`).
    pub mode: String,
    /// The runtime that serves the run.
    pub runtime: Runtime,
    /// The external runtime's reference (for example an fr project).
    pub external_ref: Option<Value>,
    /// A short human-readable status note, at most 512 characters.
    pub status_message: Option<String>,
    /// The caller's actor object, when one was supplied.
    pub actor: Option<Value>,
}

/// The public run envelope: exactly the reference's `envelope(row)`.
pub fn envelope(row: &RunRow) -> Value {
    json!({
        "run_id": row.run_id.to_string(),
        "status": row.status.as_str(),
        "result": row.result,
        "error": row.error,
        "payload_expired": row.payload_expired_at.is_some(),
    })
}

/// The reference's canonical JSON: `json.dumps(value, sort_keys=True, separators=(",",":"),
/// ensure_ascii=False, allow_nan=False)`.
///
/// Object keys are sorted (Rust's UTF-8 byte order equals Python's code-point order), strings
/// are escaped like `json`'s with non-ASCII kept as-is, and floats use Python's `repr` layout.
pub fn canonical_json(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

/// SHA-256 hex of [`canonical_json`] — the reference's `digest` and `input_hash`.
pub fn value_hash(value: &Value) -> String {
    let digest = Sha256::digest(canonical_json(value).as_bytes());
    hex(&digest[..])
}

/// The authority snapshot stored on `mcp_runs.authority`: the resolved manifest, its effective
/// selection entry and the binding's bound context, exactly as the resolver produced them.
///
/// Each member is a JSON **string** holding that model's own JSON, not a nested object: the
/// reference stores `ResolvedTool.manifest_json/effective_json/context_json` (`str`), and the
/// worker reads them with `ToolManifest.model_validate_json(...)`, which rejects an object.
/// A nested object here would let the Rust API accept a run the Python worker can never claim.
pub fn authority_snapshot(resolved: &ResolvedTool) -> Result<Value, serde_json::Error> {
    Ok(json!({
        "manifest": serde_json::to_string(&resolved.manifest)?,
        "effective": serde_json::to_string(&resolved.effective)?,
        "context": serde_json::to_string(&resolved.context)?,
    }))
}

/// The reference's `parse_actor`: `{"channel": "mcp", "address": ...}` from a request's
/// `_meta`, or `None` when it is absent or invalid.
///
/// A present-but-wrongly-typed optional field invalidates the whole actor; unknown keys are
/// dropped. The `job` identity is normalised to the canonical lowercase hyphenated form.
pub fn parse_actor(meta: Option<&Map<String, Value>>) -> Option<Value> {
    let actor = meta?.get(ACTOR_META_KEY)?;
    let Value::Object(actor) = actor else {
        return None;
    };
    if actor.get("channel")?.as_str()? != "mcp" {
        return None;
    }
    let address = actor.get("address")?.as_str()?;
    if address.is_empty() || address.chars().count() > 256 {
        return None;
    }
    let mut parsed = Map::new();
    parsed.insert("channel".to_owned(), json!("mcp"));
    parsed.insert("address".to_owned(), json!(address));
    if let Some(job) = actor.get("job") {
        let job = Rfc4122Uuid::parse(job.as_str()?)?;
        parsed.insert("job".to_owned(), json!(job.to_string()));
    }
    if let Some(on_behalf_of) = actor.get("on_behalf_of") {
        let on_behalf_of = on_behalf_of.as_str()?;
        if on_behalf_of.is_empty() || on_behalf_of.chars().count() > 256 {
            return None;
        }
        parsed.insert("on_behalf_of".to_owned(), json!(on_behalf_of));
    }
    Some(Value::Object(parsed))
}

/// The reference's `Attribution`: who a stored run or catalog append belongs to.
pub fn attribution(principal: &Principal) -> Value {
    json!({
        "subject": principal.subject,
        "license_id": principal.license_id.to_string(),
    })
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                out.push_str(&integer.to_string());
            } else if let Some(integer) = number.as_u64() {
                out.push_str(&integer.to_string());
            } else if let Some(float) = number.as_f64() {
                out.push_str(&python_float_repr(float));
            } else {
                // A JSON number is always i64, u64 or f64; nothing else can be printed.
                out.push_str("null");
            }
        }
        Value::String(string) => write_string(string, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push('{');
            for (index, key) in keys.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                if let Some(item) = map.get(key.as_str()) {
                    write_value(item, out);
                }
            }
            out.push('}');
        }
    }
}

/// `json`'s string escaping with `ensure_ascii=False`: the two mandatory escapes, the short
/// control escapes, `\u00xx` for the remaining control characters, and non-ASCII kept as UTF-8.
fn write_string(value: &str, out: &mut String) {
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

/// Python's `repr(float)` layout: the shortest round-trip digits, positioned per Python's
/// rule — fixed notation while `-4 < decpt <= 16`, scientific outside it, and an exponent
/// always carrying a sign and at least two digits.
pub(crate) fn python_float_repr(value: f64) -> String {
    let mut out = String::new();
    if !value.is_finite() {
        // `serde_json::Value` cannot hold a non-finite number, so this arm is unreachable for
        // parsed JSON; printing null keeps the function total.
        out.push_str("null");
        return out;
    }
    if value.is_sign_negative() {
        out.push('-');
    }
    // Rust's `{:e}` prints the shortest round-trip mantissa and a decimal exponent — the same
    // digits Python starts from; only the placement below differs.
    let rendered = format!("{:e}", value.abs());
    let (mantissa, exponent) = rendered
        .as_str()
        .split_once('e')
        .unwrap_or((rendered.as_str(), "0"));
    let exponent: i32 = exponent.parse().unwrap_or(0);
    let digits: String = mantissa.chars().filter(|c| *c != '.').collect();
    let Some(first) = digits.chars().next() else {
        out.push_str("0.0");
        return out;
    };
    let decpt = exponent + 1;
    if decpt <= -4 || decpt > 16 {
        out.push(first);
        let rest = &digits[first.len_utf8()..];
        if !rest.is_empty() {
            out.push('.');
            out.push_str(rest);
        }
        out.push('e');
        out.push(if exponent >= 0 { '+' } else { '-' });
        let magnitude = exponent.unsigned_abs();
        if magnitude < 10 {
            out.push('0');
        }
        out.push_str(&magnitude.to_string());
    } else if decpt <= 0 {
        out.push_str("0.");
        for _ in 0..-decpt {
            out.push('0');
        }
        out.push_str(&digits);
    } else if decpt as usize >= digits.len() {
        out.push_str(&digits);
        for _ in digits.len()..decpt as usize {
            out.push('0');
        }
        out.push_str(".0");
    } else {
        let (whole, fraction) = digits.split_at(decpt as usize);
        out.push_str(whole);
        out.push('.');
        out.push_str(fraction);
    }
    out
}

/// Lowercase hex, one byte at a time.
fn hex(bytes: &[u8]) -> String {
    const DIGITS: [u8; 16] = *b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}
