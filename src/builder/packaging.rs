//! Tool packages for tenant-authored tools: the author's script files plus the host's `kit.py`
//! and generated `ops.py`.
//!
//! Ported from the reference's `src/builder/packaging.py`. The host files are regenerated on
//! every version, so a tool can only call the operations the host pinned for it. The reference
//! reads `toolkits/_kit/kit.py` from its checkout; the text is embedded here byte for byte (the
//! Rust checkout has no `toolkits/` tree yet).
//!
//! `ops.py` is Python `json.dumps(table, indent=2, sort_keys=True)` output: two-space indent,
//! `", "` key/value separator after the colon, `ensure_ascii=True` escaping, keys sorted. The
//! writer below reproduces those bytes rather than relying on serde_json's pretty printer, whose
//! non-ASCII escaping differs.

use std::collections::BTreeMap;
use std::fmt::Write as _;

use serde_json::{Map, Value};

use crate::builder::models::{BuilderInputError, is_host_file};
use crate::catalog::ids::Operation;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::models::{Effect, ExactReference, ToolLimits, ToolManifest};
use crate::catalog::package::{PackageFile, package_digest};

/// The host-owned package file every tool receives.
pub const KIT_FILE: &str = "kit.py";
/// The generated operation table every tool receives.
pub const OPS_FILE: &str = "ops.py";
/// The generated table's assignment prefix.
pub const OPS_PREFIX: &str = "OPS = ";

/// The script key to `(operation id, exact version)` table of a package.
pub type OpRefs = BTreeMap<String, (Uuid7, PositiveVersion)>;

/// The host's `kit.py`.
pub fn kit_source() -> &'static str {
    KIT_PY
}

/// The author's own files (the host files are regenerated on every version).
pub fn user_files(files: &[PackageFile]) -> Vec<&PackageFile> {
    files
        .iter()
        .filter(|file| !is_host_file(&file.path))
        .collect()
}

/// The `{script_key: (operation_id, version)}` table of a stored package's `ops.py`.
///
/// The reference splits on the first `OPS = ` and lets `UUID`/`int` validate the entries; this
/// port validates them as the catalog's `Uuid7`/`PositiveVersion` at the same point, so a
/// corrupted table is refused here instead of surfacing later in a manifest.
pub fn parse_ops(files: &[PackageFile]) -> Result<OpRefs, BuilderInputError> {
    let Some(file) = files.iter().find(|file| file.path == OPS_FILE) else {
        return Ok(OpRefs::new());
    };
    let Some((_, text)) = file.content.split_once(OPS_PREFIX) else {
        return Err(BuilderInputError::new("ops.py has no OPS table"));
    };
    let table: Value = serde_json::from_str(text)
        .map_err(|_| BuilderInputError::new("ops.py has an invalid OPS table"))?;
    let Value::Object(table) = table else {
        return Err(BuilderInputError::new("ops.py has an invalid OPS table"));
    };
    let mut refs = OpRefs::new();
    for (key, entry) in table {
        let Value::Array(entry) = entry else {
            return Err(BuilderInputError::new("ops.py has an invalid OPS table"));
        };
        let (Some(Value::String(operation_id)), Some(version)) = (entry.first(), entry.get(1))
        else {
            return Err(BuilderInputError::new("ops.py has an invalid OPS table"));
        };
        let Some(version) = version.as_u64() else {
            return Err(BuilderInputError::new("ops.py has an invalid OPS table"));
        };
        let operation_id = Uuid7::new(operation_id.clone())
            .map_err(|_| BuilderInputError::new("ops.py has an invalid OPS table"))?;
        let version = PositiveVersion::new(version)
            .map_err(|_| BuilderInputError::new("ops.py has an invalid OPS table"))?;
        refs.insert(key, (operation_id, version));
    }
    Ok(refs)
}

/// Author files + `kit.py` + generated `ops.py`, sorted by path.
pub fn build_package(files: &[PackageFile], refs: &OpRefs) -> Vec<PackageFile> {
    let mut out: Vec<PackageFile> = user_files(files).into_iter().cloned().collect();
    out.push(PackageFile {
        path: KIT_FILE.to_owned(),
        content: kit_source().to_owned(),
    });
    out.push(PackageFile {
        path: OPS_FILE.to_owned(),
        content: ops_source(refs),
    });
    out.sort_by(|left, right| left.path.cmp(&right.path));
    out
}

/// The generated `ops.py` text.
fn ops_source(refs: &OpRefs) -> String {
    let mut text = String::from("# Generated: operation id and exact version per key.\nOPS = ");
    if refs.is_empty() {
        text.push_str("{}");
    } else {
        text.push('{');
        for (index, (key, (operation_id, version))) in refs.iter().enumerate() {
            if index > 0 {
                text.push(',');
            }
            text.push_str("\n  ");
            write_json_string(&mut text, key);
            text.push_str(": [\n    ");
            write_json_string(&mut text, operation_id.as_str());
            text.push_str(",\n    ");
            let _ = write!(text, "{}", version.get());
            text.push_str("\n  ]");
        }
        text.push_str("\n}");
    }
    text.push('\n');
    text
}

/// `json.dumps(text, ensure_ascii=True)` for one string.
fn write_json_string(out: &mut String, text: &str) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if !control.is_ascii() || control.is_ascii_control() => {
                let code = control as u32;
                if code <= 0xFFFF {
                    let _ = write!(out, "\\u{code:04x}");
                } else {
                    let adjusted = code - 0x1_0000;
                    let high = 0xD800 + (adjusted >> 10);
                    let low = 0xDC00 + (adjusted & 0x3FF);
                    let _ = write!(out, "\\u{high:04x}\\u{low:04x}");
                }
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

/// The fields `manifest_fields` assembles (the reference's keyword arguments).
pub struct ManifestFieldArgs<'a> {
    /// MCP tool name.
    pub public_name: &'a crate::catalog::ids::Name,
    /// Agent platform operation.
    pub operation: &'a Operation,
    /// Human description.
    pub description: &'a str,
    /// Package entrypoint.
    pub entrypoint: &'a str,
    /// Input JSON Schema.
    pub input_schema: &'a Map<String, Value>,
    /// Result JSON Schema; defaults to the first-party envelope.
    pub result_schema: Option<&'a Map<String, Value>>,
    /// Bound-context JSON Schema; defaults to "no context".
    pub context_schema: Option<&'a Map<String, Value>>,
    /// Read or write.
    pub effect: Effect,
    /// Runner limits; omitted from the output when absent.
    pub limits: Option<&'a ToolLimits>,
}

/// The tool manifest fields the author chose, in the reference's key order.
pub fn manifest_fields(args: ManifestFieldArgs<'_>) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert(
        "public_name".to_owned(),
        Value::String(args.public_name.to_string()),
    );
    fields.insert(
        "operation".to_owned(),
        Value::String(args.operation.to_string()),
    );
    fields.insert(
        "description".to_owned(),
        Value::String(args.description.to_owned()),
    );
    fields.insert(
        "entrypoint".to_owned(),
        Value::String(args.entrypoint.to_owned()),
    );
    fields.insert(
        "input_schema".to_owned(),
        Value::Object(args.input_schema.clone()),
    );
    fields.insert(
        "result_schema".to_owned(),
        match args.result_schema {
            Some(schema) => Value::Object(schema.clone()),
            None => default_result_schema(),
        },
    );
    fields.insert(
        "context_schema".to_owned(),
        match args.context_schema {
            Some(schema) => Value::Object(schema.clone()),
            None => no_context(),
        },
    );
    fields.insert(
        "effect".to_owned(),
        Value::String(effect_name(args.effect).to_owned()),
    );
    if let Some(limits) = args.limits {
        fields.insert("limits".to_owned(), limits_json(limits));
    }
    fields
}

/// The reference's `RESULT_SCHEMA` (the first-party result envelope).
pub fn default_result_schema() -> Value {
    serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["status", "checks", "next"],
        "properties": {
            "status": {"enum": ["ok", "precondition_failed", "check_failed", "pending", "backend_error"]},
            "data": {},
            "checks": {
                "type": "array",
                "maxItems": 64,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["name", "status", "summary"],
                    "properties": {
                        "name": {"type": "string", "maxLength": 64},
                        "status": {"enum": ["pass", "fail", "degraded", "error"]},
                        "summary": {"type": "string", "maxLength": 500}
                    }
                }
            },
            "verdict": {"enum": ["pass", "fail", "degraded"]},
            "next": {
                "type": "array",
                "maxItems": 8,
                "items": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["tool"],
                    "properties": {
                        "tool": {"type": "string", "maxLength": 64},
                        "reason": {"type": "string", "maxLength": 500},
                        "arguments": {"type": "object"}
                    }
                }
            },
            "reason": {"type": "string", "maxLength": 64},
            "error": {
                "type": "object",
                "additionalProperties": false,
                "required": ["message", "retryable"],
                "properties": {
                    "message": {"type": "string", "maxLength": 500},
                    "retryable": {"type": "boolean"}
                }
            },
            "resume_token": {"type": "string", "maxLength": 2048}
        }
    })
}

/// The reference's `NO_CONTEXT`.
pub fn no_context() -> Value {
    serde_json::json!({"type": "object", "properties": {}, "additionalProperties": false})
}

fn effect_name(effect: Effect) -> &'static str {
    match effect {
        Effect::ReadOnly => "read_only",
        Effect::Writes => "writes",
    }
}

fn limits_json(limits: &ToolLimits) -> Value {
    serde_json::json!({
        "wall_seconds": limits.wall_seconds,
        "queue_seconds": limits.queue_seconds,
        "memory_mi": limits.memory_mi,
        "cpu_millicores": limits.cpu_millicores,
        "api_calls": limits.api_calls,
        "frame_bytes": limits.frame_bytes,
        "output_bytes": limits.output_bytes,
    })
}

/// The host-filled parts of a tool manifest.
pub struct ToolManifestInput<'a> {
    /// The tool identity.
    pub tool_id: &'a Uuid7,
    /// The owning tenant.
    pub tenant_id: &'a AuthorityId,
    /// The exact version.
    pub version: PositiveVersion,
    /// The author-chosen fields.
    pub fields: &'a Map<String, Value>,
    /// The built package.
    pub files: &'a [PackageFile],
    /// The pinned operations.
    pub refs: &'a [ExactReference],
    /// The approved runner image.
    pub runner_image_digest: &'a str,
}

/// The manifest the host fills in: tenant, runner image, package digest, pinned operations.
///
/// The reference validates the assembled document as a `ToolManifest`. Field names the caller
/// put in `fields` win over the host's (the reference spreads `**fields` last), and the error
/// message is serde's rather than Pydantic's for the same refusal.
pub fn tool_manifest(input: ToolManifestInput<'_>) -> Result<ToolManifest, BuilderInputError> {
    let mut document = Map::new();
    document.insert(
        "tool_id".to_owned(),
        Value::String(input.tool_id.to_string()),
    );
    document.insert(
        "tenant_id".to_owned(),
        Value::String(input.tenant_id.to_string()),
    );
    document.insert(
        "version".to_owned(),
        Value::Number(serde_json::Number::from(input.version.get())),
    );
    document.insert(
        "package_sha256".to_owned(),
        Value::String(package_digest(input.files)),
    );
    document.insert(
        "runner_image_digest".to_owned(),
        Value::String(input.runner_image_digest.to_owned()),
    );
    let mut references: Vec<&ExactReference> = input.refs.iter().collect();
    references.sort_by_key(|reference| reference.id.clone());
    let allowed: Vec<Value> = references
        .iter()
        .map(|reference| {
            serde_json::json!({
                "id": reference.id.to_string(),
                "version": reference.version.get(),
            })
        })
        .collect();
    document.insert("allowed_operations".to_owned(), Value::Array(allowed));
    for (key, value) in input.fields {
        document.insert(key.clone(), value.clone());
    }
    serde_json::from_value(Value::Object(document))
        .map_err(|error| BuilderInputError::new(error.to_string()))
}

/// The script keys of a tool's operations, in the caller's order.
pub fn script_keys(operations: &[crate::builder::models::ToolOperation]) -> Vec<String> {
    operations
        .iter()
        .map(|operation| operation.script_key())
        .collect()
}

/// The host's shared `kit.py`, byte for byte.
const KIT_PY: &str = r#""""Shared helpers for platform toolkit scripts. Standard library only.

Copied into every tool package as ``kit.py`` next to the generated ``ops.py``
(``OPS = {key: [operation_uuid, version]}``). A tool is one deterministic script:
``async def main(inputs, ctx)`` returning the result envelope

    {status: ok|precondition_failed|check_failed|pending|backend_error,
     data, checks[{name, status, summary}], verdict, next[], reason?, error?, resume_token?}

The envelope invariants mirror src/toolkit_contract/envelope.py: a precondition_failed carries a
reason and the tool that fixes it, a pending carries a resume token and the tool to call with it,
a check_failed has a failing check, and an ok never hides one.
"""

import asyncio
import base64
import hashlib
import json
import re
import time

SUMMARY_MAX = 500
TOKEN_MAX = 2048
TOKEN_MAX_AGE = 3600
TOKEN_STATE_MAX = 1500
_IDENT = re.compile(r"[a-z][a-z0-9_]{0,63}")

OK = "ok"
PRECONDITION_FAILED = "precondition_failed"
CHECK_FAILED = "check_failed"
PENDING = "pending"
BACKEND_ERROR = "backend_error"

PASS = "pass"
FAIL = "fail"
DEGRADED = "degraded"
ERROR = "error"


def clip(text, limit=SUMMARY_MAX):
    text = str(text)
    return text if len(text) <= limit else text[: limit - 3] + "..."


# --- checks and envelope ---------------------------------------------------------------------


def check(name, status, summary=""):
    if not _IDENT.fullmatch(name) or status not in (PASS, FAIL, DEGRADED, ERROR):
        raise ValueError("invalid check")
    return {"name": name, "status": status, "summary": clip(summary)}


def verdict(checks):
    """Any fail or error -> fail; else any degraded -> degraded; else pass; None without checks."""
    if not checks:
        return None
    statuses = {c["status"] for c in checks}
    if statuses & {FAIL, ERROR}:
        return FAIL
    return DEGRADED if DEGRADED in statuses else PASS


def step(tool, reason="", arguments=None):
    if not _IDENT.fullmatch(tool):
        raise ValueError("invalid tool name")
    out = {"tool": tool, "reason": clip(reason)}
    if arguments is not None:
        out["arguments"] = arguments
    return out


def envelope(status, *, data=None, checks=(), next_steps=(), reason=None, error=None, token=None):
    checks = list(checks)
    names = [c["name"] for c in checks]
    if len(set(names)) != len(names) or len(checks) > 64 or len(next_steps) > 8:
        raise ValueError("invalid envelope")
    failing = verdict(checks) == FAIL
    if status == OK and failing:
        raise ValueError("ok result cannot carry a failing check")
    if status == CHECK_FAILED and not failing:
        raise ValueError("check_failed requires a failing check")
    if status == PRECONDITION_FAILED and (reason is None or not next_steps):
        raise ValueError("precondition_failed requires reason and next")
    if status == PENDING and (token is None or not next_steps):
        raise ValueError("pending requires resume_token and next")
    if status == BACKEND_ERROR and error is None:
        raise ValueError("backend_error requires error")
    if (token is not None) != (status == PENDING):
        raise ValueError("resume_token is only valid on pending")
    if (reason is not None) != (status == PRECONDITION_FAILED):
        raise ValueError("reason is only valid on precondition_failed")
    if (error is not None) != (status == BACKEND_ERROR):
        raise ValueError("error is only valid on backend_error")
    out = {"status": status, "checks": checks, "next": list(next_steps)}
    if data is not None:
        out["data"] = data
    if checks:
        out["verdict"] = verdict(checks)
    if reason is not None:
        if not _IDENT.fullmatch(reason):
            raise ValueError("invalid reason")
        out["reason"] = reason
    if error is not None:
        out["error"] = error
    if token is not None:
        out["resume_token"] = token
    return out


def completed(data=None, checks=(), next_steps=()):
    """ok, or check_failed when the checks' verdict is fail."""
    status = CHECK_FAILED if verdict(checks) == FAIL else OK
    return envelope(status, data=data, checks=checks, next_steps=next_steps)


def precondition_failed(reason, next_steps, checks=(), data=None):
    return envelope(
        PRECONDITION_FAILED, reason=reason, next_steps=next_steps, checks=checks, data=data
    )


def pending(token, next_steps, data=None, checks=()):
    return envelope(PENDING, token=token, next_steps=next_steps, data=data, checks=checks)


def backend_error(message, retryable=False, checks=(), data=None):
    error = {"message": clip(message) or "backend error", "retryable": bool(retryable)}
    return envelope(BACKEND_ERROR, error=error, checks=checks, data=data)


# --- time budget -----------------------------------------------------------------------------


class Budget:
    """A deadline inside the run's wall clock, minus a safety margin."""

    def __init__(self, wall_seconds, margin=20.0, clock=None):
        self._clock = clock or time.monotonic
        self._end = self._clock() + max(0.0, wall_seconds - margin)

    def remaining(self):
        return self._end - self._clock()

    def allows(self, seconds):
        return self.remaining() >= seconds


async def poll(fetch, done, budget, *, interval=3.0, reserve=0.0, attempts=20, sleep=None):
    """Fetch until ``done(value)``; returns (value, finished).

    Never sleeps past ``budget.remaining() - reserve`` and makes at most ``attempts`` fetches, so
    the caller can bound its API-call count. ``finished`` is False on timeout (a pending result,
    never a silent failure).
    """
    value = None
    for attempt in range(attempts):
        value = await fetch()
        if done(value):
            return value, True
        room = budget.remaining() - reserve
        if attempt + 1 >= attempts or room <= interval:
            return value, False
        await (sleep or asyncio.sleep)(interval)
    return value, False


# --- backend calls ---------------------------------------------------------------------------


class Abort(Exception):  # noqa: N818 - control flow carrying a finished envelope
    """Stop the tool with a finished envelope."""

    def __init__(self, result):
        super().__init__("abort")
        self.result = result


def _ops():
    import ops  # generated beside this file

    return ops.OPS


async def call(ctx, key, args, idempotency_key=None):
    """Call one operation; returns (status, body).

    2xx -> (200, body). A status the operation declared in expected_error_statuses -> (status,
    body). Anything else the runner raises (RuntimeError "api_call_denied") propagates.
    """
    operation = _ops()[key][0]
    try:
        return 200, await ctx.api.call(operation, args, idempotency_key=idempotency_key)
    except Exception as exc:  # noqa: BLE001 - duck-typed: runner.sdk.ApiStatusError
        if type(exc).__name__ == "ApiStatusError":
            return exc.status, exc.body
        raise


def describe(status, body):
    """A short, value-free summary of an unexpected HTTP status for the caller."""
    detail = ""
    if isinstance(body, dict):
        for field in ("message", "detail", "error", "error_code"):
            value = body.get(field)
            if isinstance(value, str) and value:
                detail = value
                break
    return clip(f"HTTP {status}" + (f": {detail}" if detail else ""), 300)


async def call_ok(ctx, key, args, *, what=None, retryable=False, checks=()):
    """Like call() but any non-2xx ends the tool with a backend_error."""
    status, body = await call(ctx, key, args)
    if status != 200:
        raise Abort(backend_error(f"{what or key}: {describe(status, body)}", retryable, checks))
    return body


async def guarded(coro):
    """Run a tool body; turn aborts and denied calls into envelopes."""
    try:
        return await coro
    except Abort as stop:
        return stop.result
    except RuntimeError as exc:
        if str(exc) != "api_call_denied":
            raise
        return backend_error(
            "a gateway call failed or was denied; a write may or may not have applied, "
            "read the state back with coding_repo_status before retrying",
            retryable=False,
        )


# --- resume tokens ---------------------------------------------------------------------------
# Unsigned base64url JSON {v, tool, iat, state}; the state holds only ids the caller could pass
# anyway, and each one is re-read through the tenant-scoped broker. The checksum after the dot
# only catches truncation or corruption (the token format needs two dot-separated parts).


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _unb64(text):
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _crc(body):
    return _b64(hashlib.sha256(body.encode("ascii")).digest()[:6])


def encode_token(tool, state, now=None):
    payload = {
        "v": 1,
        "tool": tool,
        "iat": int(time.time() if now is None else now),
        "state": state,
    }
    raw = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(raw) > TOKEN_STATE_MAX:
        raise ValueError("resume state too large")
    body = _b64(raw)
    token = f"{body}.{_crc(body)}"
    if len(token) > TOKEN_MAX:
        raise ValueError("resume state too large")
    return token


def decode_token(token, tool, now=None):
    """Return the state or raise ValueError (malformed, wrong tool, expired, too large)."""
    if not isinstance(token, str) or len(token) > TOKEN_MAX or token.count(".") != 1:
        raise ValueError("malformed resume_token")
    body, crc = token.split(".")
    if crc != _crc(body):
        raise ValueError("malformed resume_token")
    try:
        payload = json.loads(_unb64(body))
    except ValueError:
        raise ValueError("malformed resume_token") from None
    if not isinstance(payload, dict) or payload.get("v") != 1:
        raise ValueError("unsupported resume_token version")
    if payload.get("tool") != tool:
        raise ValueError("resume_token belongs to another tool")
    issued = payload.get("iat")
    current = time.time() if now is None else now
    if type(issued) is not int or not 0 <= current - issued <= TOKEN_MAX_AGE:
        raise ValueError("resume_token expired")
    state = payload.get("state")
    if not isinstance(state, dict):
        raise ValueError("malformed resume_token")
    return state


def bad_token(message, tool):
    """The envelope for a rejected resume token: nothing was attempted."""
    return precondition_failed(
        "invalid_resume_token",
        [step(tool, clip(message, 200) + "; call again without resume_token")],
    )
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ids::Name;

    fn reference(operation_id: &str, version: u64) -> ExactReference {
        ExactReference {
            id: Uuid7::new(operation_id).unwrap(),
            version: PositiveVersion::new(version).unwrap(),
        }
    }

    fn files() -> Vec<PackageFile> {
        vec![
            PackageFile {
                path: "tool.py".to_owned(),
                content: "async def main(inputs, ctx):\n    return {}\n".to_owned(),
            },
            PackageFile {
                path: "kit.py".to_owned(),
                content: "stale".to_owned(),
            },
            PackageFile {
                path: "ops.py".to_owned(),
                content: "stale".to_owned(),
            },
        ]
    }

    #[test]
    fn ops_py_is_python_json_dumps_output() {
        let mut refs = OpRefs::new();
        refs.insert(
            "crm.get_customer".to_owned(),
            (
                Uuid7::new("01900000-0000-7000-8000-000000000001").unwrap(),
                PositiveVersion::new(1).unwrap(),
            ),
        );
        refs.insert(
            "crm.list_orders".to_owned(),
            (
                Uuid7::new("01900000-0000-7000-8000-000000000002").unwrap(),
                PositiveVersion::new(3).unwrap(),
            ),
        );
        assert_eq!(
            ops_source(&refs),
            "# Generated: operation id and exact version per key.\nOPS = {\n  \"crm.get_customer\": [\n    \"01900000-0000-7000-8000-000000000001\",\n    1\n  ],\n  \"crm.list_orders\": [\n    \"01900000-0000-7000-8000-000000000002\",\n    3\n  ]\n}\n"
        );
        assert_eq!(
            ops_source(&OpRefs::new()),
            "# Generated: operation id and exact version per key.\nOPS = {}\n"
        );
    }

    #[test]
    fn packages_contain_the_author_files_and_regenerated_host_files() {
        let built = build_package(&files(), &OpRefs::new());
        let paths: Vec<&str> = built.iter().map(|file| file.path.as_str()).collect();
        assert_eq!(paths, vec!["kit.py", "ops.py", "tool.py"]);
        assert_eq!(built[0].content, kit_source());
        assert_eq!(
            built[1].content,
            "# Generated: operation id and exact version per key.\nOPS = {}\n"
        );
        assert_eq!(
            built[2].content,
            "async def main(inputs, ctx):\n    return {}\n"
        );
        assert_eq!(user_files(&files()).len(), 1);
    }

    #[test]
    fn parse_ops_round_trips_the_generated_table() {
        let mut refs = OpRefs::new();
        refs.insert(
            "crm.get_customer".to_owned(),
            (
                Uuid7::new("01900000-0000-7000-8000-000000000001").unwrap(),
                PositiveVersion::new(2).unwrap(),
            ),
        );
        let built = build_package(&files(), &refs);
        assert_eq!(parse_ops(&built).unwrap(), refs);
        assert!(parse_ops(&[]).unwrap().is_empty());
        let malformed = vec![PackageFile {
            path: "ops.py".to_owned(),
            content: "OPS = not json".to_owned(),
        }];
        assert!(parse_ops(&malformed).is_err());
    }

    #[test]
    fn manifest_fields_default_to_the_first_party_envelope() {
        let name = Name::new("find_customer").unwrap();
        let operation = Operation::new("customer.find").unwrap();
        let schema = serde_json::json!({"type": "object"})
            .as_object()
            .cloned()
            .unwrap();
        let fields = manifest_fields(ManifestFieldArgs {
            public_name: &name,
            operation: &operation,
            description: "Find a customer",
            entrypoint: "tool:main",
            input_schema: &schema,
            result_schema: None,
            context_schema: None,
            effect: Effect::ReadOnly,
            limits: None,
        });
        assert_eq!(fields["public_name"], "find_customer");
        assert_eq!(fields["operation"], "customer.find");
        assert_eq!(fields["effect"], "read_only");
        assert_eq!(fields["result_schema"], default_result_schema());
        assert_eq!(fields["context_schema"], no_context());
        assert!(!fields.contains_key("limits"));
    }

    #[test]
    fn tool_manifest_pins_operations_sorted_and_digests_the_package() {
        let built = build_package(&files(), &OpRefs::new());
        let name = Name::new("find_customer").unwrap();
        let operation = Operation::new("customer.find").unwrap();
        let schema = serde_json::json!({"type": "object"})
            .as_object()
            .cloned()
            .unwrap();
        let fields = manifest_fields(ManifestFieldArgs {
            public_name: &name,
            operation: &operation,
            description: "Find a customer",
            entrypoint: "tool:main",
            input_schema: &schema,
            result_schema: None,
            context_schema: None,
            effect: Effect::ReadOnly,
            limits: None,
        });
        let refs = vec![
            reference("01900000-0000-7000-8000-000000000002", 1),
            reference("01900000-0000-7000-8000-000000000001", 2),
        ];
        let manifest = tool_manifest(ToolManifestInput {
            tool_id: &Uuid7::new("01900000-0000-7000-8000-000000000009").unwrap(),
            tenant_id: &AuthorityId::new("00000000-0000-0000-8000-000000000001").unwrap(),
            version: PositiveVersion::new(1).unwrap(),
            fields: &fields,
            files: &built,
            refs: &refs,
            runner_image_digest: &format!("registry.example/runner@sha256:{}", "a".repeat(64)),
        })
        .unwrap();
        assert_eq!(manifest.package_sha256.as_str(), package_digest(&built));
        assert_eq!(
            manifest.allowed_operations[0].id.as_str(),
            "01900000-0000-7000-8000-000000000001"
        );
        assert_eq!(manifest.allowed_operations[1].version.get(), 1);
        assert_eq!(manifest.effect, Effect::ReadOnly);
    }
}
