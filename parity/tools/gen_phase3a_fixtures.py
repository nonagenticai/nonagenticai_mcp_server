"""Generate the phase-3A py-oracle golden fixtures from the pinned Python reference.

Run with the archive's own venv interpreter, archive root passed as argv[1],
output path as argv[2]. Pure functions only: no DB, no server, no network.
"""

import hashlib
import json
import sys
from datetime import UTC, datetime, timedelta
from uuid import UUID

ROOT = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, ROOT)

from src.execution.models import envelope  # noqa: E402
from src.storage.executions import value_hash  # noqa: E402
from src.tasks.extension import parse_actor  # noqa: E402
from src.tasks.mapping import create_task_result, task_view  # noqa: E402
from src.toolkits.models import BoundContext, EffectiveTool, ToolReference  # noqa: E402
from tests.fixtures import TENANT_A, TOOL, external_tool, settings, tool  # noqa: E402


def j(value):
    """JSON-safe copy of a row (datetimes/UUIDs to strings)."""
    if isinstance(value, dict):
        return {k: j(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [j(v) for v in value]
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, UUID):
        return str(value)
    return value


CFG = settings(
    execution_retention_days=7,
    task_poll_interval_ms=2000,
    external_poll_seconds=5,
)

VALUE_CASES = [
    ("empty_object", {}),
    ("nested", {"b": [1, 2, {"z": None, "a": True}], "a": {"y": "x"}}),
    ("unicode", {"name": "café ☕", "emoji": "🙂", "rtl": "مرحبا"}),
    ("strings_escapes", {"control": "\u0000\u001f", "quote": 'a"b\\c', "nl": "a\nb\tt"}),
    ("floats", {"a": 1.0, "b": 1.5, "c": 0.1, "d": -2.5}),
    ("float_exp", {"big": 1e20, "small": 1e-7, "neg": -3.5e-9}),
    # Python repr thresholds: fixed for decimal exponents -4..15, scientific outside.
    ("float_bounds", {"e15": 1e15, "e16": 1e16, "e_neg4": 1e-4, "e_neg5": 1e-5,
                      "max": 1.7976931348623157e308, "min_sub": 5e-324,
                      "frac": 123456789012345678.0}),
    ("unicode_edges", {"sep": "  ", "del": "\u007f", "nul": "\u0000",
                       "astral": "\U0001f642", "combining": "é"}),
    ("bools_null", {"t": True, "f": False, "n": None}),
    ("ints", {"zero": 0, "neg": -42, "big": 9223372036854775807, "u64": 18446744073709551615}),
    ("mixed", {"a": [], "b": {}, "c": [None, False, 0, "", {}], "d": {"": "empty-key"}}),
    ("zeros", {"neg_zero_float": -0.0, "zero": 0}),
]

HASH_CASES = [
    {"name": name, "value": value, "sha256": hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
                   allow_nan=False).encode()
    ).hexdigest()}
    for name, value in VALUE_CASES
]

NOW = datetime(2026, 11, 14, 12, 0, 0, tzinfo=UTC)
RUN = UUID("018f0000-0000-7000-8000-00000000aaaa")


def row(**over):
    base = dict(
        run_id=RUN,
        tenant_id=TENANT_A,
        binding_id=UUID("018f0000-0000-7000-8000-00000000bbbb"),
        gateway_license_id=UUID("018f0000-0000-7000-8000-00000000cccc"),
        owner_tenant_id=TENANT_A,
        tool_id=TOOL,
        tool_version=1,
        runtime="kata_python",
        status="queued",
        result=None,
        error=None,
        status_message=None,
        payload_expired_at=None,
        external_ref=None,
        created_at=NOW,
        started_at=None,
        finished_at=None,
        cancel_requested=False,
        idempotency_key=None,
        input_hash="0" * 64,
        inputs={"a": 1},
        authority={},
        profile_snapshot={},
        actor={"subject": "synthetic-subject", "license_id": str(TENANT_A)},
        queue_deadline=NOW + timedelta(seconds=60),
        created_by={},
        mode="bound",
    )
    base.update(over)
    return base


ENVELOPE_CASES = [
    {"name": "queued", "row": j(row()), "expected": j(envelope(row()))},
    {"name": "succeeded", "row": j(row(status="succeeded", result={"ok": True})),
     "expected": j(envelope(row(status="succeeded", result={"ok": True})))},
    {"name": "failed", "row": j(row(status="failed", error={"code": "preflight_failed",
                                                            "message": "denied"})),
     "expected": j(envelope(row(status="failed", error={"code": "preflight_failed",
                                                        "message": "denied"})))},
    {"name": "expired", "row": j(row(status="succeeded", result={},
                                     payload_expired_at=NOW + timedelta(days=7))),
     "expected": j(envelope(row(status="succeeded", result={},
                                payload_expired_at=NOW + timedelta(days=7))))},
]

ACTOR_META = "ai.nonagentic/actor"
ACTOR_CASES = [
    {"name": "valid_full", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "agent://job/1",
        "job": "018f0000-0000-7000-8000-00000000dddd", "on_behalf_of": "customer-7"}}}},
    {"name": "valid_minimal", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "agent://x"}}}},
    {"name": "unknown_keys_dropped", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "agent://x", "extra": 1}}}},
    {"name": "absent", "params": {"name": "t", "arguments": {}}},
    {"name": "wrong_channel", "params": {"_meta": {ACTOR_META: {
        "channel": "web", "address": "agent://x"}}}},
    {"name": "empty_address", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": ""}}}},
    {"name": "long_address", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "x" * 257}}}},
    {"name": "bad_job", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "agent://x", "job": "not-a-uuid"}}}},
    {"name": "bad_on_behalf", "params": {"_meta": {ACTOR_META: {
        "channel": "mcp", "address": "agent://x", "on_behalf_of": 7}}}},
    {"name": "not_mapping", "params": {"_meta": {ACTOR_META: ["x"]}}},
]

def elicitation(message, change_summary=None):
    """The reference's ``elicitation/create`` request payload (fr.py:119-138)."""
    text = message + ("\n\n" + change_summary if change_summary else "")
    return {
        "method": "elicitation/create",
        "params": {
            "message": text,
            "requestedSchema": {
                "type": "object",
                "required": ["decision"],
                "properties": {
                    "decision": {"type": "string", "enum": ["approved", "rejected"]},
                    "reason": {"type": "string"},
                    "comment": {"type": "string"},
                },
            },
        },
    }


OPEN_INPUTS = [
    dict(input_key="k1", state="open",
         request=elicitation("approve the start?", "2 files changed"), created_at=NOW),
    dict(input_key="k2", state="open",
         request=elicitation("approve the start?"),
         created_at=NOW, expires_at=NOW - timedelta(seconds=1)),
    dict(input_key="k3", state="answered", request=elicitation("closed"), created_at=NOW,
         answered_at=NOW + timedelta(seconds=5)),
]

TASK_VIEW_CASES = [
    {"name": "queued", "row": j(row()), "inputs": [],
     "expected": j(task_view(row(), [], CFG))},
    {"name": "running_open_input", "row": j(row(status="running", started_at=NOW,
                                               status_message="waiting")),
     "inputs": j(OPEN_INPUTS),
     "expected": j(task_view(row(status="running", started_at=NOW,
                                 status_message="waiting"), OPEN_INPUTS, CFG))},
    {"name": "cancelling", "row": j(row(status="cancelling")), "inputs": [],
     "expected": j(task_view(row(status="cancelling"), [], CFG))},
    {"name": "cancelled", "row": j(row(status="cancelled", finished_at=NOW)), "inputs": [],
     "expected": j(task_view(row(status="cancelled", finished_at=NOW), [], CFG))},
    {"name": "succeeded", "row": j(row(status="succeeded", result={"ok": True},
                                       finished_at=NOW)), "inputs": [],
     "expected": j(task_view(row(status="succeeded", result={"ok": True},
                                 finished_at=NOW), [], CFG))},
    {"name": "failed_is_completed", "row": j(row(status="failed",
                                                error={"code": "timeout", "message": "x"},
                                                finished_at=NOW)), "inputs": [],
     "expected": j(task_view(row(status="failed", error={"code": "timeout", "message": "x"},
                                 finished_at=NOW), [], CFG))},
    {"name": "fr_project", "row": j(row(status="running", runtime="fr_project",
                                        external_ref={"project_id": "p-1"})), "inputs": [],
     "fr_meta": {"project_id": "p-1", "activity": [], "signals": []},
     "expected": j(task_view(row(status="running", runtime="fr_project",
                                 external_ref={"project_id": "p-1"}), [], CFG,
                             {"project_id": "p-1", "activity": [], "signals": []}))},
]

CREATE_TASK_CASES = [
    {"name": "queued", "row": j(row()), "expected": j(create_task_result(row(), CFG))},
    {"name": "fr", "row": j(row(status="running", runtime="fr_project",
                               external_ref={"project_id": "p-1"})),
     "fr_meta": {"project_id": "p-1", "activity": [], "signals": []},
     "expected": j(create_task_result(row(status="running", runtime="fr_project",
                                          external_ref={"project_id": "p-1"}), CFG,
                                      {"project_id": "p-1", "activity": [],
                                       "signals": []}))},
]

MANIFESTS = [("kata", tool()), ("external", external_tool())]
EFFECTIVE = EffectiveTool(
    tool=ToolReference(id=TOOL, version=1, tenant_id=TENANT_A),
    limits={"queue_seconds": 30},
    public_name="synthetic_tool",
)
CONTEXT = BoundContext(tenant_id=TENANT_A)
# The reference stores each member as that model's own JSON STRING
# (`ResolvedTool.manifest_json` is `str`; readers call `model_validate_json`), so the
# fixture pins the type as well as the bytes.
AUTHORITY_CASES = [
    {"name": name,
     "manifest": manifest.model_dump_json(),
     "effective": EFFECTIVE.model_dump_json(),
     "context": CONTEXT.model_dump_json(),
     "expected": {
         "manifest": manifest.model_dump_json(),
         "effective": EFFECTIVE.model_dump_json(),
         "context": CONTEXT.model_dump_json(),
     }}
    for name, manifest in MANIFESTS
]

payload = {
    "source": "nonagenticai_mcp_server-python-archive",
    "pin": "22ac1ce4d1b8129a543832b8ed86fe0e1c0c7fe4",
    "generated_from": "pure functions only (no DB, no server)",
    "settings": {"execution_retention_days": 7, "task_poll_interval_ms": 2000,
                 "external_poll_seconds": 5},
    "value_hash": HASH_CASES,
    "envelope": ENVELOPE_CASES,
    "actor": ACTOR_CASES,
    "task_view": TASK_VIEW_CASES,
    "create_task_result": CREATE_TASK_CASES,
    "authority": AUTHORITY_CASES,
}
# Actor expectations computed last (parse_actor returns None or a dict).
for case in ACTOR_CASES:
    case["expected"] = parse_actor(case["params"])

with open(OUT, "w", encoding="utf-8") as fh:
    json.dump(payload, fh, ensure_ascii=False, indent=2, sort_keys=False)
    fh.write("\n")
print("wrote", OUT, "cases:", {k: len(payload[k]) for k in
                               ("value_hash", "envelope", "actor", "task_view",
                                "create_task_result", "authority")})
