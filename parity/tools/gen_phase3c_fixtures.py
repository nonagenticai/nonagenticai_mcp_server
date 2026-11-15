"""Generate the phase-3C py-oracle golden fixtures from the pinned Python reference.

Run with the archive's own interpreter, archive root passed as argv[1], output path as
argv[2]: `uv run --frozen python parity/tools/gen_phase3c_fixtures.py <archive> <out>`.

Everything here is produced by the reference's own code, not re-implemented: the pure
helpers are called directly, and the adapters are driven against a stub transport that
records the exact URL, bytes and headers they would send. The Rust port asserts equality
against this file, so a divergence in a signature, a JWT, a channel envelope or a bounded
project view fails a test instead of reaching fr or n8n.
"""

import asyncio
import json
import sys
from uuid import UUID

ROOT = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, ROOT)

import httpx  # noqa: E402

from src.external import fr as fr_module  # noqa: E402
from src.external import n8n as n8n_module  # noqa: E402
from src.external import signing  # noqa: E402
from src.external.fr import (  # noqa: E402
    FrAdapter,
    FrCommandAdapter,
    close_view,
    decision_text,
    project_view,
    sanitize_code,
)
from src.external.n8n import N8nAdapter, webhook_token  # noqa: E402
from tests.fixtures import TENANT_A, settings  # noqa: E402

# A fixed idempotency key: `sign()` mints one with `uuid4()`, which would make the
# signature headers differ on every run of this generator.
FIXED_UUID = UUID("018f0000-0000-7000-8000-0000000000aa")
signing.uuid4 = lambda: FIXED_UUID

# A fixed clock for both adapters: `N8nAdapter.start` signs its webhook JWT with
# `time.time()` and `FrAdapter._send` signs the channel envelope with `int(time.time())`,
# so an unfrozen clock rewrites the token and every signature on each regeneration.
FIXED_NOW = 1_763_000_000


class FrozenTime:
    @staticmethod
    def time():
        return float(FIXED_NOW)


n8n_module.time = FrozenTime()
fr_module.time = FrozenTime()

RUN = UUID("018f0000-0000-7000-8000-00000000aaaa")
SECRET = "synthetic-channel-secret"
WEBHOOK_SECRET = "synthetic-webhook-secret"
PROJECT = "018f0000-0000-7000-8000-0000000000cc"
APPROVAL = "018f0000-0000-7000-8000-0000000000dd"

FR_SETTINGS = settings(
    fr_base_url="http://fr.test:8888",
    fr_channel_secret=SECRET,
    n8n_base_url="http://n8n.test:5678",
    n8n_webhook_base_url="http://n8n.test:5678",
    n8n_api_key="synthetic-n8n-key",
    n8n_webhook_secret=WEBHOOK_SECRET,
)
N8N_UNAUTHENTICATED = settings(
    n8n_webhook_base_url="http://n8n.test:5678",
    n8n_api_key="synthetic-n8n-key",
)


class Response:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status
        self.is_success = 200 <= status < 300

    def json(self):
        return self._payload

    def raise_for_status(self):
        if not self.is_success:
            raise httpx.HTTPStatusError("refused", request=None, response=self)


class Client:
    """Records every call and answers with one prepared payload."""

    def __init__(self, payload, status=200):
        self._response = Response(payload, status)
        self.calls = []

    async def post(self, url, **kwargs):
        body = kwargs.get("content")
        self.calls.append(
            {
                "url": url,
                "content": body.decode() if body is not None else None,
                "json": kwargs.get("json"),
                "headers": kwargs.get("headers"),
            }
        )
        return self._response


def manifest(runtime, **target):
    """The stored `authority.manifest`, as the reference stores it: a JSON string."""
    return json.dumps(
        {"runtime": runtime, "target": target}, separators=(",", ":"), sort_keys=True
    )


def row(**over):
    base = {
        "run_id": RUN,
        "tenant_id": TENANT_A,
        "status": "starting",
        "inputs": {},
        "actor": None,
        "external_ref": None,
        "authority": {
            "manifest": manifest(
                "n8n_workflow", kind="n8n_workflow", webhook_path="mcp/demo",
                result_node="MCP Result",
            )
        },
    }
    base.update(over)
    return base


FR_ACTOR = {"address": f"agent:{TENANT_A}", "job": "018f0000-0000-7000-8000-0000000000bb"}
N8N_ACTOR = {"address": "claude-approval-triage-conveyor@conveyor", "channel": "mcp"}


def fr_row(**over):
    base = {
        "authority": {
            "manifest": manifest("fr_project", kind="fr_project", project_type="it")
        },
        "actor": FR_ACTOR,
    }
    base.update(over)
    return row(**base)


async def fr_start(name, response, status=200, command=None, inputs=None):
    """One `start` through the real adapter, against a recording stub transport."""
    client = Client(response, status)
    if command is None:
        adapter = FrAdapter(client, FR_SETTINGS)
        row_ = fr_row(inputs=inputs or {"title": "Synthetic project"})
    else:
        adapter = FrCommandAdapter(client, FR_SETTINGS)
        row_ = fr_row(
            inputs=inputs or {"id": PROJECT},
            authority={"manifest": manifest("fr_command", kind="fr_command", command=command)},
        )
    try:
        ref = await adapter.start(row_)
        outcome = {
            "ref": {
                "kind": ref.kind,
                "id": ref.id,
                "project_id": ref.project_id,
                "result": ref.result,
            }
        }
    except Exception as error:  # the refusal is part of the contract
        outcome = {"code": getattr(error, "code", type(error).__name__)}
    call = client.calls[0] if client.calls else None
    return {"name": name, "request": call, "outcome": outcome}


async def n8n_start(name, response, authenticated=True):
    client = Client(response)
    adapter = N8nAdapter(client, FR_SETTINGS if authenticated else N8N_UNAUTHENTICATED)
    try:
        ref = await adapter.start(row(inputs={"a": 1}))
        outcome = {"ref": {"kind": ref.kind, "id": ref.id}}
    except Exception as error:
        outcome = {"code": getattr(error, "code", type(error).__name__)}
    call = client.calls[0]
    return {"name": name, "request": call, "outcome": outcome}


PROJECTS = {
    "small": {
        "id": PROJECT,
        "name": "Synthetic project",
        "project_type": "it",
        "status": "running",
        "phase": "build",
        "url": f"/projects/{PROJECT}",
        "delivered_at": None,
        "delivery_evidence": None,
        "deliverables": ["one"],
        "internal_note": "never in a view",
    },
    "empty": {},
    "closed": {
        "id": PROJECT,
        "name": "Synthetic project",
        "project_type": "it",
        "status": "delivered",
        "phase": "done",
        "url": f"/projects/{PROJECT}",
        "delivered_at": "2026-11-15T00:00:00+00:00",
        "delivery_evidence": {"commit": "abc123"},
        "deliverables": ["one", "two"],
        "closed": True,
        "already_closed": False,
        "rm_pm_project_id": "rm-1",
    },
    "oversized_deliverables": {
        "id": PROJECT,
        "name": "Synthetic project",
        "status": "running",
        "deliverables": ["x" * 70_000],
        "delivery_evidence": {"blob": "y" * 70_000},
    },
    "oversized_text": {
        "id": PROJECT,
        "name": "n" * 70_000,
        "status": "running",
        "phase": "p" * 70_000,
    },
}

N8N_PAYLOADS = {
    "valid": {
        "status": "success",
        "data": {
            "resultData": {
                "runData": {
                    "MCP Result": [
                        {"data": {"main": [[{"json": {"answer": 42, "text": "café"}}]]}}
                    ]
                }
            }
        },
    },
    "missing_node": {"status": "success", "data": {"resultData": {"runData": {}}}},
    "not_object": {
        "status": "success",
        "data": {
            "resultData": {"runData": {"MCP Result": [{"data": {"main": [[{"json": "text"}]]}}]}}
        },
    },
    "too_large": {"status": "success", "dataTooLargeToDisplay": True, "data": {}},
    "redacted": {
        "status": "success",
        "data": {"redactionInfo": {"isRedacted": True}, "resultData": {}},
    },
    "oversized": {
        "status": "success",
        "data": {
            "resultData": {
                "runData": {
                    "MCP Result": [
                        {"data": {"main": [[{"json": {"blob": "z" * 70_000}}]]}}
                    ]
                }
            }
        },
    },
}


async def main():
    signed_body = json.dumps(
        {"address": "a@b", "text": "projects.create café", "correlation_id": "c"},
        separators=(",", ":"),
        sort_keys=True,
    )

    fixture = {
        "webhook_tokens": [
            {
                "name": "two_minute_expiry",
                "secret": WEBHOOK_SECRET,
                "run_id": str(RUN),
                "now": 1_763_000_000,
                "token": webhook_token(WEBHOOK_SECRET, str(RUN), 1_763_000_000),
            },
            {
                "name": "another_secret",
                "secret": "another-secret",
                "run_id": str(RUN),
                "now": 1_763_000_001,
                "token": webhook_token("another-secret", str(RUN), 1_763_000_001),
            },
        ],
        "signatures": [
            {
                "name": "compact_utf8",
                "body": signed_body,
                "secret": SECRET,
                "now": 1_763_000_000,
                "headers": signing.sign(signed_body.encode(), SECRET, 1_763_000_000),
            }
        ],
        "decision_text": [
            {
                "name": "approve_with_comment",
                "approval_id": "ap-1",
                "content": {"decision": "approved", "comment": "looks  good\nthanks"},
            },
            {"name": "approve_without_comment", "approval_id": "ap-1",
             "content": {"decision": "approved"}},
            {"name": "reject_with_reason", "approval_id": "ap-2",
             "content": {"decision": "rejected", "reason": "wrong repo"}},
            {"name": "reject_without_reason", "approval_id": "ap-2",
             "content": {"decision": "rejected"}},
            {"name": "no_decision", "approval_id": "ap-3", "content": {}},
        ],
        "sanitize_code": [
            {"name": "lower_and_underscore", "value": "Fr-Bad Code!", "default": "fallback"},
            {"name": "not_a_string", "value": 17, "default": "fallback"},
            {"name": "empty_string", "value": "", "default": "fallback"},
            {"name": "truncated", "value": "a" * 80, "default": "fallback"},
            {"name": "only_punctuation", "value": "!!!", "default": "fallback"},
        ],
        "project_views": [
            {"name": "small", "project": PROJECTS["small"]},
            {"name": "empty", "project": PROJECTS["empty"]},
            {"name": "closed", "project": PROJECTS["closed"]},
            {"name": "oversized_deliverables", "project": PROJECTS["oversized_deliverables"]},
            {"name": "oversized_text", "project": PROJECTS["oversized_text"]},
        ],
        "n8n_results": [],
        "fr_start": [],
        "n8n_start": [],
    }

    for entry in fixture["decision_text"]:
        entry["text"] = decision_text(entry["approval_id"], entry["content"])
    for entry in fixture["sanitize_code"]:
        entry["code"] = sanitize_code(entry["value"], entry["default"])
    for entry in fixture["project_views"]:
        entry["view"] = project_view(entry["project"])
    fixture["close_view"] = close_view(PROJECTS["closed"])

    for name, payload in N8N_PAYLOADS.items():
        state = N8nAdapter._succeeded(row(), payload)
        fixture["n8n_results"].append(
            {
                "name": name,
                "payload": payload,
                "state": {
                    "status": state.status,
                    "result": state.result,
                    "code": state.code,
                    "message": state.message,
                },
            }
        )

    fixture["fr_start"].append(
        await fr_start("pending_approval", {"status": "pending-approval", "approvalId": APPROVAL})
    )
    fixture["fr_start"].append(
        await fr_start(
            "immediate_result", {"status": "result", "result": {"project_id": PROJECT}}
        )
    )
    fixture["fr_start"].append(
        await fr_start("refused", {"status": "no-action", "code": "No Action"})
    )
    fixture["fr_start"].append(
        await fr_start("refused_server", {"status": "error"}, status=503)
    )
    fixture["fr_start"].append(
        await fr_start("command_get", {"status": "result", "result": PROJECTS["small"]},
                       command="projects.get")
    )
    fixture["fr_start"].append(
        await fr_start("command_close", {"status": "result", "result": PROJECTS["closed"]},
                       command="projects.close")
    )

    fixture["n8n_start"].append(await n8n_start("with_webhook_secret", {"executionId": "1216762"}))
    fixture["n8n_start"].append(
        await n8n_start("unauthenticated", {"executionId": "1216762"}, authenticated=False)
    )
    fixture["n8n_start"].append(await n8n_start("missing_execution_id", {}))

    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(fixture, handle, indent=2, ensure_ascii=False)
        handle.write("\n")


asyncio.run(main())
