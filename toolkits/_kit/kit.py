"""Shared helpers for platform toolkit scripts. Standard library only.

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
