"""coding.read_file: one working-tree file (or a directory listing) with its hash and line count."""

import coding
import kit
from kit import PASS, check

DEFAULT_SPAN = 400
MAX_SPAN = 2000
FIELDS = (
    "path",
    "type",
    "content",
    "entries",
    "lines_total",
    "start_line",
    "end_line",
    "sha256",
    "size_bytes",
    "truncated",
)


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


def not_found(cn, path):
    parent = path.rsplit("/", 1)[0] if path and "/" in path else None
    arguments = {"container_name": cn}
    if parent:
        arguments["path"] = parent
    return kit.precondition_failed(
        "path_not_found",
        [kit.step(coding.READ_FILE, "the path does not exist; list its parent", arguments)],
    )


async def run(inputs, ctx):
    cn, path = inputs["container_name"], inputs.get("path")
    start, end = inputs.get("start"), inputs.get("end")
    if end is not None and start is not None and not start <= end:
        return kit.precondition_failed(
            "invalid_span",
            [kit.step(coding.READ_FILE, "start must not exceed end", {"container_name": cn})],
        )
    if end is not None and end - (start or 1) + 1 > MAX_SPAN:
        return kit.precondition_failed(
            "span_too_large",
            [kit.step(coding.READ_FILE, f"read at most {MAX_SPAN} lines at a time")],
        )
    await coding.ensure_running(ctx, cn)
    arguments = {"container_name": cn}
    for key, value in (("path", path), ("start", start), ("end", end)):
        if value is not None:
            arguments[key] = value
    try:
        status, body = await kit.call(ctx, "read_file", arguments)
    except RuntimeError as exc:
        if str(exc) != "api_call_denied" or start is not None or end is not None:
            raise
        # An unbounded read of a very large file exceeds the response cap: read the head instead.
        arguments.update(start=1, end=DEFAULT_SPAN)
        status, body = await kit.call(ctx, "read_file", arguments)
    if status == 404:
        return not_found(cn, path)
    if status != 200:
        return coding.unexpected("read_file", status, body)
    data = {k: body[k] for k in FIELDS if body.get(k) is not None}
    what = "directory listing" if body.get("type") == "directory" else "file"
    summary = f"read {what} {kit.clip(body.get('path'), 200)}"
    if body.get("truncated"):
        summary += " (truncated)"
    return kit.completed(data, [check("read", PASS, summary)])
