"""coding.write_code: write files, read the change back, then ALWAYS run the code checks."""

import coding
import kit
from kit import DEGRADED, PASS, check

TOOL = coding.WRITE_CODE
WALL = 300
# Conservative seconds each stage needs; a stage that does not fit ends the call as pending
# with run_checks as the next tool, never as a silent skip.
STAGES = (("lint", 70), ("compile", 70), ("security_scan", 70), ("cycle_gate", 70))


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn, language, files = inputs["container_name"], inputs["language"], inputs["files"]
    paths = [f["path"] for f in files]
    if len(set(paths)) != len(paths):
        return kit.precondition_failed(
            "duplicate_paths", [kit.step(TOOL, "each path may appear once per call")]
        )
    budget = kit.Budget(WALL, coding.WALL_MARGIN)
    await coding.ensure_running(ctx, cn)
    before, _ = await coding.head_sha(ctx, cn)

    baseline = None
    if coding.indexed(await coding.graph_info(ctx, cn)):
        baseline = await coding.cycle_baseline(ctx, cn)

    for f in files:
        await kit.call_ok(
            ctx,
            "write_file",
            {"container_name": cn, "file_path": f["path"], "content": f["content"]},
            what="write_file " + f["path"][:100],
        )

    # Read-back: the gateway's own view of what changed (x-verifies of write-file).
    _, diff = await coding.head_sha(ctx, cn, max_bytes=4096)
    changed = {x.get("path") for x in diff.get("files", []) if isinstance(x, dict)}
    changed |= {p for p in diff.get("untracked_files", []) if isinstance(p, str)}
    unchanged = [p for p in paths if p not in changed]
    checks = [
        check(
            "write_verified",
            DEGRADED if unchanged else PASS,
            (
                "not visible as changed (identical content or failed write): "
                + ", ".join(unchanged[:6])
            )
            if unchanged
            else f"{len(paths)} files visible in the working tree diff",
        )
    ]
    data = {
        "head_sha": before,
        "written": paths,
        "diff": (diff.get("diff") or "")[:4000],
        "diff_truncated": bool(diff.get("truncated")) or len(diff.get("diff") or "") > 4000,
    }

    for name, need in STAGES:
        if not budget.allows(need):
            token = kit.encode_token(TOOL, {"cn": cn, "language": language})
            return kit.pending(
                token,
                [coding.checks_step(cn, language, "write_code ran out of time before " + name)],
                data,
                checks,
            )
        if name == "lint":
            checks.append(await coding.lint_stage(ctx, cn, paths))
        elif name == "compile":
            checks.append(await coding.compile_stage(ctx, cn, language))
        elif name == "security_scan":
            checks.append(await coding.scan_stage(ctx, cn))
        else:
            checks.append(await coding.cycle_stage(ctx, cn, baseline))
    return kit.completed(data, checks)
