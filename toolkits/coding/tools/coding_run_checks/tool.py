"""coding.run_checks: lint, compile, tests, quick scan, dependencies and the quality gate."""

import coding
import kit
from kit import check

TOOL = coding.RUN_CHECKS
WALL = 300
TEST_LANGUAGES = {
    "python": "python",
    "go": "go",
    "javascript": "javascript",
    "typescript": "typescript",
}
STAGES = (
    ("lint", 70),
    ("compile", 70),
    ("tests", 150),
    ("security_scan", 70),
    ("dependencies", 90),
    ("quality_gate", 70),
)


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn, language = inputs["container_name"], inputs["language"]
    budget = kit.Budget(WALL, coding.WALL_MARGIN)
    index, checks = 0, []
    if "resume_token" in inputs:
        try:
            state = kit.decode_token(inputs["resume_token"], TOOL)
            if state.get("cn") != cn or state.get("language") != language:
                raise ValueError("resume_token does not match this request")
            index = state["stage"]
            checks = coding.expand(state["checks"])
            if type(index) is not int or not 0 <= index <= len(STAGES):
                raise ValueError("malformed resume_token")
        except (ValueError, KeyError, TypeError) as exc:
            return kit.bad_token(str(exc), TOOL)

    await coding.ensure_running(ctx, cn)
    data = {}
    paths = None
    for position in range(index, len(STAGES)):
        name, need = STAGES[position]
        if not budget.allows(need):
            token = kit.encode_token(
                TOOL,
                {
                    "cn": cn,
                    "language": language,
                    "stage": position,
                    "checks": coding.compact(checks),
                },
            )
            return kit.pending(
                token,
                [step_again(inputs, token, "run_checks ran out of time before " + name)],
                data,
                checks,
            )
        if name == "lint":
            paths, unsafe, _ = await coding.changed_paths(ctx, cn)
            result = await coding.lint_stage(ctx, cn, paths)
            if unsafe:
                result = check(
                    result["name"],
                    result["status"],
                    result["summary"] + f" ({unsafe} paths skipped)",
                )
            checks.append(result)
        elif name == "compile":
            checks.append(await coding.compile_stage(ctx, cn, language))
        elif name == "tests":
            result, tests = await coding.tests_stage(
                ctx, cn, TEST_LANGUAGES[language], inputs.get("test_path"), "unit", 120
            )
            checks.append(result)
            data["tests"] = tests
        elif name == "security_scan":
            checks.append(await coding.scan_stage(ctx, cn))
        elif name == "dependencies":
            checks.append(await coding.deps_stage(ctx, cn))
        else:
            result, gate = await coding.gate_stage(ctx, cn)
            checks.append(result)
            if gate is not None:
                data["quality_gate"] = coding.gate_details(gate)
    sha, _ = await coding.head_sha(ctx, cn)
    data["head_sha"] = sha
    gate = data.get("quality_gate") or {}
    if gate.get("commit_sha") not in (None, sha):
        checks.append(
            check(
                "gate_matches_head",
                "degraded",
                "the quality gate graded a different commit than HEAD",
            )
        )
    return kit.completed(data, checks)


def step_again(inputs, token, reason):
    arguments = {
        "container_name": inputs["container_name"],
        "language": inputs["language"],
        "resume_token": token,
    }
    return kit.step(TOOL, reason, arguments)
