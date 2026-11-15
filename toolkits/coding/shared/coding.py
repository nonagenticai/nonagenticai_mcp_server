"""Coding-toolkit logic shared by the tool scripts (copied into each package as coding.py).

Stdlib plus kit/ops only. Everything reaches the coding gateway through kit.call.
"""

import re

import kit
from kit import DEGRADED, ERROR, FAIL, PASS, Abort, call, check, clip, describe, step

PROVISION = "coding_provision_repo"
REPO_STATUS = "coding_repo_status"
RUN_CHECKS = "coding_run_checks"
WRITE_CODE = "coding_write_code"
OPEN_PR = "coding_open_pr"
SECURITY_AUDIT = "coding_security_audit"
UPDATE_DEPENDENCIES = "coding_update_dependencies"
READ_FILE = "coding_read_file"

WALL_MARGIN = 25.0
LANGUAGES = ("python", "go", "javascript", "typescript")
TEST_LANGUAGES = (
    "python",
    "javascript",
    "typescript",
    "nodejs",
    "go",
    "rust",
    "java",
    "csharp",
    "cpp",
)

# The exact commands the exec operation's scope rule admits (the gateway allow-lists binaries,
# not arguments; the rule is what keeps exec from being a general shell).
PY_SYNTAX = (
    "import ast,pathlib,sys\n"
    "bad=[]\n"
    "for p in pathlib.Path('.').rglob('*.py'):\n"
    " if any(s in p.parts for s in ('.git','node_modules','.venv','venv','__pycache__')):\n"
    "  continue\n"
    " try:\n"
    "  ast.parse(p.read_text(encoding='utf-8'),str(p))\n"
    " except Exception as e:\n"
    "  bad.append(str(p)+': '+str(e))\n"
    "print('\\n'.join(bad[:20]))\n"
    "sys.exit(1 if bad else 0)"
)
COMPILE = {"python": ["python", "-c", PY_SYNTAX], "go": ["go", "build", "./..."]}
COMPILE_TIMEOUT = {"python": 60, "go": 120}
NOT_COMPILED = {
    "javascript": "javascript has no compile step on the gateway allow-list; not verified",
    "typescript": (
        "tsc is not on the coding gateway exec allow-list (needs a coding-gateway change); "
        "typescript compile is not verified"
    ),
}

_SEGMENT = re.compile(r"[A-Za-z0-9._@+=,~-]+")
_PACKAGE = re.compile(r"[A-Za-z0-9@][A-Za-z0-9._/@+-]*")


def safe_path(path):
    """Mirror of the platform's relative-path format (src/catalog/formats.py)."""
    if not isinstance(path, str) or not 1 <= len(path) <= 1024 or path.startswith("/"):
        return False
    return all(s not in (".", "..") and _SEGMENT.fullmatch(s) for s in path.split("/"))


def safe_package(name):
    """Mirror of the platform's package-name format (src/catalog/formats.py)."""
    if not isinstance(name, str) or not 1 <= len(name) <= 128 or not _PACKAGE.fullmatch(name):
        return False
    return ".." not in name and "//" not in name and not name.endswith("/")


def provision_step(cn, reason):
    return step(PROVISION, reason, {"container_name": cn})


def checks_step(cn, language, reason):
    return step(RUN_CHECKS, reason, {"container_name": cn, "language": language})


def unexpected(what, status, body):
    return kit.backend_error(f"{what}: {describe(status, body)}", retryable=status >= 500)


# --- preconditions -----------------------------------------------------------------------------


async def ensure_running(ctx, cn):
    """P: the workspace exists and is running, else ends the tool with precondition_failed."""
    status, body = await call(ctx, "workspace_status", {"container_name": cn})
    if status == 404:
        raise Abort(
            kit.precondition_failed(
                "not_provisioned", [provision_step(cn, "the workspace does not exist")]
            )
        )
    if status != 200:
        raise Abort(unexpected("workspace_status", status, body))
    state = body.get("container_status")
    if state != "running":
        raise Abort(
            kit.precondition_failed(
                "workspace_not_running",
                [provision_step(cn, f"the workspace is {clip(state, 40)}")],
                data={"container_status": state},
            )
        )
    return state


async def graph_info(ctx, cn):
    """The graph record, or None when there is none."""
    status, body = await call(ctx, "get_graph", {"container_name": cn})
    if status == 404:
        return None
    if status != 200:
        raise Abort(unexpected("get_graph", status, body))
    graph = body.get("graph") if isinstance(body, dict) else None
    return graph if isinstance(graph, dict) else None


def indexed(graph):
    count = graph.get("node_count") if isinstance(graph, dict) else None
    return type(count) is int and count > 0


async def require_indexed(ctx, cn):
    """G: the graph exists with node_count > 0."""
    graph = await graph_info(ctx, cn)
    if not indexed(graph):
        raise Abort(
            kit.precondition_failed(
                "not_indexed", [provision_step(cn, "the code graph is missing or empty")]
            )
        )
    return graph


async def head_sha(ctx, cn, max_bytes=1024):
    """HEAD sha (git/status has none; git/diff reports base_sha) and the diff body."""
    status, body = await call(ctx, "git_diff", {"container_name": cn, "max_bytes": max_bytes})
    if status != 200:
        raise Abort(unexpected("git_diff", status, body))
    sha = body.get("base_sha")
    if not isinstance(sha, str) or not sha:
        raise Abort(kit.backend_error("git_diff returned no base_sha", True))
    return sha, body


async def changed_paths(ctx, cn):
    """(safe changed paths, unsafe count, git status body)."""
    status, body = await call(ctx, "git_status", {"container_name": cn})
    if status != 200:
        raise Abort(unexpected("git_status", status, body))
    names = []
    for field in ("modified_files", "new_files"):
        value = body.get(field)
        if isinstance(value, list):
            names.extend(v for v in value if isinstance(v, str))
    safe = [n for n in dict.fromkeys(names) if safe_path(n)]
    return safe, len(set(names)) - len(safe), body


def is_dirty(status_body):
    for field in ("modified_files", "new_files", "deleted_files"):
        if status_body.get(field):
            return True
    return bool(status_body.get("staged_changes") or status_body.get("unstaged_changes"))


# --- check stages ------------------------------------------------------------------------------
# Each stage returns one check (never raises for a backend refusal), so the caller can always
# report every stage that ran. A denied or failed call becomes an "error" check.


def _denied(name, exc):
    if isinstance(exc, RuntimeError) and str(exc) == "api_call_denied":
        return check(name, ERROR, "the gateway call failed or was denied")
    raise exc


# Files the analyzer lints; anything else (lockfiles, manifests, docs) is out of its scope and
# sending only such files earns a 422 ("no analyzable source files"), which is not a finding.
LINTABLE = (".py", ".pyi", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx", ".go")


async def lint_stage(ctx, cn, paths):
    paths = [p for p in paths if p.lower().endswith(LINTABLE)]
    if not paths:
        return check("lint", PASS, "no changed source files to lint")
    try:
        status, body = await call(
            ctx, "quality_analyze_sync", {"container_name": cn, "paths": paths[:50]}
        )
    except RuntimeError as exc:
        return _denied("lint", exc)
    if status == 422:
        return check(
            "lint", DEGRADED, "no analyzable source files in scope: " + describe(status, body)
        )
    if status != 200:
        return check("lint", ERROR, describe(status, body))
    issues = body.get("issues")
    total = body.get("total_issues")
    if type(total) is not int:
        total = len(issues) if isinstance(issues, list) else None
    severe = 0
    if isinstance(issues, list):
        for issue in issues:
            if isinstance(issue, dict) and str(issue.get("severity", "")).lower() in (
                "critical",
                "high",
                "error",
            ):
                severe += 1
    if body.get("inconclusive") or body.get("error"):
        return check("lint", DEGRADED, "lint was inconclusive: " + clip(body.get("error", ""), 200))
    if severe:
        return check("lint", FAIL, f"{severe} high-severity issues of {total}")
    if total is None:
        return check("lint", DEGRADED, "lint result shape not recognised")
    return check("lint", PASS, f"{total} issues, none high severity")


async def compile_stage(ctx, cn, language):
    command = COMPILE.get(language)
    if command is None:
        return check("compile", DEGRADED, NOT_COMPILED.get(language, "no compile command"))
    try:
        status, body = await call(
            ctx,
            "exec",
            {"container_name": cn, "command": command, "timeout": COMPILE_TIMEOUT[language]},
        )
    except RuntimeError as exc:
        return _denied("compile", exc)
    if status != 200:
        return check("compile", ERROR, describe(status, body))
    code = body.get("exit_code")
    if code == 0:
        return check("compile", PASS, f"{language} compile check passed")
    tail = clip((body.get("stdout") or "") + (body.get("stderr") or ""), 350)
    return check("compile", FAIL, f"exit {code}: {tail}")


async def scan_stage(ctx, cn):
    try:
        status, body = await call(ctx, "security_quick", {"container_name": cn})
    except RuntimeError as exc:
        return _denied("security_scan", exc)
    if status != 200:
        return check("security_scan", ERROR, describe(status, body))
    return scan_check("security_scan", body.get("result") if isinstance(body, dict) else None)


def scan_check(name, result):
    if not isinstance(result, dict):
        return check(name, DEGRADED, "scan result shape not recognised")
    critical = result.get("critical_count", 0)
    high = result.get("high_count", 0)
    if type(critical) is int and type(high) is int and (critical or high):
        return check(name, FAIL, f"{critical} critical, {high} high findings")
    if result.get("scan_degraded"):
        reasons = result.get("degraded_reasons")
        why = "; ".join(str(r) for r in reasons[:3]) if isinstance(reasons, list) else "unknown"
        return check(name, DEGRADED, "scan_degraded: " + why)
    if "total_vulnerabilities" not in result:
        return check(name, DEGRADED, "scan result shape not recognised")
    return check(name, PASS, f"{result.get('total_vulnerabilities')} findings, none critical/high")


async def deps_stage(ctx, cn):
    try:
        status, body = await call(ctx, "deps_scan", {"container_name": cn})
    except RuntimeError as exc:
        return _denied("dependencies", exc)
    if status != 200:
        return check("dependencies", ERROR, describe(status, body))
    summary = body.get("summary") if isinstance(body, dict) else None
    if not isinstance(summary, dict):
        return check("dependencies", DEGRADED, "dependency summary not recognised")
    critical = summary.get("critical_vulnerabilities", 0)
    high = summary.get("high_vulnerabilities", 0)
    if type(critical) is int and type(high) is int and (critical or high):
        return check("dependencies", FAIL, f"{critical} critical, {high} high vulnerabilities")
    return check(
        "dependencies", PASS, f"{summary.get('vulnerable_packages', 0)} vulnerable packages"
    )


async def tests_stage(ctx, cn, language, test_path, test_type, timeout):
    """(check, data) for one test run; test output is read best-effort afterwards."""
    args = {
        "container_name": cn,
        "language": language,
        "test_type": test_type,
        "timeout": timeout,
    }
    key = "tests_execute_all"
    if test_path:
        key, args["test_path"] = "tests_execute", test_path
    try:
        status, body = await call(ctx, key, args)
    except RuntimeError as exc:
        return _denied("tests", exc), None
    if status != 200:
        return check("tests", ERROR, describe(status, body)), None
    data = {k: body.get(k) for k in ("test_id", "success", "exit_code", "execution_time", "error")}
    output = None
    test_id = body.get("test_id")
    if isinstance(test_id, str) and test_id:
        try:
            code, raw = await call(ctx, "test_result", {"container_name": cn, "test_id": test_id})
            if code == 200 and isinstance(raw, dict):
                output = clip((raw.get("stdout") or "") + (raw.get("stderr") or ""), 3000)
        except RuntimeError:
            output = None
    data["output_tail"] = output
    if body.get("success") is True and body.get("exit_code") == 0:
        return check("tests", PASS, "tests passed"), data
    return check("tests", FAIL, f"tests failed (exit {body.get('exit_code')})"), data


def _number(value):
    return (
        round(value, 1)
        if isinstance(value, (int, float)) and not isinstance(value, bool)
        else value
    )


def gate_details(body):
    """The gate fields an agent needs to act on a failure, clipped to sane sizes."""
    failing = []
    for c in body.get("gate_checks") or []:
        if isinstance(c, dict) and c.get("passed") is False:
            failing.append(
                {
                    "name": clip(c.get("name"), 64),
                    "actual": _number(c.get("actual")),
                    "threshold": _number(c.get("threshold")),
                    "description": clip(c.get("description") or "", 160),
                }
            )
    tools_failed = [clip(t, 64) for t in (body.get("tools_failed") or [])[:10]]
    return {
        "passed": body.get("passed"),
        "overall_score": _number(body.get("overall_score")),
        "grade": body.get("grade"),
        "partial": body.get("partial"),
        "inconclusive": body.get("inconclusive"),
        "commit_sha": body.get("commit_sha"),
        "source": body.get("source"),
        "tools_failed": tools_failed,
        "failing_checks": failing[:8],
        "recommendations": [clip(r, 200) for r in (body.get("recommendations") or [])[:3]],
    }


def gate_summary(body):
    d = gate_details(body)
    parts = [f"score {d['overall_score']} grade {d['grade']}"]
    if d["partial"]:
        parts.append("partial (grade from a subset of tools)")
    if d["tools_failed"]:
        parts.append("tools failed: " + ", ".join(d["tools_failed"][:5]))
    failing = [
        f"{c['name']} {c['actual']} vs {c['threshold']}"
        if c["actual"] is not None and c["threshold"] is not None
        else f"{c['name']}: {c['description']}"
        for c in d["failing_checks"][:5]
    ]
    if failing:
        parts.append("failing: " + ", ".join(failing))
    if d["recommendations"]:
        parts.append("recommendations: " + " | ".join(clip(r, 80) for r in d["recommendations"]))
    return "; ".join(parts)


async def gate_stage(ctx, cn):
    """(check, gate body or None)."""
    try:
        status, body = await call(ctx, "quality_gate", {"container_name": cn})
    except RuntimeError as exc:
        return _denied("quality_gate", exc), None
    if status != 200:
        return check("quality_gate", ERROR, describe(status, body)), None
    summary = gate_summary(body)
    if body.get("passed") is True:
        return check("quality_gate", PASS, summary), body
    if body.get("inconclusive"):
        return check("quality_gate", ERROR, "gate inconclusive: " + summary), body
    return check("quality_gate", FAIL, summary), body


def baseline_from(body):
    """Cycle signatures as the gate request needs them, or None when not usable."""
    cycles = body.get("cycles") if isinstance(body, dict) else None
    if not isinstance(cycles, list) or len(cycles) > 500:
        return None
    out = []
    for cycle in cycles:
        if isinstance(cycle, str):
            cycle = [cycle]
        if not isinstance(cycle, list) or len(cycle) > 64:
            return None
        if not all(isinstance(c, str) and len(c) <= 512 for c in cycle):
            return None
        out.append(cycle)
    return out


async def cycle_baseline(ctx, cn):
    """Baseline cycle signatures, or None (the gate then degrades)."""
    try:
        status, body = await call(ctx, "cycle_baseline", {"container_name": cn})
    except RuntimeError:
        return None
    return baseline_from(body) if status == 200 else None


async def cycle_stage(ctx, cn, baseline):
    if baseline is None:
        return check("cycle_gate", DEGRADED, "no cycle baseline could be captured; gate not run")
    try:
        status, body = await call(
            ctx, "cycle_check", {"container_name": cn, "baseline_cycles": baseline}
        )
    except RuntimeError as exc:
        return _denied("cycle_gate", exc)
    if status != 200:
        return check("cycle_gate", ERROR, describe(status, body))
    if body.get("success") is False:
        return check("cycle_gate", FAIL, "the change introduced a new dependency cycle")
    if body.get("grounded") is False:
        return check(
            "cycle_gate",
            DEGRADED,
            "no usable graph: " + clip(body.get("ungrounded_reason", ""), 200),
        )
    return check("cycle_gate", PASS, "no new dependency cycles")


def compact(checks):
    return [[c["name"], c["status"], clip(c["summary"], 90)] for c in checks]


def expand(rows):
    out = []
    for row in rows:
        if not (isinstance(row, list) and len(row) == 3 and all(isinstance(x, str) for x in row)):
            raise ValueError("malformed resume state")
        out.append(check(row[0], row[1], row[2]))
    return out
