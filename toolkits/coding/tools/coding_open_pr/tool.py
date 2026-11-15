"""coding.open_pr: branch, commit, push, pull request, then wait for CI within a bounded poll."""

import re

import coding
import kit
from kit import DEGRADED, FAIL, PASS, check

TOOL = coding.OPEN_PR
WALL = 300
POLLS = 10
FORK = re.compile(
    r"https://(?:[^/@]+@)?github\.com/([A-Za-z0-9._-]+)/([A-Za-z0-9._-]+?)(?:\.git)?/?"
)


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


def again(inputs, token, reason):
    arguments = {
        k: inputs[k]
        for k in (
            "container_name",
            "branch",
            "commit_message",
            "title",
            "body",
            "original_owner",
            "original_repo",
            "idempotency_key",
        )
    }
    arguments["resume_token"] = token
    return kit.step(TOOL, reason, arguments)


async def wait_for_ci(inputs, ctx, budget, state, checks, data):
    async def fetch():
        return await kit.call(
            ctx,
            "pr_checks",
            {"owner": state["owner"], "repo": state["repo"], "pr_number": state["pr_number"]},
        )

    (status, body), finished = await kit.poll(
        fetch,
        lambda r: r[0] != 200 or r[1].get("verdict") != "pending",
        budget,
        interval=20.0,
        attempts=POLLS,
    )
    if status != 200:
        checks.append(check("ci_checks", DEGRADED, kit.describe(status, body)))
        return kit.completed(data, checks)
    data["ci"] = {
        k: body.get(k)
        for k in ("verdict", "head_sha", "total", "completed", "failed", "failed_names")
    }
    if body.get("verdict") == "passed":
        checks.append(
            check(
                "ci_checks", PASS, f"{body.get('completed')} of {body.get('total')} checks passed"
            )
        )
    elif body.get("verdict") == "failed":
        names = ", ".join(str(n) for n in (body.get("failed_names") or [])[:5])
        checks.append(check("ci_checks", FAIL, "CI failed: " + names))
    else:
        token = kit.encode_token(TOOL, state)
        return kit.pending(token, [again(inputs, token, "CI is still running")], data, checks)
    return kit.completed(data, checks)


async def run(inputs, ctx):
    cn, branch = inputs["container_name"], inputs["branch"]
    budget = kit.Budget(WALL, coding.WALL_MARGIN)
    if "resume_token" in inputs:
        try:
            state = kit.decode_token(inputs["resume_token"], TOOL)
            if state["cn"] != cn or type(state["pr_number"]) is not int:
                raise ValueError("resume_token does not match this request")
        except (ValueError, KeyError) as exc:
            return kit.bad_token(str(exc), TOOL)
        data = {"pr_number": state["pr_number"], "pr_url": state.get("pr_url")}
        return await wait_for_ci(
            inputs, ctx, budget, state, [check("pull_request", PASS, "PR already open")], data
        )

    await coding.ensure_running(ctx, cn)
    checks = []
    await kit.call_ok(
        ctx,
        "ensure_branch",
        {"container_name": cn, "branch": branch},
        what="ensure_branch",
        checks=checks,
    )
    checks.append(check("branch", PASS, "on branch " + branch))

    paths, unsafe, git = await coding.changed_paths(ctx, cn)
    if unsafe:
        return kit.precondition_failed(
            "unsafe_paths",
            [
                kit.step(
                    coding.REPO_STATUS,
                    f"{unsafe} changed paths use characters the gateway refuses",
                    {"container_name": cn},
                )
            ],
            checks,
        )
    if paths or git.get("deleted_files"):
        files = list(
            dict.fromkeys(paths + [p for p in git.get("deleted_files", []) if coding.safe_path(p)])
        )[:100]
        body = await kit.call_ok(
            ctx,
            "commit",
            {"container_name": cn, "message": inputs["commit_message"], "files": files},
            what="commit",
            checks=checks,
        )
        checks.append(check("commit", PASS, f"{body.get('files_committed')} files committed"))
    else:
        checks.append(check("commit", DEGRADED, "nothing to commit; reusing HEAD"))

    # The gate grades HEAD only on a clean tree (a dirty tree is graded as "no commit"), so it
    # must run after the commit, against the new HEAD.
    commit_sha, _ = await coding.head_sha(ctx, cn)
    gate_check, gate = await coding.gate_stage(ctx, cn)
    checks.append(gate_check)
    language = inputs.get("language", "python")
    details = {"quality_gate": coding.gate_details(gate)} if gate is not None else None
    if gate is None or gate.get("passed") is not True:
        return kit.precondition_failed(
            "quality_gate_not_passed",
            [
                coding.checks_step(
                    cn,
                    language,
                    "the quality gate did not pass on the committed change (the commit is local "
                    "on the branch and not pushed); read the details, fix with coding_write_code, "
                    "then call coding_open_pr again",
                ),
                kit.step(coding.WRITE_CODE, "fix what the gate reports, then call coding_open_pr"),
            ],
            checks,
            details,
        )
    if gate.get("commit_sha") != commit_sha:
        return kit.precondition_failed(
            "quality_gate_stale",
            [
                coding.checks_step(
                    cn,
                    language,
                    "the gate graded a different commit than HEAD (the commit is local and "
                    "not pushed)",
                )
            ],
            checks,
            details,
        )

    body = await kit.call_ok(
        ctx, "push", {"container_name": cn, "branch": branch}, what="push", checks=checks
    )
    match = FORK.fullmatch(str(body.get("remote_url", "")))
    if match is None:
        return kit.backend_error(
            "push succeeded but its target repository could not be identified", False, checks
        )
    fork_owner, fork_repo = match.group(1), match.group(2)
    checks.append(check("push", PASS, f"pushed to {fork_owner}/{fork_repo}"))

    pr = await kit.call_ok(
        ctx,
        "create_pr",
        {
            "fork_owner": fork_owner,
            "fork_repo": fork_repo,
            "original_owner": inputs["original_owner"],
            "original_repo": inputs["original_repo"],
            "head_branch": branch,
            "base_branch": inputs.get("base_branch", "main"),
            "title": inputs["title"],
            "message": inputs["body"],
        },
        what="create_pr",
        checks=checks,
    )
    number = pr.get("pr_number")
    if type(number) is not int:
        return kit.backend_error(
            "no pull request was created: " + kit.clip(pr.get("message", ""), 200), False, checks
        )
    checks.append(check("pull_request", PASS, f"PR #{number} {pr.get('pr_status')}"))
    data = {"pr_number": number, "pr_url": pr.get("pr_url"), "head_sha": commit_sha}
    state = {
        "cn": cn,
        "owner": inputs["original_owner"],
        "repo": inputs["original_repo"],
        "pr_number": number,
        "pr_url": kit.clip(pr.get("pr_url") or "", 200),
    }
    return await wait_for_ci(inputs, ctx, budget, state, checks, data)
