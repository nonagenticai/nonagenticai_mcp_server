"""coding.security_audit: async security scan (bounded poll), dependency scan, SBOM."""

import coding
import kit
from kit import DEGRADED, ERROR, FAIL, PASS, check

TOOL = coding.SECURITY_AUDIT
WALL = 300
POLLS = 24


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


def again(inputs, token, reason):
    arguments = {"container_name": inputs["container_name"], "resume_token": token}
    return kit.step(TOOL, reason, arguments)


async def run(inputs, ctx):
    cn = inputs["container_name"]
    budget = kit.Budget(WALL, coding.WALL_MARGIN)
    task_id = None
    checks = []
    if "resume_token" in inputs:
        try:
            state = kit.decode_token(inputs["resume_token"], TOOL)
            task_id = state["task_id"]
            if state.get("cn") != cn or not isinstance(task_id, str):
                raise ValueError("resume_token does not match this request")
        except (ValueError, KeyError) as exc:
            return kit.bad_token(str(exc), TOOL)
    await coding.ensure_running(ctx, cn)

    if task_id is None:
        try:
            status, body = await kit.call(ctx, "security_async", {"container_name": cn})
        except RuntimeError:  # 503 (no results store) is not an expected status: denied
            status, body = 503, None
        if status == 200 and isinstance(body.get("task_id"), str):
            task_id = body["task_id"]
        else:
            checks.append(
                check(
                    "scan_degraded",
                    DEGRADED,
                    "async scan unavailable (" + kit.describe(status, body) + "); quick scan used",
                )
            )

    data = {}
    if task_id is not None:

        async def fetch():
            return await kit.call(ctx, "security_result", {"task_id": task_id})

        (status, body), finished = await kit.poll(
            fetch,
            lambda r: r[0] != 200 or r[1].get("status") in ("completed", "failed"),
            budget,
            interval=5.0,
            reserve=90.0,
            attempts=POLLS,
        )
        if not finished:
            token = kit.encode_token(TOOL, {"cn": cn, "task_id": task_id})
            return kit.pending(
                token,
                [again(inputs, token, "the security scan is still running")],
                {"task_id": task_id},
                checks,
            )
        if status != 200:
            checks.append(check("security_scan", ERROR, kit.describe(status, body)))
        elif body.get("status") == "failed":
            checks.append(check("security_scan", ERROR, "the scan task failed"))
        else:
            result = body.get("result")
            checks.append(
                coding.scan_check("security_scan", result if isinstance(result, dict) else body)
            )
    else:
        checks.append(await coding.scan_stage(ctx, cn))

    checks.append(await coding.deps_stage(ctx, cn))

    try:
        status, body = await kit.call(ctx, "deps_vulnerable", {"container_name": cn})
    except RuntimeError:  # the gateway answers 503 when an OSV lookup failed
        status, body = 503, None
    if status == 200 and isinstance(body, list):
        packages = [
            {
                "name": p.get("name"),
                "version": p.get("version"),
                "severity": p.get("severity"),
                "fixed_versions": p.get("fixed_versions"),
            }
            for p in body[:20]
            if isinstance(p, dict)
        ]
        data["vulnerable_packages"] = packages
        data["vulnerable_package_count"] = len(body)
        checks.append(
            check(
                "vulnerable_packages",
                FAIL if body else PASS,
                f"{len(body)} packages with known vulnerabilities",
            )
        )
    else:
        checks.append(check("vulnerable_packages", ERROR, kit.describe(status, body)))

    status, body = await kit.call(ctx, "sbom", {"container_name": cn})
    if status == 200 and body.get("status") in ("success", "completed"):
        checks.append(check("sbom", PASS, kit.clip(body.get("message", "SBOM generated"), 200)))
    elif status == 200:
        summary = f"SBOM status {kit.clip(body.get('status'), 40)}"
        if body.get("message"):
            summary += ": " + kit.clip(body.get("message"), 200)
        checks.append(check("sbom", DEGRADED, summary))
    else:
        checks.append(check("sbom", ERROR, kit.describe(status, body)))
    if task_id:
        data["task_id"] = task_id
    return kit.completed(data, checks)
