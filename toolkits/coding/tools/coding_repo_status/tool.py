"""coding.repo_status: provisioned / indexed / head_sha / dirty, the facts other tools reuse."""

import coding
import kit
from kit import DEGRADED, PASS, check


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn = inputs["container_name"]
    status, body = await kit.call(ctx, "workspace_status", {"container_name": cn})
    if status == 404:
        data = {"provisioned": False, "running": False, "indexed": False}
        return kit.completed(
            data, (), [coding.provision_step(cn, "the repository is not provisioned")]
        )
    if status != 200:
        return coding.unexpected("workspace_status", status, body)
    state = body.get("container_status")
    data = {"provisioned": True, "container_status": state, "running": state == "running"}
    checks = [
        check(
            "workspace_running", PASS if state == "running" else DEGRADED, f"workspace is {state}"
        )
    ]
    next_steps = []
    if state != "running":
        data["indexed"] = False
        next_steps.append(coding.provision_step(cn, f"the workspace is {state}"))
        return kit.completed(data, checks, next_steps)
    graph = await coding.graph_info(ctx, cn)
    data["indexed"] = coding.indexed(graph)
    if graph:
        data["node_count"] = graph.get("node_count")
        data["edge_count"] = graph.get("edge_count")
    checks.append(
        check(
            "graph_indexed",
            PASS if data["indexed"] else DEGRADED,
            "graph present" if data["indexed"] else "graph missing or empty",
        )
    )
    if not data["indexed"]:
        next_steps.append(coding.provision_step(cn, "build the code graph"))
    status, git = await kit.call(ctx, "git_status", {"container_name": cn})
    if status != 200:
        return coding.unexpected("git_status", status, git)
    sha, _ = await coding.head_sha(ctx, cn)
    dirty = coding.is_dirty(git)
    data.update(
        head_sha=sha,
        branch=git.get("branch"),
        dirty=dirty,
        modified_files=[f for f in (git.get("modified_files") or [])[:50]],
        new_files=[f for f in (git.get("new_files") or [])[:50]],
        deleted_files=[f for f in (git.get("deleted_files") or [])[:50]],
    )
    checks.append(
        check(
            "clean_tree", DEGRADED if dirty else PASS, "uncommitted changes" if dirty else "clean"
        )
    )
    return kit.completed(data, checks, next_steps)
