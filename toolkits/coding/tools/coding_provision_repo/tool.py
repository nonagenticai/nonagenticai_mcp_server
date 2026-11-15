"""coding.provision_repo: import a repository, wait for the workspace, build the graph."""

import coding
import kit
from kit import FAIL, PASS, check, step

TOOL = coding.PROVISION
WALL = 300
# initialize_graph is one synchronous gateway call; do not start it without this much time.
GRAPH_NEEDS = 110
POLLS = 15


def resume_step(inputs, reason):
    arguments = {k: inputs[k] for k in ("container_name", "repo_url", "branch")}
    arguments["idempotency_key"] = inputs["idempotency_key"]
    return step(TOOL, reason, arguments)


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn = inputs["container_name"]
    budget = kit.Budget(WALL, coding.WALL_MARGIN)
    if not cn[0].isalpha():
        return kit.precondition_failed(
            "invalid_container_name",
            [step(TOOL, "the gateway requires a name that starts with a letter")],
        )
    stage = "start"
    if "resume_token" in inputs:
        try:
            state = kit.decode_token(inputs["resume_token"], TOOL)
        except ValueError as exc:
            return kit.bad_token(str(exc), TOOL)
        if state.get("cn") != cn or state.get("stage") not in ("running", "graph"):
            return kit.bad_token("resume_token does not match this request", TOOL)
        stage = state["stage"]

    idempotent = False
    if stage == "start":
        status, body = await kit.call(ctx, "workspace_status", {"container_name": cn})
        if status == 200 and body.get("container_status") == "running":
            graph = await coding.graph_info(ctx, cn)
            if coding.indexed(graph):
                idempotent = True
                stage = "done"
            else:
                stage = "graph"
        elif status == 200 and body.get("container_status") == "creating":
            stage = "running"
        elif status in (200, 404):
            stage = "import"
        else:
            return coding.unexpected("workspace_status", status, body)

    if stage == "import":
        body = await kit.call_ok(
            ctx,
            "import_repository",
            {"repo_url": inputs["repo_url"], "branch": inputs["branch"], "container_name": cn},
            what="import_repository",
        )
        if not isinstance(body.get("container"), dict):
            return kit.backend_error("import_repository returned no container", False)
        stage = "running"

    if stage == "running":

        async def fetch():
            status, body = await kit.call(ctx, "workspace_status", {"container_name": cn})
            if status != 200:
                raise kit.Abort(coding.unexpected("workspace_status", status, body))
            return body.get("container_status")

        state, finished = await kit.poll(
            fetch,
            lambda s: s in ("running", "error", "stopped"),
            budget,
            interval=4.0,
            reserve=GRAPH_NEEDS,
            attempts=POLLS,
        )
        if state in ("error", "stopped"):
            return kit.backend_error(f"the workspace ended in state {state}", False)
        if not finished:
            return kit.pending(
                kit.encode_token(TOOL, {"cn": cn, "stage": "running"}),
                [resume_step(inputs, "the workspace is still being created")],
                data={"container_status": state},
            )
        stage = "graph"

    if stage == "graph":
        if not budget.allows(GRAPH_NEEDS):
            return kit.pending(
                kit.encode_token(TOOL, {"cn": cn, "stage": "graph"}),
                [resume_step(inputs, "not enough time left to build the graph")],
                data={"container_status": "running"},
            )
        # Provisioning already kicks off an auto-index scan, so the graph may exist by now:
        # analysis answers 409 for an existing graph, and graph_indexed below grades it.
        status, body = await kit.call(ctx, "initialize_graph", {"container_name": cn})
        if status not in (200, 409):
            return coding.unexpected("initialize_graph", status, body)

    graph = await coding.graph_info(ctx, cn)
    sha, _ = await coding.head_sha(ctx, cn)
    checks = [
        check("workspace_running", PASS, "workspace is running"),
        check(
            "graph_indexed",
            PASS if coding.indexed(graph) else FAIL,
            f"{(graph or {}).get('node_count', 0)} nodes, {(graph or {}).get('edge_count', 0)} edges",
        ),
        check("head_sha", PASS, sha),
    ]
    data = {
        "container_name": cn,
        "head_sha": sha,
        "node_count": (graph or {}).get("node_count"),
        "edge_count": (graph or {}).get("edge_count"),
        "already_provisioned": idempotent,
    }
    next_steps = [step(coding.REPO_STATUS, "inspect the workspace", {"container_name": cn})]
    return kit.completed(data, checks, next_steps)
