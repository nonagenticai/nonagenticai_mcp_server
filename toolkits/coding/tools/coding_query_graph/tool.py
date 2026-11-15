"""coding.query_graph: one read of the code graph (nodes, edges, architecture, dependencies)."""

import coding
import kit
from kit import PASS, check, step

TOOL = "coding_query_graph"
FILTERS = {"nodes": ("node_type", "name_pattern"), "edges": ("edge_type",)}


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn, query = inputs["container_name"], inputs["query"]
    given = [k for k in ("node_type", "name_pattern", "edge_type") if k in inputs]
    allowed = FILTERS.get(query, ())
    if [k for k in given if k not in allowed] or len(given) > 1:
        return kit.precondition_failed(
            "invalid_query_filter",
            [step(TOOL, f"{query} accepts at most one of {list(allowed) or 'no filter'}")],
        )
    await coding.ensure_running(ctx, cn)
    graph = await coding.require_indexed(ctx, cn)
    page, limit = inputs.get("page", 1), inputs.get("limit", 20)
    if query == "nodes":
        key, args = "list_nodes", {"container_name": cn, "page": page, "limit": limit}
        if "node_type" in inputs:
            key, args = "list_nodes_by_type", {**args, "node_type": inputs["node_type"]}
        elif "name_pattern" in inputs:
            key, args = "list_nodes_by_name", {**args, "name_pattern": inputs["name_pattern"]}
    elif query == "edges":
        key, args = "list_edges", {"container_name": cn, "page": page, "limit": limit}
        if "edge_type" in inputs:
            key, args = "list_edges_by_type", {**args, "edge_type": inputs["edge_type"]}
    elif query == "architecture":
        key = "graph_augmented"
        args = {"container_name": cn, "limit": min(limit * 4, 200), "offset": (page - 1) * limit}
    else:
        key, args = "arch_dependencies", {"container_name": cn}
    body = await kit.call_ok(ctx, key, args, what=query)
    data = {
        "query": query,
        "node_count": graph.get("node_count"),
        "edge_count": graph.get("edge_count"),
        "result": body,
    }
    return kit.completed(data, [check("graph_query", PASS, f"{query} read")])
