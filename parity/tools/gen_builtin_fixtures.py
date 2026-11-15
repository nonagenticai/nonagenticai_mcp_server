"""Generate the builtin tool inventory from the pinned Python reference.

Run with the archive's own interpreter, archive root as argv[1], output path as argv[2]:
`uv run --frozen python parity/tools/gen_builtin_fixtures.py <archive> <out>`

The builtin surface has no OpenAPI document, so this file is its contract: every mounted tool's
wire name, description and input schema exactly as the reference's FastMCP server lists them, and
the per-caller scope sets exactly as the reference's scope table derives them. The Rust port
asserts equality against this file, so a tool that is renamed, re-schematised or dropped, or a
scope that grants the wrong set, fails a test instead of reaching a caller.
"""

import asyncio
import json
import os
import sys

# The UOKiK tools are mounted only when the operator enables them, so the inventory is
# generated with them ON (the complete set) and the Rust test asserts the OFF state too.
os.environ["LEGAL_UOKIK_ENABLED"] = "true"

ROOT = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, ROOT)

from src.builtin import create_builtin_server  # noqa: E402
from src.builtin.provider import BuiltinProvider  # noqa: E402
from src.builtin.scope import PRINCIPAL_SCOPES  # noqa: E402


async def inventory() -> dict:
    provider = BuiltinProvider(server=create_builtin_server())
    tools = await provider.server.list_tools()
    entries = []
    for tool in sorted(tools, key=lambda tool: tool.name):
        mcp = tool.to_mcp_tool(name=tool.name)
        entries.append(
            {
                "name": mcp.name,
                "description": mcp.description,
                "input_schema": mcp.inputSchema,
            }
        )
    scopes = {}
    for azp in PRINCIPAL_SCOPES:
        scopes[azp] = sorted(await provider.scopes.allowed(azp))
    # A tenant-level `care-bus` licence gets the care-bus tools plus the researcher set.
    scopes["licence:care-bus"] = sorted(
        set(scopes["carebus-tool-executor"]) | set(scopes["carebus-researcher"])
    )
    return {"tools": entries, "scopes": scopes}


def main() -> None:
    document = asyncio.run(inventory())
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(document, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")
    print(f"{len(document['tools'])} tools, {len(document['scopes'])} scopes", file=sys.stderr)


if __name__ == "__main__":
    main()
