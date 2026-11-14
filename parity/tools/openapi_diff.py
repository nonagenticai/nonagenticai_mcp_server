"""OpenAPI parity gate, run with coding-testing's own implementation.

    PYTHONPATH=<coding-testing>/src python parity/tools/openapi_diff.py \
        --source-spec source.openapi.json --target-spec target.openapi.json \
        --parity-toml parity.toml

The exclusion list is read from `parity.toml`'s `[openapi_diff.ignore]` — the same file the
deployed parity route reads — so there is exactly one copy of it. The verdict is computed by
`services.openapi_diff.openapi_diff`.

`_inline_local_defs` runs first, on both documents. The reference embeds pydantic's
`model_json_schema()` in a request body, where `$id` gives the embedded schema its own resource
root and `$defs` holds what its `#/$defs/...` references point at. The normaliser resolves every
`$ref` against the DOCUMENT root, so those references are unresolvable there — measured
2026-11-14: the source document fails to diff against ITSELF on `#/$defs/ToolManifest`, so
`POST /mcp/tools` and `POST /mcp/tools/{identity}/versions` cannot be compared at all while they
are excluded and would stay incomparable after being ported. Inlining each operation's `$defs`
produces exactly the schema the normaliser would compute under correct `$id` scoping, so the
comparison stays semantic; it is a representation change, not a relaxed one.
"""

from __future__ import annotations

import argparse
import copy
import json
import sys
from pathlib import Path
from typing import Any

from services.openapi_diff import SpecInput, ignore_rules_from_parity_toml, openapi_diff

HTTP_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")


def _collect_defs(node: Any, found: dict[str, Any]) -> None:
    if isinstance(node, dict):
        local = node.get("$defs")
        if isinstance(local, dict):
            found.update(local)
        for value in node.values():
            _collect_defs(value, found)
    elif isinstance(node, list):
        for value in node:
            _collect_defs(value, found)


def _inline(node: Any, defs: dict[str, Any], stack: tuple[str, ...]) -> Any:
    if isinstance(node, dict):
        ref = node.get("$ref")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            name = ref[len("#/$defs/") :]
            if name in stack or name not in defs:
                raise SystemExit(
                    f"parity: cannot inline {ref!r} (recursive or undefined); the gate would "
                    "compare an unresolvable reference"
                )
            target = _inline(copy.deepcopy(defs[name]), defs, (*stack, name))
            extra = _inline({k: v for k, v in node.items() if k != "$ref"}, defs, stack)
            if extra:
                if not isinstance(target, dict):
                    raise SystemExit(f"parity: {ref!r} resolves to a non-object; cannot merge")
                target = {**target, **extra}
            return target
        return {k: _inline(v, defs, stack) for k, v in node.items() if k != "$defs"}
    if isinstance(node, list):
        return [_inline(value, defs, stack) for value in node]
    return node


def _inline_local_defs(document: dict[str, Any]) -> dict[str, Any]:
    """Inline each operation's own local `$defs`; leaves `#/components/...` refs alone.

    Scoped per operation, not per path item: every embedded schema carries its own `$id`, so a
    definition name in one operation has no relationship to the same name in another.
    """
    doc = copy.deepcopy(document)
    paths = doc.get("paths")
    if not isinstance(paths, dict):
        return doc
    for item in paths.values():
        if not isinstance(item, dict):
            continue
        for method in HTTP_METHODS:
            node = item.get(method)
            if not isinstance(node, dict):
                continue
            found: dict[str, Any] = {}
            _collect_defs(node, found)
            if found:
                item[method] = _inline(node, found, ())
    return doc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-spec", required=True, type=Path)
    parser.add_argument("--target-spec", required=True, type=Path)
    parser.add_argument("--parity-toml", required=True, type=Path)
    parser.add_argument("--source-name", default="source")
    args = parser.parse_args()

    source = _inline_local_defs(json.loads(args.source_spec.read_text()))
    target = _inline_local_defs(json.loads(args.target_spec.read_text()))
    rules = ignore_rules_from_parity_toml(args.parity_toml.read_text())
    result = openapi_diff(
        [SpecInput(args.source_name, source)],
        SpecInput("target", target),
        rules,
    )
    print(
        json.dumps(
            {
                "equal": result["equal"],
                "vacuous": result["vacuous"],
                "counts": result["counts"],
                "progress": result["progress"],
                "missing_operations": result["missing_operations"],
                "extra_operations": result["extra_operations"],
                "changed_operations": result["changed_operations"],
                "source_conflicts": result["source_conflicts"],
            },
            indent=1,
        )
    )
    return 0 if result["equal"] else 1


if __name__ == "__main__":
    sys.exit(main())
