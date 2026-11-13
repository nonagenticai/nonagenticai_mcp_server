"""OpenAPI parity gate, run with coding-testing's own implementation.

    PYTHONPATH=<coding-testing>/src python parity/tools/openapi_diff.py \
        --source-spec source.openapi.json --target-spec target.openapi.json \
        --parity-toml parity.toml

The exclusion list is read from `parity.toml`'s `[openapi_diff.ignore]` — the same file the
deployed parity route reads — so there is exactly one copy of it. The verdict is computed by
`services.openapi_diff.openapi_diff`.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from services.openapi_diff import SpecInput, ignore_rules_from_parity_toml, openapi_diff


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-spec", required=True, type=Path)
    parser.add_argument("--target-spec", required=True, type=Path)
    parser.add_argument("--parity-toml", required=True, type=Path)
    parser.add_argument("--source-name", default="source")
    args = parser.parse_args()

    source = json.loads(args.source_spec.read_text())
    target = json.loads(args.target_spec.read_text())
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
