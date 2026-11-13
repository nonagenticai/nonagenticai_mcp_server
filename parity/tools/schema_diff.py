"""Schema parity gate, run with coding-testing's own implementation.

    SRC_DSN=postgresql://... PYTHONPATH=<coding-testing>/src python parity/tools/schema_diff.py \
        --target-dsn postgresql://... [--ignore-kind grant]

The source DSN comes from the environment so it never appears in `ps`. Both sides are
introspected inside `BEGIN READ ONLY`. The verdict is computed by
`services.schema_parity.diff_union` — the same code the deployed
`POST /api/parity/{container}/schema-diff` route runs.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys

from models.parity_schema_models import SchemaDiffOptions
from services.schema_parity import SourceSnapshot, diff_union, introspect_dsn


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-dsn", required=True)
    parser.add_argument("--schemas", nargs="*", default=["public"])
    parser.add_argument(
        "--ignore-kind",
        action="append",
        default=[],
        help="object kind excluded from the comparison (e.g. grant)",
    )
    args = parser.parse_args()

    source_dsn = os.environ.get("SRC_DSN")
    if not source_dsn:
        parser.error("SRC_DSN is not set")

    source = await introspect_dsn(source_dsn, args.schemas)
    target = await introspect_dsn(args.target_dsn, args.schemas)
    result = diff_union(
        [SourceSnapshot("source", source)],
        target,
        SchemaDiffOptions(ignore_kinds=args.ignore_kind),
    )
    out = result.model_dump(mode="json")
    print(
        json.dumps(
            {
                "computed": out["computed"],
                "equal": out["equal"],
                "vacuous": out["vacuous"],
                "summary": out["summary"],
                "missing_in_target": out["missing_in_target"],
                "extra_in_target": out["extra_in_target"],
                "changed": out["changed"],
                "source_conflicts": out["source_conflicts"],
            },
            indent=1,
        )
    )
    return 0 if out["computed"] and out["equal"] else 1


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
