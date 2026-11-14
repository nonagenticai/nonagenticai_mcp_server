#!/usr/bin/env python3
"""Generate ``pod.json``: the golden Kata pod manifest for one fencing generation of a run.

The oracle is the pinned Python service's ``src/execution/kata.py`` (commit 22ac1ce4). The
``pod`` object below is *produced by* ``kata.pod_manifest`` executing against the archive's real
``ToolManifest``, ``Settings`` and ``ToolLimits`` models, so a Rust test that rebuilds it is
reading the Python implementation, not a paraphrase of it. Every input is recorded beside the
output so a failure says which of them disagrees.

Usage (the archive's project environment, not the system interpreter: ``kata.py`` imports the
execution service and pydantic models):

    ORACLE=/path/to/nonagenticai_mcp_server-python-archive \
        /path/to/nonagenticai_mcp_server-python-archive/.venv/bin/python -I \
        tests/fixtures/phase3b/generate_pod.py

``-I`` isolates the interpreter from the caller's environment (an interpreter also loads
modules from its script directory, so isolation keeps a planted ``json.py`` out of the run);
the archive is put on ``sys.path`` explicitly. The committed ``pod.json`` is the oracle read by
``tests/worker_kata.rs`` at test runtime — nothing here is imported then.

Three values are chosen so the golden manifest exercises the reference's capping rules rather
than only its happy path:

* ``limits.memory_mi`` (1024) exceeds ``run_memory_limit_mi`` (512), so the limit is the
  operator's; ``run_memory_request_mi`` (256) then caps the request.
* ``limits.cpu_millicores`` (1000) exceeds ``run_cpu_limit`` (500); ``run_cpu_request`` (250)
  caps the request.
* ``limits.wall_seconds`` (120) exceeds ``run_max_seconds`` (90), so ``activeDeadlineSeconds``
  is ``run_start_timeout_seconds + 90 = 120``, not the tool's own wall clock.
"""

import json
import os
import sys
from uuid import UUID

DEFAULT_ORACLE = "/Users/georgedekker/Movies/nonagenticai/nonagenticai_mcp_server-python-archive"
ORACLE = os.environ.get("ORACLE", DEFAULT_ORACLE)
sys.path.insert(0, ORACLE)

from src.catalog.models import ToolLimits, ToolManifest  # noqa: E402
from src.config import Settings  # noqa: E402
from src.execution.kata import pod_manifest  # noqa: E402

PIN = "22ac1ce4d1b8129a543832b8ed86fe0e1c0c7fe4"

#: A UUIDv7, the version `mcp_runs.run_id` is constrained to.
RUN_ID = "0190b0b0-0000-7000-8000-0000000b0001"
#: A second fencing generation, so the pod name's fence suffix is checkable.
FENCE = 3
#: The reviewed runner image, and an unrelated approved image that must not be chosen.
IMAGE = f"registry.example/runner@sha256:{'a' * 64}"
OTHER_IMAGE = f"registry.example/other@sha256:{'c' * 64}"

#: The tool contract the run's authority snapshot carries. Only `runner_image_digest` reaches
#: the pod, but the manifest must be otherwise valid so the oracle parses it.
MANIFEST = {
    "schema_version": 1,
    "tool_id": "20000000-0000-7000-8000-000000000001",
    "tenant_id": "10000000-0000-7000-8000-000000000001",
    "version": 1,
    "public_name": "phase3b_runner",
    "operation": "phase3b.runner",
    "description": "Phase 3b Kata pod manifest fixture",
    "runtime": "kata_python",
    "entrypoint": "package/main.py",
    "input_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    "result_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    "context_schema": {"type": "object", "properties": {}, "additionalProperties": False},
    "package_sha256": "b" * 64,
    "runner_image_digest": IMAGE,
    "allowed_operations": [],
    "operation_constraints": [],
    "limits": {
        "wall_seconds": 120,
        "queue_seconds": 60,
        "memory_mi": 1024,
        "cpu_millicores": 1000,
        "api_calls": 10,
        "frame_bytes": 65536,
        "output_bytes": 262144,
    },
    "effect": "read_only",
}

#: The `WorkerSettings` values `pod_manifest` reads, as the env names that produce them.
SETTINGS = {
    "run_namespace": "mcp-runs",
    "kata_runtime_class": "kata-qemu",
    "runner_image_digest": IMAGE,
    "approved_runner_images": [IMAGE, OTHER_IMAGE],
    "run_start_timeout_seconds": 30,
    "run_max_seconds": 90,
    "run_memory_request_mi": 256,
    "run_memory_limit_mi": 512,
    "run_cpu_request": 250,
    "run_cpu_limit": 500,
}


def settings() -> Settings:
    """The archive `Settings` with every pod-manifest input set explicitly.

    Init kwargs are field names (pydantic-settings applies its `MCP_` prefix to the environment
    sources, not to the constructor). `DATABASE_URL` is required by the model but never read by
    `pod_manifest`; it is a value that parses rather than a live connection.
    """
    return Settings(
        database_url="postgresql+psycopg://oracle@127.0.0.1/oracle",
        run_namespace=SETTINGS["run_namespace"],
        kata_runtime_class=SETTINGS["kata_runtime_class"],
        runner_image_digest=SETTINGS["runner_image_digest"],
        approved_runner_images=tuple(SETTINGS["approved_runner_images"]),
        run_start_timeout_seconds=SETTINGS["run_start_timeout_seconds"],
        run_max_seconds=SETTINGS["run_max_seconds"],
        run_memory_request_mi=SETTINGS["run_memory_request_mi"],
        run_memory_limit_mi=SETTINGS["run_memory_limit_mi"],
        run_cpu_request=SETTINGS["run_cpu_request"],
        run_cpu_limit=SETTINGS["run_cpu_limit"],
    )


def main() -> None:
    # The archive's `Contract` is a strict pydantic model: identities must be `UUID` instances
    # and the operation collections tuples. `MANIFEST` above stays JSON-ready for the record;
    # the model is built from it with those three fields replaced.
    limits = ToolLimits.model_validate(MANIFEST["limits"])
    manifest = ToolManifest.model_validate(
        {
            **MANIFEST,
            "tool_id": UUID(MANIFEST["tool_id"]),
            "tenant_id": UUID(MANIFEST["tenant_id"]),
            "allowed_operations": (),
            "operation_constraints": (),
            "limits": limits,
        }
    )
    row = {
        "run_id": UUID(RUN_ID),
        "fence": FENCE,
        # The worker's authority snapshot shape: each member is that model's own JSON string.
        "authority": {
            "manifest": manifest.model_dump_json(),
            "effective": json.dumps({"limits": limits.model_dump()}),
            "context": json.dumps({}),
        },
    }
    pod = pod_manifest(row, settings(), limits)

    # The oracle's own reading of its own output, asserted before it is committed.
    assert pod["metadata"]["name"] == "mcp-" + UUID(RUN_ID).hex + f"-{FENCE}"
    assert pod["spec"]["activeDeadlineSeconds"] == 120
    assert pod["spec"]["containers"][0]["resources"] == {
        "requests": {"memory": "256Mi", "cpu": "250m"},
        "limits": {"memory": "512Mi", "cpu": "500m", "ephemeral-storage": "64Mi"},
    }

    record = {
        "source": "nonagenticai_mcp_server-python-archive",
        "pin": PIN,
        "generated_from": "src/execution/kata.py (pod_manifest, pod_name)",
        "run_id": RUN_ID,
        "fence": FENCE,
        "settings": SETTINGS,
        "limits": limits.model_dump(),
        "authority": row["authority"],
        "pod": pod,
    }
    target = os.path.join(os.path.dirname(os.path.abspath(__file__)), "pod.json")
    with open(target, "w", encoding="utf-8") as handle:
        json.dump(record, handle, indent=2, sort_keys=True)
        handle.write("\n")
    print(f"{target}: {pod['metadata']['name']}")


if __name__ == "__main__":
    main()
