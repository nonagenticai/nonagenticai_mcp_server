"""coding.run_tests: run the workspace's tests and report the outcome with an output tail."""

import coding
import kit


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn = inputs["container_name"]
    await coding.ensure_running(ctx, cn)
    result, data = await coding.tests_stage(
        ctx,
        cn,
        inputs["language"],
        inputs.get("test_path"),
        inputs.get("test_type", "unit"),
        inputs.get("timeout", 120),
    )
    return kit.completed(data or {}, [result])
