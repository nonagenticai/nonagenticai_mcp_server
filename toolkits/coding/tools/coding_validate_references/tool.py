"""coding.validate_references: do the named files, functions and classes exist?"""

import coding
import kit
from kit import DEGRADED, FAIL, PASS, check

KEYS = {
    "file": ("validate_file", "file_path"),
    "function": ("validate_function", "function_name"),
    "class": ("validate_class", "class_name"),
}


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


async def run(inputs, ctx):
    cn = inputs["container_name"]
    await coding.ensure_running(ctx, cn)
    await coding.require_indexed(ctx, cn)
    results, missing, unknown = [], [], []
    for ref in inputs["references"]:
        kind, name = ref["kind"], ref["name"]
        key, field = KEYS[kind]
        if kind == "file" and not coding.safe_path(name):
            results.append(
                {"kind": kind, "name": name, "valid": False, "note": "not a safe relative path"}
            )
            missing.append(name)
            continue
        body = await kit.call_ok(ctx, key, {"container_name": cn, field: name}, what=key)
        valid = body.get("valid")
        entry = {"kind": kind, "name": name, "valid": valid}
        for extra in ("suggestion", "found_in", "note"):
            if body.get(extra) is not None:
                entry[extra] = body[extra]
        results.append(entry)
        if valid is False:
            missing.append(name)
        elif valid is None:
            unknown.append(name)
    if missing:
        c = check("references_valid", FAIL, "not found: " + ", ".join(missing[:8]))
    elif unknown:
        c = check("references_valid", DEGRADED, "could not be verified: " + ", ".join(unknown[:8]))
    else:
        c = check("references_valid", PASS, f"all {len(results)} references exist")
    return kit.completed({"references": results}, [c])
