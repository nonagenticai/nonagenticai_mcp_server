"""coding.update_dependencies: in-range dependency upgrade in the working tree (never committed)."""

import re
import tomllib

import coding
import kit
from kit import DEGRADED, FAIL, PASS, check

MAX_PACKAGES = 50
DIFF_CLIP = 4000
LANGUAGES = {
    "python": ("pyproject.toml", "uv.lock", "poetry.lock", "requirements"),
    "go": ("go.mod", "go.sum"),
    "javascript": ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"),
}


async def main(inputs, ctx):
    return await kit.guarded(run(inputs, ctx))


def language_for(paths):
    """The language whose manifest or lockfile changed (python when none is recognised)."""
    for language, markers in LANGUAGES.items():
        if any(any(m in p.rsplit("/", 1)[-1] for m in markers) for p in paths):
            return language
    return "python"


def outdated_names(body):
    """(upgradable names in order, count skipped for an unsafe name or no newer version)."""
    names, skipped = [], 0
    for item in body if isinstance(body, list) else []:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        current = item.get("current_version") or item.get("version")
        latest = item.get("latest_version")
        if not coding.safe_package(name) or not latest or latest == current:
            skipped += 1
        elif name not in names:
            names.append(name)
    return names, skipped


_REQUIREMENT = re.compile(r"\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def declared_names(text):
    """Package names declared in a pyproject.toml, in order (runtime, extras, groups, uv dev)."""
    try:
        doc = tomllib.loads(text)
    except tomllib.TOMLDecodeError:
        return []
    project = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    lists = [project.get("dependencies")]
    for table in (project.get("optional-dependencies"), doc.get("dependency-groups")):
        if isinstance(table, dict):
            lists.extend(table.values())
    uv = (doc.get("tool") or {}).get("uv") if isinstance(doc.get("tool"), dict) else None
    if isinstance(uv, dict):
        lists.append(uv.get("dev-dependencies"))
    names = []
    for entries in lists:
        for entry in entries if isinstance(entries, list) else []:
            match = _REQUIREMENT.match(entry) if isinstance(entry, str) else None
            if match and coding.safe_package(match.group(1)) and match.group(1) not in names:
                names.append(match.group(1))
    return names


async def declared_packages(ctx, cn):
    """The packages pyproject.toml declares, or [] when there is none to read."""
    status, body = await kit.call(
        ctx, "read_file", {"container_name": cn, "path": "pyproject.toml"}
    )
    if status != 200 or not isinstance(body, dict) or body.get("type") != "file":
        return []
    if body.get("truncated") or not isinstance(body.get("content"), str):
        return []
    return declared_names(body["content"])


def classify(results):
    upgraded, unchanged, failed = [], [], []
    for r in results if isinstance(results, list) else []:
        if not isinstance(r, dict):
            continue
        name = kit.clip(r.get("name"), 128)
        if r.get("success") is not True:
            failed.append({"name": name, "error": kit.clip(r.get("error") or "failed", 200)})
        elif r.get("new_version") and r.get("new_version") != r.get("previous_version"):
            upgraded.append(
                {"name": name, "from": r.get("previous_version"), "to": r.get("new_version")}
            )
        else:
            unchanged.append(name)
    return upgraded, unchanged, failed


async def run(inputs, ctx):
    cn = inputs["container_name"]
    dry_run = inputs.get("dry_run") is True
    await coding.ensure_running(ctx, cn)
    checks = []
    data = {"dry_run": dry_run}

    if "packages" in inputs:
        names = list(dict.fromkeys(inputs["packages"]))
    else:
        status, body = await kit.call(ctx, "deps_outdated", {"container_name": cn})
        if status != 200:
            return coding.unexpected("deps_outdated", status, body)
        names, skipped = outdated_names(body)
        data["skipped_outdated_entries"] = skipped
        selection = "outdated"
        if not names:
            # The gateway's outdated list can come back empty although newer releases exist
            # (its latest-version lookup is unavailable): fall back to every package the
            # manifest declares and let the in-range re-lock decide what actually moves.
            names = await declared_packages(ctx, cn)
            selection = "declared"
        if not names:
            data.update(upgraded=[], selected=[])
            return kit.completed(
                data,
                [
                    check(
                        "outdated",
                        DEGRADED,
                        "the gateway reported no outdated packages and no pyproject.toml "
                        "declares any; pass `packages` to upgrade named packages",
                    )
                ],
            )
        capped = len(names) > MAX_PACKAGES
        names = names[:MAX_PACKAGES]
        summary = (
            f"{len(names)} outdated packages selected"
            if selection == "outdated"
            else f"the gateway reported no outdated packages; selected the {len(names)} "
            "packages pyproject.toml declares for an in-range upgrade"
        ) + (f" (capped at {MAX_PACKAGES}; run again for the rest)" if capped else "")
        checks.append(check("outdated", PASS, summary))
        data["selection"] = selection
    data["selected"] = names

    arguments = {"container_name": cn, "packages": [{"name": n} for n in names]}
    if dry_run:
        arguments["dry_run"] = True
    status, body = await kit.call(ctx, "deps_upgrade", arguments)
    if status != 200:
        return coding.unexpected("deps_upgrade", status, body)

    upgraded, unchanged, failed = classify(body.get("results"))
    exit_code = body.get("exit_code")
    data.update(upgraded=upgraded, unchanged=unchanged, failed=failed)
    prefix = "dry run: " if dry_run else ""
    if exit_code != 0 or failed:
        tail = kit.clip((body.get("stderr") or "") + (body.get("stdout") or ""), 350)
        names_failed = ", ".join(f["name"] for f in failed[:5])
        checks.append(
            check("upgrade", FAIL, f"exit {exit_code}; failed: {names_failed or 'none'}: {tail}")
        )
        data["output_tail"] = tail
        return kit.completed(data, checks)
    if not upgraded:
        checks.append(
            check(
                "upgrade",
                DEGRADED,
                prefix + "no in-range update available (newer releases are outside the "
                "manifest constraints): " + ", ".join(unchanged[:10]),
            )
        )
        return kit.completed(data, checks)
    summary = prefix + f"{len(upgraded)} packages upgraded"
    if unchanged:
        summary += f"; {len(unchanged)} unchanged"
    checks.append(check("upgrade", PASS, summary))
    if dry_run:
        return kit.completed(data, checks)

    # Read-back: the gateway's own view of what the upgrade changed in the working tree.
    sha, diff = await coding.head_sha(ctx, cn, max_bytes=DIFF_CLIP)
    changed = [x.get("path") for x in diff.get("files", []) if isinstance(x, dict)]
    changed += [p for p in diff.get("untracked_files", []) if isinstance(p, str)]
    changed = [p for p in dict.fromkeys(changed) if isinstance(p, str)]
    text = diff.get("diff") or ""
    data.update(
        head_sha=sha,
        changed_files=changed[:50],
        diff=text[:DIFF_CLIP],
        diff_truncated=bool(diff.get("truncated")) or len(text) > DIFF_CLIP,
    )
    checks.append(
        check(
            "tree_changed",
            PASS if changed else DEGRADED,
            f"{len(changed)} files changed in the working tree"
            if changed
            else "the upgrade reported changes but the working tree shows none",
        )
    )
    next_steps = [
        coding.checks_step(cn, language_for(changed), "verify the upgrade before opening a PR"),
        kit.step(coding.OPEN_PR, "open the PR once coding_run_checks passes"),
    ]
    return kit.completed(data, checks, next_steps)
