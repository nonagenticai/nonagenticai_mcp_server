#!/usr/bin/env python3
"""Generate ``policy.json`` by *executing* the pinned Python oracle.

Run with the archive checked out at commit ``22ac1ce4``::

    uv run --project <archive> python tests/fixtures/phase3b/generate_policy.py <archive>

The archive root is passed as an argument (never assumed to be the cwd). The committed JSON is
the oracle: the Rust test replays it and never imports Python. Regenerate deliberately, and
justify every diff against the Python source.

The fixture covers the pure functions of ``src/broker/egress.py``, ``src/broker/limits.py`` and
``src/broker/policy.py``: address/hostname policy, ``embedded_addresses``, ``transport``,
``project``, ``enforce`` and ``RateLimits.read``/``ceiling``.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
import sys
import tempfile
from pathlib import Path
from uuid import UUID

ARCHIVE = Path(sys.argv[1] if len(sys.argv) > 1 else os.environ["ORACLE_ARCHIVE"]).resolve()
sys.path.insert(0, str(ARCHIVE))

from src.broker import egress  # noqa: E402
from src.broker.egress import EgressDeniedError, address_allowed, check_hostname  # noqa: E402
from src.broker.egress import embedded_addresses, parse_address  # noqa: E402
from src.broker.limits import RateLimits  # noqa: E402
from src.broker.policy import enforce, project, transport  # noqa: E402
from src.catalog.models import (  # noqa: E402
    ArgumentMapping,
    ContextEquality,
    ExactReference,
    LiteralValue,
    NumericBounds,
    OperationManifest,
    OwnershipRead,
    RelativePath,
    SetMembership,
    SourcePointer,
)
from src.execution.models import ExecutionDeniedError  # noqa: E402


def u7(n: int) -> UUID:
    return UUID(f"01900000-0000-7000-8000-{n:012d}")


def operation(**overrides) -> OperationManifest:
    base = dict(
        operation_id=u7(1),
        version=1,
        service=ExactReference(id=u7(2), version=1),
        method="GET",
        path_template="/records/{record}",
        input_schema={},
        output_schema={},
        response_projection=("/ok",),
        effect="read_only",
        timeout_seconds=5,
        pagination_limit=10,
        max_response_bytes=1024,
    )
    base.update(overrides)
    return OperationManifest(**base)


RECORD = ArgumentMapping(
    location="path", target="record", value=SourcePointer(source="input", pointer="/id")
)

OPERATIONS: dict[str, OperationManifest] = {
    "records": operation(
        query_fields=("limit", "flag", "ratio"),
        header_fields=("x_version",),
        mappings=(
            RECORD,
            ArgumentMapping(
                location="query",
                target="limit",
                value=SourcePointer(source="input", pointer="/limit"),
            ),
            ArgumentMapping(
                location="query",
                target="flag",
                value=SourcePointer(source="input", pointer="/flag"),
            ),
            ArgumentMapping(
                location="query",
                target="ratio",
                value=SourcePointer(source="input", pointer="/ratio"),
            ),
            ArgumentMapping(
                location="header",
                target="x_version",
                value=SourcePointer(source="context", pointer="/version"),
            ),
        ),
        response_projection=("/records",),
        redact_fields=("/records/0/token",),
    ),
    "optional": operation(
        path_template="/search",
        query_fields=("q", "limit"),
        mappings=(
            ArgumentMapping(
                location="query",
                target="q",
                value=SourcePointer(source="input", pointer="/q"),
            ),
            ArgumentMapping(
                location="query",
                target="limit",
                value=SourcePointer(source="input", pointer="/limit"),
                optional=True,
            ),
        ),
    ),
    "create": operation(
        method="POST",
        path_template="/records",
        effect="writes",
        mappings=(
            ArgumentMapping(
                location="body",
                target="/nested",
                value=SourcePointer(source="input", pointer="/body"),
            ),
            ArgumentMapping(
                location="body",
                target="/name",
                value=LiteralValue(source="literal", value="fixed"),
            ),
        ),
    ),
    "whole_body": operation(
        method="POST",
        path_template="/raw",
        effect="writes",
        mappings=(
            ArgumentMapping(
                location="body",
                target="",
                value=SourcePointer(source="input", pointer="/body"),
            ),
        ),
    ),
    "escaped_body": operation(
        method="POST",
        path_template="/records/{record}",
        effect="writes",
        mappings=(
            RECORD,
            ArgumentMapping(
                location="body",
                target="/a~1b/c~0d",
                value=SourcePointer(source="input", pointer="/value"),
            ),
        ),
    ),
    "projection": operation(
        path_template="/x",
        response_projection=("/a/b", "/c"),
        redact_fields=("/a/b/key", "/nothing/here", "/c/0", "/map/a~1b"),
    ),
    "empty_projection": operation(path_template="/x", response_projection=("",)),
    "redact_empty": operation(
        path_template="/x", response_projection=("/ok",), redact_fields=("",)
    ),
    "missing_projection": operation(path_template="/x", response_projection=("/absent",)),
}


def dump_failure(error: BaseException) -> dict:
    return {"refused": True, "error": type(error).__name__}


def transport_cases() -> list[dict]:
    cases: list[dict] = []

    def case(name: str, op: str, arguments, context) -> None:
        try:
            path, query, headers, body = transport(OPERATIONS[op], arguments, context)
        except (ExecutionDeniedError, ValueError, TypeError, AttributeError) as error:
            cases.append(
                {"name": name, "operation": op, "arguments": arguments,
                 "context": context, **dump_failure(error)}
            )
            return
        cases.append(
            {
                "name": name,
                "operation": op,
                "arguments": arguments,
                "context": context,
                "expected": {
                    "path": path,
                    "query": query,
                    "headers": headers,
                    "body": body,
                },
            }
        )

    record_args = {"id": "abc", "limit": 5, "flag": True, "ratio": 1.5}
    case("record_happy", "records", record_args, {"version": "v1"})
    case(
        "record_number_rendering",
        "records",
        {"id": "abc", "limit": True, "flag": False, "ratio": 1.0},
        {"version": "v1"},
    )
    case(
        "record_percent_encoding",
        "records",
        {"id": "café ☕", "limit": 1, "flag": False, "ratio": 0.5},
        {"version": "v1"},
    )
    case(
        "record_unreserved_path_value",
        "records",
        {"id": "a.b-c_d~e", "limit": 1, "flag": False, "ratio": 0.5},
        {"version": "v1"},
    )
    for name, bad in (
        ("path_dot", "."),
        ("path_dotdot", ".."),
        ("path_empty", ""),
        ("path_slash", "evil/path"),
        ("path_percent", "%2f"),
        ("path_backslash", "a\\b"),
        ("path_question", "a?b"),
        ("path_fragment", "a#b"),
        ("path_control", "\r\nInjected"),
        ("path_control_unit", "\x01"),
        ("path_object", {"id": "object"}),
        ("path_null", None),
        ("path_list", [1]),
    ):
        if isinstance(bad, str):
            arguments = dict(record_args, id=bad)
        else:
            arguments = dict(record_args, id="abc")
            arguments["id"] = bad
        case(name, "records", arguments, {"version": "v1"})
    case(
        "header_object_refused",
        "records",
        record_args,
        {"version": {"nested": True}},
    )
    case("missing_required_input", "records", {"id": "abc"}, {"version": "v1"})
    case("missing_context", "records", record_args, {})
    case("optional_absent", "optional", {"q": "x"}, {})
    case("optional_present", "optional", {"q": "x", "limit": 3}, {})
    case("required_query_missing", "optional", {"limit": 3}, {})
    case("literal_and_body", "create", {"body": {"ok": True}}, {})
    case("body_object_refused", "create", {"body": [1, 2]}, {})
    case("whole_body_object", "whole_body", {"body": {"any": "json"}}, {})
    case("whole_body_list", "whole_body", {"body": [1, 2]}, {})
    case("whole_body_scalar", "whole_body", {"body": "text"}, {})
    case("body_pointer_escaping", "escaped_body", {"id": "abc", "value": 7}, {})
    return cases


def projection_cases() -> list[dict]:
    cases: list[dict] = []

    def case(name: str, op: str, value) -> None:
        try:
            projected = project(OPERATIONS[op], value)
        except (ExecutionDeniedError, ValueError, TypeError, AttributeError) as error:
            cases.append({"name": name, "operation": op, "value": value, **dump_failure(error)})
            return
        cases.append(
            {"name": name, "operation": op, "value": value, "expected": projected}
        )

    case(
        "projection_and_redaction",
        "records",
        {"records": [{"token": "secret", "id": 1}], "hidden": "secret"},
    )
    case(
        "projection_nested_and_array_redaction",
        "projection",
        {
            "a": {"b": {"key": "secret", "keep": 1}},
            "c": [{"token": "secret"}, "text"],
            "map": {"a/b": "secret", "other": 1},
            "hidden": "secret",
        },
    )
    case("projection_absent_refused", "missing_projection", {"ok": 1})
    case("projection_empty_whole_value", "empty_projection", {"anything": [1, 2]})
    case("redact_empty_refused", "redact_empty", {"ok": 1})
    return cases


def constraint_cases() -> list[dict]:
    ownership_id = u7(3)
    ownership = OwnershipRead(
        kind="ownership_read",
        argument="/subject",
        operation=ExactReference(id=ownership_id, version=1),
        result="/owner",
        context="/owner",
    )
    rules = {
        "context": ContextEquality(kind="context_equal", argument="/value", context="/bound"),
        "set": SetMembership(kind="set_membership", argument="/value", values=(1, 2)),
        "number": NumericBounds(kind="numeric_bounds", argument="/value", minimum=1.0, maximum=3.0),
        "huge": NumericBounds(
            kind="numeric_bounds",
            argument="/value",
            minimum=-9007199254740992.0,
            maximum=9007199254740992.0,
        ),
        "path": RelativePath(kind="relative_path", argument="/value", root="src"),
        "ownership": ownership,
    }
    cases: list[dict] = []

    async def run(name: str, rule_names, arguments, context, ownership_result=None) -> None:
        selected = [rules[rule] for rule in rule_names]
        calls = []

        async def read(reference, received):
            calls.append({"reference": str(reference.operation.id), "arguments": received})
            if ownership_result is None:
                raise AssertionError("ownership read not expected")
            return ownership_result

        record = {
            "name": name,
            "rules": [rule.model_dump(mode="json") for rule in selected],
            "arguments": arguments,
            "context": context,
            "ownership_result": ownership_result,
        }
        try:
            await enforce(tuple(selected), arguments, context, read)
        except (ExecutionDeniedError, ValueError, AttributeError, TypeError) as error:
            record.update(dump_failure(error))
        else:
            record["accepted"] = True
        record["ownership_calls"] = calls
        cases.append(record)

    async def all_cases() -> None:
        await run("context_equal_accepted", ["context"], {"value": "bound"}, {"bound": "bound"})
        await run("context_equal_refused", ["context"], {"value": "other"}, {"bound": "bound"})
        await run("context_bool_is_not_int", ["context"], {"value": True}, {"bound": 1})
        await run("context_int_is_not_float", ["context"], {"value": 1}, {"bound": 1.0})
        await run("context_missing_argument", ["context"], {}, {"bound": "bound"})
        await run("context_missing_context", ["context"], {"value": "bound"}, {})
        await run("set_member", ["set"], {"value": 1}, {})
        await run("set_bool_is_not_member", ["set"], {"value": True}, {})
        await run("set_non_member", ["set"], {"value": 3}, {})
        await run("number_in_bounds", ["number"], {"value": 2}, {})
        await run("number_float_in_bounds", ["number"], {"value": 2.5}, {})
        await run("number_bool_refused", ["number"], {"value": True}, {})
        await run("number_above_bounds", ["number"], {"value": 9}, {})
        await run("number_string_refused", ["number"], {"value": "2"}, {})
        await run("number_2_53_boundary_accepted", ["huge"], {"value": 9007199254740992}, {})
        await run("number_above_2_53_refused", ["huge"], {"value": 9007199254740993}, {})
        await run("number_below_2_53_refused", ["huge"], {"value": -9007199254740993}, {})
        await run("path_under_root", ["path"], {"value": "src/file.py"}, {})
        await run("path_is_root", ["path"], {"value": "src"}, {})
        await run("path_sibling_refused", ["path"], {"value": "src-other/file.py"}, {})
        await run("path_traversal_refused", ["path"], {"value": "src/../escape.py"}, {})
        await run("path_absolute_refused", ["path"], {"value": "/src/file.py"}, {})
        await run("path_non_string_refused", ["path"], {"value": 1}, {})
        await run(
            "ownership_accepted",
            ["ownership"],
            {"subject": "s-1"},
            {"owner": "t-1"},
            {"owner": "t-1"},
        )
        await run(
            "ownership_mismatch_refused",
            ["ownership"],
            {"subject": "s-1"},
            {"owner": "t-2"},
            {"owner": "t-1"},
        )
        await run(
            "ownership_missing_result_refused",
            ["ownership"],
            {"subject": "s-1"},
            {"owner": "t-1"},
            {"other": "t-1"},
        )
        await run(
            "ownership_missing_context_refused",
            ["ownership"],
            {"subject": "s-1"},
            {},
            {"owner": "t-1"},
        )
        await run(
            "conjunction_accepted",
            ["context", "set", "number"],
            {"value": 1},
            {"bound": 1},
        )
        await run(
            "conjunction_refused",
            ["context", "number"],
            {"value": 1},
            {"bound": 2},
        )

    asyncio.run(all_cases())
    return cases


def limits_cases() -> dict:
    tenant = u7(4)
    other_tenant = u7(5)
    service_a = u7(6)
    service_b = u7(7)

    accepted = {
        "schema_version": 1,
        "limits": [
            {
                "service_id": str(service_a),
                "tenant_id": str(tenant),
                "calls_per_minute": 1,
                "concurrency": 2,
            },
            {
                "service_id": str(service_a),
                "calls_per_minute": 5,
                "concurrency": 3,
            },
            {
                "service_id": str(service_b),
                "tenant_id": str(tenant),
                "calls_per_minute": 7,
                "concurrency": 4,
            },
        ],
    }

    def accepted_payloads() -> list[dict]:
        payloads = [
            ("accepted_table", accepted),
            ("accepted_empty", {"schema_version": 1}),
        ]
        out = []
        with tempfile.TemporaryDirectory() as directory:
            for name, payload in payloads:
                path = Path(directory) / f"{name}.json"
                path.write_text(json.dumps(payload))
                result = RateLimits.read(path)
                entries = [
                    {
                        "service_id": str(item.service_id),
                        "tenant_id": str(item.tenant_id) if item.tenant_id else None,
                        "calls_per_minute": item.calls_per_minute,
                        "concurrency": item.concurrency,
                    }
                    for item in result.limits
                ]
                out.append({"name": name, "payload": payload, "limits": entries})
        return out

    item = {
        "service_id": str(service_a),
        "calls_per_minute": 2,
        "concurrency": 1,
    }
    refused_payloads = [
        ("schema_version_two", json.dumps({"schema_version": 2, "limits": []})),
        (
            "extra_field",
            json.dumps({"schema_version": 1, "limits": [], "url": "https://evil.example"}),
        ),
        (
            "duplicate_identity",
            json.dumps({"schema_version": 1, "limits": [item, item]}),
        ),
        (
            "calls_out_of_range",
            json.dumps(
                {
                    "schema_version": 1,
                    "limits": [dict(item, calls_per_minute=0)],
                }
            ),
        ),
        (
            "concurrency_out_of_range",
            json.dumps(
                {
                    "schema_version": 1,
                    "limits": [dict(item, concurrency=101)],
                }
            ),
        ),
        (
            "wrong_type",
            json.dumps(
                {
                    "schema_version": 1,
                    "limits": [dict(item, calls_per_minute="5")],
                }
            ),
        ),
        (
            "float_type",
            json.dumps({"schema_version": 1.0, "limits": []}),
        ),
        (
            "nested_extra_field",
            json.dumps(
                {
                    "schema_version": 1,
                    "limits": [dict(item, url="https://evil.example")],
                }
            ),
        ),
    ]
    refused = []
    with tempfile.TemporaryDirectory() as directory:
        for name, payload in refused_payloads:
            path = Path(directory) / f"{name}.json"
            path.write_bytes(payload.encode())
            try:
                RateLimits.read(path)
            except ValueError as error:
                message = str(error)
                if "exceeds bounds" in message:
                    kind = "too_large"
                elif "duplicate" in message:
                    kind = "duplicate"
                else:
                    kind = "invalid"
            else:
                raise AssertionError(f"{name} was accepted")
            refused.append({"name": name, "bytes": payload, "error": kind})

    ceilings = []
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "limits.json"
        path.write_text(json.dumps(accepted))
        table = RateLimits.read(path)
        for name, who, service, calls, concurrency in (
            ("tenant_specific_narrows", tenant, service_a, 100, 10),
            ("global_entry_narrows", other_tenant, service_a, 100, 10),
            ("other_service", tenant, service_b, 100, 10),
            ("unlisted_service", tenant, u7(8), 100, 10),
        ):
            narrowed = table.ceiling(who, service, calls, concurrency)
            ceilings.append(
                {
                    "name": name,
                    "tenant": str(who),
                    "service": str(service),
                    "calls": calls,
                    "concurrency": concurrency,
                    "expected": list(narrowed),
                }
            )

    return {
        "accepted": accepted_payloads(),
        "refused": refused,
        "oversized": {"length": 262145, "fill": "x", "error": "too_large"},
        "ceilings": ceilings,
    }


REFUSED_ADDRESSES = [
    "127.0.0.1",
    "127.1.2.3",
    "10.0.0.1",
    "172.16.5.4",
    "192.168.1.1",
    "169.254.169.254",
    "169.254.170.2",
    "100.64.0.1",
    "100.100.100.200",
    "192.0.0.192",
    "0.0.0.0",
    "224.0.0.1",
    "239.255.255.250",
    "240.0.0.1",
    "255.255.255.255",
    "198.18.0.1",
    "192.0.2.1",
    "::1",
    "::",
    "fe80::1",
    "fe80::1%eth0",
    "fc00::1",
    "fd00:ec2::254",
    "ff02::1",
    "::ffff:127.0.0.1",
    "::ffff:10.1.2.3",
    "::ffff:169.254.169.254",
    "::127.0.0.1",
    "64:ff9b::7f00:1",
    "64:ff9b::a9fe:a9fe",
    "2002:7f00:1::1",
    "2002:a9fe:a9fe::1",
    "2002:0a00:0001::",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "2001:db8::1",
    "100::1",
    "fec0::1",
    "febf::1",
    "192.88.99.1",
    "192.88.99.255",
    "64:ff9b::c058:6301",
]
ALLOWED_ADDRESSES = [
    "8.8.8.8",
    "1.1.1.1",
    "93.184.216.34",
    "2606:4700:4700::1111",
    "2a00:1450:4001::1",
]
DENY_CASES = [
    ("8.8.8.8", ["8.8.8.0/24"], False),
    ("2606:4700:4700::1111", ["2606:4700::/32"], False),
    ("1.1.1.1", ["8.8.8.0/24"], True),
    ("::ffff:8.8.8.8", ["8.8.8.0/24"], False),
]
EMBEDDED_CASES = [
    "::ffff:8.8.8.8",
    "::ffff:127.0.0.1",
    "64:ff9b::7f00:1",
    "2002:7f00:1::1",
    "2001:0:4136:e378:8000:63bf:3fff:fdd2",
    "8.8.8.8",
]
REFUSED_HOSTNAMES = [
    "localhost",
    "app.localhost",
    "127.0.0.1",
    "[::1]",
    "2130706433",
    "0x7f.1",
    "intranet",
    "printer.local",
    "db.internal",
    "api.svc",
    "x.cluster.local",
    "x.svc.cluster.local",
    "",
    "a..b.com",
    "-bad.example.com",
    "under_score.example.com",
    "u@h.example.com",
]


def egress_cases() -> dict:
    addresses = [
        {"address": address, "deny": [], "allowed": address_allowed(parse_address(address), ())}
        for address in REFUSED_ADDRESSES
    ]
    addresses.extend(
        {"address": address, "deny": [], "allowed": address_allowed(parse_address(address), ())}
        for address in ALLOWED_ADDRESSES
    )
    for address, deny, expected in DENY_CASES:
        networks = [ipaddress.ip_network(cidr) for cidr in deny]
        allowed = address_allowed(parse_address(address), networks)
        assert allowed == expected, (address, deny, allowed)
        addresses.append({"address": address, "deny": deny, "allowed": allowed})
    embedded = [
        {
            "address": address,
            "embedded": [str(value) for value in embedded_addresses(parse_address(address))],
        }
        for address in EMBEDDED_CASES
    ]
    hostnames = [{"host": host, "accepted": False} for host in REFUSED_HOSTNAMES]
    hostnames.append(
        {"host": "API.Example.com.", "accepted": True, "normalized": check_hostname("API.Example.com.")}
    )
    for host in REFUSED_HOSTNAMES:
        try:
            check_hostname(host)
        except EgressDeniedError:
            continue
        raise AssertionError(f"{host!r} was accepted")
    return {"addresses": addresses, "embedded": embedded, "hostnames": hostnames}


def main() -> None:
    fixture = {
        "oracle": "nonagenticai_mcp_server-python-archive@22ac1ce4",
        "operations": {
            name: manifest.model_dump(mode="json") for name, manifest in OPERATIONS.items()
        },
        "transport": transport_cases(),
        "projection": projection_cases(),
        "constraints": constraint_cases(),
        "limits": limits_cases(),
        "egress": egress_cases(),
    }
    destination = Path(__file__).with_name("policy.json")
    destination.write_text(json.dumps(fixture, indent=2, sort_keys=True) + "\n")
    print(f"wrote {destination}")


if __name__ == "__main__":
    main()
