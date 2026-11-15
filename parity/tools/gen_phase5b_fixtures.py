"""Generate the phase-5B py-oracle golden fixtures from the pinned Python reference.

Run with the archive's own interpreter, archive root passed as argv[1], output path as
argv[2]: `uv run --frozen python parity/tools/gen_phase5b_fixtures.py <archive> <out>`.

Everything here is produced by the reference's own code: `list_operations`, `import_openapi`,
`build_package`, `kit_source` and `tool_manifest` are called directly, so a divergence in a
preview row, a refusal message, an operation manifest, the generated ``ops.py``, a package
digest or the assembled tool manifest fails a Rust test instead of reaching a tenant.

Determinism: the importer mints one UUIDv7 per imported operation. A time-based id would make
the fixture differ on every run, so ``openapi.uuid7`` is replaced with a counter that yields
fixed version-7 / RFC 4122 identities; the counter is reset before the conversion section so
the recorded ids do not depend on how many refusal cases ran first. The builder reads no clock;
no other timestamp is involved.
"""

import hashlib
import json
import sys
from uuid import UUID

ROOT = sys.argv[1]
OUT = sys.argv[2]
sys.path.insert(0, ROOT)

from pydantic import ValidationError  # noqa: E402

from src.builder import openapi as openapi_module  # noqa: E402
from src.builder.models import (  # noqa: E402
    BindRequest,
    ImportRequest,
    OperationOverride,
    SpecFetchRequest,
    ToolCreate,
    ToolOperation,
)
from src.builder.openapi import (  # noqa: E402
    OpenApiImportError,
    import_openapi,
    list_operations,
)
from src.builder.packaging import (  # noqa: E402
    build_package,
    kit_source,
    manifest_fields,
    tool_manifest,
)
from src.catalog.models import ExactReference  # noqa: E402
from src.catalog.package import PackageFile, package_digest  # noqa: E402

#: The identities the importer mints, fixed: version 7, RFC 4122 variant.
_UUID7 = "01900000-0000-7000-8000-{:012d}"
_minted = {"count": 0}


def _fixed_uuid7() -> UUID:
    _minted["count"] += 1
    return UUID(_UUID7.format(_minted["count"]))


openapi_module.uuid7 = _fixed_uuid7


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def json_body(schema: dict) -> dict:
    return {"content": {"application/json": {"schema": schema}}}


#: The fixed bundled OpenAPI 3.1 sample document. It deliberately carries a read, a write, an
#: optional body, a 204, a recursive schema, a denied endpoint, a cookie parameter, a required
#: reserved header, a multipart body, an external $ref, an unsupported method, an invalid
#: operation and a non-object path item, so one document exercises every branch of the importer.
DOCUMENT = {
    "openapi": "3.1.0",
    "info": {"title": "Items", "version": "2"},
    "paths": {
        "/items/{itemId}": {
            "parameters": [
                {"name": "itemId", "in": "path", "required": True, "schema": {"type": "string"}}
            ],
            "get": {
                "operationId": "readItem",
                "summary": "Read",
                "parameters": [
                    {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                    {"name": "X-Tenant-ID", "in": "header", "schema": {"type": "string"}},
                    {"$ref": "#/components/parameters/Trace"},
                ],
                "responses": {
                    "422": json_body({"type": "object"}),
                    "200": json_body({"$ref": "#/components/schemas/Item"}),
                },
            },
            "delete": {"operationId": "dropItem", "responses": {"204": {"description": "gone"}}},
        },
        "/items": {
            "post": {
                "operationId": "makeItem",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {"schema": {"$ref": "#/components/schemas/Item"}}
                    },
                },
                "responses": {"201": json_body({"$ref": "#/components/schemas/Item"})},
            },
            "put": {
                "operationId": "optBody",
                "requestBody": json_body({"type": "object"}),
                "responses": {"200": json_body({"type": "object"})},
            },
        },
        "/tree": {
            "get": {
                "operationId": "tree",
                "responses": {"200": json_body({"$ref": "#/components/schemas/Node"})},
            }
        },
        "/api/ai/chat": {"get": {"operationId": "chat", "responses": {"200": json_body({})}}},
        "/c": {
            "get": {
                "operationId": "cookie",
                "parameters": [{"name": "s", "in": "cookie", "schema": {"type": "string"}}],
                "responses": {"200": json_body({})},
            }
        },
        "/h": {
            "get": {
                "operationId": "hdr",
                "parameters": [
                    {
                        "name": "Authorization",
                        "in": "header",
                        "required": True,
                        "schema": {"type": "string"},
                    }
                ],
                "responses": {"200": json_body({})},
            }
        },
        "/form": {
            "post": {
                "operationId": "form",
                "requestBody": {
                    "content": {"multipart/form-data": {"schema": {"type": "object"}}}
                },
                "responses": {"200": json_body({})},
            }
        },
        "/ext": {
            "get": {"operationId": "ext", "responses": {"200": json_body({"$ref": "http://x/y#/z"})}}
        },
        "/options": {"options": {"operationId": "optionsOp", "responses": {"200": json_body({})}}},
        "/broken": {"get": {"operationId": "broken"}},
        "/bad": {"get": 5},
        "/skip": "nope",
    },
    "components": {
        "parameters": {"Trace": {"name": "x-trace", "in": "header", "schema": {"type": "string"}}},
        "schemas": {
            "Item": {
                "type": "object",
                "required": ["name", "id"],
                "properties": {
                    "id": {"type": "integer", "readOnly": True},
                    "name": {"type": "string", "pattern": "^a", "examples": ["x"]},
                    "secret": {"type": "string", "writeOnly": True},
                },
            },
            "Node": {
                "type": "object",
                "properties": {"next": {"$ref": "#/components/schemas/Node"}},
            },
        },
    },
}

#: The service the imported operations belong to; a fixed UUIDv7 of its own, so it cannot be
#: confused with an id the importer mints.
SERVICE = ExactReference(id=UUID("01900000-0000-7000-8000-0000000000aa"), version=1)

#: The fixed selection and per-operation overrides of the conversion section.
SELECTION = ["readItem", "makeItem"]
OVERRIDES = {"readItem": {"timeout_seconds": 5, "expected_error_statuses": [404]}}
KEY_PREFIX = "crm"

TOOL_FILE = {"path": "tool.py", "content": "async def main(inputs, ctx):\n    return {}\n"}
TOOL_ID = "01900000-0000-7000-8000-000000000009"
TENANT_ID = "00000000-0000-0000-8000-000000000001"
RUNNER_IMAGE_DIGEST = "registry.example/runner@sha256:" + "a" * 64
PUBLIC_NAME = "find_item"
PLATFORM_OPERATION = "item.find"
DESCRIPTION = "Find an item"
ENTRYPOINT = "tool:main"
INPUT_SCHEMA = {"type": "object", "properties": {}, "additionalProperties": False}

#: The document table: every case is a whole document the reference must refuse, the message is
#: the reference's own.
DOCUMENT_REFUSALS = [
    ("document_swagger_2", {"swagger": "2.0"}),
    ("document_openapi_3_2", {"openapi": "3.2.0", "paths": {}}),
    ("document_without_paths", {"openapi": "3.0.0"}),
    ("document_not_an_object", []),
    ("document_paths_not_an_object", {"openapi": "3.1.0", "paths": []}),
]

#: Selection entries that are neither an operationId nor a {method, path} pair.
SELECTION_ENTRY_REFUSALS = [
    ("selection_not_an_id_or_pair", 5),
    ("selection_pair_without_path", {"method": "GET"}),
]

#: (name, selection, overrides) cases the reference must refuse.
SELECT_REFUSALS = [
    ("select_recursive", ["tree"], None),
    ("select_denied", ["chat"], None),
    ("select_cookie", ["cookie"], None),
    ("select_required_reserved_header", ["hdr"], None),
    ("select_non_json_body", ["form"], None),
    ("select_external_ref", ["ext"], None),
    ("select_no_responses", ["broken"], None),
    ("select_unsupported_method", ["optionsOp"], None),
    ("select_unknown_operation", ["nope"], None),
    ("select_empty", [], None),
    ("override_op_key_needs_one_selection", ["readItem", "makeItem"], {"op_key": "x"}),
    ("override_unknown_field", ["readItem"], {"readItem": {"bogus": 1}}),
    ("override_invalid_op_key", ["readItem"], {"op_key": "Bad Key"}),
]

#: (name, model, body) request bodies the reference's own models must refuse.
MODEL_REFUSALS = [
    (
        "tool_operation_two_origins",
        ToolOperation,
        {"op_key": "x", "source_key": "crm", "service": "fr"},
    ),
    ("tool_operation_no_origin", ToolOperation, {"op_key": "x"}),
    ("operation_override_empty_projection", OperationOverride, {"response_projection": []}),
    (
        "operation_override_too_many_statuses",
        OperationOverride,
        {"expected_error_statuses": list(range(17))},
    ),
    (
        "import_request_lowercase_method",
        ImportRequest,
        {"spec_sha256": "a" * 64, "select": [{"method": "get", "path": "/x"}]},
    ),
    (
        "import_request_too_many_statuses",
        ImportRequest,
        {
            "spec_sha256": "a" * 64,
            "select": ["readItem"],
            "overrides": {"readItem": {"expected_error_statuses": list(range(17))}},
        },
    ),
    (
        "import_request_selector_extra_field",
        ImportRequest,
        {
            "spec_sha256": "a" * 64,
            "select": [{"method": "GET", "path": "/x", "extra": True}],
        },
    ),
    ("spec_fetch_request_non_canonical_path", SpecFetchRequest, {"path": "openapi.json"}),
    ("bind_request_bad_product", BindRequest, {"product": "Bad Product"}),
    ("tool_create_missing_fields", ToolCreate, {"public_name": "x"}),
]


def refusal_message(call) -> str:
    """The reference's own refusal message for `call`."""
    try:
        call()
    except (OpenApiImportError, ValueError) as error:
        return str(error)
    raise AssertionError("the malformed input was accepted")


def model_message(model, body: dict) -> str:
    """The reference's first Pydantic error message for `body`."""
    try:
        model.model_validate_json(json.dumps(body))
    except ValidationError as error:
        return error.errors()[0]["msg"]
    raise AssertionError(f"{model.__name__} accepted a malformed body")


def conversion() -> tuple[dict, str]:
    """One fixed selection, its imported manifests, the package and the assembled tool."""
    _minted["count"] = 0
    operations = import_openapi(DOCUMENT, SERVICE, SELECTION, None, OVERRIDES)
    refs = {
        f"{KEY_PREFIX}.{operation.op_key}": (
            operation.manifest.operation_id,
            operation.manifest.version,
        )
        for operation in operations
    }
    files = build_package([PackageFile(**TOOL_FILE)], refs)
    ops_py = next(file.content for file in files if file.path == "ops.py")
    fields = manifest_fields(
        public_name=PUBLIC_NAME,
        operation=PLATFORM_OPERATION,
        description=DESCRIPTION,
        entrypoint=ENTRYPOINT,
        input_schema=INPUT_SCHEMA,
        result_schema=None,
        context_schema=None,
        effect="read_only",
        limits=None,
    )
    manifest = tool_manifest(
        tool_id=UUID(TOOL_ID),
        tenant_id=UUID(TENANT_ID),
        version=1,
        fields=fields,
        files=files,
        refs=[
            ExactReference(id=operation.manifest.operation_id, version=operation.manifest.version)
            for operation in operations
        ],
        runner_image_digest=RUNNER_IMAGE_DIGEST,
    )
    section = {
        "service": {"id": str(SERVICE.id), "version": SERVICE.version},
        "key_prefix": KEY_PREFIX,
        "selection": SELECTION,
        "overrides": OVERRIDES,
        "input_files": [TOOL_FILE],
        "operations": [
            {
                "op_key": operation.op_key,
                "operation_id": operation.operation_id,
                "method": operation.method,
                "path": operation.path,
                "summary": operation.summary,
                "manifest": json.loads(operation.manifest.model_dump_json()),
            }
            for operation in operations
        ],
        "fields": fields,
        "tool": {
            "tool_id": TOOL_ID,
            "tenant_id": TENANT_ID,
            "version": 1,
            "public_name": PUBLIC_NAME,
            "operation": PLATFORM_OPERATION,
            "description": DESCRIPTION,
            "entrypoint": ENTRYPOINT,
            "input_schema": INPUT_SCHEMA,
            "effect": "read_only",
            "runner_image_digest": RUNNER_IMAGE_DIGEST,
        },
        "tool_manifest": json.loads(manifest.model_dump_json()),
        "package": {
            "files": [
                {
                    "path": file.path,
                    "sha256": sha256(file.content),
                    "bytes": len(file.content.encode("utf-8")),
                }
                for file in files
            ],
            "digest": package_digest(files),
        },
    }
    return section, ops_py


def refusals() -> list[dict]:
    table = [
        {
            "name": name,
            "kind": "document",
            "input": document,
            "message": refusal_message(lambda document=document: list_operations(document)),
        }
        for name, document in DOCUMENT_REFUSALS
    ]
    table.extend(
        {
            "name": name,
            "kind": "selection_entry",
            "input": entry,
            "message": refusal_message(
                lambda entry=entry: import_openapi(DOCUMENT, SERVICE, [entry], None)
            ),
        }
        for name, entry in SELECTION_ENTRY_REFUSALS
    )
    table.extend(
        {
            "name": name,
            "kind": "select",
            "selection": selection,
            "overrides": overrides,
            "message": refusal_message(
                lambda selection=selection, overrides=overrides: import_openapi(
                    DOCUMENT, SERVICE, selection, None, overrides
                )
            ),
        }
        for name, selection, overrides in SELECT_REFUSALS
    )
    table.extend(
        {
            "name": name,
            "kind": "model",
            "model": model.__name__,
            "input": body,
            "message": model_message(model, body),
        }
        for name, model, body in MODEL_REFUSALS
    )
    return table


def main() -> None:
    kit = kit_source()
    conversion_section, ops_py = conversion()
    fixtures = {
        "document": DOCUMENT,
        "kit_source": {"text": kit, "sha256": sha256(kit)},
        "operations": list_operations(DOCUMENT),
        "conversion": conversion_section,
        "ops_py": ops_py,
        "refusals": refusals(),
    }
    with open(OUT, "w", encoding="utf-8") as handle:
        json.dump(fixtures, handle, indent=1, sort_keys=True, ensure_ascii=False)
        handle.write("\n")


if __name__ == "__main__":
    main()
