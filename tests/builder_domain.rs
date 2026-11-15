//! Builder domain acceptance: the OpenAPI importer, the request models, the host package and the
//! round trip spec -> operations -> manifests -> package. Each test fails if the behaviour it
//! covers is removed.

use std::collections::BTreeMap;

use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};

use mcp_server_rs::builder::models::{
    BindRequest, ImportRequest, OperationOverride, SelectionEntry, SpecFetchRequest, ToolCreate,
    ToolOperation,
};
use mcp_server_rs::builder::openapi::{Selection, import_openapi, list_operations, spec_info};
use mcp_server_rs::builder::packaging::{
    ManifestFieldArgs, OpRefs, ToolManifestInput, build_package, kit_source, manifest_fields,
    parse_ops, tool_manifest, user_files,
};
use mcp_server_rs::builder::spec::{checked_spec_path, digest, parse_document, title_version};
use mcp_server_rs::catalog::ids::{AuthorityId, Name, Operation, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::models::{Effect, ExactReference, Method};
use mcp_server_rs::catalog::package::{PackageFile, package_digest, validate_package};
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::config::PackageLimits;

const TOOL_ID: &str = "01900000-0000-7000-8000-000000000009";
const TENANT_ID: &str = "00000000-0000-0000-8000-000000000001";

fn uuid(value: &str) -> Uuid7 {
    Uuid7::new(value).expect("a valid uuid7")
}

fn version(value: u64) -> PositiveVersion {
    PositiveVersion::new(value).expect("a valid version")
}

fn service() -> ExactReference {
    ExactReference {
        id: uuid("01900000-0000-7000-8000-000000000001"),
        version: version(1),
    }
}

fn tool_file() -> PackageFile {
    PackageFile {
        path: "tool.py".to_owned(),
        content: "async def main(inputs, ctx):\n    return {}\n".to_owned(),
    }
}

fn object(value: Value) -> serde_json::Map<String, Value> {
    value.as_object().cloned().expect("a JSON object")
}

/// The reference's FASTAPI fixture: a read, a write, an optional body, a 204, a recursive schema,
/// a denied endpoint, a cookie parameter, a required reserved header, a multipart body and an
/// external ref.
fn fastapi() -> Value {
    let body = |schema: Value| json!({"content": {"application/json": {"schema": schema}}});
    json!({
        "openapi": "3.1.0",
        "info": {"title": "Items", "version": "2"},
        "paths": {
            "/items/{itemId}": {
                "parameters": [
                    {"name": "itemId", "in": "path", "required": true, "schema": {"type": "string"}}
                ],
                "get": {
                    "operationId": "readItem",
                    "summary": "Read",
                    "parameters": [
                        {"name": "verbose", "in": "query", "schema": {"type": "boolean"}},
                        {"name": "X-Tenant-ID", "in": "header", "schema": {"type": "string"}},
                        {"$ref": "#/components/parameters/Trace"}
                    ],
                    "responses": {
                        "422": body(json!({"type": "object"})),
                        "200": body(json!({"$ref": "#/components/schemas/Item"}))
                    }
                },
                "delete": {"operationId": "dropItem", "responses": {"204": {"description": "gone"}}}
            },
            "/items": {
                "post": {
                    "operationId": "makeItem",
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Item"}}}
                    },
                    "responses": {"201": body(json!({"$ref": "#/components/schemas/Item"}))}
                },
                "put": {
                    "operationId": "optBody",
                    "requestBody": body(json!({"type": "object"})),
                    "responses": {"200": body(json!({"type": "object"}))}
                }
            },
            "/tree": {
                "get": {
                    "operationId": "tree",
                    "responses": {"200": body(json!({"$ref": "#/components/schemas/Node"}))}
                }
            },
            "/api/ai/chat": {"get": {"operationId": "chat", "responses": {"200": body(json!({}))}}},
            "/c": {
                "get": {
                    "operationId": "cookie",
                    "parameters": [{"name": "s", "in": "cookie", "schema": {"type": "string"}}],
                    "responses": {"200": body(json!({}))}
                }
            },
            "/h": {
                "get": {
                    "operationId": "hdr",
                    "parameters": [
                        {"name": "Authorization", "in": "header", "required": true, "schema": {"type": "string"}}
                    ],
                    "responses": {"200": body(json!({}))}
                }
            },
            "/form": {
                "post": {
                    "operationId": "form",
                    "requestBody": {"content": {"multipart/form-data": {"schema": {"type": "object"}}}},
                    "responses": {"200": body(json!({}))}
                }
            },
            "/ext": {
                "get": {"operationId": "ext", "responses": {"200": body(json!({"$ref": "http://x/y#/z"}))}}
            },
            "/options": {
                "options": {"operationId": "optionsOp", "responses": {"200": body(json!({}))}}
            },
            "/broken": {"get": {"operationId": "broken"}},
            "/bad": {"get": 5},
            "/skip": "nope"
        },
        "components": {
            "parameters": {
                "Trace": {"name": "x-trace", "in": "header", "schema": {"type": "string"}}
            },
            "schemas": {
                "Item": {
                    "type": "object",
                    "required": ["name", "id"],
                    "properties": {
                        "id": {"type": "integer", "readOnly": true},
                        "name": {"type": "string", "pattern": "^a", "examples": ["x"]},
                        "secret": {"type": "string", "writeOnly": true}
                    }
                },
                "Node": {
                    "type": "object",
                    "properties": {"next": {"$ref": "#/components/schemas/Node"}}
                }
            }
        }
    })
}

#[test]
fn an_accepted_conversion_produces_the_reference_manifest_and_package() {
    let doc = fastapi();
    let imported = import_openapi(
        &doc,
        &service(),
        &[Selection::operation_id("readItem")],
        Some(&SchemaLimits::default()),
        None,
    )
    .expect("readItem imports");
    assert_eq!(imported.len(), 1);
    let operation = &imported[0];
    assert_eq!(operation.op_key, "read_item");
    assert_eq!(operation.operation_id.as_deref(), Some("readItem"));
    assert_eq!(operation.method, "GET");
    assert_eq!(operation.path, "/items/{itemId}");
    assert_eq!(operation.summary, "Read");
    let manifest = &operation.manifest;
    assert_eq!(manifest.method, Method::Get);
    assert_eq!(manifest.effect, Effect::ReadOnly);
    assert_eq!(manifest.path_template, "/items/{item_id}");
    let properties = manifest.input_schema["properties"]
        .as_object()
        .expect("an object");
    let names: Vec<&str> = properties.keys().map(String::as_str).collect();
    assert_eq!(names, vec!["item_id", "verbose", "x_trace"]);
    assert_eq!(manifest.input_schema["required"], json!(["item_id"]));
    assert_eq!(manifest.input_schema["additionalProperties"], json!(false));
    let optional: BTreeMap<&str, bool> = manifest
        .mappings
        .iter()
        .map(|mapping| (mapping.target.as_str(), mapping.optional))
        .collect();
    assert_eq!(
        optional,
        BTreeMap::from([("item_id", false), ("verbose", true), ("x_trace", true)])
    );
    assert_eq!(manifest.output_schema["$ref"], "#/$defs/Item");
    let item = &manifest.output_schema["$defs"]["Item"];
    assert!(item["properties"].get("name").expect("name")["pattern"].is_null());
    let output_properties: Vec<&str> = item["properties"]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(output_properties, vec!["id", "name"]);
    assert_eq!(item["required"], json!(["name", "id"]));
    assert_eq!(manifest.response_projection[0].as_str(), "");
    assert_eq!(manifest.timeout_seconds, 10);
    assert_eq!(manifest.pagination_limit, 10);
    assert_eq!(manifest.max_response_bytes, 262_144);

    // The generated package: the author file plus the host's regenerated files, sorted.
    let files = build_package(&[tool_file()], &OpRefs::new());
    let paths: Vec<&str> = files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(paths, vec!["kit.py", "ops.py", "tool.py"]);
    assert_eq!(files[0].content, kit_source());
    assert_eq!(
        files[1].content,
        "# Generated: operation id and exact version per key.\nOPS = {}\n"
    );
    assert_eq!(files[2], tool_file());
    assert_eq!(user_files(&files), vec![&files[2]]);
    // The host file is byte-identical to toolkits/_kit/kit.py of the Python checkout.
    assert_eq!(
        hex::encode(Sha256::digest(kit_source().as_bytes())),
        "cb3dc8579aebe3ff6bd1fbaa7805b49b42e0b2a0fd0953eeb35735d9d1ee6fcf"
    );
    assert!(
        validate_package(
            &files,
            "tool:main",
            &package_digest(&files),
            &PackageLimits::default()
        )
        .is_ok()
    );
}

#[test]
fn write_bodies_and_204_responses_follow_the_reference() {
    let doc = fastapi();
    let imported = import_openapi(
        &doc,
        &service(),
        &[
            Selection::operation_id("makeItem"),
            Selection::operation_id("optBody"),
            Selection::operation_id("dropItem"),
        ],
        Some(&SchemaLimits::default()),
        None,
    )
    .expect("imports");
    let make = &imported[0];
    assert_eq!(make.manifest.effect, Effect::Writes);
    assert_eq!(make.manifest.input_schema["required"], json!(["body"]));
    let item = &make.manifest.input_schema["$defs"]["Item"];
    assert!(item["properties"].get("id").is_none());
    assert!(item["properties"].get("secret").is_some());
    assert_eq!(item["required"], json!(["name"]));
    assert_eq!(
        make.manifest.mappings[0].location,
        mcp_server_rs::catalog::models::MappingLocation::Body
    );
    assert!(!make.manifest.mappings[0].optional);
    let output_properties: Vec<&str> = make.manifest.output_schema["$defs"]["Item"]["properties"]
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(output_properties, vec!["id", "name"]);
    assert!(imported[1].manifest.mappings[0].optional);
    let drop = &imported[2].manifest;
    assert!(drop.empty_response);
    assert_eq!(drop.effect, Effect::Writes);
    assert_eq!(drop.method, Method::Delete);
    assert!(!make.manifest.empty_response);
}

#[test]
fn selection_by_method_path_and_overrides_match_the_reference() {
    let doc = fastapi();
    let settings = SchemaLimits::default();
    let overrides = object(json!({
        "op_key": "fetch",
        "expected_error_statuses": [404],
        "timeout_seconds": 5,
        "response_projection": [""]
    }));
    let imported = import_openapi(
        &doc,
        &service(),
        &[Selection::method_path("get", "/items/{itemId}")],
        Some(&settings),
        Some(&overrides),
    )
    .expect("imports");
    assert_eq!(imported[0].op_key, "fetch");
    assert_eq!(imported[0].manifest.expected_error_statuses, vec![404]);
    assert_eq!(imported[0].manifest.timeout_seconds, 5);

    let per_operation = object(json!({"readItem": {"timeout_seconds": 3}}));
    let two = import_openapi(
        &doc,
        &service(),
        &[
            Selection::operation_id("readItem"),
            Selection::operation_id("makeItem"),
        ],
        Some(&settings),
        Some(&per_operation),
    )
    .expect("imports");
    assert_eq!(
        two.iter()
            .map(|operation| operation.manifest.timeout_seconds)
            .collect::<Vec<_>>(),
        vec![3, 10]
    );

    let error = import_openapi(
        &doc,
        &service(),
        &[
            Selection::operation_id("readItem"),
            Selection::operation_id("makeItem"),
        ],
        Some(&settings),
        Some(&object(json!({"op_key": "x"}))),
    )
    .expect_err("op_key needs one selection");
    assert_eq!(
        error.reason,
        "op_key can only be overridden when one operation is selected"
    );

    // The request model and the importer agree on the two selection shapes.
    let request: ImportRequest = serde_json::from_value(json!({
        "spec_sha256": "a".repeat(64),
        "select": ["readItem", {"method": "GET", "path": "/items/{itemId}"}],
    }))
    .expect("a valid import request");
    let selections: Vec<Selection> = request.select.iter().map(Selection::from_entry).collect();
    assert_eq!(selections[0], Selection::operation_id("readItem"));
    assert_eq!(
        selections[1],
        Selection::method_path("get", "/items/{itemId}")
    );
}

#[test]
fn the_refusal_table_is_stable() {
    let doc = fastapi();
    let listed = list_operations(&doc, None).expect("a valid document");
    let rows: BTreeMap<String, &mcp_server_rs::builder::openapi::OperationListing> = listed
        .iter()
        .filter_map(|row| row.operation_id.as_ref().map(|id| (id.clone(), row)))
        .collect();
    assert!(rows["readItem"].importable);
    assert_eq!(rows["readItem"].summary.as_deref(), Some("Read"));
    for (operation, expected) in [
        ("tree", "recursive"),
        ("chat", "deny list"),
        ("cookie", "cookie"),
        ("hdr", "required"),
        ("form", "JSON"),
        ("ext", "external"),
        ("broken", "no responses declared"),
        ("optionsOp", "OPTIONS is not supported"),
    ] {
        let reason = rows[operation].reason.as_deref().unwrap_or_default();
        assert!(
            !rows[operation].importable && reason.contains(expected),
            "{operation}: {reason}"
        );
    }
    assert!(listed.iter().any(|row| {
        row.method == "GET"
            && row.path == "/bad"
            && row.reason.as_deref() == Some("invalid operation")
    }));
    assert!(!listed.iter().any(|row| row.path == "/skip"));

    // Every refused operation cannot be selected, with the label and the reason in the message.
    for operation in ["tree", "chat", "cookie", "hdr", "form", "ext", "broken"] {
        let error = import_openapi(
            &doc,
            &service(),
            &[Selection::operation_id(operation)],
            Some(&SchemaLimits::default()),
            None,
        )
        .expect_err("refused");
        assert!(
            error.reason.contains("cannot be imported"),
            "{operation}: {}",
            error.reason
        );
    }
    let unknown = import_openapi(
        &doc,
        &service(),
        &[Selection::operation_id("nope")],
        Some(&SchemaLimits::default()),
        None,
    )
    .expect_err("unknown");
    assert_eq!(unknown.reason, "operation not found in the spec");
    let empty = import_openapi(&doc, &service(), &[], None, None).expect_err("empty");
    assert_eq!(empty.reason, "select at least one operation");
    for bad in [
        json!({"swagger": "2.0"}),
        json!({"openapi": "3.2.0", "paths": {}}),
        json!({"openapi": "3.0.0"}),
    ] {
        assert!(list_operations(&bad, None).is_err(), "{bad}");
    }
    assert_eq!(
        spec_info(&object(doc)),
        mcp_server_rs::builder::openapi::SpecInfo {
            title: Some("Items".to_owned()),
            version: Some("2".to_owned()),
        }
    );
}

#[test]
fn request_models_refuse_missing_and_malformed_fields() {
    assert!(serde_json::from_value::<ToolCreate>(json!({"public_name": "x"})).is_err());
    assert!(serde_json::from_value::<SpecFetchRequest>(json!({"path": "openapi.json"})).is_err());
    assert!(
        serde_json::from_value::<ImportRequest>(json!({
            "spec_sha256": "a".repeat(64),
            "select": [{"method": "get", "path": "/x"}],
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<ImportRequest>(json!({
            "spec_sha256": "a".repeat(64),
            "select": ["readItem"],
            "overrides": {"readItem": {"expected_error_statuses": [1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17]}},
        }))
        .is_err()
    );
    assert!(
        serde_json::from_value::<OperationOverride>(json!({"response_projection": []})).is_err()
    );
    let error = serde_json::from_value::<ToolOperation>(
        json!({"op_key": "get_customer", "source_key": "crm", "service": "fr"}),
    )
    .expect_err("two origins");
    assert!(
        error
            .to_string()
            .contains("name exactly one of source_key or service")
    );
    assert!(serde_json::from_value::<BindRequest>(json!({"product": "Bad Product"})).is_err());
    // The selection union refuses an unknown extra field rather than coercing it.
    assert!(
        serde_json::from_value::<ImportRequest>(json!({
            "spec_sha256": "a".repeat(64),
            "select": [{"method": "GET", "path": "/x", "extra": true}],
        }))
        .is_err()
    );
    assert!(serde_json::to_value(SelectionEntry::OperationId("readItem".to_owned())).is_ok());
}

#[test]
fn packaging_bounds_are_enforced_by_the_catalog() {
    let files = |count: usize, content: &str| -> Vec<PackageFile> {
        (0..count)
            .map(|index| PackageFile {
                path: format!("file{index}.py"),
                content: content.to_owned(),
            })
            .collect()
    };
    let limits = PackageLimits {
        max_package_files: 2,
        max_package_file_bytes: 10,
        max_package_bytes: 100,
    };
    assert_eq!(
        validate_package(&files(3, ""), "tool:main", "", &limits)
            .expect_err("too many files")
            .to_string(),
        "package file count outside configured limit"
    );
    assert_eq!(
        validate_package(&files(1, "xxxxxxxxxxx"), "tool:main", "", &limits)
            .expect_err("too large a file")
            .to_string(),
        "package file too large"
    );
    let total = PackageLimits {
        max_package_files: 5,
        max_package_file_bytes: 20_000,
        max_package_bytes: 10,
    };
    assert_eq!(
        validate_package(&files(2, "xxxxxx"), "tool:main", "", &total)
            .expect_err("too large a package")
            .to_string(),
        "package too large"
    );
    // `build_package` adds the host files but never enforces the limits: the catalog does.
    let built = build_package(&files(1, "xxxxxx"), &OpRefs::new());
    assert_eq!(built.len(), 3);
    assert_eq!(
        validate_package(&built, "tool:main", &package_digest(&built), &total)
            .expect_err("the host files overflow the total")
            .to_string(),
        "package too large"
    );
}

#[test]
fn round_trip_spec_operations_manifests_and_package() {
    let doc = fastapi();
    let settings = SchemaLimits::default();
    let listed = list_operations(&doc, Some(&settings)).expect("a valid document");
    let importable: Vec<&mcp_server_rs::builder::openapi::OperationListing> =
        listed.iter().filter(|row| row.importable).collect();
    assert_eq!(importable.len(), 4, "readItem, dropItem, makeItem, optBody");
    let selections: Vec<Selection> = importable
        .iter()
        .map(|row| Selection::method_path(row.method.to_lowercase(), row.path.clone()))
        .collect();
    let imported = import_openapi(&doc, &service(), &selections, Some(&settings), None)
        .expect("every importable operation imports");
    assert_eq!(imported.len(), importable.len());
    let keys: BTreeMap<&str, ()> = imported
        .iter()
        .map(|operation| (operation.op_key.as_str(), ()))
        .collect();
    assert_eq!(keys.len(), imported.len());
    assert!(
        imported
            .iter()
            .all(|operation| !operation.path.starts_with("/api/ai"))
    );

    let references: Vec<ExactReference> = imported
        .iter()
        .map(|operation| ExactReference {
            id: operation.manifest.operation_id.clone(),
            version: operation.manifest.version,
        })
        .collect();
    let mut refs = OpRefs::new();
    for operation in &imported {
        refs.insert(
            format!("crm.{}", operation.op_key),
            (
                operation.manifest.operation_id.clone(),
                operation.manifest.version,
            ),
        );
    }
    let files = build_package(&[tool_file()], &refs);
    assert_eq!(parse_ops(&files).expect("the generated table parses"), refs);

    let name = Name::new("find_customer").expect("a name");
    let operation = Operation::new("customer.find").expect("an operation");
    let schema = object(json!({"type": "object", "properties": {}, "additionalProperties": false}));
    let fields = manifest_fields(ManifestFieldArgs {
        public_name: &name,
        operation: &operation,
        description: "Find a customer",
        entrypoint: "tool:main",
        input_schema: &schema,
        result_schema: None,
        context_schema: None,
        effect: Effect::ReadOnly,
        limits: None,
    });
    let manifest = tool_manifest(ToolManifestInput {
        tool_id: &uuid(TOOL_ID),
        tenant_id: &AuthorityId::new(TENANT_ID).expect("a tenant identity"),
        version: version(1),
        fields: &fields,
        files: &files,
        refs: &references,
        runner_image_digest: &format!("registry.example/runner@sha256:{}", "a".repeat(64)),
    })
    .expect("the assembled manifest is valid");
    assert_eq!(manifest.allowed_operations.len(), references.len());
    assert_eq!(manifest.package_sha256.as_str(), package_digest(&files));
    assert_eq!(
        parse_ops(&files).expect("the table parses").len(),
        references.len()
    );
}

#[test]
fn spec_bytes_and_paths_match_the_reference() {
    let raw = br#"{"openapi": "3.1.0", "info": {"title": "Items", "version": "2"}, "paths": {}}"#;
    let document = parse_document(raw, 1024).expect("a JSON spec");
    assert_eq!(
        title_version(&document),
        (Some("Items".to_owned()), Some("2".to_owned()))
    );
    assert_eq!(digest(raw), hex::encode(Sha256::digest(raw)));
    assert_eq!(
        checked_spec_path(None, Some("/openapi.json")).expect("default"),
        "/openapi.json"
    );
    assert_eq!(
        checked_spec_path(None, None)
            .expect_err("no path")
            .message(),
        "the source has no spec_path; pass a path"
    );
    assert!(parse_document(b"openapi: 3.1.0\n", 1024).is_err());
}
