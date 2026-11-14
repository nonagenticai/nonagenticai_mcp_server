//! Catalog slice acceptance: strict manifests, the closed JSON-Schema subset, named formats,
//! public schema policy and the lifecycle matrices. Each test fails if the behaviour it covers
//! is removed.

use serde_json::{Value, json};

use mcp_server_rs::catalog::CatalogError;
use mcp_server_rs::catalog::formats;
use mcp_server_rs::catalog::ids::{AppKey, Digest, ImageDigest, Name, Operation, Pointer};
use mcp_server_rs::catalog::lifecycle::{
    TOOL_TRANSITIONS, TOOLKIT_TRANSITIONS, VersionStatus, tool_transition_allowed,
    toolkit_transition_allowed,
};
use mcp_server_rs::catalog::models::{Runtime, ToolLimits, ToolManifest, VersionDescriptor};
use mcp_server_rs::catalog::package::canonical_path;
use mcp_server_rs::catalog::public::{
    RESERVED_NAMES, RUN_STATUSES, output_envelope, validate_public_input,
};
use mcp_server_rs::catalog::validation::{
    ARRAYS, DIALECT, MAPS, SINGLE, SUPPORTED, SchemaLimits, bounded_json, validate_schema,
};

fn err<T: std::fmt::Debug>(result: Result<T, CatalogError>) -> String {
    result.unwrap_err().to_string()
}

fn manifest_json() -> Value {
    json!({
        "schema_version": 1,
        "tool_id": "20000000-0000-7000-8000-000000000001",
        "tenant_id": "10000000-0000-7000-8000-000000000001",
        "version": 1,
        "public_name": "synthetic_tool",
        "operation": "synthetic.synthetic_tool",
        "description": "Synthetic fixture",
        "runtime": "kata_python",
        "entrypoint": "package.main:run",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "runner_image_digest": format!("registry.example/runner@sha256:{}", "a".repeat(64)),
        "effect": "read_only",
    })
}

fn with_change(changes: Value) -> Value {
    let mut value = manifest_json();
    for (key, change) in changes.as_object().expect("object of changes") {
        value[key] = change.clone();
    }
    value
}

fn parsed(value: Value) -> Result<ToolManifest, serde_json::Error> {
    serde_json::from_value(value)
}

#[test]
fn a_valid_manifest_is_accepted() {
    let manifest = parsed(manifest_json()).expect("valid manifest");
    assert_eq!(manifest.public_name.as_str(), "synthetic_tool");
    assert_eq!(manifest.operation.as_str(), "synthetic.synthetic_tool");
    assert_eq!(manifest.runtime, Runtime::KataPython);
    assert_eq!(manifest.limits, ToolLimits::default());
    assert_eq!(manifest.limits.output_bytes, 262_144);
    for schema in [
        &manifest.input_schema,
        &manifest.result_schema,
        &manifest.context_schema,
    ] {
        validate_schema(&Value::Object(schema.clone()), &SchemaLimits::default())
            .expect("manifest schema");
    }
    validate_public_input(&Value::Object(manifest.input_schema.clone())).expect("public input");
    let envelope =
        output_envelope(&Value::Object(manifest.result_schema.clone())).expect("envelope");
    validate_schema(&envelope, &SchemaLimits::default()).expect("envelope schema");

    // Field names are the reference names exactly, including explicit nulls.
    let encoded = serde_json::to_value(&manifest).expect("serializes");
    for field in [
        "schema_version",
        "tool_id",
        "tenant_id",
        "version",
        "public_name",
        "operation",
        "description",
        "runtime",
        "target",
        "entrypoint",
        "input_schema",
        "result_schema",
        "context_schema",
        "package_sha256",
        "runner_image_digest",
        "allowed_operations",
        "operation_constraints",
        "limits",
        "effect",
    ] {
        assert!(encoded.get(field).is_some(), "missing field {field}");
    }
    assert_eq!(encoded["target"], Value::Null);
    assert_eq!(encoded["schema_version"], 1);
}

#[test]
fn manifests_reject_unknown_fields_and_never_coerce() {
    let mut unknown = manifest_json();
    unknown["unknown"] = json!("field");
    assert!(parsed(unknown).is_err(), "extra fields are forbidden");

    for changes in [
        json!({"version": "1"}),
        json!({"version": 1.0}),
        json!({"version": true}),
        json!({"version": 0}),
        json!({"version": 2_147_483_648_u64}),
        json!({"schema_version": 2}),
        json!({"schema_version": true}),
        json!({"schema_version": "1"}),
        json!({"runtime": "in_process"}),
        json!({"runner_image_digest": "runner:latest"}),
        json!({"tenant_id": "tenant"}),
        json!({"public_name": "../tool"}),
        json!({"limits": {"wall_seconds": 0}}),
        json!({"limits": {"wall_seconds": true}}),
        json!({"limits": {"frame_bytes": 100, "output_bytes": 10}}),
    ] {
        assert!(parsed(with_change(changes.clone())).is_err(), "{changes}");
    }

    // Omitted optional fields take the reference defaults; a partial limits object is filled.
    let mut value = manifest_json();
    value.as_object_mut().expect("object").remove("limits");
    value
        .as_object_mut()
        .expect("object")
        .remove("allowed_operations");
    let manifest = parsed(value).expect("defaults");
    assert_eq!(manifest.limits, ToolLimits::default());
    assert!(manifest.allowed_operations.is_empty());

    let manifest =
        parsed(with_change(json!({"limits": {"wall_seconds": 5}}))).expect("partial limits");
    assert_eq!(manifest.limits.wall_seconds, 5);
    assert_eq!(manifest.limits.queue_seconds, 60);
    assert_eq!(manifest.limits.frame_bytes, 65_536);
}

#[test]
fn names_and_operations_are_pattern_checked() {
    assert!(Name::new("synthetic_tool").is_ok());
    for name in ["Tool", "tool-name", "1tool", "", "../tool"] {
        assert!(Name::new(name).is_err(), "{name}");
    }
    assert!(Name::new("a".repeat(64)).is_ok());
    assert!(Name::new("a".repeat(65)).is_err());

    assert!(Operation::new("synthetic.synthetic_tool").is_ok());
    for operation in [
        "synthetic",
        "Synthetic.get",
        "synthetic.Get",
        "a.b.c",
        "synthetic..get",
    ] {
        assert!(Operation::new(operation).is_err(), "{operation}");
    }

    assert!(AppKey::new("care-bus").is_ok());
    assert!(AppKey::new("CareBus").is_err());
    assert!(Digest::new("a".repeat(64)).is_ok());
    assert!(Digest::new("A".repeat(64)).is_err());
    assert!(ImageDigest::new(format!("registry.example/runner@sha256:{}", "a".repeat(64))).is_ok());
    assert!(ImageDigest::new("runner:latest").is_err());
    assert!(Pointer::new("/a/b").is_ok());
    assert!(Pointer::new("a").is_err());

    assert!(parsed(with_change(json!({"public_name": "../tool"}))).is_err());
    assert!(parsed(with_change(json!({"operation": "not an operation"}))).is_err());
}

#[test]
fn every_unsupported_keyword_is_refused() {
    let limits = SchemaLimits::default();
    for keyword in [
        "$anchor",
        "$comment",
        "$dynamicRef",
        "$id",
        "$vocabulary",
        "contains",
        "contentEncoding",
        "contentMediaType",
        "dependentRequired",
        "dependentSchemas",
        "deprecated",
        "examples",
        "if",
        "then",
        "else",
        "maxContains",
        "minContains",
        "pattern",
        "propertyNames",
        "readOnly",
        "unevaluatedItems",
        "unevaluatedProperties",
        "uniqueItems",
        "writeOnly",
    ] {
        let mut schema = serde_json::Map::new();
        schema.insert(keyword.to_owned(), json!("x"));
        let schema = Value::Object(schema);
        assert_eq!(
            err(validate_schema(&schema, &limits)),
            "unsupported schema keyword",
            "{keyword}"
        );
    }

    // The supported set is the reference's, exactly, and never includes `pattern`.
    let mut sorted = SUPPORTED.to_vec();
    sorted.sort_unstable();
    assert_eq!(
        sorted,
        vec![
            "$defs",
            "$ref",
            "$schema",
            "additionalProperties",
            "allOf",
            "anyOf",
            "const",
            "default",
            "description",
            "enum",
            "exclusiveMaximum",
            "exclusiveMinimum",
            "format",
            "items",
            "maxItems",
            "maxLength",
            "maxProperties",
            "maximum",
            "minItems",
            "minLength",
            "minProperties",
            "minimum",
            "not",
            "oneOf",
            "prefixItems",
            "properties",
            "required",
            "title",
            "type",
        ]
    );
    assert_eq!(MAPS, ["$defs", "properties"].as_slice());
    assert_eq!(SINGLE, ["additionalProperties", "items", "not"].as_slice());
    assert_eq!(
        ARRAYS,
        ["prefixItems", "allOf", "anyOf", "oneOf"].as_slice()
    );
}

#[test]
fn external_references_are_refused() {
    let limits = SchemaLimits::default();
    for reference in [
        "https://evil.test/schema",
        "file:///etc/passwd",
        "other.json#/$defs/a",
        "#",
    ] {
        let schema = json!({"$ref": reference});
        assert_eq!(
            err(validate_schema(&schema, &limits)),
            "only bounded bundle-local $defs references are supported",
            "{reference}"
        );
    }
    let schema = json!({"$ref": "#/$defs/missing", "$defs": {}});
    assert_eq!(
        err(validate_schema(&schema, &limits)),
        "unresolved local schema reference"
    );
}

#[test]
fn recursive_references_are_refused() {
    let limits = SchemaLimits::default();
    let schema = json!({"$defs": {"cycle": {"$ref": "#/$defs/cycle"}}});
    assert_eq!(
        err(validate_schema(&schema, &limits)),
        "recursive schema references are unsupported"
    );
    let schema = json!({
        "$defs": {"a": {"$ref": "#/$defs/b"}, "b": {"$ref": "#/$defs/a"}},
        "allOf": [{"$ref": "#/$defs/a"}],
    });
    assert_eq!(
        err(validate_schema(&schema, &limits)),
        "recursive schema references are unsupported"
    );
    // A shared, non-cyclic reference is fine.
    let schema = json!({
        "$defs": {"a": {}},
        "allOf": [{"$ref": "#/$defs/a"}, {"$ref": "#/$defs/a"}],
    });
    assert!(validate_schema(&schema, &limits).is_ok());
}

#[test]
fn only_the_2020_12_dialect_is_accepted() {
    let limits = SchemaLimits::default();
    for dialect in [
        "http://json-schema.org/draft-07/schema#",
        "https://json-schema.org/draft/2019-09/schema",
        "https://json-schema.org/draft/2020-12/schema/",
    ] {
        let schema = json!({"$schema": dialect});
        assert_eq!(
            err(validate_schema(&schema, &limits)),
            "unsupported JSON Schema dialect",
            "{dialect}"
        );
    }
    assert!(validate_schema(&json!({"$schema": DIALECT}), &limits).is_ok());
    assert!(validate_schema(&json!({"$schema": 1}), &limits).is_err());
}

#[test]
fn formats_must_be_registered() {
    let limits = SchemaLimits::default();
    for format in ["uri", "regex", "email", "date-time", "hostname"] {
        let schema = json!({"type": "string", "format": format});
        assert_eq!(
            err(validate_schema(&schema, &limits)),
            "unregistered string format",
            "{format}"
        );
    }
    for (name, _) in formats::FORMATS {
        let schema = json!({"type": "string", "format": name});
        assert!(validate_schema(&schema, &limits).is_ok(), "{name}");
    }
    for (name, value, expected) in [
        ("container-name", "a-b", Some(true)),
        ("container-name", "A", Some(false)),
        ("git-branch", "feat/catalog", Some(true)),
        ("git-branch", "-x", Some(false)),
        (
            "repo-url-https",
            "https://github.com/owner/repo",
            Some(true),
        ),
        (
            "repo-url-https",
            "http://github.com/owner/repo",
            Some(false),
        ),
        ("relative-path", "src/main.rs", Some(true)),
        ("relative-path", "/src/main.rs", Some(false)),
        ("package-name", "@scope/name", Some(true)),
        ("package-name", "-name", Some(false)),
        ("uuid", "10000000-0000-7000-8000-000000000001", Some(true)),
        ("uuid", "not-a-uuid", Some(false)),
        ("idempotency-key", "abcd1234", Some(true)),
        ("idempotency-key", "short", Some(false)),
        ("resume-token", "abc.def", Some(true)),
        ("resume-token", "abc", Some(false)),
        ("uri", "x", None),
    ] {
        assert_eq!(formats::check(name, value), expected, "{name}: {value}");
    }
}

#[test]
fn raw_pattern_is_never_accepted() {
    let limits = SchemaLimits::default();
    let schema = json!({"type": "string", "pattern": "^[a-z]+$"});
    assert_eq!(
        err(validate_schema(&schema, &limits)),
        "unsupported schema keyword"
    );
    assert!(!SUPPORTED.contains(&"pattern"));
}

#[test]
fn bounds_are_enforced() {
    assert_eq!(
        err(bounded_json(&json!("x".repeat(11)), 10, 100, 10)),
        "JSON string exceeds byte limit"
    );
    assert_eq!(
        err(bounded_json(&json!(vec![0; 11]), 100, 10, 10)),
        "JSON array exceeds node limit"
    );
    assert_eq!(
        err(bounded_json(&json!({"a": {"b": 1}}), 100, 100, 1)),
        "JSON complexity exceeds configured limits"
    );
    assert_eq!(
        err(bounded_json(&json!({"a": "x"}), 5, 100, 10)),
        "JSON byte limit exceeded"
    );

    let schema = json!({
        "type": "object",
        "properties": {"count": {"type": "integer", "minimum": 0}},
        "required": ["count"],
        "additionalProperties": false,
    });
    for limits in [
        SchemaLimits {
            max_bytes: 5,
            ..SchemaLimits::default()
        },
        SchemaLimits {
            max_nodes: 3,
            ..SchemaLimits::default()
        },
        SchemaLimits {
            max_depth: 1,
            ..SchemaLimits::default()
        },
    ] {
        assert!(validate_schema(&schema, &limits).is_err());
    }
    let references = json!({
        "$defs": {"a": {}},
        "allOf": [{"$ref": "#/$defs/a"}, {"$ref": "#/$defs/a"}],
    });
    let limits = SchemaLimits {
        max_references: 1,
        ..SchemaLimits::default()
    };
    assert_eq!(
        err(validate_schema(&references, &limits)),
        "only bounded bundle-local $defs references are supported"
    );
}

#[test]
fn public_input_must_be_closed_and_omit_bound_fields() {
    assert!(
        validate_public_input(&json!({
            "type": "object",
            "properties": {"message": {"type": "string"}},
            "additionalProperties": false,
        }))
        .is_ok()
    );
    for bad in [
        json!({"type": "object", "properties": {}}),
        json!({"type": "string", "additionalProperties": false}),
        json!({"type": "object", "additionalProperties": true}),
    ] {
        assert_eq!(
            err(validate_public_input(&bad)),
            "public input must be a closed object and omit bound fields",
            "{bad}"
        );
    }

    for field in [
        "tenant_id",
        "project_id",
        "workspace_id",
        "project_phase",
        "work_type",
        "card_stage",
        "responsibility",
        "test_command",
        "reviewed_commit",
    ] {
        let mut schema = serde_json::Map::new();
        schema.insert("type".to_owned(), json!("object"));
        schema.insert("additionalProperties".to_owned(), json!(false));
        let mut properties = serde_json::Map::new();
        properties.insert(field.to_owned(), json!({"type": "string"}));
        schema.insert("properties".to_owned(), Value::Object(properties));
        assert!(
            validate_public_input(&Value::Object(schema)).is_err(),
            "{field} must not be public"
        );
    }

    let nested = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"x": {"properties": {"project_id": {}}}},
    });
    assert!(validate_public_input(&nested).is_err());
    let open_properties = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": [],
    });
    assert_eq!(
        err(validate_public_input(&open_properties)),
        "invalid public schema properties"
    );

    assert!(RESERVED_NAMES.contains(&"mcp_run_status"));
    assert!(RESERVED_NAMES.contains(&"mcp_run_cancel"));
}

#[test]
fn output_envelope_has_the_reference_shape() {
    let result_schema = json!({
        "type": "object",
        "properties": {"x": {"$ref": "#/$defs/inner"}},
        "$defs": {"inner": {"type": "string"}},
        "additionalProperties": false,
    });
    let envelope = output_envelope(&result_schema).expect("envelope");
    assert_eq!(envelope["type"], "object");
    assert_eq!(envelope["additionalProperties"], false);
    assert_eq!(
        envelope["required"],
        json!(["run_id", "status", "result", "error"])
    );
    assert_eq!(
        envelope["properties"]["status"]["enum"],
        json!(RUN_STATUSES)
    );
    assert_eq!(
        envelope["properties"]["run_id"],
        json!({"type": "string", "minLength": 36, "maxLength": 36})
    );
    assert_eq!(
        envelope["properties"]["payload_expired"],
        json!({"type": "boolean"})
    );
    assert_eq!(
        envelope["properties"]["result"]["anyOf"],
        json!([{"$ref": "#/$defs/tool_result"}, {"type": "null"}])
    );
    assert_eq!(
        envelope["properties"]["error"]["anyOf"][0],
        json!({"type": "null"})
    );
    assert_eq!(
        envelope["properties"]["error"]["anyOf"][1]["required"],
        json!(["code", "message"])
    );
    assert_eq!(
        envelope["properties"]["error"]["anyOf"][1]["properties"]["code"],
        json!({"type": "string", "maxLength": 64})
    );
    assert_eq!(
        envelope["$defs"]["tool_result"]["properties"]["x"]["$ref"],
        json!("#/$defs/tool_result/$defs/inner")
    );
    validate_schema(&envelope, &SchemaLimits::default()).expect("envelope is a valid schema");

    // A `$ref` in a literal position is data, not a reference: it is left untouched.
    let literal = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {},
        "default": {"$ref": "#/whatever"},
        "enum": [{"$ref": "https://evil.test/x"}],
    });
    let envelope = output_envelope(&literal).expect("envelope");
    assert_eq!(
        envelope["$defs"]["tool_result"]["default"]["$ref"],
        "#/whatever"
    );
    assert_eq!(
        envelope["$defs"]["tool_result"]["enum"][0]["$ref"],
        "https://evil.test/x"
    );

    assert_eq!(
        err(output_envelope(&json!({"$ref": "https://evil.test/x"}))),
        "external result reference"
    );
}

#[test]
fn tool_transition_matrix_is_exact() {
    let allowed = [
        (VersionStatus::Draft, VersionStatus::Published),
        (VersionStatus::Draft, VersionStatus::Disabled),
        (VersionStatus::Draft, VersionStatus::Retired),
        (VersionStatus::Published, VersionStatus::Disabled),
        (VersionStatus::Published, VersionStatus::Retired),
        (VersionStatus::Disabled, VersionStatus::Retired),
    ];
    assert_eq!(TOOL_TRANSITIONS.len(), 6);
    for from in VersionStatus::ALL {
        for to in VersionStatus::ALL {
            assert_eq!(
                tool_transition_allowed(from, to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
            assert_eq!(
                from.allowed_tool_transitions().any(|status| status == to),
                allowed.contains(&(from, to))
            );
        }
    }
}

#[test]
fn toolkit_transition_matrix_is_exact() {
    let allowed = [
        (VersionStatus::Draft, VersionStatus::Published),
        (VersionStatus::Draft, VersionStatus::Disabled),
        (VersionStatus::Published, VersionStatus::Disabled),
    ];
    assert_eq!(TOOLKIT_TRANSITIONS.len(), 3);
    for from in VersionStatus::ALL {
        for to in VersionStatus::ALL {
            assert_eq!(
                toolkit_transition_allowed(from, to),
                allowed.contains(&(from, to)),
                "{from:?} -> {to:?}"
            );
            assert_eq!(
                from.allowed_toolkit_transitions()
                    .any(|status| status == to),
                allowed.contains(&(from, to))
            );
        }
    }
}

#[test]
fn runtime_shapes_are_enforced() {
    let mut target = manifest_json();
    target["target"] = json!({"kind": "n8n_workflow", "webhook_path": "mcp/demo"});
    assert!(
        parsed(target)
            .unwrap_err()
            .to_string()
            .contains("take no external target")
    );

    let mut missing = manifest_json();
    missing["runtime"] = json!("n8n_workflow");
    missing["entrypoint"] = Value::Null;
    missing["runner_image_digest"] = Value::Null;
    assert!(
        parsed(missing)
            .unwrap_err()
            .to_string()
            .contains("target whose kind matches")
    );

    let mut external = manifest_json();
    external["runtime"] = json!("n8n_workflow");
    external["target"] = json!({"kind": "n8n_workflow", "webhook_path": "mcp/demo"});
    external["entrypoint"] = Value::Null;
    external["runner_image_digest"] = Value::Null;
    let external = parsed(external).expect("external tool");
    assert_eq!(external.runtime, Runtime::N8nWorkflow);
    assert_eq!(
        serde_json::to_value(&external).unwrap()["target"],
        json!({"kind": "n8n_workflow", "webhook_path": "mcp/demo", "result_node": "MCP Result"})
    );
}

#[test]
fn descriptors_carry_the_reference_statuses() {
    let descriptor = json!({
        "tenant_id": "10000000-0000-7000-8000-000000000001",
        "tool_id": "20000000-0000-7000-8000-000000000001",
        "version": 1,
        "revision": 1,
        "status": "draft",
        "manifest": manifest_json(),
        "created_by": {"subject": "synthetic-subject"},
    });
    let parsed_descriptor: VersionDescriptor =
        serde_json::from_value(descriptor.clone()).expect("descriptor");
    assert_eq!(parsed_descriptor.status, VersionStatus::Draft);
    for status in ["published", "disabled", "retired"] {
        let mut value = descriptor.clone();
        value["status"] = json!(status);
        assert!(
            serde_json::from_value::<VersionDescriptor>(value).is_ok(),
            "{status}"
        );
    }
    let mut bad = descriptor;
    bad["status"] = json!("archived");
    assert!(serde_json::from_value::<VersionDescriptor>(bad).is_err());
    let mut bad = descriptor_json_with_unknown();
    bad["created_by"] = json!({"subject": ""});
    assert!(serde_json::from_value::<VersionDescriptor>(bad).is_err());
}

fn descriptor_json_with_unknown() -> Value {
    json!({
        "tenant_id": "10000000-0000-7000-8000-000000000001",
        "tool_id": "20000000-0000-7000-8000-000000000001",
        "version": 1,
        "revision": 1,
        "status": "draft",
        "manifest": manifest_json(),
        "created_by": {"subject": "synthetic-subject", "unknown": true},
    })
}

#[test]
fn package_paths_are_canonical() {
    assert_eq!(
        canonical_path("package/main.py").unwrap(),
        "package/main.py"
    );
    for path in ["", "/main.py", "a/../b", "a//b", "a\\b", "c:x"] {
        assert!(canonical_path(path).is_err(), "{path:?}");
    }
}
