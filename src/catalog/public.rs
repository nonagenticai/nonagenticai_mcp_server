//! Public schema policy shared by authoring and binding selection.

use serde_json::{Value, json};

use crate::catalog::error::CatalogError;
use crate::catalog::toolkit_models::BoundContext;
use crate::catalog::validation::{ARRAYS, MAPS, SINGLE};

/// Names the platform reserves for its own run-control tools.
pub const RESERVED_NAMES: [&str; 2] = ["mcp_run_status", "mcp_run_cancel"];

/// Every run status the envelope's `status` may carry.
pub const RUN_STATUSES: [&str; 9] = [
    "queued",
    "starting",
    "running",
    "cancelling",
    "succeeded",
    "failed",
    "cancelled",
    "timed_out",
    "interrupted",
];

/// A public input must be a closed object and must not expose any bound-context field anywhere
/// in the schema tree (a caller could otherwise smuggle the platform's own context).
pub fn validate_public_input(schema: &Value) -> Result<(), CatalogError> {
    let closed = schema.get("type").and_then(Value::as_str) == Some("object")
        && schema.get("additionalProperties") == Some(&Value::Bool(false));
    if !closed {
        return Err(CatalogError(
            "public input must be a closed object and omit bound fields",
        ));
    }
    if overlaps(schema)? {
        return Err(CatalogError(
            "public input must be a closed object and omit bound fields",
        ));
    }
    Ok(())
}

/// Walk every node: a dict whose `properties` name a bound-context field overlaps.
fn overlaps(node: &Value) -> Result<bool, CatalogError> {
    match node {
        Value::Object(map) => {
            let properties = match map.get("properties") {
                None => None,
                Some(Value::Object(properties)) => Some(properties),
                Some(_) => return Err(CatalogError("invalid public schema properties")),
            };
            if let Some(properties) = properties
                && properties
                    .keys()
                    .any(|key| BoundContext::FIELD_NAMES.contains(&key.as_str()))
            {
                return Ok(true);
            }
            for value in map.values() {
                if overlaps(value)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        Value::Array(items) => {
            for item in items {
                if overlaps(item)? {
                    return Ok(true);
                }
            }
            Ok(false)
        }
        _ => Ok(false),
    }
}

/// The MCP result envelope for one tool result schema.
///
/// Only schema positions are walked, so a `$ref` sitting in a literal position (`default`,
/// `enum`, `const`) is not a reference and is left alone. A `$ref` in a schema position is
/// re-rooted under `#/$defs/tool_result`; anything not bundle-local is refused.
pub fn output_envelope(result_schema: &Value) -> Result<Value, CatalogError> {
    let mut schema = result_schema.clone();
    rebase(&mut schema)?;
    Ok(json!({
        "type": "object",
        "additionalProperties": false,
        "$defs": {"tool_result": schema},
        "required": ["run_id", "status", "result", "error"],
        "properties": {
            "run_id": {"type": "string", "minLength": 36, "maxLength": 36},
            "status": {"enum": RUN_STATUSES},
            "payload_expired": {"type": "boolean"},
            "result": {"anyOf": [{"$ref": "#/$defs/tool_result"}, {"type": "null"}]},
            "error": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["code", "message"],
                        "properties": {
                            "code": {"type": "string", "maxLength": 64},
                            "message": {"type": "string", "maxLength": 512},
                        },
                    },
                ]
            },
        },
    }))
}

fn rebase(node: &mut Value) -> Result<(), CatalogError> {
    let Value::Object(map) = node else {
        return Ok(());
    };
    let replacement = match map.get("$ref") {
        Some(Value::String(reference)) => {
            if !reference.starts_with('#') {
                return Err(CatalogError("external result reference"));
            }
            Some(format!("#/$defs/tool_result{}", &reference[1..]))
        }
        Some(_) => return Err(CatalogError("external result reference")),
        None => None,
    };
    if let Some(replacement) = replacement {
        map.insert("$ref".to_owned(), Value::String(replacement));
    }
    for (key, value) in map.iter_mut() {
        if MAPS.contains(&key.as_str()) {
            if let Value::Object(children) = value {
                for child in children.values_mut() {
                    rebase(child)?;
                }
            }
        } else if SINGLE.contains(&key.as_str()) {
            rebase(value)?;
        } else if ARRAYS.contains(&key.as_str())
            && let Value::Array(children) = value
        {
            for child in children {
                rebase(child)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn public_inputs_must_be_closed_objects() {
        assert!(
            validate_public_input(
                &json!({"type":"object","properties":{},"additionalProperties":false})
            )
            .is_ok()
        );
        assert!(validate_public_input(&json!({"type":"object","properties":{}})).is_err());
        assert!(
            validate_public_input(&json!({"type":"string","additionalProperties":false})).is_err()
        );
        assert!(
            validate_public_input(
                &json!({"type":"object","additionalProperties":false,"properties":{"tenant_id":{}}})
            )
            .is_err()
        );
        assert!(validate_public_input(&json!({"type":"object","additionalProperties":false,"properties":{"x":{"properties":{"project_id":{}}}}})).is_err());
        assert!(
            validate_public_input(
                &json!({"type":"object","additionalProperties":false,"properties":[]})
            )
            .is_err()
        );
    }

    #[test]
    fn envelope_reroots_schema_refs_only() {
        let schema = json!({
            "type": "object",
            "properties": {"x": {"$ref": "#/$defs/inner"}, "lit": {"default": {"$ref": "#/nope"}}},
            "$defs": {"inner": {"type": "string"}},
            "additionalProperties": false
        });
        let envelope = output_envelope(&schema).unwrap();
        assert_eq!(
            envelope["$defs"]["tool_result"]["properties"]["x"]["$ref"],
            json!("#/$defs/tool_result/$defs/inner")
        );
        assert_eq!(
            envelope["$defs"]["tool_result"]["properties"]["lit"]["default"]["$ref"],
            json!("#/nope")
        );
        assert_eq!(
            envelope["required"],
            json!(["run_id", "status", "result", "error"])
        );
        assert_eq!(
            envelope["properties"]["status"]["enum"],
            json!(RUN_STATUSES)
        );
        assert!(output_envelope(&json!({"$ref": "https://evil.test/x"})).is_err());
    }
}
