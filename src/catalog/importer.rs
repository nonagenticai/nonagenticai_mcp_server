//! Bounded OpenAPI 3.1 draft import. Publication still requires reviewed scope policy.
//!
//! Ported from the reference `src/catalog/importer.py` (`OperationImport`, `import_drafts`):
//! the same closed document subset, the same order of checks, the same generated manifest and
//! the same refusal messages.
//!
//! One reference behaviour is deliberately not reproduced: a malformed *nested* shape (a
//! parameter without `name` or `schema`, a `parameters` value that is not a list, a
//! `requestBody` or 200 response without a JSON content schema) raises an uncaught
//! `KeyError`/`TypeError` there — a 500 with no contract body — so it is not a refusal the
//! reference can express. This port refuses such a document as `invalid_request` instead of
//! crashing.

use serde::Deserialize;
use serde::de::Error as _;
use serde_json::{Map, Value, json};
use uuid::Uuid;

use crate::catalog::error::CatalogError;
use crate::catalog::models::{ExactReference, OperationManifest};
use crate::catalog::validation::{SchemaLimits, validate_schema};

/// The reference's `OperationImport`: one bundled OpenAPI document for one service version.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationImport {
    /// The exact platform service version the drafts belong to.
    pub service: ExactReference,
    /// The bundled OpenAPI 3.1 document (openapi/info/paths only).
    pub document: Map<String, Value>,
    /// The draft-count ceiling, 1 to 128. Checked after each draft is appended.
    #[serde(
        default = "default_max_operations",
        deserialize_with = "max_operations"
    )]
    pub max_operations: u32,
}

/// The reference's `Field(default=32, ge=1, le=128)`.
fn default_max_operations() -> u32 {
    32
}

fn max_operations<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    let value = u32::deserialize(deserializer)?;
    if (1..=128).contains(&value) {
        Ok(value)
    } else {
        Err(D::Error::custom("max_operations must be 1 to 128"))
    }
}

/// The reference's `import_drafts`: the document's operations as version-1 drafts.
///
/// Every refusal message is the reference's own; the drafts are unvalidated against a live
/// service on purpose (publication still requires reviewed scope policy and a source).
pub fn import_drafts(
    payload: &OperationImport,
    limits: &SchemaLimits,
) -> Result<Vec<OperationManifest>, CatalogError> {
    let document = &payload.document;
    let bundled = document.get("openapi").and_then(Value::as_str) == Some("3.1.0")
        && document
            .keys()
            .all(|key| matches!(key.as_str(), "openapi" | "info" | "paths"));
    if !bundled {
        return Err(CatalogError::new(
            "v1 importer requires a bundled OpenAPI 3.1 document without references",
        ));
    }
    let Some(Value::Object(paths)) = document.get("paths") else {
        return Err(CatalogError::new("paths required"));
    };
    let mut result = Vec::new();
    for (path, methods) in paths {
        let Value::Object(methods) = methods else {
            return Err(CatalogError::new("invalid path"));
        };
        for (method, definition) in methods {
            if !matches!(method.as_str(), "get" | "post" | "put" | "patch" | "delete") {
                return Err(CatalogError::new("unsupported OpenAPI operation"));
            }
            let Value::Object(definition) = definition else {
                return Err(CatalogError::new("unsupported OpenAPI operation"));
            };
            if definition.keys().any(|key| {
                !matches!(
                    key.as_str(),
                    "summary"
                        | "description"
                        | "operationId"
                        | "requestBody"
                        | "responses"
                        | "parameters"
                )
            }) {
                return Err(CatalogError::new("unsupported OpenAPI operation field"));
            }

            let mut properties = Map::new();
            let mut required: Vec<Value> = Vec::new();
            let mut mappings: Vec<Value> = Vec::new();
            let parameters: &[Value] = match definition.get("parameters") {
                None => &[],
                Some(Value::Array(parameters)) => parameters.as_slice(),
                Some(_) => return Err(CatalogError::new("unsupported parameter")),
            };
            for parameter in parameters {
                let Value::Object(parameter) = parameter else {
                    return Err(CatalogError::new("unsupported parameter"));
                };
                if parameter.keys().any(|key| {
                    !matches!(
                        key.as_str(),
                        "name" | "in" | "required" | "schema" | "description"
                    )
                }) {
                    return Err(CatalogError::new("unsupported parameter"));
                }
                let Some(location) = parameter.get("in").and_then(Value::as_str) else {
                    return Err(CatalogError::new("unsupported parameter"));
                };
                if !matches!(location, "path" | "query") {
                    return Err(CatalogError::new("unsupported parameter"));
                }
                let Some(name) = parameter.get("name").and_then(Value::as_str) else {
                    return Err(CatalogError::new("unsupported parameter"));
                };
                if properties.contains_key(name) {
                    return Err(CatalogError::new("duplicate parameter"));
                }
                let Some(schema) = parameter.get("schema").cloned() else {
                    return Err(CatalogError::new("unsupported parameter"));
                };
                properties.insert(name.to_owned(), schema);
                if parameter.get("required").is_some_and(truthy) {
                    required.push(Value::String(name.to_owned()));
                }
                mappings.push(json!({
                    "location": location,
                    "target": name,
                    "value": {"source": "input", "pointer": format!("/{name}")},
                }));
            }
            if let Some(request_body) = definition.get("requestBody") {
                if properties.contains_key("body") {
                    return Err(CatalogError::new("body parameter collision"));
                }
                let schema = request_body
                    .get("content")
                    .and_then(|content| content.get("application/json"))
                    .and_then(|media| media.get("schema"))
                    .cloned()
                    .ok_or(CatalogError::new("unsupported OpenAPI operation field"))?;
                properties.insert("body".to_owned(), schema);
                if request_body.get("required").is_some_and(truthy) {
                    required.push(Value::String("body".to_owned()));
                }
                mappings.push(json!({
                    "location": "body",
                    "target": "",
                    "value": {"source": "input", "pointer": "/body"},
                }));
            }
            let responses = match definition.get("responses") {
                Some(Value::Object(responses)) => responses,
                _ => {
                    return Err(CatalogError::new(
                        "import requires one explicit JSON 200 response",
                    ));
                }
            };
            if responses.len() != 1 || !responses.contains_key("200") {
                return Err(CatalogError::new(
                    "import requires one explicit JSON 200 response",
                ));
            }
            let output = responses
                .get("200")
                .and_then(|response| response.get("content"))
                .and_then(|content| content.get("application/json"))
                .and_then(|media| media.get("schema"))
                .cloned()
                .ok_or(CatalogError::new(
                    "import requires one explicit JSON 200 response",
                ))?;
            let inputs = json!({
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": false,
            });
            validate_schema(&inputs, limits)?;
            validate_schema(&output, limits)?;
            let query_fields: Vec<Value> = mappings
                .iter()
                .filter(|mapping| mapping.get("location").and_then(Value::as_str) == Some("query"))
                .filter_map(|mapping| mapping.get("target").cloned())
                .collect();
            let draft = json!({
                "operation_id": Uuid::now_v7().to_string(),
                "version": 1,
                "service": payload.service,
                "method": method.to_ascii_uppercase(),
                "path_template": path,
                "query_fields": query_fields,
                "mappings": mappings,
                "input_schema": inputs,
                "output_schema": output,
                "response_projection": [""],
                "effect": if method.as_str() == "get" { "read_only" } else { "writes" },
                "timeout_seconds": 10,
                "pagination_limit": 1,
                "max_response_bytes": 65536,
            });
            let manifest: OperationManifest = serde_json::from_value(draft)
                .map_err(|_| CatalogError::new("invalid operation manifest"))?;
            result.push(manifest);
            if result.len() > payload.max_operations as usize {
                return Err(CatalogError::new("import operation limit"));
            }
        }
    }
    if result.is_empty() {
        return Err(CatalogError::new("empty import"));
    }
    Ok(result)
}

/// Python's truthiness of a JSON value, as the reference's `if parameter.get("required")` uses.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(value) => !value.is_empty(),
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
    }
}
