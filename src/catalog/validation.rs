//! Closed, bounded Draft 2020-12 subset. No network, no author-supplied regex evaluation.
//!
//! The Rust walk mirrors the reference exactly: the same supported keyword set, the same
//! sub-schema positions, a local non-recursive `$ref` rule, a registered-`format` rule, and the
//! same meta-schema refusals for the supported subset. The reference's bounded LRU of successful
//! validations is deliberately not ported: it existed because Python's meta-validation made
//! `tools/list` slow, and this walk is a small constant-cost pass.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::catalog::error::CatalogError;
use crate::catalog::formats;

/// The one accepted JSON Schema dialect.
pub const DIALECT: &str = "https://json-schema.org/draft/2020-12/schema";

/// Every keyword a schema may use. Raw `pattern` is absent on purpose: a schema author's regex
/// would run on untrusted input.
pub const SUPPORTED: &[&str] = &[
    "$schema",
    "$defs",
    "$ref",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "items",
    "prefixItems",
    "minItems",
    "maxItems",
    "minProperties",
    "maxProperties",
    "minLength",
    "maxLength",
    "minimum",
    "maximum",
    "exclusiveMinimum",
    "exclusiveMaximum",
    "enum",
    "const",
    "allOf",
    "anyOf",
    "oneOf",
    "not",
    "title",
    "description",
    "default",
    "format",
];

/// Positions whose value is a map of schemas.
pub const MAPS: &[&str] = &["$defs", "properties"];
/// Positions whose value is a single schema.
pub const SINGLE: &[&str] = &["additionalProperties", "items", "not"];
/// Positions whose value is a bounded array of schemas.
pub const ARRAYS: &[&str] = &["prefixItems", "allOf", "anyOf", "oneOf"];

/// The schema and instance limits. Defaults are the reference `Settings` defaults.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaLimits {
    /// Maximum UTF-8 bytes of the serialized schema.
    pub max_bytes: usize,
    /// Maximum expanded schema nodes.
    pub max_nodes: usize,
    /// Maximum nesting depth.
    pub max_depth: usize,
    /// Maximum `$ref` occurrences.
    pub max_references: usize,
    /// Maximum UTF-8 bytes of the serialized instance.
    pub max_instance_bytes: usize,
    /// Maximum instance nodes.
    pub max_instance_nodes: usize,
    /// Maximum instance nesting depth.
    pub max_instance_depth: usize,
    /// Maximum schema-work times instance-work a validation may charge.
    pub max_validation_work: usize,
}

impl Default for SchemaLimits {
    fn default() -> Self {
        Self {
            max_bytes: 65_536,
            max_nodes: 1_024,
            max_depth: 16,
            max_references: 32,
            max_instance_bytes: 1_048_576,
            max_instance_nodes: 10_000,
            max_instance_depth: 32,
            max_validation_work: 100_000,
        }
    }
}

/// Count nodes and enforce the byte, node and depth bounds before serializing.
///
/// The per-string bound counts characters, exactly as the reference's `len(item)` on a `str`
/// does; so the refusal point is identical. The aggregate bound counts UTF-8 bytes of the
/// serialized value, as the reference's final check does. Every refusal message is the
/// reference's. The reference's "JSON object keys must be strings" check cannot fail here:
/// `serde_json::Value` object keys are always strings.
pub fn bounded_json(
    value: &Value,
    max_bytes: usize,
    max_nodes: usize,
    max_depth: usize,
) -> Result<usize, CatalogError> {
    let mut stack = vec![(value, 0usize)];
    let mut nodes = 0usize;
    while let Some((item, depth)) = stack.pop() {
        nodes += 1;
        if nodes > max_nodes || depth > max_depth {
            return Err(CatalogError("JSON complexity exceeds configured limits"));
        }
        match item {
            Value::String(text) if text.chars().count() > max_bytes => {
                return Err(CatalogError("JSON string exceeds byte limit"));
            }
            Value::Object(map) => {
                if map.len() > max_nodes {
                    return Err(CatalogError("JSON object exceeds node limit"));
                }
                stack.extend(map.values().map(|child| (child, depth + 1)));
            }
            Value::Array(items) => {
                if items.len() > max_nodes {
                    return Err(CatalogError("JSON array exceeds node limit"));
                }
                stack.extend(items.iter().map(|child| (child, depth + 1)));
            }
            Value::Number(number) => {
                if let Some(float) = number.as_f64()
                    && !float.is_finite()
                {
                    return Err(CatalogError(
                        "Out of range float values are not JSON compliant",
                    ));
                }
            }
            _ => {}
        }
    }
    if serialized_len(value) > max_bytes {
        return Err(CatalogError("JSON byte limit exceeded"));
    }
    Ok(nodes)
}

/// Length of Python's default `json.dumps(value, ensure_ascii=False, allow_nan=False)` output in
/// UTF-8 bytes: default separators are `", "` and `": "`, non-ASCII is emitted raw, and control
/// characters use the same escapes serde_json emits.
fn serialized_len(value: &Value) -> usize {
    match value {
        Value::Null => 4,
        Value::Bool(true) => 4,
        Value::Bool(false) => 5,
        Value::Number(number) => number.to_string().len(),
        Value::String(text) => 2 + escaped_len(text),
        Value::Array(items) => {
            let mut total = 2;
            for (index, item) in items.iter().enumerate() {
                total += if index == 0 { 0 } else { 2 };
                total += serialized_len(item);
            }
            total
        }
        Value::Object(map) => {
            let mut total = 2;
            for (index, (key, item)) in map.iter().enumerate() {
                total += if index == 0 { 0 } else { 2 };
                total += 2 + escaped_len(key) + 2 + serialized_len(item);
            }
            total
        }
    }
}

fn escaped_len(text: &str) -> usize {
    text.chars()
        .map(|character| match character {
            '"' | '\\' => 2,
            '\u{08}' | '\t' | '\n' | '\u{0c}' | '\r' => 2,
            control if (control as u32) < 0x20 => 6,
            other => other.len_utf8(),
        })
        .sum()
}

/// Validate a schema against the closed subset and return the expanded work (node visits).
pub fn validate_schema(schema: &Value, limits: &SchemaLimits) -> Result<usize, CatalogError> {
    bounded_json(schema, limits.max_bytes, limits.max_nodes, limits.max_depth)?;
    let mut walk = Walk {
        root: schema,
        limits,
        references: 0,
        work: 0,
    };
    walk.walk(schema, 0, &BTreeSet::new())?;
    check_meta(schema)?;
    Ok(walk.work)
}

struct Walk<'a> {
    root: &'a Value,
    limits: &'a SchemaLimits,
    references: usize,
    work: usize,
}

impl Walk<'_> {
    fn walk(
        &mut self,
        node: &Value,
        depth: usize,
        ancestors: &BTreeSet<String>,
    ) -> Result<(), CatalogError> {
        self.work += 1;
        if self.work > self.limits.max_nodes || depth > self.limits.max_depth {
            return Err(CatalogError("expanded schema exceeds complexity limits"));
        }
        if node.is_boolean() {
            return Ok(());
        }
        let Value::Object(map) = node else {
            return Err(CatalogError("unsupported schema keyword"));
        };
        if map.keys().any(|key| !SUPPORTED.contains(&key.as_str())) {
            return Err(CatalogError("unsupported schema keyword"));
        }
        if let Some(dialect) = map.get("$schema")
            && dialect.as_str() != Some(DIALECT)
        {
            return Err(CatalogError("unsupported JSON Schema dialect"));
        }
        if let Some(format) = map.get("format") {
            match format.as_str() {
                Some(name) if formats::registered(name) => {}
                _ => return Err(CatalogError("unregistered string format")),
            }
        }
        if let Some(reference) = map.get("$ref") {
            self.references += 1;
            let Some(reference) = reference.as_str() else {
                return Err(CatalogError(
                    "only bounded bundle-local $defs references are supported",
                ));
            };
            if self.references > self.limits.max_references || !reference.starts_with("#/$defs/") {
                return Err(CatalogError(
                    "only bounded bundle-local $defs references are supported",
                ));
            }
            if ancestors.contains(reference) {
                return Err(CatalogError("recursive schema references are unsupported"));
            }
            let mut target = self.root;
            for part in reference[2..].split('/') {
                let key = part.replace("~1", "/").replace("~0", "~");
                target = match target {
                    Value::Object(map) => map
                        .get(&key)
                        .ok_or(CatalogError("unresolved local schema reference"))?,
                    _ => return Err(CatalogError("unresolved local schema reference")),
                };
            }
            let mut next = ancestors.clone();
            next.insert(reference.to_owned());
            self.walk(target, depth + 1, &next)?;
        }
        for (key, value) in map {
            if MAPS.contains(&key.as_str()) {
                let Value::Object(children) = value else {
                    return Err(CatalogError("invalid schema map"));
                };
                for child in children.values() {
                    self.walk(child, depth + 1, ancestors)?;
                }
            } else if SINGLE.contains(&key.as_str()) {
                self.walk(value, depth + 1, ancestors)?;
            } else if ARRAYS.contains(&key.as_str()) {
                let Value::Array(children) = value else {
                    return Err(CatalogError("schema branches must contain 1 to 8 entries"));
                };
                if !(1..=8).contains(&children.len()) {
                    return Err(CatalogError("schema branches must contain 1 to 8 entries"));
                }
                for child in children {
                    self.walk(child, depth + 1, ancestors)?;
                }
            }
        }
        Ok(())
    }
}

const SIMPLE_TYPES: &[&str] = &[
    "array", "boolean", "integer", "null", "number", "object", "string",
];

const META_MESSAGE: CatalogError = CatalogError("invalid Draft 2020-12 schema");

/// The reference's `Draft202012Validator.check_schema` for the supported keyword subset.
///
/// Unknown keywords and non-schema positions were already refused by [`Walk`]; this second pass
/// checks the shapes the 2020-12 meta-schema constrains: `type`, `required`, numeric keywords,
/// non-negative integer keywords, and string annotations.
fn check_meta(node: &Value) -> Result<(), CatalogError> {
    if node.is_boolean() {
        return Ok(());
    }
    let Value::Object(map) = node else {
        return Err(META_MESSAGE);
    };
    if let Some(kind) = map.get("type") {
        check_type(kind)?;
    }
    if let Some(choices) = map.get("enum")
        && !choices.is_array()
    {
        return Err(META_MESSAGE);
    }
    if let Some(required) = map.get("required") {
        check_unique_strings(required)?;
    }
    for keyword in ["minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum"] {
        if let Some(value) = map.get(keyword)
            && !value.is_number()
        {
            return Err(META_MESSAGE);
        }
    }
    for keyword in [
        "minItems",
        "maxItems",
        "minProperties",
        "maxProperties",
        "minLength",
        "maxLength",
    ] {
        if let Some(value) = map.get(keyword)
            && !is_non_negative_integer(value)
        {
            return Err(META_MESSAGE);
        }
    }
    for keyword in ["title", "description"] {
        if let Some(value) = map.get(keyword)
            && !value.is_string()
        {
            return Err(META_MESSAGE);
        }
    }
    for (key, value) in map {
        if MAPS.contains(&key.as_str()) {
            if let Value::Object(children) = value {
                for child in children.values() {
                    check_meta(child)?;
                }
            }
        } else if SINGLE.contains(&key.as_str()) {
            check_meta(value)?;
        } else if ARRAYS.contains(&key.as_str())
            && let Value::Array(children) = value
        {
            for child in children {
                check_meta(child)?;
            }
        }
    }
    Ok(())
}

fn check_type(kind: &Value) -> Result<(), CatalogError> {
    match kind {
        Value::String(name) if SIMPLE_TYPES.contains(&name.as_str()) => Ok(()),
        Value::Array(names) => {
            if names.is_empty() {
                return Err(META_MESSAGE);
            }
            let mut seen = BTreeSet::new();
            for name in names {
                let Value::String(name) = name else {
                    return Err(META_MESSAGE);
                };
                if !SIMPLE_TYPES.contains(&name.as_str()) || !seen.insert(name) {
                    return Err(META_MESSAGE);
                }
            }
            Ok(())
        }
        _ => Err(META_MESSAGE),
    }
}

fn check_unique_strings(values: &Value) -> Result<(), CatalogError> {
    let Value::Array(values) = values else {
        return Err(META_MESSAGE);
    };
    let mut seen = BTreeSet::new();
    for value in values {
        let Value::String(value) = value else {
            return Err(META_MESSAGE);
        };
        if !seen.insert(value) {
            return Err(META_MESSAGE);
        }
    }
    Ok(())
}

/// JSON Schema's `integer`: an integral number, never a boolean (an integral float is accepted,
/// exactly as Python's jsonschema treats `1.0`).
fn is_non_negative_integer(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            if number.as_u64().is_some() {
                true
            } else if let Some(signed) = number.as_i64() {
                signed >= 0
            } else if let Some(float) = number.as_f64() {
                float.is_finite() && float >= 0.0 && float.fract() == 0.0
            } else {
                false
            }
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits() -> SchemaLimits {
        SchemaLimits::default()
    }

    #[test]
    fn accepts_the_supported_subset() {
        let schema = json!({
            "$schema": DIALECT,
            "$defs": {"count": {"type": "integer", "minimum": 0}},
            "type": "object",
            "properties": {"count": {"$ref": "#/$defs/count"}},
            "required": ["count"],
            "additionalProperties": false
        });
        assert!(validate_schema(&schema, &limits()).unwrap() >= 3);
    }

    #[test]
    fn refuses_unsupported_shapes() {
        for schema in [
            json!({"$ref": "https://evil.test/schema"}),
            json!({"$ref": "file:///etc/passwd"}),
            json!({"$ref": "#"}),
            json!({"$schema": "http://json-schema.org/draft-07/schema#"}),
            json!({"$dynamicRef": "#x"}),
            json!({"$id": "https://evil.test"}),
            json!({"pattern": "(a+)+$"}),
            json!({"format": "uri"}),
            json!({"$ref": "#/$defs/missing", "$defs": {}}),
            json!({"$defs": {"cycle": {"$ref": "#/$defs/cycle"}}}),
            json!({"anyOf": [{}, {}, {}, {}, {}, {}, {}, {}, {}]}),
            json!({"properties": []}),
            json!({"items": 5}),
            json!({"type": "made_up"}),
            json!({"required": ["a", "a"]}),
            json!({"minLength": -1}),
            json!({"title": 5}),
        ] {
            assert!(validate_schema(&schema, &limits()).is_err(), "{schema}");
        }
    }

    #[test]
    fn plain_boolean_schema_is_valid() {
        assert!(validate_schema(&json!(true), &limits()).is_ok());
        assert!(validate_schema(&json!(false), &limits()).is_ok());
    }

    #[test]
    fn bounded_json_bounds_every_axis() {
        assert_eq!(bounded_json(&json!({"a": 1}), 100, 100, 10).unwrap(), 2);
        assert_eq!(
            bounded_json(&json!([1, 2, 3]), 100, 2, 10).unwrap_err().0,
            "JSON array exceeds node limit"
        );
        assert_eq!(
            bounded_json(&json!({"a": {"b": 1}}), 100, 100, 1)
                .unwrap_err()
                .0,
            "JSON complexity exceeds configured limits"
        );
        assert_eq!(
            bounded_json(&json!("xxxxxxxxxx"), 9, 100, 10)
                .unwrap_err()
                .0,
            "JSON string exceeds byte limit"
        );
        assert_eq!(
            bounded_json(&json!({"a": "x"}), 5, 100, 10).unwrap_err().0,
            "JSON byte limit exceeded"
        );
    }
}
