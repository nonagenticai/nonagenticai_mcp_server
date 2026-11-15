//! OpenAPI 3.0.x / 3.1.x (JSON) -> draft `OperationManifest` importer.
//!
//! Ported from the reference's `src/builder/openapi.py`. Pure: no network, no database. Local
//! `$ref` only. `components/schemas` become `$defs` of the operation's own schemas (only the
//! reachable ones); every other component is inlined. 3.0 schemas are normalised to the 2020-12
//! subset the catalog validates: `nullable` and boolean `exclusive*` are converted,
//! annotation-only keywords are dropped, and keywords the validator cannot enforce (`pattern`
//! etc.) are dropped as well, so the upstream stays the authority for them. Anything that cannot
//! be represented exactly makes ONE operation non-importable with a short, safe reason; it never
//! fails the whole document.
//!
//! The reference's `denied_by` (`src.toolkit_contract.endpoints`) is not ported elsewhere in
//! this crate yet, so the deny list lives here with the same patterns and classification.

use std::collections::{BTreeSet, HashMap, HashSet, VecDeque};
use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::{Map, Value, json};

use crate::builder::models::SelectionEntry;
use crate::catalog::formats;
use crate::catalog::models::{ExactReference, Method, OperationManifest};
use crate::catalog::validation::{SchemaLimits, validate_schema};

/// The methods the catalog supports, lowercase as the document spells them.
pub const METHODS: &[&str] = &["get", "post", "put", "patch", "delete"];

/// The per-operation override fields the reference accepts.
pub const OVERRIDE_FIELDS: &[&str] = &[
    "op_key",
    "effect",
    "expected_error_statuses",
    "response_projection",
    "timeout_seconds",
];

/// Headers the platform owns; an optional one is dropped, a required one refuses the operation.
const RESERVED_HEADERS: &[&str] = &[
    "authorization",
    "cookie",
    "host",
    "proxy-authorization",
    "x-tenant-id",
    "connection",
    "content-length",
    "content-type",
    "accept",
    "transfer-encoding",
    "idempotency-key",
    "x-idempotency-key",
    "user-agent",
];

/// Validation keywords the catalog subset supports and that are kept.
const KEEP: &[&str] = &[
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

/// Keywords that change what a schema means and cannot be dropped: refuse the operation.
const STRUCTURAL: &[&str] = &[
    "$id",
    "$anchor",
    "$dynamicRef",
    "$dynamicAnchor",
    "$recursiveRef",
    "$defs",
    "definitions",
];

const MAX_DEPTH: usize = 48;
const MAX_DESCRIPTION: usize = 300;
const DEFAULT_TIMEOUT: u32 = 10;
const DEFAULT_PAGINATION: u32 = 10;
const DEFAULT_RESPONSE_BYTES: u32 = 262_144;

static VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A3\.[01]\.\d+(?:-[A-Za-z0-9.]+)?\z").expect("the version pattern is valid")
});
static SCHEMA_REF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A#/components/schemas/([^/]+)\z").expect("the schema ref pattern is valid")
});
static NAME: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-z][a-z0-9_]{0,63}\z").expect("the name pattern is valid"));
static TEMPLATE_TOKEN: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\{([^{}]+)\}").expect("the template token pattern is valid"));
static SUCCESS_CODE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A20[0-4]\z").expect("the success code pattern is valid"));
static JSON_PLUS: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\Aapplication/[a-z0-9.+-]+\+json\z").expect("the JSON media type pattern is valid")
});
static DEF_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r##""#/\$defs/([A-Za-z0-9_]+)""##).expect("the def reference pattern is valid")
});

/// The document or a selected operation cannot be imported. `reason` is safe to show.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{reason}")]
pub struct OpenApiImportError {
    /// The safe-to-show reason.
    pub reason: String,
}

impl OpenApiImportError {
    /// Construct from a reason.
    pub fn new(reason: impl Into<String>) -> Self {
        Self {
            reason: reason.into(),
        }
    }
}

/// One operation is not importable.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Refused(String);

impl Refused {
    fn new(reason: impl Into<String>) -> Self {
        Self(reason.into())
    }
}

/// A selection: an `operationId` or a lowercase `{method, path}` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Selection {
    /// The document's `operationId`.
    OperationId(String),
    /// A method (lowercase) and the document's path.
    MethodPath {
        /// Lowercase HTTP method.
        method: String,
        /// The path exactly as the document spells it.
        path: String,
    },
}

impl Selection {
    /// Select by operationId.
    pub fn operation_id(id: impl Into<String>) -> Self {
        Self::OperationId(id.into())
    }

    /// Select by method and path.
    pub fn method_path(method: impl Into<String>, path: impl Into<String>) -> Self {
        Self::MethodPath {
            method: method.into().to_lowercase(),
            path: path.into(),
        }
    }

    /// The reference's `_selector`: a string is an operationId, a `{method, path}` object is a
    /// method/path selection (the method is lowercased).
    pub fn from_value(value: &Value) -> Result<Self, OpenApiImportError> {
        match value {
            Value::String(id) => Ok(Self::operation_id(id.clone())),
            Value::Object(map) => match (map.get("method"), map.get("path")) {
                (Some(Value::String(method)), Some(Value::String(path))) => {
                    Ok(Self::method_path(method.clone(), path.clone()))
                }
                _ => Err(OpenApiImportError::new(
                    "a selection is an operationId or {method, path}",
                )),
            },
            _ => Err(OpenApiImportError::new(
                "a selection is an operationId or {method, path}",
            )),
        }
    }

    /// The request model's selection as an importer selection.
    pub fn from_entry(entry: &SelectionEntry) -> Self {
        match entry {
            SelectionEntry::OperationId(id) => Self::operation_id(id.clone()),
            SelectionEntry::Operation(selector) => {
                Self::method_path(method_name(selector.method), selector.path.clone())
            }
        }
    }
}

fn method_name(method: Method) -> &'static str {
    match method {
        Method::Get => "get",
        Method::Post => "post",
        Method::Put => "put",
        Method::Patch => "patch",
        Method::Delete => "delete",
    }
}

/// One imported operation with its draft manifest.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedOperation {
    /// The script key.
    pub op_key: String,
    /// The draft operation manifest.
    pub manifest: OperationManifest,
    /// The document's `operationId`, when it had one.
    pub operation_id: Option<String>,
    /// The uppercase HTTP method.
    pub method: String,
    /// The document's path (not the normalised template).
    pub path: String,
    /// The operation's summary (first 200 characters, or empty).
    pub summary: String,
}

/// The document's info metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SpecInfo {
    /// The info title (first 200 characters).
    pub title: Option<String>,
    /// The info version (first 64 characters).
    pub version: Option<String>,
}

/// One row of the import preview.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct OperationListing {
    /// The uppercase HTTP method.
    pub method: String,
    /// The document's path.
    pub path: String,
    /// The `operationId`, when it is a string.
    #[serde(rename = "operationId")]
    pub operation_id: Option<String>,
    /// The summary (first 200 characters), when it is a string.
    pub summary: Option<String>,
    /// Whether the operation can be imported.
    pub importable: bool,
    /// Why it cannot, when it cannot.
    pub reason: Option<String>,
}

/// The reference's `document_version`: an OpenAPI 3.0.x/3.1.x object with a paths map.
pub fn document_version(doc: &Value) -> Result<String, OpenApiImportError> {
    let Value::Object(map) = doc else {
        return Err(OpenApiImportError::new("not an OpenAPI document"));
    };
    let Some(Value::String(version)) = map.get("openapi") else {
        return Err(OpenApiImportError::new("not an OpenAPI document"));
    };
    if !VERSION.is_match(version) {
        return Err(OpenApiImportError::new(
            "only OpenAPI 3.0.x and 3.1.x are supported",
        ));
    }
    if !matches!(map.get("paths"), Some(Value::Object(_))) {
        return Err(OpenApiImportError::new("paths are required"));
    }
    Ok(version.clone())
}

/// The document's info title (200) and version (64), when they are strings.
pub fn spec_info(doc: &Map<String, Value>) -> SpecInfo {
    let Some(Value::Object(info)) = doc.get("info") else {
        return SpecInfo {
            title: None,
            version: None,
        };
    };
    SpecInfo {
        title: info
            .get("title")
            .and_then(Value::as_str)
            .map(|text| truncate(text, 200)),
        version: info
            .get("version")
            .and_then(Value::as_str)
            .map(|text| truncate(text, 64)),
    }
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// The reference's `snake`: split camelCase, collapse runs of non-alphanumerics, lowercase,
/// prefix `p_` when the result does not start with a letter, cap at 64 characters.
///
/// The reference's lookbehind `(?<=[a-z0-9])([A-Z])` is spelled out as a scan because the Rust
/// regex crate has no lookaround.
pub fn snake(name: &str) -> String {
    let mut split = String::with_capacity(name.len() + 8);
    let mut previous_is_lower_or_digit = false;
    for character in name.chars() {
        if character.is_ascii_uppercase() && previous_is_lower_or_digit {
            split.push('_');
        }
        split.push(character);
        previous_is_lower_or_digit = character.is_ascii_lowercase() || character.is_ascii_digit();
    }
    let mut collapsed = String::with_capacity(split.len());
    let mut in_run = false;
    for character in split.chars() {
        if character.is_ascii_alphanumeric() {
            collapsed.push(character);
            in_run = false;
        } else if !in_run {
            collapsed.push('_');
            in_run = true;
        }
    }
    let lowered = collapsed.trim_matches('_').to_lowercase();
    let text = if lowered
        .chars()
        .next()
        .map(char::is_alphabetic)
        .unwrap_or(false)
    {
        lowered
    } else {
        format!("p_{lowered}")
    };
    let trimmed = text
        .chars()
        .take(64)
        .collect::<String>()
        .trim_end_matches('_')
        .to_owned();
    if trimmed.is_empty() {
        "p".to_owned()
    } else {
        trimmed
    }
}

fn unescape(part: &str) -> String {
    part.replace("~1", "/").replace("~0", "~")
}

fn sanitize_def_name(name: &str) -> String {
    let replaced: String = name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .collect();
    if replaced.is_empty() {
        "schema".to_owned()
    } else {
        replaced
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Direction {
    Input,
    Output,
}

/// Schema conversion for ONE direction of ONE operation, collecting its `$defs`.
struct Converter<'a> {
    doc: &'a Value,
    direction: Direction,
    defs: Map<String, Value>,
    names: HashMap<String, String>,
    inline: Vec<String>,
}

impl<'a> Converter<'a> {
    fn new(doc: &'a Value, direction: Direction) -> Self {
        Self {
            doc,
            direction,
            defs: Map::new(),
            names: HashMap::new(),
            inline: Vec::new(),
        }
    }

    fn pointer(&self, reference: &str) -> Result<&'a Value, Refused> {
        if !reference.starts_with("#/") {
            return Err(Refused::new("external $ref is not supported"));
        }
        let mut target = self.doc;
        for part in reference[2..].split('/') {
            let key = unescape(part);
            target = match target {
                Value::Object(map) => map
                    .get(&key)
                    .ok_or_else(|| Refused::new("unresolved $ref"))?,
                _ => return Err(Refused::new("unresolved $ref")),
            };
        }
        Ok(target)
    }

    fn reference(&mut self, value: &Value) -> Result<Value, Refused> {
        let Some(reference) = value.as_str() else {
            return Err(Refused::new("invalid $ref"));
        };
        let Some(captures) = SCHEMA_REF.captures(reference) else {
            if self.inline.iter().any(|seen| seen == reference) || self.inline.len() > 16 {
                return Err(Refused::new("recursive $ref outside components/schemas"));
            }
            let target = self.pointer(reference)?;
            self.inline.push(reference.to_owned());
            let converted = self.schema(target, 0);
            self.inline.pop();
            return converted;
        };
        let Some(matched) = captures.get(1) else {
            return Err(Refused::new("invalid $ref"));
        };
        let name = unescape(matched.as_str());
        let candidate = match self.names.get(&name).cloned() {
            Some(candidate) => candidate,
            None => {
                let base = sanitize_def_name(&name);
                let mut candidate = base.clone();
                let mut suffix = 1usize;
                while self.defs.contains_key(&candidate) {
                    suffix += 1;
                    candidate = format!("{base}_{suffix}");
                }
                self.names.insert(name.clone(), candidate.clone());
                self.defs
                    .insert(candidate.clone(), Value::Object(Map::new()));
                let target = self.pointer(reference)?;
                let converted = self.schema(target, 0)?;
                self.defs.insert(candidate.clone(), converted);
                candidate
            }
        };
        Ok(json!({"$ref": format!("#/$defs/{candidate}")}))
    }

    fn schema(&mut self, node: &Value, depth: usize) -> Result<Value, Refused> {
        if depth > MAX_DEPTH {
            return Err(Refused::new("schema nesting is too deep"));
        }
        match node {
            Value::Bool(_) => return Ok(node.clone()),
            Value::Object(map) => {
                if let Some(bad) = map
                    .keys()
                    .filter(|key| STRUCTURAL.contains(&key.as_str()))
                    .min()
                {
                    return Err(Refused::new(format!("unsupported schema keyword {bad}")));
                }
                let mut out = Map::new();
                if let Some(reference) = map.get("$ref") {
                    let mut converted = self.reference(reference)?;
                    // 3.1 allows siblings; an annotation-only wrapper is enough to keep.
                    let plain_reference = match &converted {
                        Value::Object(inner) => inner.len() == 1 && inner.contains_key("$ref"),
                        _ => false,
                    };
                    if plain_reference {
                        for key in ["title", "description"] {
                            if let Some(value) = map.get(key) {
                                let annotated = Self::annotation(value, key)?;
                                if let Value::Object(inner) = &mut converted {
                                    inner.insert(key.to_owned(), Value::String(annotated));
                                }
                            }
                        }
                    }
                    if map.get("nullable") == Some(&Value::Bool(true)) {
                        converted = json!({"anyOf": [converted, {"type": "null"}]});
                    }
                    return Ok(converted);
                }
                for (key, value) in map {
                    match key.as_str() {
                        "title" | "description" => {
                            let annotated = Self::annotation(value, key)?;
                            out.insert(key.clone(), Value::String(annotated));
                        }
                        "properties" => {
                            out.insert(key.clone(), Value::Object(self.properties(value, depth)?));
                        }
                        "additionalProperties" | "items" | "not" => {
                            out.insert(key.clone(), self.schema(value, depth + 1)?);
                        }
                        "prefixItems" | "allOf" | "anyOf" | "oneOf" => {
                            let Value::Array(items) = value else {
                                return Err(Refused::new("invalid schema"));
                            };
                            let mut converted = Vec::with_capacity(items.len());
                            for item in items {
                                converted.push(self.schema(item, depth + 1)?);
                            }
                            out.insert(key.clone(), Value::Array(converted));
                        }
                        "format" => {
                            if let Some(name) = value.as_str()
                                && formats::registered(name)
                            {
                                out.insert(key.clone(), value.clone());
                            }
                        }
                        "exclusiveMinimum" | "exclusiveMaximum" => {
                            let bound = if key == "exclusiveMinimum" {
                                "minimum"
                            } else {
                                "maximum"
                            };
                            match value {
                                Value::Bool(flag) => {
                                    // 3.0: a boolean modifier of minimum/maximum.
                                    if *flag && matches!(map.get(bound), Some(Value::Number(_))) {
                                        if let Some(bound_value) = map.get(bound) {
                                            out.insert(key.clone(), bound_value.clone());
                                        }
                                        out.shift_remove(bound);
                                    }
                                }
                                other => {
                                    out.insert(key.clone(), other.clone());
                                }
                            }
                        }
                        "minimum" | "maximum" => {
                            let exclusive = if key == "minimum" {
                                "exclusiveMinimum"
                            } else {
                                "exclusiveMaximum"
                            };
                            if map.get(exclusive) != Some(&Value::Bool(true)) {
                                out.insert(key.clone(), value.clone());
                            }
                        }
                        other => {
                            if KEEP.contains(&other) {
                                out.insert(key.clone(), value.clone());
                            }
                        }
                    }
                }
                if out.contains_key("properties")
                    && let Some(Value::Array(required)) = out.get("required").cloned()
                {
                    let kept = out.get("properties").and_then(Value::as_object);
                    let source = map.get("properties").and_then(Value::as_object);
                    let filtered: Vec<Value> = required
                        .iter()
                        .filter(|entry| match entry.as_str() {
                            Some(name) => {
                                kept.is_some_and(|kept| kept.contains_key(name))
                                    || source.is_none_or(|source| !source.contains_key(name))
                            }
                            // Unhashable values raise in the reference; keeping them here
                            // is the only non-panicking reading of the same filter.
                            None => true,
                        })
                        .cloned()
                        .collect();
                    out.insert("required".to_owned(), Value::Array(filtered));
                }
                if map.get("nullable") == Some(&Value::Bool(true)) {
                    match out.get("type").cloned() {
                        Some(Value::String(kind)) => {
                            out.insert(
                                "type".to_owned(),
                                Value::Array(vec![
                                    Value::String(kind),
                                    Value::String("null".to_owned()),
                                ]),
                            );
                        }
                        Some(Value::Array(mut kinds)) => {
                            if !kinds.iter().any(|kind| kind.as_str() == Some("null")) {
                                kinds.push(Value::String("null".to_owned()));
                            }
                            out.insert("type".to_owned(), Value::Array(kinds));
                        }
                        _ => {
                            let mut wrapper = Map::new();
                            wrapper.insert(
                                "anyOf".to_owned(),
                                Value::Array(vec![
                                    Value::Object(std::mem::take(&mut out)),
                                    json!({"type": "null"}),
                                ]),
                            );
                            out = wrapper;
                        }
                    }
                    if !out.contains_key("anyOf")
                        && let Some(mut choices) = out.get("enum").and_then(python_sequence)
                        && !choices.iter().any(Value::is_null)
                    {
                        choices.push(Value::Null);
                        out.insert("enum".to_owned(), Value::Array(choices));
                    }
                }
                Ok(Value::Object(out))
            }
            _ => Err(Refused::new("invalid schema")),
        }
    }

    fn annotation(value: &Value, key: &str) -> Result<String, Refused> {
        let Some(text) = value.as_str() else {
            return Err(Refused::new("invalid schema"));
        };
        let limit = if key == "title" { 120 } else { MAX_DESCRIPTION };
        Ok(truncate(text, limit))
    }

    fn properties(&mut self, value: &Value, depth: usize) -> Result<Map<String, Value>, Refused> {
        let Value::Object(map) = value else {
            return Err(Refused::new("invalid schema"));
        };
        let mut result = Map::new();
        for (name, child) in map {
            if let Value::Object(child_map) = child {
                let skip = match self.direction {
                    Direction::Input => child_map.get("readOnly") == Some(&Value::Bool(true)),
                    Direction::Output => child_map.get("writeOnly") == Some(&Value::Bool(true)),
                };
                if skip {
                    continue;
                }
            }
            result.insert(name.clone(), self.schema(child, depth + 1)?);
        }
        Ok(result)
    }

    /// Reachable defs only, and no cycles (the catalog validator forbids recursive refs).
    fn finish(&self, root: &Value) -> Result<Value, Refused> {
        let mut result = match root {
            Value::Object(map) => map.clone(),
            _ => Map::new(),
        };
        let graph: Vec<(String, Vec<String>)> = self
            .defs
            .iter()
            .map(|(name, body)| {
                let serialized = match serde_json::to_string(body) {
                    Ok(text) => text,
                    Err(_) => String::new(),
                };
                (name.clone(), def_references(&serialized))
            })
            .collect();
        // The reference's recursive DFS is spelled as Kahn's algorithm so a pathological
        // document cannot overflow the stack.
        let present: HashSet<&str> = graph.iter().map(|(name, _)| name.as_str()).collect();
        let mut indegree: HashMap<&str, usize> = graph
            .iter()
            .map(|(name, _)| (name.as_str(), 0usize))
            .collect();
        let mut edges: HashMap<&str, Vec<&str>> = HashMap::new();
        for (name, references) in &graph {
            let mut unique: Vec<&str> = Vec::new();
            for reference in references {
                let child = reference.as_str();
                if present.contains(child) && !unique.contains(&child) {
                    unique.push(child);
                }
            }
            for child in &unique {
                if let Some(count) = indegree.get_mut(*child) {
                    *count += 1;
                }
            }
            edges.insert(name.as_str(), unique);
        }
        let mut queue: VecDeque<&str> = indegree
            .iter()
            .filter(|(_, count)| **count == 0)
            .map(|(name, _)| *name)
            .collect();
        let mut processed = 0usize;
        while let Some(node) = queue.pop_front() {
            processed += 1;
            if let Some(children) = edges.get(node) {
                for child in children {
                    if let Some(count) = indegree.get_mut(*child) {
                        *count -= 1;
                        if *count == 0 {
                            queue.push_back(*child);
                        }
                    }
                }
            }
        }
        if processed < indegree.len() {
            return Err(Refused::new("recursive schemas are not supported"));
        }
        if !self.defs.is_empty() {
            result.insert("$defs".to_owned(), Value::Object(self.defs.clone()));
        }
        Ok(Value::Object(result))
    }
}

fn def_references(serialized: &str) -> Vec<String> {
    DEF_REFERENCE
        .captures_iter(serialized)
        .filter_map(|captures| captures.get(1).map(|matched| matched.as_str().to_owned()))
        .collect()
}

fn deref<'a>(doc: &'a Value, node: &'a Value) -> Result<&'a Value, Refused> {
    let mut current = node;
    let mut seen = 0usize;
    while let Value::Object(map) = current {
        let Some(reference_value) = map.get("$ref") else {
            break;
        };
        seen += 1;
        let Some(reference) = reference_value.as_str() else {
            return Err(Refused::new("unsupported $ref"));
        };
        if seen > 16 || !reference.starts_with("#/") {
            return Err(Refused::new("unsupported $ref"));
        }
        let mut target = doc;
        for part in reference[2..].split('/') {
            let key = unescape(part);
            target = match target {
                Value::Object(map) => map
                    .get(&key)
                    .ok_or_else(|| Refused::new("unresolved $ref"))?,
                _ => return Err(Refused::new("unresolved $ref")),
            };
        }
        current = target;
    }
    Ok(current)
}

fn deref_safe<'a>(doc: &'a Value, node: &'a Value) -> Option<&'a Value> {
    deref(doc, node).ok()
}

fn scalar_schema(doc: &Value, schema: &Value) -> Result<bool, Refused> {
    let node = deref(doc, schema)?;
    let Value::Object(map) = node else {
        return Ok(true);
    };
    let kinds: Vec<&str> = match map.get("type") {
        Some(Value::String(kind)) => vec![kind.as_str()],
        Some(Value::Array(items)) => items.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    Ok(!kinds.iter().any(|kind| matches!(*kind, "array" | "object")))
}

/// The schema of the preferred JSON media type, `None` when there is none.
fn json_content(content: Option<&Value>) -> Option<Value> {
    let Some(Value::Object(media)) = content else {
        return None;
    };
    for (name, body) in media {
        let base = name.split(';').next().unwrap_or_default();
        let base = base.trim().to_lowercase();
        if base == "application/json" || JSON_PLUS.is_match(&base) {
            let schema = match body {
                Value::Object(map) => map
                    .get("schema")
                    .cloned()
                    .unwrap_or_else(|| Value::Object(Map::new())),
                _ => Value::Object(Map::new()),
            };
            // The reference uses JSON `false` as its "no JSON media type" sentinel, so a literal
            // boolean-false schema is refused exactly like a missing one (`schema is False`).
            if matches!(schema, Value::Bool(false)) {
                return None;
            }
            return Some(schema);
        }
    }
    None
}

#[derive(Debug, Clone)]
struct Built {
    method: String,
    path_template: String,
    query_fields: Vec<String>,
    header_fields: Vec<String>,
    mappings: Vec<Value>,
    input_schema: Value,
    output_schema: Value,
    empty_response: bool,
    effect: &'static str,
}

fn build(
    doc: &Value,
    path: &str,
    method: &str,
    item: &Map<String, Value>,
    operation: &Map<String, Value>,
) -> Result<Built, Refused> {
    if let Some(classification) = denied_by(path) {
        return Err(Refused::new(format!(
            "blocked by the LLM endpoint deny list ({})",
            classification.as_str()
        )));
    }
    let mut params: Vec<((String, String), &Value)> = Vec::new();
    for source in [item.get("parameters"), operation.get("parameters")] {
        let Some(value) = source else {
            continue;
        };
        if !python_truthy(value) {
            continue;
        }
        let Value::Array(entries) = value else {
            return Err(Refused::new("invalid parameter"));
        };
        for raw in entries {
            let param = deref(doc, raw)?;
            let Value::Object(param_map) = param else {
                return Err(Refused::new("invalid parameter"));
            };
            let Some(name) = param_map.get("name").and_then(Value::as_str) else {
                return Err(Refused::new("invalid parameter"));
            };
            let location = match param_map.get("in") {
                Some(value) => python_str(value),
                None => "None".to_owned(),
            };
            let key = (name.to_owned(), location);
            match params.iter_mut().find(|(existing, _)| *existing == key) {
                Some(existing) => existing.1 = param,
                None => params.push((key, param)),
            }
        }
    }
    let mut tokens: BTreeSet<String> = BTreeSet::new();
    for captures in TEMPLATE_TOKEN.captures_iter(path) {
        if let Some(name) = captures.get(1) {
            tokens.insert(name.as_str().to_owned());
        }
    }
    let declared: BTreeSet<String> = params
        .iter()
        .filter(|((_, location), _)| location == "path")
        .map(|((name, _), _)| name.clone())
        .collect();
    if tokens != declared {
        return Err(Refused::new(
            "path parameters do not match the path template",
        ));
    }
    params.sort_by_key(|((_, location), _)| match location.as_str() {
        "path" => 0,
        "query" => 1,
        "header" => 2,
        _ => 9,
    });
    let mut inputs = Converter::new(doc, Direction::Input);
    let mut properties = Map::new();
    let mut required: Vec<Value> = Vec::new();
    let mut mappings: Vec<Value> = Vec::new();
    let mut query_fields: Vec<String> = Vec::new();
    let mut header_fields: Vec<String> = Vec::new();
    let mut template = path.to_owned();
    for ((name, location), param) in params {
        let Value::Object(param_map) = param else {
            return Err(Refused::new("invalid parameter"));
        };
        if location == "cookie" {
            return Err(Refused::new("cookie parameters are not supported"));
        }
        if location != "path" && location != "query" && location != "header" {
            return Err(Refused::new("unsupported parameter location"));
        }
        if param_map.contains_key("content") || !param_map.contains_key("schema") {
            return Err(Refused::new(
                "parameter without a plain schema is not supported",
            ));
        }
        let Some(schema_value) = param_map.get("schema") else {
            return Err(Refused::new(
                "parameter without a plain schema is not supported",
            ));
        };
        if !scalar_schema(doc, schema_value)? {
            return Err(Refused::new(format!(
                "{location} parameter {} must be a scalar",
                python_repr(&name)
            )));
        }
        let is_required =
            location == "path" || param_map.get("required") == Some(&Value::Bool(true));
        let mut prop;
        let target;
        match location.as_str() {
            "path" => {
                prop = snake(&name);
                if !NAME.is_match(&prop) {
                    return Err(Refused::new("unrepresentable path parameter name"));
                }
                template = template.replace(&format!("{{{name}}}"), &format!("{{{prop}}}"));
                target = prop.clone();
            }
            "query" => {
                if !NAME.is_match(&name) {
                    return Err(Refused::new(format!(
                        "query parameter {} needs a lowercase snake_case name",
                        python_repr(&name)
                    )));
                }
                prop = name.clone();
                target = name.clone();
                query_fields.push(name.clone());
            }
            _ => {
                let wire = name.to_lowercase();
                if RESERVED_HEADERS.contains(&wire.as_str())
                    || wire.starts_with("x-forwarded-")
                    || wire.starts_with("proxy-")
                {
                    if is_required {
                        return Err(Refused::new(format!(
                            "reserved header {} is required",
                            python_repr(&wire)
                        )));
                    }
                    // The platform sets reserved headers; an optional one is dropped.
                    continue;
                }
                if name.contains('_') {
                    return Err(Refused::new(
                        "header names with underscores are not supported",
                    ));
                }
                target = wire.replace('-', "_");
                if !NAME.is_match(&target) {
                    return Err(Refused::new(format!(
                        "unrepresentable header name {}",
                        python_repr(&name)
                    )));
                }
                prop = target.clone();
                header_fields.push(target.clone());
            }
        }
        if properties.contains_key(&prop) {
            let adjusted = format!("{prop}_{location}");
            if properties.contains_key(&adjusted) {
                return Err(Refused::new("duplicate parameter name"));
            }
            prop = adjusted;
        }
        let converted = inputs.schema(schema_value, 0)?;
        properties.insert(prop.clone(), converted);
        let description = match param_map.get("description") {
            Some(Value::String(text)) => Some(Value::String(truncate(text, MAX_DESCRIPTION))),
            // Python's slice also accepts a list here; a non-sliceable value raises in the
            // reference, so only the two representable shapes are kept.
            Some(Value::Array(items)) => Some(Value::Array(
                items.iter().take(MAX_DESCRIPTION).cloned().collect(),
            )),
            _ => None,
        };
        if let Some(description) = description
            && let Some(Value::Object(property)) = properties.get_mut(&prop)
        {
            property
                .entry("description".to_owned())
                .or_insert(description);
        }
        if is_required {
            required.push(Value::String(prop.clone()));
        }
        mappings.push(json!({
            "location": location,
            "target": target,
            "value": {"source": "input", "pointer": format!("/{prop}")},
            "optional": !is_required,
        }));
    }
    if let Some(body_value) = operation.get("requestBody") {
        let body = deref(doc, body_value)?;
        let Value::Object(body_map) = body else {
            return Err(Refused::new("only JSON request bodies are supported"));
        };
        let Some(schema) = json_content(body_map.get("content")) else {
            return Err(Refused::new("only JSON request bodies are supported"));
        };
        let prop = if properties.contains_key("body") {
            "request_body".to_owned()
        } else {
            "body".to_owned()
        };
        if properties.contains_key(&prop) {
            return Err(Refused::new("request body name collision"));
        }
        let converted = inputs.schema(&schema, 0)?;
        properties.insert(prop.clone(), converted);
        let body_required = body_map.get("required") == Some(&Value::Bool(true));
        if body_required {
            required.push(Value::String(prop.clone()));
        }
        mappings.push(json!({
            "location": "body",
            "target": "",
            "value": {"source": "input", "pointer": format!("/{prop}")},
            "optional": !body_required,
        }));
    }
    let mut input_root = Map::new();
    input_root.insert("type".to_owned(), Value::String("object".to_owned()));
    input_root.insert("properties".to_owned(), Value::Object(properties));
    input_root.insert("required".to_owned(), Value::Array(required));
    input_root.insert("additionalProperties".to_owned(), Value::Bool(false));
    let input_schema = inputs.finish(&Value::Object(input_root))?;
    // Lowest 2xx in 200-204; JSON gives the schema, 204/no content gives an empty response.
    let Some(Value::Object(responses)) = operation.get("responses") else {
        return Err(Refused::new("no responses declared"));
    };
    let mut codes: Vec<&String> = responses
        .keys()
        .filter(|code| SUCCESS_CODE.is_match(code))
        .collect();
    codes.sort();
    let Some(code) = codes.first() else {
        return Err(Refused::new("no 200-204 response"));
    };
    let code = code.as_str();
    let Some(response_value) = responses.get(code) else {
        return Err(Refused::new("no 200-204 response"));
    };
    let response = deref(doc, response_value)?;
    let content = match response {
        Value::Object(map) => map.get("content"),
        _ => None,
    };
    let empty_content = match content {
        None => true,
        Some(value) => !python_truthy(value),
    };
    let (output_schema, empty_response) = if code == "204" || empty_content {
        (json!({"type": "object"}), true)
    } else {
        let Some(schema) = json_content(content) else {
            return Err(Refused::new("the success response is not JSON"));
        };
        let mut outputs = Converter::new(doc, Direction::Output);
        let converted = outputs.schema(&schema, 0)?;
        (outputs.finish(&converted)?, false)
    };
    Ok(Built {
        method: method.to_uppercase(),
        path_template: template,
        query_fields,
        header_fields,
        mappings,
        input_schema,
        output_schema,
        empty_response,
        effect: if method == "get" {
            "read_only"
        } else {
            "writes"
        },
    })
}

/// The document's candidate operations: `(method, path, item, operation or refusal)`.
struct Candidate<'a> {
    method: &'static str,
    path: String,
    item: &'a Map<String, Value>,
    operation: Option<&'a Map<String, Value>>,
    refusal: Option<String>,
}

fn candidates(doc: &Value) -> Vec<Candidate<'_>> {
    const DOCUMENT_METHODS: [&str; 8] = [
        "get", "put", "post", "delete", "options", "head", "patch", "trace",
    ];
    let mut out = Vec::new();
    let Some(Value::Object(paths)) = doc.get("paths") else {
        return out;
    };
    let mut names: Vec<&String> = paths.keys().collect();
    names.sort();
    for name in names {
        let Some(item_value) = paths.get(name) else {
            continue;
        };
        let Value::Object(item_map) = item_value else {
            continue;
        };
        let resolved = if item_map.contains_key("$ref") {
            let Some(value) = deref_safe(doc, item_value) else {
                continue;
            };
            value
        } else {
            item_value
        };
        let Value::Object(item) = resolved else {
            continue;
        };
        for method in DOCUMENT_METHODS {
            let Some(operation_value) = item.get(method) else {
                continue;
            };
            // The reference's `dict.get` returns None for an explicit JSON null too.
            if operation_value.is_null() {
                continue;
            }
            match operation_value {
                Value::Object(operation) if METHODS.contains(&method) => {
                    out.push(Candidate {
                        method,
                        path: name.clone(),
                        item,
                        operation: Some(operation),
                        refusal: None,
                    });
                }
                Value::Object(operation) => out.push(Candidate {
                    method,
                    path: name.clone(),
                    item,
                    operation: Some(operation),
                    refusal: Some(format!("{} is not supported", method.to_uppercase())),
                }),
                _ => out.push(Candidate {
                    method,
                    path: name.clone(),
                    item,
                    operation: None,
                    refusal: Some("invalid operation".to_owned()),
                }),
            }
        }
    }
    out
}

/// Every operation of a spec, for the preview: whether it can be imported, and if not why.
pub fn list_operations(
    doc: &Value,
    settings: Option<&SchemaLimits>,
) -> Result<Vec<OperationListing>, OpenApiImportError> {
    document_version(doc)?;
    let mut result = Vec::new();
    for candidate in candidates(doc) {
        let mut reason = candidate.refusal.clone();
        if reason.is_none()
            && let Some(operation) = candidate.operation
            && let Err(error) = make(
                doc,
                candidate.method,
                &candidate.path,
                candidate.item,
                operation,
                None,
                settings,
                &Overrides::default(),
            )
        {
            reason = Some(error.0);
        }
        let (operation_id, summary) = match candidate.operation {
            Some(operation) if !operation.is_empty() => (
                operation
                    .get("operationId")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                operation
                    .get("summary")
                    .and_then(Value::as_str)
                    .map(|text| truncate(text, 200)),
            ),
            _ => (None, None),
        };
        result.push(OperationListing {
            method: candidate.method.to_uppercase(),
            path: candidate.path,
            operation_id,
            summary,
            importable: reason.is_none(),
            reason,
        });
    }
    Ok(result)
}

#[derive(Debug, Clone, Default)]
struct Overrides {
    op_key: Option<String>,
    invalid_op_key: bool,
    effect: Option<&'static str>,
    expected_error_statuses: Option<Value>,
    response_projection: Option<Value>,
    timeout_seconds: Option<Value>,
}

impl Overrides {
    fn parse(overrides: &Map<String, Value>) -> Self {
        let mut invalid_op_key = false;
        let op_key = match overrides.get("op_key") {
            Some(value) if python_truthy(value) => match value.as_str() {
                Some(text) => Some(text.to_owned()),
                None => {
                    invalid_op_key = true;
                    None
                }
            },
            _ => None,
        };
        let effect = match overrides.get("effect").and_then(Value::as_str) {
            Some("read_only") => Some("read_only"),
            Some("writes") => Some("writes"),
            _ => None,
        };
        Self {
            op_key,
            invalid_op_key,
            effect,
            expected_error_statuses: overrides.get("expected_error_statuses").cloned(),
            response_projection: overrides.get("response_projection").cloned(),
            timeout_seconds: overrides.get("timeout_seconds").cloned(),
        }
    }
}

fn overrides_for(
    overrides: Option<&Map<String, Value>>,
    selected: usize,
    label: &str,
    operation_id: Option<&str>,
) -> Result<Overrides, OpenApiImportError> {
    let Some(overrides) = overrides else {
        return Ok(Overrides::default());
    };
    if overrides.is_empty() {
        return Ok(Overrides::default());
    }
    if overrides
        .keys()
        .all(|key| OVERRIDE_FIELDS.contains(&key.as_str()))
    {
        if overrides.contains_key("op_key") && selected != 1 {
            return Err(OpenApiImportError::new(
                "op_key can only be overridden when one operation is selected",
            ));
        }
        return Ok(Overrides::parse(overrides));
    }
    // Per-operation form: {"<operationId>" | "METHOD /path": {...}}
    let by_id = operation_id.and_then(|id| overrides.get(id));
    let found = if by_id.is_some_and(|value| !value.is_null()) {
        by_id
    } else {
        overrides.get(label)
    };
    let Some(found) = found.filter(|value| !value.is_null()) else {
        return Ok(Overrides::default());
    };
    let Value::Object(found) = found else {
        return Err(OpenApiImportError::new("unknown override field"));
    };
    if found
        .keys()
        .any(|key| !OVERRIDE_FIELDS.contains(&key.as_str()))
    {
        return Err(OpenApiImportError::new("unknown override field"));
    }
    Ok(Overrides::parse(found))
}

/// Python's `value or default`: the reference builds these as `list(x or default)`.
fn list_value(value: Option<&Value>, default: Value) -> Value {
    match value {
        None => default,
        Some(value) if !python_truthy(value) => default,
        Some(value) => match python_sequence(value) {
            Some(items) => Value::Array(items),
            // A truthy number/boolean raises in the reference; the manifest validation refuses it.
            None => value.clone(),
        },
    }
}

/// Python's iteration over a JSON value: list items, object keys, string characters.
fn python_sequence(value: &Value) -> Option<Vec<Value>> {
    match value {
        Value::Array(items) => Some(items.clone()),
        Value::Object(map) => Some(map.keys().map(|key| Value::String(key.clone())).collect()),
        Value::String(text) => Some(
            text.chars()
                .map(|character| Value::String(character.to_string()))
                .collect(),
        ),
        _ => None,
    }
}

#[allow(clippy::too_many_arguments)]
fn make(
    doc: &Value,
    method: &str,
    path: &str,
    item: &Map<String, Value>,
    operation: &Map<String, Value>,
    service: Option<&ExactReference>,
    settings: Option<&SchemaLimits>,
    overrides: &Overrides,
) -> Result<(Built, Option<OperationManifest>), Refused> {
    let mut built = build(doc, path, method, item, operation)?;
    if let Some(effect) = overrides.effect {
        built.effect = effect;
    }
    if let Some(limits) = settings {
        validate_schema(&built.input_schema, limits)
            .map_err(|error| Refused::new(format!("schema not supported: {error}")))?;
        validate_schema(&built.output_schema, limits)
            .map_err(|error| Refused::new(format!("schema not supported: {error}")))?;
    }
    let Some(service) = service else {
        return Ok((built, None));
    };
    let mut payload = Map::new();
    payload.insert(
        "operation_id".to_owned(),
        Value::String(uuid::Uuid::now_v7().to_string()),
    );
    payload.insert("version".to_owned(), json!(1));
    match serde_json::to_value(service) {
        Ok(value) => {
            payload.insert("service".to_owned(), value);
        }
        Err(_) => return Err(Refused::new("invalid operation: service reference")),
    }
    payload.insert("method".to_owned(), Value::String(built.method.clone()));
    payload.insert(
        "path_template".to_owned(),
        Value::String(built.path_template.clone()),
    );
    payload.insert(
        "query_fields".to_owned(),
        Value::Array(
            built
                .query_fields
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    payload.insert(
        "header_fields".to_owned(),
        Value::Array(
            built
                .header_fields
                .iter()
                .cloned()
                .map(Value::String)
                .collect(),
        ),
    );
    payload.insert("mappings".to_owned(), Value::Array(built.mappings.clone()));
    payload.insert("input_schema".to_owned(), built.input_schema.clone());
    payload.insert("output_schema".to_owned(), built.output_schema.clone());
    payload.insert(
        "response_projection".to_owned(),
        list_value(overrides.response_projection.as_ref(), json!([""])),
    );
    payload.insert("effect".to_owned(), Value::String(built.effect.to_owned()));
    payload.insert(
        "timeout_seconds".to_owned(),
        overrides
            .timeout_seconds
            .clone()
            .unwrap_or_else(|| json!(DEFAULT_TIMEOUT)),
    );
    payload.insert(
        "expected_error_statuses".to_owned(),
        list_value(overrides.expected_error_statuses.as_ref(), json!([])),
    );
    payload.insert(
        "empty_response".to_owned(),
        Value::Bool(built.empty_response),
    );
    payload.insert("pagination_limit".to_owned(), json!(DEFAULT_PAGINATION));
    payload.insert(
        "max_response_bytes".to_owned(),
        json!(DEFAULT_RESPONSE_BYTES),
    );
    match serde_json::from_value::<OperationManifest>(Value::Object(payload)) {
        Ok(manifest) => Ok((built, Some(manifest))),
        Err(error) => Err(Refused::new(format!("invalid operation: {error}"))),
    }
}

/// Draft `OperationManifest` per selected operation (`operationId` or `{method, path}`).
///
/// `overrides` is one dict of `{op_key, effect, expected_error_statuses, response_projection,
/// timeout_seconds}` for every selected operation (`op_key` needs exactly one selection), or a
/// mapping from `operationId` / `"METHOD /path"` to such a dict.
pub fn import_openapi(
    doc: &Value,
    service_ref: &ExactReference,
    selection: &[Selection],
    settings: Option<&SchemaLimits>,
    overrides: Option<&Map<String, Value>>,
) -> Result<Vec<ImportedOperation>, OpenApiImportError> {
    document_version(doc)?;
    if selection.is_empty() {
        return Err(OpenApiImportError::new("select at least one operation"));
    }
    let candidates = candidates(doc);
    let mut index: HashMap<(String, String), usize> = HashMap::new();
    for (position, candidate) in candidates.iter().enumerate() {
        index
            .entry((candidate.method.to_owned(), candidate.path.clone()))
            .or_insert(position);
    }
    let mut by_id: HashMap<String, (String, String)> = HashMap::new();
    for candidate in &candidates {
        if let Some(operation) = candidate.operation {
            if operation.is_empty() {
                continue;
            }
            if let Some(operation_id) = operation.get("operationId").and_then(Value::as_str) {
                by_id
                    .entry(operation_id.to_owned())
                    .or_insert((candidate.method.to_owned(), candidate.path.clone()));
            }
        }
    }
    let mut chosen: Vec<usize> = Vec::new();
    for item in selection {
        let key = match item {
            Selection::OperationId(operation_id) => by_id.get(operation_id).cloned(),
            Selection::MethodPath { method, path } => Some((method.clone(), path.clone())),
        };
        let Some(key) = key else {
            return Err(OpenApiImportError::new("operation not found in the spec"));
        };
        let Some(position) = index.get(&key).copied() else {
            return Err(OpenApiImportError::new("operation not found in the spec"));
        };
        if !chosen.contains(&position) {
            chosen.push(position);
        }
    }
    let mut result = Vec::new();
    let mut used: Vec<String> = Vec::new();
    let selected = chosen.len();
    for position in chosen {
        let Some(candidate) = candidates.get(position) else {
            return Err(OpenApiImportError::new("operation not found in the spec"));
        };
        let label = format!("{} {}", candidate.method.to_uppercase(), candidate.path);
        if let Some(refusal) = &candidate.refusal {
            return Err(OpenApiImportError::new(format!(
                "{label} cannot be imported: {refusal}"
            )));
        }
        let Some(operation) = candidate.operation else {
            return Err(OpenApiImportError::new(format!(
                "{label} cannot be imported: None"
            )));
        };
        let operation_id = operation
            .get("operationId")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let override_values = overrides_for(
            overrides,
            selected,
            &label,
            operation_id.as_deref().filter(|id| !id.is_empty()),
        )?;
        let (built, manifest) = make(
            doc,
            candidate.method,
            &candidate.path,
            candidate.item,
            operation,
            Some(service_ref),
            settings,
            &override_values,
        )
        .map_err(|error| {
            OpenApiImportError::new(format!("{label} cannot be imported: {}", error.0))
        })?;
        let Some(manifest) = manifest else {
            return Err(OpenApiImportError::new(format!(
                "{label} cannot be imported: invalid operation"
            )));
        };
        let mut key = match (&override_values.op_key, override_values.invalid_op_key) {
            (Some(custom), _) => custom.clone(),
            (None, true) => {
                return Err(OpenApiImportError::new(
                    "op_key must be lowercase snake_case, 64 characters or fewer",
                ));
            }
            (None, false) => match &operation_id {
                // Python's `op_id or f"{method}_{path}"`: an empty operationId is falsy.
                Some(id) if !id.is_empty() => snake(id),
                _ => snake(&format!("{}_{}", candidate.method, candidate.path)),
            },
        };
        if !NAME.is_match(&key) {
            return Err(OpenApiImportError::new(
                "op_key must be lowercase snake_case, 64 characters or fewer",
            ));
        }
        if used.contains(&key) {
            let base = truncate(&key, 60);
            let mut suffix = 1usize;
            while used.contains(&key) {
                suffix += 1;
                key = format!("{base}_{suffix}");
            }
        }
        used.push(key.clone());
        let summary = operation
            .get("summary")
            .and_then(Value::as_str)
            .map(|text| truncate(text, 200))
            .unwrap_or_default();
        result.push(ImportedOperation {
            op_key: key,
            manifest,
            operation_id,
            method: built.method,
            path: candidate.path.clone(),
            summary,
        });
    }
    Ok(result)
}

fn python_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().map(|float| float != 0.0).unwrap_or(true),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python's `str(value)` for JSON values, used only to key parameter locations.
fn python_str(value: &Value) -> String {
    match value {
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        Value::Number(number) => number.to_string(),
        Value::String(text) => text.clone(),
        Value::Array(_) | Value::Object(_) => serde_json::to_string(value).unwrap_or_default(),
    }
}

/// Python's `repr(str)` for the refusal messages that embed a name.
///
/// Printable characters are kept raw (Python's `isprintable` is not reproduced); escapes are
/// the ones the reference's messages realistically carry.
fn python_repr(value: &str) -> String {
    let quote = if value.contains('\'') && !value.contains('"') {
        '"'
    } else {
        '\''
    };
    let mut out = String::with_capacity(value.len() + 2);
    out.push(quote);
    for character in value.chars() {
        match character {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            control if control == quote => {
                out.push('\\');
                out.push(control);
            }
            control if control.is_ascii_control() => {
                out.push_str(&format!("\\x{:02x}", control as u32));
            }
            other => out.push(other),
        }
    }
    out.push(quote);
    out
}

// ── the no-LLM deny list (`src.toolkit_contract.endpoints`) ─────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DenyClass {
    Llm,
    Unclassified,
}

impl DenyClass {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Llm => "llm",
            Self::Unclassified => "unclassified",
        }
    }
}

const LLM_DENY_LIST: &[(&str, DenyClass)] = &[
    ("/api/ai", DenyClass::Llm),
    ("/api/ai/*", DenyClass::Llm),
    ("/api/tests/ai", DenyClass::Llm),
    ("/api/tests/ai/*", DenyClass::Llm),
    ("*/ai-augmented", DenyClass::Llm),
    ("*/ai-augmented/*", DenyClass::Llm),
    ("*/execute-agent", DenyClass::Llm),
    ("*/execute-agent/*", DenyClass::Llm),
    ("*/chat/completions*", DenyClass::Llm),
    ("/workers/*/message*", DenyClass::Llm),
    ("*/query/ask*", DenyClass::Llm),
    ("/api/ask", DenyClass::Llm),
    ("/api/ask/*", DenyClass::Llm),
    ("*/bug-hunter", DenyClass::Unclassified),
    ("*/bug-hunter/*", DenyClass::Unclassified),
    ("*/semantic/analyze-codebase*", DenyClass::Unclassified),
    ("*/static/advanced-validation*", DenyClass::Unclassified),
    ("*/static/documentation*", DenyClass::Unclassified),
];

fn denied_by(path: &str) -> Option<DenyClass> {
    let lowered = path.to_lowercase();
    let stripped = lowered.trim_end_matches('/');
    let normalized = if stripped.is_empty() { "/" } else { stripped };
    LLM_DENY_LIST
        .iter()
        .find(|(pattern, _)| glob_match(&pattern.to_lowercase(), normalized))
        .map(|(_, classification)| *classification)
}

/// The reference's deny patterns are `*`-separated literals anchored at both ends; `*` spans
/// any run of characters, including `/`.
fn glob_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return text == pattern;
    }
    let first = parts[0];
    if !text.starts_with(first) {
        return false;
    }
    let mut rest = &text[first.len()..];
    let last = parts.len() - 1;
    for part in &parts[1..last] {
        match rest.find(part) {
            Some(index) => rest = &rest[index + part.len()..],
            None => return false,
        }
    }
    rest.ends_with(parts[last])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snake_matches_the_reference_examples() {
        assert_eq!(snake("readItem"), "read_item");
        assert_eq!(snake("itemId"), "item_id");
        assert_eq!(snake("x-trace"), "x_trace");
        assert_eq!(snake("GET /items/{itemId}"), "get_items_item_id");
        assert_eq!(snake("123abc"), "p_123abc");
        assert_eq!(snake("---"), "p");
        assert_eq!(snake(&"a".repeat(100)), "a".repeat(64));
        assert_eq!(snake("trailing___"), "trailing");
    }

    #[test]
    fn document_versions_are_checked() {
        assert_eq!(
            document_version(&json!({"openapi": "3.1.0", "paths": {}})).unwrap(),
            "3.1.0"
        );
        assert_eq!(
            document_version(&json!({"openapi": "3.0.3-rc1", "paths": {}})).unwrap(),
            "3.0.3-rc1"
        );
        for doc in [
            json!({"swagger": "2.0"}),
            json!({"openapi": "3.2.0", "paths": {}}),
            json!({"openapi": "3.0.0"}),
            json!([]),
        ] {
            assert!(document_version(&doc).is_err(), "{doc}");
        }
    }

    #[test]
    fn the_deny_list_matches_like_the_reference() {
        assert_eq!(denied_by("/api/ai/chat"), Some(DenyClass::Llm));
        assert_eq!(denied_by("/API/AI"), Some(DenyClass::Llm));
        assert_eq!(denied_by("/api/ai/"), Some(DenyClass::Llm));
        assert_eq!(denied_by("/x/ai-augmented/y"), Some(DenyClass::Llm));
        assert_eq!(
            denied_by("/api/v1/bug-hunter"),
            Some(DenyClass::Unclassified)
        );
        assert_eq!(denied_by("/api/v1/customers"), None);
        assert_eq!(denied_by("/"), None);
    }

    #[test]
    fn schema_normalisation_converts_nullable_and_30_exclusive_bounds() {
        let doc = json!({
            "openapi": "3.0.3",
            "paths": {},
            "components": {"schemas": {"B": {"type": "string", "enum": ["x"], "nullable": true}}},
        });
        let mut converter = Converter::new(&doc, Direction::Output);
        let schema = json!({
            "type": "object",
            "properties": {
                "a": {"type": "string", "nullable": true, "example": "z"},
                "b": {"allOf": [{"$ref": "#/components/schemas/B"}], "nullable": true},
                "limit": {"type": "integer", "minimum": 0, "exclusiveMinimum": true},
            },
            "discriminator": {"propertyName": "a"},
        });
        let converted = converter.schema(&schema, 0).unwrap();
        let finished = converter.finish(&converted).unwrap();
        assert_eq!(
            finished["properties"]["a"],
            json!({"type": ["string", "null"]})
        );
        assert_eq!(
            finished["properties"]["b"]["anyOf"][0],
            json!({"allOf": [{"$ref": "#/$defs/B"}]})
        );
        assert_eq!(
            finished["properties"]["limit"],
            json!({"type": "integer", "exclusiveMinimum": 0})
        );
        assert_eq!(
            finished["$defs"]["B"],
            json!({"type": ["string", "null"], "enum": ["x", null]})
        );
        assert!(finished.get("discriminator").is_none());
    }

    #[test]
    fn structural_keywords_and_external_refs_are_refused() {
        let doc = json!({"openapi": "3.1.0", "paths": {}});
        for schema in [
            json!({"$defs": {}}),
            json!({"$id": "https://evil.test/schema"}),
            json!({"$ref": "https://evil.test/schema"}),
            json!({"$ref": "#/components/schemas/Missing"}),
        ] {
            let mut converter = Converter::new(&doc, Direction::Input);
            assert!(converter.schema(&schema, 0).is_err(), "{schema}");
        }
        let mut converter = Converter::new(&doc, Direction::Input);
        assert_eq!(
            converter
                .schema(&json!({"$ref": "http://x/y#/z"}), 0)
                .unwrap_err(),
            Refused::new("external $ref is not supported")
        );
    }

    #[test]
    fn a_boolean_false_schema_is_the_reference_sentinel() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {
                "/a": {"get": {"operationId": "a", "responses": {"200": {"content": {"application/json": {"schema": false}}}}}},
                "/b": {"post": {"operationId": "b", "requestBody": {"content": {"application/json": {"schema": false}}}, "responses": {"200": {"description": "ok"}}}},
            }
        });
        let listed = list_operations(&doc, None).unwrap();
        let reason = |operation_id: &str| {
            listed
                .iter()
                .find(|row| row.operation_id.as_deref() == Some(operation_id))
                .and_then(|row| row.reason.clone())
                .unwrap_or_default()
        };
        assert_eq!(reason("a"), "the success response is not JSON");
        assert_eq!(reason("b"), "only JSON request bodies are supported");
    }

    #[test]
    fn recursive_components_are_refused_at_finish() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {},
            "components": {"schemas": {
                "Node": {"type": "object", "properties": {"next": {"$ref": "#/components/schemas/Node"}}}
            }},
        });
        let mut converter = Converter::new(&doc, Direction::Output);
        let converted = converter
            .schema(&json!({"$ref": "#/components/schemas/Node"}), 0)
            .unwrap();
        assert_eq!(
            converter.finish(&converted).unwrap_err(),
            Refused::new("recursive schemas are not supported")
        );
    }

    #[test]
    fn non_ascii_def_names_are_sanitised() {
        let doc = json!({
            "openapi": "3.1.0",
            "paths": {},
            "components": {"schemas": {"a-b": {"type": "string"}}},
        });
        let mut converter = Converter::new(&doc, Direction::Output);
        let converted = converter
            .schema(&json!({"$ref": "#/components/schemas/a-b"}), 0)
            .unwrap();
        assert_eq!(converted["$ref"], "#/$defs/a_b");
        assert_eq!(
            converter.finish(&converted).unwrap()["$defs"]["a_b"],
            json!({"type": "string"})
        );
    }
}
