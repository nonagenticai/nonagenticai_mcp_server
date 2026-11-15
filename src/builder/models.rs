//! Strict request bodies of the tenant builder (REST and the builder_* MCP tools share them).
//!
//! Ported from the reference's `src/builder/models.py`. Every model mirrors the reference's
//! Pydantic configuration: unknown fields are refused (`extra="forbid"`), JSON types are never
//! coerced (`strict=True`), and cross-field validators run during deserialization. The reference
//! module imports `SpecPath` from `src.sources.models`; that module has no Rust counterpart yet, so
//! the pattern-constrained type lives here with the identical pattern and bounds.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::catalog::ids::{Digest, Name, Operation, Pointer, PositiveVersion, Uuid7};
use crate::catalog::models::{Effect, Idempotency, Method, ToolLimits};
use crate::catalog::package::PackageFile;

/// The reference's `HOST_FILES`: written into every tool package by the host, never by the author.
pub const HOST_FILES: [&str; 2] = ["kit.py", "ops.py"];

/// Whether the host owns this package path.
pub fn is_host_file(path: &str) -> bool {
    HOST_FILES.contains(&path)
}

/// The request body is invalid; the message names fields and rules, never values.
///
/// The reference defines this type in `src/builder/service.py` (not in `models.py`); the builder
/// domain uses it for every authored-content refusal so the surface can map one error type.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{0}")]
pub struct BuilderInputError(pub String);

impl BuilderInputError {
    /// Construct from a safe-to-show message.
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }

    /// The message.
    pub fn message(&self) -> &str {
        &self.0
    }
}

/// A same-origin spec path: `^/[A-Za-z0-9._~/-]{0,255}$`.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SpecPath(String);

impl SpecPath {
    /// Validate and wrap a spec path.
    pub fn new(value: impl Into<String>) -> Result<Self, BuilderInputError> {
        static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"\A/[A-Za-z0-9._~/-]{0,255}\z").expect("the spec path pattern is valid")
        });
        let value = value.into();
        if PATTERN.is_match(&value) {
            Ok(Self(value))
        } else {
            Err(BuilderInputError::new("invalid spec path"))
        }
    }

    /// The validated path.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for SpecPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for SpecPath {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SpecPath {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl TryFrom<&str> for SpecPath {
    type Error = BuilderInputError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

// ── bounded field deserializers ─────────────────────────────────────────────────────────────

fn bounded_text<'de, D: Deserializer<'de>>(
    deserializer: D,
    min: usize,
    max: usize,
    message: &'static str,
) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    let length = value.chars().count();
    if length < min || length > max {
        Err(D::Error::custom(message))
    } else {
        Ok(value)
    }
}

fn text_1_1024<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 1024, "text must be 1 to 1024 characters")
}

fn text_1_4096<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 4096, "text must be 1 to 4096 characters")
}

fn text_0_256<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 0, 256, "text must be at most 256 characters")
}

fn optional_text_1_4096<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => {
            let length = value.chars().count();
            if (1..=4096).contains(&length) {
                Ok(Some(value))
            } else {
                Err(D::Error::custom("text must be 1 to 4096 characters"))
            }
        }
        None => Ok(None),
    }
}

fn optional_timeout<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u32>, D::Error> {
    match Option::<u64>::deserialize(deserializer)? {
        Some(value) if (1..=300).contains(&value) => Ok(Some(value as u32)),
        Some(_) => Err(D::Error::custom("timeout_seconds must be 1 to 300")),
        None => Ok(None),
    }
}

fn optional_retries<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<u32>, D::Error> {
    match Option::<u64>::deserialize(deserializer)? {
        Some(value) if (0..=3).contains(&value) => Ok(Some(value as u32)),
        Some(_) => Err(D::Error::custom("max_retries must be 0 to 3")),
        None => Ok(None),
    }
}

fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
    min: usize,
    max: usize,
    message: &'static str,
) -> Result<Vec<T>, D::Error> {
    let values = Vec::<T>::deserialize(deserializer)?;
    if values.len() < min || values.len() > max {
        Err(D::Error::custom(message))
    } else {
        Ok(values)
    }
}

fn vec_1_32<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 1, 32, "files must have 1 to 32 entries")
}

fn optional_vec_1_32<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error> {
    match Option::<Vec<T>>::deserialize(deserializer)? {
        Some(values) if values.is_empty() || values.len() > 32 => {
            Err(D::Error::custom("files must have 1 to 32 entries"))
        }
        other => Ok(other),
    }
}

fn vec_max_32<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 0, 32, "at most 32 entries")
}

fn optional_vec_max_32<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error> {
    match Option::<Vec<T>>::deserialize(deserializer)? {
        Some(values) if values.len() > 32 => Err(D::Error::custom("at most 32 entries")),
        other => Ok(other),
    }
}

fn optional_vec_max_16<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error> {
    match Option::<Vec<T>>::deserialize(deserializer)? {
        Some(values) if values.len() > 16 => Err(D::Error::custom("at most 16 entries")),
        other => Ok(other),
    }
}

fn optional_vec_min_1<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Option<Vec<T>>, D::Error> {
    match Option::<Vec<T>>::deserialize(deserializer)? {
        Some(values) if values.is_empty() => Err(D::Error::custom("at least 1 entry")),
        other => Ok(other),
    }
}

fn vec_1_128<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 1, 128, "tools must have 1 to 128 entries")
}

fn map_max_128<'de, D: Deserializer<'de>, V: Deserialize<'de>>(
    deserializer: D,
) -> Result<BTreeMap<String, V>, D::Error> {
    let values = BTreeMap::<String, V>::deserialize(deserializer)?;
    if values.len() > 128 {
        Err(D::Error::custom("at most 128 entries"))
    } else {
        Ok(values)
    }
}

fn product<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"\A[a-z][a-z0-9-]{0,47}\z").expect("the product pattern is valid")
    });
    match Option::<String>::deserialize(deserializer)? {
        Some(value) if PATTERN.is_match(&value) => Ok(Some(value)),
        Some(_) => Err(D::Error::custom(
            "product must be lowercase letters, digits and hyphens",
        )),
        None => Ok(None),
    }
}

// ── spec fetch and import requests ──────────────────────────────────────────────────────────

/// Fetch the source's OpenAPI document (JSON). `path` defaults to the source's `spec_path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SpecFetchRequest {
    /// Same-origin path; omitted means the source's configured `spec_path`.
    #[serde(default)]
    pub path: Option<SpecPath>,
}

/// One `{method, path}` selection of an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationSelector {
    /// The HTTP method; the document's method names are lowercase, the selector's uppercase.
    pub method: Method,
    /// The path exactly as the document spells it.
    #[serde(deserialize_with = "text_1_1024")]
    pub path: String,
}

/// Per-operation choices; every field is optional and replaces the importer's default.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationOverride {
    /// The script key; only valid when exactly one operation is selected.
    #[serde(default)]
    pub op_key: Option<Name>,
    /// Read or write.
    #[serde(default)]
    pub effect: Option<Effect>,
    /// 4xx statuses the tool handles itself.
    #[serde(default, deserialize_with = "optional_vec_max_16")]
    pub expected_error_statuses: Option<Vec<u16>>,
    /// Result pointers to project, at least one when present.
    #[serde(default, deserialize_with = "optional_vec_min_1")]
    pub response_projection: Option<Vec<Pointer>>,
    /// Per-attempt timeout, 1 to 300 seconds.
    #[serde(default, deserialize_with = "optional_timeout")]
    pub timeout_seconds: Option<u32>,
}

/// A selection entry: an operationId or a `{method, path}` pair.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SelectionEntry {
    /// The document's `operationId`.
    OperationId(String),
    /// A method and path pair.
    Operation(OperationSelector),
}

impl Serialize for SelectionEntry {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::OperationId(id) => serializer.serialize_str(id),
            Self::Operation(selector) => selector.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SelectionEntry {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        match value {
            Value::String(id) => {
                let length = id.chars().count();
                if (1..=256).contains(&length) {
                    Ok(Self::OperationId(id))
                } else {
                    Err(D::Error::custom("selection must be 1 to 256 characters"))
                }
            }
            other @ Value::Object(_) => OperationSelector::deserialize(other)
                .map(Self::Operation)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom(
                "a selection is an operationId or {method, path}",
            )),
        }
    }
}

/// Import operations from a cached spec. `select` entries are an operationId or a
/// `{method, path}`; `overrides` is keyed by that operationId or by `"METHOD /path"`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ImportRequest {
    /// SHA-256 of the fetched spec document.
    pub spec_sha256: Digest,
    /// 1 to 128 selections.
    #[serde(deserialize_with = "vec_1_128")]
    pub select: Vec<SelectionEntry>,
    /// At most 128 per-operation overrides.
    #[serde(default, deserialize_with = "map_max_128")]
    pub overrides: BTreeMap<String, OperationOverride>,
}

/// A new draft version of an imported operation (omitted fields keep their value).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationPatch {
    /// The version this patch expects.
    pub expected_version: PositiveVersion,
    /// Read or write.
    #[serde(default)]
    pub effect: Option<Effect>,
    /// 4xx statuses the tool handles itself.
    #[serde(default, deserialize_with = "optional_vec_max_16")]
    pub expected_error_statuses: Option<Vec<u16>>,
    /// Result pointers to project, at least one when present.
    #[serde(default, deserialize_with = "optional_vec_min_1")]
    pub response_projection: Option<Vec<Pointer>>,
    /// Result pointers to redact.
    #[serde(default)]
    pub redact_fields: Option<Vec<Pointer>>,
    /// Per-attempt timeout, 1 to 300 seconds.
    #[serde(default, deserialize_with = "optional_timeout")]
    pub timeout_seconds: Option<u32>,
    /// Retries, 0 to 3.
    #[serde(default, deserialize_with = "optional_retries")]
    pub max_retries: Option<u32>,
    /// Retry idempotency.
    #[serde(default)]
    pub idempotency: Option<Idempotency>,
    /// A successful response may carry no body.
    #[serde(default)]
    pub empty_response: Option<bool>,
}

// ── tool requests ───────────────────────────────────────────────────────────────────────────

/// An operation the script may call: one of your sources (`source_key`) or a platform service
/// shared with you (`service`), plus its `op_key`. In the script the operation is
/// `"<source_key or service>.<op_key>"`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolOperation")]
pub struct ToolOperation {
    /// The operation's key inside its origin.
    pub op_key: Name,
    /// The tenant source that owns the operation.
    pub source_key: Option<Name>,
    /// The platform service that owns the operation.
    pub service: Option<Name>,
}

impl ToolOperation {
    /// The script key: `"<source_key or service>.<op_key>"`.
    pub fn script_key(&self) -> String {
        match (&self.source_key, &self.service) {
            (Some(source), _) => format!("{source}.{}", self.op_key),
            (None, Some(service)) => format!("{service}.{}", self.op_key),
            (None, None) => self.op_key.to_string(),
        }
    }
}

/// Create a draft tool.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolCreate")]
pub struct ToolCreate {
    /// The MCP tool name.
    pub public_name: Name,
    /// The agent platform operation the tool implements.
    pub operation: Operation,
    /// Human description, 1 to 4096 characters.
    pub description: String,
    /// 1 to 32 author package files.
    pub files: Vec<PackageFile>,
    /// Input JSON Schema.
    pub input_schema: Map<String, Value>,
    /// Result JSON Schema.
    pub result_schema: Option<Map<String, Value>>,
    /// Read or write.
    pub effect: Effect,
    /// Operations the script may call, at most 32.
    pub ops: Vec<ToolOperation>,
    /// Runner limits.
    pub limits: Option<ToolLimits>,
    /// Package entrypoint.
    pub entrypoint: String,
}

/// A new draft version of a tool. Omitted fields keep the latest version's value; `files`
/// replaces ALL script files; `ops` replaces the operation list.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolUpdate")]
pub struct ToolUpdate {
    /// The revision this update expects.
    pub expected_revision: PositiveVersion,
    /// Human description, 1 to 4096 characters.
    pub description: Option<String>,
    /// 1 to 32 author package files.
    pub files: Option<Vec<PackageFile>>,
    /// Input JSON Schema.
    pub input_schema: Option<Map<String, Value>>,
    /// Result JSON Schema.
    pub result_schema: Option<Map<String, Value>>,
    /// Read or write.
    pub effect: Option<Effect>,
    /// Operations the script may call, at most 32.
    pub ops: Option<Vec<ToolOperation>>,
    /// Runner limits.
    pub limits: Option<ToolLimits>,
}

/// The inputs of one author test run.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolTestRequest {
    /// Tool inputs.
    #[serde(default)]
    pub inputs: Map<String, Value>,
    /// Required for a tool whose effect is `writes`.
    #[serde(default)]
    pub confirm_writes: bool,
}

/// Publish a draft tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolPublishRequest {
    /// The revision this publish expects.
    pub expected_revision: PositiveVersion,
}

/// One tool selected into a toolkit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitTool {
    /// The tool identity.
    pub tool_id: Uuid7,
    /// A published version; omitted means the newest published version.
    #[serde(default)]
    pub version: Option<PositiveVersion>,
}

/// Create a toolkit (draft v1) or, with `toolkit_id` + `expected_revision`, its next draft version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolkitRequest")]
pub struct ToolkitRequest {
    /// The toolkit name.
    pub name: Name,
    /// Human description, 1 to 4096 characters.
    pub description: String,
    /// 1 to 128 selected tools.
    pub tools: Vec<ToolkitTool>,
    /// The toolkit to append a version to.
    pub toolkit_id: Option<Uuid7>,
    /// The revision the append expects.
    pub expected_revision: Option<PositiveVersion>,
}

/// Publish a draft toolkit.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitPublishRequest {
    /// The revision this publish expects.
    pub expected_revision: PositiveVersion,
}

/// Re-bind the tenant's product bindings so they include its published toolkits.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindRequest {
    /// Limit to one product; omitted means every product with a binding.
    #[serde(default, deserialize_with = "product")]
    pub product: Option<String>,
}

// ── strict wire forms ───────────────────────────────────────────────────────────────────────

mod wire {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolOperation {
        pub op_key: Name,
        #[serde(default)]
        pub source_key: Option<Name>,
        #[serde(default)]
        pub service: Option<Name>,
    }

    impl TryFrom<ToolOperation> for super::ToolOperation {
        type Error = BuilderInputError;

        fn try_from(wire: ToolOperation) -> Result<Self, Self::Error> {
            if wire.source_key.is_none() == wire.service.is_none() {
                return Err(BuilderInputError::new(
                    "name exactly one of source_key or service",
                ));
            }
            Ok(Self {
                op_key: wire.op_key,
                source_key: wire.source_key,
                service: wire.service,
            })
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolCreate {
        pub public_name: Name,
        pub operation: Operation,
        #[serde(deserialize_with = "text_1_4096")]
        pub description: String,
        #[serde(deserialize_with = "vec_1_32")]
        pub files: Vec<PackageFile>,
        pub input_schema: Map<String, Value>,
        #[serde(default)]
        pub result_schema: Option<Map<String, Value>>,
        pub effect: Effect,
        #[serde(default, deserialize_with = "vec_max_32")]
        pub ops: Vec<super::ToolOperation>,
        #[serde(default)]
        pub limits: Option<ToolLimits>,
        #[serde(default = "default_entrypoint", deserialize_with = "text_0_256")]
        pub entrypoint: String,
    }

    fn default_entrypoint() -> String {
        "tool:main".to_owned()
    }

    impl TryFrom<ToolCreate> for super::ToolCreate {
        type Error = BuilderInputError;

        fn try_from(wire: ToolCreate) -> Result<Self, Self::Error> {
            if wire.files.iter().any(|file| is_host_file(&file.path)) {
                return Err(BuilderInputError::new(
                    "kit.py and ops.py are written by the host; do not send them",
                ));
            }
            let mut keys = BTreeSet::new();
            for operation in &wire.ops {
                if !keys.insert(operation.script_key()) {
                    return Err(BuilderInputError::new("duplicate operation in ops"));
                }
            }
            Ok(Self {
                public_name: wire.public_name,
                operation: wire.operation,
                description: wire.description,
                files: wire.files,
                input_schema: wire.input_schema,
                result_schema: wire.result_schema,
                effect: wire.effect,
                ops: wire.ops,
                limits: wire.limits,
                entrypoint: wire.entrypoint,
            })
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolUpdate {
        pub expected_revision: PositiveVersion,
        #[serde(default, deserialize_with = "optional_text_1_4096")]
        pub description: Option<String>,
        #[serde(default, deserialize_with = "optional_vec_1_32")]
        pub files: Option<Vec<PackageFile>>,
        #[serde(default)]
        pub input_schema: Option<Map<String, Value>>,
        #[serde(default)]
        pub result_schema: Option<Map<String, Value>>,
        #[serde(default)]
        pub effect: Option<Effect>,
        #[serde(default, deserialize_with = "optional_vec_max_32")]
        pub ops: Option<Vec<super::ToolOperation>>,
        #[serde(default)]
        pub limits: Option<ToolLimits>,
    }

    impl TryFrom<ToolUpdate> for super::ToolUpdate {
        type Error = BuilderInputError;

        fn try_from(wire: ToolUpdate) -> Result<Self, Self::Error> {
            if let Some(files) = &wire.files
                && files.iter().any(|file| is_host_file(&file.path))
            {
                return Err(BuilderInputError::new(
                    "kit.py and ops.py are written by the host; do not send them",
                ));
            }
            Ok(Self {
                expected_revision: wire.expected_revision,
                description: wire.description,
                files: wire.files,
                input_schema: wire.input_schema,
                result_schema: wire.result_schema,
                effect: wire.effect,
                ops: wire.ops,
                limits: wire.limits,
            })
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolkitRequest {
        pub name: Name,
        #[serde(deserialize_with = "text_1_4096")]
        pub description: String,
        #[serde(deserialize_with = "vec_1_128")]
        pub tools: Vec<ToolkitTool>,
        #[serde(default)]
        pub toolkit_id: Option<Uuid7>,
        #[serde(default)]
        pub expected_revision: Option<PositiveVersion>,
    }

    impl TryFrom<ToolkitRequest> for super::ToolkitRequest {
        type Error = BuilderInputError;

        fn try_from(wire: ToolkitRequest) -> Result<Self, Self::Error> {
            if wire.toolkit_id.is_none() != wire.expected_revision.is_none() {
                return Err(BuilderInputError::new(
                    "toolkit_id and expected_revision go together",
                ));
            }
            Ok(Self {
                name: wire.name,
                description: wire.description,
                tools: wire.tools,
                toolkit_id: wire.toolkit_id,
                expected_revision: wire.expected_revision,
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn tool_operation_needs_exactly_one_origin() {
        assert!(
            serde_json::from_value::<ToolOperation>(
                json!({"op_key": "get_customer", "source_key": "crm"})
            )
            .is_ok()
        );
        assert!(
            serde_json::from_value::<ToolOperation>(
                json!({"op_key": "get_customer", "service": "fr"})
            )
            .is_ok()
        );
        for value in [
            json!({"op_key": "get_customer"}),
            json!({"op_key": "get_customer", "source_key": "crm", "service": "fr"}),
        ] {
            let error = serde_json::from_value::<ToolOperation>(value).unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("name exactly one of source_key or service"),
                "{error}"
            );
        }
        let operation: ToolOperation =
            serde_json::from_value(json!({"op_key": "get_customer", "source_key": "crm"})).unwrap();
        assert_eq!(operation.script_key(), "crm.get_customer");
        let service_operation: ToolOperation =
            serde_json::from_value(json!({"op_key": "get_projects", "service": "fr"})).unwrap();
        assert_eq!(service_operation.script_key(), "fr.get_projects");
        // `op_key` is a plain catalog name in the reference (`models.py:81`), never dotted:
        // the script key's separator comes from the origin, not from the key.
        assert!(
            serde_json::from_value::<ToolOperation>(
                json!({"op_key": "projects.get", "service": "fr"})
            )
            .is_err()
        );
    }

    #[test]
    fn host_files_are_refused_at_every_level() {
        for files in [
            json!([{"path": "kit.py", "content": "x"}]),
            json!([{"path": "ops.py", "content": "x"}]),
        ] {
            let error = serde_json::from_value::<ToolCreate>(json!({
                "public_name": "find_customer",
                "operation": "customer.find",
                "description": "Find",
                "files": files,
                "input_schema": {"type": "object"},
                "effect": "read_only",
            }))
            .unwrap_err();
            assert!(
                error
                    .to_string()
                    .contains("kit.py and ops.py are written by the host"),
                "{error}"
            );
        }
        assert!(
            serde_json::from_value::<ToolCreate>(json!({
                "public_name": "find_customer",
                "operation": "customer.find",
                "description": "Find",
                "files": [{"path": "tool.py", "content": "x"}],
                "input_schema": {"type": "object"},
                "effect": "read_only",
                "ops": [
                    {"op_key": "get_customer", "source_key": "crm"},
                    {"op_key": "get_customer", "source_key": "crm"}
                ],
            }))
            .unwrap_err()
            .to_string()
            .contains("duplicate operation in ops")
        );
    }

    #[test]
    fn tool_create_defaults_match_the_reference() {
        let create: ToolCreate = serde_json::from_value(json!({
            "public_name": "find_customer",
            "operation": "customer.find",
            "description": "Find",
            "files": [{"path": "tool.py", "content": "x"}],
            "input_schema": {"type": "object"},
            "effect": "read_only",
        }))
        .unwrap();
        assert_eq!(create.entrypoint, "tool:main");
        assert!(create.ops.is_empty());
        assert!(create.result_schema.is_none());
        assert!(create.limits.is_none());
    }

    #[test]
    fn selections_are_an_id_or_a_method_path_pair() {
        let entries: ImportRequest = serde_json::from_value(json!({
            "spec_sha256": "a".repeat(64),
            "select": ["readItem", {"method": "GET", "path": "/items"}],
        }))
        .unwrap();
        assert_eq!(
            entries.select,
            vec![
                SelectionEntry::OperationId("readItem".into()),
                SelectionEntry::Operation(OperationSelector {
                    method: Method::Get,
                    path: "/items".into(),
                }),
            ]
        );
        assert!(
            serde_json::from_value::<ImportRequest>(json!({
                "spec_sha256": "a".repeat(64),
                "select": [{"method": "get", "path": "/items"}],
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ImportRequest>(json!({
                "spec_sha256": "a".repeat(64),
                "select": [],
            }))
            .is_err()
        );
        assert!(
            serde_json::from_value::<ImportRequest>(json!({
                "spec_sha256": "a".repeat(64),
                "select": [""],
            }))
            .is_err()
        );
    }

    #[test]
    fn toolkit_identity_and_revision_go_together() {
        let base = json!({
            "name": "crm",
            "description": "CRM tools",
            "tools": [{"tool_id": "01900000-0000-7000-8000-000000000001"}],
        });
        assert!(serde_json::from_value::<ToolkitRequest>(base.clone()).is_ok());
        assert!(
            serde_json::from_value::<ToolkitRequest>(json!({
                "toolkit_id": "01900000-0000-7000-8000-000000000002",
                "expected_revision": 2,
                "name": "crm",
                "description": "CRM tools",
                "tools": [{"tool_id": "01900000-0000-7000-8000-000000000001"}],
            }))
            .is_ok()
        );
        let error = serde_json::from_value::<ToolkitRequest>(json!({
            "toolkit_id": "01900000-0000-7000-8000-000000000002",
            "name": "crm",
            "description": "CRM tools",
            "tools": [{"tool_id": "01900000-0000-7000-8000-000000000001"}],
        }))
        .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("toolkit_id and expected_revision go together"),
            "{error}"
        );
    }

    #[test]
    fn spec_paths_and_products_are_bounded() {
        assert!(SpecPath::new("/openapi.json").is_ok());
        assert!(SpecPath::new("/").is_ok());
        assert!(SpecPath::new("openapi.json").is_err());
        assert!(SpecPath::new("/a b").is_err());
        assert!(SpecPath::new(format!("/{}", "a".repeat(256))).is_err());
        assert!(serde_json::from_value::<BindRequest>(json!({"product": "care-bus"})).is_ok());
        assert!(serde_json::from_value::<BindRequest>(json!({"product": "Care Bus"})).is_err());
    }
}
