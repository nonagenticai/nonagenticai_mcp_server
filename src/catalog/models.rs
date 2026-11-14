//! Strict domain models for the catalog: constraints, services, operations, tools.
//!
//! Every model mirrors the reference's Pydantic configuration: unknown fields are refused
//! (`extra="forbid"`), JSON types are never coerced (`strict=True`), and cross-field validators
//! run during deserialization so an invalid manifest cannot be constructed from a request body.
//! Field names are the reference field names exactly: these models become JSON bodies later.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};

use crate::catalog::error::CatalogError;
use crate::catalog::ids::{
    AppKey, AuthorityId, Digest, ImageDigest, Name, Operation, Pointer, PositiveVersion, Uuid7,
    default_one, one,
};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::package::canonical_path;

// ── deterministic field deserializers ────────────────────────────────────────────────────────

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

pub(crate) fn text_1_4096<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 4096, "text must be 1 to 4096 characters")
}

fn text_1_1024<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 1024, "text must be 1 to 1024 characters")
}

fn text_1_256<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 1, 256, "text must be 1 to 256 characters")
}

fn text_0_512<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    bounded_text(deserializer, 0, 512, "text must be at most 512 characters")
}

pub(crate) fn optional_text_1_1024<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => {
            let length = value.chars().count();
            if (1..=1024).contains(&length) {
                Ok(Some(value))
            } else {
                Err(D::Error::custom("text must be 1 to 1024 characters"))
            }
        }
        None => Ok(None),
    }
}

fn optional_text_256<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<String>, D::Error> {
    match Option::<String>::deserialize(deserializer)? {
        Some(value) => {
            if value.chars().count() <= 256 {
                Ok(Some(value))
            } else {
                Err(D::Error::custom("text must be at most 256 characters"))
            }
        }
        None => Ok(None),
    }
}

fn bounded_integer<'de, D: Deserializer<'de>>(
    deserializer: D,
    min: u64,
    max: u64,
    message: &'static str,
) -> Result<u64, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value < min || value > max {
        Err(D::Error::custom(message))
    } else {
        Ok(value)
    }
}

fn bytes_10m<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(
        deserializer,
        1,
        10_485_760,
        "byte limit must be 1 to 10485760",
    )
    .map(|value| value as u32)
}

fn timeout_1_300<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 300, "timeout_seconds must be 1 to 300")
        .map(|value| value as u32)
}

fn pagination_1_1000<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 1000, "pagination_limit must be 1 to 1000")
        .map(|value| value as u32)
}

fn retries_0_3<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 0, 3, "max_retries must be 0 to 3").map(|value| value as u32)
}

fn wall_1_300<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 300, "wall_seconds must be 1 to 300").map(|value| value as u32)
}

fn queue_1_600<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 600, "queue_seconds must be 1 to 600")
        .map(|value| value as u32)
}

fn memory_1_1024<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 1024, "memory_mi must be 1 to 1024").map(|value| value as u32)
}

fn cpu_1_1000<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 1, 1000, "cpu_millicores must be 1 to 1000")
        .map(|value| value as u32)
}

fn api_calls_0_100<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(deserializer, 0, 100, "api_calls must be 0 to 100").map(|value| value as u32)
}

fn frame_1_1048576<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(
        deserializer,
        1,
        1_048_576,
        "frame_bytes must be 1 to 1048576",
    )
    .map(|value| value as u32)
}

fn output_1_1048576<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u32, D::Error> {
    bounded_integer(
        deserializer,
        1,
        1_048_576,
        "output_bytes must be 1 to 1048576",
    )
    .map(|value| value as u32)
}

fn bounded_vec<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
    min: usize,
    max: usize,
    message: &'static str,
) -> Result<Vec<T>, D::Error> {
    let value = Vec::<T>::deserialize(deserializer)?;
    if value.len() < min || value.len() > max {
        Err(D::Error::custom(message))
    } else {
        Ok(value)
    }
}

pub(crate) fn vec_max_128<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 0, 128, "at most 128 entries")
}

pub(crate) fn vec_max_100<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 0, 100, "at most 100 entries")
}

pub(crate) fn vec_max_64<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 0, 64, "at most 64 entries")
}

pub(crate) fn vec_max_32<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 0, 32, "at most 32 entries")
}

fn vec_min_1<'de, D: Deserializer<'de>, T: Deserialize<'de>>(
    deserializer: D,
) -> Result<Vec<T>, D::Error> {
    bounded_vec(deserializer, 1, usize::MAX, "at least one entry")
}

fn set_values<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Value>, D::Error> {
    bounded_vec(
        deserializer,
        1,
        64,
        "set membership requires 1 to 64 values",
    )
}

fn package_path<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
    let value = String::deserialize(deserializer)?;
    canonical_path(&value).map_err(|error| D::Error::custom(error.to_string()))
}

/// Define a field deserializer enforcing one anchored pattern.
macro_rules! pattern_field {
    ($fn_name:ident, $pattern:literal, $message:literal) => {
        fn $fn_name<'de, D: Deserializer<'de>>(deserializer: D) -> Result<String, D::Error> {
            static PATTERN: LazyLock<Regex> =
                LazyLock::new(|| Regex::new($pattern).expect("field pattern is valid"));
            let value = String::deserialize(deserializer)?;
            if PATTERN.is_match(&value) {
                Ok(value)
            } else {
                Err(D::Error::custom($message))
            }
        }
    };
}

pattern_field!(
    webhook_path,
    r"^[a-z0-9][a-z0-9/_-]{0,127}$",
    "invalid n8n webhook path"
);
pattern_field!(
    result_node,
    r"^[A-Za-z0-9 _.-]{1,128}$",
    "invalid n8n result node"
);
pattern_field!(
    project_type,
    r"^[a-z0-9_-]{1,128}$",
    "invalid fr project type"
);

// ── closed enums ────────────────────────────────────────────────────────────────────────────

/// Where the runner gets the service credential.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthAdapter {
    /// `Authorization: Bearer <licence>`.
    LicenseBearer,
    /// A configured licence header.
    LicenseHeader,
    /// Whatever the registered destination source stores.
    Source,
}

/// The tool runtime and the external target kind share these names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Runtime {
    /// A packaged Python tool run by the Kata runner.
    #[default]
    KataPython,
    /// An n8n workflow webhook.
    N8nWorkflow,
    /// The fr channel's project answer.
    FrProject,
    /// One fixed fr channel command.
    FrCommand,
}

/// Whether the operation reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Effect {
    /// A pure read.
    ReadOnly,
    /// A mutation.
    Writes,
}

/// HTTP methods the platform supports.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Method {
    /// GET
    Get,
    /// POST
    Post,
    /// PUT
    Put,
    /// PATCH
    Patch,
    /// DELETE
    Delete,
}

/// Retry idempotency.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Idempotency {
    /// Never retried unless the operation says otherwise.
    #[default]
    None,
    /// Retries reuse the downstream idempotency key.
    DownstreamKey,
}

/// Where a mapping places its value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MappingLocation {
    /// A path template variable.
    Path,
    /// A declared query field.
    Query,
    /// A declared header field.
    Header,
    /// A JSON Pointer into the request body.
    Body,
}

/// The `kind` literal of `context_equal`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContextEqualKind {
    /// `context_equal`
    ContextEqual,
}

/// The `kind` literal of `set_membership`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SetMembershipKind {
    /// `set_membership`
    SetMembership,
}

/// The `kind` literal of `numeric_bounds`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NumericBoundsKind {
    /// `numeric_bounds`
    NumericBounds,
}

/// The `kind` literal of `relative_path`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RelativePathKind {
    /// `relative_path`
    RelativePath,
}

/// The `kind` literal of `ownership_read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OwnershipReadKind {
    /// `ownership_read`
    OwnershipRead,
}

/// The `kind` literal of `n8n_workflow`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum N8nWorkflowKind {
    /// `n8n_workflow`
    N8nWorkflow,
}

/// The `kind` literal of `fr_project`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrProjectKind {
    /// `fr_project`
    FrProject,
}

/// The `kind` literal of `fr_command`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FrCommandKind {
    /// `fr_command`
    FrCommand,
}

/// The two fixed fr commands a tool target may carry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FrCommand {
    /// `projects.get`
    #[serde(rename = "projects.get")]
    ProjectsGet,
    /// `projects.close`
    #[serde(rename = "projects.close")]
    ProjectsClose,
}

// ── references and constraints ──────────────────────────────────────────────────────────────

/// One exact `(identity, version)` pin. Protocol v1 never floats to another version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactReference {
    /// A UUIDv7 identity.
    pub id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
}

/// `context_equal`: the argument must equal one bound-context value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ContextEquality {
    /// Always `context_equal`.
    pub kind: ContextEqualKind,
    /// Pointer into the tool input.
    pub argument: Pointer,
    /// Pointer into the bound context.
    pub context: Pointer,
}

/// `set_membership`: the argument must be one of the listed values.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SetMembership {
    /// Always `set_membership`.
    pub kind: SetMembershipKind,
    /// Pointer into the tool input.
    pub argument: Pointer,
    /// The allowed values, 1 to 64.
    #[serde(deserialize_with = "set_values")]
    pub values: Vec<Value>,
}

/// `numeric_bounds`: the argument must fall inside the inclusive bounds.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::NumericBounds")]
pub struct NumericBounds {
    /// Always `numeric_bounds`.
    pub kind: NumericBoundsKind,
    /// Pointer into the tool input.
    pub argument: Pointer,
    /// Inclusive minimum.
    pub minimum: f64,
    /// Inclusive maximum.
    pub maximum: f64,
}

impl NumericBounds {
    fn validate(&self) -> Result<(), CatalogError> {
        if !self.minimum.is_finite() || !self.maximum.is_finite() || self.minimum > self.maximum {
            Err(CatalogError("invalid numeric bounds"))
        } else {
            Ok(())
        }
    }
}

/// `relative_path`: the argument must be a canonical path under `root`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelativePath {
    /// Always `relative_path`.
    pub kind: RelativePathKind,
    /// Pointer into the tool input.
    pub argument: Pointer,
    /// The canonical root every accepted path stays under.
    #[serde(deserialize_with = "package_path")]
    pub root: String,
}

/// `ownership_read`: read the owner from another published read and compare.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnershipRead {
    /// Always `ownership_read`.
    pub kind: OwnershipReadKind,
    /// Pointer into the tool input.
    pub argument: Pointer,
    /// The read-only operation that answers the owner.
    pub operation: ExactReference,
    /// Pointer into that operation's result.
    pub result: Pointer,
    /// Pointer into the bound context.
    pub context: Pointer,
}

/// A scope rule. The reference's discriminated union, dispatched on `kind`.
#[derive(Debug, Clone, PartialEq)]
pub enum Constraint {
    /// `context_equal`
    ContextEquality(ContextEquality),
    /// `set_membership`
    SetMembership(SetMembership),
    /// `numeric_bounds`
    NumericBounds(NumericBounds),
    /// `relative_path`
    RelativePath(RelativePath),
    /// `ownership_read`
    OwnershipRead(OwnershipRead),
}

impl Constraint {
    /// The reference's discriminator value.
    pub fn kind(&self) -> &'static str {
        match self {
            Self::ContextEquality(_) => "context_equal",
            Self::SetMembership(_) => "set_membership",
            Self::NumericBounds(_) => "numeric_bounds",
            Self::RelativePath(_) => "relative_path",
            Self::OwnershipRead(_) => "ownership_read",
        }
    }
}

impl Serialize for Constraint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::ContextEquality(value) => value.serialize(serializer),
            Self::SetMembership(value) => value.serialize(serializer),
            Self::NumericBounds(value) => value.serialize(serializer),
            Self::RelativePath(value) => value.serialize(serializer),
            Self::OwnershipRead(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for Constraint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let Some(kind) = value.get("kind").and_then(Value::as_str).map(str::to_owned) else {
            return Err(D::Error::custom("constraint requires a kind"));
        };
        match kind.as_str() {
            "context_equal" => serde_json::from_value(value)
                .map(Self::ContextEquality)
                .map_err(D::Error::custom),
            "set_membership" => serde_json::from_value(value)
                .map(Self::SetMembership)
                .map_err(D::Error::custom),
            "numeric_bounds" => serde_json::from_value(value)
                .map(Self::NumericBounds)
                .map_err(D::Error::custom),
            "relative_path" => serde_json::from_value(value)
                .map(Self::RelativePath)
                .map_err(D::Error::custom),
            "ownership_read" => serde_json::from_value(value)
                .map(Self::OwnershipRead)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("unsupported constraint kind")),
        }
    }
}

/// A pointer into the tool input or the bound context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourcePointer {
    /// `input` or `context`.
    pub source: SourceKind,
    /// The pointer itself.
    pub pointer: Pointer,
}

/// The `source` literal of [`SourcePointer`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceKind {
    /// The tool input.
    Input,
    /// The bound context.
    Context,
}

/// A constant mapped into a request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LiteralValue {
    /// Always `literal`.
    pub source: LiteralSource,
    /// Any JSON value.
    pub value: Value,
}

/// The `source` literal of [`LiteralValue`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LiteralSource {
    /// `literal`
    Literal,
}

/// The two ways a mapping gets its value, discriminated on `source`.
#[derive(Debug, Clone, PartialEq)]
pub enum ArgumentValue {
    /// A pointer into the input or context.
    Source(SourcePointer),
    /// A literal value.
    Literal(LiteralValue),
}

impl ArgumentValue {
    /// The reference's discriminator value.
    pub fn source(&self) -> &'static str {
        match self {
            Self::Source(pointer) => match pointer.source {
                SourceKind::Input => "input",
                SourceKind::Context => "context",
            },
            Self::Literal(_) => "literal",
        }
    }
}

impl Serialize for ArgumentValue {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Source(value) => value.serialize(serializer),
            Self::Literal(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ArgumentValue {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let source = value
            .get("source")
            .and_then(Value::as_str)
            .map(str::to_owned);
        match source.as_deref() {
            Some("input" | "context") => serde_json::from_value(value)
                .map(Self::Source)
                .map_err(D::Error::custom),
            Some("literal") => serde_json::from_value(value)
                .map(Self::Literal)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("mapping value requires a source")),
        }
    }
}

/// One value the runner puts into the downstream request.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::ArgumentMapping")]
pub struct ArgumentMapping {
    /// Where the value goes.
    pub location: MappingLocation,
    /// Path variable, query/header field name, or body JSON Pointer.
    pub target: String,
    /// Where the value comes from.
    pub value: ArgumentValue,
    /// An absent optional input is omitted instead of denying the call. Inputs only, never a
    /// path parameter.
    pub optional: bool,
}

impl ArgumentMapping {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.optional
            && (self.location == MappingLocation::Path
                || !matches!(
                    &self.value,
                    ArgumentValue::Source(SourcePointer {
                        source: SourceKind::Input,
                        ..
                    })
                ))
        {
            Err(CatalogError("only non-path input mappings can be optional"))
        } else {
            Ok(())
        }
    }
}

// ── service manifests ───────────────────────────────────────────────────────────────────────

/// A downstream service contract version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::ServiceManifest")]
pub struct ServiceManifest {
    /// Always 1.
    pub schema_version: u8,
    /// A UUIDv7 identity.
    pub service_id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The service key.
    pub service_key: Name,
    /// The destination alias the runner resolves.
    pub destination_alias: Name,
    /// Required unless `auth_adapter` is `source`.
    pub license_app_key: Option<AppKey>,
    /// How the runner authenticates.
    pub auth_adapter: AuthAdapter,
    /// The credential profile entry this service reads.
    pub credential_profile_key: Name,
    /// Maximum request body bytes, 1 to 10485760.
    pub max_request_bytes: u32,
    /// Maximum response body bytes, 1 to 10485760.
    pub max_response_bytes: u32,
}

impl ServiceManifest {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.license_app_key.is_none() && self.auth_adapter != AuthAdapter::Source {
            Err(CatalogError("licence adapters need license_app_key"))
        } else {
            Ok(())
        }
    }
}

// ── operation manifests ─────────────────────────────────────────────────────────────────────

/// One downstream HTTP operation contract version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::OperationManifest")]
pub struct OperationManifest {
    /// Always 1.
    pub schema_version: u8,
    /// A UUIDv7 identity.
    pub operation_id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The service version this operation belongs to.
    pub service: ExactReference,
    /// The HTTP method.
    pub method: Method,
    /// A fixed relative path template, 1 to 1024 characters.
    pub path_template: String,
    /// Declared query fields.
    pub query_fields: Vec<Name>,
    /// Declared header fields.
    pub header_fields: Vec<Name>,
    /// Argument mappings, at most one per target.
    pub mappings: Vec<ArgumentMapping>,
    /// Scope rules the broker must re-enforce.
    pub scope_rules: Vec<Constraint>,
    /// Input JSON Schema.
    pub input_schema: Map<String, Value>,
    /// Output JSON Schema.
    pub output_schema: Map<String, Value>,
    /// Result pointers to project, at least one.
    pub response_projection: Vec<Pointer>,
    /// Result pointers to redact.
    pub redact_fields: Vec<Pointer>,
    /// Read or write.
    pub effect: Effect,
    /// Retry idempotency.
    pub idempotency: Idempotency,
    /// Retries, 0 to 3.
    pub max_retries: u32,
    /// Per-attempt timeout, 1 to 300 seconds.
    pub timeout_seconds: u32,
    /// 4xx statuses the tool handles itself.
    pub expected_error_statuses: Vec<u16>,
    /// A successful response may carry no body.
    pub empty_response: bool,
    /// Page size cap, 1 to 1000.
    pub pagination_limit: u32,
    /// Maximum response bytes, 1 to 10485760.
    pub max_response_bytes: u32,
}

impl OperationManifest {
    fn validate(&self) -> Result<(), CatalogError> {
        let path = &self.path_template;
        if !path.starts_with('/')
            || path.starts_with("//")
            || path
                .chars()
                .any(|character| matches!(character, '\\' | '?' | '#' | '%' | '\r' | '\n'))
        {
            return Err(CatalogError(
                "operation needs a fixed relative path template",
            ));
        }
        if path[1..]
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
        {
            return Err(CatalogError("noncanonical operation path"));
        }
        static TOKEN: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"\{([a-z][a-z0-9_]*)\}").expect("template pattern is valid")
        });
        static POINTER: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^(?:/(?:[^~/]|~[01])*)*$").expect("pointer pattern is valid")
        });
        let tokens: HashSet<&str> = TOKEN
            .captures_iter(path)
            .filter_map(|captures| captures.get(1))
            .map(|capture| capture.as_str())
            .collect();
        let stripped = TOKEN.replace_all(path, "");
        if stripped.contains('{')
            || stripped.contains('}')
            || path.chars().any(|character| (character as u32) < 32)
        {
            return Err(CatalogError("invalid path template"));
        }
        let mut mapped: HashSet<(MappingLocation, &str)> = HashSet::new();
        for mapping in &self.mappings {
            if mapping.location == MappingLocation::Body {
                if !POINTER.is_match(&mapping.target) {
                    return Err(CatalogError("body target must be a JSON Pointer"));
                }
            } else if mapping.target.is_empty() {
                return Err(CatalogError("transport field target is required"));
            }
            if !mapped.insert((mapping.location, mapping.target.as_str())) {
                return Err(CatalogError("duplicate mapping target"));
            }
            if mapping.location == MappingLocation::Query
                && !self
                    .query_fields
                    .iter()
                    .any(|field| field.as_str() == mapping.target)
            {
                return Err(CatalogError("undeclared query field"));
            }
            if mapping.location == MappingLocation::Header
                && !self
                    .header_fields
                    .iter()
                    .any(|field| field.as_str() == mapping.target)
            {
                return Err(CatalogError("undeclared header field"));
            }
        }
        let path_targets: HashSet<&str> = self
            .mappings
            .iter()
            .filter(|mapping| mapping.location == MappingLocation::Path)
            .map(|mapping| mapping.target.as_str())
            .collect();
        if tokens != path_targets {
            return Err(CatalogError(
                "path mappings must cover exactly the template variables",
            ));
        }
        let body_targets: Vec<&str> = self
            .mappings
            .iter()
            .filter(|mapping| mapping.location == MappingLocation::Body)
            .map(|mapping| mapping.target.as_str())
            .collect();
        for first in &body_targets {
            let prefix = format!("{first}/");
            for second in &body_targets {
                if first != second && (first.is_empty() || second.starts_with(&prefix)) {
                    return Err(CatalogError("overlapping body mapping targets"));
                }
            }
        }
        const FORBIDDEN: [&str; 10] = [
            "authorization",
            "cookie",
            "host",
            "proxy_authorization",
            "x_tenant_id",
            "connection",
            "content_length",
            "transfer_encoding",
            "idempotency_key",
            "x_idempotency_key",
        ];
        if self
            .header_fields
            .iter()
            .any(|field| FORBIDDEN.contains(&field.as_str()))
        {
            return Err(CatalogError("transport credentials cannot be mapped"));
        }
        if self.effect == Effect::Writes
            && self.max_retries > 0
            && self.idempotency != Idempotency::DownstreamKey
        {
            return Err(CatalogError(
                "mutation retries require downstream idempotency",
            ));
        }
        if matches!(self.method, Method::Put | Method::Patch | Method::Delete)
            && self.effect != Effect::Writes
        {
            return Err(CatalogError("mutating method must declare writes"));
        }
        let mut seen = HashSet::new();
        if self.expected_error_statuses.len() > 16
            || !self
                .expected_error_statuses
                .iter()
                .all(|status| (400..=499).contains(status) && !matches!(*status, 401 | 403 | 407))
            || !self
                .expected_error_statuses
                .iter()
                .all(|status| seen.insert(*status))
        {
            return Err(CatalogError(
                "expected error statuses must be unique 4xx other than 401/403/407",
            ));
        }
        Ok(())
    }
}

// ── external tool targets ───────────────────────────────────────────────────────────────────

/// An n8n workflow target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct N8nWorkflowTarget {
    /// Always `n8n_workflow`.
    pub kind: N8nWorkflowKind,
    /// The workflow webhook path.
    #[serde(deserialize_with = "webhook_path")]
    pub webhook_path: String,
    /// The workflow node that holds the result.
    #[serde(default = "default_result_node", deserialize_with = "result_node")]
    pub result_node: String,
}

fn default_result_node() -> String {
    "MCP Result".to_owned()
}

/// The fr project answer target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrProjectTarget {
    /// Always `fr_project`.
    pub kind: FrProjectKind,
    /// The default fr project type.
    #[serde(deserialize_with = "project_type")]
    pub project_type: String,
}

/// One fixed fr channel command target.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FrCommandTarget {
    /// Always `fr_command`.
    pub kind: FrCommandKind,
    /// Fixed by the catalog: a tool target never carries free-form channel text.
    pub command: FrCommand,
}

/// A tool's external target, discriminated on `kind`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExternalTarget {
    /// `n8n_workflow`
    N8nWorkflow(N8nWorkflowTarget),
    /// `fr_project`
    FrProject(FrProjectTarget),
    /// `fr_command`
    FrCommand(FrCommandTarget),
}

impl ExternalTarget {
    /// The runtime the target belongs to.
    pub fn kind(&self) -> Runtime {
        match self {
            Self::N8nWorkflow(_) => Runtime::N8nWorkflow,
            Self::FrProject(_) => Runtime::FrProject,
            Self::FrCommand(_) => Runtime::FrCommand,
        }
    }
}

impl Serialize for ExternalTarget {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::N8nWorkflow(value) => value.serialize(serializer),
            Self::FrProject(value) => value.serialize(serializer),
            Self::FrCommand(value) => value.serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for ExternalTarget {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = Value::deserialize(deserializer)?;
        let kind = value.get("kind").and_then(Value::as_str).map(str::to_owned);
        match kind.as_deref() {
            Some("n8n_workflow") => serde_json::from_value(value)
                .map(Self::N8nWorkflow)
                .map_err(D::Error::custom),
            Some("fr_project") => serde_json::from_value(value)
                .map(Self::FrProject)
                .map_err(D::Error::custom),
            Some("fr_command") => serde_json::from_value(value)
                .map(Self::FrCommand)
                .map_err(D::Error::custom),
            _ => Err(D::Error::custom("external target requires a known kind")),
        }
    }
}

// ── tool manifests ─────────────────────────────────────────────────────────────────────────

/// The runner resource limits for one tool.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolLimits")]
pub struct ToolLimits {
    /// Wall clock seconds, 1 to 300.
    pub wall_seconds: u32,
    /// Queue seconds, 1 to 600.
    pub queue_seconds: u32,
    /// Memory in MiB, 1 to 1024.
    pub memory_mi: u32,
    /// CPU millicores, 1 to 1000.
    pub cpu_millicores: u32,
    /// Downstream API calls, 0 to 100.
    pub api_calls: u32,
    /// One output frame, 1 to 1048576 bytes.
    pub frame_bytes: u32,
    /// Aggregate output, 1 to 1048576 bytes.
    pub output_bytes: u32,
}

impl Default for ToolLimits {
    fn default() -> Self {
        Self {
            wall_seconds: 60,
            queue_seconds: 60,
            memory_mi: 256,
            cpu_millicores: 250,
            api_calls: 10,
            frame_bytes: 65_536,
            output_bytes: 262_144,
        }
    }
}

impl ToolLimits {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.frame_bytes > self.output_bytes {
            Err(CatalogError(
                "frame limit exceeds aggregate output allowance",
            ))
        } else {
            Ok(())
        }
    }
}

/// A per-operation rule set attached to a tool or toolkit selection.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationConstraints {
    /// The operation the rules constrain.
    pub operation: ExactReference,
    /// At most 64 rules.
    #[serde(deserialize_with = "vec_max_64")]
    pub rules: Vec<Constraint>,
}

/// A tool contract version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolManifest")]
pub struct ToolManifest {
    /// Always 1.
    pub schema_version: u8,
    /// A UUIDv7 identity.
    pub tool_id: Uuid7,
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// The exact version.
    pub version: PositiveVersion,
    /// The MCP tool name.
    pub public_name: Name,
    /// The agent platform operation this tool implements.
    pub operation: Operation,
    /// Human description, 1 to 4096 characters.
    pub description: String,
    /// The runtime.
    pub runtime: Runtime,
    /// Required for external runtimes, forbidden for `kata_python`.
    pub target: Option<ExternalTarget>,
    /// Package entrypoint, required for `kata_python`.
    pub entrypoint: Option<String>,
    /// Input JSON Schema.
    pub input_schema: Map<String, Value>,
    /// Result JSON Schema.
    pub result_schema: Map<String, Value>,
    /// Bound-context JSON Schema.
    pub context_schema: Map<String, Value>,
    /// SHA-256 of the canonical package.
    pub package_sha256: Digest,
    /// The approved runner image, required for `kata_python`.
    pub runner_image_digest: Option<ImageDigest>,
    /// Upstream operations this tool may call.
    pub allowed_operations: Vec<ExactReference>,
    /// Per-operation rules, each referring to an allowed operation.
    pub operation_constraints: Vec<OperationConstraints>,
    /// Runner limits.
    pub limits: ToolLimits,
    /// Read or write.
    pub effect: Effect,
}

impl ToolManifest {
    fn validate(&self) -> Result<(), CatalogError> {
        if self.runtime == Runtime::KataPython {
            if self.target.is_some() {
                return Err(CatalogError("kata_python tools take no external target"));
            }
            if self.entrypoint.is_none() || self.runner_image_digest.is_none() {
                return Err(CatalogError(
                    "kata_python tools require entrypoint and runner_image_digest",
                ));
            }
        } else {
            match &self.target {
                Some(target) if target.kind() == self.runtime => {}
                _ => {
                    return Err(CatalogError(
                        "external tools require a target whose kind matches the runtime",
                    ));
                }
            }
            if self.entrypoint.is_some() || self.runner_image_digest.is_some() {
                return Err(CatalogError(
                    "external tools take no entrypoint or runner image",
                ));
            }
        }
        let allowed: HashSet<(&str, u32)> = self
            .allowed_operations
            .iter()
            .map(|reference| (reference.id.as_str(), reference.version.get()))
            .collect();
        let constrained: Vec<(&str, u32)> = self
            .operation_constraints
            .iter()
            .map(|entry| (entry.operation.id.as_str(), entry.operation.version.get()))
            .collect();
        let constrained_set: HashSet<(&str, u32)> = constrained.iter().copied().collect();
        if allowed.len() != self.allowed_operations.len()
            || constrained_set.len() != constrained.len()
        {
            return Err(CatalogError("duplicate operation reference"));
        }
        if self
            .allowed_operations
            .iter()
            .map(|reference| reference.id.as_str())
            .collect::<HashSet<_>>()
            .len()
            != self.allowed_operations.len()
        {
            return Err(CatalogError(
                "protocol v1 selects one exact version per operation identity",
            ));
        }
        if !constrained_set.is_subset(&allowed) {
            return Err(CatalogError(
                "constraints reference an undeclared operation",
            ));
        }
        Ok(())
    }
}

/// Who created or changed a version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attribution {
    /// The acting subject, 1 to 256 characters.
    #[serde(deserialize_with = "text_1_256")]
    pub subject: String,
    /// The licence that authorized the change, when any.
    #[serde(default)]
    pub license_id: Option<AuthorityId>,
}

/// A tool version as stored and served.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VersionDescriptor {
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// A UUIDv7 identity.
    pub tool_id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The identity's revision at this version.
    pub revision: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
    /// The manifest.
    pub manifest: ToolManifest,
    /// Who created it.
    pub created_by: Attribution,
    /// The version it was copied from, when any.
    #[serde(default)]
    pub source: Option<ExactReference>,
}

// ── wire models: strict field shapes, then the model validators ─────────────────────────────

mod wire {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct NumericBounds {
        pub kind: NumericBoundsKind,
        pub argument: Pointer,
        pub minimum: f64,
        pub maximum: f64,
    }

    impl TryFrom<NumericBounds> for super::NumericBounds {
        type Error = CatalogError;

        fn try_from(wire: NumericBounds) -> Result<Self, Self::Error> {
            let model = Self {
                kind: wire.kind,
                argument: wire.argument,
                minimum: wire.minimum,
                maximum: wire.maximum,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ArgumentMapping {
        pub location: MappingLocation,
        #[serde(deserialize_with = "text_0_512")]
        pub target: String,
        pub value: ArgumentValue,
        #[serde(default)]
        pub optional: bool,
    }

    impl TryFrom<ArgumentMapping> for super::ArgumentMapping {
        type Error = CatalogError;

        fn try_from(wire: ArgumentMapping) -> Result<Self, Self::Error> {
            let model = Self {
                location: wire.location,
                target: wire.target,
                value: wire.value,
                optional: wire.optional,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ServiceManifest {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub service_id: Uuid7,
        pub version: PositiveVersion,
        pub service_key: Name,
        pub destination_alias: Name,
        #[serde(default)]
        pub license_app_key: Option<AppKey>,
        pub auth_adapter: AuthAdapter,
        pub credential_profile_key: Name,
        #[serde(deserialize_with = "bytes_10m")]
        pub max_request_bytes: u32,
        #[serde(deserialize_with = "bytes_10m")]
        pub max_response_bytes: u32,
    }

    impl TryFrom<ServiceManifest> for super::ServiceManifest {
        type Error = CatalogError;

        fn try_from(wire: ServiceManifest) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                service_id: wire.service_id,
                version: wire.version,
                service_key: wire.service_key,
                destination_alias: wire.destination_alias,
                license_app_key: wire.license_app_key,
                auth_adapter: wire.auth_adapter,
                credential_profile_key: wire.credential_profile_key,
                max_request_bytes: wire.max_request_bytes,
                max_response_bytes: wire.max_response_bytes,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct OperationManifest {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub operation_id: Uuid7,
        pub version: PositiveVersion,
        pub service: ExactReference,
        pub method: Method,
        #[serde(deserialize_with = "text_1_1024")]
        pub path_template: String,
        #[serde(default)]
        pub query_fields: Vec<Name>,
        #[serde(default)]
        pub header_fields: Vec<Name>,
        #[serde(default)]
        pub mappings: Vec<super::ArgumentMapping>,
        #[serde(default)]
        pub scope_rules: Vec<Constraint>,
        pub input_schema: Map<String, Value>,
        pub output_schema: Map<String, Value>,
        #[serde(deserialize_with = "vec_min_1")]
        pub response_projection: Vec<Pointer>,
        #[serde(default)]
        pub redact_fields: Vec<Pointer>,
        pub effect: Effect,
        #[serde(default)]
        pub idempotency: Idempotency,
        #[serde(default, deserialize_with = "retries_0_3")]
        pub max_retries: u32,
        #[serde(deserialize_with = "timeout_1_300")]
        pub timeout_seconds: u32,
        #[serde(default)]
        pub expected_error_statuses: Vec<u16>,
        #[serde(default)]
        pub empty_response: bool,
        #[serde(deserialize_with = "pagination_1_1000")]
        pub pagination_limit: u32,
        #[serde(deserialize_with = "bytes_10m")]
        pub max_response_bytes: u32,
    }

    impl TryFrom<OperationManifest> for super::OperationManifest {
        type Error = CatalogError;

        fn try_from(wire: OperationManifest) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                operation_id: wire.operation_id,
                version: wire.version,
                service: wire.service,
                method: wire.method,
                path_template: wire.path_template,
                query_fields: wire.query_fields,
                header_fields: wire.header_fields,
                mappings: wire.mappings,
                scope_rules: wire.scope_rules,
                input_schema: wire.input_schema,
                output_schema: wire.output_schema,
                response_projection: wire.response_projection,
                redact_fields: wire.redact_fields,
                effect: wire.effect,
                idempotency: wire.idempotency,
                max_retries: wire.max_retries,
                timeout_seconds: wire.timeout_seconds,
                expected_error_statuses: wire.expected_error_statuses,
                empty_response: wire.empty_response,
                pagination_limit: wire.pagination_limit,
                max_response_bytes: wire.max_response_bytes,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolLimits {
        #[serde(default = "default_wall_seconds", deserialize_with = "wall_1_300")]
        pub wall_seconds: u32,
        #[serde(default = "default_queue_seconds", deserialize_with = "queue_1_600")]
        pub queue_seconds: u32,
        #[serde(default = "default_memory_mi", deserialize_with = "memory_1_1024")]
        pub memory_mi: u32,
        #[serde(default = "default_cpu_millicores", deserialize_with = "cpu_1_1000")]
        pub cpu_millicores: u32,
        #[serde(default = "default_api_calls", deserialize_with = "api_calls_0_100")]
        pub api_calls: u32,
        #[serde(default = "default_frame_bytes", deserialize_with = "frame_1_1048576")]
        pub frame_bytes: u32,
        #[serde(
            default = "default_output_bytes",
            deserialize_with = "output_1_1048576"
        )]
        pub output_bytes: u32,
    }

    impl TryFrom<ToolLimits> for super::ToolLimits {
        type Error = CatalogError;

        fn try_from(wire: ToolLimits) -> Result<Self, Self::Error> {
            let model = Self {
                wall_seconds: wire.wall_seconds,
                queue_seconds: wire.queue_seconds,
                memory_mi: wire.memory_mi,
                cpu_millicores: wire.cpu_millicores,
                api_calls: wire.api_calls,
                frame_bytes: wire.frame_bytes,
                output_bytes: wire.output_bytes,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolManifest {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub tool_id: Uuid7,
        pub tenant_id: AuthorityId,
        pub version: PositiveVersion,
        pub public_name: Name,
        pub operation: Operation,
        #[serde(deserialize_with = "text_1_4096")]
        pub description: String,
        #[serde(default)]
        pub runtime: Runtime,
        #[serde(default)]
        pub target: Option<ExternalTarget>,
        #[serde(default, deserialize_with = "optional_text_256")]
        pub entrypoint: Option<String>,
        pub input_schema: Map<String, Value>,
        pub result_schema: Map<String, Value>,
        pub context_schema: Map<String, Value>,
        pub package_sha256: Digest,
        #[serde(default)]
        pub runner_image_digest: Option<ImageDigest>,
        #[serde(default)]
        pub allowed_operations: Vec<ExactReference>,
        #[serde(default)]
        pub operation_constraints: Vec<OperationConstraints>,
        #[serde(default)]
        pub limits: super::ToolLimits,
        pub effect: Effect,
    }

    impl TryFrom<ToolManifest> for super::ToolManifest {
        type Error = CatalogError;

        fn try_from(wire: ToolManifest) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                tool_id: wire.tool_id,
                tenant_id: wire.tenant_id,
                version: wire.version,
                public_name: wire.public_name,
                operation: wire.operation,
                description: wire.description,
                runtime: wire.runtime,
                target: wire.target,
                entrypoint: wire.entrypoint,
                input_schema: wire.input_schema,
                result_schema: wire.result_schema,
                context_schema: wire.context_schema,
                package_sha256: wire.package_sha256,
                runner_image_digest: wire.runner_image_digest,
                allowed_operations: wire.allowed_operations,
                operation_constraints: wire.operation_constraints,
                limits: wire.limits,
                effect: wire.effect,
            };
            model.validate()?;
            Ok(model)
        }
    }
}

fn default_wall_seconds() -> u32 {
    60
}

fn default_queue_seconds() -> u32 {
    60
}

fn default_memory_mi() -> u32 {
    256
}

fn default_cpu_millicores() -> u32 {
    250
}

fn default_api_calls() -> u32 {
    10
}

fn default_frame_bytes() -> u32 {
    65_536
}

fn default_output_bytes() -> u32 {
    262_144
}
