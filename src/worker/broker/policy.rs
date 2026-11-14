//! Concrete invocation policy: conjunctions, typed JSON equality and closed mappings.
//!
//! Port of the reference `src/broker/policy.py`. Three pure-ish entry points sit on the same
//! manifest:
//!
//! * [`enforce`] re-enforces every scope rule on the concrete call. Equality is *typed* — it
//!   compares [`crate::execution::canonical_json`] text, so `true` never equals `1` and `1.0`
//!   never equals `1`, exactly like the reference's `encoded(...)`.
//! * [`transport`] builds the request from **declared** mappings only: no runner-supplied
//!   header, query parameter or path segment can reach the upstream. Missing required inputs
//!   deny; missing optional inputs are omitted, never sent as `null`.
//! * [`project`] returns declared response pointers, then redacts declared fields.
//!
//! A pointer that misses is the reference's `ValueError` and is carried as
//! [`PolicyError::MissingPointer`]; a policy refusal is [`PolicyError::Denied`].

use std::cmp::Ordering;
use std::collections::BTreeMap;

use async_trait::async_trait;
use serde_json::{Map, Value};
use thiserror::Error;

use crate::catalog::models::{
    ArgumentValue, Constraint, ExactReference, MappingLocation, OperationManifest, SourceKind,
};
use crate::catalog::package::canonical_path;
use crate::execution::{canonical_json, python_float_repr};
use crate::toolkits::constraints::pointer;
use crate::worker::creds::quote;

/// Headers a mapping may never set (`policy.py:84-95`): framing, routing and credentials.
///
/// The manifest validator already refuses these names in `header_fields`, so this is the
/// reference's second line of defence rather than a reachable state for a valid manifest.
const FORBIDDEN_HEADERS: [&str; 10] = [
    "authorization",
    "x-tenant-id",
    "host",
    "cookie",
    "connection",
    "content-length",
    "transfer-encoding",
    "proxy-authorization",
    "idempotency-key",
    "x-idempotency-key",
];

/// A policy refusal (the reference's `ExecutionDeniedError`) or a missing pointer (its
/// `ValueError`). Neither carries request content.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum PolicyError {
    /// The call is refused: a rule failed, a mapped value is unsafe, a projection is absent.
    #[error("policy denied")]
    Denied,
    /// A JSON Pointer into the arguments, the context or an ownership result missed.
    #[error("required pointer is missing")]
    MissingPointer,
    /// An ownership read failed (transport or denial surfaced by the host).
    #[error("ownership read failed: {0}")]
    Ownership(String),
}

/// The host-side read an `ownership_read` rule needs (`policy.py:32-34`).
///
/// The implementation performs the referenced read itself; the rule's `argument` is used to
/// select the record from `arguments`. A denial or a transport failure is the implementor's
/// [`PolicyError`] and aborts the call.
#[async_trait]
pub trait OwnershipRead: Send + Sync {
    /// Read the referenced operation for this call and return its projected result.
    async fn read(
        &self,
        reference: &ExactReference,
        arguments: &Map<String, Value>,
    ) -> Result<Value, PolicyError>;
}

fn at<'value>(root: &'value Value, path: &str) -> Result<&'value Value, PolicyError> {
    pointer(root, path).map_err(|_| PolicyError::MissingPointer)
}

/// Whether a JSON number is inside the inclusive bounds, exactly as Python compares an `int`
/// or `float` to a float: an integer beyond 2^53 is compared as an integer and never rounded
/// through `f64` (which would let `9007199254740993` pass a `9007199254740992.0` ceiling).
fn within_bounds(number: &serde_json::Number, minimum: f64, maximum: f64) -> bool {
    if !minimum.is_finite() || !maximum.is_finite() {
        return number
            .as_f64()
            .is_some_and(|value| minimum <= value && value <= maximum);
    }
    match integer_part(number) {
        Some(integer) => {
            compare_integer(integer, minimum) != Ordering::Less
                && compare_integer(integer, maximum) != Ordering::Greater
        }
        None => number
            .as_f64()
            .is_some_and(|value| minimum <= value && value <= maximum),
    }
}

fn integer_part(number: &serde_json::Number) -> Option<i128> {
    if let Some(value) = number.as_i64() {
        Some(i128::from(value))
    } else {
        number.as_u64().map(i128::from)
    }
}

/// Exact `int` vs finite `float` ordering.
fn compare_integer(integer: i128, bound: f64) -> Ordering {
    if bound.trunc() == bound {
        // An integral f64 converts to i128 exactly; a bound beyond i128's range saturates,
        // which still orders correctly against a 64-bit value.
        return integer.cmp(&(bound as i128));
    }
    // A non-integral f64 is below 2^52 in magnitude.
    if integer.unsigned_abs() < 1u128 << 53 {
        (integer as f64)
            .partial_cmp(&bound)
            .unwrap_or(Ordering::Equal)
    } else if integer > 0 {
        Ordering::Greater
    } else {
        Ordering::Less
    }
}

/// Enforce every rule as a conjunction (`policy.py:20-38`).
pub async fn enforce(
    rules: &[Constraint],
    arguments: &Map<String, Value>,
    context: &Map<String, Value>,
    ownership: &dyn OwnershipRead,
) -> Result<(), PolicyError> {
    let arguments_value = Value::Object(arguments.clone());
    let context_value = Value::Object(context.clone());
    for rule in rules {
        let valid = match rule {
            Constraint::ContextEquality(rule) => {
                let value = at(&arguments_value, rule.argument.as_str())?;
                canonical_json(value) == canonical_json(at(&context_value, rule.context.as_str())?)
            }
            Constraint::SetMembership(rule) => {
                let value = at(&arguments_value, rule.argument.as_str())?;
                let encoded = canonical_json(value);
                rule.values
                    .iter()
                    .any(|candidate| canonical_json(candidate) == encoded)
            }
            Constraint::NumericBounds(rule) => {
                match at(&arguments_value, rule.argument.as_str())? {
                    Value::Number(number) => within_bounds(number, rule.minimum, rule.maximum),
                    _ => false,
                }
            }
            Constraint::RelativePath(rule) => {
                let value = at(&arguments_value, rule.argument.as_str())?;
                match value.as_str().map(canonical_path) {
                    Some(Ok(path)) => {
                        path == rule.root || path.starts_with(&format!("{}/", rule.root))
                    }
                    _ => false,
                }
            }
            Constraint::OwnershipRead(rule) => {
                let result = ownership.read(&rule.operation, arguments).await?;
                canonical_json(at(&result, rule.result.as_str())?)
                    == canonical_json(at(&context_value, rule.context.as_str())?)
            }
        };
        if !valid {
            return Err(PolicyError::Denied);
        }
    }
    Ok(())
}

/// Replace the value at `path` in a JSON object (`policy.py:41-51`).
///
/// An empty path replaces the whole body; the body must then be a JSON object because this
/// entry point returns a map (the transport builder uses the value-shaped walk below and can
/// carry a whole scalar or array body).
pub fn set_pointer(
    target: Map<String, Value>,
    path: &str,
    value: Value,
) -> Result<Map<String, Value>, PolicyError> {
    match set_value_pointer(Value::Object(target), path, value)? {
        Value::Object(map) => Ok(map),
        _ => Err(PolicyError::Denied),
    }
}

/// The value-shaped walk behind [`set_pointer`] and the body builder: `~1` then `~0` unescape,
/// an empty path replaces the whole value, and an intermediate that is not an object denies.
fn set_value_pointer(mut target: Value, path: &str, value: Value) -> Result<Value, PolicyError> {
    if path.is_empty() {
        return Ok(value);
    }
    if !path.starts_with('/') {
        return Err(PolicyError::Denied);
    }
    let parts: Vec<String> = path[1..]
        .split('/')
        .map(|part| part.replace("~1", "/").replace("~0", "~"))
        .collect();
    let Some((last, parents)) = parts.split_last() else {
        // `path[1..].split('/')` always yields at least one element.
        return Err(PolicyError::Denied);
    };
    let mut current = &mut target;
    for part in parents {
        let Value::Object(map) = current else {
            return Err(PolicyError::Denied);
        };
        current = map
            .entry(part.clone())
            .or_insert_with(|| Value::Object(Map::new()));
    }
    let Value::Object(map) = current else {
        return Err(PolicyError::Denied);
    };
    map.insert(last.clone(), value);
    Ok(target)
}

/// A request built from the operation's declared mappings only (`policy.py:54-100`).
#[derive(Debug, Clone, PartialEq)]
pub struct TransportRequest {
    /// The substituted path template.
    pub path: String,
    /// Declared query parameters, already rendered as text.
    pub query: BTreeMap<String, String>,
    /// Declared headers, already rendered as text.
    pub headers: BTreeMap<String, String>,
    /// The JSON body, when any body mapping applied.
    pub body: Option<Value>,
}

/// Render one scalar exactly as Python's `str(value)` (`True`/`False`, `repr(float)`).
fn scalar_text(value: &Value) -> Result<String, PolicyError> {
    match value {
        Value::String(text) => Ok(text.clone()),
        Value::Bool(true) => Ok("True".to_owned()),
        Value::Bool(false) => Ok("False".to_owned()),
        Value::Number(number) => {
            if let Some(integer) = number.as_i64() {
                Ok(integer.to_string())
            } else if let Some(integer) = number.as_u64() {
                Ok(integer.to_string())
            } else if let Some(float) = number.as_f64() {
                Ok(python_float_repr(float))
            } else {
                Err(PolicyError::Denied)
            }
        }
        _ => Err(PolicyError::Denied),
    }
}

/// Build the upstream request (`policy.py:54-100`).
pub fn transport(
    operation: &OperationManifest,
    arguments: &Map<String, Value>,
    context: &Map<String, Value>,
) -> Result<TransportRequest, PolicyError> {
    let arguments_value = Value::Object(arguments.clone());
    let context_value = Value::Object(context.clone());
    let mut path = operation.path_template.clone();
    let mut query = BTreeMap::new();
    let mut headers = BTreeMap::new();
    let mut body: Option<Value> = None;

    for mapping in &operation.mappings {
        let value = match &mapping.value {
            ArgumentValue::Literal(literal) => literal.value.clone(),
            ArgumentValue::Source(source) => {
                let root = match source.source {
                    SourceKind::Input => &arguments_value,
                    SourceKind::Context => &context_value,
                };
                match pointer(root, source.pointer.as_str()) {
                    Ok(value) => value.clone(),
                    // An absent optional input is omitted, never sent as null.
                    Err(_) if mapping.optional => continue,
                    Err(_) => return Err(PolicyError::MissingPointer),
                }
            }
        };
        if mapping.location == MappingLocation::Body {
            let target = mapping.target.as_str();
            body = Some(match body {
                None => set_value_pointer(Value::Object(Map::new()), target, value)?,
                Some(current) => set_value_pointer(current, target, value)?,
            });
            continue;
        }
        let text = scalar_text(&value)?;
        if text
            .chars()
            .any(|character| (character as u32) < 32 || character as u32 == 127)
        {
            return Err(PolicyError::Denied);
        }
        match mapping.location {
            MappingLocation::Path => {
                if text.is_empty()
                    || text == "."
                    || text == ".."
                    || text
                        .chars()
                        .any(|character| matches!(character, '/' | '\\' | '%' | '?' | '#'))
                {
                    return Err(PolicyError::Denied);
                }
                path = path.replace(&format!("{{{}}}", mapping.target), &quote(&text));
            }
            MappingLocation::Query => {
                query.insert(mapping.target.clone(), text);
            }
            MappingLocation::Header => {
                let name = mapping.target.replace('_', "-");
                if FORBIDDEN_HEADERS.contains(&name.to_ascii_lowercase().as_str()) {
                    return Err(PolicyError::Denied);
                }
                headers.insert(name, text);
            }
            MappingLocation::Body => unreachable!("handled above"),
        }
    }
    // A template variable no mapping covered must never reach the wire.
    if path.contains('{') || path.contains('}') {
        return Err(PolicyError::Denied);
    }
    Ok(TransportRequest {
        path,
        query,
        headers,
        body,
    })
}

/// Mutable walk with the same pointer grammar as [`crate::toolkits::constraints::pointer`].
fn pointer_mut<'value>(value: &'value mut Value, path: &str) -> Option<&'value mut Value> {
    let mut current = value;
    for component in path.split('/').skip(1) {
        let key = component.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Array(items) => {
                let index: i64 = key.parse().ok()?;
                let index = if index < 0 {
                    index.checked_add(items.len() as i64)?
                } else {
                    index
                };
                items.get_mut(usize::try_from(index).ok()?)?
            }
            Value::Object(map) => map.get_mut(&key)?,
            _ => return None,
        };
    }
    Some(current)
}

/// Project declared result pointers and redact declared fields (`policy.py:103-120`).
///
/// A missing projection pointer denies. A redaction whose parent or target is absent is a
/// no-op, exactly as the reference; an **empty** redaction pointer denies.
pub fn project(operation: &OperationManifest, value: &Value) -> Result<Value, PolicyError> {
    let mut result = Value::Object(Map::new());
    for path in &operation.response_projection {
        let picked = at(value, path.as_str())?.clone();
        result = set_value_pointer(result, path.as_str(), picked)?;
    }
    for path in &operation.redact_fields {
        if path.as_str().is_empty() {
            return Err(PolicyError::Denied);
        }
        let (parent, tail) = match path.as_str().rsplit_once('/') {
            Some((parent, tail)) => (parent, tail),
            None => ("", path.as_str()),
        };
        let key = tail.replace("~1", "/").replace("~0", "~");
        let Some(container) = pointer_mut(&mut result, parent) else {
            continue;
        };
        match container {
            Value::Array(items) => {
                let Ok(index) = key.parse::<i64>() else {
                    continue;
                };
                let index = if index < 0 {
                    index.saturating_add(items.len() as i64)
                } else {
                    index
                };
                let Ok(index) = usize::try_from(index) else {
                    continue;
                };
                if let Some(slot) = items.get_mut(index) {
                    *slot = Value::Null;
                }
            }
            Value::Object(map) => {
                map.remove(&key);
            }
            _ => {}
        }
    }
    Ok(result)
}
