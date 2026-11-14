//! Instance validation against the closed Draft 2020-12 subset.
//!
//! Ported from the reference `src/catalog/validation.py` (`validate_instance`,
//! `InputValidationError`, `_pointer`, `_problems`, `MAX_PROBLEMS = 20`). The schema is
//! validated first with [`validate_schema`], so every keyword reached by this walk is one the
//! closed subset allows; the walk itself accepts exactly that subset and nothing more.
//!
//! Draft 2020-12 semantics that are easy to get wrong and are deliberate here: `$ref` is a
//! normal applicator, so its target and the schema object's sibling keywords both apply; an
//! `integer` is any number with no fractional part, `1.0` included; `enum`/`const` use JSON
//! equality, where `1` equals `1.0` but never `true`; `items` covers only the elements after
//! `prefixItems`; `minLength`/`maxLength` count characters, not bytes; and a failing
//! `additionalProperties: false` or `items: false` is one problem at the container, not one
//! per offending member, exactly as jsonschema reports them.
//!
//! A problem carries only a JSON pointer and the keyword that refused it. Instance values and
//! schema text never appear in one: a refused bound context may hold a secret.

use std::cmp::Ordering;
use std::fmt;

use serde_json::{Number, Value};

use crate::catalog::error::CatalogError;
use crate::catalog::formats;
use crate::catalog::validation::{SchemaLimits, bounded_json, validate_schema};

/// The most problems a refusal reports, matching the reference's `MAX_PROBLEMS`.
pub const MAX_PROBLEMS: usize = 20;

/// One refusal: the JSON pointer to the failing value and the keyword that refused it. The
/// pointed-to value itself is never included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Problem {
    pub path: String,
    pub rule: String,
}

/// The instance does not match the schema. Its message is exactly the reference's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputValidationError {
    pub problems: Vec<Problem>,
}

impl fmt::Display for InputValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("instance does not match declared schema")
    }
}

impl std::error::Error for InputValidationError {}

/// Why an instance could not be validated. The three cases are deliberately distinguishable:
/// a mismatch is the caller's data being wrong, a work refusal is a resource bound, and a
/// bounds refusal is a schema-side (or instance-shape) refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InstanceError {
    /// The instance does not match the declared schema.
    Invalid(InputValidationError),
    /// `schema work * instance work` exceeded `max_validation_work`.
    Work(&'static str),
    /// The schema or the instance violates a configured bound.
    Bounds(CatalogError),
}

impl fmt::Display for InstanceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Invalid(error) => fmt::Display::fmt(error, formatter),
            Self::Work(message) => formatter.write_str(message),
            Self::Bounds(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for InstanceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Invalid(error) => Some(error),
            Self::Bounds(error) => Some(error),
            Self::Work(_) => None,
        }
    }
}

impl From<CatalogError> for InstanceError {
    fn from(error: CatalogError) -> Self {
        Self::Bounds(error)
    }
}

/// Validate `instance` against `schema` under the closed subset, returning the charged work.
///
/// The order is the reference's: validate the schema (schema work), bound the instance
/// (instance work), refuse when the product exceeds `max_validation_work`, then walk. The
/// returned value is that product, the quantity charged against the work limit.
pub fn validate_instance(
    schema: &Value,
    instance: &Value,
    limits: &SchemaLimits,
) -> Result<usize, InstanceError> {
    let schema_work = validate_schema(schema, limits)?;
    let instance_work = bounded_json(
        instance,
        limits.max_instance_bytes,
        limits.max_instance_nodes,
        limits.max_instance_depth,
    )?;
    let work = schema_work.saturating_mul(instance_work);
    if work > limits.max_validation_work {
        return Err(InstanceError::Work("validation work limit exceeded"));
    }
    let mut validator = Validator {
        root: schema,
        problems: Vec::new(),
        stopped: false,
    };
    let mut path = String::new();
    validator.check(schema, instance, &mut path, true);
    if validator.problems.is_empty() {
        Ok(work)
    } else {
        Err(InstanceError::Invalid(InputValidationError {
            problems: validator.problems,
        }))
    }
}

struct Validator<'a> {
    root: &'a Value,
    problems: Vec<Problem>,
    /// Set once [`MAX_PROBLEMS`] are collected; every later visit is a no-op.
    stopped: bool,
}

impl Validator<'_> {
    /// Whether `instance` matches `schema`, without recording anything.
    fn probe(&mut self, schema: &Value, instance: &Value) -> bool {
        let mut path = String::new();
        self.check(schema, instance, &mut path, false)
    }

    /// Validate `instance` at `path`, returning whether it matched. When `report` is set,
    /// refusals are appended to [`Validator::problems`], at most [`MAX_PROBLEMS`] of them.
    fn check(&mut self, schema: &Value, instance: &Value, path: &mut String, report: bool) -> bool {
        if self.stopped {
            return true;
        }
        let Value::Object(map) = schema else {
            return match schema {
                Value::Bool(true) => true,
                Value::Bool(false) => {
                    // A boolean schema has no keyword to name; jsonschema reports a `None`
                    // validator here, and `false` is the honest rule for this port.
                    if report {
                        self.record(path, "false");
                    }
                    false
                }
                // Unreachable: `validate_schema` admits only objects and booleans.
                _ => true,
            };
        };
        let mut valid = true;
        for (keyword, value) in map {
            match keyword.as_str() {
                // Draft 2020-12: `$ref` is an applicator like any other, so the target and
                // this object's sibling keywords both apply.
                "$ref" => {
                    if let Some(target) = resolve(self.root, value) {
                        valid &= self.check(target, instance, path, report);
                    }
                }
                "type" => {
                    if !type_matches(value, instance) {
                        valid = false;
                        if report {
                            self.record(path, "type");
                        }
                    }
                }
                "properties" => {
                    if let (Value::Object(object), Value::Object(properties)) = (instance, value) {
                        for (name, subschema) in properties {
                            if let Some(child) = object.get(name) {
                                let mark = path.len();
                                push_part(path, name);
                                valid &= self.check(subschema, child, path, report);
                                path.truncate(mark);
                            }
                        }
                    }
                }
                "required" => {
                    if let Value::Object(object) = instance
                        && let Some(names) = value.as_array()
                    {
                        for name in names {
                            if let Some(name) = name.as_str()
                                && !object.contains_key(name)
                            {
                                valid = false;
                                if report {
                                    let mark = path.len();
                                    push_part(path, name);
                                    self.record(path, "required");
                                    path.truncate(mark);
                                }
                            }
                        }
                    }
                }
                "additionalProperties" => {
                    if let Value::Object(object) = instance {
                        for (name, child) in object {
                            let declared = map
                                .get("properties")
                                .and_then(Value::as_object)
                                .is_some_and(|properties| properties.contains_key(name));
                            if declared {
                                continue;
                            }
                            match value {
                                // jsonschema reports one problem at the object, however many
                                // properties are unexpected.
                                Value::Bool(false) => {
                                    valid = false;
                                    if report {
                                        self.record(path, "additionalProperties");
                                    }
                                    break;
                                }
                                Value::Bool(true) => break,
                                subschema => {
                                    let mark = path.len();
                                    push_part(path, name);
                                    valid &= self.check(subschema, child, path, report);
                                    path.truncate(mark);
                                }
                            }
                        }
                    }
                }
                "items" => {
                    if let Value::Array(items) = instance {
                        let start = map
                            .get("prefixItems")
                            .and_then(Value::as_array)
                            .map_or(0, Vec::len);
                        if items.len() > start {
                            match value {
                                Value::Bool(true) => {}
                                // One problem at the array, not one per extra element.
                                Value::Bool(false) => {
                                    valid = false;
                                    if report {
                                        self.record(path, "items");
                                    }
                                }
                                subschema => {
                                    for (index, child) in items.iter().enumerate().skip(start) {
                                        let segment = index.to_string();
                                        let mark = path.len();
                                        push_part(path, &segment);
                                        valid &= self.check(subschema, child, path, report);
                                        path.truncate(mark);
                                    }
                                }
                            }
                        }
                    }
                }
                "prefixItems" => {
                    if let (Value::Array(items), Value::Array(subschemas)) = (instance, value) {
                        for (index, (child, subschema)) in items.iter().zip(subschemas).enumerate()
                        {
                            let segment = index.to_string();
                            let mark = path.len();
                            push_part(path, &segment);
                            valid &= self.check(subschema, child, path, report);
                            path.truncate(mark);
                        }
                    }
                }
                "minItems" => {
                    if let Value::Array(items) = instance
                        && items.len() < count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "minItems");
                        }
                    }
                }
                "maxItems" => {
                    if let Value::Array(items) = instance
                        && items.len() > count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "maxItems");
                        }
                    }
                }
                "minProperties" => {
                    if let Value::Object(object) = instance
                        && object.len() < count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "minProperties");
                        }
                    }
                }
                "maxProperties" => {
                    if let Value::Object(object) = instance
                        && object.len() > count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "maxProperties");
                        }
                    }
                }
                "minLength" => {
                    if let Value::String(text) = instance
                        && text.chars().count() < count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "minLength");
                        }
                    }
                }
                "maxLength" => {
                    if let Value::String(text) = instance
                        && text.chars().count() > count_bound(value)
                    {
                        valid = false;
                        if report {
                            self.record(path, "maxLength");
                        }
                    }
                }
                "minimum" => {
                    if refused_below(instance, value, &[Ordering::Less]) {
                        valid = false;
                        if report {
                            self.record(path, "minimum");
                        }
                    }
                }
                "maximum" => {
                    if refused_below(instance, value, &[Ordering::Greater]) {
                        valid = false;
                        if report {
                            self.record(path, "maximum");
                        }
                    }
                }
                "exclusiveMinimum" => {
                    if refused_below(instance, value, &[Ordering::Less, Ordering::Equal]) {
                        valid = false;
                        if report {
                            self.record(path, "exclusiveMinimum");
                        }
                    }
                }
                "exclusiveMaximum" => {
                    if refused_below(instance, value, &[Ordering::Greater, Ordering::Equal]) {
                        valid = false;
                        if report {
                            self.record(path, "exclusiveMaximum");
                        }
                    }
                }
                "enum" => {
                    if let Some(choices) = value.as_array()
                        && !choices.iter().any(|choice| json_equal(choice, instance))
                    {
                        valid = false;
                        if report {
                            self.record(path, "enum");
                        }
                    }
                }
                "const" => {
                    if !json_equal(value, instance) {
                        valid = false;
                        if report {
                            self.record(path, "const");
                        }
                    }
                }
                "allOf" => {
                    if let Some(branches) = value.as_array() {
                        for branch in branches {
                            valid &= self.check(branch, instance, path, report);
                        }
                    }
                }
                "anyOf" => {
                    let matched = value.as_array().is_some_and(|branches| {
                        branches.iter().any(|branch| self.probe(branch, instance))
                    });
                    if !matched {
                        valid = false;
                        if report {
                            self.record(path, "anyOf");
                        }
                    }
                }
                "oneOf" => {
                    let matches = value.as_array().map_or(0, |branches| {
                        branches
                            .iter()
                            .filter(|branch| self.probe(branch, instance))
                            .count()
                    });
                    if matches != 1 {
                        valid = false;
                        if report {
                            self.record(path, "oneOf");
                        }
                    }
                }
                "not" => {
                    if self.probe(value, instance) {
                        valid = false;
                        if report {
                            self.record(path, "not");
                        }
                    }
                }
                "format" => {
                    if let Value::String(text) = instance
                        && let Some(name) = value.as_str()
                        && formats::check(name, text) == Some(false)
                    {
                        valid = false;
                        if report {
                            self.record(path, "format");
                        }
                    }
                }
                // `$schema`, `$defs`, `title`, `description` and `default` assert nothing.
                _ => {}
            }
        }
        valid
    }

    fn record(&mut self, path: &str, rule: &'static str) {
        if self.problems.len() >= MAX_PROBLEMS {
            self.stopped = true;
            return;
        }
        self.problems.push(Problem {
            path: path.to_owned(),
            rule: rule.to_owned(),
        });
        self.stopped = self.problems.len() >= MAX_PROBLEMS;
    }
}

/// `#/$defs/...` pointer resolution with JSON-pointer unescaping. `validate_schema` already
/// proved the reference resolves and is not recursive, so `None` is unreachable in practice.
fn resolve<'a>(root: &'a Value, reference: &Value) -> Option<&'a Value> {
    let mut target = root;
    for part in reference.as_str()?.strip_prefix("#/")?.split('/') {
        let key = part.replace("~1", "/").replace("~0", "~");
        target = target.as_object()?.get(&key)?;
    }
    Some(target)
}

/// Append one JSON-pointer segment, escaping `~` and `/`.
fn push_part(path: &mut String, part: &str) {
    path.push('/');
    for character in part.chars() {
        match character {
            '~' => path.push_str("~0"),
            '/' => path.push_str("~1"),
            other => path.push(other),
        }
    }
}

fn type_matches(kind: &Value, instance: &Value) -> bool {
    match kind {
        Value::String(name) => type_name_matches(name, instance),
        Value::Array(names) => names.iter().any(|name| {
            name.as_str()
                .is_some_and(|name| type_name_matches(name, instance))
        }),
        // Unreachable: `validate_schema` admits only the two forms above.
        _ => false,
    }
}

fn type_name_matches(name: &str, instance: &Value) -> bool {
    match name {
        "null" => instance.is_null(),
        "boolean" => instance.is_boolean(),
        "object" => instance.is_object(),
        "array" => instance.is_array(),
        "string" => instance.is_string(),
        "number" => instance.is_number(),
        // JSON Schema's integer: a number with no fractional part, `1.0` included.
        "integer" => match instance {
            Value::Number(number) => is_integer(number),
            _ => false,
        },
        _ => false,
    }
}

fn is_integer(number: &Number) -> bool {
    if number.as_u64().is_some() || number.as_i64().is_some() {
        return true;
    }
    number
        .as_f64()
        .is_some_and(|float| float.is_finite() && float.fract() == 0.0)
}

/// JSON equality: numerics compare by value (`1 == 1.0`), booleans never equal numbers, and
/// arrays and objects compare recursively.
fn json_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Null, Value::Null) => true,
        (Value::Bool(left), Value::Bool(right)) => left == right,
        (Value::Number(left), Value::Number(right)) => numbers_equal(left, right),
        (Value::String(left), Value::String(right)) => left == right,
        (Value::Array(left), Value::Array(right)) => {
            left.len() == right.len()
                && left
                    .iter()
                    .zip(right)
                    .all(|(left, right)| json_equal(left, right))
        }
        (Value::Object(left), Value::Object(right)) => {
            left.len() == right.len()
                && left.iter().all(|(key, value)| {
                    right.get(key).is_some_and(|other| json_equal(value, other))
                })
        }
        _ => false,
    }
}

fn numbers_equal(left: &Number, right: &Number) -> bool {
    if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
        return left == right;
    }
    if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
        return left == right;
    }
    matches!(
        (left.as_f64(), right.as_f64()),
        (Some(left), Some(right)) if left == right
    )
}

/// `Some(ordering)` when both values are numbers; integer pairs compare exactly.
fn compare_numbers(left: &Value, right: &Value) -> Option<Ordering> {
    let (Value::Number(left), Value::Number(right)) = (left, right) else {
        return None;
    };
    if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
        return Some(left.cmp(&right));
    }
    if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
        return Some(left.cmp(&right));
    }
    left.as_f64()?.partial_cmp(&right.as_f64()?)
}

/// Whether a numeric bound refuses the instance. Non-numbers are ignored, as jsonschema does.
fn refused_below(instance: &Value, bound: &Value, refused: &[Ordering]) -> bool {
    let Value::Number(_) = instance else {
        return false;
    };
    compare_numbers(instance, bound).is_some_and(|ordering| refused.contains(&ordering))
}

/// A non-negative integer bound. `usize::MAX` means "no constraint" for a malformed value,
/// which `validate_schema` has already refused.
fn count_bound(value: &Value) -> usize {
    let Value::Number(number) = value else {
        return usize::MAX;
    };
    if let Some(count) = number.as_u64() {
        return count as usize;
    }
    number.as_f64().map_or(usize::MAX, |float| float as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn limits() -> SchemaLimits {
        SchemaLimits::default()
    }

    fn assert_valid(schema: &Value, instance: &Value) {
        assert!(
            validate_instance(schema, instance, &limits()).is_ok(),
            "{schema} should accept {instance}"
        );
    }

    fn assert_problems(schema: &Value, instance: &Value, expected: &[(&str, &str)]) {
        let problems = match validate_instance(schema, instance, &limits()) {
            Err(InstanceError::Invalid(error)) => error.problems,
            other => panic!("{schema} should refuse {instance}: {other:?}"),
        };
        let mut actual: Vec<(&str, &str)> = problems
            .iter()
            .map(|problem| (problem.path.as_str(), problem.rule.as_str()))
            .collect();
        actual.sort_unstable();
        let mut expected = expected.to_vec();
        expected.sort_unstable();
        assert_eq!(actual, expected, "{schema} / {instance}");
    }

    #[test]
    fn type_accepts_and_refuses_the_closed_set() {
        let string = json!({"type": "string"});
        assert_valid(&string, &json!("x"));
        assert_valid(&string, &json!(""));
        assert_problems(&string, &json!(1), &[("", "type")]);
        assert_problems(&string, &json!(true), &[("", "type")]);

        let nullable = json!({"type": ["string", "null"]});
        assert_valid(&nullable, &json!(null));
        assert_valid(&nullable, &json!("x"));
        assert_problems(&nullable, &json!(0), &[("", "type")]);

        let object = json!({"type": "object"});
        assert_valid(&object, &json!({}));
        assert_problems(&object, &json!([]), &[("", "type")]);

        let array = json!({"type": "array"});
        assert_valid(&array, &json!([]));
        assert_problems(&array, &json!({}), &[("", "type")]);
    }

    #[test]
    fn integer_is_a_number_without_a_fractional_part() {
        let integer = json!({"type": "integer"});
        assert_valid(&integer, &json!(1));
        assert_valid(&integer, &json!(-3));
        assert_valid(&integer, &json!(1.0));
        assert_valid(&integer, &json!(1e3));
        assert_problems(&integer, &json!(1.5), &[("", "type")]);
        assert_problems(&integer, &json!(true), &[("", "type")]);
        assert_problems(&integer, &json!("1"), &[("", "type")]);

        let number = json!({"type": "number"});
        assert_valid(&number, &json!(1.5));
        assert_valid(&number, &json!(1));
        assert_problems(&number, &json!(true), &[("", "type")]);
    }

    #[test]
    fn object_keywords() {
        let schema = json!({
            "type": "object",
            "properties": {
                "count": {"type": "integer"},
                "label": {"type": "string"}
            },
            "required": ["count", "label"],
            "additionalProperties": false,
            "minProperties": 2,
            "maxProperties": 3
        });
        assert_valid(&schema, &json!({"count": 1, "label": "a"}));
        assert_problems(
            &schema,
            &json!({"count": "x", "extra": 1}),
            &[
                ("/count", "type"),
                ("/label", "required"),
                ("", "additionalProperties"),
            ],
        );

        // `additionalProperties` applies only to keys `properties` does not name, and a
        // schema there descends into each unexpected value.
        let typed = json!({
            "type": "object",
            "properties": {"known": {}},
            "additionalProperties": {"type": "integer"}
        });
        assert_valid(&typed, &json!({"known": "anything", "count": 1}));
        assert_problems(&typed, &json!({"count": "x"}), &[("/count", "type")]);

        assert_problems(
            &json!({"minProperties": 2}),
            &json!({}),
            &[("", "minProperties")],
        );
        assert_problems(
            &json!({"maxProperties": 1}),
            &json!({"a": 1, "b": 2}),
            &[("", "maxProperties")],
        );
    }

    #[test]
    fn array_keywords() {
        let tuple = json!({
            "type": "array",
            "prefixItems": [{"type": "string"}, {"type": "integer"}],
            "items": {"type": "boolean"},
            "minItems": 2,
            "maxItems": 4
        });
        assert_valid(&tuple, &json!(["a", 1]));
        assert_valid(&tuple, &json!(["a", 1, true]));
        assert_problems(
            &tuple,
            &json!([1, "b", 3]),
            &[("/0", "type"), ("/1", "type"), ("/2", "type")],
        );

        // Without `prefixItems`, `items` covers every element.
        let all = json!({"items": {"type": "integer"}});
        assert_valid(&all, &json!([1, 2]));
        assert_problems(&all, &json!(["a"]), &[("/0", "type")]);

        // `items: false` is one problem at the array, never one per element.
        let closed = json!({"prefixItems": [true], "items": false});
        assert_valid(&closed, &json!([1]));
        assert_problems(&closed, &json!([1, 2, 3]), &[("", "items")]);

        assert_problems(&json!({"minItems": 2}), &json!([1]), &[("", "minItems")]);
        assert_problems(&json!({"maxItems": 1}), &json!([1, 2]), &[("", "maxItems")]);
    }

    #[test]
    fn string_lengths_count_characters_not_bytes() {
        let schema = json!({"type": "string", "minLength": 2, "maxLength": 3});
        assert_valid(&schema, &json!("üé"));
        assert_problems(&schema, &json!("a"), &[("", "minLength")]);
        assert_problems(&schema, &json!("abcd"), &[("", "maxLength")]);

        // Length keywords ignore non-strings.
        assert_valid(&json!({"minLength": 2, "maxLength": 3}), &json!(5));
    }

    #[test]
    fn numeric_bounds_are_inclusive_or_exclusive() {
        let inclusive = json!({"minimum": 0, "maximum": 10});
        assert_valid(&inclusive, &json!(0));
        assert_valid(&inclusive, &json!(10));
        assert_valid(&inclusive, &json!(0.5));
        assert_problems(&inclusive, &json!(-1), &[("", "minimum")]);
        assert_problems(&inclusive, &json!(11), &[("", "maximum")]);
        assert_valid(&inclusive, &json!("5"));

        let exclusive = json!({"exclusiveMinimum": 0, "exclusiveMaximum": 10});
        assert_valid(&exclusive, &json!(0.5));
        assert_valid(&exclusive, &json!(9.5));
        assert_problems(&exclusive, &json!(0), &[("", "exclusiveMinimum")]);
        assert_problems(&exclusive, &json!(10), &[("", "exclusiveMaximum")]);
    }

    #[test]
    fn enum_and_const_compare_json_values() {
        let choices = json!({"enum": [1, "a", null]});
        assert_valid(&choices, &json!(1));
        assert_valid(&choices, &json!(1.0));
        assert_valid(&choices, &json!("a"));
        assert_valid(&choices, &json!(null));
        assert_problems(&choices, &json!(true), &[("", "enum")]);
        assert_problems(&choices, &json!(2), &[("", "enum")]);

        let fixed = json!({"const": {"a": [1]}});
        assert_valid(&fixed, &json!({"a": [1.0]}));
        assert_problems(&fixed, &json!({"a": [2]}), &[("", "const")]);
    }

    #[test]
    fn combinators() {
        let all = json!({"allOf": [{"type": "string"}, {"minLength": 2}]});
        assert_valid(&all, &json!("ab"));
        assert_problems(&all, &json!("a"), &[("", "minLength")]);
        assert_problems(&all, &json!(5), &[("", "type")]);

        let any = json!({"anyOf": [{"type": "string"}, {"type": "integer"}]});
        assert_valid(&any, &json!("a"));
        assert_valid(&any, &json!(1));
        assert_problems(&any, &json!(1.5), &[("", "anyOf")]);

        let one = json!({"oneOf": [{"type": "number"}, {"type": "integer"}]});
        assert_valid(&one, &json!(1.5));
        assert_problems(&one, &json!(1), &[("", "oneOf")]);
        assert_problems(&one, &json!("a"), &[("", "oneOf")]);

        let not = json!({"not": {"type": "string"}});
        assert_valid(&not, &json!(1));
        assert_problems(&not, &json!("a"), &[("", "not")]);

        assert_valid(&json!(true), &json!(1));
        assert_problems(&json!(false), &json!(1), &[("", "false")]);
    }

    #[test]
    fn local_refs_into_defs_and_sibling_keywords() {
        let schema = json!({
            "$defs": {"positive": {"type": "integer", "minimum": 1}},
            "type": "object",
            "properties": {"count": {"$ref": "#/$defs/positive"}}
        });
        assert_valid(&schema, &json!({"count": 2}));
        assert_problems(&schema, &json!({"count": 0}), &[("/count", "minimum")]);

        // Draft 2020-12 applies a `$ref` target and its sibling keywords both.
        let sibling = json!({
            "$defs": {"count": {"type": "integer"}},
            "$ref": "#/$defs/count",
            "minimum": 5
        });
        assert_valid(&sibling, &json!(6));
        assert_problems(&sibling, &json!(3), &[("", "minimum")]);
        assert_problems(&sibling, &json!(1.5), &[("", "minimum"), ("", "type")]);
    }

    #[test]
    fn formats_use_the_registry() {
        let schema = json!({"format": "uuid"});
        assert_valid(&schema, &json!("018f2b3c-4d5e-7f80-9abc-def012345678"));
        assert_problems(&schema, &json!("not-a-uuid"), &[("", "format")]);
        // The reference's checker lets every non-string through.
        assert_valid(&schema, &json!(5));
    }

    #[test]
    fn work_limit_and_bounds_are_distinguishable_from_a_mismatch() {
        let bounded = SchemaLimits {
            max_validation_work: 0,
            ..SchemaLimits::default()
        };
        let error =
            validate_instance(&json!({"type": "integer"}), &json!(1), &bounded).unwrap_err();
        assert!(matches!(
            error,
            InstanceError::Work("validation work limit exceeded")
        ));
        assert_eq!(error.to_string(), "validation work limit exceeded");

        let bounded = SchemaLimits {
            max_instance_nodes: 1,
            ..SchemaLimits::default()
        };
        let error =
            validate_instance(&json!({"type": "array"}), &json!([1, 2]), &bounded).unwrap_err();
        assert!(matches!(error, InstanceError::Bounds(_)));
        assert_eq!(error.to_string(), "JSON array exceeds node limit");

        let bounded = SchemaLimits {
            max_instance_bytes: 4,
            ..SchemaLimits::default()
        };
        let error =
            validate_instance(&json!({"type": "string"}), &json!("longer"), &bounded).unwrap_err();
        assert_eq!(error.to_string(), "JSON string exceeds byte limit");

        // The schema is validated first, so schema-side refusals surface before instance ones.
        let error = validate_instance(&json!({"pattern": "x"}), &json!(1), &bounded).unwrap_err();
        assert!(matches!(error, InstanceError::Bounds(_)));
        assert_eq!(error.to_string(), "unsupported schema keyword");
    }

    #[test]
    fn at_most_twenty_problems_and_never_an_instance_value() {
        let names: Vec<String> = (0..30).map(|index| format!("field-{index}")).collect();
        let schema = json!({"type": "object", "required": names});
        let problems = match validate_instance(&schema, &json!({}), &limits()) {
            Err(InstanceError::Invalid(error)) => error.problems,
            other => panic!("{other:?}"),
        };
        assert_eq!(problems.len(), MAX_PROBLEMS);
        assert!(problems.iter().all(|problem| problem.rule == "required"));
        let mut paths: Vec<&str> = problems
            .iter()
            .map(|problem| problem.path.as_str())
            .collect();
        paths.sort_unstable();
        paths.dedup();
        assert_eq!(paths.len(), MAX_PROBLEMS);

        // A problem carries only the pointer and the keyword, never the failing value.
        let secret = "sk-live-instance-secret";
        let schema = json!({
            "type": "object",
            "properties": {
                "token": {"type": "integer"},
                "a/b~c": {"type": "integer"}
            }
        });
        let instance = json!({"token": secret, "a/b~c": secret});
        let problems = match validate_instance(&schema, &instance, &limits()) {
            Err(InstanceError::Invalid(error)) => error.problems,
            other => panic!("{other:?}"),
        };
        let actual: Vec<(&str, &str)> = problems
            .iter()
            .map(|problem| (problem.path.as_str(), problem.rule.as_str()))
            .collect();
        assert_eq!(actual, vec![("/a~1b~0c", "type"), ("/token", "type")]);
        assert!(
            problems
                .iter()
                .all(|problem| !problem.path.contains(secret) && !problem.rule.contains(secret))
        );
    }

    #[test]
    fn input_validation_error_displays_the_reference_message() {
        let error = InputValidationError {
            problems: vec![Problem {
                path: String::new(),
                rule: "type".to_owned(),
            }],
        };
        assert_eq!(error.to_string(), "instance does not match declared schema");
        let boxed: Box<dyn std::error::Error> = Box::new(error);
        assert_eq!(boxed.to_string(), "instance does not match declared schema");

        let invalid =
            validate_instance(&json!({"type": "integer"}), &json!("x"), &limits()).unwrap_err();
        assert!(matches!(invalid, InstanceError::Invalid(_)));
        assert_eq!(
            invalid.to_string(),
            "instance does not match declared schema"
        );
    }
}
