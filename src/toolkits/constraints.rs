//! Bound-context requirements and static policy intersections.
//!
//! Ported from the reference `src/toolkits/constraints.py`: [`pointer`] walks a bound context
//! with a JSON Pointer and [`check_rules`] refuses a rule set that no value could satisfy. These
//! checks never execute operation policy: the broker must enforce every rule again on each
//! concrete request, including host-side ownership reads.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::catalog::error::CatalogError;
use crate::catalog::models::Constraint;
use crate::catalog::package::canonical_path;

fn missing() -> CatalogError {
    CatalogError("required bound context is missing")
}

/// Walk `path` into `value`; a miss is the reference's ValueError, carried as a catalog refusal.
///
/// The key is unescaped exactly as the reference does it (`~1` then `~0`), a list index is
/// numeric, and anything else misses.
pub fn pointer<'value>(value: &'value Value, path: &str) -> Result<&'value Value, CatalogError> {
    let mut current = value;
    for component in path.split('/').skip(1) {
        let key = component.replace("~1", "/").replace("~0", "~");
        current = match current {
            Value::Array(items) => {
                let index: i64 = key.parse().map_err(|_| missing())?;
                let index = if index < 0 {
                    index + items.len() as i64
                } else {
                    index
                };
                let index = usize::try_from(index).map_err(|_| missing())?;
                items.get(index).ok_or_else(missing)?
            }
            Value::Object(map) => map.get(&key).ok_or_else(missing)?,
            _ => return Err(missing()),
        };
    }
    Ok(current)
}

/// The argument pointer a rule restricts; rules on one pointer are one conjunction.
fn argument(rule: &Constraint) -> &str {
    match rule {
        Constraint::ContextEquality(rule) => rule.argument.as_str(),
        Constraint::SetMembership(rule) => rule.argument.as_str(),
        Constraint::NumericBounds(rule) => rule.argument.as_str(),
        Constraint::RelativePath(rule) => rule.argument.as_str(),
        Constraint::OwnershipRead(rule) => rule.argument.as_str(),
    }
}

/// Whether `candidate` is strictly under `root`.
fn under(root: &str, candidate: &str) -> bool {
    candidate
        .strip_prefix(root)
        .is_some_and(|rest| rest.starts_with('/'))
}

/// Whether a candidate value is an acceptable canonical path under `root`.
fn rooted(candidate: &Value, root: &str) -> bool {
    let Some(text) = candidate.as_str() else {
        return false;
    };
    let Ok(path) = canonical_path(text) else {
        return false;
    };
    path == root || under(root, &path)
}

/// A candidate inside the narrowed inclusive numeric bounds; anything but a JSON number fails.
fn bounded(candidate: &Value, minimum: f64, maximum: f64) -> bool {
    candidate
        .as_f64()
        .is_some_and(|number| number >= minimum && number <= maximum)
}

/// Refuse a rule set that cannot be satisfied, with the reference's exact messages.
///
/// Rules on one argument are conjunctive: equality and membership candidates intersect, numeric
/// bounds narrow, relative-path roots must nest, and the surviving candidate set must be
/// non-empty. An ownership read needs its context pointer to resolve.
pub fn check_rules(rules: &[Constraint], context: &Value) -> Result<(), CatalogError> {
    struct Group<'a> {
        argument: &'a str,
        root: Option<&'a str>,
        rules: Vec<&'a Constraint>,
    }

    let mut groups: Vec<Group<'_>> = Vec::new();
    for rule in rules {
        if let Constraint::OwnershipRead(read) = rule {
            pointer(context, read.context.as_str())?;
        }
        let argument = argument(rule);
        let index = match groups.iter().position(|group| group.argument == argument) {
            Some(index) => index,
            None => {
                groups.push(Group {
                    argument,
                    root: None,
                    rules: Vec::new(),
                });
                groups.len() - 1
            }
        };
        let group = &mut groups[index];
        if let Constraint::RelativePath(rule) = rule {
            if let Some(root) = group.root
                && !(root == rule.root || under(&rule.root, root) || under(root, &rule.root))
            {
                return Err(CatalogError("incompatible relative path restrictions"));
            }
            let longest = group.root.map_or(0, |root| root.chars().count());
            if rule.root.chars().count() > longest {
                group.root = Some(rule.root.as_str());
            }
        }
        group.rules.push(rule);
    }

    for group in &groups {
        let mut minimum = f64::NEG_INFINITY;
        let mut maximum = f64::INFINITY;
        let mut values: Option<BTreeSet<String>> = None;
        for rule in &group.rules {
            let candidates: Option<Vec<&Value>> = match *rule {
                Constraint::ContextEquality(rule) => {
                    Some(vec![pointer(context, rule.context.as_str())?])
                }
                Constraint::SetMembership(rule) => Some(rule.values.iter().collect()),
                Constraint::NumericBounds(rule) => {
                    minimum = minimum.max(rule.minimum);
                    maximum = maximum.min(rule.maximum);
                    None
                }
                Constraint::RelativePath(_) | Constraint::OwnershipRead(_) => None,
            };
            if let Some(candidates) = candidates {
                // Canonical text: serde_json's object map is key-sorted, so this is the
                // reference's `json.dumps(value, sort_keys=True, allow_nan=False)`.
                let encoded: BTreeSet<String> = candidates
                    .into_iter()
                    .map(|candidate| {
                        serde_json::to_string(candidate)
                            .expect("a bound context value is JSON-serializable")
                    })
                    .collect();
                values = Some(match values {
                    None => encoded,
                    Some(existing) => existing.intersection(&encoded).cloned().collect(),
                });
            }
        }
        if minimum > maximum {
            return Err(CatalogError("incompatible numeric restrictions"));
        }
        if let Some(values) = values {
            let narrowed = minimum != f64::NEG_INFINITY || maximum != f64::INFINITY;
            let possible = values.iter().any(|encoded| {
                let candidate: Value =
                    serde_json::from_str(encoded).expect("canonical JSON round-trips");
                (!narrowed || bounded(&candidate, minimum, maximum))
                    && group.root.is_none_or(|root| rooted(&candidate, root))
            });
            if !possible {
                return Err(CatalogError("incompatible value restrictions"));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn rule(value: Value) -> Constraint {
        serde_json::from_value(value).expect("a valid constraint")
    }

    #[test]
    fn pointer_walks_objects_lists_and_escapes() {
        let context = json!({
            "tenant_id": "10000000-0000-7000-8000-000000000001",
            "nested": {"a/b": [10, 20]},
        });
        assert_eq!(pointer(&context, "").unwrap(), &context);
        assert_eq!(
            pointer(&context, "/tenant_id").unwrap(),
            &json!("10000000-0000-7000-8000-000000000001")
        );
        assert_eq!(pointer(&context, "/nested/a~1b/1").unwrap(), &json!(20));
        assert_eq!(pointer(&context, "/nested/a~1b/-1").unwrap(), &json!(20));
        assert_eq!(
            pointer(&context, "/missing").unwrap_err(),
            CatalogError("required bound context is missing")
        );
        assert!(pointer(&context, "/nested/a~1b/2").is_err());
        assert!(pointer(&json!(5), "/x").is_err());
    }

    #[test]
    fn context_equality_reads_the_bound_context() {
        let context = json!({"tenant_id": "t", "project_id": "p"});
        let accepted = [rule(json!({
            "kind": "context_equal",
            "argument": "/tenant",
            "context": "/tenant_id"
        }))];
        assert!(check_rules(&accepted, &context).is_ok());

        // Two equalities on one argument intersect; different context fields intersect empty.
        let refused = [
            rule(json!({"kind": "context_equal", "argument": "/x", "context": "/tenant_id"})),
            rule(json!({"kind": "context_equal", "argument": "/x", "context": "/project_id"})),
        ];
        assert_eq!(
            check_rules(&refused, &context).unwrap_err(),
            CatalogError("incompatible value restrictions")
        );

        let missing = [rule(json!({
            "kind": "context_equal",
            "argument": "/tenant",
            "context": "/missing"
        }))];
        assert_eq!(
            check_rules(&missing, &context).unwrap_err(),
            CatalogError("required bound context is missing")
        );
    }

    #[test]
    fn set_memberships_intersect_and_refuse_empty() {
        let context = json!({});
        let accepted = [
            rule(json!({"kind": "set_membership", "argument": "/tag", "values": ["a", "b"]})),
            rule(json!({"kind": "set_membership", "argument": "/tag", "values": ["b", "c"]})),
        ];
        assert!(check_rules(&accepted, &context).is_ok());
        let refused = [
            rule(json!({"kind": "set_membership", "argument": "/tag", "values": ["a"]})),
            rule(json!({"kind": "set_membership", "argument": "/tag", "values": ["b"]})),
        ];
        assert_eq!(
            check_rules(&refused, &context).unwrap_err(),
            CatalogError("incompatible value restrictions")
        );
    }

    #[test]
    fn numeric_bounds_narrow_and_refuse_empty() {
        let context = json!({});
        let accepted = [
            rule(json!({
                "kind": "numeric_bounds", "argument": "/size", "minimum": 0.0, "maximum": 10.0
            })),
            rule(json!({
                "kind": "numeric_bounds", "argument": "/size", "minimum": 5.0, "maximum": 20.0
            })),
            rule(json!({"kind": "set_membership", "argument": "/size", "values": [5, 11]})),
        ];
        assert!(check_rules(&accepted, &context).is_ok());
        let refused = [
            rule(json!({
                "kind": "numeric_bounds", "argument": "/size", "minimum": 0.0, "maximum": 10.0
            })),
            rule(json!({
                "kind": "numeric_bounds", "argument": "/size", "minimum": 20.0, "maximum": 30.0
            })),
        ];
        assert_eq!(
            check_rules(&refused, &context).unwrap_err(),
            CatalogError("incompatible numeric restrictions")
        );
        let filtered = [
            rule(json!({
                "kind": "numeric_bounds", "argument": "/size", "minimum": 0.0, "maximum": 10.0
            })),
            rule(json!({"kind": "set_membership", "argument": "/size", "values": ["wide"]})),
        ];
        assert_eq!(
            check_rules(&filtered, &context).unwrap_err(),
            CatalogError("incompatible value restrictions")
        );
    }

    #[test]
    fn relative_paths_keep_the_longest_comparable_root() {
        let context = json!({});
        let accepted = [
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "project"})),
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "project/src"})),
            rule(json!({
                "kind": "set_membership", "argument": "/path",
                "values": ["project/src/main.rs"]
            })),
        ];
        assert!(check_rules(&accepted, &context).is_ok());
        let outside = [
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "project"})),
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "project/src"})),
            rule(json!({
                "kind": "set_membership", "argument": "/path",
                "values": ["project/README.md"]
            })),
        ];
        assert_eq!(
            check_rules(&outside, &context).unwrap_err(),
            CatalogError("incompatible value restrictions")
        );
        let incompatible = [
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "project"})),
            rule(json!({"kind": "relative_path", "argument": "/path", "root": "other"})),
        ];
        assert_eq!(
            check_rules(&incompatible, &context).unwrap_err(),
            CatalogError("incompatible relative path restrictions")
        );
    }

    #[test]
    fn ownership_reads_require_their_context_pointer() {
        let context = json!({"owner_id": "o"});
        let accepted = [rule(json!({
            "kind": "ownership_read",
            "argument": "/owner",
            "operation": {"id": "30000000-0000-7000-8000-000000000001", "version": 1},
            "result": "/owner_id",
            "context": "/owner_id"
        }))];
        assert!(check_rules(&accepted, &context).is_ok());
        let missing_rule = [rule(json!({
            "kind": "ownership_read",
            "argument": "/owner",
            "operation": {"id": "30000000-0000-7000-8000-000000000001", "version": 1},
            "result": "/owner_id",
            "context": "/missing"
        }))];
        assert_eq!(
            check_rules(&missing_rule, &context).unwrap_err(),
            CatalogError("required bound context is missing")
        );
    }
}
