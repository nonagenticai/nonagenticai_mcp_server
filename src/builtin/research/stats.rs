//! Statistics via scientific-processor (`/api/stats/*`): `research_stats_meta_analysis`,
//! `research_stats_confidence_interval` and `research_stats_trend`.
//!
//! The tools are pure forwarded computations over the numbers the caller passes; nothing is
//! stored. Inputs are checked here against the service's own limits
//! (`scientific-processor/src/models/statistics.py`) so a bad call fails fast as `[permanent]`
//! without an upstream request, and every answer echoes the count and the method so a reviewer
//! can tie a reported number to the call that produced it.
//!
//! The arithmetic itself stays upstream: this family performs no statistics of its own, exactly
//! as the reference does (`src/builtin/research/stats.py`).

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::legal::{child, child_or, enum_or, schema, success};
use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    CallRequest, Clients, MAX_POINTS, MAX_STUDIES, MAX_VALUES, Service, call_json, finite, int_or,
    number_or,
};

/// The `method` values the meta-analysis service accepts.
pub const META_METHODS: &[&str] = &["fixed", "random"];
/// The `method` values the confidence-interval service accepts.
pub const CI_METHODS: &[&str] = &["normal", "bootstrap"];
/// The trend tests the service accepts.
pub const TREND_TESTS: &[&str] = &["mann_kendall", "linear_regression"];

/// One study the caller submits (the reference's Pydantic `Study`, without `weight`: the MCP
/// tool never sends it).
struct Study {
    effect_size: f64,
    standard_error: f64,
    sample_size: i64,
    label: Option<String>,
}

/// One time-series point (the reference's Pydantic `Point`).
struct Point {
    timestamp: f64,
    value: f64,
}

/// One required number field of an array item.
fn item_number(fields: &Map<String, Value>, index: usize, field: &str) -> Result<f64, String> {
    fields
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("[permanent] invalid studies[{index}].{field}: expected a number"))
}

/// One required integer field of an array item.
fn item_integer(fields: &Map<String, Value>, index: usize, field: &str) -> Result<i64, String> {
    fields
        .get(field)
        .and_then(super::integer_value)
        .ok_or_else(|| format!("[permanent] invalid studies[{index}].{field}: expected an integer"))
}

/// The reference's Pydantic `list[Study]`: items are objects, unknown members are ignored, and a
/// missing `label` is absent (Pydantic's `exclude_none=True` then omits it from the request).
fn parse_studies(arguments: &Map<String, Value>) -> Result<Vec<Study>, String> {
    let Some(items) = arguments.get("studies").and_then(Value::as_array) else {
        return Err("[permanent] invalid studies: expected an array".to_owned());
    };
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let fields = item
            .as_object()
            .ok_or_else(|| format!("[permanent] invalid studies[{index}]: expected an object"))?;
        let label = match fields.get("label") {
            None | Some(Value::Null) => None,
            Some(Value::String(text)) => Some(text.clone()),
            Some(_) => {
                return Err(format!(
                    "[permanent] invalid studies[{index}].label: expected a string"
                ));
            }
        };
        parsed.push(Study {
            effect_size: item_number(fields, index, "effect_size")?,
            standard_error: item_number(fields, index, "standard_error")?,
            sample_size: item_integer(fields, index, "sample_size")?,
            label,
        });
    }
    Ok(parsed)
}

/// The reference's Pydantic `list[Point]`.
fn parse_points(arguments: &Map<String, Value>) -> Result<Vec<Point>, String> {
    let Some(items) = arguments.get("data").and_then(Value::as_array) else {
        return Err("[permanent] invalid data: expected an array".to_owned());
    };
    let mut parsed = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let fields = item
            .as_object()
            .ok_or_else(|| format!("[permanent] invalid data[{index}]: expected an object"))?;
        let timestamp = fields
            .get("timestamp")
            .and_then(Value::as_f64)
            .ok_or_else(|| {
                format!("[permanent] invalid data[{index}].timestamp: expected a number")
            })?;
        let value = fields
            .get("value")
            .and_then(Value::as_f64)
            .ok_or_else(|| format!("[permanent] invalid data[{index}].value: expected a number"))?;
        parsed.push(Point { timestamp, value });
    }
    Ok(parsed)
}

/// The reference's Pydantic `list[float]`.
fn parse_values(arguments: &Map<String, Value>) -> Result<Vec<f64>, String> {
    let Some(items) = arguments.get("values").and_then(Value::as_array) else {
        return Err("[permanent] invalid values: expected an array".to_owned());
    };
    items
        .iter()
        .enumerate()
        .map(|(index, item)| {
            item.as_f64()
                .ok_or_else(|| format!("[permanent] invalid values[{index}]: expected a number"))
        })
        .collect()
}

/// The reference's `_level`: the confidence level must be in `[0.5, 1.0)`.
fn level(confidence_level: f64) -> Result<f64, String> {
    if (0.5..1.0).contains(&confidence_level) {
        Ok(confidence_level)
    } else {
        Err("[permanent] confidence_level must be in [0.5, 1.0)".to_owned())
    }
}

/// Inverse-variance meta-analysis over 2+ study results.
pub async fn meta_analysis(
    clients: &Clients,
    arguments: &Map<String, Value>,
) -> Result<Value, String> {
    let studies = parse_studies(arguments)?;
    if !(2..=MAX_STUDIES).contains(&studies.len()) {
        return Err(format!(
            "[permanent] studies must have 2-{MAX_STUDIES} entries"
        ));
    }
    for (index, study) in studies.iter().enumerate() {
        finite(&format!("studies[{index}].effect_size"), study.effect_size)?;
        let standard_error = finite(
            &format!("studies[{index}].standard_error"),
            study.standard_error,
        )?;
        if standard_error <= 0.0 {
            return Err(format!(
                "[permanent] studies[{index}].standard_error must be > 0"
            ));
        }
        if study.sample_size <= 0 {
            return Err(format!(
                "[permanent] studies[{index}].sample_size must be > 0"
            ));
        }
    }
    let method = enum_or(arguments, "method", "random", META_METHODS)?;
    let confidence_level = level(number_or(arguments, "confidence_level", 0.95)?)?;

    let mut payload = Vec::with_capacity(studies.len());
    for study in &studies {
        let mut fields = Map::new();
        fields.insert("effect_size".to_owned(), Value::from(study.effect_size));
        fields.insert(
            "standard_error".to_owned(),
            Value::from(study.standard_error),
        );
        fields.insert("sample_size".to_owned(), Value::from(study.sample_size));
        if let Some(label) = &study.label {
            fields.insert("label".to_owned(), Value::String(label.clone()));
        }
        payload.push(Value::Object(fields));
    }
    let mut body = Map::new();
    body.insert("studies".to_owned(), Value::Array(payload));
    body.insert("method".to_owned(), Value::String(method.clone()));
    body.insert("confidence_level".to_owned(), Value::from(confidence_level));
    let answer = call_json(
        clients,
        Service::ScientificProcessor,
        "POST",
        "/api/stats/meta-analysis",
        CallRequest {
            body: Some(Value::Object(body)),
            ..CallRequest::default()
        },
    )
    .await?;

    let weights = child(&answer, "study_weights")
        .as_array()
        .cloned()
        .unwrap_or_default();
    let study_weights: Vec<Value> = studies
        .iter()
        .zip(weights.iter())
        .map(|(study, weight)| {
            let mut out = Map::new();
            out.insert(
                "label".to_owned(),
                study
                    .label
                    .as_ref()
                    .map(|label| Value::String(label.clone()))
                    .unwrap_or(Value::Null),
            );
            out.insert("weight".to_owned(), weight.clone());
            Value::Object(out)
        })
        .collect();
    let mut out = Map::new();
    out.insert(
        "method".to_owned(),
        child_or(&answer, "method", &Value::String(method)).clone(),
    );
    out.insert("confidence_level".to_owned(), Value::from(confidence_level));
    out.insert("studies_count".to_owned(), Value::from(studies.len()));
    out.insert(
        "pooled_effect".to_owned(),
        child(&answer, "pooled_effect").clone(),
    );
    out.insert("pooled_se".to_owned(), child(&answer, "pooled_se").clone());
    out.insert("ci_lower".to_owned(), child(&answer, "ci_lower").clone());
    out.insert("ci_upper".to_owned(), child(&answer, "ci_upper").clone());
    out.insert(
        "heterogeneity_q".to_owned(),
        child(&answer, "heterogeneity_q").clone(),
    );
    out.insert(
        "heterogeneity_i_squared".to_owned(),
        child(&answer, "heterogeneity_i_squared").clone(),
    );
    out.insert("study_weights".to_owned(), Value::Array(study_weights));
    Ok(Value::Object(out))
}

/// Mean of 2+ values with its confidence interval.
pub async fn confidence_interval(
    clients: &Clients,
    arguments: &Map<String, Value>,
) -> Result<Value, String> {
    let values = parse_values(arguments)?;
    if !(2..=MAX_VALUES).contains(&values.len()) {
        return Err(format!(
            "[permanent] values must have 2-{MAX_VALUES} entries"
        ));
    }
    for (index, value) in values.iter().enumerate() {
        finite(&format!("values[{index}]"), *value)?;
    }
    let method = enum_or(arguments, "method", "normal", CI_METHODS)?;
    let confidence_level = level(number_or(arguments, "confidence_level", 0.95)?)?;
    let n_bootstrap = int_or(arguments, "n_bootstrap", 10_000)?;
    if !(100..=100_000).contains(&n_bootstrap) {
        return Err("[permanent] n_bootstrap must be 100-100000".to_owned());
    }

    let mut body = Map::new();
    body.insert(
        "values".to_owned(),
        Value::Array(values.iter().map(|value| Value::from(*value)).collect()),
    );
    body.insert("method".to_owned(), Value::String(method.clone()));
    body.insert("confidence_level".to_owned(), Value::from(confidence_level));
    body.insert("n_bootstrap".to_owned(), Value::from(n_bootstrap));
    let answer = call_json(
        clients,
        Service::ScientificProcessor,
        "POST",
        "/api/stats/confidence-interval",
        CallRequest {
            body: Some(Value::Object(body)),
            ..CallRequest::default()
        },
    )
    .await?;

    let mut out = Map::new();
    out.insert(
        "method".to_owned(),
        child_or(&answer, "method", &Value::String(method)).clone(),
    );
    out.insert(
        "confidence_level".to_owned(),
        child_or(&answer, "confidence_level", &Value::from(confidence_level)).clone(),
    );
    out.insert("values_count".to_owned(), Value::from(values.len()));
    out.insert("mean".to_owned(), child(&answer, "mean").clone());
    out.insert("ci_lower".to_owned(), child(&answer, "ci_lower").clone());
    out.insert("ci_upper".to_owned(), child(&answer, "ci_upper").clone());
    Ok(Value::Object(out))
}

/// Trend test over a time series of 3+ points.
pub async fn trend(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let points = parse_points(arguments)?;
    if !(3..=MAX_POINTS).contains(&points.len()) {
        return Err(format!("[permanent] data must have 3-{MAX_POINTS} points"));
    }
    for (index, point) in points.iter().enumerate() {
        finite(&format!("data[{index}].timestamp"), point.timestamp)?;
        finite(&format!("data[{index}].value"), point.value)?;
    }
    let test = enum_or(arguments, "test", "mann_kendall", TREND_TESTS)?;

    let body_points: Vec<Value> = points
        .iter()
        .map(|point| json!({"timestamp": point.timestamp, "value": point.value}))
        .collect();
    let mut body = Map::new();
    body.insert("data".to_owned(), Value::Array(body_points));
    body.insert("test".to_owned(), Value::String(test.clone()));
    let answer = call_json(
        clients,
        Service::ScientificProcessor,
        "POST",
        "/api/stats/trend",
        CallRequest {
            body: Some(Value::Object(body)),
            ..CallRequest::default()
        },
    )
    .await?;

    let mut out = Map::new();
    out.insert("test".to_owned(), Value::String(test));
    out.insert("points_count".to_owned(), Value::from(points.len()));
    out.insert("trend".to_owned(), child(&answer, "trend").clone());
    out.insert("p_value".to_owned(), child(&answer, "p_value").clone());
    out.insert("statistic".to_owned(), child(&answer, "statistic").clone());
    out.insert("slope".to_owned(), child(&answer, "slope").clone());
    out.insert("intercept".to_owned(), child(&answer, "intercept").clone());
    Ok(Value::Object(out))
}

/// Register the three statistics tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "research",
        "stats_meta_analysis",
        "Inverse-variance meta-analysis (fixed or random effects) over 2+ study results, each an\n\
         effect size with its standard error and sample size. Returns the pooled effect, its CI,\n\
         heterogeneity (Q, I^2) and each study's weight (same order as given).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "studies": {
                    "items": {
                        "properties": {
                            "effect_size": {"type": "number"},
                            "standard_error": {"type": "number"},
                            "sample_size": {"type": "integer"},
                            "label": {
                                "anyOf": [{"type": "string"}, {"type": "null"}],
                                "default": null,
                            },
                        },
                        "required": ["effect_size", "standard_error", "sample_size"],
                        "type": "object",
                    },
                    "type": "array",
                },
                "method": {"default": "random", "enum": META_METHODS, "type": "string"},
                "confidence_level": {"default": 0.95, "type": "number"},
            },
            "required": ["studies"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(meta_analysis(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "research",
        "stats_confidence_interval",
        "Mean of 2+ values with its confidence interval (normal approximation, or percentile\n\
         bootstrap with n_bootstrap resamples, 100-100000).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "values": {"items": {"type": "number"}, "type": "array"},
                "method": {"default": "normal", "enum": CI_METHODS, "type": "string"},
                "confidence_level": {"default": 0.95, "type": "number"},
                "n_bootstrap": {"default": 10000, "type": "integer"},
            },
            "required": ["values"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                success(confidence_interval(&Clients::from_env(), &arguments).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "research",
        "stats_trend",
        "Trend test over a time series of 3+ (timestamp, value) points: Mann-Kendall (monotonic,\n\
         non-parametric) or linear regression (slope + intercept). Returns increasing / decreasing /\n\
         no_trend with the p-value and test statistic.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "data": {
                    "items": {
                        "properties": {
                            "timestamp": {"type": "number"},
                            "value": {"type": "number"},
                        },
                        "required": ["timestamp", "value"],
                        "type": "object",
                    },
                    "type": "array",
                },
                "test": {
                    "default": "mann_kendall",
                    "enum": TREND_TESTS,
                    "type": "string",
                },
            },
            "required": ["data"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(trend(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn levels_accept_half_open_and_refuse_the_edges() {
        assert_eq!(level(0.5).unwrap(), 0.5);
        assert_eq!(level(0.999).unwrap(), 0.999);
        assert_eq!(
            level(1.0).unwrap_err(),
            "[permanent] confidence_level must be in [0.5, 1.0)"
        );
        assert_eq!(
            level(0.49).unwrap_err(),
            "[permanent] confidence_level must be in [0.5, 1.0)"
        );
    }

    #[test]
    fn studies_parse_integral_numbers_and_drop_a_missing_label() {
        let arguments = json!({
            "studies": [
                {"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100.0, "label": "A"},
                {"effect_size": 0.5, "standard_error": 0.15, "sample_size": 80},
            ],
        });
        let parsed = parse_studies(arguments.as_object().unwrap()).unwrap();
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].sample_size, 100);
        assert_eq!(parsed[0].label.as_deref(), Some("A"));
        assert_eq!(parsed[1].label, None);
    }
}
