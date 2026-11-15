//! Polish court judgments via SAOS (www.saos.org.pl/api): `legal_saos_search`,
//! `legal_saos_judgment`.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, child, child_or, clamp_max_chars, int_or, optional_enum, optional_string,
    parse_iso_date, python_str, required_string, schema, strip_tags, success, truncate, truthy,
};

/// The reference's `CourtType`.
pub const COURT_TYPES: &[&str] = &[
    "COMMON",
    "SUPREME",
    "ADMINISTRATIVE",
    "CONSTITUTIONAL_TRIBUNAL",
    "NATIONAL_APPEAL_CHAMBER",
];

fn date_field(field: &str, value: Option<String>) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(text) => match parse_iso_date(&text) {
            Some(date) => Ok(Some(date.format("%Y-%m-%d").to_string())),
            None => Err(format!("[permanent] invalid {field}: expected YYYY-MM-DD")),
        },
    }
}

/// (court name, division name). Common courts nest the court in the division; the other court
/// types have no court object, so the court type stands in for the court.
fn court(raw: &Value) -> (Value, Value) {
    let division = child(raw, "division");
    let mut court_name = Value::Null;
    let mut division_name = Value::Null;
    let is_object = division.is_object();
    if is_object {
        let name = child(child(division, "court"), "name");
        if truthy(name) {
            court_name = name.clone();
        }
        let name = child(division, "name");
        if truthy(name) {
            division_name = name.clone();
        }
    }
    if !truthy(&division_name)
        && let Some(first) = child(raw, "divisions")
            .as_array()
            .and_then(|items| items.first())
    {
        let name = child(first, "name");
        if truthy(name) {
            division_name = name.clone();
        }
    }
    if !truthy(&court_name) {
        court_name = child(raw, "courtType").clone();
    }
    (court_name, division_name)
}

/// The case numbers a judgment carries, in order.
fn case_numbers(raw: &Value) -> Value {
    let numbers: Vec<Value> = child(raw, "courtCases")
        .as_array()
        .map(|cases| {
            cases
                .iter()
                .filter_map(|case| {
                    let number = child(case, "caseNumber");
                    if truthy(number) {
                        Some(number.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    Value::Array(numbers)
}

/// One named field from each object in an array, dropping falsy values (the reference's
/// `[j.get("name") for j in ... if j.get("name")]`).
fn named(items: &Value, key: &str) -> Vec<Value> {
    items
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|item| {
                    let value = child(item, key);
                    if truthy(value) {
                        Some(value.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Full-text search of Polish court judgments (SAOS), newest first.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let query = required_string(arguments, "query")?;
    if query.trim().is_empty() || query.chars().count() > 500 {
        return Err("[permanent] query must be 1-500 chars".to_owned());
    }
    let case_number = optional_string(arguments, "case_number")?;
    if let Some(case_number) = &case_number
        && case_number.chars().count() > 100
    {
        return Err("[permanent] case_number too long (max 100 chars)".to_owned());
    }
    let court_type = optional_enum(arguments, "court_type", COURT_TYPES)?;
    let date_from = date_field("date_from", optional_string(arguments, "date_from")?)?;
    let date_to = date_field("date_to", optional_string(arguments, "date_to")?)?;
    let page_size = int_or(arguments, "page_size", 10)?;
    let page = int_or(arguments, "page", 0)?;
    let mut params: Vec<(&str, String)> = vec![("all", query)];
    if let Some(court_type) = court_type {
        params.push(("courtType", court_type));
    }
    if let Some(case_number) = case_number
        && !case_number.is_empty()
    {
        params.push(("caseNumber", case_number));
    }
    if let Some(date_from) = date_from {
        params.push(("judgmentDateFrom", date_from));
    }
    if let Some(date_to) = date_to {
        params.push(("judgmentDateTo", date_to));
    }
    params.push(("pageSize", page_size.clamp(1, 100).to_string()));
    params.push(("pageNumber", page.max(0).to_string()));
    params.push(("sortingField", "JUDGMENT_DATE".to_owned()));
    params.push(("sortingDirection", "DESC".to_owned()));

    let client = clients.get(Service::Saos)?;
    let answer = client
        .get_json("/api/search/judgments", &params, None)
        .await?;
    let keywords_default = Value::Array(Vec::new());
    let items: Vec<Value> = child(&answer, "items")
        .as_array()
        .map(|items| {
            items
                .iter()
                .map(|raw| {
                    let (court, division) = court(raw);
                    json!({
                        "id": child(raw, "id"),
                        "case_numbers": case_numbers(raw),
                        "judgment_date": child(raw, "judgmentDate"),
                        "judgment_type": child(raw, "judgmentType"),
                        "court": court,
                        "division": division,
                        "keywords": child_or(raw, "keywords", &keywords_default).clone(),
                        "snippet": strip_tags(
                            child(raw, "textContent").as_str().unwrap_or_default(),
                        ),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(json!({
        "total": child(child(&answer, "info"), "totalResults"),
        "items": items,
    }))
}

/// One Polish court judgment from SAOS by numeric id.
pub async fn judgment(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let id = int_or(arguments, "id", 0)?;
    if id <= 0 || id >= 10_000_000_000 {
        return Err(format!("[permanent] invalid id: {id}"));
    }
    let max_chars = clamp_max_chars(int_or(arguments, "max_chars", 60_000)?);
    let client = clients.get(Service::Saos)?;
    let answer = client
        .get_json(
            &format!("/api/judgments/{id}"),
            &[],
            Some("judgment not found"),
        )
        .await?;
    let raw = child(&answer, "data");
    let (court, division) = court(raw);
    let (text, truncated) = truncate(
        &super::html_to_text(child(raw, "textContent").as_str().unwrap_or_default()),
        max_chars,
    );
    let source = child(raw, "source");
    let summary = child(raw, "summary");
    let url = if truthy(child(source, "judgmentUrl")) {
        child(source, "judgmentUrl").clone()
    } else {
        child(raw, "href").clone()
    };
    Ok(json!({
        "id": child_or(raw, "id", &Value::Number(id.into())).clone(),
        "case_numbers": case_numbers(raw),
        "judgment_date": child(raw, "judgmentDate"),
        "judgment_type": child(raw, "judgmentType"),
        "court": court,
        "division": division,
        "judges": named(child(raw, "judges"), "name"),
        "legal_bases": child_or(raw, "legalBases", &Value::Array(Vec::new())).clone(),
        "referenced_regulations": named(child(raw, "referencedRegulations"), "text"),
        "summary": if truthy(summary) {
            Value::String(strip_tags(&python_str(summary)))
        } else {
            Value::Null
        },
        "text": text,
        "truncated": truncated,
        "url": url,
    }))
}

/// Register the two SAOS tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "saos_search",
        "Full-text search of Polish court judgments (SAOS), newest first. Dates YYYY-MM-DD.\n\
         Returns judgment ids for legal_saos_judgment.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "query": {"type": "string"},
                "court_type": {
                    "anyOf": [
                        {"enum": COURT_TYPES, "type": "string"},
                        {"type": "null"},
                    ],
                    "default": null,
                },
                "case_number": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "date_from": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "date_to": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "page_size": {"default": 10, "type": "integer"},
                "page": {"default": 0, "type": "integer"},
            },
            "required": ["query"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "saos_judgment",
        "One Polish court judgment from SAOS by numeric id: court, judges, legal bases,\n\
         referenced regulations and the full text (plain).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "id": {"type": "integer"},
                "max_chars": {"default": 60000, "type": "integer"},
            },
            "required": ["id"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(judgment(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
