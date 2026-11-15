//! EU law via the Publications Office CELLAR (SPARQL + content negotiation):
//! `legal_eurlex_act`, `legal_eurlex_text`. eur-lex.europa.eu HTML sits behind an AWS WAF
//! challenge, so it is never fetched; its URL is only returned as a citation link.

use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, child, encode_segment, html_to_text, int_or, python_repr, schema, success,
    truncate,
};

/// The reference's `_CELEX`.
static CELEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[0-9CE][0-9]{4}[A-Z]{1,2}[0-9A-Z()_-]{1,20}\z")
        .expect("the CELEX pattern is valid")
});
/// The reference's `_LANG`: an ISO 639-2 code.
static LANG: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-z]{3}\z").expect("the language pattern is valid"));

/// The reference's `SPARQL_PATH`.
const SPARQL_PATH: &str = "/webapi/rdf/sparql";

/// The reference's `_QUERY`, with its `%(celex)s` / `%(lang)s` literals filled in.
const QUERY: &str = r#"PREFIX cdm: <http://publications.europa.eu/ontology/cdm#>
PREFIX xsd: <http://www.w3.org/2001/XMLSchema#>
SELECT ?work ?date ?inforce ?eif ?eov ?title_pl ?title_en WHERE {
  ?work cdm:resource_legal_id_celex "CELEX_PLACEHOLDER"^^xsd:string .
  OPTIONAL { ?work cdm:work_date_document ?date }
  OPTIONAL { ?work cdm:resource_legal_in-force ?inforce }
  OPTIONAL { ?work cdm:resource_legal_date_entry-into-force ?eif }
  OPTIONAL { ?work cdm:resource_legal_date_end-of-validity ?eov }
  OPTIONAL { ?e1 cdm:expression_belongs_to_work ?work ;
                 cdm:expression_uses_language <http://publications.europa.eu/resource/authority/language/POL> ; cdm:expression_title ?title_pl }
  OPTIONAL { ?e2 cdm:expression_belongs_to_work ?work ;
                 cdm:expression_uses_language <http://publications.europa.eu/resource/authority/language/ENG> ; cdm:expression_title ?title_en }
} LIMIT 200"#;

fn sparql(celex: &str) -> String {
    QUERY.replace("CELEX_PLACEHOLDER", celex)
}

/// Validate a CELEX number; the literal is placed in the query only after this fullmatch.
pub fn celex_id(celex: &Value) -> Result<String, String> {
    match celex.as_str() {
        Some(text) if CELEX.is_match(text) => Ok(text.to_owned()),
        _ => {
            // The reference's `repr(celex)[:40]`, without an ellipsis.
            let shown: String = python_repr(celex).chars().take(40).collect();
            Err(format!(
                "[permanent] invalid celex: {shown} (expected e.g. 32016R0679, 62014CJ0362)"
            ))
        }
    }
}

fn to_bool(value: &Value) -> Value {
    match value.as_str() {
        Some("1") | Some("true") => Value::Bool(true),
        Some("0") | Some("false") => Value::Bool(false),
        _ => Value::Null,
    }
}

/// The reference's `_first`: the value of the first row that carries the variable at all.
fn first(rows: &[Value], variable: &str) -> Value {
    for row in rows {
        if let Some(binding) = row.get(variable) {
            return child(binding, "value").clone();
        }
    }
    Value::Null
}

/// Metadata of one EU act by CELEX number.
pub async fn act(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let celex = celex_id(&super::argument(arguments, "celex"))?;
    let client = clients.get(Service::Cellar)?;
    let reply = client
        .post_form(
            SPARQL_PATH,
            vec![("query".to_owned(), sparql(&celex))],
            vec![("Accept", "application/sparql-results+json".to_owned())],
            None,
        )
        .await?;
    let document: Value = serde_json::from_slice(&reply.body)
        .map_err(|_| "[retryable] unexpected SPARQL answer from CELLAR".to_owned())?;
    let Some(rows) = child(child(&document, "results"), "bindings").as_array() else {
        return Err("[retryable] unexpected SPARQL answer from CELLAR".to_owned());
    };
    if rows.is_empty() {
        return Err("[permanent] celex not found".to_owned());
    }
    let entry_into_force: Vec<String> = rows
        .iter()
        .filter_map(|row| {
            row.get("eif")
                .and_then(|binding| child(binding, "value").as_str())
                .map(str::to_owned)
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    Ok(json!({
        "celex": celex,
        "title_pl": first(rows, "title_pl"),
        "title_en": first(rows, "title_en"),
        "date_document": first(rows, "date"),
        "in_force": to_bool(&first(rows, "inforce")),
        "entry_into_force": entry_into_force,
        "end_of_validity": first(rows, "eov"),
        "text_url": format!("https://eur-lex.europa.eu/legal-content/PL/TXT/?uri=CELEX:{celex}"),
    }))
}

/// Plain text of an EU act by CELEX number, from CELLAR.
pub async fn text(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let celex = celex_id(&super::argument(arguments, "celex"))?;
    let language = super::optional_string(arguments, "lang")?.unwrap_or_else(|| "pol".to_owned());
    if !LANG.is_match(&language) {
        return Err(format!(
            "[permanent] invalid lang: {} (expected e.g. pol, eng)",
            python_repr(&Value::String(language))
        ));
    }
    let max_chars = super::clamp_max_chars_with(int_or(arguments, "max_chars", 30_000)?, 200_000);
    let client = clients.get(Service::Cellar)?;
    let not_found = format!("celex not found or no {language} XHTML text");
    let reply = client
        .get_text_follow(
            &format!("/resource/celex/{}", encode_segment(&celex)),
            vec![
                ("Accept", "application/xhtml+xml".to_owned()),
                ("Accept-Language", language.clone()),
            ],
            Some(not_found.as_str()),
        )
        .await?;
    if reply.status != 200 || reply.text().trim().is_empty() {
        // 300 Multiple Choices: several manifestations, none negotiated.
        return Err(format!(
            "[permanent] no single {language} XHTML text for {celex} (status {})",
            reply.status
        ));
    }
    let (text, truncated) = truncate(&html_to_text(&reply.text()), max_chars);
    Ok(json!({
        "celex": celex,
        "lang": language,
        "text": text,
        "truncated": truncated,
    }))
}

/// Register the two EUR-Lex tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "eurlex_act",
        "Metadata of one EU act by CELEX number (e.g. \"32016R0679\" = GDPR): Polish and English\n\
         title, document date, whether it is in force, entry-into-force dates, end of validity.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"celex": {"type": "string"}},
            "required": ["celex"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(act(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "eurlex_text",
        "Plain text of an EU act by CELEX number, from CELLAR (lang: ISO 639-2 code, default\n\
         \"pol\"; \"eng\" for English).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "celex": {"type": "string"},
                "max_chars": {"default": 30000, "type": "integer"},
                "lang": {"default": "pol", "type": "string"},
            },
            "required": ["celex"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(text(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
