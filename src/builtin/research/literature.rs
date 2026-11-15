//! Scientific literature via discovery-engine: `research_literature_search` and
//! `research_literature_record`.
//!
//! discovery-engine (`POST /api/search`) fans one query out to public academic sources (PubMed,
//! Europe PMC, Crossref, Semantic Scholar, arXiv, ...), dedups, stores each hit in its corpus and
//! answers with that corpus id. `GET /api/papers/{id}` reads one stored record back. Only these
//! two read paths are used: no sessions, ingest or push.
//!
//! Every item carries its discovery-engine id (`id`), the upstream ids (`doi`, `pmid`, ...) and a
//! canonical `url`, and the abstract text a quote can be matched against.

use std::collections::HashMap;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::legal::{
    bool_or, child, child_or, enum_or, python_repr, python_str, required_string, schema,
    strip_tags, success, truncate, truthy,
};
use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    CallRequest, Clients, MAX_PER_SOURCE, Service, call_json, dedupe, external_ids, int_or,
    optional_int, optional_strings, or_value,
};

/// The adapters the live engine has enabled (GET /api/search/sources, 2026-10-23); openalex,
/// core and google_books are registered there but not configured, so they would only ever fail.
pub const SOURCES: &[&str] = &[
    "pubmed",
    "europe_pmc",
    "crossref",
    "semantic_scholar",
    "arxiv",
    "openlibrary",
];
/// The engine's sort orders.
pub const SORT_BY: &[&str] = &["relevance", "citation_count", "year"];

/// Abstracts from Crossref / Europe PMC carry JATS/HTML markup; return plain text.
fn text(value: &Value) -> Option<String> {
    let raw = value.as_str()?;
    if raw.is_empty() {
        return None;
    }
    if raw.contains('<') {
        Some(strip_tags(raw))
    } else {
        Some(raw.trim().to_owned())
    }
}

/// Canonical public URL for a record: DOI, then PubMed, PMC, arXiv, then the PDF link. The DOI
/// prefix is normalized so `https://doi.org/x` and `x` both answer `https://doi.org/x`.
pub fn source_url(external_ids: &Map<String, Value>, pdf_url: Option<&str>) -> Option<String> {
    let mut ids: HashMap<String, String> = HashMap::new();
    for (key, value) in external_ids {
        if truthy(value) {
            ids.insert(key.clone(), python_str(value));
        }
    }
    if let Some(doi) = ids.get("doi") {
        let doi = doi.strip_prefix("https://doi.org/").unwrap_or(doi.as_str());
        return Some(format!("https://doi.org/{doi}"));
    }
    if let Some(pmid) = ids.get("pmid").or_else(|| ids.get("pubmed_id")) {
        return Some(format!("https://pubmed.ncbi.nlm.nih.gov/{pmid}/"));
    }
    if let Some(pmcid) = ids.get("pmcid") {
        return Some(format!(
            "https://www.ncbi.nlm.nih.gov/pmc/articles/{pmcid}/"
        ));
    }
    if let Some(arxiv) = ids.get("arxiv_id").or_else(|| ids.get("arxiv")) {
        return Some(format!("https://arxiv.org/abs/{arxiv}"));
    }
    pdf_url.filter(|url| !url.is_empty()).map(str::to_owned)
}

/// The reference's `_authors`: a dict contributes its truthy `name`, anything else is its own
/// name, and every name is rendered with Python's `str`.
fn authors(value: &Value) -> Vec<Value> {
    let mut names = Vec::new();
    let Some(items) = value.as_array() else {
        return names;
    };
    for author in items {
        let name = match author {
            Value::Object(fields) => fields.get("name"),
            other => Some(other),
        };
        if let Some(name) = name
            && truthy(name)
        {
            names.push(Value::String(python_str(name)));
        }
    }
    names
}

/// The reference's `_year`: a missing year is null, a present one must be 1000-2100.
fn year(field: &str, value: i64) -> Result<i64, String> {
    if (1000..=2100).contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "[permanent] invalid {field}: expected a year 1000-2100"
        ))
    }
}

/// The reference's `_paper_id`: a UUID in canonical form, else `[permanent] invalid id`.
fn paper_id(value: &str) -> Result<String, String> {
    match uuid::Uuid::parse_str(value) {
        Ok(uuid) => Ok(uuid.to_string()),
        Err(_) => {
            let shown: String = value.chars().take(60).collect();
            Err(format!(
                "[permanent] invalid id: {} (expected a uuid)",
                python_repr(&Value::String(shown))
            ))
        }
    }
}

/// One search hit, as `research_literature_search` returns it.
fn search_item(raw: &Value, abstract_max_chars: usize) -> Value {
    let ext = external_ids(child(raw, "external_ids"));
    let abstract_text = text(child(raw, "abstract")).unwrap_or_default();
    let (abstract_text, truncated) = truncate(&abstract_text, abstract_max_chars);
    let mut out = Map::new();
    out.insert(
        "id".to_owned(),
        or_value(child(raw, "id"), child(raw, "paper_id")),
    );
    out.insert("title".to_owned(), child(raw, "title").clone());
    out.insert(
        "authors".to_owned(),
        Value::Array(authors(child(raw, "authors"))),
    );
    out.insert("year".to_owned(), child(raw, "year").clone());
    out.insert("venue".to_owned(), child(raw, "venue").clone());
    out.insert(
        "doi".to_owned(),
        ext.get("doi").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "pmid".to_owned(),
        ext.get("pmid")
            .or_else(|| ext.get("pubmed_id"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert("external_ids".to_owned(), Value::Object(ext.clone()));
    out.insert(
        "url".to_owned(),
        source_url(&ext, child(raw, "pdf_url").as_str())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert("pdf_url".to_owned(), child(raw, "pdf_url").clone());
    out.insert("source".to_owned(), child(raw, "source").clone());
    out.insert(
        "citation_count".to_owned(),
        child(raw, "citation_count").clone(),
    );
    out.insert(
        "abstract".to_owned(),
        if abstract_text.is_empty() {
            Value::Null
        } else {
            Value::String(abstract_text)
        },
    );
    out.insert("abstract_truncated".to_owned(), Value::Bool(truncated));
    Value::Object(out)
}

/// Search scientific literature in one federated query.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let query = required_string(arguments, "query")?;
    if query.trim().is_empty() || query.chars().count() > 1000 {
        return Err("[permanent] query must be 1-1000 chars".to_owned());
    }
    let year_min = optional_int(arguments, "year_min")?
        .map(|value| year("year_min", value))
        .transpose()?;
    let year_max = optional_int(arguments, "year_max")?
        .map(|value| year("year_max", value))
        .transpose()?;
    if let (Some(min), Some(max)) = (year_min, year_max)
        && min > max
    {
        return Err("[permanent] year_min is after year_max".to_owned());
    }
    let sources = optional_strings(arguments, "sources", SOURCES)?;
    let max_results_per_source = int_or(arguments, "max_results_per_source", 3)?;
    let open_access_only = bool_or(arguments, "open_access_only", false)?;
    let sort_by = enum_or(arguments, "sort_by", "relevance", SORT_BY)?;
    let abstract_max_chars = int_or(arguments, "abstract_max_chars", 1500)?.clamp(200, 20_000);
    let abstract_max_chars = usize::try_from(abstract_max_chars).unwrap_or(200);

    let mut filters = Map::new();
    if let Some(year_min) = year_min {
        filters.insert("year_min".to_owned(), Value::from(year_min));
    }
    if let Some(year_max) = year_max {
        filters.insert("year_max".to_owned(), Value::from(year_max));
    }
    if let Some(sources) = sources.filter(|sources| !sources.is_empty()) {
        let sources: Vec<Value> = dedupe(sources).into_iter().map(Value::String).collect();
        filters.insert("sources".to_owned(), Value::Array(sources));
    }
    let requested_query = query.trim().to_owned();
    let mut body = Map::new();
    body.insert("query".to_owned(), Value::String(requested_query.clone()));
    body.insert("sources".to_owned(), Value::Object(filters));
    body.insert(
        "max_results_per_source".to_owned(),
        Value::from(max_results_per_source.clamp(1, MAX_PER_SOURCE)),
    );
    body.insert("open_access_only".to_owned(), Value::Bool(open_access_only));
    body.insert("sort_by".to_owned(), Value::String(sort_by));

    let answer = call_json(
        clients,
        Service::DiscoveryEngine,
        "POST",
        "/api/search",
        CallRequest {
            body: Some(Value::Object(body)),
            not_found: None,
            ..CallRequest::default()
        },
    )
    .await?;

    let items: Vec<Value> = child(&answer, "results")
        .as_array()
        .map(|results| {
            results
                .iter()
                .map(|raw| search_item(raw, abstract_max_chars))
                .collect()
        })
        .unwrap_or_default();
    let mut out = Map::new();
    out.insert(
        "query".to_owned(),
        child_or(&answer, "query", &Value::String(requested_query)).clone(),
    );
    out.insert(
        "total".to_owned(),
        child_or(&answer, "total_results", &Value::from(items.len())).clone(),
    );
    out.insert(
        "sources_queried".to_owned(),
        child_or(&answer, "sources_queried", &json!([])).clone(),
    );
    out.insert(
        "sources_failed".to_owned(),
        child_or(&answer, "sources_failed", &json!([])).clone(),
    );
    out.insert("items".to_owned(), Value::Array(items));
    Ok(Value::Object(out))
}

/// One literature record by the `id` a search returned.
pub async fn record(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let raw_id = required_string(arguments, "id")?;
    let paper_id = paper_id(&raw_id)?;
    let answer = call_json(
        clients,
        Service::DiscoveryEngine,
        "GET",
        &format!("/api/papers/{paper_id}"),
        CallRequest {
            not_found: Some("paper not found"),
            ..CallRequest::default()
        },
    )
    .await?;

    let ext = external_ids(child(&answer, "external_ids"));
    let mut author_values = Vec::new();
    if let Some(items) = child(&answer, "authors").as_array() {
        for author in items {
            let Some(fields) = author.as_object() else {
                continue;
            };
            let Some(name) = fields.get("name").filter(|name| truthy(name)) else {
                continue;
            };
            let mut out = Map::new();
            out.insert("name".to_owned(), name.clone());
            out.insert(
                "affiliation".to_owned(),
                fields.get("affiliation").cloned().unwrap_or(Value::Null),
            );
            author_values.push(Value::Object(out));
        }
    }
    let mut out = Map::new();
    out.insert(
        "id".to_owned(),
        child_or(&answer, "id", &Value::String(paper_id)).clone(),
    );
    out.insert("title".to_owned(), child(&answer, "title").clone());
    out.insert("authors".to_owned(), Value::Array(author_values));
    out.insert("year".to_owned(), child(&answer, "year").clone());
    out.insert("venue".to_owned(), child(&answer, "venue").clone());
    out.insert(
        "doi".to_owned(),
        ext.get("doi").cloned().unwrap_or(Value::Null),
    );
    out.insert(
        "pmid".to_owned(),
        ext.get("pmid")
            .or_else(|| ext.get("pubmed_id"))
            .cloned()
            .unwrap_or(Value::Null),
    );
    out.insert("external_ids".to_owned(), Value::Object(ext.clone()));
    out.insert(
        "url".to_owned(),
        source_url(&ext, child(&answer, "pdf_url").as_str())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert("pdf_url".to_owned(), child(&answer, "pdf_url").clone());
    out.insert(
        "is_open_access".to_owned(),
        child(&answer, "is_open_access").clone(),
    );
    out.insert(
        "citation_count".to_owned(),
        child(&answer, "citation_count").clone(),
    );
    out.insert(
        "abstract".to_owned(),
        text(child(&answer, "abstract"))
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    Ok(Value::Object(out))
}

/// Register the two literature tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "research",
        "literature_search",
        "Search scientific literature (PubMed, Europe PMC, Crossref, Semantic Scholar, arXiv, ...)\n\
         in one federated query. Each item has a stable `id` for research_literature_record, upstream\n\
         ids (doi, pmid), a canonical `url` and the abstract. Default sources: all the engine has\n\
         enabled; `sources_failed` lists any that errored or are not available. Can take ~10-60 s.\n\
         Abstracts are capped (default 1500 chars) to keep the result small; quote from\n\
         research_literature_record, which returns the full abstract.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "query": {"type": "string"},
                "sources": {
                    "anyOf": [
                        {"items": {"enum": SOURCES, "type": "string"}, "type": "array"},
                        {"type": "null"},
                    ],
                    "default": null,
                },
                "max_results_per_source": {"default": 3, "type": "integer"},
                "year_min": {
                    "anyOf": [{"type": "integer"}, {"type": "null"}],
                    "default": null,
                },
                "year_max": {
                    "anyOf": [{"type": "integer"}, {"type": "null"}],
                    "default": null,
                },
                "open_access_only": {"default": false, "type": "boolean"},
                "sort_by": {
                    "default": "relevance",
                    "enum": SORT_BY,
                    "type": "string",
                },
                "abstract_max_chars": {"default": 1500, "type": "integer"},
            },
            "required": ["query"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "research",
        "literature_record",
        "One literature record by the `id` research_literature_search returned: title, authors\n\
         (with affiliations), year, venue, upstream ids, canonical url and the full abstract.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(record(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ids(value: Value) -> Map<String, Value> {
        value.as_object().cloned().expect("an ids object")
    }

    #[test]
    fn source_url_prefers_doi_then_pubmed_then_pmc_then_arxiv_then_pdf() {
        let cases: Vec<(Value, Option<&str>, Option<&str>)> = vec![
            (
                json!({"doi": "https://doi.org/10.1/x"}),
                None,
                Some("https://doi.org/10.1/x"),
            ),
            (
                json!({"pmid": "1"}),
                None,
                Some("https://pubmed.ncbi.nlm.nih.gov/1/"),
            ),
            (
                json!({"pubmed_id": "2"}),
                None,
                Some("https://pubmed.ncbi.nlm.nih.gov/2/"),
            ),
            (
                json!({"pmcid": "PMC3"}),
                None,
                Some("https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3/"),
            ),
            (
                json!({"arxiv": "2401.1"}),
                None,
                Some("https://arxiv.org/abs/2401.1"),
            ),
            (
                json!({"s2_id": "abc"}),
                Some("https://x/p.pdf"),
                Some("https://x/p.pdf"),
            ),
            (json!({}), None, None),
        ];
        for (external_ids, pdf, expected) in cases {
            assert_eq!(
                source_url(&ids(external_ids), pdf),
                expected.map(str::to_owned)
            );
        }
    }

    #[test]
    fn paper_ids_are_canonical_uuids_or_a_permanent_error() {
        assert_eq!(
            paper_id("01A1673C-78ED-74C8-B7A1-1BF043CEB236").unwrap(),
            "01a1673c-78ed-74c8-b7a1-1bf043ceb236"
        );
        assert!(
            paper_id("../health")
                .unwrap_err()
                .starts_with("[permanent] invalid id: ")
        );
    }
}
