//! Dziennik Urzędowy Województwa Dolnośląskiego (edzienniki.duw.pl): `legal_duw_search`,
//! `legal_duw_document`.
//!
//! There is no published API; the site is an AngularJS front-end over its own JSON endpoints,
//! which these tools call the way the page does: `POST /api/SearchLegalAct` (the server always
//! answers up to 500 positions, so the answer is cached briefly and paged here),
//! `GET /api/legalact` (one position) and `GET /GetActPdf.ashx` (the published PDF).

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, TtlCache, cached, check_text, child, clamp_max_chars, clamp_page,
    fetch_pdf_text, finish, int_or, iso_day, python_str, remember, required_string, schema,
    success, truthy,
};

/// The reference's `JOURNAL`.
pub const JOURNAL: &str = "Dziennik Urzędowy Województwa Dolnośląskiego";
/// The voivodeship (and its journal) exists since 1999.
const FIRST_YEAR: i64 = 1999;

/// (title, year) -> the server's whole answer; it is ~0.5 MB, so paging must not refetch it.
static SEARCH_CACHE: LazyLock<TtlCache> =
    LazyLock::new(|| TtlCache::new(32, Duration::from_secs(3600)));

/// Empty the search cache (the reference's `clear_search_cache` test hook).
pub fn clear_search_cache() {
    SEARCH_CACHE.clear();
}

fn valid_year(year: Option<i64>) -> Result<Option<i64>, String> {
    match year {
        None => Ok(None),
        Some(year) if (FIRST_YEAR..=2100).contains(&year) => Ok(Some(year)),
        Some(year) => Err(format!("[permanent] invalid year: {year}")),
    }
}

/// The canonical, citable position URL `/legalact/{year}/{position}/`.
fn position_url(client: &super::PublicClient, year: &Value, position: &Value) -> String {
    client.url(&format!(
        "/legalact/{}/{}/",
        python_str(year),
        python_str(position)
    ))
}

/// Search the Dolnośląskie official journal by words of the act title.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let title = check_text("query", Some(required_string(arguments, "query")?), 200)?;
    let Some(title) = title else {
        return Err("[permanent] query must be 1-200 chars".to_owned());
    };
    let year = valid_year(super::optional_int(arguments, "year")?)?;
    let (page, page_size) = clamp_page(
        int_or(arguments, "page", 1)?,
        int_or(arguments, "page_size", 20)?,
        50,
    );
    let key = format!(
        "{}|{}",
        title.to_lowercase(),
        year.map(|year| year.to_string()).unwrap_or_default()
    );
    let client = clients.get(Service::Duw)?;
    let answer = match SEARCH_CACHE.get(&key) {
        Some(answer) => answer,
        None => {
            let mut body = Map::new();
            body.insert("Title".to_owned(), Value::String(title));
            body.insert("PageNumber".to_owned(), Value::from(1));
            body.insert("SelectedKeywords".to_owned(), Value::Array(Vec::new()));
            body.insert("SelectedLegalActType".to_owned(), Value::Array(Vec::new()));
            body.insert("PublisherName".to_owned(), Value::String(String::new()));
            if let Some(year) = year {
                body.insert("Year".to_owned(), Value::from(year));
            }
            let reply = client
                .post_json(
                    "/api/SearchLegalAct",
                    Value::Object(body),
                    vec![("Accept", "application/json".to_owned())],
                )
                .await?;
            let answer: Value = serde_json::from_slice(&reply.body).map_err(|_| {
                "[retryable] non-JSON answer from POST /api/SearchLegalAct".to_owned()
            })?;
            if !answer.is_object() {
                return Err(
                    "[retryable] unexpected answer from POST /api/SearchLegalAct".to_owned(),
                );
            }
            SEARCH_CACHE.put(key, answer.clone());
            answer
        }
    };
    let acts: Vec<Value> = child(&answer, "LegalActs")
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item.is_object())
                .cloned()
                .collect()
        })
        .unwrap_or_default();
    let start = usize::try_from((page - 1).saturating_mul(page_size)).unwrap_or(usize::MAX);
    let size = usize::try_from(page_size).unwrap_or_default();
    let items: Vec<Value> = acts
        .iter()
        .skip(start)
        .take(size)
        .map(|act| {
            json!({
                "year": child(act, "Year"),
                "position": child(act, "Position"),
                "title": child(act, "Title"),
                "act_type": child(act, "LegalActType"),
                "number": child(act, "CaseNumber"),
                "publisher": child(act, "Publisher"),
                "act_date": iso_day(child(act, "ActDate")),
                "publication_date": iso_day(child(act, "PublicationDate")),
                "url": position_url(&client, child(act, "Year"), child(act, "Position")),
            })
        })
        .collect();
    let shown = i64::try_from(acts.len()).unwrap_or(i64::MAX);
    Ok(json!({
        "total": child(&answer, "TotalItems"),
        "returned_by_source": shown,
        "page": page,
        "items": items,
        "has_more": page.saturating_mul(page_size) < shown,
    }))
}

/// The reference's document body, factored out so its mapping is testable without a PDF.
pub fn document_value(
    meta: &Value,
    year: i64,
    position: i64,
    text: String,
    client: &super::PublicClient,
) -> Value {
    let status = child(meta, "ActStatus");
    let publishers: Vec<Value> = child(meta, "Publishers")
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|publisher| {
                    let name = child(publisher, "Name");
                    if truthy(name) {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let publisher = publishers
        .first()
        .cloned()
        .unwrap_or_else(|| child(meta, "PublisherGenetive").clone());
    let keywords: Vec<Value> = child(meta, "Keywords")
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(|keyword| {
                    let name = child(keyword, "Name");
                    if truthy(name) {
                        Some(name.clone())
                    } else {
                        None
                    }
                })
                .collect()
        })
        .unwrap_or_default();
    let description = child(status, "Description");
    let status_note = if truthy(description) {
        description.clone()
    } else {
        Value::Null
    };
    let pdf_path = format!("/GetActPdf.ashx?year={year}&book=0&position={position}");
    json!({
        "year": year,
        "position": position,
        "journal": JOURNAL,
        "position_number": child(meta, "ActPositionNumber"),
        "title": child(meta, "Title"),
        "act_type": child(meta, "LegalActType"),
        "number": child(meta, "CaseNumber"),
        "publisher": publisher,
        "act_date": iso_day(child(meta, "ActDate")),
        "publication_date": iso_day(child(meta, "PublicationDate")),
        "keywords": keywords,
        "invalid": truthy(child(status, "IsInvalid")),
        "partially_invalid": truthy(child(status, "IsPartialInvalid")),
        "status_note": status_note,
        "text": text,
        "url": client.url(&format!("/legalact/{year}/{position}/")),
        "pdf_url": client.url(&pdf_path),
    })
}

/// One position of the Dolnośląskie official journal by (year, position).
pub async fn document(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let year = valid_year(Some(int_or(arguments, "year", 0)?))?.unwrap_or_default();
    let position = int_or(arguments, "position", 0)?;
    if position <= 0 || position >= 1_000_000 {
        return Err(format!("[permanent] invalid position: {position}"));
    }
    let max_chars = clamp_max_chars(int_or(arguments, "max_chars", 25_000)?);
    let key = format!("duw:{year}:{position}");
    let stored = cached(&key);
    let hit = stored.is_some();
    let doc = match stored {
        Some(doc) => doc,
        None => {
            let client = clients.get(Service::Duw)?;
            let meta = client
                .get_json(
                    "/api/legalact",
                    &[
                        ("year", year.to_string()),
                        ("journal", "0".to_owned()),
                        ("position", position.to_string()),
                    ],
                    Some("journal position not found"),
                )
                .await?;
            if !meta.is_object() {
                return Err("[retryable] unexpected answer from GET /api/legalact".to_owned());
            }
            let pdf_path = format!("/GetActPdf.ashx?year={year}&book=0&position={position}");
            let text = fetch_pdf_text(&client, &pdf_path, "act PDF not found").await?;
            let doc = document_value(&meta, year, position, text, &client);
            remember(&key, doc.clone());
            doc
        }
    };
    Ok(finish(doc, max_chars, hit))
}

/// Register the two DUW tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "duw_search",
        "Search the official journal of the Dolnośląskie voivodeship (local law: municipal and\n\
         county resolutions, voivode orders) by words of the act title, optionally one year. Newest\n\
         first. Returns (year, position) for legal_duw_document.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "query": {"type": "string"},
                "year": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": null},
                "page": {"default": 1, "type": "integer"},
                "page_size": {"default": 20, "type": "integer"},
            },
            "required": ["query"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "duw_document",
        "One position of the Dolnośląskie official journal by (year, position): title, act type\n\
         and number, issuing body, act and publication dates, keywords, status and the act text\n\
         (plain, from the published PDF). Cite `url`.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "year": {"type": "integer"},
                "position": {"type": "integer"},
                "max_chars": {"default": 25000, "type": "integer"},
            },
            "required": ["year", "position"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(document(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
