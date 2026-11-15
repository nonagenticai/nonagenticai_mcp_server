//! Polish legislation via the Sejm ELI API (api.sejm.gov.pl/eli): `legal_eli_search`,
//! `legal_eli_act`, `legal_eli_act_text`.

use std::collections::HashMap;
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, TtlCache, argument, bool_or, child, child_or, element_text, enum_or,
    html_to_text, int_or, optional_int, optional_string, schema, shown_repr, success, truncate,
    truthy,
};

/// The reference's `_pdf_cache` (`eli.py:183`): parsed consolidated PDFs, keyed by path, eight
/// entries for a day. A PDF is immutable once published, so a repeat citation is free.
static PDF_CACHE: LazyLock<TtlCache> =
    LazyLock::new(|| TtlCache::new(8, Duration::from_secs(24 * 3600)));

/// Empty the consolidated-PDF text cache (the reference's `clear_pdf_cache` test hook).
pub fn clear_pdf_cache() {
    PDF_CACHE.clear();
}

/// The reference's `_ELI`: `DU/1964/59`, `MP/2020/1`.
static ELI_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(DU|MP)/(\d{4})/(\d{1,5})\z").expect("the ELI id pattern is valid")
});

/// "133", "133a", "133^1", "133(1)", "133_1", "133¹" -> the ELI html id suffix.
static ARTICLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A(\d{1,5})([a-z]{0,3})(?:\^(\d{1,2})|\((\d{1,2})\)|_(\d{1,2})|([¹²³⁴⁵⁶⁷⁸⁹⁰]{1,2}))?\z",
    )
    .expect("the article pattern is valid")
});

/// A consolidated PDF file name that may go in a path (no traversal, no query).
static PDF_FILE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z0-9_.-]{1,64}\.pdf\z").expect("the PDF file pattern is valid")
});

/// The reference's `MAX_REFS_PER_GROUP`.
const MAX_REFS_PER_GROUP: usize = 50;
/// The reference's `TJ_GROUP`: the consolidated-texts ("tekst jednolity") reference group.
pub const TJ_GROUP: &str = "Inf. o tekście jednolitym";
/// The reference's `AMENDING_GROUP`.
pub const AMENDING_GROUP: &str = "Akty zmieniające";
/// The reference's `MAX_PDF_BYTES` for a consolidated text.
const MAX_CONSOLIDATED_PDF_BYTES: usize = 40 * 1024 * 1024;

fn in_force(value: &Value) -> Value {
    match value.as_str() {
        Some("IN_FORCE") => Value::Bool(true),
        Some("NOT_IN_FORCE") => Value::Bool(false),
        _ => Value::Null,
    }
}

/// Validate an ELI id ("DU/1964/59") and return its URL path ("/eli/acts/DU/1964/59").
pub fn eli_path(eli: &Value) -> Result<String, String> {
    match eli.as_str() {
        Some(text) if ELI_ID.is_match(text) => Ok(format!("/eli/acts/{text}")),
        _ => Err(format!(
            "[permanent] invalid eli: {} (expected PUBLISHER/YEAR/POSITION, \
             e.g. DU/1964/59; publisher DU or MP)",
            shown_repr(eli)
        )),
    }
}

/// Normalise a caller's article number to the ELI html id suffix after "arti_".
pub fn article_id(article: &Value) -> Result<String, String> {
    let Some(text) = article.as_str() else {
        return Err(format!(
            "[permanent] invalid article: {}",
            shown_repr(article)
        ));
    };
    let lowered = text.trim().to_lowercase();
    let cleaned = lowered.strip_prefix("art.").unwrap_or(&lowered).trim();
    let Some(captures) = ARTICLE.captures(cleaned) else {
        return Err(format!(
            "[permanent] invalid article: {} (expected e.g. 133, 133a, 133^1)",
            shown_repr(article)
        ));
    };
    let number = &captures[1];
    let letters = &captures[2];
    let superscript = captures
        .get(3)
        .or_else(|| captures.get(4))
        .or_else(|| captures.get(5))
        .map(|matched| matched.as_str().to_owned())
        .or_else(|| {
            captures
                .get(6)
                .map(|matched| superscript_digits(matched.as_str()))
        });
    Ok(match superscript {
        Some(superscript) => format!("{number}{letters}_{superscript}"),
        None => format!("{number}{letters}"),
    })
}

fn superscript_digits(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '⁰' => '0',
            '¹' => '1',
            '²' => '2',
            '³' => '3',
            '⁴' => '4',
            '⁵' => '5',
            '⁶' => '6',
            '⁷' => '7',
            '⁸' => '8',
            '⁹' => '9',
            other => other,
        })
        .collect()
}

/// One search hit, exactly the reference's `_item`.
fn item(raw: &Value) -> Value {
    json!({
        "eli": child(raw, "ELI"),
        "title": child(raw, "title"),
        "address": child(raw, "displayAddress"),
        "type": child(raw, "type"),
        "status": child(raw, "status"),
        "in_force": in_force(child(raw, "inForce")),
        "promulgation": child(raw, "promulgation"),
    })
}

/// Search Polish legal acts in the Sejm ELI database.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let title = optional_string(arguments, "title")?;
    let keyword = optional_string(arguments, "keyword")?;
    let year = optional_int(arguments, "year")?;
    let act_type = optional_string(arguments, "type")?;
    let in_force_only = bool_or(arguments, "in_force_only", true)?;
    let publisher = enum_or(arguments, "publisher", "DU", &["DU", "MP"])?;
    let limit = int_or(arguments, "limit", 20)?;
    let offset = int_or(arguments, "offset", 0)?;
    if let Some(year) = year
        && !(1918..=2100).contains(&year)
    {
        return Err(format!("[permanent] invalid year: {year}"));
    }
    for (name, value) in [
        ("title", &title),
        ("keyword", &keyword),
        ("type", &act_type),
    ] {
        if let Some(value) = value
            && value.chars().count() > 200
        {
            return Err(format!("[permanent] {name} too long (max 200 chars)"));
        }
    }
    let mut params: Vec<(&str, String)> = vec![("publisher", publisher)];
    if let Some(value) = title {
        params.push(("title", value));
    }
    if let Some(value) = keyword {
        params.push(("keyword", value));
    }
    if let Some(value) = year {
        params.push(("year", value.to_string()));
    }
    if let Some(value) = act_type {
        params.push(("type", value));
    }
    if in_force_only {
        params.push(("inForce", "1".to_owned()));
    }
    params.push(("limit", limit.clamp(1, 100).to_string()));
    params.push(("offset", offset.max(0).to_string()));

    let client = clients.get(Service::Eli)?;
    let answer = client.get_json("/eli/acts/search", &params, None).await?;
    let total = if answer.get("totalCount").is_some() {
        child(&answer, "totalCount").clone()
    } else {
        child(&answer, "count").clone()
    };
    let items: Vec<Value> = child(&answer, "items")
        .as_array()
        .map(|items| items.iter().map(item).collect())
        .unwrap_or_default();
    Ok(json!({ "total": total, "items": items }))
}

/// The reference's `_refs_from_endpoint`: the references endpoint adds each act's title.
fn refs_from_endpoint(raw: &Value) -> Value {
    let mut groups = Map::new();
    if let Some(entries) = raw.as_object() {
        for (group, values) in entries {
            let mapped: Vec<Value> = values
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_REFS_PER_GROUP)
                        .map(|entry| {
                            json!({
                                "eli": child(child(entry, "act"), "ELI"),
                                "title": child(child(entry, "act"), "title"),
                                "date": child(entry, "date"),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            groups.insert(group.clone(), Value::Array(mapped));
        }
    }
    Value::Object(groups)
}

/// The reference's `_refs_from_act`: the act's own reference list (ids only).
fn refs_from_act(raw: &Value) -> Value {
    let mut groups = Map::new();
    if let Some(entries) = raw.as_object() {
        for (group, values) in entries {
            let mapped: Vec<Value> = values
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .take(MAX_REFS_PER_GROUP)
                        .map(|entry| {
                            json!({
                                "eli": child(entry, "id"),
                                "title": Value::Null,
                                "date": child(entry, "date"),
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            groups.insert(group.clone(), Value::Array(mapped));
        }
    }
    Value::Object(groups)
}

/// Metadata of one Polish act by ELI id.
pub async fn act(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let eli = argument(arguments, "eli");
    let path = eli_path(&eli)?;
    let client = clients.get(Service::Eli)?;
    let references_path = format!("{path}/references");
    let (act_result, references_result) = tokio::join!(
        client.get_json(&path, &[], Some("act not found")),
        client.get_json(&references_path, &[], Some("act not found")),
    );
    let act = act_result?;
    // The references endpoint adds titles; the act's own reference list is the fallback.
    let references = match references_result {
        Ok(references) => refs_from_endpoint(&references),
        Err(_) => refs_from_act(child(&act, "references")),
    };
    let has_html = truthy(child(&act, "textHTML"));
    let keyword_default = Value::Array(Vec::new());
    let keywords = child_or(&act, "keywords", &keyword_default).clone();
    Ok(json!({
        "eli": child_or(&act, "ELI", &eli).clone(),
        "title": child(&act, "title"),
        "address": child(&act, "displayAddress"),
        "type": child(&act, "type"),
        "status": child(&act, "status"),
        "in_force": in_force(child(&act, "inForce")),
        "entry_into_force": child(&act, "entryIntoForce"),
        "valid_from": child(&act, "validFrom"),
        "change_date": child(&act, "changeDate"),
        "has_html": has_html,
        "keywords": keywords,
        "references": references,
        "text_url_html": if has_html {
            Value::String(client.url(&format!("{path}/text.html")))
        } else {
            Value::Null
        },
        "text_url_pdf": if truthy(child(&act, "textPDF")) {
            Value::String(client.url(&format!("{path}/text.pdf")))
        } else {
            Value::Null
        },
    }))
}

/// Plain text of the first element whose id names the article ("arti_133") or one of its
/// paragraphs ("...-arti_133-para_1").
fn article_from_html(html: &str, suffix: &str) -> Option<String> {
    let wanted = format!("arti_{suffix}");
    let dashed = format!("-{wanted}");
    element_text(html, move |_tag, attrs: &HashMap<String, String>| {
        attrs
            .get("id")
            .is_some_and(|id| id.as_str() == wanted.as_str() || id.ends_with(dashed.as_str()))
    })
}

/// The newest consolidated text among the TJ entries, by (promulgation-or-announcement, ELI).
fn newest_consolidation(entries: &[Value]) -> Option<Value> {
    let mut best: Option<(String, String, Value)> = None;
    for entry in entries {
        let act = child(entry, "act");
        let Some(eli) = child(act, "ELI").as_str() else {
            continue;
        };
        if !ELI_ID.is_match(eli) {
            continue;
        }
        let date = if truthy(child(act, "promulgation")) {
            super::python_str(child(act, "promulgation"))
        } else if truthy(child(act, "announcementDate")) {
            super::python_str(child(act, "announcementDate"))
        } else {
            String::new()
        };
        let key = (date, eli.to_owned());
        let replace = match &best {
            None => true,
            Some((best_date, best_eli, _)) => (&key.0, &key.1) > (best_date, best_eli),
        };
        if replace {
            best = Some((key.0, key.1, act.clone()));
        }
    }
    best.map(|(_, _, act)| act)
}

/// Promulgation date of the consolidation before `newest`; None if there is none.
fn previous_promulgation(entries: &[Value], newest: &Value) -> Option<String> {
    let mine = child(newest, "promulgation")
        .as_str()
        .unwrap_or_default()
        .to_owned();
    let mut best: Option<String> = None;
    for entry in entries {
        let act = child(entry, "act");
        if let Some(promulgation) = child(act, "promulgation").as_str()
            && !promulgation.is_empty()
            && promulgation < mine.as_str()
        {
            let replace = best.as_deref().is_none_or(|current| promulgation > current);
            if replace {
                best = Some(promulgation.to_owned());
            }
        }
    }
    best
}

/// The consolidated PDF: `texts[]` type T (Kancelaria Sejmu text), then U, else text.pdf.
fn pdf_path(source_path: &str, meta: &Value) -> String {
    let mut files: HashMap<String, Value> = HashMap::new();
    if let Some(texts) = child(meta, "texts").as_array() {
        for text in texts {
            if let Some(kind) = child(text, "type").as_str() {
                files.insert(kind.to_owned(), child(text, "fileName").clone());
            }
        }
    }
    for kind in ["T", "U"] {
        if let Some(Value::String(name)) = files.get(kind)
            && PDF_FILE.is_match(name)
        {
            return format!("{source_path}/text/{kind}/{name}");
        }
    }
    format!("{source_path}/text.pdf")
}

/// The act's text as originally published (HTML only).
async fn original(
    eli: &str,
    path: &str,
    suffix: Option<&str>,
    article: &Value,
    client: &super::PublicClient,
) -> Result<Value, String> {
    let html = client
        .get_text(&format!("{path}/text.html"), Some("act not found"))
        .await?;
    if html.trim().is_empty() {
        return Err(format!(
            "[permanent] no HTML text (PDF only): {}",
            client.url(&format!("{path}/text.pdf"))
        ));
    }
    let text = match suffix {
        None => html_to_text(&html),
        Some(suffix) => article_from_html(&html, suffix).ok_or_else(|| {
            format!(
                "[permanent] article {} not found in the HTML text of {eli}",
                super::python_str(article)
            )
        })?,
    };
    Ok(json!({
        "text": text,
        "source_eli": eli,
        "source_format": "html",
        "consolidation_date": Value::Null,
        "consolidation_date_inferred": false,
        "amended_after_consolidation": Value::Null,
    }))
}

/// The newest consolidated text ("tekst jednolity"), HTML or else its PDF.
async fn current(
    eli: &str,
    path: &str,
    suffix: Option<&str>,
    article: &Value,
    client: &super::PublicClient,
) -> Result<Value, String> {
    let references = client
        .get_json(&format!("{path}/references"), &[], Some("act not found"))
        .await?;
    let tj_entries = child(&references, TJ_GROUP)
        .as_array()
        .cloned()
        .unwrap_or_default();
    let newest = newest_consolidation(&tj_entries);
    let source_eli = newest
        .as_ref()
        .and_then(|act| child(act, "ELI").as_str().map(str::to_owned))
        .unwrap_or_else(|| eli.to_owned());
    let source_path = eli_path(&Value::String(source_eli.clone()))?;
    let meta = client
        .get_json(&source_path, &[], Some("act not found"))
        .await?;
    // A consolidated text covers amendments published before its cut-off date
    // (legalStatusDate); without one the cut-off is inferred conservatively from the previous
    // consolidation's promulgation, else every amending act is listed.
    let mut inferred = false;
    let mut consolidation_date: Option<String> = None;
    if let Some(newest_act) = &newest {
        let legal_status_date = child(&meta, "legalStatusDate");
        if truthy(legal_status_date) {
            consolidation_date = Some(super::python_str(legal_status_date));
        } else {
            inferred = true;
            consolidation_date = previous_promulgation(&tj_entries, newest_act);
        }
    }
    let mut amended: Vec<Value> = Vec::new();
    for entry in child(&references, AMENDING_GROUP)
        .as_array()
        .cloned()
        .unwrap_or_default()
    {
        let amending = child(&entry, "act");
        let Some(amend_eli) = child(amending, "ELI").as_str() else {
            continue;
        };
        let promulgation = child(amending, "promulgation");
        if truthy(promulgation) {
            let promulgation = super::python_str(promulgation);
            let covered = consolidation_date
                .as_deref()
                .is_some_and(|cut_off| promulgation.as_str() < cut_off);
            if !covered {
                amended.push(json!({
                    "eli": amend_eli,
                    "promulgation": promulgation,
                    "date_unknown": false,
                }));
            }
        } else {
            // A DU/MP position is published in its ELI year, so an act from a year before the
            // cut-off's year is provably covered; otherwise list it.
            let year = if ELI_ID.is_match(amend_eli) {
                amend_eli.split('/').nth(1).unwrap_or_default().to_owned()
            } else {
                String::new()
            };
            let covered = consolidation_date.as_deref().is_some_and(|cut_off| {
                let cut_off_year: String = cut_off.chars().take(4).collect();
                !year.is_empty() && year.as_str() < cut_off_year.as_str()
            });
            if !covered {
                amended.push(json!({
                    "eli": amend_eli,
                    "promulgation": Value::Null,
                    "date_unknown": true,
                }));
            }
        }
    }
    amended.sort_by(|left, right| {
        let left_promulgation = left
            .get("promulgation")
            .and_then(Value::as_str)
            .unwrap_or("9999");
        let right_promulgation = right
            .get("promulgation")
            .and_then(Value::as_str)
            .unwrap_or("9999");
        let left_eli = left.get("eli").and_then(Value::as_str).unwrap_or_default();
        let right_eli = right.get("eli").and_then(Value::as_str).unwrap_or_default();
        (left_promulgation, left_eli).cmp(&(right_promulgation, right_eli))
    });
    let mut source_format = "html";
    let html = if truthy(child(&meta, "textHTML")) {
        client
            .get_text(&format!("{source_path}/text.html"), Some("act not found"))
            .await?
    } else {
        String::new()
    };
    let text: Option<String> = if !html.trim().is_empty() {
        match suffix {
            None => Some(html_to_text(&html)),
            Some(suffix) => article_from_html(&html, suffix),
        }
    } else {
        source_format = "pdf";
        let path = pdf_path(&source_path, &meta);
        // The reference caches the parsed text by path (`eli.py:183,232-243`); its size check
        // runs only on a miss.
        // Its OWN cache: the document cache beside it is the search/doc store, and a 40 MB PDF
        // text must not evict (or be evicted by) a UOKiK document.
        let text = match PDF_CACHE.get(&path) {
            Some(text) => text.as_str().unwrap_or_default().to_owned(),
            None => {
                let full = client
                    .get_bytes(&path, false, Some("consolidated PDF not found"), None)
                    .await?;
                if full.len() > MAX_CONSOLIDATED_PDF_BYTES {
                    return Err(format!(
                        "[permanent] consolidated PDF too large ({} bytes)",
                        full.len()
                    ));
                }
                let text = super::pdf_full_text(full).await?;
                PDF_CACHE.put(path.clone(), Value::String(text.clone()));
                text
            }
        };
        match suffix {
            None => Some(text),
            Some(suffix) => match crate::pdf::cut_article(&text, suffix) {
                Ok(article) => article,
                Err(ambiguous) => {
                    let flat = &ambiguous.0;
                    return Err(format!(
                        "[permanent] article ambiguous: {} -- {} prints it as 'Art. {flat}.' \
                         which could also be a real article {flat}; check the PDF",
                        super::python_str(article),
                        source_eli
                    ));
                }
            },
        }
    };
    let Some(text) = text else {
        return Err(format!(
            "[permanent] article {} not found in {source_eli} ({source_format})",
            super::python_str(article)
        ));
    };
    Ok(json!({
        "text": text,
        "source_eli": source_eli,
        "source_format": source_format,
        "consolidation_date": consolidation_date,
        "consolidation_date_inferred": inferred,
        "amended_after_consolidation": amended,
    }))
}

/// Text of a Polish act by ELI id, optionally one article, current or original wording.
pub async fn act_text(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let eli_value = argument(arguments, "eli");
    let path = eli_path(&eli_value)?;
    let eli = eli_value.as_str().unwrap_or_default().to_owned();
    let article = argument(arguments, "article");
    let suffix = if article.is_null() {
        None
    } else {
        Some(article_id(&article)?)
    };
    let wording = enum_or(arguments, "wording", "current", &["current", "original"])?;
    let max_chars = super::clamp_max_chars_with(int_or(arguments, "max_chars", 30_000)?, 200_000);
    let client = clients.get(Service::Eli)?;
    let output = if wording == "original" {
        original(&eli, &path, suffix.as_deref(), &article, &client).await?
    } else {
        current(&eli, &path, suffix.as_deref(), &article, &client).await?
    };
    let Value::Object(mut fields) = output else {
        unreachable!("an ELI text answer is an object");
    };
    let text = fields
        .shift_remove("text")
        .map(|value| super::python_str(&value))
        .unwrap_or_default();
    let (text, truncated) = truncate(&text, max_chars);
    let mut result = Map::new();
    result.insert("eli".to_owned(), Value::String(eli));
    result.insert("article".to_owned(), article);
    result.insert("wording".to_owned(), Value::String(wording));
    for (key, value) in fields {
        result.insert(key, value);
    }
    result.insert("text".to_owned(), Value::String(text));
    result.insert("truncated".to_owned(), Value::Bool(truncated));
    Ok(Value::Object(result))
}

const SEARCH_DESCRIPTION: &str = "Search Polish legal acts (Dziennik Ustaw / Monitor Polski) in the Sejm ELI database.\n\n\
title: words of the act title (e.g. \"kodeks rodzinny\"); keyword: ELI subject keyword;\n\
type: act type such as \"Ustawa\", \"Rozporządzenie\", \"Obwieszczenie\". Returns ELI ids\n\
(e.g. \"DU/1964/59\") to pass to legal_eli_act / legal_eli_act_text.";

/// Register the three ELI tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "eli_search",
        SEARCH_DESCRIPTION,
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "title": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "keyword": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "year": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": null},
                "type": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "in_force_only": {"default": true, "type": "boolean"},
                "publisher": {"default": "DU", "enum": ["DU", "MP"], "type": "string"},
                "limit": {"default": 20, "type": "integer"},
                "offset": {"default": 0, "type": "integer"},
            },
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "eli_act",
        "Metadata of one Polish act by ELI id (e.g. \"DU/1964/59\"): status, whether it is in force,\n\
         dates, keywords, and related acts (amending acts, consolidated texts \"Inf. o tekście\n\
         jednolitym\", Constitutional Tribunal rulings, ...).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {"eli": {"type": "string"}},
            "required": ["eli"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(act(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "eli_act_text",
        "Text of a Polish act by ELI id; with `article` (\"133\", \"133a\", \"133^1\") only that article.\n\n\
         wording=\"current\" (default): the newest consolidated text (\"tekst jednolity\") of the act,\n\
         HTML or else its PDF. Amendments published after that consolidation are NOT in it; they are\n\
         listed in amended_after_consolidation ({eli, promulgation, date_unknown}) -- tell the reader to\n\
         check them. consolidation_date_inferred=true means the cut-off was not published and a\n\
         conservative earlier date was used, so the list may over-report. Without any\n\
         consolidation the act's own text is used and every amending act is listed.\n\
         wording=\"original\": the act's HTML text as originally published.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "eli": {"type": "string"},
                "article": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "wording": {"default": "current", "enum": ["current", "original"], "type": "string"},
                "max_chars": {"default": 30000, "type": "integer"},
            },
            "required": ["eli"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(act_text(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
