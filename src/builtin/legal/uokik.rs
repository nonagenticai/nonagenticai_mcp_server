//! Decisions of the President of UOKiK from decyzje.uokik.gov.pl (a Lotus Domino database
//! with no API): `legal_uokik_search`, `legal_uokik_document`.
//!
//! The site's search form redirects to a Domino full-text SearchView on the WWW-decyzje view;
//! this module builds that same GET. A decision is the document
//! `/bp/dec_prez.nsf/1/{UNID}?editDocument&act=Decyzja`, whose metadata table links the
//! decision text as PDF attachments.
//!
//! Both tools are gated by `LEGAL_UOKIK_ENABLED` (default off), as the reference does: the
//! owner's intent is that uokik.gov.pl's robots.txt disallows AI agents, so the family hides
//! the tools entirely unless the gate is on.

use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, MAX_PDF_BYTES, Service, argument, cached, check_text, clamp_max_chars, clamp_page,
    clean, dotted_date, encode_segment, fetch_pdf, finish, int_or, optional_string, pdf_text,
    remember, schema, success,
};

/// A Domino document id: 32 hex characters.
static UNID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[0-9A-Fa-f]{32}\z").expect("the UOKiK unid pattern is valid"));
static ROW: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)<TR\s*>").expect("the UOKiK row pattern is valid"));
static SEARCH_LINK: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)HREF="?/bp/dec_prez\.nsf/1/([0-9A-F]{32})\?editDocument[^>]*>(.*?)</a>"#)
        .expect("the UOKiK search-link pattern is valid")
});
static SEARCH_WHEN: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)Data decyzji:\s*</b>\s*([\d.]+)")
        .expect("the UOKiK search date pattern is valid")
});
static SEARCH_PARTIES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)Data decyzji:\s*</b>\s*[\d.]+\s*<br>(.*?)<br>\s*<b>Rodzaj")
        .expect("the UOKiK search participants pattern is valid")
});
static SEARCH_PRACTICE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)Rodzaj praktyki:\s*</b>(.*?)</text>")
        .expect("the UOKiK search practice pattern is valid")
});
static DECISION_ROW: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<tr[^>]*>\s*<td[^>]*>\s*<b>(.*?):?</b>\s*</td>\s*<td[^>]*>(.*?)</td>")
        .expect("the UOKiK decision-row pattern is valid")
});
static DECISION_PDF: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)href="(/bp/dec_prez\.nsf/[^"]*/\$FILE/[^"]+\.pdf)""#)
        .expect("the UOKiK decision-pdf pattern is valid")
});
static RELATED_JUDGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r#"(?is)HREF="/bp/wyroki\.nsf/0/([0-9A-F]{32})\?editDocument&act=Wyrok">(.*?)</a>\s*<BR>\s*<b>Data wyroku:\s*</B>\s*([\d.]+)"#,
    )
    .expect("the UOKiK related-judgment pattern is valid")
});
static US_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\d{1,2})/(\d{1,2})/(\d{4})").expect("the UOKiK US date pattern is valid")
});

/// Attachments read per decision.
const MAX_PDFS: usize = 3;
/// All attachments of one decision together (each one is also capped at `MAX_PDF_BYTES`).
const MAX_DECISION_PDF_BYTES: usize = 25 * 1024 * 1024;

/// Domino query-syntax characters a value must not smuggle in (field refs, grouping, quotes).
fn value(text: &str) -> String {
    text.chars()
        .map(|ch| match ch {
            '[' | ']' | '(' | ')' | '"' | '=' | '<' | '>' => ' ',
            other => other,
        })
        .collect::<String>()
        .trim()
        .to_owned()
}

fn doc_path(unid: &str) -> String {
    format!("/bp/dec_prez.nsf/1/{unid}?editDocument&act=Decyzja")
}

/// The reference's `_parse_search`: one item per Domino result row.
pub fn parse_search(page: &str) -> Vec<Value> {
    let mut items: Vec<Value> = Vec::new();
    for row in ROW.split(page).skip(1) {
        let Some(link) = SEARCH_LINK.captures(row) else {
            continue;
        };
        items.push(json!({
            "unid": link[1].to_ascii_uppercase(),
            "decision_number": clean(Some(&Value::String(link[2].to_owned()))),
            "date": SEARCH_WHEN
                .captures(row)
                .and_then(|captures| dotted_date(Some(&captures[1])))
                .map(Value::String)
                .unwrap_or(Value::Null),
            "participants": SEARCH_PARTIES
                .captures(row)
                .map(|captures| clean(Some(&Value::String(captures[1].to_owned()))))
                .unwrap_or(Value::Null),
            "practice": SEARCH_PRACTICE
                .captures(row)
                .map(|captures| clean(Some(&Value::String(captures[1].to_owned()))))
                .unwrap_or(Value::Null),
        }));
    }
    items
}

/// Search decisions of the President of UOKiK.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let words = check_text("query", optional_string(arguments, "query")?, 300)?;
    let number = check_text(
        "decision_number",
        optional_string(arguments, "decision_number")?,
        60,
    )?;
    let signature = check_text("signature", optional_string(arguments, "signature")?, 60)?;
    let participant = check_text(
        "participant",
        optional_string(arguments, "participant")?,
        60,
    )?;
    let mut terms: Vec<String> = vec!["([FORM]=Decyzja)".to_owned()];
    if let Some(number) = &number {
        let sanitized = value(number);
        if !sanitized.is_empty() {
            terms.push(format!("([decyzja_nr] = \"{sanitized}\")"));
        }
    }
    if let Some(signature) = &signature {
        let sanitized = value(signature);
        if !sanitized.is_empty() {
            terms.push(format!("([Sygnatura] contains \"{sanitized}\")"));
        }
    }
    if let Some(participant) = &participant {
        let sanitized = value(participant);
        if !sanitized.is_empty() {
            terms.push(format!(
                "([Uczestnicy_postepowania] contains \"{sanitized}\")"
            ));
        }
    }
    if let Some(words) = &words {
        let sanitized = value(words);
        if !sanitized.is_empty() {
            terms.push(format!("({sanitized})"));
        }
    }
    if terms.len() == 1 {
        return Err(
            "[permanent] give a query, decision_number, signature or participant".to_owned(),
        );
    }
    let (page, page_size) = clamp_page(
        int_or(arguments, "page", 1)?,
        int_or(arguments, "page_size", 20)?,
        50,
    );
    let start = (page - 1).saturating_mul(page_size).saturating_add(1);
    let path = format!(
        "/bp/dec_prez.nsf/WWW-decyzje?SearchView&Query={}&SearchOrder=3&SearchMax=0&Start={start}&Count={page_size}",
        encode_segment(&terms.join(" AND "))
    );
    let client = clients.get(Service::Uokik)?;
    let mut items = parse_search(&client.get_text(&path, None).await?);
    for item in &mut items {
        if let Value::Object(fields) = item {
            let unid = fields
                .get("unid")
                .and_then(Value::as_str)
                .map(str::to_owned);
            if let Some(unid) = unid {
                fields.insert(
                    "url".to_owned(),
                    Value::String(client.url(&doc_path(&unid))),
                );
            }
        }
    }
    let has_more = i64::try_from(items.len()).unwrap_or(i64::MAX) == page_size;
    Ok(json!({ "page": page, "items": items, "has_more": has_more }))
}

/// The document page prints dates as MM/DD/YYYY (the list shows the same day DD.MM.YYYY).
fn us_date(value: Option<&str>) -> Value {
    let Some(captures) = US_DATE.captures(value.unwrap_or_default()) else {
        return Value::Null;
    };
    let month: u32 = match captures[1].parse() {
        Ok(month) => month,
        Err(_) => return Value::Null,
    };
    let day: u32 = match captures[2].parse() {
        Ok(day) => day,
        Err(_) => return Value::Null,
    };
    let year: i32 = match captures[3].parse() {
        Ok(year) => year,
        Err(_) => return Value::Null,
    };
    match chrono::NaiveDate::from_ymd_opt(year, month, day) {
        Some(date) => Value::String(date.format("%Y-%m-%d").to_string()),
        None => Value::Null,
    }
}

/// The reference's `_parse_decision`: the metadata table, its PDF attachments, related
/// judgments.
pub fn parse_decision(page: &str) -> Value {
    let mut fields: Map<String, Value> = Map::new();
    for row in DECISION_ROW.captures_iter(page) {
        fields.insert(
            match clean(Some(&Value::String(row[1].to_owned()))) {
                Value::String(label) => label,
                _ => String::new(),
            },
            Value::String(row[2].to_owned()),
        );
    }
    let pdfs: Vec<String> = fields
        .get("Decyzja")
        .and_then(Value::as_str)
        .map(|cell| {
            DECISION_PDF
                .captures_iter(cell)
                .take(MAX_PDFS)
                .map(|capture| capture[1].to_owned())
                .collect()
        })
        .unwrap_or_default();
    let related: Vec<Value> = RELATED_JUDGMENT
        .captures_iter(page)
        .map(|capture| {
            json!({
                "signature": clean(Some(&Value::String(capture[2].to_owned()))),
                "date": dotted_date(Some(&capture[3]))
                    .map(Value::String)
                    .unwrap_or(Value::Null),
                "unid": capture[1].to_ascii_uppercase(),
            })
        })
        .collect();
    let field = |name: &str| clean(fields.get(name));
    let date = fields
        .get("Data wydania decyzji")
        .and_then(Value::as_str)
        .map(|text| us_date(Some(text)))
        .unwrap_or(Value::Null);
    json!({
        "decision_number": field("Numer decyzji"),
        "date": date,
        "case_signature": field("Sygnatura akt"),
        "participants": field("Uczestnicy postępowania"),
        "practice": field("Rodzaj praktyki"),
        "penalty": field("Kara"),
        "sector": field("Branża"),
        "region": field("Region"),
        "appealed": field("Odwołanie do sądu"),
        "related_judgments": related,
        "pdf_paths": pdfs,
    })
}

/// The reference's document body, factored out so its mapping is testable without a PDF.
pub fn document_value(
    meta: &Map<String, Value>,
    unid: &str,
    texts: &[String],
    pdf_paths: &[String],
    client: &super::PublicClient,
) -> Value {
    let mut doc = Map::new();
    doc.insert("unid".to_owned(), Value::String(unid.to_owned()));
    doc.insert(
        "body".to_owned(),
        Value::String("Prezes Urzędu Ochrony Konkurencji i Konsumentów".to_owned()),
    );
    for (key, value) in meta {
        doc.insert(key.clone(), value.clone());
    }
    doc.insert("text".to_owned(), Value::String(texts.join("\n\n")));
    doc.insert("url".to_owned(), Value::String(client.url(&doc_path(unid))));
    doc.insert(
        "pdf_urls".to_owned(),
        Value::Array(
            pdf_paths
                .iter()
                .map(|path| Value::String(client.url(path)))
                .collect(),
        ),
    );
    Value::Object(doc)
}

/// One UOKiK President's decision by the unid from `legal_uokik_search`.
pub async fn document(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let unid_value = argument(arguments, "unid");
    let Some(unid) = unid_value.as_str() else {
        return Err("[permanent] invalid unid: expected 32 hex characters".to_owned());
    };
    if !UNID.is_match(unid) {
        return Err("[permanent] invalid unid: expected 32 hex characters".to_owned());
    }
    let unid = unid.to_ascii_uppercase();
    let max_chars = clamp_max_chars(int_or(arguments, "max_chars", 25_000)?);
    let key = format!("uokik:{unid}");
    let stored = cached(&key);
    let hit = stored.is_some();
    let doc = match stored {
        Some(doc) => doc,
        None => {
            let client = clients.get(Service::Uokik)?;
            let page = client
                .get_text(&doc_path(&unid), Some("decision not found"))
                .await?;
            let Value::Object(mut meta) = parse_decision(&page) else {
                unreachable!("the parsed decision is an object");
            };
            if meta.get("decision_number").is_none_or(Value::is_null) {
                return Err("[permanent] decision not found (not a decision document)".to_owned());
            }
            let pdf_paths: Vec<String> = meta
                .shift_remove("pdf_paths")
                .and_then(|paths| paths.as_array().cloned())
                .unwrap_or_default()
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect();
            let mut texts: Vec<String> = Vec::new();
            let mut budget = MAX_DECISION_PDF_BYTES;
            for path in &pdf_paths {
                if budget == 0 {
                    return Err(format!(
                        "[permanent] decision PDFs too large in total (max {MAX_DECISION_PDF_BYTES})"
                    ));
                }
                let data = fetch_pdf(
                    &client,
                    path,
                    "decision PDF not found",
                    Some(budget.min(MAX_PDF_BYTES)),
                )
                .await?;
                budget = budget.saturating_sub(data.len());
                texts.push(pdf_text(data).await?);
            }
            let doc = document_value(&meta, &unid, &texts, &pdf_paths, &client);
            remember(&key, doc.clone());
            doc
        }
    };
    Ok(finish(doc, max_chars, hit))
}

/// Register the two UOKiK tools. [`super::register_with`] calls this only when the gate is on.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "uokik_search",
        "Search decisions of the President of UOKiK (competition and consumer protection) on\n\
         decyzje.uokik.gov.pl: full-text words, decision number (\"DDK-1/2016\"), case signature or a\n\
         participant (company) name. Returns unids for legal_uokik_document.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "query": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "decision_number": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "signature": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "participant": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "page": {"default": 1, "type": "integer"},
                "page_size": {"default": 20, "type": "integer"},
            },
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "uokik_document",
        "One UOKiK President's decision by the unid from legal_uokik_search: number, date, case\n\
         signature, participants, practice, penalty, appeal, related court judgments and the decision\n\
         text (plain, from the published PDF). Cite `url`.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "unid": {"type": "string"},
                "max_chars": {"default": 25000, "type": "integer"},
            },
            "required": ["unid"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(document(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
