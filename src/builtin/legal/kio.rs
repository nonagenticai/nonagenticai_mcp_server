//! KIO (Krajowa Izba Odwoławcza) rulings from the UZP search site orzeczenia.uzp.gov.pl,
//! which has no API: `legal_kio_search`, `legal_kio_document`.

use std::sync::{Arc, LazyLock};

use regex::Regex;
use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::{
    Clients, Service, cached, check_text, child, clamp_max_chars, clean, dotted_date, finish,
    html_to_text, int_or, optional_enum, optional_string, polish_date, remember, schema, success,
};

/// The reference's `DocumentType`.
pub const DOCUMENT_TYPES: &[&str] = &["wyrok", "postanowienie", "uchwała"];

static TOTAL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Liczba znalezionych dokument[^:]*:\s*(\d+)")
        .expect("the KIO result-count pattern is valid")
});
static RESULT_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"href="/Home/Details/(\d+)""#).expect("the KIO result-link pattern is valid")
});
static RESULT_FRAGMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"(?is)<p class="fragment">(.*?)</p>"#)
        .expect("the KIO result-fragment pattern is valid")
});
static DETAIL_LABEL: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<label[^>]*>([^<]*)</label>").expect("the KIO details-label pattern is valid")
});
static OUTCOMES: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)Sygnatura akt / Spos[^<]*</label>\s*<ul>(.*?)</ul>")
        .expect("the KIO outcomes pattern is valid")
});
static OUTCOME_ITEM: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?is)<li>(.*?)</li>").expect("the KIO outcome item pattern is valid")
});
static LINK: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?is)<a[^>]*>(.*?)</a>").expect("the KIO link pattern is valid"));
static DETAILS_TITLE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r#"<h2 class="section-title"[^>]*>\s*([^<]+?)\s*<"#)
        .expect("the KIO details-title pattern is valid")
});

/// One labelled detail value: the text after the label, up to its `</p>`, never into the next
/// label (the reference's `<label...>(?:(?!<label).)*?</p>`).
fn field(block: &str, label: &str) -> Value {
    let pattern = format!(
        r"(?is)<label[^>]*>\s*{}:?\s*</label>(.*?)</(?:p|div)>",
        regex::escape(label)
    );
    match Regex::new(&pattern) {
        Ok(regex) => match regex.captures(block) {
            Some(captures) => clean(Some(&Value::String(captures[1].to_owned()))),
            None => Value::Null,
        },
        Err(_) => Value::Null,
    }
}

/// The reference's `clean`-then-string idiom for a captured fragment.
fn cleaned_text(fragment: &str) -> String {
    match clean(Some(&Value::String(fragment.to_owned()))) {
        Value::String(text) => text,
        _ => String::new(),
    }
}

/// The reference's `_parse_results`: the site's total and one item per result block.
pub fn parse_results(page: &str) -> (Value, Vec<Value>) {
    let total = TOTAL
        .captures(page)
        .and_then(|captures| captures[1].parse::<i64>().ok())
        .map(Value::from)
        .unwrap_or(Value::Null);
    let mut items: Vec<Value> = Vec::new();
    for block in page.split("<div class=\"search-list-item\"").skip(1) {
        let Some(id) = RESULT_ID
            .captures(block)
            .and_then(|captures| captures[1].parse::<i64>().ok())
        else {
            continue;
        };
        let snippet = match RESULT_FRAGMENT.captures(block) {
            Some(captures) => clean(Some(&Value::String(captures[1].to_owned()))),
            None => Value::Null,
        };
        items.push(json!({
            "id": id,
            "signature": field(block, "Sygnatura"),
            "document_type": field(block, "Rodzaj dokumentu"),
            "date": match field(block, "Data wydania") {
                Value::String(text) => dotted_date(Some(&text)).map(Value::String).unwrap_or(Value::Null),
                _ => Value::Null,
            },
            "body": field(block, "Organ wydający"),
            "snippet": snippet,
        }));
    }
    (total, items)
}

/// The reference's `links_after`: the anchor texts in the paragraph after a heading.
fn links_after(page: &str, heading: &str) -> Vec<Value> {
    let pattern = format!(r"(?is){}.*?<p[^>]*>(.*?)</p>", regex::escape(heading));
    let Ok(regex) = Regex::new(&pattern) else {
        return Vec::new();
    };
    let Some(captures) = regex.captures(page) else {
        return Vec::new();
    };
    LINK.captures_iter(&captures[1])
        .filter_map(|capture| {
            let text = cleaned_text(&capture[1]);
            if text.is_empty() {
                None
            } else {
                Some(Value::String(text))
            }
        })
        .collect()
}

/// The reference's `_parse_details`: the labelled fields, outcomes, provisions and topics.
pub fn parse_details(page: &str) -> Value {
    let mut fields: Map<String, Value> = Map::new();
    for captures in DETAIL_LABEL.captures_iter(page) {
        let label = cleaned_text(&captures[1]);
        let Some(whole) = captures.get(0) else {
            continue;
        };
        let rest = &page[whole.end()..];
        let lowered = rest.to_ascii_lowercase();
        let Some(close) = lowered.find("</p>") else {
            continue;
        };
        if lowered
            .find("<label")
            .is_some_and(|next_label| next_label < close)
        {
            continue;
        }
        fields.insert(label, clean(Some(&Value::String(rest[..close].to_owned()))));
    }
    let mut signatures: Vec<Value> = Vec::new();
    if let Some(block) = OUTCOMES.captures(page) {
        for item in OUTCOME_ITEM.captures_iter(&block[1]) {
            let text = cleaned_text(&item[1]);
            let (signature, outcome) = match text.split_once(" / ") {
                Some((signature, outcome)) => (signature.trim(), outcome.trim()),
                None => (text.trim(), ""),
            };
            signatures.push(json!({
                "signature": signature,
                "outcome": if outcome.is_empty() {
                    Value::Null
                } else {
                    Value::String(outcome.to_owned())
                },
            }));
        }
    }
    let title_signature = DETAILS_TITLE
        .captures(page)
        .map(|captures| Value::String(captures[1].trim().to_owned()))
        .unwrap_or(Value::Null);
    let mut out = Map::new();
    out.insert("title_signature".to_owned(), title_signature);
    out.insert(
        "body".to_owned(),
        fields.remove("Organ wydający").unwrap_or(Value::Null),
    );
    out.insert(
        "document_type".to_owned(),
        fields.remove("Rodzaj dokumentu").unwrap_or(Value::Null),
    );
    out.insert(
        "date".to_owned(),
        fields
            .remove("Data wydania rozstrzygnięcia")
            .unwrap_or(Value::Null),
    );
    out.insert(
        "chairman".to_owned(),
        fields.remove("Przewodniczący").unwrap_or(Value::Null),
    );
    out.insert(
        "contracting_authority".to_owned(),
        fields.remove("Zamawiający").unwrap_or(Value::Null),
    );
    out.insert(
        "city".to_owned(),
        fields.remove("Miejscowość").unwrap_or(Value::Null),
    );
    out.insert(
        "procedure".to_owned(),
        fields.remove("Tryb postępowania").unwrap_or(Value::Null),
    );
    out.insert(
        "contract_type".to_owned(),
        fields.remove("Rodzaj zamówienia").unwrap_or(Value::Null),
    );
    out.insert("signatures".to_owned(), Value::Array(signatures));
    out.insert(
        "key_provisions".to_owned(),
        Value::Array(links_after(page, "Kluczowe przepisy")),
    );
    out.insert(
        "topics".to_owned(),
        Value::Array(links_after(page, "Zagadnienia merytoryczne")),
    );
    Value::Object(out)
}

/// Search KIO rulings by phrase and/or signature.
pub async fn search(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let phrase = check_text("query", optional_string(arguments, "query")?, 500)?;
    let signature = check_text("signature", optional_string(arguments, "signature")?, 100)?;
    if phrase.is_none() && signature.is_none() {
        return Err("[permanent] give a query or a signature".to_owned());
    }
    let document_type = optional_enum(arguments, "document_type", DOCUMENT_TYPES)?;
    let page = int_or(arguments, "page", 1)?.max(1);
    // The site's form: forms of the phrase, text search, KIO only.
    let mut form: Vec<(String, String)> = Vec::new();
    if let Some(phrase) = phrase {
        form.push(("Phrase".to_owned(), phrase));
    }
    if let Some(signature) = signature {
        form.push(("Sign".to_owned(), signature));
    }
    form.push(("Fle".to_owned(), "1".to_owned()));
    form.push(("SCnt".to_owned(), "1".to_owned()));
    form.push(("Kind".to_owned(), "KIO".to_owned()));
    if let Some(document_type) = document_type {
        form.push(("KIO.DecT".to_owned(), document_type));
    }
    form.push(("Pg".to_owned(), page.to_string()));
    form.push(("CountStats".to_owned(), "True".to_owned()));

    let client = clients.get(Service::Kio)?;
    let reply = client
        .post_form("/Home/GetResults", form, Vec::new(), None)
        .await?;
    let (total, mut items) = parse_results(&reply.text());
    for item in &mut items {
        if let Value::Object(fields) = item
            && let Some(id) = fields.get("id").and_then(Value::as_i64)
        {
            fields.insert(
                "url".to_owned(),
                Value::String(client.url(&format!("/Home/Details/{id}"))),
            );
        }
    }
    Ok(json!({ "total": total, "page": page, "items": items }))
}

/// One KIO ruling by the id from `legal_kio_search`.
pub async fn document(clients: &Clients, arguments: &Map<String, Value>) -> Result<Value, String> {
    let id = int_or(arguments, "id", 0)?;
    if id <= 0 || id >= 1_000_000_000 {
        return Err(format!("[permanent] invalid id: {id}"));
    }
    let max_chars = clamp_max_chars(int_or(arguments, "max_chars", 25_000)?);
    let key = format!("kio:{id}");
    let stored = cached(&key);
    let hit = stored.is_some();
    let doc = match stored {
        Some(doc) => doc,
        None => {
            let client = clients.get(Service::Kio)?;
            let details = client
                .get_text(&format!("/Home/Details/{id}"), Some("ruling not found"))
                .await?;
            let meta = parse_details(&details);
            let body = client
                .get_text(
                    &format!("/Home/ContentHtml/{id}?Kind=KIO"),
                    Some("ruling not found"),
                )
                .await?;
            let text = html_to_text(&body);
            let Value::Object(mut meta) = meta else {
                unreachable!("the parsed details are an object");
            };
            let signatures = meta
                .shift_remove("signatures")
                .unwrap_or_else(|| Value::Array(Vec::new()));
            let title_signature = meta.shift_remove("title_signature").unwrap_or(Value::Null);
            let signature = signatures
                .as_array()
                .and_then(|items| items.first())
                .map(|first| child(first, "signature").clone())
                .unwrap_or(title_signature);
            let raw_date = meta.get("date").cloned().unwrap_or(Value::Null);
            let date = match raw_date.as_str() {
                Some(text) => dotted_date(Some(text)).map(Value::String),
                None => None,
            }
            .or_else(|| {
                polish_date(&text.chars().take(1000).collect::<String>()).map(Value::String)
            })
            .unwrap_or(Value::Null);
            let mut fields = Map::new();
            fields.insert("id".to_owned(), Value::from(id));
            fields.insert("signature".to_owned(), signature);
            fields.insert("signatures".to_owned(), signatures);
            for name in [
                "body",
                "document_type",
                "date",
                "chairman",
                "contracting_authority",
                "city",
                "procedure",
                "contract_type",
                "key_provisions",
                "topics",
            ] {
                fields.insert(
                    name.to_owned(),
                    meta.shift_remove(name).unwrap_or(Value::Null),
                );
            }
            // Replaces the parsed value in place: the reference's `{**meta, "date": ...}`.
            fields.insert("date".to_owned(), date);
            fields.insert("text".to_owned(), Value::String(text));
            fields.insert(
                "url".to_owned(),
                Value::String(client.url(&format!("/Home/Details/{id}"))),
            );
            fields.insert(
                "pdf_url".to_owned(),
                Value::String(client.url(&format!("/Home/PdfContent/{id}?Kind=KIO"))),
            );
            let doc = Value::Object(fields);
            remember(&key, doc.clone());
            doc
        }
    };
    Ok(finish(doc, max_chars, hit))
}

/// Register the two KIO tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "legal",
        "kio_search",
        "Search KIO (National Appeal Chamber, public procurement) rulings on orzeczenia.uzp.gov.pl\n\
         by phrase (e.g. \"rażąco niska cena\", \"art. 224 ust. 1\") and/or signature (\"KIO 2105/22\").\n\
         10 hits per page, most relevant first. Returns ids for legal_kio_document.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "query": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "signature": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                "document_type": {
                    "anyOf": [
                        {"enum": DOCUMENT_TYPES, "type": "string"},
                        {"type": "null"},
                    ],
                    "default": null,
                },
                "page": {"default": 1, "type": "integer"},
            },
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(search(&Clients::from_env(), &arguments).await?) })
        }),
    ));
    provider.register(BuiltinTool::new(
        "legal",
        "kio_document",
        "One KIO ruling by the id from legal_kio_search: signature(s) and outcome, date, body,\n\
         contracting authority, key Pzp provisions and the full ruling text (plain). Cite `url`.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "id": {"type": "integer"},
                "max_chars": {"default": 25000, "type": "integer"},
            },
            "required": ["id"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move { success(document(&Clients::from_env(), &arguments).await?) })
        }),
    ));
}
