//! faq tool: namespace `faq`, so `faq_ask`. strata_rag `POST /api/ask` retrieves and generates,
//! one numbered source per document, with the job's persona passed as `instructions`.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{schema, success, text_argument};

/// strata_rag's `MAX_QUERY_STORES`: the most stores one query may name in `leaf_ids`.
pub const MAX_LEAF_IDS: usize = 256;

/// strata_rag's `MAX_INSTRUCTIONS_BYTES`: the job persona, not a second corpus.
pub const MAX_INSTRUCTIONS_BYTES: usize = 16 * 1024;

/// strata_rag's `MAX_ANSWER_TOKENS`.
pub const MAX_ANSWER_TOKENS: u32 = 8192;

/// The reference's tool description, line breaks included.
const ASK_DESCRIPTION: &str = "Answer a general question from the knowledge stores, with cited sources.\n\n\
leaf_ids (care-bus sets it, never the model): search exactly these leaf stores instead of routing\n\
from the tenant's root; care-bus passes the stores outside every legal-matter wall. The answer then\n\
carries scope.leaf_ids, the filter applied, which care-bus requires before it uses the answer.";

/// Validate the store filter: 1..=[`MAX_LEAF_IDS`] uuid strings, returned unchanged.
///
/// This runs before the strata_rag client is resolved, exactly as the reference validates the
/// filter before it looks up `STRATA_RAG_URL`, so a bad filter never reaches the network.
pub fn leaf_ids(value: &Value) -> Result<Vec<Value>, String> {
    let Value::Array(items) = value else {
        return Err(format!(
            "[permanent] leaf_ids must be a list of 1-{MAX_LEAF_IDS} store ids"
        ));
    };
    if items.is_empty() || items.len() > MAX_LEAF_IDS {
        return Err(format!(
            "[permanent] leaf_ids must be a list of 1-{MAX_LEAF_IDS} store ids"
        ));
    }
    let mut stores = Vec::with_capacity(items.len());
    for item in items {
        let Value::String(id) = item else {
            return Err("[permanent] leaf_ids must be store uuids".to_owned());
        };
        if uuid::Uuid::parse_str(id).is_err() {
            return Err("[permanent] leaf_ids must be store uuids".to_owned());
        }
        stores.push(Value::String(id.clone()));
    }
    Ok(stores)
}

/// The optional `instructions` argument: a string when given, never anything else.
fn instructions_argument(arguments: &Map<String, Value>) -> Result<Option<String>, String> {
    match arguments.get("instructions") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(s)) => Ok(Some(s.clone())),
        Some(_) => Err("[permanent] instructions must be a string".to_owned()),
    }
}

/// The optional `max_tokens` argument: a positive integer within strata_rag's bound.
fn max_tokens_argument(arguments: &Map<String, Value>) -> Result<Option<u32>, String> {
    match arguments.get("max_tokens") {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Number(n)) => n
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
            .filter(|n| (1..=MAX_ANSWER_TOKENS).contains(n))
            .map(Some)
            .ok_or_else(|| {
                format!("[permanent] max_tokens must be between 1 and {MAX_ANSWER_TOKENS}")
            }),
        Some(_) => Err("[permanent] max_tokens must be an integer".to_owned()),
    }
}

/// Answer a general question from the knowledge stores, with cited sources.
///
/// `scope` is the already-validated leaf-store filter: strata_rag searches exactly those leaves
/// instead of routing from the tenant's root, and the answer carries `scope.leaf_ids`, the
/// filter applied, which care-bus requires before it uses the answer.
///
/// `instructions` is the job's persona (care-bus's `preamble`/`actor`/`stance`), forwarded so the
/// answer keeps the job's voice while strata_rag generates it. `max_tokens` bounds the answer.
pub async fn ask(
    service: &ServiceClient,
    question: &str,
    scope: Option<Vec<Value>>,
    instructions: Option<&str>,
    max_tokens: Option<u32>,
) -> Result<Value, String> {
    let mut body = Map::new();
    body.insert("query".to_owned(), Value::String(question.to_owned()));
    body.insert("route_mode".to_owned(), Value::String("hybrid".to_owned()));
    body.insert("top_k".to_owned(), Value::from(8));
    if let Some(i) = instructions.map(str::trim).filter(|i| !i.is_empty()) {
        if i.len() > MAX_INSTRUCTIONS_BYTES {
            return Err(format!(
                "[permanent] instructions must be at most {MAX_INSTRUCTIONS_BYTES} bytes"
            ));
        }
        body.insert("instructions".to_owned(), Value::String(i.to_owned()));
    }
    if let Some(n) = max_tokens {
        if !(1..=MAX_ANSWER_TOKENS).contains(&n) {
            return Err(format!(
                "[permanent] max_tokens must be between 1 and {MAX_ANSWER_TOKENS}"
            ));
        }
        body.insert("max_tokens".to_owned(), Value::from(n));
    }
    let applied = scope.map(Value::Array);
    if let Some(stores) = &applied {
        body.insert("leaf_ids".to_owned(), stores.clone());
    }
    let answer = service.post("/api/ask", Value::Object(body)).await?;
    let (sources, citations) = document_sources(&answer);

    let mut out = Map::new();
    out.insert(
        "answer".to_owned(),
        answer
            .get("answer")
            .cloned()
            .unwrap_or_else(|| Value::String(String::new())),
    );
    out.insert("citations".to_owned(), Value::Array(citations));
    out.insert("sources".to_owned(), Value::Array(sources));
    out.insert(
        "timings_ms".to_owned(),
        answer
            .get("timings_ms")
            .cloned()
            .unwrap_or_else(|| Value::Object(Map::new())),
    );
    if let Some(stores) = applied {
        out.insert("scope".to_owned(), json!({"leaf_ids": stores}));
    }
    Ok(Value::Object(out))
}

/// One source per **cited document**, in strata_rag's `documents` order, and one citation (the
/// document's first cited chunk) per source.
///
/// The source carries the document's retrieved passages joined as the model read them under that
/// number, so a downstream step that needs the text (and the case record) has it. An older strata
/// without `documents` is grouped from the cited chunks by `document_id` instead.
fn document_sources(answer: &Value) -> (Vec<Value>, Vec<Value>) {
    let results = answer
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let cited: Vec<Value> = answer
        .get("citations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let text_of = |id: &Value| -> String {
        results
            .iter()
            .rfind(|r| r.get("chunk_id") == Some(id))
            .and_then(|r| r.get("text").and_then(Value::as_str))
            .unwrap_or_default()
            .to_string()
    };

    let mut sources = Vec::new();
    let mut citations = Vec::new();
    if let Some(documents) = answer.get("documents").and_then(Value::as_array) {
        for doc in documents {
            let ids: Vec<Value> = doc
                .get("chunk_ids")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            // The document's first cited chunk, in its prompt order, is the representative.
            let Some(first) = ids.iter().find(|id| cited.contains(*id)) else {
                continue;
            };
            let text = ids
                .iter()
                .map(text_of)
                .filter(|t| !t.is_empty())
                .collect::<Vec<_>>()
                .join("\n\n");
            sources.push(json!({
                "number": detail(doc, "number"),
                "chunk_id": first,
                "document_id": detail(doc, "document_id"),
                "store_path": detail(doc, "store_path"),
                "title": detail(doc, "title"),
                "source": detail(doc, "source"),
                "page_start": detail(doc, "page_start"),
                "page_end": detail(doc, "page_end"),
                "text": text,
            }));
            citations.push(first.clone());
        }
        return (sources, citations);
    }

    // Older strata: number documents by first appearance in the citations.
    let mut groups: Vec<(Value, Vec<Value>)> = Vec::new();
    for id in &cited {
        let Some(result) = results.iter().rfind(|r| r.get("chunk_id") == Some(id)) else {
            continue;
        };
        let document = detail(result, "document_id");
        if let Some(position) = groups.iter().position(|(d, _)| *d == document) {
            let ids = &mut groups[position].1;
            if !ids.contains(id) {
                ids.push(id.clone());
            }
        } else {
            groups.push((document, vec![id.clone()]));
        }
    }
    for (n, (document, ids)) in groups.iter().enumerate() {
        let ord = |id: &Value| -> i64 {
            results
                .iter()
                .rfind(|r| r.get("chunk_id") == Some(id))
                .and_then(|r| r.get("ord").and_then(Value::as_i64))
                .unwrap_or(0)
        };
        let mut ordered = ids.clone();
        ordered.sort_by_key(ord);
        let Some(first) = ordered.first().cloned() else {
            continue;
        };
        let result = results
            .iter()
            .rfind(|r| r.get("chunk_id") == Some(&first))
            .cloned()
            .unwrap_or(Value::Null);
        let text = ordered
            .iter()
            .map(text_of)
            .filter(|t| !t.is_empty())
            .collect::<Vec<_>>()
            .join("\n\n");
        sources.push(json!({
            "number": n + 1,
            "chunk_id": first,
            "document_id": document,
            "store_path": detail(&result, "store_path"),
            "title": detail(&result, "title"),
            "source": detail(&result, "source"),
            "page_start": detail(&result, "page_start"),
            "page_end": detail(&result, "page_end"),
            "text": text,
        }));
        citations.push(first);
    }
    (sources, citations)
}

/// One result field, or JSON null when the upstream omits it (`page_start` is null for a
/// document without pages).
fn detail(result: &Value, field: &str) -> Value {
    result.get(field).cloned().unwrap_or(Value::Null)
}

/// Register the faq tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "faq",
        "ask",
        ASK_DESCRIPTION,
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "question": {"type": "string"},
                "leaf_ids": {
                    "anyOf": [
                        {"items": {"type": "string"}, "type": "array"},
                        {"type": "null"},
                    ],
                    "default": null,
                },
                "instructions": {
                    "anyOf": [{"type": "string"}, {"type": "null"}],
                    "default": null,
                },
                "max_tokens": {
                    "anyOf": [
                        {"maximum": MAX_ANSWER_TOKENS, "minimum": 1, "type": "integer"},
                        {"type": "null"},
                    ],
                    "default": null,
                },
            },
            "required": ["question"],
        })),
        Arc::new(|caller, arguments| {
            boxed(async move {
                let question = text_argument(&arguments, "question")?;
                // Validate the filter first: the reference refuses a bad one before it
                // resolves the strata_rag client.
                let scope = match arguments.get("leaf_ids") {
                    None | Some(Value::Null) => None,
                    Some(value) => Some(leaf_ids(value)?),
                };
                let instructions = instructions_argument(&arguments)?;
                let max_tokens = max_tokens_argument(&arguments)?;
                let service = client::strata_rag(&caller)?;
                success(
                    ask(
                        &service,
                        &question,
                        scope,
                        instructions.as_deref(),
                        max_tokens,
                    )
                    .await?,
                )
            })
        }),
    ));
}
