//! faq tool: namespace `faq`, so `faq_ask`. Answers come from strata_rag `POST /api/ask`.

use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{schema, success, text_argument};

/// strata_rag's `MAX_QUERY_STORES`: the most stores one query may name in `leaf_ids`.
pub const MAX_LEAF_IDS: usize = 256;

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

/// Answer a general question from the knowledge stores, with cited sources.
///
/// `scope` is the already-validated leaf-store filter: strata_rag searches exactly those leaves
/// instead of routing from the tenant's root, and the answer carries `scope.leaf_ids`, the
/// filter applied, which care-bus requires before it uses the answer.
pub async fn ask(
    service: &ServiceClient,
    question: &str,
    scope: Option<Vec<Value>>,
) -> Result<Value, String> {
    let mut body = Map::new();
    body.insert("query".to_owned(), Value::String(question.to_owned()));
    body.insert("route_mode".to_owned(), Value::String("hybrid".to_owned()));
    body.insert("top_k".to_owned(), Value::from(8));
    let applied = scope.map(Value::Array);
    if let Some(stores) = &applied {
        body.insert("leaf_ids".to_owned(), stores.clone());
    }
    let answer = service.post("/api/ask", Value::Object(body)).await?;

    // Citations are chunk UUIDs; the identifying details live in `results`.
    let citations = answer
        .get("citations")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let results = answer
        .get("results")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    // A citation without a result is not a source; the reference's dict lets the LAST result
    // for a chunk id win.
    let sources: Vec<Value> = citations
        .iter()
        .filter_map(|chunk| {
            let position = results
                .iter()
                .rposition(|result| result.get("chunk_id") == Some(chunk))?;
            let result = &results[position];
            Some(json!({
                "chunk_id": chunk,
                "document_id": detail(result, "document_id"),
                "store_path": detail(result, "store_path"),
                "title": detail(result, "title"),
                "source": detail(result, "source"),
                "page_start": detail(result, "page_start"),
                "page_end": detail(result, "page_end"),
            }))
        })
        .collect();

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
                let service = client::strata_rag(&caller)?;
                success(ask(&service, &question, scope).await?)
            })
        }),
    ));
}
