//! The care-bus builtin tools: the reference's 13 tools plus `faq_search`, the retrieval stage
//! care-bus's own answer composition calls, `ebook_request`, the website channel's book request,
//! and `early_access_request`, the website channel's early-access request.
//!
//! Ported from the reference `src/builtin/carebus/`. Each tool keeps its reference namespace
//! (`crm`, `order`, `delivery`, `rules`, `procedures`, `faq`, `ebook`, `early_access`), so its
//! wire name is
//! `{namespace}_{function}` and the scope tables in [`crate::builtin::scope`] grant it exactly
//! as before. Every tool answers a JSON object as MCP structured content; every failure is a
//! tool error whose text starts with `[retryable] ` or `[permanent] `.
//!
//! The upstream bases, tokens and timeouts come from [`client`]; a missing base refuses rather
//! than panics, and nothing here logs a request body, an argument or a result.

pub mod client;
pub mod crm;
pub mod delivery;
pub mod early_access;
pub mod ebook;
pub mod faq;
pub mod order;
pub mod procedures;
pub mod rules;

use serde_json::{Map, Value};

use crate::builtin::provider::{BuiltinProvider, HandlerResult};
use rmcp::model::CallToolResult;

/// Register the care-bus family — the reference's `mount_carebus`.
pub fn register(provider: &mut BuiltinProvider) {
    crm::register(provider);
    order::register(provider);
    delivery::register(provider);
    rules::register(provider);
    procedures::register(provider);
    faq::register(provider);
    ebook::register(provider);
    early_access::register(provider);
}

/// The MCP success for one tool's JSON answer: the same value as text and as structured
/// content, which is the shape FastMCP produced for the reference.
pub fn success(value: Value) -> HandlerResult {
    Ok(CallToolResult::structured(value))
}

/// One tool's declared input schema, as the provider registers and validates it.
pub fn schema(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .cloned()
        .expect("a care-bus tool schema is a JSON object")
}

/// One argument exactly as it arrived (a missing one is JSON null, so `path_id` owns the
/// refusal).
pub fn argument(arguments: &Map<String, Value>, field: &str) -> Value {
    arguments.get(field).cloned().unwrap_or(Value::Null)
}

/// One argument the provider's schema already proved is a string.
pub fn text_argument(arguments: &Map<String, Value>, field: &str) -> Result<String, String> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("[permanent] invalid {field}: expected a string"))
}

/// One argument the provider's schema already proved is a number.
pub fn number_argument(arguments: &Map<String, Value>, field: &str) -> Result<f64, String> {
    arguments
        .get(field)
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("[permanent] invalid {field}: expected a number"))
}
