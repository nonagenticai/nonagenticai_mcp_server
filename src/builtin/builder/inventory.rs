//! The 20 `builder_*` tools' declared surface: the pinned reference's own FastMCP inventory.
//!
//! The builtin tools have no OpenAPI document, so `tests/fixtures/builtin/oracle.json` is their
//! contract. `inventory.json` holds the fixture's `builder_`-prefixed entries copied verbatim
//! (name, description, input schema); it is generated from that fixture and must never be
//! edited by hand. `tests/builtin_builder.rs` proves the registered tools equal the fixture.

use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::{Map, Value};

/// One inventory entry: a tool's wire name, its MCP description and its declared input schema.
#[derive(Debug, Clone, Deserialize)]
pub struct Entry {
    /// The wire name, `builder_{function}`.
    pub name: String,
    /// The MCP tool description the reference declares.
    pub description: String,
    /// The input schema the provider validates and lists.
    pub input_schema: Map<String, Value>,
}

#[derive(Deserialize)]
struct Inventory {
    tools: Vec<Entry>,
}

static INVENTORY: LazyLock<Vec<Entry>> = LazyLock::new(|| {
    serde_json::from_str::<Inventory>(include_str!("inventory.json"))
        .expect("the embedded builder inventory is the generated reference inventory")
        .tools
});

/// The 20 entries, sorted by wire name.
pub fn entries() -> &'static [Entry] {
    &INVENTORY
}

/// One entry by its function suffix (the wire name without the `builder_` namespace).
pub fn entry(function: &str) -> &'static Entry {
    entries()
        .iter()
        .find(|entry| entry.name == format!("builder_{function}"))
        .unwrap_or_else(|| panic!("the inventory holds builder_{function}"))
}
