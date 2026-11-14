//! The worker compares its re-serialisation of a run's manifest with the canonical JSON the
//! Python API wrote at admission (`worker::authority::live`).
//!
//! That comparison is byte-for-byte, so `serde_json` must preserve object key order. A plain
//! `BTreeMap` sorts nested `input_schema`/`result_schema` keys while Python preserves the
//! JSONB order, and every bound run is refused as a changed authority. The fixtures are one
//! live coding-run manifest in its stored (JSONB) form and the Python-written snapshot it must
//! round-trip to.

use mcp_server_rs::catalog::models::ToolManifest;

#[test]
fn the_python_canonical_manifest_round_trips_byte_for_byte() {
    let catalog = include_str!("fixtures/phase3b/live_manifest_catalog.json");
    let snapshot = include_str!("fixtures/phase3b/live_manifest_snapshot.json").trim();
    let manifest: ToolManifest = serde_json::from_str(catalog).expect("the stored manifest parses");
    let rendered = serde_json::to_string(&manifest).expect("the manifest serialises");
    assert_eq!(rendered, snapshot);
}
