//! The execution domain against the Python oracle.
//!
//! `tests/fixtures/phase3a/oracle.json` was generated from the pinned reference service
//! (`nonagenticai_mcp_server-python-archive`, pin `22ac1ce4`). The Python worker deserialises
//! the stored `authority` column and re-derives `input_hash` from the same canonical JSON, so
//! every case here is a wire-compatibility requirement, not a local convention.

use chrono::{DateTime, Utc};
use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::catalog::models::{Runtime, ToolManifest};
use mcp_server_rs::catalog::resolver::ResolvedTool;
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool};
use mcp_server_rs::execution::{
    RunRow, RunStatus, attribution, authority_snapshot, envelope, parse_actor, value_hash,
};
use serde_json::{Map, Value};

fn oracle() -> Value {
    serde_json::from_str(include_str!("fixtures/phase3a/oracle.json")).expect("the oracle parses")
}

fn cases<'a>(oracle: &'a Value, group: &str) -> &'a [Value] {
    oracle[group]
        .as_array()
        .expect("the group is an array")
        .as_slice()
}

fn name(case: &Value) -> &str {
    case["name"].as_str().expect("every case is named")
}

fn uuid(value: &Value) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(value.as_str().expect("a uuid string")).expect("a valid uuid")
}

fn instant(value: &Value) -> DateTime<Utc> {
    serde_json::from_value(value.clone()).expect("an RFC 3339 instant")
}

fn jsonb(value: &Value) -> Option<Value> {
    if value.is_null() {
        None
    } else {
        Some(value.clone())
    }
}

/// The fixture row objects carry the columns the API reads; the storage slice replaces this
/// decoder with the sqlx one.
fn row_from_json(row: &Value) -> RunRow {
    RunRow {
        run_id: uuid(&row["run_id"]),
        tenant_id: uuid(&row["tenant_id"]),
        gateway_license_id: uuid(&row["gateway_license_id"]),
        owner_tenant_id: uuid(&row["owner_tenant_id"]),
        tool_id: uuid(&row["tool_id"]),
        binding_id: jsonb(&row["binding_id"]).as_ref().map(uuid),
        binding_revision: row.get("binding_revision").and_then(Value::as_i64),
        credential_profile_id: row
            .get("credential_profile_id")
            .and_then(jsonb)
            .as_ref()
            .map(uuid),
        profile_snapshot: row["profile_snapshot"].clone(),
        tool_version: i32::try_from(row["tool_version"].as_i64().expect("an integer"))
            .expect("an i32"),
        authority: row["authority"].clone(),
        inputs: row["inputs"].clone(),
        input_hash: row["input_hash"].as_str().expect("a digest").to_owned(),
        idempotency_key: row
            .get("idempotency_key")
            .and_then(Value::as_str)
            .map(str::to_owned),
        created_by: row["created_by"].clone(),
        status: RunStatus::parse(row["status"].as_str().expect("a status")).expect("a DDL status"),
        created_at: instant(&row["created_at"]),
        queue_deadline: instant(&row["queue_deadline"]),
        started_at: row.get("started_at").and_then(jsonb).as_ref().map(instant),
        finished_at: row.get("finished_at").and_then(jsonb).as_ref().map(instant),
        cancel_requested: row["cancel_requested"].as_bool().expect("a bool"),
        result: jsonb(&row["result"]),
        error: jsonb(&row["error"]),
        payload_expired_at: row
            .get("payload_expired_at")
            .and_then(jsonb)
            .as_ref()
            .map(instant),
        mode: row["mode"].as_str().expect("a mode").to_owned(),
        runtime: serde_json::from_value::<Runtime>(row["runtime"].clone()).expect("a runtime"),
        external_ref: jsonb(&row["external_ref"]),
        status_message: row
            .get("status_message")
            .and_then(Value::as_str)
            .map(str::to_owned),
        actor: jsonb(&row["actor"]),
    }
}

#[test]
fn value_hash_matches_the_oracle() {
    let oracle = oracle();
    let cases = cases(&oracle, "value_hash");
    assert_eq!(cases.len(), 12, "the oracle's value_hash cases");
    for case in cases {
        assert_eq!(
            value_hash(&case["value"]),
            case["sha256"].as_str().expect("a digest"),
            "value_hash {}",
            name(case)
        );
    }
}

#[test]
fn envelope_matches_the_oracle() {
    let oracle = oracle();
    let cases = cases(&oracle, "envelope");
    assert_eq!(cases.len(), 4, "the oracle's envelope cases");
    for case in cases {
        let row = row_from_json(&case["row"]);
        assert_eq!(
            &envelope(&row),
            &case["expected"],
            "envelope {}",
            name(case)
        );
    }
}

#[test]
fn actor_matches_the_oracle() {
    let oracle = oracle();
    let cases = cases(&oracle, "actor");
    assert_eq!(cases.len(), 10, "the oracle's actor cases");
    for case in cases {
        let params = &case["params"];
        let meta: Option<&Map<String, Value>> = params.get("_meta").and_then(Value::as_object);
        let actual = parse_actor(meta);
        let expected = &case["expected"];
        if expected.is_null() {
            assert_eq!(actual, None, "actor {}", name(case));
        } else {
            assert_eq!(actual.as_ref(), Some(expected), "actor {}", name(case));
        }
    }
}

#[test]
fn authority_matches_the_oracle() {
    let oracle = oracle();
    let cases = cases(&oracle, "authority");
    assert_eq!(cases.len(), 2, "the oracle's authority cases");
    for case in cases {
        let resolved = ResolvedTool {
            manifest: serde_json::from_value::<ToolManifest>(case["manifest"].clone())
                .expect("a manifest"),
            effective: serde_json::from_value::<EffectiveTool>(case["effective"].clone())
                .expect("an effective selection entry"),
            context: serde_json::from_value::<BoundContext>(case["context"].clone())
                .expect("a bound context"),
        };
        assert_eq!(
            &authority_snapshot(&resolved).expect("a serializable snapshot"),
            &case["expected"],
            "authority {}",
            name(case)
        );
    }
}

#[test]
fn run_status_round_trips_the_ddl_states() {
    // `mcp_runs_status_check` in migrations/0001_baseline.sql.
    let ddl = [
        "queued",
        "starting",
        "running",
        "cancelling",
        "succeeded",
        "failed",
        "cancelled",
        "timed_out",
        "interrupted",
    ];
    assert_eq!(RunStatus::ALL.len(), ddl.len());
    for status in ddl {
        let parsed = RunStatus::parse(status).expect("a DDL status");
        assert_eq!(parsed.as_str(), status);
        assert_eq!(
            serde_json::to_value(parsed).expect("a serializable status"),
            Value::String(status.to_owned())
        );
    }
    for status in RunStatus::ALL {
        assert!(
            ddl.contains(&status.as_str()),
            "{} is in the DDL",
            status.as_str()
        );
    }
    let terminal: Vec<&str> = RunStatus::ALL
        .iter()
        .filter(|status| status.is_terminal())
        .map(|status| status.as_str())
        .collect();
    assert_eq!(
        terminal,
        [
            "succeeded",
            "failed",
            "cancelled",
            "timed_out",
            "interrupted"
        ]
    );
    assert_eq!(RunStatus::parse("unknown"), None);
}

#[test]
fn attribution_carries_the_subject_and_licence() {
    let principal = Principal {
        tenant_id: Rfc4122Uuid::parse("10000000-0000-7000-8000-000000000001").expect("a tenant"),
        license_id: Rfc4122Uuid::parse("018f0000-0000-7000-8000-00000000cccc").expect("a licence"),
        subject: "synthetic-subject".to_owned(),
        binding_id: None,
        binding_revision: None,
        management: false,
        platform: false,
    };
    assert_eq!(
        attribution(&principal),
        serde_json::json!({
            "subject": "synthetic-subject",
            "license_id": "018f0000-0000-7000-8000-00000000cccc",
        })
    );
}
