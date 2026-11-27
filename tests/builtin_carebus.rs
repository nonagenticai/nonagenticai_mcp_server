//! The care-bus builtin family: the 13 wire tools, their exact upstream calls and their
//! error mapping, over loopback stubs.
//!
//! Every test starts a real axum server on `127.0.0.1:0` for the upstream under test and reads
//! back what the client actually put on the wire (method, path, query, headers, body), the way
//! `tests/external_n8n.rs` drives the n8n adapter. No database, no network, no env mutation:
//! configuration is resolved through `client::from_lookup`, the same function the handlers use
//! with `std::env::var`.
//!
//! The expected descriptions and input schemas are the reference's own `tools/list` output
//! (FastMCP on the archive's `src/builtin/carebus/`), not a transcription guess; the wire names
//! are the archived `tests/test_carebus_mount.py::CONTRACT`.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Value, json};

use mcp_server_rs::builtin::BuiltinProvider;
use mcp_server_rs::builtin::audit::{AuditError, AuditFuture, AuditSink};
use mcp_server_rs::builtin::carebus::{
    self, client, crm, delivery, early_access, ebook, faq, handover, order, procedures, rules,
};
use mcp_server_rs::builtin::scope::{BuiltinCaller, CallerKind};

// ── a loopback upstream that records every request ────────────────────────────────────────

#[derive(Clone)]
struct Stub {
    replies: Arc<Mutex<VecDeque<Reply>>>,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    delay: Option<Duration>,
}

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    query: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Stub {
    /// Queue one JSON reply.
    fn reply(&self, status: StatusCode, body: Value) {
        self.queue(
            status,
            serde_json::to_vec(&body).expect("a JSON reply"),
            None,
        );
    }

    /// Queue one plain-text reply.
    fn reply_text(&self, status: StatusCode, body: &str) {
        self.queue(status, body.as_bytes().to_vec(), None);
    }

    /// Queue one JSON reply that is written only after `delay`.
    fn reply_after(&self, status: StatusCode, body: Value, delay: Duration) {
        self.queue(
            status,
            serde_json::to_vec(&body).expect("a JSON reply"),
            Some(delay),
        );
    }

    fn queue(&self, status: StatusCode, body: Vec<u8>, delay: Option<Duration>) {
        self.replies
            .lock()
            .expect("an unpoisoned stub")
            .push_back(Reply {
                status,
                body,
                delay,
            });
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("an unpoisoned stub").clone()
    }
}

async fn local_server() -> (String, Stub) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback stub");
    let address = listener.local_addr().expect("a loopback address");
    let stub = Stub {
        replies: Arc::default(),
        requests: Arc::default(),
    };
    let app = Router::new().fallback(any(handle)).with_state(stub.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), stub)
}

async fn handle(State(stub): State<Stub>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024)
        .await
        .expect("the request body")
        .to_vec();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    stub.requests
        .lock()
        .expect("an unpoisoned stub")
        .push(Recorded {
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            query: parts.uri.query().map(str::to_owned),
            headers,
            body,
        });
    let reply = stub
        .replies
        .lock()
        .expect("an unpoisoned stub")
        .pop_front()
        .expect("a queued reply");
    if let Some(delay) = reply.delay {
        tokio::time::sleep(delay).await;
    }
    (reply.status, reply.body).into_response()
}

// ── helpers ──────────────────────────────────────────────────────────────────────────────

/// A client pointed at one loopback stub with the reference's default timeout.
fn service(base: &str, token: &str) -> client::ServiceClient {
    client::ServiceClient::new(
        base,
        Some(token.to_owned()),
        Duration::from_secs_f64(client::DEFAULT_TIMEOUT_S),
    )
}

fn only(stub: &Stub) -> Recorded {
    let mut requests = stub.requests();
    assert_eq!(requests.len(), 1, "exactly one upstream request");
    requests.pop().expect("one request")
}

fn json_body(request: &Recorded) -> Value {
    serde_json::from_slice(&request.body).expect("a JSON request body")
}

/// Records what each audit write would store, so a test can inspect the whole row.
#[derive(Default)]
struct RecordingSink {
    rows: Mutex<Vec<(String, Value)>>,
}

impl AuditSink for RecordingSink {
    fn write<'a>(
        &'a self,
        _caller: &'a BuiltinCaller,
        _tool: &'a str,
        status: &'a str,
        details: &'a Value,
    ) -> AuditFuture<'a> {
        self.rows
            .lock()
            .expect("an unpoisoned sink")
            .push((status.to_owned(), details.clone()));
        Box::pin(async { Ok::<(), AuditError>(()) })
    }
}

fn executor() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::KeycloakService,
        subject: "carebus-tool-executor".to_owned(),
        scope: "carebus-tool-executor".to_owned(),
        tenant_id: None,
        license_id: None,
        strata_token: None,
    }
}

fn licence_caller() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::CarebusLicence,
        subject: "svc:10000000-0000-7000-8000-000000000001:care-bus".to_owned(),
        scope: "licence:care-bus".to_owned(),
        tenant_id: Some("10000000-0000-7000-8000-000000000001".to_owned()),
        license_id: None,
        strata_token: None,
    }
}

const C1: &str = "0b6f9a0e-6a51-4a2c-9a1e-2d1f00000001";
const C2: &str = "0b6f9a0e-6a51-4a2c-9a1e-2d1f00000002";
const L1: &str = "7f1c9a2e-0000-4000-8000-0000000000a1";
const L2: &str = "7f1c9a2e-0000-4000-8000-0000000000a2";

// ── the contract: names, descriptions and input schemas ──────────────────────────────────

/// The reference's `tools/list` for the care-bus family, in the wire names it mounts.
fn contract() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "crm_get_start_data",
            "Most recent orders, shipments, payments and communications (last 90 days).",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            }),
        ),
        (
            "crm_verify_customer",
            "Verify a customer id and return name, tier and verification status.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"customer_id": {"type": "string"}},
                "required": ["customer_id"],
            }),
        ),
        (
            "delivery_track_shipment",
            "Carrier status, scan events and ETA for a shipment.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"shipment_id": {"type": "string"}},
                "required": ["shipment_id"],
            }),
        ),
        (
            "faq_ask",
            "Answer a general question from the knowledge stores, with cited sources.\n\nleaf_ids (care-bus sets it, never the model): search exactly these leaf stores instead of routing\nfrom the tenant's root; care-bus passes the stores outside every legal-matter wall. The answer then\ncarries scope.leaf_ids, the filter applied, which care-bus requires before it uses the answer.",
            json!({
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
            }),
        ),
        (
            "faq_search",
            "Search the knowledge stores and return the numbered passages that answer the question.\n\nleaf_ids (care-bus sets it, never the model): search exactly these leaf stores instead of routing\nfrom the tenant's root; care-bus passes the stores outside every legal-matter wall. The result is\nthe retrieval only — care-bus composes and cites the answer from these passages.",
            json!({
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
            }),
        ),
        (
            "ebook_request",
            "Request a book: file the request with book-fulfillment and, unless it lands on the waitlist, return the reader's one-time download link.\n\nemail: the reader's own address, which the request and the link are bound to; never invent one.\nlanguage: the edition's language code (default \"en\").\nip: the reader's address when care-bus has it; book-fulfillment records it.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "email": {"type": "string"},
                    "language": {"type": "string", "default": "en"},
                    "ip": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["email"],
            }),
        ),
        (
            "early_access_request",
            "Ask for early access to a product: an explicit \"yes\" or \"true\" files the request with the early-access service; anything else only proposes it and sends nothing.\n\nemail: the caller's own address, which the request is bound to; never invent one.\nproduct: the product's slug, exactly as the site names it.\nconfirm: \"yes\" or \"true\" files the request; anything else only proposes it.\nip: the caller's address when care-bus has it; the early-access service records it.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "email": {"type": "string"},
                    "product": {"type": "string"},
                    "confirm": {"type": "string"},
                    "ip": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["email", "product", "confirm"],
            }),
        ),
        (
            "handover_request",
            "Hand the conversation to a person: ask care-bus to open an operator handover for it.\n\nconversation_id: the care-bus conversation to hand over, exactly as the session names it.\nreason: the visitor's own words for why they need a person; never invent one.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "conversation_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["conversation_id", "reason"],
            }),
        ),
        (
            "order_create_rma",
            "Create a return authorisation. Idempotent per idempotency_key.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "order_id": {"type": "string"},
                    "reason": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["order_id", "reason", "idempotency_key"],
            }),
        ),
        (
            "order_create_warranty_claim",
            "Register a warranty claim and book a pickup. Idempotent per idempotency_key.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "order_id": {"type": "string"},
                    "defect": {"type": "string"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["order_id", "defect", "idempotency_key"],
            }),
        ),
        (
            "order_get_order",
            "Get one order with lines, status and shipment id.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            }),
        ),
        (
            "order_get_payments",
            "All payments captured for an order.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"order_id": {"type": "string"}},
                "required": ["order_id"],
            }),
        ),
        (
            "order_issue_refund",
            "Refund one payment in full or in part. Idempotent per idempotency_key.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "payment_id": {"type": "string"},
                    "amount": {"type": "number"},
                    "idempotency_key": {"type": "string"},
                },
                "required": ["payment_id", "amount", "idempotency_key"],
            }),
        ),
        (
            "procedures_get_procedure",
            "Steps of the PUBLISHED version of a procedure (PKO/PDDL model from carebus-api).",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"name": {"type": "string"}},
                "required": ["name"],
            }),
        ),
        (
            "rules_check_payment_issue",
            "PAY-04: two equal captures within 5 minutes count as a duplicate charge.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "order_id": {"type": "string"},
                    "error_type": {"type": "string"},
                },
                "required": ["order_id", "error_type"],
            }),
        ),
        (
            "rules_check_return_window",
            "RET-01: returns are allowed for 30 days after delivery. category and delivered_on are accepted because step args send them; the rule reads both from the order.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "order_id": {"type": "string"},
                    "category": {"type": "string"},
                    "delivered_on": {
                        "anyOf": [{"type": "string"}, {"type": "null"}],
                        "default": null,
                    },
                },
                "required": ["order_id", "category"],
            }),
        ),
        (
            "rules_check_warranty",
            "WAR-01: 24 months of warranty after delivery. category and delivered_on are accepted, not forwarded.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "order_id": {"type": "string"},
                    "category": {"type": "string"},
                    "delivered_on": {
                        "anyOf": [{"type": "string"}, {"type": "null"}],
                        "default": null,
                    },
                },
                "required": ["order_id", "category"],
            }),
        ),
    ]
}

#[tokio::test]
async fn the_registry_is_the_reference_contract_plus_the_extensions() {
    let mut provider = BuiltinProvider::new();
    carebus::register(&mut provider);

    let tools = provider.list(&executor());
    let expected = contract();
    assert_eq!(
        tools.len(),
        expected.len(),
        "the care-bus contract is the reference's 13 tools plus faq_search, ebook_request, early_access_request and handover_request"
    );
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
        [
            "crm_get_start_data",
            "crm_verify_customer",
            "delivery_track_shipment",
            "early_access_request",
            "ebook_request",
            "faq_ask",
            "faq_search",
            "handover_request",
            "order_create_rma",
            "order_create_warranty_claim",
            "order_get_order",
            "order_get_payments",
            "order_issue_refund",
            "procedures_get_procedure",
            "rules_check_payment_issue",
            "rules_check_return_window",
            "rules_check_warranty",
        ]
    );

    for (name, description, schema) in &expected {
        let tool = tools
            .iter()
            .find(|tool| tool.name == *name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        assert_eq!(tool.description.as_deref(), Some(*description), "{name}");
        assert_eq!(
            Value::Object((*tool.input_schema).clone()),
            *schema,
            "{name}"
        );
    }

    // The scope tables grant the family to the care-bus contract and the care-bus licence,
    // and to nobody else.
    assert!(provider.list(&licence_caller()).len() == expected.len());
    assert!(
        provider
            .list(&BuiltinCaller {
                scope: "carebus-researcher".to_owned(),
                subject: "carebus-researcher".to_owned(),
                ..executor()
            })
            .is_empty()
    );
    assert!(
        provider
            .list(&BuiltinCaller {
                scope: "unknown-client".to_owned(),
                subject: "unknown-client".to_owned(),
                ..executor()
            })
            .is_empty()
    );
}

// ── the MCP result envelope ─────────────────────────────────────────────────────────────

#[test]
fn a_tool_answer_is_both_structured_content_and_its_text() {
    // FastMCP answered a `-> dict` tool with the same value twice: as `structuredContent` and
    // as a JSON text block. The care-bus client reads either.
    let result = carebus::success(json!({"verified": true})).expect("a success");
    assert_eq!(result.is_error, Some(false));
    assert_eq!(result.structured_content, Some(json!({"verified": true})));
    assert_eq!(
        result.content[0].as_text().expect("a text block").text,
        "{\"verified\":true}"
    );
}

// ── crm ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn crm_verify_customer_returns_the_verified_customer() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"customer_id": "C-10482", "name": "Anna de Vries", "tier": "Gold"}),
    );
    let out = crm::verify_customer(&service(&base, "demo-token"), &json!("C-10482"))
        .await
        .expect("a customer");

    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/customers/C-10482");
    assert_eq!(request.query, None);
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer demo-token")
    );
    assert!(request.body.is_empty(), "a GET carries no body");

    assert_eq!(
        out,
        json!({
            "customer_id": "C-10482",
            "name": "Anna de Vries",
            "tier": "Gold",
            "verified": true,
        })
    );
    assert_eq!(
        out.as_object()
            .and_then(|object| object.keys().next_back())
            .map(String::as_str),
        Some("verified"),
        "verified is the last key, as in the reference"
    );
}

#[tokio::test]
async fn crm_get_start_data_passes_the_body_through() {
    let (base, stub) = local_server().await;
    let body = json!({
        "customer": {"customer_id": "C-10482"},
        "orders": [{"order_id": "ORD-58790"}],
        "deliveries": [{"shipment_id": "SHP-88123", "order_id": "ORD-58790", "status": "in_transit"}],
        "payments": [],
        "communications": [],
    });
    stub.reply(StatusCode::OK, body.clone());
    let out = crm::get_start_data(&service(&base, "demo-token"), &json!("C-10482"))
        .await
        .expect("start data");

    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/customers/C-10482/start-data");
    assert_eq!(out, body);
}

// ── order ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn order_get_order_and_payments_use_the_order_paths() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"order_id": "ORD-58790", "shipment_id": "SHP-88123"}),
    );
    stub.reply(
        StatusCode::OK,
        json!({"order_id": "ORD-58790", "payments": [{"payment_id": "PAY-3398"}, {"payment_id": "PAY-3399"}]}),
    );
    let service = service(&base, "demo-token");

    let order = order::get_order(&service, &json!("ORD-58790"))
        .await
        .expect("an order");
    let payments = order::get_payments(&service, &json!("ORD-58790"))
        .await
        .expect("the payments");

    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].method, "GET");
    assert_eq!(requests[0].path, "/api/orders/ORD-58790");
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].path, "/api/orders/ORD-58790/payments");
    assert_eq!(order["shipment_id"], json!("SHP-88123"));
    assert_eq!(payments["payments"].as_array().map(Vec::len), Some(2));
}

#[tokio::test]
async fn order_create_rma_posts_the_reason_and_the_idempotency_key() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"rma_id": "RMA-41007", "order_id": "ORD-58213"}),
    );
    let out = order::create_rma(
        &service(&base, "demo-token"),
        &json!("ORD-58213"),
        "too uncomfortable",
        "CASE-0002:2:rma",
    )
    .await
    .expect("an rma");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/orders/ORD-58213/rmas");
    assert_eq!(
        request.headers.get("content-type").map(String::as_str),
        Some("application/json")
    );
    assert_eq!(
        json_body(&request),
        json!({"reason": "too uncomfortable", "idempotency_key": "CASE-0002:2:rma"})
    );
    assert_eq!(out["rma_id"], json!("RMA-41007"));
}

#[tokio::test]
async fn order_create_warranty_claim_posts_the_defect() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::CREATED, json!({"claim_id": "WC-7719"}));
    let out = order::create_warranty_claim(
        &service(&base, "demo-token"),
        &json!("ORD-57102"),
        "stopped working",
        "k1",
    )
    .await
    .expect("a claim");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/orders/ORD-57102/warranty-claims");
    assert_eq!(
        json_body(&request),
        json!({"defect": "stopped working", "idempotency_key": "k1"})
    );
    assert_eq!(out["claim_id"], json!("WC-7719"));
}

#[tokio::test]
async fn order_issue_refund_posts_the_amount() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"refund_id": "REF-1", "amount": 229.0}),
    );
    let out = order::issue_refund(
        &service(&base, "demo-token"),
        &json!("PAY-3399"),
        229.0,
        "k2",
    )
    .await
    .expect("a refund");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/payments/PAY-3399/refunds");
    assert_eq!(
        json_body(&request),
        json!({"amount": 229.0, "idempotency_key": "k2"})
    );
    assert_eq!(out["refund_id"], json!("REF-1"));
}

// ── delivery ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn delivery_track_shipment_reads_the_shipment() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"shipment_id": "SHP-88123", "status": "in_transit"}),
    );
    let out = delivery::track_shipment(&service(&base, "demo-token"), &json!("SHP-88123"))
        .await
        .expect("a shipment");

    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/shipments/SHP-88123");
    assert_eq!(out["status"], json!("in_transit"));
}

// ── rules ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn rules_check_return_window_sends_only_the_order_id() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"eligible": false, "rule": "RET-01", "reason": "ended", "alternative": "warranty"}),
    );
    let out = rules::check_return_window(&service(&base, "demo-token"), "ORD-57102")
        .await
        .expect("a rule");

    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/rules/return-window");
    assert_eq!(
        request.query.as_deref(),
        Some("order_id=ORD-57102"),
        "category and delivered_on are never forwarded"
    );
    assert_eq!(out["eligible"], json!(false));
    assert_eq!(out["rule"], json!("RET-01"));
}

#[tokio::test]
async fn rules_check_warranty_sends_only_the_order_id() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, json!({"eligible": true, "rule": "WAR-01"}));
    let out = rules::check_warranty(&service(&base, "demo-token"), "ORD-57102")
        .await
        .expect("a rule");

    let request = only(&stub);
    assert_eq!(request.path, "/api/rules/warranty");
    assert_eq!(request.query.as_deref(), Some("order_id=ORD-57102"));
    assert_eq!(out["rule"], json!("WAR-01"));
}

#[tokio::test]
async fn rules_check_payment_issue_sends_the_error_type() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"eligible": true, "rule": "PAY-04", "refund_payment_id": "PAY-3399", "refund_amount": 229.0}),
    );
    let out = rules::check_payment_issue(
        &service(&base, "demo-token"),
        "ORD-58790",
        "duplicate_charge",
    )
    .await
    .expect("a rule");

    let request = only(&stub);
    assert_eq!(request.path, "/api/rules/payment-issue");
    assert_eq!(
        request.query.as_deref(),
        Some("order_id=ORD-58790&error_type=duplicate_charge")
    );
    assert_eq!(out["refund_payment_id"], json!("PAY-3399"));
}

// ── procedures ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn procedures_get_procedure_reads_the_published_version() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"name": "return", "version": "1.3.0", "version_status": "PUBLISHED", "steps": []}),
    );
    let out = procedures::get_procedure(&service(&base, "api-tok"), &json!("return"))
        .await
        .expect("a procedure");

    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, "/api/procedures/return");
    assert_eq!(request.query.as_deref(), Some("status=PUBLISHED"));
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer api-tok"),
        "procedures read carebus-api, not the demo backends"
    );
    assert_eq!(out["version_status"], json!("PUBLISHED"));
}

// ── faq ─────────────────────────────────────────────────────────────────────────────────

/// The reference's `AskResponse` fixture: two results, one of them cited.
fn ask_response() -> Value {
    json!({
        "answer": "Refunds go back within 5 business days.",
        "citations": [C1],
        "results": [
            {
                "chunk_id": C1,
                "document_id": "d-17",
                "store_path": ["care", "policies", "returns-policy"],
                "ord": 3,
                "text": "long chunk",
                "page_start": 2,
                "page_end": 3,
                "source": "returns-policy.pdf",
                "title": "Returns policy",
                "scores": {"dense": 0.8},
            },
            {
                "chunk_id": C2,
                "document_id": "d-18",
                "store_path": ["care", "logistics", "shipping-faq"],
                "text": "other chunk",
                "scores": {"dense": 0.4},
            },
        ],
        "timings_ms": {"embed": 38, "route": 410, "search": 22, "rerank": 300, "generate": 1300, "total": 2100},
    })
}

#[tokio::test]
async fn faq_ask_posts_the_hybrid_query_and_shapes_the_citations() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, ask_response());
    let out = faq::ask(
        &service(&base, "rag-tok"),
        "How long does a refund take?",
        None,
    )
    .await
    .expect("an answer");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/ask");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer rag-tok")
    );
    assert_eq!(
        json_body(&request),
        json!({"query": "How long does a refund take?", "route_mode": "hybrid", "top_k": 8}),
        "no leaf filter, and never the model's own top_k"
    );
    assert_eq!(
        out["answer"],
        json!("Refunds go back within 5 business days.")
    );
    assert_eq!(out["citations"], json!([C1]));
    assert_eq!(
        out["sources"],
        json!([{
            "chunk_id": C1,
            "document_id": "d-17",
            "store_path": ["care", "policies", "returns-policy"],
            "title": "Returns policy",
            "source": "returns-policy.pdf",
            "page_start": 2,
            "page_end": 3,
        }]),
        "only a cited chunk is a source, and the chunk text is never returned"
    );
    assert!(out.get("scope").is_none());
    assert_eq!(out["timings_ms"]["generate"], json!(1300));
    assert_eq!(out["timings_ms"]["total"], json!(2100));
}

#[tokio::test]
async fn faq_ask_forwards_a_store_filter_and_confirms_it() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"answer": "a", "citations": [], "results": []}),
    );
    let scope = faq::leaf_ids(&json!([L1, L2])).expect("a valid filter");
    let out = faq::ask(&service(&base, "rag-tok"), "q", Some(scope))
        .await
        .expect("an answer");

    assert_eq!(
        json_body(&only(&stub)),
        json!({"query": "q", "route_mode": "hybrid", "top_k": 8, "leaf_ids": [L1, L2]})
    );
    assert_eq!(out["scope"], json!({"leaf_ids": [L1, L2]}));
    assert_eq!(out["citations"], json!([]));
    assert_eq!(out["sources"], json!([]));
    assert_eq!(out["timings_ms"], json!({}));
}

#[tokio::test]
async fn faq_search_posts_the_query_and_numbers_the_passages() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, ask_response());
    let out = faq::search(
        &service(&base, "rag-tok"),
        "How long does a refund take?",
        None,
    )
    .await
    .expect("sources");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/query");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer rag-tok")
    );
    assert_eq!(
        json_body(&request),
        json!({"query": "How long does a refund take?", "route_mode": "hybrid", "top_k": 8}),
        "retrieval only: no answer and no model-owned arguments"
    );
    assert_eq!(out["sources"][0]["n"], json!(1));
    assert_eq!(out["sources"][0]["chunk_id"], json!(C1));
    assert_eq!(out["sources"][0]["text"], json!("long chunk"));
    assert_eq!(out["sources"][0]["title"], json!("Returns policy"));
    assert_eq!(out["sources"][1]["n"], json!(2));
    assert_eq!(out["sources"][1]["chunk_id"], json!(C2));
    assert!(
        out.get("answer").is_none(),
        "search returns passages, not an answer"
    );
    assert!(out.get("scope").is_none());
    assert_eq!(out["timings_ms"]["total"], json!(2100));
}

#[tokio::test]
async fn faq_search_forwards_a_store_filter_and_confirms_it() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, json!({"results": [], "timings_ms": {}}));
    let scope = faq::leaf_ids(&json!([L1])).expect("a valid filter");
    let out = faq::search(&service(&base, "rag-tok"), "q", Some(scope))
        .await
        .expect("sources");
    assert_eq!(
        json_body(&only(&stub)),
        json!({"query": "q", "route_mode": "hybrid", "top_k": 8, "leaf_ids": [L1]})
    );
    assert_eq!(out["sources"], json!([]));
    assert_eq!(out["scope"], json!({"leaf_ids": [L1]}));
    assert_eq!(out["timings_ms"], json!({}));
}

#[tokio::test]
async fn faq_search_refuses_a_bad_store_filter_before_any_request() {
    let mut provider = BuiltinProvider::new();
    faq::register(&mut provider);
    let arguments = json!({"question": "q", "leaf_ids": []})
        .as_object()
        .cloned()
        .expect("an arguments object");
    let result = provider.call(&executor(), "faq_search", arguments).await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        result.content[0]
            .as_text()
            .expect("a text refusal")
            .text
            .starts_with("[permanent] leaf_ids"),
        "the call reached the handler"
    );
}

#[test]
fn a_bad_store_filter_is_refused_before_any_request() {
    // The filter is validated before the strata_rag client is resolved, so no request can be
    // made for any of these.
    for bad in [
        json!([]),
        json!(["not-a-uuid"]),
        Value::Array(vec![json!(L1); faq::MAX_LEAF_IDS + 1]),
    ] {
        let error = faq::leaf_ids(&bad).expect_err("a bad filter is refused");
        assert!(error.starts_with("[permanent] leaf_ids"), "{error}");
    }
    assert_eq!(
        faq::leaf_ids(&json!([L1, L2])).expect("a valid filter"),
        vec![json!(L1), json!(L2)],
        "the ids are returned unchanged"
    );
}

#[test]
fn a_licence_caller_must_bring_its_own_strata_token() {
    let base = "http://rag.test";
    let lookup = |key: &str| (key == "STRATA_RAG_URL").then(|| base.to_owned());

    let error = client::strata_rag_from_lookup(&licence_caller(), lookup)
        .expect_err("a licence caller without a forwarded token is refused");
    assert_eq!(error, client::X_STRATA_TOKEN_REQUIRED);

    // The reference's `if not token`: an empty forwarded value is no token either.
    let empty = BuiltinCaller {
        strata_token: Some(String::new()),
        ..licence_caller()
    };
    let error = client::strata_rag_from_lookup(&empty, lookup)
        .expect_err("an empty forwarded token is refused");
    assert_eq!(error, client::X_STRATA_TOKEN_REQUIRED);

    // The reference resolves the pinned client first: a missing base wins over the token rule.
    let error = client::strata_rag_from_lookup(&licence_caller(), |_| None)
        .expect_err("a missing base is refused first");
    assert_eq!(
        error,
        "[permanent] STRATA_RAG_URL is not set on the MCP server"
    );

    // A Keycloak caller (the transition path) uses the pinned client unchanged.
    let service = client::strata_rag_from_lookup(&executor(), lookup)
        .expect("a keycloak caller uses the pinned token");
    assert_eq!(service.base_url(), base);
}

/// The tenant's own strata-rag licence, as the `/mcp` request forwards it.
const FORWARDED_TOKEN: &str = "tenant-strata-licence-token";

#[tokio::test]
async fn a_licence_caller_searches_its_own_tenant_with_the_forwarded_token() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, ask_response());
    // Both are configured, so only the forwarded token can be the one sent.
    let lookup = |key: &str| match key {
        "STRATA_RAG_URL" => Some(base.clone()),
        "STRATA_RAG_TOKEN" => Some("pinned-token".to_owned()),
        _ => None,
    };
    let caller = BuiltinCaller {
        strata_token: Some(FORWARDED_TOKEN.to_owned()),
        ..licence_caller()
    };

    let service = client::strata_rag_from_lookup(&caller, lookup)
        .expect("a licence caller's own strata-rag licence is accepted");
    faq::ask(&service, "How long does a refund take?", None)
        .await
        .expect("an answer");

    let request = only(&stub);
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer tenant-strata-licence-token"),
        "the caller's own licence, never the pinned STRATA_RAG_TOKEN"
    );
    assert_eq!(
        request.headers.get("x-tenant-id").map(String::as_str),
        Some("10000000-0000-7000-8000-000000000001"),
        "the licence's tenant, so strata_rag can answer tenant_mismatch"
    );
}

#[tokio::test]
async fn a_service_caller_keeps_the_pinned_token_and_sends_no_tenant() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, ask_response());
    let lookup = |key: &str| match key {
        "STRATA_RAG_URL" => Some(base.clone()),
        "STRATA_RAG_TOKEN" => Some("pinned-token".to_owned()),
        _ => None,
    };

    let service = client::strata_rag_from_lookup(&executor(), lookup)
        .expect("a keycloak caller uses the pinned token");
    faq::ask(&service, "q", None).await.expect("an answer");

    let request = only(&stub);
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer pinned-token")
    );
    assert!(
        !request.headers.contains_key("x-tenant-id"),
        "the pinned client names no tenant: {:?}",
        request.headers
    );
}

#[tokio::test]
async fn the_forwarded_token_never_reaches_an_audit_row_or_a_log_line() {
    let sink = Arc::new(RecordingSink::default());
    let mut provider = BuiltinProvider::new().with_sink(sink.clone());
    faq::register(&mut provider);
    let caller = BuiltinCaller {
        strata_token: Some(FORWARDED_TOKEN.to_owned()),
        ..licence_caller()
    };

    // Refused inside the handler before any network call (leaf_ids holds 1..=256 ids): exactly
    // one audit row is written and no request leaves the process.
    let arguments = json!({"question": "q", "leaf_ids": []})
        .as_object()
        .cloned()
        .expect("an arguments object");
    let result = provider.call(&caller, "faq_ask", arguments).await;
    assert_eq!(result.is_error, Some(true));
    assert!(
        result.content[0]
            .as_text()
            .expect("a text refusal")
            .text
            .starts_with("[permanent] leaf_ids"),
        "the call reached the handler"
    );

    let rows = sink.rows.lock().expect("an unpoisoned sink");
    assert_eq!(rows.len(), 1, "one audit row per call");
    let audit = serde_json::to_string(&*rows).expect("the rows render");
    assert!(
        !audit.contains(FORWARDED_TOKEN),
        "the token reached the audit row: {audit}"
    );

    // A log line that renders the caller — `?caller` — gets the redaction, never the token.
    let debug = format!("{caller:?}");
    assert!(
        !debug.contains(FORWARDED_TOKEN),
        "the token reached a log line: {debug}"
    );
    assert!(debug.contains("<redacted>"), "{debug}");
}

// ── the error mapping ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_backend_refusal_is_permanent_with_the_backend_message() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::CONFLICT,
        json!({"error": {"code": "refund_exceeds_capture", "message": "refund 500.00 exceeds captured 229.00"}}),
    );
    let error = order::issue_refund(
        &service(&base, "demo-token"),
        &json!("PAY-3399"),
        500.0,
        "k2",
    )
    .await
    .expect_err("a refusal");

    assert_eq!(
        error,
        "[permanent] 409 from POST /api/payments/PAY-3399/refunds: \
         refund 500.00 exceeds captured 229.00"
    );
    assert_eq!(
        json_body(&only(&stub)),
        json!({"amount": 500.0, "idempotency_key": "k2"})
    );
}

#[tokio::test]
async fn server_errors_and_rate_limits_are_retryable() {
    for (status, code) in [
        (StatusCode::SERVICE_UNAVAILABLE, 503),
        (StatusCode::TOO_MANY_REQUESTS, 429),
    ] {
        let (base, stub) = local_server().await;
        stub.reply(status, json!({"error": {"message": "busy"}}));
        let error = order::get_order(&service(&base, "demo-token"), &json!("ORD-1"))
            .await
            .expect_err("a retryable failure");
        assert_eq!(
            error,
            format!("[retryable] {code} from GET /api/orders/ORD-1: busy")
        );
    }
}

#[tokio::test]
async fn a_plain_text_refusal_is_permanent_and_an_empty_one_uses_the_reason() {
    let (base, stub) = local_server().await;
    stub.reply_text(StatusCode::NOT_FOUND, "no such order");
    let error = order::get_order(&service(&base, "demo-token"), &json!("ORD-404"))
        .await
        .expect_err("a refusal");
    assert_eq!(
        error,
        "[permanent] 404 from GET /api/orders/ORD-404: no such order"
    );

    let (base, stub) = local_server().await;
    stub.reply_text(StatusCode::NOT_FOUND, "");
    let error = order::get_order(&service(&base, "demo-token"), &json!("ORD-404"))
        .await
        .expect_err("a refusal");
    assert_eq!(
        error,
        "[permanent] 404 from GET /api/orders/ORD-404: Not Found"
    );
}

#[tokio::test]
async fn an_unreachable_backend_is_retryable() {
    // A port that was just closed: the connect is refused, as an httpx ConnectError would be.
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind a throwaway port");
    let address = listener.local_addr().expect("a throwaway address");
    drop(listener);

    let service = client::ServiceClient::new(
        format!("http://{address}"),
        Some("demo-token".to_owned()),
        Duration::from_secs_f64(client::DEFAULT_TIMEOUT_S),
    );
    let error = delivery::track_shipment(&service, &json!("SHP-1"))
        .await
        .expect_err("an unreachable backend");
    assert_eq!(
        error,
        "[retryable] cannot reach backend for GET /api/shipments/SHP-1: ConnectError"
    );
}

#[tokio::test]
async fn a_slow_backend_times_out_retryably() {
    let (base, stub) = local_server().await;
    stub.reply_after(
        StatusCode::OK,
        json!({"shipment_id": "SHP-1"}),
        Duration::from_millis(500),
    );
    let service = client::ServiceClient::new(
        base.as_str(),
        Some("demo-token".to_owned()),
        Duration::from_millis(50),
    );
    let error = delivery::track_shipment(&service, &json!("SHP-1"))
        .await
        .expect_err("a timeout");
    assert!(error.starts_with("[retryable] timeout after "), "{error}");
    assert!(
        error.ends_with(" ms calling GET /api/shipments/SHP-1"),
        "{error}"
    );
}

// ── path ids ────────────────────────────────────────────────────────────────────────────

/// Every tool that puts a caller-supplied id in the URL path.
async fn call_each_path_tool(
    service: &client::ServiceClient,
    id: &Value,
) -> Vec<(&'static str, String)> {
    vec![
        (
            "customer_id",
            crm::verify_customer(service, id)
                .await
                .expect_err("refused"),
        ),
        (
            "customer_id",
            crm::get_start_data(service, id).await.expect_err("refused"),
        ),
        (
            "order_id",
            order::get_order(service, id).await.expect_err("refused"),
        ),
        (
            "order_id",
            order::get_payments(service, id).await.expect_err("refused"),
        ),
        (
            "order_id",
            order::create_rma(service, id, "r", "k")
                .await
                .expect_err("refused"),
        ),
        (
            "order_id",
            order::create_warranty_claim(service, id, "d", "k")
                .await
                .expect_err("refused"),
        ),
        (
            "payment_id",
            order::issue_refund(service, id, 1.0, "k")
                .await
                .expect_err("refused"),
        ),
        (
            "shipment_id",
            delivery::track_shipment(service, id)
                .await
                .expect_err("refused"),
        ),
        (
            "name",
            procedures::get_procedure(service, id)
                .await
                .expect_err("refused"),
        ),
    ]
}

#[tokio::test]
async fn path_ids_are_validated_before_any_request() {
    let (base, stub) = local_server().await;
    let service = service(&base, "demo-token");
    for bad in [
        json!("../admin/reset?"),
        json!(".."),
        json!("."),
        json!("a/b"),
        json!("x?y"),
        json!(""),
        json!("%2e%2e"),
        json!("a b"),
        json!("x".repeat(500)),
    ] {
        for (field, error) in call_each_path_tool(&service, &bad).await {
            let prefix = format!("[permanent] invalid {field}: ");
            assert!(error.starts_with(prefix.as_str()), "{bad}: {error}");
            assert!(
                error.chars().count() < 200,
                "a huge id is not echoed back: {error}"
            );
        }
    }
    assert!(
        stub.requests().is_empty(),
        "a rejected id never reaches the backend"
    );
}

#[tokio::test]
async fn a_valid_path_id_is_percent_encoded_as_one_segment() {
    let (base, stub) = local_server().await;
    stub.reply(
        StatusCode::OK,
        json!({"customer_id": "C:1", "name": "n", "tier": "t"}),
    );
    let out = crm::verify_customer(&service(&base, "demo-token"), &json!("C:1"))
        .await
        .expect("a customer");
    assert_eq!(only(&stub).path, "/api/customers/C%3A1");
    assert_eq!(out["customer_id"], json!("C:1"));
}

// ── configuration ──────────────────────────────────────────────────────────────────────

#[test]
fn a_missing_base_url_is_the_reference_refusal() {
    for (service, name) in [
        (client::Service::DemoBackends, "DEMO_BACKENDS_URL"),
        (client::Service::StrataRag, "STRATA_RAG_URL"),
        (client::Service::CarebusApi, "CAREBUS_API_URL"),
    ] {
        for lookup in [None, Some(String::new())] {
            let error = client::from_lookup(service, |_| lookup.clone())
                .expect_err("a missing base refuses");
            assert_eq!(
                error,
                format!("[permanent] {name} is not set on the MCP server")
            );
        }
    }
}

#[test]
fn the_clients_use_the_reference_timeouts() {
    let configured = |pairs: &[(&str, &str)]| -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect()
    };
    let lookup = |map: HashMap<String, String>| move |key: &str| map.get(key).cloned();

    let demo = client::from_lookup(
        client::Service::DemoBackends,
        lookup(configured(&[("DEMO_BACKENDS_URL", "http://demo.test")])),
    )
    .expect("a configured demo client");
    assert_eq!(demo.timeout(), Duration::from_secs_f64(2.5));

    let rag = client::from_lookup(
        client::Service::StrataRag,
        lookup(configured(&[("STRATA_RAG_URL", "http://rag.test")])),
    )
    .expect("a configured rag client");
    assert_eq!(rag.timeout(), Duration::from_secs(18));

    let rag = client::from_lookup(
        client::Service::StrataRag,
        lookup(configured(&[
            ("STRATA_RAG_URL", "http://rag.test"),
            ("FAQ_TIMEOUT_S", "5"),
        ])),
    )
    .expect("an overridden rag client");
    assert_eq!(rag.timeout(), Duration::from_secs(5));

    for bad in ["soon", "0", "-3"] {
        let rag = configured(&[
            ("STRATA_RAG_URL", "http://rag.test"),
            ("FAQ_TIMEOUT_S", bad),
        ]);
        assert!(
            client::from_lookup(client::Service::StrataRag, lookup(rag)).is_err(),
            "FAQ_TIMEOUT_S={bad} must be refused"
        );
    }
}

#[tokio::test]
async fn no_token_set_sends_no_authorization_header() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, json!({"order_id": "ORD-1"}));
    let service = client::ServiceClient::new(
        base.as_str(),
        None,
        Duration::from_secs_f64(client::DEFAULT_TIMEOUT_S),
    );
    order::get_order(&service, &json!("ORD-1"))
        .await
        .expect("an order");
    assert!(!only(&stub).headers.contains_key("authorization"));
}

// ── ebook, early access, handover ────────────────────────────────────────────────────────

#[tokio::test]
async fn ebook_request_mints_and_returns_the_download_link() {
    let (fulfillment_base, fulfillment) = local_server().await;
    let (links_base, links) = local_server().await;
    fulfillment.reply(StatusCode::OK, json!({"state": "sent"}));
    links.reply(
        StatusCode::OK,
        json!({"url": "https://books.test/download/one-time"}),
    );

    let out = ebook::request_with(
        &service(&fulfillment_base, "fulfillment-token"),
        async { Ok::<_, String>(service(&links_base, "links-token")) },
        "reader@example.test",
        "en",
        None,
    )
    .await
    .expect("a sent request");

    let filed = only(&fulfillment);
    assert_eq!(filed.method, "POST");
    assert_eq!(filed.path, "/", "BOOK_REQUESTS_URL is the endpoint itself");
    assert_eq!(
        json_body(&filed),
        json!({"email": "reader@example.test", "language": "en"})
    );
    let minted = only(&links);
    assert_eq!(minted.method, "POST");
    assert_eq!(minted.path, "/internal/download-links");
    assert_eq!(
        minted.headers.get("authorization").map(String::as_str),
        Some("Bearer links-token")
    );
    assert_eq!(
        json_body(&minted),
        json!({"email": "reader@example.test", "lang": "en", "fresh": true})
    );
    assert_eq!(
        out,
        json!({
            "status": "sent",
            "edition": "en",
            "email": "reader@example.test",
            "link": "https://books.test/download/one-time",
        })
    );
}

#[tokio::test]
async fn ebook_waitlist_never_awaits_the_link_service() {
    let (fulfillment_base, fulfillment) = local_server().await;
    let (links_base, links) = local_server().await;
    fulfillment.reply(StatusCode::OK, json!({"state": "waitlist"}));

    let out = ebook::request_with(
        &service(&fulfillment_base, "fulfillment-token"),
        async { Ok::<_, String>(service(&links_base, "links-token")) },
        "reader@example.test",
        "de",
        Some("203.0.113.7"),
    )
    .await
    .expect("a waitlist request");

    assert_eq!(
        out,
        json!({"status": "waitlist", "edition": "de", "email": "reader@example.test"})
    );
    let filed = only(&fulfillment);
    assert_eq!(
        filed.headers.get("cf-connecting-ip").map(String::as_str),
        Some("203.0.113.7")
    );
    assert!(
        links.requests().is_empty(),
        "a waitlisted request must mint no link and send no mail"
    );
}

#[tokio::test]
async fn handover_request_posts_the_four_fields_and_returns_the_answer() {
    let (base, stub) = local_server().await;
    let answer = json!({"status": "handed_over", "chat_id": "-100123", "thread_id": 7});
    stub.reply(StatusCode::OK, answer.clone());

    let out = handover::request(
        &service(&base, "api-token"),
        "tenant-1",
        "support",
        C1,
        "I need a person",
    )
    .await
    .expect("a handover");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/internal/handover");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer api-token")
    );
    assert_eq!(
        json_body(&request),
        json!({
            "tenant_id": "tenant-1",
            "job": "support",
            "conversation_id": C1,
            "reason": "I need a person",
        })
    );
    assert_eq!(out, answer);
}

#[test]
fn handover_refuses_a_blank_reason_before_any_client_is_resolved() {
    // The refusal lives in `request_arguments`, which cannot reach a client: a blank reason
    // sends nothing and resolves no env.
    let arguments = json!({"conversation_id": C1, "reason": "   "});
    let error = handover::request_arguments(arguments.as_object().expect("an object"))
        .expect_err("a blank reason refuses");
    assert_eq!(
        error,
        "[permanent] invalid reason: expected the visitor's words"
    );

    let arguments = json!({"conversation_id": "  ", "reason": "please"});
    let error = handover::request_arguments(arguments.as_object().expect("an object"))
        .expect_err("a blank conversation id refuses");
    assert_eq!(
        error,
        "[permanent] invalid conversation_id: expected the conversation to hand over"
    );
}

#[tokio::test]
async fn early_access_file_with_posts_the_consent_and_the_bearer() {
    let (base, stub) = local_server().await;
    stub.reply(StatusCode::OK, json!({}));

    early_access::file_with(
        &base,
        "kc-token",
        "caller@example.test",
        "widget",
        "req-0001",
        Some("203.0.113.7"),
    )
    .await
    .expect("a filed request");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/", "EARLY_ACCESS_URL is the endpoint itself");
    assert_eq!(
        request.headers.get("authorization").map(String::as_str),
        Some("Bearer kc-token")
    );
    assert_eq!(
        request.headers.get("cf-connecting-ip").map(String::as_str),
        Some("203.0.113.7")
    );
    assert_eq!(
        json_body(&request),
        json!({
            "email": "caller@example.test",
            "product": "widget",
            "consent": true,
            "requestId": "req-0001",
        })
    );
}

#[tokio::test]
async fn early_access_file_with_maps_a_client_error_to_permanent() {
    let (base, stub) = local_server().await;
    stub.reply_text(StatusCode::BAD_REQUEST, "no");

    let error = early_access::file_with(
        &base,
        "kc-token",
        "caller@example.test",
        "widget",
        "req-0002",
        None,
    )
    .await
    .expect_err("a 400 refuses");
    assert_eq!(error, "[permanent] 400 from the early-access service");
}
