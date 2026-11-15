//! order tools: namespace `order`. Side-effect tools forward `idempotency_key` unchanged.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{argument, number_argument, schema, success, text_argument};

/// Get one order with lines, status and shipment id.
pub async fn get_order(service: &ServiceClient, order_id: &Value) -> Result<Value, String> {
    let path = format!("/api/orders/{}", client::path_id("order_id", order_id)?);
    service.get(&path, &[]).await
}

/// All payments captured for an order.
pub async fn get_payments(service: &ServiceClient, order_id: &Value) -> Result<Value, String> {
    let path = format!(
        "/api/orders/{}/payments",
        client::path_id("order_id", order_id)?
    );
    service.get(&path, &[]).await
}

/// Create a return authorisation. Idempotent per `idempotency_key`.
pub async fn create_rma(
    service: &ServiceClient,
    order_id: &Value,
    reason: &str,
    idempotency_key: &str,
) -> Result<Value, String> {
    let path = format!(
        "/api/orders/{}/rmas",
        client::path_id("order_id", order_id)?
    );
    service
        .post(
            &path,
            json!({"reason": reason, "idempotency_key": idempotency_key}),
        )
        .await
}

/// Register a warranty claim and book a pickup. Idempotent per `idempotency_key`.
pub async fn create_warranty_claim(
    service: &ServiceClient,
    order_id: &Value,
    defect: &str,
    idempotency_key: &str,
) -> Result<Value, String> {
    let path = format!(
        "/api/orders/{}/warranty-claims",
        client::path_id("order_id", order_id)?
    );
    service
        .post(
            &path,
            json!({"defect": defect, "idempotency_key": idempotency_key}),
        )
        .await
}

/// Refund one payment in full or in part. Idempotent per `idempotency_key`.
pub async fn issue_refund(
    service: &ServiceClient,
    payment_id: &Value,
    amount: f64,
    idempotency_key: &str,
) -> Result<Value, String> {
    let path = format!(
        "/api/payments/{}/refunds",
        client::path_id("payment_id", payment_id)?
    );
    service
        .post(
            &path,
            json!({"amount": amount, "idempotency_key": idempotency_key}),
        )
        .await
}

/// Register the five order tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "order",
        "get_order",
        "Get one order with lines, status and shipment id.",
        order_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = argument(&arguments, "order_id");
                let service = client::demo_backends()?;
                success(get_order(&service, &order_id).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "order",
        "get_payments",
        "All payments captured for an order.",
        order_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = argument(&arguments, "order_id");
                let service = client::demo_backends()?;
                success(get_payments(&service, &order_id).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "order",
        "create_rma",
        "Create a return authorisation. Idempotent per idempotency_key.",
        create_schema("reason"),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = argument(&arguments, "order_id");
                let reason = text_argument(&arguments, "reason")?;
                let idempotency_key = text_argument(&arguments, "idempotency_key")?;
                let service = client::demo_backends()?;
                success(create_rma(&service, &order_id, &reason, &idempotency_key).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "order",
        "create_warranty_claim",
        "Register a warranty claim and book a pickup. Idempotent per idempotency_key.",
        create_schema("defect"),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = argument(&arguments, "order_id");
                let defect = text_argument(&arguments, "defect")?;
                let idempotency_key = text_argument(&arguments, "idempotency_key")?;
                let service = client::demo_backends()?;
                success(
                    create_warranty_claim(&service, &order_id, &defect, &idempotency_key).await?,
                )
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "order",
        "issue_refund",
        "Refund one payment in full or in part. Idempotent per idempotency_key.",
        refund_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let payment_id = argument(&arguments, "payment_id");
                let amount = number_argument(&arguments, "amount")?;
                let idempotency_key = text_argument(&arguments, "idempotency_key")?;
                let service = client::demo_backends()?;
                success(issue_refund(&service, &payment_id, amount, &idempotency_key).await?)
            })
        }),
    ));
}

/// One order-id argument.
fn order_schema() -> serde_json::Map<String, Value> {
    schema(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "order_id": {"type": "string"},
        },
        "required": ["order_id"],
    }))
}

/// An order id, one idempotency key and the operation's own reason field.
fn create_schema(reason: &str) -> serde_json::Map<String, Value> {
    let mut properties = serde_json::Map::new();
    properties.insert("order_id".to_owned(), json!({"type": "string"}));
    properties.insert(reason.to_owned(), json!({"type": "string"}));
    properties.insert("idempotency_key".to_owned(), json!({"type": "string"}));
    schema(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": properties,
        "required": ["order_id", reason, "idempotency_key"],
    }))
}

/// A payment id, a number amount and one idempotency key.
fn refund_schema() -> serde_json::Map<String, Value> {
    schema(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "payment_id": {"type": "string"},
            "amount": {"type": "number"},
            "idempotency_key": {"type": "string"},
        },
        "required": ["payment_id", "amount", "idempotency_key"],
    }))
}
