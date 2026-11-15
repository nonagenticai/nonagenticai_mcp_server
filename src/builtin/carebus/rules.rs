//! business-rules tools: namespace `rules`.
//!
//! `category` and `delivered_on` are in the declared schema because care-bus step arguments
//! send them, and the rules service reads both from the order: neither is forwarded.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{schema, success, text_argument};

/// `RET-01`: returns are allowed for 30 days after delivery.
pub async fn check_return_window(service: &ServiceClient, order_id: &str) -> Result<Value, String> {
    service
        .get("/api/rules/return-window", &[("order_id", order_id)])
        .await
}

/// `WAR-01`: 24 months of warranty after delivery.
pub async fn check_warranty(service: &ServiceClient, order_id: &str) -> Result<Value, String> {
    service
        .get("/api/rules/warranty", &[("order_id", order_id)])
        .await
}

/// `PAY-04`: two equal captures within 5 minutes count as a duplicate charge.
pub async fn check_payment_issue(
    service: &ServiceClient,
    order_id: &str,
    error_type: &str,
) -> Result<Value, String> {
    service
        .get(
            "/api/rules/payment-issue",
            &[("order_id", order_id), ("error_type", error_type)],
        )
        .await
}

/// Register the three rules tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "rules",
        "check_return_window",
        "RET-01: returns are allowed for 30 days after delivery. category and delivered_on are accepted because step args send them; the rule reads both from the order.",
        window_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = text_argument(&arguments, "order_id")?;
                let service = client::demo_backends()?;
                success(check_return_window(&service, &order_id).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "rules",
        "check_warranty",
        "WAR-01: 24 months of warranty after delivery. category and delivered_on are accepted, not forwarded.",
        window_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = text_argument(&arguments, "order_id")?;
                let service = client::demo_backends()?;
                success(check_warranty(&service, &order_id).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "rules",
        "check_payment_issue",
        "PAY-04: two equal captures within 5 minutes count as a duplicate charge.",
        payment_issue_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let order_id = text_argument(&arguments, "order_id")?;
                let error_type = text_argument(&arguments, "error_type")?;
                let service = client::demo_backends()?;
                success(check_payment_issue(&service, &order_id, &error_type).await?)
            })
        }),
    ));
}

/// An order id plus the two step arguments the rule accepts but never forwards.
fn window_schema() -> serde_json::Map<String, Value> {
    schema(json!({
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
    }))
}

/// An order id and the payment error the caller reports.
fn payment_issue_schema() -> serde_json::Map<String, Value> {
    schema(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "order_id": {"type": "string"},
            "error_type": {"type": "string"},
        },
        "required": ["order_id", "error_type"],
    }))
}
