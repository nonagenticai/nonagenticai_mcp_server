//! crm tools: namespace `crm`, so `crm_verify_customer` and `crm_get_start_data`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{argument, schema, success};

/// Verify a customer id and return name, tier and verification status.
pub async fn verify_customer(
    service: &ServiceClient,
    customer_id: &Value,
) -> Result<Value, String> {
    let path = format!(
        "/api/customers/{}",
        client::path_id("customer_id", customer_id)?
    );
    let customer = service.get(&path, &[]).await?;
    Ok(json!({
        "customer_id": required(&customer, "customer_id")?,
        "name": required(&customer, "name")?,
        "tier": required(&customer, "tier")?,
        "verified": true,
    }))
}

/// Most recent orders, shipments, payments and communications (last 90 days).
pub async fn get_start_data(service: &ServiceClient, customer_id: &Value) -> Result<Value, String> {
    let path = format!(
        "/api/customers/{}/start-data",
        client::path_id("customer_id", customer_id)?
    );
    service.get(&path, &[]).await
}

/// The reference's `c["field"]`: a customer record missing one is a permanent tool error.
fn required(customer: &Value, field: &str) -> Result<Value, String> {
    customer
        .get(field)
        .cloned()
        .ok_or_else(|| format!("[permanent] customer record is missing {field:?}"))
}

/// Register the two crm tools.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "crm",
        "verify_customer",
        "Verify a customer id and return name, tier and verification status.",
        customer_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let customer_id = argument(&arguments, "customer_id");
                let service = client::demo_backends()?;
                success(verify_customer(&service, &customer_id).await?)
            })
        }),
    ));
    provider.register(BuiltinTool::new(
        "crm",
        "get_start_data",
        "Most recent orders, shipments, payments and communications (last 90 days).",
        customer_schema(),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let customer_id = argument(&arguments, "customer_id");
                let service = client::demo_backends()?;
                success(get_start_data(&service, &customer_id).await?)
            })
        }),
    ));
}

/// Both crm tools take exactly one customer id.
fn customer_schema() -> serde_json::Map<String, Value> {
    schema(json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "customer_id": {"type": "string"},
        },
        "required": ["customer_id"],
    }))
}
