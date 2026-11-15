//! delivery tools: namespace `delivery`, so `delivery_track_shipment`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{argument, schema, success};

/// Carrier status, scan events and ETA for a shipment.
pub async fn track_shipment(service: &ServiceClient, shipment_id: &Value) -> Result<Value, String> {
    let path = format!(
        "/api/shipments/{}",
        client::path_id("shipment_id", shipment_id)?
    );
    service.get(&path, &[]).await
}

/// Register the delivery tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "delivery",
        "track_shipment",
        "Carrier status, scan events and ETA for a shipment.",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "shipment_id": {"type": "string"},
            },
            "required": ["shipment_id"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let shipment_id = argument(&arguments, "shipment_id");
                let service = client::demo_backends()?;
                success(track_shipment(&service, &shipment_id).await?)
            })
        }),
    ));
}
