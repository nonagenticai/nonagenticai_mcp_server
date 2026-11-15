//! procedures tool: namespace `procedures`, so `procedures_get_procedure`.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{argument, schema, success};

/// Steps of the PUBLISHED version of a procedure (the PKO/PDDL model from carebus-api).
pub async fn get_procedure(service: &ServiceClient, name: &Value) -> Result<Value, String> {
    let path = format!("/api/procedures/{}", client::path_id("name", name)?);
    service.get(&path, &[("status", "PUBLISHED")]).await
}

/// Register the procedures tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "procedures",
        "get_procedure",
        "Steps of the PUBLISHED version of a procedure (PKO/PDDL model from carebus-api).",
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "name": {"type": "string"},
            },
            "required": ["name"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let name = argument(&arguments, "name");
                let service = client::carebus_api()?;
                success(get_procedure(&service, &name).await?)
            })
        }),
    ));
}
