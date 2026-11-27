//! handover tools: namespace `handover`. `handover_request` hands a care-bus conversation to a
//! person: carebus-api's internal route opens the operator handover and answers with the Telegram
//! chat and topic.
//!
//! The body rides carebus-api's service bearer (`CAREBUS_API_TOKEN`), the tenant comes from the
//! caller's own licence and the job key from `CAREBUS_JOB`. Nothing here logs the conversation id,
//! the reason, the token or the body.

use std::sync::Arc;

use serde_json::{Value, json};

use crate::builtin::BuiltinCaller;
use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{schema, success, text_argument};

/// The request tool's description, read by the model.
const REQUEST_DESCRIPTION: &str = "Hand the conversation to a person: ask care-bus to open an operator handover for it.\n\n\
conversation_id: the care-bus conversation to hand over, exactly as the session names it.\n\
reason: the visitor's own words for why they need a person; never invent one.";

/// The caller's tenant: its licence names it, and the handover is filed under it. A credential
/// that carries no tenant cannot be handed over; no deployment default is invented here.
fn tenant(caller: &BuiltinCaller) -> Result<String, String> {
    caller
        .tenant_id
        .as_deref()
        .filter(|tenant| !tenant.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            "[permanent] a licence tenant is required to request a handover; this caller carries none"
                .to_owned()
        })
}

/// The handover's job key (`CAREBUS_JOB`): the care-bus job the handover belongs to. There is no
/// compiled default — a public repository names no deployment.
fn job() -> Result<String, String> {
    std::env::var("CAREBUS_JOB")
        .ok()
        .filter(|job| !job.trim().is_empty())
        .ok_or_else(|| "[permanent] CAREBUS_JOB is not set on the MCP server".to_owned())
}

/// File one handover with carebus-api's internal route. The route opens the operator topic and
/// answers `{status: "handed_over", chat_id, thread_id}`, which the caller gets unchanged; 429,
/// 5xx and timeouts are retryable and every other 4xx is permanent (see [`ServiceClient`]).
pub async fn request(
    api: &ServiceClient,
    tenant_id: &str,
    job: &str,
    conversation_id: &str,
    reason: &str,
) -> Result<Value, String> {
    api.post(
        "/api/internal/handover",
        json!({
            "tenant_id": tenant_id,
            "job": job,
            "conversation_id": conversation_id,
            "reason": reason,
        }),
    )
    .await
}

/// Register the handover tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "handover",
        "request",
        REQUEST_DESCRIPTION,
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "conversation_id": {"type": "string"},
                "reason": {"type": "string"},
            },
            "required": ["conversation_id", "reason"],
        })),
        Arc::new(|caller, arguments| {
            boxed(async move {
                let conversation_id = text_argument(&arguments, "conversation_id")?;
                // A blank id names no conversation; refuse before any client is resolved.
                if conversation_id.trim().is_empty() {
                    return Err(
                        "[permanent] invalid conversation_id: expected the conversation to hand over"
                            .to_owned(),
                    );
                }
                let reason = text_argument(&arguments, "reason")?;
                // The operator needs the visitor's words; a blank reason is the caller's mistake.
                if reason.trim().is_empty() {
                    return Err(
                        "[permanent] invalid reason: expected the visitor's words".to_owned()
                    );
                }
                let tenant_id = tenant(&caller)?;
                let job_key = job()?;
                let api = client::carebus_api()?;
                success(request(&api, &tenant_id, &job_key, &conversation_id, &reason).await?)
            })
        }),
    ));
}
