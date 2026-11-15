//! The n8n workflow adapter: the reference's `src/external/n8n.py`.
//!
//! HTTP only — the driver owns every `mcp_runs` write — and the same rule the whole module keeps:
//! no log line and no [`ExternalState::message`] ever carries the API key, the webhook secret or
//! an upstream body. The one message this adapter produces is the reference's fixed sentence for a
//! workflow parked in fr approval.
//!
//! Three upstream shapes are carried over unchanged:
//!
//! - a **start** is one JSON webhook call. When a secret is configured it travels as a short-lived
//!   HS256 JWT rather than the secret itself, because n8n stores every request header in the
//!   execution record.
//! - a **poll** is one execution read, whose body is capped at 4 MiB so a workflow that returns a
//!   bucket cannot exhaust the driver, and whose extracted result is capped at 64 KiB of compact
//!   JSON.
//! - an `unknown` status is counted per run and fails after `unknown_status_limit` consecutive
//!   sightings rather than polling a wedged execution forever.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard};

use async_trait::async_trait;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use reqwest::StatusCode;
use serde_json::{Map, Value, json};
use sha2::Sha256;

use super::{
    AdapterError, ExternalAdapter, ExternalRef, ExternalStartError, ExternalState, RefKind,
};
use crate::config::ExternalDriverSettings;
use crate::worker::row::WorkerRow;

/// The reference's `BODY_LIMIT_BYTES`: the most of an execution body this adapter will read.
const BODY_LIMIT_BYTES: usize = 4 * 1024 * 1024;

/// The reference's `RESULT_LIMIT_BYTES`: the most compact JSON a run's result may occupy.
const RESULT_LIMIT_BYTES: usize = 64 * 1024;

/// The reference's `DEFAULT_RESULT_NODE`: the node a workflow's answer is read from when its
/// target does not name one.
const DEFAULT_RESULT_NODE: &str = "MCP Result";

/// The reference's `WAITING_MESSAGE`: the one progress sentence a poll may report.
const WAITING_MESSAGE: &str = "waiting for approval in fr";

/// The reference's `WEBHOOK_TOKEN_TTL_SECONDS`: how long a start JWT is valid.
const WEBHOOK_TOKEN_TTL_SECONDS: i64 = 120;

/// The reference's JWT header, byte for byte: HS256, no `kid`, no claims beyond the three.
const JWT_HEADER: &str = r#"{"alg":"HS256","typ":"JWT"}"#;

/// `quote(segment, safe="")`: everything but the RFC 3986 unreserved characters is escaped, which
/// is what Python's `urllib.parse.quote` keeps.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

const UNCONFIGURED: &str = "external_unconfigured";
const START_FAILED: &str = "external_start_failed";
const POLL_FAILED: &str = "external_poll_failed";
const MISSING: &str = "external_missing";
const RESULT_INVALID: &str = "external_result_invalid";
const RESULT_REDACTED: &str = "external_result_redacted";
const STATUS_UNKNOWN: &str = "external_status_unknown";
const FAILED: &str = "external_failed";
const CANCEL_FAILED: &str = "external_cancel_failed";

/// The n8n settings this adapter reads, narrowed from [`ExternalDriverSettings`].
///
/// The names drop the reference's `n8n_` prefix because the whole struct is n8n's. As in the
/// reference settings, an empty string is unset for the two base URLs (pydantic's
/// `str | None`); the API key and webhook secret are secrets — present or absent, never empty.
#[derive(Clone, PartialEq, Eq)]
pub struct N8nSettings {
    /// `MCP_N8N_BASE_URL`: the API base every execution read and stop is made against.
    pub base_url: Option<String>,
    /// `MCP_N8N_WEBHOOK_BASE_URL`: the base a workflow start posts to.
    pub webhook_base_url: Option<String>,
    /// `MCP_N8N_API_KEY`: the `X-N8N-API-KEY` every execution call carries. Never logged.
    pub api_key: Option<String>,
    /// `MCP_N8N_WEBHOOK_SECRET`: the HS256 key a start JWT is signed with. Never logged.
    pub webhook_secret: Option<String>,
    /// `MCP_N8N_UNKNOWN_STATUS_LIMIT`: consecutive `unknown` statuses after which the run fails.
    pub unknown_status_limit: u32,
}

impl From<&ExternalDriverSettings> for N8nSettings {
    fn from(settings: &ExternalDriverSettings) -> Self {
        Self {
            base_url: settings.n8n_base_url.clone(),
            webhook_base_url: settings.n8n_webhook_base_url.clone(),
            api_key: settings.n8n_api_key.clone(),
            webhook_secret: settings.n8n_webhook_secret.clone(),
            unknown_status_limit: settings.n8n_unknown_status_limit,
        }
    }
}

/// [`N8nSettings`] with both secrets redacted, so a stray `?settings` cannot leak them.
impl std::fmt::Debug for N8nSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("N8nSettings")
            .field("base_url", &self.base_url)
            .field("webhook_base_url", &self.webhook_base_url)
            .field("api_key", &self.api_key.as_ref().map(|_| "<redacted>"))
            .field(
                "webhook_secret",
                &self.webhook_secret.as_ref().map(|_| "<redacted>"),
            )
            .field("unknown_status_limit", &self.unknown_status_limit)
            .finish()
    }
}

/// The start JWT the n8n Webhook node's JWT Auth credential checks.
///
/// Header and claims are the exact bytes the reference's PyJWT call produced: the header is
/// `{"alg":"HS256","typ":"JWT"}`, the claims are `sub`, `iat`, `exp` in that order, and the
/// signing input is `base64url(header) "." base64url(claims)` with no padding.
pub fn webhook_token(secret: &str, run_id: &str, now: i64) -> String {
    let mut claims = Map::new();
    claims.insert("sub".to_owned(), json!(run_id));
    claims.insert("iat".to_owned(), json!(now));
    claims.insert(
        "exp".to_owned(),
        json!(now.saturating_add(WEBHOOK_TOKEN_TTL_SECONDS)),
    );
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(JWT_HEADER),
        URL_SAFE_NO_PAD.encode(Value::Object(claims).to_string())
    );
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .expect("HMAC accepts a key of any length");
    mac.update(signing_input.as_bytes());
    format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    )
}

/// One n8n workflow runtime (the reference's `N8nAdapter`).
pub struct N8nAdapter {
    client: reqwest::Client,
    settings: N8nSettings,
    /// How many consecutive `unknown` statuses each run has reported, keyed by run id. The
    /// reference keeps this in the adapter, so it is per process and dies with it.
    unknown: Mutex<HashMap<String, u32>>,
}

impl N8nAdapter {
    /// An adapter over one HTTP client and one settings snapshot.
    pub fn new(client: reqwest::Client, settings: N8nSettings) -> Self {
        Self {
            client,
            settings,
            unknown: Mutex::new(HashMap::new()),
        }
    }

    /// The per-run `unknown` counter. A poisoned lock still holds a usable map.
    fn unknown(&self) -> MutexGuard<'_, HashMap<String, u32>> {
        self.unknown
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// The API base and key, both required — the reference's `_api_configured`.
    fn api_configured(&self) -> Option<(&str, &str)> {
        let base = self
            .settings
            .base_url
            .as_deref()
            .filter(|base| !base.is_empty())?;
        let key = self.settings.api_key.as_deref()?;
        Some((base, key))
    }

    /// The reference's `_succeeded`: the run's answer out of a `success` execution body.
    ///
    /// `authority.manifest` is a JSON **string** and names the node carrying the answer at
    /// `target.result_node`; a missing or empty name means `DEFAULT_RESULT_NODE`. A payload
    /// whose answer path is absent is an empty answer, not a failure — a workflow that returned
    /// nothing still ran. A redacted or oversized answer is a failure: the client must never see
    /// a partial result.
    pub fn result_state(row: &WorkerRow, payload: &Value) -> ExternalState {
        let manifest_target = target(row);
        let node = manifest_target
            .get("result_node")
            .and_then(Value::as_str)
            .filter(|node| !node.is_empty())
            .unwrap_or(DEFAULT_RESULT_NODE);
        if payload.get("dataTooLargeToDisplay").is_some_and(truthy) {
            return ExternalState::failed(RESULT_INVALID);
        }
        let Some(data) = payload.get("data").and_then(Value::as_object) else {
            return ExternalState::failed(RESULT_INVALID);
        };
        let redacted = data
            .get("redactionInfo")
            .and_then(Value::as_object)
            .and_then(|info| info.get("isRedacted"))
            .is_some_and(truthy);
        if redacted {
            // The workflow's redaction policy hides its output (revealing needs execution:reveal).
            return ExternalState::failed(RESULT_REDACTED);
        }
        let result = data
            .get("resultData")
            .and_then(|value| value.get("runData"))
            .and_then(|value| value.get(node))
            .and_then(last)
            .and_then(|value| value.get("data"))
            .and_then(|value| value.get("main"))
            // `main[0][-1]`: the FIRST output branch, its LAST item. Not `main[-1]` — a node
            // with several branches would otherwise answer with a different branch's item.
            .and_then(first)
            .and_then(last)
            .and_then(|value| value.get("json"));
        let Some(result) = result else {
            return ExternalState::succeeded(Some(json!({})));
        };
        if !result.is_object() {
            return ExternalState::failed(RESULT_INVALID);
        }
        match serde_json::to_vec(result) {
            Ok(encoded) if encoded.len() <= RESULT_LIMIT_BYTES => {
                ExternalState::succeeded(Some(Value::clone(result)))
            }
            _ => ExternalState::failed(RESULT_INVALID),
        }
    }
}

#[async_trait]
impl ExternalAdapter for N8nAdapter {
    async fn start(&self, row: &WorkerRow) -> Result<ExternalRef, ExternalStartError> {
        let Some(base) = self
            .settings
            .webhook_base_url
            .as_deref()
            .filter(|base| !base.is_empty())
        else {
            return Err(ExternalStartError::new(UNCONFIGURED));
        };
        let manifest_target = target(row);
        let path = manifest_target
            .get("webhook_path")
            .and_then(Value::as_str)
            .ok_or_else(|| ExternalStartError::new(START_FAILED))?;
        let url = format!(
            "{}/webhook/{}",
            base.trim_end_matches('/'),
            path.trim_start_matches('/')
        );
        let run_id = row.run.run_id.to_string();
        let body = json!({
            "mcp_run_id": run_id.clone(),
            "tenant_id": row.run.tenant_id.to_string(),
            "inputs": row.run.inputs.clone(),
        });
        let mut request = self.client.post(url).json(&body);
        if let Some(secret) = self.settings.webhook_secret.as_deref() {
            let token = webhook_token(secret, &run_id, Utc::now().timestamp());
            request = request.header("Authorization", format!("Bearer {token}"));
        }
        let response = request
            .send()
            .await
            .map_err(|_| ExternalStartError::new(START_FAILED))?;
        if !response.status().is_success() {
            return Err(ExternalStartError::new(START_FAILED));
        }
        let payload = response
            .json::<Value>()
            .await
            .map_err(|_| ExternalStartError::new(START_FAILED))?;
        let execution_id = payload
            .get("executionId")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ExternalStartError::new(START_FAILED))?;
        Ok(ExternalRef::new(RefKind::N8n, execution_id))
    }

    async fn poll(&self, row: &WorkerRow) -> Result<ExternalState, AdapterError> {
        let Some((base, key)) = self.api_configured() else {
            return Ok(ExternalState::failed(UNCONFIGURED));
        };
        let run_key = row.run.run_id.to_string();
        let id = execution_id(row).ok_or_else(|| AdapterError::new(POLL_FAILED))?;
        // n8n 2.46.1 drops `data` above EXECUTIONS_DATA_MAX_DISPLAY_SIZE unless asked; the body
        // cap below still bounds what is read. The query is part of the URL because the values
        // are fixed literals: nothing here needs encoding, and it keeps the request identical to
        // the reference's `params={...}`.
        let mut response = self
            .client
            .get(execution_url(
                base,
                id,
                "?includeData=true&ignoreDataSizeLimit=true",
            ))
            .header("X-N8N-API-KEY", key)
            .send()
            .await
            .map_err(|_| AdapterError::new(POLL_FAILED))?;
        if response.status() == StatusCode::NOT_FOUND {
            self.unknown().remove(&run_key);
            return Ok(ExternalState::failed(MISSING));
        }
        if !response.status().is_success() {
            // The reference's `raise_for_status`: a transient upstream failure, retried on the
            // next tick rather than failing the run.
            return Err(AdapterError::new(POLL_FAILED));
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    if body.len() + chunk.len() > BODY_LIMIT_BYTES {
                        self.unknown().remove(&run_key);
                        return Ok(ExternalState::failed(RESULT_INVALID));
                    }
                    body.extend_from_slice(&chunk);
                }
                Ok(None) => break,
                Err(_) => return Err(AdapterError::new(POLL_FAILED)),
            }
        }
        let Ok(payload) = serde_json::from_slice::<Value>(&body) else {
            return Ok(ExternalState::failed(RESULT_INVALID));
        };
        let status = payload.get("status").and_then(Value::as_str);
        if status == Some("unknown") {
            let mut unknown = self.unknown();
            let count = unknown.get(&run_key).copied().unwrap_or(0) + 1;
            if count >= self.settings.unknown_status_limit {
                unknown.remove(&run_key);
                return Ok(ExternalState::failed(STATUS_UNKNOWN));
            }
            unknown.insert(run_key, count);
            return Ok(ExternalState::running());
        }
        self.unknown().remove(&run_key);
        Ok(match status {
            Some("new" | "running") => ExternalState::running(),
            Some("waiting") => ExternalState::running_with(WAITING_MESSAGE),
            Some("success") => Self::result_state(row, &payload),
            Some("canceled") => ExternalState::cancelled(),
            _ => ExternalState::failed(FAILED),
        })
    }

    async fn cancel(&self, row: &WorkerRow) -> Result<(), AdapterError> {
        let requested = row.run.external_ref.as_ref().is_some_and(truthy);
        let Some((base, key)) = self.api_configured() else {
            return Ok(());
        };
        if !requested {
            return Ok(());
        }
        let id = execution_id(row).ok_or_else(|| AdapterError::new(CANCEL_FAILED))?;
        let response = self
            .client
            .post(execution_url(base, id, "/stop"))
            .header("X-N8N-API-KEY", key)
            .send()
            .await
            .map_err(|_| AdapterError::new(CANCEL_FAILED))?;
        if response.status() == StatusCode::NOT_FOUND || response.status().is_success() {
            // A finished-and-retentioned execution has nothing left to stop.
            return Ok(());
        }
        Err(AdapterError::new(CANCEL_FAILED))
    }
}

/// The reference's `_target`: the run's manifest target object, or null when it does not exist.
///
/// `authority.manifest` is a JSON string written by the API at admission; a member that is
/// already an object is accepted too, because the reference's `_target` tolerates either. A
/// missing, mistyped or unparseable manifest degrades to "no target", never a panic.
fn target(row: &WorkerRow) -> Value {
    let Some(manifest) = row.run.authority.get("manifest") else {
        return Value::Null;
    };
    let manifest = match manifest {
        Value::String(text) => match serde_json::from_str::<Value>(text) {
            Ok(manifest) => manifest,
            Err(_) => return Value::Null,
        },
        other => other.clone(),
    };
    manifest.get("target").cloned().unwrap_or(Value::Null)
}

/// The execution id a run is parked on, when the row recorded one.
fn execution_id(row: &WorkerRow) -> Option<&str> {
    row.run.external_ref.as_ref()?.get("id")?.as_str()
}

/// One execution URL: the base, the percent-encoded id, then the suffix (`""` or `"/stop"`).
fn execution_url(base: &str, id: &str, suffix: &str) -> String {
    format!(
        "{}/api/v1/executions/{}{suffix}",
        base.trim_end_matches('/'),
        utf8_percent_encode(id, PATH_SEGMENT)
    )
}

/// Python truthiness for a JSON value, which the upstream payloads are written in.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}

/// The last element of a JSON array, or nothing (the reference's `[-1]`).
fn last(value: &Value) -> Option<&Value> {
    value.as_array().and_then(|items| items.last())
}

/// The first item of a JSON array.
fn first(value: &Value) -> Option<&Value> {
    value.as_array().and_then(|items| items.first())
}
