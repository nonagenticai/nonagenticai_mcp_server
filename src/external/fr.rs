//! The fr project and one-shot command adapters.
//!
//! Ported from the reference `src/external/fr.py`: fr's `mcp` channel takes the same commands a
//! chat user types, spoken as the person the run's actor names. A project start parks an action
//! approval; its outcome arrives as an fr event that records the project id on the run's
//! `external_ref`, which is what this adapter polls.
//!
//! HTTP only: an adapter never writes `mcp_runs`, never logs secrets or bodies.

use std::collections::BTreeMap;
use std::sync::LazyLock;
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use regex::Regex;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use serde_json::{Map, Value, json};

use crate::config::ExternalDriverSettings;
use crate::external::signing::sign;
use crate::external::{
    AdapterError, AnswerForwarder, ExternalAdapter, ExternalRef, ExternalStartError, ExternalState,
    RefKind,
};
use crate::storage::task_inputs::TaskInputRow;
use crate::worker::row::WorkerRow;

/// The inbound channel path fr accepts signed messages on.
const INBOUND_PATH: &str = "/api/webhooks/mcp/incoming";
/// The start failure code used when fr's answer names no project.
const DEFAULT_START_CODE: &str = "external_start_failed";
/// fr's inbound text limit (`channels/mcp.ts` `MAX_TEXT`).
const TEXT_LIMIT: usize = 4000;
/// Start inputs copied onto the create payload, in the reference's order.
const START_PASSTHROUGH: [&str; 4] = [
    "description",
    "problem_statement",
    "desired_outcome",
    "repository_url",
];
/// The longest progress text that fits `mcp_runs.status_message`.
const PHASE_LIMIT: usize = 512;
/// Optional actor fields forwarded next to `address`.
const ACTOR_CONTEXT: [&str; 2] = ["job", "on_behalf_of"];
/// `projects.status` values that end the run as cancelled.
const CANCELLED_STATUSES: [&str; 2] = ["cancelled", "archived"];
/// `projects.status` values that end the run as failed.
const FAILED_STATUSES: [&str; 1] = ["failed"];
/// The project fields a tool result carries.
const PROJECT_KEYS: [&str; 9] = [
    "id",
    "name",
    "project_type",
    "status",
    "phase",
    "url",
    "delivered_at",
    "delivery_evidence",
    "deliverables",
];
/// The `projects.close` answer: the read fields plus how it closed.
const CLOSED_KEYS: [&str; 12] = [
    "id",
    "name",
    "project_type",
    "status",
    "phase",
    "url",
    "delivered_at",
    "delivery_evidence",
    "deliverables",
    "closed",
    "already_closed",
    "rm_pm_project_id",
];
/// The channel commands a catalog target may pin.
const FR_COMMANDS: [&str; 2] = ["projects.get", "projects.close"];
/// The most bytes a project view may occupy, compact UTF-8.
const PROJECT_VIEW_MAX_BYTES: usize = 64 * 1024;
/// Fields dropped, whole, when a view is too large.
const DROPPABLE_KEYS: [&str; 2] = ["deliverables", "delivery_evidence"];

/// `^[a-z0-9_-]{1,128}$`: fr's project-type name.
static PROJECT_TYPE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9_-]{1,128}$").expect("project type pattern"));

/// The fr settings the adapter reads: the backend base and the channel HMAC key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrSettings {
    /// `MCP_FR_BASE_URL`: the fr backend base.
    pub base_url: Option<String>,
    /// `MCP_FR_CHANNEL_SECRET`: the HMAC key every channel message is signed with. Never logged.
    pub channel_secret: Option<String>,
}

impl From<&ExternalDriverSettings> for FrSettings {
    fn from(settings: &ExternalDriverSettings) -> Self {
        Self {
            base_url: settings.fr_base_url.clone(),
            channel_secret: settings.fr_channel_secret.clone(),
        }
    }
}

/// Python truthiness, as `data.get("code") or ...` and `if inputs.get(key)` use it.
fn is_truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// Python's `str(value)` for the scalars fr returns; containers fall back to their JSON.
fn py_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// Python's `" ".join(str(value).split())` over a falsy-or-missing value.
fn one_line(value: Option<&Value>) -> String {
    let Some(value) = value.filter(|value| is_truthy(value)) else {
        return String::new();
    };
    py_str(value)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Map an upstream error code into `^[a-z_]{1,64}$`.
pub fn sanitize_code(value: &Value, default: &str) -> String {
    let Value::String(text) = value else {
        return default.to_owned();
    };
    let code: String = text
        .to_lowercase()
        .chars()
        .map(|character| {
            if character.is_ascii_lowercase() || character == '_' {
                character
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if code.chars().all(|character| character == '_') {
        default.to_owned()
    } else {
        code
    }
}

/// fr's chat grammar for an answer: `approve <id> [comment]` / `reject <id> <reason>`.
pub fn decision_text(approval_id: &str, content: &Value) -> Option<String> {
    match content.get("decision").and_then(Value::as_str) {
        Some("approved") => {
            let comment = one_line(content.get("comment"));
            Some(format!("approve {approval_id} {comment}").trim().to_owned())
        }
        Some("rejected") => {
            let reason = one_line(content.get("reason"));
            if reason.is_empty() {
                None
            } else {
                Some(format!("reject {approval_id} {reason}"))
            }
        }
        _ => None,
    }
}

/// One fr project as a tool result: the public fields that are present, nothing else, bounded
/// so fr evidence cannot blow the run's result.
pub fn project_view(project: &Value) -> Value {
    Value::Object(view_of(project, &PROJECT_KEYS))
}

/// The `projects.close` answer: the project plus how it closed.
pub fn close_view(project: &Value) -> Value {
    Value::Object(view_of(project, &CLOSED_KEYS))
}

fn view_of(project: &Value, keys: &[&str]) -> Map<String, Value> {
    let mut view = Map::new();
    for key in keys {
        if let Some(value) = project.get(*key).filter(|value| !value.is_null()) {
            view.insert((*key).to_owned(), value.clone());
        }
    }
    bounded(view)
}

/// The compact UTF-8 size of one view, exactly the reference's `_encoded_size`.
fn encoded_size(view: &Map<String, Value>) -> usize {
    serde_json::to_string(view)
        .map(|encoded| encoded.len())
        .unwrap_or(usize::MAX)
}

/// Bound a view to [`PROJECT_VIEW_MAX_BYTES`]: drop `deliverables`, then `delivery_evidence`,
/// and as a last resort cut every string to an equal share, halving until it fits.
fn bounded(mut view: Map<String, Value>) -> Map<String, Value> {
    if encoded_size(&view) <= PROJECT_VIEW_MAX_BYTES {
        return view;
    }
    for key in DROPPABLE_KEYS {
        view.remove(key);
        if encoded_size(&view) <= PROJECT_VIEW_MAX_BYTES {
            return view;
        }
    }
    // `share` counts characters, as Python's `value[:share]` does.
    let mut share = PROJECT_VIEW_MAX_BYTES / view.len().max(1);
    let mut bounded = shrink(&view, share);
    while encoded_size(&bounded) > PROJECT_VIEW_MAX_BYTES && share > 64 {
        share /= 2;
        bounded = shrink(&view, share);
    }
    bounded
}

/// Every string cut to `share` characters; the fixed scalars are untouched.
fn shrink(view: &Map<String, Value>, share: usize) -> Map<String, Value> {
    view.iter()
        .map(|(key, value)| {
            let value = match value {
                Value::String(text) => Value::String(text.chars().take(share).collect()),
                other => other.clone(),
            };
            (key.clone(), value)
        })
        .collect()
}

fn truncate_chars(text: String, limit: usize) -> String {
    text.chars().take(limit).collect()
}

/// A stored actor (the run's or an answer's) with a non-empty address, else `None`.
fn actor_of(value: Option<&Value>) -> Option<Value> {
    let value = value?;
    if let Value::String(encoded) = value {
        let parsed = serde_json::from_str::<Value>(encoded).ok()?;
        return actor_object(parsed);
    }
    actor_object(value.clone())
}

fn actor_object(value: Value) -> Option<Value> {
    let Value::Object(map) = value else {
        return None;
    };
    let address = map.get("address")?.as_str()?;
    if address.is_empty() {
        return None;
    }
    Some(Value::Object(map))
}

/// An `agent:<tenant>` address may only name the run's own tenant.
fn in_tenant(row: &WorkerRow, actor: &Value) -> bool {
    let Some(address) = actor.get("address").and_then(Value::as_str) else {
        return false;
    };
    !address.starts_with("agent:") || address == format!("agent:{}", row.run.tenant_id)
}

/// The run's manifest, whose members are JSON strings in the authority snapshot.
fn manifest_of(row: &WorkerRow) -> Value {
    match row.run.authority.get("manifest") {
        Some(Value::String(encoded)) => serde_json::from_str(encoded).unwrap_or(Value::Null),
        Some(value) => value.clone(),
        None => Value::Null,
    }
}

/// The call's `project_type` input, else the tool target's default.
fn project_type_of(row: &WorkerRow) -> Result<String, ExternalStartError> {
    match row.run.inputs.get("project_type") {
        None | Some(Value::Null) => manifest_of(row)
            .get("target")
            .and_then(|target| target.get("project_type"))
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| ExternalStartError::new("invalid_project_type")),
        Some(requested) => {
            let Some(requested) = requested.as_str() else {
                return Err(ExternalStartError::new("invalid_project_type"));
            };
            if !PROJECT_TYPE.is_match(requested) {
                return Err(ExternalStartError::new("invalid_project_type"));
            }
            Ok(requested.to_owned())
        }
    }
}

fn target_command(row: &WorkerRow) -> Option<String> {
    manifest_of(row)
        .get("target")?
        .get("command")?
        .as_str()
        .map(str::to_owned)
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs() as i64)
        .unwrap_or(0)
}

/// One failed channel message: fr's answered refusal, an HTTP status, or transport failure.
enum SendError {
    Refused(String),
    Http(u16),
    Unavailable,
}

impl SendError {
    /// The public code the driver records (`^[a-z_]{1,64}$`).
    fn code(self) -> String {
        match self {
            Self::Refused(code) => code,
            Self::Unavailable => "fr_unavailable".to_owned(),
            Self::Http(status) if status >= 500 => "fr_unavailable".to_owned(),
            Self::Http(_) => "fr_rejected".to_owned(),
        }
    }
}

/// The fr project adapter: one project start per run, polled by project id.
#[derive(Debug, Clone)]
pub struct FrAdapter {
    client: reqwest::Client,
    base: String,
    secret: Option<String>,
}

impl FrAdapter {
    /// A project adapter over one HTTP client.
    pub fn new(client: reqwest::Client, settings: FrSettings) -> Self {
        let base = settings
            .base_url
            .unwrap_or_default()
            .trim_end_matches('/')
            .to_owned();
        Self {
            client,
            base,
            secret: settings.channel_secret,
        }
    }

    /// Whether both the base URL and the channel secret are set.
    pub fn configured(&self) -> bool {
        !self.base.is_empty()
            && self
                .secret
                .as_deref()
                .is_some_and(|secret| !secret.is_empty())
    }

    fn require(&self) -> Result<(), &'static str> {
        if self.configured() {
            Ok(())
        } else {
            Err("external_unconfigured")
        }
    }

    /// One signed channel message. The envelope is compact JSON with sorted keys; the projection
    /// text inside it is literal UTF-8 (`ensure_ascii=False`).
    async fn send(&self, actor: &Value, text: &str, correlation: &str) -> Result<Value, SendError> {
        let address = actor
            .get("address")
            .and_then(Value::as_str)
            .unwrap_or_default();
        let mut envelope: BTreeMap<String, Value> = BTreeMap::new();
        envelope.insert("address".to_owned(), json!(address));
        envelope.insert("text".to_owned(), json!(text));
        envelope.insert("correlation_id".to_owned(), json!(correlation));
        for key in ACTOR_CONTEXT {
            if let Some(value) = actor.get(key).filter(|value| is_truthy(value)) {
                envelope.insert(key.to_owned(), value.clone());
            }
        }
        let body = serde_json::to_vec(&envelope)
            .map_err(|_| SendError::Refused("external_result_invalid".to_owned()))?;
        let secret = self.secret.as_deref().unwrap_or_default();
        let mut headers = sign(&body, secret, unix_now());
        headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        let mut header_map = HeaderMap::new();
        for (name, value) in &headers {
            let name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|_| SendError::Refused("external_result_invalid".to_owned()))?;
            let value = HeaderValue::from_bytes(value.as_bytes())
                .map_err(|_| SendError::Refused("external_result_invalid".to_owned()))?;
            header_map.insert(name, value);
        }
        let response = self
            .client
            .post(format!("{}{INBOUND_PATH}", self.base))
            .headers(header_map)
            .body(body)
            .send()
            .await
            .map_err(|_| SendError::Unavailable)?;
        let status = response.status().as_u16();
        if status >= 400 {
            return Err(SendError::Http(status));
        }
        let bytes = response.bytes().await.map_err(|_| SendError::Unavailable)?;
        let Ok(data) = serde_json::from_slice::<Value>(&bytes) else {
            return Err(SendError::Refused("external_result_invalid".to_owned()));
        };
        let Value::Object(data) = data else {
            return Err(SendError::Refused("external_result_invalid".to_owned()));
        };
        match data.get("status").and_then(Value::as_str) {
            Some("unknown-sender") => Err(SendError::Refused("actor_unresolved".to_owned())),
            Some(status @ ("no-action" | "error")) => {
                let code = data
                    .get("code")
                    .filter(|value| is_truthy(value))
                    .cloned()
                    .unwrap_or_else(|| json!(format!("fr_{status}")));
                Err(SendError::Refused(sanitize_code(&code, DEFAULT_START_CODE)))
            }
            _ => Ok(Value::Object(data)),
        }
    }
}

#[async_trait]
impl ExternalAdapter for FrAdapter {
    async fn start(&self, row: &WorkerRow) -> Result<ExternalRef, ExternalStartError> {
        self.require().map_err(ExternalStartError::new)?;
        let actor = actor_of(row.run.actor.as_ref())
            .ok_or_else(|| ExternalStartError::new("actor_required"))?;
        if !in_tenant(row, &actor) {
            return Err(ExternalStartError::new("actor_tenant_mismatch"));
        }
        let title = one_line(row.run.inputs.get("title"));
        if title.is_empty() {
            return Err(ExternalStartError::new("title_required"));
        }
        let mut payload = Map::new();
        payload.insert("title".to_owned(), json!(title));
        payload.insert("project_type".to_owned(), json!(project_type_of(row)?));
        for key in START_PASSTHROUGH {
            if let Some(value) = row.run.inputs.get(key).filter(|value| is_truthy(value)) {
                payload.insert(key.to_owned(), value.clone());
            }
        }
        let payload = serde_json::to_string(&Value::Object(payload))
            .map_err(|_| ExternalStartError::new(DEFAULT_START_CODE))?;
        let text = format!("projects.create {payload}");
        if text.chars().count() > TEXT_LIMIT {
            return Err(ExternalStartError::new("inputs_too_large"));
        }
        let data = self
            .send(&actor, &text, &row.run.run_id.to_string())
            .await
            .map_err(|error| ExternalStartError::new(error.code()))?;
        let status = data.get("status").and_then(Value::as_str);
        let approval = (status == Some("pending-approval"))
            .then(|| data.get("approvalId").and_then(Value::as_str))
            .flatten();
        if let Some(approval) = approval {
            return Ok(ExternalRef::new(RefKind::Fr, approval));
        }
        let project = (status == Some("result"))
            .then(|| {
                data.get("result")
                    .and_then(|result| result.get("project_id"))
                    .and_then(Value::as_str)
                    .filter(|project| !project.is_empty())
            })
            .flatten();
        if let Some(project) = project {
            let mut reference = ExternalRef::new(RefKind::Fr, project);
            reference.project_id = Some(project.to_owned());
            return Ok(reference);
        }
        Err(ExternalStartError::new(DEFAULT_START_CODE))
    }

    async fn poll(&self, row: &WorkerRow) -> Result<ExternalState, AdapterError> {
        self.require().map_err(AdapterError::new)?;
        if row.run.status.as_str() == "cancelling" {
            // fr has no customer cancel: the task ends, the project goes on.
            return Ok(ExternalState::cancelled());
        }
        let reference = row.run.external_ref.as_ref();
        let project = reference
            .and_then(|reference| reference.get("project_id"))
            .and_then(Value::as_str)
            .filter(|project| !project.is_empty());
        let Some(project) = project else {
            let outcome = reference
                .and_then(|reference| reference.get("start_outcome"))
                .and_then(Value::as_str);
            return Ok(match outcome {
                Some("rejected" | "voided") => ExternalState::cancelled(),
                Some("expired") => ExternalState::failed("project_start_expired"),
                Some("failed") => ExternalState::failed("project_start_failed"),
                _ => ExternalState::running_with("waiting for the project start to be approved"),
            });
        };
        let query = json!({ "id": project }).to_string();
        let actor = actor_of(row.run.actor.as_ref()).unwrap_or_else(|| json!({ "address": "" }));
        let data = self
            .send(
                &actor,
                &format!("projects.get {query}"),
                &format!("{}:poll", row.run.run_id),
            )
            .await
            .map_err(|error| AdapterError::new(error.code()))?;
        let Some(project_state) = data.get("result").and_then(Value::as_object) else {
            return Err(AdapterError::new("external_result_invalid"));
        };
        match project_state.get("status").and_then(Value::as_str) {
            Some("delivered") => Ok(ExternalState::succeeded(Some(project_view(
                &Value::Object(project_state.clone()),
            )))),
            Some(status) if CANCELLED_STATUSES.contains(&status) => Ok(ExternalState::cancelled()),
            Some(status) if FAILED_STATUSES.contains(&status) => {
                Ok(ExternalState::failed("project_failed"))
            }
            _ => {
                let phase = project_state
                    .get("phase")
                    .filter(|value| is_truthy(value))
                    .or_else(|| project_state.get("status").filter(|value| is_truthy(value)));
                Ok(match phase {
                    Some(value) => {
                        ExternalState::running_with(truncate_chars(py_str(value), PHASE_LIMIT))
                    }
                    None => ExternalState::running(),
                })
            }
        }
    }

    async fn cancel(&self, row: &WorkerRow) -> Result<(), AdapterError> {
        self.require().map_err(AdapterError::new)?;
        let reference = row.run.external_ref.as_ref();
        if reference
            .and_then(|reference| reference.get("project_id"))
            .is_some_and(is_truthy)
        {
            return Ok(());
        }
        let Some(id) = reference
            .and_then(|reference| reference.get("id"))
            .filter(|id| is_truthy(id))
            .and_then(Value::as_str)
        else {
            return Ok(());
        };
        let Some(actor) = actor_of(row.run.actor.as_ref()) else {
            return Ok(());
        };
        let text = format!("reject {id} cancelled by the client");
        let correlation = format!("{}:cancel", row.run.run_id);
        if let Err(error) = self.send(&actor, &text, &correlation).await {
            tracing::info!(code = %error.code(), "fr start withdrawal refused");
        }
        Ok(())
    }
}

#[async_trait]
impl AnswerForwarder for FrAdapter {
    async fn forward(
        &self,
        row: &WorkerRow,
        item: &TaskInputRow,
    ) -> Result<Option<String>, AdapterError> {
        self.require().map_err(AdapterError::new)?;
        let response = item.response.as_ref();
        if response
            .and_then(|response| response.get("action"))
            .and_then(Value::as_str)
            != Some("accept")
        {
            // Declined or cancelled here: the approval stays open in fr's other channels.
            return Ok(None);
        }
        let actor = actor_of(item.actor.as_ref());
        let content = response
            .and_then(|response| response.get("content"))
            .unwrap_or(&Value::Null);
        let text = decision_text(&item.source_ref, content);
        let (Some(actor), Some(text)) = (actor, text) else {
            return Ok(None);
        };
        if !in_tenant(row, &actor) {
            return Ok(Some("actor_tenant_mismatch".to_owned()));
        }
        let correlation = format!("{}:{}", row.run.run_id, item.input_key);
        match self.send(&actor, &text, &correlation).await {
            Ok(_) => Ok(None),
            Err(SendError::Refused(code)) => {
                tracing::info!(code = %code, "fr refused an answer");
                Ok(Some(code))
            }
            Err(error) => Err(AdapterError::new(error.code())),
        }
    }
}

/// A one-shot fr channel command: `projects.get` / `projects.close` answer at once, so there is
/// nothing to poll and nothing to withdraw. The answer is kept on the run's reference, which is
/// what makes a crash between the send and the status write harmless: `poll` replays it instead
/// of dispatching the command a second time.
#[derive(Debug, Clone)]
pub struct FrCommandAdapter {
    inner: FrAdapter,
}

impl FrCommandAdapter {
    /// A command adapter over one HTTP client.
    pub fn new(client: reqwest::Client, settings: FrSettings) -> Self {
        Self {
            inner: FrAdapter::new(client, settings),
        }
    }

    /// Whether both the base URL and the channel secret are set.
    pub fn configured(&self) -> bool {
        self.inner.configured()
    }
}

#[async_trait]
impl ExternalAdapter for FrCommandAdapter {
    async fn start(&self, row: &WorkerRow) -> Result<ExternalRef, ExternalStartError> {
        self.inner.require().map_err(ExternalStartError::new)?;
        let actor = actor_of(row.run.actor.as_ref())
            .ok_or_else(|| ExternalStartError::new("actor_required"))?;
        if !in_tenant(row, &actor) {
            return Err(ExternalStartError::new("actor_tenant_mismatch"));
        }
        let command = target_command(row)
            .filter(|command| FR_COMMANDS.contains(&command.as_str()))
            .ok_or_else(|| ExternalStartError::new("unsupported_command"))?;
        let project_id = row
            .run
            .inputs
            .get("id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())
            .ok_or_else(|| ExternalStartError::new("invalid_project_id"))?;
        let payload = json!({ "id": project_id });
        let text = format!("{command} {payload}");
        if text.chars().count() > TEXT_LIMIT {
            return Err(ExternalStartError::new("inputs_too_large"));
        }
        let data = self
            .inner
            .send(&actor, &text, &row.run.run_id.to_string())
            .await
            .map_err(|error| ExternalStartError::new(error.code()))?;
        if data.get("status").and_then(Value::as_str) != Some("result") {
            return Err(ExternalStartError::new("external_result_invalid"));
        }
        let Some(result) = data.get("result").filter(|result| result.is_object()) else {
            return Err(ExternalStartError::new("external_result_invalid"));
        };
        let answer = if command == "projects.close" {
            close_view(result)
        } else {
            project_view(result)
        };
        let mut reference = ExternalRef::new(RefKind::FrCommand, project_id);
        reference.project_id = Some(project_id.to_owned());
        reference.result = Some(answer);
        Ok(reference)
    }

    async fn poll(&self, row: &WorkerRow) -> Result<ExternalState, AdapterError> {
        if let Some(result) = row
            .run
            .external_ref
            .as_ref()
            .and_then(|reference| reference.get("result"))
            .filter(|result| result.is_object())
        {
            return Ok(ExternalState::succeeded(Some(result.clone())));
        }
        ExternalAdapter::poll(&self.inner, row).await
    }

    async fn cancel(&self, _row: &WorkerRow) -> Result<(), AdapterError> {
        // A read has nothing to withdraw: the task ends, the answer (if any) stays on the ref.
        Ok(())
    }
}
