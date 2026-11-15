//! The external-run driver: the non-Kata runtimes `n8n_workflow`, `fr_project` and `fr_command`.
//!
//! Ported from the reference `src/external/{adapter,signing,n8n,fr,driver}.py`. The driver is one
//! process (one UUIDv7 worker id) and the **single writer** of `mcp_runs` rows for those three
//! runtimes: adapters speak HTTP only and never touch the database.
//!
//! Two rules the whole module exists to keep:
//!
//! - **At most once.** A `dispatch` event is committed *before* `adapter.start`, so a run found
//!   `starting` with that event and no `external_ref` is `interrupted`, never re-sent.
//! - **No secret ever reaches a log.** Log lines carry run ids and public error codes only: never
//!   settings, request or response bodies, inputs, or exception messages (transport errors embed
//!   URLs).
//!
//! The binary is `mcp-external-driver`; its only listener is the internal probe port.

pub mod driver;
pub mod fr;
pub mod health;
pub mod n8n;
pub mod signing;
pub mod store;

use async_trait::async_trait;
use serde_json::{Map, Value, json};

use crate::storage::task_inputs::TaskInputRow;
use crate::worker::row::WorkerRow;

/// Which external system a run is parked on (the reference's `ExternalRef.kind`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefKind {
    /// An n8n workflow execution.
    N8n,
    /// An fr project start (the approval id until the project exists).
    Fr,
    /// A one-shot fr channel command.
    FrCommand,
}

impl RefKind {
    /// The stored text (`mcp_runs.external_ref.kind`).
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::N8n => "n8n",
            Self::Fr => "fr",
            Self::FrCommand => "fr_command",
        }
    }
}

/// Where one run lives upstream (the reference's `ExternalRef`).
///
/// Stored keys only grow: migration 0011's guard refuses a `external_ref` that loses a key, and a
/// late fr event may already have recorded the project id by the time a start returns.
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalRef {
    /// The external system the run is parked on.
    pub kind: RefKind,
    /// n8n: the execution id. fr: the start approval id (or the project id if none was needed).
    /// fr_command: the project id the read answered for.
    pub id: String,
    /// fr: the project, once it exists.
    pub project_id: Option<String>,
    /// fr_command: the one-shot read's answer, so a crash between start and finish loses nothing.
    pub result: Option<Value>,
}

impl ExternalRef {
    /// A reference carrying only its kind and id.
    pub fn new(kind: RefKind, id: impl Into<String>) -> Self {
        Self {
            kind,
            id: id.into(),
            project_id: None,
            result: None,
        }
    }

    /// The reference's `stored()`: the object written to `external_ref`, null fields dropped.
    pub fn stored(&self) -> Value {
        let mut map = Map::new();
        map.insert("kind".to_owned(), json!(self.kind.as_str()));
        map.insert("id".to_owned(), json!(self.id));
        if let Some(project_id) = &self.project_id {
            map.insert("project_id".to_owned(), json!(project_id));
        }
        if let Some(result) = &self.result {
            map.insert("result".to_owned(), result.clone());
        }
        Value::Object(map)
    }
}

/// What one poll found (the reference's `ExternalState.status`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExternalStatus {
    /// Still going.
    Running,
    /// Finished successfully.
    Succeeded,
    /// Finished with a public failure code.
    Failed,
    /// Cancelled upstream.
    Cancelled,
}

/// The outcome of one poll (the reference's `ExternalState`).
#[derive(Debug, Clone, PartialEq)]
pub struct ExternalState {
    /// The run's new state.
    pub status: ExternalStatus,
    /// The result, when the run finished successfully.
    pub result: Option<Value>,
    /// The public failure code (`^[a-z_]{1,64}$`), when it failed.
    pub code: Option<String>,
    /// Short progress text for `status_message`; never secrets, never upstream bodies.
    pub message: Option<String>,
}

impl ExternalState {
    /// Still running, with no progress text.
    pub fn running() -> Self {
        Self {
            status: ExternalStatus::Running,
            result: None,
            code: None,
            message: None,
        }
    }

    /// Still running, with the progress text the client reads verbatim.
    pub fn running_with(message: impl Into<String>) -> Self {
        Self {
            status: ExternalStatus::Running,
            result: None,
            code: None,
            message: Some(message.into()),
        }
    }

    /// Finished successfully with the run's result.
    pub fn succeeded(result: Option<Value>) -> Self {
        Self {
            status: ExternalStatus::Succeeded,
            result,
            code: None,
            message: None,
        }
    }

    /// Finished with a public failure code.
    pub fn failed(code: impl Into<String>) -> Self {
        Self {
            status: ExternalStatus::Failed,
            result: None,
            code: Some(code.into()),
            message: None,
        }
    }

    /// Cancelled upstream.
    pub fn cancelled() -> Self {
        Self {
            status: ExternalStatus::Cancelled,
            result: None,
            code: None,
            message: None,
        }
    }
}

/// A start could not complete.
///
/// Two outcomes, and the difference is the whole at-most-once contract: a **refusal** means
/// nothing is running upstream (the run is `failed` with the public code), while an **unknown**
/// outcome means the request may have reached the system (the run is `interrupted`, and recovery
/// never re-sends it). The reference draws the same line by letting a transport error escape
/// `start` into the driver's generic handler.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct ExternalStartError {
    /// The public failure code (`^[a-z_]{1,64}$`).
    pub code: String,
    /// The request may have reached the upstream: finish the run `interrupted`, never `failed`.
    pub outcome_unknown: bool,
}

impl ExternalStartError {
    /// A start refusal with a public code: nothing is running upstream.
    pub fn new(code: impl Into<String>) -> Self {
        Self {
            code: code.into(),
            outcome_unknown: false,
        }
    }

    /// The upstream may have the work: the outcome is unknown.
    pub fn unknown() -> Self {
        Self {
            code: "external_start_unknown".to_owned(),
            outcome_unknown: true,
        }
    }
}

/// An adapter call that failed in a way the driver retries on a later tick.
///
/// The code is public (`^[a-z_]{1,64}$`), so it is the only thing a log line may carry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("{code}")]
pub struct AdapterError {
    /// The public failure code.
    pub code: String,
}

impl AdapterError {
    /// An adapter failure with a public code.
    pub fn new(code: impl Into<String>) -> Self {
        Self { code: code.into() }
    }
}

/// One external system (n8n, fr). HTTP only: an adapter never writes `mcp_runs`.
#[async_trait]
pub trait ExternalAdapter: Send + Sync {
    /// Dispatch the run upstream and return where it lives.
    async fn start(&self, row: &WorkerRow) -> Result<ExternalRef, ExternalStartError>;

    /// Read the run's state. An error is retried on the next tick.
    async fn poll(&self, row: &WorkerRow) -> Result<ExternalState, AdapterError>;

    /// Best-effort upstream withdrawal. An error is retried on the next tick.
    async fn cancel(&self, row: &WorkerRow) -> Result<(), AdapterError>;
}

/// The fr channel, as the one forwarder of a human's answer.
///
/// Every task input is an fr approval (n8n questions are routed through fr too), so every answer
/// goes back to fr whatever the run's runtime. `Ok(Some(code))` is fr's refusal, shown to the
/// client as `fr refused the answer: <code>`; `Ok(None)` means fr took it, or there was nothing
/// to send.
#[async_trait]
pub trait AnswerForwarder: Send + Sync {
    /// Relay one answered input as the human who answered it.
    async fn forward(
        &self,
        row: &WorkerRow,
        item: &TaskInputRow,
    ) -> Result<Option<String>, AdapterError>;
}
