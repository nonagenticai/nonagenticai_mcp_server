//! The MCP projection: `rmcp`'s streamable HTTP transport at `/mcp`.
//!
//! `tools/list` is the reference's `listing` closure (`src/protocol.py`), ported: the caller's
//! resolved binding is projected into its public tools through the same live catalog resolver
//! the REST surface uses, paged by `CATALOG_PAGE_SIZE` with an HMAC-signed, fingerprint-bound
//! cursor. Every failure — a missing credential, a changed binding, a stale catalog, a bad
//! cursor — is the reference's single `-32602 catalog_unavailable_or_invalid_cursor`.
//!
//! `tools/call` is the reference's `CatalogTool.run` (`src/catalog/provider.py`) and the
//! protocol handler's `calling` closure (`src/protocol.py`), ported: the caller's live
//! projection is resolved, the tool is selected by its public name, the input instance is
//! validated against the tool's declared schema, the whole resolved tool is re-resolved and
//! compared immediately before durable acceptance, and the returned envelope is validated
//! against the tool's public output schema and its size bound. Every refusal — an unknown
//! tool, invalid arguments, a withdrawn authority, a full queue, a deployment without
//! execution, an oversized envelope — is a tool RESULT carrying `isError: true`, never a
//! JSON-RPC error, so the calling agent always reads the refusal as text.
//!
//! One known divergence: `rmcp`'s typed [`CallToolRequestParams`] drops unknown top-level keys,
//! so the reference's "unsupported call extension" refusal (`src/protocol.py:158-161`) cannot
//! be reproduced here. A call carrying extra top-level keys behaves as a normal call.
//!
//! The `io.modelcontextprotocol/tasks` extension (`src/tasks/extension.py`) is served when
//! `MCP_TASKS_ENABLED` is set: `initialize` advertises it, a `tools/call` whose run is still
//! non-terminal is answered with a task handle when the client declared the extension at
//! protocol version `2026-07-28`, and `tasks/get|update|cancel` are served with the reference's
//! ownership rule. `tasks/get` renders the same view the pure mapping produces; where `rmcp`'s
//! typed model cannot carry the reference's bytes, the closest wire-equivalent is sent and
//! reported: an `inputRequests` entry re-serialises through [`InputRequest`], which spells a
//! stored `elicitation/create` request back out with an added `"mode": "form"` discriminator
//! (`rmcp` `model.rs` `ElicitRequestParams`), so that one key is not byte-identical to
//! `src/tasks/mapping.py:98`.
//!
//! The caller's authority arrives as the [`Principal`] the `/mcp` authentication middleware
//! inserts into the request extensions. rmcp's streamable HTTP tower service splits the HTTP
//! request and inserts its [`Parts`] — extensions included — into the JSON-RPC request, which
//! the service loop moves into [`RequestContext::extensions`]; the handler reads it from there
//! and trusts nothing else.

use std::sync::Arc;

use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use chrono::Utc;
use hmac::{Hmac, KeyInit, Mac};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, CancelTaskParams, ClientCapabilities,
    ContentBlock, CreateTaskResult, DetailedTask, ErrorData as McpError, GetTaskParams,
    GetTaskResult, Implementation, InputRequest, InputRequests, JsonObject, ListToolsResult,
    MetaObject, PaginatedRequestParams, ProtocolVersion, ResultType, ServerCapabilities,
    ServerConfig, Task, TaskPayload, TaskStatus, Tool, ToolAnnotations, UpdateTaskParams,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use serde_json::{Map, Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;

use crate::AppState;
use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::instance::{InstanceError, validate_instance};
use crate::catalog::models::Effect;
use crate::catalog::public::output_envelope;
use crate::catalog::resolver::{CatalogResolver, ResolvedTool};
use crate::catalog::validation::SchemaLimits;
use crate::config::ExecutionSettings;
use crate::execution::service::{ExecutionService, ExecutionServiceError};
use crate::execution::{RunRow, RunStatus, parse_actor};
use crate::storage::bindings;
use crate::storage::executions::ExecutionRepository;
use crate::storage::task_inputs::TaskInputRepository;
use crate::tasks::{create_task_result, fr_meta, task_view};

/// The reference's one catalog-listing refusal: it never tells a caller which check failed.
const CATALOG_REFUSAL: &str = "catalog_unavailable_or_invalid_cursor";

/// The reference's one tool-call refusal: never reflects inputs, schema diagnostics or SQL.
const CALL_REFUSAL: &str = "tool_request_denied";

/// The cursor grammar's bound: anything longer cannot be one of this service's cursors.
const CURSOR_MAX_BYTES: usize = 512;

/// The MCP handler: the catalog pool, the configured page bound, the live resolver, the
/// execution service and the execution settings. Built once per service; the pool and resolver
/// are shared, and nothing is cached per caller.
#[derive(Clone)]
pub struct McpServer {
    pool: PgPool,
    page_size: u32,
    resolver: CatalogResolver,
    execution: ExecutionService,
    /// The runs the tasks extension reads and cancels.
    runs: ExecutionRepository,
    /// The durable inputs `tasks/update` answers.
    inputs: TaskInputRepository,
    settings: ExecutionSettings,
}

impl McpServer {
    /// The reference's `listing` closure, in full: resolve the caller's projection, prove the
    /// binding has not moved under the credential, fingerprint the projection, validate and
    /// mint the cursor, page, and project each tool into the MCP wire object.
    async fn listing(
        &self,
        request: Option<PaginatedRequestParams>,
        context: &RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // The middleware's resolved principal. rmcp inserts the HTTP `Parts` (with the
        // extensions the middleware wrote) into the request; either half missing is a refusal.
        let principal = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<Principal>())
            .cloned()
            .ok_or_else(refusal)?;

        // A live projection, re-derived for this request; management and bindingless callers
        // are refused by the resolver itself.
        let tools = self
            .resolver
            .resolve(&principal)
            .await
            .map_err(|_| refusal())?;

        // The credential's binding, re-read with no lock: a revision that moved since the
        // middleware authenticated means the credential is no longer the current authority.
        let binding_id = principal.binding_id.ok_or_else(refusal)?;
        let tenant = AuthorityId::new(principal.tenant_id.to_string()).map_err(|_| refusal())?;
        let identity = Uuid7::new(binding_id.to_string()).map_err(|_| refusal())?;
        let mut conn = self.pool.acquire().await.map_err(|_| refusal())?;
        let row = bindings::get_binding(&mut conn, &tenant, &identity, false)
            .await
            .map_err(|_| refusal())?;
        drop(conn);
        if principal.binding_revision != Some(row.revision) {
            return Err(refusal());
        }
        // The HMAC key is the binding's stored token digest; the token itself is never held.
        let key = hex::decode(&row.token_sha256).map_err(|_| refusal())?;
        let generation = self.resolver.generation().await.map_err(|_| refusal())?;

        // The reference's identity array. The per-tool entries are its
        // `manifest_json + effective_json` concatenation; the exact JSON text is opaque to the
        // caller (it only ever feeds the fingerprint), so this service re-serialises and does
        // not chase byte-compatibility with a Python-generated cursor.
        let entries: Vec<String> = tools
            .iter()
            .map(|tool| {
                let manifest = serde_json::to_string(&tool.manifest)?;
                let effective = serde_json::to_string(&tool.effective)?;
                Ok::<String, serde_json::Error>(format!("{manifest}{effective}"))
            })
            .collect::<Result<_, _>>()
            .map_err(|_| refusal())?;
        let identity = json!([
            principal.tenant_id.to_string(),
            principal.license_id.to_string(),
            binding_id.to_string(),
            row.revision,
            generation,
            entries,
        ]);
        let encoded = serde_json::to_vec(&identity).map_err(|_| refusal())?;
        let fingerprint = hex::encode(Sha256::digest(&encoded));

        // Cursor validation, in the reference's order: length, exactly two '.', constant-time
        // signature, fingerprint equality, then an in-range position.
        let mut offset = 0usize;
        if let Some(cursor) = request.as_ref().and_then(|params| params.cursor.as_deref()) {
            if cursor.len() > CURSOR_MAX_BYTES {
                return Err(refusal());
            }
            let mut parts = cursor.split('.');
            let (Some(raw), Some(signature), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(refusal());
            };
            let expected = sign(&key, raw)?;
            if !bool::from(signature.as_bytes().ct_eq(expected.as_bytes())) {
                return Err(refusal());
            }
            let decoded = URL_SAFE.decode(raw).map_err(|_| refusal())?;
            let data: Value = serde_json::from_slice(&decoded).map_err(|_| refusal())?;
            let position = data.get("o").and_then(Value::as_u64);
            match position {
                Some(o)
                    if data.get("f").and_then(Value::as_str) == Some(fingerprint.as_str())
                        && o > 0
                        && o < tools.len() as u64 =>
                {
                    offset = usize::try_from(o).map_err(|_| refusal())?;
                }
                _ => return Err(refusal()),
            }
        }

        let page_size = usize::try_from(self.page_size).unwrap_or(usize::MAX);
        let end = offset.saturating_add(page_size);
        let next_cursor = if end < tools.len() {
            let raw = URL_SAFE.encode(
                serde_json::to_vec(&json!({"o": end, "f": fingerprint})).map_err(|_| refusal())?,
            );
            Some(format!("{raw}.{}", sign(&key, &raw)?))
        } else {
            None
        };
        let tools = tools
            .get(offset..end.min(tools.len()))
            .ok_or_else(refusal)?
            .iter()
            .map(project)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ListToolsResult {
            tools,
            next_cursor,
            result_type: None,
            ttl_ms: None,
            cache_scope: None,
            meta: None,
        })
    }

    /// The reference's `CatalogTool.run` (`src/catalog/provider.py`) and the protocol
    /// handler's `calling` closure (`src/protocol.py`): one `tools/call`, answered with the
    /// run envelope or a tool-level refusal.
    ///
    /// The order is the reference's: the caller's principal, the arguments, the live
    /// projection and the tool it names, the input schema, a second full resolution compared
    /// whole, the caller's actor and idempotency key, durable acceptance, then the envelope's
    /// public-schema, identity and size checks. Every refusal after the principal is a
    /// `CallToolResult` with `isError: true`; a missing principal is the listing's `-32602`.
    async fn calling(
        &self,
        request: CallToolRequestParams,
        context: &RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        // The middleware's resolved principal, read exactly as `listing` reads it.
        let parts = context.extensions.get::<Parts>().ok_or_else(refusal)?;
        let principal = parts
            .extensions
            .get::<Principal>()
            .cloned()
            .ok_or_else(refusal)?;

        // `params.arguments or {}`: absent arguments are an empty object.
        let arguments = request.arguments.clone().unwrap_or_default();
        let arguments_value = Value::Object(arguments);

        // The live projection, then the tool the call names. A catalog that cannot resolve is
        // the caller's tool-level refusal, never a JSON-RPC error: the reference's `calling`
        // catches every exception from this point as one.
        let Ok(tools) = self.resolver.resolve(&principal).await else {
            return Ok(call_refusal(CALL_REFUSAL));
        };
        let Some(tool) = tools
            .into_iter()
            .find(|tool| tool.manifest.public_name.as_str() == request.name.as_ref())
        else {
            return Ok(call_refusal(CALL_REFUSAL));
        };

        // The declared input schema, before any catalog read: the caller can fix its own call.
        // The refusal carries pointers and keywords only, never an instance value.
        match validate_instance(
            &Value::Object(tool.manifest.input_schema.clone()),
            &arguments_value,
            &SchemaLimits::default(),
        ) {
            Ok(_) => {}
            Err(InstanceError::Invalid(error)) => {
                let Ok(text) = serde_json::to_string(&json!({
                    "error": "invalid_arguments",
                    "problems": error.problems,
                })) else {
                    return Ok(call_refusal(CALL_REFUSAL));
                };
                return Ok(CallToolResponse::Complete(CallToolResult::error(vec![
                    ContentBlock::text(text),
                ])));
            }
            Err(_) => return Ok(call_refusal(CALL_REFUSAL)),
        }

        // Do this after input validation, immediately before submission: a retained wrapper
        // never retains its earlier caller's authority. The whole resolved tool must match.
        let Ok(tools) = self.resolver.resolve(&principal).await else {
            return Ok(call_refusal(CALL_REFUSAL));
        };
        let Some(current) = tools
            .into_iter()
            .find(|candidate| candidate.manifest.public_name == tool.manifest.public_name)
        else {
            return Ok(call_refusal(CALL_REFUSAL));
        };
        if current != tool {
            return Ok(call_refusal(CALL_REFUSAL));
        }

        // The caller's actor from the request's `_meta`, and the middleware-validated
        // idempotency key, which it has already proven single-valued. rmcp strips the wire
        // `params._meta` into the request context before dispatch, so the typed params field
        // is always empty: the context's metadata is the one to read.
        let actor = parse_actor(Some(&(context.meta).0.0));
        let key = parts
            .headers
            .get("x-mcp-idempotency-key")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);

        // Durable acceptance. Only the reference's two named errors have their own text.
        let envelope = match self
            .execution
            .submit(
                &principal,
                &tool,
                &arguments_value,
                key.as_deref(),
                actor.as_ref(),
            )
            .await
        {
            Ok(envelope) => envelope,
            Err(ExecutionServiceError::QueueFull) => {
                return Ok(call_refusal("execution_queue_full"));
            }
            Err(ExecutionServiceError::Unavailable) => {
                return Ok(call_refusal("execution_unavailable"));
            }
            Err(_) => return Ok(call_refusal(CALL_REFUSAL)),
        };

        // The envelope against the tool's public output schema, then its identity, then the
        // result against the declared result schema only when the run succeeded.
        let Ok(output_schema) =
            output_envelope(&Value::Object(tool.manifest.result_schema.clone()))
        else {
            return Ok(call_refusal(CALL_REFUSAL));
        };
        if validate_instance(&output_schema, &envelope, &SchemaLimits::default()).is_err() {
            return Ok(call_refusal(CALL_REFUSAL));
        }
        let Some(run_id) = envelope.get("run_id").and_then(Value::as_str) else {
            return Ok(call_refusal(CALL_REFUSAL));
        };
        if Uuid7::new(run_id).is_err() {
            return Ok(call_refusal(CALL_REFUSAL));
        }
        if envelope.get("status").and_then(Value::as_str) == Some("succeeded") {
            let result = envelope.get("result").cloned().unwrap_or(Value::Null);
            if validate_instance(
                &Value::Object(tool.manifest.result_schema.clone()),
                &result,
                &SchemaLimits::default(),
            )
            .is_err()
            {
                return Ok(call_refusal(CALL_REFUSAL));
            }
        }

        // The reference's aggregate output bound: the tool's own limit, never above half of
        // the configured protocol output bound.
        // The text is `json.dumps(envelope)` — the reference's separator layout, so a client
        // reading `content[0].text` sees what the Python service would have written.
        let encoded = crate::tasks::envelope_text(&envelope);
        if encoded.is_empty() {
            return Ok(call_refusal(CALL_REFUSAL));
        }
        let limit = usize::try_from(tool.effective.limits.output_bytes)
            .unwrap_or(usize::MAX)
            .min(self.settings.protocol_output_bytes / 2);
        if encoded.len() > limit {
            return Ok(call_refusal(CALL_REFUSAL));
        }

        // SEP-2663: a non-terminal run may be handed back as a task handle, but only to a client
        // that declared the extension at the pinned protocol version. A terminal run — or any
        // failure to re-read it — answers with the envelope, exactly as without the extension.
        let terminal = envelope
            .get("status")
            .and_then(Value::as_str)
            .and_then(RunStatus::parse)
            .is_some_and(RunStatus::is_terminal);
        if self.settings.tasks_enabled
            && context.protocol_version() == Some(ProtocolVersion::V_2026_07_28)
            && !terminal
            && declared(context).is_ok()
        {
            let tenant =
                AuthorityId::new(principal.tenant_id.to_string()).map_err(|_| refusal())?;
            let run_id = Uuid7::new(run_id.to_owned()).map_err(|_| refusal())?;
            if let Ok(row) = self.runs.get(&tenant, &run_id).await {
                let meta = fr_meta(&self.pool, &tenant, &row, &self.settings, Utc::now())
                    .await
                    .ok()
                    .flatten();
                let handle = create_task_result(&row, &self.settings, meta.as_ref());
                if let Some(task) = create_task_result_wire(&handle) {
                    return Ok(CallToolResponse::Task(task));
                }
            }
        }

        // The text and the structured value are the same envelope; a run that ended badly is
        // a tool-level error the calling agent reads, not a protocol error.
        let failed = matches!(
            envelope.get("status").and_then(Value::as_str),
            Some("failed" | "cancelled" | "timed_out" | "interrupted")
        );
        let mut result = CallToolResult::success(vec![ContentBlock::text(encoded)]);
        result.structured_content = Some(envelope);
        result.is_error = Some(failed);
        // rmcp clears this for peers that negotiated an older protocol version.
        result.result_type = Some(ResultType::COMPLETE);
        Ok(CallToolResponse::Complete(result))
    }

    /// The reference's `_owned`: the task must belong to this caller's binding and licence,
    /// must not have had its payload expired, and must be named consistently in `Mcp-Name`.
    /// Every ownership refusal is the one `-32602 task not found`; a header that names a
    /// different task is its own mismatch code, never a silent "not found".
    async fn owned(
        &self,
        principal: &Principal,
        task_id: &str,
        context: &RequestContext<RoleServer>,
    ) -> Result<(AuthorityId, RunRow), McpError> {
        if let Some(name) = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.headers.get("mcp-name"))
            .and_then(|value| value.to_str().ok())
            && name != task_id
        {
            return Err(McpError::header_mismatch("Mcp-Name header mismatch", None));
        }
        let tenant = AuthorityId::new(principal.tenant_id.to_string()).map_err(|_| not_found())?;
        let binding_id = principal.binding_id.as_ref().ok_or_else(not_found)?;
        let run_id = Uuid7::new(task_id.to_owned()).map_err(|_| not_found())?;
        let row = self
            .runs
            .get(&tenant, &run_id)
            .await
            .map_err(|_| not_found())?;
        let owned = row.binding_id.as_ref().map(ToString::to_string)
            == Some(binding_id.to_string())
            && row.gateway_license_id.to_string() == principal.license_id.to_string()
            && row.payload_expired_at.is_none();
        if !owned {
            return Err(not_found());
        }
        Ok((tenant, row))
    }
}

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        // `initialize` itself is answered by rmcp: it negotiates the protocol version.
        // Two fields are the Python source's, measured from fastmcp's own `initialize` reply
        // at the pinned SHA — the wire contract consumers see:
        //   * `serverInfo` is its identity;
        //   * `capabilities.tools.listChanged` is serialised as an explicit `false`
        //     (rmcp omits the field when it is `None`, which is a visible wire difference).
        // The tasks extension is advertised only when the deployment serves it; rmcp answers
        // `tasks/*` with `-32601` for a server that does not declare it, exactly as the
        // reference's unregistered methods do.
        let builder = ServerCapabilities::builder().enable_tools();
        let mut capabilities = if self.settings.tasks_enabled {
            builder.enable_tasks().build()
        } else {
            builder.build()
        };
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("Executable catalog", "2.0.0"))
    }

    async fn list_tools(
        &self,
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.listing(request, &context).await
    }

    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, McpError> {
        self.calling(request, &context).await
    }

    async fn get_task(
        &self,
        request: GetTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<GetTaskResult, McpError> {
        let principal = caller(&context)?;
        declared(&context)?;
        let (tenant, row) = self.owned(&principal, &request.task_id, &context).await?;
        let run_id = Uuid7::new(row.run_id.to_string()).map_err(|_| not_found())?;
        let inputs = self
            .inputs
            .open_for(&tenant, &run_id)
            .await
            .map_err(|_| McpError::internal_error("task inputs unavailable", None))?;
        let now = Utc::now();
        let meta = fr_meta(&self.pool, &tenant, &row, &self.settings, now)
            .await
            .map_err(|_| McpError::internal_error("task activity unavailable", None))?;
        let view = task_view(&row, &inputs, &self.settings, meta.as_ref(), now);
        get_task_result(&view).ok_or_else(|| McpError::internal_error("task projection", None))
    }

    async fn update_task(
        &self,
        request: UpdateTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let principal = caller(&context)?;
        declared(&context)?;
        let (tenant, row) = self.owned(&principal, &request.task_id, &context).await?;
        // The caller's actor, read exactly as `calling` reads it: rmcp moves the wire
        // `params._meta` into the request context before dispatch.
        let actor = parse_actor(Some(&(context.meta).0.0))
            .ok_or_else(|| McpError::invalid_params("actor required", None))?;
        let run_id = Uuid7::new(row.run_id.to_string()).map_err(|_| not_found())?;
        let responses: Map<String, Value> = request.input_responses.into_iter().collect();
        self.inputs
            .answer(&tenant, &run_id, &responses, &actor)
            .await
            .map_err(|_| McpError::internal_error("task answer unavailable", None))?;
        Ok(())
    }

    async fn cancel_task(
        &self,
        request: CancelTaskParams,
        context: RequestContext<RoleServer>,
    ) -> Result<(), McpError> {
        let principal = caller(&context)?;
        declared(&context)?;
        let (tenant, row) = self.owned(&principal, &request.task_id, &context).await?;
        let run_id = Uuid7::new(row.run_id.to_string()).map_err(|_| not_found())?;
        self.runs
            .cancel(&tenant, &run_id)
            .await
            .map_err(|_| not_found())?;
        Ok(())
    }
}

/// The reference's refusal: `MCPError(code=-32602, message="catalog_unavailable_or_invalid_cursor")`.
fn refusal() -> McpError {
    McpError::invalid_params(CATALOG_REFUSAL, None)
}

/// The reference's tool-level refusal: `CallToolResult(content=[text], is_error=True)`. It is
/// a result the caller reads, never a JSON-RPC error.
fn call_refusal(text: &str) -> CallToolResponse {
    CallToolResponse::Complete(CallToolResult::error(vec![ContentBlock::text(text)]))
}

// ── the tasks extension's wire adapters ──────────────────────────────────────────────────

/// The reference's one ownership refusal: `MCPError(-32602, "task not found")`. It never tells
/// a caller which check failed.
fn not_found() -> McpError {
    McpError::invalid_params("task not found", None)
}

/// The middleware's resolved principal, read exactly as `listing` reads it.
fn caller(context: &RequestContext<RoleServer>) -> Result<Principal, McpError> {
    context
        .extensions
        .get::<Parts>()
        .and_then(|parts| parts.extensions.get::<Principal>())
        .cloned()
        .ok_or_else(|| McpError::internal_error("no caller authority on the request", None))
}

/// SEP-2663: every `tasks/*` call requires the client to have declared the extension. rmcp
/// enforces this before dispatch (`handler/server.rs`); the same refusal is issued here so the
/// rule stays visible where the ownership rules are.
fn declared(context: &RequestContext<RoleServer>) -> Result<(), McpError> {
    if context
        .client_capabilities()
        .is_some_and(|capabilities| capabilities.supports_tasks())
    {
        return Ok(());
    }
    Err(McpError::missing_required_client_capability(
        ClientCapabilities::builder().enable_tasks().build(),
    ))
}

/// One task status as the typed model spells it.
fn task_status_of(status: &str) -> Option<TaskStatus> {
    Some(match status {
        "working" => TaskStatus::Working,
        "input_required" => TaskStatus::InputRequired,
        "completed" => TaskStatus::Completed,
        "failed" => TaskStatus::Failed,
        "cancelled" => TaskStatus::Cancelled,
        _ => return None,
    })
}

/// The base task fields of a projected view, as the typed model.
fn task_of(view: &Value, status: TaskStatus) -> Option<Task> {
    let mut task = Task::new(
        view.get("taskId")?.as_str()?,
        status,
        view.get("createdAt")?.as_str()?,
        view.get("lastUpdatedAt")?.as_str()?,
    );
    task.ttl_ms = view.get("ttlMs").and_then(Value::as_u64);
    task.poll_interval_ms = view.get("pollIntervalMs").and_then(Value::as_u64);
    task.status_message = view
        .get("statusMessage")
        .and_then(Value::as_str)
        .map(str::to_owned);
    Some(task)
}

/// The status-specific payload of a projected view.
///
/// An `inputRequests` entry is re-parsed into rmcp's typed request union: the closest
/// wire-equivalent, which spells a stored `elicitation/create` request back out with rmcp's
/// `"mode"` discriminator. An entry that does not parse is dropped, and a task left with no
/// parseable question reports `working` rather than an empty `inputRequests`.
fn task_payload(view: &Value) -> Option<TaskPayload> {
    match view.get("status")?.as_str()? {
        "working" => Some(TaskPayload::Working),
        "input_required" => {
            let mut inputs = InputRequests::new();
            for (key, request) in view.get("inputRequests")?.as_object()? {
                if let Ok(parsed) = serde_json::from_value::<InputRequest>(request.clone()) {
                    inputs.insert(key.clone(), parsed);
                }
            }
            if inputs.is_empty() {
                return Some(TaskPayload::Working);
            }
            Some(TaskPayload::InputRequired {
                input_requests: inputs,
            })
        }
        "completed" => Some(TaskPayload::Completed {
            result: view.get("result")?.as_object()?.clone(),
        }),
        "cancelled" => Some(TaskPayload::Cancelled),
        _ => None,
    }
}

/// The `_meta` a projected view carries, as the typed model.
fn view_meta(view: &Value) -> Option<MetaObject> {
    view.get("_meta")
        .and_then(Value::as_object)
        .cloned()
        .map(MetaObject)
}

/// A projected view as the `tasks/get` result.
fn get_task_result(view: &Value) -> Option<GetTaskResult> {
    let payload = task_payload(view)?;
    let task = task_of(view, payload.status())?;
    let mut result = GetTaskResult::new(DetailedTask::new(task, payload));
    result.meta = view_meta(view);
    Some(result)
}

/// A projected view as the `tools/call` task handle.
fn create_task_result_wire(view: &Value) -> Option<CreateTaskResult> {
    let status = task_status_of(view.get("status")?.as_str()?)?;
    let mut handle = CreateTaskResult::new(task_of(view, status)?);
    handle.meta = view_meta(view);
    Some(handle)
}

/// `hmac_sha256(key, raw)` rendered as lowercase hex, exactly the cursor's signature.
fn sign(key: &[u8], raw: &str) -> Result<String, McpError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| refusal())?;
    mac.update(raw.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// One resolved tool as the MCP `Tool` the reference serves (`ResolvedTool.public()`).
///
/// `version` is a fastmcp-local attribute in the reference, not part of the MCP `Tool` schema,
/// so it is deliberately absent from the wire object here too.
fn project(tool: &ResolvedTool) -> Result<Tool, McpError> {
    let manifest = &tool.manifest;
    let envelope =
        output_envelope(&Value::Object(manifest.result_schema.clone())).map_err(|_| refusal())?;
    let output_schema = envelope.as_object().cloned().ok_or_else(refusal)?;
    // Non-exhaustive structs: `from_raw` names every hint the reference sets.
    let annotations = ToolAnnotations::from_raw(
        None,
        Some(manifest.effect == Effect::ReadOnly),
        Some(manifest.effect == Effect::Writes),
        Some(false),
        Some(!manifest.allowed_operations.is_empty()),
    );
    let meta = MetaObject(JsonObject::from_iter([(
        "operation".to_owned(),
        json!(manifest.operation),
    )]));
    Ok(Tool::new(
        manifest.public_name.as_str().to_owned(),
        manifest.description.clone(),
        manifest.input_schema.clone(),
    )
    .with_raw_output_schema(Arc::new(output_schema))
    .with_annotations(annotations)
    .with_meta(meta))
}

/// The `/mcp` tower service. Mount it with `route_service`; the auth middleware must run
/// first so the handler can read the resolved credential from the request extensions.
pub fn service(state: &AppState) -> StreamableHttpService<McpServer, LocalSessionManager> {
    // The resolver is built exactly as the REST projection builds it, so both surfaces serve
    // one live catalog and cannot disagree. `tools/call` submits through the same resolver, so
    // the admission path's re-resolution can never disagree with the projection either.
    let resolver = crate::routes::available::resolver(state);
    let runs = ExecutionRepository::new(state.pool.clone(), state.execution.clone());
    let server = McpServer {
        pool: state.pool.clone(),
        page_size: state.catalog_page_size,
        execution: ExecutionService::new(
            runs.clone(),
            resolver.clone(),
            state.execution.clone(),
            state.execution_enabled,
        ),
        runs,
        inputs: TaskInputRepository::new(state.pool.clone()),
        settings: state.execution.clone(),
        resolver,
    };
    // Non-exhaustive: start from `Default` and set only the fields this service owns.
    let mut config = StreamableHttpServerConfig::default();
    // Stateless, like the Python source: no `MCP-Session-Id` is issued or required.
    // `json_response` is honoured only in this mode (rmcp tower.rs).
    config.legacy_session_mode = false;
    // `false` = SSE frames, matching fastmcp's `json_response=False`.
    config.json_response = false;
    // rmcp's default `allowed_hosts` is loopback-only; the deployment sets the in-cluster
    // hostnames here. An empty value keeps the default (refuse non-loopback Host headers).
    let config = match std::env::var("MCP_ALLOWED_HOSTS") {
        Ok(hosts) if !hosts.trim().is_empty() => {
            config.with_allowed_hosts(hosts.split(',').map(str::trim).filter(|h| !h.is_empty()))
        }
        _ => config,
    };
    StreamableHttpService::new(
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}
