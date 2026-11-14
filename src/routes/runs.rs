//! The four durable execution operations under `/mcp/runs`.
//!
//! Ported from the reference `src/routers/executions.py` (`submit`, `inspect`, `events`,
//! `cancel`). The reference reads every request through a raw JSON contract, so FastAPI
//! declares NO request body and NO response model: `POST /mcp/runs` carries no
//! `request_body` and every success response declares the empty `{}` schema (`AnyJson`). Each
//! operation with a path parameter declares the reference's 422 `HTTPValidationError`.
//!
//! A domain refusal is `{"error": <code>}` with `Cache-Control: no-store`: permission is
//! `403 forbidden`, a missing run `404 not_found`, a conflict `409
//! revision_or_lifecycle_conflict` and any other refusal `422 invalid_request`. The two
//! router-level refusals are FastAPI's `{"detail": ...}` verbatim and carry no `no-store` of
//! their own: the queue bound is `429 execution_queue_full` with `Retry-After: 1`, and a
//! deployment that cannot execute is `503 execution_unavailable`.
//!
//! The idempotency key travels only in `x-mcp-idempotency-key`, exactly the reference's
//! rule; the middleware has already bounded and syntax-checked it, and this route reads it.

use axum::Json;
use axum::body::Bytes as RawBody;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::header::{CACHE_CONTROL, RETRY_AFTER};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::SecondsFormat;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value, json};
use utoipa::IntoParams;

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::{AuthorityId, Name, Uuid7};
use crate::catalog::resolver::CatalogResolverError;
use crate::execution::envelope;
use crate::execution::service::{ExecutionService, ExecutionServiceError};
use crate::routes::available::resolver;
use crate::routes::health::AnyJson;
use crate::routes::tools::HTTPValidationError;
use crate::storage::catalog::CatalogStoreError;
use crate::storage::executions::{ExecutionRepository, ExecutionStoreError};
use crate::toolkits::service::ToolkitServiceError;

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// An execution refusal, rendered as the reference renders it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RunsError {
    /// `PermissionError`: the caller may not submit or does not own the run.
    Forbidden,
    /// `CatalogNotFoundError`: no such run for this tenant.
    NotFound,
    /// `CatalogConflictError`: the authority changed during acceptance.
    Conflict,
    /// A request-level validation refusal, the path identity and the query bounds included.
    Invalid,
    /// The reference's `HTTPException(429, "execution_queue_full")`.
    QueueFull,
    /// The reference's `HTTPException(503, "execution_unavailable")`.
    Unavailable,
    /// The database failed; a 4xx would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for RunsError {
    fn into_response(self) -> Response {
        match self {
            Self::QueueFull => {
                let mut response = (
                    StatusCode::TOO_MANY_REQUESTS,
                    Json(json!({ "detail": "execution_queue_full" })),
                )
                    .into_response();
                response
                    .headers_mut()
                    .insert(RETRY_AFTER, HeaderValue::from_static("1"));
                response
            }
            // FastAPI's `HTTPException` body: no `{"error": ...}` and no `no-store`.
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                Json(json!({ "detail": "execution_unavailable" })),
            )
                .into_response(),
            Self::Forbidden => error_response(StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => error_response(StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => {
                error_response(StatusCode::CONFLICT, "revision_or_lifecycle_conflict")
            }
            Self::Invalid => error_response(StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => error_response(StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        }
    }
}

/// The reference's `{"error": <code>}` refusal body, never cached.
fn error_response(status: StatusCode, code: &'static str) -> Response {
    let mut response = (status, Json(json!({ "error": code }))).into_response();
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

impl From<ExecutionServiceError> for RunsError {
    fn from(error: ExecutionServiceError) -> Self {
        match error {
            ExecutionServiceError::QueueFull => Self::QueueFull,
            ExecutionServiceError::Unavailable => Self::Unavailable,
            ExecutionServiceError::Denied => Self::Forbidden,
            ExecutionServiceError::Conflict(_) => Self::Conflict,
            ExecutionServiceError::Invalid => Self::Invalid,
            ExecutionServiceError::NotFound => Self::NotFound,
            ExecutionServiceError::Internal => Self::Internal,
        }
    }
}

impl From<ExecutionStoreError> for RunsError {
    fn from(error: ExecutionStoreError) -> Self {
        match error {
            ExecutionStoreError::QueueFull => Self::QueueFull,
            ExecutionStoreError::Denied => Self::Forbidden,
            ExecutionStoreError::Conflict(_) => Self::Conflict,
            ExecutionStoreError::NotFound => Self::NotFound,
            ExecutionStoreError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogResolverError> for RunsError {
    fn from(error: CatalogResolverError) -> Self {
        match error {
            CatalogResolverError::Forbidden(_) => Self::Forbidden,
            CatalogResolverError::Conflict(_) => Self::Conflict,
            CatalogResolverError::Invalid(_) => Self::Invalid,
            CatalogResolverError::Store(error)
            | CatalogResolverError::Service(ToolkitServiceError::Store(error)) => error.into(),
            CatalogResolverError::Service(error) => error.into(),
        }
    }
}

impl From<ToolkitServiceError> for RunsError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Forbidden,
            ToolkitServiceError::Invalid(_) => Self::Invalid,
            ToolkitServiceError::Conflict(_) => Self::Conflict,
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for RunsError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            // The reference's exception handler answers a stored row its model can no longer
            // parse with the validation response, exactly as the binding routes do.
            CatalogStoreError::Corrupt(_) => Self::Invalid,
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "execution database failure");
                Self::Internal
            }
        }
    }
}

// ── request models ────────────────────────────────────────────────────────────────────────

/// The reference's `RunRequest`: a public tool name and its input arguments.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RunRequest {
    tool: String,
    inputs: Map<String, Value>,
}

/// The reference's query bounds for `GET /mcp/runs/{identity}/events`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EventsQuery {
    /// Return events after this run-scoped identity.
    #[param(minimum = 0, default = 0)]
    pub after: Option<i64>,
    /// Maximum number of events to return.
    #[param(minimum = 1, maximum = 100, default = 50)]
    pub limit: Option<i64>,
}

// ── handlers ──────────────────────────────────────────────────────────────────────────────

/// Submit one bound tool call and answer its run envelope.
#[utoipa::path(
    post,
    path = "/mcp/runs",
    tag = "runs",
    responses((status = 202, description = "Successful Response", body = AnyJson))
)]
pub async fn submit_run(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    headers: HeaderMap,
    body: RawBody,
) -> Result<Response, RunsError> {
    let principal = require_binding(principal)?;
    let request: RunRequest = parse_body(&body)?;
    let tool = Name::new(request.tool).map_err(|_| RunsError::Invalid)?;
    let selected = resolver(&state)
        .resolve(&principal)
        .await?
        .into_iter()
        .find(|candidate| candidate.manifest.public_name.as_str() == tool.as_str())
        .ok_or(RunsError::Forbidden)?;
    // The middleware validated this header's shape; a duplicate or non-ASCII value already
    // failed the request before it reached this handler.
    let idempotency_key = headers
        .get("x-mcp-idempotency-key")
        .and_then(|value| value.to_str().ok());
    let envelope = service(&state)
        .submit(
            &principal,
            &selected,
            &Value::Object(request.inputs),
            idempotency_key,
            None,
        )
        .await?;
    Ok((StatusCode::ACCEPTED, Json(envelope)).into_response())
}

/// One run's public envelope.
#[utoipa::path(
    get,
    path = "/mcp/runs/{identity}",
    tag = "runs",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect_run(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
) -> Result<Response, RunsError> {
    let identity = Uuid7::new(identity).map_err(|_| RunsError::Invalid)?;
    let row = service(&state).inspect(&principal.0, &identity).await?;
    Ok(Json(envelope(&row)).into_response())
}

/// One run's event stream, ascending and bounded.
#[utoipa::path(
    get,
    path = "/mcp/runs/{identity}/events",
    tag = "runs",
    params(("identity" = String, Path, format = "uuid7"), EventsQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn run_events(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    query: Result<Query<EventsQuery>, QueryRejection>,
) -> Result<Response, RunsError> {
    let identity = Uuid7::new(identity).map_err(|_| RunsError::Invalid)?;
    let Query(query) = query.map_err(|_| RunsError::Invalid)?;
    let after = query.after.unwrap_or(0);
    let limit = query.limit.unwrap_or(50);
    if after < 0 || !(1..=100).contains(&limit) {
        return Err(RunsError::Invalid);
    }
    let limit = u32::try_from(limit).map_err(|_| RunsError::Invalid)?;
    let service = service(&state);
    let row = service.inspect(&principal.0, &identity).await?;
    let tenant = AuthorityId::new(row.tenant_id.to_string()).map_err(|_| RunsError::Internal)?;
    let events = service
        .repository()
        .events(&tenant, &identity, after, limit)
        .await?;
    let items: Vec<Value> = events
        .iter()
        .map(|event| {
            json!({
                "event_id": event.event_id,
                "kind": event.kind.as_str(),
                // FastAPI encodes the stored instant the way Python's `isoformat` does.
                "created_at": event.created_at.to_rfc3339_opts(SecondsFormat::Micros, false),
            })
        })
        .collect();
    Ok(Json(json!({ "items": items })).into_response())
}

/// Ask one run to stop. A worker still owns the status transition.
#[utoipa::path(
    post,
    path = "/mcp/runs/{identity}/cancel",
    tag = "runs",
    params(("identity" = String, Path, format = "uuid7")),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn cancel_run(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
) -> Result<Response, RunsError> {
    let identity = Uuid7::new(identity).map_err(|_| RunsError::Invalid)?;
    let service = service(&state);
    let row = service.inspect(&principal.0, &identity).await?;
    let tenant = AuthorityId::new(row.tenant_id.to_string()).map_err(|_| RunsError::Internal)?;
    service.repository().cancel(&tenant, &identity).await?;
    // The reference answers with the inspected row's envelope plus the request flag; the
    // stored flag only decides whether an event is appended.
    let mut envelope = envelope(&row);
    if let Value::Object(fields) = &mut envelope {
        fields.insert("cancel_requested".to_owned(), json!(true));
    }
    Ok(Json(envelope).into_response())
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

/// The middleware only raises a management principal on a management path; a submission
/// reached with anything but binding authority is refused, exactly as the reference does.
fn require_binding(principal: AuthPrincipal) -> Result<Principal, RunsError> {
    if principal.0.management {
        Err(RunsError::Forbidden)
    } else {
        Ok(principal.0)
    }
}

/// The execution service for this request: one repository, one live resolver, the configured
/// bounds and this deployment's execution switch.
fn service(state: &AppState) -> ExecutionService {
    ExecutionService::new(
        ExecutionRepository::new(state.pool.clone(), state.execution.clone()),
        resolver(state),
        state.execution.clone(),
        state.execution_enabled,
    )
}

fn parse_body<T: DeserializeOwned>(body: &RawBody) -> Result<T, RunsError> {
    serde_json::from_slice(body).map_err(|_| RunsError::Invalid)
}
