//! The eight tenant tool-catalog operations under `/mcp/tools`.
//!
//! Ported from the reference `src/routers/catalog.py`. Behaviour comes from the reference
//! handlers and `CatalogService`; the OpenAPI shapes are the ones the reference's own document
//! declares, measured from it rather than guessed:
//!
//! * every response declares an empty schema (`{}`) — the reference has no response model,
//!   but its handlers DO return JSON at runtime, and so do these: a write answers with the
//!   reference's `VersionDescriptor`, `definitions` with `{"items", "limit", "offset"}`, an
//!   inspect with `{"descriptor", "files"}` and validate with its fixed result object;
//! * exactly five operations declare a request body: create (`ToolUpload`), append
//!   (`ToolAppend`) and the three status transitions (`RevisionRequest`);
//! * every operation with a path or query parameter declares the reference's 422
//!   `HTTPValidationError`;
//! * a refusal is `{"error": <code>}` with `Cache-Control: no-store` — permission is
//!   `403 forbidden`, a missing row `404 not_found`, a revision/lifecycle conflict
//!   `409 revision_or_lifecycle_conflict` and every other refusal
//!   `422 invalid_request`.
//!
//! The request-body schemas are the reference's pydantic schemas. They are embedded as JSON
//! Schema below (with `$defs` already inlined, because the parity runner inlines them on both
//! sides) and converted into `utoipa`'s schema tree at document generation. The catalog model
//! lives in `crate::catalog` and carries no `utoipa` derivation; keeping the measured contract
//! here means a change to the wire schema is a visible change to this file instead of a silent
//! one in a derive.

use std::collections::BTreeMap;

use axum::Json;
use axum::body::Bytes;
use axum::extract::rejection::QueryRejection;
use axum::extract::{Path, Query, State};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header::CACHE_CONTROL;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use utoipa::openapi::schema::{
    AdditionalProperties, AnyOf, Array, Discriminator, Object, OneOf, Schema, SchemaType, Type,
};
use utoipa::openapi::{Ref, RefOr, SchemaFormat};
use utoipa::{IntoParams, Number, PartialSchema, ToSchema};

use crate::AppState;
use crate::auth::{AuthPrincipal, Principal};
use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{Attribution, ToolManifest, VersionDescriptor};
use crate::catalog::package::PackageFile;
use crate::catalog::service::{CatalogService, CatalogServiceError};
use crate::catalog::validation::SchemaLimits;
use crate::config::PackageLimits;
use crate::routes::health::AnyJson;
use crate::storage::catalog::{AppendRequest, CatalogRepository, CatalogStoreError};

// ── refusals ──────────────────────────────────────────────────────────────────────────────

/// A tool-catalog refusal, rendered as the reference's `{"error": <code>}` with `no-store`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ToolError {
    /// `PermissionError`: the caller may not perform this operation.
    Forbidden,
    /// `CatalogNotFoundError`: no such tenant-owned identity or version.
    NotFound,
    /// `CatalogConflictError` / a database uniqueness violation.
    Conflict,
    /// A validation refusal (`ValueError`, the pydantic request model, the path/query bounds).
    Invalid,
    /// The database failed; a 422 would misreport it as the caller's mistake.
    Internal,
}

impl IntoResponse for ToolError {
    fn into_response(self) -> Response {
        let (status, code) = match self {
            Self::Forbidden => (StatusCode::FORBIDDEN, "forbidden"),
            Self::NotFound => (StatusCode::NOT_FOUND, "not_found"),
            Self::Conflict => (StatusCode::CONFLICT, "revision_or_lifecycle_conflict"),
            Self::Invalid => (StatusCode::UNPROCESSABLE_ENTITY, "invalid_request"),
            Self::Internal => (StatusCode::INTERNAL_SERVER_ERROR, "internal"),
        };
        let mut response = (status, axum::Json(json!({ "error": code }))).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        response
    }
}

impl From<CatalogServiceError> for ToolError {
    fn from(error: CatalogServiceError) -> Self {
        match error {
            CatalogServiceError::Invalid(_) => Self::Invalid,
            CatalogServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogStoreError> for ToolError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(_) => Self::NotFound,
            CatalogStoreError::Conflict(_) => Self::Conflict,
            // A stored row the model can no longer parse: the reference's ValidationError
            // on that read, which its exception handler maps to 422.
            CatalogStoreError::Corrupt(_) => Self::Invalid,
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "tool catalog database failure");
                Self::Internal
            }
        }
    }
}

// ── request models ────────────────────────────────────────────────────────────────────────

/// The reference's `ToolUpload` management envelope.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolUpload {
    manifest: ToolManifest,
    files: Vec<PackageFile>,
}

/// The reference's `ToolAppend`: an upload with the revision the caller last saw.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolAppend {
    manifest: ToolManifest,
    files: Vec<PackageFile>,
    expected_revision: PositiveVersion,
}

/// The reference's `RevisionRequest`: the revision the caller last saw.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionRequest {
    expected_revision: PositiveVersion,
}

/// The reference's query bounds for `GET /mcp/tools/definitions`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DefinitionsQuery {
    /// Maximum number of definitions to return.
    #[param(minimum = 1, maximum = 100, default = 50)]
    pub limit: Option<u32>,
    /// Definitions to skip.
    #[param(minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

/// The reference's FastAPI `ValidationError` component.
#[derive(Debug)]
pub struct ValidationError;

/// The reference's FastAPI `HTTPValidationError` component.
#[derive(Debug)]
pub struct HTTPValidationError;

// ── success responses ─────────────────────────────────────────────────────────────────────
//
// The reference declares no response schema, so the OpenAPI document keeps its empty `{}`
// shape; the JSON below is what the reference's handlers actually return at runtime. Each
// struct is declared with the reference's own field order (pydantic's declaration order /
// the definitions query's column order), because `Json` serializes it field by field.

/// One row of the reference's `GET /mcp/tools/definitions` query.
#[derive(Debug, Serialize)]
struct DefinitionsItem<'a> {
    tool_id: &'a Uuid7,
    version: PositiveVersion,
    public_name: &'a Name,
    revision: PositiveVersion,
    status: VersionStatus,
}

/// The reference's definitions envelope: the page plus the window it answered for.
#[derive(Debug, Serialize)]
struct DefinitionsPage<'a> {
    items: Vec<DefinitionsItem<'a>>,
    limit: u32,
    offset: u32,
}

/// The reference's inspect envelope: one exact version and its package files.
#[derive(Debug, Serialize)]
struct InspectResponse<'a> {
    descriptor: &'a VersionDescriptor,
    files: &'a [PackageFile],
}

/// The reference's `validate` result: the constants its handler returns after revalidating.
#[derive(Debug, Serialize)]
struct ValidationResult<'a> {
    tool_id: &'a Uuid7,
    version: PositiveVersion,
    metadata_valid: bool,
    credentials_verified: bool,
    execution: &'static str,
}

/// A successful lifecycle write: the reference returns the affected `VersionDescriptor`.
fn descriptor_response(status: StatusCode, descriptor: VersionDescriptor) -> Response {
    (status, Json(descriptor)).into_response()
}

// ── handlers ──────────────────────────────────────────────────────────────────────────────

/// Create a tenant tool identity at version 1.
#[utoipa::path(
    post,
    path = "/mcp/tools",
    tag = "tools",
    request_body = ToolUpload,
    responses((status = 201, description = "Successful Response", body = AnyJson))
)]
pub async fn create_tool(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    body: Bytes,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let payload: ToolUpload = parse_body(&body)?;
    let tenant = tenant_id(&principal);
    if payload.manifest.tenant_id != tenant {
        return Err(ToolError::Forbidden);
    }
    if payload.files.is_empty() {
        return Err(ToolError::Invalid);
    }
    let descriptor = service(&state)
        .create_draft(
            &tenant,
            &payload.manifest,
            &payload.files,
            &actor(&principal),
        )
        .await?;
    Ok(descriptor_response(StatusCode::CREATED, descriptor))
}

/// Append the next draft version to an owned tool identity.
#[utoipa::path(
    post,
    path = "/mcp/tools/{identity}/versions",
    tag = "tools",
    params(("identity" = String, Path, format = "uuid7")),
    request_body = ToolAppend,
    responses(
        (status = 201, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn append_tool(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path(identity): Path<String>,
    body: Bytes,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolError::Invalid)?;
    let payload: ToolAppend = parse_body(&body)?;
    let tenant = tenant_id(&principal);
    if payload.manifest.tenant_id != tenant {
        return Err(ToolError::Forbidden);
    }
    if payload.manifest.tool_id != identity {
        return Err(ToolError::Invalid);
    }
    if payload.files.is_empty() {
        return Err(ToolError::Invalid);
    }
    let descriptor = service(&state)
        .append_draft(&AppendRequest {
            tenant_id: &tenant,
            tool_id: &identity,
            content: &payload.manifest,
            files: &payload.files,
            actor: &actor(&principal),
            expected_revision: Some(payload.expected_revision),
            exact_version: true,
        })
        .await?;
    Ok(descriptor_response(StatusCode::CREATED, descriptor))
}

/// Every tenant version, newest identity first.
#[utoipa::path(
    get,
    path = "/mcp/tools/definitions",
    tag = "tools",
    params(DefinitionsQuery),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn definitions(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    query: Result<Query<DefinitionsQuery>, QueryRejection>,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let Query(query) = query.map_err(|_| ToolError::Invalid)?;
    let limit = query.limit.unwrap_or(50);
    let offset = query.offset.unwrap_or(0);
    if !(1..=100).contains(&limit) {
        return Err(ToolError::Invalid);
    }
    let definitions = CatalogRepository::new(state.pool.clone())
        .definitions(&tenant_id(&principal), limit, offset)
        .await?;
    Ok(Json(DefinitionsPage {
        items: definitions
            .iter()
            .map(|definition| DefinitionsItem {
                tool_id: &definition.tool_id,
                version: definition.version,
                public_name: &definition.public_name,
                revision: definition.revision,
                status: definition.status,
            })
            .collect(),
        limit,
        offset,
    })
    .into_response())
}

/// One exact version and its package files.
#[utoipa::path(
    get,
    path = "/mcp/tools/{identity}/versions/{version}",
    tag = "tools",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path, minimum = 1)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn inspect(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolError::Invalid)?;
    let version = version_parameter(&version, true)?;
    let tenant = tenant_id(&principal);
    let repository = CatalogRepository::new(state.pool.clone());
    let descriptor = repository.get_version(&tenant, &identity, version).await?;
    let files = repository.files(&tenant, &identity, version).await?;
    Ok(Json(InspectResponse {
        descriptor: &descriptor,
        files: &files,
    })
    .into_response())
}

/// Re-run the complete validation over a stored version.
#[utoipa::path(
    post,
    path = "/mcp/tools/{identity}/versions/{version}/validate",
    tag = "tools",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn validate(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolError::Invalid)?;
    let version = version_parameter(&version, false)?;
    let tenant = tenant_id(&principal);
    let repository = CatalogRepository::new(state.pool.clone());
    let original = repository.get_version(&tenant, &identity, version).await?;
    let files = repository.files(&tenant, &identity, version).await?;
    service(&state).validate(&original.manifest, &files).await?;
    Ok(Json(ValidationResult {
        tool_id: &identity,
        version,
        metadata_valid: true,
        credentials_verified: false,
        execution: "unavailable",
    })
    .into_response())
}

/// Publish a draft version.
#[utoipa::path(
    post,
    path = "/mcp/tools/{identity}/versions/{version}/publish",
    tag = "tools",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    request_body = RevisionRequest,
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn publish_tool(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ToolError> {
    transition(
        state,
        principal,
        identity,
        version,
        body,
        VersionStatus::Published,
    )
    .await
}

/// Disable a version.
#[utoipa::path(
    post,
    path = "/mcp/tools/{identity}/versions/{version}/disable",
    tag = "tools",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    request_body = RevisionRequest,
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn disable_tool(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ToolError> {
    transition(
        state,
        principal,
        identity,
        version,
        body,
        VersionStatus::Disabled,
    )
    .await
}

/// Retire a version.
#[utoipa::path(
    post,
    path = "/mcp/tools/{identity}/versions/{version}/retire",
    tag = "tools",
    params(
        ("identity" = String, Path, format = "uuid7"),
        ("version" = i32, Path)
    ),
    request_body = RevisionRequest,
    responses(
        (status = 200, description = "Successful Response", body = AnyJson),
        (status = 422, description = "Validation Error", body = HTTPValidationError)
    )
)]
pub async fn retire_tool(
    State(state): State<AppState>,
    principal: AuthPrincipal,
    Path((identity, version)): Path<(String, String)>,
    body: Bytes,
) -> Result<Response, ToolError> {
    transition(
        state,
        principal,
        identity,
        version,
        body,
        VersionStatus::Retired,
    )
    .await
}

// ── handler helpers ──────────────────────────────────────────────────────────────────────

async fn transition(
    state: AppState,
    principal: AuthPrincipal,
    identity: String,
    version: String,
    body: Bytes,
    status: VersionStatus,
) -> Result<Response, ToolError> {
    let principal = require_management(principal)?;
    let identity = Uuid7::new(identity).map_err(|_| ToolError::Invalid)?;
    let version = version_parameter(&version, false)?;
    let payload: RevisionRequest = parse_body(&body)?;
    let descriptor = service(&state)
        .transition(
            &tenant_id(&principal),
            &identity,
            version,
            status,
            &actor(&principal),
            payload.expected_revision,
        )
        .await?;
    Ok(descriptor_response(StatusCode::OK, descriptor))
}

/// The middleware only ever raises a management principal on a management path; a handler
/// reached with anything else is a wiring fault, and the reference's `get_operator` refuses it.
fn require_management(principal: AuthPrincipal) -> Result<Principal, ToolError> {
    if principal.0.management {
        Ok(principal.0)
    } else {
        Err(ToolError::Forbidden)
    }
}

fn tenant_id(principal: &Principal) -> AuthorityId {
    AuthorityId::new(principal.tenant_id.to_string()).expect("licence identity is an RFC 4122 UUID")
}

fn actor(principal: &Principal) -> Attribution {
    Attribution {
        subject: principal.subject.clone(),
        license_id: AuthorityId::new(principal.license_id.to_string()).ok(),
    }
}

fn service(state: &AppState) -> CatalogService {
    CatalogService::new(
        CatalogRepository::new(state.pool.clone()),
        SchemaLimits::default(),
        PackageLimits::default(),
    )
}

fn parse_body<T: DeserializeOwned>(body: &Bytes) -> Result<T, ToolError> {
    serde_json::from_slice(body).map_err(|_| ToolError::Invalid)
}

/// Parse one path `version`. `bounded` is the route's own `Path(ge=1)`: when it is absent the
/// reference passes the raw integer to the repository, where a non-positive version simply
/// finds no row — a 404, not a validation refusal.
fn version_parameter(value: &str, bounded: bool) -> Result<PositiveVersion, ToolError> {
    let value: i64 = value.parse().map_err(|_| ToolError::Invalid)?;
    if value < 1 {
        return Err(if bounded {
            ToolError::Invalid
        } else {
            ToolError::NotFound
        });
    }
    PositiveVersion::new(u64::try_from(value).expect("a positive integer fits u64"))
        .map_err(|_| ToolError::Invalid)
}

// ── OpenAPI: the reference's measured request-body schemas ────────────────────────────────

/// A JSON Pointer schema: the reference's `Annotated[str, Field(pattern=..., max_length=512)]`.
fn pointer_schema() -> Value {
    json!({
        "type": "string",
        "maxLength": 512,
        "pattern": "^(?:/(?:[^~/]|~[01])*)*$"
    })
}

/// The reference's `ExactReference`.
fn exact_reference_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "id": {"type": "string", "format": "uuid7"},
            "version": {"type": "integer", "exclusiveMinimum": 0, "maximum": 2147483647}
        },
        "required": ["id", "version"]
    })
}

/// One `OperationConstraints.rules` member, unioned by the discriminator on `kind`.
fn context_equality_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string", "const": "context_equal"},
            "argument": pointer_schema(),
            "context": pointer_schema()
        },
        "required": ["kind", "argument", "context"]
    })
}

fn set_membership_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string", "const": "set_membership"},
            "argument": pointer_schema(),
            "values": {
                "type": "array",
                "items": {},
                "minItems": 1,
                "maxItems": 64
            }
        },
        "required": ["kind", "argument", "values"]
    })
}

fn numeric_bounds_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string", "const": "numeric_bounds"},
            "argument": pointer_schema(),
            "minimum": {"type": "number"},
            "maximum": {"type": "number"}
        },
        "required": ["kind", "argument", "minimum", "maximum"]
    })
}

fn relative_path_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string", "const": "relative_path"},
            "argument": pointer_schema(),
            "root": {"type": "string"}
        },
        "required": ["kind", "argument", "root"]
    })
}

fn ownership_read_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "kind": {"type": "string", "const": "ownership_read"},
            "argument": pointer_schema(),
            "operation": exact_reference_schema(),
            "result": pointer_schema(),
            "context": pointer_schema()
        },
        "required": ["kind", "argument", "operation", "result", "context"]
    })
}

/// The reference's discriminated rule union. The mapping strings are the reference's own
/// `#/$defs/...` values: the comparer does not resolve a discriminator mapping, so they must
/// be reproduced verbatim.
fn rule_schema() -> Value {
    json!({
        "discriminator": {
            "propertyName": "kind",
            "mapping": {
                "context_equal": "#/$defs/ContextEquality",
                "set_membership": "#/$defs/SetMembership",
                "numeric_bounds": "#/$defs/NumericBounds",
                "relative_path": "#/$defs/RelativePath",
                "ownership_read": "#/$defs/OwnershipRead"
            }
        },
        "oneOf": [
            context_equality_schema(),
            set_membership_schema(),
            numeric_bounds_schema(),
            relative_path_schema(),
            ownership_read_schema()
        ]
    })
}

fn operation_constraints_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "operation": exact_reference_schema(),
            "rules": {"type": "array", "items": rule_schema(), "maxItems": 64}
        },
        "required": ["operation", "rules"]
    })
}

/// The reference's `ToolLimits`.
fn limits_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "wall_seconds": {"type": "integer", "default": 60, "exclusiveMinimum": 0, "maximum": 300},
            "queue_seconds": {"type": "integer", "default": 60, "exclusiveMinimum": 0, "maximum": 600},
            "cpu_millicores": {"type": "integer", "default": 250, "exclusiveMinimum": 0, "maximum": 1000},
            "memory_mi": {"type": "integer", "default": 256, "exclusiveMinimum": 0, "maximum": 1024},
            "frame_bytes": {"type": "integer", "default": 65536, "exclusiveMinimum": 0, "maximum": 1048576},
            "output_bytes": {"type": "integer", "default": 262144, "exclusiveMinimum": 0, "maximum": 1048576},
            "api_calls": {"type": "integer", "default": 10, "minimum": 0, "maximum": 100}
        }
    })
}

/// The reference's `ExternalTarget` union, nullable.
fn target_schema() -> Value {
    json!({
        "anyOf": [
            {
                "discriminator": {
                    "propertyName": "kind",
                    "mapping": {
                        "n8n_workflow": "#/$defs/N8nWorkflowTarget",
                        "fr_project": "#/$defs/FrProjectTarget",
                        "fr_command": "#/$defs/FrCommandTarget"
                    }
                },
                "oneOf": [
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "kind": {"type": "string", "const": "n8n_workflow"},
                            "webhook_path": {"type": "string", "pattern": "^[a-z0-9][a-z0-9/_-]{0,127}$"},
                            "result_node": {"type": "string", "default": "MCP Result", "pattern": "^[A-Za-z0-9 _.-]{1,128}$"}
                        },
                        "required": ["kind", "webhook_path"]
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "kind": {"type": "string", "const": "fr_project"},
                            "project_type": {"type": "string", "pattern": "^[a-z0-9_-]{1,128}$"}
                        },
                        "required": ["kind", "project_type"]
                    },
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {
                            "kind": {"type": "string", "const": "fr_command"},
                            "command": {"type": "string", "enum": ["projects.get", "projects.close"]}
                        },
                        "required": ["kind", "command"]
                    }
                ]
            },
            {"type": "null"}
        ]
    })
}

/// The reference's strict `ToolManifest`.
fn manifest_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "schema_version": {"type": "integer", "const": 1, "default": 1},
            "tool_id": {"type": "string", "format": "uuid7"},
            "tenant_id": {"type": "string", "format": "uuid"},
            "version": {"type": "integer", "exclusiveMinimum": 0, "maximum": 2147483647},
            "public_name": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"},
            "operation": {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,31}\\.[a-z][a-z0-9_]{0,31}$"},
            "description": {"type": "string", "minLength": 1, "maxLength": 4096},
            "runtime": {
                "type": "string",
                "enum": ["kata_python", "n8n_workflow", "fr_project", "fr_command"],
                "default": "kata_python"
            },
            "target": target_schema(),
            "entrypoint": {
                "anyOf": [
                    {"type": "string", "maxLength": 256},
                    {"type": "null"}
                ]
            },
            "input_schema": {"type": "object"},
            "result_schema": {"type": "object"},
            "context_schema": {"type": "object"},
            "package_sha256": {"type": "string", "pattern": "^[a-f0-9]{64}$"},
            "runner_image_digest": {
                "anyOf": [
                    {"type": "string", "pattern": "^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$"},
                    {"type": "null"}
                ]
            },
            "allowed_operations": {"type": "array", "default": [], "items": exact_reference_schema()},
            "operation_constraints": {
                "type": "array",
                "default": [],
                "items": operation_constraints_schema()
            },
            "limits": limits_schema(),
            "effect": {"type": "string", "enum": ["read_only", "writes"]}
        },
        "required": [
            "tool_id",
            "tenant_id",
            "version",
            "public_name",
            "operation",
            "description",
            "input_schema",
            "result_schema",
            "context_schema",
            "package_sha256",
            "effect"
        ]
    })
}

fn package_file_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "path": {"type": "string"},
            "content": {"type": "string"}
        },
        "required": ["path", "content"]
    })
}

fn expected_revision_schema() -> Value {
    json!({
        "type": "integer",
        "exclusiveMinimum": 0,
        "maximum": 2147483647
    })
}

/// The reference's `ToolUpload` envelope: a manifest plus at least one package file.
fn tool_upload_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "manifest": manifest_schema(),
            "files": {"type": "array", "minItems": 1, "items": package_file_schema()}
        },
        "required": ["manifest", "files"]
    })
}

/// The reference's `ToolAppend` envelope.
fn tool_append_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "manifest": manifest_schema(),
            "files": {"type": "array", "minItems": 1, "items": package_file_schema()},
            "expected_revision": expected_revision_schema()
        },
        "required": ["manifest", "files", "expected_revision"]
    })
}

/// The reference's `RevisionRequest`.
fn revision_request_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {"expected_revision": expected_revision_schema()},
        "required": ["expected_revision"]
    })
}

/// The reference's `ValidationError`.
fn validation_error_schema() -> Value {
    json!({
        "type": "object",
        "properties": {
            "loc": {
                "type": "array",
                "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]}
            },
            "msg": {"type": "string"},
            "type": {"type": "string"},
            "input": {},
            "ctx": {"type": "object"}
        },
        "required": ["loc", "msg", "type"]
    })
}

// ── JSON Schema -> utoipa schema ─────────────────────────────────────────────────────────

/// Keys that document a schema but are not part of its contract; they are dropped exactly as
/// the parity comparer drops them.
const DOC_KEYS: &[&str] = &["title", "description", "$id", "$schema"];

fn utoipa_schema(value: &Value) -> Schema {
    let map = value.as_object().expect("schema is a JSON object");
    if let Some(branches) = map.get("oneOf") {
        let mut composite = OneOf::new();
        composite.items = schema_items(branches);
        composite.discriminator = discriminator(map);
        return Schema::OneOf(composite);
    }
    if let Some(branches) = map.get("anyOf") {
        let mut composite = AnyOf::new();
        composite.items = schema_items(branches);
        composite.discriminator = discriminator(map);
        return Schema::AnyOf(composite);
    }
    if map.get("type").and_then(Value::as_str) == Some("array") {
        return Schema::Array(array_schema(map));
    }
    Schema::Object(object_schema(map))
}

fn schema_items(value: &Value) -> Vec<RefOr<Schema>> {
    value
        .as_array()
        .expect("a composite schema is an array")
        .iter()
        .map(|branch| RefOr::T(utoipa_schema(branch)))
        .collect()
}

fn discriminator(map: &Map<String, Value>) -> Option<Discriminator> {
    map.get("discriminator").map(|value| {
        let discriminator = value.as_object().expect("discriminator object");
        let property_name = discriminator
            .get("propertyName")
            .and_then(Value::as_str)
            .expect("discriminator propertyName");
        let mapping = discriminator
            .get("mapping")
            .map_or_else(BTreeMap::new, |mapping| {
                mapping
                    .as_object()
                    .expect("discriminator mapping object")
                    .iter()
                    .map(|(kind, reference)| {
                        (
                            kind.clone(),
                            reference
                                .as_str()
                                .expect("discriminator mapping reference")
                                .to_owned(),
                        )
                    })
                    .collect()
            });
        Discriminator {
            property_name: property_name.to_owned(),
            mapping,
            extensions: None,
        }
    })
}

fn schema_type(value: Option<&Value>) -> SchemaType {
    match value {
        None => SchemaType::AnyValue,
        Some(Value::String(name)) => match name.as_str() {
            "object" => SchemaType::Type(Type::Object),
            "string" => SchemaType::Type(Type::String),
            "integer" => SchemaType::Type(Type::Integer),
            "number" => SchemaType::Type(Type::Number),
            "boolean" => SchemaType::Type(Type::Boolean),
            "array" => SchemaType::Type(Type::Array),
            "null" => SchemaType::Type(Type::Null),
            other => panic!("unsupported schema type {other}"),
        },
        Some(other) => panic!("unsupported schema type {other}"),
    }
}

fn array_schema(map: &Map<String, Value>) -> Array {
    let mut array = Array::new(RefOr::T(utoipa_schema(
        map.get("items").expect("array items"),
    )));
    array.min_items = map.get("minItems").map(usize_value);
    array.max_items = map.get("maxItems").map(usize_value);
    array.default = map.get("default").cloned();
    for key in map.keys() {
        assert!(
            matches!(
                key.as_str(),
                "type" | "items" | "minItems" | "maxItems" | "default"
            ) || DOC_KEYS.contains(&key.as_str()),
            "unsupported array keyword {key}"
        );
    }
    array
}

fn object_schema(map: &Map<String, Value>) -> Object {
    let mut object = Object::with_type(schema_type(map.get("type")));
    object.format = map.get("format").map(|format| {
        SchemaFormat::Custom(format.as_str().expect("format is a string").to_owned())
    });
    object.default = map.get("default").cloned();
    object.enum_values = map
        .get("enum")
        .and_then(Value::as_array)
        .cloned()
        .or_else(|| map.get("const").map(|value| vec![value.clone()]));
    object.required = map
        .get("required")
        .and_then(Value::as_array)
        .map(|required| {
            required
                .iter()
                .map(|name| name.as_str().expect("required name").to_owned())
                .collect()
        })
        .unwrap_or_default();
    object.properties = map
        .get("properties")
        .and_then(Value::as_object)
        .map(|properties| {
            properties
                .iter()
                .map(|(name, value)| (name.clone(), RefOr::T(utoipa_schema(value))))
                .collect()
        })
        .unwrap_or_default();
    object.additional_properties = map.get("additionalProperties").map(|value| {
        Box::new(match value {
            Value::Bool(allowed) => AdditionalProperties::FreeForm(*allowed),
            Value::Object(inner) if inner.is_empty() => AdditionalProperties::RefOr(RefOr::T(
                Schema::Object(Object::with_type(SchemaType::AnyValue)),
            )),
            other => AdditionalProperties::RefOr(RefOr::T(utoipa_schema(other))),
        })
    });
    object.minimum = map.get("minimum").map(number_value);
    object.maximum = map.get("maximum").map(number_value);
    object.exclusive_minimum = map.get("exclusiveMinimum").map(number_value);
    object.exclusive_maximum = map.get("exclusiveMaximum").map(number_value);
    object.min_length = map.get("minLength").map(usize_value);
    object.max_length = map.get("maxLength").map(usize_value);
    object.pattern = map
        .get("pattern")
        .map(|pattern| pattern.as_str().expect("pattern is a string").to_owned());
    for key in map.keys() {
        assert!(
            matches!(
                key.as_str(),
                "type"
                    | "format"
                    | "default"
                    | "enum"
                    | "const"
                    | "required"
                    | "properties"
                    | "additionalProperties"
                    | "minimum"
                    | "maximum"
                    | "exclusiveMinimum"
                    | "exclusiveMaximum"
                    | "minLength"
                    | "maxLength"
                    | "pattern"
            ) || DOC_KEYS.contains(&key.as_str()),
            "unsupported object keyword {key}"
        );
    }
    object
}

fn number_value(value: &Value) -> Number {
    let number = value.as_number().expect("a numeric bound");
    match number.as_i64() {
        Some(integer) => Number::Int(isize::try_from(integer).expect("bound fits isize")),
        None => Number::Float(number.as_f64().expect("a numeric bound")),
    }
}

fn usize_value(value: &Value) -> usize {
    usize::try_from(value.as_u64().expect("a non-negative bound")).expect("bound fits usize")
}

impl PartialSchema for ToolUpload {
    fn schema() -> RefOr<Schema> {
        RefOr::T(utoipa_schema(&tool_upload_schema()))
    }
}

impl ToSchema for ToolUpload {}

impl PartialSchema for ToolAppend {
    fn schema() -> RefOr<Schema> {
        RefOr::T(utoipa_schema(&tool_append_schema()))
    }
}

impl ToSchema for ToolAppend {}

impl PartialSchema for RevisionRequest {
    fn schema() -> RefOr<Schema> {
        RefOr::T(utoipa_schema(&revision_request_schema()))
    }
}

impl ToSchema for RevisionRequest {}

impl PartialSchema for ValidationError {
    fn schema() -> RefOr<Schema> {
        RefOr::T(utoipa_schema(&validation_error_schema()))
    }
}

impl ToSchema for ValidationError {}

impl PartialSchema for HTTPValidationError {
    fn schema() -> RefOr<Schema> {
        // The reference's component: `detail` is an array of `ValidationError`, by reference.
        let detail = Array::new(RefOr::Ref(Ref::new("#/components/schemas/ValidationError")));
        let mut object = Object::with_type(Type::Object);
        object.properties =
            BTreeMap::from([("detail".to_owned(), RefOr::T(Schema::Array(detail)))]);
        RefOr::T(Schema::Object(object))
    }
}

impl ToSchema for HTTPValidationError {}
