//! Tenant builder catalog writes and reads (the reference's `src/storage/builder.py`).
//!
//! Every service/operation write goes through a `SECURITY DEFINER` `public.mcp_builder_*`
//! function, which rejects the platform tenant and enforces ownership, so a caller bug cannot
//! cross tenants. The tool lifecycle uses the same tables and error boundaries as
//! [`crate::storage::catalog`]; the quota is counted under the tenant advisory lock
//! (`pg_advisory_xact_lock(hashtext('builder:<tenant>'))`), the same lock the `mcp_builder_*`
//! functions take before they count a quota.
//!
//! The methods here are the SQL half of the reference's builder service: source→service
//! agreement, service and operation creation/listing/update, platform-operation resolution and
//! repinning, the tool lifecycle (create/append/get/list/publish/set-status), the toolkit
//! write/publish calls, and the author's draft test runs (`submit_draft`/`draft_run` — the
//! reference's `ExecutionService.submit_draft`/`draft_run` over the execution repository's
//! `accept_draft`/`get_draft`/`trace`). `rebind` is the bindings-ensure service's, ported in
//! [`crate::storage::bindings_ensure`]: a toolkit publication that triggers it reports a
//! re-bind failure and never rolls the already-committed publication back.
//!
//! Refusals keep the reference's exception split: `MB001`/`23505` are conflicts, `MB002` not
//! found, `MB003` the quota, `MB004` the platform-tenant refusal, `23514`/`23503` invalid
//! requests. Only the primary message is kept, never row detail.

use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use chrono::{DateTime, Utc};
use serde::Serialize;
use serde_json::{Map, Value, json};
use sqlx::error::DatabaseError as _;
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Postgres, Row, Transaction};
use thiserror::Error;

use crate::auth::BoxFuture;
use crate::auth::uuid::Rfc4122Uuid;
use crate::builder::models::{OperationPatch, ToolOperation};
use crate::builder::packaging;
use crate::catalog::ids::{AppKey, AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::instance::validate_instance;
use crate::catalog::lifecycle::{VersionStatus, tool_transition_allowed};
use crate::catalog::models::{
    Attribution, AuthAdapter, Effect, ExactReference, OperationManifest, Runtime, ServiceManifest,
    ToolLimits, ToolManifest, VersionDescriptor,
};
use crate::catalog::package::PackageFile;
use crate::catalog::resolver::ResolvedTool;
use crate::catalog::toolkit_models::{
    BoundContext, CredentialProfile, CredentialReference, EffectiveTool, ToolReference,
    ToolkitDescriptor,
};
use crate::catalog::validation::SchemaLimits;
use crate::execution::{RunRow, authority_snapshot, value_hash};
use crate::storage::catalog::{
    AppendRequest, CatalogRepository, CatalogStoreError, ToolDefinition,
};
use crate::storage::executions::{ExecutionStoreError, RUN_COLUMNS, decode_run};
use crate::storage::toolkits::{
    ToolkitStoreError, transition_toolkit as toolkit_transition, write_toolkit as toolkit_write,
};
use crate::toolkits::resolver::{SelectionResolver, narrow_limits};
use crate::worker::creds::{CredentialError, Minter};

/// A refused or impossible builder storage operation, in the reference's exception shapes.
#[derive(Debug, Error)]
pub enum BuilderStoreError {
    /// The reference's `CatalogConflictError` (`MB001`, `23505`, stale revision, lifecycle).
    #[error("{0}")]
    Conflict(String),
    /// The reference's `CatalogNotFoundError` (`MB002`).
    #[error("{0}")]
    NotFound(String),
    /// The reference's `QuotaExceededError` (`MB003`), whose message is
    /// `"<resource> quota exceeded"`.
    #[error("{0} quota exceeded")]
    Quota(&'static str),
    /// The reference's `BuilderForbiddenError` (`MB004`): the platform tenant never authors, and
    /// the reference's `PermissionError`/`ExecutionDeniedError` for a refused execution.
    #[error("{0}")]
    Forbidden(String),
    /// The reference's `BuilderUnavailableError` (`503`): this deployment cannot run drafts.
    #[error("{0}")]
    Unavailable(&'static str),
    /// The reference's `ValueError` for a request-level violation (`23514`/`23503`).
    #[error("{0}")]
    Invalid(String),
    /// A stored row no longer satisfies the domain model (schema drift, not a request error).
    #[error("stored builder row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed the statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<CatalogStoreError> for BuilderStoreError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::Conflict(message) => Self::Conflict(message.to_owned()),
            CatalogStoreError::NotFound(message) => Self::NotFound(message.to_owned()),
            CatalogStoreError::Corrupt(message) => Self::Corrupt(message),
            CatalogStoreError::Database(error) => Self::Database(error),
        }
    }
}

impl From<ToolkitStoreError> for BuilderStoreError {
    fn from(error: ToolkitStoreError) -> Self {
        match error {
            ToolkitStoreError::Permission(message) => Self::Forbidden(message.to_owned()),
            ToolkitStoreError::Invalid(message) => Self::Invalid(message.to_owned()),
            ToolkitStoreError::Conflict(message) => Self::Conflict(message.to_owned()),
            ToolkitStoreError::NotFound(message) => Self::NotFound(message.to_owned()),
            ToolkitStoreError::Corrupt(message) => Self::Corrupt(message),
            ToolkitStoreError::Database(error) => match error {
                sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
                    Self::Conflict("toolkit identity or name already exists".to_owned())
                }
                other => Self::Database(other),
            },
        }
    }
}

impl From<ExecutionStoreError> for BuilderStoreError {
    fn from(error: ExecutionStoreError) -> Self {
        match error {
            // A draft read never queues, so these two only arrive from a shared decoder that a
            // caller misused; the public HTTP shape is the reference's 403 in either case.
            ExecutionStoreError::QueueFull => Self::Forbidden("execution queue is full".to_owned()),
            ExecutionStoreError::Denied => Self::Forbidden("execution denied".to_owned()),
            ExecutionStoreError::Conflict(message) => Self::Conflict(message.to_owned()),
            ExecutionStoreError::NotFound => Self::NotFound("run not found".to_owned()),
            ExecutionStoreError::Store(error) => error.into(),
        }
    }
}

/// The reference's `builder_errors` translation (`storage/catalog.py:59-85`).
fn builder_error(error: sqlx::Error, resource: &'static str) -> BuilderStoreError {
    match error {
        sqlx::Error::Database(database) => {
            let message = database.message().to_owned();
            let code = database.code().as_deref().map(str::to_owned);
            match code.as_deref() {
                Some("MB001") => BuilderStoreError::Conflict(message),
                Some("MB002") => BuilderStoreError::NotFound(message),
                Some("MB003") => BuilderStoreError::Quota(resource),
                Some("MB004") => BuilderStoreError::Forbidden(message),
                Some("23505") => BuilderStoreError::Conflict(format!("{resource} already exists")),
                Some("23514") | Some("23503") => BuilderStoreError::Invalid(message),
                _ => BuilderStoreError::Database(sqlx::Error::Database(database)),
            }
        }
        other => BuilderStoreError::Database(other),
    }
}

/// Roll a refused transaction back before returning it.
///
/// Dropping a live `Transaction` starts an asynchronous rollback whose completion the pool
/// waits for before reusing the connection; on a current-thread runtime the next `begin` can
/// then wait on a connection nobody is driving. Every refusal after `begin` rolls back first.
async fn refusing(tx: Transaction<'_, Postgres>, error: BuilderStoreError) -> BuilderStoreError {
    let _ = tx.rollback().await;
    error
}

/// The four per-tenant builder quotas (`builder.py:29-37`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resource {
    /// Active `mcp_sources` owned by the tenant.
    Sources,
    /// Keyed operations of the tenant's services.
    Operations,
    /// Non-retired tools.
    Tools,
    /// Toolkit identities.
    Toolkits,
}

impl Resource {
    /// The reference's dictionary key, which is also the quota message's resource name.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Sources => "sources",
            Self::Operations => "operations",
            Self::Tools => "tools",
            Self::Toolkits => "toolkits",
        }
    }
}

impl std::fmt::Display for Resource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The reference's `usage` result: current counts for the four quota resources.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Usage {
    /// Active sources.
    pub sources: i64,
    /// Keyed operations.
    pub operations: i64,
    /// Non-retired tools.
    pub tools: i64,
    /// Toolkit identities.
    pub toolkits: i64,
}

impl Usage {
    /// One resource's count.
    pub fn get(&self, resource: Resource) -> i64 {
        match resource {
            Resource::Sources => self.sources,
            Resource::Operations => self.operations,
            Resource::Tools => self.tools,
            Resource::Toolkits => self.toolkits,
        }
    }
}

/// The newest version of a tenant's service for one of its sources (`ServiceRecord`).
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceRecord {
    /// The service identity.
    pub service_id: Uuid7,
    /// The service key.
    pub service_key: Name,
    /// The identity's revision.
    pub revision: PositiveVersion,
    /// The newest version.
    pub version: PositiveVersion,
    /// The newest version's lifecycle status.
    pub status: VersionStatus,
    /// The newest version's manifest.
    pub manifest: ServiceManifest,
}

/// The newest version of an operation and the key tools address it by (`OperationRecord`).
#[derive(Debug, Clone, PartialEq)]
pub struct OperationRecord {
    /// The key the operation is addressed by.
    pub op_key: Name,
    /// The operation identity.
    pub operation_id: Uuid7,
    /// The owning service.
    pub service_id: Uuid7,
    /// The newest version.
    pub version: PositiveVersion,
    /// The newest version's lifecycle status.
    pub status: VersionStatus,
    /// The newest version's manifest.
    pub manifest: OperationManifest,
}

/// Why a platform service is visible to a tenant (`visible_platform_services`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Visibility {
    /// An explicit `mcp_service_grants` row.
    Grant,
    /// A licence-kind platform source the tenant may use.
    Licence,
}

/// One platform service a tenant tool may reference (`visible_platform_services`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VisibleService {
    /// The service identity.
    pub service_id: Uuid7,
    /// The service key.
    pub service_key: Name,
    /// The newest published version.
    pub version: PositiveVersion,
    /// How it is shared.
    pub via: Visibility,
}

/// The reference's `OPERATION_SELECT` (`builder.py:98-104`), with the identity columns cast to
/// text because this crate's `sqlx` build carries no `uuid` mapping.
const OPERATION_SELECT: &str = "SELECT k.op_key,k.operation_id::text AS operation_id,\
     k.service_id::text AS service_id,o.version,o.status,o.manifest \
     FROM public.mcp_operation_keys k \
     JOIN public.mcp_services s ON s.service_id=k.service_id \
     JOIN LATERAL (SELECT * FROM public.mcp_operation_versions v \
       WHERE v.operation_id=k.operation_id ORDER BY v.version DESC LIMIT 1) o ON true ";

/// The reference's `lock_key` (`builder.py:106-107`).
pub fn lock_key(tenant: &AuthorityId) -> String {
    format!("builder:{}", tenant.as_str())
}

/// The reference's `lock_tenant` (`builder.py:110-113`): serialize a tenant's builder writes
/// for the rest of the transaction, the same lock every `mcp_builder_*` function takes.
pub async fn lock_tenant(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
) -> Result<(), BuilderStoreError> {
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext($1))")
        .bind(lock_key(tenant))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The reference's fixed `COUNTS` statements (`builder.py:29-37`).
fn count_statement(resource: Resource) -> &'static str {
    match resource {
        Resource::Sources => {
            "SELECT count(*) AS n FROM public.mcp_sources \
             WHERE owner_tenant_id=$1::uuid AND status='active'"
        }
        Resource::Operations => {
            "SELECT count(*) AS n FROM public.mcp_operation_keys k \
             JOIN public.mcp_services s USING (service_id) WHERE s.owner_tenant_id=$1::uuid"
        }
        Resource::Tools => {
            "SELECT count(*) AS n FROM public.mcp_tools WHERE tenant_id=$1::uuid AND NOT retired"
        }
        Resource::Toolkits => {
            "SELECT count(*) AS n FROM public.mcp_toolkits WHERE tenant_id=$1::uuid"
        }
    }
}

/// One resource's count, exactly as [`usage`] reads it.
pub async fn count_for(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    resource: Resource,
) -> Result<i64, BuilderStoreError> {
    let count: i64 = sqlx::query_scalar(AssertSqlSafe(count_statement(resource)))
        .bind(tenant.as_str())
        .fetch_one(&mut *conn)
        .await?;
    Ok(count)
}

/// The reference's `usage` (`builder.py:116-123`): current counts for the four quotas.
pub async fn usage(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
) -> Result<Usage, BuilderStoreError> {
    Ok(Usage {
        sources: count_for(&mut *conn, tenant, Resource::Sources).await?,
        operations: count_for(&mut *conn, tenant, Resource::Operations).await?,
        tools: count_for(&mut *conn, tenant, Resource::Tools).await?,
        toolkits: count_for(&mut *conn, tenant, Resource::Toolkits).await?,
    })
}

/// The reference's `enforce_quota` (`builder.py:126-134`): take the tenant lock, then refuse
/// when the resource already has `limit` rows. Call it inside the transaction that inserts the
/// new row (tools, toolkits; sources and operations are checked by their own functions).
pub async fn enforce_quota(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    resource: Resource,
    limit: i32,
) -> Result<(), BuilderStoreError> {
    lock_tenant(&mut *conn, tenant).await?;
    let count = count_for(&mut *conn, tenant, resource).await?;
    if count >= i64::from(limit) {
        return Err(BuilderStoreError::Quota(resource.as_str()));
    }
    Ok(())
}

/// The reference's `reference_rows` (`builder.py:137-138`): the JSON array of exact references.
fn reference_rows(references: &[ExactReference]) -> Value {
    Value::Array(
        references
            .iter()
            .map(|reference| {
                json!({
                    "id": reference.id.as_str(),
                    "version": reference.version.get(),
                })
            })
            .collect(),
    )
}

/// The reference's lifecycle kind for `mcp_builder_set_status` (`builder.py:194-206`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuilderKind {
    /// A service version.
    Service,
    /// An operation version.
    Operation,
}

impl BuilderKind {
    /// The value the function expects.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Service => "service",
            Self::Operation => "operation",
        }
    }
}

/// The execution and builder bounds one draft admission runs under: exactly the subset of the
/// reference `Settings` that `ExecutionService.submit_draft` and
/// `ExecutionRepository.accept_draft` read, plus the gateway application key they both use.
/// The phase-5B service builds it from `ExecutionSettings`, `WorkerSettings` and the builder's
/// own settings; keeping it explicit is what lets this storage call be tested without a
/// deployment.
#[derive(Debug, Clone)]
pub struct DraftRunSettings {
    /// `MCP_EXECUTION_ENABLED`: without it every draft admission is `Unavailable`.
    pub execution_enabled: bool,
    /// The reserved platform tenant that owns the first-party sources of licence references.
    pub platform_tenant_id: AuthorityId,
    /// `MCP_LICENSE_APP_KEY`, the gateway credential's application key; `"mcp"` when unset.
    pub license_app_key: Option<String>,
    /// `MCP_APPROVED_RUNNER_IMAGES`: the runner digests a `kata_python` draft may name.
    pub approved_runner_images: Vec<String>,
    /// `MCP_SYNC_WAIT_SECONDS`: how long the call polls the run before returning it queued.
    pub sync_wait: Duration,
    /// `MCP_QUEUE_GLOBAL_MAX`: runs queued across all tenants.
    pub queue_global_max: u64,
    /// `MCP_QUEUE_PER_TENANT_MAX`: runs queued for one tenant.
    pub queue_per_tenant_max: u64,
    /// `MCP_RUN_QUEUE_TIMEOUT_SECONDS`: the longest a run may wait to be claimed.
    pub run_queue_timeout: Duration,
    /// `MCP_RUN_MAX_SECONDS`: the wall-clock ceiling a tool's own limit is narrowed to.
    pub run_max: Duration,
    /// `MCP_MAX_API_CALLS_PER_RUN`: the call ceiling a tool's own limit is narrowed to.
    pub max_api_calls_per_run: u32,
    /// `MCP_BUILDER_TEST_RUNS_PER_HOUR`: draft runs one tenant may admit per hour.
    pub test_runs_per_hour: u64,
}

/// Why a draft run could not resolve a backend licence.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DraftLicenceError {
    /// The reference's `MinterUnavailableError`: the authority cannot answer. The reference's
    /// builder mount still renders it as a denial, never a retryable 5xx.
    #[error("licence authority unavailable")]
    Unavailable,
    /// The reference's `ExecutionDeniedError` from the minter: no licence for this tenant/app.
    #[error("licence denied")]
    Denied,
}

/// The backend-licence lookup a draft run needs for licence-kind platform services: the
/// reference's `Minter.licence_id(tenant, app, None)`.
///
/// The licence authority is an external boundary, so production passes the worker's [`Minter`]
/// and tests may stand in a deterministic lookup.
pub trait DraftLicenceLookup: Send + Sync {
    /// The tenant's licence identity for `app`.
    fn licence_id<'a>(
        &'a self,
        tenant: &'a AuthorityId,
        app: &'a str,
    ) -> BoxFuture<'a, Result<AuthorityId, DraftLicenceError>>;
}

impl DraftLicenceLookup for Minter {
    fn licence_id<'a>(
        &'a self,
        tenant: &'a AuthorityId,
        app: &'a str,
    ) -> BoxFuture<'a, Result<AuthorityId, DraftLicenceError>> {
        Box::pin(async move {
            let tenant = Rfc4122Uuid::parse(tenant.as_str()).ok_or(DraftLicenceError::Denied)?;
            let minted = Minter::licence_id(self, &tenant, app, None)
                .await
                .map_err(|error| match error {
                    CredentialError::Unavailable(_) => DraftLicenceError::Unavailable,
                    CredentialError::Denied(_) => DraftLicenceError::Denied,
                })?;
            AuthorityId::new(minted.to_string()).map_err(|_| DraftLicenceError::Denied)
        })
    }
}

/// The reference's `DRAFT_STATUSES`: the tool lifecycle states a test run may execute.
const DRAFT_STATUSES: [VersionStatus; 2] = [VersionStatus::Draft, VersionStatus::Published];

/// The reference's admission lock, shared with bound acceptance: one advisory transaction lock
/// serializes bounded admission across API replicas.
const DRAFT_ADMISSION_LOCK: i64 = 72_441_001;

/// The reference's per-run event bound (`mcp_run_events`, 256 rows).
const DRAFT_EVENT_LIMIT: i64 = 256;

/// The reference's `POLL_RETRIES`: consecutive failed reads tolerated while waiting.
const DRAFT_POLL_RETRIES: u32 = 3;

/// The gateway credential's service key in a credential profile.
const GATEWAY_SERVICE: &str = "gateway";

/// The reference's only accepted idempotency key shape (`[A-Za-z0-9_.:-]{1,128}`).
fn idempotency_key_valid(key: &str) -> bool {
    (1..=128).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

/// How an admission returned: a replayed prior run or a freshly queued one.
enum DraftAdmission {
    /// The reference's idempotent replay: the same tenant, tool version and key with the same
    /// input hash.
    Replay(RunRow),
    /// A newly queued run.
    Accepted(RunRow),
}

/// One `mcp_run_api_calls` row as the draft view projects it.
struct DraftCall {
    sequence: i32,
    operation_id: String,
    operation_version: i32,
    method: Option<String>,
    path: Option<String>,
    effect: String,
    status: String,
    http_status: Option<i32>,
    duration_ms: Option<i32>,
    reason: Option<String>,
    error_excerpt: Option<String>,
    started_at: DateTime<Utc>,
    finished_at: Option<DateTime<Utc>>,
}

impl DraftCall {
    /// The reference's row dict, with each instant in Python's `isoformat()` layout.
    fn as_json(&self) -> Value {
        json!({
            "sequence": self.sequence,
            "operation_id": self.operation_id,
            "operation_version": self.operation_version,
            "method": self.method,
            "path": self.path,
            "effect": self.effect,
            "status": self.status,
            "http_status": self.http_status,
            "duration_ms": self.duration_ms,
            "reason": self.reason,
            "error_excerpt": self.error_excerpt,
            "started_at": isoformat(self.started_at),
            "finished_at": self.finished_at.map(isoformat),
        })
    }
}

/// The reference's `draft_view`: the public envelope plus the call trace, and the last non-empty
/// redacted error excerpt of the trace.
fn draft_view(row: &RunRow, trace: &[DraftCall]) -> Value {
    let excerpt = trace.iter().rev().find_map(|call| {
        call.error_excerpt
            .as_deref()
            .filter(|text| !text.is_empty())
    });
    let calls: Vec<Value> = trace.iter().map(DraftCall::as_json).collect();
    json!({
        "run_id": row.run_id.to_string(),
        "status": row.status.as_str(),
        "result": row.result,
        "error": row.error,
        "payload_expired": row.payload_expired_at.is_some(),
        "mode": "draft",
        "trace": calls,
        "error_excerpt": excerpt,
    })
}

/// Python's `datetime.isoformat()` for an aware UTC instant: microseconds only when non-zero,
/// always the explicit `+00:00` offset.
fn isoformat(instant: DateTime<Utc>) -> String {
    let micros = instant.timestamp_subsec_micros();
    let seconds = instant.format("%Y-%m-%dT%H:%M:%S");
    if micros == 0 {
        format!("{seconds}+00:00")
    } else {
        format!("{seconds}.{micros:06}+00:00")
    }
}

/// Runtime-role access to the builder's services and operations, and the SQL half of the tool
/// lifecycle (`BuilderCatalogRepository`).
#[derive(Debug, Clone)]
pub struct BuilderCatalogRepository {
    pool: PgPool,
    catalog: CatalogRepository,
}

impl BuilderCatalogRepository {
    /// Bind the repository to the runtime pool.
    pub fn new(pool: PgPool) -> Self {
        let catalog = CatalogRepository::new(pool.clone());
        Self { pool, catalog }
    }

    // ── source → service agreement ──────────────────────────────────────────────────────────

    /// The reference's `create_service` (`builder.py:146-163`): version 1 of the service for a
    /// tenant source — adapter `source`, 1:1 with the source named by `destination_alias`.
    ///
    /// `CatalogNotFoundError` when the source is not an active own source, a conflict when it
    /// already has a service.
    pub async fn create_service(
        &self,
        tenant: &AuthorityId,
        manifest: &ServiceManifest,
        actor: &Attribution,
    ) -> Result<(), BuilderStoreError> {
        let manifest =
            serde_json::to_value(manifest).map_err(|_| BuilderStoreError::Corrupt("service"))?;
        let actor =
            serde_json::to_value(actor).map_err(|_| BuilderStoreError::Corrupt("service actor"))?;
        sqlx::query("SELECT public.mcp_builder_service_create($1::uuid,$2::jsonb,$3::jsonb)")
            .bind(tenant.as_str())
            .bind(manifest)
            .bind(actor)
            .execute(&self.pool)
            .await
            .map_err(|error| builder_error(error, "service"))?;
        Ok(())
    }

    /// The reference's `append_service` (`builder.py:165-189`): version n+1 of an own service
    /// (same key and source, `version` must be next, the identity at `expected_revision`).
    pub async fn append_service(
        &self,
        tenant: &AuthorityId,
        manifest: &ServiceManifest,
        actor: &Attribution,
        expected_revision: i64,
    ) -> Result<(), BuilderStoreError> {
        let manifest =
            serde_json::to_value(manifest).map_err(|_| BuilderStoreError::Corrupt("service"))?;
        let actor =
            serde_json::to_value(actor).map_err(|_| BuilderStoreError::Corrupt("service actor"))?;
        sqlx::query("SELECT public.mcp_builder_service_append($1::uuid,$2::jsonb,$3,$4::jsonb)")
            .bind(tenant.as_str())
            .bind(manifest)
            .bind(expected_revision)
            .bind(actor)
            .execute(&self.pool)
            .await
            .map_err(|error| builder_error(error, "service"))?;
        Ok(())
    }

    /// The reference's `service_for_source` (`builder.py:216-241`): the tenant's service for
    /// `source_key` (newest version), or `None`.
    pub async fn service_for_source(
        &self,
        tenant: &AuthorityId,
        source_key: &str,
    ) -> Result<Option<ServiceRecord>, BuilderStoreError> {
        let row = sqlx::query(
            "SELECT s.service_id::text AS service_id,s.service_key,s.revision,v.version,v.status,\
             v.manifest FROM public.mcp_services s \
             JOIN public.mcp_service_versions v1 ON v1.service_id=s.service_id AND v1.version=1 \
             JOIN LATERAL (SELECT * FROM public.mcp_service_versions x \
               WHERE x.service_id=s.service_id ORDER BY x.version DESC LIMIT 1) v ON true \
             WHERE s.owner_tenant_id=$1::uuid AND v1.manifest->>'destination_alias'=$2",
        )
        .bind(tenant.as_str())
        .bind(source_key)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(decode_service).transpose()
    }

    // ── operations ─────────────────────────────────────────────────────────────────────────

    /// The reference's `create_operation` (`builder.py:169-176`): a draft operation version.
    ///
    /// `op_key` is required for version 1 (it names the operation for ever) and optional
    /// afterwards; `manifest.version` must be the next one. `Quota(Operations)` when the tenant
    /// already has `max_operations` keyed operations.
    pub async fn create_operation(
        &self,
        tenant: &AuthorityId,
        manifest: &OperationManifest,
        actor: &Attribution,
        op_key: Option<&str>,
        max_operations: i32,
    ) -> Result<(), BuilderStoreError> {
        let manifest =
            serde_json::to_value(manifest).map_err(|_| BuilderStoreError::Corrupt("operation"))?;
        let actor = serde_json::to_value(actor)
            .map_err(|_| BuilderStoreError::Corrupt("operation actor"))?;
        sqlx::query(
            "SELECT public.mcp_builder_operation_create($1::uuid,$2::jsonb,$3,$4::jsonb,$5)",
        )
        .bind(tenant.as_str())
        .bind(manifest)
        .bind(op_key)
        .bind(actor)
        .bind(max_operations)
        .execute(&self.pool)
        .await
        .map_err(|error| builder_error(error, "operation"))?;
        Ok(())
    }

    /// The reference's `operations` (`builder.py:243-263`): keyed operations (newest version
    /// each) of the tenant's service for `source_key`, ordered by key. Empty when the source has
    /// no service yet.
    pub async fn operations(
        &self,
        tenant: &AuthorityId,
        source_key: &str,
    ) -> Result<Vec<OperationRecord>, BuilderStoreError> {
        let Some(service) = self.service_for_source(tenant, source_key).await? else {
            return Ok(Vec::new());
        };
        let statement = format!(
            "{OPERATION_SELECT}WHERE s.owner_tenant_id=$1::uuid AND k.service_id=$2::uuid \
             ORDER BY k.op_key"
        );
        let rows = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(service.service_id.as_str())
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(decode_operation).collect()
    }

    /// The reference's `operation_by_key` (`builder.py:265-279`): resolve `(source_key,
    /// op_key)` to the newest version of an own operation, or `None`.
    pub async fn operation_by_key(
        &self,
        tenant: &AuthorityId,
        source_key: &str,
        op_key: &str,
    ) -> Result<Option<OperationRecord>, BuilderStoreError> {
        let Some(service) = self.service_for_source(tenant, source_key).await? else {
            return Ok(None);
        };
        let statement = format!(
            "{OPERATION_SELECT}WHERE s.owner_tenant_id=$1::uuid AND k.service_id=$2::uuid \
             AND k.op_key=$3"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(service.service_id.as_str())
            .bind(op_key)
            .fetch_optional(&self.pool)
            .await?;
        row.as_ref().map(decode_operation).transpose()
    }

    /// The reference service's `operation_list` (`service.py:378-381`): the source must exist,
    /// then every keyed operation of its service is listed.
    pub async fn operation_list(
        &self,
        tenant: &AuthorityId,
        source_key: &str,
    ) -> Result<Vec<OperationRecord>, BuilderStoreError> {
        let exists: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM public.mcp_sources \
             WHERE owner_tenant_id=$1::uuid AND source_key=$2",
        )
        .bind(tenant.as_str())
        .bind(source_key)
        .fetch_optional(&self.pool)
        .await?;
        if exists.is_none() {
            return Err(BuilderStoreError::NotFound("source not found".to_owned()));
        }
        self.operations(tenant, source_key).await
    }

    /// The reference service's `operation_update` (`service.py:383-408`): a new draft version
    /// from the newest one, with the patch's present fields replaced.
    ///
    /// The record's version is the optimistic lock: a stale `expected_version` is
    /// `Conflict("the operation changed; re-read it")`.
    pub async fn operation_update(
        &self,
        tenant: &AuthorityId,
        source_key: &str,
        op_key: &str,
        patch: &OperationPatch,
        actor: &Attribution,
        max_operations: i32,
    ) -> Result<OperationRecord, BuilderStoreError> {
        let record = self
            .operation_by_key(tenant, source_key, op_key)
            .await?
            .ok_or_else(|| BuilderStoreError::NotFound("operation not found".to_owned()))?;
        if record.version != patch.expected_version {
            return Err(BuilderStoreError::Conflict(
                "the operation changed; re-read it".to_owned(),
            ));
        }
        let mut data = serde_json::to_value(&record.manifest)
            .map_err(|_| BuilderStoreError::Corrupt("operation manifest"))?;
        {
            let object = data
                .as_object_mut()
                .ok_or(BuilderStoreError::Corrupt("operation manifest"))?;
            object.insert("version".to_owned(), json!(record.version.get() + 1));
            insert_some(object, "effect", &patch.effect)?;
            insert_some(
                object,
                "expected_error_statuses",
                &patch.expected_error_statuses,
            )?;
            insert_some(object, "response_projection", &patch.response_projection)?;
            insert_some(object, "redact_fields", &patch.redact_fields)?;
            insert_some(object, "timeout_seconds", &patch.timeout_seconds)?;
            insert_some(object, "max_retries", &patch.max_retries)?;
            insert_some(object, "idempotency", &patch.idempotency)?;
            insert_some(object, "empty_response", &patch.empty_response)?;
        }
        let manifest: OperationManifest = serde_json::from_value(data).map_err(|error| {
            BuilderStoreError::Invalid(format!("invalid operation manifest: {error}"))
        })?;
        self.create_operation(tenant, &manifest, actor, None, max_operations)
            .await?;
        self.operation_by_key(tenant, source_key, op_key)
            .await?
            .ok_or(BuilderStoreError::Corrupt("operation record"))
    }

    // ── platform operations ─────────────────────────────────────────────────────────────────

    /// The reference's `visible_platform_services` (`builder.py:281-299`): platform services
    /// (newest published version) a tenant tool may reference, with how each is shared.
    pub async fn visible_platform_services(
        &self,
        tenant: &AuthorityId,
    ) -> Result<Vec<VisibleService>, BuilderStoreError> {
        let rows = sqlx::query(
            "SELECT s.service_id::text AS service_id,s.service_key,v.version,\
             CASE WHEN EXISTS (SELECT 1 FROM public.mcp_service_grants g \
               WHERE g.service_id=s.service_id AND g.grantee_tenant_id=$1::uuid) \
             THEN 'grant' ELSE 'licence' END AS via \
             FROM public.mcp_services s \
             JOIN LATERAL (SELECT version FROM public.mcp_service_versions x \
               WHERE x.service_id=s.service_id AND x.status='published' \
               ORDER BY x.version DESC LIMIT 1) v ON true \
             WHERE s.owner_tenant_id=public.mcp_platform_tenant() \
             AND public.mcp_tenant_may_use_service($1::uuid,s.service_id,v.version) \
             ORDER BY s.service_key",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await?;
        rows.iter().map(decode_visible_service).collect()
    }

    /// The reference service's `platform_operation` (`service.py:412-432`): the newest published
    /// version of a platform operation the tenant may use.
    pub async fn platform_operation(
        &self,
        tenant: &AuthorityId,
        service: &str,
        op_key: &str,
    ) -> Result<ExactReference, BuilderStoreError> {
        let visible = self.visible_platform_services(tenant).await?;
        let Some(shared) = visible
            .iter()
            .find(|entry| entry.service_key.as_str() == service)
        else {
            return Err(BuilderStoreError::NotFound(format!(
                "platform service '{service}' is not shared with you"
            )));
        };
        let row = sqlx::query(
            "SELECT k.operation_id::text AS operation_id,o.version \
             FROM public.mcp_operation_keys k \
             JOIN LATERAL (SELECT version FROM public.mcp_operation_versions v \
               WHERE v.operation_id=k.operation_id AND v.status='published' \
               ORDER BY v.version DESC LIMIT 1) o ON true \
             WHERE k.service_id=$1::uuid AND k.op_key=$2",
        )
        .bind(shared.service_id.as_str())
        .bind(op_key)
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Err(BuilderStoreError::NotFound(format!(
                "operation {service}.{op_key} is not available"
            )));
        };
        let identity: String = row.try_get("operation_id")?;
        Ok(ExactReference {
            id: identity7(identity)?,
            version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        })
    }

    /// The reference service's `resolve_operations` (`service.py:434-453`): every named
    /// operation as the exact version a new tool pins, keyed by its script key.
    pub async fn resolve_operations(
        &self,
        tenant: &AuthorityId,
        operations: &[ToolOperation],
    ) -> Result<BTreeMap<String, ExactReference>, BuilderStoreError> {
        let mut references = BTreeMap::new();
        for item in operations {
            let reference = match &item.source_key {
                Some(source_key) => {
                    let record = self
                        .operation_by_key(tenant, source_key.as_str(), item.op_key.as_str())
                        .await?
                        .ok_or_else(|| {
                            BuilderStoreError::NotFound(format!(
                                "operation {} is not imported; import it first",
                                item.script_key()
                            ))
                        })?;
                    ExactReference {
                        id: record.operation_id,
                        version: record.version,
                    }
                }
                None => {
                    let Some(service) = &item.service else {
                        return Err(BuilderStoreError::Invalid(
                            "name exactly one of source_key or service".to_owned(),
                        ));
                    };
                    self.platform_operation(tenant, service.as_str(), item.op_key.as_str())
                        .await?
                }
            };
            references.insert(item.script_key(), reference);
        }
        Ok(references)
    }

    /// The reference service's `repin` (`service.py:548-560`): the newest version of every
    /// operation in a stored package's `ops.py` table.
    pub async fn repin(
        &self,
        tenant: &AuthorityId,
        files: &[PackageFile],
    ) -> Result<BTreeMap<String, ExactReference>, BuilderStoreError> {
        let table = packaging::parse_ops(files)
            .map_err(|error| BuilderStoreError::Invalid(error.to_string()))?;
        let mut references = BTreeMap::new();
        for (script_key, (operation_id, _version)) in table {
            let (origin, op_key) = match script_key.split_once('.') {
                Some((origin, op_key)) => (origin, op_key),
                None => (script_key.as_str(), ""),
            };
            let reference = match self.operation_by_key(tenant, origin, op_key).await? {
                Some(record) if record.operation_id == operation_id => ExactReference {
                    id: record.operation_id,
                    version: record.version,
                },
                _ => self.platform_operation(tenant, origin, op_key).await?,
            };
            references.insert(script_key, reference);
        }
        Ok(references)
    }

    // ── service/operation publication ──────────────────────────────────────────────────────

    /// The reference's `publish` (`builder.py:191-206`): publish own service versions, then
    /// operation versions (idempotent for published ones).
    ///
    /// Pass the caller's transaction through [`BuilderCatalogRepository::publish_tool`] to
    /// publish a tool and its dependencies atomically; this method cannot share a caller's
    /// transaction because the Rust catalog repository owns its own.
    pub async fn publish(
        &self,
        tenant: &AuthorityId,
        actor: &Attribution,
        services: &[ExactReference],
        operations: &[ExactReference],
    ) -> Result<(), BuilderStoreError> {
        let actor =
            serde_json::to_value(actor).map_err(|_| BuilderStoreError::Corrupt("publication"))?;
        sqlx::query("SELECT public.mcp_builder_publish($1::uuid,$2::jsonb,$3::jsonb,$4::jsonb)")
            .bind(tenant.as_str())
            .bind(reference_rows(services))
            .bind(reference_rows(operations))
            .bind(actor)
            .execute(&self.pool)
            .await
            .map_err(|error| builder_error(error, "publication"))?;
        Ok(())
    }

    /// The reference's `set_status` (`builder.py:208-222`): one service or operation version's
    /// lifecycle state.
    pub async fn set_status(
        &self,
        tenant: &AuthorityId,
        kind: BuilderKind,
        reference: &ExactReference,
        status: VersionStatus,
        actor: &Attribution,
    ) -> Result<(), BuilderStoreError> {
        let actor = serde_json::to_value(actor)
            .map_err(|_| BuilderStoreError::Corrupt("publication actor"))?;
        sqlx::query("SELECT public.mcp_builder_set_status($1::uuid,$2,$3::uuid,$4,$5,$6::jsonb)")
            .bind(tenant.as_str())
            .bind(kind.as_str())
            .bind(reference.id.as_str())
            .bind(version_bits(reference.version))
            .bind(status_text(status))
            .bind(actor)
            .execute(&self.pool)
            .await
            .map_err(|error| builder_error(error, kind.as_str()))?;
        Ok(())
    }

    /// The reference's `usage` (`builder.py:301-303`).
    pub async fn usage(&self, tenant: &AuthorityId) -> Result<Usage, BuilderStoreError> {
        let mut conn = self.pool.acquire().await?;
        usage(&mut conn, tenant).await
    }

    // ── tool lifecycle ─────────────────────────────────────────────────────────────────────

    /// The reference service's `tool_create` (`service.py:470-499`): the tool identity, its
    /// first version and its package in one transaction, under the tenant advisory lock.
    ///
    /// The quota is counted under `pg_advisory_xact_lock(hashtext('builder:<tenant>'))` in the
    /// same transaction that inserts the identity, so two concurrent creates cannot both pass.
    pub async fn create_tool(
        &self,
        tenant: &AuthorityId,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
        max_tools: i32,
    ) -> Result<VersionDescriptor, BuilderStoreError> {
        if manifest.tenant_id != *tenant || manifest.version.get() != 1 {
            return Err(BuilderStoreError::Conflict(
                "identity ownership or first version mismatch".to_owned(),
            ));
        }
        let mut tx = self.pool.begin().await?;
        if let Err(error) = enforce_quota(&mut tx, tenant, Resource::Tools, max_tools).await {
            return Err(refusing(tx, error).await);
        }
        let created = sqlx::query(
            "INSERT INTO public.mcp_tools(tenant_id,tool_id,public_name,created_by) \
             VALUES ($1::uuid,$2::uuid,$3,$4)",
        )
        .bind(tenant.as_str())
        .bind(manifest.tool_id.as_str())
        .bind(manifest.public_name.as_str())
        .bind(serde_json::to_value(actor).map_err(|_| BuilderStoreError::Corrupt("tool actor"))?)
        .execute(&mut *tx)
        .await;
        if let Err(error) = created {
            return Err(refusing(tx, tool_unique(error)).await);
        }
        if let Err(error) = Self::insert_tool_version(&mut tx, manifest, files, actor).await {
            return Err(refusing(tx, error).await);
        }
        let result =
            match Self::tool_version_on(&mut tx, tenant, &manifest.tool_id, manifest.version).await
            {
                Ok(result) => result,
                Err(error) => return Err(refusing(tx, error).await),
            };
        if let Err(error) = Self::audit_tool(&mut tx, &result, actor, "tool.created").await {
            return Err(refusing(tx, error).await);
        }
        tx.commit().await?;
        Ok(result)
    }

    /// The reference service's `tool_update` append (`service.py:501-546` via
    /// `catalog.append_draft`): the next version of an owned tool under the identity's row lock.
    pub async fn append_tool(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
        expected_revision: PositiveVersion,
    ) -> Result<VersionDescriptor, BuilderStoreError> {
        let request = AppendRequest {
            tenant_id: tenant,
            tool_id,
            content: manifest,
            files,
            actor,
            expected_revision: Some(expected_revision),
            exact_version: true,
        };
        self.catalog
            .append(&request, None)
            .await
            .map_err(Into::into)
    }

    /// The reference service's `tool_get` (`service.py:562-571`): one version with its package,
    /// or the newest one when `version` is omitted.
    pub async fn tool_get(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        version: Option<PositiveVersion>,
    ) -> Result<(VersionDescriptor, Vec<PackageFile>), BuilderStoreError> {
        let version = match version {
            Some(version) => version,
            None => {
                self.catalog
                    .latest_version(tenant, tool_id)
                    .await?
                    .ok_or_else(|| BuilderStoreError::NotFound("tool not found".to_owned()))?
                    .version
            }
        };
        let descriptor = self.catalog.get_version(tenant, tool_id, version).await?;
        let files = self.catalog.files(tenant, tool_id, version).await?;
        Ok((descriptor, files))
    }

    /// The reference service's `tool_list` (`service.py:573-575`).
    pub async fn tool_list(
        &self,
        tenant: &AuthorityId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ToolDefinition>, BuilderStoreError> {
        self.catalog
            .definitions(tenant, limit, offset)
            .await
            .map_err(Into::into)
    }

    /// The reference service's `tool_publish` (`service.py:630-656`): publish a tool version
    /// together with the draft service and operation versions it pins, in ONE transaction.
    ///
    /// All of it or none: a failing tool transition (stale revision, lifecycle, a dependency
    /// that is still not published) rolls the service/operation publication back with it.
    pub async fn publish_tool(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
        actor: &Attribution,
        expected_revision: PositiveVersion,
    ) -> Result<VersionDescriptor, BuilderStoreError> {
        // The reference reads the descriptor and its own dependencies before the transaction.
        let descriptor = self.catalog.get_version(tenant, tool_id, version).await?;
        let (services, operations) = self.own_dependencies(tenant, &descriptor.manifest).await?;
        let actor_json = serde_json::to_value(actor)
            .map_err(|_| BuilderStoreError::Corrupt("publication actor"))?;
        let mut tx = self.pool.begin().await?;
        if !services.is_empty() || !operations.is_empty() {
            let published = sqlx::query(
                "SELECT public.mcp_builder_publish($1::uuid,$2::jsonb,$3::jsonb,$4::jsonb)",
            )
            .bind(tenant.as_str())
            .bind(reference_rows(&services))
            .bind(reference_rows(&operations))
            .bind(&actor_json)
            .execute(&mut *tx)
            .await;
            if let Err(error) = published {
                return Err(refusing(tx, builder_error(error, "publication")).await);
            }
        }
        let parent = match Self::lock_tool(&mut tx, tenant, tool_id, Some(expected_revision)).await
        {
            Ok(parent) => parent,
            Err(error) => return Err(refusing(tx, error).await),
        };
        let current = match Self::tool_version_on(&mut tx, tenant, tool_id, version).await {
            Ok(current) => current,
            Err(error) => return Err(refusing(tx, error).await),
        };
        if parent.retired {
            return Err(refusing(
                tx,
                BuilderStoreError::Conflict("identity retired".to_owned()),
            )
            .await);
        }
        if !tool_transition_allowed(current.status, VersionStatus::Published) {
            return Err(refusing(
                tx,
                BuilderStoreError::Conflict("invalid lifecycle transition".to_owned()),
            )
            .await);
        }
        let dependencies = match sqlx::query(
            "SELECT o.status AS operation_status, s.status AS service_status \
             FROM public.mcp_tool_version_operations r \
             JOIN public.mcp_operation_versions o \
               ON (o.operation_id,o.version)=(r.operation_id,r.operation_version) \
             JOIN public.mcp_service_versions s \
               ON (s.service_id,s.version)=(o.service_id,o.service_version) \
             WHERE r.tenant_id = $1::uuid AND r.tool_id = $2::uuid AND r.version = $3",
        )
        .bind(tenant.as_str())
        .bind(tool_id.as_str())
        .bind(version_bits(version))
        .fetch_all(&mut *tx)
        .await
        {
            Ok(dependencies) => dependencies,
            Err(error) => return Err(refusing(tx, BuilderStoreError::Database(error)).await),
        };
        let mut unavailable = false;
        for dependency in &dependencies {
            let operation_status: String =
                dependency.try_get("operation_status").unwrap_or_default();
            let service_status: String = dependency.try_get("service_status").unwrap_or_default();
            if operation_status != "published" || service_status != "published" {
                unavailable = true;
            }
        }
        if unavailable {
            return Err(refusing(
                tx,
                BuilderStoreError::Conflict("operation or service is not published".to_owned()),
            )
            .await);
        }
        let moved = async {
            sqlx::query(
                "UPDATE public.mcp_tool_versions SET status='published',updated_by=$1,\
                 updated_at=clock_timestamp() \
                 WHERE tenant_id = $2::uuid AND tool_id = $3::uuid AND version = $4",
            )
            .bind(&actor_json)
            .bind(tenant.as_str())
            .bind(tool_id.as_str())
            .bind(version_bits(version))
            .execute(&mut *tx)
            .await?;
            sqlx::query(
                "UPDATE public.mcp_tools SET revision=revision+1 \
                 WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
            )
            .bind(tenant.as_str())
            .bind(tool_id.as_str())
            .execute(&mut *tx)
            .await?;
            Ok::<(), sqlx::Error>(())
        }
        .await;
        if let Err(error) = moved {
            return Err(refusing(tx, BuilderStoreError::Database(error)).await);
        }
        let result = match Self::tool_version_on(&mut tx, tenant, tool_id, version).await {
            Ok(result) => result,
            Err(error) => return Err(refusing(tx, error).await),
        };
        if let Err(error) = Self::audit_tool(&mut tx, &result, actor, "tool.published").await {
            return Err(refusing(tx, error).await);
        }
        tx.commit().await?;
        Ok(result)
    }

    /// The reference service's `tool_set_status` (`service.py:658-664`): the catalog lifecycle
    /// transition, unchanged.
    pub async fn set_tool_status(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
        status: VersionStatus,
        actor: &Attribution,
        expected_revision: PositiveVersion,
    ) -> Result<VersionDescriptor, BuilderStoreError> {
        self.catalog
            .transition(tenant, tool_id, version, status, actor, expected_revision)
            .await
            .map_err(Into::into)
    }

    /// The reference service's `own_dependencies` (`service.py:611-628`): the tenant-owned
    /// service and operation versions a tool pins that are not yet published (platform
    /// operations are the platform's to publish).
    async fn own_dependencies(
        &self,
        tenant: &AuthorityId,
        manifest: &ToolManifest,
    ) -> Result<(Vec<ExactReference>, Vec<ExactReference>), BuilderStoreError> {
        let mut services: BTreeMap<String, ExactReference> = BTreeMap::new();
        let mut operations = Vec::new();
        for reference in &manifest.allowed_operations {
            let (operation, state) = self.catalog.operation(reference).await?;
            if self.catalog.service_owner(&operation.service.id).await? != *tenant {
                continue;
            }
            let (_service, service_state) = self.catalog.service(&operation.service).await?;
            if service_state != VersionStatus::Published {
                services
                    .entry(format!(
                        "{}:{}",
                        operation.service.id.as_str(),
                        operation.service.version.get()
                    ))
                    .or_insert_with(|| operation.service.clone());
            }
            if state != VersionStatus::Published {
                operations.push(reference.clone());
            }
        }
        Ok((services.into_values().collect(), operations))
    }

    // ── toolkit write/publish ─────────────────────────────────────────────────────────────

    /// The reference service's `toolkit_create` write (`service.py:680-715` via
    /// `AccessService.write_toolkit`): a draft toolkit version inside one transaction.
    ///
    /// A new identity (`expected` is `None`) counts the toolkit quota under the tenant lock;
    /// an append takes the identity's row lock and advances its revision.
    pub async fn write_toolkit(
        &self,
        resolver: &SelectionResolver,
        tenant: &AuthorityId,
        actor: &Attribution,
        manifest: &crate::catalog::toolkit_models::ToolkitManifest,
        expected: Option<PositiveVersion>,
        max_toolkits: Option<i32>,
    ) -> Result<ToolkitDescriptor, BuilderStoreError> {
        let mut tx = self.pool.begin().await?;
        if expected.is_none()
            && let Some(limit) = max_toolkits
            && let Err(error) = enforce_quota(&mut tx, tenant, Resource::Toolkits, limit).await
        {
            return Err(refusing(tx, error).await);
        }
        let result = match toolkit_write(&mut tx, resolver, tenant, actor, manifest, expected).await
        {
            Ok(result) => result,
            Err(error) => return Err(refusing(tx, error.into()).await),
        };
        tx.commit().await?;
        Ok(result)
    }

    /// The reference service's `toolkit_publish` transition (`service.py:717-736` via
    /// `AccessService.transition_toolkit`): publish a toolkit version.
    ///
    /// The re-bind that follows a successful publication is the bindings-ensure service's, not
    /// builder storage, and is not called here.
    pub async fn publish_toolkit(
        &self,
        resolver: &SelectionResolver,
        tenant: &AuthorityId,
        actor: &Attribution,
        toolkit_id: &Uuid7,
        version: PositiveVersion,
        expected: PositiveVersion,
    ) -> Result<ToolkitDescriptor, BuilderStoreError> {
        let mut tx = self.pool.begin().await?;
        let result = match toolkit_transition(
            &mut tx,
            resolver,
            tenant,
            actor,
            toolkit_id,
            version,
            VersionStatus::Published,
            expected,
        )
        .await
        {
            Ok(result) => result,
            Err(error) => return Err(refusing(tx, error.into()).await),
        };
        tx.commit().await?;
        Ok(result)
    }

    // ── draft test runs ───────────────────────────────────────────────────────────────────

    /// The reference's `ExecutionService.submit_draft`: run the author's own draft or published
    /// tool version without a binding, and return its draft view.
    ///
    /// The order is the reference's, whole: the execution switch, the idempotency key, the
    /// catalog generation, the tool version (owned, runnable, not retired, an approved runner
    /// image for `kata_python`), every dependency the tool pins (usable by THIS tenant now),
    /// the write confirmation, the input schema, the ephemeral credential profile (the caller's
    /// proven `license_id` as gateway plus, for licence-kind platform services, the minter's
    /// licence for that service), the narrowed limits and the draft authority snapshot. Only
    /// then is the run admitted: under the shared admission lock, with a last generation check,
    /// the idempotency replay, the hourly test-run quota and the queue bounds — the reference's
    /// `accept_draft`. The returned view carries the upstream call trace of the run.
    #[allow(clippy::too_many_arguments)]
    pub async fn submit_draft(
        &self,
        author_tenant: &AuthorityId,
        license_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
        inputs: &Value,
        confirm_writes: bool,
        idempotency_key: Option<&str>,
        settings: &DraftRunSettings,
        minter: Option<&dyn DraftLicenceLookup>,
    ) -> Result<Value, BuilderStoreError> {
        if !settings.execution_enabled {
            return Err(BuilderStoreError::Unavailable(
                "test runs are not available: execution is disabled",
            ));
        }
        if let Some(key) = idempotency_key
            && !idempotency_key_valid(key)
        {
            return Err(BuilderStoreError::Invalid(
                "invalid idempotency key".to_owned(),
            ));
        }
        // Every read below belongs to one catalog state; acceptance re-locks the generation.
        let before = self.catalog_generation().await?;
        let descriptor = self
            .catalog
            .get_version(author_tenant, tool_id, version)
            .await?;
        let manifest = descriptor.manifest;
        if !DRAFT_STATUSES.contains(&descriptor.status)
            || self.retired(author_tenant, tool_id).await?
        {
            return Err(BuilderStoreError::Conflict(
                "tool version is not runnable".to_owned(),
            ));
        }
        if manifest.runtime == Runtime::KataPython
            && !manifest.runner_image_digest.as_ref().is_some_and(|digest| {
                settings
                    .approved_runner_images
                    .iter()
                    .any(|approved| approved == digest.as_str())
            })
        {
            return Err(BuilderStoreError::Conflict(
                "tool runner image is not approved".to_owned(),
            ));
        }
        let (services, writes) = self.draft_dependencies(author_tenant, &manifest).await?;
        if (manifest.effect == Effect::Writes || writes) && !confirm_writes {
            return Err(BuilderStoreError::Invalid(
                "this tool writes; confirm_writes is required".to_owned(),
            ));
        }
        let schema = Value::Object(manifest.input_schema.clone());
        validate_instance(&schema, inputs, &SchemaLimits::default())
            .map_err(|_| BuilderStoreError::Invalid("invalid input arguments".to_owned()))?;
        let app_key =
            AppKey::new(settings.license_app_key.as_deref().unwrap_or("mcp")).map_err(|_| {
                BuilderStoreError::Invalid("invalid gateway application key".to_owned())
            })?;
        let profile = CredentialProfile {
            schema_version: 1,
            profile_id: crate::storage::bindings::fresh_identity(),
            tenant_id: author_tenant.clone(),
            name: Name::new("draft_run")
                .map_err(|_| BuilderStoreError::Corrupt("draft profile name"))?,
            gateway: CredentialReference {
                service: Name::new(GATEWAY_SERVICE)
                    .map_err(|_| BuilderStoreError::Corrupt("gateway service"))?,
                alias: Name::new(GATEWAY_SERVICE)
                    .map_err(|_| BuilderStoreError::Corrupt("gateway service"))?,
                license_id: license_id.clone(),
                app_key,
                bundle: None,
            },
            services: self
                .licence_references(author_tenant, &services, settings, minter)
                .await?,
        };
        // The reference's ceiling: the deployment's bounds, then the manifest narrows them.
        let ceiling = ToolLimits {
            wall_seconds: u32::try_from(settings.run_max.as_secs())
                .unwrap_or(u32::MAX)
                .min(300),
            queue_seconds: u32::try_from(settings.run_queue_timeout.as_secs())
                .unwrap_or(u32::MAX)
                .min(600),
            api_calls: settings.max_api_calls_per_run,
            ..ToolLimits::default()
        };
        let resolved = ResolvedTool {
            effective: EffectiveTool {
                tool: ToolReference {
                    id: tool_id.clone(),
                    version,
                    tenant_id: author_tenant.clone(),
                },
                operation_constraints: Vec::new(),
                limits: narrow_limits(manifest.limits, ceiling),
                public_name: manifest.public_name.clone(),
            },
            context: BoundContext {
                tenant_id: author_tenant.clone(),
                project_id: None,
                workspace_id: None,
                project_phase: None,
                work_type: None,
                card_stage: None,
                responsibility: None,
                test_command: None,
                reviewed_commit: None,
            },
            manifest,
        };
        let digest = value_hash(inputs);
        let authority =
            authority_snapshot(&resolved).map_err(|_| BuilderStoreError::Corrupt("authority"))?;
        let profile_snapshot =
            serde_json::to_value(&profile).map_err(|_| BuilderStoreError::Corrupt("profile"))?;
        let created_by = json!({
            "subject": format!("tenant:{}", author_tenant.as_str()),
            "license_id": license_id.as_str(),
        });
        let run = match self
            .admit_draft(
                author_tenant,
                license_id,
                &profile_snapshot,
                &resolved,
                &authority,
                inputs,
                &digest,
                idempotency_key,
                &created_by,
                before,
                settings,
            )
            .await?
        {
            DraftAdmission::Replay(run) | DraftAdmission::Accepted(run) => run,
        };
        self.draft_result(author_tenant, run, settings).await
    }

    /// The reference's `ExecutionService.draft_run`, the read behind
    /// `GET /mcp/builder/runs/{run_id}`: the author's test run, with its call trace.
    ///
    /// Another tenant's run, an absent run and a bound run are all the same not-found refusal.
    pub async fn draft_run(
        &self,
        author_tenant: &AuthorityId,
        run_id: &Uuid7,
    ) -> Result<Value, BuilderStoreError> {
        let row = self.draft_row(author_tenant, run_id.as_str()).await?;
        let trace = self.trace(author_tenant, run_id.as_str()).await?;
        Ok(draft_view(&row, &trace))
    }

    /// The reference's `CatalogRepository.generation`: the catalog's monotonic generation.
    async fn catalog_generation(&self) -> Result<i64, BuilderStoreError> {
        let generation: Option<i64> =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_optional(&self.pool)
                .await?;
        generation.ok_or(BuilderStoreError::Corrupt("catalog generation row"))
    }

    /// The reference's `_retired`: an absent identity counts as retired.
    async fn retired(
        &self,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
    ) -> Result<bool, BuilderStoreError> {
        let retired: Option<bool> = sqlx::query_scalar(
            "SELECT retired FROM public.mcp_tools WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
        )
        .bind(tenant.as_str())
        .bind(tool_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        Ok(retired.unwrap_or(true))
    }

    /// The reference's `_draft_dependencies`: every operation and service the tool names must be
    /// usable by THIS tenant now — its own draft or published ones, or published platform
    /// services it may use. Returns the services (first-occurrence order) and whether any
    /// operation writes.
    async fn draft_dependencies(
        &self,
        tenant: &AuthorityId,
        manifest: &ToolManifest,
    ) -> Result<(Vec<(Name, ServiceManifest)>, bool), BuilderStoreError> {
        let mut services: Vec<(Name, ServiceManifest)> = Vec::new();
        let mut writes = false;
        for reference in &manifest.allowed_operations {
            let (operation, operation_status) = self.catalog.operation(reference).await?;
            let (service, service_status) = self.catalog.service(&operation.service).await?;
            let owner = self.catalog.service_owner(&operation.service.id).await?;
            let allowed = if owner != *tenant {
                operation_status == VersionStatus::Published
                    && service_status == VersionStatus::Published
            } else {
                DRAFT_STATUSES.contains(&operation_status)
                    && DRAFT_STATUSES.contains(&service_status)
            };
            if !allowed
                || !self
                    .catalog
                    .may_use_service(tenant, &operation.service)
                    .await?
            {
                return Err(BuilderStoreError::Conflict(
                    "tool depends on an unavailable operation or service".to_owned(),
                ));
            }
            writes = writes || operation.effect == Effect::Writes;
            // The reference's dict: a later version of the same service key replaces the value
            // at its first position.
            let position = services
                .iter()
                .position(|(key, _)| *key == service.service_key);
            match position {
                Some(index) => services[index].1 = service,
                None => services.push((service.service_key.clone(), service)),
            }
        }
        Ok((services, writes))
    }

    /// The reference's `_licence_references`: minted licence references for platform services
    /// whose platform source is licence kind. A missing minter or application key, and any
    /// minter refusal, is the reference's `ExecutionDeniedError`.
    async fn licence_references(
        &self,
        tenant: &AuthorityId,
        services: &[(Name, ServiceManifest)],
        settings: &DraftRunSettings,
        minter: Option<&dyn DraftLicenceLookup>,
    ) -> Result<Vec<CredentialReference>, BuilderStoreError> {
        let mut references = Vec::new();
        for (service_key, service) in services {
            if service.auth_adapter == AuthAdapter::Source {
                continue;
            }
            // A stored token has no tenant licence to verify.
            let kind: Option<String> = sqlx::query_scalar(
                "SELECT auth->>'kind' FROM public.mcp_sources \
                 WHERE owner_tenant_id = $1::uuid AND source_key = $2",
            )
            .bind(settings.platform_tenant_id.as_str())
            .bind(service.destination_alias.as_str())
            .fetch_optional(&self.pool)
            .await?;
            if kind.as_deref() != Some("licence") {
                continue;
            }
            let Some(app_key) = service.license_app_key.clone() else {
                return Err(BuilderStoreError::Forbidden("execution denied".to_owned()));
            };
            let Some(minter) = minter else {
                return Err(BuilderStoreError::Forbidden("execution denied".to_owned()));
            };
            let licence = minter
                .licence_id(tenant, app_key.as_str())
                .await
                .map_err(|_| BuilderStoreError::Forbidden("execution denied".to_owned()))?;
            references.push(CredentialReference {
                service: service_key.clone(),
                alias: service_key.clone(),
                license_id: licence,
                app_key,
                bundle: None,
            });
        }
        Ok(references)
    }

    /// The reference's `accept_draft`: one bounded admission transaction under the shared
    /// admission lock, serialized with bound acceptance so the queue bounds and the hourly
    /// test-run limit are race-free.
    #[allow(clippy::too_many_arguments)]
    async fn admit_draft(
        &self,
        tenant: &AuthorityId,
        license_id: &AuthorityId,
        profile_snapshot: &Value,
        resolved: &ResolvedTool,
        authority: &Value,
        inputs: &Value,
        digest: &str,
        idempotency_key: Option<&str>,
        created_by: &Value,
        generation: i64,
        settings: &DraftRunSettings,
    ) -> Result<DraftAdmission, BuilderStoreError> {
        let reference = &resolved.effective.tool;
        let mut tx = self.pool.begin().await?;
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(DRAFT_ADMISSION_LOCK)
            .execute(&mut *tx)
            .await?;
        let current: i64 =
            sqlx::query_scalar("SELECT public.mcp_lock_execution_authority() AS generation")
                .fetch_one(&mut *tx)
                .await?;
        if current != generation {
            return Err(refusing(
                tx,
                BuilderStoreError::Conflict("authority changed during acceptance".to_owned()),
            )
            .await);
        }
        if let Some(key) = idempotency_key {
            let statement = format!(
                "SELECT {RUN_COLUMNS} FROM public.mcp_runs \
                 WHERE mode = 'draft' AND tenant_id = $1::uuid AND tool_id = $2::uuid \
                 AND tool_version = $3 AND idempotency_key = $4"
            );
            let prior = sqlx::query(AssertSqlSafe(statement))
                .bind(tenant.as_str())
                .bind(reference.id.as_str())
                .bind(version_bits(reference.version))
                .bind(key)
                .fetch_optional(&mut *tx)
                .await?;
            if let Some(row) = prior {
                let run = decode_run(&row).map_err(BuilderStoreError::from)?;
                if run.input_hash != digest {
                    return Err(refusing(
                        tx,
                        BuilderStoreError::Conflict("idempotency input conflict".to_owned()),
                    )
                    .await);
                }
                tx.commit().await?;
                return Ok(DraftAdmission::Replay(run));
            }
        }
        let recent: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM public.mcp_runs WHERE mode = 'draft' AND tenant_id = $1::uuid \
             AND created_at > clock_timestamp() - interval '1 hour'",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if recent >= i64::try_from(settings.test_runs_per_hour).unwrap_or(i64::MAX) {
            return Err(refusing(tx, BuilderStoreError::Quota("test runs per hour")).await);
        }
        let (total, queued): (i64, i64) = sqlx::query_as(
            "SELECT count(*) AS total, count(*) FILTER (WHERE tenant_id = $1::uuid) AS tenant \
             FROM public.mcp_runs WHERE status = 'queued'",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if total >= i64::try_from(settings.queue_global_max).unwrap_or(i64::MAX)
            || queued >= i64::try_from(settings.queue_per_tenant_max).unwrap_or(i64::MAX)
        {
            return Err(refusing(
                tx,
                BuilderStoreError::Forbidden("execution queue is full".to_owned()),
            )
            .await);
        }
        let statement = format!(
            "INSERT INTO public.mcp_runs(run_id,mode,tenant_id,binding_id,binding_revision,\
             gateway_license_id,credential_profile_id,profile_snapshot,owner_tenant_id,tool_id,\
             tool_version,authority,inputs,input_hash,idempotency_key,created_by,queue_deadline) \
             VALUES (uuidv7(),'draft',$1::uuid,NULL,NULL,$2::uuid,NULL,$3,$4::uuid,$5::uuid,$6,\
             $7,$8,$9,$10,$11,\
             clock_timestamp() + make_interval(secs => LEAST($12::double precision,$13::double precision))) \
             RETURNING {RUN_COLUMNS}"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(license_id.as_str())
            .bind(profile_snapshot.clone())
            .bind(tenant.as_str())
            .bind(reference.id.as_str())
            .bind(version_bits(reference.version))
            .bind(authority.clone())
            .bind(inputs.clone())
            .bind(digest)
            .bind(idempotency_key)
            .bind(created_by.clone())
            .bind(f64::from(resolved.effective.limits.queue_seconds))
            .bind(settings.run_queue_timeout.as_secs_f64())
            .fetch_one(&mut *tx)
            .await?;
        let run = decode_run(&row).map_err(BuilderStoreError::from)?;
        let run_id = run.run_id.to_string();
        sqlx::query(
            "INSERT INTO public.mcp_tenant_execution_locks(tenant_id) VALUES ($1::uuid) \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_str())
        .execute(&mut *tx)
        .await?;
        // No untrusted logs or credentials are persisted. Each run has a bounded lifecycle.
        sqlx::query(
            "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) \
             SELECT $1::uuid,$2::uuid,$3 \
             WHERE (SELECT count(*) FROM public.mcp_run_events \
                    WHERE tenant_id = $1::uuid AND run_id = $2::uuid) < $4",
        )
        .bind(tenant.as_str())
        .bind(run_id.as_str())
        .bind("queued")
        .bind(DRAFT_EVENT_LIMIT)
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(DraftAdmission::Accepted(run))
    }

    /// Wait for the accepted draft and project it with its trace.
    async fn draft_result(
        &self,
        tenant: &AuthorityId,
        run: RunRow,
        settings: &DraftRunSettings,
    ) -> Result<Value, BuilderStoreError> {
        let run_id = run.run_id.to_string();
        let row = self
            .wait_draft(tenant, &run_id, run, settings.sync_wait)
            .await;
        let trace = self.trace(tenant, &run_id).await?;
        Ok(draft_view(&row, &trace))
    }

    /// The reference's `_wait`: poll an ACCEPTED run until terminal or the sync wait ends. A
    /// transient read failure never denies a run that is already durable.
    async fn wait_draft(
        &self,
        tenant: &AuthorityId,
        run_id: &str,
        mut row: RunRow,
        sync_wait: Duration,
    ) -> RunRow {
        let stop = Instant::now() + sync_wait;
        let mut failures: u32 = 0;
        while !row.status.is_terminal() && Instant::now() < stop {
            tokio::time::sleep(Duration::from_millis(50) * 2_u32.pow(failures)).await;
            match self.draft_row(tenant, run_id).await {
                Ok(fresh) => {
                    row = fresh;
                    failures = 0;
                }
                Err(error) => {
                    failures += 1;
                    tracing::warn!(%error, "draft run poll failed; the run is already durable");
                    if failures > DRAFT_POLL_RETRIES {
                        break;
                    }
                }
            }
        }
        row
    }

    /// The reference's `get_draft`: a draft run of this tenant; a bound run or another tenant's
    /// run is not found.
    async fn draft_row(
        &self,
        tenant: &AuthorityId,
        run_id: &str,
    ) -> Result<RunRow, BuilderStoreError> {
        let statement = format!(
            "SELECT {RUN_COLUMNS} FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(run_id)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| BuilderStoreError::NotFound("run not found".to_owned()))?;
        let run = decode_run(&row).map_err(BuilderStoreError::from)?;
        if run.mode != "draft" {
            return Err(BuilderStoreError::NotFound("run not found".to_owned()));
        }
        Ok(run)
    }

    /// The reference's `trace`: the run's upstream calls in order, exactly the columns the
    /// reference selects.
    async fn trace(
        &self,
        tenant: &AuthorityId,
        run_id: &str,
    ) -> Result<Vec<DraftCall>, BuilderStoreError> {
        let rows = sqlx::query(
            "SELECT sequence,operation_id::text AS operation_id,operation_version,method,path,\
             effect,status,http_status,duration_ms,reason,error_excerpt,\
             (extract(epoch FROM started_at) * 1000000)::bigint AS started_at_us, \
             (extract(epoch FROM finished_at) * 1000000)::bigint AS finished_at_us \
             FROM public.mcp_run_api_calls \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid ORDER BY sequence",
        )
        .bind(tenant.as_str())
        .bind(run_id)
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                let started_at: i64 = row.try_get("started_at_us")?;
                let finished_at: Option<i64> = row.try_get("finished_at_us")?;
                Ok(DraftCall {
                    sequence: row.try_get("sequence")?,
                    operation_id: row.try_get("operation_id")?,
                    operation_version: row.try_get("operation_version")?,
                    method: row.try_get("method")?,
                    path: row.try_get("path")?,
                    effect: row.try_get("effect")?,
                    status: row.try_get("status")?,
                    http_status: row.try_get("http_status")?,
                    duration_ms: row.try_get("duration_ms")?,
                    reason: row.try_get("reason")?,
                    error_excerpt: row.try_get("error_excerpt")?,
                    started_at: DateTime::from_timestamp_micros(started_at)
                        .ok_or(BuilderStoreError::Corrupt("trace instant"))?,
                    finished_at: match finished_at {
                        Some(micros) => Some(
                            DateTime::from_timestamp_micros(micros)
                                .ok_or(BuilderStoreError::Corrupt("trace instant"))?,
                        ),
                        None => None,
                    },
                })
            })
            .collect()
    }

    // ── tool row helpers ──────────────────────────────────────────────────────────────────

    /// Insert the tool version snapshot and its children. The children must be written in the
    /// same transaction as the version row; the database checks that at commit.
    async fn insert_tool_version(
        conn: &mut PgConnection,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
    ) -> Result<(), BuilderStoreError> {
        let actor =
            serde_json::to_value(actor).map_err(|_| BuilderStoreError::Corrupt("tool actor"))?;
        sqlx::query(
            "INSERT INTO public.mcp_tool_versions(tenant_id,tool_id,version,manifest,\
             package_sha256,file_count,operation_count,created_by,updated_by) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$8)",
        )
        .bind(manifest.tenant_id.as_str())
        .bind(manifest.tool_id.as_str())
        .bind(version_bits(manifest.version))
        .bind(
            serde_json::to_value(manifest)
                .map_err(|_| BuilderStoreError::Corrupt("tool manifest"))?,
        )
        .bind(manifest.package_sha256.as_str())
        .bind(child_count(files.len())?)
        .bind(child_count(manifest.allowed_operations.len())?)
        .bind(actor)
        .execute(&mut *conn)
        .await
        .map_err(tool_unique)?;
        for file in files {
            sqlx::query(
                "INSERT INTO public.mcp_tool_version_files(tenant_id,tool_id,version,path,content) \
                 VALUES ($1::uuid,$2::uuid,$3,$4,$5)",
            )
            .bind(manifest.tenant_id.as_str())
            .bind(manifest.tool_id.as_str())
            .bind(version_bits(manifest.version))
            .bind(file.path.as_str())
            .bind(file.content.as_str())
            .execute(&mut *conn)
            .await?;
        }
        for operation in &manifest.allowed_operations {
            sqlx::query(
                "INSERT INTO public.mcp_tool_version_operations(tenant_id,tool_id,version,\
                 operation_id,operation_version) VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5)",
            )
            .bind(manifest.tenant_id.as_str())
            .bind(manifest.tool_id.as_str())
            .bind(version_bits(manifest.version))
            .bind(operation.id.as_str())
            .bind(version_bits(operation.version))
            .execute(&mut *conn)
            .await?;
        }
        Ok(())
    }

    /// One tenant-owned version joined with its identity's current revision.
    async fn tool_version_on(
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
    ) -> Result<VersionDescriptor, BuilderStoreError> {
        let row = sqlx::query(
            "SELECT v.tenant_id::text AS tenant_id, v.tool_id::text AS tool_id, v.version, \
             v.status, v.manifest, v.created_by, v.source_tool_id::text AS source_tool_id, \
             v.source_version, t.revision \
             FROM public.mcp_tool_versions v JOIN public.mcp_tools t USING (tenant_id, tool_id) \
             WHERE v.tenant_id = $1::uuid AND v.tool_id = $2::uuid AND v.version = $3",
        )
        .bind(tenant.as_str())
        .bind(tool_id.as_str())
        .bind(version_bits(version))
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| BuilderStoreError::NotFound("tenant-owned version not found".to_owned()))?;
        decode_tool_version(&row)
    }

    /// Lock the tool identity and enforce the caller's expected revision.
    async fn lock_tool(
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        tool_id: &Uuid7,
        expected_revision: Option<PositiveVersion>,
    ) -> Result<ToolParent, BuilderStoreError> {
        let row = sqlx::query(
            "SELECT revision,retired FROM public.mcp_tools \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant.as_str())
        .bind(tool_id.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| BuilderStoreError::NotFound("tenant-owned identity not found".to_owned()))?;
        let revision: i64 = row.try_get("revision")?;
        if expected_revision.is_some_and(|expected| i64::from(expected.get()) != revision) {
            return Err(BuilderStoreError::Conflict(
                "stale expected revision".to_owned(),
            ));
        }
        Ok(ToolParent {
            retired: row.try_get("retired")?,
        })
    }

    /// Append one tool audit row. The action strings are the reference's.
    async fn audit_tool(
        conn: &mut PgConnection,
        result: &VersionDescriptor,
        actor: &Attribution,
        action: &'static str,
    ) -> Result<(), BuilderStoreError> {
        sqlx::query(
            "INSERT INTO public.mcp_access_events(event_id,tenant_id,subject,license_id,entity_id,\
             revision,action,artifact_version) \
             VALUES (uuidv7(),$1::uuid,$2,$3::uuid,$4::uuid,$5,$6,$7)",
        )
        .bind(result.tenant_id.as_str())
        .bind(actor.subject.as_str())
        .bind(actor.license_id.as_ref().map(AuthorityId::as_str))
        .bind(result.tool_id.as_str())
        .bind(i64::from(result.revision.get()))
        .bind(action)
        .bind(version_bits(result.version))
        .execute(&mut *conn)
        .await?;
        Ok(())
    }
}

/// The columns [`BuilderCatalogRepository::lock_tool`] needs from the parent identity.
struct ToolParent {
    retired: bool,
}

/// Insert one present patch field, leaving the newest manifest's value when it is absent.
fn insert_some<T: Serialize>(
    object: &mut Map<String, Value>,
    key: &'static str,
    value: &Option<T>,
) -> Result<(), BuilderStoreError> {
    if let Some(value) = value {
        object.insert(
            key.to_owned(),
            serde_json::to_value(value)
                .map_err(|_| BuilderStoreError::Corrupt("operation manifest"))?,
        );
    }
    Ok(())
}

fn decode_service(row: &PgRow) -> Result<ServiceRecord, BuilderStoreError> {
    let identity: String = row.try_get("service_id")?;
    let service_key: String = row.try_get("service_key")?;
    let status: String = row.try_get("status")?;
    Ok(ServiceRecord {
        service_id: identity7(identity)?,
        service_key: Name::new(service_key)
            .map_err(|_| BuilderStoreError::Corrupt("service key"))?,
        revision: positive(row.try_get("revision")?)?,
        version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        status: parse_status(&status)?,
        manifest: serde_json::from_value(row.try_get::<Value, _>("manifest")?)
            .map_err(|_| BuilderStoreError::Corrupt("service manifest"))?,
    })
}

fn decode_operation(row: &PgRow) -> Result<OperationRecord, BuilderStoreError> {
    let identity: String = row.try_get("operation_id")?;
    let service: String = row.try_get("service_id")?;
    let op_key: String = row.try_get("op_key")?;
    let status: String = row.try_get("status")?;
    Ok(OperationRecord {
        op_key: Name::new(op_key).map_err(|_| BuilderStoreError::Corrupt("operation key"))?,
        operation_id: identity7(identity)?,
        service_id: identity7(service)?,
        version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        status: parse_status(&status)?,
        manifest: serde_json::from_value(row.try_get::<Value, _>("manifest")?)
            .map_err(|_| BuilderStoreError::Corrupt("operation manifest"))?,
    })
}

fn decode_visible_service(row: &PgRow) -> Result<VisibleService, BuilderStoreError> {
    let identity: String = row.try_get("service_id")?;
    let service_key: String = row.try_get("service_key")?;
    let via: String = row.try_get("via")?;
    Ok(VisibleService {
        service_id: identity7(identity)?,
        service_key: Name::new(service_key)
            .map_err(|_| BuilderStoreError::Corrupt("service key"))?,
        version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        via: if via == "grant" {
            Visibility::Grant
        } else {
            Visibility::Licence
        },
    })
}

fn decode_tool_version(row: &PgRow) -> Result<VersionDescriptor, BuilderStoreError> {
    let status: String = row.try_get("status")?;
    let source_tool_id: Option<String> = row.try_get("source_tool_id")?;
    let source_version: Option<i32> = row.try_get("source_version")?;
    let source = match (source_tool_id, source_version) {
        (Some(id), Some(version)) => Some(ExactReference {
            id: identity7(id)?,
            version: positive(i64::from(version))?,
        }),
        (None, None) => None,
        _ => return Err(BuilderStoreError::Corrupt("version source")),
    };
    Ok(VersionDescriptor {
        tenant_id: parse_authority(row.try_get::<String, _>("tenant_id")?)?,
        tool_id: identity7(row.try_get::<String, _>("tool_id")?)?,
        version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        revision: positive(row.try_get::<i64, _>("revision")?)?,
        status: parse_status(&status)?,
        manifest: serde_json::from_value(row.try_get::<Value, _>("manifest")?)
            .map_err(|_| BuilderStoreError::Corrupt("tool manifest"))?,
        created_by: serde_json::from_value(row.try_get::<Value, _>("created_by")?)
            .map_err(|_| BuilderStoreError::Corrupt("created_by attribution"))?,
        source,
    })
}

/// The reference's unique-violation boundary for a tool identity: a public name or identity
/// already held is a conflict, never a 500.
fn tool_unique(error: sqlx::Error) -> BuilderStoreError {
    match error {
        sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
            BuilderStoreError::Conflict("tool identity or public name already exists".to_owned())
        }
        other => BuilderStoreError::Database(other),
    }
}

fn parse_authority(value: String) -> Result<AuthorityId, BuilderStoreError> {
    AuthorityId::new(value).map_err(|_| BuilderStoreError::Corrupt("tenant identity"))
}

fn identity7(value: String) -> Result<Uuid7, BuilderStoreError> {
    Uuid7::new(value).map_err(|_| BuilderStoreError::Corrupt("identity"))
}

fn positive(value: i64) -> Result<PositiveVersion, BuilderStoreError> {
    let value = u64::try_from(value).map_err(|_| BuilderStoreError::Corrupt("version"))?;
    PositiveVersion::new(value).map_err(|_| BuilderStoreError::Corrupt("version"))
}

fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

fn child_count(value: usize) -> Result<i32, BuilderStoreError> {
    i32::try_from(value)
        .map_err(|_| BuilderStoreError::Conflict("child count outside bound".to_owned()))
}

fn parse_status(value: &str) -> Result<VersionStatus, BuilderStoreError> {
    match value {
        "draft" => Ok(VersionStatus::Draft),
        "published" => Ok(VersionStatus::Published),
        "disabled" => Ok(VersionStatus::Disabled),
        "retired" => Ok(VersionStatus::Retired),
        _ => Err(BuilderStoreError::Corrupt("version status")),
    }
}

fn status_text(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "draft",
        VersionStatus::Published => "published",
        VersionStatus::Disabled => "disabled",
        VersionStatus::Retired => "retired",
    }
}
