//! Admission and live execution authority over the durable queue.
//!
//! Ported from the reference `src/execution/service.py` (`ExecutionService.submit`, `_wait`
//! and `inspect`). The order of the checks is the reference's: the execution switch, the
//! idempotency key, the input schema, the catalog generation, a full re-resolution of the
//! caller's authority, and only then durable acceptance. A refusal before acceptance leaves
//! no row behind; a refusal after it never cancels a run that is already durable.
//!
//! A `kata_python` run is polled inline for at most the configured synchronous wait; every
//! other runtime is driven out of band and returns its queued envelope immediately. A
//! transient read failure during polling never turns a durable run into an error: after the
//! reference's retry budget the last known row is returned so the caller polls it instead.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use regex::Regex;
use serde_json::Value;
use thiserror::Error;

use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::instance::validate_instance;
use crate::catalog::models::Runtime;
use crate::catalog::resolver::{CatalogResolver, CatalogResolverError, ResolvedTool};
use crate::catalog::validation::SchemaLimits;
use crate::config::ExecutionSettings;
use crate::execution::{RunRow, envelope};
use crate::storage::catalog::CatalogStoreError;
use crate::storage::executions::{ExecutionRepository, ExecutionStoreError};
use crate::toolkits::service::ToolkitServiceError;

/// The reference's `POLL_RETRIES`: consecutive failed reads tolerated while waiting.
const POLL_RETRIES: u32 = 3;

/// The reference's only accepted idempotency key shape.
static IDEMPOTENCY_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.:-]{1,128}$").expect("static pattern"));

/// A refused execution request, in the reference's exception vocabulary.
#[derive(Debug, Error, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionServiceError {
    /// `QueueFullError`: the global or the per-tenant queue bound is reached.
    #[error("execution queue is full")]
    QueueFull,
    /// `SubmissionError`: this deployment cannot run tools.
    #[error("execution is unavailable")]
    Unavailable,
    /// `PermissionError` / `ExecutionDeniedError`: the caller's authority was withdrawn.
    #[error("execution denied")]
    Denied,
    /// `CatalogConflictError`: the authority changed between resolution and acceptance.
    #[error("{0}")]
    Conflict(&'static str),
    /// `ValueError`: an invalid idempotency key or input arguments.
    #[error("invalid request")]
    Invalid,
    /// `CatalogNotFoundError`: no such run for this tenant.
    #[error("run not found")]
    NotFound,
    /// A storage failure or a stored row outside the domain.
    #[error("execution storage failure")]
    Internal,
}

impl From<CatalogStoreError> for ExecutionServiceError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::Conflict(message) => Self::Conflict(message),
            // A missing binding or selection is the reference's `ExecutionDeniedError`, never a
            // 404: the caller is told nothing about rows it may not use.
            CatalogStoreError::NotFound(_) => Self::Denied,
            CatalogStoreError::Corrupt(what) => {
                tracing::error!(row = what, "stored execution row is invalid");
                Self::Internal
            }
            CatalogStoreError::Database(error) => {
                tracing::error!(%error, "execution database failure");
                Self::Internal
            }
        }
    }
}

impl From<ToolkitServiceError> for ExecutionServiceError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(_) => Self::Denied,
            ToolkitServiceError::Invalid(_) => Self::Invalid,
            ToolkitServiceError::Conflict(message) => Self::Conflict(message),
            ToolkitServiceError::Store(error) => error.into(),
        }
    }
}

impl From<CatalogResolverError> for ExecutionServiceError {
    fn from(error: CatalogResolverError) -> Self {
        match error {
            CatalogResolverError::Forbidden(_) => Self::Denied,
            CatalogResolverError::Conflict(message) => Self::Conflict(message),
            CatalogResolverError::Invalid(_) => Self::Invalid,
            CatalogResolverError::Store(error)
            | CatalogResolverError::Service(ToolkitServiceError::Store(error)) => error.into(),
            CatalogResolverError::Service(error) => error.into(),
        }
    }
}

impl From<ExecutionStoreError> for ExecutionServiceError {
    fn from(error: ExecutionStoreError) -> Self {
        match error {
            ExecutionStoreError::QueueFull => Self::QueueFull,
            ExecutionStoreError::Denied => Self::Denied,
            ExecutionStoreError::Conflict(message) => Self::Conflict(message),
            ExecutionStoreError::NotFound => Self::NotFound,
            ExecutionStoreError::Store(error) => error.into(),
        }
    }
}

/// The reference's `ExecutionService`: one repository, one live resolver, the execution
/// settings and this deployment's switch.
#[derive(Debug, Clone)]
pub struct ExecutionService {
    repository: ExecutionRepository,
    resolver: CatalogResolver,
    settings: ExecutionSettings,
    execution_enabled: bool,
}

impl ExecutionService {
    /// Bind the service to its repository, resolver, settings and the `EXECUTION_ENABLED`
    /// switch.
    pub fn new(
        repository: ExecutionRepository,
        resolver: CatalogResolver,
        settings: ExecutionSettings,
        execution_enabled: bool,
    ) -> Self {
        Self {
            repository,
            resolver,
            settings,
            execution_enabled,
        }
    }

    /// The repository this service writes through: the events read of a run's stream.
    pub fn repository(&self) -> &ExecutionRepository {
        &self.repository
    }

    /// Submit one resolved tool call and return its public envelope.
    ///
    /// The reference's exact order: the deployment switch, the idempotency key, the input
    /// schema, the catalog generation, the caller's live authority compared whole, then
    /// durable acceptance. A `kata_python` run is waited on inline; an external one is not.
    pub async fn submit(
        &self,
        principal: &Principal,
        tool: &ResolvedTool,
        inputs: &Value,
        idempotency_key: Option<&str>,
        actor: Option<&Value>,
    ) -> Result<Value, ExecutionServiceError> {
        if !self.execution_enabled {
            return Err(ExecutionServiceError::Unavailable);
        }
        if let Some(key) = idempotency_key
            && !IDEMPOTENCY_KEY.is_match(key)
        {
            return Err(ExecutionServiceError::Invalid);
        }
        // The validator speaks `Value`; the manifest stores the schema as an object.
        let input_schema = Value::Object(tool.manifest.input_schema.clone());
        validate_instance(&input_schema, inputs, &SchemaLimits::default())
            .map_err(|_| ExecutionServiceError::Invalid)?;
        let generation = self.resolver.generation().await?;
        let current = self
            .resolver
            .resolve(principal)
            .await?
            .into_iter()
            .find(|candidate| candidate.effective.tool == tool.effective.tool);
        // The whole resolved tool, not just its reference: a widened or narrowed constraint,
        // a different context or a changed manifest all invalidate the caller's selection.
        let Some(current) = current else {
            return Err(ExecutionServiceError::Conflict("authority changed"));
        };
        if &current != tool {
            return Err(ExecutionServiceError::Conflict("authority changed"));
        }
        let row = self
            .repository
            .accept(
                principal,
                &current,
                inputs,
                idempotency_key,
                generation,
                actor,
            )
            .await?;
        if tool.manifest.runtime != Runtime::KataPython {
            // External runs are driven out of band and never finish inside the sync window.
            return Ok(envelope(&row));
        }
        Ok(envelope(&self.wait(row).await))
    }

    /// The reference's `_wait`: poll an ACCEPTED run until terminal or the sync wait ends.
    async fn wait(&self, row: RunRow) -> RunRow {
        let Ok(tenant) = AuthorityId::new(row.tenant_id.to_string()) else {
            return row;
        };
        let Ok(identity) = Uuid7::new(row.run_id.to_string()) else {
            return row;
        };
        let stop = Instant::now() + self.settings.sync_wait;
        let mut row = row;
        let mut failures: u32 = 0;
        while !row.status.is_terminal() && Instant::now() < stop {
            tokio::time::sleep(Duration::from_millis(50) * 2_u32.pow(failures)).await;
            match self.repository.get(&tenant, &identity).await {
                Ok(fresh) => {
                    row = fresh;
                    failures = 0;
                }
                Err(error) => {
                    failures += 1;
                    tracing::warn!(%error, "run poll failed; the run is already durable");
                    if failures > POLL_RETRIES {
                        break;
                    }
                }
            }
        }
        row
    }

    /// The reference's `inspect`: one run, owned by the caller's binding and licence, or any
    /// run of the operator's own tenant.
    ///
    /// A non-management caller must still hold the binding and licence the run was accepted
    /// under, and re-resolving proves the binding was not revoked since.
    pub async fn inspect(
        &self,
        principal: &Principal,
        identity: &Uuid7,
    ) -> Result<RunRow, ExecutionServiceError> {
        let tenant = AuthorityId::new(principal.tenant_id.to_string())
            .map_err(|_| ExecutionServiceError::Internal)?;
        let row = self.repository.get(&tenant, identity).await?;
        if !principal.management {
            if principal.binding_id != row.binding_id
                || principal.license_id != row.gateway_license_id
            {
                return Err(ExecutionServiceError::Denied);
            }
            // The live authority, not the snapshot: a revoked binding stops reads too.
            self.resolver.resolve(principal).await?;
        }
        Ok(row)
    }
}
