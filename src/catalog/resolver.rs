//! One live public projection, with no cross-request authorization cache.
//!
//! Ported from the reference `src/catalog/resolver.py`: `resolve` re-reads the catalog
//! generation around every read of the binding and its selection, so a caller can never be
//! served a projection assembled across two catalog states. `preview` is the operator path:
//! it inspects any tenant-owned binding and resolves it under a synthesized binding principal.

use chrono::Utc;
use serde_json::{Value, json};
use sqlx::PgPool;
use thiserror::Error;

use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::models::{Effect, Runtime, ToolManifest};
use crate::catalog::public::{RESERVED_NAMES, output_envelope};
use crate::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use crate::catalog::validation::{SchemaLimits, validate_schema};
use crate::storage::bindings;
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::ResolveError;
use crate::toolkits::service::{ToolkitService, ToolkitServiceError};

/// One resolved public tool: the stored manifest, its effective selection entry and the
/// binding's tenant-bound context.
#[derive(Debug, Clone)]
pub struct ResolvedTool {
    /// The exact tool version the selection resolved to.
    pub manifest: ToolManifest,
    /// The effective selection entry (public name, constraints, narrowed limits).
    pub effective: EffectiveTool,
    /// The binding's context, carried by every call.
    pub context: BoundContext,
}

impl ResolvedTool {
    /// The reference's `ResolvedTool.public`: the MCP tool object served to a caller.
    ///
    /// The result envelope is recomputed here rather than stored; `resolve` validated the same
    /// deterministic value first, so an error at this point would mean a corrupt in-memory
    /// manifest, never a caller mistake.
    pub fn public(&self) -> Value {
        json!({
            "name": self.manifest.public_name,
            "description": self.manifest.description,
            "inputSchema": self.manifest.input_schema,
            "outputSchema": output_envelope(&Value::Object(self.manifest.result_schema.clone()))
                .expect("the result envelope was validated during resolution"),
            "annotations": {
                "readOnlyHint": self.manifest.effect == Effect::ReadOnly,
                "destructiveHint": self.manifest.effect == Effect::Writes,
                "idempotentHint": false,
                "openWorldHint": !self.manifest.allowed_operations.is_empty(),
            },
            // The agent platform's canonical object.verb (tool names cannot carry dots).
            "_meta": {"operation": self.manifest.operation},
        })
    }
}

/// A refused resolution: the reference's `PermissionError` / `CatalogConflictError`, a storage
/// failure or a toolkit-service failure raised while re-deriving the selection.
#[derive(Debug, Error)]
pub enum CatalogResolverError {
    /// The reference's `PermissionError`: the caller lacks binding authority, the binding's
    /// authority changed under it, or a selected tool may not be served.
    #[error("{0}")]
    Forbidden(&'static str),
    /// The reference's `CatalogConflictError`: the catalog moved twice during one resolution.
    #[error("{0}")]
    Conflict(&'static str),
    /// A missing generation row, a missing manifest or a failed statement.
    #[error(transparent)]
    Store(CatalogStoreError),
    /// A failure raised by [`ToolkitService::effective`] or the selection resolver.
    #[error(transparent)]
    Service(ToolkitServiceError),
}

impl From<CatalogStoreError> for CatalogResolverError {
    fn from(error: CatalogStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<ResolveError> for CatalogResolverError {
    fn from(error: ResolveError) -> Self {
        Self::Service(error.into())
    }
}

impl From<ToolkitServiceError> for CatalogResolverError {
    fn from(error: ToolkitServiceError) -> Self {
        match error {
            ToolkitServiceError::Forbidden(message) => Self::Forbidden(message),
            ToolkitServiceError::Conflict(message) => Self::Conflict(message),
            // The reference raises `CatalogConflictError` when the effective selection no
            // longer matches. A profile that no longer validates cannot reach this path in
            // production (the same spec was validated when the binding was written), so the
            // request-level `ValueError` is treated as the same catalog conflict: the caller
            // gets the reference's 409, never a 422 that blames its own request.
            ToolkitServiceError::Invalid(message) => Self::Conflict(message),
            ToolkitServiceError::Store(error) => Self::Store(error),
        }
    }
}

/// The live catalog resolver: one pool, one toolkit service, the configured approved runner
/// images. Every call names its principal; nothing is cached across requests.
#[derive(Debug, Clone)]
pub struct CatalogResolver {
    pool: PgPool,
    service: ToolkitService,
    /// `MCP_APPROVED_RUNNER_IMAGES`: the runner digests a `kata_python` tool may name.
    approved_runner_images: Vec<String>,
}

impl CatalogResolver {
    /// Bind the resolver to the database, the toolkit service and the approved runner list.
    pub fn new(pool: PgPool, service: ToolkitService, approved_runner_images: Vec<String>) -> Self {
        Self {
            pool,
            service,
            approved_runner_images,
        }
    }

    /// The reference's `CatalogRepository.generation`: the catalog's monotonic generation.
    /// A missing row is storage drift, not a request error.
    async fn generation(&self) -> Result<i64, CatalogStoreError> {
        let generation: Option<i64> =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_optional(&self.pool)
                .await?;
        generation.ok_or(CatalogStoreError::Corrupt("catalog generation row"))
    }

    /// Resolve the caller's binding into its live public projection.
    ///
    /// At most two attempts: every read is bracketed by the generation, so an unchanged
    /// generation proves the projection came from one catalog state and a changed one retries.
    /// Authorization is rechecked on each attempt — nothing is trusted from a prior request.
    pub async fn resolve(
        &self,
        principal: &Principal,
    ) -> Result<Vec<ResolvedTool>, CatalogResolverError> {
        if principal.management
            || principal.binding_id.is_none()
            || principal.binding_revision.is_none()
        {
            return Err(CatalogResolverError::Forbidden(
                "explicit binding authority required",
            ));
        }
        let binding_id = principal
            .binding_id
            .as_ref()
            .map(|identity| Uuid7::new(identity.to_string()))
            .expect("a binding identity was checked present")
            .map_err(|_| CatalogStoreError::Corrupt("principal binding identity"))?;
        let tenant = AuthorityId::new(principal.tenant_id.to_string())
            .map_err(|_| CatalogStoreError::Corrupt("principal tenant identity"))?;
        let licence = principal.license_id.to_string();
        let expected_revision = principal
            .binding_revision
            .expect("a binding revision was checked present");

        // Generation checks surround all reads, including the durable binding. No transaction
        // or connection stays open across transport/dispatch waits.
        for _ in 0..2 {
            let before = self.generation().await?;
            let binding = bindings::inspect(&self.pool, &tenant, &binding_id).await?;
            if binding.gateway_license_id.as_str() != licence
                || i64::from(binding.revision.get()) != expected_revision
                || binding.revoked
                || !binding.spec.enabled
                || binding.spec.expires_at <= Utc::now()
            {
                return Err(CatalogResolverError::Forbidden("binding authority changed"));
            }
            let effective = self.service.effective(&binding).await?;
            let references: Vec<ToolReference> =
                effective.iter().map(|entry| entry.tool.clone()).collect();
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(CatalogStoreError::Database)?;
            let manifests = self
                .service
                .resolver()
                .tools_bulk(&mut conn, &tenant, &references, false, true)
                .await?;
            drop(conn);
            let mut result = Vec::with_capacity(effective.len());
            for entry in &effective {
                let manifest = manifests
                    .get(&(entry.tool.id.as_str().to_owned(), entry.tool.version.get()))
                    .filter(|manifest| manifest.tenant_id == entry.tool.tenant_id)
                    .ok_or(CatalogStoreError::Corrupt("tool manifest missing"))?;
                let approved = manifest.runner_image_digest.as_ref().is_some_and(|digest| {
                    self.approved_runner_images
                        .iter()
                        .any(|approved| approved == digest.as_str())
                });
                if (manifest.runtime == Runtime::KataPython && !approved)
                    || RESERVED_NAMES.contains(&manifest.public_name.as_str())
                {
                    return Err(CatalogResolverError::Forbidden("tool is unavailable"));
                }
                let envelope = output_envelope(&Value::Object(manifest.result_schema.clone()))
                    .map_err(|_| CatalogStoreError::Corrupt("tool result envelope"))?;
                validate_schema(&envelope, &SchemaLimits::default())
                    .map_err(|_| CatalogStoreError::Corrupt("tool result envelope"))?;
                result.push(ResolvedTool {
                    manifest: manifest.clone(),
                    effective: entry.clone(),
                    context: binding.spec.context.clone(),
                });
            }
            if before == self.generation().await? {
                result.sort_by(|left, right| {
                    left.manifest.public_name.cmp(&right.manifest.public_name)
                });
                return Ok(result);
            }
        }
        Err(CatalogResolverError::Conflict(
            "catalog changed during resolution; retry",
        ))
    }

    /// The reference's `preview`: an operator inspects any tenant-owned binding's projection
    /// through the same resolver, under a synthesized binding principal.
    pub async fn preview(
        &self,
        operator: &Principal,
        identity: &Uuid7,
    ) -> Result<Vec<ResolvedTool>, CatalogResolverError> {
        if !operator.management {
            return Err(CatalogResolverError::Forbidden(
                "management authorization required",
            ));
        }
        let tenant = AuthorityId::new(operator.tenant_id.to_string())
            .map_err(|_| CatalogStoreError::Corrupt("principal tenant identity"))?;
        let binding = bindings::inspect(&self.pool, &tenant, identity).await?;
        let binding_id = crate::auth::Rfc4122Uuid::parse(binding.binding_id.as_str())
            .ok_or(CatalogStoreError::Corrupt("binding identity"))?;
        let license_id = crate::auth::Rfc4122Uuid::parse(binding.gateway_license_id.as_str())
            .ok_or(CatalogStoreError::Corrupt("binding gateway licence"))?;
        self.resolve(&Principal {
            tenant_id: operator.tenant_id,
            license_id,
            subject: operator.subject.clone(),
            binding_id: Some(binding_id),
            binding_revision: Some(i64::from(binding.revision.get())),
            management: false,
            platform: false,
        })
        .await
    }
}
