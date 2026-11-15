//! Strict complete-package validation and tenant lifecycle.
//!
//! Ported from the reference `src/catalog/service.py` (`CatalogService`): the same validation
//! order, the same refusal messages and the same publish re-validation. One reference input is
//! deliberately absent: the operator-approved runner-image list (`settings.approved_runner_images`)
//! has no counterpart in this crate's configuration yet, so the "runner image is not
//! operator-approved" refusal is not checked here. Every other check is ported.

use serde_json::Value;
use thiserror::Error;

use crate::catalog::error::CatalogError;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    Attribution, Constraint, Effect, ExactReference, OperationManifest, Runtime, ServiceManifest,
    ToolManifest, VersionDescriptor,
};
use crate::catalog::package::{PackageFile, validate_package};
use crate::catalog::public::{RESERVED_NAMES, output_envelope, validate_public_input};
use crate::catalog::validation::{SchemaLimits, validate_schema};
use crate::config::PackageLimits;
use crate::storage::catalog::{
    AppendRequest, CatalogRepository, CatalogStoreError, PlatformCatalogRepository,
    PlatformDefinition, PlatformKind, PlatformStoreError,
};

/// A refused catalog operation: either an invalid value or a repository refusal.
#[derive(Debug, Error)]
pub enum CatalogServiceError {
    /// The reference's `ValueError` from validation.
    #[error(transparent)]
    Invalid(#[from] CatalogError),
    /// A conflict or missing row from the repository.
    #[error(transparent)]
    Store(#[from] CatalogStoreError),
}

/// The catalog authoring service: validate a manifest, then persist it.
#[derive(Debug, Clone)]
pub struct CatalogService {
    repository: CatalogRepository,
    limits: SchemaLimits,
    packages: PackageLimits,
}

impl CatalogService {
    /// Bind the service to a repository and the operator's schema and package bounds.
    pub fn new(
        repository: CatalogRepository,
        limits: SchemaLimits,
        packages: PackageLimits,
    ) -> Self {
        Self {
            repository,
            limits,
            packages,
        }
    }

    /// The reference's complete validation, in its order.
    ///
    /// The manifest is revalidated even though it was validated on construction: the same
    /// reason the reference revalidates, namely that a caller may have built or copied a value
    /// without running the validators.
    pub async fn validate(
        &self,
        manifest: &ToolManifest,
        files: &[PackageFile],
    ) -> Result<(), CatalogServiceError> {
        let manifest: ToolManifest = serde_json::to_value(manifest)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(CatalogError("invalid tool manifest"))?;
        for schema in [
            &manifest.input_schema,
            &manifest.result_schema,
            &manifest.context_schema,
        ] {
            validate_schema(&Value::Object(schema.clone()), &self.limits)?;
        }
        if RESERVED_NAMES.contains(&manifest.public_name.as_str()) {
            return Err(CatalogError("reserved platform tool name").into());
        }
        validate_public_input(&Value::Object(manifest.input_schema.clone()))?;
        validate_schema(
            &output_envelope(&Value::Object(manifest.result_schema.clone()))?,
            &self.limits,
        )?;
        if manifest.runtime == Runtime::KataPython {
            let entrypoint = manifest.entrypoint.as_deref().ok_or(CatalogError(
                "kata_python tools require entrypoint and runner_image_digest",
            ))?;
            validate_package(
                files,
                entrypoint,
                manifest.package_sha256.as_str(),
                &self.packages,
            )?;
        }
        for reference in &manifest.allowed_operations {
            let (operation, _status) = self.repository.operation(reference).await?;
            self.repository.service(&operation.service).await?;
            if manifest.effect == Effect::ReadOnly && operation.effect != Effect::ReadOnly {
                return Err(CatalogError("read-only tool cannot grant mutations").into());
            }
        }
        for entry in &manifest.operation_constraints {
            self.ownership_reads(&entry.rules).await?;
        }
        Ok(())
    }

    /// Validate and create a draft identity at version 1.
    pub async fn create_draft(
        &self,
        tenant_id: &AuthorityId,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
    ) -> Result<VersionDescriptor, CatalogServiceError> {
        self.validate(manifest, files).await?;
        Ok(self
            .repository
            .create(tenant_id, manifest, files, actor)
            .await?)
    }

    /// Validate and append the next draft version.
    pub async fn append_draft(
        &self,
        request: &AppendRequest<'_>,
    ) -> Result<VersionDescriptor, CatalogServiceError> {
        self.validate(request.content, request.files).await?;
        Ok(self.repository.append(request, None).await?)
    }

    /// Publish, disable or retire a version. Publishing revalidates the stored version first,
    /// exactly as the reference does.
    pub async fn transition(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
        status: VersionStatus,
        actor: &Attribution,
        expected_revision: PositiveVersion,
    ) -> Result<VersionDescriptor, CatalogServiceError> {
        if status == VersionStatus::Published {
            let original = self
                .repository
                .get_version(tenant_id, tool_id, version)
                .await?;
            let files = self.repository.files(tenant_id, tool_id, version).await?;
            self.validate(&original.manifest, &files).await?;
        }
        Ok(self
            .repository
            .transition(
                tenant_id,
                tool_id,
                version,
                status,
                actor,
                expected_revision,
            )
            .await?)
    }

    /// Every ownership check must be an approved published read, and never recursive.
    async fn ownership_reads(&self, rules: &[Constraint]) -> Result<(), CatalogServiceError> {
        for rule in rules {
            let Constraint::OwnershipRead(read) = rule else {
                continue;
            };
            let (operation, state) = self.repository.operation(&read.operation).await?;
            let (_, service_state) = self.repository.service(&operation.service).await?;
            if operation.effect != Effect::ReadOnly
                || state != VersionStatus::Published
                || service_state != VersionStatus::Published
            {
                return Err(
                    CatalogError("ownership checks require an approved published read").into(),
                );
            }
            if operation
                .scope_rules
                .iter()
                .any(|rule| matches!(rule, Constraint::OwnershipRead(_)))
            {
                return Err(CatalogError("recursive ownership checks are unsupported").into());
            }
        }
        Ok(())
    }
}

// ── platform authoring: operator-only, over the platform pool ───────────────────────────────

/// A refused platform-authoring call: either an invalid value or a platform store refusal.
#[derive(Debug, Error)]
pub enum PlatformServiceError {
    /// The reference's `ValueError` from schema or ownership validation.
    #[error(transparent)]
    Invalid(#[from] CatalogError),
    /// A conflict, missing row or source refusal from the platform repository.
    #[error(transparent)]
    Store(#[from] PlatformStoreError),
}

impl From<CatalogStoreError> for PlatformServiceError {
    fn from(error: CatalogStoreError) -> Self {
        Self::Store(error.into())
    }
}

impl From<CatalogServiceError> for PlatformServiceError {
    fn from(error: CatalogServiceError) -> Self {
        match error {
            CatalogServiceError::Invalid(error) => Self::Invalid(error),
            CatalogServiceError::Store(error) => Self::Store(error.into()),
        }
    }
}

/// The reference's `PlatformCatalogService`: platform contract authoring by an operator.
///
/// It holds the platform repository (the elevated pool) and the tenant catalog service used
/// for the validations both authoring paths share: the closed schema walk, the ownership-read
/// rules, and the exact-version reads. Deliberately absent from any tenant or agent dependency.
#[derive(Debug, Clone)]
pub struct PlatformCatalogService {
    repository: PlatformCatalogRepository,
    catalog: CatalogService,
}

impl PlatformCatalogService {
    /// Bind the service to the platform repository and the catalog service.
    pub fn new(repository: PlatformCatalogRepository, catalog: CatalogService) -> Self {
        Self {
            repository,
            catalog,
        }
    }

    /// The reference's `catalog.settings`: the bounds every schema validation uses.
    pub fn limits(&self) -> &SchemaLimits {
        &self.catalog.limits
    }

    /// Create the service identity at version 1, or append the next version.
    pub async fn add_service(
        &self,
        manifest: &ServiceManifest,
        actor: &Attribution,
        expected_revision: Option<i64>,
    ) -> Result<(), PlatformServiceError> {
        let manifest: ServiceManifest = serde_json::to_value(manifest)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(CatalogError("invalid service manifest"))?;
        Ok(self
            .repository
            .add_service(&manifest, actor, expected_revision)
            .await?)
    }

    /// Append the next operation version after the reference's complete validation.
    pub async fn add_operation(
        &self,
        manifest: &OperationManifest,
        actor: &Attribution,
    ) -> Result<(), PlatformServiceError> {
        let manifest: OperationManifest = serde_json::to_value(manifest)
            .ok()
            .and_then(|value| serde_json::from_value(value).ok())
            .ok_or(CatalogError("invalid operation manifest"))?;
        self.validate_schemas(&manifest)?;
        let (service, _status) = self.catalog.repository.service(&manifest.service).await?;
        if manifest.max_response_bytes > service.max_response_bytes {
            return Err(
                PlatformStoreError::Conflict("operation exceeds service response limit").into(),
            );
        }
        self.catalog.ownership_reads(&manifest.scope_rules).await?;
        Ok(self.repository.add_operation(&manifest, actor).await?)
    }

    /// Move one exact platform version through the lifecycle.
    pub async fn transition(
        &self,
        kind: PlatformKind,
        reference: &ExactReference,
        status: VersionStatus,
        actor: &Attribution,
    ) -> Result<(), PlatformStoreError> {
        self.repository
            .transition(kind, reference, status, actor)
            .await
    }

    /// One exact platform service version and its status (the reference's `catalog.repository`).
    pub async fn service(
        &self,
        reference: &ExactReference,
    ) -> Result<(ServiceManifest, VersionStatus), CatalogStoreError> {
        self.catalog.repository.service(reference).await
    }

    /// One exact platform operation version and its status.
    pub async fn operation(
        &self,
        reference: &ExactReference,
    ) -> Result<(OperationManifest, VersionStatus), CatalogStoreError> {
        self.catalog.repository.operation(reference).await
    }

    /// The shared ownership-read rule: every check must be an approved published read.
    pub async fn ownership_reads(&self, rules: &[Constraint]) -> Result<(), PlatformServiceError> {
        Ok(self.catalog.ownership_reads(rules).await?)
    }

    /// Validate an operation's input and output schemas against the configured bounds.
    pub fn validate_schemas(&self, manifest: &OperationManifest) -> Result<(), CatalogError> {
        validate_schema(
            &Value::Object(manifest.input_schema.clone()),
            &self.catalog.limits,
        )?;
        validate_schema(
            &Value::Object(manifest.output_schema.clone()),
            &self.catalog.limits,
        )?;
        Ok(())
    }

    /// Insert the importer's version-1 drafts in one transaction.
    pub async fn insert_drafts(
        &self,
        manifests: &[OperationManifest],
        actor: &Attribution,
    ) -> Result<(), PlatformStoreError> {
        self.repository
            .insert_operation_drafts(manifests, actor)
            .await
    }

    /// Every platform version of one kind (all statuses), ordered by identity then version.
    pub async fn definitions(
        &self,
        kind: PlatformKind,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PlatformDefinition>, PlatformStoreError> {
        self.repository.definitions(kind, limit, offset).await
    }
}
