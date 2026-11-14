//! The toolkit authoring service: management-gated writes, each in one transaction.
//!
//! Ported from the reference `src/toolkits/service.py` (`AccessService.toolkit_write`,
//! `toolkit_transition`): the same operator gate, the same transaction discipline and the same
//! refusal messages. The storage statements live in [`crate::storage::toolkits`].

use sqlx::PgPool;
use thiserror::Error;

use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::Attribution;
use crate::catalog::toolkit_models::{ToolkitDescriptor, ToolkitManifest};
use crate::storage::catalog::CatalogStoreError;
use crate::storage::toolkits as toolkit_store;
use crate::storage::toolkits::{ToolkitListing, ToolkitStoreError};
use crate::toolkits::resolver::SelectionResolver;

/// A refused toolkit operation: the operator gate, a request violation, a conflict or storage.
#[derive(Debug, Error)]
pub enum ToolkitServiceError {
    /// The reference's `PermissionError` for a caller that may not manage toolkits, and its
    /// tenant-mismatch refusal.
    #[error("{0}")]
    Forbidden(&'static str),
    /// The reference's `ValueError` for a request-level violation.
    #[error("{0}")]
    Invalid(&'static str),
    /// The reference's `CatalogConflictError`.
    #[error("{0}")]
    Conflict(&'static str),
    /// A missing row, a corrupt row or a failed statement.
    #[error(transparent)]
    Store(#[from] CatalogStoreError),
}

impl From<ToolkitStoreError> for ToolkitServiceError {
    fn from(error: ToolkitStoreError) -> Self {
        match error {
            ToolkitStoreError::Permission(message) => Self::Forbidden(message),
            ToolkitStoreError::Invalid(message) => Self::Invalid(message),
            ToolkitStoreError::Conflict(message) => Self::Conflict(message),
            ToolkitStoreError::NotFound(message) => {
                Self::Store(CatalogStoreError::NotFound(message))
            }
            ToolkitStoreError::Corrupt(message) => Self::Store(CatalogStoreError::Corrupt(message)),
            ToolkitStoreError::Database(error) => Self::Store(CatalogStoreError::Database(error)),
        }
    }
}

/// The toolkit authoring service. One pool, one resolver; every call names its principal.
#[derive(Debug, Clone)]
pub struct ToolkitService {
    pool: PgPool,
    resolver: SelectionResolver,
}

impl ToolkitService {
    /// Bind the service to the database and the exact-selection resolver.
    pub fn new(pool: PgPool, resolver: SelectionResolver) -> Self {
        Self { pool, resolver }
    }

    /// The reference's operator gate: only a management principal may write toolkits.
    pub fn operator(principal: &Principal) -> Result<Attribution, ToolkitServiceError> {
        if !principal.management {
            return Err(ToolkitServiceError::Forbidden(
                "management authorization required",
            ));
        }
        let license_id = AuthorityId::new(principal.license_id.to_string()).map_err(|_| {
            ToolkitServiceError::Store(CatalogStoreError::Corrupt("principal licence identity"))
        })?;
        Ok(Attribution {
            subject: principal.subject.clone(),
            license_id: Some(license_id),
        })
    }

    /// Create a draft toolkit at version one, or append the next draft version.
    pub async fn write(
        &self,
        principal: &Principal,
        manifest: &ToolkitManifest,
        expected: Option<PositiveVersion>,
    ) -> Result<ToolkitDescriptor, ToolkitServiceError> {
        let actor = Self::operator(principal)?;
        let tenant = tenant(principal)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let result = toolkit_store::write_toolkit(
            &mut transaction,
            &self.resolver,
            &tenant,
            &actor,
            manifest,
            expected,
        )
        .await
        .map_err(map_write)?;
        transaction.commit().await.map_err(database)?;
        Ok(result)
    }

    /// Move one toolkit version along its lifecycle.
    pub async fn transition(
        &self,
        principal: &Principal,
        identity: &Uuid7,
        version: PositiveVersion,
        status: VersionStatus,
        expected: PositiveVersion,
    ) -> Result<ToolkitDescriptor, ToolkitServiceError> {
        let actor = Self::operator(principal)?;
        let tenant = tenant(principal)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let result = toolkit_store::transition_toolkit(
            &mut transaction,
            &self.resolver,
            &tenant,
            &actor,
            identity,
            version,
            status,
            expected,
        )
        .await
        .map_err(map_transition)?;
        transaction.commit().await.map_err(database)?;
        Ok(result)
    }

    /// The principal tenant's toolkit identities, ordered by identity.
    pub async fn list(
        &self,
        principal: &Principal,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ToolkitListing>, ToolkitServiceError> {
        Self::operator(principal)?;
        let tenant = tenant(principal)?;
        let mut conn = self.pool.acquire().await.map_err(database)?;
        Ok(toolkit_store::list_toolkits(&mut conn, &tenant, limit, offset).await?)
    }
}

/// The principal's tenant as the catalog's authority identity.
fn tenant(principal: &Principal) -> Result<AuthorityId, ToolkitServiceError> {
    AuthorityId::new(principal.tenant_id.to_string())
        .map_err(|_| ToolkitServiceError::Store(CatalogStoreError::Corrupt("principal tenant")))
}

fn database(error: sqlx::Error) -> ToolkitServiceError {
    ToolkitServiceError::Store(CatalogStoreError::Database(error))
}

/// The reference's `UniqueViolation` and `CheckViolation` mapping for the write path.
fn map_write(error: ToolkitStoreError) -> ToolkitServiceError {
    match postgres_code(&error).as_deref() {
        Some("23505") => ToolkitServiceError::Conflict("toolkit identity or name already exists"),
        Some("23514") => ToolkitServiceError::Conflict("toolkit dependencies unavailable"),
        _ => error.into(),
    }
}

/// The reference's `CheckViolation` mapping for the transition path.
fn map_transition(error: ToolkitStoreError) -> ToolkitServiceError {
    match postgres_code(&error).as_deref() {
        Some("23514") => ToolkitServiceError::Conflict("toolkit dependencies unavailable"),
        _ => error.into(),
    }
}

/// The SQLSTATE a failed statement reported, when the error is a database refusal.
fn postgres_code(error: &ToolkitStoreError) -> Option<String> {
    match error {
        ToolkitStoreError::Database(sqlx::Error::Database(database)) => {
            database.code().map(|code| code.into_owned())
        }
        _ => None,
    }
}
