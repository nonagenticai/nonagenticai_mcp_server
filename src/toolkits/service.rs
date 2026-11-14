//! The toolkit authoring service: management-gated writes, each in one transaction.
//!
//! Ported from the reference `src/toolkits/service.py` (`AccessService.toolkit_write`,
//! `toolkit_transition`): the same operator gate, the same transaction discipline and the same
//! refusal messages. The storage statements live in [`crate::storage::toolkits`].

use std::collections::{HashMap, HashSet};

use chrono::Utc;
use sqlx::{PgConnection, PgPool};
use thiserror::Error;

use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{Attribution, AuthAdapter, ExactReference};
use crate::catalog::toolkit_models::{
    BindingDescriptor, BindingSpec, CredentialProfile, EffectiveTool, ToolReference,
    ToolkitDescriptor, ToolkitManifest, owned_toolkits,
};
use crate::storage::bindings;
use crate::storage::catalog::CatalogStoreError;
use crate::storage::toolkits as toolkit_store;
use crate::storage::toolkits::{ToolkitListing, ToolkitStoreError};
use crate::toolkits::resolver::{ResolveError, SelectionResolver};

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
    Store(CatalogStoreError),
}

impl From<CatalogStoreError> for ToolkitServiceError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::Conflict(message) => Self::Conflict(message),
            other => Self::Store(other),
        }
    }
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

impl From<ResolveError> for ToolkitServiceError {
    fn from(error: ResolveError) -> Self {
        match error {
            ResolveError::NotFound(message) => Self::Store(CatalogStoreError::NotFound(message)),
            ResolveError::Conflict(message) => Self::Conflict(message),
            ResolveError::Invalid(message) => Self::Invalid(message),
            ResolveError::Storage(error) => Self::Store(error),
        }
    }
}

/// The toolkit and binding authoring service. One pool, one resolver, one gateway app key;
/// every call names its principal.
#[derive(Debug, Clone)]
pub struct ToolkitService {
    pool: PgPool,
    resolver: SelectionResolver,
    /// The configured gateway licence application key (`MCP_LICENSE_APP_KEY`). A credential
    /// profile's gateway reference must name it.
    license_app_key: Option<String>,
}

impl ToolkitService {
    /// Bind the service to the database, the exact-selection resolver and the configured
    /// gateway application key.
    pub fn new(pool: PgPool, resolver: SelectionResolver, license_app_key: Option<String>) -> Self {
        Self {
            pool,
            resolver,
            license_app_key,
        }
    }

    /// The exact-selection resolver this service reads tools through (the catalog resolver's
    /// bulk read).
    pub fn resolver(&self) -> &SelectionResolver {
        &self.resolver
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

    /// The reference's `validate_profile`: the credential profile must name the configured
    /// gateway application and an application reference for every service behind the selection
    /// that does not carry its own credential.
    ///
    /// `share` takes the profile row `FOR SHARE`, serializing reference edits with issuance.
    pub async fn validate_profile(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        spec: &BindingSpec,
        tools: &[EffectiveTool],
        share: bool,
    ) -> Result<CredentialProfile, ToolkitServiceError> {
        let profile =
            bindings::profile_row(conn, tenant, &spec.credential_profile_id, false, share).await?;
        if self.license_app_key.as_deref() != Some(profile.gateway.app_key.as_str()) {
            return Err(ToolkitServiceError::Invalid(
                "gateway credential has wrong application",
            ));
        }
        let references: Vec<ToolReference> = tools.iter().map(|entry| entry.tool.clone()).collect();
        let loaded = self
            .resolver
            .tools_bulk(conn, tenant, &references, false, true)
            .await?;
        // Every service behind the selection in one read, not one read per operation.
        let mut wanted: Vec<ExactReference> = Vec::new();
        let mut seen: HashSet<(String, u32)> = HashSet::new();
        for entry in tools {
            let manifest = loaded_tool(&loaded, entry)?;
            for operation in &manifest.allowed_operations {
                if seen.insert((operation.id.as_str().to_owned(), operation.version.get())) {
                    wanted.push(operation.clone());
                }
            }
        }
        let services = bindings::service_manifests(conn, &wanted).await?;
        let refs: HashMap<&str, &crate::catalog::toolkit_models::CredentialReference> = profile
            .services
            .iter()
            .map(|reference| (reference.service.as_str(), reference))
            .collect();
        for entry in tools {
            let manifest = loaded_tool(&loaded, entry)?;
            for operation in &manifest.allowed_operations {
                let service = services
                    .get(&(operation.id.as_str().to_owned(), operation.version.get()))
                    .ok_or(CatalogStoreError::Corrupt("service manifest missing"))?;
                if service.auth_adapter == AuthAdapter::Source {
                    // A tenant source carries its own credential (docs/TOOL_BUILDER.md).
                    continue;
                }
                let named = refs
                    .get(service.service_key.as_str())
                    .is_some_and(|reference| {
                        Some(&reference.app_key) == service.license_app_key.as_ref()
                    });
                if !named {
                    return Err(ToolkitServiceError::Invalid(
                        "credential profile lacks required application reference",
                    ));
                }
            }
        }
        Ok(profile)
    }

    /// Create (no `identity`) or update (with `expected`) a binding in one transaction.
    ///
    /// A new token is returned only for a create.
    pub async fn binding_write(
        &self,
        principal: &Principal,
        spec: &BindingSpec,
        identity: Option<Uuid7>,
        expected: Option<PositiveVersion>,
    ) -> Result<(BindingDescriptor, Option<String>), ToolkitServiceError> {
        let actor = Self::operator(principal)?;
        let tenant = tenant(principal)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let result = self
            .write_binding(&mut transaction, &tenant, &actor, spec, identity, expected)
            .await
            .map_err(map_binding_write)?;
        transaction.commit().await.map_err(database)?;
        Ok(result)
    }

    /// The reference's `write_binding`: binding create/update inside the caller's transaction.
    pub async fn write_binding(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        actor: &Attribution,
        spec: &BindingSpec,
        identity: Option<Uuid7>,
        expected: Option<PositiveVersion>,
    ) -> Result<(BindingDescriptor, Option<String>), ToolkitServiceError> {
        let spec = owned_toolkits(spec.clone(), tenant)
            .map_err(|error| ToolkitServiceError::Invalid(error.0))?;
        if spec.expires_at <= Utc::now() {
            return Err(ToolkitServiceError::Invalid(
                "binding expiry must be in the future",
            ));
        }
        verify_context(tenant, &spec)?;
        let token = if identity.is_none() {
            Some(bindings::mint_token())
        } else {
            None
        };
        let identity = identity.unwrap_or_else(bindings::fresh_identity);
        let old = if let Some(expected) = expected {
            let row = bindings::get_binding(conn, tenant, &identity, true).await?;
            bindings::check_revision(&row, expected)?;
            if row.revoked {
                return Err(ToolkitServiceError::Conflict("binding is revoked"));
            }
            Some(row)
        } else {
            if token.is_none() {
                return Err(ToolkitServiceError::Invalid(
                    "binding updates require an expected revision",
                ));
            }
            None
        };
        let tools = self.resolver.binding(conn, tenant, &spec, true).await?;
        let profile = self
            .validate_profile(conn, tenant, &spec, &tools, true)
            .await?;
        if let Some(old) = &old
            && profile.gateway.license_id != old.gateway_license_id
        {
            return Err(ToolkitServiceError::Invalid(
                "gateway license identity is immutable; issue a new binding",
            ));
        }
        if old.is_some() {
            bindings::update_binding(
                conn,
                tenant,
                &identity,
                &spec.credential_profile_id,
                &spec,
                &tools,
                actor,
            )
            .await?;
        } else {
            let token = token.as_deref().expect("a create mints a token");
            bindings::insert_binding(
                conn,
                tenant,
                &identity,
                &profile.gateway.license_id,
                &spec.credential_profile_id,
                &bindings::digest_token(token),
                &spec,
                &tools,
                actor,
            )
            .await?;
        }
        let result =
            bindings::descriptor(&bindings::get_binding(conn, tenant, &identity, false).await?)?;
        bindings::binding_members(conn, &result).await?;
        bindings::audit_binding(
            conn,
            tenant,
            actor,
            &identity,
            result.revision,
            "binding.changed",
        )
        .await?;
        Ok((result, token))
    }

    /// Rotate (a new token) or revoke a binding in one transaction.
    pub async fn binding_action(
        &self,
        principal: &Principal,
        identity: &Uuid7,
        expected: PositiveVersion,
        revoke: bool,
    ) -> Result<(BindingDescriptor, Option<String>), ToolkitServiceError> {
        let actor = Self::operator(principal)?;
        let tenant = tenant(principal)?;
        let mut transaction = self.pool.begin().await.map_err(database)?;
        let result = self
            .act_binding(
                &mut transaction,
                &tenant,
                &actor,
                identity,
                expected,
                revoke,
            )
            .await
            .map_err(map_binding_write)?;
        transaction.commit().await.map_err(database)?;
        Ok(result)
    }

    /// The reference's `act_binding`: rotate or revoke inside the caller's transaction; the
    /// binding's protocol sessions are dropped either way.
    pub async fn act_binding(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        actor: &Attribution,
        identity: &Uuid7,
        expected: PositiveVersion,
        revoke: bool,
    ) -> Result<(BindingDescriptor, Option<String>), ToolkitServiceError> {
        let token = if revoke {
            None
        } else {
            Some(bindings::mint_token())
        };
        let row = bindings::get_binding(conn, tenant, identity, true).await?;
        bindings::check_revision(&row, expected)?;
        if row.revoked {
            return Err(ToolkitServiceError::Conflict("binding is revoked"));
        }
        let digest = token.as_deref().map(bindings::digest_token);
        bindings::rotate_or_revoke(conn, tenant, identity, digest.as_deref(), revoke, actor)
            .await?;
        bindings::delete_sessions(conn, tenant, identity).await?;
        let result =
            bindings::descriptor(&bindings::get_binding(conn, tenant, identity, false).await?)?;
        bindings::audit_binding(
            conn,
            tenant,
            actor,
            identity,
            result.revision,
            if revoke {
                "binding.revoked"
            } else {
                "binding.rotated"
            },
        )
        .await?;
        Ok((result, token))
    }

    /// The reference's `effective`: the live selection a stored binding still serves.
    ///
    /// A profile whose gateway licence changed, or a selection that no longer matches the
    /// stored tools, is a conflict — never a silent substitution.
    pub async fn effective(
        &self,
        binding: &BindingDescriptor,
    ) -> Result<Vec<EffectiveTool>, ToolkitServiceError> {
        let mut conn = self.pool.acquire().await.map_err(database)?;
        let profile = self
            .validate_profile(
                &mut conn,
                &binding.tenant_id,
                &binding.spec,
                &binding.tools,
                false,
            )
            .await?;
        if profile.gateway.license_id != binding.gateway_license_id {
            return Err(ToolkitServiceError::Conflict("gateway profile changed"));
        }
        let current = self
            .resolver
            .binding(&mut conn, &binding.tenant_id, &binding.spec, false)
            .await?;
        if current != binding.tools {
            return Err(ToolkitServiceError::Conflict("effective selection changed"));
        }
        Ok(current)
    }
}

/// The reference's `ContextVerifier`: only tenant scope is self-verifying at this stage.
///
/// The reference raises `ValueError`; every context it refuses is a caller error, so it maps
/// to [`ToolkitServiceError::Invalid`] (the route layer's 422) and never to `Forbidden`.
fn verify_context(tenant: &AuthorityId, spec: &BindingSpec) -> Result<(), ToolkitServiceError> {
    let values = spec.context.public_values();
    let keys: Vec<&String> = values
        .as_object()
        .map(|object| object.keys().collect())
        .unwrap_or_default();
    if spec.context.tenant_id != *tenant || keys.len() != 1 || keys[0] != "tenant_id" {
        return Err(ToolkitServiceError::Invalid(
            "resource and stage context requires host ownership/provenance verification",
        ));
    }
    Ok(())
}

/// One loaded tool manifest for a selection entry, checking the owner as the resolver does.
fn loaded_tool<'a>(
    loaded: &'a HashMap<(String, u32), crate::catalog::models::ToolManifest>,
    entry: &EffectiveTool,
) -> Result<&'a crate::catalog::models::ToolManifest, ToolkitServiceError> {
    loaded
        .get(&(entry.tool.id.as_str().to_owned(), entry.tool.version.get()))
        .filter(|manifest| manifest.tenant_id == entry.tool.tenant_id)
        .ok_or_else(|| {
            ToolkitServiceError::Store(CatalogStoreError::Corrupt("tool manifest missing"))
        })
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

/// The reference's ASGI mapping for the binding write path: a unique violation is a conflict.
fn map_binding_write(error: ToolkitServiceError) -> ToolkitServiceError {
    if let ToolkitServiceError::Store(CatalogStoreError::Database(sqlx::Error::Database(database))) =
        &error
        && database.code().as_deref() == Some("23505")
    {
        return ToolkitServiceError::Conflict("binding identity already exists");
    }
    error
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
