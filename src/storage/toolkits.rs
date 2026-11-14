//! Toolkit reads. Every statement is tenant-explicit and takes the caller's connection, so the
//! caller owns the transaction. The statements are the reference's (`src/storage/bindings.py`
//! and `src/toolkits/resolver.py`), with the same conflict/not-found boundaries.

use std::collections::HashMap;

use serde::Serialize;
use serde_json::Value;
use sqlx::{PgConnection, Row};
use thiserror::Error;

use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::{VersionStatus, toolkit_transition_allowed};
use crate::catalog::models::{Attribution, ToolManifest};
use crate::catalog::toolkit_models::{ToolReference, ToolkitDescriptor, ToolkitManifest};
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::{ResolveError, SelectionResolver};

/// A refused toolkit write, in the reference's error shapes.
///
/// The reference raises `PermissionError`, `ValueError`, `CatalogConflictError` and
/// `CatalogNotFoundError` from the same functions; the first two have no counterpart in
/// [`CatalogStoreError`], so a toolkit-specific type carries them.
#[derive(Debug, Error)]
pub enum ToolkitStoreError {
    /// The reference's `PermissionError`: the manifest is not the caller's to write.
    #[error("{0}")]
    Permission(&'static str),
    /// The reference's `ValueError` for a request-level violation.
    #[error("{0}")]
    Invalid(&'static str),
    /// The reference's `CatalogConflictError`.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `CatalogNotFoundError`.
    #[error("{0}")]
    NotFound(&'static str),
    /// A stored row no longer satisfies the domain model (schema drift, not a request error).
    #[error("stored toolkit row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed the statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<CatalogStoreError> for ToolkitStoreError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::Conflict(message) => Self::Conflict(message),
            CatalogStoreError::NotFound(message) => Self::NotFound(message),
            CatalogStoreError::Corrupt(message) => Self::Corrupt(message),
            CatalogStoreError::Database(error) => Self::Database(error),
        }
    }
}

impl From<ResolveError> for ToolkitStoreError {
    fn from(error: ResolveError) -> Self {
        match error {
            ResolveError::Invalid(message) => Self::Invalid(message),
            ResolveError::NotFound(message) => Self::NotFound(message),
            ResolveError::Conflict(message) => Self::Conflict(message),
            ResolveError::Storage(error) => error.into(),
        }
    }
}

/// One row of [`list_toolkits`]: an identity without its manifests.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolkitListing {
    /// A UUIDv7 identity.
    pub toolkit_id: Uuid7,
    /// The identity's name.
    pub name: Name,
    /// The identity's revision.
    pub revision: PositiveVersion,
}

/// One exact toolkit version joined with its identity's revision.
///
/// The reference's `get_toolkit`: the row must be owned by `tenant`, and a missing row is
/// `CatalogNotFoundError("toolkit version not found")`.
pub async fn get_toolkit(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    version: PositiveVersion,
) -> Result<ToolkitDescriptor, CatalogStoreError> {
    let row = sqlx::query(
        "SELECT v.manifest, v.tools, v.status, t.revision \
         FROM public.mcp_toolkit_versions v \
         JOIN public.mcp_toolkits t USING (tenant_id, toolkit_id) \
         WHERE v.tenant_id = $1::uuid AND v.toolkit_id = $2::uuid AND v.version = $3",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(version_bits(version))
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(CatalogStoreError::NotFound("toolkit version not found"))?;
    let manifest: Value = row.try_get("manifest")?;
    let tools: Value = row.try_get("tools")?;
    let status: String = row.try_get("status")?;
    Ok(ToolkitDescriptor {
        manifest: serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("toolkit manifest"))?,
        revision: positive(row.try_get("revision")?)?,
        status: parse_status(&status)?,
        tools: serde_json::from_value(tools)
            .map_err(|_| CatalogStoreError::Corrupt("toolkit tools"))?,
    })
}

/// The reference `tools_bulk` read: every requested tool in two statements instead of two per
/// tool.
///
/// A row must belong to `reference.tenant_id` and be visible to `reader` (its own, or shared
/// with it), published and not retired, with every operation and service published. When
/// `bound_platform` is set, a platform-owned reference is read as the platform tenant, its
/// owner. Manifests are keyed by `(tool_id, version)`; callers verify the owner.
pub async fn selectable_tools(
    conn: &mut PgConnection,
    reader: &AuthorityId,
    references: &[ToolReference],
    bound_platform: bool,
    platform_tenant: &AuthorityId,
) -> Result<HashMap<(String, u32), ToolManifest>, CatalogStoreError> {
    if references.is_empty() {
        return Ok(HashMap::new());
    }
    let owners: Vec<String> = references
        .iter()
        .map(|reference| reference.tenant_id.as_str().to_owned())
        .collect();
    let identities: Vec<String> = references
        .iter()
        .map(|reference| reference.id.as_str().to_owned())
        .collect();
    let versions: Vec<i32> = references
        .iter()
        .map(|reference| version_bits(reference.version))
        .collect();
    let readers: Vec<String> = references
        .iter()
        .map(|reference| {
            let selected = if bound_platform && reference.tenant_id == *platform_tenant {
                &reference.tenant_id
            } else {
                reader
            };
            selected.as_str().to_owned()
        })
        .collect();
    let rows = sqlx::query(
        "WITH want(owner, tool_id, version, reader) AS (\
           SELECT * FROM unnest($1::text[], $2::text[], $3::int[], $4::text[])) \
         SELECT v.manifest, v.status, t.retired \
         FROM want w \
         JOIN public.mcp_tool_versions v \
           ON (v.tenant_id, v.tool_id, v.version) = (w.owner::uuid, w.tool_id::uuid, w.version) \
         JOIN public.mcp_tools t ON (t.tenant_id, t.tool_id) = (v.tenant_id, v.tool_id) \
         WHERE w.owner::uuid = w.reader::uuid OR EXISTS ( \
           SELECT 1 FROM public.mcp_tool_shares s \
           WHERE s.owner_tenant_id = w.owner::uuid AND s.tool_id = w.tool_id::uuid \
             AND s.grantee_tenant_id = w.reader::uuid)",
    )
    .bind(&owners)
    .bind(&identities)
    .bind(&versions)
    .bind(&readers)
    .fetch_all(&mut *conn)
    .await?;
    let mut found: HashMap<(String, u32), ToolManifest> = HashMap::new();
    for row in rows {
        let status: String = row.try_get("status")?;
        let retired: bool = row.try_get("retired")?;
        if status != "published" || retired {
            return Err(CatalogStoreError::Conflict("selected tool is unavailable"));
        }
        let manifest: Value = row.try_get("manifest")?;
        let manifest: ToolManifest = serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("tool manifest"))?;
        found.insert(
            (manifest.tool_id.as_str().to_owned(), manifest.version.get()),
            manifest,
        );
    }
    for reference in references {
        let selected = found.get(&(reference.id.as_str().to_owned(), reference.version.get()));
        match selected {
            Some(manifest) if manifest.tenant_id == reference.tenant_id => {}
            _ => return Err(CatalogStoreError::NotFound("selected tool not found")),
        }
    }
    let rows = sqlx::query(
        "SELECT r.tenant_id, r.tool_id, r.version, \
         bool_and(o.status = 'published' AND s.status = 'published') AS ok \
         FROM public.mcp_tool_version_operations r \
         JOIN public.mcp_operation_versions o \
           ON (o.operation_id, o.version) = (r.operation_id, r.operation_version) \
         JOIN public.mcp_service_versions s \
           ON (s.service_id, s.version) = (o.service_id, o.service_version) \
         WHERE (r.tenant_id, r.tool_id, r.version) IN ( \
           SELECT owner::uuid, tool_id::uuid, version \
           FROM unnest($1::text[], $2::text[], $3::int[]) AS want(owner, tool_id, version)) \
         GROUP BY 1, 2, 3",
    )
    .bind(&owners)
    .bind(&identities)
    .bind(&versions)
    .fetch_all(&mut *conn)
    .await?;
    for row in rows {
        let ok: bool = row.try_get("ok")?;
        if !ok {
            return Err(CatalogStoreError::Conflict(
                "selected operation is unavailable",
            ));
        }
    }
    Ok(found)
}

/// The reference's `mcp_lock_access_tool`: serialize concurrent edits of one access entry.
pub async fn lock_access_tool(
    conn: &mut PgConnection,
    reader: &AuthorityId,
    reference: &ToolReference,
) -> Result<(), CatalogStoreError> {
    sqlx::query("SELECT public.mcp_lock_access_tool($1::uuid, $2::uuid, $3::uuid, $4)")
        .bind(reader.as_str())
        .bind(reference.tenant_id.as_str())
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The reference's `FOR SHARE` read lock on one toolkit version. A missing row is not an error
/// here; `get_toolkit` reports it.
pub async fn lock_toolkit_version(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    version: PositiveVersion,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "SELECT 1 FROM public.mcp_toolkit_versions \
         WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid AND version = $3 FOR SHARE",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(version_bits(version))
    .fetch_optional(&mut *conn)
    .await?;
    Ok(())
}

/// The reference's `write_toolkit`: create a toolkit at version one, or append the next draft.
///
/// The caller owns the transaction. `expected` is `None` for a create (which must submit
/// version one) and the identity's current revision for an append, where the submitted version
/// is discarded in favour of `max(version)+1` and the identity's revision advances once.
pub async fn write_toolkit(
    conn: &mut PgConnection,
    resolver: &SelectionResolver,
    tenant: &AuthorityId,
    actor: &Attribution,
    manifest: &ToolkitManifest,
    expected: Option<PositiveVersion>,
) -> Result<ToolkitDescriptor, ToolkitStoreError> {
    if manifest.tenant_id != *tenant {
        return Err(ToolkitStoreError::Permission("tenant mismatch"));
    }
    let mut manifest = manifest.clone();
    match expected {
        None => {
            if manifest.version.get() != 1 {
                return Err(ToolkitStoreError::Invalid(
                    "first toolkit version must be one",
                ));
            }
            sqlx::query(
                "INSERT INTO public.mcp_toolkits(tenant_id,toolkit_id,name,created_by) \
                 VALUES ($1::uuid,$2::uuid,$3,$4)",
            )
            .bind(tenant.as_str())
            .bind(manifest.toolkit_id.as_str())
            .bind(manifest.name.as_str())
            .bind(snapshot(actor)?)
            .execute(&mut *conn)
            .await?;
        }
        Some(expected) => {
            let row = sqlx::query(
                "SELECT revision,name FROM public.mcp_toolkits \
                 WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid FOR UPDATE",
            )
            .bind(tenant.as_str())
            .bind(manifest.toolkit_id.as_str())
            .fetch_optional(&mut *conn)
            .await?
            .ok_or(ToolkitStoreError::NotFound("toolkit not found"))?;
            let revision: i64 = row.try_get("revision")?;
            if i64::from(expected.get()) != revision {
                return Err(ToolkitStoreError::Conflict("stale expected revision"));
            }
            let name: String = row.try_get("name")?;
            if name != manifest.name.as_str() {
                return Err(ToolkitStoreError::Conflict("toolkit name is immutable"));
            }
            let next: Option<i32> = sqlx::query_scalar(
                "SELECT max(version)+1 FROM public.mcp_toolkit_versions \
                 WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid",
            )
            .bind(tenant.as_str())
            .bind(manifest.toolkit_id.as_str())
            .fetch_one(&mut *conn)
            .await?;
            let next = next.ok_or(ToolkitStoreError::Corrupt("toolkit version counter"))?;
            manifest.version = positive_bits(next)?;
            sqlx::query(
                "UPDATE public.mcp_toolkits SET revision = revision + 1 \
                 WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid",
            )
            .bind(tenant.as_str())
            .bind(manifest.toolkit_id.as_str())
            .execute(&mut *conn)
            .await?;
        }
    }
    let tools = resolver.flatten(&mut *conn, &manifest).await?;
    sqlx::query(
        "INSERT INTO public.mcp_toolkit_versions(tenant_id,toolkit_id,version,manifest,tools,\
         created_by,updated_by) VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$6)",
    )
    .bind(tenant.as_str())
    .bind(manifest.toolkit_id.as_str())
    .bind(version_bits(manifest.version))
    .bind(snapshot(&manifest)?)
    .bind(
        serde_json::to_value(&tools)
            .map_err(|_| ToolkitStoreError::Corrupt("toolkit tools snapshot"))?,
    )
    .bind(snapshot(actor)?)
    .execute(&mut *conn)
    .await?;
    for tool in &tools {
        sqlx::query(
            "INSERT INTO public.mcp_toolkit_version_tools(tenant_id,toolkit_id,version,\
             owner_tenant_id,tool_id,tool_version,public_name) \
             VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5::uuid,$6,$7)",
        )
        .bind(tenant.as_str())
        .bind(manifest.toolkit_id.as_str())
        .bind(version_bits(manifest.version))
        .bind(tool.tool.tenant_id.as_str())
        .bind(tool.tool.id.as_str())
        .bind(version_bits(tool.tool.version))
        .bind(tool.public_name.as_str())
        .execute(&mut *conn)
        .await?;
    }
    for reference in &manifest.includes {
        sqlx::query(
            "INSERT INTO public.mcp_toolkit_inclusions(tenant_id,toolkit_id,version,\
             included_id,included_version) VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5)",
        )
        .bind(tenant.as_str())
        .bind(manifest.toolkit_id.as_str())
        .bind(version_bits(manifest.version))
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .execute(&mut *conn)
        .await?;
    }
    let result = get_toolkit(&mut *conn, tenant, &manifest.toolkit_id, manifest.version).await?;
    audit(
        &mut *conn,
        tenant,
        actor,
        &manifest.toolkit_id,
        result.revision,
        "toolkit.draft",
    )
    .await?;
    Ok(result)
}

/// The reference's `transition_toolkit`: move one version along the toolkit lifecycle.
///
/// The caller owns the transaction. Publishing re-flattens the stored manifest and refuses
/// with [`ToolkitStoreError::Conflict`]`("toolkit dependency mismatch")` when the selection no
/// longer resolves to the stored tools.
#[allow(clippy::too_many_arguments)]
pub async fn transition_toolkit(
    conn: &mut PgConnection,
    resolver: &SelectionResolver,
    tenant: &AuthorityId,
    actor: &Attribution,
    identity: &Uuid7,
    version: PositiveVersion,
    status: VersionStatus,
    expected: PositiveVersion,
) -> Result<ToolkitDescriptor, ToolkitStoreError> {
    let row = sqlx::query(
        "SELECT revision FROM public.mcp_toolkits \
         WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid FOR UPDATE",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .fetch_optional(&mut *conn)
    .await?
    .ok_or(ToolkitStoreError::NotFound("toolkit not found"))?;
    let revision: i64 = row.try_get("revision")?;
    if i64::from(expected.get()) != revision {
        return Err(ToolkitStoreError::Conflict("stale expected revision"));
    }
    let original = get_toolkit(&mut *conn, tenant, identity, version).await?;
    if !toolkit_transition_allowed(original.status, status) {
        return Err(ToolkitStoreError::Conflict("invalid toolkit transition"));
    }
    if status == VersionStatus::Published {
        let tools = match resolver.flatten(&mut *conn, &original.manifest).await {
            Ok(tools) => tools,
            Err(ResolveError::Storage(error)) => return Err(error.into()),
            Err(_) => return Err(ToolkitStoreError::Conflict("toolkit dependency mismatch")),
        };
        if tools != original.tools {
            return Err(ToolkitStoreError::Conflict("toolkit dependency mismatch"));
        }
    }
    sqlx::query(
        "UPDATE public.mcp_toolkit_versions SET status = $1, updated_by = $2, \
         updated_at = clock_timestamp() \
         WHERE tenant_id = $3::uuid AND toolkit_id = $4::uuid AND version = $5",
    )
    .bind(status_text(status))
    .bind(snapshot(actor)?)
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(version_bits(version))
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "UPDATE public.mcp_toolkits SET revision = revision + 1 \
         WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .execute(&mut *conn)
    .await?;
    let result = get_toolkit(&mut *conn, tenant, identity, version).await?;
    audit(
        &mut *conn,
        tenant,
        actor,
        identity,
        result.revision,
        status_action(status),
    )
    .await?;
    Ok(result)
}

/// The tenant's toolkit identities, ordered by identity.
pub async fn list_toolkits(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    limit: u32,
    offset: u32,
) -> Result<Vec<ToolkitListing>, ToolkitStoreError> {
    let rows = sqlx::query(
        "SELECT toolkit_id::text AS toolkit_id,name,revision FROM public.mcp_toolkits \
         WHERE tenant_id = $1::uuid ORDER BY toolkit_id LIMIT $2 OFFSET $3",
    )
    .bind(tenant.as_str())
    .bind(i64::from(limit))
    .bind(i64::from(offset))
    .fetch_all(&mut *conn)
    .await?;
    rows.into_iter()
        .map(|row| {
            Ok(ToolkitListing {
                toolkit_id: identity(row.try_get::<String, _>("toolkit_id")?)?,
                name: Name::new(row.try_get::<String, _>("name")?)
                    .map_err(|_| ToolkitStoreError::Corrupt("toolkit name"))?,
                revision: positive_revision(row.try_get::<i64, _>("revision")?)?,
            })
        })
        .collect()
}

/// One toolkit audit row. Toolkit actions pass no artifact version, exactly as the reference.
async fn audit(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    actor: &Attribution,
    entity: &Uuid7,
    revision: PositiveVersion,
    action: &'static str,
) -> Result<(), ToolkitStoreError> {
    sqlx::query(
        "INSERT INTO public.mcp_access_events(event_id,tenant_id,subject,license_id,entity_id,\
         revision,action,artifact_version) VALUES (uuidv7(),$1::uuid,$2,$3::uuid,$4::uuid,$5,$6,$7)",
    )
    .bind(tenant.as_str())
    .bind(actor.subject.as_str())
    .bind(actor.license_id.as_ref().map(AuthorityId::as_str))
    .bind(entity.as_str())
    .bind(i64::from(revision.get()))
    .bind(action)
    .bind(None::<i32>)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

fn snapshot<T: Serialize>(value: &T) -> Result<Value, ToolkitStoreError> {
    serde_json::to_value(value).map_err(|_| ToolkitStoreError::Corrupt("toolkit snapshot"))
}

fn identity(value: String) -> Result<Uuid7, ToolkitStoreError> {
    Uuid7::new(value).map_err(|_| ToolkitStoreError::Corrupt("toolkit identity"))
}

fn positive_revision(value: i64) -> Result<PositiveVersion, ToolkitStoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(ToolkitStoreError::Corrupt("positive version"))
}

fn positive_bits(value: i32) -> Result<PositiveVersion, ToolkitStoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(ToolkitStoreError::Corrupt("toolkit version counter"))
}

fn status_text(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "draft",
        VersionStatus::Published => "published",
        VersionStatus::Disabled => "disabled",
        VersionStatus::Retired => "retired",
    }
}

fn status_action(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "toolkit.draft",
        VersionStatus::Published => "toolkit.published",
        VersionStatus::Disabled => "toolkit.disabled",
        VersionStatus::Retired => "toolkit.retired",
    }
}

fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

fn positive(value: i64) -> Result<PositiveVersion, CatalogStoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(CatalogStoreError::Corrupt("positive version"))
}

fn parse_status(value: &str) -> Result<VersionStatus, CatalogStoreError> {
    match value {
        "draft" => Ok(VersionStatus::Draft),
        "published" => Ok(VersionStatus::Published),
        "disabled" => Ok(VersionStatus::Disabled),
        "retired" => Ok(VersionStatus::Retired),
        _ => Err(CatalogStoreError::Corrupt("version status")),
    }
}
