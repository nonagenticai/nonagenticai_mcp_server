//! Toolkit reads. Every statement is tenant-explicit and takes the caller's connection, so the
//! caller owns the transaction. The statements are the reference's (`src/storage/bindings.py`
//! and `src/toolkits/resolver.py`), with the same conflict/not-found boundaries.

use std::collections::HashMap;

use serde_json::Value;
use sqlx::{PgConnection, Row};

use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::ToolManifest;
use crate::catalog::toolkit_models::{ToolReference, ToolkitDescriptor};
use crate::storage::catalog::CatalogStoreError;

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
