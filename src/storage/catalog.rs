//! Transactional complete snapshots. Every tenant operation requires explicit ownership.
//!
//! Ported from the reference `src/storage/catalog.py` (`CatalogRepository`): the same
//! statements, the same conflict/not-found boundaries and the same audit actions. Every
//! statement is tenant-explicit (`WHERE tenant_id = $1`); there is no row-level security and no
//! session variable, exactly as the reference.
//!
//! One implementation detail is expressed in SQL because this crate carries no UUID generator:
//! `mcp_access_events.event_id` is minted by Postgres 18's `uuidv7()`, which satisfies the
//! table's version-7 check. The reference mints it with Python's `uuid.uuid7()`.
//!
//! Deliberately not ported in this slice: the reference's optional `conn` parameter on the
//! write methods (the builder flows that share a caller's transaction are another slice) and
//! `PlatformCatalogRepository` (the operator path, not the tenant tool catalog).

use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::{VersionStatus, tool_transition_allowed};
use crate::catalog::models::{
    Attribution, ExactReference, OperationManifest, ServiceManifest, ToolManifest,
    VersionDescriptor,
};
use crate::catalog::package::PackageFile;

/// A refused or impossible catalog storage operation.
#[derive(Debug, Error)]
pub enum CatalogStoreError {
    /// The reference's `CatalogConflictError`: an identity, expected-revision or lifecycle
    /// conflict. The message is the reference's message.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `CatalogNotFoundError`: no version or identity owned by this tenant.
    #[error("{0}")]
    NotFound(&'static str),
    /// A stored row no longer satisfies the domain model (schema drift, not a request error).
    #[error("stored catalog row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed the statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl CatalogStoreError {
    /// The reference's exception type for a unique violation.
    fn map_unique_violation(error: sqlx::Error) -> Self {
        match &error {
            sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
                Self::Conflict("tool identity or public name already exists")
            }
            _ => Self::Database(error),
        }
    }
}

/// One row of [`CatalogRepository::definitions`]: a version without its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolDefinition {
    /// A UUIDv7 identity.
    pub tool_id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The identity's public name.
    pub public_name: Name,
    /// The identity's revision.
    pub revision: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
}

/// The reference `append` arguments: the owned target, the submitted snapshot and the
/// expected-revision guard. `source` is not here because only the copy flow (not this slice)
/// sets it.
#[derive(Debug, Clone, Copy)]
pub struct AppendRequest<'a> {
    /// The owning tenant.
    pub tenant_id: &'a AuthorityId,
    /// The target identity.
    pub tool_id: &'a Uuid7,
    /// The submitted manifest; its `version` is only a template.
    pub content: &'a ToolManifest,
    /// The submitted package files.
    pub files: &'a [PackageFile],
    /// Who is appending.
    pub actor: &'a Attribution,
    /// Refuse unless the identity is still at this revision.
    pub expected_revision: Option<PositiveVersion>,
    /// Refuse unless the submitted version is exactly the next one.
    pub exact_version: bool,
}

/// The tenant tool catalog. One repository is shared; every call names its tenant.
#[derive(Debug, Clone)]
pub struct CatalogRepository {
    pool: PgPool,
}

impl CatalogRepository {
    /// Bind the repository to a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// One tenant-owned version, or the reference's not-found refusal.
    pub async fn get_version(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
    ) -> Result<VersionDescriptor, CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        Self::version_on(&mut conn, tenant_id, tool_id, version).await
    }

    /// Highest version of an owned identity, or `None` when the identity does not exist.
    pub async fn latest_version(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
    ) -> Result<Option<VersionDescriptor>, CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT v.tenant_id::text AS tenant_id, v.tool_id::text AS tool_id, v.version, \
             v.status, v.manifest, v.created_by, v.source_tool_id::text AS source_tool_id, \
             v.source_version, t.revision \
             FROM public.mcp_tool_versions v JOIN public.mcp_tools t USING (tenant_id, tool_id) \
             WHERE v.tenant_id = $1::uuid AND v.tool_id = $2::uuid \
             ORDER BY v.version DESC LIMIT 1",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .fetch_optional(&mut *conn)
        .await?;
        row.as_ref().map(decode_version).transpose()
    }

    /// The files of one tenant-owned version, ordered by path.
    pub async fn files(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
    ) -> Result<Vec<PackageFile>, CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        Self::version_on(&mut conn, tenant_id, tool_id, version).await?;
        let rows = sqlx::query(
            "SELECT path, content FROM public.mcp_tool_version_files \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid AND version = $3 \
             ORDER BY path",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .bind(version_bits(version))
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(PackageFile {
                    path: row.try_get("path")?,
                    content: row.try_get("content")?,
                })
            })
            .collect()
    }

    /// Create the identity and its first version in one transaction.
    pub async fn create(
        &self,
        tenant_id: &AuthorityId,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
    ) -> Result<VersionDescriptor, CatalogStoreError> {
        if &manifest.tenant_id != tenant_id || manifest.version.get() != 1 {
            return Err(CatalogStoreError::Conflict(
                "identity ownership or first version mismatch",
            ));
        }
        let result = async {
            let mut tx = self.pool.begin().await?;
            sqlx::query(
                "INSERT INTO public.mcp_tools(tenant_id,tool_id,public_name,created_by) \
                 VALUES ($1::uuid,$2::uuid,$3,$4)",
            )
            .bind(tenant_id.as_str())
            .bind(manifest.tool_id.as_str())
            .bind(manifest.public_name.as_str())
            .bind(snapshot(actor)?)
            .execute(&mut *tx)
            .await?;
            Self::insert_version(&mut tx, manifest, files, actor, None).await?;
            let result =
                Self::version_on(&mut tx, tenant_id, &manifest.tool_id, manifest.version).await?;
            Self::audit(&mut tx, &result, actor, "tool.created").await?;
            tx.commit().await?;
            Ok(result)
        }
        .await;
        match result {
            Err(CatalogStoreError::Database(error)) => {
                Err(CatalogStoreError::map_unique_violation(error))
            }
            other => other,
        }
    }

    /// Append a version. The content's artifact version is a template; `max(version) + 1` is
    /// allocated under the parent's row lock.
    pub async fn append(
        &self,
        request: &AppendRequest<'_>,
        source: Option<&ExactReference>,
    ) -> Result<VersionDescriptor, CatalogStoreError> {
        let AppendRequest {
            tenant_id,
            tool_id,
            content,
            files,
            actor,
            expected_revision,
            exact_version,
        } = *request;
        if &content.tenant_id != tenant_id || &content.tool_id != tool_id {
            return Err(CatalogStoreError::Conflict(
                "content identity differs from owned target",
            ));
        }
        let mut tx = self.pool.begin().await?;
        let parent = Self::lock(&mut tx, tenant_id, tool_id, expected_revision).await?;
        if parent.retired || parent.public_name != content.public_name.as_str() {
            return Err(CatalogStoreError::Conflict(
                "retired identity or public name mismatch",
            ));
        }
        let next: i32 = sqlx::query_scalar(
            "SELECT coalesce(max(version),0)+1 FROM public.mcp_tool_versions \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if exact_version && version_bits(content.version) != next {
            return Err(CatalogStoreError::Conflict(
                "manifest version must be the next version",
            ));
        }
        let mut manifest = content.clone();
        manifest.version = positive(i64::from(next)).map_err(|_| {
            CatalogStoreError::Conflict("manifest version must be the next version")
        })?;
        Self::insert_version(&mut tx, &manifest, files, actor, source).await?;
        sqlx::query(
            "UPDATE public.mcp_tools SET revision=revision+1 \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .execute(&mut *tx)
        .await?;
        let result = Self::version_on(&mut tx, tenant_id, tool_id, manifest.version).await?;
        Self::audit(&mut tx, &result, actor, "tool.version_created").await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Move one version through the reference's lifecycle machine.
    pub async fn transition(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
        status: VersionStatus,
        actor: &Attribution,
        expected_revision: PositiveVersion,
    ) -> Result<VersionDescriptor, CatalogStoreError> {
        let mut tx = self.pool.begin().await?;
        let parent = Self::lock(&mut tx, tenant_id, tool_id, Some(expected_revision)).await?;
        let row = Self::version_on(&mut tx, tenant_id, tool_id, version).await?;
        if !tool_transition_allowed(row.status, status) {
            return Err(CatalogStoreError::Conflict("invalid lifecycle transition"));
        }
        if status == VersionStatus::Published {
            if parent.retired {
                return Err(CatalogStoreError::Conflict("identity retired"));
            }
            let dependencies = sqlx::query(
                "SELECT o.status AS operation_status, s.status AS service_status \
                 FROM public.mcp_tool_version_operations r \
                 JOIN public.mcp_operation_versions o \
                   ON (o.operation_id,o.version)=(r.operation_id,r.operation_version) \
                 JOIN public.mcp_service_versions s \
                   ON (s.service_id,s.version)=(o.service_id,o.service_version) \
                 WHERE r.tenant_id = $1::uuid AND r.tool_id = $2::uuid AND r.version = $3",
            )
            .bind(tenant_id.as_str())
            .bind(tool_id.as_str())
            .bind(version_bits(version))
            .fetch_all(&mut *tx)
            .await?;
            for dependency in &dependencies {
                let operation_status: String = dependency.try_get("operation_status")?;
                let service_status: String = dependency.try_get("service_status")?;
                if operation_status != "published" || service_status != "published" {
                    return Err(CatalogStoreError::Conflict(
                        "operation or service is not published",
                    ));
                }
            }
        }
        sqlx::query(
            "UPDATE public.mcp_tool_versions SET status=$1,updated_by=$2,updated_at=clock_timestamp() \
             WHERE tenant_id = $3::uuid AND tool_id = $4::uuid AND version = $5",
        )
        .bind(status_text(status))
        .bind(snapshot(actor)?)
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .bind(version_bits(version))
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "UPDATE public.mcp_tools SET revision=revision+1 \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .execute(&mut *tx)
        .await?;
        let result = Self::version_on(&mut tx, tenant_id, tool_id, version).await?;
        let action = match status {
            VersionStatus::Published => "tool.published",
            VersionStatus::Disabled => "tool.disabled",
            VersionStatus::Retired => "tool.retired",
            VersionStatus::Draft => {
                return Err(CatalogStoreError::Conflict("invalid lifecycle transition"));
            }
        };
        Self::audit(&mut tx, &result, actor, action).await?;
        tx.commit().await?;
        Ok(result)
    }

    /// Every tenant version (all statuses), ordered by identity then version.
    pub async fn definitions(
        &self,
        tenant_id: &AuthorityId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<ToolDefinition>, CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        let rows = sqlx::query(
            "SELECT v.tool_id::text AS tool_id, v.version, t.public_name, t.revision, v.status \
             FROM public.mcp_tool_versions v JOIN public.mcp_tools t USING(tenant_id,tool_id) \
             WHERE v.tenant_id = $1::uuid ORDER BY v.tool_id,v.version LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id.as_str())
        .bind(i64::from(limit))
        .bind(i64::from(offset))
        .fetch_all(&mut *conn)
        .await?;
        rows.iter()
            .map(|row| {
                let status: String = row.try_get("status")?;
                Ok(ToolDefinition {
                    tool_id: identity7(row.try_get::<String, _>("tool_id")?)?,
                    version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
                    public_name: parse_name(row.try_get::<String, _>("public_name")?)?,
                    revision: positive(row.try_get::<i64, _>("revision")?)?,
                    status: parse_status(&status)?,
                })
            })
            .collect()
    }

    /// Retire the identity. The reference records no audit row for this write.
    pub async fn retire(
        &self,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        expected_revision: PositiveVersion,
    ) -> Result<(), CatalogStoreError> {
        let mut tx = self.pool.begin().await?;
        let parent = Self::lock(&mut tx, tenant_id, tool_id, Some(expected_revision)).await?;
        if parent.retired {
            return Err(CatalogStoreError::Conflict("identity already retired"));
        }
        sqlx::query(
            "UPDATE public.mcp_tools SET retired=true,revision=revision+1 \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .execute(&mut *tx)
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// One exact platform operation version and its status.
    pub async fn operation(
        &self,
        reference: &ExactReference,
    ) -> Result<(OperationManifest, VersionStatus), CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT manifest,status FROM public.mcp_operation_versions \
             WHERE operation_id = $1::uuid AND version = $2",
        )
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound("exact operation not found"))?;
        let manifest: Value = row.try_get("manifest")?;
        let manifest = serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("operation manifest"))?;
        let status: String = row.try_get("status")?;
        Ok((manifest, parse_status(&status)?))
    }

    /// `CatalogRepository.service_owner`: the platform tenant or the authoring tenant that owns a
    /// service identity. The broker resolves a source as `(owner, destination_alias)`, so the
    /// owner is what keeps a tenant source from serving a platform service.
    pub async fn service_owner(
        &self,
        service_id: &Uuid7,
    ) -> Result<AuthorityId, CatalogStoreError> {
        let owner: Option<String> = sqlx::query_scalar(
            "SELECT owner_tenant_id::text FROM public.mcp_services WHERE service_id = $1::uuid",
        )
        .bind(service_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let owner = owner.ok_or(CatalogStoreError::NotFound("service not found"))?;
        AuthorityId::new(owner).map_err(|_| CatalogStoreError::Corrupt("service owner"))
    }

    /// `CatalogRepository.may_use_service`: the rule the database enforces on tool versions —
    /// own services, granted platform services, and licence-kind platform services. The broker
    /// re-checks it per call.
    pub async fn may_use_service(
        &self,
        tenant_id: &AuthorityId,
        reference: &ExactReference,
    ) -> Result<bool, CatalogStoreError> {
        let allowed: Option<bool> = sqlx::query_scalar(
            "SELECT public.mcp_tenant_may_use_service($1::uuid,$2::uuid,$3) AS ok",
        )
        .bind(tenant_id.as_str())
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .fetch_optional(&self.pool)
        .await?;
        Ok(allowed.unwrap_or(false))
    }

    /// One exact platform service version and its status.
    pub async fn service(
        &self,
        reference: &ExactReference,
    ) -> Result<(ServiceManifest, VersionStatus), CatalogStoreError> {
        let mut conn = self.pool.acquire().await?;
        let row = sqlx::query(
            "SELECT manifest,status FROM public.mcp_service_versions \
             WHERE service_id = $1::uuid AND version = $2",
        )
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound("exact service not found"))?;
        let manifest: Value = row.try_get("manifest")?;
        let manifest = serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("service manifest"))?;
        let status: String = row.try_get("status")?;
        Ok((manifest, parse_status(&status)?))
    }

    /// One tenant-owned version joined with its identity's current revision.
    async fn version_on(
        conn: &mut PgConnection,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        version: PositiveVersion,
    ) -> Result<VersionDescriptor, CatalogStoreError> {
        let row = sqlx::query(
            "SELECT v.tenant_id::text AS tenant_id, v.tool_id::text AS tool_id, v.version, \
             v.status, v.manifest, v.created_by, v.source_tool_id::text AS source_tool_id, \
             v.source_version, t.revision \
             FROM public.mcp_tool_versions v JOIN public.mcp_tools t USING (tenant_id, tool_id) \
             WHERE v.tenant_id = $1::uuid AND v.tool_id = $2::uuid AND v.version = $3",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .bind(version_bits(version))
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound(
            "tenant-owned version not found",
        ))?;
        decode_version(&row)
    }

    /// Insert the version snapshot and its children. The children must be written in the same
    /// transaction as the version row; the database checks that at commit.
    async fn insert_version(
        conn: &mut PgConnection,
        manifest: &ToolManifest,
        files: &[PackageFile],
        actor: &Attribution,
        source: Option<&ExactReference>,
    ) -> Result<(), CatalogStoreError> {
        let actor = snapshot(actor)?;
        let (source_tool_id, source_version) = match source {
            Some(reference) => (
                Some(reference.id.as_str()),
                Some(version_bits(reference.version)),
            ),
            None => (None, None),
        };
        sqlx::query(
            "INSERT INTO public.mcp_tool_versions(tenant_id,tool_id,version,manifest,package_sha256,\
             file_count,operation_count,created_by,updated_by,source_tool_id,source_version) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$8,$9::uuid,$10)",
        )
        .bind(manifest.tenant_id.as_str())
        .bind(manifest.tool_id.as_str())
        .bind(version_bits(manifest.version))
        .bind(snapshot(manifest)?)
        .bind(manifest.package_sha256.as_str())
        .bind(child_count(files.len(), "package file count outside configured limit")?)
        .bind(child_count(
            manifest.allowed_operations.len(),
            "operation count outside configured limit",
        )?)
        .bind(actor)
        .bind(source_tool_id)
        .bind(source_version)
        .execute(&mut *conn)
        .await?;
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

    /// Lock the parent identity and enforce the caller's expected revision.
    async fn lock(
        conn: &mut PgConnection,
        tenant_id: &AuthorityId,
        tool_id: &Uuid7,
        expected_revision: Option<PositiveVersion>,
    ) -> Result<Parent, CatalogStoreError> {
        let row = sqlx::query(
            "SELECT revision,retired,public_name FROM public.mcp_tools \
             WHERE tenant_id = $1::uuid AND tool_id = $2::uuid FOR UPDATE",
        )
        .bind(tenant_id.as_str())
        .bind(tool_id.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound(
            "tenant-owned identity not found",
        ))?;
        let revision: i64 = row.try_get("revision")?;
        if expected_revision.is_some_and(|expected| i64::from(expected.get()) != revision) {
            return Err(CatalogStoreError::Conflict("stale expected revision"));
        }
        Ok(Parent {
            retired: row.try_get("retired")?,
            public_name: row.try_get("public_name")?,
        })
    }

    /// Append one audit row. The action strings are the reference's.
    async fn audit(
        conn: &mut PgConnection,
        result: &VersionDescriptor,
        actor: &Attribution,
        action: &'static str,
    ) -> Result<(), CatalogStoreError> {
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

/// The columns [`CatalogRepository::lock`] needs from the parent identity.
struct Parent {
    retired: bool,
    public_name: String,
}

fn decode_version(row: &PgRow) -> Result<VersionDescriptor, CatalogStoreError> {
    let status: String = row.try_get("status")?;
    let source_tool_id: Option<String> = row.try_get("source_tool_id")?;
    let source_version: Option<i32> = row.try_get("source_version")?;
    let source = match (source_tool_id, source_version) {
        (Some(id), Some(version)) => Some(ExactReference {
            id: identity7(id)?,
            version: positive(i64::from(version))?,
        }),
        (None, None) => None,
        _ => return Err(CatalogStoreError::Corrupt("version source")),
    };
    Ok(VersionDescriptor {
        tenant_id: parse_authority(row.try_get::<String, _>("tenant_id")?)?,
        tool_id: identity7(row.try_get::<String, _>("tool_id")?)?,
        version: positive(i64::from(row.try_get::<i32, _>("version")?))?,
        revision: positive(row.try_get::<i64, _>("revision")?)?,
        status: parse_status(&status)?,
        manifest: serde_json::from_value(row.try_get::<Value, _>("manifest")?)
            .map_err(|_| CatalogStoreError::Corrupt("tool manifest"))?,
        created_by: serde_json::from_value(row.try_get::<Value, _>("created_by")?)
            .map_err(|_| CatalogStoreError::Corrupt("created_by attribution"))?,
        source,
    })
}

/// The reference's `snapshot`: the JSON form stored in every `jsonb` column.
fn snapshot<T: Serialize>(value: &T) -> Result<Value, CatalogStoreError> {
    serde_json::to_value(value).map_err(|_| CatalogStoreError::Corrupt("catalog snapshot"))
}

/// A version column as the reference's `PositiveVersion`.
fn positive(value: i64) -> Result<PositiveVersion, CatalogStoreError> {
    let value = u64::try_from(value).map_err(|_| CatalogStoreError::Corrupt("version"))?;
    PositiveVersion::new(value).map_err(|_| CatalogStoreError::Corrupt("version"))
}

/// A [`PositiveVersion`] as the `integer` a version column stores.
fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

fn child_count(value: usize, message: &'static str) -> Result<i32, CatalogStoreError> {
    i32::try_from(value).map_err(|_| CatalogStoreError::Conflict(message))
}

fn parse_authority(value: String) -> Result<AuthorityId, CatalogStoreError> {
    AuthorityId::new(value).map_err(|_| CatalogStoreError::Corrupt("tenant identity"))
}

fn identity7(value: String) -> Result<Uuid7, CatalogStoreError> {
    Uuid7::new(value).map_err(|_| CatalogStoreError::Corrupt("tool identity"))
}

fn parse_name(value: String) -> Result<Name, CatalogStoreError> {
    Name::new(value).map_err(|_| CatalogStoreError::Corrupt("public name"))
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

fn status_text(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "draft",
        VersionStatus::Published => "published",
        VersionStatus::Disabled => "disabled",
        VersionStatus::Retired => "retired",
    }
}
