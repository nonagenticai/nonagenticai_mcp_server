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
//! Deliberately not ported in the tenant slice: the reference's optional `conn` parameter on
//! the write methods (the builder flows that share a caller's transaction are another slice).
//! `PlatformCatalogRepository` lives at the bottom of this file: the operator path over the
//! platform pool, never supplied as a tenant or agent dependency.

use serde::Serialize;
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

use crate::catalog::ids::{AppKey, AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::{VersionStatus, tool_transition_allowed};
use crate::catalog::models::{
    Attribution, AuthAdapter, ExactReference, OperationManifest, ServiceManifest, ToolManifest,
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

// ── platform authoring: the operator path over the platform pool ─────────────────────────────

/// A refused platform-catalog storage operation.
///
/// The variants are the reference's exception boundaries: a conflict (`CatalogConflictError`
/// or a check/unique violation), a missing exact version (`CatalogNotFoundError`), a source
/// that cannot serve the service (`SourceUnavailableError`), a request the database refused on
/// a reference (`ForeignKeyViolation`), and an unreadable stored row.
#[derive(Debug, Error)]
pub enum PlatformStoreError {
    /// The reference's `CatalogConflictError`.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `CatalogNotFoundError`.
    #[error("{0}")]
    NotFound(&'static str),
    /// The reference's `SourceUnavailableError`.
    #[error("{0}")]
    SourceUnavailable(&'static str),
    /// A refused reference (the reference's `ForeignKeyViolation`).
    #[error("{0}")]
    Invalid(&'static str),
    /// A stored row no longer satisfies the domain model.
    #[error("stored platform catalog row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed the statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

impl From<CatalogStoreError> for PlatformStoreError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::Conflict(_) => Self::Conflict("catalog conflict"),
            CatalogStoreError::NotFound(_) => Self::NotFound("catalog version not found"),
            CatalogStoreError::Corrupt(_) => Self::Corrupt("catalog row"),
            CatalogStoreError::Database(error) => Self::Database(error),
        }
    }
}

/// The two contract kinds the platform repository addresses. A closed set: it only ever
/// selects one of two literal statements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PlatformKind {
    /// `mcp_service_versions`
    Service,
    /// `mcp_operation_versions`
    Operation,
}

/// `PlatformCatalogRepository.latest_service`: the newest service version of one identity.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestService {
    /// The newest version.
    pub version: PositiveVersion,
    /// The identity's revision, read with the version.
    pub revision: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
    /// The stored manifest.
    pub manifest: ServiceManifest,
}

/// `PlatformCatalogRepository.latest_operation`: the newest operation version of one identity.
#[derive(Debug, Clone, PartialEq)]
pub struct LatestOperation {
    /// The newest version.
    pub version: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
    /// The stored manifest.
    pub manifest: OperationManifest,
}

/// One row of [`PlatformCatalogRepository::definitions`]: a version without its manifest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlatformDefinition {
    /// The service or operation identity.
    pub id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
}

/// The reference's `PlatformCatalogRepository`: separate operator path, never supplied as a
/// tenant/agent dependency. Every statement is the reference's, verbatim.
#[derive(Debug, Clone)]
pub struct PlatformCatalogRepository {
    pool: PgPool,
}

impl PlatformCatalogRepository {
    /// Bind the repository to the platform pool (`MCP_PLATFORM_DATABASE_URL`).
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Newest service version as `{version, revision, status, manifest}`, or `None`.
    pub async fn latest_service(
        &self,
        service_id: &Uuid7,
    ) -> Result<Option<LatestService>, PlatformStoreError> {
        let row = sqlx::query(
            "SELECT v.version,v.status,v.manifest,s.revision FROM public.mcp_service_versions v \
             JOIN public.mcp_services s USING (service_id) WHERE v.service_id = $1::uuid \
             ORDER BY v.version DESC LIMIT 1",
        )
        .bind(service_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: String = row.try_get("status")?;
        Ok(Some(LatestService {
            version: platform_positive(i64::from(row.try_get::<i32, _>("version")?))?,
            revision: platform_positive(row.try_get::<i64, _>("revision")?)?,
            status: platform_status(&status)?,
            manifest: platform_manifest(row.try_get("manifest")?, "service manifest")?,
        }))
    }

    /// Newest operation version as `{version, status, manifest}`, or `None`.
    pub async fn latest_operation(
        &self,
        operation_id: &Uuid7,
    ) -> Result<Option<LatestOperation>, PlatformStoreError> {
        let row = sqlx::query(
            "SELECT version,status,manifest FROM public.mcp_operation_versions \
             WHERE operation_id = $1::uuid ORDER BY version DESC LIMIT 1",
        )
        .bind(operation_id.as_str())
        .fetch_optional(&self.pool)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        let status: String = row.try_get("status")?;
        Ok(Some(LatestOperation {
            version: platform_positive(i64::from(row.try_get::<i32, _>("version")?))?,
            status: platform_status(&status)?,
            manifest: platform_manifest(row.try_get("manifest")?, "operation manifest")?,
        }))
    }

    /// Create the service identity at version 1, or append the next version under the
    /// identity's row lock after checking the caller's expected revision and the service key.
    pub async fn add_service(
        &self,
        manifest: &ServiceManifest,
        actor: &Attribution,
        expected_revision: Option<i64>,
    ) -> Result<(), PlatformStoreError> {
        let result: Result<(), PlatformStoreError> = async {
            let mut tx = self.pool.begin().await?;
            if manifest.version.get() == 1 {
                sqlx::query(
                    "INSERT INTO public.mcp_services(service_id,service_key,created_by) \
                     VALUES ($1::uuid,$2,$3)",
                )
                .bind(manifest.service_id.as_str())
                .bind(manifest.service_key.as_str())
                .bind(platform_snapshot(actor)?)
                .execute(&mut *tx)
                .await?;
            } else {
                let row = sqlx::query(
                    "SELECT revision,service_key FROM public.mcp_services \
                     WHERE service_id = $1::uuid FOR UPDATE",
                )
                .bind(manifest.service_id.as_str())
                .fetch_optional(&mut *tx)
                .await?;
                let matched = match &row {
                    Some(row) => {
                        let revision: i64 = row.try_get("revision")?;
                        let service_key: String = row.try_get("service_key")?;
                        expected_revision == Some(revision)
                            && service_key == manifest.service_key.as_str()
                    }
                    None => false,
                };
                if !matched {
                    return Err(PlatformStoreError::Conflict(
                        "service identity or revision mismatch",
                    ));
                }
                let next: Option<i32> = sqlx::query_scalar(
                    "SELECT max(version)+1 AS next FROM public.mcp_service_versions \
                     WHERE service_id = $1::uuid",
                )
                .bind(manifest.service_id.as_str())
                .fetch_one(&mut *tx)
                .await?;
                if next != Some(version_bits(manifest.version)) {
                    return Err(PlatformStoreError::Conflict("service version must append"));
                }
                sqlx::query(
                    "UPDATE public.mcp_services SET revision=revision+1 \
                     WHERE service_id = $1::uuid",
                )
                .bind(manifest.service_id.as_str())
                .execute(&mut *tx)
                .await?;
            }
            let actor = platform_snapshot(actor)?;
            sqlx::query(
                "INSERT INTO public.mcp_service_versions(service_id,version,manifest,created_by,\
                 updated_by) VALUES ($1::uuid,$2,$3,$4,$5)",
            )
            .bind(manifest.service_id.as_str())
            .bind(version_bits(manifest.version))
            .bind(platform_snapshot(manifest)?)
            .bind(actor.clone())
            .bind(actor)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        result.map_err(platform_database_error)
    }

    /// Append the next operation version. The allocated version is checked under an advisory
    /// lock on the identity, exactly as the reference does.
    pub async fn add_operation(
        &self,
        manifest: &OperationManifest,
        actor: &Attribution,
    ) -> Result<(), PlatformStoreError> {
        let result: Result<(), PlatformStoreError> = async {
            let mut tx = self.pool.begin().await?;
            sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1::text,0))")
                .bind(manifest.operation_id.as_str())
                .execute(&mut *tx)
                .await?;
            let next: Option<i32> = sqlx::query_scalar(
                "SELECT coalesce(max(version),0)+1 AS next FROM public.mcp_operation_versions \
                 WHERE operation_id = $1::uuid",
            )
            .bind(manifest.operation_id.as_str())
            .fetch_one(&mut *tx)
            .await?;
            if next != Some(version_bits(manifest.version)) {
                return Err(PlatformStoreError::Conflict(
                    "operation version must append",
                ));
            }
            let actor = platform_snapshot(actor)?;
            sqlx::query(
                "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
                 service_version,manifest,created_by,updated_by) \
                 VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6,$7)",
            )
            .bind(manifest.operation_id.as_str())
            .bind(version_bits(manifest.version))
            .bind(manifest.service.id.as_str())
            .bind(version_bits(manifest.service.version))
            .bind(platform_snapshot(manifest)?)
            .bind(actor.clone())
            .bind(actor)
            .execute(&mut *tx)
            .await?;
            tx.commit().await?;
            Ok(())
        }
        .await;
        result.map_err(platform_database_error)
    }

    /// Insert the importer's version-1 drafts in one transaction, exactly as the reference's
    /// `/mcp/operations/import` handler does.
    pub async fn insert_operation_drafts(
        &self,
        manifests: &[OperationManifest],
        actor: &Attribution,
    ) -> Result<(), PlatformStoreError> {
        let result: Result<(), PlatformStoreError> = async {
            let mut tx = self.pool.begin().await?;
            let actor = platform_snapshot(actor)?;
            for manifest in manifests {
                sqlx::query(
                    "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
                     service_version,manifest,created_by,updated_by) \
                     VALUES ($1::uuid,$2,$3::uuid,$4,$5,$6,$7)",
                )
                .bind(manifest.operation_id.as_str())
                .bind(version_bits(manifest.version))
                .bind(manifest.service.id.as_str())
                .bind(version_bits(manifest.service.version))
                .bind(platform_snapshot(manifest)?)
                .bind(actor.clone())
                .bind(actor.clone())
                .execute(&mut *tx)
                .await?;
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        result.map_err(platform_database_error)
    }

    /// Move one exact platform version to a lifecycle state.
    pub async fn transition(
        &self,
        kind: PlatformKind,
        reference: &ExactReference,
        status: VersionStatus,
        actor: &Attribution,
    ) -> Result<(), PlatformStoreError> {
        if !matches!(
            status,
            VersionStatus::Published | VersionStatus::Disabled | VersionStatus::Retired
        ) {
            return Err(PlatformStoreError::Conflict("invalid lifecycle state"));
        }
        let result: Result<(), PlatformStoreError> = async {
            let mut tx = self.pool.begin().await?;
            if kind == PlatformKind::Service && status == VersionStatus::Published {
                Self::require_source(&mut tx, reference).await?;
            }
            if kind == PlatformKind::Operation && status == VersionStatus::Published {
                let row = sqlx::query(
                    "SELECT s.status FROM public.mcp_operation_versions o JOIN \
                     public.mcp_service_versions s ON \
                     (s.service_id,s.version)=(o.service_id,o.service_version) \
                     WHERE o.operation_id = $1::uuid AND o.version = $2 FOR SHARE OF s",
                )
                .bind(reference.id.as_str())
                .bind(version_bits(reference.version))
                .fetch_optional(&mut *tx)
                .await?;
                let published = match &row {
                    Some(row) => row.try_get::<String, _>("status")? == "published",
                    None => false,
                };
                if !published {
                    return Err(PlatformStoreError::Conflict("service must be published"));
                }
            }
            let statement = match kind {
                PlatformKind::Service => {
                    "UPDATE public.mcp_service_versions SET status=$1,updated_by=$2,\
                     updated_at=clock_timestamp() WHERE service_id = $3::uuid AND version = $4 \
                     RETURNING version"
                }
                PlatformKind::Operation => {
                    "UPDATE public.mcp_operation_versions SET status=$1,updated_by=$2,\
                     updated_at=clock_timestamp() WHERE operation_id = $3::uuid AND version = $4 \
                     RETURNING version"
                }
            };
            let updated: Option<i32> = sqlx::query_scalar(statement)
                .bind(status_text(status))
                .bind(platform_snapshot(actor)?)
                .bind(reference.id.as_str())
                .bind(version_bits(reference.version))
                .fetch_optional(&mut *tx)
                .await?;
            if updated.is_none() {
                return Err(PlatformStoreError::NotFound(
                    "exact platform version not found",
                ));
            }
            tx.commit().await?;
            Ok(())
        }
        .await;
        result.map_err(platform_database_error)
    }

    /// Every platform version of one kind (all statuses), ordered by identity then version.
    pub async fn definitions(
        &self,
        kind: PlatformKind,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<PlatformDefinition>, PlatformStoreError> {
        let statement = match kind {
            PlatformKind::Service => {
                "SELECT service_id::text AS identity,version,status FROM public.mcp_service_versions \
                 ORDER BY service_id,version LIMIT $1 OFFSET $2"
            }
            PlatformKind::Operation => {
                "SELECT operation_id::text AS identity,version,status FROM \
                 public.mcp_operation_versions ORDER BY operation_id,version LIMIT $1 OFFSET $2"
            }
        };
        let rows = sqlx::query(statement)
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?;
        rows.iter()
            .map(|row| {
                let status: String = row.try_get("status")?;
                Ok(PlatformDefinition {
                    id: Uuid7::new(row.try_get::<String, _>("identity")?)
                        .map_err(|_| PlatformStoreError::Corrupt("platform identity"))?,
                    version: platform_positive(i64::from(row.try_get::<i32, _>("version")?))?,
                    status: platform_status(&status)?,
                })
            })
            .collect()
    }

    /// Publishing a service needs `destination_alias` to name an active source that agrees
    /// with the service's licence application and auth adapter (the source owns URL and
    /// credential).
    async fn require_source(
        conn: &mut PgConnection,
        reference: &ExactReference,
    ) -> Result<(), PlatformStoreError> {
        let found: Option<Value> = sqlx::query_scalar(
            "SELECT manifest FROM public.mcp_service_versions \
             WHERE service_id = $1::uuid AND version = $2",
        )
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .fetch_optional(&mut *conn)
        .await?;
        let manifest: ServiceManifest = platform_manifest(
            found.ok_or(PlatformStoreError::NotFound(
                "exact platform version not found",
            ))?,
            "service manifest",
        )?;
        let source = sqlx::query(
            "SELECT status,auth FROM public.mcp_sources \
             WHERE owner_tenant_id = public.mcp_platform_tenant() AND source_key = $1 FOR SHARE",
        )
        .bind(manifest.destination_alias.as_str())
        .fetch_optional(&mut *conn)
        .await?;
        let Some(source) = source else {
            return Err(PlatformStoreError::SourceUnavailable(
                "service source is not registered and active",
            ));
        };
        let status: String = source.try_get("status")?;
        if status != "active" {
            return Err(PlatformStoreError::SourceUnavailable(
                "service source is not registered and active",
            ));
        }
        let auth: Value = source.try_get("auth")?;
        if auth.get("kind").and_then(Value::as_str) == Some("licence") {
            let scheme = auth
                .get("scheme")
                .and_then(Value::as_str)
                .unwrap_or("bearer");
            let adapter = match scheme {
                "bearer" => "license_bearer",
                "x_tenant_id_bearer" => "license_header",
                _ => {
                    // The reference would `KeyError` here (a 500); a stored source cannot
                    // name another scheme through its own contract, so refuse it instead.
                    return Err(PlatformStoreError::SourceUnavailable(
                        "service disagrees with its source",
                    ));
                }
            };
            let app_key = auth.get("app_key").and_then(Value::as_str);
            let manifest_key = manifest.license_app_key.as_ref().map(AppKey::as_str);
            if app_key != manifest_key || adapter != adapter_text(manifest.auth_adapter) {
                return Err(PlatformStoreError::SourceUnavailable(
                    "service disagrees with its source",
                ));
            }
        }
        Ok(())
    }
}

/// The reference's `{"bearer": "license_bearer", "x_tenant_id_bearer": "license_header"}`
/// mapping, applied to the service's own adapter.
fn adapter_text(adapter: AuthAdapter) -> &'static str {
    match adapter {
        AuthAdapter::LicenseBearer => "license_bearer",
        AuthAdapter::LicenseHeader => "license_header",
        AuthAdapter::Source => "source",
    }
}

/// The reference's exception boundary for a database failure: an integrity violation is a
/// 409 (`UniqueViolation`/`CheckViolation`) or a 422 (`ForeignKeyViolation`), never a 500.
fn platform_database_error(error: PlatformStoreError) -> PlatformStoreError {
    let code = match &error {
        PlatformStoreError::Database(sqlx::Error::Database(database)) => {
            database.code().map(|code| code.to_string())
        }
        _ => None,
    };
    match code.as_deref() {
        Some("23505" | "23514") => PlatformStoreError::Conflict("catalog constraint violated"),
        Some("23503") => PlatformStoreError::Invalid("catalog reference is missing"),
        _ => error,
    }
}

/// The reference's `snapshot`: the JSON form stored in every `jsonb` column.
fn platform_snapshot<T: Serialize>(value: &T) -> Result<Value, PlatformStoreError> {
    serde_json::to_value(value).map_err(|_| PlatformStoreError::Corrupt("catalog snapshot"))
}

fn platform_manifest<T: serde::de::DeserializeOwned>(
    value: Value,
    what: &'static str,
) -> Result<T, PlatformStoreError> {
    serde_json::from_value(value).map_err(|_| PlatformStoreError::Corrupt(what))
}

fn platform_positive(value: i64) -> Result<PositiveVersion, PlatformStoreError> {
    let value = u64::try_from(value).map_err(|_| PlatformStoreError::Corrupt("version"))?;
    PositiveVersion::new(value).map_err(|_| PlatformStoreError::Corrupt("version"))
}

fn platform_status(value: &str) -> Result<VersionStatus, PlatformStoreError> {
    match value {
        "draft" => Ok(VersionStatus::Draft),
        "published" => Ok(VersionStatus::Published),
        "disabled" => Ok(VersionStatus::Disabled),
        "retired" => Ok(VersionStatus::Retired),
        _ => Err(PlatformStoreError::Corrupt("version status")),
    }
}
