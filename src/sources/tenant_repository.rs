//! A tenant's own tool sources: the runtime-role half of the source catalogue.
//!
//! Port of the reference `src/sources/repository.py:262-547` (`TenantSourceRepository`). The
//! platform half lives in [`crate::sources::repository`]; every statement here names the
//! calling tenant and can only see or change that tenant's rows, so a platform source is never
//! visible through this repository and a tenant source is never visible through the platform
//! one.
//!
//! Every write goes through a `SECURITY DEFINER` `public.mcp_builder_source_*` function (the
//! reference's migration 0010). The functions re-check ownership and the platform-tenant
//! refusal themselves — this port calls them exactly as the reference does and never
//! re-implements their guards. Registration adds what the database cannot check: the port
//! allow-list and, for a `licence` kind source, the operator host allow-list (a minted licence
//! never goes to an arbitrary host).
//!
//! Database refusals surface through [`refused`]: `MB001`/`23505` are conflicts, `MB002` not
//! found, `MB003` the quota, `MB004` the platform-tenant refusal, `23514`/`23503` invalid
//! requests. Only the primary message is kept, never row detail.
//!
//! Nothing here logs or `Debug`-formats a token, a ciphertext or a stored spec document.

use serde_json::Value;
use sqlx::error::DatabaseError as _;
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Postgres, Row, Transaction};
use thiserror::Error;
use uuid::Uuid;

use crate::catalog::ids::AuthorityId;
use crate::catalog::models::Attribution;
use crate::config::SourceSettings;
use crate::sources::crypto::{SourceCryptoError, encrypt_token};
use crate::sources::guard::{GuardError, enforce};
use crate::sources::models::{
    SourceAuth, SourceView, TenantSourceCreate, TenantSourceUpdate, TokenUpdate, checked_secret,
    needs_secret,
};

/// The reference's `VIEW_COLUMNS` (`repository.py:37-42`): what `page`/`get` and every write
/// returning a source view select. Timestamps are rendered as RFC 3339 text with the reference
/// pydantic view's shape, because this crate's `sqlx` build carries no timestamp mapping.
const VIEW_COLUMNS: &str = "source_id::text AS source_id, owner_tenant_id::text AS owner_tenant_id, \
     source_key, revision, status, base_url, allow_internal_http, auth, \
     (token_ciphertext IS NOT NULL) AS has_token, \
     to_char(token_set_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS token_set_at, \
     spec_path, idempotency_header, ca_file, max_request_bytes, max_response_bytes, \
     created_by, updated_by, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS created_at, \
     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS updated_at";

/// A refused or impossible tenant source operation. Each message is the reference's.
#[derive(Debug, Error)]
pub enum TenantSourceError {
    /// The reference's `CatalogNotFoundError`: no source with that key owned by the tenant.
    #[error("{0}")]
    NotFound(String),
    /// The reference's `CatalogConflictError`: a stale expected revision, a state the row is
    /// already in, or a key already in use.
    #[error("{0}")]
    Conflict(String),
    /// The reference's `ValueError`: a request the source contract refuses (422).
    #[error("{0}")]
    Invalid(String),
    /// The reference's `QuotaExceededError`, whose message is `"<resource> quota exceeded"`.
    #[error("{0} quota exceeded")]
    Quota(&'static str),
    /// The reference's `BuilderForbiddenError`: the platform tenant never authors.
    #[error("{0}")]
    Forbidden(String),
    /// The reference's `SourceSecretUnavailableError`: no `MCP_SOURCE_SECRET_KEY`, so a static
    /// token cannot be stored.
    #[error("source secret key is not configured")]
    SecretUnavailable,
    /// The reference's `enforce`: a destination the operator has not approved.
    #[error(transparent)]
    Guard(#[from] GuardError),
    /// A stored row no longer satisfies the domain model.
    #[error("stored source row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed the statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// The reference's `from_settings` inputs (`config.py:141-160`).
///
/// The reference reads them from its one `Settings` object. This crate's `Config` carries the
/// `MCP_SOURCE_*` pair only, so the tenant-builder bounds are their own value: the reference's
/// defaults here, and a deployment's `MCP_BUILDER_*` values can overwrite the public fields
/// before [`TenantSourceRepository::from_settings`] is called.
#[derive(Clone, PartialEq, Eq)]
pub struct TenantSourceSettings {
    /// The decoded `MCP_SOURCE_SECRET_KEY`, exactly 32 bytes when configured.
    pub secret_key: Option<Vec<u8>>,
    /// `MCP_BUILDER_MAX_SOURCES` (default 20): the active-source quota.
    pub max_sources: i32,
    /// `MCP_SOURCE_ALLOWED_HOSTS`: the operator allow-list a `licence` source must name.
    pub licence_hosts: Vec<String>,
    /// `MCP_BUILDER_ALLOWED_PORTS` (default `443`): ports a tenant origin may use.
    pub allowed_ports: Vec<u16>,
    /// How many cached OpenAPI documents one source keeps (the reference's 3).
    pub spec_keep: i32,
    /// `MCP_BUILDER_SPEC_MAX_TOTAL_BYTES_PER_TENANT` (default 25 MiB).
    pub spec_max_total_bytes: i64,
}

impl std::fmt::Debug for TenantSourceSettings {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantSourceSettings")
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "<redacted>"),
            )
            .field("max_sources", &self.max_sources)
            .field("licence_hosts", &self.licence_hosts)
            .field("allowed_ports", &self.allowed_ports)
            .field("spec_keep", &self.spec_keep)
            .field("spec_max_total_bytes", &self.spec_max_total_bytes)
            .finish()
    }
}

impl Default for TenantSourceSettings {
    fn default() -> Self {
        Self {
            secret_key: None,
            max_sources: 20,
            licence_hosts: Vec::new(),
            allowed_ports: vec![443],
            spec_keep: 3,
            spec_max_total_bytes: 25 * 1024 * 1024,
        }
    }
}

impl TenantSourceSettings {
    /// The reference's `from_settings`: the `MCP_SOURCE_*` pair, the reference builder defaults.
    pub fn from_source_settings(sources: &SourceSettings) -> Self {
        Self {
            secret_key: sources.secret_key.clone(),
            licence_hosts: sources.allowed_hosts.clone(),
            ..Self::default()
        }
    }
}

/// One `mcp_sources` row as `owned` reads it for a write.
struct Owned {
    source_id: Uuid,
    auth: Value,
    has_token: bool,
}

/// The reference's `view` (`repository.py:67-68`) for a tenant-scoped statement.
fn view(row: &PgRow) -> Result<SourceView, TenantSourceError> {
    let value = serde_json::json!({
        "source_id": row.try_get::<String, _>("source_id")?,
        "owner_tenant_id": row.try_get::<String, _>("owner_tenant_id")?,
        "source_key": row.try_get::<String, _>("source_key")?,
        "revision": row.try_get::<i64, _>("revision")?,
        "status": row.try_get::<String, _>("status")?,
        "base_url": row.try_get::<String, _>("base_url")?,
        "allow_internal_http": row.try_get::<bool, _>("allow_internal_http")?,
        "auth": row.try_get::<Value, _>("auth")?,
        "has_token": row.try_get::<bool, _>("has_token")?,
        "token_set_at": row.try_get::<Option<String>, _>("token_set_at")?,
        "spec_path": row.try_get::<Option<String>, _>("spec_path")?,
        "idempotency_header": row.try_get::<Option<String>, _>("idempotency_header")?,
        "ca_file": row.try_get::<Option<String>, _>("ca_file")?,
        "max_request_bytes": row.try_get::<Option<i32>, _>("max_request_bytes")?,
        "max_response_bytes": row.try_get::<Option<i32>, _>("max_response_bytes")?,
        "created_by": row.try_get::<Value, _>("created_by")?,
        "updated_by": row.try_get::<Value, _>("updated_by")?,
        "created_at": row.try_get::<String, _>("created_at")?,
        "updated_at": row.try_get::<String, _>("updated_at")?,
    });
    serde_json::from_value(value).map_err(|_| TenantSourceError::Corrupt("source view"))
}

/// The reference's `builder_errors("source")` (`storage/catalog.py:59-85`).
fn refused(error: sqlx::Error, resource: &'static str) -> TenantSourceError {
    match error {
        sqlx::Error::Database(database) => {
            let message = database.message().to_owned();
            let code = database.code().as_deref().map(str::to_owned);
            match code.as_deref() {
                Some("MB001") => TenantSourceError::Conflict(message),
                Some("MB002") => TenantSourceError::NotFound(message),
                Some("MB003") => TenantSourceError::Quota(resource),
                Some("MB004") => TenantSourceError::Forbidden(message),
                Some("23505") => TenantSourceError::Conflict(format!("{resource} already exists")),
                Some("23514") | Some("23503") => TenantSourceError::Invalid(message),
                _ => TenantSourceError::Database(sqlx::Error::Database(database)),
            }
        }
        other => TenantSourceError::Database(other),
    }
}

/// Roll a refused transaction back before returning it.
///
/// Dropping a live `Transaction` starts an asynchronous rollback whose completion the pool
/// waits for before reusing the connection; on a current-thread runtime the next `begin` can
/// then wait on a connection nobody is driving. Every refusal after `begin` rolls back first.
async fn refusing(tx: Transaction<'_, Postgres>, error: TenantSourceError) -> TenantSourceError {
    let _ = tx.rollback().await;
    error
}

/// A tenant's own sources (the reference's `TenantSourceRepository`).
#[derive(Clone)]
pub struct TenantSourceRepository {
    pool: PgPool,
    settings: TenantSourceSettings,
    secret_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for TenantSourceRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TenantSourceRepository")
            .field("pool", &self.pool)
            .field("max_sources", &self.settings.max_sources)
            .field("licence_hosts", &self.settings.licence_hosts)
            .field("allowed_ports", &self.settings.allowed_ports)
            .field("spec_keep", &self.settings.spec_keep)
            .field("spec_max_total_bytes", &self.settings.spec_max_total_bytes)
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl TenantSourceRepository {
    /// Bind the repository to the tenant pool and the tenant-builder settings.
    pub fn new(pool: PgPool, settings: TenantSourceSettings) -> Self {
        let secret_key = settings
            .secret_key
            .as_deref()
            .and_then(|key| <[u8; 32]>::try_from(key).ok());
        Self {
            pool,
            settings,
            secret_key,
        }
    }

    /// The reference's `from_settings` (`repository.py:305-315`): the pool plus the
    /// `MCP_SOURCE_*` and `MCP_BUILDER_*` values.
    ///
    /// A key that is not 32 bytes fails closed as "no key", which refuses every sealing write
    /// rather than storing a credential under a truncated key.
    pub fn from_settings(pool: PgPool, settings: &TenantSourceSettings) -> Self {
        Self::new(pool, settings.clone())
    }

    /// The reference's `seal` (`repository.py:317-320`): the token sealed for this source row.
    pub fn seal(&self, source_id: Uuid, token: &str) -> Result<Vec<u8>, TenantSourceError> {
        let Some(key) = self.secret_key.as_ref() else {
            return Err(TenantSourceError::SecretUnavailable);
        };
        encrypt_token(key, source_id, token).map_err(|error| match error {
            SourceCryptoError::InvalidCredential => {
                TenantSourceError::Invalid("invalid credential material".to_owned())
            }
            SourceCryptoError::KeyEncoding
            | SourceCryptoError::KeyLength
            | SourceCryptoError::Unavailable => TenantSourceError::Corrupt("source credential"),
        })
    }

    /// The reference's `check_origin` (`repository.py:322-329`).
    ///
    /// Every URL the source would send a credential to must be on the operator port list; a
    /// `licence` kind source must additionally be on the operator host list.
    pub fn check_origin(&self, base_url: &str, auth: &SourceAuth) -> Result<(), TenantSourceError> {
        let token_url = match auth {
            SourceAuth::OAuth2ClientCredentials(value) => Some(value.token_url.as_str()),
            _ => None,
        };
        for value in std::iter::once(base_url).chain(token_url) {
            let url = url::Url::parse(value)
                .map_err(|_| TenantSourceError::Invalid("invalid URL".to_owned()))?;
            let port = url.port().unwrap_or(443);
            if !self.settings.allowed_ports.contains(&port) {
                return Err(TenantSourceError::Invalid("port is not allowed".to_owned()));
            }
        }
        if auth.kind() == "licence" {
            enforce(
                base_url,
                false,
                self.settings.licence_hosts.iter().map(String::as_str),
            )?;
        }
        Ok(())
    }

    /// The reference's `parameters` (`repository.py:331-339`): the five body-derived binds.
    fn parameters(auth: &SourceAuth) -> Result<Value, TenantSourceError> {
        serde_json::to_value(auth).map_err(|_| TenantSourceError::Corrupt("source auth snapshot"))
    }

    /// The reference's `create` (`repository.py:341-372`).
    ///
    /// `QuotaExceededError` at `max_sources` active sources; a conflict when the tenant already
    /// has that key. The sealed token is bound once and never copied into an error message.
    pub async fn create(
        &self,
        tenant: &AuthorityId,
        body: &TenantSourceCreate,
        actor: &Attribution,
    ) -> Result<SourceView, TenantSourceError> {
        self.check_origin(&body.base_url, &body.auth)?;
        let source_id = Uuid::now_v7();
        let sealed = match body.token.as_ref() {
            Some(token) => Some(self.seal(source_id, token.expose_secret())?),
            None => None,
        };
        let auth = Self::parameters(&body.auth)?;
        let actor = serde_json::to_value(actor)
            .map_err(|_| TenantSourceError::Corrupt("source actor snapshot"))?;
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_builder_source_create(\
             $1::uuid,$2::uuid,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(source_id.to_string())
            .bind(body.source_key.as_str())
            .bind(body.base_url.as_str())
            .bind(auth)
            .bind(sealed)
            .bind(body.spec_path.as_deref())
            .bind(body.idempotency_header.map(|header| header.as_str()))
            .bind(body.max_request_bytes.map(|value| value as i32))
            .bind(body.max_response_bytes.map(|value| value as i32))
            .bind(actor)
            .bind(self.settings.max_sources)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| refused(error, "source"))?;
        view(&row)
    }

    /// The reference's `update` (`repository.py:374-420`).
    ///
    /// An omitted `token` keeps the stored secret; a secret-less kind clears it; switching to a
    /// secret-bearing kind with nothing stored is refused here, before the function call.
    pub async fn update(
        &self,
        tenant: &AuthorityId,
        key: &str,
        body: &TenantSourceUpdate,
        actor: &Attribution,
    ) -> Result<SourceView, TenantSourceError> {
        self.check_origin(&body.base_url, &body.auth)?;
        let auth = Self::parameters(&body.auth)?;
        let actor = serde_json::to_value(actor)
            .map_err(|_| TenantSourceError::Corrupt("source actor snapshot"))?;
        let mut tx = self.pool.begin().await?;
        let current = match Self::owned(&mut tx, tenant, key).await {
            Ok(current) => current,
            Err(error) => return Err(refusing(tx, error).await),
        };
        let sealed = match body.token.as_ref() {
            Some(token) => match self.seal(current.source_id, token.expose_secret()) {
                Ok(sealed) => Some(sealed),
                Err(error) => return Err(refusing(tx, error).await),
            },
            None => None,
        };
        if needs_secret(&body.auth) && sealed.is_none() && !current.has_token {
            return Err(refusing(
                tx,
                TenantSourceError::Invalid("a source of this kind needs its secret".to_owned()),
            )
            .await);
        }
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_builder_source_update(\
             $1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"
        );
        let row = match sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(key)
            .bind(body.expected_revision as i64)
            .bind(body.base_url.as_str())
            .bind(auth)
            .bind(sealed)
            .bind(body.spec_path.as_deref())
            .bind(body.idempotency_header.map(|header| header.as_str()))
            .bind(body.max_request_bytes.map(|value| value as i32))
            .bind(body.max_response_bytes.map(|value| value as i32))
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(row) => row,
            Err(error) => return Err(refusing(tx, refused(error, "source")).await),
        };
        tx.commit().await?;
        view(&row)
    }

    /// The reference's `set_secret` (`repository.py:422-457`): rotate the stored secret.
    ///
    /// `licence` and `none` carry no stored secret, so the function refuses them; every other
    /// kind validates the credential material before it is sealed.
    pub async fn set_secret(
        &self,
        tenant: &AuthorityId,
        key: &str,
        body: &TokenUpdate,
        actor: &Attribution,
    ) -> Result<SourceView, TenantSourceError> {
        let actor = serde_json::to_value(actor)
            .map_err(|_| TenantSourceError::Corrupt("source actor snapshot"))?;
        let mut tx = self.pool.begin().await?;
        let current = match Self::owned(&mut tx, tenant, key).await {
            Ok(current) => current,
            Err(error) => return Err(refusing(tx, error).await),
        };
        let kind = match current.auth.get("kind").and_then(Value::as_str) {
            Some(kind) => kind.to_owned(),
            None => return Err(refusing(tx, TenantSourceError::Corrupt("source auth")).await),
        };
        if checked_secret(&kind, body.token.expose_secret()).is_err() {
            return Err(refusing(
                tx,
                TenantSourceError::Invalid("invalid credential material".to_owned()),
            )
            .await);
        }
        let sealed = match self.seal(current.source_id, body.token.expose_secret()) {
            Ok(sealed) => sealed,
            Err(error) => return Err(refusing(tx, error).await),
        };
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_builder_source_set_secret(\
             $1::uuid,$2,$3,$4,$5)"
        );
        let row = match sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(key)
            .bind(body.expected_revision as i64)
            .bind(sealed)
            .bind(actor)
            .fetch_one(&mut *tx)
            .await
        {
            Ok(row) => row,
            Err(error) => return Err(refusing(tx, refused(error, "source")).await),
        };
        tx.commit().await?;
        view(&row)
    }

    /// The reference's `set_status` (`repository.py:459-483`): `disabled` or `active`.
    ///
    /// Disabling keeps the key reserved. A no-op is the function's conflict; it records no
    /// second event.
    pub async fn set_status(
        &self,
        tenant: &AuthorityId,
        key: &str,
        expected_revision: i64,
        status: &str,
        actor: &Attribution,
    ) -> Result<SourceView, TenantSourceError> {
        let actor = serde_json::to_value(actor)
            .map_err(|_| TenantSourceError::Corrupt("source actor snapshot"))?;
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_builder_source_set_status(\
             $1::uuid,$2,$3,$4,$5)"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(key)
            .bind(expected_revision)
            .bind(status)
            .bind(actor)
            .fetch_one(&self.pool)
            .await
            .map_err(|error| refused(error, "source"))?;
        view(&row)
    }

    /// The reference's `owned` (`repository.py:485-500`): the row a write is about, or the
    /// not-found refusal. `auth` stays JSON because only its `kind` is needed.
    async fn owned(
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        key: &str,
    ) -> Result<Owned, TenantSourceError> {
        let row = sqlx::query(
            "SELECT source_id::text AS source_id,auth,\
             (token_ciphertext IS NOT NULL) AS has_token \
             FROM public.mcp_sources WHERE owner_tenant_id=$1::uuid AND source_key=$2",
        )
        .bind(tenant.as_str())
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or_else(|| TenantSourceError::NotFound("source not found".to_owned()))?;
        let identity: String = row.try_get("source_id")?;
        let source_id = Uuid::parse_str(&identity)
            .map_err(|_| TenantSourceError::Corrupt("source identity"))?;
        Ok(Owned {
            source_id,
            auth: row.try_get("auth")?,
            has_token: row.try_get("has_token")?,
        })
    }

    /// The reference's `get` (`repository.py:502-514`): one source owned by the tenant.
    pub async fn get(
        &self,
        tenant: &AuthorityId,
        key: &str,
    ) -> Result<SourceView, TenantSourceError> {
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_sources \
             WHERE owner_tenant_id=$1::uuid AND source_key=$2"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .ok_or_else(|| TenantSourceError::NotFound("source not found".to_owned()))?;
        view(&row)
    }

    /// The reference's `page` (`repository.py:516-526`): the tenant's sources ordered by key.
    pub async fn page(
        &self,
        tenant: &AuthorityId,
        limit: u32,
        offset: u32,
    ) -> Result<Vec<SourceView>, TenantSourceError> {
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_sources WHERE owner_tenant_id=$1::uuid \
             ORDER BY source_key LIMIT $2 OFFSET $3"
        );
        let rows = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(view).collect()
    }

    /// The reference's `put_spec` (`repository.py:530-551`): cache one fetched OpenAPI document
    /// (last three per source, the tenant's total capped by `spec_max_total_bytes`).
    pub async fn put_spec(
        &self,
        tenant: &AuthorityId,
        key: &str,
        sha256: &str,
        document: &Value,
        size: i32,
    ) -> Result<(), TenantSourceError> {
        let mut tx = self.pool.begin().await?;
        let current = match Self::owned(&mut tx, tenant, key).await {
            Ok(current) => current,
            Err(error) => return Err(refusing(tx, error).await),
        };
        if let Err(error) =
            sqlx::query("SELECT public.mcp_builder_spec_put($1::uuid,$2::uuid,$3,$4,$5,$6,$7)")
                .bind(tenant.as_str())
                .bind(current.source_id.to_string())
                .bind(sha256)
                .bind(size)
                .bind(document)
                .bind(self.settings.spec_keep)
                .bind(self.settings.spec_max_total_bytes)
                .execute(&mut *tx)
                .await
        {
            return Err(refusing(tx, refused(error, "spec")).await);
        }
        tx.commit().await?;
        Ok(())
    }

    /// The reference's `get_spec` (`repository.py:553-574`): the cached document with
    /// `sha256`, or the newest one; `None` when absent.
    pub async fn get_spec(
        &self,
        tenant: &AuthorityId,
        key: &str,
        sha256: Option<&str>,
    ) -> Result<Option<SpecRecord>, TenantSourceError> {
        let row = sqlx::query(
            "SELECT p.sha256,p.bytes,p.fetched_at::text AS fetched_at,p.document \
             FROM public.mcp_source_specs p JOIN public.mcp_sources s \
             ON s.source_id=p.source_id AND s.owner_tenant_id=p.owner_tenant_id \
             WHERE s.owner_tenant_id=$1::uuid AND s.source_key=$2 \
             AND ($3::text IS NULL OR p.sha256=$4) \
             ORDER BY p.fetched_at DESC LIMIT 1",
        )
        .bind(tenant.as_str())
        .bind(key)
        .bind(sha256)
        .bind(sha256)
        .fetch_optional(&self.pool)
        .await?;
        row.as_ref().map(SpecRecord::from_row).transpose()
    }
}

/// One cached OpenAPI document. `Debug` redacts the document: it never reaches a log line.
pub struct SpecRecord {
    /// The document's SHA-256 (lowercase hex).
    pub sha256: String,
    /// The document's byte length as fetched.
    pub bytes: i32,
    /// When it was last fetched, as the reference's text rendering.
    pub fetched_at: String,
    /// The parsed document.
    pub document: Value,
}

impl SpecRecord {
    fn from_row(row: &PgRow) -> Result<Self, TenantSourceError> {
        Ok(Self {
            sha256: row.try_get("sha256")?,
            bytes: row.try_get("bytes")?,
            fetched_at: row.try_get("fetched_at")?,
            document: row.try_get("document")?,
        })
    }
}

impl std::fmt::Debug for SpecRecord {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpecRecord")
            .field("sha256", &self.sha256)
            .field("bytes", &self.bytes)
            .field("fetched_at", &self.fetched_at)
            .field("document", &"<redacted>")
            .finish()
    }
}
