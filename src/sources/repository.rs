//! Platform-role persistence of tool sources. The stored secret is write-only: the view read
//! path never returns ciphertext, and no path here returns plaintext.
//!
//! Port of the reference `src/sources/repository.py:1-260` (`resolve_row`, `view`,
//! `SourceSecretUnavailableError` and the whole `SourceRepository`). Every statement is scoped
//! by the platform tenant — `owner_tenant_id = public.mcp_platform_tenant()`, the reference's
//! `PLATFORM` constant — so a tenant-owned row of the same key is invisible here. Every write
//! appends its `mcp_source_events` row in the same transaction, with the reference's event
//! names (`created`, `updated`, `token_set`, `disabled`, `enabled`) and revision.
//!
//! `mcp_sources.source_id` has no column default; the reference mints a UUIDv7 client-side
//! (`uuid.uuid7()`), and [`SourceRepository::create`] does the same with `Uuid::now_v7`.
//!
//! Three wire details are expressed in SQL because this crate's `sqlx` build carries no
//! `uuid` or `chrono` type mapping: identity columns travel as text, timestamps are rendered
//! as RFC 3339 text (the shape the reference's pydantic view serialises), and a
//! secret-bearing kind switch binds the sealed blob once. Nothing here logs or `Debug`-formats
//! a token or a ciphertext.

use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;
use uuid::Uuid;

use crate::catalog::models::Attribution;
use crate::config::SourceSettings;
use crate::sources::crypto::{SourceCryptoError, encrypt_token};
use crate::sources::guard::{GuardError, enforce};
use crate::sources::models::{
    SourceAuth, SourceCreate, SourceUpdate, SourceView, TokenUpdate, checked_secret, needs_secret,
};

/// The reference's `PLATFORM` scope (`repository.py:36`): every platform statement names the
/// reserved platform tenant, never the caller's.
const PLATFORM: &str = "owner_tenant_id = public.mcp_platform_tenant()";

/// The reference's `VIEW_COLUMNS` (`repository.py:37-42`): what `page`/`get` and every write
/// returning a source view select. `created_at`/`updated_at`/`token_set_at` carry RFC 3339
/// text; the reference casts them to text and lets `SourceView` re-parse them.
const VIEW_COLUMNS: &str = "source_id::text AS source_id, owner_tenant_id::text AS owner_tenant_id, \
     source_key, revision, status, base_url, allow_internal_http, auth, \
     (token_ciphertext IS NOT NULL) AS has_token, \
     to_char(token_set_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS token_set_at, \
     spec_path, idempotency_header, ca_file, max_request_bytes, max_response_bytes, \
     created_by, updated_by, \
     to_char(created_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS created_at, \
     to_char(updated_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS.US\"+00:00\"') AS updated_at";

/// The reference's `RESOLVE_COLUMNS` (`repository.py:44-47`): what the broker needs in order
/// to call a source, ciphertext included (decrypt only in the worker).
const RESOLVE_COLUMNS: &str = "source_id::text AS source_id, owner_tenant_id::text AS owner_tenant_id, \
     source_key, revision, status, base_url, allow_internal_http, auth, token_ciphertext, \
     spec_path, idempotency_header, ca_file, max_request_bytes, max_response_bytes";

/// A refused or impossible source storage operation. Each variant's message is the reference's.
#[derive(Debug, Error)]
pub enum SourceStoreError {
    /// The reference's `CatalogNotFoundError`: no source with that key owned by the platform.
    #[error("{0}")]
    NotFound(&'static str),
    /// The reference's `CatalogConflictError`, or a unique violation: a stale expected
    /// revision, a state the row is already in, or a key already in use.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `ValueError`: a request the source contract refuses (422).
    #[error("{0}")]
    Invalid(&'static str),
    /// The reference's `SourceSecretUnavailableError`: no `MCP_SOURCE_SECRET_KEY`, so a static
    /// token cannot be stored (503 `source_secret_unavailable` at the route).
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

/// One `mcp_sources` row as [`resolve_row`] hands it to the broker.
///
/// `token_ciphertext` is the sealed blob; only the worker decrypts it, and `Debug` redacts it.
pub struct SourceRow {
    /// The source identity (a UUIDv7).
    pub source_id: Uuid,
    /// The owning tenant; platform sources carry the reserved platform tenant.
    pub owner_tenant_id: Uuid,
    /// The source key, unique per owner.
    pub source_key: String,
    /// The row's revision; advances once per write.
    pub revision: i64,
    /// `active` or `disabled`.
    pub status: String,
    /// The approved origin, with an optional fixed path prefix.
    pub base_url: String,
    /// Whether the origin may be plain HTTP (an internal upstream).
    pub allow_internal_http: bool,
    /// The stored credential contract.
    pub auth: SourceAuth,
    /// The sealed token, present exactly when [`SourceAuth`] needs a secret.
    pub token_ciphertext: Option<Vec<u8>>,
    /// The optional OpenAPI document path on the origin.
    pub spec_path: Option<String>,
    /// The optional idempotency header the origin understands.
    pub idempotency_header: Option<String>,
    /// The optional CA bundle the origin needs.
    pub ca_file: Option<String>,
    /// The source's own request-size bound, when it is narrower than the service's.
    pub max_request_bytes: Option<i32>,
    /// The source's own response-size bound, when it is narrower than the service's.
    pub max_response_bytes: Option<i32>,
}

impl std::fmt::Debug for SourceRow {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRow")
            .field("source_id", &self.source_id)
            .field("owner_tenant_id", &self.owner_tenant_id)
            .field("source_key", &self.source_key)
            .field("revision", &self.revision)
            .field("status", &self.status)
            .field("base_url", &self.base_url)
            .field("allow_internal_http", &self.allow_internal_http)
            .field("auth", &self.auth)
            .field(
                "token_ciphertext",
                &self.token_ciphertext.as_ref().map(|_| "<redacted>"),
            )
            .field("spec_path", &self.spec_path)
            .field("idempotency_header", &self.idempotency_header)
            .field("ca_file", &self.ca_file)
            .field("max_request_bytes", &self.max_request_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// The reference's `resolve_row` (`repository.py:50-60`): the source `(owner, key)` as the
/// broker consumes it, ciphertext included.
///
/// The owner is the calling service's `owner_tenant_id` — platform services resolve platform
/// sources, a tenant's service resolves that tenant's source — so a key alone never identifies
/// a source. `Ok(None)` is the reference's `None`; a stored row the contract cannot read is an
/// error, never a silent skip.
pub async fn resolve_row(
    conn: &mut PgConnection,
    owner_tenant_id: Uuid,
    source_key: &str,
) -> Result<Option<SourceRow>, SourceStoreError> {
    let statement = format!(
        "SELECT {RESOLVE_COLUMNS} FROM public.mcp_sources \
         WHERE owner_tenant_id=$1::uuid AND source_key=$2"
    );
    let row = sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(owner_tenant_id.to_string())
        .bind(source_key)
        .fetch_optional(&mut *conn)
        .await?;
    row.as_ref().map(decode_resolved).transpose()
}

/// The reference's `view` (`repository.py:67-68`): one selected row as the served view.
///
/// The reference validates the row through pydantic; this builds the same JSON object and lets
/// [`SourceView`]'s own contract read it, so an unreadable row is a refusal rather than a
/// half-filled response.
fn view(row: &PgRow) -> Result<SourceView, SourceStoreError> {
    let value = serde_json::json!({
        "source_id": row.try_get::<String, _>("source_id")?,
        "owner_tenant_id": row.try_get::<String, _>("owner_tenant_id")?,
        "source_key": row.try_get::<String, _>("source_key")?,
        "revision": row.try_get::<i64, _>("revision")?,
        "status": row.try_get::<String, _>("status")?,
        "base_url": row.try_get::<String, _>("base_url")?,
        "allow_internal_http": row.try_get::<bool, _>("allow_internal_http")?,
        "auth": row.try_get::<serde_json::Value, _>("auth")?,
        "has_token": row.try_get::<bool, _>("has_token")?,
        "token_set_at": row.try_get::<Option<String>, _>("token_set_at")?,
        "spec_path": row.try_get::<Option<String>, _>("spec_path")?,
        "idempotency_header": row.try_get::<Option<String>, _>("idempotency_header")?,
        "ca_file": row.try_get::<Option<String>, _>("ca_file")?,
        "max_request_bytes": row.try_get::<Option<i32>, _>("max_request_bytes")?,
        "max_response_bytes": row.try_get::<Option<i32>, _>("max_response_bytes")?,
        "created_by": row.try_get::<serde_json::Value, _>("created_by")?,
        "updated_by": row.try_get::<serde_json::Value, _>("updated_by")?,
        "created_at": row.try_get::<String, _>("created_at")?,
        "updated_at": row.try_get::<String, _>("updated_at")?,
    });
    serde_json::from_value(value).map_err(|_| SourceStoreError::Corrupt("source view"))
}

/// The platform tool source repository. One repository is shared; every statement is already
/// scoped to the platform tenant.
#[derive(Clone)]
pub struct SourceRepository {
    pool: PgPool,
    allowed_hosts: Vec<String>,
    secret_key: Option<[u8; 32]>,
}

impl std::fmt::Debug for SourceRepository {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceRepository")
            .field("pool", &self.pool)
            .field("allowed_hosts", &self.allowed_hosts)
            .field(
                "secret_key",
                &self.secret_key.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl SourceRepository {
    /// Bind the repository to the platform pool, the operator host allow-list and the decoded
    /// `MCP_SOURCE_SECRET_KEY`.
    pub fn new(pool: PgPool, allowed_hosts: Vec<String>, secret_key: Option<[u8; 32]>) -> Self {
        Self {
            pool,
            allowed_hosts,
            secret_key,
        }
    }

    /// Bind the repository to the `MCP_SOURCE_*` settings.
    ///
    /// `SourceSettings::secret_key` is validated at startup (`config.rs`); a value of any other
    /// length fails closed as "no key", which refuses every sealing write rather than storing a
    /// credential under a truncated key.
    pub fn from_settings(pool: PgPool, settings: &SourceSettings) -> Self {
        let secret_key = settings
            .secret_key
            .as_deref()
            .and_then(|key| <[u8; 32]>::try_from(key).ok());
        Self::new(pool, settings.allowed_hosts.clone(), secret_key)
    }

    /// The reference's `seal` (`repository.py:82-85`): the token sealed for this source row.
    ///
    /// Without a configured key this is the reference's `SourceSecretUnavailableError`; the
    /// route maps that variant to `503 source_secret_unavailable`. Credential material the
    /// crypto contract refuses is the reference's `invalid credential material`.
    pub fn seal(&self, source_id: Uuid, token: &str) -> Result<Vec<u8>, SourceStoreError> {
        let Some(key) = self.secret_key.as_ref() else {
            return Err(SourceStoreError::SecretUnavailable);
        };
        encrypt_token(key, source_id, token).map_err(|error| match error {
            SourceCryptoError::InvalidCredential => {
                SourceStoreError::Invalid("invalid credential material")
            }
            // AES-GCM cannot refuse a credential under the validated 4096-byte bound; a key
            // length error is impossible for a `[u8; 32]`. Keep them distinct from a request
            // refusal rather than mislabelling them.
            SourceCryptoError::KeyEncoding
            | SourceCryptoError::KeyLength
            | SourceCryptoError::Unavailable => SourceStoreError::Corrupt("source credential"),
        })
    }

    /// The reference's `create` (`repository.py:101-134`).
    ///
    /// The destination is enforced first (before any transaction), then the row and its
    /// `created` event are written in one transaction. A key another platform source already
    /// holds is the unique violation the reference reports as a conflict.
    /// Roll a refused transaction back before returning it.
    ///
    /// Dropping a live `Transaction` starts an asynchronous rollback whose completion the pool
    /// waits for before reusing the connection. On a current-thread runtime the next `begin`
    /// can then wait on a connection nobody is driving, which is a hang, not an error. Every
    /// refusal that happens after `begin` rolls back explicitly first.
    async fn refusing(
        tx: sqlx::Transaction<'_, sqlx::Postgres>,
        error: SourceStoreError,
    ) -> SourceStoreError {
        let _ = tx.rollback().await;
        error
    }

    pub async fn create(
        &self,
        body: &SourceCreate,
        actor: &Attribution,
    ) -> Result<SourceView, SourceStoreError> {
        enforce(
            &body.base_url,
            body.allow_internal_http,
            self.allowed_hosts.iter().map(String::as_str),
        )?;
        let source_id = Uuid::now_v7();
        let sealed = match body.token.as_ref().map(|s| s.expose_secret()) {
            Some(token) => Some(self.seal(source_id, token)?),
            None => None,
        };
        let auth = snapshot(&body.auth, "source auth snapshot")?;
        let actor = snapshot(actor, "source actor snapshot")?;
        let result = async {
            let mut tx = self.pool.begin().await?;
            let statement = format!(
                "INSERT INTO public.mcp_sources(source_id,source_key,base_url,\
                 allow_internal_http,auth,token_ciphertext,token_set_at,spec_path,\
                 idempotency_header,ca_file,max_request_bytes,max_response_bytes,created_by,\
                 updated_by) VALUES ($1::uuid,$2,$3,$4,$5,$6,\
                 CASE WHEN $6::bytea IS NULL THEN NULL ELSE clock_timestamp() END,\
                 $7,$8,$9,$10,$11,$12,$12) RETURNING {VIEW_COLUMNS}"
            );
            let row = sqlx::query(sqlx::AssertSqlSafe(statement))
                .bind(source_id.to_string())
                .bind(body.source_key.as_str())
                .bind(body.base_url.as_str())
                .bind(body.allow_internal_http)
                .bind(auth)
                .bind(sealed)
                .bind(body.spec_path.as_deref())
                .bind(body.idempotency_header.map(|h| h.as_str()))
                .bind(body.ca_file.as_deref())
                .bind(body.max_request_bytes.map(|value| value as i64))
                .bind(body.max_response_bytes.map(|value| value as i64))
                .bind(&actor)
                .fetch_one(&mut *tx)
                .await?;
            event(&mut tx, &row, "created", &actor).await?;
            let view = view(&row)?;
            tx.commit().await?;
            Ok(view)
        }
        .await;
        result.map_err(map_unique_violation)
    }

    /// The reference's `page` (`repository.py:136-145`): every platform source ordered by key.
    pub async fn page(&self, limit: u32, offset: u32) -> Result<Vec<SourceView>, SourceStoreError> {
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_sources WHERE {PLATFORM} \
             ORDER BY source_key LIMIT $1 OFFSET $2"
        );
        let rows = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(i64::from(limit))
            .bind(i64::from(offset))
            .fetch_all(&self.pool)
            .await?;
        rows.iter().map(view).collect()
    }

    /// The reference's `get` (`repository.py:147-158`): one platform source by key.
    pub async fn get(&self, key: &str) -> Result<SourceView, SourceStoreError> {
        let statement = format!(
            "SELECT {VIEW_COLUMNS} FROM public.mcp_sources WHERE {PLATFORM} AND source_key=$1"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(key)
            .fetch_optional(&self.pool)
            .await?
            .ok_or(SourceStoreError::NotFound("source not found"))?;
        view(&row)
    }

    /// The reference's `locked` (`repository.py:160-173`): the platform source under a row
    /// lock, refusing a caller whose read is stale.
    async fn locked(
        conn: &mut PgConnection,
        key: &str,
        expected: i64,
    ) -> Result<Locked, SourceStoreError> {
        let row = sqlx::query(
            "SELECT source_id::text AS source_id, source_key, revision, status, auth, \
             (token_ciphertext IS NOT NULL) AS has_token FROM public.mcp_sources \
             WHERE owner_tenant_id=public.mcp_platform_tenant() AND source_key=$1 FOR UPDATE",
        )
        .bind(key)
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(SourceStoreError::NotFound("source not found"))?;
        let identity: String = row.try_get("source_id")?;
        let source_id =
            Uuid::parse_str(&identity).map_err(|_| SourceStoreError::Corrupt("source identity"))?;
        let revision: i64 = row.try_get("revision")?;
        if revision != expected {
            return Err(SourceStoreError::Conflict("source revision mismatch"));
        }
        Ok(Locked {
            source_id,
            status: row.try_get("status")?,
            auth: row.try_get("auth")?,
            has_token: row.try_get("has_token")?,
        })
    }

    /// The reference's `update` (`repository.py:175-217`).
    ///
    /// The destination is enforced first, then the row is locked and the expected revision
    /// checked. A secret-bearing kind keeps the stored token unless a new one is supplied;
    /// becoming secret-less clears it; becoming secret-bearing with nothing stored is refused.
    pub async fn update(
        &self,
        key: &str,
        body: &SourceUpdate,
        actor: &Attribution,
    ) -> Result<SourceView, SourceStoreError> {
        enforce(
            &body.base_url,
            body.allow_internal_http,
            self.allowed_hosts.iter().map(String::as_str),
        )?;
        let stored = needs_secret(&body.auth);
        let auth = snapshot(&body.auth, "source auth snapshot")?;
        let actor = snapshot(actor, "source actor snapshot")?;
        let expected = body.expected_revision as i64;
        let mut tx = self.pool.begin().await?;
        let current = match Self::locked(&mut tx, key, expected).await {
            Ok(current) => current,
            Err(error) => return Err(Self::refusing(tx, error).await),
        };
        if !stored && body.token.is_some() {
            return Err(Self::refusing(
                tx,
                SourceStoreError::Invalid("this source kind carries no stored secret"),
            )
            .await);
        }
        if stored && body.token.is_none() && !current.has_token {
            return Err(Self::refusing(
                tx,
                SourceStoreError::Invalid("a source of this kind needs its secret"),
            )
            .await);
        }
        // Three literal statements: keep the stored token, clear it, or rotate it. The sealed
        // blob is bound once and never copied into a log line.
        let (statement, sealed) = match (stored, body.token.as_ref().map(|s| s.expose_secret())) {
            (false, _) => (
                format!(
                    "UPDATE public.mcp_sources SET revision=revision+1,base_url=$1,\
                     allow_internal_http=$2,auth=$3,spec_path=$4,idempotency_header=$5,\
                     ca_file=$6,max_request_bytes=$7,max_response_bytes=$8,updated_by=$9,\
                     updated_at=clock_timestamp(),token_ciphertext=NULL,token_set_at=NULL \
                     WHERE source_id=$10::uuid RETURNING {VIEW_COLUMNS}"
                ),
                None,
            ),
            (true, None) => (
                format!(
                    "UPDATE public.mcp_sources SET revision=revision+1,base_url=$1,\
                     allow_internal_http=$2,auth=$3,spec_path=$4,idempotency_header=$5,\
                     ca_file=$6,max_request_bytes=$7,max_response_bytes=$8,updated_by=$9,\
                     updated_at=clock_timestamp(),token_ciphertext=token_ciphertext,\
                     token_set_at=token_set_at WHERE source_id=$10::uuid RETURNING {VIEW_COLUMNS}"
                ),
                None,
            ),
            (true, Some(token)) => (
                format!(
                    "UPDATE public.mcp_sources SET revision=revision+1,base_url=$1,\
                     allow_internal_http=$2,auth=$3,spec_path=$4,idempotency_header=$5,\
                     ca_file=$6,max_request_bytes=$7,max_response_bytes=$8,updated_by=$9,\
                     updated_at=clock_timestamp(),token_ciphertext=$10,\
                     token_set_at=clock_timestamp() WHERE source_id=$11::uuid \
                     RETURNING {VIEW_COLUMNS}"
                ),
                Some(self.seal(current.source_id, token)?),
            ),
        };
        let mut query = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(body.base_url.as_str())
            .bind(body.allow_internal_http)
            .bind(auth)
            .bind(body.spec_path.as_deref())
            .bind(body.idempotency_header.map(|h| h.as_str()))
            .bind(body.ca_file.as_deref())
            .bind(body.max_request_bytes.map(|value| value as i64))
            .bind(body.max_response_bytes.map(|value| value as i64))
            .bind(&actor);
        if let Some(sealed) = sealed {
            query = query.bind(sealed);
        }
        let row = query
            .bind(current.source_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        event(&mut tx, &row, "updated", &actor).await?;
        let view = view(&row)?;
        tx.commit().await?;
        Ok(view)
    }

    /// The reference's `set_token` (`repository.py:219-240`): rotate the stored secret.
    ///
    /// `licence` and `none` carry no stored secret, so the reference refuses them here; any
    /// other kind validates the credential material before sealing it.
    pub async fn set_token(
        &self,
        key: &str,
        body: &TokenUpdate,
        actor: &Attribution,
    ) -> Result<SourceView, SourceStoreError> {
        let actor = snapshot(actor, "source actor snapshot")?;
        let expected = body.expected_revision as i64;
        let mut tx = self.pool.begin().await?;
        let current = match Self::locked(&mut tx, key, expected).await {
            Ok(current) => current,
            Err(error) => return Err(Self::refusing(tx, error).await),
        };
        let kind = current
            .auth
            .get("kind")
            .and_then(serde_json::Value::as_str)
            .ok_or(SourceStoreError::Corrupt("source auth"))?;
        if kind == "licence" || kind == "none" {
            return Err(Self::refusing(
                tx,
                SourceStoreError::Invalid("this source kind carries no stored secret"),
            )
            .await);
        }
        if checked_secret(kind, body.token.expose_secret()).is_err() {
            return Err(Self::refusing(
                tx,
                SourceStoreError::Invalid("invalid credential material"),
            )
            .await);
        }
        let sealed = self.seal(current.source_id, body.token.expose_secret())?;
        let statement = format!(
            "UPDATE public.mcp_sources SET revision=revision+1,token_ciphertext=$1,\
             token_set_at=clock_timestamp(),updated_by=$2,updated_at=clock_timestamp() \
             WHERE source_id=$3::uuid RETURNING {VIEW_COLUMNS}"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(sealed)
            .bind(&actor)
            .bind(current.source_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        event(&mut tx, &row, "token_set", &actor).await?;
        let view = view(&row)?;
        tx.commit().await?;
        Ok(view)
    }

    /// The reference's `set_status` (`repository.py:242-259`): disable or re-enable a source.
    ///
    /// A no-op is the reference's conflict, not a second event; a real change bumps the
    /// revision and records `disabled` or `enabled`.
    pub async fn set_status(
        &self,
        key: &str,
        expected: i64,
        status: &str,
        actor: &Attribution,
    ) -> Result<SourceView, SourceStoreError> {
        let actor = snapshot(actor, "source actor snapshot")?;
        let mut tx = self.pool.begin().await?;
        let current = match Self::locked(&mut tx, key, expected).await {
            Ok(current) => current,
            Err(error) => return Err(Self::refusing(tx, error).await),
        };
        if current.status == status {
            return Err(Self::refusing(
                tx,
                SourceStoreError::Conflict("source already in that state"),
            )
            .await);
        }
        let statement = format!(
            "UPDATE public.mcp_sources SET revision=revision+1,status=$1,updated_by=$2,\
             updated_at=clock_timestamp() WHERE source_id=$3::uuid RETURNING {VIEW_COLUMNS}"
        );
        let row = sqlx::query(sqlx::AssertSqlSafe(statement))
            .bind(status)
            .bind(&actor)
            .bind(current.source_id.to_string())
            .fetch_one(&mut *tx)
            .await?;
        let name = if status == "disabled" {
            "disabled"
        } else {
            "enabled"
        };
        event(&mut tx, &row, name, &actor).await?;
        let view = view(&row)?;
        tx.commit().await?;
        Ok(view)
    }
}

/// The columns [`SourceRepository::locked`] needs from the row it locks.
struct Locked {
    source_id: Uuid,
    status: String,
    auth: serde_json::Value,
    has_token: bool,
}

/// The reference's `event` (`repository.py:87-99`): one `mcp_source_events` row in the write's
/// own transaction.
async fn event(
    conn: &mut PgConnection,
    row: &PgRow,
    name: &'static str,
    actor: &serde_json::Value,
) -> Result<(), SourceStoreError> {
    sqlx::query(
        "INSERT INTO public.mcp_source_events(source_id,source_key,revision,event,actor) \
         VALUES ($1::uuid,$2,$3,$4,$5)",
    )
    .bind(row.try_get::<String, _>("source_id")?)
    .bind(row.try_get::<String, _>("source_key")?)
    .bind(row.try_get::<i64, _>("revision")?)
    .bind(name)
    .bind(actor.clone())
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The reference's `Snapshot`: the JSON form stored in every `jsonb` column.
fn snapshot<T: serde::Serialize>(
    value: &T,
    what: &'static str,
) -> Result<serde_json::Value, SourceStoreError> {
    serde_json::to_value(value).map_err(|_| SourceStoreError::Corrupt(what))
}

/// Turn a resolved row into its typed form. The sealed blob is copied once and never logged.
fn decode_resolved(row: &PgRow) -> Result<SourceRow, SourceStoreError> {
    let source_id: String = row.try_get("source_id")?;
    let owner_tenant_id: String = row.try_get("owner_tenant_id")?;
    let auth: serde_json::Value = row.try_get("auth")?;
    Ok(SourceRow {
        source_id: Uuid::parse_str(&source_id)
            .map_err(|_| SourceStoreError::Corrupt("source identity"))?,
        owner_tenant_id: Uuid::parse_str(&owner_tenant_id)
            .map_err(|_| SourceStoreError::Corrupt("source owner"))?,
        source_key: row.try_get("source_key")?,
        revision: row.try_get("revision")?,
        status: row.try_get("status")?,
        base_url: row.try_get("base_url")?,
        allow_internal_http: row.try_get("allow_internal_http")?,
        auth: serde_json::from_value(auth).map_err(|_| SourceStoreError::Corrupt("source auth"))?,
        token_ciphertext: row.try_get("token_ciphertext")?,
        spec_path: row.try_get("spec_path")?,
        idempotency_header: row.try_get("idempotency_header")?,
        ca_file: row.try_get("ca_file")?,
        max_request_bytes: row.try_get("max_request_bytes")?,
        max_response_bytes: row.try_get("max_response_bytes")?,
    })
}

/// The reference's unique-violation boundary: a key already held by another platform source is
/// a conflict, never a 500.
fn map_unique_violation(error: SourceStoreError) -> SourceStoreError {
    match error {
        SourceStoreError::Database(database_error) => match &database_error {
            sqlx::Error::Database(database) if database.code().as_deref() == Some("23505") => {
                SourceStoreError::Conflict("source key already exists")
            }
            _ => SourceStoreError::Database(database_error),
        },
        other => other,
    }
}
