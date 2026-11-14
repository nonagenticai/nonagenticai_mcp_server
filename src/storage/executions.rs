//! Short transactions for immutable acceptance, fenced ownership and bounded inspection.
//!
//! Ported from the reference `src/storage/executions.py` (`accept`, `get`, `events`, `cancel`
//! and the bounded `event` append): the same statements, in the same order, under the same
//! advisory admission lock. A Python worker may later read the rows this writes, so every
//! stored value — the authority snapshot, the canonical input hash, the raw profile snapshot —
//! is the reference's byte for byte.
//!
//! Two implementation details are expressed in SQL because this crate carries no UUID generator
//! and no `sqlx` date mapping: `mcp_runs.run_id` is minted by Postgres 18's `uuidv7()`, and every
//! instant is read as epoch microseconds and rebuilt as a `DateTime<Utc>` (see
//! `src/storage/bindings.rs`).

use chrono::{DateTime, Utc};
use serde_json::Value;
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Row};
use thiserror::Error;

use crate::auth::Principal;
use crate::auth::uuid::Rfc4122Uuid;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::models::Runtime;
use crate::catalog::resolver::ResolvedTool;
use crate::config::ExecutionSettings;
use crate::execution::{RunRow, RunStatus, attribution, authority_snapshot, value_hash};
use crate::storage::bindings;
use crate::storage::catalog::CatalogStoreError;

/// The reference's admission lock: one advisory transaction lock serializes bounded acceptance
/// across API replicas, so the queue bounds are race-free without an in-memory queue.
const ADMISSION_LOCK: i64 = 72_441_001;

/// The reference's per-run lifecycle bound: `mcp_run_events` is capped at 256 rows per run.
const EVENT_LIMIT: i64 = 256;

/// The run's public event stream bound, as the reference's route declares it.
const EVENTS_MAX: u32 = 100;

/// A refused or impossible execution storage operation.
#[derive(Debug, Error)]
pub enum ExecutionStoreError {
    /// The reference's `QueueFullError`: the global or the per-tenant queue bound is reached.
    #[error("queue is full")]
    QueueFull,
    /// The reference's `ExecutionDeniedError`: the binding no longer authorizes this call.
    #[error("execution denied")]
    Denied,
    /// The reference's `CatalogConflictError`: a stale generation or an idempotency mismatch.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `CatalogNotFoundError("run not found")`.
    #[error("run not found")]
    NotFound,
    /// A storage failure or a stored row outside the domain.
    #[error(transparent)]
    Store(CatalogStoreError),
}

impl From<CatalogStoreError> for ExecutionStoreError {
    fn from(error: CatalogStoreError) -> Self {
        Self::Store(error)
    }
}

impl From<sqlx::Error> for ExecutionStoreError {
    fn from(error: sqlx::Error) -> Self {
        Self::Store(CatalogStoreError::Database(error))
    }
}

/// One `mcp_run_events` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RunEvent {
    /// The run-scoped ascending identity.
    pub event_id: i64,
    /// The lifecycle step (`queued`, `running`, a terminal status, `cancel_requested`, …).
    pub kind: String,
    /// When it was appended.
    pub created_at: DateTime<Utc>,
}

/// The execution repository: one pool, the execution settings, every call tenant-explicit.
#[derive(Debug, Clone)]
pub struct ExecutionRepository {
    pool: PgPool,
    settings: ExecutionSettings,
}

impl ExecutionRepository {
    /// Bind the repository to a pool and the configured execution bounds.
    pub fn new(pool: PgPool, settings: ExecutionSettings) -> Self {
        Self { pool, settings }
    }

    /// The reference's `accept`: one bounded, fenced admission transaction that writes the
    /// immutable run row, its tenant lock and its `queued` event.
    pub async fn accept(
        &self,
        principal: &Principal,
        resolved: &ResolvedTool,
        inputs: &Value,
        idempotency_key: Option<&str>,
        generation: i64,
        actor: Option<&Value>,
    ) -> Result<RunRow, ExecutionStoreError> {
        let tenant = AuthorityId::new(principal.tenant_id.to_string())
            .map_err(|_| ExecutionStoreError::Denied)?;
        let binding_id = principal
            .binding_id
            .as_ref()
            .ok_or(ExecutionStoreError::Denied)
            .and_then(|identity| {
                Uuid7::new(identity.to_string()).map_err(|_| ExecutionStoreError::Denied)
            })?;
        let revision = principal
            .binding_revision
            .ok_or(ExecutionStoreError::Denied)?;
        let reference = &resolved.effective.tool;
        let digest = value_hash(inputs);
        let licence = principal.license_id.to_string();
        let authority = authority_snapshot(resolved)
            .map_err(|_| ExecutionStoreError::Store(CatalogStoreError::Corrupt("authority")))?;
        let mut tx = self.pool.begin().await?;

        // Serialize bounded admission across API replicas; no in-memory queue.
        sqlx::query("SELECT pg_advisory_xact_lock($1)")
            .bind(ADMISSION_LOCK)
            .execute(&mut *tx)
            .await?;

        let binding = bindings::get_binding(&mut tx, &tenant, &binding_id, true).await?;
        if binding.revision != revision
            || binding.revoked
            || !binding.enabled
            || binding.expires_at <= Utc::now()
            || binding.gateway_license_id.as_str() != licence
        {
            return Err(ExecutionStoreError::Denied);
        }

        let profile: Option<Value> = sqlx::query_scalar(
            "SELECT manifest FROM public.mcp_credential_profiles \
             WHERE tenant_id = $1::uuid AND profile_id = $2::uuid FOR SHARE",
        )
        .bind(tenant.as_str())
        .bind(binding.credential_profile_id.as_str())
        .fetch_optional(&mut *tx)
        .await?;
        let profile = profile.ok_or(ExecutionStoreError::Denied)?;

        let current: i64 =
            sqlx::query_scalar("SELECT public.mcp_lock_execution_authority() AS generation")
                .fetch_one(&mut *tx)
                .await?;
        if current != generation {
            return Err(ExecutionStoreError::Conflict(
                "authority changed during acceptance",
            ));
        }

        if let Some(key) = idempotency_key {
            let statement = format!(
                "SELECT {RUN_COLUMNS} FROM public.mcp_runs \
                 WHERE tenant_id = $1::uuid AND binding_id = $2::uuid \
                 AND owner_tenant_id = $3::uuid AND tool_id = $4::uuid \
                 AND tool_version = $5 AND idempotency_key = $6"
            );
            let prior = sqlx::query(AssertSqlSafe(statement))
                .bind(tenant.as_str())
                .bind(binding_id.as_str())
                .bind(reference.tenant_id.as_str())
                .bind(reference.id.as_str())
                .bind(version_bits(reference.version))
                .bind(key)
                .fetch_optional(&mut *tx)
                .await?;
            if let Some(row) = prior {
                let run = decode_run(&row)?;
                if run.input_hash != digest {
                    return Err(ExecutionStoreError::Conflict("idempotency input conflict"));
                }
                tx.commit().await?;
                return Ok(run);
            }
        }

        let (total, queued): (i64, i64) = sqlx::query_as(
            "SELECT count(*) AS total, count(*) FILTER (WHERE tenant_id = $1::uuid) AS tenant \
             FROM public.mcp_runs WHERE status = 'queued'",
        )
        .bind(tenant.as_str())
        .fetch_one(&mut *tx)
        .await?;
        if total >= i64::try_from(self.settings.queue_global_max).unwrap_or(i64::MAX)
            || queued >= i64::try_from(self.settings.queue_per_tenant_max).unwrap_or(i64::MAX)
        {
            return Err(ExecutionStoreError::QueueFull);
        }

        let statement = format!(
            "INSERT INTO public.mcp_runs(run_id,tenant_id,binding_id,binding_revision,\
             gateway_license_id,credential_profile_id,profile_snapshot,owner_tenant_id,tool_id,\
             tool_version,authority,inputs,input_hash,idempotency_key,created_by,queue_deadline,\
             runtime,actor) \
             VALUES (uuidv7(),$1::uuid,$2::uuid,$3,$4::uuid,$5::uuid,$6,$7::uuid,$8::uuid,$9,\
             $10,$11,$12,$13,$14,\
             clock_timestamp() + make_interval(secs => LEAST($15::double precision,$16::double precision)),\
             $17,$18) \
             RETURNING {RUN_COLUMNS}"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(binding_id.as_str())
            .bind(revision)
            .bind(licence.as_str())
            .bind(binding.credential_profile_id.as_str())
            .bind(profile)
            .bind(reference.tenant_id.as_str())
            .bind(reference.id.as_str())
            .bind(version_bits(reference.version))
            .bind(authority)
            .bind(inputs.clone())
            .bind(digest.as_str())
            .bind(idempotency_key)
            .bind(attribution(principal))
            .bind(f64::from(resolved.effective.limits.queue_seconds))
            .bind(self.settings.run_queue_timeout.as_secs_f64())
            .bind(runtime_text(resolved.manifest.runtime))
            .bind(actor.cloned())
            .fetch_one(&mut *tx)
            .await?;
        let run = decode_run(&row)?;
        let run_id = run.run_id.to_string();

        sqlx::query(
            "INSERT INTO public.mcp_tenant_execution_locks(tenant_id) VALUES ($1::uuid) \
             ON CONFLICT DO NOTHING",
        )
        .bind(tenant.as_str())
        .execute(&mut *tx)
        .await?;
        event(&mut tx, tenant.as_str(), &run_id, "queued").await?;
        tx.commit().await?;
        Ok(run)
    }

    /// The reference's `get`: one tenant-owned run.
    pub async fn get(
        &self,
        tenant: &AuthorityId,
        run_id: &Uuid7,
    ) -> Result<RunRow, ExecutionStoreError> {
        let statement = format!(
            "SELECT {RUN_COLUMNS} FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid"
        );
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(run_id.as_str())
            .fetch_optional(&self.pool)
            .await?
            .ok_or(ExecutionStoreError::NotFound)?;
        decode_run(&row)
    }

    /// The reference's `events`: ascending `event_id`, only entries after `after`, bounded.
    ///
    /// The route's `ge=0` / `ge=1,le=100` bounds are applied here, so a caller cannot widen the
    /// read.
    pub async fn events(
        &self,
        tenant: &AuthorityId,
        run_id: &Uuid7,
        after: i64,
        limit: u32,
    ) -> Result<Vec<RunEvent>, ExecutionStoreError> {
        let rows = sqlx::query(
            "SELECT event_id, kind, \
             (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us \
             FROM public.mcp_run_events \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND event_id > $3 \
             ORDER BY event_id LIMIT $4",
        )
        .bind(tenant.as_str())
        .bind(run_id.as_str())
        .bind(after.max(0))
        .bind(i64::from(limit.clamp(1, EVENTS_MAX)))
        .fetch_all(&self.pool)
        .await?;
        rows.iter()
            .map(|row| {
                Ok(RunEvent {
                    event_id: row.try_get("event_id")?,
                    kind: row.try_get("kind")?,
                    created_at: instant(row.try_get("created_at_us")?)?,
                })
            })
            .collect()
    }

    /// The reference's `cancel`: only the API flag is written; a worker owns every status
    /// transition.
    ///
    /// The returned row always reports `cancel_requested = true`, exactly the reference's
    /// `{**row, "cancel_requested": True}` — even for a terminal run whose stored flag stays
    /// false.
    pub async fn cancel(
        &self,
        tenant: &AuthorityId,
        run_id: &Uuid7,
    ) -> Result<RunRow, ExecutionStoreError> {
        let statement = format!(
            "SELECT {RUN_COLUMNS} FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND run_id = $2::uuid FOR UPDATE"
        );
        let mut tx = self.pool.begin().await?;
        let row = sqlx::query(AssertSqlSafe(statement))
            .bind(tenant.as_str())
            .bind(run_id.as_str())
            .fetch_optional(&mut *tx)
            .await?
            .ok_or(ExecutionStoreError::NotFound)?;
        let mut run = decode_run(&row)?;
        if !run.status.is_terminal() && !run.cancel_requested {
            sqlx::query(
                "UPDATE public.mcp_runs SET cancel_requested = true \
                 WHERE tenant_id = $1::uuid AND run_id = $2::uuid",
            )
            .bind(tenant.as_str())
            .bind(run_id.as_str())
            .execute(&mut *tx)
            .await?;
            event(
                &mut tx,
                tenant.as_str(),
                run_id.as_str(),
                "cancel_requested",
            )
            .await?;
        }
        run.cancel_requested = true;
        tx.commit().await?;
        Ok(run)
    }
}

/// Append one run event, bounded to [`EVENT_LIMIT`] rows per run.
async fn event(
    conn: &mut PgConnection,
    tenant: &str,
    run_id: &str,
    kind: &str,
) -> Result<(), ExecutionStoreError> {
    // No untrusted logs or credentials are persisted. Each run has a bounded lifecycle.
    sqlx::query(
        "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) \
         SELECT $1::uuid,$2::uuid,$3 \
         WHERE (SELECT count(*) FROM public.mcp_run_events \
                WHERE tenant_id = $1::uuid AND run_id = $2::uuid) < $4",
    )
    .bind(tenant)
    .bind(run_id)
    .bind(kind)
    .bind(EVENT_LIMIT)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The run columns every statement projects, in the decoder's order. Instants travel as epoch
/// microseconds because this crate's `sqlx` build carries no `chrono` type mapping.
///
/// `pub(crate)` so the worker store projects the identical run snapshot and decodes it with
/// [`decode_run`] rather than keeping a second copy of the column list.
pub(crate) const RUN_COLUMNS: &str = "run_id::text AS run_id, tenant_id::text AS tenant_id, \
     gateway_license_id::text AS gateway_license_id, \
     owner_tenant_id::text AS owner_tenant_id, tool_id::text AS tool_id, \
     binding_id::text AS binding_id, binding_revision, \
     credential_profile_id::text AS credential_profile_id, profile_snapshot, tool_version, \
     authority, inputs, input_hash, idempotency_key, created_by, status, \
     (extract(epoch FROM created_at) * 1000000)::bigint AS created_at_us, \
     (extract(epoch FROM queue_deadline) * 1000000)::bigint AS queue_deadline_us, \
     (extract(epoch FROM started_at) * 1000000)::bigint AS started_at_us, \
     (extract(epoch FROM finished_at) * 1000000)::bigint AS finished_at_us, cancel_requested, \
     result, error, \
     (extract(epoch FROM payload_expired_at) * 1000000)::bigint AS payload_expired_at_us, \
     mode, runtime, external_ref, status_message, actor";

/// Decode one row selected with [`RUN_COLUMNS`]; the worker adds its own columns to the same
/// projection and calls this for the run half.
pub(crate) fn decode_run(row: &PgRow) -> Result<RunRow, ExecutionStoreError> {
    let status: String = row.try_get("status")?;
    Ok(RunRow {
        run_id: identity(row.try_get::<String, _>("run_id")?)?,
        tenant_id: identity(row.try_get::<String, _>("tenant_id")?)?,
        gateway_license_id: identity(row.try_get::<String, _>("gateway_license_id")?)?,
        owner_tenant_id: identity(row.try_get::<String, _>("owner_tenant_id")?)?,
        tool_id: identity(row.try_get::<String, _>("tool_id")?)?,
        binding_id: row
            .try_get::<Option<String>, _>("binding_id")?
            .map(identity)
            .transpose()?,
        binding_revision: row.try_get("binding_revision")?,
        credential_profile_id: row
            .try_get::<Option<String>, _>("credential_profile_id")?
            .map(identity)
            .transpose()?,
        profile_snapshot: row.try_get("profile_snapshot")?,
        tool_version: row.try_get("tool_version")?,
        authority: row.try_get("authority")?,
        inputs: row.try_get("inputs")?,
        input_hash: row.try_get("input_hash")?,
        idempotency_key: row.try_get("idempotency_key")?,
        created_by: row.try_get("created_by")?,
        status: RunStatus::parse(&status).ok_or_else(|| corrupt("run status"))?,
        created_at: instant(row.try_get("created_at_us")?)?,
        queue_deadline: instant(row.try_get("queue_deadline_us")?)?,
        started_at: optional_instant(row.try_get("started_at_us")?)?,
        finished_at: optional_instant(row.try_get("finished_at_us")?)?,
        cancel_requested: row.try_get("cancel_requested")?,
        result: row.try_get("result")?,
        error: row.try_get("error")?,
        payload_expired_at: optional_instant(row.try_get("payload_expired_at_us")?)?,
        mode: row.try_get("mode")?,
        runtime: runtime(row.try_get("runtime")?)?,
        external_ref: row.try_get("external_ref")?,
        status_message: row.try_get("status_message")?,
        actor: row.try_get("actor")?,
    })
}

/// The stored text of one [`Runtime`].
fn runtime_text(runtime: Runtime) -> &'static str {
    match runtime {
        Runtime::KataPython => "kata_python",
        Runtime::N8nWorkflow => "n8n_workflow",
        Runtime::FrProject => "fr_project",
        Runtime::FrCommand => "fr_command",
    }
}

/// A stored runtime name as the domain enum (the reference stores and validates the literal).
fn runtime(value: String) -> Result<Runtime, ExecutionStoreError> {
    serde_json::from_value(Value::String(value)).map_err(|_| corrupt("run runtime"))
}

/// The `integer` a version column stores.
pub(crate) fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

/// The stored identity as the crate's RFC 4122 UUID value.
pub(crate) fn identity(value: String) -> Result<Rfc4122Uuid, ExecutionStoreError> {
    Rfc4122Uuid::parse(&value).ok_or_else(|| corrupt("run identity"))
}

/// An epoch-microsecond column as an instant.
pub(crate) fn instant(micros: i64) -> Result<DateTime<Utc>, ExecutionStoreError> {
    DateTime::from_timestamp_micros(micros).ok_or_else(|| corrupt("run instant"))
}

/// A nullable epoch-microsecond column as an optional instant.
pub(crate) fn optional_instant(
    micros: Option<i64>,
) -> Result<Option<DateTime<Utc>>, ExecutionStoreError> {
    micros.map(instant).transpose()
}

/// A stored row outside the domain.
pub(crate) fn corrupt(what: &'static str) -> ExecutionStoreError {
    ExecutionStoreError::Store(CatalogStoreError::Corrupt(what))
}
