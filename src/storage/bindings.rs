//! Binding reads, tokens and selection rows.
//!
//! Ported from the reference `src/storage/bindings.py` (`binding_descriptor`, `audit`,
//! `get_binding`, `binding_members`, `tools_json`, `check_revision`): the same statements, the
//! same conflict/not-found boundaries and the same audit actions. Every statement is
//! tenant-explicit (`WHERE tenant_id = $1`); there is no row-level security and no session
//! variable, exactly as the reference.
//!
//! Two implementation details are expressed in SQL because this crate carries no UUID generator
//! and no `sqlx` date mapping: `mcp_access_events.event_id` is minted by Postgres 18's
//! `uuidv7()`, and `expires_at` is read as epoch microseconds and rebuilt as a `DateTime<Utc>`.

use std::fmt::Write as _;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Utc};
use rand::Rng as _;
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgRow;
use sqlx::{AssertSqlSafe, PgConnection, PgPool, Row};

use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::models::Attribution;
use crate::catalog::toolkit_models::{BindingDescriptor, EffectiveTool};
use crate::storage::catalog::CatalogStoreError;

/// The number of random bytes behind a binding token: `secrets.token_urlsafe(32)`.
pub const TOKEN_BYTES: usize = 32;

/// Mint a binding token: [`TOKEN_BYTES`] cryptographically random bytes rendered as URL-safe
/// base64 without padding (43 characters, no prefix), exactly the reference's
/// `secrets.token_urlsafe(32)`.
pub fn mint_token() -> String {
    let mut bytes = [0u8; TOKEN_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The reference's `digest_token`: the lowercase SHA-256 hex of the token's UTF-8 bytes.
pub fn digest_token(token: &str) -> String {
    hex(&Sha256::digest(token.as_bytes()))
}

/// One `mcp_bindings` row.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BindingRow {
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// The binding identity.
    pub binding_id: Uuid7,
    /// The gateway licence the binding serves.
    pub gateway_license_id: AuthorityId,
    /// The credential profile the runtime resolves service credentials from.
    pub credential_profile_id: Uuid7,
    /// The lowercase SHA-256 hex of the token; the token itself is never stored.
    pub token_sha256: String,
    /// Whether the binding may serve calls.
    pub enabled: bool,
    /// Whether the binding has been revoked.
    pub revoked: bool,
    /// The binding's expiry.
    pub expires_at: DateTime<Utc>,
    /// The identity's revision.
    pub revision: i64,
    /// The stored spec.
    pub spec: Value,
    /// The stored effective tools.
    pub tools: Value,
}

/// The reference's `binding_descriptor`: the stored row as the served domain model.
pub fn descriptor(row: &BindingRow) -> Result<BindingDescriptor, CatalogStoreError> {
    Ok(BindingDescriptor {
        binding_id: row.binding_id.clone(),
        tenant_id: row.tenant_id.clone(),
        gateway_license_id: row.gateway_license_id.clone(),
        revision: positive(row.revision)?,
        revoked: row.revoked,
        spec: serde_json::from_value(row.spec.clone())
            .map_err(|_| CatalogStoreError::Corrupt("binding spec"))?,
        tools: serde_json::from_value(row.tools.clone())
            .map_err(|_| CatalogStoreError::Corrupt("binding tools"))?,
    })
}

/// The reference's `get_binding`: one tenant-owned row, optionally locked for an update.
///
/// A missing row is `CatalogNotFoundError("binding not found")`.
pub async fn get_binding(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    lock: bool,
) -> Result<BindingRow, CatalogStoreError> {
    let statement = format!(
        "SELECT {COLUMNS} FROM public.mcp_bindings \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid{}",
        if lock { " FOR UPDATE" } else { "" }
    );
    let row = sqlx::query(AssertSqlSafe(statement))
        .bind(tenant.as_str())
        .bind(identity.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound("binding not found"))?;
    decode_binding(&row)
}

/// The reference's `BindingRepository.inspect`: the binding descriptor of one owned row.
pub async fn inspect(
    pool: &PgPool,
    tenant: &AuthorityId,
    identity: &Uuid7,
) -> Result<BindingDescriptor, CatalogStoreError> {
    let mut conn = pool.acquire().await?;
    descriptor(&get_binding(&mut conn, tenant, identity, false).await?)
}

/// The reference's `binding_members`: replace the binding's selection rows.
///
/// The database checks the rows against `spec.toolkits` and `tools` at commit
/// (`mcp_access_complete`), so a caller must run this in the transaction that wrote the row.
pub async fn binding_members(
    conn: &mut PgConnection,
    binding: &BindingDescriptor,
) -> Result<(), CatalogStoreError> {
    let tenant = &binding.tenant_id;
    let identity = &binding.binding_id;
    sqlx::query(
        "DELETE FROM public.mcp_binding_tools \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .execute(&mut *conn)
    .await?;
    sqlx::query(
        "DELETE FROM public.mcp_binding_toolkits \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .execute(&mut *conn)
    .await?;
    for reference in &binding.spec.toolkits {
        sqlx::query(
            "INSERT INTO public.mcp_binding_toolkits(\
             tenant_id,binding_id,toolkit_id,version,owner_tenant_id) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4,$5::uuid)",
        )
        .bind(tenant.as_str())
        .bind(identity.as_str())
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .bind(reference.tenant_id.as_ref().unwrap_or(tenant).as_str())
        .execute(&mut *conn)
        .await?;
    }
    for tool in &binding.tools {
        sqlx::query(
            "INSERT INTO public.mcp_binding_tools(\
             tenant_id,binding_id,owner_tenant_id,tool_id,version,public_name) \
             VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6)",
        )
        .bind(tenant.as_str())
        .bind(identity.as_str())
        .bind(tool.tool.tenant_id.as_str())
        .bind(tool.tool.id.as_str())
        .bind(version_bits(tool.tool.version))
        .bind(tool.public_name.as_str())
        .execute(&mut *conn)
        .await?;
    }
    Ok(())
}

/// The reference's `tools_json`: the JSON array the binding stores in `tools`.
pub fn tools_json(tools: &[EffectiveTool]) -> Result<Value, CatalogStoreError> {
    serde_json::to_value(tools).map_err(|_| CatalogStoreError::Corrupt("binding tools snapshot"))
}

/// The reference's `check_revision`: refuse a caller whose read is stale.
pub fn check_revision(
    row: &BindingRow,
    expected: PositiveVersion,
) -> Result<(), CatalogStoreError> {
    if i64::from(expected.get()) != row.revision {
        return Err(CatalogStoreError::Conflict("expected revision conflict"));
    }
    Ok(())
}

/// The reference's `audit` for binding actions (`binding.changed`, `binding.rotated`,
/// `binding.revoked`): one append-only `mcp_access_events` row with no artifact version.
pub async fn audit_binding(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    actor: &Attribution,
    identity: &Uuid7,
    revision: PositiveVersion,
    action: &'static str,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "INSERT INTO public.mcp_access_events(\
         event_id,tenant_id,subject,license_id,entity_id,revision,action,artifact_version) \
         VALUES (uuidv7(),$1::uuid,$2,$3::uuid,$4::uuid,$5,$6,$7)",
    )
    .bind(tenant.as_str())
    .bind(actor.subject.as_str())
    .bind(actor.license_id.as_ref().map(AuthorityId::as_str))
    .bind(identity.as_str())
    .bind(i64::from(revision.get()))
    .bind(action)
    .bind(None::<i32>)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The row columns [`get_binding`] reads. `expires_at` travels as epoch microseconds because
/// this crate's `sqlx` build carries no `chrono` type mapping.
const COLUMNS: &str = "tenant_id::text AS tenant_id, binding_id::text AS binding_id, \
     gateway_license_id::text AS gateway_license_id, \
     credential_profile_id::text AS credential_profile_id, token_sha256, enabled, revoked, \
     (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_micros, revision, spec, \
     tools";

fn decode_binding(row: &PgRow) -> Result<BindingRow, CatalogStoreError> {
    Ok(BindingRow {
        tenant_id: parse_authority(row.try_get::<String, _>("tenant_id")?)?,
        binding_id: parse_identity(row.try_get::<String, _>("binding_id")?)?,
        gateway_license_id: parse_authority(row.try_get::<String, _>("gateway_license_id")?)?,
        credential_profile_id: parse_identity(row.try_get::<String, _>("credential_profile_id")?)?,
        token_sha256: row.try_get("token_sha256")?,
        enabled: row.try_get("enabled")?,
        revoked: row.try_get("revoked")?,
        expires_at: DateTime::from_timestamp_micros(row.try_get::<i64, _>("expires_at_micros")?)
            .ok_or(CatalogStoreError::Corrupt("binding expiry"))?,
        revision: row.try_get("revision")?,
        spec: row.try_get("spec")?,
        tools: row.try_get("tools")?,
    })
}

/// The reference's `hexdigest()`.
fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

fn positive(value: i64) -> Result<PositiveVersion, CatalogStoreError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(CatalogStoreError::Corrupt("positive version"))
}

fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

fn parse_authority(value: String) -> Result<AuthorityId, CatalogStoreError> {
    AuthorityId::new(value).map_err(|_| CatalogStoreError::Corrupt("binding authority"))
}

fn parse_identity(value: String) -> Result<Uuid7, CatalogStoreError> {
    Uuid7::new(value).map_err(|_| CatalogStoreError::Corrupt("binding identity"))
}
