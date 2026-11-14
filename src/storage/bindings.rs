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

use std::collections::HashMap;
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
use crate::catalog::models::{Attribution, ExactReference, ServiceManifest};
use crate::catalog::toolkit_models::{
    BindingDescriptor, BindingSpec, CredentialProfile, EffectiveTool,
};
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

/// A fresh UUIDv7 identity: 48 bits of epoch milliseconds, 74 random bits, RFC 9562 version and
/// variant markers. The reference mints identities client-side with `uuid.uuid7()`; this crate
/// carries no UUID dependency, so the canonical string is assembled and validated here.
pub fn fresh_identity() -> Uuid7 {
    let mut bytes = [0u8; 16];
    let millis = u64::try_from(Utc::now().timestamp_millis()).unwrap_or(0) & 0x0000_ffff_ffff_ffff;
    bytes[..6].copy_from_slice(&millis.to_be_bytes()[2..]);
    rand::rng().fill_bytes(&mut bytes[6..]);
    bytes[6] = (bytes[6] & 0x0f) | 0x70;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let raw = hex(&bytes);
    let canonical = format!(
        "{}-{}-{}-{}-{}",
        &raw[0..8],
        &raw[8..12],
        &raw[12..16],
        &raw[16..20],
        &raw[20..32]
    );
    Uuid7::new(canonical).expect("a generated RFC 9562 UUIDv7 is canonical")
}

/// The reference's `profile_row`: one tenant-owned credential profile manifest, optionally
/// locked for an update (`FOR UPDATE`) or an issuance read (`FOR SHARE`).
///
/// A missing row is `CatalogNotFoundError("credential profile not found")`.
pub async fn profile_row(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    lock: bool,
    share: bool,
) -> Result<CredentialProfile, CatalogStoreError> {
    let statement = format!(
        "SELECT manifest FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid{}",
        if lock {
            " FOR UPDATE"
        } else if share {
            " FOR SHARE"
        } else {
            ""
        }
    );
    let row = sqlx::query(AssertSqlSafe(statement))
        .bind(tenant.as_str())
        .bind(identity.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(CatalogStoreError::NotFound("credential profile not found"))?;
    let manifest: Value = row.try_get("manifest")?;
    serde_json::from_value(manifest).map_err(|_| CatalogStoreError::Corrupt("credential profile"))
}

/// The reference's `validate_profile` service read: one manifest per operation behind a
/// selection, in one statement rather than one per operation.
pub async fn service_manifests(
    conn: &mut PgConnection,
    references: &[ExactReference],
) -> Result<HashMap<(String, u32), ServiceManifest>, CatalogStoreError> {
    if references.is_empty() {
        return Ok(HashMap::new());
    }
    let identities: Vec<String> = references
        .iter()
        .map(|reference| reference.id.as_str().to_owned())
        .collect();
    let versions: Vec<i32> = references
        .iter()
        .map(|reference| version_bits(reference.version))
        .collect();
    let rows = sqlx::query(
        "SELECT o.operation_id::text AS operation_id, o.version, s.manifest \
         FROM public.mcp_operation_versions o \
         JOIN public.mcp_service_versions s \
           ON (s.service_id, s.version) = (o.service_id, o.service_version) \
         WHERE (o.operation_id, o.version) IN \
           (SELECT * FROM unnest($1::text[]::uuid[], $2::int[]))",
    )
    .bind(&identities)
    .bind(&versions)
    .fetch_all(&mut *conn)
    .await?;
    let mut found: HashMap<(String, u32), ServiceManifest> =
        HashMap::with_capacity(references.len());
    for row in rows {
        let identity: String = row.try_get("operation_id")?;
        let stored: i32 = row.try_get("version")?;
        let version =
            u32::try_from(stored).map_err(|_| CatalogStoreError::Corrupt("operation version"))?;
        let manifest: Value = row.try_get("manifest")?;
        let manifest: ServiceManifest = serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("service manifest"))?;
        found.insert((identity, version), manifest);
    }
    Ok(found)
}

/// The reference's `write_binding` insert: the row and its token digest in one statement.
#[allow(clippy::too_many_arguments)]
pub async fn insert_binding(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    gateway_license_id: &AuthorityId,
    credential_profile_id: &Uuid7,
    token_sha256: &str,
    spec: &BindingSpec,
    tools: &[EffectiveTool],
    actor: &Attribution,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "INSERT INTO public.mcp_bindings(tenant_id,binding_id,gateway_license_id,\
         credential_profile_id,token_sha256,spec,tools,enabled,expires_at,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6::jsonb,$7::jsonb,$8,\
         (timestamptz 'epoch' + $9::bigint * interval '1 microsecond'),$10,$10)",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(gateway_license_id.as_str())
    .bind(credential_profile_id.as_str())
    .bind(token_sha256)
    .bind(snapshot(spec, "binding spec snapshot")?)
    .bind(tools_json(tools)?)
    .bind(spec.enabled)
    .bind(instant_micros(spec.expires_at))
    .bind(snapshot(actor, "binding actor snapshot")?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The reference's `write_binding` update: the replacement spec and its selection.
pub async fn update_binding(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    credential_profile_id: &Uuid7,
    spec: &BindingSpec,
    tools: &[EffectiveTool],
    actor: &Attribution,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "UPDATE public.mcp_bindings SET spec=$3::jsonb,tools=$4::jsonb,\
         credential_profile_id=$5::uuid,enabled=$6,\
         expires_at=(timestamptz 'epoch' + $7::bigint * interval '1 microsecond'),\
         revision=revision+1,updated_by=$8,updated_at=clock_timestamp() \
         WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(snapshot(spec, "binding spec snapshot")?)
    .bind(tools_json(tools)?)
    .bind(credential_profile_id.as_str())
    .bind(spec.enabled)
    .bind(instant_micros(spec.expires_at))
    .bind(snapshot(actor, "binding actor snapshot")?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The reference's `act_binding` update: rotate (`Some` digest) or revoke (keep the digest).
pub async fn rotate_or_revoke(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
    token_sha256: Option<&str>,
    revoked: bool,
    actor: &Attribution,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "UPDATE public.mcp_bindings SET token_sha256=COALESCE($3,token_sha256),revoked=$4,\
         revision=revision+1,updated_by=$5,updated_at=clock_timestamp() \
         WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .bind(token_sha256)
    .bind(revoked)
    .bind(snapshot(actor, "binding actor snapshot")?)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The reference's `act_binding` session drop: every protocol session of the binding.
pub async fn delete_sessions(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
) -> Result<(), CatalogStoreError> {
    sqlx::query(
        "DELETE FROM public.mcp_protocol_sessions \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
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

/// The reference's `snapshot`: the JSON form stored in every `jsonb` column.
fn snapshot<T: serde::Serialize>(
    value: &T,
    what: &'static str,
) -> Result<Value, CatalogStoreError> {
    serde_json::to_value(value).map_err(|_| CatalogStoreError::Corrupt(what))
}

/// An instant as epoch microseconds, the exact integer the write path binds.
fn instant_micros(instant: DateTime<Utc>) -> i64 {
    instant.timestamp_micros()
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
