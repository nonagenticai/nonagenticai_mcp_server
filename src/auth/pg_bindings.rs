//! The real binding authority: an `X-MCP-Binding` token resolved against `mcp_bindings`.
//!
//! The reference's `BindingRepository.authenticate`: the lookup is scoped to the caller's
//! tenant and keyed by the token's SHA-256 digest; the stored digest is compared in constant
//! time. Any denial — unknown token, digest mismatch, foreign gateway licence, disabled,
//! revoked or expired — is `AuthError::Unauthorized`, never "authority unavailable": the
//! authority answered, and the answer is no. Only a database failure is `Unavailable`.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Row};
use subtle::ConstantTimeEq as _;

use super::BoxFuture;
use super::bindings::{Binding, BindingAuthority};
use super::error::AuthError;
use super::principal::LicenseIdentity;
use super::uuid::Rfc4122Uuid;
use crate::storage::bindings::digest_token;

/// Resolves binding tokens through the tenant's own `mcp_bindings` rows.
#[derive(Debug, Clone)]
pub struct PgBindingAuthority {
    pool: PgPool,
}

impl PgBindingAuthority {
    /// Bind the authority to a pool.
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

impl BindingAuthority for PgBindingAuthority {
    fn authenticate<'a>(
        &'a self,
        identity: &'a LicenseIdentity,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async move {
            let digest = digest_token(token);
            let mut conn = self
                .pool
                .acquire()
                .await
                .map_err(|_| AuthError::Unavailable)?;
            let row = sqlx::query(
                "SELECT binding_id::text AS binding_id, token_sha256, \
                 gateway_license_id::text AS gateway_license_id, enabled, revoked, \
                 (extract(epoch FROM expires_at) * 1000000)::bigint AS expires_at_micros, \
                 revision \
                 FROM public.mcp_bindings \
                 WHERE tenant_id = $1::uuid AND token_sha256 = $2",
            )
            .bind(identity.tenant_id.to_string())
            .bind(&digest)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|_| AuthError::Unavailable)?
            .ok_or(AuthError::Unauthorized)?;

            let stored: String = row.try_get("token_sha256").map_err(unavailable)?;
            let gateway_license_id: String =
                row.try_get("gateway_license_id").map_err(unavailable)?;
            let enabled: bool = row.try_get("enabled").map_err(unavailable)?;
            let revoked: bool = row.try_get("revoked").map_err(unavailable)?;
            let expires: DateTime<Utc> = DateTime::from_timestamp_micros(
                row.try_get("expires_at_micros").map_err(unavailable)?,
            )
            .ok_or(AuthError::Unavailable)?;
            let revision: i64 = row.try_get("revision").map_err(unavailable)?;
            let binding_id: String = row.try_get("binding_id").map_err(unavailable)?;

            let digest_matches: bool = stored.as_bytes().ct_eq(digest.as_bytes()).into();
            if !digest_matches
                || gateway_license_id != identity.license_id.to_string()
                || !enabled
                || revoked
                || expires <= Utc::now()
            {
                return Err(AuthError::Unauthorized);
            }
            Ok(Binding {
                binding_id: Rfc4122Uuid::parse(&binding_id).ok_or(AuthError::Unavailable)?,
                revision,
            })
        })
    }
}

/// A stored value that does not decode is the store's fault, not the caller's credential.
fn unavailable(_: sqlx::Error) -> AuthError {
    AuthError::Unavailable
}
