//! The binding seam.
//!
//! Resolving an `X-MCP-Binding` token into a binding row is storage work and lives in the
//! storage slice. This module defines only the trait the authentication layer calls, so the
//! middleware has no database code and the storage slice binds its implementation in through
//! [`super::Auth::with_bindings`].

use super::BoxFuture;
use super::error::AuthError;
use super::principal::LicenseIdentity;
use super::uuid::Rfc4122Uuid;

/// The binding an `X-MCP-Binding` token resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Binding {
    pub binding_id: Rfc4122Uuid,
    pub revision: i64,
}

/// Authenticates a binding token for an already-introspected tenant licence.
///
/// Implementations MUST scope the lookup to `identity.tenant_id` and return
/// `AuthError::Unauthorized` for an unknown/foreign token; `AuthError::Unavailable` when the
/// store cannot be read. No database code lives in this crate's auth layer.
pub trait BindingAuthority: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        identity: &'a LicenseIdentity,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>>;
}

/// The default until the storage slice wires the real authority: binding requests fail
/// closed with 503 rather than ever being admitted.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnavailableBindings;

impl BindingAuthority for UnavailableBindings {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        _token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async { Err(AuthError::Unavailable) })
    }
}
