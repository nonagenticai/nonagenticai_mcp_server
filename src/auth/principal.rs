//! Immutable identities resolved by the authentication layer.
//!
//! Incoming bearer credentials never enter these values: they carry only what the licence
//! authority asserted and the binding lookup resolved.

use super::uuid::Rfc4122Uuid;

/// `subject_kind` of a licence holder, as the licence authority reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SubjectKind {
    /// A tenant-level holder (`svc:<tenant>:<app>`), never a person.
    Tenant,
    /// A person's per-login licence.
    Member,
}

/// The introspected licence authority (see `licences::LicenceAuthority`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LicenseIdentity {
    pub tenant_id: Rfc4122Uuid,
    pub license_id: Rfc4122Uuid,
    pub subject: String,
    pub subject_kind: Option<SubjectKind>,
}

impl LicenseIdentity {
    /// A binding's gateway licence must be the tenant's own (`svc:<tenant>:<mcp>`), never a
    /// member's per-login licence.
    pub fn tenant_level(&self) -> bool {
        self.subject_kind == Some(SubjectKind::Tenant)
    }
}

/// The authenticated principal stored in request extensions by the `/mcp` middleware.
///
/// `management` is set by the operator-key path; `platform` raises a management principal with
/// a valid platform key. Binding principals carry the binding the token resolved to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub tenant_id: Rfc4122Uuid,
    pub license_id: Rfc4122Uuid,
    pub subject: String,
    pub binding_id: Option<Rfc4122Uuid>,
    pub binding_revision: Option<i64>,
    pub management: bool,
    pub platform: bool,
}
