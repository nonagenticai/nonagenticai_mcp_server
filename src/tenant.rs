//! Trusted-header tenant extractor.
//!
//! The tenant arrives in `X-Tenant-Id`, set by the trusted edge in front of this service
//! (gateway / licence introspection), exactly like the Python services' `X-Tenant-*`
//! headers. The service TRUSTS it, so it must only be reachable through that edge
//! (mesh AuthorizationPolicy at onboarding). Never derive a tenant from a licence
//! `subject_id`.
//!
//! Use it as a handler argument: `async fn list(tenant: TenantId, ...)`, and document the
//! header in OpenAPI with `params(TenantHeader)` on the `#[utoipa::path]`.

use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use serde::Deserialize;
use utoipa::IntoParams;

use crate::error::AppError;

/// Header name (HTTP header names are case-insensitive; this is the canonical spelling).
pub const TENANT_HEADER: &str = "X-Tenant-Id";
/// Upper bound on the header value; tenant ids are UUIDs or short slugs.
const MAX_LEN: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantId(pub String);

impl TenantId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<S: Send + Sync> FromRequestParts<S> for TenantId {
    type Rejection = AppError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let raw = parts
            .headers
            .get(TENANT_HEADER)
            .ok_or_else(|| AppError::Unauthorized(format!("missing {TENANT_HEADER} header")))?;
        let value = raw
            .to_str()
            .map_err(|_| AppError::Unauthorized(format!("invalid {TENANT_HEADER} header")))?
            .trim();
        let valid = !value.is_empty()
            && value.len() <= MAX_LEN
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
        if !valid {
            return Err(AppError::Unauthorized(format!(
                "invalid {TENANT_HEADER} header"
            )));
        }
        Ok(TenantId(value.to_owned()))
    }
}

/// OpenAPI-only description of the header, for `params(TenantHeader)`.
#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Header)]
pub struct TenantHeader {
    /// Tenant id set by the trusted edge.
    #[serde(rename = "X-Tenant-Id")]
    pub x_tenant_id: String,
}
