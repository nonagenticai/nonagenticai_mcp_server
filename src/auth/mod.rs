//! Authentication and authorisation for the `/mcp` surface (phase 2).
//!
//! The layer reproduces the reference service's middleware contract:
//! `POST {"token": ..., "app": ...}` licence introspection, operator keys mounted as files,
//! binding-token resolution behind a storage trait seam, and the fixed error bodies
//! `{"error": "unauthorized" | "forbidden" | "authority_unavailable" | "request_too_large"}`
//! with `Cache-Control: no-store`. No settings means no access — never a bypass.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::config::ConfigError;

pub mod bindings;
pub mod error;
pub mod keycloak;
pub mod licenses;
pub mod management;
pub mod pg_bindings;
pub mod principal;
pub mod protocol;
pub mod time;
pub mod uuid;

pub use crate::config::AuthConfig;
pub use crate::config::KeycloakSettings;
pub use bindings::{Binding, BindingAuthority, UnavailableBindings};
pub use error::AuthError;
pub use keycloak::{
    AuthorPrincipal, KeycloakError, KeycloakVerifier, ServiceClaims, ServicePrincipal,
    author_principal,
};
pub use licenses::{
    HttpLicenceAuthority, LicenceApp, LicenceAuthority, UnconfiguredLicenceAuthority,
};
pub use management::ManagementAuthorizer;
pub use pg_bindings::PgBindingAuthority;
pub use principal::{LicenceFacts, LicenseIdentity, Principal, SubjectKind};
pub use protocol::{AuthPrincipal, is_management, protect};
pub use uuid::Rfc4122Uuid;

/// A boxed, `Send` future; async trait methods stay object-safe without an `async_trait`
/// dependency (this crate adds no dependencies).
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Everything the `/mcp` middleware needs, resolved once at startup.
#[derive(Clone)]
pub struct Auth {
    pub licences: Arc<dyn LicenceAuthority>,
    pub management: Arc<ManagementAuthorizer>,
    pub bindings: Arc<dyn BindingAuthority>,
    /// `MCP_MAX_MANAGEMENT_BYTES`: the bound on a buffered management request body.
    pub max_management_bytes: usize,
    /// `MCP_LICENSE_APP_KEY`: the application key a tenant's own licence carries — the tool
    /// builder's author credential when it is enabled (`auth/protocol.py:113-125`).
    pub license_app_key: Option<String>,
    /// `MCP_BUILDER_ENABLED`: whether a tenant-level `mcp` licence with no binding is the
    /// builder's author. Off, that licence is the reference's 401 "binding required".
    pub builder_enabled: bool,
    /// The reserved platform tenant, which never authors through the builder (403).
    pub platform_tenant_id: Rfc4122Uuid,
}

impl Auth {
    /// Read the authentication settings and operator key files. Invalid settings (a key file
    /// that is unreadable or too short, two equal key files, a half-configured authority) are
    /// a startup error, exactly as in the reference service.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_config(&AuthConfig::from_env()?)
    }

    /// Build from already-parsed settings; [`AuthConfig::validate`] runs first, so a config
    /// assembled by hand (tests, a future supervisor) cannot skip the cross-setting rules.
    pub fn from_config(config: &AuthConfig) -> Result<Self, ConfigError> {
        config.validate()?;
        let licences: Arc<dyn LicenceAuthority> =
            match (&config.license_introspect_url, &config.license_app_key) {
                (Some(url), Some(app_key)) => Arc::new(HttpLicenceAuthority::new(
                    url,
                    app_key,
                    config.license_timeout,
                    config.license_max_response_bytes,
                    config.license_expiry_skew,
                )?),
                _ => Arc::new(UnconfiguredLicenceAuthority),
            };
        Ok(Self {
            licences,
            management: Arc::new(ManagementAuthorizer::from_config(config)?),
            // The storage slice supplies the real authority; until it is wired, binding
            // requests fail closed.
            bindings: Arc::new(UnavailableBindings),
            max_management_bytes: config.max_management_bytes,
            license_app_key: config.license_app_key.clone(),
            builder_enabled: false,
            platform_tenant_id: crate::config::default_platform_tenant_id(),
        })
    }

    /// The composition root's builder facts: whether `MCP_BUILDER_ENABLED` is on and which
    /// tenant is the platform's. Everything else was already read from the same settings.
    pub fn with_builder(mut self, enabled: bool, platform_tenant_id: Rfc4122Uuid) -> Self {
        self.builder_enabled = enabled;
        self.platform_tenant_id = platform_tenant_id;
        self
    }

    /// Replace the binding authority (the storage slice's seam; tests use a fake).
    pub fn with_bindings(mut self, bindings: Arc<dyn BindingAuthority>) -> Self {
        self.bindings = bindings;
        self
    }
}
