//! The API binary's composition of the tool builder.
//!
//! The reference runs one process over one `Settings`; this crate split it into an API and a
//! worker, so the builder's collaborators are assembled here from the settings the API already
//! parses. Nothing is invented: every constructor is the worker's own, and a missing piece
//! fails closed exactly as it does there — no document fetcher makes every spec fetch
//! unavailable, no licence minter makes licence-kind sources refuse, no draft settings make
//! test runs unavailable.
//!
//! The service is installed only when `MCP_BUILDER_ENABLED` is true. With the flag off the
//! caller keeps [`BuilderRuntime::disabled`], which answers the reference's `404 not_found` on
//! both mounts before any credential is read.

use std::sync::Arc;

use crate::AppState;
use crate::auth::{Auth, KeycloakVerifier};
use crate::builder::{
    BuilderService, BuilderServiceDependencies, DocumentFetcher, PinnedEgressFetcher,
};
use crate::catalog::ids::AuthorityId;
use crate::catalog::service::CatalogService;
use crate::catalog::validation::SchemaLimits;
use crate::config::{AuthConfig, Config, ConfigError};
use crate::routes::builder::BuilderRuntime;
use crate::sources::tenant_repository::{TenantSourceRepository, TenantSourceSettings};
use crate::storage::bindings_ensure::{BindingEnsureService, LicenceLookup};
use crate::storage::builder::{BuilderCatalogRepository, DraftLicenceLookup, DraftRunSettings};
use crate::storage::catalog::CatalogRepository;
use crate::toolkits::resolver::SelectionResolver;
use crate::worker::broker::auth::AuthAdapters;
use crate::worker::broker::egress::{
    EgressPolicy, PlatformClients, PoolLimits, SystemResolver, tenant_client,
};
use crate::worker::creds::{CredentialResolver, FileResolver, Minter};
use crate::worker::sources::SourceRegistry;

/// How many cached OpenAPI documents one builder source keeps (the reference's constant).
const SPEC_KEEP: i32 = 3;

/// The enabled builder runtime: the reference's `builder_runtime.install` (`asgi.py:125`).
pub fn runtime(
    cfg: &Config,
    auth_config: &AuthConfig,
    auth: &Auth,
    state: &AppState,
) -> Result<BuilderRuntime, ConfigError> {
    let platform_tenant =
        AuthorityId::new(cfg.platform_tenant_id.to_string()).map_err(|_| ConfigError::Invalid {
            name: "PLATFORM_TENANT_ID",
            reason: "the platform tenant is not an authority identity".into(),
        })?;
    let limits = PoolLimits::default();
    let deny: Vec<&str> = cfg.builder.deny_cidrs.iter().map(String::as_str).collect();
    let egress = Arc::new(
        EgressPolicy::new(&cfg.builder.allowed_ports, &deny, Arc::new(SystemResolver)).map_err(
            |error| ConfigError::Invalid {
                name: "MCP_BUILDER_ALLOWED_PORTS",
                reason: format!("the builder egress policy is unusable: {error}"),
            },
        )?,
    );
    let platform = PlatformClients::new(limits);
    let platform_client = platform
        .client_for(None)
        .map_err(|error| ConfigError::Invalid {
            name: "MCP_BUILDER_ENABLED",
            reason: format!("cannot build the platform HTTP client: {error}"),
        })?;
    let tenant_http = tenant_client(&egress, Some(limits))
        .build()
        .map_err(|error| ConfigError::Invalid {
            name: "MCP_BUILDER_ENABLED",
            reason: format!("cannot build the tenant HTTP client: {error}"),
        })?;
    let adapters = AuthAdapters::new(
        (*platform_client).clone(),
        tenant_http,
        cfg.builder.oauth_token_max_ttl,
    );

    // The builder's licence minter is the SAME configured `MCP_LICENCE_MINTER_*` that
    // `/mcp/internal` uses, so a source's minted credential and a binding's agree. Without one
    // a mounted bundle may still answer licence-kind sources; without either they refuse.
    let minter = if auth_config.binding_ensure.minter.enabled {
        Some(Arc::new(
            Minter::new(
                &auth_config.binding_ensure.minter,
                state.license_app_key.clone(),
                auth.licences.clone(),
                (*platform_client).clone(),
            )
            .map_err(|_| ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_SECRET_FILE",
                reason: "the minter client secret is unavailable".into(),
            })?,
        ))
    } else {
        None
    };
    let credentials: Option<Arc<dyn CredentialResolver>> = match &minter {
        Some(minter) => Some(minter.clone() as Arc<dyn CredentialResolver>),
        None => cfg
            .builder
            .credential_bundle_file
            .as_ref()
            .map(|path| Arc::new(FileResolver::new(path)) as Arc<dyn CredentialResolver>),
    };
    let draft_minter: Option<Arc<dyn DraftLicenceLookup>> = minter
        .clone()
        .map(|minter| minter as Arc<dyn DraftLicenceLookup>);
    let ensure_minter: Option<Arc<dyn LicenceLookup>> =
        minter.map(|minter| minter as Arc<dyn LicenceLookup>);

    let registry = SourceRegistry::new(
        state.pool.clone(),
        cfg.sources.secret_key_text.as_deref(),
        cfg.sources.allowed_hosts.clone(),
    )
    .map_err(|_| ConfigError::Invalid {
        name: "MCP_SOURCE_SECRET_KEY",
        reason: "the source sealing key is unusable".into(),
    })?;
    let tenant_sources = TenantSourceRepository::from_settings(
        state.pool.clone(),
        &TenantSourceSettings {
            secret_key: cfg.sources.secret_key.clone(),
            max_sources: cfg.builder.max_sources,
            licence_hosts: cfg.sources.allowed_hosts.clone(),
            allowed_ports: cfg.builder.allowed_ports.clone(),
            spec_keep: SPEC_KEEP,
            spec_max_total_bytes: cfg.builder.spec_max_total_bytes_per_tenant,
        },
    );
    let resolver = SelectionResolver {
        platform_tenant_id: platform_tenant.clone(),
    };
    let catalog = CatalogService::new(
        CatalogRepository::new(state.pool.clone()),
        SchemaLimits::default(),
        cfg.packages,
    );
    let fetcher = Arc::new(PinnedEgressFetcher::new(
        egress,
        limits,
        adapters,
        credentials,
    ));
    let ensure = BindingEnsureService::new(
        state.pool.clone(),
        resolver.clone(),
        state.license_app_key.clone(),
        auth.licences.clone(),
        ensure_minter,
        &auth_config.binding_ensure,
        platform_tenant.clone(),
    );
    let draft = DraftRunSettings {
        execution_enabled: cfg.execution_enabled,
        platform_tenant_id: platform_tenant,
        license_app_key: state.license_app_key.clone(),
        approved_runner_images: cfg.approved_runner_images.clone(),
        sync_wait: cfg.execution.sync_wait,
        queue_global_max: cfg.execution.queue_global_max,
        queue_per_tenant_max: cfg.execution.queue_per_tenant_max,
        run_queue_timeout: cfg.execution.run_queue_timeout,
        run_max: cfg.builder.run_max,
        max_api_calls_per_run: cfg.builder.max_api_calls_per_run,
        test_runs_per_hour: cfg.builder.test_runs_per_hour,
    };
    let service = Arc::new(BuilderService::new(
        state.pool.clone(),
        cfg.builder.clone(),
        SchemaLimits::default(),
        cfg.approved_runner_images.clone(),
        BuilderServiceDependencies {
            sources: tenant_sources,
            builder: BuilderCatalogRepository::new(state.pool.clone()),
            catalog,
            resolver,
            draft: Some(draft),
            minter: draft_minter,
            fetcher: Some(fetcher as Arc<dyn DocumentFetcher>),
            registry: Some(registry),
            ensure: Some(ensure),
        },
    ));

    let keycloak = match &auth_config.keycloak {
        Some(settings) => Some(Arc::new(KeycloakVerifier::from_settings(settings)?)),
        None => None,
    };
    Ok(BuilderRuntime::new(
        service,
        keycloak,
        auth.licences.clone(),
        cfg.platform_tenant_id,
        state.license_app_key.clone(),
        auth.max_management_bytes,
    ))
}
