//! The worker loop: wiring, signals, reconcile ticks and graceful teardown (slice S8).
//!
//! Ported from the reference `src/execution/worker.py`. The worker is the only process that
//! holds credentials and Kubernetes permissions; its only inputs are the `mcp_*` tables and its
//! only listener is the internal probe port.
//!
//! The loop is the reference's, including its failure posture: a transient database failure is
//! logged, backed off (0.2 s doubling to 5 s) and retried, and only *60 consecutive* failures
//! end the process — at which point Kubernetes restarts it and the crash is visible. Anything
//! else exits immediately rather than retrying a fault the worker cannot fix. Shutdown is
//! cooperative: the controllers select on one watch flag, so each in-flight run still stops its
//! pod and persists `interrupted`/`worker_stopped` before the process exits.

use std::sync::Arc;
use std::time::Duration;

use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio::time::{Instant, sleep};

use crate::auth::licenses::{HttpLicenceAuthority, LicenceAuthority, UnconfiguredLicenceAuthority};
use crate::auth::uuid::Rfc4122Uuid;
use crate::catalog::ids::AuthorityId;
use crate::catalog::resolver::CatalogResolver;
use crate::config::{
    AuthConfig, ConfigError, ExecutionSettings, WorkerSettings, default_platform_tenant_id,
};
use crate::db;
use crate::storage::catalog::CatalogRepository;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::ToolkitService;
use crate::worker::backend::{Backend, BackendError};
use crate::worker::broker::Broker;
use crate::worker::broker::auth::AuthAdapters;
use crate::worker::broker::egress::{
    EgressError, EgressPolicy, PlatformClients, PoolLimits, SystemResolver, tenant_client,
};
use crate::worker::broker::limits::SourceLimiter;
use crate::worker::controller::Controller;
use crate::worker::creds::{CredentialError, CredentialResolver, FileResolver, Minter};
use crate::worker::health;
use crate::worker::kata::Kata;
use crate::worker::recovery::Recovery;
use crate::worker::scheduler::Scheduler;
use crate::worker::sources::{SourceError, SourceRegistry};
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// The reference's transient-failure taxonomy, as far as `sqlx` can express it: the connection
/// was closed under the pool, the handle is unusable, or the pool could not hand one out in
/// time. A query error or a decode failure is not transient and exits.
fn transient(error: &WorkerStoreError) -> bool {
    matches!(
        error,
        WorkerStoreError::Store(
            sqlx::Error::Io(_)
                | sqlx::Error::PoolTimedOut
                | sqlx::Error::PoolClosed
                | sqlx::Error::WorkerCrashed
        )
    )
}

/// After this many consecutive transient failures (~5 minutes at the 5 s cap) the worker exits
/// instead of retrying forever (`worker.py:42`).
const TRANSIENT_RETRY_LIMIT: u32 = 60;

/// The reference's fixed backoff floor (`worker.py:111`).
const BACKOFF_FLOOR: Duration = Duration::from_millis(200);
/// The reference's fixed backoff ceiling (`worker.py:146`).
const BACKOFF_CEILING: Duration = Duration::from_secs(5);
/// How often the idle loop checks for a shutdown or a finished task (`worker.py:149`).
const IDLE_WAIT: Duration = Duration::from_millis(200);

/// Why the worker could not run, or stopped running.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    /// The worker is not configured to execute anything (the reference's `ValueError`).
    #[error("{0}")]
    Refused(&'static str),
    #[error("DATABASE_URL is not set")]
    MissingDatabaseUrl,
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error("worker storage: {0}")]
    Store(#[from] WorkerStoreError),
    #[error("runner backend: {0}")]
    Backend(#[from] BackendError),
    #[error("credentials: {0}")]
    Credential(#[from] CredentialError),
    #[error("sources: {0}")]
    Source(#[from] SourceError),
    #[error("egress: {0}")]
    Egress(#[from] EgressError),
    #[error("http client: {0}")]
    Http(#[from] reqwest::Error),
    #[error("kubernetes: {0}")]
    Kubernetes(#[from] kube::Error),
    #[error("worker io: {0}")]
    Io(#[from] std::io::Error),
    #[error("probe server failed: {0}")]
    Probe(String),
}

/// The worker binary's entry point: load settings, refuse an unusable configuration, and serve
/// until a signal or a permanent failure.
pub async fn run() -> Result<(), RuntimeError> {
    let settings = WorkerSettings::from_env()?;
    let execution = ExecutionSettings::from_env()?;
    let auth_config = AuthConfig::from_env()?;

    // The reference's worker-start rule (`worker.py:61-64`): an explicitly enabled executor with
    // an explicit credential source, or no process at all.
    if !execution_enabled()?
        || (settings.credential_bundle_file.is_none() && !settings.licence_minter.enabled)
    {
        return Err(RuntimeError::Refused(
            "worker requires explicit execution enablement and worker configuration",
        ));
    }

    // `Config::from_env` also requires `BIND_ADDR`, which an executor does not serve on. The
    // worker needs only the pool URL, so it reads the same variable directly.
    let database_url = std::env::var("DATABASE_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(RuntimeError::MissingDatabaseUrl)?;
    let pool = db::connect(&database_url).await?;
    let served = serve(&settings, &execution, &auth_config, pool.clone()).await;
    pool.close().await;
    served
}

/// Build the worker's dependencies and run the claim loop until shutdown.
async fn serve(
    settings: &WorkerSettings,
    execution: &ExecutionSettings,
    auth_config: &AuthConfig,
    pool: PgPool,
) -> Result<(), RuntimeError> {
    // The schema contract first: a worker never repairs or guesses a schema (`worker.py:75-76`).
    health::verify_schema(&pool).await?;

    // The licences service is optional. Without it, minted credentials fail closed exactly as
    // the reference's unconfigured client does.
    let licences: Arc<dyn LicenceAuthority> = licence_authority(auth_config)?;

    // The two egress shapes: platform sources through the pooled platform client, tenant
    // sources through the pinned, SSRF-checked transport.
    let egress = Arc::new(EgressPolicy::from_settings(
        settings,
        Arc::new(SystemResolver),
    ));
    let platform_http = PlatformClients::new(PoolLimits::default());
    let platform_client = platform_http.client_for(None)?;
    let tenant_http = tenant_client(&egress, Some(PoolLimits::default())).build()?;
    let limiter = SourceLimiter::new(
        settings.builder_source_calls_per_minute,
        settings.builder_source_concurrency,
    );

    let credentials: Arc<dyn CredentialResolver> = credential_resolver(
        settings,
        auth_config.license_app_key.clone(),
        licences.clone(),
        (*platform_client).clone(),
    )?;
    credentials.read().map_err(RuntimeError::Credential)?;

    let store = WorkerStore::new(pool.clone(), settings.clone(), execution.clone());
    let scheduler = Arc::new(Scheduler::new(store.clone()));
    scheduler.verify_capacity().await?;

    let platform_tenant = platform_tenant_id()?;
    let resolver = CatalogResolver::new(
        pool.clone(),
        ToolkitService::new(
            pool.clone(),
            SelectionResolver {
                platform_tenant_id: platform_tenant.clone(),
            },
            auth_config.license_app_key.clone(),
        ),
        settings.approved_runner_images.clone(),
    );

    let backend: Arc<dyn Backend> = Arc::new(Kata::new(
        kube::Client::try_default().await?,
        settings.clone(),
    )?);
    backend.ready().await?;

    let auth = AuthAdapters::new(
        (*platform_client).clone(),
        tenant_http,
        settings.builder_oauth_token_max_ttl,
    );
    let sources = SourceRegistry::new(pool.clone(), settings.source_secret_key.as_deref())?;

    let broker = Arc::new(Broker::new(
        pool.clone(),
        store.clone(),
        settings.clone(),
        execution.clone(),
        CatalogRepository::new(pool.clone()),
        resolver.clone(),
        credentials.clone(),
        licences.clone(),
        sources,
        auth,
        egress,
        limiter,
        platform_http,
        auth_config.license_app_key.clone(),
        platform_tenant,
    ));

    let (shutdown_tx, shutdown_rx) = watch::channel(false);

    let controller = Controller::new(
        store.clone(),
        resolver,
        broker.clone(),
        backend.clone(),
        pool.clone(),
        settings.clone(),
        execution.clone(),
        shutdown_rx.clone(),
    );
    let recovery = Recovery::new(store.clone(), backend.clone());

    // The probe listener is the worker's only port; the deployment maps it and the worker's
    // NetworkPolicy restricts it to the cluster.
    let listener = TcpListener::bind(("0.0.0.0", settings.probe_port)).await?;
    let router = health::app(
        store.clone(),
        scheduler.clone(),
        backend.clone(),
        credentials.clone(),
    );
    let mut probe_shutdown = shutdown_rx.clone();
    let probe = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = probe_shutdown.wait_for(|value| *value).await;
            })
            .await
    });

    // The executor owns signals; the probe server never replaces handlers.
    let signal_tx = shutdown_tx.clone();
    tokio::spawn(async move {
        shutdown_signal().await;
        let _ = signal_tx.send(true);
    });

    let worker = uuid::Uuid::now_v7().to_string();
    let capacity =
        usize::try_from(settings.max_inflight.min(settings.global_slots)).unwrap_or(usize::MAX);
    let mut active: Vec<tokio::task::JoinHandle<()>> = Vec::new();
    let mut next_reconcile = Instant::now();
    let mut delay = BACKOFF_FLOOR;
    let mut failures: u32 = 0;
    let mut idle = shutdown_rx.clone();

    // The loop's outcome is captured, never returned directly: teardown must run either way.
    let loop_result: Result<(), RuntimeError> = async {
        while !*shutdown_rx.borrow() {
            if probe.is_finished() {
                tracing::error!("the probe server stopped; exiting");
                break;
            }

            // One loop body: reconcile on schedule, collect finished runs, claim when there is
            // local and durable capacity. Every storage call inside is retryable the same way.
            let step: Result<bool, WorkerStoreError> = async {
                if Instant::now() >= next_reconcile {
                    recovery.reconcile(&worker).await?;
                    store.expire_payloads().await?;
                    next_reconcile = Instant::now() + settings.reconcile;
                }
                // A failed run is a failed run, not a worker exit.
                let mut remaining = Vec::with_capacity(active.len());
                for handle in active.drain(..) {
                    if !handle.is_finished() {
                        remaining.push(handle);
                        continue;
                    }
                    if let Err(error) = handle.await {
                        tracing::error!(error = %error, "execution task failed");
                    }
                }
                active = remaining;
                // Bounds the local task count as well as durable global capacity.
                if active.len() < capacity
                    && let Some(row) = scheduler.claim(&worker).await?
                {
                    let controller = controller.clone();
                    active.push(tokio::spawn(async move { controller.execute(row).await }));
                    return Ok(true);
                }
                Ok(false)
            }
            .await;

            match step {
                Ok(claimed) => {
                    delay = BACKOFF_FLOOR;
                    failures = 0;
                    if claimed {
                        continue;
                    }
                }
                Err(error) if transient(&error) => {
                    failures += 1;
                    if failures >= TRANSIENT_RETRY_LIMIT {
                        tracing::error!(
                            failures,
                            "database still unavailable after repeated retries; exiting"
                        );
                        let _ = shutdown_tx.send(true);
                        return Err(RuntimeError::Store(error));
                    }
                    tracing::warn!(
                        error = %error,
                        retry_in = ?delay,
                        "transient database error; retrying"
                    );
                    tokio::select! {
                        () = sleep(delay) => {}
                        result = idle.changed() => { let _ = result; }
                    }
                    delay = (delay * 2).min(BACKOFF_CEILING);
                    continue;
                }
                Err(error) => {
                    let _ = shutdown_tx.send(true);
                    return Err(RuntimeError::Store(error));
                }
            }

            tokio::select! {
                () = sleep(IDLE_WAIT) => {}
                result = idle.changed() => { let _ = result; }
            }
        }
        Ok(())
    }
    .await;

    // Graceful teardown, in the reference's order: probes first, then the runs (which stop
    // their own pods and persist `worker_stopped`), then the broker and the pool.
    let _ = shutdown_tx.send(true);

    let probe_result = match probe.await {
        Ok(result) => result.map_err(|error| RuntimeError::Probe(error.to_string())),
        Err(error) => Err(RuntimeError::Probe(error.to_string())),
    };

    for handle in active.drain(..) {
        let _ = handle.await;
    }

    broker.close().await;
    // The backend, credential resolver and licences client hold only connections and caches;
    // dropping them is their close.
    drop(backend);
    drop(credentials);
    drop(licences);

    loop_result.and(probe_result)
}

/// Licence-minted per-tenant credentials when enabled, else the mounted bundle file
/// (`worker.py:52-56`).
fn credential_resolver(
    settings: &WorkerSettings,
    gateway_app_key: Option<String>,
    licences: Arc<dyn LicenceAuthority>,
    client: reqwest::Client,
) -> Result<Arc<dyn CredentialResolver>, CredentialError> {
    if settings.licence_minter.enabled {
        Ok(Arc::new(Minter::from_settings(
            settings,
            gateway_app_key,
            licences,
            client,
        )?))
    } else {
        Ok(Arc::new(FileResolver::from_settings(settings)?))
    }
}

/// The configured licences authority, or the fail-closed placeholder when authentication is
/// not configured (`AuthConfig` requires the URL and the application key together).
fn licence_authority(config: &AuthConfig) -> Result<Arc<dyn LicenceAuthority>, ConfigError> {
    match (&config.license_introspect_url, &config.license_app_key) {
        (Some(url), Some(app_key)) => Ok(Arc::new(HttpLicenceAuthority::new(
            url.clone(),
            app_key.clone(),
            config.license_timeout,
            config.license_max_response_bytes,
            config.license_expiry_skew,
        )?)),
        _ => Ok(Arc::new(UnconfiguredLicenceAuthority)),
    }
}

/// The reserved platform tenant the toolkit service resolves platform toolkits under.
fn platform_tenant_id() -> Result<AuthorityId, ConfigError> {
    let configured = std::env::var("PLATFORM_TENANT_ID")
        .ok()
        .filter(|value| !value.trim().is_empty());
    let identity = match configured {
        Some(value) => Rfc4122Uuid::parse(value.trim()).ok_or_else(|| ConfigError::Invalid {
            name: "PLATFORM_TENANT_ID",
            reason: format!("{value:?} is not an RFC 4122 UUID"),
        })?,
        None => default_platform_tenant_id(),
    };
    AuthorityId::new(identity.to_string()).map_err(|error| ConfigError::Invalid {
        name: "PLATFORM_TENANT_ID",
        reason: error.to_string(),
    })
}

/// The worker-start switch. `EXECUTION_ENABLED` is this service's name; the reference's
/// prefixed `MCP_EXECUTION_ENABLED` is accepted as an alias, and the unprefixed name wins.
///
/// This mirrors the resolution in `crate::config` (whose helper is private to that module).
fn execution_enabled() -> Result<bool, ConfigError> {
    let read = |key: &str| {
        std::env::var(key)
            .ok()
            .filter(|value| !value.trim().is_empty())
    };
    match (read("EXECUTION_ENABLED"), read("MCP_EXECUTION_ENABLED")) {
        (Some(value), _) => parse_switch("EXECUTION_ENABLED", &value),
        (None, Some(value)) => parse_switch("MCP_EXECUTION_ENABLED", &value),
        (None, None) => Ok(false),
    }
}

fn parse_switch(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    if value.eq_ignore_ascii_case("true") || value == "1" {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" {
        Ok(false)
    } else {
        Err(ConfigError::Invalid {
            name,
            reason: format!("{value:?} is not one of true/false/1/0"),
        })
    }
}

/// SIGTERM (Kubernetes) or Ctrl-C, whichever arrives first.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {}
        () = term => {}
    }
    tracing::info!("shutdown signal received");
}
