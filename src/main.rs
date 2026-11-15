#![forbid(unsafe_code)]
//! Binary entry point. `--print-openapi` writes the OpenAPI JSON to stdout and exits without
//! reading any env or touching a database (the parity tooling runs it in a bare workspace).
//! `--seed-platform <dir>` publishes the repository's platform toolkits and exits, the
//! reference's `python -m src.platform.seed`.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use clap::Parser;
use tokio::net::TcpListener;

// The crate's own imports stay in their own group so a rename never reorders them.
use mcp_server_rs::config::{AuthConfig, Config};
use mcp_server_rs::error::StartupError;
use mcp_server_rs::platform::seed::{self as platform_seed, SeedOptions, SeedReport, SeedSettings};
use mcp_server_rs::platform::toolkit_source::load_all;
use mcp_server_rs::{AppState, app, db, openapi, telemetry};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Print the OpenAPI document as JSON to stdout and exit.
    #[arg(long)]
    print_openapi: bool,
    /// Publish the platform toolkits under DIR and exit (content-addressed, idempotent).
    #[arg(long, value_name = "DIR")]
    seed_platform: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> ExitCode {
    // Two rustls providers are linked into this binary; pick one before any TLS client exists.
    mcp_server_rs::install_crypto_provider();
    let cli = Cli::parse();
    if cli.print_openapi {
        return match openapi().to_pretty_json() {
            Ok(json) => {
                println!("{json}");
                ExitCode::SUCCESS
            }
            Err(e) => {
                eprintln!("error: cannot serialise OpenAPI: {e}");
                ExitCode::FAILURE
            }
        };
    }
    if let Some(directory) = cli.seed_platform.as_deref() {
        return seed_platform(directory).await;
    }
    telemetry::init_tracing();
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            ExitCode::FAILURE
        }
    }
}

/// The reference's `python -m src.platform.seed`: migrate, then publish `directory`'s toolkits.
///
/// Its only configuration is `DATABASE_URL` (and `DATABASE_MIGRATE_URL` when set); everything
/// else has the reference's default (`PLATFORM_TENANT_ID`) or an unset-means-skip meaning
/// (`MCP_RUNNER_IMAGE_DIGEST`). The report is printed to stdout, one line per artifact.
async fn seed_platform(directory: &Path) -> ExitCode {
    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => {
            eprintln!("error: DATABASE_URL is not set");
            return ExitCode::FAILURE;
        }
    };
    let settings = match SeedSettings::from_env() {
        Ok(settings) => settings,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let sources = match load_all(directory) {
        Ok(sources) => sources,
        Err(error) => {
            eprintln!("error: {error}");
            return ExitCode::FAILURE;
        }
    };
    let pool = match db::connect(&database_url).await {
        Ok(pool) => pool,
        Err(error) => {
            eprintln!("platform seed failed: {error}");
            return ExitCode::FAILURE;
        }
    };
    // The serving mode migrates before the listener exists; the seed mode is the deployment's
    // bootstrap, so it applies the same migrations through the same direct URL when given.
    let migrated = match std::env::var("DATABASE_MIGRATE_URL") {
        Ok(url) if !url.trim().is_empty() => match db::connect(&url).await {
            Ok(direct) => {
                let result = db::migrate(&direct).await;
                direct.close().await;
                result
            }
            Err(error) => {
                eprintln!("platform seed failed: {error}");
                return ExitCode::FAILURE;
            }
        },
        _ => db::migrate(&pool).await,
    };
    if let Err(error) = migrated {
        eprintln!("platform seed failed: {error}");
        return ExitCode::FAILURE;
    }
    match platform_seed::seed(&pool, &settings, &sources, None, SeedOptions::default()).await {
        Ok(report) => {
            print_seed_report(&report);
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("platform seed failed: {error}");
            ExitCode::FAILURE
        }
    }
}

/// The reference's per-artifact log lines, the skipped-source warnings and its summary.
fn print_seed_report(report: &SeedReport) {
    for (key, action) in &report.actions {
        if let Some((kind, name)) = key.split_once(':') {
            println!("{kind} {name}: {}", action.as_str().unwrap_or_default());
        }
    }
    for (name, alias) in &report.sources_missing {
        println!(
            "toolkit {name} skipped: source {} is not registered and active (POST /mcp/sources)",
            alias.as_str().unwrap_or_default()
        );
    }
    println!("{}", report.summary());
}

async fn serve() -> Result<(), StartupError> {
    let cfg = Config::from_env()?;
    // Authentication settings are parsed and validated exactly once: the same configuration
    // builds the `/mcp` middleware and supplies the binding service's gateway application key.
    let auth_config = AuthConfig::from_env()?;
    let pool = db::connect(&cfg.database_url).await?;
    match &cfg.database_migrate_url {
        Some(url) => {
            let direct = db::connect(url).await?;
            db::migrate(&direct).await?;
            direct.close().await;
        }
        None => db::migrate(&pool).await?,
    }
    tracing::info!("migrations applied");

    // `MCP_BUILDER_ENABLED=true` is refused rather than half-served: the builder's routes and
    // service are complete, but this binary's composition root still mounts the reference's
    // disabled runtime — the service needs the broker's pinned-egress fetcher, adapter set and
    // credential resolver, which live in the worker's settings, not the API's. A deployment
    // that sets the flag must not silently get a 404 for every builder path. The live
    // deployment leaves it unset (the reference's default), so this refuses nothing today.
    if cfg.builder.enabled {
        return Err(mcp_server_rs::error::StartupError::Config(
            mcp_server_rs::config::ConfigError::Invalid {
                name: "MCP_BUILDER_ENABLED",
                reason: "the builder composition is not wired into the API binary yet".into(),
            },
        ));
    }

    // The reference refuses startup when a platform pool is configured without platform
    // authorization (`src/config.py:314`); a pool nobody may use is a misconfiguration, not a
    // feature. The same rule holds here, before the listener exists.
    if cfg.platform_database_url.is_some() && auth_config.platform_admin_key_file.is_none() {
        return Err(mcp_server_rs::error::StartupError::Config(
            mcp_server_rs::config::ConfigError::Invalid {
                name: "MCP_PLATFORM_DATABASE_URL",
                reason: "platform authorization requires MCP_PLATFORM_ADMIN_KEY_FILE".into(),
            },
        ));
    }
    // Same database, elevated role: opened before the listener so a bad URL refuses startup
    // instead of 503-ing its routes later. No second migration target — the schema applied
    // above is the schema it reads.
    let platform = match &cfg.platform_database_url {
        Some(url) => Some(db::connect(url).await?),
        None => None,
    };

    let listener = TcpListener::bind(cfg.bind_addr).await?;
    tracing::info!(addr = %listener.local_addr()?, "listening");
    axum::serve(
        listener,
        app(
            AppState {
                pool,
                execution_enabled: cfg.execution_enabled,
                license_app_key: auth_config.license_app_key.clone(),
                approved_runner_images: cfg.approved_runner_images.clone(),
                platform_tenant_id: cfg.platform_tenant_id,
                catalog_page_size: cfg.catalog_page_size,
                platform,
                sources: cfg.sources.clone(),
                execution: cfg.execution.clone(),
            },
            &auth_config,
        )?,
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;
    Ok(())
}

/// SIGTERM (Kubernetes) or Ctrl-C.
async fn shutdown_signal() {
    let ctrl_c = async {
        let _ = tokio::signal::ctrl_c().await;
    };
    #[cfg(unix)]
    let term = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut s) => {
                s.recv().await;
            }
            Err(_) => std::future::pending::<()>().await,
        }
    };
    #[cfg(not(unix))]
    let term = std::future::pending::<()>();
    tokio::select! {
        () = ctrl_c => {},
        () = term => {},
    }
    tracing::info!("shutdown signal received");
}
