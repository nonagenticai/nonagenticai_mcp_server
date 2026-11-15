#![forbid(unsafe_code)]
//! Binary entry point. `--print-openapi` writes the OpenAPI JSON to stdout and exits without
//! reading any env or touching a database (the parity tooling runs it in a bare workspace).

use std::process::ExitCode;

use clap::Parser;
use tokio::net::TcpListener;

// The crate's own imports stay in their own group so a rename never reorders them.
use mcp_server_rs::config::{AuthConfig, Config};
use mcp_server_rs::error::StartupError;
use mcp_server_rs::{AppState, app, db, openapi, telemetry};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Print the OpenAPI document as JSON to stdout and exit.
    #[arg(long)]
    print_openapi: bool,
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
    telemetry::init_tracing();
    match serve().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "startup failed");
            ExitCode::FAILURE
        }
    }
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
