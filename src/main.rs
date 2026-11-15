#![forbid(unsafe_code)]
//! Binary entry point. `--print-openapi` writes the OpenAPI JSON to stdout and exits without
//! reading any env or touching a database (the parity tooling runs it in a bare workspace); the
//! operator actions `--adopt-schema` and `--grant-runtime-role` connect to exactly one database,
//! print what they did and exit, so the image is self-sufficient for the API cutover without
//! either Python script.
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
use mcp_server_rs::{AppState, app, db, grant, openapi, telemetry};

#[derive(Debug, Parser)]
#[command(version, about)]
struct Cli {
    /// Print the OpenAPI document as JSON to stdout and exit.
    #[arg(long, group = "action")]
    print_openapi: bool,

    /// Stamp the embedded migrations as applied WITHOUT running their SQL, for a database whose
    /// schema already exists (the live one was created by alembic and has no `_sqlx_migrations`).
    ///
    /// Prints every migration it stamped. A version already stamped with a different checksum, a
    /// failed row, or a stamped version this binary does not embed is refused and nothing is
    /// written. Run it before a Rust instance of this service starts, with the old one stopped: a
    /// concurrent migrator would race the history it writes. Reads DATABASE_MIGRATE_URL when
    /// --url is absent; prefer it or --url over a pgbouncer address, because sqlx's migrator
    /// holds a session-level advisory lock.
    #[arg(long, group = "action")]
    adopt_schema: bool,

    /// Grant the catalog privileges the runtime role needs, idempotently, in one transaction.
    ///
    /// This is the archived service's grant_runtime_role.py: schema usage, catalog DML and
    /// EXECUTE on the SECURITY DEFINER functions. The role must already exist. Reads
    /// DATABASE_URL when --url is absent.
    #[arg(long, group = "action", requires = "role")]
    grant_runtime_role: bool,

    /// The role to grant, as created: ASCII letters, digits and underscores, at most 63 bytes.
    /// Only with --grant-runtime-role.
    #[arg(long, value_name = "NAME", requires = "grant_runtime_role")]
    role: Option<String>,

    /// Grant the worker's execution privileges instead of the API's. Only with
    /// --grant-runtime-role.
    #[arg(long, requires = "grant_runtime_role")]
    worker: bool,

    /// A direct Postgres URL for the action, overriding the environment variable named above.
    #[arg(long, value_name = "URL")]
    url: Option<String>,
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
    // Operator actions print their own report and never start a listener or read the service's
    // configuration: they need one URL and nothing else.
    if cli.adopt_schema {
        return report(adopt(&cli).await);
    }
    if cli.grant_runtime_role {
        return report(grant_role(&cli).await);
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

fn report(outcome: Result<(), String>) -> ExitCode {
    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("error: {message}");
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

/// `--adopt-schema`: one direct connection, `DATABASE_MIGRATE_URL` unless `--url` names one.
async fn adopt(cli: &Cli) -> Result<(), String> {
    let url = action_url("--adopt-schema", cli.url.as_deref(), grant::ADOPT_URL_ENV)?;
    let report = grant::adopt_schema(&url)
        .await
        .map_err(|e| grant::redact(&e.to_string(), &url))?;
    print!("{report}");
    Ok(())
}

/// `--grant-runtime-role`: one connection and one transaction, `DATABASE_URL` unless `--url`.
async fn grant_role(cli: &Cli) -> Result<(), String> {
    let role = cli
        .role
        .as_deref()
        .ok_or_else(|| "--grant-runtime-role needs --role <name>".to_owned())?;
    let url = action_url(
        "--grant-runtime-role",
        cli.url.as_deref(),
        grant::GRANT_URL_ENV,
    )?;
    let report = grant::grant_runtime_role(&url, role, cli.worker)
        .await
        .map_err(|e| grant::redact(&e.to_string(), &url))?;
    print!("{report}");
    Ok(())
}

/// The URL for one operator action: `--url`, else the action's environment variable. An empty
/// value counts as unset, as it does everywhere else in this crate's configuration.
fn action_url(
    action: &'static str,
    explicit: Option<&str>,
    env_name: &'static str,
) -> Result<String, String> {
    if let Some(url) = explicit.map(str::trim).filter(|url| !url.is_empty()) {
        return Ok(url.to_owned());
    }
    match std::env::var(env_name) {
        Ok(url) if !url.trim().is_empty() => Ok(url.trim().to_owned()),
        _ => Err(format!("{action} needs --url or {env_name}")),
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
