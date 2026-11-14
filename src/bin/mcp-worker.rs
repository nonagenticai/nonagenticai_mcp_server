#![forbid(unsafe_code)]
//! The executor binary: claim queued `kata_python` runs, drive one sandboxed runner pod per
//! run, broker every upstream call and record the outcome.
//!
//! It is a separate binary over the same library, exactly as the reference service runs
//! `python -m src.execution.worker` as its own deployment. Nothing here is reachable from the
//! public API surface: the worker's only listener is the internal probe/metrics port, and its
//! only inputs are the `mcp_*` tables and the cluster.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // Two rustls providers are linked into this binary; pick one before any TLS client exists.
    mcp_server_rs::install_crypto_provider();
    mcp_server_rs::telemetry::init_tracing();
    match mcp_server_rs::worker::runtime::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "worker failed");
            ExitCode::FAILURE
        }
    }
}
