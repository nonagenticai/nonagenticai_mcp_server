#![forbid(unsafe_code)]
//! The external-driver binary: drive `n8n_workflow`, `fr_project` and `fr_command` runs through
//! their external systems.
//!
//! It is a separate binary over the same library, exactly as the reference service runs
//! `python -m src.external.driver` as its own deployment. Nothing here is reachable from the
//! public API surface: the driver's only listener is the internal probe port, and its only
//! inputs are the `mcp_*` tables and the two upstream systems.

use std::process::ExitCode;

#[tokio::main]
async fn main() -> ExitCode {
    // Two rustls providers are linked into this binary; pick one before any TLS client exists.
    mcp_server_rs::install_crypto_provider();
    mcp_server_rs::telemetry::init_tracing();
    match mcp_server_rs::external::driver::run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            tracing::error!(error = %error, "external driver failed");
            ExitCode::FAILURE
        }
    }
}
