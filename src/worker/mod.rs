//! The executor: the process that claims queued `kata_python` runs, drives one sandboxed
//! runner pod per run over the runner protocol, brokers every upstream call, and records the
//! outcome. It is a separate binary (`mcp-worker`) over the same library, exactly as the
//! reference service runs `python -m src.execution.worker` as its own deployment.
//!
//! Nothing here is reachable from the public API surface: the worker's only listeners are the
//! internal probe/metrics port, and its only inputs are the `mcp_*` tables and the cluster.

pub mod authority;
pub mod backend;
pub mod broker;
pub mod controller;
pub mod creds;
pub mod health;
pub mod kata;
pub mod protocol;
pub mod recovery;
pub mod row;
pub mod runtime;
pub mod scheduler;
pub mod sources;
pub mod store;
