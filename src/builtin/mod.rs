//! First-party in-process builtin tools and the provider that serves them.
//!
//! Ported from the reference `src/builtin/`. The 34 care-bus, legal, web and research tools keep
//! their public wire names (`{namespace}_{function}`), are offered only to non-binding
//! principals whose scope lists them ([`scope`]), and every call is audited ([`audit`]).
//!
//! This card installs the provider core, the care-bus family, the legal family, the web family
//! and the research family; the builder family is a later card and registers through
//! [`register`]. A caller with no catalog binding lists exactly its scope's tools and every
//! other builtin call is denied — the same answer a scope grants nothing.
//!
//! See `docs/AUTHENTICATION_BINDINGS.md` in the reference for the caller model.

pub mod audit;
pub mod carebus;
pub mod legal;
pub mod provider;
pub mod research;
pub mod scope;
pub mod web;

pub use audit::{AuditSink, DatabaseAuditSink};
pub use provider::{BuiltinProvider, BuiltinTool, Handler, HandlerFuture, HandlerResult, boxed};
pub use scope::{BuiltinCaller, CallerKind, DENIED_MESSAGE};

use std::sync::Arc;

use sqlx::PgPool;

/// The service's builtin provider: the database audit sink and the registered families.
///
/// The care-bus, legal, web and research families are registered here; [`register`] is the one
/// place a family adds tools.
pub fn create(pool: PgPool) -> BuiltinProvider {
    let mut provider =
        BuiltinProvider::new().with_sink(Arc::new(DatabaseAuditSink::new(pool.clone())));
    register(&mut provider);
    provider
}

/// The family registration point. Each family registers every tool under its namespace with
/// its declared input schema and its `{namespace}_{function}` wire name; the reference mounts
/// the same groups (`create_builtin_server`).
///
/// The care-bus, legal, web and research families register here; the builder family is a later
/// card.
pub fn register(provider: &mut BuiltinProvider) {
    carebus::register(provider); // crm, order, delivery, rules, procedures, faq
    legal::register(provider); // eli, eurlex, duw, kio, krs, vat, saos, uokik (gated)
    web::register(provider); // scrape
    research::register(provider); // literature, stats
    // builder::register(provider);
}
