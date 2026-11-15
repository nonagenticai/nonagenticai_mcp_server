//! First-party in-process builtin tools and the provider that serves them.
//!
//! Ported from the reference `src/builtin/`. The 34 care-bus and researcher tools keep their
//! public wire names (`{namespace}_{function}`), are offered only to non-binding principals
//! whose scope lists them ([`scope`]), and every call is audited ([`audit`]).
//!
//! This card installs the provider core with an EMPTY registry; the care-bus, legal, web,
//! research and builder families are later cards and register through [`register`]. Until
//! then a caller with no catalog binding lists no tools and every builtin call is denied —
//! the same answer a scope grants nothing.
//!
//! See `docs/AUTHENTICATION_BINDINGS.md` in the reference for the caller model.

pub mod audit;
pub mod provider;
pub mod scope;

pub use audit::{AuditSink, DatabaseAuditSink};
pub use provider::{BuiltinProvider, BuiltinTool, Handler, HandlerFuture, HandlerResult, boxed};
pub use scope::{BuiltinCaller, CallerKind, DENIED_MESSAGE};

use std::sync::Arc;

use sqlx::PgPool;

/// The service's builtin provider: the database audit sink and the registered families.
///
/// The registry starts EMPTY in this card; [`register`] is the one place a family adds tools.
pub fn create(pool: PgPool) -> BuiltinProvider {
    let mut provider =
        BuiltinProvider::new().with_sink(Arc::new(DatabaseAuditSink::new(pool.clone())));
    register(&mut provider);
    provider
}

/// The family registration point. Each family registers every tool under its namespace with
/// its declared input schema and its `{namespace}_{function}` wire name; the reference mounts
/// the same five groups (`create_builtin_server`).
///
/// The registry is deliberately empty here: no family is ported in this card.
pub fn register(_provider: &mut BuiltinProvider) {
    // carebus::register(provider);   // crm, order, delivery, rules, procedures, faq
    // legal::register(provider);
    // web::register(provider);
    // research::register(provider);
    // builder::register(provider);
}
