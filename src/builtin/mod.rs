//! First-party in-process builtin tools and the provider that serves them.
//!
//! Ported from the reference `src/builtin/`. The 34 care-bus, legal, web and research tools keep
//! their public wire names (`{namespace}_{function}`), are offered only to non-binding
//! principals whose scope lists them ([`scope`]), and every call is audited ([`audit`]).
//!
//! This card installs the provider core, the care-bus, legal, web and research families, and
//! the 20-tool builder family when the tenant builder's service is installed. A caller with no
//! catalog binding lists exactly its scope's tools and every other builtin call is denied — the
//! same answer a scope grants nothing.
//!
//! See `docs/AUTHENTICATION_BINDINGS.md` in the reference for the caller model.

pub mod audit;
pub mod builder;
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

use crate::builder::service::BuilderService;

/// The service's builtin provider: the database audit sink and the registered families.
///
/// The care-bus, legal, web and research families are registered here; [`register`] is the one
/// place a family adds tools. The builder family needs the installed [`BuilderService`] — the
/// reference's `app.state.builder` — so it registers only when the composition root passes one,
/// exactly as the reference's builtin server mounts it only while the builder is enabled.
pub fn create(pool: PgPool, service: Option<Arc<BuilderService>>) -> BuiltinProvider {
    let mut provider =
        BuiltinProvider::new().with_sink(Arc::new(DatabaseAuditSink::new(pool.clone())));
    register(&mut provider);
    if let Some(service) = service {
        builder::register(&mut provider, service);
    }
    provider
}

/// The family registration point. Each family registers every tool under its namespace with
/// its declared input schema and its `{namespace}_{function}` wire name; the reference mounts
/// the same groups (`create_builtin_server`).
///
/// The builder family is the one family that needs a runtime service, so [`create`] registers
/// it directly instead of through this function.
pub fn register(provider: &mut BuiltinProvider) {
    carebus::register(provider); // crm, order, delivery, rules, procedures, faq
    legal::register(provider); // eli, eurlex, duw, kio, krs, vat, saos, uokik (gated)
    web::register(provider); // scrape
    research::register(provider); // literature, stats
}
