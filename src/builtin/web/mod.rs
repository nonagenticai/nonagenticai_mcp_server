//! The web builtin tools: the single `web_scrape` tool.
//!
//! Ported from the reference `src/builtin/web/`. The family keeps the reference namespace
//! `web`, so its wire name is `web_scrape` and the scope tables in [`crate::builtin::scope`]
//! grant it to `carebus-researcher` and a `care-bus` licence, exactly as before.
//!
//! The URL comes from an LLM, so it is checked before any request leaves this process (the
//! webscraper has its own guard as well): http/https only, no credentials in the URL, and the
//! host — literal or every address it resolves to — must be a public address. The check and the
//! `/api/scrape/url` mapping live in [`scrape`].

pub mod scrape;

use crate::builtin::provider::BuiltinProvider;

/// Register the web family — the reference's `mount_web`.
pub fn register(provider: &mut BuiltinProvider) {
    scrape::register(provider);
}
