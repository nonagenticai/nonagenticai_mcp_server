//! Postgres access.
//!
//! The reference keeps its repositories in `src/storage/`; this module is the phase-2 home for
//! the tenant catalog repository. Every statement is tenant-explicit (`WHERE tenant_id = $1`):
//! there is no row-level security and no session variable, exactly as the reference.

pub mod bindings;
pub mod catalog;
pub mod toolkits;

pub use catalog::{AppendRequest, CatalogRepository, CatalogStoreError, ToolDefinition};
