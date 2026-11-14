//! Tool catalog domain (phase 2): the strict models, the closed JSON-Schema subset, named
//! formats, public schema policy and the lifecycle state machines.

pub mod error;
pub mod formats;
pub mod ids;
pub mod lifecycle;
pub mod models;
pub mod package;
pub mod public;
pub mod toolkit_models;
pub mod validation;

pub use error::CatalogError;
