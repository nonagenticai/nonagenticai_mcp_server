//! HTTP handlers. Add one module per resource and register each handler in `lib.rs`
//! `api_router()` with `routes!(...)`.

pub mod health;
pub mod toolkits;
pub mod tools;
