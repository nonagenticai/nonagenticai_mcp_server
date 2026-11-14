//! Catalog domain refusals.
//!
//! Every message is the constant string the reference raises, and none of them echoes the
//! offending value (a refused manifest may carry a secret), matching the reference's
//! `hide_input_in_errors` model configuration.

use thiserror::Error;

/// A refused catalog value. The message is exactly the one the reference raises.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct CatalogError(pub &'static str);

impl CatalogError {
    /// Construct from the reference's message.
    pub const fn new(message: &'static str) -> Self {
        Self(message)
    }
}
