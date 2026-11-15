//! Platform publication: the repository's `toolkits/` tree and the generic toolkit import.
//!
//! Ported from the reference `src/platform/`: [`toolkit_source`] is the pure filesystem loader
//! and packager, [`seed`] the content-addressed, advisory-locked publisher the binary's
//! `--seed-platform` mode and `POST /mcp/toolkits/import` share.

pub mod seed;
pub mod toolkit_source;
