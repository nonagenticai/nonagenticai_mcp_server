//! The tool-source domain: how one registered upstream's destination is approved and how its
//! one stored credential is sealed at rest.
//!
//! Ported from the reference `src/sources/crypto.py` and `src/sources/guard.py`:
//!
//! - [`crypto`] seals and opens the stored secret with AES-256-GCM, using the source id's 16
//!   bytes as associated data, so a ciphertext copied onto another source row fails
//!   authentication instead of silently sending one upstream's credential to another. It also
//!   holds the charset checks credential material passes before it is sealed.
//! - [`guard`] is the destination policy shared by registration and call time (the SSRF guard):
//!   an operator-approved HTTPS origin, never an address literal or userinfo, whose host must
//!   also be named by the operator allow-list (`MCP_SOURCE_ALLOWED_HOSTS`).
//! - [`models`] is the contract every writer shares: the source bodies, the closed auth union,
//!   the tenant-URL rule and the one read-back view (`SourceView`, which never carries a token).
//! - [`repository`] is the platform-role persistence behind `/mcp/sources`: the platform-tenant
//!   scoped statements, the source views and events, and the broker's ciphertext-bearing
//!   `resolve_row`. Ciphertext never leaves it except to the worker that decrypts it.
//!
//! No secret leaves this module except as the plain `String` [`crypto::decrypt_token`] returns;
//! nothing here logs or `Debug`-formats credential material.

pub mod crypto;
pub mod guard;
pub mod models;
pub mod repository;
