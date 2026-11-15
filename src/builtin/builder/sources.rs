//! The builder source tools: create, update, rotate the secret, list and disable.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::auth::AuthorPrincipal;
use crate::builder::service::BuilderService;
use crate::builtin::provider::{HandlerFuture, boxed};
use crate::sources::models::{
    RevisionOnly, SourceStatus, TenantSourceCreate, TenantSourceUpdate, TokenUpdate,
};

use super::{answer, given, page, parse};

/// `builder_source_create`: register an HTTPS API as one of the tenant's sources.
pub(crate) fn source_create(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let body: TenantSourceCreate = parse(given(
            &arguments,
            &[
                "source_key",
                "base_url",
                "auth",
                "token",
                "spec_path",
                "idempotency_header",
                "max_request_bytes",
                "max_response_bytes",
            ],
        ))?;
        answer(service.source_create(&author, &body).await)
    })
}

/// `builder_source_update`: replace a source's configuration; an omitted token keeps the secret.
pub(crate) fn source_update(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = super::text(&arguments, "source_key")?;
        let body: TenantSourceUpdate = parse(given(
            &arguments,
            &[
                "base_url",
                "auth",
                "token",
                "spec_path",
                "idempotency_header",
                "max_request_bytes",
                "max_response_bytes",
                "expected_revision",
            ],
        ))?;
        answer(service.source_update(&author, &key, &body).await)
    })
}

/// `builder_source_set_secret`: set or rotate a source's write-only secret.
pub(crate) fn source_set_secret(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = super::text(&arguments, "source_key")?;
        let body: TokenUpdate = parse(given(&arguments, &["token", "expected_revision"]))?;
        answer(service.source_set_secret(&author, &key, &body).await)
    })
}

/// `builder_source_list`: the tenant's sources, never their secrets.
pub(crate) fn source_list(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let (limit, offset) = page(&arguments);
        answer(service.source_list(&author, limit, offset).await)
    })
}

/// `builder_source_disable`: one revision-guarded state change; the key stays reserved.
pub(crate) fn source_disable(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = super::text(&arguments, "source_key")?;
        let body: RevisionOnly = parse(given(&arguments, &["expected_revision"]))?;
        answer(
            service
                .source_set_status(&author, &key, &body, SourceStatus::Disabled)
                .await,
        )
    })
}
