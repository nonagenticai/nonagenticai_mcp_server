//! The builder spec and operation tools: fetch a spec, list its operations, import and patch
//! operations.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::auth::AuthorPrincipal;
use crate::builder::models::{ImportRequest, OperationPatch, SpecFetchRequest};
use crate::builder::service::BuilderService;
use crate::builtin::provider::{HandlerFuture, boxed};

use super::{answer, given, parse, text};

/// `builder_spec_fetch`: fetch the source's OpenAPI document through its credential.
pub(crate) fn spec_fetch(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = text(&arguments, "source_key")?;
        let body: SpecFetchRequest = parse(given(&arguments, &["path"]))?;
        answer(service.spec_fetch(&author, &key, &body).await)
    })
}

/// `builder_spec_operations`: the operations of a previously fetched spec, by sha256.
pub(crate) fn spec_operations(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = text(&arguments, "source_key")?;
        let sha256 = text(&arguments, "spec_sha256")?;
        answer(service.spec_operations(&author, &key, &sha256).await)
    })
}

/// `builder_operations_import`: create draft operations from the cached spec.
pub(crate) fn operations_import(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = text(&arguments, "source_key")?;
        let body: ImportRequest =
            parse(given(&arguments, &["spec_sha256", "select", "overrides"]))?;
        answer(service.operations_import(&author, &key, &body).await)
    })
}

/// `builder_operation_list`: every keyed operation of the source's service.
pub(crate) fn operation_list(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = text(&arguments, "source_key")?;
        answer(service.operation_list(&author, &key).await)
    })
}

/// `builder_operation_update`: a new draft version of an imported operation.
pub(crate) fn operation_update(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let key = text(&arguments, "source_key")?;
        let op_key = text(&arguments, "op_key")?;
        let body: OperationPatch = parse(given(
            &arguments,
            &[
                "expected_version",
                "effect",
                "expected_error_statuses",
                "response_projection",
                "redact_fields",
                "timeout_seconds",
                "max_retries",
                "idempotency",
                "empty_response",
            ],
        ))?;
        answer(
            service
                .operation_update(&author, &key, &op_key, &body)
                .await,
        )
    })
}
