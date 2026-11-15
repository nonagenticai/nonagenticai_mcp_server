//! The builder tool tools: create, update, read, list, test, inspect the run, publish.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::auth::AuthorPrincipal;
use crate::builder::models::{ToolCreate, ToolPublishRequest, ToolTestRequest, ToolUpdate};
use crate::builder::service::BuilderService;
use crate::builtin::provider::{HandlerFuture, boxed};

use super::{answer, given, optional_version, page, parse, text, uuid_arg, version};

/// `builder_tool_create`: a draft tool (a script over the tenant's operations).
pub(crate) fn tool_create(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let body: ToolCreate = parse(given(
            &arguments,
            &[
                "public_name",
                "operation",
                "description",
                "files",
                "input_schema",
                "effect",
                "ops",
                "result_schema",
                "limits",
            ],
        ))?;
        answer(service.tool_create(&author, &body).await)
    })
}

/// `builder_tool_update`: the next draft version of an owned tool.
pub(crate) fn tool_update(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let tool_id = uuid_arg(&text(&arguments, "tool_id")?, "tool_id")?;
        let body: ToolUpdate = parse(given(
            &arguments,
            &[
                "expected_revision",
                "description",
                "files",
                "input_schema",
                "result_schema",
                "effect",
                "ops",
                "limits",
            ],
        ))?;
        answer(service.tool_update(&author, &tool_id, &body).await)
    })
}

/// `builder_tool_get`: one tool version (default: the newest) with its files and ops.
pub(crate) fn tool_get(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let tool_id = uuid_arg(&text(&arguments, "tool_id")?, "tool_id")?;
        let version = optional_version(&arguments, "version")?;
        answer(service.tool_get(&author, &tool_id, version).await)
    })
}

/// `builder_tool_list`: the tenant's tool versions with status and revision.
pub(crate) fn tool_list(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let (limit, offset) = page(&arguments);
        answer(service.tool_list(&author, limit, offset).await)
    })
}

/// `builder_tool_test`: one draft or published tool version, no binding needed.
pub(crate) fn tool_test(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let tool_id = uuid_arg(&text(&arguments, "tool_id")?, "tool_id")?;
        let version = version(&arguments, "version")?;
        let body: ToolTestRequest = parse(given(&arguments, &["inputs", "confirm_writes"]))?;
        answer(service.tool_test(&author, &tool_id, version, &body).await)
    })
}

/// `builder_run_get`: the run envelope plus the trace of upstream calls.
pub(crate) fn run_get(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let run_id = uuid_arg(&text(&arguments, "run_id")?, "run_id")?;
        answer(service.run_get(&author, &run_id).await)
    })
}

/// `builder_tool_publish`: publish a version with the draft dependencies it pins.
pub(crate) fn tool_publish(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let tool_id = uuid_arg(&text(&arguments, "tool_id")?, "tool_id")?;
        let version = version(&arguments, "version")?;
        let body: ToolPublishRequest = parse(given(&arguments, &["expected_revision"]))?;
        answer(
            service
                .tool_publish(&author, &tool_id, version, &body)
                .await,
        )
    })
}
