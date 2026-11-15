//! The builder toolkit tools: create, publish and re-bind the tenant's product bindings.

use std::sync::Arc;

use serde_json::{Map, Value};

use crate::auth::AuthorPrincipal;
use crate::builder::models::{BindRequest, ToolkitPublishRequest, ToolkitRequest};
use crate::builder::service::BuilderService;
use crate::builtin::provider::{HandlerFuture, boxed};

use super::{answer, given, parse, text, uuid_arg, version};

/// `builder_toolkit_create`: a draft toolkit (or the next version of one).
pub(crate) fn toolkit_create(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let body: ToolkitRequest = parse(given(
            &arguments,
            &[
                "name",
                "description",
                "tools",
                "toolkit_id",
                "expected_revision",
            ],
        ))?;
        answer(service.toolkit_create(&author, &body).await)
    })
}

/// `builder_toolkit_publish`: publish a toolkit version and re-bind the product bindings.
pub(crate) fn toolkit_publish(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let toolkit_id = uuid_arg(&text(&arguments, "toolkit_id")?, "toolkit_id")?;
        let version = version(&arguments, "version")?;
        let body: ToolkitPublishRequest = parse(given(&arguments, &["expected_revision"]))?;
        answer(
            service
                .toolkit_publish(&author, &toolkit_id, version, &body)
                .await,
        )
    })
}

/// `builder_toolkit_bind`: re-provision the tenant's existing product bindings.
pub(crate) fn toolkit_bind(
    service: Arc<BuilderService>,
    author: AuthorPrincipal,
    arguments: Map<String, Value>,
) -> HandlerFuture {
    boxed(async move {
        let body: BindRequest = parse(given(&arguments, &["product"]))?;
        answer(service.rebind(&author, &body).await)
    })
}
