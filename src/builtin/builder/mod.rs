//! The builder builtin tools: the 20 `builder_*` tools a tenant author drives the tool builder
//! with.
//!
//! Ported from the reference `src/builder/tools.py`. The family keeps the reference namespace
//! `builder`, so each wire name is `builder_{function}` and the scope tables in
//! [`crate::builtin::scope`] grant the family to a tenant-level `mcp` licence alone
//! (`licence:mcp`). Each tool calls the same [`BuilderService`] method its REST route calls, so
//! the MCP surface and `/mcp/builder` can never disagree, and every answer is the service's
//! JSON view as MCP structured content.
//!
//! The tenant always comes from the authenticated caller, never from an argument ([`author`]);
//! a caller that is not a tenant-level mcp licence author is refused
//! `[permanent] not permitted` before any tool body runs. Secrets are write-only: no tool
//! result, error text or log line carries one.
//!
//! The declared descriptions and input schemas are the pinned reference's own FastMCP
//! inventory, generated into [`inventory`] byte for byte, because the builtin tools have no
//! OpenAPI document; `tests/builtin_builder.rs` holds the registry to that fixture.
//!
//! Failures are the reference's `guard` mapping ([`refusal`]): a quota is
//! `quota exceeded: <resource> quota exceeded`, a missing row `not found: …`, a lifecycle
//! conflict `conflict: …`, a `ValueError` `invalid: <≤500 characters>`, a permission refusal
//! `[permanent] not permitted`, and a uuid argument that does not parse `<what> must be a
//! uuid`. A tool's success text is its JSON view, never rewritten here.

pub mod inventory;
mod sources;
mod specs;
mod toolkits;
mod tools;

use std::sync::Arc;

use rmcp::model::CallToolResult;
use serde::de::DeserializeOwned;
use serde_json::{Map, Value};

use crate::auth::{AuthorPrincipal, Rfc4122Uuid};
use crate::builder::service::{BuilderError, BuilderService};
use crate::catalog::ids::{PositiveVersion, Uuid7};

use super::provider::{BuiltinProvider, BuiltinTool, Handler, HandlerFuture, boxed};
use super::scope::{BuiltinCaller, CallerKind};

/// The reference's one permission refusal (`[permanent] not permitted`).
pub(crate) const NOT_PERMITTED: &str = "[permanent] not permitted";

/// The builder family namespace: every tool's scope key and wire-name prefix.
const NAMESPACE: &str = "builder";

/// One tool body: the service, the authenticated author and the schema-validated arguments.
pub(crate) type Body =
    fn(Arc<BuilderService>, AuthorPrincipal, Map<String, Value>) -> HandlerFuture;

/// Register the 20 builder tools — the reference's `mount_builder`.
///
/// Each tool's description and input schema come from [`inventory`], the reference's own
/// FastMCP inventory; the handler is the shared action over the installed service.
pub fn register(provider: &mut BuiltinProvider, service: Arc<BuilderService>) {
    let bodies: [(&'static str, Body); 20] = [
        ("operation_list", specs::operation_list),
        ("operation_update", specs::operation_update),
        ("operations_import", specs::operations_import),
        ("run_get", tools::run_get),
        ("source_create", sources::source_create),
        ("source_disable", sources::source_disable),
        ("source_list", sources::source_list),
        ("source_set_secret", sources::source_set_secret),
        ("source_update", sources::source_update),
        ("spec_fetch", specs::spec_fetch),
        ("spec_operations", specs::spec_operations),
        ("tool_create", tools::tool_create),
        ("tool_get", tools::tool_get),
        ("tool_list", tools::tool_list),
        ("tool_publish", tools::tool_publish),
        ("tool_test", tools::tool_test),
        ("tool_update", tools::tool_update),
        ("toolkit_bind", toolkits::toolkit_bind),
        ("toolkit_create", toolkits::toolkit_create),
        ("toolkit_publish", toolkits::toolkit_publish),
    ];
    for (function, body) in bodies {
        let entry = inventory::entry(function);
        provider.register(BuiltinTool::new(
            NAMESPACE,
            function,
            entry.description.clone(),
            entry.input_schema.clone(),
            handler(service.clone(), body),
        ));
    }
}

/// Bind one tool body to the installed service, resolving the author first: the reference's
/// `author()` runs inside the guarded function, so a caller that is not a tenant author gets
/// the one `[permanent] not permitted` tool error, never a listing privilege.
fn handler(service: Arc<BuilderService>, body: Body) -> Handler {
    Arc::new(move |caller, arguments| match author(&caller) {
        Ok(author) => body(service.clone(), author, arguments),
        Err(text) => boxed(async move { Err(text) }),
    })
}

/// The reference's `author()`: the authenticated caller as a tenant author, or the one
/// permission refusal.
///
/// [`CallerKind::TenantAuthor`] is only ever derived from a tenant-level `mcp` licence with no
/// binding, and the scope check has already run; a missing or unparseable identity is still an
/// error, never a panic.
pub(crate) fn author(caller: &BuiltinCaller) -> Result<AuthorPrincipal, String> {
    if caller.kind != CallerKind::TenantAuthor {
        return Err(NOT_PERMITTED.to_owned());
    }
    let tenant_id = caller
        .tenant_id
        .as_deref()
        .and_then(Rfc4122Uuid::parse)
        .ok_or_else(|| NOT_PERMITTED.to_owned())?;
    let license_id = caller
        .license_id
        .as_deref()
        .and_then(Rfc4122Uuid::parse)
        .ok_or_else(|| NOT_PERMITTED.to_owned())?;
    Ok(AuthorPrincipal {
        tenant_id,
        license_id,
        subject: caller.subject.clone(),
        via: None,
    })
}

/// The reference's `given(**fields)`: the named arguments that are present and not null.
pub(crate) fn given(arguments: &Map<String, Value>, fields: &[&str]) -> Map<String, Value> {
    let mut payload = Map::new();
    for field in fields {
        if let Some(value) = arguments.get(*field)
            && !value.is_null()
        {
            payload.insert((*field).to_owned(), value.clone());
        }
    }
    payload
}

/// The reference's `parse(Model, payload)`: strict model validation of the payload.
///
/// A refusal is a `BuilderInputError`, which the guard shows verbatim (no `invalid:` prefix),
/// so the message travels unchanged — truncated to the reference's 1500 characters.
pub(crate) fn parse<T: DeserializeOwned>(payload: Map<String, Value>) -> Result<T, String> {
    serde_json::from_value(Value::Object(payload))
        .map_err(|error| truncated(&error.to_string(), 1500))
}

/// One required string argument. The provider's schema check has already ensured presence and
/// type; the fallback refusal is the `invalid:` class rather than a panic.
pub(crate) fn text(arguments: &Map<String, Value>, field: &str) -> Result<String, String> {
    arguments
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| format!("invalid: {field}: expected a string"))
}

/// One required integer argument (again schema-validated first).
pub(crate) fn integer(arguments: &Map<String, Value>, field: &str) -> Result<u64, String> {
    arguments
        .get(field)
        .and_then(Value::as_u64)
        .ok_or_else(|| format!("invalid: {field}: expected an integer"))
}

/// The pagination defaults the reference's Python signature declares (50, 0); the schema has
/// already bounded a present value.
pub(crate) fn page(arguments: &Map<String, Value>) -> (u32, u32) {
    let read = |field: &str, default: u32| {
        arguments
            .get(field)
            .and_then(Value::as_u64)
            .and_then(|value| u32::try_from(value).ok())
            .unwrap_or(default)
    };
    (read("limit", 50), read("offset", 0))
}

/// The reference's `uuid_arg`: a tool, run or toolkit identity, or `"{what} must be a uuid"`.
pub(crate) fn uuid_arg(value: &str, what: &str) -> Result<Uuid7, String> {
    Uuid7::new(value).map_err(|_| format!("{what} must be a uuid"))
}

/// One required positive version (schema-bounded to an integer of at least one).
pub(crate) fn version(
    arguments: &Map<String, Value>,
    field: &str,
) -> Result<PositiveVersion, String> {
    let value = integer(arguments, field)?;
    PositiveVersion::new(value).map_err(|_| format!("invalid: {field} must be a positive integer"))
}

/// An optional version: absent and null are both "the newest".
pub(crate) fn optional_version(
    arguments: &Map<String, Value>,
    field: &str,
) -> Result<Option<PositiveVersion>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => {
            let number = value
                .as_u64()
                .ok_or_else(|| format!("invalid: {field}: expected an integer"))?;
            PositiveVersion::new(number)
                .map(Some)
                .map_err(|_| format!("invalid: {field} must be a positive integer"))
        }
    }
}

/// The MCP success for one tool: the service's JSON view as both structured content and text,
/// the shape FastMCP produced for the reference.
pub(crate) fn answer(result: Result<Value, BuilderError>) -> Result<CallToolResult, String> {
    match result {
        Ok(value) => Ok(CallToolResult::structured(value)),
        Err(error) => Err(refusal(error)),
    }
}

/// The reference's `guard` error mapping, text for text.
pub(crate) fn refusal(error: BuilderError) -> String {
    match error {
        BuilderError::Forbidden(_) => NOT_PERMITTED.to_owned(),
        // `QuotaExceededError`'s own text is `"{resource} quota exceeded"`; the guard prefixes
        // `quota exceeded: `, so the doubled phrasing is the reference's.
        BuilderError::Quota(resource) => format!("quota exceeded: {resource} quota exceeded"),
        BuilderError::NotFound(message) => format!("not found: {message}"),
        BuilderError::Conflict(message) => format!("conflict: {message}"),
        // The reference's uncaught `ValueError`: the message, bounded to 500 characters.
        BuilderError::Invalid(message) => format!("invalid: {}", truncated(&message, 500)),
        // `BuilderError` subclasses and `BuilderInputError` carry a message the guard shows
        // unchanged.
        BuilderError::Failed(message)
        | BuilderError::Unavailable(message)
        | BuilderError::RateLimited(message)
        | BuilderError::Upstream(message)
        | BuilderError::Input(message) => message,
    }
}

/// Python's `text[:maximum]` (characters, not bytes).
fn truncated(text: &str, maximum: usize) -> String {
    text.chars().take(maximum).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn caller(kind: CallerKind, tenant: Option<&str>, licence: Option<&str>) -> BuiltinCaller {
        BuiltinCaller {
            kind,
            subject: "svc:t:mcp".to_owned(),
            scope: "licence:mcp".to_owned(),
            tenant_id: tenant.map(str::to_owned),
            license_id: licence.map(str::to_owned),
            strata_token: None,
        }
    }

    #[test]
    fn the_inventory_is_the_twenty_reference_tools() {
        let names: Vec<&str> = inventory::entries()
            .iter()
            .map(|entry| entry.name.as_str())
            .collect();
        let mut sorted = names.clone();
        sorted.sort_unstable();
        assert_eq!(names, sorted, "the inventory is sorted by wire name");
        assert_eq!(names.len(), 20);
        assert!(names.iter().all(|name| name.starts_with("builder_")));
    }

    #[test]
    fn an_author_needs_the_tenant_author_kind_and_both_identities() {
        let tenant = "10000000-0000-7000-8000-000000000001";
        let licence = "30000000-0000-4000-8000-000000000001";
        let principal = author(&caller(
            CallerKind::TenantAuthor,
            Some(tenant),
            Some(licence),
        ))
        .expect("a tenant author");
        assert_eq!(principal.tenant_id.to_string(), tenant);
        assert_eq!(principal.license_id.to_string(), licence);
        assert_eq!(principal.subject, "svc:t:mcp");
        assert!(principal.via.is_none());

        for refused in [
            caller(CallerKind::CarebusLicence, Some(tenant), Some(licence)),
            caller(CallerKind::TenantAuthor, None, Some(licence)),
            caller(CallerKind::TenantAuthor, Some(tenant), None),
            caller(CallerKind::TenantAuthor, Some("not-a-uuid"), Some(licence)),
            caller(CallerKind::TenantAuthor, Some(tenant), Some("not-a-uuid")),
        ] {
            assert_eq!(author(&refused), Err(NOT_PERMITTED.to_owned()));
        }
    }

    #[test]
    fn the_guard_texts_are_the_references() {
        assert_eq!(
            refusal(BuilderError::Quota("source")),
            "quota exceeded: source quota exceeded"
        );
        assert_eq!(
            refusal(BuilderError::NotFound("source not found".to_owned())),
            "not found: source not found"
        );
        assert_eq!(
            refusal(BuilderError::Conflict(
                "source revision mismatch".to_owned()
            )),
            "conflict: source revision mismatch"
        );
        assert_eq!(
            refusal(BuilderError::Invalid("bad".to_owned())),
            "invalid: bad"
        );
        assert_eq!(
            refusal(BuilderError::Forbidden("platform".to_owned())),
            NOT_PERMITTED
        );
        assert_eq!(
            refusal(BuilderError::Input("field: rule".to_owned())),
            "field: rule"
        );
        let long = "x".repeat(600);
        assert_eq!(refusal(BuilderError::Invalid(long)).chars().count(), 509);
        assert_eq!(
            uuid_arg("nope", "tool_id"),
            Err("tool_id must be a uuid".to_owned())
        );
    }
}
