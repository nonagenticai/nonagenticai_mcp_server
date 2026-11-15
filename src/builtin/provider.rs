//! The builtin provider: list and call the in-process builtin tools for one caller.
//!
//! Ported from the reference `src/builtin/provider.py`. `list` returns exactly the caller's
//! scope in one ordered page; `call` of anything outside that scope is refused with
//! [`scope::DENIED_MESSAGE`] and audited as `denied`. Every call that reaches a result — allowed or
//! refused — writes one audit row through [`super::audit`].
//!
//! Tool results and tool error texts pass through unchanged: the care-bus executor reads the
//! `[retryable]` / `[permanent]` prefix a tool puts on its error text, so this provider must
//! never rewrite it. Arguments are validated against the tool's declared input schema before
//! the handler runs, and a refusal names the failing pointer and keyword only, never a value.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;

use rmcp::model::{CallToolResult, ContentBlock, Tool};
use serde_json::{Map, Value};

use crate::catalog::instance::{InstanceError, validate_instance};
use crate::catalog::validation::SchemaLimits;

use super::audit::{self, AuditSink};
use super::scope::{self, BuiltinCaller};

/// What a tool handler answers: the MCP result, or the error text the caller reads unchanged.
pub type HandlerResult = Result<CallToolResult, String>;
/// A handler's future; it owns everything it needs, so a handler never borrows a request.
pub type HandlerFuture = Pin<Box<dyn Future<Output = HandlerResult> + Send>>;
/// One builtin tool's implementation.
#[allow(clippy::type_complexity)]
pub type Handler = Arc<dyn Fn(BuiltinCaller, Map<String, Value>) -> HandlerFuture + Send + Sync>;

/// Box one handler future; families write `boxed(async move { ... })`.
pub fn boxed<F>(future: F) -> HandlerFuture
where
    F: Future<Output = HandlerResult> + Send + 'static,
{
    Box::pin(future)
}

/// One registered builtin tool.
#[derive(Clone)]
pub struct BuiltinTool {
    /// The wire name, `{namespace}_{function}` (see [`scope::wire_name`]).
    pub name: String,
    /// The family namespace this tool belongs to — the reference's `(server, namespace)`
    /// group. [`scope::namespaces`] maps a caller's scope key to the namespaces it may use;
    /// the provider never keeps a hand-written list of allowed names.
    pub scope: String,
    /// The MCP tool description.
    pub description: String,
    /// The tool's declared input schema, validated before every call.
    pub input_schema: Map<String, Value>,
    /// The tool's implementation.
    pub handler: Handler,
}

impl BuiltinTool {
    /// Register one tool under its family namespace; the wire name follows the reference's
    /// `{namespace}_{function}` rule.
    pub fn new(
        namespace: &str,
        function: &str,
        description: impl Into<String>,
        input_schema: Map<String, Value>,
        handler: Handler,
    ) -> Self {
        Self {
            name: scope::wire_name(namespace, function),
            scope: namespace.to_owned(),
            description: description.into(),
            input_schema,
            handler,
        }
    }
}

/// An ordered registry of builtin tools and the audit sink every call writes to.
///
/// The registry starts empty in this card (`super::register`); each later family registers its
/// tools through [`BuiltinProvider::register`].
#[derive(Clone, Default)]
pub struct BuiltinProvider {
    tools: Vec<BuiltinTool>,
    sink: Option<Arc<dyn AuditSink>>,
}

impl BuiltinProvider {
    /// An empty registry with no audit sink.
    pub fn new() -> Self {
        Self::default()
    }

    /// Attach the audit destination. Without one, calls are not audited (the reference's
    /// `sink=None`).
    pub fn with_sink(mut self, sink: Arc<dyn AuditSink>) -> Self {
        self.sink = Some(sink);
        self
    }

    /// Add one tool to the registry, preserving insertion order.
    pub fn register(&mut self, tool: BuiltinTool) {
        self.tools.push(tool);
    }

    /// The caller's tools, in one page sorted by wire name — the reference's `sorted(...)`.
    pub fn list(&self, caller: &BuiltinCaller) -> Vec<Tool> {
        let namespaces = scope::namespaces(&caller.scope);
        let mut tools: Vec<&BuiltinTool> = self
            .tools
            .iter()
            .filter(|tool| namespaces.contains(&tool.scope.as_str()))
            .collect();
        tools.sort_by_key(|tool| tool.name.as_str());
        tools
            .into_iter()
            .map(|tool| {
                Tool::new(
                    tool.name.clone(),
                    tool.description.clone(),
                    tool.input_schema.clone(),
                )
            })
            .collect()
    }

    /// One `tools/call`, answered with the tool's result or a tool-level error.
    ///
    /// The order is the reference's: the scope check (a refusal is audited as `denied`), the
    /// tool, the declared input schema, then the handler. A handler's error text is returned
    /// unchanged and audited as the failure's text.
    pub async fn call(
        &self,
        caller: &BuiltinCaller,
        name: &str,
        arguments: Map<String, Value>,
    ) -> CallToolResult {
        let started = Instant::now();
        let namespaces = scope::namespaces(&caller.scope);
        let granted = self
            .tools
            .iter()
            .any(|tool| tool.name == name && namespaces.contains(&tool.scope.as_str()));
        if !granted {
            audit::record(
                self.sink.clone(),
                caller,
                name,
                0,
                Some(scope::DENIED_MESSAGE),
                false,
                true,
            )
            .await;
            return error_result(scope::DENIED_MESSAGE);
        }

        // A name the registry does not hold would be the reference's NotFoundError branch; the
        // scope check above already covers every unregistered tool, so this is defensive.
        let Some(tool) = self.tools.iter().find(|candidate| candidate.name == name) else {
            let text = format!("Unknown tool: '{name}'");
            audit::record(
                self.sink.clone(),
                caller,
                name,
                elapsed_ms(started),
                Some(&text),
                false,
                false,
            )
            .await;
            return error_result(&text);
        };

        let schema = Value::Object(tool.input_schema.clone());
        let instance = Value::Object(arguments.clone());
        if let Err(error) = validate_instance(&schema, &instance, &SchemaLimits::default()) {
            let text = invalid_arguments(&error);
            audit::record(
                self.sink.clone(),
                caller,
                name,
                elapsed_ms(started),
                Some(&text),
                false,
                false,
            )
            .await;
            return error_result(&text);
        }

        match (tool.handler)(caller.clone(), arguments).await {
            Ok(result) => {
                audit::record(
                    self.sink.clone(),
                    caller,
                    name,
                    elapsed_ms(started),
                    None,
                    false,
                    false,
                )
                .await;
                result
            }
            Err(text) => {
                audit::record(
                    self.sink.clone(),
                    caller,
                    name,
                    elapsed_ms(started),
                    Some(&text),
                    false,
                    false,
                )
                .await;
                error_result(&text)
            }
        }
    }
}

/// The reference's `_error(text)`.
fn error_result(text: &str) -> CallToolResult {
    CallToolResult::error(vec![ContentBlock::text(text.to_owned())])
}

/// Milliseconds since `started`, clamped to the audit column's range.
fn elapsed_ms(started: Instant) -> i64 {
    i64::try_from(started.elapsed().as_millis()).unwrap_or(i64::MAX)
}

/// The reference's `_safe_text` for a schema refusal: name the pointer and the keyword, never
/// an argument value, at most 8 rules and 1000 characters.
fn invalid_arguments(error: &InstanceError) -> String {
    let InstanceError::Invalid(error) = error else {
        return error.to_string();
    };
    let parts: Vec<String> = error
        .problems
        .iter()
        .take(8)
        .map(|problem| {
            let location = if problem.path.is_empty() {
                "arguments"
            } else {
                problem.path.as_str()
            };
            format!("{location}: {}", problem.rule)
        })
        .collect();
    format!("invalid arguments: {}", parts.join("; "))
        .chars()
        .take(1000)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::builtin::scope::CallerKind;

    fn caller(scope: &str) -> BuiltinCaller {
        BuiltinCaller {
            kind: CallerKind::KeycloakService,
            subject: "test".to_owned(),
            scope: scope.to_owned(),
            tenant_id: None,
            license_id: None,
        }
    }

    fn schema() -> Map<String, Value> {
        let value = serde_json::json!({
            "type": "object",
            "properties": {"x": {"type": "integer"}},
            "required": ["x"],
            "additionalProperties": false,
        });
        value.as_object().cloned().expect("schema object")
    }

    fn echo() -> Handler {
        Arc::new(|_caller, arguments| {
            boxed(async move {
                Ok(CallToolResult::success(vec![ContentBlock::text(
                    arguments
                        .get("x")
                        .cloned()
                        .unwrap_or(Value::Null)
                        .to_string(),
                )]))
            })
        })
    }

    #[tokio::test]
    async fn listing_is_scope_filtered_and_sorted() {
        let mut provider = BuiltinProvider::new();
        provider.register(BuiltinTool::new("crm", "zeta", "z", schema(), echo()));
        provider.register(BuiltinTool::new("crm", "alpha", "a", schema(), echo()));
        provider.register(BuiltinTool::new("legal", "statute", "l", schema(), echo()));

        let executor = provider.list(&caller("carebus-tool-executor"));
        let names: Vec<&str> = executor.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(names, ["crm_alpha", "crm_zeta"]);

        let researcher = provider.list(&caller("carebus-researcher"));
        let names: Vec<&str> = researcher.iter().map(|tool| tool.name.as_ref()).collect();
        assert_eq!(names, ["legal_statute"]);

        assert!(provider.list(&caller("")).is_empty());
    }

    #[tokio::test]
    async fn out_of_scope_call_is_the_reference_denial() {
        let mut provider = BuiltinProvider::new();
        provider.register(BuiltinTool::new("crm", "alpha", "a", schema(), echo()));
        let result = provider
            .call(&caller("carebus-researcher"), "crm_alpha", Map::new())
            .await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.content[0].as_text().unwrap().text,
            scope::DENIED_MESSAGE
        );
    }

    #[tokio::test]
    async fn arguments_are_validated_without_echoing_values() {
        let mut provider = BuiltinProvider::new();
        provider.register(BuiltinTool::new("crm", "alpha", "a", schema(), echo()));
        let mut arguments = Map::new();
        arguments.insert("x".to_owned(), Value::String("secret".to_owned()));
        let result = provider
            .call(&caller("carebus-tool-executor"), "crm_alpha", arguments)
            .await;
        assert_eq!(result.is_error, Some(true));
        let text = result.content[0].as_text().unwrap().text.clone();
        assert!(text.starts_with("invalid arguments: "), "{text}");
        assert!(!text.contains("secret"), "{text}");
    }

    #[tokio::test]
    async fn a_tool_error_text_passes_through_unchanged() {
        let mut provider = BuiltinProvider::new();
        let handler: Handler = Arc::new(|_caller, _arguments| {
            boxed(async { Err("[permanent] 404 from GET /api/orders/X: not found".to_owned()) })
        });
        provider.register(BuiltinTool::new("crm", "alpha", "a", schema(), handler));
        let mut arguments = Map::new();
        arguments.insert("x".to_owned(), Value::from(1));
        let result = provider
            .call(&caller("carebus-tool-executor"), "crm_alpha", arguments)
            .await;
        assert_eq!(result.is_error, Some(true));
        assert_eq!(
            result.content[0].as_text().unwrap().text,
            "[permanent] 404 from GET /api/orders/X: not found"
        );
    }
}
