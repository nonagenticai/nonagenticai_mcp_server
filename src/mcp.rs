//! The MCP projection: `rmcp`'s streamable HTTP transport at `/mcp`.
//!
//! Phase 0 answers `initialize` and an empty `tools/list`. The wire shape matches the
//! Python source (`server.http_app(path="/", stateless_http=True, json_response=False)`):
//! no session, SSE-framed JSON-RPC responses. Phase 2 gives the handler the catalog pool so
//! `tools/list` is projected from `mcp_binding_tools`, filtered by the credential the auth
//! middleware resolved into the request extensions.

use std::sync::Arc;

use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    ErrorData as McpError, Implementation, ListToolsResult, PaginatedRequestParams,
    ServerCapabilities, ServerConfig,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;

/// The MCP handler. Phase 0 carries no state.
#[derive(Clone, Default)]
pub struct McpServer;

impl ServerHandler for McpServer {
    fn get_info(&self) -> ServerConfig {
        // `initialize` itself is answered by rmcp: it negotiates the protocol version.
        // Two fields are the Python source's, measured from fastmcp's own `initialize` reply
        // at the pinned SHA — the wire contract consumers see:
        //   * `serverInfo` is its identity;
        //   * `capabilities.tools.listChanged` is serialised as an explicit `false`
        //     (rmcp omits the field when it is `None`, which is a visible wire difference).
        let mut capabilities = ServerCapabilities::builder().enable_tools().build();
        if let Some(tools) = capabilities.tools.as_mut() {
            tools.list_changed = Some(false);
        }
        ServerConfig::new(capabilities)
            .with_server_info(Implementation::new("Executable catalog", "2.0.0"))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        Ok(ListToolsResult {
            tools: vec![],
            next_cursor: None,
            result_type: None,
            ttl_ms: None,
            cache_scope: None,
            meta: None,
        })
    }
}

/// The `/mcp` tower service. Mount it with `route_service`; the auth middleware must run
/// first so the handler can read the resolved credential from the request extensions.
pub fn service() -> StreamableHttpService<McpServer, LocalSessionManager> {
    // Non-exhaustive: start from `Default` and set only the fields this service owns.
    let mut config = StreamableHttpServerConfig::default();
    // Stateless, like the Python source: no `MCP-Session-Id` is issued or required.
    // `json_response` is honoured only in this mode (rmcp tower.rs).
    config.legacy_session_mode = false;
    // `false` = SSE frames, matching fastmcp's `json_response=False`.
    config.json_response = false;
    // rmcp's default `allowed_hosts` is loopback-only; the deployment sets the in-cluster
    // hostnames here. An empty value keeps the default (refuse non-loopback Host headers).
    let config = match std::env::var("MCP_ALLOWED_HOSTS") {
        Ok(hosts) if !hosts.trim().is_empty() => {
            config.with_allowed_hosts(hosts.split(',').map(str::trim).filter(|h| !h.is_empty()))
        }
        _ => config,
    };
    StreamableHttpService::new(
        || Ok(McpServer),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}
