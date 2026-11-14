//! The MCP projection: `rmcp`'s streamable HTTP transport at `/mcp`.
//!
//! `tools/list` is the reference's `listing` closure (`src/protocol.py`), ported: the caller's
//! resolved binding is projected into its public tools through the same live catalog resolver
//! the REST surface uses, paged by `CATALOG_PAGE_SIZE` with an HMAC-signed, fingerprint-bound
//! cursor. Every failure — a missing credential, a changed binding, a stale catalog, a bad
//! cursor — is the reference's single `-32602 catalog_unavailable_or_invalid_cursor`.
//!
//! The caller's authority arrives as the [`Principal`] the `/mcp` authentication middleware
//! inserts into the request extensions. rmcp's streamable HTTP tower service splits the HTTP
//! request and inserts its [`Parts`] — extensions included — into the JSON-RPC request, which
//! the service loop moves into [`RequestContext::extensions`]; the handler reads it from there
//! and trusts nothing else.

use std::sync::Arc;

use axum::http::request::Parts;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use hmac::{Hmac, KeyInit, Mac};
use rmcp::handler::server::ServerHandler;
use rmcp::model::{
    ErrorData as McpError, Implementation, JsonObject, ListToolsResult, MetaObject,
    PaginatedRequestParams, ServerCapabilities, ServerConfig, Tool, ToolAnnotations,
};
use rmcp::service::{RequestContext, RoleServer};
use rmcp::transport::StreamableHttpServerConfig;
use rmcp::transport::streamable_http_server::StreamableHttpService;
use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use sqlx::PgPool;
use subtle::ConstantTimeEq as _;

use crate::AppState;
use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::catalog::models::Effect;
use crate::catalog::public::output_envelope;
use crate::catalog::resolver::{CatalogResolver, ResolvedTool};
use crate::storage::bindings;

/// The reference's one catalog-listing refusal: it never tells a caller which check failed.
const CATALOG_REFUSAL: &str = "catalog_unavailable_or_invalid_cursor";

/// The cursor grammar's bound: anything longer cannot be one of this service's cursors.
const CURSOR_MAX_BYTES: usize = 512;

/// The MCP handler: the catalog pool, the configured page bound and the live resolver. Built
/// once per service; the pool and resolver are shared, and nothing is cached per caller.
#[derive(Clone)]
pub struct McpServer {
    pool: PgPool,
    page_size: u32,
    resolver: CatalogResolver,
}

impl McpServer {
    /// The reference's `listing` closure, in full: resolve the caller's projection, prove the
    /// binding has not moved under the credential, fingerprint the projection, validate and
    /// mint the cursor, page, and project each tool into the MCP wire object.
    async fn listing(
        &self,
        request: Option<PaginatedRequestParams>,
        context: &RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        // The middleware's resolved principal. rmcp inserts the HTTP `Parts` (with the
        // extensions the middleware wrote) into the request; either half missing is a refusal.
        let principal = context
            .extensions
            .get::<Parts>()
            .and_then(|parts| parts.extensions.get::<Principal>())
            .cloned()
            .ok_or_else(refusal)?;

        // A live projection, re-derived for this request; management and bindingless callers
        // are refused by the resolver itself.
        let tools = self
            .resolver
            .resolve(&principal)
            .await
            .map_err(|_| refusal())?;

        // The credential's binding, re-read with no lock: a revision that moved since the
        // middleware authenticated means the credential is no longer the current authority.
        let binding_id = principal.binding_id.ok_or_else(refusal)?;
        let tenant = AuthorityId::new(principal.tenant_id.to_string()).map_err(|_| refusal())?;
        let identity = Uuid7::new(binding_id.to_string()).map_err(|_| refusal())?;
        let mut conn = self.pool.acquire().await.map_err(|_| refusal())?;
        let row = bindings::get_binding(&mut conn, &tenant, &identity, false)
            .await
            .map_err(|_| refusal())?;
        drop(conn);
        if principal.binding_revision != Some(row.revision) {
            return Err(refusal());
        }
        // The HMAC key is the binding's stored token digest; the token itself is never held.
        let key = hex::decode(&row.token_sha256).map_err(|_| refusal())?;
        let generation = self.resolver.generation().await.map_err(|_| refusal())?;

        // The reference's identity array. The per-tool entries are its
        // `manifest_json + effective_json` concatenation; the exact JSON text is opaque to the
        // caller (it only ever feeds the fingerprint), so this service re-serialises and does
        // not chase byte-compatibility with a Python-generated cursor.
        let entries: Vec<String> = tools
            .iter()
            .map(|tool| {
                let manifest = serde_json::to_string(&tool.manifest)?;
                let effective = serde_json::to_string(&tool.effective)?;
                Ok::<String, serde_json::Error>(format!("{manifest}{effective}"))
            })
            .collect::<Result<_, _>>()
            .map_err(|_| refusal())?;
        let identity = json!([
            principal.tenant_id.to_string(),
            principal.license_id.to_string(),
            binding_id.to_string(),
            row.revision,
            generation,
            entries,
        ]);
        let encoded = serde_json::to_vec(&identity).map_err(|_| refusal())?;
        let fingerprint = hex::encode(Sha256::digest(&encoded));

        // Cursor validation, in the reference's order: length, exactly two '.', constant-time
        // signature, fingerprint equality, then an in-range position.
        let mut offset = 0usize;
        if let Some(cursor) = request.as_ref().and_then(|params| params.cursor.as_deref()) {
            if cursor.len() > CURSOR_MAX_BYTES {
                return Err(refusal());
            }
            let mut parts = cursor.split('.');
            let (Some(raw), Some(signature), None) = (parts.next(), parts.next(), parts.next())
            else {
                return Err(refusal());
            };
            let expected = sign(&key, raw)?;
            if !bool::from(signature.as_bytes().ct_eq(expected.as_bytes())) {
                return Err(refusal());
            }
            let decoded = URL_SAFE.decode(raw).map_err(|_| refusal())?;
            let data: Value = serde_json::from_slice(&decoded).map_err(|_| refusal())?;
            let position = data.get("o").and_then(Value::as_u64);
            match position {
                Some(o)
                    if data.get("f").and_then(Value::as_str) == Some(fingerprint.as_str())
                        && o > 0
                        && o < tools.len() as u64 =>
                {
                    offset = usize::try_from(o).map_err(|_| refusal())?;
                }
                _ => return Err(refusal()),
            }
        }

        let page_size = usize::try_from(self.page_size).unwrap_or(usize::MAX);
        let end = offset.saturating_add(page_size);
        let next_cursor = if end < tools.len() {
            let raw = URL_SAFE.encode(
                serde_json::to_vec(&json!({"o": end, "f": fingerprint})).map_err(|_| refusal())?,
            );
            Some(format!("{raw}.{}", sign(&key, &raw)?))
        } else {
            None
        };
        let tools = tools
            .get(offset..end.min(tools.len()))
            .ok_or_else(refusal)?
            .iter()
            .map(project)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(ListToolsResult {
            tools,
            next_cursor,
            result_type: None,
            ttl_ms: None,
            cache_scope: None,
            meta: None,
        })
    }
}

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
        request: Option<PaginatedRequestParams>,
        context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, McpError> {
        self.listing(request, &context).await
    }
}

/// The reference's refusal: `MCPError(code=-32602, message="catalog_unavailable_or_invalid_cursor")`.
fn refusal() -> McpError {
    McpError::invalid_params(CATALOG_REFUSAL, None)
}

/// `hmac_sha256(key, raw)` rendered as lowercase hex, exactly the cursor's signature.
fn sign(key: &[u8], raw: &str) -> Result<String, McpError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).map_err(|_| refusal())?;
    mac.update(raw.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// One resolved tool as the MCP `Tool` the reference serves (`ResolvedTool.public()`).
///
/// `version` is a fastmcp-local attribute in the reference, not part of the MCP `Tool` schema,
/// so it is deliberately absent from the wire object here too.
fn project(tool: &ResolvedTool) -> Result<Tool, McpError> {
    let manifest = &tool.manifest;
    let envelope =
        output_envelope(&Value::Object(manifest.result_schema.clone())).map_err(|_| refusal())?;
    let output_schema = envelope.as_object().cloned().ok_or_else(refusal)?;
    // Non-exhaustive structs: `from_raw` names every hint the reference sets.
    let annotations = ToolAnnotations::from_raw(
        None,
        Some(manifest.effect == Effect::ReadOnly),
        Some(manifest.effect == Effect::Writes),
        Some(false),
        Some(!manifest.allowed_operations.is_empty()),
    );
    let meta = MetaObject(JsonObject::from_iter([(
        "operation".to_owned(),
        json!(manifest.operation),
    )]));
    Ok(Tool::new(
        manifest.public_name.as_str().to_owned(),
        manifest.description.clone(),
        manifest.input_schema.clone(),
    )
    .with_raw_output_schema(Arc::new(output_schema))
    .with_annotations(annotations)
    .with_meta(meta))
}

/// The `/mcp` tower service. Mount it with `route_service`; the auth middleware must run
/// first so the handler can read the resolved credential from the request extensions.
pub fn service(state: &AppState) -> StreamableHttpService<McpServer, LocalSessionManager> {
    // The resolver is built exactly as the REST projection builds it, so both surfaces serve
    // one live catalog and cannot disagree.
    let server = McpServer {
        pool: state.pool.clone(),
        page_size: state.catalog_page_size,
        resolver: crate::routes::available::resolver(state),
    };
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
        move || Ok(server.clone()),
        Arc::new(LocalSessionManager::default()),
        config,
    )
}
