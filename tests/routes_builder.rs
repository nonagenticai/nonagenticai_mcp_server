//! The 26 tenant tool-builder operations under `/mcp/builder`, exercised through the real
//! router, the real builder service, a real Postgres 18, a stub JWKS (RS256 tokens signed for
//! real) and a stub document fetch.
//!
//! Both mounts are driven end to end over the same script: the tenant mount with a tenant
//! licence, and the product mirror with a service JWT plus the path tenant's licence — once in
//! the headers and once inside the JSON body (which the middleware must strip before the
//! handler's `deny_unknown_fields` model sees it). Each refusal the reference defines is
//! asserted with its exact body and status: the disabled builder's `404 not_found` before any
//! credential is read, the tenant mount's `401`/`403`, the product mount's service-token and
//! licence refusals (a path tenant never chooses the acting tenant), the router's own
//! `422 invalid_request`, the FastAPI `404 {"detail": "Not Found"}`, the `405`, and the body
//! bound's `413 request_too_large`.
//!
//! Server selection is `tests/support`'s: `TEST_DATABASE_URL`, else `DATABASE_URL`, else an
//! ephemeral `postgres:18` container, else FAIL (never skip). Each test gets its own database.

mod support;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tower::ServiceExt;

use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, BoxFuture, KeycloakSettings, KeycloakVerifier, LicenceAuthority,
    LicenseIdentity, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::builder::service::{
    BuilderService, BuilderServiceDependencies, DocumentFetcher, FetchError,
};
use mcp_server_rs::catalog::ids::AuthorityId;
use mcp_server_rs::catalog::service::CatalogService;
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::config::{BindingEnsureSettings, BuilderSettings, PackageLimits};
use mcp_server_rs::routes::builder::BuilderRuntime;
use mcp_server_rs::routes::internal::InternalRuntime;
use mcp_server_rs::sources::tenant_repository::{TenantSourceRepository, TenantSourceSettings};
use mcp_server_rs::storage::bindings_ensure::BindingEnsureService;
use mcp_server_rs::storage::builder::{BuilderCatalogRepository, DraftRunSettings};
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::worker::sources::{ResolvedSource, SourceRegistry};
use mcp_server_rs::{AppState, app_with_builder, install_crypto_provider, openapi};

use support::Fixture;

const TENANT_A: &str = support::TENANT_A;
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const TENANT_PLATFORM: &str = support::TENANT_PLATFORM;
const LICENCE_A: &str = support::LICENCE_ID;
const LICENCE_B: &str = "30000000-0000-4000-8000-000000000002";
const PLATFORM_LICENCE: &str = "30000000-0000-4000-8000-000000000003";
const GATEWAY_APP_KEY: &str = support::GATEWAY_APP_KEY;

const TENANT_TOKEN: &str = "tenant-a-builder-licence";
const TENANT_B_TOKEN: &str = "tenant-b-builder-licence";
const MEMBER_TOKEN: &str = "tenant-a-member-licence";
const PLATFORM_TOKEN: &str = "platform-builder-licence";
const PRODUCT_TOKEN: &str = "tenant-a-product-licence";

/// The approved runner image the builder service's `tool_create` pins.
const DIGEST: &str = "registry.example/runner@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// The stub document the fetcher serves: two importable read operations.
const SPEC: &str = r#"{
  "openapi": "3.1.0",
  "info": {"title": "Billing", "version": "1.2"},
  "paths": {
    "/items": {
      "get": {
        "operationId": "list_items",
        "summary": "List items",
        "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object", "properties": {"id": {"type": "string"}}}}}}}
      }
    },
    "/widgets": {
      "get": {
        "operationId": "list_widgets",
        "summary": "List widgets",
        "responses": {"200": {"description": "ok", "content": {"application/json": {"schema": {"type": "object"}}}}}
      }
    }
  }
}"#;

const CLIENT: &str = "carebus-tool-executor";
const OTHER_CLIENT: &str = "portal-frontend";
const AUDIENCE: &str = "nonagenticai-mcp";
const REALM: &str = "portal";
const KID: &str = "test-kid-1";
const ENTERPRISE_UUID7: &str = "01900000-0000-7000-8000-0000000000d1";

// ── the harness ───────────────────────────────────────────────────────────────────────────

struct Harness {
    fixture: Fixture,
    jwks: Stub,
    licences: Arc<RouteLicence>,
}

impl Harness {
    async fn new() -> Self {
        install_crypto_provider();
        Self {
            fixture: Fixture::new().await,
            jwks: Stub::start().await,
            licences: Arc::new(RouteLicence),
        }
    }

    fn state(&self) -> AppState {
        self.fixture.state()
    }

    fn auth(&self) -> Auth {
        let mut auth = Auth::from_config(&AuthConfig {
            // The URL and key travel together; the authority itself is the stub below, so the
            // endpoint is never called.
            license_introspect_url: Some("https://licence.example/introspect".into()),
            license_app_key: Some(GATEWAY_APP_KEY.to_owned()),
            ..AuthConfig::default()
        })
        .expect("a valid auth config");
        auth.licences = self.licences.clone();
        auth
    }

    /// The enabled application: the real service, the stub JWKS verifier and the stub fetch.
    fn app(&self) -> Router {
        let state = self.state();
        let auth = self.auth();
        let internal = InternalRuntime::unavailable(&state, &auth);
        let builder = BuilderRuntime::new(
            self.service(),
            Some(Arc::new(self.jwks.verifier())),
            self.licences.clone(),
            platform_identity(),
            Some(GATEWAY_APP_KEY.to_owned()),
            262_144,
        );
        app_with_builder(state, auth, internal, builder)
    }

    /// The same application with no builder installed (the reference's disabled builder).
    fn disabled_app(&self) -> Router {
        let state = self.state();
        let auth = self.auth();
        let internal = InternalRuntime::unavailable(&state, &auth);
        let builder = BuilderRuntime::disabled(&state, &auth);
        app_with_builder(state, auth, internal, builder)
    }

    /// The enabled application with the product mount's verifier unconfigured.
    fn app_without_keycloak(&self) -> Router {
        let state = self.state();
        let auth = self.auth();
        let internal = InternalRuntime::unavailable(&state, &auth);
        let builder = BuilderRuntime::new(
            self.service(),
            None,
            self.licences.clone(),
            platform_identity(),
            Some(GATEWAY_APP_KEY.to_owned()),
            262_144,
        );
        app_with_builder(state, auth, internal, builder)
    }

    fn service(&self) -> Arc<BuilderService> {
        let settings = BuilderSettings {
            enabled: true,
            ..BuilderSettings::default()
        };
        let sources = TenantSourceRepository::from_settings(
            self.fixture.pool.clone(),
            &TenantSourceSettings {
                secret_key: Some(secret_key().to_vec()),
                max_sources: settings.max_sources,
                licence_hosts: vec!["api.example.test".to_owned()],
                allowed_ports: settings.allowed_ports.clone(),
                spec_keep: 3,
                spec_max_total_bytes: settings.spec_max_total_bytes_per_tenant,
            },
        );
        let resolver = SelectionResolver {
            platform_tenant_id: platform(),
        };
        let ensure = BindingEnsureService::new(
            self.fixture.pool.clone(),
            resolver.clone(),
            Some(GATEWAY_APP_KEY.to_owned()),
            self.licences.clone(),
            None,
            &BindingEnsureSettings::default(),
            platform(),
        );
        let dependencies = BuilderServiceDependencies {
            sources,
            builder: BuilderCatalogRepository::new(self.fixture.pool.clone()),
            catalog: CatalogService::new(
                CatalogRepository::new(self.fixture.pool.clone()),
                SchemaLimits::default(),
                PackageLimits::default(),
            ),
            resolver,
            draft: Some(draft_settings()),
            minter: None,
            fetcher: Some(Arc::new(BodyFetcher(SPEC.as_bytes().to_vec()))),
            registry: Some({
                // The registry decodes the sealing key at construction, exactly as a deployment
                // hands it the configured `MCP_SOURCE_SECRET_KEY`.
                let key = source_secret_key();
                SourceRegistry::new(self.fixture.pool.clone(), Some(&key), Vec::new())
                    .expect("the source registry")
            }),
            ensure: Some(ensure),
        };
        Arc::new(BuilderService::new(
            self.fixture.pool.clone(),
            settings,
            SchemaLimits::default(),
            vec![DIGEST.to_owned()],
            dependencies,
        ))
    }

    async fn call(
        &self,
        app: &Router,
        mount: Mount,
        method: Method,
        inner: &str,
        body: Option<Value>,
    ) -> (StatusCode, HeaderMap, Value) {
        let token = service_token(&self.jwks, CLIENT);
        send(app, request(mount, method, inner, body, &token)).await
    }

    async fn call_ok(
        &self,
        app: &Router,
        mount: Mount,
        method: Method,
        inner: &str,
        body: Option<Value>,
        expected: StatusCode,
    ) -> Value {
        let (status, headers, value) = self.call(app, mount, method.clone(), inner, body).await;
        assert_eq!(status, expected, "{method} {inner}: {value}");
        assert!(
            no_store(&headers),
            "{method} {inner} must carry Cache-Control: no-store"
        );
        value
    }

    /// The whole 26-operation lifecycle, through one mount.
    async fn drive_lifecycle(&self, app: &Router, mount: Mount) {
        // usage
        let usage = self
            .call_ok(app, mount, Method::GET, "/usage", None, StatusCode::OK)
            .await;
        assert_eq!(usage["used"]["sources"], 0);
        assert_eq!(usage["limits"]["sources"], 20);

        // create the source; on the product mount this request carries the licence in the body
        let create_mount = match mount {
            Mount::Product => Mount::ProductBody,
            other => other,
        };
        let source = self
            .call_ok(
                app,
                create_mount,
                Method::POST,
                "/sources",
                Some(json!({
                    "source_key": "billing",
                    "base_url": "https://api.example.test",
                    "auth": {"kind": "static_bearer"},
                    "token": "source-token",
                    "spec_path": "/openapi.json",
                })),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(source["source_key"], "billing");
        assert_eq!(source["revision"], 1);
        assert_eq!(source["status"], "active");
        assert!(
            source.get("token").is_none(),
            "a source view never carries the secret"
        );

        let listed = self
            .call_ok(app, mount, Method::GET, "/sources", None, StatusCode::OK)
            .await;
        assert_eq!(listed["items"].as_array().expect("items").len(), 1);
        assert_eq!(listed["limit"], 50);

        let got = self
            .call_ok(
                app,
                mount,
                Method::GET,
                "/sources/billing",
                None,
                StatusCode::OK,
            )
            .await;
        assert_eq!(got["source_key"], "billing");

        let updated = self
            .call_ok(
                app,
                mount,
                Method::PUT,
                "/sources/billing",
                Some(json!({
                    "base_url": "https://api.example.test",
                    "auth": {"kind": "static_bearer"},
                    "spec_path": "/openapi.json",
                    "expected_revision": 1,
                })),
                StatusCode::OK,
            )
            .await;
        assert_eq!(updated["revision"], 2);

        let rotated = self
            .call_ok(
                app,
                mount,
                Method::PUT,
                "/sources/billing/secret",
                Some(json!({"token": "second-token", "expected_revision": 2})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(rotated["revision"], 3);
        assert_eq!(rotated["has_token"], true);

        let disabled = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/sources/billing/disable",
                Some(json!({"expected_revision": 3})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(disabled["status"], "disabled");
        assert_eq!(disabled["revision"], 4);

        let enabled = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/sources/billing/enable",
                Some(json!({"expected_revision": 4})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(enabled["status"], "active");
        assert_eq!(enabled["revision"], 5);

        // spec fetch, cached by digest
        let fetched = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/sources/billing/spec/fetch",
                Some(json!({})),
                StatusCode::OK,
            )
            .await;
        let sha = fetched["sha256"].as_str().expect("the digest").to_owned();
        assert_eq!(sha.len(), 64);
        assert_eq!(fetched["title"], "Billing");
        assert_eq!(
            fetched["operations"].as_array().expect("operations").len(),
            2
        );

        let operations = self
            .call_ok(
                app,
                mount,
                Method::GET,
                &format!("/sources/billing/spec/{sha}/operations"),
                None,
                StatusCode::OK,
            )
            .await;
        assert_eq!(
            operations["operations"]
                .as_array()
                .expect("operations")
                .len(),
            2
        );

        let imported = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/sources/billing/operations/import",
                Some(json!({"spec_sha256": sha, "select": ["list_items"]})),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(imported["imported"][0]["op_key"], "list_items");
        assert_eq!(imported["imported"][0]["version"], 1);

        let listed_operations = self
            .call_ok(
                app,
                mount,
                Method::GET,
                "/sources/billing/operations",
                None,
                StatusCode::OK,
            )
            .await;
        assert_eq!(
            listed_operations["operations"]
                .as_array()
                .expect("operations")
                .len(),
            1
        );

        let patched = self
            .call_ok(
                app,
                mount,
                Method::PATCH,
                "/sources/billing/operations/list_items",
                Some(json!({"expected_version": 1, "timeout_seconds": 30})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(patched["version"], 2);
        assert_eq!(patched["timeout_seconds"], 30);

        // tools
        let tool = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/tools",
                Some(tool_body("list_items")),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(tool["version"], 1);
        assert_eq!(tool["status"], "draft");
        assert_eq!(tool["ops"], json!(["billing.list_items"]));
        let tool_id = tool["tool_id"].as_str().expect("a tool id").to_owned();

        let listed_tools = self
            .call_ok(app, mount, Method::GET, "/tools", None, StatusCode::OK)
            .await;
        assert_eq!(listed_tools["items"].as_array().expect("items").len(), 1);

        let got_tool = self
            .call_ok(
                app,
                mount,
                Method::GET,
                &format!("/tools/{tool_id}"),
                None,
                StatusCode::OK,
            )
            .await;
        assert_eq!(got_tool["version"], 1);

        let appended = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/tools/{tool_id}/versions"),
                Some(json!({"expected_revision": 1, "description": "Find a customer by name"})),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(appended["version"], 2);
        assert_eq!(
            appended["manifest"]["description"],
            "Find a customer by name"
        );

        let tested = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/tools/{tool_id}/versions/1/test"),
                Some(json!({})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(tested["mode"], "draft");
        let run_id = tested["run_id"].as_str().expect("a run id").to_owned();

        let run = self
            .call_ok(
                app,
                mount,
                Method::GET,
                &format!("/runs/{run_id}"),
                None,
                StatusCode::OK,
            )
            .await;
        assert_eq!(run["mode"], "draft");
        assert_eq!(run["status"], "queued");

        let published = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/tools/{tool_id}/versions/2/publish"),
                Some(json!({"expected_revision": 2})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(published["status"], "published");
        assert_eq!(published["revision"], 3);

        // toolkits
        let toolkit = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/toolkits",
                Some(json!({
                    "name": "builder_toolkit",
                    "description": "A builder toolkit",
                    "tools": [{"tool_id": tool_id}],
                })),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(toolkit["manifest"]["version"], 1);
        assert_eq!(toolkit["revision"], 1);
        let toolkit_id = toolkit["manifest"]["toolkit_id"]
            .as_str()
            .expect("a toolkit id")
            .to_owned();

        let appended_toolkit = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/toolkits/{toolkit_id}/versions"),
                Some(json!({
                    "toolkit_id": toolkit_id,
                    "name": "builder_toolkit",
                    "description": "A builder toolkit",
                    "tools": [{"tool_id": tool_id}],
                    "expected_revision": 1,
                })),
                StatusCode::CREATED,
            )
            .await;
        assert_eq!(appended_toolkit["manifest"]["version"], 2);
        assert_eq!(appended_toolkit["revision"], 2);

        let published_toolkit = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/toolkits/{toolkit_id}/versions/2/publish"),
                Some(json!({"expected_revision": 2})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(published_toolkit["status"], "published");
        assert_eq!(published_toolkit["bindings"]["products"], json!([]));

        let rebound = self
            .call_ok(
                app,
                mount,
                Method::POST,
                "/toolkits/bind",
                Some(json!({})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(rebound["products"], json!([]));

        // the tool lifecycle's last transitions
        let disabled_tool = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/tools/{tool_id}/versions/2/disable"),
                Some(json!({"expected_revision": 3})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(disabled_tool["status"], "disabled");
        assert_eq!(disabled_tool["revision"], 4);

        let retired_tool = self
            .call_ok(
                app,
                mount,
                Method::POST,
                &format!("/tools/{tool_id}/versions/2/retire"),
                Some(json!({"expected_revision": 4})),
                StatusCode::OK,
            )
            .await;
        assert_eq!(retired_tool["status"], "retired");
        assert_eq!(retired_tool["revision"], 5);
    }

    async fn finish(self) {
        self.jwks.stop();
        self.fixture.finish().await;
    }
}

// ── the two mounts ────────────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mount {
    /// `/mcp/builder/*`: the tenant licence in `X-Tenant-Id`.
    Tenant,
    /// `/mcp/internal/tenants/{tenant}/builder/*`: service JWT plus the licence in headers.
    Product,
    /// The product mirror with the licence in the JSON body instead.
    ProductBody,
}

fn product_path(tenant: &str, inner: &str) -> String {
    format!("/mcp/internal/tenants/{tenant}/builder{inner}")
}

fn inner_path(mount: Mount, inner: &str) -> String {
    match mount {
        Mount::Tenant => format!("/mcp/builder{inner}"),
        Mount::Product | Mount::ProductBody => product_path(TENANT_A, inner),
    }
}

fn request(
    mount: Mount,
    method: Method,
    inner: &str,
    body: Option<Value>,
    jwt: &str,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(inner_path(mount, inner));
    let mut body = body;
    match mount {
        Mount::Tenant => {
            builder = builder.header("x-tenant-id", format!("Bearer {TENANT_TOKEN}"));
        }
        Mount::Product => {
            builder = builder
                .header(header::AUTHORIZATION, format!("Bearer {jwt}"))
                .header("x-tenant-id", format!("Bearer {PRODUCT_TOKEN}"))
                .header("x-mcp-licence-id", LICENCE_A);
        }
        Mount::ProductBody => {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {jwt}"));
            let mut value = body.take().unwrap_or_else(|| json!({}));
            value["licence_id"] = json!(LICENCE_A);
            value["licence_token"] = json!(PRODUCT_TOKEN);
            body = Some(value);
        }
    }
    let body = body
        .map(|value| Body::from(value.to_string()))
        .unwrap_or_default();
    builder.body(body).expect("a valid request")
}

/// A product-mount GET carrying the service JWT and, when given, the tenant licence headers.
fn product_licence_request(
    jwt: &str,
    path: String,
    tenant_header: Option<&str>,
    licence_id: Option<&str>,
) -> Request<Body> {
    let mut builder = Request::builder()
        .method(Method::GET)
        .uri(path)
        .header(header::AUTHORIZATION, format!("Bearer {jwt}"));
    if let Some(tenant_header) = tenant_header {
        builder = builder.header("x-tenant-id", format!("Bearer {tenant_header}"));
    }
    if let Some(licence_id) = licence_id {
        builder = builder.header("x-mcp-licence-id", licence_id);
    }
    builder.body(Body::empty()).expect("a valid request")
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app
        .clone()
        .oneshot(request)
        .await
        .expect("the router answers");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("a response body")
        .to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("a JSON body")
    };
    (status, headers, value)
}
fn no_store(headers: &HeaderMap) -> bool {
    headers
        .get_all(header::CACHE_CONTROL)
        .iter()
        .any(|value| matches!(value.to_str(), Ok("no-store")))
}

fn tool_body(op_key: &str) -> Value {
    json!({
        "public_name": "find_customer",
        "operation": "customer.find",
        "description": "Find a customer",
        "files": [{"path": "tool.py", "content": "async def main(inputs, ctx):\n    return {}\n"}],
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "effect": "read_only",
        "ops": [{"op_key": op_key, "source_key": "billing"}],
    })
}

// ── the lifecycle through each mount ─────────────────────────────────────────────────────

#[tokio::test]
async fn the_tenant_mount_serves_every_builder_operation() {
    let harness = Harness::new().await;
    let app = harness.app();
    harness.drive_lifecycle(&app, Mount::Tenant).await;
    harness.finish().await;
}

#[tokio::test]
async fn the_product_mount_serves_every_builder_operation() {
    let harness = Harness::new().await;
    let app = harness.app();
    harness.drive_lifecycle(&app, Mount::Product).await;
    harness.finish().await;
}

// ── the disabled builder ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_disabled_builder_answers_404_before_reading_credentials() {
    let harness = Harness::new().await;
    let app = harness.disabled_app();

    for mount in [Mount::Tenant, Mount::Product] {
        for inner in ["/usage", "/sources", "/nope"] {
            let path = inner_path(mount, inner);
            // No credential at all, then a garbage credential: the same 404, its own body.
            for credential in [None, Some("Bearer nonsense")] {
                let mut builder = Request::builder().method(Method::GET).uri(&path);
                if let Some(credential) = credential {
                    builder = builder
                        .header("x-tenant-id", credential)
                        .header(header::AUTHORIZATION, credential);
                }
                let (status, headers, body) =
                    send(&app, builder.body(Body::empty()).expect("a valid request")).await;
                assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
                assert_eq!(body, json!({"error": "not_found"}), "{path}");
                assert!(no_store(&headers), "{path}");
            }
        }
    }
    harness.finish().await;
}

// ── the tenant mount's authority ─────────────────────────────────────────────────────────

#[tokio::test]
async fn the_tenant_mount_refuses_anything_but_a_tenant_licence() {
    let harness = Harness::new().await;
    let app = harness.app();
    let path = inner_path(Mount::Tenant, "/usage");

    let cases: [(&str, Option<&str>, &str, StatusCode, Value); 7] = [
        (
            "no licence",
            None,
            "",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
        (
            "bare tenant id",
            Some(TENANT_TOKEN),
            "",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
        (
            "member licence",
            Some(MEMBER_TOKEN),
            "",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
        (
            "platform tenant",
            Some(PLATFORM_TOKEN),
            "",
            StatusCode::FORBIDDEN,
            json!({"error": "forbidden"}),
        ),
        (
            "binding header",
            Some(TENANT_TOKEN),
            "x-mcp-binding",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
        (
            "operator key",
            Some(TENANT_TOKEN),
            "x-mcp-admin-key",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
        (
            "platform operator key",
            Some(TENANT_TOKEN),
            "x-mcp-platform-admin-key",
            StatusCode::UNAUTHORIZED,
            json!({"error": "unauthorized"}),
        ),
    ];
    for (name, token, extra_header, expected_status, expected_body) in cases {
        let mut builder = Request::builder().method(Method::GET).uri(&path);
        if let Some(token) = token {
            let value = if name == "bare tenant id" {
                token.to_owned()
            } else {
                format!("Bearer {token}")
            };
            builder = builder.header("x-tenant-id", value);
        }
        if !extra_header.is_empty() {
            builder = builder.header(extra_header, "present");
        }
        let (status, headers, body) =
            send(&app, builder.body(Body::empty()).expect("request")).await;
        assert_eq!(status, expected_status, "{name}");
        assert_eq!(body, expected_body, "{name}");
        if expected_status == StatusCode::UNAUTHORIZED {
            assert!(
                headers.get(header::WWW_AUTHENTICATE).is_some(),
                "{name} must challenge"
            );
        }
    }
    harness.finish().await;
}

// ── the product mount's authority ────────────────────────────────────────────────────────

#[tokio::test]
async fn the_product_mount_requires_a_service_token_and_that_tenants_licence() {
    let harness = Harness::new().await;
    let app = harness.app();

    let licence_headers = |builder: axum::http::request::Builder| {
        builder
            .header("x-tenant-id", format!("Bearer {PRODUCT_TOKEN}"))
            .header("x-mcp-licence-id", LICENCE_A)
    };

    // No service token.
    let (status, _, body) = send(
        &app,
        licence_headers(
            Request::builder()
                .method(Method::GET)
                .uri(product_path(TENANT_A, "/usage")),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));

    // A token issued to a client outside the allow-list.
    let other = service_token(&harness.jwks, OTHER_CLIENT);
    let (status, _, body) = send(
        &app,
        licence_headers(
            Request::builder()
                .method(Method::GET)
                .uri(product_path(TENANT_A, "/usage"))
                .header(header::AUTHORIZATION, format!("Bearer {other}")),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // A binding token on the product path is ambiguous.
    let token = service_token(&harness.jwks, CLIENT);
    let (status, _, body) = send(
        &app,
        licence_headers(
            Request::builder()
                .method(Method::GET)
                .uri(product_path(TENANT_A, "/usage"))
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header("x-mcp-binding", "present"),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));

    // A service token with no tenant licence at all.
    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(product_path(TENANT_A, "/usage"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));

    // The verifier is what makes the mount callable; unconfigured it fails closed.
    let unconfigured = harness.app_without_keycloak();
    let (status, _, body) = send(
        &unconfigured,
        licence_headers(
            Request::builder()
                .method(Method::GET)
                .uri(product_path(TENANT_A, "/usage"))
                .header(header::AUTHORIZATION, format!("Bearer {token}")),
        )
        .body(Body::empty())
        .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error": "authority_unavailable"}));

    harness.finish().await;
}

#[tokio::test]
async fn the_product_mount_refuses_a_licence_that_is_not_the_path_tenants() {
    let harness = Harness::new().await;
    let app = harness.app();
    let token = service_token(&harness.jwks, CLIENT);

    let call = |path: String, tenant_header: Option<&str>, licence_id: Option<&str>| {
        product_licence_request(&token, path, tenant_header, licence_id)
    };

    // The path names tenant B; the licence is tenant A's.
    let (status, _, body) = send(
        &app,
        call(
            product_path(TENANT_B, "/usage"),
            Some(PRODUCT_TOKEN),
            Some(LICENCE_A),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // The path names tenant A; the licence belongs to tenant B.
    let (status, _, body) = send(
        &app,
        call(
            product_path(TENANT_A, "/usage"),
            Some(TENANT_B_TOKEN),
            Some(LICENCE_B),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // The licence's asserted id is not the tenant's licence.
    let (status, _, body) = send(
        &app,
        call(
            product_path(TENANT_A, "/usage"),
            Some(PRODUCT_TOKEN),
            Some(LICENCE_B),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // A member's per-login licence never authors.
    let (status, _, body) = send(
        &app,
        call(
            product_path(TENANT_A, "/usage"),
            Some(MEMBER_TOKEN),
            Some(LICENCE_A),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // The reserved platform tenant never authors, even with its own licence.
    let (status, _, body) = send(
        &app,
        call(
            product_path(TENANT_PLATFORM, "/usage"),
            Some(PLATFORM_TOKEN),
            Some(PLATFORM_LICENCE),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // A path tenant that is not a UUID is the reference's `invalid tenant`.
    let (status, _, body) = send(
        &app,
        call(
            product_path("not-a-uuid", "/usage"),
            Some(PRODUCT_TOKEN),
            Some(LICENCE_A),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    // The licence may arrive in the body; the handler must never see the extra fields.
    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(product_path(TENANT_A, "/sources"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .body(Body::from(
                json!({
                    "source_key": "from_the_body",
                    "base_url": "https://api.example.test",
                    "auth": {"kind": "none"},
                    "licence_id": LICENCE_A,
                    "licence_token": PRODUCT_TOKEN,
                })
                .to_string(),
            ))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["source_key"], "from_the_body");

    // And the row belongs to the licence tenant, not to whoever the path named: tenant B's own
    // view lists nothing.
    let b_path = product_path(TENANT_B, "/sources");
    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(b_path)
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header("x-tenant-id", format!("Bearer {TENANT_B_TOKEN}"))
            .header("x-mcp-licence-id", LICENCE_B)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["items"], json!([]));

    harness.finish().await;
}

// ── the router's own refusals ────────────────────────────────────────────────────────────

#[tokio::test]
async fn builder_refusals_carry_the_references_bodies() {
    let harness = Harness::new().await;
    let app = harness.app();

    // A missing row is `{"error": "not_found"}` with no detail.
    let (status, headers, body) = harness
        .call(&app, Mount::Tenant, Method::GET, "/sources/missing", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));
    assert!(no_store(&headers));

    // A body that is not the model is the 422 with a fixed, value-free detail.
    let (status, _, body) = harness
        .call(
            &app,
            Mount::Tenant,
            Method::POST,
            "/sources",
            Some(json!({"source_key": "billing"})),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        json!({"error": "invalid_request", "detail": "invalid request body"})
    );

    // The router's own cross-field refusal carries the reference's message.
    let (status, _, body) = harness
        .call(
            &app,
            Mount::Tenant,
            Method::POST,
            "/toolkits",
            Some(json!({
                "toolkit_id": ENTERPRISE_UUID7,
                "expected_revision": 1,
                "name": "builder_toolkit",
                "description": "A builder toolkit",
                "tools": [{"tool_id": ENTERPRISE_UUID7}],
            })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(
        body,
        json!({
            "error": "invalid_request",
            "detail": "use POST /toolkits/{id}/versions for a new version",
        })
    );

    // An authenticated unknown builder path is FastAPI's own 404 …
    let (status, _, body) = harness
        .call(&app, Mount::Tenant, Method::GET, "/nope", None)
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"detail": "Not Found"}));

    // … and it is authenticated first: without a licence it is 401, not 404.
    let path = inner_path(Mount::Tenant, "/nope");
    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::GET)
            .uri(path)
            .body(Body::empty())
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));

    // A method the path does not serve is FastAPI's 405.
    let (status, _, body) = harness
        .call(&app, Mount::Tenant, Method::POST, "/usage", Some(json!({})))
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
    assert_eq!(body, json!({"detail": "Method Not Allowed"}));

    harness.finish().await;
}

#[tokio::test]
async fn builder_path_and_query_validation_is_422() {
    let harness = Harness::new().await;
    let app = harness.app();
    let invalid_request = json!({"error": "invalid_request"});

    let cases: [(Method, String, Option<Value>); 8] = [
        (Method::GET, "/sources/Bad".to_owned(), None),
        (
            Method::GET,
            format!("/sources/billing/spec/{}/operations", "A".repeat(64)),
            None,
        ),
        (Method::GET, "/tools/not-a-uuid".to_owned(), None),
        (
            Method::POST,
            format!("/tools/{ENTERPRISE_UUID7}/versions/0/test"),
            Some(json!({})),
        ),
        (Method::GET, "/sources?limit=0".to_owned(), None),
        (Method::GET, "/sources?limit=101".to_owned(), None),
        (Method::GET, "/sources?offset=-1".to_owned(), None),
        (
            Method::GET,
            format!("/tools/{ENTERPRISE_UUID7}?version=0"),
            None,
        ),
    ];
    for (method, inner, body) in cases {
        let (status, _, value) = harness
            .call(&app, Mount::Tenant, method, &inner, body)
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{inner}");
        assert_eq!(value, invalid_request, "{inner}");
    }
    harness.finish().await;
}

#[tokio::test]
async fn a_body_over_the_management_bound_is_413() {
    let harness = Harness::new().await;
    let app = harness.app();

    let (status, _, body) = send(
        &app,
        Request::builder()
            .method(Method::POST)
            .uri(inner_path(Mount::Tenant, "/sources"))
            .header("x-tenant-id", format!("Bearer {TENANT_TOKEN}"))
            .body(Body::from("x".repeat(300_000)))
            .expect("request"),
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body, json!({"error": "request_too_large"}));

    harness.finish().await;
}

// ── the OpenAPI document ─────────────────────────────────────────────────────────────────

#[test]
fn openapi_documents_the_builder_operations_without_request_bodies() {
    let spec = serde_json::to_value(openapi()).expect("the OpenAPI document is JSON");
    let paths = spec["paths"].as_object().expect("paths");
    let mut described = 0;
    let mut operations = 0;
    let mut product_described = 0;
    let mut product_operations = 0;
    // OpenAPI requires every operationId to be unique; the builder handlers declare the
    // reference's generated ids explicitly so they cannot collide with the operator routes,
    // and the product mirror derives its own from them.
    let mut ids = std::collections::BTreeSet::new();
    for (path, item) in paths {
        let tenant = path.starts_with("/mcp/builder");
        let product = path.starts_with("/mcp/internal/tenants/{tenant_id}/builder");
        let item = item.as_object().expect("a path item");
        for (method, operation) in item {
            let id = operation["operationId"]
                .as_str()
                .unwrap_or_else(|| panic!("{method} {path} has no operationId"));
            assert!(ids.insert(id.to_owned()), "{id} is not unique");
            if !tenant && !product {
                continue;
            }
            assert!(
                operation.get("requestBody").is_none(),
                "{method} {path} must declare no request body"
            );
            assert_eq!(operation["tags"], json!(["builder"]), "{method} {path}");
            if tenant {
                operations += 1;
            } else {
                product_operations += 1;
            }
        }
        if tenant {
            described += 1;
        } else if product {
            product_described += 1;
        }
    }
    assert_eq!(described, 23, "every builder path is described");
    assert_eq!(operations, 26, "every builder operation is described");
    assert_eq!(product_described, 23, "the product mirror is described");
    assert_eq!(
        product_operations, 26,
        "every mirrored operation is described"
    );
    assert_eq!(
        spec["paths"]["/mcp/internal/tenants/{tenant_id}/builder/usage"]["get"]["operationId"],
        "usage_mcp_internal_tenants__tenant_id__builder_usage_get"
    );
    assert_eq!(
        spec["paths"]["/mcp/internal/tenants/{tenant_id}/builder/sources/{key}"]["get"]
            ["parameters"]
            .as_array()
            .expect("parameters")
            .len(),
        1,
        "the reference declares no tenant_id parameter"
    );
    assert_eq!(
        spec["paths"]["/mcp/builder/sources"]["post"]["operationId"],
        "create_source_mcp_builder_sources_post"
    );
    assert_eq!(
        spec["paths"]["/mcp/builder/sources/{key}"]["get"]["parameters"][0]["schema"]["pattern"],
        "^[a-z][a-z0-9_]{0,63}$"
    );
    assert_eq!(
        spec["paths"]["/mcp/builder/sources"]["post"]["responses"]["201"]["description"],
        "Successful Response"
    );
    assert_eq!(
        spec["paths"]["/mcp/builder/usage"]["get"]["responses"]["200"]["description"],
        "Successful Response"
    );

    // The reference declares a 422 only where a path or query parameter exists, and exactly
    // these success codes (`src/routers/builder.py`).
    let expected: [(&str, &str, &[&str]); 26] = [
        ("/mcp/builder/usage", "get", &["200"]),
        ("/mcp/builder/sources", "post", &["201"]),
        ("/mcp/builder/sources", "get", &["200", "422"]),
        ("/mcp/builder/sources/{key}", "get", &["200", "422"]),
        ("/mcp/builder/sources/{key}", "put", &["200", "422"]),
        ("/mcp/builder/sources/{key}/secret", "put", &["200", "422"]),
        (
            "/mcp/builder/sources/{key}/disable",
            "post",
            &["200", "422"],
        ),
        ("/mcp/builder/sources/{key}/enable", "post", &["200", "422"]),
        (
            "/mcp/builder/sources/{key}/spec/fetch",
            "post",
            &["200", "422"],
        ),
        (
            "/mcp/builder/sources/{key}/spec/{sha}/operations",
            "get",
            &["200", "422"],
        ),
        (
            "/mcp/builder/sources/{key}/operations/import",
            "post",
            &["201", "422"],
        ),
        (
            "/mcp/builder/sources/{key}/operations",
            "get",
            &["200", "422"],
        ),
        (
            "/mcp/builder/sources/{key}/operations/{op_key}",
            "patch",
            &["200", "422"],
        ),
        ("/mcp/builder/tools", "post", &["201"]),
        ("/mcp/builder/tools", "get", &["200", "422"]),
        ("/mcp/builder/tools/{identity}", "get", &["200", "422"]),
        (
            "/mcp/builder/tools/{identity}/versions",
            "post",
            &["201", "422"],
        ),
        (
            "/mcp/builder/tools/{identity}/versions/{version}/test",
            "post",
            &["200", "422"],
        ),
        (
            "/mcp/builder/tools/{identity}/versions/{version}/publish",
            "post",
            &["200", "422"],
        ),
        (
            "/mcp/builder/tools/{identity}/versions/{version}/disable",
            "post",
            &["200", "422"],
        ),
        (
            "/mcp/builder/tools/{identity}/versions/{version}/retire",
            "post",
            &["200", "422"],
        ),
        ("/mcp/builder/runs/{run_id}", "get", &["200", "422"]),
        ("/mcp/builder/toolkits", "post", &["201"]),
        ("/mcp/builder/toolkits/bind", "post", &["200"]),
        (
            "/mcp/builder/toolkits/{identity}/versions",
            "post",
            &["201", "422"],
        ),
        (
            "/mcp/builder/toolkits/{identity}/versions/{version}/publish",
            "post",
            &["200", "422"],
        ),
    ];
    for (path, method, statuses) in expected {
        let responses = spec["paths"][path][method]["responses"]
            .as_object()
            .unwrap_or_else(|| panic!("{method} {path} has no responses"));
        let mut actual: Vec<&str> = responses.keys().map(String::as_str).collect();
        actual.sort_unstable();
        assert_eq!(actual.as_slice(), statuses, "{method} {path}");
    }
}

// ── the stub Keycloak JWKS ───────────────────────────────────────────────────────────────

const PRIVATE_KEY_DER_BASE64: &str = concat!(
    "MIIEpAIBAAKCAQEAqAWN2ORmbmbQYq+aagWIw0dmjMAw8164FJZs6SE9EKr0UOJURKbAPSTtN4XP",
    "Ib6OcSSLrosz6hyZoCSVy+uSaR2lYBguwVbSzt9mOtehb37jtGLYzLONCTDOQBSpV3sSo3EJR+Io",
    "xzm2CgQf5G2H+MHUzapzPu/cyNDmWc7zfE+unVw1m6zcvkJsxkEUshxc8xaqjPCRGqP3xUdc4t9g",
    "m1QlIl38HAbaYuw89KmvuV+XJKSMw8DREAg/V8Hq6Wx35pUmFg3OaLBasyZykERHl2rENbZcIYnj",
    "yvHLgJI8sNm+b/fXnluyUbSRQws/xc9vEs7m/I3tv/ScLYXRHKRh2wIDAQABAoIBAA0BNQvrDbSQ",
    "16MzxUdce0vmDF1riL5lf+j0BaT7sh7GpJdYFT6lC28QGx43iKMrfRnrwrX1R0ThBtD60+9PIetp",
    "5IFuDbxgLHvflamLRA79qsEs/2vEn+9srCIQl1TSjUxCNP4v1okpAdp/nDpRcftCgWaTwUzHQvb2",
    "GEYuOvFNly1ua60g0h2RsVvp5Ktx1rwIYdIo28WVL8k+s0qjkHHT6iocfALAEVMW2rbzG649WXrg",
    "iWp67gVVwDPS7npPrRepqlfdSIwRZTTVuosBEM8N/oPNVeBRfZPMDEGurJDhfPRabTIiQcUGs27J",
    "mduGi0okOUvWF213rVFWFcUkVBkCgYEA7CszJ6+71qpY+huAti+0LEdPf1y7Z7UM3EicE+h2IwhB",
    "MqoCboJqB3ULexVdt8/7n/9PfkDKIfWYh3IbeBq4FYV+HMLjRvha0ExXQpEhylqqEDPRMIySEpS1",
    "IDkayi/iOR1UdZ6G6hA9T5AZvrS1utd+Nd2a1RfLJGgCPfP0UFMCgYEAtiFud80uZ/DydcpoUru2",
    "lVyP8EowkpNXf7HwX8xD48wI1CMvXK87+L9Jab1KRWnOKihifd5rd6aMNK0LF5Lq0bHtUvtR351A",
    "9gNw0W7D0f4bPVd4uvRPKGGVNnvuiiusQXnvCD0TpTD216QAyelJNDWv9Co1rQFVgyBPqbTvF1kC",
    "gYBOtptHJ/AwPPiI66+7iSzA8UeSyIKBrztJFD5I+FqflHm+fCFxWbAjKiSYcmeZAw33pq2FA+0a",
    "4nNi+WokXqtqKOL+jQoZNl92O2t9+UdM3Wj/G3Yme0OYQ84WnlHKf6kjph3nUd3fl2gH45xhDnPf",
    "gUFEjMa1LUf8q1nL8kpElwKBgQCZRHMBEELgJ4zygR3fmaYh9V4P2W8cui+k/yoIhA4Rsg8v7lga",
    "CEFQqDDwceIBnfNn2Mphn/4SF67fWUv/T5yaUMAl1+bjZiNXpDeZlzvlCJEFwwmPUq8WjWATFKH9",
    "1pjEFQeJiFRy7Eyd1Z7wS4hWDmP+9lJrP7clfNhtOR0HKQKBgQCdgoc81OVJBeJ9rfyPkEydH1G4",
    "bwXT7RKdpEmoWUnGpqpW9V2s+8XkVWsebNvKn67/lIJK4LMiO/+w9gKf5B1WH1O3eZ6+VqXt2Fxx",
    "p+36bVoz90WYw4PkUb5/M/JJGg0lo6UyN7hawB0IokRYmfCYjMeP9MKkXcKAjnKH1AwCmA==",
);
const JWKS_N: &str = "qAWN2ORmbmbQYq-aagWIw0dmjMAw8164FJZs6SE9EKr0UOJURKbAPSTtN4XPIb6OcSSLrosz6hyZoCSVy-uSaR2lYBguwVbSzt9mOtehb37jtGLYzLONCTDOQBSpV3sSo3EJR-Ioxzm2CgQf5G2H-MHUzapzPu_cyNDmWc7zfE-unVw1m6zcvkJsxkEUshxc8xaqjPCRGqP3xUdc4t9gm1QlIl38HAbaYuw89KmvuV-XJKSMw8DREAg_V8Hq6Wx35pUmFg3OaLBasyZykERHl2rENbZcIYnjyvHLgJI8sNm-b_fXnluyUbSRQws_xc9vEs7m_I3tv_ScLYXRHKRh2w";
const JWKS_E: &str = "AQAB";

fn jwks() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": JWKS_N,
            "e": JWKS_E,
        }]
    })
}

async fn certs() -> axum::Json<Value> {
    axum::Json(jwks())
}

struct Stub {
    base: String,
    task: tokio::task::JoinHandle<()>,
}

impl Stub {
    async fn start() -> Self {
        let router =
            Router::new().route("/realms/{realm}/protocol/openid-connect/certs", get(certs));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the stub JWKS server");
        let base = format!(
            "http://{}",
            listener.local_addr().expect("the stub address")
        );
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self { base, task }
    }

    fn verifier(&self) -> KeycloakVerifier {
        KeycloakVerifier::from_settings(&KeycloakSettings {
            url: self.base.clone(),
            realm: REALM.to_owned(),
            audiences: vec![AUDIENCE.to_owned()],
            allowed_clients: vec![CLIENT.to_owned()],
        })
        .expect("the stub verifier")
    }

    fn issuer(&self) -> String {
        format!("{}/realms/{REALM}", self.base)
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn signing_key() -> EncodingKey {
    let der = base64::engine::general_purpose::STANDARD
        .decode(PRIVATE_KEY_DER_BASE64)
        .expect("the test key DER");
    EncodingKey::from_rsa_der(&der)
}

/// A real RS256 service token for the stub realm, issued to `azp`.
fn service_token(stub: &Stub, azp: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    let now = jsonwebtoken::get_current_timestamp();
    let claims = json!({
        "iss": stub.issuer(),
        "aud": [AUDIENCE, "account"],
        "azp": azp,
        "sub": "service-account-sub",
        "iat": now,
        "exp": now + 300,
    });
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign RS256")
}

// ── the licence authority ────────────────────────────────────────────────────────────────

struct RouteLicence;

fn identity(tenant: &str, licence: &str, kind: SubjectKind) -> LicenseIdentity {
    LicenseIdentity {
        tenant_id: Rfc4122Uuid::parse(tenant).expect("a tenant uuid"),
        license_id: Rfc4122Uuid::parse(licence).expect("a licence uuid"),
        subject: "svc:tenant:mcp".to_owned(),
        subject_kind: Some(kind),
    }
}

impl LicenceAuthority for RouteLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            match token {
                TENANT_TOKEN | PRODUCT_TOKEN => {
                    Ok(identity(TENANT_A, LICENCE_A, SubjectKind::Tenant))
                }
                TENANT_B_TOKEN => Ok(identity(TENANT_B, LICENCE_B, SubjectKind::Tenant)),
                MEMBER_TOKEN => Ok(identity(TENANT_A, LICENCE_A, SubjectKind::Member)),
                PLATFORM_TOKEN => Ok(identity(
                    TENANT_PLATFORM,
                    PLATFORM_LICENCE,
                    SubjectKind::Tenant,
                )),
                _ => Err(AuthError::Unauthorized),
            }
        })
    }

    fn authenticate_for_app<'a>(
        &'a self,
        token: &'a str,
        app_key: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            if app_key != GATEWAY_APP_KEY {
                return Err(AuthError::Unauthorized);
            }
            match token {
                PRODUCT_TOKEN => Ok(identity(TENANT_A, LICENCE_A, SubjectKind::Tenant)),
                TENANT_B_TOKEN => Ok(identity(TENANT_B, LICENCE_B, SubjectKind::Tenant)),
                MEMBER_TOKEN => Ok(identity(TENANT_A, LICENCE_A, SubjectKind::Member)),
                PLATFORM_TOKEN => Ok(identity(
                    TENANT_PLATFORM,
                    PLATFORM_LICENCE,
                    SubjectKind::Tenant,
                )),
                _ => Err(AuthError::Unauthorized),
            }
        })
    }
}

// ── the service's collaborators ─────────────────────────────────────────────────────────

fn platform() -> AuthorityId {
    AuthorityId::new(TENANT_PLATFORM).expect("the platform tenant")
}

/// The same tenant as the licence-style identity the builder runtime carries.
fn platform_identity() -> Rfc4122Uuid {
    Rfc4122Uuid::parse(TENANT_PLATFORM).expect("the platform tenant")
}

fn secret_key() -> [u8; 32] {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/phase5a/oracle.json"
    );
    let text = std::fs::read_to_string(path).expect("the phase-5A fixture file exists");
    let document: Value = serde_json::from_str(&text).expect("the phase-5A fixture file is JSON");
    let bytes: Vec<u8> = document["sealing_keys"]["other"]
        .as_array()
        .expect("the fixture carries the sealing key")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("a byte")).expect("a byte"))
        .collect();
    bytes.try_into().expect("a 32-byte key")
}

/// The same sealing key in the configured text form (`MCP_SOURCE_SECRET_KEY`, base64url).
fn source_secret_key() -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_key())
}

fn draft_settings() -> DraftRunSettings {
    DraftRunSettings {
        execution_enabled: true,
        platform_tenant_id: platform(),
        license_app_key: Some(GATEWAY_APP_KEY.to_owned()),
        approved_runner_images: vec![DIGEST.to_owned()],
        sync_wait: Duration::ZERO,
        queue_global_max: 100,
        queue_per_tenant_max: 20,
        run_queue_timeout: Duration::from_secs(240),
        run_max: Duration::from_secs(60),
        max_api_calls_per_run: 10,
        test_runs_per_hour: 60,
    }
}

/// The document fetch seam: the reference's `DocumentFetcher` protocol, answered from a fixture.
struct BodyFetcher(Vec<u8>);

#[async_trait]
impl DocumentFetcher for BodyFetcher {
    async fn fetch_document(
        &self,
        _source: &ResolvedSource,
        _path: &str,
        _max_bytes: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        Ok(self.0.clone())
    }
}
