//! The tenant builder application service against a real Postgres 18: every `/mcp/builder*`
//! operation at the service level, the disabled-builder refusal, the quota refusals, the spec
//! fetch (accepted through a stub server, refused by the real egress policy) and a draft test
//! run going through `submit_draft`.
//!
//! Every test drives the real repositories over the migrated schema from `tests/support`; each
//! test gets its own fresh database, dropped at the end. The document-fetch seam is the
//! reference's `DocumentFetcher` protocol: the acceptance case runs a real stub HTTP server, the
//! refusal case runs the production [`PinnedEgressFetcher`] with a resolver whose answer the
//! real address predicate refuses (so the refusal happens before any I/O).

mod support;

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::routing::get;
use serde_json::{Value, json};
use sqlx::Row;

use mcp_server_rs::auth::{AuthorPrincipal, Rfc4122Uuid};
use mcp_server_rs::builder::models::{
    BindRequest, ImportRequest, OperationPatch, SpecFetchRequest, SpecPath, ToolCreate,
    ToolPublishRequest, ToolTestRequest, ToolUpdate, ToolkitPublishRequest, ToolkitRequest,
};
use mcp_server_rs::builder::service::{
    BuilderError, BuilderService, BuilderServiceDependencies, DocumentFetcher, FetchError,
    PinnedEgressFetcher,
};
use mcp_server_rs::builder::spec::digest;
use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{
    Attribution, OperationManifest, ServiceManifest, ToolManifest,
};
use mcp_server_rs::catalog::package::PackageFile;
use mcp_server_rs::catalog::service::CatalogService;
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::config::{BindingEnsureSettings, BuilderSettings, PackageLimits};
use mcp_server_rs::sources::models::{
    RevisionOnly, SourceStatus, TenantSourceCreate, TenantSourceUpdate, TokenUpdate,
};
use mcp_server_rs::sources::tenant_repository::{TenantSourceRepository, TenantSourceSettings};
use mcp_server_rs::storage::bindings_ensure::BindingEnsureService;
use mcp_server_rs::storage::builder::{BuilderCatalogRepository, DraftRunSettings};
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::worker::broker::auth::AuthAdapters;
use mcp_server_rs::worker::broker::egress::{EgressPolicy, PoolLimits, Resolver};
use mcp_server_rs::worker::sources::{ResolvedSource, SourceRegistry};

use support::Fixture;

const TENANT_A: &str = support::TENANT_A;
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENSE: &str = support::LICENCE_ID;
const PLATFORM: &str = support::TENANT_PLATFORM;
const BASE_URL: &str = "https://api.example.test";
const SERVICE_ID: &str = "01900000-0000-7000-8000-0000000000a1";
const OPERATION_ID: &str = "01900000-0000-7000-8000-0000000000b1";
/// The runner image the fixture approves (`MCP_APPROVED_RUNNER_IMAGES`).
const DIGEST: &str = "registry.example/runner@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A spec with two importable read operations and stable metadata.
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

fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value).expect("authority identity")
}

fn uuid7(value: &str) -> Uuid7 {
    Uuid7::new(value).expect("uuid7 identity")
}

fn version(value: u32) -> PositiveVersion {
    PositiveVersion::new(u64::from(value)).expect("positive version")
}

fn actor() -> Attribution {
    Attribution {
        subject: "agent-09".to_owned(),
        license_id: Some(authority(LICENSE)),
    }
}

fn author() -> AuthorPrincipal {
    AuthorPrincipal {
        tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("tenant A"),
        license_id: Rfc4122Uuid::parse(LICENSE).expect("licence"),
        subject: "svc:test:mcp".to_owned(),
        via: None,
    }
}

fn other_author() -> AuthorPrincipal {
    AuthorPrincipal {
        tenant_id: Rfc4122Uuid::parse(TENANT_B).expect("tenant B"),
        license_id: Rfc4122Uuid::parse(LICENSE).expect("licence"),
        subject: "svc:test:mcp".to_owned(),
        via: None,
    }
}

fn settings() -> BuilderSettings {
    BuilderSettings {
        enabled: true,
        ..BuilderSettings::default()
    }
}

fn draft_settings() -> DraftRunSettings {
    DraftRunSettings {
        execution_enabled: true,
        platform_tenant_id: authority(PLATFORM),
        license_app_key: Some("synthetic".to_owned()),
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

/// The decoded sealing key from the phase-5A oracle fixture (no key-shaped literal here).
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

fn tenant_sources(fixture: &Fixture, configured: &BuilderSettings) -> TenantSourceRepository {
    TenantSourceRepository::from_settings(
        fixture.pool.clone(),
        &TenantSourceSettings {
            secret_key: Some(secret_key().to_vec()),
            max_sources: configured.max_sources,
            licence_hosts: vec!["api.example.test".to_owned()],
            allowed_ports: configured.allowed_ports.clone(),
            spec_keep: 3,
            spec_max_total_bytes: configured.spec_max_total_bytes_per_tenant,
        },
    )
}

fn registry(fixture: &Fixture) -> SourceRegistry {
    SourceRegistry::new(fixture.pool.clone(), None, Vec::new()).expect("source registry")
}

fn ensure_service(fixture: &Fixture) -> BindingEnsureService {
    BindingEnsureService::new(
        fixture.pool.clone(),
        SelectionResolver {
            platform_tenant_id: authority(PLATFORM),
        },
        Some("synthetic".to_owned()),
        Arc::new(support::TestLicence),
        None,
        &BindingEnsureSettings::default(),
        authority(PLATFORM),
    )
}

/// The service's collaborators, defaulted to a real draft runner and no fetch.
struct Parts {
    fetcher: Option<Arc<dyn DocumentFetcher>>,
    registry: Option<SourceRegistry>,
    ensure: Option<BindingEnsureService>,
    draft: Option<DraftRunSettings>,
}

impl Default for Parts {
    fn default() -> Self {
        Self {
            fetcher: None,
            registry: None,
            ensure: None,
            draft: Some(draft_settings()),
        }
    }
}

fn build_service(fixture: &Fixture, configured: BuilderSettings, parts: Parts) -> BuilderService {
    let sources = tenant_sources(fixture, &configured);
    let dependencies = BuilderServiceDependencies {
        sources,
        builder: BuilderCatalogRepository::new(fixture.pool.clone()),
        catalog: CatalogService::new(
            CatalogRepository::new(fixture.pool.clone()),
            SchemaLimits::default(),
            PackageLimits::default(),
        ),
        resolver: SelectionResolver {
            platform_tenant_id: authority(PLATFORM),
        },
        draft: parts.draft,
        minter: None,
        fetcher: parts.fetcher,
        registry: parts.registry,
        ensure: parts.ensure,
    };
    BuilderService::new(
        fixture.pool.clone(),
        configured,
        SchemaLimits::default(),
        vec![DIGEST.to_owned()],
        dependencies,
    )
}

// ── request builders ────────────────────────────────────────────────────────────────────────

fn source_body(
    key: &str,
    auth: Value,
    token: Option<&str>,
    spec_path: Option<&str>,
) -> TenantSourceCreate {
    let mut body = json!({"source_key": key, "base_url": BASE_URL, "auth": auth});
    if let Some(token) = token {
        body["token"] = json!(token);
    }
    if let Some(path) = spec_path {
        body["spec_path"] = json!(path);
    }
    serde_json::from_value(body).expect("a valid tenant source create")
}

fn update_body(expected_revision: u64) -> TenantSourceUpdate {
    serde_json::from_value(json!({
        "base_url": BASE_URL,
        "auth": {"kind": "static_bearer"},
        "expected_revision": expected_revision,
    }))
    .expect("a valid tenant source update")
}

fn secret_body(token: &str, expected_revision: u64) -> TokenUpdate {
    serde_json::from_value(json!({"token": token, "expected_revision": expected_revision}))
        .expect("a valid token update")
}

fn spec_request(path: &str) -> SpecFetchRequest {
    SpecFetchRequest {
        path: Some(SpecPath::new(path).expect("a valid spec path")),
    }
}

fn tool_body(public_name: &str, effect: &str) -> ToolCreate {
    serde_json::from_value(json!({
        "public_name": public_name,
        "operation": "customer.find",
        "description": "Find a customer",
        "files": [{"path": "tool.py", "content": "async def main(inputs, ctx):\n    return {}\n"}],
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "effect": effect,
        "ops": [{"op_key": "get_customer", "source_key": "billing"}],
    }))
    .expect("a valid tool create")
}

fn service_manifest() -> ServiceManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "service_id": SERVICE_ID,
        "version": 1,
        "service_key": "builder_service",
        "destination_alias": "billing",
        "auth_adapter": "source",
        "credential_profile_key": "billing",
        "max_request_bytes": 1048576,
        "max_response_bytes": 10485760,
    }))
    .expect("a valid service manifest")
}

fn operation_manifest() -> OperationManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "operation_id": OPERATION_ID,
        "version": 1,
        "service": {"id": SERVICE_ID, "version": 1},
        "method": "GET",
        "path_template": "/customers",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "mappings": [],
        "effect": "read_only",
        "timeout_seconds": 30,
        "pagination_limit": 100,
        "max_response_bytes": 4096,
    }))
    .expect("a valid operation manifest")
}

fn external_tool(tenant: &str, tool_id: &str) -> ToolManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "tool_id": tool_id,
        "tenant_id": tenant,
        "version": 1,
        "public_name": "workflow_tool",
        "operation": "synthetic.workflow",
        "description": "A workflow tool",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "effect": "read_only",
        "allowed_operations": [{"id": OPERATION_ID, "version": 1}],
    }))
    .expect("a valid external tool manifest")
}

/// A tenant with an active source, its service and one draft operation: everything a tool pins.
async fn seed_tenant(
    fixture: &Fixture,
    configured: BuilderSettings,
    parts: Parts,
) -> BuilderService {
    let service = build_service(fixture, configured, parts);
    let author = author();
    service
        .source_create(
            &author,
            &source_body(
                "billing",
                json!({"kind": "none"}),
                None,
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("create the billing source");
    let builder = BuilderCatalogRepository::new(fixture.pool.clone());
    builder
        .create_service(&authority(TENANT_A), &service_manifest(), &actor())
        .await
        .expect("create the service");
    builder
        .create_operation(
            &authority(TENANT_A),
            &operation_manifest(),
            &actor(),
            Some("get_customer"),
            300,
        )
        .await
        .expect("create the operation");
    service
}

async fn cached_spec(fixture: &Fixture, key: &str, sha: &str) {
    let sources = tenant_sources(fixture, &settings());
    let document: Value = serde_json::from_str(SPEC).expect("the spec is JSON");
    sources
        .put_spec(&authority(TENANT_A), key, sha, &document, SPEC.len() as i32)
        .await
        .expect("cache the spec");
}

// ── fetch stubs ────────────────────────────────────────────────────────────────────────────

/// The acceptance case's fetcher: a real GET against the test's stub server.
struct StubServerFetcher {
    base: String,
    client: reqwest::Client,
}

#[async_trait]
impl DocumentFetcher for StubServerFetcher {
    async fn fetch_document(
        &self,
        _source: &ResolvedSource,
        path: &str,
        max_bytes: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        let response = self
            .client
            .get(format!("{}{}", self.base, path))
            .send()
            .await
            .map_err(|_| FetchError::Failed("OSError"))?;
        if !response.status().is_success() {
            return Err(FetchError::Failed("ValueError"));
        }
        let bytes = response
            .bytes()
            .await
            .map_err(|_| FetchError::Failed("OSError"))?;
        if bytes.len() > max_bytes {
            return Err(FetchError::Failed("ValueError"));
        }
        Ok(bytes.to_vec())
    }
}

struct DeniedFetcher;

#[async_trait]
impl DocumentFetcher for DeniedFetcher {
    async fn fetch_document(
        &self,
        _source: &ResolvedSource,
        _path: &str,
        _max_bytes: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        Err(FetchError::Denied)
    }
}

struct FailedFetcher(FetchError);

#[async_trait]
impl DocumentFetcher for FailedFetcher {
    async fn fetch_document(
        &self,
        _source: &ResolvedSource,
        _path: &str,
        _max_bytes: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        Err(self.0)
    }
}

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

async fn stub_server() -> String {
    let body = SPEC.to_owned();
    let app = Router::new().route(
        "/openapi.json",
        get(move || {
            let body = body.clone();
            async move { ([("content-type", "application/json")], body) }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind the stub server");
    let address = listener.local_addr().expect("stub address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    format!("http://{address}")
}

/// A resolver whose answer the real address predicate refuses (a private address).
struct PrivateResolver;

#[async_trait]
impl Resolver for PrivateResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Vec<IpAddr> {
        vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))]
    }
}

fn refused<T>(result: Result<T, BuilderError>) -> BuilderError {
    match result {
        Ok(_) => panic!("expected a builder refusal"),
        Err(error) => error,
    }
}

// ── sources ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sources_are_created_read_updated_rotated_and_toggled() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings(), Parts::default());
    let author = author();

    let created = service
        .source_create(
            &author,
            &source_body(
                "billing",
                json!({"kind": "static_bearer"}),
                Some("source-token"),
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("create the source");
    assert_eq!(created["source_key"], "billing");
    assert_eq!(created["revision"], 1);
    assert_eq!(created["status"], "active");
    assert_eq!(created["has_token"], true);
    assert!(created["token_set_at"].is_string());
    assert!(
        created.get("token").is_none(),
        "a source view never carries the secret"
    );

    let listed = service
        .source_list(&author, 50, 0)
        .await
        .expect("list sources");
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    assert_eq!(listed["limit"], 50);
    assert_eq!(listed["offset"], 0);

    let got = service
        .source_get(&author, "billing")
        .await
        .expect("read the source");
    assert_eq!(got["source_key"], "billing");

    let updated = service
        .source_update(&author, "billing", &update_body(1))
        .await
        .expect("update the source");
    assert_eq!(updated["revision"], 2);
    assert_eq!(
        updated["has_token"], true,
        "an omitted token keeps the stored one"
    );

    let rotated = service
        .source_set_secret(&author, "billing", &secret_body("second-token", 2))
        .await
        .expect("rotate the secret");
    assert_eq!(rotated["revision"], 3);

    let disabled = service
        .source_set_status(
            &author,
            "billing",
            &RevisionOnly {
                expected_revision: 3,
            },
            SourceStatus::Disabled,
        )
        .await
        .expect("disable the source");
    assert_eq!(disabled["revision"], 4);
    assert_eq!(disabled["status"], "disabled");

    let enabled = service
        .source_set_status(
            &author,
            "billing",
            &RevisionOnly {
                expected_revision: 4,
            },
            SourceStatus::Active,
        )
        .await
        .expect("enable the source");
    assert_eq!(enabled["revision"], 5);
    assert_eq!(enabled["status"], "active");

    // Another tenant reads nothing of it.
    let error = refused(service.source_get(&other_author(), "billing").await);
    assert_eq!(error.to_string(), "source not found");
    assert_eq!(error.status(), 404);
    assert_eq!(error.code(), "not_found");

    fixture.finish().await;
}

#[tokio::test]
async fn usage_reports_the_four_counts_and_limits() {
    let fixture = Fixture::new().await;
    let service = seed_tenant(&fixture, settings(), Parts::default()).await;
    let usage = service.usage(&author()).await.expect("usage");
    assert_eq!(usage["used"]["sources"], 1);
    assert_eq!(usage["used"]["operations"], 1);
    assert_eq!(usage["used"]["tools"], 0);
    assert_eq!(usage["used"]["toolkits"], 0);
    assert_eq!(usage["limits"]["sources"], 20);
    assert_eq!(usage["limits"]["operations"], 300);
    assert_eq!(usage["limits"]["tools"], 50);
    assert_eq!(usage["limits"]["toolkits"], 10);

    service
        .tool_create(&author(), &tool_body("first_tool", "read_only"))
        .await
        .expect("create a tool");
    let usage = service.usage(&author()).await.expect("usage");
    assert_eq!(usage["used"]["tools"], 1);
    fixture.finish().await;
}

// ── specs ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn spec_fetch_accepts_a_stub_server_and_stores_the_document_by_digest() {
    mcp_server_rs::install_crypto_provider();
    let fixture = Fixture::new().await;
    let base = stub_server().await;
    let fetcher: Arc<dyn DocumentFetcher> = Arc::new(StubServerFetcher {
        base,
        client: reqwest::Client::new(),
    });
    let mut configured = settings();
    // The fetch window is one: the second fetch in this test must be rate-limited.
    configured.spec_fetches_per_hour = 1;
    let source_settings = configured.clone();
    let service = build_service(
        &fixture,
        configured,
        Parts {
            fetcher: Some(fetcher),
            registry: Some(registry(&fixture)),
            ..Parts::default()
        },
    );
    let author = author();
    service
        .source_create(
            &author,
            &source_body(
                "billing",
                json!({"kind": "none"}),
                None,
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("create the source");

    let fetched = service
        .spec_fetch(&author, "billing", &SpecFetchRequest { path: None })
        .await
        .expect("fetch the spec");
    let sha = digest(SPEC.as_bytes());
    assert_eq!(fetched["sha256"], sha);
    assert_eq!(fetched["bytes"], SPEC.len());
    assert_eq!(fetched["title"], "Billing");
    assert_eq!(fetched["version"], "1.2");
    let operations = fetched["operations"].as_array().expect("operations");
    assert_eq!(operations.len(), 2);
    assert_eq!(operations[0]["method"], "GET");
    assert_eq!(operations[0]["operationId"], "list_items");
    assert_eq!(operations[0]["importable"], true);

    // The document is stored by digest and the stored view reads it back.
    let sources = tenant_sources(&fixture, &source_settings);
    let stored = sources
        .get_spec(&authority(TENANT_A), "billing", Some(&sha))
        .await
        .expect("read the cached spec")
        .expect("the fetched document is cached");
    assert_eq!(stored.bytes, SPEC.len() as i32);
    assert_eq!(stored.document["info"]["title"], "Billing");

    let shown = service
        .spec_operations(&author, "billing", &sha)
        .await
        .expect("read the cached operations");
    assert_eq!(shown["sha256"], sha);
    assert_eq!(shown["fetched_at"], stored.fetched_at);
    assert_eq!(shown["operations"].as_array().expect("operations").len(), 2);

    let error = refused(
        service
            .spec_operations(&author, "billing", &"c".repeat(64))
            .await,
    );
    assert_eq!(error.to_string(), "spec not found; fetch it first");
    assert_eq!(error.code(), "not_found");

    // One fetch per hour was configured; the second is the rate-limit refusal.
    let error = refused(
        service
            .spec_fetch(&author, "billing", &SpecFetchRequest { path: None })
            .await,
    );
    assert_eq!(error.to_string(), "too many spec fetches this hour");
    assert_eq!(error.status(), 429);
    assert_eq!(error.code(), "rate_limited");

    fixture.finish().await;
}

#[tokio::test]
async fn spec_fetch_refusals_keep_the_reference_messages() {
    mcp_server_rs::install_crypto_provider();
    let fixture = Fixture::new().await;
    let author = author();

    // Without a fetcher or a registry the feature is unavailable.
    let unavailable = build_service(&fixture, settings(), Parts::default());
    unavailable
        .source_create(
            &author,
            &source_body(
                "billing",
                json!({"kind": "none"}),
                None,
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("create the source");
    let error = refused(
        unavailable
            .spec_fetch(&author, "billing", &SpecFetchRequest { path: None })
            .await,
    );
    assert_eq!(error.to_string(), "spec fetching is not available");
    assert_eq!(error.status(), 503);
    assert_eq!(error.code(), "builder_unavailable");

    // A disabled source is refused before any fetch is attempted.
    unavailable
        .source_set_status(
            &author,
            "billing",
            &RevisionOnly {
                expected_revision: 1,
            },
            SourceStatus::Disabled,
        )
        .await
        .expect("disable the source");
    let error = refused(
        unavailable
            .spec_fetch(&author, "billing", &SpecFetchRequest { path: None })
            .await,
    );
    assert_eq!(error.to_string(), "the source is disabled");
    assert_eq!(error.code(), "revision_or_lifecycle_conflict");

    // A source with no spec_path and no explicit path names what is missing.
    let denied: Arc<dyn DocumentFetcher> = Arc::new(DeniedFetcher);
    let service = build_service(
        &fixture,
        settings(),
        Parts {
            fetcher: Some(denied),
            registry: Some(registry(&fixture)),
            ..Parts::default()
        },
    );
    service
        .source_create(
            &author,
            &source_body("plain", json!({"kind": "none"}), None, None),
        )
        .await
        .expect("create the plain source");
    let error = refused(
        service
            .spec_fetch(&author, "plain", &SpecFetchRequest { path: None })
            .await,
    );
    assert_eq!(
        error.to_string(),
        "the source has no spec_path; pass a path"
    );
    assert_eq!(error.status(), 422);
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(
        error.detail(),
        Some("the source has no spec_path; pass a path")
    );

    // A fetcher denial is the reference's "not reachable" upstream error.
    let error = refused(
        service
            .spec_fetch(&author, "plain", &spec_request("/openapi.json"))
            .await,
    );
    assert_eq!(
        error.to_string(),
        "the source is not reachable: it was refused by the egress policy, is disabled or its \
         credential is unavailable"
    );
    assert_eq!(error.status(), 502);
    assert_eq!(error.code(), "upstream_failed");

    // A fetch failure reports the reference's exception class.
    let failing: Arc<dyn DocumentFetcher> =
        Arc::new(FailedFetcher(FetchError::Failed("ValueError")));
    let failing_service = build_service(
        &fixture,
        settings(),
        Parts {
            fetcher: Some(failing),
            registry: Some(registry(&fixture)),
            ..Parts::default()
        },
    );
    let error = refused(
        failing_service
            .spec_fetch(&author, "plain", &spec_request("/openapi.json"))
            .await,
    );
    assert_eq!(
        error.to_string(),
        "spec fetch failed (ValueError): check the base_url, spec path, the source credential \
         and that the document is JSON under the size limit"
    );

    // A body that parses as bytes but is not JSON is the input refusal.
    let yaml: Arc<dyn DocumentFetcher> = Arc::new(BodyFetcher(b"openapi: 3.1.0\n".to_vec()));
    let yaml_service = build_service(
        &fixture,
        settings(),
        Parts {
            fetcher: Some(yaml),
            registry: Some(registry(&fixture)),
            ..Parts::default()
        },
    );
    let error = refused(
        yaml_service
            .spec_fetch(&author, "plain", &spec_request("/openapi.json"))
            .await,
    );
    assert_eq!(
        error.to_string(),
        "the spec is not JSON (YAML is not supported); serve the OpenAPI document as JSON"
    );
    assert_eq!(error.code(), "invalid_request");

    fixture.finish().await;
}

#[tokio::test]
async fn spec_fetch_is_refused_by_the_egress_policy() {
    mcp_server_rs::install_crypto_provider();
    let fixture = Fixture::new().await;
    let policy = Arc::new(
        EgressPolicy::new(&[443], &[], Arc::new(PrivateResolver)).expect("a valid egress policy"),
    );
    let fetcher: Arc<dyn DocumentFetcher> = Arc::new(PinnedEgressFetcher::new(
        policy,
        PoolLimits::default(),
        AuthAdapters::new(
            reqwest::Client::new(),
            reqwest::Client::new(),
            Duration::from_secs(60),
        ),
        None,
    ));
    let service = build_service(
        &fixture,
        settings(),
        Parts {
            fetcher: Some(fetcher),
            registry: Some(registry(&fixture)),
            ..Parts::default()
        },
    );
    let author = author();
    let mut body = serde_json::to_value(source_body(
        "billing",
        json!({"kind": "none"}),
        None,
        Some("/openapi.json"),
    ))
    .expect("source body json");
    body["base_url"] = json!("https://tenant.example.com");
    let body: TenantSourceCreate = serde_json::from_value(body).expect("a valid source");
    service
        .source_create(&author, &body)
        .await
        .expect("create the source");

    let error = refused(
        service
            .spec_fetch(&author, "billing", &SpecFetchRequest { path: None })
            .await,
    );
    // The resolver answered a private address; the real predicate refused it before any I/O,
    // and the service reports the reference's "not reachable" upstream error.
    assert_eq!(error.status(), 502);
    assert_eq!(error.code(), "upstream_failed");
    assert_eq!(
        error.to_string(),
        "the source is not reachable: it was refused by the egress policy, is disabled or its \
         credential is unavailable"
    );
    fixture.finish().await;
}

// ── operations ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn operations_import_list_and_update() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings(), Parts::default());
    let author = author();
    service
        .source_create(
            &author,
            &source_body(
                "billing",
                json!({"kind": "none"}),
                None,
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("create the source");
    let sha = "a".repeat(64);
    cached_spec(&fixture, "billing", &sha).await;

    let body: ImportRequest = serde_json::from_value(json!({
        "spec_sha256": sha,
        "select": ["list_items", "list_widgets"],
        "overrides": {"list_items": {"timeout_seconds": 60}},
    }))
    .expect("a valid import request");
    let imported = service
        .operations_import(&author, "billing", &body)
        .await
        .expect("import the operations");
    assert_eq!(imported["source_key"], "billing");
    let done = imported["imported"].as_array().expect("imported");
    assert_eq!(done.len(), 2);
    let items = done
        .iter()
        .find(|entry| entry["op_key"] == "list_items")
        .expect("the list_items operation");
    assert_eq!(items["method"], "GET");
    assert_eq!(items["path"], "/items");
    assert_eq!(items["effect"], "read_only");
    assert_eq!(items["version"], 1);

    // The service was created on first use and the imported operations are listed.
    let builder = BuilderCatalogRepository::new(fixture.pool.clone());
    assert!(
        builder
            .service_for_source(&authority(TENANT_A), "billing")
            .await
            .expect("read the service")
            .is_some(),
        "the import ensures the source's service"
    );
    let listed = service
        .operation_list(&author, "billing")
        .await
        .expect("list the operations");
    let operations = listed["operations"].as_array().expect("operations");
    assert_eq!(operations.len(), 2);
    let keys: Vec<&str> = operations
        .iter()
        .map(|entry| entry["op_key"].as_str().expect("an op key"))
        .collect();
    assert_eq!(keys, ["list_items", "list_widgets"]);
    let list_items = operations
        .iter()
        .find(|entry| entry["op_key"] == "list_items")
        .expect("list_items");
    assert_eq!(list_items["timeout_seconds"], 60);
    assert_eq!(list_items["idempotency"], "none");
    assert_eq!(list_items["status"], "draft");
    let list_widgets = operations
        .iter()
        .find(|entry| entry["op_key"] == "list_widgets")
        .expect("list_widgets");
    assert_eq!(list_widgets["timeout_seconds"], 10);

    // A re-import of a key adds a version.
    let reimported = service
        .operations_import(&author, "billing", &body)
        .await
        .expect("re-import");
    for entry in reimported["imported"].as_array().expect("imported") {
        assert_eq!(entry["version"], 2);
    }

    // The patch replaces present fields only; a stale expected version is the reference's
    // conflict.
    let patch: OperationPatch = serde_json::from_value(json!({
        "expected_version": 2,
        "effect": "writes",
        "timeout_seconds": 45,
    }))
    .expect("a valid operation patch");
    let updated = service
        .operation_update(&author, "billing", "list_items", &patch)
        .await
        .expect("update the operation");
    assert_eq!(updated["version"], 3);
    assert_eq!(updated["effect"], "writes");
    assert_eq!(updated["timeout_seconds"], 45);
    // Fields the patch omitted keep the newest version's value.
    assert_eq!(updated["path_template"], "/items");

    let stale: OperationPatch = serde_json::from_value(json!({
        "expected_version": 1,
        "effect": "read_only",
    }))
    .expect("a valid operation patch");
    let error = refused(
        service
            .operation_update(&author, "billing", "list_items", &stale)
            .await,
    );
    assert_eq!(error.to_string(), "the operation changed; re-read it");
    assert_eq!(error.code(), "revision_or_lifecycle_conflict");

    // An unknown spec digest is the not-found refusal.
    let unknown: ImportRequest = serde_json::from_value(json!({
        "spec_sha256": "d".repeat(64),
        "select": ["list_items"],
    }))
    .expect("a valid import request");
    let error = refused(
        service
            .operations_import(&author, "billing", &unknown)
            .await,
    );
    assert_eq!(error.to_string(), "spec not found; fetch it first");

    // Another tenant sees neither the source nor its service.
    let error = refused(service.operation_list(&other_author(), "billing").await);
    assert_eq!(error.to_string(), "source not found");

    fixture.finish().await;
}

// ── tools ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tool_lifecycle_end_to_end() {
    let fixture = Fixture::new().await;
    let service = seed_tenant(&fixture, settings(), Parts::default()).await;
    let author = author();

    let created = service
        .tool_create(&author, &tool_body("find_customer", "read_only"))
        .await
        .expect("create the tool");
    assert_eq!(created["version"], 1);
    assert_eq!(created["revision"], 1);
    assert_eq!(created["status"], "draft");
    assert_eq!(created["manifest"]["runtime"], "kata_python");
    assert_eq!(created["manifest"]["runner_image_digest"], DIGEST);
    // The host files are regenerated and never returned as the author's.
    let files = created["files"].as_array().expect("files");
    assert_eq!(files.len(), 1);
    assert_eq!(files[0]["path"], "tool.py");
    assert_eq!(created["ops"], json!(["billing.get_customer"]));
    let tool_id = uuid7(created["tool_id"].as_str().expect("a tool id"));

    let newest = service
        .tool_get(&author, &tool_id, None)
        .await
        .expect("read the newest version");
    assert_eq!(newest["version"], 1);
    let listed = service.tool_list(&author, 50, 0).await.expect("list tools");
    assert_eq!(listed["items"].as_array().expect("items").len(), 1);
    assert_eq!(listed["items"][0]["tool_id"], tool_id.as_str());

    let append: ToolUpdate = serde_json::from_value(json!({
        "expected_revision": 1,
        "description": "Find a customer by name",
    }))
    .expect("a valid tool update");
    let appended = service
        .tool_update(&author, &tool_id, &append)
        .await
        .expect("append a tool version");
    assert_eq!(appended["version"], 2);
    assert_eq!(appended["revision"], 2);
    assert_eq!(
        appended["manifest"]["description"],
        "Find a customer by name"
    );
    // The stored package's operations are re-pinned when the update names none.
    assert_eq!(appended["ops"], json!(["billing.get_customer"]));
    assert_eq!(
        service.tool_list(&author, 50, 0).await.expect("list tools")["items"]
            .as_array()
            .expect("items")
            .len(),
        2
    );
    let first = service
        .tool_get(&author, &tool_id, Some(version(1)))
        .await
        .expect("read version one");
    assert_eq!(first["version"], 1);
    assert_eq!(first["manifest"]["description"], "Find a customer");

    // Publishing the tool also publishes the draft service and operation it pins.
    let publish: ToolPublishRequest =
        serde_json::from_value(json!({"expected_revision": 2})).expect("a valid publish");
    let published = service
        .tool_publish(&author, &tool_id, version(2), &publish)
        .await
        .expect("publish the tool");
    assert_eq!(published["status"], "published");
    assert_eq!(published["revision"], 3);
    let service_status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_service_versions WHERE service_id=$1::uuid AND version=1",
    )
    .bind(SERVICE_ID)
    .fetch_one(&fixture.pool)
    .await
    .expect("service status");
    assert_eq!(service_status, "published");
    let operation_status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_operation_versions \
         WHERE operation_id=$1::uuid AND version=1",
    )
    .bind(OPERATION_ID)
    .fetch_one(&fixture.pool)
    .await
    .expect("operation status");
    assert_eq!(operation_status, "published");

    let disabled = service
        .tool_set_status(
            &author,
            &tool_id,
            version(2),
            VersionStatus::Disabled,
            version(3),
        )
        .await
        .expect("disable the tool version");
    assert_eq!(disabled["status"], "disabled");
    assert_eq!(disabled["revision"], 4);
    let retired = service
        .tool_set_status(
            &author,
            &tool_id,
            version(2),
            VersionStatus::Retired,
            version(4),
        )
        .await
        .expect("retire the tool version");
    assert_eq!(retired["status"], "retired");

    // An external runtime has no authored package to edit.
    let external_id = "01900000-0000-7000-8000-0000000000c9";
    BuilderCatalogRepository::new(fixture.pool.clone())
        .create_tool(
            &authority(TENANT_A),
            &external_tool(TENANT_A, external_id),
            // The schema requires at least one package file even for an external runtime;
            // what makes it "external" is its runtime and target, not an empty package.
            &[PackageFile {
                path: "tool.py".to_owned(),
                content: "def run(inputs):\n    return inputs\n".to_owned(),
            }],
            &actor(),
            50,
        )
        .await
        .expect("seed an external tool");
    let error = refused(
        service
            .tool_update(
                &author,
                &uuid7(external_id),
                &serde_json::from_value(json!({"expected_revision": 1}))
                    .expect("a valid tool update"),
            )
            .await,
    );
    assert_eq!(error.to_string(), "only kata_python tools can be edited");
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(error.detail(), Some("only kata_python tools can be edited"));

    // Another tenant reads nothing of the tool.
    let error = refused(
        service
            .tool_get(&other_author(), &tool_id, Some(version(2)))
            .await,
    );
    assert_eq!(error.to_string(), "tenant-owned version not found");

    fixture.finish().await;
}

#[tokio::test]
async fn tool_test_runs_through_submit_draft() {
    let fixture = Fixture::new().await;
    let service = seed_tenant(&fixture, settings(), Parts::default()).await;
    let author = author();
    let created = service
        .tool_create(&author, &tool_body("find_customer", "read_only"))
        .await
        .expect("create the tool");
    let tool_id = uuid7(created["tool_id"].as_str().expect("a tool id"));

    let test_body = ToolTestRequest {
        inputs: serde_json::Map::new(),
        confirm_writes: false,
    };
    let view = service
        .tool_test(&author, &tool_id, version(1), &test_body)
        .await
        .expect("submit a draft run");
    assert_eq!(view["mode"], "draft");
    assert_eq!(view["status"], "queued");
    assert_eq!(view["trace"], json!([]));
    let run_id = uuid7(view["run_id"].as_str().expect("a run id"));

    // The run went through `submit_draft`: one draft row, no binding, the caller's licence.
    let row = sqlx::query(
        "SELECT mode, binding_id::text AS binding_id, tool_id::text AS tool_id, tool_version, \
         gateway_license_id::text AS gateway_license_id FROM public.mcp_runs \
         WHERE tenant_id=$1::uuid AND run_id=$2::uuid",
    )
    .bind(TENANT_A)
    .bind(run_id.as_str())
    .fetch_one(&fixture.pool)
    .await
    .expect("the draft run row");
    assert_eq!(row.try_get::<String, _>("mode").expect("mode"), "draft");
    assert_eq!(
        row.try_get::<Option<String>, _>("binding_id")
            .expect("binding"),
        None
    );
    assert_eq!(
        row.try_get::<String, _>("tool_id").expect("tool"),
        tool_id.as_str()
    );
    assert_eq!(row.try_get::<i32, _>("tool_version").expect("version"), 1);
    assert_eq!(
        row.try_get::<String, _>("gateway_license_id")
            .expect("licence"),
        LICENSE
    );

    let shown = service
        .run_get(&author, &run_id)
        .await
        .expect("read the draft run");
    assert_eq!(shown["run_id"], run_id.as_str());
    assert_eq!(shown["mode"], "draft");
    assert_eq!(shown["trace"], json!([]));

    // The per-hour window is the service's pre-check. One run already exists for this tenant,
    // so a limit of two admits one more and then refuses.
    let mut limited = settings();
    limited.test_runs_per_hour = 2;
    let mut limited_draft = draft_settings();
    limited_draft.test_runs_per_hour = 2;
    let limited_service = build_service(
        &fixture,
        limited,
        Parts {
            draft: Some(limited_draft),
            ..Parts::default()
        },
    );
    limited_service
        .tool_test(&author, &tool_id, version(1), &test_body)
        .await
        .expect("the second run of the hour");
    let error = refused(
        limited_service
            .tool_test(&author, &tool_id, version(1), &test_body)
            .await,
    );
    assert_eq!(error.to_string(), "too many test runs this hour");
    assert_eq!(error.status(), 429);
    assert_eq!(error.code(), "rate_limited");

    // With no execution wiring every test run and run read is unavailable.
    let unwired = build_service(
        &fixture,
        settings(),
        Parts {
            draft: None,
            ..Parts::default()
        },
    );
    let error = refused(
        unwired
            .tool_test(&author, &tool_id, version(1), &test_body)
            .await,
    );
    assert_eq!(
        error.to_string(),
        "test runs are not available: execution is disabled"
    );
    assert_eq!(error.code(), "builder_unavailable");
    let error = refused(unwired.run_get(&author, &run_id).await);
    assert_eq!(error.to_string(), "runs are not available");

    // A writing tool needs the confirmation; the refusal is the 422 without a body message.
    let writes = service
        .tool_create(&author, &tool_body("writing_tool", "writes"))
        .await
        .expect("create the writing tool");
    let writes_id = uuid7(writes["tool_id"].as_str().expect("a tool id"));
    let error = refused(
        service
            .tool_test(&author, &writes_id, version(1), &test_body)
            .await,
    );
    assert_eq!(error.code(), "invalid_request");
    assert_eq!(error.status(), 422);
    assert_eq!(error.detail(), None);
    service
        .tool_test(
            &author,
            &writes_id,
            version(1),
            &ToolTestRequest {
                inputs: serde_json::Map::new(),
                confirm_writes: true,
            },
        )
        .await
        .expect("a confirmed write run");

    fixture.finish().await;
}

// ── toolkits ───────────────────────────────────────────────────────────────────────────────

/// Seed a tenant, create and publish its first tool, and return the service and the tool id.
async fn published_tool(fixture: &Fixture, parts: Parts) -> (BuilderService, Uuid7) {
    let service = seed_tenant(fixture, settings(), parts).await;
    let author = author();
    let created = service
        .tool_create(&author, &tool_body("find_customer", "read_only"))
        .await
        .expect("create the tool");
    let tool_id = uuid7(created["tool_id"].as_str().expect("a tool id"));
    let publish: ToolPublishRequest =
        serde_json::from_value(json!({"expected_revision": 1})).expect("a valid publish");
    service
        .tool_publish(&author, &tool_id, version(1), &publish)
        .await
        .expect("publish the tool");
    (service, tool_id)
}

fn toolkit_body(name: &str, tool_id: &Uuid7) -> ToolkitRequest {
    serde_json::from_value(json!({
        "name": name,
        "description": "A builder toolkit",
        "tools": [{"tool_id": tool_id}],
    }))
    .expect("a valid toolkit request")
}

#[tokio::test]
async fn toolkits_create_append_and_publish_with_a_rebind_report() {
    let fixture = Fixture::new().await;
    let (service, tool_id) = published_tool(&fixture, Parts::default()).await;
    let author = author();

    let created = service
        .toolkit_create(&author, &toolkit_body("builder_toolkit", &tool_id))
        .await
        .expect("create the toolkit");
    assert_eq!(created["manifest"]["version"], 1);
    assert_eq!(created["revision"], 1);
    assert_eq!(created["status"], "draft");
    let toolkit_id = uuid7(
        created["manifest"]["toolkit_id"]
            .as_str()
            .expect("a toolkit id"),
    );

    let mut append = serde_json::to_value(toolkit_body("builder_toolkit", &tool_id))
        .expect("toolkit request json");
    append["toolkit_id"] = json!(toolkit_id);
    append["expected_revision"] = json!(1);
    let append: ToolkitRequest = serde_json::from_value(append).expect("a valid toolkit request");
    let appended = service
        .toolkit_create(&author, &append)
        .await
        .expect("append a toolkit version");
    assert_eq!(appended["manifest"]["version"], 2);
    assert_eq!(appended["revision"], 2);

    let publish: ToolkitPublishRequest =
        serde_json::from_value(json!({"expected_revision": 2})).expect("a valid publish");
    let published = service
        .toolkit_publish(&author, &toolkit_id, version(2), &publish)
        .await
        .expect("publish the toolkit");
    assert_eq!(published["status"], "published");
    assert_eq!(published["revision"], 3);
    // No provisioner is wired: the publication stands and the re-bind is reported.
    assert_eq!(published["bindings"]["error"], "rebind_failed");
    assert_eq!(published["bindings"]["detail"], "call toolkit bind again");

    // Binding without a provisioner is the reference's unavailable refusal.
    let error = refused(
        service
            .rebind(&author, &BindRequest { product: None })
            .await,
    );
    assert_eq!(error.to_string(), "binding provisioning is not available");
    assert_eq!(error.code(), "builder_unavailable");

    // An unpublished tool version cannot be selected.
    let error = refused(
        service
            .toolkit_create(
                &author,
                &serde_json::from_value(json!({
                    "name": "fresh_toolkit",
                    "description": "Another toolkit",
                    "tools": [{"tool_id": tool_id, "version": 99}],
                }))
                .expect("a valid toolkit request"),
            )
            .await,
    );
    assert_eq!(error.to_string(), "tenant-owned version not found");

    fixture.finish().await;
}

#[tokio::test]
async fn toolkit_publish_rebinds_through_the_provisioner() {
    let fixture = Fixture::new().await;
    let parts = Parts {
        ensure: Some(ensure_service(&fixture)),
        ..Parts::default()
    };
    let (service, tool_id) = published_tool(&fixture, parts).await;
    let author = author();
    let created = service
        .toolkit_create(&author, &toolkit_body("bound_toolkit", &tool_id))
        .await
        .expect("create the toolkit");
    let toolkit_id = uuid7(
        created["manifest"]["toolkit_id"]
            .as_str()
            .expect("a toolkit id"),
    );
    let publish: ToolkitPublishRequest =
        serde_json::from_value(json!({"expected_revision": 1})).expect("a valid publish");
    let published = service
        .toolkit_publish(&author, &toolkit_id, version(1), &publish)
        .await
        .expect("publish the toolkit");
    assert_eq!(published["status"], "published");
    // There are no ensure rows yet, so the re-bind reports no products.
    assert_eq!(published["bindings"]["products"], json!([]));

    let rebound = service
        .rebind(&author, &BindRequest { product: None })
        .await
        .expect("rebind");
    assert_eq!(rebound["products"], json!([]));
    fixture.finish().await;
}

// ── quotas and the disabled builder ────────────────────────────────────────────────────────

#[tokio::test]
async fn source_and_operation_quotas_are_refused() {
    let fixture = Fixture::new().await;
    let mut configured = settings();
    configured.max_sources = 1;
    configured.max_operations = 1;
    let service = build_service(&fixture, configured, Parts::default());
    let author = author();
    service
        .source_create(
            &author,
            &source_body(
                "first",
                json!({"kind": "none"}),
                None,
                Some("/openapi.json"),
            ),
        )
        .await
        .expect("first source");
    let error = refused(
        service
            .source_create(
                &author,
                &source_body("second", json!({"kind": "none"}), None, None),
            )
            .await,
    );
    assert_eq!(error.to_string(), "source quota exceeded");
    assert_eq!(error.status(), 409);
    assert_eq!(error.code(), "quota_exceeded");
    assert_eq!(error.resource(), Some("source"));

    // Two selections against a quota of one: the first imports, the second is refused.
    let sha = "a".repeat(64);
    cached_spec(&fixture, "first", &sha).await;
    let body: ImportRequest = serde_json::from_value(json!({
        "spec_sha256": sha,
        "select": ["list_items", "list_widgets"],
    }))
    .expect("a valid import request");
    let error = refused(service.operations_import(&author, "first", &body).await);
    assert_eq!(error.to_string(), "operation quota exceeded");
    assert_eq!(error.code(), "quota_exceeded");
    assert_eq!(error.resource(), Some("operation"));
    // The storage calls own their transactions, so the first operation stays imported.
    assert_eq!(
        service
            .operation_list(&author, "first")
            .await
            .expect("operations")["operations"]
            .as_array()
            .expect("operations")
            .len(),
        1
    );
    fixture.finish().await;
}

#[tokio::test]
async fn tool_and_toolkit_quotas_are_refused() {
    let fixture = Fixture::new().await;
    let mut configured = settings();
    configured.max_tools = 1;
    configured.max_toolkits = 1;
    let service = seed_tenant(&fixture, configured, Parts::default()).await;
    let author = author();
    let created = service
        .tool_create(&author, &tool_body("first_tool", "read_only"))
        .await
        .expect("first tool");
    let tool_id = uuid7(created["tool_id"].as_str().expect("a tool id"));
    let error = refused(
        service
            .tool_create(&author, &tool_body("second_tool", "read_only"))
            .await,
    );
    assert_eq!(error.to_string(), "tools quota exceeded");
    assert_eq!(error.resource(), Some("tools"));

    let publish: ToolPublishRequest =
        serde_json::from_value(json!({"expected_revision": 1})).expect("a valid publish");
    service
        .tool_publish(&author, &tool_id, version(1), &publish)
        .await
        .expect("publish the tool");
    service
        .toolkit_create(&author, &toolkit_body("first_toolkit", &tool_id))
        .await
        .expect("first toolkit");
    let error = refused(
        service
            .toolkit_create(&author, &toolkit_body("second_toolkit", &tool_id))
            .await,
    );
    assert_eq!(error.to_string(), "toolkits quota exceeded");
    assert_eq!(error.resource(), Some("toolkits"));
    fixture.finish().await;
}

#[tokio::test]
async fn a_disabled_builder_refuses_with_the_reference_error() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, BuilderSettings::default(), Parts::default());
    let error = refused(service.ensure_enabled());
    assert_eq!(error.to_string(), "the tool builder is not enabled");
    assert_eq!(error.status(), 503);
    assert_eq!(error.code(), "builder_unavailable");
    assert_eq!(error.detail(), Some("the tool builder is not enabled"));
    fixture.finish().await;
}
