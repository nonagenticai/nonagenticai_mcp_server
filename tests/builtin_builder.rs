//! The builder builtin surface: the 20 `builder_*` tools over the installed [`BuilderService`].
//!
//! The reference's builtin inventory is the contract (the fixture `tests/fixtures/builtin/
//! oracle.json`), so the registry is compared to it name, description and input schema for
//! name. Behaviour runs against a real Postgres 18 through the fixture recipe of
//! `tests/builder_service.rs`: a round trip through the provider proves the tool acts on the
//! same rows the REST surface serves, and each of the reference's refusal classes is checked
//! text for text. The scope half proves a care-bus caller never sees a builder tool and a
//! tenant author sees nothing else; the end-to-end half proves the real `/mcp` transport lists
//! exactly the 20 names for the reference's tenant-author principal.

mod support;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use axum::Router;
use axum::extract::{Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use rmcp::model::CallToolResult;
use serde_json::{Value, json};

use mcp_server_rs::auth::{LicenceFacts, Principal, Rfc4122Uuid, SubjectKind};
use mcp_server_rs::builder::service::{
    BuilderService, BuilderServiceDependencies, DocumentFetcher, FetchError,
};
use mcp_server_rs::builtin::scope::{BuiltinCaller, CallerKind};
use mcp_server_rs::builtin::{BuiltinProvider, create};
use mcp_server_rs::catalog::ids::AuthorityId;
use mcp_server_rs::catalog::service::CatalogService;
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::config::{BuilderSettings, PackageLimits};
use mcp_server_rs::mcp;
use mcp_server_rs::sources::tenant_repository::{TenantSourceRepository, TenantSourceSettings};
use mcp_server_rs::storage::builder::BuilderCatalogRepository;
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::worker::sources::ResolvedSource;

use support::Fixture;

/// The runner image the service pins for a new tool; the tool tests never author one.
const DIGEST: &str = "registry.example/runner@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

// ── the service recipe (the same collaborators `tests/builder_service.rs` builds) ───────────

fn settings() -> BuilderSettings {
    BuilderSettings {
        enabled: true,
        ..BuilderSettings::default()
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

/// The document-fetch seam, stubbed exactly as the reference's `DocumentFetcher` protocol
/// allows: the round trip never fetches, so an empty answer is enough here.
struct StubFetcher;

#[async_trait]
impl DocumentFetcher for StubFetcher {
    async fn fetch_document(
        &self,
        _source: &ResolvedSource,
        _path: &str,
        _max_bytes: usize,
        _timeout: Duration,
    ) -> Result<Vec<u8>, FetchError> {
        Ok(Vec::new())
    }
}

fn build_service(fixture: &Fixture, configured: BuilderSettings) -> Arc<BuilderService> {
    let sources = TenantSourceRepository::from_settings(
        fixture.pool.clone(),
        &TenantSourceSettings {
            secret_key: Some(secret_key().to_vec()),
            max_sources: configured.max_sources,
            licence_hosts: vec!["api.example.test".to_owned()],
            allowed_ports: configured.allowed_ports.clone(),
            spec_keep: 3,
            spec_max_total_bytes: configured.spec_max_total_bytes_per_tenant,
        },
    );
    let dependencies = BuilderServiceDependencies {
        sources,
        builder: BuilderCatalogRepository::new(fixture.pool.clone()),
        catalog: CatalogService::new(
            CatalogRepository::new(fixture.pool.clone()),
            SchemaLimits::default(),
            PackageLimits::default(),
        ),
        resolver: SelectionResolver {
            platform_tenant_id: AuthorityId::new(support::TENANT_PLATFORM)
                .expect("platform tenant"),
        },
        draft: None,
        minter: None,
        fetcher: Some(Arc::new(StubFetcher)),
        registry: None,
        ensure: None,
    };
    Arc::new(BuilderService::new(
        fixture.pool.clone(),
        configured,
        SchemaLimits::default(),
        vec![DIGEST.to_owned()],
        dependencies,
    ))
}

// ── the provider and its callers ────────────────────────────────────────────────────────────

fn tenant_author() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::TenantAuthor,
        subject: format!("svc:{}:mcp", support::TENANT_A),
        scope: "licence:mcp".to_owned(),
        tenant_id: Some(support::TENANT_A.to_owned()),
        license_id: Some(support::LICENCE_ID.to_owned()),
        strata_token: None,
    }
}

/// The reference's tenant-level care-bus licence: the widest non-builder builtin scope.
fn care_bus_licence() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::CarebusLicence,
        subject: format!("svc:{}:care-bus", support::TENANT_A),
        scope: "licence:care-bus".to_owned(),
        tenant_id: Some(support::TENANT_A.to_owned()),
        license_id: None,
        strata_token: None,
    }
}

async fn call(
    provider: &BuiltinProvider,
    caller: &BuiltinCaller,
    name: &str,
    arguments: Value,
) -> CallToolResult {
    provider
        .call(
            caller,
            name,
            arguments
                .as_object()
                .cloned()
                .expect("the arguments are an object"),
        )
        .await
}

/// The tool-error text (the provider's refusal or the tool's own answer).
fn error_text(result: &CallToolResult) -> String {
    assert_eq!(result.is_error, Some(true), "{result:?}");
    result.content[0]
        .as_text()
        .expect("a text block")
        .text
        .clone()
}

fn value(result: &CallToolResult) -> Value {
    assert_eq!(result.is_error, Some(false), "{result:?}");
    result
        .structured_content
        .clone()
        .expect("a structured builder view")
}

fn source_create(source_key: &str) -> Value {
    json!({
        "source_key": source_key,
        "base_url": "https://api.example.test",
        "auth": {"kind": "none"},
        "spec_path": "/openapi.json",
    })
}

// ── the inventory ──────────────────────────────────────────────────────────────────────────

fn oracle() -> Value {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/builtin/oracle.json"
    );
    let text = std::fs::read_to_string(path).expect("the builtin fixture file exists");
    serde_json::from_str(&text).expect("the builtin fixture file is JSON")
}

#[tokio::test]
async fn the_builder_family_is_the_references_inventory() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings());
    let provider = create(fixture.pool.clone(), Some(service));

    let listed = provider.list(&tenant_author());
    assert_eq!(listed.len(), 20, "the family registers all 20 tools");

    let document = oracle();
    let mut expected: Vec<&Value> = document["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter(|tool| {
            tool["name"]
                .as_str()
                .is_some_and(|name| name.starts_with("builder_"))
        })
        .collect();
    expected.sort_by_key(|tool| tool["name"].as_str().expect("name").to_owned());
    assert_eq!(expected.len(), listed.len());

    for (tool, fixture_entry) in listed.iter().zip(expected) {
        let name = fixture_entry["name"].as_str().expect("name");
        assert_eq!(tool.name.as_ref(), name, "the wire name differs");
        assert_eq!(
            tool.description.as_deref(),
            Some(fixture_entry["description"].as_str().expect("description")),
            "{name}: the description differs from the reference's"
        );
        assert_eq!(
            Value::Object((*tool.input_schema).clone()),
            fixture_entry["input_schema"],
            "{name}: the input schema differs from the reference's"
        );
    }
    fixture.finish().await;
}

// ── behaviour over a real Postgres ────────────────────────────────────────────────────────

#[tokio::test]
async fn a_tenant_author_creates_and_lists_a_source_through_the_tools() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings());
    let provider = create(fixture.pool.clone(), Some(service.clone()));
    let caller = tenant_author();

    let created = call(
        &provider,
        &caller,
        "builder_source_create",
        source_create("billing"),
    )
    .await;
    let created = value(&created);
    assert_eq!(created["source_key"], "billing");
    assert_eq!(created["revision"], 1);
    assert_eq!(created["status"], "active");
    assert!(
        created.get("token").is_none(),
        "a source view never carries the secret"
    );

    let listed = call(&provider, &caller, "builder_source_list", json!({})).await;
    let listed = value(&listed);
    let items = listed["items"].as_array().expect("items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["source_key"], "billing");
    assert_eq!(items[0]["spec_path"], "/openapi.json");
    assert_eq!(listed["limit"], 50);
    assert_eq!(listed["offset"], 0);

    // The row the tools wrote is the row the REST service reads back.
    let author = mcp_server_rs::auth::AuthorPrincipal {
        tenant_id: Rfc4122Uuid::parse(support::TENANT_A).expect("tenant"),
        license_id: Rfc4122Uuid::parse(support::LICENCE_ID).expect("licence"),
        subject: "svc:t:mcp".to_owned(),
        via: None,
    };
    let row = service
        .source_get(&author, "billing")
        .await
        .expect("the source row exists");
    assert_eq!(row["source_key"], "billing");
    assert_eq!(row["revision"], 1);
    fixture.finish().await;
}

#[tokio::test]
async fn the_references_refusal_classes_are_the_tools_error_texts() {
    let fixture = Fixture::new().await;
    let configured = BuilderSettings {
        max_sources: 1,
        ..settings()
    };
    let service = build_service(&fixture, configured);
    let provider = create(fixture.pool.clone(), Some(service));
    let caller = tenant_author();

    let created = call(
        &provider,
        &caller,
        "builder_source_create",
        source_create("billing"),
    )
    .await;
    assert_eq!(created.is_error, Some(false), "{created:?}");

    // Quota: the second source exceeds `MCP_BUILDER_MAX_SOURCES` (`QuotaExceededError`'s own
    // text is `<resource> quota exceeded`, and the guard prefixes `quota exceeded: `).
    let quota = call(
        &provider,
        &caller,
        "builder_source_create",
        source_create("second"),
    )
    .await;
    assert_eq!(error_text(&quota), "quota exceeded: source quota exceeded");

    // Not found: an update of a key the tenant does not own.
    let missing = call(
        &provider,
        &caller,
        "builder_source_update",
        json!({
            "source_key": "absent",
            "expected_revision": 1,
            "base_url": "https://api.example.test",
            "auth": {"kind": "none"},
        }),
    )
    .await;
    assert_eq!(error_text(&missing), "not found: source not found");

    // Conflict: a stale optimistic-lock revision.
    let conflict = call(
        &provider,
        &caller,
        "builder_source_update",
        json!({
            "source_key": "billing",
            "expected_revision": 99,
            "base_url": "https://api.example.test",
            "auth": {"kind": "none"},
        }),
    )
    .await;
    assert_eq!(error_text(&conflict), "conflict: source revision mismatch");

    // Invalid: a service `ValueError` (the guard's `invalid: <≤500 chars>` class).
    let invalid = call(
        &provider,
        &caller,
        "builder_source_disable",
        json!({"source_key": "billing", "expected_revision": u64::MAX}),
    )
    .await;
    assert_eq!(error_text(&invalid), "invalid: invalid expected revision");

    // The uuid-argument refusal is its own exact text.
    let identity = call(
        &provider,
        &caller,
        "builder_tool_get",
        json!({"tool_id": "not-a-uuid"}),
    )
    .await;
    assert_eq!(error_text(&identity), "tool_id must be a uuid");
    fixture.finish().await;
}

#[tokio::test]
async fn only_a_tenant_author_sees_the_builder_family() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings());
    let provider = create(fixture.pool.clone(), Some(service));

    let author: Vec<String> = provider
        .list(&tenant_author())
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert_eq!(author.len(), 20);
    assert!(author.iter().all(|name| name.starts_with("builder_")));
    assert!(
        !author
            .iter()
            .any(|name| name.starts_with("legal_") || name.starts_with("crm_")),
        "a tenant author sees no other family"
    );

    let care_bus: Vec<String> = provider
        .list(&care_bus_licence())
        .into_iter()
        .map(|tool| tool.name.to_string())
        .collect();
    assert!(
        !care_bus.iter().any(|name| name.starts_with("builder_")),
        "a care-bus licence never sees the builder: {care_bus:?}"
    );

    // And a care-bus licence cannot call a builder tool even when it names one.
    let denied = call(
        &provider,
        &care_bus_licence(),
        "builder_source_list",
        json!({}),
    )
    .await;
    assert_eq!(
        error_text(&denied),
        "[permanent] tool not permitted for this caller"
    );
    fixture.finish().await;
}

// ── end to end: the real `/mcp` transport ─────────────────────────────────────────────────

/// Inserts the principal the `/mcp` authenticator resolves, exactly as the auth middleware does.
async fn inject(State(principal): State<Principal>, mut request: Request, next: Next) -> Response {
    request.extensions_mut().insert(principal);
    next.run(request).await
}

/// A tenant-level mcp licence with no binding: the reference's tenant author.
fn tenant_author_principal() -> Principal {
    Principal {
        tenant_id: Rfc4122Uuid::parse(support::TENANT_A).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(support::LICENCE_ID).expect("licence identity"),
        subject: format!("svc:{}:mcp", support::TENANT_A),
        binding_id: None,
        binding_revision: None,
        management: false,
        platform: false,
        licence: Some(LicenceFacts {
            app: "mcp".to_owned(),
            subject_kind: Some(SubjectKind::Tenant),
        }),
    }
}

fn app(
    state: mcp_server_rs::AppState,
    principal: Principal,
    service: Arc<BuilderService>,
) -> Router {
    Router::new()
        .route_service("/mcp", mcp::service_with_builder(&state, Some(service)))
        .layer(from_fn_with_state(principal, inject))
}

#[tokio::test]
async fn the_mcp_transport_lists_exactly_the_twenty_builder_tools() {
    let fixture = Fixture::new().await;
    let service = build_service(&fixture, settings());
    let app = app(fixture.state(), tenant_author_principal(), service);

    let (status, _, reply) = support::mcp_post(
        &app,
        None,
        json!({"jsonrpc": "2.0", "id": 7, "method": "tools/list", "params": {}}),
    )
    .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{reply}");
    let mut names: Vec<String> = reply["result"]["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .map(|tool| tool["name"].as_str().expect("name").to_owned())
        .collect();
    names.sort();
    let document = oracle();
    let mut expected: Vec<String> = document["tools"]
        .as_array()
        .expect("tools")
        .iter()
        .filter_map(|tool| tool["name"].as_str())
        .filter(|name| name.starts_with("builder_"))
        .map(str::to_owned)
        .collect();
    expected.sort();
    assert_eq!(names, expected, "{reply}");
    fixture.finish().await;
}
