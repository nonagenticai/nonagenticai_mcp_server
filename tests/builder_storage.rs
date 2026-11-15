//! Tenant builder SQL against a real Postgres 18: the tenant source repository (registration,
//! revisions, secret rotation, cached specs) and the builder storage (source→service agreement,
//! operations, platform resolution, the tool lifecycle and toolkit writes).
//!
//! Every test drives the real repositories over the migrated schema from `tests/support`; a
//! removed statement, guard or refusal fails here rather than in production. Each test gets its
//! own fresh database, dropped at the end.

mod support;

use serde_json::{Value, json};

use mcp_server_rs::builder::models::{OperationPatch, ToolOperation};
use mcp_server_rs::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{
    Attribution, Effect, OperationManifest, ServiceManifest, ToolManifest,
};
use mcp_server_rs::catalog::package::PackageFile;
use mcp_server_rs::catalog::toolkit_models::ToolkitManifest;
use mcp_server_rs::sources::models::{
    SourceStatus, TenantSourceCreate, TenantSourceUpdate, TokenUpdate,
};
use mcp_server_rs::sources::tenant_repository::{
    TenantSourceError, TenantSourceRepository, TenantSourceSettings,
};
use mcp_server_rs::storage::builder::{
    BuilderCatalogRepository, BuilderStoreError, Resource, usage,
};
use mcp_server_rs::toolkits::resolver::SelectionResolver;

use support::Fixture;

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENSE: &str = "30000000-0000-4000-8000-000000000001";
const PLATFORM: &str = "01900000-0000-7000-8000-00000000f001";
const SERVICE_A: &str = "01900000-0000-7000-8000-0000000000a1";
const SERVICE_B: &str = "01900000-0000-7000-8000-0000000000a2";
const OPERATION_A: &str = "01900000-0000-7000-8000-0000000000b1";
const OPERATION_B: &str = "01900000-0000-7000-8000-0000000000b2";
const OPERATION_C: &str = "01900000-0000-7000-8000-0000000000b3";
const TOOL_A: &str = "01900000-0000-7000-8000-0000000000c1";
const TOOL_B: &str = "01900000-0000-7000-8000-0000000000c2";
const TOOLKIT_A: &str = "01900000-0000-7000-8000-0000000000d1";
const TOOLKIT_B: &str = "01900000-0000-7000-8000-0000000000d2";
const BASE_URL: &str = "https://api.example.test";

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

fn tenant_settings(max_sources: i32) -> TenantSourceSettings {
    TenantSourceSettings {
        secret_key: Some(secret_key().to_vec()),
        max_sources,
        licence_hosts: vec!["api.example.test".to_owned()],
        allowed_ports: vec![443],
        spec_keep: 3,
        spec_max_total_bytes: 25 * 1024 * 1024,
    }
}

fn sources(fixture: &Fixture, max_sources: i32) -> TenantSourceRepository {
    TenantSourceRepository::from_settings(fixture.pool.clone(), &tenant_settings(max_sources))
}

fn builder(fixture: &Fixture) -> BuilderCatalogRepository {
    BuilderCatalogRepository::new(fixture.pool.clone())
}

fn resolver() -> SelectionResolver {
    SelectionResolver {
        platform_tenant_id: authority(PLATFORM),
    }
}

fn create_body(key: &str, auth: Value, token: Option<&str>) -> TenantSourceCreate {
    let mut body = json!({"source_key": key, "base_url": BASE_URL, "auth": auth});
    if let Some(token) = token {
        body["token"] = json!(token);
    }
    serde_json::from_value(body).expect("a valid tenant source create")
}

fn create_body_at(key: &str, base_url: &str, auth: Value) -> TenantSourceCreate {
    serde_json::from_value(json!({"source_key": key, "base_url": base_url, "auth": auth}))
        .expect("a valid tenant source create")
}

fn update_body(auth: Value, expected_revision: u64) -> TenantSourceUpdate {
    serde_json::from_value(json!({
        "base_url": BASE_URL,
        "auth": auth,
        "expected_revision": expected_revision,
    }))
    .expect("a valid tenant source update")
}

fn token_body(token: &str, expected_revision: u64) -> TokenUpdate {
    serde_json::from_value(json!({
        "token": token,
        "expected_revision": expected_revision,
    }))
    .expect("a valid token update")
}

fn source_refused<T>(result: Result<T, TenantSourceError>) -> TenantSourceError {
    match result {
        Ok(_) => panic!("expected a source refusal"),
        Err(error) => error,
    }
}

fn builder_refused<T>(result: Result<T, BuilderStoreError>) -> BuilderStoreError {
    match result {
        Ok(_) => panic!("expected a builder refusal"),
        Err(error) => error,
    }
}

async fn create_source(
    repo: &TenantSourceRepository,
    tenant: &AuthorityId,
    key: &str,
) -> mcp_server_rs::sources::models::SourceView {
    repo.create(
        tenant,
        &create_body(key, json!({"kind": "static_bearer"}), Some("source-token")),
        &actor(),
    )
    .await
    .expect("create tenant source")
}

fn service_manifest(
    service_id: &str,
    service_key: &str,
    alias: &str,
    version: u32,
) -> ServiceManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "service_id": service_id,
        "version": version,
        "service_key": service_key,
        "destination_alias": alias,
        "auth_adapter": "source",
        "credential_profile_key": alias,
        "max_request_bytes": 1048576,
        "max_response_bytes": 10485760,
    }))
    .expect("a valid service manifest")
}

fn operation_manifest(
    service_id: &str,
    operation_id: &str,
    version: u32,
    effect: &str,
) -> OperationManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "operation_id": operation_id,
        "version": version,
        "service": {"id": service_id, "version": 1},
        "method": "GET",
        "path_template": "/synthetic",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "mappings": [],
        "effect": effect,
        "timeout_seconds": 30,
        "pagination_limit": 100,
        "max_response_bytes": 4096,
    }))
    .expect("a valid operation manifest")
}

fn tool_manifest(
    tenant: &str,
    tool_id: &str,
    version: u32,
    public_name: &str,
    operation_id: &str,
    operation_version: u32,
) -> ToolManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "tool_id": tool_id,
        "tenant_id": tenant,
        "version": version,
        "public_name": public_name,
        "operation": format!("synthetic.{public_name}"),
        "description": "Synthetic builder fixture",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "effect": "read_only",
        "allowed_operations": [{"id": operation_id, "version": operation_version}],
    }))
    .expect("a valid tool manifest")
}

fn toolkit_manifest(
    tenant: &str,
    toolkit_id: &str,
    name: &str,
    tool_id: &str,
    tool_version: u32,
) -> ToolkitManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "toolkit_id": toolkit_id,
        "tenant_id": tenant,
        "version": 1,
        "name": name,
        "description": "Synthetic toolkit",
        "tools": [{"tool": {"id": tool_id, "version": tool_version, "tenant_id": tenant}}],
    }))
    .expect("a valid toolkit manifest")
}

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "tool.py".to_owned(),
        content: "async def main(inputs, ctx):\n    return {}\n".to_owned(),
    }]
}

/// A source with its service and one draft operation: everything a tool can pin.
async fn setup_tenant(fixture: &Fixture) {
    let sources = sources(fixture, 20);
    let builder = builder(fixture);
    let tenant = authority(TENANT_A);
    create_source(&sources, &tenant, "billing").await;
    builder
        .create_service(
            &tenant,
            &service_manifest(SERVICE_A, "builder_service", "billing", 1),
            &actor(),
        )
        .await
        .expect("create service");
    builder
        .create_operation(
            &tenant,
            &operation_manifest(SERVICE_A, OPERATION_A, 1, "read_only"),
            &actor(),
            Some("get_customer"),
            300,
        )
        .await
        .expect("create operation");
}

async fn service_status(fixture: &Fixture, service_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT status FROM public.mcp_service_versions \
         WHERE service_id=$1::uuid AND version=1",
    )
    .bind(service_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("service status")
}

async fn operation_status(fixture: &Fixture, operation_id: &str) -> String {
    sqlx::query_scalar(
        "SELECT status FROM public.mcp_operation_versions \
         WHERE operation_id=$1::uuid AND version=1",
    )
    .bind(operation_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("operation status")
}

async fn tool_status(fixture: &Fixture, tool_id: &str, version: i32) -> String {
    sqlx::query_scalar(
        "SELECT status FROM public.mcp_tool_versions \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND version=$3",
    )
    .bind(TENANT_A)
    .bind(tool_id)
    .bind(version)
    .fetch_one(&fixture.pool)
    .await
    .expect("tool status")
}

// ── the tenant source repository ────────────────────────────────────────────────────────────

#[tokio::test]
async fn source_create_update_secret_and_status() {
    let fixture = Fixture::new().await;
    let repo = sources(&fixture, 20);
    let tenant = authority(TENANT_A);

    let created = create_source(&repo, &tenant, "billing").await;
    assert_eq!(created.source_key.as_str(), "billing");
    assert_eq!(created.revision, 1);
    assert_eq!(created.status, SourceStatus::Active);
    assert!(created.has_token);
    assert!(created.token_set_at.is_some());

    // Leaving the token out keeps the stored one.
    let updated = repo
        .update(
            &tenant,
            "billing",
            &update_body(json!({"kind": "static_bearer"}), 1),
            &actor(),
        )
        .await
        .expect("update");
    assert_eq!(updated.revision, 2);
    assert!(updated.has_token);

    let rotated = repo
        .set_secret(&tenant, "billing", &token_body("second-token", 2), &actor())
        .await
        .expect("rotate the secret");
    assert_eq!(rotated.revision, 3);

    let error = source_refused(
        repo.set_secret(&tenant, "billing", &token_body("has a space", 3), &actor())
            .await,
    );
    assert_eq!(error.to_string(), "invalid credential material");
    assert!(matches!(error, TenantSourceError::Invalid(_)));

    let disabled = repo
        .set_status(&tenant, "billing", 3, "disabled", &actor())
        .await
        .expect("disable");
    assert_eq!(disabled.revision, 4);
    assert_eq!(disabled.status, SourceStatus::Disabled);

    let error = source_refused(
        repo.set_status(&tenant, "billing", 4, "disabled", &actor())
            .await,
    );
    assert_eq!(
        error.to_string(),
        "source revision mismatch or already in that state"
    );

    // A secret-less kind clears the stored credential.
    let cleared = repo
        .update(
            &tenant,
            "billing",
            &update_body(json!({"kind": "none"}), 4),
            &actor(),
        )
        .await
        .expect("clear the secret");
    assert!(!cleared.has_token);
    assert!(cleared.token_set_at.is_none());
    fixture.finish().await;
}

#[tokio::test]
async fn source_create_refuses_ports_hosts_and_the_quota() {
    let fixture = Fixture::new().await;
    let repo = sources(&fixture, 1);
    let tenant = authority(TENANT_A);

    let error = source_refused(
        repo.create(
            &tenant,
            &create_body_at(
                "billing",
                "https://api.example.test:8443",
                json!({"kind": "none"}),
            ),
            &actor(),
        )
        .await,
    );
    assert_eq!(error.to_string(), "port is not allowed");

    let error = source_refused(
        repo.create(
            &tenant,
            &create_body_at(
                "other",
                "https://not-allowed.example.test",
                json!({"kind": "licence", "app_key": "coding"}),
            ),
            &actor(),
        )
        .await,
    );
    assert_eq!(
        error.to_string(),
        "source host is not in the allowed host list"
    );

    create_source(&repo, &tenant, "first").await;
    let error = source_refused(
        repo.create(
            &tenant,
            &create_body("second", json!({"kind": "none"}), None),
            &actor(),
        )
        .await,
    );
    assert_eq!(error.to_string(), "source quota exceeded");
    assert!(matches!(error, TenantSourceError::Quota("source")));

    // A disabled source does not count against the active quota.
    repo.set_status(&tenant, "first", 1, "disabled", &actor())
        .await
        .expect("disable");
    repo.create(
        &tenant,
        &create_body("second", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("a disabled source frees a quota slot");
    fixture.finish().await;
}

#[tokio::test]
async fn sources_and_specs_are_tenant_scoped() {
    let fixture = Fixture::new().await;
    let repo = sources(&fixture, 20);
    let tenant_a = authority(TENANT_A);
    let tenant_b = authority(TENANT_B);
    create_source(&repo, &tenant_a, "billing").await;
    create_source(&repo, &tenant_b, "other").await;

    let page = |views: Vec<mcp_server_rs::sources::models::SourceView>| -> Vec<String> {
        views
            .iter()
            .map(|view| view.source_key.as_str().to_owned())
            .collect()
    };
    assert_eq!(
        page(repo.page(&tenant_a, 10, 0).await.expect("page")),
        ["billing"]
    );
    assert_eq!(
        page(repo.page(&tenant_b, 10, 0).await.expect("page")),
        ["other"]
    );

    let error = source_refused(repo.get(&tenant_a, "other").await);
    assert_eq!(error.to_string(), "source not found");
    let error = source_refused(
        repo.update(
            &tenant_a,
            "other",
            &update_body(json!({"kind": "none"}), 1),
            &actor(),
        )
        .await,
    );
    assert_eq!(error.to_string(), "source not found");

    let sha = "a".repeat(64);
    repo.put_spec(&tenant_a, "billing", &sha, &json!({"openapi": "3.1.0"}), 20)
        .await
        .expect("cache a spec");
    assert!(
        repo.get_spec(&tenant_a, "other", None)
            .await
            .expect("a foreign source has no spec")
            .is_none()
    );
    assert!(
        repo.get_spec(&tenant_b, "billing", None)
            .await
            .expect("a foreign key has no spec")
            .is_none()
    );
    fixture.finish().await;
}

#[tokio::test]
async fn specs_follow_the_sha_rule() {
    let fixture = Fixture::new().await;
    let repo = sources(&fixture, 20);
    let tenant = authority(TENANT_A);
    create_source(&repo, &tenant, "billing").await;

    let first = "a".repeat(64);
    let second = "b".repeat(64);
    let third = "c".repeat(64);
    repo.put_spec(&tenant, "billing", &first, &json!({"title": "first"}), 11)
        .await
        .expect("first spec");
    repo.put_spec(&tenant, "billing", &second, &json!({"title": "second"}), 12)
        .await
        .expect("second spec");

    let newest = repo
        .get_spec(&tenant, "billing", None)
        .await
        .expect("newest spec")
        .expect("a stored spec");
    assert_eq!(newest.sha256, second);
    assert_eq!(newest.bytes, 12);
    assert_eq!(newest.document["title"], json!("second"));

    let pinned = repo
        .get_spec(&tenant, "billing", Some(first.as_str()))
        .await
        .expect("pinned spec")
        .expect("the first document is kept");
    assert_eq!(pinned.document["title"], json!("first"));

    assert!(
        repo.get_spec(&tenant, "billing", Some(third.as_str()))
            .await
            .expect("unknown sha")
            .is_none()
    );
    assert!(
        repo.get_spec(&tenant, "billing", None)
            .await
            .expect("still cached")
            .is_some()
    );
    fixture.finish().await;
}

// ── services and operations ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn service_for_source_is_one_to_one_and_requires_an_active_source() {
    let fixture = Fixture::new().await;
    let repo = sources(&fixture, 20);
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    create_source(&repo, &tenant, "billing").await;

    builder
        .create_service(
            &tenant,
            &service_manifest(SERVICE_A, "builder_service", "billing", 1),
            &actor(),
        )
        .await
        .expect("create service");
    let record = builder
        .service_for_source(&tenant, "billing")
        .await
        .expect("read the service")
        .expect("the source has a service");
    assert_eq!(record.service_id.as_str(), SERVICE_A);
    assert_eq!(record.version.get(), 1);
    assert_eq!(record.revision.get(), 1);
    assert_eq!(record.status, VersionStatus::Draft);
    assert_eq!(record.manifest.destination_alias.as_str(), "billing");

    let error = builder_refused(
        builder
            .create_service(
                &tenant,
                &service_manifest(SERVICE_B, "builder_service_two", "billing", 1),
                &actor(),
            )
            .await,
    );
    assert_eq!(error.to_string(), "this source already has a service");

    let error = builder_refused(
        builder
            .create_service(
                &tenant,
                &service_manifest(SERVICE_B, "builder_service_two", "missing", 1),
                &actor(),
            )
            .await,
    );
    assert_eq!(error.to_string(), "source not found");

    // Version n+1 keeps the identity and the source, and the newest version is what reads see.
    builder
        .append_service(
            &tenant,
            &service_manifest(SERVICE_A, "builder_service", "billing", 2),
            &actor(),
            1,
        )
        .await
        .expect("append a service version");
    let record = builder
        .service_for_source(&tenant, "billing")
        .await
        .expect("read the service")
        .expect("the source still has a service");
    assert_eq!(record.version.get(), 2);
    assert_eq!(record.revision.get(), 2);

    // A disabled source cannot back a service.
    create_source(&repo, &tenant, "old").await;
    repo.set_status(&tenant, "old", 1, "disabled", &actor())
        .await
        .expect("disable");
    let error = builder_refused(
        builder
            .create_service(
                &tenant,
                &service_manifest(SERVICE_B, "builder_service_three", "old", 1),
                &actor(),
            )
            .await,
    );
    assert_eq!(error.to_string(), "source not found");
    fixture.finish().await;
}

#[tokio::test]
async fn operations_are_listed_updated_and_quota_refused() {
    let fixture = Fixture::new().await;
    let sources = sources(&fixture, 20);
    let builder = builder(&fixture);
    let tenant_a = authority(TENANT_A);
    let tenant_b = authority(TENANT_B);
    create_source(&sources, &tenant_a, "billing").await;
    builder
        .create_service(
            &tenant_a,
            &service_manifest(SERVICE_A, "builder_service", "billing", 1),
            &actor(),
        )
        .await
        .expect("create service");

    builder
        .create_operation(
            &tenant_a,
            &operation_manifest(SERVICE_A, OPERATION_A, 1, "read_only"),
            &actor(),
            Some("get_customer"),
            300,
        )
        .await
        .expect("create operation");
    let listed = builder
        .operation_list(&tenant_a, "billing")
        .await
        .expect("list operations");
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].op_key.as_str(), "get_customer");
    assert_eq!(listed[0].version.get(), 1);
    assert_eq!(listed[0].status, VersionStatus::Draft);

    let patch: OperationPatch = serde_json::from_value(json!({
        "expected_version": 1,
        "effect": "writes",
        "timeout_seconds": 60,
    }))
    .expect("a valid operation patch");
    let updated = builder
        .operation_update(&tenant_a, "billing", "get_customer", &patch, &actor(), 300)
        .await
        .expect("update the operation");
    assert_eq!(updated.version.get(), 2);
    assert_eq!(updated.manifest.effect, Effect::Writes);
    assert_eq!(updated.manifest.timeout_seconds, 60);
    // The key still names one operation; only its newest version moved.
    assert_eq!(
        builder
            .operations(&tenant_a, "billing")
            .await
            .expect("operations")
            .len(),
        1
    );

    let stale: OperationPatch = serde_json::from_value(json!({
        "expected_version": 1,
        "effect": "writes",
    }))
    .expect("a valid operation patch");
    let error = builder_refused(
        builder
            .operation_update(&tenant_a, "billing", "get_customer", &stale, &actor(), 300)
            .await,
    );
    assert_eq!(error.to_string(), "the operation changed; re-read it");

    builder
        .create_operation(
            &tenant_a,
            &operation_manifest(SERVICE_A, OPERATION_B, 1, "read_only"),
            &actor(),
            Some("list_orders"),
            300,
        )
        .await
        .expect("second operation");
    let keys: Vec<String> = builder
        .operations(&tenant_a, "billing")
        .await
        .expect("operations")
        .iter()
        .map(|record| record.op_key.as_str().to_owned())
        .collect();
    assert_eq!(keys, ["get_customer", "list_orders"]);

    let error = builder_refused(
        builder
            .create_operation(
                &tenant_a,
                &operation_manifest(SERVICE_A, OPERATION_C, 1, "read_only"),
                &actor(),
                Some("third"),
                2,
            )
            .await,
    );
    assert_eq!(error.to_string(), "operation quota exceeded");
    assert!(matches!(error, BuilderStoreError::Quota("operation")));

    // Another tenant sees neither the service nor the operations.
    assert!(
        builder
            .service_for_source(&tenant_b, "billing")
            .await
            .expect("foreign read")
            .is_none()
    );
    assert!(
        builder
            .operation_by_key(&tenant_b, "billing", "get_customer")
            .await
            .expect("foreign read")
            .is_none()
    );
    let error = builder_refused(builder.operation_list(&tenant_b, "billing").await);
    assert_eq!(error.to_string(), "source not found");

    let resolved = builder
        .resolve_operations(
            &tenant_a,
            &[ToolOperation {
                op_key: Name::new("get_customer").expect("operation key"),
                source_key: Some(Name::new("billing").expect("source key")),
                service: None,
            }],
        )
        .await
        .expect("resolve an own operation");
    assert_eq!(resolved["billing.get_customer"].id.as_str(), OPERATION_A);
    assert_eq!(resolved["billing.get_customer"].version.get(), 2);

    // A stored package pinning version 1 is repinned to the newest version.
    let stored = vec![PackageFile {
        path: "ops.py".to_owned(),
        content: format!(
            "# Generated: operation id and exact version per key.\nOPS = {{\"billing.get_customer\": [\"{OPERATION_A}\", 1]}}"
        ),
    }];
    let repinned = builder
        .repin(&tenant_a, &stored)
        .await
        .expect("repin a stored package");
    assert_eq!(repinned["billing.get_customer"].version.get(), 2);
    fixture.finish().await;
}

#[tokio::test]
async fn platform_operations_resolve_through_the_visibility_rule() {
    let fixture = Fixture::new().await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    support::seed_service(&fixture).await;
    support::seed_operation(&fixture).await;
    sqlx::query(
        "INSERT INTO public.mcp_operation_keys(service_id,op_key,operation_id) \
         VALUES ($1::uuid,$2,$3::uuid)",
    )
    .bind(support::SERVICE_ID)
    .bind("get_customer")
    .bind(support::OPERATION_ALPHA)
    .execute(&fixture.pool)
    .await
    .expect("platform operation key");

    let visible = builder
        .visible_platform_services(&tenant)
        .await
        .expect("visible platform services");
    assert!(
        visible
            .iter()
            .any(|service| service.service_key.as_str() == "synthetic_service")
    );

    let reference = builder
        .platform_operation(&tenant, "synthetic_service", "get_customer")
        .await
        .expect("resolve a platform operation");
    assert_eq!(reference.id.as_str(), support::OPERATION_ALPHA);
    assert_eq!(reference.version.get(), 1);

    let error = builder_refused(
        builder
            .platform_operation(&tenant, "missing", "get_customer")
            .await,
    );
    assert_eq!(
        error.to_string(),
        "platform service 'missing' is not shared with you"
    );
    let error = builder_refused(
        builder
            .platform_operation(&tenant, "synthetic_service", "missing")
            .await,
    );
    assert_eq!(
        error.to_string(),
        "operation synthetic_service.missing is not available"
    );

    let resolved = builder
        .resolve_operations(
            &tenant,
            &[ToolOperation {
                op_key: Name::new("get_customer").expect("operation key"),
                source_key: None,
                service: Some(Name::new("synthetic_service").expect("service key")),
            }],
        )
        .await
        .expect("resolve a platform operation");
    assert_eq!(
        resolved["synthetic_service.get_customer"].id.as_str(),
        support::OPERATION_ALPHA
    );
    fixture.finish().await;
}

// ── tools ───────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn tool_create_append_publish_get_list_and_status() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant_a = authority(TENANT_A);
    let tenant_b = authority(TENANT_B);

    let first = builder
        .create_tool(
            &tenant_a,
            &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
            &files(),
            &actor(),
            50,
        )
        .await
        .expect("create the tool");
    assert_eq!(first.version.get(), 1);
    assert_eq!(first.revision.get(), 1);
    assert_eq!(first.status, VersionStatus::Draft);

    let appended = builder
        .append_tool(
            &tenant_a,
            &uuid7(TOOL_A),
            &tool_manifest(TENANT_A, TOOL_A, 2, "builder_tool", OPERATION_A, 1),
            &files(),
            &actor(),
            version(1),
        )
        .await
        .expect("append a tool version");
    assert_eq!(appended.version.get(), 2);
    assert_eq!(appended.revision.get(), 2);
    assert_eq!(appended.status, VersionStatus::Draft);

    let error = builder_refused(
        builder
            .append_tool(
                &tenant_a,
                &uuid7(TOOL_A),
                &tool_manifest(TENANT_A, TOOL_A, 3, "builder_tool", OPERATION_A, 1),
                &files(),
                &actor(),
                version(1),
            )
            .await,
    );
    assert_eq!(error.to_string(), "stale expected revision");

    let (latest, stored) = builder
        .tool_get(&tenant_a, &uuid7(TOOL_A), None)
        .await
        .expect("read the newest version");
    assert_eq!(latest.version.get(), 2);
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].path, "tool.py");

    let definitions = builder
        .tool_list(&tenant_a, 10, 0)
        .await
        .expect("list tools");
    assert_eq!(definitions.len(), 2);
    assert!(
        definitions
            .iter()
            .all(|definition| definition.tool_id.as_str() == TOOL_A)
    );

    // Publishing the tool also publishes the draft service and operation it pins.
    let published = builder
        .publish_tool(&tenant_a, &uuid7(TOOL_A), version(2), &actor(), version(2))
        .await
        .expect("publish the tool");
    assert_eq!(published.status, VersionStatus::Published);
    assert_eq!(published.revision.get(), 3);
    assert_eq!(service_status(&fixture, SERVICE_A).await, "published");
    assert_eq!(operation_status(&fixture, OPERATION_A).await, "published");

    let disabled = builder
        .set_tool_status(
            &tenant_a,
            &uuid7(TOOL_A),
            version(2),
            VersionStatus::Disabled,
            &actor(),
            version(3),
        )
        .await
        .expect("disable the tool version");
    assert_eq!(disabled.status, VersionStatus::Disabled);
    assert_eq!(disabled.revision.get(), 4);

    // Another tenant reads nothing of it.
    let error = builder_refused(
        builder
            .tool_get(&tenant_b, &uuid7(TOOL_A), Some(version(2)))
            .await,
    );
    assert_eq!(error.to_string(), "tenant-owned version not found");
    assert!(
        builder
            .tool_list(&tenant_b, 10, 0)
            .await
            .expect("foreign tool list")
            .is_empty()
    );

    let counts = builder.usage(&tenant_a).await.expect("usage");
    assert_eq!(counts.sources, 1);
    assert_eq!(counts.operations, 1);
    assert_eq!(counts.tools, 1);
    assert_eq!(counts.toolkits, 0);
    assert_eq!(counts.get(Resource::Tools), 1);
    let mut conn = fixture.pool.acquire().await.expect("connection");
    assert_eq!(
        usage(&mut conn, &tenant_a).await.expect("free usage"),
        counts
    );
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn tool_publish_is_one_transaction_with_its_drafts() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    builder
        .create_tool(
            &tenant,
            &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
            &files(),
            &actor(),
            50,
        )
        .await
        .expect("create the tool");

    // A stale expected revision refuses AFTER the service/operation publication ran; the whole
    // transaction must roll back, leaving the drafts unpublished.
    let error = builder_refused(
        builder
            .publish_tool(&tenant, &uuid7(TOOL_A), version(1), &actor(), version(99))
            .await,
    );
    assert_eq!(error.to_string(), "stale expected revision");
    assert_eq!(service_status(&fixture, SERVICE_A).await, "draft");
    assert_eq!(operation_status(&fixture, OPERATION_A).await, "draft");
    assert_eq!(tool_status(&fixture, TOOL_A, 1).await, "draft");

    // The same publication succeeds once the revision is the one the caller read.
    let published = builder
        .publish_tool(&tenant, &uuid7(TOOL_A), version(1), &actor(), version(1))
        .await
        .expect("publish");
    assert_eq!(published.status, VersionStatus::Published);
    assert_eq!(service_status(&fixture, SERVICE_A).await, "published");
    assert_eq!(operation_status(&fixture, OPERATION_A).await, "published");
    fixture.finish().await;
}

#[tokio::test]
async fn tool_quota_is_counted_under_the_advisory_lock() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let files = files();
    let first = tool_manifest(TENANT_A, TOOL_A, 1, "first_tool", OPERATION_A, 1);
    let second = tool_manifest(TENANT_A, TOOL_B, 1, "second_tool", OPERATION_A, 1);
    let actor_a = actor();
    let actor_b = actor();

    // Both creates race the same tenant lock; exactly one may insert under the quota of one.
    let (left, right) = tokio::join!(
        builder.create_tool(&tenant, &first, &files, &actor_a, 1),
        builder.create_tool(&tenant, &second, &files, &actor_b, 1),
    );
    let successes = usize::from(left.is_ok()) + usize::from(right.is_ok());
    assert_eq!(successes, 1, "the advisory lock serialized the quota count");
    let error = match (left, right) {
        (Err(error), Ok(_)) | (Ok(_), Err(error)) => error,
        _ => panic!("exactly one create must be refused"),
    };
    assert_eq!(error.to_string(), "tools quota exceeded");
    assert!(matches!(error, BuilderStoreError::Quota("tools")));

    let counts = builder.usage(&tenant).await.expect("usage");
    assert_eq!(counts.tools, 1);
    fixture.finish().await;
}

// ── toolkits ────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn toolkit_write_publish_and_quota() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    builder
        .create_tool(
            &tenant,
            &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
            &files(),
            &actor(),
            50,
        )
        .await
        .expect("create the tool");
    builder
        .publish_tool(&tenant, &uuid7(TOOL_A), version(1), &actor(), version(1))
        .await
        .expect("publish the tool");

    let created = builder
        .write_toolkit(
            &resolver(),
            &tenant,
            &actor(),
            &toolkit_manifest(TENANT_A, TOOLKIT_A, "builder_toolkit", TOOL_A, 1),
            None,
            Some(1),
        )
        .await
        .expect("create the toolkit");
    assert_eq!(created.manifest.version.get(), 1);
    assert_eq!(created.revision.get(), 1);
    assert_eq!(created.status, VersionStatus::Draft);

    let appended = builder
        .write_toolkit(
            &resolver(),
            &tenant,
            &actor(),
            &toolkit_manifest(TENANT_A, TOOLKIT_A, "builder_toolkit", TOOL_A, 1),
            Some(version(1)),
            Some(1),
        )
        .await
        .expect("append a toolkit version");
    assert_eq!(appended.manifest.version.get(), 2);
    assert_eq!(appended.revision.get(), 2);

    let published = builder
        .publish_toolkit(
            &resolver(),
            &tenant,
            &actor(),
            &uuid7(TOOLKIT_A),
            version(2),
            version(2),
        )
        .await
        .expect("publish the toolkit");
    assert_eq!(published.status, VersionStatus::Published);
    assert_eq!(published.revision.get(), 3);

    let error = builder_refused(
        builder
            .write_toolkit(
                &resolver(),
                &tenant,
                &actor(),
                &toolkit_manifest(TENANT_A, TOOLKIT_B, "second_toolkit", TOOL_A, 1),
                None,
                Some(1),
            )
            .await,
    );
    assert_eq!(error.to_string(), "toolkits quota exceeded");
    assert!(matches!(error, BuilderStoreError::Quota("toolkits")));

    let counts = builder.usage(&tenant).await.expect("usage");
    assert_eq!(counts.toolkits, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn toolkit_writes_are_tenant_scoped() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant_a = authority(TENANT_A);
    let tenant_b = authority(TENANT_B);
    builder
        .create_tool(
            &tenant_a,
            &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
            &files(),
            &actor(),
            50,
        )
        .await
        .expect("create the tool");
    builder
        .publish_tool(&tenant_a, &uuid7(TOOL_A), version(1), &actor(), version(1))
        .await
        .expect("publish the tool");

    let error = builder_refused(
        builder
            .write_toolkit(
                &resolver(),
                &tenant_b,
                &actor(),
                &toolkit_manifest(TENANT_A, TOOLKIT_A, "builder_toolkit", TOOL_A, 1),
                None,
                Some(10),
            )
            .await,
    );
    assert_eq!(error.to_string(), "tenant mismatch");
    assert!(matches!(error, BuilderStoreError::Forbidden(_)));

    let counts = builder.usage(&tenant_b).await.expect("usage");
    assert_eq!(counts.toolkits, 0);
    fixture.finish().await;
}
