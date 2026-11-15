//! Tenant builder SQL against a real Postgres 18: the tenant source repository (registration,
//! revisions, secret rotation, cached specs) and the builder storage (source→service agreement,
//! operations, platform resolution, the tool lifecycle and toolkit writes).
//!
//! Every test drives the real repositories over the migrated schema from `tests/support`; a
//! removed statement, guard or refusal fails here rather than in production. Each test gets its
//! own fresh database, dropped at the end.

mod support;

use std::time::Duration;

use serde_json::{Value, json};
use sqlx::Row;

use mcp_server_rs::auth::BoxFuture;
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
    BuilderCatalogRepository, BuilderStoreError, DraftLicenceError, DraftLicenceLookup,
    DraftRunSettings, Resource, usage,
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
const TOOL_C: &str = "01900000-0000-7000-8000-0000000000c3";
const TOOL_D: &str = "01900000-0000-7000-8000-0000000000c4";
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

// ── draft test runs ─────────────────────────────────────────────────────────────────────────

const PLATFORM_SERVICE: &str = "01900000-0000-7000-8000-0000000000e1";
const PLATFORM_OPERATION: &str = "01900000-0000-7000-8000-0000000000e2";
const PLATFORM_SOURCE: &str = "01900000-0000-7000-8000-0000000000e3";
const PLATFORM_TOOL: &str = "01900000-0000-7000-8000-0000000000e4";
const MINTED_LICENCE: &str = "30000000-0000-4000-8000-0000000000cd";

fn draft_settings() -> DraftRunSettings {
    DraftRunSettings {
        execution_enabled: true,
        platform_tenant_id: authority(PLATFORM),
        license_app_key: Some("synthetic".to_owned()),
        approved_runner_images: Vec::new(),
        sync_wait: Duration::ZERO,
        queue_global_max: 100,
        queue_per_tenant_max: 20,
        run_queue_timeout: Duration::from_secs(240),
        run_max: Duration::from_secs(60),
        max_api_calls_per_run: 10,
        test_runs_per_hour: 60,
    }
}

/// A licence authority stand-in at the external boundary: the tenant's licence for any app.
struct GrantingDraftMinter;

impl DraftLicenceLookup for GrantingDraftMinter {
    fn licence_id<'a>(
        &'a self,
        _tenant: &'a AuthorityId,
        _app: &'a str,
    ) -> BoxFuture<'a, Result<AuthorityId, DraftLicenceError>> {
        Box::pin(async move { Ok(authority(MINTED_LICENCE)) })
    }
}

struct DenyingDraftMinter;

impl DraftLicenceLookup for DenyingDraftMinter {
    fn licence_id<'a>(
        &'a self,
        _tenant: &'a AuthorityId,
        _app: &'a str,
    ) -> BoxFuture<'a, Result<AuthorityId, DraftLicenceError>> {
        Box::pin(async move { Err(DraftLicenceError::Denied) })
    }
}

/// The fixture manifest with a different effect (`read_only` or `writes`).
fn with_effect(manifest: ToolManifest, effect: &str) -> ToolManifest {
    let mut value = serde_json::to_value(manifest).expect("manifest json");
    value["effect"] = json!(effect);
    serde_json::from_value(value).expect("a valid manifest")
}

/// The fixture manifest with one optional string input, so two valid inputs differ.
fn with_note_input(manifest: ToolManifest) -> ToolManifest {
    let mut value = serde_json::to_value(manifest).expect("manifest json");
    value["input_schema"] = json!({
        "type": "object",
        "properties": {"note": {"type": "string"}},
        "additionalProperties": false,
    });
    serde_json::from_value(value).expect("a valid manifest")
}

/// A `kata_python` tool naming the digest the execution fixture approves.
fn kata_tool(tool_id: &str, operation_id: &str) -> ToolManifest {
    let mut value = serde_json::to_value(tool_manifest(
        TENANT_A,
        tool_id,
        1,
        "draft_kata",
        operation_id,
        1,
    ))
    .expect("manifest json");
    let object = value.as_object_mut().expect("manifest object");
    object.remove("target");
    value["runtime"] = json!("kata_python");
    value["entrypoint"] = json!("package/main.py");
    value["runner_image_digest"] =
        json!(format!("registry.example/runner@sha256:{}", "b".repeat(64)));
    serde_json::from_value(value).expect("a valid kata manifest")
}

async fn create_draft_tool(fixture: &Fixture, manifest: &ToolManifest) {
    builder(fixture)
        .create_tool(&authority(TENANT_A), manifest, &files(), &actor(), 50)
        .await
        .expect("create the draft tool");
}

/// A published platform service behind a licence-kind source, granted to tenant A, and a
/// published platform operation: what a licence reference is minted for.
async fn seed_platform_licence_service(fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO public.mcp_sources(source_id,source_key,base_url,auth,created_by,updated_by,\
         owner_tenant_id) VALUES ($1::uuid,'licence_source','https://licence.example.test',$2,$3,$3,\
         $4::uuid)",
    )
    .bind(PLATFORM_SOURCE)
    .bind(json!({"kind": "licence"}))
    .bind(json!({"subject": "agent-09", "license_id": LICENSE}))
    .bind(PLATFORM)
    .execute(&fixture.pool)
    .await
    .expect("platform licence source");
    sqlx::query(
        "INSERT INTO public.mcp_services(service_id,service_key,created_by,owner_tenant_id) \
         VALUES ($1::uuid,'shared_service',$2,$3::uuid)",
    )
    .bind(PLATFORM_SERVICE)
    .bind(json!({"subject": "agent-09", "license_id": LICENSE}))
    .bind(PLATFORM)
    .execute(&fixture.pool)
    .await
    .expect("platform service identity");
    sqlx::query(
        "INSERT INTO public.mcp_service_versions(service_id,version,manifest,created_by,updated_by) \
         VALUES ($1::uuid,1,$2,$3,$3)",
    )
    .bind(PLATFORM_SERVICE)
    .bind(json!({
        "schema_version": 1,
        "service_id": PLATFORM_SERVICE,
        "version": 1,
        "service_key": "shared_service",
        "destination_alias": "licence_source",
        "license_app_key": "synthetic",
        "auth_adapter": "license_bearer",
        "credential_profile_key": "synthetic_profile",
        "max_request_bytes": 4096,
        "max_response_bytes": 4096,
    }))
    .bind(json!({"subject": "agent-09", "license_id": LICENSE}))
    .execute(&fixture.pool)
    .await
    .expect("platform service version");
    sqlx::query(
        "UPDATE public.mcp_service_versions SET status='published' \
         WHERE service_id = $1::uuid AND version = 1",
    )
    .bind(PLATFORM_SERVICE)
    .execute(&fixture.pool)
    .await
    .expect("publish the platform service");
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(PLATFORM_OPERATION)
    .bind(PLATFORM_SERVICE)
    .bind(json!({
        "schema_version": 1,
        "operation_id": PLATFORM_OPERATION,
        "version": 1,
        "service": {"id": PLATFORM_SERVICE, "version": 1},
        "method": "GET",
        "path_template": "/shared",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "mappings": [],
        "effect": "read_only",
        "timeout_seconds": 30,
        "pagination_limit": 100,
        "max_response_bytes": 4096
    }))
    .bind(json!({"subject": "agent-09", "license_id": LICENSE}))
    .execute(&fixture.pool)
    .await
    .expect("platform operation version");
    sqlx::query(
        "UPDATE public.mcp_operation_versions SET status='published' \
         WHERE operation_id = $1::uuid AND version = 1",
    )
    .bind(PLATFORM_OPERATION)
    .execute(&fixture.pool)
    .await
    .expect("publish the platform operation");
    sqlx::query(
        "INSERT INTO public.mcp_service_grants(service_id,grantee_tenant_id,granted_by) \
         VALUES ($1::uuid,$2::uuid,$3)",
    )
    .bind(PLATFORM_SERVICE)
    .bind(TENANT_A)
    .bind(json!({"subject": "agent-09", "license_id": LICENSE}))
    .execute(&fixture.pool)
    .await
    .expect("grant the platform service");
}

async fn run_row(fixture: &Fixture, run_id: &str) -> Value {
    let row = sqlx::query(
        "SELECT mode, binding_id::text AS binding_id, binding_revision, \
         credential_profile_id::text AS credential_profile_id, \
         gateway_license_id::text AS gateway_license_id, owner_tenant_id::text AS owner_tenant_id, \
         tool_id::text AS tool_id, tool_version, profile_snapshot, authority, created_by, runtime, \
         status FROM public.mcp_runs WHERE tenant_id=$1::uuid AND run_id=$2::uuid",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("draft run row");
    json!({
        "mode": row.try_get::<String, _>("mode").expect("mode"),
        "binding_id": row.try_get::<Option<String>, _>("binding_id").expect("binding"),
        "binding_revision": row.try_get::<Option<i64>, _>("binding_revision").expect("revision"),
        "credential_profile_id": row
            .try_get::<Option<String>, _>("credential_profile_id")
            .expect("profile"),
        "gateway_license_id": row
            .try_get::<String, _>("gateway_license_id")
            .expect("gateway"),
        "owner_tenant_id": row.try_get::<String, _>("owner_tenant_id").expect("owner"),
        "tool_id": row.try_get::<String, _>("tool_id").expect("tool"),
        "tool_version": row.try_get::<i32, _>("tool_version").expect("tool version"),
        "profile_snapshot": row.try_get::<Value, _>("profile_snapshot").expect("profile"),
        "authority": row.try_get::<Value, _>("authority").expect("authority"),
        "created_by": row.try_get::<Value, _>("created_by").expect("creator"),
        "runtime": row.try_get::<String, _>("runtime").expect("runtime"),
        "status": row.try_get::<String, _>("status").expect("status"),
    })
}

#[tokio::test]
async fn draft_run_queues_without_a_binding_and_replays_idempotently() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let other = authority(TENANT_B);
    let licence = authority(LICENSE);
    let settings = draft_settings();
    create_draft_tool(
        &fixture,
        &with_note_input(tool_manifest(
            TENANT_A,
            TOOL_A,
            1,
            "builder_tool",
            OPERATION_A,
            1,
        )),
    )
    .await;

    let view = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({}),
            false,
            None,
            &settings,
            None,
        )
        .await
        .expect("submit a draft run");
    assert_eq!(view["status"], "queued");
    assert_eq!(view["mode"], "draft");
    assert_eq!(view["trace"], json!([]));
    assert_eq!(view["payload_expired"], false);
    assert_eq!(view["result"], Value::Null);
    assert_eq!(view["error"], Value::Null);
    assert_eq!(view["error_excerpt"], Value::Null);
    let run_id = view["run_id"].as_str().expect("run id").to_owned();

    let row = run_row(&fixture, &run_id).await;
    assert_eq!(row["mode"], "draft");
    assert_eq!(row["binding_id"], Value::Null);
    assert_eq!(row["binding_revision"], Value::Null);
    assert_eq!(row["credential_profile_id"], Value::Null);
    assert_eq!(row["gateway_license_id"], LICENSE);
    assert_eq!(row["owner_tenant_id"], TENANT_A);
    assert_eq!(row["tool_id"], TOOL_A);
    assert_eq!(row["tool_version"], 1);
    // The ephemeral profile: the caller's proven licence is the gateway, no service references.
    assert_eq!(row["profile_snapshot"]["name"], "draft_run");
    assert_eq!(row["profile_snapshot"]["tenant_id"], TENANT_A);
    assert_eq!(row["profile_snapshot"]["gateway"]["service"], "gateway");
    assert_eq!(row["profile_snapshot"]["gateway"]["license_id"], LICENSE);
    assert_eq!(row["profile_snapshot"]["gateway"]["app_key"], "synthetic");
    assert_eq!(row["profile_snapshot"]["services"], json!([]));
    // The authority snapshot's three members are each a JSON string, as the worker reads them.
    for member in ["manifest", "effective", "context"] {
        assert!(
            row["authority"][member].is_string(),
            "authority.{member} must be a JSON string: {}",
            row["authority"]
        );
    }
    let context = format!(
        "{{\"tenant_id\":\"{TENANT_A}\",\"project_id\":null,\"workspace_id\":null,\"project_phase\":null,\"work_type\":null,\"card_stage\":null,\"responsibility\":null,\"test_command\":null,\"reviewed_commit\":null}}"
    );
    assert_eq!(
        row["authority"]["context"]
            .as_str()
            .expect("context string"),
        context
    );
    assert_eq!(
        row["created_by"],
        json!({"subject": format!("tenant:{TENANT_A}"), "license_id": LICENSE})
    );
    // The reference's draft INSERT leaves `runtime` to the column default.
    assert_eq!(row["runtime"], "kata_python");

    // A replay is the same run; the same key with different inputs is a conflict.
    let keyed = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({"note": "a"}),
            false,
            Some("k1"),
            &settings,
            None,
        )
        .await
        .expect("first keyed run");
    let replayed = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({"note": "a"}),
            false,
            Some("k1"),
            &settings,
            None,
        )
        .await
        .expect("replay");
    assert_eq!(keyed["run_id"], replayed["run_id"]);
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({"note": "b"}),
                false,
                Some("k1"),
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "idempotency input conflict");
    assert!(matches!(error, BuilderStoreError::Conflict(_)));
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                Some("bad key"),
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "invalid idempotency key");
    assert!(matches!(error, BuilderStoreError::Invalid(_)));

    // Another tenant's tool is not found, and a run is only readable by its own tenant.
    let error = builder_refused(
        builder
            .submit_draft(
                &other,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "tenant-owned version not found");
    let error = builder_refused(builder.draft_run(&other, &uuid7(&run_id)).await);
    assert_eq!(error.to_string(), "run not found");
    let error = builder_refused(
        builder
            .draft_run(&tenant, &uuid7("01900000-0000-7000-8000-0000000000aa"))
            .await,
    );
    assert_eq!(error.to_string(), "run not found");
    assert!(matches!(error, BuilderStoreError::NotFound(_)));

    fixture.finish().await;
}

#[tokio::test]
async fn draft_runs_need_confirmation_for_writes() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENSE);
    let settings = draft_settings();
    create_draft_tool(
        &fixture,
        &with_effect(
            tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
            "writes",
        ),
    )
    .await;

    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(
        error.to_string(),
        "this tool writes; confirm_writes is required"
    );
    assert!(matches!(error, BuilderStoreError::Invalid(_)));
    let confirmed = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({}),
            true,
            None,
            &settings,
            None,
        )
        .await
        .expect("a confirmed write run");
    assert_eq!(confirmed["status"], "queued");

    // A read-only tool whose OPERATION writes needs the confirmation too.
    builder
        .create_operation(
            &tenant,
            &operation_manifest(SERVICE_A, OPERATION_B, 1, "writes"),
            &actor(),
            Some("write_customer"),
            300,
        )
        .await
        .expect("create a writing operation");
    create_draft_tool(
        &fixture,
        &tool_manifest(TENANT_A, TOOL_B, 1, "reader_tool", OPERATION_B, 1),
    )
    .await;
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_B),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(
        error.to_string(),
        "this tool writes; confirm_writes is required"
    );

    fixture.finish().await;
}

#[tokio::test]
async fn draft_admission_refuses_inputs_unrunnable_tools_runners_and_dependencies() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENSE);
    let settings = draft_settings();
    create_draft_tool(
        &fixture,
        &with_note_input(tool_manifest(
            TENANT_A,
            TOOL_A,
            1,
            "builder_tool",
            OPERATION_A,
            1,
        )),
    )
    .await;

    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({"other": 1}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "invalid input arguments");
    assert!(matches!(error, BuilderStoreError::Invalid(_)));

    let mut disabled = draft_settings();
    disabled.execution_enabled = false;
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &disabled,
                None,
            )
            .await,
    );
    assert_eq!(
        error.to_string(),
        "test runs are not available: execution is disabled"
    );
    assert!(matches!(error, BuilderStoreError::Unavailable(_)));

    // A disabled version is not runnable; a retired identity is not runnable either.
    sqlx::query(
        "UPDATE public.mcp_tool_versions SET status='disabled' \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND version=1",
    )
    .bind(TENANT_A)
    .bind(TOOL_A)
    .execute(&fixture.pool)
    .await
    .expect("disable the tool version");
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "tool version is not runnable");
    // A retired identity is not runnable either. The identity guard demands revision + 1.
    create_draft_tool(
        &fixture,
        &tool_manifest(TENANT_A, TOOL_D, 1, "retired_tool", OPERATION_A, 1),
    )
    .await;
    sqlx::query(
        "UPDATE public.mcp_tools SET retired=true, revision=revision+1 \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid",
    )
    .bind(TENANT_A)
    .bind(TOOL_D)
    .execute(&fixture.pool)
    .await
    .expect("retire the tool identity");
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_D),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "tool version is not runnable");

    // A kata tool needs an approved runner image; an approved one is admitted.
    let kata = kata_tool(TOOL_B, OPERATION_A);
    create_draft_tool(&fixture, &kata).await;
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_B),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "tool runner image is not approved");
    let mut approved = draft_settings();
    approved.approved_runner_images = vec![
        kata.runner_image_digest
            .as_ref()
            .expect("a kata digest")
            .as_str()
            .to_owned(),
    ];
    let admitted = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_B),
            version(1),
            &json!({}),
            false,
            None,
            &approved,
            None,
        )
        .await
        .expect("an approved kata run");
    assert_eq!(admitted["status"], "queued");

    // A dependency that is no longer runnable refuses the run.
    builder
        .create_operation(
            &tenant,
            &operation_manifest(SERVICE_A, OPERATION_B, 1, "read_only"),
            &actor(),
            Some("later_operation"),
            300,
        )
        .await
        .expect("create the dependency operation");
    create_draft_tool(
        &fixture,
        &tool_manifest(TENANT_A, TOOL_C, 1, "dependent_tool", OPERATION_B, 1),
    )
    .await;
    sqlx::query(
        "UPDATE public.mcp_operation_versions SET status='disabled' \
         WHERE operation_id=$1::uuid AND version=1",
    )
    .bind(OPERATION_B)
    .execute(&fixture.pool)
    .await
    .expect("disable the dependency operation");
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_C),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(
        error.to_string(),
        "tool depends on an unavailable operation or service"
    );
    assert!(matches!(error, BuilderStoreError::Conflict(_)));

    fixture.finish().await;
}

#[tokio::test]
async fn draft_admission_applies_the_test_run_quota_and_the_queue_bounds() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENSE);
    create_draft_tool(
        &fixture,
        &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
    )
    .await;

    let limited = DraftRunSettings {
        test_runs_per_hour: 1,
        ..draft_settings()
    };
    builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({}),
            false,
            None,
            &limited,
            None,
        )
        .await
        .expect("the first run of the hour");
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &limited,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "test runs per hour quota exceeded");
    assert!(matches!(
        error,
        BuilderStoreError::Quota("test runs per hour")
    ));

    // The global queue bound is checked under the same admission lock.
    let bounded = DraftRunSettings {
        queue_global_max: 0,
        ..draft_settings()
    };
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(TOOL_A),
                version(1),
                &json!({}),
                false,
                None,
                &bounded,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "execution queue is full");
    assert!(matches!(error, BuilderStoreError::Forbidden(_)));

    fixture.finish().await;
}

#[tokio::test]
async fn draft_run_projects_the_trace_and_the_last_error_excerpt() {
    let fixture = Fixture::new().await;
    setup_tenant(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENSE);
    let settings = draft_settings();
    create_draft_tool(
        &fixture,
        &tool_manifest(TENANT_A, TOOL_A, 1, "builder_tool", OPERATION_A, 1),
    )
    .await;
    let view = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(TOOL_A),
            version(1),
            &json!({}),
            false,
            None,
            &settings,
            None,
        )
        .await
        .expect("submit a draft run");
    let run_id = view["run_id"].as_str().expect("run id").to_owned();

    sqlx::query(
        "INSERT INTO public.mcp_run_api_calls(tenant_id,run_id,sequence,operation_id,\
         operation_version,request_hash,license_id,effect,method,path,duration_ms,status) \
         VALUES ($1::uuid,$2::uuid,1,$3::uuid,1,$4,$5::uuid,'read_only','GET','/v1/x',12,\
         'succeeded')",
    )
    .bind(TENANT_A)
    .bind(&run_id)
    .bind(OPERATION_A)
    .bind("a".repeat(64))
    .bind(LICENSE)
    .execute(&fixture.pool)
    .await
    .expect("first trace row");
    sqlx::query(
        "INSERT INTO public.mcp_run_api_calls(tenant_id,run_id,sequence,operation_id,\
         operation_version,request_hash,license_id,effect,method,path,http_status,duration_ms,\
         reason,error_excerpt,finished_at,status) \
         VALUES ($1::uuid,$2::uuid,2,$3::uuid,1,$4,$5::uuid,'read_only','GET','/v1/x',404,12,\
         'status','no such customer',clock_timestamp(),'failed')",
    )
    .bind(TENANT_A)
    .bind(&run_id)
    .bind(OPERATION_A)
    .bind("b".repeat(64))
    .bind(LICENSE)
    .execute(&fixture.pool)
    .await
    .expect("second trace row");

    let shown = builder
        .draft_run(&tenant, &uuid7(&run_id))
        .await
        .expect("read the draft run");
    assert_eq!(shown["run_id"], run_id);
    assert_eq!(shown["mode"], "draft");
    assert_eq!(shown["error_excerpt"], "no such customer");
    let trace = shown["trace"].as_array().expect("trace");
    assert_eq!(trace.len(), 2);
    assert_eq!(trace[0]["sequence"], 1);
    assert_eq!(trace[0]["operation_id"], OPERATION_A);
    assert_eq!(trace[0]["operation_version"], 1);
    assert_eq!(trace[0]["effect"], "read_only");
    assert_eq!(trace[0]["status"], "succeeded");
    assert_eq!(trace[0]["http_status"], Value::Null);
    assert_eq!(trace[0]["reason"], Value::Null);
    assert_eq!(trace[0]["error_excerpt"], Value::Null);
    assert_eq!(trace[0]["finished_at"], Value::Null);
    assert_eq!(trace[1]["method"], "GET");
    assert_eq!(trace[1]["path"], "/v1/x");
    assert_eq!(trace[1]["status"], "failed");
    assert_eq!(trace[1]["http_status"], 404);
    assert_eq!(trace[1]["duration_ms"], 12);
    assert_eq!(trace[1]["reason"], "status");
    assert_eq!(trace[1]["error_excerpt"], "no such customer");
    let started = trace[1]["started_at"].as_str().expect("started_at");
    assert!(
        started.ends_with("+00:00"),
        "Python isoformat carries the offset: {started}"
    );
    assert!(
        trace[1]["finished_at"]
            .as_str()
            .expect("finished_at")
            .ends_with("+00:00")
    );

    fixture.finish().await;
}

#[tokio::test]
async fn draft_runs_mint_licence_references_for_licence_kind_platform_services() {
    let fixture = Fixture::new().await;
    seed_platform_licence_service(&fixture).await;
    let builder = builder(&fixture);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENSE);
    let settings = draft_settings();
    create_draft_tool(
        &fixture,
        &tool_manifest(
            TENANT_A,
            PLATFORM_TOOL,
            1,
            "shared_tool",
            PLATFORM_OPERATION,
            1,
        ),
    )
    .await;

    // Without a minter the licence-kind service cannot be established: the reference's
    // ExecutionDeniedError.
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(PLATFORM_TOOL),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                None,
            )
            .await,
    );
    assert_eq!(error.to_string(), "execution denied");
    assert!(matches!(error, BuilderStoreError::Forbidden(_)));
    let error = builder_refused(
        builder
            .submit_draft(
                &tenant,
                &licence,
                &uuid7(PLATFORM_TOOL),
                version(1),
                &json!({}),
                false,
                None,
                &settings,
                Some(&DenyingDraftMinter),
            )
            .await,
    );
    assert_eq!(error.to_string(), "execution denied");

    // The minter's licence lands in the ephemeral profile, one reference per service.
    let view = builder
        .submit_draft(
            &tenant,
            &licence,
            &uuid7(PLATFORM_TOOL),
            version(1),
            &json!({}),
            false,
            None,
            &settings,
            Some(&GrantingDraftMinter),
        )
        .await
        .expect("a draft run with a minted reference");
    assert_eq!(view["status"], "queued");
    let run_id = view["run_id"].as_str().expect("run id").to_owned();
    let row = run_row(&fixture, &run_id).await;
    assert_eq!(
        row["profile_snapshot"]["services"]
            .as_array()
            .expect("services")
            .len(),
        1
    );
    assert_eq!(
        row["profile_snapshot"]["services"][0],
        json!({
            "service": "shared_service",
            "alias": "shared_service",
            "license_id": MINTED_LICENCE,
            "app_key": "synthetic",
            "bundle": null,
        })
    );
    assert_eq!(row["profile_snapshot"]["gateway"]["license_id"], LICENSE);
    // The narrowing ceiling leaves the fixture's own limits in place.
    let effective: Value =
        serde_json::from_str(row["authority"]["effective"].as_str().expect("effective"))
            .expect("effective json");
    assert_eq!(effective["limits"]["wall_seconds"], 60);
    assert_eq!(effective["limits"]["queue_seconds"], 60);
    assert_eq!(effective["limits"]["api_calls"], 10);

    fixture.finish().await;
}
