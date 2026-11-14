//! Catalog persistence and lifecycle against a real Postgres 18. Each test fails if the
//! behaviour it covers is removed.
//!
//! Server selection mirrors `tests/db.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL` (a URL whose
//! user may CREATE DATABASE), else an ephemeral `postgres:18` container started here with docker
//! and removed afterwards, else FAIL (never skip). `TEST_PG_REGISTRY` may name a registry mirror.
//! Each test gets its own fresh database, dropped at the end.

use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, PgConnection, PgPool};

use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{Attribution, ExactReference, ToolManifest};
use mcp_server_rs::catalog::package::{PackageFile, package_digest};
use mcp_server_rs::catalog::service::{CatalogService, CatalogServiceError};
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::config::PackageLimits;
use mcp_server_rs::db;
use mcp_server_rs::storage::catalog::{AppendRequest, CatalogRepository, CatalogStoreError};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENSE: &str = "30000000-0000-4000-8000-000000000001";
const TOOL_1: &str = "20000000-0000-7000-8000-000000000001";
const TOOL_2: &str = "20000000-0000-7000-8000-000000000002";
const TOOL_3: &str = "20000000-0000-7000-8000-000000000003";
const SERVICE_ID: &str = "40000000-0000-7000-8000-000000000001";
const OPERATION_ID: &str = "50000000-0000-7000-8000-000000000001";

// ── the real-server harness ────────────────────────────────────────────────────────────────

struct Server {
    url: String,
    container: Option<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(id) = &self.container {
            let _ = Command::new("docker").args(["rm", "-f", "-v", id]).output();
        }
    }
}

fn env_url() -> Option<String> {
    ["TEST_DATABASE_URL", "DATABASE_URL"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
}

async fn server() -> Server {
    if let Some(url) = env_url() {
        return Server {
            url,
            container: None,
        };
    }
    let image = match std::env::var("TEST_PG_REGISTRY") {
        Ok(registry) if !registry.trim().is_empty() => {
            format!("{}/postgres:18", registry.trim_end_matches('/'))
        }
        _ => "postgres:18".to_owned(),
    };
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--tmpfs",
            "/var/lib/postgresql",
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-p",
            "127.0.0.1::5432",
            &image,
            "-c",
            "fsync=off",
        ])
        .output()
        .expect("no TEST_DATABASE_URL/DATABASE_URL and `docker` cannot run: failing closed");
    assert!(
        out.status.success(),
        "docker run {image} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    let mut srv = Server {
        url: String::new(),
        container: Some(id.clone()),
    };
    let port_out = Command::new("docker")
        .args(["port", &id, "5432/tcp"])
        .output()
        .expect("docker port");
    let mapping = String::from_utf8(port_out.stdout).unwrap();
    let port = mapping
        .lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .map(str::trim)
        .filter(|port| !port.is_empty())
        .unwrap_or_else(|| panic!("no published port for {id}: {mapping:?}"))
        .to_owned();
    srv.url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match PgConnection::connect(&srv.url).await {
            Ok(connection) => {
                let _ = connection.close().await;
                break;
            }
            Err(error) if Instant::now() > deadline => {
                panic!("postgres never became ready: {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    srv
}

struct Fixture {
    pool: PgPool,
    admin_url: String,
    name: String,
    server: Server,
}

impl Fixture {
    async fn new() -> Self {
        let server = server().await;
        let admin_opts = PgConnectOptions::from_str(&server.url).expect("parse database url");
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("mcp_storage_{}_{nanos}", std::process::id());
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&mut admin)
            .await
            .expect("create test database");
        let _ = admin.close().await;
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .connect_with(admin_opts.database(&name))
            .await
            .expect("connect test database");
        db::migrate(&pool).await.expect("apply migrations");
        Self {
            pool,
            admin_url: server.url.clone(),
            name,
            server,
        }
    }

    fn repository(&self) -> CatalogRepository {
        CatalogRepository::new(self.pool.clone())
    }

    fn service(&self) -> CatalogService {
        CatalogService::new(
            self.repository(),
            SchemaLimits::default(),
            PackageLimits::default(),
        )
    }

    async fn finish(self) {
        let Self {
            pool,
            admin_url,
            name,
            server,
        } = self;
        pool.close().await;
        let admin_opts = PgConnectOptions::from_str(&admin_url).expect("parse admin url");
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");
        sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE \"{name}\" WITH (FORCE)"
        )))
        .execute(&mut admin)
        .await
        .expect("drop test database");
        let _ = admin.close().await;
        drop(server);
    }
}

// ── fixtures ───────────────────────────────────────────────────────────────────────────────

fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value).expect("authority identity")
}

fn tool_id(value: &str) -> Uuid7 {
    Uuid7::new(value).expect("tool identity")
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

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "package/main.py".to_owned(),
        content: "print('synthetic')\n".to_owned(),
    }]
}

/// A strict, valid manifest. The runtime is external so no package digest is involved.
fn manifest(name: &str, tool: &str, tenant: &str, version: u32) -> ToolManifest {
    parse_manifest(json!({
        "schema_version": 1,
        "tool_id": tool,
        "tenant_id": tenant,
        "version": version,
        "public_name": name,
        "operation": "synthetic.synthetic_tool",
        "description": "Synthetic fixture",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "effect": "read_only",
    }))
}

fn parse_manifest(json: Value) -> ToolManifest {
    serde_json::from_value(json).expect("valid tool manifest")
}

/// A strict, valid `kata_python` manifest carrying `digest` as its package digest.
fn kata_manifest(name: &str, tool: &str, tenant: &str, version: u32, digest: &str) -> ToolManifest {
    parse_manifest(json!({
        "schema_version": 1,
        "tool_id": tool,
        "tenant_id": tenant,
        "version": version,
        "public_name": name,
        "operation": "synthetic.synthetic_tool",
        "description": "Synthetic fixture",
        "runtime": "kata_python",
        "entrypoint": "package.main:run",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": digest,
        "runner_image_digest": format!("registry.example/runner@sha256:{}", "a".repeat(64)),
        "effect": "read_only",
    }))
}

fn conflict(error: CatalogStoreError) -> &'static str {
    match error {
        CatalogStoreError::Conflict(message) => message,
        other => panic!("expected a conflict, got {other:?}"),
    }
}

fn not_found(error: CatalogStoreError) -> &'static str {
    match error {
        CatalogStoreError::NotFound(message) => message,
        other => panic!("expected a not-found, got {other:?}"),
    }
}

fn append_request<'a>(
    tenant: &'a AuthorityId,
    tool: &'a Uuid7,
    content: &'a ToolManifest,
    files: &'a [PackageFile],
    actor: &'a Attribution,
    expected_revision: Option<PositiveVersion>,
    exact_version: bool,
) -> AppendRequest<'a> {
    AppendRequest {
        tenant_id: tenant,
        tool_id: tool,
        content,
        files,
        actor,
        expected_revision,
        exact_version,
    }
}

async fn audit_actions(pool: &PgPool, tenant: &str, tool: &str) -> Vec<String> {
    sqlx::query_scalar(
        "SELECT action FROM public.mcp_access_events \
         WHERE tenant_id = $1::uuid AND entity_id = $2::uuid ORDER BY event_id",
    )
    .bind(tenant)
    .bind(tool)
    .fetch_all(pool)
    .await
    .expect("read audit rows")
}

/// A platform service and operation at `draft`, owned by the platform tenant.
async fn seed_draft_dependency(pool: &PgPool) {
    let writer = json!({"subject": "agent-09", "license_id": LICENSE});
    sqlx::query(
        "INSERT INTO public.mcp_services(service_id,service_key,created_by) \
         VALUES ($1::uuid,'synthetic_service',$2)",
    )
    .bind(SERVICE_ID)
    .bind(writer.clone())
    .execute(pool)
    .await
    .expect("service identity");
    sqlx::query(
        "INSERT INTO public.mcp_service_versions(service_id,version,manifest,created_by,updated_by) \
         VALUES ($1::uuid,1,$2,$3,$3)",
    )
    .bind(SERVICE_ID)
    .bind(json!({
        "schema_version": 1,
        "service_id": SERVICE_ID,
        "version": 1,
        "service_key": "synthetic_service",
        "destination_alias": "synthetic_source",
        "auth_adapter": "source",
        "credential_profile_key": "synthetic_profile",
        "max_request_bytes": 4096,
        "max_response_bytes": 4096,
    }))
    .bind(writer.clone())
    .execute(pool)
    .await
    .expect("service version");
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(OPERATION_ID)
    .bind(SERVICE_ID)
    .bind(json!({
        "schema_version": 1,
        "operation_id": OPERATION_ID,
        "version": 1,
        "service": {"id": SERVICE_ID, "version": 1},
    }))
    .bind(writer)
    .execute(pool)
    .await
    .expect("operation version");
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_then_read_back() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tool = tool_id(TOOL_1);
    let created = repository
        .create(
            &authority(TENANT_A),
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");
    assert_eq!(created.version.get(), 1);
    assert_eq!(created.revision.get(), 1);
    assert_eq!(created.status, VersionStatus::Draft);
    assert_eq!(created.manifest.public_name.as_str(), "synthetic_tool");
    assert!(created.source.is_none());

    let read = repository
        .get_version(&authority(TENANT_A), &tool, version(1))
        .await
        .expect("get_version");
    assert_eq!(read, created);
    let latest = repository
        .latest_version(&authority(TENANT_A), &tool)
        .await
        .expect("latest_version");
    assert_eq!(latest, Some(created));
    let stored = repository
        .files(&authority(TENANT_A), &tool, version(1))
        .await
        .expect("files");
    assert_eq!(stored, files());
    assert_eq!(
        audit_actions(&fixture.pool, TENANT_A, TOOL_1).await,
        ["tool.created"]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn duplicate_identity_or_public_name_conflicts() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    repository
        .create(
            &authority(TENANT_A),
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("first create");
    let duplicate_identity = repository
        .create(
            &authority(TENANT_A),
            &manifest("other_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect_err("same identity must conflict");
    assert_eq!(
        conflict(duplicate_identity),
        "tool identity or public name already exists"
    );
    let duplicate_name = repository
        .create(
            &authority(TENANT_A),
            &manifest("synthetic_tool", TOOL_2, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect_err("same public name must conflict");
    assert_eq!(
        conflict(duplicate_name),
        "tool identity or public name already exists"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn append_allocates_the_next_version_and_refuses_stale_revisions() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    let tool = tool_id(TOOL_1);
    let created = repository
        .create(
            &tenant,
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");
    assert_eq!(created.revision.get(), 1);

    // The submitted artifact version is only a template.
    let appended = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 9),
                &files(),
                &actor(),
                Some(version(1)),
                false,
            ),
            None,
        )
        .await
        .expect("append");
    assert_eq!(appended.version.get(), 2);
    assert_eq!(appended.manifest.version.get(), 2);
    assert_eq!(appended.revision.get(), 2);

    let stale = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 9),
                &files(),
                &actor(),
                Some(version(1)),
                false,
            ),
            None,
        )
        .await
        .expect_err("stale revision must conflict");
    assert_eq!(conflict(stale), "stale expected revision");

    let not_the_next = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 9),
                &files(),
                &actor(),
                Some(version(2)),
                true,
            ),
            None,
        )
        .await
        .expect_err("exact_version must refuse a non-next version");
    assert_eq!(
        conflict(not_the_next),
        "manifest version must be the next version"
    );

    let exact = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 3),
                &files(),
                &actor(),
                Some(version(2)),
                true,
            ),
            None,
        )
        .await
        .expect("exact next version");
    assert_eq!(exact.version.get(), 3);
    let latest = repository
        .latest_version(&tenant, &tool)
        .await
        .expect("latest")
        .expect("a version");
    assert_eq!(latest.version.get(), 3);
    assert_eq!(
        audit_actions(&fixture.pool, TENANT_A, TOOL_1).await,
        [
            "tool.created",
            "tool.version_created",
            "tool.version_created"
        ]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_retired_identity_refuses_append() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    let tool = tool_id(TOOL_1);
    repository
        .create(
            &tenant,
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");
    repository
        .retire(&tenant, &tool, version(1))
        .await
        .expect("retire");
    let refused = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 2),
                &files(),
                &actor(),
                Some(version(2)),
                false,
            ),
            None,
        )
        .await
        .expect_err("a retired identity must refuse append");
    assert_eq!(
        conflict(refused),
        "retired identity or public name mismatch"
    );
    let again = repository
        .retire(&tenant, &tool, version(2))
        .await
        .expect_err("retiring twice conflicts");
    assert_eq!(conflict(again), "identity already retired");
    let publish = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(2),
        )
        .await
        .expect_err("a retired identity cannot publish");
    assert_eq!(conflict(publish), "identity retired");
    fixture.finish().await;
}

#[tokio::test]
async fn a_public_name_mismatch_is_refused() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    let tool = tool_id(TOOL_1);
    repository
        .create(
            &tenant,
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");
    let mismatch = repository
        .append(
            &append_request(
                &tenant,
                &tool,
                &manifest("renamed_tool", TOOL_1, TENANT_A, 2),
                &files(),
                &actor(),
                Some(version(1)),
                false,
            ),
            None,
        )
        .await
        .expect_err("a renamed identity must conflict");
    assert_eq!(
        conflict(mismatch),
        "retired identity or public name mismatch"
    );
    let foreign = repository
        .append(
            &append_request(
                &authority(TENANT_B),
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_A, 2),
                &files(),
                &actor(),
                None,
                false,
            ),
            None,
        )
        .await
        .expect_err("content from another tenant must conflict");
    assert_eq!(
        conflict(foreign),
        "content identity differs from owned target"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn lifecycle_transitions_allow_and_refuse_the_reference_matrix() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    let tool = tool_id(TOOL_1);
    repository
        .create(
            &tenant,
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");

    let to_draft = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Draft,
            &actor(),
            version(1),
        )
        .await
        .expect_err("draft is never a target");
    assert_eq!(conflict(to_draft), "invalid lifecycle transition");

    let published = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("draft -> published");
    assert_eq!(published.status, VersionStatus::Published);
    assert_eq!(published.revision.get(), 2);

    let republish = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(2),
        )
        .await
        .expect_err("published -> published is refused");
    assert_eq!(conflict(republish), "invalid lifecycle transition");

    let disabled = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Disabled,
            &actor(),
            version(2),
        )
        .await
        .expect("published -> disabled");
    assert_eq!(disabled.status, VersionStatus::Disabled);
    assert_eq!(disabled.revision.get(), 3);

    let reenable = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(3),
        )
        .await
        .expect_err("disabled -> published is refused");
    assert_eq!(conflict(reenable), "invalid lifecycle transition");

    let retired = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Retired,
            &actor(),
            version(3),
        )
        .await
        .expect("disabled -> retired");
    assert_eq!(retired.status, VersionStatus::Retired);
    assert_eq!(retired.revision.get(), 4);
    let after = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Disabled,
            &actor(),
            version(4),
        )
        .await
        .expect_err("retired is terminal");
    assert_eq!(conflict(after), "invalid lifecycle transition");

    // The rest of the matrix: draft -> disabled and draft -> retired.
    for (id, name, target) in [
        (TOOL_2, "second_tool", VersionStatus::Disabled),
        (TOOL_3, "third_tool", VersionStatus::Retired),
    ] {
        repository
            .create(
                &tenant,
                &manifest(name, id, TENANT_A, 1),
                &files(),
                &actor(),
            )
            .await
            .expect("create");
        let moved = repository
            .transition(
                &tenant,
                &tool_id(id),
                version(1),
                target,
                &actor(),
                version(1),
            )
            .await
            .expect("draft -> target");
        assert_eq!(moved.status, target);
    }
    assert_eq!(
        audit_actions(&fixture.pool, TENANT_A, TOOL_1).await,
        [
            "tool.created",
            "tool.published",
            "tool.disabled",
            "tool.retired"
        ]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn publish_requires_published_operations_and_services() {
    let fixture = Fixture::new().await;
    seed_draft_dependency(&fixture.pool).await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    let tool = tool_id(TOOL_1);
    let mut with_operation = manifest("synthetic_tool", TOOL_1, TENANT_A, 1);
    with_operation.allowed_operations = vec![ExactReference {
        id: tool_id(OPERATION_ID),
        version: version(1),
    }];
    repository
        .create(&tenant, &with_operation, &files(), &actor())
        .await
        .expect("create");

    let refused = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect_err("a draft dependency must block publication");
    assert_eq!(conflict(refused), "operation or service is not published");

    sqlx::query(
        "UPDATE public.mcp_service_versions SET status='published' \
         WHERE service_id = $1::uuid AND version = 1",
    )
    .bind(SERVICE_ID)
    .execute(&fixture.pool)
    .await
    .expect("publish service");
    sqlx::query(
        "UPDATE public.mcp_operation_versions SET status='published' \
         WHERE operation_id = $1::uuid AND version = 1",
    )
    .bind(OPERATION_ID)
    .execute(&fixture.pool)
    .await
    .expect("publish operation");

    let published = repository
        .transition(
            &tenant,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("published dependencies allow publication");
    assert_eq!(published.status, VersionStatus::Published);
    fixture.finish().await;
}

#[tokio::test]
async fn definitions_paginate_over_every_status() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    for (id, name) in [
        (TOOL_1, "alpha_tool"),
        (TOOL_2, "beta_tool"),
        (TOOL_3, "gamma_tool"),
    ] {
        repository
            .create(
                &tenant,
                &manifest(name, id, TENANT_A, 1),
                &files(),
                &actor(),
            )
            .await
            .expect("create");
    }
    repository
        .append(
            &append_request(
                &tenant,
                &tool_id(TOOL_1),
                &manifest("alpha_tool", TOOL_1, TENANT_A, 2),
                &files(),
                &actor(),
                Some(version(1)),
                false,
            ),
            None,
        )
        .await
        .expect("append second version");
    repository
        .transition(
            &tenant,
            &tool_id(TOOL_2),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish second tool");

    let first = repository
        .definitions(&tenant, 2, 0)
        .await
        .expect("first page");
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].tool_id.as_str(), TOOL_1);
    assert_eq!(first[0].version.get(), 1);
    assert_eq!(first[0].public_name.as_str(), "alpha_tool");
    assert_eq!(first[0].status, VersionStatus::Draft);
    assert_eq!(first[1].version.get(), 2);

    let second = repository
        .definitions(&tenant, 2, 2)
        .await
        .expect("second page");
    assert_eq!(second.len(), 2);
    assert_eq!(second[0].tool_id.as_str(), TOOL_2);
    assert_eq!(second[0].status, VersionStatus::Published);
    assert_eq!(second[0].revision.get(), 2);
    assert_eq!(second[1].tool_id.as_str(), TOOL_3);

    let beyond = repository
        .definitions(&tenant, 2, 4)
        .await
        .expect("last page");
    assert!(beyond.is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn tenant_b_cannot_read_tenant_a() {
    let fixture = Fixture::new().await;
    let repository = fixture.repository();
    let tool = tool_id(TOOL_1);
    repository
        .create(
            &authority(TENANT_A),
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("create");
    repository
        .get_version(&authority(TENANT_A), &tool, version(1))
        .await
        .expect("tenant A can read its own tool");

    let tenant_b = authority(TENANT_B);
    let read = repository
        .get_version(&tenant_b, &tool, version(1))
        .await
        .expect_err("tenant B must not read tenant A's tool");
    assert_eq!(not_found(read), "tenant-owned version not found");
    assert_eq!(
        repository
            .latest_version(&tenant_b, &tool)
            .await
            .expect("latest"),
        None
    );
    let file_rows = repository
        .files(&tenant_b, &tool, version(1))
        .await
        .expect_err("tenant B must not read tenant A's files");
    assert_eq!(not_found(file_rows), "tenant-owned version not found");
    let append = repository
        .append(
            &append_request(
                &tenant_b,
                &tool,
                &manifest("synthetic_tool", TOOL_1, TENANT_B, 2),
                &files(),
                &actor(),
                None,
                false,
            ),
            None,
        )
        .await
        .expect_err("tenant B must not append tenant A's identity");
    assert_eq!(not_found(append), "tenant-owned identity not found");
    let transition = repository
        .transition(
            &tenant_b,
            &tool,
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect_err("tenant B must not transition tenant A's tool");
    assert_eq!(not_found(transition), "tenant-owned identity not found");
    let retire = repository
        .retire(&tenant_b, &tool, version(1))
        .await
        .expect_err("tenant B must not retire tenant A's tool");
    assert_eq!(not_found(retire), "tenant-owned identity not found");
    assert!(
        repository
            .definitions(&tenant_b, 10, 0)
            .await
            .expect("tenant B definitions")
            .is_empty()
    );
    fixture.finish().await;
}

#[tokio::test]
async fn the_service_validates_before_it_persists() {
    let fixture = Fixture::new().await;
    let service = fixture.service();
    let tenant = authority(TENANT_A);

    let reserved = service
        .create_draft(
            &tenant,
            &manifest("mcp_run_status", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect_err("reserved names are refused");
    match reserved {
        CatalogServiceError::Invalid(error) => {
            assert_eq!(error.to_string(), "reserved platform tool name");
        }
        other => panic!("expected an invalid refusal, got {other:?}"),
    }

    let mut open_input = manifest("synthetic_tool", TOOL_1, TENANT_A, 1);
    open_input.input_schema.remove("additionalProperties");
    let public = service
        .create_draft(&tenant, &open_input, &files(), &actor())
        .await
        .expect_err("an open public input is refused");
    match public {
        CatalogServiceError::Invalid(error) => assert_eq!(
            error.to_string(),
            "public input must be a closed object and omit bound fields"
        ),
        other => panic!("expected an invalid refusal, got {other:?}"),
    }

    let mismatched = kata_manifest("kata_tool", TOOL_2, TENANT_A, 1, &"b".repeat(64));
    let package = service
        .create_draft(&tenant, &mismatched, &files(), &actor())
        .await
        .expect_err("a package digest mismatch is refused");
    match package {
        CatalogServiceError::Invalid(error) => {
            assert_eq!(error.to_string(), "package digest mismatch");
        }
        other => panic!("expected an invalid refusal, got {other:?}"),
    }
    let matching = kata_manifest("kata_tool", TOOL_2, TENANT_A, 1, &package_digest(&files()));
    service
        .create_draft(&tenant, &matching, &files(), &actor())
        .await
        .expect("a matching package digest creates the draft");

    let created = service
        .create_draft(
            &tenant,
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 1),
            &files(),
            &actor(),
        )
        .await
        .expect("valid draft");
    assert_eq!(created.status, VersionStatus::Draft);
    let appended = service
        .append_draft(&append_request(
            &tenant,
            &tool_id(TOOL_1),
            &manifest("synthetic_tool", TOOL_1, TENANT_A, 2),
            &files(),
            &actor(),
            Some(version(1)),
            false,
        ))
        .await
        .expect("valid append");
    assert_eq!(appended.version.get(), 2);
    let published = service
        .transition(
            &tenant,
            &tool_id(TOOL_1),
            version(2),
            VersionStatus::Published,
            &actor(),
            version(2),
        )
        .await
        .expect("published");
    assert_eq!(published.status, VersionStatus::Published);
    fixture.finish().await;
}
