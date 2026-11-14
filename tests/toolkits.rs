//! Toolkit write-path persistence against a real Postgres 18. Each test fails if the behaviour
//! it covers is removed.
//!
//! Server selection mirrors `tests/storage.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL` (a URL
//! whose user may CREATE DATABASE), else an ephemeral `postgres:18` container started here with
//! docker and removed afterwards, else FAIL (never skip). `TEST_PG_REGISTRY` may name a registry
//! mirror. Each test gets its own fresh database, dropped at the end.

use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, PgConnection, PgPool};

use mcp_server_rs::auth::{Principal, Rfc4122Uuid};
use mcp_server_rs::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{
    Attribution, Constraint, OperationConstraints, ToolLimits, ToolManifest,
};
use mcp_server_rs::catalog::package::PackageFile;
use mcp_server_rs::catalog::toolkit_models::{
    BindingSpec, BoundContext, EffectiveTool, ToolReference, ToolkitDescriptor, ToolkitManifest,
    ToolkitReference,
};
use mcp_server_rs::db;
use mcp_server_rs::storage::catalog::{CatalogRepository, CatalogStoreError};
use mcp_server_rs::storage::toolkits as toolkit_store;
use mcp_server_rs::toolkits::resolver::{ResolveError, SelectionResolver};
use mcp_server_rs::toolkits::service::{ToolkitService, ToolkitServiceError};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const TENANT_PLATFORM: &str = "10000000-0000-7000-8000-0000000000ff";
const LICENSE: &str = "30000000-0000-4000-8000-000000000001";
const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000000ff";
const TOOL_ALPHA: &str = "20000000-0000-7000-8000-000000000001";
const TOOL_ZETA: &str = "20000000-0000-7000-8000-000000000002";
const TOOL_GAMMA: &str = "20000000-0000-7000-8000-000000000003";
const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
const OPERATION_BETA: &str = "40000000-0000-7000-8000-000000000002";
const TOOLKIT_1: &str = "01900000-0000-7000-8000-000000000001";
const TOOLKIT_2: &str = "01900000-0000-7000-8000-000000000002";
const TOOLKIT_3: &str = "01900000-0000-7000-8000-000000000003";
const TOOLKIT_UNKNOWN: &str = "01900000-0000-7000-8000-0000000000ff";

// ── the real-server harness (the same one `tests/storage.rs` uses) ─────────────────────────

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
        let name = format!("mcp_toolkits_{}_{nanos}", std::process::id());
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

    fn service(&self) -> ToolkitService {
        ToolkitService::new(
            self.pool.clone(),
            SelectionResolver {
                platform_tenant_id: authority(TENANT_PLATFORM),
            },
            // No credential profile is validated on the toolkit write path.
            None,
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

fn identity(value: &str) -> Uuid7 {
    Uuid7::new(value).expect("toolkit identity")
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

fn principal(tenant: &str, management: bool) -> Principal {
    Principal {
        tenant_id: Rfc4122Uuid::parse(tenant).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(LICENSE).expect("licence identity"),
        subject: "agent-09".to_owned(),
        binding_id: None,
        binding_revision: None,
        management,
        platform: false,
    }
}

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "package/main.py".to_owned(),
        content: "print('synthetic')\n".to_owned(),
    }]
}

/// A strict, valid tool manifest. The runtime is external so no package digest is involved.
fn tool_json(name: &str, tool: &str) -> Value {
    json!({
        "schema_version": 1,
        "tool_id": tool,
        "tenant_id": TENANT_A,
        "version": 1,
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
    })
}

fn tool_manifest(name: &str, tool: &str) -> ToolManifest {
    serde_json::from_value(tool_json(name, tool)).expect("valid tool manifest")
}

/// A strict, valid toolkit manifest selecting exact tools and inclusions.
fn toolkit_manifest(
    toolkit: &str,
    tenant: &str,
    toolkit_version: u32,
    name: &str,
    tools: &[(&str, u32)],
    includes: &[(&str, u32)],
) -> ToolkitManifest {
    let tools: Vec<Value> = tools
        .iter()
        .map(|(tool, tool_version)| {
            json!({"tool": {"id": tool, "version": tool_version, "tenant_id": tenant}})
        })
        .collect();
    let includes: Vec<Value> = includes
        .iter()
        .map(|(id, include_version)| json!({"id": id, "version": include_version}))
        .collect();
    serde_json::from_value(json!({
        "schema_version": 1,
        "toolkit_id": toolkit,
        "tenant_id": tenant,
        "version": toolkit_version,
        "name": name,
        "description": "Synthetic toolkit",
        "tools": tools,
        "includes": includes,
    }))
    .expect("valid toolkit manifest")
}

/// A published tool owned by tenant A.
async fn published_tool(fixture: &Fixture, tool: &str, name: &str) {
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    repository
        .create(&tenant, &tool_manifest(name, tool), &files(), &actor())
        .await
        .expect("create tool");
    repository
        .transition(
            &tenant,
            &identity(tool),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
}

async fn create_toolkit(service: &ToolkitService, manifest: &ToolkitManifest) -> ToolkitDescriptor {
    service
        .write(&principal(TENANT_A, true), manifest, None)
        .await
        .expect("create toolkit")
}

fn forbidden(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Forbidden(message) => message,
        other => panic!("expected forbidden, got {other:?}"),
    }
}

fn invalid(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Invalid(message) => message,
        other => panic!("expected invalid, got {other:?}"),
    }
}

fn conflict(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Conflict(message) => message,
        other => panic!("expected conflict, got {other:?}"),
    }
}

fn not_found(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Store(CatalogStoreError::NotFound(message)) => message,
        other => panic!("expected not-found, got {other:?}"),
    }
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_flattens_tools_sorted_by_public_name() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ZETA, "zeta_tool").await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_1,
        TENANT_A,
        1,
        "synthetic_toolkit",
        &[(TOOL_ZETA, 1), (TOOL_ALPHA, 1)],
        &[],
    );
    let created = create_toolkit(&service, &manifest).await;
    assert_eq!(created.revision.get(), 1);
    assert_eq!(created.status, VersionStatus::Draft);
    assert_eq!(created.manifest.version.get(), 1);
    assert_eq!(created.manifest.toolkit_id.as_str(), TOOLKIT_1);
    assert_eq!(created.manifest.name.as_str(), "synthetic_toolkit");
    assert_eq!(created.tools.len(), 2);
    assert_eq!(created.tools[0].public_name.as_str(), "alpha_tool");
    assert_eq!(created.tools[0].tool.id.as_str(), TOOL_ALPHA);
    assert_eq!(created.tools[1].public_name.as_str(), "zeta_tool");
    assert_eq!(created.tools[1].tool.id.as_str(), TOOL_ZETA);
    fixture.finish().await;
}

#[tokio::test]
async fn a_first_version_other_than_one_is_invalid() {
    let fixture = Fixture::new().await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_1,
        TENANT_A,
        2,
        "synthetic_toolkit",
        &[(TOOL_ALPHA, 1)],
        &[],
    );
    let refused = service
        .write(&principal(TENANT_A, true), &manifest, None)
        .await
        .expect_err("version two cannot create");
    assert_eq!(invalid(refused), "first toolkit version must be one");
    fixture.finish().await;
}

#[tokio::test]
async fn a_foreign_tenant_manifest_is_forbidden() {
    let fixture = Fixture::new().await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_1,
        TENANT_B,
        1,
        "synthetic_toolkit",
        &[(TOOL_ALPHA, 1)],
        &[],
    );
    let refused = service
        .write(&principal(TENANT_A, true), &manifest, None)
        .await
        .expect_err("a foreign tenant's toolkit cannot be written");
    assert_eq!(forbidden(refused), "tenant mismatch");
    fixture.finish().await;
}

#[tokio::test]
async fn a_non_management_principal_is_forbidden() {
    let fixture = Fixture::new().await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_1,
        TENANT_A,
        1,
        "synthetic_toolkit",
        &[(TOOL_ALPHA, 1)],
        &[],
    );
    let refused = service
        .write(&principal(TENANT_A, false), &manifest, None)
        .await
        .expect_err("only management may write toolkits");
    assert_eq!(forbidden(refused), "management authorization required");
    fixture.finish().await;
}

#[tokio::test]
async fn append_discards_the_supplied_version_and_bumps_revision() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let created = create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let appended = service
        .write(
            &operator,
            &toolkit_manifest(
                TOOLKIT_1,
                TENANT_A,
                9,
                "synthetic_toolkit",
                &[(TOOL_ALPHA, 1)],
                &[],
            ),
            Some(created.revision),
        )
        .await
        .expect("append");
    assert_eq!(appended.manifest.version.get(), 2);
    assert_eq!(appended.revision.get(), 2);
    assert_eq!(appended.status, VersionStatus::Draft);
    let mut conn = fixture.pool.acquire().await.expect("connection");
    let stored = toolkit_store::get_toolkit(
        &mut conn,
        &authority(TENANT_A),
        &identity(TOOLKIT_1),
        version(2),
    )
    .await
    .expect("stored version two");
    assert_eq!(stored, appended);
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn append_refuses_a_name_change() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let created = create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let refused = service
        .write(
            &operator,
            &toolkit_manifest(
                TOOLKIT_1,
                TENANT_A,
                1,
                "renamed_toolkit",
                &[(TOOL_ALPHA, 1)],
                &[],
            ),
            Some(created.revision),
        )
        .await
        .expect_err("the name is immutable");
    assert_eq!(conflict(refused), "toolkit name is immutable");
    fixture.finish().await;
}

#[tokio::test]
async fn append_refuses_a_stale_expected_revision() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_1,
        TENANT_A,
        1,
        "synthetic_toolkit",
        &[(TOOL_ALPHA, 1)],
        &[],
    );
    create_toolkit(&service, &manifest).await;
    let refused = service
        .write(&principal(TENANT_A, true), &manifest, Some(version(2)))
        .await
        .expect_err("the identity is still at revision one");
    assert_eq!(conflict(refused), "stale expected revision");
    fixture.finish().await;
}

#[tokio::test]
async fn append_to_an_unknown_identity_is_not_found() {
    let fixture = Fixture::new().await;
    let service = fixture.service();
    let manifest = toolkit_manifest(
        TOOLKIT_UNKNOWN,
        TENANT_A,
        1,
        "synthetic_toolkit",
        &[(TOOL_ALPHA, 1)],
        &[],
    );
    let refused = service
        .write(&principal(TENANT_A, true), &manifest, Some(version(1)))
        .await
        .expect_err("no such toolkit");
    assert_eq!(not_found(refused), "toolkit not found");
    fixture.finish().await;
}

#[tokio::test]
async fn the_transition_matrix_is_enforced() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let created = create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let published = service
        .transition(
            &operator,
            &identity(TOOLKIT_1),
            version(1),
            VersionStatus::Published,
            created.revision,
        )
        .await
        .expect("draft to published");
    assert_eq!(published.status, VersionStatus::Published);
    assert_eq!(published.revision.get(), 2);
    let disabled = service
        .transition(
            &operator,
            &identity(TOOLKIT_1),
            version(1),
            VersionStatus::Disabled,
            published.revision,
        )
        .await
        .expect("published to disabled");
    assert_eq!(disabled.status, VersionStatus::Disabled);
    assert_eq!(disabled.revision.get(), 3);
    let refused = service
        .transition(
            &operator,
            &identity(TOOLKIT_1),
            version(1),
            VersionStatus::Published,
            disabled.revision,
        )
        .await
        .expect_err("disabled cannot publish again");
    assert_eq!(conflict(refused), "invalid toolkit transition");
    fixture.finish().await;
}

#[tokio::test]
async fn publishing_after_an_inclusion_was_disabled_is_a_dependency_mismatch() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let included = create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "included_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let included = service
        .transition(
            &operator,
            &identity(TOOLKIT_1),
            version(1),
            VersionStatus::Published,
            included.revision,
        )
        .await
        .expect("publish the included toolkit");
    assert_eq!(included.status, VersionStatus::Published);
    let including = create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_2,
            TENANT_A,
            1,
            "including_toolkit",
            &[],
            &[(TOOLKIT_1, 1)],
        ),
    )
    .await;
    assert_eq!(including.tools.len(), 1);
    assert_eq!(including.tools[0].public_name.as_str(), "alpha_tool");
    let disabled = service
        .transition(
            &operator,
            &identity(TOOLKIT_1),
            version(1),
            VersionStatus::Disabled,
            included.revision,
        )
        .await
        .expect("disable the included toolkit");
    assert_eq!(disabled.status, VersionStatus::Disabled);
    let refused = service
        .transition(
            &operator,
            &identity(TOOLKIT_2),
            version(1),
            VersionStatus::Published,
            including.revision,
        )
        .await
        .expect_err("the inclusion no longer resolves");
    assert_eq!(conflict(refused), "toolkit dependency mismatch");
    fixture.finish().await;
}

#[tokio::test]
async fn another_tenant_cannot_read_the_toolkit() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    create_toolkit(
        &service,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let mut conn = fixture.pool.acquire().await.expect("connection");
    let read = toolkit_store::get_toolkit(
        &mut conn,
        &authority(TENANT_B),
        &identity(TOOLKIT_1),
        version(1),
    )
    .await;
    assert!(matches!(
        read,
        Err(CatalogStoreError::NotFound("toolkit version not found"))
    ));
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn list_returns_identities_in_order_and_pages() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let service = fixture.service();
    for (id, name) in [
        (TOOLKIT_1, "first_toolkit"),
        (TOOLKIT_2, "second_toolkit"),
        (TOOLKIT_3, "third_toolkit"),
    ] {
        create_toolkit(
            &service,
            &toolkit_manifest(id, TENANT_A, 1, name, &[(TOOL_ALPHA, 1)], &[]),
        )
        .await;
    }
    let page = service
        .list(&principal(TENANT_A, true), 2, 1)
        .await
        .expect("list");
    assert_eq!(page.len(), 2);
    assert_eq!(page[0].toolkit_id.as_str(), TOOLKIT_2);
    assert_eq!(page[0].name.as_str(), "second_toolkit");
    assert_eq!(page[0].revision.get(), 1);
    assert_eq!(page[1].toolkit_id.as_str(), TOOLKIT_3);
    assert_eq!(page[1].name.as_str(), "third_toolkit");
    assert_eq!(page[1].revision.get(), 1);
    fixture.finish().await;
}

// ── binding selection (`SelectionResolver.binding`) ─────────────────────────────────────────

fn manifest(value: Value) -> ToolManifest {
    serde_json::from_value(value).expect("valid tool manifest")
}

fn writer() -> Value {
    json!({"subject": "agent-09", "license_id": LICENSE})
}

/// A published platform service, the dependency every seeded operation names.
async fn seed_service(fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO public.mcp_services(service_id,service_key,created_by) \
         VALUES ($1::uuid,'synthetic_service',$2)",
    )
    .bind(SERVICE_ID)
    .bind(writer())
    .execute(&fixture.pool)
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
    .bind(writer())
    .execute(&fixture.pool)
    .await
    .expect("service version");
    sqlx::query(
        "UPDATE public.mcp_service_versions SET status='published' \
         WHERE service_id = $1::uuid AND version = 1",
    )
    .bind(SERVICE_ID)
    .execute(&fixture.pool)
    .await
    .expect("publish service");
}

/// A published operation whose manifest carries the caller's overrides.
async fn seed_operation(fixture: &Fixture, operation: &str, overrides: Value) {
    let mut manifest = json!({
        "schema_version": 1,
        "operation_id": operation,
        "version": 1,
        "service": {"id": SERVICE_ID, "version": 1},
        "method": "GET",
        "path_template": "/synthetic",
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "mappings": [],
        "effect": "read_only",
        "timeout_seconds": 30,
        "pagination_limit": 100,
        "max_response_bytes": 4096
    });
    for (key, value) in overrides.as_object().expect("an override object") {
        manifest[key] = value.clone();
    }
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(operation)
    .bind(SERVICE_ID)
    .bind(manifest)
    .bind(writer())
    .execute(&fixture.pool)
    .await
    .expect("operation version");
    sqlx::query(
        "UPDATE public.mcp_operation_versions SET status='published' \
         WHERE operation_id = $1::uuid AND version = 1",
    )
    .bind(operation)
    .execute(&fixture.pool)
    .await
    .expect("publish operation");
}

/// A published tool from a fully shaped manifest.
async fn published_tool_manifest(fixture: &Fixture, manifest: &ToolManifest) {
    let repository = fixture.repository();
    let tenant = manifest.tenant_id.clone();
    repository
        .create(&tenant, manifest, &files(), &actor())
        .await
        .expect("create tool");
    repository
        .transition(
            &tenant,
            &manifest.tool_id,
            manifest.version,
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
}

/// Create a toolkit and publish it, returning the published descriptor.
async fn published_toolkit(fixture: &Fixture, manifest: &ToolkitManifest) -> ToolkitDescriptor {
    let service = fixture.service();
    let drafted = create_toolkit(&service, manifest).await;
    service
        .transition(
            &principal(TENANT_A, true),
            &manifest.toolkit_id,
            manifest.version,
            VersionStatus::Published,
            drafted.revision,
        )
        .await
        .expect("publish toolkit")
}

fn applicability_of(mut manifest: ToolkitManifest, work_type: &str) -> ToolkitManifest {
    manifest.applicability.work_type = Some(Name::new(work_type).expect("valid label"));
    manifest
}

fn operation_constraints(operation: &str, rules: Value) -> OperationConstraints {
    serde_json::from_value(json!({
        "operation": {"id": operation, "version": 1},
        "rules": rules,
    }))
    .expect("valid operation constraints")
}

fn context() -> BoundContext {
    BoundContext {
        tenant_id: authority(TENANT_A),
        project_id: None,
        workspace_id: None,
        project_phase: None,
        work_type: None,
        card_stage: None,
        responsibility: None,
        test_command: None,
        reviewed_commit: None,
    }
}

fn spec_for(context: BoundContext, toolkits: &[&str]) -> BindingSpec {
    BindingSpec {
        schema_version: 1,
        credential_profile_id: identity("20000000-0000-7000-8000-0000000000f0"),
        toolkits: toolkits
            .iter()
            .map(|toolkit| ToolkitReference {
                id: identity(toolkit),
                version: version(1),
                tenant_id: Some(authority(TENANT_A)),
            })
            .collect(),
        tool_subset: None,
        context,
        operation_constraints: Vec::new(),
        limits: ToolLimits::default(),
        expires_at: "2026-11-14T00:00:00Z".parse().expect("an instant"),
        enabled: true,
    }
}

fn reference(tool: &str, owner: &str) -> ToolReference {
    ToolReference {
        id: identity(tool),
        version: version(1),
        tenant_id: authority(owner),
    }
}

async fn binding_of(
    fixture: &Fixture,
    spec: &BindingSpec,
) -> Result<Vec<EffectiveTool>, ResolveError> {
    let resolver = SelectionResolver {
        platform_tenant_id: authority(TENANT_PLATFORM),
    };
    let mut conn = fixture.pool.acquire().await.expect("connection");
    resolver
        .binding(&mut conn, &authority(TENANT_A), spec, false)
        .await
}

fn selection_invalid(error: ResolveError) -> &'static str {
    match error {
        ResolveError::Invalid(message) => message,
        other => panic!("expected invalid, got {other:?}"),
    }
}

fn selection_conflict(error: ResolveError) -> &'static str {
    match error {
        ResolveError::Conflict(message) => message,
        other => panic!("expected conflict, got {other:?}"),
    }
}

fn selection_not_found(error: ResolveError) -> &'static str {
    match error {
        ResolveError::NotFound(message) => message,
        other => panic!("expected not-found, got {other:?}"),
    }
}

#[tokio::test]
async fn binding_returns_the_flattened_selection_narrowed_by_spec_limits() {
    let fixture = Fixture::new().await;
    let mut zeta = tool_json("zeta_tool", TOOL_ZETA);
    zeta["operation"] = json!("synthetic.zeta_tool");
    published_tool_manifest(&fixture, &manifest(zeta)).await;
    let mut alpha = tool_json("alpha_tool", TOOL_ALPHA);
    alpha["operation"] = json!("synthetic.alpha_tool");
    published_tool_manifest(&fixture, &manifest(alpha)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ZETA, 1), (TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let mut spec = spec_for(context(), &[TOOLKIT_1]);
    spec.limits = ToolLimits {
        wall_seconds: 30,
        api_calls: 3,
        ..ToolLimits::default()
    };
    let resolved = binding_of(&fixture, &spec).await.expect("binding resolves");
    assert_eq!(resolved.len(), 2);
    assert_eq!(resolved[0].public_name.as_str(), "alpha_tool");
    assert_eq!(resolved[0].tool.id.as_str(), TOOL_ALPHA);
    assert_eq!(resolved[1].public_name.as_str(), "zeta_tool");
    assert_eq!(resolved[1].tool.id.as_str(), TOOL_ZETA);
    let narrowed = ToolLimits {
        wall_seconds: 30,
        api_calls: 3,
        ..ToolLimits::default()
    };
    assert_eq!(resolved[0].limits, narrowed);
    assert_eq!(resolved[1].limits, narrowed);
    assert!(
        resolved
            .iter()
            .all(|entry| entry.operation_constraints.is_empty())
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_context_for_another_tenant() {
    let fixture = Fixture::new().await;
    let mut context = context();
    context.tenant_id = authority(TENANT_B);
    let refused = binding_of(&fixture, &spec_for(context, &[TOOLKIT_1]))
        .await
        .expect_err("another tenant's context");
    assert_eq!(
        selection_invalid(refused),
        "bound tenant differs from authenticated tenant"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_foreign_toolkit_pin() {
    let fixture = Fixture::new().await;
    let mut spec = spec_for(context(), &[TOOLKIT_1]);
    spec.toolkits[0].tenant_id = Some(authority(TENANT_B));
    let refused = binding_of(&fixture, &spec)
        .await
        .expect_err("a foreign pin");
    assert_eq!(selection_not_found(refused), "toolkit version not found");
    fixture.finish().await;
}

#[tokio::test]
async fn binding_keeps_only_a_valid_tool_subset() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ZETA, "zeta_tool").await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ZETA, 1), (TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let mut outside = spec_for(context(), &[TOOLKIT_1]);
    outside.tool_subset = Some(vec![reference(TOOL_GAMMA, TENANT_A)]);
    let refused = binding_of(&fixture, &outside)
        .await
        .expect_err("the subset names a non-member");
    assert_eq!(
        selection_invalid(refused),
        "subset contains tools outside toolkit membership"
    );
    let mut foreign = spec_for(context(), &[TOOLKIT_1]);
    foreign.tool_subset = Some(vec![reference(TOOL_ZETA, TENANT_B)]);
    let refused = binding_of(&fixture, &foreign)
        .await
        .expect_err("the owner is part of the reference");
    assert_eq!(
        selection_invalid(refused),
        "subset contains tools outside toolkit membership"
    );
    let mut valid = spec_for(context(), &[TOOLKIT_1]);
    valid.tool_subset = Some(vec![reference(TOOL_ZETA, TENANT_A)]);
    let filtered = binding_of(&fixture, &valid)
        .await
        .expect("a member subset resolves");
    assert_eq!(filtered.len(), 1);
    assert_eq!(filtered[0].public_name.as_str(), "zeta_tool");
    assert_eq!(filtered[0].tool.id.as_str(), TOOL_ZETA);
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_an_operation_collision() {
    let fixture = Fixture::new().await;
    let mut alpha = tool_json("alpha_tool", TOOL_ALPHA);
    alpha["operation"] = json!("synthetic.collision");
    published_tool_manifest(&fixture, &manifest(alpha)).await;
    let mut zeta = tool_json("zeta_tool", TOOL_ZETA);
    zeta["operation"] = json!("synthetic.collision");
    published_tool_manifest(&fixture, &manifest(zeta)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1), (TOOL_ZETA, 1)],
            &[],
        ),
    )
    .await;
    let refused = binding_of(&fixture, &spec_for(context(), &[TOOLKIT_1]))
        .await
        .expect_err("two tools, one canonical operation");
    assert_eq!(
        selection_conflict(refused),
        "operation collision in effective selection"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_constraint_on_an_unselected_operation() {
    let fixture = Fixture::new().await;
    seed_service(&fixture).await;
    seed_operation(&fixture, OPERATION_ALPHA, json!({})).await;
    let mut tool = tool_json("alpha_tool", TOOL_ALPHA);
    tool["allowed_operations"] = json!([{"id": OPERATION_ALPHA, "version": 1}]);
    published_tool_manifest(&fixture, &manifest(tool)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let mut spec = spec_for(context(), &[TOOLKIT_1]);
    spec.operation_constraints = vec![operation_constraints(
        OPERATION_BETA,
        json!([{"kind": "set_membership", "argument": "/tag", "values": ["a"]}]),
    )];
    let refused = binding_of(&fixture, &spec)
        .await
        .expect_err("no selected tool allows the operation");
    assert_eq!(
        selection_invalid(refused),
        "binding constraint targets an unselected operation"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_appends_a_spec_constraint_to_the_toolkit_constraint() {
    let fixture = Fixture::new().await;
    seed_service(&fixture).await;
    seed_operation(&fixture, OPERATION_ALPHA, json!({})).await;
    let mut tool = tool_json("alpha_tool", TOOL_ALPHA);
    tool["allowed_operations"] = json!([{"id": OPERATION_ALPHA, "version": 1}]);
    tool["operation_constraints"] = json!([{
        "operation": {"id": OPERATION_ALPHA, "version": 1},
        "rules": [{"kind": "set_membership", "argument": "/tag", "values": ["a", "b"]}]
    }]);
    published_tool_manifest(&fixture, &manifest(tool)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let mut spec = spec_for(context(), &[TOOLKIT_1]);
    spec.operation_constraints = vec![operation_constraints(
        OPERATION_ALPHA,
        json!([{"kind": "set_membership", "argument": "/tag", "values": ["b", "c"]}]),
    )];
    let resolved = binding_of(&fixture, &spec)
        .await
        .expect("the constraints intersect");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].operation_constraints.len(), 2);
    assert_eq!(
        resolved[0].operation_constraints[0].operation.id.as_str(),
        OPERATION_ALPHA
    );
    assert_eq!(
        resolved[0].operation_constraints[1].operation.id.as_str(),
        OPERATION_ALPHA
    );
    let tool_rules = match &resolved[0].operation_constraints[0].rules[..] {
        [Constraint::SetMembership(rule)] => rule.values.clone(),
        other => panic!("expected the tool's set membership, got {other:?}"),
    };
    assert_eq!(tool_rules, vec![json!("a"), json!("b")]);
    let spec_rules = match &resolved[0].operation_constraints[1].rules[..] {
        [Constraint::SetMembership(rule)] => rule.values.clone(),
        other => panic!("expected the spec's set membership, got {other:?}"),
    };
    assert_eq!(spec_rules, vec![json!("b"), json!("c")]);
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_context_missing_a_required_property() {
    let fixture = Fixture::new().await;
    let mut tool = tool_json("alpha_tool", TOOL_ALPHA);
    tool["context_schema"] = json!({
        "type": "object",
        "properties": {"project_id": {"type": "string"}},
        "required": ["project_id"],
        "additionalProperties": false
    });
    published_tool_manifest(&fixture, &manifest(tool)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let refused = binding_of(&fixture, &spec_for(context(), &[TOOLKIT_1]))
        .await
        .expect_err("the context lacks project_id");
    assert_eq!(
        selection_invalid(refused),
        "instance does not match declared schema"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_context_mapping_pointer_the_context_lacks() {
    let fixture = Fixture::new().await;
    seed_service(&fixture).await;
    seed_operation(
        &fixture,
        OPERATION_ALPHA,
        json!({
            "mappings": [{
                "location": "body",
                "target": "/owner",
                "value": {"source": "context", "pointer": "/project_id"}
            }]
        }),
    )
    .await;
    let mut tool = tool_json("alpha_tool", TOOL_ALPHA);
    tool["allowed_operations"] = json!([{"id": OPERATION_ALPHA, "version": 1}]);
    published_tool_manifest(&fixture, &manifest(tool)).await;
    published_toolkit(
        &fixture,
        &toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
    )
    .await;
    let refused = binding_of(&fixture, &spec_for(context(), &[TOOLKIT_1]))
        .await
        .expect_err("the mapping pointer misses");
    assert_eq!(
        selection_invalid(refused),
        "required bound context is missing"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn binding_refuses_a_toolkit_the_context_does_not_satisfy() {
    let fixture = Fixture::new().await;
    published_tool(&fixture, TOOL_ALPHA, "alpha_tool").await;
    let manifest = applicability_of(
        toolkit_manifest(
            TOOLKIT_1,
            TENANT_A,
            1,
            "synthetic_toolkit",
            &[(TOOL_ALPHA, 1)],
            &[],
        ),
        "review",
    );
    published_toolkit(&fixture, &manifest).await;
    let refused = binding_of(&fixture, &spec_for(context(), &[TOOLKIT_1]))
        .await
        .expect_err("the context has no work type");
    assert_eq!(
        selection_invalid(refused),
        "binding context does not satisfy toolkit applicability"
    );
    let mut satisfied = context();
    satisfied.work_type = Some(Name::new("review").expect("valid label"));
    let resolved = binding_of(&fixture, &spec_for(satisfied, &[TOOLKIT_1]))
        .await
        .expect("the label matches");
    assert_eq!(resolved.len(), 1);
    assert_eq!(resolved[0].public_name.as_str(), "alpha_tool");
    fixture.finish().await;
}
