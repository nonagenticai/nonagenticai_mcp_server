//! Binding persistence, token rules and the real binding authority against a real Postgres 18.
//! Each test fails if the behaviour it covers is removed.
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
use sqlx::{AssertSqlSafe, Connection, PgConnection, PgPool, Row};

use mcp_server_rs::auth::pg_bindings::PgBindingAuthority;
use mcp_server_rs::auth::{
    AuthError, BindingAuthority, LicenseIdentity, Principal, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{Attribution, ToolManifest};
use mcp_server_rs::catalog::package::PackageFile;
use mcp_server_rs::catalog::toolkit_models::{BindingSpec, ToolkitDescriptor, ToolkitManifest};
use mcp_server_rs::db;
use mcp_server_rs::storage::bindings;
use mcp_server_rs::storage::catalog::{CatalogRepository, CatalogStoreError};
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::toolkits::service::{ToolkitService, ToolkitServiceError};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const TENANT_PLATFORM: &str = "10000000-0000-7000-8000-0000000000ff";
const LICENSE: &str = "30000000-0000-4000-8000-000000000001";
const OTHER_LICENSE: &str = "30000000-0000-4000-8000-000000000002";
const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000000ff";
const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
const TOOL_ALPHA: &str = "20000000-0000-7000-8000-000000000001";
const TOOL_ZETA: &str = "20000000-0000-7000-8000-000000000002";
const TOOLKIT_1: &str = "01900000-0000-7000-8000-000000000001";
const PROFILE: &str = "01900000-0000-7000-8000-0000000000f1";
const PROFILE_2: &str = "01900000-0000-7000-8000-0000000000f2";
const PROJECT: &str = "01900000-0000-7000-8000-0000000000c1";
const BINDING: &str = "01900000-0000-7000-8000-0000000000b1";
const BINDING_REVOKED: &str = "01900000-0000-7000-8000-0000000000b2";
const BINDING_DISABLED: &str = "01900000-0000-7000-8000-0000000000b3";
const BINDING_EXPIRED: &str = "01900000-0000-7000-8000-0000000000b4";
const BINDING_FOREIGN: &str = "01900000-0000-7000-8000-0000000000b5";
const BINDING_UNKNOWN: &str = "01900000-0000-7000-8000-0000000000bf";
const FUTURE: &str = "2033-05-18T03:33:20Z";
const PAST: &str = "2001-09-09T01:46:40Z";

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
        let name = format!("mcp_bindings_{}_{nanos}", std::process::id());
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
            Some("synthetic".to_owned()),
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

fn actor_snapshot() -> Value {
    json!({"subject": "agent-09", "license_id": LICENSE})
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

fn license_identity(license: &str) -> LicenseIdentity {
    LicenseIdentity {
        tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(license).expect("licence identity"),
        subject: "svc:synthetic:mcp".to_owned(),
        subject_kind: Some(SubjectKind::Tenant),
    }
}

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "package/main.py".to_owned(),
        content: "print('synthetic')\n".to_owned(),
    }]
}

/// A strict, valid tool manifest. The runtime is external so no package digest is involved.
fn tool_manifest(name: &str, tool: &str) -> ToolManifest {
    serde_json::from_value(json!({
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
    }))
    .expect("valid tool manifest")
}

fn toolkit_manifest(tools: &[(&str, &str)]) -> ToolkitManifest {
    let tools: Vec<Value> = tools
        .iter()
        .map(|(tool, _)| json!({"tool": {"id": tool, "version": 1, "tenant_id": TENANT_A}}))
        .collect();
    serde_json::from_value(json!({
        "schema_version": 1,
        "toolkit_id": TOOLKIT_1,
        "tenant_id": TENANT_A,
        "version": 1,
        "name": "synthetic_toolkit",
        "description": "Synthetic toolkit",
        "tools": tools,
    }))
    .expect("valid toolkit manifest")
}

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
            &uuid7(tool),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
}

/// A published toolkit owned by tenant A, created through the real write path.
async fn seed_toolkit(fixture: &Fixture, tools: &[(&str, &str)]) -> ToolkitDescriptor {
    for (tool, name) in tools {
        published_tool(fixture, tool, name).await;
    }
    fixture
        .service()
        .write(&principal(TENANT_A, true), &toolkit_manifest(tools), None)
        .await
        .expect("create toolkit")
}

/// A credential profile row and its reference rows, gateway reference included.
///
/// `services` is the profile's service-reference array; the gateway reference is always the
/// row the binding runtime reads first.
async fn insert_profile_with(
    fixture: &Fixture,
    profile: &str,
    name: &str,
    gateway_license: &str,
    services: Value,
) {
    let manifest = json!({
        "schema_version": 1,
        "tenant_id": TENANT_A,
        "profile_id": profile,
        "name": name,
        "gateway": {
            "service": "gateway",
            "alias": "gateway",
            "license_id": gateway_license,
            "app_key": "synthetic"
        },
        "services": services
    });
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_credential_profiles(\
         tenant_id,profile_id,name,manifest,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$5)",
    )
    .bind(TENANT_A)
    .bind(profile)
    .bind(name)
    .bind(manifest)
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("insert credential profile");
    sqlx::query(
        "INSERT INTO public.mcp_credential_refs(\
         tenant_id,profile_id,service_key,alias,license_id,app_key) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5::uuid,$6)",
    )
    .bind(TENANT_A)
    .bind(profile)
    .bind("__gateway")
    .bind("gateway")
    .bind(gateway_license)
    .bind("synthetic")
    .execute(&mut *tx)
    .await
    .expect("insert gateway reference");
    for service in services.as_array().expect("service references") {
        sqlx::query(
            "INSERT INTO public.mcp_credential_refs(\
             tenant_id,profile_id,service_key,alias,license_id,app_key) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5::uuid,$6)",
        )
        .bind(TENANT_A)
        .bind(profile)
        .bind(service["service"].as_str().expect("service key"))
        .bind(service["alias"].as_str().expect("alias"))
        .bind(service["license_id"].as_str().expect("licence"))
        .bind(service["app_key"].as_str().expect("application key"))
        .execute(&mut *tx)
        .await
        .expect("insert service reference");
    }
    tx.commit().await.expect("commit credential profile");
}

/// A credential profile the binding may reference: gateway only, no service references.
async fn insert_profile(fixture: &Fixture) {
    insert_profile_with(fixture, PROFILE, "synthetic_profile", LICENSE, json!([])).await;
}

/// The service reference the synthetic service requires.
fn service_references() -> Value {
    json!([{
        "service": "synthetic_service",
        "alias": "synthetic",
        "license_id": LICENSE,
        "app_key": "synthetic"
    }])
}

/// A published platform service whose runner authenticates with a licence bearer.
async fn seed_service(fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO public.mcp_services(service_id,service_key,created_by) \
         VALUES ($1::uuid,'synthetic_service',$2)",
    )
    .bind(SERVICE_ID)
    .bind(actor_snapshot())
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
        "destination_alias": "synthetic_destination",
        "license_app_key": "synthetic",
        "auth_adapter": "license_bearer",
        "credential_profile_key": "synthetic_profile",
        "max_request_bytes": 4096,
        "max_response_bytes": 4096,
    }))
    .bind(actor_snapshot())
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

/// A published operation of the synthetic service.
async fn seed_operation(fixture: &Fixture, operation: &str) {
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(operation)
    .bind(SERVICE_ID)
    .bind(json!({
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
    }))
    .bind(actor_snapshot())
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

/// A strict tool manifest whose single operation is `operation`, allowed exactly once.
fn tool_manifest_with_operation(name: &str, tool: &str, operation: &str) -> ToolManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "tool_id": tool,
        "tenant_id": TENANT_A,
        "version": 1,
        "public_name": name,
        "operation": format!("synthetic.{name}"),
        "description": "Synthetic fixture",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "effect": "read_only",
        "allowed_operations": [{"id": operation, "version": 1}],
    }))
    .expect("valid tool manifest")
}

/// The full binding fixture: a published service and operation, a published tool that allows
/// the operation, and one published toolkit selecting that tool.
async fn published_binding_toolkit(
    fixture: &Fixture,
    tool: &str,
    name: &str,
    operation: &str,
) -> ToolkitDescriptor {
    seed_service(fixture).await;
    seed_operation(fixture, operation).await;
    let manifest = tool_manifest_with_operation(name, tool, operation);
    let repository = fixture.repository();
    let tenant = authority(TENANT_A);
    repository
        .create(&tenant, &manifest, &files(), &actor())
        .await
        .expect("create tool");
    repository
        .transition(
            &tenant,
            &uuid7(tool),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let drafted = service
        .write(&operator, &toolkit_manifest(&[(tool, name)]), None)
        .await
        .expect("create toolkit");
    service
        .transition(
            &operator,
            &uuid7(TOOLKIT_1),
            version(1),
            VersionStatus::Published,
            drafted.revision,
        )
        .await
        .expect("publish toolkit")
}

/// A binding spec pinning the synthetic toolkit.
fn binding_spec(profile: &str, expires_at: &str, context: Value) -> BindingSpec {
    serde_json::from_value(json!({
        "schema_version": 1,
        "credential_profile_id": profile,
        "toolkits": [{"id": TOOLKIT_1, "version": 1, "tenant_id": TENANT_A}],
        "context": context,
        "expires_at": expires_at,
    }))
    .expect("valid binding spec")
}

fn tenant_context() -> Value {
    json!({"tenant_id": TENANT_A})
}

fn invalid_error(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Invalid(message) => message,
        other => panic!("expected invalid, got {other:?}"),
    }
}

fn conflict_error(error: ToolkitServiceError) -> &'static str {
    match error {
        ToolkitServiceError::Conflict(message) => message,
        other => panic!("expected conflict, got {other:?}"),
    }
}

/// One raw `mcp_bindings` row, as a test case varies it.
struct BindingCase<'a> {
    binding: &'a str,
    token: &'a str,
    gateway_license: &'a str,
    enabled: bool,
    revoked: bool,
    expires_at: &'a str,
}

/// Insert a binding and its selection rows the way the reference's `write_binding` does: the
/// row and member rows in one transaction, with the token stored only as its digest.
async fn insert_binding(fixture: &Fixture, toolkit: &ToolkitDescriptor, case: BindingCase<'_>) {
    let spec = json!({
        "schema_version": 1,
        "credential_profile_id": PROFILE,
        "toolkits": [{"id": TOOLKIT_1, "version": 1, "tenant_id": TENANT_A}],
        "context": {"tenant_id": TENANT_A},
        "expires_at": case.expires_at,
        "enabled": case.enabled,
    });
    let tools = bindings::tools_json(&toolkit.tools).expect("binding tools snapshot");
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_bindings(\
         tenant_id,binding_id,gateway_license_id,credential_profile_id,token_sha256,spec,tools,\
         enabled,revoked,expires_at,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3::uuid,$4::uuid,$5,$6::jsonb,$7::jsonb,$8,$9,\
         ($6::jsonb->>'expires_at')::timestamptz,$10,$10)",
    )
    .bind(TENANT_A)
    .bind(case.binding)
    .bind(case.gateway_license)
    .bind(PROFILE)
    .bind(bindings::digest_token(case.token))
    .bind(spec)
    .bind(tools)
    .bind(case.enabled)
    .bind(case.revoked)
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("insert binding");
    let row = bindings::get_binding(&mut tx, &authority(TENANT_A), &uuid7(case.binding), false)
        .await
        .expect("binding row");
    let stored = bindings::descriptor(&row).expect("binding descriptor");
    bindings::binding_members(&mut tx, &stored)
        .await
        .expect("binding members");
    tx.commit().await.expect("commit binding");
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_enabled_binding_authenticates_and_inspects() {
    let fixture = Fixture::new().await;
    insert_profile(&fixture).await;
    let toolkit = seed_toolkit(
        &fixture,
        &[(TOOL_ALPHA, "alpha_tool"), (TOOL_ZETA, "zeta_tool")],
    )
    .await;
    let token = bindings::mint_token();
    insert_binding(
        &fixture,
        &toolkit,
        BindingCase {
            binding: BINDING,
            token: &token,
            gateway_license: LICENSE,
            enabled: true,
            revoked: false,
            expires_at: FUTURE,
        },
    )
    .await;

    let binding_authority = PgBindingAuthority::new(fixture.pool.clone());
    let resolved = binding_authority
        .authenticate(&license_identity(LICENSE), &token)
        .await
        .expect("an enabled binding resolves");
    assert_eq!(resolved.binding_id.to_string(), BINDING);
    assert_eq!(resolved.revision, 1);
    drop(binding_authority);

    let inspected = bindings::inspect(&fixture.pool, &authority(TENANT_A), &uuid7(BINDING))
        .await
        .expect("inspect");
    assert_eq!(inspected.binding_id.as_str(), BINDING);
    assert_eq!(inspected.tenant_id.as_str(), TENANT_A);
    assert_eq!(inspected.gateway_license_id.as_str(), LICENSE);
    assert_eq!(inspected.revision.get(), 1);
    assert!(!inspected.revoked);
    assert_eq!(inspected.spec.toolkits.len(), 1);
    assert_eq!(inspected.spec.toolkits[0].id.as_str(), TOOLKIT_1);
    assert_eq!(inspected.tools, toolkit.tools);

    let mut conn = fixture.pool.acquire().await.expect("connection");
    let row = bindings::get_binding(&mut conn, &authority(TENANT_A), &uuid7(BINDING), true)
        .await
        .expect("locked row");
    assert!(bindings::check_revision(&row, version(1)).is_ok());
    assert!(matches!(
        bindings::check_revision(&row, version(2)),
        Err(CatalogStoreError::Conflict("expected revision conflict"))
    ));
    assert_eq!(row.expires_at.to_rfc3339(), "2033-05-18T03:33:20+00:00");
    drop(conn);

    let mut tx = fixture.pool.begin().await.expect("transaction");
    bindings::audit_binding(
        &mut tx,
        &authority(TENANT_A),
        &actor(),
        &uuid7(BINDING),
        version(1),
        "binding.changed",
    )
    .await
    .expect("audit binding");
    tx.commit().await.expect("commit audit");
    let mut conn = fixture.pool.acquire().await.expect("connection");
    let audited = sqlx::query(
        "SELECT tenant_id::text AS tenant_id, entity_id::text AS entity_id, revision, action, \
         artifact_version FROM public.mcp_access_events WHERE entity_id = $1::uuid",
    )
    .bind(BINDING)
    .fetch_one(&mut *conn)
    .await
    .expect("audit row");
    assert_eq!(
        audited.try_get::<String, _>("tenant_id").expect("tenant"),
        TENANT_A
    );
    assert_eq!(
        audited.try_get::<String, _>("entity_id").expect("entity"),
        BINDING
    );
    assert_eq!(audited.try_get::<i64, _>("revision").expect("revision"), 1);
    assert_eq!(
        audited.try_get::<String, _>("action").expect("action"),
        "binding.changed"
    );
    assert!(
        audited
            .try_get::<Option<i32>, _>("artifact_version")
            .expect("artifact version")
            .is_none(),
        "a binding audit row carries no artifact version"
    );
    drop(conn);

    let mut conn = fixture.pool.acquire().await.expect("connection");
    assert!(matches!(
        bindings::get_binding(
            &mut conn,
            &authority(TENANT_A),
            &uuid7(BINDING_UNKNOWN),
            false
        )
        .await,
        Err(CatalogStoreError::NotFound("binding not found"))
    ));
    assert!(matches!(
        bindings::get_binding(&mut conn, &authority(TENANT_B), &uuid7(BINDING), false).await,
        Err(CatalogStoreError::NotFound("binding not found"))
    ));
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn a_wrong_token_is_refused() {
    let fixture = Fixture::new().await;
    insert_profile(&fixture).await;
    let toolkit = seed_toolkit(&fixture, &[(TOOL_ALPHA, "alpha_tool")]).await;
    let token = bindings::mint_token();
    insert_binding(
        &fixture,
        &toolkit,
        BindingCase {
            binding: BINDING,
            token: &token,
            gateway_license: LICENSE,
            enabled: true,
            revoked: false,
            expires_at: FUTURE,
        },
    )
    .await;

    let binding_authority = PgBindingAuthority::new(fixture.pool.clone());
    let refused = binding_authority
        .authenticate(&license_identity(LICENSE), &bindings::mint_token())
        .await;
    assert_eq!(refused, Err(AuthError::Unauthorized));
    drop(binding_authority);
    fixture.finish().await;
}

#[tokio::test]
async fn revoked_disabled_expired_and_foreign_licence_bindings_are_refused() {
    let fixture = Fixture::new().await;
    insert_profile(&fixture).await;
    let toolkit = seed_toolkit(&fixture, &[(TOOL_ALPHA, "alpha_tool")]).await;
    let revoked = bindings::mint_token();
    let disabled = bindings::mint_token();
    let expired = bindings::mint_token();
    let foreign = bindings::mint_token();
    for case in [
        BindingCase {
            binding: BINDING_REVOKED,
            token: &revoked,
            gateway_license: LICENSE,
            enabled: true,
            revoked: true,
            expires_at: FUTURE,
        },
        BindingCase {
            binding: BINDING_DISABLED,
            token: &disabled,
            gateway_license: LICENSE,
            enabled: false,
            revoked: false,
            expires_at: FUTURE,
        },
        BindingCase {
            binding: BINDING_EXPIRED,
            token: &expired,
            gateway_license: LICENSE,
            enabled: true,
            revoked: false,
            expires_at: PAST,
        },
        BindingCase {
            binding: BINDING_FOREIGN,
            token: &foreign,
            gateway_license: OTHER_LICENSE,
            enabled: true,
            revoked: false,
            expires_at: FUTURE,
        },
    ] {
        insert_binding(&fixture, &toolkit, case).await;
    }

    let binding_authority = PgBindingAuthority::new(fixture.pool.clone());
    let identity = license_identity(LICENSE);
    for (token, case) in [
        (&revoked, "revoked"),
        (&disabled, "disabled"),
        (&expired, "expired"),
        (&foreign, "foreign licence"),
    ] {
        let refused = binding_authority.authenticate(&identity, token).await;
        assert_eq!(refused, Err(AuthError::Unauthorized), "{case}");
    }
    drop(binding_authority);
    fixture.finish().await;
}

#[tokio::test]
async fn the_stored_digest_is_the_sha_256_hex_and_the_plaintext_is_never_stored() {
    let fixture = Fixture::new().await;
    insert_profile(&fixture).await;
    let toolkit = seed_toolkit(&fixture, &[(TOOL_ALPHA, "alpha_tool")]).await;
    let token = bindings::mint_token();
    insert_binding(
        &fixture,
        &toolkit,
        BindingCase {
            binding: BINDING,
            token: &token,
            gateway_license: LICENSE,
            enabled: true,
            revoked: false,
            expires_at: FUTURE,
        },
    )
    .await;

    let mut conn = fixture.pool.acquire().await.expect("connection");
    let row = sqlx::query(
        "SELECT token_sha256, encode(sha256(convert_to($1, 'UTF8')), 'hex') AS expected \
         FROM public.mcp_bindings \
         WHERE tenant_id = $2::uuid AND binding_id = $3::uuid",
    )
    .bind(&token)
    .bind(TENANT_A)
    .bind(BINDING)
    .fetch_one(&mut *conn)
    .await
    .expect("stored digest");
    let stored: String = row.try_get("token_sha256").expect("digest column");
    let expected: String = row.try_get("expected").expect("sha256 column");
    assert_eq!(stored, expected, "the column holds the token's SHA-256 hex");
    assert_eq!(stored, bindings::digest_token(&token));
    assert_eq!(stored.len(), 64);
    assert!(
        stored
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    );
    assert_eq!(
        bindings::digest_token("abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );

    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_bindings b WHERE strpos(to_jsonb(b)::text, $1) > 0",
    )
    .bind(&token)
    .fetch_one(&mut *conn)
    .await
    .expect("plaintext scan");
    assert_eq!(leaked, 0, "the token itself is stored in no column");
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn binding_members_writes_one_row_per_entry_and_repeats_safely() {
    let fixture = Fixture::new().await;
    insert_profile(&fixture).await;
    let toolkit = seed_toolkit(
        &fixture,
        &[(TOOL_ALPHA, "alpha_tool"), (TOOL_ZETA, "zeta_tool")],
    )
    .await;
    let token = bindings::mint_token();
    insert_binding(
        &fixture,
        &toolkit,
        BindingCase {
            binding: BINDING,
            token: &token,
            gateway_license: LICENSE,
            enabled: true,
            revoked: false,
            expires_at: FUTURE,
        },
    )
    .await;

    // Re-run the writer inside a new transaction against the same row.
    let mut tx = fixture.pool.begin().await.expect("transaction");
    let row = bindings::get_binding(&mut tx, &authority(TENANT_A), &uuid7(BINDING), true)
        .await
        .expect("locked row");
    let stored = bindings::descriptor(&row).expect("binding descriptor");
    bindings::binding_members(&mut tx, &stored)
        .await
        .expect("replace members");
    tx.commit().await.expect("commit members");

    let mut conn = fixture.pool.acquire().await.expect("connection");
    let toolkits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_binding_toolkits \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(BINDING)
    .fetch_one(&mut *conn)
    .await
    .expect("toolkit count");
    assert_eq!(toolkits, 1);
    let tools: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_binding_tools \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(BINDING)
    .fetch_one(&mut *conn)
    .await
    .expect("tool count");
    assert_eq!(tools, toolkit.tools.len() as i64);
    assert_eq!(tools, 2);

    let toolkit_row = sqlx::query(
        "SELECT toolkit_id::text AS toolkit_id, version, owner_tenant_id::text AS owner \
         FROM public.mcp_binding_toolkits \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(BINDING)
    .fetch_one(&mut *conn)
    .await
    .expect("toolkit row");
    assert_eq!(
        toolkit_row.try_get::<String, _>("toolkit_id").expect("id"),
        TOOLKIT_1
    );
    assert_eq!(
        toolkit_row.try_get::<i32, _>("version").expect("version"),
        1
    );
    assert_eq!(
        toolkit_row.try_get::<String, _>("owner").expect("owner"),
        TENANT_A
    );

    let names: Vec<String> = sqlx::query_scalar(
        "SELECT public_name FROM public.mcp_binding_tools \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid ORDER BY public_name",
    )
    .bind(TENANT_A)
    .bind(BINDING)
    .fetch_all(&mut *conn)
    .await
    .expect("tool rows");
    assert_eq!(names, ["alpha_tool", "zeta_tool"]);
    drop(conn);
    fixture.finish().await;
}

#[test]
fn mint_token_is_43_url_safe_characters_and_unique() {
    let one = bindings::mint_token();
    let two = bindings::mint_token();
    assert_eq!(one.len(), 43);
    assert!(
        one.bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "URL-safe base64 without padding: {one}"
    );
    assert_ne!(one, two);
    assert_eq!(bindings::digest_token(&one).len(), 64);
}

// ── the binding service (`ToolkitService` binding write/action/effective) ───────────────────

#[tokio::test]
async fn create_returns_a_descriptor_and_a_token_and_records_the_selection() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    let toolkit =
        published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let spec = binding_spec(PROFILE, FUTURE, tenant_context());
    let (descriptor, token) = service
        .binding_write(&principal(TENANT_A, true), &spec, None, None)
        .await
        .expect("create binding");
    let token = token.expect("a create mints a token");
    assert_eq!(descriptor.revision.get(), 1);
    assert!(!descriptor.revoked);
    assert_eq!(descriptor.gateway_license_id.as_str(), LICENSE);
    assert_eq!(descriptor.tools, toolkit.tools);
    assert_eq!(token.len(), 43);
    assert!(
        token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "URL-safe base64 without padding: {token}"
    );

    let mut conn = fixture.pool.acquire().await.expect("connection");
    let stored: String = sqlx::query_scalar(
        "SELECT token_sha256 FROM public.mcp_bindings \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(descriptor.binding_id.as_str())
    .fetch_one(&mut *conn)
    .await
    .expect("binding row");
    assert_eq!(stored, bindings::digest_token(&token));
    assert_eq!(stored.len(), 64);
    let leaked: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_bindings b WHERE strpos(to_jsonb(b)::text, $1) > 0",
    )
    .bind(&token)
    .fetch_one(&mut *conn)
    .await
    .expect("plaintext scan");
    assert_eq!(leaked, 0, "the token itself is stored in no column");
    let toolkits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_binding_toolkits \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(descriptor.binding_id.as_str())
    .fetch_one(&mut *conn)
    .await
    .expect("toolkit rows");
    assert_eq!(toolkits, 1);
    let tools: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_binding_tools \
         WHERE tenant_id = $1::uuid AND binding_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(descriptor.binding_id.as_str())
    .fetch_one(&mut *conn)
    .await
    .expect("tool rows");
    assert_eq!(tools, 1);
    let (action, revision): (String, i64) = sqlx::query_as(
        "SELECT action, revision FROM public.mcp_access_events WHERE entity_id = $1::uuid",
    )
    .bind(descriptor.binding_id.as_str())
    .fetch_one(&mut *conn)
    .await
    .expect("audit row");
    assert_eq!(action, "binding.changed");
    assert_eq!(revision, 1);
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn create_refuses_an_expiry_in_the_past() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let refused = fixture
        .service()
        .binding_write(
            &principal(TENANT_A, true),
            &binding_spec(PROFILE, PAST, tenant_context()),
            None,
            None,
        )
        .await
        .expect_err("an expired binding cannot be created");
    assert_eq!(
        invalid_error(refused),
        "binding expiry must be in the future"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn create_refuses_a_context_beyond_tenant_scope() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let context = json!({"tenant_id": TENANT_A, "project_id": PROJECT});
    let refused = fixture
        .service()
        .binding_write(
            &principal(TENANT_A, true),
            &binding_spec(PROFILE, FUTURE, context),
            None,
            None,
        )
        .await
        .expect_err("only tenant scope is self-verifying");
    assert_eq!(
        invalid_error(refused),
        "resource and stage context requires host ownership/provenance verification"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn update_requires_an_expected_revision() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let spec = binding_spec(PROFILE, FUTURE, tenant_context());
    let (descriptor, _) = service
        .binding_write(&operator, &spec, None, None)
        .await
        .expect("create binding");
    let refused = service
        .binding_write(&operator, &spec, Some(descriptor.binding_id.clone()), None)
        .await
        .expect_err("an update names its revision");
    assert_eq!(
        invalid_error(refused),
        "binding updates require an expected revision"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn update_refuses_a_changed_gateway_licence() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    insert_profile_with(
        &fixture,
        PROFILE_2,
        "synthetic_profile_two",
        OTHER_LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let (descriptor, _) = service
        .binding_write(
            &operator,
            &binding_spec(PROFILE, FUTURE, tenant_context()),
            None,
            None,
        )
        .await
        .expect("create binding");
    let refused = service
        .binding_write(
            &operator,
            &binding_spec(PROFILE_2, FUTURE, tenant_context()),
            Some(descriptor.binding_id.clone()),
            Some(descriptor.revision),
        )
        .await
        .expect_err("the gateway licence is immutable");
    assert_eq!(
        invalid_error(refused),
        "gateway license identity is immutable; issue a new binding"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn update_refuses_a_stale_expected_revision() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let spec = binding_spec(PROFILE, FUTURE, tenant_context());
    let (descriptor, _) = service
        .binding_write(&operator, &spec, None, None)
        .await
        .expect("create binding");
    let refused = service
        .binding_write(
            &operator,
            &spec,
            Some(descriptor.binding_id.clone()),
            Some(version(2)),
        )
        .await
        .expect_err("the identity is still at revision one");
    assert_eq!(conflict_error(refused), "expected revision conflict");
    fixture.finish().await;
}

#[tokio::test]
async fn rotate_issues_a_new_token_and_the_old_one_stops_authenticating() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let (descriptor, token) = service
        .binding_write(
            &operator,
            &binding_spec(PROFILE, FUTURE, tenant_context()),
            None,
            None,
        )
        .await
        .expect("create binding");
    let old = token.expect("a create mints a token");
    let (rotated, token) = service
        .binding_action(
            &operator,
            &descriptor.binding_id,
            descriptor.revision,
            false,
        )
        .await
        .expect("rotate");
    let new = token.expect("a rotate mints a token");
    assert_ne!(new, old);
    assert_eq!(rotated.revision.get(), 2);
    assert!(!rotated.revoked);

    let binding_authority = PgBindingAuthority::new(fixture.pool.clone());
    assert_eq!(
        binding_authority
            .authenticate(&license_identity(LICENSE), &old)
            .await,
        Err(AuthError::Unauthorized),
        "the rotated token no longer authenticates"
    );
    let resolved = binding_authority
        .authenticate(&license_identity(LICENSE), &new)
        .await
        .expect("the new token authenticates");
    assert_eq!(resolved.revision, 2);
    drop(binding_authority);
    fixture.finish().await;
}

#[tokio::test]
async fn revoke_is_terminal() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let operator = principal(TENANT_A, true);
    let (descriptor, token) = service
        .binding_write(
            &operator,
            &binding_spec(PROFILE, FUTURE, tenant_context()),
            None,
            None,
        )
        .await
        .expect("create binding");
    let old = token.expect("a create mints a token");
    let (revoked, token) = service
        .binding_action(&operator, &descriptor.binding_id, descriptor.revision, true)
        .await
        .expect("revoke");
    assert!(token.is_none(), "a revoke mints no token");
    assert!(revoked.revoked);
    assert_eq!(revoked.revision.get(), 2);

    let binding_authority = PgBindingAuthority::new(fixture.pool.clone());
    assert_eq!(
        binding_authority
            .authenticate(&license_identity(LICENSE), &old)
            .await,
        Err(AuthError::Unauthorized)
    );
    drop(binding_authority);

    let refused = service
        .binding_action(&operator, &revoked.binding_id, revoked.revision, false)
        .await
        .expect_err("a revoked binding cannot rotate");
    assert_eq!(conflict_error(refused), "binding is revoked");
    fixture.finish().await;
}

#[tokio::test]
async fn effective_returns_the_stored_tools_and_refuses_a_changed_selection() {
    let fixture = Fixture::new().await;
    insert_profile_with(
        &fixture,
        PROFILE,
        "synthetic_profile",
        LICENSE,
        service_references(),
    )
    .await;
    let toolkit =
        published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let service = fixture.service();
    let (descriptor, _) = service
        .binding_write(
            &principal(TENANT_A, true),
            &binding_spec(PROFILE, FUTURE, tenant_context()),
            None,
            None,
        )
        .await
        .expect("create binding");
    let effective = service.effective(&descriptor).await.expect("effective");
    assert_eq!(effective, descriptor.tools);
    assert_eq!(effective, toolkit.tools);

    // Mutate the stored tools row (and its members, which the deferred check pairs) so the
    // stored selection no longer matches the live selection.
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "UPDATE public.mcp_bindings SET tools='[]'::jsonb, revision=revision+1 \
         WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(TENANT_A)
    .bind(descriptor.binding_id.as_str())
    .execute(&mut *tx)
    .await
    .expect("mutate stored tools");
    sqlx::query(
        "DELETE FROM public.mcp_binding_tools \
         WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(TENANT_A)
    .bind(descriptor.binding_id.as_str())
    .execute(&mut *tx)
    .await
    .expect("drop stored tool rows");
    tx.commit().await.expect("commit mutation");

    let mutated = bindings::inspect(&fixture.pool, &authority(TENANT_A), &descriptor.binding_id)
        .await
        .expect("inspect mutated binding");
    let refused = service
        .effective(&mutated)
        .await
        .expect_err("the stored selection changed");
    assert_eq!(conflict_error(refused), "effective selection changed");
    fixture.finish().await;
}

#[tokio::test]
async fn a_profile_without_the_required_service_reference_is_refused() {
    let fixture = Fixture::new().await;
    // A gateway-only profile: the synthetic service's licence bearer has no reference.
    insert_profile(&fixture).await;
    published_binding_toolkit(&fixture, TOOL_ALPHA, "alpha_tool", OPERATION_ALPHA).await;
    let refused = fixture
        .service()
        .binding_write(
            &principal(TENANT_A, true),
            &binding_spec(PROFILE, FUTURE, tenant_context()),
            None,
            None,
        )
        .await
        .expect_err("the profile lacks the service application reference");
    assert_eq!(
        invalid_error(refused),
        "credential profile lacks required application reference"
    );
    fixture.finish().await;
}
