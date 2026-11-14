#![allow(dead_code)]
//! The shared real-server fixture harness for the HTTP integration tests.
//!
//! Every success asserts against the real router, the real `/mcp` authentication middleware,
//! the real `PgBindingAuthority` and a real Postgres 18: the same catalog rows the REST
//! projection serves are the ones `tools/list` projects. Server selection: `TEST_DATABASE_URL`,
//! else `DATABASE_URL`, else an ephemeral `postgres:18` container started with docker and
//! removed afterwards, else FAIL (never skip). Each test gets its own fresh database.

use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, PgConnection, PgPool};
use tower::ServiceExt;

use mcp_server_rs::auth::pg_bindings::PgBindingAuthority;
use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, Binding, BindingAuthority, BoxFuture, LicenceAuthority,
    LicenseIdentity, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::ToolManifest;
use mcp_server_rs::catalog::toolkit_models::ToolkitManifest;
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::toolkits::service::ToolkitService;
use mcp_server_rs::{AppState, app_with_auth, db};

pub const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
pub const TENANT_PLATFORM: &str = "10000000-0000-7000-8000-0000000000ff";
pub const LICENCE_ID: &str = "30000000-0000-4000-8000-000000000001";
pub const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000000ff";
pub const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
pub const TOOL_ALPHA: &str = "20000000-0000-7000-8000-000000000001";
pub const TOOL_BETA: &str = "20000000-0000-7000-8000-000000000002";
pub const TOOLKIT_1: &str = "01900000-0000-7000-8000-000000000001";
pub const PROFILE: &str = "01900000-0000-7000-8000-0000000000f1";
pub const FUTURE: &str = "2033-05-18T03:33:20Z";
pub const LICENCE_TOKEN: &str = "licence-token";
pub const ADMIN_KEY: &str = "routes-available-operator-key-012345";
pub const GATEWAY_APP_KEY: &str = "synthetic";

// ── the real-server harness ────────────────────────────────────────────────────────────────

pub struct Server {
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

pub struct Fixture {
    pub pool: PgPool,
    admin_url: String,
    name: String,
    server: Server,
}

impl Fixture {
    pub async fn new() -> Self {
        let server = server().await;
        let admin_opts = PgConnectOptions::from_str(&server.url).expect("parse database url");
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let name = format!("mcp_routes_available_{}_{nanos}", std::process::id());
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

    pub fn state(&self) -> AppState {
        self.state_with_page_size(10)
    }

    pub fn state_with_page_size(&self, catalog_page_size: u32) -> AppState {
        AppState {
            pool: self.pool.clone(),
            execution_enabled: false,
            license_app_key: Some(GATEWAY_APP_KEY.to_owned()),
            approved_runner_images: Vec::new(),
            platform_tenant_id: Rfc4122Uuid::parse(TENANT_PLATFORM).expect("static uuid"),
            catalog_page_size,
        }
    }

    pub fn auth(&self) -> Auth {
        let config = AuthConfig {
            license_introspect_url: Some("https://licence.example/introspect".into()),
            license_app_key: Some("test-app-key".into()),
            admin_key_file: Some(admin_key_file()),
            admin_tenant_ids: vec![Rfc4122Uuid::parse(TENANT_A).expect("static uuid")],
            ..AuthConfig::default()
        };
        let mut auth = Auth::from_config(&config).expect("valid auth config");
        auth.licences = Arc::new(TestLicence);
        auth
    }

    pub fn app(&self) -> Router {
        self.app_with_bindings(Arc::new(PgBindingAuthority::new(self.pool.clone())))
    }

    pub fn app_with_bindings(&self, bindings: Arc<dyn BindingAuthority>) -> Router {
        app_with_auth(self.state(), self.auth().with_bindings(bindings))
    }

    /// The same application with a configured `CATALOG_PAGE_SIZE`.
    pub fn app_with_page_size(
        &self,
        page_size: u32,
        bindings: Arc<dyn BindingAuthority>,
    ) -> Router {
        app_with_auth(
            self.state_with_page_size(page_size),
            self.auth().with_bindings(bindings),
        )
    }

    pub fn service(&self) -> ToolkitService {
        ToolkitService::new(
            self.pool.clone(),
            SelectionResolver {
                platform_tenant_id: authority(TENANT_PLATFORM),
            },
            Some(GATEWAY_APP_KEY.to_owned()),
        )
    }

    pub async fn finish(self) {
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

// ── authentication: the real middleware, a deterministic licence authority ────────────────

pub struct TestLicence;

impl LicenceAuthority for TestLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            if token != LICENCE_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(LicenseIdentity {
                tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("static uuid"),
                license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("static uuid"),
                subject: "svc:test:mcp".into(),
                subject_kind: Some(SubjectKind::Tenant),
            })
        })
    }
}

/// A binding authority that reports a fixed (possibly stale) revision: the read raced another
/// client's update, so the handler must refuse the credential.
pub struct FixedBindings {
    pub id: Rfc4122Uuid,
    pub revision: i64,
}

impl BindingAuthority for FixedBindings {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        _token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async move {
            Ok(Binding {
                binding_id: self.id,
                revision: self.revision,
            })
        })
    }
}

pub fn admin_key_file() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("mcp-routes-available-admin-{}", std::process::id()));
    std::fs::write(&path, ADMIN_KEY).expect("write operator key");
    path
}

// ── requests and fixtures ─────────────────────────────────────────────────────────────────

pub fn management(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY);
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => request.body(Body::empty()).expect("request"),
    }
}

/// A binding caller: the tenant licence plus the binding token, no operator key.
pub fn binding_request(method: Method, uri: &str, token: &str) -> Request<Body> {
    Request::builder()
        .method(method)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", token)
        .body(Body::empty())
        .expect("request")
}

/// A caller with a tenant licence and no binding token or operator key.
pub fn licence_only(uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .body(Body::empty())
        .expect("request")
}

pub async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = app.clone().oneshot(request).await.expect("router");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).expect("json body")
    };
    (status, headers, body)
}

pub fn assert_no_store(headers: &HeaderMap) {
    assert!(
        headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .any(|value| value == "no-store"),
        "missing Cache-Control: no-store in {headers:?}"
    );
}

pub fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value).expect("authority identity")
}

pub fn uuid7(value: &str) -> Uuid7 {
    Uuid7::new(value).expect("uuid7 identity")
}

pub fn version(value: u32) -> PositiveVersion {
    PositiveVersion::new(u64::from(value)).expect("positive version")
}

pub fn actor_snapshot() -> Value {
    json!({"subject": "agent-09", "license_id": LICENCE_ID})
}

pub fn principal() -> mcp_server_rs::auth::Principal {
    mcp_server_rs::auth::Principal {
        tenant_id: Rfc4122Uuid::parse(TENANT_A).expect("tenant identity"),
        license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("licence identity"),
        subject: "agent-09".to_owned(),
        binding_id: None,
        binding_revision: None,
        management: true,
        platform: false,
    }
}

/// A strict, valid tool manifest whose single operation is `OPERATION_ALPHA`, allowed once.
pub fn tool_manifest(name: &str, tool: &str) -> ToolManifest {
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
        "allowed_operations": [{"id": OPERATION_ALPHA, "version": 1}],
    }))
    .expect("valid tool manifest")
}

pub fn toolkit_manifest(tools: &[(&str, &str)]) -> ToolkitManifest {
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

pub async fn seed_service(fixture: &Fixture) {
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
        "license_app_key": GATEWAY_APP_KEY,
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

pub async fn seed_operation(fixture: &Fixture) {
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(OPERATION_ALPHA)
    .bind(SERVICE_ID)
    .bind(json!({
        "schema_version": 1,
        "operation_id": OPERATION_ALPHA,
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
    .bind(OPERATION_ALPHA)
    .execute(&fixture.pool)
    .await
    .expect("publish operation");
}

pub async fn insert_profile_with(fixture: &Fixture, profile: &str, name: &str, gateway: &str) {
    let manifest = json!({
        "schema_version": 1,
        "tenant_id": TENANT_A,
        "profile_id": profile,
        "name": name,
        "gateway": {
            "service": "gateway",
            "alias": "gateway",
            "license_id": gateway,
            "app_key": GATEWAY_APP_KEY
        },
        "services": [{
            "service": "synthetic_service",
            "alias": "synthetic",
            "license_id": LICENCE_ID,
            "app_key": GATEWAY_APP_KEY
        }]
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
    for (service_key, alias, license) in [
        ("__gateway", "gateway", gateway),
        ("synthetic_service", "synthetic", LICENCE_ID),
    ] {
        sqlx::query(
            "INSERT INTO public.mcp_credential_refs(\
             tenant_id,profile_id,service_key,alias,license_id,app_key) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5::uuid,$6)",
        )
        .bind(TENANT_A)
        .bind(profile)
        .bind(service_key)
        .bind(alias)
        .bind(license)
        .bind(GATEWAY_APP_KEY)
        .execute(&mut *tx)
        .await
        .expect("insert credential reference");
    }
    tx.commit().await.expect("commit credential profile");
}

/// The full fixture: a published service and operation, a published tool, one published
/// toolkit selecting that tool, and the credential profile. The binding itself is created
/// through the HTTP surface so its token is the real one.
pub async fn binding_fixture(fixture: &Fixture) {
    binding_fixture_with_tool(fixture, &tool_manifest("alpha_tool", TOOL_ALPHA)).await;
}

/// The same fixture with a caller-supplied tool manifest. The row is inserted directly
/// because the authoring path refuses a reserved public name and a `kata_python` manifest
/// needs no package; the resolver must still refuse either at read time.
pub async fn binding_fixture_with_tool(fixture: &Fixture, manifest: &ToolManifest) {
    binding_fixture_with_tools(fixture, std::slice::from_ref(manifest)).await;
}

/// The same fixture with every supplied tool selected by the single toolkit.
pub async fn binding_fixture_with_tools(fixture: &Fixture, manifests: &[ToolManifest]) {
    insert_profile_with(fixture, PROFILE, "synthetic_profile", LICENCE_ID).await;
    seed_service(fixture).await;
    seed_operation(fixture).await;
    for manifest in manifests {
        insert_published_tool(fixture, manifest).await;
    }
    let references: Vec<(&str, &str)> = manifests
        .iter()
        .map(|manifest| (manifest.tool_id.as_str(), manifest.public_name.as_str()))
        .collect();
    let service = fixture.service();
    let operator = principal();
    let drafted = service
        .write(&operator, &toolkit_manifest(&references), None)
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
        .expect("publish toolkit");
}

/// One published tool version, written straight to the snapshot tables.
///
/// One transaction: the completeness constraint trigger is deferred to commit, and the
/// publication guard requires the snapshot to start as a draft.
pub async fn insert_published_tool(fixture: &Fixture, manifest: &ToolManifest) {
    let snapshot = serde_json::to_value(manifest).expect("manifest json");
    let version = i32::try_from(manifest.version.get()).expect("version");
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_tools(tenant_id,tool_id,public_name,created_by) \
         VALUES ($1::uuid,$2::uuid,$3,$4)",
    )
    .bind(manifest.tenant_id.as_str())
    .bind(manifest.tool_id.as_str())
    .bind(manifest.public_name.as_str())
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("tool identity");
    sqlx::query(
        "INSERT INTO public.mcp_tool_versions(tenant_id,tool_id,version,manifest,\
         package_sha256,file_count,operation_count,status,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,1,$6,'draft',$7,$7)",
    )
    .bind(manifest.tenant_id.as_str())
    .bind(manifest.tool_id.as_str())
    .bind(version)
    .bind(snapshot)
    .bind(manifest.package_sha256.as_str())
    .bind(i32::try_from(manifest.allowed_operations.len()).expect("operation count"))
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("tool version");
    sqlx::query(
        "INSERT INTO public.mcp_tool_version_files(tenant_id,tool_id,version,path,content) \
         VALUES ($1::uuid,$2::uuid,$3,'package/main.py','print(''synthetic'')')",
    )
    .bind(manifest.tenant_id.as_str())
    .bind(manifest.tool_id.as_str())
    .bind(version)
    .execute(&mut *tx)
    .await
    .expect("tool package file");
    for operation in &manifest.allowed_operations {
        sqlx::query(
            "INSERT INTO public.mcp_tool_version_operations(tenant_id,tool_id,version,\
             operation_id,operation_version) VALUES ($1::uuid,$2::uuid,$3,$4::uuid,$5)",
        )
        .bind(manifest.tenant_id.as_str())
        .bind(manifest.tool_id.as_str())
        .bind(version)
        .bind(operation.id.as_str())
        .bind(i32::try_from(operation.version.get()).expect("operation version"))
        .execute(&mut *tx)
        .await
        .expect("tool operation reference");
    }
    sqlx::query(
        "UPDATE public.mcp_tool_versions SET status='published' \
         WHERE tenant_id = $1::uuid AND tool_id = $2::uuid AND version = $3",
    )
    .bind(manifest.tenant_id.as_str())
    .bind(manifest.tool_id.as_str())
    .bind(version)
    .execute(&mut *tx)
    .await
    .expect("publish tool version");
    tx.commit().await.expect("commit tool version");
}

/// The fixture manifest with a platform-reserved public name.
pub fn reserved_manifest() -> ToolManifest {
    let mut value =
        serde_json::to_value(tool_manifest("alpha_tool", TOOL_ALPHA)).expect("manifest json");
    value["public_name"] = json!("mcp_run_status");
    serde_json::from_value(value).expect("reserved manifest")
}

/// The fixture manifest as a `kata_python` tool naming a runner no deployment approved.
pub fn kata_manifest() -> ToolManifest {
    let mut value =
        serde_json::to_value(tool_manifest("alpha_tool", TOOL_ALPHA)).expect("manifest json");
    value
        .as_object_mut()
        .expect("manifest object")
        .remove("target");
    value["runtime"] = json!("kata_python");
    value["entrypoint"] = json!("package/main.py");
    value["runner_image_digest"] =
        json!(format!("registry.example/runner@sha256:{}", "b".repeat(64)));
    serde_json::from_value(value).expect("kata manifest")
}

pub fn binding_spec() -> Value {
    json!({
        "schema_version": 1,
        "credential_profile_id": PROFILE,
        "toolkits": [{"id": TOOLKIT_1, "version": 1, "tenant_id": TENANT_A}],
        "context": {"tenant_id": TENANT_A},
        "expires_at": FUTURE,
    })
}

pub async fn create_binding(app: &Router) -> Value {
    let (status, headers, body) = send(
        app,
        management(Method::POST, "/mcp/bindings", Some(binding_spec())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_store(&headers);
    body
}

// ── MCP transport ────────────────────────────────────────────────────────────────────────

/// POST one JSON-RPC message to `/mcp` the way the Python source is called: stateless
/// streamable HTTP, both content types accepted, loopback Host (rmcp's default allowlist).
/// `binding_token` is the middleware's `X-MCP-Binding`; `None` sends no binding credential.
pub async fn mcp_post(
    app: &Router,
    binding_token: Option<&str>,
    message: Value,
) -> (StatusCode, String, Value) {
    let mut request = Request::post("/mcp")
        .header("host", "127.0.0.1")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("content-type", "application/json")
        .header("accept", "application/json, text/event-stream");
    if let Some(token) = binding_token {
        request = request.header("x-mcp-binding", token);
    }
    let response = app
        .clone()
        .oneshot(
            request
                .body(Body::from(serde_json::to_vec(&message).expect("json body")))
                .expect("request"),
        )
        .await
        .expect("router");
    let status = response.status();
    let content_type = response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_owned();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    (
        status,
        content_type,
        rpc_payload(&String::from_utf8_lossy(&bytes)),
    )
}

/// The JSON-RPC message carried by an SSE frame (`json_response=False`, like fastmcp) or,
/// when the transport answered plainly, the body itself.
pub fn rpc_payload(body: &str) -> Value {
    let data = body
        .lines()
        .find_map(|line| line.strip_prefix("data:"))
        .map(str::trim)
        .unwrap_or(body);
    serde_json::from_str(data).unwrap_or_else(|e| panic!("not JSON ({e}): {body:?}"))
}

// ── the reference body ────────────────────────────────────────────────────────────────────

/// The envelope [`mcp_server_rs::catalog::public::output_envelope`] builds for the fixture's
/// empty result schema, written out exactly as the reference serializes it.
pub fn output_schema() -> Value {
    json!({
        "type": "object",
        "additionalProperties": false,
        "$defs": {
            "tool_result": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            }
        },
        "required": ["run_id", "status", "result", "error"],
        "properties": {
            "run_id": {"type": "string", "minLength": 36, "maxLength": 36},
            "status": {"enum": [
                "queued", "starting", "running", "cancelling", "succeeded",
                "failed", "cancelled", "timed_out", "interrupted"
            ]},
            "payload_expired": {"type": "boolean"},
            "result": {"anyOf": [{"$ref": "#/$defs/tool_result"}, {"type": "null"}]},
            "error": {
                "anyOf": [
                    {"type": "null"},
                    {
                        "type": "object",
                        "additionalProperties": false,
                        "required": ["code", "message"],
                        "properties": {
                            "code": {"type": "string", "maxLength": 64},
                            "message": {"type": "string", "maxLength": 512}
                        }
                    }
                ]
            }
        }
    })
}

/// The exact `{"tools": [...], "execution": "unavailable"}` body for the one fixture tool.
pub fn projection_body() -> Value {
    json!({
        "tools": [{
            "name": "alpha_tool",
            "description": "Synthetic fixture",
            "inputSchema": {
                "type": "object",
                "properties": {},
                "additionalProperties": false
            },
            "outputSchema": output_schema(),
            "annotations": {
                "readOnlyHint": true,
                "destructiveHint": false,
                "idempotentHint": false,
                "openWorldHint": true
            },
            "_meta": {"operation": "synthetic.alpha_tool"}
        }],
        "execution": "unavailable"
    })
}
