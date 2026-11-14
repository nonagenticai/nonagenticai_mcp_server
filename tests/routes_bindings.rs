//! The five `/mcp/bindings` operations against the real router and a real Postgres 18. Each
//! test fails if the behaviour it covers is removed: every success asserts the reference's
//! response BODY field by field (the parity gate cannot see bodies), a caller that may not
//! manage is refused, every refusal renders the reference's `{"error": …}` with
//! `Cache-Control: no-store`, and the OpenAPI document declares the reference's shapes (no
//! request body, 201/200, 422 only where a path parameter exists).
//!
//! Server selection mirrors `tests/routes_toolkits.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL` (a URL whose user may CREATE DATABASE), else an ephemeral `postgres:18`
//! container started here with docker and removed afterwards, else FAIL (never skip).
//! `TEST_PG_REGISTRY` may name a registry mirror. Each test gets its own fresh database,
//! dropped at the end.

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

use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, BoxFuture, LicenceAuthority, LicenseIdentity, Rfc4122Uuid,
    SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::models::{Attribution, ToolManifest};
use mcp_server_rs::catalog::package::PackageFile;
use mcp_server_rs::catalog::toolkit_models::{ToolkitDescriptor, ToolkitManifest};
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::toolkits::service::ToolkitService;
use mcp_server_rs::{AppState, app_with_auth, db, openapi};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_PLATFORM: &str = "10000000-0000-7000-8000-0000000000ff";
const LICENCE_ID: &str = "30000000-0000-4000-8000-000000000001";
const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000000ff";
const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
const TOOL_ALPHA: &str = "20000000-0000-7000-8000-000000000001";
const TOOLKIT_1: &str = "01900000-0000-7000-8000-000000000001";
const PROFILE: &str = "01900000-0000-7000-8000-0000000000f1";
const UNKNOWN_BINDING: &str = "01900000-0000-7000-8000-0000000000bf";
const FUTURE: &str = "2033-05-18T03:33:20Z";
const LICENCE_TOKEN: &str = "licence-token";
const ADMIN_KEY: &str = "routes-bindings-operator-key-0123456";
const GATEWAY_APP_KEY: &str = "synthetic";

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
        let name = format!("mcp_routes_bindings_{}_{nanos}", std::process::id());
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

    fn app(&self) -> Router {
        app_with_auth(
            AppState {
                pool: self.pool.clone(),
                execution_enabled: false,
                license_app_key: Some(GATEWAY_APP_KEY.to_owned()),
                approved_runner_images: Vec::new(),
                platform_tenant_id: mcp_server_rs::auth::Rfc4122Uuid::parse(
                    "01900000-0000-7000-8000-00000000f001",
                )
                .expect("static uuid"),
                catalog_page_size: 10,
            },
            auth(),
        )
    }

    fn service(&self) -> ToolkitService {
        ToolkitService::new(
            self.pool.clone(),
            SelectionResolver {
                platform_tenant_id: authority(TENANT_PLATFORM),
            },
            Some(GATEWAY_APP_KEY.to_owned()),
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

// ── authentication: the real middleware, a deterministic licence authority ────────────────

struct TestLicence;

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

fn admin_key_file() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("mcp-routes-bindings-admin-{}", std::process::id()));
    std::fs::write(&path, ADMIN_KEY).expect("write operator key");
    path
}

fn auth() -> Auth {
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

// ── requests and fixtures ─────────────────────────────────────────────────────────────────

fn management(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    with_management(method, uri, body, true)
}

fn with_management(method: Method, uri: &str, body: Option<Value>, headers: bool) -> Request<Body> {
    let mut request = Request::builder().method(method).uri(uri);
    if headers {
        request = request
            .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-mcp-admin-key", ADMIN_KEY);
    }
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => request.body(Body::empty()).expect("request"),
    }
}

async fn send(app: &Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
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

fn assert_no_store(headers: &HeaderMap) {
    assert!(
        headers
            .get_all(header::CACHE_CONTROL)
            .iter()
            .any(|value| value == "no-store"),
        "missing Cache-Control: no-store in {headers:?}"
    );
}

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
        license_id: Some(authority(LICENCE_ID)),
    }
}

fn actor_snapshot() -> Value {
    json!({"subject": "agent-09", "license_id": LICENCE_ID})
}

fn principal() -> mcp_server_rs::auth::Principal {
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

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "package/main.py".to_owned(),
        content: "print('synthetic')\n".to_owned(),
    }]
}

/// A strict, valid tool manifest whose single operation is `OPERATION_ALPHA`, allowed once.
fn tool_manifest(name: &str, tool: &str) -> ToolManifest {
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

/// A published operation of the synthetic service.
async fn seed_operation(fixture: &Fixture) {
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

/// The credential profile row and its reference rows, gateway reference included.
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
            "app_key": GATEWAY_APP_KEY
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
    .bind(GATEWAY_APP_KEY)
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

/// The full binding fixture: a published service and operation, a published tool that allows
/// the operation, one published toolkit selecting that tool, and the credential profile.
async fn binding_fixture(fixture: &Fixture) -> ToolkitDescriptor {
    insert_profile_with(
        fixture,
        PROFILE,
        "synthetic_profile",
        LICENCE_ID,
        json!([{
            "service": "synthetic_service",
            "alias": "synthetic",
            "license_id": LICENCE_ID,
            "app_key": GATEWAY_APP_KEY
        }]),
    )
    .await;
    seed_service(fixture).await;
    seed_operation(fixture).await;
    let repository = CatalogRepository::new(fixture.pool.clone());
    let tenant = authority(TENANT_A);
    repository
        .create(
            &tenant,
            &tool_manifest("alpha_tool", TOOL_ALPHA),
            &files(),
            &actor(),
        )
        .await
        .expect("create tool");
    repository
        .transition(
            &tenant,
            &uuid7(TOOL_ALPHA),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
    let service = fixture.service();
    let operator = principal();
    let drafted = service
        .write(
            &operator,
            &toolkit_manifest(&[(TOOL_ALPHA, "alpha_tool")]),
            None,
        )
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

/// The reference's `BindingSpec` body.
fn binding_spec() -> Value {
    json!({
        "schema_version": 1,
        "credential_profile_id": PROFILE,
        "toolkits": [{"id": TOOLKIT_1, "version": 1, "tenant_id": TENANT_A}],
        "context": {"tenant_id": TENANT_A},
        "expires_at": FUTURE,
    })
}

/// The reference's `BindingUpdate` body.
fn binding_update(expected_revision: u32) -> Value {
    json!({"expected_revision": expected_revision, "spec": binding_spec()})
}

async fn create_binding(app: &Router) -> (StatusCode, HeaderMap, Value) {
    send(
        app,
        management(Method::POST, "/mcp/bindings", Some(binding_spec())),
    )
    .await
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_inspect_update_rotate_and_revoke_answer_the_reference_bodies() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let app = fixture.app();

    // Create: 201, the descriptor and the one plaintext token.
    let (status, headers, body) = create_binding(&app).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_no_store(&headers);
    let token = body["token"]
        .as_str()
        .expect("create returns the token")
        .to_owned();
    assert_eq!(token.len(), 43, "secrets.token_urlsafe(32)");
    let binding = body["binding"].clone();
    assert_eq!(
        body.to_string().matches(&token).count(),
        1,
        "the plaintext token appears exactly once in the response"
    );
    let binding_id = binding["binding_id"]
        .as_str()
        .expect("binding identity")
        .to_owned();
    assert_eq!(binding["tenant_id"], json!(TENANT_A));
    assert_eq!(binding["gateway_license_id"], json!(LICENCE_ID));
    assert_eq!(binding["revision"], json!(1));
    assert_eq!(binding["revoked"], json!(false));
    assert_eq!(binding["spec"]["credential_profile_id"], json!(PROFILE));
    assert_eq!(binding["spec"]["toolkits"][0]["id"], json!(TOOLKIT_1));
    assert_eq!(binding["spec"]["context"]["tenant_id"], json!(TENANT_A));
    assert_eq!(binding["tools"].as_array().expect("tools").len(), 1);
    assert_eq!(binding["tools"][0]["public_name"], json!("alpha_tool"));

    // Get: the stored descriptor, byte-for-byte what create returned under `binding`.
    let (status, headers, inspected) = send(
        &app,
        management(Method::GET, &format!("/mcp/bindings/{binding_id}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(inspected, binding);

    // Patch: 200, revision 2, and no token is reissued.
    let (status, headers, updated) = send(
        &app,
        management(
            Method::PATCH,
            &format!("/mcp/bindings/{binding_id}"),
            Some(binding_update(1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(updated["binding_id"], json!(binding_id));
    assert_eq!(updated["revision"], json!(2));
    assert_eq!(updated["revoked"], json!(false));
    assert!(
        updated.get("token").is_none(),
        "an update mints no token: {updated}"
    );

    // Rotate: 200, a NEW token, revision 3.
    let (status, headers, rotated) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/bindings/{binding_id}/rotate-token"),
            Some(json!({"expected_revision": 2})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    let new_token = rotated["token"]
        .as_str()
        .expect("a rotate returns the new token")
        .to_owned();
    assert_ne!(new_token, token, "rotation issues a new token");
    assert_eq!(rotated["binding"]["binding_id"], json!(binding_id));
    assert_eq!(rotated["binding"]["revision"], json!(3));

    // Revoke: 200, `revoked: true`, revision 4, no token.
    let (status, headers, revoked) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/bindings/{binding_id}/revoke"),
            Some(json!({"expected_revision": 3})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(revoked["binding_id"], json!(binding_id));
    assert_eq!(revoked["revision"], json!(4));
    assert_eq!(revoked["revoked"], json!(true));
    assert!(revoked.get("token").is_none(), "a revoke mints no token");

    // The stored row agrees.
    let (status, _, stored) = send(
        &app,
        management(Method::GET, &format!("/mcp/bindings/{binding_id}"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stored, revoked);

    fixture.finish().await;
}

#[tokio::test]
async fn refusals_carry_the_reference_codes_and_no_store() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let app = fixture.app();
    let (status, _, created) = create_binding(&app).await;
    assert_eq!(status, StatusCode::CREATED);
    let binding_id = created["binding"]["binding_id"]
        .as_str()
        .expect("binding identity")
        .to_owned();

    // 404: an identity this tenant does not own.
    let (status, headers, body) = send(
        &app,
        management(
            Method::GET,
            &format!("/mcp/bindings/{UNKNOWN_BINDING}"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));
    assert_no_store(&headers);

    // 409: a stale expected revision.
    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/bindings/{binding_id}/rotate-token"),
            Some(json!({"expected_revision": 99})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));
    assert_no_store(&headers);

    // 422: an invalid path identity.
    let (status, headers, body) = send(
        &app,
        management(Method::GET, "/mcp/bindings/not-a-uuid", None),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));
    assert_no_store(&headers);

    // 422: a body the strict model refuses.
    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            "/mcp/bindings",
            Some(json!({"credential_profile_id": PROFILE})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));
    assert_no_store(&headers);

    // 401: no management headers at all.
    let (status, headers, body) = send(
        &app,
        with_management(Method::GET, "/mcp/bindings", None, false),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));
    assert_no_store(&headers);

    fixture.finish().await;
}

#[test]
fn the_openapi_document_declares_the_binding_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    let operations = [
        ("/mcp/bindings", "post", false),
        ("/mcp/bindings/{identity}", "get", true),
        ("/mcp/bindings/{identity}", "patch", true),
        ("/mcp/bindings/{identity}/rotate-token", "post", true),
        ("/mcp/bindings/{identity}/revoke", "post", true),
    ];
    for (path, method, validates) in operations {
        let operation = &spec["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert_eq!(operation["tags"], json!(["bindings"]), "{method} {path}");
        // The reference reads every body through `Depends(json_contract(...))`, so its
        // document declares no request body on any of these operations.
        assert!(
            operation.get("requestBody").is_none(),
            "{method} {path} must declare no request body"
        );
        // 422 exists exactly on the operations with a path parameter.
        assert_eq!(
            operation["responses"].get("422").is_some(),
            validates,
            "{method} {path} 422 presence"
        );
        for (code, response) in operation["responses"].as_object().expect("responses") {
            if code == "422" {
                continue;
            }
            assert_eq!(
                response["content"]["application/json"]["schema"],
                json!({"$ref": "#/components/schemas/AnyJson"}),
                "{method} {path} {code} must declare an empty schema"
            );
        }
    }

    // The path parameter: a UUID7 identity.
    let parameters = spec["paths"]["/mcp/bindings/{identity}"]["get"]["parameters"]
        .as_array()
        .expect("parameters");
    assert_eq!(parameters[0]["name"], "identity");
    assert_eq!(parameters[0]["in"], "path");
    assert_eq!(parameters[0]["schema"]["format"], "uuid7");
}
