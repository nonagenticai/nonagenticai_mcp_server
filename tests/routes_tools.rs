//! The eight `/mcp/tools` operations against the real router and a real Postgres 18. Each test
//! fails if the behaviour it covers is removed: every success asserts the reference's response
//! BODY (its `VersionDescriptor` / definitions page / inspect envelope / validation result),
//! a binding credential cannot reach a management route, every refusal renders the reference's
//! `{"error": …}` with `Cache-Control: no-store`, and every route is wired to its handler.
//!
//! Server selection mirrors `tests/db.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL` (a URL whose
//! user may CREATE DATABASE), else an ephemeral `postgres:18` container started here with docker
//! and removed afterwards, else FAIL (never skip). `TEST_PG_REGISTRY` may name a registry mirror.
//! Each test gets its own fresh database, dropped at the end.

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
use mcp_server_rs::{AppState, app_with_auth, db, openapi};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENCE_ID: &str = "30000000-0000-4000-8000-000000000001";
const TOOL: &str = "20000000-0000-7000-8000-000000000001";
const MISSING_TOOL: &str = "20000000-0000-7000-8000-0000000000ff";
const LICENCE_TOKEN: &str = "licence-token";
const BINDING_TOKEN: &str = "binding-token";
const ADMIN_KEY: &str = "routes-tools-operator-key-0123456789";

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
        let name = format!("mcp_routes_tools_{}_{nanos}", std::process::id());
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
                execution: mcp_server_rs::config::ExecutionSettings::default(),
                license_app_key: None,
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

// ── authentication: the real middleware, deterministic licence/binding authorities ────────

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

struct TestBindings;

impl mcp_server_rs::auth::BindingAuthority for TestBindings {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        token: &'a str,
    ) -> BoxFuture<'a, Result<mcp_server_rs::auth::Binding, AuthError>> {
        Box::pin(async move {
            if token != BINDING_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(mcp_server_rs::auth::Binding {
                binding_id: Rfc4122Uuid::parse("01900000-0000-7000-8000-0000000000bb")
                    .expect("static uuid"),
                revision: 1,
            })
        })
    }
}

fn admin_key_file() -> PathBuf {
    let path = std::env::temp_dir().join(format!("mcp-routes-tools-admin-{}", std::process::id()));
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
    auth.bindings = Arc::new(TestBindings);
    auth
}

// ── requests and fixtures ──────────────────────────────────────────────────────────────────

fn management(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
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

fn manifest(tenant: &str, version: u32) -> Value {
    json!({
        "schema_version": 1,
        "tool_id": TOOL,
        "tenant_id": tenant,
        "version": version,
        "public_name": "synthetic_tool",
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

fn upload(tenant: &str, version: u32) -> Value {
    json!({
        "manifest": manifest(tenant, version),
        "files": [{"path": "package/main.py", "content": "print('synthetic')\n"}],
    })
}

fn append(tenant: &str, version: u32, expected_revision: u32) -> Value {
    json!({
        "manifest": manifest(tenant, version),
        "files": [{"path": "package/main.py", "content": "print('synthetic')\n"}],
        "expected_revision": expected_revision,
    })
}

/// The manifest as the reference echoes it: the submitted fields plus every model default.
fn echoed_manifest(tenant: &str, version: u32) -> Value {
    json!({
        "schema_version": 1,
        "tool_id": TOOL,
        "tenant_id": tenant,
        "version": version,
        "public_name": "synthetic_tool",
        "operation": "synthetic.synthetic_tool",
        "description": "Synthetic fixture",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook", "result_node": "MCP Result"},
        "entrypoint": null,
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "runner_image_digest": null,
        "allowed_operations": [],
        "operation_constraints": [],
        "limits": {
            "wall_seconds": 60,
            "queue_seconds": 60,
            "memory_mi": 256,
            "cpu_millicores": 250,
            "api_calls": 10,
            "frame_bytes": 65536,
            "output_bytes": 262144
        },
        "effect": "read_only",
    })
}

/// The reference's `VersionDescriptor`, exactly as `catalog.py` returns it.
fn descriptor(tenant: &str, version: u32, revision: u32, status: &str) -> Value {
    json!({
        "tenant_id": tenant,
        "tool_id": TOOL,
        "version": version,
        "revision": revision,
        "status": status,
        "manifest": echoed_manifest(tenant, version),
        "created_by": {"subject": "svc:test:mcp", "license_id": LICENCE_ID},
        "source": null,
    })
}

/// One row of the reference's definitions query, as its raw DB row serializes.
fn definition(version: u32, revision: u32, status: &str) -> Value {
    json!({
        "tool_id": TOOL,
        "version": version,
        "public_name": "synthetic_tool",
        "revision": revision,
        "status": status,
    })
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_returns_the_first_version_descriptor() {
    let fixture = Fixture::new().await;
    let (status, headers, body) = send(
        &fixture.app(),
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_no_store(&headers);
    // Every field of the reference's VersionDescriptor, no extras and no omissions.
    assert_eq!(body, descriptor(TENANT_A, 1, 1, "draft"));

    let tools: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tools WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(TOOL)
    .fetch_one(&fixture.pool)
    .await
    .expect("read identity");
    assert_eq!(tools, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn append_returns_the_next_version_descriptor() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let (status, _, _) = send(
        &app,
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/tools/{TOOL}/versions"),
            Some(append(TENANT_A, 2, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_no_store(&headers);
    // Version 2 of the same identity, and the identity's revision is bumped to 2.
    assert_eq!(body, descriptor(TENANT_A, 2, 2, "draft"));
    fixture.finish().await;
}

#[tokio::test]
async fn definitions_returns_the_items_and_the_window() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let (status, _, _) = send(
        &app,
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/tools/{TOOL}/versions"),
            Some(append(TENANT_A, 2, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(
            Method::GET,
            "/mcp/tools/definitions?limit=10&offset=0",
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    // Both versions carry the identity's current revision (2), as the reference's join does.
    assert_eq!(
        body,
        json!({
            "items": [definition(1, 2, "draft"), definition(2, 2, "draft")],
            "limit": 10,
            "offset": 0,
        })
    );

    // The window is honoured, not just echoed: offset 1 with limit 1 skips version 1.
    let (status, _, body) = send(
        &app,
        management(Method::GET, "/mcp/tools/definitions?limit=1&offset=1", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "items": [definition(2, 2, "draft")],
            "limit": 1,
            "offset": 1,
        })
    );

    // The reference's defaults: limit 50, offset 0.
    let (status, _, body) = send(
        &app,
        management(Method::GET, "/mcp/tools/definitions", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "items": [definition(1, 2, "draft"), definition(2, 2, "draft")],
            "limit": 50,
            "offset": 0,
        })
    );
    fixture.finish().await;
}

#[tokio::test]
async fn inspect_returns_the_descriptor_and_the_files() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let create = json!({
        "manifest": manifest(TENANT_A, 1),
        "files": [
            {"path": "package/main.py", "content": "print('synthetic')\n"},
            {"path": "package/helper.py", "content": "VALUE = 1\n"},
        ],
    });
    let (status, _, created_body) =
        send(&app, management(Method::POST, "/mcp/tools", Some(create))).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(Method::GET, &format!("/mcp/tools/{TOOL}/versions/1"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    // The descriptor of the inspected version, byte-for-byte what create returned, and every
    // package file with its exact content, ordered by path as the reference's query does.
    assert_eq!(body["descriptor"], created_body);
    assert_eq!(
        body["files"],
        json!([
            {"path": "package/helper.py", "content": "VALUE = 1\n"},
            {"path": "package/main.py", "content": "print('synthetic')\n"},
        ])
    );
    assert_eq!(
        body.as_object()
            .expect("inspect envelope")
            .keys()
            .map(String::as_str)
            .collect::<Vec<_>>(),
        ["descriptor", "files"],
        "inspect answers exactly the reference's two keys"
    );
    fixture.finish().await;
}

#[tokio::test]
async fn validate_returns_the_reference_result() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let (status, _, _) = send(
        &app,
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/tools/{TOOL}/versions/1/validate"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(
        body,
        json!({
            "tool_id": TOOL,
            "version": 1,
            "metadata_valid": true,
            "credentials_verified": false,
            "execution": "unavailable",
        })
    );
    fixture.finish().await;
}

#[tokio::test]
async fn transitions_return_the_descriptor_with_the_new_status() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let (status, _, _) = send(
        &app,
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // draft (revision 1) → published (2) → disabled (3) → retired (4).
    for (action, expected_revision, status_text, revision) in [
        ("publish", 1, "published", 2),
        ("disable", 2, "disabled", 3),
        ("retire", 3, "retired", 4),
    ] {
        let (status, headers, body) = send(
            &app,
            management(
                Method::POST,
                &format!("/mcp/tools/{TOOL}/versions/1/{action}"),
                Some(json!({"expected_revision": expected_revision})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{action}");
        assert_no_store(&headers);
        assert_eq!(
            body,
            descriptor(TENANT_A, 1, revision, status_text),
            "{action} must answer the affected version's descriptor"
        );
    }

    let status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_tool_versions \
         WHERE tenant_id = $1::uuid AND tool_id = $2::uuid AND version = 1",
    )
    .bind(TENANT_A)
    .bind(TOOL)
    .fetch_one(&fixture.pool)
    .await
    .expect("read status");
    assert_eq!(status, "retired");
    fixture.finish().await;
}

#[tokio::test]
async fn a_binding_credential_never_reaches_a_management_route() {
    let fixture = Fixture::new().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/tools")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", BINDING_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(upload(TENANT_A, 1).to_string()))
        .expect("request");
    let (status, headers, body) = send(&fixture.app(), request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));
    assert_no_store(&headers);
    fixture.finish().await;
}

#[tokio::test]
async fn a_manifest_for_another_tenant_is_forbidden() {
    let fixture = Fixture::new().await;
    let (status, headers, body) = send(
        &fixture.app(),
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_B, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));
    assert_no_store(&headers);
    fixture.finish().await;
}

#[tokio::test]
async fn refusals_carry_the_reference_codes_and_no_store() {
    let fixture = Fixture::new().await;
    let app = fixture.app();

    // 404: an identity this tenant does not own.
    let (status, headers, body) = send(
        &app,
        management(
            Method::GET,
            &format!("/mcp/tools/{MISSING_TOOL}/versions/1"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));
    assert_no_store(&headers);

    // 409: a stale expected revision.
    let (status, _, _) = send(
        &app,
        management(Method::POST, "/mcp/tools", Some(upload(TENANT_A, 1))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/tools/{TOOL}/versions/1/publish"),
            Some(json!({"expected_revision": 99})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));
    assert_no_store(&headers);

    // 422: a body the strict model refuses.
    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            "/mcp/tools",
            Some(json!({"manifest": {"tool_id": TOOL}})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));
    assert_no_store(&headers);

    // 422: the path identity and the manifest identity disagree.
    let (status, _, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/tools/{MISSING_TOOL}/versions"),
            Some(append(TENANT_A, 2, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));
    fixture.finish().await;
}

#[test]
fn the_openapi_document_declares_the_tools_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    let operations = [
        ("/mcp/tools", "post"),
        ("/mcp/tools/{identity}/versions", "post"),
        ("/mcp/tools/definitions", "get"),
        ("/mcp/tools/{identity}/versions/{version}", "get"),
        ("/mcp/tools/{identity}/versions/{version}/validate", "post"),
        ("/mcp/tools/{identity}/versions/{version}/publish", "post"),
        ("/mcp/tools/{identity}/versions/{version}/disable", "post"),
        ("/mcp/tools/{identity}/versions/{version}/retire", "post"),
    ];
    for (path, method) in operations {
        assert!(
            spec["paths"][path][method].is_object(),
            "missing {method} {path}"
        );
    }
    // Request bodies exist on exactly the five operations the reference declares them on.
    for (path, method) in operations {
        let has_body = spec["paths"][path][method].get("requestBody").is_some();
        let expected = matches!(
            path,
            "/mcp/tools"
                | "/mcp/tools/{identity}/versions"
                | "/mcp/tools/{identity}/versions/{version}/publish"
                | "/mcp/tools/{identity}/versions/{version}/disable"
                | "/mcp/tools/{identity}/versions/{version}/retire"
        );
        assert_eq!(
            has_body, expected,
            "request body presence on {method} {path}"
        );
    }
    // The 422 component the reference's path parameters imply.
    assert_eq!(
        spec["components"]["schemas"]["HTTPValidationError"]["properties"]["detail"]["items"]["$ref"],
        json!("#/components/schemas/ValidationError")
    );
    assert_eq!(
        spec["components"]["schemas"]["ValidationError"]["required"],
        json!(["loc", "msg", "type"])
    );
    // Every success response declares an empty schema, exactly like the reference's document.
    assert_eq!(spec["components"]["schemas"]["AnyJson"], json!({}));
    for (path, method) in operations {
        let responses = spec["paths"][path][method]["responses"]
            .as_object()
            .expect("responses");
        for (code, response) in responses {
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
}
