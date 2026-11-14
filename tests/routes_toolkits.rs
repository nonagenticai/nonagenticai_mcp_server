//! The six `/mcp/toolkits` operations against the real router and a real Postgres 18. Each test
//! fails if the behaviour it covers is removed: every success asserts the reference's response
//! BODY field by field (the parity gate cannot see bodies), a caller that may not manage is
//! refused, every refusal renders the reference's `{"error": …}` with `Cache-Control: no-store`,
//! and the OpenAPI document declares the reference's shapes (no request body, 201/200, 422 only
//! where a path or query parameter exists).
//!
//! Server selection mirrors `tests/routes_tools.rs`: `TEST_DATABASE_URL`, else `DATABASE_URL`
//! (a URL whose user may CREATE DATABASE), else an ephemeral `postgres:18` container started
//! here with docker and removed afterwards, else FAIL (never skip). `TEST_PG_REGISTRY` may name
//! a registry mirror. Each test gets its own fresh database, dropped at the end.

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
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::{AppState, app_with_auth, db, openapi};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENCE_ID: &str = "30000000-0000-4000-8000-000000000001";
const TOOL: &str = "20000000-0000-7000-8000-000000000001";
const TOOLKIT: &str = "01900000-0000-7000-8000-000000000001";
const TOOLKIT_TWO: &str = "01900000-0000-7000-8000-000000000002";
const UNKNOWN_TOOLKIT: &str = "01900000-0000-7000-8000-0000000000ff";
const LICENCE_TOKEN: &str = "licence-token";
const BINDING_TOKEN: &str = "binding-token";
const ADMIN_KEY: &str = "routes-toolkits-operator-key-0123456";

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
        let name = format!("mcp_routes_toolkits_{}_{nanos}", std::process::id());
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
                license_app_key: Some("synthetic".to_owned()),
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
        std::env::temp_dir().join(format!("mcp-routes-toolkits-admin-{}", std::process::id()));
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
        subject: "svc:test:mcp".to_owned(),
        license_id: Some(authority(LICENCE_ID)),
    }
}

/// A strict, valid tool manifest. The runtime is external so no package digest is involved.
fn tool_manifest() -> ToolManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "tool_id": TOOL,
        "tenant_id": TENANT_A,
        "version": 1,
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
    }))
    .expect("valid tool manifest")
}

fn files() -> Vec<PackageFile> {
    vec![PackageFile {
        path: "package/main.py".to_owned(),
        content: "print('synthetic')\n".to_owned(),
    }]
}

/// A published tool owned by tenant A, selectable by a toolkit.
async fn published_tool(fixture: &Fixture) {
    let repository = CatalogRepository::new(fixture.pool.clone());
    let tenant = authority(TENANT_A);
    repository
        .create(&tenant, &tool_manifest(), &files(), &actor())
        .await
        .expect("create tool");
    repository
        .transition(
            &tenant,
            &identity(TOOL),
            version(1),
            VersionStatus::Published,
            &actor(),
            version(1),
        )
        .await
        .expect("publish tool");
}

/// The reference's `ToolkitManifest` body: only the fields a caller sends.
fn toolkit_body(tenant: &str, toolkit: &str, toolkit_version: u32, name: &str) -> Value {
    json!({
        "schema_version": 1,
        "toolkit_id": toolkit,
        "tenant_id": tenant,
        "version": toolkit_version,
        "name": name,
        "description": "Synthetic toolkit",
        "tools": [{"tool": {"id": TOOL, "version": 1, "tenant_id": tenant}}],
    })
}

/// The reference's `ToolkitUpdate` body.
fn toolkit_update(toolkit: &str, toolkit_version: u32, expected_revision: u32) -> Value {
    json!({
        "expected_revision": expected_revision,
        "manifest": toolkit_body(TENANT_A, toolkit, toolkit_version, "synthetic_toolkit"),
    })
}

/// The tool's default limits, as `ToolLimits` serializes them.
fn limits() -> Value {
    json!({
        "wall_seconds": 60,
        "queue_seconds": 60,
        "memory_mi": 256,
        "cpu_millicores": 250,
        "api_calls": 10,
        "frame_bytes": 65536,
        "output_bytes": 262144,
    })
}

/// The manifest as the reference echoes it: the submitted fields plus every model default.
fn echoed_manifest(toolkit: &str, toolkit_version: u32, name: &str) -> Value {
    json!({
        "schema_version": 1,
        "toolkit_id": toolkit,
        "tenant_id": TENANT_A,
        "version": toolkit_version,
        "name": name,
        "description": "Synthetic toolkit",
        "tools": [{
            "tool": {"id": TOOL, "version": 1, "tenant_id": TENANT_A},
            "operation_constraints": [],
            "limits": limits(),
        }],
        "includes": [],
        "applicability": {
            "capability": null,
            "project_phase": null,
            "work_type": null,
            "card_stage": null,
            "responsibility": null,
        },
    })
}

/// The reference's `ToolkitDescriptor`, exactly as the toolkit service returns it.
fn descriptor(
    toolkit: &str,
    toolkit_version: u32,
    revision: u32,
    status: &str,
    name: &str,
) -> Value {
    json!({
        "manifest": echoed_manifest(toolkit, toolkit_version, name),
        "revision": revision,
        "status": status,
        "tools": [{
            "tool": {"id": TOOL, "version": 1, "tenant_id": TENANT_A},
            "operation_constraints": [],
            "limits": limits(),
            "public_name": "synthetic_tool",
        }],
    })
}

async fn create(app: &Router, toolkit: &str, name: &str) -> (StatusCode, HeaderMap, Value) {
    send(
        app,
        management(
            Method::POST,
            "/mcp/toolkits",
            Some(toolkit_body(TENANT_A, toolkit, 1, name)),
        ),
    )
    .await
}

// ── tests ─────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn create_returns_the_descriptor_and_echoes_nothing_extra() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let (status, headers, body) = create(&fixture.app(), TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);
    assert_no_store(&headers);
    // The full descriptor, field by field: the submitted manifest plus every model default, and
    // nothing the request did not send.
    assert_eq!(
        body,
        descriptor(TOOLKIT, 1, 1, "draft", "synthetic_toolkit")
    );

    let identities: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_toolkits WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(TOOLKIT)
    .fetch_one(&fixture.pool)
    .await
    .expect("read identity");
    assert_eq!(identities, 1);
    fixture.finish().await;
}

#[tokio::test]
async fn append_returns_the_next_version_descriptor() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let app = fixture.app();
    let (status, _, _) = create(&app, TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/toolkits/{TOOLKIT}/versions"),
            Some(toolkit_update(TOOLKIT, 2, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_no_store(&headers);
    // Version 2 of the same identity, and the identity's revision is bumped to 2.
    assert_eq!(
        body,
        descriptor(TOOLKIT, 2, 2, "draft", "synthetic_toolkit")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn list_returns_the_items_and_the_window() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let app = fixture.app();
    let (status, _, _) = create(&app, TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = create(&app, TOOLKIT_TWO, "second_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(&app, management(Method::GET, "/mcp/toolkits", None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    // The reference's defaults: limit 50, offset 0; identities ordered by identity.
    assert_eq!(
        body,
        json!({
            "items": [
                {"toolkit_id": TOOLKIT, "name": "synthetic_toolkit", "revision": 1},
                {"toolkit_id": TOOLKIT_TWO, "name": "second_toolkit", "revision": 1},
            ],
            "limit": 50,
            "offset": 0,
        })
    );

    // The window is honoured, not just echoed.
    let (status, _, body) = send(
        &app,
        management(Method::GET, "/mcp/toolkits?limit=1&offset=1", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        body,
        json!({
            "items": [{"toolkit_id": TOOLKIT_TWO, "name": "second_toolkit", "revision": 1}],
            "limit": 1,
            "offset": 1,
        })
    );
    fixture.finish().await;
}

#[tokio::test]
async fn inspect_returns_the_exact_descriptor() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let app = fixture.app();
    let (status, _, created_body) = create(&app, TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, headers, body) = send(
        &app,
        management(
            Method::GET,
            &format!("/mcp/toolkits/{TOOLKIT}/versions/1"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    // The descriptor of the inspected version, byte-for-byte what create returned.
    assert_eq!(body, created_body);
    assert_eq!(
        body,
        descriptor(TOOLKIT, 1, 1, "draft", "synthetic_toolkit")
    );
    fixture.finish().await;
}

#[tokio::test]
async fn transitions_return_the_descriptor_with_the_new_status() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let app = fixture.app();
    let (status, _, _) = create(&app, TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);

    // draft (revision 1) → published (2) → disabled (3).
    for (action, expected_revision, status_text, revision) in [
        ("publish", 1, "published", 2),
        ("disable", 2, "disabled", 3),
    ] {
        let (status, headers, body) = send(
            &app,
            management(
                Method::POST,
                &format!("/mcp/toolkits/{TOOLKIT}/versions/1/{action}"),
                Some(json!({"expected_revision": expected_revision})),
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{action}");
        assert_no_store(&headers);
        assert_eq!(
            body,
            descriptor(TOOLKIT, 1, revision, status_text, "synthetic_toolkit"),
            "{action} must answer the affected version's descriptor"
        );
    }

    let status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_toolkit_versions \
         WHERE tenant_id = $1::uuid AND toolkit_id = $2::uuid AND version = 1",
    )
    .bind(TENANT_A)
    .bind(TOOLKIT)
    .fetch_one(&fixture.pool)
    .await
    .expect("read status");
    assert_eq!(status, "disabled");
    fixture.finish().await;
}

#[tokio::test]
async fn refusals_carry_the_reference_codes_and_no_store() {
    let fixture = Fixture::new().await;
    published_tool(&fixture).await;
    let app = fixture.app();

    // 404: an identity this tenant does not own.
    let (status, headers, body) = send(
        &app,
        management(
            Method::GET,
            &format!("/mcp/toolkits/{UNKNOWN_TOOLKIT}/versions/1"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));
    assert_no_store(&headers);

    // 404: publishing an identity that does not exist.
    let (status, _, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/toolkits/{UNKNOWN_TOOLKIT}/versions/1/publish"),
            Some(json!({"expected_revision": 1})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));

    // 404: a non-positive version is a bare integer that simply finds no row.
    let (status, _, body) = send(
        &app,
        management(
            Method::GET,
            &format!("/mcp/toolkits/{TOOLKIT}/versions/0"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "not_found"}));

    // 409: a stale expected revision.
    let (status, _, _) = create(&app, TOOLKIT, "synthetic_toolkit").await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/toolkits/{TOOLKIT}/versions/1/publish"),
            Some(json!({"expected_revision": 99})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));
    assert_no_store(&headers);

    // 422: an invalid path identity, a non-integer path version, and every bad pagination.
    for uri in [
        "/mcp/toolkits/not-a-uuid/versions/1".to_owned(),
        format!("/mcp/toolkits/{TOOLKIT}/versions/not-a-number"),
        "/mcp/toolkits?limit=0".to_owned(),
        "/mcp/toolkits?limit=101".to_owned(),
        "/mcp/toolkits?offset=-1".to_owned(),
    ] {
        let (status, headers, body) = send(&app, management(Method::GET, &uri, None)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{uri}");
        assert_eq!(body, json!({"error": "invalid_request"}), "{uri}");
        assert_no_store(&headers);
    }

    // 422: the path identity and the manifest identity disagree.
    let (status, _, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/toolkits/{TOOLKIT_TWO}/versions"),
            Some(toolkit_update(TOOLKIT, 2, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));

    // 422: a body the strict model refuses.
    let (status, _, body) = send(
        &app,
        management(
            Method::POST,
            "/mcp/toolkits",
            Some(json!({"toolkit_id": TOOLKIT})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_eq!(body, json!({"error": "invalid_request"}));
    fixture.finish().await;
}

#[tokio::test]
async fn a_binding_credential_never_reaches_a_toolkit_route() {
    let fixture = Fixture::new().await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/toolkits")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", BINDING_TOKEN)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            toolkit_body(TENANT_A, TOOLKIT, 1, "synthetic_toolkit").to_string(),
        ))
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
        management(
            Method::POST,
            "/mcp/toolkits",
            Some(toolkit_body(TENANT_B, TOOLKIT, 1, "synthetic_toolkit")),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));
    assert_no_store(&headers);
    fixture.finish().await;
}

#[test]
fn the_openapi_document_declares_the_toolkit_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    let operations = [
        ("/mcp/toolkits", "post", false),
        ("/mcp/toolkits/{identity}/versions", "post", true),
        ("/mcp/toolkits", "get", true),
        ("/mcp/toolkits/{identity}/versions/{version}", "get", true),
        (
            "/mcp/toolkits/{identity}/versions/{version}/publish",
            "post",
            true,
        ),
        (
            "/mcp/toolkits/{identity}/versions/{version}/disable",
            "post",
            true,
        ),
    ];
    for (path, method, validates) in operations {
        let operation = &spec["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert_eq!(operation["tags"], json!(["toolkits"]), "{method} {path}");
        // The reference reads every body through `Depends(json_contract(...))`, so its
        // document declares no request body on any of these operations.
        assert!(
            operation.get("requestBody").is_none(),
            "{method} {path} must declare no request body"
        );
        // 422 exists exactly on the operations with a path or query parameter.
        assert_eq!(
            operation["responses"].get("422").is_some(),
            validates,
            "{method} {path} 422 presence"
        );
        // Every success response declares the reference's empty schema.
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

    // The list query: the reference's `int` defaults, with no bounds keywords (the handler
    // performs the bounds check itself).
    let parameters = spec["paths"]["/mcp/toolkits"]["get"]["parameters"]
        .as_array()
        .expect("parameters");
    assert_eq!(parameters.len(), 2);
    for (index, (name, default)) in [("limit", 50), ("offset", 0)].into_iter().enumerate() {
        assert_eq!(parameters[index]["in"], "query");
        assert_eq!(parameters[index]["name"], name);
        assert_eq!(parameters[index]["required"], false);
        assert_eq!(parameters[index]["schema"]["type"], "integer");
        assert_eq!(parameters[index]["schema"]["default"], default);
        assert!(parameters[index]["schema"].get("minimum").is_none());
        assert!(parameters[index]["schema"].get("maximum").is_none());
    }
    // The path parameters: a UUID7 identity and a bare integer version.
    let parameters =
        spec["paths"]["/mcp/toolkits/{identity}/versions/{version}"]["get"]["parameters"]
            .as_array()
            .expect("parameters");
    assert_eq!(parameters[0]["name"], "identity");
    assert_eq!(parameters[0]["in"], "path");
    assert_eq!(parameters[0]["schema"]["format"], "uuid7");
    assert_eq!(parameters[1]["name"], "version");
    assert_eq!(parameters[1]["in"], "path");
    assert_eq!(parameters[1]["schema"]["type"], "integer");
    assert!(parameters[1]["schema"].get("minimum").is_none());
}
