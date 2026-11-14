//! `/mcp` authentication and authorisation against the real router.
//!
//! The licence authority is an external HTTP boundary, so it is faked with a real local HTTP
//! server returning canned introspection payloads: that exercises the real client (request
//! body, app-key matching, active/expiry/UUID checks) rather than replacing it. The binding
//! lookup is a storage seam and is faked at the trait, as the storage slice will implement it.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Router;
use axum::body::Body;
use axum::extract::Json;
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderMap, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::post;
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sqlx::postgres::PgPoolOptions;
use tower::ServiceExt;

use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, AuthPrincipal, Binding, BindingAuthority, BoxFuture,
    LicenseIdentity, Rfc4122Uuid, protect,
};
use mcp_server_rs::{AppState, app_with_auth};

const TENANT: &str = "5f868d42-03f8-51f0-a93c-3e83070dc196";
const OTHER_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
const LICENCE: &str = "01900000-0000-7000-8000-0000000000aa";
const BINDING: &str = "01900000-0000-7000-8000-0000000000bb";
const ADMIN_KEY: &str = "tenant-operator-key-0123456789abcdef";
const PLATFORM_KEY: &str = "platform-operator-key-0123456789abcdef";
const LICENCE_TOKEN: &str = "licence-token";
const BINDING_TOKEN: &str = "binding-token";

// ── the fake licence authority (a real HTTP server) ─────────────────────────────────────────

struct Authority {
    url: String,
    requests: tokio::sync::mpsc::UnboundedReceiver<Value>,
}

async fn authority(reply: Value) -> Authority {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind authority");
    let address = listener.local_addr().expect("authority address");
    let (sender, requests) = tokio::sync::mpsc::unbounded_channel();
    let router = Router::new().route(
        "/license/introspect",
        post(move |Json(body): Json<Value>| {
            let reply = reply.clone();
            let sender = sender.clone();
            async move {
                let _ = sender.send(body);
                Json(reply)
            }
        }),
    );
    tokio::spawn(async move {
        axum::serve(listener, router)
            .await
            .expect("authority server");
    });
    Authority {
        url: format!("http://{address}/license/introspect"),
        requests,
    }
}

fn active_licence(app: &str, tenant: &str, subject_kind: &str) -> Value {
    json!({
        "active": true,
        "app": {"key": app},
        "tenant_id": tenant,
        "license_id": LICENCE,
        "subject_id": "svc:tenant:mcp",
        "subject_kind": subject_kind,
        "expires_at": "2099-01-01T00:00:00.000000+00:00",
        "token_expires_at": Value::Null,
    })
}

// ── key files, the binding seam and the app under test ──────────────────────────────────────

static KEY_FILE_COUNTER: AtomicU64 = AtomicU64::new(0);

struct KeyFile {
    path: PathBuf,
}

impl KeyFile {
    fn new(contents: &[u8]) -> Self {
        let path = std::env::temp_dir().join(format!(
            "mcp-auth-test-{}-{}.key",
            std::process::id(),
            KEY_FILE_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::write(&path, contents).expect("write key file");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for KeyFile {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

struct FakeBindings;

impl BindingAuthority for FakeBindings {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async move {
            if token != BINDING_TOKEN {
                return Err(AuthError::Unauthorized);
            }
            Ok(Binding {
                binding_id: Rfc4122Uuid::parse(BINDING).expect("static uuid"),
                revision: 7,
            })
        })
    }
}

fn config(
    authority: Option<&str>,
    admin_key: Option<&Path>,
    platform_key: Option<&Path>,
) -> AuthConfig {
    AuthConfig {
        license_introspect_url: authority.map(str::to_owned),
        license_app_key: authority.map(|_| "mcp".to_owned()),
        license_allow_http: true,
        admin_key_file: admin_key.map(Path::to_path_buf),
        admin_tenant_ids: vec![Rfc4122Uuid::parse(TENANT).expect("static uuid")],
        platform_admin_key_file: platform_key.map(Path::to_path_buf),
        ..AuthConfig::default()
    }
}

fn auth(settings: &AuthConfig) -> Auth {
    Auth::from_config(settings)
        .expect("valid auth config")
        .with_bindings(Arc::new(FakeBindings))
}

fn state() -> AppState {
    let pool = PgPoolOptions::new()
        .acquire_timeout(std::time::Duration::from_millis(500))
        .connect_lazy("postgres://unused:unused@127.0.0.1:1/unused")
        .expect("lazy pool");
    AppState {
        pool,
        execution_enabled: false,
        execution: mcp_server_rs::config::ExecutionSettings::default(),
        license_app_key: None,
        approved_runner_images: Vec::new(),
        platform_tenant_id: mcp_server_rs::auth::Rfc4122Uuid::parse(
            "01900000-0000-7000-8000-00000000f001",
        )
        .expect("static uuid"),
        catalog_page_size: 10,
    }
}

fn real_app(auth: Auth) -> Router {
    app_with_auth(state(), auth)
}

/// The same middleware over probe routes, so principals can be observed. `/mcp/tools` is a
/// management path and `/mcp/available-tools` a binding path, exactly as on the real router.
fn probe(auth: Auth) -> Router {
    Router::new()
        .route("/mcp/tools", post(whoami))
        .route("/mcp/available-tools", post(whoami))
        .layer(axum::middleware::from_fn_with_state(auth, protect))
}

async fn whoami(AuthPrincipal(principal): AuthPrincipal) -> Json<Value> {
    Json(json!({
        "tenant_id": principal.tenant_id.to_string(),
        "license_id": principal.license_id.to_string(),
        "subject": principal.subject,
        "binding_id": principal.binding_id.map(|id| id.to_string()),
        "binding_revision": principal.binding_revision,
        "management": principal.management,
        "platform": principal.platform,
    }))
}

// ── request/response helpers ───────────────────────────────────────────────────────────────

async fn call(router: Router, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
    let response = router.oneshot(request).await.expect("infallible service");
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("response body")
        .to_bytes();
    let body = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes).unwrap_or(Value::Null)
    };
    (status, headers, body)
}

fn binding_request(path: &str, token: &str, binding: &str) -> Request<Body> {
    Request::post(path)
        .header("x-tenant-id", format!("Bearer {token}"))
        .header("x-mcp-binding", binding)
        .header("content-type", "application/json")
        .body(Body::empty())
        .expect("request")
}

fn management_request(path: &str, token: &str, admin_key: &str) -> Request<Body> {
    Request::post(path)
        .header("x-tenant-id", format!("Bearer {token}"))
        .header("x-mcp-admin-key", admin_key)
        .header("content-type", "application/json")
        .body(Body::from(r#"{"body":true}"#))
        .expect("request")
}

fn assert_unauthorized(status: StatusCode, headers: &HeaderMap, body: &Value) {
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, &json!({ "error": "unauthorized" }));
    assert_eq!(
        headers.get(WWW_AUTHENTICATE).expect("WWW-Authenticate"),
        "Bearer"
    );
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("Cache-Control"),
        "no-store"
    );
}

// ── the contract ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn every_mcp_path_is_protected() {
    let app = real_app(auth(&config(None, None, None)));
    for request in [
        Request::post("/mcp").body(Body::empty()).unwrap(),
        Request::get("/mcp/").body(Body::empty()).unwrap(),
        Request::get("/mcp/tools").body(Body::empty()).unwrap(),
        Request::get("/mcp/unknown/route")
            .body(Body::empty())
            .unwrap(),
    ] {
        let path = request.uri().path().to_owned();
        let (status, headers, body) = call(app.clone(), request).await;
        assert_unauthorized(status, &headers, &body);
        assert_eq!(body, json!({ "error": "unauthorized" }), "{path}");
    }
}

#[tokio::test]
async fn missing_licence_is_401_and_the_authority_is_never_called() {
    let mut authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        Request::post("/mcp/available-tools")
            .header("x-mcp-binding", BINDING_TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
    assert!(
        authority.requests.try_recv().is_err(),
        "no credential must mean no introspection call"
    );
}

#[tokio::test]
async fn trusted_tenant_header_alone_never_authorises() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        Request::post("/mcp/available-tools")
            .header("x-tenant-id", TENANT) // bare id, not "Bearer <licence>"
            .header("x-mcp-binding", BINDING_TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn inactive_licence_is_401() {
    let authority = authority(json!({ "active": false, "reason": "token_not_found" })).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn licence_for_another_app_is_401() {
    let mut authority = authority(active_licence("care-bus", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
    // The introspection request is the contract: the presented token and THIS app's key.
    let sent = authority
        .requests
        .recv()
        .await
        .expect("introspection request");
    assert_eq!(sent, json!({ "token": LICENCE_TOKEN, "app": "mcp" }));
}

#[tokio::test]
async fn expired_licence_is_401() {
    let mut reply = active_licence("mcp", TENANT, "tenant");
    reply["expires_at"] = json!("2000-01-01T00:00:00+00:00");
    let authority = authority(reply).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn binding_requires_a_tenant_level_licence() {
    // A member's per-login licence never authenticates a binding.
    let authority = authority(active_licence("mcp", TENANT, "member")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn available_tools_without_a_binding_header_is_401() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        Request::post("/mcp/available-tools")
            .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn binding_credentials_resolve_a_principal() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = probe(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app.clone(),
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("Cache-Control"),
        "no-store"
    );
    assert_eq!(
        body,
        json!({
            "tenant_id": TENANT,
            "license_id": LICENCE,
            "subject": "svc:tenant:mcp",
            "binding_id": BINDING,
            "binding_revision": 7,
            "management": false,
            "platform": false,
        })
    );
    // A token the binding authority refuses is a 401, not a principal.
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, "wrong-binding"),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn authorization_bearer_is_the_binding_fallback() {
    // Off-cluster through the ingress the edge strips X-Tenant-Id, so a binding caller sends
    // its licence as Authorization: Bearer. It is authenticated exactly like the header form.
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = probe(auth(&config(Some(&authority.url), None, None)));
    let (status, _, body) = call(
        app.clone(),
        Request::post("/mcp/available-tools")
            .header("authorization", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-mcp-binding", BINDING_TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["binding_id"], BINDING);
    // Management keeps X-Tenant-Id only: Authorization never satisfies a management path.
    let (status, headers, body) = call(
        app,
        Request::post("/mcp/tools")
            .header("authorization", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-mcp-admin-key", ADMIN_KEY)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn duplicate_credentials_are_refused() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        Request::post("/mcp/available-tools")
            .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-mcp-binding", BINDING_TOKEN)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn licence_with_a_non_rfc4122_identity_is_401() {
    let mut reply = active_licence("mcp", "not-a-uuid", "tenant");
    reply["license_id"] = json!("01900000-0000-7000-0000-0000000000aa"); // reserved variant
    let authority = authority(reply).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn management_rejects_a_tenant_outside_the_allowlist() {
    let authority = authority(active_licence("mcp", OTHER_TENANT, "tenant")).await;
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let app = real_app(auth(&config(
        Some(&authority.url),
        Some(admin.path()),
        None,
    )));
    let (status, headers, body) = call(
        app,
        management_request("/mcp/tools", LICENCE_TOKEN, ADMIN_KEY),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn management_rejects_a_wrong_operator_key() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let app = real_app(auth(&config(
        Some(&authority.url),
        Some(admin.path()),
        None,
    )));
    let (status, headers, body) = call(
        app,
        management_request(
            "/mcp/tools",
            LICENCE_TOKEN,
            "not-the-operator-key-0123456789",
        ),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn management_accepts_the_operator_key() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let app = probe(auth(&config(
        Some(&authority.url),
        Some(admin.path()),
        None,
    )));
    let (status, headers, body) = call(
        app,
        management_request("/mcp/tools", LICENCE_TOKEN, ADMIN_KEY),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("Cache-Control"),
        "no-store"
    );
    assert_eq!(
        body,
        json!({
            "tenant_id": TENANT,
            "license_id": LICENCE,
            "subject": "svc:tenant:mcp",
            "binding_id": Value::Null,
            "binding_revision": Value::Null,
            "management": true,
            "platform": false,
        })
    );
}

#[tokio::test]
async fn platform_key_marks_the_principal_platform() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let platform = KeyFile::new(PLATFORM_KEY.as_bytes());
    let app = probe(auth(&config(
        Some(&authority.url),
        Some(admin.path()),
        Some(platform.path()),
    )));
    let request = |platform_key: Option<&str>| {
        let mut builder = Request::post("/mcp/tools")
            .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
            .header("x-mcp-admin-key", ADMIN_KEY);
        if let Some(key) = platform_key {
            builder = builder.header("x-mcp-platform-admin-key", key);
        }
        builder.body(Body::empty()).unwrap()
    };
    let (status, _, body) = call(app.clone(), request(Some(PLATFORM_KEY))).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["management"], true);
    assert_eq!(body["platform"], true);
    // Presenting the wrong platform key is refused even with the correct operator key.
    let (status, headers, body) =
        call(app, request(Some("not-the-platform-key-0123456789abcdef"))).await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn management_paths_refuse_binding_credentials() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let app = real_app(auth(&config(Some(&authority.url), None, None)));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_unauthorized(status, &headers, &body);
}

#[tokio::test]
async fn oversized_management_body_is_413() {
    let authority = authority(active_licence("mcp", TENANT, "tenant")).await;
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let settings = AuthConfig {
        max_management_bytes: 16,
        ..config(Some(&authority.url), Some(admin.path()), None)
    };
    let app = real_app(auth(&settings));
    let request = Request::post("/mcp/tools")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY)
        .header("content-type", "application/json")
        .body(Body::from("x".repeat(1024)))
        .unwrap();
    let (status, headers, body) = call(app, request).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(body, json!({ "error": "request_too_large" }));
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("Cache-Control"),
        "no-store"
    );
}

#[tokio::test]
async fn unconfigured_authority_fails_closed() {
    let app = real_app(auth(&AuthConfig::default()));
    let (status, headers, body) = call(
        app,
        binding_request("/mcp/available-tools", LICENCE_TOKEN, BINDING_TOKEN),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({ "error": "authority_unavailable" }));
    assert_eq!(
        headers.get(CACHE_CONTROL).expect("Cache-Control"),
        "no-store"
    );
}

#[tokio::test]
async fn startup_rejects_two_equal_key_files() {
    let admin = KeyFile::new(ADMIN_KEY.as_bytes());
    let platform = KeyFile::new(ADMIN_KEY.as_bytes());
    let settings = config(
        Some("https://licenses.example/license/introspect"),
        Some(admin.path()),
        Some(platform.path()),
    );
    assert!(Auth::from_config(&settings).is_err());
}

#[tokio::test]
async fn startup_rejects_a_short_or_non_printable_key() {
    let cases: Vec<Vec<u8>> = vec![b"short-key".to_vec(), vec![b'x'; 31], vec![b'x'; 4097]];
    for contents in &cases {
        let admin = KeyFile::new(contents);
        let settings = config(
            Some("https://licenses.example/license/introspect"),
            Some(admin.path()),
            None,
        );
        assert!(
            Auth::from_config(&settings).is_err(),
            "{} bytes must be refused",
            contents.len()
        );
    }
    // Trailing whitespace is stripped before the length check, as the reference reader does.
    let mut padded = ADMIN_KEY.as_bytes().to_vec();
    padded.push(b'\n');
    let admin = KeyFile::new(&padded);
    let settings = config(
        Some("https://licenses.example/license/introspect"),
        Some(admin.path()),
        None,
    );
    assert!(Auth::from_config(&settings).is_ok());
}

#[tokio::test]
async fn forbidden_maps_to_the_fixed_body() {
    // 403 has no wire path in this slice (it belongs to the builder/internal routes); the
    // mapping is still part of the contract the storage and route slices rely on.
    let response = AuthError::Forbidden.into_response();
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    assert_eq!(
        response
            .headers()
            .get(CACHE_CONTROL)
            .expect("Cache-Control"),
        "no-store"
    );
    let bytes = response
        .into_body()
        .collect()
        .await
        .expect("body")
        .to_bytes();
    assert_eq!(
        serde_json::from_slice::<Value>(&bytes).expect("json"),
        json!({ "error": "forbidden" })
    );
}
