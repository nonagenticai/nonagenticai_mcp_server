//! The seven platform-operator tool-source operations under `/mcp/sources` against the real
//! router and a real Postgres 18.
//!
//! Every success asserts the reference's response BODY field by field (the parity gate cannot
//! see bodies); a caller without the platform key is refused; a build without the platform pool
//! answers the reference's `503 {"detail": …}`; a sealing write without an
//! `MCP_SOURCE_SECRET_KEY` answers the reference's `503 source_secret_unavailable`; every other
//! refusal renders the reference's `{"error": …}` with `Cache-Control: no-store`. The stored
//! secret is checked through the real crypto contract — the row's ciphertext is opened with the
//! configured key, so "retained" and "rotated" are proven, not inferred from timestamps — and
//! no response body ever carries a token or the ciphertext column.
//!
//! The platform pool is a second pool to the same test database, standing in for
//! `MCP_PLATFORM_DATABASE_URL` (the same database under the elevated platform role). Server
//! selection and the fresh-database-per-test rule come from `tests/support`.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use mcp_server_rs::auth::{Auth, AuthConfig, Rfc4122Uuid};
use mcp_server_rs::config::SourceSettings;
use mcp_server_rs::sources::crypto::decrypt_token;
use mcp_server_rs::{app_with_auth, openapi};

use support::{ADMIN_KEY, Fixture, LICENCE_TOKEN, TENANT_A, TestLicence, assert_no_store, send};

const PLATFORM_KEY: &str = "routes-sources-platform-key-0123456789abcd";
/// The reserved platform tenant `public.mcp_platform_tenant()` resolves to.
const PLATFORM_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
/// The decoded `MCP_SOURCE_SECRET_KEY` the fixture installs, taken from the oracle fixture
/// so no key-shaped literal lives in this file.
fn key_bytes() -> [u8; 32] {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/phase5a/oracle.json"
    );
    let text = std::fs::read_to_string(path).expect("the phase-5A fixture file exists");
    let document: serde_json::Value =
        serde_json::from_str(&text).expect("the phase-5A fixture file is JSON");
    let bytes: Vec<u8> = document["sealing_keys"]["primary"]
        .as_array()
        .expect("the fixture carries the sealing key")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("a byte")).expect("a byte"))
        .collect();
    bytes.try_into().expect("a 32-byte key")
}
const SOURCE_KEY: &str = "billing";
const TOKEN: &str = "synthetic-token";
const ROTATED: &str = "rotated-token";

// ── the real-server fixture ───────────────────────────────────────────────────────────────

fn platform_key_file() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "mcp-routes-sources-platform-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, PLATFORM_KEY).expect("write platform key");
    path
}

/// The real middleware with BOTH operator keys configured: the tenant operator key raises a
/// management principal, the platform key raises it to platform.
fn auth_with_platform() -> Auth {
    let config = AuthConfig {
        license_introspect_url: Some("https://licence.example/introspect".into()),
        license_app_key: Some("test-app-key".into()),
        admin_key_file: Some(support::admin_key_file()),
        platform_admin_key_file: Some(platform_key_file()),
        admin_tenant_ids: vec![Rfc4122Uuid::parse(TENANT_A).expect("static uuid")],
        ..AuthConfig::default()
    };
    let mut auth = Auth::from_config(&config).expect("valid auth config");
    auth.licences = Arc::new(TestLicence);
    auth
}

/// The `MCP_SOURCE_*` settings: one allowed host, and the sealing key when `secret` is set.
fn source_settings(secret: bool) -> SourceSettings {
    SourceSettings {
        secret_key: secret.then_some(key_bytes().to_vec()),
        allowed_hosts: vec!["api.example.com".to_owned()],
    }
}

/// The application with a platform pool (a second pool to the same test database).
async fn platform_app(fixture: &Fixture, secret: bool) -> Router {
    let mut state = fixture.state();
    state.platform = Some(fixture.second_pool().await);
    state.sources = source_settings(secret);
    app_with_auth(state, auth_with_platform())
}

/// The application with the platform pool unset, as a deployment without
/// `MCP_PLATFORM_DATABASE_URL`.
fn pool_less_app(fixture: &Fixture, secret: bool) -> Router {
    let mut state = fixture.state();
    assert!(
        state.platform.is_none(),
        "the fixture leaves the pool unset"
    );
    state.sources = source_settings(secret);
    app_with_auth(state, auth_with_platform())
}

// ── requests and bodies ──────────────────────────────────────────────────────────────────

fn call(method: Method, uri: &str, body: Option<Value>, platform: bool) -> Request<Body> {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY);
    if platform {
        builder = builder.header("x-mcp-platform-admin-key", PLATFORM_KEY);
    }
    match body {
        Some(body) => builder
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => builder.body(Body::empty()).expect("request"),
    }
}

/// One request carrying a management principal and the platform key.
fn platform_call(method: Method, uri: &str, body: Option<Value>) -> Request<Body> {
    call(method, uri, body, true)
}

fn create_body() -> Value {
    json!({
        "source_key": SOURCE_KEY,
        "base_url": "https://api.example.com",
        "auth": {"kind": "static_bearer"},
        "token": TOKEN,
    })
}

fn update_body(expected_revision: u64) -> Value {
    json!({
        "expected_revision": expected_revision,
        "base_url": "https://api.example.com/v1",
        "auth": {"kind": "static_bearer"},
        "spec_path": "/openapi.json",
        "max_request_bytes": 4096,
    })
}

fn token_body(expected_revision: u64) -> Value {
    json!({"expected_revision": expected_revision, "token": ROTATED})
}

fn revision_body(expected_revision: u64) -> Value {
    json!({"expected_revision": expected_revision})
}

/// No response body may carry the write-only secret or the ciphertext column.
fn assert_no_secret(body: &Value, context: &str) {
    let text = body.to_string();
    for needle in [TOKEN, ROTATED, "token_ciphertext"] {
        assert!(!text.contains(needle), "{context} carried {needle}");
    }
}

/// A view is exactly the reference's `SourceView`: no token and no ciphertext field at all.
fn assert_no_token_field(body: &Value, context: &str) {
    let object = body
        .as_object()
        .unwrap_or_else(|| panic!("{context} is not an object"));
    for field in ["token", "token_ciphertext"] {
        assert!(!object.contains_key(field), "{context} carries {field}");
    }
}

/// Open the source's stored secret with the configured key, through the real crypto contract.
async fn stored_token(fixture: &Fixture, source_key: &str) -> String {
    let row = sqlx::query(
        "SELECT source_id::text AS source_id, token_ciphertext FROM public.mcp_sources \
         WHERE source_key = $1",
    )
    .bind(source_key)
    .fetch_one(&fixture.pool)
    .await
    .expect("source row");
    let identity: String = row.try_get("source_id").expect("source id");
    let blob: Option<Vec<u8>> = row.try_get("token_ciphertext").expect("ciphertext");
    decrypt_token(
        Some(&key_bytes()),
        Uuid::parse_str(&identity).expect("source identity"),
        &blob.expect("a stored secret"),
    )
    .expect("the stored secret opens under the configured key")
}

// ── the source lifecycle ─────────────────────────────────────────────────────────────────

#[tokio::test]
async fn sources_author_through_the_platform_pool() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture, true).await;

    // Create: 201, the reference's view, the platform tenant owns it, and the secret is stored
    // but never echoed.
    let (status, headers, created) = send(
        &app,
        platform_call(Method::POST, "/mcp/sources", Some(create_body())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_no_store(&headers);
    assert_no_secret(&created, "create");
    assert_no_token_field(&created, "create");
    assert_eq!(created["source_key"], json!(SOURCE_KEY));
    assert_eq!(created["owner_tenant_id"], json!(PLATFORM_TENANT));
    assert_eq!(created["revision"], json!(1));
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["base_url"], json!("https://api.example.com"));
    assert_eq!(created["allow_internal_http"], json!(false));
    assert_eq!(created["auth"], json!({"kind": "static_bearer"}));
    assert_eq!(created["has_token"], json!(true));
    assert!(created["token_set_at"].is_string(), "{created}");
    assert_eq!(created["spec_path"], Value::Null);
    assert_eq!(created["idempotency_header"], Value::Null);
    assert_eq!(created["ca_file"], Value::Null);
    assert_eq!(created["max_request_bytes"], Value::Null);
    assert_eq!(created["max_response_bytes"], Value::Null);
    assert_eq!(created["created_by"]["subject"], json!("svc:test:mcp"));
    assert_eq!(created["created_by"], created["updated_by"]);
    assert!(created["source_id"].is_string(), "{created}");
    assert!(created["created_at"].is_string(), "{created}");
    assert!(created["updated_at"].is_string(), "{created}");
    assert_eq!(stored_token(&fixture, SOURCE_KEY).await, TOKEN);

    // List: the reference's `{items, limit, offset}` envelope, with its defaults.
    let (status, headers, listed) =
        send(&app, platform_call(Method::GET, "/mcp/sources", None)).await;
    assert_eq!(status, StatusCode::OK, "{listed}");
    assert_no_store(&headers);
    assert_no_secret(&listed, "list");
    assert_eq!(listed["limit"], json!(50));
    assert_eq!(listed["offset"], json!(0));
    let items = listed["items"].as_array().expect("items");
    assert_eq!(items.len(), 1, "{listed}");
    assert_eq!(items[0], created);
    assert_no_token_field(&items[0], "list item");

    // The query bounds are the reference's: 1..=100 and >= 0, an unparseable value included.
    let (status, _, bounded) = send(
        &app,
        platform_call(Method::GET, "/mcp/sources?limit=10&offset=0", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{bounded}");
    assert_eq!(bounded["limit"], json!(10));
    for query in ["?limit=0", "?limit=101", "?offset=-1", "?limit=abc"] {
        let (status, headers, body) = send(
            &app,
            platform_call(Method::GET, &format!("/mcp/sources{query}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{query}: {body}");
        assert_eq!(body, json!({"error": "invalid_request"}), "{query}");
        assert_no_store(&headers);
    }

    // Get one: the same view; an unknown key is the reference's 404.
    let (status, headers, fetched) = send(
        &app,
        platform_call(Method::GET, "/mcp/sources/billing", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{fetched}");
    assert_no_store(&headers);
    assert_eq!(fetched, created);
    let (status, headers, body) = send(
        &app,
        platform_call(Method::GET, "/mcp/sources/absent", None),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));
    assert_no_store(&headers);

    // Update: the revision advances, the contract changes, the stored secret is retained.
    let (status, headers, updated) = send(
        &app,
        platform_call(Method::PUT, "/mcp/sources/billing", Some(update_body(1))),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{updated}");
    assert_no_store(&headers);
    assert_no_secret(&updated, "update");
    assert_no_token_field(&updated, "update");
    assert_eq!(updated["revision"], json!(2));
    assert_eq!(updated["base_url"], json!("https://api.example.com/v1"));
    assert_eq!(updated["spec_path"], json!("/openapi.json"));
    assert_eq!(updated["max_request_bytes"], json!(4096));
    assert_eq!(updated["max_response_bytes"], Value::Null);
    assert_eq!(updated["has_token"], json!(true));
    assert_eq!(updated["token_set_at"], created["token_set_at"]);
    assert_eq!(updated["created_at"], created["created_at"]);
    assert_eq!(stored_token(&fixture, SOURCE_KEY).await, TOKEN);

    // A stale expected revision is the reference's conflict, not a second write.
    let (status, headers, body) = send(
        &app,
        platform_call(Method::PUT, "/mcp/sources/billing", Some(update_body(1))),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));
    assert_no_store(&headers);
    assert_eq!(stored_token(&fixture, SOURCE_KEY).await, TOKEN);

    // Rotate the stored secret: the revision advances and the row now holds the new token.
    let (status, headers, rotated) = send(
        &app,
        platform_call(
            Method::PUT,
            "/mcp/sources/billing/token",
            Some(token_body(2)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{rotated}");
    assert_no_store(&headers);
    assert_no_secret(&rotated, "token rotation");
    assert_no_token_field(&rotated, "token rotation");
    assert_eq!(rotated["revision"], json!(3));
    assert_eq!(rotated["has_token"], json!(true));
    assert!(rotated["token_set_at"].is_string(), "{rotated}");
    assert_eq!(stored_token(&fixture, SOURCE_KEY).await, ROTATED);

    // A stale rotation is refused and leaves the stored secret alone.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::PUT,
            "/mcp/sources/billing/token",
            Some(token_body(2)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));
    assert_eq!(stored_token(&fixture, SOURCE_KEY).await, ROTATED);

    // Disable, then enable: each is a revisioned state change with its own event.
    let (status, headers, disabled) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources/billing/disable",
            Some(revision_body(3)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{disabled}");
    assert_no_store(&headers);
    assert_no_secret(&disabled, "disable");
    assert_eq!(disabled["status"], json!("disabled"));
    assert_eq!(disabled["revision"], json!(4));

    // Already disabled is the reference's conflict, not a second event.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources/billing/disable",
            Some(revision_body(4)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));

    let (status, _, enabled) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources/billing/enable",
            Some(revision_body(4)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{enabled}");
    assert_no_secret(&enabled, "enable");
    assert_eq!(enabled["status"], json!("active"));
    assert_eq!(enabled["revision"], json!(5));

    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources/billing/enable",
            Some(revision_body(5)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A body the model refuses is the reference's 422, never a 500.
    let (status, headers, body) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources",
            Some(json!({
                "source_key": "Upper",
                "base_url": "https://api.example.com",
                "auth": {"kind": "none"},
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));
    assert_no_store(&headers);

    fixture.finish().await;
}

// ── the sealing key ─────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_secret_bearing_write_without_a_key_is_unavailable() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture, false).await;

    // The reference's `secret_guard`: the body is valid, the sealing key is not configured.
    let (status, headers, body) = send(
        &app,
        platform_call(Method::POST, "/mcp/sources", Some(create_body())),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"detail": "source_secret_unavailable"}));
    assert_no_store(&headers);
    assert_no_secret(&body, "unavailable");

    // A secretless kind needs no key: the guard wraps sealing writes only.
    let (status, headers, created) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/sources",
            Some(json!({
                "source_key": "public",
                "base_url": "https://api.example.com",
                "auth": {"kind": "none"},
            })),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    assert_no_store(&headers);
    assert_eq!(created["has_token"], json!(false));
    assert_eq!(created["token_set_at"], Value::Null);
    assert_eq!(created["auth"], json!({"kind": "none"}));

    // Rotating a token on a kind that carries none is the reference's 422, not the 503.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::PUT,
            "/mcp/sources/public/token",
            Some(token_body(1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));

    fixture.finish().await;
}

// ── platform authorization ───────────────────────────────────────────────────────────────

#[tokio::test]
async fn platform_authorization_needs_the_platform_key_and_a_pool() {
    let fixture = Fixture::new().await;
    let app = pool_less_app(&fixture, true);

    // Management without the platform key is refused before the pool matters.
    let requests = [
        (Method::GET, "/mcp/sources", None),
        (Method::POST, "/mcp/sources", Some(create_body())),
        (Method::GET, "/mcp/sources/billing", None),
        (Method::PUT, "/mcp/sources/billing", Some(update_body(1))),
        (
            Method::PUT,
            "/mcp/sources/billing/token",
            Some(token_body(1)),
        ),
        (
            Method::POST,
            "/mcp/sources/billing/disable",
            Some(revision_body(1)),
        ),
        (
            Method::POST,
            "/mcp/sources/billing/enable",
            Some(revision_body(1)),
        ),
    ];
    for (method, path, body) in requests {
        let (status, headers, refusal) = send(&app, call(method.clone(), path, body, false)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{method} {path}: {refusal}");
        assert_eq!(refusal, json!({"error": "forbidden"}), "{method} {path}");
        assert_no_store(&headers);
    }

    // The platform key passes authorization; the unset pool is the reference's HTTPException.
    for path in ["/mcp/sources", "/mcp/sources/billing"] {
        let (status, headers, body) = send(&app, call(Method::GET, path, None, true)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        assert_eq!(body, json!({"detail": "platform_authoring_unavailable"}));
        assert_no_store(&headers);
    }

    fixture.finish().await;
}

// ── OpenAPI document ─────────────────────────────────────────────────────────────────────

#[test]
fn the_openapi_document_declares_the_source_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    // (`path`, `method`, success status, whether the reference declares a 422)
    let operations = [
        ("/mcp/sources", "post", "201", false),
        ("/mcp/sources", "get", "200", true),
        ("/mcp/sources/{key}", "get", "200", true),
        ("/mcp/sources/{key}", "put", "200", true),
        ("/mcp/sources/{key}/token", "put", "200", true),
        ("/mcp/sources/{key}/disable", "post", "200", true),
        ("/mcp/sources/{key}/enable", "post", "200", true),
    ];
    for (path, method, success, validates) in operations {
        let operation = &spec["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert_eq!(operation["tags"], json!(["sources"]), "{method} {path}");
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
        assert_eq!(
            operation["responses"][success]["content"]["application/json"]["schema"],
            json!({"$ref": "#/components/schemas/AnyJson"}),
            "{method} {path} {success} must declare an empty schema"
        );
    }

    let query = spec["paths"]["/mcp/sources"]["get"]["parameters"]
        .as_array()
        .expect("parameters");
    assert_eq!(query[0]["name"], "limit");
    assert_eq!(query[0]["in"], "query");
    assert_eq!(query[1]["name"], "offset");
    assert_eq!(query[1]["in"], "query");

    let path = spec["paths"]["/mcp/sources/{key}"]["get"]["parameters"]
        .as_array()
        .expect("parameters");
    assert_eq!(path[0]["name"], "key");
    assert_eq!(path[0]["in"], "path");
}
