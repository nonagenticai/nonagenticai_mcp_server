//! The fourteen platform-authoring operations under `/mcp/services` and `/mcp/operations`
//! against the real router and a real Postgres 18.
//!
//! Every success asserts the reference's response BODY field by field (the parity gate cannot
//! see bodies); a caller without the platform key is refused; a build without the platform pool
//! answers the reference's `503 {"detail": …}`; every refusal renders the reference's
//! `{"error": …}` with `Cache-Control: no-store`; and the importer's refusal messages are the
//! reference's own. The platform pool is a second pool to the same test database, standing in
//! for `MCP_PLATFORM_DATABASE_URL` (the same database under the elevated platform role).
//!
//! Server selection and the fresh-database-per-test rule come from `tests/support`.

mod support;

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};

use mcp_server_rs::auth::{Auth, AuthConfig, Rfc4122Uuid};
use mcp_server_rs::catalog::importer::{OperationImport, import_drafts};
use mcp_server_rs::catalog::validation::SchemaLimits;
use mcp_server_rs::{app_with_auth, openapi};

use support::{ADMIN_KEY, Fixture, LICENCE_TOKEN, TENANT_A, TestLicence, assert_no_store, send};

const PLATFORM_KEY: &str = "routes-operations-platform-key-0123456789";
const GATEWAY_APP_KEY: &str = "synthetic";
const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000001a1";
const SERVICE_IMPORT_ID: &str = "30000000-0000-7000-8000-0000000001a2";
const SERVICE_SMALL_ID: &str = "30000000-0000-7000-8000-0000000001a3";
const OPERATION_ID: &str = "40000000-0000-7000-8000-0000000001a1";
const UNKNOWN_SERVICE_ID: &str = "30000000-0000-7000-8000-0000000001ff";
const SOURCE_ID: &str = "01900000-0000-7000-8000-0000000001c1";
const SOURCE_DISAGREEING_ID: &str = "01900000-0000-7000-8000-0000000001c2";

// ── the real-server fixture ───────────────────────────────────────────────────────────────

fn platform_key_file() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "mcp-routes-operations-platform-{}-{nanos}-{}",
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

/// The application with a platform pool (a second pool to the same test database).
async fn platform_app(fixture: &Fixture) -> Router {
    let mut state = fixture.state();
    state.platform = Some(fixture.second_pool().await);
    app_with_auth(state, auth_with_platform())
}

/// The application with the platform pool unset, as a deployment without
/// `MCP_PLATFORM_DATABASE_URL`.
fn pool_less_app(fixture: &Fixture) -> Router {
    let state = fixture.state();
    assert!(
        state.platform.is_none(),
        "the fixture leaves the pool unset"
    );
    app_with_auth(state, auth_with_platform())
}

// ── requests and manifests ────────────────────────────────────────────────────────────────

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

fn service_manifest(id: &str, version: u32, key: &str, alias: &str, response: u32) -> Value {
    json!({
        "schema_version": 1,
        "service_id": id,
        "version": version,
        "service_key": key,
        "destination_alias": alias,
        "license_app_key": GATEWAY_APP_KEY,
        "auth_adapter": "license_bearer",
        "credential_profile_key": "synthetic_profile",
        "max_request_bytes": 4096,
        "max_response_bytes": response,
    })
}

fn operation_manifest(id: &str, service_id: &str, response: u32) -> Value {
    json!({
        "schema_version": 1,
        "operation_id": id,
        "version": 1,
        "service": {"id": service_id, "version": 1},
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
        "max_response_bytes": response,
    })
}

/// The reference's own import sample: one POST with a path parameter and a JSON body.
fn import_document() -> Value {
    json!({
        "openapi": "3.1.0",
        "paths": {
            "/records/{record}": {
                "post": {
                    "parameters": [
                        {
                            "in": "path",
                            "name": "record",
                            "required": true,
                            "schema": {"type": "string"}
                        }
                    ],
                    "requestBody": {
                        "required": true,
                        "content": {"application/json": {"schema": {"type": "object"}}}
                    },
                    "responses": {
                        "200": {"content": {"application/json": {"schema": {"type": "object"}}}}
                    }
                }
            }
        }
    })
}

/// One active platform source for `source_key`; the service's `destination_alias` must name it.
async fn seed_source(
    fixture: &Fixture,
    source_id: &str,
    source_key: &str,
    app_key: &str,
    scheme: &str,
) {
    sqlx::query(
        "INSERT INTO public.mcp_sources(source_id,source_key,base_url,auth,created_by,updated_by) \
         VALUES ($1::uuid,$2,'https://service1.example',$3,$4,$4)",
    )
    .bind(source_id)
    .bind(source_key)
    .bind(json!({"kind": "licence", "app_key": app_key, "scheme": scheme}))
    .bind(support::actor_snapshot())
    .execute(&fixture.pool)
    .await
    .expect("source row");
}

async fn create_service(app: &Router, manifest: &Value) -> Value {
    let (status, headers, body) = send(
        app,
        platform_call(Method::POST, "/mcp/services", Some(manifest.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_store(&headers);
    body
}

// ── service and operation lifecycle ───────────────────────────────────────────────────────

#[tokio::test]
async fn services_and_operations_author_through_the_platform_pool() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture).await;

    let manifest = service_manifest(
        SERVICE_ID,
        1,
        "catalog_service",
        "catalog_destination",
        65536,
    );
    let created = create_service(&app, &manifest).await;
    assert_eq!(created, json!({"manifest": manifest, "status": "draft"}));

    // A second version-1 create is the reference's unique violation: 409.
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, "/mcp/services", Some(manifest.clone())),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));

    // A first version other than 1 is the reference's "first version required".
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            "/mcp/services",
            Some(service_manifest(
                SERVICE_IMPORT_ID,
                2,
                "catalog_import_service",
                "catalog_import_destination",
                65536,
            )),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));

    let base = format!("/mcp/services/{SERVICE_ID}/versions/1");

    // Inspect: the stored manifest and its draft status.
    let (status, _, body) = send(&app, platform_call(Method::GET, &base, None)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!({"manifest": manifest, "status": "draft"}));

    // List: one row, the reference's exact column set.
    let (status, _, body) = send(
        &app,
        platform_call(Method::GET, "/mcp/services?limit=1&offset=0", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"items": [{"service_id": SERVICE_ID, "version": 1, "status": "draft"}]})
    );

    // Query bounds are the reference's: 1..=100 and >= 0.
    for query in ["?limit=0", "?limit=101", "?offset=-1"] {
        let (status, _, body) = send(
            &app,
            platform_call(Method::GET, &format!("/mcp/services{query}"), None),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{query}: {body}");
        assert_eq!(body, json!({"error": "invalid_request"}));
    }

    // Validate: the reference's fixed result, no credential check.
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{base}/validate"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"id": SERVICE_ID, "version": 1, "status": "valid", "credentials_verified": false})
    );

    // Publishing needs the named source registered and active first.
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{base}/publish"), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "source_unavailable"}));

    // One operation draft under the (still draft) service.
    let operation = operation_manifest(OPERATION_ID, SERVICE_ID, 4096);
    let opbase = format!("/mcp/operations/{OPERATION_ID}/versions");
    let (status, _, body) = send(&app, platform_call(Method::POST, &opbase, Some(operation))).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["manifest"]["operation_id"], json!(OPERATION_ID));

    // An operation cannot publish before its service version does.
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{opbase}/1/publish"), None),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));

    // Operation list, inspect and validate.
    let (status, _, body) = send(
        &app,
        platform_call(Method::GET, "/mcp/operations?limit=10", None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"][0]["operation_id"], json!(OPERATION_ID));
    assert_eq!(body["items"][0]["version"], json!(1));
    assert_eq!(body["items"][0]["status"], json!("draft"));

    let (status, _, body) = send(
        &app,
        platform_call(Method::GET, &format!("{opbase}/1"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["manifest"]["effect"], json!("read_only"));
    assert_eq!(body["manifest"]["method"], json!("GET"));
    assert_eq!(body["manifest"]["max_response_bytes"], json!(4096));

    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{opbase}/1/validate"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"id": OPERATION_ID, "version": 1, "status": "valid", "credentials_verified": false})
    );

    // Register the agreeing source: the service publishes, then the operation does.
    seed_source(
        &fixture,
        SOURCE_ID,
        "catalog_destination",
        GATEWAY_APP_KEY,
        "bearer",
    )
    .await;
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{base}/publish"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body,
        json!({"id": SERVICE_ID, "version": 1, "status": "published", "credentials_verified": false})
    );
    let (status, _, body) = send(&app, platform_call(Method::GET, &base, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("published"));

    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{opbase}/1/publish"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("published"));

    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{opbase}/1/disable"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("disabled"));
    let (status, _, body) = send(
        &app,
        platform_call(Method::GET, &format!("{opbase}/1"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("disabled"));

    // The service version disables the same way.
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, &format!("{base}/disable"), None),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("disabled"));
    let (status, _, body) = send(&app, platform_call(Method::GET, &base, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], json!("disabled"));

    // Append the service's next version against the identity's revision (1 after creation).
    let second = service_manifest(
        SERVICE_ID,
        2,
        "catalog_service",
        "catalog_destination",
        65536,
    );
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &format!("/mcp/services/{SERVICE_ID}/versions"),
            Some(json!({"manifest": second, "expected_revision": 1})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["manifest"]["version"], json!(2));
    assert_eq!(body["status"], json!("draft"));
    let (status, _, body) = send(&app, platform_call(Method::GET, &base, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["manifest"]["version"], json!(1));

    // The identity's revision advanced; the same expectation is now stale.
    let third = service_manifest(
        SERVICE_ID,
        3,
        "catalog_service",
        "catalog_destination",
        65536,
    );
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &format!("/mcp/services/{SERVICE_ID}/versions"),
            Some(json!({"manifest": third, "expected_revision": 1})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));

    // A body naming another identity is the reference's "identity mismatch".
    let other = service_manifest(
        SERVICE_IMPORT_ID,
        2,
        "catalog_import_service",
        "catalog_import_destination",
        65536,
    );
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &format!("/mcp/services/{SERVICE_ID}/versions"),
            Some(json!({"manifest": other, "expected_revision": 2})),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));

    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &opbase,
            Some(operation_manifest(
                "40000000-0000-7000-8000-0000000001a9",
                SERVICE_ID,
                4096,
            )),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));

    // Missing and malformed exact versions.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::GET,
            &format!("/mcp/services/{UNKNOWN_SERVICE_ID}/versions/1"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));

    for version in ["0", "-1", "not-a-number"] {
        let (status, _, body) = send(
            &app,
            platform_call(
                Method::GET,
                &format!("/mcp/services/{SERVICE_ID}/versions/{version}"),
                None,
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNPROCESSABLE_ENTITY,
            "{version}: {body}"
        );
        assert_eq!(body, json!({"error": "invalid_request"}));
    }

    // A validate of a version that does not exist is a 404, not a refusal of the request.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &format!("/mcp/services/{SERVICE_ID}/versions/99/validate"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));

    fixture.finish().await;
}

#[tokio::test]
async fn publishing_a_service_needs_an_agreeing_active_source() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture).await;

    let manifest = service_manifest(
        SERVICE_SMALL_ID,
        1,
        "catalog_small_service",
        "disagreeing_source",
        4096,
    );
    create_service(&app, &manifest).await;

    // A source that exists and is active but names another licence application.
    seed_source(
        &fixture,
        SOURCE_DISAGREEING_ID,
        "disagreeing_source",
        "other_app",
        "bearer",
    )
    .await;
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::POST,
            &format!("/mcp/services/{SERVICE_SMALL_ID}/versions/1/publish"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body, json!({"error": "source_unavailable"}));

    fixture.finish().await;
}

// ── OpenAPI import ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn openapi_import_creates_drafts_and_refuses_unsupported_documents() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture).await;

    // Two parents: one wide enough for the importer's 64 KiB response ceiling, one not.
    create_service(
        &app,
        &service_manifest(
            SERVICE_IMPORT_ID,
            1,
            "catalog_import_service",
            "catalog_import_destination",
            65536,
        ),
    )
    .await;
    create_service(
        &app,
        &service_manifest(
            SERVICE_SMALL_ID,
            1,
            "catalog_small_service",
            "disagreeing_source",
            4096,
        ),
    )
    .await;

    let payload = json!({
        "service": {"id": SERVICE_IMPORT_ID, "version": 1},
        "document": import_document(),
    });
    let (status, headers, body) = send(
        &app,
        platform_call(Method::POST, "/mcp/operations/import", Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_store(&headers);
    assert_eq!(body["status"], json!("draft"));
    let items = body["items"].as_array().expect("imported items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["effect"], json!("writes"));
    assert_eq!(items[0]["version"], json!(1));
    assert_eq!(
        items[0]["service"],
        json!({"id": SERVICE_IMPORT_ID, "version": 1})
    );
    assert_eq!(
        items[0]["input_schema"]["additionalProperties"],
        json!(false)
    );
    assert_eq!(
        items[0]["input_schema"]["required"],
        json!(["record", "body"])
    );
    assert_eq!(items[0]["query_fields"], json!([]));
    assert_eq!(
        items[0]["mappings"],
        json!([
            {
                "location": "path",
                "target": "record",
                "value": {"source": "input", "pointer": "/record"},
                "optional": false
            },
            {
                "location": "body",
                "target": "",
                "value": {"source": "input", "pointer": "/body"},
                "optional": false
            }
        ])
    );
    let operation_id = items[0]["operation_id"]
        .as_str()
        .expect("imported operation identity")
        .to_owned();

    // The draft is a real platform operation version over the platform pool.
    let (status, _, body) = send(
        &app,
        platform_call(
            Method::GET,
            &format!("/mcp/operations/{operation_id}/versions/1"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], json!("draft"));
    assert_eq!(body["manifest"]["operation_id"], json!(operation_id));
    assert_eq!(
        body["manifest"]["path_template"],
        json!("/records/{record}")
    );

    // Every declared importer refusal is the reference's 422.
    let refused = [
        ("openapi version", json!({"openapi": "3.0.0", "paths": {}})),
        (
            "not bundled",
            json!({"openapi": "3.1.0", "paths": {}, "components": {}}),
        ),
        ("empty paths", json!({"openapi": "3.1.0", "paths": {}})),
        (
            "unsupported method",
            json!({"openapi": "3.1.0", "paths": {"/x": {"trace": {}}}}),
        ),
        (
            "unsupported field",
            json!({"openapi": "3.1.0", "paths": {"/x": {"get": {"tags": []}}}}),
        ),
        (
            "one explicit 200",
            json!({
                "openapi": "3.1.0",
                "paths": {"/x": {"get": {"responses": {"201": {"content": {
                    "application/json": {"schema": {"type": "object"}}
                }}}}}}
            }),
        ),
    ];
    for (name, document) in refused {
        let payload = json!({
            "service": {"id": SERVICE_IMPORT_ID, "version": 1},
            "document": document,
        });
        let (status, headers, body) = send(
            &app,
            platform_call(Method::POST, "/mcp/operations/import", Some(payload)),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{name}: {body}");
        assert_eq!(body, json!({"error": "invalid_request"}), "{name}");
        assert_no_store(&headers);
    }

    // The importer's 64 KiB response ceiling must fit the parent service's.
    let payload = json!({
        "service": {"id": SERVICE_SMALL_ID, "version": 1},
        "document": import_document(),
    });
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, "/mcp/operations/import", Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_eq!(body, json!({"error": "invalid_request"}));

    // An import for a missing service version is the reference's 404.
    let payload = json!({
        "service": {"id": UNKNOWN_SERVICE_ID, "version": 1},
        "document": import_document(),
    });
    let (status, _, body) = send(
        &app,
        platform_call(Method::POST, "/mcp/operations/import", Some(payload)),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));

    fixture.finish().await;
}

fn import_payload(document: Value) -> OperationImport {
    serde_json::from_value(json!({
        "service": {"id": SERVICE_IMPORT_ID, "version": 1},
        "document": document,
    }))
    .expect("valid import payload")
}

fn import_refusal(document: Value) -> String {
    import_drafts(&import_payload(document), &SchemaLimits::default())
        .expect_err("the reference refuses this document")
        .to_string()
}

#[test]
fn the_importer_refusals_carry_the_reference_messages() {
    let one_get = json!({
        "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
    });
    assert_eq!(
        import_refusal(json!({"openapi": "3.0.0", "paths": {}})),
        "v1 importer requires a bundled OpenAPI 3.1 document without references"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": {}, "components": {}})),
        "v1 importer requires a bundled OpenAPI 3.1 document without references"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0"})),
        "paths required"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": []})),
        "paths required"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": {"/x": []}})),
        "invalid path"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": {"/x": {"trace": {}}}})),
        "unsupported OpenAPI operation"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": {"/x": {"get": {"tags": []}}}})),
        "unsupported OpenAPI operation field"
    );
    assert_eq!(
        import_refusal(json!({
            "openapi": "3.1.0",
            "paths": {"/x": {"get": {
                "parameters": [{"in": "header", "name": "x", "schema": {}}],
                "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
            }}}
        })),
        "unsupported parameter"
    );
    assert_eq!(
        import_refusal(json!({
            "openapi": "3.1.0",
            "paths": {"/x": {"get": {
                "parameters": [
                    {"in": "query", "name": "q", "schema": {"type": "string"}},
                    {"in": "query", "name": "q", "schema": {"type": "string"}}
                ],
                "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
            }}}
        })),
        "duplicate parameter"
    );
    assert_eq!(
        import_refusal(json!({
            "openapi": "3.1.0",
            "paths": {"/x": {"post": {
                "parameters": [{"in": "query", "name": "body", "schema": {"type": "string"}}],
                "requestBody": {
                    "required": true,
                    "content": {"application/json": {"schema": {"type": "object"}}}
                },
                "responses": {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
            }}}
        })),
        "body parameter collision"
    );
    assert_eq!(
        import_refusal(json!({
            "openapi": "3.1.0",
            "paths": {"/x": {"get": {
                "responses": {"201": {"content": {"application/json": {"schema": {"type": "object"}}}}}
            }}}
        })),
        "import requires one explicit JSON 200 response"
    );
    // The ceiling is the payload's `max_operations` (default 32), not a fixed number: two
    // operations fit the default, and exceed a ceiling of one.
    let bounded = serde_json::from_value::<OperationImport>(json!({
        "service": {"id": SERVICE_IMPORT_ID, "version": 1},
        "document": {
            "openapi": "3.1.0",
            "paths": {"/a": {"get": one_get.clone()}, "/b": {"get": one_get}}
        },
        "max_operations": 1,
    }))
    .expect("a valid bounded payload");
    assert_eq!(
        import_drafts(&bounded, &SchemaLimits::default())
            .expect_err("the reference refuses this document")
            .to_string(),
        "import operation limit"
    );
    assert_eq!(
        import_refusal(json!({"openapi": "3.1.0", "paths": {}})),
        "empty import"
    );
}

#[test]
fn the_import_payload_bounds_max_operations() {
    let document = json!({"openapi": "3.1.0", "paths": {}});
    for invalid in [0, 129, -1] {
        let payload = json!({
            "service": {"id": SERVICE_IMPORT_ID, "version": 1},
            "document": document,
            "max_operations": invalid,
        });
        assert!(
            serde_json::from_value::<OperationImport>(payload).is_err(),
            "max_operations {invalid} must be refused"
        );
    }
    let payload = json!({
        "service": {"id": SERVICE_IMPORT_ID, "version": 1},
        "document": document,
        "max_operations": 1,
    });
    assert_eq!(
        serde_json::from_value::<OperationImport>(payload)
            .expect("a bounded ceiling is accepted")
            .max_operations,
        1
    );
}

// ── platform authorization ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn platform_authorization_needs_the_platform_key_and_a_pool() {
    let fixture = Fixture::new().await;
    let app = pool_less_app(&fixture);

    // Management without the platform key is refused before the pool matters.
    for (method, path) in [
        (Method::GET, "/mcp/services"),
        (Method::GET, "/mcp/operations"),
        (Method::POST, "/mcp/services"),
    ] {
        let body = if method == Method::POST {
            Some(service_manifest(
                SERVICE_ID,
                1,
                "catalog_service",
                "catalog_destination",
                65536,
            ))
        } else {
            None
        };
        let (status, headers, body) = send(&app, call(method, path, body, false)).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}: {body}");
        assert_eq!(body, json!({"error": "forbidden"}));
        assert_no_store(&headers);
    }

    // The platform key passes authorization; the unset pool is the reference's HTTPException.
    for path in ["/mcp/services", "/mcp/operations"] {
        let (status, _, body) = send(&app, call(Method::GET, path, None, true)).await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{path}: {body}");
        assert_eq!(body, json!({"detail": "platform_authoring_unavailable"}));
    }

    fixture.finish().await;
}

// ── OpenAPI document ─────────────────────────────────────────────────────────────────────

#[test]
fn the_openapi_document_declares_the_platform_authoring_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    let operations = [
        ("/mcp/services", "post", "services", "201", false),
        ("/mcp/services", "get", "services", "200", true),
        (
            "/mcp/services/{identity}/versions",
            "post",
            "services",
            "201",
            true,
        ),
        (
            "/mcp/services/{identity}/versions/{version}",
            "get",
            "services",
            "200",
            true,
        ),
        (
            "/mcp/services/{identity}/versions/{version}/validate",
            "post",
            "services",
            "200",
            true,
        ),
        (
            "/mcp/services/{identity}/versions/{version}/publish",
            "post",
            "services",
            "200",
            true,
        ),
        (
            "/mcp/services/{identity}/versions/{version}/disable",
            "post",
            "services",
            "200",
            true,
        ),
        ("/mcp/operations", "get", "operations", "200", true),
        (
            "/mcp/operations/{identity}/versions",
            "post",
            "operations",
            "201",
            true,
        ),
        ("/mcp/operations/import", "post", "operations", "201", false),
        (
            "/mcp/operations/{identity}/versions/{version}",
            "get",
            "operations",
            "200",
            true,
        ),
        (
            "/mcp/operations/{identity}/versions/{version}/validate",
            "post",
            "operations",
            "200",
            true,
        ),
        (
            "/mcp/operations/{identity}/versions/{version}/publish",
            "post",
            "operations",
            "200",
            true,
        ),
        (
            "/mcp/operations/{identity}/versions/{version}/disable",
            "post",
            "operations",
            "200",
            true,
        ),
    ];
    for (path, method, tag, success, validates) in operations {
        let operation = &spec["paths"][path][method];
        assert!(operation.is_object(), "missing {method} {path}");
        assert_eq!(operation["tags"], json!([tag]), "{method} {path}");
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

    let parameters =
        spec["paths"]["/mcp/services/{identity}/versions/{version}"]["get"]["parameters"]
            .as_array()
            .expect("parameters");
    assert_eq!(parameters[0]["name"], "identity");
    assert_eq!(parameters[0]["in"], "path");
    assert_eq!(parameters[0]["schema"]["format"], "uuid7");
    assert_eq!(parameters[1]["name"], "version");
    assert_eq!(parameters[1]["in"], "path");

    let query = spec["paths"]["/mcp/operations"]["get"]["parameters"]
        .as_array()
        .expect("parameters");
    assert_eq!(query[0]["name"], "limit");
    assert_eq!(query[0]["in"], "query");
    assert_eq!(query[1]["name"], "offset");
    assert_eq!(query[1]["in"], "query");
}
