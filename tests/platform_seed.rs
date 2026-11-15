//! The platform seed and the generic toolkit import against real Postgres 18.
//!
//! The repository's `toolkits/` tree is the real content the deployment bootstraps: the seed
//! publishes it twice (the second run must be a complete no-op, byte content unchanged, no new
//! revisions and no new audit rows), imports a bundle over it (append + publish, a draft a dead
//! run left behind is published, a disabled row is never resurrected), and refuses to run while
//! another seed holds the advisory lock. The route tests assert the reference's exact bodies:
//! `201 {actions, versions, tools_skipped, changed}`, the nested
//! `409 {"detail": {"error": "import_failed", "detail": …}}` and the
//! `503 {"detail": "platform_authoring_unavailable"}`.
//!
//! Server selection and the fresh-database-per-test rule come from `tests/support`; the platform
//! pool is a second pool to the same database, standing in for `MCP_PLATFORM_DATABASE_URL`.

mod support;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Map, Value, json};
use uuid::Uuid;

use mcp_server_rs::auth::{Auth, AuthConfig, Rfc4122Uuid};
use mcp_server_rs::builder::packaging;
use mcp_server_rs::catalog::ids::{AuthorityId, Name};
use mcp_server_rs::catalog::models::{Attribution, ServiceManifest};
use mcp_server_rs::platform::seed::{
    BundleFile, BundleTool, LOCK_KEY, SEED_LICENCE_ID, SeedError, SeedOptions, SeedReport,
    SeedSettings, ToolkitBundle, import_bundle, seed,
};
use mcp_server_rs::platform::toolkit_source::load_all;
use mcp_server_rs::storage::catalog::PlatformCatalogRepository;
use mcp_server_rs::{app_with_auth, openapi};

use support::{ADMIN_KEY, Fixture, LICENCE_TOKEN, TestLicence, send};

/// The reserved platform tenant `public.mcp_platform_tenant()` resolves to.
const PLATFORM_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
const PLATFORM_KEY: &str = "platform-seed-platform-key-0123456789abcd";

const SYNTHETIC_SERVICE_ID: &str = "01900000-0000-7000-8000-00000000f101";
const SYNTHETIC_OPERATION_ID: &str = "01900000-0000-7000-8000-00000000f102";
const SYNTHETIC_TOOL_ID: &str = "01900000-0000-7000-8000-00000000f103";
const SYNTHETIC_TOOLKIT_ID: &str = "01900000-0000-7000-8000-00000000f104";

/// The runner image the seed pins into every kata tool.
fn runner_image() -> String {
    format!("registry.example/runner@sha256:{}", "a".repeat(64))
}

fn settings(digest: Option<String>) -> SeedSettings {
    SeedSettings {
        platform_tenant_id: AuthorityId::new(PLATFORM_TENANT).expect("platform tenant"),
        runner_image_digest: digest,
        approved_runner_images: vec![runner_image()],
    }
}

fn toolkits_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("toolkits")
}

fn read_text(relative: &str) -> String {
    let path = toolkits_root().join(relative);
    std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("{}: {error}", path.display()))
}

fn read_json(relative: &str) -> Value {
    serde_json::from_str(&read_text(relative)).expect("fixture json")
}

// ── fixtures ──────────────────────────────────────────────────────────────────────────────

/// A platform tool source row, what `POST /mcp/sources` registers.
async fn register_source(fixture: &Fixture, key: &str, app_key: &str) {
    let actor =
        json!({"subject": "platform-seed", "license_id": "01900000-0000-7000-8000-00000000f002"});
    sqlx::query(
        "INSERT INTO public.mcp_sources(source_id,source_key,base_url,auth,created_by,updated_by) \
         VALUES ($1::uuid,$2,$3,$4,$5,$5)",
    )
    .bind(Uuid::now_v7().to_string())
    .bind(key)
    .bind(format!("https://{key}.example"))
    .bind(json!({"kind": "licence", "scheme": "bearer", "app_key": app_key}))
    .bind(actor)
    .execute(&fixture.pool)
    .await
    .expect("register the platform source");
}

/// The repository tree's `coding` toolkit as a one-tool import bundle: the same service and
/// operations, the same `coding_read_file` tool and package, with one edited description.
fn coding_bundle() -> ToolkitBundle {
    let toolkit = read_json("coding/toolkit.json");
    let service = read_json("coding/service.json");
    let tool = read_json("coding/tools/coding_read_file/tool.json");
    let mut fields = tool.as_object().cloned().expect("tool fields");
    let op_keys: Vec<Name> = fields
        .remove("allowed_operations")
        .and_then(|keys| keys.as_array().cloned())
        .expect("allowed_operations")
        .iter()
        .map(|key| Name::new(key.as_str().expect("an operation key")).expect("a catalog name"))
        .collect();
    // The repository loader supplies these two defaults; the bundle is plain JSON and must
    // carry them itself.
    fields.insert(
        "result_schema".to_owned(),
        packaging::default_result_schema(),
    );
    fields.insert("context_schema".to_owned(), packaging::no_context());
    fields.insert(
        "description".to_owned(),
        json!("Edited by the platform import test."),
    );
    let mut operations = Map::new();
    for key in &op_keys {
        operations.insert(
            key.to_string(),
            read_json(&format!("coding/operations/{key}.json")),
        );
    }
    ToolkitBundle {
        toolkit: toolkit.as_object().cloned().expect("toolkit object"),
        service: service.as_object().cloned().expect("service object"),
        operations,
        tools: vec![BundleTool {
            fields,
            op_keys,
            files: vec![
                BundleFile {
                    path: "tool.py".to_owned(),
                    content: read_text("coding/tools/coding_read_file/tool.py"),
                },
                BundleFile {
                    path: "coding.py".to_owned(),
                    content: read_text("coding/shared/coding.py"),
                },
                BundleFile {
                    path: "kit.py".to_owned(),
                    content: read_text("_kit/kit.py"),
                },
            ],
        }],
    }
}

/// One bundle the import route accepts: a synthetic service, one read operation and one
/// external (n8n) tool, so the seed needs no runner digest for the tool itself.
fn import_body(destination: &str) -> Value {
    json!({
        "toolkit": {
            "toolkit_id": SYNTHETIC_TOOLKIT_ID,
            "name": "synthetic_import",
            "description": "Synthetic platform import"
        },
        "service": {
            "service_id": SYNTHETIC_SERVICE_ID,
            "service_key": "synthetic_import",
            "destination_alias": destination,
            "license_app_key": "synthetic",
            "auth_adapter": "license_bearer",
            "credential_profile_key": "synthetic",
            "max_request_bytes": 4096,
            "max_response_bytes": 4096
        },
        "operations": {
            "do_thing": {
                "operation_id": SYNTHETIC_OPERATION_ID,
                "method": "GET",
                "path_template": "/synthetic",
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
                "output_schema": {"type": "object"},
                "response_projection": [""],
                "effect": "read_only",
                "timeout_seconds": 30,
                "pagination_limit": 10,
                "max_response_bytes": 4096
            }
        },
        "tools": [{
            "fields": {
                "tool_id": SYNTHETIC_TOOL_ID,
                "public_name": "synthetic_import_tool",
                "operation": "synthetic.import",
                "description": "Synthetic import tool",
                "runtime": "n8n_workflow",
                "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/import"},
                "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
                "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
                "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
                "effect": "read_only"
            },
            "op_keys": ["do_thing"],
            "files": [{"path": "README.md", "content": "synthetic"}]
        }]
    })
}

// ── the repository seed ─────────────────────────────────────────────────────────────────

async fn seed_repository(fixture: &Fixture) -> SeedReport {
    let sources = load_all(&toolkits_root()).expect("the repository toolkits load");
    seed(
        &fixture.pool,
        &settings(Some(runner_image())),
        &sources,
        Some(&fixture.second_pool().await),
        SeedOptions::default(),
    )
    .await
    .expect("the platform seed succeeds")
}

#[tokio::test]
async fn the_repository_toolkits_seed_and_the_second_run_is_a_no_op() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "coding", "coding").await;
    let first = seed_repository(&fixture).await;

    assert!(!first.tools_skipped);
    assert!(first.changed());
    assert!(first.sources_missing.is_empty());
    assert_eq!(first.actions["service:coding"], json!("created"));
    assert_eq!(
        first.actions["operation:coding.git_status"],
        json!("created")
    );
    assert_eq!(
        first.actions["tool:coding.coding_read_file"],
        json!("created")
    );
    assert_eq!(first.actions["tool:fr.start_fr_project"], json!("created"));
    assert_eq!(first.actions["toolkit:coding"], json!("created"));
    assert_eq!(first.actions["toolkit:fr"], json!("created"));

    // 11 coding tools + 3 external fr tools; both toolkits, every version published.
    let tools: i64 =
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_tools WHERE tenant_id=$1::uuid")
            .bind(PLATFORM_TENANT)
            .fetch_one(&fixture.pool)
            .await
            .expect("tool count");
    assert_eq!(tools, 14);
    let drafts: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tool_versions \
         WHERE tenant_id=$1::uuid AND status<>'published'",
    )
    .bind(PLATFORM_TENANT)
    .fetch_one(&fixture.pool)
    .await
    .expect("draft count");
    assert_eq!(drafts, 0);
    let toolkits: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_toolkit_versions WHERE status='published'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("toolkit count");
    assert_eq!(toolkits, 2);

    // The package is the tool's own files plus the shared module, kit.py and ops.py.
    let read_id = read_json("coding/tools/coding_read_file/tool.json")["tool_id"]
        .as_str()
        .expect("the tool identity")
        .to_owned();
    let files: Vec<String> = sqlx::query_scalar(
        "SELECT path FROM public.mcp_tool_version_files \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND version=1 ORDER BY path",
    )
    .bind(PLATFORM_TENANT)
    .bind(&read_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("package files");
    assert_eq!(files, vec!["coding.py", "kit.py", "ops.py", "tool.py"]);
    let kit: String = sqlx::query_scalar(
        "SELECT content FROM public.mcp_tool_version_files \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND version=1 AND path='kit.py'",
    )
    .bind(PLATFORM_TENANT)
    .bind(&read_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("kit.py");
    assert_eq!(kit, read_text("_kit/kit.py"));
    let ops: String = sqlx::query_scalar(
        "SELECT content FROM public.mcp_tool_version_files \
         WHERE tenant_id=$1::uuid AND tool_id=$2::uuid AND version=1 AND path='ops.py'",
    )
    .bind(PLATFORM_TENANT)
    .bind(&read_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("ops.py");
    for key in ["read_file", "workspace_status"] {
        let identity = read_json(&format!("coding/operations/{key}.json"))["operation_id"]
            .as_str()
            .expect("an operation identity")
            .to_owned();
        assert!(ops.contains(&identity), "ops.py pins {key}");
    }

    let tool_revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM public.mcp_tools WHERE tenant_id=$1::uuid AND tool_id=$2::uuid",
    )
    .bind(PLATFORM_TENANT)
    .bind(&read_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("tool revision");
    let events: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_access_events")
        .fetch_one(&fixture.pool)
        .await
        .expect("audit rows");

    let second = seed_repository(&fixture).await;
    assert!(!second.changed());
    for key in first.actions.keys() {
        assert_eq!(
            second.actions.get(key.as_str()),
            Some(&json!("unchanged")),
            "{key} must be unchanged"
        );
    }
    let unchanged_tool_revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM public.mcp_tools WHERE tenant_id=$1::uuid AND tool_id=$2::uuid",
    )
    .bind(PLATFORM_TENANT)
    .bind(&read_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("tool revision");
    assert_eq!(unchanged_tool_revision, tool_revision);
    let unchanged_events: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_access_events")
        .fetch_one(&fixture.pool)
        .await
        .expect("audit rows");
    assert_eq!(unchanged_events, events);

    fixture.finish().await;
}

#[tokio::test]
async fn without_a_runner_digest_only_services_operations_and_external_toolkits_are_seeded() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "coding", "coding").await;
    let sources = load_all(&toolkits_root()).expect("the repository toolkits load");
    let report = seed(
        &fixture.pool,
        &settings(None),
        &sources,
        Some(&fixture.second_pool().await),
        SeedOptions::default(),
    )
    .await
    .expect("the platform seed succeeds");

    assert!(report.tools_skipped);
    assert_eq!(report.actions["service:coding"], json!("created"));
    assert!(!report.actions.contains_key("tool:coding.coding_read_file"));
    // The external toolkit needs no runner image, so it seeds regardless.
    assert_eq!(report.actions["tool:fr.start_fr_project"], json!("created"));
    assert_eq!(report.actions["toolkit:fr"], json!("created"));
    let kata_tools: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tools WHERE public_name LIKE 'coding_%'",
    )
    .fetch_one(&fixture.pool)
    .await
    .expect("kata tools");
    assert_eq!(kata_tools, 0);

    // A later run with the digest completes the catalog and leaves the earlier rows alone.
    let later = seed_repository(&fixture).await;
    assert_eq!(later.actions["service:coding"], json!("unchanged"));
    assert_eq!(
        later.actions["tool:coding.coding_read_file"],
        json!("created")
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_digest_outside_the_approved_list_is_refused() {
    let fixture = Fixture::new().await;
    let sources = load_all(&toolkits_root()).expect("the repository toolkits load");
    let mut settings = settings(Some(runner_image()));
    settings.approved_runner_images =
        vec![format!("registry.example/other@sha256:{}", "b".repeat(64))];
    let error = seed(
        &fixture.pool,
        &settings,
        &sources,
        Some(&fixture.second_pool().await),
        SeedOptions::default(),
    )
    .await
    .expect_err("an unapproved digest is refused");
    assert!(matches!(
        error,
        SeedError::Refused(ref message)
            if message == "MCP_RUNNER_IMAGE_DIGEST is not in MCP_APPROVED_RUNNER_IMAGES"
    ));
    let services: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_services")
        .fetch_one(&fixture.pool)
        .await
        .expect("services");
    assert_eq!(services, 0);
    fixture.finish().await;
}

#[tokio::test]
async fn a_held_lock_times_out_and_the_unlocked_run_seeds() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "coding", "coding").await;
    let mut holder = fixture.pool.acquire().await.expect("a lock connection");
    sqlx::query("SELECT pg_advisory_lock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *holder)
        .await
        .expect("hold the seed lock");
    let sources = load_all(&toolkits_root()).expect("the repository toolkits load");
    let error = seed(
        &fixture.pool,
        &settings(Some(runner_image())),
        &sources,
        Some(&fixture.second_pool().await),
        SeedOptions {
            lock_timeout: Duration::from_millis(300),
            ..SeedOptions::default()
        },
    )
    .await
    .expect_err("a held lock refuses the run");
    assert!(matches!(
        error,
        SeedError::Refused(ref message) if message == "another platform seed holds the lock"
    ));
    sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *holder)
        .await
        .expect("release the seed lock");
    drop(holder);

    let report = seed_repository(&fixture).await;
    assert_eq!(report.actions["toolkit:coding"], json!("created"));
    fixture.finish().await;
}

// ── the generic import ───────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_import_over_the_seeded_catalog_appends_publishes_and_never_resurrects() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "coding", "coding").await;
    seed_repository(&fixture).await;
    let platform = fixture.second_pool().await;
    let bundle = coding_bundle();
    let tool_id = read_json("coding/tools/coding_read_file/tool.json")["tool_id"]
        .as_str()
        .expect("the tool identity")
        .to_owned();
    let toolkit_id = read_json("coding/toolkit.json")["toolkit_id"]
        .as_str()
        .expect("the toolkit identity")
        .to_owned();

    let report = import_bundle(
        &fixture.pool,
        &settings(Some(runner_image())),
        &bundle,
        &platform,
    )
    .await
    .expect("the import appends the edited tool");
    assert_eq!(report.actions["service:coding"], json!("unchanged"));
    assert_eq!(
        report.actions["operation:coding.read_file"],
        json!("unchanged")
    );
    assert_eq!(
        report.actions["tool:coding.coding_read_file"],
        json!("appended")
    );
    assert_eq!(report.actions["toolkit:coding"], json!("appended"));
    assert_eq!(report.versions["tool:coding.coding_read_file"], json!(2));
    assert_eq!(report.versions["toolkit:coding"], json!(2));

    let versions: Vec<i32> = sqlx::query_scalar(
        "SELECT version FROM public.mcp_tool_versions WHERE tool_id=$1::uuid ORDER BY version",
    )
    .bind(&tool_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("tool versions");
    assert_eq!(versions, vec![1, 2]);
    let published: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_tool_versions \
         WHERE tool_id=$1::uuid AND status='published'",
    )
    .bind(&tool_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("published versions");
    assert_eq!(published, 2, "the earlier version stays published");
    let toolkit_versions: Vec<i32> = sqlx::query_scalar(
        "SELECT version FROM public.mcp_toolkit_versions \
         WHERE toolkit_id=$1::uuid ORDER BY version",
    )
    .bind(&toolkit_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("toolkit versions");
    assert_eq!(toolkit_versions, vec![1, 2]);

    let again = import_bundle(
        &fixture.pool,
        &settings(Some(runner_image())),
        &bundle,
        &platform,
    )
    .await
    .expect("the second import is a no-op");
    assert!(!again.changed());

    // A human disabled the tool version the repository still declares: never resurrect it.
    sqlx::query(
        "UPDATE public.mcp_tool_versions SET status='disabled' \
         WHERE tool_id=$1::uuid AND version=2",
    )
    .bind(&tool_id)
    .execute(&fixture.pool)
    .await
    .expect("disable the tool version");
    let refusal = import_bundle(
        &fixture.pool,
        &settings(Some(runner_image())),
        &bundle,
        &platform,
    )
    .await
    .expect_err("a disabled row is refused");
    assert!(
        matches!(
            refusal,
            SeedError::Refused(ref message)
                if message == "tool coding.coding_read_file v2 is disabled in the catalog"
        ),
        "{refusal:?}"
    );

    fixture.finish().await;
}

/// The actor the seed writes with (the reference's `ACTOR`).
fn seed_actor() -> Attribution {
    Attribution {
        subject: "platform-seed".to_owned(),
        license_id: Some(AuthorityId::new(SEED_LICENCE_ID).expect("the seed licence identity")),
    }
}

fn synthetic_bundle(destination: &str) -> ToolkitBundle {
    serde_json::from_value(import_body(destination)).expect("a valid toolkit bundle")
}

#[tokio::test]
async fn a_draft_left_by_a_dead_run_is_published() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "synthetic_import", "synthetic").await;
    let platform = fixture.second_pool().await;
    // An earlier run created the service at version 1 and died before publishing it.
    let manifest: ServiceManifest = serde_json::from_value(json!({
        "schema_version": 1,
        "service_id": SYNTHETIC_SERVICE_ID,
        "version": 1,
        "service_key": "synthetic_import",
        "destination_alias": "synthetic_import",
        "license_app_key": "synthetic",
        "auth_adapter": "license_bearer",
        "credential_profile_key": "synthetic",
        "max_request_bytes": 4096,
        "max_response_bytes": 4096
    }))
    .expect("a valid service manifest");
    PlatformCatalogRepository::new(platform.clone())
        .add_service(&manifest, &seed_actor(), None)
        .await
        .expect("a service draft");

    let bundle = synthetic_bundle("synthetic_import");
    let report = import_bundle(&fixture.pool, &settings(None), &bundle, &platform)
        .await
        .expect("the seed succeeds");
    assert_eq!(
        report.actions["service:synthetic_import"],
        json!("published")
    );
    assert_eq!(report.versions["service:synthetic_import"], json!(1));
    assert_eq!(
        report.actions["operation:synthetic_import.do_thing"],
        json!("created")
    );
    let status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_service_versions \
         WHERE service_id=$1::uuid AND version=1",
    )
    .bind(SYNTHETIC_SERVICE_ID)
    .fetch_one(&fixture.pool)
    .await
    .expect("the service status");
    assert_eq!(status, "published");

    fixture.finish().await;
}

// ── the HTTP route ──────────────────────────────────────────────────────────────────────

fn platform_key_file() -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let path = std::env::temp_dir().join(format!(
        "mcp-platform-seed-key-{}-{nanos}-{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::write(&path, PLATFORM_KEY).expect("write the platform key");
    path
}

fn auth_with_platform() -> Auth {
    let config = AuthConfig {
        license_introspect_url: Some("https://licence.example/introspect".into()),
        license_app_key: Some("test-app-key".into()),
        admin_key_file: Some(support::admin_key_file()),
        platform_admin_key_file: Some(platform_key_file()),
        admin_tenant_ids: vec![Rfc4122Uuid::parse(support::TENANT_A).expect("static uuid")],
        ..AuthConfig::default()
    };
    let mut auth = Auth::from_config(&config).expect("valid auth config");
    auth.licences = Arc::new(TestLicence);
    auth
}

/// The app with a platform pool; the approved list mirrors the process's runner digest so the
/// route's outcome does not depend on the ambient environment.
async fn platform_app(fixture: &Fixture) -> axum::Router {
    let mut state = fixture.state();
    state.platform = Some(fixture.second_pool().await);
    state.approved_runner_images = match std::env::var("MCP_RUNNER_IMAGE_DIGEST") {
        Ok(digest) if !digest.trim().is_empty() => vec![digest],
        _ => Vec::new(),
    };
    app_with_auth(state, auth_with_platform())
}

fn platform_request(body: Option<Value>) -> Request<Body> {
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/toolkits/import")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY)
        .header("x-mcp-platform-admin-key", PLATFORM_KEY);
    match body {
        Some(body) => request
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body.to_string()))
            .expect("request"),
        None => request.body(Body::empty()).expect("request"),
    }
}

#[tokio::test]
async fn the_import_route_publishes_a_bundle_over_the_platform_pool() {
    let fixture = Fixture::new().await;
    register_source(&fixture, "synthetic_import", "synthetic").await;
    let app = platform_app(&fixture).await;
    let digest_configured = std::env::var("MCP_RUNNER_IMAGE_DIGEST")
        .ok()
        .is_some_and(|value| !value.trim().is_empty());

    let (status, headers, body) = send(
        &app,
        platform_request(Some(import_body("synthetic_import"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    let object = body.as_object().expect("the report is an object");
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    assert_eq!(
        keys,
        vec!["actions", "versions", "tools_skipped", "changed"],
        "the reference's report shape"
    );
    assert_eq!(
        body["actions"]["service:synthetic_import"],
        json!("created")
    );
    assert_eq!(
        body["actions"]["operation:synthetic_import.do_thing"],
        json!("created")
    );
    assert_eq!(body["tools_skipped"], json!(!digest_configured));
    assert_eq!(body["changed"], json!(true));
    assert_eq!(body["versions"]["service:synthetic_import"], json!(1));
    support::assert_no_store(&headers);

    // The identical import changes nothing.
    let (status, _, body) = send(
        &app,
        platform_request(Some(import_body("synthetic_import"))),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["changed"], json!(false));
    assert_eq!(
        body["actions"]["service:synthetic_import"],
        json!("unchanged")
    );

    fixture.finish().await;
}

#[tokio::test]
async fn the_import_route_answers_the_reference_bodies() {
    let fixture = Fixture::new().await;
    let app = platform_app(&fixture).await;

    // A missing source is a seed refusal: FastAPI nests the detail object.
    let (status, _, body) = send(&app, platform_request(Some(import_body("missing_source")))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(
        body,
        json!({
            "detail": {
                "error": "import_failed",
                "detail": "source missing_source is not registered and active"
            }
        })
    );

    // A bundle the contract refuses is the request model's validation error.
    let mut invalid = import_body("synthetic_import");
    invalid["tools"][0]["files"][0]["path"] = json!("ops.py");
    let (status, _, _) = send(&app, platform_request(Some(invalid))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // A management principal without the platform key is the reference's PermissionError.
    let no_platform = Request::builder()
        .method(Method::POST)
        .uri("/mcp/toolkits/import")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(import_body("synthetic_import").to_string()))
        .expect("request");
    let (status, headers, body) = send(&app, no_platform).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));
    support::assert_no_store(&headers);

    // A deployment without `MCP_PLATFORM_DATABASE_URL` answers the reference's 503.
    let pool_less = app_with_auth(fixture.state(), auth_with_platform());
    let (status, _, body) = send(
        &pool_less,
        platform_request(Some(import_body("synthetic_import"))),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"detail": "platform_authoring_unavailable"}));

    fixture.finish().await;
}

#[test]
fn the_openapi_document_declares_the_import_contract() {
    let spec = serde_json::to_value(openapi()).expect("openapi json");
    let operation = &spec["paths"]["/mcp/toolkits/import"]["post"];
    assert!(operation.is_object(), "missing post /mcp/toolkits/import");
    assert_eq!(operation["tags"], json!(["sources"]));
    // The reference reads the body through `Depends(json_contract(...))`: no declared body.
    assert!(operation.get("requestBody").is_none());
    assert_eq!(
        operation["responses"]["201"]["content"]["application/json"]["schema"],
        json!({"$ref": "#/components/schemas/AnyJson"})
    );
    // No path or query parameter, so the reference declares no 422.
    assert!(operation["responses"].get("422").is_none());
}
