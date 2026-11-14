//! The four `/mcp/runs` operations against a real Postgres 18 and the real `/mcp`
//! middleware.
//!
//! Ported from the reference `src/routers/executions.py` and `src/execution/service.py`.
//! Every test fails if the behaviour it covers is removed: admission is durable and bounded,
//! a kata run is waited on inline until its worker finishes, an external run is not waited
//! on at all, and every read is scoped to the caller's tenant, binding and licence.
//!
//! Server selection mirrors `tests/routes_available.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL`, else an ephemeral `postgres:18` container started with docker and removed
//! afterwards, else FAIL (never skip). Each test gets its own fresh database.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::auth::pg_bindings::PgBindingAuthority;
use mcp_server_rs::auth::{
    AuthError, Binding, BindingAuthority, BoxFuture, LicenceAuthority, LicenseIdentity,
    Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::models::ToolManifest;
use mcp_server_rs::config::ExecutionSettings;
use mcp_server_rs::{AppState, app_with_auth};

use support::{
    ADMIN_KEY, Fixture, LICENCE_ID, LICENCE_TOKEN, TENANT_A, TOOL_ALPHA, assert_no_store,
    binding_fixture_with_tools, create_binding, kata_manifest, send, tool_manifest,
};

const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const LICENCE_B: &str = "30000000-0000-4000-8000-000000000002";
const BINDING_B: &str = "01900000-0000-7000-8000-0000000000b9";
const OTHER_TOKEN: &str = "other-tenant-token";
const UNKNOWN_RUN: &str = "01900000-0000-7000-8000-0000000000af";

// ── the bound fixture ─────────────────────────────────────────────────────────────────────

struct Bound {
    fixture: Fixture,
    app: Router,
    token: String,
}

/// A published catalog, a real binding created through the HTTP surface, and the app served
/// with the given execution settings.
async fn bound(manifests: &[ToolManifest], settings: ExecutionSettings, enabled: bool) -> Bound {
    let fixture = Fixture::new().await;
    binding_fixture_with_tools(&fixture, manifests).await;
    let created = create_binding(&fixture.app()).await;
    let token = created["token"].as_str().expect("binding token").to_owned();
    let app = app_with_auth(
        fixture.state_with_execution(settings, enabled),
        fixture
            .auth()
            .with_bindings(Arc::new(PgBindingAuthority::new(fixture.pool.clone()))),
    );
    Bound {
        fixture,
        app,
        token,
    }
}

fn submit_request(token: &str, body: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri("/mcp/runs")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_owned()))
        .expect("request")
}

fn submit_json(token: &str, body: &Value) -> Request<Body> {
    submit_request(token, &body.to_string())
}

fn binding_get(token: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::GET)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", token)
        .body(Body::empty())
        .expect("request")
}

fn binding_post(token: &str, uri: &str) -> Request<Body> {
    Request::builder()
        .method(Method::POST)
        .uri(uri)
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-binding", token)
        .body(Body::empty())
        .expect("request")
}

/// Submit one run of the fixture tool and return its identity.
async fn queued(app: &Router, token: &str) -> String {
    let (status, _, body) = send(
        app,
        submit_json(token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    body["run_id"].as_str().expect("run identity").to_owned()
}

async fn append_event(pool: &PgPool, run_id: &str, kind: &str) {
    sqlx::query(
        "INSERT INTO public.mcp_run_events(tenant_id,run_id,kind) \
         VALUES ($1::uuid,$2::uuid,$3)",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .bind(kind)
    .execute(pool)
    .await
    .expect("append event");
}

async fn event_count(pool: &PgPool, run_id: &str, kind: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_run_events \
         WHERE tenant_id = $1::uuid AND run_id = $2::uuid AND kind = $3",
    )
    .bind(TENANT_A)
    .bind(run_id)
    .bind(kind)
    .fetch_one(pool)
    .await
    .expect("event count")
}

/// Walk the one queued run through the worker's transition matrix. `mcp_guard_run` refuses a
/// direct queued → succeeded update, so the three steps are required.
async fn walk_queued_run(pool: &PgPool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let run: Option<String> = sqlx::query_scalar(
            "SELECT run_id::text FROM public.mcp_runs \
             WHERE tenant_id = $1::uuid AND status = 'queued' \
             ORDER BY created_at DESC LIMIT 1",
        )
        .bind(TENANT_A)
        .fetch_optional(pool)
        .await
        .expect("find the queued run");
        if let Some(run) = run {
            for statement in [
                "UPDATE public.mcp_runs SET status = 'starting', started_at = clock_timestamp() \
                 WHERE run_id = $1::uuid",
                "UPDATE public.mcp_runs SET status = 'running' WHERE run_id = $1::uuid",
                "UPDATE public.mcp_runs SET status = 'succeeded', finished_at = clock_timestamp() \
                 WHERE run_id = $1::uuid",
            ] {
                sqlx::query(statement)
                    .bind(&run)
                    .execute(pool)
                    .await
                    .expect("walk the run");
            }
            return;
        }
        assert!(Instant::now() < deadline, "no queued run appeared");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A licence authority that proves two tenants, so tenant isolation is exercised through the
/// real middleware instead of by calling the service directly.
struct TenantLicence;

impl LicenceAuthority for TenantLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            let (tenant, licence) = match token {
                OTHER_TOKEN => (TENANT_B, LICENCE_B),
                LICENCE_TOKEN => (TENANT_A, LICENCE_ID),
                _ => return Err(AuthError::Unauthorized),
            };
            Ok(LicenseIdentity {
                tenant_id: Rfc4122Uuid::parse(tenant).expect("tenant identity"),
                license_id: Rfc4122Uuid::parse(licence).expect("licence identity"),
                subject: "svc:test:mcp".to_owned(),
                subject_kind: Some(SubjectKind::Tenant),
            })
        })
    }
}

/// Any binding token authenticates: the second tenant only needs a principal to be refused a
/// run it does not own, and it holds no rows of its own.
struct AnyBinding;

impl BindingAuthority for AnyBinding {
    fn authenticate<'a>(
        &'a self,
        _identity: &'a LicenseIdentity,
        _token: &'a str,
    ) -> BoxFuture<'a, Result<Binding, AuthError>> {
        Box::pin(async move {
            Ok(Binding {
                binding_id: Rfc4122Uuid::parse(BINDING_B).expect("binding identity"),
                revision: 1,
            })
        })
    }
}

fn other_tenant_app(fixture: &Fixture) -> Router {
    let mut auth = fixture.auth();
    auth.licences = Arc::new(TenantLicence);
    auth.bindings = Arc::new(AnyBinding);
    let state: AppState = fixture.state_with_execution(ExecutionSettings::default(), true);
    app_with_auth(state, auth)
}

// ── submission ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn submit_answers_202_with_a_queued_envelope_and_a_uuid7_run_id() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let (status, headers, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_no_store(&headers);
    let run_id = body["run_id"].as_str().expect("run identity");
    assert_eq!(run_id.len(), 36);
    assert_eq!(&run_id[14..15], "7", "a run identity is UUIDv7: {run_id}");
    assert_eq!(body["status"], "queued");
    assert_eq!(body["result"], Value::Null);
    assert_eq!(body["error"], Value::Null);
    assert_eq!(body["payload_expired"], json!(false));
    bound.fixture.finish().await;
}

#[tokio::test]
async fn an_external_tool_never_waits_for_its_worker() {
    // The wait would take 300 ms; an n8n run is answered straight from admission.
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings {
            sync_wait: Duration::from_millis(300),
            ..ExecutionSettings::default()
        },
        true,
    )
    .await;
    let started = Instant::now();
    let (status, _, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    let elapsed = started.elapsed();
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "queued");
    assert!(
        elapsed < Duration::from_millis(250),
        "an external run returned after {elapsed:?}"
    );
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_kata_run_returns_the_terminal_row_within_the_sync_wait() {
    let bound = bound(
        &[kata_manifest()],
        ExecutionSettings {
            sync_wait: Duration::from_millis(300),
            ..ExecutionSettings::default()
        },
        true,
    )
    .await;
    let pool = bound.fixture.pool.clone();
    let walker = tokio::spawn(async move { walk_queued_run(&pool).await });
    let (status, _, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    walker.await.expect("walker");
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    assert_eq!(body["status"], "succeeded", "{body}");
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_management_caller_cannot_submit() {
    // An operator key authenticates on the whole runs surface, as in the reference; the
    // collection POST then refuses a management caller at the route (`403 forbidden`), which
    // is the reference's `PermissionError`, not a 401 from the middleware.
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/mcp/runs")
        .header("x-tenant-id", format!("Bearer {LICENCE_TOKEN}"))
        .header("x-mcp-admin-key", ADMIN_KEY)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            json!({"tool": "alpha_tool", "inputs": {}}).to_string(),
        ))
        .expect("request");
    let (status, _, body) = send(&bound.app, request).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, json!({"error": "forbidden"}));
    bound.fixture.finish().await;
}

#[tokio::test]
async fn an_unknown_tool_is_forbidden() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let (status, headers, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "missing_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body, json!({"error": "forbidden"}));
    assert_no_store(&headers);
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_malformed_body_is_invalid() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    for body in [
        "not json".to_owned(),
        json!({"inputs": {}}).to_string(),
        json!({"tool": "Not_A_Name", "inputs": {}}).to_string(),
        json!({"tool": "alpha_tool", "inputs": []}).to_string(),
        json!({"tool": "alpha_tool", "inputs": {}, "extra": 1}).to_string(),
    ] {
        let (status, headers, body) = send(&bound.app, submit_request(&bound.token, &body)).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(body, json!({"error": "invalid_request"}), "{body}");
        assert_no_store(&headers);
    }
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_full_queue_is_429_with_retry_after() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings {
            queue_global_max: 1,
            queue_per_tenant_max: 1,
            ..ExecutionSettings::default()
        },
        true,
    )
    .await;
    let (status, _, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let (status, headers, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body, json!({"detail": "execution_queue_full"}));
    assert_eq!(
        headers
            .get(header::RETRY_AFTER)
            .and_then(|value| value.to_str().ok()),
        Some("1")
    );
    bound.fixture.finish().await;
}

#[tokio::test]
async fn a_deployment_without_execution_is_unavailable() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        false,
    )
    .await;
    let (status, _, body) = send(
        &bound.app,
        submit_json(&bound.token, &json!({"tool": "alpha_tool", "inputs": {}})),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "{body}");
    assert_eq!(body, json!({"detail": "execution_unavailable"}));
    bound.fixture.finish().await;
}

// ── inspection ───────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_foreign_or_unknown_run_is_not_found() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let run = queued(&bound.app, &bound.token).await;

    let (status, headers, body) = send(
        &bound.app,
        binding_get(&bound.token, &format!("/mcp/runs/{UNKNOWN_RUN}")),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));
    assert_no_store(&headers);

    // The same run, asked for by a caller of another tenant, is invisible rather than refused.
    let other = other_tenant_app(&bound.fixture);
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/mcp/runs/{run}"))
        .header("x-tenant-id", format!("Bearer {OTHER_TOKEN}"))
        .header("x-mcp-binding", "other-binding-token")
        .body(Body::empty())
        .expect("request");
    let (status, _, body) = send(&other, request).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body, json!({"error": "not_found"}));
    bound.fixture.finish().await;
}

#[tokio::test]
async fn events_are_ascending_bounded_and_the_bounds_are_enforced() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let run = queued(&bound.app, &bound.token).await;
    append_event(&bound.fixture.pool, &run, "starting").await;
    append_event(&bound.fixture.pool, &run, "running").await;
    let uri = format!("/mcp/runs/{run}/events");

    let (status, _, body) = send(&bound.app, binding_get(&bound.token, &uri)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let items = body["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    assert_eq!(items[0]["kind"], "queued");
    assert_eq!(items[1]["kind"], "starting");
    assert_eq!(items[2]["kind"], "running");
    let ids: Vec<i64> = items
        .iter()
        .map(|item| item["event_id"].as_i64().expect("event identity"))
        .collect();
    assert!(ids.windows(2).all(|pair| pair[0] < pair[1]), "{ids:?}");
    let created_at = items[0]["created_at"].as_str().expect("created_at");
    chrono::DateTime::parse_from_rfc3339(created_at).expect("ISO-8601 instant");

    let (status, _, body) = send(
        &bound.app,
        binding_get(&bound.token, &format!("{uri}?limit=2")),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["items"].as_array().expect("items").len(), 2);

    let (status, _, body) = send(
        &bound.app,
        binding_get(&bound.token, &format!("{uri}?after={}", ids[0])),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let after = body["items"].as_array().expect("items");
    assert_eq!(after.len(), 2);
    assert_eq!(after[0]["kind"], "starting");

    for query in ["limit=0", "limit=101", "after=-1"] {
        let (status, _, body) = send(
            &bound.app,
            binding_get(&bound.token, &format!("{uri}?{query}")),
        )
        .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{query}: {body}");
        assert_eq!(body, json!({"error": "invalid_request"}), "{query}");
    }
    bound.fixture.finish().await;
}

#[tokio::test]
async fn cancel_answers_the_flag_and_appends_one_event() {
    let bound = bound(
        &[tool_manifest("alpha_tool", TOOL_ALPHA)],
        ExecutionSettings::default(),
        true,
    )
    .await;
    let run = queued(&bound.app, &bound.token).await;
    let uri = format!("/mcp/runs/{run}/cancel");

    let (status, _, body) = send(&bound.app, binding_post(&bound.token, &uri)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cancel_requested"], json!(true));
    assert_eq!(body["status"], "queued");
    assert_eq!(
        event_count(&bound.fixture.pool, &run, "cancel_requested").await,
        1
    );

    let (status, _, body) = send(&bound.app, binding_post(&bound.token, &uri)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["cancel_requested"], json!(true));
    assert_eq!(
        event_count(&bound.fixture.pool, &run, "cancel_requested").await,
        1,
        "a repeated cancel appends no event"
    );
    bound.fixture.finish().await;
}
