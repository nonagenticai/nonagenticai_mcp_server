//! The upstream broker against a real Postgres 18, a real local HTTP upstream and the real
//! catalog: every assertion is on what actually left the process and what the journal recorded.
//!
//! Ported from the reference `src/broker/client.py`. The harness mirrors `tests/worker_storage.rs`
//! — a run is accepted by the real `ExecutionRepository::accept`, then claimed exactly as the
//! reference scheduler claims it — so the authority snapshot, the fence and the deadlines have
//! the shapes a live worker sees.
//!
//! The catalog schema makes a published version's content immutable (`mcp_guard_snapshot`), so
//! every negative case is a *configuration* of its own lab rather than a mutation of a published
//! row. Server selection mirrors `tests/support/mod.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL`, else an ephemeral `postgres:18` container started with docker, else FAIL.

mod support;

use std::collections::VecDeque;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, Method as HttpMethod, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use serde_json::{Value, json};
use sqlx::PgPool;

use mcp_server_rs::auth::licenses::LicenceAuthority;
use mcp_server_rs::auth::{
    AuthError, BoxFuture, LicenseIdentity, Principal, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, Name};
use mcp_server_rs::catalog::models::ToolLimits;
use mcp_server_rs::catalog::resolver::{CatalogResolver, ResolvedTool};
use mcp_server_rs::catalog::toolkit_models::{BoundContext, EffectiveTool, ToolReference};
use mcp_server_rs::config::{ExecutionSettings, WorkerSettings};
use mcp_server_rs::execution::RunRow;
use mcp_server_rs::storage::catalog::CatalogRepository;
use mcp_server_rs::storage::executions::ExecutionRepository;
use mcp_server_rs::worker::broker::auth::AuthAdapters;
use mcp_server_rs::worker::broker::egress::{
    EgressPolicy, PlatformClients, PoolLimits, SystemResolver,
};
use mcp_server_rs::worker::broker::limits::SourceLimiter;
use mcp_server_rs::worker::broker::{Broker, BrokerError, CallOutcome};
use mcp_server_rs::worker::creds::{CredentialResolver, FileResolver};
use mcp_server_rs::worker::row::WorkerRow;
use mcp_server_rs::worker::sources::{SourceRegistry, crypto};
use mcp_server_rs::worker::store::WorkerStore;

use support::{Fixture, LICENCE_ID, PROFILE, SERVICE_ID, TENANT_A, TOOL_ALPHA, actor_snapshot};

// ── identities ──────────────────────────────────────────────────────────────────────────────

/// `public.mcp_platform_tenant()` — the owner of a platform service, not the app state's.
const PLATFORM: &str = "01900000-0000-7000-8000-00000000f001";
const OPERATION: &str = "40000000-0000-7000-8000-000000000001";
const SOURCE_ID: &str = "0190a0b0-0000-7000-8000-00000000d001";
const SOURCE_KEY: &str = "synthetic_destination";
const SERVICE_KEY: &str = "synthetic_service";
const GATEWAY_APP_KEY: &str = "synthetic";
/// A 32-byte base64url key (all zero bytes) for the sealed source secrets.
const SOURCE_KEY_BYTES: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const GATEWAY_TOKEN: &str = "gw-token";
const SERVICE_TOKEN: &str = "svc-token";
const FOREIGN_TOKEN: &str = "foreign-token";
const SOURCE_SECRET: &str = "source-secret";
/// A port nothing listens on: a transport failure after the request is prepared.
const DEAD_BASE: &str = "http://127.0.0.1:1";

fn uuid(value: &str) -> Rfc4122Uuid {
    Rfc4122Uuid::parse(value).expect("static identity")
}

fn authority(value: &str) -> AuthorityId {
    AuthorityId::new(value).expect("authority identity")
}

// ── the local upstream ─────────────────────────────────────────────────────────────────────

#[derive(Clone, Debug, Default)]
struct Seen {
    method: String,
    path: String,
    query: String,
    headers: Vec<(String, String)>,
    body: String,
}

impl Seen {
    fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(candidate, _)| candidate.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone)]
struct Reply {
    status: u16,
    body: String,
}

struct Upstream {
    base: String,
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}

impl Upstream {
    fn push(&self, status: u16, body: impl Into<String>) {
        self.replies.lock().unwrap().push_back(Reply {
            status,
            body: body.into(),
        });
    }

    fn requests(&self) -> Vec<Seen> {
        self.seen.lock().unwrap().clone()
    }

    fn last(&self) -> Seen {
        self.requests().pop().expect("no upstream request")
    }
}

#[derive(Clone)]
struct UpstreamState {
    seen: Arc<Mutex<Vec<Seen>>>,
    replies: Arc<Mutex<VecDeque<Reply>>>,
}

async fn upstream_handler(
    State(state): State<UpstreamState>,
    method: HttpMethod,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    state.seen.lock().unwrap().push(Seen {
        method: method.to_string(),
        path: uri.path().to_owned(),
        query: uri.query().unwrap_or_default().to_owned(),
        headers: headers
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_owned(),
                    value.to_str().unwrap_or_default().to_owned(),
                )
            })
            .collect(),
        body: String::from_utf8_lossy(&body).into_owned(),
    });
    let reply = state.replies.lock().unwrap().pop_front().unwrap_or(Reply {
        status: 200,
        body: "{\"id\":\"synthetic\"}".to_owned(),
    });
    let status = StatusCode::from_u16(reply.status).unwrap_or(StatusCode::OK);
    (
        status,
        [(header::CONTENT_TYPE, "application/json")],
        reply.body,
    )
        .into_response()
}

async fn upstream() -> Upstream {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let replies = Arc::new(Mutex::new(VecDeque::new()));
    let state = UpstreamState {
        seen: Arc::clone(&seen),
        replies: Arc::clone(&replies),
    };
    let app: Router = Router::new().fallback(upstream_handler).with_state(state);
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind upstream");
    let address = listener.local_addr().expect("upstream address");
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    Upstream {
        base: format!("http://127.0.0.1:{}", address.port()),
        seen,
        replies,
    }
}

// ── the licence authority ──────────────────────────────────────────────────────────────────

/// Two fixed identities: the tenant's own credential and one that belongs to another tenant.
struct Tokens;

impl LicenceAuthority for Tokens {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move { Self::identity_for(token) })
    }

    fn authenticate_for_app<'a>(
        &'a self,
        token: &'a str,
        _app_key: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move { Self::identity_for(token) })
    }
}

impl Tokens {
    fn identity_for(token: &str) -> Result<LicenseIdentity, AuthError> {
        let tenant = match token {
            GATEWAY_TOKEN | SERVICE_TOKEN => TENANT_A,
            FOREIGN_TOKEN => "20000000-0000-4000-8000-000000000001",
            _ => return Err(AuthError::Unauthorized),
        };
        Ok(LicenseIdentity {
            tenant_id: uuid(tenant),
            license_id: uuid(LICENCE_ID),
            subject: "svc:test:mcp".to_owned(),
            subject_kind: Some(SubjectKind::Tenant),
        })
    }
}

// ── the credential bundle ─────────────────────────────────────────────────────────────────

fn bundle_path() -> PathBuf {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    std::env::temp_dir().join(format!(
        "mcp-worker-broker-bundle-{}-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos()),
        NEXT.fetch_add(1, Ordering::Relaxed)
    ))
}

fn write_bundle(path: &Path, gateway_token: &str, service_app_key: &str) {
    let entry = |service: &str, alias: &str, app_key: &str, token: &str| {
        json!({
            "tenant_id": TENANT_A,
            "profile_id": PROFILE,
            "service": service,
            "alias": alias,
            "license_id": LICENCE_ID,
            "app_key": app_key,
            "token": token,
        })
    };
    let bundle = json!({
        "schema_version": 1,
        "entries": [
            entry("gateway", "gateway", GATEWAY_APP_KEY, gateway_token),
            entry(SERVICE_KEY, "synthetic", service_app_key, SERVICE_TOKEN),
        ],
    });
    std::fs::write(path, bundle.to_string()).expect("write credential bundle");
}

// ── the fixture description ───────────────────────────────────────────────────────────────

/// One lab's upstream contract: what the service, the operation and the source look like.
struct Config {
    operation: Value,
    /// The service manifest's adapter.
    auth_adapter: &'static str,
    /// The source's stored `auth` object.
    source_auth: Value,
    /// The sealed secret, when the auth kind needs one.
    source_token: Option<&'static str>,
    /// Whether the source belongs to the tenant (the pinned, https-only transport).
    tenant_source: bool,
    /// Where the source points; `None` uses the local upstream.
    base_url: Option<&'static str>,
    /// The profile's credential for the service.
    credential_app_key: &'static str,
    limits: ToolLimits,
    max_request_bytes: i32,
    max_response_bytes: i32,
    idempotency_header: Option<&'static str>,
    /// A `mcp_service_grants` row for the tenant. A platform service whose destination source
    /// carries a stored secret is usable only when it is granted (`mcp_tenant_may_use_service`);
    /// a licence-kind one needs no grant.
    grant: bool,
    limiter: Option<(u32, u32)>,
    global_concurrency: Option<u32>,
}

impl Config {
    fn new(operation: Value) -> Self {
        Self {
            operation,
            auth_adapter: "license_bearer",
            source_auth: json!({"kind": "static_bearer"}),
            source_token: Some(SOURCE_SECRET),
            tenant_source: false,
            base_url: None,
            credential_app_key: GATEWAY_APP_KEY,
            limits: ToolLimits {
                frame_bytes: 4096,
                ..ToolLimits::default()
            },
            max_request_bytes: 4096,
            max_response_bytes: 4096,
            idempotency_header: None,
            grant: true,
            limiter: None,
            global_concurrency: None,
        }
    }
}

// ── the lab ───────────────────────────────────────────────────────────────────────────────

struct Lab {
    fixture: Fixture,
    store: WorkerStore,
    broker: Broker,
    upstream: Upstream,
    principal: Principal,
    resolved: ResolvedTool,
    worker_id: String,
    bundle: PathBuf,
}

/// One accepted, claimed run.
struct Job {
    run: RunRow,
    row: WorkerRow,
}

impl Lab {
    async fn start(config: Config) -> Self {
        let fixture = Fixture::new().await;
        let mut settings = WorkerSettings {
            lease: Duration::from_secs(30),
            run_max: Duration::from_secs(60),
            api_max_inflight: 8,
            api_concurrency_global: config.global_concurrency.unwrap_or(8),
            api_concurrency_per_service: 8,
            api_max_calls_per_minute: 60,
            api_timeout: Duration::from_secs(5),
            service_limits_file: None,
            ..WorkerSettings::default()
        };
        settings.builder_source_calls_per_minute = config.limiter.map_or(60, |(calls, _)| calls);
        settings.builder_source_concurrency =
            config.limiter.map_or(2, |(_, concurrency)| concurrency);
        let execution = ExecutionSettings::default();
        let upstream = upstream().await;

        let owner = if config.tenant_source {
            TENANT_A
        } else {
            PLATFORM
        };
        seed_service(&fixture, &config, owner).await;
        seed_operation(&fixture, &config.operation).await;
        let base_url = match (config.base_url, config.tenant_source) {
            // A tenant source is https-only by the table's own check.
            (Some(base), _) => base.to_owned(),
            (None, true) => "https://api.example.test".to_owned(),
            (None, false) => upstream.base.clone(),
        };
        seed_source(&fixture, &config, owner, &base_url).await;
        if config.grant && !config.tenant_source {
            sqlx::query(
                "INSERT INTO public.mcp_service_grants(service_id,grantee_tenant_id,granted_by) \
                 VALUES ($1::uuid,$2::uuid,$3)",
            )
            .bind(SERVICE_ID)
            .bind(TENANT_A)
            .bind(actor_snapshot())
            .execute(&fixture.pool)
            .await
            .expect("service grant");
        }

        let manifest: mcp_server_rs::catalog::models::ToolManifest = serde_json::from_value(json!({
            "schema_version": 1,
            "tool_id": TOOL_ALPHA,
            "tenant_id": TENANT_A,
            "version": 1,
            "public_name": "alpha_tool",
            "operation": "synthetic.alpha_tool",
            "description": "Synthetic fixture",
            "runtime": "n8n_workflow",
            "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
            "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
            "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
            "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
            "package_sha256": "a".repeat(64),
            "effect": effect_of(&config.operation),
            "allowed_operations": [{"id": OPERATION, "version": 1}],
        }))
        .expect("valid tool manifest");
        support::insert_published_tool(&fixture, &manifest).await;
        insert_profile(&fixture, config.credential_app_key).await;
        let toolkit = fixture.service();
        let operator = support::principal();
        let references = [(TOOL_ALPHA, "alpha_tool")];
        let drafted = toolkit
            .write(&operator, &support::toolkit_manifest(&references), None)
            .await
            .expect("create toolkit");
        toolkit
            .transition(
                &operator,
                &support::uuid7(support::TOOLKIT_1),
                support::version(1),
                mcp_server_rs::catalog::lifecycle::VersionStatus::Published,
                drafted.revision,
            )
            .await
            .expect("publish toolkit");
        let created = support::create_binding(&fixture.app()).await;
        let binding = created["binding"]["binding_id"]
            .as_str()
            .expect("binding identity")
            .to_owned();
        let revision = created["binding"]["revision"]
            .as_i64()
            .expect("binding revision");
        let principal = Principal {
            tenant_id: uuid(TENANT_A),
            license_id: uuid(LICENCE_ID),
            subject: "agent-09".to_owned(),
            binding_id: Some(uuid(&binding)),
            binding_revision: Some(revision),
            management: false,
            platform: false,
        };

        let resolved = ResolvedTool {
            manifest,
            effective: EffectiveTool {
                tool: ToolReference {
                    id: support::uuid7(TOOL_ALPHA),
                    version: support::version(1),
                    tenant_id: authority(TENANT_A),
                },
                operation_constraints: Vec::new(),
                limits: config.limits,
                public_name: Name::new("alpha_tool").expect("public name"),
            },
            context: BoundContext {
                tenant_id: authority(TENANT_A),
                project_id: None,
                workspace_id: None,
                project_phase: None,
                work_type: None,
                card_stage: None,
                responsibility: None,
                test_command: None,
                reviewed_commit: None,
            },
        };

        let bundle = bundle_path();
        write_bundle(&bundle, GATEWAY_TOKEN, config.credential_app_key);
        let credentials: Arc<dyn CredentialResolver> = Arc::new(FileResolver::new(bundle.clone()));
        let egress = Arc::new(EgressPolicy::from_settings(
            &settings,
            Arc::new(SystemResolver),
        ));
        // Both rustls providers are linked in this test binary; pick one before any client
        // exists rather than relying on reqwest building its TLS config lazily.
        mcp_server_rs::install_crypto_provider();
        let auth = AuthAdapters::new(
            reqwest::Client::new(),
            reqwest::Client::new(),
            Duration::from_secs(3_600),
        );
        let limiter = SourceLimiter::new(
            settings.builder_source_calls_per_minute,
            settings.builder_source_concurrency,
        );
        let store = WorkerStore::new(fixture.pool.clone(), settings.clone(), execution.clone());
        let broker = Broker::new(
            fixture.pool.clone(),
            store.clone(),
            settings,
            execution,
            CatalogRepository::new(fixture.pool.clone()),
            CatalogResolver::new(fixture.pool.clone(), fixture.service(), Vec::new()),
            credentials,
            Arc::new(Tokens),
            SourceRegistry::new(fixture.pool.clone(), Some(SOURCE_KEY_BYTES))
                .expect("source registry"),
            auth,
            egress,
            limiter,
            PlatformClients::new(PoolLimits::default()),
            Some(GATEWAY_APP_KEY.to_owned()),
            authority(PLATFORM),
        );
        Self {
            fixture,
            store,
            broker,
            upstream,
            principal,
            resolved,
            worker_id: uuid::Uuid::now_v7().to_string(),
            bundle,
        }
    }

    /// Accept the run through the real repository, then claim it the way the scheduler does.
    async fn accept(&self) -> Job {
        let generation: i64 =
            sqlx::query_scalar("SELECT generation FROM public.mcp_catalog_state WHERE singleton")
                .fetch_one(&self.fixture.pool)
                .await
                .expect("catalog generation");
        let repository =
            ExecutionRepository::new(self.fixture.pool.clone(), ExecutionSettings::default());
        let run = repository
            .accept(
                &self.principal,
                &self.resolved,
                &json!({"query": "hello"}),
                None,
                generation,
                None,
            )
            .await
            .expect("accept");
        let pool = &self.fixture.pool;
        sqlx::query(
            "UPDATE public.mcp_runs SET status = 'starting', worker_id = $1::uuid, \
             fence = fence + 1, lease_until = clock_timestamp() + interval '30 seconds', \
             heartbeat_at = clock_timestamp(), \
             start_deadline = clock_timestamp() + interval '30 seconds', \
             deadline = clock_timestamp() + interval '45 seconds' \
             WHERE run_id = $2::uuid",
        )
        .bind(&self.worker_id)
        .bind(run.run_id.to_string())
        .execute(pool)
        .await
        .expect("claim");
        sqlx::query("INSERT INTO public.mcp_execution_slots(slot_id,run_id) VALUES (1,$1::uuid)")
            .bind(run.run_id.to_string())
            .execute(pool)
            .await
            .expect("slot");
        let mut tx = pool.begin().await.expect("transaction");
        let row = self
            .store
            .owned(&mut tx, &run.run_id, &self.worker_id, 1, true)
            .await
            .expect("owned");
        tx.commit().await.expect("commit");
        Job { run, row }
    }

    /// Rewrite the stored profile *and* the mounted bundle: the service credential now names
    /// another application. The access guard needs the revision to advance by one, and the
    /// deferred completeness trigger needs the reference row to agree.
    async fn set_credential_app_key(&self, app_key: &str) {
        let manifest = profile_manifest(app_key);
        let mut tx = self.fixture.pool.begin().await.expect("transaction");
        sqlx::query(
            "UPDATE public.mcp_credential_profiles SET manifest = $1, revision = revision + 1 \
             WHERE tenant_id = $2::uuid AND profile_id = $3::uuid",
        )
        .bind(&manifest)
        .bind(TENANT_A)
        .bind(PROFILE)
        .execute(&mut *tx)
        .await
        .expect("rewrite profile");
        sqlx::query(
            "UPDATE public.mcp_credential_refs SET app_key = $1 \
             WHERE tenant_id = $2::uuid AND profile_id = $3::uuid AND service_key = $4",
        )
        .bind(app_key)
        .bind(TENANT_A)
        .bind(PROFILE)
        .bind(SERVICE_KEY)
        .execute(&mut *tx)
        .await
        .expect("rewrite reference");
        tx.commit().await.expect("commit profile");
        write_bundle(&self.bundle, GATEWAY_TOKEN, app_key);
    }

    /// Point the gateway credential at another tenant's identity.
    fn set_gateway_token(&self, token: &str, app_key: &str) {
        write_bundle(&self.bundle, token, app_key);
    }

    async fn calls(&self, job: &Job) -> Vec<(i32, String, Option<String>, Option<i32>)> {
        sqlx::query_as(
            "SELECT sequence, status, reason, http_status FROM public.mcp_run_api_calls \
             WHERE run_id = $1::uuid ORDER BY sequence",
        )
        .bind(job.run.run_id.to_string())
        .fetch_all(&self.fixture.pool)
        .await
        .expect("journal rows")
    }

    async fn call_row(&self, job: &Job, sequence: i32) -> (String, Option<String>, Option<String>) {
        sqlx::query_as(
            "SELECT status, reason, method FROM public.mcp_run_api_calls \
             WHERE run_id = $1::uuid AND sequence = $2",
        )
        .bind(job.run.run_id.to_string())
        .bind(sequence)
        .fetch_one(&self.fixture.pool)
        .await
        .expect("journal row")
    }

    async fn permits(&self) -> i64 {
        sqlx::query_scalar("SELECT count(*) FROM public.mcp_api_permits")
            .fetch_one(&self.fixture.pool)
            .await
            .expect("permits")
    }

    async fn events(&self, job: &Job) -> Vec<String> {
        sqlx::query_scalar(
            "SELECT kind FROM public.mcp_run_events WHERE run_id = $1::uuid ORDER BY event_id",
        )
        .bind(job.run.run_id.to_string())
        .fetch_all(&self.fixture.pool)
        .await
        .expect("events")
    }

    fn pool(&self) -> &PgPool {
        &self.fixture.pool
    }
}

// ── seeding ───────────────────────────────────────────────────────────────────────────────

async fn seed_service(fixture: &Fixture, config: &Config, owner: &str) {
    sqlx::query(
        "INSERT INTO public.mcp_services(service_id,service_key,owner_tenant_id,created_by) \
         VALUES ($1::uuid,$2,$3::uuid,$4)",
    )
    .bind(SERVICE_ID)
    .bind(SERVICE_KEY)
    .bind(owner)
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
        "service_key": SERVICE_KEY,
        "destination_alias": SOURCE_KEY,
        "license_app_key": GATEWAY_APP_KEY,
        "auth_adapter": config.auth_adapter,
        "credential_profile_key": "synthetic_profile",
        "max_request_bytes": config.max_request_bytes,
        "max_response_bytes": config.max_response_bytes,
    }))
    .bind(actor_snapshot())
    .execute(&fixture.pool)
    .await
    .expect("service version");
    set_status(
        &fixture.pool,
        "mcp_service_versions",
        "service_id",
        SERVICE_ID,
        "published",
    )
    .await;
}

async fn seed_operation(fixture: &Fixture, manifest: &Value) {
    sqlx::query(
        "INSERT INTO public.mcp_operation_versions(operation_id,version,service_id,\
         service_version,manifest,created_by,updated_by) VALUES ($1::uuid,1,$2::uuid,1,$3,$4,$4)",
    )
    .bind(OPERATION)
    .bind(SERVICE_ID)
    .bind(manifest)
    .bind(actor_snapshot())
    .execute(&fixture.pool)
    .await
    .expect("operation version");
    set_status(
        &fixture.pool,
        "mcp_operation_versions",
        "operation_id",
        OPERATION,
        "published",
    )
    .await;
}

/// Move one version row along its lifecycle (content is immutable, status is not).
async fn set_status(pool: &PgPool, table: &str, column: &str, identity: &str, status: &str) {
    let statement =
        format!("UPDATE public.{table} SET status = $2 WHERE {column} = $1::uuid AND version = 1");
    sqlx::query(sqlx::AssertSqlSafe(statement))
        .bind(identity)
        .bind(status)
        .execute(pool)
        .await
        .expect("set version status");
}

async fn seed_source(fixture: &Fixture, config: &Config, owner: &str, base_url: &str) {
    let key = crypto::decode_key(SOURCE_KEY_BYTES).expect("source key");
    let id = uuid(SOURCE_ID);
    let ciphertext = config
        .source_token
        .map(|token| crypto::encrypt(&key, &id, token).expect("seal secret"));
    sqlx::query(
        "INSERT INTO public.mcp_sources(source_id,owner_tenant_id,source_key,base_url,auth,\
         token_ciphertext,token_set_at,idempotency_header,max_request_bytes,max_response_bytes,\
         created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$6,\
         CASE WHEN $6::bytea IS NULL THEN NULL ELSE clock_timestamp() END,$7,$8,$9,$10,$10)",
    )
    .bind(SOURCE_ID)
    .bind(owner)
    .bind(SOURCE_KEY)
    .bind(base_url)
    .bind(&config.source_auth)
    .bind(ciphertext)
    .bind(config.idempotency_header)
    .bind(config.max_request_bytes)
    .bind(config.max_response_bytes)
    .bind(actor_snapshot())
    .execute(&fixture.pool)
    .await
    .expect("insert source");
}

fn profile_manifest(service_app_key: &str) -> Value {
    json!({
        "schema_version": 1,
        "tenant_id": TENANT_A,
        "profile_id": PROFILE,
        "name": "synthetic_profile",
        "gateway": {
            "service": "gateway",
            "alias": "gateway",
            "license_id": LICENCE_ID,
            "app_key": GATEWAY_APP_KEY,
        },
        "services": [{
            "service": SERVICE_KEY,
            "alias": "synthetic",
            "license_id": LICENCE_ID,
            "app_key": service_app_key,
        }],
    })
}

async fn insert_profile(fixture: &Fixture, service_app_key: &str) {
    let manifest = profile_manifest(service_app_key);
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_credential_profiles(\
         tenant_id,profile_id,name,manifest,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,'synthetic_profile',$3,$4,$4)",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .bind(&manifest)
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("insert credential profile");
    for (service_key, alias, app_key) in [
        ("__gateway", "gateway", GATEWAY_APP_KEY),
        (SERVICE_KEY, "synthetic", service_app_key),
    ] {
        sqlx::query(
            "INSERT INTO public.mcp_credential_refs(\
             tenant_id,profile_id,service_key,alias,license_id,app_key) \
             VALUES ($1::uuid,$2::uuid,$3,$4,$5::uuid,$6)",
        )
        .bind(TENANT_A)
        .bind(PROFILE)
        .bind(service_key)
        .bind(alias)
        .bind(LICENCE_ID)
        .bind(app_key)
        .execute(&mut *tx)
        .await
        .expect("insert credential reference");
    }
    tx.commit().await.expect("commit credential profile");
}

// ── the operation manifests ───────────────────────────────────────────────────────────────

/// A read that maps one path, one query, one header and one body value, and projects `/id`.
fn mapped_operation(header_target: &str, idempotency: Option<&str>) -> Value {
    let mut header_fields = vec![json!("x_trace")];
    if header_target != "x_trace" {
        header_fields.push(json!(header_target));
    }
    let mut operation = json!({
        "schema_version": 1,
        "operation_id": OPERATION,
        "version": 1,
        "service": {"id": SERVICE_ID, "version": 1},
        "method": "POST",
        "path_template": "/items/{item_id}",
        "query_fields": ["page"],
        "header_fields": header_fields,
        "mappings": [
            {"location": "path", "target": "item_id", "value": {"source": "input", "pointer": "/item_id"}},
            {"location": "query", "target": "page", "value": {"source": "input", "pointer": "/page"}},
            {"location": "header", "target": header_target, "value": {"source": "input", "pointer": "/trace"}},
            {"location": "body", "target": "/note", "value": {"source": "input", "pointer": "/note"}}
        ],
        "input_schema": {
            "type": "object",
            "properties": {
                "item_id": {"type": "string"},
                "page": {"type": "integer"},
                "trace": {"type": "string"},
                "note": {"type": "string"}
            },
            "required": ["item_id"],
            "additionalProperties": false
        },
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "effect": "read_only",
        "timeout_seconds": 5,
        "pagination_limit": 100,
        "max_response_bytes": 4096
    });
    if let Some(idempotency) = idempotency {
        operation["idempotency"] = json!(idempotency);
    }
    operation
}

/// A plain read of `GET /synthetic` projecting `/id`.
fn simple_operation() -> Value {
    json!({
        "schema_version": 1,
        "operation_id": OPERATION,
        "version": 1,
        "service": {"id": SERVICE_ID, "version": 1},
        "method": "GET",
        "path_template": "/synthetic",
        "query_fields": [],
        "header_fields": [],
        "mappings": [],
        // The calls below pass `arguments()`, so the declared schema has to admit them.
        "input_schema": {
            "type": "object",
            "properties": {
                "item_id": {"type": "string"},
                "page": {"type": "integer"},
                "trace": {"type": "string"},
                "note": {"type": "string"}
            },
            "required": ["item_id"],
            "additionalProperties": false
        },
        "output_schema": {"type": "object"},
        "response_projection": ["/id"],
        "scope_rules": [],
        "effect": "read_only",
        "timeout_seconds": 5,
        "pagination_limit": 100,
        "max_response_bytes": 4096
    })
}

fn effect_of(operation: &Value) -> &'static str {
    match operation["effect"].as_str() {
        Some("writes") => "writes",
        _ => "read_only",
    }
}

fn arguments() -> serde_json::Map<String, Value> {
    json!({"item_id": "abc", "page": 2, "trace": "t-1", "note": "hello"})
        .as_object()
        .cloned()
        .expect("arguments")
}

// ── preflight ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn preflight_accepts_a_valid_run() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    lab.broker
        .preflight(&job.row)
        .await
        .expect("valid authority");
}

#[tokio::test]
async fn preflight_refuses_a_revoked_binding() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    sqlx::query(
        "UPDATE public.mcp_bindings SET revoked = true, revision = revision + 1 \
         WHERE binding_id = $1::uuid",
    )
    .bind(job.run.binding_id.expect("binding").to_string())
    .execute(lab.pool())
    .await
    .expect("revoke");
    assert!(matches!(
        lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

#[tokio::test]
async fn preflight_refuses_a_changed_profile() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    sqlx::query(
        "UPDATE public.mcp_credential_profiles \
         SET manifest = jsonb_set(manifest, '{name}', '\"other\"'), revision = revision + 1 \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .execute(lab.pool())
    .await
    .expect("change profile");
    assert!(matches!(
        lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

#[tokio::test]
async fn preflight_refuses_a_foreign_tenant_credential() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    lab.set_gateway_token(FOREIGN_TOKEN, GATEWAY_APP_KEY);
    assert!(matches!(
        lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

#[tokio::test]
async fn preflight_refuses_an_unpublished_operation_and_service() {
    // The lifecycle is one-way (`disabled → published` is not a transition), so each refusal
    // gets its own freshly seeded fixture instead of walking a status back.
    let operation_lab = Lab::start(Config::new(simple_operation())).await;
    let job = operation_lab.accept().await;
    set_status(
        operation_lab.pool(),
        "mcp_operation_versions",
        "operation_id",
        OPERATION,
        "disabled",
    )
    .await;
    assert!(matches!(
        operation_lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));

    let service_lab = Lab::start(Config::new(simple_operation())).await;
    let job = service_lab.accept().await;
    set_status(
        service_lab.pool(),
        "mcp_service_versions",
        "service_id",
        SERVICE_ID,
        "disabled",
    )
    .await;
    assert!(matches!(
        service_lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

#[tokio::test]
async fn preflight_refuses_a_service_the_tenant_may_not_use() {
    // A platform service behind a stored secret is usable only while it is granted; withdrawing
    // the grant is the reference's "a tenant never reaches a service it is not shared with".
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    sqlx::query("DELETE FROM public.mcp_service_grants WHERE service_id = $1::uuid")
        .bind(SERVICE_ID)
        .execute(lab.pool())
        .await
        .expect("withdraw grant");
    assert!(matches!(
        lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

#[tokio::test]
async fn preflight_refuses_a_mismatched_licence_credential() {
    let mut config = Config::new(simple_operation());
    config.source_auth = json!({"kind": "licence", "app_key": GATEWAY_APP_KEY});
    config.source_token = None;
    let lab = Lab::start(config).await;
    // The profile's service credential resolves, but no longer names the service's application.
    lab.set_credential_app_key("other-app").await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker.preflight(&job.row).await,
        Err(BrokerError::Denied)
    ));
}

// ── the request ──────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_call_sends_exactly_the_mapped_request() {
    let lab = Lab::start(Config::new(mapped_operation("x_trace", None))).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":\"synthetic\",\"extra\":1}");
    let outcome = lab
        .broker
        .call(&job.row, OPERATION, &arguments(), None)
        .await
        .expect("call");
    assert_eq!(outcome, CallOutcome::Value(json!({"id": "synthetic"})));

    let seen = lab.upstream.last();
    assert_eq!(seen.method, "POST");
    assert_eq!(seen.path, "/items/abc");
    assert!(seen.query.contains("page=2"), "{}", seen.query);
    assert_eq!(seen.header("x-trace"), Some("t-1"));
    assert_eq!(seen.header("content-type"), Some("application/json"));
    assert_eq!(
        seen.header("authorization"),
        Some("Bearer source-secret"),
        "the stored credential is the only Authorization"
    );
    assert_eq!(
        serde_json::from_str::<Value>(&seen.body).expect("json body"),
        json!({"note": "hello"})
    );
}

#[tokio::test]
async fn a_mapped_header_cannot_override_the_credential() {
    // The source owns `X-Api-Key`; the operation maps the same header under another case.
    let mut config = Config::new(mapped_operation("x_api_key", None));
    config.source_auth = json!({"kind": "static_header", "header": "X-Api-Key"});
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    assert!(
        lab.upstream.requests().is_empty(),
        "a refused call sent bytes"
    );
    assert!(
        lab.calls(&job).await.is_empty(),
        "the intent was not journalled"
    );
}

#[tokio::test]
async fn the_idempotency_header_is_only_sent_when_the_operation_declares_it() {
    // Declared: the key is the caller's, and it is the only source of the header.
    let mut config = Config::new(simple_operation());
    config.idempotency_header = Some("Idempotency-Key");
    let mut operation = config.operation.clone();
    operation["idempotency"] = json!("downstream_key");
    config.operation = operation;
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    lab.broker
        .call(&job.row, OPERATION, &arguments(), Some("key-1"))
        .await
        .expect("the call carries the key");
    assert_eq!(
        lab.upstream.last().header("idempotency-key"),
        Some("key-1"),
        "the declared header carries the caller's key"
    );
    lab.broker
        .call(&job.row, OPERATION, &arguments(), None)
        .await
        .expect("a keyless read is allowed");
    assert!(
        lab.upstream.last().header("idempotency-key").is_none(),
        "no key was supplied"
    );

    // Undeclared by the operation: a key is refused before any I/O.
    let mut config = Config::new(simple_operation());
    config.idempotency_header = Some("Idempotency-Key");
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), Some("key-1"))
            .await,
        Err(BrokerError::Denied)
    ));
    assert!(lab.upstream.requests().is_empty());
}

#[tokio::test]
async fn a_writes_operation_with_retries_and_no_key_is_refused() {
    let mut operation = simple_operation();
    operation["effect"] = json!("writes");
    operation["max_retries"] = json!(1);
    operation["idempotency"] = json!("downstream_key");
    let mut config = Config::new(operation);
    config.idempotency_header = Some("Idempotency-Key");
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    assert!(lab.upstream.requests().is_empty());

    // The same operation with the caller's key is allowed through.
    lab.upstream.push(200, "{\"id\":\"synthetic\"}");
    lab.broker
        .call(&job.row, OPERATION, &arguments(), Some("key-1"))
        .await
        .expect("a keyed write is allowed");
}

// ── statuses and failures ────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_expected_status_is_a_result_and_a_server_error_denies() {
    let mut operation = simple_operation();
    operation["expected_error_statuses"] = json!([404]);
    let lab = Lab::start(Config::new(operation)).await;
    let job = lab.accept().await;

    lab.upstream.push(404, "{\"id\":\"missing\"}");
    let outcome = lab
        .broker
        .call(&job.row, OPERATION, &arguments(), None)
        .await
        .expect("an expected status is a result");
    assert_eq!(
        outcome,
        CallOutcome::Expected {
            status: 404,
            body: json!({"id": "missing"}),
        }
    );
    let rows = lab.calls(&job).await;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].1, "failed");
    assert_eq!(rows[0].2.as_deref(), Some("status"));
    assert_eq!(rows[0].3, Some(404));

    lab.upstream.push(500, "{\"id\":\"boom\"}");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].1, "failed");
    assert_eq!(rows[1].2.as_deref(), Some("status"));
    assert_eq!(rows[1].3, Some(500));
    assert_eq!(lab.permits().await, 0, "the permit was released");
}

#[tokio::test]
async fn a_transport_failure_is_outcome_unknown_for_a_write_and_denied_for_a_read() {
    // A write: the request may have been delivered, so the run must not be told it failed.
    let mut operation = simple_operation();
    operation["effect"] = json!("writes");
    let mut config = Config::new(operation);
    config.base_url = Some(DEAD_BASE);
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert_eq!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::OutcomeUnknown)
    );
    let rows = lab.calls(&job).await;
    assert_eq!(rows[0].1, "outcome_unknown");
    assert_eq!(rows[0].2.as_deref(), Some("transport"));
    assert_eq!(lab.permits().await, 0);

    // A read: a transport failure is a plain denial, retried once, then the run fails.
    let mut operation = simple_operation();
    operation["max_retries"] = json!(1);
    let mut config = Config::new(operation);
    config.base_url = Some(DEAD_BASE);
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows.len(), 2, "one intent per attempt: {rows:?}");
    assert!(rows.iter().all(|row| row.1 == "failed"));
    assert!(rows.iter().all(|row| row.2.as_deref() == Some("transport")));
    assert_eq!(lab.permits().await, 0, "every permit was released");
}

// ── framing ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn an_oversized_request_response_and_frame_are_refused() {
    // The request bound refuses before any I/O.
    let mut config = Config::new(mapped_operation("x_trace", None));
    config.max_request_bytes = 4;
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    assert!(
        lab.upstream.requests().is_empty(),
        "an oversized request was sent"
    );

    // The response bound refuses a body larger than the service allows.
    let mut config = Config::new(simple_operation());
    config.max_response_bytes = 8;
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":\"a-much-longer-body\"}");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows[0].2.as_deref(), Some("too_large"));

    // The frame bound refuses a projected result that does not fit the runner's frame.
    let mut config = Config::new(simple_operation());
    config.limits.frame_bytes = 8;
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":\"synthetic\"}");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows[0].2.as_deref(), Some("too_large"));
}

#[tokio::test]
async fn an_upstream_echo_of_a_credential_is_refused() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":\"source-secret\"}");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows[0].1, "failed", "an echoed secret is never returned");
}

#[tokio::test]
async fn a_result_that_breaks_the_output_schema_is_refused() {
    let mut operation = simple_operation();
    operation["output_schema"] = json!({
        "type": "object",
        "properties": {"id": {"type": "string"}},
        "required": ["id"],
        "additionalProperties": false
    });
    let lab = Lab::start(Config::new(operation)).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":5}");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    let rows = lab.calls(&job).await;
    assert_eq!(rows[0].2.as_deref(), Some("schema_mismatch"));
}

// ── journalling, permits and limits ──────────────────────────────────────────────────────

#[tokio::test]
async fn the_intent_is_committed_before_io_and_finalized_once() {
    let lab = Lab::start(Config::new(simple_operation())).await;
    let job = lab.accept().await;
    lab.upstream.push(200, "{\"id\":\"synthetic\"}");
    lab.broker
        .call(&job.row, OPERATION, &arguments(), None)
        .await
        .expect("call");

    let rows = lab.calls(&job).await;
    assert_eq!(rows.len(), 1, "exactly one intent, exactly one outcome");
    assert_eq!(rows[0].0, 1);
    assert_eq!(rows[0].1, "succeeded");
    assert_eq!(rows[0].3, Some(200));
    let (status, reason, method) = lab.call_row(&job, 1).await;
    assert_eq!(status, "succeeded");
    assert!(reason.is_none());
    assert_eq!(method.as_deref(), Some("GET"));
    let api_calls: i32 =
        sqlx::query_scalar("SELECT api_calls FROM public.mcp_runs WHERE run_id = $1::uuid")
            .bind(job.run.run_id.to_string())
            .fetch_one(lab.pool())
            .await
            .expect("api calls");
    assert_eq!(api_calls, 1);
    assert_eq!(lab.permits().await, 0, "the permit was released");
}

#[tokio::test]
async fn a_denial_releases_the_permit_and_emits_the_broker_denied_event() {
    // A permit held by a foreign run exhausts the global concurrency ceiling.
    let mut config = Config::new(simple_operation());
    config.global_concurrency = Some(1);
    let lab = Lab::start(config).await;
    let job = lab.accept().await;
    // The permit table has a `(tenant_id, run_id)` FK, so the ceiling is exhausted with a second
    // permit on this run's own fence rather than an invented id.
    sqlx::query(
        "INSERT INTO public.mcp_api_permits(permit_id,tenant_id,run_id,fence,service_id,expires_at) \
         VALUES (uuidv7(),$1::uuid,$3::uuid,1,$2::uuid,clock_timestamp() + interval '1 minute')",
    )
    .bind(TENANT_A)
    .bind(SERVICE_ID)
    .bind(job.row.run.run_id.to_string())
    .execute(lab.pool())
    .await
    .expect("held permit");
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    assert!(
        lab.calls(&job).await.is_empty(),
        "a refused call journalled an intent"
    );
    assert!(lab.events(&job).await.contains(&"broker_denied".to_owned()));

    // Freed: the call succeeds, and its own permit is released again.
    sqlx::query("DELETE FROM public.mcp_api_permits")
        .execute(lab.pool())
        .await
        .expect("free the ceiling");
    lab.upstream.push(200, "{\"id\":\"synthetic\"}");
    lab.broker
        .call(&job.row, OPERATION, &arguments(), None)
        .await
        .expect("call");
    assert_eq!(lab.permits().await, 0);
}

#[tokio::test]
async fn the_limiter_and_the_database_permit_both_deny_and_are_released() {
    // A tenant-owned source: the pinned transport refuses the unresolvable host, and every
    // refusal still releases the limiter slot and the permit.
    let mut config = Config::new(simple_operation());
    config.tenant_source = true;
    config.limiter = Some((2, 1));
    let lab = Lab::start(config).await;
    let job = lab.accept().await;

    for _ in 0..2 {
        assert!(
            lab.broker
                .call(&job.row, OPERATION, &arguments(), None)
                .await
                .is_err(),
            "the pinned transport cannot reach the fixture host"
        );
        assert_eq!(lab.permits().await, 0, "the permit was released");
    }
    let rows = lab.calls(&job).await;
    assert_eq!(
        rows.len(),
        2,
        "the slot was released after each refusal: {rows:?}"
    );

    // The per-minute allowance is spent: the limiter refuses before any intent is journalled.
    assert!(matches!(
        lab.broker
            .call(&job.row, OPERATION, &arguments(), None)
            .await,
        Err(BrokerError::Denied)
    ));
    assert_eq!(
        lab.calls(&job).await.len(),
        2,
        "a limiter refusal sent bytes or journalled an intent"
    );
    assert_eq!(lab.permits().await, 0);
}
