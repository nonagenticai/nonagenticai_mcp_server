//! `POST /mcp/internal/tenants/{t}/bindings/ensure` against the real router, a real Postgres 18,
//! a stub Keycloak JWKS (tokens signed for real with RS256) and a stub licence introspection.
//!
//! Each test fails if the behaviour it covers is removed: a first ensure issues the only token
//! and records the profile/binding/ensure/access event; a re-ensure reports the token was
//! already issued and never returns it again; an explicit rotate issues a new one; an unknown
//! product, a licence for another tenant and the platform tenant are refused; a toolkit the
//! platform has not published (or whose backend licence cannot be established) is skipped with
//! its reason; and two concurrent ensures serialize on the ensure row, so only one token is ever
//! issued.
//!
//! Server selection mirrors `tests/routes_bindings.rs`: `TEST_DATABASE_URL`, else
//! `DATABASE_URL` (a URL whose user may CREATE DATABASE), else an ephemeral `postgres:18`
//! container started here with docker and removed afterwards, else FAIL (never skip).
//! `TEST_PG_REGISTRY` may name a registry mirror. Each test gets its own fresh database.

use std::process::Command;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use axum::Json;
use axum::Router;
use axum::body::Body;
use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, Request, StatusCode, header};
use axum::routing::get;
use base64::Engine as _;
use http_body_util::BodyExt;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, PgConnection, PgPool, Row};
use tokio::sync::Mutex;
use tower::ServiceExt;

use mcp_server_rs::auth::{
    Auth, AuthConfig, AuthError, BoxFuture, KeycloakSettings, KeycloakVerifier, LicenceAuthority,
    LicenseIdentity, Principal, Rfc4122Uuid, SubjectKind,
};
use mcp_server_rs::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use mcp_server_rs::catalog::lifecycle::VersionStatus;
use mcp_server_rs::catalog::toolkit_models::ToolkitManifest;
use mcp_server_rs::config::{BindingEnsureSettings, ExecutionSettings, SourceSettings};
use mcp_server_rs::routes::internal::InternalRuntime;
use mcp_server_rs::storage::bindings;
use mcp_server_rs::storage::bindings_ensure::{
    BindingEnsureService, EnsureError, LicenceLookup, LicenceLookupError, RebindEntry, actor_for,
    rebind_failed_report,
};
use mcp_server_rs::toolkits::resolver::SelectionResolver;
use mcp_server_rs::toolkits::service::ToolkitService;
use mcp_server_rs::{AppState, app_with_internal, db};

const TENANT_A: &str = "10000000-0000-7000-8000-000000000001";
const TENANT_B: &str = "10000000-0000-7000-8000-000000000002";
const TENANT_PLATFORM: &str = "01900000-0000-7000-8000-00000000f001";
const LICENCE_ID: &str = "30000000-0000-4000-8000-000000000001";
const LICENCE_B: &str = "30000000-0000-4000-8000-000000000002";
const PLATFORM_LICENCE: &str = "30000000-0000-4000-8000-000000000003";
const BACKEND_LICENCE: &str = "30000000-0000-4000-8000-0000000000ab";
const SERVICE_ID: &str = "30000000-0000-7000-8000-0000000000ff";
const OPERATION_ALPHA: &str = "40000000-0000-7000-8000-000000000001";
const TOOL_FR: &str = "20000000-0000-7000-8000-000000000001";
const TOOLKIT_FR: &str = "01900000-0000-7000-8000-000000000001";
const GATEWAY_APP_KEY: &str = "synthetic";
const TENANT_TOKEN: &str = "tenant-a-mcp-licence-token";
const TENANT_B_TOKEN: &str = "tenant-b-mcp-licence-token";
const PLATFORM_TOKEN: &str = "platform-mcp-licence-token";
const CLIENT: &str = "carebus-tool-executor";
const OTHER_CLIENT: &str = "portal-frontend";
const AUDIENCE: &str = "nonagenticai-mcp";
const REALM: &str = "portal";
const KID: &str = "test-kid-1";
const JWKS_USER_AGENT: &str = "nonagenticai-mcp-server (jwks)";
const ENSURE_PATH: &str = "/mcp/internal/tenants";

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
    jwks: Stub,
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
        static SEQUENCE: AtomicUsize = AtomicUsize::new(0);
        let sequence = SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let name = format!(
            "mcp_bindings_ensure_{}_{nanos}_{sequence}",
            std::process::id()
        );
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
            jwks: Stub::start().await,
        }
    }

    fn state(&self) -> AppState {
        AppState {
            pool: self.pool.clone(),
            execution_enabled: false,
            license_app_key: Some(GATEWAY_APP_KEY.to_owned()),
            approved_runner_images: Vec::new(),
            platform_tenant_id: Rfc4122Uuid::parse(TENANT_PLATFORM).expect("static uuid"),
            catalog_page_size: 10,
            platform: None,
            sources: SourceSettings::default(),
            execution: ExecutionSettings::default(),
        }
    }

    fn licences(&self) -> Arc<dyn LicenceAuthority> {
        Arc::new(TestLicence)
    }

    /// The application with the internal runtime: a real service, the stub-JWKS verifier and the
    /// supplied product table/minter. `with_keycloak = false` models an unconfigured verifier.
    fn app(
        &self,
        settings: &BindingEnsureSettings,
        minter: Option<Arc<dyn LicenceLookup>>,
        with_keycloak: bool,
    ) -> Router {
        mcp_server_rs::install_crypto_provider();
        let licences = self.licences();
        let service = BindingEnsureService::new(
            self.pool.clone(),
            SelectionResolver {
                platform_tenant_id: authority(TENANT_PLATFORM),
            },
            Some(GATEWAY_APP_KEY.to_owned()),
            licences.clone(),
            minter,
            settings,
            authority(TENANT_PLATFORM),
        );
        let keycloak = if with_keycloak {
            Some(Arc::new(self.jwks.verifier()))
        } else {
            None
        };
        let runtime = InternalRuntime::new(service, keycloak, 262_144);
        let mut auth = Auth::from_config(&AuthConfig::default()).expect("valid auth config");
        auth.licences = licences;
        app_with_internal(self.state(), auth, runtime)
    }

    fn toolkit_service(&self) -> ToolkitService {
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
            jwks,
        } = self;
        jwks.stop();
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

// ── the stub Keycloak JWKS ────────────────────────────────────────────────────────────────

const PRIVATE_KEY_DER_BASE64: &str = concat!(
    "MIIEpAIBAAKCAQEAqAWN2ORmbmbQYq+aagWIw0dmjMAw8164FJZs6SE9EKr0UOJURKbAPSTtN4XP",
    "Ib6OcSSLrosz6hyZoCSVy+uSaR2lYBguwVbSzt9mOtehb37jtGLYzLONCTDOQBSpV3sSo3EJR+Io",
    "xzm2CgQf5G2H+MHUzapzPu/cyNDmWc7zfE+unVw1m6zcvkJsxkEUshxc8xaqjPCRGqP3xUdc4t9g",
    "m1QlIl38HAbaYuw89KmvuV+XJKSMw8DREAg/V8Hq6Wx35pUmFg3OaLBasyZykERHl2rENbZcIYnj",
    "yvHLgJI8sNm+b/fXnluyUbSRQws/xc9vEs7m/I3tv/ScLYXRHKRh2wIDAQABAoIBAA0BNQvrDbSQ",
    "16MzxUdce0vmDF1riL5lf+j0BaT7sh7GpJdYFT6lC28QGx43iKMrfRnrwrX1R0ThBtD60+9PIetp",
    "5IFuDbxgLHvflamLRA79qsEs/2vEn+9srCIQl1TSjUxCNP4v1okpAdp/nDpRcftCgWaTwUzHQvb2",
    "GEYuOvFNly1ua60g0h2RsVvp5Ktx1rwIYdIo28WVL8k+s0qjkHHT6iocfALAEVMW2rbzG649WXrg",
    "iWp67gVVwDPS7npPrRepqlfdSIwRZTTVuosBEM8N/oPNVeBRfZPMDEGurJDhfPRabTIiQcUGs27J",
    "mduGi0okOUvWF213rVFWFcUkVBkCgYEA7CszJ6+71qpY+huAti+0LEdPf1y7Z7UM3EicE+h2IwhB",
    "MqoCboJqB3ULexVdt8/7n/9PfkDKIfWYh3IbeBq4FYV+HMLjRvha0ExXQpEhylqqEDPRMIySEpS1",
    "IDkayi/iOR1UdZ6G6hA9T5AZvrS1utd+Nd2a1RfLJGgCPfP0UFMCgYEAtiFud80uZ/DydcpoUru2",
    "lVyP8EowkpNXf7HwX8xD48wI1CMvXK87+L9Jab1KRWnOKihifd5rd6aMNK0LF5Lq0bHtUvtR351A",
    "9gNw0W7D0f4bPVd4uvRPKGGVNnvuiiusQXnvCD0TpTD216QAyelJNDWv9Co1rQFVgyBPqbTvF1kC",
    "gYBOtptHJ/AwPPiI66+7iSzA8UeSyIKBrztJFD5I+FqflHm+fCFxWbAjKiSYcmeZAw33pq2FA+0a",
    "4nNi+WokXqtqKOL+jQoZNl92O2t9+UdM3Wj/G3Yme0OYQ84WnlHKf6kjph3nUd3fl2gH45xhDnPf",
    "gUFEjMa1LUf8q1nL8kpElwKBgQCZRHMBEELgJ4zygR3fmaYh9V4P2W8cui+k/yoIhA4Rsg8v7lga",
    "CEFQqDDwceIBnfNn2Mphn/4SF67fWUv/T5yaUMAl1+bjZiNXpDeZlzvlCJEFwwmPUq8WjWATFKH9",
    "1pjEFQeJiFRy7Eyd1Z7wS4hWDmP+9lJrP7clfNhtOR0HKQKBgQCdgoc81OVJBeJ9rfyPkEydH1G4",
    "bwXT7RKdpEmoWUnGpqpW9V2s+8XkVWsebNvKn67/lIJK4LMiO/+w9gKf5B1WH1O3eZ6+VqXt2Fxx",
    "p+36bVoz90WYw4PkUb5/M/JJGg0lo6UyN7hawB0IokRYmfCYjMeP9MKkXcKAjnKH1AwCmA==",
);
const JWKS_N: &str = "qAWN2ORmbmbQYq-aagWIw0dmjMAw8164FJZs6SE9EKr0UOJURKbAPSTtN4XPIb6OcSSLrosz6hyZoCSVy-uSaR2lYBguwVbSzt9mOtehb37jtGLYzLONCTDOQBSpV3sSo3EJR-Ioxzm2CgQf5G2H-MHUzapzPu_cyNDmWc7zfE-unVw1m6zcvkJsxkEUshxc8xaqjPCRGqP3xUdc4t9gm1QlIl38HAbaYuw89KmvuV-XJKSMw8DREAg_V8Hq6Wx35pUmFg3OaLBasyZykERHl2rENbZcIYnjyvHLgJI8sNm-b_fXnluyUbSRQws_xc9vEs7m_I3tv_ScLYXRHKRh2w";
const JWKS_E: &str = "AQAB";

#[derive(Clone)]
struct StubState {
    fetches: Arc<AtomicUsize>,
    user_agent: Arc<Mutex<Option<String>>>,
    document: Arc<Mutex<Value>>,
}

async fn certs(State(state): State<StubState>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    state.fetches.fetch_add(1, Ordering::SeqCst);
    *state.user_agent.lock().await = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let document = state.document.lock().await.clone();
    (StatusCode::OK, Json(document))
}

struct Stub {
    base: String,
    state: StubState,
    task: tokio::task::JoinHandle<()>,
}

impl Stub {
    async fn start() -> Self {
        let state = StubState {
            fetches: Arc::new(AtomicUsize::new(0)),
            user_agent: Arc::new(Mutex::new(None)),
            document: Arc::new(Mutex::new(jwks())),
        };
        let router = Router::new()
            .route("/realms/{realm}/protocol/openid-connect/certs", get(certs))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind JWKS server");
        let base = format!("http://{}", listener.local_addr().expect("JWKS address"));
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self { base, state, task }
    }

    fn settings(&self) -> KeycloakSettings {
        KeycloakSettings {
            url: self.base.clone(),
            realm: REALM.to_owned(),
            audiences: vec![AUDIENCE.to_owned()],
            allowed_clients: vec![CLIENT.to_owned()],
        }
    }

    fn verifier(&self) -> KeycloakVerifier {
        KeycloakVerifier::from_settings(&self.settings()).expect("verifier")
    }

    fn issuer(&self) -> String {
        format!("{}/realms/{REALM}", self.base)
    }

    fn fetches(&self) -> usize {
        self.state.fetches.load(Ordering::SeqCst)
    }

    async fn user_agent(&self) -> Option<String> {
        self.state.user_agent.lock().await.clone()
    }

    fn stop(self) {
        self.task.abort();
    }
}

fn jwks() -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": KID,
            "n": JWKS_N,
            "e": JWKS_E,
        }]
    })
}

fn signing_key() -> EncodingKey {
    let der = base64::engine::general_purpose::STANDARD
        .decode(PRIVATE_KEY_DER_BASE64)
        .expect("test key DER");
    EncodingKey::from_rsa_der(&der)
}

/// A real RS256 service token for the stub realm, issued to `azp`.
fn service_token(stub: &Stub, azp: &str) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(KID.to_owned());
    let now = jsonwebtoken::get_current_timestamp();
    let claims = json!({
        "iss": stub.issuer(),
        "aud": [AUDIENCE, "account"],
        "azp": azp,
        "sub": "service-account-sub",
        "iat": now,
        "exp": now + 300,
    });
    jsonwebtoken::encode(&header, &claims, &signing_key()).expect("sign RS256")
}

// ── licence introspection and minter stubs ────────────────────────────────────────────────

struct TestLicence;

fn identity(tenant: &str, licence: &str) -> LicenseIdentity {
    LicenseIdentity {
        tenant_id: Rfc4122Uuid::parse(tenant).expect("tenant uuid"),
        license_id: Rfc4122Uuid::parse(licence).expect("licence uuid"),
        subject: "svc:tenant:mcp".to_owned(),
        subject_kind: Some(SubjectKind::Tenant),
    }
}

impl LicenceAuthority for TestLicence {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            match token {
                TENANT_TOKEN => Ok(identity(TENANT_A, LICENCE_ID)),
                TENANT_B_TOKEN => Ok(identity(TENANT_B, LICENCE_B)),
                PLATFORM_TOKEN => Ok(identity(TENANT_PLATFORM, PLATFORM_LICENCE)),
                _ => Err(AuthError::Unauthorized),
            }
        })
    }
}

struct FakeMinter {
    deny: bool,
}

impl FakeMinter {
    fn granting() -> Arc<dyn LicenceLookup> {
        Arc::new(Self { deny: false })
    }

    fn denying() -> Arc<dyn LicenceLookup> {
        Arc::new(Self { deny: true })
    }
}

impl LicenceLookup for FakeMinter {
    fn licence_id<'a>(
        &'a self,
        _tenant: &'a Rfc4122Uuid,
        _app: &'a str,
        _bundle: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Rfc4122Uuid, LicenceLookupError>> {
        let result = if self.deny {
            Err(LicenceLookupError::Denied)
        } else {
            Ok(Rfc4122Uuid::parse(BACKEND_LICENCE).expect("backend licence"))
        };
        Box::pin(async move { result })
    }
}

// ── requests and fixtures ─────────────────────────────────────────────────────────────────

fn settings(products: &[(&str, &[&str])]) -> BindingEnsureSettings {
    BindingEnsureSettings {
        products: products
            .iter()
            .map(|(product, toolkits)| {
                (
                    (*product).to_owned(),
                    toolkits.iter().map(|name| (*name).to_owned()).collect(),
                )
            })
            .collect(),
        bundles: products
            .iter()
            .map(|(product, _)| ((*product).to_owned(), (*product).to_owned()))
            .collect(),
        ..BindingEnsureSettings::default()
    }
}

fn default_settings() -> BindingEnsureSettings {
    settings(&[("agent", &["fr"])])
}

fn ensure_body(product: &str, licence_id: &str, licence_token: &str, rotate: bool) -> Value {
    json!({
        "product": product,
        "licence_id": licence_id,
        "licence_token": licence_token,
        "rotate": rotate,
    })
}

async fn post_ensure(
    app: &Router,
    tenant: &str,
    token: &str,
    body: Value,
) -> (StatusCode, HeaderMap, Value) {
    let request = Request::post(format!("{ENSURE_PATH}/{tenant}/bindings/ensure"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("request");
    send(app, request).await
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

fn actor_snapshot() -> Value {
    json!({"subject": "agent-09", "license_id": LICENCE_ID})
}

fn platform_principal() -> Principal {
    Principal {
        tenant_id: Rfc4122Uuid::parse(TENANT_PLATFORM).expect("platform uuid"),
        license_id: Rfc4122Uuid::parse(LICENCE_ID).expect("licence uuid"),
        subject: "agent-09".to_owned(),
        binding_id: None,
        binding_revision: None,
        management: true,
        platform: true,
    }
}

/// A published service and operation, the platform's published tool, and the platform toolkit
/// `fr` selecting it: exactly what the product table names.
async fn seed_platform_toolkit(fixture: &Fixture) {
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
    insert_published_tool(fixture).await;
    let service = fixture.toolkit_service();
    let operator = platform_principal();
    let drafted = service
        .write(&operator, &toolkit_manifest(), None)
        .await
        .expect("create the platform toolkit");
    service
        .transition(
            &operator,
            &uuid7(TOOLKIT_FR),
            version(1),
            VersionStatus::Published,
            drafted.revision,
        )
        .await
        .expect("publish the platform toolkit");
}

fn tool_manifest() -> Value {
    json!({
        "schema_version": 1,
        "tool_id": TOOL_FR,
        "tenant_id": TENANT_PLATFORM,
        "version": 1,
        "public_name": "fr_tool",
        "operation": "synthetic.fr_tool",
        "description": "Synthetic platform fixture",
        "runtime": "n8n_workflow",
        "target": {"kind": "n8n_workflow", "webhook_path": "synthetic/hook"},
        "input_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "result_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "context_schema": {"type": "object", "properties": {}, "additionalProperties": false},
        "package_sha256": "a".repeat(64),
        "effect": "read_only",
        "allowed_operations": [{"id": OPERATION_ALPHA, "version": 1}],
    })
}

fn toolkit_manifest() -> ToolkitManifest {
    serde_json::from_value(json!({
        "schema_version": 1,
        "toolkit_id": TOOLKIT_FR,
        "tenant_id": TENANT_PLATFORM,
        "version": 1,
        "name": "fr",
        "description": "Synthetic platform toolkit",
        "tools": [{"tool": {"id": TOOL_FR, "version": 1, "tenant_id": TENANT_PLATFORM}}],
    }))
    .expect("valid toolkit manifest")
}

/// One published platform tool, written straight to the snapshot tables (the authoring path
/// refuses a reserved public name; the resolver must still see a real published row).
async fn insert_published_tool(fixture: &Fixture) {
    let manifest = tool_manifest();
    let mut tx = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_tools(tenant_id,tool_id,public_name,created_by) \
         VALUES ($1::uuid,$2::uuid,'fr_tool',$3)",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOL_FR)
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("tool identity");
    sqlx::query(
        "INSERT INTO public.mcp_tool_versions(tenant_id,tool_id,version,manifest,\
         package_sha256,file_count,operation_count,status,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,1,$3,$4,1,1,'draft',$5,$5)",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOL_FR)
    .bind(&manifest)
    .bind("a".repeat(64))
    .bind(actor_snapshot())
    .execute(&mut *tx)
    .await
    .expect("tool version");
    sqlx::query(
        "INSERT INTO public.mcp_tool_version_files(tenant_id,tool_id,version,path,content) \
         VALUES ($1::uuid,$2::uuid,1,'package/main.py','print(''synthetic'')')",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOL_FR)
    .execute(&mut *tx)
    .await
    .expect("tool package file");
    sqlx::query(
        "INSERT INTO public.mcp_tool_version_operations(tenant_id,tool_id,version,\
         operation_id,operation_version) VALUES ($1::uuid,$2::uuid,1,$3::uuid,1)",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOL_FR)
    .bind(OPERATION_ALPHA)
    .execute(&mut *tx)
    .await
    .expect("tool operation reference");
    sqlx::query(
        "UPDATE public.mcp_tool_versions SET status='published' \
         WHERE tenant_id = $1::uuid AND tool_id = $2::uuid AND version = 1",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOL_FR)
    .execute(&mut *tx)
    .await
    .expect("publish tool version");
    tx.commit().await.expect("commit tool version");
}

// ── database assertions ───────────────────────────────────────────────────────────────────

async fn ensure_row(fixture: &Fixture, tenant: &str, product: &str) -> Value {
    let row = sqlx::query(
        "SELECT ensure_id::text AS ensure_id, revision, binding_id::text AS binding_id, \
         gateway_license_id::text AS gateway_license_id, \
         credential_profile_id::text AS credential_profile_id, toolkits, skipped, \
         (token_issued_at IS NOT NULL) AS issued FROM public.mcp_binding_ensures \
         WHERE tenant_id=$1::uuid AND product=$2",
    )
    .bind(tenant)
    .bind(product)
    .fetch_one(&fixture.pool)
    .await
    .expect("ensure row");
    json!({
        "ensure_id": row.try_get::<String, _>("ensure_id").expect("ensure id"),
        "revision": row.try_get::<i64, _>("revision").expect("revision"),
        "binding_id": row.try_get::<Option<String>, _>("binding_id").expect("binding id"),
        "gateway_license_id": row.try_get::<Option<String>, _>("gateway_license_id").expect("gateway"),
        "credential_profile_id": row.try_get::<Option<String>, _>("credential_profile_id").expect("profile"),
        "toolkits": row.try_get::<Value, _>("toolkits").expect("toolkits"),
        "skipped": row.try_get::<Value, _>("skipped").expect("skipped"),
        "issued": row.try_get::<bool, _>("issued").expect("issued"),
    })
}

async fn profile(fixture: &Fixture, tenant: &str, name: &str) -> Value {
    let row = sqlx::query(
        "SELECT profile_id::text AS profile_id, manifest FROM public.mcp_credential_profiles \
         WHERE tenant_id=$1::uuid AND name=$2",
    )
    .bind(tenant)
    .bind(name)
    .fetch_one(&fixture.pool)
    .await
    .expect("credential profile");
    json!({
        "profile_id": row.try_get::<String, _>("profile_id").expect("profile id"),
        "manifest": row.try_get::<Value, _>("manifest").expect("manifest"),
    })
}

async fn service_references(fixture: &Fixture, tenant: &str, profile_id: &str) -> Vec<Value> {
    let rows = sqlx::query(
        "SELECT service_key, alias, license_id::text AS license_id, app_key \
         FROM public.mcp_credential_refs WHERE tenant_id=$1::uuid AND profile_id=$2::uuid \
         ORDER BY service_key",
    )
    .bind(tenant)
    .bind(profile_id)
    .fetch_all(&fixture.pool)
    .await
    .expect("credential references");
    rows.into_iter()
        .map(|row| {
            json!({
                "service_key": row.try_get::<String, _>("service_key").expect("service"),
                "alias": row.try_get::<String, _>("alias").expect("alias"),
                "license_id": row.try_get::<String, _>("license_id").expect("licence"),
                "app_key": row.try_get::<String, _>("app_key").expect("app key"),
            })
        })
        .collect()
}

async fn binding_row(fixture: &Fixture, tenant: &str, binding_id: &str) -> Value {
    let row = sqlx::query(
        "SELECT gateway_license_id::text AS gateway_license_id, \
         credential_profile_id::text AS credential_profile_id, token_sha256, revoked \
         FROM public.mcp_bindings WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(tenant)
    .bind(binding_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("binding row");
    json!({
        "gateway_license_id": row.try_get::<String, _>("gateway_license_id").expect("gateway"),
        "credential_profile_id": row.try_get::<String, _>("credential_profile_id").expect("profile"),
        "token_sha256": row.try_get::<String, _>("token_sha256").expect("digest"),
        "revoked": row.try_get::<bool, _>("revoked").expect("revoked"),
    })
}

async fn ensure_events(fixture: &Fixture, tenant: &str, ensure_id: &str) -> i64 {
    sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_access_events \
         WHERE tenant_id=$1::uuid AND entity_id=$2::uuid AND action='binding.ensured'",
    )
    .bind(tenant)
    .bind(ensure_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("access events")
}

// ── the tests ────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn the_first_ensure_issues_the_only_token_and_records_everything() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    let (status, headers, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_store(&headers);
    assert_eq!(body["status"], "created");
    assert_eq!(body["tenant_id"], TENANT_A);
    assert_eq!(body["product"], "agent");
    assert_eq!(body["gateway_license_id"], LICENCE_ID);
    assert_eq!(body["binding_revision"], 1);
    assert_eq!(body["token_already_issued"], false);
    let issued = body["token"]
        .as_str()
        .expect("a create issues a token")
        .to_owned();
    assert_eq!(issued.len(), 43, "secrets.token_urlsafe(32)");
    assert_eq!(
        body["toolkits"],
        json!([{
            "name": "fr",
            "tenant_id": TENANT_PLATFORM,
            "toolkit_id": TOOLKIT_FR,
            "version": 1,
        }])
    );
    assert_eq!(body["skipped"], json!([]));
    assert!(body["expires_at"].as_str().is_some());
    let binding_id = body["binding_id"].as_str().expect("binding id").to_owned();
    let ensure_id = body["ensure_id"].as_str().expect("ensure id").to_owned();

    // The profile: the gateway is the tenant's mcp licence, the service reference is the
    // minted backend licence, in the product's bundle.
    let profile = profile(&fixture, TENANT_A, "ensure_agent").await;
    assert_eq!(profile["manifest"]["name"], "ensure_agent");
    assert_eq!(profile["manifest"]["gateway"]["service"], "gateway");
    assert_eq!(profile["manifest"]["gateway"]["license_id"], LICENCE_ID);
    assert_eq!(profile["manifest"]["gateway"]["app_key"], GATEWAY_APP_KEY);
    assert_eq!(
        profile["manifest"]["services"][0]["service"],
        "synthetic_service"
    );
    assert_eq!(
        profile["manifest"]["services"][0]["license_id"],
        BACKEND_LICENCE
    );
    assert_eq!(
        profile["manifest"]["services"][0]["app_key"],
        GATEWAY_APP_KEY
    );
    assert_eq!(profile["manifest"]["services"][0]["bundle"], "agent");
    let profile_id = profile["profile_id"]
        .as_str()
        .expect("profile id")
        .to_owned();
    let references = service_references(&fixture, TENANT_A, &profile_id).await;
    assert_eq!(
        references,
        vec![
            json!({
                "service_key": "__gateway",
                "alias": "gateway",
                "license_id": LICENCE_ID,
                "app_key": GATEWAY_APP_KEY,
            }),
            json!({
                "service_key": "synthetic_service",
                "alias": "synthetic_service",
                "license_id": BACKEND_LICENCE,
                "app_key": GATEWAY_APP_KEY,
            }),
        ]
    );

    // The binding: the tenant's mcp licence is the gateway, and only the token's digest is
    // stored.
    let binding = binding_row(&fixture, TENANT_A, &binding_id).await;
    assert_eq!(binding["gateway_license_id"], LICENCE_ID);
    assert_eq!(binding["credential_profile_id"], profile_id);
    assert_eq!(binding["token_sha256"], bindings::digest_token(&issued));
    assert_eq!(binding["revoked"], false);

    // The ensure row and its one access event.
    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["ensure_id"], ensure_id);
    assert_eq!(row["binding_id"], binding_id);
    assert_eq!(row["credential_profile_id"], profile_id);
    assert_eq!(row["gateway_license_id"], LICENCE_ID);
    assert_eq!(row["issued"], true);
    // The insert starts at revision 1 and every ensure advances it once.
    assert_eq!(row["revision"], 2);
    assert_eq!(ensure_events(&fixture, TENANT_A, &ensure_id).await, 1);

    // The stub JWKS was consulted for the service token.
    assert_eq!(fixture.jwks.fetches(), 1);
    assert_eq!(
        fixture.jwks.user_agent().await.as_deref(),
        Some(JWKS_USER_AGENT)
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_re_ensure_reports_the_token_already_issued_and_never_returns_it() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);
    let body = ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false);

    let (first_status, _, first) = post_ensure(&app, TENANT_A, &token, body.clone()).await;
    assert_eq!(first_status, StatusCode::CREATED, "{first}");
    let binding_id = first["binding_id"].clone();

    let (status, headers, second) = post_ensure(&app, TENANT_A, &token, body).await;
    assert_eq!(status, StatusCode::OK, "{second}");
    assert_no_store(&headers);
    assert_eq!(second["status"], "unchanged");
    assert_eq!(second["token_already_issued"], true);
    assert!(
        second.get("token").is_none(),
        "a re-ensure must not return the token: {second}"
    );
    assert_eq!(second["binding_id"], binding_id);
    assert_eq!(second["binding_revision"], 1);

    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["revision"], 3);
    assert_eq!(row["binding_id"], binding_id);
    assert_eq!(row["issued"], true);

    fixture.finish().await;
}

#[tokio::test]
async fn an_explicit_rotate_issues_a_new_token_and_stops_the_old_one() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    let (_, _, first) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    let first_token = first["token"].as_str().expect("first token").to_owned();
    let binding_id = first["binding_id"].as_str().expect("binding id").to_owned();

    let (status, _, rotated) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, true),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{rotated}");
    assert_eq!(rotated["status"], "rotated");
    assert_eq!(rotated["token_already_issued"], false);
    let rotated_token = rotated["token"]
        .as_str()
        .expect("a rotation issues a token");
    assert_ne!(rotated_token, first_token);
    assert_eq!(rotated["binding_id"], binding_id);
    assert_eq!(rotated["binding_revision"], 2);

    let binding = binding_row(&fixture, TENANT_A, &binding_id).await;
    assert_eq!(
        binding["token_sha256"],
        bindings::digest_token(rotated_token)
    );

    // A plain ensure afterwards still reports the token as already issued.
    let (status, _, after) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(after["token_already_issued"], true);
    assert!(after.get("token").is_none());

    fixture.finish().await;
}

#[tokio::test]
async fn an_unknown_product_is_404_not_found() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    let (status, headers, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("unknown-product", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "not_found"}));

    fixture.finish().await;
}

#[tokio::test]
async fn the_platform_tenant_is_not_provisioned_through_a_product() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    let (status, _, body) = post_ensure(
        &app,
        TENANT_PLATFORM,
        &token,
        ensure_body("agent", PLATFORM_LICENCE, PLATFORM_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    fixture.finish().await;
}

#[tokio::test]
async fn a_licence_for_another_tenant_writes_nothing() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    // Tenant B's licence presented for tenant A's path.
    let (status, _, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_B, TENANT_B_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));

    let rows: i64 = sqlx::query_scalar(
        "SELECT count(*) FROM public.mcp_binding_ensures WHERE tenant_id=$1::uuid AND product='agent'",
    )
    .bind(TENANT_A)
    .fetch_one(&fixture.pool)
    .await
    .expect("ensure rows");
    assert_eq!(rows, 0, "a refused licence must not create the ensure row");

    fixture.finish().await;
}

#[tokio::test]
async fn a_toolkit_the_platform_has_not_published_is_skipped_with_its_reason() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(
        &settings(&[("agent", &["fr", "not_published_yet"])]),
        Some(FakeMinter::granting()),
        true,
    );
    let token = service_token(&fixture.jwks, CLIENT);

    let (status, _, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["toolkits"].as_array().expect("toolkits").len(), 1);
    assert_eq!(body["toolkits"][0]["name"], "fr");
    assert_eq!(
        body["skipped"],
        json!([{"toolkit": "not_published_yet", "reason": "not_published"}])
    );
    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["skipped"][0]["reason"], "not_published");

    fixture.finish().await;
}

#[tokio::test]
async fn a_toolkit_without_a_backend_licence_is_skipped_and_no_binding_is_written() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::denying()), true);
    let token = service_token(&fixture.jwks, CLIENT);

    let (status, _, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["binding_id"], Value::Null);
    assert_eq!(body["token_already_issued"], false);
    assert!(body.get("token").is_none());
    assert_eq!(body["toolkits"], json!([]));
    assert_eq!(
        body["skipped"],
        json!([{
            "toolkit": "fr",
            "reason": "service_credentials_unavailable",
        }])
    );
    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["binding_id"], Value::Null);
    assert_eq!(row["issued"], false);

    fixture.finish().await;
}

#[tokio::test]
async fn two_concurrent_ensures_serialize_and_only_one_token_is_issued() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);
    let body = ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false);

    let (first, second) = tokio::join!(
        post_ensure(&app, TENANT_A, &token, body.clone()),
        post_ensure(&app, TENANT_A, &token, body),
    );
    // Which request wins the serialization is a race, not a fact about the argument order:
    // exactly one 201 and one 200, whichever landed first.
    let mut statuses = [first.0.as_u16(), second.0.as_u16()];
    statuses.sort_unstable();
    assert_eq!(
        statuses,
        [StatusCode::OK.as_u16(), StatusCode::CREATED.as_u16()],
        "{} / {}",
        first.2,
        second.2
    );

    let issued = [&first.2, &second.2]
        .iter()
        .filter(|body| body.get("token").is_some())
        .count();
    assert_eq!(issued, 1, "exactly one ensure issues the token");
    let already = [&first.2, &second.2]
        .iter()
        .filter(|body| body["token_already_issued"].as_bool() == Some(true))
        .count();
    assert_eq!(already, 1);
    assert_eq!(first.2["binding_id"], second.2["binding_id"]);

    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["revision"], 3, "both ensures serialized on the row");
    assert_eq!(row["issued"], true);
    let ensure_id = row["ensure_id"].as_str().expect("ensure id").to_owned();
    assert_eq!(ensure_events(&fixture, TENANT_A, &ensure_id).await, 2);

    fixture.finish().await;
}

// ── the route's credential contract ──────────────────────────────────────────────────────

#[tokio::test]
async fn a_missing_service_token_is_401_unauthorized() {
    let fixture = Fixture::new().await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let request = Request::post(format!("{ENSURE_PATH}/{TENANT_A}/bindings/ensure"))
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(
            ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false).to_string(),
        ))
        .expect("request");
    let (status, headers, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "unauthorized"}));
    assert_eq!(headers[header::WWW_AUTHENTICATE], "Bearer");
    fixture.finish().await;
}

#[tokio::test]
async fn a_client_outside_the_allow_list_is_403_forbidden() {
    let fixture = Fixture::new().await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, OTHER_CLIENT);
    let (status, _, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(body, json!({"error": "forbidden"}));
    fixture.finish().await;
}

#[tokio::test]
async fn a_licence_header_on_an_internal_route_is_401() {
    let fixture = Fixture::new().await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);
    let request = Request::post(format!("{ENSURE_PATH}/{TENANT_A}/bindings/ensure"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header("x-tenant-id", format!("Bearer {TENANT_TOKEN}"))
        .body(Body::from(
            ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false).to_string(),
        ))
        .expect("request");
    let (status, _, body) = send(&app, request).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(body, json!({"error": "unauthorized"}));
    fixture.finish().await;
}

#[tokio::test]
async fn an_unconfigured_keycloak_verifier_is_503_authority_unavailable() {
    let fixture = Fixture::new().await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), false);
    let token = service_token(&fixture.jwks, CLIENT);
    let (status, _, body) = post_ensure(
        &app,
        TENANT_A,
        &token,
        ensure_body("agent", LICENCE_ID, TENANT_TOKEN, false),
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body, json!({"error": "authority_unavailable"}));
    fixture.finish().await;
}

#[tokio::test]
async fn a_malformed_body_is_422_invalid_request() {
    let fixture = Fixture::new().await;
    let app = fixture.app(&default_settings(), Some(FakeMinter::granting()), true);
    let token = service_token(&fixture.jwks, CLIENT);
    for body in [
        json!({"product": "Agent", "licence_id": LICENCE_ID, "licence_token": TENANT_TOKEN}),
        json!({"product": "agent", "licence_id": "not-a-uuid", "licence_token": TENANT_TOKEN}),
        json!({"product": "agent", "licence_id": LICENCE_ID, "licence_token": ""}),
        json!({"product": "agent", "licence_id": LICENCE_ID, "licence_token": TENANT_TOKEN, "extra": 1}),
    ] {
        let (status, _, response) = post_ensure(&app, TENANT_A, &token, body.clone()).await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
        assert_eq!(response, json!({"error": "invalid_request"}));
    }
    fixture.finish().await;
}

#[test]
fn the_internal_path_is_documented_with_its_tag() {
    let spec = serde_json::to_value(mcp_server_rs::openapi()).expect("openapi json");
    let operation = &spec["paths"]["/mcp/internal/tenants/{tenant_id}/bindings/ensure"]["post"];
    assert!(operation.is_object(), "{spec:#}");
    assert_eq!(operation["tags"], json!(["internal"]));
    assert!(
        spec["tags"]
            .as_array()
            .expect("tags")
            .iter()
            .any(|tag| tag["name"] == "internal")
    );
}

// ── re-bind after a toolkit publication ────────────────────────────────────────────────────

/// The same binding-provisioning service the router builds, callable directly.
fn ensure_service(
    fixture: &Fixture,
    settings: &BindingEnsureSettings,
    minter: Option<Arc<dyn LicenceLookup>>,
) -> BindingEnsureService {
    BindingEnsureService::new(
        fixture.pool.clone(),
        SelectionResolver {
            platform_tenant_id: authority(TENANT_PLATFORM),
        },
        Some(GATEWAY_APP_KEY.to_owned()),
        fixture.licences(),
        minter,
        settings,
        authority(TENANT_PLATFORM),
    )
}

/// A licence authority stand-in that refuses one product's licences bundle: the external
/// boundary a re-bind failure is raised at.
struct BundleMinter {
    failing_bundle: &'static str,
}

impl LicenceLookup for BundleMinter {
    fn licence_id<'a>(
        &'a self,
        _tenant: &'a Rfc4122Uuid,
        _app: &'a str,
        bundle: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Rfc4122Uuid, LicenceLookupError>> {
        let fails = bundle == Some(self.failing_bundle);
        let licence = Rfc4122Uuid::parse(BACKEND_LICENCE).expect("backend licence");
        Box::pin(async move {
            if fails {
                Err(LicenceLookupError::Unavailable)
            } else {
                Ok(licence)
            }
        })
    }
}

/// Publish version two of the platform `fr` toolkit through the real toolkit service, the way
/// the builder's publish route does (an identity at revision two, so a new draft is revision
/// three).
async fn publish_toolkit_version_two(fixture: &Fixture) {
    let service = fixture.toolkit_service();
    let operator = platform_principal();
    let mut manifest = serde_json::to_value(toolkit_manifest()).expect("toolkit manifest json");
    manifest["version"] = json!(2);
    let manifest: ToolkitManifest =
        serde_json::from_value(manifest).expect("a valid toolkit manifest");
    let drafted = service
        .write(&operator, &manifest, Some(version(2)))
        .await
        .expect("write toolkit version two");
    assert_eq!(drafted.manifest.version.get(), 2);
    service
        .transition(
            &operator,
            &uuid7(TOOLKIT_FR),
            version(2),
            VersionStatus::Published,
            drafted.revision,
        )
        .await
        .expect("publish toolkit version two");
}

async fn binding_spec_row(fixture: &Fixture, tenant: &str, binding_id: &str) -> Value {
    let row = sqlx::query(
        "SELECT revision, spec, token_sha256 FROM public.mcp_bindings \
         WHERE tenant_id=$1::uuid AND binding_id=$2::uuid",
    )
    .bind(tenant)
    .bind(binding_id)
    .fetch_one(&fixture.pool)
    .await
    .expect("binding row");
    json!({
        "revision": row.try_get::<i64, _>("revision").expect("revision"),
        "spec": row.try_get::<Value, _>("spec").expect("spec"),
        "token_sha256": row.try_get::<String, _>("token_sha256").expect("digest"),
    })
}

#[tokio::test]
async fn rebind_updates_each_binding_to_the_newest_published_toolkit_version() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let settings = default_settings();
    let service = ensure_service(&fixture, &settings, Some(FakeMinter::granting()));
    let tenant = authority(TENANT_A);
    let licence = authority(LICENCE_ID);
    let actor = actor_for(CLIENT, &licence);

    let ensured = service
        .ensure(&tenant, "agent", CLIENT, &licence, TENANT_TOKEN, false)
        .await
        .expect("first ensure");
    let binding_id = ensured
        .binding_id
        .clone()
        .expect("a create records its binding")
        .as_str()
        .to_owned();
    assert_eq!(ensured.binding_revision, Some(version(1)));
    let before = binding_spec_row(&fixture, TENANT_A, &binding_id).await;
    assert_eq!(before["spec"]["toolkits"][0]["version"], 1);

    publish_toolkit_version_two(&fixture).await;

    // A product filter that matches nothing reports nothing and writes nothing.
    assert!(
        service
            .rebind(&tenant, &actor, &licence, Some("care-bus"))
            .await
            .expect("a filtered re-bind")
            .is_empty()
    );

    let report = service
        .rebind(&tenant, &actor, &licence, None)
        .await
        .expect("re-bind");
    assert_eq!(report.len(), 1);
    let entry = &report[0];
    match entry {
        RebindEntry::Rebound {
            product, status, ..
        } => {
            assert_eq!(product, "agent");
            assert_eq!(*status, "updated");
        }
        other => panic!("expected an updated product, got {other:?}"),
    }
    let json = entry.as_json();
    assert_eq!(json["product"], "agent");
    assert_eq!(json["status"], "updated");
    assert_eq!(json["binding_revision"], 2);
    assert_eq!(json["toolkits"][0]["name"], "fr");
    assert_eq!(json["toolkits"][0]["version"], 2);
    assert_eq!(json["skipped"], json!([]));
    // A re-bind never returns a token, and never says one was already issued.
    assert!(json.get("token").is_none());
    assert!(json.get("token_already_issued").is_none());
    let serialized = serde_json::to_string(&report).expect("report json");
    assert!(
        !serialized.contains("\"token\""),
        "the report must not carry a token: {serialized}"
    );

    // The binding moved to revision two, pins version two, and kept its token digest.
    let after = binding_spec_row(&fixture, TENANT_A, &binding_id).await;
    assert_eq!(after["revision"], 2);
    let pins = after["spec"]["toolkits"].as_array().expect("toolkit pins");
    assert_eq!(pins.len(), 1);
    assert_eq!(pins[0]["version"], 2);
    assert_eq!(pins[0]["tenant_id"], TENANT_PLATFORM);
    assert_eq!(after["token_sha256"], before["token_sha256"]);

    // The ensure row records the new pin and advanced once per write.
    let row = ensure_row(&fixture, TENANT_A, "agent").await;
    assert_eq!(row["toolkits"][0]["version"], 2);
    assert_eq!(row["revision"], 3);

    // Nothing changed the second time.
    let again = service
        .rebind(&tenant, &actor, &licence, None)
        .await
        .expect("second re-bind");
    match &again[0] {
        RebindEntry::Rebound { status, .. } => assert_eq!(*status, "unchanged"),
        other => panic!("expected an unchanged product, got {other:?}"),
    }
    assert_eq!(again[0].as_json()["binding_revision"], 2);
    assert_eq!(
        binding_spec_row(&fixture, TENANT_A, &binding_id).await["revision"],
        2
    );

    fixture.finish().await;
}

#[tokio::test]
async fn rebind_reports_unknown_products_and_a_changed_gateway_licence() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let service = ensure_service(&fixture, &default_settings(), Some(FakeMinter::granting()));
    let tenant = authority(TENANT_A);
    let licence = authority(LICENCE_ID);
    let actor = actor_for(CLIENT, &licence);
    let ensured = service
        .ensure(&tenant, "agent", CLIENT, &licence, TENANT_TOKEN, false)
        .await
        .expect("ensure");
    let binding_id = ensured
        .binding_id
        .expect("a create records its binding")
        .as_str()
        .to_owned();
    publish_toolkit_version_two(&fixture).await;

    // A binding provisioned for another gateway licence can never authenticate under this one.
    let changed = authority(LICENCE_B);
    let report = service
        .rebind(&tenant, &actor_for(CLIENT, &changed), &changed, None)
        .await
        .expect("re-bind under a different licence");
    assert_eq!(
        report[0].as_json(),
        json!({"product": "agent", "status": "licence_changed"})
    );
    let unchanged = binding_spec_row(&fixture, TENANT_A, &binding_id).await;
    assert_eq!(unchanged["revision"], 1);
    assert_eq!(unchanged["spec"]["toolkits"][0]["version"], 1);

    // A product the configuration no longer names is reported, never touched.
    let unconfigured = ensure_service(&fixture, &settings(&[]), Some(FakeMinter::granting()));
    let report = unconfigured
        .rebind(&tenant, &actor, &licence, None)
        .await
        .expect("re-bind with no configured products");
    assert_eq!(
        report[0].as_json(),
        json!({"product": "agent", "status": "unknown_product"})
    );
    assert_eq!(
        binding_spec_row(&fixture, TENANT_A, &binding_id).await["revision"],
        1
    );

    // The platform tenant is not provisioned through a product.
    let error = service
        .rebind(
            &authority(TENANT_PLATFORM),
            &actor_for(CLIENT, &authority(PLATFORM_LICENCE)),
            &authority(PLATFORM_LICENCE),
            None,
        )
        .await;
    assert!(matches!(error, Err(EnsureError::Forbidden(_))), "{error:?}");

    fixture.finish().await;
}

#[tokio::test]
async fn a_failed_rebind_is_reported_and_never_undoes_the_publication_or_earlier_products() {
    let fixture = Fixture::new().await;
    seed_platform_toolkit(&fixture).await;
    let settings = settings(&[("agent", &["fr"]), ("care-bus", &["fr"])]);
    let tenant = authority(TENANT_A);
    let licence = authority(LICENCE_ID);
    let actor = actor_for(CLIENT, &licence);
    let granting = ensure_service(&fixture, &settings, Some(FakeMinter::granting()));
    let agent = granting
        .ensure(&tenant, "agent", CLIENT, &licence, TENANT_TOKEN, false)
        .await
        .expect("ensure agent");
    let care_bus = granting
        .ensure(&tenant, "care-bus", CLIENT, &licence, TENANT_TOKEN, false)
        .await
        .expect("ensure care-bus");
    assert_eq!(agent.binding_revision, Some(version(1)));
    assert_eq!(care_bus.binding_revision, Some(version(1)));
    let agent_binding = agent.binding_id.expect("agent binding").as_str().to_owned();
    let care_bus_binding = care_bus
        .binding_id
        .expect("care-bus binding")
        .as_str()
        .to_owned();

    // The toolkit publication this re-bind follows has already committed.
    publish_toolkit_version_two(&fixture).await;

    // Products are processed in product order: `agent` re-binds, then `care-bus` cannot
    // establish its backend licence and the call raises the reference's 503-vocabulary failure.
    let failing = ensure_service(
        &fixture,
        &settings,
        Some(Arc::new(BundleMinter {
            failing_bundle: "care-bus",
        })),
    );
    let error = failing.rebind(&tenant, &actor, &licence, None).await;
    assert!(
        matches!(error, Err(EnsureError::Unavailable(_))),
        "{error:?}"
    );

    // The earlier product stayed written; the failing one is untouched.
    let agent_row = binding_spec_row(&fixture, TENANT_A, &agent_binding).await;
    assert_eq!(agent_row["revision"], 2);
    assert_eq!(agent_row["spec"]["toolkits"][0]["version"], 2);
    let care_bus_row = binding_spec_row(&fixture, TENANT_A, &care_bus_binding).await;
    assert_eq!(care_bus_row["revision"], 1);
    assert_eq!(care_bus_row["spec"]["toolkits"][0]["version"], 1);

    // The publication the re-bind followed is still published.
    let status: String = sqlx::query_scalar(
        "SELECT status FROM public.mcp_toolkit_versions \
         WHERE tenant_id=$1::uuid AND toolkit_id=$2::uuid AND version=2",
    )
    .bind(TENANT_PLATFORM)
    .bind(TOOLKIT_FR)
    .fetch_one(&fixture.pool)
    .await
    .expect("toolkit version two");
    assert_eq!(status, "published");

    // The report the reference's toolkit publish answers with when the re-bind fails.
    assert_eq!(
        rebind_failed_report(),
        json!({"error": "rebind_failed", "detail": "call toolkit bind again"})
    );

    fixture.finish().await;
}
