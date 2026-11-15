//! Keycloak service-token validation for `/mcp/internal/*`.
//!
//! Tokens are signed for real with RS256 and the JWKS is served by a local HTTP server, so
//! `kid` selection, signature verification, every claim rule and the fetch/cache behaviour run
//! for real. The RSA key is a fixed test key: no key-generation dependency may be added and
//! `jsonwebtoken`'s `use_pem` feature is off, so the PKCS#1 DER (the form aws-lc-rs parses) and
//! its JWK `n`/`e` are embedded below.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::header::USER_AGENT;
use axum::http::{HeaderMap, StatusCode};
use axum::routing::get;
use base64::Engine as _;
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use serde_json::{Value, json};
use tokio::sync::Mutex;

use mcp_server_rs::auth::{
    AuthError, KeycloakError, KeycloakSettings, KeycloakVerifier, LicenseIdentity, Rfc4122Uuid,
    ServiceClaims, SubjectKind, author_principal,
};
use mcp_server_rs::config::{AuthConfig, ConfigError};

const REALM: &str = "portal";
const AUDIENCE: &str = "nonagenticai-mcp";
const CLIENT: &str = "carebus-tool-executor";
const KID_1: &str = "test-kid-1";
const KID_2: &str = "test-kid-2";
const TENANT: &str = "0195f48b-d000-7000-8000-000000000001";
const LICENSE: &str = "01900000-0000-7000-8000-0000000000aa";
const PLATFORM_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
const JWKS_USER_AGENT: &str = "nonagenticai-mcp-server (jwks)";

/// Base64 of the PKCS#1 DER private key whose public half is `JWKS_N`/`JWKS_E`.
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
/// The same key's modulus and exponent (65537), base64url without padding.
const JWKS_N: &str = "qAWN2ORmbmbQYq-aagWIw0dmjMAw8164FJZs6SE9EKr0UOJURKbAPSTtN4XPIb6OcSSLrosz6hyZoCSVy-uSaR2lYBguwVbSzt9mOtehb37jtGLYzLONCTDOQBSpV3sSo3EJR-Ioxzm2CgQf5G2H-MHUzapzPu_cyNDmWc7zfE-unVw1m6zcvkJsxkEUshxc8xaqjPCRGqP3xUdc4t9gm1QlIl38HAbaYuw89KmvuV-XJKSMw8DREAg_V8Hq6Wx35pUmFg3OaLBasyZykERHl2rENbZcIYnjyvHLgJI8sNm-b_fXnluyUbSRQws_xc9vEs7m_I3tv_ScLYXRHKRh2w";
const JWKS_E: &str = "AQAB";

// ── the JWKS stub server ────────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct StubState {
    fetches: Arc<AtomicUsize>,
    user_agent: Arc<Mutex<Option<String>>>,
    document: Arc<Mutex<Value>>,
    status: Arc<Mutex<StatusCode>>,
}

async fn certs(State(state): State<StubState>, headers: HeaderMap) -> (StatusCode, Json<Value>) {
    state.fetches.fetch_add(1, Ordering::SeqCst);
    *state.user_agent.lock().await = headers
        .get(USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let status = *state.status.lock().await;
    let document = state.document.lock().await.clone();
    (status, Json(document))
}

struct Stub {
    base: String,
    state: StubState,
}

impl Stub {
    async fn start() -> Self {
        Self::with(StatusCode::OK, jwks(KID_1)).await
    }

    async fn with(status: StatusCode, document: Value) -> Self {
        let state = StubState {
            fetches: Arc::new(AtomicUsize::new(0)),
            user_agent: Arc::new(Mutex::new(None)),
            document: Arc::new(Mutex::new(document)),
            status: Arc::new(Mutex::new(status)),
        };
        let router = Router::new()
            .route("/realms/{realm}/protocol/openid-connect/certs", get(certs))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind JWKS server");
        let base = format!("http://{}", listener.local_addr().expect("JWKS address"));
        tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        Self { base, state }
    }

    fn settings(&self) -> KeycloakSettings {
        KeycloakSettings {
            url: self.base.clone(),
            realm: REALM.to_owned(),
            audiences: vec![AUDIENCE.to_owned()],
            allowed_clients: vec![CLIENT.to_owned(), "other-client".to_owned()],
        }
    }

    fn verifier(&self) -> KeycloakVerifier {
        mcp_server_rs::install_crypto_provider();
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

    async fn serve(&self, kid: &str) {
        *self.state.document.lock().await = jwks(kid);
    }
}

fn jwks(kid: &str) -> Value {
    json!({
        "keys": [{
            "kty": "RSA",
            "use": "sig",
            "alg": "RS256",
            "kid": kid,
            "n": JWKS_N,
            "e": JWKS_E,
        }]
    })
}

// ── token signing ───────────────────────────────────────────────────────────────────────────

fn signing_key() -> EncodingKey {
    let der = base64::engine::general_purpose::STANDARD
        .decode(PRIVATE_KEY_DER_BASE64)
        .expect("test key DER");
    EncodingKey::from_rsa_der(&der)
}

fn token(kid: &str, claims: &Value) -> String {
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some(kid.to_owned());
    jsonwebtoken::encode(&header, claims, &signing_key()).expect("sign RS256")
}

fn claims(stub: &Stub) -> Value {
    let now = jsonwebtoken::get_current_timestamp();
    json!({
        "iss": stub.issuer(),
        "aud": [AUDIENCE, "account"],
        "azp": CLIENT,
        "sub": "service-account-sub",
        "iat": now,
        "exp": now + 300,
        "tenant_id": TENANT,
    })
}

// ── the token rules ─────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_valid_service_token_is_accepted() {
    let stub = Stub::start().await;
    let verifier = stub.verifier();
    let validated = verifier
        .validate(&token(KID_1, &claims(&stub)))
        .await
        .expect("valid token");
    assert_eq!(validated.azp, CLIENT);
    assert_eq!(validated.subject.as_deref(), Some("service-account-sub"));
    assert_eq!(
        validated.tenant_id,
        Some(Rfc4122Uuid::parse(TENANT).expect("tenant uuid"))
    );

    let principal = verifier
        .service_principal(&validated)
        .expect("allowed client");
    assert_eq!(principal.azp, CLIENT);
    assert_eq!(stub.fetches(), 1);
    assert_eq!(stub.user_agent().await.as_deref(), Some(JWKS_USER_AGENT));
}

#[tokio::test]
async fn a_future_iat_is_tolerated() {
    // Clock skew between Keycloak and this pod must not 401 every caller (reference
    // `keycloak.py:145-148`: verify_iat is deliberately off).
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["iat"] = json!(jsonwebtoken::get_current_timestamp() + 60);
    stub.verifier()
        .validate(&token(KID_1, &claims))
        .await
        .expect("future iat tolerated");
}

#[tokio::test]
async fn a_non_uuid_tenant_claim_is_ignored() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["tenant_id"] = json!("n8n-dev");
    let validated = stub
        .verifier()
        .validate(&token(KID_1, &claims))
        .await
        .expect("valid token");
    assert_eq!(validated.tenant_id, None);
}

#[tokio::test]
async fn a_wrong_audience_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["aud"] = json!("account");
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims))
            .await
            .unwrap_err(),
        KeycloakError::WrongAudience
    );
}

#[tokio::test]
async fn a_missing_audience_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims.as_object_mut().expect("claims").remove("aud");
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims))
            .await
            .unwrap_err(),
        KeycloakError::MissingClaim("aud".to_owned())
    );
}

#[tokio::test]
async fn a_wrong_issuer_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["iss"] = json!("https://auth.example.test/realms/other");
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims))
            .await
            .unwrap_err(),
        KeycloakError::WrongIssuer
    );
}

#[tokio::test]
async fn an_expired_token_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["exp"] = json!(jsonwebtoken::get_current_timestamp() - 60);
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims))
            .await
            .unwrap_err(),
        KeycloakError::Expired
    );
}

#[tokio::test]
async fn a_token_without_azp_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims.as_object_mut().expect("claims").remove("azp");
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims))
            .await
            .unwrap_err(),
        KeycloakError::MissingAzp
    );
}

#[tokio::test]
async fn an_azp_outside_the_allow_list_is_refused() {
    let stub = Stub::start().await;
    let mut claims = claims(&stub);
    claims["azp"] = json!("portal-frontend");
    let error = stub
        .verifier()
        .validate(&token(KID_1, &claims))
        .await
        .unwrap_err();
    assert_eq!(
        error,
        KeycloakError::ClientNotAllowed("portal-frontend".to_owned())
    );
    // The reference's exact message (`keycloak.py:160-162`).
    assert_eq!(
        error.to_string(),
        "token was issued to client 'portal-frontend', which may not call this service"
    );
}

#[tokio::test]
async fn hs256_is_refused_before_any_jwks_fetch() {
    let stub = Stub::start().await;
    let mut header = Header::new(Algorithm::HS256);
    header.kid = Some(KID_1.to_owned());
    let key = EncodingKey::from_secret(b"shared-secret-shared-secret-1234").expect("HS256 key");
    let token = jsonwebtoken::encode(&header, &claims(&stub), &key).expect("sign HS256");
    assert_eq!(
        stub.verifier().validate(&token).await.unwrap_err(),
        KeycloakError::NotRs256
    );
    assert_eq!(stub.fetches(), 0);
}

#[tokio::test]
async fn an_unknown_kid_triggers_one_refetch_and_then_succeeds() {
    let stub = Stub::start().await;
    let verifier = stub.verifier();
    let claims = claims(&stub);
    // Prime the cache with KID_1.
    verifier
        .validate(&token(KID_1, &claims))
        .await
        .expect("first key");
    assert_eq!(stub.fetches(), 1);

    // The realm rotates its key. The stale-kid attempt refetches once and then succeeds, and
    // the refreshed set answers the next token without another fetch.
    stub.serve(KID_2).await;
    verifier
        .validate(&token(KID_2, &claims))
        .await
        .expect("rotated key");
    assert_eq!(stub.fetches(), 2);
    verifier
        .validate(&token(KID_2, &claims))
        .await
        .expect("cached key");
    assert_eq!(stub.fetches(), 2);
}

#[tokio::test]
async fn a_jwks_fetch_failure_is_a_refusal_not_a_panic() {
    let stub = Stub::with(
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({ "error": "boom" }),
    )
    .await;
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims(&stub)))
            .await
            .unwrap_err(),
        KeycloakError::JwksUnavailable
    );
}

#[tokio::test]
async fn an_unusable_jwks_is_a_refusal() {
    let stub = Stub::with(StatusCode::OK, json!({ "keys": [] })).await;
    assert_eq!(
        stub.verifier()
            .validate(&token(KID_1, &claims(&stub)))
            .await
            .unwrap_err(),
        KeycloakError::JwksInvalid
    );
}

// ── configuration: all four or none, never a wildcard ──────────────────────────────────────

fn settings(
    pairs: &[(&str, &str)],
    allow_http: bool,
) -> Result<Option<KeycloakSettings>, ConfigError> {
    let values: HashMap<String, String> = pairs
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    KeycloakSettings::from_lookup(|key| values.get(key).cloned(), allow_http)
}

fn configured() -> [(&'static str, &'static str); 4] {
    [
        ("MCP_INTERNAL_KEYCLOAK_URL", "https://auth.example.test"),
        ("MCP_INTERNAL_KEYCLOAK_REALM", REALM),
        ("MCP_INTERNAL_KEYCLOAK_AUDIENCE", AUDIENCE),
        ("MCP_INTERNAL_KEYCLOAK_ALLOWED_CLIENTS", CLIENT),
    ]
}

#[test]
fn all_four_unset_turns_the_verifier_off() {
    assert_eq!(settings(&[], false).expect("no settings"), None);
}

#[test]
fn a_partial_configuration_is_off_never_any_realm_token() {
    let all = configured();
    for missing in KeycloakSettings::REQUIRED_ENV {
        let pairs: Vec<(&str, &str)> = all
            .iter()
            .copied()
            .filter(|(name, _)| *name != missing)
            .collect();
        assert_eq!(
            settings(&pairs, false).expect("partial settings are not an error"),
            None,
            "{missing} missing"
        );
    }
}

#[test]
fn an_empty_list_turns_the_verifier_off() {
    let all = configured();
    for name in [
        "MCP_INTERNAL_KEYCLOAK_AUDIENCE",
        "MCP_INTERNAL_KEYCLOAK_ALLOWED_CLIENTS",
    ] {
        let pairs: Vec<(&str, &str)> = all
            .iter()
            .map(|(key, value)| {
                if *key == name {
                    (*key, " , ")
                } else {
                    (*key, *value)
                }
            })
            .collect();
        assert_eq!(
            settings(&pairs, false).expect("not an error"),
            None,
            "{name}"
        );
    }
}

#[test]
fn a_configured_verifier_splits_its_lists() {
    let pairs: Vec<(&str, &str)> = vec![
        ("MCP_INTERNAL_KEYCLOAK_URL", "https://auth.example.test"),
        ("MCP_INTERNAL_KEYCLOAK_REALM", REALM),
        ("MCP_INTERNAL_KEYCLOAK_AUDIENCE", "mcp, account"),
        ("MCP_INTERNAL_KEYCLOAK_ALLOWED_CLIENTS", "one, two"),
    ];
    let settings = settings(&pairs, false).expect("valid").expect("enabled");
    assert_eq!(settings.url, "https://auth.example.test");
    assert_eq!(settings.realm, REALM);
    assert_eq!(settings.audiences, vec!["mcp", "account"]);
    assert_eq!(settings.allowed_clients, vec!["one", "two"]);
}

#[test]
fn the_keycloak_url_follows_the_licence_http_switch() {
    let http = [
        ("MCP_INTERNAL_KEYCLOAK_URL", "http://keycloak.internal:8080"),
        ("MCP_INTERNAL_KEYCLOAK_REALM", REALM),
        ("MCP_INTERNAL_KEYCLOAK_AUDIENCE", AUDIENCE),
        ("MCP_INTERNAL_KEYCLOAK_ALLOWED_CLIENTS", CLIENT),
    ];
    assert!(matches!(
        settings(&http, false),
        Err(ConfigError::Invalid {
            name: "MCP_INTERNAL_KEYCLOAK_URL",
            ..
        })
    ));
    assert!(settings(&http, true).expect("approved http").is_some());

    let mut query = http;
    query[0] = (
        "MCP_INTERNAL_KEYCLOAK_URL",
        "https://auth.example.test/?x=1",
    );
    assert!(
        settings(&query, false).is_err(),
        "query strings are refused"
    );
}

#[test]
fn auth_config_carries_the_internal_keycloak_block() {
    let values: HashMap<String, String> = configured()
        .iter()
        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
        .collect();
    let config = AuthConfig::from_lookup(|key| values.get(key).cloned()).expect("config");
    let keycloak = config.keycloak.expect("configured");
    assert_eq!(keycloak.realm, REALM);
    assert_eq!(keycloak.audiences, vec![AUDIENCE]);

    let defaults = AuthConfig::from_lookup(|_| None).expect("defaults");
    assert_eq!(defaults.keycloak, None);
}

// ── the issuer/certs URLs and the principal constructors ───────────────────────────────────

#[test]
fn issuer_and_certs_url_follow_the_realm() {
    mcp_server_rs::install_crypto_provider();
    let verifier = KeycloakVerifier::from_settings(&KeycloakSettings {
        url: "https://auth.example.test/".to_owned(),
        realm: REALM.to_owned(),
        audiences: vec![AUDIENCE.to_owned()],
        allowed_clients: vec![CLIENT.to_owned()],
    })
    .expect("verifier");
    assert_eq!(verifier.issuer(), "https://auth.example.test/realms/portal");
    assert_eq!(
        verifier.certs_url(),
        "https://auth.example.test/realms/portal/protocol/openid-connect/certs"
    );
}

fn licence_identity(tenant: &str, kind: SubjectKind) -> LicenseIdentity {
    LicenseIdentity {
        tenant_id: Rfc4122Uuid::parse(tenant).expect("tenant uuid"),
        license_id: Rfc4122Uuid::parse(LICENSE).expect("licence uuid"),
        subject: "svc:tenant:mcp".to_owned(),
        subject_kind: Some(kind),
    }
}

#[test]
fn author_principal_refuses_the_platform_tenant() {
    let platform = Rfc4122Uuid::parse(PLATFORM_TENANT).expect("platform uuid");
    assert_eq!(
        author_principal(
            &licence_identity(PLATFORM_TENANT, SubjectKind::Tenant),
            platform
        )
        .unwrap_err(),
        AuthError::Forbidden
    );
}

#[test]
fn author_principal_refuses_a_member_licence_and_keeps_a_tenant_author() {
    let platform = Rfc4122Uuid::parse(PLATFORM_TENANT).expect("platform uuid");
    assert_eq!(
        author_principal(&licence_identity(TENANT, SubjectKind::Member), platform).unwrap_err(),
        AuthError::Unauthorized
    );
    let principal = author_principal(&licence_identity(TENANT, SubjectKind::Tenant), platform)
        .expect("tenant author");
    assert_eq!(
        principal.tenant_id,
        Rfc4122Uuid::parse(TENANT).expect("tenant uuid")
    );
    assert_eq!(
        principal.license_id,
        Rfc4122Uuid::parse(LICENSE).expect("licence uuid")
    );
    assert_eq!(principal.subject, "svc:tenant:mcp");
    assert_eq!(principal.via, None);
}

#[test]
fn claims_debug_redacts_the_subject() {
    let claims = ServiceClaims {
        azp: CLIENT.to_owned(),
        subject: Some("person@example.test".to_owned()),
        tenant_id: None,
    };
    let rendered = format!("{claims:?}");
    assert!(!rendered.contains("person@example.test"));
    assert!(rendered.contains("<redacted>"));
}
