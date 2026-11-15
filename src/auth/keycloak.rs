//! Keycloak service-token validation for `/mcp/internal/*` — the reference
//! `src/auth/keycloak.py`.
//!
//! A token passes only if: the signature is RS256 and verifies against the realm JWKS selected
//! by the token's `kid`; `exp`, `iss`, `azp` and `aud` are present; `exp` is in the future;
//! `iss` equals `{url}/realms/{realm}`; `aud` intersects the configured audiences; and `azp`
//! (the client the token was issued TO) is in the allowed clients. Without the `azp` gate every
//! valid token of the realm — any portal user's browser token — would be accepted.
//!
//! Deliberate differences from the reference, all preserved here:
//!
//! * `iat` is NOT verified. PyJWT verifies it by default and rejects a token whose `iat` is in
//!   the future, so one second of clock skew between Keycloak and this pod would 401 every
//!   caller. `exp` still bounds the token's life.
//! * The JWKS fetch sends `User-Agent: nonagenticai-mcp-server (jwks)`. Cloudflare in front of
//!   the issuer answers urllib's default agent with 403 (measured live 2026-10-22).
//! * No raw credential is kept: [`ServiceClaims`] carries claims only and its `Debug` redacts
//!   the token subject, which can identify a person.

use std::collections::HashMap;
use std::fmt;
use std::time::{Duration, Instant};

use jsonwebtoken::errors::ErrorKind;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, AlgorithmFamily, DecodingKey, Validation, decode, decode_header};
use serde::Deserialize;
use serde_json::Value;

use crate::config::{AuthConfig, ConfigError, KeycloakSettings};

use super::error::AuthError;
use super::principal::LicenseIdentity;
use super::uuid::Rfc4122Uuid;

/// Sent on every JWKS fetch. Cloudflare 403s a default library User-Agent; any other agent is
/// answered 200 (reference `keycloak.py:49-52`).
const JWKS_USER_AGENT: &str = "nonagenticai-mcp-server (jwks)";
/// How long a fetched key set is reused. An unknown `kid` forces one refetch regardless.
const JWKS_CACHE_LIFESPAN: Duration = Duration::from_secs(300);
/// Bound on one JWKS fetch.
const JWKS_FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// Bound on a JWKS response body; a realm key set is a few kilobytes.
const JWKS_MAX_RESPONSE_BYTES: usize = 512 * 1024;
/// The reference truncates `azp` and the author's subject to this many characters when they
/// become principals.
const MAX_PRINCIPAL_SUBJECT: usize = 256;

/// Why a Keycloak service token was refused.
///
/// The reference's routes collapse every one of these into `401 {"error": "unauthorized"}`
/// (`invalid keycloak token` in its log). The variants exist so the route can log the real
/// reason without ever logging the token.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum KeycloakError {
    #[error("token is not a JWT")]
    Malformed,
    #[error("token is not signed with RS256")]
    NotRs256,
    #[error("token has no kid header")]
    MissingKid,
    #[error("no signing key matches kid '{0}'")]
    UnknownKid(String),
    #[error("token signature does not verify")]
    BadSignature,
    #[error("token has expired")]
    Expired,
    #[error("token is missing the {0} claim")]
    MissingClaim(String),
    #[error("token issuer is not the configured realm")]
    WrongIssuer,
    #[error("token audience is not one of the configured audiences")]
    WrongAudience,
    #[error("token is missing the azp claim")]
    MissingAzp,
    /// The reference's exact message (`keycloak.py:160-162`).
    #[error("token was issued to client '{0}', which may not call this service")]
    ClientNotAllowed(String),
    #[error("the realm JWKS could not be fetched")]
    JwksUnavailable,
    #[error("the realm JWKS is not a usable key set")]
    JwksInvalid,
    #[error("invalid keycloak token")]
    Invalid,
}

impl KeycloakError {
    fn from_jwt(error: jsonwebtoken::errors::Error) -> Self {
        match error.kind() {
            ErrorKind::ExpiredSignature => Self::Expired,
            ErrorKind::InvalidIssuer => Self::WrongIssuer,
            ErrorKind::InvalidAudience => Self::WrongAudience,
            ErrorKind::InvalidAlgorithm => Self::NotRs256,
            ErrorKind::InvalidSignature => Self::BadSignature,
            ErrorKind::MissingRequiredClaim(claim) => Self::MissingClaim(claim.clone()),
            _ => Self::Invalid,
        }
    }
}

/// The reference maps any token-validation failure to `401 unauthorized`
/// (`protocol.py:311-315`), including a JWKS outage, so a route can use `?` directly.
impl From<KeycloakError> for AuthError {
    fn from(_: KeycloakError) -> Self {
        Self::Unauthorized
    }
}

/// The claims the internal routes use. No raw token is kept, and `Debug` does not print the
/// token subject: it can identify a person.
#[derive(Clone, PartialEq, Eq)]
pub struct ServiceClaims {
    /// The client the token was issued to, already checked against the allowed clients.
    pub azp: String,
    /// The token's `sub`, when present. Never a tenant identity.
    pub subject: Option<String>,
    /// The token's `tenant_id` claim, only when it is an RFC 4122 UUID; anything else is
    /// ignored exactly like the reference's `jwt_tenant` helper.
    pub tenant_id: Option<Rfc4122Uuid>,
}

impl fmt::Debug for ServiceClaims {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ServiceClaims")
            .field("azp", &self.azp)
            .field("subject", &self.subject.as_ref().map(|_| "<redacted>"))
            .field("tenant_id", &self.tenant_id)
            .finish()
    }
}

/// A Keycloak service account on `/mcp/internal/*` (the reference `ServicePrincipal`).
///
/// It carries no licence, binding or tenant: the route's path names the tenant, and the route
/// itself decides what the service may do there. No credential is kept here.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServicePrincipal {
    pub azp: String,
}

/// A tenant author of the tool builder (the reference `AuthorPrincipal`).
///
/// It is not a [`super::principal::Principal`], so an author can never reach the operator
/// (management) routes, and it carries no binding. `via` is the service JWT's `azp` when a
/// product platform presents the tenant's licence on its behalf.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorPrincipal {
    pub tenant_id: Rfc4122Uuid,
    pub license_id: Rfc4122Uuid,
    pub subject: String,
    pub via: Option<String>,
}

/// What the tenant-licence half of the builder routes resolves.
///
/// The reference's refusals: a member's per-login licence is `401` with `tenant licence
/// required` (`protocol.py:167-168`); the platform tenant is `403` with `the platform tenant
/// does not author through the builder` (`protocol.py:169-170,280-281`). [`AuthError`] carries
/// the status, not the message (its body is the middleware contract), so the exact strings live
/// with the routes' logs.
pub fn author_principal(
    identity: &LicenseIdentity,
    platform_tenant_id: Rfc4122Uuid,
) -> Result<AuthorPrincipal, AuthError> {
    if !identity.tenant_level() {
        return Err(AuthError::Unauthorized);
    }
    if identity.tenant_id == platform_tenant_id {
        return Err(AuthError::Forbidden);
    }
    Ok(AuthorPrincipal {
        tenant_id: identity.tenant_id,
        license_id: identity.license_id,
        subject: bound_subject(&identity.subject),
        via: None,
    })
}

/// The verifier: one realm's issuer, audiences and allowed clients, plus a cached key set.
pub struct KeycloakVerifier {
    url: String,
    realm: String,
    audiences: Vec<String>,
    allowed_clients: Vec<String>,
    client: reqwest::Client,
    cache: tokio::sync::Mutex<JwksCache>,
}

#[derive(Default)]
struct JwksCache {
    /// The realm's RSA signing keys by `kid`.
    keys: HashMap<String, DecodingKey>,
    /// When the current key set was fetched; `None` until the first fetch.
    fetched_at: Option<Instant>,
}

impl KeycloakVerifier {
    /// The `MCP_INTERNAL_KEYCLOAK_*` verifier, or `None` when it is not configured.
    pub fn from_config(config: &AuthConfig) -> Result<Option<Self>, ConfigError> {
        match &config.keycloak {
            Some(settings) => Self::from_settings(settings).map(Some),
            None => Ok(None),
        }
    }

    /// Build the verifier once at startup; the HTTP client is shared by every request.
    pub fn from_settings(settings: &KeycloakSettings) -> Result<Self, ConfigError> {
        let client = reqwest::Client::builder()
            .timeout(JWKS_FETCH_TIMEOUT)
            // Mirror the reference client: no redirects, no proxy-environment trust.
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| ConfigError::Invalid {
                name: "MCP_INTERNAL_KEYCLOAK_URL",
                reason: format!("cannot build the JWKS client: {error}"),
            })?;
        Ok(Self {
            url: settings.url.clone(),
            realm: settings.realm.clone(),
            audiences: settings.audiences.clone(),
            allowed_clients: settings.allowed_clients.clone(),
            client,
            cache: tokio::sync::Mutex::new(JwksCache::default()),
        })
    }

    /// `{url}/realms/{realm}`, with a trailing slash on the configured URL tolerated.
    pub fn issuer(&self) -> String {
        format!("{}/realms/{}", self.url.trim_end_matches('/'), self.realm)
    }

    /// `{issuer}/protocol/openid-connect/certs`.
    pub fn certs_url(&self) -> String {
        format!("{}/protocol/openid-connect/certs", self.issuer())
    }

    /// Validate one Keycloak service token. The token is never logged or retained.
    pub async fn validate(&self, token: &str) -> Result<ServiceClaims, KeycloakError> {
        let header = decode_header(token).map_err(|_| KeycloakError::Malformed)?;
        // Checked before any key is fetched: a symmetric token must not reach the JWKS at all.
        if header.alg != Algorithm::RS256 {
            return Err(KeycloakError::NotRs256);
        }
        let kid = header.kid.ok_or(KeycloakError::MissingKid)?;
        let key = self.signing_key(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        // PyJWT's default leeway is zero; jsonwebtoken's is 60 seconds.
        validation.leeway = 0;
        // jsonwebtoken only knows exp/nbf/aud/iss/sub as required claims; `azp` is checked
        // below, after the signature and the standard claims have passed.
        validation.required_spec_claims = ["exp", "aud", "iss"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        validation.set_audience(&self.audiences);
        validation.set_issuer(&[self.issuer()]);
        // `iat` is not part of jsonwebtoken's validation: the deliberate skew tolerance of the
        // reference (`keycloak.py:145-148`) is the default here.
        let claims = decode::<RawClaims>(token, &key, &validation)
            .map_err(KeycloakError::from_jwt)?
            .claims;

        let azp = claims.azp.ok_or(KeycloakError::MissingAzp)?;
        if azp.is_empty() || !self.allowed_clients.contains(&azp) {
            return Err(KeycloakError::ClientNotAllowed(azp));
        }
        Ok(ServiceClaims {
            azp,
            subject: claims.sub,
            tenant_id: claims
                .tenant_id
                .as_ref()
                .and_then(Value::as_str)
                .and_then(Rfc4122Uuid::parse),
        })
    }

    /// The `/mcp/internal/*` principal for validated claims.
    ///
    /// The allow-list is checked a second time, exactly as the reference's route checks it
    /// after validation: an `azp` outside the list is `403` with the reference's message
    /// `client may not call internal routes` (`protocol.py:317-318`).
    pub fn service_principal(&self, claims: &ServiceClaims) -> Result<ServicePrincipal, AuthError> {
        if !self.allowed_clients.contains(&claims.azp) {
            return Err(AuthError::Forbidden);
        }
        Ok(ServicePrincipal {
            azp: claims.azp.chars().take(MAX_PRINCIPAL_SUBJECT).collect(),
        })
    }

    /// The RSA key for `kid` from the cached key set, refetching when the set is older than
    /// [`JWKS_CACHE_LIFESPAN`] or does not contain `kid` (one refetch on an unknown `kid`, like
    /// `PyJWKClient`; a Keycloak key rotation needs no restart).
    ///
    /// The lock is held across the fetch, so concurrent callers cannot stampede the issuer.
    /// A failed fetch never replaces the cache; it is the caller's refusal.
    async fn signing_key(&self, kid: &str) -> Result<DecodingKey, KeycloakError> {
        let mut cache = self.cache.lock().await;
        let stale = cache
            .fetched_at
            .is_none_or(|at| at.elapsed() >= JWKS_CACHE_LIFESPAN);
        if stale || !cache.keys.contains_key(kid) {
            cache.keys = self.fetch_keys().await?;
            cache.fetched_at = Some(Instant::now());
        }
        cache
            .keys
            .get(kid)
            .cloned()
            .ok_or_else(|| KeycloakError::UnknownKid(kid.to_owned()))
    }

    /// One bounded JWKS fetch: 5 s, at most [`JWKS_MAX_RESPONSE_BYTES`], status 200, a real
    /// key set. Only RSA signing keys are kept.
    async fn fetch_keys(&self) -> Result<HashMap<String, DecodingKey>, KeycloakError> {
        let mut response = self
            .client
            .get(self.certs_url())
            .header(reqwest::header::USER_AGENT, JWKS_USER_AGENT)
            .send()
            .await
            .map_err(|_| KeycloakError::JwksUnavailable)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(KeycloakError::JwksUnavailable);
        }
        let mut body = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    body.extend_from_slice(&chunk);
                    if body.len() > JWKS_MAX_RESPONSE_BYTES {
                        return Err(KeycloakError::JwksInvalid);
                    }
                }
                Ok(None) => break,
                Err(_) => return Err(KeycloakError::JwksUnavailable),
            }
        }
        let set: JwkSet = serde_json::from_slice(&body).map_err(|_| KeycloakError::JwksInvalid)?;
        let mut keys = HashMap::new();
        for jwk in set.keys {
            let Some(kid) = jwk.common.key_id.clone() else {
                continue;
            };
            let Ok(key) = DecodingKey::from_jwk(&jwk) else {
                continue;
            };
            if key.family() != AlgorithmFamily::Rsa {
                continue;
            }
            keys.entry(kid).or_insert(key);
        }
        if keys.is_empty() {
            return Err(KeycloakError::JwksInvalid);
        }
        Ok(keys)
    }
}

/// The claims this verifier reads. Unknown claims are ignored, exactly like PyJWT's dict.
#[derive(Deserialize)]
struct RawClaims {
    #[serde(default)]
    azp: Option<String>,
    #[serde(default)]
    sub: Option<String>,
    /// Kept as a value so a non-string claim is ignored rather than invalidating the token.
    #[serde(default)]
    tenant_id: Option<Value>,
}

/// The reference slices principals' subjects to 256 characters (`principal.py:81`,
/// `protocol.py:176,283`).
fn bound_subject(subject: &str) -> String {
    subject.chars().take(MAX_PRINCIPAL_SUBJECT).collect()
}
