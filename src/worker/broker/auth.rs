//! Credential injection for registered sources (slice S5).
//!
//! Port of `src/broker/auth.py`: everything except the per-call `licence` mint, which the
//! broker performs from the tenant's profile and this module never touches. One encrypted
//! secret per source; static bearer/header/query/basic and the OAuth2 client-credentials grant.
//!
//! Every secret — and every encoded form of it that could reach an upstream request — is
//! returned to the caller, so it can be added to the broker's leak check. The OAuth token is
//! cached per `(source_id, revision)` with a single-flight refresh, a bounded lifetime, and
//! eviction when an upstream answers 401. A header or query name that the operation mapping
//! already set is refused, never overwritten.
//!
//! The tenant transport is used when [`ResolvedSource::tenant_owned`]; the platform transport
//! otherwise. Both are supplied by the caller: egress pinning belongs to their construction.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use serde_json::Value;
use thiserror::Error;

use crate::auth::Rfc4122Uuid;
use crate::worker::creds::{Clock, form_encode, quote, system_clock};
use crate::worker::sources::{ClientAuth, ResolvedSource, SourceAuth, valid_token};

/// The token endpoint's response bound (`auth.py:29`).
const TOKEN_RESPONSE_LIMIT: usize = 64 * 1024;
/// The token endpoint's time bound (`auth.py:30`).
const TOKEN_TIMEOUT: Duration = Duration::from_secs(10);
/// Renew a cached token this early (`auth.py:31`).
const SKEW_SECONDS: f64 = 30.0;
/// The lifetime assumed when the endpoint omits `expires_in` (`auth.py:32`).
const DEFAULT_LIFETIME_SECONDS: f64 = 300.0;
/// The cached-token bound (`auth.py:33`).
const CACHE_LIMIT: usize = 256;

/// The credential could not be applied or obtained (the reference's `AuthFailedError`, trace
/// reason `auth_failed`). Never carries credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum AuthError {
    #[error("auth failed")]
    Failed,
}

/// One cached OAuth access token.
struct Token {
    access: String,
    /// Seconds from the adapter's clock (`auth.py:52` uses `time.monotonic`).
    until: f64,
}

/// One single-flight slot per source generation.
type Slot = Arc<tokio::sync::Mutex<Option<Token>>>;
/// The process-wide token cache.
type Cache = HashMap<(Rfc4122Uuid, i64), Slot>;

/// Per-source credential injection, one process-wide OAuth token cache.
pub struct AuthAdapters {
    /// The platform egress transport.
    platform: reqwest::Client,
    /// The pinned tenant transport, used for tenant-owned sources.
    tenant: reqwest::Client,
    /// The longest an upstream token may be reused (`MCP_BUILDER_OAUTH_TOKEN_MAX_TTL`).
    max_ttl: Duration,
    clock: Clock,
    /// One single-flight slot per `(source_id, revision)`; the outer lock only guards the map.
    cache: Mutex<Cache>,
}

impl AuthAdapters {
    pub fn new(platform: reqwest::Client, tenant: reqwest::Client, max_ttl: Duration) -> Self {
        Self {
            platform,
            tenant,
            max_ttl,
            clock: system_clock(),
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Replace the clock (tests prove the TTL cap without sleeping).
    pub fn with_clock(mut self, clock: Clock) -> Self {
        self.clock = clock;
        self
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    fn map(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Add the source credential to `headers`/`query` and return every secret string.
    ///
    /// Runs after the operation mapping, so a mapping that targets the credential's header or
    /// query parameter is rejected rather than overwritten. The query secret goes in last.
    ///
    /// `tenant_client` is the caller's **pinned** transport for a tenant-owned source's OAuth
    /// token fetch: the broker validates and pins the token endpoint's own host, exactly as it
    /// pins the source's, and reqwest pins one client per `(host, validated address)`. The
    /// platform client is used for everything else, and a caller that passes `None` falls back
    /// to the adapter's own tenant client (the reference's single tenant client).
    pub async fn apply(
        &self,
        source: &ResolvedSource,
        headers: &mut HashMap<String, String>,
        query: &mut HashMap<String, String>,
        tenant_client: Option<&reqwest::Client>,
    ) -> Result<Vec<String>, AuthError> {
        if matches!(&source.auth, SourceAuth::None | SourceAuth::Licence { .. }) {
            return Ok(Vec::new());
        }
        let secret = source.token.as_deref().ok_or(AuthError::Failed)?;
        let mut secrets = vec![secret.to_owned()];
        match &source.auth {
            SourceAuth::None | SourceAuth::Licence { .. } => unreachable!("handled above"),
            SourceAuth::StaticBearer => {
                set_header(headers, "Authorization", format!("Bearer {secret}"))?;
            }
            SourceAuth::StaticHeader { name } => {
                set_header(headers, name, secret.to_owned())?;
            }
            SourceAuth::Basic { username } => {
                let blob = STANDARD.encode(format!("{username}:{secret}"));
                set_header(headers, "Authorization", format!("Basic {blob}"))?;
                secrets.push(blob);
            }
            SourceAuth::OAuth2ClientCredentials { .. } => {
                let access = self.access_token(source, secret, tenant_client).await?;
                set_header(headers, "Authorization", format!("Bearer {access}"))?;
                secrets.push(access);
            }
            SourceAuth::QueryParam { name } => {
                if query.contains_key(name) {
                    return Err(AuthError::Failed);
                }
                query.insert(name.clone(), secret.to_owned());
                secrets.push(quote(secret));
            }
        }
        Ok(secrets)
    }

    /// An upstream rejected the token: drop it so the next call fetches a fresh one.
    pub fn evict(&self, source: &ResolvedSource) {
        self.map().remove(&(source.source_id, source.revision));
    }

    async fn access_token(
        &self,
        source: &ResolvedSource,
        client_secret: &str,
        tenant_client: Option<&reqwest::Client>,
    ) -> Result<String, AuthError> {
        let key = (source.source_id, source.revision);
        let slot = {
            let mut cache = self.map();
            cache
                .entry(key)
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(None)))
                .clone()
        };
        let mut guard = slot.lock().await;
        // Single flight: a concurrent caller may have refreshed while we waited for the slot.
        if let Some(token) = guard.as_ref()
            && self.now() < token.until
        {
            return Ok(token.access.clone());
        }
        let (access, ttl) = self.fetch(source, client_secret, tenant_client).await?;
        *guard = (ttl > 0.0).then(|| Token {
            access: access.clone(),
            until: self.now() + ttl,
        });
        drop(guard);
        let now = self.now();
        let mut cache = self.map();
        if cache.len() > CACHE_LIMIT {
            // The reference prunes expired entries, then clears if still full.
            cache.retain(|existing, slot| {
                *existing == key
                    || slot
                        .try_lock()
                        .ok()
                        .is_some_and(|token| token.as_ref().is_some_and(|token| token.until > now))
            });
        }
        Ok(access)
    }

    /// `POST {token_url}` with the client-credentials grant (`auth.py:126-180`).
    async fn fetch(
        &self,
        source: &ResolvedSource,
        client_secret: &str,
        tenant_client: Option<&reqwest::Client>,
    ) -> Result<(String, f64), AuthError> {
        let SourceAuth::OAuth2ClientCredentials {
            token_url,
            client_id,
            scopes,
            audience,
            client_auth,
        } = &source.auth
        else {
            return Err(AuthError::Failed);
        };
        let mut form: Vec<(&str, &str)> = vec![("grant_type", "client_credentials")];
        if let Some(scopes) = scopes {
            form.push(("scope", scopes.as_str()));
        }
        if let Some(audience) = audience {
            form.push(("audience", audience.as_str()));
        }
        let authorization = match client_auth {
            ClientAuth::Basic => Some(format!(
                "Basic {}",
                STANDARD.encode(format!("{}:{}", quote(client_id), quote(client_secret)))
            )),
            ClientAuth::Post => {
                form.push(("client_id", client_id.as_str()));
                form.push(("client_secret", client_secret));
                None
            }
        };
        let mut body = String::new();
        for (index, (name, value)) in form.iter().enumerate() {
            if index > 0 {
                body.push('&');
            }
            body.push_str(&form_encode(name));
            body.push('=');
            body.push_str(&form_encode(value));
        }
        let http = if source.tenant_owned {
            tenant_client.unwrap_or(&self.tenant)
        } else {
            &self.platform
        };
        let mut request = http
            .post(token_url)
            .header("Accept", "application/json")
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body(body)
            .timeout(TOKEN_TIMEOUT);
        if let Some(authorization) = authorization {
            request = request.header("Authorization", authorization);
        }
        let mut response = request.send().await.map_err(|_| AuthError::Failed)?;
        if response.status() != reqwest::StatusCode::OK {
            return Err(AuthError::Failed);
        }
        let mut data = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    data.extend_from_slice(&chunk);
                    if data.len() > TOKEN_RESPONSE_LIMIT {
                        return Err(AuthError::Failed);
                    }
                }
                Ok(None) => break,
                Err(_) => return Err(AuthError::Failed),
            }
        }
        let payload: Value = serde_json::from_slice(&data).map_err(|_| AuthError::Failed)?;
        let access = payload
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|access| valid_token(access))
            .ok_or(AuthError::Failed)?;
        let kind = payload
            .get("token_type")
            .and_then(Value::as_str)
            .ok_or(AuthError::Failed)?;
        if !kind.eq_ignore_ascii_case("bearer") {
            return Err(AuthError::Failed);
        }
        let lifetime = match payload.get("expires_in") {
            None => DEFAULT_LIFETIME_SECONDS,
            Some(value) => value.as_f64().ok_or(AuthError::Failed)?,
        };
        if !lifetime.is_finite() {
            return Err(AuthError::Failed);
        }
        Ok((
            access.to_owned(),
            lifetime.min(self.max_ttl.as_secs_f64()) - SKEW_SECONDS,
        ))
    }
}

/// Set `name` unless any existing header has the same name in any case, and refuse a value
/// carrying control characters (`auth.py:92-98`).
fn set_header(
    headers: &mut HashMap<String, String>,
    name: &str,
    value: String,
) -> Result<(), AuthError> {
    if headers
        .keys()
        .any(|existing| existing.eq_ignore_ascii_case(name))
    {
        return Err(AuthError::Failed);
    }
    if value
        .chars()
        .any(|character| (character as u32) < 32 || character as u32 == 127)
    {
        return Err(AuthError::Failed);
    }
    headers.insert(name.to_owned(), value);
    Ok(())
}
