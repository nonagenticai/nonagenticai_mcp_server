//! Licence introspection: the external authority boundary.
//!
//! `POST {"token": <licence>, "app": <configured app key>}` to `LICENSE_INTROSPECT_URL`; the
//! answer is accepted only when it is `active: true`, names the configured app, carries
//! RFC 4122 ids and has not expired. The call is bounded in time and in response size, and any
//! authority failure fails closed (503) rather than granting access.
//!
//! Unlike the reference implementation this port does NOT cache identities: the cache there is
//! keyed by a SHA-256 digest of the token (never the token itself), and this crate has no
//! hashing dependency. Skipping it makes revocation immediate instead of deferring it by up to
//! `LICENSE_CACHE_TTL_SECONDS` — stricter, never weaker.

use std::time::Duration;

use serde_json::Value;

use crate::config::ConfigError;

use super::BoxFuture;
use super::error::AuthError;
use super::principal::{LicenseIdentity, SubjectKind};
use super::time::{parse_iso8601_epoch_seconds, unix_now};
use super::uuid::Rfc4122Uuid;

/// Resolves an opaque licence token into the identity it grants.
pub trait LicenceAuthority: Send + Sync {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>>;
}

/// Authentication is not configured: every attempt fails closed with 503.
#[derive(Debug, Clone, Copy, Default)]
pub struct UnconfiguredLicenceAuthority;

impl LicenceAuthority for UnconfiguredLicenceAuthority {
    fn authenticate<'a>(
        &'a self,
        _token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async { Err(AuthError::Unavailable) })
    }
}

/// HTTP introspection client for the licences service.
pub struct HttpLicenceAuthority {
    client: reqwest::Client,
    url: String,
    app_key: String,
    max_response_bytes: usize,
    expiry_skew_seconds: i64,
}

impl HttpLicenceAuthority {
    pub fn new(
        url: impl Into<String>,
        app_key: impl Into<String>,
        timeout: Duration,
        max_response_bytes: usize,
        expiry_skew: Duration,
    ) -> Result<Self, ConfigError> {
        let client = reqwest::Client::builder()
            .timeout(timeout)
            // Mirror the reference client: no redirects, no proxy-environment trust.
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| ConfigError::Invalid {
                name: "LICENSE_INTROSPECT_URL",
                reason: format!("cannot build the introspection client: {error}"),
            })?;
        Ok(Self {
            client,
            url: url.into(),
            app_key: app_key.into(),
            max_response_bytes,
            expiry_skew_seconds: i64::try_from(expiry_skew.as_secs()).unwrap_or(i64::MAX),
        })
    }

    /// Validate one introspection payload exactly as the reference client does.
    fn parse(&self, info: &Value) -> Result<LicenseIdentity, AuthError> {
        let info = info.as_object().ok_or(AuthError::Unauthorized)?;
        if info.get("active") != Some(&Value::Bool(true)) {
            return Err(AuthError::Unauthorized);
        }
        let app = info
            .get("app")
            .and_then(Value::as_object)
            .ok_or(AuthError::Unauthorized)?;
        if app.get("key").and_then(Value::as_str) != Some(self.app_key.as_str()) {
            return Err(AuthError::Unauthorized);
        }
        let tenant_id = info
            .get("tenant_id")
            .and_then(Value::as_str)
            .and_then(Rfc4122Uuid::parse)
            .ok_or(AuthError::Unauthorized)?;
        let license_id = info
            .get("license_id")
            .and_then(Value::as_str)
            .and_then(Rfc4122Uuid::parse)
            .ok_or(AuthError::Unauthorized)?;
        let subject = info
            .get("subject_id")
            .and_then(Value::as_str)
            .filter(|subject| (1..=256).contains(&subject.len()))
            .ok_or(AuthError::Unauthorized)?
            .to_owned();
        // Missing expiry fields are malformed, not perpetual; explicit null is perpetual.
        let expires_at = expiry(info.get("expires_at").ok_or(AuthError::Unauthorized)?)?;
        let token_expires_at = expiry(
            info.get("token_expires_at")
                .ok_or(AuthError::Unauthorized)?,
        )?;
        let until = match (expires_at, token_expires_at) {
            (None, None) => None,
            (Some(until), None) | (None, Some(until)) => Some(until),
            (Some(left), Some(right)) => Some(left.min(right)),
        };
        if let Some(until) = until
            && unix_now() >= until.saturating_sub(self.expiry_skew_seconds)
        {
            return Err(AuthError::Unauthorized);
        }
        let subject_kind = match info.get("subject_kind") {
            None | Some(Value::Null) => None,
            Some(Value::String(kind)) if kind == "tenant" => Some(SubjectKind::Tenant),
            Some(Value::String(kind)) if kind == "member" => Some(SubjectKind::Member),
            Some(_) => return Err(AuthError::Unauthorized),
        };
        Ok(LicenseIdentity {
            tenant_id,
            license_id,
            subject,
            subject_kind,
        })
    }
}

/// `None` = perpetual (explicit null); a string must parse as a timezone-aware ISO 8601 value.
fn expiry(value: &Value) -> Result<Option<i64>, AuthError> {
    match value {
        Value::Null => Ok(None),
        Value::String(text) => parse_iso8601_epoch_seconds(text)
            .map(Some)
            .ok_or(AuthError::Unauthorized),
        _ => Err(AuthError::Unauthorized),
    }
}

impl LicenceAuthority for HttpLicenceAuthority {
    fn authenticate<'a>(
        &'a self,
        token: &'a str,
    ) -> BoxFuture<'a, Result<LicenseIdentity, AuthError>> {
        Box::pin(async move {
            if !(1..=4096).contains(&token.len())
                || !token.bytes().all(|byte| (33..=126).contains(&byte))
            {
                return Err(AuthError::Unauthorized);
            }
            let mut response = self
                .client
                .post(&self.url)
                .json(&serde_json::json!({ "token": token, "app": self.app_key }))
                .send()
                .await
                .map_err(|_| AuthError::Unavailable)?;
            if response.status() != reqwest::StatusCode::OK {
                return Err(AuthError::Unavailable);
            }
            let mut body = Vec::new();
            loop {
                match response.chunk().await {
                    Ok(Some(chunk)) => {
                        body.extend_from_slice(&chunk);
                        if body.len() > self.max_response_bytes {
                            return Err(AuthError::Unavailable);
                        }
                    }
                    Ok(None) => break,
                    Err(_) => return Err(AuthError::Unavailable),
                }
            }
            let info: Value = serde_json::from_slice(&body).map_err(|_| AuthError::Unauthorized)?;
            self.parse(&info)
        })
    }
}
