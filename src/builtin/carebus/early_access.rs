//! early-access tool: namespace `early_access`. `early_access_request` asks for early access to
//! a product. Without an explicit confirmation it only proposes the request and makes no network
//! call; with one it files the request with the early-access service under a Keycloak
//! client-credentials bearer.
//!
//! The token exchange copies `client::book_links_token_from_lookup`'s shape (a form-encoded
//! client-credentials request, cached until 30 s before expiry). Nothing here logs the email, the
//! request body, the token or the request id.

use std::sync::{Arc, LazyLock, Mutex};
use std::time::{Duration, Instant};

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client;
use super::{schema, success, text_argument};

/// The request tool's description, read by the model.
const REQUEST_DESCRIPTION: &str = "Ask for early access to a product: an explicit \"yes\" or \"true\" files the request with the early-access service; anything else only proposes it and sends nothing.\n\n\
email: the caller's own address, which the request is bound to; never invent one.\n\
product: the product's slug, exactly as the site names it.\n\
confirm: \"yes\" or \"true\" files the request; anything else only proposes it.\n\
ip: the caller's address when care-bus has it; the early-access service records it.";

/// One optional string argument: absent or null is `None`, anything else must be a string.
fn optional_text(arguments: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| format!("[permanent] invalid {field}: expected a string")),
    }
}

/// The explicit confirmation: `yes` or `true`, case-insensitive. Anything else proposes only.
fn confirmed(confirm: &str) -> bool {
    let confirm = confirm.trim();
    confirm.eq_ignore_ascii_case("yes") || confirm.eq_ignore_ascii_case("true")
}

/// The optional product allow-list: `EARLY_ACCESS_PRODUCTS`, comma-separated. Unset or empty
/// means every product is open.
fn allowed_products() -> Option<Vec<String>> {
    let raw = std::env::var("EARLY_ACCESS_PRODUCTS").ok()?;
    let products: Vec<String> = raw
        .split(',')
        .map(str::trim)
        .filter(|product| !product.is_empty())
        .map(str::to_owned)
        .collect();
    (!products.is_empty()).then_some(products)
}

/// The early-access service's full request route (`EARLY_ACCESS_URL`).
fn request_url() -> Result<String, String> {
    std::env::var("EARLY_ACCESS_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .ok_or_else(|| "[permanent] EARLY_ACCESS_URL is not set on the MCP server".to_owned())
}

/// File one early-access request.
///
/// `EARLY_ACCESS_URL` is the service's full request route, so the POST goes to that URL itself.
/// `cf-connecting-ip` rides only when the caller supplies `ip`. Any 2xx is a filed request;
/// 429 and 5xx are retryable and every other 4xx is permanent. The response body is never read,
/// so nothing can echo the email back.
async fn file(url: &str, email: &str, product: &str, ip: Option<&str>) -> Result<(), String> {
    let token = early_access_token().await?;
    let mut request = reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(client::DEFAULT_TIMEOUT_S))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| format!("[permanent] cannot build the early-access HTTP client: {error}"))?
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .json(&json!({
            "email": email,
            "product": product,
            "consent": true,
            "requestId": uuid::Uuid::new_v4().to_string(),
        }));
    if let Some(ip) = ip {
        request = request.header("cf-connecting-ip", ip);
    }
    let response = match request.send().await {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return Err("[retryable] timeout calling the early-access service".to_owned());
        }
        Err(_) => return Err("[retryable] cannot reach the early-access service".to_owned()),
    };
    let status = response.status();
    if status.is_success() {
        return Ok(());
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Err(format!(
            "[retryable] {} from the early-access service",
            status.as_u16()
        ));
    }
    Err(format!(
        "[permanent] {} from the early-access service",
        status.as_u16()
    ))
}

/// The early-access bearer and the instant it stops being reused: its expiry minus 30 s, so no
/// call ever rides a token that is about to lapse.
static TOKEN_CACHE: LazyLock<Mutex<Option<(String, Instant)>>> = LazyLock::new(|| Mutex::new(None));

/// The early-access bearer: a Keycloak client-credentials token, cached across calls. The token
/// is never logged.
async fn early_access_token() -> Result<String, String> {
    early_access_token_from_lookup(&|key| std::env::var(key).ok()).await
}

/// [`early_access_token`] over a lookup (a map in tests).
async fn early_access_token_from_lookup(
    get: &impl Fn(&str) -> Option<String>,
) -> Result<String, String> {
    {
        // The guard is dropped before the await below: a std mutex is never held across one.
        let cache = TOKEN_CACHE
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if let Some((token, deadline)) = cache.as_ref()
            && Instant::now() < *deadline
        {
            return Ok(token.clone());
        }
    }
    let (token, deadline) = fetch_token(get).await?;
    let mut cache = TOKEN_CACHE
        .lock()
        .unwrap_or_else(|poison| poison.into_inner());
    *cache = Some((token.clone(), deadline));
    Ok(token)
}

/// One client-credentials exchange with the Keycloak early-access client. The secret comes from
/// `EARLY_ACCESS_CLIENT_SECRET` or, when that is unset, from the file named by
/// `EARLY_ACCESS_CLIENT_SECRET_FILE`. Neither the secret nor the response body is ever logged.
async fn fetch_token(get: &impl Fn(&str) -> Option<String>) -> Result<(String, Instant), String> {
    let url = required("EARLY_ACCESS_TOKEN_URL", get)?;
    let client_id = required("EARLY_ACCESS_CLIENT_ID", get)?;
    let secret = match get("EARLY_ACCESS_CLIENT_SECRET").filter(|secret| !secret.is_empty()) {
        Some(secret) => secret,
        None => {
            let path = required("EARLY_ACCESS_CLIENT_SECRET_FILE", get)?;
            std::fs::read_to_string(&path)
                .map_err(|error| {
                    format!("[permanent] cannot read EARLY_ACCESS_CLIENT_SECRET_FILE: {error}")
                })?
                .trim()
                .to_owned()
        }
    };
    let form = encode_query(&[
        ("grant_type", "client_credentials"),
        ("client_id", &client_id),
        ("client_secret", &secret),
    ]);
    let response = reqwest::Client::builder()
        .timeout(Duration::from_secs_f64(client::DEFAULT_TIMEOUT_S))
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .build()
        .map_err(|error| {
            format!("[permanent] cannot build the early-access token client: {error}")
        })?
        .post(&url)
        .header("Content-Type", "application/x-www-form-urlencoded")
        .body(form)
        .send()
        .await;
    let response = match response {
        Ok(response) => response,
        Err(error) if error.is_timeout() => {
            return Err("[retryable] timeout fetching the early-access token".to_owned());
        }
        Err(_) => return Err("[retryable] cannot fetch the early-access token".to_owned()),
    };
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|_| "[retryable] cannot read the early-access token response".to_owned())?;
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
        return Err(format!(
            "[retryable] {} from the early-access token endpoint",
            status.as_u16()
        ));
    }
    if status.as_u16() >= 400 {
        return Err(format!(
            "[permanent] {} from the early-access token endpoint",
            status.as_u16()
        ));
    }
    let value: Value = serde_json::from_slice(&body).map_err(|_| {
        "[permanent] invalid response from the early-access token endpoint".to_owned()
    })?;
    let token = value
        .get("access_token")
        .and_then(Value::as_str)
        .filter(|token| !token.is_empty())
        .ok_or_else(|| {
            "[permanent] the early-access token endpoint returned no access_token".to_owned()
        })?
        .to_owned();
    let lifetime = value
        .get("expires_in")
        .and_then(Value::as_f64)
        .unwrap_or(60.0);
    // Reuse stops 30 s before expiry; a lifetime that short is simply not reused.
    let deadline = Instant::now() + Duration::from_secs_f64((lifetime - 30.0).max(0.0));
    Ok((token, deadline))
}

/// One required env value's refusal: the same shape the base-URL refusals use.
fn required(name: &str, get: &impl Fn(&str) -> Option<String>) -> Result<String, String> {
    get(name)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| format!("[permanent] {name} is not set on the MCP server"))
}

/// `k=v&k=v` with both sides percent-encoded exactly as `application/x-www-form-urlencoded`
/// leaves them: alphanumerics and `-._*` unescaped, everything else escaped.
fn encode_query(params: &[(&str, &str)]) -> String {
    use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};

    const FORM: &AsciiSet = &NON_ALPHANUMERIC
        .remove(b'-')
        .remove(b'.')
        .remove(b'_')
        .remove(b'*');
    params
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(key, FORM),
                utf8_percent_encode(value, FORM)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// Register the early-access tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "early_access",
        "request",
        REQUEST_DESCRIPTION,
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "email": {"type": "string"},
                "product": {"type": "string"},
                "confirm": {"type": "string"},
                "ip": {"type": "string"},
            },
            "required": ["email", "product", "confirm"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let email = text_argument(&arguments, "email")?;
                // A request without a real address can never be answered; refuse before any
                // client is resolved.
                if !email.contains('@') {
                    return Err(
                        "[permanent] invalid email: expected an address with an @".to_owned()
                    );
                }
                let product = text_argument(&arguments, "product")?.trim().to_owned();
                if product.is_empty() {
                    return Err("[permanent] invalid product: expected a product name".to_owned());
                }
                let confirm = text_argument(&arguments, "confirm")?;
                let ip = optional_text(&arguments, "ip")?;
                // A value reqwest would reject as a header would otherwise surface as a
                // retryable transport error; the caller's mistake is permanent.
                if ip
                    .as_deref()
                    .is_some_and(|ip| ip.chars().any(char::is_control))
                {
                    return Err("[permanent] invalid ip: expected a plain address".to_owned());
                }
                // The deployment's own gate: a product outside the list is refused the same way
                // for a proposal and a filing, and before anything is sent.
                if let Some(products) = allowed_products()
                    && !products.iter().any(|allowed| *allowed == product)
                {
                    return Err(
                        "[permanent] invalid product: early access is not open for this product"
                            .to_owned(),
                    );
                }
                if !confirmed(&confirm) {
                    // No confirmation, no network: the caller gets a proposal it can approve.
                    return success(json!({
                        "status": "proposed",
                        "product": product,
                        "email": email,
                        "summary": format!(
                            "I can ask for early access to {product} for {email}."
                        ),
                    }));
                }
                file(&request_url()?, &email, &product, ip.as_deref()).await?;
                success(json!({"status": "filed", "product": product, "email": email}))
            })
        }),
    ));
}
