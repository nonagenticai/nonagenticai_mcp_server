//! Shared HTTP client for the care-bus builtin tools.
//!
//! Ported from the reference `src/builtin/carebus/client.py`. Every failure leaves as a tool
//! error whose text starts with `[retryable] ` or `[permanent] `: the care-bus tool executor
//! reads that prefix to decide whether a worker may retry, so it is a cross-service contract
//! and not cosmetics.
//!
//! One behaviour is deliberately narrower than the reference: nothing here logs a request
//! body, an argument or a result — those carry customer data. The reference logs the request
//! path when a backend is unreachable; a path holds the customer's id, so this port logs the
//! internal base URL, the method and the error class.
//!
//! The reference's credential rule is kept in full: a licence caller's strata_rag client is its
//! OWN. The request's forwarded `X-Strata-Token` replaces the pinned `STRATA_RAG_TOKEN` and
//! `X-Tenant-Id` names the licence's tenant, so strata_rag answers `tenant_mismatch` if the two
//! disagree. A licence caller without a forwarded token is refused with the reference's own
//! message ([`X_STRATA_TOKEN_REQUIRED`]), never served from the pinned tenant; a Keycloak caller
//! (the transition path) uses the pinned `STRATA_RAG_TOKEN` unchanged.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use serde_json::Value;

use crate::builtin::BuiltinCaller;

/// Wall-clock bound on one care-bus backend call; below the executor's 3 s tool timeout.
pub const DEFAULT_TIMEOUT_S: f64 = 2.5;
/// `FAQ_TIMEOUT_S`'s default: a strata_rag `/api/ask` includes vLLM generation, and must stay
/// below the executor's 20 s faq budget.
pub const FAQ_TIMEOUT_DEFAULT_S: f64 = 18.0;
/// The reference's refusal for a licence caller that forwards no strata-rag token.
pub const X_STRATA_TOKEN_REQUIRED: &str = "[permanent] X-Strata-Token (the tenant's strata-rag licence token) is required for a licence caller";

/// `quote(segment, safe="")`: everything but the RFC 3986 unreserved characters is escaped,
/// which is exactly what Python's `urllib.parse.quote` keeps.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Path ids come from the model or the customer. An unchecked `../admin/reset?` would reach
/// another route with the same bearer token; percent-encoding alone leaves `..` intact, so the
/// shape is allow-listed first and encoded after.
static PATH_ID: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\z").expect("the path id pattern is valid")
});

/// The three upstreams a care-bus tool may call, with their env-configured base and token.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    /// The demo backends: customers, orders, payments, shipments and business rules.
    DemoBackends,
    /// strata_rag: the knowledge-store answer service behind `faq_ask`.
    StrataRag,
    /// carebus-api: the procedure store behind `procedures_get_procedure`.
    CarebusApi,
}

impl Service {
    /// The reference's `_ENV` pair: the base URL variable and its bearer token variable.
    pub fn env_names(self) -> (&'static str, &'static str) {
        match self {
            Self::DemoBackends => ("DEMO_BACKENDS_URL", "DEMO_BACKENDS_TOKEN"),
            Self::StrataRag => ("STRATA_RAG_URL", "STRATA_RAG_TOKEN"),
            Self::CarebusApi => ("CAREBUS_API_URL", "CAREBUS_API_TOKEN"),
        }
    }
}

/// One upstream: a trimmed base URL, an optional bearer token, an optional tenant and one
/// wall-clock timeout.
///
/// A client is built per call, exactly as the reference opens one `httpx.AsyncClient` per
/// request, so a long-lived process never pins a connection to a backend that moved.
#[derive(Clone)]
pub struct ServiceClient {
    base_url: String,
    token: Option<String>,
    /// `X-Tenant-Id`: set only on a licence caller's own strata_rag client.
    tenant_id: Option<String>,
    timeout: Duration,
}

/// Redacts the bearer token, so a `?client` log line cannot carry a strata-rag licence.
impl std::fmt::Debug for ServiceClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServiceClient")
            .field("base_url", &self.base_url)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .field("tenant_id", &self.tenant_id)
            .field("timeout", &self.timeout)
            .finish()
    }
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

impl ServiceClient {
    /// One client over an explicit base, token and timeout (`set_client`'s test seam).
    pub fn new(base_url: impl Into<String>, token: Option<String>, timeout: Duration) -> Self {
        let base_url: String = base_url.into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            token: token.filter(|token| !token.is_empty()),
            tenant_id: None,
            timeout,
        }
    }

    /// The pinned client under a caller's own credentials: the licence caller's forwarded
    /// strata-rag token and the tenant it names. The deployment's base and timeout stay.
    fn forwarded(self, token: String, tenant_id: Option<String>) -> Self {
        Self {
            token: Some(token),
            tenant_id: tenant_id.filter(|tenant| !tenant.is_empty()),
            ..self
        }
    }

    /// The trimmed base URL (`http://demo.test`).
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    /// The wall-clock bound on one call.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// `GET path` with an optional query.
    ///
    /// The query is encoded here with `percent-encoding` (already a dependency) rather than
    /// through `RequestBuilder::query`, which reqwest gates behind a feature this build does
    /// not enable; the wire form is identical (`k=v&k=v`, both sides percent-encoded).
    pub async fn get(&self, path: &str, params: &[(&str, &str)]) -> Result<Value, String> {
        let client = self.client()?;
        let path = if params.is_empty() {
            path.to_owned()
        } else {
            format!("{path}?{}", encode_query(params))
        };
        let request = self.request(&client, reqwest::Method::GET, &path);
        self.send(request, "GET", &path).await
    }

    /// `POST path` with a JSON body.
    pub async fn post(&self, path: &str, body: Value) -> Result<Value, String> {
        let client = self.client()?;
        let request = self
            .request(&client, reqwest::Method::POST, path)
            .json(&body);
        self.send(request, "POST", path).await
    }

    /// The one HTTP client: no redirects (httpx does not follow them by default) and no
    /// proxy-environment trust (in-cluster backends are reached directly).
    fn client(&self) -> Result<reqwest::Client, String> {
        reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| format!("[permanent] cannot build the care-bus HTTP client: {error}"))
    }

    /// One request with the reference's headers: the configured bearer token, and
    /// `X-Tenant-Id` when the client is a licence caller's own (never on the pinned client).
    fn request(
        &self,
        client: &reqwest::Client,
        method: reqwest::Method,
        path: &str,
    ) -> reqwest::RequestBuilder {
        let request = client.request(method, format!("{}{path}", self.base_url));
        let request = match &self.token {
            Some(token) => request.header("Authorization", format!("Bearer {token}")),
            None => request,
        };
        match &self.tenant_id {
            Some(tenant) => request.header("X-Tenant-Id", tenant),
            None => request,
        }
    }

    /// Send one request and map its outcome to the reference's answer or one tool error.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
        method: &str,
        path: &str,
    ) -> Result<Value, String> {
        let started = Instant::now();
        let response = match request.send().await {
            Ok(response) => response,
            Err(error) => return Err(self.failure(&error, method, path, started)),
        };
        let status = response.status();
        let body = match response.bytes().await {
            Ok(body) => body,
            Err(error) => return Err(self.failure(&error, method, path, started)),
        };
        if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
            return Err(format!(
                "[retryable] {} from {method} {path}: {}",
                status.as_u16(),
                message(&body, status)
            ));
        }
        if status.as_u16() >= 400 {
            return Err(format!(
                "[permanent] {} from {method} {path}: {}",
                status.as_u16(),
                message(&body, status)
            ));
        }
        serde_json::from_slice(&body)
            .map_err(|error| format!("[permanent] invalid response from {method} {path}: {error}"))
    }

    /// The reference's timeout and transport branches, with no argument or result logged.
    fn failure(
        &self,
        error: &reqwest::Error,
        method: &str,
        path: &str,
        started: Instant,
    ) -> String {
        if error.is_timeout() {
            return format!(
                "[retryable] timeout after {} ms calling {method} {path}",
                started.elapsed().as_millis()
            );
        }
        // The internal base URL is logged, the path (a customer's id) is not.
        let class = error_class(error);
        tracing::warn!(
            base = %self.base_url,
            method = %method,
            class = %class,
            "care-bus backend unreachable"
        );
        format!("[retryable] cannot reach backend for {method} {path}: {class}")
    }
}

/// One upstream's client from a lookup (`from_env` at runtime, a map in tests).
///
/// A missing or empty base is the reference's own refusal, never a panic; the token may be
/// absent, and the timeout is the FAQ timeout only for strata_rag.
pub fn from_lookup(
    service: Service,
    get: impl Fn(&str) -> Option<String>,
) -> Result<ServiceClient, String> {
    let (url_var, token_var) = service.env_names();
    let base = get(url_var)
        .filter(|base| !base.is_empty())
        .ok_or_else(|| format!("[permanent] {url_var} is not set on the MCP server"))?;
    let token = get(token_var).filter(|token| !token.is_empty());
    let timeout = if service == Service::StrataRag {
        faq_timeout(&get)?
    } else {
        DEFAULT_TIMEOUT_S
    };
    Ok(ServiceClient::new(
        base,
        token,
        Duration::from_secs_f64(timeout),
    ))
}

/// One upstream's client from the process environment.
pub fn from_env(service: Service) -> Result<ServiceClient, String> {
    from_lookup(service, |key| std::env::var(key).ok())
}

/// The demo backends (customers, orders, payments, shipments, rules).
pub fn demo_backends() -> Result<ServiceClient, String> {
    from_env(Service::DemoBackends)
}

/// carebus-api (the procedure store).
pub fn carebus_api() -> Result<ServiceClient, String> {
    from_env(Service::CarebusApi)
}

/// strata_rag for this caller.
///
/// The reference resolves the pinned client first, so a missing `STRATA_RAG_URL` refuses with
/// its own message before the caller is considered; only then does a licence caller — who must
/// bring its own `X-Strata-Token` — get the reference's refusal here. A licence caller that
/// does bring one searches its own tenant with it, never the pinned tenant.
pub fn strata_rag(caller: &BuiltinCaller) -> Result<ServiceClient, String> {
    strata_rag_from_lookup(caller, |key| std::env::var(key).ok())
}

/// [`strata_rag`] over a lookup (a map in tests).
pub fn strata_rag_from_lookup(
    caller: &BuiltinCaller,
    get: impl Fn(&str) -> Option<String>,
) -> Result<ServiceClient, String> {
    let base = from_lookup(Service::StrataRag, get)?;
    if caller.kind.auth_method() != "license" {
        return Ok(base);
    }
    let Some(token) = caller
        .strata_token
        .as_deref()
        .filter(|token| !token.is_empty())
    else {
        return Err(X_STRATA_TOKEN_REQUIRED.to_owned());
    };
    Ok(base.forwarded(token.to_owned(), caller.tenant_id.clone()))
}

/// `FAQ_TIMEOUT_S` (default 18): a value that cannot name a positive duration refuses rather
/// than building a client that panics or times out on every call.
fn faq_timeout(get: &impl Fn(&str) -> Option<String>) -> Result<f64, String> {
    let Some(raw) = get("FAQ_TIMEOUT_S") else {
        return Ok(FAQ_TIMEOUT_DEFAULT_S);
    };
    match raw.trim().parse::<f64>() {
        Ok(seconds) if seconds.is_finite() && seconds > 0.0 => Ok(seconds),
        _ => Err(format!("[permanent] invalid FAQ_TIMEOUT_S: {raw:?}")),
    }
}

/// Validate one caller-supplied id and return it as a single encoded URL path segment.
pub fn path_id(field: &str, value: &Value) -> Result<String, String> {
    let Some(text) = value.as_str() else {
        return Err(invalid_path_id(field, value));
    };
    if text == "." || text == ".." || !PATH_ID.is_match(text) {
        return Err(invalid_path_id(field, value));
    }
    Ok(utf8_percent_encode(text, PATH_SEGMENT).to_string())
}

/// The reference's `[permanent] invalid <field>` refusal, with the value shown but bounded.
fn invalid_path_id(field: &str, value: &Value) -> String {
    let mut shown = python_repr(value);
    if shown.chars().count() > 40 {
        shown = shown.chars().take(40).collect::<String>() + "...";
    }
    format!(
        "[permanent] invalid {field}: {shown} \
         (expected 1-128 chars of letters, digits, '_', '.', ':', '-')"
    )
}

/// The reference's `_message`: the backend's own error message, else its text, else the reason.
fn message(body: &[u8], status: reqwest::StatusCode) -> String {
    if let Ok(value) = serde_json::from_slice::<Value>(body)
        && let Some(text) = value.get("error").and_then(|error| error.get("message"))
        && truthy(text)
    {
        return python_str(text);
    }
    let text: String = String::from_utf8_lossy(body).chars().take(200).collect();
    if text.is_empty() {
        status.canonical_reason().unwrap_or_default().to_owned()
    } else {
        text
    }
}

/// The reference's `auth_method` names the error classes httpx would raise. The caller
/// branches on the `[retryable]` prefix, never on the class.
fn error_class(error: &reqwest::Error) -> &'static str {
    if error.is_connect() {
        "ConnectError"
    } else if error.is_body() || error.is_decode() {
        "ReadError"
    } else {
        "TransportError"
    }
}

/// Python's `str(value)` for the values a backend puts in an error message.
fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// Python's `repr(value)`, used only to show a rejected id back to the caller.
fn python_repr(value: &Value) -> String {
    match value {
        Value::String(text) => format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// Python truthiness for a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}
