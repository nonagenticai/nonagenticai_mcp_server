//! The legal builtin tools: the 15 tools over public EU/Polish legal sources.
//!
//! Ported from the reference `src/builtin/legal/`. Each tool keeps the reference namespace
//! `legal`, so its wire name is `legal_{function}` and the scope tables in
//! [`crate::builtin::scope`] grant the family exactly as before: `carebus-researcher` and a
//! `care-bus` licence. Every tool answers a JSON object as MCP structured content; every
//! failure is a tool error whose text starts with `[retryable] ` or `[permanent] `, the
//! contract the care-bus researcher branches on.
//!
//! Public sources only: Sejm ELI (Polish acts), SAOS (Polish judgments), CELLAR (EU law), KRS
//! (court register) and the MF VAT whitelist, plus three sites without an API that are read
//! from their public HTML/JSON front-ends: KIO rulings (orzeczenia.uzp.gov.pl), UOKiK
//! President's decisions (decyzje.uokik.gov.pl) and the Dolnośląskie official journal
//! (edzienniki.duw.pl).
//!
//! One behaviour here is deliberately narrower than the reference, because this build has no
//! gzip decoder: requests ask for `Accept-Encoding: identity`. The HTML entity table covers the
//! common Latin/Polish named entities plus every numeric reference; the reference decodes the
//! full HTML5 table. PDF text is ported (`crate::pdf`): the PDF-only paths of `eli_act_text`
//! (a consolidated text without HTML), `duw_document` and `uokik_document` extract the
//! document's text exactly as the reference does, within the same page cap and wall clock.
//!
//! Nothing here logs a request body, an argument or a result: those carry the caller's query.

pub mod duw;
pub mod eli;
pub mod eurlex;
pub mod kio;
pub mod krs;
pub mod saos;
pub mod uokik;
pub mod vat;

use std::collections::HashMap;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use chrono::{Datelike, NaiveDate, Weekday};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use regex::Regex;
use rmcp::model::CallToolResult;
use serde_json::{Map, Value};

use crate::builtin::provider::{BuiltinProvider, HandlerResult};

/// The reference's `USER_AGENT`, sent on every upstream call.
pub const USER_AGENT: &str = "nonagenticai-mcp-legal/1.0 (+https://nonagentic.ai)";
/// The reference's `DEFAULT_TIMEOUT_S`.
pub const DEFAULT_TIMEOUT_S: f64 = 20.0;
/// The reference's `DEFAULT_SCRAPE_INTERVAL_S`: one second between calls to a scraped host.
pub const DEFAULT_SCRAPE_INTERVAL_S: f64 = 1.0;
/// The reference's `MAX_SCRAPE_BODY_BYTES`: the biggest scraped answer (the DUW JSON is ~0.5 MB).
pub const MAX_SCRAPE_BODY_BYTES: usize = 5 * 1024 * 1024;
/// One court ruling / decision / journal PDF; real ones are well under 5 MB.
pub const MAX_PDF_BYTES: usize = 15 * 1024 * 1024;
/// The reference's `DEFAULT_MAX_CHARS` for the scrape-only document tools.
pub const DEFAULT_MAX_CHARS: usize = 25_000;

/// `quote(segment, safe="")`: everything but the RFC 3986 unreserved characters is escaped.
const PATH_SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// A JSON null borrowed as a `&Value`, so nested extraction never needs an owned fallback.
static NULL: Value = Value::Null;

/// One public legal source: its base URL setting and default (the reference's `_ENV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    /// Sejm ELI: Polish acts.
    Eli,
    /// SAOS: Polish court judgments.
    Saos,
    /// Publications Office CELLAR (EU law).
    Cellar,
    /// The National Court Register.
    Krs,
    /// The Ministry of Finance VAT whitelist.
    MfWl,
    /// KIO rulings on orzeczenia.uzp.gov.pl (scraped, paced).
    Kio,
    /// UOKiK President's decisions on decyzje.uokik.gov.pl (scraped, paced).
    Uokik,
    /// The Dolnośląskie official journal (scraped, paced).
    Duw,
}

impl Service {
    /// The reference's `_ENV` pair: the base-URL variable and its default public base.
    pub fn url_env(self) -> (&'static str, &'static str) {
        match self {
            Self::Eli => ("LEGAL_ELI_URL", "https://api.sejm.gov.pl"),
            Self::Saos => ("LEGAL_SAOS_URL", "https://www.saos.org.pl"),
            Self::Cellar => ("LEGAL_CELLAR_URL", "https://publications.europa.eu"),
            Self::Krs => ("LEGAL_KRS_URL", "https://api-krs.ms.gov.pl"),
            Self::MfWl => ("LEGAL_MF_WL_URL", "https://wl-api.mf.gov.pl"),
            Self::Kio => ("LEGAL_KIO_URL", "https://orzeczenia.uzp.gov.pl"),
            Self::Uokik => ("LEGAL_UOKIK_URL", "https://decyzje.uokik.gov.pl"),
            Self::Duw => ("LEGAL_DUW_URL", "https://edzienniki.duw.pl"),
        }
    }

    /// The scrape-only sites: per-host pacing and the body cap (the reference's `SCRAPED`).
    pub fn scraped(self) -> bool {
        matches!(self, Self::Kio | Self::Uokik | Self::Duw)
    }
}

/// `LEGAL_TIMEOUT_S` and `LEGAL_SCRAPE_MIN_INTERVAL_S`, read per resolution.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct Settings {
    /// Wall-clock bound on one upstream call (`LEGAL_TIMEOUT_S`, default 20 s).
    pub timeout: Duration,
    /// Minimum interval between calls to one scraped host (`LEGAL_SCRAPE_MIN_INTERVAL_S`).
    pub scrape_interval: Duration,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs_f64(DEFAULT_TIMEOUT_S),
            scrape_interval: Duration::from_secs_f64(DEFAULT_SCRAPE_INTERVAL_S),
        }
    }
}

impl Settings {
    pub fn from_env() -> Self {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// The reference's `timeout_s` / `scrape_interval_s`: an unparseable value takes the
    /// default; a negative interval becomes zero; a value that cannot name a duration (NaN,
    /// infinity) never reaches `Duration::from_secs_f64`, which would panic.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Self {
        let default = Self::default();
        let timeout =
            match get("LEGAL_TIMEOUT_S").and_then(|value| value.trim().parse::<f64>().ok()) {
                Some(seconds) if seconds.is_finite() && seconds > 0.0 => {
                    Duration::from_secs_f64(seconds)
                }
                _ => default.timeout,
            };
        let scrape_interval = match get("LEGAL_SCRAPE_MIN_INTERVAL_S")
            .and_then(|value| value.trim().parse::<f64>().ok())
        {
            Some(seconds) if seconds.is_nan() => Duration::ZERO,
            Some(seconds) if seconds.is_finite() => Duration::from_secs_f64(seconds.max(0.0)),
            Some(_) => default.scrape_interval,
            None => default.scrape_interval,
        };
        Self {
            timeout,
            scrape_interval,
        }
    }
}

/// The per-service clients a tool resolves: an explicit override (the test seam) or the
/// deployment's environment. The reference's `get_client` / `set_client` pair.
#[derive(Clone, Default)]
pub struct Clients {
    overrides: HashMap<Service, PublicClient>,
}

impl Clients {
    /// A resolver that reads every service from the environment.
    pub fn from_env() -> Self {
        Self::default()
    }

    /// A resolver with one service pinned to an explicit client.
    pub fn with(mut self, service: Service, client: PublicClient) -> Self {
        self.overrides.insert(service, client);
        self
    }

    /// The client for one service: the override, else the environment's base with the
    /// reference's timeout, pacing and body cap.
    pub fn get(&self, service: Service) -> Result<PublicClient, String> {
        if let Some(client) = self.overrides.get(&service) {
            return Ok(client.clone());
        }
        let (env_name, default_base) = service.url_env();
        let base = std::env::var(env_name)
            .ok()
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| default_base.to_owned());
        let settings = Settings::from_env();
        Ok(PublicClient {
            base_url: base.trim_end_matches('/').to_owned(),
            timeout: settings.timeout,
            min_interval: if service.scraped() {
                settings.scrape_interval
            } else {
                Duration::ZERO
            },
            max_body_bytes: if service.scraped() {
                Some(MAX_SCRAPE_BODY_BYTES)
            } else {
                None
            },
        })
    }
}

/// One public source's HTTP client: a trimmed base, a timeout, the per-host scrape interval and
/// an optional decoded-body cap.
#[derive(Clone, Debug)]
pub struct PublicClient {
    pub base_url: String,
    pub timeout: Duration,
    pub min_interval: Duration,
    pub max_body_bytes: Option<usize>,
}

/// One answer that was not an HTTP error: its status, its (capped) decoded body and the URL it
/// finally came from.
#[derive(Debug, Clone)]
pub struct RawReply {
    pub status: u16,
    pub body: Vec<u8>,
    pub final_url: String,
}

impl RawReply {
    /// The body as text, decoded as UTF-8 with replacement (upstreams serve UTF-8).
    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }
}

/// The optional parts of one call (the reference's `PublicClient.request` keywords).
#[derive(Default)]
pub struct RequestOptions<'a> {
    pub query: Vec<(String, String)>,
    pub headers: Vec<(&'a str, String)>,
    pub form: Option<Vec<(String, String)>>,
    pub json: Option<Value>,
    pub follow_redirects: bool,
    pub not_found: Option<&'a str>,
    pub max_bytes: Option<usize>,
}

impl PublicClient {
    /// One client over an explicit base, timeout, pacing and cap (the test seam).
    pub fn new(
        base_url: impl Into<String>,
        timeout: Duration,
        min_interval: Duration,
        max_body_bytes: Option<usize>,
    ) -> Self {
        let base_url: String = base_url.into();
        Self {
            base_url: base_url.trim_end_matches('/').to_owned(),
            timeout,
            min_interval,
            max_body_bytes,
        }
    }

    /// An absolute URL under this client's base.
    pub fn url(&self, path: &str) -> String {
        format!("{}{}", self.base_url, path)
    }

    /// `GET path` as JSON; a non-JSON answer is `[retryable]` (the reference's `get_json`).
    pub async fn get_json(
        &self,
        path: &str,
        params: &[(&str, String)],
        not_found: Option<&str>,
    ) -> Result<Value, String> {
        let reply = self
            .request(
                "GET",
                path,
                RequestOptions {
                    query: params
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), value.clone()))
                        .collect(),
                    headers: vec![("Accept", "application/json".to_owned())],
                    not_found,
                    ..RequestOptions::default()
                },
            )
            .await?;
        serde_json::from_slice(&reply.body)
            .map_err(|_| format!("[retryable] non-JSON answer from GET {path}"))
    }

    /// `GET path` as text, without following redirects (the reference's `get_text`).
    pub async fn get_text(&self, path: &str, not_found: Option<&str>) -> Result<String, String> {
        Ok(self
            .request(
                "GET",
                path,
                RequestOptions {
                    not_found,
                    ..RequestOptions::default()
                },
            )
            .await?
            .text())
    }

    /// `GET path` as text, following redirects and keeping the final status (CELLAR's
    /// content-negotiated manifestation).
    pub async fn get_text_follow(
        &self,
        path: &str,
        headers: Vec<(&str, String)>,
        not_found: Option<&str>,
    ) -> Result<RawReply, String> {
        self.request(
            "GET",
            path,
            RequestOptions {
                headers,
                follow_redirects: true,
                not_found,
                ..RequestOptions::default()
            },
        )
        .await
    }

    /// `GET path` as bytes, with the reference's optional redirect following and cap.
    pub async fn get_bytes(
        &self,
        path: &str,
        follow_redirects: bool,
        not_found: Option<&str>,
        max_bytes: Option<usize>,
    ) -> Result<Vec<u8>, String> {
        Ok(self
            .request(
                "GET",
                path,
                RequestOptions {
                    follow_redirects,
                    not_found,
                    max_bytes,
                    ..RequestOptions::default()
                },
            )
            .await?
            .body)
    }

    /// `POST path` with an `application/x-www-form-urlencoded` body.
    pub async fn post_form(
        &self,
        path: &str,
        form: Vec<(String, String)>,
        headers: Vec<(&str, String)>,
        not_found: Option<&str>,
    ) -> Result<RawReply, String> {
        self.request(
            "POST",
            path,
            RequestOptions {
                form: Some(form),
                headers,
                not_found,
                ..RequestOptions::default()
            },
        )
        .await
    }

    /// `POST path` with a JSON body.
    pub async fn post_json(
        &self,
        path: &str,
        body: Value,
        headers: Vec<(&str, String)>,
    ) -> Result<RawReply, String> {
        self.request(
            "POST",
            path,
            RequestOptions {
                json: Some(body),
                headers,
                ..RequestOptions::default()
            },
        )
        .await
    }

    /// One call, mapped to the reference's answer or its one tool error.
    ///
    /// The order is the reference's: pace the host, send (following redirects only when asked,
    /// pacing and host-checking every hop), cap the decoded body, then map 429/5xx to
    /// `[retryable]`, a 404 with `not_found` to `[permanent] {not_found}`, any other 4xx to
    /// `[permanent]`, and anything below 400 to the answer.
    pub async fn request(
        &self,
        method: &str,
        path: &str,
        options: RequestOptions<'_>,
    ) -> Result<RawReply, String> {
        if method != "GET" && method != "POST" {
            return Err(format!("[permanent] unsupported method: {method}"));
        }
        let host = host_of(&self.base_url).ok_or_else(|| {
            format!(
                "[permanent] invalid legal source base URL: {}",
                self.base_url
            )
        })?;
        let mut current_url = self.url(path);
        if !options.query.is_empty() {
            current_url.push('?');
            current_url.push_str(&encode_pairs(&options.query));
        }
        let client = reqwest::Client::builder()
            .timeout(self.timeout)
            .redirect(reqwest::redirect::Policy::none())
            .no_proxy()
            .build()
            .map_err(|error| format!("[permanent] cannot build the legal HTTP client: {error}"))?;
        pace(&host, self.min_interval).await;
        let started = Instant::now();
        let mut hops = 0usize;
        loop {
            hops += 1;
            let mut request = match method {
                "GET" => client.get(&current_url),
                _ => client.post(&current_url),
            };
            request = request
                .header(reqwest::header::USER_AGENT, USER_AGENT)
                .header(reqwest::header::ACCEPT_ENCODING, "identity");
            for (name, value) in &options.headers {
                request = request.header(*name, value);
            }
            if let Some(form) = &options.form {
                request = request
                    .header(
                        reqwest::header::CONTENT_TYPE,
                        "application/x-www-form-urlencoded",
                    )
                    .body(encode_pairs(form));
            }
            if let Some(json) = &options.json {
                request = request.json(json);
            }
            let mut response = match request.send().await {
                Ok(response) => response,
                Err(error) => return Err(self.failure(&error, method, path, started)),
            };
            let status = response.status();
            if options.follow_redirects
                && matches!(status.as_u16(), 301 | 302 | 303 | 307 | 308)
                && let Some(location) = response
                    .headers()
                    .get(reqwest::header::LOCATION)
                    .and_then(|value| value.to_str().ok())
                    .map(str::to_owned)
            {
                if hops > 20 {
                    return Err(format!(
                        "[retryable] cannot reach {} for {method} {path}: TooManyRedirects",
                        self.base_url
                    ));
                }
                let next = resolve(&current_url, &location)?;
                if self.min_interval > Duration::ZERO {
                    let next_host = host_of(&next).unwrap_or_default();
                    if next_host != host {
                        return Err(format!(
                            "[permanent] {method} {path} redirects to another host ({next_host})"
                        ));
                    }
                    pace(&host, self.min_interval).await;
                }
                current_url = next;
                continue;
            }
            let cap = options.max_bytes.or(self.max_body_bytes);
            let body = if let Some(cap) = cap {
                let declared = response
                    .headers()
                    .get(reqwest::header::CONTENT_LENGTH)
                    .and_then(|value| value.to_str().ok())
                    .unwrap_or_default()
                    .to_owned();
                if !declared.is_empty()
                    && declared.bytes().all(|byte| byte.is_ascii_digit())
                    && let Ok(size) = declared.parse::<usize>()
                    && size > cap
                {
                    return Err(format!(
                        "[permanent] answer to {method} {path} too large ({declared} bytes, max {cap})"
                    ));
                }
                let mut body: Vec<u8> = Vec::new();
                let mut size = 0usize;
                loop {
                    match response.chunk().await {
                        Ok(Some(chunk)) => {
                            size += chunk.len();
                            if size > cap {
                                return Err(format!(
                                    "[permanent] answer to {method} {path} too large (over {cap} bytes)"
                                ));
                            }
                            body.extend_from_slice(&chunk);
                        }
                        Ok(None) => break,
                        Err(error) => return Err(self.failure(&error, method, path, started)),
                    }
                }
                body
            } else {
                match response.bytes().await {
                    Ok(body) => body.to_vec(),
                    Err(error) => return Err(self.failure(&error, method, path, started)),
                }
            };
            if status == reqwest::StatusCode::TOO_MANY_REQUESTS || status.is_server_error() {
                return Err(format!(
                    "[retryable] {} from {method} {path}: {}",
                    status.as_u16(),
                    message(&body, status)
                ));
            }
            if status.as_u16() == 404
                && let Some(not_found) = options.not_found
            {
                return Err(format!("[permanent] {not_found}"));
            }
            if status.as_u16() >= 400 {
                return Err(format!(
                    "[permanent] {} from {method} {path}: {}",
                    status.as_u16(),
                    message(&body, status)
                ));
            }
            return Ok(RawReply {
                status: status.as_u16(),
                body,
                final_url: current_url,
            });
        }
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
        let class = error_class(error);
        tracing::warn!(
            base = %self.base_url,
            method = %method,
            class = %class,
            "legal source unreachable"
        );
        format!(
            "[retryable] cannot reach {} for {method} {path}: {class}",
            self.base_url
        )
    }
}

/// The host of the deployment's next free request slot, across tools and concurrent calls.
/// The reference's `_next_slot`.
static NEXT_SLOT: LazyLock<Mutex<HashMap<String, Instant>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Wait for this host's next request slot. Reserving the slot has no await in between, so
/// concurrent callers queue one interval apart instead of racing.
async fn pace(host: &str, interval: Duration) {
    if interval.is_zero() {
        return;
    }
    let now = Instant::now();
    let wait = {
        let mut slots = NEXT_SLOT
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let slot = slots.get(host).copied().unwrap_or(now).max(now);
        slots.insert(host.to_owned(), slot + interval);
        slot.saturating_duration_since(now)
    };
    if !wait.is_zero() {
        tokio::time::sleep(wait).await;
    }
}

/// The host a base URL names, lowercased for the slot table and the redirect check.
fn host_of(url: &str) -> Option<String> {
    url::Url::parse(url)
        .ok()
        .and_then(|parsed| parsed.host_str().map(|host| host.to_ascii_lowercase()))
}

/// Resolve a redirect `Location` against the URL that answered it.
fn resolve(current: &str, location: &str) -> Result<String, String> {
    let base = url::Url::parse(current)
        .map_err(|error| format!("[permanent] invalid request URL: {error}"))?;
    base.join(location)
        .map(|next| next.to_string())
        .map_err(|error| format!("[permanent] invalid redirect location: {error}"))
}

/// `k=v&k=v`, both sides percent-encoded with the RFC 3986 unreserved set (query and form).
fn encode_pairs(pairs: &[(String, String)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| {
            format!(
                "{}={}",
                utf8_percent_encode(key, PATH_SEGMENT),
                utf8_percent_encode(value, PATH_SEGMENT)
            )
        })
        .collect::<Vec<_>>()
        .join("&")
}

/// One caller-supplied value as a single encoded URL path segment (`quote(text, safe="")`).
pub fn encode_segment(text: &str) -> String {
    utf8_percent_encode(text, PATH_SEGMENT).to_string()
}

/// The reference's `_message`: the upstream's own error message, else its text, else the reason.
fn message(body: &[u8], status: reqwest::StatusCode) -> String {
    if let Ok(Value::Object(fields)) = serde_json::from_slice::<Value>(body) {
        if let Some(Value::Object(error)) = fields.get("error")
            && let Some(text) = error.get("message")
            && truthy(text)
        {
            return python_str(text).chars().take(200).collect();
        }
        if let Some(text) = fields.get("message")
            && truthy(text)
        {
            return python_str(text).chars().take(200).collect();
        }
    }
    let text: String = String::from_utf8_lossy(body).chars().take(200).collect();
    let text = text.trim().to_owned();
    if text.is_empty() {
        status.canonical_reason().unwrap_or_default().to_owned()
    } else {
        text
    }
}

/// The reference's `error_class` names the classes httpx would raise; callers branch on the
/// `[retryable]` prefix, never on the class.
fn error_class(error: &reqwest::Error) -> &'static str {
    if error.is_connect() {
        "ConnectError"
    } else if error.is_body() || error.is_decode() {
        "ReadError"
    } else {
        "TransportError"
    }
}

// ── JSON helpers, with the reference's Python value semantics ────────────────────────────────

/// One child exactly as Python's `value.get(key)` sees it: missing or non-object is null.
pub fn child<'a>(value: &'a Value, key: &str) -> &'a Value {
    value.get(key).unwrap_or(&NULL)
}

/// Python's `value.get(key, default)`: the key present with null yields null, not the default.
pub fn child_or<'a>(value: &'a Value, key: &str, default: &'a Value) -> &'a Value {
    value.get(key).unwrap_or(default)
}

/// Python truthiness for a JSON value.
pub fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(members) => !members.is_empty(),
    }
}

/// Python's `str(value)` for the values an upstream puts in its answers.
pub fn python_str(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// Python's `repr(value)`, used only to show a rejected value back to the caller.
pub fn python_repr(value: &Value) -> String {
    match value {
        Value::String(text) => format!("'{}'", text.replace('\\', "\\\\").replace('\'', "\\'")),
        Value::Null => "None".to_owned(),
        Value::Bool(true) => "True".to_owned(),
        Value::Bool(false) => "False".to_owned(),
        other => other.to_string(),
    }
}

/// The reference's `_shown`: `repr(value)` cut to 40 characters plus an ellipsis.
pub fn shown_repr(value: &Value) -> String {
    let shown = python_repr(value);
    if shown.chars().count() > 40 {
        shown.chars().take(40).collect::<String>() + "..."
    } else {
        shown
    }
}

/// `repr(str(value)[:40])`, the reference's spelling for a rejected NIP or KRS number.
pub fn shown_str_slice(value: &Value) -> String {
    let text: String = python_str(value).chars().take(40).collect();
    python_repr(&Value::String(text))
}

/// One string array's truthy string members, as the reference's list comprehensions build them.
pub fn truthy_strings(value: &Value) -> Vec<Value> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter(|item| item.as_str().is_some_and(|text| !text.is_empty()))
                .cloned()
                .collect()
        })
        .unwrap_or_default()
}

// ── argument parsing ────────────────────────────────────────────────────────────────────────

/// One argument exactly as it arrived (a missing one is JSON null).
pub fn argument(arguments: &Map<String, Value>, field: &str) -> Value {
    arguments.get(field).cloned().unwrap_or(Value::Null)
}

/// A required string argument.
pub fn required_string(arguments: &Map<String, Value>, field: &str) -> Result<String, String> {
    match arguments.get(field) {
        Some(Value::String(text)) => Ok(text.clone()),
        _ => Err(format!("[permanent] invalid {field}: expected a string")),
    }
}

/// An optional string argument; present null is absent.
pub fn optional_string(
    arguments: &Map<String, Value>,
    field: &str,
) -> Result<Option<String>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) => Ok(Some(text.clone())),
        Some(_) => Err(format!("[permanent] invalid {field}: expected a string")),
    }
}

/// An optional integer argument; present null is absent.
pub fn optional_int(arguments: &Map<String, Value>, field: &str) -> Result<Option<i64>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_i64()
            .map(Some)
            .ok_or_else(|| format!("[permanent] invalid {field}: expected an integer")),
    }
}

/// An integer argument with the tool's own default.
pub fn int_or(arguments: &Map<String, Value>, field: &str, default: i64) -> Result<i64, String> {
    Ok(optional_int(arguments, field)?.unwrap_or(default))
}

/// A boolean argument with the tool's own default.
pub fn bool_or(arguments: &Map<String, Value>, field: &str, default: bool) -> Result<bool, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(default),
        Some(Value::Bool(flag)) => Ok(*flag),
        Some(_) => Err(format!("[permanent] invalid {field}: expected a boolean")),
    }
}

/// An enumerated string argument with the tool's own default.
pub fn enum_or(
    arguments: &Map<String, Value>,
    field: &str,
    default: &str,
    allowed: &[&str],
) -> Result<String, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(default.to_owned()),
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => Ok(text.clone()),
        Some(_) => Err(format!(
            "[permanent] invalid {field}: expected one of {}",
            allowed.join(", ")
        )),
    }
}

/// An optional enumerated string argument; present null is absent.
pub fn optional_enum(
    arguments: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<Option<String>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(text)) if allowed.contains(&text.as_str()) => Ok(Some(text.clone())),
        Some(_) => Err(format!(
            "[permanent] invalid {field}: expected one of {}",
            allowed.join(", ")
        )),
    }
}

// ── registration helpers ────────────────────────────────────────────────────────────────────

/// The MCP success for one tool's JSON answer: the value as text and as structured content.
pub fn success(value: Value) -> HandlerResult {
    Ok(CallToolResult::structured(value))
}

/// One tool's declared input schema, as the provider registers and validates it.
pub fn schema(value: Value) -> Map<String, Value> {
    value
        .as_object()
        .cloned()
        .expect("a legal tool schema is a JSON object")
}

// ── HTML to text (the reference's `html_text.py`) ───────────────────────────────────────────

const BLOCK_TAGS: &[&str] = &[
    "p",
    "div",
    "br",
    "li",
    "ul",
    "ol",
    "tr",
    "table",
    "h1",
    "h2",
    "h3",
    "h4",
    "h5",
    "h6",
    "section",
    "article",
    "blockquote",
    "hr",
    "dd",
    "dt",
];
const CELL_TAGS: &[&str] = &["td", "th"];
const SKIP_TAGS: &[&str] = &["script", "style", "head", "title", "noscript"];
const VOID_TAGS: &[&str] = &[
    "area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "param", "source",
    "track", "wbr",
];

fn is_block(tag: &str) -> bool {
    BLOCK_TAGS.contains(&tag)
}

fn is_cell(tag: &str) -> bool {
    CELL_TAGS.contains(&tag)
}

fn is_skip(tag: &str) -> bool {
    SKIP_TAGS.contains(&tag)
}

fn is_void(tag: &str) -> bool {
    VOID_TAGS.contains(&tag)
}

/// One element predicate: the tag name and its attributes.
type ElementMatcher<'a> = &'a dyn Fn(&str, &HashMap<String, String>) -> bool;

struct TextCollector<'a> {
    matcher: Option<ElementMatcher<'a>>,
    parts: Vec<String>,
    skip_depth: i32,
    inside: Option<i32>,
    found: bool,
    done: bool,
}

impl TextCollector<'_> {
    fn active(&self) -> bool {
        self.inside.is_some() && !self.done && self.skip_depth == 0
    }

    fn start_tag(&mut self, tag: &str, attrs: &HashMap<String, String>) {
        if self.done {
            return;
        }
        if self.inside.is_none() {
            let matches = self
                .matcher
                .expect("a matcher selects the element being read");
            if !is_void(tag) && matches(tag, attrs) {
                self.inside = Some(1);
                self.found = true;
            }
            return;
        }
        if !is_void(tag)
            && self.matcher.is_some()
            && let Some(depth) = self.inside.as_mut()
        {
            *depth += 1;
        }
        if is_skip(tag) {
            self.skip_depth += 1;
            return;
        }
        if !self.active() {
            return;
        }
        if is_block(tag) {
            self.parts.push("\n".to_owned());
        } else if is_cell(tag) {
            self.parts.push(" ".to_owned());
        } else if tag == "sup" {
            self.parts.push("^".to_owned());
        }
    }

    fn start_end_tag(&mut self, tag: &str) {
        if self.active() && is_block(tag) {
            self.parts.push("\n".to_owned());
        }
    }

    fn end_tag(&mut self, tag: &str) {
        if self.done || self.inside.is_none() {
            return;
        }
        if is_skip(tag) && self.skip_depth > 0 {
            self.skip_depth -= 1;
        } else if self.active() && is_block(tag) {
            self.parts.push("\n".to_owned());
        }
        if self.matcher.is_some()
            && !is_void(tag)
            && let Some(depth) = self.inside.as_mut()
        {
            *depth -= 1;
            if *depth == 0 {
                self.done = true;
            }
        }
    }

    fn data(&mut self, text: &str) {
        if self.active() {
            self.parts.push(decode_entities(text));
        }
    }
}

/// HTML -> plain text. Block elements become line breaks, `<td>`/`<th>` a space, `<sup>` a
/// caret (so "Art. 449<sup>1</sup>" reads "Art. 449^1"); script/style/head/title are dropped.
pub fn html_to_text(html: &str) -> String {
    let mut collector = new_collector(None);
    parse_html(html, &mut collector);
    normalise(&collector.parts)
}

/// Plain text of the first element the predicate selects, or None if there is none.
pub fn element_text(
    html: &str,
    matches: impl Fn(&str, &HashMap<String, String>) -> bool,
) -> Option<String> {
    let matcher: &dyn Fn(&str, &HashMap<String, String>) -> bool = &matches;
    let mut collector = new_collector(Some(matcher));
    parse_html(html, &mut collector);
    if collector.found {
        Some(normalise(&collector.parts))
    } else {
        None
    }
}

fn new_collector<'a>(matcher: Option<ElementMatcher<'a>>) -> TextCollector<'a> {
    TextCollector {
        matcher,
        parts: Vec::new(),
        skip_depth: 0,
        // None = not (yet) inside the matched element.
        inside: if matcher.is_some() { None } else { Some(0) },
        found: matcher.is_none(),
        done: false,
    }
}

fn parse_html(html: &str, collector: &mut TextCollector<'_>) {
    let mut index = 0usize;
    while index < html.len() {
        let rest = &html[index..];
        if !rest.starts_with('<') {
            match rest.find('<') {
                Some(offset) => {
                    collector.data(&rest[..offset]);
                    index += offset;
                }
                None => {
                    collector.data(rest);
                    index = html.len();
                }
            }
            continue;
        }
        if let Some(comment) = rest.strip_prefix("<!--") {
            match comment.find("-->") {
                Some(offset) => index += 4 + offset + 3,
                None => index = html.len(),
            }
            continue;
        }
        if rest.starts_with("<!") || rest.starts_with("<?") {
            match rest.find('>') {
                Some(offset) => index += offset + 1,
                None => index = html.len(),
            }
            continue;
        }
        let Some(end) = tag_end(rest) else {
            index = html.len();
            continue;
        };
        let inner = &rest[1..end];
        index += end + 1;
        let trimmed = inner.trim_end();
        let self_closing = trimmed.ends_with('/');
        let body = trimmed.trim_end_matches('/').trim();
        if let Some(name_text) = body.strip_prefix('/') {
            collector.end_tag(&tag_name(name_text));
            continue;
        }
        if body.is_empty() {
            continue;
        }
        let (name, attrs) = parse_tag(body);
        if self_closing {
            collector.start_end_tag(&name);
            continue;
        }
        collector.start_tag(&name, &attrs);
        if name == "script" || name == "style" {
            // Raw text elements: a tag-looking token inside them is content, never markup
            // (Python's HTMLParser switches to CDATA mode for exactly these two).
            let close = format!("</{name}");
            if let Some(offset) = find_ascii_case_insensitive(&html[index..], &close) {
                index += offset;
            }
        }
    }
}

/// The index of the `>` that ends the tag starting at `rest[0] == '<'`, honouring quotes.
fn tag_end(rest: &str) -> Option<usize> {
    let bytes = rest.as_bytes();
    let mut quote: Option<u8> = None;
    let mut index = 1usize;
    while index < bytes.len() {
        let byte = bytes[index];
        match quote {
            Some(open) => {
                if byte == open {
                    quote = None;
                }
            }
            None => {
                if byte == b'"' || byte == b'\'' {
                    quote = Some(byte);
                } else if byte == b'>' {
                    return Some(index);
                }
            }
        }
        index += 1;
    }
    None
}

/// A tag name: everything up to whitespace, `=` or `/`, lowercased.
fn tag_name(text: &str) -> String {
    let end = text
        .find(|ch: char| ch.is_whitespace() || ch == '=' || ch == '/')
        .unwrap_or(text.len());
    text[..end].to_ascii_lowercase()
}

/// One tag's name and attributes, attribute values entity-decoded and names lowercased.
fn parse_tag(body: &str) -> (String, HashMap<String, String>) {
    let name = tag_name(body);
    let mut rest = &body[name.len()..];
    let mut attrs: HashMap<String, String> = HashMap::new();
    loop {
        rest = rest.trim_start();
        if rest.is_empty() {
            break;
        }
        let end = rest
            .find(|ch: char| ch.is_whitespace() || ch == '=' || ch == '/')
            .unwrap_or(rest.len());
        let attribute = rest[..end].to_ascii_lowercase();
        rest = &rest[end..];
        if attribute.is_empty() {
            // Malformed markup (a bare '/', '=' or similar): consume one character so the
            // scanner always makes progress instead of spinning on it.
            let mut characters = rest.chars();
            characters.next();
            rest = characters.as_str();
            continue;
        }
        let mut value = String::new();
        let candidate = rest.trim_start();
        if let Some(after_equals) = candidate.strip_prefix('=') {
            let value_rest = after_equals.trim_start();
            let mut chars = value_rest.chars();
            match chars.next() {
                Some(quote @ ('"' | '\'')) => {
                    let inner = &value_rest[1..];
                    let close = inner.find(quote).unwrap_or(inner.len());
                    value = decode_entities(&inner[..close]);
                    rest = if close < inner.len() {
                        &inner[close + 1..]
                    } else {
                        ""
                    };
                }
                _ => {
                    let close = value_rest
                        .find(char::is_whitespace)
                        .unwrap_or(value_rest.len());
                    value = decode_entities(&value_rest[..close]);
                    rest = &value_rest[close..];
                }
            }
        } else {
            rest = candidate;
        }
        if !attribute.is_empty() {
            attrs.insert(attribute, value);
        }
    }
    (name, attrs)
}

fn find_ascii_case_insensitive(haystack: &str, needle: &str) -> Option<usize> {
    let haystack = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len()).find(|&start| {
        haystack[start..start + needle.len()]
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

fn normalise(parts: &[String]) -> String {
    let text = parts.concat().replace('\u{a0}', " ");
    let mut lines: Vec<String> = Vec::new();
    for line in text.split('\n') {
        let mut collapsed = String::with_capacity(line.len());
        let mut previous_space = false;
        for ch in line.chars() {
            if matches!(ch, ' ' | '\t' | '\r' | '\u{c}' | '\u{b}') {
                if !previous_space {
                    collapsed.push(' ');
                    previous_space = true;
                }
            } else {
                collapsed.push(ch);
                previous_space = false;
            }
        }
        let trimmed = collapsed.trim();
        if !trimmed.is_empty() {
            lines.push(trimmed.to_owned());
        }
    }
    lines.join("\n").replace("^ ", "^")
}

/// Inline snippets (SAOS `<em>` highlights): tags removed, whitespace collapsed.
pub fn strip_tags(fragment: &str) -> String {
    html_to_text(fragment)
        .replace('\n', " ")
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Decode the common named entities and every numeric character reference. The reference
/// decodes the full HTML5 table; this table carries the Latin/Polish set the sources use.
pub fn decode_entities(text: &str) -> String {
    if !text.contains('&') {
        return text.to_owned();
    }
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(position) = rest.find('&') {
        output.push_str(&rest[..position]);
        let after = &rest[position + 1..];
        let Some(end) = after.find(';').filter(|end| *end <= 32) else {
            output.push('&');
            rest = after;
            continue;
        };
        match decode_entity(&after[..end]) {
            Some(ch) => {
                output.push(ch);
                rest = &after[end + 1..];
            }
            None => {
                output.push('&');
                rest = after;
            }
        }
    }
    output.push_str(rest);
    output
}

fn decode_entity(entity: &str) -> Option<char> {
    if let Some(number) = entity.strip_prefix('#') {
        let code = if let Some(hex) = number
            .strip_prefix('x')
            .or_else(|| number.strip_prefix('X'))
        {
            u32::from_str_radix(hex, 16).ok()?
        } else {
            number.parse::<u32>().ok()?
        };
        return char::from_u32(code);
    }
    let text = match entity {
        "amp" => "&",
        "lt" => "<",
        "gt" => ">",
        "quot" => "\"",
        "apos" => "'",
        "nbsp" => "\u{a0}",
        "shy" => "\u{ad}",
        "copy" => "\u{a9}",
        "reg" => "\u{ae}",
        "trade" => "\u{2122}",
        "hellip" => "\u{2026}",
        "ndash" => "\u{2013}",
        "mdash" => "\u{2014}",
        "lsquo" => "\u{2018}",
        "rsquo" => "\u{2019}",
        "ldquo" => "\u{201c}",
        "rdquo" => "\u{201d}",
        "bdquo" => "\u{201e}",
        "laquo" => "\u{ab}",
        "raquo" => "\u{bb}",
        "bull" => "\u{2022}",
        "middot" => "\u{b7}",
        "deg" => "\u{b0}",
        "plusmn" => "\u{b1}",
        "times" => "\u{d7}",
        "divide" => "\u{f7}",
        "sup1" => "\u{b9}",
        "sup2" => "\u{b2}",
        "sup3" => "\u{b3}",
        "frac12" => "\u{bd}",
        "frac14" => "\u{bc}",
        "frac34" => "\u{be}",
        "sect" => "\u{a7}",
        "para" => "\u{b6}",
        "dagger" => "\u{2020}",
        "Dagger" => "\u{2021}",
        "permil" => "\u{2030}",
        "euro" => "\u{20ac}",
        "cent" => "\u{a2}",
        "pound" => "\u{a3}",
        "yen" => "\u{a5}",
        "oacute" => "\u{f3}",
        "Oacute" => "\u{d3}",
        "aacute" => "\u{e1}",
        "Aacute" => "\u{c1}",
        "eacute" => "\u{e9}",
        "Eacute" => "\u{c9}",
        "iacute" => "\u{ed}",
        "Iacute" => "\u{cd}",
        "uacute" => "\u{fa}",
        "Uacute" => "\u{da}",
        "ntilde" => "\u{f1}",
        "Ntilde" => "\u{d1}",
        "ccedil" => "\u{e7}",
        "Ccedil" => "\u{c7}",
        "szlig" => "\u{df}",
        "agrave" => "\u{e0}",
        "Agrave" => "\u{c0}",
        "egrave" => "\u{e8}",
        "Egrave" => "\u{c8}",
        "ograve" => "\u{f2}",
        "Ograve" => "\u{d2}",
        "oslash" => "\u{f8}",
        "Oslash" => "\u{d8}",
        "aelig" => "\u{e6}",
        "AElig" => "\u{c6}",
        "aring" => "\u{e5}",
        "Aring" => "\u{c5}",
        "auml" => "\u{e4}",
        "Auml" => "\u{c4}",
        "ouml" => "\u{f6}",
        "Ouml" => "\u{d6}",
        "uuml" => "\u{fc}",
        "Uuml" => "\u{dc}",
        "ecirc" => "\u{ea}",
        "Ecirc" => "\u{ca}",
        "acirc" => "\u{e2}",
        "Acirc" => "\u{c2}",
        "icirc" => "\u{ee}",
        "Icirc" => "\u{ce}",
        "ocirc" => "\u{f4}",
        "Ocirc" => "\u{d4}",
        "ucirc" => "\u{fb}",
        "Ucirc" => "\u{db}",
        "aogon" => "\u{105}",
        "Aogon" => "\u{104}",
        "eogon" => "\u{119}",
        "Eogon" => "\u{118}",
        "cacute" => "\u{107}",
        "Cacute" => "\u{106}",
        "nacute" => "\u{144}",
        "Nacute" => "\u{143}",
        "sacute" => "\u{15b}",
        "Sacute" => "\u{15a}",
        "zacute" => "\u{17a}",
        "Zacute" => "\u{179}",
        "zdot" => "\u{17c}",
        "Zdot" => "\u{17b}",
        "lstrok" => "\u{142}",
        "Lstrok" => "\u{141}",
        _ => return None,
    };
    text.chars().next()
}

/// Python's `text[:max_chars]`: a CHARACTER slice, never a byte slice.
pub fn truncate(text: &str, max_chars: usize) -> (String, bool) {
    if text.chars().count() <= max_chars {
        return (text.to_owned(), false);
    }
    (text.chars().take(max_chars).collect(), true)
}

// ── dates ───────────────────────────────────────────────────────────────────────────────────

static PL_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"(?i)\bdnia\s+(\d{1,2})\s+(stycznia|lutego|marca|kwietnia|maja|czerwca|lipca|sierpnia|września|października|listopada|grudnia)\s+(\d{4})",
    )
    .expect("the Polish date pattern is valid")
});

static DOTTED_DATE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A\s*(\d{1,2})[.-](\d{1,2})[.-](\d{4})\s*\z")
        .expect("the dotted date pattern is valid")
});

/// ISO date of the first "[z] dnia 25 sierpnia 2022" in `text`, else None.
pub fn polish_date(text: &str) -> Option<String> {
    let captures = PL_DATE.captures(text)?;
    let day: u32 = captures[1].parse().ok()?;
    let month = match captures[2].to_lowercase().as_str() {
        "stycznia" => 1,
        "lutego" => 2,
        "marca" => 3,
        "kwietnia" => 4,
        "maja" => 5,
        "czerwca" => 6,
        "lipca" => 7,
        "sierpnia" => 8,
        "września" => 9,
        "października" => 10,
        "listopada" => 11,
        "grudnia" => 12,
        _ => return None,
    };
    let year: i32 = captures[3].parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day).map(|date| date.format("%Y-%m-%d").to_string())
}

/// DD.MM.YYYY or DD-MM-YYYY -> ISO; anything else -> None.
pub fn dotted_date(value: Option<&str>) -> Option<String> {
    let captures = DOTTED_DATE.captures(value.unwrap_or_default())?;
    let day: u32 = captures[1].parse().ok()?;
    let month: u32 = captures[2].parse().ok()?;
    let year: i32 = captures[3].parse().ok()?;
    NaiveDate::from_ymd_opt(year, month, day).map(|date| date.format("%Y-%m-%d").to_string())
}

/// A strict `YYYY-MM-DD` parse; the reference's `date.fromisoformat` for these sources.
pub fn parse_iso_date(text: &str) -> Option<NaiveDate> {
    NaiveDate::parse_from_str(text, "%Y-%m-%d").ok()
}

/// The reference's `_day` helper: the first ten characters of an ISO timestamp as a date.
pub fn iso_day(value: &Value) -> Value {
    let Some(text) = value.as_str() else {
        return Value::Null;
    };
    if text.chars().count() < 10 {
        return Value::Null;
    }
    let prefix: String = text.chars().take(10).collect();
    match parse_iso_date(&prefix) {
        Some(date) => Value::String(date.format("%Y-%m-%d").to_string()),
        None => Value::Null,
    }
}

/// Today's date in Europe/Warsaw, without a timezone crate: Poland follows the EU rule (last
/// Sunday of March 01:00 UTC through last Sunday of October 01:00 UTC is +02:00, else +01:00).
pub fn warsaw_today() -> String {
    let now = chrono::Utc::now();
    let utc = now.naive_utc();
    let year = utc.date().year();
    let offset_hours = if is_warsaw_summer(&utc, year) { 2 } else { 1 };
    let local = (now + chrono::Duration::hours(offset_hours)).date_naive();
    local.format("%Y-%m-%d").to_string()
}

fn is_warsaw_summer(utc: &chrono::NaiveDateTime, year: i32) -> bool {
    let (Some(start_day), Some(end_day)) = (last_sunday(year, 3), last_sunday(year, 10)) else {
        return false;
    };
    let (Some(start), Some(end)) = (start_day.and_hms_opt(1, 0, 0), end_day.and_hms_opt(1, 0, 0))
    else {
        return false;
    };
    *utc >= start && *utc < end
}

/// The last Sunday of one month (Poland's DST switch day).
fn last_sunday(year: i32, month: u32) -> Option<NaiveDate> {
    let first_of_next = if month == 12 {
        NaiveDate::from_ymd_opt(year + 1, 1, 1)?
    } else {
        NaiveDate::from_ymd_opt(year, month + 1, 1)?
    };
    let mut date = first_of_next.pred_opt()?;
    while date.weekday() != Weekday::Sun {
        date = date.pred_opt()?;
    }
    Some(date)
}

// ── scrape helpers (the reference's `scrape_util.py`) ──────────────────────────────────────

/// None/blank -> None; too long -> `[permanent]`; otherwise stripped.
pub fn check_text(
    field: &str,
    value: Option<String>,
    max_len: usize,
) -> Result<Option<String>, String> {
    match value {
        None => Ok(None),
        Some(text) if text.trim().is_empty() => Ok(None),
        Some(text) if text.chars().count() > max_len => Err(format!(
            "[permanent] {field} too long (max {max_len} chars)"
        )),
        Some(text) => Ok(Some(text.trim().to_owned())),
    }
}

/// `max(500, min(max_chars, maximum))`.
pub fn clamp_max_chars_with(max_chars: i64, maximum: i64) -> usize {
    usize::try_from(max_chars.clamp(500, maximum)).unwrap_or(500)
}

/// `max(500, min(max_chars, 300_000))` for the scrape-only tools.
pub fn clamp_max_chars(max_chars: i64) -> usize {
    clamp_max_chars_with(max_chars, 300_000)
}

/// `max(1, page), max(1, min(page_size, max_size))`.
pub fn clamp_page(page: i64, page_size: i64, max_size: i64) -> (i64, i64) {
    (page.max(1), page_size.clamp(1, max_size))
}

/// Inline HTML fragment -> one line of text; empty or "-" -> null.
pub fn clean(fragment: Option<&Value>) -> Value {
    let Some(Value::String(text)) = fragment else {
        return Value::Null;
    };
    let stripped = strip_tags(text);
    let trimmed = stripped.trim_end_matches([' ', ',', ';']);
    if trimmed.is_empty() || trimmed == "-" {
        Value::Null
    } else {
        Value::String(trimmed.to_owned())
    }
}

/// The cached document as one call returns it: text cut to max_chars, flags added, and `text`
/// LAST so a consumer that cuts the serialised result keeps the metadata.
pub fn finish(doc: Value, max_chars: usize, hit: bool) -> Value {
    let mut fields = match doc {
        Value::Object(fields) => fields,
        other => return other,
    };
    let text = fields
        .shift_remove("text")
        .map(|value| python_str(&value))
        .unwrap_or_default();
    let (text, truncated) = truncate(&text, max_chars);
    let mut out = Map::new();
    for (key, value) in fields {
        out.insert(key, value);
    }
    out.insert("truncated".to_owned(), Value::Bool(truncated));
    out.insert("cached".to_owned(), Value::Bool(hit));
    out.insert("text".to_owned(), Value::String(text));
    Value::Object(out)
}

/// The PDF's bytes, streamed and refused past `max_bytes`, and refused if it is not a PDF.
pub async fn fetch_pdf(
    client: &PublicClient,
    path: &str,
    not_found: &str,
    max_bytes: Option<usize>,
) -> Result<Vec<u8>, String> {
    let body = client
        .get_bytes(
            path,
            true,
            Some(not_found),
            Some(max_bytes.unwrap_or(MAX_PDF_BYTES)),
        )
        .await?;
    if !body.starts_with(b"%PDF") {
        return Err("[permanent] the document file is not a PDF".to_owned());
    }
    Ok(body)
}

/// PDF -> plain text. The class-shaped suffix mirrors the reference's
/// `cannot read the PDF text: {ClassName}`; this parser reports one stable class for pypdf's
/// family of read errors.
const PDF_TEXT_ERROR: &str = "[permanent] cannot read the PDF text: PdfReadError";

/// The reference's `PDF_TIMEOUT_S`: wall time for one extraction (`scrape_util.py:20`). The
/// extraction is CPU-bound and runs on a blocking thread; a timed-out one is left to finish, as
/// the reference's worker thread is (the page cap bounds it).
const PDF_TIMEOUT: Duration = Duration::from_secs(60);

/// PDF -> plain text of the first [`crate::pdf::MAX_PDF_PAGES`] pages, the reference's
/// `scrape_util.pdf_text`: one worker thread, one 60 s wall clock, and the reference's two
/// permanent error texts.
pub async fn pdf_text(data: Vec<u8>) -> Result<String, String> {
    let extraction = tokio::task::spawn_blocking(move || crate::pdf::text(&data));
    match tokio::time::timeout(PDF_TIMEOUT, extraction).await {
        Err(_) => Err(format!(
            "[permanent] reading the PDF text took over {} s",
            PDF_TIMEOUT.as_secs()
        )),
        // A panicked extraction is a damaged file's class, never a process failure.
        Ok(Err(_)) | Ok(Ok(Err(_))) => Err(PDF_TEXT_ERROR.to_owned()),
        Ok(Ok(Ok(text))) => Ok(text),
    }
}

/// Fetch and extract one PDF's text.
pub async fn fetch_pdf_text(
    client: &PublicClient,
    path: &str,
    not_found: &str,
) -> Result<String, String> {
    let data = fetch_pdf(client, path, not_found, None).await?;
    pdf_text(data).await
}

/// Every page's text, no page cap and no wall clock — the ELI consolidated-PDF path, which
/// matches the reference's `eli._pdf_text` (its own thread, `pdf_to_text` with no page limit).
pub async fn pdf_full_text(data: Vec<u8>) -> Result<String, String> {
    match tokio::task::spawn_blocking(move || crate::pdf::full_text(&data)).await {
        Ok(Ok(text)) => Ok(text),
        Ok(Err(_)) | Err(_) => Err(PDF_TEXT_ERROR.to_owned()),
    }
}

// ── the process-wide TTL caches (the reference's cachetools TTLCache) ──────────────────────

struct CacheEntry {
    value: Value,
    expires: Instant,
    used: u64,
}

/// A bounded, expiring store. `cachetools.TTLCache` is LRU on overflow; this evicts the least
/// recently used entry, with a process-wide tick ordering access.
pub struct TtlCache {
    max: usize,
    ttl: Duration,
    entries: Mutex<HashMap<String, CacheEntry>>,
    tick: std::sync::atomic::AtomicU64,
}

impl TtlCache {
    fn new(max: usize, ttl: Duration) -> Self {
        Self {
            max,
            ttl,
            entries: Mutex::new(HashMap::new()),
            tick: std::sync::atomic::AtomicU64::new(0),
        }
    }

    fn get(&self, key: &str) -> Option<Value> {
        let now = Instant::now();
        let tick = self.tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if entries.get(key).is_some_and(|entry| entry.expires <= now) {
            entries.remove(key);
            return None;
        }
        let entry = entries.get_mut(key)?;
        entry.used = tick;
        Some(entry.value.clone())
    }

    fn put(&self, key: String, value: Value) {
        let now = Instant::now();
        let tick = self.tick.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, entry| entry.expires > now);
        if !entries.contains_key(&key)
            && entries.len() >= self.max
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, entry)| entry.used)
                .map(|(key, _)| key.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(
            key,
            CacheEntry {
                value,
                expires: now + self.ttl,
                used: tick,
            },
        );
    }

    fn clear(&self) {
        self.entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clear();
    }
}

/// One court ruling / decision / journal position, cached 24 h (published documents never
/// change; a day keeps repeat citations off the source servers).
static DOC_CACHE: LazyLock<TtlCache> =
    LazyLock::new(|| TtlCache::new(128, Duration::from_secs(24 * 3600)));

pub fn cached(key: &str) -> Option<Value> {
    DOC_CACHE.get(key)
}

pub fn remember(key: &str, doc: Value) {
    DOC_CACHE.put(key.to_owned(), doc);
}

pub fn clear_doc_cache() {
    DOC_CACHE.clear();
}

// ── the family registration and the UOKiK gate ─────────────────────────────────────────────

/// `LEGAL_UOKIK_ENABLED`: the reference's `{"1", "true", "yes"}` (trimmed, lowercased).
pub fn uokik_enabled() -> bool {
    uokik_enabled_value(std::env::var("LEGAL_UOKIK_ENABLED").ok().as_deref())
}

/// [`uokik_enabled`] over one raw value (a map in tests).
pub fn uokik_enabled_value(raw: Option<&str>) -> bool {
    matches!(
        raw.map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("1" | "true" | "yes")
    )
}

/// Register the legal family: every tool under the `legal` namespace. The two UOKiK tools are
/// registered only when the gate is on, so a disabled one is absent from the listing and its
/// call is the provider's scope refusal.
pub fn register(provider: &mut BuiltinProvider) {
    register_with(provider, uokik_enabled());
}

/// [`register`] over an explicit gate (the test seam): `duw`, `eli`, `eurlex`, `kio`, `krs`,
/// `saos`, `uokik`, `vat` — the reference's import order.
pub fn register_with(provider: &mut BuiltinProvider, uokik_enabled: bool) {
    duw::register(provider);
    eli::register(provider);
    eurlex::register(provider);
    kio::register(provider);
    krs::register(provider);
    saos::register(provider);
    if uokik_enabled {
        uokik::register(provider);
    }
    vat::register(provider);
}
