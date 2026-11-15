//! The research builtin tools: the 5 tools over the two in-cluster research backends.
//!
//! Ported from the reference `src/builtin/research/`. Each tool keeps the reference namespace
//! `research`, so its wire name is `research_{function}` and the scope tables in
//! [`crate::builtin::scope`] grant the family exactly as before: `carebus-researcher` and a
//! `care-bus` licence. Every tool answers a JSON object as MCP structured content; every
//! failure is a tool error whose text starts with `[retryable] ` or `[permanent] `, the
//! contract the care-bus researcher branches on.
//!
//! Literature comes from discovery-engine (`POST /api/search`, `GET /api/papers/{id}`) and the
//! three statistics tools are forwarded to scientific-processor (`POST /api/stats/*`), which
//! performs the arithmetic; nothing is stored here. The upstreams, their licence tokens and
//! their timeouts are resolved per call ([`Clients`]), so a tool never pins a connection to a
//! backend that moved.
//!
//! The reference's legal `PublicClient` is reused unchanged, which keeps the one error contract
//! of both families: 429/5xx and a timeout/unreachable host are `[retryable]`, every other 4xx
//! and a bad argument are `[permanent]`. Nothing here logs a request body, an argument or a
//! result: those carry the caller's query.
//!
//! One behaviour is deliberately narrower than the reference, inherited from this crate's legal
//! port: requests ask for `Accept-Encoding: identity` (this build has no gzip decoder), and a
//! non-JSON answer is the reference's `[retryable] non-JSON answer` error.

pub mod literature;
pub mod stats;

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Map, Value};

use crate::builtin::legal::{PublicClient, RequestOptions, python_str, truthy};
use crate::builtin::provider::BuiltinProvider;

/// discovery-engine's cap on one query's results per source (`MAX_PER_SOURCE`).
pub const MAX_PER_SOURCE: i64 = 20;
/// scientific-processor's meta-analysis cap (`MAX_STUDIES`).
pub const MAX_STUDIES: usize = 1_000;
/// scientific-processor's confidence-interval cap (`MAX_VALUES`).
pub const MAX_VALUES: usize = 100_000;
/// scientific-processor's trend cap (`MAX_POINTS`).
pub const MAX_POINTS: usize = 10_000;

/// One research backend: its base-URL setting and default, token setting, and timeout.
#[derive(Debug, Clone, Copy)]
pub struct ServiceSpec {
    pub url_env: &'static str,
    pub default_url: &'static str,
    pub token_env: &'static str,
    pub timeout_env: &'static str,
    pub default_timeout_s: f64,
}

/// The two upstreams a research tool may call (the reference's `_ENV`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Service {
    /// discovery-engine: federated literature search and the stored corpus.
    DiscoveryEngine,
    /// scientific-processor: the `/api/stats/*` computations.
    ScientificProcessor,
}

impl Service {
    /// The reference's settings for this service. discovery-engine fans a search out to several
    /// public sources within its own ~75 s budget, hence the longer default timeout.
    pub fn spec(self) -> ServiceSpec {
        match self {
            Self::DiscoveryEngine => ServiceSpec {
                url_env: "DISCOVERY_ENGINE_URL",
                default_url: "http://discovery-engine.discovery-engine:8807",
                token_env: "DISCOVERY_ENGINE_TOKEN",
                timeout_env: "DISCOVERY_ENGINE_TIMEOUT_S",
                default_timeout_s: 90.0,
            },
            Self::ScientificProcessor => ServiceSpec {
                url_env: "SCIENTIFIC_PROCESSOR_URL",
                default_url: "http://scientific-processor.scientific-processor:8808",
                token_env: "SCIENTIFIC_PROCESSOR_TOKEN",
                timeout_env: "SCIENTIFIC_PROCESSOR_TIMEOUT_S",
                default_timeout_s: 30.0,
            },
        }
    }
}

/// One service's client from a lookup (`from_env` at runtime, a map in tests). A missing or
/// empty base is the reference's in-cluster default; an unparseable timeout is its default too.
pub fn client_from_lookup(service: Service, get: impl Fn(&str) -> Option<String>) -> PublicClient {
    let spec = service.spec();
    let base = get(spec.url_env)
        .filter(|base| !base.trim().is_empty())
        .unwrap_or_else(|| spec.default_url.to_owned());
    PublicClient::new(
        base,
        timeout_from(get(spec.timeout_env), spec.default_timeout_s),
        Duration::ZERO,
        None,
    )
}

/// The reference's `_timeout`: a positive finite number of seconds, else the default. A value
/// that cannot name a duration (NaN, infinity, zero, negative) would panic or disable the bound,
/// so it takes the default instead.
pub fn timeout_from(raw: Option<String>, default_s: f64) -> Duration {
    match raw.and_then(|value| value.trim().parse::<f64>().ok()) {
        Some(seconds) if seconds.is_finite() && seconds > 0.0 => Duration::from_secs_f64(seconds),
        _ => Duration::from_secs_f64(default_s),
    }
}

/// The per-service clients a tool resolves: an explicit override (the test seam) or the
/// deployment's environment. The reference's `get_client` / `set_client` pair.
#[derive(Clone, Default)]
pub struct Clients {
    overrides: HashMap<Service, PublicClient>,
    /// A pinned token per service; an entry of `None` forces the no-token header even when the
    /// deployment sets one (the test seam).
    tokens: HashMap<Service, Option<String>>,
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

    /// A resolver with one service's licence token pinned (`None` forces no identity header).
    pub fn with_token(mut self, service: Service, token: Option<String>) -> Self {
        self.tokens.insert(service, token);
        self
    }

    /// The client for one service: the override, else the environment's base and timeout.
    pub fn get(&self, service: Service) -> PublicClient {
        self.overrides
            .get(&service)
            .cloned()
            .unwrap_or_else(|| client_from_lookup(service, |key| std::env::var(key).ok()))
    }

    /// The service's licence token: the pinned override, else `*_TOKEN` when set and non-empty.
    /// The reference sends `X-Tenant-Id: Bearer <token>` and no identity header otherwise;
    /// identities are never forwarded from the MCP caller.
    pub fn token(&self, service: Service) -> Option<String> {
        match self.tokens.get(&service) {
            Some(token) => token.clone(),
            None => std::env::var(service.spec().token_env)
                .ok()
                .filter(|token| !token.is_empty()),
        }
    }
}

/// The optional parts of one research backend call (the reference's `call_json` keywords).
#[derive(Default)]
pub struct CallRequest<'a> {
    pub body: Option<Value>,
    pub params: Vec<(String, String)>,
    pub not_found: Option<&'a str>,
}

/// One JSON call to a research backend, with that backend's identity header (if any).
///
/// The response mapping is the reference's `_json`: a non-JSON answer is `[retryable]`, because
/// the backend may answer an HTML error page on a transient failure.
pub async fn call_json(
    clients: &Clients,
    service: Service,
    method: &str,
    path: &str,
    call: CallRequest<'_>,
) -> Result<Value, String> {
    let client = clients.get(service);
    let mut headers: Vec<(&'static str, String)> = vec![("Accept", "application/json".to_owned())];
    if let Some(token) = clients.token(service) {
        headers.push(("X-Tenant-Id", format!("Bearer {token}")));
    }
    let reply = client
        .request(
            method,
            path,
            RequestOptions {
                query: call.params,
                headers,
                json: call.body,
                not_found: call.not_found,
                ..RequestOptions::default()
            },
        )
        .await?;
    serde_json::from_slice(&reply.body)
        .map_err(|_| format!("[retryable] non-JSON answer from {method} {path}"))
}

// ── argument parsing ────────────────────────────────────────────────────────────────────────

/// One JSON number as an integer. The provider's schema accepts `1.0` as an `integer` (Draft
/// 2020-12), and the reference's Pydantic int fields coerce it, so an integral float is one.
pub fn integer_value(value: &Value) -> Option<i64> {
    if let Some(integer) = value.as_i64() {
        return Some(integer);
    }
    if let Some(integer) = value.as_u64() {
        return i64::try_from(integer).ok();
    }
    let float = value.as_f64()?;
    let in_range = (i64::MIN as f64..=i64::MAX as f64).contains(&float);
    if float.is_finite() && float.fract() == 0.0 && in_range {
        return Some(float as i64);
    }
    None
}

/// An optional integer argument; present null is absent.
pub fn optional_int(arguments: &Map<String, Value>, field: &str) -> Result<Option<i64>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => integer_value(value)
            .map(Some)
            .ok_or_else(|| format!("[permanent] invalid {field}: expected an integer")),
    }
}

/// An integer argument with the tool's own default.
pub fn int_or(arguments: &Map<String, Value>, field: &str, default: i64) -> Result<i64, String> {
    Ok(optional_int(arguments, field)?.unwrap_or(default))
}

/// An optional number argument; present null is absent.
pub fn optional_number(arguments: &Map<String, Value>, field: &str) -> Result<Option<f64>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_f64()
            .map(Some)
            .ok_or_else(|| format!("[permanent] invalid {field}: expected a number")),
    }
}

/// A number argument with the tool's own default.
pub fn number_or(arguments: &Map<String, Value>, field: &str, default: f64) -> Result<f64, String> {
    Ok(optional_number(arguments, field)?.unwrap_or(default))
}

/// The reference's `_finite`: every number a tool forwards must be finite.
pub fn finite(name: &str, value: f64) -> Result<f64, String> {
    if value.is_finite() {
        Ok(value)
    } else {
        Err(format!("[permanent] {name} must be a finite number"))
    }
}

/// An optional array of enumerated strings; present null is absent. The provider's schema also
/// enforces the same allow-list, so this refusal serves direct callers.
pub fn optional_strings(
    arguments: &Map<String, Value>,
    field: &str,
    allowed: &[&str],
) -> Result<Option<Vec<String>>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::Array(items)) => {
            let mut values = Vec::with_capacity(items.len());
            for item in items {
                match item.as_str() {
                    Some(text) if allowed.contains(&text) => values.push(text.to_owned()),
                    _ => return Err(invalid_strings(field, allowed)),
                }
            }
            Ok(Some(values))
        }
        Some(_) => Err(invalid_strings(field, allowed)),
    }
}

fn invalid_strings(field: &str, allowed: &[&str]) -> String {
    format!(
        "[permanent] invalid {field}: expected an array of {}",
        allowed.join(", ")
    )
}

/// The reference's `list(dict.fromkeys(values))`: first occurrence wins.
pub fn dedupe(values: Vec<String>) -> Vec<String> {
    let mut seen = Vec::with_capacity(values.len());
    for value in values {
        if !seen.contains(&value) {
            seen.push(value);
        }
    }
    seen
}

// ── JSON helpers, with the reference's Python value semantics ───────────────────────────────

/// The reference's `(raw.get("external_ids") or {})` stringified map: only truthy values, each
/// rendered with Python's `str`, exactly as `literature.py` builds `ext`.
pub fn external_ids(value: &Value) -> Map<String, Value> {
    let mut out = Map::new();
    if let Value::Object(fields) = value {
        for (key, value) in fields {
            if truthy(value) {
                out.insert(key.clone(), Value::String(python_str(value)));
            }
        }
    }
    out
}

/// The reference's `a or b`: the first value when Python-truthy, else the second.
pub fn or_value(first: &Value, second: &Value) -> Value {
    if truthy(first) {
        first.clone()
    } else {
        second.clone()
    }
}

/// Register the research family: the reference's `mount_research` (literature, then stats).
pub fn register(provider: &mut BuiltinProvider) {
    literature::register(provider);
    stats::register(provider);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lookup(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
            .collect();
        move |key| map.get(key).cloned()
    }

    #[test]
    fn clients_default_to_the_reference_in_cluster_services() {
        let discovery = client_from_lookup(Service::DiscoveryEngine, lookup(&[]));
        assert_eq!(
            discovery.base_url,
            "http://discovery-engine.discovery-engine:8807"
        );
        assert_eq!(discovery.timeout, Duration::from_secs(90));
        assert_eq!(discovery.min_interval, Duration::ZERO);
        assert_eq!(discovery.max_body_bytes, None);

        let processor = client_from_lookup(Service::ScientificProcessor, lookup(&[]));
        assert_eq!(
            processor.base_url,
            "http://scientific-processor.scientific-processor:8808"
        );
        assert_eq!(processor.timeout, Duration::from_secs(30));
    }

    #[test]
    fn clients_take_the_env_url_and_timeout_and_ignore_bad_values() {
        let discovery = client_from_lookup(
            Service::DiscoveryEngine,
            lookup(&[
                ("DISCOVERY_ENGINE_URL", "http://de.example:1/"),
                ("DISCOVERY_ENGINE_TIMEOUT_S", "12"),
            ]),
        );
        assert_eq!(
            (discovery.base_url.as_str(), discovery.timeout),
            ("http://de.example:1", Duration::from_secs(12))
        );
        let processor = client_from_lookup(
            Service::ScientificProcessor,
            lookup(&[
                ("SCIENTIFIC_PROCESSOR_URL", "  "),
                ("SCIENTIFIC_PROCESSOR_TIMEOUT_S", "not-a-number"),
            ]),
        );
        assert_eq!(
            processor.base_url,
            "http://scientific-processor.scientific-processor:8808"
        );
        assert_eq!(processor.timeout, Duration::from_secs(30));
    }

    #[test]
    fn integral_floats_are_integers_and_fractions_are_not() {
        assert_eq!(integer_value(&Value::from(1.0)), Some(1));
        assert_eq!(integer_value(&Value::from(3)), Some(3));
        assert_eq!(integer_value(&Value::from(1.5)), None);
        assert_eq!(integer_value(&Value::from("1")), None);
    }

    #[test]
    fn dedupe_keeps_the_first_occurrence() {
        assert_eq!(
            dedupe(vec![
                "pubmed".to_owned(),
                "arxiv".to_owned(),
                "pubmed".to_owned()
            ]),
            ["pubmed", "arxiv"]
        );
    }
}
