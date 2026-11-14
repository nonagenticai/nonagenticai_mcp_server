//! Egress, in-process limits and invocation policy: the pinned Python oracle's case list.
//!
//! `tests/fixtures/phase3b/policy.json` is produced by *executing* the archive's
//! `src/broker/{egress,limits,policy}.py` at commit `22ac1ce4` — `generate_policy.py` beside it
//! is the generator. The JSON is committed, so this test never touches the archive: the fixture
//! **is** the oracle, and a change to it is a semantic change that must be justified against the
//! Python source.
//!
//! The network cases use real `tokio` listeners. A pinned client is proved by *observing which
//! listener accepts*: the resolver's first answer is where the connection must land, a second
//! answer (which would be the attack) must never be consulted, and a refused address must never
//! produce a connection at all. The TLS handshake itself is irrelevant to the pin — a plain TCP
//! accept is the proof — so no TLS test server is needed.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use async_trait::async_trait;
use serde_json::{Map, Value, json};
use tokio::net::TcpListener;

use mcp_server_rs::catalog::ids::{AuthorityId, Uuid7};
use mcp_server_rs::catalog::models::{Constraint, ExactReference, OperationManifest};
use mcp_server_rs::config::WorkerSettings;
use mcp_server_rs::worker::broker::egress::{
    AddressCheck, EgressError, EgressPolicy, IpNetwork, PinnedClients, PlatformClients, PoolLimits,
    Resolver, address_allowed, check_hostname, embedded_addresses, parse_address, tenant_client,
};
use mcp_server_rs::worker::broker::limits::{
    RateLimitedError, RateLimits, RateLimitsError, SourceLimiter,
};
use mcp_server_rs::worker::broker::policy::{
    OwnershipRead, PolicyError, enforce, project, set_pointer, transport,
};
use mcp_server_rs::worker::creds::Clock;

const FIXTURE: &str = include_str!("fixtures/phase3b/policy.json");
/// A public DNS name the hostname policy accepts.
const HOST: &str = "tenant.example.com";

fn fixture() -> Value {
    serde_json::from_str(FIXTURE).expect("the fixture parses")
}

fn name(case: &Value) -> &str {
    case["name"].as_str().expect("a case name")
}

fn operations(fixture: &Value) -> HashMap<String, OperationManifest> {
    fixture["operations"]
        .as_object()
        .expect("operations")
        .iter()
        .map(|(key, value)| {
            (
                key.clone(),
                serde_json::from_value(value.clone()).expect("a valid operation manifest"),
            )
        })
        .collect()
}

fn object(value: &Value) -> &Map<String, Value> {
    value.as_object().expect("an object")
}

fn temporary(name: &str, bytes: &[u8]) -> PathBuf {
    let path = std::env::temp_dir().join(format!("mcp-policy-{}-{name}", std::process::id()));
    std::fs::write(&path, bytes).expect("the temporary file is writable");
    path
}

// ── a resolver whose answers change per lookup ──────────────────────────────────────────────

/// The oracle's `resolver(...)`: each answer in turn (the last repeats), counting lookups.
struct StubResolver {
    answers: Mutex<Vec<Vec<IpAddr>>>,
    calls: AtomicUsize,
}

impl StubResolver {
    fn new(answers: Vec<Vec<IpAddr>>) -> Arc<Self> {
        Arc::new(Self {
            answers: Mutex::new(answers),
            calls: AtomicUsize::new(0),
        })
    }

    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn as_resolver(self: &Arc<Self>) -> Arc<dyn Resolver> {
        Arc::clone(self) as Arc<dyn Resolver>
    }
}

#[async_trait]
impl Resolver for StubResolver {
    async fn resolve(&self, _host: &str, _port: u16) -> Vec<IpAddr> {
        let call = self.calls.fetch_add(1, Ordering::SeqCst);
        let answers = self
            .answers
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match answers.len() {
            0 => Vec::new(),
            length => answers[call.min(length - 1)].clone(),
        }
    }
}

fn loopback_only() -> AddressCheck {
    // The oracle's `loopback_ok` monkeypatch: the listener is on loopback, which the real
    // predicate correctly refuses; this test is about the pin, not the loopback rule.
    Arc::new(|address: IpAddr, _deny: &[IpNetwork]| match address {
        IpAddr::V4(ip) => ip.is_loopback(),
        IpAddr::V6(ip) => ip.is_loopback(),
    })
}

// ── egress policy: the oracle's address and hostname tables ────────────────────────────────

#[test]
fn address_policy_matches_the_oracle() {
    let fixture = fixture();
    let cases = fixture["egress"]["addresses"]
        .as_array()
        .expect("addresses");
    assert!(!cases.is_empty());
    for case in cases {
        let text = case["address"].as_str().expect("an address");
        let deny: Vec<IpNetwork> = case["deny"]
            .as_array()
            .expect("deny networks")
            .iter()
            .map(|cidr| IpNetwork::parse(cidr.as_str().expect("a CIDR")).expect("a valid CIDR"))
            .collect();
        let address = parse_address(text).unwrap_or_else(|| panic!("{text} parses"));
        assert_eq!(
            address_allowed(address, &deny),
            case["allowed"].as_bool().expect("allowed"),
            "address {text} with deny {deny:?}"
        );
    }
}

#[test]
fn embedded_addresses_match_the_oracle() {
    let fixture = fixture();
    for case in fixture["egress"]["embedded"].as_array().expect("embedded") {
        let text = case["address"].as_str().expect("an address");
        let address = parse_address(text).expect("an address");
        let expected: Vec<IpAddr> = case["embedded"]
            .as_array()
            .expect("embedded list")
            .iter()
            .map(|value| parse_address(value.as_str().expect("an address")).expect("an address"))
            .collect();
        assert_eq!(embedded_addresses(address), expected, "address {text}");
    }
}

#[test]
fn hostname_policy_matches_the_oracle() {
    let fixture = fixture();
    for case in fixture["egress"]["hostnames"]
        .as_array()
        .expect("hostnames")
    {
        let host = case["host"].as_str().expect("a hostname");
        if case["accepted"].as_bool().expect("accepted") {
            assert_eq!(
                check_hostname(host).expect("an accepted hostname"),
                case["normalized"].as_str().expect("normalized"),
                "hostname {host}"
            );
        } else {
            assert_eq!(
                check_hostname(host),
                Err(EgressError::SsrfBlocked),
                "hostname {host}"
            );
        }
    }
}

// ── egress policy: resolution and the pin ──────────────────────────────────────────────────

#[tokio::test]
async fn only_allow_listed_ports_are_resolved() {
    let resolver = StubResolver::new(vec![vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]]);
    let policy = EgressPolicy::new(&[443], &[], resolver.as_resolver()).expect("a policy");
    for port in [80, 8443, 22] {
        assert_eq!(
            policy.validated(HOST, port).await,
            Err(EgressError::SsrfBlocked)
        );
    }
    assert_eq!(resolver.calls(), 0, "a refused port never resolves");
    // `from_settings` keeps the reference defaults: 443 only.
    let fallback = StubResolver::new(vec![vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))]]);
    let settings = EgressPolicy::from_settings(&WorkerSettings::default(), fallback.as_resolver());
    assert_eq!(
        settings.validated(HOST, 8443).await,
        Err(EgressError::SsrfBlocked)
    );
    assert_eq!(fallback.calls(), 0);
}

#[tokio::test]
async fn mixed_public_and_private_answers_are_refused_entirely() {
    let resolver = StubResolver::new(vec![vec![
        IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8)),
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)),
    ]]);
    let policy = EgressPolicy::new(&[443], &[], resolver.as_resolver()).expect("a policy");
    assert_eq!(
        policy.validated(HOST, 443).await,
        Err(EgressError::SsrfBlocked),
        "one bad answer poisons the whole set"
    );
}

#[tokio::test]
async fn empty_or_unresolvable_answers_are_refused() {
    let resolver = StubResolver::new(Vec::new());
    let policy = EgressPolicy::new(&[443], &[], resolver.as_resolver()).expect("a policy");
    assert_eq!(
        policy.validated(HOST, 443).await,
        Err(EgressError::Transport)
    );
}

#[tokio::test]
async fn a_refused_address_never_reaches_the_listener() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("a listener");
    let port = listener.local_addr().expect("an address").port();
    let resolver = StubResolver::new(vec![vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]]);
    let policy = Arc::new(EgressPolicy::new(&[port], &[], resolver.as_resolver()).expect("policy"));
    let clients = PinnedClients::new(policy, PoolLimits::default());
    assert_eq!(
        clients.clients(HOST, port, None).await.err(),
        Some(EgressError::SsrfBlocked)
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err(),
        "a refused address reached the listener"
    );
}

#[tokio::test]
async fn the_connection_uses_the_validated_address_and_resolves_once() {
    let first = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .await
        .expect("the first listener");
    let port = first.local_addr().expect("an address").port();
    // The second listener is the address a *second*, later resolution would return — the
    // attack this pin exists to stop. It lives on the other loopback family at the same port.
    let second = TcpListener::bind((Ipv6Addr::LOCALHOST, port))
        .await
        .expect("the second listener");
    let resolver = StubResolver::new(vec![
        vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
        vec![IpAddr::V6(Ipv6Addr::LOCALHOST)],
    ]);
    let policy = Arc::new(
        EgressPolicy::new(&[port], &[], resolver.as_resolver())
            .expect("a policy")
            .with_address_check(loopback_only()),
    );
    let clients = PinnedClients::new(policy, PoolLimits::default());
    let pinned = clients
        .clients(HOST, port, None)
        .await
        .expect("pinned clients");
    assert_eq!(pinned.len(), 1);
    let (address, client) = pinned.into_iter().next().expect("one client");
    assert_eq!(address, (Ipv4Addr::LOCALHOST, port).into());

    let url: reqwest::Url = format!("https://{HOST}:{port}/records")
        .parse()
        .expect("a URL");
    let request = reqwest::Request::new(reqwest::Method::GET, url);
    let probe = Arc::clone(&client);
    let task = tokio::spawn(async move { probe.execute(request).await });

    let (stream, _) = tokio::time::timeout(Duration::from_secs(2), first.accept())
        .await
        .expect("the validated address is connected")
        .expect("a connection");
    drop(stream);
    assert!(
        tokio::time::timeout(Duration::from_millis(300), second.accept())
            .await
            .is_err(),
        "the second resolver answer was consulted"
    );
    assert_eq!(resolver.calls(), 1, "the host resolved exactly once");

    task.abort();
    let _ = task.await;

    // The same client refuses a non-https destination before any byte is written.
    let plain: reqwest::Url = format!("http://{HOST}:{port}/records")
        .parse()
        .expect("a URL");
    let request = reqwest::Request::new(reqwest::Method::GET, plain);
    assert_eq!(
        client.execute(request).await.err(),
        Some(EgressError::SsrfBlocked)
    );
}

#[tokio::test]
async fn every_validated_address_gets_one_pinned_client_and_is_cached() {
    let resolver = StubResolver::new(vec![vec![
        IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V4(Ipv4Addr::new(127, 0, 0, 2)),
    ]]);
    let policy = Arc::new(
        EgressPolicy::new(&[443], &[], resolver.as_resolver())
            .expect("a policy")
            .with_address_check(loopback_only()),
    );
    let clients = PinnedClients::new(policy, PoolLimits::default());
    let pinned = clients
        .clients(HOST, 443, None)
        .await
        .expect("pinned clients");
    assert_eq!(pinned.len(), 2);
    assert_eq!(pinned[0].0, (Ipv4Addr::LOCALHOST, 443).into());
    assert_eq!(pinned[1].0, (Ipv4Addr::new(127, 0, 0, 2), 443).into());
    let again = clients
        .clients(HOST, 443, None)
        .await
        .expect("cached clients");
    assert!(
        Arc::ptr_eq(&pinned[0].1, &again[0].1),
        "the cache is reused"
    );
    assert!(Arc::ptr_eq(&pinned[1].1, &again[1].1));
}

#[test]
fn platform_clients_pool_per_ca_file() {
    let pool = PlatformClients::new(PoolLimits::default());
    let default = pool.client_for(None).expect("the default client");
    let same = pool.client_for(None).expect("the cached default client");
    assert!(Arc::ptr_eq(&default, &same), "one client per CA bundle");
    assert_eq!(
        pool.client_for(Some(Path::new("/nonexistent/ca.pem")))
            .err(),
        Some(EgressError::Transport),
        "a missing CA bundle never falls back to the system roots"
    );
    // The tenant client builder itself is well-formed (the pin is added per host).
    let resolver = StubResolver::new(Vec::new());
    let policy = EgressPolicy::new(&[443], &[], resolver.as_resolver()).expect("a policy");
    tenant_client(&policy, None)
        .build()
        .expect("a usable builder");
}

// ── invocation policy: transport, projection and scope rules ───────────────────────────────

#[test]
fn transport_matches_the_oracle() {
    let fixture = fixture();
    let operations = operations(&fixture);
    let cases = fixture["transport"].as_array().expect("transport cases");
    assert!(!cases.is_empty());
    for case in cases {
        let operation = operations
            .get(case["operation"].as_str().expect("an operation"))
            .unwrap_or_else(|| panic!("case {}: unknown operation", name(case)));
        let arguments = object(&case["arguments"]);
        let context = object(&case["context"]);
        let result = transport(operation, arguments, context);
        if case.get("refused").is_some() {
            let error = result.err().unwrap_or_else(|| {
                panic!("case {}: transport accepted a refused case", name(case))
            });
            match case["error"].as_str().expect("an error kind") {
                "ExecutionDeniedError" => assert_eq!(
                    error,
                    PolicyError::Denied,
                    "case {}: a denial is a denial",
                    name(case)
                ),
                "ValueError" => assert_eq!(
                    error,
                    PolicyError::MissingPointer,
                    "case {}: a missing pointer",
                    name(case)
                ),
                other => panic!("case {}: unexpected oracle error {other}", name(case)),
            }
            continue;
        }
        let request = result
            .unwrap_or_else(|error| panic!("case {}: transport refused ({error})", name(case)));
        let expected = &case["expected"];
        assert_eq!(
            request.path,
            expected["path"].as_str().expect("path"),
            "case {}",
            name(case)
        );
        assert_eq!(
            serde_json::to_value(&request.query).expect("query"),
            expected["query"],
            "case {}: query",
            name(case)
        );
        assert_eq!(
            serde_json::to_value(&request.headers).expect("headers"),
            expected["headers"],
            "case {}: headers",
            name(case)
        );
        assert_eq!(
            serde_json::to_value(&request.body).expect("body"),
            expected["body"],
            "case {}: body",
            name(case)
        );
    }
}

#[test]
fn projection_matches_the_oracle() {
    let fixture = fixture();
    let operations = operations(&fixture);
    for case in fixture["projection"].as_array().expect("projection cases") {
        let operation = operations
            .get(case["operation"].as_str().expect("an operation"))
            .unwrap_or_else(|| panic!("case {}: unknown operation", name(case)));
        let result = project(operation, &case["value"]);
        if case.get("refused").is_some() {
            let error = result.err().unwrap_or_else(|| {
                panic!("case {}: projection accepted a refused case", name(case))
            });
            match case["error"].as_str().expect("an error kind") {
                "ExecutionDeniedError" => {
                    assert_eq!(error, PolicyError::Denied, "case {}", name(case))
                }
                "ValueError" => {
                    assert_eq!(error, PolicyError::MissingPointer, "case {}", name(case))
                }
                other => panic!("case {}: unexpected oracle error {other}", name(case)),
            }
            continue;
        }
        assert_eq!(
            result.unwrap_or_else(|error| panic!("case {}: refused ({error})", name(case))),
            case["expected"],
            "case {}",
            name(case)
        );
    }
}

struct StubOwnership {
    result: Option<Value>,
    calls: AtomicUsize,
    seen: Mutex<Vec<String>>,
}

impl StubOwnership {
    fn new(result: Option<Value>) -> Self {
        Self {
            result,
            calls: AtomicUsize::new(0),
            seen: Mutex::new(Vec::new()),
        }
    }
}

#[async_trait]
impl OwnershipRead for StubOwnership {
    async fn read(
        &self,
        reference: &ExactReference,
        _arguments: &Map<String, Value>,
    ) -> Result<Value, PolicyError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .push(reference.id.as_str().to_owned());
        match &self.result {
            Some(value) => Ok(value.clone()),
            None => panic!("an ownership read was not expected"),
        }
    }
}

#[tokio::test]
async fn scope_rules_match_the_oracle() {
    let fixture = fixture();
    let cases = fixture["constraints"].as_array().expect("constraint cases");
    assert!(!cases.is_empty());
    for case in cases {
        let rules: Vec<Constraint> = case["rules"]
            .as_array()
            .expect("rules")
            .iter()
            .map(|rule| serde_json::from_value(rule.clone()).expect("a valid constraint"))
            .collect();
        let ownership = StubOwnership::new(
            case["ownership_result"]
                .as_object()
                .map(|_| case["ownership_result"].clone()),
        );
        let result = enforce(
            &rules,
            object(&case["arguments"]),
            object(&case["context"]),
            &ownership,
        )
        .await;
        if case.get("accepted").is_some() {
            result.unwrap_or_else(|error| {
                panic!("case {}: a valid call was refused ({error})", name(case))
            });
        } else {
            let error = result
                .err()
                .unwrap_or_else(|| panic!("case {}: an invalid call was accepted", name(case)));
            match case["error"].as_str().expect("an error kind") {
                "ExecutionDeniedError" => {
                    assert_eq!(error, PolicyError::Denied, "case {}", name(case))
                }
                "ValueError" => assert!(
                    // The reference's `ValueError` covers both a missed pointer and an invalid
                    // canonical path; this port carries the former as `MissingPointer` and the
                    // latter as a rule failure (`Denied`).
                    matches!(error, PolicyError::MissingPointer | PolicyError::Denied),
                    "case {}: an invalid value",
                    name(case)
                ),
                // The reference raises `AttributeError` for a non-string path value; this port
                // refuses it like any other invalid value.
                "AttributeError" | "TypeError" => {}
                other => panic!("case {}: unexpected oracle error {other}", name(case)),
            }
        }
        let expected_calls = case["ownership_calls"].as_array().expect("calls");
        assert_eq!(
            ownership.calls.load(Ordering::SeqCst),
            expected_calls.len(),
            "case {}: ownership read count",
            name(case)
        );
        let seen = ownership
            .seen
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone();
        let expected: Vec<&str> = expected_calls
            .iter()
            .map(|call| call["reference"].as_str().expect("a reference"))
            .collect();
        let seen: Vec<&str> = seen.iter().map(String::as_str).collect();
        assert_eq!(seen, expected, "case {}: ownership reference", name(case));
    }
}

#[test]
fn set_pointer_unescapes_and_replaces_the_whole_body() {
    let mut target = Map::new();
    target.insert("keep".to_owned(), json!(1));
    assert_eq!(
        set_pointer(target.clone(), "/a~1b/c~0d", json!(2)).expect("a valid pointer"),
        Map::from_iter([
            ("keep".to_owned(), json!(1)),
            ("a/b".to_owned(), json!({"c~d": 2})),
        ])
    );
    assert_eq!(
        set_pointer(target, "", json!({"whole": "body"})).expect("an empty pointer"),
        Map::from_iter([("whole".to_owned(), json!("body"))])
    );
    assert_eq!(
        set_pointer(Map::new(), "", json!(1)),
        Err(PolicyError::Denied),
        "the map-shaped entry point cannot carry a scalar body"
    );
    assert_eq!(
        set_pointer(Map::new(), "relative", json!(1)),
        Err(PolicyError::Denied)
    );
}

// ── in-process limiter ──────────────────────────────────────────────────────────────────────

fn fake_clock() -> (Clock, Arc<Mutex<f64>>) {
    let now = Arc::new(Mutex::new(0.0_f64));
    let handle = Arc::clone(&now);
    let clock: Clock =
        Arc::new(move || *handle.lock().unwrap_or_else(|poison| poison.into_inner()));
    (clock, now)
}

#[test]
fn limiter_caps_rate_and_concurrency_per_tenant_and_service() {
    let (clock, now) = fake_clock();
    let limiter = SourceLimiter::with_clock(3, 2, clock);
    let first = limiter.acquire("t", "s").expect("the first call");
    let second = limiter.acquire("t", "s").expect("the second call");
    assert_eq!(
        limiter.acquire("t", "s").err(),
        Some(RateLimitedError),
        "concurrency is 2"
    );
    limiter
        .acquire("t", "other")
        .expect("another service is independent");
    limiter
        .acquire("u", "s")
        .expect("another tenant is independent");
    first.release();
    let third = limiter
        .acquire("t", "s")
        .expect("a released slot is reusable");
    second.release();
    third.release();
    assert_eq!(
        limiter.acquire("t", "s").err(),
        Some(RateLimitedError),
        "3 calls in the minute"
    );
    *now.lock().expect("the clock") = 61.0;
    limiter
        .acquire("t", "s")
        .expect("the window has rolled over")
        .release();
}

#[test]
fn a_dropped_slot_releases_the_in_flight_count() {
    let (clock, _) = fake_clock();
    let limiter = SourceLimiter::with_clock(10, 1, clock);
    drop(
        limiter
            .acquire("t", "s")
            .expect("the only concurrency slot"),
    );
    limiter
        .acquire("t", "s")
        .expect("drop released the slot")
        .release();
}

// ── deployment limits ──────────────────────────────────────────────────────────────────────

#[test]
fn rate_limits_file_matches_the_oracle() {
    let fixture = fixture();
    let limits = &fixture["limits"];
    assert_eq!(
        RateLimits::read(None).expect("the default").limits,
        Vec::new()
    );
    assert_eq!(
        RateLimits::read(None).expect("the default").schema_version,
        1
    );

    for case in limits["accepted"].as_array().expect("accepted tables") {
        let payload = serde_json::to_string(&case["payload"]).expect("payload text");
        let path = temporary(name(case), payload.as_bytes());
        let table = RateLimits::read(Some(&path)).expect("an accepted table");
        let expected = case["limits"].as_array().expect("limits");
        assert_eq!(table.limits.len(), expected.len());
        for (actual, expected) in table.limits.iter().zip(expected) {
            assert_eq!(
                actual.service_id.as_str(),
                expected["service_id"].as_str().expect("a service id")
            );
            match (&actual.tenant_id, expected["tenant_id"].as_str()) {
                (Some(actual), Some(expected)) => assert_eq!(actual.as_str(), expected),
                (None, None) => {}
                other => panic!("case {}: tenant mismatch {other:?}", name(case)),
            }
            assert_eq!(
                actual.calls_per_minute,
                expected["calls_per_minute"].as_u64().expect("calls") as u32
            );
            assert_eq!(
                actual.concurrency,
                expected["concurrency"].as_u64().expect("concurrency") as u32
            );
        }
        let _ = std::fs::remove_file(path);
    }

    for case in limits["refused"].as_array().expect("refused tables") {
        let path = temporary(
            name(case),
            case["bytes"].as_str().expect("bytes").as_bytes(),
        );
        let expected = match case["error"].as_str().expect("an error kind") {
            "invalid" => RateLimitsError::Invalid,
            "duplicate" => RateLimitsError::Duplicate,
            "too_large" => RateLimitsError::TooLarge,
            other => panic!("case {}: unexpected error {other}", name(case)),
        };
        assert_eq!(
            RateLimits::read(Some(&path)).err(),
            Some(expected),
            "case {}",
            name(case)
        );
        let _ = std::fs::remove_file(path);
    }

    let oversized = limits["oversized"].as_object().expect("oversized case");
    let length = oversized["length"].as_u64().expect("length") as usize;
    let fill = oversized["fill"].as_str().expect("fill").as_bytes()[0];
    let path = temporary("oversized", &vec![fill; length]);
    assert_eq!(
        RateLimits::read(Some(&path)).err(),
        Some(RateLimitsError::TooLarge)
    );
    let _ = std::fs::remove_file(path);
}

#[test]
fn rate_limits_ceiling_matches_the_oracle() {
    let fixture = fixture();
    let limits = &fixture["limits"];
    let accepted = limits["accepted"]
        .as_array()
        .expect("accepted tables")
        .iter()
        .find(|case| case["name"] == "accepted_table")
        .expect("the accepted table");
    let payload = serde_json::to_string(&accepted["payload"]).expect("payload text");
    let path = temporary("ceiling", payload.as_bytes());
    let table = RateLimits::read(Some(&path)).expect("an accepted table");
    for case in limits["ceilings"].as_array().expect("ceiling cases") {
        let tenant = AuthorityId::new(case["tenant"].as_str().expect("a tenant"))
            .expect("a tenant identity");
        let service =
            Uuid7::new(case["service"].as_str().expect("a service")).expect("a service identity");
        let calls = case["calls"].as_u64().expect("calls") as u32;
        let concurrency = case["concurrency"].as_u64().expect("concurrency") as u32;
        let expected = case["expected"].as_array().expect("expected");
        assert_eq!(
            table.ceiling(&tenant, &service, calls, concurrency),
            (
                expected[0].as_u64().expect("calls") as u32,
                expected[1].as_u64().expect("concurrency") as u32
            ),
            "case {}",
            name(case)
        );
    }
    let _ = std::fs::remove_file(path);
}
