//! The web builtin family: `web_scrape`, the SSRF guard on the LLM-supplied URL, and the
//! webscraper `/api/scrape/url` contract, over a loopback stub.
//!
//! The guard is exercised with literal addresses (the reference's blocked list), and with the
//! resolver pinned through the same seam the reference's tests use (`set_client(_resolve)`), so
//! no test touches real DNS. The expected description and input schema are the reference's own
//! `tools/list` output (FastMCP 4.1.4 on the archive's `src/builtin/web/`).

use std::collections::{HashMap, VecDeque};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Map, Value, json};

use mcp_server_rs::builtin::BuiltinProvider;
use mcp_server_rs::builtin::legal::{PublicClient, USER_AGENT};
use mcp_server_rs::builtin::scope::{BuiltinCaller, CallerKind};
use mcp_server_rs::builtin::web::{self, scrape::Clients};

// ── a loopback webscraper that records every request ───────────────────────────────────────

type Endpoint = (String, String);
type Routes = Arc<Mutex<HashMap<Endpoint, VecDeque<Reply>>>>;

#[derive(Clone)]
struct Stub {
    routes: Routes,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

#[derive(Clone)]
struct Reply {
    status: StatusCode,
    body: Vec<u8>,
    content_type: Option<&'static str>,
    delay: Option<Duration>,
}

#[derive(Clone, Debug)]
struct Recorded {
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Stub {
    fn json(&self, method: &str, path: &str, status: StatusCode, body: Value) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body: serde_json::to_vec(&body).expect("a JSON reply"),
                content_type: Some("application/json"),
                delay: None,
            });
    }

    fn text(&self, method: &str, path: &str, status: StatusCode, body: &str) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body: body.as_bytes().to_vec(),
                content_type: Some("text/html; charset=utf-8"),
                delay: None,
            });
    }

    fn slow_json(&self, method: &str, path: &str, body: Value, delay: Duration) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status: StatusCode::OK,
                body: serde_json::to_vec(&body).expect("a JSON reply"),
                content_type: Some("application/json"),
                delay: Some(delay),
            });
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("an unpoisoned stub").clone()
    }
}

async fn local_server() -> (String, Stub) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback stub");
    let address = listener.local_addr().expect("a loopback address");
    let stub = Stub {
        routes: Arc::default(),
        requests: Arc::default(),
    };
    let app = Router::new().fallback(any(handle)).with_state(stub.clone());
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), stub)
}

async fn handle(State(stub): State<Stub>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let body = to_bytes(body, 8 * 1024 * 1024)
        .await
        .expect("the request body")
        .to_vec();
    let headers = parts
        .headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_owned(), value.to_owned()))
        })
        .collect();
    let key = (
        parts.method.as_str().to_owned(),
        parts.uri.path().to_owned(),
    );
    stub.requests
        .lock()
        .expect("an unpoisoned stub")
        .push(Recorded {
            method: parts.method.as_str().to_owned(),
            path: parts.uri.path().to_owned(),
            headers,
            body,
        });
    let reply = stub
        .routes
        .lock()
        .expect("an unpoisoned stub")
        .get_mut(&key)
        .and_then(VecDeque::pop_front);
    let Some(reply) = reply else {
        let body = serde_json::to_string(&json!({"message": "not found"})).expect("a JSON body");
        return (StatusCode::NOT_FOUND, body).into_response();
    };
    if let Some(delay) = reply.delay {
        tokio::time::sleep(delay).await;
    }
    let mut response = Response::new(axum::body::Body::from(reply.body));
    *response.status_mut() = reply.status;
    if let Some(content_type) = reply.content_type {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(content_type),
        );
    }
    response
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────

fn public_client(base: &str) -> PublicClient {
    PublicClient::new(base, Duration::from_secs(20), Duration::ZERO, None)
}

fn clients_for(base: &str) -> Clients {
    Clients::from_env()
        .with(public_client(base))
        .with_token(None)
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("an arguments object")
}

fn only(stub: &Stub) -> Recorded {
    let mut requests = stub.requests();
    assert_eq!(requests.len(), 1, "exactly one upstream request");
    requests.pop().expect("one request")
}

fn json_body(request: &Recorded) -> Value {
    serde_json::from_slice(&request.body).expect("a JSON request body")
}

fn header<'a>(request: &'a Recorded, name: &str) -> Option<&'a str> {
    request.headers.get(name).map(String::as_str)
}

fn researcher() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::KeycloakService,
        subject: "carebus-researcher".to_owned(),
        scope: "carebus-researcher".to_owned(),
        tenant_id: None,
        license_id: None,
        strata_token: None,
    }
}

fn executor() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::KeycloakService,
        subject: "carebus-tool-executor".to_owned(),
        scope: "carebus-tool-executor".to_owned(),
        tenant_id: None,
        license_id: None,
        strata_token: None,
    }
}

fn licence_caller() -> BuiltinCaller {
    BuiltinCaller {
        kind: CallerKind::CarebusLicence,
        subject: "svc:10000000-0000-7000-8000-000000000001:care-bus".to_owned(),
        scope: "licence:care-bus".to_owned(),
        tenant_id: Some("10000000-0000-7000-8000-000000000001".to_owned()),
        license_id: None,
        strata_token: None,
    }
}

fn public_address() -> IpAddr {
    "93.184.215.14".parse().expect("a public address")
}

fn scraped() -> Value {
    json!({
        "url": "https://example.com/a",
        "final_url": "https://www.example.com/a",
        "title": "Example",
        "text_content": "Hello world. ".repeat(10),
        "markdown_content": "# Hello",
        "status": "completed",
        "error": null,
    })
}

fn scraped_with(text: &str) -> Value {
    let mut answer = scraped();
    answer["text_content"] = json!(text);
    answer
}

fn failed_with(error: Value) -> Value {
    let mut answer = scraped();
    answer["status"] = json!("failed");
    answer["error"] = error;
    answer
}

// ── the tool contract ──────────────────────────────────────────────────────────────────────

#[test]
fn the_registry_is_exactly_the_web_contract() {
    let mut provider = BuiltinProvider::new();
    web::register(&mut provider);

    let tools = provider.list(&researcher());
    assert_eq!(tools.len(), 1, "the web contract is 1 tool");
    assert_eq!(tools[0].name.as_ref(), "web_scrape");
    assert_eq!(
        tools[0].description.as_deref(),
        Some("Fetch one public web page (http/https) and return its title and readable text.")
    );
    assert_eq!(
        Value::Object((*tools[0].input_schema).clone()),
        json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "url": {"type": "string"},
                "max_chars": {"default": 30000, "type": "integer"},
            },
            "required": ["url"],
        })
    );

    assert_eq!(provider.list(&licence_caller()).len(), 1);
    assert!(provider.list(&executor()).is_empty());
}

// ── the scrape contract ────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn scrape_calls_the_webscraper_and_maps_the_answer() {
    let (base, stub) = local_server().await;
    stub.json("POST", "/api/scrape/url", StatusCode::OK, scraped());
    let clients = clients_for(&base).with_resolved(vec![public_address()]);

    let out = web::scrape::scrape(
        &clients,
        &args(json!({"url": "https://example.com/a", "max_chars": 500})),
    )
    .await
    .expect("a scrape");
    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/scrape/url");
    assert_eq!(
        json_body(&request),
        json!({"url": "https://example.com/a", "scraper_type": "auto", "timeout": 30.0})
    );
    assert_eq!(header(&request, "user-agent"), Some(USER_AGENT));
    assert_eq!(header(&request, "x-tenant-id"), None);
    assert_eq!(
        out,
        json!({
            "url": "https://example.com/a",
            "final_url": "https://www.example.com/a",
            "title": "Example",
            "text": "Hello world. ".repeat(10),
            "truncated": false,
        })
    );
}

#[tokio::test]
async fn scrape_sends_the_licence_token_when_configured() {
    let (base, stub) = local_server().await;
    stub.json("POST", "/api/scrape/url", StatusCode::OK, scraped());
    let clients = clients_for(&base)
        .with_token(Some("lic-abc".to_owned()))
        .with_resolved(vec![public_address()]);
    web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect("a scrape");
    assert_eq!(header(&only(&stub), "x-tenant-id"), Some("Bearer lic-abc"));
}

#[tokio::test]
async fn scrape_truncates_and_clamps_the_text_bound() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::OK,
        scraped_with(&"x".repeat(5000)),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let out = web::scrape::scrape(
        &clients,
        &args(json!({"url": "https://example.com/a", "max_chars": 1000})),
    )
    .await
    .expect("a scrape");
    assert_eq!(out["truncated"], Value::Bool(true));
    assert_eq!(out["text"].as_str().unwrap().chars().count(), 1000);

    // The floor is 500 characters (`max(500, min(max_chars, 200000))`).
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::OK,
        scraped_with(&"x".repeat(5000)),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let out = web::scrape::scrape(
        &clients,
        &args(json!({"url": "https://example.com/a", "max_chars": 10})),
    )
    .await
    .expect("a scrape");
    assert_eq!(out["text"].as_str().unwrap().chars().count(), 500);
}

#[tokio::test]
async fn scrape_falls_back_to_markdown_and_the_requested_urls() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::OK,
        json!({
            "url": null,
            "final_url": null,
            "title": "Fallback",
            "text_content": "",
            "markdown_content": "# Hello",
            "status": "completed",
        }),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let out = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect("a scrape");
    assert_eq!(out["text"], "# Hello");
    assert_eq!(out["url"], "https://example.com/a");
    assert_eq!(out["final_url"], "https://example.com/a");
}

#[tokio::test]
async fn scrape_failed_status_is_permanent() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::OK,
        failed_with(json!("403 from site")),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a failed scrape");
    assert_eq!(error, "[permanent] scrape failed: 403 from site");

    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::OK,
        failed_with(Value::Null),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a failed scrape");
    assert_eq!(error, "[permanent] scrape failed: unknown");
}

#[tokio::test]
async fn scrape_maps_the_upstream_error_classes() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/scrape/url",
        StatusCode::INTERNAL_SERVER_ERROR,
        json!({"detail": "Scraping failed"}),
    );
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a 500");
    assert!(
        error.starts_with("[retryable] 500 from POST /api/scrape/url: "),
        "{error}"
    );

    let (base, _stub) = local_server().await;
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a 404");
    assert_eq!(
        error,
        "[permanent] 404 from POST /api/scrape/url: not found"
    );
}

#[tokio::test]
async fn scrape_timeout_unreachable_and_non_json_are_retryable() {
    let (base, stub) = local_server().await;
    stub.slow_json(
        "POST",
        "/api/scrape/url",
        scraped(),
        Duration::from_millis(300),
    );
    let clients = Clients::from_env()
        .with(PublicClient::new(
            &base,
            Duration::from_millis(50),
            Duration::ZERO,
            None,
        ))
        .with_token(None)
        .with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a timeout");
    assert!(error.starts_with("[retryable] timeout after"), "{error}");

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    let clients = clients_for(&format!("http://{address}")).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a connect error");
    assert!(error.starts_with("[retryable] cannot reach"), "{error}");
    assert!(error.contains("ConnectError"), "{error}");

    let (base, stub) = local_server().await;
    stub.text("POST", "/api/scrape/url", StatusCode::OK, "<html>");
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a non-JSON answer");
    assert_eq!(error, "[retryable] non-JSON answer from the webscraper");
}

#[tokio::test]
async fn a_missing_webscraper_url_is_permanent() {
    let clients = Clients::from_env()
        .with_url(None)
        .with_token(None)
        .with_resolved(vec![public_address()]);
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect_err("a missing URL");
    assert_eq!(
        error,
        "[permanent] WEBSCRAPER_URL is not set on the MCP server"
    );
}

// ── the SSRF guard ────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn ssrf_urls_are_rejected_before_any_request() {
    let (base, stub) = local_server().await;
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let blocked = [
        "file:///etc/passwd",
        "ftp://example.com/x",
        "gopher://example.com/",
        "javascript:alert(1)",
        "http://127.0.0.1/",
        "http://127.0.0.1:9119/api/scrape/url",
        "http://10.42.0.5:8033/mcp",
        "http://192.168.1.1/",
        "http://172.16.0.1/",
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "http://[fe80::1]/",
        "http://[::ffff:127.0.0.1]/",
        "http://0.0.0.0/",
        "http://100.64.0.1/",
        "http://localhost/",
        "http://LOCALHOST./",
        "http://webscraper/",
        "http://2130706433/",
        "http://blocked.svc.cluster.local:9119/",
        "http://blocked.internal/",
        "http://printer.local/",
        "http://user:pw@example.com/",
        "http://example.com:22/",
        "http:///nohost",
        "https://example.com:99999/",
        "http://[127.0.0.1]/",
        "http://[::1]x/",
        "",
    ];
    for url in blocked {
        let error = web::scrape::scrape(&clients, &args(json!({"url": url})))
            .await
            .expect_err("a refused url");
        assert!(error.starts_with("[permanent] url"), "{url:?} -> {error}");
    }
    assert!(stub.requests().is_empty(), "no request leaves on a refusal");
}

#[tokio::test]
async fn the_guard_names_the_why_of_a_refusal() {
    let (base, _stub) = local_server().await;
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    let cases = [
        (
            "https://example.com:99999/",
            "[permanent] url not allowed (malformed): 'https://example.com:99999/'",
        ),
        (
            "file:///etc/passwd",
            "[permanent] url not allowed (scheme must be http or https): 'file:///etc/passwd'",
        ),
        (
            "http://user:pw@example.com/",
            "[permanent] url not allowed (credentials in url): 'http://user:pw@example.com/'",
        ),
        (
            "http:///nohost",
            "[permanent] url not allowed (no host): 'http:///nohost'",
        ),
        (
            "http://example.com:22/",
            "[permanent] url not allowed (non-standard port): 'http://example.com:22/'",
        ),
        (
            "http://webscraper/",
            "[permanent] url not allowed (internal host name): 'http://webscraper/'",
        ),
        (
            "http://10.42.0.5/mcp",
            "[permanent] url not allowed (private, loopback or link-local address): \
             'http://10.42.0.5/mcp'",
        ),
    ];
    for (url, message) in cases {
        let error = web::scrape::scrape(&clients, &args(json!({"url": url})))
            .await
            .expect_err("a refused url");
        assert_eq!(error, message, "{url}");
    }
}

#[tokio::test]
async fn a_hostname_must_resolve_to_public_addresses() {
    for resolved in [
        vec!["127.0.0.1".parse().unwrap()],
        vec![
            "93.184.215.14".parse().unwrap(),
            "10.0.0.7".parse().unwrap(),
        ],
        Vec::new(),
    ] {
        let (base, stub) = local_server().await;
        let clients = clients_for(&base).with_resolved(resolved);
        let error = web::scrape::scrape(
            &clients,
            &args(json!({"url": "https://rebind.example.com/"})),
        )
        .await
        .expect_err("a refused host");
        assert!(error.starts_with("[permanent] url not allowed"), "{error}");
        assert!(stub.requests().is_empty());
    }
}

#[tokio::test]
async fn an_unresolvable_host_is_rejected() {
    let (base, stub) = local_server().await;
    let clients = clients_for(&base).with_unresolvable_host();
    let error = web::scrape::scrape(&clients, &args(json!({"url": "https://nx.example.com/"})))
        .await
        .expect_err("an unresolvable host");
    assert_eq!(
        error,
        "[permanent] url not allowed (host does not resolve): 'https://nx.example.com/'"
    );
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn a_public_literal_and_a_public_resolution_are_allowed() {
    let (base, stub) = local_server().await;
    stub.json("POST", "/api/scrape/url", StatusCode::OK, scraped());
    stub.json("POST", "/api/scrape/url", StatusCode::OK, scraped());
    let clients = clients_for(&base).with_resolved(vec![public_address()]);
    web::scrape::scrape(&clients, &args(json!({"url": "http://93.184.215.14/"})))
        .await
        .expect("a public literal");
    web::scrape::scrape(&clients, &args(json!({"url": "https://example.com/a"})))
        .await
        .expect("a public resolution");
    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(json_body(&requests[0])["url"], "http://93.184.215.14/");
    assert_eq!(json_body(&requests[1])["url"], "https://example.com/a");
}
