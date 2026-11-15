//! The research builtin family: the 5 wire tools, their exact upstream calls, parsing and error
//! mapping, over loopback stubs.
//!
//! Every test starts a real axum server on `127.0.0.1:0` and records what the client actually
//! put on the wire (method, path, query, headers, body). The expected descriptions and input
//! schemas are the reference's own `tools/list` output (FastMCP 4.1.4 on the archive's
//! `src/builtin/research/`); fixtures are trimmed copies of the archive's recorded real answers
//! (`tests/test_research_tools.py`), and the statistics expectations are computed from the
//! reference service's own formulas (stated at each helper).
//!
//! The three statistics tools perform no arithmetic here: the reference forwards them to
//! scientific-processor, and so does this port. Their tests therefore build the upstream answer
//! with the reference's formulas and assert the exact request body and output mapping.

use std::collections::{HashMap, VecDeque};
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
use mcp_server_rs::builtin::research::{
    self, Clients, Service, client_from_lookup, finite, literature, stats,
};
use mcp_server_rs::builtin::scope::{BuiltinCaller, CallerKind};

// ── a loopback upstream that routes by (method, path) and records every request ─────────────

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
    fn route(&self, method: &str, path: &str, status: StatusCode, body: Vec<u8>) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body,
                content_type: Some("application/json"),
                delay: None,
            });
    }

    fn json(&self, method: &str, path: &str, status: StatusCode, body: Value) {
        self.route(
            method,
            path,
            status,
            serde_json::to_vec(&body).expect("a JSON reply"),
        );
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

fn clients_for(service: Service, base: &str) -> Clients {
    Clients::default()
        .with(service, public_client(base))
        .with_token(service, None)
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

// ── the reference fixtures ─────────────────────────────────────────────────────────────────

const PAPER_ID: &str = "01a1673c-78ed-74c8-b7a1-1bf043ceb236";

fn search_answer() -> Value {
    json!({
        "session_id": null,
        "query": "probiotics antibiotic associated diarrhea",
        "total_results": 2,
        "results": [
            {
                "id": PAPER_ID,
                "external_ids": {"pmid": "42898607", "doi": "10.5187/jast.2600114"},
                "title": "A multi-omics characterization of the gut microbiota of weaned piglets.",
                "authors": [{"name": "Nae-Ho Park", "external_ids": {}}, "Minho Song"],
                "year": 2026,
                "abstract": "Weaning is a critical developmental stage in piglets.",
                "source": "pubmed",
                "citation_count": null,
                "venue": "J Anim Sci Technol",
                "is_open_access": null,
                "pdf_url": null,
                "relevance_rank": 0,
            },
            {
                "id": "01a1673c-78ed-74c8-b7a1-1bf043ceb237",
                "external_ids": {"arxiv_id": "2401.00001"},
                "title": "Second",
                "authors": [],
                "year": 2024,
                "abstract": "<jats:p>Probiotics <jats:italic>reduce</jats:italic> risk.</jats:p>",
                "source": "arxiv",
                "pdf_url": "https://arxiv.org/pdf/2401.00001",
            },
        ],
        "sources_queried": ["pubmed", "arxiv"],
        "sources_failed": ["openalex"],
        "per_source_counts": {"pubmed": 1, "arxiv": 1},
        "raw_total": 2,
        "deduped_total": 2,
    })
}

fn paper_answer() -> Value {
    json!({
        "id": PAPER_ID,
        "title": "A multi-omics characterization of the gut microbiota of weaned piglets.",
        "abstract": "Weaning is a critical developmental stage in piglets. Six piglets were assigned.",
        "year": 2026,
        "venue": "J Anim Sci Technol",
        "external_ids": {"pmid": "42898607", "doi": "10.5187/jast.2600114"},
        "citation_count": 0,
        "is_open_access": true,
        "pdf_url": null,
        "metadata": {},
        "authors": [
            {"name": "Nae-Ho Park", "affiliation": "Chungnam National University", "h_index": null}
        ],
        "created_at": "2026-10-23T05:29:38Z",
        "updated_at": "2026-10-23T05:29:38Z",
    })
}

// ── the reference statistics formulas (scientific-processor src/services/stats_service.py) ──

/// The two-sided 95% normal critical value, `scipy.stats.norm.ppf((1 + 0.95) / 2)`.
const Z_95: f64 = 1.959_963_984_540_054;
/// The two-sided 95% Student-t critical value with 4 degrees of freedom,
/// `scipy.stats.t.ppf(0.975, 4)`, the reference's interval for a five-value sample.
const T_975_DF4: f64 = 2.776_445_105_197_793_4;

/// Python's `round(value, places)` (the service rounds every answer it returns).
fn round_to(value: f64, places: i32) -> f64 {
    let factor = 10f64.powi(places);
    (value * factor).round() / factor
}

/// The reference's meta-analysis answer:
/// `w_i = 1/se_i^2`; `pooled_fixed = Σ w_i y_i / Σ w_i`; `Q = Σ w_i (y_i - pooled_fixed)^2`;
/// `I^2 = max(0, (Q - (k-1)) / Q)`; `c = Σ w_i - Σ w_i^2 / Σ w_i`;
/// `tau^2 = max(0, (Q - (k-1)) / c)`; random-effects weights `w*_i = 1/(se_i^2 + tau^2)`;
/// `pooled_se = 1/sqrt(Σ w)`; `CI = pooled ± 1.96 * pooled_se` (the 95 % level every case
/// below uses; a level-dependent z needs an inverse normal CDF the reference does not carry either).
fn meta_answer(studies: &[(f64, f64)], method: &str) -> Value {
    let k = studies.len() as f64;
    let weights: Vec<f64> = studies
        .iter()
        .map(|(_, standard_error)| 1.0 / standard_error.powi(2))
        .collect();
    let sum_weights: f64 = weights.iter().sum();
    let pooled_fixed: f64 = studies
        .iter()
        .zip(&weights)
        .map(|((effect, _), weight)| weight * effect)
        .sum::<f64>()
        / sum_weights;
    let q: f64 = studies
        .iter()
        .zip(&weights)
        .map(|((effect, _), weight)| weight * (effect - pooled_fixed).powi(2))
        .sum();
    let i_squared = if q > 0.0 {
        ((q - (k - 1.0)) / q).max(0.0)
    } else {
        0.0
    };
    let (pooled, pooled_se, weights_out) = if method == "random" {
        let c =
            sum_weights - weights.iter().map(|weight| weight.powi(2)).sum::<f64>() / sum_weights;
        let tau2 = if c > 0.0 {
            ((q - (k - 1.0)) / c).max(0.0)
        } else {
            0.0
        };
        let adjusted: Vec<f64> = studies
            .iter()
            .map(|(_, standard_error)| 1.0 / (standard_error.powi(2) + tau2))
            .collect();
        let sum_adjusted: f64 = adjusted.iter().sum();
        let pooled = studies
            .iter()
            .zip(&adjusted)
            .map(|((effect, _), weight)| weight * effect)
            .sum::<f64>()
            / sum_adjusted;
        (pooled, 1.0 / sum_adjusted.sqrt(), adjusted)
    } else {
        (pooled_fixed, 1.0 / sum_weights.sqrt(), weights)
    };
    let z = Z_95;
    json!({
        "pooled_effect": round_to(pooled, 6),
        "pooled_se": round_to(pooled_se, 6),
        "ci_lower": round_to(pooled - z * pooled_se, 6),
        "ci_upper": round_to(pooled + z * pooled_se, 6),
        "heterogeneity_q": round_to(q, 4),
        "heterogeneity_i_squared": round_to(i_squared, 4),
        "method": method,
        "study_weights": weights_out.iter().map(|w| round_to(*w, 6)).collect::<Vec<f64>>(),
    })
}

/// The reference's normal-approximation interval: `mean ± t_(1+level)/2, n-1 * sample_sd / sqrt(n)`
/// (`numpy.std(ddof=1) / sqrt(n)` then `scipy.stats.t.interval`).
fn interval_answer(values: &[f64], level: f64) -> Value {
    let n = values.len() as f64;
    let mean = values.iter().sum::<f64>() / n;
    let variance = values
        .iter()
        .map(|value| (value - mean).powi(2))
        .sum::<f64>()
        / (n - 1.0);
    let standard_error = variance.sqrt() / n.sqrt();
    let t = T_975_DF4;
    json!({
        "mean": round_to(mean, 6),
        "ci_lower": round_to(mean - t * standard_error, 6),
        "ci_upper": round_to(mean + t * standard_error, 6),
        "confidence_level": level,
        "method": "normal",
    })
}

/// `scipy.stats.linregress` for a perfect straight line: the closed-form slope and intercept,
/// with the p-value the reference's scipy call reports for a perfect fit.
fn line_answer(points: &[(f64, f64)]) -> Value {
    let n = points.len() as f64;
    let mean_x = points.iter().map(|(x, _)| x).sum::<f64>() / n;
    let mean_y = points.iter().map(|(_, y)| y).sum::<f64>() / n;
    let covariance: f64 = points
        .iter()
        .map(|(x, y)| (x - mean_x) * (y - mean_y))
        .sum();
    let variance: f64 = points.iter().map(|(x, _)| (x - mean_x).powi(2)).sum();
    let slope = covariance / variance;
    let intercept = mean_y - slope * mean_x;
    json!({
        "trend": if slope > 0.0 { "increasing" } else { "decreasing" },
        "p_value": 1e-20,
        "statistic": round_to(slope, 6),
        "slope": round_to(slope, 6),
        "intercept": round_to(intercept, 6),
    })
}

/// The reference's Mann-Kendall test: `S = Σ sign(x_j - x_i)`; `var(S) = n(n-1)(2n+5)/18`;
/// `z = (S∓1)/sqrt(var(S))`; `tau = 2S/(n(n-1))`; Theil-Sen slope = median of `(x_j-x_i)/(j-i)`.
/// `p = 2(1 - Φ(|z|))`; the constant below is the reference's scipy result for `[1, 2, 3, 4]`.
fn mann_kendall(values: &[f64]) -> (Value, f64, f64) {
    let n = values.len();
    let mut s = 0i64;
    let mut slopes = Vec::new();
    for i in 0..n - 1 {
        for j in i + 1..n {
            let difference = values[j] - values[i];
            if difference > 0.0 {
                s += 1;
            } else if difference < 0.0 {
                s -= 1;
            }
            slopes.push(difference / ((j - i) as f64));
        }
    }
    let n = n as f64;
    let variance = n * (n - 1.0) * (2.0 * n + 5.0) / 18.0;
    let z = if s > 0 {
        (s as f64 - 1.0) / variance.sqrt()
    } else if s < 0 {
        (s as f64 + 1.0) / variance.sqrt()
    } else {
        0.0
    };
    let tau = 2.0 * s as f64 / (n * (n - 1.0));
    slopes.sort_by(|left, right| left.partial_cmp(right).expect("finite slopes"));
    let middle = slopes.len() / 2;
    let slope = if middle * 2 == slopes.len() {
        (slopes[middle - 1] + slopes[middle]) / 2.0
    } else {
        slopes[middle]
    };
    let p_value = 2.0 * (1.0 - normal_cdf(z.abs()));
    let trend = if p_value < 0.05 {
        if s > 0 { "increasing" } else { "decreasing" }
    } else {
        "no_trend"
    };
    (
        json!({
            "trend": trend,
            "p_value": round_to(p_value, 6),
            "statistic": round_to(tau, 6),
            "slope": round_to(slope, 6),
            "intercept": Value::Null,
        }),
        tau,
        slope,
    )
}

/// The standard normal CDF (Abramowitz & Stegun 26.2.17, |error| < 7.5e-8), enough to check the
/// reference's reported p-value at its six-decimal rounding.
fn normal_cdf(value: f64) -> f64 {
    let t = 1.0 / (1.0 + 0.231_641_9 * value);
    let polynomial = 0.319_381_530 * t - 0.356_563_782 * t.powi(2) + 1.781_477_937 * t.powi(3)
        - 1.821_255_978 * t.powi(4)
        + 1.330_274_429 * t.powi(5);
    let density = (-value * value / 2.0).exp() / (2.0 * std::f64::consts::PI).sqrt();
    1.0 - density * polynomial
}

// ── the tool contract ──────────────────────────────────────────────────────────────────────

fn contract() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "research_literature_record",
            "One literature record by the `id` research_literature_search returned: title, authors\n\
             (with affiliations), year, venue, upstream ids, canonical url and the full abstract.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"id": {"type": "string"}},
                "required": ["id"],
            }),
        ),
        (
            "research_literature_search",
            "Search scientific literature (PubMed, Europe PMC, Crossref, Semantic Scholar, arXiv, ...)\n\
             in one federated query. Each item has a stable `id` for research_literature_record, upstream\n\
             ids (doi, pmid), a canonical `url` and the abstract. Default sources: all the engine has\n\
             enabled; `sources_failed` lists any that errored or are not available. Can take ~10-60 s.\n\
             Abstracts are capped (default 1500 chars) to keep the result small; quote from\n\
             research_literature_record, which returns the full abstract.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"type": "string"},
                    "sources": {
                        "anyOf": [
                            {
                                "items": {
                                    "enum": [
                                        "pubmed", "europe_pmc", "crossref",
                                        "semantic_scholar", "arxiv", "openlibrary"
                                    ],
                                    "type": "string",
                                },
                                "type": "array",
                            },
                            {"type": "null"},
                        ],
                        "default": null,
                    },
                    "max_results_per_source": {"default": 3, "type": "integer"},
                    "year_min": {
                        "anyOf": [{"type": "integer"}, {"type": "null"}],
                        "default": null,
                    },
                    "year_max": {
                        "anyOf": [{"type": "integer"}, {"type": "null"}],
                        "default": null,
                    },
                    "open_access_only": {"default": false, "type": "boolean"},
                    "sort_by": {
                        "default": "relevance",
                        "enum": ["relevance", "citation_count", "year"],
                        "type": "string",
                    },
                    "abstract_max_chars": {"default": 1500, "type": "integer"},
                },
                "required": ["query"],
            }),
        ),
        (
            "research_stats_confidence_interval",
            "Mean of 2+ values with its confidence interval (normal approximation, or percentile\n\
             bootstrap with n_bootstrap resamples, 100-100000).",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "values": {"items": {"type": "number"}, "type": "array"},
                    "method": {
                        "default": "normal",
                        "enum": ["normal", "bootstrap"],
                        "type": "string",
                    },
                    "confidence_level": {"default": 0.95, "type": "number"},
                    "n_bootstrap": {"default": 10000, "type": "integer"},
                },
                "required": ["values"],
            }),
        ),
        (
            "research_stats_meta_analysis",
            "Inverse-variance meta-analysis (fixed or random effects) over 2+ study results, each an\n\
             effect size with its standard error and sample size. Returns the pooled effect, its CI,\n\
             heterogeneity (Q, I^2) and each study's weight (same order as given).",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "studies": {
                        "items": {
                            "properties": {
                                "effect_size": {"type": "number"},
                                "standard_error": {"type": "number"},
                                "sample_size": {"type": "integer"},
                                "label": {
                                    "anyOf": [{"type": "string"}, {"type": "null"}],
                                    "default": null,
                                },
                            },
                            "required": ["effect_size", "standard_error", "sample_size"],
                            "type": "object",
                        },
                        "type": "array",
                    },
                    "method": {"default": "random", "enum": ["fixed", "random"], "type": "string"},
                    "confidence_level": {"default": 0.95, "type": "number"},
                },
                "required": ["studies"],
            }),
        ),
        (
            "research_stats_trend",
            "Trend test over a time series of 3+ (timestamp, value) points: Mann-Kendall (monotonic,\n\
             non-parametric) or linear regression (slope + intercept). Returns increasing / decreasing /\n\
             no_trend with the p-value and test statistic.",
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "data": {
                        "items": {
                            "properties": {
                                "timestamp": {"type": "number"},
                                "value": {"type": "number"},
                            },
                            "required": ["timestamp", "value"],
                            "type": "object",
                        },
                        "type": "array",
                    },
                    "test": {
                        "default": "mann_kendall",
                        "enum": ["mann_kendall", "linear_regression"],
                        "type": "string",
                    },
                },
                "required": ["data"],
            }),
        ),
    ]
}

#[test]
fn the_registry_is_exactly_the_five_tool_contract() {
    let mut provider = BuiltinProvider::new();
    research::register(&mut provider);

    let tools = provider.list(&researcher());
    let expected = contract();
    assert_eq!(
        tools.len(),
        expected.len(),
        "the research contract is 5 tools"
    );
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
        [
            "research_literature_record",
            "research_literature_search",
            "research_stats_confidence_interval",
            "research_stats_meta_analysis",
            "research_stats_trend",
        ]
    );
    for (name, description, schema) in &expected {
        let tool = tools
            .iter()
            .find(|tool| tool.name == *name)
            .unwrap_or_else(|| panic!("{name} is registered"));
        assert_eq!(tool.description.as_deref(), Some(*description), "{name}");
        assert_eq!(
            Value::Object((*tool.input_schema).clone()),
            *schema,
            "{name}"
        );
    }

    // The family is granted to the researcher and to a care-bus licence, and to nobody else.
    assert_eq!(provider.list(&licence_caller()).len(), 5);
    assert!(provider.list(&executor()).is_empty());
}

// ── literature ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn literature_search_sends_the_engine_request_and_maps_items() {
    let (base, stub) = local_server().await;
    stub.json("POST", "/api/search", StatusCode::OK, search_answer());
    let clients = clients_for(Service::DiscoveryEngine, &base);

    let out = literature::search(
        &clients,
        &args(json!({
            "query": "  probiotics antibiotic associated diarrhea ",
            "sources": ["pubmed", "arxiv", "pubmed"],
            "max_results_per_source": 500,
            "year_min": 2020,
            "sort_by": "year",
        })),
    )
    .await
    .expect("a search");

    let request = only(&stub);
    assert_eq!(request.method, "POST");
    assert_eq!(request.path, "/api/search");
    assert_eq!(
        json_body(&request),
        json!({
            "query": "probiotics antibiotic associated diarrhea",
            "sources": {"year_min": 2020, "sources": ["pubmed", "arxiv"]},
            "max_results_per_source": 20,
            "open_access_only": false,
            "sort_by": "year",
        })
    );
    assert_eq!(header(&request, "user-agent"), Some(USER_AGENT));
    assert_eq!(header(&request, "x-tenant-id"), None);
    assert_eq!(header(&request, "accept"), Some("application/json"));

    assert_eq!(out["query"], "probiotics antibiotic associated diarrhea");
    assert_eq!(out["total"], 2);
    assert_eq!(out["sources_queried"], json!(["pubmed", "arxiv"]));
    assert_eq!(out["sources_failed"], json!(["openalex"]));
    let items = out["items"].as_array().expect("items");
    assert_eq!(items.len(), 2);
    assert_eq!(
        items[0],
        json!({
            "id": PAPER_ID,
            "title": "A multi-omics characterization of the gut microbiota of weaned piglets.",
            "authors": ["Nae-Ho Park", "Minho Song"],
            "year": 2026,
            "venue": "J Anim Sci Technol",
            "doi": "10.5187/jast.2600114",
            "pmid": "42898607",
            "external_ids": {"pmid": "42898607", "doi": "10.5187/jast.2600114"},
            "url": "https://doi.org/10.5187/jast.2600114",
            "pdf_url": null,
            "source": "pubmed",
            "citation_count": null,
            "abstract": "Weaning is a critical developmental stage in piglets.",
            "abstract_truncated": false,
        })
    );
    assert_eq!(items[1]["url"], "https://arxiv.org/abs/2401.00001");
    assert_eq!(items[1]["abstract"], "Probiotics reduce risk.");
}

#[tokio::test]
async fn literature_search_omits_sources_and_truncates_abstracts() {
    let (base, stub) = local_server().await;
    let mut answer = search_answer();
    answer["results"] = json!([{
        "id": PAPER_ID,
        "title": "Long",
        "authors": [],
        "abstract": "x".repeat(1000),
    }]);
    stub.json("POST", "/api/search", StatusCode::OK, answer);
    let clients = clients_for(Service::DiscoveryEngine, &base);

    let out = literature::search(
        &clients,
        &args(json!({"query": "q", "abstract_max_chars": 10})),
    )
    .await
    .expect("a search");
    let request = only(&stub);
    assert_eq!(json_body(&request)["sources"], json!({}));
    assert_eq!(json_body(&request)["max_results_per_source"], 3);
    let items = out["items"].as_array().expect("items");
    let item = &items[0];
    assert_eq!(item["abstract"].as_str().unwrap().chars().count(), 200);
    assert_eq!(item["abstract_truncated"], Value::Bool(true));
}

#[tokio::test]
async fn literature_search_sends_the_licence_token_when_configured() {
    let (base, stub) = local_server().await;
    stub.json("POST", "/api/search", StatusCode::OK, search_answer());
    let clients = clients_for(Service::DiscoveryEngine, &base)
        .with_token(Service::DiscoveryEngine, Some("lic-de".to_owned()));
    literature::search(&clients, &args(json!({"query": "q"})))
        .await
        .expect("a search");
    assert_eq!(header(&only(&stub), "x-tenant-id"), Some("Bearer lic-de"));
}

#[tokio::test]
async fn literature_search_rejects_bad_arguments_without_calling() {
    let (base, stub) = local_server().await;
    let clients = clients_for(Service::DiscoveryEngine, &base);
    let long = "x".repeat(1001);
    let cases = [
        (
            json!({"query": "  "}),
            "[permanent] query must be 1-1000 chars",
        ),
        (
            json!({"query": long}),
            "[permanent] query must be 1-1000 chars",
        ),
        (
            json!({"query": "q", "year_min": 99}),
            "[permanent] invalid year_min: expected a year 1000-2100",
        ),
        (
            json!({"query": "q", "year_min": 2020, "year_max": 2010}),
            "[permanent] year_min is after year_max",
        ),
        (
            json!({"query": "q", "sources": ["google"]}),
            "[permanent] invalid sources: expected an array of",
        ),
    ];
    for (arguments, message) in cases {
        let error = literature::search(&clients, &args(arguments.clone()))
            .await
            .expect_err("a refusal");
        assert!(error.starts_with(message), "{arguments}: {error}");
    }
    assert!(stub.requests().is_empty(), "no request leaves on a refusal");
}

#[tokio::test]
async fn literature_search_unknown_source_is_refused_by_the_schema() {
    let mut provider = BuiltinProvider::new();
    research::register(&mut provider);
    let result = provider
        .call(
            &researcher(),
            "research_literature_search",
            args(json!({"query": "q", "sources": ["google"]})),
        )
        .await;
    assert_eq!(result.is_error, Some(true));
    let text = result.content[0].as_text().unwrap().text.clone();
    assert!(text.starts_with("invalid arguments: "), "{text}");
}

#[tokio::test]
async fn literature_search_reads_the_pmid_semantic_scholar_stores_as_pubmed_id() {
    let (base, stub) = local_server().await;
    let mut answer = search_answer();
    answer["results"] = json!([{
        "id": PAPER_ID,
        "external_ids": {"pubmed_id": "123456"},
        "authors": [],
    }]);
    stub.json("POST", "/api/search", StatusCode::OK, answer);
    let clients = clients_for(Service::DiscoveryEngine, &base);
    let out = literature::search(&clients, &args(json!({"query": "q"})))
        .await
        .expect("a search");
    assert_eq!(out["items"][0]["pmid"], "123456");
    assert_eq!(
        out["items"][0]["url"],
        "https://pubmed.ncbi.nlm.nih.gov/123456/"
    );
}

#[tokio::test]
async fn literature_search_maps_the_upstream_error_classes() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/search",
        StatusCode::SERVICE_UNAVAILABLE,
        json!({"message": "down"}),
    );
    stub.json(
        "POST",
        "/api/search",
        StatusCode::UNPROCESSABLE_ENTITY,
        json!({"detail": "bad"}),
    );
    stub.json(
        "POST",
        "/api/search",
        StatusCode::UNAUTHORIZED,
        json!({"message": "Authentication required"}),
    );
    let clients = clients_for(Service::DiscoveryEngine, &base);
    let arguments = args(json!({"query": "q"}));

    let error = literature::search(&clients, &arguments)
        .await
        .expect_err("a 503");
    assert!(
        error.starts_with("[retryable] 503 from POST /api/search: "),
        "{error}"
    );
    let error = literature::search(&clients, &arguments)
        .await
        .expect_err("a 422");
    assert!(
        error.starts_with("[permanent] 422 from POST /api/search: "),
        "{error}"
    );
    let error = literature::search(&clients, &arguments)
        .await
        .expect_err("a 401");
    assert!(
        error.starts_with("[permanent] 401 from POST /api/search: ")
            && error.contains("Authentication required"),
        "{error}"
    );
}

#[tokio::test]
async fn literature_search_timeout_and_non_json_are_retryable() {
    let (base, stub) = local_server().await;
    stub.slow_json(
        "POST",
        "/api/search",
        search_answer(),
        Duration::from_millis(300),
    );
    let clients = Clients::default()
        .with(
            Service::DiscoveryEngine,
            PublicClient::new(&base, Duration::from_millis(50), Duration::ZERO, None),
        )
        .with_token(Service::DiscoveryEngine, None);
    let error = literature::search(&clients, &args(json!({"query": "q"})))
        .await
        .expect_err("a timeout");
    assert!(error.starts_with("[retryable] timeout after"), "{error}");

    let (base, stub) = local_server().await;
    stub.text("POST", "/api/search", StatusCode::OK, "<html>");
    let clients = clients_for(Service::DiscoveryEngine, &base);
    let error = literature::search(&clients, &args(json!({"query": "q"})))
        .await
        .expect_err("a non-JSON answer");
    assert_eq!(error, "[retryable] non-JSON answer from POST /api/search");
}

#[tokio::test]
async fn literature_record_maps_the_paper() {
    let (base, stub) = local_server().await;
    stub.json(
        "GET",
        &format!("/api/papers/{PAPER_ID}"),
        StatusCode::OK,
        paper_answer(),
    );
    let clients = clients_for(Service::DiscoveryEngine, &base);

    let out = literature::record(&clients, &args(json!({"id": PAPER_ID.to_uppercase()})))
        .await
        .expect("a record");
    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(request.path, format!("/api/papers/{PAPER_ID}"));
    assert_eq!(
        out,
        json!({
            "id": PAPER_ID,
            "title": "A multi-omics characterization of the gut microbiota of weaned piglets.",
            "authors": [{"name": "Nae-Ho Park", "affiliation": "Chungnam National University"}],
            "year": 2026,
            "venue": "J Anim Sci Technol",
            "doi": "10.5187/jast.2600114",
            "pmid": "42898607",
            "external_ids": {"pmid": "42898607", "doi": "10.5187/jast.2600114"},
            "url": "https://doi.org/10.5187/jast.2600114",
            "pdf_url": null,
            "is_open_access": true,
            "citation_count": 0,
            "abstract": "Weaning is a critical developmental stage in piglets. Six piglets were assigned.",
        })
    );
}

#[tokio::test]
async fn literature_record_404_and_bad_id_are_permanent() {
    let (base, stub) = local_server().await;
    let clients = clients_for(Service::DiscoveryEngine, &base);

    let error = literature::record(&clients, &args(json!({"id": PAPER_ID})))
        .await
        .expect_err("a 404");
    assert_eq!(error, "[permanent] paper not found");
    let error = literature::record(&clients, &args(json!({"id": "../health"})))
        .await
        .expect_err("a bad id");
    assert!(error.starts_with("[permanent] invalid id: "), "{error}");
    assert_eq!(stub.requests().len(), 1, "only the 404 left the process");
}

#[test]
fn source_url_prefers_doi_then_pubmed_then_pmc_then_arxiv_then_pdf() {
    let cases: Vec<(Value, Option<&str>, Option<&str>)> = vec![
        (
            json!({"doi": "https://doi.org/10.1/x"}),
            None,
            Some("https://doi.org/10.1/x"),
        ),
        (
            json!({"pmid": "1"}),
            None,
            Some("https://pubmed.ncbi.nlm.nih.gov/1/"),
        ),
        (
            json!({"pubmed_id": "2"}),
            None,
            Some("https://pubmed.ncbi.nlm.nih.gov/2/"),
        ),
        (
            json!({"pmcid": "PMC3"}),
            None,
            Some("https://www.ncbi.nlm.nih.gov/pmc/articles/PMC3/"),
        ),
        (
            json!({"arxiv": "2401.1"}),
            None,
            Some("https://arxiv.org/abs/2401.1"),
        ),
        (
            json!({"s2_id": "abc"}),
            Some("https://x/p.pdf"),
            Some("https://x/p.pdf"),
        ),
        (json!({}), None, None),
    ];
    for (ids, pdf, expected) in cases {
        let ids = ids.as_object().cloned().expect("an ids object");
        assert_eq!(
            literature::source_url(&ids, pdf),
            expected.map(str::to_owned)
        );
    }
}

// ── statistics ────────────────────────────────────────────────────────────────────────────

fn studies_json() -> Value {
    json!([
        {"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100, "label": "A"},
        {"effect_size": 0.5, "standard_error": 0.15, "sample_size": 80},
    ])
}

#[tokio::test]
async fn meta_analysis_maps_the_reference_random_effects_formula() {
    let (base, stub) = local_server().await;
    // The formula reproduces the reference's own recorded answer (tests/test_research_tools.py):
    // pooled 0.36875, se 0.094992, CI [0.18257, 0.55493], Q 1.2308, I^2 0.1875,
    // weights [72.727273, 38.095238].
    let answer = meta_answer(&[(0.3, 0.1), (0.5, 0.15)], "random");
    stub.json(
        "POST",
        "/api/stats/meta-analysis",
        StatusCode::OK,
        answer.clone(),
    );
    let clients = clients_for(Service::ScientificProcessor, &base);

    let out = stats::meta_analysis(&clients, &args(json!({"studies": studies_json()})))
        .await
        .expect("a meta-analysis");
    assert_eq!(
        json_body(&only(&stub)),
        json!({
            "studies": [
                {"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100, "label": "A"},
                {"effect_size": 0.5, "standard_error": 0.15, "sample_size": 80},
            ],
            "method": "random",
            "confidence_level": 0.95,
        })
    );
    assert_eq!(out["method"], "random");
    assert_eq!(out["confidence_level"], 0.95);
    assert_eq!(out["studies_count"], 2);
    assert_eq!(out["pooled_effect"], answer["pooled_effect"]);
    assert_eq!(out["pooled_se"], answer["pooled_se"]);
    assert_eq!(out["ci_lower"], answer["ci_lower"]);
    assert_eq!(out["ci_upper"], answer["ci_upper"]);
    assert_eq!(out["heterogeneity_q"], answer["heterogeneity_q"]);
    assert_eq!(
        out["heterogeneity_i_squared"],
        answer["heterogeneity_i_squared"]
    );
    assert_eq!(
        out["study_weights"],
        json!([
            {"label": "A", "weight": 72.727273},
            {"label": null, "weight": 38.095238},
        ])
    );
    // The formula's numbers are the reference's recorded ones (rounded to six places).
    assert!((out["pooled_effect"].as_f64().unwrap() - 0.36875).abs() < 1e-9);
    assert!((out["pooled_se"].as_f64().unwrap() - 0.094992).abs() < 1e-9);
    assert!((out["ci_lower"].as_f64().unwrap() - 0.18257).abs() < 1e-9);
    assert!((out["ci_upper"].as_f64().unwrap() - 0.55493).abs() < 1e-9);
    assert!((out["heterogeneity_q"].as_f64().unwrap() - 1.2308).abs() < 1e-9);
    assert!((out["heterogeneity_i_squared"].as_f64().unwrap() - 0.1875).abs() < 1e-9);
}

#[tokio::test]
async fn meta_analysis_fixed_effects_uses_inverse_variance_weights() {
    let (base, stub) = local_server().await;
    let answer = meta_answer(&[(0.3, 0.1), (0.5, 0.15)], "fixed");
    stub.json(
        "POST",
        "/api/stats/meta-analysis",
        StatusCode::OK,
        answer.clone(),
    );
    let clients = clients_for(Service::ScientificProcessor, &base);
    let out = stats::meta_analysis(
        &clients,
        &args(json!({"studies": studies_json(), "method": "fixed"})),
    )
    .await
    .expect("a meta-analysis");
    assert_eq!(json_body(&only(&stub))["method"], "fixed");
    assert_eq!(out["method"], "fixed");
    // w_i = 1/se_i^2: 100 and 44.444444; pooled = 0.361538; se = 1/sqrt(144.444444).
    assert_eq!(
        out["study_weights"],
        json!([
            {"label": "A", "weight": 100.0},
            {"label": null, "weight": 44.444444},
        ])
    );
    assert!((out["pooled_effect"].as_f64().unwrap() - 0.361538).abs() < 1e-9);
    assert!((out["pooled_se"].as_f64().unwrap() - 0.083205).abs() < 1e-9);
    assert!((out["ci_lower"].as_f64().unwrap() - 0.19846).abs() < 1e-9);
    assert!((out["ci_upper"].as_f64().unwrap() - 0.524617).abs() < 1e-9);
}

#[tokio::test]
async fn meta_analysis_rejects_bad_input_without_calling() {
    let (base, stub) = local_server().await;
    let clients = clients_for(Service::ScientificProcessor, &base);
    let cases = [
        (
            json!({"studies": [{"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100}]}),
            "[permanent] studies must have 2-1000 entries",
        ),
        (
            json!({"studies": [
                {"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100},
                {"effect_size": 0.5, "standard_error": 0.0, "sample_size": 80},
            ]}),
            "[permanent] studies[1].standard_error must be > 0",
        ),
        (
            json!({"studies": [
                {"effect_size": 0.3, "standard_error": 0.1, "sample_size": 100},
                {"effect_size": 0.5, "standard_error": 0.15, "sample_size": 0},
            ]}),
            "[permanent] studies[1].sample_size must be > 0",
        ),
        (
            json!({"studies": studies_json(), "confidence_level": 1.0}),
            "[permanent] confidence_level must be in [0.5, 1.0)",
        ),
    ];
    for (arguments, message) in cases {
        let error = stats::meta_analysis(&clients, &args(arguments.clone()))
            .await
            .expect_err("a refusal");
        assert_eq!(error, message, "{arguments}");
    }
    assert!(stub.requests().is_empty(), "no request leaves on a refusal");
}

#[tokio::test]
async fn meta_analysis_weights_zip_stops_at_the_shorter_side() {
    let (base, stub) = local_server().await;
    stub.json(
        "POST",
        "/api/stats/meta-analysis",
        StatusCode::OK,
        json!({"method": "random", "study_weights": [72.727273]}),
    );
    let clients = clients_for(Service::ScientificProcessor, &base);
    let out = stats::meta_analysis(&clients, &args(json!({"studies": studies_json()})))
        .await
        .expect("a meta-analysis");
    assert_eq!(
        out["study_weights"],
        json!([{"label": "A", "weight": 72.727273}])
    );
    assert_eq!(out["pooled_effect"], Value::Null);
}

#[tokio::test]
async fn confidence_interval_sends_floats_and_maps_the_t_interval() {
    let (base, stub) = local_server().await;
    // The reference's own recorded answer for [1, 2, 3, 4, 5]: mean 3.0, CI [1.036757, 4.963243].
    let answer = interval_answer(&[1.0, 2.0, 3.0, 4.0, 5.0], 0.95);
    stub.json(
        "POST",
        "/api/stats/confidence-interval",
        StatusCode::OK,
        answer.clone(),
    );
    let clients = clients_for(Service::ScientificProcessor, &base);
    let out = stats::confidence_interval(&clients, &args(json!({"values": [1, 2, 3, 4, 5]})))
        .await
        .expect("an interval");
    assert_eq!(
        json_body(&only(&stub)),
        json!({
            "values": [1.0, 2.0, 3.0, 4.0, 5.0],
            "method": "normal",
            "confidence_level": 0.95,
            "n_bootstrap": 10000,
        })
    );
    assert_eq!(out["method"], "normal");
    assert_eq!(out["confidence_level"], 0.95);
    assert_eq!(out["values_count"], 5);
    assert_eq!(out["mean"], 3.0);
    assert!((out["ci_lower"].as_f64().unwrap() - 1.036757).abs() < 1e-9);
    assert!((out["ci_upper"].as_f64().unwrap() - 4.963243).abs() < 1e-9);
}

#[tokio::test]
async fn confidence_interval_rejects_bad_input_without_calling() {
    let (base, stub) = local_server().await;
    let clients = clients_for(Service::ScientificProcessor, &base);
    let cases = [
        (
            json!({"values": [1]}),
            "[permanent] values must have 2-100000 entries",
        ),
        (
            json!({"values": [1, 2], "n_bootstrap": 5}),
            "[permanent] n_bootstrap must be 100-100000",
        ),
    ];
    for (arguments, message) in cases {
        let error = stats::confidence_interval(&clients, &args(arguments.clone()))
            .await
            .expect_err("a refusal");
        assert_eq!(error, message, "{arguments}");
    }
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn trend_linear_regression_maps_the_closed_form_line() {
    let (base, stub) = local_server().await;
    let points: Vec<(f64, f64)> = (0..4)
        .map(|index| (f64::from(index), f64::from(index) * 1.5))
        .collect();
    let answer = line_answer(&points);
    stub.json("POST", "/api/stats/trend", StatusCode::OK, answer.clone());
    let clients = clients_for(Service::ScientificProcessor, &base);
    let data: Vec<Value> = points
        .iter()
        .map(|(timestamp, value)| json!({"timestamp": timestamp, "value": value}))
        .collect();
    let out = stats::trend(
        &clients,
        &args(json!({"data": data, "test": "linear_regression"})),
    )
    .await
    .expect("a trend");
    assert_eq!(
        json_body(&only(&stub)),
        json!({"data": data, "test": "linear_regression"})
    );
    assert_eq!(out["test"], "linear_regression");
    assert_eq!(out["points_count"], 4);
    assert_eq!(out["trend"], "increasing");
    assert_eq!(out["statistic"], 1.5);
    assert_eq!(out["slope"], 1.5);
    assert_eq!(out["intercept"], 0.0);
    assert_eq!(out["p_value"], 1e-20);
}

#[tokio::test]
async fn trend_mann_kendall_maps_the_reference_statistics() {
    let (base, stub) = local_server().await;
    let (answer, tau, slope) = mann_kendall(&[1.0, 2.0, 3.0, 4.0]);
    // The reference's scipy call rounds this test's p-value to 0.089429 (no_trend at 5%).
    assert!((answer["p_value"].as_f64().unwrap() - 0.089429).abs() < 1e-9);
    stub.json("POST", "/api/stats/trend", StatusCode::OK, answer);
    let clients = clients_for(Service::ScientificProcessor, &base);
    let data = json!([
        {"timestamp": 0.0, "value": 1.0},
        {"timestamp": 1.0, "value": 2.0},
        {"timestamp": 2.0, "value": 3.0},
        {"timestamp": 3.0, "value": 4.0},
    ]);
    let out = stats::trend(&clients, &args(json!({"data": data})))
        .await
        .expect("a trend");
    assert_eq!(
        json_body(&only(&stub)),
        json!({"data": data, "test": "mann_kendall"})
    );
    assert_eq!(out["test"], "mann_kendall");
    assert_eq!(out["points_count"], 4);
    assert_eq!(out["trend"], "no_trend");
    assert!((out["p_value"].as_f64().unwrap() - 0.089429).abs() < 1e-9);
    assert!((out["statistic"].as_f64().unwrap() - tau).abs() < 1e-9);
    assert!((out["slope"].as_f64().unwrap() - slope).abs() < 1e-9);
    assert_eq!(out["intercept"], Value::Null);
}

#[tokio::test]
async fn trend_rejects_a_short_series_without_calling() {
    let (base, stub) = local_server().await;
    let clients = clients_for(Service::ScientificProcessor, &base);
    let error = stats::trend(
        &clients,
        &args(json!({"data": [{"timestamp": 0, "value": 1}]})),
    )
    .await
    .expect_err("a refusal");
    assert_eq!(error, "[permanent] data must have 3-10000 points");
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn trend_sends_the_licence_token_when_configured() {
    let (base, stub) = local_server().await;
    let (answer, _, _) = mann_kendall(&[1.0, 2.0, 3.0]);
    stub.json("POST", "/api/stats/trend", StatusCode::OK, answer);
    let clients = clients_for(Service::ScientificProcessor, &base)
        .with_token(Service::ScientificProcessor, Some("lic-sp".to_owned()));
    stats::trend(
        &clients,
        &args(json!({"data": [
            {"timestamp": 0, "value": 1},
            {"timestamp": 1, "value": 2},
            {"timestamp": 2, "value": 3},
        ]})),
    )
    .await
    .expect("a trend");
    assert_eq!(header(&only(&stub), "x-tenant-id"), Some("Bearer lic-sp"));
}

#[tokio::test]
async fn stats_backend_unreachable_is_retryable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    let clients = clients_for(Service::ScientificProcessor, &format!("http://{address}"));
    let error = stats::trend(
        &clients,
        &args(json!({"data": [
            {"timestamp": 0, "value": 1},
            {"timestamp": 1, "value": 2},
            {"timestamp": 2, "value": 3},
        ]})),
    )
    .await
    .expect_err("a connect error");
    assert!(error.starts_with("[retryable] cannot reach"), "{error}");
    assert!(error.contains("ConnectError"), "{error}");
}

#[test]
fn non_finite_numbers_are_the_reference_permanent_error() {
    assert_eq!(
        finite("x", f64::NAN).unwrap_err(),
        "[permanent] x must be a finite number"
    );
    assert_eq!(finite("x", 0.5).unwrap(), 0.5);
}

// ── client config ─────────────────────────────────────────────────────────────────────────

#[test]
fn clients_default_to_the_reference_in_cluster_services() {
    let discovery = client_from_lookup(Service::DiscoveryEngine, |_| None);
    assert_eq!(
        discovery.base_url,
        "http://discovery-engine.discovery-engine:8807"
    );
    assert_eq!(discovery.timeout, Duration::from_secs(90));
    let processor = client_from_lookup(Service::ScientificProcessor, |_| None);
    assert_eq!(
        processor.base_url,
        "http://scientific-processor.scientific-processor:8808"
    );
    assert_eq!(processor.timeout, Duration::from_secs(30));
}

#[test]
fn client_url_and_timeout_come_from_the_environment() {
    let values = HashMap::from([
        ("DISCOVERY_ENGINE_URL", "http://de.example:1/"),
        ("DISCOVERY_ENGINE_TIMEOUT_S", "12"),
        ("SCIENTIFIC_PROCESSOR_TIMEOUT_S", "not-a-number"),
    ]);
    let get = |key: &str| values.get(key).copied().map(str::to_owned);
    let discovery = client_from_lookup(Service::DiscoveryEngine, get);
    assert_eq!(
        (discovery.base_url.as_str(), discovery.timeout),
        ("http://de.example:1", Duration::from_secs(12))
    );
    let processor = client_from_lookup(Service::ScientificProcessor, get);
    assert_eq!(processor.timeout, Duration::from_secs(30));
}
