//! The legal builtin family: the 15 wire tools, their exact upstream calls, parsing and error
//! mapping, over loopback stubs.
//!
//! Every test starts a real axum server on `127.0.0.1:0` and records what the client actually
//! put on the wire (method, path, query, headers, body). The expected descriptions and input
//! schemas are the reference's own `tools/list` output (FastMCP 4.1.4 on the archive's
//! `src/builtin/legal/`); fixtures are trimmed copies of the archive's recorded real answers
//! (`tests/fixtures/legal/`), and the parser expectations were produced by the reference code
//! itself.
//!
//! The PDF-only paths cannot be ported without a PDF parser (see `legal::pdf_text`): those
//! tests assert the reference's permanent error and the request sequence up to the PDF.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use axum::body::to_bytes;
use axum::extract::{Request, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use serde_json::{Map, Value, json};

use mcp_server_rs::builtin::BuiltinProvider;
use mcp_server_rs::builtin::legal::{
    self,
    duw::document_value as duw_document_value,
    kio::{parse_details, parse_results},
    uokik::{parse_decision, parse_search},
};
use mcp_server_rs::builtin::legal::{Clients, PublicClient, Service};
use mcp_server_rs::builtin::scope::{BuiltinCaller, CallerKind, DENIED_MESSAGE};

// ── a loopback upstream that routes by (method, path) and records every request ─────────────

type Endpoint = (String, String);
type Routes = Arc<Mutex<HashMap<Endpoint, VecDeque<Reply>>>>;
type Locations = Arc<Mutex<HashMap<Endpoint, String>>>;

#[derive(Clone)]
struct Stub {
    routes: Routes,
    requests: Arc<Mutex<Vec<Recorded>>>,
    locations: Locations,
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
    query: Option<String>,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl Stub {
    fn route(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        body: Vec<u8>,
        content_type: Option<&'static str>,
    ) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body,
                content_type,
                delay: None,
            });
    }

    fn json(&self, method: &str, path: &str, status: StatusCode, body: Value) {
        self.route(
            method,
            path,
            status,
            serde_json::to_vec(&body).expect("a JSON reply"),
            Some("application/json"),
        );
    }

    fn text(&self, method: &str, path: &str, status: StatusCode, body: &str) {
        self.route(
            method,
            path,
            status,
            body.as_bytes().to_vec(),
            Some("text/html; charset=utf-8"),
        );
    }

    fn bytes(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        body: &[u8],
        content_type: &'static str,
    ) {
        self.route(method, path, status, body.to_vec(), Some(content_type));
    }

    fn redirect(&self, method: &str, path: &str, status: StatusCode, location: &str) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body: Vec::new(),
                content_type: None,
                delay: None,
            });
        self.locations
            .lock()
            .expect("an unpoisoned stub")
            .insert((method.to_owned(), path.to_owned()), location.to_owned());
    }

    fn slow_json(
        &self,
        method: &str,
        path: &str,
        status: StatusCode,
        body: Value,
        delay: Duration,
    ) {
        self.routes
            .lock()
            .expect("an unpoisoned stub")
            .entry((method.to_owned(), path.to_owned()))
            .or_default()
            .push_back(Reply {
                status,
                body: serde_json::to_vec(&body).expect("a JSON reply"),
                content_type: Some("application/json"),
                delay: Some(delay),
            });
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().expect("an unpoisoned stub").clone()
    }
}

async fn local_server() -> (String, Stub, Locations) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a loopback stub");
    let address = listener.local_addr().expect("a loopback address");
    let locations: Locations = Arc::default();
    let stub = Stub {
        routes: Arc::default(),
        requests: Arc::default(),
        locations: locations.clone(),
    };
    let app = Router::new()
        .fallback(any(handle))
        .with_state((stub.clone(), locations.clone()));
    tokio::spawn(async move {
        let _ = axum::serve(listener, app).await;
    });
    (format!("http://{address}"), stub, locations)
}

async fn handle(State((stub, locations)): State<(Stub, Locations)>, request: Request) -> Response {
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
            query: parts.uri.query().map(str::to_owned),
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
    let location = locations
        .lock()
        .expect("an unpoisoned stub")
        .get(&key)
        .cloned();
    let mut response = Response::new(axum::body::Body::from(reply.body));
    *response.status_mut() = reply.status;
    if let Some(content_type) = reply.content_type {
        response.headers_mut().insert(
            axum::http::header::CONTENT_TYPE,
            axum::http::HeaderValue::from_static(content_type),
        );
    }
    if let Some(location) = location {
        response.headers_mut().insert(
            axum::http::header::LOCATION,
            axum::http::HeaderValue::from_str(&location).expect("a header value"),
        );
    }
    response
}

// ── helpers ────────────────────────────────────────────────────────────────────────────────

fn public_client(base: &str) -> PublicClient {
    PublicClient::new(base, Duration::from_secs(20), Duration::ZERO, None)
}

fn clients_for(service: Service, base: &str) -> Clients {
    Clients::default().with(service, public_client(base))
}

fn args(value: Value) -> Map<String, Value> {
    value.as_object().cloned().expect("an arguments object")
}

fn only(stub: &Stub) -> Recorded {
    let mut requests = stub.requests();
    assert_eq!(requests.len(), 1, "exactly one upstream request");
    requests.pop().expect("one request")
}

fn decode(value: &str) -> String {
    percent_encoding::percent_decode_str(&value.replace('+', " "))
        .decode_utf8_lossy()
        .into_owned()
}

fn query_params(request: &Recorded) -> HashMap<String, String> {
    request
        .query
        .as_deref()
        .unwrap_or_default()
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
}

fn form_params(request: &Recorded) -> HashMap<String, String> {
    String::from_utf8_lossy(&request.body)
        .split('&')
        .filter(|pair| !pair.is_empty())
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or((pair, ""));
            (decode(key), decode(value))
        })
        .collect()
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

fn eli_search_answer() -> Value {
    json!({
        "count": 2,
        "items": [
            {
                "displayAddress": "Dz.U. 2026 poz. 236",
                "promulgation": "2026-02-27",
                "status": "obowiązujący",
                "title": "Obwieszczenie Marszałka Sejmu Rzeczypospolitej Polskiej z dnia 20 lutego 2026 r.",
                "type": "Obwieszczenie",
                "inForce": "IN_FORCE",
                "ELI": "DU/2026/236",
            },
            {
                "displayAddress": "Dz.U. 2025 poz. 897",
                "promulgation": "2025-07-07",
                "status": "akt objęty tekstem jednolitym",
                "title": "Ustawa z dnia 24 czerwca 2025 r. o zmianie ustawy - Kodeks rodzinny i opiekuńczy",
                "type": "Ustawa",
                "inForce": "NOT_IN_FORCE",
                "ELI": "DU/2025/897",
            },
        ],
    })
}

fn eli_act_answer() -> Value {
    json!({
        "title": "Ustawa z dnia 25 lutego 1964 r. - Kodeks rodzinny i opiekuńczy.",
        "displayAddress": "Dz.U. 1964 nr 9 poz. 59",
        "type": "Ustawa",
        "status": "akt posiada tekst jednolity",
        "inForce": "IN_FORCE",
        "entryIntoForce": "1965-01-01",
        "validFrom": "1965-01-01",
        "changeDate": "2026-07-10T11:02:11",
        "textHTML": true,
        "textPDF": true,
        "keywords": ["alimenty", "cywilne prawo"],
        "references": {
            "Akty zmieniające": [
                {"id": "DU/2025/897", "date": "2025-10-08"},
                {"id": "DU/2023/1843", "date": "2023-09-26"},
            ],
        },
        "ELI": "DU/1964/59",
    })
}

fn eli_refs_answer() -> Value {
    json!({
        "Akty zmieniające": [
            {
                "act": {
                    "ELI": "DU/2025/897",
                    "title": "Ustawa z dnia 24 czerwca 2025 r. o zmianie ustawy - Kodeks rodzinny i opiekuńczy",
                    "promulgation": "2025-07-07",
                },
                "date": "2025-10-08",
            },
            {
                "act": {
                    "ELI": "DU/2023/1843",
                    "title": "Ustawa z dnia 7 lipca 2023 r. o ogólnoeuropejskim indywidualnym produkcie emerytalnym",
                    "promulgation": "2023-09-11",
                },
                "date": "2023-09-26",
            },
        ],
        "Inf. o tekście jednolitym": [
            {
                "act": {
                    "ELI": "DU/2026/236",
                    "title": "Obwieszczenie Marszałka Sejmu",
                    "promulgation": "2026-02-27",
                },
            },
            {
                "act": {
                    "ELI": "DU/2023/2809",
                    "title": "Obwieszczenie Marszałka Sejmu",
                    "promulgation": "2023-12-29",
                },
            },
        ],
    })
}

const ELI_TEXT_HTML: &str = r#"<html><body>
<div class="unit unit_arti" id="book_III-titl_VI-arti_133">
  <h3><b>Art.&nbsp;133.</b></h3>
  <div class="unit unit_para" id="book_III-titl_VI-arti_133-para_1">§ 1. Rodzice obowiązani są do świadczeń alimentacyjnych.</div>
  <div class="unit unit_para" id="book_III-titl_VI-arti_133-para_2">§ 2. <span>Znajduje się w niedostatku.</span></div>
</div>
<div class="unit unit_arti" id="book_III-titl_VI-arti_134"><div>Art. 134. Inny.</div></div>
</body></html>"#;

const ELI_SUP_HTML: &str = r#"<html><body>
<div class="unit unit_arti" id="book_III-titl_VI-arti_449" data-id="arti_449">
  <h3><b>Art.&nbsp;449.</b></h3><div>Plain article.</div></div>
<div class="unit unit_arti" id="book_III-titl_VI_1-arti_449_1" data-id="arti_449_1">
  <h3><b>Art.&nbsp;449<sup>1</sup>.</b></h3>
  <div class="unit unit_para" id="book_III-titl_VI_1-arti_449_1-para_1"><br/>
  <div>Producent odpowiada za szkodę.<img src="x.png"></div></div></div>
<div class="unit unit_arti" id="book_III-titl_VI_1-arti_449a" data-id="arti_449a">
  <div>Letter article.</div></div>
</body></html>"#;

fn saos_search_answer() -> Value {
    json!({
        "items": [{
            "id": 554405,
            "courtType": "COMMON",
            "courtCases": [{"caseNumber": "VI Ca 188/26"}],
            "judgmentType": "REASONS",
            "textContent": " przedstawicielkę ustawową D. T. o podwyższenie <em>alimentów</em> – zasądził od pozwanego.",
            "keywords": ["podwyższenie alimentów"],
            "division": {
                "name": "VI Wydział Cywilny Rodzinny",
                "court": {"name": "Sąd Okręgowy w Olsztynie"},
            },
            "judgmentDate": "2026-10-15",
        }],
        "info": {"totalResults": 17935},
    })
}

fn saos_judgment_answer() -> Value {
    json!({
        "data": {
            "id": 554405,
            "courtType": "COMMON",
            "courtCases": [{"caseNumber": "VI Ca 188/26"}],
            "judgmentType": "REASONS",
            "judgmentDate": "2026-10-15",
            "judges": [{"name": "Robert Kłosowski"}],
            "division": {
                "name": "VI Wydział Cywilny Rodzinny",
                "court": {"name": "Sąd Okręgowy w Olsztynie"},
            },
            "source": {
                "judgmentUrl": "https://apiorzeczenia.wroclaw.sa.gov.pl/ncourt-api/judgement/details?id=1",
            },
            "summary": null,
            "textContent": "<p>Sygn. akt VI Ca 188/26</p>\n    <div>\n      <h2>UZASADNIENIE</h2>\n      <p>Sąd Rejonowy w Olsztynie wyrokiem z dnia 7 maja 2026 r. wydanym w sprawie o sygn. akt III RC 530/25 z powództwa małoletniego W. M. o podwyższenie alimentów – zasądził od pozwanego tytułem podwyższonych alimentów na rzecz małoletniego powoda kwoty po 1200 zł miesięcznie, w miejsce alimentów w kwocie po 700 zł miesięcznie, zasądzonych wyrokiem Sądu Okręgowego w Olsztynie z dnia 25 kwietnia 2018 r. w sprawie VI RC 1772/17.</p></div>",
            "legalBases": ["art. 138 kro"],
            "referencedRegulations": [
                {"text": "Ustawa z dnia 25 lutego 1964 r. - Kodeks rodzinny i opiekuńczy (Dz. U. z 1964 r. Nr 9, poz. 59 - art. 133; art. 135; art. 138)"},
            ],
            "keywords": ["podwyższenie alimentów"],
        },
    })
}

fn eurlex_sparql_answer() -> Value {
    json!({
        "head": {"vars": ["work", "date", "inforce", "eif", "eov", "title_pl", "title_en"]},
        "results": {"bindings": [
            {
                "work": {"type": "uri", "value": "http://publications.europa.eu/resource/cellar/3e485e15"},
                "date": {"type": "literal", "value": "2016-04-27"},
                "inforce": {"type": "literal", "value": "1"},
                "eif": {"type": "literal", "value": "2016-05-24"},
                "eov": {"type": "literal", "value": "9999-12-31"},
                "title_pl": {"type": "literal", "value": "Rozporządzenie Parlamentu Europejskiego i Rady (UE) 2016/679"},
                "title_en": {"type": "literal", "value": "Regulation (EU) 2016/679"},
            },
            {
                "work": {"type": "uri", "value": "http://publications.europa.eu/resource/cellar/3e485e15"},
                "date": {"type": "literal", "value": "2016-04-27"},
                "inforce": {"type": "literal", "value": "1"},
                "eif": {"type": "literal", "value": "2018-05-25"},
                "eov": {"type": "literal", "value": "9999-12-31"},
                "title_pl": {"type": "literal", "value": "Rozporządzenie Parlamentu Europejskiego i Rady (UE) 2016/679"},
                "title_en": {"type": "literal", "value": "Regulation (EU) 2016/679"},
            },
        ]},
    })
}

fn krs_answer() -> Value {
    json!({
        "odpis": {
            "naglowekA": {"numerKRS": "0000028860", "stanZDnia": "09.10.2026"},
            "dane": {
                "dzial1": {
                    "danePodmiotu": {
                        "formaPrawna": "SPÓŁKA AKCYJNA",
                        "identyfikatory": {"regon": "61018820100000", "nip": "7740001454"},
                        "nazwa": "ORLEN SPÓŁKA AKCYJNA",
                    },
                    "siedzibaIAdres": {
                        "adres": {
                            "ulica": "CHEMIKÓW",
                            "nrDomu": "7",
                            "miejscowosc": "PŁOCK",
                            "kodPocztowy": "09-411",
                            "kraj": "POLSKA",
                        },
                    },
                    "kapital": {
                        "wysokoscKapitaluZakladowego": {"wartosc": "1451177561,25", "waluta": "PLN"},
                    },
                },
                "dzial2": {
                    "reprezentacja": {
                        "nazwaOrganu": "ZARZĄD",
                        "sposobReprezentacji": "- DWAJ CZŁONKOWIE ZARZĄDU DZIAŁAJĄCY ŁĄCZNIE",
                        "sklad": [{
                            "nazwisko": {"nazwiskoICzlon": "F*****"},
                            "imiona": {"imie": "I*******"},
                            "funkcjaWOrganie": "PREZES ZARZĄDU",
                        }],
                    },
                },
                "dzial3": {
                    "przedmiotDzialalnosci": {
                        "przedmiotPrzewazajacejDzialalnosci": [{
                            "opis": "WYTWARZANIE I PRZETWARZANIE PRODUKTÓW RAFINACJI ROPY NAFTOWEJ",
                            "kodDzial": "19",
                            "kodKlasa": "20",
                            "kodPodklasa": "Z",
                        }],
                        "przedmiotPozostalejDzialalnosci": [{
                            "opis": "SPRZEDAŻ HURTOWA PALIW",
                            "kodDzial": "46",
                            "kodKlasa": "71",
                            "kodPodklasa": "Z",
                        }],
                    },
                },
            },
        },
    })
}

fn vat_answer() -> Value {
    json!({
        "result": {
            "subject": {
                "name": "ORLEN SPÓŁKA AKCYJNA",
                "statusVat": "Czynny",
                "regon": "610188201",
                "krs": "0000028860",
                "registrationLegalDate": "1993-07-05",
                "removalDate": null,
                "accountNumbers": ["a", "b", "c"],
            },
            "requestId": "adO3M-9938hnd",
        },
    })
}

const KIO_RESULTS_HTML: &str = r#"
<span class="result-count-info">Liczba znalezionych dokumentów: 8719</span>
<div class="search-list-item" style="">
    <p><label>Organ wydający:</label>
    Krajowa Izba Odwo&#x142;awcza</p>
    <p><label>Rodzaj dokumentu:</label> wyrok</p>
    <p><label>Sygnatura:</label> KIO 3766/24</p>
    <p><label>Data wydania:</label> -</p>
    <p class="fragment">, <span class='highlight'>rażąco</span> niska cena</p>
    <a class="link-details"  href="/Home/Details/20846">Wyświetl szczegóły</a>
</div>
<div class="search-list-item" style="">
    <p><label>Organ wydający:</label> Sąd</p>
    <p><label>Rodzaj dokumentu:</label> wyrok</p>
    <p><label>Sygnatura:</label> KIO 2105/22</p>
    <p><label>Data wydania:</label> 05-03-2026</p>
    <p class="fragment">druga</p>
    <a href="/Home/Details/18119">x</a>
</div>
"#;

const KIO_DETAILS_HTML: &str = r#"<h2 class="section-title" style="margin-bottom:0;">KIO 2105/22</h2>
<div>
<p><label aria-label="Organ wydający">Organ wydający</label><br/>Krajowa Izba Odwoławcza</p>
<p><label for="Metrics_DecisionType">Rodzaj dokumentu</label><br/>wyrok</p>
<p><label for="Metrics_IssueDate">Data wydania rozstrzygnięcia</label><br/></p>
<p><label for="Chairman">Przewodniczący</label><br/>Magdalena Rams</p>
<p><label for="Purchaser">Zamawiający</label><br/>Generalna Dyrekcja Dróg</p>
<p><label for="City">Miejscowość</label><br/>Warszawa</p>
<div><label>Sygnatura akt / Sposób rozstrzygnięcia</label><ul><li>KIO 2105/22 / oddalone</li></ul></div>
<p><label for="Procedure">Tryb postępowania</label><br/>przetarg nieograniczony</p>
<p><label for="ContractType">Rodzaj zamówienia</label><br/></p>
</div>
<b>Kluczowe przepisy ustawy Pzp</b>
<p style="margin-top:5px"><a href="/x">art. 224 ust. 1</a>; <a href="/y">art. 226</a></p>
<b>Zagadnienia merytoryczne w odwołaniu</b>
<p><a href="/z">zasada uczciwej konkurencji</a></p>
"#;

fn kio_content_html() -> String {
    let filler = "Sąd zważył, co następuje. ".repeat(40);
    format!(
        "<div><p>Sygn. akt: KIO 2105/22</p><p>WYROK</p><p>z dnia 25 sierpnia 2022 r.</p><p>{filler}</p><p>Oddala odwołanie.</p></div>"
    )
}

const UOKIK_SEARCHVIEW_HTML: &str = r#"<TABLE><TR ><text><b>Numer decyzji: </b><a class="bluelink" HREF=/bp/dec_prez.nsf/1/86734DC793D1A570C125880D0037E958?editDocument&act=Decyzja>DKK-69/2022</a><BR><b>Data decyzji:      </B>02.03.2022<BR>Allegro.pl sp. z o.o. z siedzibą w Poznaniu <br><b>Rodzaj praktyki: </b>Kontrola koncentracji</text></TR ><hr/><TR ><text><b>Numer decyzji: </b><a HREF=/bp/dec_prez.nsf/1/EFC05E0C47FEE157C1257F8F0031EF80?editDocument&act=Decyzja>DDK-1/2016</a><BR><b>Data decyzji:      </B>09.02.2016<BR><a href=/x>Grupa Allegro sp. z o.o.</a>, <br><b>Rodzaj praktyki: </b>Ochrona zbiorowych interesów konsumentów</text></TR ><hr/></TABLE>"#;

const UOKIK_DECISION_HTML: &str = r#"<table>
<tr valign="top"><td width="113"><b>Numer decyzji:</b></td><td width="397">DDK-1/2016    </td></tr>
<tr valign="top"><td width="113"><b>Data wydania decyzji:</b></td><td width="397">02/09/2016</td></tr>
<tr valign="top"><td width="113"><b>Sygnatura akt:</b></td><td width="397">DDK-61-6/14/MN</td></tr>
<tr valign="top"><td width="113"><b>Uczestnicy postępowania:</b></td><td width="397"> <a href=/x>Grupa Allegro spółka z ograniczoną odpowiedzialnością z siedzibą w Poznaniu</a>,  </td></tr>
<tr valign="top"><td width="113"><b>Rodzaj praktyki:</b></td><td width="397">Ochrona zbiorowych interesów konsumentów</td></tr>
<tr valign="top"><td width="113"><b>Kara:</b></td><td width="397">Nie</td></tr>
<tr valign="top"><td width="113"><b>Branża:</b></td><td width="397">63.12 PORTALE</td></tr>
<tr valign="top"><td width="113"><b>Region:</b></td><td width="397">Wielkopolskie</td></tr>
<tr valign="top"><td width="113"><b>Decyzja:</b></td><td width="397"><div><a href="/bp/dec_prez.nsf/43104c28a7a1be23c1257eac006d8dd4/efc05e0c47fee157c1257f8f0031ef80/$FILE/DDK%201_2016%20-%20Allegro%20%20-%20w.%20jawna.pdf" title="x"><img src="y"></a></div></td></tr>
<tr valign="top"><td width="113"><b>Odwołanie do sądu:</b></td><td width="397"><font face="Arial">Tak</font></td></tr>
</table>
<tbody><tr><td><p><b>Sygnatura akt: </b><a HREF="/bp/wyroki.nsf/0/CD2E9D4E218F6DD7C12583A1004C8C61?editDocument&act=Wyrok">XVII Ama 51/16</a><BR><b>Data wyroku:      </B>25.01.2019<BR><b>Dotyczy: </b></p></td></tr></tbody>"#;

const UOKIK_UNID: &str = "EFC05E0C47FEE157C1257F8F0031EF80";
const UOKIK_PDF_PATH: &str = "/bp/dec_prez.nsf/43104c28a7a1be23c1257eac006d8dd4/efc05e0c47fee157c1257f8f0031ef80/$FILE/DDK%201_2016%20-%20Allegro%20%20-%20w.%20jawna.pdf";

fn duw_search_answer() -> Value {
    json!({
        "LegalActs": [
            {
                "PublicationDate": "2026-09-11T10:41:24.967",
                "ActDate": "2026-08-27T00:00:00",
                "Publisher": "Rady Miejskiej w Kątach Wrocławskich",
                "CaseNumber": "XXX/303/2026",
                "LegalActType": "Uchwała",
                "Title": "Uchwała nr XXX/303/2026 Rady Miejskiej w Kątach Wrocławskich",
                "Position": 4019,
                "Year": 2026,
            },
            {
                "PublicationDate": "2026-09-04T10:14:36.417",
                "ActDate": "2026-08-27T00:00:00",
                "Publisher": "Rady Miejskiej w Bardzie",
                "CaseNumber": "XXXVII/181/2026",
                "LegalActType": "Uchwała",
                "Title": "Uchwała nr XXXVII/181/2026 Rady Miejskiej w Bardzie",
                "Position": 3896,
                "Year": 2026,
            },
            {
                "PublicationDate": "2026-07-14T10:53:25.797",
                "ActDate": "2026-06-30T00:00:00",
                "Publisher": "Rady Miasta Lubań",
                "CaseNumber": "XXXIV/193/2026",
                "LegalActType": "Uchwała",
                "Title": "Uchwała nr XXXIV/193/2026 Rady Miasta Lubań",
                "Position": 3300,
                "Year": 2026,
            },
        ],
        "TotalItems": 1243,
    })
}

fn duw_legalact_answer() -> Value {
    json!({
        "ActPositionNumber": "2026.4019",
        "Title": "Uchwała nr XXX/303/2026 Rady Miejskiej w Kątach Wrocławskich",
        "LegalActType": "Uchwała",
        "CaseNumber": "XXX/303/2026",
        "ActDate": "2026-08-27T00:00:00",
        "PublicationDate": "2026-09-11T10:41:24.967",
        "PublisherGenetive": "Rady Miejskiej w Kątach Wrocławskich",
        "Keywords": [{"Name": "zasady gospodarki nieruchomościami"}],
        "Publishers": [{"Name": "Rada Miejska w Kątach Wrocławskich"}],
        "ActStatus": {"IsInvalid": false, "IsPartialInvalid": false, "Description": ""},
    })
}

// ── contract: names, descriptions and input schemas ────────────────────────────────────────

fn contract() -> Vec<(&'static str, &'static str, Value)> {
    vec![
        (
            "legal_duw_document",
            concat!(
                "One position of the Dolnośląskie official journal by (year, position): title, act type\n",
                "and number, issuing body, act and publication dates, keywords, status and the act text\n",
                "(plain, from the published PDF). Cite `url`."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "year": {"type": "integer"},
                    "position": {"type": "integer"},
                    "max_chars": {"default": 25000, "type": "integer"},
                },
                "required": ["year", "position"],
            }),
        ),
        (
            "legal_duw_search",
            concat!(
                "Search the official journal of the Dolnośląskie voivodeship (local law: municipal and\n",
                "county resolutions, voivode orders) by words of the act title, optionally one year. Newest\n",
                "first. Returns (year, position) for legal_duw_document."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"type": "string"},
                    "year": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": null},
                    "page": {"default": 1, "type": "integer"},
                    "page_size": {"default": 20, "type": "integer"},
                },
                "required": ["query"],
            }),
        ),
        (
            "legal_eli_act",
            concat!(
                "Metadata of one Polish act by ELI id (e.g. \"DU/1964/59\"): status, whether it is in force,\n",
                "dates, keywords, and related acts (amending acts, consolidated texts \"Inf. o tekście\n",
                "jednolitym\", Constitutional Tribunal rulings, ...)."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"eli": {"type": "string"}},
                "required": ["eli"],
            }),
        ),
        (
            "legal_eli_act_text",
            concat!(
                "Text of a Polish act by ELI id; with `article` (\"133\", \"133a\", \"133^1\") only that article.\n\n",
                "wording=\"current\" (default): the newest consolidated text (\"tekst jednolity\") of the act,\n",
                "HTML or else its PDF. Amendments published after that consolidation are NOT in it; they are\n",
                "listed in amended_after_consolidation ({eli, promulgation, date_unknown}) -- tell the reader to\n",
                "check them. consolidation_date_inferred=true means the cut-off was not published and a\n",
                "conservative earlier date was used, so the list may over-report. Without any\n",
                "consolidation the act's own text is used and every amending act is listed.\n",
                "wording=\"original\": the act's HTML text as originally published."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "eli": {"type": "string"},
                    "article": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "wording": {"default": "current", "enum": ["current", "original"], "type": "string"},
                    "max_chars": {"default": 30000, "type": "integer"},
                },
                "required": ["eli"],
            }),
        ),
        (
            "legal_eli_search",
            concat!(
                "Search Polish legal acts (Dziennik Ustaw / Monitor Polski) in the Sejm ELI database.\n\n",
                "title: words of the act title (e.g. \"kodeks rodzinny\"); keyword: ELI subject keyword;\n",
                "type: act type such as \"Ustawa\", \"Rozporządzenie\", \"Obwieszczenie\". Returns ELI ids\n",
                "(e.g. \"DU/1964/59\") to pass to legal_eli_act / legal_eli_act_text."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "title": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "keyword": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "year": {"anyOf": [{"type": "integer"}, {"type": "null"}], "default": null},
                    "type": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "in_force_only": {"default": true, "type": "boolean"},
                    "publisher": {"default": "DU", "enum": ["DU", "MP"], "type": "string"},
                    "limit": {"default": 20, "type": "integer"},
                    "offset": {"default": 0, "type": "integer"},
                },
            }),
        ),
        (
            "legal_eurlex_act",
            concat!(
                "Metadata of one EU act by CELEX number (e.g. \"32016R0679\" = GDPR): Polish and English\n",
                "title, document date, whether it is in force, entry-into-force dates, end of validity."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {"celex": {"type": "string"}},
                "required": ["celex"],
            }),
        ),
        (
            "legal_eurlex_text",
            concat!(
                "Plain text of an EU act by CELEX number, from CELLAR (lang: ISO 639-2 code, default\n",
                "\"pol\"; \"eng\" for English)."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "celex": {"type": "string"},
                    "max_chars": {"default": 30000, "type": "integer"},
                    "lang": {"default": "pol", "type": "string"},
                },
                "required": ["celex"],
            }),
        ),
        (
            "legal_kio_document",
            concat!(
                "One KIO ruling by the id from legal_kio_search: signature(s) and outcome, date, body,\n",
                "contracting authority, key Pzp provisions and the full ruling text (plain). Cite `url`."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "id": {"type": "integer"},
                    "max_chars": {"default": 25000, "type": "integer"},
                },
                "required": ["id"],
            }),
        ),
        (
            "legal_kio_search",
            concat!(
                "Search KIO (National Appeal Chamber, public procurement) rulings on orzeczenia.uzp.gov.pl\n",
                "by phrase (e.g. \"rażąco niska cena\", \"art. 224 ust. 1\") and/or signature (\"KIO 2105/22\").\n",
                "10 hits per page, most relevant first. Returns ids for legal_kio_document."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "signature": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "document_type": {
                        "anyOf": [
                            {"enum": ["wyrok", "postanowienie", "uchwała"], "type": "string"},
                            {"type": "null"},
                        ],
                        "default": null,
                    },
                    "page": {"default": 1, "type": "integer"},
                },
            }),
        ),
        (
            "legal_krs_extract",
            concat!(
                "Current KRS extract of a Polish company / organisation by KRS number (register \"P\" =\n",
                "entrepreneurs, \"S\" = associations/foundations): name, legal form, NIP, REGON, address,\n",
                "share capital, who represents it and how, main business activities. Personal names are\n",
                "masked by the source."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "krs": {"type": "string"},
                    "register": {"default": "P", "enum": ["P", "S"], "type": "string"},
                },
                "required": ["krs"],
            }),
        ),
        (
            "legal_saos_judgment",
            concat!(
                "One Polish court judgment from SAOS by numeric id: court, judges, legal bases,\n",
                "referenced regulations and the full text (plain)."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "id": {"type": "integer"},
                    "max_chars": {"default": 60000, "type": "integer"},
                },
                "required": ["id"],
            }),
        ),
        (
            "legal_saos_search",
            concat!(
                "Full-text search of Polish court judgments (SAOS), newest first. Dates YYYY-MM-DD.\n",
                "Returns judgment ids for legal_saos_judgment."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"type": "string"},
                    "court_type": {
                        "anyOf": [
                            {"enum": [
                                "COMMON", "SUPREME", "ADMINISTRATIVE",
                                "CONSTITUTIONAL_TRIBUNAL", "NATIONAL_APPEAL_CHAMBER"
                            ], "type": "string"},
                            {"type": "null"},
                        ],
                        "default": null,
                    },
                    "case_number": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "date_from": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "date_to": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "page_size": {"default": 10, "type": "integer"},
                    "page": {"default": 0, "type": "integer"},
                },
                "required": ["query"],
            }),
        ),
        (
            "legal_uokik_document",
            concat!(
                "One UOKiK President's decision by the unid from legal_uokik_search: number, date, case\n",
                "signature, participants, practice, penalty, appeal, related court judgments and the decision\n",
                "text (plain, from the published PDF). Cite `url`."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "unid": {"type": "string"},
                    "max_chars": {"default": 25000, "type": "integer"},
                },
                "required": ["unid"],
            }),
        ),
        (
            "legal_uokik_search",
            concat!(
                "Search decisions of the President of UOKiK (competition and consumer protection) on\n",
                "decyzje.uokik.gov.pl: full-text words, decision number (\"DDK-1/2016\"), case signature or a\n",
                "participant (company) name. Returns unids for legal_uokik_document."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "query": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "decision_number": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "signature": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "participant": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "page": {"default": 1, "type": "integer"},
                    "page_size": {"default": 20, "type": "integer"},
                },
            }),
        ),
        (
            "legal_vat_whitelist",
            concat!(
                "Check a Polish VAT taxpayer on the Ministry of Finance whitelist by NIP: VAT status\n",
                "(\"Czynny\" active, \"Zwolniony\" exempt, or not registered), name, REGON, KRS, dates and the\n",
                "number of registered bank accounts. With `account` (26-digit NRB) it instead answers whether\n",
                "that account is registered for the NIP on the date (default today, Europe/Warsaw)."
            ),
            json!({
                "type": "object",
                "additionalProperties": false,
                "properties": {
                    "nip": {"type": "string"},
                    "date": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                    "account": {"anyOf": [{"type": "string"}, {"type": "null"}], "default": null},
                },
                "required": ["nip"],
            }),
        ),
    ]
}

#[test]
fn the_registry_is_exactly_the_fifteen_tool_contract() {
    let mut provider = BuiltinProvider::new();
    legal::register_with(&mut provider, true);

    let tools = provider.list(&researcher());
    let expected = contract();
    assert_eq!(
        tools.len(),
        expected.len(),
        "the legal contract is 15 tools"
    );
    let names: Vec<&str> = tools.iter().map(|tool| tool.name.as_ref()).collect();
    assert_eq!(
        names,
        [
            "legal_duw_document",
            "legal_duw_search",
            "legal_eli_act",
            "legal_eli_act_text",
            "legal_eli_search",
            "legal_eurlex_act",
            "legal_eurlex_text",
            "legal_kio_document",
            "legal_kio_search",
            "legal_krs_extract",
            "legal_saos_judgment",
            "legal_saos_search",
            "legal_uokik_document",
            "legal_uokik_search",
            "legal_vat_whitelist",
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
    assert_eq!(provider.list(&licence_caller()).len(), 15);
    assert!(provider.list(&executor()).is_empty());
    assert!(
        provider
            .list(&BuiltinCaller {
                scope: "unknown-client".to_owned(),
                subject: "unknown-client".to_owned(),
                ..executor()
            })
            .is_empty()
    );
}

#[tokio::test]
async fn uokik_tools_are_absent_unless_the_gate_is_on() {
    let mut disabled = BuiltinProvider::new();
    legal::register_with(&mut disabled, false);
    let tools = disabled.list(&researcher());
    assert_eq!(tools.len(), 13);
    assert!(
        tools
            .iter()
            .all(|tool| !tool.name.starts_with("legal_uokik"))
    );
    // A disabled tool is refused on call, before any handler runs.
    let result = disabled
        .call(&researcher(), "legal_uokik_search", args(json!({})))
        .await;
    assert_eq!(result.is_error, Some(true));
    assert_eq!(
        result.content[0].as_text().expect("a text block").text,
        DENIED_MESSAGE
    );

    let mut enabled = BuiltinProvider::new();
    legal::register_with(&mut enabled, true);
    assert_eq!(enabled.list(&researcher()).len(), 15);
}

#[test]
fn the_uokik_gate_accepts_exactly_the_reference_spellings() {
    for raw in [
        Some("1"),
        Some("true"),
        Some("yes"),
        Some("TRUE"),
        Some(" yes "),
    ] {
        assert!(legal::uokik_enabled_value(raw), "{raw:?}");
    }
    for raw in [
        None,
        Some(""),
        Some("0"),
        Some("false"),
        Some("on"),
        Some("no"),
    ] {
        assert!(!legal::uokik_enabled_value(raw), "{raw:?}");
    }
}

// ── ELI ────────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn eli_search_maps_items_and_sends_filters() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/eli/acts/search",
        StatusCode::OK,
        eli_search_answer(),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::search(
        &clients,
        &args(json!({"title": "kodeks rodzinny i opiekuńczy", "limit": 500})),
    )
    .await
    .expect("an ELI search answer");
    assert_eq!(out["total"], 2);
    assert_eq!(
        out["items"][0],
        json!({
            "eli": "DU/2026/236",
            "title": "Obwieszczenie Marszałka Sejmu Rzeczypospolitej Polskiej z dnia 20 lutego 2026 r.",
            "address": "Dz.U. 2026 poz. 236",
            "type": "Obwieszczenie",
            "status": "obowiązujący",
            "in_force": true,
            "promulgation": "2026-02-27",
        })
    );
    assert_eq!(out["items"][1]["in_force"], Value::Bool(false));
    let request = only(&stub);
    assert_eq!(request.method, "GET");
    assert_eq!(
        query_params(&request),
        HashMap::from([
            ("publisher".to_owned(), "DU".to_owned()),
            (
                "title".to_owned(),
                "kodeks rodzinny i opiekuńczy".to_owned()
            ),
            ("inForce".to_owned(), "1".to_owned()),
            ("limit".to_owned(), "100".to_owned()),
            ("offset".to_owned(), "0".to_owned()),
        ])
    );
    assert_eq!(
        header(&request, "user-agent"),
        Some("nonagenticai-mcp-legal/1.0 (+https://nonagentic.ai)")
    );
}

#[tokio::test]
async fn eli_search_without_the_in_force_filter_and_with_mp() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/eli/acts/search",
        StatusCode::OK,
        json!({"count": 0, "items": []}),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::search(
        &clients,
        &args(json!({"keyword": "alimenty", "in_force_only": false, "publisher": "MP"})),
    )
    .await
    .expect("an empty answer");
    assert_eq!(out, json!({"total": 0, "items": []}));
    let params = query_params(&only(&stub));
    assert!(!params.contains_key("inForce"));
    assert_eq!(params["publisher"], "MP");
}

#[tokio::test]
async fn eli_act_maps_metadata_and_titled_references() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59",
        StatusCode::OK,
        eli_act_answer(),
    );
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59/references",
        StatusCode::OK,
        eli_refs_answer(),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act(&clients, &args(json!({"eli": "DU/1964/59"})))
        .await
        .expect("an ELI act answer");
    assert_eq!(
        out["title"],
        "Ustawa z dnia 25 lutego 1964 r. - Kodeks rodzinny i opiekuńczy."
    );
    assert_eq!(out["in_force"], Value::Bool(true));
    assert_eq!(out["entry_into_force"], "1965-01-01");
    assert_eq!(out["valid_from"], "1965-01-01");
    assert_eq!(out["has_html"], Value::Bool(true));
    assert_eq!(out["keywords"], json!(["alimenty", "cywilne prawo"]));
    assert_eq!(
        out["references"]["Akty zmieniające"][0],
        json!({
            "eli": "DU/2025/897",
            "title": "Ustawa z dnia 24 czerwca 2025 r. o zmianie ustawy - Kodeks rodzinny i opiekuńczy",
            "date": "2025-10-08",
        })
    );
    assert_eq!(
        out["text_url_html"],
        format!("{base}/eli/acts/DU/1964/59/text.html")
    );
    assert_eq!(
        out["text_url_pdf"],
        format!("{base}/eli/acts/DU/1964/59/text.pdf")
    );
    let mut paths: Vec<String> = stub.requests().iter().map(|r| r.path.clone()).collect();
    paths.sort();
    assert_eq!(
        paths,
        ["/eli/acts/DU/1964/59", "/eli/acts/DU/1964/59/references"]
    );
}

#[tokio::test]
async fn eli_act_falls_back_to_untitled_references_and_caps_them() {
    let (base, stub, _locations) = local_server().await;
    let mut act = eli_act_answer();
    act["references"]["Akty zmieniające"] = Value::Array(
        (0..80)
            .map(|index| json!({"id": format!("DU/2000/{index}")}))
            .collect(),
    );
    stub.json("GET", "/eli/acts/DU/1964/59", StatusCode::OK, act);
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59/references",
        StatusCode::SERVICE_UNAVAILABLE,
        json!({}),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act(&clients, &args(json!({"eli": "DU/1964/59"})))
        .await
        .expect("the fallback answer");
    let references = out["references"]["Akty zmieniające"]
        .as_array()
        .expect("a reference list");
    assert_eq!(references.len(), 50);
    assert_eq!(
        references[0],
        json!({"eli": "DU/2000/0", "title": null, "date": null})
    );
}

#[tokio::test]
async fn eli_act_text_cuts_one_article_from_html() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/eli/acts/DU/1964/59/text.html",
        StatusCode::OK,
        ELI_TEXT_HTML,
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/59", "article": "133", "wording": "original"})),
    )
    .await
    .expect("an article answer");
    assert_eq!(out["article"], "133");
    assert_eq!(out["wording"], "original");
    assert_eq!(out["source_eli"], "DU/1964/59");
    assert_eq!(out["source_format"], "html");
    assert_eq!(out["consolidation_date"], Value::Null);
    assert_eq!(out["truncated"], Value::Bool(false));
    assert_eq!(
        out["text"],
        "Art. 133.\n§ 1. Rodzice obowiązani są do świadczeń alimentacyjnych.\n§ 2. Znajduje się w niedostatku."
    );
    assert_eq!(only(&stub).path, "/eli/acts/DU/1964/59/text.html");
}

#[tokio::test]
async fn eli_act_text_accepts_every_superscript_form() {
    for article in ["449^1", "449(1)", "449_1", "449¹", "Art. 449^1"] {
        let (base, stub, _locations) = local_server().await;
        stub.text(
            "GET",
            "/eli/acts/DU/1964/93/text.html",
            StatusCode::OK,
            ELI_SUP_HTML,
        );
        let clients = clients_for(Service::Eli, &base);
        let out = legal::eli::act_text(
            &clients,
            &args(json!({"eli": "DU/1964/93", "article": article, "wording": "original"})),
        )
        .await
        .unwrap_or_else(|error| panic!("{article}: {error}"));
        assert_eq!(
            out["text"], "Art. 449^1.\nProducent odpowiada za szkodę.",
            "{article}"
        );
    }
}

#[tokio::test]
async fn eli_act_text_unknown_article_is_permanent() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/eli/acts/DU/1964/93/text.html",
        StatusCode::OK,
        ELI_SUP_HTML,
    );
    let clients = clients_for(Service::Eli, &base);
    let error = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/93", "article": "999", "wording": "original"})),
    )
    .await
    .expect_err("an unknown article");
    assert!(
        error.starts_with("[permanent] article 999 not found"),
        "{error}"
    );
}

#[tokio::test]
async fn eli_bad_ids_are_rejected_before_any_request() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Eli, &base);
    for bad in [
        "../../admin",
        "DU/1964/59/../../x",
        "DU/1964/59?x=1",
        "XX/1964/59",
        "DU/64/59",
        "DU/1964/123456",
        "",
        "du/1964/59",
        "DU/1964/59/",
    ] {
        for tool in ["act", "act_text"] {
            let result = if tool == "act" {
                legal::eli::act(&clients, &args(json!({"eli": bad}))).await
            } else {
                legal::eli::act_text(&clients, &args(json!({"eli": bad}))).await
            };
            let error = result.expect_err("a bad eli");
            assert!(
                error.starts_with("[permanent] invalid eli"),
                "{bad}: {error}"
            );
        }
    }
    for bad in ["133; drop", "../1", "abc", "133^", "1111111", "133-para_1"] {
        let error = legal::eli::act_text(
            &clients,
            &args(json!({"eli": "DU/1964/59", "article": bad})),
        )
        .await
        .expect_err("a bad article");
        assert!(
            error.starts_with("[permanent] invalid article"),
            "{bad}: {error}"
        );
    }
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn eli_act_text_empty_html_is_pdf_only() {
    let (base, stub, _locations) = local_server().await;
    stub.text("GET", "/eli/acts/DU/2026/236/text.html", StatusCode::OK, "");
    let clients = clients_for(Service::Eli, &base);
    let error = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/2026/236", "wording": "original"})),
    )
    .await
    .expect_err("PDF only");
    assert!(
        error.starts_with("[permanent] no HTML text (PDF only):"),
        "{error}"
    );
    assert!(error.ends_with("text.pdf"), "{error}");
}

#[tokio::test]
async fn eli_act_text_whole_act_is_truncated_in_characters() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/eli/acts/DU/1964/59/text.html",
        StatusCode::OK,
        &ELI_TEXT_HTML.repeat(20),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/59", "max_chars": 600, "wording": "original"})),
    )
    .await
    .expect("a truncated answer");
    assert_eq!(out["article"], Value::Null);
    assert_eq!(out["truncated"], Value::Bool(true));
    assert_eq!(out["text"].as_str().expect("text").chars().count(), 600);
}

fn consolidated_html() -> &'static str {
    r#"<html><body>
<div class="unit unit_arti" id="book_III-titl_VI-arti_133">
  <h3><b>Art.&nbsp;133.</b></h3>
  <div class="unit unit_para" id="book_III-titl_VI-arti_133-para_1">§ 1. Rodzice obowiązani są do świadczeń alimentacyjnych.</div>
  <div class="unit unit_para" id="book_III-titl_VI-arti_133-para_3">§ 3. Rodzice mogą uchylić się od świadczeń alimentacyjnych.</div>
</div></body></html>"#
}

fn tj_meta(text_html: bool) -> Value {
    json!({
        "textHTML": text_html,
        "legalStatusDate": "2026-02-19",
        "texts": [
            {"type": "O", "fileName": "D20260236.pdf"},
            {"type": "T", "fileName": "D20260236L.pdf"},
        ],
        "ELI": "DU/2026/236",
    })
}

#[tokio::test]
async fn eli_act_text_current_wording_prefers_consolidated_html() {
    let (base, stub, _locations) = local_server().await;
    let mut references = eli_refs_answer();
    references["Akty zmieniające"] = json!([
        {"act": {"ELI": "DU/2025/897", "promulgation": "2025-07-07"}, "date": "2025-10-08"},
        {"act": {"ELI": "DU/2026/900", "promulgation": "2026-06-01"}, "date": "2026-07-01"},
        {"act": {"ELI": "DU/2026/100", "promulgation": "2026-02-18"}, "date": "2026-03-01"},
        {"act": {"ELI": "DU/2026/240", "promulgation": "2026-02-19"}, "date": "2026-03-05"},
        {"act": {"ELI": "DU/2026/999"}, "date": null},
        {"act": {"ELI": "DU/1993/78"}, "date": null},
    ]);
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59/references",
        StatusCode::OK,
        references,
    );
    stub.json(
        "GET",
        "/eli/acts/DU/2026/236",
        StatusCode::OK,
        tj_meta(true),
    );
    stub.text(
        "GET",
        "/eli/acts/DU/2026/236/text.html",
        StatusCode::OK,
        consolidated_html(),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/59", "article": "133"})),
    )
    .await
    .expect("the consolidated answer");
    assert_eq!(out["source_eli"], "DU/2026/236");
    assert_eq!(out["source_format"], "html");
    assert_eq!(out["consolidation_date"], "2026-02-19");
    assert_eq!(out["consolidation_date_inferred"], Value::Bool(false));
    assert_eq!(
        out["amended_after_consolidation"],
        json!([
            {"eli": "DU/2026/240", "promulgation": "2026-02-19", "date_unknown": false},
            {"eli": "DU/2026/900", "promulgation": "2026-06-01", "date_unknown": false},
            {"eli": "DU/2026/999", "promulgation": null, "date_unknown": true},
        ])
    );
    assert_eq!(
        out["text"],
        "Art. 133.\n§ 1. Rodzice obowiązani są do świadczeń alimentacyjnych.\n§ 3. Rodzice mogą uchylić się od świadczeń alimentacyjnych."
    );
    let paths: Vec<String> = stub.requests().iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        [
            "/eli/acts/DU/1964/59/references",
            "/eli/acts/DU/2026/236",
            "/eli/acts/DU/2026/236/text.html",
        ]
    );
}

#[tokio::test]
async fn eli_act_text_missing_legal_status_date_is_inferred() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59/references",
        StatusCode::OK,
        eli_refs_answer(),
    );
    let mut meta = tj_meta(true);
    meta.as_object_mut()
        .expect("an object")
        .remove("legalStatusDate");
    stub.json("GET", "/eli/acts/DU/2026/236", StatusCode::OK, meta);
    stub.text(
        "GET",
        "/eli/acts/DU/2026/236/text.html",
        StatusCode::OK,
        consolidated_html(),
    );
    let clients = clients_for(Service::Eli, &base);
    let out = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/59", "article": "133"})),
    )
    .await
    .expect("the inferred answer");
    assert_eq!(out["consolidation_date"], "2023-12-29");
    assert_eq!(out["consolidation_date_inferred"], Value::Bool(true));
    assert_eq!(
        out["amended_after_consolidation"],
        json!([{"eli": "DU/2025/897", "promulgation": "2025-07-07", "date_unknown": false}])
    );
}

#[tokio::test]
async fn eli_act_text_pdf_only_path_fetches_the_typed_pdf_and_stops() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/eli/acts/DU/1964/59/references",
        StatusCode::OK,
        eli_refs_answer(),
    );
    stub.json(
        "GET",
        "/eli/acts/DU/2026/236",
        StatusCode::OK,
        tj_meta(false),
    );
    stub.bytes(
        "GET",
        "/eli/acts/DU/2026/236/text/T/D20260236L.pdf",
        StatusCode::OK,
        b"%PDF-1.4\n%test\n",
        "application/pdf",
    );
    let clients = clients_for(Service::Eli, &base);
    let error = legal::eli::act_text(
        &clients,
        &args(json!({"eli": "DU/1964/59", "article": "133"})),
    )
    .await
    .expect_err("the PDF parser is not ported");
    assert!(
        error.starts_with("[permanent] cannot read the PDF text"),
        "{error}"
    );
    let paths: Vec<String> = stub.requests().iter().map(|r| r.path.clone()).collect();
    assert_eq!(
        paths,
        [
            "/eli/acts/DU/1964/59/references",
            "/eli/acts/DU/2026/236",
            "/eli/acts/DU/2026/236/text/T/D20260236L.pdf",
        ]
    );
}

// ── SAOS ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn saos_search_maps_items_and_strips_highlights() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/search/judgments",
        StatusCode::OK,
        saos_search_answer(),
    );
    let clients = clients_for(Service::Saos, &base);
    let out = legal::saos::search(
        &clients,
        &args(json!({
            "query": "alimenty",
            "court_type": "COMMON",
            "date_from": "2026-01-01",
            "page_size": 3,
        })),
    )
    .await
    .expect("a SAOS answer");
    assert_eq!(out["total"], 17935);
    assert_eq!(out["items"][0]["id"], 554405);
    assert_eq!(out["items"][0]["case_numbers"], json!(["VI Ca 188/26"]));
    assert_eq!(out["items"][0]["judgment_date"], "2026-10-15");
    assert_eq!(out["items"][0]["court"], "Sąd Okręgowy w Olsztynie");
    assert_eq!(out["items"][0]["division"], "VI Wydział Cywilny Rodzinny");
    assert_eq!(
        out["items"][0]["keywords"],
        json!(["podwyższenie alimentów"])
    );
    let snippet = out["items"][0]["snippet"].as_str().expect("a snippet");
    assert!(
        !snippet.contains("<em>") && snippet.contains("alimentów"),
        "{snippet}"
    );
    assert_eq!(
        query_params(&only(&stub)),
        HashMap::from([
            ("all".to_owned(), "alimenty".to_owned()),
            ("courtType".to_owned(), "COMMON".to_owned()),
            ("judgmentDateFrom".to_owned(), "2026-01-01".to_owned()),
            ("pageSize".to_owned(), "3".to_owned()),
            ("pageNumber".to_owned(), "0".to_owned()),
            ("sortingField".to_owned(), "JUDGMENT_DATE".to_owned()),
            ("sortingDirection".to_owned(), "DESC".to_owned()),
        ])
    );
}

#[tokio::test]
async fn saos_rejects_bad_input_before_any_request() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Saos, &base);
    for arguments in [
        json!({"query": " "}),
        json!({"query": "x".repeat(501)}),
        json!({"query": "a", "date_to": "15.10.2026"}),
    ] {
        let error = legal::saos::search(&clients, &args(arguments))
            .await
            .expect_err("bad input");
        assert!(error.starts_with("[permanent] "), "{error}");
    }
    for id in [0, -5, 10_000_000_000_i64] {
        let error = legal::saos::judgment(&clients, &args(json!({"id": id})))
            .await
            .expect_err("a bad id");
        assert!(error.starts_with("[permanent] invalid id"), "{error}");
    }
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn saos_judgment_maps_and_converts_html() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/judgments/554405",
        StatusCode::OK,
        saos_judgment_answer(),
    );
    let clients = clients_for(Service::Saos, &base);
    let out = legal::saos::judgment(&clients, &args(json!({"id": 554405})))
        .await
        .expect("a judgment");
    assert_eq!(out["case_numbers"], json!(["VI Ca 188/26"]));
    assert_eq!(out["court"], "Sąd Okręgowy w Olsztynie");
    assert_eq!(out["judges"], json!(["Robert Kłosowski"]));
    assert_eq!(out["legal_bases"], json!(["art. 138 kro"]));
    assert!(
        out["referenced_regulations"][0]
            .as_str()
            .expect("a regulation")
            .contains("Kodeks rodzinny")
    );
    assert_eq!(out["summary"], Value::Null);
    let text = out["text"].as_str().expect("text");
    assert!(
        text.starts_with("Sygn. akt VI Ca 188/26\nUZASADNIENIE"),
        "{text}"
    );
    assert!(!text.contains('<'), "{text}");
    assert_eq!(out["truncated"], Value::Bool(false));
    assert!(
        out["url"]
            .as_str()
            .expect("url")
            .starts_with("https://apiorzeczenia.wroclaw.sa.gov.pl/")
    );
    assert_eq!(only(&stub).path, "/api/judgments/554405");
}

#[tokio::test]
async fn saos_judgment_truncates_to_the_requested_bound() {
    let (base, stub, _locations) = local_server().await;
    let mut answer = saos_judgment_answer();
    answer["data"]["textContent"] = Value::String(format!(
        "<p>Sygn. akt VI Ca 188/26</p><p>{}</p>",
        "Uzasadnienie. ".repeat(200)
    ));
    stub.json("GET", "/api/judgments/554405", StatusCode::OK, answer);
    let clients = clients_for(Service::Saos, &base);
    let out = legal::saos::judgment(&clients, &args(json!({"id": 554405, "max_chars": 500})))
        .await
        .expect("a truncated judgment");
    assert_eq!(out["truncated"], Value::Bool(true));
    assert_eq!(out["text"].as_str().expect("text").chars().count(), 500);
}

#[tokio::test]
async fn saos_judgment_404_is_the_reference_message() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Saos, &base);
    let error = legal::saos::judgment(&clients, &args(json!({"id": 1})))
        .await
        .expect_err("a missing judgment");
    assert_eq!(error, "[permanent] judgment not found");
    assert_eq!(only(&stub).path, "/api/judgments/1");
}

// ── EUR-Lex ───────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn eurlex_act_maps_sparql_and_sends_the_typed_literal() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "POST",
        "/webapi/rdf/sparql",
        StatusCode::OK,
        eurlex_sparql_answer(),
    );
    let clients = clients_for(Service::Cellar, &base);
    let out = legal::eurlex::act(&clients, &args(json!({"celex": "32016R0679"})))
        .await
        .expect("a SPARQL answer");
    assert_eq!(out["celex"], "32016R0679");
    assert_eq!(
        out["title_pl"],
        "Rozporządzenie Parlamentu Europejskiego i Rady (UE) 2016/679"
    );
    assert_eq!(out["title_en"], "Regulation (EU) 2016/679");
    assert_eq!(out["date_document"], "2016-04-27");
    assert_eq!(out["in_force"], Value::Bool(true));
    assert_eq!(out["entry_into_force"], json!(["2016-05-24", "2018-05-25"]));
    assert_eq!(out["end_of_validity"], "9999-12-31");
    assert!(
        out["text_url"]
            .as_str()
            .expect("url")
            .ends_with("CELEX:32016R0679")
    );
    let request = only(&stub);
    assert_eq!(
        header(&request, "accept"),
        Some("application/sparql-results+json")
    );
    let form = form_params(&request);
    assert!(form["query"].contains("\"32016R0679\"^^xsd:string"));
    assert!(form["query"].contains("LIMIT 200"));
}

#[tokio::test]
async fn eurlex_act_unknown_celex_and_5xx_are_mapped() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "POST",
        "/webapi/rdf/sparql",
        StatusCode::OK,
        json!({"results": {"bindings": []}}),
    );
    let clients = clients_for(Service::Cellar, &base);
    assert_eq!(
        legal::eurlex::act(&clients, &args(json!({"celex": "32099R9999"})))
            .await
            .expect_err("an unknown celex"),
        "[permanent] celex not found"
    );

    let (base, stub, _locations) = local_server().await;
    stub.json(
        "POST",
        "/webapi/rdf/sparql",
        StatusCode::SERVICE_UNAVAILABLE,
        json!({}),
    );
    let clients = clients_for(Service::Cellar, &base);
    let error = legal::eurlex::act(&clients, &args(json!({"celex": "32016R0679"})))
        .await
        .expect_err("a 503");
    assert!(error.starts_with("[retryable] 503"), "{error}");
}

#[tokio::test]
async fn eurlex_text_follows_the_redirect_and_strips_html() {
    let (base, stub, _locations) = local_server().await;
    let manifestation = "/resource/cellar/3e485e15.0018.03/DOC_1";
    stub.redirect(
        "GET",
        "/resource/celex/32016R0679",
        StatusCode::SEE_OTHER,
        &format!("{base}{manifestation}"),
    );
    let xhtml = format!(
        "<html><head><title>L_2016119PL</title></head><body><p>ROZPORZĄDZENIE PARLAMENTU EUROPEJSKIEGO I RADY (UE) 2016/679</p><p>{}</p></body></html>",
        "Przepis. ".repeat(300)
    );
    stub.bytes(
        "GET",
        manifestation,
        StatusCode::OK,
        xhtml.as_bytes(),
        "application/xhtml+xml",
    );
    let clients = clients_for(Service::Cellar, &base);
    let out = legal::eurlex::text(
        &clients,
        &args(json!({"celex": "32016R0679", "max_chars": 2000})),
    )
    .await
    .expect("the followed answer");
    let text = out["text"].as_str().expect("text");
    assert!(text.contains("ROZPORZĄDZENIE PARLAMENTU EUROPEJSKIEGO I RADY (UE) 2016/679"));
    assert!(!text.contains("L_2016119PL"), "the title is dropped");
    assert_eq!(out["truncated"], Value::Bool(true));
    assert_eq!(text.chars().count(), 2000);
    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        header(&requests[0], "accept"),
        Some("application/xhtml+xml")
    );
    assert_eq!(header(&requests[0], "accept-language"), Some("pol"));
    assert_eq!(requests[1].path, manifestation);
}

#[tokio::test]
async fn eurlex_text_multiple_choices_is_permanent() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/resource/celex/32016R0679",
        StatusCode::MULTIPLE_CHOICES,
        "<html>choices</html>",
    );
    let clients = clients_for(Service::Cellar, &base);
    let error = legal::eurlex::text(&clients, &args(json!({"celex": "32016R0679"})))
        .await
        .expect_err("multiple choices");
    assert!(
        error.starts_with("[permanent] no single pol XHTML text"),
        "{error}"
    );
    assert!(error.contains("status 300"), "{error}");
}

#[tokio::test]
async fn eurlex_bad_ids_are_rejected_before_any_request() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Cellar, &base);
    for bad in [
        "32016R0679\" } ; DROP",
        "../32016R0679",
        "32016R0679/../x",
        "32016r0679",
        "A2016R0679",
        "3201",
        "",
        "32016R0679 ",
    ] {
        for tool in ["act", "text"] {
            let result = if tool == "act" {
                legal::eurlex::act(&clients, &args(json!({"celex": bad}))).await
            } else {
                legal::eurlex::text(&clients, &args(json!({"celex": bad}))).await
            };
            let error = result.expect_err("a bad celex");
            assert!(
                error.starts_with("[permanent] invalid celex"),
                "{bad}: {error}"
            );
        }
    }
    for bad in ["pl", "POL", "po/l", "pol;x"] {
        let error =
            legal::eurlex::text(&clients, &args(json!({"celex": "32016R0679", "lang": bad})))
                .await
                .expect_err("a bad lang");
        assert!(error.starts_with("[permanent] invalid lang"), "{error}");
    }
    assert!(stub.requests().is_empty());
}

// ── KRS ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn krs_extract_maps_the_extract_and_left_pads_the_number() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/krs/OdpisAktualny/0000028860",
        StatusCode::OK,
        krs_answer(),
    );
    let clients = clients_for(Service::Krs, &base);
    let out = legal::krs::extract(&clients, &args(json!({"krs": "28860"})))
        .await
        .expect("a KRS extract");
    assert_eq!(
        query_params(&only(&stub)),
        HashMap::from([
            ("rejestr".to_owned(), "P".to_owned()),
            ("format".to_owned(), "json".to_owned()),
        ])
    );
    assert_eq!(out["krs"], "0000028860");
    assert_eq!(out["as_of"], "09.10.2026");
    assert_eq!(out["name"], "ORLEN SPÓŁKA AKCYJNA");
    assert_eq!(out["legal_form"], "SPÓŁKA AKCYJNA");
    assert_eq!(out["nip"], "7740001454");
    assert_eq!(out["regon"], "61018820100000");
    assert_eq!(out["address"], "CHEMIKÓW 7, 09-411 PŁOCK, POLSKA");
    assert_eq!(
        out["capital"],
        json!({"amount": "1451177561,25", "currency": "PLN"})
    );
    assert_eq!(out["representation"]["body"], "ZARZĄD");
    assert_eq!(
        out["representation"]["members"][0],
        json!({"name": "I******* F*****", "function": "PREZES ZARZĄDU"})
    );
    assert_eq!(
        out["business_activity"]
            .as_array()
            .expect("activities")
            .len(),
        2
    );
    assert_eq!(
        out["business_activity"][0],
        json!({
            "code": "19.20.Z",
            "description": "WYTWARZANIE I PRZETWARZANIE PRODUKTÓW RAFINACJI ROPY NAFTOWEJ",
            "predominant": true,
        })
    );
    assert_eq!(
        out["business_activity"][1]["predominant"],
        Value::Bool(false)
    );
}

#[tokio::test]
async fn krs_register_s_and_404_are_mapped() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Krs, &base);
    let error = legal::krs::extract(
        &clients,
        &args(json!({"krs": "0000000001", "register": "S"})),
    )
    .await
    .expect_err("a missing register entry");
    assert_eq!(error, "[permanent] KRS entry not found in this register");
    assert_eq!(query_params(&only(&stub))["rejestr"], "S");
}

#[tokio::test]
async fn krs_rejects_bad_numbers_before_any_request() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Krs, &base);
    for bad in ["12345678901", "../1", "12a", "", "0000028860?x"] {
        let error = legal::krs::extract(&clients, &args(json!({"krs": bad})))
            .await
            .expect_err("a bad krs");
        assert!(
            error.starts_with("[permanent] invalid krs"),
            "{bad}: {error}"
        );
    }
    assert!(stub.requests().is_empty());
}

// ── MF VAT whitelist ──────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn vat_whitelist_maps_and_caches_search_answers() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/search/nip/7740001454",
        StatusCode::OK,
        vat_answer(),
    );
    let clients = clients_for(Service::MfWl, &base);
    let out = legal::vat::whitelist(
        &clients,
        &args(json!({"nip": "774-000-14-54", "date": "2026-10-22"})),
    )
    .await
    .expect("a whitelist answer");
    assert_eq!(
        out,
        json!({
            "nip": "7740001454",
            "date": "2026-10-22",
            "found": true,
            "name": "ORLEN SPÓŁKA AKCYJNA",
            "status_vat": "Czynny",
            "regon": "610188201",
            "krs": "0000028860",
            "registration_date": "1993-07-05",
            "removal_date": null,
            "accounts_count": 3,
            "request_id": "adO3M-9938hnd",
            "cached": false,
        })
    );
    assert_eq!(
        query_params(&only(&stub)),
        HashMap::from([("date".to_owned(), "2026-10-22".to_owned())])
    );
    let again = legal::vat::whitelist(
        &clients,
        &args(json!({"nip": "7740001454", "date": "2026-10-22"})),
    )
    .await
    .expect("the cached answer");
    assert_eq!(again["cached"], Value::Bool(true));
    assert_eq!(again["name"], "ORLEN SPÓŁKA AKCYJNA");
    assert_eq!(stub.requests().len(), 1);
}

#[tokio::test]
async fn vat_whitelist_account_check_answers_assignment() {
    let nrb = "30102010260000140203550589";
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        &format!("/api/check/nip/7740001454/bank-account/{nrb}"),
        StatusCode::OK,
        json!({"result": {"accountAssigned": "TAK", "requestId": "r-1"}}),
    );
    let clients = clients_for(Service::MfWl, &base);
    let out = legal::vat::whitelist(
        &clients,
        &args(json!({
            "nip": "7740001454",
            "date": "2026-10-22",
            "account": "PL30 1020 1026 0000 1402 0355 0589",
        })),
    )
    .await
    .expect("an account answer");
    assert_eq!(
        out,
        json!({
            "nip": "7740001454",
            "date": "2026-10-22",
            "account": nrb,
            "account_assigned": true,
            "request_id": "r-1",
        })
    );
    assert_eq!(stub.requests().len(), 1);
}

#[tokio::test]
async fn vat_whitelist_rejects_bad_input_and_maps_the_mf_message() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::MfWl, &base);
    for (arguments, needle) in [
        (json!({"nip": "7740001455"}), "checksum"),
        (json!({"nip": "../1234567"}), "invalid nip"),
        (json!({"nip": "123"}), "invalid nip"),
        (
            json!({"nip": "7740001454", "date": "22.10.2026"}),
            "invalid date",
        ),
        (
            json!({"nip": "7740001454", "account": "1234/../x"}),
            "invalid account",
        ),
    ] {
        let error = legal::vat::whitelist(&clients, &args(arguments))
            .await
            .expect_err("bad input");
        assert!(
            error.starts_with("[permanent] ") && error.contains(needle),
            "{needle}: {error}"
        );
    }
    assert!(stub.requests().is_empty());

    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/search/nip/7740001454",
        StatusCode::BAD_REQUEST,
        json!({"code": "WL-113", "message": "Pole 'date' ma nieprawidłowy format."}),
    );
    let clients = clients_for(Service::MfWl, &base);
    let error = legal::vat::whitelist(
        &clients,
        &args(json!({"nip": "7740001454", "date": "2026-10-24"})),
    )
    .await
    .expect_err("a 400");
    assert!(
        error.starts_with("[permanent] 400") && error.contains("nieprawidłowy format"),
        "{error}"
    );
}

// ── KIO ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn kio_search_posts_the_site_form_and_maps_hits() {
    let (base, stub, _locations) = local_server().await;
    stub.text("POST", "/Home/GetResults", StatusCode::OK, KIO_RESULTS_HTML);
    let clients = clients_for(Service::Kio, &base);
    let out = legal::kio::search(
        &clients,
        &args(json!({"query": "rażąco niska cena", "document_type": "wyrok"})),
    )
    .await
    .expect("a KIO search answer");
    let request = only(&stub);
    assert_eq!(request.method, "POST");
    let form = form_params(&request);
    assert_eq!(form["Phrase"], "rażąco niska cena");
    assert_eq!(form["Kind"], "KIO");
    assert_eq!(form["Pg"], "1");
    assert_eq!(form["KIO.DecT"], "wyrok");
    assert_eq!(form["Fle"], "1");
    assert_eq!(form["SCnt"], "1");
    assert_eq!(form["CountStats"], "True");
    assert!(!form.contains_key("Sign"));
    assert_eq!(out["total"], 8719);
    assert_eq!(out["items"][0]["id"], 20846);
    assert_eq!(out["items"][0]["signature"], "KIO 3766/24");
    assert_eq!(out["items"][0]["date"], Value::Null);
    assert_eq!(out["items"][0]["body"], "Krajowa Izba Odwoławcza");
    assert_eq!(out["items"][0]["snippet"], ", rażąco niska cena");
    assert_eq!(out["items"][0]["url"], format!("{base}/Home/Details/20846"));
    assert_eq!(out["items"][1]["date"], "2026-03-05");
}

#[tokio::test]
async fn kio_search_by_signature_only_and_bad_input() {
    let (base, stub, _locations) = local_server().await;
    stub.text("POST", "/Home/GetResults", StatusCode::OK, KIO_RESULTS_HTML);
    let clients = clients_for(Service::Kio, &base);
    legal::kio::search(
        &clients,
        &args(json!({"signature": "KIO 2105/22", "page": 2})),
    )
    .await
    .expect("a signature search");
    let form = form_params(&only(&stub));
    assert_eq!(form["Sign"], "KIO 2105/22");
    assert_eq!(form["Pg"], "2");
    assert!(!form.contains_key("Phrase"));

    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Kio, &base);
    for arguments in [
        json!({}),
        json!({"query": "  "}),
        json!({"query": "x".repeat(501)}),
        json!({"signature": "x".repeat(101)}),
    ] {
        let error = legal::kio::search(&clients, &args(arguments))
            .await
            .expect_err("bad input");
        assert!(error.starts_with("[permanent] "), "{error}");
    }
    for id in [0, -1, 1_000_000_000_i64] {
        let error = legal::kio::document(&clients, &args(json!({"id": id})))
            .await
            .expect_err("a bad id");
        assert!(error.starts_with("[permanent] invalid id"), "{error}");
    }
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn kio_document_maps_metadata_text_and_cache() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/Home/Details/18119",
        StatusCode::OK,
        KIO_DETAILS_HTML,
    );
    stub.text(
        "GET",
        "/Home/ContentHtml/18119",
        StatusCode::OK,
        &kio_content_html(),
    );
    let clients = clients_for(Service::Kio, &base);
    let out = legal::kio::document(&clients, &args(json!({"id": 18119})))
        .await
        .expect("a ruling");
    assert_eq!(out["signature"], "KIO 2105/22");
    assert_eq!(
        out["signatures"],
        json!([{"signature": "KIO 2105/22", "outcome": "oddalone"}])
    );
    assert_eq!(out["date"], "2022-08-25");
    assert_eq!(out["body"], "Krajowa Izba Odwoławcza");
    assert_eq!(out["document_type"], "wyrok");
    assert_eq!(out["chairman"], "Magdalena Rams");
    assert_eq!(out["contracting_authority"], "Generalna Dyrekcja Dróg");
    assert_eq!(out["city"], "Warszawa");
    assert_eq!(out["procedure"], "przetarg nieograniczony");
    assert_eq!(out["contract_type"], Value::Null);
    assert_eq!(
        out["key_provisions"],
        json!(["art. 224 ust. 1", "art. 226"])
    );
    assert_eq!(out["topics"], json!(["zasada uczciwej konkurencji"]));
    let text = out["text"].as_str().expect("text");
    assert!(
        text.starts_with("Sygn. akt: KIO 2105/22\nWYROK\nz dnia 25 sierpnia 2022 r."),
        "{text}"
    );
    assert!(text.contains("Oddala odwołanie."));
    assert_eq!(out["url"], format!("{base}/Home/Details/18119"));
    assert_eq!(
        out["pdf_url"],
        format!("{base}/Home/PdfContent/18119?Kind=KIO")
    );
    assert_eq!(out["truncated"], Value::Bool(false));
    assert_eq!(out["cached"], Value::Bool(false));
    assert_eq!(
        query_params(&stub.requests()[1]),
        HashMap::from([("Kind".to_owned(), "KIO".to_owned())])
    );

    let again = legal::kio::document(&clients, &args(json!({"id": 18119, "max_chars": 500})))
        .await
        .expect("the cached ruling");
    assert_eq!(stub.requests().len(), 2);
    assert_eq!(again["cached"], Value::Bool(true));
    assert_eq!(again["truncated"], Value::Bool(true));
    assert_eq!(again["text"].as_str().expect("text").chars().count(), 500);
}

#[tokio::test]
async fn kio_document_404_is_permanent() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Kio, &base);
    let error = legal::kio::document(&clients, &args(json!({"id": 99999999})))
        .await
        .expect_err("a missing ruling");
    assert_eq!(error, "[permanent] ruling not found");
    assert_eq!(only(&stub).path, "/Home/Details/99999999");
}

// ── UOKiK ───────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn uokik_search_builds_the_domino_query_and_maps_rows() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/bp/dec_prez.nsf/WWW-decyzje",
        StatusCode::OK,
        UOKIK_SEARCHVIEW_HTML,
    );
    let clients = clients_for(Service::Uokik, &base);
    let out = legal::uokik::search(
        &clients,
        &args(json!({"participant": "Allegro", "page_size": 5})),
    )
    .await
    .expect("a UOKiK search answer");
    let request = only(&stub);
    let params = query_params(&request);
    assert_eq!(
        params["Query"],
        "([FORM]=Decyzja) AND ([Uczestnicy_postepowania] contains \"Allegro\")"
    );
    assert_eq!(params["SearchOrder"], "3");
    assert_eq!(params["SearchMax"], "0");
    assert_eq!(params["Start"], "1");
    assert_eq!(params["Count"], "5");
    assert_eq!(out["page"], 1);
    assert_eq!(out["items"][0]["unid"], "86734DC793D1A570C125880D0037E958");
    assert_eq!(out["items"][0]["decision_number"], "DKK-69/2022");
    assert_eq!(out["items"][0]["date"], "2022-03-02");
    assert_eq!(out["items"][0]["practice"], "Kontrola koncentracji");
    assert!(
        out["items"][0]["participants"]
            .as_str()
            .expect("participants")
            .starts_with("Allegro.pl sp. z o.o. z siedzibą w Poznaniu")
    );
    assert_eq!(
        out["items"][0]["url"],
        format!(
            "{base}/bp/dec_prez.nsf/1/86734DC793D1A570C125880D0037E958?editDocument&act=Decyzja"
        )
    );
    assert_eq!(out["has_more"], Value::Bool(false));
}

#[tokio::test]
async fn uokik_search_all_criteria_paging_and_injection_guard() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/bp/dec_prez.nsf/WWW-decyzje",
        StatusCode::OK,
        "<html></html>",
    );
    let clients = clients_for(Service::Uokik, &base);
    let out = legal::uokik::search(
        &clients,
        &args(json!({
            "query": "klauzule niedozwolone",
            "decision_number": "RKR-1/2020",
            "signature": "RKR.610.1.2019",
            "page": 3,
            "page_size": 10,
        })),
    )
    .await
    .expect("an empty answer");
    let params = query_params(&only(&stub));
    assert_eq!(
        params["Query"],
        "([FORM]=Decyzja) AND ([decyzja_nr] = \"RKR-1/2020\") AND \
         ([Sygnatura] contains \"RKR.610.1.2019\") AND (klauzule niedozwolone)"
    );
    assert_eq!(params["Start"], "21");
    assert_eq!(params["Count"], "10");
    assert_eq!(out, json!({"page": 3, "items": [], "has_more": false}));

    let (base, stub, _locations) = local_server().await;
    stub.text("GET", "/bp/dec_prez.nsf/WWW-decyzje", StatusCode::OK, "");
    let clients = clients_for(Service::Uokik, &base);
    legal::uokik::search(
        &clients,
        &args(json!({
            "participant": "x\") OR ([FORM]=*",
            "query": "a [Kara]=Tak",
        })),
    )
    .await
    .expect("a sanitised query");
    let query = query_params(&only(&stub))["Query"].clone();
    let tail = query
        .strip_prefix("([FORM]=Decyzja) AND ")
        .expect("the form term");
    // Domino syntax cannot be smuggled in: no brackets outside the field names, and only the
    // two quotes the tool itself adds.
    let without_field = tail.replace("[Uczestnicy_postepowania]", "");
    assert!(!without_field.contains('['), "{query}");
    assert!(!without_field.contains(']'), "{query}");
    assert!(!without_field.contains('='), "{query}");
    assert_eq!(tail.matches('"').count(), 2, "{query}");
    assert!(
        tail.contains("Uczestnicy_postepowania] contains \""),
        "{query}"
    );
    assert!(tail.contains("OR"), "{query}");
    assert!(tail.contains("FORM"), "{query}");
    assert!(tail.ends_with("(a  Kara  Tak)"), "{query}");
}

#[tokio::test]
async fn uokik_search_needs_a_criterion_and_rejects_bad_input() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Uokik, &base);
    let error = legal::uokik::search(&clients, &args(json!({"query": " "})))
        .await
        .expect_err("no criterion");
    assert!(error.starts_with("[permanent] give a query"), "{error}");
    for bad in [
        "",
        "EFC05E0C",
        "../admin",
        "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ",
    ] {
        let error = legal::uokik::document(&clients, &args(json!({"unid": bad})))
            .await
            .expect_err("a bad unid");
        assert!(
            error.starts_with("[permanent] invalid unid"),
            "{bad}: {error}"
        );
    }
    assert!(stub.requests().is_empty());
}

#[test]
fn uokik_search_and_decision_parsers_match_the_reference() {
    let items = parse_search(UOKIK_SEARCHVIEW_HTML);
    assert_eq!(
        items,
        vec![
            json!({
                "unid": "86734DC793D1A570C125880D0037E958",
                "decision_number": "DKK-69/2022",
                "date": "2022-03-02",
                "participants": "Allegro.pl sp. z o.o. z siedzibą w Poznaniu",
                "practice": "Kontrola koncentracji",
            }),
            json!({
                "unid": "EFC05E0C47FEE157C1257F8F0031EF80",
                "decision_number": "DDK-1/2016",
                "date": "2016-02-09",
                "participants": "Grupa Allegro sp. z o.o.",
                "practice": "Ochrona zbiorowych interesów konsumentów",
            }),
        ]
    );
    assert_eq!(
        parse_decision(UOKIK_DECISION_HTML),
        json!({
            "decision_number": "DDK-1/2016",
            "date": "2016-02-09",
            "case_signature": "DDK-61-6/14/MN",
            "participants": "Grupa Allegro spółka z ograniczoną odpowiedzialnością z siedzibą w Poznaniu",
            "practice": "Ochrona zbiorowych interesów konsumentów",
            "penalty": "Nie",
            "sector": "63.12 PORTALE",
            "region": "Wielkopolskie",
            "appealed": "Tak",
            "related_judgments": [{
                "signature": "XVII Ama 51/16",
                "date": "2019-01-25",
                "unid": "CD2E9D4E218F6DD7C12583A1004C8C61",
            }],
            "pdf_paths": [UOKIK_PDF_PATH],
        })
    );
}

#[tokio::test]
async fn uokik_document_fetches_the_attachment_then_reports_the_pdf_gap() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        &format!("/bp/dec_prez.nsf/1/{UOKIK_UNID}"),
        StatusCode::OK,
        UOKIK_DECISION_HTML,
    );
    stub.bytes(
        "GET",
        UOKIK_PDF_PATH,
        StatusCode::OK,
        b"%PDF-1.4\n%test\n",
        "application/pdf",
    );
    let clients = clients_for(Service::Uokik, &base);
    let error = legal::uokik::document(
        &clients,
        &args(json!({"unid": UOKIK_UNID.to_ascii_lowercase()})),
    )
    .await
    .expect_err("the PDF parser is not ported");
    assert!(
        error.starts_with("[permanent] cannot read the PDF text"),
        "{error}"
    );
    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].path, format!("/bp/dec_prez.nsf/1/{UOKIK_UNID}"));
    assert_eq!(
        requests[0].query.as_deref(),
        Some("editDocument&act=Decyzja")
    );
    assert_eq!(requests[1].path, UOKIK_PDF_PATH);
}

#[test]
fn uokik_document_value_keeps_the_reference_shape() {
    let client = public_client("https://uokik.test");
    let meta = parse_decision(UOKIK_DECISION_HTML);
    let Value::Object(mut meta) = meta else {
        panic!("the parsed decision is an object");
    };
    let pdf_paths: Vec<String> = meta
        .shift_remove("pdf_paths")
        .and_then(|paths| paths.as_array().cloned())
        .unwrap_or_default()
        .iter()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect();
    let doc = legal::uokik::document_value(
        &meta,
        UOKIK_UNID,
        &["DECYZJA Nr DDK 1/2016\n\nWarszawa, dn. 9 lutego 2016 r.".to_owned()],
        &pdf_paths,
        &client,
    );
    assert_eq!(doc["unid"], UOKIK_UNID);
    assert_eq!(
        doc["body"],
        "Prezes Urzędu Ochrony Konkurencji i Konsumentów"
    );
    assert_eq!(doc["decision_number"], "DDK-1/2016");
    assert_eq!(doc["date"], "2016-02-09");
    assert_eq!(doc["case_signature"], "DDK-61-6/14/MN");
    assert_eq!(doc["penalty"], "Nie");
    assert_eq!(doc["appealed"], "Tak");
    assert_eq!(
        doc["related_judgments"][0],
        json!({"signature": "XVII Ama 51/16", "date": "2019-01-25", "unid": "CD2E9D4E218F6DD7C12583A1004C8C61"})
    );
    assert_eq!(
        doc["text"],
        "DECYZJA Nr DDK 1/2016\n\nWarszawa, dn. 9 lutego 2016 r."
    );
    assert_eq!(
        doc["url"],
        format!("https://uokik.test/bp/dec_prez.nsf/1/{UOKIK_UNID}?editDocument&act=Decyzja")
    );
    assert_eq!(
        doc["pdf_urls"],
        json!([format!("https://uokik.test{UOKIK_PDF_PATH}")])
    );
}

#[tokio::test]
async fn uokik_document_attachment_that_is_not_a_pdf_and_404_are_permanent() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        &format!("/bp/dec_prez.nsf/1/{UOKIK_UNID}"),
        StatusCode::OK,
        UOKIK_DECISION_HTML,
    );
    stub.text("GET", UOKIK_PDF_PATH, StatusCode::OK, "<html>login</html>");
    let clients = clients_for(Service::Uokik, &base);
    let error = legal::uokik::document(&clients, &args(json!({"unid": UOKIK_UNID})))
        .await
        .expect_err("a non-PDF attachment");
    assert_eq!(error, "[permanent] the document file is not a PDF");

    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Uokik, &base);
    let missing = "0".repeat(32);
    let error = legal::uokik::document(&clients, &args(json!({"unid": missing})))
        .await
        .expect_err("a missing decision");
    assert_eq!(error, "[permanent] decision not found");
    assert_eq!(
        only(&stub).path,
        format!("/bp/dec_prez.nsf/1/{}", "0".repeat(32))
    );
}

// ── DUW ──────────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn duw_search_posts_json_and_pages_from_one_cached_answer() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "POST",
        "/api/SearchLegalAct",
        StatusCode::OK,
        duw_search_answer(),
    );
    let clients = clients_for(Service::Duw, &base);
    let out = legal::duw::search(
        &clients,
        &args(json!({"query": "targow", "year": 2026, "page_size": 2})),
    )
    .await
    .expect("a DUW search answer");
    let body = json_body(&only(&stub));
    assert_eq!(
        body,
        json!({
            "Title": "targow",
            "PageNumber": 1,
            "SelectedKeywords": [],
            "SelectedLegalActType": [],
            "PublisherName": "",
            "Year": 2026,
        })
    );
    assert_eq!(out["total"], 1243);
    assert_eq!(out["returned_by_source"], 3);
    assert_eq!(out["page"], 1);
    assert_eq!(out["has_more"], Value::Bool(true));
    assert_eq!(
        out["items"][0],
        json!({
            "year": 2026,
            "position": 4019,
            "title": "Uchwała nr XXX/303/2026 Rady Miejskiej w Kątach Wrocławskich",
            "act_type": "Uchwała",
            "number": "XXX/303/2026",
            "publisher": "Rady Miejskiej w Kątach Wrocławskich",
            "act_date": "2026-08-27",
            "publication_date": "2026-09-11",
            "url": format!("{base}/legalact/2026/4019/"),
        })
    );

    let second = legal::duw::search(
        &clients,
        &args(json!({"query": "Targow", "year": 2026, "page": 2, "page_size": 2})),
    )
    .await
    .expect("the second page");
    assert_eq!(stub.requests().len(), 1, "one cached source answer");
    assert_eq!(second["items"][0]["position"], 3300);
    assert_eq!(second["has_more"], Value::Bool(false));
}

#[tokio::test]
async fn duw_search_rejects_bad_input_before_any_request() {
    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Duw, &base);
    for arguments in [
        json!({"query": ""}),
        json!({"query": "x".repeat(201)}),
        json!({"query": "a", "year": 1990}),
    ] {
        let error = legal::duw::search(&clients, &args(arguments))
            .await
            .expect_err("bad input");
        assert!(error.starts_with("[permanent] "), "{error}");
    }
    assert!(stub.requests().is_empty());
}

#[tokio::test]
async fn duw_document_maps_metadata_and_reports_the_pdf_gap() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/legalact",
        StatusCode::OK,
        duw_legalact_answer(),
    );
    stub.bytes(
        "GET",
        "/GetActPdf.ashx",
        StatusCode::OK,
        b"%PDF-1.4\n%test\n",
        "application/pdf",
    );
    let clients = clients_for(Service::Duw, &base);
    let error = legal::duw::document(&clients, &args(json!({"year": 2026, "position": 4019})))
        .await
        .expect_err("the PDF parser is not ported");
    assert!(
        error.starts_with("[permanent] cannot read the PDF text"),
        "{error}"
    );
    let requests = stub.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(
        query_params(&requests[0]),
        HashMap::from([
            ("year".to_owned(), "2026".to_owned()),
            ("journal".to_owned(), "0".to_owned()),
            ("position".to_owned(), "4019".to_owned()),
        ])
    );
    assert_eq!(
        query_params(&requests[1]),
        HashMap::from([
            ("year".to_owned(), "2026".to_owned()),
            ("book".to_owned(), "0".to_owned()),
            ("position".to_owned(), "4019".to_owned()),
        ])
    );
}

#[test]
fn duw_document_value_keeps_the_reference_shape() {
    let client = public_client("https://duw.test");
    let doc = duw_document_value(
        &duw_legalact_answer(),
        2026,
        4019,
        "UCHWAŁA NR XXX/303/2026\nz bonifikatą w wysokości 70%".to_owned(),
        &client,
    );
    assert_eq!(doc["position_number"], "2026.4019");
    assert_eq!(
        doc["journal"],
        "Dziennik Urzędowy Województwa Dolnośląskiego"
    );
    assert_eq!(doc["act_type"], "Uchwała");
    assert_eq!(doc["number"], "XXX/303/2026");
    assert_eq!(doc["publisher"], "Rada Miejska w Kątach Wrocławskich");
    assert_eq!(doc["act_date"], "2026-08-27");
    assert_eq!(doc["publication_date"], "2026-09-11");
    assert_eq!(
        doc["keywords"],
        json!(["zasady gospodarki nieruchomościami"])
    );
    assert_eq!(doc["invalid"], Value::Bool(false));
    assert_eq!(doc["partially_invalid"], Value::Bool(false));
    assert_eq!(doc["status_note"], Value::Null);
    assert_eq!(
        doc["text"],
        "UCHWAŁA NR XXX/303/2026\nz bonifikatą w wysokości 70%"
    );
    assert_eq!(doc["url"], "https://duw.test/legalact/2026/4019/");
    assert_eq!(
        doc["pdf_url"],
        "https://duw.test/GetActPdf.ashx?year=2026&book=0&position=4019"
    );
}

#[tokio::test]
async fn duw_document_404_and_bad_input_are_mapped() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "GET",
        "/api/legalact",
        StatusCode::NOT_FOUND,
        "Nie znaleziono pozycji",
    );
    let clients = clients_for(Service::Duw, &base);
    let error = legal::duw::document(&clients, &args(json!({"year": 2026, "position": 999999})))
        .await
        .expect_err("a missing position");
    assert_eq!(error, "[permanent] journal position not found");

    let (base, stub, _locations) = local_server().await;
    let clients = clients_for(Service::Duw, &base);
    for arguments in [
        json!({"year": 2026, "position": 0}),
        json!({"year": 1900, "position": 1}),
    ] {
        let error = legal::duw::document(&clients, &args(arguments))
            .await
            .expect_err("bad input");
        assert!(error.starts_with("[permanent] invalid"), "{error}");
    }
    assert!(stub.requests().is_empty());
}

// ── the client: errors, caps, redirects and pacing ──────────────────────────────────────

#[tokio::test]
async fn timeout_and_transport_errors_are_retryable() {
    let (base, stub, _locations) = local_server().await;
    stub.slow_json(
        "GET",
        "/api/krs/OdpisAktualny/0000028860",
        StatusCode::OK,
        json!({}),
        Duration::from_millis(300),
    );
    let clients = Clients::default().with(
        Service::Krs,
        PublicClient::new(&base, Duration::from_millis(50), Duration::ZERO, None),
    );
    let error = legal::krs::extract(&clients, &args(json!({"krs": "28860"})))
        .await
        .expect_err("a timeout");
    assert!(error.starts_with("[retryable] timeout after"), "{error}");

    // A closed loopback port answers the reference's ConnectError branch.
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind a port");
    let address = listener.local_addr().expect("an address");
    drop(listener);
    let client = PublicClient::new(
        format!("http://{address}"),
        Duration::from_secs(2),
        Duration::ZERO,
        None,
    );
    let error = client
        .get_json("/x", &[], None)
        .await
        .expect_err("a connect error");
    assert!(error.starts_with("[retryable] cannot reach"), "{error}");
    assert!(error.contains("ConnectError"), "{error}");
}

#[tokio::test]
async fn a_429_is_retryable_and_a_4xx_carries_the_upstream_message() {
    let (base, stub, _locations) = local_server().await;
    stub.json(
        "GET",
        "/api/search/nip/7770001453",
        StatusCode::TOO_MANY_REQUESTS,
        json!({"message": "limit"}),
    );
    let clients = clients_for(Service::MfWl, &base);
    let error = legal::vat::whitelist(
        &clients,
        &args(json!({"nip": "7770001453", "date": "2026-10-23"})),
    )
    .await
    .expect_err("a 429");
    assert_eq!(
        error,
        "[retryable] 429 from GET /api/search/nip/7770001453: limit"
    );
}

#[tokio::test]
async fn a_body_cap_refuses_an_oversize_answer_before_reading_it() {
    let (base, stub, _locations) = local_server().await;
    stub.text(
        "POST",
        "/Home/GetResults",
        StatusCode::OK,
        &"x".repeat(5000),
    );
    let clients = Clients::default().with(
        Service::Kio,
        PublicClient::new(&base, Duration::from_secs(20), Duration::ZERO, Some(1000)),
    );
    let error = legal::kio::search(&clients, &args(json!({"query": "wadium"})))
        .await
        .expect_err("an oversize answer");
    assert!(
        error.starts_with(
            "[permanent] answer to POST /Home/GetResults too large (5000 bytes, max 1000)"
        ),
        "{error}"
    );
}

#[tokio::test]
async fn a_same_host_redirect_is_followed_and_a_cross_host_one_is_refused() {
    let (base, stub, _locations) = local_server().await;
    stub.redirect("GET", "/start", StatusCode::SEE_OTHER, "/end");
    stub.text("GET", "/end", StatusCode::OK, "landed");
    let client = public_client(&base);
    let reply = client
        .get_text_follow("/start", Vec::new(), None)
        .await
        .expect("a followed redirect");
    assert_eq!(reply.text(), "landed");
    assert_eq!(stub.requests().len(), 2);

    let (other_base, _other, _locations) = local_server().await;
    let (base, stub, _locations) = local_server().await;
    stub.redirect(
        "GET",
        "/start",
        StatusCode::FOUND,
        &format!("{}/end", other_base.replacen("127.0.0.1", "localhost", 1)),
    );
    let client = PublicClient::new(
        &base,
        Duration::from_secs(20),
        Duration::from_millis(1),
        None,
    );
    let error = client
        .get_text_follow("/start", Vec::new(), None)
        .await
        .expect_err("a cross-host redirect");
    assert!(
        error.starts_with("[permanent] GET /start redirects to another host"),
        "{error}"
    );
}

#[tokio::test]
async fn scraped_clients_are_paced_per_host() {
    let (base, stub, _locations) = local_server().await;
    stub.text("GET", "/x", StatusCode::OK, "one");
    stub.text("GET", "/y", StatusCode::OK, "two");
    let client = PublicClient::new(
        &base,
        Duration::from_secs(20),
        Duration::from_millis(60),
        None,
    );
    let started = Instant::now();
    client.get_text("/x", None).await.expect("the first call");
    client.get_text("/y", None).await.expect("the second call");
    assert!(
        started.elapsed() >= Duration::from_millis(55),
        "the second call waited for the host's slot: {:?}",
        started.elapsed()
    );
}

#[test]
fn settings_take_the_reference_defaults_and_spellings() {
    let defaults = legal::Settings::from_lookup(|_| None);
    assert_eq!(defaults.timeout, Duration::from_secs_f64(20.0));
    assert_eq!(defaults.scrape_interval, Duration::from_secs_f64(1.0));
    let configured = legal::Settings::from_lookup(|key| match key {
        "LEGAL_TIMEOUT_S" => Some("7".to_owned()),
        "LEGAL_SCRAPE_MIN_INTERVAL_S" => Some("-2.5".to_owned()),
        _ => None,
    });
    assert_eq!(configured.timeout, Duration::from_secs(7));
    assert_eq!(configured.scrape_interval, Duration::ZERO);
    let invalid = legal::Settings::from_lookup(|key| match key {
        "LEGAL_TIMEOUT_S" => Some("soon".to_owned()),
        "LEGAL_SCRAPE_MIN_INTERVAL_S" => Some("later".to_owned()),
        _ => None,
    });
    assert_eq!(invalid, defaults);
}

// ── HTML and date helpers ────────────────────────────────────────────────────────────────

#[test]
fn html_to_text_drops_script_style_and_head_and_keeps_blocks() {
    let html = "<html><head><title>T</title><style>x{}</style></head><body><p>a&nbsp;b</p>\
                <script>evil()</script><table><tr><td>c</td><td>d</td></tr></table></body></html>";
    assert_eq!(legal::html_to_text(html), "a b\nc d");
}

#[test]
fn html_to_text_normalises_superscripts_and_entities() {
    let html = "<p>Art. 449<sup>1</sup>. &sect; &quot;x&quot; &#261; &#x142;</p>";
    assert_eq!(legal::html_to_text(html), "Art. 449^1. § \"x\" ą ł");
    assert_eq!(legal::html_to_text("<p>a<br/>b</p>"), "a\nb");
    assert_eq!(
        legal::html_to_text("<ul><li>one</li><li>two</li></ul>"),
        "one\ntwo"
    );
}

#[test]
fn element_text_selects_the_first_match_and_none_when_absent() {
    let html = r#"<div id="a">x</div><div id="b">y</div>"#;
    assert_eq!(
        legal::element_text(html, |_tag, attrs| attrs
            .get("id")
            .is_some_and(|id| id == "b")),
        Some("y".to_owned())
    );
    assert_eq!(
        legal::element_text(html, |_tag, attrs| attrs
            .get("id")
            .is_some_and(|id| id == "missing")),
        None
    );
}

#[test]
fn strip_tags_collapses_inline_markup() {
    assert_eq!(
        legal::strip_tags(" przedstawicielkę <em>D. T.</em>\n  o podwyższenie <em>alimentów</em>"),
        "przedstawicielkę D. T. o podwyższenie alimentów"
    );
}

#[test]
fn date_helpers_match_the_reference() {
    assert_eq!(
        legal::polish_date("WYROK z dnia 3 września 2021 r."),
        Some("2021-09-03".to_owned())
    );
    assert_eq!(legal::polish_date("z dnia 31 lutego 2021"), None);
    assert_eq!(legal::polish_date("bez daty"), None);
    let head = "WYROK\nWarszawa, dnia 4 listopada 2024 r.\nustawy z dnia 11 września 2019 r.";
    assert_eq!(legal::polish_date(head), Some("2024-11-04".to_owned()));
    assert_eq!(
        legal::dotted_date(Some("09.02.2016")),
        Some("2016-02-09".to_owned())
    );
    assert_eq!(
        legal::dotted_date(Some("05-03-2026")),
        Some("2026-03-05".to_owned())
    );
    assert_eq!(legal::dotted_date(Some("-")), None);
}

#[test]
fn finish_puts_text_last_so_a_cut_result_keeps_its_url() {
    let out = legal::finish(
        json!({"text": "x".repeat(10), "url": "https://example.test/1", "signature": "KIO 1/26"}),
        5,
        false,
    );
    let keys: Vec<&str> = out
        .as_object()
        .expect("an object")
        .keys()
        .map(String::as_str)
        .collect();
    assert_eq!(keys.last().copied(), Some("text"));
    assert_eq!(out["truncated"], Value::Bool(true));
    assert_eq!(out["text"], "xxxxx");
}

#[test]
fn the_kio_parsers_match_the_reference() {
    let (total, items) = parse_results(KIO_RESULTS_HTML);
    assert_eq!(total, json!(8719));
    assert_eq!(
        items,
        vec![
            json!({
                "id": 20846,
                "signature": "KIO 3766/24",
                "document_type": "wyrok",
                "date": null,
                "body": "Krajowa Izba Odwoławcza",
                "snippet": ", rażąco niska cena",
            }),
            json!({
                "id": 18119,
                "signature": "KIO 2105/22",
                "document_type": "wyrok",
                "date": "2026-03-05",
                "body": "Sąd",
                "snippet": "druga",
            }),
        ]
    );
    assert_eq!(
        parse_details(KIO_DETAILS_HTML),
        json!({
            "title_signature": "KIO 2105/22",
            "body": "Krajowa Izba Odwoławcza",
            "document_type": "wyrok",
            "date": null,
            "chairman": "Magdalena Rams",
            "contracting_authority": "Generalna Dyrekcja Dróg",
            "city": "Warszawa",
            "procedure": "przetarg nieograniczony",
            "contract_type": null,
            "signatures": [{"signature": "KIO 2105/22", "outcome": "oddalone"}],
            "key_provisions": ["art. 224 ust. 1", "art. 226"],
            "topics": ["zasada uczciwej konkurencji"],
        })
    );
}
