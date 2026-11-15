//! fr's inbound channel: `POST /api/channels/fr/events`, authenticated by signature only.
//!
//! Ported from the reference `src/routers/fr_channel.py`. fr's outbound `mcp` adapter posts every
//! event to one `address` (a linked person), and an approval fans out to every linked member of
//! the workspace — so one approval arrives once per address. It is routed to runs by what it
//! names, never by the address:
//!
//! - `correlation_id` (a run id) when fr has one — n8n questions carry the n8n start's run id;
//! - else `project_id` → the fr run whose `external_ref.project_id` it is;
//! - else the approval id → the fr run whose start parked that approval (`external_ref.id`).
//!
//! `message` events are chat replies, correlated by the run id this server sent: the parked start
//! (`approval-request`) and its outcome (`action-result` / `action-error`). The outcome is recorded
//! on `external_ref` (it only grows); the driver reads it on its next poll. fr also echoes every
//! command WE dispatch back as a `message` whose `correlation_id` is `"<run>:<poll|input>"`, never
//! a run id: those are dropped before any database work — live this was >12k events in 72 h.
//!
//! Approvals the run was asked about, and their closure, also become activity rows — the feed the
//! platform shows under `tasks/get` `_meta["ai.nonagentic/fr"]`.
//!
//! Three rules this module keeps:
//!
//! - **The signature is checked first**, before the envelope is parsed, sharing
//!   [`crate::external::signing`] with the outbound driver rather than a second implementation:
//!   `sha256=<hex>` over `<timestamp>.<raw body>`, a 300 s skew window and a constant-time
//!   compare. The route carries no bearer authentication and is not under the `/mcp` middleware.
//! - **Never a secret, a signature or a body in a log line.** Lines carry event types, approval
//!   ids (truncated), counts and run ids only.
//! - **A feed failure never fails the event.** The approval path fans out to every linked run, so
//!   a 500 there would abort the remaining runs' inputs and fr (which does not retry) would lose
//!   them.

use axum::Extension;
use axum::Json;
use axum::extract::{Request, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use chrono::{DateTime, NaiveDate, NaiveDateTime, SecondsFormat, Utc};
use serde_json::{Map, Value, json};
use sqlx::postgres::PgRow;
use sqlx::{PgPool, Row};

use crate::AppState;
use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::execution::RunStatus;
use crate::external::signing;
use crate::routes::health::AnyJson;
use crate::storage::run_activity::{self, TEXT_LIMIT};

/// The largest body this route reads; a bigger one is refused before it is parsed.
pub const MAX_BODY_BYTES: usize = 65_536;

/// The event types fr posts; anything else is acknowledged and dropped.
pub const EVENT_TYPES: [&str; 3] = ["approval.requested", "approval.closed", "message"];

/// The `message` event: a chat reply for one run.
const MESSAGE: &str = "message";

/// The action a parked start carries (`meta.actionName`).
const START_ACTION: &str = "projects.create";

/// `approval.closed` final statuses that end a parked start without a project.
const START_ENDINGS: [&str; 3] = ["rejected", "expired", "voided"];

/// The feed line for an approval that named no description.
const APPROVAL_TEXT: &str = "an approval was requested";

/// The `status_message` cap (the reference's `external/fr.py` `PHASE_LIMIT`; the column check
/// in the baseline migration is the same 512).
const PHASE_LIMIT: usize = 512;

/// The fr channel's HMAC key, as the application carries it (`MCP_FR_CHANNEL_SECRET`).
///
/// The reference reads `settings.fr_channel_secret` off `app.state`. This crate's [`AppState`] is
/// built by six existing struct literals, so the key travels as a request extension inserted by
/// `app_with_channel_secret` instead — one value, from the same environment variable the external
/// driver reads, and never rendered by a `Debug` impl.
#[derive(Clone)]
pub struct ChannelSecret(pub Option<String>);

/// [`ChannelSecret`] from the environment; `None` when unset, empty counting as unset exactly as
/// [`crate::config::ExternalDriverSettings::from_lookup`] treats it (the value itself is not
/// trimmed — the key is used byte for byte).
pub fn secret_from_env() -> Option<String> {
    std::env::var("MCP_FR_CHANNEL_SECRET")
        .ok()
        .filter(|value| !value.trim().is_empty())
}

/// fr's inbound channel event.
///
/// Signature first (`401 invalid_signature`), then the envelope (`204` for anything this route
/// does not act on), then its effect. The reference's `JSONResponse` refusals carry no
/// `Cache-Control` of their own, so neither do these.
#[utoipa::path(
    post,
    path = "/api/channels/fr/events",
    tag = "channel",
    responses((status = 200, description = "Successful Response", body = AnyJson))
)]
pub async fn events(
    State(state): State<AppState>,
    Extension(secret): Extension<ChannelSecret>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    // The reference's `_read_capped`: a declared length over the cap is refused without reading,
    // and the stream itself is bounded below so a body that declares nothing is bounded too.
    if declared_length(&headers).is_some_and(|declared| declared > MAX_BODY_BYTES as u64) {
        return refusal(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large");
    }
    let body = match axum::body::to_bytes(request.into_body(), MAX_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => return refusal(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large"),
    };
    let Some(secret) = secret.0.as_deref() else {
        return refusal(StatusCode::SERVICE_UNAVAILABLE, "channel_unconfigured");
    };
    if !signing::verify(
        &body,
        &signed_headers(&headers),
        secret,
        Utc::now().timestamp(),
    ) {
        return refusal(StatusCode::UNAUTHORIZED, "invalid_signature");
    }

    let Ok(event) = serde_json::from_slice::<Value>(&body) else {
        // The reference's `json.loads` catches `ValueError`, which also covers invalid UTF-8.
        return StatusCode::NO_CONTENT.into_response();
    };
    let kind = event.get("type").and_then(|value| value.as_str());
    let Some(kind) = kind.filter(|kind| EVENT_TYPES.contains(kind)) else {
        tracing::info!(
            kind = kind.unwrap_or("?"),
            "fr channel event ignored: unknown type"
        );
        return StatusCode::NO_CONTENT.into_response();
    };

    let outcome = if kind == MESSAGE {
        message(&state.pool, &event).await
    } else {
        approval(&state.pool, kind, &event).await
    };
    match outcome {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => {
            // A database failure is not the caller's mistake, and the reference's escaping
            // exception is a 500. Ids and the event type only: never the body.
            tracing::error!(kind, error = %error, "fr channel event failed");
            refusal(StatusCode::INTERNAL_SERVER_ERROR, "internal")
        }
    }
}

// ── refusals and envelope reads ──────────────────────────────────────────────────────────────

/// The reference's `JSONResponse({"error": <code>}, status_code=...)`.
fn refusal(status: StatusCode, code: &'static str) -> Response {
    (status, Json(json!({ "error": code }))).into_response()
}

/// `Content-Length` when it is ASCII digits and fits: the reference's `declared.isdigit()`.
fn declared_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(axum::http::header::CONTENT_LENGTH)
        .and_then(|value| value.to_str().ok())
        .filter(|value| !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|value| value.parse::<u64>().ok())
}

/// The request's headers as the signing helper takes them: lowercased names, and a value that is
/// not ASCII/UTF-8 simply absent (a mismatched signature, which is what it would be).
fn signed_headers(headers: &HeaderMap) -> std::collections::BTreeMap<String, String> {
    headers
        .iter()
        .filter_map(|(name, value)| {
            value
                .to_str()
                .ok()
                .map(|value| (name.as_str().to_lowercase(), value.to_owned()))
        })
        .collect()
}

/// The reference's `_text`: a non-empty string, and nothing else.
fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(|value| value.as_str())
        .filter(|value| !value.is_empty())
}

/// `value[key]` when `value` is an object (the reference's `_mapping(...).get(key)`).
fn member<'a>(value: Option<&'a Value>, key: &str) -> Option<&'a Value> {
    value
        .and_then(Value::as_object)
        .and_then(|object| object.get(key))
}

/// Python truthiness, for the reference's `not (... or {}).get("project_id")`.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(object) => !object.is_empty(),
    }
}

/// The reference's `_uuid`: any string Python's `uuid.UUID` accepts, as its canonical text.
fn event_uuid(value: Option<&Value>) -> Option<String> {
    uuid::Uuid::parse_str(text(value)?)
        .ok()
        .map(|parsed| parsed.to_string())
}

/// The reference's `_expires_at`: the event's `expires_at` as an aware UTC instant, or `None`
/// when absent, empty or unparsable (which is the reference's "no expiry" too).
fn expires_at(value: Option<&Value>) -> Option<DateTime<Utc>> {
    parse_instant(text(value)?)
}

/// Python's `datetime.fromisoformat`: `Z`/`±HH:MM` offsets, compact `±HHMM`/`±HH` ones, a bare
/// (naive, assumed UTC) timestamp, and a date alone.
fn parse_instant(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(parsed) = DateTime::parse_from_rfc3339(value) {
        return Some(parsed.with_timezone(&Utc));
    }
    for format in [
        "%Y-%m-%dT%H:%M:%S%.f",
        "%Y-%m-%dT%H:%M",
        "%Y-%m-%d %H:%M:%S%.f",
    ] {
        if let Ok(parsed) = NaiveDateTime::parse_from_str(value, format) {
            return Some(parsed.and_utc());
        }
    }
    // `fromisoformat` also takes a space separator and a compact offset; the licence-expiry
    // parser already covers exactly those shapes (and requires a timezone, so a naive value
    // cannot be read here).
    if let Some(seconds) = crate::auth::time::parse_iso8601_epoch_seconds(value) {
        return DateTime::from_timestamp(seconds, 0);
    }
    NaiveDate::parse_from_str(value, "%Y-%m-%d")
        .ok()
        .and_then(|date| date.and_hms_opt(0, 0, 0))
        .map(|naive| naive.and_utc())
}

/// The reference's `_expired`.
fn expired(value: Option<&Value>, now: DateTime<Utc>) -> bool {
    expires_at(value).is_some_and(|at| at <= now)
}

/// An approval id or a message kind, truncated for a log line.
fn head(value: &str) -> String {
    value.chars().take(64).collect()
}

/// The reference's `TERMINAL_STATUSES`, taken from the status vocabulary so the two cannot drift.
fn terminal_statuses() -> Vec<String> {
    RunStatus::ALL
        .iter()
        .filter(|status| status.is_terminal())
        .map(|status| status.as_str().to_owned())
        .collect()
}

// ── approvals ────────────────────────────────────────────────────────────────────────────────

/// One live run an event is about.
#[derive(Debug, Clone)]
struct TargetRun {
    run_id: String,
    tenant_id: String,
    external_ref: Option<Value>,
}

impl TargetRun {
    /// The reference's `run["external_ref"] or {}` with its `id`.
    fn reference_id(&self) -> Option<&str> {
        member(self.external_ref.as_ref(), "id").and_then(|value| value.as_str())
    }

    /// The reference's `not (run["external_ref"] or {}).get("project_id")`.
    fn has_project(&self) -> bool {
        member(self.external_ref.as_ref(), "project_id").is_some_and(truthy)
    }
}

/// An `approval.requested` / `approval.closed` event.
async fn approval(pool: &PgPool, kind: &str, event: &Value) -> Result<(), sqlx::Error> {
    let Some(approval_id) = text(event.get("approval_id")) else {
        tracing::info!(kind, "fr channel event ignored: no approval id");
        return Ok(());
    };
    if kind == "approval.requested" && expired(event.get("expires_at"), Utc::now()) {
        // fr's approval window already closed: opening an input would ask an unanswerable
        // question (fr would refuse the answer) and the feed would claim one is waiting.
        tracing::info!(
            kind,
            approval = %head(approval_id),
            "fr channel event ignored: approval already expired"
        );
        return Ok(());
    }

    let runs = runs(pool, event, approval_id).await?;
    // Ids and counts only (never text): enough to tell "not sent" from "sent but unmatched".
    tracing::info!(
        kind,
        approval = %head(approval_id),
        final_status = event
            .get("final_status")
            .and_then(|value| value.as_str())
            .unwrap_or("-"),
        runs = runs.len(),
        "fr channel event"
    );

    if kind == "approval.requested" {
        let prompt = elicitation_request(
            event
                .get("description")
                .and_then(|value| value.as_str())
                .unwrap_or(""),
            event.get("change_summary"),
        );
        let project = text(event.get("project_id"));
        let description: String = text(event.get("description"))
            .unwrap_or(APPROVAL_TEXT)
            .chars()
            .take(TEXT_LIMIT)
            .collect();
        let expires = expires_at(event.get("expires_at"));
        for run in &runs {
            open_input(
                pool,
                &run.tenant_id,
                &run.run_id,
                approval_id,
                &prompt,
                expires,
            )
            .await?;
            // fr names the project on an approval raised inside it: a run started before that
            // (its start approval carried no project) adopts the id here, so its poll can read
            // the project instead of waiting forever for the start outcome.
            if let Some(project) = project {
                if !run.has_project() {
                    record(pool, run, json!({ "project_id": project })).await?;
                }
            }
            activity(
                pool,
                run,
                "approval_requested",
                &description,
                Some(approval_id),
            )
            .await;
        }
        return Ok(());
    }

    close_everywhere(pool, approval_id).await?;
    let final_status = text(event.get("final_status"));
    let closed_text: String = final_status
        .map_or_else(
            || "approval closed".to_owned(),
            |final_status| format!("approval closed: {final_status}"),
        )
        .chars()
        .take(TEXT_LIMIT)
        .collect();
    for run in &runs {
        // A tombstone, so a late approval.requested for this run is ignored.
        close_input(pool, &run.tenant_id, &run.run_id, approval_id).await?;
        if let Some(final_status) = final_status {
            if START_ENDINGS.contains(&final_status)
                && run.reference_id() == Some(approval_id)
                && !run.has_project()
            {
                record(pool, run, json!({ "start_outcome": final_status })).await?;
            }
        }
        activity(
            pool,
            run,
            "approval_closed",
            &closed_text,
            Some(approval_id),
        )
        .await;
    }
    Ok(())
}

/// The reference's `_runs`: the live runs an approval event is about.
async fn runs(pool: &PgPool, event: &Value, approval: &str) -> Result<Vec<TargetRun>, sqlx::Error> {
    let rows = if let Some(run_id) = event_uuid(event.get("correlation_id")) {
        sqlx::query(
            "SELECT run_id::text AS run_id, tenant_id::text AS tenant_id, external_ref \
             FROM public.mcp_runs \
             WHERE run_id = $1::uuid AND status <> ALL($2::text[]) \
             AND runtime <> 'kata_python'",
        )
        .bind(run_id)
        .bind(terminal_statuses())
        .fetch_all(pool)
        .await?
    } else if let Some(project) = text(event.get("project_id")) {
        sqlx::query(
            "SELECT run_id::text AS run_id, tenant_id::text AS tenant_id, external_ref \
             FROM public.mcp_runs \
             WHERE runtime = 'fr_project' AND external_ref->>'project_id' = $1 \
             AND status <> ALL($2::text[]) AND runtime <> 'kata_python'",
        )
        .bind(project)
        .bind(terminal_statuses())
        .fetch_all(pool)
        .await?
    } else {
        sqlx::query(
            "SELECT run_id::text AS run_id, tenant_id::text AS tenant_id, external_ref \
             FROM public.mcp_runs \
             WHERE runtime = 'fr_project' AND external_ref->>'id' = $1 \
             AND status <> ALL($2::text[]) AND runtime <> 'kata_python'",
        )
        .bind(approval)
        .bind(terminal_statuses())
        .fetch_all(pool)
        .await?
    };
    rows.iter().map(target_run).collect()
}

fn target_run(row: &PgRow) -> Result<TargetRun, sqlx::Error> {
    Ok(TargetRun {
        run_id: row.try_get("run_id")?,
        tenant_id: row.try_get("tenant_id")?,
        external_ref: row.try_get("external_ref")?,
    })
}

/// The reference's `_record`: add what fr reported about the start to `external_ref`; the first
/// report wins (the clause refuses a second `project_id` or `start_outcome`).
async fn record(pool: &PgPool, run: &TargetRun, facts: Value) -> Result<(), sqlx::Error> {
    let mut merged = Map::new();
    merged.insert("kind".to_owned(), json!("fr"));
    if let Value::Object(facts) = facts {
        merged.extend(facts);
    }
    sqlx::query(
        "UPDATE public.mcp_runs SET external_ref = COALESCE(external_ref, '{}'::jsonb) || $1::jsonb \
         WHERE tenant_id = $2::uuid AND run_id = $3::uuid AND runtime = 'fr_project' \
         AND status <> ALL($4::text[]) \
         AND NOT (COALESCE(external_ref, '{}'::jsonb) ?| ARRAY['project_id','start_outcome'])",
    )
    .bind(Value::Object(merged))
    .bind(&run.tenant_id)
    .bind(&run.run_id)
    .bind(terminal_statuses())
    .execute(pool)
    .await?;
    Ok(())
}

/// One feed row for `tasks/get`; a feed failure never fails the event.
async fn activity(
    pool: &PgPool,
    run: &TargetRun,
    kind: &str,
    text: &str,
    source_ref: Option<&str>,
) {
    let (Ok(tenant), Ok(run_id)) = (
        AuthorityId::new(run.tenant_id.as_str()),
        Uuid7::new(run.run_id.as_str()),
    ) else {
        tracing::warn!(
            run = %run.run_id,
            "activity record skipped: stored identity is outside the domain"
        );
        return;
    };
    if run_activity::record(pool, &tenant, &run_id, kind, text, None, source_ref)
        .await
        .is_err()
    {
        // The reference logs the exception's type only; a feed line must never carry the text.
        tracing::warn!(run = %run.run_id, kind, "activity record failed");
    }
}

/// The reference's `elicitation_request`: the section 5 `elicitation/create` request for one fr
/// approval. A non-empty `change_summary` string is appended as a second paragraph.
fn elicitation_request(message: &str, change_summary: Option<&Value>) -> Value {
    let mut text = message.to_owned();
    if let Some(summary) = change_summary
        .and_then(|value| value.as_str())
        .filter(|summary| !summary.is_empty())
    {
        text = format!("{text}\n\n{summary}");
    }
    json!({
        "method": "elicitation/create",
        "params": {
            "message": text,
            "requestedSchema": {
                "type": "object",
                "required": ["decision"],
                "properties": {
                    "decision": {"type": "string", "enum": ["approved", "rejected"]},
                    "reason": {"type": "string"},
                    "comment": {"type": "string"},
                },
            },
        },
    })
}

// ── messages ─────────────────────────────────────────────────────────────────────────────────

/// A `message` event: a chat reply for one run.
async fn message(pool: &PgPool, event: &Value) -> Result<(), sqlx::Error> {
    let Some(run_id) = event_uuid(event.get("correlation_id")) else {
        // fr echoes every channel command it dispatches back as a `message` whose correlation_id
        // is "<run id>:<poll|input key>", not a run id: our own poll, replayed. Dropped before any
        // database work.
        tracing::debug!("fr channel message ignored: non-UUID correlation");
        return Ok(());
    };
    let run = correlated(pool, &run_id).await?;
    let kind = event.get("kind").and_then(|value| value.as_str());
    tracing::info!(
        kind = %head(kind.unwrap_or("?")),
        matched = run.is_some(),
        "fr channel message"
    );
    let Some(run) = run else {
        return Ok(());
    };
    let meta = event.get("meta");
    let body = text(event.get("text"));

    if kind == Some("approval-request") {
        if let (Some(approval), Some(message)) = (text(member(meta, "approvalId")), body) {
            open_input(
                pool,
                &run.target.tenant_id,
                &run.target.run_id,
                approval,
                &elicitation_request(message, None),
                None,
            )
            .await?;
        }
        return Ok(());
    }

    if text(member(meta, "actionName")) == Some(START_ACTION) && run.runtime == "fr_project" {
        let project = text(member(member(meta, "result"), "project_id"));
        let outcome = text(member(meta, "outcome"));
        if kind == Some("action-result") && outcome == Some("approved") {
            // The reference folds `and project` into the condition: an approval that named no
            // project records nothing here.
            if let Some(project) = project {
                record(pool, &run.target, json!({ "project_id": project })).await?;
            }
        } else if kind == Some("action-result") && outcome == Some("rejected") {
            record(pool, &run.target, json!({ "start_outcome": "rejected" })).await?;
        } else if kind == Some("action-error") {
            record(pool, &run.target, json!({ "start_outcome": "failed" })).await?;
        }
        return Ok(());
    }

    if matches!(kind, Some("text" | "report")) {
        if let Some(body) = body {
            let message: String = body.chars().take(PHASE_LIMIT).collect();
            sqlx::query(
                "UPDATE public.mcp_runs SET status_message = $1 \
                 WHERE tenant_id = $2::uuid AND run_id = $3::uuid \
                 AND status <> ALL($4::text[])",
            )
            .bind(message)
            .bind(&run.target.tenant_id)
            .bind(&run.target.run_id)
            .bind(terminal_statuses())
            .execute(pool)
            .await?;
        }
    }
    Ok(())
}

/// A run a `message` event is correlated with.
struct CorrelatedRun {
    target: TargetRun,
    runtime: String,
}

/// The reference's `_correlated`: the live run with this id, when it is not a Kata run.
async fn correlated(pool: &PgPool, run_id: &str) -> Result<Option<CorrelatedRun>, sqlx::Error> {
    let row = sqlx::query(
        "SELECT run_id::text AS run_id, tenant_id::text AS tenant_id, runtime, external_ref \
         FROM public.mcp_runs \
         WHERE run_id = $1::uuid AND status <> ALL($2::text[]) \
         AND runtime <> 'kata_python'",
    )
    .bind(run_id)
    .bind(terminal_statuses())
    .fetch_optional(pool)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    Ok(Some(CorrelatedRun {
        target: target_run(&row)?,
        runtime: row.try_get("runtime")?,
    }))
}

// ── the task inputs an approval surfaces ─────────────────────────────────────────────────────

/// The reference's `key_for`: the run id and 16 fresh hex characters.
fn key_for(run_id: &str) -> String {
    let random = uuid::Uuid::new_v4().simple().to_string();
    format!("{run_id}:{}", &random[..16])
}

/// The reference's `open`: a new input, or nothing when (run, source ref) exists in any state (a
/// closed tombstone included), the run is unknown, or the approval already expired (fr would
/// refuse the answer, so the input is closed instead).
async fn open_input(
    pool: &PgPool,
    tenant: &str,
    run_id: &str,
    source_ref: &str,
    request: &Value,
    expires: Option<DateTime<Utc>>,
) -> Result<(), sqlx::Error> {
    if expires.is_some_and(|at| at <= Utc::now()) {
        return close_input(pool, tenant, run_id, source_ref).await;
    }
    // No chrono feature on this crate's sqlx: an instant travels as its canonical RFC 3339 text
    // and is cast by the server, so the stored value keeps microsecond precision.
    let expires = expires.map(|at| at.to_rfc3339_opts(SecondsFormat::Micros, true));
    let outcome = sqlx::query_scalar::<_, String>(
        "INSERT INTO public.mcp_task_inputs\
         (input_key,tenant_id,run_id,source_ref,request,expires_at) \
         VALUES ($1,$2::uuid,$3::uuid,$4,$5,$6::text::timestamptz) \
         ON CONFLICT (run_id,source_ref) DO NOTHING RETURNING input_key",
    )
    .bind(key_for(run_id))
    .bind(tenant)
    .bind(run_id)
    .bind(source_ref)
    .bind(request.clone())
    .bind(expires)
    .fetch_optional(pool)
    .await;
    match outcome {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(database)) if database.code().as_deref() == Some("23503") => {
            // The run is unknown or belongs to another tenant: a foreign key violation is a
            // silent no-op, exactly as the reference's `ForeignKeyViolation` handler.
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The reference's `close`: close the input; with none yet, leave a closed tombstone so a late
/// open is ignored.
async fn close_input(
    pool: &PgPool,
    tenant: &str,
    run_id: &str,
    source_ref: &str,
) -> Result<(), sqlx::Error> {
    let outcome = sqlx::query(
        "INSERT INTO public.mcp_task_inputs\
         (input_key,tenant_id,run_id,source_ref,request,state,closed_at) \
         VALUES ($1,$2::uuid,$3::uuid,$4,'{}'::jsonb,'closed',now()) \
         ON CONFLICT (run_id,source_ref) DO UPDATE SET state = 'closed', closed_at = now() \
         WHERE mcp_task_inputs.tenant_id = EXCLUDED.tenant_id \
         AND mcp_task_inputs.state <> 'closed'",
    )
    .bind(key_for(run_id))
    .bind(tenant)
    .bind(run_id)
    .bind(source_ref)
    .execute(pool)
    .await;
    match outcome {
        Ok(_) => Ok(()),
        Err(sqlx::Error::Database(database)) if database.code().as_deref() == Some("23503") => {
            Ok(())
        }
        Err(error) => Err(error),
    }
}

/// The reference's `close_everywhere`: fr closed an approval, so close it on every run it was
/// surfaced on.
async fn close_everywhere(pool: &PgPool, source_ref: &str) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE public.mcp_task_inputs SET state = 'closed', closed_at = now() \
         WHERE source_ref = $1 AND state <> 'closed'",
    )
    .bind(source_ref)
    .execute(pool)
    .await?;
    Ok(())
}
