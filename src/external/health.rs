//! The external driver's internal probes.
//!
//! Ported from the reference `src/external/driver.py` (`Liveness` and `probe_app`). The listener
//! is bound on `MCP_EXTERNAL_PROBE_PORT` and restricted by the driver's NetworkPolicy: nothing
//! here is reachable from the public surface, and the bodies are the reference's exactly.
//!
//! Readiness is *liveness*, not a dependency check: the reference answers ready while the last
//! completed tick is inside three poll intervals, so a driver that has stopped ticking is
//! restarted by Kubernetes rather than reported healthy.

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use serde_json::{Value, json};

/// The last time a tick completed, and how long that stays fresh.
#[derive(Debug)]
pub struct Liveness {
    window: Duration,
    last_ok: Mutex<Option<Instant>>,
}

impl Liveness {
    /// A liveness window: three poll intervals, as the reference builds it.
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            last_ok: Mutex::new(None),
        }
    }

    /// Record that a tick completed.
    pub fn mark(&self) {
        if let Ok(mut last) = self.last_ok.lock() {
            *last = Some(Instant::now());
        }
    }

    /// Whether the last completed tick is still inside the window.
    pub fn ready(&self) -> bool {
        self.last_ok
            .lock()
            .ok()
            .and_then(|last| *last)
            .is_some_and(|last| last.elapsed() <= self.window)
    }
}

/// The driver's probe router: `/health/live` and `/health/ready`.
pub fn app(liveness: Arc<Liveness>) -> Router {
    Router::new()
        .route("/health/live", get(live))
        .route("/health/ready", get(ready))
        .with_state(liveness)
}

/// `GET /health/live`
async fn live() -> Json<Value> {
    Json(json!({"status": "alive"}))
}

/// `GET /health/ready`
async fn ready(State(liveness): State<Arc<Liveness>>) -> Response {
    if liveness.ready() {
        Json(json!({"status": "ready"})).into_response()
    } else {
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Json(json!({"status": "not_ready"})),
        )
            .into_response()
    }
}
