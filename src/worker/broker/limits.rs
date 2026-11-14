//! Upstream limits: the deployment-owned ceiling table and the in-process tenant-source limiter.
//!
//! Port of the reference `src/broker/limits.py` and of `RateLimitedError`/`SourceLimiter` in
//! `src/broker/egress.py`. Two different limits live here on purpose:
//!
//! * [`RateLimits`] is **deployment-owned**: an operator writes one JSON file of per-service
//!   ceilings, and the broker narrows the configured `api_*` values with
//!   [`RateLimits::ceiling`]. The counters and the cross-process permit live in PostgreSQL and
//!   are implemented in [`crate::worker::store`]; nothing here touches the database.
//! * [`SourceLimiter`] is **in-process**: a per-`(tenant, service)` calls-per-minute and
//!   concurrency bound for tenant-registered sources. The database permit stays the global
//!   limit across processes; this only stops one process from becoming a request cannon against
//!   a single third party.
//!
//! A denied [`SourceLimiter::acquire`] is a [`RateLimitedError`], raised before any I/O and
//! re-exported from [`super::egress`] because the reference defines the class there.

use std::collections::{HashMap, HashSet};
use std::io::Read as _;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard};

use thiserror::Error;

use crate::catalog::ids::{AuthorityId, Uuid7};
use crate::worker::creds::Clock;

/// The file bound (`limits.py:29-30` reads `262145` bytes and refuses anything longer).
const MAX_LIMIT_FILE_BYTES: usize = 262_144;
/// The table bound (`RateLimits.limits` is `max_length=1024`).
const MAX_LIMIT_ENTRIES: usize = 1_024;
/// The per-key rate window.
const WINDOW_SECONDS: f64 = 60.0;
/// When the recent-call map grows past this, stale keys are swept (`limits.py:110`).
const SWEEP_THRESHOLD: usize = 4_096;

/// A tenant source is over its per-minute or concurrency budget (`egress.py:255`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
#[error("rate limited")]
pub struct RateLimitedError;

/// Why an upstream limit table was refused. Never carries the offending value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum RateLimitsError {
    /// The file is longer than the bounded read.
    #[error("upstream limit file exceeds bounds")]
    TooLarge,
    /// Two entries name the same `(service_id, tenant_id)`.
    #[error("duplicate upstream limit")]
    Duplicate,
    /// The payload is not the closed schema, or a value is out of range.
    #[error("invalid upstream limit table")]
    Invalid,
}

/// One deployment-owned ceiling (`ServiceLimit`), scoped to a tenant when one is named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLimit {
    /// The service the ceiling applies to.
    pub service_id: Uuid7,
    /// `None` applies to every tenant; otherwise only to this tenant.
    pub tenant_id: Option<AuthorityId>,
    /// Calls allowed in one minute, 1 to 10000.
    pub calls_per_minute: u32,
    /// Calls allowed in flight, 1 to 100.
    pub concurrency: u32,
}

impl ServiceLimit {
    fn valid(&self) -> bool {
        (1..=10_000).contains(&self.calls_per_minute) && (1..=100).contains(&self.concurrency)
    }
}

impl TryFrom<wire::ServiceLimit> for ServiceLimit {
    type Error = RateLimitsError;

    fn try_from(wire: wire::ServiceLimit) -> Result<Self, Self::Error> {
        let limit = Self {
            service_id: wire.service_id,
            tenant_id: wire.tenant_id,
            calls_per_minute: wire.calls_per_minute,
            concurrency: wire.concurrency,
        };
        if limit.valid() {
            Ok(limit)
        } else {
            Err(RateLimitsError::Invalid)
        }
    }
}

/// The closed deployment table (`RateLimits`): a schema version and its entries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RateLimits {
    /// Always 1.
    pub schema_version: u8,
    /// At most 1024 entries, each identity unique.
    pub limits: Vec<ServiceLimit>,
}

impl Default for RateLimits {
    fn default() -> Self {
        // The reference's `RateLimits()`: the pydantic default for `schema_version` is 1.
        Self {
            schema_version: 1,
            limits: Vec::new(),
        }
    }
}

impl RateLimits {
    /// Read the operator's table, or the empty default when no file is configured.
    ///
    /// The reference reads at most 262145 bytes and refuses a longer file before parsing, so a
    /// hostile file cannot make the process allocate without bound.
    pub fn read(path: Option<&Path>) -> Result<Self, RateLimitsError> {
        let Some(path) = path else {
            return Ok(Self::default());
        };
        let mut payload = Vec::new();
        std::fs::File::open(path)
            .map_err(|_| RateLimitsError::Invalid)?
            .take((MAX_LIMIT_FILE_BYTES + 1) as u64)
            .read_to_end(&mut payload)
            .map_err(|_| RateLimitsError::Invalid)?;
        if payload.len() > MAX_LIMIT_FILE_BYTES {
            return Err(RateLimitsError::TooLarge);
        }
        let wire: wire::RateLimits =
            serde_json::from_slice(&payload).map_err(|_| RateLimitsError::Invalid)?;
        let schema_version = wire.schema_version;
        if wire.limits.len() > MAX_LIMIT_ENTRIES {
            return Err(RateLimitsError::Invalid);
        }
        let mut limits = Vec::with_capacity(wire.limits.len());
        for entry in wire.limits {
            limits.push(ServiceLimit::try_from(entry)?);
        }
        let mut identities = HashSet::with_capacity(limits.len());
        for limit in &limits {
            if !identities.insert((limit.service_id.clone(), limit.tenant_id.clone())) {
                return Err(RateLimitsError::Duplicate);
            }
        }
        Ok(Self {
            schema_version,
            limits,
        })
    }

    /// The narrowed `(calls_per_minute, concurrency)` for one tenant and service
    /// (`limits.py:36-41`): every matching entry applies, tenant-specific ones included.
    pub fn ceiling(
        &self,
        tenant: &AuthorityId,
        service: &Uuid7,
        calls: u32,
        concurrency: u32,
    ) -> (u32, u32) {
        let mut calls = calls;
        let mut concurrency = concurrency;
        for limit in &self.limits {
            if &limit.service_id == service
                && (limit.tenant_id.is_none() || limit.tenant_id.as_ref() == Some(tenant))
            {
                calls = calls.min(limit.calls_per_minute);
                concurrency = concurrency.min(limit.concurrency);
            }
        }
        (calls, concurrency)
    }
}

/// The wire shape of [`RateLimits`]: strict, closed, and rejected as a whole on any extra field.
mod wire {
    use super::{AuthorityId, Uuid7};
    use serde::Deserialize;
    use serde::de::Error as _;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct RateLimits {
        #[serde(default, deserialize_with = "one")]
        pub(super) schema_version: u8,
        #[serde(default)]
        pub(super) limits: Vec<ServiceLimit>,
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(super) struct ServiceLimit {
        pub(super) service_id: Uuid7,
        #[serde(default)]
        pub(super) tenant_id: Option<AuthorityId>,
        pub(super) calls_per_minute: u32,
        pub(super) concurrency: u32,
    }

    /// `Literal[1]` as an integer and nothing else; a float or string is invalid.
    fn one<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
        let value = u64::deserialize(deserializer)?;
        if value == 1 {
            Ok(1)
        } else {
            Err(D::Error::custom("schema_version must be an integer 1"))
        }
    }
}

/// Per-key limiter state; the outer `Arc` makes a [`Slot`] an independent release guard.
struct State {
    /// Timestamps inside the current minute window, oldest first.
    recent: HashMap<(String, String), Vec<f64>>,
    /// Calls currently in flight.
    inflight: HashMap<(String, String), u32>,
}

/// The reference's `time.monotonic`: seconds from an arbitrary monotonic start.
fn monotonic_clock() -> Clock {
    let start = std::time::Instant::now();
    Arc::new(move || start.elapsed().as_secs_f64())
}

/// The in-process per-`(tenant, service)` rate and concurrency limiter (`egress.py:264-297`).
pub struct SourceLimiter {
    calls: u32,
    concurrency: u32,
    clock: Clock,
    state: Arc<Mutex<State>>,
}

impl SourceLimiter {
    /// A limiter with the monotonic clock, exactly as the reference's default
    /// (`time.monotonic`): a wall-clock step never widens or closes the minute window.
    pub fn new(calls_per_minute: u32, concurrency: u32) -> Self {
        Self::with_clock(calls_per_minute, concurrency, monotonic_clock())
    }

    /// A limiter with an injectable clock, so the minute window is proved without sleeping.
    pub fn with_clock(calls_per_minute: u32, concurrency: u32, clock: Clock) -> Self {
        Self {
            calls: calls_per_minute,
            concurrency,
            clock,
            state: Arc::new(Mutex::new(State {
                recent: HashMap::new(),
                inflight: HashMap::new(),
            })),
        }
    }

    fn now(&self) -> f64 {
        (self.clock)()
    }

    fn state(&self) -> MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner())
    }

    /// Take one slot for `(tenant, service)`, or refuse before any I/O is started.
    ///
    /// The two ceilings are checked together, exactly as the reference: a call that would
    /// exceed either the per-minute allowance or the in-flight count is denied.
    pub fn acquire(&self, tenant: &str, service: &str) -> Result<Slot, RateLimitedError> {
        let key = (tenant.to_owned(), service.to_owned());
        let now = self.now();
        let mut state = self.state();
        let mut recent = state.recent.remove(&key).unwrap_or_default();
        recent.retain(|timestamp| now - *timestamp < WINDOW_SECONDS);
        let inflight = state.inflight.get(&key).copied().unwrap_or(0);
        if recent.len() as u32 >= self.calls || inflight >= self.concurrency {
            state.recent.insert(key, recent);
            return Err(RateLimitedError);
        }
        recent.push(now);
        state.recent.insert(key.clone(), recent);
        *state.inflight.entry(key.clone()).or_insert(0) += 1;
        // A tenant that churns service names can grow this map; the reference sweeps it once it
        // passes 4096 keys, dropping every key whose last call is outside the window.
        if state.recent.len() > SWEEP_THRESHOLD {
            state
                .recent
                .retain(|_, timestamps| match timestamps.last() {
                    Some(last) => now - *last < WINDOW_SECONDS,
                    None => false,
                });
        }
        Ok(Slot {
            state: Arc::clone(&self.state),
            key,
            held: true,
        })
    }
}

/// One acquired slot; releasing it (explicitly or on drop) frees the in-flight count.
pub struct Slot {
    state: Arc<Mutex<State>>,
    key: (String, String),
    held: bool,
}

impl Slot {
    /// Release the slot now.
    pub fn release(mut self) {
        self.release_inner();
    }

    fn release_inner(&mut self) {
        if !self.held {
            return;
        }
        self.held = false;
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        match state.inflight.get(&self.key).copied().unwrap_or(1) {
            left if left > 1 => {
                state.inflight.insert(self.key.clone(), left - 1);
            }
            _ => {
                state.inflight.remove(&self.key);
            }
        }
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.release_inner();
    }
}
