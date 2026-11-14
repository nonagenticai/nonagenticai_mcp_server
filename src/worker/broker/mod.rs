//! The upstream broker: every call a runner makes leaves through this module, fenced,
//! journalled, policy-checked and credential-minted.
//!
//! Port of the reference `src/broker/client.py` (pinned oracle `22ac1ce4`). Nothing a runner
//! sends is trusted: the operation, the destination, the credentials and the limits all come
//! from the snapshotted authority and the registered source, never from the frame.
//!
//! The shape of the port:
//!
//! * [`Broker::preflight`] proves the whole authority before a pod is allocated: the live
//!   binding, the gateway and service credentials, and every pinned operation — published, owned
//!   or shared, sourced, and (for a licence-kind source) mintable. A single mismatch denies.
//! * [`Broker::call`] is the fenced, journalled, bounded exchange. Intent is committed **before**
//!   any network I/O, the outcome exactly once after it, the permit and the tenant limiter slot
//!   are always released, and a transport failure after a write may have been delivered is
//!   [`BrokerError::OutcomeUnknown`] rather than a denial.
//! * [`CallOutcome::Expected`] is the reference's `UpstreamStatusError`: a declared expected
//!   status is a *result* for the runner, journalled `failed`/`status`, never a denial.
//!
//! Four reference behaviours have no direct reqwest counterpart and are documented at their
//! function: the pinned tenant transport (`PinnedClient::execute`), the per-host pin used for a
//! tenant-owned source's OAuth token fetch, `close` (reqwest has no explicit close), and the
//! retry classification of a pinned transport failure.

pub mod auth;
pub mod egress;
pub mod limits;
pub mod policy;

use std::collections::HashMap;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use chrono::Utc;
use serde_json::{Map, Value, json};
use thiserror::Error;
use url::Url;

use crate::auth::Rfc4122Uuid;
use crate::auth::licenses::LicenceAuthority;
use crate::catalog::ids::{AppKey, AuthorityId};
use crate::catalog::instance::validate_instance;
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    AuthAdapter, Constraint, Effect, ExactReference, Idempotency, Method, OperationManifest,
    ServiceManifest,
};
use crate::catalog::resolver::CatalogResolver;
use crate::catalog::toolkit_models::{CredentialProfile, CredentialReference};
use crate::catalog::validation::SchemaLimits;
use crate::config::{ExecutionSettings, WorkerSettings};
use crate::execution::{canonical_json, value_hash};
use crate::storage::catalog::CatalogRepository;
use crate::worker::authority;
use crate::worker::creds::{self, CredentialResolver};
use crate::worker::row::WorkerRow;
use crate::worker::sources::{LicenceScheme, ResolvedSource, SourceAuth, SourceRegistry};
use crate::worker::store::{JournalOperation, WorkerStore};

use self::auth::AuthAdapters;
use self::egress::{
    EgressError, EgressPolicy, PinnedClients, PlatformClients, PoolLimits, tenant_client,
};
use self::limits::SourceLimiter;
use self::policy::{OwnershipRead, PolicyError};

/// The first 2 KB of a failed upstream answer (`client.py:45`).
const EXCERPT_CHARS: usize = 2048;

/// A refused call. Never carries request content or credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum BrokerError {
    /// The reference's `ExecutionDeniedError`: a fence, policy, credential, transport or
    /// framing refusal. The runner is told the call did not happen.
    #[error("broker denied")]
    Denied,
    /// The reference's `OutcomeUnknownError`: a transport failure after a request that writes
    /// may have been delivered. The run must end `outcome_unknown`, never be retried.
    #[error("upstream outcome unknown")]
    OutcomeUnknown,
}

/// The result of one brokered call.
///
/// [`CallOutcome::Expected`] is the reference's `UpstreamStatusError`: an upstream answered a
/// status the operation declares, and its projected body is a *result* for the tool.
#[derive(Debug, Clone, PartialEq)]
pub enum CallOutcome {
    /// A successful exchange, projected and validated against the operation's output schema.
    Value(Value),
    /// A declared expected status. `body` is the projected JSON, or `Value::Null` when the
    /// answer could not be projected safely (`error_body` returns `None`).
    Expected { status: u16, body: Value },
}

/// One failure inside an exchange attempt.
///
/// `retry` is set only for the reference's `httpx.TransportError` class (a transport failure
/// with attempts remaining), never for an egress refusal. `egress_reset` is the reference's
/// `sent = error.reason == "redirect"` (`client.py:615`): only an `EgressDeniedError` rewrites
/// the "a request may have been sent" flag, so no other kind of failure touches it.
struct Failure {
    reason: Option<&'static str>,
    egress_reset: Option<bool>,
    retry: bool,
    error_excerpt: Option<String>,
}

impl Failure {
    /// A refusal that carries no egress decision; the `sent` flag is left as it was.
    fn denied(reason: Option<&'static str>) -> Self {
        Self {
            reason,
            egress_reset: None,
            retry: false,
            error_excerpt: None,
        }
    }

    /// A refusal raised while resolving the destination, before any byte was written.
    fn resolution(error: EgressError) -> Self {
        Self {
            reason: Some(error.reason()),
            egress_reset: Some(false),
            retry: false,
            error_excerpt: None,
        }
    }

    /// A refusal raised by the transport, after or around the request.
    fn refused(error: EgressError) -> Self {
        match error {
            // A redirect answer proves bytes were sent; nothing is ever followed.
            EgressError::Redirect => Self {
                reason: Some("redirect"),
                egress_reset: Some(true),
                retry: false,
                error_excerpt: None,
            },
            EgressError::SsrfBlocked => Self::resolution(error),
            // The reference's pinned backend raises `EgressDeniedError("transport")` before a
            // connection; a *connection* failure inside `PinnedClient::execute` carries the same
            // variant in this port, so it keeps the reference's retry classification. A failure
            // after the request may have been sent keeps that classification too (the retry
            // loop, not the address walk, decides); it is never replayed on another address.
            EgressError::Transport | EgressError::TransportSent => Self {
                reason: Some("transport"),
                egress_reset: None,
                retry: true,
                error_excerpt: None,
            },
        }
    }

    /// A reqwest transport failure (the reference's `httpx.TransportError`).
    fn transport(reason: &'static str) -> Self {
        Self {
            reason: Some(reason),
            egress_reset: None,
            retry: true,
            error_excerpt: None,
        }
    }
}

/// The upstream broker. Every dependency is explicit: the store and the catalog are read per
/// call, the credentials and licences are external boundaries, and the transports are pinned by
/// the composition root.
pub struct Broker {
    /// The database pool the denial event's own transaction runs on.
    pool: sqlx::PgPool,
    store: WorkerStore,
    settings: WorkerSettings,
    execution: ExecutionSettings,
    catalog: CatalogRepository,
    resolver: CatalogResolver,
    credentials: Arc<dyn CredentialResolver>,
    licences: Arc<dyn LicenceAuthority>,
    sources: SourceRegistry,
    auth: AuthAdapters,
    egress: Arc<EgressPolicy>,
    limiter: SourceLimiter,
    platform_http: PlatformClients,
    /// One client per validated tenant address (`egress.py:127-165`).
    pins: PinnedClients,
    /// `MCP_LICENSE_APP_KEY`: the gateway application key the profile must name.
    license_app_key: Option<String>,
    /// `PLATFORM_TENANT_ID`: the reserved tenant that owns platform services.
    platform_tenant_id: AuthorityId,
}

impl Broker {
    /// Bind the broker to every dependency it uses. Nothing is read from the environment here.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: sqlx::PgPool,
        store: WorkerStore,
        settings: WorkerSettings,
        execution: ExecutionSettings,
        catalog: CatalogRepository,
        resolver: CatalogResolver,
        credentials: Arc<dyn CredentialResolver>,
        licences: Arc<dyn LicenceAuthority>,
        sources: SourceRegistry,
        auth: AuthAdapters,
        egress: Arc<EgressPolicy>,
        limiter: SourceLimiter,
        platform_http: PlatformClients,
        license_app_key: Option<String>,
        platform_tenant_id: AuthorityId,
    ) -> Self {
        let pins = PinnedClients::new(Arc::clone(&egress), pool_limits(&settings));
        Self {
            pool,
            store,
            settings,
            execution,
            catalog,
            resolver,
            credentials,
            licences,
            sources,
            auth,
            egress,
            limiter,
            platform_http,
            pins,
            license_app_key,
            platform_tenant_id,
        }
    }

    /// Whether the resolver holds the gateway (mcp) licence (`client.py:165-170`).
    fn gateway_credentials(&self) -> bool {
        self.credentials.gateway_credentials()
    }

    fn pool_limits(&self) -> PoolLimits {
        pool_limits(&self.settings)
    }

    /// Prove the whole authority before a pod is allocated (`client.py:277-306`).
    ///
    /// The live binding, the profile's gateway identity, every service credential, and every
    /// pinned operation are verified. Nothing here is cached, so a revocation between preflight
    /// and the first call still denies.
    pub async fn preflight(&self, row: &WorkerRow) -> Result<(), BrokerError> {
        let live = authority::live(&self.store, &self.resolver, row)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let profile = &live.profile;
        let gateway = row.run.gateway_license_id.to_string();
        if self.license_app_key.as_deref() != Some(profile.gateway.app_key.as_str())
            || profile.gateway.license_id.as_str() != gateway
        {
            return Err(BrokerError::Denied);
        }
        if self.gateway_credentials() {
            self.identity(row, profile, &profile.gateway).await?;
        }
        for credential in &profile.services {
            self.identity(row, profile, credential).await?;
        }
        let tenant = tenant_of(row)?;
        for reference in &live.resolved.manifest.allowed_operations {
            let (operation, status) = self
                .catalog
                .operation(reference)
                .await
                .map_err(|_| BrokerError::Denied)?;
            let (service, service_status) = self
                .catalog
                .service(&operation.service)
                .await
                .map_err(|_| BrokerError::Denied)?;
            if status != VersionStatus::Published || service_status != VersionStatus::Published {
                return Err(BrokerError::Denied);
            }
            let (owner, source) = self.destination(&operation, &service).await?;
            if !self.usable(&tenant, &owner, &operation.service).await? {
                return Err(BrokerError::Denied);
            }
            if !matches!(source.auth, SourceAuth::Licence { .. }) {
                // A stored token: no tenant licence to verify.
                continue;
            }
            if service.auth_adapter == AuthAdapter::Source {
                self.source_licence(row, &service, &source).await?;
                continue;
            }
            let credential =
                Self::licence_credential(profile, &service, &source).ok_or(BrokerError::Denied)?;
            self.identity(row, profile, credential).await?;
        }
        Ok(())
    }

    /// Broker exactly one operation for this run (`client.py:307-341`).
    ///
    /// On any denial only fixed facts are logged (run id, operation id, error type) and the
    /// `broker_denied` event is appended under the fence. A declared expected status is returned
    /// as [`CallOutcome::Expected`], never as an error.
    pub async fn call(
        &self,
        row: &WorkerRow,
        operation_id: &str,
        arguments: &Map<String, Value>,
        idempotency_key: Option<&str>,
    ) -> Result<CallOutcome, BrokerError> {
        let result = self
            .call_inner(row, operation_id, arguments, idempotency_key, None)
            .await;
        if let Err(error) = &result {
            // Operators need to know WHICH check denied: identities, the fixed error type and
            // nothing else — never a message, a path or a value.
            tracing::warn!(
                run = %row.run.run_id,
                operation = operation_id,
                cause = ?error,
                "broker denied"
            );
            self.note_denied(row).await;
        }
        result
    }

    /// Release what the broker holds. reqwest has no explicit `close`: a pooled client's
    /// connections are released when the last reference to it is dropped, so this is a no-op in
    /// this port and exists for the reference's call sites.
    pub async fn close(&self) {}

    // ── the exchange ────────────────────────────────────────────────────────────────────────

    async fn call_inner(
        &self,
        row: &WorkerRow,
        operation_id: &str,
        arguments: &Map<String, Value>,
        idempotency_key: Option<&str>,
        ownership_reference: Option<&ExactReference>,
    ) -> Result<CallOutcome, BrokerError> {
        let live = authority::live(&self.store, &self.resolver, row)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let profile = &live.profile;
        if self.gateway_credentials() {
            // A minting resolver never holds the gateway licence: the caller's request already
            // authenticated it, and the live check above re-checks binding and fence.
            self.identity(row, profile, &profile.gateway).await?;
        }
        let reference = match ownership_reference {
            // Only host policy evaluation can enter this branch, never a frame flag.
            Some(reference) => reference.clone(),
            None => live
                .resolved
                .manifest
                .allowed_operations
                .iter()
                .find(|candidate| candidate.id.as_str() == operation_id)
                .cloned()
                .ok_or(BrokerError::Denied)?,
        };
        let (operation, status) = self
            .catalog
            .operation(&reference)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let (service, service_status) = self
            .catalog
            .service(&operation.service)
            .await
            .map_err(|_| BrokerError::Denied)?;
        if status != VersionStatus::Published || service_status != VersionStatus::Published {
            return Err(BrokerError::Denied);
        }
        if ownership_reference.is_some()
            && (operation.effect != Effect::ReadOnly
                || operation
                    .scope_rules
                    .iter()
                    .any(|rule| matches!(rule, Constraint::OwnershipRead(_))))
        {
            return Err(BrokerError::Denied);
        }
        if live.resolved.manifest.effect == Effect::ReadOnly && operation.effect != Effect::ReadOnly
        {
            return Err(BrokerError::Denied);
        }
        validate_instance(
            &Value::Object(operation.input_schema.clone()),
            &Value::Object(arguments.clone()),
            &SchemaLimits::default(),
        )
        .map_err(|_| BrokerError::Denied)?;
        let context_value = live.resolved.context.public_values();
        let context: Map<String, Value> = context_value.as_object().cloned().unwrap_or_default();

        let ownership = Ownership { broker: self, row };
        policy::enforce(&operation.scope_rules, arguments, &context, &ownership)
            .await
            .map_err(|_| BrokerError::Denied)?;
        if ownership_reference.is_none() {
            for constraints in &live.effective.operation_constraints {
                if constraints.operation == reference {
                    policy::enforce(&constraints.rules, arguments, &context, &ownership)
                        .await
                        .map_err(|_| BrokerError::Denied)?;
                }
            }
        }
        let (owner, destination) = self.destination(&operation, &service).await?;
        let tenant = tenant_of(row)?;
        if !self.usable(&tenant, &owner, &operation.service).await? {
            return Err(BrokerError::Denied);
        }
        let request =
            policy::transport(&operation, arguments, &context).map_err(|_| BrokerError::Denied)?;
        let path = request.path;
        let body = request.body;
        let mut query: HashMap<String, String> = request.query.into_iter().collect();
        let mut headers: HashMap<String, String> = request.headers.into_iter().collect();

        let mut secrets: Vec<String> = Vec::new();
        let mut credential: Option<CredentialReference> = None;
        if matches!(destination.auth, SourceAuth::Licence { .. }) {
            let scheme = match &destination.auth {
                SourceAuth::Licence { scheme, .. } => *scheme,
                _ => unreachable!("checked above"),
            };
            let token = if service.auth_adapter == AuthAdapter::Source {
                let (reference, token) = self.source_licence(row, &service, &destination).await?;
                credential = Some(reference);
                token
            } else {
                let reference = Self::licence_credential(profile, &service, &destination)
                    .ok_or(BrokerError::Denied)?;
                let token = self.identity(row, profile, reference).await?;
                credential = Some(reference.clone());
                token
            };
            secrets.push(token.clone());
            headers.insert(scheme.header().to_owned(), format!("Bearer {token}"));
            // Optional operator-provisioned upstream OAuth is independent of the application's
            // licence. Only the licence-header scheme can coexist in this form; neither value is
            // ever accepted from runner arguments or headers.
            if service.auth_adapter != AuthAdapter::Source
                && let Some(reference) = credential.as_ref()
            {
                let resolver_reference = resolver_reference(reference)?;
                let material = self
                    .credentials
                    .entry(
                        &row.run.tenant_id,
                        &profile_id(profile)?,
                        &resolver_reference,
                    )
                    .await
                    .map_err(|_| BrokerError::Denied)?;
                if let Some(oauth) = material.oauth_bearer {
                    if scheme != LicenceScheme::XTenantIdBearer {
                        return Err(BrokerError::Denied);
                    }
                    headers.insert("Authorization".to_owned(), format!("Bearer {oauth}"));
                }
            }
        }
        if let Some(key) = idempotency_key {
            if !valid_idempotency_key(key)
                || operation.idempotency != Idempotency::DownstreamKey
                || destination.idempotency_header.is_none()
            {
                return Err(BrokerError::Denied);
            }
            if let Some(name) = destination.idempotency_header.as_ref() {
                headers.insert(name.clone(), key.to_owned());
            }
        }
        if operation.effect == Effect::Writes
            && operation.max_retries > 0
            && idempotency_key.is_none()
        {
            return Err(BrokerError::Denied);
        }

        let method = method_text(operation.method);
        let trace_path: String = path.chars().take(1024).collect();
        let started = Instant::now();

        // A tenant-owned source's OAuth token fetch uses the caller's pinned client; every other
        // kind performs no I/O here.
        let tenant_http = if destination.tenant_owned
            && matches!(destination.auth, SourceAuth::OAuth2ClientCredentials { .. })
        {
            let token_url = match &destination.auth {
                SourceAuth::OAuth2ClientCredentials { token_url, .. } => token_url.as_str(),
                _ => unreachable!("checked above"),
            };
            Some(self.pinned_tenant_client(token_url).await?)
        } else {
            None
        };
        // Stored credentials last: the query secret is added after every mapped parameter and a
        // collision with a mapped name or header is rejected, never overwritten.
        let applied = self
            .auth
            .apply(&destination, &mut headers, &mut query, tenant_http.as_ref())
            .await
            .map_err(|_| BrokerError::Denied)?;
        secrets.extend(applied);

        let payload = body.as_ref().map(canonical_json);
        let request_bytes = path.len()
            + canonical_json(&object(&query)).len()
            + canonical_json(&object(&headers)).len()
            + payload.as_deref().map_or(0, str::len);
        let request_cap = (service.max_request_bytes as u64).min(destination.max_request_bytes);
        if request_bytes as u64 > request_cap {
            return Err(BrokerError::Denied);
        }
        if payload.is_some() {
            headers.insert("Content-Type".to_owned(), "application/json".to_owned());
        }
        let request = build_request(&operation, &destination, &path, &query, &headers, payload)?;

        let limit = (operation.max_response_bytes as u64)
            .min(service.max_response_bytes as u64)
            .min(destination.max_response_bytes)
            .min(self.execution.max_result_bytes as u64)
            .min(self.settings.api_max_response_bytes as u64);
        let frame_limit = usize::try_from(live.effective.limits.frame_bytes / 2).unwrap_or(0);
        let call_limit = live.effective.limits.api_calls;
        let leaks = self.leaks(row, profile, secrets).await?;
        let draft = row.run.mode == "draft" && destination.tenant_owned;
        let writes = operation.effect == Effect::Writes;

        let slot = if destination.tenant_owned {
            let tenant_key = row.run.tenant_id.to_string();
            Some(
                self.limiter
                    .acquire(&tenant_key, operation.service.id.as_str())
                    .map_err(|_| BrokerError::Denied)?,
            )
        } else {
            None
        };
        let service_id =
            Rfc4122Uuid::parse(service.service_id.as_str()).ok_or(BrokerError::Denied)?;
        let mut permit = match self.store.permit(row, &service_id).await {
            Ok(permit) => permit,
            Err(_) => {
                if let Some(slot) = slot {
                    slot.release();
                }
                return Err(BrokerError::Denied);
            }
        };

        let journal_operation = JournalOperation {
            id: Rfc4122Uuid::parse(reference.id.as_str()).ok_or(BrokerError::Denied)?,
            version: i32::try_from(reference.version.get()).unwrap_or(i32::MAX),
            effect: effect_text(operation.effect).to_owned(),
            pagination_limit: i64::from(operation.pagination_limit),
        };
        let license_id = match credential.as_ref() {
            Some(reference) => {
                Rfc4122Uuid::parse(reference.license_id.as_str()).ok_or(BrokerError::Denied)?
            }
            None => row.run.gateway_license_id,
        };
        let mut sequence: Option<i64> = None;
        let mut sent = false;
        let mut reason: Option<&'static str> = None;
        let mut http_status: Option<u16> = None;

        let budget = exchange_budget(&self.settings, &operation, row);
        let exchange = async {
            // Commit intent before network I/O. The host request hash excludes credentials.
            sequence = Some(
                self.store
                    .journal_intent(
                        row,
                        &journal_operation,
                        &value_hash(&json!({
                            "operation": reference.id.as_str(),
                            "version": reference.version.get(),
                            "arguments": Value::Object(arguments.clone()),
                        })),
                        idempotency_key,
                        &license_id,
                        Some(call_limit),
                        Some(method),
                        Some(trace_path.as_str()),
                    )
                    .await
                    .map_err(|_| Failure::denied(None))?,
            );
            let mut attempt: u32 = 0;
            loop {
                // Fencing, revocation and budget are rechecked even for retries. Budget is
                // charged per actual HTTP attempt, including host ownership reads.
                authority::live(&self.store, &self.resolver, row)
                    .await
                    .map_err(|_| Failure::denied(None))?;
                if attempt > 0 {
                    let _ = self.store.release_permit(row, &permit).await;
                    permit = self
                        .store
                        .permit(row, &service_id)
                        .await
                        .map_err(|_| Failure::denied(None))?;
                    sequence = Some(
                        self.store
                            .journal_intent(
                                row,
                                &journal_operation,
                                &value_hash(&Value::Object(arguments.clone())),
                                idempotency_key,
                                &license_id,
                                Some(call_limit),
                                Some(method),
                                Some(trace_path.as_str()),
                            )
                            .await
                            .map_err(|_| Failure::denied(None))?,
                    );
                }
                sent = true;
                reason = None;
                let attempt_request = request.try_clone().ok_or_else(|| Failure::denied(None))?;
                match self.send(&destination, attempt_request).await {
                    Ok(mut response) => {
                        let status = response.status().as_u16();
                        http_status = Some(status);
                        if status == 401
                            && matches!(
                                destination.auth,
                                SourceAuth::OAuth2ClientCredentials { .. }
                            )
                        {
                            self.auth.evict(&destination);
                        }
                        if operation.expected_error_statuses.contains(&status) {
                            let body = self
                                .error_body(&mut response, &operation, limit, frame_limit, &leaks)
                                .await;
                            let excerpt = if draft {
                                body.as_ref()
                                    .map(|body| truncate(&canonical_json(body), EXCERPT_CHARS))
                            } else {
                                None
                            };
                            let current = sequence.unwrap_or_default();
                            self.journal_outcome_row(
                                row,
                                current,
                                "failed",
                                http_status,
                                started.elapsed(),
                                Some("status"),
                                excerpt.as_deref(),
                            )
                            .await
                            .map_err(|_| Failure::denied(None))?;
                            sequence = None;
                            return Ok(CallOutcome::Expected {
                                status,
                                body: body.unwrap_or(Value::Null),
                            });
                        }
                        if !(200..300).contains(&status) {
                            let excerpt = if draft {
                                Self::excerpt(&mut response, &leaks).await
                            } else {
                                None
                            };
                            reason = Some(if status == 401 {
                                "auth_failed"
                            } else {
                                "status"
                            });
                            return Err(Failure {
                                reason,
                                egress_reset: None,
                                retry: false,
                                error_excerpt: excerpt,
                            });
                        }
                        let mut data: Vec<u8> = Vec::new();
                        loop {
                            match response.chunk().await {
                                Ok(Some(chunk)) => {
                                    data.extend_from_slice(&chunk);
                                    if data.len() as u64 > limit {
                                        reason = Some("too_large");
                                        return Err(Failure::denied(reason));
                                    }
                                }
                                Ok(None) => break,
                                Err(_) => {
                                    reason = Some("transport");
                                    return Err(Failure::transport("transport"));
                                }
                            }
                        }
                        reason = Some("schema_mismatch");
                        let result = if operation.empty_response {
                            json!({})
                        } else {
                            let raw: Value = serde_json::from_slice(&data)
                                .map_err(|_| Failure::denied(reason))?;
                            policy::project(&operation, &raw)
                                .map_err(|_| Failure::denied(reason))?
                        };
                        // A downstream echo must not transport mounted auth material into a
                        // runner even if an operator declared a broad schema.
                        if leaks.contains(&canonical_json(&result)) {
                            return Err(Failure::denied(reason));
                        }
                        validate_instance(
                            &Value::Object(operation.output_schema.clone()),
                            &result,
                            &SchemaLimits::default(),
                        )
                        .map_err(|_| Failure::denied(reason))?;
                        if canonical_json(&result).len() > frame_limit {
                            reason = Some("too_large");
                            return Err(Failure::denied(reason));
                        }
                        reason = None;
                        let current = sequence.unwrap_or_default();
                        self.journal_outcome_row(
                            row,
                            current,
                            "succeeded",
                            http_status,
                            started.elapsed(),
                            None,
                            None,
                        )
                        .await
                        .map_err(|_| Failure::denied(None))?;
                        sequence = None;
                        return Ok(CallOutcome::Value(result));
                    }
                    Err(failure) => {
                        reason = failure.reason;
                        if let Some(value) = failure.egress_reset {
                            sent = value;
                        }
                        if failure.retry {
                            if let Some(current) = sequence {
                                let _ = self
                                    .journal_outcome_row(
                                        row,
                                        current,
                                        if writes { "outcome_unknown" } else { "failed" },
                                        http_status,
                                        started.elapsed(),
                                        failure.reason,
                                        None,
                                    )
                                    .await;
                            }
                            if attempt >= operation.max_retries {
                                return Err(failure);
                            }
                            tokio::time::sleep(Duration::from_secs_f64(
                                0.05 * f64::from(attempt + 1),
                            ))
                            .await;
                            attempt += 1;
                            continue;
                        }
                        return Err(failure);
                    }
                }
            }
        };

        let exchanged = tokio::time::timeout(budget, exchange).await;
        // Always release the permit and the limiter slot, whatever happened.
        let _ = self.store.release_permit(row, &permit).await;
        if let Some(slot) = slot {
            slot.release();
        }
        let ambiguous = sent && writes;
        match exchanged {
            Ok(Ok(outcome)) => Ok(outcome),
            Ok(Err(failure)) => {
                if let Some(current) = sequence {
                    let _ = self
                        .journal_outcome_row(
                            row,
                            current,
                            if ambiguous {
                                "outcome_unknown"
                            } else {
                                "failed"
                            },
                            http_status,
                            started.elapsed(),
                            failure.reason.or(reason),
                            failure.error_excerpt.as_deref(),
                        )
                        .await;
                }
                Err(if ambiguous {
                    BrokerError::OutcomeUnknown
                } else {
                    BrokerError::Denied
                })
            }
            Err(_) => {
                if let Some(current) = sequence {
                    let _ = self
                        .journal_outcome_row(
                            row,
                            current,
                            if ambiguous {
                                "outcome_unknown"
                            } else {
                                "failed"
                            },
                            http_status,
                            started.elapsed(),
                            Some("timeout"),
                            None,
                        )
                        .await;
                }
                Err(if ambiguous {
                    BrokerError::OutcomeUnknown
                } else {
                    BrokerError::Denied
                })
            }
        }
    }

    // ── credentials ────────────────────────────────────────────────────────────────────────

    /// Resolve one profile credential and prove the licence authority agrees with the run
    /// (`client.py:172-183`).
    async fn identity(
        &self,
        row: &WorkerRow,
        profile: &CredentialProfile,
        reference: &CredentialReference,
    ) -> Result<String, BrokerError> {
        let tenant = row.run.tenant_id;
        let reference = resolver_reference(reference)?;
        let token = self
            .credentials
            .resolve(&tenant, &profile_id(profile)?, &reference)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let identity = self
            .licences
            .authenticate_for_app(&token, reference.app_key.as_str())
            .await
            .map_err(|_| BrokerError::Denied)?;
        if identity.tenant_id != tenant || identity.license_id != reference.license_id {
            return Err(BrokerError::Denied);
        }
        Ok(token)
    }

    /// The profile credential a licence-kind source needs, or `None` when it does not match
    /// (`client.py:109-124`). A `source`-adapter service carries no profile credential.
    fn licence_credential<'a>(
        profile: &'a CredentialProfile,
        service: &ServiceManifest,
        destination: &ResolvedSource,
    ) -> Option<&'a CredentialReference> {
        if service.auth_adapter == AuthAdapter::Source {
            return None;
        }
        let app_key = service.license_app_key.as_ref()?;
        let credential = profile
            .services
            .iter()
            .find(|candidate| candidate.service == service.service_key)?;
        let SourceAuth::Licence {
            app_key: source_app_key,
            scheme,
            ..
        } = &destination.auth
        else {
            return None;
        };
        if &credential.app_key != app_key
            || source_app_key.as_str() != app_key.as_str()
            || adapter_for(*scheme) != service.auth_adapter
        {
            return None;
        }
        Some(credential)
    }

    /// Mint the RUN's tenant licence for a licence-kind `source`-adapter service straight from
    /// the source row (`client.py:126-146`). Fails closed when the resolver cannot mint or the
    /// tenant lacks the grant.
    async fn source_licence(
        &self,
        row: &WorkerRow,
        service: &ServiceManifest,
        destination: &ResolvedSource,
    ) -> Result<(CredentialReference, String), BrokerError> {
        let SourceAuth::Licence {
            app_key, bundle, ..
        } = &destination.auth
        else {
            return Err(BrokerError::Denied);
        };
        if self.license_app_key.as_deref() == Some(app_key.as_str()) {
            return Err(BrokerError::Denied);
        }
        let tenant = row.run.tenant_id;
        let minted = self
            .credentials
            .mint(&tenant, app_key, bundle.as_deref())
            .await
            .map_err(|_| BrokerError::Denied)?;
        let identity = self
            .licences
            .authenticate_for_app(&minted.token, app_key)
            .await
            .map_err(|_| BrokerError::Denied)?;
        if identity.tenant_id != tenant || identity.license_id != minted.license_id {
            return Err(BrokerError::Denied);
        }
        let reference = CredentialReference {
            service: service.service_key.clone(),
            alias: service.service_key.clone(),
            license_id: AuthorityId::new(minted.license_id.to_string())
                .map_err(|_| BrokerError::Denied)?,
            app_key: AppKey::new(app_key.clone()).map_err(|_| BrokerError::Denied)?,
            bundle: bundle
                .as_deref()
                .map(AppKey::new)
                .transpose()
                .map_err(|_| BrokerError::Denied)?,
        };
        Ok((reference, minted.token))
    }

    /// Every mounted secret a response must never echo (`client.py:451-469`).
    ///
    /// The reference resolves them when the check first runs; this port resolves them once,
    /// before the exchange, so a failure is a denial before any I/O rather than after a
    /// response. Preflight already resolves each of them.
    async fn leaks(
        &self,
        row: &WorkerRow,
        profile: &CredentialProfile,
        mut secrets: Vec<String>,
    ) -> Result<Leaks, BrokerError> {
        let tenant = row.run.tenant_id;
        let profile_id = profile_id(profile)?;
        let mut oauth: Vec<String> = Vec::new();
        let mut references: Vec<&CredentialReference> = Vec::new();
        if self.gateway_credentials() {
            references.push(&profile.gateway);
        }
        references.extend(profile.services.iter());
        for reference in references {
            let reference = resolver_reference(reference)?;
            secrets.push(
                self.credentials
                    .resolve(&tenant, &profile_id, &reference)
                    .await
                    .map_err(|_| BrokerError::Denied)?,
            );
            let material = self
                .credentials
                .entry(&tenant, &profile_id, &reference)
                .await
                .map_err(|_| BrokerError::Denied)?;
            if let Some(material) = material.oauth_bearer {
                oauth.push(material);
            }
        }
        Ok(Leaks { secrets, oauth })
    }

    // ── catalog ────────────────────────────────────────────────────────────────────────────

    /// The source named by `service.destination_alias`, resolved for the service's owner (never
    /// by key alone), and the owner-scope rule for tenant tools (`client.py:103-107`).
    async fn destination(
        &self,
        operation: &OperationManifest,
        service: &ServiceManifest,
    ) -> Result<(AuthorityId, ResolvedSource), BrokerError> {
        let owner = self
            .catalog
            .service_owner(&operation.service.id)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let owner_id = Rfc4122Uuid::parse(owner.as_str()).ok_or(BrokerError::Denied)?;
        let source = self
            .sources
            .get(&owner_id, service.destination_alias.as_str())
            .await
            .map_err(|_| BrokerError::Denied)?;
        Ok((owner, source))
    }

    /// A service is callable by its owner, or by a tenant it is shared with (`client.py:185-190`).
    async fn usable(
        &self,
        tenant: &AuthorityId,
        owner: &AuthorityId,
        service_reference: &ExactReference,
    ) -> Result<bool, BrokerError> {
        if owner != &self.platform_tenant_id && owner != tenant {
            return Ok(false);
        }
        self.catalog
            .may_use_service(tenant, service_reference)
            .await
            .map_err(|_| BrokerError::Denied)
    }

    // ── transport ──────────────────────────────────────────────────────────────────────────

    /// Send one request through the destination's transport (`client.py:544-553`).
    async fn send(
        &self,
        destination: &ResolvedSource,
        request: reqwest::Request,
    ) -> Result<reqwest::Response, Failure> {
        let ca_file = destination.ca_file.as_deref().map(Path::new);
        if destination.tenant_owned {
            let (host, port) = endpoint(destination).map_err(Failure::resolution)?;
            let clients = self
                .pins
                .clients(&host, port, ca_file)
                .await
                .map_err(Failure::resolution)?;
            let mut last: Option<EgressError> = None;
            for (_, client) in clients {
                let Some(clone) = request.try_clone() else {
                    break;
                };
                match client.execute(clone).await {
                    Ok(response) => return Ok(response),
                    // A connection failure may be answered by the next validated address; a
                    // policy refusal never is, and neither is a failure after the request may
                    // have been sent — the retry loop owns that decision.
                    Err(EgressError::Transport) => last = Some(EgressError::Transport),
                    Err(EgressError::TransportSent) => {
                        return Err(Failure::transport("transport"));
                    }
                    Err(error) => return Err(Failure::refused(error)),
                }
            }
            Err(match last {
                Some(error) => Failure::refused(error),
                None => Failure::resolution(EgressError::Transport),
            })
        } else {
            let client = self
                .platform_http
                .client_for(ca_file)
                .map_err(Failure::resolution)?;
            client.execute(request).await.map_err(|error| {
                if error.is_timeout() {
                    Failure::transport("timeout")
                } else {
                    Failure::transport("transport")
                }
            })
        }
    }

    /// The pinned client a tenant-owned source's OAuth token fetch runs through.
    ///
    /// The reference reuses one tenant client for every host; reqwest pins one client per
    /// `(host, validated address)`, so this builds (and does not cache — the adapter caches the
    /// token) one pinned client for the token endpoint's own host.
    async fn pinned_tenant_client(&self, endpoint: &str) -> Result<reqwest::Client, BrokerError> {
        let url = Url::parse(endpoint).map_err(|_| BrokerError::Denied)?;
        let host = url.host_str().ok_or(BrokerError::Denied)?.to_owned();
        let port = url.port_or_known_default().ok_or(BrokerError::Denied)?;
        let addresses = self
            .egress
            .validated(&host, port)
            .await
            .map_err(|_| BrokerError::Denied)?;
        let address = *addresses.first().ok_or(BrokerError::Denied)?;
        tenant_client(&self.egress, Some(self.pool_limits()))
            .resolve(&host, address)
            .build()
            .map_err(|_| BrokerError::Denied)
    }

    // ── journalling ────────────────────────────────────────────────────────────────────────

    /// Finalize one journalled intent (`client.py:484-520`).
    ///
    /// The argument list is the reference's journal signature (row, sequence, status and the
    /// four trace fields); grouping them into a struct would only rename the same call.
    #[allow(clippy::too_many_arguments)]
    async fn journal_outcome_row(
        &self,
        row: &WorkerRow,
        sequence: i64,
        status: &str,
        http_status: Option<u16>,
        elapsed: Duration,
        reason: Option<&str>,
        error_excerpt: Option<&str>,
    ) -> Result<(), BrokerError> {
        let duration = i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX);
        self.store
            .journal_outcome(
                row,
                sequence,
                status,
                http_status.map(i32::from),
                Some(duration),
                reason,
                error_excerpt,
            )
            .await
            .map_err(|_| BrokerError::Denied)
    }

    /// Append the fixed `broker_denied` event under the fence (`client.py:332-340`). A stale
    /// controller cannot append events after losing its fence, so every failure is ignored.
    async fn note_denied(&self, row: &WorkerRow) {
        let Ok(worker) = row.worker() else {
            return;
        };
        let Ok(mut tx) = self.pool.begin().await else {
            return;
        };
        let owned = self
            .store
            .owned(&mut tx, &row.run.run_id, worker, row.fence, true)
            .await;
        if owned.is_ok()
            && self
                .store
                .event(&mut tx, row, "broker_denied")
                .await
                .is_ok()
        {
            let _ = tx.commit().await;
        }
    }

    // ── response framing ──────────────────────────────────────────────────────────────────

    /// Projected, redacted JSON of an expected-status response, or `None` when it is oversized,
    /// not JSON, not projectable, or carries credential material. Never an error
    /// (`client.py:192-207`).
    async fn error_body(
        &self,
        response: &mut reqwest::Response,
        operation: &OperationManifest,
        limit: u64,
        frame_limit: usize,
        leaks: &Leaks,
    ) -> Option<Value> {
        let mut data: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    data.extend_from_slice(&chunk);
                    if data.len() as u64 > limit {
                        return None;
                    }
                }
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        let raw: Value = serde_json::from_slice(&data).ok()?;
        let body = policy::project(operation, &raw).ok()?;
        let public = canonical_json(&body);
        if public.len() > frame_limit || leaks.contains(&public) {
            None
        } else {
            Some(body)
        }
    }

    /// The first 2 KB of a failed upstream answer, for an author's test run. Withheld when it
    /// carries credential material; never raises (`client.py:262-275`).
    async fn excerpt(response: &mut reqwest::Response, leaks: &Leaks) -> Option<String> {
        let mut data: Vec<u8> = Vec::new();
        loop {
            match response.chunk().await {
                Ok(Some(chunk)) => {
                    data.extend_from_slice(&chunk);
                    if data.len() >= EXCERPT_CHARS * 4 {
                        break;
                    }
                }
                Ok(None) => break,
                Err(_) => return None,
            }
        }
        let text = String::from_utf8_lossy(&data).replace('\0', "");
        let text = truncate(&text, EXCERPT_CHARS);
        Some(if leaks.contains(&text) {
            "[withheld: credential material]".to_owned()
        } else {
            text
        })
    }
}

/// The host-side read an `ownership_read` rule needs (`policy.py:32-34`).
///
/// The reference recurses through `Broker.call` with `ownership_reference`; this port recurses
/// through the same inner exchange, so a nested read is journalled, bounded and fenced exactly
/// like a top-level call. A nested denial is logged once, by the outermost call.
struct Ownership<'a> {
    broker: &'a Broker,
    row: &'a WorkerRow,
}

#[async_trait]
impl OwnershipRead for Ownership<'_> {
    async fn read(
        &self,
        reference: &ExactReference,
        arguments: &Map<String, Value>,
    ) -> Result<Value, PolicyError> {
        match self
            .broker
            .call_inner(
                self.row,
                reference.id.as_str(),
                arguments,
                None,
                Some(reference),
            )
            .await
        {
            Ok(CallOutcome::Value(value)) => Ok(value),
            // An expected status has no representation in the policy seam; the reference would
            // surface it as the outer call's result. Refusing is the fail-closed reading.
            Ok(CallOutcome::Expected { .. }) | Err(_) => Err(PolicyError::Denied),
        }
    }
}

/// Every secret a response must never echo.
struct Leaks {
    /// Credential strings: matched raw and in their JSON-escaped form.
    secrets: Vec<String>,
    /// Operator-provisioned OAuth bearers, matched raw only (as the reference does).
    oauth: Vec<String>,
}

impl Leaks {
    fn contains(&self, public: &str) -> bool {
        self.secrets
            .iter()
            .any(|secret| secret_matches(public, secret))
            || self
                .oauth
                .iter()
                .any(|secret| public.contains(secret.as_str()))
    }
}

/// Whether `public` carries `secret` or its encoded form (`client.py:460`).
fn secret_matches(public: &str, secret: &str) -> bool {
    !secret.is_empty()
        && (public.contains(secret) || public.contains(encoded_inner(secret).as_str()))
}

/// Python's `encoded(secret)[1:-1]`: the JSON-escaped body of a string literal.
fn encoded_inner(secret: &str) -> String {
    let encoded = canonical_json(&Value::String(secret.to_owned()));
    encoded
        .get(1..encoded.len().saturating_sub(1))
        .unwrap_or_default()
        .to_owned()
}

/// The exchange's total budget (`client.py:514-523`).
fn exchange_budget(
    settings: &WorkerSettings,
    operation: &OperationManifest,
    row: &WorkerRow,
) -> Duration {
    let mut budget =
        Duration::from_secs(u64::from(operation.timeout_seconds)).min(settings.api_timeout);
    if let Some(deadline) = row.deadline {
        let remaining = (deadline - Utc::now()).num_milliseconds().max(1);
        budget = budget.min(Duration::from_millis(u64::try_from(remaining).unwrap_or(1)));
    }
    budget
}

/// Build the upstream request from declared values only (`client.py:437-553`).
fn build_request(
    operation: &OperationManifest,
    destination: &ResolvedSource,
    path: &str,
    query: &HashMap<String, String>,
    headers: &HashMap<String, String>,
    payload: Option<String>,
) -> Result<reqwest::Request, BrokerError> {
    let url = format!("{}{}", destination.base_url.trim_end_matches('/'), path);
    let mut url = Url::parse(&url).map_err(|_| BrokerError::Denied)?;
    {
        let mut pairs = url.query_pairs_mut();
        let mut names: Vec<&String> = query.keys().collect();
        names.sort();
        for name in names {
            pairs.append_pair(name, &query[name]);
        }
    }
    let method = match operation.method {
        Method::Get => reqwest::Method::GET,
        Method::Post => reqwest::Method::POST,
        Method::Put => reqwest::Method::PUT,
        Method::Patch => reqwest::Method::PATCH,
        Method::Delete => reqwest::Method::DELETE,
    };
    let mut request = reqwest::Request::new(method, url);
    let mut map = reqwest::header::HeaderMap::new();
    let mut names: Vec<&String> = headers.keys().collect();
    names.sort();
    for name in names {
        let header = reqwest::header::HeaderName::from_bytes(name.as_bytes())
            .map_err(|_| BrokerError::Denied)?;
        let value = reqwest::header::HeaderValue::from_str(&headers[name])
            .map_err(|_| BrokerError::Denied)?;
        map.append(header, value);
    }
    *request.headers_mut() = map;
    request
        .timeout_mut()
        .replace(Duration::from_secs(u64::from(operation.timeout_seconds)));
    if let Some(payload) = payload {
        *request.body_mut() = Some(reqwest::Body::from(payload));
    }
    Ok(request)
}

/// The destination's `(host, port)`; a URL that cannot be read is refused before any I/O.
fn endpoint(source: &ResolvedSource) -> Result<(String, u16), EgressError> {
    let url = Url::parse(&source.base_url).map_err(|_| EgressError::SsrfBlocked)?;
    let host = url.host_str().ok_or(EgressError::SsrfBlocked)?.to_owned();
    let port = url
        .port_or_known_default()
        .ok_or(EgressError::SsrfBlocked)?;
    Ok((host, port))
}

fn pool_limits(settings: &WorkerSettings) -> PoolLimits {
    PoolLimits {
        max_connections: usize::try_from(settings.api_max_inflight).unwrap_or(8),
        ..PoolLimits::default()
    }
}

/// The run's tenant as an authority identity.
fn tenant_of(row: &WorkerRow) -> Result<AuthorityId, BrokerError> {
    AuthorityId::new(row.run.tenant_id.to_string()).map_err(|_| BrokerError::Denied)
}

/// The credential profile's identity.
fn profile_id(profile: &CredentialProfile) -> Result<Rfc4122Uuid, BrokerError> {
    Rfc4122Uuid::parse(profile.profile_id.as_str()).ok_or(BrokerError::Denied)
}

/// One profile credential in the resolver's own type.
fn resolver_reference(
    reference: &CredentialReference,
) -> Result<creds::CredentialReference, BrokerError> {
    Ok(creds::CredentialReference {
        service: reference.service.as_str().to_owned(),
        alias: reference.alias.as_str().to_owned(),
        license_id: Rfc4122Uuid::parse(reference.license_id.as_str()).ok_or(BrokerError::Denied)?,
        app_key: reference.app_key.as_str().to_owned(),
    })
}

/// The licence header scheme as the service manifest's adapter (`sources/models.py:45-57`).
fn adapter_for(scheme: LicenceScheme) -> AuthAdapter {
    match scheme {
        LicenceScheme::Bearer => AuthAdapter::LicenseBearer,
        LicenceScheme::XTenantIdBearer => AuthAdapter::LicenseHeader,
    }
}

fn effect_text(effect: Effect) -> &'static str {
    match effect {
        Effect::ReadOnly => "read_only",
        Effect::Writes => "writes",
    }
}

fn method_text(method: Method) -> &'static str {
    match method {
        Method::Get => "GET",
        Method::Post => "POST",
        Method::Put => "PUT",
        Method::Patch => "PATCH",
        Method::Delete => "DELETE",
    }
}

/// `[A-Za-z0-9_.:-]{1,128}` (`client.py:416`).
fn valid_idempotency_key(key: &str) -> bool {
    (1..=128).contains(&key.len())
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

/// A string map as a JSON object, for the reference's `encoded(...)` sizing.
fn object(values: &HashMap<String, String>) -> Value {
    let mut map = Map::new();
    for (name, value) in values {
        map.insert(name.clone(), Value::String(value.clone()));
    }
    Value::Object(map)
}

fn truncate(text: &str, limit: usize) -> String {
    text.chars().take(limit).collect()
}
