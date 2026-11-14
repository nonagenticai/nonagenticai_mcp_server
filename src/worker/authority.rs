//! The run's live authority, re-validated on every execution step.
//!
//! A run is accepted against a snapshot: the tool manifest, the effective selection and the
//! binding's bound context, stored as three JSON strings on `mcp_runs.authority`. Execution may
//! begin minutes later, and the world may have moved: the binding can be revoked, the tool
//! retired, the context changed, the credential profile rewritten. The reference's
//! `ExecutionService.live` answers exactly one question per call — *is the authority this run
//! was accepted under still the authority it has now?* — and this module ports it.
//!
//! Two properties are load-bearing:
//!
//! * The snapshot never widens. The intersection is `narrow_limits(snapshot, current)` plus the
//!   union of both operation-constraint lists, so a later narrowing takes effect immediately and
//!   a later widening never replaces what the run was accepted with.
//! * Nothing is cached. Every `live` re-reads the binding, the profile and the catalog, exactly
//!   as the reference does, because a revocation must stop the very next upstream call.

use chrono::Utc;
use serde_json::Value;
use sqlx::PgPool;

use crate::auth::Principal;
use crate::catalog::ids::{AuthorityId, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{Effect, ToolManifest, VersionDescriptor};
use crate::catalog::resolver::{CatalogResolver, ResolvedTool};
use crate::catalog::toolkit_models::{BoundContext, CredentialProfile, EffectiveTool};
use crate::execution::RunRow;
use crate::storage::bindings;
use crate::storage::catalog::CatalogRepository;
use crate::toolkits::resolver::narrow_limits;
use crate::worker::row::WorkerRow;
use crate::worker::store::{WorkerStore, WorkerStoreError};

/// Statuses a draft run may execute under (`service.py:33`).
const DRAFT_STATUSES: &[VersionStatus] = &[VersionStatus::Draft, VersionStatus::Published];

/// Why a run may not proceed under its authority.
///
/// Every variant is a denial for the caller: the broker refuses the call, the controller fails
/// or interrupts the run. No variant carries credential material or a schema detail.
#[derive(Debug)]
pub enum AuthorityError {
    /// The fence, the binding, the profile, the manifest or the wall clock refused the step.
    Denied,
    /// A worker-storage read or write failed.
    Storage(WorkerStoreError),
    /// A catalog or profile read failed, or its stored value could not be interpreted.
    Catalog(String),
}

impl std::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Denied => write!(f, "run authority denied"),
            Self::Storage(error) => write!(f, "run authority storage: {error}"),
            Self::Catalog(error) => write!(f, "run authority catalog: {error}"),
        }
    }
}

impl std::error::Error for AuthorityError {}

impl From<WorkerStoreError> for AuthorityError {
    fn from(error: WorkerStoreError) -> Self {
        Self::Storage(error)
    }
}

impl From<crate::storage::catalog::CatalogStoreError> for AuthorityError {
    fn from(error: crate::storage::catalog::CatalogStoreError) -> Self {
        Self::Catalog(error.to_string())
    }
}

impl From<sqlx::Error> for AuthorityError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(WorkerStoreError::Store(error))
    }
}

/// The run's snapshotted authority, rebuilt from the three stored JSON strings.
///
/// The members are strings, not objects: the reference stores pydantic `model_dump_json`
/// output and its worker calls `model_validate_json`. A nested object would be unreadable by
/// the Python worker, which is why the Rust API writes strings too.
pub fn resolved_snapshot(run: &RunRow) -> Result<ResolvedTool, AuthorityError> {
    let manifest: ToolManifest = serde_json::from_str(member_string(run, "manifest")?)
        .map_err(|_| AuthorityError::Denied)?;
    let effective: EffectiveTool = serde_json::from_str(member_string(run, "effective")?)
        .map_err(|_| AuthorityError::Denied)?;
    let context: BoundContext =
        serde_json::from_str(member_string(run, "context")?).map_err(|_| AuthorityError::Denied)?;
    Ok(ResolvedTool {
        manifest,
        effective,
        context,
    })
}

/// What one live check authorises: the effective selection the run must obey now, the credential
/// profile it resolves secrets from, and the snapshot it was accepted with.
#[derive(Debug, Clone)]
pub struct LiveAuthority {
    /// The snapshotted authority, rebuilt from the stored strings.
    pub resolved: ResolvedTool,
    /// The effective selection after narrowing (constraints unioned, limits intersected).
    pub effective: EffectiveTool,
    /// The credential profile, parsed from the run's own snapshot.
    pub profile: CredentialProfile,
}

/// The reference's `ExecutionService.live`: prove this worker still owns the run, then intersect
/// the snapshotted authority with the live one.
///
/// A draft run takes the draft path ([`live_draft`]); everything else re-checks the binding, the
/// profile snapshot, the live catalog and the wall clock.
pub async fn live(
    store: &WorkerStore,
    resolver: &CatalogResolver,
    row: &WorkerRow,
) -> Result<LiveAuthority, AuthorityError> {
    // The fence first: a stale worker learns nothing and writes nothing.
    fence_check(store, row).await?;

    if row.run.mode == "draft" {
        return live_draft(store, row).await;
    }

    let original = resolved_snapshot(&row.run)?;
    let tenant =
        AuthorityId::new(row.run.tenant_id.to_string()).map_err(|_| AuthorityError::Denied)?;
    let binding_id = Uuid7::new(
        row.run
            .binding_id
            .as_ref()
            .ok_or(AuthorityError::Denied)?
            .to_string(),
    )
    .map_err(|_| AuthorityError::Denied)?;
    let binding = bindings::inspect(store.pool(), &tenant, &binding_id).await?;
    // Context identity and profile identity are both part of the authority a run was accepted
    // under; a change to either invalidates work already in flight.
    if serde_json::to_string(&binding.spec.context).ok().as_deref()
        != row.run.authority.get("context").and_then(Value::as_str)
        || row
            .run
            .credential_profile_id
            .as_ref()
            .map(ToString::to_string)
            != Some(binding.spec.credential_profile_id.to_string())
    {
        return Err(AuthorityError::Denied);
    }
    let principal = Principal {
        tenant_id: row.run.tenant_id,
        license_id: row.run.gateway_license_id,
        subject: "execution-worker".to_owned(),
        binding_id: row.run.binding_id,
        binding_revision: Some(i64::from(binding.revision.get())),
        management: false,
        platform: false,
    };
    let current = resolver
        .resolve(&principal)
        .await
        .map_err(|_| AuthorityError::Denied)?
        .into_iter()
        .find(|candidate| candidate.effective.tool == original.effective.tool)
        .ok_or(AuthorityError::Denied)?;
    if serde_json::to_string(&current.manifest).ok().as_deref()
        != Some(member_string(&row.run, "manifest")?)
    {
        return Err(AuthorityError::Denied);
    }
    // The profile must be identical to the one the run was accepted with.
    let stored: Option<Value> = sqlx::query_scalar(
        "SELECT manifest FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(row.run.tenant_id.to_string())
    .bind(
        row.run
            .credential_profile_id
            .as_ref()
            .ok_or(AuthorityError::Denied)?
            .to_string(),
    )
    .fetch_optional(store.pool())
    .await
    .map_err(|_| AuthorityError::Denied)?;
    if stored.as_ref() != Some(&row.run.profile_snapshot) {
        return Err(AuthorityError::Denied);
    }
    let effective = intersect(&original, &current);
    wall_clock(&row.run, effective.limits.wall_seconds)?;
    let profile: CredentialProfile = serde_json::from_value(row.run.profile_snapshot.clone())
        .map_err(|_| AuthorityError::Denied)?;
    Ok(LiveAuthority {
        resolved: original,
        effective,
        profile,
    })
}

/// The draft analogue of [`live`]: no binding and no stored profile, but the author's CURRENT
/// tool version must be unchanged, still runnable, still owned by the run's tenant, and every
/// dependency must still be usable by it.
pub async fn live_draft(
    store: &WorkerStore,
    row: &WorkerRow,
) -> Result<LiveAuthority, AuthorityError> {
    fence_check(store, row).await?;

    let run = &row.run;
    if run.owner_tenant_id != run.tenant_id {
        return Err(AuthorityError::Denied);
    }
    let original = resolved_snapshot(run)?;
    let catalog = CatalogRepository::new(store.pool().clone());
    let tenant = AuthorityId::new(run.tenant_id.to_string()).map_err(|_| AuthorityError::Denied)?;
    let descriptor = catalog
        .get_version(
            &tenant,
            &Uuid7::new(run.tool_id.to_string()).map_err(|_| AuthorityError::Denied)?,
            PositiveVersion::new(
                u64::try_from(run.tool_version).map_err(|_| AuthorityError::Denied)?,
            )
            .map_err(|_| AuthorityError::Denied)?,
        )
        .await
        .map_err(|_| AuthorityError::Denied)?;
    if !DRAFT_STATUSES.contains(&descriptor.status)
        || retired(store.pool(), run).await?
        || serde_json::to_string(&descriptor.manifest).ok().as_deref()
            != Some(member_string(run, "manifest")?)
    {
        return Err(AuthorityError::Denied);
    }
    draft_dependencies(&catalog, &tenant, &descriptor).await?;
    wall_clock(run, original.effective.limits.wall_seconds)?;
    let profile: CredentialProfile =
        serde_json::from_value(run.profile_snapshot.clone()).map_err(|_| AuthorityError::Denied)?;
    let effective = original.effective.clone();
    Ok(LiveAuthority {
        resolved: original,
        effective,
        profile,
    })
}

/// `_draft_dependencies`: every operation and service the tool names must be usable by this
/// tenant now — its own draft or published ones, or published platform services it may use.
/// Returns whether any operation writes (the draft run's confirmation rule, phase 5).
pub async fn draft_dependencies(
    catalog: &CatalogRepository,
    tenant: &AuthorityId,
    descriptor: &VersionDescriptor,
) -> Result<bool, AuthorityError> {
    let mut writes = false;
    for reference in &descriptor.manifest.allowed_operations {
        let (operation, status) = catalog
            .operation(reference)
            .await
            .map_err(|_| AuthorityError::Denied)?;
        let (service, service_status) = catalog
            .service(&operation.service)
            .await
            .map_err(|_| AuthorityError::Denied)?;
        let owner = catalog
            .service_owner(&service.service_id)
            .await
            .map_err(|_| AuthorityError::Denied)?;
        let allowed = if owner != *tenant {
            status == VersionStatus::Published && service_status == VersionStatus::Published
        } else {
            DRAFT_STATUSES.contains(&status) && DRAFT_STATUSES.contains(&service_status)
        };
        if !allowed
            || !catalog
                .may_use_service(tenant, &operation.service)
                .await
                .map_err(|_| AuthorityError::Denied)?
        {
            return Err(AuthorityError::Denied);
        }
        writes |= operation.effect == Effect::Writes;
    }
    Ok(writes)
}

/// The fence, proved in its own short transaction: a stale worker learns nothing.
async fn fence_check(store: &WorkerStore, row: &WorkerRow) -> Result<(), AuthorityError> {
    let mut tx = store.pool().begin().await?;
    store
        .owned(&mut tx, &row.run.run_id, row.worker()?, row.fence, false)
        .await?;
    tx.commit().await?;
    Ok(())
}

/// The intersection the run must obey now: the union of both constraint lists and the
/// narrowest limit for every field.
fn intersect(original: &ResolvedTool, current: &ResolvedTool) -> EffectiveTool {
    let mut effective = original.effective.clone();
    effective
        .operation_constraints
        .extend(current.effective.operation_constraints.iter().cloned());
    effective.limits = narrow_limits(original.effective.limits, current.effective.limits);
    effective
}

/// A later narrowing of the time allowance takes effect immediately.
fn wall_clock(run: &RunRow, wall_seconds: u32) -> Result<(), AuthorityError> {
    if let Some(started) = run.started_at {
        let elapsed = Utc::now().signed_duration_since(started).num_seconds();
        if elapsed > i64::from(wall_seconds) {
            return Err(AuthorityError::Denied);
        }
    }
    Ok(())
}

async fn retired(pool: &PgPool, run: &RunRow) -> Result<bool, AuthorityError> {
    let retired: Option<bool> = sqlx::query_scalar(
        "SELECT retired FROM public.mcp_tools WHERE tenant_id = $1::uuid AND tool_id = $2::uuid",
    )
    .bind(run.tenant_id.to_string())
    .bind(run.tool_id.to_string())
    .fetch_optional(pool)
    .await
    .map_err(|_| AuthorityError::Denied)?;
    Ok(retired != Some(false))
}

fn member_string<'a>(run: &'a RunRow, name: &str) -> Result<&'a str, AuthorityError> {
    run.authority
        .get(name)
        .and_then(Value::as_str)
        .ok_or(AuthorityError::Denied)
}
