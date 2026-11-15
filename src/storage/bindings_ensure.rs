//! `POST /mcp/internal/tenants/{t}/bindings/ensure`: one binding per (tenant, product).
//!
//! Ported behaviour-for-behaviour from the reference `src/storage/bindings_ensure.py`. A
//! product's provisioning (the agent, care-bus approval) calls the route with a Keycloak
//! service JWT and the tenant's mcp licence it holds (`licence_id` plus `licence_token`). The
//! token is introspected: it must be the path tenant's tenant-level mcp licence with exactly
//! that id, or nothing is written. mcp never mints its own (`app=mcp`) licence.
//!
//! The product → toolkit-name table is declarative ([`crate::config::BindingEnsureSettings`]).
//! Each named toolkit resolves to the **platform tenant's** latest published version (first-party
//! toolkits are platform-owned) and is pinned in the binding; a toolkit the platform has not
//! published, or whose backend credentials cannot be established, is skipped **with a reason**.
//! Backend credential references carry the product's licences bundle so the minter never meets
//! `ambiguous_bundle`.
//!
//! Everything is written in ONE transaction serialized on the (tenant, product) ensure row,
//! which records the binding's product: the credential profile (gateway = the tenant's mcp
//! licence, services = the backend licences the selected tools need), the binding, the ensure
//! row and an access event. The binding token is returned **only** when it is issued (create, or
//! an explicit rotate); PostgreSQL stores its digest only. A re-ensure reports
//! `token_already_issued` and never returns the token again.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::sync::Arc;

use chrono::{DateTime, Duration, SecondsFormat, Utc};
use serde::Serialize;
use serde_json::{Value, json};
use sqlx::error::DatabaseError as _;
use sqlx::postgres::PgRow;
use sqlx::{PgConnection, PgPool, Row};

use crate::auth::BoxFuture;
use crate::auth::error::AuthError;
use crate::auth::licenses::LicenceAuthority;
use crate::auth::uuid::Rfc4122Uuid;
use crate::catalog::ids::{AppKey, AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::models::{Attribution, ToolLimits};
use crate::catalog::toolkit_models::{
    BindingSpec, BoundContext, CredentialProfile, CredentialReference, ToolkitReference,
};
use crate::config::BindingEnsureSettings;
use crate::storage::bindings;
use crate::storage::catalog::CatalogStoreError;
use crate::toolkits::resolver::SelectionResolver;
use crate::toolkits::service::{ToolkitService, ToolkitServiceError};
use crate::worker::creds::{CredentialError, Minter};

/// The platform has not published a version of this toolkit name.
pub const NOT_PUBLISHED: &str = "not_published";
/// A tenant toolkit would displace a tool an already-selected toolkit provides.
pub const NAME_COLLISION: &str = "tool_name_collision";
/// The backend licence behind the toolkit's services could not be established.
pub const CREDENTIALS_UNAVAILABLE: &str = "service_credentials_unavailable";
/// The gateway credential's service key.
pub const GATEWAY_SERVICE: &str = "gateway";

/// Binding-level ceiling: tool manifests (and their selections) narrow below it. The reference's
/// `MAX_LIMITS`, whose `memory_mi`/`cpu_millicores` are the model defaults.
pub const MAX_LIMITS: ToolLimits = ToolLimits {
    wall_seconds: 300,
    queue_seconds: 240,
    memory_mi: 256,
    cpu_millicores: 250,
    api_calls: 100,
    frame_bytes: 262_144,
    output_bytes: 1_048_576,
};

/// The credential-profile name one product's ensure owns: `ensure_<product with _ for ->`.
pub fn profile_name(product: &str) -> String {
    format!("ensure_{}", product.replace('-', "_"))
}

/// The actor a product's ensure is attributed to: `service:<azp>`, bounded to 256 characters.
pub fn actor_for(azp: &str, licence: &AuthorityId) -> Attribution {
    Attribution {
        subject: format!("service:{azp}").chars().take(256).collect(),
        license_id: Some(licence.clone()),
    }
}

/// Why a binding ensure was refused. Every message is the reference's exact string (the HTTP
/// body is the route's `{"error": …}`, so messages are for logs, never the caller).
#[derive(Debug, thiserror::Error)]
pub enum EnsureError {
    /// The reference's `PermissionError`: the licence or the tenant may not be provisioned.
    #[error("{0}")]
    Forbidden(&'static str),
    /// The reference's `CatalogNotFoundError`: no such product.
    #[error("{0}")]
    NotFound(&'static str),
    /// The reference's `CatalogConflictError`: the ensure row/profile could not be written.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `ValueError` for a request-level violation.
    #[error("{0}")]
    Invalid(&'static str),
    /// The reference's `AuthorityUnavailableError`: the licence authority cannot answer.
    #[error("{0}")]
    Unavailable(&'static str),
    /// A stored row no longer satisfies the domain model (schema drift, not a request error).
    #[error("stored binding-ensure row is invalid: {0}")]
    Corrupt(&'static str),
    /// The database refused or failed a statement.
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    /// A catalog read/write failure.
    #[error(transparent)]
    Store(#[from] CatalogStoreError),
    /// A profile/binding write failure.
    #[error(transparent)]
    Toolkit(#[from] ToolkitServiceError),
}

/// Why the minter could not name the tenant's licence for one backend application.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum LicenceLookupError {
    /// The reference's `MinterUnavailableError`: the authority cannot answer; fail closed (503).
    #[error("licence authority unavailable")]
    Unavailable,
    /// The reference's `ExecutionDeniedError`: no licence for this tenant/app; skip the toolkit.
    #[error("licence denied")]
    Denied,
}

/// The backend-licence lookup ensure needs: the reference's `Minter.licence_id`.
pub trait LicenceLookup: Send + Sync {
    fn licence_id<'a>(
        &'a self,
        tenant: &'a Rfc4122Uuid,
        app: &'a str,
        bundle: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Rfc4122Uuid, LicenceLookupError>>;
}

impl LicenceLookup for Minter {
    fn licence_id<'a>(
        &'a self,
        tenant: &'a Rfc4122Uuid,
        app: &'a str,
        bundle: Option<&'a str>,
    ) -> BoxFuture<'a, Result<Rfc4122Uuid, LicenceLookupError>> {
        Box::pin(async move {
            Minter::licence_id(self, tenant, app, bundle)
                .await
                .map_err(|error| match error {
                    CredentialError::Unavailable(_) => LicenceLookupError::Unavailable,
                    CredentialError::Denied(_) => LicenceLookupError::Denied,
                })
        })
    }
}

/// One toolkit the ensure pinned, exactly as the ensure row records it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EnsuredToolkit {
    /// The configured name the product asked for.
    pub name: String,
    /// The toolkit's owner (the platform tenant, or the tenant for its own toolkit).
    pub tenant_id: AuthorityId,
    /// The toolkit identity.
    pub toolkit_id: Uuid7,
    /// The pinned version.
    pub version: PositiveVersion,
}

/// One toolkit left out of the binding, with the reason the reference reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SkippedToolkit {
    /// The configured name (or the tenant's own toolkit name).
    pub toolkit: String,
    /// [`NOT_PUBLISHED`], [`NAME_COLLISION`] or [`CREDENTIALS_UNAVAILABLE`].
    pub reason: &'static str,
}

/// What one ensure wrote and — only when it was issued — the one plaintext binding token.
///
/// `Debug` is written by hand: a stray `?result` must never print the token.
#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct EnsureResult {
    /// The (tenant, product) ensure identity.
    pub ensure_id: Uuid7,
    /// The provisioned tenant.
    pub tenant_id: AuthorityId,
    /// The product.
    pub product: String,
    /// `pending`, `unchanged`, `created`, `updated` or `rotated`.
    pub status: &'static str,
    /// The binding the ensure row records, when one exists.
    pub binding_id: Option<Uuid7>,
    /// The binding's revision after the write.
    pub binding_revision: Option<PositiveVersion>,
    /// The gateway licence the binding serves.
    pub gateway_license_id: AuthorityId,
    /// The binding's expiry (RFC 3339), when one exists.
    pub expires_at: Option<String>,
    /// The pinned toolkits.
    pub toolkits: Vec<EnsuredToolkit>,
    /// The toolkits left out, with reasons.
    pub skipped: Vec<SkippedToolkit>,
    /// Whether the binding exists and its token was NOT issued by this call.
    pub token_already_issued: bool,
    /// The one plaintext token; present only when this call issued it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token: Option<String>,
}

impl fmt::Debug for EnsureResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EnsureResult")
            .field("ensure_id", &self.ensure_id)
            .field("tenant_id", &self.tenant_id)
            .field("product", &self.product)
            .field("status", &self.status)
            .field("binding_id", &self.binding_id)
            .field("binding_revision", &self.binding_revision)
            .field("gateway_license_id", &self.gateway_license_id)
            .field("expires_at", &self.expires_at)
            .field("toolkits", &self.toolkits)
            .field("skipped", &self.skipped)
            .field("token_already_issued", &self.token_already_issued)
            .field("token", &self.token.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

/// One product's re-bind outcome: exactly one entry of the reference's `rebind` report.
///
/// The report never carries a binding token: a re-bind re-provisions an existing binding and
/// the reference's report entry keeps only the status, revision, toolkits and skips.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebindEntry {
    /// The product is no longer configured; its binding is left untouched.
    UnknownProduct {
        /// The ensure row's product.
        product: String,
    },
    /// The binding was provisioned for a different gateway licence and can never authenticate
    /// under this one; bindings/ensure owns it.
    LicenceChanged {
        /// The ensure row's product.
        product: String,
    },
    /// The ensure ran; `status` is its result (`created`, `updated`, `unchanged`, `pending` or
    /// `rotated`) and the binding now pins `toolkits`.
    Rebound {
        /// The ensure row's product.
        product: String,
        /// The ensure's status word.
        status: &'static str,
        /// The binding's revision after the write, when one exists.
        binding_revision: Option<PositiveVersion>,
        /// The toolkit pins now in the binding.
        toolkits: Vec<EnsuredToolkit>,
        /// The toolkits left out, with reasons.
        skipped: Vec<SkippedToolkit>,
    },
}

impl RebindEntry {
    /// The entry exactly as the reference's report serializes it. `binding_revision` is present
    /// even when null for a re-bound product; the two refusal statuses carry only their product.
    pub fn as_json(&self) -> Value {
        match self {
            Self::UnknownProduct { product } => {
                json!({"product": product, "status": "unknown_product"})
            }
            Self::LicenceChanged { product } => {
                json!({"product": product, "status": "licence_changed"})
            }
            Self::Rebound {
                product,
                status,
                binding_revision,
                toolkits,
                skipped,
            } => json!({
                "product": product,
                "status": status,
                "binding_revision": binding_revision,
                "toolkits": toolkits,
                "skipped": skipped,
            }),
        }
    }
}

impl Serialize for RebindEntry {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.as_json().serialize(serializer)
    }
}

/// The `bindings` field the reference's toolkit publish answers when the re-bind that follows
/// it fails (`builder/service.py:745-757`): the publication is already committed and is never
/// undone, only the error's TYPE is logged, and the caller is told to bind again.
pub fn rebind_failed_report() -> Value {
    json!({"error": "rebind_failed", "detail": "call toolkit bind again"})
}

/// The reference's `except UniqueViolation` boundary around one product's ensure write.
fn product_conflict(error: EnsureError) -> EnsureError {
    match error {
        EnsureError::Database(sqlx::Error::Database(database))
            if database.code().as_deref() == Some("23505") =>
        {
            EnsureError::Conflict("ensure profile name is already in use")
        }
        other => other,
    }
}

/// One candidate name (a product name or the tenant's own toolkit), its latest published
/// version when there is one, and the tenant that owns it.
#[derive(Debug, Clone)]
struct Candidate {
    name: String,
    published: Option<(Uuid7, PositiveVersion)>,
    owner: AuthorityId,
}

/// One toolkit resolved from the platform's (or the tenant's) published versions.
#[derive(Debug, Clone)]
struct ResolvedToolkit {
    name: String,
    tenant_id: AuthorityId,
    toolkit_id: Uuid7,
    version: PositiveVersion,
    /// `manifest->>'service_key'` → `manifest->>'license_app_key'`, source adapters excluded.
    services: BTreeMap<String, Option<String>>,
}

/// One `mcp_binding_ensures` row as the write path reads it.
#[derive(Debug, Clone)]
struct EnsureRow {
    ensure_id: Uuid7,
    revision: i64,
    gateway_license_id: Option<AuthorityId>,
    credential_profile_id: Option<Uuid7>,
    binding_id: Option<Uuid7>,
    token_issued_at: Option<DateTime<Utc>>,
}

/// The product binding-provisioning service. One pool, one resolver, the configured gateway
/// application key, the licence authority and (when minting is enabled) the minter.
pub struct BindingEnsureService {
    pool: PgPool,
    resolver: SelectionResolver,
    license_app_key: Option<String>,
    licences: Arc<dyn LicenceAuthority>,
    minter: Option<Arc<dyn LicenceLookup>>,
    products: BTreeMap<String, Vec<String>>,
    bundles: BTreeMap<String, String>,
    ttl_days: u64,
    platform_tenant_id: AuthorityId,
}

impl fmt::Debug for BindingEnsureService {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BindingEnsureService")
            .field("products", &self.products)
            .field("bundles", &self.bundles)
            .field("ttl_days", &self.ttl_days)
            .field("platform_tenant_id", &self.platform_tenant_id)
            .field(
                "license_app_key",
                &self.license_app_key.as_ref().map(|_| "<configured>"),
            )
            .field("minter", &self.minter.is_some())
            .finish()
    }
}

impl BindingEnsureService {
    /// Bind the service to the database, the exact-selection resolver, the configured gateway
    /// application key, the licence authority, the optional minter, the product table and the
    /// reserved platform tenant.
    pub fn new(
        pool: PgPool,
        resolver: SelectionResolver,
        license_app_key: Option<String>,
        licences: Arc<dyn LicenceAuthority>,
        minter: Option<Arc<dyn LicenceLookup>>,
        settings: &BindingEnsureSettings,
        platform_tenant_id: AuthorityId,
    ) -> Self {
        Self {
            pool,
            resolver,
            license_app_key,
            licences,
            minter,
            products: settings.products.clone(),
            bundles: settings.bundles.clone(),
            ttl_days: settings.ttl_days,
            platform_tenant_id,
        }
    }

    /// The product's configured platform toolkit names, `None` for an unknown product.
    pub fn product_toolkits(&self, product: &str) -> Option<&[String]> {
        self.products.get(product).map(Vec::as_slice)
    }

    /// Provision the one binding of `product` for `tenant`.
    ///
    /// The licence is introspected first (nothing is written when it fails), the platform's
    /// published toolkits are resolved and their backend licences established outside the
    /// transaction, then everything is written in one transaction serialized on the ensure row.
    pub async fn ensure(
        &self,
        tenant: &AuthorityId,
        product: &str,
        azp: &str,
        licence_id: &AuthorityId,
        licence_token: &str,
        rotate: bool,
    ) -> Result<EnsureResult, EnsureError> {
        let Some(names) = self.products.get(product) else {
            return Err(EnsureError::NotFound("unknown product"));
        };
        if *tenant == self.platform_tenant_id {
            return Err(EnsureError::Forbidden(
                "the platform tenant is not provisioned through a product",
            ));
        }
        let gateway = self
            .gateway_licence(tenant, licence_id, licence_token)
            .await?;
        let (resolved, mut skipped) = {
            let mut connection = self.pool.acquire().await?;
            self.discover(&mut connection, names, Some(tenant)).await?
        };
        // The reference reads `settings.product_bundles[product]`; startup validation guarantees
        // an entry, and a missing one here is a wiring fault, never a caller error.
        let Some(bundle) = self.bundles.get(product) else {
            return Err(EnsureError::Unavailable(
                "every product needs a licences bundle key",
            ));
        };
        let (resolved, services) = self
            .service_references(tenant, resolved, &mut skipped, Some(bundle))
            .await?;
        let actor = actor_for(azp, &gateway);
        let mut transaction = self.pool.begin().await?;
        let result = self
            .write(
                &mut transaction,
                tenant,
                product,
                &actor,
                &gateway,
                &resolved,
                &services,
                &skipped,
                rotate,
            )
            .await?;
        transaction.commit().await?;
        Ok(result)
    }

    /// The reference's `rebind` (`bindings_ensure.py:239-288`): re-provision the tenant's
    /// EXISTING product bindings with its current toolkits — each product's configured platform
    /// toolkits plus the tenant's own published ones, at their newest published versions. No
    /// token is issued or returned: a binding is updated only when it was provisioned for
    /// `gateway` (the caller's own tenant-level mcp licence); otherwise it is reported
    /// `licence_changed` and left to bindings/ensure.
    ///
    /// The order is the reference's: every ensure row with a binding, optionally for one
    /// product, ordered by product; then per product the same discovery, licence references and
    /// one-transaction write `ensure` runs, with `rotate` false. Each product's write is its own
    /// transaction, so an error raised here leaves every earlier product written exactly as the
    /// reference does. Nothing here touches a toolkit version, so a failure can never undo the
    /// publication that prompted the call: the caller reports [`rebind_failed_report`].
    pub async fn rebind(
        &self,
        tenant: &AuthorityId,
        actor: &Attribution,
        gateway: &AuthorityId,
        product: Option<&str>,
    ) -> Result<Vec<RebindEntry>, EnsureError> {
        if *tenant == self.platform_tenant_id {
            return Err(EnsureError::Forbidden(
                "the platform tenant is not provisioned through a product",
            ));
        }
        let rows = sqlx::query(
            "SELECT product, gateway_license_id::text AS gateway_license_id \
             FROM public.mcp_binding_ensures \
             WHERE tenant_id = $1::uuid AND binding_id IS NOT NULL \
             AND ($2::text IS NULL OR product = $2) ORDER BY product",
        )
        .bind(tenant.as_str())
        .bind(product)
        .fetch_all(&self.pool)
        .await?;
        let mut report = Vec::with_capacity(rows.len());
        for row in rows {
            let name: String = row.try_get("product")?;
            let bound_gateway: Option<String> = row.try_get("gateway_license_id")?;
            let Some(names) = self.products.get(&name) else {
                report.push(RebindEntry::UnknownProduct { product: name });
                continue;
            };
            if bound_gateway.as_deref() != Some(gateway.as_str()) {
                report.push(RebindEntry::LicenceChanged { product: name });
                continue;
            }
            let names = names.clone();
            let (resolved, mut skipped) = {
                let mut connection = self.pool.acquire().await?;
                self.discover(&mut connection, &names, Some(tenant)).await?
            };
            let Some(bundle) = self.bundles.get(&name) else {
                return Err(EnsureError::Unavailable(
                    "every product needs a licences bundle key",
                ));
            };
            let bundle = bundle.clone();
            let (resolved, services) = self
                .service_references(tenant, resolved, &mut skipped, Some(bundle.as_str()))
                .await?;
            let mut transaction = self.pool.begin().await?;
            let result = self
                .write(
                    &mut transaction,
                    tenant,
                    &name,
                    actor,
                    gateway,
                    &resolved,
                    &services,
                    &skipped,
                    false,
                )
                .await
                .map_err(product_conflict)?;
            transaction.commit().await?;
            report.push(RebindEntry::Rebound {
                product: name,
                status: result.status,
                binding_revision: result.binding_revision,
                toolkits: result.toolkits,
                skipped: result.skipped,
            });
        }
        Ok(report)
    }

    /// The reference's `gateway_licence`: the product-held mcp licence, verified by
    /// introspection; fails closed.
    ///
    /// It must authenticate for the mcp application as the path tenant's tenant-level
    /// (`subject_kind: tenant`) licence whose id is `licence_id`.
    async fn gateway_licence(
        &self,
        tenant: &AuthorityId,
        licence_id: &AuthorityId,
        licence_token: &str,
    ) -> Result<AuthorityId, EnsureError> {
        let Some(app) = self.license_app_key.as_deref() else {
            return Err(EnsureError::Unavailable(
                "license authentication is not configured",
            ));
        };
        let identity = match self.licences.authenticate_for_app(licence_token, app).await {
            Ok(identity) => identity,
            Err(AuthError::Unauthorized) => {
                return Err(EnsureError::Forbidden(
                    "the mcp licence did not authenticate",
                ));
            }
            Err(_) => return Err(EnsureError::Unavailable("licence authority unavailable")),
        };
        // Compared as canonical strings: both sides are validated identities, and the niche
        // nil-version UUID an `AuthorityId` accepts must compare, not fail to parse.
        if identity.tenant_id.to_string() != tenant.as_str()
            || !identity.tenant_level()
            || identity.license_id.to_string() != licence_id.as_str()
        {
            return Err(EnsureError::Forbidden(
                "the licence is not this tenant's tenant-level mcp licence",
            ));
        }
        AuthorityId::new(identity.license_id.to_string())
            .map_err(|_| EnsureError::Corrupt("licence identity"))
    }

    /// The reference's `discover`: the latest published toolkit version per name, with the
    /// backend services behind it.
    ///
    /// First-party toolkits are the platform tenant's, looked up by the product's names. With
    /// `tenant`, every toolkit that tenant authored and published is added too, so a caller
    /// keeps ONE binding per product.
    async fn discover(
        &self,
        conn: &mut PgConnection,
        names: &[String],
        tenant: Option<&AuthorityId>,
    ) -> Result<(Vec<ResolvedToolkit>, Vec<SkippedToolkit>), EnsureError> {
        let platform = &self.platform_tenant_id;
        let wanted: Vec<String> = names.to_vec();
        let rows = sqlx::query(
            "SELECT t.name, v.toolkit_id::text AS toolkit_id, max(v.version) AS version \
             FROM public.mcp_toolkits t \
             JOIN public.mcp_toolkit_versions v USING(tenant_id,toolkit_id) \
             WHERE t.tenant_id = $1::uuid AND t.name = ANY($2::text[]) AND v.status='published' \
             GROUP BY t.name,v.toolkit_id",
        )
        .bind(platform.as_str())
        .bind(&wanted)
        .fetch_all(&mut *conn)
        .await?;
        let mut found: HashMap<String, (Uuid7, PositiveVersion)> = HashMap::new();
        for row in rows {
            let name: String = row.try_get("name")?;
            found.insert(name, decoded_version(&row)?);
        }
        let mut own: Vec<(String, (Uuid7, PositiveVersion))> = Vec::new();
        if let Some(tenant) = tenant
            && tenant != platform
        {
            let rows = sqlx::query(
                "SELECT t.name, v.toolkit_id::text AS toolkit_id, max(v.version) AS version \
                 FROM public.mcp_toolkits t \
                 JOIN public.mcp_toolkit_versions v USING(tenant_id,toolkit_id) \
                 WHERE t.tenant_id = $1::uuid AND v.status='published' \
                 GROUP BY t.name,v.toolkit_id ORDER BY t.name",
            )
            .bind(tenant.as_str())
            .fetch_all(&mut *conn)
            .await?;
            for row in rows {
                let name: String = row.try_get("name")?;
                own.push((name, decoded_version(&row)?));
            }
        }
        let mut candidates: Vec<Candidate> = Vec::new();
        for name in names {
            candidates.push(Candidate {
                name: name.clone(),
                published: found.get(name).cloned(),
                owner: platform.clone(),
            });
        }
        for (name, published) in &own {
            let owner = tenant
                .cloned()
                .ok_or(EnsureError::Corrupt("tenant identity"))?;
            candidates.push(Candidate {
                name: name.clone(),
                published: Some(published.clone()),
                owner,
            });
        }
        let mut resolved: Vec<ResolvedToolkit> = Vec::new();
        let mut skipped: Vec<SkippedToolkit> = Vec::new();
        let mut taken: HashMap<String, (AuthorityId, Uuid7)> = HashMap::new();
        for Candidate {
            name,
            published,
            owner,
        } in candidates
        {
            let Some((toolkit_id, version)) = published else {
                skipped.push(SkippedToolkit {
                    toolkit: name,
                    reason: NOT_PUBLISHED,
                });
                continue;
            };
            let rows = sqlx::query(
                "SELECT public_name,owner_tenant_id::text AS owner_tenant_id,\
                 tool_id::text AS tool_id FROM public.mcp_toolkit_version_tools \
                 WHERE tenant_id=$1::uuid AND toolkit_id=$2::uuid AND version=$3",
            )
            .bind(owner.as_str())
            .bind(toolkit_id.as_str())
            .bind(version_bits(version))
            .fetch_all(&mut *conn)
            .await?;
            let mut names_in: Vec<(String, (AuthorityId, Uuid7))> = Vec::new();
            for row in rows {
                let public_name: String = row.try_get("public_name")?;
                let owner_tenant_id =
                    AuthorityId::new(row.try_get::<String, _>("owner_tenant_id")?)
                        .map_err(|_| EnsureError::Corrupt("tool owner"))?;
                let tool_id = Uuid7::new(row.try_get::<String, _>("tool_id")?)
                    .map_err(|_| EnsureError::Corrupt("tool identity"))?;
                names_in.push((public_name, (owner_tenant_id, tool_id)));
            }
            if owner != *platform
                && names_in
                    .iter()
                    .any(|(name, who)| taken.get(name).is_some_and(|held| held != who))
            {
                // A tenant toolkit never displaces a tool already selected (or breaks the
                // binding): it is reported and left out until the names differ.
                skipped.push(SkippedToolkit {
                    toolkit: name,
                    reason: NAME_COLLISION,
                });
                continue;
            }
            for (name, who) in &names_in {
                taken.insert(name.clone(), who.clone());
            }
            let rows = sqlx::query(
                "SELECT DISTINCT s.manifest->>'service_key' AS service,\
                 s.manifest->>'license_app_key' AS app \
                 FROM public.mcp_toolkit_versions tv \
                 CROSS JOIN LATERAL jsonb_array_elements(tv.tools) e \
                 JOIN public.mcp_tool_version_operations r \
                   ON r.tenant_id=(e->'tool'->>'tenant_id')::uuid \
                   AND r.tool_id=(e->'tool'->>'id')::uuid \
                   AND r.version=(e->'tool'->>'version')::integer \
                 JOIN public.mcp_operation_versions o \
                   ON (o.operation_id,o.version)=(r.operation_id,r.operation_version) \
                 JOIN public.mcp_service_versions s \
                   ON (s.service_id,s.version)=(o.service_id,o.service_version) \
                 WHERE tv.tenant_id=$1::uuid AND tv.toolkit_id=$2::uuid AND tv.version=$3 \
                   AND s.manifest->>'auth_adapter' IS DISTINCT FROM 'source' ORDER BY 1",
            )
            .bind(owner.as_str())
            .bind(toolkit_id.as_str())
            .bind(version_bits(version))
            .fetch_all(&mut *conn)
            .await?;
            let mut services: BTreeMap<String, Option<String>> = BTreeMap::new();
            for row in rows {
                let service: String = row.try_get("service")?;
                let app: Option<String> = row.try_get("app")?;
                services.insert(service, app);
            }
            resolved.push(ResolvedToolkit {
                name,
                tenant_id: owner,
                toolkit_id,
                version,
                services,
            });
        }
        Ok((resolved, skipped))
    }

    /// The reference's `service_references`: backend licence references for each toolkit;
    /// toolkits lacking one are skipped with [`CREDENTIALS_UNAVAILABLE`].
    async fn service_references(
        &self,
        tenant: &AuthorityId,
        resolved: Vec<ResolvedToolkit>,
        skipped: &mut Vec<SkippedToolkit>,
        bundle: Option<&str>,
    ) -> Result<(Vec<ResolvedToolkit>, BTreeMap<String, CredentialReference>), EnsureError> {
        // The minter's identity type cannot carry the nil-version UUID an `AuthorityId`
        // accepts, so the conversion is only made when a minter will actually be called.
        let tenant_uuid = if self.minter.is_some() {
            Some(tenant_uuid(tenant)?)
        } else {
            None
        };
        let mut known: HashMap<String, Option<Rfc4122Uuid>> = HashMap::new();
        let mut kept: Vec<ResolvedToolkit> = Vec::new();
        let mut references: BTreeMap<String, CredentialReference> = BTreeMap::new();
        for toolkit in resolved {
            let mut ok = true;
            for (service, app) in &toolkit.services {
                let Some(app) = app.as_deref() else {
                    // A service with no licence application key cannot be established.
                    ok = false;
                    continue;
                };
                let licence = match known.get(app) {
                    Some(known) => *known,
                    None => {
                        let mut licence = None;
                        if let Some(minter) = &self.minter {
                            let tenant_uuid = tenant_uuid
                                .as_ref()
                                .expect("a configured minter has a tenant identity");
                            match minter.licence_id(tenant_uuid, app, bundle).await {
                                Ok(found) => licence = Some(found),
                                // 403 dependency_grant_scope, no licence: skip, fail closed.
                                Err(LicenceLookupError::Denied) => {}
                                Err(LicenceLookupError::Unavailable) => {
                                    return Err(EnsureError::Unavailable(
                                        "licence authority unavailable",
                                    ));
                                }
                            }
                        }
                        known.insert(app.to_owned(), licence);
                        licence
                    }
                };
                let Some(licence) = licence else {
                    ok = false;
                    continue;
                };
                let (Ok(service_name), Ok(app_key)) =
                    (Name::new(service.as_str()), AppKey::new(app))
                else {
                    ok = false;
                    continue;
                };
                let Ok(license_id) = AuthorityId::new(licence.to_string()) else {
                    ok = false;
                    continue;
                };
                references.insert(
                    service.clone(),
                    CredentialReference {
                        service: service_name.clone(),
                        alias: service_name,
                        license_id,
                        app_key,
                        bundle: bundle.and_then(|bundle| AppKey::new(bundle).ok()),
                    },
                );
            }
            if ok {
                kept.push(toolkit);
            } else {
                skipped.push(SkippedToolkit {
                    toolkit: toolkit.name,
                    reason: CREDENTIALS_UNAVAILABLE,
                });
            }
        }
        let needed: HashSet<&str> = kept
            .iter()
            .flat_map(|toolkit| toolkit.services.keys().map(String::as_str))
            .collect();
        references.retain(|service, _| needed.contains(service.as_str()));
        Ok((kept, references))
    }

    /// The reference's `write`: everything in the caller's transaction, serialized on the
    /// (tenant, product) ensure row.
    #[allow(clippy::too_many_arguments)]
    async fn write(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        product: &str,
        actor: &Attribution,
        gateway: &AuthorityId,
        resolved: &[ResolvedToolkit],
        services: &BTreeMap<String, CredentialReference>,
        skipped: &[SkippedToolkit],
        rotate: bool,
    ) -> Result<EnsureResult, EnsureError> {
        sqlx::query(
            "INSERT INTO public.mcp_binding_ensures(ensure_id,tenant_id,product,created_by,\
             updated_by) VALUES (uuidv7(),$1::uuid,$2,$3,$3) \
             ON CONFLICT (tenant_id,product) DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(product)
        .bind(actor.subject.as_str())
        .execute(&mut *conn)
        .await?;
        let row = ensure_row(&mut *conn, tenant, product)
            .await?
            .ok_or(EnsureError::Conflict("binding ensure unavailable"))?;

        let binding = match &row.binding_id {
            Some(identity) => {
                Some(bindings::get_binding(&mut *conn, tenant, identity, true).await?)
            }
            None => None,
        };
        let valid = binding
            .as_ref()
            .is_some_and(|binding| !binding.revoked && binding.gateway_license_id == *gateway);
        let mut token: Option<String> = None;
        let mut status: &'static str = if valid { "unchanged" } else { "pending" };
        let mut profile_id = row.credential_profile_id.clone();
        let toolkits: Vec<EnsuredToolkit> = resolved
            .iter()
            .map(|toolkit| EnsuredToolkit {
                name: toolkit.name.clone(),
                tenant_id: toolkit.tenant_id.clone(),
                toolkit_id: toolkit.toolkit_id.clone(),
                version: toolkit.version,
            })
            .collect();
        let mut binding_id = row.binding_id.clone();
        if !resolved.is_empty() {
            profile_id = Some(
                self.write_profile(
                    &mut *conn,
                    tenant,
                    product,
                    actor,
                    gateway,
                    services,
                    profile_id.clone(),
                )
                .await?,
            );
            let ttl = Duration::days(i64::try_from(self.ttl_days).unwrap_or(i64::MAX));
            let now = Utc::now();
            let mut references: Vec<ToolkitReference> = resolved
                .iter()
                .map(|toolkit| ToolkitReference {
                    id: toolkit.toolkit_id.clone(),
                    version: toolkit.version,
                    tenant_id: Some(toolkit.tenant_id.clone()),
                })
                .collect();
            references.sort_by(|left, right| {
                (
                    left.tenant_id.as_ref().map_or("", AuthorityId::as_str),
                    left.id.as_str(),
                    left.version.get(),
                )
                    .cmp(&(
                        right.tenant_id.as_ref().map_or("", AuthorityId::as_str),
                        right.id.as_str(),
                        right.version.get(),
                    ))
            });
            let spec = BindingSpec {
                schema_version: 1,
                credential_profile_id: profile_id
                    .clone()
                    .expect("a written profile has an identity"),
                toolkits: references,
                tool_subset: None,
                context: BoundContext {
                    tenant_id: tenant.clone(),
                    project_id: None,
                    workspace_id: None,
                    project_phase: None,
                    work_type: None,
                    card_stage: None,
                    responsibility: None,
                    test_command: None,
                    reviewed_commit: None,
                },
                operation_constraints: Vec::new(),
                // Ceiling only: each tool's own manifest limits are the binding constraint.
                limits: MAX_LIMITS,
                expires_at: now + ttl,
                enabled: true,
            };
            let service = self.toolkit_service();
            if let Some(binding) = binding.as_ref()
                && !binding.revoked
                && !valid
            {
                // The tenant's mcp licence changed: the old binding can never authenticate again.
                service
                    .act_binding(
                        &mut *conn,
                        tenant,
                        actor,
                        &binding.binding_id,
                        positive_revision(binding.revision)?,
                        true,
                    )
                    .await?;
            }
            if !valid {
                let (created, issued) = service
                    .write_binding(&mut *conn, tenant, actor, &spec, None, None)
                    .await?;
                binding_id = Some(created.binding_id);
                status = "created";
                token = issued;
            } else {
                binding_id = row.binding_id.clone();
                let current = match binding.as_ref() {
                    Some(binding) => serde_json::from_value::<BindingSpec>(binding.spec.clone())
                        .map_err(|_| EnsureError::Corrupt("binding spec"))?,
                    None => spec.clone(),
                };
                if current.toolkits != spec.toolkits
                    || current.credential_profile_id != spec.credential_profile_id
                    || current.limits != spec.limits
                    || !current.enabled
                    || current.expires_at - now < ttl / 2
                {
                    let revision = match binding.as_ref() {
                        Some(binding) => positive_revision(binding.revision)?,
                        None => PositiveVersion::new(1)
                            .map_err(|_| EnsureError::Corrupt("binding revision"))?,
                    };
                    service
                        .write_binding(
                            &mut *conn,
                            tenant,
                            actor,
                            &spec,
                            binding_id.clone(),
                            Some(revision),
                        )
                        .await?;
                    status = "updated";
                }
            }
        } else {
            binding_id = if valid { row.binding_id.clone() } else { None };
        }
        if rotate
            && let Some(identity) = binding_id.clone()
            && token.is_none()
        {
            let current = bindings::get_binding(&mut *conn, tenant, &identity, true).await?;
            let (_, issued) = self
                .toolkit_service()
                .act_binding(
                    &mut *conn,
                    tenant,
                    actor,
                    &identity,
                    positive_revision(current.revision)?,
                    false,
                )
                .await?;
            token = issued;
            status = "rotated";
        }
        let issued_at = if token.is_some() {
            Some(Utc::now())
        } else if binding_id == row.binding_id {
            row.token_issued_at
        } else {
            None
        };
        let gateway_to_store = if binding_id.is_some() {
            Some(gateway.clone())
        } else {
            row.gateway_license_id.clone()
        };
        sqlx::query(
            "UPDATE public.mcp_binding_ensures SET revision=revision+1,gateway_license_id=$2::uuid,\
             credential_profile_id=$3::uuid,binding_id=$4::uuid,toolkits=$5::jsonb,skipped=$6::jsonb,\
             token_issued_at=(timestamptz 'epoch' + $7::bigint * interval '1 microsecond'),\
             updated_by=$8,updated_at=clock_timestamp() WHERE ensure_id=$1::uuid",
        )
        .bind(row.ensure_id.as_str())
        .bind(gateway_to_store.as_ref().map(AuthorityId::as_str))
        .bind(profile_id.as_ref().map(Uuid7::as_str))
        .bind(binding_id.as_ref().map(Uuid7::as_str))
        .bind(
            serde_json::to_value(&toolkits)
                .map_err(|_| EnsureError::Corrupt("ensure toolkits"))?,
        )
        .bind(serde_json::to_value(skipped).map_err(|_| EnsureError::Corrupt("ensure skipped"))?)
        .bind(issued_at.map(|instant| instant.timestamp_micros()))
        .bind(actor.subject.as_str())
        .execute(&mut *conn)
        .await?;
        audit_ensure(&mut *conn, tenant, actor, &row.ensure_id, row.revision + 1).await?;
        let final_binding = match &binding_id {
            Some(identity) => {
                Some(bindings::get_binding(&mut *conn, tenant, identity, false).await?)
            }
            None => None,
        };
        Ok(EnsureResult {
            ensure_id: row.ensure_id,
            tenant_id: tenant.clone(),
            product: product.to_owned(),
            status,
            binding_id,
            binding_revision: match final_binding.as_ref() {
                Some(binding) => Some(positive_revision(binding.revision)?),
                None => None,
            },
            gateway_license_id: gateway.clone(),
            expires_at: final_binding.as_ref().map(|binding| {
                binding
                    .expires_at
                    .to_rfc3339_opts(SecondsFormat::AutoSi, false)
            }),
            toolkits,
            skipped: skipped.to_vec(),
            token_already_issued: token.is_none() && final_binding.is_some(),
            token,
        })
    }

    /// The reference's `write_profile`: the tenant's ensure profile, reusing the ensure row's
    /// existing identity and writing only when the desired profile differs.
    async fn write_profile(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        product: &str,
        actor: &Attribution,
        gateway: &AuthorityId,
        services: &BTreeMap<String, CredentialReference>,
        profile_id: Option<Uuid7>,
    ) -> Result<Uuid7, EnsureError> {
        let Some(app) = self.license_app_key.as_deref() else {
            return Err(EnsureError::Unavailable(
                "license authentication is not configured",
            ));
        };
        let desired = CredentialProfile {
            schema_version: 1,
            profile_id: profile_id.clone().unwrap_or_else(bindings::fresh_identity),
            tenant_id: tenant.clone(),
            name: Name::new(profile_name(product))
                .map_err(|_| EnsureError::Corrupt("ensure profile name"))?,
            gateway: CredentialReference {
                service: Name::new(GATEWAY_SERVICE)
                    .map_err(|_| EnsureError::Corrupt("gateway service"))?,
                alias: Name::new(GATEWAY_SERVICE)
                    .map_err(|_| EnsureError::Corrupt("gateway service"))?,
                license_id: gateway.clone(),
                app_key: AppKey::new(app)
                    .map_err(|_| EnsureError::Corrupt("gateway application key"))?,
                bundle: None,
            },
            // `services[k] for k in sorted(services)`: a `BTreeMap` iterates sorted.
            services: services.values().cloned().collect(),
        };
        let service = self.toolkit_service();
        match profile_id {
            None => {
                service
                    .write_profile(&mut *conn, tenant, actor, &desired, None)
                    .await?;
                Ok(desired.profile_id)
            }
            Some(identity) => {
                let row = bindings::profile_row(&mut *conn, tenant, &identity, true, false).await?;
                if row.profile != desired {
                    service
                        .write_profile(
                            &mut *conn,
                            tenant,
                            actor,
                            &desired,
                            Some(positive_revision(row.revision)?),
                        )
                        .await?;
                }
                Ok(identity)
            }
        }
    }

    fn toolkit_service(&self) -> ToolkitService {
        ToolkitService::new(
            self.pool.clone(),
            self.resolver.clone(),
            self.license_app_key.clone(),
        )
    }
}

/// The reference's `get_binding` read of the ensure row, locked for the update.
async fn ensure_row(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    product: &str,
) -> Result<Option<EnsureRow>, EnsureError> {
    let row = sqlx::query(
        "SELECT ensure_id::text AS ensure_id, revision, \
         gateway_license_id::text AS gateway_license_id, \
         credential_profile_id::text AS credential_profile_id, \
         binding_id::text AS binding_id, \
         (extract(epoch FROM token_issued_at) * 1000000)::bigint AS token_issued_at_micros \
         FROM public.mcp_binding_ensures WHERE tenant_id=$1::uuid AND product=$2 FOR UPDATE",
    )
    .bind(tenant.as_str())
    .bind(product)
    .fetch_optional(&mut *conn)
    .await?;
    row.map(decode_ensure).transpose()
}

fn decode_ensure(row: PgRow) -> Result<EnsureRow, EnsureError> {
    let gateway_license_id = row
        .try_get::<Option<String>, _>("gateway_license_id")?
        .map(|value| {
            AuthorityId::new(value).map_err(|_| EnsureError::Corrupt("ensure gateway licence"))
        })
        .transpose()?;
    let credential_profile_id = row
        .try_get::<Option<String>, _>("credential_profile_id")?
        .map(|value| {
            Uuid7::new(value).map_err(|_| EnsureError::Corrupt("ensure credential profile"))
        })
        .transpose()?;
    let binding_id = row
        .try_get::<Option<String>, _>("binding_id")?
        .map(|value| Uuid7::new(value).map_err(|_| EnsureError::Corrupt("ensure binding")))
        .transpose()?;
    let token_issued_at = row
        .try_get::<Option<i64>, _>("token_issued_at_micros")?
        .map(|micros| {
            DateTime::from_timestamp_micros(micros)
                .ok_or(EnsureError::Corrupt("ensure token issue time"))
        })
        .transpose()?;
    Ok(EnsureRow {
        ensure_id: Uuid7::new(row.try_get::<String, _>("ensure_id")?)
            .map_err(|_| EnsureError::Corrupt("ensure identity"))?,
        revision: row.try_get("revision")?,
        gateway_license_id,
        credential_profile_id,
        binding_id,
        token_issued_at,
    })
}

/// One append-only `mcp_access_events` row for the ensure (`binding.ensured`).
async fn audit_ensure(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    actor: &Attribution,
    ensure_id: &Uuid7,
    revision: i64,
) -> Result<(), EnsureError> {
    sqlx::query(
        "INSERT INTO public.mcp_access_events(\
         event_id,tenant_id,subject,license_id,entity_id,revision,action,artifact_version) \
         VALUES (uuidv7(),$1::uuid,$2,$3::uuid,$4::uuid,$5,$6,$7)",
    )
    .bind(tenant.as_str())
    .bind(actor.subject.as_str())
    .bind(actor.license_id.as_ref().map(AuthorityId::as_str))
    .bind(ensure_id.as_str())
    .bind(revision)
    .bind("binding.ensured")
    .bind(None::<i32>)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// A discovered toolkit row's `(identity, latest version)`.
fn decoded_version(row: &PgRow) -> Result<(Uuid7, PositiveVersion), EnsureError> {
    let toolkit_id = Uuid7::new(row.try_get::<String, _>("toolkit_id")?)
        .map_err(|_| EnsureError::Corrupt("toolkit identity"))?;
    let version: i32 = row.try_get("version")?;
    let version = u32::try_from(version)
        .ok()
        .and_then(|version| PositiveVersion::new(u64::from(version)).ok())
        .ok_or(EnsureError::Corrupt("toolkit version"))?;
    Ok((toolkit_id, version))
}

/// The tenant's identity as the licence authority's UUID type.
fn tenant_uuid(tenant: &AuthorityId) -> Result<Rfc4122Uuid, EnsureError> {
    Rfc4122Uuid::parse(tenant.as_str()).ok_or(EnsureError::Corrupt("tenant identity"))
}

/// A stored `bigint` revision as the model's positive version.
fn positive_revision(value: i64) -> Result<PositiveVersion, EnsureError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or(EnsureError::Corrupt("binding revision"))
}

fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}
