//! Idempotent, content-addressed publication of the platform toolkits (`--seed-platform`) and
//! the generic toolkit import (`POST /mcp/toolkits/import`).
//!
//! Ported from the reference `src/platform/seed.py`. For each toolkit under `toolkits/` it
//! publishes, under the platform tenant and in dependency order, service -> operations -> tools
//! -> toolkit. Every artifact id is fixed in the repository; the version is assigned here by
//! content: the full manifest (including resolved exact references and the runner image digest)
//! is compared with the latest version of that id.
//!
//! * identical and published   -> no-op
//! * identical and draft       -> publish (an earlier run died between create and publish)
//! * different (or absent)     -> append `max+1` (`1`) and publish
//!
//! Older versions stay published, so existing bindings keep working until they are rotated.
//! External toolkits (no service.json: tools with an external runtime, no Kata package) need no
//! runner image and are seeded whether or not the digest is set. Without
//! `MCP_RUNNER_IMAGE_DIGEST` only services and operations are seeded: a tool manifest pins the
//! digest, so tools and toolkits wait for it. A digest outside `MCP_APPROVED_RUNNER_IMAGES` is a
//! hard error. The whole run holds one advisory lock, so concurrent migrate containers (rolling
//! update, two replicas) serialize.
//!
//! Services and operations are platform contracts: they are written with the platform pool
//! (the elevated `mcp_platform` role), tools and toolkits with the runtime pool.
//!
//! No document and no token is ever logged: the only logged values are artifact kind, name,
//! action and source-key names.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Map, Value, json};
use sqlx::{PgConnection, PgPool, Row};
use thiserror::Error;

use crate::auth::Rfc4122Uuid;
use crate::builder::packaging::OpRefs;
use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    Attribution, ExactReference, OperationManifest, ServiceManifest, ToolLimits, ToolManifest,
};
use crate::catalog::package::package_digest;
use crate::catalog::service::{CatalogService, PlatformCatalogService};
use crate::catalog::toolkit_models::{ToolReference, ToolSelection, ToolkitManifest};
use crate::catalog::validation::SchemaLimits;
use crate::config::{ConfigError, PackageLimits};
use crate::platform::toolkit_source::{
    LoadError, PackageMode, ToolSource, ToolkitSource, package_files,
};
use crate::storage::catalog::{
    AppendRequest, CatalogRepository, PlatformCatalogRepository, PlatformKind,
};
use crate::storage::toolkits::{ToolkitStoreError, transition_toolkit, write_toolkit};
use crate::toolkits::resolver::SelectionResolver;

/// Audit rows require a licence identity; the seed has none, so it uses this fixed marker.
pub const SEED_LICENCE_ID: &str = "01900000-0000-7000-8000-00000000f002";
/// The reserved platform tenant (`public.mcp_platform_tenant()`), the reference's default.
pub const DEFAULT_PLATFORM_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
/// Arbitrary constant naming the seed's advisory lock ("MCPSEED").
pub const LOCK_KEY: i64 = 0x004D_4350_5345_4544;
/// How long a seed waits for another seed before refusing.
pub const LOCK_WAIT: Duration = Duration::from_secs(300);

/// The settings the seed reads: the same three values the reference's single `Settings` holds.
///
/// The binary's `--seed-platform` mode needs nothing else, so this type deliberately parses its
/// own environment instead of the serving configuration (which requires `BIND_ADDR`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SeedSettings {
    /// `PLATFORM_TENANT_ID` (default: the reserved platform tenant). Must be UUIDv7.
    pub platform_tenant_id: AuthorityId,
    /// `MCP_RUNNER_IMAGE_DIGEST`: the runner image a kata tool pins. Unset = tools skipped.
    pub runner_image_digest: Option<String>,
    /// `MCP_APPROVED_RUNNER_IMAGES` (JSON list): every digest a tool may name.
    pub approved_runner_images: Vec<String>,
}

impl SeedSettings {
    /// Parse the seed's settings from the process environment.
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|key| std::env::var(key).ok())
    }

    /// Testable core of [`SeedSettings::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |key: &str| get(key).filter(|value| !value.trim().is_empty());
        let platform_tenant_id = match get("PLATFORM_TENANT_ID") {
            None => AuthorityId::new(DEFAULT_PLATFORM_TENANT)
                .expect("the default platform tenant is a valid RFC 4122 UUID"),
            Some(value) => {
                let parsed =
                    Rfc4122Uuid::parse(value.trim()).ok_or_else(|| ConfigError::Invalid {
                        name: "PLATFORM_TENANT_ID",
                        reason: format!("{value:?} is not an RFC 4122 UUID"),
                    })?;
                // The reference's startup rule (`config.py:350`): the reserved tenant is UUIDv7.
                if parsed.to_string().as_bytes().get(14) != Some(&b'7') {
                    return Err(ConfigError::Invalid {
                        name: "PLATFORM_TENANT_ID",
                        reason: "the platform tenant identity must be UUIDv7".into(),
                    });
                }
                AuthorityId::new(parsed.to_string()).map_err(|_| ConfigError::Invalid {
                    name: "PLATFORM_TENANT_ID",
                    reason: "the platform tenant identity must be an RFC 9562 UUID".into(),
                })?
            }
        };
        let approved_runner_images = match get("MCP_APPROVED_RUNNER_IMAGES") {
            None => Vec::new(),
            Some(raw) => {
                serde_json::from_str::<Vec<String>>(&raw).map_err(|error| ConfigError::Invalid {
                    name: "MCP_APPROVED_RUNNER_IMAGES",
                    reason: format!("expected a JSON list of runner image digests: {error}"),
                })?
            }
        };
        Ok(Self {
            platform_tenant_id,
            runner_image_digest: get("MCP_RUNNER_IMAGE_DIGEST"),
            approved_runner_images,
        })
    }
}

/// A refused or impossible platform seed.
#[derive(Debug, Error)]
pub enum SeedError {
    /// The reference's `SeedError`: the catalog cannot be brought to the repository's state.
    /// The route answers `409`, the binary exits 1.
    #[error("{0}")]
    Refused(String),
    /// Anything the reference lets escape as a 500 (a model, storage or database failure).
    #[error("{0}")]
    Failed(String),
}

impl From<LoadError> for SeedError {
    fn from(error: LoadError) -> Self {
        Self::Failed(error.to_string())
    }
}

impl From<sqlx::Error> for SeedError {
    fn from(error: sqlx::Error) -> Self {
        Self::Failed(error.to_string())
    }
}

/// `<kind>:<name>` -> the action the seed took, plus the version now published (or pending).
#[derive(Debug, Clone, Default)]
pub struct SeedReport {
    /// `"<kind>:<name>"` -> `"created" | "appended" | "published" | "unchanged"`, in run order.
    pub actions: Map<String, Value>,
    /// `"<kind>:<name>"` -> the version that is now published for the artifact.
    pub versions: Map<String, Value>,
    /// True when no runner image digest was configured: tools and toolkits were skipped.
    pub tools_skipped: bool,
    /// Toolkits left unseeded because their service's source is not registered and active.
    pub sources_missing: Map<String, Value>,
}

impl SeedReport {
    /// How many artifacts the seed reports with this action.
    pub fn count(&self, action: &str) -> usize {
        self.actions
            .values()
            .filter(|value| value.as_str() == Some(action))
            .count()
    }

    /// True when at least one artifact changed.
    pub fn changed(&self) -> bool {
        self.actions
            .values()
            .any(|value| value.as_str() != Some("unchanged"))
    }

    /// The reference's final log line.
    pub fn summary(&self) -> String {
        let unchanged = self.count("unchanged");
        let changed = self.actions.len() - unchanged;
        format!(
            "platform seed done: {changed} changed, {unchanged} unchanged{}",
            if self.tools_skipped {
                " (tools skipped: no runner image digest)"
            } else {
                ""
            }
        )
    }
}

/// How one run seeds: the packager, the lock wait and whether a missing source refuses.
#[derive(Debug, Clone, Copy)]
pub struct SeedOptions {
    /// The repository tree packager, or a bundle's.
    pub package_mode: PackageMode,
    /// How long to wait for another seed's advisory lock.
    pub lock_timeout: Duration,
    /// The generic import refuses a missing or disabled source; the repository seed skips it.
    pub strict_sources: bool,
}

impl Default for SeedOptions {
    fn default() -> Self {
        Self {
            package_mode: PackageMode::Repository,
            lock_timeout: LOCK_WAIT,
            strict_sources: false,
        }
    }
}

// ── the generic import bundle ──────────────────────────────────────────────────────────────

/// One package file of a bundle: the reference's `BundleFile` (strict, bounded).
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleFile {
    /// Relative POSIX path inside the package.
    pub path: String,
    /// Exact file content.
    pub content: String,
}

/// One tool of a bundle: `ToolManifest` fields plus its operation keys and package files.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BundleTool {
    /// ToolManifest fields except tenant_id, version, package_sha256, runner_image_digest and
    /// allowed_operations.
    pub fields: Map<String, Value>,
    /// Keys into the bundle's `operations`.
    pub op_keys: Vec<Name>,
    /// The tool's package files (a `kata_python` tool supplies its own `kit.py`).
    pub files: Vec<BundleFile>,
}

impl BundleTool {
    /// The reference's `name`: the manifest's public name, as the import's label component.
    pub fn name(&self) -> String {
        self.fields
            .get("public_name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }
}

/// A toolkit as plain JSON: the same parts as `toolkits/<tk>/` in the repository.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitBundle {
    /// `toolkit.json` fields.
    pub toolkit: Map<String, Value>,
    /// `service.json` fields (a bundle always names its service).
    pub service: Map<String, Value>,
    /// `"<key>": OperationManifest without `version` and `service`, in the caller's order`.
    pub operations: Map<String, Value>,
    /// The toolkit's tools.
    pub tools: Vec<BundleTool>,
}

impl ToolkitBundle {
    /// The reference's `name`: the toolkit's declared name.
    pub fn name(&self) -> String {
        self.toolkit
            .get("name")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned()
    }

    /// The reference's `ToolkitBundle.consistent` model validator plus the declared bounds.
    ///
    /// A refusal here is request validation (the route's 422), never a seed error (its 409).
    pub fn validate(&self) -> Result<(), BundleError> {
        if !(1..=128).contains(&self.operations.len()) {
            return Err(BundleError(
                "operations must hold between 1 and 128 entries".to_owned(),
            ));
        }
        if !(1..=64).contains(&self.tools.len()) {
            return Err(BundleError(
                "tools must hold between 1 and 64 entries".to_owned(),
            ));
        }
        for key in self.operations.keys() {
            Name::new(key.clone())
                .map_err(|_| BundleError("operation keys must be catalog names".to_owned()))?;
        }
        for operation in self.operations.values() {
            if !operation.is_object() {
                return Err(BundleError(
                    "every operation must be a JSON object".to_owned(),
                ));
            }
        }
        let mut names = BTreeSet::new();
        for tool in &self.tools {
            if !(1..=64).contains(&tool.op_keys.len()) {
                return Err(BundleError(
                    "a tool must name between 1 and 64 operations".to_owned(),
                ));
            }
            if !(1..=64).contains(&tool.files.len()) {
                return Err(BundleError(
                    "a tool must carry between 1 and 64 package files".to_owned(),
                ));
            }
            if !names.insert(tool.name()) {
                return Err(BundleError("duplicate tool name".to_owned()));
            }
            for key in &tool.op_keys {
                if !self.operations.contains_key(key.as_str()) {
                    return Err(BundleError("tool uses an unknown operation key".to_owned()));
                }
            }
            let mut paths = BTreeSet::new();
            for file in &tool.files {
                let length = file.path.chars().count();
                if !(1..=256).contains(&length) {
                    return Err(BundleError(
                        "a package file path must hold 1 to 256 characters".to_owned(),
                    ));
                }
                if file.content.chars().count() > 262_144 {
                    return Err(BundleError(
                        "a package file may carry at most 262144 characters".to_owned(),
                    ));
                }
                if file.path == "ops.py" {
                    return Err(BundleError("ops.py is generated".to_owned()));
                }
                if !paths.insert(file.path.as_str()) {
                    return Err(BundleError("duplicate package file".to_owned()));
                }
            }
        }
        Ok(())
    }
}

/// A toolkit bundle the request model refuses (the reference's Pydantic `ValidationError`).
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("{0}")]
pub struct BundleError(pub String);

/// The bundle in the seeder's source shape.
fn bundle_source(bundle: &ToolkitBundle) -> ToolkitSource {
    let tools = bundle
        .tools
        .iter()
        .map(|tool| ToolSource {
            name: tool.name(),
            fields: tool.fields.clone(),
            op_keys: tool.op_keys.iter().map(ToString::to_string).collect(),
            files: tool
                .files
                .iter()
                .map(|file| (file.path.clone(), file.content.clone()))
                .collect(),
        })
        .collect();
    ToolkitSource {
        name: bundle.name(),
        toolkit: bundle.toolkit.clone(),
        service: Some(Value::Object(bundle.service.clone())),
        operations: bundle.operations.clone(),
        tools,
        kit: String::new(),
        shared: Vec::new(),
    }
}

// ── entry points ──────────────────────────────────────────────────────────────────────────

/// Publish every source under the platform tenant, serialized by the seed's advisory lock.
///
/// `platform_pool` is the elevated platform-authoring pool; the reference defaults it to the
/// runtime pool when it is unset.
pub async fn seed(
    pool: &PgPool,
    settings: &SeedSettings,
    sources: &[ToolkitSource],
    platform_pool: Option<&PgPool>,
    options: SeedOptions,
) -> Result<SeedReport, SeedError> {
    let platform_pool = platform_pool.unwrap_or(pool);
    let mut lock = pool.acquire().await?;
    acquire_lock(&mut lock, options.lock_timeout).await?;
    let result = Seeder::new(pool, platform_pool, settings, options)
        .run(sources)
        .await;
    // The session ends either way; an unlock that fails is followed by closing the connection,
    // which releases the session-level lock exactly as the reference's `lock.close()` does.
    let unlocked = sqlx::query("SELECT pg_advisory_unlock($1)")
        .bind(LOCK_KEY)
        .execute(&mut *lock)
        .await;
    if unlocked.is_err() {
        let _ = lock.close().await;
    }
    result
}

/// Publish one toolkit bundle under the platform tenant through the same content-addressed
/// path as the repository seed. A missing or disabled source is an error here.
pub async fn import_bundle(
    pool: &PgPool,
    settings: &SeedSettings,
    bundle: &ToolkitBundle,
    platform_pool: &PgPool,
) -> Result<SeedReport, SeedError> {
    let source = bundle_source(bundle);
    seed(
        pool,
        settings,
        std::slice::from_ref(&source),
        Some(platform_pool),
        SeedOptions {
            package_mode: PackageMode::Bundle,
            strict_sources: true,
            ..SeedOptions::default()
        },
    )
    .await
}

/// The reference's `acquire_lock`: poll `pg_try_advisory_lock` so a statement timeout cannot
/// abort a long wait.
async fn acquire_lock(conn: &mut PgConnection, timeout: Duration) -> Result<(), SeedError> {
    let deadline = Instant::now() + timeout;
    loop {
        let acquired: bool = sqlx::query_scalar("SELECT pg_try_advisory_lock($1) AS ok")
            .bind(LOCK_KEY)
            .fetch_one(&mut *conn)
            .await?;
        if acquired {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(SeedError::Refused(
                "another platform seed holds the lock".to_owned(),
            ));
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

// ── the seeder ────────────────────────────────────────────────────────────────────────────

struct Seeder<'a> {
    pool: &'a PgPool,
    platform_pool: &'a PgPool,
    tenant: AuthorityId,
    runner_image_digest: Option<String>,
    approved_runner_images: Vec<String>,
    strict_sources: bool,
    package_mode: PackageMode,
    repository: CatalogRepository,
    platform: PlatformCatalogRepository,
    catalog: CatalogService,
    platform_service: PlatformCatalogService,
    resolver: SelectionResolver,
    report: SeedReport,
}

impl<'a> Seeder<'a> {
    fn new(
        pool: &'a PgPool,
        platform_pool: &'a PgPool,
        settings: &SeedSettings,
        options: SeedOptions,
    ) -> Self {
        let repository = CatalogRepository::new(pool.clone());
        let catalog = CatalogService::new(
            repository.clone(),
            SchemaLimits::default(),
            PackageLimits::default(),
        );
        let platform = PlatformCatalogRepository::new(platform_pool.clone());
        let platform_service = PlatformCatalogService::new(platform.clone(), catalog.clone());
        let resolver = SelectionResolver {
            platform_tenant_id: settings.platform_tenant_id.clone(),
        };
        Self {
            pool,
            platform_pool,
            tenant: settings.platform_tenant_id.clone(),
            runner_image_digest: settings.runner_image_digest.clone(),
            approved_runner_images: settings.approved_runner_images.clone(),
            strict_sources: options.strict_sources,
            package_mode: options.package_mode,
            repository,
            platform,
            catalog,
            platform_service,
            resolver,
            report: SeedReport::default(),
        }
    }

    fn note(&mut self, kind: &str, name: &str, action: &str, version: Option<u32>) {
        let key = format!("{kind}:{name}");
        self.report
            .actions
            .insert(key.clone(), Value::String(action.to_owned()));
        if let Some(version) = version {
            self.report.versions.insert(key, json!(version));
        }
        // Names only: never a document and never a token.
        tracing::info!("{kind} {name}: {action}");
    }

    async fn run(mut self, sources: &[ToolkitSource]) -> Result<SeedReport, SeedError> {
        let digest = self.runner_image_digest.clone();
        if let Some(digest) = &digest
            && !self
                .approved_runner_images
                .iter()
                .any(|image| image == digest)
        {
            return Err(SeedError::Refused(
                "MCP_RUNNER_IMAGE_DIGEST is not in MCP_APPROVED_RUNNER_IMAGES".to_owned(),
            ));
        }
        if digest.is_none() {
            self.report.tools_skipped = true;
            tracing::warn!(
                "MCP_RUNNER_IMAGE_DIGEST is unset: seeding services and operations only; \
                 tools and toolkits are skipped"
            );
        }
        for source in sources {
            let Some(service_value) = source.service.as_ref() else {
                // An external toolkit needs no runner image; its tools are part of the seed.
                self.publish_toolkit(source, &BTreeMap::new(), None).await?;
                continue;
            };
            let service_name = string_field(service_value, "service_key")?;
            let alias = string_field(service_value, "destination_alias")?;
            if !self.source_active(&alias).await? {
                if self.strict_sources {
                    return Err(SeedError::Refused(format!(
                        "source {alias} is not registered and active"
                    )));
                }
                self.report
                    .sources_missing
                    .insert(source.name.clone(), Value::String(alias.clone()));
                tracing::warn!(
                    "toolkit {} skipped: source {} is not registered and active \
                     (POST /mcp/sources)",
                    source.name,
                    alias
                );
                continue;
            }
            let service = self.service(&service_name, service_value).await?;
            let mut refs: BTreeMap<String, ExactReference> = BTreeMap::new();
            for (key, operation) in &source.operations {
                refs.insert(
                    key.clone(),
                    self.operation(key, operation, &service, &service_name)
                        .await?,
                );
            }
            if digest.is_none() {
                continue;
            }
            self.publish_toolkit(source, &refs, digest.as_deref())
                .await?;
        }
        Ok(self.report)
    }

    async fn source_active(&self, key: &str) -> Result<bool, SeedError> {
        let status: Option<String> = sqlx::query_scalar(
            "SELECT status FROM public.mcp_sources \
             WHERE owner_tenant_id=public.mcp_platform_tenant() AND source_key=$1",
        )
        .bind(key)
        .fetch_optional(self.platform_pool)
        .await?;
        Ok(status.as_deref() == Some("active"))
    }

    // -- services and operations ------------------------------------------------------------

    async fn service(&mut self, name: &str, source: &Value) -> Result<ExactReference, SeedError> {
        let candidate = build_service(source)?;
        let Some(latest) = self
            .platform
            .latest_service(&candidate.service_id)
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?
        else {
            let reference = ExactReference {
                id: candidate.service_id.clone(),
                version: one(),
            };
            self.platform_service
                .add_service(&candidate, actor(), None)
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.platform
                .transition(
                    PlatformKind::Service,
                    &reference,
                    VersionStatus::Published,
                    actor(),
                )
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.note("service", name, "created", Some(1));
            return Ok(reference);
        };
        let reference = ExactReference {
            id: candidate.service_id.clone(),
            version: latest.version,
        };
        if same_service(&latest.manifest, &candidate) {
            return self
                .settle(PlatformKind::Service, name, reference, latest.status)
                .await;
        }
        let next = next_version(latest.version)?;
        let mut appended = candidate.clone();
        appended.version = next;
        self.platform_service
            .add_service(&appended, actor(), Some(i64::from(latest.revision.get())))
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        let reference = ExactReference {
            id: candidate.service_id.clone(),
            version: next,
        };
        self.platform
            .transition(
                PlatformKind::Service,
                &reference,
                VersionStatus::Published,
                actor(),
            )
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        self.note("service", name, "appended", Some(next.get()));
        Ok(reference)
    }

    async fn operation(
        &mut self,
        name: &str,
        source: &Value,
        service: &ExactReference,
        service_name: &str,
    ) -> Result<ExactReference, SeedError> {
        let candidate = build_operation(source, service)?;
        let label = format!("{service_name}.{name}");
        let Some(latest) = self
            .platform
            .latest_operation(&candidate.operation_id)
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?
        else {
            let reference = ExactReference {
                id: candidate.operation_id.clone(),
                version: one(),
            };
            self.platform_service
                .add_operation(&candidate, actor())
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.platform
                .transition(
                    PlatformKind::Operation,
                    &reference,
                    VersionStatus::Published,
                    actor(),
                )
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.note("operation", &label, "created", Some(1));
            return Ok(reference);
        };
        let reference = ExactReference {
            id: candidate.operation_id.clone(),
            version: latest.version,
        };
        if same_operation(&latest.manifest, &candidate) {
            return self
                .settle(PlatformKind::Operation, &label, reference, latest.status)
                .await;
        }
        let next = next_version(latest.version)?;
        let mut appended = candidate.clone();
        appended.version = next;
        self.platform_service
            .add_operation(&appended, actor())
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        let reference = ExactReference {
            id: candidate.operation_id.clone(),
            version: next,
        };
        self.platform
            .transition(
                PlatformKind::Operation,
                &reference,
                VersionStatus::Published,
                actor(),
            )
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        self.note("operation", &label, "appended", Some(next.get()));
        Ok(reference)
    }

    /// The identical version already exists: publish a draft, accept a published one, refuse a
    /// row a human disabled or retired.
    async fn settle(
        &mut self,
        kind: PlatformKind,
        name: &str,
        reference: ExactReference,
        status: VersionStatus,
    ) -> Result<ExactReference, SeedError> {
        let kind_name = platform_kind_name(kind);
        match status {
            VersionStatus::Draft => {
                self.platform
                    .transition(kind, &reference, VersionStatus::Published, actor())
                    .await
                    .map_err(|error| SeedError::Failed(error.to_string()))?;
                self.note(kind_name, name, "published", Some(reference.version.get()));
            }
            VersionStatus::Published => {
                self.note(kind_name, name, "unchanged", Some(reference.version.get()));
            }
            VersionStatus::Disabled | VersionStatus::Retired => {
                return Err(SeedError::Refused(format!(
                    "{kind_name} {name} v{} is {} in the catalog but is the repository's \
                     current content; a human disabled it, so the seed will not resurrect it",
                    reference.version,
                    status_text(status)
                )));
            }
        }
        Ok(reference)
    }

    // -- tools and toolkits -----------------------------------------------------------------

    async fn tool(
        &mut self,
        toolkit: &ToolkitSource,
        source: &ToolSource,
        refs: &BTreeMap<String, ExactReference>,
        digest: Option<&str>,
    ) -> Result<ToolReference, SeedError> {
        // External tools run in a service of their own, not in a runner image.
        let digest = if toolkit.external() { None } else { digest };
        let mut allowed = Vec::with_capacity(source.op_keys.len());
        for key in &source.op_keys {
            let reference = refs.get(key).cloned().ok_or_else(|| {
                SeedError::Refused(format!(
                    "tool {} uses unknown operation '{key}'",
                    source.name
                ))
            })?;
            allowed.push(reference);
        }
        let files = package_files(toolkit, source, &op_refs(refs), self.package_mode)?;
        let mut values = source.fields.clone();
        for key in [
            "tenant_id",
            "version",
            "package_sha256",
            "runner_image_digest",
            "allowed_operations",
        ] {
            values.remove(key);
        }
        values.insert(
            "tenant_id".to_owned(),
            Value::String(self.tenant.as_str().to_owned()),
        );
        values.insert("version".to_owned(), json!(1));
        values.insert(
            "package_sha256".to_owned(),
            Value::String(package_digest(&files)),
        );
        values.insert(
            "runner_image_digest".to_owned(),
            digest.map_or(Value::Null, |digest| Value::String(digest.to_owned())),
        );
        values.insert(
            "allowed_operations".to_owned(),
            serde_json::to_value(&allowed).map_err(|error| SeedError::Failed(error.to_string()))?,
        );
        let candidate: ToolManifest = serde_json::from_value(Value::Object(values))
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        let label = format!("{}.{}", toolkit.name, source.name);
        let latest = self
            .repository
            .latest_version(&self.tenant, &candidate.tool_id)
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        let Some(latest) = latest else {
            let created = self
                .catalog
                .create_draft(&self.tenant, &candidate, &files, actor())
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.catalog
                .transition(
                    &self.tenant,
                    &candidate.tool_id,
                    one(),
                    VersionStatus::Published,
                    actor(),
                    created.revision,
                )
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            self.note("tool", &label, "created", Some(1));
            return Ok(ToolReference {
                tenant_id: self.tenant.clone(),
                id: candidate.tool_id.clone(),
                version: one(),
            });
        };
        if same_tool(&latest.manifest, &candidate) {
            match latest.status {
                VersionStatus::Draft => {
                    self.catalog
                        .transition(
                            &self.tenant,
                            &candidate.tool_id,
                            latest.version,
                            VersionStatus::Published,
                            actor(),
                            latest.revision,
                        )
                        .await
                        .map_err(|error| SeedError::Failed(error.to_string()))?;
                    self.note("tool", &label, "published", Some(latest.version.get()));
                }
                VersionStatus::Published => {
                    self.note("tool", &label, "unchanged", Some(latest.version.get()));
                }
                VersionStatus::Disabled | VersionStatus::Retired => {
                    return Err(SeedError::Refused(format!(
                        "tool {label} v{} is {} in the catalog",
                        latest.version,
                        status_text(latest.status)
                    )));
                }
            }
            return Ok(ToolReference {
                tenant_id: self.tenant.clone(),
                id: candidate.tool_id.clone(),
                version: latest.version,
            });
        }
        let next = next_version(latest.version)?;
        let mut content = candidate.clone();
        content.version = next;
        let remainder = self
            .catalog
            .append_draft(&AppendRequest {
                tenant_id: &self.tenant,
                tool_id: &candidate.tool_id,
                content: &content,
                files: &files,
                actor: actor(),
                expected_revision: Some(latest.revision),
                exact_version: true,
            })
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        self.catalog
            .transition(
                &self.tenant,
                &candidate.tool_id,
                next,
                VersionStatus::Published,
                actor(),
                remainder.revision,
            )
            .await
            .map_err(|error| SeedError::Failed(error.to_string()))?;
        self.note("tool", &label, "appended", Some(next.get()));
        Ok(ToolReference {
            tenant_id: self.tenant.clone(),
            id: candidate.tool_id.clone(),
            version: next,
        })
    }

    async fn publish_toolkit(
        &mut self,
        source: &ToolkitSource,
        refs: &BTreeMap<String, ExactReference>,
        digest: Option<&str>,
    ) -> Result<(), SeedError> {
        let mut published: Vec<(ToolReference, ToolLimits)> =
            Vec::with_capacity(source.tools.len());
        for tool in &source.tools {
            let reference = self.tool(source, tool, refs, digest).await?;
            let stored = self
                .repository
                .get_version(&self.tenant, &reference.id, reference.version)
                .await
                .map_err(|error| SeedError::Failed(error.to_string()))?;
            published.push((reference, stored.manifest.limits));
        }
        let candidate = self.toolkit_manifest(source, &published)?;
        let (action, version) = self.store_toolkit(source, &candidate).await?;
        self.note("toolkit", &source.name, action, Some(version.get()));
        Ok(())
    }

    fn toolkit_manifest(
        &self,
        source: &ToolkitSource,
        published: &[(ToolReference, ToolLimits)],
    ) -> Result<ToolkitManifest, SeedError> {
        let mut values = source.toolkit.clone();
        for key in ["tenant_id", "version", "tools"] {
            values.remove(key);
        }
        values.insert(
            "tenant_id".to_owned(),
            Value::String(self.tenant.as_str().to_owned()),
        );
        values.insert("version".to_owned(), json!(1));
        let selections: Vec<ToolSelection> = published
            .iter()
            .map(|(reference, limits)| ToolSelection {
                tool: reference.clone(),
                operation_constraints: Vec::new(),
                limits: *limits,
            })
            .collect();
        values.insert(
            "tools".to_owned(),
            serde_json::to_value(&selections)
                .map_err(|error| SeedError::Failed(error.to_string()))?,
        );
        serde_json::from_value(Value::Object(values))
            .map_err(|error| SeedError::Failed(error.to_string()))
    }

    /// Write (or accept) the toolkit and return the action and version the run reports.
    async fn store_toolkit(
        &self,
        source: &ToolkitSource,
        candidate: &ToolkitManifest,
    ) -> Result<(&'static str, PositiveVersion), SeedError> {
        let mut transaction = self.pool.begin().await?;
        let outcome =
            match latest_toolkit(&mut transaction, &self.tenant, &candidate.toolkit_id).await? {
                None => {
                    let draft = write_toolkit(
                        &mut transaction,
                        &self.resolver,
                        &self.tenant,
                        actor(),
                        candidate,
                        None,
                    )
                    .await
                    .map_err(toolkit_failure)?;
                    transition_toolkit(
                        &mut transaction,
                        &self.resolver,
                        &self.tenant,
                        actor(),
                        &candidate.toolkit_id,
                        one(),
                        VersionStatus::Published,
                        draft.revision,
                    )
                    .await
                    .map_err(toolkit_failure)?;
                    ("created", one())
                }
                Some(latest) => {
                    if same_toolkit(&latest.manifest, candidate) {
                        match latest.status {
                            VersionStatus::Draft => {
                                transition_toolkit(
                                    &mut transaction,
                                    &self.resolver,
                                    &self.tenant,
                                    actor(),
                                    &candidate.toolkit_id,
                                    latest.version,
                                    VersionStatus::Published,
                                    latest.revision,
                                )
                                .await
                                .map_err(toolkit_failure)?;
                                ("published", latest.version)
                            }
                            VersionStatus::Published => ("unchanged", latest.version),
                            VersionStatus::Disabled | VersionStatus::Retired => {
                                return Err(SeedError::Refused(format!(
                                    "toolkit {} is {} in the catalog",
                                    source.name,
                                    status_text(latest.status)
                                )));
                            }
                        }
                    } else {
                        let draft = write_toolkit(
                            &mut transaction,
                            &self.resolver,
                            &self.tenant,
                            actor(),
                            candidate,
                            Some(latest.revision),
                        )
                        .await
                        .map_err(toolkit_failure)?;
                        transition_toolkit(
                            &mut transaction,
                            &self.resolver,
                            &self.tenant,
                            actor(),
                            &candidate.toolkit_id,
                            draft.manifest.version,
                            VersionStatus::Published,
                            draft.revision,
                        )
                        .await
                        .map_err(toolkit_failure)?;
                        ("appended", draft.manifest.version)
                    }
                }
            };
        transaction.commit().await?;
        Ok(outcome)
    }
}

// ── helpers ───────────────────────────────────────────────────────────────────────────────

/// The seed's fixed audit identity.
fn actor() -> &'static Attribution {
    static ACTOR: LazyLock<Attribution> = LazyLock::new(|| Attribution {
        subject: "platform-seed".to_owned(),
        license_id: Some(
            AuthorityId::new(SEED_LICENCE_ID).expect("the seed licence identity is valid"),
        ),
    });
    &ACTOR
}

/// The newest toolkit version of one identity, as the reference's `latest_toolkit`.
struct LatestToolkit {
    version: PositiveVersion,
    manifest: ToolkitManifest,
    revision: PositiveVersion,
    status: VersionStatus,
}

async fn latest_toolkit(
    conn: &mut PgConnection,
    tenant: &AuthorityId,
    identity: &Uuid7,
) -> Result<Option<LatestToolkit>, SeedError> {
    let row = sqlx::query(
        "SELECT v.version,v.manifest,v.status,t.revision \
         FROM public.mcp_toolkit_versions v JOIN public.mcp_toolkits t \
           USING (tenant_id,toolkit_id) \
         WHERE v.tenant_id = $1::uuid AND v.toolkit_id = $2::uuid \
         ORDER BY v.version DESC LIMIT 1",
    )
    .bind(tenant.as_str())
    .bind(identity.as_str())
    .fetch_optional(&mut *conn)
    .await?;
    let Some(row) = row else {
        return Ok(None);
    };
    let status: String = row.try_get("status").map_err(storage)?;
    Ok(Some(LatestToolkit {
        version: positive(i64::from(
            row.try_get::<i32, _>("version").map_err(storage)?,
        ))?,
        manifest: serde_json::from_value(row.try_get::<Value, _>("manifest").map_err(storage)?)
            .map_err(|_| SeedError::Failed("stored toolkit manifest is invalid".to_owned()))?,
        revision: positive(row.try_get::<i64, _>("revision").map_err(storage)?)?,
        status: parse_status(&status)?,
    }))
}

/// The reference's `build(ServiceManifest, **values, version=1)`.
fn build_service(source: &Value) -> Result<ServiceManifest, SeedError> {
    let mut values = object(source)?;
    values.insert("version".to_owned(), json!(1));
    serde_json::from_value(Value::Object(values))
        .map_err(|error| SeedError::Failed(error.to_string()))
}

/// The reference's `build(OperationManifest, **values, version=1, service=<exact>)`.
fn build_operation(
    source: &Value,
    service: &ExactReference,
) -> Result<OperationManifest, SeedError> {
    let mut values = object(source)?;
    values.insert("version".to_owned(), json!(1));
    values.insert(
        "service".to_owned(),
        json!({"id": service.id.as_str(), "version": service.version.get()}),
    );
    serde_json::from_value(Value::Object(values))
        .map_err(|error| SeedError::Failed(error.to_string()))
}

fn object(source: &Value) -> Result<Map<String, Value>, SeedError> {
    match source {
        Value::Object(object) => Ok(object.clone()),
        _ => Err(SeedError::Failed(
            "manifest source is not a JSON object".to_owned(),
        )),
    }
}

fn string_field(source: &Value, field: &str) -> Result<String, SeedError> {
    source
        .get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| SeedError::Failed(format!("service source carries no `{field}`")))
}

/// The `ops.py` table the packager needs: key -> (operation id, exact version).
fn op_refs(refs: &BTreeMap<String, ExactReference>) -> OpRefs {
    refs.iter()
        .map(|(key, reference)| (key.clone(), (reference.id.clone(), reference.version)))
        .collect()
}

/// Content equality ignoring only the version the seed assigns.
fn same_service(stored: &ServiceManifest, candidate: &ServiceManifest) -> bool {
    let mut stored = stored.clone();
    stored.version = candidate.version;
    stored == *candidate
}

fn same_operation(stored: &OperationManifest, candidate: &OperationManifest) -> bool {
    let mut stored = stored.clone();
    stored.version = candidate.version;
    stored == *candidate
}

fn same_tool(stored: &ToolManifest, candidate: &ToolManifest) -> bool {
    let mut stored = stored.clone();
    stored.version = candidate.version;
    stored == *candidate
}

fn same_toolkit(stored: &ToolkitManifest, candidate: &ToolkitManifest) -> bool {
    let mut stored = stored.clone();
    stored.version = candidate.version;
    stored == *candidate
}

fn next_version(version: PositiveVersion) -> Result<PositiveVersion, SeedError> {
    PositiveVersion::new(u64::from(version.get()) + 1)
        .map_err(|error| SeedError::Failed(error.to_string()))
}

fn one() -> PositiveVersion {
    PositiveVersion::new(1).expect("one is a positive version")
}

fn positive(value: i64) -> Result<PositiveVersion, SeedError> {
    u64::try_from(value)
        .ok()
        .and_then(|value| PositiveVersion::new(value).ok())
        .ok_or_else(|| SeedError::Failed("stored version is not positive".to_owned()))
}

fn storage(error: sqlx::Error) -> SeedError {
    SeedError::Failed(error.to_string())
}

fn toolkit_failure(error: ToolkitStoreError) -> SeedError {
    SeedError::Failed(error.to_string())
}

fn parse_status(value: &str) -> Result<VersionStatus, SeedError> {
    match value {
        "draft" => Ok(VersionStatus::Draft),
        "published" => Ok(VersionStatus::Published),
        "disabled" => Ok(VersionStatus::Disabled),
        "retired" => Ok(VersionStatus::Retired),
        _ => Err(SeedError::Failed(
            "stored version status is invalid".to_owned(),
        )),
    }
}

fn status_text(status: VersionStatus) -> &'static str {
    match status {
        VersionStatus::Draft => "draft",
        VersionStatus::Published => "published",
        VersionStatus::Disabled => "disabled",
        VersionStatus::Retired => "retired",
    }
}

fn platform_kind_name(kind: PlatformKind) -> &'static str {
    match kind {
        PlatformKind::Service => "service",
        PlatformKind::Operation => "operation",
    }
}
