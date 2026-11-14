//! Configuration from the environment. Nothing has a default port: the deployment sets
//! `BIND_ADDR` explicitly, so the binary never guesses one.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;

use crate::auth::uuid::Rfc4122Uuid;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ConfigError {
    #[error("{0} is not set")]
    Missing(&'static str),
    #[error("{name} is invalid: {reason}")]
    Invalid { name: &'static str, reason: String },
}

#[derive(Debug, Clone)]
pub struct Config {
    /// `DATABASE_URL`: the runtime pool (usually pgbouncer).
    pub database_url: String,
    /// `DATABASE_MIGRATE_URL` (optional): a DIRECT Postgres URL for migrations. sqlx's
    /// migrator takes a session-level advisory lock, which is unsafe through pgbouncer's
    /// transaction pooling. Unset = migrate over `DATABASE_URL`.
    pub database_migrate_url: Option<String>,
    /// `BIND_ADDR`, e.g. `0.0.0.0:<port>`. Required.
    pub bind_addr: SocketAddr,
    /// `EXECUTION_ENABLED` (optional, default false): whether this build can run tools.
    /// Reported by `/health` and `/health/ready`; the deployment sets it true only when the
    /// execution slice is live.
    pub execution_enabled: bool,
    /// `PLATFORM_TENANT_ID` (optional): the reserved platform tenant that owns platform
    /// toolkits and their tools.
    pub platform_tenant_id: Rfc4122Uuid,
    /// `CATALOG_PAGE_SIZE` (optional, default 10, 1 to 100): the management catalog page bound.
    pub catalog_page_size: u32,
    /// `MCP_APPROVED_RUNNER_IMAGES` (optional, comma-separated, default empty): the runner
    /// image digests a `kata_python` tool may name. A tool with any other digest is refused.
    pub approved_runner_images: Vec<String>,
    /// The `MCP_MAX_PACKAGE_*` bounds a submitted tool package is validated against.
    pub packages: PackageLimits,
    /// The `MCP_*` execution queue, timeout and retention bounds.
    pub execution: ExecutionSettings,
}

impl Config {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`Config::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let database_url = get("DATABASE_URL").ok_or(ConfigError::Missing("DATABASE_URL"))?;
        let bind_raw = get("BIND_ADDR").ok_or(ConfigError::Missing("BIND_ADDR"))?;
        let bind_addr = bind_raw
            .trim()
            .parse()
            .map_err(|e: std::net::AddrParseError| ConfigError::Invalid {
                name: "BIND_ADDR",
                reason: format!("{e} (expected host:port, e.g. 0.0.0.0:9000)"),
            })?;
        // `EXECUTION_ENABLED` is this service's switch. The live deployment ConfigMap still sets
        // the reference's prefixed `MCP_EXECUTION_ENABLED`, so the prefixed name is accepted as
        // an alias during the drop-in cutover; the unprefixed name wins when both are set.
        let execution_enabled = execution_enabled_setting(&get)?;
        let platform_tenant_id = match get("PLATFORM_TENANT_ID") {
            None => default_platform_tenant_id(),
            Some(v) => Rfc4122Uuid::parse(v.trim()).ok_or_else(|| ConfigError::Invalid {
                name: "PLATFORM_TENANT_ID",
                reason: format!("{v:?} is not an RFC 4122 UUID"),
            })?,
        };
        let catalog_page_size = u32_setting(&get, "CATALOG_PAGE_SIZE", 10, 1, 100)?;
        Ok(Self {
            database_url,
            database_migrate_url: get("DATABASE_MIGRATE_URL"),
            bind_addr,
            execution_enabled,
            platform_tenant_id,
            catalog_page_size,
            approved_runner_images: comma_list(get("MCP_APPROVED_RUNNER_IMAGES")),
            // `get` is also consumed by `PackageLimits::from_lookup` below, so hand this
            // settings block its own borrowing closure instead of moving the shared one.
            execution: ExecutionSettings::from_lookup(|key| get(key))?,
            packages: PackageLimits::from_lookup(get)?,
        })
    }
}

/// The package bounds from the reference `Settings`: how many files a submitted tool package may
/// carry and how large they and their total may be.
///
/// Env names are the reference's (`MCP_` prefix, `Settings` in `src/config.py`), and so are the
/// defaults. Every bound is a `PositiveInt` there, so zero is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PackageLimits {
    /// `MCP_MAX_PACKAGE_FILES`: maximum number of files in one package.
    pub max_package_files: usize,
    /// `MCP_MAX_PACKAGE_FILE_BYTES`: maximum UTF-8 bytes of one file's content.
    pub max_package_file_bytes: usize,
    /// `MCP_MAX_PACKAGE_BYTES`: maximum UTF-8 bytes of all file contents together.
    pub max_package_bytes: usize,
}

impl Default for PackageLimits {
    fn default() -> Self {
        Self {
            max_package_files: 64,
            max_package_file_bytes: 262_144,
            max_package_bytes: 1_048_576,
        }
    }
}

impl PackageLimits {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`PackageLimits::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let limits = Self {
            max_package_files: positive_int_setting(&get, "MCP_MAX_PACKAGE_FILES", 64)?,
            max_package_file_bytes: positive_int_setting(
                &get,
                "MCP_MAX_PACKAGE_FILE_BYTES",
                262_144,
            )?,
            max_package_bytes: positive_int_setting(&get, "MCP_MAX_PACKAGE_BYTES", 1_048_576)?,
        };
        limits.validate()?;
        Ok(limits)
    }

    /// The reference's `consistent_limits` rule: one file can never be allowed to exceed the
    /// package it is part of.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_package_file_bytes > self.max_package_bytes {
            return Err(ConfigError::Invalid {
                name: "MCP_MAX_PACKAGE_FILE_BYTES",
                reason: "file limit exceeds package limit".into(),
            });
        }
        Ok(())
    }
}

/// The execution queue, timeout and retention bounds from the reference `Settings`.
///
/// Env names are the reference's (`MCP_` prefix, `Settings` in `src/config.py`), and so are the
/// defaults. The reference validates two cross-setting rules at startup: one tenant's queue
/// share can never exceed the global queue, and the synchronous wait must end before the
/// protocol timeout does.
#[derive(Debug, Clone, PartialEq)]
pub struct ExecutionSettings {
    /// `MCP_SYNC_WAIT_SECONDS` (0 to 300, default 0): how long a synchronous `tools/call`
    /// waits inline before handing the run back as a task.
    pub sync_wait: Duration,
    /// `MCP_PROTOCOL_TIMEOUT_SECONDS` (greater than 0, at most 360, default 15): one protocol
    /// round trip.
    pub protocol_timeout: Duration,
    /// `MCP_QUEUE_GLOBAL_MAX` (1 to 10000, default 100): runs queued across all tenants.
    pub queue_global_max: u64,
    /// `MCP_QUEUE_PER_TENANT_MAX` (1 to 1000, default 20): runs queued for one tenant.
    pub queue_per_tenant_max: u64,
    /// `MCP_RUN_QUEUE_TIMEOUT_SECONDS` (1 to 600, default 240): the longest a run may wait.
    pub run_queue_timeout: Duration,
    /// `MCP_EXECUTION_RETENTION_DAYS` (1 to 365, default 7): how long a run's payload is kept
    /// before its result is expired.
    pub retention_days: u64,
    /// `MCP_TASK_POLL_INTERVAL_MS` (500 to 60000, default 2000): the poll hint a task returns.
    pub task_poll_interval_ms: u64,
    /// `MCP_EXTERNAL_POLL_SECONDS` (1 to 300, default 5): how often an external run's target is
    /// polled.
    pub external_poll_seconds: f64,
    /// `MCP_PROTOCOL_OUTPUT_BYTES` (1 to 8388608, default 2097152): bound on one protocol
    /// response.
    pub protocol_output_bytes: usize,
    /// `MCP_MAX_RESULT_BYTES` (1 to 1048576, default 262144): bound on a stored run result.
    pub max_result_bytes: usize,
    /// `MCP_TASKS_ENABLED` (default false): whether the tasks extension is served.
    pub tasks_enabled: bool,
    /// `FR_APPROVAL_WAIT_SECONDS` (60 to 86400, default 900): how long an fr approval may wait
    /// before the activity feed raises `approval_waiting`. Advisory: it never changes the run.
    pub fr_approval_wait_seconds: u64,
    /// `FR_PHASE_STALL_SECONDS` (60 to 604800, default 3600): how long an fr phase may stand
    /// still before the feed raises `phase_stalled`. Advisory, like the wait threshold.
    pub fr_phase_stall_seconds: u64,
}

impl Default for ExecutionSettings {
    fn default() -> Self {
        Self {
            sync_wait: Duration::ZERO,
            protocol_timeout: Duration::from_secs(15),
            queue_global_max: 100,
            queue_per_tenant_max: 20,
            run_queue_timeout: Duration::from_secs(240),
            retention_days: 7,
            task_poll_interval_ms: 2_000,
            external_poll_seconds: 5.0,
            protocol_output_bytes: 2_097_152,
            max_result_bytes: 262_144,
            tasks_enabled: false,
            fr_approval_wait_seconds: 900,
            fr_phase_stall_seconds: 3_600,
        }
    }
}

impl ExecutionSettings {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`ExecutionSettings::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let settings = Self {
            sync_wait: Duration::from_secs_f64(bounded_float_setting(
                &get,
                "MCP_SYNC_WAIT_SECONDS",
                0.0,
                0.0,
                300.0,
            )?),
            protocol_timeout: Duration::from_secs_f64(float_setting(
                &get,
                "MCP_PROTOCOL_TIMEOUT_SECONDS",
                15.0,
                0.0,
                360.0,
            )?),
            queue_global_max: u64_setting(&get, "MCP_QUEUE_GLOBAL_MAX", 100, 1, 10_000)?,
            queue_per_tenant_max: u64_setting(&get, "MCP_QUEUE_PER_TENANT_MAX", 20, 1, 1_000)?,
            run_queue_timeout: Duration::from_secs(u64_setting(
                &get,
                "MCP_RUN_QUEUE_TIMEOUT_SECONDS",
                240,
                1,
                600,
            )?),
            retention_days: u64_setting(&get, "MCP_EXECUTION_RETENTION_DAYS", 7, 1, 365)?,
            task_poll_interval_ms: u64_setting(
                &get,
                "MCP_TASK_POLL_INTERVAL_MS",
                2_000,
                500,
                60_000,
            )?,
            external_poll_seconds: bounded_float_setting(
                &get,
                "MCP_EXTERNAL_POLL_SECONDS",
                5.0,
                1.0,
                300.0,
            )?,
            protocol_output_bytes: int_setting(
                &get,
                "MCP_PROTOCOL_OUTPUT_BYTES",
                2_097_152,
                1,
                8_388_608,
            )?,
            max_result_bytes: int_setting(&get, "MCP_MAX_RESULT_BYTES", 262_144, 1, 1_048_576)?,
            tasks_enabled: bool_setting(&get, "MCP_TASKS_ENABLED", false)?,
            // The two fr signal thresholds carry explicit unprefixed aliases in the reference
            // (`src/config.py:198-203`), so they are read unprefixed here too.
            fr_approval_wait_seconds: u64_setting(
                &get,
                "FR_APPROVAL_WAIT_SECONDS",
                900,
                60,
                86_400,
            )?,
            fr_phase_stall_seconds: u64_setting(
                &get,
                "FR_PHASE_STALL_SECONDS",
                3_600,
                60,
                604_800,
            )?,
        };
        settings.validate()?;
        Ok(settings)
    }

    /// The reference's startup cross-checks.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.queue_per_tenant_max > self.queue_global_max {
            return Err(ConfigError::Invalid {
                name: "MCP_QUEUE_PER_TENANT_MAX",
                reason: "per-tenant queue exceeds the global queue".into(),
            });
        }
        if self.sync_wait >= self.protocol_timeout {
            return Err(ConfigError::Invalid {
                name: "MCP_SYNC_WAIT_SECONDS",
                reason: "sync wait must be shorter than the protocol timeout".into(),
            });
        }
        Ok(())
    }
}

/// The worker process's settings from the reference `Settings` (`src/config.py`), minus the
/// queue, timeout and retention bounds [`ExecutionSettings`] already carries.
///
/// Env names are the reference's (`MCP_` prefix), and so are the defaults. The reference
/// validates its cross-setting rules at startup; [`WorkerSettings::validate`] mirrors them and
/// adds the worker-start rule that a process needs an explicit credential source
/// (`src/execution/worker.py:run`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkerSettings {
    /// `MCP_WORKER_PROBE_PORT` (1024 to 65535, default 8034): the worker's health probe port.
    pub probe_port: u16,
    /// `MCP_WORKER_MAX_INFLIGHT` (1 to 128, default 8): runs or local controller tasks one
    /// worker process drives at once.
    pub max_inflight: u32,
    /// `MCP_EXECUTION_GLOBAL_SLOTS` (1 to 128, default 1): runner slots across all tenants.
    pub global_slots: u32,
    /// `MCP_EXECUTION_PER_TENANT_SLOTS` (1 to 32, at most the global slots, default 1): runner
    /// slots one tenant may hold.
    pub per_tenant_slots: u32,
    /// `MCP_RUN_START_TIMEOUT_SECONDS` (1 to 120, default 30): bound on starting one run.
    pub run_start_timeout: Duration,
    /// `MCP_RUN_MAX_SECONDS` (1 to 300, default 60): bound on one Kata run's lifetime.
    pub run_max: Duration,
    /// `MCP_LEASE_SECONDS` (10 to 300, default 30): how long a claimed run's lease holds.
    pub lease: Duration,
    /// `MCP_HEARTBEAT_SECONDS` (1 to 60, default 5): lease renewal interval; three intervals
    /// must fit inside one lease.
    pub heartbeat: Duration,
    /// `MCP_RECONCILE_SECONDS` (1 to 60, default 10): how often orphaned runs are reconciled.
    pub reconcile: Duration,
    /// `MCP_API_MAX_INFLIGHT` (1 to 100, default 8): upstream API calls in flight per run.
    pub api_max_inflight: u32,
    /// `MCP_API_CONCURRENCY_GLOBAL` (1 to 100, default 8): upstream API calls in flight across
    /// the worker.
    pub api_concurrency_global: u32,
    /// `MCP_API_CONCURRENCY_PER_SERVICE` (1 to 100, default 8): upstream API calls in flight to
    /// one service.
    pub api_concurrency_per_service: u32,
    /// `MCP_API_MAX_CALLS_PER_MINUTE` (1 to 10000, default 60): upstream call rate bound.
    pub api_max_calls_per_minute: u32,
    /// `MCP_MAX_API_CALLS_PER_RUN` (0 to 100, default 10): the worker-wide ceiling on upstream
    /// calls one run may journal, narrowed by the authority's own limit.
    pub max_api_calls_per_run: u32,
    /// `MCP_API_TIMEOUT_SECONDS` (1 to 300, default 30): bound on one upstream API call.
    pub api_timeout: Duration,
    /// `MCP_API_MAX_RESPONSE_BYTES` (1 to 10485760, default 262144): bound on one upstream
    /// response body.
    pub api_max_response_bytes: usize,
    /// `MCP_MAX_FRAME_BYTES` (1 to 1048576, default 65536): bound on one runner-protocol frame;
    /// never larger than [`Self::max_output_bytes`].
    pub max_frame_bytes: usize,
    /// `MCP_MAX_OUTPUT_BYTES` (1 to 4194304, default 1048576): bound on a run's captured output.
    pub max_output_bytes: usize,
    /// `MCP_MAX_LOG_BYTES` (1 to 65536, default 8192): bound on a run's captured logs.
    pub max_log_bytes: usize,
    /// `MCP_MAX_FRAMES` (1 to 1000, default 256): bound on the frames one run may exchange.
    pub max_frames: u32,
    /// `MCP_RUN_NAMESPACE` (default `mcp-runs`): the dedicated namespace runner pods live in;
    /// any other value is refused.
    pub run_namespace: String,
    /// `MCP_KATA_RUNTIME_CLASS` (optional): the RuntimeClass runner pods request. Required when
    /// execution is enabled.
    pub kata_runtime_class: Option<String>,
    /// `MCP_RUNNER_IMAGE_DIGEST` (optional): the runner image a run may use. Required when
    /// execution is enabled.
    pub runner_image_digest: Option<String>,
    /// `MCP_APPROVED_RUNNER_IMAGES` (optional, comma-separated, default empty): the runner image
    /// digests a `kata_python` tool may name. Must be non-empty when execution is enabled.
    pub approved_runner_images: Vec<String>,
    /// `MCP_RUN_MEMORY_REQUEST_MI` (32 to 1024, default 256): runner memory request, MiB.
    pub run_memory_request_mi: u32,
    /// `MCP_RUN_MEMORY_LIMIT_MI` (32 to 1024, default 256): runner memory limit, MiB.
    pub run_memory_limit_mi: u32,
    /// `MCP_RUN_CPU_REQUEST` (10 to 1000, default 250): runner CPU request, millicores.
    pub run_cpu_request: u32,
    /// `MCP_RUN_CPU_LIMIT` (10 to 1000, default 250): runner CPU limit, millicores.
    pub run_cpu_limit: u32,
    /// `MCP_CREDENTIAL_BUNDLE_FILE` (optional): the mounted per-tenant credential bundle.
    pub credential_bundle_file: Option<PathBuf>,
    /// The `MCP_LICENCE_MINTER_*` settings for licence-minted credentials.
    pub licence_minter: MinterSettings,
    /// `MCP_SOURCE_SECRET_KEY` (optional): the AES-256-GCM key for stored source tokens, 32
    /// bytes as padded or unpadded base64url.
    pub source_secret_key: Option<String>,
    /// `MCP_BUILDER_OAUTH_TOKEN_MAX_TTL` (30 to 86400 seconds, default 3600): the longest an
    /// OAuth token the tool builder obtains may be reused.
    pub builder_oauth_token_max_ttl: Duration,
    /// `MCP_BUILDER_SOURCE_CALLS_PER_MINUTE` (1 to 100000, default 60): the builder's upstream
    /// call rate bound.
    pub builder_source_calls_per_minute: u32,
    /// `MCP_BUILDER_SOURCE_CONCURRENCY` (1 to 100, default 2): the builder's upstream calls in
    /// flight.
    pub builder_source_concurrency: u32,
    /// `MCP_BUILDER_SERVICE_LIMITS_FILE` (optional): the per-service builder rate-limit table.
    pub service_limits_file: Option<PathBuf>,
}

impl Default for WorkerSettings {
    fn default() -> Self {
        Self {
            probe_port: 8_034,
            max_inflight: 8,
            global_slots: 1,
            per_tenant_slots: 1,
            run_start_timeout: Duration::from_secs(30),
            run_max: Duration::from_secs(60),
            lease: Duration::from_secs(30),
            heartbeat: Duration::from_secs(5),
            reconcile: Duration::from_secs(10),
            api_max_inflight: 8,
            api_concurrency_global: 8,
            api_concurrency_per_service: 8,
            api_max_calls_per_minute: 60,
            max_api_calls_per_run: 10,
            api_timeout: Duration::from_secs(30),
            api_max_response_bytes: 262_144,
            max_frame_bytes: 65_536,
            max_output_bytes: 1_048_576,
            max_log_bytes: 8_192,
            max_frames: 256,
            run_namespace: "mcp-runs".to_owned(),
            kata_runtime_class: None,
            runner_image_digest: None,
            approved_runner_images: Vec::new(),
            run_memory_request_mi: 256,
            run_memory_limit_mi: 256,
            run_cpu_request: 250,
            run_cpu_limit: 250,
            credential_bundle_file: None,
            licence_minter: MinterSettings::default(),
            source_secret_key: None,
            builder_oauth_token_max_ttl: Duration::from_secs(3_600),
            builder_source_calls_per_minute: 60,
            builder_source_concurrency: 2,
            service_limits_file: None,
        }
    }
}

impl WorkerSettings {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`WorkerSettings::from_env`]. Empty values count as unset. The
    /// execution switch is resolved from the same environment, so a plain `from_env` cannot
    /// miss the prerequisites of an enabled worker.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let execution_enabled = execution_enabled_setting(&get)?;
        let settings = Self {
            probe_port: u16_setting(&get, "MCP_WORKER_PROBE_PORT", 8_034, 1_024, 65_535)?,
            max_inflight: u32_setting(&get, "MCP_WORKER_MAX_INFLIGHT", 8, 1, 128)?,
            global_slots: u32_setting(&get, "MCP_EXECUTION_GLOBAL_SLOTS", 1, 1, 128)?,
            per_tenant_slots: positive_u32_setting(&get, "MCP_EXECUTION_PER_TENANT_SLOTS", 1)?,
            run_start_timeout: Duration::from_secs(u64_setting(
                &get,
                "MCP_RUN_START_TIMEOUT_SECONDS",
                30,
                1,
                120,
            )?),
            run_max: Duration::from_secs(u64_setting(&get, "MCP_RUN_MAX_SECONDS", 60, 1, 300)?),
            lease: Duration::from_secs(u64_setting(&get, "MCP_LEASE_SECONDS", 30, 10, 300)?),
            heartbeat: Duration::from_secs(u64::from(positive_u32_setting(
                &get,
                "MCP_HEARTBEAT_SECONDS",
                5,
            )?)),
            reconcile: Duration::from_secs(u64_setting(&get, "MCP_RECONCILE_SECONDS", 10, 1, 60)?),
            api_max_inflight: u32_setting(&get, "MCP_API_MAX_INFLIGHT", 8, 1, 100)?,
            api_concurrency_global: u32_setting(&get, "MCP_API_CONCURRENCY_GLOBAL", 8, 1, 100)?,
            api_concurrency_per_service: u32_setting(
                &get,
                "MCP_API_CONCURRENCY_PER_SERVICE",
                8,
                1,
                100,
            )?,
            api_max_calls_per_minute: u32_setting(
                &get,
                "MCP_API_MAX_CALLS_PER_MINUTE",
                60,
                1,
                10_000,
            )?,
            max_api_calls_per_run: u32_setting(&get, "MCP_MAX_API_CALLS_PER_RUN", 10, 0, 100)?,
            api_timeout: Duration::from_secs(u64_setting(
                &get,
                "MCP_API_TIMEOUT_SECONDS",
                30,
                1,
                300,
            )?),
            api_max_response_bytes: int_setting(
                &get,
                "MCP_API_MAX_RESPONSE_BYTES",
                262_144,
                1,
                10_485_760,
            )?,
            max_frame_bytes: int_setting(&get, "MCP_MAX_FRAME_BYTES", 65_536, 1, 1_048_576)?,
            max_output_bytes: int_setting(&get, "MCP_MAX_OUTPUT_BYTES", 1_048_576, 1, 4_194_304)?,
            max_log_bytes: int_setting(&get, "MCP_MAX_LOG_BYTES", 8_192, 1, 65_536)?,
            max_frames: u32_setting(&get, "MCP_MAX_FRAMES", 256, 1, 1_000)?,
            run_namespace: get("MCP_RUN_NAMESPACE").unwrap_or_else(|| "mcp-runs".to_owned()),
            kata_runtime_class: get("MCP_KATA_RUNTIME_CLASS"),
            runner_image_digest: get("MCP_RUNNER_IMAGE_DIGEST"),
            approved_runner_images: comma_list(get("MCP_APPROVED_RUNNER_IMAGES")),
            run_memory_request_mi: u32_setting(&get, "MCP_RUN_MEMORY_REQUEST_MI", 256, 32, 1_024)?,
            run_memory_limit_mi: u32_setting(&get, "MCP_RUN_MEMORY_LIMIT_MI", 256, 32, 1_024)?,
            run_cpu_request: u32_setting(&get, "MCP_RUN_CPU_REQUEST", 250, 10, 1_000)?,
            run_cpu_limit: u32_setting(&get, "MCP_RUN_CPU_LIMIT", 250, 10, 1_000)?,
            credential_bundle_file: get("MCP_CREDENTIAL_BUNDLE_FILE").map(PathBuf::from),
            licence_minter: MinterSettings::from_lookup(|key| get(key))?,
            source_secret_key: get("MCP_SOURCE_SECRET_KEY"),
            builder_oauth_token_max_ttl: Duration::from_secs(u64_setting(
                &get,
                "MCP_BUILDER_OAUTH_TOKEN_MAX_TTL",
                3_600,
                30,
                86_400,
            )?),
            builder_source_calls_per_minute: u32_setting(
                &get,
                "MCP_BUILDER_SOURCE_CALLS_PER_MINUTE",
                60,
                1,
                100_000,
            )?,
            builder_source_concurrency: u32_setting(
                &get,
                "MCP_BUILDER_SOURCE_CONCURRENCY",
                2,
                1,
                100,
            )?,
            service_limits_file: get("MCP_BUILDER_SERVICE_LIMITS_FILE").map(PathBuf::from),
        };
        if let Some(value) = &settings.source_secret_key {
            decode_source_secret_key(value)?;
        }
        settings.validate(execution_enabled)?;
        Ok(settings)
    }

    /// The reference's startup cross-checks (`src/config.py:316-333`), plus the worker-start
    /// rule from `src/execution/worker.py:run`. `execution_enabled` is the resolved
    /// `EXECUTION_ENABLED`/`MCP_EXECUTION_ENABLED` switch.
    pub fn validate(&self, execution_enabled: bool) -> Result<(), ConfigError> {
        if self.heartbeat.saturating_mul(3) >= self.lease {
            return Err(ConfigError::Invalid {
                name: "MCP_HEARTBEAT_SECONDS",
                reason: "lease must be longer than three heartbeat intervals".into(),
            });
        }
        if self.per_tenant_slots > 32 {
            return Err(ConfigError::Invalid {
                name: "MCP_EXECUTION_PER_TENANT_SLOTS",
                reason: "per-tenant slots exceed 32".into(),
            });
        }
        if self.per_tenant_slots > self.global_slots {
            return Err(ConfigError::Invalid {
                name: "MCP_EXECUTION_PER_TENANT_SLOTS",
                reason: "per-tenant slots exceed the global slots".into(),
            });
        }
        if self.heartbeat > Duration::from_secs(60) {
            return Err(ConfigError::Invalid {
                name: "MCP_HEARTBEAT_SECONDS",
                reason: "heartbeat exceeds 60 seconds".into(),
            });
        }
        if self.max_frame_bytes > self.max_output_bytes {
            return Err(ConfigError::Invalid {
                name: "MCP_MAX_FRAME_BYTES",
                reason: "frame limit exceeds the aggregate output limit".into(),
            });
        }
        if self.run_memory_request_mi > self.run_memory_limit_mi {
            return Err(ConfigError::Invalid {
                name: "MCP_RUN_MEMORY_REQUEST_MI",
                reason: "runner requests exceed limits".into(),
            });
        }
        if self.run_cpu_request > self.run_cpu_limit {
            return Err(ConfigError::Invalid {
                name: "MCP_RUN_CPU_REQUEST",
                reason: "runner requests exceed limits".into(),
            });
        }
        if self.run_namespace != "mcp-runs" {
            return Err(ConfigError::Invalid {
                name: "MCP_RUN_NAMESPACE",
                reason: "execution requires the dedicated mcp-runs namespace".into(),
            });
        }
        if execution_enabled && self.approved_runner_images.is_empty() {
            return Err(ConfigError::Invalid {
                name: "MCP_APPROVED_RUNNER_IMAGES",
                reason: "execution requires approved runner images".into(),
            });
        }
        if execution_enabled && self.kata_runtime_class.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_KATA_RUNTIME_CLASS",
                reason: "execution requires a Kata runtime class".into(),
            });
        }
        if execution_enabled && self.runner_image_digest.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_RUNNER_IMAGE_DIGEST",
                reason: "execution requires a runner image digest".into(),
            });
        }
        self.licence_minter.validate()?;
        if execution_enabled
            && self.credential_bundle_file.is_none()
            && !self.licence_minter.enabled
        {
            return Err(ConfigError::Invalid {
                name: "MCP_CREDENTIAL_BUNDLE_FILE",
                reason: "a worker requires a credential bundle file or the licence minter".into(),
            });
        }
        Ok(())
    }
}

/// Licence-minted per-tenant broker credentials, the reference's `licence_minter_*` settings
/// (`src/credentials/minter.py`).
///
/// Off by default: the mounted [`WorkerSettings::credential_bundle_file`] is the credential
/// source until an operator enables minting. Env names carry the reference's `MCP_` prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MinterSettings {
    /// `MCP_LICENCE_MINTER_ENABLED` (default false): mint credentials per tenant from licences.
    pub enabled: bool,
    /// `MCP_LICENCE_MINTER_URL` (required when enabled): the licences service base URL.
    pub url: Option<String>,
    /// `MCP_LICENCE_MINTER_TOKEN_URL` (required when enabled): the client-credentials token URL.
    pub token_url: Option<String>,
    /// `MCP_LICENCE_MINTER_CLIENT_ID` (default `mcp-bundle-minter`): the Keycloak client the
    /// minter authenticates as.
    pub client_id: String,
    /// `MCP_LICENCE_MINTER_SECRET_FILE` (required when enabled): the mounted client secret.
    pub secret_file: Option<PathBuf>,
    /// `MCP_LICENCE_MINTER_TTL_MINUTES` (1 to 60, default 15): the lifetime requested for a
    /// minted credential.
    pub ttl: Duration,
    /// `MCP_LICENCE_MINTER_SKEW_SECONDS` (0 to 300, default 30): renew a credential this early.
    pub skew: Duration,
}

impl Default for MinterSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            url: None,
            token_url: None,
            client_id: "mcp-bundle-minter".to_owned(),
            secret_file: None,
            ttl: Duration::from_secs(15 * 60),
            skew: Duration::from_secs(30),
        }
    }
}

impl MinterSettings {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`MinterSettings::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let settings = Self {
            enabled: bool_setting(&get, "MCP_LICENCE_MINTER_ENABLED", false)?,
            url: get("MCP_LICENCE_MINTER_URL"),
            token_url: get("MCP_LICENCE_MINTER_TOKEN_URL"),
            client_id: get("MCP_LICENCE_MINTER_CLIENT_ID")
                .unwrap_or_else(|| "mcp-bundle-minter".to_owned()),
            secret_file: get("MCP_LICENCE_MINTER_SECRET_FILE").map(PathBuf::from),
            ttl: Duration::from_secs(
                u64_setting(&get, "MCP_LICENCE_MINTER_TTL_MINUTES", 15, 1, 60)? * 60,
            ),
            skew: Duration::from_secs(u64_setting(
                &get,
                "MCP_LICENCE_MINTER_SKEW_SECONDS",
                30,
                0,
                300,
            )?),
        };
        settings.validate()?;
        Ok(settings)
    }

    /// When enabled, minting requires the licences URL, the token URL and the client secret
    /// file, and both URLs must be http(s) authorities (the reference's `checked_url`).
    pub fn validate(&self) -> Result<(), ConfigError> {
        if !self.enabled {
            return Ok(());
        }
        if self.url.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_URL",
                reason: "licence minting requires the licences URL".into(),
            });
        }
        if self.token_url.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_TOKEN_URL",
                reason: "licence minting requires the token URL".into(),
            });
        }
        if self.secret_file.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_SECRET_FILE",
                reason: "licence minting requires the client secret file".into(),
            });
        }
        if let Some(url) = &self.url {
            checked_http_url("MCP_LICENCE_MINTER_URL", url)?;
        }
        if let Some(url) = &self.token_url {
            checked_http_url("MCP_LICENCE_MINTER_TOKEN_URL", url)?;
        }
        Ok(())
    }
}

/// Authentication configuration for the `/mcp` surface.
///
/// Env names are the reference service's `src/config.py` names: pydantic-settings with prefix
/// `MCP_`, except the two fields that carry an explicit unprefixed alias
/// (`LICENSE_INTROSPECT_URL`). Omitted authentication settings keep protected work disabled —
/// there is no bypass: an unconfigured authority answers 503.
#[derive(Debug, Clone)]
pub struct AuthConfig {
    /// `LICENSE_INTROSPECT_URL`: the licence authority's introspection endpoint.
    pub license_introspect_url: Option<String>,
    /// `MCP_LICENSE_APP_KEY`: the app key this service introspects licences for.
    pub license_app_key: Option<String>,
    /// `MCP_LICENSE_ALLOW_HTTP`: permit an `http://` introspection URL (in-cluster only).
    pub license_allow_http: bool,
    /// `MCP_LICENSE_TIMEOUT_SECONDS`: bound on one introspection call.
    pub license_timeout: Duration,
    /// `MCP_LICENSE_MAX_RESPONSE_BYTES`: bound on the introspection response body.
    pub license_max_response_bytes: usize,
    /// `MCP_LICENSE_EXPIRY_SKEW_SECONDS`: treat licences as expired this early.
    pub license_expiry_skew: Duration,
    /// `MCP_ADMIN_KEY_FILE`: mounted operator key file, read once at startup.
    pub admin_key_file: Option<PathBuf>,
    /// `MCP_ADMIN_TENANT_IDS`: JSON list of tenant UUIDs allowed to operate management.
    pub admin_tenant_ids: Vec<Rfc4122Uuid>,
    /// `MCP_PLATFORM_ADMIN_KEY_FILE`: raises a management principal to platform.
    pub platform_admin_key_file: Option<PathBuf>,
    /// `MCP_MAX_MANAGEMENT_BYTES`: bound on a buffered management request body.
    pub max_management_bytes: usize,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            license_introspect_url: None,
            license_app_key: None,
            license_allow_http: false,
            license_timeout: Duration::from_secs(3),
            license_max_response_bytes: 65_536,
            license_expiry_skew: Duration::from_secs(2),
            admin_key_file: None,
            admin_tenant_ids: Vec::new(),
            platform_admin_key_file: None,
            max_management_bytes: 262_144,
        }
    }
}

impl AuthConfig {
    pub fn from_env() -> Result<Self, ConfigError> {
        Self::from_lookup(|k| std::env::var(k).ok())
    }

    /// Testable core of [`AuthConfig::from_env`]. Empty values count as unset.
    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Self, ConfigError> {
        let get = |k: &str| get(k).filter(|v| !v.trim().is_empty());
        let timeout_seconds = float_setting(&get, "MCP_LICENSE_TIMEOUT_SECONDS", 3.0, 0.0, 10.0)?;
        let config = Self {
            license_introspect_url: get("LICENSE_INTROSPECT_URL"),
            license_app_key: get("MCP_LICENSE_APP_KEY"),
            license_allow_http: bool_setting(&get, "MCP_LICENSE_ALLOW_HTTP", false)?,
            license_timeout: Duration::from_secs_f64(timeout_seconds),
            license_max_response_bytes: int_setting(
                &get,
                "MCP_LICENSE_MAX_RESPONSE_BYTES",
                65_536,
                1,
                1_048_576,
            )?,
            license_expiry_skew: Duration::from_secs(u64_setting(
                &get,
                "MCP_LICENSE_EXPIRY_SKEW_SECONDS",
                2,
                0,
                30,
            )?),
            admin_key_file: get("MCP_ADMIN_KEY_FILE").map(PathBuf::from),
            admin_tenant_ids: tenant_ids(get("MCP_ADMIN_TENANT_IDS"))?,
            platform_admin_key_file: get("MCP_PLATFORM_ADMIN_KEY_FILE").map(PathBuf::from),
            max_management_bytes: int_setting(
                &get,
                "MCP_MAX_MANAGEMENT_BYTES",
                262_144,
                1,
                1_048_576,
            )?,
        };
        config.validate()?;
        Ok(config)
    }

    /// The cross-setting rules the reference service validates at startup.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.license_introspect_url.is_some() != self.license_app_key.is_some() {
            return Err(ConfigError::Invalid {
                name: "LICENSE_INTROSPECT_URL",
                reason: "license introspection URL and application key must be configured together"
                    .into(),
            });
        }
        if let Some(url) = &self.license_introspect_url {
            checked_authority_url(url, self.license_allow_http)?;
        }
        if self.admin_key_file.is_some()
            && (self.license_app_key.is_none() || self.admin_tenant_ids.is_empty())
        {
            return Err(ConfigError::Invalid {
                name: "MCP_ADMIN_KEY_FILE",
                reason: "management requires license authentication and an explicit tenant".into(),
            });
        }
        if self.platform_admin_key_file.is_some() && self.admin_key_file.is_none() {
            return Err(ConfigError::Invalid {
                name: "MCP_PLATFORM_ADMIN_KEY_FILE",
                reason: "platform authorization requires management authorization".into(),
            });
        }
        Ok(())
    }
}

/// An authority URL: HTTPS, or HTTP only when explicitly approved for an in-cluster endpoint.
/// Credentials, query strings and fragments are refused (the reference service's `checked_url`).
fn checked_authority_url(value: &str, allow_http: bool) -> Result<(), ConfigError> {
    let invalid = |reason: &str| ConfigError::Invalid {
        name: "LICENSE_INTROSPECT_URL",
        reason: reason.to_owned(),
    };
    let rest = if let Some(rest) = value.strip_prefix("https://") {
        rest
    } else if allow_http {
        match value.strip_prefix("http://") {
            Some(rest) => rest,
            None => {
                return Err(invalid(
                    "authority URLs require HTTPS or explicitly approved internal HTTP",
                ));
            }
        }
    } else {
        return Err(invalid(
            "authority URLs require HTTPS or explicitly approved internal HTTP",
        ));
    };
    if value.contains('#') || value.contains('?') {
        return Err(invalid("authority URLs must not carry a fragment or query"));
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid("authority URLs require a host and no credentials"));
    }
    Ok(())
}

/// An http(s) URL with a host and no credentials, query string or fragment: the reference's
/// `checked_url`, with both schemes allowed (unlike [`checked_authority_url`]).
fn checked_http_url(name: &'static str, value: &str) -> Result<(), ConfigError> {
    let invalid = |reason: &str| ConfigError::Invalid {
        name,
        reason: reason.to_owned(),
    };
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .ok_or_else(|| invalid("URLs require http or https"))?;
    if value.contains('#') || value.contains('?') {
        return Err(invalid("URLs must not carry a fragment or query"));
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() || authority.contains('@') {
        return Err(invalid("URLs require a host and no credentials"));
    }
    let host = match authority.strip_prefix('[') {
        Some(bracketed) => bracketed.split(']').next().unwrap_or_default(),
        None => authority.split(':').next().unwrap_or_default(),
    };
    if host.is_empty() {
        return Err(invalid("URLs require a host"));
    }
    Ok(())
}

/// A comma-separated list: surrounding whitespace is trimmed and empty entries are dropped.
fn comma_list(raw: Option<String>) -> Vec<String> {
    raw.map(|value| {
        value
            .split(',')
            .map(str::trim)
            .filter(|entry| !entry.is_empty())
            .map(str::to_owned)
            .collect()
    })
    .unwrap_or_default()
}

fn tenant_ids(raw: Option<String>) -> Result<Vec<Rfc4122Uuid>, ConfigError> {
    let Some(raw) = raw else {
        return Ok(Vec::new());
    };
    let invalid = |reason: String| ConfigError::Invalid {
        name: "MCP_ADMIN_TENANT_IDS",
        reason,
    };
    let values: Vec<String> = serde_json::from_str(&raw)
        .map_err(|e| invalid(format!("expected a JSON list of UUIDs: {e}")))?;
    values
        .iter()
        .map(|value| {
            Rfc4122Uuid::parse(value)
                .ok_or_else(|| invalid(format!("{value:?} is not an RFC 4122 UUID")))
        })
        .collect()
}

/// A 32-byte AES-256-GCM key from padded or unpadded base64url (the reference's
/// `sources/crypto.py:decode_key`).
fn decode_source_secret_key(value: &str) -> Result<(), ConfigError> {
    let invalid = |reason: &str| ConfigError::Invalid {
        name: "MCP_SOURCE_SECRET_KEY",
        reason: reason.to_owned(),
    };
    let mut padded = value.trim().to_owned();
    match padded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        _ => return Err(invalid("must be base64url")),
    }
    let key = URL_SAFE
        .decode(padded.as_bytes())
        .map_err(|_| invalid("must be base64url"))?;
    if key.len() != 32 {
        return Err(invalid("must decode to 32 bytes"));
    }
    Ok(())
}

fn bool_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => bool_value(name, &value),
    }
}

/// One boolean setting's accepted spellings: `true`/`false` in any case, and `1`/`0`.
fn bool_value(name: &'static str, value: &str) -> Result<bool, ConfigError> {
    if value.eq_ignore_ascii_case("true") || value == "1" {
        Ok(true)
    } else if value.eq_ignore_ascii_case("false") || value == "0" {
        Ok(false)
    } else {
        Err(ConfigError::Invalid {
            name,
            reason: format!("{value:?} is not one of true/false/1/0"),
        })
    }
}

/// The execution switch, shared by [`Config`] and [`WorkerSettings`]. `EXECUTION_ENABLED` is
/// this service's name; the reference's prefixed `MCP_EXECUTION_ENABLED` is accepted as an alias
/// during the drop-in cutover, and the unprefixed name wins when both are set.
fn execution_enabled_setting(get: &impl Fn(&str) -> Option<String>) -> Result<bool, ConfigError> {
    match (get("EXECUTION_ENABLED"), get("MCP_EXECUTION_ENABLED")) {
        (Some(value), _) => bool_value("EXECUTION_ENABLED", &value),
        (None, Some(value)) => bool_value("MCP_EXECUTION_ENABLED", &value),
        (None, None) => Ok(false),
    }
}

fn int_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<usize>() {
            Ok(parsed) if (minimum..=maximum).contains(&parsed) => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not an integer in {minimum}..={maximum}"),
            }),
        },
    }
}

fn u32_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u32,
    minimum: u32,
    maximum: u32,
) -> Result<u32, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<u32>() {
            Ok(parsed) if (minimum..=maximum).contains(&parsed) => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not an integer in {minimum}..={maximum}"),
            }),
        },
    }
}

fn u16_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u16,
    minimum: u16,
    maximum: u16,
) -> Result<u16, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<u16>() {
            Ok(parsed) if (minimum..=maximum).contains(&parsed) => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not an integer in {minimum}..={maximum}"),
            }),
        },
    }
}

/// A strictly positive `u32`: the reference uses `gt=0` without an upper bound for a few
/// settings (per-tenant slots, heartbeat), whose real limit is a cross-setting rule.
fn positive_u32_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u32,
) -> Result<u32, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<u32>() {
            Ok(parsed) if parsed > 0 => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not a positive integer"),
            }),
        },
    }
}

/// The reference's reserved platform tenant, the owner of platform toolkits.
pub(crate) fn default_platform_tenant_id() -> Rfc4122Uuid {
    Rfc4122Uuid::parse("01900000-0000-7000-8000-00000000f001")
        .expect("the default platform tenant is a valid RFC 4122 UUID")
}

fn positive_int_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: usize,
) -> Result<usize, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<usize>() {
            Ok(parsed) if parsed > 0 => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not a positive integer"),
            }),
        },
    }
}

fn u64_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<u64>() {
            Ok(parsed) if (minimum..=maximum).contains(&parsed) => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not an integer in {minimum}..={maximum}"),
            }),
        },
    }
}

fn float_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: f64,
    minimum: f64,
    maximum: f64,
) -> Result<f64, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<f64>() {
            Ok(parsed) if parsed.is_finite() && parsed > minimum && parsed <= maximum => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not a number in ({minimum}, {maximum}]"),
            }),
        },
    }
}

/// Like [`float_setting`], but with inclusive bounds: a synchronous wait may be exactly zero
/// and the external poll interval may be exactly its minimum.
fn bounded_float_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: f64,
    minimum: f64,
    maximum: f64,
) -> Result<f64, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) => match value.trim().parse::<f64>() {
            Ok(parsed) if parsed.is_finite() && (minimum..=maximum).contains(&parsed) => Ok(parsed),
            _ => Err(ConfigError::Invalid {
                name,
                reason: format!("{value:?} is not a number in {minimum}..={maximum}"),
            }),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn cfg(pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        Config::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn requires_database_url_and_bind_addr() {
        assert_eq!(
            cfg(&[("BIND_ADDR", "127.0.0.1:9")]).unwrap_err(),
            ConfigError::Missing("DATABASE_URL")
        );
        assert_eq!(
            cfg(&[("DATABASE_URL", "postgres://x")]).unwrap_err(),
            ConfigError::Missing("BIND_ADDR")
        );
        assert_eq!(
            cfg(&[("DATABASE_URL", "postgres://x"), ("BIND_ADDR", " ")]).unwrap_err(),
            ConfigError::Missing("BIND_ADDR")
        );
    }

    #[test]
    fn parses_bind_addr_and_optional_migrate_url() {
        let c = cfg(&[("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")]).unwrap();
        assert_eq!(c.bind_addr.port(), 9);
        assert_eq!(c.database_migrate_url, None);
        assert!(matches!(
            cfg(&[("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "nope")]),
            Err(ConfigError::Invalid { .. })
        ));
    }

    #[test]
    fn package_limits_take_reference_defaults_and_env_names() {
        let base = [("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")];
        let defaults = cfg(&base).unwrap().packages;
        assert_eq!(defaults, PackageLimits::default());
        assert_eq!(defaults.max_package_files, 64);
        assert_eq!(defaults.max_package_file_bytes, 262_144);
        assert_eq!(defaults.max_package_bytes, 1_048_576);

        let mut pairs = base.to_vec();
        pairs.extend_from_slice(&[
            ("MCP_MAX_PACKAGE_FILES", "2"),
            ("MCP_MAX_PACKAGE_FILE_BYTES", "10"),
            ("MCP_MAX_PACKAGE_BYTES", "20"),
        ]);
        let configured = cfg(&pairs).unwrap().packages;
        assert_eq!(configured.max_package_files, 2);
        assert_eq!(configured.max_package_file_bytes, 10);
        assert_eq!(configured.max_package_bytes, 20);
    }

    #[test]
    fn approved_runner_images_default_empty_and_parse_a_comma_separated_list() {
        let base = [("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")];
        assert!(cfg(&base).unwrap().approved_runner_images.is_empty());

        let mut pairs = base.to_vec();
        pairs.push((
            "MCP_APPROVED_RUNNER_IMAGES",
            "registry.example/runner@sha256:aaa, registry.example/other@sha256:bbb ,",
        ));
        assert_eq!(
            cfg(&pairs).unwrap().approved_runner_images,
            vec![
                "registry.example/runner@sha256:aaa".to_owned(),
                "registry.example/other@sha256:bbb".to_owned(),
            ]
        );
    }

    #[test]
    fn package_limits_are_positive_and_a_file_may_not_exceed_its_package() {
        let base = [("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")];
        let with = |name: &'static str, value: &'static str| {
            let mut pairs = base.to_vec();
            pairs.push((name, value));
            cfg(&pairs)
        };
        for value in ["0", "-1", "1.5", "many"] {
            assert!(
                with("MCP_MAX_PACKAGE_FILES", value).is_err(),
                "MCP_MAX_PACKAGE_FILES={value}"
            );
            assert!(
                with("MCP_MAX_PACKAGE_FILE_BYTES", value).is_err(),
                "MCP_MAX_PACKAGE_FILE_BYTES={value}"
            );
            assert!(
                with("MCP_MAX_PACKAGE_BYTES", value).is_err(),
                "MCP_MAX_PACKAGE_BYTES={value}"
            );
        }
        // `max_package_file_bytes <= max_package_bytes` is the reference's consistent-limits rule.
        let over = [
            ("DATABASE_URL", "postgres://x"),
            ("BIND_ADDR", "0.0.0.0:9"),
            ("MCP_MAX_PACKAGE_FILE_BYTES", "21"),
            ("MCP_MAX_PACKAGE_BYTES", "20"),
        ];
        assert_eq!(
            cfg(&over).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_MAX_PACKAGE_FILE_BYTES",
                reason: "file limit exceeds package limit".into(),
            }
        );
        let equal = [
            ("DATABASE_URL", "postgres://x"),
            ("BIND_ADDR", "0.0.0.0:9"),
            ("MCP_MAX_PACKAGE_FILE_BYTES", "20"),
            ("MCP_MAX_PACKAGE_BYTES", "20"),
        ];
        assert!(cfg(&equal).is_ok());
    }

    fn auth_cfg(pairs: &[(&str, &str)]) -> Result<AuthConfig, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        AuthConfig::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn auth_defaults_are_disabled_and_valid() {
        let c = AuthConfig::default();
        assert!(c.validate().is_ok());
        assert_eq!(c.license_timeout, Duration::from_secs(3));
        assert_eq!(c.max_management_bytes, 262_144);
    }

    #[test]
    fn auth_requires_url_and_app_key_together() {
        assert!(
            auth_cfg(&[("MCP_LICENSE_APP_KEY", "mcp")]).is_err(),
            "app key without a URL"
        );
        assert!(
            auth_cfg(&[("LICENSE_INTROSPECT_URL", "https://x/introspect")]).is_err(),
            "URL without an app key"
        );
    }

    #[test]
    fn auth_checks_the_introspection_url_scheme() {
        assert!(
            auth_cfg(&[
                (
                    "LICENSE_INTROSPECT_URL",
                    "http://licenses.svc:8544/license/introspect"
                ),
                ("MCP_LICENSE_APP_KEY", "mcp"),
            ])
            .is_err(),
            "http without explicit approval"
        );
        assert!(
            auth_cfg(&[
                (
                    "LICENSE_INTROSPECT_URL",
                    "http://licenses.svc:8544/license/introspect"
                ),
                ("MCP_LICENSE_APP_KEY", "mcp"),
                ("MCP_LICENSE_ALLOW_HTTP", "true"),
            ])
            .is_ok()
        );
        assert!(
            auth_cfg(&[
                ("LICENSE_INTROSPECT_URL", "https://x/introspect?tenant=1"),
                ("MCP_LICENSE_APP_KEY", "mcp"),
            ])
            .is_err(),
            "query string"
        );
    }

    #[test]
    fn auth_management_requires_licence_auth_and_a_tenant_list() {
        let dir = std::env::temp_dir();
        let key = dir.join(format!("mcp-auth-cfg-key-{}", std::process::id()));
        std::fs::write(&key, "a".repeat(32)).unwrap();
        let key = key.to_str().unwrap();
        assert!(
            auth_cfg(&[("MCP_ADMIN_KEY_FILE", key)]).is_err(),
            "no licence authentication"
        );
        assert!(
            auth_cfg(&[
                ("MCP_ADMIN_KEY_FILE", key),
                ("MCP_LICENSE_APP_KEY", "mcp"),
                ("LICENSE_INTROSPECT_URL", "https://x/introspect"),
            ])
            .is_err(),
            "no tenant allowlist"
        );
        let with_tenants = |extra: &[(&str, &str)]| {
            let mut pairs = vec![
                ("MCP_ADMIN_KEY_FILE", key),
                ("MCP_LICENSE_APP_KEY", "mcp"),
                ("LICENSE_INTROSPECT_URL", "https://x/introspect"),
                (
                    "MCP_ADMIN_TENANT_IDS",
                    r#"["5f868d42-03f8-51f0-a93c-3e83070dc196"]"#,
                ),
            ];
            pairs.extend_from_slice(extra);
            auth_cfg(&pairs)
        };
        assert!(with_tenants(&[]).is_ok());
        assert!(
            with_tenants(&[("MCP_PLATFORM_ADMIN_KEY_FILE", key)]).is_ok(),
            "platform key requires management, which is configured"
        );
        let _ = std::fs::remove_file(key);
    }

    fn exec_settings(pairs: &[(&str, &str)]) -> Result<ExecutionSettings, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        ExecutionSettings::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn execution_settings_take_reference_defaults_and_env_names() {
        let defaults = ExecutionSettings::default();
        assert_eq!(defaults.sync_wait, Duration::ZERO);
        assert_eq!(defaults.protocol_timeout, Duration::from_secs(15));
        assert_eq!(defaults.queue_global_max, 100);
        assert_eq!(defaults.queue_per_tenant_max, 20);
        assert_eq!(defaults.run_queue_timeout, Duration::from_secs(240));
        assert_eq!(defaults.retention_days, 7);
        assert_eq!(defaults.task_poll_interval_ms, 2_000);
        assert_eq!(defaults.external_poll_seconds, 5.0);
        assert_eq!(defaults.protocol_output_bytes, 2_097_152);
        assert_eq!(defaults.max_result_bytes, 262_144);
        assert!(!defaults.tasks_enabled);
        assert_eq!(exec_settings(&[]).unwrap(), defaults);
        let base = [("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")];
        assert_eq!(cfg(&base).unwrap().execution, defaults);

        let configured = exec_settings(&[
            ("MCP_SYNC_WAIT_SECONDS", "2.5"),
            ("MCP_PROTOCOL_TIMEOUT_SECONDS", "30"),
            ("MCP_QUEUE_GLOBAL_MAX", "200"),
            ("MCP_QUEUE_PER_TENANT_MAX", "40"),
            ("MCP_RUN_QUEUE_TIMEOUT_SECONDS", "120"),
            ("MCP_EXECUTION_RETENTION_DAYS", "14"),
            ("MCP_TASK_POLL_INTERVAL_MS", "5000"),
            ("MCP_EXTERNAL_POLL_SECONDS", "10"),
            ("MCP_PROTOCOL_OUTPUT_BYTES", "4096"),
            ("MCP_MAX_RESULT_BYTES", "1024"),
            ("MCP_TASKS_ENABLED", "true"),
        ])
        .unwrap();
        assert_eq!(configured.sync_wait, Duration::from_millis(2_500));
        assert_eq!(configured.protocol_timeout, Duration::from_secs(30));
        assert_eq!(configured.queue_global_max, 200);
        assert_eq!(configured.queue_per_tenant_max, 40);
        assert_eq!(configured.run_queue_timeout, Duration::from_secs(120));
        assert_eq!(configured.retention_days, 14);
        assert_eq!(configured.task_poll_interval_ms, 5_000);
        assert_eq!(configured.external_poll_seconds, 10.0);
        assert_eq!(configured.protocol_output_bytes, 4_096);
        assert_eq!(configured.max_result_bytes, 1_024);
        assert!(configured.tasks_enabled);
    }

    #[test]
    fn execution_settings_refuse_every_out_of_range_bound() {
        for (name, value) in [
            ("MCP_SYNC_WAIT_SECONDS", "-1"),
            ("MCP_SYNC_WAIT_SECONDS", "300.5"),
            ("MCP_PROTOCOL_TIMEOUT_SECONDS", "0"),
            ("MCP_PROTOCOL_TIMEOUT_SECONDS", "361"),
            ("MCP_QUEUE_GLOBAL_MAX", "0"),
            ("MCP_QUEUE_GLOBAL_MAX", "10001"),
            ("MCP_QUEUE_PER_TENANT_MAX", "0"),
            ("MCP_QUEUE_PER_TENANT_MAX", "1001"),
            ("MCP_RUN_QUEUE_TIMEOUT_SECONDS", "0"),
            ("MCP_RUN_QUEUE_TIMEOUT_SECONDS", "601"),
            ("MCP_EXECUTION_RETENTION_DAYS", "0"),
            ("MCP_EXECUTION_RETENTION_DAYS", "366"),
            ("MCP_TASK_POLL_INTERVAL_MS", "499"),
            ("MCP_TASK_POLL_INTERVAL_MS", "60001"),
            ("MCP_EXTERNAL_POLL_SECONDS", "0.5"),
            ("MCP_EXTERNAL_POLL_SECONDS", "301"),
            ("MCP_PROTOCOL_OUTPUT_BYTES", "0"),
            ("MCP_PROTOCOL_OUTPUT_BYTES", "8388609"),
            ("MCP_MAX_RESULT_BYTES", "0"),
            ("MCP_MAX_RESULT_BYTES", "1048577"),
            ("MCP_TASKS_ENABLED", "maybe"),
            ("MCP_QUEUE_GLOBAL_MAX", "many"),
        ] {
            assert!(
                exec_settings(&[(name, value)]).is_err(),
                "{name}={value} must be refused"
            );
        }
    }

    #[test]
    fn execution_settings_cross_check_queue_and_timeouts() {
        // One tenant can never hold more than the global queue; equality is allowed.
        assert!(
            exec_settings(&[
                ("MCP_QUEUE_GLOBAL_MAX", "10"),
                ("MCP_QUEUE_PER_TENANT_MAX", "11")
            ])
            .is_err()
        );
        assert!(
            exec_settings(&[
                ("MCP_QUEUE_GLOBAL_MAX", "10"),
                ("MCP_QUEUE_PER_TENANT_MAX", "10")
            ])
            .is_ok()
        );
        // The synchronous wait must end before the protocol timeout does; equality is refused.
        assert!(
            exec_settings(&[
                ("MCP_SYNC_WAIT_SECONDS", "15"),
                ("MCP_PROTOCOL_TIMEOUT_SECONDS", "15")
            ])
            .is_err()
        );
        assert!(
            exec_settings(&[
                ("MCP_SYNC_WAIT_SECONDS", "14.5"),
                ("MCP_PROTOCOL_TIMEOUT_SECONDS", "15")
            ])
            .is_ok()
        );
    }

    #[test]
    fn execution_enabled_accepts_the_prefixed_alias() {
        let base = [("DATABASE_URL", "postgres://x"), ("BIND_ADDR", "0.0.0.0:9")];
        assert!(!cfg(&base).unwrap().execution_enabled, "default off");

        let mut pairs = base.to_vec();
        pairs.push(("MCP_EXECUTION_ENABLED", "true"));
        assert!(cfg(&pairs).unwrap().execution_enabled, "alias alone");

        // The unprefixed name is the service's own and wins when both are set.
        let mut pairs = base.to_vec();
        pairs.push(("EXECUTION_ENABLED", "false"));
        pairs.push(("MCP_EXECUTION_ENABLED", "true"));
        assert!(!cfg(&pairs).unwrap().execution_enabled);

        let mut pairs = base.to_vec();
        pairs.push(("MCP_EXECUTION_ENABLED", "not-a-bool"));
        assert_eq!(
            cfg(&pairs).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_EXECUTION_ENABLED",
                reason: "\"not-a-bool\" is not one of true/false/1/0".into(),
            }
        );
    }

    fn worker_settings(pairs: &[(&str, &str)]) -> Result<WorkerSettings, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        WorkerSettings::from_lookup(|k| m.get(k).cloned())
    }

    fn minter_settings(pairs: &[(&str, &str)]) -> Result<MinterSettings, ConfigError> {
        let m: HashMap<String, String> = pairs
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect();
        MinterSettings::from_lookup(|k| m.get(k).cloned())
    }

    #[test]
    fn worker_settings_take_reference_defaults() {
        let defaults = WorkerSettings::default();
        assert_eq!(defaults.probe_port, 8_034);
        assert_eq!(defaults.max_inflight, 8);
        assert_eq!(defaults.global_slots, 1);
        assert_eq!(defaults.per_tenant_slots, 1);
        assert_eq!(defaults.run_start_timeout, Duration::from_secs(30));
        assert_eq!(defaults.run_max, Duration::from_secs(60));
        assert_eq!(defaults.lease, Duration::from_secs(30));
        assert_eq!(defaults.heartbeat, Duration::from_secs(5));
        assert_eq!(defaults.reconcile, Duration::from_secs(10));
        assert_eq!(defaults.api_max_inflight, 8);
        assert_eq!(defaults.api_concurrency_global, 8);
        assert_eq!(defaults.api_concurrency_per_service, 8);
        assert_eq!(defaults.api_max_calls_per_minute, 60);
        assert_eq!(defaults.api_timeout, Duration::from_secs(30));
        assert_eq!(defaults.api_max_response_bytes, 262_144);
        assert_eq!(defaults.max_frame_bytes, 65_536);
        assert_eq!(defaults.max_output_bytes, 1_048_576);
        assert_eq!(defaults.max_log_bytes, 8_192);
        assert_eq!(defaults.max_frames, 256);
        assert_eq!(defaults.run_namespace, "mcp-runs");
        assert!(defaults.kata_runtime_class.is_none());
        assert!(defaults.runner_image_digest.is_none());
        assert!(defaults.approved_runner_images.is_empty());
        assert_eq!(defaults.run_memory_request_mi, 256);
        assert_eq!(defaults.run_memory_limit_mi, 256);
        assert_eq!(defaults.run_cpu_request, 250);
        assert_eq!(defaults.run_cpu_limit, 250);
        assert!(defaults.credential_bundle_file.is_none());
        assert_eq!(defaults.licence_minter, MinterSettings::default());
        assert!(defaults.source_secret_key.is_none());
        assert_eq!(
            defaults.builder_oauth_token_max_ttl,
            Duration::from_secs(3_600)
        );
        assert_eq!(defaults.builder_source_calls_per_minute, 60);
        assert_eq!(defaults.builder_source_concurrency, 2);
        assert!(defaults.service_limits_file.is_none());
        assert_eq!(worker_settings(&[]).unwrap(), defaults);
        assert!(defaults.validate(false).is_ok());
    }

    #[test]
    fn worker_settings_read_every_env_name() {
        let padded_key = format!("{}=", "A".repeat(43));
        let configured = worker_settings(&[
            ("MCP_WORKER_PROBE_PORT", "9001"),
            ("MCP_WORKER_MAX_INFLIGHT", "4"),
            ("MCP_EXECUTION_GLOBAL_SLOTS", "2"),
            ("MCP_EXECUTION_PER_TENANT_SLOTS", "2"),
            ("MCP_RUN_START_TIMEOUT_SECONDS", "15"),
            ("MCP_RUN_MAX_SECONDS", "120"),
            ("MCP_LEASE_SECONDS", "90"),
            ("MCP_HEARTBEAT_SECONDS", "20"),
            ("MCP_RECONCILE_SECONDS", "20"),
            ("MCP_API_MAX_INFLIGHT", "3"),
            ("MCP_API_CONCURRENCY_GLOBAL", "5"),
            ("MCP_API_CONCURRENCY_PER_SERVICE", "7"),
            ("MCP_API_MAX_CALLS_PER_MINUTE", "120"),
            ("MCP_API_TIMEOUT_SECONDS", "45"),
            ("MCP_API_MAX_RESPONSE_BYTES", "1024"),
            ("MCP_MAX_FRAME_BYTES", "2048"),
            ("MCP_MAX_OUTPUT_BYTES", "4096"),
            ("MCP_MAX_LOG_BYTES", "1024"),
            ("MCP_MAX_FRAMES", "64"),
            ("MCP_RUN_NAMESPACE", "mcp-runs"),
            ("MCP_KATA_RUNTIME_CLASS", "kata-cc"),
            ("MCP_RUNNER_IMAGE_DIGEST", "sha256:abc"),
            (
                "MCP_APPROVED_RUNNER_IMAGES",
                "registry.example/runner@sha256:aaa, registry.example/other@sha256:bbb ,",
            ),
            ("MCP_RUN_MEMORY_REQUEST_MI", "512"),
            ("MCP_RUN_MEMORY_LIMIT_MI", "1024"),
            ("MCP_RUN_CPU_REQUEST", "500"),
            ("MCP_RUN_CPU_LIMIT", "1000"),
            ("MCP_CREDENTIAL_BUNDLE_FILE", "/run/credentials/bundle.json"),
            ("MCP_LICENCE_MINTER_ENABLED", "true"),
            ("MCP_LICENCE_MINTER_URL", "https://licences.internal"),
            (
                "MCP_LICENCE_MINTER_TOKEN_URL",
                "https://auth.internal/token",
            ),
            ("MCP_LICENCE_MINTER_CLIENT_ID", "minter"),
            ("MCP_LICENCE_MINTER_SECRET_FILE", "/run/secrets/minter"),
            ("MCP_LICENCE_MINTER_TTL_MINUTES", "30"),
            ("MCP_LICENCE_MINTER_SKEW_SECONDS", "10"),
            ("MCP_SOURCE_SECRET_KEY", padded_key.as_str()),
            ("MCP_BUILDER_OAUTH_TOKEN_MAX_TTL", "7200"),
            ("MCP_BUILDER_SOURCE_CALLS_PER_MINUTE", "120"),
            ("MCP_BUILDER_SOURCE_CONCURRENCY", "8"),
            ("MCP_BUILDER_SERVICE_LIMITS_FILE", "/etc/mcp/limits.json"),
        ])
        .unwrap();
        assert_eq!(configured.probe_port, 9_001);
        assert_eq!(configured.max_inflight, 4);
        assert_eq!(configured.global_slots, 2);
        assert_eq!(configured.per_tenant_slots, 2);
        assert_eq!(configured.run_start_timeout, Duration::from_secs(15));
        assert_eq!(configured.run_max, Duration::from_secs(120));
        assert_eq!(configured.lease, Duration::from_secs(90));
        assert_eq!(configured.heartbeat, Duration::from_secs(20));
        assert_eq!(configured.reconcile, Duration::from_secs(20));
        assert_eq!(configured.api_max_inflight, 3);
        assert_eq!(configured.api_concurrency_global, 5);
        assert_eq!(configured.api_concurrency_per_service, 7);
        assert_eq!(configured.api_max_calls_per_minute, 120);
        assert_eq!(configured.api_timeout, Duration::from_secs(45));
        assert_eq!(configured.api_max_response_bytes, 1_024);
        assert_eq!(configured.max_frame_bytes, 2_048);
        assert_eq!(configured.max_output_bytes, 4_096);
        assert_eq!(configured.max_log_bytes, 1_024);
        assert_eq!(configured.max_frames, 64);
        assert_eq!(configured.run_namespace, "mcp-runs");
        assert_eq!(configured.kata_runtime_class.as_deref(), Some("kata-cc"));
        assert_eq!(
            configured.runner_image_digest.as_deref(),
            Some("sha256:abc")
        );
        assert_eq!(
            configured.approved_runner_images,
            vec![
                "registry.example/runner@sha256:aaa".to_owned(),
                "registry.example/other@sha256:bbb".to_owned(),
            ]
        );
        assert_eq!(configured.run_memory_request_mi, 512);
        assert_eq!(configured.run_memory_limit_mi, 1_024);
        assert_eq!(configured.run_cpu_request, 500);
        assert_eq!(configured.run_cpu_limit, 1_000);
        assert_eq!(
            configured.credential_bundle_file,
            Some(PathBuf::from("/run/credentials/bundle.json"))
        );
        assert!(configured.licence_minter.enabled);
        assert_eq!(
            configured.licence_minter.url.as_deref(),
            Some("https://licences.internal")
        );
        assert_eq!(
            configured.licence_minter.token_url.as_deref(),
            Some("https://auth.internal/token")
        );
        assert_eq!(configured.licence_minter.client_id, "minter");
        assert_eq!(
            configured.licence_minter.secret_file,
            Some(PathBuf::from("/run/secrets/minter"))
        );
        assert_eq!(configured.licence_minter.ttl, Duration::from_secs(30 * 60));
        assert_eq!(configured.licence_minter.skew, Duration::from_secs(10));
        assert_eq!(
            configured.source_secret_key.as_deref(),
            Some(padded_key.as_str())
        );
        assert_eq!(
            configured.builder_oauth_token_max_ttl,
            Duration::from_secs(7_200)
        );
        assert_eq!(configured.builder_source_calls_per_minute, 120);
        assert_eq!(configured.builder_source_concurrency, 8);
        assert_eq!(
            configured.service_limits_file,
            Some(PathBuf::from("/etc/mcp/limits.json"))
        );
    }

    #[test]
    fn worker_settings_refuse_every_out_of_range_bound() {
        for (name, value) in [
            ("MCP_WORKER_PROBE_PORT", "1023"),
            ("MCP_WORKER_PROBE_PORT", "65536"),
            ("MCP_WORKER_PROBE_PORT", "-1"),
            ("MCP_WORKER_MAX_INFLIGHT", "0"),
            ("MCP_WORKER_MAX_INFLIGHT", "129"),
            ("MCP_EXECUTION_GLOBAL_SLOTS", "0"),
            ("MCP_EXECUTION_GLOBAL_SLOTS", "129"),
            ("MCP_EXECUTION_PER_TENANT_SLOTS", "0"),
            ("MCP_RUN_START_TIMEOUT_SECONDS", "0"),
            ("MCP_RUN_START_TIMEOUT_SECONDS", "121"),
            ("MCP_RUN_MAX_SECONDS", "0"),
            ("MCP_RUN_MAX_SECONDS", "301"),
            ("MCP_LEASE_SECONDS", "9"),
            ("MCP_LEASE_SECONDS", "301"),
            ("MCP_HEARTBEAT_SECONDS", "0"),
            ("MCP_RECONCILE_SECONDS", "0"),
            ("MCP_RECONCILE_SECONDS", "61"),
            ("MCP_API_MAX_INFLIGHT", "0"),
            ("MCP_API_MAX_INFLIGHT", "101"),
            ("MCP_API_CONCURRENCY_GLOBAL", "0"),
            ("MCP_API_CONCURRENCY_GLOBAL", "101"),
            ("MCP_API_CONCURRENCY_PER_SERVICE", "0"),
            ("MCP_API_CONCURRENCY_PER_SERVICE", "101"),
            ("MCP_API_MAX_CALLS_PER_MINUTE", "0"),
            ("MCP_API_MAX_CALLS_PER_MINUTE", "10001"),
            ("MCP_API_TIMEOUT_SECONDS", "0"),
            ("MCP_API_TIMEOUT_SECONDS", "301"),
            ("MCP_API_MAX_RESPONSE_BYTES", "0"),
            ("MCP_API_MAX_RESPONSE_BYTES", "10485761"),
            ("MCP_MAX_FRAME_BYTES", "0"),
            ("MCP_MAX_FRAME_BYTES", "1048577"),
            ("MCP_MAX_OUTPUT_BYTES", "0"),
            ("MCP_MAX_OUTPUT_BYTES", "4194305"),
            ("MCP_MAX_LOG_BYTES", "0"),
            ("MCP_MAX_LOG_BYTES", "65537"),
            ("MCP_MAX_FRAMES", "0"),
            ("MCP_MAX_FRAMES", "1001"),
            ("MCP_RUN_MEMORY_REQUEST_MI", "31"),
            ("MCP_RUN_MEMORY_REQUEST_MI", "1025"),
            ("MCP_RUN_MEMORY_LIMIT_MI", "31"),
            ("MCP_RUN_MEMORY_LIMIT_MI", "1025"),
            ("MCP_RUN_CPU_REQUEST", "9"),
            ("MCP_RUN_CPU_REQUEST", "1001"),
            ("MCP_RUN_CPU_LIMIT", "9"),
            ("MCP_RUN_CPU_LIMIT", "1001"),
            ("MCP_BUILDER_OAUTH_TOKEN_MAX_TTL", "29"),
            ("MCP_BUILDER_OAUTH_TOKEN_MAX_TTL", "86401"),
            ("MCP_BUILDER_SOURCE_CALLS_PER_MINUTE", "0"),
            ("MCP_BUILDER_SOURCE_CALLS_PER_MINUTE", "100001"),
            ("MCP_BUILDER_SOURCE_CONCURRENCY", "0"),
            ("MCP_BUILDER_SOURCE_CONCURRENCY", "101"),
            ("MCP_LICENCE_MINTER_TTL_MINUTES", "0"),
            ("MCP_LICENCE_MINTER_TTL_MINUTES", "61"),
            ("MCP_LICENCE_MINTER_SKEW_SECONDS", "301"),
            ("MCP_WORKER_MAX_INFLIGHT", "many"),
            ("MCP_HEARTBEAT_SECONDS", "many"),
        ] {
            assert!(
                worker_settings(&[(name, value)]).is_err(),
                "{name}={value} must be refused"
            );
        }
    }

    #[test]
    fn worker_settings_cross_check_the_reference_rules() {
        // The lease must exceed three heartbeat intervals; equality is refused.
        assert_eq!(
            worker_settings(&[("MCP_HEARTBEAT_SECONDS", "10"), ("MCP_LEASE_SECONDS", "30"),])
                .unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_HEARTBEAT_SECONDS",
                reason: "lease must be longer than three heartbeat intervals".into(),
            }
        );
        assert!(
            worker_settings(&[("MCP_HEARTBEAT_SECONDS", "9"), ("MCP_LEASE_SECONDS", "30"),])
                .is_ok()
        );
        // One tenant can never hold more slots than the global pool; equality is allowed.
        assert_eq!(
            worker_settings(&[
                ("MCP_EXECUTION_GLOBAL_SLOTS", "2"),
                ("MCP_EXECUTION_PER_TENANT_SLOTS", "3"),
            ])
            .unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_EXECUTION_PER_TENANT_SLOTS",
                reason: "per-tenant slots exceed the global slots".into(),
            }
        );
        assert!(
            worker_settings(&[
                ("MCP_EXECUTION_GLOBAL_SLOTS", "2"),
                ("MCP_EXECUTION_PER_TENANT_SLOTS", "2"),
            ])
            .is_ok()
        );
        // One protocol frame can never be allowed to exceed the aggregate output bound.
        assert_eq!(
            worker_settings(&[
                ("MCP_MAX_FRAME_BYTES", "4096"),
                ("MCP_MAX_OUTPUT_BYTES", "2048"),
            ])
            .unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_MAX_FRAME_BYTES",
                reason: "frame limit exceeds the aggregate output limit".into(),
            }
        );
        assert!(
            worker_settings(&[
                ("MCP_MAX_FRAME_BYTES", "2048"),
                ("MCP_MAX_OUTPUT_BYTES", "2048"),
            ])
            .is_ok()
        );
        // Runner requests may not exceed their limits, for memory and for CPU.
        assert_eq!(
            worker_settings(&[
                ("MCP_RUN_MEMORY_REQUEST_MI", "512"),
                ("MCP_RUN_MEMORY_LIMIT_MI", "256"),
            ])
            .unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_RUN_MEMORY_REQUEST_MI",
                reason: "runner requests exceed limits".into(),
            }
        );
        assert_eq!(
            worker_settings(&[("MCP_RUN_CPU_REQUEST", "500"), ("MCP_RUN_CPU_LIMIT", "250"),])
                .unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_RUN_CPU_REQUEST",
                reason: "runner requests exceed limits".into(),
            }
        );
        assert!(
            worker_settings(&[
                ("MCP_RUN_MEMORY_REQUEST_MI", "512"),
                ("MCP_RUN_MEMORY_LIMIT_MI", "512"),
                ("MCP_RUN_CPU_REQUEST", "500"),
                ("MCP_RUN_CPU_LIMIT", "500"),
            ])
            .is_ok()
        );
        // Runner pods live in the dedicated namespace and nowhere else.
        assert_eq!(
            worker_settings(&[("MCP_RUN_NAMESPACE", "runs")]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_RUN_NAMESPACE",
                reason: "execution requires the dedicated mcp-runs namespace".into(),
            }
        );
        assert!(worker_settings(&[("MCP_RUN_NAMESPACE", "mcp-runs")]).is_ok());
    }

    #[test]
    fn worker_settings_require_configuration_when_execution_is_enabled() {
        let on = ("EXECUTION_ENABLED", "true");
        let images = (
            "MCP_APPROVED_RUNNER_IMAGES",
            "registry.example/runner@sha256:aaa",
        );
        let kata = ("MCP_KATA_RUNTIME_CLASS", "kata-cc");
        let digest = ("MCP_RUNNER_IMAGE_DIGEST", "sha256:abc");
        let bundle = ("MCP_CREDENTIAL_BUNDLE_FILE", "/run/credentials/bundle.json");

        let missing_images = ConfigError::Invalid {
            name: "MCP_APPROVED_RUNNER_IMAGES",
            reason: "execution requires approved runner images".into(),
        };
        // Both spellings of the switch are read; the enabled worker needs an approved image.
        assert_eq!(worker_settings(&[on]).unwrap_err(), missing_images);
        assert_eq!(
            worker_settings(&[("MCP_EXECUTION_ENABLED", "true")]).unwrap_err(),
            missing_images
        );
        // The unprefixed name wins when both are set.
        assert!(
            worker_settings(&[
                ("EXECUTION_ENABLED", "false"),
                ("MCP_EXECUTION_ENABLED", "true"),
            ])
            .is_ok()
        );
        assert_eq!(
            worker_settings(&[on, images]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_KATA_RUNTIME_CLASS",
                reason: "execution requires a Kata runtime class".into(),
            }
        );
        assert_eq!(
            worker_settings(&[on, images, kata]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_RUNNER_IMAGE_DIGEST",
                reason: "execution requires a runner image digest".into(),
            }
        );
        // With every prerequisite but a credential source, the worker still refuses to start.
        assert_eq!(
            worker_settings(&[on, images, kata, digest]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_CREDENTIAL_BUNDLE_FILE",
                reason: "a worker requires a credential bundle file or the licence minter".into(),
            }
        );
        // Either a mounted bundle or an enabled minter satisfies the credential source; the
        // prefixed switch carries the same prerequisites.
        assert!(worker_settings(&[on, images, kata, digest, bundle]).is_ok());
        assert!(
            worker_settings(&[
                ("MCP_EXECUTION_ENABLED", "true"),
                images,
                kata,
                digest,
                bundle,
            ])
            .is_ok()
        );
        assert!(
            worker_settings(&[
                on,
                images,
                kata,
                digest,
                ("MCP_LICENCE_MINTER_ENABLED", "true"),
                ("MCP_LICENCE_MINTER_URL", "https://licences.internal"),
                (
                    "MCP_LICENCE_MINTER_TOKEN_URL",
                    "https://auth.internal/token"
                ),
                ("MCP_LICENCE_MINTER_SECRET_FILE", "/run/secrets/minter"),
            ])
            .is_ok()
        );
    }

    #[test]
    fn minter_settings_take_reference_defaults_and_env_names() {
        let defaults = MinterSettings::default();
        assert!(!defaults.enabled);
        assert!(defaults.url.is_none());
        assert!(defaults.token_url.is_none());
        assert_eq!(defaults.client_id, "mcp-bundle-minter");
        assert!(defaults.secret_file.is_none());
        assert_eq!(defaults.ttl, Duration::from_secs(15 * 60));
        assert_eq!(defaults.skew, Duration::from_secs(30));
        assert_eq!(minter_settings(&[]).unwrap(), defaults);
        assert!(defaults.validate().is_ok());

        let configured = minter_settings(&[
            ("MCP_LICENCE_MINTER_ENABLED", "true"),
            ("MCP_LICENCE_MINTER_URL", "https://licences.internal/"),
            ("MCP_LICENCE_MINTER_TOKEN_URL", "http://auth.internal/token"),
            ("MCP_LICENCE_MINTER_CLIENT_ID", "minter"),
            ("MCP_LICENCE_MINTER_SECRET_FILE", "/run/secrets/minter"),
            ("MCP_LICENCE_MINTER_TTL_MINUTES", "45"),
            ("MCP_LICENCE_MINTER_SKEW_SECONDS", "0"),
        ])
        .unwrap();
        assert!(configured.enabled);
        assert_eq!(
            configured.url.as_deref(),
            Some("https://licences.internal/")
        );
        assert_eq!(
            configured.token_url.as_deref(),
            Some("http://auth.internal/token")
        );
        assert_eq!(configured.client_id, "minter");
        assert_eq!(
            configured.secret_file,
            Some(PathBuf::from("/run/secrets/minter"))
        );
        assert_eq!(configured.ttl, Duration::from_secs(45 * 60));
        assert_eq!(configured.skew, Duration::ZERO);
    }

    #[test]
    fn minter_settings_require_urls_and_a_secret_file_when_enabled() {
        let on = ("MCP_LICENCE_MINTER_ENABLED", "true");
        let url = ("MCP_LICENCE_MINTER_URL", "https://licences.internal");
        let token_url = (
            "MCP_LICENCE_MINTER_TOKEN_URL",
            "https://auth.internal/token",
        );
        let secret = ("MCP_LICENCE_MINTER_SECRET_FILE", "/run/secrets/minter");
        assert_eq!(
            minter_settings(&[on, token_url, secret]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_URL",
                reason: "licence minting requires the licences URL".into(),
            }
        );
        assert_eq!(
            minter_settings(&[on, url, secret]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_TOKEN_URL",
                reason: "licence minting requires the token URL".into(),
            }
        );
        assert_eq!(
            minter_settings(&[on, url, token_url]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_LICENCE_MINTER_SECRET_FILE",
                reason: "licence minting requires the client secret file".into(),
            }
        );
        assert!(minter_settings(&[on, url, token_url, secret]).is_ok());
    }

    #[test]
    fn minter_settings_refuse_urls_that_are_not_plain_http_authorities() {
        let with_url = |name: &'static str, value: &'static str| {
            minter_settings(&[
                ("MCP_LICENCE_MINTER_ENABLED", "true"),
                ("MCP_LICENCE_MINTER_URL", "https://licences.internal"),
                (
                    "MCP_LICENCE_MINTER_TOKEN_URL",
                    "https://auth.internal/token",
                ),
                ("MCP_LICENCE_MINTER_SECRET_FILE", "/run/secrets/minter"),
                (name, value),
            ])
        };
        for value in [
            "ftp://licences.internal",
            "licences.internal",
            "https://",
            "https://user@licences.internal",
            "https://licences.internal?tenant=1",
            "https://licences.internal#fragment",
        ] {
            assert!(
                with_url("MCP_LICENCE_MINTER_URL", value).is_err(),
                "MCP_LICENCE_MINTER_URL={value} must be refused"
            );
            assert!(
                with_url("MCP_LICENCE_MINTER_TOKEN_URL", value).is_err(),
                "MCP_LICENCE_MINTER_TOKEN_URL={value} must be refused"
            );
        }
        assert!(with_url("MCP_LICENCE_MINTER_URL", "http://licences.internal:8443").is_ok());
    }

    #[test]
    fn source_secret_key_must_decode_to_thirty_two_bytes() {
        let unpadded = "A".repeat(43);
        let padded = format!("{unpadded}=");
        assert!(
            worker_settings(&[("MCP_SOURCE_SECRET_KEY", unpadded.as_str())]).is_ok(),
            "unpadded base64url"
        );
        assert!(
            worker_settings(&[("MCP_SOURCE_SECRET_KEY", padded.as_str())]).is_ok(),
            "padded base64url"
        );
        for value in ["A".repeat(22), "A".repeat(44)] {
            assert_eq!(
                worker_settings(&[("MCP_SOURCE_SECRET_KEY", value.as_str())]).unwrap_err(),
                ConfigError::Invalid {
                    name: "MCP_SOURCE_SECRET_KEY",
                    reason: "must decode to 32 bytes".into(),
                }
            );
        }
        assert_eq!(
            worker_settings(&[("MCP_SOURCE_SECRET_KEY", "not base64url!")]).unwrap_err(),
            ConfigError::Invalid {
                name: "MCP_SOURCE_SECRET_KEY",
                reason: "must be base64url".into(),
            }
        );
    }
}
