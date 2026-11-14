//! Configuration from the environment. Nothing has a default port: the deployment sets
//! `BIND_ADDR` explicitly, so the binary never guesses one.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

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
        let execution_enabled = match get("EXECUTION_ENABLED") {
            None => false,
            Some(v) if v.eq_ignore_ascii_case("true") || v == "1" => true,
            Some(v) if v.eq_ignore_ascii_case("false") || v == "0" => false,
            Some(v) => {
                return Err(ConfigError::Invalid {
                    name: "EXECUTION_ENABLED",
                    reason: format!("{v:?} is not one of true/false/1/0"),
                });
            }
        };
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

fn bool_setting(
    get: &impl Fn(&str) -> Option<String>,
    name: &'static str,
    default: bool,
) -> Result<bool, ConfigError> {
    match get(name) {
        None => Ok(default),
        Some(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Some(value) if value.eq_ignore_ascii_case("false") || value == "0" => Ok(false),
        Some(value) => Err(ConfigError::Invalid {
            name,
            reason: format!("{value:?} is not one of true/false/1/0"),
        }),
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
}
