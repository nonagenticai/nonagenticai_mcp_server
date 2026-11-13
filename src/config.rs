//! Configuration from the environment. Nothing has a default port: the deployment sets
//! `BIND_ADDR` explicitly, so the binary never guesses one.

use std::net::SocketAddr;

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
        Ok(Self {
            database_url,
            database_migrate_url: get("DATABASE_MIGRATE_URL"),
            bind_addr,
            execution_enabled,
        })
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
}
