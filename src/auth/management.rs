//! Operator keys are mounted files, independent of licence and binding credentials.
//!
//! Keys are read once at startup, bounded even for an incorrectly mounted file, and compared
//! to the presented header in constant time. The platform key raises a management principal;
//! it must not equal the tenant operator key (that is a startup error, as in the reference
//! service).

use std::fs::File;
use std::io::Read;
use std::path::Path;

use crate::config::{AuthConfig, ConfigError};

use super::error::AuthError;
use super::principal::{LicenseIdentity, Principal};
use super::uuid::Rfc4122Uuid;

/// Smallest operator key the reference service accepts, in printable bytes.
const MIN_KEY_BYTES: usize = 32;
/// Largest operator key it accepts.
const MAX_KEY_BYTES: usize = 4096;
/// Python's reader stops at this many bytes (`stream.read(4097)`), bounding a bad mount.
const MAX_FILE_BYTES: u64 = 4097;

/// Authorises management requests from an introspected licence plus operator keys.
#[derive(Debug)]
pub struct ManagementAuthorizer {
    tenants: Vec<Rfc4122Uuid>,
    admin: Option<Vec<u8>>,
    platform: Option<Vec<u8>>,
}

impl ManagementAuthorizer {
    /// Read the key files once. Missing management settings are NOT an error: every
    /// management request then fails closed with 503.
    pub fn from_config(config: &AuthConfig) -> Result<Self, ConfigError> {
        let admin = match &config.admin_key_file {
            Some(path) => Some(read_key(path, "MCP_ADMIN_KEY_FILE")?),
            None => None,
        };
        let platform = match &config.platform_admin_key_file {
            Some(path) => Some(read_key(path, "MCP_PLATFORM_ADMIN_KEY_FILE")?),
            None => None,
        };
        if let (Some(admin), Some(platform)) = (&admin, &platform)
            && constant_time_eq(admin, platform)
        {
            return Err(ConfigError::Invalid {
                name: "MCP_PLATFORM_ADMIN_KEY_FILE",
                reason: "platform and tenant operator keys must be distinct".into(),
            });
        }
        Ok(Self {
            tenants: config.admin_tenant_ids.clone(),
            admin,
            platform,
        })
    }

    /// Check the licence's tenant against the allow-list and the presented key against the
    /// mounted operator key; an optional platform key raises the principal to platform.
    pub fn authorize(
        &self,
        identity: &LicenseIdentity,
        key: &str,
        platform_key: Option<&str>,
    ) -> Result<Principal, AuthError> {
        let Some(admin) = &self.admin else {
            return Err(AuthError::Unavailable);
        };
        if !self.tenants.contains(&identity.tenant_id) || !constant_time_eq(admin, key.as_bytes()) {
            return Err(AuthError::Unauthorized);
        }
        let mut platform = false;
        if let Some(presented) = platform_key {
            match &self.platform {
                Some(expected) if constant_time_eq(expected, presented.as_bytes()) => {
                    platform = true;
                }
                _ => return Err(AuthError::Unauthorized),
            }
        }
        Ok(Principal {
            tenant_id: identity.tenant_id,
            license_id: identity.license_id,
            subject: identity.subject.clone(),
            binding_id: None,
            binding_revision: None,
            management: true,
            platform,
        })
    }
}

/// Read one operator key file: bounded, stripped of surrounding ASCII whitespace, and
/// refused unless it is 32..=4096 printable (non-space) bytes.
fn read_key(path: &Path, name: &'static str) -> Result<Vec<u8>, ConfigError> {
    let invalid = |reason: String| ConfigError::Invalid { name, reason };
    let file =
        File::open(path).map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    let mut buffer = Vec::new();
    file.take(MAX_FILE_BYTES)
        .read_to_end(&mut buffer)
        .map_err(|e| invalid(format!("cannot read {}: {e}", path.display())))?;
    let value = buffer.trim_ascii();
    if !(MIN_KEY_BYTES..=MAX_KEY_BYTES).contains(&value.len())
        || value.iter().any(|byte| !(33..=126).contains(byte))
    {
        return Err(invalid(
            "operator key file must contain 32 to 4096 printable bytes".into(),
        ));
    }
    Ok(value.to_vec())
}

/// Constant-time equality for secrets of possibly unequal length (length itself is not a
/// secret: the accepted range is public).
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut difference = 0u8;
    for (a, b) in left.iter().zip(right) {
        difference |= a ^ b;
    }
    difference == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn constant_time_equality_matches_ordinary_equality() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(!constant_time_eq(b"same", b"samf"));
        assert!(!constant_time_eq(b"same", b"same "));
        assert!(!constant_time_eq(b"", b"x"));
        assert!(constant_time_eq(b"", b""));
    }
}
