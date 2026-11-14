//! Canonical packages: paths are checked here; inspecting a package never imports uploaded code.
//!
//! The reference's `package_digest` and `validate_package` are not ported in this slice: the
//! digest is SHA-256 over the sorted `[path, content]` pairs and this crate carries no SHA-256
//! implementation or dependency. Everything here is dependency-free and faithful except the
//! reference's NFC normalization check, which needs Unicode tables this crate does not have.

use serde::{Deserialize, Serialize};

use crate::catalog::error::CatalogError;

/// One file of an uploaded tool package. The reference model is strict and forbids extras.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    /// Relative POSIX path inside the package.
    pub path: String,
    /// Exact file content.
    pub content: String,
}

/// Check a package path: canonical relative POSIX, at most 512 UTF-8 bytes.
///
/// Deviation from the reference, deliberate: the reference also rejects paths that are not
/// already Unicode NFC-normalized. Rust's standard library has no normalization tables and the
/// crate may take no new dependency, so that one check is absent; every other rule is enforced.
pub fn canonical_path(path: &str) -> Result<String, CatalogError> {
    let message = CatalogError("package paths must be canonical relative POSIX paths");
    if path.is_empty()
        || path.len() > 512
        || path.contains('\\')
        || path.contains(':')
        || path
            .chars()
            .any(|character| (character as u32) < 32 || (character as u32) == 127)
        || path
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        Err(message)
    } else {
        Ok(path.to_owned())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_canonical_paths() {
        assert_eq!(
            canonical_path("package/main.py").unwrap(),
            "package/main.py"
        );
        assert_eq!(canonical_path("main.py").unwrap(), "main.py");
    }

    #[test]
    fn rejects_noncanonical_paths() {
        for path in [
            "",
            "/absolute.py",
            "a/../b.py",
            "a/./b.py",
            "a//b.py",
            "a\\b.py",
            "c:/x.py",
            "a\nb.py",
            "a\u{7f}b.py",
        ] {
            assert!(canonical_path(path).is_err(), "{path:?} must be refused");
        }
        assert!(canonical_path(&"a".repeat(513)).is_err());
        assert!(canonical_path(&"a".repeat(512)).is_ok());
    }

    #[test]
    fn package_files_reject_extras() {
        assert!(serde_json::from_str::<PackageFile>(r#"{"path":"a","content":""}"#).is_ok());
        assert!(
            serde_json::from_str::<PackageFile>(r#"{"path":"a","content":"","symlink":"/etc"}"#)
                .is_err()
        );
    }
}
