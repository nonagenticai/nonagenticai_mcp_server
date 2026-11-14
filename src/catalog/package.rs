//! Canonical packages: paths are checked here; inspecting a package never imports uploaded code.
//!
//! Ported from the reference's `src/catalog/package.py`. [`canonical_path`], [`package_digest`]
//! and [`validate_package`] enforce the same rules in the same order, so a package either side
//! refuses is refused here and an accepted package carries the identical digest.
//!
//! The digest is SHA-256 hex over compact UTF-8 JSON of the sorted `[path, content]` pairs.
//! serde_json's compact array encoding matches the reference's
//! `json.dumps(pairs, ensure_ascii=False, separators=(",", ":"), allow_nan=False)` byte for byte
//! for these pairs: no insignificant whitespace, `"`/`\`/control escapes, and non-ASCII emitted
//! raw. Sorting is by UTF-8 bytes, which is code-point order, the order Python's `sorted` uses.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use unicode_normalization::UnicodeNormalization;

use crate::catalog::error::CatalogError;
use crate::config::PackageLimits;

/// One file of an uploaded tool package. The reference model is strict and forbids extras.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageFile {
    /// Relative POSIX path inside the package.
    pub path: String,
    /// Exact file content.
    pub content: String,
}

/// The reference's `[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*` with `re.ASCII`: `\w` is
/// spelled out as `[A-Za-z0-9_]`, so a Unicode word character never matches.
static ENTRYPOINT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)*:[A-Za-z_][A-Za-z0-9_]*\z")
        .expect("the entrypoint pattern is valid")
});

/// Check a package path: canonical relative POSIX, at most 512 UTF-8 bytes, and already its own
/// Unicode NFC form.
///
/// The NFC rule is the reference's `unicodedata.normalize("NFC", path) != path`: a decomposed
/// spelling such as `e` followed by U+0301 is refused, while the precomposed `é` is accepted.
pub fn canonical_path(path: &str) -> Result<String, CatalogError> {
    let message = CatalogError("package paths must be canonical relative POSIX paths");
    if path.is_empty()
        || path.len() > 512
        || path.contains('\\')
        || path.contains(':')
        || path
            .chars()
            .any(|character| (character as u32) < 32 || (character as u32) == 127)
        || !path.nfc().eq(path.chars())
        || path
            .split('/')
            .any(|segment| matches!(segment, "" | "." | ".."))
    {
        Err(message)
    } else {
        Ok(path.to_owned())
    }
}

/// SHA-256 hex of compact UTF-8 JSON of the sorted `[path, exact content]` pairs.
pub fn package_digest(files: &[PackageFile]) -> String {
    let mut pairs: Vec<(&str, &str)> = files
        .iter()
        .map(|file| (file.path.as_str(), file.content.as_str()))
        .collect();
    pairs.sort_unstable();
    let encoded = serde_json::to_string(&pairs).expect("package pairs are JSON-serializable");
    hex(&Sha256::digest(encoded.as_bytes()))
}

/// The reference's `hexdigest()`.
fn hex(bytes: &[u8]) -> String {
    let mut hex = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(hex, "{byte:02x}").expect("writing to a String cannot fail");
    }
    hex
}

/// Refuse a package the reference refuses, in the reference's order and with its messages.
pub fn validate_package(
    files: &[PackageFile],
    entrypoint: &str,
    digest: &str,
    limits: &PackageLimits,
) -> Result<(), CatalogError> {
    if files.is_empty() || files.len() > limits.max_package_files {
        return Err(CatalogError("package file count outside configured limit"));
    }
    let mut paths: BTreeSet<&str> = BTreeSet::new();
    let mut total = 0usize;
    for file in files {
        // The reference stores the canonicalized path; this check never rewrites it, so the
        // input spelling is the canonical one.
        canonical_path(&file.path)?;
        if !paths.insert(file.path.as_str()) {
            return Err(CatalogError("duplicate package path"));
        }
        let size = file.content.len();
        if size > limits.max_package_file_bytes {
            return Err(CatalogError("package file too large"));
        }
        total += size;
    }
    if total > limits.max_package_bytes {
        return Err(CatalogError("package too large"));
    }
    for path in &paths {
        let parts: Vec<&str> = path.split('/').collect();
        for prefix in 1..parts.len() {
            if paths.contains(parts[..prefix].join("/").as_str()) {
                return Err(CatalogError("package file/directory collision"));
            }
        }
    }
    if !ENTRYPOINT.is_match(entrypoint) {
        return Err(CatalogError("entrypoint must be package.module:function"));
    }
    let module = entrypoint
        .split(':')
        .next()
        .unwrap_or_default()
        .replace('.', "/");
    if !paths.contains(format!("{module}.py").as_str()) {
        return Err(CatalogError("entrypoint module missing"));
    }
    if package_digest(files) != digest {
        return Err(CatalogError("package digest mismatch"));
    }
    Ok(())
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
        // Precomposed forms are their own NFC form and are accepted.
        assert_eq!(canonical_path("héllo.txt").unwrap(), "héllo.txt");
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
            // `e` + U+0301 decomposes differently from `é`.
            "cafe\u{301}.py",
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
