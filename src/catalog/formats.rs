//! Named string formats: the only way a schema constrains string shape.
//!
//! Raw `pattern` is never accepted: a schema author's regex would run on untrusted input
//! (ReDoS). Each format is fixed code: anchored, length-checked before any regex, and using
//! only linear-time patterns (single character classes, no nested quantifiers). `format:
//! "<name>"` must name an entry here; [`crate::catalog::validation::validate_schema`] rejects
//! unknown names, and [`check`] enforces the known ones.

use std::sync::LazyLock;

use regex::Regex;

/// DNS-label style workspace name: 1..63 lowercase alphanumerics and inner hyphens.
pub fn container_name(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$").expect("format pattern is valid")
    });
    value.len() <= 63 && PATTERN.is_match(value)
}

/// A conservative subset of `git check-ref-format` for a branch name.
pub fn git_branch(value: &str) -> bool {
    static BRANCH_CHARS: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._/-]+$").expect("format pattern is valid"));
    if !(1..=200).contains(&value.len()) || !BRANCH_CHARS.is_match(value) {
        return false;
    }
    if value.starts_with('-')
        || value.starts_with('/')
        || value.starts_with('.')
        || value.ends_with('/')
        || value.ends_with('.')
        || value.ends_with(".lock")
    {
        return false;
    }
    !value.contains("..") && !value.contains("//") && !value.contains("/.")
}

/// `https://host[:port]/owner/repo[.git]`, no credentials, query, fragment or traversal.
pub fn repo_url_https(value: &str) -> bool {
    static HOST: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(
            r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$",
        )
        .expect("format pattern is valid")
    });
    static URL_PATH: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._~-]+$").expect("format pattern is valid"));
    if value.len() > 512 {
        return false;
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return false;
    };
    let (authority, path) = match rest.split_once('/') {
        Some(parts) => parts,
        None => (rest, ""),
    };
    let (host, port) = match authority.split_once(':') {
        Some(parts) => (parts.0, Some(parts.1)),
        None => (authority, None),
    };
    if host.is_empty() || host.len() > 253 || !HOST.is_match(host) {
        return false;
    }
    if let Some(port) = port.filter(|port| !port.is_empty()) {
        if !port.bytes().all(|byte| byte.is_ascii_digit()) {
            return false;
        }
        match port.parse::<u64>() {
            Ok(number) if (1..=65535).contains(&number) => {}
            _ => return false,
        }
    }
    let segments: Vec<&str> = path.split('/').collect();
    if segments.len() < 2 {
        return false;
    }
    segments
        .iter()
        .all(|segment| !matches!(*segment, "." | "..") && URL_PATH.is_match(segment))
}

/// Workspace-relative file path: no leading `/`, no `.`, `..`, or empty segments.
pub fn relative_path(value: &str) -> bool {
    static SEGMENT: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._@+=,~-]+$").expect("format pattern is valid"));
    if !(1..=1024).contains(&value.len()) || value.starts_with('/') {
        return false;
    }
    value
        .split('/')
        .all(|segment| !matches!(segment, "." | "..") && SEGMENT.is_match(segment))
}

/// Package-manager name (pypi, npm incl. `@scope/name`, go, cargo): never starts with `-`.
pub fn package_name(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z0-9@][A-Za-z0-9._/@+-]*$").expect("format pattern is valid")
    });
    if !(1..=128).contains(&value.len()) || !PATTERN.is_match(value) {
        return false;
    }
    !value.contains("..") && !value.contains("//") && !value.ends_with('/')
}

/// Canonical hyphenated UUID (any version), lowercase or uppercase hex.
pub fn uuid(value: &str) -> bool {
    if value.len() != 36 {
        return false;
    }
    let bytes = value.as_bytes();
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return false;
            }
        } else if !byte.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

/// An idempotency key: 8..128 characters of the reference's key alphabet.
pub fn idempotency_key(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[A-Za-z0-9._:-]+$").expect("format pattern is valid"));
    (8..=128).contains(&value.len()) && PATTERN.is_match(value)
}

/// A resume token: two token segments separated by a dot, 3..2048 characters.
pub fn resume_token(value: &str) -> bool {
    static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$").expect("format pattern is valid")
    });
    (3..=2048).contains(&value.len()) && PATTERN.is_match(value)
}

/// The signature every registered format implements.
pub type FormatCheck = fn(&str) -> bool;

/// The registered formats, in registration order.
pub const FORMATS: &[(&str, FormatCheck)] = &[
    ("container-name", container_name),
    ("git-branch", git_branch),
    ("repo-url-https", repo_url_https),
    ("relative-path", relative_path),
    ("package-name", package_name),
    ("uuid", uuid),
    ("idempotency-key", idempotency_key),
    ("resume-token", resume_token),
];

/// Whether `name` is a registered format.
pub fn registered(name: &str) -> bool {
    FORMATS.iter().any(|(format, _)| *format == name)
}

/// Check a value against a registered format. `None` means the format is not registered.
///
/// The reference's checker lets non-strings through (`not isinstance(v, str) or check(v)`);
/// this port takes a `&str`, so callers apply it only to strings.
pub fn check(name: &str, value: &str) -> Option<bool> {
    FORMATS
        .iter()
        .find(|(format, _)| *format == name)
        .map(|(_, checker)| checker(value))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn container_names() {
        assert!(container_name("a"));
        assert!(container_name("a-b"));
        assert!(!container_name("-a"));
        assert!(!container_name("A"));
        assert!(!container_name(&"a".repeat(64)));
        assert!(container_name(&format!("a{}", "b".repeat(62))));
        assert!(!container_name("a-"));
    }

    #[test]
    fn git_branches() {
        assert!(git_branch("main"));
        assert!(git_branch("feat/catalog-v1"));
        assert!(!git_branch(""));
        assert!(!git_branch("-x"));
        assert!(!git_branch(".x"));
        assert!(!git_branch("/x"));
        assert!(!git_branch("x.lock"));
        assert!(!git_branch("a..b"));
        assert!(!git_branch("a//b"));
        assert!(!git_branch("a/.b"));
        assert!(!git_branch(&"a".repeat(201)));
    }

    #[test]
    fn repository_urls() {
        assert!(repo_url_https("https://github.com/owner/repo"));
        assert!(repo_url_https("https://github.com/owner/repo.git"));
        assert!(repo_url_https("https://example.test:443/owner/repo"));
        assert!(repo_url_https("https://example.test:/owner/repo"));
        assert!(!repo_url_https("http://github.com/owner/repo"));
        assert!(!repo_url_https("https://github.com"));
        assert!(!repo_url_https("https://github.com/"));
        assert!(!repo_url_https("https://github.com/owner/../repo"));
        assert!(!repo_url_https("https://user:token@github.com/owner/repo"));
        assert!(!repo_url_https("https://github.com/owner/repo?x=1"));
        assert!(!repo_url_https("https://github.com/owner/repo#x"));
        assert!(!repo_url_https("https://github.com:99999/owner/repo"));
    }

    #[test]
    fn relative_paths() {
        assert!(relative_path("src/main.rs"));
        assert!(relative_path("a"));
        assert!(!relative_path(""));
        assert!(!relative_path("/a"));
        assert!(!relative_path("a/../b"));
        assert!(!relative_path("a//b"));
        assert!(!relative_path("a/./b"));
    }

    #[test]
    fn package_names() {
        assert!(package_name("serde"));
        assert!(package_name("@scope/name"));
        assert!(package_name("a-b_c.d"));
        assert!(!package_name("-a"));
        assert!(!package_name("a/../b"));
        assert!(!package_name("a//b"));
        assert!(!package_name("a/"));
        assert!(!package_name(""));
    }

    #[test]
    fn uuids() {
        assert!(uuid("10000000-0000-7000-8000-000000000001"));
        assert!(uuid("ABCDEF01-2345-7678-9ABC-DEF012345678"));
        assert!(!uuid("10000000-0000-7000-8000-00000000001"));
        assert!(!uuid("10000000-0000-7000-8000-00000000000g"));
        assert!(!uuid("10000000000070008000000000000001"));
    }

    #[test]
    fn keys_and_tokens() {
        assert!(idempotency_key("abcd1234"));
        assert!(!idempotency_key("short"));
        assert!(!idempotency_key("abcd 1234"));
        assert!(resume_token("abc.def"));
        assert!(!resume_token("abc"));
        assert!(!resume_token("abc.def.ghi"));
    }

    #[test]
    fn registry() {
        assert!(registered("uuid"));
        assert!(!registered("uri"));
        assert!(!registered("regex"));
        assert_eq!(check("container-name", "a-b"), Some(true));
        assert_eq!(check("uri", "x"), None);
    }
}
