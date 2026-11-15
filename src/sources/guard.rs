//! Destination policy shared by registration and call time (the SSRF guard).
//!
//! Port of the reference `src/sources/guard.py`. A source's `base_url` is an
//! operator-approved origin with an optional fixed path prefix
//! (`https://api.example.test/v1`). The origin must additionally be named by the operator
//! allow-list: exact hosts, `*.suffix` patterns, or `host:port` when the port is not the
//! scheme default. An empty allow-list allows nothing. Address literals and userinfo are always
//! refused, so a DNS name is the only addressable upstream.
//!
//! The URL is parsed with the WHATWG parser (`url`), which the reference's
//! `urllib.parse.urlsplit` predates. Canonicalisation therefore differs in details — dot
//! segments, backslashes and IDNA are resolved, and empty `?`/`#` delimiters are preserved —
//! but the origin that is checked here is the origin the HTTP client will dial, and the
//! allow-list still decides whether that origin is approved.

use std::sync::OnceLock;

use regex::Regex;
use thiserror::Error;
use url::Url;

/// The fixed path prefix shape (`guard.py:15`): lowercase simple segments and an optional
/// trailing slash. An empty path and `/` both match.
const PATH_PATTERN: &str = r"^(?:/[a-z0-9][a-z0-9_-]*)*/?$";
/// The hostname shape (`guard.py:37`): a DNS name, never an address literal.
const HOST_PATTERN: &str = r"^[a-z0-9]([a-z0-9.-]{0,251}[a-z0-9])?$";

/// Why a destination was refused. The message is exactly the reference's.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum GuardError {
    /// The origin itself is unusable: not an approved scheme, userinfo, a query, a fragment,
    /// a path outside the fixed-prefix shape, an address literal or a malformed host.
    #[error("source requires an explicitly approved origin")]
    Origin,
    /// The origin is well formed but its host is not named by the allow-list.
    #[error("source host is not in the allowed host list")]
    HostNotAllowed,
}

/// The scheme/userinfo/path policy, without the host allow-list (`guard.py:19-40`).
///
/// `https` is always acceptable; `http` only when `allow_internal_http` is set (an internal
/// upstream). Returns the input unchanged, as the reference returns `base_url`.
pub fn checked_base_url(base_url: &str, allow_internal_http: bool) -> Result<&str, GuardError> {
    static HOST: OnceLock<Regex> = OnceLock::new();
    static PATH: OnceLock<Regex> = OnceLock::new();

    let url = Url::parse(base_url).map_err(|_| GuardError::Origin)?;
    let scheme_ok = match url.scheme() {
        "https" => true,
        "http" => allow_internal_http,
        _ => false,
    };
    let host = url.host_str().ok_or(GuardError::Origin)?;
    // The reference compares `url.query`/`url.fragment` for truthiness, so an empty delimiter
    // (`https://host?`) is not a query and is accepted; keep that behaviour.
    let has_query = url.query().is_some_and(|query| !query.is_empty());
    let has_fragment = url.fragment().is_some_and(|fragment| !fragment.is_empty());
    if !scheme_ok
        || !url.username().is_empty()
        || url.password().is_some()
        // `url.username()` cannot distinguish absent userinfo from an empty one, and the
        // reference rejects both `url.username is not None` and `"@" in url.netloc`.
        || base_url.contains('@')
        || has_query
        || has_fragment
        // Python's parser rejects out-of-range ports itself and the URL parser here does the
        // same, so zero is the only port left for this check.
        || url.port() == Some(0)
        || is_ip_literal(host)
        || !HOST
            .get_or_init(|| Regex::new(HOST_PATTERN).expect("the guard host pattern compiles"))
            .is_match(host)
        || !PATH
            .get_or_init(|| Regex::new(PATH_PATTERN).expect("the guard path pattern compiles"))
            .is_match(url.path())
    {
        return Err(GuardError::Origin);
    }
    Ok(base_url)
}

/// Whether `host` is an address literal, including the numeric-last-label forms
/// (`guard.py:43-52`).
///
/// Surrounding `[]` are ignored, so an IPv6 literal is recognised in its bracketed URL
/// spelling. Some stacks resolve `127.1`, `2130706433` and `0x7f.1` as addresses too, so any
/// host whose last dot-separated label is all digits or starts with `0x` counts as an address
/// literal; no legitimate DNS name ends in a number.
pub fn is_ip_literal(host: &str) -> bool {
    let bare = host.trim_matches(['[', ']']);
    if bare.parse::<std::net::IpAddr>().is_ok() {
        return true;
    }
    let last = host.rsplit('.').next().unwrap_or(host);
    !last.is_empty() && (last.bytes().all(|byte| byte.is_ascii_digit()) || last.starts_with("0x"))
}

/// Whether `base_url`'s origin is named by the operator allow-list (`guard.py:55-77`).
///
/// A bare entry names the scheme's default port; a non-default port is allowed only by an
/// explicit `host:port` entry. A `*.suffix` entry covers subdomains but never the apex, and a
/// bare `*` is not a wildcard. Entries are trimmed and compared case-insensitively; blank
/// entries are ignored, so an empty allow-list allows nothing.
///
/// A value the URL parser cannot read cannot be allowed, so it answers `false` (the
/// reference's `urlsplit` would raise there; [`enforce`] refuses such a value at the origin
/// check before this is reached).
pub fn host_allowed<'a>(base_url: &str, allowed: impl Iterator<Item = &'a str>) -> bool {
    let Ok(url) = Url::parse(base_url) else {
        return false;
    };
    let host = url.host_str().unwrap_or_default().to_ascii_lowercase();
    let port = url.port();
    let port_text = port.map(|port| port.to_string());
    // `Url::port()` drops the scheme default, so this is `port != DEFAULT_PORTS[scheme]`
    // whenever a port survived parsing.
    let non_default = port.is_some_and(|port| Some(port) != default_port(url.scheme()));
    for entry in allowed {
        let entry = entry.trim().to_ascii_lowercase();
        if entry.is_empty() {
            continue;
        }
        let (pattern, entry_port) = match entry.split_once(':') {
            Some((pattern, entry_port)) => {
                // `"host:"` has an empty port, which the reference treats as no port.
                (pattern, Some(entry_port).filter(|port| !port.is_empty()))
            }
            None => (entry.as_str(), None),
        };
        if non_default {
            // A non-default port is allowed only by an explicit `host:port` entry.
            if entry_port != port_text.as_deref() {
                continue;
            }
        } else if entry_port.is_some() {
            // A port entry never matches a default-port origin.
            continue;
        }
        if let Some(suffix) = pattern
            .strip_prefix('*')
            .filter(|suffix| suffix.starts_with('.'))
        {
            // The suffix keeps its leading dot, so `*.example.test` covers
            // `api.example.test` but never the apex `example.test`.
            if host.ends_with(suffix) && host.len() > suffix.len() {
                return true;
            }
        } else if host == pattern {
            return true;
        }
    }
    false
}

/// The complete destination policy: [`checked_base_url`] first, then [`host_allowed`]
/// (`guard.py:80-84`). Returns the input unchanged.
pub fn enforce<'a, 'b>(
    base_url: &'a str,
    allow_internal_http: bool,
    allowed: impl Iterator<Item = &'b str>,
) -> Result<&'a str, GuardError> {
    checked_base_url(base_url, allow_internal_http)?;
    if !host_allowed(base_url, allowed) {
        return Err(GuardError::HostNotAllowed);
    }
    Ok(base_url)
}

/// A scheme's default port (`guard.py:16`): only the two schemes a source may use.
fn default_port(scheme: &str) -> Option<u16> {
    match scheme {
        "https" => Some(443),
        "http" => Some(80),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{GuardError, checked_base_url, enforce, host_allowed, is_ip_literal};

    fn allowed<'a>(entries: &'a [&'a str]) -> impl Iterator<Item = &'a str> + 'a {
        entries.iter().copied()
    }

    #[test]
    fn an_origin_is_https_or_an_explicitly_allowed_internal_http() {
        assert_eq!(
            checked_base_url("https://api.example.test", false),
            Ok("https://api.example.test")
        );
        assert_eq!(
            checked_base_url("https://api.example.test/v1/a_b-1/", false),
            Ok("https://api.example.test/v1/a_b-1/")
        );
        assert!(checked_base_url("http://api.example.test", true).is_ok());
        assert_eq!(
            checked_base_url("http://api.example.test", false),
            Err(GuardError::Origin)
        );
        assert_eq!(
            checked_base_url("ftp://api.example.test", false),
            Err(GuardError::Origin)
        );
        assert_eq!(
            checked_base_url("not a url", false),
            Err(GuardError::Origin)
        );
    }

    #[test]
    fn a_path_prefix_is_lowercase_simple_segments() {
        assert!(checked_base_url("https://api.example.test/", false).is_ok());
        for value in [
            "https://api.example.test/V1",
            "https://api.example.test//api",
            "https://api.example.test/a b",
            "https://api.example.test/a.b",
            "https://api.example.test/v1//a",
        ] {
            assert_eq!(
                checked_base_url(value, false),
                Err(GuardError::Origin),
                "{value}"
            );
        }
    }

    #[test]
    fn userinfo_queries_and_fragments_are_refused() {
        for value in [
            "https://user@api.example.test",
            "https://user:pass@api.example.test",
            "https://@api.example.test",
            "https://api.example.test?x=1",
            "https://api.example.test#x",
            "https://api.example.test/a@b",
        ] {
            assert_eq!(
                checked_base_url(value, false),
                Err(GuardError::Origin),
                "{value}"
            );
        }
    }

    #[test]
    fn address_literals_are_refused() {
        for value in [
            "https://127.0.0.1",
            "https://127.0.0.1:9000",
            "https://[::1]",
            "https://[2001:db8::1]/v1",
            "https://127.1",
            "https://2130706433",
            "https://0x7f.1",
        ] {
            assert_eq!(
                checked_base_url(value, false),
                Err(GuardError::Origin),
                "{value}"
            );
        }
        // A DNS name that merely contains digits is not an address literal.
        assert!(checked_base_url("https://123.example.test", false).is_ok());
    }

    #[test]
    fn a_hostname_starts_and_ends_alphanumeric() {
        // The reference's pattern only constrains the first and last character; an interior
        // `-.` or `..` passes this shape check and is refused later, by the resolver.
        for value in [
            "https://-api.example.test",
            "https://.example.test",
            "https://api_example.test",
        ] {
            assert_eq!(
                checked_base_url(value, false),
                Err(GuardError::Origin),
                "{value}"
            );
        }
        // Accepted by the reference's shape check, refused by DNS resolution later.
        for value in ["https://api-.example.test", "https://api..example.test"] {
            assert!(checked_base_url(value, false).is_ok(), "{value}");
        }
    }

    #[test]
    fn ports_are_bounded_and_zero_is_refused() {
        assert!(checked_base_url("https://api.example.test:443", false).is_ok());
        assert!(checked_base_url("https://api.example.test:8443/v1", false).is_ok());
        for value in [
            "https://api.example.test:0",
            "https://api.example.test:65536",
            "https://api.example.test:99999",
        ] {
            assert_eq!(
                checked_base_url(value, false),
                Err(GuardError::Origin),
                "{value}"
            );
        }
    }

    #[test]
    fn ip_literals_include_numeric_last_labels() {
        for host in [
            "127.0.0.1",
            "::1",
            "[::1]",
            "127.1",
            "2130706433",
            "0x7f.1",
            "example.1",
            "example.01",
        ] {
            assert!(is_ip_literal(host), "{host}");
        }
        for host in [
            "example.test",
            "1.example",
            "example",
            "",
            "example.0X1",
            "a.b.c",
        ] {
            assert!(!is_ip_literal(host), "{host}");
        }
    }

    #[test]
    fn exact_hosts_match_case_insensitively() {
        assert!(host_allowed(
            "https://api.example.test/v1",
            allowed(&["api.example.test"])
        ));
        assert!(host_allowed(
            "https://API.Example.TEST",
            allowed(&[" api.example.test "])
        ));
        assert!(!host_allowed(
            "https://other.example.test",
            allowed(&["api.example.test"])
        ));
        assert!(!host_allowed("https://api.example.test", allowed(&[])));
        assert!(!host_allowed(
            "https://api.example.test",
            allowed(&["", " "])
        ));
        assert!(!host_allowed("not a url", allowed(&["api.example.test"])));
    }

    #[test]
    fn a_wildcard_covers_subdomains_but_never_the_apex() {
        assert!(host_allowed(
            "https://a.b.example",
            allowed(&["*.b.example"])
        ));
        assert!(host_allowed(
            "https://deep.a.b.example",
            allowed(&["*.b.example"])
        ));
        assert!(!host_allowed(
            "https://b.example",
            allowed(&["*.b.example"])
        ));
        assert!(!host_allowed(
            "https://notb.example",
            allowed(&["*.b.example"])
        ));
    }

    #[test]
    fn a_bare_star_entry_is_not_a_wildcard() {
        assert!(!host_allowed("https://api.example.test", allowed(&["*"])));
        assert!(!host_allowed(
            "https://api.example.test",
            allowed(&["*example.test"])
        ));
    }

    #[test]
    fn a_port_entry_is_needed_only_off_the_scheme_default() {
        assert!(host_allowed(
            "https://api.example.test:443",
            allowed(&["api.example.test"])
        ));
        assert!(host_allowed(
            "http://api.example.test:80",
            allowed(&["api.example.test"])
        ));
        assert!(!host_allowed(
            "https://api.example.test",
            allowed(&["api.example.test:443"])
        ));
        assert!(!host_allowed(
            "http://api.example.test:8080",
            allowed(&["api.example.test"])
        ));
        assert!(host_allowed(
            "http://api.example.test:8080",
            allowed(&["api.example.test:8080"])
        ));
        assert!(!host_allowed(
            "https://example.test:8443",
            allowed(&["*.example.test:8443"])
        ));
        assert!(host_allowed(
            "https://api.example.test:8443",
            allowed(&["*.example.test:8443"])
        ));
    }

    #[test]
    fn enforce_reports_the_origin_before_the_allow_list() {
        assert_eq!(
            enforce("http://api.example.test", false, allowed(&[])),
            Err(GuardError::Origin)
        );
        assert_eq!(
            enforce("https://api.example.test", false, allowed(&[])),
            Err(GuardError::HostNotAllowed)
        );
        assert_eq!(
            enforce(
                "https://api.example.test/v1",
                false,
                allowed(&["api.example.test"])
            ),
            Ok("https://api.example.test/v1")
        );
    }

    #[test]
    fn every_guard_refusal_uses_the_reference_message() {
        assert_eq!(
            GuardError::Origin.to_string(),
            "source requires an explicitly approved origin"
        );
        assert_eq!(
            GuardError::HostNotAllowed.to_string(),
            "source host is not in the allowed host list"
        );
    }
}
