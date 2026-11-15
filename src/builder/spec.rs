//! OpenAPI document handling for tenant sources (JSON only).
//!
//! Ported from the reference's `src/builder/spec.py`: the same-origin path rule, the size bound,
//! JSON-only parsing, the content hash and the per-hour in-process rate limit. The reference's
//! `DocumentFetcher` protocol is the broker boundary (network), so it is not ported here; this
//! module stays pure.

use std::collections::{HashMap, VecDeque};
use std::sync::LazyLock;
use std::time::Instant;

use regex::Regex;
use serde_json::{Map, Value};
use sha2::{Digest as _, Sha256};
use uuid::Uuid;

use crate::builder::models::BuilderInputError;

/// The reference's `SPEC_TIMEOUT_SECONDS`.
pub const SPEC_TIMEOUT_SECONDS: f64 = 20.0;
/// One hour in seconds, the reference's rate-limit window.
pub const HOUR: f64 = 3600.0;

static SPEC_PATH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A/[A-Za-z0-9._~/-]{0,255}\z").expect("the spec path pattern is valid")
});

/// A sliding-window rate limit per tenant, in process (spec fetches are not stored).
pub struct RateLimit {
    limit: usize,
    window: f64,
    clock: Box<dyn Fn() -> f64 + Send + Sync>,
    events: HashMap<Uuid, VecDeque<f64>>,
}

impl RateLimit {
    /// A limit of `limit` events per hour, on the process's monotonic clock.
    pub fn new(limit: usize) -> Self {
        Self::with_clock(limit, HOUR, monotonic_clock())
    }

    /// A limit with an explicit window and clock (tests).
    pub fn with_clock(
        limit: usize,
        window: f64,
        clock: Box<dyn Fn() -> f64 + Send + Sync>,
    ) -> Self {
        Self {
            limit,
            window,
            clock,
            events: HashMap::new(),
        }
    }

    /// Charge one event to `tenant`; false when the window is already full.
    pub fn take(&mut self, tenant: Uuid) -> bool {
        let now = (self.clock)();
        let events = self.events.entry(tenant).or_default();
        while let Some(front) = events.front().copied() {
            if now - front >= self.window {
                events.pop_front();
            } else {
                break;
            }
        }
        if events.len() >= self.limit {
            return false;
        }
        events.push_back(now);
        true
    }
}

fn monotonic_clock() -> Box<dyn Fn() -> f64 + Send + Sync> {
    let start = Instant::now();
    Box::new(move || start.elapsed().as_secs_f64())
}

/// The path to fetch: the explicit path, else the source's default, refused when neither is a
/// valid same-origin absolute path.
pub fn checked_spec_path(
    path: Option<&str>,
    default: Option<&str>,
) -> Result<String, BuilderInputError> {
    let chosen = match path {
        Some(value) if !value.is_empty() => Some(value),
        _ => default,
    }
    .filter(|value| !value.is_empty());
    let Some(chosen) = chosen else {
        return Err(BuilderInputError::new(
            "the source has no spec_path; pass a path",
        ));
    };
    if !SPEC_PATH.is_match(chosen) {
        return Err(BuilderInputError::new("invalid spec path"));
    }
    Ok(chosen.to_owned())
}

/// The spec as a JSON object. YAML and other formats are refused with a clear message.
///
/// The reference's `json.loads(bytes)` detects UTF-8, UTF-16 and UTF-32 from a BOM; the BOM
/// decoding below reproduces that, so a document either side accepts is accepted here.
pub fn parse_document(
    raw: &[u8],
    max_bytes: usize,
) -> Result<Map<String, Value>, BuilderInputError> {
    if raw.len() > max_bytes {
        return Err(BuilderInputError::new(
            "the spec is larger than the allowed size",
        ));
    }
    let Some(text) = decode_json_bytes(raw) else {
        return Err(not_json());
    };
    let document: Value = serde_json::from_str(&text).map_err(|_| not_json())?;
    let Value::Object(document) = document else {
        return Err(BuilderInputError::new("the spec must be a JSON object"));
    };
    let Some(Value::String(version)) = document.get("openapi") else {
        return Err(BuilderInputError::new(
            "only OpenAPI 3.0.x and 3.1.x documents are supported",
        ));
    };
    if !(version.starts_with("3.0") || version.starts_with("3.1")) {
        return Err(BuilderInputError::new(
            "only OpenAPI 3.0.x and 3.1.x documents are supported",
        ));
    }
    Ok(document)
}

fn not_json() -> BuilderInputError {
    BuilderInputError::new(
        "the spec is not JSON (YAML is not supported); serve the OpenAPI document as JSON",
    )
}

/// Decode the byte encodings Python's `json.loads` accepts: UTF-8 (optionally with a BOM),
/// UTF-16 LE/BE and UTF-32 LE/BE chosen by a BOM.
fn decode_json_bytes(raw: &[u8]) -> Option<String> {
    if let Some(rest) = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]) {
        return String::from_utf8(rest.to_vec()).ok();
    }
    if let Some(rest) = raw.strip_prefix(&[0xFF, 0xFE, 0x00, 0x00]) {
        return decode_utf32(rest, true);
    }
    if let Some(rest) = raw.strip_prefix(&[0x00, 0x00, 0xFE, 0xFF]) {
        return decode_utf32(rest, false);
    }
    if let Some(rest) = raw.strip_prefix(&[0xFF, 0xFE]) {
        return decode_utf16(rest, true);
    }
    if let Some(rest) = raw.strip_prefix(&[0xFE, 0xFF]) {
        return decode_utf16(rest, false);
    }
    String::from_utf8(raw.to_vec()).ok()
}

fn decode_utf16(raw: &[u8], little_endian: bool) -> Option<String> {
    if !raw.len().is_multiple_of(2) {
        return None;
    }
    let mut units = Vec::with_capacity(raw.len() / 2);
    for pair in raw.as_chunks::<2>().0 {
        units.push(if little_endian {
            u16::from_le_bytes(*pair)
        } else {
            u16::from_be_bytes(*pair)
        });
    }
    String::from_utf16(&units).ok()
}

fn decode_utf32(raw: &[u8], little_endian: bool) -> Option<String> {
    if !raw.len().is_multiple_of(4) {
        return None;
    }
    let mut text = String::with_capacity(raw.len() / 4);
    for group in raw.as_chunks::<4>().0 {
        let code = if little_endian {
            u32::from_le_bytes(*group)
        } else {
            u32::from_be_bytes(*group)
        };
        text.push(char::from_u32(code)?);
    }
    Some(text)
}

/// SHA-256 hex of the raw body.
pub fn digest(raw: &[u8]) -> String {
    hex::encode(Sha256::digest(raw))
}

/// The document's info title (up to 200 characters) and version (up to 100), when present.
pub fn title_version(document: &Map<String, Value>) -> (Option<String>, Option<String>) {
    let Some(Value::Object(info)) = document.get("info") else {
        return (None, None);
    };
    let title = info
        .get("title")
        .and_then(Value::as_str)
        .map(|text| text.chars().take(200).collect());
    let version = info
        .get("version")
        .and_then(Value::as_str)
        .map(|text| text.chars().take(100).collect());
    (title, version)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SPEC: &[u8] = br#"{"openapi": "3.1.0", "info": {"title": "t", "version": "1"}}"#;

    #[test]
    fn spec_paths_are_same_origin_and_bounded() {
        assert_eq!(
            checked_spec_path(Some("/openapi.json"), Some("/other")).unwrap(),
            "/openapi.json"
        );
        assert_eq!(
            checked_spec_path(None, Some("/openapi.json")).unwrap(),
            "/openapi.json"
        );
        // `path or default`: an empty explicit path falls back to the default.
        assert_eq!(
            checked_spec_path(Some(""), Some("/openapi.json")).unwrap(),
            "/openapi.json"
        );
        assert_eq!(
            checked_spec_path(None, None).unwrap_err().message(),
            "the source has no spec_path; pass a path"
        );
        for path in ["openapi.json", "/a?x=1", "/a b", "//\n"] {
            assert_eq!(
                checked_spec_path(Some(path), None).unwrap_err().message(),
                "invalid spec path"
            );
        }
        let long = format!("/{}", "a".repeat(256));
        assert!(checked_spec_path(Some(long.as_str()), None).is_err());
    }

    #[test]
    fn documents_are_json_objects_with_a_supported_version() {
        assert_eq!(parse_document(SPEC, 1024).unwrap()["openapi"], "3.1.0");
        assert_eq!(
            parse_document(b"openapi: 3.1.0\n", 1024)
                .unwrap_err()
                .message(),
            "the spec is not JSON (YAML is not supported); serve the OpenAPI document as JSON"
        );
        assert_eq!(
            parse_document(b"[]", 1024).unwrap_err().message(),
            "the spec must be a JSON object"
        );
        assert_eq!(
            parse_document(b"{\"openapi\": \"2.0\"}", 1024)
                .unwrap_err()
                .message(),
            "only OpenAPI 3.0.x and 3.1.x documents are supported"
        );
        assert_eq!(
            parse_document(SPEC, 4).unwrap_err().message(),
            "the spec is larger than the allowed size"
        );
    }

    #[test]
    fn bom_encoded_documents_are_decoded() {
        let utf16: Vec<u8> = [0xFF, 0xFE]
            .into_iter()
            .chain(
                r#"{"openapi": "3.1.0"}"#
                    .encode_utf16()
                    .flat_map(|unit| unit.to_le_bytes()),
            )
            .collect();
        assert_eq!(parse_document(&utf16, 1024).unwrap()["openapi"], "3.1.0");
        let utf8_bom: Vec<u8> = [0xEF, 0xBB, 0xBF]
            .into_iter()
            .chain(SPEC.iter().copied())
            .collect();
        assert_eq!(parse_document(&utf8_bom, 1024).unwrap()["openapi"], "3.1.0");
    }

    #[test]
    fn digest_and_title_match_the_reference() {
        assert_eq!(
            digest(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        let document = parse_document(
            br#"{"openapi": "3.0.3", "info": {"title": "Old", "version": "1"}}"#,
            1024,
        )
        .unwrap();
        assert_eq!(
            title_version(&document),
            (Some("Old".to_owned()), Some("1".to_owned()))
        );
        assert_eq!(title_version(&Map::new()), (None, None));
    }

    #[test]
    fn rate_limit_is_a_sliding_window_per_tenant() {
        let now = std::sync::Arc::new(std::sync::Mutex::new(0.0_f64));
        let read = now.clone();
        let mut limit = RateLimit::with_clock(
            2,
            HOUR,
            Box::new(move || *read.lock().expect("clock lock is never poisoned")),
        );
        let tenant = Uuid::from_u128(1);
        let other = Uuid::from_u128(2);
        assert!(limit.take(tenant));
        assert!(limit.take(tenant));
        assert!(!limit.take(tenant));
        assert!(limit.take(other));
        *now.lock().expect("clock lock is never poisoned") = HOUR;
        assert!(limit.take(tenant));
    }
}
