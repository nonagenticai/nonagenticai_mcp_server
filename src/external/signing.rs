//! HMAC signing for the fr <-> MCP channel (spec section 3.1).
//!
//! The signature is `sha256=<hex>` over `<timestamp>.<raw body>`; a receiver rejects a
//! timestamp more than [`SKEW_SECONDS`] from its own clock. Ported from the reference
//! `src/external/signing.py`.

use std::collections::BTreeMap;

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

/// The receiver's accepted clock skew, in seconds.
pub const SKEW_SECONDS: i64 = 300;
/// The signature header (`sha256=<hex>`).
pub const SIGNATURE_HEADER: &str = "X-Channel-Signature";
/// The timestamp header: Unix seconds, ASCII digits.
pub const TIMESTAMP_HEADER: &str = "X-Channel-Timestamp";
/// The idempotency header: one fresh UUIDv4 per message.
pub const IDEMPOTENCY_HEADER: &str = "Idempotency-Key";

/// `sha256=<hex>` over `<timestamp>.<body>`.
///
/// `None` only if HMAC rejects the key length; HMAC accepts every length, so signing cannot
/// fail on any input a caller can supply here.
fn digest(body: &[u8], secret: &str, timestamp: &str) -> Option<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).ok()?;
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    Some(format!(
        "sha256={}",
        hex::encode(mac.finalize().into_bytes())
    ))
}

/// The three headers one signed channel message carries.
pub fn sign(body: &[u8], secret: &str, now: i64) -> BTreeMap<String, String> {
    let timestamp = now.to_string();
    let mut headers = BTreeMap::new();
    headers.insert(
        SIGNATURE_HEADER.to_owned(),
        digest(body, secret, &timestamp).expect("HMAC accepts keys of any length"),
    );
    headers.insert(TIMESTAMP_HEADER.to_owned(), timestamp);
    headers.insert(
        IDEMPOTENCY_HEADER.to_owned(),
        uuid::Uuid::new_v4().to_string(),
    );
    headers
}

/// True only for a fresh, correctly signed body. Never panics: any malformed header, timestamp
/// or signature is `false`.
pub fn verify(body: &[u8], headers: &BTreeMap<String, String>, secret: &str, now: i64) -> bool {
    verify_inner(body, headers, secret, now).unwrap_or(false)
}

fn verify_inner(
    body: &[u8],
    headers: &BTreeMap<String, String>,
    secret: &str,
    now: i64,
) -> Option<bool> {
    let lowered: BTreeMap<String, &str> = headers
        .iter()
        .map(|(name, value)| (name.to_lowercase(), value.as_str()))
        .collect();
    let signature = lowered.get(&SIGNATURE_HEADER.to_lowercase())?;
    let timestamp = lowered.get(&TIMESTAMP_HEADER.to_lowercase())?;
    // The reference's `timestamp.isascii() and timestamp.isdigit()`: ASCII digits only, so
    // whitespace, signs and Unicode digits are refusals, and an empty string never parses.
    if timestamp.is_empty() || !timestamp.bytes().all(|byte| byte.is_ascii_digit()) {
        return Some(false);
    }
    // Python's `int()` is unbounded; comparing as `i128` keeps any digit string total.
    let timestamp = match timestamp.parse::<i128>() {
        Ok(timestamp) => timestamp,
        Err(_) => return Some(false),
    };
    if (i128::from(now) - timestamp).abs() > i128::from(SKEW_SECONDS) {
        return Some(false);
    }
    let expected = digest(body, secret, &timestamp.to_string())?;
    Some(bool::from(signature.as_bytes().ct_eq(expected.as_bytes())))
}
