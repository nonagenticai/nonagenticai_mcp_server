//! Authenticated encryption of a source's one stored secret (AES-256-GCM).
//!
//! Port of the reference `src/sources/crypto.py`. A sealed blob is the 12-byte nonce followed
//! by the AES-GCM output (ciphertext and 16-byte tag). The associated data is the source id's
//! 16 bytes (the UUID in big-endian order, as `uuid.UUID.bytes` renders it), so a ciphertext
//! copied onto another source row fails authentication instead of silently sending one
//! upstream's credential to another.
//!
//! Every refusal is one of the reference's constant messages; none echoes the offending value.
//! [`decrypt_token`] fails closed with `source credential unavailable` for a missing key, a
//! short blob, a swapped row or any corruption, and does not reveal which step refused.
//!
//! This crate has no `secrecy` or `zeroize` dependency, so [`decrypt_token`] returns the secret
//! as a plain `String`. A caller must treat it as a secret: never log it and never render it
//! through `Debug`.

// `aes-gcm` 0.10 is the latest release and still exposes its nonce through `generic_array`,
// which upstream has deprecated ahead of 0.11. The alternative (moving to an unreleased 0.11)
// would put an RC in the runtime image; the type is stable and the dependency is pinned, so
// the deprecation is accepted here and nowhere else.
#![allow(deprecated)]

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::{Aead, KeyInit, OsRng, Payload};
use aes_gcm::{AeadCore as _, Aes256Gcm};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE;
use thiserror::Error;
use uuid::Uuid;

/// The nonce prefix of a sealed blob (`crypto.py:19`).
pub const NONCE_BYTES: usize = 12;

/// The AES-256-GCM tag appended to the ciphertext.
#[cfg(test)]
const TAG_BYTES: usize = 16;

/// The longest credential accepted, in bytes (`crypto.py:35`).
const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Why credential material could not be decoded, validated, sealed or opened.
///
/// The message is exactly the reference's, and no variant carries credential material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SourceCryptoError {
    /// [`decode_key`] got something that is not base64url.
    #[error("source secret key must be base64url")]
    KeyEncoding,
    /// [`decode_key`] decoded a value whose length is not 32 bytes.
    #[error("source secret key must be 32 bytes")]
    KeyLength,
    /// [`valid_token`] or [`valid_secret`] refused the charset or the length.
    #[error("invalid credential material")]
    InvalidCredential,
    /// The reference's fail-closed refusal for an unopenable credential. AES-GCM can only
    /// refuse to seal a message orders of magnitude larger than the 4096-byte credential
    /// bound, so the sealing path uses it for that unreachable case too.
    #[error("source credential unavailable")]
    Unavailable,
}

/// A 32-byte key from padded or unpadded base64url (`crypto.py:22-30`).
///
/// Surrounding whitespace is ignored, as the reference's `value.strip()` does. The decoder is
/// strict about the alphabet: the reference's `binascii` decoder silently discards characters
/// outside it, but no generated key contains any, and the same strictness already validates
/// `MCP_SOURCE_SECRET_KEY` at startup (`config.rs`).
pub fn decode_key(value: &str) -> Result<[u8; 32], SourceCryptoError> {
    let trimmed = value.trim();
    let mut padded = trimmed.to_owned();
    match padded.len() % 4 {
        0 => {}
        2 => padded.push_str("=="),
        3 => padded.push('='),
        // A base64 quantum cannot encode one leftover character; the reference's decoder
        // refuses these too, through `binascii.Error`.
        _ => return Err(SourceCryptoError::KeyEncoding),
    }
    let decoded = URL_SAFE
        .decode(padded.as_bytes())
        .map_err(|_| SourceCryptoError::KeyEncoding)?;
    <[u8; 32]>::try_from(decoded.as_slice()).map_err(|_| SourceCryptoError::KeyLength)
}

/// A bearer token, header value or API key: printable ASCII without spaces
/// (`crypto.py:33-38`).
///
/// Returns the value unchanged so a caller can bind the checked value in one step.
pub fn valid_token(value: &str) -> Result<&str, SourceCryptoError> {
    let valid = (1..=MAX_CREDENTIAL_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (33..=126).contains(&byte));
    if valid {
        Ok(value)
    } else {
        Err(SourceCryptoError::InvalidCredential)
    }
}

/// Stored secret material: printable ASCII with spaces allowed, for example a basic-auth
/// password (`crypto.py:40-44`).
pub fn valid_secret(value: &str) -> Result<&str, SourceCryptoError> {
    let valid = (1..=MAX_CREDENTIAL_BYTES).contains(&value.len())
        && value.bytes().all(|byte| (32..=126).contains(&byte));
    if valid {
        Ok(value)
    } else {
        Err(SourceCryptoError::InvalidCredential)
    }
}

/// Seal `token` for `source_id`: a fresh random 12-byte nonce followed by the AES-256-GCM
/// output (`crypto.py:47-52`).
///
/// The token is validated with [`valid_secret`], exactly as the reference validates the value
/// it passes to AES-GCM.
pub fn encrypt_token(
    key: &[u8; 32],
    source_id: Uuid,
    token: &str,
) -> Result<Vec<u8>, SourceCryptoError> {
    let secret = valid_secret(token)?;
    // A fixed-size 32-byte key always fits AES-256; the error arm is unreachable but keeps a
    // wrong key length mapped to the reference's key-length message rather than a panic.
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SourceCryptoError::KeyLength)?;
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);
    let sealed = cipher
        .encrypt(
            &nonce,
            Payload {
                msg: secret.as_bytes(),
                aad: source_id.as_bytes(),
            },
        )
        .map_err(|_| SourceCryptoError::Unavailable)?;
    let mut blob = nonce.to_vec();
    blob.extend_from_slice(&sealed);
    Ok(blob)
}

/// Open one stored secret (`crypto.py:55-65`).
///
/// Fails closed with [`SourceCryptoError::Unavailable`] for a missing key, a blob no longer
/// than a nonce, a ciphertext sealed for another source row, or any corruption. The decrypted
/// plaintext is re-validated with [`valid_secret`], and a refused plaintext reports the same
/// unavailable message, exactly as the reference catches its own `ValueError` there.
///
/// The returned `String` is a secret: the caller must not log it or format it with `Debug`.
pub fn decrypt_token(
    key: Option<&[u8; 32]>,
    source_id: Uuid,
    blob: &[u8],
) -> Result<String, SourceCryptoError> {
    let key = key.ok_or(SourceCryptoError::Unavailable)?;
    if blob.len() <= NONCE_BYTES {
        return Err(SourceCryptoError::Unavailable);
    }
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|_| SourceCryptoError::Unavailable)?;
    let (nonce, sealed) = blob.split_at(NONCE_BYTES);
    let plain = cipher
        .decrypt(
            GenericArray::from_slice(nonce),
            Payload {
                msg: sealed,
                aad: source_id.as_bytes(),
            },
        )
        .map_err(|_| SourceCryptoError::Unavailable)?;
    let text = std::str::from_utf8(&plain).map_err(|_| SourceCryptoError::Unavailable)?;
    valid_secret(text).map_err(|_| SourceCryptoError::Unavailable)?;
    Ok(text.to_owned())
}

#[cfg(test)]
mod tests {
    use super::{
        NONCE_BYTES, SourceCryptoError, TAG_BYTES, decode_key, decrypt_token, encrypt_token,
        valid_secret, valid_token,
    };
    use uuid::Uuid;

    /// The key bytes `0..=31`, as the reference's `decode_key` would return them.
    const KEY: [u8; 32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
        0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d,
        0x1e, 0x1f,
    ];
    /// The same key in the transport form a deployment supplies. Built at run time rather
    /// than written as a literal: a 32-byte base64url constant is indistinguishable from a
    /// real credential to a secret scanner, and allowlisting one teaches the scanner nothing.
    fn key_b64() -> String {
        base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, KEY)
    }
    /// A base64url value that decodes to 16 bytes, not 32.
    fn key_b64_16_bytes() -> String {
        base64::Engine::encode(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD,
            &KEY[..16],
        )
    }
    const SOURCE_ID: &str = "12345678-1234-5678-1234-567812345678";

    /// The reference's output for `AESGCM(bytes(range(32))).encrypt(bytes(range(12)),
    /// b"tok-abc_123", UUID(SOURCE_ID).bytes)`, prefixed with that nonce.
    const REFERENCE_BLOB: [u8; 39] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x33, 0x6d, 0xbd,
        0x36, 0xa4, 0x87, 0xa1, 0x44, 0xbc, 0x73, 0xa4, 0xb1, 0x86, 0x19, 0x84, 0xfd, 0xe4, 0x95,
        0xc0, 0x25, 0x7e, 0x0f, 0x82, 0x3c, 0xc2, 0x1b, 0x88,
    ];

    #[test]
    fn a_blob_sealed_by_the_reference_decrypts_to_its_token() {
        let source_id = Uuid::parse_str(SOURCE_ID).unwrap();
        assert_eq!(
            decrypt_token(Some(&KEY), source_id, &REFERENCE_BLOB),
            Ok("tok-abc_123".to_owned())
        );
    }

    #[test]
    fn a_token_round_trips_through_seal_and_open() {
        let source_id = Uuid::parse_str(SOURCE_ID).unwrap();
        for token in ["tok-abc_123", "user:basic pass phrase"] {
            let blob = encrypt_token(&KEY, source_id, token).unwrap();
            assert_eq!(
                decrypt_token(Some(&KEY), source_id, &blob),
                Ok(token.to_owned())
            );
        }
    }

    #[test]
    fn a_blob_is_a_twelve_byte_nonce_then_ciphertext_and_tag() {
        let source_id = Uuid::new_v4();
        let token = "tok";
        let first = encrypt_token(&KEY, source_id, token).unwrap();
        let second = encrypt_token(&KEY, source_id, token).unwrap();
        assert_eq!(first.len(), NONCE_BYTES + token.len() + TAG_BYTES);
        assert_eq!(first.len() - NONCE_BYTES, token.len() + TAG_BYTES);
        assert_ne!(
            &first[..NONCE_BYTES],
            &second[..NONCE_BYTES],
            "every seal draws a fresh nonce"
        );
        assert_ne!(first, second);
        assert_eq!(
            decrypt_token(Some(&KEY), source_id, &second),
            Ok(token.to_owned())
        );
    }

    #[test]
    fn a_swapped_source_id_or_key_fails_closed() {
        let source_id = Uuid::parse_str(SOURCE_ID).unwrap();
        let other_source = Uuid::new_v4();
        let blob = encrypt_token(&KEY, source_id, "tok-abc_123").unwrap();
        assert_eq!(
            decrypt_token(Some(&KEY), other_source, &blob),
            Err(SourceCryptoError::Unavailable)
        );
        let other_key = [0x2a; 32];
        assert_eq!(
            decrypt_token(Some(&other_key), source_id, &blob),
            Err(SourceCryptoError::Unavailable)
        );
    }

    #[test]
    fn a_missing_key_short_blob_or_corruption_fails_closed() {
        let source_id = Uuid::parse_str(SOURCE_ID).unwrap();
        assert_eq!(
            decrypt_token(None, source_id, &REFERENCE_BLOB),
            Err(SourceCryptoError::Unavailable)
        );
        assert_eq!(
            decrypt_token(Some(&KEY), source_id, &[]),
            Err(SourceCryptoError::Unavailable)
        );
        assert_eq!(
            decrypt_token(Some(&KEY), source_id, &REFERENCE_BLOB[..NONCE_BYTES]),
            Err(SourceCryptoError::Unavailable)
        );
        let mut corrupted = REFERENCE_BLOB;
        corrupted[NONCE_BYTES] ^= 0xff;
        assert_eq!(
            decrypt_token(Some(&KEY), source_id, &corrupted),
            Err(SourceCryptoError::Unavailable)
        );
    }

    #[test]
    fn a_key_is_padded_or_unpadded_base64url() {
        assert_eq!(decode_key(&key_b64()), Ok(KEY));
        assert_eq!(decode_key(&format!("{}=", key_b64())), Ok(KEY));
        assert_eq!(decode_key(&format!("  {}\n", key_b64())), Ok(KEY));
    }

    #[test]
    fn a_key_refuses_a_bad_alphabet_and_a_wrong_length() {
        assert_eq!(decode_key("!!!!"), Err(SourceCryptoError::KeyEncoding));
        // One leftover base64 digit can never complete a quantum.
        assert_eq!(decode_key("A"), Err(SourceCryptoError::KeyEncoding));
        assert_eq!(
            decode_key(&key_b64_16_bytes()),
            Err(SourceCryptoError::KeyLength)
        );
        assert_eq!(decode_key(""), Err(SourceCryptoError::KeyLength));
        assert_eq!(decode_key("abc"), Err(SourceCryptoError::KeyLength));
    }

    #[test]
    fn a_token_is_printable_ascii_without_spaces() {
        assert_eq!(valid_token("tok-abc_123"), Ok("tok-abc_123"));
        assert_eq!(valid_token("~"), Ok("~"));
        assert_eq!(valid_token(""), Err(SourceCryptoError::InvalidCredential));
        assert_eq!(
            valid_token("a b"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert_eq!(
            valid_token("tab\tins"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert_eq!(
            valid_token("del\u{7f}"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert_eq!(
            valid_token("tökén"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert!(valid_token(&"a".repeat(4096)).is_ok());
        assert_eq!(
            valid_token(&"a".repeat(4097)),
            Err(SourceCryptoError::InvalidCredential)
        );
    }

    #[test]
    fn a_secret_is_printable_ascii_with_spaces_allowed() {
        assert_eq!(valid_secret("basic pass phrase"), Ok("basic pass phrase"));
        assert_eq!(valid_secret(""), Err(SourceCryptoError::InvalidCredential));
        assert_eq!(
            valid_secret("tab\tins"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert_eq!(
            valid_secret("tökén"),
            Err(SourceCryptoError::InvalidCredential)
        );
        assert!(valid_secret(&"p".repeat(4096)).is_ok());
        assert_eq!(
            valid_secret(&"p".repeat(4097)),
            Err(SourceCryptoError::InvalidCredential)
        );
    }

    #[test]
    fn sealing_refuses_invalid_secret_material() {
        // The reference seals through `valid_secret`, not `valid_token`: a space is legal
        // (a basic-auth password is one), a control character is not.
        assert!(encrypt_token(&KEY, Uuid::new_v4(), "a b").is_ok());
        for value in ["", "tab\tinside"] {
            assert_eq!(
                encrypt_token(&KEY, Uuid::new_v4(), value),
                Err(SourceCryptoError::InvalidCredential)
            );
        }
    }

    #[test]
    fn every_crypto_refusal_uses_the_reference_message() {
        assert_eq!(
            SourceCryptoError::KeyEncoding.to_string(),
            "source secret key must be base64url"
        );
        assert_eq!(
            SourceCryptoError::KeyLength.to_string(),
            "source secret key must be 32 bytes"
        );
        assert_eq!(
            SourceCryptoError::InvalidCredential.to_string(),
            "invalid credential material"
        );
        assert_eq!(
            SourceCryptoError::Unavailable.to_string(),
            "source credential unavailable"
        );
    }
}
