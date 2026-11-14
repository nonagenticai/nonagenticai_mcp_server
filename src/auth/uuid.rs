//! UUID identities, parsed and rendered without a UUID dependency.
//!
//! Licence-authority identities (`tenant_id`, `license_id`) may be any RFC 4122/9562 version:
//! the licences service inserts rows with SQL `gen_random_uuid()` (v4) while this service mints
//! v7. The reference implementation parses them with Python's `uuid.UUID` and accepts a value
//! only when the variant is RFC 4122 and the version is not the nil version — reproduced here.
//! Text forms Python accepts (case, `urn:uuid:`, braces, missing hyphens) are canonicalised to
//! the lowercase hyphenated form.

use std::fmt;

/// A parsed RFC 4122/9562 UUID (any non-nil version).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Rfc4122Uuid([u8; 16]);

impl Rfc4122Uuid {
    /// Parse `value`, rejecting anything Python's `uuid.UUID` would reject or whose variant is
    /// not RFC 4122 / whose version is the nil version.
    pub fn parse(value: &str) -> Option<Self> {
        let lowered = value.to_ascii_lowercase();
        let body = match lowered.strip_prefix("urn:uuid:") {
            Some(rest) => rest,
            None => lowered.as_str(),
        };
        let body = body.trim_matches(|c| c == '{' || c == '}');
        let hex: String = body.chars().filter(|c| *c != '-').collect();
        if hex.len() != 32 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut bytes = [0u8; 16];
        let (pairs, remainder) = hex.as_bytes().as_chunks::<2>();
        if !remainder.is_empty() {
            return None;
        }
        for (slot, pair) in bytes.iter_mut().zip(pairs) {
            *slot = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        // Version 0 is the nil UUID; Python's `version` attribute is None for it.
        if bytes[6] >> 4 == 0 {
            return None;
        }
        // RFC 4122 variant: the two most significant bits of octet 8 are `10`.
        if bytes[8] & 0xC0 != 0x80 {
            return None;
        }
        Some(Self(bytes))
    }
}

impl fmt::Display for Rfc4122Uuid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = &self.0;
        write!(
            f,
            "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            b[0],
            b[1],
            b[2],
            b[3],
            b[4],
            b[5],
            b[6],
            b[7],
            b[8],
            b[9],
            b[10],
            b[11],
            b[12],
            b[13],
            b[14],
            b[15]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const V7: &str = "01900000-0000-7000-8000-00000000f001";
    const V4: &str = "5f868d42-03f8-41f0-a93c-3e83070dc196";

    #[test]
    fn accepts_rfc4122_versions_in_every_python_text_form() {
        let canonical = Rfc4122Uuid::parse(V7).expect("v7");
        assert_eq!(canonical.to_string(), V7);
        assert_eq!(
            Rfc4122Uuid::parse(&V7.to_ascii_uppercase()).unwrap(),
            canonical
        );
        assert_eq!(
            Rfc4122Uuid::parse(&format!("urn:uuid:{V7}")).unwrap(),
            canonical
        );
        assert_eq!(Rfc4122Uuid::parse(&format!("{{{V7}}}")).unwrap(), canonical);
        assert_eq!(Rfc4122Uuid::parse(&V7.replace('-', "")).unwrap(), canonical);
        assert_eq!(Rfc4122Uuid::parse(V4).unwrap().to_string(), V4);
    }

    #[test]
    fn rejects_non_rfc4122_values() {
        // nil version
        assert!(Rfc4122Uuid::parse("00000000-0000-0000-0000-000000000000").is_none());
        // Microsoft/reserved variant (fourth group does not start 8..b)
        assert!(Rfc4122Uuid::parse("01900000-0000-7000-c000-00000000f001").is_none());
        assert!(Rfc4122Uuid::parse("01900000-0000-7000-0000-00000000f001").is_none());
        // wrong length / non-hex / garbage
        assert!(Rfc4122Uuid::parse("01900000-0000-7000-8000-00000000f00").is_none());
        assert!(Rfc4122Uuid::parse("01900000-0000-7000-8000-00000000f00z").is_none());
        assert!(Rfc4122Uuid::parse("").is_none());
    }
}
