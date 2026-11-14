//! Pattern-constrained identifiers, versions and identities.
//!
//! Each type validates on construction and on JSON deserialization, so an invalid value can
//! never reach a model: the Rust equivalent of the reference's `Annotated[str, Field(pattern=…)]`
//! and `UUID7`/`AuthorityId` annotations. Identities are kept as canonical lowercase hyphenated
//! strings because this crate carries no UUID dependency; every rule the reference's `uuid.UUID`
//! checks are reproduced in [`canonical_uuid`].

use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::catalog::error::CatalogError;

/// Define a string newtype whose value must match an anchored, linear-time pattern.
macro_rules! pattern_id {
    ($name:ident, $pattern:literal, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap a value.
            pub fn new(value: impl Into<String>) -> Result<Self, CatalogError> {
                static PATTERN: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new($pattern).expect("identifier pattern is valid"));
                let value = value.into();
                if PATTERN.is_match(&value) {
                    Ok(Self(value))
                } else {
                    Err(CatalogError($message))
                }
            }

            /// The validated value.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CatalogError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

pattern_id!(Name, r"^[a-z][a-z0-9_]{0,63}$", "invalid catalog name");
pattern_id!(
    Operation,
    r"^[a-z][a-z0-9_]{0,31}\.[a-z][a-z0-9_]{0,31}$",
    "invalid operation name"
);
pattern_id!(
    AppKey,
    r"^[a-z][a-z0-9_-]{0,63}$",
    "invalid application key"
);
pattern_id!(Digest, r"^[a-f0-9]{64}$", "invalid digest");
pattern_id!(
    ImageDigest,
    r"^[a-z0-9][a-z0-9./:_-]*@sha256:[a-f0-9]{64}$",
    "invalid image digest"
);

/// A JSON Pointer: nothing outside the reference's pointer grammar, and at most 512 characters.
///
/// The reference's type is the straight pointer pattern plus `max_length=512`; the pattern
/// itself accepts newlines, so the length bound is what keeps it small.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pointer(String);

impl Pointer {
    /// Validate and wrap a pointer.
    pub fn new(value: impl Into<String>) -> Result<Self, CatalogError> {
        static PATTERN: LazyLock<Regex> = LazyLock::new(|| {
            Regex::new(r"^(?:/(?:[^~/]|~[01])*)*$").expect("pointer pattern is valid")
        });
        let value = value.into();
        if PATTERN.is_match(&value) && value.chars().count() <= 512 {
            Ok(Self(value))
        } else {
            Err(CatalogError("invalid JSON pointer"))
        }
    }

    /// The validated pointer.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for Pointer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Serialize for Pointer {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for Pointer {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
    }
}

impl TryFrom<&str> for Pointer {
    type Error = CatalogError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

/// A positive version: the reference's `int` in `1..=2147483647`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PositiveVersion(u32);

impl PositiveVersion {
    /// The largest accepted version.
    pub const MAX: u32 = 2_147_483_647;

    /// Validate and wrap a version.
    pub fn new(value: u64) -> Result<Self, CatalogError> {
        if (1..=u64::from(Self::MAX)).contains(&value) {
            Ok(Self(value as u32))
        } else {
            Err(CatalogError("version must be between 1 and 2147483647"))
        }
    }

    /// The version as a number.
    pub const fn get(self) -> u32 {
        self.0
    }
}

impl fmt::Display for PositiveVersion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}", self.0)
    }
}

impl Serialize for PositiveVersion {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_u32(self.0)
    }
}

impl<'de> Deserialize<'de> for PositiveVersion {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let value = u64::deserialize(deserializer)?;
        Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
    }
}

/// Parse a canonical hyphenated UUID (any case) and report its version nibble and whether the
/// variant is RFC 4122.
///
/// This reproduces the two checks the reference's `uuid.UUID` types apply: `UUID7` needs
/// version 7, and `AuthorityId` needs `variant == RFC_4122` (which is also what makes Python's
/// `UUID.version` non-`None`). Non-canonical input is rejected; the reference's Pydantic UUID
/// parsers reject it too.
fn canonical_uuid(value: &str) -> Option<(u8, bool)> {
    let bytes = value.as_bytes();
    if bytes.len() != 36 {
        return None;
    }
    for (index, byte) in bytes.iter().enumerate() {
        if matches!(index, 8 | 13 | 18 | 23) {
            if *byte != b'-' {
                return None;
            }
        } else if !byte.is_ascii_hexdigit() {
            return None;
        }
    }
    let version = (bytes[14] as char).to_digit(16)? as u8;
    let variant_nibble = (bytes[19] as char).to_digit(16)? as u8;
    Some((version, variant_nibble & 0xC == 0x8))
}

/// Define a UUID newtype over its canonical lowercase string form.
macro_rules! uuid_id {
    ($name:ident, $accepts:expr, $message:literal) => {
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validate and wrap an identity. Accepted values are normalized to lowercase.
            pub fn new(value: impl Into<String>) -> Result<Self, CatalogError> {
                let value = value.into();
                match canonical_uuid(&value) {
                    Some(parts) if $accepts(parts) => Ok(Self(value.to_ascii_lowercase())),
                    _ => Err(CatalogError($message)),
                }
            }

            /// The canonical lowercase identity.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl Serialize for $name {
            fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(|error| D::Error::custom(error.to_string()))
            }
        }

        impl TryFrom<&str> for $name {
            type Error = CatalogError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl From<$name> for String {
            fn from(value: $name) -> Self {
                value.0
            }
        }
    };
}

uuid_id!(
    Uuid7,
    |(version, rfc_variant): (u8, bool)| version == 7 && rfc_variant,
    "identity must be an RFC 9562 UUID version 7"
);
uuid_id!(
    AuthorityId,
    |(_version, rfc_variant): (u8, bool)| rfc_variant,
    "identity must be an RFC 9562 UUID"
);

/// The reference's `Literal[1]` schema version, accepted as an integer and nothing else.
pub(crate) fn one<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u8, D::Error> {
    let value = u64::deserialize(deserializer)?;
    if value == 1 {
        Ok(1)
    } else {
        Err(D::Error::custom("schema_version must be an integer 1"))
    }
}

/// Omitted `schema_version` defaults to 1.
pub(crate) const fn default_one() -> u8 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifiers_are_anchored() {
        assert!(Name::new("synthetic_tool").is_ok());
        assert!(Name::new("Tool").is_err());
        assert!(Name::new("tool\n").is_err());
        assert!(Name::new(format!("a{}", "b".repeat(64))).is_err());
        assert!(Operation::new("projects.get").is_ok());
        assert!(Operation::new("projects").is_err());
        assert!(Operation::new("Projects.get").is_err());
        assert!(AppKey::new("care-bus").is_ok());
        assert!(AppKey::new("Care_bus").is_err());
        assert!(Digest::new("a".repeat(64)).is_ok());
        assert!(Digest::new("A".repeat(64)).is_err());
        assert!(
            ImageDigest::new(format!("registry.example/runner@sha256:{}", "a".repeat(64))).is_ok()
        );
        assert!(ImageDigest::new("runner:latest").is_err());
        assert!(Pointer::new("").is_ok());
        assert!(Pointer::new("/a/b").is_ok());
        assert!(Pointer::new("a").is_err());
        assert!(Pointer::new("/a~2").is_err());
        assert!(Pointer::new(format!("/{}", "a".repeat(513))).is_err());
    }

    #[test]
    fn positive_versions_are_bounded() {
        assert_eq!(PositiveVersion::new(1).unwrap().get(), 1);
        assert!(PositiveVersion::new(2_147_483_647).is_ok());
        assert!(PositiveVersion::new(0).is_err());
        assert!(PositiveVersion::new(2_147_483_648).is_err());
    }

    #[test]
    fn uuid_checks_match_the_reference() {
        assert!(Uuid7::new("10000000-0000-7000-8000-000000000001").is_ok());
        assert_eq!(
            Uuid7::new("ABCDEF01-2345-7678-9ABC-DEF012345678")
                .unwrap()
                .as_str(),
            "abcdef01-2345-7678-9abc-def012345678"
        );
        // Version 7 with a non-RFC variant: Python's `UUID.version` is None.
        assert!(Uuid7::new("00000000-0000-7000-c000-00000000000a").is_err());
        assert!(Uuid7::new("00000000-0000-4000-8000-000000000001").is_err());
        assert!(AuthorityId::new("00000000-0000-0000-8000-000000000000").is_ok());
        assert!(AuthorityId::new("00000000-0000-0000-c000-000000000000").is_err());
        assert!(AuthorityId::new("not-a-uuid").is_err());
        assert!(AuthorityId::new("00000000000070008000000000000001").is_err());
    }
}
