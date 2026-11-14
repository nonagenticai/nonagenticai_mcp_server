//! Tool and toolkit lifecycle state machines, as data.
//!
//! The reference enforces these in SQL (`src/storage/catalog.py`) and in the toolkit service;
//! both matrices are reproduced here so the route layer has one source of truth.

use serde::{Deserialize, Serialize};

/// A version's lifecycle status. Both tools and toolkit versions use the same four values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VersionStatus {
    /// Editable, not usable by a binding.
    Draft,
    /// Usable by a binding.
    Published,
    /// Withdrawn; cannot be published again.
    Disabled,
    /// Terminal.
    Retired,
}

/// Every legal tool transition: `draft→published|disabled|retired`, `published→disabled|retired`,
/// `disabled→retired`. A tool also only ever moves *to* published, disabled or retired.
pub const TOOL_TRANSITIONS: &[(VersionStatus, VersionStatus)] = &[
    (VersionStatus::Draft, VersionStatus::Published),
    (VersionStatus::Draft, VersionStatus::Disabled),
    (VersionStatus::Draft, VersionStatus::Retired),
    (VersionStatus::Published, VersionStatus::Disabled),
    (VersionStatus::Published, VersionStatus::Retired),
    (VersionStatus::Disabled, VersionStatus::Retired),
];

/// Every legal toolkit transition: `draft→published|disabled`, `published→disabled`.
pub const TOOLKIT_TRANSITIONS: &[(VersionStatus, VersionStatus)] = &[
    (VersionStatus::Draft, VersionStatus::Published),
    (VersionStatus::Draft, VersionStatus::Disabled),
    (VersionStatus::Published, VersionStatus::Disabled),
];

/// May a tool version move from `from` to `to`?
pub fn tool_transition_allowed(from: VersionStatus, to: VersionStatus) -> bool {
    TOOL_TRANSITIONS.contains(&(from, to))
}

/// May a toolkit version move from `from` to `to`?
pub fn toolkit_transition_allowed(from: VersionStatus, to: VersionStatus) -> bool {
    TOOLKIT_TRANSITIONS.contains(&(from, to))
}

impl VersionStatus {
    /// Every status, in the reference's declaration order.
    pub const ALL: [Self; 4] = [Self::Draft, Self::Published, Self::Disabled, Self::Retired];

    /// The statuses a tool may move to from here.
    pub fn allowed_tool_transitions(self) -> impl Iterator<Item = Self> {
        TOOL_TRANSITIONS
            .iter()
            .filter(move |(from, _)| *from == self)
            .map(|(_, to)| *to)
    }

    /// The statuses a toolkit may move to from here.
    pub fn allowed_toolkit_transitions(self) -> impl Iterator<Item = Self> {
        TOOLKIT_TRANSITIONS
            .iter()
            .filter(move |(from, _)| *from == self)
            .map(|(_, to)| *to)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tool_matrix() {
        assert!(tool_transition_allowed(
            VersionStatus::Draft,
            VersionStatus::Published
        ));
        assert!(tool_transition_allowed(
            VersionStatus::Disabled,
            VersionStatus::Retired
        ));
        assert!(!tool_transition_allowed(
            VersionStatus::Published,
            VersionStatus::Draft
        ));
        assert!(!tool_transition_allowed(
            VersionStatus::Retired,
            VersionStatus::Disabled
        ));
    }

    #[test]
    fn toolkit_matrix() {
        assert!(toolkit_transition_allowed(
            VersionStatus::Published,
            VersionStatus::Disabled
        ));
        assert!(!toolkit_transition_allowed(
            VersionStatus::Draft,
            VersionStatus::Retired
        ));
        assert!(!toolkit_transition_allowed(
            VersionStatus::Disabled,
            VersionStatus::Published
        ));
    }

    #[test]
    fn statuses_serialize_as_reference_strings() {
        assert_eq!(
            serde_json::to_string(&VersionStatus::Draft).unwrap(),
            r#""draft""#
        );
        assert_eq!(
            serde_json::to_string(&VersionStatus::Disabled).unwrap(),
            r#""disabled""#
        );
    }
}
