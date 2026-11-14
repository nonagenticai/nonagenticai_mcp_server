//! Strict toolkit models: exact selections, inclusions, descriptors and the bound context.
//!
//! The reference keeps these in `src/toolkits/models.py`; this crate owns `src/catalog/**` for
//! the domain slice, so they live here until the toolkit service module lands. Field names are
//! the reference field names exactly.

use std::collections::HashSet;
use std::sync::LazyLock;

use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};

use crate::catalog::error::CatalogError;
use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7, default_one, one};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    ExactReference, OperationConstraints, ToolLimits, optional_text_1_1024, text_1_4096,
    vec_max_32, vec_max_100, vec_max_128,
};

/// A tool pin that names its owner: the binding's tenant or the reserved platform tenant.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolReference {
    /// A UUIDv7 identity.
    pub id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The tool's owner.
    pub tenant_id: AuthorityId,
}

/// One tool selected into a toolkit, with its own rules and limits.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolSelection {
    /// The exact tool.
    pub tool: ToolReference,
    /// At most 100 per-operation rule sets.
    #[serde(default, deserialize_with = "vec_max_100")]
    pub operation_constraints: Vec<OperationConstraints>,
    /// Limits overriding the tool's own.
    #[serde(default)]
    pub limits: ToolLimits,
}

/// The optional applicability labels a toolkit declares.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Applicability {
    /// Capability label.
    #[serde(default)]
    pub capability: Option<Name>,
    /// Project phase label.
    #[serde(default)]
    pub project_phase: Option<Name>,
    /// Work type label.
    #[serde(default)]
    pub work_type: Option<Name>,
    /// Card stage label.
    #[serde(default)]
    pub card_stage: Option<Name>,
    /// Responsibility label.
    #[serde(default)]
    pub responsibility: Option<Name>,
}

/// A toolkit contract version.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::ToolkitManifest")]
pub struct ToolkitManifest {
    /// Always 1.
    pub schema_version: u8,
    /// A UUIDv7 identity.
    pub toolkit_id: Uuid7,
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// The exact version.
    pub version: PositiveVersion,
    /// The toolkit name.
    pub name: Name,
    /// Human description, 1 to 4096 characters.
    pub description: String,
    /// Selected tools, at most 128.
    pub tools: Vec<ToolSelection>,
    /// Included toolkits, at most 32.
    pub includes: Vec<ExactReference>,
    /// Applicability labels.
    pub applicability: Applicability,
}

impl ToolkitManifest {
    fn validate(&self) -> Result<(), CatalogError> {
        let tools: HashSet<(&str, &str, u32)> = self
            .tools
            .iter()
            .map(|selection| {
                (
                    selection.tool.tenant_id.as_str(),
                    selection.tool.id.as_str(),
                    selection.tool.version.get(),
                )
            })
            .collect();
        let includes: HashSet<(&str, u32)> = self
            .includes
            .iter()
            .map(|reference| (reference.id.as_str(), reference.version.get()))
            .collect();
        if tools.len() != self.tools.len() || includes.len() != self.includes.len() {
            return Err(CatalogError("duplicate exact reference"));
        }
        if self
            .includes
            .iter()
            .any(|reference| reference.id == self.toolkit_id)
        {
            return Err(CatalogError("self inclusion is forbidden"));
        }
        if self.tools.is_empty() && self.includes.is_empty() {
            return Err(CatalogError("a toolkit must select tools"));
        }
        Ok(())
    }
}

/// One selected tool as the resolver flattens it, with its public name.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EffectiveTool {
    /// The exact tool.
    pub tool: ToolReference,
    /// At most 100 per-operation rule sets.
    #[serde(default, deserialize_with = "vec_max_100")]
    pub operation_constraints: Vec<OperationConstraints>,
    /// Limits overriding the tool's own.
    #[serde(default)]
    pub limits: ToolLimits,
    /// The tool's MCP name.
    pub public_name: Name,
}

/// A toolkit version as stored and served.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitDescriptor {
    /// The manifest.
    pub manifest: ToolkitManifest,
    /// The identity's revision at this version.
    pub revision: PositiveVersion,
    /// The lifecycle status.
    pub status: VersionStatus,
    /// The flattened effective tools.
    pub tools: Vec<EffectiveTool>,
}

/// The tenant-bound context a binding gives every tool call.
///
/// `FIELD_NAMES` is the source of truth for [`crate::catalog::public::validate_public_input`]:
/// a public input schema may not name any of these.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BoundContext {
    /// The tenant.
    pub tenant_id: AuthorityId,
    /// The project, when the tool is project-scoped.
    #[serde(default)]
    pub project_id: Option<Uuid7>,
    /// The workspace, when workspace-scoped.
    #[serde(default)]
    pub workspace_id: Option<Uuid7>,
    /// The project phase label.
    #[serde(default)]
    pub project_phase: Option<Name>,
    /// The work type label.
    #[serde(default)]
    pub work_type: Option<Name>,
    /// The card stage label.
    #[serde(default)]
    pub card_stage: Option<Name>,
    /// The responsibility label.
    #[serde(default)]
    pub responsibility: Option<Name>,
    /// The test command this context runs.
    #[serde(default, deserialize_with = "optional_text_1_1024")]
    pub test_command: Option<String>,
    /// The reviewed commit, 40 to 64 lowercase hex characters.
    #[serde(default, deserialize_with = "optional_commit")]
    pub reviewed_commit: Option<String>,
}

impl BoundContext {
    /// Every field name a public input schema must not expose.
    pub const FIELD_NAMES: &'static [&'static str] = &[
        "tenant_id",
        "project_id",
        "workspace_id",
        "project_phase",
        "work_type",
        "card_stage",
        "responsibility",
        "test_command",
        "reviewed_commit",
    ];
}

fn optional_commit<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Option<String>, D::Error> {
    static PATTERN: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[a-f0-9]{40,64}$").expect("field pattern is valid"));
    match Option::<String>::deserialize(deserializer)? {
        Some(value) if PATTERN.is_match(&value) => Ok(Some(value)),
        Some(_) => Err(D::Error::custom("invalid reviewed commit")),
        None => Ok(None),
    }
}

mod wire {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct ToolkitManifest {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub toolkit_id: Uuid7,
        pub tenant_id: AuthorityId,
        pub version: PositiveVersion,
        pub name: Name,
        #[serde(deserialize_with = "text_1_4096")]
        pub description: String,
        #[serde(default, deserialize_with = "vec_max_128")]
        pub tools: Vec<ToolSelection>,
        #[serde(default, deserialize_with = "vec_max_32")]
        pub includes: Vec<ExactReference>,
        #[serde(default)]
        pub applicability: Applicability,
    }

    impl TryFrom<ToolkitManifest> for super::ToolkitManifest {
        type Error = CatalogError;

        fn try_from(wire: ToolkitManifest) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                toolkit_id: wire.toolkit_id,
                tenant_id: wire.tenant_id,
                version: wire.version,
                name: wire.name,
                description: wire.description,
                tools: wire.tools,
                includes: wire.includes,
                applicability: wire.applicability,
            };
            model.validate()?;
            Ok(model)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn manifest(value: serde_json::Value) -> Result<ToolkitManifest, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn base() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "toolkit_id": "20000000-0000-7000-8000-000000000001",
            "tenant_id": "10000000-0000-7000-8000-000000000001",
            "version": 1,
            "name": "synthetic_toolkit",
            "description": "Synthetic toolkit",
            "tools": [{
                "tool": {
                    "id": "20000000-0000-7000-8000-000000000002",
                    "version": 1,
                    "tenant_id": "10000000-0000-7000-8000-000000000001"
                }
            }]
        })
    }

    #[test]
    fn accepts_a_minimal_toolkit() {
        assert!(manifest(base()).is_ok());
    }

    #[test]
    fn refuses_duplicates_self_inclusion_and_empty_selections() {
        let mut value = base();
        value["tools"] = json!([base()["tools"][0], base()["tools"][0]]);
        assert!(manifest(value).is_err());

        let mut value = base();
        value["tools"] = json!([]);
        value["includes"] = json!([{
            "id": "20000000-0000-7000-8000-000000000001",
            "version": 1
        }]);
        assert!(
            manifest(value)
                .unwrap_err()
                .to_string()
                .contains("self inclusion")
        );

        let mut value = base();
        value["tools"] = json!([]);
        assert!(
            manifest(value)
                .unwrap_err()
                .to_string()
                .contains("must select tools")
        );
    }

    #[test]
    fn bound_context_names_are_the_reference_names() {
        assert_eq!(
            BoundContext::FIELD_NAMES,
            [
                "tenant_id",
                "project_id",
                "workspace_id",
                "project_phase",
                "work_type",
                "card_stage",
                "responsibility",
                "test_command",
                "reviewed_commit",
            ]
        );
    }
}
