//! Strict toolkit models: exact selections, inclusions, descriptors and the bound context.
//!
//! The reference keeps these in `src/toolkits/models.py`; this crate owns `src/catalog/**` for
//! the domain slice, so they live here until the toolkit service module lands. Field names are
//! the reference field names exactly.

use std::collections::HashSet;
use std::sync::LazyLock;

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::catalog::error::CatalogError;
use crate::catalog::ids::{AppKey, AuthorityId, Name, PositiveVersion, Uuid7, default_one, one};
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

/// A binding's exact toolkit pin.
///
/// `tenant_id` is the toolkit's owner: the binding's tenant or the reserved platform tenant,
/// never any other tenant. Omitted, it is the binding's tenant; stored specs always carry it
/// explicitly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitReference {
    /// A UUIDv7 identity.
    pub id: Uuid7,
    /// The exact version.
    pub version: PositiveVersion,
    /// The toolkit's owner, when the spec names it.
    #[serde(default)]
    pub tenant_id: Option<AuthorityId>,
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

/// One service credential a credential profile resolves.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialReference {
    /// The service key.
    pub service: Name,
    /// The alias the runtime resolves.
    pub alias: Name,
    /// The licence that mints the credential.
    pub license_id: AuthorityId,
    /// The licence application key.
    pub app_key: AppKey,
    /// The licences bundle key the minter names explicitly; absent lets licences choose.
    #[serde(default)]
    pub bundle: Option<AppKey>,
}

/// A tenant credential profile: one gateway plus per-service references.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "wire::CredentialProfile")]
pub struct CredentialProfile {
    /// Always 1.
    pub schema_version: u8,
    /// A UUIDv7 identity.
    pub profile_id: Uuid7,
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// The profile name.
    pub name: Name,
    /// The gateway credential.
    pub gateway: CredentialReference,
    /// Per-service credentials, at most 128, one per service.
    pub services: Vec<CredentialReference>,
}

impl CredentialProfile {
    fn validate(&self) -> Result<(), CatalogError> {
        let mut services: HashSet<&str> = HashSet::with_capacity(self.services.len());
        for reference in &self.services {
            if !services.insert(reference.service.as_str()) {
                return Err(CatalogError("duplicate service credential reference"));
            }
        }
        Ok(())
    }
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

    /// The context's public values: every absent field omitted, exactly the reference's
    /// `model_dump(mode="json", exclude_none=True)`.
    pub fn public_values(&self) -> Value {
        let Value::Object(mut values) =
            serde_json::to_value(self).expect("a bound context is JSON-serializable")
        else {
            unreachable!("a bound context serializes to a JSON object");
        };
        values.retain(|_, value| !value.is_null());
        Value::Object(values)
    }
}

/// A binding contract version: the exact toolkits, context and limits one binding pins.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(try_from = "wire::BindingSpec")]
pub struct BindingSpec {
    /// Always 1.
    pub schema_version: u8,
    /// The credential profile the runtime resolves service credentials from.
    pub credential_profile_id: Uuid7,
    /// The pinned toolkits, 1 to 32.
    pub toolkits: Vec<ToolkitReference>,
    /// An exact tool subset, at most 128; absent selects every toolkit tool.
    pub tool_subset: Option<Vec<ToolReference>>,
    /// The tenant-bound context every call carries.
    pub context: BoundContext,
    /// Per-operation rules the broker re-enforces, at most 100.
    pub operation_constraints: Vec<OperationConstraints>,
    /// Limits narrowing every tool's own.
    pub limits: ToolLimits,
    /// The binding's expiry; a timezone-aware RFC 3339 instant.
    pub expires_at: DateTime<Utc>,
    /// Whether the binding may serve calls.
    pub enabled: bool,
}

impl BindingSpec {
    fn validate(&self) -> Result<(), CatalogError> {
        unique_exact_references(&self.toolkits)?;
        if let Some(subset) = &self.tool_subset {
            unique_exact_references(subset)?;
        }
        Ok(())
    }
}

/// Refuse a list holding two identical serialised references, exactly as the reference compares
/// `model_dump_json()`: field values, not identity alone, decide duplication.
fn unique_exact_references<T: Serialize>(references: &[T]) -> Result<(), CatalogError> {
    let mut seen: HashSet<String> = HashSet::with_capacity(references.len());
    for reference in references {
        let encoded = serde_json::to_string(reference).expect("a reference is JSON-serializable");
        if !seen.insert(encoded) {
            return Err(CatalogError("duplicate exact reference"));
        }
    }
    Ok(())
}

/// The spec with every toolkit owner explicit: an omitted owner is the binding's tenant. The
/// filled spec is validated again, exactly as the reference re-parses it.
pub fn owned_toolkits(
    spec: BindingSpec,
    tenant: &AuthorityId,
) -> Result<BindingSpec, CatalogError> {
    let toolkits: Vec<ToolkitReference> = spec
        .toolkits
        .iter()
        .map(|reference| ToolkitReference {
            id: reference.id.clone(),
            version: reference.version,
            tenant_id: Some(
                reference
                    .tenant_id
                    .clone()
                    .unwrap_or_else(|| tenant.clone()),
            ),
        })
        .collect();
    let owned = BindingSpec { toolkits, ..spec };
    owned.validate()?;
    Ok(owned)
}

/// A stored binding as served: identity, revision, spec and its flattened tools.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingDescriptor {
    /// A UUIDv7 identity.
    pub binding_id: Uuid7,
    /// The owning tenant.
    pub tenant_id: AuthorityId,
    /// The gateway licence the binding serves.
    pub gateway_license_id: AuthorityId,
    /// The identity's revision at this spec.
    pub revision: PositiveVersion,
    /// Whether the binding is revoked.
    pub revoked: bool,
    /// The binding spec.
    pub spec: BindingSpec,
    /// The flattened effective tools.
    pub tools: Vec<EffectiveTool>,
}

/// An optimistic-concurrency precondition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevisionRequest {
    /// The revision the caller last read.
    pub expected_revision: PositiveVersion,
}

/// Replace a binding's spec at an expected revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingUpdate {
    /// The revision the caller last read.
    pub expected_revision: PositiveVersion,
    /// The replacement spec.
    pub spec: BindingSpec,
}

/// Replace a toolkit's manifest at an expected revision.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ToolkitUpdate {
    /// The revision the caller last read.
    pub expected_revision: PositiveVersion,
    /// The replacement manifest.
    pub manifest: ToolkitManifest,
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

/// A binding needs one to 32 toolkit references.
fn toolkits_1_32<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<ToolkitReference>, D::Error> {
    let references = Vec::<ToolkitReference>::deserialize(deserializer)?;
    if references.is_empty() || references.len() > 32 {
        Err(D::Error::custom(
            "a binding needs 1 to 32 toolkit references",
        ))
    } else {
        Ok(references)
    }
}

/// An exact tool subset holds at most 128 references.
fn optional_tool_subset<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<Vec<ToolReference>>, D::Error> {
    match Option::<Vec<ToolReference>>::deserialize(deserializer)? {
        Some(references) if references.len() > 128 => Err(D::Error::custom("at most 128 entries")),
        subset => Ok(subset),
    }
}

/// Omitted `enabled` defaults to true.
const fn default_true() -> bool {
    true
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

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct CredentialProfile {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub profile_id: Uuid7,
        pub tenant_id: AuthorityId,
        pub name: Name,
        pub gateway: CredentialReference,
        #[serde(default, deserialize_with = "vec_max_128")]
        pub services: Vec<CredentialReference>,
    }

    impl TryFrom<CredentialProfile> for super::CredentialProfile {
        type Error = CatalogError;

        fn try_from(wire: CredentialProfile) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                profile_id: wire.profile_id,
                tenant_id: wire.tenant_id,
                name: wire.name,
                gateway: wire.gateway,
                services: wire.services,
            };
            model.validate()?;
            Ok(model)
        }
    }

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    pub struct BindingSpec {
        #[serde(default = "default_one", deserialize_with = "one")]
        pub schema_version: u8,
        pub credential_profile_id: Uuid7,
        #[serde(deserialize_with = "toolkits_1_32")]
        pub toolkits: Vec<ToolkitReference>,
        #[serde(default, deserialize_with = "optional_tool_subset")]
        pub tool_subset: Option<Vec<ToolReference>>,
        pub context: BoundContext,
        #[serde(default, deserialize_with = "vec_max_100")]
        pub operation_constraints: Vec<OperationConstraints>,
        #[serde(default)]
        pub limits: ToolLimits,
        pub expires_at: DateTime<Utc>,
        #[serde(default = "default_true")]
        pub enabled: bool,
    }

    impl TryFrom<BindingSpec> for super::BindingSpec {
        type Error = CatalogError;

        fn try_from(wire: BindingSpec) -> Result<Self, Self::Error> {
            let model = Self {
                schema_version: wire.schema_version,
                credential_profile_id: wire.credential_profile_id,
                toolkits: wire.toolkits,
                tool_subset: wire.tool_subset,
                context: wire.context,
                operation_constraints: wire.operation_constraints,
                limits: wire.limits,
                expires_at: wire.expires_at,
                enabled: wire.enabled,
            };
            model.validate()?;
            Ok(model)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalog::ids::AuthorityId;
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

    const TENANT: &str = "10000000-0000-7000-8000-000000000001";
    const OTHER_AUTHORITY: &str = "10000000-0000-7000-8000-000000000009";
    const TOOLKIT: &str = "20000000-0000-7000-8000-000000000001";
    const TOOL: &str = "20000000-0000-7000-8000-000000000002";
    const PROFILE: &str = "20000000-0000-7000-8000-000000000003";
    const PROJECT: &str = "20000000-0000-7000-8000-000000000004";

    fn parse<T: serde::de::DeserializeOwned>(
        value: serde_json::Value,
    ) -> Result<T, serde_json::Error> {
        serde_json::from_value(value)
    }

    fn binding() -> serde_json::Value {
        json!({
            "schema_version": 1,
            "credential_profile_id": PROFILE,
            "toolkits": [{"id": TOOLKIT, "version": 1}],
            "context": {"tenant_id": TENANT, "project_id": PROJECT},
            "expires_at": "2026-11-14T00:00:00Z",
        })
    }

    #[test]
    fn binding_specs_parse_a_timezone_aware_expiry_and_refuse_a_naive_one() {
        let spec: BindingSpec = parse(binding()).expect("a valid binding");
        assert_eq!(
            spec.expires_at,
            "2026-11-14T00:00:00Z"
                .parse::<DateTime<Utc>>()
                .expect("a fixed instant")
        );
        let mut value = binding();
        value["expires_at"] = json!("2026-11-14T00:00:00");
        assert!(parse::<BindingSpec>(value).is_err());
    }

    #[test]
    fn binding_specs_refuse_duplicate_exact_references() {
        let mut value = binding();
        value["toolkits"] = json!([
            {"id": TOOLKIT, "version": 1},
            {"id": TOOLKIT, "version": 1}
        ]);
        assert!(
            parse::<BindingSpec>(value)
                .unwrap_err()
                .to_string()
                .contains("duplicate exact reference")
        );

        let mut value = binding();
        value["tool_subset"] = json!([
            {"id": TOOL, "version": 1, "tenant_id": TENANT},
            {"id": TOOL, "version": 1, "tenant_id": TENANT}
        ]);
        assert!(
            parse::<BindingSpec>(value)
                .unwrap_err()
                .to_string()
                .contains("duplicate exact reference")
        );

        // An omitted owner serialises as null: an explicit owner is a different reference.
        let mut value = binding();
        value["toolkits"] = json!([
            {"id": TOOLKIT, "version": 1},
            {"id": TOOLKIT, "version": 1, "tenant_id": TENANT}
        ]);
        assert!(parse::<BindingSpec>(value).is_ok());

        // The same tool pinned under two owners is two references.
        let mut value = binding();
        value["tool_subset"] = json!([
            {"id": TOOL, "version": 1, "tenant_id": TENANT},
            {"id": TOOL, "version": 1, "tenant_id": OTHER_AUTHORITY}
        ]);
        assert!(parse::<BindingSpec>(value).is_ok());
    }

    #[test]
    fn owned_toolkits_fills_the_binding_tenant_and_revalidates() {
        let tenant = AuthorityId::new(TENANT).expect("a valid authority");
        let spec: BindingSpec = parse(binding()).expect("a valid binding");
        let owned = owned_toolkits(spec, &tenant).expect("no duplicates appear");
        assert_eq!(owned.toolkits[0].tenant_id.as_ref(), Some(&tenant));

        let mut value = binding();
        value["toolkits"] = json!([
            {"id": TOOLKIT, "version": 1},
            {"id": TOOLKIT, "version": 1, "tenant_id": TENANT}
        ]);
        let spec: BindingSpec = parse(value).expect("distinct while the owner is omitted");
        assert_eq!(
            owned_toolkits(spec, &tenant).unwrap_err(),
            CatalogError("duplicate exact reference")
        );
    }

    #[test]
    fn credential_profiles_refuse_duplicate_services() {
        let profile = |services: serde_json::Value| {
            json!({
                "schema_version": 1,
                "profile_id": PROFILE,
                "tenant_id": TENANT,
                "name": "synthetic_profile",
                "gateway": {
                    "service": "gateway",
                    "alias": "gateway",
                    "license_id": TENANT,
                    "app_key": "care-bus"
                },
                "services": services
            })
        };
        let refused = profile(json!([
            {"service": "cases", "alias": "cases", "license_id": TENANT, "app_key": "care-bus"},
            {"service": "cases", "alias": "other", "license_id": TENANT, "app_key": "care-bus"}
        ]));
        assert!(
            parse::<CredentialProfile>(refused)
                .unwrap_err()
                .to_string()
                .contains("duplicate service credential reference")
        );
        let accepted = profile(json!([
            {"service": "cases", "alias": "cases", "license_id": TENANT, "app_key": "care-bus"},
            {"service": "billing", "alias": "billing", "license_id": TENANT, "app_key": "care-bus"}
        ]));
        assert!(parse::<CredentialProfile>(accepted).is_ok());
    }

    #[test]
    fn public_values_drops_null_fields() {
        let context: BoundContext = parse(json!({
            "tenant_id": TENANT,
            "project_id": PROJECT,
        }))
        .expect("a valid bound context");
        assert_eq!(
            context.public_values(),
            json!({"tenant_id": TENANT, "project_id": PROJECT})
        );
    }
}
