//! The exact-selection resolver: one live reading of a toolkit version, no executable package
//! is imported or loaded.
//!
//! Ported function-for-function from the reference `src/toolkits/resolver.py` (`reference_key`
//! is inlined at its call sites).

use std::collections::{BTreeMap, HashSet};

use serde_json::Value;
use sqlx::{PgConnection, Row};
use thiserror::Error;

use crate::catalog::ids::{AuthorityId, Name, PositiveVersion, Uuid7};
use crate::catalog::instance::{InstanceError, validate_instance};
use crate::catalog::lifecycle::VersionStatus;
use crate::catalog::models::{
    ArgumentValue, Constraint, Effect, ExactReference, OperationConstraints, OperationManifest,
    SourceKind, ToolLimits, ToolManifest,
};
use crate::catalog::public::validate_public_input;
use crate::catalog::toolkit_models::{
    BindingSpec, BoundContext, EffectiveTool, ToolReference, ToolSelection, ToolkitManifest,
};
use crate::catalog::validation::SchemaLimits;
use crate::storage::catalog::CatalogStoreError;
use crate::storage::toolkits as toolkit_store;
use crate::toolkits::constraints::{check_rules, pointer};

/// A refused selection, in the reference's three request-error shapes plus the storage failure
/// that is neither.
#[derive(Debug, Error)]
pub enum ResolveError {
    /// The reference's `CatalogNotFoundError`.
    #[error("{0}")]
    NotFound(&'static str),
    /// The reference's `CatalogConflictError`.
    #[error("{0}")]
    Conflict(&'static str),
    /// The reference's `ValueError` for a request-level violation.
    #[error("{0}")]
    Invalid(&'static str),
    /// A corrupt row or a failed statement; never a request error.
    #[error(transparent)]
    Storage(CatalogStoreError),
}

impl From<CatalogStoreError> for ResolveError {
    fn from(error: CatalogStoreError) -> Self {
        match error {
            CatalogStoreError::NotFound(message) => Self::NotFound(message),
            CatalogStoreError::Conflict(message) => Self::Conflict(message),
            other => Self::Storage(other),
        }
    }
}

impl From<sqlx::Error> for ResolveError {
    fn from(error: sqlx::Error) -> Self {
        Self::Storage(CatalogStoreError::Database(error))
    }
}

/// The narrower of two limits, field by field.
pub fn narrow_limits(a: ToolLimits, b: ToolLimits) -> ToolLimits {
    ToolLimits {
        wall_seconds: a.wall_seconds.min(b.wall_seconds),
        queue_seconds: a.queue_seconds.min(b.queue_seconds),
        memory_mi: a.memory_mi.min(b.memory_mi),
        cpu_millicores: a.cpu_millicores.min(b.cpu_millicores),
        api_calls: a.api_calls.min(b.api_calls),
        frame_bytes: a.frame_bytes.min(b.frame_bytes),
        output_bytes: a.output_bytes.min(b.output_bytes),
    }
}

/// Every rule must target an operation the tool declares.
pub fn constrain(
    manifest: &ToolManifest,
    rules: &[OperationConstraints],
) -> Result<(), ResolveError> {
    let allowed: HashSet<(&str, u32)> = manifest
        .allowed_operations
        .iter()
        .map(|reference| (reference.id.as_str(), reference.version.get()))
        .collect();
    if rules
        .iter()
        .any(|rule| !allowed.contains(&(rule.operation.id.as_str(), rule.operation.version.get())))
    {
        return Err(ResolveError::Invalid(
            "constraint targets an undeclared operation",
        ));
    }
    Ok(())
}

/// Merge an effective selection by public name and return it sorted by public name.
///
/// Restrictions are conjunctions, including repeated inclusions: rules concatenate and limits
/// narrow. Two different tools under one public name are a collision.
pub fn combine(tools: Vec<EffectiveTool>) -> Result<Vec<EffectiveTool>, ResolveError> {
    let mut result: BTreeMap<Name, EffectiveTool> = BTreeMap::new();
    for item in tools {
        let merged = match result.get(&item.public_name) {
            Some(prior) => {
                if prior.tool != item.tool {
                    return Err(ResolveError::Conflict(
                        "public name collision in effective selection",
                    ));
                }
                EffectiveTool {
                    tool: item.tool.clone(),
                    public_name: item.public_name.clone(),
                    operation_constraints: prior
                        .operation_constraints
                        .iter()
                        .chain(item.operation_constraints.iter())
                        .cloned()
                        .collect(),
                    limits: narrow_limits(prior.limits, item.limits),
                }
            }
            None => item,
        };
        result.insert(merged.public_name.clone(), merged);
    }
    if result.len() > 128 {
        return Err(ResolveError::Invalid(
            "effective selection exceeds 128 tools",
        ));
    }
    Ok(result.into_values().collect())
}

/// One live exact-selection resolver.
#[derive(Debug, Clone)]
pub struct SelectionResolver {
    /// The reserved platform tenant, owner of platform toolkits' tools.
    pub platform_tenant_id: AuthorityId,
}

impl SelectionResolver {
    /// Every ownership read a selection names must be an approved, nonrecursive read.
    pub async fn ownership_reads(
        &self,
        conn: &mut PgConnection,
        entries: &[OperationConstraints],
    ) -> Result<(), ResolveError> {
        for entry in entries {
            for rule in &entry.rules {
                let Constraint::OwnershipRead(read) = rule else {
                    continue;
                };
                let row = sqlx::query(
                    "SELECT o.manifest, o.status, s.status AS service_status \
                     FROM public.mcp_operation_versions o \
                     JOIN public.mcp_service_versions s \
                       ON (s.service_id, s.version) = (o.service_id, o.service_version) \
                     WHERE o.operation_id = $1::uuid AND o.version = $2",
                )
                .bind(read.operation.id.as_str())
                .bind(version_bits(read.operation.version))
                .fetch_optional(&mut *conn)
                .await?;
                let Some(row) = row else {
                    return Err(ResolveError::Invalid("ownership read is not approved"));
                };
                let status: String = row.try_get("status")?;
                let service_status: String = row.try_get("service_status")?;
                if status != "published" || service_status != "published" {
                    return Err(ResolveError::Invalid("ownership read is not approved"));
                }
                let manifest: Value = row.try_get("manifest")?;
                let operation: OperationManifest = serde_json::from_value(manifest)
                    .map_err(|_| CatalogStoreError::Corrupt("operation manifest"))?;
                if operation.effect != Effect::ReadOnly
                    || operation
                        .scope_rules
                        .iter()
                        .any(|rule| matches!(rule, Constraint::OwnershipRead(_)))
                {
                    return Err(ResolveError::Invalid(
                        "ownership reads require nonrecursive read operations",
                    ));
                }
            }
        }
        Ok(())
    }

    /// A selectable tool: the tenant's own, or shared with it.
    ///
    /// `bound` is for tools of an already resolved binding selection only: a platform-owned
    /// tool reached through a pinned platform toolkit is then read as the platform tenant, its
    /// owner.
    pub async fn tool(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        reference: &ToolReference,
        lock: bool,
        bound: bool,
    ) -> Result<ToolManifest, ResolveError> {
        let reader = if bound && reference.tenant_id == self.platform_tenant_id {
            reference.tenant_id.clone()
        } else {
            tenant.clone()
        };
        let row = sqlx::query(
            "SELECT v.manifest, v.status, t.retired \
             FROM public.mcp_tool_versions v \
             JOIN public.mcp_tools t USING (tenant_id, tool_id) \
             WHERE v.tenant_id = $1::uuid AND v.tool_id = $2::uuid AND v.version = $3 AND \
             (v.tenant_id = $4::uuid OR EXISTS (SELECT 1 FROM public.mcp_tool_shares s \
               WHERE s.owner_tenant_id = v.tenant_id AND s.tool_id = v.tool_id \
                 AND s.grantee_tenant_id = $4::uuid))",
        )
        .bind(reference.tenant_id.as_str())
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .bind(reader.as_str())
        .fetch_optional(&mut *conn)
        .await?
        .ok_or(ResolveError::NotFound("selected tool not found"))?;
        let status: String = row.try_get("status")?;
        let retired: bool = row.try_get("retired")?;
        if status != "published" || retired {
            return Err(ResolveError::Conflict("selected tool is unavailable"));
        }
        if lock {
            toolkit_store::lock_access_tool(&mut *conn, &reader, reference).await?;
        }
        let operations = sqlx::query(
            "SELECT o.status AS op, s.status AS service \
             FROM public.mcp_tool_version_operations r \
             JOIN public.mcp_operation_versions o \
               ON (o.operation_id, o.version) = (r.operation_id, r.operation_version) \
             JOIN public.mcp_service_versions s \
               ON (s.service_id, s.version) = (o.service_id, o.service_version) \
             WHERE r.tenant_id = $1::uuid AND r.tool_id = $2::uuid AND r.version = $3",
        )
        .bind(reference.tenant_id.as_str())
        .bind(reference.id.as_str())
        .bind(version_bits(reference.version))
        .fetch_all(&mut *conn)
        .await?;
        for operation in operations {
            let op: String = operation.try_get("op")?;
            let service: String = operation.try_get("service")?;
            if op != "published" || service != "published" {
                return Err(ResolveError::Conflict("selected operation is unavailable"));
            }
        }
        let manifest: Value = row.try_get("manifest")?;
        serde_json::from_value(manifest)
            .map_err(|_| CatalogStoreError::Corrupt("tool manifest").into())
    }

    /// [`Self::tool`] for many references in two statements instead of two per tool.
    pub async fn tools_bulk(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        references: &[ToolReference],
        lock: bool,
        bound: bool,
    ) -> Result<std::collections::HashMap<(String, u32), ToolManifest>, ResolveError> {
        if references.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let loaded = toolkit_store::selectable_tools(
            &mut *conn,
            tenant,
            references,
            bound,
            &self.platform_tenant_id,
        )
        .await?;
        if lock {
            // Advisory locks stay per reference and in reference order: the write path pays
            // one round trip per tool for exactly the lock semantics `tool` has.
            for reference in references {
                let reader = if bound && reference.tenant_id == self.platform_tenant_id {
                    &reference.tenant_id
                } else {
                    tenant
                };
                toolkit_store::lock_access_tool(&mut *conn, reader, reference).await?;
            }
        }
        Ok(loaded)
    }

    /// One toolkit entry as an effective tool, with the tool manifest already loaded when the
    /// caller has it.
    pub async fn selection(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        entry: &ToolSelection,
        lock: bool,
        manifest: Option<&ToolManifest>,
    ) -> Result<EffectiveTool, ResolveError> {
        let fetched = match manifest {
            Some(_) => None,
            None => Some(
                self.tool(&mut *conn, tenant, &entry.tool, lock, false)
                    .await?,
            ),
        };
        let manifest = match manifest {
            Some(manifest) => manifest,
            None => fetched
                .as_ref()
                .expect("the manifest is loaded when none was supplied"),
        };
        constrain(manifest, &entry.operation_constraints)?;
        self.ownership_reads(&mut *conn, &entry.operation_constraints)
            .await?;
        Ok(EffectiveTool {
            tool: entry.tool.clone(),
            public_name: manifest.public_name.clone(),
            operation_constraints: manifest
                .operation_constraints
                .iter()
                .chain(entry.operation_constraints.iter())
                .cloned()
                .collect(),
            limits: narrow_limits(manifest.limits, entry.limits),
        })
    }

    /// One toolkit version's stored effective tools, after rechecking every inclusion live so
    /// disabling an ancestor reaches all bindings.
    #[allow(clippy::too_many_arguments)]
    pub async fn toolkit(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        identity: &Uuid7,
        version: PositiveVersion,
        seen: &HashSet<(Uuid7, u32)>,
        lock: bool,
        context: Option<&BoundContext>,
        budget: &mut u32,
    ) -> Result<Vec<EffectiveTool>, ResolveError> {
        let key = (identity.clone(), version.get());
        *budget += 1;
        if seen.contains(&key) || seen.len() >= 16 || *budget > 256 {
            return Err(ResolveError::Invalid("toolkit cycle or depth limit"));
        }
        if lock {
            toolkit_store::lock_toolkit_version(&mut *conn, tenant, identity, version).await?;
        }
        let descriptor = toolkit_store::get_toolkit(&mut *conn, tenant, identity, version).await?;
        if descriptor.status != VersionStatus::Published {
            return Err(ResolveError::Conflict("toolkit is unavailable"));
        }
        if let Some(context) = context {
            // Capability describes content; every other applicability field restricts
            // selection.
            let applicability = &descriptor.manifest.applicability;
            let satisfies = |required: &Option<Name>, actual: &Option<Name>| {
                required.is_none() || required == actual
            };
            if !satisfies(&applicability.project_phase, &context.project_phase)
                || !satisfies(&applicability.work_type, &context.work_type)
                || !satisfies(&applicability.card_stage, &context.card_stage)
                || !satisfies(&applicability.responsibility, &context.responsibility)
            {
                return Err(ResolveError::Invalid(
                    "binding context does not satisfy toolkit applicability",
                ));
            }
        }
        let mut descended = seen.clone();
        descended.insert(key);
        for reference in &descriptor.manifest.includes {
            Box::pin(self.toolkit(
                &mut *conn,
                tenant,
                &reference.id,
                reference.version,
                &descended,
                lock,
                context,
                budget,
            ))
            .await?;
        }
        let references: Vec<ToolReference> = descriptor
            .tools
            .iter()
            .map(|entry| entry.tool.clone())
            .collect();
        self.tools_bulk(&mut *conn, tenant, &references, lock, false)
            .await?;
        Ok(descriptor.tools)
    }

    /// A toolkit manifest's whole effective selection: its own tools plus every included
    /// toolkit's, merged and sorted by public name.
    pub async fn flatten(
        &self,
        conn: &mut PgConnection,
        manifest: &ToolkitManifest,
    ) -> Result<Vec<EffectiveTool>, ResolveError> {
        let references: Vec<ToolReference> = manifest
            .tools
            .iter()
            .map(|entry| entry.tool.clone())
            .collect();
        let loaded = self
            .tools_bulk(&mut *conn, &manifest.tenant_id, &references, true, false)
            .await?;
        let mut tools = Vec::with_capacity(manifest.tools.len());
        for entry in &manifest.tools {
            let loaded_manifest = loaded
                .get(&(entry.tool.id.as_str().to_owned(), entry.tool.version.get()))
                .filter(|tool| tool.tenant_id == entry.tool.tenant_id)
                .ok_or(ResolveError::NotFound("selected tool not found"))?;
            tools.push(
                self.selection(
                    &mut *conn,
                    &manifest.tenant_id,
                    entry,
                    true,
                    Some(loaded_manifest),
                )
                .await?,
            );
        }
        let mut budget = 0;
        let seen = HashSet::new();
        for reference in &manifest.includes {
            let nested = self
                .toolkit(
                    &mut *conn,
                    &manifest.tenant_id,
                    &reference.id,
                    reference.version,
                    &seen,
                    true,
                    None,
                    &mut budget,
                )
                .await?;
            tools.extend(nested);
        }
        combine(tools)
    }

    /// A binding spec resolved live: every pinned toolkit flattened, the exact subset kept, and
    /// each selected tool checked against the bound context and its allowed operations.
    ///
    /// A pin may name the binding's tenant or the reserved platform tenant, nothing else. One
    /// cycle budget is shared across every pin. The context is projected onto each tool's
    /// declared context schema before validation; `tenant_id` stays host authority either way.
    pub async fn binding(
        &self,
        conn: &mut PgConnection,
        tenant: &AuthorityId,
        spec: &BindingSpec,
        lock: bool,
    ) -> Result<Vec<EffectiveTool>, ResolveError> {
        if spec.context.tenant_id != *tenant {
            return Err(ResolveError::Invalid(
                "bound tenant differs from authenticated tenant",
            ));
        }
        self.ownership_reads(&mut *conn, &spec.operation_constraints)
            .await?;
        let mut tools: Vec<EffectiveTool> = Vec::new();
        let seen: HashSet<(Uuid7, u32)> = HashSet::new();
        let mut budget = 0u32;
        for reference in &spec.toolkits {
            // A binding reads its own tenant's toolkits and the platform's, nothing else.
            let owner = reference
                .tenant_id
                .clone()
                .unwrap_or_else(|| tenant.clone());
            if owner != *tenant && owner != self.platform_tenant_id {
                return Err(ResolveError::NotFound("toolkit version not found"));
            }
            tools.extend(
                self.toolkit(
                    &mut *conn,
                    &owner,
                    &reference.id,
                    reference.version,
                    &seen,
                    lock,
                    Some(&spec.context),
                    &mut budget,
                )
                .await?,
            );
        }
        let mut flattened = combine(tools)?;
        if let Some(subset) = &spec.tool_subset {
            if subset.iter().any(|wanted| {
                !flattened
                    .iter()
                    .any(|entry| same_reference(&entry.tool, wanted))
            }) {
                return Err(ResolveError::Invalid(
                    "subset contains tools outside toolkit membership",
                ));
            }
            flattened.retain(|entry| {
                subset
                    .iter()
                    .any(|wanted| same_reference(&entry.tool, wanted))
            });
        }
        let context = spec.context.public_values();
        let context_values = context
            .as_object()
            .expect("a bound context's public values are an object");
        let references: Vec<ToolReference> =
            flattened.iter().map(|entry| entry.tool.clone()).collect();
        let loaded = self
            .tools_bulk(&mut *conn, tenant, &references, lock, true)
            .await?;
        let mut wanted: Vec<ExactReference> = Vec::new();
        let mut wanted_keys: HashSet<(String, u32)> = HashSet::new();
        for entry in &flattened {
            let manifest = loaded
                .get(&(entry.tool.id.as_str().to_owned(), entry.tool.version.get()))
                .filter(|manifest| manifest.tenant_id == entry.tool.tenant_id)
                .ok_or(ResolveError::NotFound("selected tool not found"))?;
            for operation in &manifest.allowed_operations {
                if wanted_keys.insert((operation.id.as_str().to_owned(), operation.version.get())) {
                    wanted.push(operation.clone());
                }
            }
        }
        // One read for every operation behind the selection, not one read per operation.
        let operation_manifests = toolkit_store::operation_manifests(&mut *conn, &wanted).await?;
        let mut permitted: HashSet<(String, u32)> = HashSet::new();
        let mut operations: HashSet<&str> = HashSet::new();
        let mut resolved: Vec<EffectiveTool> = Vec::with_capacity(flattened.len());
        for entry in flattened {
            let manifest = loaded
                .get(&(entry.tool.id.as_str().to_owned(), entry.tool.version.get()))
                .filter(|manifest| manifest.tenant_id == entry.tool.tenant_id)
                .ok_or(ResolveError::NotFound("selected tool not found"))?;
            // The agent runner maps canonical operations to tools one to one.
            if !operations.insert(manifest.operation.as_str()) {
                return Err(ResolveError::Conflict(
                    "operation collision in effective selection",
                ));
            }
            validate_public_input(&Value::Object(manifest.input_schema.clone()))
                .map_err(|error| ResolveError::Invalid(error.0))?;
            // Tool context may accept only its declared projection; tenant remains host authority.
            let projected = match manifest.context_schema.get("properties") {
                Some(Value::Object(properties)) => Value::Object(
                    context_values
                        .iter()
                        .filter(|(key, _)| properties.contains_key(*key))
                        .map(|(key, value)| (key.clone(), value.clone()))
                        .collect(),
                ),
                Some(_) => {
                    return Err(ResolveError::Invalid(
                        "context schema must declare properties",
                    ));
                }
                None => Value::Object(serde_json::Map::new()),
            };
            match validate_instance(
                &Value::Object(manifest.context_schema.clone()),
                &projected,
                &SchemaLimits::default(),
            ) {
                Ok(_) => {}
                Err(InstanceError::Invalid(_)) => {
                    return Err(ResolveError::Invalid(
                        "instance does not match declared schema",
                    ));
                }
                Err(InstanceError::Work(_)) => {
                    return Err(ResolveError::Invalid("validation work limit exceeded"));
                }
                Err(InstanceError::Bounds(error)) => {
                    return Err(ResolveError::Invalid(error.0));
                }
            }
            let allowed: HashSet<(&str, u32)> = manifest
                .allowed_operations
                .iter()
                .map(|reference| (reference.id.as_str(), reference.version.get()))
                .collect();
            for reference in &manifest.allowed_operations {
                permitted.insert((reference.id.as_str().to_owned(), reference.version.get()));
            }
            let extra: Vec<&OperationConstraints> = spec
                .operation_constraints
                .iter()
                .filter(|entry| {
                    allowed.contains(&(entry.operation.id.as_str(), entry.operation.version.get()))
                })
                .collect();
            for operation_reference in &manifest.allowed_operations {
                let operation = operation_manifests
                    .get(&(
                        operation_reference.id.as_str().to_owned(),
                        operation_reference.version.get(),
                    ))
                    .ok_or(ResolveError::Storage(CatalogStoreError::Corrupt(
                        "operation manifest missing",
                    )))?;
                for mapping in &operation.mappings {
                    if let ArgumentValue::Source(source) = &mapping.value
                        && source.source == SourceKind::Context
                    {
                        pointer(&context, source.pointer.as_str())
                            .map_err(|error| ResolveError::Invalid(error.0))?;
                    }
                }
                let mut rules: Vec<Constraint> = operation.scope_rules.clone();
                for entry_rules in entry
                    .operation_constraints
                    .iter()
                    .chain(extra.iter().copied())
                {
                    if &entry_rules.operation == operation_reference {
                        rules.extend(entry_rules.rules.iter().cloned());
                    }
                }
                check_rules(&rules, &context).map_err(|error| ResolveError::Invalid(error.0))?;
            }
            let mut operation_constraints = entry.operation_constraints;
            operation_constraints.extend(extra.into_iter().cloned());
            resolved.push(EffectiveTool {
                tool: entry.tool,
                public_name: entry.public_name,
                operation_constraints,
                limits: narrow_limits(entry.limits, spec.limits),
            });
        }
        if spec.operation_constraints.iter().any(|entry| {
            !permitted.contains(&(
                entry.operation.id.as_str().to_owned(),
                entry.operation.version.get(),
            ))
        }) {
            return Err(ResolveError::Invalid(
                "binding constraint targets an unselected operation",
            ));
        }
        Ok(resolved)
    }
}

/// `reference_key` from the reference: a tool reference is its owner, identity and version.
fn same_reference(left: &ToolReference, right: &ToolReference) -> bool {
    left.tenant_id == right.tenant_id && left.id == right.id && left.version == right.version
}

fn version_bits(version: PositiveVersion) -> i32 {
    i32::try_from(version.get()).expect("a positive version fits the integer range")
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::catalog::models::ExactReference;

    fn authority(value: &str) -> AuthorityId {
        AuthorityId::new(value).expect("valid authority")
    }

    fn identity(value: &str) -> Uuid7 {
        Uuid7::new(value).expect("valid identity")
    }

    fn name(value: &str) -> Name {
        Name::new(value).expect("valid name")
    }

    fn version() -> PositiveVersion {
        PositiveVersion::new(1).expect("valid version")
    }

    fn operation(identity_value: &str) -> OperationConstraints {
        OperationConstraints {
            operation: ExactReference {
                id: identity(identity_value),
                version: version(),
            },
            rules: Vec::new(),
        }
    }

    fn effective(
        public_name: &str,
        tool_id: &str,
        limits: ToolLimits,
        operation_id: &str,
    ) -> EffectiveTool {
        EffectiveTool {
            tool: ToolReference {
                id: identity(tool_id),
                version: version(),
                tenant_id: authority("10000000-0000-7000-8000-000000000001"),
            },
            operation_constraints: vec![operation(operation_id)],
            limits,
            public_name: name(public_name),
        }
    }

    fn tool_manifest() -> ToolManifest {
        serde_json::from_value(json!({
            "tool_id": "20000000-0000-7000-8000-000000000002",
            "tenant_id": "10000000-0000-7000-8000-000000000001",
            "version": 1,
            "public_name": "synthetic_tool",
            "operation": "projects.get",
            "description": "Synthetic tool",
            "runtime": "kata_python",
            "entrypoint": "main.run",
            "input_schema": {},
            "result_schema": {},
            "context_schema": {},
            "package_sha256": "a".repeat(64),
            "runner_image_digest": format!("registry.example/runner@sha256:{}", "a".repeat(64)),
            "effect": "read_only"
        }))
        .expect("valid tool manifest")
    }

    #[test]
    fn narrow_limits_takes_the_minimum_of_every_field() {
        let wide = ToolLimits {
            wall_seconds: 120,
            queue_seconds: 90,
            memory_mi: 512,
            cpu_millicores: 500,
            api_calls: 40,
            frame_bytes: 65_536,
            output_bytes: 262_144,
        };
        let narrow = ToolLimits {
            wall_seconds: 30,
            queue_seconds: 600,
            memory_mi: 128,
            cpu_millicores: 900,
            api_calls: 0,
            frame_bytes: 1_024,
            output_bytes: 900_000,
        };
        assert_eq!(
            narrow_limits(wide, narrow),
            ToolLimits {
                wall_seconds: 30,
                queue_seconds: 90,
                memory_mi: 128,
                cpu_millicores: 500,
                api_calls: 0,
                frame_bytes: 1_024,
                output_bytes: 262_144,
            }
        );
    }

    #[test]
    fn combine_merges_by_public_name_and_sorts() {
        let wide = ToolLimits {
            wall_seconds: 120,
            ..ToolLimits::default()
        };
        let narrow = ToolLimits {
            wall_seconds: 30,
            ..ToolLimits::default()
        };
        let combined = combine(vec![
            effective(
                "beta",
                "20000000-0000-7000-8000-000000000010",
                wide,
                "20000000-0000-7000-8000-000000000020",
            ),
            effective(
                "alpha",
                "20000000-0000-7000-8000-000000000011",
                wide,
                "20000000-0000-7000-8000-000000000021",
            ),
            effective(
                "beta",
                "20000000-0000-7000-8000-000000000010",
                narrow,
                "20000000-0000-7000-8000-000000000022",
            ),
        ])
        .expect("no collision");
        let names: Vec<&str> = combined
            .iter()
            .map(|tool| tool.public_name.as_str())
            .collect();
        assert_eq!(names, ["alpha", "beta"]);
        assert_eq!(combined[0].operation_constraints.len(), 1);
        assert_eq!(combined[1].operation_constraints.len(), 2);
        assert_eq!(combined[1].limits.wall_seconds, 30);
        assert_eq!(
            combined[1].operation_constraints[0].operation.id.as_str(),
            "20000000-0000-7000-8000-000000000020"
        );
        assert_eq!(
            combined[1].operation_constraints[1].operation.id.as_str(),
            "20000000-0000-7000-8000-000000000022"
        );
    }

    #[test]
    fn combine_refuses_a_public_name_collision() {
        let combined = combine(vec![
            effective(
                "same_name",
                "20000000-0000-7000-8000-000000000010",
                ToolLimits::default(),
                "20000000-0000-7000-8000-000000000020",
            ),
            effective(
                "same_name",
                "20000000-0000-7000-8000-000000000011",
                ToolLimits::default(),
                "20000000-0000-7000-8000-000000000021",
            ),
        ]);
        assert!(matches!(
            combined,
            Err(ResolveError::Conflict(
                "public name collision in effective selection"
            ))
        ));
    }

    #[test]
    fn combine_refuses_more_than_128_tools() {
        let tools = (0..129)
            .map(|index| {
                effective(
                    &format!("tool_{index}"),
                    "20000000-0000-7000-8000-000000000010",
                    ToolLimits::default(),
                    "20000000-0000-7000-8000-000000000020",
                )
            })
            .collect();
        assert!(matches!(
            combine(tools),
            Err(ResolveError::Invalid(
                "effective selection exceeds 128 tools"
            ))
        ));
    }

    #[test]
    fn constrain_refuses_an_undeclared_operation() {
        let manifest = tool_manifest();
        assert!(
            constrain(&manifest, &[]).is_ok(),
            "an empty rule set targets nothing"
        );
        let undeclared = [operation("20000000-0000-7000-8000-000000000003")];
        assert!(matches!(
            constrain(&manifest, &undeclared),
            Err(ResolveError::Invalid(
                "constraint targets an undeclared operation"
            ))
        ));
    }
}
