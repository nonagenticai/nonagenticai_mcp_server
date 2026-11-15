//! Least privilege per builtin caller, and the builtin wire names.
//!
//! Ported from the reference `src/builtin/scope.py` with the same tables and fail-closed rules:
//!
//! * Keycloak service accounts are scoped by their `azp`: `carebus-tool-executor` gets the
//!   care-bus contract, `carebus-researcher` gets the legal, web and research tools.
//! * A licence caller's scope comes from the introspected licence's application key, prefixed
//!   with [`LICENCE_SCOPE_PREFIX`] so no `azp` can name one: `care-bus` gets the care-bus and
//!   researcher tools, `mcp` gets the builder tools. Only a TENANT-LEVEL licence
//!   ([`SubjectKind::Tenant`]) of a scoped application gets a scope at all; a member's
//!   per-login licence gets nothing.
//! * Any other `azp`, any unscoped licence, and the empty scope key grant NOTHING: an empty
//!   listing, and every call denied with [`DENIED_MESSAGE`].
//!
//! Binding principals never reach this table: they see catalog tools only. In this service the
//! caller identity is derived from the authenticated [`Principal`] that carries no binding
//! ([`BuiltinCaller::from_principal`]); the reference builds the same value at authentication.
//! A licence caller's forwarded `X-Strata-Token` rides on [`BuiltinCaller::strata_token`] and is
//! read by `faq_ask` alone; the [`Debug`] impl redacts it.
//!
//! Each tool belongs to one family namespace (the reference's `(server, namespace)` group),
//! and its wire name is `{namespace}_{function}` ([`wire_name`]); the tables below map a
//! caller's scope key to the namespaces it may use, so the allowed set is always derived from
//! the registered tools and never from a hand-written name list.

use crate::auth::{Principal, SubjectKind};

/// The reference's one scope refusal; its `[permanent]` prefix is read by the calling agent.
pub const DENIED_MESSAGE: &str = "[permanent] tool not permitted for this caller";

/// A Keycloak service account that executes the care-bus contract.
pub const CAREBUS_TOOL_EXECUTOR: &str = "carebus-tool-executor";
/// A Keycloak service account that reads legal, web and research sources.
pub const CAREBUS_RESEARCHER: &str = "carebus-researcher";

/// The licence application whose tenant-level callers get the care-bus tools.
pub const CAREBUS_LICENCE_APP: &str = "care-bus";
/// The licence application whose tenant-level callers author tools with the builder toolkit.
pub const MCP_LICENCE_APP: &str = "mcp";
/// Prefixed so no `azp` can name a licence scope.
pub const LICENCE_SCOPE_PREFIX: &str = "licence:";
/// The builder's scope key (`LICENCE_SCOPE_PREFIX + MCP_LICENCE_APP`).
pub const MCP_LICENCE_SCOPE: &str = "licence:mcp";

/// The six care-bus family namespaces (13 tools).
pub const CAREBUS_NAMESPACES: &[&str] = &["crm", "order", "delivery", "rules", "procedures", "faq"];
/// The researcher family namespaces.
pub const RESEARCHER_NAMESPACES: &[&str] = &["legal", "web", "research"];
/// The tool builder's namespace.
pub const BUILDER_NAMESPACES: &[&str] = &["builder"];

/// The care-bus licence's set: the care-bus contract plus the researcher set.
pub const CAREBUS_LICENCE_NAMESPACES: &[&str] = &[
    "crm",
    "order",
    "delivery",
    "rules",
    "procedures",
    "faq",
    "legal",
    "web",
    "research",
];

/// `PRINCIPAL_SCOPES`: Keycloak `azp` -> the namespaces that principal may use.
pub const PRINCIPAL_SCOPES: &[(&str, &[&str])] = &[
    (CAREBUS_TOOL_EXECUTOR, CAREBUS_NAMESPACES),
    (CAREBUS_RESEARCHER, RESEARCHER_NAMESPACES),
];

/// `LICENCE_SCOPES`: licence `app.key` -> the namespaces its callers may use.
pub const LICENCE_SCOPES: &[(&str, &[&str])] = &[
    (CAREBUS_LICENCE_APP, CAREBUS_LICENCE_NAMESPACES),
    (MCP_LICENCE_APP, BUILDER_NAMESPACES),
];

/// The namespaces one scope key grants, by the reference's `SCOPES` lookup. An unknown or
/// empty scope grants nothing.
pub fn namespaces(scope: &str) -> &'static [&'static str] {
    let entry = match scope.strip_prefix(LICENCE_SCOPE_PREFIX) {
        Some(app) => LICENCE_SCOPES
            .iter()
            .find(|(key, _)| *key == app)
            .map(|(_, namespaces)| *namespaces),
        None => PRINCIPAL_SCOPES
            .iter()
            .find(|(key, _)| *key == scope)
            .map(|(_, namespaces)| *namespaces),
    };
    entry.unwrap_or(&[])
}

/// The scope key of a licence caller: only a tenant-level licence of a scoped application
/// gets one; a member's licence, an unscoped application or a missing payload field gets the
/// empty scope, which grants nothing.
pub fn licence_scope(app: Option<&str>, subject_kind: Option<SubjectKind>) -> String {
    let Some(app) = app else {
        return String::new();
    };
    let scoped = LICENCE_SCOPES.iter().any(|(key, _)| *key == app);
    if scoped && subject_kind == Some(SubjectKind::Tenant) {
        format!("{LICENCE_SCOPE_PREFIX}{app}")
    } else {
        String::new()
    }
}

/// The wire name of one builtin tool: `{namespace}_{function}`.
pub fn wire_name(namespace: &str, function: &str) -> String {
    format!("{namespace}_{function}")
}

/// The `principal_kind` an audit row carries; the three values the
/// `mcp_tool_call_audit_principal_kind_check` constraint admits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CallerKind {
    /// A licence caller without a binding.
    CarebusLicence,
    /// A Keycloak service account.
    KeycloakService,
    /// A tenant authoring its own tools with the builder toolkit.
    TenantAuthor,
}

impl CallerKind {
    /// The `principal_kind` column value.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CarebusLicence => "carebus_licence",
            Self::KeycloakService => "keycloak_service",
            Self::TenantAuthor => "tenant_author",
        }
    }

    /// The `auth_method` column value: a licence is `license`, a Keycloak token `keycloak`.
    pub fn auth_method(self) -> &'static str {
        match self {
            Self::CarebusLicence | Self::TenantAuthor => "license",
            Self::KeycloakService => "keycloak",
        }
    }
}

/// A caller of the builtin provider: the reference's `CallerPrincipal`, plus the one forwarded
/// credential the reference keeps beside it (`CallerAuthority.strata_token`).
#[derive(Clone, PartialEq, Eq)]
pub struct BuiltinCaller {
    /// Which credential kind authenticated the caller.
    pub kind: CallerKind,
    /// The licence `subject_id` or the JWT `azp`.
    pub subject: String,
    /// The key into [`PRINCIPAL_SCOPES`] / [`LICENCE_SCOPES`]; `""` grants nothing.
    pub scope: String,
    /// The licence's tenant, when the credential carries one.
    pub tenant_id: Option<String>,
    /// The authenticating licence's id (tenant authors only).
    pub license_id: Option<String>,
    /// The request's forwarded strata-rag licence (`X-Strata-Token`), handed only to `faq_ask`.
    /// Never rendered: the [`Debug`] impl below redacts it.
    pub strata_token: Option<String>,
}

/// Redacts [`BuiltinCaller::strata_token`], so a `?caller` log line cannot carry a credential.
/// Every other field is safe to print and printed exactly as derived `Debug` would.
impl std::fmt::Debug for BuiltinCaller {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BuiltinCaller")
            .field("kind", &self.kind)
            .field("subject", &self.subject)
            .field("scope", &self.scope)
            .field("tenant_id", &self.tenant_id)
            .field("license_id", &self.license_id)
            .field(
                "strata_token",
                &self.strata_token.as_ref().map(|_| "<redacted>"),
            )
            .finish()
    }
}

impl BuiltinCaller {
    /// The builtin caller behind an authenticated principal that carries no catalog binding.
    ///
    /// The reference establishes this value at authentication, from the introspected licence
    /// or the JWT `azp`. [`crate::mcp`]'s dispatch rule reads a principal with no binding, so
    /// the same value is derived from what the authentication layer preserved:
    ///
    /// * a principal carrying the introspected licence's `app` and `subject_kind` (the non-binding
    ///   licence path) takes [`licence_scope`] from **those facts** — a member's per-login licence
    ///   therefore gets no scope even when its subject has the `svc:` shape;
    /// * otherwise an `azp` that names a [`PRINCIPAL_SCOPES`] entry is a Keycloak service account
    ///   and is its own scope key;
    /// * any other principal is scoped from its subject; anything unrecognised gets nothing.
    pub fn from_principal(principal: &Principal) -> Self {
        let subject = principal.subject.clone();
        let (kind, scope) = match principal.licence.as_ref() {
            Some(facts) => {
                // The authority's own report, including a missing `subject_kind` — which the
                // reference gives no scope (`scope.py:95`). Never inferred from the subject.
                let scope = licence_scope(Some(facts.app.as_str()), facts.subject_kind);
                let kind = if facts.app == MCP_LICENCE_APP {
                    CallerKind::TenantAuthor
                } else {
                    CallerKind::CarebusLicence
                };
                (kind, scope)
            }
            None => classify(&subject),
        };
        Self {
            kind,
            subject,
            scope,
            tenant_id: Some(principal.tenant_id.to_string()),
            license_id: (kind == CallerKind::TenantAuthor)
                .then(|| principal.license_id.to_string()),
            strata_token: None,
        }
    }

    /// Attach the request's forwarded strata-rag licence (`X-Strata-Token`), read by the `/mcp`
    /// handler. The reference keeps the same value on its `CallerAuthority`.
    pub fn with_strata_token(mut self, strata_token: Option<String>) -> Self {
        self.strata_token = strata_token;
        self
    }
}

/// The credential class and scope key behind one subject. Fail closed: an unknown shape gets
/// the empty scope.
fn classify(subject: &str) -> (CallerKind, String) {
    if PRINCIPAL_SCOPES.iter().any(|(azp, _)| *azp == subject) {
        return (CallerKind::KeycloakService, subject.to_owned());
    }
    let app = subject
        .strip_prefix("svc:")
        .and_then(|rest| rest.rsplit_once(':'))
        .map(|(_, app)| app);
    if let Some(app) = app {
        let scope = licence_scope(Some(app), Some(SubjectKind::Tenant));
        let kind = if app == MCP_LICENCE_APP {
            CallerKind::TenantAuthor
        } else {
            CallerKind::CarebusLicence
        };
        return (kind, scope);
    }
    (CallerKind::KeycloakService, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_names_are_namespace_underscore_function() {
        assert_eq!(wire_name("crm", "verify_customer"), "crm_verify_customer");
    }

    #[test]
    fn scopes_grant_exactly_the_reference_namespaces() {
        assert_eq!(namespaces(CAREBUS_TOOL_EXECUTOR), CAREBUS_NAMESPACES);
        assert_eq!(namespaces(CAREBUS_RESEARCHER), RESEARCHER_NAMESPACES);
        assert_eq!(namespaces(MCP_LICENCE_SCOPE), BUILDER_NAMESPACES);
        assert_eq!(namespaces("licence:care-bus"), CAREBUS_LICENCE_NAMESPACES);
        for scope in ["", "unknown-client", "licence:unknown", "care-bus"] {
            assert!(namespaces(scope).is_empty(), "{scope}");
        }
    }

    #[test]
    fn only_a_tenant_level_licence_of_a_scoped_app_gets_a_scope() {
        assert_eq!(
            licence_scope(Some(CAREBUS_LICENCE_APP), Some(SubjectKind::Tenant)),
            "licence:care-bus"
        );
        assert_eq!(
            licence_scope(Some(MCP_LICENCE_APP), Some(SubjectKind::Tenant)),
            MCP_LICENCE_SCOPE
        );
        assert_eq!(
            licence_scope(Some(CAREBUS_LICENCE_APP), Some(SubjectKind::Member)),
            ""
        );
        assert_eq!(licence_scope(Some(CAREBUS_LICENCE_APP), None), "");
        assert_eq!(
            licence_scope(Some("unscoped"), Some(SubjectKind::Tenant)),
            ""
        );
        assert_eq!(licence_scope(None, Some(SubjectKind::Tenant)), "");
    }

    /// A principal carrying the authority's reported licence facts.
    fn facts_principal(app: &str, kind: SubjectKind, subject: &str) -> Principal {
        Principal {
            tenant_id: crate::auth::Rfc4122Uuid::parse("01900000-0000-7000-8000-0000000000aa")
                .expect("tenant identity"),
            license_id: crate::auth::Rfc4122Uuid::parse("01900000-0000-7000-8000-0000000000bb")
                .expect("licence identity"),
            subject: subject.to_owned(),
            binding_id: None,
            binding_revision: None,
            management: false,
            platform: false,
            licence: Some(crate::auth::LicenceFacts {
                app: app.to_owned(),
                subject_kind: Some(kind),
            }),
        }
    }

    #[test]
    fn the_caller_scope_comes_from_the_reported_facts_not_the_subject() {
        // The same `svc:` subject for both; only the authority's kind decides the scope.
        let tenant = facts_principal(CAREBUS_LICENCE_APP, SubjectKind::Tenant, "svc:t:care-bus");
        let caller = BuiltinCaller::from_principal(&tenant);
        assert_eq!(caller.scope, "licence:care-bus");
        assert_eq!(caller.kind, CallerKind::CarebusLicence);

        let member = facts_principal(CAREBUS_LICENCE_APP, SubjectKind::Member, "svc:t:care-bus");
        let caller = BuiltinCaller::from_principal(&member);
        assert_eq!(caller.scope, "", "a member licence gets no scope");
        assert_eq!(caller.kind, CallerKind::CarebusLicence);

        // A tenant-level mcp licence is the builder author; its audit rows need the licence id.
        let author = facts_principal(MCP_LICENCE_APP, SubjectKind::Tenant, "svc:t:mcp");
        let caller = BuiltinCaller::from_principal(&author);
        assert_eq!(caller.scope, MCP_LICENCE_SCOPE);
        assert_eq!(caller.kind, CallerKind::TenantAuthor);
        assert_eq!(
            caller.license_id.as_deref(),
            Some("01900000-0000-7000-8000-0000000000bb")
        );

        let member_author = facts_principal(MCP_LICENCE_APP, SubjectKind::Member, "svc:t:mcp");
        assert_eq!(BuiltinCaller::from_principal(&member_author).scope, "");

        // A payload with no `subject_kind` gets NOTHING, even when the subject has the `svc:`
        // shape the tenant licence carries — the reference's own rule (`scope.py:95`).
        let none = Principal {
            licence: Some(crate::auth::LicenceFacts {
                app: CAREBUS_LICENCE_APP.to_owned(),
                subject_kind: None,
            }),
            ..facts_principal(CAREBUS_LICENCE_APP, SubjectKind::Tenant, "svc:t:care-bus")
        };
        assert_eq!(
            BuiltinCaller::from_principal(&none).scope,
            "",
            "a licence with no reported kind is unscoped"
        );
    }
}
