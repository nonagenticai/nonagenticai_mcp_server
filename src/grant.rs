//! Operator schema actions for the API cutover: `--adopt-schema` and `--grant-runtime-role`.
//!
//! The live catalog database was built by the Python service's alembic migrations, so it carries
//! every table this crate's baseline creates and no `_sqlx_migrations` row at all: a Rust binary
//! starting against it would re-run the baseline onto an existing schema and fail. [`adopt_schema`]
//! stamps the embedded migrations as applied **without executing their SQL**, in exactly the shape
//! sqlx itself writes and later verifies (`sqlx-postgres`'s `Migrate::skip`).
//!
//! [`grant_runtime_role`] is the Rust form of the archived service's
//! `scripts/grant_runtime_role.py`: the runtime role is pre-created and owns nothing, so it is
//! granted schema usage, the catalog DML it needs, and EXECUTE on the SECURITY DEFINER functions
//! it calls. The API set is 85 statements (1 schema usage, 32 select, 22 insert, 10 update, 4
//! delete, 14 execute, 2 sequence usage); `--worker` is the executor's 65 (1, 38, 10, 8, 2, 4, 2).
//!
//! Every object identifier is a closed-list constant in this module. The only value that comes
//! from the command line is the role name, which [`quoted_role`] validates before it is quoted
//! into a statement — it is never interpolated into SQL text unvalidated.

use std::collections::BTreeMap;
use std::fmt;
use std::sync::LazyLock;

use regex::Regex;
use sqlx::{AssertSqlSafe, Connection, PgConnection};

use crate::db::MIGRATOR;

/// The environment variable `--adopt-schema` reads when `--url` is absent: the DIRECT connection
/// migrations use, because sqlx's migrator takes a session-level advisory lock (unsafe through
/// pgbouncer's transaction pooling).
pub const ADOPT_URL_ENV: &str = "DATABASE_MIGRATE_URL";
/// The environment variable `--grant-runtime-role` reads when `--url` is absent.
pub const GRANT_URL_ENV: &str = "DATABASE_URL";

/// The tenant catalog tables: the runtime role reads and inserts every one of them.
const TENANT_TABLES: &[&str] = &[
    "mcp_tools",
    "mcp_tool_versions",
    "mcp_tool_version_files",
    "mcp_tool_version_operations",
    "mcp_toolkits",
    "mcp_toolkit_versions",
    "mcp_toolkit_version_tools",
    "mcp_toolkit_inclusions",
    "mcp_credential_profiles",
    "mcp_credential_refs",
    "mcp_bindings",
    "mcp_binding_tools",
    "mcp_binding_toolkits",
    "mcp_protocol_sessions",
    "mcp_access_events",
    "mcp_binding_ensures",
];

/// Read-only for the runtime role: platform contracts, shares, tool sources (ciphertext only) and
/// the tenant builder's readable state.
const READ_TABLES: &[&str] = &[
    "alembic_version",
    "mcp_catalog_state",
    "mcp_services",
    "mcp_service_versions",
    "mcp_operation_versions",
    "mcp_tool_shares",
    "mcp_sources",
    "mcp_service_grants",
    "mcp_operation_keys",
    "mcp_source_specs",
];

/// The tenant builder's write path: SECURITY DEFINER functions, so the runtime role needs no table
/// DML on the platform tables they write.
const BUILDER_FUNCTIONS: &[&str] = &[
    "public.mcp_builder_source_create(uuid,uuid,text,text,jsonb,bytea,text,text,integer,integer,jsonb,integer)",
    "public.mcp_builder_source_update(uuid,text,bigint,text,jsonb,bytea,text,text,integer,integer,jsonb)",
    "public.mcp_builder_source_set_secret(uuid,text,bigint,bytea,jsonb)",
    "public.mcp_builder_source_set_status(uuid,text,bigint,text,jsonb)",
    "public.mcp_builder_service_create(uuid,jsonb,jsonb)",
    "public.mcp_builder_service_append(uuid,jsonb,bigint,jsonb)",
    "public.mcp_builder_operation_create(uuid,jsonb,text,jsonb,integer)",
    "public.mcp_builder_set_status(uuid,text,uuid,integer,text,jsonb)",
    "public.mcp_builder_publish(uuid,jsonb,jsonb,jsonb)",
    "public.mcp_builder_spec_put(uuid,uuid,text,integer,jsonb,integer,bigint)",
];

/// Evaluated by the tool-version triggers, the broker and the builder's catalog reads.
const REFERENCE_FUNCTION: &str = "public.mcp_tenant_may_use_service(uuid,uuid,integer)";

/// The columns the API role may UPDATE on its own tables. Identity columns stay immutable, which
/// the table triggers enforce independently.
const API_UPDATE_COLUMNS: &[(&str, &[&str])] = &[
    ("mcp_tools", &["revision", "retired"]),
    ("mcp_tool_versions", &["status", "updated_by", "updated_at"]),
    ("mcp_toolkits", &["revision"]),
    (
        "mcp_toolkit_versions",
        &["status", "updated_by", "updated_at"],
    ),
    (
        "mcp_credential_profiles",
        &["revision", "manifest", "updated_by", "updated_at"],
    ),
    (
        "mcp_bindings",
        &[
            "revision",
            "token_sha256",
            "spec",
            "tools",
            "enabled",
            "revoked",
            "expires_at",
            "credential_profile_id",
            "updated_by",
            "updated_at",
        ],
    ),
    (
        "mcp_binding_ensures",
        &[
            "revision",
            "gateway_license_id",
            "credential_profile_id",
            "binding_id",
            "toolkits",
            "skipped",
            "token_issued_at",
            "updated_by",
            "updated_at",
        ],
    ),
];

/// Rows the runtime role creates and removes as bindings and sessions come and go.
const API_DELETE_TABLES: &[&str] = &[
    "mcp_credential_refs",
    "mcp_binding_tools",
    "mcp_binding_toolkits",
    "mcp_protocol_sessions",
];

/// The table `sqlx-postgres` creates before it reads or writes a history
/// (`Migrate::ensure_migrations_table`), kept byte-for-byte: sqlx verifies what it finds here, so a
/// shape this module invented would break the next `MIGRATOR.run()`.
const MIGRATIONS_TABLE: &str = "\
CREATE TABLE IF NOT EXISTS _sqlx_migrations (
    version BIGINT PRIMARY KEY,
    description TEXT NOT NULL,
    installed_on TIMESTAMPTZ NOT NULL DEFAULT now(),
    success BOOLEAN NOT NULL,
    checksum BYTEA NOT NULL,
    execution_time BIGINT NOT NULL
)";

/// The row sqlx writes when it skips a migration (`Migrate::skip`): `execution_time = -1` is its
/// "recorded, not executed" marker, `success` is true, and `installed_on` keeps the column default.
const STAMP_MIGRATION: &str = "\
INSERT INTO _sqlx_migrations (version, description, success, checksum, execution_time) \
VALUES ($1, $2, TRUE, $3, -1)";

/// The table an adopted database must already carry: `--adopt-schema` is for a schema that exists,
/// and stamping a database without one would tell sqlx a catalog is there that is not.
const SCHEMA_SENTINEL: &str = "public.mcp_catalog_state";

/// The longest identifier Postgres stores: `NAMEDATALEN - 1` bytes.
const MAX_ROLE_BYTES: usize = 63;

#[derive(Debug, thiserror::Error)]
pub enum OperatorError {
    #[error(
        "this database does not look like the catalog schema: {0} is missing, so there is \
         nothing to adopt"
    )]
    NotTheSchema(&'static str),
    #[error(
        "migration {version} is stamped as failed (success = false); repair _sqlx_migrations \
         before adopting"
    )]
    Dirty { version: i64 },
    #[error("migration {version} is stamped with a checksum this binary's migrations do not match")]
    ChecksumMismatch { version: i64 },
    #[error("migration {version} is stamped here but is not embedded in this binary")]
    UnknownApplied { version: i64 },
    #[error("role {0:?} does not exist; create it before granting")]
    UnknownRole(String),
    #[error("invalid role name {role:?}: {reason}")]
    InvalidRole { role: String, reason: &'static str },
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

/// One privilege granted by one statement, so the report counts privileges rather than the
/// statements that happened to be batched together.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Kind {
    SchemaUsage,
    Select,
    Insert,
    Update,
    Delete,
    Execute,
    SequenceUsage,
}

impl Kind {
    fn label(self) -> &'static str {
        match self {
            Self::SchemaUsage => "schema usage",
            Self::Select => "select",
            Self::Insert => "insert",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Execute => "execute",
            Self::SequenceUsage => "sequence usage",
        }
    }
}

/// A validated, quoted role name.
///
/// The shape is deliberately narrow — an ASCII letter or underscore, then letters, digits and
/// underscores, at most 63 bytes — so quoting is the only transformation needed and no character
/// that could end the identifier or the statement can appear. Postgres would accept more when
/// quoted; this CLI needs nothing more, and refusing the rest keeps the SQL text a closed set.
pub fn quoted_role(role: &str) -> Result<String, OperatorError> {
    let invalid = |reason: &'static str| OperatorError::InvalidRole {
        role: role.to_owned(),
        reason,
    };
    if role.is_empty() {
        return Err(invalid("a role name is required"));
    }
    if role.len() > MAX_ROLE_BYTES {
        return Err(invalid("a role name is at most 63 bytes"));
    }
    let mut bytes = role.bytes();
    let first = bytes
        .next()
        .expect("a non-empty role name has a first byte");
    if !(first.is_ascii_alphabetic() || first == b'_') {
        return Err(invalid(
            "the first byte must be an ASCII letter or an underscore",
        ));
    }
    if !bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_') {
        return Err(invalid(
            "only ASCII letters, digits and underscores are allowed",
        ));
    }
    // The checks above leave no quote, backslash, whitespace or non-ASCII byte, so double-quoting
    // is exactly `quote_ident`: it can only make a keyword or an upper-case name safe.
    Ok(format!("\"{role}\""))
}

fn table_grant(
    out: &mut Vec<(Kind, String)>,
    kind: Kind,
    privilege: &str,
    table: &str,
    role: &str,
) {
    out.push((
        kind,
        format!("GRANT {privilege} ON public.{table} TO {role}"),
    ));
}

fn function_grant(out: &mut Vec<(Kind, String)>, function: &str, role: &str) {
    out.push((
        Kind::Execute,
        format!("GRANT EXECUTE ON FUNCTION {function} TO {role}"),
    ));
}

fn sequence_grant(out: &mut Vec<(Kind, String)>, sequence: &str, role: &str) {
    out.push((
        Kind::SequenceUsage,
        format!("GRANT USAGE ON SEQUENCE {sequence} TO {role}"),
    ));
}

/// The API role's plan, statement for statement the archive's `grant()` plus `grant_builder()`
/// plus `grant_execution(worker=False)`.
fn api_statements(role: &str) -> Vec<(Kind, String)> {
    let mut out = Vec::new();
    out.push((
        Kind::SchemaUsage,
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
    ));
    function_grant(
        &mut out,
        "public.mcp_lock_access_tool(uuid,uuid,uuid,integer)",
        role,
    );
    // Platform toolkits: the constant the binding-toolkit owner CHECK compares with.
    function_grant(&mut out, "public.mcp_platform_tenant()", role);
    for table in TENANT_TABLES.iter().chain(READ_TABLES) {
        table_grant(&mut out, Kind::Select, "SELECT", table, role);
    }
    for table in TENANT_TABLES {
        table_grant(&mut out, Kind::Insert, "INSERT", table, role);
    }
    for (table, columns) in API_UPDATE_COLUMNS {
        let privilege = format!("UPDATE ({})", columns.join(","));
        table_grant(&mut out, Kind::Update, &privilege, table, role);
    }
    for table in API_DELETE_TABLES {
        table_grant(&mut out, Kind::Delete, "DELETE", table, role);
    }
    // Builtin provider per-call audit: append-only, no read-back from the API.
    table_grant(
        &mut out,
        Kind::Insert,
        "INSERT",
        "mcp_tool_call_audit",
        role,
    );
    for function in BUILDER_FUNCTIONS {
        function_grant(&mut out, function, role);
    }
    function_grant(&mut out, REFERENCE_FUNCTION, role);
    execution(&mut out, role, false);
    out
}

/// The worker's plan: the archive's `grant_execution(worker=True)` after `USAGE ON SCHEMA public`.
/// The archive also re-issues the shared SELECTs and a column UPDATE the table grant below
/// subsumes; one statement per privilege grants the same set without the duplicates.
fn worker_statements(role: &str) -> Vec<(Kind, String)> {
    let mut out = Vec::new();
    out.push((
        Kind::SchemaUsage,
        format!("GRANT USAGE ON SCHEMA public TO {role}"),
    ));
    execution(&mut out, role, true);
    out
}

/// The archive's `grant_execution`: what a run's journal, lease and authority need at both ends,
/// then the API's or the worker's own part.
fn execution(out: &mut Vec<(Kind, String)>, role: &str, worker: bool) {
    for table in [
        "mcp_runs",
        "mcp_run_events",
        "mcp_execution_slots",
        "mcp_tenant_execution_locks",
    ] {
        table_grant(out, Kind::Select, "SELECT", table, role);
    }
    for table in ["mcp_runs", "mcp_run_events", "mcp_tenant_execution_locks"] {
        table_grant(out, Kind::Insert, "INSERT", table, role);
    }
    sequence_grant(out, "public.mcp_run_events_event_id_seq", role);
    function_grant(out, "public.mcp_lock_execution_authority()", role);
    table_grant(
        out,
        Kind::Update,
        "UPDATE (cancel_requested)",
        "mcp_runs",
        role,
    );

    if worker {
        // Task inputs are forwarded to the runtime that answers them.
        table_grant(out, Kind::Select, "SELECT", "mcp_task_inputs", role);
        table_grant(out, Kind::Update, "UPDATE", "mcp_task_inputs", role);
        // Run activity: the external driver records phases and terminal outcomes.
        table_grant(out, Kind::Select, "SELECT", "mcp_run_activity", role);
        table_grant(out, Kind::Insert, "INSERT", "mcp_run_activity", role);
        sequence_grant(out, "public.mcp_run_activity_seq_seq", role);
        function_grant(out, "public.mcp_expire_run_payloads(integer,integer)", role);
        function_grant(out, "public.mcp_platform_tenant()", role);
        // The worker re-evaluates the reference rule per call and reads every catalog table.
        function_grant(out, REFERENCE_FUNCTION, role);
        for table in READ_TABLES.iter().chain(TENANT_TABLES) {
            table_grant(out, Kind::Select, "SELECT", table, role);
        }
        // The worker writes run trace columns of mcp_run_api_calls through the table grant.
        for table in [
            "mcp_runs",
            "mcp_execution_slots",
            "mcp_tenant_execution_locks",
            "mcp_run_api_calls",
            "mcp_api_permits",
            "mcp_api_rate_windows",
        ] {
            table_grant(out, Kind::Select, "SELECT", table, role);
            table_grant(out, Kind::Insert, "INSERT", table, role);
            table_grant(out, Kind::Update, "UPDATE", table, role);
        }
        for table in ["mcp_api_permits", "mcp_api_rate_windows"] {
            table_grant(out, Kind::Delete, "DELETE", table, role);
        }
    } else {
        // MCP tasks: the API surfaces a status message, records what fr reports about a project
        // start, and answers task inputs.
        table_grant(
            out,
            Kind::Update,
            "UPDATE (status_message,external_ref)",
            "mcp_runs",
            role,
        );
        table_grant(out, Kind::Select, "SELECT", "mcp_task_inputs", role);
        table_grant(out, Kind::Insert, "INSERT", "mcp_task_inputs", role);
        table_grant(
            out,
            Kind::Update,
            "UPDATE (state,response,actor,answered_at,closed_at)",
            "mcp_task_inputs",
            role,
        );
        // Run activity: the API records fr channel events (approvals) on the feed.
        table_grant(out, Kind::Select, "SELECT", "mcp_run_activity", role);
        table_grant(out, Kind::Insert, "INSERT", "mcp_run_activity", role);
        sequence_grant(out, "public.mcp_run_activity_seq_seq", role);
    }
}

/// A migration this run stamped, or found already stamped, in `_sqlx_migrations`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StampedMigration {
    pub version: i64,
    pub description: String,
}

/// The last migration that belongs to the pre-sqlx baseline.
///
/// `0001_baseline` is a `pg_dump` of the schema the alembic head created, and `0002_catalog_state`
/// inserts the singleton row the reference's own baseline migration inserted — both are already
/// present in a live database, which is what an adoption stamps. Anything newer must be EXECUTED
/// by the migrator: this binary runs as a per-pod-start initContainer, so stamping a migration
/// that has not run would mark its SQL applied forever and every later deploy would inherit the
/// missing schema.
pub const BASELINE_CUTOFF: i64 = 2;

/// What `--adopt-schema` did, in the order the migrations are embedded.
#[derive(Debug, Default)]
pub struct AdoptReport {
    pub stamped: Vec<StampedMigration>,
    pub already: Vec<i64>,
    /// Embedded migrations newer than the cutoff: left for the migrator to execute.
    pub pending: Vec<i64>,
}

impl fmt::Display for AdoptReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(
            formatter,
            "adopt-schema: {} stamped, {} already applied, {} pending",
            self.stamped.len(),
            self.already.len(),
            self.pending.len()
        )?;
        for stamped in &self.stamped {
            writeln!(
                formatter,
                "  stamped {} ({})",
                stamped.version, stamped.description
            )?;
        }
        for pending in &self.pending {
            writeln!(
                formatter,
                "  pending {pending}: newer than the baseline, the migrator executes it at startup"
            )?;
        }
        Ok(())
    }
}

/// What `--grant-runtime-role` granted, counted per privilege.
#[derive(Debug)]
pub struct GrantReport {
    pub role: String,
    pub worker: bool,
    pub counts: BTreeMap<Kind, usize>,
}

impl fmt::Display for GrantReport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let set = if self.worker { "worker" } else { "api" };
        let statements: usize = self.counts.values().sum();
        writeln!(
            formatter,
            "grant-runtime-role: {statements} privileges granted to \"{}\" ({set}) in one transaction",
            self.role
        )?;
        for (kind, count) in &self.counts {
            writeln!(formatter, "  {}: {count}", kind.label())?;
        }
        Ok(())
    }
}

/// Stamp the baseline migrations as applied, without executing them.
///
/// The values are the ones sqlx itself verifies: `MIGRATOR.iter()` carries the version,
/// description and SHA-384 checksum `sqlx::migrate!` computed from each file's exact bytes. A
/// version already present is compared byte for byte and left untouched when it matches, refused
/// when it does not; a failed row or a version this binary does not embed is refused for the same
/// reason `MIGRATOR.run()` would refuse it at startup. Nothing is written unless the whole run
/// passes, because every read and write is one transaction.
///
/// Only [`BASELINE_CUTOFF`] and older are stamped. A newer embedded migration is reported as
/// pending and left unstamped, so the migrator executes it at startup — the property that keeps
/// the next migration from being swallowed by a pod that adopts on every start.
pub async fn adopt_schema(url: &str) -> Result<AdoptReport, OperatorError> {
    adopt_schema_until(url, BASELINE_CUTOFF).await
}

/// [`adopt_schema`] with the cutoff as an argument, so a test can exercise "newer than the
/// baseline" without a second migration file existing yet.
pub async fn adopt_schema_until(url: &str, cutoff: i64) -> Result<AdoptReport, OperatorError> {
    let mut conn = PgConnection::connect(url).await?;
    let mut tx = conn.begin().await?;

    // `SCHEMA_SENTINEL` is a closed-list constant, never operator input.
    let schema_present: bool = sqlx::query_scalar(AssertSqlSafe(format!(
        "SELECT to_regclass('{SCHEMA_SENTINEL}') IS NOT NULL"
    )))
    .fetch_one(&mut *tx)
    .await?;
    if !schema_present {
        return Err(OperatorError::NotTheSchema(SCHEMA_SENTINEL));
    }

    sqlx::query(MIGRATIONS_TABLE).execute(&mut *tx).await?;
    // The applied set is read the way sqlx reads it (`list_applied_migrations`), plus `success`
    // so a failed row is refused here rather than at the next startup.
    let applied: Vec<(i64, bool, Vec<u8>)> =
        sqlx::query_as("SELECT version, success, checksum FROM _sqlx_migrations ORDER BY version")
            .fetch_all(&mut *tx)
            .await?;
    if let Some((version, _, _)) = applied.iter().find(|(_, success, _)| !success) {
        return Err(OperatorError::Dirty { version: *version });
    }
    // `validate_applied_migrations` with `ignore_missing = false`, which is this crate's migrator.
    for (version, _, _) in &applied {
        if !MIGRATOR.version_exists(*version) {
            return Err(OperatorError::UnknownApplied { version: *version });
        }
    }

    let mut report = AdoptReport::default();
    for migration in MIGRATOR.iter() {
        if migration.migration_type.is_down_migration() {
            continue;
        }
        match applied
            .iter()
            .find(|(version, _, _)| *version == migration.version)
        {
            Some((_, _, checksum)) if checksum.as_slice() == migration.checksum.as_ref() => {
                report.already.push(migration.version);
            }
            Some(_) => {
                return Err(OperatorError::ChecksumMismatch {
                    version: migration.version,
                });
            }
            // Newer than the baseline and not applied: the migrator's to execute, never this
            // step's to stamp.
            None if migration.version > cutoff => {
                report.pending.push(migration.version);
            }
            None => {
                sqlx::query(STAMP_MIGRATION)
                    .bind(migration.version)
                    .bind(migration.description.as_ref())
                    .bind(migration.checksum.as_ref())
                    .execute(&mut *tx)
                    .await?;
                report.stamped.push(StampedMigration {
                    version: migration.version,
                    description: migration.description.to_string(),
                });
            }
        }
    }
    tx.commit().await?;
    Ok(report)
}

/// Grant the runtime role the privileges the archive's operator script grants, idempotently and in
/// one transaction: a statement that fails on a drifted schema leaves nothing half-granted.
pub async fn grant_runtime_role(
    url: &str,
    role: &str,
    worker: bool,
) -> Result<GrantReport, OperatorError> {
    // Validated before the connection: an unusable role name never reaches a statement.
    let role_sql = quoted_role(role)?;
    let plan = if worker {
        worker_statements(&role_sql)
    } else {
        api_statements(&role_sql)
    };
    let mut conn = PgConnection::connect(url).await?;
    let mut tx = conn.begin().await?;
    let exists: Option<i32> = sqlx::query_scalar("SELECT 1 FROM pg_roles WHERE rolname = $1")
        .bind(role)
        .fetch_optional(&mut *tx)
        .await?;
    if exists.is_none() {
        return Err(OperatorError::UnknownRole(role.to_owned()));
    }
    let mut counts = BTreeMap::new();
    for (kind, statement) in &plan {
        // Every fragment is a closed-list constant, or the role quoted by `quoted_role`.
        sqlx::query(AssertSqlSafe(statement.clone()))
            .execute(&mut *tx)
            .await?;
        *counts.entry(*kind).or_insert(0usize) += 1;
    }
    tx.commit().await?;
    Ok(GrantReport {
        role: role.to_owned(),
        worker,
        counts,
    })
}

/// `scheme://user:password@` — the only place a DSN can carry a secret.
static USERINFO: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"://[^/@\s]+@").expect("static userinfo pattern"));

/// Mask secrets before a message reaches an operator's terminal: the whole database URL when it
/// appears verbatim, then the `user:password` part of any URL-shaped token. A URL's host and
/// database are not secrets; its credentials are.
pub fn redact(message: &str, url: &str) -> String {
    let whole = if url.is_empty() {
        message.to_owned()
    } else {
        message.replace(url, "postgres://<redacted>")
    };
    USERINFO.replace_all(&whole, "://<redacted>@").into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn counts(plan: &[(Kind, String)]) -> BTreeMap<Kind, usize> {
        let mut counts = BTreeMap::new();
        for (kind, _) in plan {
            *counts.entry(*kind).or_insert(0usize) += 1;
        }
        counts
    }

    fn text(plan: &[(Kind, String)]) -> String {
        plan.iter()
            .map(|(_, statement)| statement.as_str())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn role_names_are_validated_before_they_are_quoted() {
        assert_eq!(quoted_role("mcp_api").expect("valid"), "\"mcp_api\"");
        assert_eq!(quoted_role("_x1").expect("valid"), "\"_x1\"");
        assert!(quoted_role(&"a".repeat(MAX_ROLE_BYTES)).is_ok());
        for bad in [
            "",
            "1abc",
            "has space",
            "has\"quote",
            "a.b",
            "a-b",
            "a;b",
            "mcp\napi",
            "rä",
        ] {
            assert!(quoted_role(bad).is_err(), "{bad:?} must be refused");
        }
        assert!(
            quoted_role(&"a".repeat(MAX_ROLE_BYTES + 1)).is_err(),
            "longer than NAMEDATALEN"
        );
    }

    #[test]
    fn the_api_plan_is_the_oracle_privilege_set() {
        let plan = api_statements("\"mcp_api\"");
        assert_eq!(
            counts(&plan),
            BTreeMap::from([
                (Kind::SchemaUsage, 1),
                (Kind::Select, 32),
                (Kind::Insert, 22),
                (Kind::Update, 10),
                (Kind::Delete, 4),
                (Kind::Execute, 14),
                (Kind::SequenceUsage, 2),
            ])
        );
        let text = text(&plan);
        assert!(text.contains(
            "GRANT EXECUTE ON FUNCTION public.mcp_builder_publish(uuid,jsonb,jsonb,jsonb)"
        ));
        assert!(text.contains("GRANT UPDATE (revision,retired) ON public.mcp_tools"));
        assert!(text.contains("GRANT INSERT ON public.mcp_tool_call_audit"));
        assert!(text.contains(
            "GRANT UPDATE (state,response,actor,answered_at,closed_at) ON public.mcp_task_inputs"
        ));
        assert!(
            !text.contains("mcp_expire_run_payloads"),
            "the retention sweep belongs to the worker"
        );
        assert!(
            !text.contains("mcp_run_api_calls"),
            "the worker's API journal is not the API role's"
        );
    }

    #[test]
    fn the_worker_plan_is_the_execution_privilege_set() {
        let plan = worker_statements("\"mcp_worker\"");
        assert_eq!(
            counts(&plan),
            BTreeMap::from([
                (Kind::SchemaUsage, 1),
                (Kind::Select, 38),
                (Kind::Insert, 10),
                (Kind::Update, 8),
                (Kind::Delete, 2),
                (Kind::Execute, 4),
                (Kind::SequenceUsage, 2),
            ])
        );
        let text = text(&plan);
        assert!(
            text.contains(
                "GRANT EXECUTE ON FUNCTION public.mcp_expire_run_payloads(integer,integer)"
            )
        );
        assert!(text.contains("GRANT UPDATE ON public.mcp_runs"));
        assert!(text.contains("GRANT DELETE ON public.mcp_api_rate_windows"));
        assert!(
            !text.contains("mcp_builder_publish"),
            "the builder is the API role's write path"
        );
        assert!(
            !text.contains("mcp_tool_call_audit"),
            "the provider audit is the API role's"
        );
    }

    #[test]
    fn every_statement_is_a_grant_to_the_quoted_role_and_names_nothing_else_quoted() {
        for (role, plan) in [
            ("\"mcp_api\"", api_statements("\"mcp_api\"")),
            ("\"mcp_worker\"", worker_statements("\"mcp_worker\"")),
        ] {
            for (_, statement) in &plan {
                assert!(statement.starts_with("GRANT "), "{statement}");
                assert!(statement.ends_with(&format!("TO {role}")), "{statement}");
                // The role is the only quoted identifier in a statement: every object name is a
                // bare closed-list constant in this module.
                assert!(!statement.replace(role, "").contains('"'), "{statement}");
            }
        }
    }

    #[test]
    fn redaction_masks_a_url_and_any_other_userinfo() {
        let url = "postgres://postgres:s3cret@127.0.0.1:55432/mcp?sslmode=prefer";
        let masked = redact(&format!("cannot connect to {url}: refused"), url);
        assert!(!masked.contains("s3cret"), "{masked}");
        assert!(!masked.contains(url), "{masked}");

        let other = redact(
            "error: postgres://user:hunter2@db.internal:5432/x failed",
            "",
        );
        assert!(!other.contains("hunter2"), "{other}");
        assert!(
            other.contains("db.internal"),
            "the host is not a secret: {other}"
        );
    }
}
