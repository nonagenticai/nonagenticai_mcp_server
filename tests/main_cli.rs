//! The operator CLI against a real Postgres 18: `--adopt-schema` and `--grant-runtime-role`.
//!
//! Server selection is the estate's test-DB standard (`tests/db.rs`): `TEST_DATABASE_URL`, else
//! `DATABASE_URL` (a URL whose user may CREATE DATABASE and CREATE ROLE), else an ephemeral
//! `postgres:18` container started here and removed afterwards, else FAIL — never skip. Each test
//! gets its own fresh database, dropped at the end, and runs the binary cargo built
//! (`CARGO_BIN_EXE_mcp-server-rs`), so what is asserted is the real argv → stdout → SQL path.

use std::process::{Command, Output};
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, ConnectOptions, Connection, PgConnection, PgPool};

use mcp_server_rs::db;

/// The binary this package builds, under the name cargo gives integration tests.
const BIN: &str = env!("CARGO_BIN_EXE_mcp-server-rs");

/// The test server: an existing one from the environment, else an ephemeral container.
struct Server {
    url: String,
    container: Option<String>,
}

impl Drop for Server {
    fn drop(&mut self) {
        if let Some(id) = &self.container {
            let _ = Command::new("docker").args(["rm", "-f", "-v", id]).output();
        }
    }
}

fn env_url() -> Option<String> {
    ["TEST_DATABASE_URL", "DATABASE_URL"]
        .iter()
        .filter_map(|key| std::env::var(key).ok())
        .find(|value| !value.trim().is_empty())
}

async fn server() -> Server {
    if let Some(url) = env_url() {
        return Server {
            url,
            container: None,
        };
    }
    let image = match std::env::var("TEST_PG_REGISTRY") {
        Ok(registry) if !registry.trim().is_empty() => {
            format!("{}/postgres:18", registry.trim_end_matches('/'))
        }
        _ => "postgres:18".to_owned(),
    };
    let out = Command::new("docker")
        .args([
            "run",
            "-d",
            "--rm",
            "--tmpfs",
            "/var/lib/postgresql",
            "-e",
            "POSTGRES_PASSWORD=postgres",
            "-p",
            "127.0.0.1::5432",
            &image,
            "-c",
            "fsync=off",
        ])
        .output()
        .expect("no TEST_DATABASE_URL/DATABASE_URL and `docker` cannot run: failing closed");
    assert!(
        out.status.success(),
        "docker run {image} failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let id = String::from_utf8(out.stdout).unwrap().trim().to_owned();
    // Guard first, so the container is removed even if the port lookup or wait panics.
    let mut srv = Server {
        url: String::new(),
        container: Some(id.clone()),
    };
    let port_out = Command::new("docker")
        .args(["port", &id, "5432/tcp"])
        .output()
        .expect("docker port");
    let mapping = String::from_utf8(port_out.stdout).unwrap();
    let port = mapping
        .lines()
        .next()
        .and_then(|line| line.rsplit(':').next())
        .map(str::trim)
        .filter(|port| !port.is_empty())
        .unwrap_or_else(|| panic!("no published port for {id}: {mapping:?}"))
        .to_owned();
    srv.url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match PgConnection::connect(&srv.url).await {
            Ok(connection) => {
                let _ = connection.close().await;
                break;
            }
            Err(error) if Instant::now() > deadline => {
                panic!("postgres never became ready: {error}")
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    srv
}

/// One fresh database on the test server, with its own URL for the binary.
struct Database {
    /// The URL the CLI is handed: the fixture database, credentials included.
    url: String,
    admin_url: String,
    name: String,
    pool: PgPool,
    server: Server,
}

impl Database {
    /// `migrated` applies this binary's migrations, which is the schema an adopted database is
    /// expected to carry; `false` leaves the database empty, as a wrong target would be.
    async fn new(migrated: bool) -> Self {
        let server = server().await;
        let admin_opts = PgConnectOptions::from_str(&server.url).expect("parse database url");
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");
        let name = unique("mcp_cli_db");
        sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&mut admin)
            .await
            .expect("create test database");
        let options = admin_opts.database(&name);
        let url = options.to_url_lossy().to_string();
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect_with(options)
            .await
            .expect("connect test database");
        if migrated {
            db::migrate(&pool).await.expect("apply migrations");
        }
        let _ = admin.close().await;
        Self {
            url,
            admin_url: server.url.clone(),
            name,
            pool,
            server,
        }
    }

    /// Drop the database, then any role the test created, then the server. Roles are cluster
    /// wide, so they can only be dropped once the database that held their grants is gone.
    async fn finish(self, roles: &[&str]) {
        let Self {
            url: _,
            admin_url,
            name,
            pool,
            server,
        } = self;
        pool.close().await;
        let admin_opts = PgConnectOptions::from_str(&admin_url).expect("parse database url");
        let mut admin = PgConnection::connect_with(&admin_opts)
            .await
            .expect("connect admin");
        sqlx::query(AssertSqlSafe(format!(
            "DROP DATABASE \"{name}\" WITH (FORCE)"
        )))
        .execute(&mut admin)
        .await
        .expect("drop test database");
        for role in roles {
            sqlx::query(AssertSqlSafe(format!("DROP ROLE IF EXISTS \"{role}\"")))
                .execute(&mut admin)
                .await
                .expect("drop test role");
        }
        let _ = admin.close().await;
        drop(server);
    }
}

/// A name unique to this process and call: the clock alone is coarser than two parallel tests.
fn unique(prefix: &str) -> String {
    static SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0);
    let sequence = SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    format!("{prefix}_{}_{nanos}_{sequence}", std::process::id())
}

/// Run the binary with exactly this argv and environment, asserting that nothing it printed can
/// carry the database's credentials — the operator rule this CLI exists to honour.
fn run(argv: &[&str], env: &[(&str, &str)], dsn: &str) -> Output {
    let output = Command::new(BIN)
        .args(argv)
        .env_remove("DATABASE_URL")
        .env_remove("DATABASE_MIGRATE_URL")
        .envs(env.iter().copied())
        .output()
        .expect("run the operator CLI");
    for stream in [
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    ] {
        assert!(
            !stream.contains(dsn),
            "the CLI printed the database URL: {stream}"
        );
    }
    output
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

/// Every row `--adopt-schema` may write, as sqlx itself writes it.
async fn stamps(pool: &PgPool) -> Vec<(i64, String, bool, Vec<u8>, i64)> {
    sqlx::query_as(
        "SELECT version, description, success, checksum, execution_time \
         FROM _sqlx_migrations ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .expect("read _sqlx_migrations")
}

/// Every ACL in the schema as Postgres stores it: a grant run twice must not change a byte.
async fn acls(pool: &PgPool) -> Vec<String> {
    let mut rows: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(c.relacl::text, '') FROM pg_class c \
         JOIN pg_namespace n ON n.oid = c.relnamespace \
         WHERE n.nspname = 'public' AND c.relkind IN ('r', 'S') ORDER BY c.relname",
    )
    .fetch_all(pool)
    .await
    .expect("read table ACLs");
    let functions: Vec<String> = sqlx::query_scalar(
        "SELECT coalesce(p.proacl::text, '') FROM pg_proc p \
         JOIN pg_namespace n ON n.oid = p.pronamespace \
         WHERE n.nspname = 'public' ORDER BY p.proname, p.oid",
    )
    .fetch_all(pool)
    .await
    .expect("read function ACLs");
    rows.extend(functions);
    let schema: String = sqlx::query_scalar(
        "SELECT coalesce(nspacl::text, '') FROM pg_namespace WHERE nspname = 'public'",
    )
    .fetch_one(pool)
    .await
    .expect("read schema ACL");
    rows.push(schema);
    rows
}

// The casts make the overload concrete: sqlx sends untyped parameters, and `has_*_privilege` has
// several signatures that an untyped argument list would leave ambiguous.

async fn has_table(pool: &PgPool, role: &str, table: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_table_privilege($1::text, $2::text, $3::text)")
        .bind(role)
        .bind(table)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_table_privilege")
}

async fn has_column(pool: &PgPool, role: &str, table: &str, column: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_column_privilege($1::text, $2::text, $3::text, $4::text)")
        .bind(role)
        .bind(table)
        .bind(column)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_column_privilege")
}

async fn has_function(pool: &PgPool, role: &str, function: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_function_privilege($1::text, $2::text, $3::text)")
        .bind(role)
        .bind(function)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_function_privilege")
}

async fn has_schema(pool: &PgPool, role: &str, schema: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_schema_privilege($1::text, $2::text, $3::text)")
        .bind(role)
        .bind(schema)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_schema_privilege")
}

async fn has_sequence(pool: &PgPool, role: &str, sequence: &str, privilege: &str) -> bool {
    sqlx::query_scalar("SELECT has_sequence_privilege($1::text, $2::text, $3::text)")
        .bind(role)
        .bind(sequence)
        .bind(privilege)
        .fetch_one(pool)
        .await
        .expect("has_sequence_privilege")
}

#[tokio::test]
async fn adopt_stamps_only_what_is_absent_and_a_rerun_is_a_no_op() {
    let fixture = Database::new(true).await;
    let url = fixture.url.as_str();
    let embedded = db::MIGRATOR.iter().count();
    assert!(embedded >= 2, "the embedded migrations are missing");
    // The live database is alembic's: the whole schema, no sqlx history at all.
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&fixture.pool)
        .await
        .expect("clear the sqlx history");

    let first = run(&["--adopt-schema", "--url", url], &[], url);
    assert!(first.status.success(), "{}", stderr(&first));
    assert!(
        stdout(&first).contains(&format!(
            "adopt-schema: {embedded} stamped, 0 already applied"
        )),
        "{}",
        stdout(&first)
    );

    // sqlx itself is the judge of the shape: the stamp is read back column by column, and its own
    // migrator then runs over it as a no-op instead of re-executing the baseline.
    let stamped = stamps(&fixture.pool).await;
    assert_eq!(stamped.len(), embedded);
    for (row, migration) in stamped.iter().zip(db::MIGRATOR.iter()) {
        assert_eq!(row.0, migration.version);
        assert_eq!(row.1, migration.description.as_ref());
        assert!(row.2, "success");
        assert_eq!(row.3, migration.checksum.as_ref());
        assert_eq!(row.4, -1, "execution_time is sqlx's not-executed marker");
    }
    db::migrate(&fixture.pool)
        .await
        .expect("sqlx accepts the stamp: the migrator is a no-op");
    assert_eq!(
        stamps(&fixture.pool).await,
        stamped,
        "a no-op migrator run changed the history"
    );

    // The DATABASE_MIGRATE_URL path, and "only what is absent": one row removed, one stamped, and
    // the row that was already there left alone.
    let newest = db::MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .max()
        .expect("a migration");
    sqlx::query("DELETE FROM _sqlx_migrations WHERE version = $1")
        .bind(newest)
        .execute(&fixture.pool)
        .await
        .expect("remove one stamp");
    let second = run(&["--adopt-schema"], &[("DATABASE_MIGRATE_URL", url)], url);
    assert!(second.status.success(), "{}", stderr(&second));
    assert!(
        stdout(&second).contains(&format!(
            "adopt-schema: 1 stamped, {} already applied",
            embedded - 1
        )),
        "{}",
        stdout(&second)
    );
    assert!(
        stdout(&second).contains(&format!("stamped {newest} (")),
        "{}",
        stdout(&second)
    );
    assert_eq!(
        stamps(&fixture.pool).await,
        stamped,
        "the re-stamped row is the one sqlx writes"
    );
    fixture.finish(&[]).await;
}

/// The property that keeps the NEXT migration from being swallowed: this binary runs as a
/// per-pod-start initContainer, so a migration newer than the baseline must be left unstamped and
/// executed by the migrator, never marked applied by a stamp whose SQL never ran.
#[tokio::test]
async fn adopt_never_stamps_a_migration_newer_than_the_baseline() {
    let fixture = Database::new(true).await;
    let url = fixture.url.as_str();
    let versions: Vec<i64> = db::MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .collect();
    assert_eq!(
        versions,
        vec![1, 2],
        "this test is written for the 0001/0002 baseline"
    );
    // The live database is alembic's: the whole schema, no sqlx history at all.
    sqlx::query("DELETE FROM _sqlx_migrations")
        .execute(&fixture.pool)
        .await
        .expect("clear the sqlx history");

    // A cutoff that leaves 0002 to the migrator: reported, and not stamped.
    let report = mcp_server_rs::grant::adopt_schema_until(url, 1)
        .await
        .expect("adopt the baseline");
    assert_eq!(
        report
            .stamped
            .iter()
            .map(|stamped| stamped.version)
            .collect::<Vec<_>>(),
        vec![1]
    );
    assert_eq!(report.pending, vec![2]);
    assert_eq!(
        stamps(&fixture.pool)
            .await
            .iter()
            .map(|row| row.0)
            .collect::<Vec<_>>(),
        vec![1],
        "0002 is newer than the cutoff and must not be stamped"
    );

    // The migrator then EXECUTES it — 0002's `INSERT ... ON CONFLICT DO NOTHING` against the
    // singleton row the baseline already carries.
    db::migrate(&fixture.pool)
        .await
        .expect("the migrator applies what adopt left pending");
    assert_eq!(
        stamps(&fixture.pool)
            .await
            .iter()
            .map(|row| row.0)
            .collect::<Vec<_>>(),
        versions
    );
    let state: i64 = sqlx::query_scalar("SELECT count(*) FROM mcp_catalog_state")
        .fetch_one(&fixture.pool)
        .await
        .expect("catalog state");
    assert_eq!(state, 1, "0002 ran once and left exactly its singleton row");
    fixture.finish(&[]).await;
}

#[tokio::test]
async fn adopt_refuses_a_checksum_that_does_not_match_and_a_failed_row() {
    let fixture = Database::new(true).await;
    let url = fixture.url.as_str();
    let embedded = db::MIGRATOR.iter().count();
    let first_version = db::MIGRATOR
        .iter()
        .map(|migration| migration.version)
        .min()
        .expect("a migration");

    // A stamped checksum this binary's migration cannot produce: sqlx would refuse at startup
    // (`VersionMismatch`), so the operator step refuses and writes nothing.
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1 WHERE version = $2")
        .bind(vec![0u8; 48])
        .bind(first_version)
        .execute(&fixture.pool)
        .await
        .expect("tamper with one checksum");
    let refused = run(&["--adopt-schema", "--url", url], &[], url);
    assert!(
        !refused.status.success(),
        "a mismatched checksum must be refused: {}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("checksum"),
        "{}",
        stderr(&refused)
    );
    let tampered = stamps(&fixture.pool).await;
    assert_eq!(tampered.len(), embedded, "a refusal wrote no row");
    assert_eq!(
        tampered[0].3,
        vec![0u8; 48],
        "a refusal did not overwrite the stamp it refused"
    );

    // A failed row is sqlx's `Dirty` state: `run()` refuses it at startup, so adopt refuses it
    // here with the migration named.
    let correct = db::MIGRATOR
        .iter()
        .find(|migration| migration.version == first_version)
        .expect("the embedded migration")
        .checksum
        .to_vec();
    sqlx::query("UPDATE _sqlx_migrations SET checksum = $1, success = false WHERE version = $2")
        .bind(correct)
        .bind(first_version)
        .execute(&fixture.pool)
        .await
        .expect("mark one row failed");
    let refused = run(&["--adopt-schema", "--url", url], &[], url);
    assert!(
        !refused.status.success(),
        "a failed row must be refused: {}",
        stdout(&refused)
    );
    assert!(stderr(&refused).contains("failed"), "{}", stderr(&refused));
    assert_eq!(
        stamps(&fixture.pool).await.len(),
        embedded,
        "a refusal wrote no row"
    );
    fixture.finish(&[]).await;
}

#[tokio::test]
async fn adopt_refuses_a_database_without_the_catalog_schema() {
    let fixture = Database::new(false).await;
    let url = fixture.url.as_str();
    let refused = run(&["--adopt-schema", "--url", url], &[], url);
    assert!(
        !refused.status.success(),
        "an empty database is not something to adopt: {}",
        stdout(&refused)
    );
    assert!(
        stderr(&refused).contains("mcp_catalog_state"),
        "{}",
        stderr(&refused)
    );
    // Nothing was created either: the whole action is one transaction that never committed.
    let history: Option<String> =
        sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations')::text")
            .fetch_one(&fixture.pool)
            .await
            .expect("to_regclass");
    assert!(
        history.is_none(),
        "a refusal created a history table: {history:?}"
    );
    fixture.finish(&[]).await;
}

#[tokio::test]
async fn grant_is_idempotent_and_the_server_reports_the_privileges() {
    let fixture = Database::new(true).await;
    let url = fixture.url.as_str();
    let api_role = unique("mcp_cli_api");
    let worker_role = unique("mcp_cli_worker");
    for role in [&api_role, &worker_role] {
        sqlx::query(AssertSqlSafe(format!("CREATE ROLE \"{role}\"")))
            .execute(&fixture.pool)
            .await
            .expect("create the runtime role");
    }
    // A default database hands every role EXECUTE on every function and USAGE on `public` through
    // PUBLIC, which would make the positive assertions vacuous and the negative ones false. Take
    // those defaults away first, so every privilege a role ends up with is one this run granted.
    for statement in [
        "REVOKE USAGE ON SCHEMA public FROM PUBLIC",
        "REVOKE EXECUTE ON ALL FUNCTIONS IN SCHEMA public FROM PUBLIC",
    ] {
        sqlx::query(statement)
            .execute(&fixture.pool)
            .await
            .expect("take away the PUBLIC defaults");
    }

    let granted = run(
        &[
            "--grant-runtime-role",
            "--role",
            api_role.as_str(),
            "--url",
            url,
        ],
        &[],
        url,
    );
    assert!(granted.status.success(), "{}", stderr(&granted));
    assert!(
        stdout(&granted).contains(&format!(
            "grant-runtime-role: 85 privileges granted to \"{api_role}\" (api)"
        )),
        "{}",
        stdout(&granted)
    );

    // GRANT is idempotent: a second run must leave every ACL byte-identical.
    let before = acls(&fixture.pool).await;
    let repeated = run(
        &[
            "--grant-runtime-role",
            "--role",
            api_role.as_str(),
            "--url",
            url,
        ],
        &[],
        url,
    );
    assert!(repeated.status.success(), "{}", stderr(&repeated));
    assert_eq!(
        acls(&fixture.pool).await,
        before,
        "a second API grant run changed an ACL"
    );

    // The server's own verdict, not this test's reading of the grant list.
    assert!(has_schema(&fixture.pool, &api_role, "public", "USAGE").await);
    assert!(has_table(&fixture.pool, &api_role, "public.mcp_tools", "SELECT").await);
    assert!(has_table(&fixture.pool, &api_role, "public.mcp_tools", "INSERT").await);
    assert!(
        !has_table(&fixture.pool, &api_role, "public.mcp_tools", "UPDATE").await,
        "the API updates only the columns it names"
    );
    assert!(
        has_column(
            &fixture.pool,
            &api_role,
            "public.mcp_tools",
            "revision",
            "UPDATE"
        )
        .await
    );
    assert!(
        !has_column(
            &fixture.pool,
            &api_role,
            "public.mcp_tools",
            "public_name",
            "UPDATE"
        )
        .await,
        "identity columns stay immutable"
    );
    assert!(
        has_table(
            &fixture.pool,
            &api_role,
            "public.mcp_credential_refs",
            "DELETE"
        )
        .await
    );
    assert!(!has_table(&fixture.pool, &api_role, "public.mcp_runs", "DELETE").await);
    assert!(
        has_sequence(
            &fixture.pool,
            &api_role,
            "public.mcp_run_events_event_id_seq",
            "USAGE"
        )
        .await
    );
    assert!(
        has_function(
            &fixture.pool,
            &api_role,
            "public.mcp_lock_access_tool(uuid,uuid,uuid,integer)",
            "EXECUTE"
        )
        .await
    );
    assert!(
        has_function(
            &fixture.pool,
            &api_role,
            "public.mcp_builder_publish(uuid,jsonb,jsonb,jsonb)",
            "EXECUTE"
        )
        .await
    );
    assert!(
        !has_function(
            &fixture.pool,
            &api_role,
            "public.mcp_expire_run_payloads(integer,integer)",
            "EXECUTE"
        )
        .await,
        "the retention sweep belongs to the worker"
    );

    // The worker set: the execution journal and the retention sweep, not the builder or the
    // per-call provider audit.
    let worker = run(
        &[
            "--grant-runtime-role",
            "--role",
            worker_role.as_str(),
            "--worker",
            "--url",
            url,
        ],
        &[],
        url,
    );
    assert!(worker.status.success(), "{}", stderr(&worker));
    assert!(stdout(&worker).contains("(worker)"), "{}", stdout(&worker));
    let before = acls(&fixture.pool).await;
    let repeated = run(
        &[
            "--grant-runtime-role",
            "--role",
            worker_role.as_str(),
            "--worker",
            "--url",
            url,
        ],
        &[],
        url,
    );
    assert!(repeated.status.success(), "{}", stderr(&repeated));
    assert_eq!(
        acls(&fixture.pool).await,
        before,
        "a second worker grant run changed an ACL"
    );

    assert!(has_table(&fixture.pool, &worker_role, "public.mcp_runs", "UPDATE").await);
    assert!(
        has_table(
            &fixture.pool,
            &worker_role,
            "public.mcp_api_rate_windows",
            "DELETE"
        )
        .await
    );
    assert!(
        !has_table(&fixture.pool, &worker_role, "public.mcp_tools", "INSERT").await,
        "the worker reads the tenant catalog, it does not write it"
    );
    assert!(
        !has_table(
            &fixture.pool,
            &worker_role,
            "public.mcp_tool_call_audit",
            "INSERT"
        )
        .await,
        "the provider audit is the API role's"
    );
    assert!(
        has_function(
            &fixture.pool,
            &worker_role,
            "public.mcp_expire_run_payloads(integer,integer)",
            "EXECUTE"
        )
        .await
    );
    assert!(
        !has_function(
            &fixture.pool,
            &worker_role,
            "public.mcp_builder_publish(uuid,jsonb,jsonb,jsonb)",
            "EXECUTE"
        )
        .await,
        "the builder is the API role's write path"
    );

    fixture
        .finish(&[api_role.as_str(), worker_role.as_str()])
        .await;
}

#[tokio::test]
async fn an_unusable_role_name_is_refused_before_any_sql_runs() {
    let fixture = Database::new(true).await;
    let url = fixture.url.as_str();
    let before = acls(&fixture.pool).await;
    let too_long = "a".repeat(64);
    for role in [
        "",
        "mcp\"; DROP TABLE public.mcp_tools; --",
        "9lives",
        "has space",
        "dots.in.name",
        too_long.as_str(),
    ] {
        let refused = run(
            &["--grant-runtime-role", "--role", role, "--url", url],
            &[],
            url,
        );
        assert!(!refused.status.success(), "{role:?} must be refused");
        assert!(
            stderr(&refused).contains("invalid role name"),
            "{role:?}: {}",
            stderr(&refused)
        );
    }
    assert_eq!(
        acls(&fixture.pool).await,
        before,
        "a refused role name granted something"
    );
    let tools: Option<String> = sqlx::query_scalar("SELECT to_regclass('public.mcp_tools')::text")
        .fetch_one(&fixture.pool)
        .await
        .expect("to_regclass");
    assert!(tools.is_some(), "the injection attempt reached the server");

    // A well-formed role that was never created is refused too: this grants to a role, it does
    // not create one.
    let absent = unique("mcp_cli_absent");
    let refused = run(
        &[
            "--grant-runtime-role",
            "--role",
            absent.as_str(),
            "--url",
            url,
        ],
        &[],
        url,
    );
    assert!(!refused.status.success(), "an absent role must be refused");
    assert!(
        stderr(&refused).contains("does not exist"),
        "{}",
        stderr(&refused)
    );
    fixture.finish(&[]).await;
}

/// The three operator actions are mutually exclusive (one clap `action` group): the initContainer
/// runs them as three separate invocations, so a combined call must be refused by the parser
/// rather than silently running only the first action it sees.
#[test]
fn the_operator_actions_are_mutually_exclusive() {
    let out = run(
        &["--adopt-schema", "--seed-platform", "/app/toolkits"],
        &[],
        "postgres://unused",
    );
    assert!(!out.status.success(), "{}", stdout(&out));
    let err = stderr(&out);
    assert!(err.contains("cannot be used with"), "{err}");
}
