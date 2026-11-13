//! Migrations against a real Postgres 18.
//!
//! Server selection (the estate's test-DB standard): `TEST_DATABASE_URL`, else `DATABASE_URL`
//! (a URL whose user may CREATE DATABASE), else an ephemeral `postgres:18` container started
//! here with docker and removed afterwards, else FAIL (never skip). `TEST_PG_REGISTRY` may name
//! a registry mirror to pull the image from when the default is not reachable.
//! Each run gets its own fresh database, dropped at the end.

use std::process::Command;
use std::str::FromStr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection, PgConnection};

use mcp_server_rs::db;

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
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.trim().is_empty())
}

async fn server() -> Server {
    if let Some(url) = env_url() {
        return Server {
            url,
            container: None,
        };
    }
    let image = match std::env::var("TEST_PG_REGISTRY") {
        Ok(r) if !r.trim().is_empty() => format!("{}/postgres:18", r.trim_end_matches('/')),
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
        .and_then(|l| l.rsplit(':').next())
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .unwrap_or_else(|| panic!("no published port for {id}: {mapping:?}"))
        .to_owned();
    srv.url = format!("postgres://postgres:postgres@127.0.0.1:{port}/postgres");

    // The image's init-time server listens on the unix socket only, so the first TCP
    // connection that succeeds is the final server.
    let deadline = Instant::now() + Duration::from_secs(90);
    loop {
        match PgConnection::connect(&srv.url).await {
            Ok(c) => {
                let _ = c.close().await;
                break;
            }
            Err(e) if Instant::now() > deadline => panic!("postgres never became ready: {e}"),
            Err(_) => tokio::time::sleep(Duration::from_millis(300)).await,
        }
    }
    srv
}

#[tokio::test]
async fn migrations_apply_and_are_idempotent() {
    let srv = server().await;
    let admin_opts = PgConnectOptions::from_str(&srv.url).expect("parse database url");
    let mut admin = PgConnection::connect_with(&admin_opts)
        .await
        .expect("connect");

    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let name = format!("tmpl_migrate_{}_{nanos}", std::process::id());
    sqlx::query(AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
        .execute(&mut admin)
        .await
        .expect("create test database");

    let pool = PgPoolOptions::new()
        .max_connections(2)
        .connect_with(admin_opts.clone().database(&name))
        .await
        .expect("connect test database");
    db::migrate(&pool).await.expect("first migrate");
    db::migrate(&pool).await.expect("second migrate is a no-op");

    let applied: i64 = sqlx::query_scalar("SELECT count(*) FROM _sqlx_migrations WHERE success")
        .fetch_one(&pool)
        .await
        .expect("read _sqlx_migrations");
    let embedded = db::MIGRATOR.iter().count();
    assert!(embedded >= 1, "no migrations embedded");
    assert_eq!(applied, i64::try_from(embedded).unwrap());

    let server_version: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(&pool)
            .await
            .unwrap();
    assert!(
        server_version >= 180_000,
        "need Postgres 18, got {server_version}"
    );

    pool.close().await;
    sqlx::query(AssertSqlSafe(format!(
        "DROP DATABASE \"{name}\" WITH (FORCE)"
    )))
    .execute(&mut admin)
    .await
    .expect("drop test database");
}
