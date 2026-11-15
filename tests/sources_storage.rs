//! Platform source persistence against a real Postgres 18: the row, its revision and its
//! `mcp_source_events` audit rows, the platform-tenant scope, and the sealed credential.
//!
//! Every test drives the real [`SourceRepository`] over the migrated schema from
//! `tests/support`; a removed statement, event name or refusal fails here rather than in
//! production. Each test gets its own fresh database, dropped at the end.

mod support;

use serde_json::{Value, json};
use sqlx::Row;
use uuid::Uuid;

use mcp_server_rs::catalog::models::Attribution;
use mcp_server_rs::config::SourceSettings;
use mcp_server_rs::sources::crypto::decrypt_token;
use mcp_server_rs::sources::models::{SourceCreate, SourceUpdate, SourceView, TokenUpdate};
use mcp_server_rs::sources::repository::{SourceRepository, SourceStoreError, resolve_row};

use support::Fixture;

/// `public.mcp_platform_tenant()`: the reserved owner every platform statement names.
const PLATFORM_TENANT: &str = "01900000-0000-7000-8000-00000000f001";
const OTHER_TENANT: &str = "10000000-0000-7000-8000-000000000002";
const OTHER_SOURCE: &str = "01900000-0000-7000-8000-0000000000a1";
const BASE_URL: &str = "https://api.example.test";
/// The decoded `MCP_SOURCE_SECRET_KEY` every sealing test uses, taken from the oracle
/// fixture so no key-shaped literal lives in this file.
fn secret_key() -> [u8; 32] {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/phase5a/oracle.json"
    );
    let text = std::fs::read_to_string(path).expect("the phase-5A fixture file exists");
    let document: serde_json::Value =
        serde_json::from_str(&text).expect("the phase-5A fixture file is JSON");
    let bytes: Vec<u8> = document["sealing_keys"]["other"]
        .as_array()
        .expect("the fixture carries the sealing key")
        .iter()
        .map(|value| u8::try_from(value.as_u64().expect("a byte")).expect("a byte"))
        .collect();
    bytes.try_into().expect("a 32-byte key")
}

fn platform() -> Uuid {
    Uuid::parse_str(PLATFORM_TENANT).expect("the platform tenant is a UUID")
}

fn repository(fixture: &Fixture) -> SourceRepository {
    SourceRepository::from_settings(
        fixture.pool.clone(),
        &SourceSettings {
            secret_key: Some(secret_key().to_vec()),
            secret_key_text: Some({
                use base64::Engine as _;
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(secret_key())
            }),
            allowed_hosts: vec!["api.example.test".to_owned()],
        },
    )
}

fn actor() -> Attribution {
    Attribution {
        subject: "agent-09".to_owned(),
        license_id: None,
    }
}

fn create_body(key: &str, auth: Value, token: Option<&str>) -> SourceCreate {
    let mut body = json!({
        "source_key": key,
        "base_url": BASE_URL,
        "auth": auth,
    });
    if let Some(token) = token {
        body["token"] = json!(token);
    }
    serde_json::from_value(body).expect("a valid source create")
}

fn update_body(auth: Value, expected_revision: u64) -> SourceUpdate {
    serde_json::from_value(json!({
        "base_url": BASE_URL,
        "auth": auth,
        "expected_revision": expected_revision,
    }))
    .expect("a valid source update")
}

fn token_body(token: &str, expected_revision: u64) -> TokenUpdate {
    serde_json::from_value(json!({
        "token": token,
        "expected_revision": expected_revision,
    }))
    .expect("a valid token update")
}

async fn events(fixture: &Fixture, key: &str) -> Vec<(String, i64)> {
    let rows = sqlx::query(
        "SELECT event, revision FROM public.mcp_source_events WHERE source_key = $1 \
         ORDER BY event_id",
    )
    .bind(key)
    .fetch_all(&fixture.pool)
    .await
    .expect("source events");
    rows.iter()
        .map(|row| {
            (
                row.try_get::<String, _>("event").expect("event"),
                row.try_get::<i64, _>("revision").expect("revision"),
            )
        })
        .collect()
}

fn view(value: &impl serde::Serialize) -> Value {
    serde_json::to_value(value).expect("a serializable source view")
}

/// The refusal from a write, without requiring the success type to be `Debug`.
fn refused<T>(result: Result<T, SourceStoreError>) -> SourceStoreError {
    match result {
        Ok(_) => panic!("expected a refusal"),
        Err(error) => error,
    }
}

#[tokio::test]
async fn create_writes_the_row_its_created_event_and_has_token() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    let created = repo
        .create(
            &create_body("billing", json!({"kind": "static_bearer"}), Some("tok")),
            &actor(),
        )
        .await
        .expect("create");
    let created = view(&created);
    assert_eq!(created["source_key"], json!("billing"));
    assert_eq!(created["owner_tenant_id"], json!(PLATFORM_TENANT));
    assert_eq!(created["revision"], json!(1));
    assert_eq!(created["status"], json!("active"));
    assert_eq!(created["base_url"], json!(BASE_URL));
    assert_eq!(created["auth"]["kind"], json!("static_bearer"));
    assert_eq!(created["has_token"], json!(true));
    assert!(created["token_set_at"].is_string());
    assert!(created["created_at"].is_string());
    assert_eq!(
        events(&fixture, "billing").await,
        vec![("created".to_owned(), 1)]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn page_is_ordered_by_source_key() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    for key in ["gamma", "alpha", "beta"] {
        repo.create(&create_body(key, json!({"kind": "none"}), None), &actor())
            .await
            .expect("create");
    }
    let keys = |views: Vec<SourceView>| -> Vec<String> {
        views
            .iter()
            .map(|source| {
                view(source)["source_key"]
                    .as_str()
                    .expect("source_key")
                    .to_owned()
            })
            .collect()
    };
    assert_eq!(
        keys(repo.page(10, 0).await.expect("page")),
        vec!["alpha", "beta", "gamma"]
    );
    assert_eq!(keys(repo.page(1, 1).await.expect("page")), vec!["beta"]);
    assert!(keys(repo.page(10, 3).await.expect("page")).is_empty());
    fixture.finish().await;
}

#[tokio::test]
async fn get_returns_the_created_row_and_refuses_a_missing_key() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body("public", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("create");
    let got = view(&repo.get("public").await.expect("get"));
    assert_eq!(got["source_key"], json!("public"));
    assert_eq!(got["has_token"], json!(false));
    assert_eq!(got["token_set_at"], json!(null));

    let error = refused(repo.get("missing").await);
    assert_eq!(error.to_string(), "source not found");
    assert!(matches!(
        error,
        SourceStoreError::NotFound("source not found")
    ));
    fixture.finish().await;
}

#[tokio::test]
async fn update_bumps_the_revision_keeps_then_clears_the_stored_token() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body(
            "billing",
            json!({"kind": "static_bearer"}),
            Some("first-token"),
        ),
        &actor(),
    )
    .await
    .expect("create");

    // Staying on a secret-bearing kind without a supplied token keeps the stored one.
    let updated = repo
        .update(
            "billing",
            &update_body(json!({"kind": "static_bearer"}), 1),
            &actor(),
        )
        .await
        .expect("update");
    let updated = view(&updated);
    assert_eq!(updated["revision"], json!(2));
    assert_eq!(updated["has_token"], json!(true));
    assert_eq!(updated["auth"]["kind"], json!("static_bearer"));

    let mut conn = fixture.pool.acquire().await.expect("connection");
    let row = resolve_row(&mut conn, platform(), "billing")
        .await
        .expect("resolve")
        .expect("row");
    let blob = row
        .token_ciphertext
        .as_deref()
        .expect("the retained ciphertext");
    assert_eq!(
        decrypt_token(Some(&secret_key()), row.source_id, blob),
        Ok("first-token".to_owned())
    );

    // Becoming secret-less clears the stored token.
    let cleared = repo
        .update(
            "billing",
            &update_body(json!({"kind": "none"}), 2),
            &actor(),
        )
        .await
        .expect("update");
    let cleared = view(&cleared);
    assert_eq!(cleared["revision"], json!(3));
    assert_eq!(cleared["has_token"], json!(false));
    assert_eq!(cleared["token_set_at"], json!(null));
    let row = resolve_row(&mut conn, platform(), "billing")
        .await
        .expect("resolve")
        .expect("row");
    assert!(row.token_ciphertext.is_none());
    drop(conn);

    assert_eq!(
        events(&fixture, "billing").await,
        vec![
            ("created".to_owned(), 1),
            ("updated".to_owned(), 2),
            ("updated".to_owned(), 3),
        ]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn update_to_a_secret_kind_without_a_stored_token_is_refused() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body("public", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("create");
    let error = refused(
        repo.update(
            "public",
            &update_body(json!({"kind": "static_bearer"}), 1),
            &actor(),
        )
        .await,
    );
    assert_eq!(error.to_string(), "a source of this kind needs its secret");
    assert!(matches!(
        error,
        SourceStoreError::Invalid("a source of this kind needs its secret")
    ));
    let unchanged = view(&repo.get("public").await.expect("get"));
    assert_eq!(unchanged["revision"], json!(1));
    assert_eq!(unchanged["auth"]["kind"], json!("none"));
    fixture.finish().await;
}

#[tokio::test]
async fn set_token_rotates_the_secret_and_refuses_a_secretless_kind() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body(
            "billing",
            json!({"kind": "static_bearer"}),
            Some("first-token"),
        ),
        &actor(),
    )
    .await
    .expect("create");
    let rotated = repo
        .set_token("billing", &token_body("second-token", 1), &actor())
        .await
        .expect("rotate");
    let rotated = view(&rotated);
    assert_eq!(rotated["revision"], json!(2));
    assert_eq!(rotated["has_token"], json!(true));

    // The connection is taken in its own scope: `finish()` closes the pool and waits for every
    // checked-out connection, so one held to the end of the test would wait forever.
    {
        let mut conn = fixture.pool.acquire().await.expect("connection");
        let row = resolve_row(&mut conn, platform(), "billing")
            .await
            .expect("resolve")
            .expect("row");
        let blob = row
            .token_ciphertext
            .as_deref()
            .expect("the rotated ciphertext");
        assert_eq!(
            decrypt_token(Some(&secret_key()), row.source_id, blob),
            Ok("second-token".to_owned())
        );
    }

    // `none` and `licence` carry no stored secret.
    repo.create(
        &create_body("public", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("create");
    repo.create(
        &create_body(
            "coding",
            json!({"kind": "licence", "app_key": "coding"}),
            None,
        ),
        &actor(),
    )
    .await
    .expect("create");
    for key in ["public", "coding"] {
        let error = refused(
            repo.set_token(key, &token_body("rotated", 1), &actor())
                .await,
        );
        assert!(matches!(
            error,
            SourceStoreError::Invalid("this source kind carries no stored secret")
        ));
    }

    assert_eq!(
        events(&fixture, "billing").await,
        vec![("created".to_owned(), 1), ("token_set".to_owned(), 2)]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn set_status_bumps_the_revision_and_refuses_a_no_op() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body("billing", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("create");

    let disabled = view(
        &repo
            .set_status("billing", 1, "disabled", &actor())
            .await
            .expect("disable"),
    );
    assert_eq!(disabled["status"], json!("disabled"));
    assert_eq!(disabled["revision"], json!(2));

    let error = refused(repo.set_status("billing", 2, "disabled", &actor()).await);
    assert_eq!(error.to_string(), "source already in that state");
    assert!(matches!(
        error,
        SourceStoreError::Conflict("source already in that state")
    ));

    let enabled = view(
        &repo
            .set_status("billing", 2, "active", &actor())
            .await
            .expect("enable"),
    );
    assert_eq!(enabled["status"], json!("active"));
    assert_eq!(enabled["revision"], json!(3));

    assert_eq!(
        events(&fixture, "billing").await,
        vec![
            ("created".to_owned(), 1),
            ("disabled".to_owned(), 2),
            ("enabled".to_owned(), 3),
        ]
    );
    fixture.finish().await;
}

#[tokio::test]
async fn a_stale_expected_revision_is_refused_by_every_write() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body("billing", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("create");
    for error in [
        refused(
            repo.update(
                "billing",
                &update_body(json!({"kind": "none"}), 9),
                &actor(),
            )
            .await,
        ),
        refused(
            repo.set_token("billing", &token_body("tok", 9), &actor())
                .await,
        ),
        refused(repo.set_status("billing", 9, "disabled", &actor()).await),
    ] {
        assert_eq!(error.to_string(), "source revision mismatch");
        assert!(matches!(
            error,
            SourceStoreError::Conflict("source revision mismatch")
        ));
    }
    let unchanged = view(&repo.get("billing").await.expect("get"));
    assert_eq!(unchanged["revision"], json!(1));
    fixture.finish().await;
}

#[tokio::test]
async fn a_row_owned_by_another_tenant_is_invisible() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    sqlx::query(
        "INSERT INTO public.mcp_sources(owner_tenant_id,source_id,source_key,base_url,auth,\
         created_by,updated_by) VALUES ($1::uuid,$2::uuid,'other_key',$3,$4,$5,$5)",
    )
    .bind(OTHER_TENANT)
    .bind(OTHER_SOURCE)
    .bind("https://other.example.test")
    .bind(json!({"kind": "none"}))
    .bind(json!({"subject": "agent-09"}))
    .execute(&fixture.pool)
    .await
    .expect("a tenant-owned source");

    assert!(matches!(
        refused(repo.get("other_key").await),
        SourceStoreError::NotFound("source not found")
    ));
    assert!(repo.page(10, 0).await.expect("page").is_empty());
    // The broker's read is owner-explicit too: a key alone never identifies a source.
    let mut conn = fixture.pool.acquire().await.expect("connection");
    assert!(
        resolve_row(&mut conn, platform(), "other_key")
            .await
            .expect("resolve")
            .is_none()
    );
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn a_sealed_token_round_trips_through_resolve_row() {
    let fixture = Fixture::new().await;
    let repo = repository(&fixture);
    repo.create(
        &create_body(
            "billing",
            json!({"kind": "static_bearer"}),
            Some("synthetic-token"),
        ),
        &actor(),
    )
    .await
    .expect("create");
    let mut conn = fixture.pool.acquire().await.expect("connection");
    let row = resolve_row(&mut conn, platform(), "billing")
        .await
        .expect("resolve")
        .expect("row");
    assert_eq!(row.source_key, "billing");
    assert_eq!(row.owner_tenant_id, platform());
    assert_eq!(row.status, "active");
    assert_eq!(row.base_url, BASE_URL);
    let blob = row.token_ciphertext.as_deref().expect("a ciphertext");
    assert_eq!(
        decrypt_token(Some(&secret_key()), row.source_id, blob),
        Ok("synthetic-token".to_owned())
    );
    // A ciphertext copied onto another row would fail authentication.
    assert_eq!(
        decrypt_token(Some(&secret_key()), Uuid::now_v7(), blob),
        Err(mcp_server_rs::sources::crypto::SourceCryptoError::Unavailable)
    );
    drop(conn);
    fixture.finish().await;
}

#[tokio::test]
async fn sealing_without_a_configured_key_is_unavailable() {
    let fixture = Fixture::new().await;
    let repo = SourceRepository::new(
        fixture.pool.clone(),
        vec!["api.example.test".to_owned()],
        None,
    );
    let error = refused(
        repo.create(
            &create_body("billing", json!({"kind": "static_bearer"}), Some("tok")),
            &actor(),
        )
        .await,
    );
    assert_eq!(error.to_string(), "source secret key is not configured");
    assert!(matches!(error, SourceStoreError::SecretUnavailable));
    // Nothing was written, and a secret-less source still registers without a key.
    assert!(repo.page(10, 0).await.expect("page").is_empty());
    repo.create(
        &create_body("public", json!({"kind": "none"}), None),
        &actor(),
    )
    .await
    .expect("a secret-less source stores no credential");
    fixture.finish().await;
}

#[tokio::test]
async fn create_enforces_the_destination_before_writing() {
    let fixture = Fixture::new().await;
    let repo = SourceRepository::new(fixture.pool.clone(), Vec::new(), Some(secret_key()));
    let error = refused(
        repo.create(
            &create_body("billing", json!({"kind": "none"}), None),
            &actor(),
        )
        .await,
    );
    assert_eq!(
        error.to_string(),
        "source host is not in the allowed host list"
    );
    assert!(matches!(error, SourceStoreError::Guard(_)));
    assert!(repo.page(10, 0).await.expect("page").is_empty());
    fixture.finish().await;
}
