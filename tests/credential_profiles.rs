//! The three `/mcp/credential-profiles` operations against the real router and a real
//! Postgres 18: create (201), replace by expected revision (200) and validate (200).
//!
//! Every success asserts the reference's response BODY field by field (the parity gate cannot
//! see bodies) and the rows the write leaves in `mcp_credential_profiles` and
//! `mcp_credential_refs`; every refusal renders the reference's `{"error": …}` with
//! `Cache-Control: no-store`. The real-server fixture harness lives in `tests/support`.

mod support;

use axum::http::{Method, StatusCode};
use serde_json::{Value, json};
use sqlx::Row;

use support::{
    Fixture, GATEWAY_APP_KEY, LICENCE_ID, TENANT_A, actor_snapshot, assert_no_store, management,
    send,
};

const PROFILE: &str = "01900000-0000-7000-8000-0000000000c1";
const OTHER_PROFILE: &str = "01900000-0000-7000-8000-0000000000c2";
const OTHER_TENANT: &str = "10000000-0000-7000-8000-000000000002";
const PROFILE_NAME: &str = "synthetic_profile";

fn reference(service: &str, alias: &str) -> Value {
    json!({
        "service": service,
        "alias": alias,
        "license_id": LICENCE_ID,
        "app_key": GATEWAY_APP_KEY,
        "bundle": null
    })
}

fn services(entries: &[(&str, &str)]) -> Value {
    Value::Array(
        entries
            .iter()
            .map(|(service, alias)| reference(service, alias))
            .collect(),
    )
}

fn profile_body(profile: &str, name: &str, services: Value) -> Value {
    json!({
        "schema_version": 1,
        "profile_id": profile,
        "tenant_id": TENANT_A,
        "name": name,
        "gateway": reference("gateway", "gateway"),
        "services": services
    })
}

fn update_body(profile: &str, name: &str, services: Value, expected: u32) -> Value {
    json!({
        "expected_revision": expected,
        "profile": profile_body(profile, name, services)
    })
}

async fn create_profile(app: &axum::Router, services: Value) -> Value {
    let (status, headers, body) = send(
        app,
        management(
            Method::POST,
            "/mcp/credential-profiles",
            Some(profile_body(PROFILE, PROFILE_NAME, services)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_no_store(&headers);
    body
}

#[tokio::test]
async fn create_stores_the_manifest_and_its_reference_rows() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let stored = services(&[("synthetic_service", "synthetic")]);

    let body = create_profile(&app, stored.clone()).await;
    assert_eq!(
        body,
        json!({
            "profile": profile_body(PROFILE, PROFILE_NAME, stored),
            "revision": 1,
            "credentials_verified": false
        })
    );

    let row = sqlx::query(
        "SELECT name, revision, manifest FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_one(&fixture.pool)
    .await
    .expect("stored profile");
    assert_eq!(
        row.try_get::<String, _>("name").expect("name"),
        PROFILE_NAME
    );
    assert_eq!(row.try_get::<i64, _>("revision").expect("revision"), 1);
    assert_eq!(
        row.try_get::<Value, _>("manifest").expect("manifest"),
        profile_body(
            PROFILE,
            PROFILE_NAME,
            services(&[("synthetic_service", "synthetic")])
        )
    );

    let references = sqlx::query(
        "SELECT service_key, alias, license_id::text AS license_id, app_key \
         FROM public.mcp_credential_refs \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid ORDER BY service_key",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_all(&fixture.pool)
    .await
    .expect("stored references");
    let rows: Vec<(String, String, String, String)> = references
        .iter()
        .map(|row| {
            (
                row.try_get("service_key").expect("service key"),
                row.try_get("alias").expect("alias"),
                row.try_get("license_id").expect("licence"),
                row.try_get("app_key").expect("app key"),
            )
        })
        .collect();
    assert_eq!(
        rows,
        vec![
            (
                "__gateway".to_owned(),
                "gateway".to_owned(),
                LICENCE_ID.to_owned(),
                GATEWAY_APP_KEY.to_owned(),
            ),
            (
                "synthetic_service".to_owned(),
                "synthetic".to_owned(),
                LICENCE_ID.to_owned(),
                GATEWAY_APP_KEY.to_owned(),
            ),
        ]
    );

    fixture.finish().await;
}

#[tokio::test]
async fn update_replaces_the_references_and_bumps_the_revision() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let created = create_profile(&app, services(&[("synthetic_service", "synthetic")])).await;
    assert_eq!(created["revision"], json!(1));

    let replaced = services(&[("billing", "billing")]);
    let (status, headers, body) = send(
        &app,
        management(
            Method::PUT,
            &format!("/mcp/credential-profiles/{PROFILE}"),
            Some(update_body(PROFILE, PROFILE_NAME, replaced.clone(), 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_store(&headers);
    assert_eq!(
        body,
        json!({
            "profile": profile_body(PROFILE, PROFILE_NAME, replaced),
            "revision": 2,
            "credentials_verified": false
        })
    );

    let revision: i64 = sqlx::query_scalar(
        "SELECT revision FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_one(&fixture.pool)
    .await
    .expect("stored revision");
    assert_eq!(revision, 2);

    let mut keys: Vec<String> = sqlx::query_scalar(
        "SELECT service_key FROM public.mcp_credential_refs \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_all(&fixture.pool)
    .await
    .expect("stored references");
    // Compared as a set: the database's collation decides `ORDER BY` between `_` and `b`, and
    // the local cluster and CI need not share one.
    keys.sort();
    assert_eq!(keys, vec!["__gateway".to_owned(), "billing".to_owned()]);

    let actions: Vec<String> = sqlx::query_scalar(
        "SELECT action FROM public.mcp_access_events \
         WHERE tenant_id = $1::uuid AND entity_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_all(&fixture.pool)
    .await
    .expect("audit rows");
    assert_eq!(actions.len(), 2);
    assert!(
        actions
            .iter()
            .all(|action| action == "credential_profile.changed"),
        "{actions:?}"
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_stale_expected_revision_is_refused() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let current = services(&[("synthetic_service", "synthetic")]);
    create_profile(&app, current.clone()).await;
    let (status, _, body) = send(
        &app,
        management(
            Method::PUT,
            &format!("/mcp/credential-profiles/{PROFILE}"),
            Some(update_body(PROFILE, PROFILE_NAME, current.clone(), 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // Revision 1 was consumed by the successful update: the caller's read is stale.
    let (status, headers, body) = send(
        &app,
        management(
            Method::PUT,
            &format!("/mcp/credential-profiles/{PROFILE}"),
            Some(update_body(PROFILE, PROFILE_NAME, current, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "revision_or_lifecycle_conflict"}));

    fixture.finish().await;
}

#[tokio::test]
async fn a_profile_name_is_immutable() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let current = services(&[("synthetic_service", "synthetic")]);
    create_profile(&app, current.clone()).await;

    let (status, headers, body) = send(
        &app,
        management(
            Method::PUT,
            &format!("/mcp/credential-profiles/{PROFILE}"),
            Some(update_body(PROFILE, "renamed_profile", current, 1)),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "invalid_request"}));

    let row = sqlx::query(
        "SELECT name, revision FROM public.mcp_credential_profiles \
         WHERE tenant_id = $1::uuid AND profile_id = $2::uuid",
    )
    .bind(TENANT_A)
    .bind(PROFILE)
    .fetch_one(&fixture.pool)
    .await
    .expect("stored profile");
    assert_eq!(
        row.try_get::<String, _>("name").expect("name"),
        PROFILE_NAME
    );
    assert_eq!(row.try_get::<i64, _>("revision").expect("revision"), 1);

    fixture.finish().await;
}

#[tokio::test]
async fn another_tenants_profile_is_not_found() {
    let fixture = Fixture::new().await;
    insert_foreign_profile(&fixture).await;
    let app = fixture.app();

    // The caller names its own tenant in the profile and a foreign identity in the path: the
    // identity namespace is tenant-scoped, so the row is simply not there.
    let (status, headers, body) = send(
        &app,
        management(
            Method::PUT,
            &format!("/mcp/credential-profiles/{OTHER_PROFILE}"),
            Some(update_body(
                OTHER_PROFILE,
                "foreign_profile",
                services(&[]),
                1,
            )),
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "not_found"}));

    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/credential-profiles/{OTHER_PROFILE}/validate"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "not_found"}));

    fixture.finish().await;
}

#[tokio::test]
async fn validate_reports_the_stored_revision() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    create_profile(&app, services(&[("synthetic_service", "synthetic")])).await;

    let (status, headers, body) = send(
        &app,
        management(
            Method::POST,
            &format!("/mcp/credential-profiles/{PROFILE}/validate"),
            None,
        ),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_no_store(&headers);
    assert_eq!(
        body,
        json!({
            "profile_id": PROFILE,
            "revision": 1,
            "metadata_valid": true,
            "credentials_verified": false
        })
    );

    fixture.finish().await;
}

#[tokio::test]
async fn a_gateway_reference_must_name_the_configured_application() {
    let fixture = Fixture::new().await;
    let app = fixture.app();
    let mut body = profile_body(PROFILE, PROFILE_NAME, services(&[]));
    body["gateway"]["app_key"] = json!("other-app");

    let (status, headers, body) = send(
        &app,
        management(Method::POST, "/mcp/credential-profiles", Some(body)),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "invalid_request"}));

    let profiles: i64 = sqlx::query_scalar("SELECT count(*) FROM public.mcp_credential_profiles")
        .fetch_one(&fixture.pool)
        .await
        .expect("profile count");
    assert_eq!(profiles, 0);

    fixture.finish().await;
}

/// One stored profile owned by another tenant: the completeness trigger is deferred to commit,
/// so the row and its one (`__gateway`) reference land in one transaction.
async fn insert_foreign_profile(fixture: &Fixture) {
    let manifest = json!({
        "schema_version": 1,
        "profile_id": OTHER_PROFILE,
        "tenant_id": OTHER_TENANT,
        "name": "foreign_profile",
        "gateway": reference("gateway", "gateway"),
        "services": []
    });
    let mut transaction = fixture.pool.begin().await.expect("transaction");
    sqlx::query(
        "INSERT INTO public.mcp_credential_profiles(\
         tenant_id,profile_id,name,manifest,created_by,updated_by) \
         VALUES ($1::uuid,$2::uuid,$3,$4,$5,$5)",
    )
    .bind(OTHER_TENANT)
    .bind(OTHER_PROFILE)
    .bind("foreign_profile")
    .bind(&manifest)
    .bind(actor_snapshot())
    .execute(&mut *transaction)
    .await
    .expect("foreign profile");
    sqlx::query(
        "INSERT INTO public.mcp_credential_refs(\
         tenant_id,profile_id,service_key,alias,license_id,app_key) \
         VALUES ($1::uuid,$2::uuid,'__gateway','gateway',$3::uuid,$4)",
    )
    .bind(OTHER_TENANT)
    .bind(OTHER_PROFILE)
    .bind(LICENCE_ID)
    .bind(GATEWAY_APP_KEY)
    .execute(&mut *transaction)
    .await
    .expect("foreign gateway reference");
    transaction.commit().await.expect("commit foreign profile");
}
