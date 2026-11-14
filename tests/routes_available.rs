//! The two catalog projection operations against the real router and a real Postgres 18:
//! `GET /mcp/available-tools` and `GET /mcp/bindings/{identity}/effective-tools`.
//!
//! Every success asserts the reference's response BODY field by field (the parity gate cannot
//! see bodies); a caller without binding authority is refused, a stale binding revision and an
//! unavailable tool are refused with the reference's `{"error": …}` and `Cache-Control:
//! no-store`. The router is the real one, behind the real `/mcp` authentication middleware,
//! with the real `PgBindingAuthority` and a deterministic licence authority.
//!
//! The real-server fixture harness lives in `tests/support`; it is shared with `tests/http.rs`
//! so both surfaces are asserted against the same catalog rows.

mod support;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use serde_json::json;

use mcp_server_rs::auth::Rfc4122Uuid;

use support::{
    FixedBindings, Fixture, assert_no_store, binding_fixture, binding_fixture_with_tool,
    binding_request, create_binding, kata_manifest, licence_only, management, projection_body,
    reserved_manifest, send,
};

#[tokio::test]
async fn available_tools_serves_the_reference_public_projection() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let app = fixture.app();
    let created = create_binding(&app).await;
    let token = created["token"].as_str().expect("binding token").to_owned();

    let (status, headers, body) = send(
        &app,
        binding_request(Method::GET, "/mcp/available-tools", &token),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(body, projection_body());
    fixture.finish().await;
}

#[tokio::test]
async fn available_tools_requires_a_binding_and_refuses_a_stale_revision() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let app = fixture.app();
    let created = create_binding(&app).await;
    let binding_id = created["binding"]["binding_id"]
        .as_str()
        .expect("binding identity")
        .to_owned();

    // No binding token: the middleware refuses before the handler runs.
    let (status, headers, body) = send(&app, licence_only("/mcp/available-tools")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "unauthorized"}));

    // A stale revision: the authority read the binding before another client updated it.
    let stale = fixture.app_with_bindings(Arc::new(FixedBindings {
        id: Rfc4122Uuid::parse(&binding_id).expect("binding identity"),
        revision: 0,
    }));
    let (status, headers, body) = send(
        &stale,
        binding_request(Method::GET, "/mcp/available-tools", "stale-token"),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "forbidden"}));
    fixture.finish().await;
}

#[tokio::test]
async fn effective_tools_previews_for_management_and_refuses_a_binding_caller() {
    let fixture = Fixture::new().await;
    binding_fixture(&fixture).await;
    let app = fixture.app();
    let created = create_binding(&app).await;
    let binding_id = created["binding"]["binding_id"]
        .as_str()
        .expect("binding identity")
        .to_owned();
    let token = created["token"].as_str().expect("binding token").to_owned();

    let uri = format!("/mcp/bindings/{binding_id}/effective-tools");
    let (status, headers, body) = send(&app, management(Method::GET, &uri, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_no_store(&headers);
    assert_eq!(body, projection_body());

    // The management path is not a binding path: the middleware demands the operator key.
    let (status, headers, body) = send(&app, binding_request(Method::GET, &uri, &token)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "unauthorized"}));
    fixture.finish().await;
}

#[tokio::test]
async fn a_reserved_public_name_is_unavailable() {
    let fixture = Fixture::new().await;
    // The authoring path refuses a reserved name; a stored manifest can still carry one
    // (an older row, a manual repair), and resolution must refuse to serve it.
    binding_fixture_with_tool(&fixture, &reserved_manifest()).await;
    let app = fixture.app();
    let created = create_binding(&app).await;
    let token = created["token"].as_str().expect("binding token").to_owned();

    let (status, headers, body) = send(
        &app,
        binding_request(Method::GET, "/mcp/available-tools", &token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "forbidden"}));
    fixture.finish().await;
}

#[tokio::test]
async fn a_kata_python_tool_outside_the_approved_images_is_unavailable() {
    let fixture = Fixture::new().await;
    // The approved list is empty in this fixture, so any runner digest must be refused.
    binding_fixture_with_tool(&fixture, &kata_manifest()).await;
    let app = fixture.app();
    let created = create_binding(&app).await;
    let token = created["token"].as_str().expect("binding token").to_owned();

    let (status, headers, body) = send(
        &app,
        binding_request(Method::GET, "/mcp/available-tools", &token),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_no_store(&headers);
    assert_eq!(body, json!({"error": "forbidden"}));
    fixture.finish().await;
}
