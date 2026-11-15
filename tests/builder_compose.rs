//! The API binary's builder composition, over the deployment's own settings.
//!
//! `MCP_BUILDER_ENABLED=true` used to refuse startup. These tests build the service from a
//! `Config` parsed by the same code the binary uses, over a lazy pool (composition performs no
//! I/O), and assert that the ENABLED runtime is what gets installed — and that the settings it
//! reads are the ones the environment provides.

use std::collections::HashMap;
use std::time::Duration;

use sqlx::postgres::PgPoolOptions;

use mcp_server_rs::AppState;
use mcp_server_rs::auth::{Auth, AuthConfig, Rfc4122Uuid};
use mcp_server_rs::builder::compose;
use mcp_server_rs::config::Config;
use mcp_server_rs::routes::builder::BuilderRuntime;

/// A 32-byte zero key in unpadded base64url: a valid `MCP_SOURCE_SECRET_KEY`.
const SOURCE_KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

fn config(overrides: &[(&str, &str)]) -> Config {
    let mut environment: HashMap<&str, String> = HashMap::from([
        (
            "DATABASE_URL",
            "postgres://mcp:mcp@127.0.0.1:1/mcp".to_owned(),
        ),
        ("BIND_ADDR", "127.0.0.1:8099".to_owned()),
        ("MCP_BUILDER_ENABLED", "true".to_owned()),
        ("MCP_LICENSE_APP_KEY", "mcp".to_owned()),
        ("MCP_SOURCE_SECRET_KEY", SOURCE_KEY.to_owned()),
        ("MCP_SOURCE_ALLOWED_HOSTS", "api.example.test".to_owned()),
    ]);
    for (key, value) in overrides {
        environment.insert(key, (*value).to_owned());
    }
    Config::from_lookup(|key| environment.get(key).cloned()).expect("the deployment settings")
}

fn state() -> AppState {
    AppState {
        pool: PgPoolOptions::new()
            .connect_lazy("postgres://mcp:mcp@127.0.0.1:1/mcp")
            .expect("lazy pool"),
        execution_enabled: true,
        license_app_key: Some("mcp".to_owned()),
        approved_runner_images: vec![
            "registry.example/runner@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                .to_owned(),
        ],
        platform_tenant_id: Rfc4122Uuid::parse("01900000-0000-7000-8000-00000000f001")
            .expect("platform tenant"),
        catalog_page_size: 10,
        platform: None,
        sources: mcp_server_rs::config::SourceSettings::default(),
        execution: mcp_server_rs::config::ExecutionSettings::default(),
    }
}

#[tokio::test]
async fn the_enabled_builder_installs_over_the_deployment_settings() {
    let config = config(&[]);
    let auth_config = AuthConfig::default();
    let auth = Auth::from_config(&auth_config).expect("the authentication settings");
    let state = state();

    let runtime = compose::runtime(&config, &auth_config, &auth, &state)
        .expect("the builder runtime composes");
    assert!(
        runtime.installed(),
        "MCP_BUILDER_ENABLED=true installs the service"
    );
    assert!(
        runtime.service_handle().is_some(),
        "the installed service rides to the builder builtin family"
    );
    assert!(
        !BuilderRuntime::disabled(&state, &auth).installed(),
        "the disabled runtime stays the 404 one"
    );
    assert!(
        BuilderRuntime::disabled(&state, &auth)
            .service_handle()
            .is_none(),
        "a disabled builder registers no builder tools"
    );
}

#[test]
fn the_builder_reads_the_documented_worker_settings_from_the_same_environment() {
    let config = config(&[
        ("MCP_BUILDER_OAUTH_TOKEN_MAX_TTL", "7200"),
        ("MCP_RUN_MAX_SECONDS", "120"),
        ("MCP_MAX_API_CALLS_PER_RUN", "25"),
    ]);
    assert_eq!(
        config.builder.oauth_token_max_ttl,
        Duration::from_secs(7200)
    );
    assert_eq!(config.builder.run_max, Duration::from_secs(120));
    assert_eq!(config.builder.max_api_calls_per_run, 25);
    assert_eq!(config.sources.secret_key_text.as_deref(), Some(SOURCE_KEY));
    assert!(config.sources.secret_key.is_some());
}

#[test]
fn an_enabled_builder_without_a_licence_app_key_is_refused() {
    let environment: HashMap<&str, String> = HashMap::from([
        (
            "DATABASE_URL",
            "postgres://mcp:mcp@127.0.0.1:1/mcp".to_owned(),
        ),
        ("BIND_ADDR", "127.0.0.1:8099".to_owned()),
        ("MCP_BUILDER_ENABLED", "true".to_owned()),
    ]);
    let refused = Config::from_lookup(|key| environment.get(key).cloned());
    assert!(
        refused.is_err(),
        "a builder that is on has no way to admit a draft run without the key"
    );
}
