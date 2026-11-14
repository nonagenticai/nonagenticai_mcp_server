//! The `/mcp` authentication middleware: the reference service's decision path, ported.
//!
//! Every request whose path is `/mcp` or starts with `/mcp/` passes through here before any
//! router or MCP handler runs — including paths no router knows, so a future route cannot be
//! accidentally anonymous.
//!
//! Two credential kinds exist on this surface:
//!
//! * **management** — `X-Tenant-Id: Bearer <licence>` plus `X-MCP-Admin-Key`; the licence's
//!   tenant must be in the operator allow-list and the key must equal a mounted key file.
//! * **binding** — `X-Tenant-Id: Bearer <tenant-level licence>` (or `Authorization: Bearer` as
//!   the documented off-cluster fallback) plus `X-MCP-Binding`.
//!
//! Deliberately not ported (phase 5, and their observable failure is preserved as 401):
//! Keycloak JWT callers, the builtin care-bus caller, the tool-builder and `/mcp/internal`
//! credential paths. The trusted-header extractor in `crate::tenant` never authorises anything
//! here: a bare `X-Tenant-Id` without the `Bearer` licence prefix is just a malformed licence.

use std::sync::LazyLock;

use axum::extract::{FromRequestParts, Request, State};
use axum::http::HeaderMap;
use axum::http::HeaderValue;
use axum::http::header::CACHE_CONTROL;
use axum::http::request::Parts;
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use regex::Regex;

use super::Auth;
use super::error::AuthError;
use super::principal::Principal;

/// The request carries a resolved principal. Handlers take this extractor; the middleware
/// inserts the value before the inner service runs.
#[derive(Debug, Clone)]
pub struct AuthPrincipal(pub Principal);

impl<S> FromRequestParts<S> for AuthPrincipal
where
    S: Send + Sync,
{
    type Rejection = AuthError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Principal>()
            .cloned()
            .map(AuthPrincipal)
            .ok_or(AuthError::Unauthorized)
    }
}

/// Paths a binding (non-management) caller may use; anything else under `/mcp` is management.
/// The `runs`/`sse`/`messages` prefixes match by prefix exactly like the reference service.
pub fn is_management(path: &str) -> bool {
    !(matches!(
        path,
        "/mcp" | "/mcp/" | "/mcp/sse" | "/mcp/messages" | "/mcp/available-tools"
    ) || path.starts_with("/mcp/runs")
        || path.starts_with("/mcp/sse/")
        || path.starts_with("/mcp/messages/"))
}

fn protected(path: &str) -> bool {
    path == "/mcp" || path.starts_with("/mcp/")
}

/// The middleware body. Mount with
/// `axum::middleware::from_fn_with_state(auth, auth::protect)` after all routes are registered.
pub async fn protect(State(auth): State<Auth>, mut request: Request, next: Next) -> Response {
    let path = request.uri().path().to_owned();
    if !protected(&path) {
        return next.run(request).await;
    }
    // The header map is copied because `Body` is `Send` but not `Sync`: a `&Request` held
    // across an await would make this middleware's future non-`Send`, which axum requires.
    let headers = request.headers().clone();
    let principal = match authorize(&auth, &headers, &path).await {
        Ok(principal) => principal,
        Err(error) => return error.into_response(),
    };
    // Management JSON — and every run request — is read under the size bound before any
    // handler or schema validation sees it; the reference service does the same.
    let buffer = principal.management || path.starts_with("/mcp/runs");
    request.extensions_mut().insert(principal);
    if buffer {
        let (parts, body) = request.into_parts();
        match axum::body::to_bytes(body, auth.max_management_bytes).await {
            Ok(bytes) => request = Request::from_parts(parts, axum::body::Body::from(bytes)),
            Err(_) => return AuthError::TooLarge.into_response(),
        }
    }
    no_store(next.run(request).await)
}

async fn authorize(auth: &Auth, headers: &HeaderMap, path: &str) -> Result<Principal, AuthError> {
    // Operators may reach the whole runs surface with their key: the collection POST is then
    // refused by the route itself (`403 forbidden`, the reference's `PermissionError`), not by
    // the middleware, so a management caller sees 403 rather than 401.
    let operator_runs = (path == "/mcp/runs" || path.starts_with("/mcp/runs/"))
        && headers.contains_key("x-mcp-admin-key");
    let management = is_management(path) || operator_runs;

    let mut gateway = header(headers, "x-tenant-id", 4103)?;
    if !management && !gateway.as_deref().is_some_and(|v| v.starts_with("Bearer ")) {
        // Through the ingress the edge strips the client's X-Tenant-Id, so an off-cluster
        // binding caller sends its tenant licence as Authorization: Bearer instead.
        gateway = header(headers, "authorization", 4103)?;
    }
    let token = gateway
        .as_deref()
        .and_then(|value| value.strip_prefix("Bearer "))
        .filter(|token| !token.is_empty())
        .ok_or(AuthError::Unauthorized)?;

    let admin_key = if management {
        header(headers, "x-mcp-admin-key", 4096)?
    } else {
        None
    };
    let binding_token = if management {
        None
    } else {
        header(headers, "x-mcp-binding", 4096)?
    };
    if (management && admin_key.is_none()) || (!management && binding_token.is_none()) {
        return Err(AuthError::Unauthorized);
    }

    let identity = auth.licences.authenticate(token).await?;
    let principal = if management {
        // Evaluated after the licence, like the reference service: an invalid licence is 401
        // even when the platform header is also malformed.
        let platform_key = header(headers, "x-mcp-platform-admin-key", 4096)?;
        let admin_key = admin_key.as_deref().ok_or(AuthError::Unauthorized)?;
        auth.management
            .authorize(&identity, admin_key, platform_key.as_deref())?
    } else {
        if !identity.tenant_level() {
            return Err(AuthError::Unauthorized);
        }
        let binding_token = binding_token.as_deref().ok_or(AuthError::Unauthorized)?;
        let binding = auth.bindings.authenticate(&identity, binding_token).await?;
        Principal {
            tenant_id: identity.tenant_id,
            license_id: identity.license_id,
            subject: identity.subject,
            binding_id: Some(binding.binding_id),
            binding_revision: Some(binding.revision),
            management: false,
            platform: false,
        }
    };

    if let Some(key) = header(headers, "x-mcp-idempotency-key", 128)?
        && !IDEMPOTENCY_KEY.is_match(&key)
    {
        return Err(AuthError::Unauthorized);
    }
    Ok(principal)
}

/// One header value, printable ASCII, bounded; a leading `Bearer ` prefix is allowed to carry
/// its single space. Duplicates are refused rather than merged.
fn header(
    headers: &HeaderMap,
    name: &'static str,
    maximum: usize,
) -> Result<Option<String>, AuthError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let bytes = value.as_bytes();
    let len = bytes.len();
    let printable = |byte: &u8| (33..=126).contains(byte);
    let valid = (1..=maximum).contains(&len) && bytes.iter().all(printable);
    if !valid {
        let bearer_value = matches!(name, "x-tenant-id" | "authorization")
            && bytes.starts_with(b"Bearer ")
            && len <= maximum
            && bytes[7..].iter().all(printable);
        if !bearer_value {
            return Err(AuthError::Unauthorized);
        }
    }
    String::from_utf8(bytes.to_vec())
        .map(Some)
        .map_err(|_| AuthError::Unauthorized)
}

static IDEMPOTENCY_KEY: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.:-]{1,128}$").expect("static pattern"));

fn no_store(mut response: Response) -> Response {
    response
        .headers_mut()
        .append(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorize_future_is_send() {
        fn assert_send<T: Send>(_: T) {}
        let auth = Auth::from_config(&crate::config::AuthConfig::default()).unwrap();
        let headers = HeaderMap::new();
        assert_send(authorize(&auth, &headers, "/mcp/tools"));
    }

    #[test]
    fn management_partition_matches_the_reference_service() {
        for path in [
            "/mcp",
            "/mcp/",
            "/mcp/sse",
            "/mcp/messages",
            "/mcp/available-tools",
            "/mcp/runs",
            "/mcp/runs/abc",
            "/mcp/sse/abc",
            "/mcp/messages/abc",
            // A literal prefix, exactly like the reference service: `runsx` also matches.
            "/mcp/runsx",
        ] {
            assert!(!is_management(path), "{path}");
        }
        for path in [
            "/mcp/tools",
            "/mcp/toolkits",
            "/mcp/bindings",
            "/mcp/builder",
            "/mcp/internal/tenants",
            "/mcp/unknown",
        ] {
            assert!(is_management(path), "{path}");
        }
        // Only `/mcp` and `/mcp/...` are protected at all.
        assert!(protected("/mcp"));
        assert!(protected("/mcp/x"));
        assert!(!protected("/mcpx"));
        assert!(!protected("/health"));
    }
}
