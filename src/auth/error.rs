//! The authentication layer's own error responses.
//!
//! These bodies are the reference service's middleware contract and are deliberately NOT the
//! `{"detail": ...}` shape `crate::error::AppError` renders for the REST surface: a `/mcp`
//! caller sees `{"error": ...}` with `Cache-Control: no-store`, plus `WWW-Authenticate: Bearer`
//! on 401.

use axum::Json;
use axum::http::header::{CACHE_CONTROL, WWW_AUTHENTICATE};
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde_json::json;

/// Why authentication/authorisation of a `/mcp` request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    /// Invalid or missing credential (401).
    #[error("unauthorized")]
    Unauthorized,
    /// Authenticated, but this credential may not use this path or resource (403).
    #[error("forbidden")]
    Forbidden,
    /// The licence/binding authority cannot currently be verified; fail closed (503).
    #[error("authority unavailable")]
    Unavailable,
    /// The management request body exceeded `MCP_MAX_MANAGEMENT_BYTES` (413).
    #[error("request too large")]
    TooLarge,
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        let (status, body) = match self {
            Self::Unauthorized => (StatusCode::UNAUTHORIZED, json!({ "error": "unauthorized" })),
            Self::Forbidden => (StatusCode::FORBIDDEN, json!({ "error": "forbidden" })),
            Self::Unavailable => (
                StatusCode::SERVICE_UNAVAILABLE,
                json!({ "error": "authority_unavailable" }),
            ),
            Self::TooLarge => (
                StatusCode::PAYLOAD_TOO_LARGE,
                json!({ "error": "request_too_large" }),
            ),
        };
        let mut response = (status, Json(body)).into_response();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
        if self == Self::Unauthorized {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
        }
        response
    }
}
