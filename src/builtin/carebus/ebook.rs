//! ebook tools: namespace `ebook`. `ebook_request` is the website channel's book request: the
//! request itself goes to book-fulfillment and — unless it landed on the waitlist — book-links
//! mints the one-time download link the caller hands back to the reader.

use std::future::Future;
use std::sync::Arc;

use serde_json::{Map, Value, json};

use crate::builtin::{BuiltinProvider, BuiltinTool, boxed};

use super::client::{self, ServiceClient};
use super::{schema, success, text_argument};

/// The request tool's description, read by the model.
const REQUEST_DESCRIPTION: &str = "Request a book: file the request with book-fulfillment and, unless it lands on the waitlist, return the reader's one-time download link.\n\n\
email: the reader's own address, which the request and the link are bound to; never invent one.\n\
language: the edition's language code (default \"en\").\n\
ip: the reader's address when care-bus has it; book-fulfillment records it.";

/// File one book request and, unless it is waitlisted, obtain its download link.
///
/// The production path: [`request_with`] over `client::book_links()` (the env path).
pub async fn request(
    fulfillment: &ServiceClient,
    email: &str,
    language: &str,
    ip: Option<&str>,
) -> Result<Value, String> {
    request_with(fulfillment, client::book_links(), email, language, ip).await
}

/// [`request`] with the link service handed in.
///
/// `BOOK_REQUESTS_URL` is book-fulfillment's full request route, so the client's base IS the
/// endpoint and the request is posted with an empty path; `cf-connecting-ip` rides only when the
/// caller supplies `ip`. A `state: "waitlist"` answer means there is no link yet: `links` is
/// never awaited, so no client is built, no token is minted and no mail is sent. Anything else
/// gets `fresh: true`, and the link is returned to the caller, never logged.
pub async fn request_with(
    fulfillment: &ServiceClient,
    links: impl Future<Output = Result<ServiceClient, String>>,
    email: &str,
    language: &str,
    ip: Option<&str>,
) -> Result<Value, String> {
    let mut body = Map::new();
    body.insert("email".to_owned(), Value::String(email.to_owned()));
    body.insert("language".to_owned(), Value::String(language.to_owned()));
    let headers: Vec<(&str, &str)> = ip
        .map(|ip| vec![("cf-connecting-ip", ip)])
        .unwrap_or_default();
    let filed = fulfillment
        .post_with_headers("", Value::Object(body), &headers)
        .await?;
    if filed.get("state").and_then(Value::as_str) == Some("waitlist") {
        return Ok(json!({"status": "waitlist", "edition": language, "email": email}));
    }
    let links = links.await?;
    let minted = links
        .post(
            "/internal/download-links",
            json!({"email": email, "lang": language, "fresh": true}),
        )
        .await?;
    let link = minted
        .get("url")
        .and_then(Value::as_str)
        .filter(|link| !link.is_empty())
        .ok_or_else(|| "[permanent] book-links returned no download link".to_owned())?;
    Ok(json!({"status": "sent", "edition": language, "email": email, "link": link}))
}

/// One optional string argument: absent or null is `None`, anything else must be a string.
fn optional_text(arguments: &Map<String, Value>, field: &str) -> Result<Option<String>, String> {
    match arguments.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(value) => value
            .as_str()
            .map(|text| Some(text.to_owned()))
            .ok_or_else(|| format!("[permanent] invalid {field}: expected a string")),
    }
}

/// Register the ebook tool.
pub fn register(provider: &mut BuiltinProvider) {
    provider.register(BuiltinTool::new(
        "ebook",
        "request",
        REQUEST_DESCRIPTION,
        schema(json!({
            "type": "object",
            "additionalProperties": false,
            "properties": {
                "email": {"type": "string"},
                "language": {"type": "string", "default": "en"},
                "ip": {"type": "string"},
            },
            "required": ["email"],
        })),
        Arc::new(|_caller, arguments| {
            boxed(async move {
                let email = text_argument(&arguments, "email")?;
                // A request without a real address can never be answered; refuse before any
                // client is resolved.
                if !email.contains('@') {
                    return Err(
                        "[permanent] invalid email: expected an address with an @".to_owned()
                    );
                }
                let language = optional_text(&arguments, "language")?
                    .filter(|language| !language.is_empty())
                    .unwrap_or_else(|| "en".to_owned());
                let ip = optional_text(&arguments, "ip")?;
                // A value reqwest would reject as a header would otherwise surface as a
                // retryable transport error; the caller's mistake is permanent.
                if ip
                    .as_deref()
                    .is_some_and(|ip| ip.chars().any(char::is_control))
                {
                    return Err("[permanent] invalid ip: expected a plain address".to_owned());
                }
                let fulfillment = client::book_fulfillment()?;
                success(request(&fulfillment, &email, &language, ip.as_deref()).await?)
            })
        }),
    ));
}
