//! Buffer-before-dispatch validation of one MCP Streamable HTTP request.
//!
//! The device runs this on the complete, bounded request body before it
//! invokes any backend.  A rejection is answered locally with a sanitized
//! JSON-RPC error that never echoes consumer header or body values.
//!
//! Checks are profile-specific:
//!
//! * both: `Content-Type: application/json`, an `Accept` covering
//!   `application/json` and `text/event-stream`, one strict JSON object with
//!   `"jsonrpc":"2.0"` (no batches), a string or integer request ID;
//! * 2026-07-28: `MCP-Protocol-Version` and `Mcp-Method` (equal to the body
//!   `method`) are required on requests and notifications;
//!   `MCP-Protocol-Version` must be
//!   `2026-07-28` and equal `params._meta["io.modelcontextprotocol/
//!   protocolVersion"]`; `Mcp-Method` must equal `method`; `Mcp-Name`
//!   (Base64 sentinel decoded) must equal `params.name` for `tools/call` and
//!   `prompts/get` and `params.uri` for `resources/read`; `Mcp-Param-*`
//!   values must be representable (a sentinel must decode to UTF-8); a
//!   client must not POST a JSON-RPC response;
//! * 2025-11-25: `MCP-Protocol-Version` must be `2025-11-25` when present and
//!   is required on every request except `initialize`.
//!
//! `Mcp-Param-*` values are not compared with tool arguments here: that needs
//! the tool's `inputSchema`, which only the MCP server holds.

use base64::Engine;
use http::HeaderMap;
use serde_json::Value;

use crate::json::{JsonError, compact_object};
use crate::{McpProfile, PROTOCOL_2025_11_25, PROTOCOL_2026_07_28, headers};

/// JSON-RPC error codes used by local rejections.
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const INTERNAL_ERROR: i64 = -32603;
    pub const HEADER_MISMATCH: i64 = -32020;
    pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32022;
}

/// The body `_meta` key mirrored by `MCP-Protocol-Version`.
pub const META_PROTOCOL_VERSION: &str = "io.modelcontextprotocol/protocolVersion";
/// The Base64 sentinel prefix and suffix of `Mcp-Name`/`Mcp-Param-*`.
pub const BASE64_SENTINEL_PREFIX: &str = "=?base64?";
pub const BASE64_SENTINEL_SUFFIX: &str = "?=";

/// The JSON-RPC message kind of a POST body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Request,
    Notification,
    /// A result or error response (client→server responses exist only in
    /// the legacy profile).
    Response,
}

/// One validated JSON-RPC message.  `Debug` prints no payload.
#[derive(Clone)]
pub struct McpMessage {
    /// The exact compact bytes (no insignificant whitespace, no newline).
    pub compact: Vec<u8>,
    pub value: Value,
    pub kind: MessageKind,
    /// The request or response ID: a JSON string or integer.
    pub id: Option<Value>,
    pub method: Option<String>,
}

impl core::fmt::Debug for McpMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("McpMessage")
            .field("kind", &self.kind)
            .field("bytes", &self.compact.len())
            .finish_non_exhaustive()
    }
}

impl McpMessage {
    /// `params._meta.progressToken`, when present.
    #[must_use]
    pub fn progress_token(&self) -> Option<&Value> {
        self.value
            .get("params")?
            .get("_meta")?
            .get("progressToken")
            .filter(|token| token.is_string() || is_integer(token))
    }

    #[must_use]
    pub fn is_initialize(&self) -> bool {
        self.kind == MessageKind::Request && self.method.as_deref() == Some("initialize")
    }
}

/// A local rejection: HTTP status plus a sanitized JSON-RPC error.
#[derive(Clone, Debug, PartialEq)]
pub struct McpRejection {
    pub status: u16,
    pub code: i64,
    /// A fixed description; never consumer data.
    pub message: &'static str,
    /// The request ID when one was parsed, so the client can correlate.
    pub id: Option<Value>,
    /// For an unsupported protocol version: the single supported revision.
    pub supported: Option<&'static str>,
}

impl McpRejection {
    const fn new(status: u16, code: i64, message: &'static str) -> Self {
        Self {
            status,
            code,
            message,
            id: None,
            supported: None,
        }
    }

    #[must_use]
    fn with_id(mut self, id: Option<&Value>) -> Self {
        self.id = id.cloned();
        self
    }

    /// The JSON-RPC error body.  The ID is omitted when unknown.
    #[must_use]
    pub fn body(&self) -> Vec<u8> {
        let mut error = serde_json::Map::new();
        error.insert("code".to_owned(), Value::from(self.code));
        error.insert("message".to_owned(), Value::from(self.message));
        if let Some(supported) = self.supported {
            error.insert(
                "data".to_owned(),
                serde_json::json!({ "supported": [supported] }),
            );
        }
        let mut body = serde_json::Map::new();
        body.insert("jsonrpc".to_owned(), Value::from("2.0"));
        if let Some(id) = &self.id {
            body.insert("id".to_owned(), id.clone());
        }
        body.insert("error".to_owned(), Value::Object(error));
        serde_json::to_vec(&Value::Object(body)).unwrap_or_default()
    }
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
    // Singletons are enforced by the codec; a second value here is treated
    // as unreadable rather than silently picking one.
    if values.next().is_some() {
        return Some("\u{0}");
    }
    first.to_str().ok().or(Some("\u{0}"))
}

fn media_type(value: &str) -> &str {
    value.split(';').next().unwrap_or("").trim()
}

fn accept_covers(accept: &str, wanted: &str) -> bool {
    let (wanted_type, _) = wanted.split_once('/').unwrap_or((wanted, ""));
    accept.split(',').any(|range| {
        let range = media_type(range);
        range.eq_ignore_ascii_case(wanted)
            || range == "*/*"
            || range
                .strip_suffix("/*")
                .is_some_and(|kind| kind.eq_ignore_ascii_case(wanted_type))
    })
}

const JSON: &str = "application/json";
const EVENT_STREAM: &str = "text/event-stream";

/// Check `Content-Type` and `Accept` of a POST.
///
/// # Errors
/// 415 for a non-JSON content type, 406 for an `Accept` not covering both
/// response types.
pub fn check_post_headers(headers: &HeaderMap) -> Result<(), McpRejection> {
    let content_type = header(headers, headers::CONTENT_TYPE).unwrap_or("");
    if !media_type(content_type).eq_ignore_ascii_case(JSON) {
        return Err(McpRejection::new(
            415,
            codes::INVALID_REQUEST,
            "Content-Type must be application/json",
        ));
    }
    let accept = header(headers, headers::ACCEPT).unwrap_or("");
    if !accept_covers(accept, JSON) || !accept_covers(accept, EVENT_STREAM) {
        return Err(McpRejection::new(
            406,
            codes::INVALID_REQUEST,
            "Accept must list application/json and text/event-stream",
        ));
    }
    Ok(())
}

/// Parse one strict JSON-RPC message.
///
/// # Errors
/// 400 with a parse or invalid-request error.
pub fn parse_message(body: &[u8]) -> Result<McpMessage, McpRejection> {
    let compact = compact_object(body).map_err(|error| match error {
        JsonError::NotAnObject => McpRejection::new(
            400,
            codes::INVALID_REQUEST,
            "the body must be one JSON-RPC message object",
        ),
        _ => McpRejection::new(400, codes::PARSE_ERROR, "the body is not strict JSON"),
    })?;
    let value: Value = serde_json::from_slice(&compact)
        .map_err(|_| McpRejection::new(400, codes::PARSE_ERROR, "the body is not strict JSON"))?;
    let object = value.as_object().ok_or(McpRejection::new(
        400,
        codes::INVALID_REQUEST,
        "the body must be one JSON-RPC message object",
    ))?;
    let invalid = |message| McpRejection::new(400, codes::INVALID_REQUEST, message);
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(invalid("jsonrpc must be \"2.0\""));
    }
    let id = object.get("id");
    if let Some(id) = id
        && !(id.is_string() || is_integer(id))
    {
        return Err(invalid("id must be a string or an integer"));
    }
    let method = match object.get("method") {
        None => None,
        Some(Value::String(method)) if !method.is_empty() => Some(method.clone()),
        Some(_) => return Err(invalid("method must be a non-empty string").with_id(id)),
    };
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    let kind = match (&method, id, has_result, has_error) {
        (Some(_), Some(_), false, false) => MessageKind::Request,
        (Some(_), None, false, false) => MessageKind::Notification,
        (None, Some(_), true, false) | (None, Some(_), false, true) => MessageKind::Response,
        _ => return Err(invalid("not a JSON-RPC request, notification or response").with_id(id)),
    };
    if let Some(params) = object.get("params")
        && !(params.is_object() || params.is_array())
    {
        return Err(invalid("params must be an object or an array").with_id(id));
    }
    Ok(McpMessage {
        compact,
        kind,
        id: id.cloned(),
        method,
        value,
    })
}

/// Decode a `Mcp-Name`/`Mcp-Param-*` value (Base64 sentinel or plain).
#[must_use]
pub fn decode_header_value(value: &str) -> Option<String> {
    match value
        .strip_prefix(BASE64_SENTINEL_PREFIX)
        .and_then(|rest| rest.strip_suffix(BASE64_SENTINEL_SUFFIX))
    {
        Some(inner) => {
            let bytes = base64::engine::general_purpose::STANDARD
                .decode(inner)
                .ok()?;
            String::from_utf8(bytes).ok()
        }
        None => Some(value.to_owned()),
    }
}

/// Check a parsed message against the profile's metadata headers.
///
/// # Errors
/// 400 with `HeaderMismatch`, `UnsupportedProtocolVersion` or an invalid
/// request error.
pub fn check_message_headers(
    profile: McpProfile,
    headers: &HeaderMap,
    message: &McpMessage,
) -> Result<(), McpRejection> {
    let id = message.id.as_ref();
    let version = header(headers, headers::MCP_PROTOCOL_VERSION);
    match profile {
        McpProfile::V2026_07_28 => check_2026(headers, message, version).map_err(|e| e.with_id(id)),
        McpProfile::V2025_11_25 => {
            match version {
                Some(PROTOCOL_2025_11_25) => {}
                None if message.is_initialize() => {}
                None => {
                    return Err(McpRejection::new(
                        400,
                        codes::INVALID_REQUEST,
                        "MCP-Protocol-Version is required",
                    )
                    .with_id(id));
                }
                Some(_) => {
                    let mut rejection = McpRejection::new(
                        400,
                        codes::UNSUPPORTED_PROTOCOL_VERSION,
                        "Unsupported protocol version",
                    )
                    .with_id(id);
                    rejection.supported = Some(PROTOCOL_2025_11_25);
                    return Err(rejection);
                }
            }
            Ok(())
        }
    }
}

fn mismatch(message: &'static str) -> McpRejection {
    McpRejection::new(400, codes::HEADER_MISMATCH, message)
}

fn check_2026(
    headers: &HeaderMap,
    message: &McpMessage,
    version: Option<&str>,
) -> Result<(), McpRejection> {
    match (message.kind, version) {
        (MessageKind::Response, _) => {
            return Err(McpRejection::new(
                400,
                codes::INVALID_REQUEST,
                "a client must not send a JSON-RPC response in this revision",
            ));
        }
        (_, Some(PROTOCOL_2026_07_28)) => {}
        (MessageKind::Request | MessageKind::Notification, None) => {
            return Err(mismatch("missing required MCP-Protocol-Version header"));
        }
        (_, Some(_)) => {
            let mut rejection = McpRejection::new(
                400,
                codes::UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
            );
            rejection.supported = Some(PROTOCOL_2026_07_28);
            return Err(rejection);
        }
    }
    for (name, value) in headers {
        if name.as_str().starts_with(headers::MCP_PARAM_PREFIX)
            && value.to_str().ok().and_then(decode_header_value).is_none()
        {
            return Err(mismatch("an Mcp-Param header value is not representable"));
        }
    }
    let method = message.method.as_deref().unwrap_or_default();
    if header(headers, headers::MCP_METHOD) != Some(method) {
        return Err(mismatch("Mcp-Method is missing or does not match the body"));
    }
    if message.kind != MessageKind::Request {
        return Ok(());
    }
    let params = message.value.get("params");
    let body_version = params
        .and_then(|params| params.get("_meta"))
        .and_then(|meta| meta.get(META_PROTOCOL_VERSION))
        .and_then(Value::as_str);
    if body_version != Some(PROTOCOL_2026_07_28) {
        return Err(mismatch(
            "MCP-Protocol-Version does not match the request _meta protocol version",
        ));
    }
    let name_field = match method {
        "tools/call" | "prompts/get" => Some("name"),
        "resources/read" => Some("uri"),
        _ => None,
    };
    if let Some(field) = name_field {
        let expected = params
            .and_then(|params| params.get(field))
            .and_then(Value::as_str);
        let actual = header(headers, headers::MCP_NAME).and_then(decode_header_value);
        if expected.is_none() || actual.as_deref() != expected {
            return Err(mismatch("Mcp-Name is missing or does not match the body"));
        }
    }
    Ok(())
}

/// Validate a complete POST: content negotiation, strict message and
/// metadata headers.
///
/// # Errors
/// The first [`McpRejection`].
pub fn validate_post(
    profile: McpProfile,
    headers: &HeaderMap,
    body: &[u8],
) -> Result<McpMessage, McpRejection> {
    check_post_headers(headers)?;
    let message = parse_message(body)?;
    check_message_headers(profile, headers, &message)?;
    Ok(message)
}

/// Validate a legacy GET (standalone SSE stream) head.
///
/// # Errors
/// 405 for the 2026 profile, 406 without `text/event-stream`, 400 for a bad
/// protocol version.
pub fn validate_get(profile: McpProfile, headers: &HeaderMap) -> Result<(), McpRejection> {
    validate_bodyless(profile, headers)?;
    if !accept_covers(header(headers, headers::ACCEPT).unwrap_or(""), EVENT_STREAM) {
        return Err(McpRejection::new(
            406,
            codes::INVALID_REQUEST,
            "Accept must list text/event-stream",
        ));
    }
    Ok(())
}

/// Validate a legacy DELETE (session termination) head.
///
/// # Errors
/// 405 for the 2026 profile, 400 for a bad protocol version.
pub fn validate_delete(profile: McpProfile, headers: &HeaderMap) -> Result<(), McpRejection> {
    validate_bodyless(profile, headers)
}

fn validate_bodyless(profile: McpProfile, headers: &HeaderMap) -> Result<(), McpRejection> {
    if !profile.is_legacy() {
        return Err(McpRejection::new(
            405,
            codes::INVALID_REQUEST,
            "method not allowed",
        ));
    }
    match header(headers, headers::MCP_PROTOCOL_VERSION) {
        None | Some(PROTOCOL_2025_11_25) => Ok(()),
        Some(_) => {
            let mut rejection = McpRejection::new(
                400,
                codes::UNSUPPORTED_PROTOCOL_VERSION,
                "Unsupported protocol version",
            );
            rejection.supported = Some(PROTOCOL_2025_11_25);
            Err(rejection)
        }
    }
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
