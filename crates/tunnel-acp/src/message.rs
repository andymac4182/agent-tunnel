//! Buffer-before-dispatch validation of one ACP JSON-RPC message.
//!
//! The device runs this on the complete, bounded request body before it
//! invokes anything.  A rejection is answered locally with a sanitized
//! JSON-RPC error that never echoes consumer header or body values.
//!
//! Every refusal names **one rule**, and each rule has its own HTTP status and
//! its own JSON-RPC code.  That separation is the point: a test that asserted
//! only "this errored" would pass for a batch that was rejected for being
//! malformed, and a profile that answered every bad input with one generic
//! error could not tell an operator which contract was broken.  In particular
//! these three are distinct and stay distinct:
//!
//! * a **batch** — a top-level JSON array — is [`AcpRule::BatchNotSupported`],
//!   HTTP 501, decided from the first non-whitespace byte;
//! * a **protocol version that is not v1** is
//!   [`AcpRule::UnsupportedProtocolVersion`], HTTP 400;
//! * an **unsupported consumer HTTP version** is not decided here at all.  It
//!   is the codec's `HttpVersionNotAllowed`, which carries
//!   `HTTP_UNSUPPORTED_FEATURE`, and it is refused before a body exists.
//!
//! The v1 method names, the `StopReason` vocabulary and the v1
//! `session/prompt` response shape all come from the pinned
//! `agent-client-protocol` crate rather than from strings retyped here.

use agent_client_protocol::schema::v1::{PromptResponse, StopReason};
use http::HeaderMap;
use serde_json::Value;

use crate::json::{JsonError, TopLevel, compact_object, top_level};
use crate::{PROTOCOL_VERSION_V1, headers, is_accepted_method};

/// JSON-RPC error codes used by local rejections.
///
/// The negative five-digit values are the JSON-RPC standard ones; the
/// `-320xx` values are this bridge's own reserved implementation-defined
/// codes, chosen so each rule is distinguishable on the wire.
pub mod codes {
    pub const PARSE_ERROR: i64 = -32700;
    pub const INVALID_REQUEST: i64 = -32600;
    pub const METHOD_NOT_FOUND: i64 = -32601;
    pub const BATCH_NOT_SUPPORTED: i64 = -32030;
    pub const UNSUPPORTED_PROTOCOL_VERSION: i64 = -32031;
    pub const HEADER_MISMATCH: i64 = -32032;
    pub const V2_PROMPT_ACKNOWLEDGEMENT: i64 = -32033;
    pub const UNKNOWN_STOP_REASON: i64 = -32034;
}

/// The exact rule a refusal broke.  One variant per pinned claim.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum AcpRule {
    /// A `POST` whose `Content-Type` is not `application/json`.
    ContentType,
    /// A `GET` whose `Accept` does not cover `text/event-stream`.
    Accept,
    /// `Acp-Connection-Id` is required and absent.
    ConnectionHeaderRequired,
    /// `initialize` opens a connection and must not present one.
    ConnectionHeaderForbidden,
    /// A session-scoped method arrived without `Acp-Session-Id`.
    SessionHeaderRequired,
    /// `Acp-Session-Id` and the body's `params.sessionId` disagree.
    SessionHeaderMismatch,
    /// A top-level JSON array: a JSON-RPC batch.
    BatchNotSupported,
    /// The body is not strict JSON.
    NotStrictJson,
    /// The body is strict JSON but not one JSON-RPC message object.
    NotJsonRpcMessage,
    /// `jsonrpc` is absent or is not exactly `"2.0"`.
    JsonRpcVersion,
    /// `id` is present but is neither a string nor an integer.
    RequestId,
    /// The method is not one this profile carries.
    MethodNotAccepted,
    /// `protocolVersion` is present but is not a small unsigned integer.
    ProtocolVersionShape,
    /// `protocolVersion` is an integer other than 1 — notably the v2 draft.
    UnsupportedProtocolVersion,
    /// A `session/prompt` result with no `stopReason`: the v2 draft's prompt
    /// **acknowledgement**, which must never be read as a v1 turn completion.
    V2PromptAcknowledgement,
    /// A `session/prompt` result whose `stopReason` is outside the pinned v1
    /// vocabulary.
    UnknownStopReason,
    /// A `session/prompt` result that is not an object at all.
    TurnCompletionShape,
}

impl AcpRule {
    /// The HTTP status this rule answers with.
    #[must_use]
    pub const fn status(self) -> u16 {
        match self {
            Self::ContentType => 415,
            Self::Accept => 406,
            // The RFD's own answer for a batch, and the only 501 here.
            Self::BatchNotSupported => 501,
            _ => 400,
        }
    }

    /// The JSON-RPC error code this rule answers with.
    #[must_use]
    pub const fn code(self) -> i64 {
        match self {
            Self::NotStrictJson => codes::PARSE_ERROR,
            Self::BatchNotSupported => codes::BATCH_NOT_SUPPORTED,
            Self::UnsupportedProtocolVersion => codes::UNSUPPORTED_PROTOCOL_VERSION,
            Self::MethodNotAccepted => codes::METHOD_NOT_FOUND,
            Self::SessionHeaderMismatch
            | Self::ConnectionHeaderRequired
            | Self::ConnectionHeaderForbidden
            | Self::SessionHeaderRequired => codes::HEADER_MISMATCH,
            Self::V2PromptAcknowledgement => codes::V2_PROMPT_ACKNOWLEDGEMENT,
            Self::UnknownStopReason => codes::UNKNOWN_STOP_REASON,
            Self::ContentType
            | Self::Accept
            | Self::NotJsonRpcMessage
            | Self::JsonRpcVersion
            | Self::RequestId
            | Self::ProtocolVersionShape
            | Self::TurnCompletionShape => codes::INVALID_REQUEST,
        }
    }
}

/// A local rejection: the rule, its HTTP status and a sanitized JSON-RPC
/// error.  It carries no consumer bytes.
#[derive(Clone, Debug, PartialEq)]
pub struct AcpRejection {
    pub rule: AcpRule,
    pub status: u16,
    pub code: i64,
    /// A fixed description; never consumer data.
    pub message: &'static str,
    /// The request ID when one was parsed, so the client can correlate.
    pub id: Option<Value>,
    /// For an unsupported protocol version: the versions this profile
    /// supports.
    pub supported: Option<u16>,
}

impl AcpRejection {
    #[must_use]
    pub const fn new(rule: AcpRule, message: &'static str) -> Self {
        Self {
            rule,
            status: rule.status(),
            code: rule.code(),
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

/// The JSON-RPC message kind of a body.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MessageKind {
    Request,
    Notification,
    /// A result or error response.  The host POSTs these to answer a
    /// `session/request_permission` that arrived on its session stream.
    Response,
}

/// One validated JSON-RPC message.  `Debug` prints no payload.
#[derive(Clone)]
pub struct AcpMessage {
    /// The exact compact bytes (no insignificant whitespace, no newline).
    pub compact: Vec<u8>,
    pub value: Value,
    pub kind: MessageKind,
    /// The request or response ID: a JSON string or integer.
    pub id: Option<Value>,
    pub method: Option<String>,
}

impl core::fmt::Debug for AcpMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("AcpMessage")
            .field("kind", &self.kind)
            .field("bytes", &self.compact.len())
            .finish_non_exhaustive()
    }
}

impl AcpMessage {
    #[must_use]
    pub fn is_initialize(&self) -> bool {
        self.kind == MessageKind::Request
            && self.method.as_deref()
                == Some(agent_client_protocol::schema::v1::AGENT_METHOD_NAMES.initialize)
    }

    /// `params.sessionId`, when the body carries one.
    #[must_use]
    pub fn session_id(&self) -> Option<&str> {
        self.value.get("params")?.get("sessionId")?.as_str()
    }
}

fn is_integer(value: &Value) -> bool {
    value.as_i64().is_some() || value.as_u64().is_some()
}

/// Read one header.  A repeated field is reported as unreadable rather than
/// silently picking one; the codec's singleton rule already refuses it, and
/// this keeps the two from disagreeing if that rule were ever relaxed.
fn header<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    let mut values = headers.get_all(name).iter();
    let first = values.next()?;
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

/// The session-scoped methods that require `Acp-Session-Id`.
///
/// Taken from the pinned schema's names, not spelled out here.
fn requires_session_header(method: &str) -> bool {
    let agent = agent_client_protocol::schema::v1::AGENT_METHOD_NAMES;
    method == agent.session_prompt || method == agent.session_cancel
}

/// Check the `Content-Type` of a POST.
///
/// # Errors
/// [`AcpRule::ContentType`] (415) for anything but `application/json`.
pub fn check_post_content_type(headers: &HeaderMap) -> Result<(), AcpRejection> {
    let content_type = header(headers, headers::CONTENT_TYPE).unwrap_or("");
    if media_type(content_type).eq_ignore_ascii_case(JSON) {
        Ok(())
    } else {
        Err(AcpRejection::new(
            AcpRule::ContentType,
            "Content-Type must be application/json",
        ))
    }
}

/// Parse one strict JSON-RPC message.
///
/// A batch is decided **first**, from the top-level shape alone, so the 501 it
/// earns cannot be mistaken for a parse failure inside it.
///
/// # Errors
/// The first [`AcpRejection`].
pub fn parse_message(body: &[u8]) -> Result<AcpMessage, AcpRejection> {
    if top_level(body) == TopLevel::Array {
        return Err(AcpRejection::new(
            AcpRule::BatchNotSupported,
            "JSON-RPC batches are not supported by this transport",
        ));
    }
    let compact = compact_object(body).map_err(|error| match error {
        JsonError::Syntax if top_level(body) != TopLevel::Object => AcpRejection::new(
            AcpRule::NotJsonRpcMessage,
            "the body must be one JSON-RPC message object",
        ),
        _ => AcpRejection::new(AcpRule::NotStrictJson, "the body is not strict JSON"),
    })?;
    let value: Value = serde_json::from_slice(&compact)
        .map_err(|_| AcpRejection::new(AcpRule::NotStrictJson, "the body is not strict JSON"))?;
    let object = value.as_object().ok_or(AcpRejection::new(
        AcpRule::NotJsonRpcMessage,
        "the body must be one JSON-RPC message object",
    ))?;
    if object.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        return Err(AcpRejection::new(
            AcpRule::JsonRpcVersion,
            "jsonrpc must be \"2.0\"",
        ));
    }
    let id = object.get("id");
    if let Some(id) = id
        && !(id.is_string() || is_integer(id))
    {
        return Err(AcpRejection::new(
            AcpRule::RequestId,
            "id must be a string or an integer",
        ));
    }
    let method = match object.get("method") {
        None => None,
        Some(Value::String(method)) if !method.is_empty() => Some(method.clone()),
        Some(_) => {
            return Err(AcpRejection::new(
                AcpRule::NotJsonRpcMessage,
                "method must be a non-empty string",
            )
            .with_id(id));
        }
    };
    let has_result = object.contains_key("result");
    let has_error = object.contains_key("error");
    let kind = match (&method, id, has_result, has_error) {
        (Some(_), Some(_), false, false) => MessageKind::Request,
        (Some(_), None, false, false) => MessageKind::Notification,
        (None, Some(_), true, false) | (None, Some(_), false, true) => MessageKind::Response,
        _ => {
            return Err(AcpRejection::new(
                AcpRule::NotJsonRpcMessage,
                "not a JSON-RPC request, notification or response",
            )
            .with_id(id));
        }
    };
    if let Some(params) = object.get("params")
        && !params.is_object()
    {
        // ACP has no positional parameters: every v1 method takes an object,
        // and the session header can only be reconciled with an object body.
        return Err(
            AcpRejection::new(AcpRule::NotJsonRpcMessage, "params must be an object").with_id(id),
        );
    }
    Ok(AcpMessage {
        compact,
        kind,
        id: id.cloned(),
        method,
        value,
    })
}

/// Negotiate a protocol version value.
///
/// # Errors
/// [`AcpRule::ProtocolVersionShape`] for a non-integer, and
/// [`AcpRule::UnsupportedProtocolVersion`] for any integer that is not 1 —
/// which is how the v2 draft is refused, by its own rule and its own code.
pub fn negotiate_protocol_version(value: &Value) -> Result<u16, AcpRejection> {
    let Some(number) = value.as_u64().and_then(|n| u16::try_from(n).ok()) else {
        return Err(AcpRejection::new(
            AcpRule::ProtocolVersionShape,
            "protocolVersion must be an unsigned integer",
        ));
    };
    if number == PROTOCOL_VERSION_V1 {
        return Ok(number);
    }
    let mut rejection = AcpRejection::new(
        AcpRule::UnsupportedProtocolVersion,
        "this export speaks ACP protocol version 1 only",
    );
    rejection.supported = Some(PROTOCOL_VERSION_V1);
    Err(rejection)
}

/// Check an `initialize` request's or result's `protocolVersion`.
///
/// # Errors
/// As [`negotiate_protocol_version`]; a missing field is
/// [`AcpRule::ProtocolVersionShape`].
pub fn check_initialize_version(message: &AcpMessage) -> Result<u16, AcpRejection> {
    let field = match message.kind {
        MessageKind::Response => message.value.get("result"),
        _ => message.value.get("params"),
    }
    .and_then(|object| object.get("protocolVersion"));
    let Some(field) = field else {
        return Err(AcpRejection::new(
            AcpRule::ProtocolVersionShape,
            "protocolVersion is required",
        )
        .with_id(message.id.as_ref()));
    };
    negotiate_protocol_version(field).map_err(|error| error.with_id(message.id.as_ref()))
}

/// Read a `session/prompt` result as a **v1 turn completion**.
///
/// The v2 draft splits the prompt lifecycle: its prompt response is a bare
/// acknowledgement that the prompt was accepted, and output and completion
/// arrive later as notifications.  Its response object is therefore empty
/// apart from an optional `_meta`, which is exactly the shape a v1 reader
/// would otherwise deserialize as "the turn is over".  That is the confusion
/// `docs/acp.md` forbids, so it gets a rule of its own.
///
/// The accepted path is decided by the pinned crate's own `PromptResponse`
/// deserializer and `StopReason` vocabulary, not by a list here.
///
/// # Errors
/// [`AcpRule::TurnCompletionShape`] if the result is not an object,
/// [`AcpRule::V2PromptAcknowledgement`] if it has no `stopReason`, and
/// [`AcpRule::UnknownStopReason`] if its `stopReason` is outside the pinned
/// vocabulary.
pub fn read_turn_completion(result: &Value) -> Result<StopReason, AcpRejection> {
    let Some(object) = result.as_object() else {
        return Err(AcpRejection::new(
            AcpRule::TurnCompletionShape,
            "a session/prompt result must be an object",
        ));
    };
    if !object.contains_key("stopReason") {
        return Err(AcpRejection::new(
            AcpRule::V2PromptAcknowledgement,
            "a session/prompt result without stopReason is a v2 acknowledgement, not a v1 turn completion",
        ));
    }
    let response: PromptResponse = serde_json::from_value(result.clone()).map_err(|_| {
        AcpRejection::new(
            AcpRule::UnknownStopReason,
            "stopReason is not a value in the pinned ACP v1 vocabulary",
        )
    })?;
    Ok(response.stop_reason)
}

/// Check the identity headers of a POST against the parsed message.
///
/// # Errors
/// The first [`AcpRejection`].
pub fn check_identity_headers(
    headers: &HeaderMap,
    message: &AcpMessage,
) -> Result<(), AcpRejection> {
    let id = message.id.as_ref();
    let connection = header(headers, headers::ACP_CONNECTION_ID).filter(|v| !v.is_empty());
    if message.is_initialize() {
        if connection.is_some() {
            return Err(AcpRejection::new(
                AcpRule::ConnectionHeaderForbidden,
                "initialize opens a connection and must not present Acp-Connection-Id",
            )
            .with_id(id));
        }
    } else if connection.is_none() {
        return Err(AcpRejection::new(
            AcpRule::ConnectionHeaderRequired,
            "Acp-Connection-Id is required",
        )
        .with_id(id));
    }

    let session = header(headers, headers::ACP_SESSION_ID).filter(|v| !v.is_empty());
    if let Some(method) = message.method.as_deref()
        && requires_session_header(method)
        && session.is_none()
    {
        return Err(AcpRejection::new(
            AcpRule::SessionHeaderRequired,
            "this method is session-scoped and requires Acp-Session-Id",
        )
        .with_id(id));
    }
    if let (Some(session), Some(body)) = (session, message.session_id())
        && session != body
    {
        return Err(AcpRejection::new(
            AcpRule::SessionHeaderMismatch,
            "Acp-Session-Id does not match params.sessionId",
        )
        .with_id(id));
    }
    Ok(())
}

/// Validate a complete POST: content type, strict message, accepted method,
/// identity headers, and — for `initialize` — the negotiated version.
///
/// # Errors
/// The first [`AcpRejection`].
pub fn validate_post(headers: &HeaderMap, body: &[u8]) -> Result<AcpMessage, AcpRejection> {
    check_post_content_type(headers)?;
    let message = parse_message(body)?;
    if let Some(method) = message.method.as_deref()
        && !is_accepted_method(method)
    {
        return Err(AcpRejection::new(
            AcpRule::MethodNotAccepted,
            "this method is not carried by this export",
        )
        .with_id(message.id.as_ref()));
    }
    check_identity_headers(headers, &message)?;
    if message.is_initialize() {
        check_initialize_version(&message)?;
    }
    Ok(message)
}

/// Validate a `GET` (an SSE subscription) head.
///
/// # Errors
/// [`AcpRule::Accept`] (406) without `text/event-stream`, and
/// [`AcpRule::ConnectionHeaderRequired`] (400) without the connection header.
pub fn validate_get(headers: &HeaderMap) -> Result<(), AcpRejection> {
    if !accept_covers(header(headers, headers::ACCEPT).unwrap_or(""), EVENT_STREAM) {
        return Err(AcpRejection::new(
            AcpRule::Accept,
            "Accept must list text/event-stream",
        ));
    }
    require_connection(headers)
}

/// Validate a `DELETE` (connection termination) head.
///
/// # Errors
/// [`AcpRule::ConnectionHeaderRequired`] (400) without the connection header.
pub fn validate_delete(headers: &HeaderMap) -> Result<(), AcpRejection> {
    require_connection(headers)
}

fn require_connection(headers: &HeaderMap) -> Result<(), AcpRejection> {
    if header(headers, headers::ACP_CONNECTION_ID).is_some_and(|value| !value.is_empty()) {
        Ok(())
    } else {
        Err(AcpRejection::new(
            AcpRule::ConnectionHeaderRequired,
            "Acp-Connection-Id is required",
        ))
    }
}

#[cfg(test)]
#[path = "message_tests.rs"]
mod tests;
