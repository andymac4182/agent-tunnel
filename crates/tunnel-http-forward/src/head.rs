//! Typed request/response heads, strict parsing, and validated encoding.

use core::fmt;

use crate::error::CodecError;
use crate::json::{self, Json};
use crate::record::{MAX_HEAD_PAYLOAD_LEN, RecordKind, encode_record};
use crate::validate::{
    RequestPolicy, ResponsePolicy, header_error, validate_headers, validate_path, validate_query,
};

/// Methods representable in v1.  Routes restrict them further.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Method {
    Get,
    Head,
    Post,
    Put,
    Patch,
    Delete,
    Options,
}

impl Method {
    pub const ALL: [Self; 7] = [
        Self::Get,
        Self::Head,
        Self::Post,
        Self::Put,
        Self::Patch,
        Self::Delete,
        Self::Options,
    ];

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Head => "HEAD",
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
            Self::Options => "OPTIONS",
        }
    }

    fn parse(value: &str) -> Result<Self, CodecError> {
        Self::ALL
            .into_iter()
            .find(|method| method.as_str() == value)
            .ok_or(CodecError::InvalidMethod)
    }
}

/// The accepted consumer HTTP version.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpVersion {
    Http11,
    Http2,
}

impl HttpVersion {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Http11 => "1.1",
            Self::Http2 => "2",
        }
    }
}

/// One header entry.  `Debug` prints only lengths.
#[derive(Clone, Eq, PartialEq)]
pub struct HeaderField {
    pub name: String,
    pub value: String,
}

impl HeaderField {
    #[must_use]
    pub fn new(name: impl Into<String>, value: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            value: value.into(),
        }
    }
}

impl fmt::Debug for HeaderField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HeaderField")
            .field("name_len", &self.name.len())
            .field("value_len", &self.value.len())
            .finish()
    }
}

/// A validated `REQUEST_HEAD`.  `Debug` omits path, query, and headers.
#[derive(Clone, Eq, PartialEq)]
pub struct RequestHead {
    pub method: Method,
    pub path: String,
    /// The original accepted query bytes, without `?`.
    pub query: String,
    pub http_version: HttpVersion,
    pub headers: Vec<HeaderField>,
    /// `None` is an unknown streaming length.
    pub body_length: Option<u64>,
}

impl fmt::Debug for RequestHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RequestHead")
            .field("method", &self.method)
            .field("path_len", &self.path.len())
            .field("query_len", &self.query.len())
            .field("http_version", &self.http_version)
            .field("headers_len", &self.headers.len())
            .field("body_length", &self.body_length)
            .finish()
    }
}

/// A validated `RESPONSE_HEAD`.  `Debug` omits headers.
#[derive(Clone, Eq, PartialEq)]
pub struct ResponseHead {
    pub status: u16,
    pub headers: Vec<HeaderField>,
    pub body_length: Option<u64>,
}

impl fmt::Debug for ResponseHead {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResponseHead")
            .field("status", &self.status)
            .field("headers_len", &self.headers.len())
            .field("body_length", &self.body_length)
            .finish()
    }
}

const REQUEST_KEYS: [&str; 6] = [
    "method",
    "path",
    "query",
    "http_version",
    "headers",
    "body_length",
];
const RESPONSE_KEYS: [&str; 3] = ["status", "headers", "body_length"];

/// Split a top-level object into exactly the expected keys, in `keys` order.
fn exact_fields<'a, const N: usize>(
    value: &'a Json,
    keys: [&str; N],
) -> Result<[&'a Json; N], CodecError> {
    let Json::Object(entries) = value else {
        return Err(CodecError::NotAnObject);
    };
    let mut found: [Option<&Json>; N] = [None; N];
    for (key, entry) in entries {
        let Some(index) = keys.iter().position(|candidate| candidate == key) else {
            return Err(CodecError::UnknownKey);
        };
        // The parser has already rejected duplicate keys.
        found[index] = Some(entry);
    }
    let mut out: [&Json; N] = [&Json::Null; N];
    for (slot, entry) in out.iter_mut().zip(found) {
        *slot = entry.ok_or(CodecError::MissingKey)?;
    }
    Ok(out)
}

fn as_str(value: &Json) -> Result<&str, CodecError> {
    match value {
        Json::String(text) => Ok(text),
        _ => Err(CodecError::WrongType),
    }
}

fn parse_headers(value: &Json) -> Result<Vec<HeaderField>, CodecError> {
    let Json::Array(items) = value else {
        return Err(CodecError::WrongType);
    };
    items
        .iter()
        .map(|item| match item {
            Json::Array(pair) => match pair.as_slice() {
                [Json::String(name), Json::String(value)] => Ok(HeaderField::new(name, value)),
                _ => Err(CodecError::WrongType),
            },
            _ => Err(CodecError::WrongType),
        })
        .collect()
}

/// Parse a canonical unsigned decimal `body_length`.
fn parse_body_length(value: &Json) -> Result<Option<u64>, CodecError> {
    match value {
        Json::Null => Ok(None),
        Json::String(text) => parse_canonical_u64(text).map(Some),
        _ => Err(CodecError::WrongType),
    }
}

pub(crate) fn parse_canonical_u64(text: &str) -> Result<u64, CodecError> {
    let bytes = text.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(CodecError::InvalidBodyLength);
    }
    if bytes.len() > 1 && bytes[0] == b'0' {
        return Err(CodecError::InvalidBodyLength);
    }
    let mut total = 0u64;
    for digit in bytes {
        total = total
            .checked_mul(10)
            .and_then(|sum| sum.checked_add(u64::from(digit - b'0')))
            .ok_or(CodecError::InvalidBodyLength)?;
    }
    Ok(total)
}

/// Parse and validate a request head payload against the request policy.
///
/// # Errors
/// Any JSON, schema, field, route, query, or header violation.
pub fn parse_request_head(
    payload: &[u8],
    policy: &RequestPolicy,
) -> Result<RequestHead, CodecError> {
    let value = json::parse(payload)?;
    let [method, path, query, http_version, headers, body_length] =
        exact_fields(&value, REQUEST_KEYS)?;
    let method = Method::parse(as_str(method)?)?;
    let path = as_str(path)?;
    let query = as_str(query)?;
    let http_version = match as_str(http_version)? {
        "1.1" => HttpVersion::Http11,
        "2" => HttpVersion::Http2,
        _ => return Err(CodecError::InvalidHttpVersion),
    };
    let headers = parse_headers(headers)?;
    let body_length = parse_body_length(body_length)?;

    validate_path(path).map_err(CodecError::InvalidPath)?;
    if !policy.route_allowed(method, path) {
        return Err(CodecError::RouteNotAllowed);
    }
    if !policy.version_allowed(http_version) {
        return Err(CodecError::HttpVersionNotAllowed);
    }
    validate_query(query, &policy.query).map_err(CodecError::InvalidQuery)?;
    validate_headers(&headers, &policy.headers).map_err(header_error)?;
    Ok(RequestHead {
        method,
        path: path.to_owned(),
        query: query.to_owned(),
        http_version,
        headers,
        body_length,
    })
}

/// Parse and validate a response head payload against the response policy.
/// `request_method` is needed for the HEAD zero-body rule.
///
/// # Errors
/// Any JSON, schema, status, header, or zero-body violation.
pub fn parse_response_head(
    payload: &[u8],
    policy: &ResponsePolicy,
    request_method: Method,
) -> Result<ResponseHead, CodecError> {
    let value = json::parse(payload)?;
    let [status, headers, body_length] = exact_fields(&value, RESPONSE_KEYS)?;
    let status = match status {
        Json::Number(lexeme) => parse_status(lexeme)?,
        _ => return Err(CodecError::WrongType),
    };
    let headers = parse_headers(headers)?;
    let body_length = parse_body_length(body_length)?;
    validate_headers(&headers, &policy.headers).map_err(header_error)?;
    if requires_zero_body(request_method, status) && body_length != Some(0) {
        return Err(CodecError::ZeroBodyRequired);
    }
    Ok(ResponseHead {
        status,
        headers,
        body_length,
    })
}

/// Integer-only status: no sign, fraction, or exponent, 200..=599.
fn parse_status(lexeme: &str) -> Result<u16, CodecError> {
    if lexeme.len() != 3 || !lexeme.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(CodecError::InvalidStatus);
    }
    let status = lexeme
        .parse::<u16>()
        .map_err(|_| CodecError::InvalidStatus)?;
    if (200..=599).contains(&status) {
        Ok(status)
    } else {
        Err(CodecError::InvalidStatus)
    }
}

/// Responses to HEAD and statuses 204, 205, and 304 carry no body.
#[must_use]
pub const fn requires_zero_body(request_method: Method, status: u16) -> bool {
    matches!(request_method, Method::Head) || matches!(status, 204 | 205 | 304)
}

fn write_headers(headers: &[HeaderField], out: &mut String) {
    out.push('[');
    for (index, field) in headers.iter().enumerate() {
        if index > 0 {
            out.push(',');
        }
        out.push('[');
        json::write_string(&field.name, out);
        out.push(',');
        json::write_string(&field.value, out);
        out.push(']');
    }
    out.push(']');
}

fn write_body_length(body_length: Option<u64>, out: &mut String) {
    match body_length {
        None => out.push_str("null"),
        Some(length) => {
            out.push('"');
            out.push_str(&length.to_string());
            out.push('"');
        }
    }
}

/// Serialize a request head to JSON without validation.
#[must_use]
pub fn request_head_json(head: &RequestHead) -> String {
    let mut out = String::from("{\"method\":");
    json::write_string(head.method.as_str(), &mut out);
    out.push_str(",\"path\":");
    json::write_string(&head.path, &mut out);
    out.push_str(",\"query\":");
    json::write_string(&head.query, &mut out);
    out.push_str(",\"http_version\":");
    json::write_string(head.http_version.as_str(), &mut out);
    out.push_str(",\"headers\":");
    write_headers(&head.headers, &mut out);
    out.push_str(",\"body_length\":");
    write_body_length(head.body_length, &mut out);
    out.push('}');
    out
}

/// Serialize a response head to JSON without validation.
#[must_use]
pub fn response_head_json(head: &ResponseHead) -> String {
    let mut out = format!("{{\"status\":{},\"headers\":", head.status);
    write_headers(&head.headers, &mut out);
    out.push_str(",\"body_length\":");
    write_body_length(head.body_length, &mut out);
    out.push('}');
    out
}

/// Append a complete REQUEST_HEAD record.  The serialized JSON is re-parsed
/// with the same strict validator and policy, so the encoder cannot emit a
/// head its peer would reject.
///
/// # Errors
/// Any validation error, or [`CodecError::HeadTooLarge`].
pub fn encode_request_head(
    head: &RequestHead,
    policy: &RequestPolicy,
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let text = request_head_json(head);
    if text.len() > MAX_HEAD_PAYLOAD_LEN {
        return Err(CodecError::HeadTooLarge);
    }
    let reparsed = parse_request_head(text.as_bytes(), policy)?;
    if reparsed != *head {
        return Err(CodecError::EncoderRoundTrip);
    }
    encode_record(RecordKind::RequestHead, text.as_bytes(), out)
}

/// Append a complete RESPONSE_HEAD record after strict re-validation.
///
/// # Errors
/// Any validation error, or [`CodecError::HeadTooLarge`].
pub fn encode_response_head(
    head: &ResponseHead,
    policy: &ResponsePolicy,
    request_method: Method,
    out: &mut Vec<u8>,
) -> Result<(), CodecError> {
    let text = response_head_json(head);
    if text.len() > MAX_HEAD_PAYLOAD_LEN {
        return Err(CodecError::HeadTooLarge);
    }
    let reparsed = parse_response_head(text.as_bytes(), policy, request_method)?;
    if reparsed != *head {
        return Err(CodecError::EncoderRoundTrip);
    }
    encode_record(RecordKind::ResponseHead, text.as_bytes(), out)
}
