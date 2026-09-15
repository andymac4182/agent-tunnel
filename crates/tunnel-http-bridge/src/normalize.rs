//! HTTP message normalization into validated `http-forward/1` heads.
//!
//! Framing is checked before anything is stripped: duplicate or invalid
//! Content-Length, Transfer-Encoding with Content-Length, declared trailers
//! and non-identity content encodings are rejected, never laundered.  The
//! ingress consumes exactly the transport fields listed in
//! [`request_head`]; every other field is handed to the codec's strict
//! allowlist, so an unknown header fails instead of disappearing.

use core::fmt;

use bytes::Bytes;
use http::{HeaderMap, StatusCode, Version, request, response};
use tunnel_http_forward::{
    CodecError, HeaderField, HttpErrorCode, HttpVersion, Method, RequestHead, RequestPolicy,
    ResponseHead, ResponsePolicy, encode_request_head, encode_response_head,
};

/// Why a message could not become a head.  No variant carries header
/// values, paths, or body bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum NormalizeError {
    /// CONNECT or another tunnel-establishing method.
    UnsupportedMethod,
    /// An HTTP version other than 1.1 or 2.
    UnsupportedVersion,
    DuplicateContentLength,
    InvalidContentLength,
    TransferEncodingWithContentLength,
    /// Transfer codings other than a single HTTP/1.1 `chunked`, or any
    /// Transfer-Encoding on a handler response.
    UnsupportedTransferEncoding,
    /// A `trailer` field announcing trailers.
    DeclaredTrailers,
    /// A content coding other than `identity`.
    UnsupportedContentEncoding,
    /// A `connection` option other than `keep-alive` or `close`.
    UnsupportedConnectionOption,
    /// An `expect` value other than `100-continue`.
    UnsupportedExpectation,
    /// `connection`, `keep-alive` or `proxy-connection` in an HTTP/2 request,
    /// which RFC 9113 section 8.2.2 makes malformed.
    ConnectionSpecificField,
    /// A value that is not visible ASCII, space, or tab.
    InvalidHeaderValue,
    /// A declared length above the direction's body limit.
    DeclaredLengthExceedsLimit,
    /// The codec's head, route, query, or header validation.
    Codec(CodecError),
}

impl NormalizeError {
    /// The sanitized `HTTP_*` code.
    #[must_use]
    pub const fn code(self) -> HttpErrorCode {
        match self {
            Self::UnsupportedMethod
            | Self::UnsupportedVersion
            | Self::UnsupportedTransferEncoding
            | Self::DeclaredTrailers
            | Self::UnsupportedContentEncoding
            | Self::UnsupportedConnectionOption
            | Self::UnsupportedExpectation => HttpErrorCode::UnsupportedFeature,
            Self::DuplicateContentLength
            | Self::InvalidContentLength
            | Self::TransferEncodingWithContentLength
            | Self::ConnectionSpecificField
            | Self::InvalidHeaderValue => HttpErrorCode::InvalidHead,
            Self::DeclaredLengthExceedsLimit => HttpErrorCode::BodyLimit,
            Self::Codec(error) => error.code(),
        }
    }

    /// The ordinary client-error status for rejecting the consumer's request.
    #[must_use]
    pub const fn status(self) -> StatusCode {
        match self {
            // RFC 9110 section 15.5.18.
            Self::UnsupportedExpectation => StatusCode::EXPECTATION_FAILED,
            other => crate::status::gateway_status(
                crate::status::Origin::Consumer,
                other.code(),
                crate::status::Execution::NotDispatched,
            ),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    Ingress,
    Handler,
}

/// Trim boundary optional whitespace, once.
fn trim_ows(text: &str) -> &str {
    text.trim_matches([' ', '\t'])
}

fn parse_content_length(text: &str) -> Result<u64, NormalizeError> {
    if text.is_empty() || !text.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(NormalizeError::InvalidContentLength);
    }
    text.bytes()
        .try_fold(0u64, |total, digit| {
            total
                .checked_mul(10)
                .and_then(|sum| sum.checked_add(u64::from(digit - b'0')))
        })
        .ok_or(NormalizeError::InvalidContentLength)
}

fn scan_headers(
    headers: &HeaderMap,
    side: Side,
    version: Version,
) -> Result<(Vec<HeaderField>, Option<u64>), NormalizeError> {
    if headers.contains_key(http::header::TRAILER) {
        return Err(NormalizeError::DeclaredTrailers);
    }
    let mut fields = Vec::new();
    let mut lengths: Vec<&str> = Vec::new();
    let mut codings: Vec<&str> = Vec::new();
    for (name, value) in headers {
        let text = value
            .to_str()
            .map_err(|_| NormalizeError::InvalidHeaderValue)?;
        let text = trim_ows(text);
        match (side, name.as_str()) {
            (_, "content-length") => lengths.push(text),
            (_, "transfer-encoding") => codings.push(text),
            (_, "content-encoding") if !text.eq_ignore_ascii_case("identity") => {
                return Err(NormalizeError::UnsupportedContentEncoding);
            }
            // Transport fields the ingress HTTP connection has consumed.  The
            // authoritative service comes from OPEN, never from `host`.
            (Side::Ingress, "connection" | "keep-alive" | "proxy-connection")
                if version != Version::HTTP_11 =>
            {
                return Err(NormalizeError::ConnectionSpecificField);
            }
            (Side::Ingress, "host" | "keep-alive") => {}
            (Side::Ingress, "connection") => {
                let supported = text.split(',').map(trim_ows).all(|option| {
                    option.eq_ignore_ascii_case("keep-alive")
                        || option.eq_ignore_ascii_case("close")
                });
                if !supported {
                    return Err(NormalizeError::UnsupportedConnectionOption);
                }
            }
            (Side::Ingress, "expect") => {
                // The ingress answers 100-continue locally after admission.
                if !text.eq_ignore_ascii_case("100-continue") {
                    return Err(NormalizeError::UnsupportedExpectation);
                }
            }
            _ => fields.push(HeaderField::new(name.as_str(), text)),
        }
    }
    let length = match lengths.as_slice() {
        [] => None,
        [one] => Some(parse_content_length(one)?),
        _ => return Err(NormalizeError::DuplicateContentLength),
    };
    if !codings.is_empty() {
        if length.is_some() {
            return Err(NormalizeError::TransferEncodingWithContentLength);
        }
        let decoded_chunked = side == Side::Ingress
            && version == Version::HTTP_11
            && matches!(codings.as_slice(), [one] if one.eq_ignore_ascii_case("chunked"));
        if !decoded_chunked {
            return Err(NormalizeError::UnsupportedTransferEncoding);
        }
    }
    Ok((fields, length))
}

/// A validated request head and its encoded `REQUEST_HEAD` record.
/// `Debug` prints the payload-free head summary and the record length.
#[derive(Clone)]
pub struct IngressRequest {
    pub head: RequestHead,
    pub record: Bytes,
}

impl fmt::Debug for IngressRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngressRequest")
            .field("method", &self.head.method)
            .field("http_version", &self.head.http_version)
            .field("headers_len", &self.head.headers.len())
            .field("body_length", &self.head.body_length)
            .field("record_len", &self.record.len())
            .finish()
    }
}

/// Normalize a consumer request.  The ingress consumes `host`; for
/// HTTP/1.1 only, `keep-alive` and `connection: keep-alive|close`;
/// `expect: 100-continue`,
/// a single HTTP/1.1 `transfer-encoding: chunked` (already decoded into body
/// octets by the HTTP library), and `content-length` (carried as the typed
/// `body_length`).  Any URI scheme and authority are transport routing and
/// are likewise not forwarded.
///
/// # Errors
/// Any framing, feature, or codec validation failure.
pub fn request_head(
    parts: &request::Parts,
    policy: &RequestPolicy,
) -> Result<IngressRequest, NormalizeError> {
    let method = match parts.method {
        http::Method::GET => Method::Get,
        http::Method::HEAD => Method::Head,
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::PATCH => Method::Patch,
        http::Method::DELETE => Method::Delete,
        http::Method::OPTIONS => Method::Options,
        http::Method::CONNECT => return Err(NormalizeError::UnsupportedMethod),
        _ => return Err(NormalizeError::Codec(CodecError::InvalidMethod)),
    };
    let http_version = match parts.version {
        Version::HTTP_11 => HttpVersion::Http11,
        Version::HTTP_2 => HttpVersion::Http2,
        _ => return Err(NormalizeError::UnsupportedVersion),
    };
    let (headers, body_length) = scan_headers(&parts.headers, Side::Ingress, parts.version)?;
    let head = RequestHead {
        method,
        path: parts.uri.path().to_owned(),
        query: parts.uri.query().unwrap_or("").to_owned(),
        http_version,
        headers,
        body_length,
    };
    let mut record = Vec::new();
    encode_request_head(&head, policy, &mut record).map_err(NormalizeError::Codec)?;
    if body_length.is_some_and(|length| length > policy.body_limit()) {
        return Err(NormalizeError::DeclaredLengthExceedsLimit);
    }
    Ok(IngressRequest {
        head,
        record: Bytes::from(record),
    })
}

/// A validated handler response head and its encoded `RESPONSE_HEAD` record.
/// `Debug` prints status, counts and lengths only.
#[derive(Clone)]
pub struct HandlerResponse {
    pub head: ResponseHead,
    pub record: Bytes,
    /// HEAD request or 204/205/304: no BODY may follow.
    pub zero_body: bool,
}

impl fmt::Debug for HandlerResponse {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HandlerResponse")
            .field("status", &self.head.status)
            .field("headers_len", &self.head.headers.len())
            .field("body_length", &self.head.body_length)
            .field("record_len", &self.record.len())
            .field("zero_body", &self.zero_body)
            .finish()
    }
}

/// Normalize an in-process handler's response head.  Only `content-length`
/// is consumed (as `body_length`); nothing else is dropped.  For a HEAD
/// request or a 304 it is a representation-size hint and is not forwarded;
/// for 204 and 205 only `0` is accepted.  Actual body bytes are never
/// allowed on these responses.  `exact_body_len` is the body's exact size
/// hint, if it has one.
///
/// # Errors
/// Any framing, feature, zero-body, limit, or codec validation failure.
pub fn response_head(
    parts: &response::Parts,
    exact_body_len: Option<u64>,
    request_method: Method,
    policy: &ResponsePolicy,
) -> Result<HandlerResponse, NormalizeError> {
    let (headers, declared) = scan_headers(&parts.headers, Side::Handler, Version::HTTP_11)?;
    let status = parts.status.as_u16();
    let zero_body = tunnel_http_forward::requires_zero_body(request_method, status);
    let body_length = if zero_body {
        // v1 forwards no representation-size hint for these responses.  A
        // HEAD or 304 Content-Length describes the selected representation
        // (RFC 9110 sections 8.6 and 15.4.5), so it is dropped; a 204 or 205
        // has no content, so only an explicit `0` is tolerated.
        let representation_hint = request_method == Method::Head || status == 304;
        if !representation_hint && declared.is_some_and(|length| length != 0) {
            return Err(NormalizeError::Codec(CodecError::BodyForbidden));
        }
        if exact_body_len.is_some_and(|length| length != 0) {
            return Err(NormalizeError::Codec(CodecError::BodyForbidden));
        }
        Some(0)
    } else {
        if let (Some(declared), Some(exact)) = (declared, exact_body_len)
            && declared != exact
        {
            return Err(NormalizeError::Codec(CodecError::BodyLongerThanDeclared));
        }
        declared.or(exact_body_len)
    };
    let head = ResponseHead {
        status,
        headers,
        body_length,
    };
    let mut record = Vec::new();
    encode_response_head(&head, policy, request_method, &mut record)
        .map_err(NormalizeError::Codec)?;
    if body_length.is_some_and(|length| length > policy.body_limit()) {
        return Err(NormalizeError::DeclaredLengthExceedsLimit);
    }
    Ok(HandlerResponse {
        head,
        record: Bytes::from(record),
        zero_body,
    })
}
