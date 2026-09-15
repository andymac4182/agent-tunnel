//! Execution knowledge, reset detail, exchange reports and gateway responses.

use bytes::Bytes;
use http::{HeaderValue, Response, StatusCode, header};
use tunnel_http_forward::HttpErrorCode;

use crate::body::ChannelBody;

/// What the reporting endpoint knows about handler invocation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Execution {
    /// Proven not invoked: nothing that could dispatch left this endpoint,
    /// or the device's authoritative dispatch record says so.
    NotDispatched,
    /// The device invoked the handler.
    Dispatched,
    /// Forwarding could have reached the device, with no proof either way.
    Unknown,
}

impl Execution {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotDispatched => "not_dispatched",
            Self::Dispatched => "dispatched",
            Self::Unknown => "unknown",
        }
    }

    /// Parse the exact wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        [Self::NotDispatched, Self::Dispatched, Self::Unknown]
            .into_iter()
            .find(|execution| execution.as_str() == text)
    }

    pub(crate) const fn to_u8(self) -> u8 {
        match self {
            Self::NotDispatched => 0,
            Self::Dispatched => 1,
            Self::Unknown => 2,
        }
    }

    pub(crate) const fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::NotDispatched,
            1 => Self::Dispatched,
            _ => Self::Unknown,
        }
    }
}

/// The detail an outer RESET stands for in this stand-in: the protocol
/// reason code plus the bounded `RESULT_STATUS` metadata that gate 3 carries
/// separately.  It contains no payload bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ResetDetail {
    pub code: HttpErrorCode,
    pub execution: Execution,
}

/// Which side a failure is attributed to, for the gateway status only.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Origin {
    /// The consumer's request head or body was invalid, or it went away.
    Consumer,
    /// The tunnel, the device, or the handler failed or timed out.
    Upstream,
}

/// A direction's terminal state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Outcome {
    /// Never reached a terminal state (only seen in a lost report).
    Pending,
    /// HEAD, BODY*, END and FIN all passed.
    Complete,
    /// Reset, failed validation, or was cancelled before completion.
    Aborted,
}

/// The terminal status of one exchange as seen by one endpoint.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ExchangeReport {
    pub request: Outcome,
    pub response: Outcome,
    pub execution: Execution,
    /// The first failure recorded, if any.
    pub error: Option<HttpErrorCode>,
}

/// Response extension on a gateway-generated response.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct GatewayError {
    pub code: HttpErrorCode,
    pub execution: Execution,
}

/// The scoped status for a failure before response headers are committed.
#[must_use]
pub const fn gateway_status(
    origin: Origin,
    code: HttpErrorCode,
    execution: Execution,
) -> StatusCode {
    match (origin, code, execution) {
        (Origin::Consumer, HttpErrorCode::BodyLimit, _) => StatusCode::PAYLOAD_TOO_LARGE,
        (Origin::Consumer, HttpErrorCode::UnsupportedFeature, _) => StatusCode::NOT_IMPLEMENTED,
        (Origin::Consumer, _, _) => StatusCode::BAD_REQUEST,
        (Origin::Upstream, HttpErrorCode::DeadlineExceeded, _) => StatusCode::GATEWAY_TIMEOUT,
        (Origin::Upstream, HttpErrorCode::StreamInterrupted, Execution::NotDispatched) => {
            StatusCode::SERVICE_UNAVAILABLE
        }
        (Origin::Upstream, _, _) => StatusCode::BAD_GATEWAY,
    }
}

/// Build a gateway response carrying only the sanitized code and execution.
pub(crate) fn gateway_response(
    status: StatusCode,
    code: HttpErrorCode,
    execution: Execution,
) -> Response<ChannelBody> {
    let json = format!(
        "{{\"error\":{{\"code\":\"{}\",\"execution\":\"{}\"}}}}",
        code.as_str(),
        execution.as_str()
    );
    let mut response = Response::new(ChannelBody::full(Bytes::from(json)));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
        .extensions_mut()
        .insert(GatewayError { code, execution });
    response
}
