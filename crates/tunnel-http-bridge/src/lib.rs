#![forbid(unsafe_code)]
//! Implementation gate 2 of `docs/http-forwarding.md`: the `http-forward/1`
//! codec connected to an in-process streaming Rust HTTP handler.
//!
//! * [`owner::forward`] is the ingress adapter.  It normalizes an
//!   [`http::Request`] with a streaming body, writes `REQUEST_HEAD`, `BODY*`,
//!   `END` and FIN onto a bounded [`stream::FrameSender`], and concurrently
//!   decodes the response direction into an [`http::Response`] whose body
//!   streams.
//! * [`device::serve`] is the handler adapter.  It decodes the request
//!   direction, builds a typed [`http::Request`] and calls an in-process
//!   handler directly: there is no address, listener or socket anywhere in
//!   this crate.  The handler's response is encoded as `RESPONSE_HEAD`,
//!   `BODY*`, `END` and FIN.
//! * [`stream`] is the bounded stand-in for one logical tunnel stream: a
//!   byte-credited queue with ordered FIN and a reserved-capacity RESET.
//!   Gate 3 replaces it with the real owner/peer/device carriers.
//!
//! Both directions of an exchange run concurrently, every queue is bounded,
//! and no lock is held across an await.  Failures before response headers
//! become scoped gateway responses with sanitized `code`/`execution`
//! metadata; failures after headers error the body stream and emit RESET,
//! never a fabricated END.

pub mod body;
pub mod device;
mod exchange;
pub mod normalize;
pub mod owner;
mod pump;
pub mod status;
pub mod stream;

pub use body::{BodyError, BodySender, ChannelBody};
pub use device::{HandlerCancellation, serve};
pub use normalize::NormalizeError;
pub use owner::{ExchangeHandle, forward};
pub use status::{
    ExchangeReport, Execution, GatewayError, Origin, Outcome, ResetDetail, gateway_status,
};
pub use stream::{Frame, FrameReceiver, FrameSender, QueueStats, ResetSignal, SendError, channel};

use std::time::Duration;

use tunnel_http_forward::{RequestPolicy, ResponsePolicy};

/// The selected application profile's policies.  Both endpoints validate
/// against their own copy; per-profile ACP/MCP allowlists are gate-5 work.
#[derive(Clone, Debug)]
pub struct Profile {
    pub request: RequestPolicy,
    pub response: ResponsePolicy,
}

/// Per-exchange adapter limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    /// Capacity, in chunks, of the queue between a pump and the local HTTP
    /// body it feeds.  Each chunk is at most one BODY payload (65,528 bytes).
    pub body_queue: usize,
    /// Absolute wall-clock application deadline for the whole exchange.
    pub deadline: Option<Duration>,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            body_queue: 4,
            deadline: None,
        }
    }
}
