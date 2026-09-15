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
pub use stream::{
    Frame, FrameReceiver, FrameSender, QueueStats, ResetSignal, SendError, SignaledReset, channel,
};

use std::time::Duration;

use tunnel_http_forward::{RequestPolicy, ResponsePolicy};

/// The selected application profile's policies.  Both endpoints validate
/// against their own copy; per-profile ACP/MCP allowlists are gate-5 work.
#[derive(Clone, Debug)]
pub struct Profile {
    pub request: RequestPolicy,
    pub response: ResponsePolicy,
}

/// The default absolute application deadline for one exchange.
pub const DEFAULT_DEADLINE: Duration = Duration::from_secs(300);
/// The hard ceiling on a configured deadline.  There is no unlimited value.
pub const MAX_DEADLINE: Duration = Duration::from_secs(24 * 60 * 60);
/// The longest grace after the deadline during which an endpoint that has
/// aborted keeps discarding peer frames, so its RESET can reach the peer
/// before the receiver is dropped.  The grace is also capped by the
/// configured deadline itself.
pub const DISCARD_GRACE: Duration = Duration::from_secs(5);
/// The default body queue, in chunks.
pub const DEFAULT_BODY_QUEUE: usize = 4;
/// The hard ceiling on the body queue, in chunks.
pub const MAX_BODY_QUEUE: usize = 64;

/// A rejected adapter configuration.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ConfigError {
    /// Zero, or above [`MAX_DEADLINE`].
    Deadline,
    /// Zero, or above [`MAX_BODY_QUEUE`].
    BodyQueue,
}

impl core::fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "invalid http bridge configuration: {self:?}")
    }
}

impl std::error::Error for ConfigError {}

/// Per-exchange adapter limits.  Both are finite and bounded by
/// construction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BridgeConfig {
    body_queue: usize,
    deadline: Duration,
}

impl Default for BridgeConfig {
    fn default() -> Self {
        Self {
            body_queue: DEFAULT_BODY_QUEUE,
            deadline: DEFAULT_DEADLINE,
        }
    }
}

impl BridgeConfig {
    /// Set the absolute application deadline for the whole exchange.  It
    /// also bounds terminal discard of a peer that never finishes.
    ///
    /// # Errors
    /// [`ConfigError::Deadline`] for zero or above [`MAX_DEADLINE`].
    pub fn with_deadline(self, deadline: Duration) -> Result<Self, ConfigError> {
        if deadline.is_zero() || deadline > MAX_DEADLINE {
            return Err(ConfigError::Deadline);
        }
        Ok(Self { deadline, ..self })
    }

    /// Set the queue capacity, in chunks, between a pump and the local HTTP
    /// body it feeds.  Each chunk is at most one BODY payload.
    ///
    /// # Errors
    /// [`ConfigError::BodyQueue`] for zero or above [`MAX_BODY_QUEUE`].
    pub fn with_body_queue(self, body_queue: usize) -> Result<Self, ConfigError> {
        if body_queue == 0 || body_queue > MAX_BODY_QUEUE {
            return Err(ConfigError::BodyQueue);
        }
        Ok(Self { body_queue, ..self })
    }

    #[must_use]
    pub const fn deadline(&self) -> Duration {
        self.deadline
    }

    /// How long after the exchange starts terminal discard may continue:
    /// the deadline plus `min(deadline, DISCARD_GRACE)`.
    #[must_use]
    pub fn discard_bound(&self) -> Duration {
        let grace = if self.deadline < DISCARD_GRACE {
            self.deadline
        } else {
            DISCARD_GRACE
        };
        self.deadline.saturating_add(grace)
    }

    #[must_use]
    pub const fn body_queue(&self) -> usize {
        self.body_queue
    }
}
