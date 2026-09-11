//! Bounded terminal diagnostics for forwarded consumer peer streams.
//!
//! Device data and consumer streams use separate HTTP/3 routes.  The relay
//! already retains typed terminal observations for forwarded device carriers;
//! this companion keeps the same distinction for consumer streams so a data
//! carrier failure cannot be mistaken for a public response-writer timeout.
//! Only saturating counters and the latest closed-category event are retained.

use std::{
    sync::{Arc, Mutex, OnceLock},
    time::Instant,
};

use serde::Serialize;
use uuid::Uuid;

use crate::peer_transport_diagnostics::PeerTransportDiagnosticOutcome;

/// The side of the forwarded consumer peer exchange that observed a terminal
/// event.  The names describe the relay-local direction, not a user payload.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConsumerDiagnosticRole {
    /// The ingress relay could not forward a consumer request to the owner.
    IngressSend,
    /// The ingress relay could not receive a consumer response from the owner.
    IngressReceive,
    /// The owner relay could not send a consumer response to the ingress.
    OwnerSend,
    /// The owner relay could not receive a consumer request from the ingress.
    OwnerReceive,
}

/// Closed allowlist of HTTP/3 application codes retained for a consumer-peer
/// terminal event.  The original transport error text is never retained.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerConsumerDiagnosticH3Code {
    /// The peer sent a frame that was not valid in the current stream state.
    FrameUnexpected,
    /// The request or response stream was cancelled.
    RequestCancelled,
    /// The HTTP/3 connection closed without an error.
    NoError,
    /// An HTTP/3 error did not match the bounded allowlist.
    Other,
}

impl PeerConsumerDiagnosticH3Code {
    /// Return the stable redacted diagnostic label.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::FrameUnexpected => "h3_frame_unexpected",
            Self::RequestCancelled => "h3_request_cancelled",
            Self::NoError => "h3_no_error",
            Self::Other => "h3_other",
        }
    }
}

/// Authenticated bounded identity for one forwarded consumer request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PeerConsumerDiagnosticContext {
    pub(crate) tenant_id: Uuid,
    pub(crate) device_id: Uuid,
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
    pub(crate) service_id: Uuid,
    pub(crate) request_id: String,
}

impl PeerConsumerDiagnosticRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::IngressSend => "ingress_send",
            Self::IngressReceive => "ingress_receive",
            Self::OwnerSend => "owner_send",
            Self::OwnerReceive => "owner_receive",
        }
    }
}

/// One bounded terminal event for a forwarded consumer stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerConsumerDiagnosticEventSnapshot {
    /// Saturating process-local sequence number.
    pub sequence: u64,
    /// Milliseconds from this relay process's monotonic diagnostic origin.
    /// Values from separate relay processes are not directly comparable.
    pub observed_at_ms: u64,
    pub tenant_id: Uuid,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub service_id: Uuid,
    pub request_id: String,
    pub role: PeerConsumerDiagnosticRole,
    pub outcome: PeerTransportDiagnosticOutcome,
    pub h3_code: Option<PeerConsumerDiagnosticH3Code>,
}

/// Redacted consumer-peer terminal observations retained by a relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerConsumerDiagnosticSnapshot {
    pub ingress_send_count: u64,
    pub ingress_receive_count: u64,
    pub owner_send_count: u64,
    pub owner_receive_count: u64,
    pub last_ingress_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_ingress_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_owner_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    pub last_owner_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
}

#[derive(Default)]
struct PeerConsumerDiagnosticState {
    sequence: u64,
    ingress_send_count: u64,
    ingress_receive_count: u64,
    owner_send_count: u64,
    owner_receive_count: u64,
    last_ingress_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    last_ingress_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
    last_owner_send: Option<PeerConsumerDiagnosticEventSnapshot>,
    last_owner_receive: Option<PeerConsumerDiagnosticEventSnapshot>,
}

/// Cloneable bounded state for the consumer peer route.
#[derive(Clone, Default)]
pub(crate) struct PeerConsumerDiagnostics {
    state: Arc<Mutex<PeerConsumerDiagnosticState>>,
}

impl PeerConsumerDiagnostics {
    /// Record one typed terminal outcome without retaining transport text.
    pub(crate) fn record(
        &self,
        context: &PeerConsumerDiagnosticContext,
        role: PeerConsumerDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
        h3_code: Option<PeerConsumerDiagnosticH3Code>,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        let event = PeerConsumerDiagnosticEventSnapshot {
            sequence: state.sequence,
            observed_at_ms: diagnostic_now_ms(),
            tenant_id: context.tenant_id,
            device_id: context.device_id,
            session_id: context.session_id.clone(),
            epoch: context.epoch,
            service_id: context.service_id,
            request_id: context.request_id.clone(),
            role,
            outcome,
            h3_code,
        };
        match role {
            PeerConsumerDiagnosticRole::IngressSend => {
                state.ingress_send_count = state.ingress_send_count.saturating_add(1);
                state.last_ingress_send = Some(event);
            }
            PeerConsumerDiagnosticRole::IngressReceive => {
                state.ingress_receive_count = state.ingress_receive_count.saturating_add(1);
                state.last_ingress_receive = Some(event);
            }
            PeerConsumerDiagnosticRole::OwnerSend => {
                state.owner_send_count = state.owner_send_count.saturating_add(1);
                state.last_owner_send = Some(event);
            }
            PeerConsumerDiagnosticRole::OwnerReceive => {
                state.owner_receive_count = state.owner_receive_count.saturating_add(1);
                state.last_owner_receive = Some(event);
            }
        }
    }

    /// Return the bounded typed view used by the relay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerConsumerDiagnosticSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PeerConsumerDiagnosticSnapshot {
            ingress_send_count: state.ingress_send_count,
            ingress_receive_count: state.ingress_receive_count,
            owner_send_count: state.owner_send_count,
            owner_receive_count: state.owner_receive_count,
            last_ingress_send: state.last_ingress_send.clone(),
            last_ingress_receive: state.last_ingress_receive.clone(),
            last_owner_send: state.last_owner_send.clone(),
            last_owner_receive: state.last_owner_receive.clone(),
        }
    }
}

static DIAGNOSTIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

fn diagnostic_now_ms() -> u64 {
    DIAGNOSTIC_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}

/// Classify a transport error using only the bounded H3 code allowlist.
///
/// The input is inspected transiently at the relay boundary and is never
/// copied into a snapshot or emitted as a diagnostic string.
pub(crate) fn classify_h3_code(message: &str) -> PeerConsumerDiagnosticH3Code {
    if message.contains("H3_FRAME_UNEXPECTED") {
        PeerConsumerDiagnosticH3Code::FrameUnexpected
    } else if message.contains("H3_REQUEST_CANCELLED") {
        PeerConsumerDiagnosticH3Code::RequestCancelled
    } else if message.contains("H3_NO_ERROR") {
        PeerConsumerDiagnosticH3Code::NoError
    } else {
        PeerConsumerDiagnosticH3Code::Other
    }
}

#[cfg(test)]
mod tests {
    use uuid::Uuid;

    use crate::peer_transport_diagnostics::PeerTransportDiagnosticOutcome;

    use super::{
        PeerConsumerDiagnosticContext, PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
        PeerConsumerDiagnostics, classify_h3_code,
    };

    #[test]
    fn h3_diagnostic_classification_is_closed_and_redacted() {
        assert_eq!(
            classify_h3_code("H3_FRAME_UNEXPECTED: secret transport detail"),
            PeerConsumerDiagnosticH3Code::FrameUnexpected
        );
        assert_eq!(
            classify_h3_code("H3_REQUEST_CANCELLED"),
            PeerConsumerDiagnosticH3Code::RequestCancelled
        );
        assert_eq!(
            classify_h3_code("H3_NO_ERROR"),
            PeerConsumerDiagnosticH3Code::NoError
        );
        assert_eq!(
            classify_h3_code("unrecognized transport detail"),
            PeerConsumerDiagnosticH3Code::Other
        );
    }

    #[test]
    fn event_snapshot_keeps_exact_bounded_forwarding_identity() {
        let diagnostics = PeerConsumerDiagnostics::default();
        let context = PeerConsumerDiagnosticContext {
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            session_id: "session-7".to_owned(),
            epoch: 9,
            service_id: Uuid::from_u128(3),
            request_id: "request-11".to_owned(),
        };

        diagnostics.record(
            &context,
            PeerConsumerDiagnosticRole::OwnerSend,
            PeerTransportDiagnosticOutcome::H3Error,
            Some(PeerConsumerDiagnosticH3Code::FrameUnexpected),
        );

        let snapshot = diagnostics.snapshot();
        let event = snapshot.last_owner_send.expect("owner event is retained");
        assert_eq!(snapshot.owner_send_count, 1);
        assert_eq!(event.sequence, 1);
        assert_eq!(event.tenant_id, context.tenant_id);
        assert_eq!(event.device_id, context.device_id);
        assert_eq!(event.session_id, context.session_id);
        assert_eq!(event.epoch, context.epoch);
        assert_eq!(event.service_id, context.service_id);
        assert_eq!(event.request_id, context.request_id);
        assert_eq!(
            event.h3_code,
            Some(PeerConsumerDiagnosticH3Code::FrameUnexpected)
        );

        diagnostics.record(
            &context,
            PeerConsumerDiagnosticRole::IngressReceive,
            PeerTransportDiagnosticOutcome::Closed,
            None,
        );
        let second = diagnostics
            .snapshot()
            .last_ingress_receive
            .expect("ingress event is retained");
        assert!(event.observed_at_ms <= second.observed_at_ms);
    }
}
