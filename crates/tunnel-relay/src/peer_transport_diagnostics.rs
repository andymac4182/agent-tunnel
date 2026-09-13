//! Bounded diagnostics for one forwarded device peer stream.
//!
//! The relay keeps only saturating role counters and the latest observation
//! for each role.  Transport error text, peer payloads, routes, and
//! credentials never cross this diagnostic boundary.

use std::sync::{Arc, Mutex};

use serde::Serialize;
use uuid::Uuid;

use crate::actor::CarrierKey;

/// The side of a forwarded device peer stream that produced the observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerTransportDiagnosticRole {
    /// The owner relay could not send a response on the selected carrier.
    OwnerSend,
    /// The owner relay stopped receiving the selected carrier's ingress.
    IngressReceive,
}

impl PeerTransportDiagnosticRole {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerSend => "owner_send",
            Self::IngressReceive => "ingress_receive",
        }
    }
}

/// Closed, payload-free categories for one peer-stream terminal observation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerTransportDiagnosticOutcome {
    TimedOut,
    GoAway,
    H3Error,
    QuicError,
    Cancelled,
    /// The authenticated peer membership admission expired.
    TrustExpired,
    Closed,
    ProtocolError,
    Other,
}

impl PeerTransportDiagnosticOutcome {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::TimedOut => "timed_out",
            Self::GoAway => "goaway",
            Self::H3Error => "h3_error",
            Self::QuicError => "quic_error",
            Self::Cancelled => "cancelled",
            Self::TrustExpired => "trust_expired",
            Self::Closed => "closed",
            Self::ProtocolError => "protocol_error",
            Self::Other => "other",
        }
    }
}

/// The bounded identity and terminal category for the latest role event.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PeerTransportDiagnosticEventSnapshot {
    /// Saturating process-local sequence number for observations.
    pub sequence: u64,
    pub device_id: Uuid,
    pub session_id: String,
    pub epoch: u64,
    pub generation: u64,
    pub connection_id: String,
    pub role: PeerTransportDiagnosticRole,
    pub outcome: PeerTransportDiagnosticOutcome,
}

/// Redacted diagnostics retained by the typed relay snapshot.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
pub struct PeerTransportDiagnosticSnapshot {
    /// Number of owner-side response-send observations.
    pub owner_send_count: u64,
    /// Number of owner-side ingress-receive terminal observations.
    pub ingress_receive_count: u64,
    /// Latest owner-side response-send observation, if any.
    pub last_owner_send: Option<PeerTransportDiagnosticEventSnapshot>,
    /// Latest owner-side ingress-receive observation, if any.
    pub last_ingress_receive: Option<PeerTransportDiagnosticEventSnapshot>,
}

#[derive(Default)]
struct PeerTransportDiagnosticState {
    sequence: u64,
    owner_send_count: u64,
    ingress_receive_count: u64,
    last_owner_send: Option<PeerTransportDiagnosticEventSnapshot>,
    last_ingress_receive: Option<PeerTransportDiagnosticEventSnapshot>,
}

/// Cloneable, bounded state for forwarded device transport diagnostics.
#[derive(Clone, Default)]
pub(crate) struct PeerTransportDiagnostics {
    state: Arc<Mutex<PeerTransportDiagnosticState>>,
}

impl PeerTransportDiagnostics {
    /// Record one static observation without retaining transport text.
    pub(crate) fn record(
        &self,
        device_id: Uuid,
        carrier: &CarrierKey,
        role: PeerTransportDiagnosticRole,
        outcome: PeerTransportDiagnosticOutcome,
    ) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sequence = state.sequence.saturating_add(1);
        let event = PeerTransportDiagnosticEventSnapshot {
            sequence: state.sequence,
            device_id,
            session_id: carrier.session.session_id.clone(),
            epoch: carrier.session.epoch,
            generation: carrier.generation,
            connection_id: carrier.connection_id.clone(),
            role,
            outcome,
        };
        match role {
            PeerTransportDiagnosticRole::OwnerSend => {
                state.owner_send_count = state.owner_send_count.saturating_add(1);
                state.last_owner_send = Some(event);
            }
            PeerTransportDiagnosticRole::IngressReceive => {
                state.ingress_receive_count = state.ingress_receive_count.saturating_add(1);
                state.last_ingress_receive = Some(event);
            }
        }
    }

    /// Return the bounded redacted view used by a relay snapshot.
    #[must_use]
    pub(crate) fn snapshot(&self) -> PeerTransportDiagnosticSnapshot {
        let state = self
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        PeerTransportDiagnosticSnapshot {
            owner_send_count: state.owner_send_count,
            ingress_receive_count: state.ingress_receive_count,
            last_owner_send: state.last_owner_send.clone(),
            last_ingress_receive: state.last_ingress_receive.clone(),
        }
    }
}
