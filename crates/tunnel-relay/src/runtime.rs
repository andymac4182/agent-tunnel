//! Runtime-only M2 identities and bounded diagnostics.
//!
//! The transport actor remains the owner of mutable session state.  This
//! module contains the small immutable values shared by socket events and the
//! redacted snapshots consumed by an in-process harness.  It deliberately has
//! no public HTTP endpoint and never stores payloads or credentials.

use serde::Serialize;
use tunnel_protocol::rotation::RotationPhase;

use crate::wire;

/// Negotiated runtime profile for one connector session.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RuntimeProfile {
    M1,
    M2,
}

impl RuntimeProfile {
    pub(crate) const fn supports_rotation(self) -> bool {
        matches!(self, Self::M2)
    }

    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::M1 => "m1",
            Self::M2 => "m2",
        }
    }
}

/// A physical carrier identity.  Every data event carries this complete
/// context; a session key alone cannot route bytes from an old generation.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize)]
pub(crate) struct CarrierContext {
    pub(crate) session_id: String,
    pub(crate) epoch: u64,
    pub(crate) generation: u64,
    pub(crate) connection_id: String,
}

impl CarrierContext {
    pub(crate) fn new(
        session_id: impl Into<String>,
        epoch: u64,
        generation: u64,
        connection_id: impl Into<String>,
    ) -> Self {
        Self {
            session_id: session_id.into(),
            epoch,
            generation,
            connection_id: connection_id.into(),
        }
    }
}

/// Redacted carrier counters in a relay diagnostic snapshot.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelayCarrierSnapshot {
    pub generation: u64,
    pub connection_id: String,
    pub active: bool,
    pub allocated: bool,
    pub queued_bytes: usize,
}

/// Redacted logical stream counters.  Sequence values are transport
/// metadata, never application payload or operation arguments.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelayStreamSnapshot {
    pub stream_id: u64,
    /// Stable logical operation identity.  It remains unchanged across
    /// carrier generations and is safe for an internal harness to correlate.
    pub operation_id: String,
    pub last_emitted_relay_to_connector: u64,
    pub peer_acked_relay_to_connector: u64,
    pub recv_contiguous_connector_to_relay: u64,
    pub delivered_contiguous_connector_to_relay: u64,
    pub replay_frames_relay_to_connector: usize,
    pub replay_bytes_relay_to_connector: usize,
    pub queue_bytes: usize,
    pub terminal: bool,
}

/// Redacted per-device runtime view.  Identifiers are retained because the
/// in-process harness needs to correlate events; credentials and payloads are
/// absent by construction.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelaySessionSnapshot {
    pub device_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub profile: &'static str,
    pub phase: String,
    pub active_generation: u64,
    pub active_connection_id: String,
    pub candidate_generation: Option<u64>,
    pub candidate_connection_id: Option<String>,
    pub sockets: u8,
    pub queue_bytes: usize,
    pub queue_messages: usize,
    pub drain_fences: usize,
    pub drain_proofs: usize,
    pub replay_frames: usize,
    pub replay_bytes: usize,
    /// Number of successfully completed clean rotations for this session.
    pub rotations_completed: u64,
    /// Monotonic replay count.  A clean rotation leaves this at zero; a
    /// recovery replay increments it without exposing frame payloads.
    pub total_replayed_frames: u64,
    pub streams: Vec<RelayStreamSnapshot>,
}

/// Redacted relay diagnostic payload returned only through the typed handle.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelaySnapshot {
    pub sessions: Vec<RelaySessionSnapshot>,
}

/// Convert the protocol phase to a stable diagnostics string without exposing
/// internal enum layout to consumers.
pub(crate) fn phase_name(phase: RotationPhase) -> String {
    match phase {
        RotationPhase::Active => "active",
        RotationPhase::Preparing => "preparing",
        RotationPhase::Quiescing => "quiescing",
        RotationPhase::Draining => "draining",
        RotationPhase::Committing => "committing",
        RotationPhase::Retiring => "retiring",
        RotationPhase::Aborting => "aborting",
        RotationPhase::Recovering => "recovering",
        RotationPhase::Closed => "closed",
    }
    .to_owned()
}

pub(crate) fn protocol_rotation_config_ms(
    interval_ms: u64,
    handshake_ms: u64,
    overlap_ms: u64,
) -> Result<tunnel_protocol::rotation::RotationConfig, &'static str> {
    tunnel_protocol::rotation::RotationConfig::new(interval_ms, handshake_ms, overlap_ms)
        .map_err(|_| "invalid rotation policy")
}

/// Keep the digest implementation centralized for callers that need to bind
/// an attempt identity to the exact owner token.
pub(crate) fn owner_id(owner: &tunnel_catalog::OwnerToken) -> String {
    wire::owner_id(owner)
}
