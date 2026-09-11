//! Runtime-only M2 identities and bounded diagnostics.
//!
//! The transport actor remains the owner of mutable session state.  This
//! module contains the small immutable values shared by socket events and the
//! redacted snapshots consumed by an in-process harness.  It deliberately has
//! no public HTTP endpoint and never stores payloads or credentials.

use serde::Serialize;
use sha2::{Digest, Sha256};
use std::{sync::OnceLock, time::Instant};
use tunnel_protocol::rotation::{RecoveryReason, RotationPhase};
use tunnel_protocol::rotation_control::RotationAttemptIdentity;

use crate::{
    consumer_write_diagnostics::ConsumerWriteDiagnosticSnapshot,
    peer_consumer_transport_diagnostics::PeerConsumerDiagnosticSnapshot,
    peer_transport_diagnostics::PeerTransportDiagnosticSnapshot, wire,
};

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
    /// Whether Axum entered the public WebSocket upgrade callback and claimed
    /// the registration lease. A false value at the fixture barrier proves
    /// that the public callback has not claimed the local registration yet.
    pub admission_claimed: bool,
    /// Whether the relay is waiting for the connector's current
    /// challenge-bound authority result.  This is a live state bit, never a
    /// history of challenges.
    pub authorization_in_flight: bool,
    /// Monotonic receive time of the current challenge, when in flight.
    pub authorization_started_at_ms: Option<u64>,
    /// Monotonic challenge deadline, when in flight.
    pub authorization_deadline_ms: Option<u64>,
    /// Monotonic admission deadline for the previously confirmed grant.
    /// This remains visible while a refresh challenge is in flight so a
    /// harness can wait for the old grant to expire before sending a probe.
    pub authorization_admission_deadline_ms: Option<u64>,
    /// Fixed authorization failure code, when this stream hit the relay's
    /// authoritative admission check.  This is deliberately a closed,
    /// payload-free code rather than the internal reason string.
    pub authorization_failure_code: Option<&'static str>,
}

/// Payload-free transient rotation evidence for bounded acceptance probes.
/// Fence digests, sequence cursors and lifecycle bits are retained without
/// payloads or adapter events.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelayRotationSnapshot {
    pub snapshot_id: Option<String>,
    pub attempt: Option<RotationAttemptIdentity>,
    pub attempt_active: bool,
    pub relay_fence_digest: Option<String>,
    pub connector_fence_digest: Option<String>,
    pub relay_fence_sequences: Vec<(u64, u64)>,
    pub connector_fence_sequences: Vec<(u64, u64)>,
    pub relay_ack_sequences: Vec<(u64, u64)>,
    pub connector_ack_sequences: Vec<(u64, u64)>,
    pub writer_barrier_flushed: [bool; 2],
    pub candidate_ready: bool,
    pub commit_sent: bool,
    pub commit_accepted: bool,
    pub old_socket_closed: [bool; 2],
}

/// Redacted per-device runtime view.  Identifiers are retained because the
/// in-process harness needs to correlate events; credentials and payloads are
/// absent by construction.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelaySessionSnapshot {
    pub tenant_id: String,
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
    /// Monotonic protocol time at which the current rotation attempt began.
    pub rotation_started_at_ms: Option<u64>,
    /// Monotonic protocol deadline for the current rotation attempt.
    pub rotation_deadline_ms: Option<u64>,
    /// Closed recovery reason retained by the rotation state machine.
    pub rotation_recovery_reason: Option<&'static str>,
    /// Whether the old carrier was retired after the configured overlap
    /// deadline and therefore forced the state machine into recovery.
    pub rotation_deadline_forced_retirement: bool,
    pub rotation_diagnostics: Option<RelayRotationSnapshot>,
    pub streams: Vec<RelayStreamSnapshot>,
}

/// A bounded, payload-free record of a relay rotation deadline firing.
///
/// The actor latches this record before fail-closed session removal so an
/// in-process harness can correlate a deadline even when the live session is
/// no longer present in the ordinary snapshot.  All identity and timing
/// fields come from the authenticated rotation attempt and relay monotonic
/// clock; no frame body, credential, or transport error text is retained.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct RotationDeadlineEvent {
    pub tenant_id: String,
    pub device_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub old_generation: u64,
    pub old_connection_id: String,
    pub candidate_generation: u64,
    pub candidate_connection_id: String,
    pub started_at_ms: u64,
    pub deadline_ms: u64,
    pub fired_at_ms: u64,
    pub reason: &'static str,
}

/// A bounded, payload-free record of a session terminal path.
///
/// This is captured before the actor removes the live session so diagnostics
/// can distinguish an ordinary close path from a deadline event.  It is
/// observational only: it does not keep the session alive or change the
/// state-machine decision that caused the close.  `reason` is always mapped
/// through the closed vocabulary below; internal error text never crosses the
/// runtime snapshot boundary.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct SessionTerminalEvent {
    pub tenant_id: String,
    pub device_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub active_generation: u64,
    pub active_connection_id: String,
    pub candidate_generation: Option<u64>,
    pub candidate_connection_id: Option<String>,
    pub rotation_id: Option<String>,
    pub rotation_started_at_ms: Option<u64>,
    pub rotation_deadline_ms: Option<u64>,
    pub closed_at_ms: u64,
    pub reason: &'static str,
}

/// Typed causes that can be attached to a logical stream terminal latch.
///
/// The cause is deliberately closed and payload-free. A generic terminal
/// close remains unclassified; callers must prove the corresponding
/// membership/route transition separately before attributing expiry.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum StreamTerminalCause {
    /// The forwarded stream's peer membership admission reached its signed
    /// trust deadline or was invalidated for trust expiry.  The cause is
    /// resolved from the admission edge itself, never from later absence of
    /// the stream or session.
    PeerMembershipExpired,
}

/// A bounded, payload-free latch for one logical consumer stream's terminal
/// transition. It is captured before STREAM_FORGET removes the stream, so a
/// diagnostic observer cannot turn a fast reclamation into an absence-as-pass
/// result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StreamTerminalEvent {
    pub tenant_id: String,
    pub device_id: String,
    pub session_id: String,
    pub epoch: u64,
    /// Full owner fencing identity. These are bounded catalog IDs, not
    /// credentials or payloads, and all are required for exact correlation.
    pub deployment_incarnation: String,
    pub node_id: String,
    pub boot_id: String,
    pub owner_id: String,
    pub stream_id: u64,
    pub operation_id: String,
    /// The authenticated peer envelope request, when routed consumer ingress
    /// supplied one. Local public streams leave this absent.
    pub request_id: Option<String>,
    pub active_generation: u64,
    pub active_connection_id: String,
    pub rotations_completed: u64,
    pub total_replayed_frames: u64,
    pub last_emitted_relay_to_connector: u64,
    pub peer_acked_relay_to_connector: u64,
    pub recv_contiguous_connector_to_relay: u64,
    pub delivered_contiguous_connector_to_relay: u64,
    pub closed_at_ms: u64,
    pub authorization_failure_code: Option<&'static str>,
    pub reason: &'static str,
    pub cause: Option<StreamTerminalCause>,
}

/// A bounded, payload-free receipt for one actual connector `FIN`/`RESET`.
///
/// This is deliberately separate from [`StreamTerminalEvent`]: the latter
/// records the first logical terminal transition and stays immutable for
/// lifecycle and authorization diagnostics, so it may predate the connector's
/// terminal frame (for example when the public side closed first). A late
/// DATA/FIN receipt therefore needs its own record that proves the exact
/// connector-to-relay final receive cursor, the terminal sequence and the
/// physical carrier that accepted the frame. It survives STREAM_FORGET and
/// session removal so an observer cannot read a fast reclamation as an absence
/// of receipt.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct StreamTerminalReceiptEvent {
    pub tenant_id: String,
    pub device_id: String,
    pub session_id: String,
    pub epoch: u64,
    /// Full owner fencing identity. These are bounded catalog IDs, not
    /// credentials or payloads, and all are required for exact correlation.
    pub deployment_incarnation: String,
    pub node_id: String,
    pub boot_id: String,
    pub owner_id: String,
    pub stream_id: u64,
    pub operation_id: String,
    /// The authenticated peer envelope request, when routed consumer ingress
    /// supplied one. Local public streams leave this absent.
    pub request_id: Option<String>,
    /// The exact physical carrier that authenticated and processed the
    /// terminal frame, captured from the `CarrierKey` rather than inferred
    /// from mutable rotation state.
    pub active_generation: u64,
    pub active_connection_id: String,
    pub recv_contiguous_connector_to_relay: u64,
    pub delivered_contiguous_connector_to_relay: u64,
    /// The connector-to-relay terminal sequence, which must equal the final
    /// contiguous receive cursor for a complete, gap-free FIN/RESET.
    pub receive_terminal_sequence: u64,
    pub last_emitted_relay_to_connector: u64,
    pub peer_acked_relay_to_connector: u64,
    pub replay_bytes_relay_to_connector: usize,
    pub queue_bytes: usize,
    pub observed_at_ms: u64,
}

/// Keep terminal diagnostics stable and bounded even when a future caller
/// passes a new internal close string.  Known protocol and lifecycle paths
/// retain their exact allowlisted labels; everything else is deliberately
/// redacted to one fixed category.
pub(crate) fn terminal_close_reason(reason: &str) -> &'static str {
    const ALLOWED: &[&str] = &[
        "ATTACHMENT_TICKET_UNAVAILABLE",
        "ATTACHMENT_TICKET_EXPIRED",
        "ROTATION_PREPARE_INVALID",
        "ROTATION_PREPARE_QUEUE",
        "CONNECTION_HISTORY_EXHAUSTED",
        "RECOVERY_READY_CONFLICT",
        "RECOVERY_READY_FAILED",
        "RECOVERY_STATE_LOST",
        "ROTATION_JOURNAL_RESPONSE",
        "ROTATION_JOURNAL_REPLAY",
        "ROTATION_JOURNAL_INVALID",
        "STALE_CONTROL",
        "ROTATION_START_FAILED",
        "ROTATION_DUPLICATE_STATE",
        "UNEXPECTED_ROTATE_ABORT",
        "UNEXPECTED_RECOVERY_BEGIN",
        "FRAME_LIMIT",
        "INVALID_FRAME",
        "STALE_DATA",
        "UNKNOWN_STREAM",
        "INVALID_SEQUENCE",
        "DEVICE_OFFLINE",
        "REVERSE_CHANNEL_UNAVAILABLE",
        "STALE_ACK",
        "INVALID_RESET",
        "RECOVERY_QUEUE_LIMIT",
        "OWNER_FENCE_TIMEOUT",
        "OPEN_ADMISSION_TIMEOUT",
        "OWNER_FORGET_TIMEOUT",
        "TERMINAL_FIN_TIMEOUT",
        "UNEXPECTED_STREAM_FORGET",
        "ROTATION_DEADLINE_EXPIRED",
        "OWNER_FENCED",
        "AUTHORITY_UNAVAILABLE",
        "AUTHORIZATION_REVOKED",
        "CONTROL_CLOSED",
        "ROTATION_CANDIDATE_FAILED",
        "RECOVERY_START_FAILED",
        "RECOVERY_CANDIDATE_FAILED",
        "SHUTDOWN",
        "UNEXPECTED_OWNER_FENCED",
        "OWNER_FENCE_CONTEXT",
        "OWNER_FENCE_DUPLICATE",
        "OWNER_FENCE_DEADLINE",
        "OWNER_FENCE_MISSING",
        "STREAM_CLOSED",
    ];
    ALLOWED
        .iter()
        .copied()
        .find(|allowed| *allowed == reason)
        .unwrap_or("OTHER")
}

/// Redacted relay diagnostic payload returned only through the typed handle.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RelaySnapshot {
    /// Relay-local monotonic sample time for the redacted timestamp fields.
    pub monotonic_now_ms: u64,
    /// Monotonic count of application records accepted for outbound relay
    /// dispatch by this actor.  Control frames and session cleanup do not
    /// affect the value, so a harness can compare it across reconnects.
    pub lifetime_application_dispatches: u64,
    /// Monotonic count of authenticated owner-side `ConsumerChunk` records
    /// actually consumed from peer streams.  This is payload-free and is
    /// distinct from public HTTP request-body consumption or dispatch count.
    pub lifetime_consumer_chunk_reads: u64,
    /// Monotonic count of authoritative duplicate-control/owner-busy
    /// admission rejections.  It contains no identity or error payload.
    pub control_registration_conflicts: u64,
    /// Bounded public consumer response-write timeout diagnostics.  The
    /// scope contains only device/service identifiers and ingress kind.
    pub consumer_write_diagnostics: ConsumerWriteDiagnosticSnapshot,
    /// Bounded terminal observations for one forwarded device carrier.  The
    /// identity is physical-carrier metadata; no transport text or payload is
    /// retained.
    pub peer_transport_diagnostics: PeerTransportDiagnosticSnapshot,
    /// Bounded terminal observations for forwarded consumer HTTP/3 streams.
    /// This is separate from device-carrier diagnostics so a data-carrier
    /// failure cannot be misread as a public response-writer timeout.
    pub peer_consumer_diagnostics: PeerConsumerDiagnosticSnapshot,
    /// Bounded deadline events retained after the corresponding owner session
    /// is removed.  The list is diagnostics-only and does not alter deadline
    /// or cleanup behavior.
    pub rotation_deadline_events: Vec<RotationDeadlineEvent>,
    /// Bounded terminal close events captured immediately before session
    /// removal.  These are diagnostics-only and do not imply a deadline.
    pub session_terminal_events: Vec<SessionTerminalEvent>,
    /// Bounded per-stream terminal latches captured before STREAM_FORGET.
    pub stream_terminal_events: Vec<StreamTerminalEvent>,
    /// Bounded receipts for an actual connector FIN/RESET. These are separate
    /// from the immutable first-terminal latches above because a connector
    /// terminal frame may arrive after the first logical terminal transition.
    pub stream_terminal_receipt_events: Vec<StreamTerminalReceiptEvent>,
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

/// Map the protocol's closed recovery enum to a bounded diagnostic label.
/// Keep the mapping here so no internal error text or unbounded reason can
/// cross the runtime snapshot boundary.
pub(crate) const fn recovery_reason_name(reason: RecoveryReason) -> &'static str {
    match reason {
        RecoveryReason::Deadline => "deadline",
        RecoveryReason::OldTransportLost => "old_transport_lost",
        RecoveryReason::CandidateTransportLost => "candidate_transport_lost",
        RecoveryReason::ControlLost => "control_lost",
        RecoveryReason::CommitUncertain => "commit_uncertain",
        RecoveryReason::ReconciliationConflict => "reconciliation_conflict",
        RecoveryReason::MissingRetainedBytes => "missing_retained_bytes",
    }
}

pub(crate) fn protocol_rotation_config_ms(
    interval_ms: u64,
    handshake_ms: u64,
    overlap_ms: u64,
) -> Result<tunnel_protocol::rotation::RotationConfig, &'static str> {
    tunnel_protocol::rotation::RotationConfig::new(interval_ms, handshake_ms, overlap_ms)
        .map_err(|_| "invalid rotation policy")
}

/// Process-local monotonic origin shared by actor and membership diagnostics.
/// A deadline sampled by the membership runtime and a terminal event emitted
/// by the actor can therefore be compared without converting wall-clock time
/// in a harness.
static MONOTONIC_ORIGIN: OnceLock<Instant> = OnceLock::new();

pub(crate) fn monotonic_millis() -> u64 {
    MONOTONIC_ORIGIN
        .get_or_init(Instant::now)
        .elapsed()
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

pub(crate) fn monotonic_millis_at(instant: Instant) -> u64 {
    let origin = *MONOTONIC_ORIGIN.get_or_init(Instant::now);
    instant
        .saturating_duration_since(origin)
        .as_millis()
        .min(u128::from(u64::MAX)) as u64
}

/// Keep the digest implementation centralized for callers that need to bind
/// an attempt identity to the exact owner token.
pub(crate) fn owner_id(owner: &tunnel_catalog::OwnerToken) -> String {
    wire::owner_id(owner)
}

/// Build the bounded digest carried in the catalog's attachment-ticket
/// binding.  The opaque ticket itself never enters diagnostics or Redis
/// routing metadata; this digest commits the complete physical attachment
/// context that the owner will present again at consume time.
pub(crate) fn attachment_binding_digest(
    owner: &tunnel_catalog::OwnerToken,
    generation: u64,
    connection_id: &str,
    purpose: &str,
) -> String {
    let mut digest = Sha256::new();
    digest.update(serde_json::to_vec(owner).expect("OwnerToken is serializable"));
    digest.update(generation.to_be_bytes());
    digest.update(connection_id.as_bytes());
    digest.update([0]);
    digest.update(purpose.as_bytes());
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// Compute the catalog locator digest for an opaque attachment ticket.  Only
/// the digest is retained for routing/diagnostics; callers must still present
/// the opaque value to the catalog's atomic consume operation.
pub(crate) fn attachment_ticket_digest(ticket: &str) -> String {
    Sha256::digest(ticket.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub(crate) fn attachment_locator_matches(ticket: &str, locator_digest: &str) -> bool {
    locator_digest.len() == 64
        && locator_digest
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && locator_digest == attachment_ticket_digest(ticket)
}
