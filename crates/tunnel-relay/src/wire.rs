//! Relay adapters for the canonical typed tunnel-protocol wire contracts.

use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tunnel_catalog::OwnerToken;
use tunnel_protocol::{
    AuthorizationConfirmed, AuthorizationInvalidated, ControlError, ControlMessage, DataReady,
    Frame, FrameError, Open, OwnerFence, Rejected, Welcome, decode_control, encode_control,
};
use uuid::Uuid;

/// Maximum consumer/device payload in the M1 echo profile.
pub const MAX_BODY_BYTES: usize = tunnel_protocol::MAX_PAYLOAD_LEN;
/// Maximum canary prefix included in an authenticated echo response.
///
/// M1 request bodies remain capped at `MAX_BODY_BYTES`, while the connector's
/// response also carries this bounded device canary.  The negotiated echo
/// window must cover both portions so an exactly maximum request cannot make
/// the connector close its control channel while emitting the second frame.
pub const MAX_ECHO_CANARY_BYTES: usize = 256;
pub const MAX_ECHO_WINDOW_BYTES: usize = MAX_BODY_BYTES + MAX_ECHO_CANARY_BYTES;
/// Initial per-direction credit for a long-lived M2 stream.
///
/// This is deliberately bounded and leaves room for the record prefix and
/// the maximum device canary while avoiding an 8 MiB per-stream allowance.
pub const M2_INITIAL_WINDOW_BYTES: usize = 128 * 1024;
/// Maximum control WebSocket message in the M1 profile.
pub const MAX_CONTROL_BYTES: usize = tunnel_protocol::MAX_CONTROL_MESSAGE_BYTES;
/// Maximum attachment-ticket lifetime.  A ticket is supplemental to mTLS.
pub const TICKET_TTL: Duration = Duration::from_secs(10);
/// The negotiated M2 profile.  It is deliberately additive so an M1 client
/// can continue to receive the finite profile without rotation fields.
pub const ORDERED_ROTATION_FEATURE: &str = "ordered-rotation-v1";
pub const M1_PROFILE_FEATURE: &str = "m1-control-data";
/// Negotiated cluster owner fencing.  A session advertising this feature
/// remains closed to data admission until the exact OWNER_FENCED reply has
/// been observed by the owner.
pub const OWNER_FENCING_FEATURE: &str = "owner-fencing-v1";
/// M3-16: the connector understands `PRINCIPAL_SESSIONS_END`.
pub const PRINCIPAL_SESSIONS_END_FEATURE: &str = "principal-sessions-end-v1";

pub fn random_token() -> String {
    let mut bytes = [0_u8; 32];
    for chunk in bytes.chunks_exact_mut(16) {
        chunk.copy_from_slice(Uuid::new_v4().as_bytes());
    }
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn parse_control(bytes: &[u8]) -> Result<ControlMessage, ControlError> {
    decode_control(bytes)
}

pub fn encode_control_message(message: &ControlMessage) -> Result<String, ControlError> {
    let bytes = encode_control(message)?;
    String::from_utf8(bytes).map_err(|_| {
        ControlError::Json(serde_json::Error::io(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "control message was not UTF-8",
        )))
    })
}

#[allow(clippy::too_many_arguments)]
pub fn welcome(
    message_id: &str,
    reply_to: &str,
    session_id: &str,
    epoch: u64,
    generation: u64,
    connection_id: &str,
    ticket: &str,
    owner_fencing: bool,
) -> ControlMessage {
    let mut welcome = Welcome::new_m1(
        message_id,
        reply_to,
        session_id,
        epoch,
        generation,
        connection_id,
        ticket,
    );
    // M1 negotiates only the fixed echo/control-data profile.  Rotation and
    // reconnect credentials remain absent until their state machines exist.
    welcome.supported_features = vec![
        "m1-control-data".to_owned(),
        "authorization-challenge".to_owned(),
        "echo".to_owned(),
    ];
    if owner_fencing {
        welcome
            .supported_features
            .push(OWNER_FENCING_FEATURE.to_owned());
    }
    ControlMessage::Welcome(welcome)
}

/// Build the negotiated M2 WELCOME.  The owner identity is a digest of the
/// complete fencing token; no token fields or secret credentials are placed
/// on the wire.  Rotation timing is supplied in milliseconds because that is
/// the protocol representation, while deployment configuration remains in
/// whole seconds.
pub(crate) struct WelcomeM2Params<'a> {
    pub message_id: &'a str,
    pub reply_to: &'a str,
    pub session_id: &'a str,
    pub epoch: u64,
    pub generation: u64,
    pub connection_id: &'a str,
    pub ticket: &'a str,
    pub owner: &'a OwnerToken,
    pub rotation_interval_ms: u64,
    pub handshake_timeout_ms: u64,
    pub overlap_timeout_ms: u64,
    pub owner_fencing: bool,
}

pub fn welcome_m2(params: WelcomeM2Params<'_>) -> ControlMessage {
    let mut welcome = Welcome::new(
        params.message_id,
        params.reply_to,
        params.session_id,
        params.epoch,
        params.generation,
        params.connection_id,
        params.ticket,
        "",
    );
    welcome.supported_features = vec![
        M1_PROFILE_FEATURE.to_owned(),
        "authorization-challenge".to_owned(),
        "echo".to_owned(),
        ORDERED_ROTATION_FEATURE.to_owned(),
    ];
    if params.owner_fencing {
        welcome
            .supported_features
            .push(OWNER_FENCING_FEATURE.to_owned());
    }
    welcome.owner_id = Some(owner_id(params.owner));
    welcome.rotation_interval_ms = Some(params.rotation_interval_ms);
    welcome.rotation_handshake_timeout_ms = Some(params.handshake_timeout_ms);
    welcome.rotation_overlap_timeout_ms = Some(params.overlap_timeout_ms);
    // Recovery is one immutable 30-second episode shared by all physical
    // attempts.  It is deliberately independent of an accelerated overlap
    // policy used by the handover harness.
    welcome.rotation_recovery_timeout_ms = Some(30_000);
    ControlMessage::Welcome(welcome)
}

/// Build the owner-side fence sent immediately after WELCOME.  The nonce and
/// message ID are fresh for this authenticated session; the full owner token
/// remains local and only its canonical digest is carried on the wire.
pub(crate) fn owner_fence(
    session_id: &str,
    epoch: u64,
    owner_id: &str,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::OwnerFence(OwnerFence::new(
        random_token(),
        session_id,
        epoch,
        owner_id,
        random_token(),
        remaining_ms,
    ))
}

/// Canonical owner identity used by every rotation message.  `OwnerToken` is
/// serialized from a fixed-order struct, making this digest stable while
/// avoiding exposure of the full tenant/device/node fencing context.
pub fn owner_id(owner: &OwnerToken) -> String {
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(owner).expect("OwnerToken is serializable");
    Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn data_ready(
    reply_to: &str,
    session_id: &str,
    epoch: u64,
    generation: u64,
    connection_id: &str,
) -> ControlMessage {
    ControlMessage::DataReady(DataReady::new(
        random_token(),
        reply_to,
        session_id,
        epoch,
        generation,
        connection_id,
    ))
}

pub(crate) struct OpenRequest<'a> {
    pub(crate) session_id: &'a str,
    pub(crate) epoch: u64,
    pub(crate) stream_id: u64,
    pub(crate) operation_id: &'a str,
    pub(crate) service_id: &'a str,
    pub(crate) body_len: usize,
    pub(crate) grant_revision: u64,
    pub(crate) digest: &'a str,
    pub(crate) operation: &'a str,
    /// The comma-separated capability names a filesystem session carries.
    ///
    /// Bounded, and neither a path nor a credential: the four names are
    /// `read`, `write`, `list` and `delete`. The device needs them because its
    /// provider enforces primitives, and the grant's own permission set lives
    /// in the catalog, which the device never reads.
    pub(crate) fs_capabilities: Option<&'a str>,
}

pub(crate) fn open(request: OpenRequest<'_>) -> ControlMessage {
    let (initial_send_window, initial_receive_window) = match request.operation {
        "echo_stream"
        | crate::actor::HTTP_FORWARD_STREAM_OPERATION
        | crate::actor::FS_STREAM_OPERATION => (
            M2_INITIAL_WINDOW_BYTES as u64,
            M2_INITIAL_WINDOW_BYTES as u64,
        ),
        "echo" => (MAX_ECHO_WINDOW_BYTES as u64, MAX_ECHO_WINDOW_BYTES as u64),
        _ => (MAX_BODY_BYTES as u64, MAX_BODY_BYTES as u64),
    };
    let mut open = Open::new(
        random_token(),
        request.session_id,
        request.epoch,
        request.stream_id,
        request.operation_id,
        request.service_id,
        request.operation,
        initial_send_window,
        initial_receive_window,
    );
    open.metadata
        .insert("body_length".into(), request.body_len.to_string());
    open.metadata
        .insert("grant_revision".into(), request.grant_revision.to_string());
    open.metadata
        .insert("permission_digest".into(), request.digest.to_owned());
    if let Some(capabilities) = request.fs_capabilities {
        open.metadata
            .insert("fs_capabilities".into(), capabilities.to_owned());
    }
    ControlMessage::Open(open)
}

#[cfg(test)]
mod tests {
    use super::{MAX_BODY_BYTES, MAX_ECHO_CANARY_BYTES, MAX_ECHO_WINDOW_BYTES, OpenRequest, open};
    use tunnel_protocol::{
        ControlMessage, Frame,
        sequence::{Direction, StreamState},
    };

    fn open_for(operation: &'static str) -> tunnel_protocol::Open {
        let ControlMessage::Open(open) = open(OpenRequest {
            session_id: "session",
            epoch: 1,
            stream_id: 1,
            operation_id: "operation",
            service_id: "service",
            body_len: 0,
            grant_revision: 1,
            digest: "digest",
            operation,
            fs_capabilities: None,
        }) else {
            panic!("wire::open must return an OPEN control message");
        };
        open
    }

    #[test]
    fn echo_window_covers_maximum_body_and_canary() {
        let open = open_for("echo");
        assert_eq!(
            MAX_ECHO_WINDOW_BYTES,
            MAX_BODY_BYTES + MAX_ECHO_CANARY_BYTES
        );
        assert_eq!(open.initial_send_window as usize, MAX_ECHO_WINDOW_BYTES);
        assert_eq!(open.initial_receive_window as usize, MAX_ECHO_WINDOW_BYTES);
    }

    #[test]
    fn echo_window_accepts_maximum_canary_prefixed_response() {
        let open = open_for("echo");
        let mut state =
            StreamState::with_credits(1, open.initial_send_window, open.initial_receive_window)
                .expect("maximum echo window is a valid sequence credit");
        let body = Frame::data(1, 1, 1, 1, 0, vec![0x5a; MAX_BODY_BYTES]);
        let canary = Frame::data(1, 1, 1, 2, 0, vec![0x63; MAX_ECHO_CANARY_BYTES]);
        state
            .send_frame(Direction::ConnectorToRelay, &body)
            .expect("maximum body fits the negotiated credit");
        state
            .send_frame(Direction::ConnectorToRelay, &canary)
            .expect("canary suffix fits the remaining negotiated credit");
    }

    #[test]
    fn unknown_operation_keeps_body_bound_until_admitted() {
        let open = open_for("unsupported");
        assert_eq!(open.initial_send_window as usize, MAX_BODY_BYTES);
        assert_eq!(open.initial_receive_window as usize, MAX_BODY_BYTES);
    }
}

pub(crate) fn rotate_prepare(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    attachment_purpose: tunnel_protocol::rotation_control::DataAttachmentPurpose,
    attachment_ticket: &str,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::RotatePrepare(tunnel_protocol::rotation_control::RotatePrepare {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        attachment_purpose,
        attachment_ticket: attachment_ticket.to_owned(),
        reconnect_credential: None,
        remaining_ms,
    })
}

pub(crate) fn recovery_begin(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    episode_id: &str,
    attempt_no: u64,
    roster: tunnel_protocol::rotation_control::StreamRoster,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::RecoveryBegin(tunnel_protocol::rotation_control::RecoveryBegin {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        episode_id: episode_id.to_owned(),
        attempt_no,
        roster,
        remaining_ms,
    })
}

pub(crate) fn recovery_closed(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    episode_id: &str,
    attempt_no: u64,
    closed_connection_ids: Vec<String>,
    closure_digest: &str,
) -> ControlMessage {
    ControlMessage::RecoveryClosed(tunnel_protocol::rotation_control::RecoveryClosed {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        episode_id: episode_id.to_owned(),
        attempt_no,
        closed_connection_ids,
        closure_digest: closure_digest.to_owned(),
    })
}

pub(crate) fn resume(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    snapshot_id: &str,
    stage: tunnel_protocol::rotation_control::ResumeStage,
    direction: tunnel_protocol::Direction,
    entries: Vec<tunnel_protocol::rotation_control::ResumeDirectionState>,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::Resume(tunnel_protocol::rotation_control::Resume {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        snapshot_id: snapshot_id.to_owned(),
        stage,
        direction,
        reconnect_credential: None,
        entries,
        remaining_ms,
    })
}

pub(crate) fn rotate_quiesce(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    roster: tunnel_protocol::rotation_control::StreamRoster,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::RotateQuiesce(tunnel_protocol::rotation_control::RotateQuiesce {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        roster,
        remaining_ms,
    })
}

pub(crate) fn rotate_frozen(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    snapshot: tunnel_protocol::rotation_control::FenceSnapshot,
) -> ControlMessage {
    ControlMessage::RotateFrozen(tunnel_protocol::rotation_control::RotateFrozen {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        snapshot,
    })
}

pub(crate) fn rotate_drained(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    proof: tunnel_protocol::rotation_control::DrainProof,
) -> ControlMessage {
    ControlMessage::RotateDrained(tunnel_protocol::rotation_control::RotateDrained {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        proof,
    })
}

pub(crate) fn rotate_commit(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    snapshot_id: &str,
    drain_proofs: Vec<tunnel_protocol::rotation_control::DrainProofRef>,
) -> ControlMessage {
    ControlMessage::RotateCommit(tunnel_protocol::rotation_control::RotateCommit {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        snapshot_id: snapshot_id.to_owned(),
        drain_proofs,
    })
}

pub(crate) fn rotate_retire(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    snapshot_id: &str,
) -> ControlMessage {
    ControlMessage::RotateRetire(tunnel_protocol::rotation_control::RotateRetire {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        snapshot_id: snapshot_id.to_owned(),
    })
}

pub(crate) fn rotate_complete(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    snapshot_id: &str,
    forced: bool,
    reason: Option<String>,
) -> ControlMessage {
    ControlMessage::RotateComplete(tunnel_protocol::rotation_control::RotateComplete {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        snapshot_id: snapshot_id.to_owned(),
        forced,
        reason,
    })
}

pub(crate) fn rotate_abort(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    reason: &str,
    remaining_ms: u64,
) -> ControlMessage {
    ControlMessage::RotateAbort(tunnel_protocol::rotation_control::RotateAbort {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        attempt,
        reason: reason.to_owned(),
        remaining_ms,
    })
}

pub(crate) fn rotate_aborted(
    reply_to: &str,
    attempt: tunnel_protocol::rotation_control::RotationAttemptIdentity,
    reason: &str,
) -> ControlMessage {
    ControlMessage::RotateAborted(tunnel_protocol::rotation_control::RotateAborted {
        message_id: random_token(),
        reply_to: reply_to.to_owned(),
        closed_connection_id: attempt.new_connection_id.clone(),
        attempt,
        reason: reason.to_owned(),
    })
}

pub fn cancel(session_id: &str, epoch: u64, stream_id: u64, operation_id: &str) -> ControlMessage {
    ControlMessage::Cancel(tunnel_protocol::Cancel::new(
        random_token(),
        session_id,
        epoch,
        stream_id,
        operation_id,
    ))
}

pub(crate) struct AuthorizationConfirmation<'a> {
    pub(crate) reply_to: &'a str,
    pub(crate) session_id: &'a str,
    pub(crate) epoch: u64,
    pub(crate) stream_id: u64,
    pub(crate) challenge_id: &'a str,
    pub(crate) nonce: &'a str,
    pub(crate) permission_digest: &'a str,
    pub(crate) grant_revision: u64,
    pub(crate) remaining_ms: u64,
}

pub(crate) fn authorization_confirmed(request: AuthorizationConfirmation<'_>) -> ControlMessage {
    ControlMessage::AuthorizationConfirmed(AuthorizationConfirmed::new(
        random_token(),
        request.reply_to,
        request.session_id,
        request.epoch,
        request.stream_id,
        request.challenge_id,
        request.nonce,
        request.permission_digest,
        request.grant_revision,
        request.remaining_ms,
    ))
}

pub fn authorization_invalidated(
    session_id: &str,
    epoch: u64,
    stream_id: u64,
    challenge_id: &str,
    grant_revision: u64,
    reason: &str,
) -> ControlMessage {
    ControlMessage::AuthorizationInvalidated(AuthorizationInvalidated::new(
        random_token(),
        session_id,
        epoch,
        stream_id,
        challenge_id,
        grant_revision,
        reason,
    ))
}

/// Task row M3-16: tell the device to end one consumer's protocol sessions.
pub fn principal_sessions_end(
    session_id: &str,
    epoch: u64,
    service_id: &str,
    principal_binding: &str,
    reason: &str,
) -> ControlMessage {
    ControlMessage::PrincipalSessionsEnd(tunnel_protocol::PrincipalSessionsEnd {
        message_id: random_token(),
        session_id: session_id.to_owned(),
        epoch,
        service_id: service_id.to_owned(),
        principal_binding: principal_binding.to_owned(),
        reason: reason.to_owned(),
    })
}

pub fn rejected(
    reply_to: &str,
    session_id: &str,
    epoch: u64,
    stream_id: u64,
    operation_id: &str,
    code: &str,
    reason: &str,
) -> ControlMessage {
    ControlMessage::Rejected(Rejected::new(
        random_token(),
        reply_to,
        session_id,
        epoch,
        stream_id,
        operation_id,
        code,
        reason,
    ))
}

pub fn data_frame(
    epoch: u64,
    generation: u64,
    stream_id: u64,
    sequence: u64,
    body: Vec<u8>,
) -> Result<Vec<u8>, FrameError> {
    Frame::data(epoch, generation, stream_id, sequence, 0, body).encode()
}

pub(crate) fn fin_frame(
    epoch: u64,
    generation: u64,
    stream_id: u64,
    sequence: u64,
) -> Result<Vec<u8>, FrameError> {
    Frame::fin(epoch, generation, stream_id, sequence, 0).encode()
}

pub fn decode_frame(bytes: &[u8]) -> Result<Frame, FrameError> {
    Frame::decode(bytes)
}

pub fn permission_digest(grant: &tunnel_catalog::GrantSnapshot, service_id: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut digest = Sha256::new();
    digest.update(service_id.as_bytes());
    digest.update([0]);
    digest.update(grant.revision.to_be_bytes());
    for operation in &grant.permissions.operations {
        digest.update(operation.as_bytes());
        digest.update([0]);
    }
    digest
        .finalize()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[derive(Debug)]
pub enum WireError {
    Control(ControlError),
    InvalidUtf8,
}

impl fmt::Display for WireError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => write!(formatter, "control message rejected: {error}"),
            Self::InvalidUtf8 => formatter.write_str("control message was not UTF-8"),
        }
    }
}

impl std::error::Error for WireError {}
