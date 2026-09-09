//! Relay adapters for the canonical typed tunnel-protocol wire contracts.

use std::{fmt, time::Duration};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use tunnel_protocol::{
    AuthorizationConfirmed, AuthorizationInvalidated, ControlError, ControlMessage, DataReady,
    Frame, FrameError, Open, Rejected, Welcome, decode_control, encode_control,
};
use uuid::Uuid;

/// Maximum consumer/device payload in the M1 echo profile.
pub const MAX_BODY_BYTES: usize = tunnel_protocol::MAX_PAYLOAD_LEN;
/// Maximum control WebSocket message in the M1 profile.
pub const MAX_CONTROL_BYTES: usize = tunnel_protocol::MAX_CONTROL_MESSAGE_BYTES;
/// Maximum attachment-ticket lifetime.  A ticket is supplemental to mTLS.
pub const TICKET_TTL: Duration = Duration::from_secs(10);

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

pub fn welcome(
    message_id: &str,
    reply_to: &str,
    session_id: &str,
    epoch: u64,
    generation: u64,
    connection_id: &str,
    ticket: &str,
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
    ControlMessage::Welcome(welcome)
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
}

pub(crate) fn open(request: OpenRequest<'_>) -> ControlMessage {
    let mut open = Open::new(
        random_token(),
        request.session_id,
        request.epoch,
        request.stream_id,
        request.operation_id,
        request.service_id,
        // The local export name is `echo`; the durable grant operation remains
        // `echo:invoke` and is checked before this OPEN is constructed.
        "echo",
        MAX_BODY_BYTES as u64,
        MAX_BODY_BYTES as u64,
    );
    open.metadata
        .insert("body_length".into(), request.body_len.to_string());
    open.metadata
        .insert("grant_revision".into(), request.grant_revision.to_string());
    open.metadata
        .insert("permission_digest".into(), request.digest.to_owned());
    ControlMessage::Open(open)
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
