//! Bounded, strict JSON control messages for the initial tunnel handshake.
//!
//! Control messages are internally tagged with an upper-case `type` field.
//! Every integer that is a 64-bit protocol counter is encoded as a decimal
//! string so a JavaScript consumer cannot lose precision.  The codec performs
//! the byte bound before parsing and validates bounded identifiers after
//! deserialization.

use core::fmt;
use std::collections::BTreeMap;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

/// Maximum encoded control message size, inclusive.
pub const MAX_CONTROL_MESSAGE_BYTES: usize = 32 * 1024;
/// Authorization challenge/confirmation messages have a tighter independent
/// bound so saturated control traffic cannot hide a stale grant decision.
pub const MAX_AUTHORIZATION_MESSAGE_BYTES: usize = 2 * 1024;
/// Maximum UTF-8 byte length for a generic protocol identifier.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Maximum number of entries in a generic list carried by control.
pub const MAX_LIST_ENTRIES: usize = 128;
/// Maximum metadata key/value pairs on OPEN.
pub const MAX_METADATA_ENTRIES: usize = 64;
/// Maximum metadata key length.
pub const MAX_METADATA_KEY_BYTES: usize = 128;
/// Maximum metadata value length.
pub const MAX_METADATA_VALUE_BYTES: usize = 4096;
/// Maximum human-readable reason length.
pub const MAX_REASON_BYTES: usize = 1024;
/// Maximum opaque credential/ticket length.
pub const MAX_CREDENTIAL_BYTES: usize = 4096;

/// Serde helper for u64 values represented as decimal JSON strings.
pub mod decimal_u64 {
    use super::*;

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        parse_canonical_u64(&value).map_err(serde::de::Error::custom)
    }
}

/// Serde helper for optional u64 values represented as decimal strings.
pub mod optional_decimal_u64 {
    use super::*;

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => serializer.serialize_some(&value.to_string()),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = Option::<String>::deserialize(deserializer)?;
        value
            .map(|value| parse_canonical_u64(&value).map_err(serde::de::Error::custom))
            .transpose()
    }
}

/// A locally configured service advertised during HELLO.
///
/// The advertisement intentionally contains generic identifiers only.  It
/// does not carry an executable, URL, filesystem root, credential, or
/// consumer-controlled metadata.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceAdvertisement {
    pub service_id: String,
    #[serde(alias = "kind")]
    pub service_type: String,
    pub version: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capabilities: Vec<String>,
}

impl ServiceAdvertisement {
    #[must_use]
    pub fn new(
        service_id: impl Into<String>,
        service_type: impl Into<String>,
        version: impl Into<String>,
        capabilities: impl IntoIterator<Item = impl Into<String>>,
    ) -> Self {
        Self {
            service_id: service_id.into(),
            service_type: service_type.into(),
            version: version.into(),
            capabilities: capabilities.into_iter().map(Into::into).collect(),
        }
    }
}

/// HELLO advertises the connector and its generic service identifiers.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Hello {
    pub message_id: String,
    pub connector_id: String,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub features: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub services: Vec<ServiceAdvertisement>,
}

impl Hello {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        connector_id: impl Into<String>,
        protocol_major: u16,
        protocol_minor: u16,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            connector_id: connector_id.into(),
            protocol_major,
            protocol_minor,
            ..Self::default()
        }
    }
}

/// WELCOME establishes the authenticated logical session and initial data
/// attachment.  Credentials are opaque strings; this crate never generates or
/// interprets them.
#[derive(Clone, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Welcome {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    pub protocol_major: u16,
    pub protocol_minor: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub supported_features: Vec<String>,
    #[serde(with = "decimal_u64")]
    pub generation: u64,
    pub connection_id: String,
    pub attachment_ticket: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reconnect_credential: Option<String>,
    pub max_frame_payload: u32,
    pub max_control_message: u32,
    #[serde(with = "decimal_u64")]
    pub heartbeat_interval_ms: u64,
    #[serde(with = "decimal_u64")]
    pub heartbeat_timeout_ms: u64,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_decimal_u64"
    )]
    pub rotation_interval_ms: Option<u64>,
}

impl fmt::Debug for Welcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("Welcome")
            .field("message_id", &self.message_id)
            .field("reply_to", &self.reply_to)
            .field("session_id", &self.session_id)
            .field("epoch", &self.epoch)
            .field("protocol_major", &self.protocol_major)
            .field("protocol_minor", &self.protocol_minor)
            .field("supported_features", &self.supported_features)
            .field("generation", &self.generation)
            .field("connection_id", &self.connection_id)
            .field("attachment_ticket", &"<redacted>")
            .field(
                "reconnect_credential",
                &self.reconnect_credential.as_ref().map(|_| "<redacted>"),
            )
            .field("max_frame_payload", &self.max_frame_payload)
            .field("max_control_message", &self.max_control_message)
            .field("heartbeat_interval_ms", &self.heartbeat_interval_ms)
            .field("heartbeat_timeout_ms", &self.heartbeat_timeout_ms)
            .field("rotation_interval_ms", &self.rotation_interval_ms)
            .finish()
    }
}

impl Welcome {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        generation: u64,
        connection_id: impl Into<String>,
        attachment_ticket: impl Into<String>,
        reconnect_credential: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            protocol_major: 1,
            protocol_minor: 0,
            supported_features: Vec::new(),
            generation,
            connection_id: connection_id.into(),
            attachment_ticket: attachment_ticket.into(),
            reconnect_credential: Some(reconnect_credential.into())
                .filter(|value| !value.is_empty()),
            max_frame_payload: 65_536,
            max_control_message: MAX_CONTROL_MESSAGE_BYTES as u32,
            heartbeat_interval_ms: 20_000,
            heartbeat_timeout_ms: 60_000,
            rotation_interval_ms: None,
        }
    }

    /// Construct a M1 WELCOME.  M1 does not implement reconnect credentials
    /// or rotation, so those fields are intentionally omitted on the wire.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new_m1(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        generation: u64,
        connection_id: impl Into<String>,
        attachment_ticket: impl Into<String>,
    ) -> Self {
        let mut welcome = Self::new(
            message_id,
            reply_to,
            session_id,
            epoch,
            generation,
            connection_id,
            attachment_ticket,
            String::new(),
        );
        welcome.reconnect_credential = None;
        welcome.rotation_interval_ms = None;
        welcome
    }
}

/// DATA_READY confirms an attached physical data connection.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DataReady {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub generation: u64,
    pub connection_id: String,
}

impl DataReady {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        generation: u64,
        connection_id: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            generation,
            connection_id: connection_id.into(),
        }
    }
}

/// OPEN requests an authorized logical service operation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Open {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    pub service_id: String,
    pub operation: String,
    #[serde(with = "decimal_u64")]
    pub initial_send_window: u64,
    #[serde(with = "decimal_u64")]
    pub initial_receive_window: u64,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl Open {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        operation_id: impl Into<String>,
        service_id: impl Into<String>,
        operation: impl Into<String>,
        initial_send_window: u64,
        initial_receive_window: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            operation_id: operation_id.into(),
            service_id: service_id.into(),
            operation: operation.into(),
            initial_send_window,
            initial_receive_window,
            metadata: BTreeMap::new(),
        }
    }
}

/// OPENED acknowledges stream admission and its negotiated initial windows.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Opened {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    #[serde(with = "decimal_u64")]
    pub send_window: u64,
    #[serde(with = "decimal_u64")]
    pub receive_window: u64,
}

impl Opened {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        operation_id: impl Into<String>,
        send_window: u64,
        receive_window: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            operation_id: operation_id.into(),
            send_window,
            receive_window,
        }
    }
}

/// REJECTED reports a bounded admission failure.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rejected {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    pub code: String,
    pub reason: String,
}

impl Rejected {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        operation_id: impl Into<String>,
        code: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            operation_id: operation_id.into(),
            code: code.into(),
            reason: reason.into(),
        }
    }
}

/// PING checks control health independently of the data channel.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Ping {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub nonce: u64,
}

impl Ping {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        nonce: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            nonce,
        }
    }
}

/// PONG replies to PING.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Pong {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub nonce: u64,
}

impl Pong {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        nonce: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            nonce,
        }
    }
}

/// CANCEL requests best-effort cancellation of one logical operation.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cancel {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
}

impl Cancel {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        operation_id: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            operation_id: operation_id.into(),
            reason: None,
        }
    }
}

/// GOAWAY stops new stream admission and begins bounded shutdown.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct GoAway {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub last_stream_id: u64,
    pub reason: String,
}

impl GoAway {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        last_stream_id: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            last_stream_id,
            reason: reason.into(),
        }
    }
}

/// AUTHORIZATION_CHALLENGE asks the connector to confirm a frozen grant
/// snapshot before privileged dispatch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationChallenge {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub challenge_id: String,
    pub nonce: String,
    pub service_id: String,
    pub permission_digest: String,
    #[serde(with = "decimal_u64")]
    pub grant_revision: u64,
}

impl AuthorizationChallenge {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        challenge_id: impl Into<String>,
        nonce: impl Into<String>,
        service_id: impl Into<String>,
        permission_digest: impl Into<String>,
        grant_revision: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            challenge_id: challenge_id.into(),
            nonce: nonce.into(),
            service_id: service_id.into(),
            permission_digest: permission_digest.into(),
            grant_revision,
        }
    }
}

/// AUTHORIZATION_CONFIRMED acknowledges the challenge-bound grant snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationConfirmed {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub challenge_id: String,
    pub nonce: String,
    pub permission_digest: String,
    #[serde(with = "decimal_u64")]
    pub grant_revision: u64,
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

impl AuthorizationConfirmed {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        challenge_id: impl Into<String>,
        nonce: impl Into<String>,
        permission_digest: impl Into<String>,
        grant_revision: u64,
        remaining_ms: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            challenge_id: challenge_id.into(),
            nonce: nonce.into(),
            permission_digest: permission_digest.into(),
            grant_revision,
            remaining_ms,
        }
    }
}

/// AUTHORIZATION_INVALIDATED expires a previously confirmed grant snapshot.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AuthorizationInvalidated {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub challenge_id: String,
    #[serde(with = "decimal_u64")]
    pub grant_revision: u64,
    pub reason: String,
}

impl AuthorizationInvalidated {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        challenge_id: impl Into<String>,
        grant_revision: u64,
        reason: impl Into<String>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            challenge_id: challenge_id.into(),
            grant_revision,
            reason: reason.into(),
        }
    }
}

/// The initial M1 control-message registry.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ControlMessage {
    Hello(Hello),
    Welcome(Welcome),
    DataReady(DataReady),
    Open(Open),
    Opened(Opened),
    Rejected(Rejected),
    Ping(Ping),
    Pong(Pong),
    Cancel(Cancel),
    GoAway(GoAway),
    AuthorizationChallenge(AuthorizationChallenge),
    AuthorizationConfirmed(AuthorizationConfirmed),
    AuthorizationInvalidated(AuthorizationInvalidated),
}

/// Short aliases for callers that use `Control`/`Message` vocabulary.
pub type Control = ControlMessage;
pub type Message = ControlMessage;

impl ControlMessage {
    /// Return the message ID used for idempotency and request/reply matching.
    #[must_use]
    pub fn message_id(&self) -> &str {
        match self {
            Self::Hello(message) => &message.message_id,
            Self::Welcome(message) => &message.message_id,
            Self::DataReady(message) => &message.message_id,
            Self::Open(message) => &message.message_id,
            Self::Opened(message) => &message.message_id,
            Self::Rejected(message) => &message.message_id,
            Self::Ping(message) => &message.message_id,
            Self::Pong(message) => &message.message_id,
            Self::Cancel(message) => &message.message_id,
            Self::GoAway(message) => &message.message_id,
            Self::AuthorizationChallenge(message) => &message.message_id,
            Self::AuthorizationConfirmed(message) => &message.message_id,
            Self::AuthorizationInvalidated(message) => &message.message_id,
        }
    }

    /// Return the canonical registry name.
    #[must_use]
    pub const fn kind_name(&self) -> &'static str {
        match self {
            Self::Hello(_) => "HELLO",
            Self::Welcome(_) => "WELCOME",
            Self::DataReady(_) => "DATA_READY",
            Self::Open(_) => "OPEN",
            Self::Opened(_) => "OPENED",
            Self::Rejected(_) => "REJECTED",
            Self::Ping(_) => "PING",
            Self::Pong(_) => "PONG",
            Self::Cancel(_) => "CANCEL",
            Self::GoAway(_) => "GOAWAY",
            Self::AuthorizationChallenge(_) => "AUTHORIZATION_CHALLENGE",
            Self::AuthorizationConfirmed(_) => "AUTHORIZATION_CONFIRMED",
            Self::AuthorizationInvalidated(_) => "AUTHORIZATION_INVALIDATED",
        }
    }

    /// Return the per-message encoded size ceiling.
    #[must_use]
    pub const fn encoded_limit(&self) -> usize {
        match self {
            Self::AuthorizationChallenge(_)
            | Self::AuthorizationConfirmed(_)
            | Self::AuthorizationInvalidated(_) => MAX_AUTHORIZATION_MESSAGE_BYTES,
            _ => MAX_CONTROL_MESSAGE_BYTES,
        }
    }

    /// Validate IDs, bounded collections, and message-specific limits.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_message_id(self.message_id())?;
        match self {
            Self::Hello(message) => {
                validate_id("connector_id", &message.connector_id)?;
                validate_identifiers("feature", &message.features)?;
                if message.services.len() > MAX_LIST_ENTRIES {
                    return Err(ControlError::TooManyEntries {
                        field: "services",
                        maximum: MAX_LIST_ENTRIES,
                    });
                }
                for service in &message.services {
                    validate_id("service_id", &service.service_id)?;
                    validate_id("service_type", &service.service_type)?;
                    validate_id("service_version", &service.version)?;
                    validate_identifiers("capability", &service.capabilities)?;
                }
            }
            Self::Welcome(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_id("connection_id", &message.connection_id)?;
                validate_credential("attachment_ticket", &message.attachment_ticket)?;
                validate_identifiers("supported_feature", &message.supported_features)?;
                if let Some(reconnect_credential) = &message.reconnect_credential {
                    validate_credential("reconnect_credential", reconnect_credential)?;
                }
                if message.max_frame_payload as usize > crate::frame::MAX_PAYLOAD_LEN {
                    return Err(ControlError::LimitTooLarge {
                        field: "max_frame_payload",
                        maximum: crate::frame::MAX_PAYLOAD_LEN,
                        actual: message.max_frame_payload as usize,
                    });
                }
                if message.max_control_message as usize > MAX_CONTROL_MESSAGE_BYTES {
                    return Err(ControlError::LimitTooLarge {
                        field: "max_control_message",
                        maximum: MAX_CONTROL_MESSAGE_BYTES,
                        actual: message.max_control_message as usize,
                    });
                }
            }
            Self::DataReady(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_id("connection_id", &message.connection_id)?;
            }
            Self::Open(message) => {
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("operation_id", &message.operation_id)?;
                validate_id("service_id", &message.service_id)?;
                validate_id("operation", &message.operation)?;
                validate_metadata(&message.metadata)?;
            }
            Self::Opened(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("operation_id", &message.operation_id)?;
            }
            Self::Rejected(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("operation_id", &message.operation_id)?;
                validate_id("code", &message.code)?;
                validate_reason("reason", &message.reason)?;
            }
            Self::Ping(message) => validate_id("session_id", &message.session_id)?,
            Self::Pong(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
            }
            Self::Cancel(message) => {
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("operation_id", &message.operation_id)?;
                if let Some(reason) = &message.reason {
                    validate_reason("reason", reason)?;
                }
            }
            Self::GoAway(message) => {
                validate_id("session_id", &message.session_id)?;
                validate_reason("reason", &message.reason)?;
            }
            Self::AuthorizationChallenge(message) => {
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("challenge_id", &message.challenge_id)?;
                validate_id("nonce", &message.nonce)?;
                validate_id("service_id", &message.service_id)?;
                validate_id("permission_digest", &message.permission_digest)?;
            }
            Self::AuthorizationConfirmed(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("challenge_id", &message.challenge_id)?;
                validate_id("nonce", &message.nonce)?;
                validate_id("permission_digest", &message.permission_digest)?;
                if !(1..=5_000).contains(&message.remaining_ms) {
                    return Err(ControlError::InvalidAuthorizationLifetime(
                        message.remaining_ms,
                    ));
                }
            }
            Self::AuthorizationInvalidated(message) => {
                validate_id("session_id", &message.session_id)?;
                validate_nonzero_counter("stream_id", message.stream_id)?;
                validate_id("challenge_id", &message.challenge_id)?;
                validate_reason("reason", &message.reason)?;
            }
        }
        Ok(())
    }
}

/// Encode a validated control message, enforcing the inclusive byte bound.
pub fn encode_control(message: &ControlMessage) -> Result<Vec<u8>, ControlError> {
    message.validate()?;
    let encoded = serde_json::to_vec(message).map_err(ControlError::Json)?;
    if encoded.len() > message.encoded_limit() {
        return Err(ControlError::MessageTooLarge {
            length: encoded.len(),
            maximum: message.encoded_limit(),
        });
    }
    Ok(encoded)
}

/// Decode one complete bounded control message and reject unknown fields.
pub fn decode_control(encoded: &[u8]) -> Result<ControlMessage, ControlError> {
    if encoded.len() > MAX_CONTROL_MESSAGE_BYTES {
        return Err(ControlError::MessageTooLarge {
            length: encoded.len(),
            maximum: MAX_CONTROL_MESSAGE_BYTES,
        });
    }
    let message = serde_json::from_slice::<ControlMessage>(encoded).map_err(ControlError::Json)?;
    message.validate()?;
    if encoded.len() > message.encoded_limit() {
        return Err(ControlError::MessageTooLarge {
            length: encoded.len(),
            maximum: message.encoded_limit(),
        });
    }
    Ok(message)
}

/// Short aliases for function-oriented callers.
pub fn encode(message: &ControlMessage) -> Result<Vec<u8>, ControlError> {
    encode_control(message)
}

pub fn decode(encoded: &[u8]) -> Result<ControlMessage, ControlError> {
    decode_control(encoded)
}

fn validate_message_id(value: &str) -> Result<(), ControlError> {
    validate_id("message_id", value)
}

fn parse_canonical_u64(value: &str) -> Result<u64, &'static str> {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || bytes.iter().any(|byte| !byte.is_ascii_digit())
    {
        return Err("64-bit protocol counters must be canonical unsigned decimal strings");
    }
    value
        .parse::<u64>()
        .map_err(|_| "64-bit protocol counter is outside the u64 range")
}

fn validate_id(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty() || value.len() > MAX_IDENTIFIER_BYTES || value.chars().any(char::is_control)
    {
        return Err(ControlError::InvalidIdentifier {
            field,
            length: value.len(),
            maximum: MAX_IDENTIFIER_BYTES,
        });
    }
    Ok(())
}

fn validate_nonzero_counter(field: &'static str, value: u64) -> Result<(), ControlError> {
    if value == 0 {
        return Err(ControlError::ZeroCounter { field });
    }
    Ok(())
}

fn validate_credential(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty() || value.len() > MAX_CREDENTIAL_BYTES || value.chars().any(char::is_control)
    {
        return Err(ControlError::InvalidCredential {
            field,
            length: value.len(),
            maximum: MAX_CREDENTIAL_BYTES,
        });
    }
    Ok(())
}

fn validate_reason(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.len() > MAX_REASON_BYTES {
        return Err(ControlError::ValueTooLong {
            field,
            length: value.len(),
            maximum: MAX_REASON_BYTES,
        });
    }
    Ok(())
}

fn validate_identifiers(field: &'static str, values: &[String]) -> Result<(), ControlError> {
    if values.len() > MAX_LIST_ENTRIES {
        return Err(ControlError::TooManyEntries {
            field,
            maximum: MAX_LIST_ENTRIES,
        });
    }
    for value in values {
        validate_id(field, value)?;
    }
    Ok(())
}

fn validate_metadata(metadata: &BTreeMap<String, String>) -> Result<(), ControlError> {
    if metadata.len() > MAX_METADATA_ENTRIES {
        return Err(ControlError::TooManyEntries {
            field: "metadata",
            maximum: MAX_METADATA_ENTRIES,
        });
    }
    for (key, value) in metadata {
        if key.is_empty() || key.len() > MAX_METADATA_KEY_BYTES || key.chars().any(char::is_control)
        {
            return Err(ControlError::ValueTooLong {
                field: "metadata_key",
                length: key.len(),
                maximum: MAX_METADATA_KEY_BYTES,
            });
        }
        if value.len() > MAX_METADATA_VALUE_BYTES {
            return Err(ControlError::ValueTooLong {
                field: "metadata_value",
                length: value.len(),
                maximum: MAX_METADATA_VALUE_BYTES,
            });
        }
    }
    Ok(())
}

/// Errors from control serialization, parsing, and bounded validation.
pub enum ControlError {
    Json(serde_json::Error),
    MessageTooLarge {
        length: usize,
        maximum: usize,
    },
    InvalidIdentifier {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    InvalidCredential {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    ValueTooLong {
        field: &'static str,
        length: usize,
        maximum: usize,
    },
    TooManyEntries {
        field: &'static str,
        maximum: usize,
    },
    LimitTooLarge {
        field: &'static str,
        maximum: usize,
        actual: usize,
    },
    ZeroCounter {
        field: &'static str,
    },
    InvalidAuthorizationLifetime(u64),
}

impl fmt::Debug for ControlError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(_) => formatter.write_str("ControlError::Json(<redacted>)"),
            Self::MessageTooLarge { length, maximum } => formatter
                .debug_struct("MessageTooLarge")
                .field("length", length)
                .field("maximum", maximum)
                .finish(),
            Self::InvalidIdentifier {
                field,
                length,
                maximum,
            } => formatter
                .debug_struct("InvalidIdentifier")
                .field("field", field)
                .field("length", length)
                .field("maximum", maximum)
                .finish(),
            Self::InvalidCredential {
                field,
                length,
                maximum,
            } => formatter
                .debug_struct("InvalidCredential")
                .field("field", field)
                .field("length", length)
                .field("maximum", maximum)
                .finish(),
            Self::ValueTooLong {
                field,
                length,
                maximum,
            } => formatter
                .debug_struct("ValueTooLong")
                .field("field", field)
                .field("length", length)
                .field("maximum", maximum)
                .finish(),
            Self::TooManyEntries { field, maximum } => formatter
                .debug_struct("TooManyEntries")
                .field("field", field)
                .field("maximum", maximum)
                .finish(),
            Self::LimitTooLarge {
                field,
                maximum,
                actual,
            } => formatter
                .debug_struct("LimitTooLarge")
                .field("field", field)
                .field("maximum", maximum)
                .field("actual", actual)
                .finish(),
            Self::ZeroCounter { field } => {
                formatter.debug_tuple("ZeroCounter").field(field).finish()
            }
            Self::InvalidAuthorizationLifetime(value) => formatter
                .debug_tuple("InvalidAuthorizationLifetime")
                .field(value)
                .finish(),
        }
    }
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(error) => error.fmt(f),
            Self::MessageTooLarge { length, maximum } => {
                write!(f, "control message is {length} bytes, maximum is {maximum}")
            }
            Self::InvalidIdentifier {
                field,
                length,
                maximum,
            } => write!(f, "invalid {field}: {length} bytes, maximum is {maximum}"),
            Self::InvalidCredential {
                field,
                length,
                maximum,
            } => write!(f, "invalid {field}: {length} bytes, maximum is {maximum}"),
            Self::ValueTooLong {
                field,
                length,
                maximum,
            } => write!(f, "{field} is {length} bytes, maximum is {maximum}"),
            Self::TooManyEntries { field, maximum } => {
                write!(f, "{field} has more than {maximum} entries")
            }
            Self::LimitTooLarge {
                field,
                maximum,
                actual,
            } => write!(f, "{field} is {actual}, maximum is {maximum}"),
            Self::ZeroCounter { field } => write!(f, "{field} must be nonzero"),
            Self::InvalidAuthorizationLifetime(value) => write!(
                f,
                "authorization remaining_ms must be between 1 and 5000, got {value}"
            ),
        }
    }
}

impl std::error::Error for ControlError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ping() -> ControlMessage {
        ControlMessage::Ping(Ping::new("m-1", "session-1", 7, u64::MAX))
    }

    #[test]
    fn golden_ping_uses_decimal_counter_strings() {
        let encoded = encode_control(&ping()).expect("valid ping");
        let json = String::from_utf8(encoded.clone()).expect("JSON UTF-8");
        assert!(json.contains("\"type\":\"PING\""));
        assert!(json.contains("\"epoch\":\"7\""));
        assert!(json.contains("\"nonce\":\"18446744073709551615\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), ping());
    }

    #[test]
    fn unknown_fields_and_numeric_counters_are_rejected() {
        let unknown = br#"{"type":"PING","message_id":"m","session_id":"s","epoch":"1","nonce":"2","extra":true}"#;
        assert!(matches!(
            decode_control(unknown),
            Err(ControlError::Json(_))
        ));

        let numeric = br#"{"type":"PING","message_id":"m","session_id":"s","epoch":1,"nonce":"2"}"#;
        assert!(matches!(
            decode_control(numeric),
            Err(ControlError::Json(_))
        ));

        let leading_zero =
            br#"{"type":"PING","message_id":"m","session_id":"s","epoch":"01","nonce":"2"}"#;
        assert!(matches!(
            decode_control(leading_zero),
            Err(ControlError::Json(_))
        ));

        let plus = br#"{"type":"PING","message_id":"m","session_id":"s","epoch":"+1","nonce":"2"}"#;
        assert!(matches!(decode_control(plus), Err(ControlError::Json(_))));
    }

    #[test]
    fn service_advertisements_are_bounded_generic_identifiers() {
        let mut hello = Hello::new("m", "connector", 1, 0);
        hello.services.push(ServiceAdvertisement::new(
            "svc",
            "mcp",
            "1",
            ["invoke", "cancel"],
        ));
        let encoded = encode_control(&ControlMessage::Hello(hello.clone())).expect("valid hello");
        assert_eq!(
            decode_control(&encoded).expect("round trip"),
            ControlMessage::Hello(hello)
        );
    }

    #[test]
    fn control_message_limit_is_inclusive() {
        let message = ControlMessage::Hello(Hello::new("m", "connector", 1, 0));
        let encoded = encode_control(&message).expect("valid hello");
        let mut at_limit = encoded.clone();
        at_limit.resize(MAX_CONTROL_MESSAGE_BYTES, b' ');
        assert_eq!(
            decode_control(&at_limit).expect("inclusive maximum"),
            message
        );

        // A trailing byte is rejected before JSON parsing and exercises the
        // hard bound independently of the JSON shape.
        at_limit.push(b' ');
        assert!(matches!(
            decode_control(&at_limit),
            Err(ControlError::MessageTooLarge {
                maximum: MAX_CONTROL_MESSAGE_BYTES,
                ..
            })
        ));
    }

    #[test]
    fn authorization_echoes_nonce_and_enforces_remaining_lifetime_and_bound() {
        let message = ControlMessage::AuthorizationConfirmed(AuthorizationConfirmed::new(
            "message",
            "challenge-message",
            "session",
            1,
            7,
            "challenge",
            "nonce",
            "digest",
            3,
            5_000,
        ));
        let encoded = encode_control(&message).expect("valid authorization confirmation");
        assert!(
            String::from_utf8(encoded.clone())
                .expect("UTF-8")
                .contains("\"remaining_ms\":\"5000\"")
        );
        assert_eq!(decode_control(&encoded).expect("round trip"), message);

        let mut invalid = match message {
            ControlMessage::AuthorizationConfirmed(value) => value,
            _ => unreachable!(),
        };
        invalid.remaining_ms = 0;
        assert!(matches!(
            encode_control(&ControlMessage::AuthorizationConfirmed(invalid)),
            Err(ControlError::InvalidAuthorizationLifetime(0))
        ));

        let oversized = AuthorizationInvalidated::new(
            "m".repeat(MAX_IDENTIFIER_BYTES),
            "s".repeat(MAX_IDENTIFIER_BYTES),
            1,
            7,
            "c".repeat(MAX_IDENTIFIER_BYTES),
            1,
            "r".repeat(MAX_REASON_BYTES),
        );
        // The fields are individually valid.  Padding is legal JSON
        // whitespace, but pushes the complete authorization message beyond
        // its independent 2 KiB wire ceiling.
        let auth_encoded = encode_control(&ControlMessage::AuthorizationInvalidated(oversized))
            .expect("valid authorization message");
        let mut auth_padded = auth_encoded;
        auth_padded.resize(MAX_AUTHORIZATION_MESSAGE_BYTES, b' ');
        auth_padded.push(b' ');
        assert!(matches!(
            decode_control(&auth_padded),
            Err(ControlError::MessageTooLarge {
                maximum: MAX_AUTHORIZATION_MESSAGE_BYTES,
                ..
            })
        ));
    }
}
