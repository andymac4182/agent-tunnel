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

use crate::owner_fencing::{MAX_OWNER_FENCING_MESSAGE_BYTES, OwnerFence, OwnerFenced};
use crate::rotation_control::{
    RecoveryBegin, RecoveryClosed, Resume, Resumed, RotateAbort, RotateAborted, RotateCommit,
    RotateCommitted, RotateComplete, RotateDrained, RotateFrozen, RotatePrepare, RotateQuiesce,
    RotateRequest, RotateRetire, RotateRetired, StreamForget, validate_recovery_begin,
    validate_recovery_closed, validate_resume, validate_resumed, validate_rotate_abort,
    validate_rotate_aborted, validate_rotate_commit, validate_rotate_committed,
    validate_rotate_complete, validate_rotate_drained, validate_rotate_frozen,
    validate_rotate_prepare, validate_rotate_quiesce, validate_rotate_request,
    validate_rotate_retire, validate_rotate_retired, validate_stream_forget,
};

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
/// Maximum advertised rotation interval, matching the core configuration's
/// 86,400-second ceiling after conversion to milliseconds.
pub const MAX_ROTATION_INTERVAL_MS: u64 = 86_400_000;
/// Maximum candidate handshake timeout, matching the core 300-second ceiling.
pub const MAX_ROTATION_HANDSHAKE_TIMEOUT_MS: u64 = 300_000;
/// Maximum overlap timeout, matching the core 3,600-second ceiling.
pub const MAX_ROTATION_OVERLAP_TIMEOUT_MS: u64 = 3_600_000;
/// Temporary hard ceiling for negotiated recovery retention.
pub const MAX_ROTATION_RECOVERY_TIMEOUT_MS: u64 = 30_000;
/// Default rotation interval from the shared core policy, in milliseconds.
pub const DEFAULT_ROTATION_INTERVAL_MS: u64 = 300_000;
/// Default candidate handshake timeout from the shared core policy.
pub const DEFAULT_ROTATION_HANDSHAKE_TIMEOUT_MS: u64 = 10_000;
/// Default overlap timeout from the shared core policy.
pub const DEFAULT_ROTATION_OVERLAP_TIMEOUT_MS: u64 = 30_000;
/// WebSocket close status used when an authenticated device cannot acquire
/// the single active owner slot for its exact tenant/device scope.
pub const CONTROL_OWNER_BUSY_CLOSE_CODE: u16 = 1008;
/// Bounded close reason for the owner-conflict admission result.  The reason
/// is deliberately fixed so backend/catalog details never cross the socket.
pub const CONTROL_OWNER_BUSY_CLOSE_REASON: &str = "OWNER_BUSY";
/// WebSocket close status used when the relay authenticated the device's TLS
/// connection and then refused the device session it asked for: the HELLO's
/// `connector_id` does not name the certificate's device, or the catalog has
/// no active device and credential for the certificate's key (task row
/// M6-C32).  No retry of the same configuration can succeed, so the device
/// must be told so rather than see an unexplained socket loss.
pub const CONTROL_IDENTITY_REJECTED_CLOSE_CODE: u16 = 1008;
/// Task row M6-C68: how often a relay sends a WebSocket Ping on an admitted
/// device control socket.  Every device answers a WebSocket Ping with a Pong
/// (RFC 6455 section 5.5.2; `tunnel-client` does so explicitly), so a live
/// path produces an inbound frame at least this often even when idle.  It is
/// also well under the idle timeouts of the NATs and TCP proxies a device's
/// path crosses, so the pings keep such a path from being reaped.
pub const DEVICE_CONTROL_PING_INTERVAL: std::time::Duration = std::time::Duration::from_secs(10);
/// Task row M6-C68: the longest a relay keeps an admitted device control
/// socket after the last inbound frame of any kind (text, Ping or Pong).  A
/// device whose network path vanished -- a laptop waking on another network,
/// a NAT rebinding, a VPN drop -- sends nothing and answers no Ping, so its
/// relay ends that session within this bound, releases its owner slot, and
/// admits the device's reconnect.  A write is not evidence of life: it
/// completes into the kernel's buffer on a dead path.
pub const DEVICE_CONTROL_IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);
// The bounds the two values above must keep, checked when the crate builds:
// * the interval is at least a second, so the relay never floods a device;
// * the interval is at most 15 s, under the ~30--60 s idle timeouts of common
//   NATs and proxies;
// * one idle window holds three Ping intervals, so a live device must miss
//   two consecutive Pongs (a transient stall) before it is evicted;
// * the idle timeout is at most 30 s, so the relay's eviction plus its bounded
//   5 s disconnect hand-off ends well inside the 60 s a reconnecting
//   `tunnel-client` keeps retrying `OWNER_BUSY` (`OWNER_BUSY_RECONNECT_WINDOW`,
//   which asserts the same relation from its side).
const _: () = {
    assert!(DEVICE_CONTROL_PING_INTERVAL.as_secs() >= 1);
    assert!(DEVICE_CONTROL_PING_INTERVAL.as_secs() <= 15);
    assert!(DEVICE_CONTROL_IDLE_TIMEOUT.as_secs() >= 3 * DEVICE_CONTROL_PING_INTERVAL.as_secs());
    assert!(DEVICE_CONTROL_IDLE_TIMEOUT.as_secs() <= 30);
};
/// Bounded, fixed close reason for [`CONTROL_IDENTITY_REJECTED_CLOSE_CODE`].
/// It deliberately does not say which check failed: the unauthenticated
/// half of that answer (whether a key is known to the catalog) is not the
/// relay's to disclose over the socket.
pub const CONTROL_IDENTITY_REJECTED_CLOSE_REASON: &str = "DEVICE_IDENTITY_REJECTED";

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

/// Connector-requested rotation timing, expressed in milliseconds on the
/// wire.  The relay clamps these values componentwise to its own policy before
/// returning the negotiated WELCOME fields.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RotationPolicy {
    #[serde(with = "decimal_u64")]
    pub interval_ms: u64,
    #[serde(with = "decimal_u64")]
    pub handshake_timeout_ms: u64,
    #[serde(with = "decimal_u64")]
    pub overlap_timeout_ms: u64,
}

impl Default for RotationPolicy {
    fn default() -> Self {
        Self::new(
            DEFAULT_ROTATION_INTERVAL_MS,
            DEFAULT_ROTATION_HANDSHAKE_TIMEOUT_MS,
            DEFAULT_ROTATION_OVERLAP_TIMEOUT_MS,
        )
    }
}

impl RotationPolicy {
    #[must_use]
    pub const fn new(interval_ms: u64, handshake_timeout_ms: u64, overlap_timeout_ms: u64) -> Self {
        Self {
            interval_ms,
            handshake_timeout_ms,
            overlap_timeout_ms,
        }
    }

    pub fn validate(&self) -> Result<(), ControlError> {
        validate_rotation_value(
            "rotation_policy.interval_ms",
            self.interval_ms,
            MAX_ROTATION_INTERVAL_MS,
        )?;
        validate_rotation_value(
            "rotation_policy.handshake_timeout_ms",
            self.handshake_timeout_ms,
            MAX_ROTATION_HANDSHAKE_TIMEOUT_MS,
        )?;
        validate_rotation_value(
            "rotation_policy.overlap_timeout_ms",
            self.overlap_timeout_ms,
            MAX_ROTATION_OVERLAP_TIMEOUT_MS,
        )?;
        validate_rotation_order(
            self.handshake_timeout_ms,
            self.overlap_timeout_ms,
            self.interval_ms,
        )
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rotation_policy: Option<RotationPolicy>,
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
    /// Owner identity negotiated for M2 rotation.  It is optional so M1
    /// WELCOME frames remain byte-for-byte compatible with the old profile.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub owner_id: Option<String>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_decimal_u64"
    )]
    pub rotation_handshake_timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_decimal_u64"
    )]
    pub rotation_overlap_timeout_ms: Option<u64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "optional_decimal_u64"
    )]
    pub rotation_recovery_timeout_ms: Option<u64>,
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
            .field("owner_id", &self.owner_id)
            .field(
                "rotation_handshake_timeout_ms",
                &self.rotation_handshake_timeout_ms,
            )
            .field(
                "rotation_overlap_timeout_ms",
                &self.rotation_overlap_timeout_ms,
            )
            .field(
                "rotation_recovery_timeout_ms",
                &self.rotation_recovery_timeout_ms,
            )
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
            owner_id: None,
            rotation_handshake_timeout_ms: None,
            rotation_overlap_timeout_ms: None,
            rotation_recovery_timeout_ms: None,
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

    /// Validate DATA_READY against the authenticated attachment context.
    /// This takes the exact expected values rather than a whole WELCOME so a
    /// replacement data socket can be checked against its candidate ticket
    /// and generation without reusing stale bootstrap state.
    pub fn validate_context(
        &self,
        session_id: &str,
        epoch: u64,
        generation: u64,
        connection_id: &str,
    ) -> Result<(), ControlError> {
        for (field, actual, expected) in [
            ("session_id", self.session_id.as_str(), session_id),
            ("connection_id", self.connection_id.as_str(), connection_id),
        ] {
            if actual != expected {
                return Err(ControlError::ContextMismatch { field });
            }
        }
        if self.epoch != epoch {
            return Err(ControlError::ContextMismatch { field: "epoch" });
        }
        if self.generation != generation {
            return Err(ControlError::ContextMismatch {
                field: "generation",
            });
        }
        Ok(())
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

/// The maximum serialized size of the adapter-specific `RESULT_STATUS`
/// detail object (docs/http-forwarding.md, "Cancellation, resets, and
/// execution uncertainty").
pub const MAX_RESULT_DETAIL_BYTES: usize = 512;
/// The maximum length of one `RESULT_STATUS` detail token.
pub const MAX_RESULT_TOKEN_BYTES: usize = 64;

/// The closed `RESULT_STATUS` outcome vocabulary from docs/protocol.md
/// "Delivery guarantees and side effects".
pub const RESULT_OUTCOMES: [&str; 4] = ["succeeded", "failed", "cancelled", "outcome_unknown"];

/// Bounded adapter-specific detail carried by `RESULT_STATUS`.  Both fields
/// are closed-vocabulary tokens chosen by the adapter; neither may carry
/// payload, header, path or credential text.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultDetail {
    pub code: String,
    pub execution: String,
}

/// RESULT_STATUS reports one stream operation's actual or unknown outcome
/// independently of its outer RESET reason code.  It is sent on the control
/// socket, so it is not ordered with the data socket's RESET: a receiver
/// correlates it by stream and operation identity.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ResultStatus {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    #[serde(with = "decimal_u64")]
    pub stream_id: u64,
    pub operation_id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<ResultDetail>,
}

impl ResultStatus {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        stream_id: u64,
        operation_id: impl Into<String>,
        outcome: impl Into<String>,
        detail: Option<ResultDetail>,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            stream_id,
            operation_id: operation_id.into(),
            outcome: outcome.into(),
            detail,
        }
    }
}

fn validate_result_token(field: &'static str, value: &str) -> Result<(), ControlError> {
    if value.is_empty()
        || value.len() > MAX_RESULT_TOKEN_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return Err(ControlError::InvalidIdentifier {
            field,
            length: value.len(),
            maximum: MAX_RESULT_TOKEN_BYTES,
        });
    }
    Ok(())
}

fn validate_result_status(message: &ResultStatus) -> Result<(), ControlError> {
    validate_id("session_id", &message.session_id)?;
    validate_nonzero_counter("stream_id", message.stream_id)?;
    validate_id("operation_id", &message.operation_id)?;
    if !RESULT_OUTCOMES.contains(&message.outcome.as_str()) {
        return Err(ControlError::InvalidIdentifier {
            field: "outcome",
            length: message.outcome.len(),
            maximum: MAX_RESULT_TOKEN_BYTES,
        });
    }
    if let Some(detail) = &message.detail {
        validate_result_token("detail.code", &detail.code)?;
        validate_result_token("detail.execution", &detail.execution)?;
        let length = serde_json::to_vec(detail)
            .map_err(ControlError::Json)?
            .len();
        if length > MAX_RESULT_DETAIL_BYTES {
            return Err(ControlError::ValueTooLong {
                field: "detail",
                length,
                maximum: MAX_RESULT_DETAIL_BYTES,
            });
        }
    }
    Ok(())
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
    ResultStatus(ResultStatus),
    GoAway(GoAway),
    AuthorizationChallenge(AuthorizationChallenge),
    AuthorizationConfirmed(AuthorizationConfirmed),
    AuthorizationInvalidated(AuthorizationInvalidated),
    OwnerFence(OwnerFence),
    OwnerFenced(OwnerFenced),
    RotateRequest(RotateRequest),
    RotatePrepare(RotatePrepare),
    RotateQuiesce(RotateQuiesce),
    RotateFrozen(RotateFrozen),
    RotateDrained(RotateDrained),
    RotateCommit(RotateCommit),
    RotateCommitted(RotateCommitted),
    RotateRetire(RotateRetire),
    RotateRetired(RotateRetired),
    RotateComplete(RotateComplete),
    RotateAbort(RotateAbort),
    RotateAborted(RotateAborted),
    StreamForget(StreamForget),
    Resume(Resume),
    Resumed(Resumed),
    RecoveryBegin(RecoveryBegin),
    RecoveryClosed(RecoveryClosed),
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
            Self::ResultStatus(message) => &message.message_id,
            Self::GoAway(message) => &message.message_id,
            Self::AuthorizationChallenge(message) => &message.message_id,
            Self::AuthorizationConfirmed(message) => &message.message_id,
            Self::AuthorizationInvalidated(message) => &message.message_id,
            Self::OwnerFence(message) => &message.message_id,
            Self::OwnerFenced(message) => &message.message_id,
            Self::RotateRequest(message) => &message.message_id,
            Self::RotatePrepare(message) => &message.message_id,
            Self::RotateQuiesce(message) => &message.message_id,
            Self::RotateFrozen(message) => &message.message_id,
            Self::RotateDrained(message) => &message.message_id,
            Self::RotateCommit(message) => &message.message_id,
            Self::RotateCommitted(message) => &message.message_id,
            Self::RotateRetire(message) => &message.message_id,
            Self::RotateRetired(message) => &message.message_id,
            Self::RotateComplete(message) => &message.message_id,
            Self::RotateAbort(message) => &message.message_id,
            Self::RotateAborted(message) => &message.message_id,
            Self::StreamForget(message) => &message.message_id,
            Self::Resume(message) => &message.message_id,
            Self::Resumed(message) => &message.message_id,
            Self::RecoveryBegin(message) => &message.message_id,
            Self::RecoveryClosed(message) => &message.message_id,
        }
    }

    /// The stable idempotency key for this message.  Runtime journals retain
    /// the first response under this key and reject a reused key whose
    /// encoded contents differ; the wire codec only validates its shape.
    #[must_use]
    pub fn idempotency_key(&self) -> &str {
        self.message_id()
    }

    /// Return the request ID referenced by a reply, when the message carries
    /// one.  Empty reply IDs are omitted by request serialization.
    #[must_use]
    pub fn reply_to(&self) -> Option<&str> {
        let value = match self {
            Self::Welcome(message) => &message.reply_to,
            Self::DataReady(message) => &message.reply_to,
            Self::Opened(message) => &message.reply_to,
            Self::Rejected(message) => &message.reply_to,
            Self::Pong(message) => &message.reply_to,
            Self::AuthorizationConfirmed(message) => &message.reply_to,
            Self::OwnerFenced(message) => &message.reply_to,
            Self::RotateRequest(message) => &message.reply_to,
            Self::RotatePrepare(message) => &message.reply_to,
            Self::RotateQuiesce(message) => &message.reply_to,
            Self::RotateFrozen(message) => &message.reply_to,
            Self::RotateDrained(message) => &message.reply_to,
            Self::RotateCommit(message) => &message.reply_to,
            Self::RotateCommitted(message) => &message.reply_to,
            Self::RotateRetire(message) => &message.reply_to,
            Self::RotateRetired(message) => &message.reply_to,
            Self::RotateComplete(message) => &message.reply_to,
            Self::RotateAbort(message) => &message.reply_to,
            Self::RotateAborted(message) => &message.reply_to,
            Self::StreamForget(message) => &message.reply_to,
            Self::Resume(message) => &message.reply_to,
            Self::Resumed(message) => &message.reply_to,
            Self::RecoveryBegin(message) => &message.reply_to,
            Self::RecoveryClosed(message) => &message.reply_to,
            Self::Hello(_)
            | Self::Open(_)
            | Self::Ping(_)
            | Self::Cancel(_)
            | Self::ResultStatus(_)
            | Self::GoAway(_)
            | Self::AuthorizationChallenge(_)
            | Self::AuthorizationInvalidated(_)
            | Self::OwnerFence(_) => return None,
        };
        (!value.is_empty()).then_some(value)
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
            Self::ResultStatus(_) => "RESULT_STATUS",
            Self::GoAway(_) => "GOAWAY",
            Self::AuthorizationChallenge(_) => "AUTHORIZATION_CHALLENGE",
            Self::AuthorizationConfirmed(_) => "AUTHORIZATION_CONFIRMED",
            Self::AuthorizationInvalidated(_) => "AUTHORIZATION_INVALIDATED",
            Self::OwnerFence(_) => "OWNER_FENCE",
            Self::OwnerFenced(_) => "OWNER_FENCED",
            Self::RotateRequest(_) => "ROTATE_REQUEST",
            Self::RotatePrepare(_) => "ROTATE_PREPARE",
            Self::RotateQuiesce(_) => "ROTATE_QUIESCE",
            Self::RotateFrozen(_) => "ROTATE_FROZEN",
            Self::RotateDrained(_) => "ROTATE_DRAINED",
            Self::RotateCommit(_) => "ROTATE_COMMIT",
            Self::RotateCommitted(_) => "ROTATE_COMMITTED",
            Self::RotateRetire(_) => "ROTATE_RETIRE",
            Self::RotateRetired(_) => "ROTATE_RETIRED",
            Self::RotateComplete(_) => "ROTATE_COMPLETE",
            Self::RotateAbort(_) => "ROTATE_ABORT",
            Self::RotateAborted(_) => "ROTATE_ABORTED",
            Self::StreamForget(_) => "STREAM_FORGET",
            Self::Resume(_) => "RESUME",
            Self::Resumed(_) => "RESUMED",
            Self::RecoveryBegin(_) => "RECOVERY_BEGIN",
            Self::RecoveryClosed(_) => "RECOVERY_CLOSED",
        }
    }

    /// Return the per-message encoded size ceiling.
    #[must_use]
    pub const fn encoded_limit(&self) -> usize {
        match self {
            Self::AuthorizationChallenge(_)
            | Self::AuthorizationConfirmed(_)
            | Self::AuthorizationInvalidated(_) => MAX_AUTHORIZATION_MESSAGE_BYTES,
            Self::OwnerFence(_) | Self::OwnerFenced(_) => MAX_OWNER_FENCING_MESSAGE_BYTES,
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
                if let Some(rotation_policy) = &message.rotation_policy {
                    rotation_policy.validate()?;
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
                if let Some(owner_id) = &message.owner_id {
                    validate_id("owner_id", owner_id)?;
                }
                validate_optional_welcome_rotation_policy(message)?;
            }
            Self::DataReady(message) => {
                validate_id("reply_to", &message.reply_to)?;
                validate_id("session_id", &message.session_id)?;
                validate_id("connection_id", &message.connection_id)?;
                validate_nonzero_counter("epoch", message.epoch)?;
                validate_nonzero_counter("generation", message.generation)?;
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
            Self::ResultStatus(message) => validate_result_status(message)?,
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
            Self::OwnerFence(message) => message.validate()?,
            Self::OwnerFenced(message) => message.validate()?,
            Self::RotateRequest(message) => validate_rotate_request(message)?,
            Self::RotatePrepare(message) => validate_rotate_prepare(message)?,
            Self::RotateQuiesce(message) => validate_rotate_quiesce(message)?,
            Self::RotateFrozen(message) => validate_rotate_frozen(message)?,
            Self::RotateDrained(message) => validate_rotate_drained(message)?,
            Self::RotateCommit(message) => validate_rotate_commit(message)?,
            Self::RotateCommitted(message) => validate_rotate_committed(message)?,
            Self::RotateRetire(message) => validate_rotate_retire(message)?,
            Self::RotateRetired(message) => validate_rotate_retired(message)?,
            Self::RotateComplete(message) => validate_rotate_complete(message)?,
            Self::RotateAbort(message) => validate_rotate_abort(message)?,
            Self::RotateAborted(message) => validate_rotate_aborted(message)?,
            Self::StreamForget(message) => validate_stream_forget(message)?,
            Self::Resume(message) => validate_resume(message)?,
            Self::Resumed(message) => validate_resumed(message)?,
            Self::RecoveryBegin(message) => validate_recovery_begin(message)?,
            Self::RecoveryClosed(message) => validate_recovery_closed(message)?,
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

fn validate_rotation_value(
    field: &'static str,
    value: u64,
    maximum: u64,
) -> Result<(), ControlError> {
    validate_nonzero_counter(field, value)?;
    if value > maximum {
        return Err(ControlError::InvalidRotationPolicy {
            field,
            reason: "value exceeds the negotiated hard bound",
        });
    }
    Ok(())
}

fn validate_rotation_order(
    handshake_timeout_ms: u64,
    overlap_timeout_ms: u64,
    interval_ms: u64,
) -> Result<(), ControlError> {
    if handshake_timeout_ms >= overlap_timeout_ms {
        return Err(ControlError::InvalidRotationPolicy {
            field: "handshake_timeout_ms",
            reason: "must be less than overlap_timeout_ms",
        });
    }
    if overlap_timeout_ms >= interval_ms {
        return Err(ControlError::InvalidRotationPolicy {
            field: "overlap_timeout_ms",
            reason: "must be less than interval_ms",
        });
    }
    Ok(())
}

fn validate_optional_welcome_rotation_policy(message: &Welcome) -> Result<(), ControlError> {
    if let Some(interval_ms) = message.rotation_interval_ms {
        validate_rotation_value(
            "rotation_interval_ms",
            interval_ms,
            MAX_ROTATION_INTERVAL_MS,
        )?;
    }
    if let Some(handshake_timeout_ms) = message.rotation_handshake_timeout_ms {
        validate_rotation_value(
            "rotation_handshake_timeout_ms",
            handshake_timeout_ms,
            MAX_ROTATION_HANDSHAKE_TIMEOUT_MS,
        )?;
    }
    if let Some(overlap_timeout_ms) = message.rotation_overlap_timeout_ms {
        validate_rotation_value(
            "rotation_overlap_timeout_ms",
            overlap_timeout_ms,
            MAX_ROTATION_OVERLAP_TIMEOUT_MS,
        )?;
    }
    if let Some(recovery_timeout_ms) = message.rotation_recovery_timeout_ms {
        validate_rotation_value(
            "rotation_recovery_timeout_ms",
            recovery_timeout_ms,
            MAX_ROTATION_RECOVERY_TIMEOUT_MS,
        )?;
    }
    if let (Some(handshake_timeout_ms), Some(overlap_timeout_ms)) = (
        message.rotation_handshake_timeout_ms,
        message.rotation_overlap_timeout_ms,
    ) && handshake_timeout_ms >= overlap_timeout_ms
    {
        return Err(ControlError::InvalidRotationPolicy {
            field: "rotation_handshake_timeout_ms",
            reason: "must be less than rotation_overlap_timeout_ms",
        });
    }
    if let (Some(overlap_timeout_ms), Some(interval_ms)) = (
        message.rotation_overlap_timeout_ms,
        message.rotation_interval_ms,
    ) && overlap_timeout_ms >= interval_ms
    {
        return Err(ControlError::InvalidRotationPolicy {
            field: "rotation_overlap_timeout_ms",
            reason: "must be less than rotation_interval_ms",
        });
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
    InvalidOwnerFenceLifetime(u64),
    InvalidRotationPolicy {
        field: &'static str,
        reason: &'static str,
    },
    ContextMismatch {
        field: &'static str,
    },
    GenerationNotAdvanced {
        old: u64,
        new: u64,
    },
    MixedFenceDirections,
    UnorderedEntries {
        field: &'static str,
    },
    MismatchedSnapshot,
    InvalidProofCount {
        expected: usize,
        actual: usize,
    },
    InvalidDirectionCount {
        field: &'static str,
    },
    WrongConnection {
        field: &'static str,
    },
    SameConnection {
        field: &'static str,
    },
    InvalidReplayRange {
        from: u64,
        through: u64,
    },
    CursorBeyondFence {
        field: &'static str,
    },
    MismatchedStream,
    CreditExceeded {
        field: &'static str,
    },
    TerminalWithoutSequence {
        field: &'static str,
    },
    TerminalSequenceMismatch {
        field: &'static str,
    },
    InvalidDigest {
        field: &'static str,
    },
    MismatchedRecoveryContext {
        field: &'static str,
    },
    InvalidRecoveryStage {
        field: &'static str,
    },
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
            Self::InvalidOwnerFenceLifetime(value) => formatter
                .debug_tuple("InvalidOwnerFenceLifetime")
                .field(value)
                .finish(),
            Self::InvalidRotationPolicy { field, reason } => formatter
                .debug_struct("InvalidRotationPolicy")
                .field("field", field)
                .field("reason", reason)
                .finish(),
            Self::ContextMismatch { field } => formatter
                .debug_struct("ContextMismatch")
                .field("field", field)
                .finish(),
            Self::GenerationNotAdvanced { old, new } => formatter
                .debug_struct("GenerationNotAdvanced")
                .field("old", old)
                .field("new", new)
                .finish(),
            Self::MixedFenceDirections => formatter.write_str("ControlError::MixedFenceDirections"),
            Self::UnorderedEntries { field } => formatter
                .debug_struct("UnorderedEntries")
                .field("field", field)
                .finish(),
            Self::MismatchedSnapshot => formatter.write_str("ControlError::MismatchedSnapshot"),
            Self::InvalidProofCount { expected, actual } => formatter
                .debug_struct("InvalidProofCount")
                .field("expected", expected)
                .field("actual", actual)
                .finish(),
            Self::InvalidDirectionCount { field } => formatter
                .debug_struct("InvalidDirectionCount")
                .field("field", field)
                .finish(),
            Self::WrongConnection { field } => formatter
                .debug_struct("WrongConnection")
                .field("field", field)
                .finish(),
            Self::SameConnection { field } => formatter
                .debug_struct("SameConnection")
                .field("field", field)
                .finish(),
            Self::InvalidReplayRange { from, through } => formatter
                .debug_struct("InvalidReplayRange")
                .field("from", from)
                .field("through", through)
                .finish(),
            Self::CursorBeyondFence { field } => formatter
                .debug_struct("CursorBeyondFence")
                .field("field", field)
                .finish(),
            Self::MismatchedStream => formatter.write_str("ControlError::MismatchedStream"),
            Self::CreditExceeded { field } => formatter
                .debug_struct("CreditExceeded")
                .field("field", field)
                .finish(),
            Self::TerminalWithoutSequence { field } => formatter
                .debug_struct("TerminalWithoutSequence")
                .field("field", field)
                .finish(),
            Self::TerminalSequenceMismatch { field } => formatter
                .debug_struct("TerminalSequenceMismatch")
                .field("field", field)
                .finish(),
            Self::InvalidDigest { field } => formatter
                .debug_struct("InvalidDigest")
                .field("field", field)
                .finish(),
            Self::MismatchedRecoveryContext { field } => formatter
                .debug_struct("MismatchedRecoveryContext")
                .field("field", field)
                .finish(),
            Self::InvalidRecoveryStage { field } => formatter
                .debug_struct("InvalidRecoveryStage")
                .field("field", field)
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
            Self::InvalidOwnerFenceLifetime(value) => write!(
                f,
                "owner fence handshake remaining_ms must be between 1 and 20000, got {value}"
            ),
            Self::InvalidRotationPolicy { field, reason } => {
                write!(f, "invalid rotation policy {field}: {reason}")
            }
            Self::ContextMismatch { field } => {
                write!(f, "DATA_READY context does not match {field}")
            }
            Self::GenerationNotAdvanced { old, new } => {
                write!(
                    f,
                    "rotation new generation {new} must be greater than old {old}"
                )
            }
            Self::MixedFenceDirections => {
                f.write_str("a fence/proof contains mixed sequence directions")
            }
            Self::UnorderedEntries { field } => {
                write!(f, "{field} entries must be strictly ordered by stream ID")
            }
            Self::MismatchedSnapshot => f.write_str("rotation values refer to different snapshots"),
            Self::InvalidProofCount { expected, actual } => {
                write!(f, "rotation requires {expected} drain proofs, got {actual}")
            }
            Self::InvalidDirectionCount { field } => {
                write!(f, "{field} must contain exactly one entry per direction")
            }
            Self::WrongConnection { field } => {
                write!(f, "{field} does not identify the old rotation connection")
            }
            Self::SameConnection { field } => {
                write!(f, "{field} must identify distinct connections")
            }
            Self::InvalidReplayRange { from, through } => {
                write!(
                    f,
                    "replay range starts at {from} after it ends at {through}"
                )
            }
            Self::CursorBeyondFence { field } => {
                write!(
                    f,
                    "resume {field} cursor exceeds its emitted/received fence"
                )
            }
            Self::MismatchedStream => f.write_str("resume direction refers to a different stream"),
            Self::CreditExceeded { field } => {
                write!(f, "resume {field} exceeds its absolute credit limit")
            }
            Self::TerminalWithoutSequence { field } => {
                write!(f, "resume {field} requires a nonzero sequence cursor")
            }
            Self::TerminalSequenceMismatch { field } => {
                write!(f, "{field} does not match its terminal cursor")
            }
            Self::InvalidDigest { field } => {
                write!(f, "{field} must be a lowercase SHA-256 digest")
            }
            Self::MismatchedRecoveryContext { field } => {
                write!(f, "recovery records do not match on {field}")
            }
            Self::InvalidRecoveryStage { field } => {
                write!(f, "recovery stage forbids {field}")
            }
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

    fn result_status(detail: Option<ResultDetail>) -> ControlMessage {
        ControlMessage::ResultStatus(ResultStatus::new(
            "m-result",
            "session-1",
            7,
            9,
            "operation-1",
            "failed",
            detail,
        ))
    }

    #[test]
    fn result_status_round_trips_with_bounded_closed_detail() {
        let message = result_status(Some(ResultDetail {
            code: "HTTP_CANCELLED".to_owned(),
            execution: "dispatched".to_owned(),
        }));
        let encoded = encode_control(&message).expect("valid result status");
        let json = String::from_utf8(encoded.clone()).expect("JSON UTF-8");
        assert!(json.contains("\"type\":\"RESULT_STATUS\""));
        assert!(json.contains("\"stream_id\":\"9\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), message);
        assert!(encode_control(&result_status(None)).is_ok());
    }

    #[test]
    fn result_status_rejects_open_vocabulary_and_free_text_detail() {
        let mut outcome = ResultStatus::new("m", "s", 1, 1, "op", "done", None);
        assert!(
            ControlMessage::ResultStatus(outcome.clone())
                .validate()
                .is_err()
        );
        outcome.outcome = "cancelled".to_owned();
        assert!(ControlMessage::ResultStatus(outcome).validate().is_ok());
        for (code, execution) in [
            ("", "unknown"),
            ("HTTP CANCELLED", "unknown"),
            ("HTTP_CANCELLED", "Bearer secret"),
            ("HTTP_CANCELLED", "/private/path"),
        ] {
            let message = result_status(Some(ResultDetail {
                code: code.to_owned(),
                execution: execution.to_owned(),
            }));
            assert!(message.validate().is_err(), "{code:?}/{execution:?}");
        }
        let long = result_status(Some(ResultDetail {
            code: "A".repeat(MAX_RESULT_TOKEN_BYTES + 1),
            execution: "unknown".to_owned(),
        }));
        assert!(long.validate().is_err());
        let zero_stream =
            ControlMessage::ResultStatus(ResultStatus::new("m", "s", 1, 0, "op", "failed", None));
        assert!(zero_stream.validate().is_err());
        let unknown_field = br#"{"type":"RESULT_STATUS","message_id":"m","session_id":"s","epoch":"1","stream_id":"1","operation_id":"op","outcome":"failed","body":"x"}"#;
        assert!(decode_control(unknown_field).is_err());
    }

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
    fn welcome_negotiates_optional_rotation_owner_and_deadlines() {
        let mut welcome =
            Welcome::new_m1("welcome", "hello", "session", 7, 3, "connection", "ticket");
        welcome.owner_id = Some("owner-token-context".to_owned());
        welcome.rotation_interval_ms = Some(300_000);
        welcome.rotation_handshake_timeout_ms = Some(10_000);
        welcome.rotation_overlap_timeout_ms = Some(30_000);
        welcome.rotation_recovery_timeout_ms = Some(30_000);

        let encoded = encode_control(&ControlMessage::Welcome(welcome.clone()))
            .expect("valid negotiated welcome");
        let json = String::from_utf8(encoded.clone()).expect("JSON UTF-8");
        assert!(json.contains("\"rotation_handshake_timeout_ms\":\"10000\""));
        assert!(json.contains("\"rotation_overlap_timeout_ms\":\"30000\""));
        assert_eq!(
            decode_control(&encoded).expect("round trip"),
            ControlMessage::Welcome(welcome.clone())
        );

        let mut invalid = welcome;
        invalid.rotation_recovery_timeout_ms = Some(MAX_ROTATION_RECOVERY_TIMEOUT_MS + 1);
        assert!(matches!(
            encode_control(&ControlMessage::Welcome(invalid)),
            Err(ControlError::InvalidRotationPolicy {
                field: "rotation_recovery_timeout_ms",
                ..
            })
        ));
    }

    #[test]
    fn hello_rotation_policy_is_decimal_and_ordered() {
        let mut hello = Hello::new("hello", "connector", 1, 1);
        hello.rotation_policy = Some(RotationPolicy::default());
        let encoded =
            encode_control(&ControlMessage::Hello(hello.clone())).expect("valid rotation policy");
        let json = String::from_utf8(encoded.clone()).expect("JSON UTF-8");
        assert!(json.contains("\"interval_ms\":\"300000\""));
        assert_eq!(
            decode_control(&encoded).expect("round trip"),
            ControlMessage::Hello(hello.clone())
        );

        let mut invalid = hello;
        invalid.rotation_policy = Some(RotationPolicy::new(30_000, 30_000, 10_000));
        assert!(matches!(
            encode_control(&ControlMessage::Hello(invalid)),
            Err(ControlError::InvalidRotationPolicy { .. })
        ));
    }

    #[test]
    fn data_ready_context_helper_checks_candidate_binding() {
        let ready = DataReady::new("ready", "prepare", "session", 7, 4, "candidate");
        ready
            .validate_context("session", 7, 4, "candidate")
            .expect("matching context");
        assert!(matches!(
            ready.validate_context("session", 7, 3, "candidate"),
            Err(ControlError::ContextMismatch {
                field: "generation"
            })
        ));
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
