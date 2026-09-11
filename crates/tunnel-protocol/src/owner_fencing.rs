//! Connector-side owner fencing for the private-alpha cluster profile.
//!
//! `OWNER_FENCE` carries the digest of the complete catalog owner token.  The
//! digest is intentionally the same `owner_id` value already used by `WELCOME`
//! and M2 rotation messages; this module only applies the stricter digest shape
//! needed before a connector changes its active owner.  A connector drops
//! admission for its previous owner as soon as it receives a newer fence, and
//! keeps admission closed until the exact `OWNER_FENCED` acknowledgement has
//! been committed by the caller.  The carried deadline bounds that handshake;
//! ongoing dispatch freshness is a separate authorization/lease contract.
//!
//! This is a bounded protocol and a local state transition.  It does not turn
//! an asynchronous Redis lease or this acknowledgement into distributed
//! consensus.  The owner still needs an authoritative lease and must wait for
//! this acknowledgement before authorizing the new data attachment.

use core::fmt;

use serde::{Deserialize, Serialize};

use crate::control::{ControlError, MAX_IDENTIFIER_BYTES, decimal_u64};

/// Maximum owner-fence handshake budget carried by one owner fence.
///
/// This mirrors the cluster design's 20-second owner-fence handshake ceiling.
/// A message carrying a larger lifetime is rejected before it can enter the
/// state machine.  It does not cap a post-ack owner identity latch or replace
/// the separate challenge-bound dispatch permission.
pub const MAX_OWNER_FENCE_REMAINING_MS: u64 = 20_000;

/// Descriptive alias for callers that distinguish the handshake budget from
/// the separate challenge-bound dispatch permission.
pub const MAX_OWNER_FENCE_HANDSHAKE_REMAINING_MS: u64 = MAX_OWNER_FENCE_REMAINING_MS;

/// Owner-fencing records use the tighter renewal/control bound.  Keeping the
/// bound independent from the overall control ceiling prevents a saturated
/// control channel from hiding an owner transition.
pub const MAX_OWNER_FENCING_MESSAGE_BYTES: usize = 2 * 1024;

const OWNER_DIGEST_HEX_BYTES: usize = 64;

/// OWNER_FENCE asks the connector to fence its current owner and bind the
/// session to the complete owner-token digest and newer epoch.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFence {
    pub message_id: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    /// Lowercase SHA-256 of the complete `(deployment_incarnation,
    /// tenant_id, device_id, node_id, boot_id, session_id, epoch)` owner
    /// token.  The token itself is never placed on the wire.
    pub owner_id: String,
    /// Fresh nonce for this owner-fencing attempt.  Entropy is supplied by the
    /// authenticated owner; the codec only enforces a bounded opaque value.
    pub nonce: String,
    /// Remaining owner-fence handshake budget, in monotonic milliseconds.
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

impl OwnerFence {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        owner_id: impl Into<String>,
        nonce: impl Into<String>,
        remaining_ms: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            session_id: session_id.into(),
            epoch,
            owner_id: owner_id.into(),
            nonce: nonce.into(),
            remaining_ms,
        }
    }

    /// Validate the bounded wire shape without changing connector state.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_message_id(&self.message_id)?;
        validate_identifier("session_id", &self.session_id)?;
        validate_epoch(self.epoch)?;
        validate_owner_digest(&self.owner_id)?;
        validate_identifier("nonce", &self.nonce)?;
        validate_remaining_ms(self.remaining_ms)
    }
}

/// OWNER_FENCED acknowledges one exact OWNER_FENCE request.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct OwnerFenced {
    pub message_id: String,
    pub reply_to: String,
    pub session_id: String,
    #[serde(with = "decimal_u64")]
    pub epoch: u64,
    pub owner_id: String,
    pub nonce: String,
    /// The acknowledgement echoes the request's bounded handshake budget.  It
    /// is checked for exact equality and never treated as a fresh budget.
    #[serde(with = "decimal_u64")]
    pub remaining_ms: u64,
}

impl OwnerFenced {
    #[must_use]
    pub fn new(
        message_id: impl Into<String>,
        reply_to: impl Into<String>,
        session_id: impl Into<String>,
        epoch: u64,
        owner_id: impl Into<String>,
        nonce: impl Into<String>,
        remaining_ms: u64,
    ) -> Self {
        Self {
            message_id: message_id.into(),
            reply_to: reply_to.into(),
            session_id: session_id.into(),
            epoch,
            owner_id: owner_id.into(),
            nonce: nonce.into(),
            remaining_ms,
        }
    }

    #[must_use]
    pub fn from_fence(message_id: impl Into<String>, fence: &OwnerFence) -> Self {
        Self::new(
            message_id,
            fence.message_id.clone(),
            fence.session_id.clone(),
            fence.epoch,
            fence.owner_id.clone(),
            fence.nonce.clone(),
            fence.remaining_ms,
        )
    }

    /// Validate the bounded wire shape and exact request binding.
    pub fn validate(&self) -> Result<(), ControlError> {
        validate_message_id(&self.message_id)?;
        validate_identifier("reply_to", &self.reply_to)?;
        validate_identifier("session_id", &self.session_id)?;
        validate_epoch(self.epoch)?;
        validate_owner_digest(&self.owner_id)?;
        validate_identifier("nonce", &self.nonce)?;
        validate_remaining_ms(self.remaining_ms)
    }

    /// Validate that this acknowledgement is for one exact fence request.
    pub fn validate_context(&self, fence: &OwnerFence) -> Result<(), ControlError> {
        self.validate()?;
        fence.validate()?;
        for (field, actual, expected) in [
            (
                "reply_to",
                self.reply_to.as_str(),
                fence.message_id.as_str(),
            ),
            (
                "session_id",
                self.session_id.as_str(),
                fence.session_id.as_str(),
            ),
            ("owner_id", self.owner_id.as_str(), fence.owner_id.as_str()),
            ("nonce", self.nonce.as_str(), fence.nonce.as_str()),
        ] {
            if actual != expected {
                return Err(ControlError::ContextMismatch { field });
            }
        }
        if self.epoch != fence.epoch {
            return Err(ControlError::ContextMismatch { field: "epoch" });
        }
        if self.remaining_ms != fence.remaining_ms {
            return Err(ControlError::ContextMismatch {
                field: "remaining_ms",
            });
        }
        Ok(())
    }
}

/// The connector's pure owner-fencing phase.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OwnerFencePhase {
    /// No owner has been acknowledged for this authenticated session.
    Unfenced,
    /// A newer owner has invalidated the prior owner, but its exact
    /// acknowledgement has not yet been committed locally.
    AwaitingAcknowledgement,
    /// The owner identity may authorize work until explicit invalidation or a
    /// newer owner fence.  The handshake deadline no longer applies.
    Fenced,
    /// The owner-fence handshake deadline elapsed before acknowledgement.  A
    /// newer epoch is required.
    Expired,
    /// The latched owner was explicitly invalidated.  A newer epoch is
    /// required; the retained identity still fences rollback attempts.
    Invalidated,
}

/// A connector-side owner fencing state machine.
#[derive(Clone, Debug)]
pub struct OwnerFenceState {
    session_id: String,
    phase: OwnerFencePhase,
    current_fence: Option<OwnerFence>,
    acknowledgement: Option<OwnerFenced>,
    deadline_ms: Option<u64>,
    last_now_ms: Option<u64>,
}

impl OwnerFenceState {
    /// Start an unfenced state for one logical session.
    pub fn new(session_id: impl Into<String>) -> Result<Self, OwnerFenceError> {
        let session_id = session_id.into();
        validate_identifier("session_id", &session_id).map_err(OwnerFenceError::Control)?;
        Ok(Self {
            session_id,
            phase: OwnerFencePhase::Unfenced,
            current_fence: None,
            acknowledgement: None,
            deadline_ms: None,
            last_now_ms: None,
        })
    }

    #[must_use]
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    #[must_use]
    pub const fn phase(&self) -> OwnerFencePhase {
        self.phase
    }

    #[must_use]
    pub fn owner_id(&self) -> Option<&str> {
        self.current_fence
            .as_ref()
            .map(|fence| fence.owner_id.as_str())
    }

    #[must_use]
    pub fn epoch(&self) -> Option<u64> {
        self.current_fence.as_ref().map(|fence| fence.epoch)
    }

    #[must_use]
    /// Return the fixed owner-fence handshake deadline, if a fence was
    /// accepted.  This value is informational after the acknowledgement is
    /// committed; it does not expire the owner identity latch.
    pub fn deadline_ms(&self) -> Option<u64> {
        self.deadline_ms
    }

    /// Explicit name for [`Self::deadline_ms`] when callers track multiple
    /// independent authorization and lease deadlines.
    #[must_use]
    pub fn handshake_deadline_ms(&self) -> Option<u64> {
        self.deadline_ms
    }

    /// Return the exact acknowledgement retained for the current fence.
    ///
    /// The value is bounded and contains no credential or payload.  Keeping it
    /// allows an identical fence retry to replay the same acknowledgement
    /// without changing the handshake deadline or phase.
    #[must_use]
    pub fn acknowledgement(&self) -> Option<&OwnerFenced> {
        self.acknowledgement.as_ref()
    }

    /// Accept one owner fence and build its acknowledgement.
    ///
    /// Receiving a strictly newer epoch immediately invalidates the prior
    /// owner and enters `AwaitingAcknowledgement`; no data admission is
    /// possible until [`Self::acknowledgement_sent`] commits the exact reply.
    /// An identical retry returns the retained reply without extending its
    /// handshake deadline.  Lower epochs and same-epoch identity changes are
    /// rejected.  Once an acknowledgement is committed, the same owner
    /// identity remains latched; dispatch freshness belongs to the separate
    /// authorization challenge.
    pub fn accept_fence(
        &mut self,
        fence: &OwnerFence,
        acknowledgement_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<OwnerFenced, OwnerFenceError> {
        fence.validate().map_err(OwnerFenceError::Control)?;
        self.observe_time(now_ms)?;
        if fence.session_id != self.session_id {
            return Err(OwnerFenceError::SessionMismatch);
        }

        if let Some(current) = self.current_fence.as_ref() {
            if fence.epoch < current.epoch {
                return Err(OwnerFenceError::EpochRollback {
                    current: current.epoch,
                    proposed: fence.epoch,
                });
            }
            if fence.epoch == current.epoch {
                if fence.owner_id != current.owner_id {
                    return Err(OwnerFenceError::EpochConflict { epoch: fence.epoch });
                }
                if fence.nonce != current.nonce
                    || fence.message_id != current.message_id
                    || fence.remaining_ms != current.remaining_ms
                {
                    return Err(OwnerFenceError::FenceConflict { epoch: fence.epoch });
                }
                if self.phase == OwnerFencePhase::Invalidated {
                    return Err(OwnerFenceError::OwnerInvalidated);
                }
                if self.phase == OwnerFencePhase::Expired {
                    let deadline_ms = self.deadline_ms.unwrap_or(now_ms);
                    return Err(OwnerFenceError::DeadlineExpired {
                        now: now_ms,
                        deadline: deadline_ms,
                    });
                }
                if self.phase == OwnerFencePhase::AwaitingAcknowledgement {
                    let Some(deadline_ms) = self.deadline_ms else {
                        return Err(OwnerFenceError::AcknowledgementRequired);
                    };
                    if now_ms >= deadline_ms {
                        self.phase = OwnerFencePhase::Expired;
                        return Err(OwnerFenceError::DeadlineExpired {
                            now: now_ms,
                            deadline: deadline_ms,
                        });
                    }
                }
                return self
                    .acknowledgement
                    .clone()
                    .ok_or(OwnerFenceError::AcknowledgementRequired);
            }
        }

        let deadline_ms = now_ms
            .checked_add(fence.remaining_ms)
            .ok_or(OwnerFenceError::DeadlineOverflow)?;
        let acknowledgement_id = acknowledgement_id.into();
        let acknowledgement = OwnerFenced::from_fence(acknowledgement_id, fence);
        acknowledgement
            .validate_context(fence)
            .map_err(OwnerFenceError::Control)?;

        self.current_fence = Some(fence.clone());
        self.acknowledgement = Some(acknowledgement.clone());
        self.deadline_ms = Some(deadline_ms);
        self.phase = OwnerFencePhase::AwaitingAcknowledgement;
        Ok(acknowledgement)
    }

    /// Commit the exact connector acknowledgement before enabling admission.
    ///
    /// Callers should invoke this only after the bounded acknowledgement has
    /// been accepted by the connector's control writer.  The operation is
    /// idempotent for the exact acknowledgement after it has already fenced
    /// the owner; a stale or altered acknowledgement can never fence a new
    /// owner.  Only a pending handshake is subject to the original deadline.
    pub fn acknowledgement_sent(
        &mut self,
        acknowledgement: &OwnerFenced,
        now_ms: u64,
    ) -> Result<(), OwnerFenceError> {
        acknowledgement
            .validate()
            .map_err(OwnerFenceError::Control)?;
        self.observe_time(now_ms)?;
        let Some(expected) = self.acknowledgement.as_ref() else {
            return Err(OwnerFenceError::StaleAcknowledgement);
        };
        if acknowledgement != expected {
            return Err(OwnerFenceError::StaleAcknowledgement);
        }
        match self.phase {
            OwnerFencePhase::Fenced => Ok(()),
            OwnerFencePhase::AwaitingAcknowledgement => {
                let Some(deadline_ms) = self.deadline_ms else {
                    return Err(OwnerFenceError::StaleAcknowledgement);
                };
                if now_ms >= deadline_ms {
                    self.phase = OwnerFencePhase::Expired;
                    return Err(OwnerFenceError::DeadlineExpired {
                        now: now_ms,
                        deadline: deadline_ms,
                    });
                }
                self.phase = OwnerFencePhase::Fenced;
                Ok(())
            }
            OwnerFencePhase::Unfenced | OwnerFencePhase::Expired | OwnerFencePhase::Invalidated => {
                Err(OwnerFenceError::StaleAcknowledgement)
            }
        }
    }

    /// Explicitly retire the currently latched owner.
    ///
    /// The owner identity and epoch remain retained so an old owner cannot
    /// roll the connector back.  A newer epoch may fence the connector again;
    /// the same identity cannot be reactivated after invalidation.
    pub fn invalidate_owner(&mut self) {
        self.phase = OwnerFencePhase::Invalidated;
        self.acknowledgement = None;
    }

    /// Authorize a data/control admission for the currently fenced owner.
    ///
    /// The owner digest and epoch are checked on every call.  Before the
    /// acknowledgement transition, or after explicit invalidation, this
    /// always fails closed.  The owner-fence handshake deadline does not
    /// expire an established identity; dispatch freshness is checked by the
    /// separate authorization challenge.
    pub fn authorize(
        &mut self,
        owner_id: &str,
        epoch: u64,
        now_ms: u64,
    ) -> Result<(), OwnerFenceError> {
        validate_owner_digest(owner_id).map_err(OwnerFenceError::Control)?;
        validate_epoch(epoch).map_err(OwnerFenceError::Control)?;
        self.observe_time(now_ms)?;
        let Some(current) = self.current_fence.as_ref() else {
            return Err(OwnerFenceError::NotFenced);
        };
        if owner_id != current.owner_id || epoch != current.epoch {
            return Err(OwnerFenceError::StaleOwner);
        }
        match self.phase {
            OwnerFencePhase::Fenced => Ok(()),
            OwnerFencePhase::AwaitingAcknowledgement => {
                let Some(deadline_ms) = self.deadline_ms else {
                    return Err(OwnerFenceError::AcknowledgementRequired);
                };
                if now_ms >= deadline_ms {
                    self.phase = OwnerFencePhase::Expired;
                    return Err(OwnerFenceError::DeadlineExpired {
                        now: now_ms,
                        deadline: deadline_ms,
                    });
                }
                Err(OwnerFenceError::AcknowledgementRequired)
            }
            OwnerFencePhase::Unfenced => Err(OwnerFenceError::NotFenced),
            OwnerFencePhase::Expired => {
                let deadline_ms = self.deadline_ms.unwrap_or(now_ms);
                Err(OwnerFenceError::DeadlineExpired {
                    now: now_ms,
                    deadline: deadline_ms,
                })
            }
            OwnerFencePhase::Invalidated => Err(OwnerFenceError::OwnerInvalidated),
        }
    }

    fn observe_time(&mut self, now_ms: u64) -> Result<(), OwnerFenceError> {
        if let Some(previous) = self.last_now_ms
            && now_ms < previous
        {
            return Err(OwnerFenceError::ClockWentBackwards {
                previous,
                now: now_ms,
            });
        }
        self.last_now_ms = Some(now_ms);
        Ok(())
    }
}

/// Errors from owner-fencing validation and pure state transitions.
pub enum OwnerFenceError {
    Control(ControlError),
    SessionMismatch,
    EpochRollback { current: u64, proposed: u64 },
    EpochConflict { epoch: u64 },
    FenceConflict { epoch: u64 },
    StaleAcknowledgement,
    AcknowledgementRequired,
    NotFenced,
    StaleOwner,
    OwnerInvalidated,
    DeadlineExpired { now: u64, deadline: u64 },
    DeadlineOverflow,
    ClockWentBackwards { previous: u64, now: u64 },
}

impl fmt::Debug for OwnerFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(_) => formatter.write_str("OwnerFenceError::Control(<redacted>)"),
            Self::SessionMismatch => formatter.write_str("SessionMismatch"),
            Self::EpochRollback { current, proposed } => formatter
                .debug_struct("EpochRollback")
                .field("current", current)
                .field("proposed", proposed)
                .finish(),
            Self::EpochConflict { epoch } => formatter
                .debug_struct("EpochConflict")
                .field("epoch", epoch)
                .finish(),
            Self::FenceConflict { epoch } => formatter
                .debug_struct("FenceConflict")
                .field("epoch", epoch)
                .finish(),
            Self::StaleAcknowledgement => formatter.write_str("StaleAcknowledgement"),
            Self::AcknowledgementRequired => formatter.write_str("AcknowledgementRequired"),
            Self::NotFenced => formatter.write_str("NotFenced"),
            Self::StaleOwner => formatter.write_str("StaleOwner"),
            Self::OwnerInvalidated => formatter.write_str("OwnerInvalidated"),
            Self::DeadlineExpired { now, deadline } => formatter
                .debug_struct("DeadlineExpired")
                .field("now", now)
                .field("deadline", deadline)
                .finish(),
            Self::DeadlineOverflow => formatter.write_str("DeadlineOverflow"),
            Self::ClockWentBackwards { previous, now } => formatter
                .debug_struct("ClockWentBackwards")
                .field("previous", previous)
                .field("now", now)
                .finish(),
        }
    }
}

impl fmt::Display for OwnerFenceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Control(error) => error.fmt(formatter),
            Self::SessionMismatch => formatter.write_str("owner fence session does not match"),
            Self::EpochRollback { current, proposed } => write!(
                formatter,
                "owner fence epoch rolls back from {current} to {proposed}"
            ),
            Self::EpochConflict { epoch } => {
                write!(
                    formatter,
                    "owner fence conflicts with the existing epoch {epoch}"
                )
            }
            Self::FenceConflict { epoch } => {
                write!(formatter, "owner fence identity conflicts at epoch {epoch}")
            }
            Self::StaleAcknowledgement => {
                formatter.write_str("owner fencing acknowledgement is stale")
            }
            Self::AcknowledgementRequired => {
                formatter.write_str("owner fencing acknowledgement is required")
            }
            Self::NotFenced => formatter.write_str("connector has no fenced owner"),
            Self::StaleOwner => formatter.write_str("owner is stale or no longer active"),
            Self::OwnerInvalidated => formatter.write_str("owner was explicitly invalidated"),
            Self::DeadlineExpired { now, deadline } => {
                write!(
                    formatter,
                    "owner fence handshake deadline {deadline} expired at {now}"
                )
            }
            Self::DeadlineOverflow => {
                formatter.write_str("owner fence handshake deadline overflowed")
            }
            Self::ClockWentBackwards { previous, now } => write!(
                formatter,
                "owner fence clock moved backwards from {previous} to {now}"
            ),
        }
    }
}

impl std::error::Error for OwnerFenceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Control(error) => Some(error),
            _ => None,
        }
    }
}

fn validate_message_id(value: &str) -> Result<(), ControlError> {
    validate_identifier("message_id", value)
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), ControlError> {
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

fn validate_epoch(epoch: u64) -> Result<(), ControlError> {
    if epoch == 0 {
        return Err(ControlError::ZeroCounter { field: "epoch" });
    }
    Ok(())
}

fn validate_owner_digest(value: &str) -> Result<(), ControlError> {
    if value.len() != OWNER_DIGEST_HEX_BYTES
        || value
            .bytes()
            .any(|byte| !byte.is_ascii_digit() && !(b'a'..=b'f').contains(&byte))
    {
        return Err(ControlError::InvalidDigest { field: "owner_id" });
    }
    Ok(())
}

fn validate_remaining_ms(value: u64) -> Result<(), ControlError> {
    if !(1..=MAX_OWNER_FENCE_REMAINING_MS).contains(&value) {
        return Err(ControlError::InvalidOwnerFenceLifetime(value));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::{ControlMessage, decode_control, encode_control};

    const OWNER_A: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const OWNER_B: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const OWNER_C: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

    fn fence(message_id: &str, epoch: u64, owner_id: &str, nonce: &str) -> OwnerFence {
        OwnerFence::new(message_id, "session", epoch, owner_id, nonce, 20_000)
    }

    #[test]
    fn owner_fence_messages_round_trip_with_decimal_epoch_and_deadline() {
        let request = ControlMessage::OwnerFence(fence("fence-1", 7, OWNER_A, "nonce-1"));
        let encoded = encode_control(&request).expect("valid owner fence");
        let json = String::from_utf8(encoded.clone()).expect("UTF-8 JSON");
        assert!(json.contains("\"type\":\"OWNER_FENCE\""));
        assert!(json.contains("\"epoch\":\"7\""));
        assert!(json.contains("\"remaining_ms\":\"20000\""));
        assert_eq!(decode_control(&encoded).expect("round trip"), request);

        let acknowledgement = ControlMessage::OwnerFenced(OwnerFenced::new(
            "ack-1", "fence-1", "session", 7, OWNER_A, "nonce-1", 20_000,
        ));
        let encoded = encode_control(&acknowledgement).expect("valid owner ack");
        assert_eq!(
            decode_control(&encoded).expect("round trip"),
            acknowledgement
        );
    }

    #[test]
    fn invalid_digest_and_deadline_are_rejected_before_admission() {
        let invalid_digest = ControlMessage::OwnerFence(fence("fence", 1, "owner", "nonce"));
        assert!(matches!(
            encode_control(&invalid_digest),
            Err(ControlError::InvalidDigest { field: "owner_id" })
        ));

        let invalid_deadline = ControlMessage::OwnerFence(OwnerFence::new(
            "fence",
            "session",
            1,
            OWNER_A,
            "nonce",
            MAX_OWNER_FENCE_REMAINING_MS + 1,
        ));
        assert!(matches!(
            encode_control(&invalid_deadline),
            Err(ControlError::InvalidOwnerFenceLifetime(value))
                if value == MAX_OWNER_FENCE_REMAINING_MS + 1
        ));
    }

    #[test]
    fn admission_is_blocked_until_exact_acknowledgement_is_sent() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let request = fence("fence-1", 1, OWNER_A, "nonce-1");
        let acknowledgement = state
            .accept_fence(&request, "ack-1", 100)
            .expect("accept fence");
        assert_eq!(state.phase(), OwnerFencePhase::AwaitingAcknowledgement);
        assert!(matches!(
            state.authorize(OWNER_A, 1, 101),
            Err(OwnerFenceError::AcknowledgementRequired)
        ));

        state
            .acknowledgement_sent(&acknowledgement, 102)
            .expect("commit acknowledgement");
        assert_eq!(state.phase(), OwnerFencePhase::Fenced);
        state.authorize(OWNER_A, 1, 103).expect("admit owner");
    }

    #[test]
    fn duplicate_fence_replays_ack_without_extending_deadline() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let request = fence("fence-1", 1, OWNER_A, "nonce-1");
        let first = state
            .accept_fence(&request, "ack-1", 100)
            .expect("accept fence");
        let duplicate = state
            .accept_fence(&request, "ack-different", 200)
            .expect("duplicate fence");
        assert_eq!(duplicate, first);
        assert_eq!(state.deadline_ms(), Some(20_100));

        let mut altered = request;
        altered.remaining_ms -= 1;
        assert!(matches!(
            state.accept_fence(&altered, "ack-altered", 201),
            Err(OwnerFenceError::FenceConflict { epoch: 1 })
        ));
    }

    #[test]
    fn rollback_and_same_epoch_new_identity_are_rejected() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let first = fence("fence-1", 3, OWNER_A, "nonce-1");
        state
            .accept_fence(&first, "ack-1", 100)
            .expect("accept first");

        let rollback = fence("fence-0", 2, OWNER_B, "nonce-0");
        assert!(matches!(
            state.accept_fence(&rollback, "ack-0", 101),
            Err(OwnerFenceError::EpochRollback {
                current: 3,
                proposed: 2
            })
        ));

        let conflict = fence("fence-conflict", 3, OWNER_B, "nonce-conflict");
        assert!(matches!(
            state.accept_fence(&conflict, "ack-conflict", 102),
            Err(OwnerFenceError::EpochConflict { epoch: 3 })
        ));
    }

    #[test]
    fn stale_ack_cannot_fence_after_newer_epoch() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let first = fence("fence-1", 1, OWNER_A, "nonce-1");
        let old_ack = state
            .accept_fence(&first, "ack-1", 100)
            .expect("accept first");
        let newer = fence("fence-2", 2, OWNER_B, "nonce-2");
        let new_ack = state
            .accept_fence(&newer, "ack-2", 101)
            .expect("accept newer");

        assert!(matches!(
            state.acknowledgement_sent(&old_ack, 102),
            Err(OwnerFenceError::StaleAcknowledgement)
        ));
        assert!(matches!(
            state.authorize(OWNER_A, 1, 103),
            Err(OwnerFenceError::StaleOwner)
        ));
        state
            .acknowledgement_sent(&new_ack, 104)
            .expect("commit newer ack");
        state.authorize(OWNER_B, 2, 105).expect("admit new owner");
    }

    #[test]
    fn deadline_is_fixed_and_late_ack_or_admission_fails_closed() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let request = fence("fence-1", 1, OWNER_C, "nonce-1");
        let acknowledgement = state
            .accept_fence(&request, "ack-1", 100)
            .expect("accept fence");
        assert!(matches!(
            state.acknowledgement_sent(&acknowledgement, 20_100),
            Err(OwnerFenceError::DeadlineExpired {
                now: 20_100,
                deadline: 20_100
            })
        ));
        assert_eq!(state.phase(), OwnerFencePhase::Expired);
        assert!(matches!(
            state.authorize(OWNER_C, 1, 20_101),
            Err(OwnerFenceError::DeadlineExpired {
                now: 20_101,
                deadline: 20_100
            })
        ));
        assert!(matches!(
            state.accept_fence(&request, "ack-retry", 20_102),
            Err(OwnerFenceError::DeadlineExpired {
                now: 20_102,
                deadline: 20_100
            })
        ));
    }

    #[test]
    fn established_owner_latch_survives_handshake_deadline_until_invalidation() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let request = fence("fence-1", 1, OWNER_A, "nonce-1");
        let acknowledgement = state
            .accept_fence(&request, "ack-1", 100)
            .expect("accept fence");
        state
            .acknowledgement_sent(&acknowledgement, 101)
            .expect("commit acknowledgement");

        // The handshake budget has elapsed, but a committed owner identity
        // remains valid.  The separate authorization challenge owns dispatch
        // freshness and is intentionally outside this state machine.
        state
            .authorize(OWNER_A, 1, 20_100)
            .expect("latched owner remains bound");
        assert_eq!(state.phase(), OwnerFencePhase::Fenced);

        state.invalidate_owner();
        assert_eq!(state.phase(), OwnerFencePhase::Invalidated);
        assert!(matches!(
            state.authorize(OWNER_A, 1, 20_101),
            Err(OwnerFenceError::OwnerInvalidated)
        ));

        let replacement = fence("fence-2", 2, OWNER_B, "nonce-2");
        let replacement_ack = state
            .accept_fence(&replacement, "ack-2", 20_102)
            .expect("accept newer owner");
        state
            .acknowledgement_sent(&replacement_ack, 20_103)
            .expect("commit newer acknowledgement");
        state
            .authorize(OWNER_B, 2, 20_104)
            .expect("admit replacement owner");
    }

    #[test]
    fn owner_fenced_context_requires_exact_echo() {
        let request = fence("fence-1", 4, OWNER_A, "nonce-1");
        let mut acknowledgement = OwnerFenced::from_fence("ack-1", &request);
        acknowledgement.owner_id = OWNER_B.to_owned();
        assert!(matches!(
            acknowledgement.validate_context(&request),
            Err(ControlError::ContextMismatch { field: "owner_id" })
        ));
    }

    #[test]
    fn monotonic_clock_rollback_is_rejected() {
        let mut state = OwnerFenceState::new("session").expect("session");
        let request = fence("fence-1", 1, OWNER_A, "nonce-1");
        state
            .accept_fence(&request, "ack-1", 100)
            .expect("accept fence");
        assert!(matches!(
            state.accept_fence(&request, "ack-retry", 99),
            Err(OwnerFenceError::ClockWentBackwards {
                previous: 100,
                now: 99
            })
        ));
    }
}
