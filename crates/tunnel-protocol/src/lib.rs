#![forbid(unsafe_code)]
//! Typed, bounded wire contracts for Agent Tunnel.
//!
//! Socket attachment/authentication code owns session and data-context
//! validation.  This crate provides the fixed binary frame codec, strict
//! bounded JSON control messages, and pure per-stream sequence/credit state.

pub mod control;
pub mod control_journal;
pub mod frame;
pub mod owner_fencing;
pub mod rotation;
pub mod rotation_control;
pub mod sequence;

pub use control::{
    AuthorizationChallenge, AuthorizationConfirmed, AuthorizationInvalidated,
    CONTROL_OWNER_BUSY_CLOSE_CODE, CONTROL_OWNER_BUSY_CLOSE_REASON, Cancel, Control, ControlError,
    ControlMessage, DataReady, GoAway, Hello, MAX_AUTHORIZATION_MESSAGE_BYTES,
    MAX_CONTROL_MESSAGE_BYTES, MAX_RESULT_DETAIL_BYTES, Message, Open, Opened, Ping, Pong,
    Rejected, ResultDetail, ResultStatus, RotationPolicy, ServiceAdvertisement, Welcome,
    decode_control, encode_control,
};
pub use frame::{
    DataContext, Frame, FrameError, FrameKind, HEADER_LEN, MAGIC, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
    PROTOCOL_MAJOR, decode, encode, reset_reason,
};
pub use owner_fencing::{
    MAX_OWNER_FENCE_HANDSHAKE_REMAINING_MS, MAX_OWNER_FENCE_REMAINING_MS,
    MAX_OWNER_FENCING_MESSAGE_BYTES, OwnerFence, OwnerFenceError, OwnerFencePhase, OwnerFenceState,
    OwnerFenced,
};
pub use rotation_control::{
    DataAttachmentPurpose, RecoveryBegin, RecoveryClosed, RecoverySide, Resume, ResumeStage,
    Resumed, RotateAbort, RotateAborted, RotateCommit, RotateCommitted, RotateComplete,
    RotateDrained, RotateFrozen, RotatePrepare, RotateQuiesce, RotateRequest, RotateRetire,
    RotateRetired, StreamForget, combined_closure_digest,
};
pub use sequence::{
    Direction, DirectionSnapshot, DirectionState, ReceiveDisposition, RecoveryPlan, SequenceError,
    SequenceLimits, SequenceRange, StreamSnapshot, StreamState, Terminal,
};
