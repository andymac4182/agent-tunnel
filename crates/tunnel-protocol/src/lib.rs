#![forbid(unsafe_code)]
//! Typed, bounded wire contracts for Agent Tunnel M1.
//!
//! Socket attachment/authentication code owns session and data-context
//! validation.  This crate provides the fixed binary frame codec, strict
//! bounded JSON control messages, and pure per-stream sequence/credit state.

pub mod control;
pub mod frame;
pub mod sequence;

pub use control::{
    AuthorizationChallenge, AuthorizationConfirmed, AuthorizationInvalidated, Cancel, Control,
    ControlError, ControlMessage, DataReady, GoAway, Hello, MAX_AUTHORIZATION_MESSAGE_BYTES,
    MAX_CONTROL_MESSAGE_BYTES, Message, Open, Opened, Ping, Pong, Rejected, ServiceAdvertisement,
    Welcome, decode_control, encode_control,
};
pub use frame::{
    DataContext, Frame, FrameError, FrameKind, HEADER_LEN, MAGIC, MAX_FRAME_LEN, MAX_PAYLOAD_LEN,
    PROTOCOL_MAJOR, decode, encode,
};
pub use sequence::{
    Direction, DirectionState, ReceiveDisposition, SequenceError, StreamState, Terminal,
};
