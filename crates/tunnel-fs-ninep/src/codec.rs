//! Framing: `msize` negotiation, one-message encoding, and an incremental,
//! split-tolerant decoder.
//!
//! Two decode entry points, because the profile has two transports with
//! different rules and conflating them is exactly the bug `docs/testing.md`
//! warns about ("the logical-stream parser must not mistake tunnel-frame
//! boundaries for 9P message boundaries"):
//!
//! * [`decode_exact`] is the **consumer WebSocket** rule: one binary message
//!   carries exactly one complete 9P message.  Two messages packed into one
//!   binary frame are [`CodecError::TrailingBytes`]; half a message is
//!   [`CodecError::TruncatedBody`].  Neither is tolerated, because tolerating
//!   them would make the framing the sender's choice.
//! * [`FrameDecoder`] is the **relay and device** rule: an ordered byte stream
//!   over tunnel DATA frames, where a 9P record may span frames and several may
//!   share one.  It is incremental and split-tolerant: the same bytes produce
//!   the same events however they are chunked.
//!
//! Both are bounded by `msize` **before** anything is allocated.

use tunnel_fs_core::{MAX_MESSAGE_BYTES_CEILING, MIN_MESSAGE_BYTES};

use crate::error::{CodecError, SessionError};
use crate::message::{Message, MessageType};
use crate::wire::{HEADER_LEN, NOTAG, Writer};

/// The only dialect this profile speaks.
pub const DIALECT: &str = "9P2000.L";

/// The largest `msize` this profile will ever negotiate, in bytes, including
/// the seven-byte header.
///
/// The same number as gate 1's `MAX_MESSAGE_BYTES_CEILING`, narrowed to `u32`
/// because that is the width of the wire field.
pub const MAX_MESSAGE_BYTES: u32 = MAX_MESSAGE_BYTES_CEILING as u32;

/// The smallest `msize` this profile will accept, in bytes.
///
/// Gate 1's `MIN_MESSAGE_BYTES`.  Below this, `msize` is rejected rather than
/// clamped up: a client that asks for a frame too small to carry a useful
/// message has misunderstood the profile, and silently giving it a larger one
/// would break its own buffer accounting.
pub const MIN_MSIZE: u32 = MIN_MESSAGE_BYTES as u32;

/// The overhead an `Rread` or `Rreaddir` reply adds to its payload:
/// `size[4] type[1] tag[2] count[4]`.
pub const COUNTED_REPLY_OVERHEAD: u32 = HEADER_LEN as u32 + 4;

/// The overhead a `Twrite` adds to its payload:
/// `size[4] type[1] tag[2] fid[4] offset[8] count[4]`.
pub const WRITE_REQUEST_OVERHEAD: u32 = HEADER_LEN as u32 + 16;

/// Negotiate `msize` against this side's maximum.
///
/// The boundaries, exactly as `docs/filesystem-api.md` states them — "M4
/// accepts negotiated `msize` from 256 to 65536 bytes, including 9P framing;
/// reject smaller or different dialects":
///
/// | Offered | Result |
/// | --- | --- |
/// | 255 | [`SessionError::MsizeBelowFloor`] |
/// | 256 | 256 |
/// | 65,536 | 65,536 |
/// | 65,537 | 65,536, reduced |
///
/// Reduction is the only direction: the reply is `min(offered, maximum)`, so a
/// client can never be handed a larger frame than it asked for and a server can
/// never be made to accept one larger than its own ceiling.
///
/// # Errors
///
/// [`SessionError::UnsupportedDialect`] for anything but [`DIALECT`], and
/// [`SessionError::MsizeBelowFloor`] below [`MIN_MSIZE`].
///
/// The dialect refusal is a **session-terminating** protocol violation rather
/// than 9P's traditional `Rversion` with `version = "unknown"`.  That is a
/// decision this profile takes deliberately: the WebSocket subprotocol
/// `agent-tunnel.9p.v1` has already selected the dialect before a byte of 9P is
/// sent, so a `Tversion` naming another one is not a negotiation step, it is a
/// peer that ignored the handshake.  Offering it a retry would also mean
/// accepting a second `Tversion`, which this profile does not.
pub fn negotiate(
    offered_msize: u32,
    offered_version: &str,
    maximum: u32,
) -> Result<u32, SessionError> {
    if offered_version != DIALECT {
        return Err(SessionError::UnsupportedDialect);
    }
    let negotiated = offered_msize.min(maximum).min(MAX_MESSAGE_BYTES);
    if negotiated < MIN_MSIZE {
        return Err(SessionError::MsizeBelowFloor);
    }
    Ok(negotiated)
}

/// One complete 9P message: its tag and its body.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    /// The request tag, or [`NOTAG`] for the version handshake.
    pub tag: u16,
    /// The body.
    pub message: Message,
}

impl Frame {
    /// Build a frame.
    #[must_use]
    pub const fn new(tag: u16, message: Message) -> Self {
        Self { tag, message }
    }

    /// This frame's type.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message.message_type()
    }

    /// Append the complete message — header and body — to `out`.
    ///
    /// On any error `out` is left exactly as it was found, so a caller cannot
    /// accidentally transmit half a frame after a refusal.
    ///
    /// # Errors
    ///
    /// [`CodecError::NotagRequired`] / [`CodecError::NotagNotPermitted`] for a
    /// misused tag, [`CodecError::FrameAboveMsize`] when the finished message
    /// exceeds `msize`, and the body's own encoding errors.
    pub fn encode(&self, msize: u32, out: &mut Vec<u8>) -> Result<(), CodecError> {
        let start = out.len();
        match self.encode_inner(msize, out) {
            Ok(()) => Ok(()),
            Err(error) => {
                out.truncate(start);
                Err(error)
            }
        }
    }

    fn encode_inner(&self, msize: u32, out: &mut Vec<u8>) -> Result<(), CodecError> {
        check_tag(self.message_type(), self.tag)?;
        let start = out.len();
        let mut writer = Writer::new(out);
        writer.u32(0);
        writer.u8(self.message_type().code());
        writer.u16(self.tag);
        self.message.encode_body(&mut writer)?;
        let size = u32::try_from(out.len() - start).map_err(|_| CodecError::FrameAboveMsize)?;
        if size < HEADER_LEN as u32 {
            return Err(CodecError::FrameBelowHeader);
        }
        if size > MAX_MESSAGE_BYTES {
            return Err(CodecError::FrameAboveCeiling);
        }
        if size > msize {
            return Err(CodecError::FrameAboveMsize);
        }
        out[start..start + 4].copy_from_slice(&size.to_le_bytes());
        check_counts(&self.message, msize)?;
        Ok(())
    }

    /// Encode into a fresh buffer.
    ///
    /// # Errors
    /// As [`Frame::encode`].
    pub fn to_bytes(&self, msize: u32) -> Result<Vec<u8>, CodecError> {
        let mut out = Vec::new();
        self.encode(msize, &mut out)?;
        Ok(out)
    }
}

/// Decode exactly one complete message from `bytes`, which must contain that
/// message and nothing else.
///
/// This is the consumer WebSocket rule.  Use [`FrameDecoder`] for a byte
/// stream.
///
/// # Errors
///
/// [`CodecError::TruncatedBody`] when `bytes` is shorter than the declared
/// size, [`CodecError::TrailingBytes`] when it is longer — which is how two 9P
/// messages packed into one binary message are refused — and every framing and
/// body error below.
pub fn decode_exact(bytes: &[u8], msize: u32) -> Result<Frame, CodecError> {
    if bytes.len() < 4 {
        return Err(CodecError::TruncatedBody);
    }
    let size = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    check_size(size, msize)?;
    let size = size as usize;
    if bytes.len() < size {
        return Err(CodecError::TruncatedBody);
    }
    if bytes.len() > size {
        return Err(CodecError::TrailingBytes);
    }
    decode_after_size(&bytes[4..size], msize)
}

/// Validate a declared `size[4]` before a byte of body is read or reserved.
fn check_size(size: u32, msize: u32) -> Result<(), CodecError> {
    if size < HEADER_LEN as u32 {
        return Err(CodecError::FrameBelowHeader);
    }
    if size > MAX_MESSAGE_BYTES {
        return Err(CodecError::FrameAboveCeiling);
    }
    if size > msize {
        return Err(CodecError::FrameAboveMsize);
    }
    Ok(())
}

/// Decode `type[1] tag[2] body` — everything after the size prefix.
fn decode_after_size(rest: &[u8], msize: u32) -> Result<Frame, CodecError> {
    // `check_size` guaranteed at least three bytes here.
    let message_type = MessageType::from_code(rest[0])?;
    let tag = u16::from_le_bytes([rest[1], rest[2]]);
    check_tag(message_type, tag)?;
    let message = Message::decode_body(message_type, &rest[3..])?;
    check_counts(&message, msize)?;
    Ok(Frame { tag, message })
}

/// The reserved-tag rule, applied identically on encode and decode.
///
/// `Tversion` and `Rversion` use [`NOTAG`] and nothing else may; every other
/// message must carry a real tag.  Both halves matter: a `Tversion` with an
/// ordinary tag would occupy a tag slot the handshake has no way to release,
/// and any other message on `NOTAG` could never be flushed or correlated.
fn check_tag(message_type: MessageType, tag: u16) -> Result<(), CodecError> {
    let version_handshake = matches!(message_type, MessageType::Tversion | MessageType::Rversion);
    match (version_handshake, tag == NOTAG) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(CodecError::NotagRequired),
        (false, true) => Err(CodecError::NotagNotPermitted),
    }
}

/// A requested or returned `count[4]` must leave room for its own framing.
///
/// A `Tread` asking for exactly `msize` bytes cannot be answered: the `Rread`
/// carrying them would be `msize + 11`.  Refusing the request is the only
/// honest answer, because the alternative — silently shortening the reply — is
/// indistinguishable to the caller from a short read at end of file.
fn check_counts(message: &Message, msize: u32) -> Result<(), CodecError> {
    let reply_limit = msize.saturating_sub(COUNTED_REPLY_OVERHEAD);
    let write_limit = msize.saturating_sub(WRITE_REQUEST_OVERHEAD);
    let over = match message {
        Message::Tread { count, .. } | Message::Treaddir { count, .. } => *count > reply_limit,
        // A provider cannot acknowledge more bytes than a `Twrite` could have
        // carried in the first place.
        Message::Rwrite { count } => *count > write_limit,
        _ => false,
    };
    if over {
        return Err(CodecError::CountAboveMsize);
    }
    Ok(())
}

#[derive(Debug)]
enum State {
    Size { buf: [u8; 4], filled: usize },
    Body { size: usize, buf: Vec<u8> },
    Failed(CodecError),
}

/// A pure, clock-free, split-tolerant 9P frame decoder over a byte stream.
///
/// It retains at most one unfinished frame, bounded by the negotiated `msize`.
/// The body buffer is reserved **once**, to exactly the validated declared
/// size, after that size has been checked against `msize` — so a declared
/// length can never drive an allocation larger than the negotiated maximum.
#[derive(Debug)]
pub struct FrameDecoder {
    msize: u32,
    state: State,
    frames_started: u64,
}

impl Default for FrameDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameDecoder {
    /// A decoder bounded by [`MAX_MESSAGE_BYTES`] until `msize` is negotiated.
    ///
    /// The version handshake itself is therefore bounded by the profile
    /// ceiling, which is what makes a `Tversion` claiming a gigabyte impossible
    /// to send before any limit has been agreed.
    #[must_use]
    pub const fn new() -> Self {
        Self::with_msize(MAX_MESSAGE_BYTES)
    }

    /// A decoder bounded by `msize`.
    #[must_use]
    pub const fn with_msize(msize: u32) -> Self {
        Self {
            msize,
            state: State::Size {
                buf: [0; 4],
                filled: 0,
            },
            frames_started: 0,
        }
    }

    /// Apply a negotiated `msize`.
    ///
    /// Reduction only, and only at a frame boundary: raising the bound after
    /// bytes have been accepted under a smaller one would let a peer re-frame
    /// what it already sent.
    ///
    /// # Errors
    ///
    /// [`SessionError::MsizeBelowFloor`] below [`MIN_MSIZE`], and
    /// [`SessionError::BeforeVersion`] if a frame is partly received.
    pub fn apply_msize(&mut self, msize: u32) -> Result<(), SessionError> {
        if msize < MIN_MSIZE || msize > self.msize {
            return Err(SessionError::MsizeBelowFloor);
        }
        if !self.is_idle() {
            return Err(SessionError::BeforeVersion);
        }
        self.msize = msize;
        Ok(())
    }

    /// The bound currently in force.
    #[must_use]
    pub const fn msize(&self) -> u32 {
        self.msize
    }

    /// Decode at most one frame from the front of `input`, advancing it past
    /// the bytes consumed.
    ///
    /// Returns `Ok(None)` once `input` is exhausted without completing a frame.
    /// Errors are **sticky**: the first one is latched and returned to every
    /// later call, because a stream that has produced one framing violation has
    /// no trustworthy boundary to resynchronise on.
    ///
    /// # Errors
    /// Every [`CodecError`].
    pub fn decode(&mut self, input: &mut &[u8]) -> Result<Option<Frame>, CodecError> {
        match self.decode_step(input) {
            Err(error) => {
                self.state = State::Failed(error);
                Err(error)
            }
            other => other,
        }
    }

    fn decode_step(&mut self, input: &mut &[u8]) -> Result<Option<Frame>, CodecError> {
        loop {
            match &mut self.state {
                State::Failed(error) => return Err(*error),
                State::Size { buf, filled } => {
                    if input.is_empty() {
                        return Ok(None);
                    }
                    if *filled == 0 {
                        self.frames_started = self.frames_started.saturating_add(1);
                    }
                    let take = (4 - *filled).min(input.len());
                    buf[*filled..*filled + take].copy_from_slice(&input[..take]);
                    *filled += take;
                    *input = &input[take..];
                    if *filled < 4 {
                        return Ok(None);
                    }
                    let size = u32::from_le_bytes(*buf);
                    // Validated before a single body byte is reserved.
                    check_size(size, self.msize)?;
                    let remaining = size as usize - 4;
                    self.state = State::Body {
                        size: remaining,
                        // Bounded by `msize`, which `check_size` just enforced.
                        buf: Vec::with_capacity(remaining),
                    };
                }
                State::Body { size, buf } => {
                    let take = (*size - buf.len()).min(input.len());
                    buf.extend_from_slice(&input[..take]);
                    *input = &input[take..];
                    if buf.len() < *size {
                        return Ok(None);
                    }
                    let body = core::mem::take(buf);
                    self.state = State::Size {
                        buf: [0; 4],
                        filled: 0,
                    };
                    return decode_after_size(&body, self.msize).map(Some);
                }
            }
        }
    }

    /// True at a frame boundary with no retained bytes.
    #[must_use]
    pub const fn is_idle(&self) -> bool {
        matches!(self.state, State::Size { filled: 0, .. })
    }

    /// Bytes currently retained by the decoder.
    ///
    /// Never above the negotiated `msize`; the fuzz suite asserts that over
    /// arbitrary input.
    #[must_use]
    pub fn retained_len(&self) -> usize {
        match &self.state {
            State::Size { filled, .. } => *filled,
            State::Body { buf, .. } => 4 + buf.len(),
            State::Failed(_) => 0,
        }
    }

    /// How many frames have begun arriving, so a caller can tell a trickled
    /// frame from a new one when enforcing a completion deadline.
    #[must_use]
    pub const fn frames_started(&self) -> u64 {
        self.frames_started
    }

    /// The latched error, if the decoder has failed.
    #[must_use]
    pub const fn failure(&self) -> Option<CodecError> {
        match self.state {
            State::Failed(error) => Some(error),
            _ => None,
        }
    }

    /// Report the end of the stream.
    ///
    /// # Errors
    ///
    /// [`CodecError::TruncatedBody`] when the stream ended inside a frame, which
    /// is the only way a caller learns that a trailing partial message was not
    /// simply a chunk boundary.
    pub fn fin(&mut self) -> Result<(), CodecError> {
        if let State::Failed(error) = self.state {
            return Err(error);
        }
        if self.is_idle() {
            return Ok(());
        }
        self.state = State::Failed(CodecError::TruncatedBody);
        Err(CodecError::TruncatedBody)
    }
}
