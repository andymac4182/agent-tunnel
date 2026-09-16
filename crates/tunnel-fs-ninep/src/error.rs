//! Typed, payload-free codec and session errors.
//!
//! Every type here is `Copy` and every payload is another field-free enum or a
//! framing byte from the fixed header.  No variant can carry a file name, a
//! path, file content, a link target, a host detail or a credential, so a
//! derived `Debug` is safe to log — the same construction rule
//! `tunnel_fs_core::error` and `tunnel_http_forward::CodecError` follow.
//!
//! Two enums rather than one, because the two failures have different
//! consequences on the wire:
//!
//! * A [`CodecError`] is a **framing violation**.  The peer's bytes could not
//!   be read as this profile's 9P, so the reply tag — the only thing that could
//!   correlate an `Rlerror` — is itself untrustworthy.  Every one of them
//!   closes the consumer socket with 1002, and none is ever answered with an
//!   `Rlerror`.  `docs/filesystem-api.md` pins that for an over-`msize` frame;
//!   this crate applies the same rule to every framing failure, because the
//!   reason is the same in each case.
//! * A [`SessionError`] is a **state-machine refusal**.  The frame decoded, so
//!   its tag is known and an `Rlerror` could carry it.  Which of those two
//!   answers each one takes is [`SessionError::answer`], and that split is a
//!   recorded decision rather than an implementation detail.

use core::fmt;

use tunnel_fs_core::{FsError, FsErrorCode, LimitField, Outcome, SessionErrorCode};

use crate::message::MessageType;

/// Which `string[s]` field of a message failed its rule.
///
/// Field-free: the name of the field, never its bytes.  A caller that wants to
/// know *which* name was malformed already knows the message it sent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum StringField {
    /// `Tversion`/`Rversion` `version`.
    Version,
    /// `Tattach` `uname`.
    Uname,
    /// `Tattach` `aname`.
    Aname,
    /// One `Twalk` `wname`.
    WalkName,
    /// A `name` in `Tlcreate`, `Tmkdir`, `Tsymlink`, `Trename`, `Tlink` or
    /// `Tunlinkat`.
    Name,
    /// `Trenameat` `oldname`.
    OldName,
    /// `Trenameat` `newname`.
    NewName,
    /// `Tsymlink` `symtgt`.
    SymlinkTarget,
    /// `Rreadlink` `target`.
    LinkTarget,
    /// The `name` of one entry inside an `Rreaddir` payload.
    DirEntryName,
}

impl StringField {
    /// Every string field this profile defines.
    pub const ALL: [Self; 10] = [
        Self::Version,
        Self::Uname,
        Self::Aname,
        Self::WalkName,
        Self::Name,
        Self::OldName,
        Self::NewName,
        Self::SymlinkTarget,
        Self::LinkTarget,
        Self::DirEntryName,
    ];

    /// The stable diagnostic token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Version => "version",
            Self::Uname => "uname",
            Self::Aname => "aname",
            Self::WalkName => "wname",
            Self::Name => "name",
            Self::OldName => "oldname",
            Self::NewName => "newname",
            Self::SymlinkTarget => "symtgt",
            Self::LinkTarget => "target",
            Self::DirEntryName => "direntry.name",
        }
    }
}

impl fmt::Display for StringField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A framing, encoding or decoding failure.
///
/// Every variant means the byte stream is no longer trustworthy.  There is no
/// "skip this message and continue": [`crate::codec::FrameDecoder`] latches the
/// first one and answers it to every later call.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CodecError {
    /// The declared `size[4]` was below the seven-byte fixed header.
    FrameBelowHeader,
    /// The declared `size[4]` exceeded the negotiated `msize`.
    ///
    /// Exactly `msize` is legal; one byte above it is this.
    FrameAboveMsize,
    /// The declared `size[4]` exceeded [`crate::MAX_MESSAGE_BYTES`] before any
    /// `msize` had been negotiated.
    FrameAboveCeiling,
    /// The body ended before a field it declared.
    TruncatedBody,
    /// Bytes remained after the body was fully decoded.
    ///
    /// On the consumer WebSocket this is also how two 9P messages packed into
    /// one binary message are refused.
    TrailingBytes,
    /// The `type[1]` byte is not a 9P2000.L opcode at all.
    UnknownMessageType(u8),
    /// A real 9P2000.L opcode that this profile does not implement.
    ///
    /// Distinct from [`CodecError::UnknownMessageType`] deliberately: the
    /// distinction is static protocol knowledge, discloses nothing about this
    /// export, and tells an implementer whether they mistyped an opcode or
    /// reached for one the profile denies.  The byte it carries is the peer's
    /// own opcode — framing metadata from the fixed header, not payload.
    MessageTypeNotInProfile(u8),
    /// A reply where a request was expected, or the reverse.
    UnexpectedDirection(MessageType),
    /// A `string[s]` field was not valid UTF-8.
    ///
    /// **This is gate 3's answer to the contract's non-UTF-8 obligation.**  The
    /// bytes are refused here, before they could reach
    /// `tunnel_fs_core::VirtualPath`, and they are never replaced, transliterated
    /// or lossily converted.
    StringNotUtf8(StringField),
    /// A `string[s]` field was longer than the 16-bit length prefix allows.
    StringTooLong(StringField),
    /// A `count[4]` for `Tread`, `Twrite`, `Rread` or `Treaddir` could not fit
    /// its own message inside `msize`.
    CountAboveMsize,
    /// `Twalk` named more than [`crate::MAX_WALK_NAMES`] components.
    TooManyWalkNames,
    /// `NOTAG` appeared on a message other than `Tversion`.
    NotagNotPermitted,
    /// `Tversion` did not use `NOTAG`.
    NotagRequired,
    /// `NOFID` appeared where a live fid was required.
    NofidNotPermitted,
    /// A qid `type[1]` carried a bit outside `QTFILE`, `QTDIR` and `QTSYMLINK`.
    QidTypeNotInProfile,
    /// An `Rlerror` carried an errno outside the closed gate-1 vocabulary.
    ///
    /// The vocabulary is closed in both directions: a provider may not widen it
    /// on the way out, and a client may not be made to handle a code that is
    /// not in it on the way in.
    ErrnoNotInVocabulary,
    /// An `Rreaddir` payload did not decode as a whole number of entries.
    MalformedDirEntry,
}

impl CodecError {
    /// The session-level code this framing violation is reported as.
    ///
    /// Always [`SessionErrorCode::ProtocolViolation`], and therefore always
    /// WebSocket close 1002.  A framing failure is never an `Rlerror`: the tag
    /// that would have to correlate the reply is part of the frame that failed
    /// to decode.
    #[must_use]
    pub const fn session_code(self) -> SessionErrorCode {
        SessionErrorCode::ProtocolViolation
    }

    /// The WebSocket close code, which is 1002 for every variant.
    #[must_use]
    pub const fn close_code(self) -> u16 {
        1002
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every component is a static string or a framing byte from the fixed
        // header.  No payload can reach this output.
        write!(formatter, "PROTOCOL_VIOLATION: {self:?}")
    }
}

impl std::error::Error for CodecError {}

/// How a [`SessionError`] is answered on the wire.
///
/// The split is the whole point of the type, so it is named rather than
/// inferred from a code at each call site.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Answer {
    /// Reply `Rlerror` with this error and keep the session.
    ///
    /// Reachable only for a refusal the client can recover from without losing
    /// the other outstanding tags on the connection.
    Rlerror(FsError),
    /// Close the consumer socket with this code and end the session.
    Close(SessionErrorCode),
}

impl Answer {
    /// The WebSocket close code, or `None` for an `Rlerror`.
    #[must_use]
    pub const fn close_code(self) -> Option<u16> {
        match self {
            Self::Rlerror(_) => None,
            Self::Close(code) => code.close_code(),
        }
    }
}

/// A refusal taken by the session state machine.
///
/// The frame decoded, so its tag is known.  Whether the refusal is answered
/// with an `Rlerror` or by closing the socket is [`SessionError::answer`].
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SessionError {
    /// A request arrived before `Tversion`.
    BeforeVersion,
    /// A filesystem request arrived before `Tattach`.
    BeforeAttach,
    /// A second `Tversion` arrived.
    ///
    /// `docs/filesystem-api.md`: "Repeated `Tversion` after attachment is
    /// outside this profile; terminate rather than implicitly reset hidden
    /// adapter state."  This profile terminates on the *second* `Tversion`
    /// whether or not an attach has happened, because one export, one root and
    /// one grant context leave nothing a renegotiation could change.
    RepeatedVersion,
    /// A second `Tattach` arrived.
    ///
    /// One consumer connection selects one export, one root and one grant
    /// context, so a session has exactly one root fid.
    RepeatedAttach,
    /// The offered dialect was not `9P2000.L`.
    UnsupportedDialect,
    /// The offered `msize` was below [`tunnel_fs_core::MIN_MESSAGE_BYTES`].
    MsizeBelowFloor,
    /// `Tattach` carried an `afid` other than `NOFID`, a non-empty `uname` or
    /// `aname`, or an `n_uname` other than `NONUNAME`.
    ///
    /// These fields cannot choose a host identity or another export, so a value
    /// in them is a request this profile has no way to honour.
    AttachFieldNotPermitted,
    /// The tag is already outstanding.
    TagInUse,
    /// The tag is not outstanding, so no reply or flush can name it.
    TagNotInUse,
    /// The tag is outstanding but reserved by a pending flush, so it may not be
    /// reused yet.
    TagReservedByFlush,
    /// A new request would exceed `maxInflightRequests`.
    TagQuotaExhausted,
    /// The fid is not allocated in this session.
    UnknownFid,
    /// The fid is already allocated, so it cannot be the target of a walk or an
    /// attach.
    FidInUse,
    /// A new fid would exceed `maxFids`.
    FidQuotaExhausted,
    /// The fid is open, and the request is legal only on an unopened fid.
    FidIsOpen,
    /// The fid is not open, and the request is legal only on an open fid.
    FidNotOpen,
    /// The fid is open on a directory and the request requires a regular file,
    /// or the reverse.
    FidWrongKind,
    /// The grant does not permit the primitive this request decodes to.
    NotPermitted,
    /// A flag or mask bit outside the negotiated profile was set.
    FlagNotInProfile,
    /// A reply arrived whose type is not the partner of its request's.
    UnexpectedReply,
    /// A reply's own fields contradict the request it answers — an `Rwalk`
    /// with more qids than its `Twalk` named, or an `Rversion` that did not
    /// carry the value negotiation settled on.
    MalformedReply,
    /// The walk would build a path `tunnel_fs_core::VirtualPath` refuses.
    Path(tunnel_fs_core::PathRule),
    /// The session already ended.
    Closed,
}

impl SessionError {
    /// How this refusal is answered on the wire.
    ///
    /// Three groups, each for its own reason:
    ///
    /// * **`Rlerror`, session preserved** — a refusal a correct client can
    ///   recover from: an unknown or wrongly-used fid, a fid quota reached, a
    ///   flag the profile denies, a path the namespace refuses, or a primitive
    ///   the grant does not permit.  A fid quota is recoverable by clunking,
    ///   and gate 1 already decided its code (`LimitField::MaxFids` renders
    ///   `EINVAL`), so this crate follows that rather than inventing one.
    /// * **Close 1013** — the tag quota.  Reserving a tag is what makes a reply
    ///   correlatable, so a request beyond the tag quota cannot be answered by
    ///   an `Rlerror` carrying that very tag without first admitting the tag
    ///   the quota just refused.  There is no honest per-request answer, so the
    ///   session is closed as overloaded.
    /// * **Close 1002** — everything that makes the session's own state
    ///   ambiguous: out-of-order messages, repeated `Tversion`/`Tattach`, a
    ///   dialect this profile does not speak, an `msize` below the floor,
    ///   forbidden `Tattach` fields and every tag misuse.
    #[must_use]
    pub fn answer(self) -> Answer {
        match self {
            Self::UnknownFid => Answer::Rlerror(FsError::refused(FsErrorCode::Einval)),
            Self::FidInUse => Answer::Rlerror(FsError::refused(FsErrorCode::Einval)),
            Self::FidIsOpen | Self::FidNotOpen => {
                Answer::Rlerror(FsError::refused(FsErrorCode::Einval))
            }
            Self::FidWrongKind => Answer::Rlerror(FsError::refused(FsErrorCode::Enotdir)),
            Self::FidQuotaExhausted => Answer::Rlerror(FsError::Limit(LimitField::MaxFids)),
            Self::NotPermitted => Answer::Rlerror(FsError::NotPermitted),
            Self::FlagNotInProfile => Answer::Rlerror(FsError::refused(FsErrorCode::Enotsup)),
            Self::Path(rule) => Answer::Rlerror(FsError::Path(rule)),
            Self::TagQuotaExhausted => Answer::Close(SessionErrorCode::ResourceExhausted),
            Self::Closed => Answer::Close(SessionErrorCode::SessionLost),
            Self::BeforeVersion
            | Self::BeforeAttach
            | Self::RepeatedVersion
            | Self::RepeatedAttach
            | Self::UnsupportedDialect
            | Self::MsizeBelowFloor
            | Self::AttachFieldNotPermitted
            | Self::TagInUse
            | Self::TagNotInUse
            | Self::TagReservedByFlush
            | Self::UnexpectedReply
            | Self::MalformedReply => Answer::Close(SessionErrorCode::ProtocolViolation),
        }
    }

    /// Whether this refusal ends the session.
    #[must_use]
    pub fn is_fatal(self) -> bool {
        matches!(self.answer(), Answer::Close(_))
    }

    /// The `FsError` an `Rlerror` would carry, or `None` when the answer is a
    /// close.
    #[must_use]
    pub fn as_fs_error(self) -> Option<FsError> {
        match self.answer() {
            Answer::Rlerror(error) => Some(error),
            Answer::Close(_) => None,
        }
    }

    /// How far any work got.
    ///
    /// Always [`Outcome::NotStarted`]: every refusal here is taken before the
    /// request reaches the resolver, and this crate dispatches nothing.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        Outcome::NotStarted
    }
}

impl fmt::Display for SessionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `Debug` here is field-free enums only; `PathRule`'s own `Debug`
        // carries no path bytes either.
        write!(formatter, "9p session refusal: {self:?}")
    }
}

impl std::error::Error for SessionError {}

impl From<tunnel_fs_core::PathRule> for SessionError {
    fn from(rule: tunnel_fs_core::PathRule) -> Self {
        Self::Path(rule)
    }
}
