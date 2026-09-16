//! The filesystem error vocabulary and mutation outcomes.
//!
//! Every type here is `Copy` and carries no owned data beyond other field-free
//! enums, so a derived `Debug` **cannot** contain a path, a file name, file
//! content, a host detail or a credential.  That is the payload-free guarantee
//! from `docs/filesystem-api.md` enforced by construction rather than by
//! reviewer discipline, the same way `tunnel-http-forward::CodecError` does it.
//!
//! The virtual path a caller supplied is deliberately *not* part of an error.
//! A consumer already knows which path it asked for and correlates by request
//! tag; repeating it here would put it into every log line and `Debug`
//! rendering that touches the error.

use core::fmt;

use crate::limits::LimitField;
use crate::path::PathRule;

/// How far a mutation got before it failed.
///
/// The ordering is meaningful: once an operation has been observed at
/// [`Outcome::Partial`] or [`Outcome::Unknown`], it can never be reported as
/// [`Outcome::NotStarted`] again.  [`Outcome::merge`] enforces that.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Outcome {
    /// Refused before anything was dispatched to the provider.
    NotStarted,
    /// Dispatched, and the provider reported it made no change.
    Failed,
    /// Some acknowledged effect applied and the rest did not.
    Partial,
    /// Dispatched, and whether an effect applied is not known.
    Unknown,
}

impl Outcome {
    /// Every outcome, weakest first.
    pub const ALL: [Self; 4] = [Self::NotStarted, Self::Failed, Self::Partial, Self::Unknown];

    /// The stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::NotStarted => "not_started",
            Self::Failed => "failed",
            Self::Partial => "partial",
            Self::Unknown => "unknown",
        }
    }

    /// Parse the exact wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    /// Whether the caller may assume no side effect occurred.
    ///
    /// True only for [`Outcome::NotStarted`] and [`Outcome::Failed`].  A
    /// cancellation after dispatch is never `NotStarted`.
    #[must_use]
    pub const fn is_settled(self) -> bool {
        matches!(self, Self::NotStarted | Self::Failed)
    }

    /// Combine an earlier and a later observation, never weakening.
    ///
    /// This is the rule that "a rejection after a previously confirmed partial
    /// chunk cannot become `not_started`".
    #[must_use]
    pub fn merge(self, later: Self) -> Self {
        if later >= self { later } else { self }
    }
}

impl fmt::Display for Outcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A filesystem error code, translated from a Linux `.L` errno.
///
/// Closed: an errno with no mapping here becomes [`FsErrorCode::Einval`]
/// rather than being passed through, so a host cannot widen the vocabulary a
/// consumer must handle.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum FsErrorCode {
    /// No such file or directory.
    Enoent,
    /// Permission denied by the host.
    Eacces,
    /// Denied by this export's grant, before the host was consulted.
    Eperm,
    /// The export or the target is read-only.
    Erofs,
    /// The target already exists and exclusive creation was required.
    Eexist,
    /// A path component was not a directory.
    Enotdir,
    /// The target was a directory where a file was required.
    Eisdir,
    /// A directory was not empty.
    Enotempty,
    /// Too many symbolic links, or a link where none may be followed.
    Eloop,
    /// A cross-export or cross-device operation.  Never emulated by copy.
    Exdev,
    /// The operation, flag or feature is not implemented by this profile.
    Enotsup,
    /// A value exceeded a size limit.
    Efbig,
    /// A path or component exceeded its length limit.
    Enametoolong,
    /// The request was structurally invalid.
    Einval,
}

impl FsErrorCode {
    /// Every code.
    pub const ALL: [Self; 14] = [
        Self::Enoent,
        Self::Eacces,
        Self::Eperm,
        Self::Erofs,
        Self::Eexist,
        Self::Enotdir,
        Self::Eisdir,
        Self::Enotempty,
        Self::Eloop,
        Self::Exdev,
        Self::Enotsup,
        Self::Efbig,
        Self::Enametoolong,
        Self::Einval,
    ];

    /// The stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enoent => "ENOENT",
            Self::Eacces => "EACCES",
            Self::Eperm => "EPERM",
            Self::Erofs => "EROFS",
            Self::Eexist => "EEXIST",
            Self::Enotdir => "ENOTDIR",
            Self::Eisdir => "EISDIR",
            Self::Enotempty => "ENOTEMPTY",
            Self::Eloop => "ELOOP",
            Self::Exdev => "EXDEV",
            Self::Enotsup => "ENOTSUP",
            Self::Efbig => "EFBIG",
            Self::Enametoolong => "ENAMETOOLONG",
            Self::Einval => "EINVAL",
        }
    }

    /// Parse the exact wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    /// The Linux `.L` errno number this code is sent as in an `Rlerror`.
    #[must_use]
    pub const fn errno(self) -> u32 {
        match self {
            Self::Enoent => 2,
            Self::Eacces => 13,
            Self::Eperm => 1,
            Self::Erofs => 30,
            Self::Eexist => 17,
            Self::Enotdir => 20,
            Self::Eisdir => 21,
            Self::Enotempty => 39,
            Self::Eloop => 40,
            Self::Exdev => 18,
            Self::Enotsup => 95,
            Self::Efbig => 27,
            Self::Enametoolong => 36,
            Self::Einval => 22,
        }
    }

    /// Map a Linux errno onto this closed vocabulary.
    ///
    /// Anything unmapped becomes [`FsErrorCode::Einval`]; a host errno is never
    /// passed through, so a consumer's match stays exhaustive and a host cannot
    /// disclose which of its own failure modes occurred.
    #[must_use]
    pub fn from_errno(errno: u32) -> Self {
        Self::ALL
            .into_iter()
            .find(|code| code.errno() == errno)
            .unwrap_or(Self::Einval)
    }
}

impl fmt::Display for FsErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A transport or session failure, distinct from filesystem absence.
///
/// Kept separate so that `exists` can convert only a confirmed
/// [`FsErrorCode::Enoent`] into `false`, and never an unavailable device or an
/// expired credential.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionErrorCode {
    /// The logical stream ended.
    SessionLost,
    /// The consumer credential expired or was revoked.
    AuthExpired,
    /// The device is not connected.
    DeviceOffline,
    /// A consumer, tenant, session or per-session limit was reached.
    ResourceExhausted,
    /// A request or operation deadline elapsed.
    DeadlineExceeded,
    /// The caller cancelled.  Cancellation after dispatch is not rollback.
    Aborted,
    /// The grant revision moved; fresh discovery is required.
    CapabilitiesChanged,
    /// The peer violated the 9P or framing profile.
    ProtocolViolation,
}

impl SessionErrorCode {
    /// Every code.
    pub const ALL: [Self; 8] = [
        Self::SessionLost,
        Self::AuthExpired,
        Self::DeviceOffline,
        Self::ResourceExhausted,
        Self::DeadlineExceeded,
        Self::Aborted,
        Self::CapabilitiesChanged,
        Self::ProtocolViolation,
    ];

    /// The stable wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SessionLost => "SESSION_LOST",
            Self::AuthExpired => "AUTH_EXPIRED",
            Self::DeviceOffline => "DEVICE_OFFLINE",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::Aborted => "ABORTED",
            Self::CapabilitiesChanged => "CAPABILITIES_CHANGED",
            Self::ProtocolViolation => "PROTOCOL_VIOLATION",
        }
    }

    /// Parse the exact wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    /// The WebSocket close code this failure closes a consumer socket with.
    #[must_use]
    pub const fn close_code(self) -> u16 {
        match self {
            Self::ProtocolViolation => 1002,
            Self::AuthExpired | Self::CapabilitiesChanged => 1008,
            Self::ResourceExhausted => 1013,
            Self::SessionLost | Self::DeviceOffline | Self::DeadlineExceeded | Self::Aborted => {
                1011
            }
        }
    }
}

impl fmt::Display for SessionErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Why an operation was refused, at the granularity the provider decides it.
///
/// Every variant is `Copy` and its payload is another field-free enum.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FsError {
    /// A filesystem failure, translated to the closed errno vocabulary.
    Filesystem {
        /// The translated code.
        code: FsErrorCode,
        /// How far the operation got.
        outcome: Outcome,
    },
    /// The supplied path could not be validated.
    Path(PathRule),
    /// A negotiated limit refused the request.
    Limit(LimitField),
    /// The grant does not permit the requested primitive.
    ///
    /// Reported as [`FsErrorCode::Eperm`] with [`Outcome::NotStarted`]: the
    /// decision is taken before any backend dispatch.
    NotPermitted,
    /// The transport or session failed.
    Session {
        /// The session failure.
        code: SessionErrorCode,
        /// How far any in-flight operation got.
        outcome: Outcome,
    },
}

impl FsError {
    /// Build a not-started filesystem failure.
    #[must_use]
    pub const fn refused(code: FsErrorCode) -> Self {
        Self::Filesystem {
            code,
            outcome: Outcome::NotStarted,
        }
    }

    /// The errno-vocabulary code a consumer branches on.
    #[must_use]
    pub const fn code(self) -> FsErrorCode {
        match self {
            Self::Filesystem { code, .. } => code,
            Self::Path(rule) => match rule {
                PathRule::TooLongBytes | PathRule::ComponentTooLong => FsErrorCode::Enametoolong,
                _ => FsErrorCode::Einval,
            },
            Self::Limit(field) => match field {
                LimitField::MaxBufferedFileBytes
                | LimitField::MaxTotalBufferedBytes
                | LimitField::MaxQueuedBytes
                | LimitField::MaxMessageBytes => FsErrorCode::Efbig,
                LimitField::MaxPathBytes | LimitField::MaxPathComponents => {
                    FsErrorCode::Enametoolong
                }
                _ => FsErrorCode::Einval,
            },
            Self::NotPermitted => FsErrorCode::Eperm,
            Self::Session { .. } => FsErrorCode::Einval,
        }
    }

    /// How far the operation got.
    ///
    /// Every refusal this crate can produce on its own is
    /// [`Outcome::NotStarted`], because nothing here dispatches anything.
    #[must_use]
    pub const fn outcome(self) -> Outcome {
        match self {
            Self::Filesystem { outcome, .. } | Self::Session { outcome, .. } => outcome,
            Self::Path(_) | Self::Limit(_) | Self::NotPermitted => Outcome::NotStarted,
        }
    }

    /// Whether a caller may safely start the operation again.
    ///
    /// Only a settled outcome is retryable, and this crate never marks a
    /// mutation retryable on the caller's behalf: a `true` here means the
    /// operation demonstrably did not begin, not that retrying is advisable.
    #[must_use]
    pub const fn did_not_start(self) -> bool {
        matches!(self.outcome(), Outcome::NotStarted)
    }
}

impl fmt::Display for FsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Every component below is a static string.  No path, file name, file
        // content, host detail or credential can reach this output.
        match self {
            Self::Filesystem { code, outcome } => {
                write!(formatter, "{} ({})", code.as_str(), outcome.as_str())
            }
            Self::Path(rule) => write!(formatter, "EINVAL ({})", rule.as_str()),
            Self::Limit(field) => {
                write!(formatter, "{} ({})", self.code().as_str(), field.as_str())
            }
            Self::NotPermitted => formatter.write_str("EPERM (not_started)"),
            Self::Session { code, outcome } => {
                write!(formatter, "{} ({})", code.as_str(), outcome.as_str())
            }
        }
    }
}

impl std::error::Error for FsError {}

impl From<PathRule> for FsError {
    fn from(rule: PathRule) -> Self {
        Self::Path(rule)
    }
}
