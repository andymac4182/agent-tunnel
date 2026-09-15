//! Typed, payload-free codec errors.
//!
//! No variant carries body octets, JSON text, header values, paths, or query
//! bytes.  The only data carried is a record kind byte from the fixed header,
//! which is framing metadata rather than payload.

use core::fmt;

/// The `code` values defined for HTTP forwarding error detail.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HttpErrorCode {
    BadRecord,
    InvalidHead,
    BodyLimit,
    LengthMismatch,
    UnsupportedFeature,
    StreamInterrupted,
    Cancelled,
    DeadlineExceeded,
}

impl HttpErrorCode {
    /// The exact wire spelling used in bounded status metadata.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BadRecord => "HTTP_BAD_RECORD",
            Self::InvalidHead => "HTTP_INVALID_HEAD",
            Self::BodyLimit => "HTTP_BODY_LIMIT",
            Self::LengthMismatch => "HTTP_LENGTH_MISMATCH",
            Self::UnsupportedFeature => "HTTP_UNSUPPORTED_FEATURE",
            Self::StreamInterrupted => "HTTP_STREAM_INTERRUPTED",
            Self::Cancelled => "HTTP_CANCELLED",
            Self::DeadlineExceeded => "HTTP_DEADLINE_EXCEEDED",
        }
    }

    /// Every defined code.
    pub const ALL: [Self; 8] = [
        Self::BadRecord,
        Self::InvalidHead,
        Self::BodyLimit,
        Self::LengthMismatch,
        Self::UnsupportedFeature,
        Self::StreamInterrupted,
        Self::Cancelled,
        Self::DeadlineExceeded,
    ];

    /// Parse the exact wire spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|code| code.as_str() == text)
    }
}

impl fmt::Display for HttpErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which path rule rejected a `path`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PathRule {
    Empty,
    TooLong,
    MissingLeadingSlash,
    DisallowedCharacter,
    PercentEscape,
    Backslash,
    QueryOrFragmentDelimiter,
    Nul,
    EmptySegment,
    DotSegment,
}

/// Which query rule rejected a `query`.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum QueryRule {
    NotPermitted,
    TooLong,
    TooManyPairs,
    EmptyPair,
    EmptyKey,
    DisallowedCharacter,
    InvalidPercentEscape,
    EncodedKey,
    InvalidUtf8,
    DecodedControl,
    CredentialParameter,
    UnrecognizedKey,
    DuplicateKey,
}

/// Which header rule rejected the `headers` array.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum HeaderRule {
    NameLength,
    NameCharacter,
    ValueTooLong,
    ValueCharacter,
    ValueBoundaryWhitespace,
    TooManyFields,
    TotalBytes,
    /// Routing, framing, credential, or internal metadata.
    Forbidden,
    /// Hop-by-hop protocol features this profile cannot carry.
    Unsupported,
    NotAllowed,
    RepeatedSingleton,
}

/// Every error the codec, head parser, and directional machine can report.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CodecError {
    // Fixed record header.
    UnknownKind(u8),
    NonzeroFlags,
    NonzeroReserved,
    EmptyHead,
    HeadTooLarge,
    EmptyBody,
    RecordTooLarge,
    EndWithPayload,

    // Directional grammar.
    SecondHead,
    WrongDirectionHead,
    BodyBeforeHead,
    EndBeforeHead,
    BodyAfterEnd,
    RepeatedEnd,
    DataAfterEnd,
    FinBeforeEnd,
    EofInsideRecord,
    AfterTerminal,

    // Head JSON syntax and schema.
    InvalidUtf8,
    JsonSyntax,
    InvalidEscape,
    LoneSurrogate,
    NestingTooDeep,
    TrailingData,
    NotAnObject,
    DuplicateKey,
    UnknownKey,
    MissingKey,
    WrongType,

    // Head field values.
    InvalidMethod,
    InvalidHttpVersion,
    HttpVersionNotAllowed,
    InvalidStatus,
    InvalidBodyLength,
    RouteNotAllowed,
    ZeroBodyRequired,
    InvalidPath(PathRule),
    InvalidQuery(QueryRule),
    InvalidHeader(HeaderRule),

    // Lengths and limits.
    DeclaredLengthExceedsLimit,
    BodyLimitExceeded,
    BodyShorterThanDeclared,
    BodyLongerThanDeclared,
    BodyForbidden,

    // Caller-observed progress.
    RecordDeadlineExceeded,

    // The encoder's serialized head did not re-parse to the same value.
    EncoderRoundTrip,
}

impl CodecError {
    /// Map to the document's `HTTP_*` detail code.
    #[must_use]
    pub const fn code(self) -> HttpErrorCode {
        match self {
            Self::UnknownKind(_)
            | Self::NonzeroFlags
            | Self::NonzeroReserved
            | Self::EmptyHead
            | Self::HeadTooLarge
            | Self::EmptyBody
            | Self::RecordTooLarge
            | Self::EndWithPayload
            | Self::SecondHead
            | Self::WrongDirectionHead
            | Self::BodyBeforeHead
            | Self::EndBeforeHead
            | Self::BodyAfterEnd
            | Self::RepeatedEnd
            | Self::DataAfterEnd
            | Self::FinBeforeEnd
            | Self::EofInsideRecord
            | Self::AfterTerminal => HttpErrorCode::BadRecord,
            Self::InvalidHeader(HeaderRule::Unsupported) => HttpErrorCode::UnsupportedFeature,
            Self::HttpVersionNotAllowed => HttpErrorCode::UnsupportedFeature,
            Self::InvalidUtf8
            | Self::JsonSyntax
            | Self::InvalidEscape
            | Self::LoneSurrogate
            | Self::NestingTooDeep
            | Self::TrailingData
            | Self::NotAnObject
            | Self::DuplicateKey
            | Self::UnknownKey
            | Self::MissingKey
            | Self::WrongType
            | Self::InvalidMethod
            | Self::InvalidHttpVersion
            | Self::InvalidStatus
            | Self::InvalidBodyLength
            | Self::RouteNotAllowed
            | Self::ZeroBodyRequired
            | Self::InvalidPath(_)
            | Self::InvalidQuery(_)
            | Self::InvalidHeader(_)
            | Self::EncoderRoundTrip => HttpErrorCode::InvalidHead,
            Self::DeclaredLengthExceedsLimit | Self::BodyLimitExceeded => HttpErrorCode::BodyLimit,
            Self::BodyShorterThanDeclared | Self::BodyLongerThanDeclared | Self::BodyForbidden => {
                HttpErrorCode::LengthMismatch
            }
            Self::RecordDeadlineExceeded => HttpErrorCode::DeadlineExceeded,
        }
    }
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Debug output of these variants contains only static rule names and
        // at most a record kind byte, never payload data.
        write!(formatter, "{}: {:?}", self.code(), self)
    }
}

impl std::error::Error for CodecError {}

/// A trusted-configuration error when building a policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum PolicyError {
    InvalidRoutePath(PathRule),
    InvalidHeaderName,
    ForbiddenHeader,
    /// A hop-by-hop feature header (`transfer-encoding`, `te`, `trailer`,
    /// `upgrade`, `expect`) that the runtime classifies as unsupported.
    UnsupportedHeader,
    /// A body limit above [`crate::MAX_BODY_LIMIT`].
    BodyLimitAboveCeiling,
    InvalidQueryKey,
    CredentialQueryParameter,
    DuplicateEntry,
}

impl fmt::Display for PolicyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid http-forward policy: {self:?}")
    }
}

impl std::error::Error for PolicyError {}
