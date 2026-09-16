//! The negotiated per-session limits.
//!
//! Every field mirrors one property of the `limits` object in
//! `docs/contracts/filesystem-capabilities.schema.json`.  The ceiling constants
//! below are that schema's `maximum` values and the profile defaults are its
//! example's values.
//!
//! **There is no unlimited sentinel.**  Every field has a minimum of one and a
//! fixed ceiling, and [`Limits::new`] refuses zero and refuses anything above
//! the ceiling, so neither `0` nor `u64::MAX` can be read as "no limit".
//! Negotiation may only reduce a limit; [`Limits::reduce_to`] is the only
//! operation that changes one and it never raises.

use core::fmt;

use crate::path::PathBounds;

/// Ceiling for `maxMessageBytes`: the complete 9P message including header.
pub const MAX_MESSAGE_BYTES_CEILING: u64 = 65_536;
/// Floor for `maxMessageBytes`.  Smaller dialects are rejected, not clamped.
pub const MIN_MESSAGE_BYTES: u64 = 256;
/// Ceiling for `maxInflightRequests`: outstanding request tags per session.
pub const MAX_INFLIGHT_REQUESTS_CEILING: u64 = 64;
/// Ceiling for `maxFids`: live fids per session.
pub const MAX_FIDS_CEILING: u64 = 256;
/// Ceiling for `maxQueuedBytes`: queued encoded payload per consumer.
pub const MAX_QUEUED_BYTES_CEILING: u64 = 1_048_576;
/// Ceiling for `maxBufferedFileBytes`: one materialized file.
pub const MAX_BUFFERED_FILE_BYTES_CEILING: u64 = 16_777_216;
/// Ceiling for `maxTotalBufferedBytes`: concurrent internal materialization.
pub const MAX_TOTAL_BUFFERED_BYTES_CEILING: u64 = 33_554_432;
/// Ceiling for `maxPathBytes`.
pub const MAX_PATH_BYTES_CEILING: u64 = 4_096;
/// Ceiling for `maxPathComponents`.
pub const MAX_PATH_COMPONENTS_CEILING: u64 = 256;
/// Ceiling for `maxTraversalEntries`.
pub const MAX_TRAVERSAL_ENTRIES_CEILING: u64 = 10_000;
/// Ceiling for `maxTraversalDepth`.
pub const MAX_TRAVERSAL_DEPTH_CEILING: u64 = 64;
/// Ceiling for `requestTimeoutSeconds`: one 9P request.
pub const REQUEST_TIMEOUT_SECONDS_CEILING: u64 = 30;
/// Ceiling for `defaultOperationTimeoutSeconds`.
pub const DEFAULT_OPERATION_TIMEOUT_SECONDS_CEILING: u64 = 300;
/// Ceiling for `maxOperationTimeoutSeconds`.
pub const MAX_OPERATION_TIMEOUT_SECONDS_CEILING: u64 = 3_600;
/// Ceiling for `sessionIdleSeconds`.
pub const SESSION_IDLE_SECONDS_CEILING: u64 = 300;

/// Which limit rule refused a value.  Field-free, so `Debug` carries no value.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LimitRule {
    /// A field was zero.  Zero is never "unlimited"; it is invalid.
    Zero,
    /// A field exceeded its fixed ceiling.
    AboveCeiling,
    /// `maxMessageBytes` was below [`MIN_MESSAGE_BYTES`].
    MessageBytesTooSmall,
    /// `defaultOperationTimeoutSeconds` exceeded `maxOperationTimeoutSeconds`.
    DefaultOperationTimeoutAboveMaximum,
    /// `requestTimeoutSeconds` exceeded `defaultOperationTimeoutSeconds`.
    RequestTimeoutAboveOperationDefault,
    /// `maxBufferedFileBytes` exceeded `maxTotalBufferedBytes`, which would let
    /// one materialized file exceed the whole concurrent budget.
    BufferedFileAboveTotalBuffer,
    /// `maxQueuedBytes` was below `maxMessageBytes`, which would make a legal
    /// maximum-size message impossible to enqueue.
    QueuedBytesBelowMessageBytes,
    /// A negotiated value was above the value it is negotiating down from.
    NotAReduction,
}

impl LimitRule {
    /// The stable diagnostic token.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zero => "LIMIT_ZERO",
            Self::AboveCeiling => "LIMIT_ABOVE_CEILING",
            Self::MessageBytesTooSmall => "LIMIT_MSIZE_TOO_SMALL",
            Self::DefaultOperationTimeoutAboveMaximum => "LIMIT_OPERATION_DEFAULT_ABOVE_MAX",
            Self::RequestTimeoutAboveOperationDefault => "LIMIT_REQUEST_ABOVE_OPERATION_DEFAULT",
            Self::BufferedFileAboveTotalBuffer => "LIMIT_FILE_BUFFER_ABOVE_TOTAL",
            Self::QueuedBytesBelowMessageBytes => "LIMIT_QUEUE_BELOW_MSIZE",
            Self::NotAReduction => "LIMIT_NOT_A_REDUCTION",
        }
    }

    /// Every rule.
    pub const ALL: [Self; 8] = [
        Self::Zero,
        Self::AboveCeiling,
        Self::MessageBytesTooSmall,
        Self::DefaultOperationTimeoutAboveMaximum,
        Self::RequestTimeoutAboveOperationDefault,
        Self::BufferedFileAboveTotalBuffer,
        Self::QueuedBytesBelowMessageBytes,
        Self::NotAReduction,
    ];

    /// Parse the exact diagnostic token; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.as_str() == text)
    }
}

impl fmt::Display for LimitRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Which limit field a [`LimitRule`] refused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LimitField {
    /// `maxMessageBytes`.
    MaxMessageBytes,
    /// `maxInflightRequests`.
    MaxInflightRequests,
    /// `maxFids`.
    MaxFids,
    /// `maxQueuedBytes`.
    MaxQueuedBytes,
    /// `maxBufferedFileBytes`.
    MaxBufferedFileBytes,
    /// `maxTotalBufferedBytes`.
    MaxTotalBufferedBytes,
    /// `maxPathBytes`.
    MaxPathBytes,
    /// `maxPathComponents`.
    MaxPathComponents,
    /// `maxTraversalEntries`.
    MaxTraversalEntries,
    /// `maxTraversalDepth`.
    MaxTraversalDepth,
    /// `requestTimeoutSeconds`.
    RequestTimeoutSeconds,
    /// `defaultOperationTimeoutSeconds`.
    DefaultOperationTimeoutSeconds,
    /// `maxOperationTimeoutSeconds`.
    MaxOperationTimeoutSeconds,
    /// `sessionIdleSeconds`.
    SessionIdleSeconds,
}

impl LimitField {
    /// Every field, in descriptor order.
    pub const ALL: [Self; 14] = [
        Self::MaxMessageBytes,
        Self::MaxInflightRequests,
        Self::MaxFids,
        Self::MaxQueuedBytes,
        Self::MaxBufferedFileBytes,
        Self::MaxTotalBufferedBytes,
        Self::MaxPathBytes,
        Self::MaxPathComponents,
        Self::MaxTraversalEntries,
        Self::MaxTraversalDepth,
        Self::RequestTimeoutSeconds,
        Self::DefaultOperationTimeoutSeconds,
        Self::MaxOperationTimeoutSeconds,
        Self::SessionIdleSeconds,
    ];

    /// The descriptor's exact field spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxMessageBytes => "maxMessageBytes",
            Self::MaxInflightRequests => "maxInflightRequests",
            Self::MaxFids => "maxFids",
            Self::MaxQueuedBytes => "maxQueuedBytes",
            Self::MaxBufferedFileBytes => "maxBufferedFileBytes",
            Self::MaxTotalBufferedBytes => "maxTotalBufferedBytes",
            Self::MaxPathBytes => "maxPathBytes",
            Self::MaxPathComponents => "maxPathComponents",
            Self::MaxTraversalEntries => "maxTraversalEntries",
            Self::MaxTraversalDepth => "maxTraversalDepth",
            Self::RequestTimeoutSeconds => "requestTimeoutSeconds",
            Self::DefaultOperationTimeoutSeconds => "defaultOperationTimeoutSeconds",
            Self::MaxOperationTimeoutSeconds => "maxOperationTimeoutSeconds",
            Self::SessionIdleSeconds => "sessionIdleSeconds",
        }
    }

    /// This field's fixed ceiling.
    #[must_use]
    pub const fn ceiling(self) -> u64 {
        match self {
            Self::MaxMessageBytes => MAX_MESSAGE_BYTES_CEILING,
            Self::MaxInflightRequests => MAX_INFLIGHT_REQUESTS_CEILING,
            Self::MaxFids => MAX_FIDS_CEILING,
            Self::MaxQueuedBytes => MAX_QUEUED_BYTES_CEILING,
            Self::MaxBufferedFileBytes => MAX_BUFFERED_FILE_BYTES_CEILING,
            Self::MaxTotalBufferedBytes => MAX_TOTAL_BUFFERED_BYTES_CEILING,
            Self::MaxPathBytes => MAX_PATH_BYTES_CEILING,
            Self::MaxPathComponents => MAX_PATH_COMPONENTS_CEILING,
            Self::MaxTraversalEntries => MAX_TRAVERSAL_ENTRIES_CEILING,
            Self::MaxTraversalDepth => MAX_TRAVERSAL_DEPTH_CEILING,
            Self::RequestTimeoutSeconds => REQUEST_TIMEOUT_SECONDS_CEILING,
            Self::DefaultOperationTimeoutSeconds => DEFAULT_OPERATION_TIMEOUT_SECONDS_CEILING,
            Self::MaxOperationTimeoutSeconds => MAX_OPERATION_TIMEOUT_SECONDS_CEILING,
            Self::SessionIdleSeconds => SESSION_IDLE_SECONDS_CEILING,
        }
    }
}

impl fmt::Display for LimitField {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A rejected limit: which field, and which rule refused it.
///
/// Carries no value, only the field name and the rule, both static strings.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct LimitError {
    field: LimitField,
    rule: LimitRule,
}

impl LimitError {
    /// The field that was refused.
    #[must_use]
    pub const fn field(self) -> LimitField {
        self.field
    }

    /// The rule that refused it.
    #[must_use]
    pub const fn rule(self) -> LimitRule {
        self.rule
    }
}

impl fmt::Display for LimitError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.rule.as_str(), self.field.as_str())
    }
}

impl std::error::Error for LimitError {}

/// The complete negotiated limit set for one session.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct Limits {
    values: [u64; 14],
}

impl Limits {
    /// The initial profile: every field at its ceiling.
    ///
    /// These are the implementable starting defaults of
    /// `docs/filesystem-api.md`, not measured capacity claims.
    pub const PROFILE_DEFAULT: Self = Self {
        values: [
            MAX_MESSAGE_BYTES_CEILING,
            MAX_INFLIGHT_REQUESTS_CEILING,
            MAX_FIDS_CEILING,
            MAX_QUEUED_BYTES_CEILING,
            MAX_BUFFERED_FILE_BYTES_CEILING,
            MAX_TOTAL_BUFFERED_BYTES_CEILING,
            MAX_PATH_BYTES_CEILING,
            MAX_PATH_COMPONENTS_CEILING,
            MAX_TRAVERSAL_ENTRIES_CEILING,
            MAX_TRAVERSAL_DEPTH_CEILING,
            REQUEST_TIMEOUT_SECONDS_CEILING,
            DEFAULT_OPERATION_TIMEOUT_SECONDS_CEILING,
            MAX_OPERATION_TIMEOUT_SECONDS_CEILING,
            SESSION_IDLE_SECONDS_CEILING,
        ],
    };

    /// Build a limit set from explicit values, in [`LimitField::ALL`] order.
    ///
    /// # Errors
    ///
    /// Returns the first [`LimitError`] the values violate, checking each
    /// field's own bounds in descriptor order before the cross-field rules.
    pub fn new(values: [u64; 14]) -> Result<Self, LimitError> {
        for (index, field) in LimitField::ALL.into_iter().enumerate() {
            let value = values[index];
            if value == 0 {
                return Err(LimitError {
                    field,
                    rule: LimitRule::Zero,
                });
            }
            if value > field.ceiling() {
                return Err(LimitError {
                    field,
                    rule: LimitRule::AboveCeiling,
                });
            }
        }
        let limits = Self { values };
        limits.check_cross_field()?;
        Ok(limits)
    }

    /// The cross-field rules the JSON Schema's `$comment` defers to runtime.
    fn check_cross_field(self) -> Result<(), LimitError> {
        if self.max_message_bytes() < MIN_MESSAGE_BYTES {
            return Err(LimitError {
                field: LimitField::MaxMessageBytes,
                rule: LimitRule::MessageBytesTooSmall,
            });
        }
        if self.max_queued_bytes() < self.max_message_bytes() {
            return Err(LimitError {
                field: LimitField::MaxQueuedBytes,
                rule: LimitRule::QueuedBytesBelowMessageBytes,
            });
        }
        if self.max_buffered_file_bytes() > self.max_total_buffered_bytes() {
            return Err(LimitError {
                field: LimitField::MaxBufferedFileBytes,
                rule: LimitRule::BufferedFileAboveTotalBuffer,
            });
        }
        if self.default_operation_timeout_seconds() > self.max_operation_timeout_seconds() {
            return Err(LimitError {
                field: LimitField::DefaultOperationTimeoutSeconds,
                rule: LimitRule::DefaultOperationTimeoutAboveMaximum,
            });
        }
        if self.request_timeout_seconds() > self.default_operation_timeout_seconds() {
            return Err(LimitError {
                field: LimitField::RequestTimeoutSeconds,
                rule: LimitRule::RequestTimeoutAboveOperationDefault,
            });
        }
        Ok(())
    }

    /// Read one field.
    #[must_use]
    pub const fn get(self, field: LimitField) -> u64 {
        self.values[field as usize]
    }

    /// Negotiate one field downwards.
    ///
    /// # Errors
    ///
    /// Returns [`LimitRule::NotAReduction`] if `value` is above the current
    /// value, and the ordinary field and cross-field errors otherwise.
    /// Negotiation can never raise a limit.
    pub fn reduce_to(self, field: LimitField, value: u64) -> Result<Self, LimitError> {
        if value > self.get(field) {
            return Err(LimitError {
                field,
                rule: LimitRule::NotAReduction,
            });
        }
        let mut values = self.values;
        values[field as usize] = value;
        Self::new(values)
    }

    /// `maxMessageBytes`.
    #[must_use]
    pub const fn max_message_bytes(self) -> u64 {
        self.get(LimitField::MaxMessageBytes)
    }

    /// `maxInflightRequests`.
    #[must_use]
    pub const fn max_inflight_requests(self) -> u64 {
        self.get(LimitField::MaxInflightRequests)
    }

    /// `maxFids`.
    #[must_use]
    pub const fn max_fids(self) -> u64 {
        self.get(LimitField::MaxFids)
    }

    /// `maxQueuedBytes`.
    #[must_use]
    pub const fn max_queued_bytes(self) -> u64 {
        self.get(LimitField::MaxQueuedBytes)
    }

    /// `maxBufferedFileBytes`.
    #[must_use]
    pub const fn max_buffered_file_bytes(self) -> u64 {
        self.get(LimitField::MaxBufferedFileBytes)
    }

    /// `maxTotalBufferedBytes`.
    #[must_use]
    pub const fn max_total_buffered_bytes(self) -> u64 {
        self.get(LimitField::MaxTotalBufferedBytes)
    }

    /// `maxPathBytes`.
    #[must_use]
    pub const fn max_path_bytes(self) -> u64 {
        self.get(LimitField::MaxPathBytes)
    }

    /// `maxPathComponents`.
    #[must_use]
    pub const fn max_path_components(self) -> u64 {
        self.get(LimitField::MaxPathComponents)
    }

    /// `maxTraversalEntries`.
    #[must_use]
    pub const fn max_traversal_entries(self) -> u64 {
        self.get(LimitField::MaxTraversalEntries)
    }

    /// `maxTraversalDepth`.
    #[must_use]
    pub const fn max_traversal_depth(self) -> u64 {
        self.get(LimitField::MaxTraversalDepth)
    }

    /// `requestTimeoutSeconds`.
    #[must_use]
    pub const fn request_timeout_seconds(self) -> u64 {
        self.get(LimitField::RequestTimeoutSeconds)
    }

    /// `defaultOperationTimeoutSeconds`.
    #[must_use]
    pub const fn default_operation_timeout_seconds(self) -> u64 {
        self.get(LimitField::DefaultOperationTimeoutSeconds)
    }

    /// `maxOperationTimeoutSeconds`.
    #[must_use]
    pub const fn max_operation_timeout_seconds(self) -> u64 {
        self.get(LimitField::MaxOperationTimeoutSeconds)
    }

    /// `sessionIdleSeconds`.
    #[must_use]
    pub const fn session_idle_seconds(self) -> u64 {
        self.get(LimitField::SessionIdleSeconds)
    }

    /// The path bounds these limits imply.
    ///
    /// Infallible: both fields are already known non-zero and are at most their
    /// ceilings, which fit `usize` on every supported host.
    #[must_use]
    pub fn path_bounds(self) -> PathBounds {
        let max_bytes = usize::try_from(self.max_path_bytes()).unwrap_or(usize::MAX);
        let max_components = usize::try_from(self.max_path_components()).unwrap_or(usize::MAX);
        PathBounds::new(max_bytes, max_components)
            .expect("limits guarantee both path bounds are non-zero")
    }
}

impl Default for Limits {
    fn default() -> Self {
        Self::PROFILE_DEFAULT
    }
}
