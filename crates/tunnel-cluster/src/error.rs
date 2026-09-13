//! Typed errors for the private relay-to-relay contract.
//!
//! The internal error retains enough scope and execution information for an
//! owner actor to make a safe decision.  The public projection intentionally
//! drops that scope (and any transport details) before an error can cross a
//! tenant boundary.

use std::fmt;

use serde::{Deserialize, Serialize};
use tunnel_catalog::{DeviceId, ServiceId, TenantId};

/// Whether an operation could have reached a device or adapter.
///
/// `Unknown` is deliberately distinct from `Dispatched`: a transport failure
/// after dispatch does not prove that the adapter did not perform a side
/// effect.  Callers must not turn either state into an automatic retry.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionCertainty {
    NotDispatched,
    Dispatched,
    Unknown,
}

impl ExecutionCertainty {
    #[must_use]
    pub const fn is_retry_safe(self) -> bool {
        matches!(self, Self::NotDispatched)
    }
}

/// A retry hint carried by an internal error.
///
/// There is one retry class for admission.  It is only actionable when the
/// request was authenticated and the execution certainty is
/// `NotDispatched`; `RetryHint` itself is not an authorization decision.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryHint {
    #[default]
    Never,
    AdmissionOnce,
}

/// Bounded internal error codes from the cluster routing contract.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum InternalErrorCode {
    PeerUntrusted,
    PeerUnavailable,
    OwnerChanged,
    OwnerExpired,
    RegistryUnavailable,
    AuthorizationStale,
    ResourceExhausted,
    DeadlineExceeded,
    OutcomeUnknown,
    InvalidEnvelope,
    ScopeMismatch,
    CredentialInvalid,
}

impl fmt::Display for InternalErrorCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::PeerUntrusted => "PEER_UNTRUSTED",
            Self::PeerUnavailable => "PEER_UNAVAILABLE",
            Self::OwnerChanged => "OWNER_CHANGED",
            Self::OwnerExpired => "OWNER_EXPIRED",
            Self::RegistryUnavailable => "REGISTRY_UNAVAILABLE",
            Self::AuthorizationStale => "AUTHORIZATION_STALE",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::OutcomeUnknown => "OUTCOME_UNKNOWN",
            Self::InvalidEnvelope => "INVALID_ENVELOPE",
            Self::ScopeMismatch => "SCOPE_MISMATCH",
            Self::CredentialInvalid => "CREDENTIAL_INVALID",
        };
        formatter.write_str(value)
    }
}

/// Tenant/device/service scope attached to an internal diagnostic.
///
/// This is intentionally not part of [`PublicError`].  Scope identifiers are
/// useful to the owner actor and restricted diagnostics, but returning them
/// to an unauthorized public caller can disclose another tenant's records.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ErrorScope {
    pub tenant_id: Option<TenantId>,
    pub device_id: Option<DeviceId>,
    pub service_id: Option<ServiceId>,
}

/// Internal cluster error with execution certainty and an explicit retry
/// policy.  The `authenticated` bit means that the ingress request already
/// passed its consumer authentication boundary; it is never inferred from a
/// principal header or from the destination scope.
pub struct ClusterError {
    pub code: InternalErrorCode,
    pub scope: ErrorScope,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub certainty: ExecutionCertainty,
    pub retry: RetryHint,
    pub authenticated: bool,
    detail: Option<String>,
}

impl fmt::Debug for ClusterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ClusterError")
            .field("code", &self.code)
            .field("scope", &self.scope)
            .field("request_id", &self.request_id)
            .field("operation_id", &self.operation_id)
            .field("certainty", &self.certainty)
            .field("retry", &self.retry)
            .field("authenticated", &self.authenticated)
            .field("detail", &self.detail.as_ref().map(|_| "<redacted>"))
            .finish()
    }
}

impl ClusterError {
    #[must_use]
    pub fn new(
        code: InternalErrorCode,
        scope: ErrorScope,
        request_id: impl Into<String>,
        operation_id: Option<String>,
        certainty: ExecutionCertainty,
        retry: RetryHint,
        authenticated: bool,
    ) -> Self {
        Self {
            code,
            scope,
            request_id: request_id.into(),
            operation_id,
            certainty,
            retry,
            authenticated,
            detail: None,
        }
    }

    /// Attach a bounded internal diagnostic detail.
    ///
    /// Details are never copied into a public error.  The caller is expected
    /// to pass a redacted, non-secret message; the type does not log it by
    /// default.
    #[must_use]
    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    #[must_use]
    pub fn detail(&self) -> Option<&str> {
        self.detail.as_deref()
    }

    /// Project this error to the public boundary.
    ///
    /// Internal scope, retry-authentication state, and transport details are
    /// intentionally omitted.  Correlation identifiers are retained so an
    /// authorized operator can match a response to a redacted diagnostic.
    #[must_use]
    pub fn public(&self) -> PublicError {
        PublicError {
            code: self.code,
            request_id: self.request_id.clone(),
            operation_id: self.operation_id.clone(),
            certainty: self.certainty,
            retry: if self.can_retry_admission() {
                RetryHint::AdmissionOnce
            } else {
                RetryHint::Never
            },
        }
    }

    #[must_use]
    pub const fn can_retry_admission(&self) -> bool {
        // The hint is necessary but not sufficient.  Only failures that can
        // prove the request stopped before owner admission may authorize a
        // route re-read; malformed, untrusted, resource, deadline and
        // uncertain outcomes never become replayable by carrying the same
        // hint.
        self.authenticated
            && self.certainty.is_retry_safe()
            && matches!(self.retry, RetryHint::AdmissionOnce)
            && matches!(
                self.code,
                InternalErrorCode::PeerUnavailable
                    | InternalErrorCode::OwnerChanged
                    | InternalErrorCode::OwnerExpired
                    | InternalErrorCode::RegistryUnavailable
            )
    }

    /// Consume this error to obtain its single bounded admission retry.
    ///
    /// Consuming the error makes the one-retry rule explicit at the API
    /// boundary.  A dispatched or ambiguous operation can never produce an
    /// `AdmissionRetry`.
    pub fn into_admission_retry(self) -> Result<AdmissionRetry, RetryDenied> {
        if self.can_retry_admission() {
            Ok(AdmissionRetry {
                request_id: self.request_id,
                operation_id: self.operation_id,
            })
        } else {
            Err(RetryDenied {
                certainty: self.certainty,
                authenticated: self.authenticated,
                hint: self.retry,
            })
        }
    }
}

impl fmt::Display for ClusterError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({:?})", self.code, self.certainty)
    }
}

impl std::error::Error for ClusterError {}

/// The only retry token the internal contract can issue.
#[derive(Debug, Eq, PartialEq)]
pub struct AdmissionRetry {
    request_id: String,
    operation_id: Option<String>,
}

impl AdmissionRetry {
    #[must_use]
    pub fn request_id(&self) -> &str {
        &self.request_id
    }

    #[must_use]
    pub fn operation_id(&self) -> Option<&str> {
        self.operation_id.as_deref()
    }
}

/// Why an attempted admission retry was denied.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetryDenied {
    pub certainty: ExecutionCertainty,
    pub authenticated: bool,
    pub hint: RetryHint,
}

impl fmt::Display for RetryDenied {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("admission retry is not safe or was not authorized")
    }
}

impl std::error::Error for RetryDenied {}

/// Public, redacted projection of an internal cluster error.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PublicError {
    pub code: InternalErrorCode,
    pub request_id: String,
    pub operation_id: Option<String>,
    pub certainty: ExecutionCertainty,
    pub retry: RetryHint,
}

impl fmt::Display for PublicError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{} ({:?})", self.code, self.certainty)
    }
}

impl std::error::Error for PublicError {}

/// Validation failures are kept separate from dispatch errors so a caller can
/// distinguish malformed/untrusted peer input from an operation whose effect
/// may already be unknown.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum EnvelopeValidationError {
    InvalidSchemaVersion { expected: u16, actual: u16 },
    InvalidIdentifier { field: &'static str },
    InvalidPeerIdentity { field: &'static str },
    SourceIdentityMismatch,
    DestinationMismatch,
    OwnerTokenMismatch,
    TenantScopeMismatch,
    DeviceScopeMismatch,
    ServiceScopeMismatch,
    InvalidHopBudget { expected: u8, actual: u8 },
    AdmissionDeadlineMissing,
    AdmissionDeadlineExpired,
    AdmissionDeadlineTooLong { remaining_ms: u32, maximum_ms: u32 },
    StreamLifetimeInvalid { lifetime_ms: u32 },
    AdmissionExceedsStreamLifetime { admission_ms: u32, lifetime_ms: u32 },
    RoutePayloadMismatch,
    DeviceAuthenticationMissing,
    DeviceCertificateNotYetValid,
    DeviceCertificateExpired,
    DeviceBindingMismatch,
    DeviceBindingExpired,
    ConsumerBearerMissing,
    ConsumerBearerOwnerMismatch,
    OwnerJwtValidationRequired,
    OwnerJwtExpired,
    OwnerJwtTenantMismatch,
    OwnerJwtScopeMissing,
    InvalidConsumerBearer,
}

impl fmt::Display for EnvelopeValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::InvalidSchemaVersion { .. } => "unsupported envelope schema version",
            Self::InvalidIdentifier { .. } => "invalid envelope identifier",
            Self::InvalidPeerIdentity { .. } => "invalid peer identity",
            Self::SourceIdentityMismatch => "envelope source does not match verified peer",
            Self::DestinationMismatch => "envelope destination does not match expected owner",
            Self::OwnerTokenMismatch => "envelope owner token does not match expected owner",
            Self::TenantScopeMismatch => "envelope tenant scope does not match destination",
            Self::DeviceScopeMismatch => "envelope device scope does not match destination",
            Self::ServiceScopeMismatch => "envelope service scope does not match destination",
            Self::InvalidHopBudget { .. } => "invalid forwarding hop budget",
            Self::AdmissionDeadlineMissing => "admission deadline is missing",
            Self::AdmissionDeadlineExpired => "admission deadline has expired",
            Self::AdmissionDeadlineTooLong { .. } => "admission deadline exceeds the policy bound",
            Self::StreamLifetimeInvalid { .. } => "stream lifetime is outside its policy bound",
            Self::AdmissionExceedsStreamLifetime { .. } => {
                "admission deadline exceeds the stream lifetime"
            }
            Self::RoutePayloadMismatch => "route does not match its typed payload",
            Self::DeviceAuthenticationMissing => "device authentication context is missing",
            Self::DeviceCertificateNotYetValid => "device certificate is not yet valid",
            Self::DeviceCertificateExpired => "device certificate is expired",
            Self::DeviceBindingMismatch => "device authentication binding does not match request",
            Self::DeviceBindingExpired => "device authentication binding is expired",
            Self::ConsumerBearerMissing => "consumer bearer is missing",
            Self::ConsumerBearerOwnerMismatch => "consumer bearer is not bound to this owner",
            Self::OwnerJwtValidationRequired => "owner JWT validation is required",
            Self::OwnerJwtExpired => "owner JWT is expired",
            Self::OwnerJwtTenantMismatch => "owner JWT tenant does not match destination",
            Self::OwnerJwtScopeMissing => "owner JWT does not contain the requested scope",
            Self::InvalidConsumerBearer => "consumer bearer is invalid",
        };
        formatter.write_str(message)
    }
}

impl std::error::Error for EnvelopeValidationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn scope() -> ErrorScope {
        ErrorScope {
            tenant_id: Some(Uuid::from_u128(1)),
            device_id: Some(Uuid::from_u128(2)),
            service_id: Some(Uuid::from_u128(3)),
        }
    }

    #[test]
    fn only_authenticated_not_dispatched_admission_can_retry() {
        let error = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope(),
            "request-1",
            Some("operation-1".into()),
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        assert!(error.can_retry_admission());
        let retry = error
            .into_admission_retry()
            .expect("authenticated admission may retry once");
        assert_eq!(retry.request_id(), "request-1");

        let dispatched = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope(),
            "request-2",
            None,
            ExecutionCertainty::Dispatched,
            RetryHint::AdmissionOnce,
            true,
        );
        assert!(dispatched.into_admission_retry().is_err());

        let unauthenticated = ClusterError::new(
            InternalErrorCode::PeerUnavailable,
            scope(),
            "request-3",
            None,
            ExecutionCertainty::NotDispatched,
            RetryHint::AdmissionOnce,
            false,
        );
        assert!(unauthenticated.into_admission_retry().is_err());
    }

    #[test]
    fn malformed_untrusted_or_ambiguous_codes_cannot_enable_reselection() {
        let admission_codes = [
            InternalErrorCode::PeerUnavailable,
            InternalErrorCode::OwnerChanged,
            InternalErrorCode::OwnerExpired,
            InternalErrorCode::RegistryUnavailable,
        ];
        for code in admission_codes {
            let error = ClusterError::new(
                code,
                scope(),
                "request-1",
                None,
                ExecutionCertainty::NotDispatched,
                RetryHint::AdmissionOnce,
                true,
            );
            assert!(
                error.can_retry_admission(),
                "{code} should allow admission retry"
            );
        }

        let non_admission_codes = [
            InternalErrorCode::PeerUntrusted,
            InternalErrorCode::AuthorizationStale,
            InternalErrorCode::ResourceExhausted,
            InternalErrorCode::DeadlineExceeded,
            InternalErrorCode::OutcomeUnknown,
            InternalErrorCode::InvalidEnvelope,
            InternalErrorCode::ScopeMismatch,
            InternalErrorCode::CredentialInvalid,
        ];
        for code in non_admission_codes {
            let error = ClusterError::new(
                code,
                scope(),
                "request-1",
                None,
                ExecutionCertainty::NotDispatched,
                RetryHint::AdmissionOnce,
                true,
            );
            assert!(!error.can_retry_admission(), "{code} must not reselect");
        }
    }

    #[test]
    fn public_error_redacts_scope_and_detail() {
        let error = ClusterError::new(
            InternalErrorCode::OutcomeUnknown,
            scope(),
            "request-1",
            Some("operation-1".into()),
            ExecutionCertainty::Unknown,
            RetryHint::Never,
            true,
        )
        .with_detail("bearer=super-secret");

        let debug = format!("{error:?}");
        assert!(!debug.contains("super-secret"));
        assert!(debug.contains("<redacted>"));

        let public = error.public();
        let encoded = serde_json::to_string(&public).expect("public error encodes");
        assert!(!encoded.contains("tenant_id"));
        assert!(!encoded.contains("device_id"));
        assert!(!encoded.contains("service_id"));
        assert!(!encoded.contains("super-secret"));
    }

    #[test]
    fn uncertain_outcome_never_projects_an_admission_retry() {
        let error = ClusterError::new(
            InternalErrorCode::OutcomeUnknown,
            scope(),
            "request-1",
            Some("operation-1".into()),
            ExecutionCertainty::Unknown,
            RetryHint::AdmissionOnce,
            true,
        );
        let public = error.public();
        assert_eq!(public.certainty, ExecutionCertainty::Unknown);
        assert_eq!(public.retry, RetryHint::Never);
        assert!(error.into_admission_retry().is_err());
    }
}
