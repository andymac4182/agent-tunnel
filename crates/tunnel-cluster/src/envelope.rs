//! Strict, bounded admission envelopes for private relay peer requests.
//!
//! An envelope is an authenticated routing record, not a replacement for the
//! device WebSocket protocol.  It carries the complete catalog owner token,
//! tenant/device/service scope, one forwarding hop, and a short admission
//! budget.  Stream lifetime is a separate field and can never extend the
//! admission budget.

use std::fmt;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tunnel_catalog::{DeviceId, OwnerToken, ServiceId, TenantId, ValidatedAccessToken};

use crate::error::{EnvelopeValidationError, InternalErrorCode};
use crate::membership::VerifiedPeerBinding;

/// The only schema version understood by this crate.
pub const ENVELOPE_SCHEMA_VERSION: u16 = 1;
/// The encoded envelope limit.  This is checked before JSON parsing.
pub const MAX_ENVELOPE_BYTES: usize = 8 * 1024;
/// Every peer forward consumes exactly one direct hop.
pub const REQUIRED_HOP_BUDGET: u8 = 1;
/// Maximum admission budget, matching the cluster device-dispatch policy.
pub const MAX_ADMISSION_REMAINING_MS: u32 = 20_000;
/// Stream lifetime is independent of admission and has its own bounded cap.
pub const MAX_STREAM_LIFETIME_MS: u32 = 86_400_000;
/// Maximum encoded identifier size in the internal schema.
pub const MAX_IDENTIFIER_BYTES: usize = 256;
/// Maximum encoded certificate serial/fingerprint size.
pub const MAX_CERTIFICATE_FIELD_BYTES: usize = 512;

/// A typed internal route.  Public ingress routes are not accepted here.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum InternalRoute {
    Health,
    DeviceControl,
    DeviceData,
    ConsumerStreams,
    OperationStatus,
}

/// The source identity carried by an envelope.  This is untrusted wire data
/// until compared with [`VerifiedPeerIdentity`] at the transport boundary.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PeerIdentity {
    pub node_id: String,
    pub boot_id: String,
}

impl PeerIdentity {
    #[must_use]
    pub fn new(node_id: impl Into<String>, boot_id: impl Into<String>) -> Self {
        Self {
            node_id: node_id.into(),
            boot_id: boot_id.into(),
        }
    }

    fn validate(&self) -> Result<(), EnvelopeValidationError> {
        validate_identifier("source.node_id", &self.node_id)?;
        validate_identifier("source.boot_id", &self.boot_id)
    }
}

/// A peer identity produced by an already authenticated transport.
///
/// It has no `Deserialize` implementation.  The transport trust-boundary
/// constructor accepts only explicitly supplied post-verification identity
/// values, never request headers or envelope JSON.  Envelope validation takes
/// this opaque value explicitly, so a source field copied from an HTTP header
/// cannot authorize a request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedPeerIdentity {
    node_id: String,
    boot_id: String,
}

impl VerifiedPeerIdentity {
    /// Convert the opaque binding returned by the signed-membership verifier.
    ///
    /// `VerifiedPeerBinding` can only be produced after the membership
    /// signature, validity window, node, boot and SPKI checks have passed.
    /// Keeping this conversion separate from wire decoding prevents an
    /// envelope/header value from becoming transport evidence.
    pub fn from_verified_peer_binding(
        binding: &VerifiedPeerBinding,
    ) -> Result<Self, EnvelopeValidationError> {
        Self::from_verified_transport(binding.node_id(), binding.boot_id())
    }

    // Keep string construction private: production callers must carry the
    // opaque membership binding obtained from verified transport evidence.
    fn from_verified_transport(
        node_id: impl Into<String>,
        boot_id: impl Into<String>,
    ) -> Result<Self, EnvelopeValidationError> {
        let identity = Self {
            node_id: node_id.into(),
            boot_id: boot_id.into(),
        };
        validate_identifier("verified_peer.node_id", &identity.node_id)?;
        validate_identifier("verified_peer.boot_id", &identity.boot_id)?;
        Ok(identity)
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    fn matches(&self, source: &PeerIdentity) -> bool {
        self.node_id == source.node_id && self.boot_id == source.boot_id
    }
}

/// Exact owner and catalog scope selected by the authoritative owner lookup.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Destination {
    /// The complete fencing token.  This uses the canonical catalog type; it
    /// is not redefined by the cluster crate.
    #[serde(with = "strict_owner_token")]
    pub owner_token: OwnerToken,
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
    pub service_id: ServiceId,
}

impl Destination {
    #[must_use]
    pub fn new(owner_token: OwnerToken, service_id: ServiceId) -> Self {
        Self {
            tenant_id: owner_token.tenant_id,
            device_id: owner_token.device_id,
            owner_token,
            service_id,
        }
    }

    fn validate(&self) -> Result<(), EnvelopeValidationError> {
        validate_owner_token(&self.owner_token)?;
        if self.owner_token.tenant_id != self.tenant_id {
            return Err(EnvelopeValidationError::TenantScopeMismatch);
        }
        if self.owner_token.device_id != self.device_id {
            return Err(EnvelopeValidationError::DeviceScopeMismatch);
        }
        Ok(())
    }
}

/// Certificate identity verified at device ingress.
///
/// This records certificate facts needed by the owner.  It does not claim
/// that the device's end-to-end TLS session survived a peer forward; the
/// device TLS boundary remains at the device ingress and is checked there.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifiedDeviceCertificate {
    pub certificate_identity: String,
    pub spki_fingerprint: String,
    pub serial: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub tenant_id: TenantId,
    pub device_id: DeviceId,
}

impl VerifiedDeviceCertificate {
    fn validate(&self, now: DateTime<Utc>) -> Result<(), EnvelopeValidationError> {
        validate_bounded_string(
            "certificate_identity",
            &self.certificate_identity,
            MAX_CERTIFICATE_FIELD_BYTES,
        )?;
        validate_bounded_string(
            "spki_fingerprint",
            &self.spki_fingerprint,
            MAX_CERTIFICATE_FIELD_BYTES,
        )?;
        validate_bounded_string("serial", &self.serial, MAX_CERTIFICATE_FIELD_BYTES)?;
        if self.expires_at <= self.not_before {
            return Err(EnvelopeValidationError::DeviceCertificateExpired);
        }
        if now < self.not_before {
            return Err(EnvelopeValidationError::DeviceCertificateNotYetValid);
        }
        if now >= self.expires_at {
            return Err(EnvelopeValidationError::DeviceCertificateExpired);
        }
        Ok(())
    }
}

/// Binding created by the ingress that received the authenticated request.
/// Every field is repeated and compared by the owner before dispatch.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IngressRequestBinding {
    pub request_id: String,
    pub source: PeerIdentity,
    pub destination: Destination,
    pub expires_at: DateTime<Utc>,
}

impl IngressRequestBinding {
    fn validate(
        &self,
        now: DateTime<Utc>,
        request_id: &str,
        source: &PeerIdentity,
        destination: &Destination,
        certificate_expires_at: DateTime<Utc>,
    ) -> Result<(), EnvelopeValidationError> {
        validate_identifier("ingress.request_id", &self.request_id)?;
        self.source.validate()?;
        self.destination.validate()?;
        if self.request_id != request_id
            || &self.source != source
            || &self.destination != destination
        {
            return Err(EnvelopeValidationError::DeviceBindingMismatch);
        }
        if self.expires_at <= now || self.expires_at > certificate_expires_at {
            return Err(EnvelopeValidationError::DeviceBindingExpired);
        }
        Ok(())
    }
}

/// Device certificate and ingress binding presented to an owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceAuthenticationContext {
    pub certificate: VerifiedDeviceCertificate,
    pub ingress: IngressRequestBinding,
}

impl DeviceAuthenticationContext {
    fn validate(
        &self,
        now: DateTime<Utc>,
        request_id: &str,
        source: &PeerIdentity,
        destination: &Destination,
    ) -> Result<(), EnvelopeValidationError> {
        self.certificate.validate(now)?;
        if self.certificate.tenant_id != destination.tenant_id {
            return Err(EnvelopeValidationError::TenantScopeMismatch);
        }
        if self.certificate.device_id != destination.device_id {
            return Err(EnvelopeValidationError::DeviceScopeMismatch);
        }
        self.ingress.validate(
            now,
            request_id,
            source,
            destination,
            self.certificate.expires_at,
        )
    }
}

/// A consumer bearer that may cross a private peer link only when it is
/// bound to the exact owner token in the destination.
///
/// The owner must independently validate this JWT with the configured OIDC
/// verifier and catalog.  A peer-provided principal header is not represented
/// by this type and can never authorize a consumer stream.
#[derive(Clone, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ForwardedConsumerBearer {
    #[serde(with = "strict_owner_token")]
    pub destination_owner: OwnerToken,
    #[serde(rename = "bearer_token")]
    token: String,
}

impl ForwardedConsumerBearer {
    pub fn new(
        token: impl Into<String>,
        destination_owner: OwnerToken,
    ) -> Result<Self, EnvelopeValidationError> {
        let bearer = Self {
            destination_owner,
            token: token.into(),
        };
        bearer.validate()?;
        Ok(bearer)
    }

    /// Expose the bearer only to the owner-side JWT verifier.  Callers must
    /// not log or copy this value into diagnostics.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    fn validate(&self) -> Result<(), EnvelopeValidationError> {
        validate_owner_token(&self.destination_owner)?;
        if self.token.is_empty()
            || self.token.len() > MAX_CERTIFICATE_FIELD_BYTES * 8
            || self
                .token
                .chars()
                .any(|character| character.is_control() || character.is_whitespace())
        {
            return Err(EnvelopeValidationError::InvalidConsumerBearer);
        }
        Ok(())
    }
}

impl fmt::Debug for ForwardedConsumerBearer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ForwardedConsumerBearer")
            .field("destination_owner", &self.destination_owner)
            .field("bearer_token", &"<redacted>")
            .finish()
    }
}

/// Health is deliberately typed even though it has no device payload.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthRequest {
    pub check_id: String,
}

/// Device control is carried only with a verified device authentication
/// context bound to this envelope.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceControlRequest {
    pub stream_id: String,
    pub authentication: DeviceAuthenticationContext,
}

/// Device data identifies one logical stream.  The outer tunnel remains the
/// authority for sequence ordering; this contract carries only bounded peer
/// routing metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeviceDataRequest {
    pub stream_id: String,
    pub sequence: u64,
    pub authentication: DeviceAuthenticationContext,
    pub bytes: Vec<u8>,
}

/// Consumer bytes and the scope that the owner must independently check in
/// the JWT/catalog before allocating a stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumerStreamsRequest {
    pub stream_id: String,
    pub required_scope: String,
    pub bearer: ForwardedConsumerBearer,
    pub bytes: Vec<u8>,
}

/// Status is keyed by the operation ID in the common envelope and repeated
/// here to prevent accidental cross-operation lookup at the owner.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationStatusRequest {
    pub operation_id: String,
}

/// Strict, route-typed request body.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum InternalRequest {
    Health(HealthRequest),
    DeviceControl(DeviceControlRequest),
    DeviceData(DeviceDataRequest),
    ConsumerStreams(ConsumerStreamsRequest),
    OperationStatus(OperationStatusRequest),
}

impl InternalRequest {
    #[must_use]
    pub const fn route(&self) -> InternalRoute {
        match self {
            Self::Health(_) => InternalRoute::Health,
            Self::DeviceControl(_) => InternalRoute::DeviceControl,
            Self::DeviceData(_) => InternalRoute::DeviceData,
            Self::ConsumerStreams(_) => InternalRoute::ConsumerStreams,
            Self::OperationStatus(_) => InternalRoute::OperationStatus,
        }
    }
}

/// One bounded request sent over a private peer stream.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestEnvelope {
    pub schema_version: u16,
    pub route: InternalRoute,
    pub request_id: String,
    #[serde(default)]
    pub operation_id: Option<String>,
    pub source: PeerIdentity,
    pub destination: Destination,
    pub hop_budget: u8,
    /// Remaining budget for owner admission, in milliseconds.  This is not
    /// the lifetime of an already admitted stream.
    pub remaining_admission_ms: u32,
    /// Optional lifetime for the logical stream after admission.  It has its
    /// own cap and cannot extend `remaining_admission_ms`.
    #[serde(default)]
    pub stream_lifetime_ms: Option<u32>,
    pub request: InternalRequest,
}

impl RequestEnvelope {
    #[must_use]
    pub fn new(
        route: InternalRoute,
        request_id: impl Into<String>,
        source: PeerIdentity,
        destination: Destination,
        remaining_admission_ms: u32,
        stream_lifetime_ms: Option<u32>,
        request: InternalRequest,
    ) -> Self {
        Self {
            schema_version: ENVELOPE_SCHEMA_VERSION,
            route,
            request_id: request_id.into(),
            operation_id: None,
            source,
            destination,
            hop_budget: REQUIRED_HOP_BUDGET,
            remaining_admission_ms,
            stream_lifetime_ms,
            request,
        }
    }

    /// Validate the envelope after decoding and before owner dispatch.
    ///
    /// `now` and `verified_peer` are explicit inputs so tests and adapters do
    /// not accidentally use wall-clock globals or trust an unchecked source
    /// header.  `owner_access` is required for consumer streams and must be
    /// the result of independent owner-side JWT/catalog validation.
    pub fn validate(
        &self,
        now: DateTime<Utc>,
        verified_peer: &VerifiedPeerIdentity,
        expected_destination: &Destination,
        owner_access: Option<&ValidatedAccessToken>,
    ) -> Result<(), EnvelopeValidationError> {
        if self.schema_version != ENVELOPE_SCHEMA_VERSION {
            return Err(EnvelopeValidationError::InvalidSchemaVersion {
                expected: ENVELOPE_SCHEMA_VERSION,
                actual: self.schema_version,
            });
        }
        validate_identifier("request_id", &self.request_id)?;
        if let Some(operation_id) = &self.operation_id {
            validate_identifier("operation_id", operation_id)?;
        }
        self.source.validate()?;
        self.destination.validate()?;
        expected_destination.validate()?;
        if !verified_peer.matches(&self.source) {
            return Err(EnvelopeValidationError::SourceIdentityMismatch);
        }
        if self.destination.owner_token != expected_destination.owner_token {
            return Err(EnvelopeValidationError::OwnerTokenMismatch);
        }
        if self.destination.tenant_id != expected_destination.tenant_id {
            return Err(EnvelopeValidationError::TenantScopeMismatch);
        }
        if self.destination.device_id != expected_destination.device_id {
            return Err(EnvelopeValidationError::DeviceScopeMismatch);
        }
        if self.destination.service_id != expected_destination.service_id {
            return Err(EnvelopeValidationError::ServiceScopeMismatch);
        }
        if self.hop_budget != REQUIRED_HOP_BUDGET {
            return Err(EnvelopeValidationError::InvalidHopBudget {
                expected: REQUIRED_HOP_BUDGET,
                actual: self.hop_budget,
            });
        }
        if self.remaining_admission_ms == 0 {
            return Err(EnvelopeValidationError::AdmissionDeadlineExpired);
        }
        if self.remaining_admission_ms > MAX_ADMISSION_REMAINING_MS {
            return Err(EnvelopeValidationError::AdmissionDeadlineTooLong {
                remaining_ms: self.remaining_admission_ms,
                maximum_ms: MAX_ADMISSION_REMAINING_MS,
            });
        }
        if let Some(lifetime_ms) = self.stream_lifetime_ms {
            if lifetime_ms == 0 || lifetime_ms > MAX_STREAM_LIFETIME_MS {
                return Err(EnvelopeValidationError::StreamLifetimeInvalid { lifetime_ms });
            }
            if self.remaining_admission_ms > lifetime_ms {
                return Err(EnvelopeValidationError::AdmissionExceedsStreamLifetime {
                    admission_ms: self.remaining_admission_ms,
                    lifetime_ms,
                });
            }
        }
        if self.route != self.request.route() {
            return Err(EnvelopeValidationError::RoutePayloadMismatch);
        }

        match &self.request {
            InternalRequest::Health(request) => {
                validate_identifier("health.check_id", &request.check_id)?;
            }
            InternalRequest::DeviceControl(request) => {
                validate_identifier("device_control.stream_id", &request.stream_id)?;
                request.authentication.validate(
                    now,
                    &self.request_id,
                    &self.source,
                    &self.destination,
                )?;
            }
            InternalRequest::DeviceData(request) => {
                validate_identifier("device_data.stream_id", &request.stream_id)?;
                if request.sequence == 0 {
                    return Err(EnvelopeValidationError::InvalidIdentifier {
                        field: "device_data.sequence",
                    });
                }
                request.authentication.validate(
                    now,
                    &self.request_id,
                    &self.source,
                    &self.destination,
                )?;
            }
            InternalRequest::ConsumerStreams(request) => {
                validate_identifier("consumer_streams.stream_id", &request.stream_id)?;
                validate_identifier("consumer_streams.required_scope", &request.required_scope)?;
                request.bearer.validate()?;
                if request.bearer.destination_owner != self.destination.owner_token {
                    return Err(EnvelopeValidationError::ConsumerBearerOwnerMismatch);
                }
                let owner_access =
                    owner_access.ok_or(EnvelopeValidationError::OwnerJwtValidationRequired)?;
                if owner_access.expires_at <= now {
                    return Err(EnvelopeValidationError::OwnerJwtExpired);
                }
                if owner_access.consumer.tenant_id != self.destination.tenant_id {
                    return Err(EnvelopeValidationError::OwnerJwtTenantMismatch);
                }
                if !owner_access.scopes.contains(&request.required_scope) {
                    return Err(EnvelopeValidationError::OwnerJwtScopeMissing);
                }
                if request.bearer.token().is_empty() {
                    return Err(EnvelopeValidationError::InvalidConsumerBearer);
                }
            }
            InternalRequest::OperationStatus(request) => {
                validate_identifier("operation_status.operation_id", &request.operation_id)?;
                if self.operation_id.as_deref() != Some(request.operation_id.as_str()) {
                    return Err(EnvelopeValidationError::RoutePayloadMismatch);
                }
            }
        }
        Ok(())
    }

    /// Encode with the same 8 KiB bound used by [`decode_envelope`].
    pub fn encode(&self) -> Result<Vec<u8>, EnvelopeError> {
        let bytes = serde_json::to_vec(self).map_err(EnvelopeError::Json)?;
        if bytes.len() > MAX_ENVELOPE_BYTES {
            return Err(EnvelopeError::MessageTooLarge {
                length: bytes.len(),
                maximum: MAX_ENVELOPE_BYTES,
            });
        }
        Ok(bytes)
    }
}

/// JSON/size errors from the bounded envelope codec.
#[derive(Debug)]
pub enum EnvelopeError {
    MessageTooLarge { length: usize, maximum: usize },
    Json(serde_json::Error),
}

impl fmt::Display for EnvelopeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MessageTooLarge { length, maximum } => {
                write!(
                    formatter,
                    "envelope is {length} bytes; maximum is {maximum}"
                )
            }
            Self::Json(_) => formatter.write_str("invalid internal envelope JSON"),
        }
    }
}

impl std::error::Error for EnvelopeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Json(error) => Some(error),
            Self::MessageTooLarge { .. } => None,
        }
    }
}

/// Decode one complete envelope.  The byte bound is checked before invoking
/// serde so an attacker cannot allocate a parser tree from an oversized body.
pub fn decode_envelope(encoded: &[u8]) -> Result<RequestEnvelope, EnvelopeError> {
    if encoded.len() > MAX_ENVELOPE_BYTES {
        return Err(EnvelopeError::MessageTooLarge {
            length: encoded.len(),
            maximum: MAX_ENVELOPE_BYTES,
        });
    }
    serde_json::from_slice(encoded).map_err(EnvelopeError::Json)
}

/// Short function-oriented aliases for callers that use codec terminology.
pub fn encode_envelope(envelope: &RequestEnvelope) -> Result<Vec<u8>, EnvelopeError> {
    envelope.encode()
}

/// Validate a decoded envelope with explicit time, verified transport peer,
/// expected destination and independently validated owner access.
pub fn validate_envelope(
    envelope: &RequestEnvelope,
    now: DateTime<Utc>,
    verified_peer: &VerifiedPeerIdentity,
    expected_destination: &Destination,
    owner_access: Option<&ValidatedAccessToken>,
) -> Result<(), EnvelopeValidationError> {
    envelope.validate(now, verified_peer, expected_destination, owner_access)
}

/// Convert an envelope validation failure into the bounded internal error
/// class used by the relay.  The original validation variant is not included
/// in public responses, so malformed peer input cannot disclose credentials or
/// internal addresses.
#[must_use]
pub fn validation_error_code(error: &EnvelopeValidationError) -> InternalErrorCode {
    match error {
        EnvelopeValidationError::SourceIdentityMismatch
        | EnvelopeValidationError::InvalidPeerIdentity { .. } => InternalErrorCode::PeerUntrusted,
        EnvelopeValidationError::DestinationMismatch
        | EnvelopeValidationError::OwnerTokenMismatch
        | EnvelopeValidationError::TenantScopeMismatch
        | EnvelopeValidationError::DeviceScopeMismatch
        | EnvelopeValidationError::ServiceScopeMismatch => InternalErrorCode::ScopeMismatch,
        EnvelopeValidationError::AdmissionDeadlineExpired
        | EnvelopeValidationError::AdmissionDeadlineMissing
        | EnvelopeValidationError::AdmissionDeadlineTooLong { .. }
        | EnvelopeValidationError::AdmissionExceedsStreamLifetime { .. }
        | EnvelopeValidationError::StreamLifetimeInvalid { .. } => {
            InternalErrorCode::DeadlineExceeded
        }
        EnvelopeValidationError::DeviceCertificateNotYetValid
        | EnvelopeValidationError::DeviceCertificateExpired
        | EnvelopeValidationError::ConsumerBearerMissing
        | EnvelopeValidationError::ConsumerBearerOwnerMismatch
        | EnvelopeValidationError::OwnerJwtValidationRequired
        | EnvelopeValidationError::OwnerJwtExpired
        | EnvelopeValidationError::OwnerJwtTenantMismatch
        | EnvelopeValidationError::OwnerJwtScopeMissing
        | EnvelopeValidationError::InvalidConsumerBearer
        | EnvelopeValidationError::DeviceAuthenticationMissing
        | EnvelopeValidationError::DeviceBindingMismatch
        | EnvelopeValidationError::DeviceBindingExpired => InternalErrorCode::CredentialInvalid,
        EnvelopeValidationError::InvalidSchemaVersion { .. }
        | EnvelopeValidationError::InvalidIdentifier { .. }
        | EnvelopeValidationError::InvalidHopBudget { .. }
        | EnvelopeValidationError::RoutePayloadMismatch => InternalErrorCode::InvalidEnvelope,
    }
}

fn validate_identifier(field: &'static str, value: &str) -> Result<(), EnvelopeValidationError> {
    validate_bounded_string(field, value, MAX_IDENTIFIER_BYTES)
}

fn validate_bounded_string(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), EnvelopeValidationError> {
    if value.trim().is_empty() || value.len() > maximum || value.chars().any(char::is_control) {
        return Err(EnvelopeValidationError::InvalidIdentifier { field });
    }
    Ok(())
}

fn validate_owner_token(token: &OwnerToken) -> Result<(), EnvelopeValidationError> {
    validate_identifier(
        "owner_token.deployment_incarnation",
        &token.deployment_incarnation,
    )?;
    validate_identifier("owner_token.node_id", &token.node_id)?;
    validate_identifier("owner_token.boot_id", &token.boot_id)?;
    validate_identifier("owner_token.session_id", &token.session_id)?;
    if token.epoch == 0 {
        return Err(EnvelopeValidationError::InvalidIdentifier {
            field: "owner_token.epoch",
        });
    }
    Ok(())
}

/// Strict wire representation for the catalog owner token.  The catalog
/// type remains the source of truth, but its broad serde struct is wrapped so
/// unknown fields cannot be accepted inside a bounded peer envelope.
mod strict_owner_token {
    use super::*;

    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct WireOwnerToken {
        deployment_incarnation: String,
        tenant_id: TenantId,
        device_id: DeviceId,
        node_id: String,
        boot_id: String,
        session_id: String,
        epoch: u64,
    }

    pub fn serialize<S>(token: &OwnerToken, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[derive(Serialize)]
        struct WireOwnerTokenRef<'a> {
            deployment_incarnation: &'a str,
            tenant_id: TenantId,
            device_id: DeviceId,
            node_id: &'a str,
            boot_id: &'a str,
            session_id: &'a str,
            epoch: u64,
        }
        WireOwnerTokenRef {
            deployment_incarnation: &token.deployment_incarnation,
            tenant_id: token.tenant_id,
            device_id: token.device_id,
            node_id: &token.node_id,
            boot_id: &token.boot_id,
            session_id: &token.session_id,
            epoch: token.epoch,
        }
        .serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<OwnerToken, D::Error>
    where
        D: Deserializer<'de>,
    {
        let token = WireOwnerToken::deserialize(deserializer)?;
        Ok(OwnerToken {
            deployment_incarnation: token.deployment_incarnation,
            tenant_id: token.tenant_id,
            device_id: token.device_id,
            node_id: token.node_id,
            boot_id: token.boot_id,
            session_id: token.session_id,
            epoch: token.epoch,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;
    use std::collections::BTreeSet;
    use tunnel_catalog::AuthenticatedConsumer;
    use uuid::Uuid;

    fn owner() -> OwnerToken {
        OwnerToken {
            deployment_incarnation: "inc-1".into(),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
            node_id: "owner-node".into(),
            boot_id: "owner-boot".into(),
            session_id: "session-1".into(),
            epoch: 7,
        }
    }

    fn destination() -> Destination {
        Destination::new(owner(), Uuid::from_u128(3))
    }

    fn verified_peer() -> VerifiedPeerIdentity {
        VerifiedPeerIdentity::from_verified_transport("source-node", "source-boot")
            .expect("test peer is valid")
    }

    fn base(route: InternalRoute, request: InternalRequest) -> RequestEnvelope {
        RequestEnvelope::new(
            route,
            "request-1",
            PeerIdentity::new("source-node", "source-boot"),
            destination(),
            5_000,
            Some(10_000),
            request,
        )
    }

    fn health() -> RequestEnvelope {
        base(
            InternalRoute::Health,
            InternalRequest::Health(HealthRequest {
                check_id: "check-1".into(),
            }),
        )
    }

    fn certificate(now: DateTime<Utc>) -> VerifiedDeviceCertificate {
        VerifiedDeviceCertificate {
            certificate_identity: "device-cert".into(),
            spki_fingerprint: "spki".into(),
            serial: "serial".into(),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::seconds(30),
            tenant_id: Uuid::from_u128(1),
            device_id: Uuid::from_u128(2),
        }
    }

    fn device_control(now: DateTime<Utc>) -> RequestEnvelope {
        let destination = destination();
        let source = PeerIdentity::new("source-node", "source-boot");
        let authentication = DeviceAuthenticationContext {
            certificate: certificate(now),
            ingress: IngressRequestBinding {
                request_id: "request-1".into(),
                source: source.clone(),
                destination: destination.clone(),
                expires_at: now + Duration::seconds(10),
            },
        };
        base(
            InternalRoute::DeviceControl,
            InternalRequest::DeviceControl(DeviceControlRequest {
                stream_id: "stream-1".into(),
                authentication,
            }),
        )
    }

    fn consumer(now: DateTime<Utc>) -> (RequestEnvelope, ValidatedAccessToken) {
        let bearer = ForwardedConsumerBearer::new("secret.jwt.value", owner())
            .expect("test bearer is valid");
        let request = InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: "stream-1".into(),
            required_scope: "service:read".into(),
            bearer,
            bytes: Vec::new(),
        });
        let mut envelope = base(InternalRoute::ConsumerStreams, request);
        let access = ValidatedAccessToken {
            consumer: AuthenticatedConsumer {
                tenant_id: Uuid::from_u128(1),
                principal_id: Uuid::from_u128(4),
            },
            issuer: "https://issuer.example".into(),
            subject: "user-1".into(),
            scopes: BTreeSet::from(["service:read".into()]),
            expires_at: now + Duration::seconds(30),
        };
        envelope.operation_id = Some("operation-1".into());
        (envelope, access)
    }

    #[test]
    fn source_must_match_verified_transport_identity() {
        let mut envelope = health();
        envelope.source.boot_id = "other-boot".into();
        let result = envelope.validate(Utc::now(), &verified_peer(), &destination(), None);
        assert_eq!(result, Err(EnvelopeValidationError::SourceIdentityMismatch));
        assert_eq!(
            validation_error_code(&EnvelopeValidationError::SourceIdentityMismatch),
            InternalErrorCode::PeerUntrusted
        );
    }

    #[test]
    fn destination_owner_and_scope_are_exact() {
        let mut envelope = health();
        envelope.destination.service_id = Uuid::from_u128(99);
        let result = envelope.validate(Utc::now(), &verified_peer(), &destination(), None);
        assert_eq!(result, Err(EnvelopeValidationError::ServiceScopeMismatch));

        let mut envelope = health();
        envelope.destination.owner_token.epoch += 1;
        let result = envelope.validate(Utc::now(), &verified_peer(), &destination(), None);
        assert_eq!(result, Err(EnvelopeValidationError::OwnerTokenMismatch));

        let mut envelope = health();
        envelope.destination.owner_token.boot_id = "restarted-owner".into();
        let result = envelope.validate(Utc::now(), &verified_peer(), &destination(), None);
        assert_eq!(result, Err(EnvelopeValidationError::OwnerTokenMismatch));
    }

    #[test]
    fn malformed_owner_token_is_rejected_before_route_admission() {
        let mut expected = destination();
        expected.owner_token.epoch = 0;
        let mut envelope = health();
        envelope.destination = expected.clone();

        let error = envelope
            .validate(Utc::now(), &verified_peer(), &expected, None)
            .expect_err("malformed owner must fail");
        assert_eq!(
            error,
            EnvelopeValidationError::InvalidIdentifier {
                field: "owner_token.epoch"
            }
        );
        assert_eq!(
            validation_error_code(&error),
            InternalErrorCode::InvalidEnvelope
        );
    }

    #[test]
    fn whitespace_and_control_identifiers_are_rejected() {
        let mut envelope = health();
        envelope.source.node_id = "   ".into();
        assert_eq!(
            envelope.validate(Utc::now(), &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::InvalidIdentifier {
                field: "source.node_id"
            })
        );

        let mut envelope = health();
        if let InternalRequest::Health(request) = &mut envelope.request {
            request.check_id = "check\nforged".into();
        }
        assert_eq!(
            envelope.validate(Utc::now(), &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::InvalidIdentifier {
                field: "health.check_id"
            })
        );
    }

    #[test]
    fn route_payload_mismatch_is_a_malformed_internal_request() {
        let mut envelope = health();
        envelope.route = InternalRoute::DeviceData;
        let error = envelope
            .validate(Utc::now(), &verified_peer(), &destination(), None)
            .expect_err("wrong internal route must be rejected");
        assert_eq!(error, EnvelopeValidationError::RoutePayloadMismatch);
        assert_eq!(
            validation_error_code(&error),
            InternalErrorCode::InvalidEnvelope
        );
    }

    #[test]
    fn hop_budget_must_be_exactly_one() {
        let mut envelope = health();
        envelope.hop_budget = 2;
        let result = envelope.validate(Utc::now(), &verified_peer(), &destination(), None);
        assert_eq!(
            result,
            Err(EnvelopeValidationError::InvalidHopBudget {
                expected: 1,
                actual: 2,
            })
        );
    }

    #[test]
    fn admission_deadline_is_bounded_separately_from_stream_lifetime() {
        let mut envelope = health();
        envelope.remaining_admission_ms = MAX_ADMISSION_REMAINING_MS + 1;
        assert!(matches!(
            envelope.validate(Utc::now(), &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::AdmissionDeadlineTooLong { .. })
        ));

        let mut envelope = health();
        envelope.remaining_admission_ms = 4_000;
        envelope.stream_lifetime_ms = Some(3_000);
        assert_eq!(
            envelope.validate(Utc::now(), &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::AdmissionExceedsStreamLifetime {
                admission_ms: 4_000,
                lifetime_ms: 3_000,
            })
        );
    }

    #[test]
    fn oversized_and_duplicate_field_envelopes_are_rejected_before_use() {
        let oversized = vec![b' '; MAX_ENVELOPE_BYTES + 1];
        assert!(matches!(
            decode_envelope(&oversized),
            Err(EnvelopeError::MessageTooLarge { .. })
        ));

        let duplicate = br#"{
            "schema_version":1,
            "schema_version":1,
            "route":"health",
            "request_id":"request-1",
            "operation_id":null,
            "source":{"node_id":"source-node","boot_id":"source-boot"},
            "destination":{"owner_token":{"deployment_incarnation":"inc-1","tenant_id":"00000000-0000-0000-0000-000000000001","device_id":"00000000-0000-0000-0000-000000000002","node_id":"owner-node","boot_id":"owner-boot","session_id":"session-1","epoch":7},"tenant_id":"00000000-0000-0000-0000-000000000001","device_id":"00000000-0000-0000-0000-000000000002","service_id":"00000000-0000-0000-0000-000000000003"},
            "hop_budget":1,
            "remaining_admission_ms":5000,
            "stream_lifetime_ms":10000,
            "request":{"kind":"health","body":{"check_id":"check-1"}}
        }"#;
        assert!(matches!(
            decode_envelope(duplicate),
            Err(EnvelopeError::Json(_))
        ));

        let unknown = br#"{
            "schema_version":1,
            "route":"health",
            "request_id":"request-1",
            "source":{"node_id":"source-node","boot_id":"source-boot"},
            "destination":{"owner_token":{"deployment_incarnation":"inc-1","tenant_id":"00000000-0000-0000-0000-000000000001","device_id":"00000000-0000-0000-0000-000000000002","node_id":"owner-node","boot_id":"owner-boot","session_id":"session-1","epoch":7},"tenant_id":"00000000-0000-0000-0000-000000000001","device_id":"00000000-0000-0000-0000-000000000002","service_id":"00000000-0000-0000-0000-000000000003"},
            "hop_budget":1,
            "remaining_admission_ms":5000,
            "request":{"kind":"health","body":{"check_id":"check-1"}},
            "unexpected":true
        }"#;
        assert!(matches!(
            decode_envelope(unknown),
            Err(EnvelopeError::Json(_))
        ));
    }

    #[test]
    fn consumer_requires_owner_jwt_validation_and_scope() {
        let now = Utc::now();
        let (envelope, access) = consumer(now);
        assert_eq!(
            envelope.validate(now, &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::OwnerJwtValidationRequired)
        );
        assert!(
            envelope
                .validate(now, &verified_peer(), &destination(), Some(&access))
                .is_ok()
        );

        let mut envelope = envelope;
        envelope.operation_id = None;
        assert!(
            envelope
                .validate(now, &verified_peer(), &destination(), Some(&access))
                .is_ok()
        );
    }

    #[test]
    fn forwarded_bearer_is_revalidated_after_deserialization() {
        let now = Utc::now();
        let (mut envelope, _) = consumer(now);
        if let InternalRequest::ConsumerStreams(request) = &mut envelope.request {
            request.bearer.token = "token\r\nforged".into();
        }
        assert_eq!(
            envelope.validate(now, &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::InvalidConsumerBearer)
        );
    }

    #[test]
    fn bearer_constructor_rejects_whitespace_and_invalid_owner_generation() {
        assert_eq!(
            ForwardedConsumerBearer::new("token with spaces", owner()),
            Err(EnvelopeValidationError::InvalidConsumerBearer)
        );

        let mut malformed_owner = owner();
        malformed_owner.epoch = 0;
        assert_eq!(
            ForwardedConsumerBearer::new("token", malformed_owner),
            Err(EnvelopeValidationError::InvalidIdentifier {
                field: "owner_token.epoch"
            })
        );
    }

    #[test]
    fn device_context_binds_certificate_and_ingress_expiry() {
        let now = Utc::now();
        let envelope = device_control(now);
        assert!(
            envelope
                .validate(now, &verified_peer(), &destination(), None)
                .is_ok()
        );

        let mut expired = envelope;
        if let InternalRequest::DeviceControl(request) = &mut expired.request {
            request.authentication.ingress.expires_at = now;
        }
        assert_eq!(
            expired.validate(now, &verified_peer(), &destination(), None),
            Err(EnvelopeValidationError::DeviceBindingExpired)
        );
    }

    #[test]
    fn bearer_debug_redacts_secret() {
        let bearer = ForwardedConsumerBearer::new("super-secret-token", owner())
            .expect("test bearer is valid");
        let debug = format!("{bearer:?}");
        assert!(!debug.contains("super-secret-token"));
        assert!(debug.contains("<redacted>"));
    }
}
