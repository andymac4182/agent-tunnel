//! Signed operator approval for durable-catalog recovery.
//!
//! This module is a pure verification boundary.  It does not read Redis,
//! decide whether a catalog snapshot is complete, persist a version anchor,
//! or activate an incarnation.  The caller supplies the observed Redis
//! identity, the canonical digest of the durable catalog observation, a
//! fresh nonce, and the highest approval version it has durably accepted.
//! Only an operator-installed Ed25519 public key can authorize the resulting
//! [`VerifiedRecoveryApproval`].

use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ring::signature::{self, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The signed recovery approval schema understood by this crate.
pub const RECOVERY_SCHEMA_VERSION: u16 = 1;
/// A signed recovery approval cannot exceed this encoded size.
pub const MAX_RECOVERY_RECORD_BYTES: usize = 16 * 1024;
/// A recovery approval cannot authorize a window longer than one minute.
pub const MAX_RECOVERY_LIFETIME: Duration = Duration::seconds(60);
/// The maximum wall-clock skew accepted while checking an approval.
pub const MAX_RECOVERY_CLOCK_SKEW: Duration = Duration::seconds(1);

const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_NONCE_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;
const CATALOG_DIGEST_HEX_BYTES: usize = 64;
const MAX_TRUSTED_KEYS: usize = 32;

/// Return the lower-case SHA-256 digest used by [`RecoveryApproval::catalog_digest`].
///
/// The bytes must already be the canonical encoding of the durable catalog
/// observation selected by the caller.  This helper deliberately does not
/// define a catalog snapshot schema or a global revision number.
pub fn durable_catalog_digest(canonical_observation: &[u8]) -> String {
    Sha256::digest(canonical_observation)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// An unsigned, nonce-bound operator recovery approval payload.
///
/// `catalog_digest` is the lower-case hexadecimal SHA-256 digest of a
/// caller-selected canonical durable-catalog observation.  The observation
/// must include the durable authorization and revocation state that the
/// recovery path is about to serve; this module only binds and verifies the
/// digest and does not claim that the observation is complete.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryApproval {
    pub schema_version: u16,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub redis_run_id: String,
    pub deployment_incarnation: String,
    pub approval_version: u64,
    pub nonce: String,
    pub catalog_digest: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// A signed recovery approval wire record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedRecoveryApproval {
    pub schema_version: u16,
    pub deployment_id: String,
    pub redis_namespace: String,
    pub redis_run_id: String,
    pub deployment_incarnation: String,
    pub approval_version: u64,
    pub nonce: String,
    pub catalog_digest: String,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub publisher_key_id: String,
    pub signature: String,
}

impl SignedRecoveryApproval {
    /// Combine unsigned claims with the operator key identifier and signature.
    pub fn from_parts(
        approval: RecoveryApproval,
        publisher_key_id: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: approval.schema_version,
            deployment_id: approval.deployment_id,
            redis_namespace: approval.redis_namespace,
            redis_run_id: approval.redis_run_id,
            deployment_incarnation: approval.deployment_incarnation,
            approval_version: approval.approval_version,
            nonce: approval.nonce,
            catalog_digest: approval.catalog_digest,
            issued_at: approval.issued_at,
            not_before: approval.not_before,
            expires_at: approval.expires_at,
            publisher_key_id: publisher_key_id.into(),
            signature: signature.into(),
        }
    }

    /// Return the unsigned claims carried by this wire record.
    pub fn approval(&self) -> RecoveryApproval {
        RecoveryApproval {
            schema_version: self.schema_version,
            deployment_id: self.deployment_id.clone(),
            redis_namespace: self.redis_namespace.clone(),
            redis_run_id: self.redis_run_id.clone(),
            deployment_incarnation: self.deployment_incarnation.clone(),
            approval_version: self.approval_version,
            nonce: self.nonce.clone(),
            catalog_digest: self.catalog_digest.clone(),
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
        }
    }

    /// Encode the complete signed record as canonical JSON.
    pub fn encode(&self) -> Result<Vec<u8>, RecoveryError> {
        serde_json::to_vec(self).map_err(|error| RecoveryError::Serialization(error.to_string()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, RecoveryError> {
        let body = RecoverySigningBody {
            schema_version: self.schema_version,
            deployment_id: &self.deployment_id,
            redis_namespace: &self.redis_namespace,
            redis_run_id: &self.redis_run_id,
            deployment_incarnation: &self.deployment_incarnation,
            approval_version: self.approval_version,
            nonce: &self.nonce,
            catalog_digest: &self.catalog_digest,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            publisher_key_id: &self.publisher_key_id,
        };
        serde_json::to_vec(&body).map_err(|error| RecoveryError::Serialization(error.to_string()))
    }
}

/// A trusted operator public key installed outside Redis.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedRecoveryKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

impl TrustedRecoveryKey {
    /// Construct a trusted public key after checking its bounded identifier.
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> Result<Self, RecoveryError> {
        let key_id = key_id.into();
        validate_identifier("recovery publisher key id", &key_id)?;
        Ok(Self { key_id, public_key })
    }
}

/// Recovery identity values bound by an operator approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecoveryPolicy {
    deployment_id: String,
    redis_namespace: String,
    redis_run_id: String,
    deployment_incarnation: String,
}

impl RecoveryPolicy {
    /// Build a policy from values observed or supplied by the caller.
    pub fn new(
        deployment_id: impl Into<String>,
        redis_namespace: impl Into<String>,
        redis_run_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
    ) -> Result<Self, RecoveryError> {
        let policy = Self {
            deployment_id: deployment_id.into(),
            redis_namespace: redis_namespace.into(),
            redis_run_id: redis_run_id.into(),
            deployment_incarnation: deployment_incarnation.into(),
        };
        policy.validate()?;
        Ok(policy)
    }

    /// The operator trust domain bound by the approval.
    pub fn deployment_id(&self) -> &str {
        &self.deployment_id
    }

    /// The Redis namespace bound by the approval.
    pub fn redis_namespace(&self) -> &str {
        &self.redis_namespace
    }

    /// The actual Redis `run_id` observed by the caller.
    pub fn redis_run_id(&self) -> &str {
        &self.redis_run_id
    }

    /// The newly approved deployment incarnation.
    pub fn deployment_incarnation(&self) -> &str {
        &self.deployment_incarnation
    }

    fn validate(&self) -> Result<(), RecoveryError> {
        validate_identifier("deployment id", &self.deployment_id)?;
        validate_identifier("Redis namespace", &self.redis_namespace)?;
        validate_identifier("Redis run id", &self.redis_run_id)?;
        validate_identifier("deployment incarnation", &self.deployment_incarnation)
    }
}

/// An approval accepted by [`RecoveryApprovalVerifier`].
///
/// Fields are private so callers cannot fabricate an accepted approval or
/// mutate one after its signature, scope, nonce, time, and external version
/// anchor have been checked.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedRecoveryApproval {
    approval: RecoveryApproval,
    publisher_key_id: String,
    signed_bytes: Vec<u8>,
}

impl VerifiedRecoveryApproval {
    /// The verified unsigned claims.
    pub fn approval(&self) -> &RecoveryApproval {
        &self.approval
    }

    /// The trusted operator key identifier that verified the signature.
    pub fn publisher_key_id(&self) -> &str {
        &self.publisher_key_id
    }

    /// The deployment trust domain.
    pub fn deployment_id(&self) -> &str {
        &self.approval.deployment_id
    }

    /// The Redis namespace.
    pub fn redis_namespace(&self) -> &str {
        &self.approval.redis_namespace
    }

    /// The actual Redis run identity bound into the approval.
    pub fn redis_run_id(&self) -> &str {
        &self.approval.redis_run_id
    }

    /// The newly approved deployment incarnation.
    pub fn deployment_incarnation(&self) -> &str {
        &self.approval.deployment_incarnation
    }

    /// The external approval version accepted by the caller's version anchor.
    pub fn approval_version(&self) -> u64 {
        self.approval.approval_version
    }

    /// The fresh recovery nonce.
    pub fn nonce(&self) -> &str {
        &self.approval.nonce
    }

    /// The lower-case hexadecimal SHA-256 durable-catalog digest.
    pub fn catalog_digest(&self) -> &str {
        &self.approval.catalog_digest
    }

    /// The lower bound of the signed validity window.
    pub fn not_before(&self) -> DateTime<Utc> {
        self.approval.not_before
    }

    /// The upper bound of the signed validity window.
    pub fn expires_at(&self) -> DateTime<Utc> {
        self.approval.expires_at
    }

    /// The signed canonical JSON bytes retained for audit or persistence.
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }
}

/// Pure verifier for externally signed recovery approvals.
///
/// The verifier intentionally does not retain an approval version or nonce.
/// Pass the version persisted by an external checkpoint authority to each
/// [`Self::verify`] call; a successful result is not durable until the caller
/// records that version outside Redis.
pub struct RecoveryApprovalVerifier {
    policy: RecoveryPolicy,
    trusted_keys: BTreeMap<String, [u8; 32]>,
}

impl RecoveryApprovalVerifier {
    /// Build a verifier from operator-installed public keys.
    pub fn new(
        policy: RecoveryPolicy,
        trusted_keys: impl IntoIterator<Item = TrustedRecoveryKey>,
    ) -> Result<Self, RecoveryError> {
        let mut keys = BTreeMap::new();
        for trusted in trusted_keys {
            validate_identifier("recovery publisher key id", &trusted.key_id)?;
            if keys
                .insert(trusted.key_id.clone(), trusted.public_key)
                .is_some()
            {
                return Err(RecoveryError::DuplicateTrustedKey(trusted.key_id));
            }
        }
        if keys.is_empty() || keys.len() > MAX_TRUSTED_KEYS {
            return Err(RecoveryError::InvalidPolicy(
                "at least one and at most 32 recovery publisher keys are required".into(),
            ));
        }
        Ok(Self {
            policy,
            trusted_keys: keys,
        })
    }

    /// The identity policy captured by this verifier.
    pub fn policy(&self) -> &RecoveryPolicy {
        &self.policy
    }

    /// Verify one approval against the observed identity and an external
    /// monotonic version anchor.
    pub fn verify(
        &self,
        bytes: &[u8],
        expected_nonce: &str,
        now: DateTime<Utc>,
        highest_accepted_version: Option<u64>,
    ) -> Result<VerifiedRecoveryApproval, RecoveryError> {
        let signed = decode_signed_approval(bytes)?;
        let approval = signed.approval();
        validate_approval_shape(&approval, &self.policy, expected_nonce, now)?;

        let canonical = signed.encode()?;
        if canonical != bytes {
            return Err(RecoveryError::NonCanonicalEncoding);
        }
        verify_signature(
            &self.trusted_keys,
            &signed.publisher_key_id,
            &signed.signing_bytes()?,
            &signed.signature,
        )?;

        if let Some(highest) = highest_accepted_version {
            if approval.approval_version < highest {
                return Err(RecoveryError::VersionRollback {
                    highest,
                    received: approval.approval_version,
                });
            }
            if approval.approval_version == highest {
                return Err(RecoveryError::EqualVersionConflict {
                    version: approval.approval_version,
                });
            }
        }

        Ok(VerifiedRecoveryApproval {
            approval,
            publisher_key_id: signed.publisher_key_id,
            signed_bytes: bytes.to_vec(),
        })
    }
}

/// A pure signing helper for an external operator or test fixture.
///
/// Normal relay configuration should contain only [`TrustedRecoveryKey`]
/// values.  This helper does no I/O and does not persist or transmit its
/// private key.
pub struct RecoveryApprovalIssuer {
    key_id: String,
    key_pair: signature::Ed25519KeyPair,
}

impl RecoveryApprovalIssuer {
    /// Load an externally provisioned PKCS#8 Ed25519 key.
    pub fn from_pkcs8(key_id: impl Into<String>, pkcs8: &[u8]) -> Result<Self, RecoveryError> {
        let key_id = key_id.into();
        validate_identifier("recovery publisher key id", &key_id)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| RecoveryError::InvalidIssuerKey)?;
        Ok(Self { key_id, key_pair })
    }

    /// Generate an operator key for a test fixture or isolated publisher.
    pub fn generate(key_id: impl Into<String>) -> Result<(Self, Vec<u8>), RecoveryError> {
        let key_id = key_id.into();
        validate_identifier("recovery publisher key id", &key_id)?;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| RecoveryError::InvalidIssuerKey)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| RecoveryError::InvalidIssuerKey)?;
        Ok((Self { key_id, key_pair }, pkcs8.as_ref().to_vec()))
    }

    /// The public key for operator trust provisioning.
    pub fn public_key(&self) -> Result<[u8; 32], RecoveryError> {
        let mut public_key = [0_u8; 32];
        let bytes = self.key_pair.public_key().as_ref();
        if bytes.len() != public_key.len() {
            return Err(RecoveryError::InvalidIssuerKey);
        }
        public_key.copy_from_slice(bytes);
        Ok(public_key)
    }

    /// Sign one recovery approval without performing verification.
    pub fn sign_approval(
        &self,
        approval: RecoveryApproval,
    ) -> Result<SignedRecoveryApproval, RecoveryError> {
        let unsigned =
            SignedRecoveryApproval::from_parts(approval, self.key_id.clone(), String::new());
        let signature = self.key_pair.sign(&unsigned.signing_bytes()?);
        Ok(SignedRecoveryApproval::from_parts(
            unsigned.approval(),
            self.key_id.clone(),
            URL_SAFE_NO_PAD.encode(signature.as_ref()),
        ))
    }

    /// Sign one recovery approval and encode its canonical JSON wire form.
    pub fn sign_approval_bytes(
        &self,
        approval: RecoveryApproval,
    ) -> Result<Vec<u8>, RecoveryError> {
        self.sign_approval(approval)?.encode()
    }
}

/// Namespace for issuer-only integration and fixture helpers.
pub mod issuer {
    pub use super::RecoveryApprovalIssuer;
}

#[derive(Serialize)]
struct RecoverySigningBody<'a> {
    schema_version: u16,
    deployment_id: &'a str,
    redis_namespace: &'a str,
    redis_run_id: &'a str,
    deployment_incarnation: &'a str,
    approval_version: u64,
    nonce: &'a str,
    catalog_digest: &'a str,
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    publisher_key_id: &'a str,
}

fn decode_signed_approval(bytes: &[u8]) -> Result<SignedRecoveryApproval, RecoveryError> {
    if bytes.len() > MAX_RECOVERY_RECORD_BYTES {
        return Err(RecoveryError::RecordTooLarge {
            size: bytes.len(),
            max: MAX_RECOVERY_RECORD_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| RecoveryError::MalformedJson(error.to_string()))
}

fn validate_approval_shape(
    approval: &RecoveryApproval,
    policy: &RecoveryPolicy,
    expected_nonce: &str,
    now: DateTime<Utc>,
) -> Result<(), RecoveryError> {
    if approval.schema_version != RECOVERY_SCHEMA_VERSION {
        return Err(RecoveryError::UnsupportedSchemaVersion(
            approval.schema_version,
        ));
    }
    if approval.deployment_id != policy.deployment_id {
        return Err(RecoveryError::DeploymentMismatch);
    }
    if approval.redis_namespace != policy.redis_namespace {
        return Err(RecoveryError::RedisNamespaceMismatch);
    }
    if approval.redis_run_id != policy.redis_run_id {
        return Err(RecoveryError::RedisRunIdMismatch);
    }
    if approval.deployment_incarnation != policy.deployment_incarnation {
        return Err(RecoveryError::IncarnationMismatch);
    }
    validate_identifier("deployment id", &approval.deployment_id)?;
    validate_identifier("Redis namespace", &approval.redis_namespace)?;
    validate_identifier("Redis run id", &approval.redis_run_id)?;
    validate_identifier("deployment incarnation", &approval.deployment_incarnation)?;
    if approval.approval_version == 0 {
        return Err(RecoveryError::InvalidVersion);
    }
    validate_nonce(&approval.nonce)?;
    validate_nonce(expected_nonce)?;
    if approval.nonce != expected_nonce {
        return Err(RecoveryError::NonceMismatch);
    }
    validate_catalog_digest(&approval.catalog_digest)?;
    validate_window(
        approval.issued_at,
        approval.not_before,
        approval.expires_at,
        now,
    )
}

fn validate_window(
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
) -> Result<(), RecoveryError> {
    if issued_at > expires_at || not_before > expires_at {
        return Err(RecoveryError::InvalidTimeWindow);
    }
    if expires_at.signed_duration_since(issued_at) > MAX_RECOVERY_LIFETIME {
        return Err(RecoveryError::LifetimeExceeded);
    }
    let latest_issued = now
        .checked_add_signed(MAX_RECOVERY_CLOCK_SKEW)
        .ok_or(RecoveryError::InvalidTime)?;
    if issued_at > latest_issued {
        return Err(RecoveryError::IssuedInFuture);
    }
    let earliest = now
        .checked_sub_signed(MAX_RECOVERY_CLOCK_SKEW)
        .ok_or(RecoveryError::InvalidTime)?;
    let earliest_not_before = not_before
        .checked_sub_signed(MAX_RECOVERY_CLOCK_SKEW)
        .ok_or(RecoveryError::InvalidTime)?;
    if now < earliest_not_before {
        return Err(RecoveryError::NotYetValid);
    }
    if now > expires_at {
        let latest = expires_at
            .checked_add_signed(MAX_RECOVERY_CLOCK_SKEW)
            .ok_or(RecoveryError::InvalidTime)?;
        if now > latest {
            return Err(RecoveryError::Expired);
        }
    }
    if expires_at < earliest {
        return Err(RecoveryError::Expired);
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), RecoveryError> {
    if nonce.len() < MIN_NONCE_BYTES || nonce.len() > MAX_NONCE_BYTES {
        return Err(RecoveryError::InvalidNonce);
    }
    if !nonce
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(RecoveryError::InvalidNonce);
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), RecoveryError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(RecoveryError::InvalidIdentifier(label.into()));
    }
    Ok(())
}

fn validate_catalog_digest(digest: &str) -> Result<(), RecoveryError> {
    if digest.len() != CATALOG_DIGEST_HEX_BYTES
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(RecoveryError::InvalidCatalogDigest);
    }
    Ok(())
}

fn verify_signature(
    trusted_keys: &BTreeMap<String, [u8; 32]>,
    key_id: &str,
    message: &[u8],
    encoded_signature: &str,
) -> Result<(), RecoveryError> {
    validate_identifier("recovery publisher key id", key_id)?;
    let public_key = trusted_keys
        .get(key_id)
        .ok_or_else(|| RecoveryError::UnknownTrustedKey(key_id.to_owned()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| RecoveryError::InvalidSignatureEncoding)?;
    if signature.len() != 64 || URL_SAFE_NO_PAD.encode(&signature) != encoded_signature {
        return Err(RecoveryError::InvalidSignatureEncoding);
    }
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| RecoveryError::SignatureInvalid)
}

/// Typed failures returned while decoding or verifying a recovery approval.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RecoveryError {
    InvalidPolicy(String),
    MalformedJson(String),
    Serialization(String),
    RecordTooLarge { size: usize, max: usize },
    NonCanonicalEncoding,
    UnsupportedSchemaVersion(u16),
    DeploymentMismatch,
    RedisNamespaceMismatch,
    RedisRunIdMismatch,
    IncarnationMismatch,
    InvalidIdentifier(String),
    InvalidVersion,
    InvalidNonce,
    NonceMismatch,
    InvalidCatalogDigest,
    InvalidTime,
    InvalidTimeWindow,
    LifetimeExceeded,
    IssuedInFuture,
    NotYetValid,
    Expired,
    VersionRollback { highest: u64, received: u64 },
    EqualVersionConflict { version: u64 },
    DuplicateTrustedKey(String),
    UnknownTrustedKey(String),
    InvalidSignatureEncoding,
    SignatureInvalid,
    InvalidIssuerKey,
}

impl fmt::Display for RecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(message) => write!(formatter, "invalid recovery policy: {message}"),
            Self::MalformedJson(message) => {
                write!(
                    formatter,
                    "malformed signed recovery approval JSON: {message}"
                )
            }
            Self::Serialization(message) => {
                write!(
                    formatter,
                    "recovery approval serialization failed: {message}"
                )
            }
            Self::RecordTooLarge { size, max } => {
                write!(
                    formatter,
                    "recovery approval is {size} bytes; maximum is {max}"
                )
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("signed recovery approval is not canonical JSON")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported recovery schema version {version}")
            }
            Self::DeploymentMismatch => {
                formatter.write_str("recovery approval deployment does not match policy")
            }
            Self::RedisNamespaceMismatch => {
                formatter.write_str("recovery approval Redis namespace does not match policy")
            }
            Self::RedisRunIdMismatch => {
                formatter.write_str("recovery approval Redis run id does not match observation")
            }
            Self::IncarnationMismatch => {
                formatter.write_str("recovery approval incarnation does not match policy")
            }
            Self::InvalidIdentifier(label) => write!(formatter, "invalid bounded {label}"),
            Self::InvalidVersion => {
                formatter.write_str("recovery approval version must be nonzero")
            }
            Self::InvalidNonce => formatter.write_str("recovery approval nonce is invalid"),
            Self::NonceMismatch => {
                formatter.write_str("recovery approval nonce does not match challenge")
            }
            Self::InvalidCatalogDigest => formatter
                .write_str("recovery approval catalog digest is not lower-case SHA-256 hex"),
            Self::InvalidTime => {
                formatter.write_str("recovery approval time is outside the representable range")
            }
            Self::InvalidTimeWindow => {
                formatter.write_str("recovery approval time window is invalid")
            }
            Self::LifetimeExceeded => {
                formatter.write_str("recovery approval validity exceeds the bounded lifetime")
            }
            Self::IssuedInFuture => {
                formatter.write_str("recovery approval was issued too far in the future")
            }
            Self::NotYetValid => formatter.write_str("recovery approval is not yet valid"),
            Self::Expired => formatter.write_str("recovery approval has expired"),
            Self::VersionRollback { highest, received } => write!(
                formatter,
                "recovery approval version rollback from {highest} to {received}"
            ),
            Self::EqualVersionConflict { version } => write!(
                formatter,
                "conflicting recovery approval at version {version}"
            ),
            Self::DuplicateTrustedKey(key_id) => {
                write!(formatter, "duplicate trusted recovery key {key_id}")
            }
            Self::UnknownTrustedKey(key_id) => {
                write!(formatter, "unknown recovery publisher key {key_id}")
            }
            Self::InvalidSignatureEncoding => {
                formatter.write_str("recovery signature is not canonical Ed25519 base64")
            }
            Self::SignatureInvalid => formatter.write_str("recovery signature is invalid"),
            Self::InvalidIssuerKey => formatter.write_str("issuer key is not a valid Ed25519 key"),
        }
    }
}

impl std::error::Error for RecoveryError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test timestamp")
            .with_timezone(&Utc)
    }

    fn approval(now: DateTime<Utc>, version: u64) -> RecoveryApproval {
        RecoveryApproval {
            schema_version: RECOVERY_SCHEMA_VERSION,
            deployment_id: "deployment-a".into(),
            redis_namespace: "cluster-a".into(),
            redis_run_id: "redis-run-a".into(),
            deployment_incarnation: "incarnation-b".into(),
            approval_version: version,
            nonce: "0123456789abcdef".into(),
            catalog_digest: "ab".repeat(32),
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::seconds(60),
        }
    }

    fn verifier(issuer: &RecoveryApprovalIssuer) -> RecoveryApprovalVerifier {
        let key = TrustedRecoveryKey::new("operator-a", issuer.public_key().expect("public key"))
            .expect("trusted key");
        RecoveryApprovalVerifier::new(
            RecoveryPolicy::new("deployment-a", "cluster-a", "redis-run-a", "incarnation-b")
                .expect("policy"),
            [key],
        )
        .expect("verifier")
    }

    #[test]
    fn valid_approval_verifies_and_binds_catalog_observation() {
        let (issuer, _) = RecoveryApprovalIssuer::generate("operator-a").expect("issuer");
        let verifier = verifier(&issuer);
        let signed = issuer
            .sign_approval(approval(now(), 7))
            .expect("signed approval")
            .encode()
            .expect("approval bytes");

        let verified = verifier
            .verify(&signed, "0123456789abcdef", now(), Some(6))
            .expect("verified approval");
        assert_eq!(verified.approval_version(), 7);
        assert_eq!(verified.publisher_key_id(), "operator-a");
        assert_eq!(verified.redis_run_id(), "redis-run-a");
        assert_eq!(verified.catalog_digest(), &"ab".repeat(32));
        assert_eq!(verified.signed_bytes(), signed.as_slice());
    }

    #[test]
    fn tampered_and_noncanonical_records_are_rejected() {
        let (issuer, _) = RecoveryApprovalIssuer::generate("operator-a").expect("issuer");
        let verifier = verifier(&issuer);
        let signed = issuer
            .sign_approval(approval(now(), 1))
            .expect("signed approval");
        let mut tampered = signed.clone();
        tampered.catalog_digest = "cd".repeat(32);
        let tampered_bytes = tampered.encode().expect("tampered bytes");
        assert!(matches!(
            verifier.verify(&tampered_bytes, "0123456789abcdef", now(), None),
            Err(RecoveryError::SignatureInvalid)
        ));

        let canonical = signed.encode().expect("canonical bytes");
        let mut noncanonical = Vec::with_capacity(canonical.len() + 1);
        noncanonical.extend_from_slice(b" ");
        noncanonical.extend_from_slice(&canonical);
        assert!(matches!(
            verifier.verify(&noncanonical, "0123456789abcdef", now(), None),
            Err(RecoveryError::NonCanonicalEncoding)
        ));
    }

    #[test]
    fn deployment_namespace_run_and_incarnation_are_bound() {
        let (issuer, _) = RecoveryApprovalIssuer::generate("operator-a").expect("issuer");
        let verifier = verifier(&issuer);

        let mut scoped = approval(now(), 1);
        scoped.deployment_id = "other-deployment".into();
        let signed = issuer.sign_approval(scoped).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::DeploymentMismatch)
        ));

        let mut namespace = approval(now(), 1);
        namespace.redis_namespace = "other-cluster".into();
        let signed = issuer.sign_approval(namespace).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::RedisNamespaceMismatch)
        ));

        let mut run = approval(now(), 1);
        run.redis_run_id = "redis-run-restored".into();
        let signed = issuer.sign_approval(run).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::RedisRunIdMismatch)
        ));

        let mut incarnation = approval(now(), 1);
        incarnation.deployment_incarnation = "incarnation-old".into();
        let signed = issuer.sign_approval(incarnation).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::IncarnationMismatch)
        ));
    }

    #[test]
    fn digest_and_nonce_are_bounded_and_nonce_is_challenge_bound() {
        let (issuer, _) = RecoveryApprovalIssuer::generate("operator-a").expect("issuer");
        let verifier = verifier(&issuer);

        let mut digest = approval(now(), 1);
        digest.catalog_digest = "not-a-digest".into();
        let signed = issuer.sign_approval(digest).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::InvalidCatalogDigest)
        ));

        let signed = issuer
            .sign_approval(approval(now(), 1))
            .expect("signed approval")
            .encode()
            .expect("approval bytes");
        assert!(matches!(
            verifier.verify(&signed, "fedcba9876543210", now(), None),
            Err(RecoveryError::NonceMismatch)
        ));

        let mut invalid_nonce = approval(now(), 1);
        invalid_nonce.nonce = "short".into();
        let signed = issuer
            .sign_approval(invalid_nonce)
            .expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::InvalidNonce)
        ));
    }

    #[test]
    fn time_and_external_version_fences_are_fail_closed() {
        let (issuer, _) = RecoveryApprovalIssuer::generate("operator-a").expect("issuer");
        let verifier = verifier(&issuer);

        let mut future = approval(now(), 1);
        future.issued_at = now() + Duration::seconds(2);
        let signed = issuer.sign_approval(future).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::IssuedInFuture)
        ));

        let mut not_yet_valid = approval(now(), 1);
        not_yet_valid.not_before = now() + Duration::seconds(2);
        let signed = issuer
            .sign_approval(not_yet_valid)
            .expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::NotYetValid)
        ));

        let mut expired = approval(now(), 1);
        expired.issued_at = now() - Duration::seconds(60);
        expired.not_before = now() - Duration::seconds(59);
        expired.expires_at = now() - Duration::seconds(2);
        let signed = issuer.sign_approval(expired).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::Expired)
        ));

        let mut skew_boundary = approval(now(), 1);
        skew_boundary.issued_at = now() - MAX_RECOVERY_CLOCK_SKEW;
        skew_boundary.not_before = now() - MAX_RECOVERY_CLOCK_SKEW;
        skew_boundary.expires_at = now() - MAX_RECOVERY_CLOCK_SKEW;
        let signed = issuer
            .sign_approval(skew_boundary)
            .expect("signed approval")
            .encode()
            .expect("approval bytes");
        assert!(
            verifier
                .verify(&signed, "0123456789abcdef", now(), None)
                .is_ok()
        );

        let mut not_before_boundary = approval(now(), 1);
        not_before_boundary.not_before = now() + MAX_RECOVERY_CLOCK_SKEW;
        let signed = issuer
            .sign_approval(not_before_boundary)
            .expect("signed approval")
            .encode()
            .expect("approval bytes");
        assert!(
            verifier
                .verify(&signed, "0123456789abcdef", now(), None)
                .is_ok()
        );

        let mut long_lived = approval(now(), 1);
        long_lived.expires_at = now() + Duration::seconds(61);
        let signed = issuer.sign_approval(long_lived).expect("signed approval");
        assert!(matches!(
            verifier.verify(
                &signed.encode().expect("bytes"),
                "0123456789abcdef",
                now(),
                None
            ),
            Err(RecoveryError::LifetimeExceeded)
        ));

        let signed = issuer
            .sign_approval(approval(now(), 4))
            .expect("signed approval")
            .encode()
            .expect("approval bytes");
        assert!(matches!(
            verifier.verify(&signed, "0123456789abcdef", now(), Some(4)),
            Err(RecoveryError::EqualVersionConflict { version: 4 })
        ));
        assert!(matches!(
            verifier.verify(&signed, "0123456789abcdef", now(), Some(5)),
            Err(RecoveryError::VersionRollback {
                highest: 5,
                received: 4
            })
        ));
    }

    #[test]
    fn digest_helper_is_canonical_sha256_hex() {
        assert_eq!(
            durable_catalog_digest(b"catalog-observation"),
            "b7eb9e19540e645faf27e2e100634ee95985c13f34b43ae0a050a2b64b7f32a5"
        );
    }
}
