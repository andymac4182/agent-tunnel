//! Signed relay membership and bootstrap checkpoint policy.
//!
//! This module is deliberately a pure policy boundary.  It does not read
//! Redis, open sockets, or read local checkpoint files.  A relay is given a
//! signed record and an explicit clock value and receives either a bounded,
//! verified value or a typed failure.  The publisher helper is kept separate
//! from [`MembershipVerifier`]; normal relay configuration must contain only
//! trusted public keys, never a membership-signing private key.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chrono::{DateTime, Duration, Utc};
use ring::signature::{self, KeyPair, UnparsedPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The only relay role admitted by the first cluster profile.
pub const RELAY_PEER_ROLE: &str = "relay_peer";
/// The schema understood by this module.
pub const MEMBERSHIP_SCHEMA_VERSION: u16 = 1;
/// A signed membership or checkpoint cannot exceed this encoded size.
pub const MAX_SIGNED_RECORD_BYTES: usize = 16 * 1024;
/// Compatibility name for the signed record bound.
pub const MAX_RECORD_BYTES: usize = MAX_SIGNED_RECORD_BYTES;
/// A deployment cannot authorize more than this many relay nodes.
pub const MAX_AUTHORIZED_NODES: usize = 32;
/// Compatibility name for the deployment node bound.
pub const MAX_NODES: usize = MAX_AUTHORIZED_NODES;
/// A node may publish a current and a next peer certificate key.
pub const MAX_KEYS_PER_NODE: usize = 2;
/// Compatibility name for the per-node key bound.
pub const MAX_KEYS: usize = MAX_KEYS_PER_NODE;
/// The maximum validity period of signed membership/checkpoint records.
pub const MAX_RECORD_LIFETIME: Duration = Duration::seconds(60);
/// The maximum clock skew accepted by this policy.
pub const MAX_CLOCK_SKEW: Duration = Duration::seconds(1);
const MAX_IDENTIFIER_BYTES: usize = 128;
const MAX_SERVER_NAME_BYTES: usize = 255;
const MAX_ENDPOINT_BYTES: usize = 255;
const MAX_NONCE_BYTES: usize = 128;
const MIN_NONCE_BYTES: usize = 16;
const SPKI_DIGEST_HEX_BYTES: usize = 64;

/// A trusted membership publisher public key.
///
/// The corresponding private key belongs in the publisher process or its
/// secret store.  It is intentionally not part of [`MembershipPolicy`] or
/// [`MembershipVerifier`] construction.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrustedPublisherKey {
    pub key_id: String,
    pub public_key: [u8; 32],
}

impl TrustedPublisherKey {
    /// Construct a trusted public key after checking its bounded identifier.
    pub fn new(key_id: impl Into<String>, public_key: [u8; 32]) -> Result<Self, MembershipError> {
        let key_id = key_id.into();
        validate_identifier("publisher key id", &key_id)?;
        Ok(Self { key_id, public_key })
    }
}

/// Private endpoint constraints for the signed `peer_endpoint` field.
///
/// An empty `allowed_hosts` set means that the endpoint must be a private IP
/// literal.  For deployments using private DNS, use [`Self::allowlisted`]
/// with the exact names provisioned by the operator.  The endpoint is still
/// checked as `host:port` and is never interpreted as a caller-selected URL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrivateEndpointPolicy {
    /// Exact lower-case host names or IP literals accepted by the policy.
    pub allowed_hosts: BTreeSet<String>,
    /// Exact certificate server names accepted for those endpoints.
    pub allowed_server_names: BTreeSet<String>,
    /// Ports accepted by the private listener policy.
    pub allowed_ports: BTreeSet<u16>,
    /// Require an IP literal in the absence of an explicit host allowlist.
    pub require_private_ip: bool,
}

impl PrivateEndpointPolicy {
    /// A policy for private IP literals on the documented HTTP/3 port.
    pub fn private_ip_only() -> Self {
        Self {
            allowed_hosts: BTreeSet::new(),
            allowed_server_names: BTreeSet::new(),
            allowed_ports: BTreeSet::from([8443]),
            require_private_ip: true,
        }
    }

    /// An operator-provisioned private DNS/IP allowlist.
    pub fn allowlisted<I, J, K>(
        hosts: I,
        server_names: J,
        ports: K,
    ) -> Result<Self, MembershipError>
    where
        I: IntoIterator,
        I::Item: Into<String>,
        J: IntoIterator,
        J::Item: Into<String>,
        K: IntoIterator<Item = u16>,
    {
        let allowed_hosts = normalize_set("endpoint host", hosts)?;
        let allowed_server_names = normalize_set("server name", server_names)?;
        let allowed_ports: BTreeSet<u16> = ports.into_iter().filter(|port| *port != 0).collect();
        if allowed_hosts.is_empty() || allowed_ports.is_empty() {
            return Err(MembershipError::InvalidPolicy(
                "private endpoint policy requires a host and port allowlist".into(),
            ));
        }
        if allowed_hosts.len() > MAX_AUTHORIZED_NODES
            || allowed_server_names.len() > MAX_AUTHORIZED_NODES
            || allowed_ports.len() > MAX_AUTHORIZED_NODES
        {
            return Err(MembershipError::InvalidPolicy(
                "private endpoint policy allowlists are too large".into(),
            ));
        }
        Ok(Self {
            allowed_hosts,
            allowed_server_names,
            allowed_ports,
            require_private_ip: false,
        })
    }

    fn validate(&self) -> Result<(), MembershipError> {
        if self.allowed_ports.is_empty() || self.allowed_ports.contains(&0) {
            return Err(MembershipError::InvalidPolicy(
                "private endpoint policy must allow at least one nonzero port".into(),
            ));
        }
        if self.allowed_hosts.len() > MAX_AUTHORIZED_NODES
            || self.allowed_server_names.len() > MAX_AUTHORIZED_NODES
            || self.allowed_ports.len() > MAX_AUTHORIZED_NODES
        {
            return Err(MembershipError::InvalidPolicy(
                "private endpoint policy allowlists are too large".into(),
            ));
        }
        for host in &self.allowed_hosts {
            validate_host(host)?;
            if host != &host.to_ascii_lowercase() {
                return Err(MembershipError::InvalidPolicy(
                    "endpoint hosts must be lower-case".into(),
                ));
            }
        }
        for name in &self.allowed_server_names {
            validate_server_name(name)?;
            if name != &name.to_ascii_lowercase() {
                return Err(MembershipError::InvalidPolicy(
                    "server names must be lower-case".into(),
                ));
            }
        }
        if self.allowed_hosts.is_empty() && !self.require_private_ip {
            return Err(MembershipError::InvalidPolicy(
                "an endpoint policy without hosts must require private IP literals".into(),
            ));
        }
        Ok(())
    }

    fn validate_endpoint(&self, endpoint: &str, server_name: &str) -> Result<(), MembershipError> {
        if endpoint.len() > MAX_ENDPOINT_BYTES {
            return Err(MembershipError::EndpointNotAllowed(
                "peer endpoint exceeds the bounded length".into(),
            ));
        }
        let (host, port) = parse_endpoint(endpoint)?;
        let lower_host = host.to_ascii_lowercase();
        if !self.allowed_ports.contains(&port) {
            return Err(MembershipError::EndpointNotAllowed(
                "peer endpoint port is not allowed".into(),
            ));
        }
        if self.allowed_hosts.is_empty() {
            let ip = lower_host.parse::<IpAddr>().map_err(|_| {
                MembershipError::EndpointNotAllowed(
                    "private IP-only endpoint policy requires an IP literal".into(),
                )
            })?;
            if !is_private_ip(ip) {
                return Err(MembershipError::EndpointNotAllowed(
                    "peer endpoint is not in a private address range".into(),
                ));
            }
        } else if !self.allowed_hosts.contains(&lower_host) {
            return Err(MembershipError::EndpointNotAllowed(
                "peer endpoint host is not allowlisted".into(),
            ));
        }

        validate_server_name(server_name)?;
        let lower_server_name = server_name.to_ascii_lowercase();
        if !self.allowed_server_names.is_empty() {
            if !self.allowed_server_names.contains(&lower_server_name) {
                return Err(MembershipError::EndpointNotAllowed(
                    "peer server name is not allowlisted".into(),
                ));
            }
        } else if lower_server_name != lower_host {
            return Err(MembershipError::EndpointNotAllowed(
                "server name must match endpoint host unless explicitly allowlisted".into(),
            ));
        }
        Ok(())
    }
}

/// Verifier configuration supplied by the operator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MembershipPolicy {
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub endpoint_policy: PrivateEndpointPolicy,
    /// A deployment may choose a stricter bound, but never a looser one.
    pub max_record_lifetime: Duration,
    /// A deployment may choose a stricter bound, but never a looser one.
    pub max_clock_skew: Duration,
}

impl MembershipPolicy {
    pub fn new(
        deployment_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
        endpoint_policy: PrivateEndpointPolicy,
    ) -> Result<Self, MembershipError> {
        let policy = Self {
            deployment_id: deployment_id.into(),
            deployment_incarnation: deployment_incarnation.into(),
            endpoint_policy,
            max_record_lifetime: MAX_RECORD_LIFETIME,
            max_clock_skew: MAX_CLOCK_SKEW,
        };
        policy.validate()
    }

    pub fn validate(&self) -> Result<Self, MembershipError> {
        validate_identifier("deployment id", &self.deployment_id)?;
        validate_identifier("deployment incarnation", &self.deployment_incarnation)?;
        if self.max_record_lifetime <= Duration::zero()
            || self.max_record_lifetime > MAX_RECORD_LIFETIME
        {
            return Err(MembershipError::InvalidPolicy(
                "record lifetime must be in 1..=60 seconds".into(),
            ));
        }
        if self.max_clock_skew < Duration::zero() || self.max_clock_skew > MAX_CLOCK_SKEW {
            return Err(MembershipError::InvalidPolicy(
                "clock skew must be in 0..=1 second".into(),
            ));
        }
        self.endpoint_policy.validate()?;
        Ok(self.clone())
    }
}

/// One certificate public-key digest authorized for a relay node.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayKey {
    pub key_id: String,
    /// Lower-case hexadecimal SHA-256 digest of the certificate SPKI.
    pub spki_sha256: String,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Unsigned membership payload.  The publisher signs the canonical JSON
/// encoding of this value together with `publisher_key_id`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipRecord {
    pub schema_version: u16,
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub node_id: String,
    pub record_version: u64,
    pub roles: Vec<String>,
    pub peer_endpoint: String,
    pub server_name: String,
    pub keys: Vec<RelayKey>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Top-level signed membership wire record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMembershipRecord {
    pub schema_version: u16,
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub node_id: String,
    pub record_version: u64,
    pub roles: Vec<String>,
    pub peer_endpoint: String,
    pub server_name: String,
    pub keys: Vec<RelayKey>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub publisher_key_id: String,
    pub signature: String,
}

impl SignedMembershipRecord {
    pub fn from_parts(
        record: MembershipRecord,
        publisher_key_id: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: record.schema_version,
            deployment_id: record.deployment_id,
            deployment_incarnation: record.deployment_incarnation,
            node_id: record.node_id,
            record_version: record.record_version,
            roles: record.roles,
            peer_endpoint: record.peer_endpoint,
            server_name: record.server_name,
            keys: record.keys,
            issued_at: record.issued_at,
            not_before: record.not_before,
            expires_at: record.expires_at,
            publisher_key_id: publisher_key_id.into(),
            signature: signature.into(),
        }
    }

    pub fn record(&self) -> MembershipRecord {
        MembershipRecord {
            schema_version: self.schema_version,
            deployment_id: self.deployment_id.clone(),
            deployment_incarnation: self.deployment_incarnation.clone(),
            node_id: self.node_id.clone(),
            record_version: self.record_version,
            roles: self.roles.clone(),
            peer_endpoint: self.peer_endpoint.clone(),
            server_name: self.server_name.clone(),
            keys: self.keys.clone(),
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, MembershipError> {
        serde_json::to_vec(self).map_err(|error| MembershipError::Serialization(error.to_string()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, MembershipError> {
        let body = MembershipSigningBody {
            schema_version: self.schema_version,
            deployment_id: &self.deployment_id,
            deployment_incarnation: &self.deployment_incarnation,
            node_id: &self.node_id,
            record_version: self.record_version,
            roles: &self.roles,
            peer_endpoint: &self.peer_endpoint,
            server_name: &self.server_name,
            keys: &self.keys,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            publisher_key_id: &self.publisher_key_id,
        };
        serde_json::to_vec(&body).map_err(|error| MembershipError::Serialization(error.to_string()))
    }
}

/// Unsigned checkpoint payload containing the nonce-bound minimum versions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipCheckpoint {
    pub schema_version: u16,
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub checkpoint_version: u64,
    pub nonce: String,
    pub minimum_versions: BTreeMap<String, u64>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// Top-level signed checkpoint wire record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedMembershipCheckpoint {
    pub schema_version: u16,
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub checkpoint_version: u64,
    pub nonce: String,
    pub minimum_versions: BTreeMap<String, u64>,
    pub issued_at: DateTime<Utc>,
    pub not_before: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub publisher_key_id: String,
    pub signature: String,
}

impl SignedMembershipCheckpoint {
    pub fn from_parts(
        checkpoint: MembershipCheckpoint,
        publisher_key_id: impl Into<String>,
        signature: impl Into<String>,
    ) -> Self {
        Self {
            schema_version: checkpoint.schema_version,
            deployment_id: checkpoint.deployment_id,
            deployment_incarnation: checkpoint.deployment_incarnation,
            checkpoint_version: checkpoint.checkpoint_version,
            nonce: checkpoint.nonce,
            minimum_versions: checkpoint.minimum_versions,
            issued_at: checkpoint.issued_at,
            not_before: checkpoint.not_before,
            expires_at: checkpoint.expires_at,
            publisher_key_id: publisher_key_id.into(),
            signature: signature.into(),
        }
    }

    pub fn checkpoint(&self) -> MembershipCheckpoint {
        MembershipCheckpoint {
            schema_version: self.schema_version,
            deployment_id: self.deployment_id.clone(),
            deployment_incarnation: self.deployment_incarnation.clone(),
            checkpoint_version: self.checkpoint_version,
            nonce: self.nonce.clone(),
            minimum_versions: self.minimum_versions.clone(),
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>, MembershipError> {
        serde_json::to_vec(self).map_err(|error| MembershipError::Serialization(error.to_string()))
    }

    fn signing_bytes(&self) -> Result<Vec<u8>, MembershipError> {
        let body = CheckpointSigningBody {
            schema_version: self.schema_version,
            deployment_id: &self.deployment_id,
            deployment_incarnation: &self.deployment_incarnation,
            checkpoint_version: self.checkpoint_version,
            nonce: &self.nonce,
            minimum_versions: &self.minimum_versions,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expires_at: self.expires_at,
            publisher_key_id: &self.publisher_key_id,
        };
        serde_json::to_vec(&body).map_err(|error| MembershipError::Serialization(error.to_string()))
    }
}

/// A verified membership record retained by the verifier.
///
/// The evidence is intentionally opaque: callers can inspect bounded facts
/// through accessors, but cannot fabricate a value that the verifier has not
/// accepted or mutate one after it has been bound to a version/signature.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedMembership {
    record: MembershipRecord,
    publisher_key_id: String,
    signed_bytes: Vec<u8>,
}

impl VerifiedMembership {
    #[must_use]
    pub fn record(&self) -> &MembershipRecord {
        &self.record
    }

    #[must_use]
    pub fn publisher_key_id(&self) -> &str {
        &self.publisher_key_id
    }

    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }

    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.record.node_id
    }

    #[must_use]
    pub fn peer_endpoint(&self) -> &str {
        &self.record.peer_endpoint
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.record.server_name
    }

    #[must_use]
    pub fn keys(&self) -> &[RelayKey] {
        &self.record.keys
    }

    /// Select the latest non-revoked key active at an explicit wall-clock
    /// instant.  The caller still verifies the presented certificate SPKI
    /// against this key's digest at the TLS boundary.
    #[must_use]
    pub fn active_key(&self, now: DateTime<Utc>) -> Option<&RelayKey> {
        self.record
            .keys
            .iter()
            .rev()
            .find(|key| !key.revoked && key.not_before <= now && key.expires_at >= now)
    }

    /// Bind authenticated transport facts to this signed node record.
    ///
    /// `boot_id` and `presented_spki_sha256` must come from the completed
    /// peer mTLS handshake.  This method only performs the membership-side
    /// comparison and returns opaque evidence for the transport/envelope
    /// adapter; it does not construct an HTTP header identity or accept a
    /// caller-provided identity by itself.
    pub fn bind_peer(
        &self,
        node_id: &str,
        boot_id: &str,
        presented_spki_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPeerBinding, MembershipError> {
        validate_identifier("node id", node_id)?;
        validate_identifier("boot id", boot_id)?;
        if node_id != self.record.node_id {
            return Err(MembershipError::PeerNodeMismatch);
        }
        if presented_spki_sha256.len() != SPKI_DIGEST_HEX_BYTES
            || !presented_spki_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(MembershipError::PeerKeyMismatch);
        }
        if now < self.record.not_before || now >= self.record.expires_at {
            return Err(if now < self.record.not_before {
                MembershipError::NotYetValid
            } else {
                MembershipError::Expired
            });
        }
        let key = self
            .record
            .keys
            .iter()
            .find(|key| {
                !key.revoked
                    && key.not_before <= now
                    && key.expires_at >= now
                    && key.spki_sha256 == presented_spki_sha256
            })
            .ok_or(MembershipError::PeerKeyMismatch)?;
        Ok(VerifiedPeerBinding {
            node_id: self.record.node_id.clone(),
            boot_id: boot_id.to_owned(),
            key_id: key.key_id.clone(),
            spki_sha256: key.spki_sha256.clone(),
            peer_endpoint: self.record.peer_endpoint.clone(),
            server_name: self.record.server_name.clone(),
            valid_until: if self.record.expires_at < key.expires_at {
                self.record.expires_at
            } else {
                key.expires_at
            },
        })
    }
}

/// Opaque peer binding produced only after a verified membership record is
/// matched to completed mTLS evidence.  The transport adapter may pass this
/// to its envelope layer; there is no public constructor from strings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedPeerBinding {
    node_id: String,
    boot_id: String,
    key_id: String,
    spki_sha256: String,
    peer_endpoint: String,
    server_name: String,
    valid_until: DateTime<Utc>,
}

impl VerifiedPeerBinding {
    #[must_use]
    pub fn node_id(&self) -> &str {
        &self.node_id
    }

    #[must_use]
    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    #[must_use]
    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    #[must_use]
    pub fn spki_sha256(&self) -> &str {
        &self.spki_sha256
    }

    #[must_use]
    pub fn peer_endpoint(&self) -> &str {
        &self.peer_endpoint
    }

    #[must_use]
    pub fn server_name(&self) -> &str {
        &self.server_name
    }

    /// The earliest signed membership or leaf-key expiry.  The verifier
    /// variant also intersects this with checkpoint expiry; callers must
    /// still apply their local five-second cache cap and explicit clock.
    #[must_use]
    pub fn valid_until(&self) -> DateTime<Utc> {
        self.valid_until
    }
}

/// A verified, fresh, nonce-bound checkpoint retained by the verifier.
///
/// Like [`VerifiedMembership`], this evidence is immutable and cannot be
/// constructed by a peer or deserialized from an unverified payload.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedCheckpoint {
    checkpoint: MembershipCheckpoint,
    publisher_key_id: String,
    signed_bytes: Vec<u8>,
}

impl VerifiedCheckpoint {
    #[must_use]
    pub fn checkpoint(&self) -> &MembershipCheckpoint {
        &self.checkpoint
    }

    #[must_use]
    pub fn publisher_key_id(&self) -> &str {
        &self.publisher_key_id
    }

    #[must_use]
    pub fn signed_bytes(&self) -> &[u8] {
        &self.signed_bytes
    }
}

/// Version-only state suitable for persistence by the caller.
///
/// This value is intentionally data-only.  Persisting it is the caller's
/// responsibility; this module performs no filesystem I/O.  A restored
/// version without its signed bytes fences equal-version records until a
/// strictly higher version is received.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MembershipVersionState {
    pub checkpoint_version: Option<u64>,
    pub node_versions: BTreeMap<String, u64>,
}

/// Bounded, pure verifier state for signed records and checkpoints.
#[derive(Clone)]
pub struct MembershipVerifier {
    policy: MembershipPolicy,
    publisher_keys: BTreeMap<String, [u8; 32]>,
    highest_memberships: BTreeMap<String, RetainedMembership>,
    highest_checkpoint: Option<RetainedCheckpoint>,
    last_checkpoint_nonce: Option<String>,
}

#[derive(Clone)]
struct RetainedMembership {
    version: u64,
    signed_bytes: Option<Vec<u8>>,
    verified: Option<VerifiedMembership>,
}

#[derive(Clone)]
struct RetainedCheckpoint {
    version: u64,
    signed_bytes: Option<Vec<u8>>,
    verified: Option<VerifiedCheckpoint>,
}

impl MembershipVerifier {
    /// Build a verifier from operator-installed public publisher keys.
    pub fn new(
        policy: MembershipPolicy,
        publisher_keys: impl IntoIterator<Item = TrustedPublisherKey>,
    ) -> Result<Self, MembershipError> {
        let policy = policy.validate()?;
        let mut keys = BTreeMap::new();
        for trusted in publisher_keys {
            validate_identifier("publisher key id", &trusted.key_id)?;
            if keys
                .insert(trusted.key_id.clone(), trusted.public_key)
                .is_some()
            {
                return Err(MembershipError::DuplicatePublisherKey(trusted.key_id));
            }
        }
        if keys.is_empty() || keys.len() > MAX_AUTHORIZED_NODES {
            return Err(MembershipError::InvalidPolicy(
                "at least one and at most 32 publisher keys are required".into(),
            ));
        }
        Ok(Self {
            policy,
            publisher_keys: keys,
            highest_memberships: BTreeMap::new(),
            highest_checkpoint: None,
            last_checkpoint_nonce: None,
        })
    }

    pub fn policy(&self) -> &MembershipPolicy {
        &self.policy
    }

    /// Verify and retain a nonce-bound checkpoint.
    pub fn verify_checkpoint(
        &mut self,
        bytes: &[u8],
        expected_nonce: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedCheckpoint, MembershipError> {
        let signed = decode_checkpoint(bytes)?;
        let checkpoint = signed.checkpoint();
        validate_checkpoint_shape(
            &checkpoint,
            &self.policy,
            expected_nonce,
            now,
            self.policy.max_record_lifetime,
            self.policy.max_clock_skew,
        )?;
        let canonical = signed.encode()?;
        if canonical != bytes {
            return Err(MembershipError::NonCanonicalEncoding);
        }
        verify_signature(
            &self.publisher_keys,
            &signed.publisher_key_id,
            &signed.signing_bytes()?,
            &signed.signature,
        )?;

        if self.last_checkpoint_nonce.as_deref() == Some(expected_nonce) {
            return Err(MembershipError::CheckpointReplay);
        }
        if let Some(previous) = &self.highest_checkpoint {
            if checkpoint.checkpoint_version < previous.version {
                return Err(MembershipError::CheckpointVersionRollback {
                    highest: previous.version,
                    received: checkpoint.checkpoint_version,
                });
            }
            if checkpoint.checkpoint_version == previous.version {
                if previous.signed_bytes.as_deref() == Some(bytes) {
                    return Err(MembershipError::CheckpointReplay);
                }
                return Err(MembershipError::CheckpointEqualVersionConflict {
                    version: checkpoint.checkpoint_version,
                });
            }
        }

        let verified = VerifiedCheckpoint {
            checkpoint,
            publisher_key_id: signed.publisher_key_id,
            signed_bytes: bytes.to_vec(),
        };
        self.highest_checkpoint = Some(RetainedCheckpoint {
            version: verified.checkpoint.checkpoint_version,
            signed_bytes: Some(bytes.to_vec()),
            verified: Some(verified.clone()),
        });
        self.last_checkpoint_nonce = Some(expected_nonce.to_owned());
        Ok(verified)
    }

    /// Verify and retain one signed membership record.
    pub fn verify_membership(
        &mut self,
        bytes: &[u8],
        now: DateTime<Utc>,
    ) -> Result<VerifiedMembership, MembershipError> {
        let checkpoint = self.fresh_checkpoint(now)?;
        let signed = decode_membership(bytes)?;
        let record = signed.record();
        validate_membership_shape(
            &record,
            &self.policy,
            now,
            self.policy.max_record_lifetime,
            self.policy.max_clock_skew,
        )?;
        let minimum = checkpoint
            .checkpoint
            .minimum_versions
            .get(&record.node_id)
            .copied()
            .ok_or_else(|| MembershipError::NodeNotInCheckpoint(record.node_id.clone()))?;
        if record.record_version < minimum {
            return Err(MembershipError::VersionBelowCheckpoint {
                node_id: record.node_id,
                minimum,
                received: record.record_version,
            });
        }
        let canonical = signed.encode()?;
        if canonical != bytes {
            return Err(MembershipError::NonCanonicalEncoding);
        }
        verify_signature(
            &self.publisher_keys,
            &signed.publisher_key_id,
            &signed.signing_bytes()?,
            &signed.signature,
        )?;

        if let Some(previous) = self.highest_memberships.get(&record.node_id) {
            if record.record_version < previous.version {
                return Err(MembershipError::VersionRollback {
                    node_id: record.node_id,
                    highest: previous.version,
                    received: record.record_version,
                });
            }
            if record.record_version == previous.version {
                if previous.signed_bytes.as_deref() == Some(bytes) {
                    return previous.verified.clone().ok_or(
                        MembershipError::EqualVersionConflict {
                            node_id: record.node_id,
                            version: record.record_version,
                        },
                    );
                }
                return Err(MembershipError::EqualVersionConflict {
                    node_id: record.node_id,
                    version: record.record_version,
                });
            }
        } else if self.highest_memberships.len() >= MAX_AUTHORIZED_NODES {
            return Err(MembershipError::NodeLimit {
                max: MAX_AUTHORIZED_NODES,
            });
        }

        let verified = VerifiedMembership {
            record,
            publisher_key_id: signed.publisher_key_id,
            signed_bytes: bytes.to_vec(),
        };
        self.highest_memberships.insert(
            verified.record.node_id.clone(),
            RetainedMembership {
                version: verified.record.record_version,
                signed_bytes: Some(bytes.to_vec()),
                verified: Some(verified.clone()),
            },
        );
        Ok(verified)
    }

    /// Re-check that the bootstrap checkpoint remains fresh.
    pub fn fresh_checkpoint(
        &self,
        now: DateTime<Utc>,
    ) -> Result<&VerifiedCheckpoint, MembershipError> {
        let retained = self
            .highest_checkpoint
            .as_ref()
            .ok_or(MembershipError::CheckpointRequired)?;
        let checkpoint = retained
            .verified
            .as_ref()
            .ok_or(MembershipError::CheckpointRequired)?;
        validate_window(
            checkpoint.checkpoint.issued_at,
            checkpoint.checkpoint.not_before,
            checkpoint.checkpoint.expires_at,
            now,
            self.policy.max_record_lifetime,
            self.policy.max_clock_skew,
        )?;
        Ok(checkpoint)
    }

    /// Match completed peer mTLS facts against the retained, current node
    /// authority and return opaque envelope/transport evidence.
    pub fn bind_peer(
        &self,
        node_id: &str,
        boot_id: &str,
        presented_spki_sha256: &str,
        now: DateTime<Utc>,
    ) -> Result<VerifiedPeerBinding, MembershipError> {
        validate_identifier("node id", node_id)?;
        let checkpoint = self.fresh_checkpoint(now)?;
        let minimum = checkpoint
            .checkpoint
            .minimum_versions
            .get(node_id)
            .copied()
            .ok_or_else(|| MembershipError::NodeNotInCheckpoint(node_id.to_owned()))?;
        let retained = self
            .highest_memberships
            .get(node_id)
            .ok_or_else(|| MembershipError::NodeNotInCheckpoint(node_id.to_owned()))?;
        let verified = retained
            .verified
            .as_ref()
            .ok_or(MembershipError::CheckpointRequired)?;
        if retained.version < minimum {
            return Err(MembershipError::VersionBelowCheckpoint {
                node_id: node_id.to_owned(),
                minimum,
                received: retained.version,
            });
        }
        validate_membership_shape(
            &verified.record,
            &self.policy,
            now,
            self.policy.max_record_lifetime,
            self.policy.max_clock_skew,
        )?;
        let mut binding = verified.bind_peer(node_id, boot_id, presented_spki_sha256, now)?;
        if checkpoint.checkpoint.expires_at < binding.valid_until {
            binding.valid_until = checkpoint.checkpoint.expires_at;
        }
        Ok(binding)
    }

    /// Return retained highest versions for restricted caller-owned storage.
    pub fn version_state(&self) -> MembershipVersionState {
        MembershipVersionState {
            checkpoint_version: self
                .highest_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.version),
            node_versions: self
                .highest_memberships
                .iter()
                .map(|(node_id, retained)| (node_id.clone(), retained.version))
                .collect(),
        }
    }

    /// Restore version fences after a process restart, without accepting any
    /// record bytes.  Equal versions remain fenced until superseded.
    pub fn restore_version_state(
        &mut self,
        state: MembershipVersionState,
    ) -> Result<(), MembershipError> {
        if state.node_versions.len() > MAX_AUTHORIZED_NODES {
            return Err(MembershipError::NodeLimit {
                max: MAX_AUTHORIZED_NODES,
            });
        }
        for (node_id, version) in state.node_versions {
            validate_identifier("node id", &node_id)?;
            if version == 0 {
                return Err(MembershipError::InvalidVersion);
            }
            match self.highest_memberships.get(&node_id) {
                Some(previous) if previous.version > version => {}
                Some(previous) if previous.version == version => {}
                _ => {
                    if self.highest_memberships.len() >= MAX_AUTHORIZED_NODES
                        && !self.highest_memberships.contains_key(&node_id)
                    {
                        return Err(MembershipError::NodeLimit {
                            max: MAX_AUTHORIZED_NODES,
                        });
                    }
                    self.highest_memberships.insert(
                        node_id,
                        RetainedMembership {
                            version,
                            signed_bytes: None,
                            verified: None,
                        },
                    );
                }
            }
        }
        if let Some(version) = state.checkpoint_version {
            if version == 0 {
                return Err(MembershipError::InvalidVersion);
            }
            match self.highest_checkpoint.as_ref() {
                Some(previous) if previous.version >= version => {}
                _ => {
                    self.highest_checkpoint = Some(RetainedCheckpoint {
                        version,
                        signed_bytes: None,
                        verified: None,
                    });
                }
            }
        }
        Ok(())
    }

    /// Return all retained verified records.  No record is evicted when a
    /// checkpoint removes a node; callers must use checkpoint authorization
    /// before routing and can inspect this bounded set for diagnostics.
    pub fn retained_memberships(&self) -> Vec<VerifiedMembership> {
        self.highest_memberships
            .values()
            .filter_map(|retained| retained.verified.clone())
            .collect()
    }
}

/// A pure signing helper for an external publisher or test fixture.
///
/// Do not place this type in a normal relay configuration.  A relay only
/// needs [`TrustedPublisherKey`] values.  The helper never persists or
/// transmits its private key and performs no I/O.
pub struct MembershipIssuer {
    key_id: String,
    key_pair: signature::Ed25519KeyPair,
}

impl MembershipIssuer {
    /// Load an issuer key from an externally provisioned PKCS#8 document.
    pub fn from_pkcs8(key_id: impl Into<String>, pkcs8: &[u8]) -> Result<Self, MembershipError> {
        let key_id = key_id.into();
        validate_identifier("publisher key id", &key_id)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8)
            .map_err(|_| MembershipError::InvalidIssuerKey)?;
        Ok(Self { key_id, key_pair })
    }

    /// Generate an issuer key for a test fixture or an isolated publisher.
    pub fn generate(key_id: impl Into<String>) -> Result<(Self, Vec<u8>), MembershipError> {
        let key_id = key_id.into();
        validate_identifier("publisher key id", &key_id)?;
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = signature::Ed25519KeyPair::generate_pkcs8(&rng)
            .map_err(|_| MembershipError::InvalidIssuerKey)?;
        let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| MembershipError::InvalidIssuerKey)?;
        Ok((Self { key_id, key_pair }, pkcs8.as_ref().to_vec()))
    }

    pub fn key_id(&self) -> &str {
        &self.key_id
    }

    pub fn public_key(&self) -> Result<[u8; 32], MembershipError> {
        let mut public_key = [0_u8; 32];
        let bytes = self.key_pair.public_key().as_ref();
        if bytes.len() != public_key.len() {
            return Err(MembershipError::InvalidIssuerKey);
        }
        public_key.copy_from_slice(bytes);
        Ok(public_key)
    }

    pub fn sign_membership(
        &self,
        record: MembershipRecord,
    ) -> Result<SignedMembershipRecord, MembershipError> {
        let unsigned =
            SignedMembershipRecord::from_parts(record, self.key_id.clone(), String::new());
        let signature = self.key_pair.sign(&unsigned.signing_bytes()?);
        Ok(SignedMembershipRecord::from_parts(
            unsigned.record(),
            self.key_id.clone(),
            URL_SAFE_NO_PAD.encode(signature.as_ref()),
        ))
    }

    pub fn sign_membership_bytes(
        &self,
        record: MembershipRecord,
    ) -> Result<Vec<u8>, MembershipError> {
        self.sign_membership(record)?.encode()
    }

    pub fn sign_checkpoint(
        &self,
        checkpoint: MembershipCheckpoint,
    ) -> Result<SignedMembershipCheckpoint, MembershipError> {
        let unsigned =
            SignedMembershipCheckpoint::from_parts(checkpoint, self.key_id.clone(), String::new());
        let signature = self.key_pair.sign(&unsigned.signing_bytes()?);
        Ok(SignedMembershipCheckpoint::from_parts(
            unsigned.checkpoint(),
            self.key_id.clone(),
            URL_SAFE_NO_PAD.encode(signature.as_ref()),
        ))
    }

    pub fn sign_checkpoint_bytes(
        &self,
        checkpoint: MembershipCheckpoint,
    ) -> Result<Vec<u8>, MembershipError> {
        self.sign_checkpoint(checkpoint)?.encode()
    }
}

/// SHA-256 digest encoding used in the signed relay key record.
pub fn spki_sha256_hex(spki_der: &[u8]) -> String {
    let digest = Sha256::digest(spki_der);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Compatibility aliases for callers that use the shorter design names.
pub type MembershipKey = RelayKey;
pub type SignedMembership = SignedMembershipRecord;
pub type Checkpoint = MembershipCheckpoint;
pub type SignedCheckpoint = SignedMembershipCheckpoint;

/// Namespace for issuer-only integration and fixture helpers.  Keeping this
/// separate makes it harder for relay wiring to accidentally depend on a
/// signing private key.
pub mod issuer {
    pub use super::MembershipIssuer;
}

#[derive(Serialize)]
struct MembershipSigningBody<'a> {
    schema_version: u16,
    deployment_id: &'a str,
    deployment_incarnation: &'a str,
    node_id: &'a str,
    record_version: u64,
    roles: &'a [String],
    peer_endpoint: &'a str,
    server_name: &'a str,
    keys: &'a [RelayKey],
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    publisher_key_id: &'a str,
}

#[derive(Serialize)]
struct CheckpointSigningBody<'a> {
    schema_version: u16,
    deployment_id: &'a str,
    deployment_incarnation: &'a str,
    checkpoint_version: u64,
    nonce: &'a str,
    minimum_versions: &'a BTreeMap<String, u64>,
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    publisher_key_id: &'a str,
}

fn decode_membership(bytes: &[u8]) -> Result<SignedMembershipRecord, MembershipError> {
    if bytes.len() > MAX_SIGNED_RECORD_BYTES {
        return Err(MembershipError::RecordTooLarge {
            size: bytes.len(),
            max: MAX_SIGNED_RECORD_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| MembershipError::MalformedJson(error.to_string()))
}

fn decode_checkpoint(bytes: &[u8]) -> Result<SignedMembershipCheckpoint, MembershipError> {
    if bytes.len() > MAX_SIGNED_RECORD_BYTES {
        return Err(MembershipError::RecordTooLarge {
            size: bytes.len(),
            max: MAX_SIGNED_RECORD_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| MembershipError::MalformedJson(error.to_string()))
}

fn verify_signature(
    publisher_keys: &BTreeMap<String, [u8; 32]>,
    key_id: &str,
    message: &[u8],
    encoded_signature: &str,
) -> Result<(), MembershipError> {
    validate_identifier("publisher key id", key_id)?;
    let public_key = publisher_keys
        .get(key_id)
        .ok_or_else(|| MembershipError::UnknownPublisherKey(key_id.to_owned()))?;
    let signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .map_err(|_| MembershipError::InvalidSignatureEncoding)?;
    if signature.len() != 64 {
        return Err(MembershipError::InvalidSignatureEncoding);
    }
    if URL_SAFE_NO_PAD.encode(&signature) != encoded_signature {
        return Err(MembershipError::InvalidSignatureEncoding);
    }
    UnparsedPublicKey::new(&signature::ED25519, public_key)
        .verify(message, &signature)
        .map_err(|_| MembershipError::SignatureInvalid)
}

fn validate_membership_shape(
    record: &MembershipRecord,
    policy: &MembershipPolicy,
    now: DateTime<Utc>,
    max_lifetime: Duration,
    max_skew: Duration,
) -> Result<(), MembershipError> {
    if record.schema_version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedSchemaVersion(
            record.schema_version,
        ));
    }
    if record.deployment_id != policy.deployment_id {
        return Err(MembershipError::DeploymentMismatch);
    }
    if record.deployment_incarnation != policy.deployment_incarnation {
        return Err(MembershipError::IncarnationMismatch);
    }
    validate_identifier("node id", &record.node_id)?;
    if record.record_version == 0 {
        return Err(MembershipError::InvalidVersion);
    }
    if record.roles.len() != 1 || record.roles.first().map(String::as_str) != Some(RELAY_PEER_ROLE)
    {
        return Err(MembershipError::RoleNotAllowed);
    }
    policy
        .endpoint_policy
        .validate_endpoint(&record.peer_endpoint, &record.server_name)?;
    validate_window(
        record.issued_at,
        record.not_before,
        record.expires_at,
        now,
        max_lifetime,
        max_skew,
    )?;
    validate_keys(&record.keys, now, max_skew)
}

fn validate_checkpoint_shape(
    checkpoint: &MembershipCheckpoint,
    policy: &MembershipPolicy,
    expected_nonce: &str,
    now: DateTime<Utc>,
    max_lifetime: Duration,
    max_skew: Duration,
) -> Result<(), MembershipError> {
    if checkpoint.schema_version != MEMBERSHIP_SCHEMA_VERSION {
        return Err(MembershipError::UnsupportedSchemaVersion(
            checkpoint.schema_version,
        ));
    }
    if checkpoint.deployment_id != policy.deployment_id {
        return Err(MembershipError::DeploymentMismatch);
    }
    if checkpoint.deployment_incarnation != policy.deployment_incarnation {
        return Err(MembershipError::IncarnationMismatch);
    }
    if checkpoint.checkpoint_version == 0 {
        return Err(MembershipError::InvalidVersion);
    }
    validate_nonce(&checkpoint.nonce)?;
    validate_nonce(expected_nonce)?;
    if checkpoint.nonce != expected_nonce {
        return Err(MembershipError::CheckpointNonceMismatch);
    }
    if checkpoint.minimum_versions.len() > MAX_AUTHORIZED_NODES {
        return Err(MembershipError::NodeLimit {
            max: MAX_AUTHORIZED_NODES,
        });
    }
    for (node_id, minimum) in &checkpoint.minimum_versions {
        validate_identifier("node id", node_id)?;
        if *minimum == 0 {
            return Err(MembershipError::InvalidVersion);
        }
    }
    validate_window(
        checkpoint.issued_at,
        checkpoint.not_before,
        checkpoint.expires_at,
        now,
        max_lifetime,
        max_skew,
    )
}

fn validate_keys(
    keys: &[RelayKey],
    now: DateTime<Utc>,
    skew: Duration,
) -> Result<(), MembershipError> {
    if keys.is_empty() || keys.len() > MAX_KEYS_PER_NODE {
        return Err(MembershipError::KeyCountExceeded {
            max: MAX_KEYS_PER_NODE,
        });
    }
    let mut previous_activation = None;
    let mut previous_key_id = None;
    let mut ids = BTreeSet::new();
    let mut has_current = false;
    for key in keys {
        validate_identifier("relay key id", &key.key_id)?;
        if !ids.insert(key.key_id.clone()) {
            return Err(MembershipError::DuplicateRelayKey(key.key_id.clone()));
        }
        if key.spki_sha256.len() != SPKI_DIGEST_HEX_BYTES
            || !key
                .spki_sha256
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(MembershipError::InvalidSpkiDigest(key.key_id.clone()));
        }
        if key.not_before > key.expires_at {
            return Err(MembershipError::InvalidRelayKeyWindow(key.key_id.clone()));
        }
        if let Some(previous_activation) = previous_activation {
            if key.not_before < previous_activation {
                return Err(MembershipError::RelayKeysUnordered);
            }
            if key.not_before == previous_activation
                && previous_key_id.is_some_and(|previous| key.key_id.as_str() <= previous)
            {
                return Err(MembershipError::RelayKeysUnordered);
            }
        }
        previous_activation = Some(key.not_before);
        previous_key_id = Some(key.key_id.as_str());
        let latest = now
            .checked_add_signed(skew)
            .ok_or(MembershipError::InvalidTime)?;
        let earliest = now
            .checked_sub_signed(skew)
            .ok_or(MembershipError::InvalidTime)?;
        if !key.revoked && key.not_before <= latest && key.expires_at >= earliest {
            has_current = true;
        }
    }
    if !has_current {
        return Err(MembershipError::NoUsableRelayKey);
    }
    Ok(())
}

fn validate_window(
    issued_at: DateTime<Utc>,
    not_before: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    now: DateTime<Utc>,
    max_lifetime: Duration,
    skew: Duration,
) -> Result<(), MembershipError> {
    if issued_at > expires_at || not_before > expires_at {
        return Err(MembershipError::InvalidTimeWindow);
    }
    if expires_at.signed_duration_since(issued_at) > max_lifetime {
        return Err(MembershipError::LifetimeExceeded);
    }
    let latest_issued = now
        .checked_add_signed(skew)
        .ok_or(MembershipError::InvalidTime)?;
    if issued_at > latest_issued {
        return Err(MembershipError::IssuedInFuture);
    }
    let earliest = now
        .checked_sub_signed(skew)
        .ok_or(MembershipError::InvalidTime)?;
    let earliest_not_before = not_before
        .checked_sub_signed(skew)
        .ok_or(MembershipError::InvalidTime)?;
    if now < earliest_not_before {
        return Err(MembershipError::NotYetValid);
    }
    if now > expires_at {
        let latest = expires_at
            .checked_add_signed(skew)
            .ok_or(MembershipError::InvalidTime)?;
        if now > latest {
            return Err(MembershipError::Expired);
        }
    }
    if expires_at < earliest {
        return Err(MembershipError::Expired);
    }
    Ok(())
}

fn validate_nonce(nonce: &str) -> Result<(), MembershipError> {
    if nonce.len() < MIN_NONCE_BYTES || nonce.len() > MAX_NONCE_BYTES {
        return Err(MembershipError::InvalidNonce);
    }
    if !nonce
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
    {
        return Err(MembershipError::InvalidNonce);
    }
    Ok(())
}

fn validate_identifier(label: &str, value: &str) -> Result<(), MembershipError> {
    if value.is_empty()
        || value.len() > MAX_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace())
    {
        return Err(MembershipError::InvalidIdentifier(label.into()));
    }
    Ok(())
}

fn normalize_set<I>(label: &str, values: I) -> Result<BTreeSet<String>, MembershipError>
where
    I: IntoIterator,
    I::Item: Into<String>,
{
    let mut normalized = BTreeSet::new();
    for value in values {
        let value = value.into().to_ascii_lowercase();
        if value.is_empty() {
            return Err(MembershipError::InvalidPolicy(format!(
                "{label} cannot be empty"
            )));
        }
        normalized.insert(value);
    }
    Ok(normalized)
}

fn validate_host(host: &str) -> Result<(), MembershipError> {
    if host.is_empty()
        || host.len() > MAX_SERVER_NAME_BYTES
        || host.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'@' | b'?' | b'#')
        })
    {
        return Err(MembershipError::InvalidPolicy(
            "invalid endpoint host".into(),
        ));
    }
    Ok(())
}

fn validate_server_name(server_name: &str) -> Result<(), MembershipError> {
    if server_name.is_empty()
        || server_name.len() > MAX_SERVER_NAME_BYTES
        || server_name.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'@' | b'?' | b'#' | b':')
        })
    {
        return Err(MembershipError::EndpointNotAllowed(
            "invalid private server name".into(),
        ));
    }
    Ok(())
}

fn parse_endpoint(endpoint: &str) -> Result<(String, u16), MembershipError> {
    if endpoint.is_empty()
        || endpoint.bytes().any(|byte| {
            byte.is_ascii_control()
                || byte.is_ascii_whitespace()
                || matches!(byte, b'/' | b'@' | b'?' | b'#')
        })
    {
        return Err(MembershipError::EndpointNotAllowed(
            "peer endpoint must be a bounded host:port value".into(),
        ));
    }
    let (host, port_text) = if let Some(rest) = endpoint.strip_prefix('[') {
        let end = rest.find(']').ok_or_else(|| {
            MembershipError::EndpointNotAllowed("unterminated IPv6 endpoint".into())
        })?;
        let host = &rest[..end];
        let port = rest
            .get(end + 1..)
            .and_then(|suffix| suffix.strip_prefix(':'))
            .ok_or_else(|| {
                MembershipError::EndpointNotAllowed("IPv6 endpoint must include a port".into())
            })?;
        (host, port)
    } else {
        let (host, port) = endpoint.rsplit_once(':').ok_or_else(|| {
            MembershipError::EndpointNotAllowed("peer endpoint must include a port".into())
        })?;
        if host.contains(':') {
            return Err(MembershipError::EndpointNotAllowed(
                "IPv6 endpoints must use brackets".into(),
            ));
        }
        (host, port)
    };
    validate_host(host)?;
    let port = port_text
        .parse::<u16>()
        .map_err(|_| MembershipError::EndpointNotAllowed("invalid endpoint port".into()))?;
    if port == 0 {
        return Err(MembershipError::EndpointNotAllowed(
            "endpoint port cannot be zero".into(),
        ));
    }
    Ok((host.to_owned(), port))
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => is_private_ipv4(ip),
        IpAddr::V6(ip) => is_private_ipv6(ip),
    }
}

fn is_private_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_loopback() || ip.is_link_local()
}

fn is_private_ipv6(ip: Ipv6Addr) -> bool {
    ip.is_unique_local() || ip.is_loopback() || ip.is_unicast_link_local()
}

/// Errors are intentionally typed so callers can report readiness and
/// rollback/conflict states without exposing signed payloads or credentials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MembershipError {
    InvalidPolicy(String),
    MalformedJson(String),
    Serialization(String),
    RecordTooLarge {
        size: usize,
        max: usize,
    },
    NonCanonicalEncoding,
    UnsupportedSchemaVersion(u16),
    DeploymentMismatch,
    IncarnationMismatch,
    InvalidIdentifier(String),
    InvalidVersion,
    RoleNotAllowed,
    EndpointNotAllowed(String),
    InvalidTime,
    InvalidTimeWindow,
    LifetimeExceeded,
    IssuedInFuture,
    NotYetValid,
    Expired,
    InvalidNonce,
    CheckpointNonceMismatch,
    CheckpointRequired,
    CheckpointReplay,
    CheckpointVersionRollback {
        highest: u64,
        received: u64,
    },
    CheckpointEqualVersionConflict {
        version: u64,
    },
    VersionRollback {
        node_id: String,
        highest: u64,
        received: u64,
    },
    EqualVersionConflict {
        node_id: String,
        version: u64,
    },
    VersionBelowCheckpoint {
        node_id: String,
        minimum: u64,
        received: u64,
    },
    NodeNotInCheckpoint(String),
    NodeLimit {
        max: usize,
    },
    KeyCountExceeded {
        max: usize,
    },
    DuplicateRelayKey(String),
    RelayKeysUnordered,
    InvalidSpkiDigest(String),
    InvalidRelayKeyWindow(String),
    NoUsableRelayKey,
    PeerNodeMismatch,
    PeerKeyMismatch,
    DuplicatePublisherKey(String),
    UnknownPublisherKey(String),
    InvalidSignatureEncoding,
    SignatureInvalid,
    InvalidIssuerKey,
}

impl fmt::Display for MembershipError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidPolicy(message) => {
                write!(formatter, "invalid membership policy: {message}")
            }
            Self::MalformedJson(message) => {
                write!(formatter, "malformed signed membership JSON: {message}")
            }
            Self::Serialization(message) => {
                write!(formatter, "membership serialization failed: {message}")
            }
            Self::RecordTooLarge { size, max } => {
                write!(formatter, "signed record is {size} bytes; maximum is {max}")
            }
            Self::NonCanonicalEncoding => {
                formatter.write_str("signed record is not canonical JSON")
            }
            Self::UnsupportedSchemaVersion(version) => {
                write!(formatter, "unsupported membership schema version {version}")
            }
            Self::DeploymentMismatch => {
                formatter.write_str("membership deployment does not match configured deployment")
            }
            Self::IncarnationMismatch => {
                formatter.write_str("membership incarnation does not match configured incarnation")
            }
            Self::InvalidIdentifier(label) => write!(formatter, "invalid bounded {label}"),
            Self::InvalidVersion => formatter.write_str("membership version must be nonzero"),
            Self::RoleNotAllowed => {
                formatter.write_str("membership does not contain exactly the relay_peer role")
            }
            Self::EndpointNotAllowed(message) => {
                write!(formatter, "private peer endpoint rejected: {message}")
            }
            Self::InvalidTime => {
                formatter.write_str("membership time is outside the representable range")
            }
            Self::InvalidTimeWindow => formatter.write_str("membership time window is invalid"),
            Self::LifetimeExceeded => {
                formatter.write_str("membership validity exceeds the bounded lifetime")
            }
            Self::IssuedInFuture => {
                formatter.write_str("membership was issued too far in the future")
            }
            Self::NotYetValid => formatter.write_str("membership is not yet valid"),
            Self::Expired => formatter.write_str("membership has expired"),
            Self::InvalidNonce => {
                formatter.write_str("checkpoint nonce is invalid or outside its bound")
            }
            Self::CheckpointNonceMismatch => {
                formatter.write_str("checkpoint nonce does not match the fresh challenge")
            }
            Self::CheckpointRequired => formatter
                .write_str("a fresh signed checkpoint is required before membership admission"),
            Self::CheckpointReplay => {
                formatter.write_str("signed checkpoint nonce or version was replayed")
            }
            Self::CheckpointVersionRollback { highest, received } => write!(
                formatter,
                "checkpoint version rollback from {highest} to {received}"
            ),
            Self::CheckpointEqualVersionConflict { version } => write!(
                formatter,
                "conflicting checkpoint contents at version {version}"
            ),
            Self::VersionRollback {
                node_id,
                highest,
                received,
            } => write!(
                formatter,
                "node {node_id} version rollback from {highest} to {received}"
            ),
            Self::EqualVersionConflict { node_id, version } => write!(
                formatter,
                "conflicting node {node_id} contents at version {version}"
            ),
            Self::VersionBelowCheckpoint {
                node_id,
                minimum,
                received,
            } => write!(
                formatter,
                "node {node_id} version {received} is below checkpoint minimum {minimum}"
            ),
            Self::NodeNotInCheckpoint(node_id) => write!(
                formatter,
                "node {node_id} is absent from the signed checkpoint"
            ),
            Self::NodeLimit { max } => write!(formatter, "membership node limit {max} exceeded"),
            Self::KeyCountExceeded { max } => {
                write!(formatter, "membership key count exceeds {max}")
            }
            Self::DuplicateRelayKey(key_id) => write!(formatter, "duplicate relay key {key_id}"),
            Self::RelayKeysUnordered => {
                formatter.write_str("relay keys are not in activation order")
            }
            Self::InvalidSpkiDigest(key_id) => {
                write!(formatter, "relay key {key_id} has an invalid SPKI digest")
            }
            Self::InvalidRelayKeyWindow(key_id) => write!(
                formatter,
                "relay key {key_id} has an invalid validity window"
            ),
            Self::NoUsableRelayKey => {
                formatter.write_str("membership has no current unrevoked relay key")
            }
            Self::PeerNodeMismatch => {
                formatter.write_str("authenticated peer node does not match membership")
            }
            Self::PeerKeyMismatch => {
                formatter.write_str("authenticated peer SPKI is not an active approved key")
            }
            Self::DuplicatePublisherKey(key_id) => {
                write!(formatter, "duplicate trusted publisher key {key_id}")
            }
            Self::UnknownPublisherKey(key_id) => {
                write!(formatter, "unknown membership publisher key {key_id}")
            }
            Self::InvalidSignatureEncoding => {
                formatter.write_str("membership signature is not canonical Ed25519 base64")
            }
            Self::SignatureInvalid => formatter.write_str("membership signature is invalid"),
            Self::InvalidIssuerKey => formatter.write_str("issuer key is not a valid Ed25519 key"),
        }
    }
}

impl std::error::Error for MembershipError {}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        DateTime::parse_from_rfc3339("2026-01-01T00:00:00Z")
            .expect("test timestamp")
            .with_timezone(&Utc)
    }

    fn record(now: DateTime<Utc>, node_id: &str, version: u64) -> MembershipRecord {
        MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: "deployment-a".into(),
            deployment_incarnation: "incarnation-a".into(),
            node_id: node_id.into(),
            record_version: version,
            roles: vec![RELAY_PEER_ROLE.into()],
            peer_endpoint: "10.0.0.1:8443".into(),
            server_name: "10.0.0.1".into(),
            keys: vec![RelayKey {
                key_id: format!("{node_id}-current"),
                spki_sha256: "00".repeat(32),
                not_before: now - Duration::seconds(1),
                expires_at: now + Duration::seconds(59),
                revoked: false,
            }],
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::seconds(60),
        }
    }

    fn checkpoint(now: DateTime<Utc>, version: u64, nonce: &str) -> MembershipCheckpoint {
        MembershipCheckpoint {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: "deployment-a".into(),
            deployment_incarnation: "incarnation-a".into(),
            checkpoint_version: version,
            nonce: nonce.into(),
            minimum_versions: BTreeMap::from([(String::from("node-a"), 1)]),
            issued_at: now,
            not_before: now,
            expires_at: now + Duration::seconds(60),
        }
    }

    fn verifier(issuer: &MembershipIssuer) -> MembershipVerifier {
        let endpoint = PrivateEndpointPolicy::private_ip_only();
        let policy =
            MembershipPolicy::new("deployment-a", "incarnation-a", endpoint).expect("policy");
        MembershipVerifier::new(
            policy,
            [
                TrustedPublisherKey::new(issuer.key_id(), issuer.public_key().expect("key"))
                    .expect("trusted key"),
            ],
        )
        .expect("verifier")
    }

    fn verify_test_checkpoint(
        issuer: &MembershipIssuer,
        verifier: &mut MembershipVerifier,
        now: DateTime<Utc>,
    ) {
        let signed = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&signed, "0123456789abcdef", now)
            .expect("valid checkpoint");
    }

    #[test]
    fn signed_checkpoint_and_membership_verify() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let signed_checkpoint = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint");
        let checkpoint_bytes = signed_checkpoint.encode().expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&checkpoint_bytes, "0123456789abcdef", now)
            .expect("verified checkpoint");
        let signed_membership = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("record");
        let bytes = signed_membership.encode().expect("record bytes");
        verifier
            .verify_membership(&bytes, now)
            .expect("verified record");
    }

    #[test]
    fn forged_and_noncanonical_records_fail() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let checkpoint = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&checkpoint, "0123456789abcdef", now)
            .expect("checkpoint");
        let mut signed = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("record");
        signed.peer_endpoint = "10.0.0.2:8443".into();
        signed.server_name = "10.0.0.2".into();
        let forged = signed.encode().expect("forged bytes");
        assert!(matches!(
            verifier.verify_membership(&forged, now),
            Err(MembershipError::SignatureInvalid)
        ));
        let signed = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("record");
        let canonical = signed.encode().expect("canonical");
        let padded = [b" ".as_slice(), canonical.as_slice(), b" ".as_slice()].concat();
        assert!(matches!(
            verifier.verify_membership(&padded, now),
            Err(MembershipError::NonCanonicalEncoding)
        ));
    }

    #[test]
    fn replay_rollback_and_equal_version_conflict_are_rejected() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let checkpoint = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&checkpoint, "0123456789abcdef", now)
            .expect("checkpoint");
        let first = issuer
            .sign_membership(record(now, "node-a", 2))
            .expect("record")
            .encode()
            .expect("record bytes");
        verifier.verify_membership(&first, now).expect("first");
        assert!(verifier.verify_membership(&first, now).is_ok());
        let mut changed_record = record(now, "node-a", 2);
        changed_record.peer_endpoint = "10.0.0.2:8443".into();
        changed_record.server_name = "10.0.0.2".into();
        let conflicting = issuer
            .sign_membership(changed_record)
            .expect("record")
            .encode()
            .expect("conflicting record bytes");
        assert!(matches!(
            verifier.verify_membership(&conflicting, now),
            Err(MembershipError::EqualVersionConflict { .. })
        ));
        let lower = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("record")
            .encode()
            .expect("record bytes");
        assert!(matches!(
            verifier.verify_membership(&lower, now),
            Err(MembershipError::VersionRollback { .. })
        ));
    }

    #[test]
    fn checkpoint_nonce_and_expiry_are_enforced() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let signed = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        assert!(matches!(
            verifier.verify_checkpoint(&signed, "fedcba9876543210", now),
            Err(MembershipError::CheckpointNonceMismatch)
        ));
        verifier
            .verify_checkpoint(&signed, "0123456789abcdef", now)
            .expect("checkpoint");
        assert!(matches!(
            verifier.verify_checkpoint(&signed, "0123456789abcdef", now),
            Err(MembershipError::CheckpointReplay)
        ));
        assert!(matches!(
            verifier.fresh_checkpoint(now + Duration::seconds(62)),
            Err(MembershipError::Expired)
        ));
    }

    #[test]
    fn current_and_next_key_rotation_is_bounded_and_selectable() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let checkpoint = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&checkpoint, "0123456789abcdef", now)
            .expect("checkpoint");
        let mut rotated = record(now, "node-a", 2);
        rotated.keys.push(RelayKey {
            key_id: "node-a-next".into(),
            spki_sha256: "11".repeat(32),
            not_before: now + Duration::seconds(10),
            expires_at: now + Duration::seconds(600),
            revoked: false,
        });
        let signed = issuer
            .sign_membership(rotated)
            .expect("rotated record")
            .encode()
            .expect("rotated bytes");
        let verified = verifier
            .verify_membership(&signed, now + Duration::seconds(11))
            .expect("rotated membership");
        assert_eq!(
            verified
                .active_key(now + Duration::seconds(11))
                .map(|key| key.key_id.as_str()),
            Some("node-a-next")
        );
        let binding = verified
            .bind_peer(
                "node-a",
                "boot-a",
                &"11".repeat(32),
                now + Duration::seconds(11),
            )
            .expect("peer binding");
        assert_eq!(binding.node_id(), "node-a");
        assert_eq!(binding.boot_id(), "boot-a");
        assert_eq!(binding.key_id(), "node-a-next");
        let verifier_binding = verifier
            .bind_peer(
                "node-a",
                "boot-a",
                &"11".repeat(32),
                now + Duration::seconds(11),
            )
            .expect("verifier peer binding");
        assert_eq!(verifier_binding, binding);
        assert!(matches!(
            verified.bind_peer(
                "node-a",
                "boot-a",
                &"22".repeat(32),
                now + Duration::seconds(11)
            ),
            Err(MembershipError::PeerKeyMismatch)
        ));
    }

    #[test]
    fn valid_signature_with_disallowed_role_is_rejected_before_admission() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        verify_test_checkpoint(&issuer, &mut verifier, now);

        let mut invalid_role = record(now, "node-a", 1);
        invalid_role.roles = vec!["observer".into()];
        let signed = issuer
            .sign_membership(invalid_role)
            .expect("signed role-negative record")
            .encode()
            .expect("role-negative bytes");
        assert!(matches!(
            verifier.verify_membership(&signed, now),
            Err(MembershipError::RoleNotAllowed)
        ));
        assert!(verifier.retained_memberships().is_empty());
    }

    #[test]
    fn valid_signature_with_public_endpoint_is_rejected_before_admission() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        verify_test_checkpoint(&issuer, &mut verifier, now);

        let mut public_endpoint = record(now, "node-a", 1);
        public_endpoint.peer_endpoint = "203.0.113.1:8443".into();
        public_endpoint.server_name = "203.0.113.1".into();
        let signed = issuer
            .sign_membership(public_endpoint)
            .expect("signed endpoint-negative record")
            .encode()
            .expect("endpoint-negative bytes");
        assert!(matches!(
            verifier.verify_membership(&signed, now),
            Err(MembershipError::EndpointNotAllowed(_))
        ));
        assert!(verifier.retained_memberships().is_empty());
    }

    #[test]
    fn valid_membership_rejects_a_different_authenticated_peer_node() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        verify_test_checkpoint(&issuer, &mut verifier, now);
        let signed = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("valid membership")
            .encode()
            .expect("membership bytes");
        let verified = verifier
            .verify_membership(&signed, now)
            .expect("valid membership must be retained");

        assert!(matches!(
            verified.bind_peer("node-b", "boot-b", &"00".repeat(32), now),
            Err(MembershipError::PeerNodeMismatch)
        ));
    }

    #[test]
    fn unknown_fields_are_rejected_before_signature_use() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let checkpoint = issuer
            .sign_checkpoint(checkpoint(now, 1, "0123456789abcdef"))
            .expect("checkpoint")
            .encode()
            .expect("checkpoint bytes");
        verifier
            .verify_checkpoint(&checkpoint, "0123456789abcdef", now)
            .expect("checkpoint");
        let signed = issuer
            .sign_membership(record(now, "node-a", 1))
            .expect("record")
            .encode()
            .expect("record bytes");
        let mut malformed = signed[..signed.len() - 1].to_vec();
        malformed.extend_from_slice(b",\"unexpected\":true}");
        assert!(matches!(
            verifier.verify_membership(&malformed, now),
            Err(MembershipError::MalformedJson(_))
        ));
    }

    #[test]
    fn key_and_node_bounds_are_fail_closed() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        let mut checkpoint = checkpoint(now, 1, "0123456789abcdef");
        checkpoint.minimum_versions.clear();
        for index in 0..=MAX_AUTHORIZED_NODES {
            checkpoint
                .minimum_versions
                .insert(format!("node-{index}"), 1);
        }
        let signed = issuer.sign_checkpoint(checkpoint).expect("checkpoint");
        let bytes = signed.encode().expect("checkpoint bytes");
        assert!(matches!(
            verifier.verify_checkpoint(&bytes, "0123456789abcdef", now),
            Err(MembershipError::NodeLimit { .. })
        ));
    }

    /// Walk one node's signed records through old -> old+new -> new and pin
    /// the exact acceptance at every step.  This is the deterministic
    /// statement of the peer-certificate replacement rule that the configured
    /// two-relay process gate exercises over real sockets: the replacement
    /// key binds only from the record that approves it, both keys bind during
    /// the overlap, the retired key stops binding as soon as the replacement
    /// record drops it, and an unapproved key never binds at any version.
    #[test]
    fn peer_key_replacement_walks_old_then_overlap_then_new() {
        let (issuer, _) = MembershipIssuer::generate("publisher-a").expect("issuer");
        let mut verifier = verifier(&issuer);
        let now = now();
        verify_test_checkpoint(&issuer, &mut verifier, now);
        let old_spki = "00".repeat(32);
        let new_spki = "11".repeat(32);
        let rogue_spki = "22".repeat(32);
        let key = |key_id: &str, spki: &str| RelayKey {
            key_id: key_id.into(),
            spki_sha256: spki.into(),
            not_before: now - Duration::seconds(1),
            expires_at: now + Duration::seconds(59),
            revoked: false,
        };
        let signed_at = |record: MembershipRecord| {
            issuer
                .sign_membership(record)
                .expect("record")
                .encode()
                .expect("record bytes")
        };

        // Version 2 approves the old key only.  The record fixture already
        // carries exactly that key.
        let old_only = signed_at(record(now, "node-a", 2));
        let verified = verifier
            .verify_membership(&old_only, now)
            .expect("old-only record");
        assert_eq!(
            verified
                .bind_peer("node-a", "boot-a", &old_spki, now)
                .expect("old key binds")
                .key_id(),
            "node-a-current"
        );
        assert!(matches!(
            verified.bind_peer("node-a", "boot-a", &new_spki, now),
            Err(MembershipError::PeerKeyMismatch)
        ));

        // Version 3 is the overlap: both keys are approved simultaneously.
        let mut overlap = record(now, "node-a", 3);
        overlap.keys = vec![
            key("node-a-current", &old_spki),
            key("node-a-replacement", &new_spki),
        ];
        let overlap = signed_at(overlap);
        let verified = verifier
            .verify_membership(&overlap, now)
            .expect("overlap record");
        assert_eq!(verified.keys().len(), 2);
        assert_eq!(
            verified
                .bind_peer("node-a", "boot-a", &old_spki, now)
                .expect("old key still binds during the overlap")
                .key_id(),
            "node-a-current"
        );
        assert_eq!(
            verified
                .bind_peer("node-a", "boot-a", &new_spki, now)
                .expect("replacement key binds during the overlap")
                .key_id(),
            "node-a-replacement"
        );
        // `active_key` deliberately selects the latest valid key, which is
        // the replacement: an overlap never keeps the retired key preferred.
        assert_eq!(
            verified.active_key(now).map(|key| key.key_id.as_str()),
            Some("node-a-replacement")
        );
        assert!(matches!(
            verified.bind_peer("node-a", "boot-a", &rogue_spki, now),
            Err(MembershipError::PeerKeyMismatch)
        ));

        // Version 4 ends the overlap by approving the replacement alone.
        let mut replacement = record(now, "node-a", 4);
        replacement.keys = vec![key("node-a-replacement", &new_spki)];
        let replacement = signed_at(replacement);
        let verified = verifier
            .verify_membership(&replacement, now)
            .expect("replacement record");
        assert_eq!(
            verified
                .bind_peer("node-a", "boot-a", &new_spki, now)
                .expect("replacement key binds after the overlap")
                .key_id(),
            "node-a-replacement"
        );
        for retired in [&old_spki, &rogue_spki] {
            assert!(matches!(
                verified.bind_peer("node-a", "boot-a", retired, now),
                Err(MembershipError::PeerKeyMismatch)
            ));
        }
        // The verifier's retained state for this node follows the newest
        // accepted record, so the retired key stops binding there too.
        assert!(matches!(
            verifier.bind_peer("node-a", "boot-a", &old_spki, now),
            Err(MembershipError::PeerKeyMismatch)
        ));
        assert_eq!(
            verifier
                .bind_peer("node-a", "boot-a", &new_spki, now)
                .expect("verifier binds the replacement key")
                .key_id(),
            "node-a-replacement"
        );
        // A rollback to the overlap record cannot re-approve the retired key.
        assert!(matches!(
            verifier.verify_membership(&overlap, now),
            Err(MembershipError::VersionRollback { .. })
        ));
        assert!(matches!(
            verifier.bind_peer("node-a", "boot-a", &old_spki, now),
            Err(MembershipError::PeerKeyMismatch)
        ));
    }
}
