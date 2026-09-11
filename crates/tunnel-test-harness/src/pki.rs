use crate::error::{HarnessError, Result};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fmt;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

/// Role encoded by the issuing CA and the leaf profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum CertificateRole {
    Server,
    Device,
    Peer,
}

impl fmt::Display for CertificateRole {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Server => "server",
            Self::Device => "device",
            Self::Peer => "peer",
        })
    }
}

/// A validity interval used when issuing a fixture certificate.
#[derive(Clone, Copy, Debug)]
pub struct Validity {
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl Validity {
    pub fn for_duration(duration: Duration) -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            not_before: now - Duration::minutes(1),
            not_after: now + duration,
        }
    }

    pub fn one_hour() -> Self {
        Self::for_duration(Duration::hours(1))
    }

    pub fn one_day() -> Self {
        Self::for_duration(Duration::days(1))
    }

    pub fn expired() -> Self {
        let now = OffsetDateTime::now_utc();
        Self {
            not_before: now - Duration::hours(2),
            not_after: now - Duration::minutes(1),
        }
    }

    pub fn is_valid_at(&self, at: OffsetDateTime) -> bool {
        self.not_before <= at && at <= self.not_after
    }
}

/// Certificate material suitable for writing to a temporary process profile.
#[derive(Clone, Debug)]
pub struct CertificateMaterial {
    pub role: CertificateRole,
    pub subject: String,
    pub certificate_pem: String,
    pub private_key_pem: String,
    pub certificate_der: Vec<u8>,
    /// SHA-256 over the certificate DER.  It is a stable fixture identity and
    /// is intentionally exposed separately from the private key.
    pub certificate_fingerprint_sha256: String,
    pub not_before: OffsetDateTime,
    pub not_after: OffsetDateTime,
}

impl CertificateMaterial {
    pub fn is_expired(&self, at: OffsetDateTime) -> bool {
        !Validity {
            not_before: self.not_before,
            not_after: self.not_after,
        }
        .is_valid_at(at)
    }

    pub fn fingerprint_bytes(&self) -> Vec<u8> {
        hex_decode(&self.certificate_fingerprint_sha256).unwrap_or_default()
    }

    /// Lower-case SHA-256 over the DER SubjectPublicKeyInfo used by the
    /// production catalog and transport identity parser.
    pub fn spki_fingerprint_sha256(&self) -> Result<String> {
        tunnel_transport::spki_sha256_from_der(&self.certificate_der)
            .map(|fingerprint| fingerprint.to_hex())
            .map_err(|error| HarnessError::Pki(format!("deriving SPKI fingerprint: {error}")))
    }
}

/// Public CA information.  Private key material remains in the fixture PKI.
#[derive(Clone, Debug)]
pub struct CertificateAuthority {
    pub role: CertificateRole,
    pub name: String,
    pub certificate_pem: String,
    pub certificate_der: Vec<u8>,
    pub fingerprint_sha256: String,
}

struct IssuingAuthority {
    public: CertificateAuthority,
    certificate: Certificate,
    key_pair: KeyPair,
}

/// Parameters for a leaf certificate.  The role controls EKU and issuer.
#[derive(Clone, Debug)]
pub struct CertificateProfile {
    pub role: CertificateRole,
    pub subject: String,
    pub dns_names: Vec<String>,
    /// URI role marker consumed by the transport identity parser.
    pub uri_san: Option<String>,
    pub validity: Validity,
}

impl CertificateProfile {
    pub fn server(subject: impl Into<String>) -> Self {
        Self {
            role: CertificateRole::Server,
            subject: subject.into(),
            dns_names: vec!["localhost".to_owned()],
            uri_san: None,
            validity: Validity::one_day(),
        }
    }

    pub fn device(tenant_id: Uuid, device_id: Uuid) -> Self {
        Self {
            role: CertificateRole::Device,
            subject: format!("device/{tenant_id}/{device_id}"),
            dns_names: Vec::new(),
            uri_san: Some(format!("urn:agent-tunnel:device:{device_id}")),
            validity: Validity::one_day(),
        }
    }

    pub fn peer(node_id: impl Into<String>) -> Self {
        let node_id = node_id.into();
        Self {
            role: CertificateRole::Peer,
            subject: format!("peer/{node_id}"),
            dns_names: vec!["localhost".to_owned()],
            uri_san: Some(format!("urn:agent-tunnel:peer:{node_id}")),
            validity: Validity::one_day(),
        }
    }
}

/// Three isolated roots and helpers for valid and deliberately invalid leaves.
pub struct FixturePki {
    pub server_ca: CertificateAuthority,
    pub device_ca: CertificateAuthority,
    pub peer_ca: CertificateAuthority,
    server_issuer: IssuingAuthority,
    device_issuer: IssuingAuthority,
    peer_issuer: IssuingAuthority,
}

impl fmt::Debug for FixturePki {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FixturePki")
            .field("server_ca", &self.server_ca)
            .field("device_ca", &self.device_ca)
            .field("peer_ca", &self.peer_ca)
            .finish_non_exhaustive()
    }
}

impl FixturePki {
    pub fn new() -> Result<Self> {
        let server_issuer =
            create_authority(CertificateRole::Server, "Agent Tunnel fixture server CA")?;
        let device_issuer =
            create_authority(CertificateRole::Device, "Agent Tunnel fixture device CA")?;
        let peer_issuer = create_authority(CertificateRole::Peer, "Agent Tunnel fixture peer CA")?;
        Ok(Self {
            server_ca: server_issuer.public.clone(),
            device_ca: device_issuer.public.clone(),
            peer_ca: peer_issuer.public.clone(),
            server_issuer,
            device_issuer,
            peer_issuer,
        })
    }

    pub fn issue(&self, profile: CertificateProfile) -> Result<CertificateMaterial> {
        let issuer = match profile.role {
            CertificateRole::Server => &self.server_issuer,
            CertificateRole::Device => &self.device_issuer,
            CertificateRole::Peer => &self.peer_issuer,
        };
        issue_leaf(profile, issuer)
    }

    pub fn issue_server(&self, subject: impl Into<String>) -> Result<CertificateMaterial> {
        self.issue(CertificateProfile::server(subject))
    }

    pub fn issue_device(&self, tenant_id: Uuid, device_id: Uuid) -> Result<CertificateMaterial> {
        self.issue(CertificateProfile::device(tenant_id, device_id))
    }

    pub fn issue_peer(&self, node_id: impl Into<String>) -> Result<CertificateMaterial> {
        self.issue(CertificateProfile::peer(node_id))
    }

    pub fn issue_expired_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<CertificateMaterial> {
        let mut profile = CertificateProfile::device(tenant_id, device_id);
        profile.validity = Validity::expired();
        self.issue(profile)
    }

    /// A peer-signed leaf presented on a device socket.  The certificate is
    /// otherwise well-formed and trusted by the device CA, so this exercises
    /// role-marker validation after the TLS trust check rather than merely
    /// malformed PEM handling.
    pub fn issue_wrong_role_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<CertificateMaterial> {
        let mut profile = CertificateProfile::device(tenant_id, device_id);
        profile.uri_san = Some(format!("urn:agent-tunnel:peer:wrong-device-{device_id}"));
        issue_leaf(profile, &self.device_issuer)
    }

    /// A device-EKU leaf issued by the peer CA.  This is useful when an
    /// acceptance test must prove CA separation before role parsing.
    pub fn issue_device_signed_by_peer_ca(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<CertificateMaterial> {
        let profile = CertificateProfile::device(tenant_id, device_id);
        issue_leaf(profile, &self.peer_issuer)
    }

    /// A device-EKU leaf with no device/peer URI role marker.  TLS can still
    /// authenticate the certificate, but transport identity extraction must
    /// reject it as an incomplete role identity.
    pub fn issue_missing_role_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
    ) -> Result<CertificateMaterial> {
        let mut profile = CertificateProfile::device(tenant_id, device_id);
        profile.uri_san = None;
        issue_leaf(profile, &self.device_issuer)
    }

    pub fn issue_mismatched_device(
        &self,
        tenant_id: Uuid,
        different_device_id: Uuid,
    ) -> Result<CertificateMaterial> {
        self.issue_device(tenant_id, different_device_id)
    }
}

impl Default for FixturePki {
    fn default() -> Self {
        Self::new().expect("fixture PKI generation must succeed")
    }
}

fn create_authority(role: CertificateRole, common_name: &str) -> Result<IssuingAuthority> {
    let key_pair = KeyPair::generate().map_err(|error| HarnessError::Pki(error.to_string()))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let certificate = params
        .self_signed(&key_pair)
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let der = certificate.der().to_vec();
    Ok(IssuingAuthority {
        public: CertificateAuthority {
            role,
            name: common_name.to_owned(),
            certificate_pem: certificate.pem(),
            certificate_der: der.clone(),
            fingerprint_sha256: digest_hex(&der),
        },
        certificate,
        key_pair,
    })
}

fn issue_leaf(
    profile: CertificateProfile,
    issuer: &IssuingAuthority,
) -> Result<CertificateMaterial> {
    let key_pair = KeyPair::generate().map_err(|error| HarnessError::Pki(error.to_string()))?;
    let mut params = if profile.dns_names.is_empty() {
        CertificateParams::default()
    } else {
        CertificateParams::new(profile.dns_names.clone())
            .map_err(|error| HarnessError::Pki(error.to_string()))?
    };
    params
        .distinguished_name
        .push(DnType::CommonName, profile.subject.clone());
    if let Some(uri) = &profile.uri_san {
        let uri = uri
            .clone()
            .try_into()
            .map_err(|error| HarnessError::Pki(format!("invalid URI SAN: {error}")))?;
        params.subject_alt_names.push(SanType::URI(uri));
    }
    params.not_before = profile.validity.not_before;
    params.not_after = profile.validity.not_after;
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = match profile.role {
        CertificateRole::Server => vec![ExtendedKeyUsagePurpose::ServerAuth],
        CertificateRole::Device => vec![ExtendedKeyUsagePurpose::ClientAuth],
        CertificateRole::Peer => vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ],
    };
    let certificate = params
        .signed_by(&key_pair, &issuer.certificate, &issuer.key_pair)
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let der = certificate.der().to_vec();
    Ok(CertificateMaterial {
        role: profile.role,
        subject: profile.subject,
        certificate_pem: certificate.pem(),
        private_key_pem: key_pair.serialize_pem(),
        certificate_der: der.clone(),
        certificate_fingerprint_sha256: digest_hex(&der),
        not_before: profile.validity.not_before,
        not_after: profile.validity.not_after,
    })
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}
