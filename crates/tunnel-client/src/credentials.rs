//! Local device credential provisioning and mTLS material loading.
//!
//! The client never issues certificates.  `create_csr` generates a private
//! key locally and writes a CSR for an external issuer; `import_certificate`
//! accepts only a certificate whose public key matches that pending key and a
//! separately supplied server CA bundle.

use crate::config::{CredentialConfig, RuntimeConfig};
#[cfg(unix)]
use rcgen::{CertificateParams, DnType, KeyPair};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use rustls::sign::CertifiedKey;
use rustls_pemfile::{certs, private_key};
use std::{
    error::Error,
    fmt,
    fs::{self, File},
    io::{self, BufReader},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::{
    fs::OpenOptions,
    io::{Read, Write},
};
use tunnel_transport::{CertificateRole, TlsIdentityError, leaf_identity_from_der};

/// Result of creating a local key and CSR.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CsrOutput {
    pub key_path: PathBuf,
    pub csr_path: PathBuf,
}

/// Result of importing a matching certificate chain and CA bundle.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ImportedCredential {
    pub certificate_path: PathBuf,
    pub server_ca_path: PathBuf,
    pub certificate_count: usize,
    pub ca_certificate_count: usize,
}

/// Generate a local ECDSA key and a PEM CSR without overwriting files.
#[cfg(unix)]
pub fn create_csr(
    config: &RuntimeConfig,
    csr_path: impl AsRef<Path>,
) -> Result<CsrOutput, CredentialError> {
    let csr_path = csr_path.as_ref().to_owned();
    let key_path = config.credentials.client_key.clone();
    if key_path.exists() {
        return Err(CredentialError::AlreadyExists(key_path));
    }
    if csr_path.exists() {
        return Err(CredentialError::AlreadyExists(csr_path));
    }
    ensure_parent(&key_path, true)?;
    ensure_parent(&csr_path, false)?;

    let key_pair =
        KeyPair::generate().map_err(|error| CredentialError::Provision(error.to_string()))?;
    let mut params = CertificateParams::default();
    params
        .distinguished_name
        .push(DnType::CommonName, format!("device/{}", config.device_id));
    let csr = params
        .serialize_request(&key_pair)
        .map_err(|error| CredentialError::Provision(error.to_string()))?;
    let csr_pem = csr
        .pem()
        .map_err(|error| CredentialError::Provision(error.to_string()))?;

    // Write the key first with create_new.  If the second write fails, the
    // key is deliberately left as a pending credential and can be retried
    // without silently replacing it.
    write_new(&key_path, key_pair.serialize_pem().as_bytes(), true)?;
    write_new(&csr_path, csr_pem.as_bytes(), false)?;
    Ok(CsrOutput { key_path, csr_path })
}

/// Validate and import an externally issued certificate and server trust
/// bundle.  Destination files are never overwritten by this operation.
#[cfg(unix)]
pub fn import_certificate(
    config: &RuntimeConfig,
    certificate_source: impl AsRef<Path>,
    server_ca_source: impl AsRef<Path>,
) -> Result<ImportedCredential, CredentialError> {
    let certificate_source = certificate_source.as_ref();
    let server_ca_source = server_ca_source.as_ref();
    let key = load_private_key(&config.credentials.client_key)?;
    let certificate_chain = load_certificates(certificate_source)?;
    if certificate_chain.is_empty() {
        return Err(CredentialError::NoCertificates(
            certificate_source.to_owned(),
        ));
    }
    // Every refusal below is classified before any file is installed, so an
    // operator is told which of the certificate's properties is wrong rather
    // than one catch-all "key mismatch" (task row M6-C25).
    verify_certificate_key(&certificate_chain, key)?;
    verify_device_role(&certificate_chain[0], &config.device_id)?;

    let ca_chain = load_certificates(server_ca_source)?;
    if ca_chain.is_empty() {
        return Err(CredentialError::NoCertificates(server_ca_source.to_owned()));
    }

    if certificate_source != config.credentials.client_certificate {
        ensure_parent(&config.credentials.client_certificate, false)?;
        copy_new(
            certificate_source,
            &config.credentials.client_certificate,
            false,
        )?;
    }
    if server_ca_source != config.credentials.server_ca {
        ensure_parent(&config.credentials.server_ca, false)?;
        copy_new(server_ca_source, &config.credentials.server_ca, false)?;
    }
    Ok(ImportedCredential {
        certificate_path: config.credentials.client_certificate.clone(),
        server_ca_path: config.credentials.server_ca.clone(),
        certificate_count: certificate_chain.len(),
        ca_certificate_count: ca_chain.len(),
    })
}

/// Check that a client certificate chain is usable with `key`, classifying
/// each refusal separately (task row M6-C25).
///
/// In order: the end-entity certificate must parse as X.509, must be version
/// 3 (the relay's verifier refuses v1 and v2, and only v3 can carry the
/// device role SAN), the private key must be one the TLS provider can sign
/// with, and the certificate's public key must be the key's own.  Only the
/// last of these is reported as [`CredentialError::KeyMismatch`]; before
/// M6-C25 every refusal was, including a v1 certificate whose key matched.
pub fn verify_certificate_key(
    chain: &[CertificateDer<'static>],
    key: PrivateKeyDer<'static>,
) -> Result<(), CredentialError> {
    let leaf = chain.first().ok_or_else(|| {
        CredentialError::CertificateUnparseable("the chain has no end-entity certificate".into())
    })?;
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| CredentialError::CertificateUnparseable(error.to_string()))?;
    let version = parsed.version();
    if version != x509_parser::x509::X509Version::V3 {
        return Err(CredentialError::UnsupportedCertificateVersion(
            version.0.saturating_add(1),
        ));
    }
    let provider = rustls::crypto::ring::default_provider();
    let signing_key = provider
        .key_provider
        .load_private_key(key)
        .map_err(|error| CredentialError::UnsupportedPrivateKey(error.to_string()))?;
    // The same comparison `CertifiedKey::from_der` makes, taken apart so a
    // certificate the TLS stack refuses is not reported as a key mismatch.
    // As there, a key that cannot report its public half is not a refusal.
    match CertifiedKey::new(chain.to_vec(), signing_key).keys_match() {
        Ok(()) | Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::Unknown)) => Ok(()),
        Err(rustls::Error::InconsistentKeys(rustls::InconsistentKeys::KeyMismatch)) => Err(
            CredentialError::KeyMismatch("the certificate's public key is not this key's".into()),
        ),
        Err(error) => Err(CredentialError::CertificateRefused(error.to_string())),
    }
}

/// Check that the end-entity certificate names `device_id` in its device role
/// URI SAN, which the relay requires of every device session: it refuses a
/// HELLO whose `connector_id` differs from the SAN's identifier.
pub fn verify_device_role(
    leaf: &CertificateDer<'_>,
    device_id: &str,
) -> Result<(), CredentialError> {
    let identity = leaf_identity_from_der(leaf.as_ref()).map_err(|error| match error {
        TlsIdentityError::Certificate(detail) => CredentialError::CertificateUnparseable(detail),
        other => CredentialError::MissingDeviceRole(other.to_string()),
    })?;
    match identity.role() {
        CertificateRole::Device { id } if id == device_id => Ok(()),
        CertificateRole::Device { id } => Err(CredentialError::DeviceIdMismatch {
            certificate: id.clone(),
            configured: device_id.to_owned(),
        }),
        CertificateRole::Peer { .. } => Err(CredentialError::MissingDeviceRole(
            "the certificate carries a relay peer role, not a device role".into(),
        )),
    }
}

/// Local key creation is disabled until this platform has an owner-only ACL implementation.
#[cfg(not(unix))]
pub fn create_csr(
    _config: &RuntimeConfig,
    _csr_path: impl AsRef<Path>,
) -> Result<CsrOutput, CredentialError> {
    Err(CredentialError::UnsupportedPlatform(
        "credential creation requires an owner-only filesystem ACL on this platform",
    ))
}

/// Local credential import is disabled until this platform has an owner-only ACL implementation.
#[cfg(not(unix))]
pub fn import_certificate(
    _config: &RuntimeConfig,
    _certificate_source: impl AsRef<Path>,
    _server_ca_source: impl AsRef<Path>,
) -> Result<ImportedCredential, CredentialError> {
    Err(CredentialError::UnsupportedPlatform(
        "credential import requires an owner-only filesystem ACL on this platform",
    ))
}

/// Build a rustls client configuration from local PEM files.
///
/// This helper is intentionally public for integration harnesses.  Every
/// caller receives the same strict profile: TLS 1.3 only, server certificate
/// and DNS verification enabled, client certificate required, no session
/// resumption and no early data.
pub fn load_client_config(
    credentials: &CredentialConfig,
) -> Result<std::sync::Arc<rustls::ClientConfig>, CredentialError> {
    let certificate_pem = fs::read(&credentials.client_certificate).map_err(CredentialError::Io)?;
    let private_key_pem = fs::read(&credentials.client_key).map_err(CredentialError::Io)?;
    let server_ca_pem = fs::read(&credentials.server_ca).map_err(CredentialError::Io)?;
    tunnel_transport::load_client_config_from_pem_with_alpn(
        &certificate_pem,
        &private_key_pem,
        &server_ca_pem,
        &[b"http/1.1"],
    )
    .map_err(|error| CredentialError::Tls(error.to_string()))
}

/// Read certificates from a PEM file, retaining owned DER bytes.
pub fn load_certificates(
    path: impl AsRef<Path>,
) -> Result<Vec<CertificateDer<'static>>, CredentialError> {
    let file = File::open(path.as_ref()).map_err(CredentialError::Io)?;
    certs(&mut BufReader::new(file))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| CredentialError::InvalidPem(error.to_string()))
}

/// Read one supported PKCS#8/RSA/SEC1 private key from PEM.
pub fn load_private_key(path: impl AsRef<Path>) -> Result<PrivateKeyDer<'static>, CredentialError> {
    let file = File::open(path.as_ref()).map_err(CredentialError::Io)?;
    private_key(&mut BufReader::new(file))
        .map_err(|error| CredentialError::InvalidPem(error.to_string()))?
        .ok_or_else(|| CredentialError::NoPrivateKey(path.as_ref().to_owned()))
}

#[cfg(unix)]
fn ensure_parent(path: &Path, private: bool) -> Result<(), CredentialError> {
    match path.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => {
            fs::create_dir_all(parent).map_err(CredentialError::Io)?;
            if private {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                        .map_err(CredentialError::Io)?;
                }
                #[cfg(not(unix))]
                {
                    return Err(CredentialError::UnsupportedPlatform(
                        "private credential storage requires owner-only filesystem ACLs",
                    ));
                }
            }
            Ok(())
        }
        _ => Ok(()),
    }
}

#[cfg(unix)]
fn write_new(path: &Path, bytes: &[u8], private: bool) -> Result<(), CredentialError> {
    #[cfg(not(unix))]
    if private {
        return Err(CredentialError::UnsupportedPlatform(
            "private credential storage requires owner-only filesystem ACLs",
        ));
    }

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    if private {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path).map_err(|error| {
        if error.kind() == io::ErrorKind::AlreadyExists {
            CredentialError::AlreadyExists(path.to_owned())
        } else {
            CredentialError::Io(error)
        }
    })?;
    file.write_all(bytes).map_err(CredentialError::Io)?;
    file.sync_all().map_err(CredentialError::Io)
}

#[cfg(unix)]
fn copy_new(source: &Path, destination: &Path, private: bool) -> Result<(), CredentialError> {
    let mut bytes = Vec::new();
    File::open(source)
        .map_err(CredentialError::Io)?
        .read_to_end(&mut bytes)
        .map_err(CredentialError::Io)?;
    write_new(destination, &bytes, private)
}

/// Errors returned by credential parsing/provisioning.
#[derive(Debug)]
pub enum CredentialError {
    Io(io::Error),
    InvalidPem(String),
    NoCertificates(PathBuf),
    NoPrivateKey(PathBuf),
    AlreadyExists(PathBuf),
    /// The certificate's public key is not the configured private key's.
    KeyMismatch(String),
    /// The end-entity certificate is not parseable X.509 DER.
    CertificateUnparseable(String),
    /// The end-entity certificate is X.509 v1 or v2; the value is the
    /// version number as written (1, 2), not the encoded field.
    UnsupportedCertificateVersion(u32),
    /// The TLS provider cannot sign with the private key.
    UnsupportedPrivateKey(String),
    /// The TLS stack refused the certificate for a reason other than those
    /// above; the detail is the provider's.
    CertificateRefused(String),
    /// The certificate has no usable `urn:agent-tunnel:device:<id>` URI SAN.
    MissingDeviceRole(String),
    /// The certificate's device role SAN names another device than the
    /// profile's `device_id`.
    DeviceIdMismatch {
        certificate: String,
        configured: String,
    },
    /// The relay authenticated the TLS connection and then refused the
    /// device session: the profile's `device_id` does not name the
    /// certificate's device, or the catalog has no active device and
    /// credential for this certificate's key (task row M6-C32).  Terminal:
    /// no retry of the same configuration and catalog can succeed.
    RelayRefusedIdentity,
    Tls(String),
    Provision(String),
    UnsupportedPlatform(&'static str),
    InsecurePermissions(PathBuf),
}

impl fmt::Display for CredentialError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(error) => write!(formatter, "credential file I/O failed: {error}"),
            Self::InvalidPem(error) => write!(formatter, "invalid PEM credential: {error}"),
            Self::NoCertificates(path) => {
                write!(formatter, "no certificates found in {}", path.display())
            }
            Self::NoPrivateKey(path) => {
                write!(formatter, "no private key found in {}", path.display())
            }
            Self::AlreadyExists(path) => {
                write!(formatter, "refusing to overwrite {}", path.display())
            }
            Self::KeyMismatch(error) => write!(
                formatter,
                "client certificate does not match its private key: {error}"
            ),
            Self::CertificateUnparseable(error) => write!(
                formatter,
                "client certificate is not a parseable X.509 certificate: {error}"
            ),
            Self::UnsupportedCertificateVersion(version) => write!(
                formatter,
                "client certificate is X.509 v{version}; the relay accepts only v3 \
                 certificates, which carry the device role SAN (ask the issuer to sign \
                 with extensions, for example `openssl x509 -req -extfile`)"
            ),
            Self::UnsupportedPrivateKey(error) => write!(
                formatter,
                "the private key is not a supported signing key: {error}"
            ),
            Self::CertificateRefused(error) => write!(
                formatter,
                "client certificate was refused by the TLS stack: {error}"
            ),
            Self::MissingDeviceRole(error) => write!(
                formatter,
                "client certificate has no device role URI SAN \
                 urn:agent-tunnel:device:<device_id>: {error}"
            ),
            Self::DeviceIdMismatch {
                certificate,
                configured,
            } => write!(
                formatter,
                "client certificate names device {certificate} in its role SAN but the \
                 profile's device_id is {configured}; the relay refuses a device unless \
                 they are equal"
            ),
            Self::RelayRefusedIdentity => formatter.write_str(
                "the relay refused this device's identity: check that device_id equals the \
                 certificate's urn:agent-tunnel:device SAN and that the catalog holds an \
                 active device and credential for this certificate; retrying will not help",
            ),
            Self::Tls(error) => write!(
                formatter,
                "could not build strict TLS configuration: {error}"
            ),
            Self::Provision(error) => {
                write!(formatter, "could not create credential request: {error}")
            }
            Self::UnsupportedPlatform(message) => formatter.write_str(message),
            Self::InsecurePermissions(path) => write!(
                formatter,
                "credential directory permissions are not owner-only: {}",
                path.display()
            ),
        }
    }
}

impl Error for CredentialError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Io(error) => Some(error),
            _ => None,
        }
    }
}

impl From<CredentialError> for io::Error {
    fn from(error: CredentialError) -> Self {
        io::Error::new(io::ErrorKind::InvalidData, error.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::ExportConfig;
    use tempfile::tempdir;

    #[test]
    #[cfg(unix)]
    fn csr_creation_is_non_overwriting_and_local() {
        let dir = tempdir().expect("temporary directory");
        let mut config = RuntimeConfig::default();
        config.credentials.client_key = dir.path().join("device-key.pem");
        let csr_path = dir.path().join("device.csr.pem");
        let output = create_csr(&config, &csr_path).expect("create CSR");
        assert_eq!(output.key_path, config.credentials.client_key);
        assert!(csr_path.exists());
        assert!(create_csr(&config, &csr_path).is_err());
    }

    #[test]
    #[cfg(not(unix))]
    fn provisioning_is_rejected_without_creating_files() {
        let dir = tempdir().expect("temporary directory");
        let config = RuntimeConfig::default();
        assert!(matches!(
            create_csr(&config, dir.path().join("device.csr")),
            Err(CredentialError::UnsupportedPlatform(_))
        ));
        assert!(matches!(
            import_certificate(
                &config,
                dir.path().join("cert.pem"),
                dir.path().join("ca.pem")
            ),
            Err(CredentialError::UnsupportedPlatform(_))
        ));
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
    }

    /// Test-time certificate material for the M6-C25 cases.  Everything is
    /// generated per test; no key or certificate is committed.
    #[cfg(unix)]
    mod material {
        use rcgen::{CertificateParams, DnType, KeyPair, SanType};

        pub(super) const DEVICE: &str = "33333333-3333-4333-8333-333333333333";

        /// A v3 certificate for `key`, self-signed, carrying `sans`.
        pub(super) fn v3_pem(key: &KeyPair, sans: Vec<SanType>) -> String {
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, format!("device/{DEVICE}"));
            params.subject_alt_names = sans;
            params.self_signed(key).expect("v3 certificate").pem()
        }

        pub(super) fn device_san(id: &str) -> SanType {
            SanType::URI(
                format!("urn:agent-tunnel:device:{id}")
                    .try_into()
                    .expect("URI SAN"),
            )
        }

        /// A genuine X.509 **v1** certificate for `key`: the TBSCertificate
        /// of an rcgen certificate with its `[0]` version and `[3]`
        /// extensions removed (which is exactly what v1 is), re-signed with
        /// the same P-256 key so the signature is valid.  This is the shape
        /// macOS's LibreSSL `openssl x509 -req` issues without an extensions
        /// file, which is how the m6-02 worker met the defect.
        pub(super) fn v1_pem(key: &KeyPair) -> String {
            let v3 = CertificateParams::default()
                .self_signed(key)
                .expect("template certificate");
            let (outer, _) = tlv(v3.der(), 0);
            let (tbs, after_tbs) = tlv(outer, 0);
            let (_, algorithm_end) = tlv(outer, after_tbs);
            let signature_algorithm = &outer[after_tbs..algorithm_end];
            let mut children = Vec::new();
            let mut at = 0;
            while at < tbs.len() {
                let tag = tbs[at];
                let (_, end) = tlv(tbs, at);
                if tag != 0xa0 && tag != 0xa3 {
                    children.extend_from_slice(&tbs[at..end]);
                }
                at = end;
            }
            let tbs_v1 = der(0x30, &children);
            let rng = ring::rand::SystemRandom::new();
            let signer = ring::signature::EcdsaKeyPair::from_pkcs8(
                &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                &key.serialize_der(),
                &rng,
            )
            .expect("P-256 signer");
            let signature = signer.sign(&rng, &tbs_v1).expect("sign TBS");
            let mut bit_string = vec![0];
            bit_string.extend_from_slice(signature.as_ref());
            let mut body = tbs_v1;
            body.extend_from_slice(signature_algorithm);
            body.extend_from_slice(&der(0x03, &bit_string));
            pem(&der(0x30, &body))
        }

        /// Return the content of the DER element at `at` and the offset just
        /// past it.  Test-only, for well-formed rcgen output.
        fn tlv(bytes: &[u8], at: usize) -> (&[u8], usize) {
            let first = bytes[at + 1];
            let (length, header) = if first < 0x80 {
                (usize::from(first), 2)
            } else {
                let count = usize::from(first & 0x7f);
                let length = bytes[at + 2..at + 2 + count]
                    .iter()
                    .fold(0usize, |value, byte| (value << 8) | usize::from(*byte));
                (length, 2 + count)
            };
            let start = at + header;
            (&bytes[start..start + length], start + length)
        }

        fn der(tag: u8, content: &[u8]) -> Vec<u8> {
            let mut out = vec![tag];
            let length = content.len();
            if length < 0x80 {
                out.push(u8::try_from(length).expect("short length"));
            } else {
                let bytes: Vec<u8> = length
                    .to_be_bytes()
                    .into_iter()
                    .skip_while(|byte| *byte == 0)
                    .collect();
                out.push(0x80 | u8::try_from(bytes.len()).expect("length of length"));
                out.extend_from_slice(&bytes);
            }
            out.extend_from_slice(content);
            out
        }

        pub(super) fn pem(der: &[u8]) -> String {
            const ALPHABET: &[u8; 64] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let mut encoded = String::new();
            for chunk in der.chunks(3) {
                let block = [
                    chunk[0],
                    chunk.get(1).copied().unwrap_or(0),
                    chunk.get(2).copied().unwrap_or(0),
                ];
                let value =
                    (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
                for index in 0..4 {
                    if index <= chunk.len() {
                        let sextet = (value >> (18 - 6 * index)) & 0x3f;
                        encoded.push(char::from(ALPHABET[sextet as usize]));
                    } else {
                        encoded.push('=');
                    }
                }
            }
            let mut out = String::from("-----BEGIN CERTIFICATE-----\n");
            for line in encoded.as_bytes().chunks(64) {
                out.push_str(std::str::from_utf8(line).expect("ASCII"));
                out.push('\n');
            }
            out.push_str("-----END CERTIFICATE-----\n");
            out
        }
    }

    /// One import attempt of `certificate_pem` against a pending `key`.
    #[cfg(unix)]
    fn import_with(
        key: &rcgen::KeyPair,
        certificate_pem: &str,
    ) -> (
        Result<ImportedCredential, CredentialError>,
        tempfile::TempDir,
    ) {
        let dir = tempdir().expect("temporary directory");
        let mut config = RuntimeConfig {
            device_id: material::DEVICE.to_owned(),
            ..RuntimeConfig::default()
        };
        config.credentials.client_key = dir.path().join("device-key.pem");
        config.credentials.client_certificate = dir.path().join("installed-cert.pem");
        config.credentials.server_ca = dir.path().join("installed-ca.pem");
        fs::write(&config.credentials.client_key, key.serialize_pem()).expect("pending key");
        let source = dir.path().join("issued.pem");
        fs::write(&source, certificate_pem).expect("issued certificate");
        let ca_key = rcgen::KeyPair::generate().expect("CA key");
        let ca = dir.path().join("ca.pem");
        fs::write(&ca, material::v3_pem(&ca_key, Vec::new())).expect("CA bundle");
        (import_certificate(&config, &source, &ca), dir)
    }

    /// M6-C25: a v1 certificate whose key **matches** is refused as a v1
    /// certificate.  Before the fix it was refused as a key mismatch.
    #[test]
    #[cfg(unix)]
    fn a_v1_certificate_is_refused_for_its_version_not_as_a_key_mismatch() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let v1 = material::v1_pem(&key);
        // The fixture must really be v1 with this key, or the test proves
        // nothing: check both with the same parser the product uses.
        let chain = load_certificates_from(&v1);
        let (_, parsed) = x509_parser::parse_x509_certificate(chain[0].as_ref()).expect("parses");
        assert_eq!(parsed.version(), x509_parser::x509::X509Version::V1);
        assert_eq!(parsed.public_key().raw, key.public_key_der().as_slice());

        let (result, dir) = import_with(&key, &v1);
        let error = result.expect_err("a v1 certificate must be refused");
        assert!(
            matches!(error, CredentialError::UnsupportedCertificateVersion(1)),
            "a matching v1 certificate was classified as {error:?}"
        );
        let message = error.to_string();
        assert!(message.contains("X.509 v1"), "{message}");
        assert!(!message.contains("does not match"), "{message}");
        assert!(!dir.path().join("installed-cert.pem").exists());
    }

    #[test]
    #[cfg(unix)]
    fn a_genuine_key_mismatch_is_still_reported_as_one() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let other = rcgen::KeyPair::generate().expect("other key");
        let certificate = material::v3_pem(&other, vec![material::device_san(material::DEVICE)]);
        let (result, _dir) = import_with(&key, &certificate);
        assert!(
            matches!(result, Err(CredentialError::KeyMismatch(_))),
            "{result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn an_unparseable_certificate_is_not_a_key_mismatch() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let garbage = material::pem(b"\x30\x03\x02\x01\x00not a certificate");
        let (result, _dir) = import_with(&key, &garbage);
        assert!(
            matches!(result, Err(CredentialError::CertificateUnparseable(_))),
            "{result:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_certificate_without_the_device_role_san_is_refused_on_import() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem(&key, Vec::new());
        let (result, _dir) = import_with(&key, &certificate);
        let error = result.expect_err("no device SAN");
        assert!(
            matches!(error, CredentialError::MissingDeviceRole(_)),
            "{error:?}"
        );
        assert!(error.to_string().contains("urn:agent-tunnel:device:"));
    }

    #[test]
    #[cfg(unix)]
    fn a_certificate_naming_another_device_is_refused_on_import() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let other = "44444444-4444-4444-8444-444444444444";
        let certificate = material::v3_pem(&key, vec![material::device_san(other)]);
        let (result, _dir) = import_with(&key, &certificate);
        let error = result.expect_err("SAN names another device");
        assert!(
            matches!(
                &error,
                CredentialError::DeviceIdMismatch { certificate, configured }
                    if certificate == other && configured == material::DEVICE
            ),
            "{error:?}"
        );
    }

    #[test]
    #[cfg(unix)]
    fn a_matching_v3_device_certificate_imports() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem(&key, vec![material::device_san(material::DEVICE)]);
        let (result, dir) = import_with(&key, &certificate);
        let imported = result.expect("a matching certificate imports");
        assert_eq!(imported.certificate_count, 1);
        assert!(dir.path().join("installed-cert.pem").exists());
    }

    #[cfg(unix)]
    fn load_certificates_from(pem: &str) -> Vec<CertificateDer<'static>> {
        certs(&mut pem.as_bytes())
            .collect::<Result<Vec<_>, _>>()
            .expect("PEM certificates")
    }

    #[test]
    fn client_config_rejects_missing_material() {
        let dir = tempdir().expect("temporary directory");
        let credentials = CredentialConfig {
            client_certificate: dir.path().join("missing-cert.pem"),
            client_key: dir.path().join("missing-key.pem"),
            server_ca: dir.path().join("missing-ca.pem"),
        };
        assert!(load_client_config(&credentials).is_err());
    }

    #[test]
    fn default_runtime_profile_has_only_echo() {
        let config = RuntimeConfig::default();
        assert!(matches!(
            config.exports.get("echo"),
            Some(ExportConfig { .. })
        ));
        assert!(config.validate().is_ok());
    }
}
