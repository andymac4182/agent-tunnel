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
    /// The end-entity certificate's `notBefore`, as unix seconds, when it is
    /// still ahead of this host's clock (task row M6-C54).  Such a
    /// certificate is imported, because a host whose clock is behind sees
    /// every fresh certificate this way and `connect` retries it until it is
    /// valid, but the caller must say so rather than report a plain success.
    pub not_yet_valid_until: Option<i64>,
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
///
/// **All or nothing (task row M6-C55).**  Every check, including whether
/// either destination already exists, runs before any file is written, and
/// the two files are then installed together: each is written and synced
/// under a private staging name beside its destination and linked into
/// place without replacing anything, and if the second cannot be installed
/// the first is removed again.  A refusal therefore leaves the profile as it
/// was.  Before M6-C55 the certificate was written first and a refusal on the
/// server CA left it behind, which the next attempt then refused to
/// overwrite.
#[cfg(unix)]
pub fn import_certificate(
    config: &RuntimeConfig,
    certificate_source: impl AsRef<Path>,
    server_ca_source: impl AsRef<Path>,
) -> Result<ImportedCredential, CredentialError> {
    import_certificate_at(
        config,
        certificate_source.as_ref(),
        server_ca_source.as_ref(),
        unix_now(),
    )
}

/// [`import_certificate`] against an explicit clock, so the validity window
/// can be tested deterministically.
#[cfg(unix)]
fn import_certificate_at(
    config: &RuntimeConfig,
    certificate_source: &Path,
    server_ca_source: &Path,
    now_unix: i64,
) -> Result<ImportedCredential, CredentialError> {
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
    let not_yet_valid_until = check_import_validity(&certificate_chain[0], now_unix)?;

    let ca_chain = load_certificates(server_ca_source)?;
    if ca_chain.is_empty() {
        return Err(CredentialError::NoCertificates(server_ca_source.to_owned()));
    }

    let mut installs = Vec::with_capacity(2);
    if certificate_source != config.credentials.client_certificate {
        installs.push((
            certificate_source,
            config.credentials.client_certificate.as_path(),
        ));
    }
    if server_ca_source != config.credentials.server_ca {
        installs.push((server_ca_source, config.credentials.server_ca.as_path()));
    }
    install_new_files(&installs)?;
    Ok(ImportedCredential {
        certificate_path: config.credentials.client_certificate.clone(),
        server_ca_path: config.credentials.server_ca.clone(),
        certificate_count: certificate_chain.len(),
        ca_certificate_count: ca_chain.len(),
        not_yet_valid_until,
    })
}

/// Refuse an end-entity certificate that is already past `notAfter` on this
/// host's clock, and report one whose `notBefore` is still ahead (task row
/// M6-C54).
///
/// The two are deliberately treated differently, matching `connect`: an
/// expired certificate can never become valid, and `connect` exits `3` on it
/// without retrying, so importing it only defers the same refusal; a
/// certificate not yet valid is what a host whose clock is behind sees for
/// every freshly issued certificate, so refusing it would turn clock skew
/// into a failed import, and `connect` retries it until it is valid.
#[cfg(unix)]
fn check_import_validity(
    leaf: &CertificateDer<'_>,
    now_unix: i64,
) -> Result<Option<i64>, CredentialError> {
    let (_, parsed) = x509_parser::parse_x509_certificate(leaf.as_ref())
        .map_err(|error| CredentialError::CertificateUnparseable(error.to_string()))?;
    let validity = parsed.validity();
    let not_after = validity.not_after.timestamp();
    if not_after <= now_unix {
        return Err(CredentialError::CertificateExpired {
            not_after_unix: not_after,
        });
    }
    let not_before = validity.not_before.timestamp();
    Ok((not_before > now_unix).then_some(not_before))
}

#[cfg(unix)]
fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()
        .and_then(|elapsed| i64::try_from(elapsed.as_secs()).ok())
        .unwrap_or(0)
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
    let CertificateRole::Device { id } = identity.role() else {
        return Err(CredentialError::MissingDeviceRole(
            "the certificate carries a relay peer role, not a device role".into(),
        ));
    };
    // Compare as the relay does: it parses the SAN identifier and the HELLO's
    // `connector_id` (which is `device_id`) with `str::parse::<Uuid>` and
    // compares the values (`begin_register_control` and `validate_hello` in
    // `crates/tunnel-relay/src/actor.rs`; `provision-catalog` parses
    // `device.id` the same way).  A byte comparison refused an uppercase or
    // hyphen-less `device_id` the relay accepts.  No crate shared by the
    // client and the relay holds this parse, so it is repeated here.
    let Ok(certificate) = id.parse::<uuid::Uuid>() else {
        return Err(CredentialError::MissingDeviceRole(format!(
            "the device role SAN names {id:?}, which is not a UUID; the relay refuses it"
        )));
    };
    let Ok(configured) = device_id.parse::<uuid::Uuid>() else {
        return Err(CredentialError::DeviceIdNotUuid(device_id.to_owned()));
    };
    if certificate == configured {
        Ok(())
    } else {
        Err(CredentialError::DeviceIdMismatch {
            certificate: id.clone(),
            configured: device_id.to_owned(),
        })
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

/// Install every `(source, destination)` pair, or none of them (task row
/// M6-C55).
///
/// 1. Every destination is checked first; if any exists, the refusal names
///    it and nothing has been written.
/// 2. Each source is copied to a staging file beside its destination
///    (`create_new`, then synced), so a destination never appears holding a
///    partial file.
/// 3. Each staging file is hard-linked to its destination.  `link` fails
///    rather than replacing an existing name, so a destination created
///    concurrently after step 1 is still never overwritten.
/// 4. If any step fails, every destination linked by this call is removed
///    again -- it did not exist before, because its link succeeded -- and
///    every staging file is removed on every path.
#[cfg(unix)]
fn install_new_files(installs: &[(&Path, &Path)]) -> Result<(), CredentialError> {
    for (_, destination) in installs {
        match fs::symlink_metadata(destination) {
            Ok(_) => return Err(CredentialError::AlreadyExists((*destination).to_owned())),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(CredentialError::Io(error)),
        }
    }
    stage_and_link(installs)
}

/// Steps 2 to 4 of [`install_new_files`], without its up-front check, so the
/// rollback can be exercised against a destination that appears after the
/// check.
#[cfg(unix)]
fn stage_and_link(installs: &[(&Path, &Path)]) -> Result<(), CredentialError> {
    let mut staged: Vec<PathBuf> = Vec::with_capacity(installs.len());
    let mut linked: Vec<PathBuf> = Vec::with_capacity(installs.len());
    let result = (|| {
        for (source, destination) in installs {
            ensure_parent(destination, false)?;
            let mut bytes = Vec::new();
            File::open(source)
                .map_err(CredentialError::Io)?
                .read_to_end(&mut bytes)
                .map_err(CredentialError::Io)?;
            let staging = staging_path(destination);
            write_new(&staging, &bytes, false)?;
            staged.push(staging);
        }
        for ((_, destination), staging) in installs.iter().zip(&staged) {
            fs::hard_link(staging, destination).map_err(|error| {
                if error.kind() == io::ErrorKind::AlreadyExists {
                    CredentialError::AlreadyExists((*destination).to_owned())
                } else {
                    CredentialError::Io(error)
                }
            })?;
            linked.push((*destination).to_owned());
        }
        Ok(())
    })();
    if result.is_err() {
        for destination in &linked {
            let _ = fs::remove_file(destination);
        }
    }
    for staging in &staged {
        let _ = fs::remove_file(staging);
    }
    result
}

/// A staging name beside `destination`, unique to this process and call.
#[cfg(unix)]
fn staging_path(destination: &Path) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy().into_owned())
        .unwrap_or_default();
    destination.with_file_name(format!(
        ".{name}.import-{}-{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
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
    /// The end-entity certificate is past its `notAfter` on this host's
    /// clock (task row M6-C54); the value is that time as unix seconds.
    CertificateExpired {
        not_after_unix: i64,
    },
    /// The certificate has no usable `urn:agent-tunnel:device:<id>` URI SAN.
    MissingDeviceRole(String),
    /// The profile's `device_id` is not a UUID, which the relay requires.
    DeviceIdNotUuid(String),
    /// The certificate's device role SAN names another device than the
    /// profile's `device_id` (compared as UUIDs, as the relay compares them).
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
            Self::CertificateExpired { not_after_unix } => write!(
                formatter,
                "client certificate expired at unix time {not_after_unix} on this host's \
                 clock; the relay refuses it and `connect` would exit 3 on it, so it was \
                 not imported (ask the issuer for a new certificate)"
            ),
            Self::MissingDeviceRole(error) => write!(
                formatter,
                "client certificate has no device role URI SAN \
                 urn:agent-tunnel:device:<device_id>: {error}"
            ),
            Self::DeviceIdNotUuid(device_id) => write!(
                formatter,
                "the profile's device_id {device_id:?} is not a UUID; the relay accepts \
                 only the catalog device UUID"
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

    /// M1-05, owner-only key handling: the locally generated private key is
    /// created `0600` inside a directory created `0700`, and the CSR written
    /// beside it carries no private key.  The CSR test above only proved the
    /// files exist and are not overwritten, so a key written world-readable
    /// would have passed it.
    #[test]
    #[cfg(unix)]
    fn a_created_device_key_is_owner_only_and_absent_from_the_csr() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().expect("temporary directory");
        let mut config = RuntimeConfig::default();
        let key_dir = dir.path().join("private");
        config.credentials.client_key = key_dir.join("device-key.pem");
        let csr_path = dir.path().join("device.csr.pem");
        create_csr(&config, &csr_path).expect("create CSR");

        let key_mode = fs::metadata(&config.credentials.client_key)
            .expect("key metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(key_mode, 0o600, "device key mode {key_mode:o}");
        let dir_mode = fs::metadata(&key_dir)
            .expect("key directory metadata")
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "device key directory mode {dir_mode:o}");

        let key_pem = fs::read_to_string(&config.credentials.client_key).expect("key");
        assert!(
            key_pem.contains("PRIVATE KEY"),
            "the key file holds the key"
        );
        let csr_pem = fs::read_to_string(&csr_path).expect("CSR");
        assert!(csr_pem.contains("BEGIN CERTIFICATE REQUEST"));
        assert!(
            !csr_pem.contains("PRIVATE KEY"),
            "the CSR must not carry the private key"
        );
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

        /// A v3 device certificate for `key` valid over `[not_before,
        /// not_after]`, given as years.
        pub(super) fn v3_pem_between(key: &KeyPair, not_before: i32, not_after: i32) -> String {
            let mut params = CertificateParams::default();
            params
                .distinguished_name
                .push(DnType::CommonName, format!("device/{DEVICE}"));
            params.subject_alt_names = vec![device_san(DEVICE)];
            params.not_before = rcgen::date_time_ymd(not_before, 1, 1);
            params.not_after = rcgen::date_time_ymd(not_after, 1, 1);
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

    /// M1-05, certificate-role separation on import: a relay **peer**
    /// certificate is refused even when its identifier is this device's own
    /// UUID and its key matches -- the right name in the wrong role -- and
    /// nothing is installed.  The relay would refuse it at the device
    /// listener; refusing it here tells the operator before they try.
    #[test]
    #[cfg(unix)]
    fn a_relay_peer_certificate_is_refused_on_import_even_naming_this_device() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let peer_san = rcgen::SanType::URI(
            format!("urn:agent-tunnel:peer:{}", material::DEVICE)
                .try_into()
                .expect("URI SAN"),
        );
        let certificate = material::v3_pem(&key, vec![peer_san]);
        let (result, dir) = import_with(&key, &certificate);
        let error = result.expect_err("a peer-role certificate is not a device credential");
        assert!(
            matches!(&error, CredentialError::MissingDeviceRole(detail) if detail.contains("relay peer role")),
            "{error:?}"
        );
        assert!(!dir.path().join("installed-cert.pem").exists());
        assert!(!dir.path().join("installed-ca.pem").exists());
    }

    /// The relay compares device identifiers as UUIDs, so an uppercase or
    /// hyphen-less `device_id` naming the certificate's device is the same
    /// device and must import.  A byte comparison refused both.
    #[test]
    #[cfg(unix)]
    fn a_device_id_equal_as_a_uuid_imports_in_any_accepted_spelling() {
        let san = "3a3b3c3d-3e3f-4a3b-8c3d-3e3f3a3b3c3d";
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem(&key, vec![material::device_san(san)]);
        let leaf = load_certificates_from(&certificate).remove(0);
        for spelling in [
            san.to_owned(),
            san.to_uppercase(),
            san.replace('-', ""),
            san.replace('-', "").to_uppercase(),
        ] {
            // The spelling must also be one the profile validation accepts.
            let config = RuntimeConfig {
                device_id: spelling.clone(),
                ..RuntimeConfig::default()
            };
            assert!(
                config.validate().is_ok(),
                "{spelling} must be a valid device_id"
            );
            assert!(
                verify_device_role(&leaf, &spelling).is_ok(),
                "{spelling} names the certificate's device as the relay compares it"
            );
        }
        assert!(matches!(
            verify_device_role(&leaf, "not-a-uuid"),
            Err(CredentialError::DeviceIdNotUuid(_))
        ));
    }

    /// A profile directory with a pending key, an issued certificate and a
    /// CA bundle, for the M6-C54 and M6-C55 cases.
    #[cfg(unix)]
    struct ImportFixture {
        dir: tempfile::TempDir,
        config: RuntimeConfig,
        source: PathBuf,
        ca: PathBuf,
    }

    #[cfg(unix)]
    impl ImportFixture {
        fn new(key: &rcgen::KeyPair, certificate_pem: &str) -> Self {
            let dir = tempdir().expect("temporary directory");
            let mut config = RuntimeConfig {
                device_id: material::DEVICE.to_owned(),
                ..RuntimeConfig::default()
            };
            config.credentials.client_key = dir.path().join("device-key.pem");
            config.credentials.client_certificate =
                dir.path().join("credentials/installed-cert.pem");
            config.credentials.server_ca = dir.path().join("credentials/installed-ca.pem");
            fs::write(&config.credentials.client_key, key.serialize_pem()).expect("pending key");
            let source = dir.path().join("issued.pem");
            fs::write(&source, certificate_pem).expect("issued certificate");
            let ca_key = rcgen::KeyPair::generate().expect("CA key");
            let ca = dir.path().join("ca.pem");
            fs::write(&ca, material::v3_pem(&ca_key, Vec::new())).expect("CA bundle");
            Self {
                dir,
                config,
                source,
                ca,
            }
        }

        fn import(&self) -> Result<ImportedCredential, CredentialError> {
            import_certificate(&self.config, &self.source, &self.ca)
        }

        /// Every entry of the destination directory, staging files included.
        fn installed(&self) -> Vec<String> {
            let mut names: Vec<String> = fs::read_dir(self.dir.path().join("credentials"))
                .map(|entries| {
                    entries
                        .map(|entry| {
                            entry
                                .expect("directory entry")
                                .file_name()
                                .to_string_lossy()
                                .into_owned()
                        })
                        .collect()
                })
                .unwrap_or_default();
            names.sort();
            names
        }
    }

    /// M6-C55, the measured case: the server CA destination already exists
    /// (the tester had moved only the certificate aside), so the import is
    /// refused -- and it must refuse **before** writing the certificate.
    /// Before the fix the certificate was installed first, the refusal named
    /// only the CA, and the next attempt refused the certificate the failed
    /// one had written.
    #[test]
    #[cfg(unix)]
    fn a_refusal_on_the_server_ca_leaves_no_certificate_behind() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem(&key, vec![material::device_san(material::DEVICE)]);
        let fixture = ImportFixture::new(&key, &certificate);
        fs::create_dir_all(fixture.dir.path().join("credentials")).expect("credential dir");
        fs::write(&fixture.config.credentials.server_ca, "existing CA\n").expect("existing CA");

        let error = fixture.import().expect_err("the CA destination exists");
        assert!(
            matches!(&error, CredentialError::AlreadyExists(path)
                if path == &fixture.config.credentials.server_ca),
            "{error:?}"
        );
        assert_eq!(
            fixture.installed(),
            vec!["installed-ca.pem".to_owned()],
            "the refusal must leave the profile exactly as it was"
        );
        assert_eq!(
            fs::read_to_string(&fixture.config.credentials.server_ca).expect("CA"),
            "existing CA\n",
            "and must not touch the existing file"
        );

        // With the CA moved aside too, the same import now succeeds: nothing
        // from the refused attempt is in its way.
        fs::remove_file(&fixture.config.credentials.server_ca).expect("move CA aside");
        let imported = fixture.import().expect("a clean retry imports");
        assert_eq!(imported.certificate_count, 1);
        assert_eq!(
            fixture.installed(),
            vec![
                "installed-ca.pem".to_owned(),
                "installed-cert.pem".to_owned()
            ],
            "both files, and no staging file left behind"
        );
        assert_eq!(
            fs::read_to_string(&fixture.config.credentials.client_certificate).expect("cert"),
            certificate
        );
    }

    /// M6-C55, the other order: an existing certificate is refused and the
    /// CA is not written either.
    #[test]
    #[cfg(unix)]
    fn a_refusal_on_the_certificate_writes_no_server_ca() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem(&key, vec![material::device_san(material::DEVICE)]);
        let fixture = ImportFixture::new(&key, &certificate);
        fs::create_dir_all(fixture.dir.path().join("credentials")).expect("credential dir");
        fs::write(&fixture.config.credentials.client_certificate, "old\n").expect("old cert");
        let error = fixture
            .import()
            .expect_err("the certificate destination exists");
        assert!(
            matches!(&error, CredentialError::AlreadyExists(path)
                if path == &fixture.config.credentials.client_certificate),
            "{error:?}"
        );
        assert_eq!(fixture.installed(), vec!["installed-cert.pem".to_owned()]);
    }

    /// M6-C55, the install step itself: when the second link fails after
    /// the first succeeded, the first destination is removed again and no
    /// staging file survives.  The second destination is created after the
    /// existence check -- by calling the staging step directly, which is the
    /// race `link`'s no-clobber rule exists for -- so its link, and not the
    /// check, is what refuses.
    #[test]
    #[cfg(unix)]
    fn a_failed_second_link_rolls_back_the_first() {
        let dir = tempdir().expect("temporary directory");
        let first_source = dir.path().join("first-source");
        let second_source = dir.path().join("second-source");
        fs::write(&first_source, "first").expect("first source");
        fs::write(&second_source, "second").expect("second source");
        let out = dir.path().join("out");
        fs::create_dir(&out).expect("destination directory");
        let first = out.join("first");
        let second = out.join("second");
        fs::write(&second, "appeared after the check").expect("racing file");
        let error = stage_and_link(&[(&first_source, &first), (&second_source, &second)])
            .expect_err("the second link refuses to replace a file");
        assert!(
            matches!(&error, CredentialError::AlreadyExists(path) if path == &second),
            "{error:?}"
        );
        assert!(!first.exists(), "the first destination was rolled back");
        assert_eq!(
            fs::read_to_string(&second).expect("second"),
            "appeared after the check",
            "the racing file is untouched"
        );
        let mut left: Vec<String> = fs::read_dir(&out)
            .expect("destination directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        left.sort();
        assert_eq!(left, vec!["second".to_owned()], "no staging file survives");
    }

    /// M6-C54: an expired certificate is refused on import, before any file
    /// is written.  Before the fix it was imported with exit 0, and the
    /// failure surfaced only at `connect`.
    #[test]
    #[cfg(unix)]
    fn an_expired_certificate_is_refused_on_import() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem_between(&key, 2020, 2021);
        let fixture = ImportFixture::new(&key, &certificate);
        let error = fixture.import().expect_err("an expired certificate");
        assert!(
            matches!(error, CredentialError::CertificateExpired { not_after_unix }
                if not_after_unix == 1_609_459_200),
            "{error:?}"
        );
        assert!(
            error
                .to_string()
                .contains("expired at unix time 1609459200")
        );
        assert!(fixture.installed().is_empty(), "nothing was written");
    }

    /// M6-C54: a certificate not yet valid on this host's clock is imported
    /// -- a clock behind the issuer's sees every fresh certificate this way,
    /// and `connect` retries it until it is valid -- but the import reports
    /// when it becomes valid rather than a plain success.
    #[test]
    #[cfg(unix)]
    fn a_certificate_not_yet_valid_is_imported_and_reported() {
        let key = rcgen::KeyPair::generate().expect("device key");
        let certificate = material::v3_pem_between(&key, 2090, 2091);
        let fixture = ImportFixture::new(&key, &certificate);
        let imported = fixture.import().expect("imported with a report");
        assert_eq!(imported.not_yet_valid_until, Some(3_786_912_000));
        assert!(fixture.config.credentials.client_certificate.exists());
        // And a currently valid one carries no such report.
        let key = rcgen::KeyPair::generate().expect("device key");
        let current = material::v3_pem_between(&key, 2020, 2090);
        let fixture = ImportFixture::new(&key, &current);
        assert_eq!(fixture.import().expect("valid").not_yet_valid_until, None);
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
