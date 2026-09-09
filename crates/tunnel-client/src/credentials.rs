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
#[cfg(unix)]
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
    // CertifiedKey::from_der uses the selected rustls crypto provider to
    // compare the certificate SPKI with the private key.  This catches a
    // mismatched certificate before any file is installed.
    CertifiedKey::from_der(
        certificate_chain.clone(),
        key,
        &rustls::crypto::ring::default_provider(),
    )
    .map_err(|error| CredentialError::KeyMismatch(error.to_string()))?;

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
    KeyMismatch(String),
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
