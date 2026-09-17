//! TLS configuration and identity extraction.

use std::{fmt, io::Cursor, sync::Arc};

use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    crypto::{self, CryptoProvider},
    pki_types::{CertificateDer, PrivateKeyDer},
    server::{NoServerSessionStorage, WebPkiClientVerifier},
    version,
};
use sha2::{Digest, Sha256};
use thiserror::Error;
use x509_parser::{extensions::GeneralName, parse_x509_certificate};

const TLS13: &[&rustls::SupportedProtocolVersion] = &[&version::TLS13];
const DEVICE_ROLE_PREFIX: &str = "urn:agent-tunnel:device:";
const PEER_ROLE_PREFIX: &str = "urn:agent-tunnel:peer:";

/// A SHA-256 digest of a certificate's DER-encoded SubjectPublicKeyInfo.
///
/// This is a public-key pin, rather than a certificate fingerprint.  It
/// remains stable across certificate renewal when the key is deliberately
/// reused, and it is suitable for the separately managed relay peer pin set.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct SpkiSha256([u8; 32]);

impl SpkiSha256 {
    /// Construct a pin from its raw digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Return the raw digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Return the lower-case hexadecimal representation used by diagnostics.
    #[must_use]
    pub fn to_hex(self) -> String {
        encode_hex(&self.0)
    }
}

impl fmt::Display for SpkiSha256 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&encode_hex(&self.0))
    }
}

/// The authenticated role encoded by a leaf certificate's URI SAN.
///
/// The URI SAN is an identity hint only.  A relay must still map the
/// fingerprint and role identifier to its authoritative credential record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CertificateRole {
    /// A desktop/connector device identity.
    Device {
        /// Stable device identifier from the URI SAN.
        id: String,
    },
    /// A private relay peer identity.
    Peer {
        /// Stable relay-node identifier from the URI SAN.
        id: String,
    },
}

impl CertificateRole {
    /// Return the role's stable catalogue identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        match self {
            Self::Device { id } | Self::Peer { id } => id,
        }
    }

    /// Return whether this is a device role.
    #[must_use]
    pub const fn is_device(&self) -> bool {
        matches!(self, Self::Device { .. })
    }

    /// Return whether this is a peer role.
    #[must_use]
    pub const fn is_peer(&self) -> bool {
        matches!(self, Self::Peer { .. })
    }
}

/// A parsed Subject Alternative Name value retained for audit and policy
/// checks.  The raw certificate remains outside the application request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SanName {
    /// DNS SAN.
    Dns(String),
    /// URI SAN.
    Uri(String),
    /// RFC 822/e-mail SAN.
    Rfc822(String),
    /// IP address SAN represented as lower-case hexadecimal bytes.
    Ip(String),
    /// Directory name SAN.
    Directory(String),
    /// Other or unsupported GeneralName values rendered for diagnostics.
    Other(String),
}

impl SanName {
    fn as_role_uri(&self) -> Option<&str> {
        match self {
            Self::Uri(uri) => Some(uri),
            _ => None,
        }
    }
}

/// Certificate metadata inserted into an Axum request after a successful
/// rustls client-authenticated handshake.
///
/// There is intentionally no public constructor.  Consumers obtain this
/// value from [`serve`][crate::serve]'s request extension, and the transport
/// crate creates it only from the peer certificate chain returned by rustls.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TlsIdentity {
    role: CertificateRole,
    spki_sha256: SpkiSha256,
    certificate_serial: String,
    certificate_not_before: i64,
    certificate_expires_at: i64,
    subject: String,
    subject_alt_names: Vec<SanName>,
}

impl TlsIdentity {
    /// Return the role parsed from the URI SAN.
    #[must_use]
    pub fn role(&self) -> &CertificateRole {
        &self.role
    }

    /// Return the SPKI SHA-256 public-key pin.
    #[must_use]
    pub const fn spki_sha256(&self) -> SpkiSha256 {
        self.spki_sha256
    }

    /// Return the leaf certificate serial as lower-case, colon-separated
    /// hexadecimal bytes in the same representation used by x509-parser.
    ///
    /// This is observed certificate metadata.  It is not an authorization
    /// decision and must still be compared with the authoritative credential
    /// record by the caller.
    #[must_use]
    pub fn certificate_serial(&self) -> &str {
        &self.certificate_serial
    }

    /// Return the leaf certificate's `notBefore` value as Unix seconds.
    ///
    /// This is observed certificate metadata.  It is not an authorization
    /// decision and must still be checked against the authoritative
    /// credential validity window by the caller.
    #[must_use]
    pub const fn certificate_not_before(&self) -> i64 {
        self.certificate_not_before
    }

    /// Return the leaf certificate's `notAfter` value as Unix seconds.
    #[must_use]
    pub const fn certificate_expires_at(&self) -> i64 {
        self.certificate_expires_at
    }

    /// Return the RFC 4514-like subject rendering supplied by x509-parser.
    #[must_use]
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Return the parsed SAN values.
    #[must_use]
    pub fn subject_alt_names(&self) -> &[SanName] {
        &self.subject_alt_names
    }

    /// Return the role identifier from the authoritative SAN marker.
    #[must_use]
    pub fn role_id(&self) -> &str {
        self.role.id()
    }
}

/// Errors while parsing metadata from a certificate chain that rustls has
/// already verified.
#[derive(Debug, Error)]
pub enum TlsIdentityError {
    /// No leaf certificate was supplied.
    #[error("TLS peer did not present a leaf certificate")]
    MissingLeaf,
    /// The leaf DER was malformed.
    #[error("invalid leaf certificate DER: {0}")]
    Certificate(String),
    /// A certificate chain had no role marker or had conflicting markers.
    #[error(
        "leaf certificate must contain exactly one {DEVICE_ROLE_PREFIX}<id> or {PEER_ROLE_PREFIX}<id> URI SAN"
    )]
    InvalidRole,
    /// A role marker was empty.
    #[error("leaf certificate role URI has an empty identifier")]
    EmptyRoleId,
}

/// Errors raised while constructing a rustls configuration from PEM input.
#[derive(Debug, Error)]
pub enum TlsConfigError {
    /// PEM input could not be read.
    #[error("invalid PEM input: {0}")]
    Pem(#[source] std::io::Error),
    /// A certificate chain was empty.
    #[error("{0} PEM did not contain a certificate")]
    MissingCertificate(&'static str),
    /// A private key was absent.
    #[error("private-key PEM did not contain a supported private key")]
    MissingPrivateKey,
    /// A CA bundle was empty.
    #[error("client/server CA PEM did not contain a certificate")]
    MissingCertificateAuthority,
    /// A CA certificate could not be inserted into the trust store.
    #[error("invalid certificate authority: {0}")]
    InvalidCertificateAuthority(String),
    /// Rustls rejected a certificate, key, verifier, or protocol configuration.
    #[error("rustls configuration error: {0}")]
    Rustls(#[source] rustls::Error),
    /// Rustls could not construct a certificate verifier.
    #[error("certificate verifier configuration error: {0}")]
    Verifier(String),
    /// A QUIC wrapper could not be constructed from the rustls configuration.
    #[error("QUIC TLS configuration error: {0}")]
    Quic(String),
}

/// Compatibility alias for callers that want to name client configuration
/// errors explicitly while retaining one error type.
pub type ClientTlsConfigError = TlsConfigError;

/// Parse a leaf certificate and derive its authenticated metadata.
///
/// This function only parses DER.  It does not verify the chain, validity,
/// key usage, or revocation.  Call it only with the certificate chain exposed
/// by a completed rustls handshake, or after an equivalent verifier has run.
pub(crate) fn parse_leaf_identity(
    chain: &[CertificateDer<'_>],
) -> Result<TlsIdentity, TlsIdentityError> {
    let leaf = chain.first().ok_or(TlsIdentityError::MissingLeaf)?;
    let (_, certificate) = parse_x509_certificate(leaf.as_ref())
        .map_err(|error| TlsIdentityError::Certificate(error.to_string()))?;

    let subject = certificate.subject().to_string();
    let subject_alt_names = certificate
        .subject_alternative_name()
        .map_err(|error| TlsIdentityError::Certificate(error.to_string()))?
        .map(|extension| {
            extension
                .value
                .general_names
                .iter()
                .map(san_name)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let role = role_from_sans(&subject_alt_names)?;
    let spki_sha256 = spki_sha256_from_der(leaf.as_ref())?;

    Ok(TlsIdentity {
        role,
        spki_sha256,
        certificate_serial: certificate.raw_serial_as_string(),
        certificate_not_before: certificate.validity().not_before.timestamp(),
        certificate_expires_at: certificate.validity().not_after.timestamp(),
        subject,
        subject_alt_names,
    })
}

/// Derive an SPKI SHA-256 pin from a DER-encoded leaf certificate.
pub fn spki_sha256_from_der(der: &[u8]) -> Result<SpkiSha256, TlsIdentityError> {
    let (_, certificate) = parse_x509_certificate(der)
        .map_err(|error| TlsIdentityError::Certificate(error.to_string()))?;
    let mut digest = Sha256::new();
    digest.update(certificate.public_key().raw);
    let bytes: [u8; 32] = digest.finalize().into();
    Ok(SpkiSha256(bytes))
}

fn role_from_sans(sans: &[SanName]) -> Result<CertificateRole, TlsIdentityError> {
    let mut role = None;
    for uri in sans.iter().filter_map(SanName::as_role_uri) {
        let candidate = if let Some(id) = uri.strip_prefix(DEVICE_ROLE_PREFIX) {
            CertificateRole::Device { id: id.to_owned() }
        } else if let Some(id) = uri.strip_prefix(PEER_ROLE_PREFIX) {
            CertificateRole::Peer { id: id.to_owned() }
        } else {
            continue;
        };
        if candidate.id().is_empty() {
            return Err(TlsIdentityError::EmptyRoleId);
        }
        if role.replace(candidate).is_some() {
            return Err(TlsIdentityError::InvalidRole);
        }
    }
    role.ok_or(TlsIdentityError::InvalidRole)
}

fn san_name(name: &GeneralName<'_>) -> SanName {
    match name {
        GeneralName::DNSName(value) => SanName::Dns((*value).to_owned()),
        GeneralName::URI(value) => SanName::Uri((*value).to_owned()),
        GeneralName::RFC822Name(value) => SanName::Rfc822((*value).to_owned()),
        GeneralName::IPAddress(value) => SanName::Ip(encode_hex(value)),
        GeneralName::DirectoryName(value) => SanName::Directory(value.to_string()),
        other => SanName::Other(other.to_string()),
    }
}

/// Parse a mandatory trust bundle for client or server authentication.
pub fn require_root_certificates(pem: &[u8]) -> Result<RootCertStore, TlsConfigError> {
    let certificates = parse_certificates(pem, "CA")?;
    let mut roots = RootCertStore::empty();
    for certificate in certificates {
        roots
            .add(certificate)
            .map_err(|error| TlsConfigError::InvalidCertificateAuthority(error.to_string()))?;
    }
    if roots.is_empty() {
        return Err(TlsConfigError::MissingCertificateAuthority);
    }
    Ok(roots)
}

/// Build a mandatory client certificate verifier from a dedicated CA bundle.
///
/// The verifier rejects anonymous clients; it is suitable for both device and
/// relay-peer listeners.  Role separation remains a separate SAN/catalogue
/// policy check after the handshake.
pub fn require_client_ca(
    ca_pem: &[u8],
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, TlsConfigError> {
    let provider = ring_provider();
    require_client_ca_with_provider(ca_pem, provider)
}

/// Build a consumer HTTPS server configuration.  Supplying `Some(ca_pem)`
/// switches the listener to mandatory mTLS, which is required for device and
/// peer listeners; `None` leaves consumer authentication to the HTTP layer.
pub fn load_server_config_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    load_server_config_from_pem_with_alpn(
        certificate_pem,
        private_key_pem,
        client_ca_pem,
        &[b"h2", b"http/1.1"],
    )
}

/// Build a TLS 1.3 server configuration with explicit ALPN and optional
/// mandatory client authentication.
pub fn load_server_config_from_pem_with_alpn(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    client_ca_pem: Option<&[u8]>,
    alpn_protocols: &[&[u8]],
) -> Result<Arc<ServerConfig>, TlsConfigError> {
    let certificate_chain = parse_certificates(certificate_pem, "server certificate")?;
    let private_key = parse_private_key(private_key_pem)?;
    let provider = ring_provider();
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(TLS13)
        .map_err(TlsConfigError::Rustls)?;
    let mut config = match client_ca_pem {
        Some(ca_pem) => builder
            .with_client_cert_verifier(require_client_ca_with_provider(ca_pem, provider)?)
            .with_single_cert(certificate_chain, private_key)
            .map_err(TlsConfigError::Rustls)?,
        None => builder
            .with_no_client_auth()
            .with_single_cert(certificate_chain, private_key)
            .map_err(TlsConfigError::Rustls)?,
    };
    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    disable_server_resumption(&mut config);
    Ok(Arc::new(config))
}

/// Build a TLS 1.3 client configuration for WSS with a client certificate and
/// a dedicated server trust bundle.  Resumption and early data are disabled.
pub fn load_client_config_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    server_ca_pem: &[u8],
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    load_client_config_from_pem_with_alpn(
        certificate_pem,
        private_key_pem,
        server_ca_pem,
        &[b"h2", b"http/1.1"],
    )
}

/// Build a TLS 1.3 client configuration with explicit ALPN.
pub fn load_client_config_from_pem_with_alpn(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    server_ca_pem: &[u8],
    alpn_protocols: &[&[u8]],
) -> Result<Arc<ClientConfig>, TlsConfigError> {
    let certificate_chain = parse_certificates(certificate_pem, "client certificate")?;
    let private_key = parse_private_key(private_key_pem)?;
    let roots = require_root_certificates(server_ca_pem)?;
    let provider = ring_provider();
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(TLS13)
        .map_err(TlsConfigError::Rustls)?
        .with_root_certificates(roots)
        .with_client_auth_cert(certificate_chain, private_key)
        .map_err(TlsConfigError::Rustls)?;
    config.alpn_protocols = alpn_protocols
        .iter()
        .map(|protocol| protocol.to_vec())
        .collect();
    config.resumption = rustls::client::Resumption::disabled();
    config.enable_early_data = false;
    Ok(Arc::new(config))
}

/// Build a private relay HTTP/3 server configuration with mandatory peer
/// client authentication and ALPN `h3`.
pub fn load_peer_server_config_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    peer_ca_pem: &[u8],
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let tls = load_server_config_from_pem_with_alpn(
        certificate_pem,
        private_key_pem,
        Some(peer_ca_pem),
        &[b"h3"],
    )?;
    load_quinn_server_config(tls)
}

/// Build a private relay HTTP/3 client configuration with mandatory client
/// authentication, server trust, and ALPN `h3`.
pub fn load_peer_client_config_from_pem(
    certificate_pem: &[u8],
    private_key_pem: &[u8],
    server_ca_pem: &[u8],
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let tls = load_client_config_from_pem_with_alpn(
        certificate_pem,
        private_key_pem,
        server_ca_pem,
        &[b"h3"],
    )?;
    load_quinn_client_config(tls)
}

/// Wrap a TLS server configuration for Quinn.  The supplied configuration is
/// expected to use TLS 1.3 and `max_early_data_size == 0`.
pub fn load_quinn_server_config(
    tls: Arc<ServerConfig>,
) -> Result<quinn::ServerConfig, TlsConfigError> {
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TlsConfigError::Quic(error.to_string()))?;
    Ok(quinn::ServerConfig::with_crypto(Arc::new(crypto)))
}

/// Wrap a TLS client configuration for Quinn.  The supplied configuration
/// has early data and resumption disabled by the PEM helpers above.
pub fn load_quinn_client_config(
    tls: Arc<ClientConfig>,
) -> Result<quinn::ClientConfig, TlsConfigError> {
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TlsConfigError::Quic(error.to_string()))?;
    Ok(quinn::ClientConfig::new(Arc::new(crypto)))
}

fn ring_provider() -> Arc<CryptoProvider> {
    Arc::new(crypto::ring::default_provider())
}

/// A process that already had a `rustls` crypto provider before this one was
/// installed.
///
/// It is an error rather than a shrug: the only way to see it is for something
/// to have installed a provider before the first line of `main`, and whatever
/// that is has decided the process's cryptography instead of this workspace.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProviderAlreadyInstalled;

impl core::fmt::Display for ProviderAlreadyInstalled {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(
            "a rustls crypto provider was already installed before this process chose one",
        )
    }
}

impl std::error::Error for ProviderAlreadyInstalled {}

/// Install `ring` as this process's default `rustls` crypto provider.
///
/// **Every binary in this workspace must call this before any TLS work.**
/// `rustls` will only infer a process default when exactly one provider
/// feature is enabled in the build, and a workspace does not control that: a
/// single dependency anywhere in the graph that asks for `aws-lc-rs` turns the
/// inference into a panic — "Could not automatically determine the
/// process-level CryptoProvider" — in binaries that never named that
/// dependency. That is not hypothetical; it is what happened when M8 chunk 3
/// added the pinned ACP HTTP client, whose `reqwest` feature set pulls
/// `rustls/aws-lc-rs` (task row M8-C09).
///
/// Every `rustls` configuration this crate builds already passes
/// [`ring_provider`] explicitly, so nothing here depends on the inference for
/// its *choice*. What this fixes is the sites that build a `rustls` config
/// **without** naming a provider, which are not all in this workspace: the
/// nearest one is `redis-rs`'s own `ClientConfig::builder()` on a `rediss://`
/// URL, reached through `tunnel-catalog`.
///
/// # Errors
/// [`ProviderAlreadyInstalled`] when a provider was installed before this
/// call. **Treat it as fatal.** It is the only signal available that something
/// ran before `main` and chose the process's cryptography; swallowing it —
/// which this function used to invite by returning a `bool` nobody read — makes
/// the one observable symptom of that invisible.
pub fn install_process_crypto_provider() -> Result<(), ProviderAlreadyInstalled> {
    crypto::ring::default_provider()
        .install_default()
        .map_err(|_| ProviderAlreadyInstalled)
}

/// Whether the process's default provider is the `ring` one this workspace
/// installs.
///
/// Compared by cipher suite list, which is what a `CryptoProvider` exposes;
/// there is no identity to compare. **Be exact about what that distinguishes:**
/// it catches a provider with a different suite set, and it would not catch a
/// hypothetical other provider offering exactly `ring`'s suites in exactly
/// `ring`'s order. The stronger statement is the `Ok` from
/// [`install_process_crypto_provider`], which says *this* call installed it.
#[must_use]
pub fn process_provider_is_ring() -> bool {
    let Some(installed) = CryptoProvider::get_default() else {
        return false;
    };
    // Discriminate on the secure-random implementation's own type name, not on
    // the cipher-suite list.
    //
    // An earlier version of this compared `cipher_suites` against ring's, which
    // could not fail for the reason it claimed: rustls 0.23's `ring` and
    // `aws_lc_rs` default providers offer the same suites in the same order
    // (non-FIPS, tls12), so this returned `true` for *precisely* the provider
    // M8-C09 exists to exclude.  Review caught it.
    //
    // `SecureRandom` is `Debug` and each provider's implementing type is a
    // distinct named struct -- ring's is `Ring` -- so the rendered type name
    // separates them where the suite list cannot.
    format!("{:?}", installed.secure_random).starts_with("Ring")
}

fn require_client_ca_with_provider(
    ca_pem: &[u8],
    provider: Arc<CryptoProvider>,
) -> Result<Arc<dyn rustls::server::danger::ClientCertVerifier>, TlsConfigError> {
    let roots = Arc::new(require_root_certificates(ca_pem)?);
    WebPkiClientVerifier::builder_with_provider(roots, provider)
        .build()
        .map_err(|error| TlsConfigError::Verifier(error.to_string()))
}

fn disable_server_resumption(config: &mut ServerConfig) {
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.max_early_data_size = 0;
    config.send_tls13_tickets = 0;
    config.send_half_rtt_data = false;
}

fn parse_certificates(
    pem: &[u8],
    description: &'static str,
) -> Result<Vec<CertificateDer<'static>>, TlsConfigError> {
    let mut reader = Cursor::new(pem);
    let certificates = rustls_pemfile::certs(&mut reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(TlsConfigError::Pem)?;
    if certificates.is_empty() {
        return Err(TlsConfigError::MissingCertificate(description));
    }
    Ok(certificates)
}

fn parse_private_key(pem: &[u8]) -> Result<PrivateKeyDer<'static>, TlsConfigError> {
    let mut reader = Cursor::new(pem);
    rustls_pemfile::private_key(&mut reader)
        .map_err(TlsConfigError::Pem)?
        .ok_or(TlsConfigError::MissingPrivateKey)
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn role_markers_are_exact_and_unambiguous() {
        let device =
            role_from_sans(&[SanName::Uri("urn:agent-tunnel:device:desktop-01".into())]).unwrap();
        assert_eq!(
            device,
            CertificateRole::Device {
                id: "desktop-01".into()
            }
        );

        let peer =
            role_from_sans(&[SanName::Uri("urn:agent-tunnel:peer:relay-02".into())]).unwrap();
        assert_eq!(
            peer,
            CertificateRole::Peer {
                id: "relay-02".into()
            }
        );

        assert!(matches!(
            role_from_sans(&[SanName::Uri("urn:agent-tunnel:device:".into())]),
            Err(TlsIdentityError::EmptyRoleId)
        ));
        assert!(matches!(
            role_from_sans(&[
                SanName::Uri("urn:agent-tunnel:device:a".into()),
                SanName::Uri("urn:agent-tunnel:peer:b".into())
            ]),
            Err(TlsIdentityError::InvalidRole)
        ));
        assert!(matches!(
            role_from_sans(&[SanName::Dns("device.example.test".into())]),
            Err(TlsIdentityError::InvalidRole)
        ));
    }

    #[test]
    fn fingerprint_is_lower_case_hex() {
        let pin = SpkiSha256::from_bytes([0xab; 32]);
        assert_eq!(
            pin.to_hex(),
            "abababababababababababababababababababababababababababababababab"
        );
    }

    #[test]
    fn identity_exposes_observed_certificate_validity_and_serial() {
        let identity = TlsIdentity {
            role: CertificateRole::Peer {
                id: "relay-01".into(),
            },
            spki_sha256: SpkiSha256::from_bytes([0x42; 32]),
            certificate_serial: "01:02:ff".into(),
            certificate_not_before: 1_700_000_000,
            certificate_expires_at: 1_700_100_000,
            subject: "CN=relay-01".into(),
            subject_alt_names: vec![SanName::Uri("urn:agent-tunnel:peer:relay-01".into())],
        };

        assert_eq!(identity.certificate_serial(), "01:02:ff");
        assert_eq!(identity.certificate_not_before(), 1_700_000_000);
        assert_eq!(identity.certificate_expires_at(), 1_700_100_000);
    }
}
