//! A relay's own private HTTP/3 peer identity, replaceable without a restart.
//!
//! Before task rows M8-C28/M8-C45 a relay bound exactly one peer certificate
//! for the life of its process: the QUIC server and client configurations were
//! built with `with_single_cert`/`with_client_auth_cert`, so no live peer-key
//! rotation could keep the rotating relay serving.  [`RotatingPeerIdentity`]
//! is the one mutable slot both configurations resolve through.  Installing a
//! new identity changes what **new** handshakes present; a QUIC connection
//! already established keeps the identity it negotiated, which is what lets
//! in-flight streams drain under the predecessor while the successor serves.
//!
//! The slot holds a private key in memory only.  It never serializes, logs or
//! returns key material: the `Debug` output names the generation and the
//! public SPKI digest, and every accessor returns public data.  Loading a key
//! from disk, and deciding **when** a staged identity may serve, belong to the
//! relay, which gates the switch on a verified signed membership record that
//! approves the successor's SPKI (see `docs/cluster.md`).

use std::{
    fmt,
    sync::{Arc, RwLock},
};

use rustls::{
    SignatureScheme,
    client::ResolvesClientCert,
    crypto::CryptoProvider,
    pki_types::{CertificateDer, UnixTime},
    server::{ClientHello, ResolvesServerCert},
    sign::CertifiedKey,
};

use crate::tls::{
    SanName, SpkiSha256, TlsConfigError, TlsIdentity, disable_server_resumption,
    load_quinn_client_config, load_quinn_server_config, parse_certificates, parse_leaf_identity,
    parse_private_key, require_client_ca_with_provider, require_root_certificates, ring_provider,
};

/// Why a candidate peer identity was refused before it could be staged.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum PeerIdentityError {
    /// The PEM input, key, or chain was not a usable TLS identity.
    #[error("peer identity is not a usable TLS identity: {0}")]
    Unusable(String),
    /// The private key does not match the leaf certificate's public key, or
    /// the match could not be established.
    #[error("peer identity private key does not match its certificate")]
    KeyMismatch,
    /// The leaf certificate does not carry a relay peer role URI SAN.
    #[error("peer identity certificate is not a relay peer certificate")]
    NotPeerRole,
    /// The leaf certificate names a different relay node than the identity
    /// it would replace.  A rotation never changes which node this is.
    #[error("peer identity certificate names a different relay node")]
    DifferentNode,
    /// The leaf certificate drops a DNS/IP name the current identity serves,
    /// so peers dialing the approved server name would refuse it.
    #[error("peer identity certificate does not cover the current server names")]
    ServerNamesNarrowed,
    /// The identity currently served has no parseable relay peer role, so no
    /// successor can be proven to be the same node; rotation is refused.
    #[error("the served peer identity has no relay peer role, so it cannot be rotated")]
    CurrentIdentityUnverifiable,
    /// The leaf certificate does not chain to the operator-provisioned relay
    /// peer CA, or is outside its validity window, or lacks client usage.
    #[error("peer identity certificate does not verify against the peer CA: {0}")]
    Untrusted(String),
}

/// A validated peer identity that is not yet serving.
///
/// Holding one proves only that the certificate chains to the local peer CA,
/// matches its private key, and names the same relay node.  It says nothing
/// about membership approval, which the relay must check separately against
/// the signed record before calling [`RotatingPeerIdentity::install`].
pub struct StagedPeerIdentity {
    certified: Arc<CertifiedKey>,
    identity: TlsIdentity,
}

impl fmt::Debug for StagedPeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("StagedPeerIdentity")
            .field("node", &self.identity.role_id())
            .field("spki_sha256", &self.identity.spki_sha256().to_hex())
            .finish_non_exhaustive()
    }
}

impl StagedPeerIdentity {
    /// Parse and validate a certificate chain and private key.
    ///
    /// `peer_ca_pem` is the relay peer CA bundle the listeners already trust;
    /// the leaf must verify against it as a client certificate at `now`.
    pub fn from_pem(
        certificate_pem: &[u8],
        private_key_pem: &[u8],
        peer_ca_pem: &[u8],
    ) -> Result<Self, PeerIdentityError> {
        let chain = parse_certificates(certificate_pem, "peer certificate")
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        let key = parse_private_key(private_key_pem)
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        let provider = ring_provider();
        let signing_key = provider
            .key_provider
            .load_private_key(key)
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        let certified = CertifiedKey::new(chain.clone(), signing_key);
        // Strict: an "unknown" consistency result is refused as well.  A
        // staged identity that cannot prove key/certificate agreement would
        // fail at the first handshake instead of here.
        certified
            .keys_match()
            .map_err(|_| PeerIdentityError::KeyMismatch)?;
        let identity = parse_leaf_identity(&chain)
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        if !identity.role().is_peer() {
            return Err(PeerIdentityError::NotPeerRole);
        }
        verify_against_peer_ca(&chain, peer_ca_pem, &provider)?;
        Ok(Self {
            certified: Arc::new(certified),
            identity,
        })
    }

    /// The staged leaf's public SPKI digest.
    #[must_use]
    pub fn spki_sha256(&self) -> SpkiSha256 {
        self.identity.spki_sha256()
    }

    /// The staged leaf's parsed public identity.
    #[must_use]
    pub fn identity(&self) -> &TlsIdentity {
        &self.identity
    }
}

fn verify_against_peer_ca(
    chain: &[CertificateDer<'static>],
    peer_ca_pem: &[u8],
    provider: &Arc<CryptoProvider>,
) -> Result<(), PeerIdentityError> {
    let verifier = require_client_ca_with_provider(peer_ca_pem, provider.clone())
        .map_err(|error| PeerIdentityError::Untrusted(error.to_string()))?;
    let (leaf, intermediates) = chain
        .split_first()
        .ok_or_else(|| PeerIdentityError::Unusable("empty certificate chain".into()))?;
    verifier
        .verify_client_cert(leaf, intermediates, UnixTime::now())
        .map_err(|error| PeerIdentityError::Untrusted(error.to_string()))?;
    Ok(())
}

struct IdentitySlot {
    certified: Arc<CertifiedKey>,
    spki: SpkiSha256,
    /// `None` only for a startup certificate whose role SAN did not parse,
    /// which `with_single_cert` used to accept; such a slot serves but can
    /// never be rotated.
    identity: Option<TlsIdentity>,
    generation: u64,
}

/// The relay's current private peer identity, shared by its QUIC server and
/// client configurations.
///
/// Every new handshake resolves the certificate through this slot, so an
/// [`install`](Self::install) takes effect for the next handshake in either
/// direction and never for one already completed.
pub struct RotatingPeerIdentity {
    slot: RwLock<Arc<IdentitySlot>>,
}

impl fmt::Debug for RotatingPeerIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let slot = self.current_slot();
        formatter
            .debug_struct("RotatingPeerIdentity")
            .field("generation", &slot.generation)
            .field("spki_sha256", &slot.spki.to_hex())
            .finish_non_exhaustive()
    }
}

impl RotatingPeerIdentity {
    /// Start with `initial` as generation 1.
    #[must_use]
    pub fn new(initial: StagedPeerIdentity) -> Arc<Self> {
        Arc::new(Self {
            slot: RwLock::new(Arc::new(IdentitySlot {
                certified: initial.certified,
                spki: initial.identity.spki_sha256(),
                identity: Some(initial.identity),
                generation: 1,
            })),
        })
    }

    /// Start from the relay's configured peer certificate at process start.
    ///
    /// This keeps the startup contract `with_single_cert` had: the chain is
    /// not re-verified here (peers verify it at every handshake), a key whose
    /// consistency rustls cannot establish is accepted, and a leaf whose role
    /// SAN does not parse still serves (peers refuse it at the handshake if
    /// they require the role).  Such a slot cannot be rotated.  A key that
    /// provably does not match its certificate is refused.  Successors staged later go through the strict
    /// [`StagedPeerIdentity::from_pem`].
    pub fn from_pem_at_startup(
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<Arc<Self>, PeerIdentityError> {
        let chain = parse_certificates(certificate_pem, "peer certificate")
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        let key = parse_private_key(private_key_pem)
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        let certified = CertifiedKey::from_der(chain.clone(), key, &ring_provider())
            .map_err(|_| PeerIdentityError::KeyMismatch)?;
        let leaf = chain
            .first()
            .ok_or_else(|| PeerIdentityError::Unusable("empty certificate chain".into()))?;
        let spki = crate::tls::spki_sha256_from_der(leaf.as_ref())
            .map_err(|error| PeerIdentityError::Unusable(error.to_string()))?;
        Ok(Arc::new(Self {
            slot: RwLock::new(Arc::new(IdentitySlot {
                certified: Arc::new(certified),
                spki,
                identity: parse_leaf_identity(&chain).ok(),
                generation: 1,
            })),
        }))
    }

    /// Validate and start from PEM files with the strict staging checks.
    pub fn from_pem(
        certificate_pem: &[u8],
        private_key_pem: &[u8],
        peer_ca_pem: &[u8],
    ) -> Result<Arc<Self>, PeerIdentityError> {
        StagedPeerIdentity::from_pem(certificate_pem, private_key_pem, peer_ca_pem).map(Self::new)
    }

    fn current_slot(&self) -> Arc<IdentitySlot> {
        // A poisoned lock can only follow a panic inside `install`, which
        // performs no fallible work while holding it; recover the value.
        match self.slot.read() {
            Ok(slot) => slot.clone(),
            Err(poisoned) => poisoned.into_inner().clone(),
        }
    }

    /// The SPKI digest new handshakes present.
    #[must_use]
    pub fn current_spki(&self) -> SpkiSha256 {
        self.current_slot().spki
    }

    /// The generation new handshakes present.  It starts at 1 and increases
    /// by one on every install.
    #[must_use]
    pub fn generation(&self) -> u64 {
        self.current_slot().generation
    }

    /// The public identity new handshakes present, when its role parsed.
    #[must_use]
    pub fn current_identity(&self) -> Option<TlsIdentity> {
        self.current_slot().identity.clone()
    }

    /// Check that `staged` may replace the current identity: same relay node,
    /// and every DNS/IP name the current certificate serves is still served.
    pub fn check_replacement(&self, staged: &StagedPeerIdentity) -> Result<(), PeerIdentityError> {
        let slot = self.current_slot();
        let current = slot
            .identity
            .as_ref()
            .ok_or(PeerIdentityError::CurrentIdentityUnverifiable)?;
        if staged.identity.role_id() != current.role_id() {
            return Err(PeerIdentityError::DifferentNode);
        }
        let covers = |name: &SanName| {
            !matches!(name, SanName::Dns(_) | SanName::Ip(_))
                || staged.identity.subject_alt_names().contains(name)
        };
        if !current.subject_alt_names().iter().all(covers) {
            return Err(PeerIdentityError::ServerNamesNarrowed);
        }
        Ok(())
    }

    /// Make `staged` the identity new handshakes present and return its
    /// generation.  Established connections keep what they negotiated.
    pub fn install(&self, staged: StagedPeerIdentity) -> Result<u64, PeerIdentityError> {
        self.check_replacement(&staged)?;
        let mut slot = match self.slot.write() {
            Ok(slot) => slot,
            Err(poisoned) => poisoned.into_inner(),
        };
        let generation = slot.generation.saturating_add(1);
        *slot = Arc::new(IdentitySlot {
            certified: staged.certified,
            spki: staged.identity.spki_sha256(),
            identity: Some(staged.identity),
            generation,
        });
        Ok(generation)
    }

    /// Build the private HTTP/3 server configuration resolving through this
    /// slot, with mandatory peer client authentication and ALPN `h3`.
    pub fn quinn_server_config(
        self: &Arc<Self>,
        peer_ca_pem: &[u8],
    ) -> Result<quinn::ServerConfig, TlsConfigError> {
        let provider = ring_provider();
        let mut config = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TlsConfigError::Rustls)?
            .with_client_cert_verifier(require_client_ca_with_provider(peer_ca_pem, provider)?)
            .with_cert_resolver(Arc::new(ServerResolver(self.clone())));
        config.alpn_protocols = vec![b"h3".to_vec()];
        disable_server_resumption(&mut config);
        load_quinn_server_config(Arc::new(config))
    }

    /// Build the private HTTP/3 client configuration resolving its client
    /// certificate through this slot, with server trust and ALPN `h3`.
    pub fn quinn_client_config(
        self: &Arc<Self>,
        server_ca_pem: &[u8],
    ) -> Result<quinn::ClientConfig, TlsConfigError> {
        let roots = require_root_certificates(server_ca_pem)?;
        let mut config = rustls::ClientConfig::builder_with_provider(ring_provider())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(TlsConfigError::Rustls)?
            .with_root_certificates(roots)
            .with_client_cert_resolver(Arc::new(ClientResolver(self.clone())));
        config.alpn_protocols = vec![b"h3".to_vec()];
        config.resumption = rustls::client::Resumption::disabled();
        config.enable_early_data = false;
        load_quinn_client_config(Arc::new(config))
    }
}

struct ServerResolver(Arc<RotatingPeerIdentity>);

impl fmt::Debug for ServerResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ServerResolver")
            .field(&self.0)
            .finish()
    }
}

impl ResolvesServerCert for ServerResolver {
    fn resolve(&self, _client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current_slot().certified.clone())
    }
}

struct ClientResolver(Arc<RotatingPeerIdentity>);

impl fmt::Debug for ClientResolver {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("ClientResolver")
            .field(&self.0)
            .finish()
    }
}

impl ResolvesClientCert for ClientResolver {
    fn resolve(
        &self,
        _root_hint_subjects: &[&[u8]],
        _sigschemes: &[SignatureScheme],
    ) -> Option<Arc<CertifiedKey>> {
        Some(self.0.current_slot().certified.clone())
    }

    fn has_certs(&self) -> bool {
        true
    }
}
