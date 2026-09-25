//! Reusable, synthetic M7 cluster fixture material.
//!
//! This module is deliberately a fixture layer rather than a relay runner. It
//! owns the resources that a three-node test needs before the production
//! membership, peer, and routing APIs are wired together:
//!
//! * one certificate per relay, issued by the existing dedicated peer CA;
//! * one reserved loopback TCP and UDP socket per relay;
//! * an operator-like membership/checkpoint authority whose private key never
//!   leaves this module; and
//! * a deterministic logical ingress fanout which does not create extra device
//!   sockets or ports.
//!
//! The signed records are opaque bytes to the catalog.  The future cluster
//! verifier should validate the payload and signature against the published
//! authority public key before accepting a record from Redis.  Redis is not
//! involved in constructing this fixture and cannot bootstrap its trust.

use crate::error::{HarnessError, Result};
use crate::pki::{CertificateAuthority, CertificateMaterial, FixturePki};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, TcpListener, UdpSocket};
use tunnel_catalog::SignedMembershipRecord as CatalogSignedMembershipRecord;
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
    RELAY_PEER_ROLE, RelayKey, SignedMembershipCheckpoint, SignedMembershipRecord,
};
use uuid::Uuid;

/// The number of relay identities and address pairs in the M7 fixture.
pub const M7_RELAY_COUNT: usize = 3;

/// The bounded lifetime used for synthetic membership and checkpoint records.
/// This is intentionally shorter than the test process lifetime so a test can
/// exercise the trust-expiry path without retaining a stale record forever.
pub const M7_MEMBERSHIP_LIFETIME: Duration = Duration::seconds(60);

const DEFAULT_DEPLOYMENT_ID: &str = "m7-fixture-deployment";
const DEFAULT_DEPLOYMENT_INCARNATION: &str = "m7-fixture-incarnation-1";
const DEFAULT_PUBLISHER_KEY_ID: &str = "m7-fixture-membership-authority-1";
const DEFAULT_SERVER_NAME: &str = "localhost";

/// A stable logical relay identity used by fixture records.
pub type RelayNodeId = String;

/// The four logical ingress classes exercised by the M7 routing gate.
///
/// A device still owns exactly one control and one active data WebSocket. The
/// classes below select which relay accepts each arrival; they do not allocate
/// another device port.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IngressKind {
    Control,
    ActiveData,
    ReplacementData,
    Consumer,
}

/// One node's reserved loopback addresses.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct LoopbackAddresses {
    /// TCP is the address used by a public/private TCP listener in a fixture
    /// process.  The fixture reserves it even when the current relay adapter
    /// is QUIC-only, so tests cannot accidentally collide with another node.
    pub tcp: SocketAddr,
    /// UDP is the address used by the private HTTP/3/QUIC listener.
    pub udp: SocketAddr,
}

/// A real loopback port reservation owned by a fixture node.
///
/// Keeping the listeners open until a test explicitly transfers them makes
/// port ownership visible and prevents a parallel test from racing an
/// address-only `bind(0)` probe.  A production listener can take ownership of
/// either socket with the `take_*` methods when its API accepts a pre-bound
/// socket.
pub struct LoopbackPortReservation {
    addresses: LoopbackAddresses,
    tcp: Option<TcpListener>,
    udp: Option<UdpSocket>,
}

impl fmt::Debug for LoopbackPortReservation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LoopbackPortReservation")
            .field("addresses", &self.addresses)
            .field("tcp_reserved", &self.tcp.is_some())
            .field("udp_reserved", &self.udp.is_some())
            .finish()
    }
}

impl LoopbackPortReservation {
    fn bind() -> Result<Self> {
        let tcp = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        tcp.set_nonblocking(true)?;
        let tcp_address = tcp.local_addr()?;

        // In a C11 child this also holds the TCP port with the same number, so
        // no CLI's TCP source address can print as this UDP endpoint.
        let udp = crate::c11_capture::bind_twinned_loopback_udp()?;
        udp.set_nonblocking(true)?;
        let udp_address = udp.local_addr()?;

        Ok(Self {
            addresses: LoopbackAddresses {
                tcp: tcp_address,
                udp: udp_address,
            },
            tcp: Some(tcp),
            udp: Some(udp),
        })
    }

    /// Return the currently owned addresses without releasing their sockets.
    pub fn addresses(&self) -> LoopbackAddresses {
        self.addresses
    }

    /// Transfer the pre-bound TCP listener to the caller.
    pub fn take_tcp(&mut self) -> Result<TcpListener> {
        self.tcp.take().ok_or_else(|| {
            HarnessError::InvalidInput(format!(
                "TCP loopback reservation {} was already transferred",
                self.addresses.tcp
            ))
        })
    }

    /// Transfer the pre-bound UDP socket to the caller.
    pub fn take_udp(&mut self) -> Result<UdpSocket> {
        self.udp.take().ok_or_else(|| {
            HarnessError::InvalidInput(format!(
                "UDP loopback reservation {} was already transferred",
                self.addresses.udp
            ))
        })
    }

    /// Release both sockets while retaining the addresses for diagnostics.
    pub fn release(&mut self) {
        self.tcp.take();
        self.udp.take();
    }

    /// Whether both address families remain reserved by this fixture.
    pub fn is_fully_reserved(&self) -> bool {
        self.tcp.is_some() && self.udp.is_some()
    }
}

/// One relay's synthetic identity, certificate, and owned loopback sockets.
pub struct RelayNodeFixture {
    pub node_id: RelayNodeId,
    /// A fresh process identity used when a test constructs an owner token.
    pub boot_id: String,
    pub addresses: LoopbackAddresses,
    /// The leaf is issued under `FixturePki::peer_ca`, which is separate from
    /// the device and public-server CAs.  Its private key is used only by a
    /// test process that explicitly takes ownership of the fixture.
    pub peer_certificate: CertificateMaterial,
    peer_ca_pem: String,
    ports: LoopbackPortReservation,
}

impl fmt::Debug for RelayNodeFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayNodeFixture")
            .field("node_id", &self.node_id)
            .field("boot_id", &self.boot_id)
            .field("addresses", &self.addresses)
            .field("peer_certificate_role", &self.peer_certificate.role)
            .field(
                "peer_certificate_fingerprint_sha256",
                &self.peer_certificate.certificate_fingerprint_sha256,
            )
            .field("ports", &self.ports)
            .finish()
    }
}

impl RelayNodeFixture {
    fn new(pki: &FixturePki, node_id: impl Into<String>) -> Result<Self> {
        let node_id = node_id.into();
        let peer_certificate = pki.issue_peer(node_id.clone())?;
        let ports = LoopbackPortReservation::bind()?;
        let addresses = ports.addresses();
        Ok(Self {
            node_id,
            boot_id: Uuid::new_v4().to_string(),
            addresses,
            peer_certificate,
            peer_ca_pem: pki.peer_ca.certificate_pem.clone(),
            ports,
        })
    }

    /// Return the full leaf-plus-CA PEM chain used by the peer TLS adapter.
    pub fn peer_certificate_chain_pem(&self) -> String {
        format!(
            "{}{}",
            self.peer_certificate.certificate_pem, self.peer_ca_pem
        )
    }

    /// Return the trusted peer CA PEM without exposing any issuing private key.
    pub fn peer_ca_pem(&self) -> &str {
        &self.peer_ca_pem
    }

    /// Return the leaf SPKI digest used in signed membership key entries.
    pub fn peer_spki_fingerprint(&self) -> Result<String> {
        self.peer_certificate.spki_fingerprint_sha256()
    }

    /// Transfer the node's reserved TCP listener.
    pub fn take_tcp_listener(&mut self) -> Result<TcpListener> {
        self.ports.take_tcp()
    }

    /// Transfer the node's reserved UDP socket.
    pub fn take_udp_socket(&mut self) -> Result<UdpSocket> {
        self.ports.take_udp()
    }

    /// Transfer the reserved UDP socket for this node's QUIC listener and
    /// release the TCP reservation, which no QUIC-only relay uses.
    ///
    /// Releasing the UDP reservation and binding its address again later is a
    /// race: anything else binding an ephemeral port in between, a sibling
    /// relay's peer client or UDP proxy among them, can be given that port,
    /// and the listener then fails `Address already in use` (M7-C118).  Bind
    /// the listener on the returned socket with [`quic_server_on`] instead.
    pub fn take_quic_socket(&mut self) -> Result<UdpSocket> {
        let socket = self.ports.take_udp()?;
        self.ports.release();
        Ok(socket)
    }

    /// Release both reservations.  The node's addresses remain available for
    /// diagnostics, but a later listener may bind them after this call.
    pub fn release_ports(&mut self) {
        self.ports.release();
    }

    /// Whether both address reservations are still held by this fixture.
    pub fn ports_reserved(&self) -> bool {
        self.ports.is_fully_reserved()
    }
}

/// Start a QUIC server endpoint on an already bound, reserved UDP socket.
pub fn quic_server_on(
    config: quinn::ServerConfig,
    socket: UdpSocket,
) -> std::io::Result<quinn::Endpoint> {
    let runtime = quinn::default_runtime().ok_or_else(|| {
        std::io::Error::other("no async runtime is available for the QUIC endpoint")
    })?;
    quinn::Endpoint::new(
        quinn::EndpointConfig::default(),
        Some(config),
        socket,
        runtime,
    )
}

/// Compatibility aliases for the cluster crate's canonical payload types.
/// Keeping the aliases in the harness lets acceptance code stay fixture
/// focused while the cluster crate remains the source of truth for the wire
/// schema and validation rules.
pub type FixturePeerKey = RelayKey;
pub type FixtureMembershipPayload = MembershipRecord;
pub type FixtureCheckpointPayload = MembershipCheckpoint;

/// Explicit signed-record inputs for a focused key-overlap/expiry fixture.
/// The caller still supplies only public certificate digests; the operator
/// issuer remains the sole signer and record lifetime is independently
/// bounded by the cluster verifier.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRecordOptions {
    pub record_version: u64,
    pub peer_endpoint: SocketAddr,
    pub keys: Vec<FixturePeerKey>,
    pub now: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

/// The parts of a relay node fixture a membership record actually commits to.
///
/// A long-running fixture has to re-sign its records from a background task,
/// which cannot borrow the node fixture itself.  Capturing exactly the two
/// committed values keeps that task honest: it can refresh a record's validity
/// window, and it cannot change which node or which peer certificate the
/// record names.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipNodeIdentity {
    pub node_id: String,
    pub peer_spki_sha256: String,
}

/// Explicit inputs for one signed membership record that uses the fixture's
/// default single-key set but needs a caller-chosen lifetime.
///
/// Grouped rather than passed positionally because the lifetime is the fourth
/// quantity that varies together with the record version, endpoint and issue
/// instant, and the same grouping is already how
/// [`MembershipRecordOptions`] carries an explicit key set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MembershipLifetimeOptions {
    pub record_version: u64,
    pub peer_endpoint: SocketAddr,
    pub now: DateTime<Utc>,
    pub lifetime: Duration,
}

/// A signed membership record with both the payload and opaque envelope bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedMembershipFixture {
    pub payload: FixtureMembershipPayload,
    pub signed: SignedMembershipRecord,
    encoded_bytes: Vec<u8>,
}

impl SignedMembershipFixture {
    /// Opaque bytes suitable for a `SignedMembershipRecord` or Redis value.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }

    /// Return the cluster crate's typed signed record.
    pub fn cluster_record(&self) -> &SignedMembershipRecord {
        &self.signed
    }

    /// Alias used by callers that do not need to name the cluster crate.
    pub fn signed_record(&self) -> &SignedMembershipRecord {
        self.cluster_record()
    }

    /// Convert to the catalog's intentionally opaque signed-record contract.
    pub fn catalog_record(&self) -> CatalogSignedMembershipRecord {
        CatalogSignedMembershipRecord {
            version: self.payload.record_version,
            bytes: self.encoded_bytes.clone(),
        }
    }
}

/// A signed checkpoint fixture.  Its nonce must be freshly generated by the
/// process starting a relay; a Redis snapshot cannot manufacture one.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SignedCheckpointFixture {
    pub payload: FixtureCheckpointPayload,
    pub signed: SignedMembershipCheckpoint,
    encoded_bytes: Vec<u8>,
}

impl SignedCheckpointFixture {
    /// Opaque signed checkpoint bytes for the cluster verifier.
    pub fn encoded_bytes(&self) -> &[u8] {
        &self.encoded_bytes
    }

    pub fn signed_checkpoint(&self) -> &SignedMembershipCheckpoint {
        &self.signed
    }
}

/// Operator-like test authority for signed membership and startup checkpoints.
///
/// The generated key is intentionally independent from every relay leaf key.
/// Only the public key and signed bytes are intended to be passed to relay
/// configuration; the private key remains private to this fixture authority.
pub struct TestMembershipAuthority {
    issuer: MembershipIssuer,
    public_key: [u8; 32],
}

impl fmt::Debug for TestMembershipAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TestMembershipAuthority")
            .field("key_id", &self.issuer.key_id())
            .field("public_key_present", &true)
            .finish_non_exhaustive()
    }
}

impl TestMembershipAuthority {
    /// Generate a fresh Ed25519 publisher key through the cluster crate's
    /// external-issuer helper.  Relays receive only its public key.
    pub fn new() -> Result<Self> {
        Self::with_key_id(DEFAULT_PUBLISHER_KEY_ID)
    }

    /// Generate a fresh publisher key with a caller-selected public key ID.
    pub fn with_key_id(key_id: impl Into<String>) -> Result<Self> {
        let (issuer, _pkcs8) = MembershipIssuer::generate(key_id)
            .map_err(|error| HarnessError::Pki(format!("generating membership signer: {error}")))?;
        let public_key = issuer
            .public_key()
            .map_err(|error| HarnessError::Pki(format!("reading membership signer: {error}")))?;
        Ok(Self { issuer, public_key })
    }

    pub fn key_id(&self) -> &str {
        self.issuer.key_id()
    }

    /// Return the operator-installed Ed25519 verification key bytes.
    pub fn public_key(&self) -> [u8; 32] {
        self.public_key
    }

    /// Construct the cluster verifier's trusted publisher key.
    pub fn trusted_key(&self) -> Result<tunnel_cluster::membership::TrustedPublisherKey> {
        tunnel_cluster::membership::TrustedPublisherKey::new(self.key_id(), self.public_key)
            .map_err(|error| {
                HarnessError::InvalidInput(format!("membership publisher key: {error}"))
            })
    }

    /// Sign one complete relay membership payload.
    pub fn sign_membership(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        node: &RelayNodeFixture,
        record_version: u64,
        now: DateTime<Utc>,
    ) -> Result<SignedMembershipFixture> {
        self.sign_membership_with_endpoint(
            deployment_id,
            deployment_incarnation,
            node,
            record_version,
            node.addresses.udp,
            now,
        )
    }

    /// Sign one relay membership record with an explicitly advertised peer
    /// endpoint.  Production fault fixtures use this to advertise a bounded
    /// UDP path proxy while the relay itself remains bound to its real private
    /// listener address.
    pub fn sign_membership_with_endpoint(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        node: &RelayNodeFixture,
        record_version: u64,
        peer_endpoint: SocketAddr,
        now: DateTime<Utc>,
    ) -> Result<SignedMembershipFixture> {
        self.sign_membership_with_endpoint_and_lifetime(
            deployment_id,
            deployment_incarnation,
            node,
            MembershipLifetimeOptions {
                record_version,
                peer_endpoint,
                now,
                lifetime: M7_MEMBERSHIP_LIFETIME,
            },
        )
    }

    /// Sign one relay membership record with an explicitly advertised peer
    /// endpoint **and an explicit record/key lifetime**.
    ///
    /// [`M7_MEMBERSHIP_LIFETIME`] is deliberately short so the trust-expiry
    /// gates can watch a record lapse inside a bounded run.  A long-running
    /// fixture that must stay continuously trusted (the production cluster,
    /// whose records are signed once at bootstrap and never re-signed) needs a
    /// lifetime that outlives its whole scenario instead, because the relay's
    /// trust deadline is
    /// `min(checkpoint_expiry, record.expires_at, peer_key.expires_at)` and
    /// only the checkpoint is minted fresh on each reconcile pass.
    pub fn sign_membership_with_endpoint_and_lifetime(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        node: &RelayNodeFixture,
        options: MembershipLifetimeOptions,
    ) -> Result<SignedMembershipFixture> {
        self.sign_membership_identity(
            deployment_id,
            deployment_incarnation,
            &MembershipNodeIdentity {
                node_id: node.node_id.clone(),
                peer_spki_sha256: node.peer_spki_fingerprint()?,
            },
            options,
        )
    }

    /// Sign one membership record from the node identity alone.
    ///
    /// This is the form a background re-signer uses.  It exists because the
    /// relay's verifier caps a record's lifetime at the product maximum, so a
    /// fixture whose scenario outlives that cap cannot buy itself a longer
    /// record; it has to keep issuing fresh ones inside the cap, exactly as a
    /// real control plane does.  The caller supplies a strictly increasing
    /// record version, since the verifier replaces a record only with a newer
    /// one.
    pub fn sign_membership_identity(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        identity: &MembershipNodeIdentity,
        options: MembershipLifetimeOptions,
    ) -> Result<SignedMembershipFixture> {
        let MembershipLifetimeOptions {
            record_version,
            peer_endpoint,
            now,
            lifetime,
        } = options;
        let payload = FixtureMembershipPayload {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: deployment_id.to_owned(),
            deployment_incarnation: deployment_incarnation.to_owned(),
            node_id: identity.node_id.clone(),
            record_version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: peer_endpoint.to_string(),
            server_name: DEFAULT_SERVER_NAME.to_owned(),
            keys: vec![FixturePeerKey {
                key_id: format!("{}-peer", identity.node_id),
                spki_sha256: identity.peer_spki_sha256.clone(),
                not_before: now,
                expires_at: now + lifetime,
                revoked: false,
            }],
            issued_at: now,
            not_before: now,
            expires_at: now + lifetime,
        };
        let signed = self
            .issuer
            .sign_membership(payload.clone())
            .map_err(|error| HarnessError::Pki(format!("signing membership payload: {error}")))?;
        let encoded_bytes = signed
            .encode()
            .map_err(|error| HarnessError::Pki(format!("encoding membership payload: {error}")))?;
        Ok(SignedMembershipFixture {
            payload,
            signed,
            encoded_bytes,
        })
    }

    /// Sign a relay record with an explicit bounded key set and record
    /// lifetime.  This is used by the real process fixture to let one
    /// authenticated certificate expire while a signed overlap record and
    /// the rest of the deployment remain valid.
    pub fn sign_membership_with_endpoint_and_keys(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        node: &RelayNodeFixture,
        options: MembershipRecordOptions,
    ) -> Result<SignedMembershipFixture> {
        if options.record_version == 0 || options.keys.is_empty() {
            return Err(HarnessError::InvalidInput(
                "signed membership record options are incomplete".into(),
            ));
        }
        let payload = FixtureMembershipPayload {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: deployment_id.to_owned(),
            deployment_incarnation: deployment_incarnation.to_owned(),
            node_id: node.node_id.clone(),
            record_version: options.record_version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: options.peer_endpoint.to_string(),
            server_name: DEFAULT_SERVER_NAME.to_owned(),
            keys: options.keys,
            issued_at: options.now,
            not_before: options.now,
            expires_at: options.expires_at,
        };
        let signed = self
            .issuer
            .sign_membership(payload.clone())
            .map_err(|error| HarnessError::Pki(format!("signing membership payload: {error}")))?;
        let encoded_bytes = signed
            .encode()
            .map_err(|error| HarnessError::Pki(format!("encoding membership payload: {error}")))?;
        Ok(SignedMembershipFixture {
            payload,
            signed,
            encoded_bytes,
        })
    }

    /// Sign a nonce-bound startup checkpoint for the supplied record versions.
    pub fn sign_checkpoint(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        nonce: impl Into<String>,
        minimum_record_versions: BTreeMap<RelayNodeId, u64>,
        now: DateTime<Utc>,
    ) -> Result<SignedCheckpointFixture> {
        self.sign_checkpoint_with_version(
            deployment_id,
            deployment_incarnation,
            1,
            nonce,
            minimum_record_versions,
            now,
        )
    }

    /// Sign a checkpoint with an explicit monotonic version.  Refreshing a
    /// verifier checkpoint must advance this value; a new nonce alone is not
    /// an equal-version replacement proof.
    pub fn sign_checkpoint_with_version(
        &self,
        deployment_id: &str,
        deployment_incarnation: &str,
        checkpoint_version: u64,
        nonce: impl Into<String>,
        minimum_record_versions: BTreeMap<RelayNodeId, u64>,
        now: DateTime<Utc>,
    ) -> Result<SignedCheckpointFixture> {
        if checkpoint_version == 0 {
            return Err(HarnessError::InvalidInput(
                "membership checkpoint version must be non-zero".to_owned(),
            ));
        }
        let payload = FixtureCheckpointPayload {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: deployment_id.to_owned(),
            deployment_incarnation: deployment_incarnation.to_owned(),
            checkpoint_version,
            nonce: nonce.into(),
            minimum_versions: minimum_record_versions,
            issued_at: now,
            not_before: now,
            expires_at: now + M7_MEMBERSHIP_LIFETIME,
        };
        let signed = self
            .issuer
            .sign_checkpoint(payload.clone())
            .map_err(|error| {
                HarnessError::Pki(format!("signing membership checkpoint: {error}"))
            })?;
        let encoded_bytes = signed.encode().map_err(|error| {
            HarnessError::Pki(format!("encoding membership checkpoint: {error}"))
        })?;
        Ok(SignedCheckpointFixture {
            payload,
            signed,
            encoded_bytes,
        })
    }
}

/// The complete three-node fixture foundation.
pub struct ClusterFixture {
    pub deployment_id: String,
    pub deployment_incarnation: String,
    pub peer_ca: CertificateAuthority,
    pub membership_authority: TestMembershipAuthority,
    pub nodes: Vec<RelayNodeFixture>,
    pub memberships: BTreeMap<RelayNodeId, SignedMembershipFixture>,
    pub checkpoint: SignedCheckpointFixture,
    pub ingress: IngressFanout,
}

impl fmt::Debug for ClusterFixture {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClusterFixture")
            .field("deployment_id", &self.deployment_id)
            .field("deployment_incarnation", &self.deployment_incarnation)
            .field("peer_ca", &self.peer_ca)
            .field("membership_authority", &self.membership_authority)
            .field("nodes", &self.nodes)
            .field("membership_count", &self.memberships.len())
            .field("checkpoint", &self.checkpoint)
            .field("ingress", &self.ingress)
            .finish()
    }
}

impl ClusterFixture {
    /// Build three relay identities and reserve one TCP/UDP pair per node.
    ///
    /// The caller supplies the already-created M1 fixture PKI.  No second CA
    /// is generated here: all peer leaves share the existing dedicated peer CA
    /// while each call to `issue_peer` creates a distinct key and certificate.
    pub fn new(pki: &FixturePki) -> Result<Self> {
        Self::with_deployment(pki, DEFAULT_DEPLOYMENT_ID, DEFAULT_DEPLOYMENT_INCARNATION)
    }

    /// Build the fixture with explicit deployment identity values.
    pub fn with_deployment(
        pki: &FixturePki,
        deployment_id: impl Into<String>,
        deployment_incarnation: impl Into<String>,
    ) -> Result<Self> {
        let deployment_id = deployment_id.into();
        let deployment_incarnation = deployment_incarnation.into();
        validate_identifier(&deployment_id, "deployment ID")?;
        validate_identifier(&deployment_incarnation, "deployment incarnation")?;

        let node_names = ["relay-a", "relay-b", "relay-c"];
        let mut nodes = Vec::with_capacity(M7_RELAY_COUNT);
        for node_name in node_names {
            nodes.push(RelayNodeFixture::new(pki, node_name)?);
        }
        let ingress = IngressFanout::for_nodes(&nodes)?;
        let membership_authority = TestMembershipAuthority::new()?;
        let now = Utc::now();
        let mut memberships = BTreeMap::new();
        let mut minimum_record_versions = BTreeMap::new();
        for node in &nodes {
            let membership = membership_authority.sign_membership(
                &deployment_id,
                &deployment_incarnation,
                node,
                1,
                now,
            )?;
            minimum_record_versions.insert(node.node_id.clone(), membership.payload.record_version);
            memberships.insert(node.node_id.clone(), membership);
        }
        let checkpoint = membership_authority.sign_checkpoint_with_version(
            &deployment_id,
            &deployment_incarnation,
            1,
            fresh_nonce(),
            minimum_record_versions,
            now,
        )?;
        let peer_ca = pki.peer_ca.clone();
        Ok(Self {
            deployment_id,
            deployment_incarnation,
            peer_ca,
            membership_authority,
            nodes,
            memberships,
            checkpoint,
            ingress,
        })
    }

    pub fn node(&self, node_id: &str) -> Option<&RelayNodeFixture> {
        self.nodes.iter().find(|node| node.node_id == node_id)
    }

    pub fn node_mut(&mut self, node_id: &str) -> Option<&mut RelayNodeFixture> {
        self.nodes.iter_mut().find(|node| node.node_id == node_id)
    }

    pub fn membership(&self, node_id: &str) -> Option<&SignedMembershipFixture> {
        self.memberships.get(node_id)
    }

    /// Make a fresh checkpoint for a caller-provided startup nonce.  This is
    /// the intended boundary for a real relay bootstrap flow.
    pub fn checkpoint_for_nonce(
        &self,
        nonce: impl Into<String>,
    ) -> Result<SignedCheckpointFixture> {
        let minimum_record_versions = self
            .memberships
            .iter()
            .map(|(node_id, membership)| (node_id.clone(), membership.payload.record_version))
            .collect();
        self.membership_authority.sign_checkpoint_with_version(
            &self.deployment_id,
            &self.deployment_incarnation,
            self.checkpoint.payload.checkpoint_version.saturating_add(1),
            nonce,
            minimum_record_versions,
            Utc::now(),
        )
    }

    pub fn node_for_ingress(&self, kind: IngressKind) -> Option<&RelayNodeFixture> {
        self.node(self.ingress.node_for(kind))
    }
}

/// Deterministic role-to-node fanout for a three-node acceptance run.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct IngressFanout {
    pub control: RelayNodeId,
    pub active_data: RelayNodeId,
    pub replacement_data: RelayNodeId,
    pub consumer: RelayNodeId,
}

impl IngressFanout {
    /// Assign control to node A, active data to B, replacement data to C, and
    /// consumer ingress to B.  The consumer path is therefore non-owner when
    /// the initial control arrival selects A, while every class is still
    /// routed through an existing relay address and device socket.
    pub fn for_nodes(nodes: &[RelayNodeFixture]) -> Result<Self> {
        if nodes.len() < M7_RELAY_COUNT {
            return Err(HarnessError::InvalidInput(format!(
                "M7 ingress fanout requires at least {M7_RELAY_COUNT} relay nodes"
            )));
        }
        Self::from_node_ids([
            nodes[0].node_id.clone(),
            nodes[1].node_id.clone(),
            nodes[2].node_id.clone(),
        ])
    }

    /// Construct the fixed three-node assignment from stable node IDs.
    pub fn from_node_ids(node_ids: [RelayNodeId; M7_RELAY_COUNT]) -> Result<Self> {
        if node_ids.iter().any(|id| id.trim().is_empty()) {
            return Err(HarnessError::InvalidInput(
                "M7 ingress fanout node IDs must be non-empty".to_owned(),
            ));
        }
        Ok(Self {
            control: node_ids[0].clone(),
            active_data: node_ids[1].clone(),
            replacement_data: node_ids[2].clone(),
            consumer: node_ids[1].clone(),
        })
    }

    pub fn node_for(&self, kind: IngressKind) -> &str {
        match kind {
            IngressKind::Control => &self.control,
            IngressKind::ActiveData => &self.active_data,
            IngressKind::ReplacementData => &self.replacement_data,
            IngressKind::Consumer => &self.consumer,
        }
    }
}

fn validate_identifier(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 {
        return Err(HarnessError::InvalidInput(format!(
            "{label} must be 1..=128 bytes"
        )));
    }
    Ok(())
}

fn fresh_nonce() -> String {
    Uuid::new_v4().simple().to_string()
}

#[cfg(test)]
mod tests {
    use super::{ClusterFixture, FixturePki, IngressFanout, IngressKind};
    use chrono::Utc;
    use std::collections::BTreeSet;
    use std::net::{TcpListener, UdpSocket};
    use tunnel_cluster::membership::{MembershipPolicy, MembershipVerifier, PrivateEndpointPolicy};

    #[test]
    fn cluster_fixture_has_three_distinct_peer_leaves_and_owned_ports() {
        let pki = FixturePki::new().expect("fixture PKI");
        let fixture = ClusterFixture::new(&pki).expect("cluster fixture");
        assert_eq!(fixture.nodes.len(), 3);
        let fingerprints = fixture
            .nodes
            .iter()
            .map(|node| node.peer_certificate.certificate_fingerprint_sha256.clone())
            .collect::<BTreeSet<_>>();
        assert_eq!(fingerprints.len(), 3);
        assert!(fixture.nodes.iter().all(|node| node.ports_reserved()));
        assert!(
            fixture
                .nodes
                .iter()
                .all(|node| node.peer_certificate.role == crate::pki::CertificateRole::Peer)
        );
        assert!(
            fixture
                .memberships
                .values()
                .all(|membership| !membership.signed.signature.is_empty())
        );
        assert!(!fixture.checkpoint.signed.signature.is_empty());
        assert_ne!(
            fixture.nodes[0].peer_certificate.private_key_pem,
            fixture.nodes[1].peer_certificate.private_key_pem
        );
    }

    #[test]
    fn records_verify_through_the_cluster_membership_policy() {
        let pki = FixturePki::new().expect("fixture PKI");
        let fixture = ClusterFixture::new(&pki).expect("cluster fixture");
        let ports = fixture
            .nodes
            .iter()
            .map(|node| node.addresses.udp.port())
            .collect::<BTreeSet<_>>();
        let policy = MembershipPolicy::new(
            &fixture.deployment_id,
            &fixture.deployment_incarnation,
            PrivateEndpointPolicy::allowlisted(["127.0.0.1"], ["localhost"], ports)
                .expect("endpoint policy"),
        )
        .expect("membership policy");
        let mut verifier = MembershipVerifier::new(
            policy,
            [fixture
                .membership_authority
                .trusted_key()
                .expect("trusted publisher")],
        )
        .expect("membership verifier");
        verifier
            .verify_checkpoint(
                fixture.checkpoint.encoded_bytes(),
                &fixture.checkpoint.payload.nonce,
                Utc::now(),
            )
            .expect("checkpoint");
        for membership in fixture.memberships.values() {
            verifier
                .verify_membership(membership.encoded_bytes(), Utc::now())
                .expect("membership");
        }
    }

    #[test]
    fn reservations_prevent_address_reuse_until_transferred() {
        let pki = FixturePki::new().expect("fixture PKI");
        let mut fixture = ClusterFixture::new(&pki).expect("cluster fixture");
        let addresses = fixture.nodes[0].addresses;
        assert!(TcpListener::bind(addresses.tcp).is_err());
        assert!(UdpSocket::bind(addresses.udp).is_err());
        let tcp = fixture.nodes[0]
            .take_tcp_listener()
            .expect("take TCP reservation");
        let udp = fixture.nodes[0]
            .take_udp_socket()
            .expect("take UDP reservation");
        assert_eq!(
            tcp.local_addr().expect("transferred TCP address"),
            addresses.tcp
        );
        assert_eq!(
            udp.local_addr().expect("transferred UDP address"),
            addresses.udp
        );
        assert!(TcpListener::bind(addresses.tcp).is_err());
        assert!(UdpSocket::bind(addresses.udp).is_err());
        assert!(fixture.nodes[0].take_tcp_listener().is_err());
        assert!(fixture.nodes[0].take_udp_socket().is_err());
        // Ownership transfer keeps the ports reserved. After these handles
        // are dropped, other concurrent fixtures may legitimately acquire
        // the ports, so an immediate successful rebind is not guaranteed.
    }

    #[test]
    fn fanout_reuses_existing_three_nodes_without_new_device_ports() {
        let fanout = IngressFanout::from_node_ids([
            "relay-a".to_owned(),
            "relay-b".to_owned(),
            "relay-c".to_owned(),
        ])
        .expect("fanout");
        assert_eq!(fanout.node_for(IngressKind::Control), "relay-a");
        assert_eq!(fanout.node_for(IngressKind::ActiveData), "relay-b");
        assert_eq!(fanout.node_for(IngressKind::ReplacementData), "relay-c");
        assert_eq!(fanout.node_for(IngressKind::Consumer), "relay-b");
    }

    /// Task row M7-C118: a QUIC listener started on a node's reserved socket
    /// holds that node's address throughout, while the old release-then-bind
    /// path leaves a window in which anything else can take the port.
    #[tokio::test]
    async fn quic_listener_binds_the_reserved_socket_without_releasing_its_port() {
        let pki = FixturePki::new().expect("fixture PKI");
        let mut fixture = ClusterFixture::new(&pki).expect("cluster fixture");
        let server_config = |node: &super::RelayNodeFixture| {
            tunnel_transport::load_peer_server_config_from_pem(
                node.peer_certificate_chain_pem().as_bytes(),
                node.peer_certificate.private_key_pem.as_bytes(),
                node.peer_ca_pem().as_bytes(),
            )
            .expect("peer server TLS")
        };

        let reserved = fixture.nodes[0].addresses.udp;
        let socket = fixture.nodes[0]
            .take_quic_socket()
            .expect("take the QUIC reservation");
        assert!(
            UdpSocket::bind(reserved).is_err(),
            "the reserved port was free to take"
        );
        let endpoint = super::quic_server_on(server_config(&fixture.nodes[0]), socket)
            .expect("listener on the reserved socket");
        assert_eq!(endpoint.local_addr().expect("listener address"), reserved);
        endpoint.close(0_u32.into(), b"test done");

        // Control: releasing first lets another socket take the port, and
        // the listener then fails exactly as the hosted gate did.
        let released = fixture.nodes[1].addresses.udp;
        fixture.nodes[1].release_ports();
        // If this bind fails, something else already took the released port,
        // which is the race itself; either way the port is now held.
        let _thief = UdpSocket::bind(released).ok();
        let error = quinn::Endpoint::server(server_config(&fixture.nodes[1]), released)
            .expect_err("rebinding a taken port");
        assert_eq!(error.kind(), std::io::ErrorKind::AddrInUse);
    }
}
