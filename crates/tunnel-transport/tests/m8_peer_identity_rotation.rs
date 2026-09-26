//! Live peer identity rotation at the transport layer (task rows M8-C28,
//! M8-C45).
//!
//! A relay's private HTTP/3 server and client configurations resolve their
//! certificate through one [`RotatingPeerIdentity`].  These tests prove, over
//! real QUIC/TLS handshakes, that an install changes what **new** handshakes
//! present in both directions, that an already established connection keeps
//! the identity it negotiated and keeps serving, and that a pooled client
//! connection under a superseded identity drains instead of carrying new
//! streams, and is closed when its generation is retired.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{sync::watch, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    ApprovedPeerPins, MAX_ROTATION_DRAINING_CONNECTIONS, PeerClient, PeerDestination,
    PeerIdentityError, PeerServer, PeerTransportError, PeerTransportLimits, RotatingPeerIdentity,
    SharedPeerPins, SpkiSha256, StagedPeerIdentity, TlsIdentity, spki_sha256_from_der,
};

const SERVER_NAME: &str = "localhost";
const CASE_TIMEOUT: Duration = Duration::from_secs(5);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Leaf {
    chain_pem: String,
    private_key_pem: String,
    spki: SpkiSha256,
}

struct Pki {
    ca: Certificate,
    ca_key: KeyPair,
    ca_pem: String,
}

impl Pki {
    fn new(name: &str) -> Self {
        let ca_key = KeyPair::generate().expect("rotation CA key");
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, name);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params
            .self_signed(&ca_key)
            .expect("rotation CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue(&self, role_uri: &str, dns: &[&str]) -> Leaf {
        let key = KeyPair::generate().expect("rotation leaf key");
        let mut params = CertificateParams::new(
            dns.iter()
                .map(|name| (*name).to_owned())
                .collect::<Vec<_>>(),
        )
        .expect("rotation leaf params");
        params
            .distinguished_name
            .push(DnType::CommonName, role_uri.to_owned());
        params
            .subject_alt_names
            .push(SanType::URI(role_uri.try_into().expect("role URI")));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("rotation leaf certificate");
        Leaf {
            chain_pem: format!("{}{}", certificate.pem(), self.ca_pem),
            private_key_pem: key.serialize_pem(),
            spki: spki_sha256_from_der(certificate.der()).expect("rotation leaf SPKI"),
        }
    }

    fn peer(&self, node: &str) -> Leaf {
        self.issue(&format!("urn:agent-tunnel:peer:{node}"), &[SERVER_NAME])
    }

    fn staged(&self, leaf: &Leaf) -> StagedPeerIdentity {
        StagedPeerIdentity::from_pem(
            leaf.chain_pem.as_bytes(),
            leaf.private_key_pem.as_bytes(),
            self.ca_pem.as_bytes(),
        )
        .expect("staged rotation identity")
    }
}

fn limits() -> PeerTransportLimits {
    PeerTransportLimits {
        handshake_timeout: CASE_TIMEOUT,
        stream_timeout: CASE_TIMEOUT,
        idle_timeout: CASE_TIMEOUT,
        drain_timeout: Duration::from_secs(3),
        ..PeerTransportLimits::default()
    }
}

/// A peer server whose `/who` answers with the SPKI digest of the client
/// certificate that completed *this connection's* handshake, and whose
/// `/hold` does the same only after `release` flips.
struct Server {
    destination: PeerDestination,
    cancel: CancellationToken,
    task: JoinHandle<Result<(), PeerTransportError>>,
}

impl Server {
    fn start(
        pki: &Pki,
        identity: &Arc<RotatingPeerIdentity>,
        client_pins: &[SpkiSha256],
        release: watch::Receiver<bool>,
    ) -> Self {
        let mut config = identity
            .quinn_server_config(pki.ca_pem.as_bytes())
            .expect("rotating server config");
        limits()
            .apply_to_server_config(&mut config)
            .expect("server limits");
        let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("rotating server endpoint");
        let address = endpoint.local_addr().expect("server address");
        let pins = SharedPeerPins::new(
            ApprovedPeerPins::new(client_pins.iter().copied()).expect("client pins"),
        )
        .expect("client pin provider");
        let handler = move |identity: TlsIdentity,
                            request: Request<()>,
                            mut stream: tunnel_transport::PeerServerStream| {
            let mut release = release.clone();
            async move {
                if request.uri().path() == "/hold" {
                    while !*release.borrow() {
                        release
                            .changed()
                            .await
                            .map_err(|_| PeerTransportError::Cancelled)?;
                    }
                }
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|_| PeerTransportError::H3("response".into()))?;
                stream.send_response(response).await?;
                stream
                    .send_chunk(Bytes::from(identity.spki_sha256().to_hex()))
                    .await?;
                stream.finish().await
            }
        };
        let server = PeerServer::new_with_pin_provider(
            endpoint,
            pins,
            limits(),
            |_identity: &TlsIdentity, _request: &Request<()>| true,
            handler,
        )
        .expect("rotating peer server");
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { server.serve(task_cancel).await });
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            cancel,
            task,
        }
    }

    async fn stop(self) {
        self.cancel.cancel();
        let _ = timeout(CASE_TIMEOUT, self.task).await;
    }
}

fn client(
    pki: &Pki,
    identity: &Arc<RotatingPeerIdentity>,
    server_pins: &[SpkiSha256],
    track: bool,
) -> PeerClient {
    let mut config = identity
        .quinn_client_config(pki.ca_pem.as_bytes())
        .expect("rotating client config");
    limits()
        .apply_to_client_config(&mut config)
        .expect("client limits");
    let mut endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).expect("client endpoint");
    endpoint.set_default_client_config(config);
    let client = PeerClient::new(
        endpoint,
        ApprovedPeerPins::new(server_pins.iter().copied()).expect("server pins"),
        limits(),
    )
    .expect("peer client");
    if track {
        client.with_local_identity(Arc::clone(identity))
    } else {
        client
    }
}

async fn body_of(mut stream: tunnel_transport::PeerClientStream) -> TestResult<String> {
    stream.finish().await?;
    read_body(stream).await
}

/// Open a request and end its (empty) request body at once, so a server
/// that answers later never meets an unfinished request.
async fn open_finished(
    pool: &PeerClient,
    destination: &PeerDestination,
    path: &str,
) -> TestResult<tunnel_transport::PeerClientStream> {
    let mut stream = pool.open(destination.clone(), get(path)).await?;
    stream.finish().await?;
    Ok(stream)
}

async fn read_body(mut stream: tunnel_transport::PeerClientStream) -> TestResult<String> {
    let response = timeout(CASE_TIMEOUT, stream.recv_response()).await??;
    if response.status() != StatusCode::OK {
        return Err(format!("unexpected status {}", response.status()).into());
    }
    let mut body = Vec::new();
    while let Some(chunk) = timeout(CASE_TIMEOUT, stream.recv_chunk()).await?? {
        body.extend_from_slice(chunk.as_bytes());
    }
    Ok(String::from_utf8(body)?)
}

fn get(path: &str) -> Request<()> {
    Request::builder()
        .method("GET")
        .uri(format!("https://{SERVER_NAME}{path}"))
        .body(())
        .expect("request")
}

#[tokio::test]
async fn a_server_install_changes_new_handshakes_and_keeps_established_connections() -> TestResult {
    let pki = Pki::new("rotation server CA");
    let first = pki.peer("relay-a");
    let second = pki.peer("relay-a");
    let dialer = pki.peer("relay-b");
    let server_identity = RotatingPeerIdentity::new(pki.staged(&first));
    let dialer_identity = RotatingPeerIdentity::new(pki.staged(&dialer));
    let (_release_tx, release) = watch::channel(true);
    let server = Server::start(&pki, &server_identity, &[dialer.spki], release);
    let pins = [first.spki, second.spki];

    let before = client(&pki, &dialer_identity, &pins, false);
    let established = before.connect(server.destination.clone()).await?;
    assert_eq!(established.peer_identity().spki_sha256(), first.spki);

    let generation = server_identity.install(pki.staged(&second))?;
    assert_eq!(generation, 2);
    assert_eq!(server_identity.current_spki(), second.spki);

    // A fresh handshake presents the successor.
    let after = client(&pki, &dialer_identity, &pins, false);
    let fresh = after.connect(server.destination.clone()).await?;
    assert_eq!(fresh.peer_identity().spki_sha256(), second.spki);

    // The connection established before the install still presents -- and
    // serves under -- the predecessor.
    assert_eq!(established.peer_identity().spki_sha256(), first.spki);
    let served = body_of(established.open(get("/who")).await?).await?;
    assert_eq!(served, dialer.spki.to_hex());

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn a_client_install_drains_the_superseded_connection_and_dials_with_the_successor()
-> TestResult {
    let pki = Pki::new("rotation client CA");
    let server_leaf = pki.peer("relay-owner");
    let first = pki.peer("relay-ingress");
    let second = pki.peer("relay-ingress");
    let third = pki.peer("relay-ingress");
    let server_identity = RotatingPeerIdentity::new(pki.staged(&server_leaf));
    let (release_tx, release) = watch::channel(false);
    let server = Server::start(
        &pki,
        &server_identity,
        &[first.spki, second.spki, third.spki],
        release,
    );
    let local = RotatingPeerIdentity::new(pki.staged(&first));
    let pool = client(&pki, &local, &[server_leaf.spki], true);

    assert_eq!(
        body_of(pool.open(server.destination.clone(), get("/who")).await?).await?,
        first.spki.to_hex()
    );
    // A stream in flight on the generation-1 connection.
    let held = pool.open(server.destination.clone(), get("/hold")).await?;

    local.install(pki.staged(&second))?;
    // New streams ride a new connection presenting the successor ...
    assert_eq!(
        body_of(pool.open(server.destination.clone(), get("/who")).await?).await?,
        second.spki.to_hex()
    );
    assert_eq!(pool.draining_connection_count(), 1);
    // ... while the in-flight stream completes on the predecessor.
    release_tx.send(true)?;
    assert_eq!(body_of(held).await?, first.spki.to_hex());

    // Retirement closes a superseded connection that still carries a stream.
    release_tx.send(false)?;
    let held = pool.open(server.destination.clone(), get("/hold")).await?;
    local.install(pki.staged(&third))?;
    assert_eq!(
        body_of(pool.open(server.destination.clone(), get("/who")).await?).await?,
        third.spki.to_hex()
    );
    assert!(pool.retire_local_generations_before(3).await >= 1);
    let error = body_of(held)
        .await
        .expect_err("a stream on a retired generation must end with an error");
    assert!(
        matches!(
            error.downcast_ref::<PeerTransportError>(),
            Some(PeerTransportError::LocalIdentityRetired)
        ),
        "a caller on a retired generation must see the typed cause, got {error}"
    );
    assert_eq!(pool.draining_connection_count(), 0);

    server.stop().await;
    Ok(())
}

#[tokio::test]
async fn the_drain_set_is_bounded_and_a_full_set_keeps_the_predecessor_serving() -> TestResult {
    // M7-C154.  Five destinations each carry an in-flight stream on a
    // generation-1 connection when the local identity changes.  Four drain
    // and redial under the successor; the fifth finds the bounded drain set
    // full and keeps using its predecessor -- which the overlap still
    // approves -- rather than tearing its stream down or exceeding the bound.
    let pki = Pki::new("rotation drain-bound CA");
    let first = pki.peer("relay-ingress");
    let second = pki.peer("relay-ingress");
    let (release_tx, release) = watch::channel(false);
    let mut servers = Vec::new();
    for index in 0..=MAX_ROTATION_DRAINING_CONNECTIONS {
        let leaf = pki.peer(&format!("relay-owner-{index}"));
        let identity = RotatingPeerIdentity::new(pki.staged(&leaf));
        let server = Server::start(&pki, &identity, &[first.spki, second.spki], release.clone());
        servers.push((server, leaf.spki));
    }
    let local = RotatingPeerIdentity::new(pki.staged(&first));
    let server_pins: Vec<SpkiSha256> = servers.iter().map(|(_, spki)| *spki).collect();
    let pool = client(&pki, &local, &server_pins, true);
    let mut held = Vec::new();
    for (server, _) in &servers {
        held.push(open_finished(&pool, &server.destination, "/hold").await?);
    }
    local.install(pki.staged(&second))?;
    let mut bodies = Vec::new();
    for (server, _) in &servers {
        let stream = pool
            .open(server.destination.clone(), get("/who"))
            .await
            .map_err(|error| format!("who open: {error}"))?;
        bodies.push(
            body_of(stream)
                .await
                .map_err(|error| format!("who body: {error}"))?,
        );
    }
    release_tx.send(true)?;
    let successors = bodies
        .iter()
        .filter(|body| **body == second.spki.to_hex())
        .count();
    assert_eq!(successors, MAX_ROTATION_DRAINING_CONNECTIONS);
    assert_eq!(bodies.last(), Some(&first.spki.to_hex()));
    for (index, stream) in held.into_iter().enumerate() {
        let body = read_body(stream)
            .await
            .map_err(|error| format!("held body {index}: {error}"))?;
        assert_eq!(body, first.spki.to_hex());
    }
    // Once the drained connections have closed, the fifth destination drains
    // too and moves to the successor.
    let deadline = std::time::Instant::now() + CASE_TIMEOUT;
    while pool.draining_connection_count() > 0 && std::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let last = &servers.last().expect("five servers").0;
    assert_eq!(
        body_of(pool.open(last.destination.clone(), get("/who")).await?).await?,
        second.spki.to_hex()
    );
    for (server, _) in servers {
        server.stop().await;
    }
    Ok(())
}

#[tokio::test]
async fn an_untracked_client_keeps_its_pooled_connection_across_an_install() -> TestResult {
    // The control for the drain test above: without `with_local_identity`
    // the pool has no generation to compare, so it reuses the connection and
    // the server keeps seeing the predecessor.  This is what every relay did
    // before M8-C45, and why the relay must opt in.
    let pki = Pki::new("rotation control CA");
    let server_leaf = pki.peer("relay-owner");
    let first = pki.peer("relay-ingress");
    let second = pki.peer("relay-ingress");
    let server_identity = RotatingPeerIdentity::new(pki.staged(&server_leaf));
    let (_release_tx, release) = watch::channel(true);
    let server = Server::start(&pki, &server_identity, &[first.spki, second.spki], release);
    let local = RotatingPeerIdentity::new(pki.staged(&first));
    let pool = client(&pki, &local, &[server_leaf.spki], false);
    body_of(pool.open(server.destination.clone(), get("/who")).await?).await?;
    local.install(pki.staged(&second))?;
    assert_eq!(
        body_of(pool.open(server.destination.clone(), get("/who")).await?).await?,
        first.spki.to_hex()
    );
    server.stop().await;
    Ok(())
}

#[test]
fn a_candidate_identity_is_refused_unless_it_is_the_same_relay_under_the_same_ca() {
    let pki = Pki::new("rotation validation CA");
    let other_ca = Pki::new("rotation foreign CA");
    let current = pki.peer("relay-a");
    let slot = RotatingPeerIdentity::new(pki.staged(&current));

    // Wrong private key for the certificate.
    let mismatched = pki.peer("relay-a");
    let foreign_key = pki.peer("relay-a");
    assert_eq!(
        StagedPeerIdentity::from_pem(
            mismatched.chain_pem.as_bytes(),
            foreign_key.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .unwrap_err(),
        PeerIdentityError::KeyMismatch
    );
    // A certificate from a CA the peer listeners do not trust.
    let untrusted = other_ca.peer("relay-a");
    assert!(matches!(
        StagedPeerIdentity::from_pem(
            untrusted.chain_pem.as_bytes(),
            untrusted.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        ),
        Err(PeerIdentityError::Untrusted(_))
    ));
    // A device certificate, even from the right CA.
    let device = pki.issue("urn:agent-tunnel:device:laptop", &[SERVER_NAME]);
    assert_eq!(
        StagedPeerIdentity::from_pem(
            device.chain_pem.as_bytes(),
            device.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .unwrap_err(),
        PeerIdentityError::NotPeerRole
    );
    // A different relay node.
    let other_node = pki.peer("relay-b");
    assert_eq!(
        slot.install(pki.staged(&other_node)).unwrap_err(),
        PeerIdentityError::DifferentNode
    );
    // A certificate that no longer covers the approved server name.
    let narrowed = pki.issue("urn:agent-tunnel:peer:relay-a", &["elsewhere.test"]);
    assert_eq!(
        slot.install(pki.staged(&narrowed)).unwrap_err(),
        PeerIdentityError::ServerNamesNarrowed
    );
    // Nothing above changed what the slot serves.
    assert_eq!(slot.current_spki(), current.spki);
    assert_eq!(slot.generation(), 1);
    // And the key never appears in diagnostics.
    let rendered = format!("{slot:?}");
    assert!(rendered.contains(&current.spki.to_hex()));
    assert!(!rendered.contains("PRIVATE KEY"));
}

#[test]
fn a_startup_certificate_without_a_role_still_serves_but_cannot_be_rotated() {
    // `with_single_cert` accepted a peer leaf whose role SAN does not parse;
    // peers refuse it at the handshake if they require the role.  The
    // replaceable slot keeps that startup contract (the M7 startup tests
    // rely on it), and refuses any rotation away from an identity it cannot
    // prove is a relay node.
    let pki = Pki::new("rotation role-less CA");
    let roleless = pki.issue("urn:example:not-a-role", &[SERVER_NAME]);
    let slot = RotatingPeerIdentity::from_pem_at_startup(
        roleless.chain_pem.as_bytes(),
        roleless.private_key_pem.as_bytes(),
    )
    .expect("a role-less startup certificate still serves");
    assert_eq!(slot.current_spki(), roleless.spki);
    assert!(slot.current_identity().is_none());
    let successor = pki.peer("relay-a");
    assert_eq!(
        slot.install(pki.staged(&successor)).unwrap_err(),
        PeerIdentityError::CurrentIdentityUnverifiable
    );
    assert_eq!(slot.generation(), 1);
}
