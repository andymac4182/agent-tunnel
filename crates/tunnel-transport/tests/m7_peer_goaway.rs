use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{
    sync::{Notify, watch},
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerConnectionHandle, PeerDestination, PeerServer,
    PeerServerDiagnostics, PeerTransportError, PeerTransportLimits, SharedPeerPins,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};

const SERVER_NAME: &str = "localhost";
const GOAWAY_PATH: &str = "/m7/goaway";
const CASE_TIMEOUT: Duration = Duration::from_secs(3);
const GOAWAY_DRAIN_QUIET: Duration = Duration::from_millis(100);
const RESPONSE_A: &[u8] = b"admitted-before-goaway";
const RESPONSE_B: &[u8] = b"fresh-reroute";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Leaf {
    certificate_pem: String,
    private_key_pem: String,
    der: Vec<u8>,
}

struct FixturePki {
    ca: Certificate,
    ca_key: KeyPair,
    ca_pem: String,
}

impl FixturePki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().expect("GOAWAY CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M7 GOAWAY CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params.self_signed(&ca_key).expect("GOAWAY CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("GOAWAY peer key");
        let mut params =
            CertificateParams::new(vec![SERVER_NAME.to_owned()]).expect("GOAWAY peer params");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("GOAWAY peer role URI"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("GOAWAY peer certificate");
        Leaf {
            certificate_pem: certificate.pem(),
            private_key_pem: key.serialize_pem(),
            der: certificate.der().to_vec(),
        }
    }

    fn chain(&self, leaf: &Leaf) -> String {
        format!("{}{}", leaf.certificate_pem, self.ca_pem)
    }
}

struct ServerFixture {
    destination: PeerDestination,
    accepted: Arc<AtomicUsize>,
    post_goaway_admitted: Arc<AtomicUsize>,
    goaway_sent: Arc<Notify>,
    release_response: Arc<Notify>,
    drain_complete: Arc<Notify>,
    cancel: CancellationToken,
    task: JoinHandle<TestResult>,
}

impl ServerFixture {
    fn start(pki: &FixturePki, server_leaf: &Leaf, goaway: bool) -> Self {
        let server_config = load_peer_server_config_from_pem(
            pki.chain(server_leaf).as_bytes(),
            server_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("GOAWAY server TLS config");
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("GOAWAY server endpoint");
        let address = endpoint.local_addr().expect("GOAWAY server address");
        let accepted = Arc::new(AtomicUsize::new(0));
        let post_goaway_admitted = Arc::new(AtomicUsize::new(0));
        let goaway_sent = Arc::new(Notify::new());
        let release_response = Arc::new(Notify::new());
        let drain_complete = Arc::new(Notify::new());
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve_one(
            endpoint,
            ServerSignals {
                accepted: accepted.clone(),
                post_goaway_admitted: post_goaway_admitted.clone(),
                goaway_sent: goaway_sent.clone(),
                release_response: release_response.clone(),
                drain_complete: drain_complete.clone(),
                cancel: cancel.clone(),
            },
            goaway,
        ));
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            accepted,
            post_goaway_admitted,
            goaway_sent,
            release_response,
            drain_complete,
            cancel,
            task,
        }
    }

    async fn shutdown(mut self) -> TestResult {
        self.cancel.cancel();
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(joined) => {
                joined??;
                Ok(())
            }
            Err(_) => {
                self.task.abort();
                let joined = timeout(CASE_TIMEOUT, &mut self.task)
                    .await
                    .map_err(|_| "GOAWAY server abort join deadline exceeded")?;
                match joined {
                    Ok(Ok(())) => Err("GOAWAY server exceeded its join deadline".into()),
                    Ok(Err(error)) => Err(error),
                    Err(error) if error.is_cancelled() => {
                        Err("GOAWAY server required forced cancellation".into())
                    }
                    Err(error) => Err(Box::new(error)),
                }
            }
        }
    }
}

impl Drop for ServerFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

struct ServerSignals {
    accepted: Arc<AtomicUsize>,
    post_goaway_admitted: Arc<AtomicUsize>,
    goaway_sent: Arc<Notify>,
    release_response: Arc<Notify>,
    drain_complete: Arc<Notify>,
    cancel: CancellationToken,
}

/// A peer server that answers one request, sends GOAWAY, and then shuts down
/// the way the transport and the relay do: QUIC application code 0 on the
/// connection and the endpoint, rather than the `H3_NO_ERROR` code the other
/// fixtures use.
struct CodeZeroServerFixture {
    destination: PeerDestination,
    close_now: Arc<Notify>,
    task: JoinHandle<TestResult>,
}

impl CodeZeroServerFixture {
    fn start(pki: &FixturePki, server_leaf: &Leaf) -> Self {
        let server_config = load_peer_server_config_from_pem(
            pki.chain(server_leaf).as_bytes(),
            server_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("code-zero server TLS config");
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("code-zero server endpoint");
        let address = endpoint.local_addr().expect("code-zero server address");
        let close_now = Arc::new(Notify::new());
        let task = tokio::spawn(serve_one_then_close_with_code_zero(
            endpoint,
            close_now.clone(),
        ));
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            close_now,
            task,
        }
    }

    fn send_goaway_then_close_with_code_zero(&self) -> TestResult {
        self.close_now.notify_one();
        Ok(())
    }

    async fn join(mut self) -> TestResult {
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(joined) => {
                joined??;
                Ok(())
            }
            Err(_) => {
                self.task.abort();
                Err("code-zero server exceeded its join deadline".into())
            }
        }
    }
}

impl Drop for CodeZeroServerFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_one_then_close_with_code_zero(
    endpoint: quinn::Endpoint,
    close_now: Arc<Notify>,
) -> TestResult {
    let incoming = timeout(CASE_TIMEOUT, endpoint.accept())
        .await?
        .ok_or("code-zero server had no incoming connection")?;
    let connection = timeout(CASE_TIMEOUT, incoming).await??;
    let quic = h3_quinn::Connection::new(connection.clone());
    let mut h3_connection =
        timeout(CASE_TIMEOUT, h3::server::builder().build::<_, Bytes>(quic)).await??;
    let resolver = timeout(CASE_TIMEOUT, h3_connection.accept())
        .await??
        .ok_or("code-zero server ended before the first request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if request.uri().path() != GOAWAY_PATH {
        return Err(format!(
            "unexpected code-zero fixture path: {}",
            request.uri().path()
        )
        .into());
    }
    while stream.recv_data().await?.is_some() {}
    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream.send_data(Bytes::from_static(RESPONSE_A)).await?;
    stream.finish().await?;

    // Keep driving H3 until the test asks for the shutdown, so the client has
    // consumed its response before GOAWAY.
    loop {
        tokio::select! {
            _ = close_now.notified() => break,
            result = timeout(GOAWAY_DRAIN_QUIET, h3_connection.accept()) => match result {
                Ok(Ok(Some(resolver))) => {
                    let (_, mut rejected) =
                        timeout(CASE_TIMEOUT, resolver.resolve_request()).await??;
                    rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                }
                Ok(Ok(None)) => break,
                Ok(Err(error)) => return Err(error.into()),
                Err(_) => {}
            },
        }
    }

    // GOAWAY first, so the client driver enters its planned drain, then the
    // graceful close every relay shutdown path performs: application code 0.
    timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await??;
    connection.close(quinn::VarInt::from_u32(0), b"code-zero cleanup");
    endpoint.close(quinn::VarInt::from_u32(0), b"code-zero server shutdown");
    timeout(CASE_TIMEOUT, endpoint.wait_idle()).await?;
    Ok(())
}

async fn serve_one(endpoint: quinn::Endpoint, signals: ServerSignals, goaway: bool) -> TestResult {
    let ServerSignals {
        accepted,
        post_goaway_admitted,
        goaway_sent,
        release_response,
        drain_complete,
        cancel,
    } = signals;
    let incoming = tokio::select! {
        _ = cancel.cancelled() => {
            endpoint.close(quinn::VarInt::from_u32(0), b"test cancelled");
            return Ok(())
        }
        incoming = timeout(CASE_TIMEOUT, endpoint.accept()) => incoming?,
    };
    let Some(incoming) = incoming else {
        endpoint.close(quinn::VarInt::from_u32(0), b"test no incoming");
        return Ok(());
    };
    let connection = timeout(CASE_TIMEOUT, incoming).await??;
    let quic = h3_quinn::Connection::new(connection.clone());
    let builder = h3::server::builder();
    let mut h3_connection = timeout(CASE_TIMEOUT, builder.build::<_, Bytes>(quic)).await??;
    let resolver = timeout(CASE_TIMEOUT, h3_connection.accept())
        .await??
        .ok_or("GOAWAY server ended before the first request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if request.uri().path() != GOAWAY_PATH {
        return Err(format!("unexpected GOAWAY fixture path: {}", request.uri().path()).into());
    }
    while stream.recv_data().await?.is_some() {}
    accepted.fetch_add(1, Ordering::AcqRel);

    if goaway {
        // This is the locked h3 0.0.8 wire API. The first accepted request is
        // stream 0, so shutdown(0) sends GOAWAY(last_stream_id=0), preserving
        // that request while rejecting later client-initiated streams.
        timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await??;
        // `notify_one` retains one permit if the test has not reached the
        // wait yet; `notify_waiters` would lose an early GOAWAY observation.
        goaway_sent.notify_one();

        // Keep polling the H3 connection while the admitted response is
        // intentionally held.  This lets the server's actual GOAWAY stream
        // gate reject a race-created stream and records any resolver that
        // would unexpectedly cross the post-GOAWAY admission boundary.
        let mut released = false;
        while !released {
            tokio::select! {
                _ = cancel.cancelled() => break,
                _ = release_response.notified() => released = true,
                result = h3_connection.accept() => match result? {
                    Some(resolver) => {
                        post_goaway_admitted.fetch_add(1, Ordering::AcqRel);
                        let (_, mut rejected) =
                            timeout(CASE_TIMEOUT, resolver.resolve_request()).await??;
                        rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                    }
                    None => break,
                },
            }
        }
        if !released {
            connection.close(
                quinn::VarInt::from_u32(0),
                b"test cancelled before response",
            );
            endpoint.close(quinn::VarInt::from_u32(0), b"test server shutdown");
            return Ok(());
        }
    }

    stream
        .send_response(Response::builder().status(StatusCode::OK).body(())?)
        .await?;
    stream
        .send_data(Bytes::from_static(if goaway {
            RESPONSE_A
        } else {
            RESPONSE_B
        }))
        .await?;
    stream.finish().await?;

    if goaway {
        // Continue driving H3 until the client observes a bounded quiet
        // period or the fixture is explicitly canceled. A real resolver here
        // is a typed counterexample to the GOAWAY admission boundary, never
        // evidence of a successful application request.
        loop {
            if cancel.is_cancelled() {
                break;
            }
            match timeout(GOAWAY_DRAIN_QUIET, h3_connection.accept()).await {
                Ok(Ok(Some(resolver))) => {
                    post_goaway_admitted.fetch_add(1, Ordering::AcqRel);
                    let (_, mut rejected) =
                        timeout(CASE_TIMEOUT, resolver.resolve_request()).await??;
                    rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                }
                Ok(Ok(None)) | Err(_) => {
                    drain_complete.notify_one();
                    break;
                }
                Ok(Err(error)) => return Err(error.into()),
            }
        }
    } else {
        cancel.cancelled().await;
    }
    // The test has already asserted the GOAWAY path and the admitted response
    // has been consumed by its caller before fixture cancellation. Keep this
    // final fixture close on the HTTP/3 clean terminal so the client cleanup
    // does not inherit an ambiguous QUIC application code 0.
    let _ = timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await;
    let clean_close_code = quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
        .expect("H3_NO_ERROR fits a QUIC application close code");
    connection.close(clean_close_code, b"test cleanup after GOAWAY");
    endpoint.close(clean_close_code, b"test server shutdown");
    Ok(())
}

fn request() -> Request<()> {
    Request::builder()
        .method("POST")
        .uri(format!("https://{SERVER_NAME}{GOAWAY_PATH}"))
        .body(())
        .expect("GOAWAY request")
}

async fn open_until_goaway(connection: &PeerConnectionHandle) -> TestResult<usize> {
    let deadline = Instant::now() + CASE_TIMEOUT;
    let mut attempts = 0;
    loop {
        attempts += 1;
        let result = timeout_at(deadline, connection.open(request()))
            .await
            .map_err(|_| "GOAWAY rejection deadline exceeded")?;
        match result {
            Err(PeerTransportError::GoAway) => return Ok(attempts),
            // Any other transport or H3 error is a real failure. The fixture
            // never retries arbitrary protocol text as if it were GOAWAY.
            Err(error) => return Err(format!("new request was not typed GOAWAY: {error}").into()),
            Ok(mut stream) => {
                // The request can win the race with delivery of the control
                // stream GOAWAY.  The server has already lowered its local
                // acceptance limit, so this stream is rejected before the
                // application resolver and has no body/effect.  Cancel it,
                // then keep waiting for the typed pre-dispatch result.
                stream.cancel();
                if attempts >= 32 {
                    return Err("GOAWAY propagation exceeded the attempt bound".into());
                }
                tokio::task::yield_now().await;
            }
        }
    }
}

fn body_bytes(chunk: Option<tunnel_transport::PeerBodyChunk>) -> TestResult<Vec<u8>> {
    chunk
        .map(|chunk| chunk.as_bytes().to_vec())
        .ok_or_else(|| "GOAWAY response did not contain its bounded body".into())
}

fn limits() -> PeerTransportLimits {
    PeerTransportLimits {
        handshake_timeout: CASE_TIMEOUT,
        stream_timeout: CASE_TIMEOUT,
        idle_timeout: CASE_TIMEOUT,
        drain_timeout: Duration::from_secs(1),
        ..PeerTransportLimits::default()
    }
}

#[tokio::test]
async fn authenticated_h3_goaway_preserves_admitted_stream_and_reroutes_without_replay()
-> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("goaway-client");
    let server_leaf_a = pki.issue_peer("goaway-a");
    let server_leaf_b = pki.issue_peer("goaway-b");
    let server_a = ServerFixture::start(&pki, &server_leaf_a, true);
    let server_b = ServerFixture::start(&pki, &server_leaf_b, false);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("GOAWAY client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("GOAWAY client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf_a.der).expect("GOAWAY A pin"),
        spki_sha256_from_der(&server_leaf_b.der).expect("GOAWAY B pin"),
    ])
    .expect("GOAWAY server pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("GOAWAY peer client");

    let scenario = async {
        let connection_a = client.connect(server_a.destination.clone()).await?;
        if connection_a.peer_identity().role_id() != "goaway-a" {
            return Err("GOAWAY A peer identity was not authenticated".into());
        }
        let mut admitted = connection_a.open(request()).await?;
        admitted.finish().await?;
        timeout(CASE_TIMEOUT, server_a.goaway_sent.notified())
            .await
            .map_err(|_| "GOAWAY frame was not sent")?;

        let attempts = open_until_goaway(&connection_a).await?;
        if attempts > 32 {
            return Err("GOAWAY propagation needed too many bounded attempts".into());
        }
        if server_a.accepted.load(Ordering::Acquire) != 1 {
            return Err("the admitted A request count changed".into());
        }

        // The response is deliberately held until the client has observed
        // typed RemoteClosing. This proves the already admitted stream still
        // completes after the actual wire GOAWAY, rather than merely before
        // it was delivered.
        server_a.release_response.notify_one();
        let response = admitted.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err("admitted GOAWAY stream did not receive a successful response".into());
        }
        if body_bytes(admitted.recv_chunk().await?)?.as_slice() != RESPONSE_A {
            return Err("admitted GOAWAY stream response body changed".into());
        }
        if admitted.recv_chunk().await?.is_some() {
            return Err("admitted GOAWAY stream replayed an extra body chunk".into());
        }
        timeout(CASE_TIMEOUT, server_a.drain_complete.notified())
            .await
            .map_err(|_| "GOAWAY server drain did not complete")?;
        if server_a.post_goaway_admitted.load(Ordering::Acquire) != 0 {
            return Err("a post-GOAWAY request reached the server resolver".into());
        }

        // Planned fixture cancellation is explicit before the client drops
        // its A pool entry, so the server task is never mistaken for a
        // protocol failure during the final joined close.
        server_a.cancel.cancel();
        client.close_peer(&server_a.destination).await?;
        let connection_b = client.connect(server_b.destination.clone()).await?;
        if connection_b.peer_identity().role_id() != "goaway-b" {
            return Err("GOAWAY B peer identity was not authenticated".into());
        }
        let mut rerouted = connection_b.open(request()).await?;
        rerouted.finish().await?;
        let response = rerouted.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err("rerouted GOAWAY request did not receive a successful response".into());
        }
        if body_bytes(rerouted.recv_chunk().await?)?.as_slice() != RESPONSE_B {
            return Err("rerouted GOAWAY response body changed".into());
        }
        if rerouted.recv_chunk().await?.is_some() {
            return Err("rerouted GOAWAY request replayed an extra body chunk".into());
        }
        if server_b.accepted.load(Ordering::Acquire) != 1 {
            return Err("rerouted GOAWAY request was not admitted exactly once".into());
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // PeerClient::shutdown owns the cancellation and per-connection bounded
    // joins; do not wrap it in a timeout that could detach that future before
    // its driver cleanup has been observed.
    let client_shutdown = client.shutdown().await;
    let server_a_shutdown = server_a.shutdown().await;
    let server_b_shutdown = server_b.shutdown().await;
    scenario?;
    client_shutdown?;
    server_a_shutdown?;
    server_b_shutdown?;
    Ok(())
}

struct PlannedPeerServerFixture {
    destination: PeerDestination,
    admitted: Arc<Notify>,
    release: watch::Sender<bool>,
    accepted: Arc<AtomicUsize>,
    post_goaway_admitted: Arc<AtomicUsize>,
    goaway_observed: Arc<AtomicBool>,
    handler_active: Arc<AtomicUsize>,
    handler_completed: Arc<AtomicUsize>,
    handler_dropped: Arc<AtomicUsize>,
    pin_provider: SharedPeerPins,
    diagnostics: Arc<PeerServerDiagnostics>,
    cancel: CancellationToken,
    task: JoinHandle<Result<(), PeerTransportError>>,
}

impl PlannedPeerServerFixture {
    fn start(pki: &FixturePki, server_leaf: &Leaf, client_leaf: &Leaf) -> Self {
        Self::start_with_body_read(pki, server_leaf, client_leaf, false)
    }

    /// Start the planned server.  With `read_request_body` set, the handler
    /// consumes the request body before responding, so a peer reset of an
    /// admitted stream is observed by the handler itself (as an owner's
    /// forwarding handler would) rather than only at response time.
    fn start_with_body_read(
        pki: &FixturePki,
        server_leaf: &Leaf,
        client_leaf: &Leaf,
        read_request_body: bool,
    ) -> Self {
        let mut server_config = load_peer_server_config_from_pem(
            pki.chain(server_leaf).as_bytes(),
            server_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("planned peer server TLS config");
        limits()
            .apply_to_server_config(&mut server_config)
            .expect("planned peer server transport config");
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("planned peer server endpoint");
        let address = endpoint.local_addr().expect("planned peer server address");
        let admitted = Arc::new(Notify::new());
        let (release, release_receiver) = watch::channel(false);
        let accepted = Arc::new(AtomicUsize::new(0));
        let post_goaway_admitted = Arc::new(AtomicUsize::new(0));
        let goaway_observed = Arc::new(AtomicBool::new(false));
        let handler_active = Arc::new(AtomicUsize::new(0));
        let handler_completed = Arc::new(AtomicUsize::new(0));
        let handler_dropped = Arc::new(AtomicUsize::new(0));
        let cancel = CancellationToken::new();
        let handler_admitted = admitted.clone();
        let handler_release = release_receiver.clone();
        let handler_accepted = accepted.clone();
        let handler_post_goaway = post_goaway_admitted.clone();
        let handler_goaway_observed = goaway_observed.clone();
        let handler_active_count = handler_active.clone();
        let handler_completed_count = handler_completed.clone();
        let handler_dropped_count = handler_dropped.clone();
        let handler = move |_identity: tunnel_transport::TlsIdentity,
                            _request: Request<()>,
                            mut stream: tunnel_transport::PeerServerStream| {
            let admitted = handler_admitted.clone();
            let mut release = handler_release.clone();
            let accepted = handler_accepted.clone();
            let post_goaway_admitted = handler_post_goaway.clone();
            let goaway_observed = handler_goaway_observed.clone();
            let active = handler_active_count.clone();
            let completed = handler_completed_count.clone();
            let dropped = handler_dropped_count.clone();
            async move {
                struct HandlerDropGuard {
                    active: Arc<AtomicUsize>,
                    completed: Arc<AtomicUsize>,
                    dropped: Arc<AtomicUsize>,
                    completed_normally: bool,
                }

                impl Drop for HandlerDropGuard {
                    fn drop(&mut self) {
                        self.active.fetch_sub(1, Ordering::AcqRel);
                        if self.completed_normally {
                            self.completed.fetch_add(1, Ordering::AcqRel);
                        } else {
                            self.dropped.fetch_add(1, Ordering::AcqRel);
                        }
                    }
                }

                active.fetch_add(1, Ordering::AcqRel);
                let mut guard = HandlerDropGuard {
                    active,
                    completed,
                    dropped,
                    completed_normally: false,
                };
                if goaway_observed.load(Ordering::Acquire) {
                    post_goaway_admitted.fetch_add(1, Ordering::AcqRel);
                }
                accepted.fetch_add(1, Ordering::AcqRel);
                admitted.notify_one();
                if read_request_body {
                    // A peer reset of the request body surfaces here as the
                    // handler's own typed error, before any response is sent.
                    while stream.recv_chunk().await?.is_some() {}
                }
                while !*release.borrow() {
                    release
                        .changed()
                        .await
                        .map_err(|_| PeerTransportError::Cancelled)?;
                }
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|_| PeerTransportError::H3("test response build failed".to_owned()))?;
                stream.send_response(response).await?;
                stream.send_chunk(Bytes::from_static(RESPONSE_A)).await?;
                stream.finish().await?;
                guard.completed_normally = true;
                Ok(())
            }
        };
        let client_pin = spki_sha256_from_der(&client_leaf.der).expect("planned peer client pin");
        let server_pins = ApprovedPeerPins::new([client_pin]).expect("planned peer client pin set");
        let pin_provider = SharedPeerPins::new(server_pins).expect("planned peer client pins");
        let server = PeerServer::new_with_pin_provider(
            endpoint,
            pin_provider.clone(),
            limits(),
            |_identity: &tunnel_transport::TlsIdentity, _request: &Request<()>| true,
            handler,
        )
        .expect("planned peer server");
        let diagnostics = server.diagnostics();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move { server.serve_planned(task_cancel).await });
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            admitted,
            release,
            accepted,
            post_goaway_admitted,
            goaway_observed,
            handler_active,
            handler_completed,
            handler_dropped,
            pin_provider,
            diagnostics,
            cancel,
            task,
        }
    }

    async fn wait_for_goaway_sent(&self) -> TestResult {
        let deadline = Instant::now() + CASE_TIMEOUT;
        loop {
            if self
                .diagnostics
                .snapshot()
                .connections
                .iter()
                .any(|connection| {
                    connection.planned_goaway_sent && connection.accepted_streams >= 1
                })
            {
                return Ok(());
            }
            timeout_at(deadline, sleep(Duration::from_millis(5)))
                .await
                .map_err(|_| "planned GOAWAY was not confirmed by server diagnostics")?;
        }
    }

    async fn wait_for_handler_drop(&self) -> TestResult {
        let deadline = Instant::now() + CASE_TIMEOUT;
        loop {
            if self.handler_dropped.load(Ordering::Acquire) == 1
                && self.handler_active.load(Ordering::Acquire) == 0
            {
                return Ok(());
            }
            timeout_at(deadline, sleep(Duration::from_millis(5)))
                .await
                .map_err(|_| "planned handler was not dropped within its bounded deadline")?;
        }
    }

    async fn join(mut self) -> TestResult {
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(result) => result??,
            Err(_) => {
                self.task.abort();
                match timeout(CASE_TIMEOUT, &mut self.task).await {
                    Ok(Ok(Ok(()))) => {
                        return Err("planned peer server required forced abort".into());
                    }
                    Ok(Ok(Err(error))) => return Err(error.into()),
                    Ok(Err(error)) if error.is_cancelled() => {
                        return Err("planned peer server required forced cancellation".into());
                    }
                    Ok(Err(error)) => return Err(error.into()),
                    Err(_) => {
                        return Err("planned peer server abort join deadline exceeded".into());
                    }
                }
            }
        }
        Ok(())
    }

    async fn join_expect_timeout(mut self) -> TestResult {
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(Ok(Err(PeerTransportError::Timeout))) => Ok(()),
            Ok(Ok(Ok(()))) => Err("planned forced drain completed without its timeout".into()),
            Ok(Ok(Err(_))) => Err("planned forced drain returned an unexpected typed error".into()),
            Ok(Err(error)) => Err(Box::new(error)),
            Err(_) => {
                self.task.abort();
                let joined = timeout(CASE_TIMEOUT, &mut self.task)
                    .await
                    .map_err(|_| "planned forced server abort join deadline exceeded")?;
                match joined {
                    Ok(Ok(())) => Err("planned forced server required an abort".into()),
                    Ok(Err(_)) => Err("planned forced server did not return before abort".into()),
                    Err(error) if error.is_cancelled() => {
                        Err("planned forced server required forced cancellation".into())
                    }
                    Err(error) => Err(Box::new(error)),
                }
            }
        }
    }
}

impl Drop for PlannedPeerServerFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

#[tokio::test]
async fn peer_server_planned_goaway_drains_admitted_stream_before_quic_close() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("planned-goaway-client");
    let server_leaf = pki.issue_peer("planned-goaway-server");
    let server = PlannedPeerServerFixture::start(&pki, &server_leaf, &client_leaf);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("planned GOAWAY client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("planned GOAWAY client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("planned GOAWAY server pin")
    ])
    .expect("planned GOAWAY client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("planned GOAWAY client");

    let scenario = async {
        let connection = client.connect(server.destination.clone()).await?;
        let mut admitted = connection.open(request()).await?;
        admitted.finish().await?;
        timeout(CASE_TIMEOUT, server.admitted.notified())
            .await
            .map_err(|_| "planned GOAWAY handler did not admit the stream")?;

        // This is the planned server signal.  The server must stop new
        // accepts without closing this existing QUIC connection, send H3
        // GOAWAY, and keep the admitted handler alive.
        server.cancel.cancel();
        server.wait_for_goaway_sent().await?;
        let attempts = open_until_goaway(&connection).await?;
        if attempts > 32 {
            return Err("planned GOAWAY propagation exceeded its attempt bound".into());
        }
        let accepted_at_goaway = server.accepted.load(Ordering::Acquire);
        if accepted_at_goaway != 1 {
            return Err("a request raced past planned GOAWAY before observation".into());
        }
        server.goaway_observed.store(true, Ordering::Release);

        server
            .release
            .send(true)
            .map_err(|_| "planned GOAWAY handler release receiver was dropped")?;
        let response = admitted.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err("planned GOAWAY admitted response was not successful".into());
        }
        if body_bytes(admitted.recv_chunk().await?)?.as_slice() != RESPONSE_A {
            return Err("planned GOAWAY admitted response changed".into());
        }
        if admitted.recv_chunk().await?.is_some() {
            return Err("planned GOAWAY admitted response replayed a chunk".into());
        }
        if server.accepted.load(Ordering::Acquire) != 1 {
            return Err("a request after planned GOAWAY reached the handler".into());
        }
        sleep(GOAWAY_DRAIN_QUIET).await;
        if server.post_goaway_admitted.load(Ordering::Acquire) != 0 {
            return Err("a request after observed planned GOAWAY reached the handler".into());
        }
        // The client GOAWAY acknowledgement is deliberately gated on every
        // existing StreamLease being returned.  Make the admitted stream's
        // lifetime boundary explicit before the server join observes the
        // acknowledgement.
        drop(admitted);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let server_join = server.join().await;
    let client_shutdown = client.shutdown().await;
    scenario?;
    server_join?;
    client_shutdown?;
    Ok(())
}

#[tokio::test]
async fn peer_server_planned_deadline_cancels_held_handler_and_joins() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("forced-goaway-client");
    let server_leaf = pki.issue_peer("forced-goaway-server");
    let server = PlannedPeerServerFixture::start(&pki, &server_leaf, &client_leaf);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("forced GOAWAY client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("forced GOAWAY client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("forced GOAWAY server pin")
    ])
    .expect("forced GOAWAY client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("forced GOAWAY client");

    let scenario = async {
        let connection = client.connect(server.destination.clone()).await?;
        let mut admitted = connection.open(request()).await?;
        admitted.finish().await?;
        timeout(CASE_TIMEOUT, server.admitted.notified())
            .await
            .map_err(|_| "forced GOAWAY handler did not admit the stream")?;

        // Deliberately keep the admitted handler waiting past the one-second
        // transport drain deadline. The resulting client error is a bounded
        // QUIC/H3 close; the handler DropGuard below is the authoritative
        // cancellation observation and must not be reported as completion.
        server.cancel.cancel();
        server.wait_for_goaway_sent().await?;
        server.wait_for_handler_drop().await?;
        if server.handler_completed.load(Ordering::Acquire) != 0 {
            return Err("forced planned drain incorrectly completed the held handler".into());
        }
        if server.accepted.load(Ordering::Acquire) != 1 {
            return Err("forced planned drain admitted an extra request".into());
        }
        let response = timeout(CASE_TIMEOUT, admitted.recv_response()).await;
        match response {
            Ok(Err(PeerTransportError::H3(_)))
            | Ok(Err(PeerTransportError::Quic(_)))
            | Ok(Err(PeerTransportError::Cancelled)) => {}
            Ok(Err(_)) => {
                return Err("forced planned close had an unallowlisted typed outcome".into());
            }
            Ok(Ok(_)) => return Err("forced planned close returned a response".into()),
            Err(_) => return Err("forced planned close exceeded its response deadline".into()),
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let server_join = server.join_expect_timeout().await;
    let client_shutdown = client.shutdown().await;
    scenario?;
    // The forced planned deadline is already proven by the joined server
    // returning the typed Timeout above. Its peer necessarily observes the
    // QUIC application-close terminal used by that forced cleanup; accept
    // only this exact static H3 rendering here. Graceful planned/passive
    // tests keep requiring a successful client shutdown.
    server_join?;
    match client_shutdown {
        Ok(()) => {}
        Err(PeerTransportError::H3(error)) if error == "Remote error: ApplicationClose: 0x0" => {}
        Err(error) => return Err(error.into()),
    }
    Ok(())
}

#[tokio::test]
async fn peer_server_pin_revocation_emergency_closes_without_planned_goaway() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("emergency-pin-client");
    let server_leaf = pki.issue_peer("emergency-pin-server");
    let server = PlannedPeerServerFixture::start(&pki, &server_leaf, &client_leaf);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("emergency pin client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("emergency pin client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("emergency pin server pin")
    ])
    .expect("emergency pin client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("emergency pin client");

    let scenario = async {
        let connection = client.connect(server.destination.clone()).await?;
        let mut admitted = connection.open(request()).await?;
        admitted.finish().await?;
        timeout(CASE_TIMEOUT, server.admitted.notified())
            .await
            .map_err(|_| "emergency pin handler did not admit the stream")?;
        if server
            .diagnostics
            .snapshot()
            .connections
            .iter()
            .any(|connection| connection.planned_goaway_sent)
        {
            return Err("emergency pin case sent planned GOAWAY before revocation".into());
        }

        // Revoking the authenticated client pin is the emergency control
        // case. It must close the existing QUIC connection directly rather
        // than entering the planned GOAWAY branch.
        server
            .pin_provider
            .replace(std::iter::empty::<tunnel_transport::SpkiSha256>())
            .map_err(|_| "emergency pin revocation failed")?;
        server.wait_for_handler_drop().await?;
        if server.handler_completed.load(Ordering::Acquire) != 0 {
            return Err("emergency pin revocation completed the held handler".into());
        }
        let response = timeout(CASE_TIMEOUT, admitted.recv_response()).await;
        match response {
            Ok(Err(PeerTransportError::GoAway)) => {
                return Err("emergency pin revocation was misreported as planned GOAWAY".into());
            }
            Ok(Err(PeerTransportError::H3(_)))
            | Ok(Err(PeerTransportError::Quic(_)))
            | Ok(Err(PeerTransportError::Cancelled)) => {}
            Ok(Err(_)) => {
                return Err("emergency pin close had an unallowlisted typed outcome".into());
            }
            Ok(Ok(_)) => return Err("emergency pin close returned a response".into()),
            Err(_) => return Err("emergency pin close exceeded its response deadline".into()),
        }
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // The pin watcher only closes the selected connection; the planned server
    // listener still needs its explicit cancellation for joined cleanup.
    server.cancel.cancel();
    let server_join = server.join().await;
    let client_shutdown = client.shutdown().await;
    scenario?;
    server_join?;
    client_shutdown?;
    Ok(())
}
#[tokio::test]
async fn peer_client_passively_acknowledges_goaway_without_post_goaway_open() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("passive-goaway-client");
    let server_leaf = pki.issue_peer("passive-goaway-server");
    let server = PlannedPeerServerFixture::start(&pki, &server_leaf, &client_leaf);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("passive GOAWAY client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("passive GOAWAY client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("passive GOAWAY server pin")
    ])
    .expect("passive GOAWAY client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("passive GOAWAY client");

    let scenario = async {
        let connection = client.connect(server.destination.clone()).await?;
        let mut admitted = connection.open(request()).await?;
        admitted.finish().await?;
        timeout(CASE_TIMEOUT, server.admitted.notified())
            .await
            .map_err(|_| "passive GOAWAY handler did not admit the stream")?;

        // The only request on this connection is already admitted.  The
        // planned server signal must be observed by the client driver while
        // this response is still held; no failed post-GOAWAY open is used as
        // a wake-up probe.
        server.cancel.cancel();
        server.wait_for_goaway_sent().await?;
        if server.accepted.load(Ordering::Acquire) != 1 {
            return Err("passive GOAWAY admitted request count changed".into());
        }

        server
            .release
            .send(true)
            .map_err(|_| "passive GOAWAY handler release receiver was dropped")?;
        let response = admitted.recv_response().await?;
        if response.status() != StatusCode::OK {
            return Err("passive GOAWAY admitted response was not successful".into());
        }
        if body_bytes(admitted.recv_chunk().await?)?.as_slice() != RESPONSE_A {
            return Err("passive GOAWAY admitted response changed".into());
        }
        if admitted.recv_chunk().await?.is_some() {
            return Err("passive GOAWAY admitted response replayed a chunk".into());
        }

        // Returning this final lease lets the passive driver send the client
        // GOAWAY acknowledgement.  The server join below is the bounded
        // wire-level observation of that acknowledgement; no new stream is
        // opened after the remote GOAWAY.
        drop(admitted);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    let server_join = server.join().await;
    let client_shutdown = client.shutdown().await;
    scenario?;
    server_join?;
    client_shutdown?;
    Ok(())
}

/// Shutdown-after-GOAWAY regression: an admitted stream that its peer tears
/// down during the planned drain (the `H3_REQUEST_CANCELLED` reset a relay
/// ingress sends when its forwarded consumer or device socket closes) is a
/// stream-local outcome.  The owner's planned drain must join it and complete
/// cleanly; it previously surfaced as the listener result
/// `peer HTTP/3 operation failed: Remote reset: H3_REQUEST_CANCELLED` and
/// failed the relay shutdown.
#[tokio::test]
async fn peer_server_planned_drain_joins_cleanly_when_peer_resets_admitted_stream() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("reset-drain-client");
    let server_leaf = pki.issue_peer("reset-drain-server");
    let server =
        PlannedPeerServerFixture::start_with_body_read(&pki, &server_leaf, &client_leaf, true);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("reset-drain client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("reset-drain client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("reset-drain server pin")
    ])
    .expect("reset-drain client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("reset-drain client");

    let scenario = async {
        let connection = client.connect(server.destination.clone()).await?;
        // The request body is deliberately left open: the admitted handler is
        // reading it and observes the peer's reset directly.
        let mut admitted = connection.open(request()).await?;
        timeout(CASE_TIMEOUT, server.admitted.notified())
            .await
            .map_err(|_| "reset-drain handler did not admit the stream")?;

        server.cancel.cancel();
        server.wait_for_goaway_sent().await?;
        if server.accepted.load(Ordering::Acquire) != 1 {
            return Err("reset-drain admitted request count changed".into());
        }

        // The ingress side tears its admitted stream down after GOAWAY with
        // the same H3_REQUEST_CANCELLED reset the relay uses; the handler
        // ends with that typed error while the drain is still in progress.
        admitted.cancel();
        server.wait_for_handler_drop().await?;
        if server.handler_completed.load(Ordering::Acquire) != 0 {
            return Err("reset-drain handler completed after the peer reset".into());
        }
        if server.post_goaway_admitted.load(Ordering::Acquire) != 0 {
            return Err("a request after planned GOAWAY reached the reset-drain handler".into());
        }
        // Returning the lease lets the client acknowledge GOAWAY so the
        // server's accept boundary completes and its planned drain joins.
        drop(admitted);
        Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
    }
    .await;

    // A clean planned drain is the regression assertion: the stream-local
    // reset must not become the listener's typed failure, while the join
    // still completes inside the shared drain deadline.
    let server_join = server.join().await;
    let client_shutdown = client.shutdown().await;
    scenario?;
    server_join?;
    client_shutdown?;
    Ok(())
}

/// A raw authenticated HTTP/3 owner that refuses its first request without
/// processing it.  This is the wire shape an ingress observes when it opens a
/// stream after the owner closed planned admission but before the ingress
/// processed the GOAWAY control frame.
struct ResetServerFixture {
    destination: PeerDestination,
    cancel: CancellationToken,
    task: JoinHandle<TestResult>,
}

impl ResetServerFixture {
    fn start(pki: &FixturePki, server_leaf: &Leaf, code: h3::error::Code) -> Self {
        let server_config = load_peer_server_config_from_pem(
            pki.chain(server_leaf).as_bytes(),
            server_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("reset server TLS config");
        let endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("reset server endpoint");
        let address = endpoint.local_addr().expect("reset server address");
        let cancel = CancellationToken::new();
        let task = tokio::spawn(serve_reset_one(endpoint, code, cancel.clone()));
        Self {
            destination: PeerDestination::new(address, SERVER_NAME),
            cancel,
            task,
        }
    }

    async fn shutdown(mut self) -> TestResult {
        self.cancel.cancel();
        match timeout(CASE_TIMEOUT, &mut self.task).await {
            Ok(joined) => {
                joined??;
                Ok(())
            }
            Err(_) => {
                self.task.abort();
                let _ = timeout(CASE_TIMEOUT, &mut self.task).await;
                Err("reset server exceeded its join deadline".into())
            }
        }
    }
}

impl Drop for ResetServerFixture {
    fn drop(&mut self) {
        self.cancel.cancel();
        self.task.abort();
    }
}

async fn serve_reset_one(
    endpoint: quinn::Endpoint,
    code: h3::error::Code,
    cancel: CancellationToken,
) -> TestResult {
    let incoming = tokio::select! {
        _ = cancel.cancelled() => {
            endpoint.close(quinn::VarInt::from_u32(0), b"test cancelled");
            return Ok(())
        }
        incoming = timeout(CASE_TIMEOUT, endpoint.accept()) => incoming?,
    };
    let Some(incoming) = incoming else {
        endpoint.close(quinn::VarInt::from_u32(0), b"test no incoming");
        return Ok(());
    };
    let connection = timeout(CASE_TIMEOUT, incoming).await??;
    let quic = h3_quinn::Connection::new(connection.clone());
    let builder = h3::server::builder();
    let mut h3_connection = timeout(CASE_TIMEOUT, builder.build::<_, Bytes>(quic)).await??;
    let resolver = timeout(CASE_TIMEOUT, h3_connection.accept())
        .await??
        .ok_or("reset server ended before the first request")?;
    let (request, mut stream) = resolver.resolve_request().await?;
    if request.uri().path() != GOAWAY_PATH {
        return Err(format!("unexpected reset fixture path: {}", request.uri().path()).into());
    }
    // Refuse the resolved request without reading its body or sending any
    // response, mirroring the owner's admission-closed reset.
    stream.stop_sending(code);
    stream.stop_stream(code);
    // Keep driving the connection so the reset is delivered and later client
    // frames are processed until the case cancels the fixture.
    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = h3_connection.accept() => match result? {
                Some(resolver) => {
                    let (_, mut rejected) =
                        timeout(CASE_TIMEOUT, resolver.resolve_request()).await??;
                    rejected.stop_stream(h3::error::Code::H3_REQUEST_REJECTED);
                }
                None => break,
            },
        }
    }
    let _ = timeout(CASE_TIMEOUT, h3_connection.shutdown(0)).await;
    let clean_close_code = quinn::VarInt::from_u64(h3::error::Code::H3_NO_ERROR.value())
        .expect("H3_NO_ERROR fits a QUIC application close code");
    connection.close(clean_close_code, b"test cleanup after reset");
    endpoint.close(clean_close_code, b"test server shutdown");
    Ok(())
}

/// Open one request against a refusing owner and return the typed outcome the
/// pooled client reports at its response boundary.
async fn refused_request_outcome(
    label: &str,
    code: h3::error::Code,
) -> TestResult<Result<Response<()>, PeerTransportError>> {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer(&format!("{label}-client"));
    let server_leaf = pki.issue_peer(&format!("{label}-server"));
    let server = ResetServerFixture::start(&pki, &server_leaf, code);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("reset case client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("reset case client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("reset case server pin")
    ])
    .expect("reset case client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("reset case client");

    let outcome = async {
        let connection = client.connect(server.destination.clone()).await?;
        // The request stream exists before the owner refuses it, so the typed
        // outcome must be observed at the response boundary, exactly where a
        // relay ingress reads the owner's admission response.
        let mut stream = connection.open(request()).await?;
        let response = timeout(CASE_TIMEOUT, stream.recv_response())
            .await
            .map_err(|_| "refused request exceeded its response deadline")?;
        drop(stream);
        Ok::<_, Box<dyn std::error::Error + Send + Sync>>(response)
    }
    .await;

    let server_shutdown = server.shutdown().await;
    let client_shutdown = client.shutdown().await;
    let response = outcome?;
    server_shutdown?;
    client_shutdown?;
    Ok(response)
}

/// An owner that refuses a raced stream with `H3_REQUEST_REJECTED` did not
/// process it (RFC 9114 §8.1), so the pooled client must report the typed
/// pre-dispatch `GoAway` that the relay maps to `PEER_UNAVAILABLE` /
/// `not_dispatched`, not a generic HTTP/3 error with `unknown` certainty.
#[tokio::test]
async fn peer_client_types_request_rejected_reset_as_goaway_not_dispatched() -> TestResult {
    match refused_request_outcome("reject-reset", h3::error::Code::H3_REQUEST_REJECTED).await? {
        Err(PeerTransportError::GoAway) => Ok(()),
        Err(error) => Err(format!("H3_REQUEST_REJECTED was not typed as GoAway: {error}").into()),
        Ok(_) => Err("refused request unexpectedly received a response".into()),
    }
}

/// A `H3_REQUEST_CANCELLED` reset may follow dispatch, so it must keep the
/// generic HTTP/3 classification and its `unknown` execution certainty.
#[tokio::test]
async fn peer_client_keeps_request_cancelled_reset_as_generic_h3() -> TestResult {
    match refused_request_outcome("cancel-reset", h3::error::Code::H3_REQUEST_CANCELLED).await? {
        Err(PeerTransportError::H3(_)) => Ok(()),
        Err(PeerTransportError::GoAway) => {
            Err("H3_REQUEST_CANCELLED was misreported as a pre-dispatch GoAway".into())
        }
        Err(error) => {
            Err(format!("H3_REQUEST_CANCELLED had an unexpected typed outcome: {error}").into())
        }
        Ok(_) => Err("cancelled request unexpectedly received a response".into()),
    }
}

/// Characterization of the post-GOAWAY drain against a peer that shuts down
/// the way production does: QUIC application code 0.
///
/// Honest scope: this case passes both before and after the classifier fix,
/// because with no stream lease outstanding the driver can finish its drain
/// without reaching `planned_idle_result`. It is kept because it pins the
/// invariant with a production-shaped close, and because the other fixtures
/// deliberately avoid that close. The evidence for the fix itself is the code
/// path plus repeated runs of the I08 GOAWAY gate, recorded in docs/tasks.md.
///
/// Every graceful close in the transport and the relay closes its QUIC
/// connection and endpoint with application code 0. `is_h3_no_error` accepts
/// only `H3_NO_ERROR` (0x100), so the post-GOAWAY drain classified that clean
/// shutdown as a protocol failure. A cluster stops its relays in sequence, so
/// the later relay's client pool was still draining a connection to the one
/// already stopped and its shutdown reported `stopping relay <node>: peer
/// transport failed`, failing the I08 GOAWAY gate's cluster cleanup in two
/// consecutive surveys on whichever relay stopped later. Note the existing
/// `ServerFixture` deliberately closes with `H3_NO_ERROR` to avoid this, so
/// this case needs a fixture that closes the way production does.
#[tokio::test]
async fn peer_client_drain_completes_when_the_peer_closes_with_application_code_zero() -> TestResult
{
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("code-zero-client");
    let server_leaf = pki.issue_peer("code-zero-server");
    let server = CodeZeroServerFixture::start(&pki, &server_leaf);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("code-zero client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("code-zero client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("code-zero server pin")
    ])
    .expect("code-zero client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("code-zero client");

    // One real authenticated exchange, so the pooled connection is live and
    // its driver is running rather than idle from birth.
    let connection = client.connect(server.destination.clone()).await?;
    let mut admitted = connection.open(request()).await?;
    admitted.finish().await?;
    let response = admitted.recv_response().await?;
    if response.status() != StatusCode::OK {
        return Err("code-zero exchange was not successful".into());
    }
    if body_bytes(admitted.recv_chunk().await?)?.as_slice() != RESPONSE_A {
        return Err("code-zero response body changed".into());
    }
    drop(admitted);

    // The peer sends GOAWAY, putting this client's driver into its planned
    // drain, and then shuts down the way the relay does: QUIC application
    // code 0 on the connection and the endpoint.
    server.send_goaway_then_close_with_code_zero()?;

    // The drain must complete: this client's own shutdown joins cleanly and
    // stays inside its drain deadline.
    let started = tokio::time::Instant::now();
    client.shutdown().await.map_err(|error| {
        format!("drain after a peer close with application code 0 failed: {error}")
    })?;
    if started.elapsed() >= CASE_TIMEOUT {
        return Err("client shutdown did not complete within its drain deadline".into());
    }
    server.join().await?;
    Ok(())
}

/// Characterization: a pooled connection whose remote peer has already stopped
/// must not make this client's own shutdown report a failure.
///
/// Honest scope: this also passes before the classifier fix, because a clean
/// remote close leaves the driver's result successful on that path. It pins the
/// multi-node teardown invariant that a cluster relies on when it stops relays
/// in sequence.
///
/// A cluster stops its relays in sequence, so by the time a later relay shuts
/// down its peer client pool, it still holds connections to relays that are
/// already gone. Those connections end with the remote's close code, and
/// `PeerClient::shutdown` previously propagated that terminal state as a
/// shutdown error. The relay surfaced it as `stopping relay <node>: peer
/// transport failed`, which failed the I08 GOAWAY gate's cluster cleanup in
/// two consecutive surveys on whichever relay happened to be stopped later.
/// Shutdown reports the drain exceeding its deadline, not the terminal state
/// of a connection it closed itself.
#[tokio::test]
async fn peer_client_shutdown_joins_cleanly_when_the_remote_peer_is_already_gone() -> TestResult {
    let pki = FixturePki::new();
    let client_leaf = pki.issue_peer("gone-peer-client");
    let server_leaf = pki.issue_peer("gone-peer-server");
    let server = ServerFixture::start(&pki, &server_leaf, false);

    let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("gone-peer client endpoint");
    let client_config = load_peer_client_config_from_pem(
        pki.chain(&client_leaf).as_bytes(),
        client_leaf.private_key_pem.as_bytes(),
        pki.ca_pem.as_bytes(),
    )
    .expect("gone-peer client TLS config");
    client_endpoint.set_default_client_config(client_config);
    let pins = ApprovedPeerPins::new([
        spki_sha256_from_der(&server_leaf.der).expect("gone-peer server pin")
    ])
    .expect("gone-peer client pins");
    let client = PeerClient::new(client_endpoint, pins, limits()).expect("gone-peer client");

    // One real authenticated exchange, so the pooled connection is live and
    // its driver is running rather than idle from birth.
    let connection = client.connect(server.destination.clone()).await?;
    let mut admitted = connection.open(request()).await?;
    admitted.finish().await?;
    let response = admitted.recv_response().await?;
    if response.status() != StatusCode::OK {
        return Err("gone-peer exchange was not successful".into());
    }
    if body_bytes(admitted.recv_chunk().await?)?.as_slice() != RESPONSE_B {
        return Err("gone-peer response body changed".into());
    }
    drop(admitted);

    // The remote stops first, exactly as an earlier relay in a cluster
    // teardown does. The pooled connection is now terminal through no fault
    // of this client.
    server.shutdown().await?;

    // The client still holds that pooled connection. Its own shutdown must
    // join cleanly and stay within the drain deadline.
    let started = tokio::time::Instant::now();
    client
        .shutdown()
        .await
        .map_err(|error| format!("shutting down a client whose peer is gone failed: {error}"))?;
    if started.elapsed() >= CASE_TIMEOUT {
        return Err("client shutdown did not complete within its drain deadline".into());
    }

    // Shutdown is idempotent and still clean with the pool already drained.
    client
        .shutdown()
        .await
        .map_err(|error| format!("second client shutdown failed: {error}"))?;
    Ok(())
}
