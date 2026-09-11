use super::*;

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
    },
    time::{Duration, Instant},
};

use axum::http::{Request, Response};
use bytes::Bytes;
use chrono::{DateTime, Utc};
use rcgen::{
    BasicConstraints, Certificate, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair, KeyUsagePurpose, SanType,
};
use tokio::{task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, MemoryCatalog};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerRequestHandler, PeerServer,
    PeerServerStream, PeerTransportError, PeerTransportLimits, TlsIdentity,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};

use crate::{
    peer_runtime::{
        PeerBindingFuture, PeerRuntime, PeerRuntimeError,
        peer_readiness::{PeerListenerState, PeerProbeState, PeerReadiness, PeerRouteTarget},
    },
    routing::{OwnerRouter, RelayIdentity},
};

const SOURCE_NODE: &str = "probe-source";
const SOURCE_BOOT: &str = "probe-source-boot";
const DESTINATION_NODE: &str = "probe-destination";
const DESTINATION_BOOT: &str = "probe-destination-boot";

#[derive(Clone, Copy)]
#[repr(u8)]
enum ProbeMode {
    Runtime = 0,
    Body = 1,
    Blackhole = 2,
    Delayed = 3,
}

impl ProbeMode {
    fn from_u8(value: u8) -> Self {
        match value {
            0 => Self::Runtime,
            1 => Self::Body,
            2 => Self::Blackhole,
            _ => Self::Delayed,
        }
    }
}

#[derive(Clone, Default)]
struct ReadyProvider;

impl PeerBindingProvider for ReadyProvider {
    fn binding<'a>(
        &'a self,
        _node_id: &'a str,
        _boot_id: &'a str,
        _now: DateTime<Utc>,
    ) -> PeerBindingFuture<'a> {
        Box::pin(async {
            Err(PeerRuntimeError::Membership(
                "probe fixture has no owner bindings".to_owned(),
            ))
        })
    }

    fn is_ready(&self) -> bool {
        true
    }
}

struct ProbeHandler {
    runtime: Arc<PeerRuntime>,
    mode: Arc<AtomicU8>,
    cancel: CancellationToken,
    customer_started: Arc<tokio::sync::Notify>,
    release_customer: Arc<tokio::sync::Notify>,
    admission_started: Arc<tokio::sync::Notify>,
    admission_cancelled: Arc<tokio::sync::Notify>,
    probe_started: Arc<tokio::sync::Notify>,
    release_probe: Arc<tokio::sync::Notify>,
}

impl PeerRequestHandler for ProbeHandler {
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let runtime = Arc::clone(&self.runtime);
        let mode = ProbeMode::from_u8(self.mode.load(Ordering::Acquire));
        let cancel = self.cancel.clone();
        let customer_started = Arc::clone(&self.customer_started);
        let release_customer = Arc::clone(&self.release_customer);
        let admission_started = Arc::clone(&self.admission_started);
        let admission_cancelled = Arc::clone(&self.admission_cancelled);
        let probe_started = Arc::clone(&self.probe_started);
        let release_probe = Arc::clone(&self.release_probe);
        Box::pin(async move {
            if request.uri().path() == "/internal/v1/device/data" {
                customer_started.notify_one();
                tokio::select! {
                    _ = release_customer.notified() => {}
                    _ = cancel.cancelled() => return Ok(()),
                }
                let (mut send, mut recv) = stream.split();
                while recv.recv_chunk().await?.is_some() {}
                send.send_response(Response::new(())).await?;
                return send.finish().await;
            }
            if request.uri().path() == "/internal/v1/streams" {
                admission_started.notify_one();
                let (mut send, _recv) = stream.split();
                tokio::time::sleep(Duration::from_millis(200)).await;
                match send.send_response(Response::new(())).await {
                    Ok(()) => return send.finish().await,
                    // A transport timeout means the fixture's own deadline
                    // fired.  It is not evidence that the client cancelled
                    // the dropped stream, so leave the cancellation signal
                    // unset and surface the timeout to the server task.
                    Err(PeerTransportError::Timeout) => {
                        return Err(PeerTransportError::Timeout);
                    }
                    // The client-side drop is reported by h3/quic as a
                    // stream error (or an explicit transport cancellation).
                    // Record only those errors as the expected cancellation.
                    Err(
                        PeerTransportError::H3(_)
                        | PeerTransportError::Quic(_)
                        | PeerTransportError::Cancelled,
                    ) => {
                        admission_cancelled.notify_one();
                        return Ok(());
                    }
                    Err(error) => return Err(error),
                }
            }
            if matches!(mode, ProbeMode::Runtime) {
                return runtime
                    .accept_probe(identity, request, stream)
                    .await
                    .map_err(probe_transport_error);
            }
            if matches!(mode, ProbeMode::Blackhole) {
                cancel.cancelled().await;
                return Ok(());
            }

            if matches!(mode, ProbeMode::Delayed) {
                probe_started.notify_waiters();
                tokio::select! {
                    _ = release_probe.notified() => {}
                    _ = cancel.cancelled() => return Ok(()),
                }
            }

            let (mut send, mut recv) = stream.split();
            while recv.recv_chunk().await?.is_some() {}
            send.send_response(Response::new(())).await?;
            if matches!(mode, ProbeMode::Body) {
                send.send_chunk(Bytes::from_static(b"unexpected probe body"))
                    .await?;
            }
            send.finish().await
        })
    }
}

fn probe_transport_error(error: PeerRuntimeError) -> PeerTransportError {
    match error {
        PeerRuntimeError::Transport(error) => error,
        _ => PeerTransportError::H3("probe fixture rejected request".to_owned()),
    }
}

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
        let ca_key = KeyPair::generate().expect("probe CA key");
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "probe CA");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = params.self_signed(&ca_key).expect("probe CA certificate");
        Self {
            ca_pem: ca.pem(),
            ca,
            ca_key,
        }
    }

    fn issue_peer(&self, node_id: &str) -> Leaf {
        let key = KeyPair::generate().expect("probe peer key");
        let mut params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("probe peer params");
        params
            .distinguished_name
            .push(DnType::CommonName, format!("peer/{node_id}"));
        params.subject_alt_names.push(SanType::URI(
            format!("urn:agent-tunnel:peer:{node_id}")
                .try_into()
                .expect("probe peer URI SAN"),
        ));
        params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let certificate = params
            .signed_by(&key, &self.ca, &self.ca_key)
            .expect("probe peer certificate");
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

struct H3Fixture {
    client_runtime: Arc<PeerRuntime>,
    server_runtime: Arc<PeerRuntime>,
    client_readiness: Arc<PeerReadiness>,
    target: PeerRouteTarget,
    mode: Arc<AtomicU8>,
    customer_started: Arc<tokio::sync::Notify>,
    release_customer: Arc<tokio::sync::Notify>,
    admission_started: Arc<tokio::sync::Notify>,
    admission_cancelled: Arc<tokio::sync::Notify>,
    probe_started: Arc<tokio::sync::Notify>,
    release_probe: Arc<tokio::sync::Notify>,
    cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
}

impl H3Fixture {
    fn new(mode: ProbeMode, max_streams_per_connection: usize) -> Self {
        Self::new_with_limits(
            mode,
            max_streams_per_connection,
            Duration::from_millis(100),
            Duration::from_millis(200),
        )
    }

    fn new_with_limits(
        mode: ProbeMode,
        max_streams_per_connection: usize,
        stream_timeout: Duration,
        idle_timeout: Duration,
    ) -> Self {
        let pki = FixturePki::new();
        let source_leaf = pki.issue_peer(SOURCE_NODE);
        let destination_leaf = pki.issue_peer(DESTINATION_NODE);
        let source_chain = pki.chain(&source_leaf);
        let destination_chain = pki.chain(&destination_leaf);
        let source_pin = spki_sha256_from_der(&source_leaf.der)
            .expect("source SPKI")
            .to_hex();
        let destination_pin = spki_sha256_from_der(&destination_leaf.der)
            .expect("destination SPKI")
            .to_hex();

        let server_config = load_peer_server_config_from_pem(
            destination_chain.as_bytes(),
            destination_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("probe server TLS");
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("probe server endpoint");
        let destination_address = server_endpoint.local_addr().expect("destination address");

        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("probe client endpoint");
        let source_address = client_endpoint.local_addr().expect("source address");
        let client_config = load_peer_client_config_from_pem(
            source_chain.as_bytes(),
            source_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("probe client TLS");
        client_endpoint.set_default_client_config(client_config);

        let mut server_client_endpoint =
            quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("server runtime client endpoint");
        let server_client_config = load_peer_client_config_from_pem(
            destination_chain.as_bytes(),
            destination_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("server runtime client TLS");
        server_client_endpoint.set_default_client_config(server_client_config);

        let limits = PeerTransportLimits {
            max_streams_per_connection,
            stream_timeout,
            idle_timeout,
            drain_timeout: Duration::from_secs(1),
            ..PeerTransportLimits::default()
        };

        let client_readiness = readiness(PeerRouteTarget::for_test(
            DESTINATION_NODE,
            destination_address.to_string(),
            "localhost",
            vec![destination_pin.clone()],
        ));
        let server_readiness = readiness(PeerRouteTarget::for_test(
            SOURCE_NODE,
            source_address.to_string(),
            "localhost",
            vec![source_pin.clone()],
        ));
        let provider: Arc<dyn PeerBindingProvider> = Arc::new(ReadyProvider);
        let client_router = owner_router(SOURCE_NODE, SOURCE_BOOT);
        let server_router = owner_router(DESTINATION_NODE, DESTINATION_BOOT);
        let client = PeerClient::new(
            client_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&destination_leaf.der).expect("destination pin")
            ])
            .expect("client pins"),
            limits.clone(),
        )
        .expect("peer client");
        let server_client = PeerClient::new(
            server_client_endpoint,
            ApprovedPeerPins::new([spki_sha256_from_der(&source_leaf.der).expect("source pin")])
                .expect("server runtime pins"),
            limits.clone(),
        )
        .expect("server runtime client");
        let client_runtime = Arc::new(PeerRuntime::new_with_readiness(
            client,
            client_router,
            Arc::clone(&provider),
            SOURCE_NODE,
            SOURCE_BOOT,
            Arc::clone(&client_readiness),
        ));
        let server_runtime = Arc::new(PeerRuntime::new_with_readiness(
            server_client,
            server_router,
            provider,
            DESTINATION_NODE,
            DESTINATION_BOOT,
            server_readiness,
        ));
        let mode = Arc::new(AtomicU8::new(mode as u8));
        let customer_started = Arc::new(tokio::sync::Notify::new());
        let release_customer = Arc::new(tokio::sync::Notify::new());
        let admission_started = Arc::new(tokio::sync::Notify::new());
        let admission_cancelled = Arc::new(tokio::sync::Notify::new());
        let probe_started = Arc::new(tokio::sync::Notify::new());
        let release_probe = Arc::new(tokio::sync::Notify::new());
        let cancel = CancellationToken::new();
        let handler = ProbeHandler {
            runtime: Arc::clone(&server_runtime),
            mode: Arc::clone(&mode),
            customer_started: Arc::clone(&customer_started),
            release_customer: Arc::clone(&release_customer),
            admission_started: Arc::clone(&admission_started),
            admission_cancelled: Arc::clone(&admission_cancelled),
            probe_started: Arc::clone(&probe_started),
            release_probe: Arc::clone(&release_probe),
            cancel: cancel.clone(),
        };
        let server = PeerServer::new(
            server_endpoint,
            ApprovedPeerPins::new([
                spki_sha256_from_der(&source_leaf.der).expect("source server pin")
            ])
            .expect("server pins"),
            limits,
            PeerRuntime::server_policy(),
            handler,
        )
        .expect("peer server");
        let server_task = tokio::spawn(server.serve(cancel.clone()));

        Self {
            client_runtime,
            server_runtime,
            client_readiness,
            target: PeerRouteTarget::for_test(
                DESTINATION_NODE,
                destination_address.to_string(),
                "localhost",
                vec![destination_pin],
            ),
            mode,
            customer_started,
            release_customer,
            admission_started,
            admission_cancelled,
            probe_started,
            release_probe,
            cancel,
            server_task,
        }
    }

    fn set_mode(&self, mode: ProbeMode) {
        self.mode.store(mode as u8, Ordering::Release);
    }

    fn destination(&self) -> PeerDestination {
        PeerDestination::new(
            self.target
                .peer_endpoint()
                .parse()
                .expect("probe destination address"),
            self.target.server_name(),
        )
    }

    fn health_request() -> Request<()> {
        Request::builder()
            .method("GET")
            .uri("https://localhost/internal/v1/health")
            .body(())
            .expect("probe health request")
    }

    fn customer_request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://localhost/internal/v1/device/data")
            .body(())
            .expect("customer request")
    }

    fn consumer_stream_request() -> Request<()> {
        Request::builder()
            .method("POST")
            .uri("https://localhost/internal/v1/streams")
            .body(())
            .expect("consumer stream request")
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let server_result = timeout(Duration::from_secs(3), self.server_task)
            .await
            .expect("probe server shutdown deadline")
            .expect("probe server join");
        assert!(
            server_result.is_ok(),
            "probe server failed: {server_result:?}"
        );
        self.client_runtime
            .shutdown()
            .await
            .expect("client runtime shutdown");
        self.server_runtime
            .shutdown()
            .await
            .expect("server runtime shutdown");
    }
}

fn owner_router(node_id: &str, boot_id: &str) -> Arc<OwnerRouter<dyn Catalog>> {
    let catalog: Arc<dyn Catalog> = Arc::new(MemoryCatalog::new());
    let identity = RelayIdentity::new("probe-deployment", node_id, boot_id).expect("identity");
    Arc::new(OwnerRouter::new(catalog, identity).expect("owner router"))
}

fn readiness(target: PeerRouteTarget) -> Arc<PeerReadiness> {
    let readiness = Arc::new(PeerReadiness::new(1).expect("readiness"));
    readiness.set_listener_state(PeerListenerState::Bound);
    readiness.set_available_capacity(1);
    readiness
        .replace_required_routes([target])
        .expect("readiness route");
    readiness
}

#[tokio::test]
async fn real_h3_probe_accepts_authenticated_empty_eof() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 2);
    let result = fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await;
    assert!(
        result.is_ok(),
        "empty authenticated probe failed: {result:?}"
    );
    assert!(fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_probe_rejects_nonempty_response_body() {
    let fixture = H3Fixture::new(ProbeMode::Body, 2);
    let result = fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await;
    assert!(
        matches!(result, Err(PeerRuntimeError::Closed)),
        "unexpected nonempty-body result: {result:?}"
    );
    assert!(!fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_probe_has_one_deadline_after_cached_connection_blackhole() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 2);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("seed pooled authenticated connection");
    fixture.set_mode(ProbeMode::Blackhole);
    let started = Instant::now();
    let result = fixture
        .client_runtime
        .probe_route_with_deadline(&fixture.target, Duration::from_millis(75))
        .await;
    assert!(
        matches!(
            result,
            Err(PeerRuntimeError::Transport(PeerTransportError::Timeout))
        ),
        "blackhole result was not a bounded timeout: {result:?}"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
    let refresh = fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await;
    assert!(refresh.is_err(), "blackhole refresh unexpectedly succeeded");
    assert!(!fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_stream_capacity_failure_withdraws_and_recovers_readiness() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 1);
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("cached connection");
    let mut held = connection
        .open(H3Fixture::health_request())
        .await
        .expect("reserve only request stream");
    held.finish().await.expect("finish held request body");
    held.recv_response()
        .await
        .expect("held request response headers");
    assert!(
        held.recv_chunk()
            .await
            .expect("held request response body")
            .is_none()
    );

    let result = fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await;
    // A reserved stream permit is a bounded capacity condition.  The
    // transport keeps sender-lock and H3 setup timeouts distinct, so refresh
    // records capacity and withdraws readiness without closing the pooled
    // connection.
    assert!(
        matches!(
            result,
            Err(PeerRuntimeError::Transport(PeerTransportError::Capacity))
        ),
        "stream-capacity result was not typed capacity: {result:?}"
    );
    assert_eq!(fixture.client_readiness.snapshot().capacity_ready_routes, 0);
    assert!(!fixture.client_readiness.is_ready());

    drop(held);
    let mut customer_stream = connection
        .open(H3Fixture::health_request())
        .await
        .expect("capacity probe retired a healthy pooled connection");
    customer_stream
        .finish()
        .await
        .expect("customer request body finish");
    let response = customer_stream
        .recv_response()
        .await
        .expect("customer response headers");
    assert!(response.status().is_success());
    assert!(
        customer_stream
            .recv_chunk()
            .await
            .expect("customer response body")
            .is_none()
    );
    drop(customer_stream);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("probe after stream release");
    assert!(fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

/// A full configured peer connection must report its exhausted HTTP/3 stream
/// permit as capacity.  This intentionally holds every one of the production
/// 128 request-stream permits before asking the authenticated readiness probe
/// for one more, while retaining a separate response-timeout negative case.
#[tokio::test]
async fn real_h3_full_stream_checkout_is_typed_capacity() {
    const STREAM_LIMIT: usize = 128;
    let fixture = H3Fixture::new(ProbeMode::Runtime, STREAM_LIMIT);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("seed healthy readiness before exhausting stream permits");
    assert!(fixture.client_readiness.is_ready());
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("cached connection");
    let mut held = Vec::with_capacity(STREAM_LIMIT);
    for _ in 0..STREAM_LIMIT {
        let mut stream = connection
            .open(H3Fixture::health_request())
            .await
            .expect("reserve configured request stream");
        stream.finish().await.expect("finish held request body");
        stream
            .recv_response()
            .await
            .expect("held request response headers");
        assert!(
            stream
                .recv_chunk()
                .await
                .expect("held request response body")
                .is_none()
        );
        held.push(stream);
    }

    let result = fixture
        .client_runtime
        .probe_route_with_deadline(&fixture.target, Duration::from_millis(75))
        .await;
    assert!(
        matches!(
            result,
            Err(PeerRuntimeError::Transport(PeerTransportError::Capacity))
        ),
        "full stream checkout was not typed capacity: {result:?}"
    );

    let refresh = fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await;
    assert!(
        matches!(
            refresh,
            Err(PeerRuntimeError::Transport(PeerTransportError::Capacity))
        ),
        "refresh did not preserve the typed capacity result: {refresh:?}"
    );
    assert_eq!(fixture.client_readiness.snapshot().capacity_ready_routes, 0);
    assert!(!fixture.client_readiness.is_ready());

    drop(held);
    fixture.set_mode(ProbeMode::Runtime);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("probe after releasing all stream permits");
    assert!(fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

/// A response-path timeout is still a timeout.  The permit-specific capacity
/// classification must not relabel a cached-connection blackhole.
#[tokio::test]
async fn real_h3_response_timeout_remains_timeout() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 2);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("seed pooled authenticated connection");
    fixture.set_mode(ProbeMode::Blackhole);
    let result = fixture
        .client_runtime
        .probe_route_with_deadline(&fixture.target, Duration::from_millis(75))
        .await;
    assert!(
        matches!(
            result,
            Err(PeerRuntimeError::Transport(PeerTransportError::Timeout))
        ),
        "response timeout was relabeled as capacity: {result:?}"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_probe_failure_does_not_close_active_customer_stream() {
    let fixture = H3Fixture::new(ProbeMode::Body, 2);
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("cached connection");
    let mut customer_stream = connection
        .open(H3Fixture::customer_request())
        .await
        .expect("customer stream");
    customer_stream
        .finish()
        .await
        .expect("customer request body finish");
    let customer_started = timeout(
        Duration::from_millis(750),
        fixture.customer_started.notified(),
    )
    .await
    .is_ok();
    if !customer_started {
        fixture.shutdown().await;
        panic!("customer request did not reach the peer");
    }

    let probe_result = fixture
        .client_runtime
        .probe_route_with_deadline(&fixture.target, Duration::from_millis(750))
        .await;

    fixture.release_customer.notify_one();
    let customer_result = timeout(Duration::from_secs(1), async {
        let response = customer_stream.recv_response().await?;
        let body = customer_stream.recv_chunk().await?;
        Ok::<bool, PeerTransportError>(response.status().is_success() && body.is_none())
    })
    .await;

    fixture.set_mode(ProbeMode::Runtime);
    let replacement_result = timeout(Duration::from_secs(1), async {
        let replacement = fixture
            .client_runtime
            .client
            .connect(fixture.destination())
            .await?;
        let mut replacement_stream = replacement.open(H3Fixture::health_request()).await?;
        replacement_stream.finish().await?;
        let response = replacement_stream.recv_response().await?;
        let body = replacement_stream.recv_chunk().await?;
        Ok::<bool, PeerTransportError>(response.status().is_success() && body.is_none())
    })
    .await;

    fixture.shutdown().await;
    assert!(
        matches!(&probe_result, &Err(PeerRuntimeError::Closed)),
        "health probe did not fail with the bounded response error: {probe_result:?}"
    );
    assert!(
        matches!(&customer_result, Ok(Ok(true))),
        "customer stream was closed by the failed probe: {customer_result:?}"
    );
    assert!(
        matches!(&replacement_result, Ok(Ok(true))),
        "replacement health stream did not recover: {replacement_result:?}"
    );
}

#[tokio::test]
async fn real_h3_revision_fences_old_success_after_current_route_loss() {
    let fixture = H3Fixture::new(ProbeMode::Delayed, 2);
    let started = fixture.probe_started.notified();
    let runtime = Arc::clone(&fixture.client_runtime);
    let target = fixture.target.clone();
    let refresh = tokio::spawn(async move { runtime.refresh_required_routes(vec![target]).await });
    timeout(Duration::from_millis(750), started)
        .await
        .expect("delayed probe did not reach the real H3 handler");
    let second_revision = fixture
        .client_readiness
        .replace_required_routes_with_revision([fixture.target.clone()])
        .expect("new refresh revision");
    fixture
        .client_readiness
        .record_probe_at(
            second_revision,
            &fixture.target,
            PeerProbeState::Unreachable,
        )
        .expect("current route loss");
    fixture.release_probe.notify_one();
    let refresh_result = refresh.await.expect("refresh task join");
    assert!(
        refresh_result.is_ok(),
        "stale probe should be ignored rather than fail refresh: {refresh_result:?}"
    );
    assert_eq!(fixture.client_readiness.snapshot().reachable_routes, 0);
    assert!(!fixture.client_readiness.is_ready());

    fixture.set_mode(ProbeMode::Runtime);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("recovery probe");
    assert!(fixture.client_readiness.is_ready());
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_stale_capacity_error_is_returned_without_overwriting_current_healthy_revision() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 1);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("seed healthy readiness");
    assert!(fixture.client_readiness.is_ready());

    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("cached connection");
    let mut held = connection
        .open(H3Fixture::health_request())
        .await
        .expect("hold the only request stream permit");
    held.finish().await.expect("finish held request body");
    held.recv_response()
        .await
        .expect("held request response headers");
    assert!(
        held.recv_chunk()
            .await
            .expect("held request response body")
            .is_none()
    );

    let first_revision = fixture.client_readiness.current_revision();
    let runtime = Arc::clone(&fixture.client_runtime);
    let target = fixture.target.clone();
    let stale_refresh =
        tokio::spawn(async move { runtime.refresh_required_routes(vec![target]).await });
    timeout(Duration::from_millis(750), async {
        loop {
            if fixture.client_readiness.current_revision() > first_revision {
                break;
            }
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("stale refresh did not install its revision");

    let current_revision = fixture
        .client_readiness
        .replace_required_routes_with_revision([fixture.target.clone()])
        .expect("current healthy revision");
    fixture
        .client_readiness
        .record_probe_at(current_revision, &fixture.target, PeerProbeState::Reachable)
        .expect("publish current healthy probe");
    assert!(fixture.client_readiness.is_ready());

    let stale_result = stale_refresh.await.expect("stale refresh task join");
    let newer_revision_stayed_ready = fixture.client_readiness.is_ready();
    let capacity_ready_routes = fixture.client_readiness.snapshot().capacity_ready_routes;

    drop(held);
    fixture.set_mode(ProbeMode::Runtime);
    fixture
        .client_runtime
        .refresh_required_routes(vec![fixture.target.clone()])
        .await
        .expect("probe after releasing stream permit");
    assert!(fixture.client_readiness.is_ready());
    fixture.shutdown().await;
    assert!(
        matches!(
            stale_result,
            Err(PeerRuntimeError::Transport(PeerTransportError::Capacity))
        ),
        "stale capacity result was hidden: {stale_result:?}"
    );
    assert!(
        newer_revision_stayed_ready,
        "stale capacity result overwrote the current healthy revision"
    );
    assert_eq!(capacity_ready_routes, 1);
}

#[tokio::test]
async fn real_h3_health_request_body_is_rejected_before_response() {
    let fixture = H3Fixture::new(ProbeMode::Runtime, 2);
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("health connection");
    let mut stream = connection
        .open(H3Fixture::health_request())
        .await
        .expect("health stream");
    stream
        .send_chunk(Bytes::from_static(b"unexpected request body"))
        .await
        .expect("send request body");
    stream.finish().await.expect("finish request body");
    let response = timeout(Duration::from_millis(750), stream.recv_response()).await;
    assert!(
        response.is_err() || response.expect("response result").is_err(),
        "health request body must not receive a successful response"
    );
    fixture.shutdown().await;
}

#[tokio::test]
async fn real_h3_dropped_admission_stream_cancels_without_poisoning_connection() {
    // The handler deliberately waits 200 ms before writing headers.  Keep
    // this cancellation fixture's transport deadlines above that delay so a
    // server-side Timeout cannot be mistaken for a client-side stream drop.
    let fixture = H3Fixture::new_with_limits(
        ProbeMode::Runtime,
        2,
        Duration::from_secs(1),
        Duration::from_secs(2),
    );
    let connection = fixture
        .client_runtime
        .client
        .connect(fixture.destination())
        .await
        .expect("admission connection");
    // First prove that the production-approved consumer-stream path really
    // reaches a handler and can complete successfully on this connection.
    let control_started = fixture.admission_started.notified();
    let mut control = connection
        .open(H3Fixture::consumer_stream_request())
        .await
        .expect("consumer stream control");
    control.finish().await.expect("finish control request");
    timeout(Duration::from_secs(1), control_started)
        .await
        .expect("consumer stream handler did not start for control");
    let control_response = timeout(Duration::from_secs(1), control.recv_response())
        .await
        .expect("consumer stream control response deadline")
        .expect("consumer stream control response");
    assert!(control_response.status().is_success());
    assert!(
        control
            .recv_chunk()
            .await
            .expect("consumer stream control body")
            .is_none()
    );

    // Now open the same allowed route and cancel it after the handler has
    // started, before it writes headers.  The expected signal is the actual
    // failed send, not a client-side Timeout result.
    let dropped_started = fixture.admission_started.notified();
    let mut stream = connection
        .open(H3Fixture::consumer_stream_request())
        .await
        .expect("consumer stream cancellation request");
    stream.finish().await.expect("finish cancellation request");
    timeout(Duration::from_secs(1), dropped_started)
        .await
        .expect("consumer stream handler did not start for cancellation");
    drop(stream);

    timeout(
        Duration::from_secs(2),
        fixture.admission_cancelled.notified(),
    )
    .await
    .expect("dropped consumer stream was not observed by the peer");

    let mut health = connection
        .open(H3Fixture::health_request())
        .await
        .expect("connection remains reusable after admission cancellation");
    health.finish().await.expect("finish health request");
    let response = health
        .recv_response()
        .await
        .expect("health response after admission cancellation");
    assert!(response.status().is_success());
    assert!(
        health
            .recv_chunk()
            .await
            .expect("health response body after admission cancellation")
            .is_none()
    );

    fixture.shutdown().await;
}
