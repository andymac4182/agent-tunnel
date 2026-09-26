//! Real private HTTP/3 acceptance components for the M7 cluster fixture.
//!
//! This module deliberately stops at one authenticated relay-to-relay
//! connection.  It proves that the frozen peer transport can send response
//! headers and body before the request body reaches request-end, reject an
//! unapproved key and a non-peer role, and enforce its per-chunk bound.  It
//! does not claim three-node routing or replace the eventual relay
//! forwarding path with an in-memory echo.

use std::{
    future::pending,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::{
    net::{TcpListener, UdpSocket},
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerDestination, PeerRequestHandler, PeerRequestPolicy,
    PeerServer, PeerServerStream, PeerTransportError, PeerTransportLimits, SharedPeerPins,
    SpkiSha256, TlsIdentity, load_client_config_from_pem_with_alpn,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, load_quinn_client_config,
    load_quinn_server_config, load_server_config_from_pem_with_alpn, spki_sha256_from_der,
};
use uuid::Uuid;

use crate::cluster_fixture::ClusterFixture;
use crate::{CertificateMaterial, FixturePki, HarnessError, Result};

const SERVER_NODE_ID: &str = "relay-a";
const CLIENT_NODE_ID: &str = "relay-b";
const SERVER_NAME: &str = "localhost";
const DUPLEX_PATH: &str = "/m7/duplex";
const OVERSIZED_PATH: &str = "/m7/oversized";
const RESPONSE_HEAD_TRUNCATION_PATH: &str = "/m7/fault/response-head-truncation";
const RESPONSE_BODY_TRUNCATION_PATH: &str = "/m7/fault/response-body-truncation";
const IDLE_BLACKHOLE_PATH: &str = "/m7/fault/idle-blackhole";
const SATURATED_LANE_PATH: &str = "/m7/fault/saturated-lane";
const PIN_REVOCATION_PATH: &str = "/m7/fault/pin-revocation";
const ISOLATED_STREAM_PATH: &str = "/m7/fault/isolated-stream";
const SURVIVING_STREAM_PATH: &str = "/m7/fault/surviving-stream";
const STREAM_BUDGET_PATH: &str = "/m7/fault/stream-budget";
const CONNECTION_BUDGET_PATH: &str = "/m7/fault/connection-budget";
const UDP_BLACKHOLE_PATH: &str = "/m7/fault/udp-blackhole";
const NO_FALLBACK_PATH: &str = "/m7/fault/no-fallback";
const RESPONSE_HEADER: &str = "response-before-request-end";
const REQUEST_PREFIX: &[u8] = b"request-prefix-before-response";
const RESPONSE_BODY: &[u8] = b"response-body-before-request-end\0\xff";
const TRUNCATED_RESPONSE_BODY: &[u8] = b"response-body-prefix-only";
const TRUNCATION_BARRIER: &[u8] = b"client-observed-response-prefix";
const PIN_REVOCATION_BODY: &[u8] = b"body-before-pin-revocation";
const SURVIVING_STREAM_BODY: &[u8] = b"stream-b-survives";
const UDP_BLACKHOLE_BODY: &[u8] = b"body-blocked-during-udp-blackhole";
const UDP_RESTORED_BODY: &[u8] = b"body-after-udp-restoration";
const NO_FALLBACK_BODY: &[u8] = b"h3-positive-control";
const CASE_TIMEOUT: Duration = Duration::from_secs(8);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const FALLBACK_PROBE_SETTLE: Duration = Duration::from_millis(500);
const ZERO_RTT_TICKET_WAIT: Duration = Duration::from_secs(1);
const UDP_PROXY_IO_TIMEOUT: Duration = Duration::from_millis(500);

/// Evidence returned by the component-level M7 private-peer acceptance.
///
/// A successful value proves only the authenticated, bounded H3 exchange and
/// its negative cases.  It is intentionally not a three-node routing result;
/// the fixture's ingress fanout remains a logical routing plan until relay
/// forwarding is wired.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClusterTransportEvidence {
    /// HTTP status received before the client finished its request body.
    pub response_status: u16,
    /// Response bytes received before the client finished its request body.
    pub response_body: Vec<u8>,
    /// Whether response headers were observed before request-end.
    pub response_before_request_end: bool,
    /// Whether the response body was observed before request-end.
    pub body_before_request_end: bool,
    /// Whether the wrong server SPKI pin was rejected.
    pub wrong_pin_rejected: bool,
    /// Whether a device-role leaf was rejected on the peer route.
    pub wrong_role_rejected: bool,
    /// Whether a body chunk over the configured limit was rejected locally.
    pub oversized_chunk_rejected: bool,
    /// Whether the client pool cancelled and joined its connection driver.
    pub client_shutdown_joined: bool,
    /// Whether the server cancelled and joined its connection/request tasks.
    pub server_shutdown_joined: bool,
    /// Whether an absent response head was reported as a bounded failure.
    pub response_head_truncation_rejected: bool,
    /// Whether a response body that ended before finish was reported as
    /// truncated rather than accepted as a complete response.
    pub response_body_truncation_rejected: bool,
    /// Whether an idle peer stream closed at its configured inactivity bound.
    pub idle_blackhole_closed: bool,
    /// Whether cancellation woke a request waiting behind a saturated stream
    /// lane within the absolute checkout bound.
    pub saturated_lane_cancellation_bounded: bool,
    /// Whether revoking the authenticated peer pin closed an active stream.
    pub active_stream_pin_revocation_closed: bool,
    /// Whether canceling one stream while its receive is pending left another
    /// stream on the same H3 connection usable.
    pub shared_stream_isolated: bool,
    /// Whether sequential chunks reclaimed stream and pooled-connection body
    /// budget while preserving every echoed payload.
    pub body_budget_reclamation_verified: bool,
    /// Whether a real loopback UDP blackhole stopped an admitted H3 response
    /// at its idle deadline and restoration allowed a fresh trusted exchange.
    pub udp_blackhole_restored: bool,
    /// Whether a blocked UDP peer endpoint failed without accepting a TCP
    /// fallback connection.
    pub no_tcp_fallback: bool,
    /// Whether a real Quinn connection could not enter 0-RTT and admitted no
    /// peer request before the normal handshake.
    pub zero_rtt_not_admitted: bool,
}

/// Run the bounded authenticated H3 component against two fixture relays.
///
/// The supplied [`ClusterFixture`] contributes the distinct relay leaves and
/// dedicated peer CA.  The supplied [`FixturePki`] is used only to create the
/// deliberately wrong-role negative leaf.  All sockets are real loopback
/// QUIC endpoints, and every case owns cancellation and joins its server and
/// client tasks before returning.
pub async fn verify(
    fixture: &ClusterFixture,
    pki: &FixturePki,
) -> Result<ClusterTransportEvidence> {
    let server_node = fixture.node(SERVER_NODE_ID).ok_or_else(|| {
        HarnessError::InvalidInput(format!("M7 fixture is missing {SERVER_NODE_ID}"))
    })?;
    let client_node = fixture.node(CLIENT_NODE_ID).ok_or_else(|| {
        HarnessError::InvalidInput(format!("M7 fixture is missing {CLIENT_NODE_ID}"))
    })?;

    let server = peer_material(
        &server_node.peer_certificate,
        &fixture.peer_ca.certificate_pem,
    )?;
    let client = peer_material(
        &client_node.peer_certificate,
        &fixture.peer_ca.certificate_pem,
    )?;
    let limits = test_limits()?;

    let duplex = run_duplex_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
        limits.clone(),
    )
    .await?;
    if duplex.status != StatusCode::OK.as_u16()
        || !duplex.response_before_request_end
        || !duplex.body_before_request_end
    {
        return Err(HarnessError::Http(
            "M7 peer response was not complete before request-end".to_owned(),
        ));
    }

    let wrong_pin_rejected = run_wrong_pin_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
        limits.clone(),
    )
    .await?;

    let wrong_role = pki.issue_device_signed_by_peer_ca(Uuid::new_v4(), Uuid::new_v4())?;
    let wrong_role = peer_material(&wrong_role, &fixture.peer_ca.certificate_pem)?;
    let wrong_role_rejected = run_wrong_role_case(
        &server,
        &wrong_role,
        fixture.peer_ca.certificate_pem.as_str(),
        limits.clone(),
    )
    .await?;

    let oversized_chunk_rejected =
        run_oversized_chunk_case(&server, &client, fixture.peer_ca.certificate_pem.as_str())
            .await?;

    let (response_head_truncation_rejected, response_body_truncation_rejected) =
        run_response_truncation_cases(
            &server,
            &client,
            fixture.peer_ca.certificate_pem.as_str(),
            limits.clone(),
        )
        .await?;
    let idle_blackhole_closed =
        run_idle_blackhole_case(&server, &client, fixture.peer_ca.certificate_pem.as_str()).await?;
    let saturated_lane_cancellation_bounded = run_saturated_lane_cancellation_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
    )
    .await?;
    let active_stream_pin_revocation_closed = run_active_stream_pin_revocation_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
    )
    .await?;
    let shared_stream_isolated = run_shared_stream_isolation_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
    )
    .await?;
    let body_budget_reclamation_verified = run_body_budget_reclamation_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
    )
    .await?;
    let udp_blackhole_restored =
        run_udp_blackhole_case(&server, &client, fixture.peer_ca.certificate_pem.as_str()).await?;
    let (no_tcp_fallback, zero_rtt_not_admitted) = run_no_fallback_and_zero_rtt_case(
        &server,
        &client,
        fixture.peer_ca.certificate_pem.as_str(),
    )
    .await?;

    Ok(ClusterTransportEvidence {
        response_status: duplex.status,
        response_body: duplex.body,
        response_before_request_end: duplex.response_before_request_end,
        body_before_request_end: duplex.body_before_request_end,
        wrong_pin_rejected,
        wrong_role_rejected,
        oversized_chunk_rejected,
        client_shutdown_joined: true,
        server_shutdown_joined: true,
        response_head_truncation_rejected,
        response_body_truncation_rejected,
        idle_blackhole_closed,
        saturated_lane_cancellation_bounded,
        active_stream_pin_revocation_closed,
        shared_stream_isolated,
        body_budget_reclamation_verified,
        udp_blackhole_restored,
        no_tcp_fallback,
        zero_rtt_not_admitted,
    })
}

#[derive(Clone, Debug)]
struct PeerMaterial {
    chain_pem: String,
    private_key_pem: String,
    pin: SpkiSha256,
}

fn peer_material(certificate: &CertificateMaterial, peer_ca_pem: &str) -> Result<PeerMaterial> {
    let pin = spki_sha256_from_der(&certificate.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("deriving peer SPKI: {error}")))?;
    Ok(PeerMaterial {
        chain_pem: format!("{}{}", certificate.certificate_pem, peer_ca_pem),
        private_key_pem: certificate.private_key_pem.clone(),
        pin,
    })
}

fn test_limits() -> Result<PeerTransportLimits> {
    PeerTransportLimits::new(
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        2,
        4,
        2,
        16 * 1024,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .map_err(|error| HarnessError::Http(format!("building M7 peer limits: {error}")))
}

fn bounded_chunk_limits() -> Result<PeerTransportLimits> {
    PeerTransportLimits::new(
        4,
        8,
        16,
        1,
        1,
        1,
        1024,
        Duration::from_secs(2),
        Duration::from_secs(2),
    )
    .map_err(|error| HarnessError::Http(format!("building M7 chunk limits: {error}")))
}

fn fault_limits(max_streams_per_connection: usize) -> Result<PeerTransportLimits> {
    PeerTransportLimits::new_with_timeouts(
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        1,
        max_streams_per_connection,
        1,
        16 * 1024,
        Duration::from_millis(500),
        Duration::from_millis(750),
        Duration::from_millis(120),
        Duration::from_millis(750),
    )
    .map_err(|error| HarnessError::Http(format!("building M7 fault limits: {error}")))
}

fn peer_server_config(material: &PeerMaterial, peer_ca_pem: &str) -> Result<quinn::ServerConfig> {
    load_peer_server_config_from_pem(
        material.chain_pem.as_bytes(),
        material.private_key_pem.as_bytes(),
        peer_ca_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building M7 peer server TLS: {error}")))
}

fn peer_client_config(material: &PeerMaterial, peer_ca_pem: &str) -> Result<quinn::ClientConfig> {
    load_peer_client_config_from_pem(
        material.chain_pem.as_bytes(),
        material.private_key_pem.as_bytes(),
        peer_ca_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building M7 peer client TLS: {error}")))
}

fn pins(pin: SpkiSha256) -> Result<ApprovedPeerPins> {
    ApprovedPeerPins::new([pin])
        .map_err(|error| HarnessError::Http(format!("building M7 peer pin set: {error}")))
}

/// A bounded loopback UDP forwarder used to inject a real QUIC path fault.
///
/// One socket represents the network path between the client and the server;
/// it remembers the single synthetic client address and forwards datagrams in
/// both directions.  Toggling [`Self::set_drop`] drops both directions while
/// keeping the socket and task alive, so restoring the path does not silently
/// create a second proxy or trusted identity.
struct UdpFaultProxy {
    address: SocketAddr,
    drop_packets: Arc<AtomicBool>,
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl UdpFaultProxy {
    async fn bind(server_address: SocketAddr) -> Result<Self> {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .map_err(|error| HarnessError::Http(format!("binding M7 UDP fault proxy: {error}")))?;
        let address = socket.local_addr().map_err(|error| {
            HarnessError::Http(format!("reading M7 UDP proxy address: {error}"))
        })?;
        let drop_packets = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task_drop = drop_packets.clone();
        let task = tokio::spawn(async move {
            let mut client_address = None;
            let mut packet = [0_u8; 64 * 1024];
            loop {
                let (length, source) = tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    received = socket.recv_from(&mut packet) => received
                        .map_err(|error| HarnessError::Http(format!("receiving M7 UDP proxy datagram: {error}")))?,
                };
                let destination = if source == server_address {
                    match client_address {
                        Some(client_address) => client_address,
                        None => continue,
                    }
                } else {
                    client_address = Some(source);
                    server_address
                };
                if task_drop.load(Ordering::Acquire) {
                    continue;
                }
                timeout(
                    UDP_PROXY_IO_TIMEOUT,
                    socket.send_to(&packet[..length], destination),
                )
                .await
                .map_err(|_| HarnessError::Timeout("M7 UDP proxy send timed out".to_owned()))?
                .map_err(|error| {
                    HarnessError::Http(format!("sending M7 UDP proxy datagram: {error}"))
                })?;
            }
            Ok(())
        });
        Ok(Self {
            address,
            drop_packets,
            cancel,
            task: Some(task),
        })
    }

    fn address(&self) -> SocketAddr {
        self.address
    }

    fn set_drop(&self, drop_packets: bool) {
        self.drop_packets.store(drop_packets, Ordering::Release);
    }

    async fn shutdown(&mut self) -> Result<()> {
        self.cancel.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(CLEANUP_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(error)) => Err(HarnessError::Http(format!("M7 UDP proxy task: {error}"))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(HarnessError::Timeout(
                    "M7 UDP proxy shutdown timed out".to_owned(),
                ))
            }
        }
    }
}

impl Drop for UdpFaultProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn make_server<P, H>(
    material: &PeerMaterial,
    peer_ca_pem: &str,
    approved_client_pin: SpkiSha256,
    limits: PeerTransportLimits,
    policy: P,
    handler: H,
) -> Result<(PeerServer<P, H>, SocketAddr)>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let endpoint = quinn::Endpoint::server(
        peer_server_config(material, peer_ca_pem)?,
        SocketAddr::from(([127, 0, 0, 1], 0)),
    )
    .map_err(|error| HarnessError::Http(format!("binding M7 peer H3 server: {error}")))?;
    let address = endpoint
        .local_addr()
        .map_err(|error| HarnessError::Http(format!("reading M7 peer H3 address: {error}")))?;
    let pin_provider = SharedPeerPins::new(pins(approved_client_pin)?)
        .map_err(|error| HarnessError::Http(format!("building M7 peer pin provider: {error}")))?;
    let server = PeerServer::new_with_pin_provider(endpoint, pin_provider, limits, policy, handler)
        .map_err(|error| HarnessError::Http(format!("constructing M7 peer server: {error}")))?;
    Ok((server, address))
}

fn make_server_with_pin_provider<P, H>(
    material: &PeerMaterial,
    peer_ca_pem: &str,
    pin_provider: SharedPeerPins,
    limits: PeerTransportLimits,
    policy: P,
    handler: H,
) -> Result<(PeerServer<P, H>, SocketAddr)>
where
    P: PeerRequestPolicy,
    H: PeerRequestHandler,
{
    let endpoint = quinn::Endpoint::server(
        peer_server_config(material, peer_ca_pem)?,
        SocketAddr::from(([127, 0, 0, 1], 0)),
    )
    .map_err(|error| HarnessError::Http(format!("binding M7 peer H3 server: {error}")))?;
    let address = endpoint
        .local_addr()
        .map_err(|error| HarnessError::Http(format!("reading M7 peer H3 address: {error}")))?;
    let server = PeerServer::new_with_pin_provider(endpoint, pin_provider, limits, policy, handler)
        .map_err(|error| HarnessError::Http(format!("constructing M7 peer server: {error}")))?;
    Ok((server, address))
}

fn make_client(
    material: &PeerMaterial,
    peer_ca_pem: &str,
    approved_server_pin: SpkiSha256,
    limits: PeerTransportLimits,
) -> Result<PeerClient> {
    let mut endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(|error| HarnessError::Http(format!("binding M7 peer H3 client: {error}")))?;
    endpoint.set_default_client_config(peer_client_config(material, peer_ca_pem)?);
    let pin_provider = SharedPeerPins::new(pins(approved_server_pin)?)
        .map_err(|error| HarnessError::Http(format!("building M7 peer pin provider: {error}")))?;
    PeerClient::new_with_pin_provider(endpoint, pin_provider, limits)
        .map_err(|error| HarnessError::Http(format!("constructing M7 peer client: {error}")))
}

#[derive(Debug)]
struct DuplexResult {
    status: u16,
    body: Vec<u8>,
    response_before_request_end: bool,
    body_before_request_end: bool,
}

async fn run_duplex_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
    limits: PeerTransportLimits,
) -> Result<DuplexResult> {
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == DUPLEX_PATH
    };
    let handler = move |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| {
        async move {
            let response = Response::builder()
                .status(StatusCode::OK)
                .header("x-m7-duplex", RESPONSE_HEADER)
                .body(())
                .map_err(|error| PeerTransportError::H3(error.to_string()))?;
            let (mut send, mut recv) = stream.split();

            // The request receiver is intentionally untouched until after the
            // response has been sent and finished.  This is the actual
            // bidirectional proof; no echo or in-memory transport is used.
            send.send_response(response).await?;
            send.send_chunk(Bytes::from_static(RESPONSE_BODY)).await?;
            send.finish().await?;
            while recv.recv_chunk().await?.is_some() {}
            Ok(())
        }
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let exchange = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        let connection = client
            .connect(destination)
            .await
            .map_err(|error| HarnessError::Http(format!("M7 peer connect: {error}")))?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://agent-tunnel.peer{DUPLEX_PATH}"))
            .body(())
            .map_err(|error| HarnessError::Http(format!("building M7 H3 request: {error}")))?;
        let stream = connection
            .open(request)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 H3 stream: {error}")))?;
        let (mut send, mut recv) = stream.split();

        // Send a prefix, leave request-end open, and wait for response headers
        // and body.  Only after both have arrived is request-end sent below.
        send.send_chunk(Bytes::from_static(REQUEST_PREFIX))
            .await
            .map_err(|error| HarnessError::Http(format!("sending M7 request prefix: {error}")))?;
        let response = recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 response headers: {error}"))
        })?;
        let response_before_request_end = response.status() == StatusCode::OK
            && response
                .headers()
                .get("x-m7-duplex")
                .and_then(|value| value.to_str().ok())
                == Some(RESPONSE_HEADER);

        let mut body = Vec::new();
        while let Some(chunk) = recv
            .recv_chunk()
            .await
            .map_err(|error| HarnessError::Http(format!("receiving M7 response body: {error}")))?
        {
            body.extend_from_slice(chunk.as_bytes());
        }
        let body_before_request_end = body.as_slice() == RESPONSE_BODY;
        send.finish()
            .await
            .map_err(|error| HarnessError::Http(format!("finishing M7 request body: {error}")))?;

        Ok::<_, HarnessError>(DuplexResult {
            status: response.status().as_u16(),
            body,
            response_before_request_end,
            body_before_request_end,
        })
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 duplex exchange timed out".to_owned(),
        )),
    };

    finish_client_and_server(client, cancel, server_task, exchange).await
}

async fn run_wrong_pin_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
    limits: PeerTransportLimits,
) -> Result<bool> {
    let policy = |_identity: &TlsIdentity, _request: &Request<()>| true;
    let handler = |_identity: TlsIdentity, _request: Request<()>, _stream: PeerServerStream| async move {
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let wrong_server_pin = SpkiSha256::from_bytes([0xa5; 32]);
    let client = make_client(client_material, peer_ca_pem, wrong_server_pin, limits)?;
    let result = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        client.connect(destination).await
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(PeerTransportError::Timeout),
    };
    let rejected = matches!(result, Err(PeerTransportError::Authentication(_)));
    finish_client_and_server(client, cancel, server_task, Ok::<_, HarnessError>(())).await?;
    if !rejected {
        return Err(HarnessError::Http(
            "M7 wrong server SPKI pin unexpectedly connected".to_owned(),
        ));
    }
    Ok(true)
}

async fn run_wrong_role_case(
    server_material: &PeerMaterial,
    wrong_role_client: &PeerMaterial,
    peer_ca_pem: &str,
    limits: PeerTransportLimits,
) -> Result<bool> {
    let policy = |_identity: &TlsIdentity, _request: &Request<()>| true;
    let handler = |_identity: TlsIdentity, _request: Request<()>, _stream: PeerServerStream| async move {
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        wrong_role_client.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(wrong_role_client, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        match client.connect(destination).await {
            Err(error) => Err(error),
            Ok(connection) => {
                let request = Request::builder()
                    .method("POST")
                    .uri(format!("https://agent-tunnel.peer{DUPLEX_PATH}"))
                    .body(())
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                match connection.open(request).await {
                    Ok(mut stream) => match stream.recv_response().await {
                        Ok(_) => {
                            stream.cancel();
                            Ok(())
                        }
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error),
                }
            }
        }
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(PeerTransportError::Timeout),
    };
    let rejected = result.is_err();
    finish_client_and_server(client, cancel, server_task, Ok::<_, HarnessError>(())).await?;
    if !rejected {
        return Err(HarnessError::Http(
            "M7 wrong peer role unexpectedly connected".to_owned(),
        ));
    }
    Ok(true)
}

async fn run_oversized_chunk_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = bounded_chunk_limits()?;
    let policy = |_identity: &TlsIdentity, _request: &Request<()>| true;
    let handler = |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| async {
        let (_send, mut recv) = stream.split();
        while recv.recv_chunk().await?.is_some() {}
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        let connection = client
            .connect(destination)
            .await
            .map_err(|error| HarnessError::Http(format!("M7 oversized connect: {error}")))?;
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://agent-tunnel.peer{OVERSIZED_PATH}"))
            .body(())
            .map_err(|error| {
                HarnessError::Http(format!("building M7 oversized request: {error}"))
            })?;
        let mut stream = connection
            .open(request)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 oversized stream: {error}")))?;
        Ok::<_, HarnessError>(stream.send_chunk(Bytes::from_static(b"12345")).await)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 oversized chunk case timed out".to_owned(),
        )),
    };
    let rejected = matches!(
        result,
        Ok(Err(PeerTransportError::ChunkTooLarge {
            observed: 5,
            maximum: 4
        }))
    );
    finish_client_and_server(client, cancel, server_task, Ok::<_, HarnessError>(())).await?;
    if !rejected {
        return Err(HarnessError::Http(
            "M7 oversized body chunk was not rejected at the configured bound".to_owned(),
        ));
    }
    Ok(true)
}

fn peer_request(path: &str) -> Result<Request<()>> {
    Request::builder()
        .method("POST")
        .uri(format!("https://agent-tunnel.peer{path}"))
        .body(())
        .map_err(|error| HarnessError::Http(format!("building M7 fault request: {error}")))
}

async fn run_response_truncation_cases(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
    limits: PeerTransportLimits,
) -> Result<(bool, bool)> {
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer()
            && matches!(
                request.uri().path(),
                RESPONSE_HEAD_TRUNCATION_PATH | RESPONSE_BODY_TRUNCATION_PATH
            )
    };
    let handler = |_identity: TlsIdentity, request: Request<()>, stream: PeerServerStream| async move {
        let path = request.uri().path().to_owned();
        let (mut send, mut recv) = stream.split();
        if path == RESPONSE_HEAD_TRUNCATION_PATH {
            // A response stream that is reset before HEADERS is a truncated
            // response head.  The client must not turn the request into a
            // successful empty response.
            send.cancel();
            return Ok::<_, PeerTransportError>(());
        }

        let response = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|error| PeerTransportError::H3(error.to_string()))?;
        send.send_response(response).await?;
        send.send_chunk(Bytes::from_static(TRUNCATED_RESPONSE_BODY))
            .await?;
        // Wait until the client has received the response head and prefix.
        // This request-direction barrier makes the truncation assertion
        // deterministic: the reset below cannot race the response head.
        let barrier = timeout(Duration::from_millis(500), recv.recv_chunk())
            .await
            .map_err(|_| PeerTransportError::Timeout)??;
        if !matches!(barrier, Some(chunk) if chunk.as_bytes() == TRUNCATION_BARRIER) {
            return Err(PeerTransportError::H3(
                "M7 truncation barrier was not received".to_owned(),
            ));
        }
        // Deliberately reset the response direction without FIN.  The client
        // must retain only the received prefix and report a transport error.
        send.cancel();
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        let connection = client
            .connect(destination)
            .await
            .map_err(|error| HarnessError::Http(format!("M7 truncation connect: {error}")))?;

        let head_stream = connection
            .open(peer_request(RESPONSE_HEAD_TRUNCATION_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 head truncation: {error}")))?;
        let (mut head_send, mut head_recv) = head_stream.split();
        let head_result = head_recv.recv_response().await;
        head_send.cancel();
        let head_rejected = head_result.is_err();

        let body_stream = connection
            .open(peer_request(RESPONSE_BODY_TRUNCATION_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 body truncation: {error}")))?;
        let (mut body_send, mut body_recv) = body_stream.split();
        let response = body_recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 truncated response head: {error}"))
        })?;
        let mut body = Vec::new();
        let prefix = body_recv.recv_chunk().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 truncated response prefix: {error}"))
        })?;
        if let Some(prefix) = prefix {
            body.extend_from_slice(prefix.as_bytes());
        }
        body_send
            .send_chunk(Bytes::from_static(TRUNCATION_BARRIER))
            .await
            .map_err(|error| {
                HarnessError::Http(format!("sending M7 truncation barrier: {error}"))
            })?;
        let terminal_error = body_recv.recv_chunk().await.is_err();
        body_send.cancel();
        let body_rejected = response.status() == StatusCode::OK
            && body.as_slice() == TRUNCATED_RESPONSE_BODY
            && terminal_error;

        Ok::<_, HarnessError>((head_rejected, body_rejected))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 response truncation cases timed out".to_owned(),
        )),
    };

    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result.0 {
        return Err(HarnessError::Http(
            "M7 truncated response head was accepted".to_owned(),
        ));
    }
    if !result.1 {
        return Err(HarnessError::Http(
            "M7 truncated response body was accepted".to_owned(),
        ));
    }
    Ok(result)
}

async fn run_idle_blackhole_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = fault_limits(2)?;
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == IDLE_BLACKHOLE_PATH
    };
    let handler = |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| async move {
        // Leave the response head absent indefinitely.  The transport's
        // per-operation idle deadline, rather than a task sleep, bounds the
        // client's wait and server shutdown remains cancellation-driven.
        pending::<()>().await;
        drop(stream);
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let connection = client
            .connect(PeerDestination::new(address, SERVER_NAME))
            .await
            .map_err(|error| HarnessError::Http(format!("M7 blackhole connect: {error}")))?;
        let stream = connection
            .open(peer_request(IDLE_BLACKHOLE_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 idle blackhole: {error}")))?;
        let (mut send, mut recv) = stream.split();
        let response = recv.recv_response().await;
        send.cancel();
        recv.cancel();
        Ok::<_, HarnessError>(matches!(response, Err(PeerTransportError::Timeout)))
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 idle blackhole case timed out".to_owned(),
        )),
    };
    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result {
        return Err(HarnessError::Http(
            "M7 idle blackhole did not close at its bounded deadline".to_owned(),
        ));
    }
    Ok(result)
}

async fn run_saturated_lane_cancellation_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = fault_limits(1)?;
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == SATURATED_LANE_PATH
    };
    let handler = |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| async move {
        pending::<()>().await;
        drop(stream);
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits,
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(
        client_material,
        peer_ca_pem,
        server_material.pin,
        fault_limits(1)?,
    )?;

    let result = match timeout(CASE_TIMEOUT, async {
        let connection = client
            .connect(PeerDestination::new(address, SERVER_NAME))
            .await
            .map_err(|error| HarnessError::Http(format!("M7 saturated-lane connect: {error}")))?;
        let first = connection
            .open(peer_request(SATURATED_LANE_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 saturated lane: {error}")))?;
        let second_connection = connection.clone();
        let second_request = peer_request(SATURATED_LANE_PATH)?;
        let second = tokio::spawn(async move { second_connection.open(second_request).await });
        // Give the second open a scheduling turn so it is waiting on the one
        // stream permit before cancellation is requested.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let shutdown_client = client.clone();
        let shutdown = tokio::spawn(async move { shutdown_client.shutdown().await });
        let second_result = timeout(CASE_TIMEOUT, second)
            .await
            .map_err(|_| HarnessError::Timeout("M7 saturated-lane waiter timed out".to_owned()))?
            .map_err(|error| {
                HarnessError::Http(format!("M7 saturated-lane waiter task: {error}"))
            })?;
        let shutdown_result = timeout(CASE_TIMEOUT, shutdown)
            .await
            .map_err(|_| HarnessError::Timeout("M7 saturated-lane shutdown timed out".to_owned()))?
            .map_err(|error| {
                HarnessError::Http(format!("M7 saturated-lane shutdown task: {error}"))
            })?;
        drop(first);
        Ok::<_, HarnessError>(
            matches!(second_result, Err(PeerTransportError::Cancelled)) && shutdown_result.is_ok(),
        )
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 saturated-lane cancellation case timed out".to_owned(),
        )),
    };
    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result {
        return Err(HarnessError::Http(
            "M7 saturated-lane cancellation did not wake the waiter".to_owned(),
        ));
    }
    Ok(result)
}

async fn run_active_stream_pin_revocation_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = fault_limits(2)?;
    let server_pins = SharedPeerPins::new(pins(client_material.pin)?).map_err(|error| {
        HarnessError::Http(format!("building M7 revocation pin provider: {error}"))
    })?;
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == PIN_REVOCATION_PATH
    };
    let handler = |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| async {
        let (mut send, _recv) = stream.split();
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|error| PeerTransportError::H3(error.to_string()))?;
        send.send_response(response).await?;
        send.send_chunk(Bytes::from_static(PIN_REVOCATION_BODY))
            .await?;
        // Keep the response direction active so pin revocation is observed on
        // a real stream rather than only during a future connection attempt.
        pending::<()>().await;
        drop(send);
        drop(_recv);
        Ok::<_, PeerTransportError>(())
    };
    let (server, address) = make_server_with_pin_provider(
        server_material,
        peer_ca_pem,
        server_pins.clone(),
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let connection = client
            .connect(PeerDestination::new(address, SERVER_NAME))
            .await
            .map_err(|error| HarnessError::Http(format!("M7 pin-revocation connect: {error}")))?;
        let stream = connection
            .open(peer_request(PIN_REVOCATION_PATH)?)
            .await
            .map_err(|error| {
                HarnessError::Http(format!("opening M7 pin-revocation stream: {error}"))
            })?;
        let (mut send, mut recv) = stream.split();
        send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 pin-revocation request: {error}"))
        })?;
        recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 pin-revocation head: {error}"))
        })?;
        let first = recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 pin-revocation body: {error}"))
            })?
            .map(|chunk| chunk.as_bytes().to_vec());
        let revoked =
            server_pins.replace(std::iter::empty()).is_ok() && server_pins.snapshot().is_empty();
        let closed = match timeout(CASE_TIMEOUT, recv.recv_chunk()).await {
            Ok(Err(_)) | Ok(Ok(None)) => true,
            Ok(Ok(Some(_))) | Err(_) => false,
        };
        send.cancel();
        recv.cancel();
        Ok::<_, HarnessError>(revoked && first.as_deref() == Some(PIN_REVOCATION_BODY) && closed)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 active pin-revocation case timed out".to_owned(),
        )),
    };
    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result {
        return Err(HarnessError::Http(
            "M7 active stream remained usable after peer pin revocation".to_owned(),
        ));
    }
    Ok(result)
}

async fn run_shared_stream_isolation_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = fault_limits(2)?;
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer()
            && matches!(
                request.uri().path(),
                ISOLATED_STREAM_PATH | SURVIVING_STREAM_PATH
            )
    };
    let handler = |_identity: TlsIdentity, request: Request<()>, stream: PeerServerStream| async move {
        let path = request.uri().path().to_owned();
        if path == ISOLATED_STREAM_PATH {
            let (mut send, recv) = stream.split();
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .map_err(|error| PeerTransportError::H3(error.to_string()))?;
            send.send_response(response).await?;
            // Keep the response body absent so the client-side recv remains
            // pending until the transport idle timeout.  Both directions are
            // captured to keep this request stream alive while its sibling
            // stream proves same-connection isolation.
            pending::<()>().await;
            drop(send);
            drop(recv);
            return Ok::<_, PeerTransportError>(());
        }

        let mut send = stream;
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|error| PeerTransportError::H3(error.to_string()))?;
        send.send_response(response).await?;
        send.send_chunk(Bytes::from_static(SURVIVING_STREAM_BODY))
            .await?;
        send.finish().await
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        let connection = client
            .connect(PeerDestination::new(address, SERVER_NAME))
            .await
            .map_err(|error| HarnessError::Http(format!("M7 stream-isolation connect: {error}")))?;
        let isolated = connection
            .open(peer_request(ISOLATED_STREAM_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 isolated stream: {error}")))?;
        let surviving = connection
            .open(peer_request(SURVIVING_STREAM_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 surviving stream: {error}")))?;
        let (mut isolated_send, mut isolated_recv) = isolated.split();
        let (mut surviving_send, mut surviving_recv) = surviving.split();

        isolated_send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 isolated request: {error}"))
        })?;
        isolated_recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 isolated response head: {error}"))
        })?;
        // `recv_chunk` owns the bounded idle timeout.  The operation is
        // intentionally pending here so the vendored h3-quinn receive-stream
        // fix is exercised when timeout calls stop_sending with its read
        // future in flight.  Repeating cancel must remain stream-local and
        // panic-free after that timeout.
        let isolated_timed_out = matches!(
            isolated_recv.recv_chunk().await,
            Err(PeerTransportError::Timeout)
        );
        for _ in 0..3 {
            isolated_recv.cancel();
        }
        isolated_send.cancel();

        surviving_send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 surviving request: {error}"))
        })?;
        let surviving_response = surviving_recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 surviving response head: {error}"))
        })?;
        let surviving_body = surviving_recv
            .recv_chunk()
            .await
            .map_err(|error| HarnessError::Http(format!("receiving M7 surviving body: {error}")))?
            .map(|chunk| chunk.as_bytes().to_vec());
        let surviving_end = surviving_recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 surviving terminal: {error}"))
            })?
            .is_none();
        Ok::<_, HarnessError>(
            isolated_timed_out
                && surviving_response.status() == StatusCode::OK
                && surviving_body.as_deref() == Some(SURVIVING_STREAM_BODY)
                && surviving_end,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 shared stream isolation case timed out".to_owned(),
        )),
    };
    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result {
        return Err(HarnessError::Http(
            "M7 cancellation of one shared stream affected its peer".to_owned(),
        ));
    }
    Ok(result)
}

fn body_budget_limits() -> Result<PeerTransportLimits> {
    // A two-byte chunk keeps the encoded body well below the per-call bound,
    // while the stream and connection totals are deliberately crossed by the
    // sequential cases below.  The QUIC windows remain bounded at the same
    // small connection budget.
    PeerTransportLimits::new_with_timeouts(
        2,
        8,
        16,
        1,
        4,
        1,
        1024,
        Duration::from_millis(500),
        Duration::from_secs(2),
        Duration::from_millis(500),
        Duration::from_millis(750),
    )
    .map_err(|error| HarnessError::Http(format!("building M7 body-budget limits: {error}")))
}

/// One source of received body chunks (task row M7-C120).
trait EchoSource {
    async fn next_echo_chunk(&mut self) -> std::result::Result<Option<Bytes>, PeerTransportError>;
}

impl EchoSource for tunnel_transport::PeerClientRecv {
    async fn next_echo_chunk(&mut self) -> std::result::Result<Option<Bytes>, PeerTransportError> {
        Ok(self
            .recv_chunk()
            .await?
            .map(|chunk| Bytes::copy_from_slice(chunk.as_bytes())))
    }
}

/// Read one echoed message of `expected` bytes, however the transport split
/// it (task row M7-C120).  `recv_chunk` returns whatever HTTP/3 has received
/// of the current DATA frame: the vendored h3 `FrameStream::poll_data`
/// returns a partial frame payload when only part of it has arrived (its own
/// `poll_data_split` test), and these cases run with a 16-byte QUIC
/// connection window, so a 2-byte echo can arrive as two 1-byte chunks.  The
/// case compared the first chunk with the whole payload and reported a split
/// as unreclaimed budget.  Every chunk read here still takes and releases its
/// own budget charge, so reclamation is exercised exactly as before.  Stops
/// early only at the end of the stream, leaving the shortfall to the caller.
/// Also returns how many chunks carried the echo, so a passing run can report
/// whether the split this row describes actually occurred.
async fn recv_echo<S: EchoSource>(
    source: &mut S,
    expected: usize,
) -> std::result::Result<(Vec<u8>, usize), PeerTransportError> {
    let mut received = Vec::with_capacity(expected);
    let mut chunks = 0;
    while received.len() < expected {
        match source.next_echo_chunk().await? {
            Some(chunk) => {
                chunks += 1;
                received.extend_from_slice(&chunk);
            }
            None => break,
        }
    }
    Ok((received, chunks))
}

fn budget_payload(index: usize) -> Bytes {
    Bytes::from(vec![index as u8, 0xa5 ^ (index as u8)])
}

async fn run_body_budget_reclamation_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = body_budget_limits()?;
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer()
            && matches!(
                request.uri().path(),
                STREAM_BUDGET_PATH | CONNECTION_BUDGET_PATH
            )
    };
    let handler = |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| async move {
        let (mut send, mut recv) = stream.split();
        let response = Response::builder()
            .status(StatusCode::OK)
            .body(())
            .map_err(|error| PeerTransportError::H3(error.to_string()))?;
        send.send_response(response).await?;
        while let Some(chunk) = recv.recv_chunk().await? {
            // Keep the received charge live while the response charge is
            // acquired.  The configured stream budget permits this one
            // request/response pair, but not cumulative chunks.
            send.send_chunk(Bytes::copy_from_slice(chunk.as_bytes()))
                .await?;
        }
        send.finish().await
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;

    let result = match timeout(CASE_TIMEOUT, async {
        // Echoes that arrived in more than one chunk (task row M7-C120): the
        // split the old first-chunk comparison misreported.  Printed on a
        // pass so a loaded-host loop shows whether the mechanism occurs.
        let mut split_echoes = 0usize;
        let connection = client
            .connect(PeerDestination::new(address, SERVER_NAME))
            .await
            .map_err(|error| HarnessError::Http(format!("M7 body-budget connect: {error}")))?;

        // One logical stream crosses its eight-byte body budget by sending
        // six two-byte messages.  Each message is consumed and echoed before
        // the next one is admitted, so this succeeds only when the transport
        // releases completed in-flight charges.
        let stream = connection
            .open(peer_request(STREAM_BUDGET_PATH)?)
            .await
            .map_err(|error| {
                HarnessError::Http(format!("opening M7 stream-budget stream: {error}"))
            })?;
        let (mut stream_send, mut stream_recv) = stream.split();
        for index in 0..6 {
            let payload = budget_payload(index);
            stream_send
                .send_chunk(payload.clone())
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("sending M7 stream-budget chunk: {error}"))
                })?;
            if index == 0 {
                stream_recv.recv_response().await.map_err(|error| {
                    HarnessError::Http(format!("receiving M7 stream-budget response head: {error}"))
                })?;
            }
            let (echoed, chunks) =
                recv_echo(&mut stream_recv, payload.len())
                    .await
                    .map_err(|error| {
                        HarnessError::Http(format!("receiving M7 stream-budget chunk: {error}"))
                    })?;
            if chunks > 1 {
                split_echoes += 1;
            }
            if echoed != payload.as_ref() {
                eprintln!(
                    "M7 body-budget: stream-budget echo {index} of 6 differed: sent {} bytes, \
                     received {} bytes, connection charge {} of 16 bytes",
                    payload.len(),
                    echoed.len(),
                    connection.body_bytes_charged()
                );
                return Ok::<_, HarnessError>(false);
            }
        }
        stream_send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 stream-budget request: {error}"))
        })?;
        if stream_recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 stream-budget terminal: {error}"))
            })?
            .is_some()
        {
            return Ok(false);
        }

        // Five independent streams on this one pooled connection cross the
        // sixteen-byte connection budget in aggregate.  They are sequential,
        // so no more than one request/response pair is live at a time.
        for index in 0..5 {
            let stream = connection
                .open(peer_request(CONNECTION_BUDGET_PATH)?)
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("opening M7 connection-budget stream: {error}"))
                })?;
            let (mut send, mut recv) = stream.split();
            let payload = budget_payload(32 + index);
            send.send_chunk(payload.clone()).await.map_err(|error| {
                HarnessError::Http(format!("sending M7 connection-budget chunk: {error}"))
            })?;
            recv.recv_response().await.map_err(|error| {
                HarnessError::Http(format!(
                    "receiving M7 connection-budget response head: {error}"
                ))
            })?;
            let (echoed, chunks) = recv_echo(&mut recv, payload.len()).await.map_err(|error| {
                HarnessError::Http(format!("receiving M7 connection-budget chunk: {error}"))
            })?;
            if chunks > 1 {
                split_echoes += 1;
            }
            if echoed != payload.as_ref() {
                eprintln!(
                    "M7 body-budget: connection-budget echo on stream {index} of 5 differed: \
                     sent {} bytes, received {} bytes, connection charge {} of 16 bytes",
                    payload.len(),
                    echoed.len(),
                    connection.body_bytes_charged()
                );
                return Ok(false);
            }
            send.finish().await.map_err(|error| {
                HarnessError::Http(format!("finishing M7 connection-budget request: {error}"))
            })?;
            if recv
                .recv_chunk()
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("receiving M7 connection-budget terminal: {error}"))
                })?
                .is_some()
            {
                return Ok(false);
            }
        }

        eprintln!("M7 body-budget: 11 echoes read whole, split_echoes={split_echoes}");
        Ok::<_, HarnessError>(true)
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 body-budget reclamation case timed out".to_owned(),
        )),
    };
    let result = finish_client_and_server(client, cancel, server_task, result).await?;
    if !result {
        return Err(HarnessError::Http(
            "M7 body-budget charges were not reclaimed between sequential transfers".to_owned(),
        ));
    }
    Ok(result)
}

fn udp_fault_limits() -> Result<PeerTransportLimits> {
    PeerTransportLimits::new_with_timeouts(
        1024,
        4096,
        16 * 1024,
        1,
        4,
        1,
        4096,
        Duration::from_millis(750),
        Duration::from_secs(2),
        Duration::from_millis(500),
        Duration::from_millis(750),
    )
    .map_err(|error| HarnessError::Http(format!("building M7 UDP fault limits: {error}")))
}

async fn run_udp_blackhole_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let limits = udp_fault_limits()?;
    let invocations = Arc::new(AtomicUsize::new(0));
    let first_body_gate = Arc::new(Notify::new());
    let first_handler_done = Arc::new(Notify::new());
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == UDP_BLACKHOLE_PATH
    };
    let handler_invocations = invocations.clone();
    let handler_gate = first_body_gate.clone();
    let handler_done = first_handler_done.clone();
    let handler = move |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| {
        let invocation = handler_invocations.fetch_add(1, Ordering::SeqCst);
        let gate = handler_gate.clone();
        let done = handler_done.clone();
        async move {
            let result = async {
                let (mut send, _recv) = stream.split();
                let response = Response::builder()
                    .status(StatusCode::OK)
                    .body(())
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                send.send_response(response).await?;
                if invocation == 0 {
                    // The client signals only after it has received HEADERS.
                    // The proxy is switched to drop mode before this permit
                    // is used, so the response body can be admitted but
                    // cannot arrive.
                    gate.notified().await;
                }
                let body = if invocation == 0 {
                    UDP_BLACKHOLE_BODY
                } else {
                    UDP_RESTORED_BODY
                };
                send.send_chunk(Bytes::from_static(body)).await?;
                send.finish().await
            }
            .await;
            if invocation == 0 {
                // A handler completion is the server-side release signal for
                // its stream.  The connection slot may still be draining,
                // so the client below also uses a bounded reconnect window.
                done.notify_one();
            }
            result
        }
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let mut proxy = UdpFaultProxy::bind(address).await?;
    let client = make_client(client_material, peer_ca_pem, server_material.pin, limits)?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));

    let destination = PeerDestination::new(proxy.address(), SERVER_NAME);
    let exchange = match timeout(CASE_TIMEOUT, async {
        let connection = client
            .connect(destination.clone())
            .await
            .map_err(|error| HarnessError::Http(format!("M7 UDP blackhole connect: {error}")))?;
        let initial_identity_matches =
            connection.peer_identity().spki_sha256() == server_material.pin;
        let stream = connection
            .open(peer_request(UDP_BLACKHOLE_PATH)?)
            .await
            .map_err(|error| {
                HarnessError::Http(format!("opening M7 UDP blackhole stream: {error}"))
            })?;
        let (mut send, mut recv) = stream.split();
        send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 UDP blackhole request: {error}"))
        })?;
        let response = recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 UDP blackhole response head: {error}"))
        })?;
        let admitted = response.status() == StatusCode::OK
            && initial_identity_matches
            && invocations.load(Ordering::SeqCst) == 1;

        proxy.set_drop(true);
        first_body_gate.notify_one();
        let body_result = timeout(Duration::from_secs(2), recv.recv_chunk()).await;
        let stopped_without_success = matches!(body_result, Ok(Err(_)));
        let no_replay = invocations.load(Ordering::SeqCst) == 1;
        send.cancel();
        recv.cancel();
        drop(send);
        drop(recv);
        drop(connection);
        if !admitted || !stopped_without_success || !no_replay {
            return Ok::<_, HarnessError>(false);
        }

        // Restore forwarding before retiring the pooled connection.  This
        // lets CONNECTION_CLOSE reach the server and releases its configured
        // one-connection slot instead of waiting for the QUIC idle timeout.
        // The next request therefore proves a fresh QUIC/H3 path under the
        // same client identity and approved server SPKI pin, with no replay
        // of the admitted request.
        proxy.set_drop(false);
        client
            .close_peer(&destination)
            .await
            .map_err(|error| HarnessError::Http(format!("closing M7 blackholed peer: {error}")))?;
        if timeout(Duration::from_secs(2), first_handler_done.notified())
            .await
            .is_err()
        {
            return Ok(false);
        }
        let reconnect_deadline = Instant::now() + Duration::from_secs(2);
        let fresh_connection = loop {
            match client.connect(destination.clone()).await {
                Ok(connection) => break connection,
                Err(error) if Instant::now() < reconnect_deadline => {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    let _ = error;
                }
                Err(error) => {
                    return Err(HarnessError::Http(format!(
                        "reconnecting M7 restored UDP path: {error}"
                    )));
                }
            }
        };
        let fresh_identity_matches =
            fresh_connection.peer_identity().spki_sha256() == server_material.pin;
        let fresh_stream = fresh_connection
            .open(peer_request(UDP_BLACKHOLE_PATH)?)
            .await
            .map_err(|error| HarnessError::Http(format!("opening M7 restored stream: {error}")))?;
        let (mut fresh_send, mut fresh_recv) = fresh_stream.split();
        fresh_send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 restored request: {error}"))
        })?;
        let fresh_response = fresh_recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 restored response head: {error}"))
        })?;
        let fresh_body = fresh_recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 restored response body: {error}"))
            })?
            .map(|chunk| chunk.as_bytes().to_vec());
        let fresh_end = fresh_recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 restored response terminal: {error}"))
            })?
            .is_none();
        fresh_send.cancel();
        fresh_recv.cancel();
        Ok::<_, HarnessError>(
            fresh_identity_matches
                && fresh_response.status() == StatusCode::OK
                && fresh_body.as_deref() == Some(UDP_RESTORED_BODY)
                && fresh_end
                && invocations.load(Ordering::SeqCst) == 2,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 UDP blackhole/restoration case timed out".to_owned(),
        )),
    };
    proxy.set_drop(false);
    let transport_result = finish_client_and_server(client, cancel, server_task, exchange).await;
    let proxy_result = proxy.shutdown().await;
    let result = transport_result?;
    proxy_result?;
    if !result {
        return Err(HarnessError::Http(
            "M7 UDP blackhole did not stop the admitted stream and restore a fresh trusted path"
                .to_owned(),
        ));
    }
    Ok(result)
}

async fn run_no_fallback_and_zero_rtt_case(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<(bool, bool)> {
    let limits = test_limits()?;
    let client = make_client(
        client_material,
        peer_ca_pem,
        server_material.pin,
        limits.clone(),
    )?;

    // Bind only TCP at this address.  The peer client is still given the
    // address as a QUIC destination, so a successful TCP accept would be
    // direct evidence of an unapproved fallback path.
    let tcp_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .map_err(|error| HarnessError::Http(format!("binding M7 fallback probe: {error}")))?;
    let tcp_address = tcp_listener.local_addr().map_err(|error| {
        HarnessError::Http(format!("reading M7 fallback probe address: {error}"))
    })?;
    let tcp_probe_cancel = CancellationToken::new();
    let tcp_probe_accepts = Arc::new(AtomicBool::new(false));
    let tcp_probe_cancel_task = tcp_probe_cancel.clone();
    let tcp_probe_accepts_task = tcp_probe_accepts.clone();
    let tcp_probe = tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = tcp_probe_cancel_task.cancelled() => break,
                accepted = tcp_listener.accept() => match accepted {
                    Ok((_stream, _peer)) => {
                        tcp_probe_accepts_task.store(true, Ordering::Release);
                    }
                    Err(error) => {
                        return Err(HarnessError::Http(format!(
                            "accepting M7 fallback probe connection: {error}"
                        )));
                    }
                },
            }
        }
        Ok::<_, HarnessError>(())
    });
    let blocked_result = client
        .connect(PeerDestination::new(tcp_address, SERVER_NAME))
        .await;
    // Keep observing after connect returns: a fallback implementation may
    // start its TCP attempt only after the UDP/QUIC deadline has elapsed.
    tokio::time::sleep(FALLBACK_PROBE_SETTLE).await;
    tcp_probe_cancel.cancel();
    let mut tcp_probe = tcp_probe;
    match timeout(CLEANUP_TIMEOUT, &mut tcp_probe).await {
        Ok(result) => {
            result
                .map_err(|error| HarnessError::Http(format!("joining M7 fallback probe: {error}")))?
                .map_err(|error| {
                    HarnessError::Http(format!("M7 fallback probe failed: {error}"))
                })?;
        }
        Err(_) => {
            tcp_probe.abort();
            let _ = tcp_probe.await;
            return Err(HarnessError::Timeout(
                "M7 fallback probe shutdown timed out".to_owned(),
            ));
        }
    }
    let no_tcp_fallback = matches!(
        blocked_result,
        Err(PeerTransportError::Timeout | PeerTransportError::Quic(_))
    ) && !tcp_probe_accepts.load(Ordering::Acquire);

    // Positive control: the same mTLS client still reaches an actual H3
    // server and receives a complete response on a real QUIC endpoint.
    let admissions = Arc::new(AtomicUsize::new(0));
    let policy = |identity: &TlsIdentity, request: &Request<()>| {
        identity.role().is_peer() && request.uri().path() == NO_FALLBACK_PATH
    };
    let handler_admissions = admissions.clone();
    let handler = move |_identity: TlsIdentity, _request: Request<()>, stream: PeerServerStream| {
        handler_admissions.fetch_add(1, Ordering::SeqCst);
        async move {
            let (mut send, mut recv) = stream.split();
            // Read the request to its end before answering.  A handler that
            // answered and returned first dropped its receive half, whose
            // STOP_SENDING could reach the client before the client had
            // finished its request, failing the positive control's own
            // `finish` with "Remote reset: 0x0" (M7-C117).
            while recv.recv_chunk().await?.is_some() {}
            let response = Response::builder()
                .status(StatusCode::OK)
                .body(())
                .map_err(|error| PeerTransportError::H3(error.to_string()))?;
            send.send_response(response).await?;
            send.send_chunk(Bytes::from_static(NO_FALLBACK_BODY))
                .await?;
            send.finish().await
        }
    };
    let (server, address) = make_server(
        server_material,
        peer_ca_pem,
        client_material.pin,
        limits.clone(),
        policy,
        handler,
    )?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));

    let exchange = match timeout(CASE_TIMEOUT, async {
        let destination = PeerDestination::new(address, SERVER_NAME);
        let connection = client.connect(destination).await.map_err(|error| {
            HarnessError::Http(format!("M7 fallback positive connect: {error}"))
        })?;
        let stream = connection
            .open(peer_request(NO_FALLBACK_PATH)?)
            .await
            .map_err(|error| {
                HarnessError::Http(format!("opening M7 fallback positive stream: {error}"))
            })?;
        let (mut send, mut recv) = stream.split();
        send.finish().await.map_err(|error| {
            HarnessError::Http(format!("finishing M7 fallback positive request: {error}"))
        })?;
        let response = recv.recv_response().await.map_err(|error| {
            HarnessError::Http(format!("receiving M7 fallback positive head: {error}"))
        })?;
        let body = recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 fallback positive body: {error}"))
            })?
            .map(|chunk| chunk.as_bytes().to_vec());
        let end = recv
            .recv_chunk()
            .await
            .map_err(|error| {
                HarnessError::Http(format!("receiving M7 fallback positive terminal: {error}"))
            })?
            .is_none();
        send.cancel();
        recv.cancel();
        Ok::<_, HarnessError>(
            response.status() == StatusCode::OK
                && body.as_deref() == Some(NO_FALLBACK_BODY)
                && end
                && admissions.load(Ordering::SeqCst) == 1,
        )
    })
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M7 fallback positive control timed out".to_owned(),
        )),
    };
    let probe_result = async {
        let positive_control = exchange?;
        if !positive_control {
            return Err(HarnessError::Http(
                "M7 H3 positive control did not complete without fallback".to_owned(),
            ));
        }

        // The production TLS helpers disable client resumption/early data and
        // server tickets.  A second-handshake attempt therefore cannot obtain
        // Quinn's 0-RTT connection form; the failed conversion is the runtime
        // negative proof, while the completed positive control above proves
        // that ordinary post-handshake H3 admission still works.
        let admissions_before_zero_rtt = admissions.load(Ordering::SeqCst);
        let mut raw_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| HarnessError::Http(format!("binding M7 0-RTT probe: {error}")))?;
        raw_endpoint.set_default_client_config(peer_client_config(client_material, peer_ca_pem)?);
        let warm_connecting = raw_endpoint
            .connect(address, SERVER_NAME)
            .map_err(|error| HarnessError::Http(format!("starting M7 0-RTT probe: {error}")))?;
        let warm_connection = timeout(limits.handshake_timeout, warm_connecting)
            .await
            .map_err(|_| HarnessError::Timeout("M7 0-RTT warm handshake timed out".to_owned()))?
            .map_err(|error| HarnessError::Http(format!("M7 0-RTT warm handshake: {error}")))?;
        // Give a completed authenticated handshake a bounded opportunity to
        // deliver any session ticket.  Production helpers intentionally send
        // none, but this makes the following conversion test the same endpoint
        // and config after a real warm-up rather than an uninitialized client.
        tokio::time::sleep(ZERO_RTT_TICKET_WAIT).await;
        warm_connection.close(quinn::VarInt::from_u32(0), b"0-rtt-warm-close");
        if timeout(CASE_TIMEOUT, raw_endpoint.wait_idle())
            .await
            .is_err()
        {
            return Err(HarnessError::Timeout(
                "M7 0-RTT warm connection did not close".to_owned(),
            ));
        }

        let connecting = raw_endpoint
            .connect(address, SERVER_NAME)
            .map_err(|error| HarnessError::Http(format!("starting M7 0-RTT probe: {error}")))?;
        let zero_rtt_disabled = match connecting.into_0rtt() {
            Ok((connection, _accepted)) => {
                connection.close(quinn::VarInt::from_u32(0), b"0-rtt-disabled-check");
                false
            }
            Err(connecting) => {
                let connection = timeout(limits.handshake_timeout, connecting)
                    .await
                    .map_err(|_| {
                        HarnessError::Timeout("M7 0-RTT probe handshake timed out".to_owned())
                    })?
                    .map_err(|error| {
                        HarnessError::Http(format!("M7 0-RTT probe handshake: {error}"))
                    })?;
                connection.close(quinn::VarInt::from_u32(0), b"0-rtt-disabled-check");
                true
            }
        };
        let raw_idle = timeout(CASE_TIMEOUT, raw_endpoint.wait_idle())
            .await
            .is_ok();
        let mutation_positive =
            run_enabled_zero_rtt_control(server_material, client_material, peer_ca_pem).await?;
        let admissions_after_zero_rtt = admissions.load(Ordering::SeqCst);
        let zero_rtt_not_admitted = zero_rtt_disabled
            && raw_idle
            && mutation_positive
            && admissions_after_zero_rtt == admissions_before_zero_rtt;
        if !no_tcp_fallback {
            return Err(HarnessError::Http(
                format!(
                    "M7 blocked QUIC endpoint unexpectedly accepted a TCP fallback (no_tcp_fallback={no_tcp_fallback}, zero_rtt_disabled={zero_rtt_disabled}, raw_idle={raw_idle}, mutation_positive={mutation_positive}, admissions_before={admissions_before_zero_rtt}, admissions_after={admissions_after_zero_rtt})"
                ),
            ));
        }
        if !zero_rtt_not_admitted {
            return Err(HarnessError::Http(
                format!(
                    "M7 peer 0-RTT was available or admitted a request (no_tcp_fallback={no_tcp_fallback}, zero_rtt_disabled={zero_rtt_disabled}, raw_idle={raw_idle}, mutation_positive={mutation_positive}, admissions_before={admissions_before_zero_rtt}, admissions_after={admissions_after_zero_rtt})"
                ),
            ));
        }
        Ok((no_tcp_fallback, zero_rtt_not_admitted))
    }
    .await;
    finish_client_and_server(client, cancel, server_task, probe_result).await
}

fn test_only_early_data_server_config(
    server_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<quinn::ServerConfig> {
    let tls = load_server_config_from_pem_with_alpn(
        server_material.chain_pem.as_bytes(),
        server_material.private_key_pem.as_bytes(),
        Some(peer_ca_pem.as_bytes()),
        &[b"h3"],
    )
    .map_err(|error| HarnessError::Pki(format!("building M7 test 0-RTT server TLS: {error}")))?;
    let mut tls = Arc::try_unwrap(tls).map_err(|_| {
        HarnessError::Pki("test 0-RTT server TLS config was unexpectedly shared".to_owned())
    })?;
    tls.session_storage = rustls::server::ServerSessionMemoryCache::new(4);
    // quinn-proto's rustls adapter requires QUIC's sentinel value for
    // enabled early data; ordinary application/body limits remain explicit in
    // the production transport fixture.
    tls.max_early_data_size = u32::MAX;
    tls.send_tls13_tickets = 2;
    load_quinn_server_config(Arc::new(tls))
        .map_err(|error| HarnessError::Pki(format!("building M7 test 0-RTT QUIC server: {error}")))
}

fn test_only_early_data_client_config(
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
    ticket_count: Arc<AtomicUsize>,
    ticket_received: Arc<Notify>,
    ticket_max_early_data: Arc<AtomicUsize>,
    ticket_take_count: Arc<AtomicUsize>,
    ticket_take_hits: Arc<AtomicUsize>,
) -> Result<quinn::ClientConfig> {
    let tls = load_client_config_from_pem_with_alpn(
        client_material.chain_pem.as_bytes(),
        client_material.private_key_pem.as_bytes(),
        peer_ca_pem.as_bytes(),
        &[b"h3"],
    )
    .map_err(|error| HarnessError::Pki(format!("building M7 test 0-RTT client TLS: {error}")))?;
    let mut tls = Arc::try_unwrap(tls).map_err(|_| {
        HarnessError::Pki("test 0-RTT client TLS config was unexpectedly shared".to_owned())
    })?;
    tls.resumption = rustls::client::Resumption::store(Arc::new(TestClientSessionStore {
        // rustls 0.23.44 rounds this requested ticket bound into per-server
        // slots; four tickets yields one slot, whose bounded cache evicts the
        // just-inserted key at capacity. Sixteen keeps two server slots while
        // remaining a small, explicit test-only bound.
        inner: rustls::client::ClientSessionMemoryCache::new(16),
        ticket_count,
        ticket_received,
        ticket_max_early_data,
        ticket_take_count,
        ticket_take_hits,
    }));
    tls.enable_early_data = true;
    load_quinn_client_config(Arc::new(tls))
        .map_err(|error| HarnessError::Pki(format!("building M7 test 0-RTT QUIC client: {error}")))
}

#[derive(Debug)]
struct TestClientSessionStore {
    inner: rustls::client::ClientSessionMemoryCache,
    ticket_count: Arc<AtomicUsize>,
    ticket_received: Arc<Notify>,
    ticket_max_early_data: Arc<AtomicUsize>,
    ticket_take_count: Arc<AtomicUsize>,
    ticket_take_hits: Arc<AtomicUsize>,
}

impl rustls::client::ClientSessionStore for TestClientSessionStore {
    fn set_kx_hint(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        group: rustls::NamedGroup,
    ) {
        rustls::client::ClientSessionStore::set_kx_hint(&self.inner, server_name, group);
    }

    fn kx_hint(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::NamedGroup> {
        rustls::client::ClientSessionStore::kx_hint(&self.inner, server_name)
    }

    fn set_tls12_session(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls12ClientSessionValue,
    ) {
        rustls::client::ClientSessionStore::set_tls12_session(&self.inner, server_name, value);
    }

    fn tls12_session(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls12ClientSessionValue> {
        rustls::client::ClientSessionStore::tls12_session(&self.inner, server_name)
    }

    fn remove_tls12_session(&self, server_name: &rustls::pki_types::ServerName<'static>) {
        rustls::client::ClientSessionStore::remove_tls12_session(&self.inner, server_name);
    }

    fn insert_tls13_ticket(
        &self,
        server_name: rustls::pki_types::ServerName<'static>,
        value: rustls::client::Tls13ClientSessionValue,
    ) {
        self.ticket_max_early_data
            .store(value.max_early_data_size() as usize, Ordering::SeqCst);
        rustls::client::ClientSessionStore::insert_tls13_ticket(&self.inner, server_name, value);
        self.ticket_count.fetch_add(1, Ordering::SeqCst);
        self.ticket_received.notify_waiters();
    }

    fn take_tls13_ticket(
        &self,
        server_name: &rustls::pki_types::ServerName<'_>,
    ) -> Option<rustls::client::Tls13ClientSessionValue> {
        self.ticket_take_count.fetch_add(1, Ordering::SeqCst);
        let server_name = server_name.to_owned();
        let value =
            rustls::client::ClientSessionStore::take_tls13_ticket(&self.inner, &server_name);
        if value.is_some() {
            self.ticket_take_hits.fetch_add(1, Ordering::SeqCst);
        }
        value
    }
}

async fn serve_test_only_early_data(
    endpoint: quinn::Endpoint,
    cancel: CancellationToken,
    connection_closed: Arc<Notify>,
) -> Result<()> {
    loop {
        let incoming = tokio::select! {
            _ = cancel.cancelled() => break,
            incoming = endpoint.accept() => incoming,
        };
        let Some(incoming) = incoming else {
            break;
        };
        let connection = tokio::select! {
            _ = cancel.cancelled() => break,
            result = timeout(CASE_TIMEOUT, incoming) => match result {
                Ok(Ok(connection)) => connection,
                Ok(Err(_)) | Err(_) => continue,
            },
        };
        // A completed TLS handshake does not guarantee that the client has
        // consumed the post-handshake NewSessionTicket yet.  Consume one
        // bounded 1-RTT application stream before waiting for the warm
        // connection to close.  This mirrors Quinn's own 0-RTT fixture and
        // makes ticket delivery a real, exercised event in this positive
        // control rather than a timing assumption.
        tokio::select! {
            _ = cancel.cancelled() => break,
            result = timeout(CASE_TIMEOUT, async {
                if let Ok(mut stream) = connection.accept_uni().await {
                    let _ = stream.read_to_end(1024).await;
                    if let Ok(mut ack) = connection.open_uni().await
                        && ack.write_all(b"ticket-ready").await.is_ok()
                    {
                        let _ = ack.finish();
                    }
                }
            }) => {
                let _ = result;
            },
        }
        tokio::select! {
            _ = cancel.cancelled() => break,
            _ = connection.closed() => connection_closed.notify_one(),
        }
    }
    endpoint.close(quinn::VarInt::from_u32(0), b"test 0-rtt shutdown");
    Ok(())
}

async fn run_enabled_zero_rtt_control(
    server_material: &PeerMaterial,
    client_material: &PeerMaterial,
    peer_ca_pem: &str,
) -> Result<bool> {
    let server_endpoint = quinn::Endpoint::server(
        test_only_early_data_server_config(server_material, peer_ca_pem)?,
        SocketAddr::from(([127, 0, 0, 1], 0)),
    )
    .map_err(|error| HarnessError::Http(format!("binding M7 test 0-RTT server: {error}")))?;
    let server_address = server_endpoint.local_addr().map_err(|error| {
        HarnessError::Http(format!("reading M7 test 0-RTT server address: {error}"))
    })?;
    let cancel = CancellationToken::new();
    let connection_closed = Arc::new(Notify::new());
    let ticket_count = Arc::new(AtomicUsize::new(0));
    let ticket_received = Arc::new(Notify::new());
    let ticket_max_early_data = Arc::new(AtomicUsize::new(0));
    let ticket_take_count = Arc::new(AtomicUsize::new(0));
    let ticket_take_hits = Arc::new(AtomicUsize::new(0));
    let server_task = tokio::spawn(serve_test_only_early_data(
        server_endpoint,
        cancel.clone(),
        connection_closed.clone(),
    ));

    let result: Result<bool> = async {
        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| {
                HarnessError::Http(format!("binding M7 test 0-RTT client: {error}"))
            })?;
        client_endpoint.set_default_client_config(test_only_early_data_client_config(
            client_material,
            peer_ca_pem,
            ticket_count.clone(),
            ticket_received.clone(),
            ticket_max_early_data.clone(),
            ticket_take_count.clone(),
            ticket_take_hits.clone(),
        )?);

        let warm_connecting = client_endpoint
            .connect(server_address, SERVER_NAME)
            .map_err(|error| {
                HarnessError::Http(format!("starting M7 test 0-RTT warm-up: {error}"))
            })?;
        let warm_connection = timeout(Duration::from_secs(2), warm_connecting)
            .await
            .map_err(|_| HarnessError::Timeout("M7 test 0-RTT warm-up timed out".to_owned()))?
            .map_err(|error| HarnessError::Http(format!("M7 test 0-RTT warm-up: {error}")))?;
        let mut warm_stream = warm_connection.open_uni().await.map_err(|error| {
            HarnessError::Http(format!("opening M7 test 0-RTT warm-up stream: {error}"))
        })?;
        warm_stream
            .write_all(b"ticket-warm-up")
            .await
            .map_err(|error| {
                HarnessError::Http(format!("writing M7 test 0-RTT warm-up stream: {error}"))
            })?;
        warm_stream.finish().map_err(|error| {
            HarnessError::Http(format!("finishing M7 test 0-RTT warm-up stream: {error}"))
        })?;
        let mut ticket_ack = timeout(CASE_TIMEOUT, warm_connection.accept_uni())
            .await
            .map_err(|_| HarnessError::Timeout("M7 test 0-RTT ticket ack timed out".to_owned()))?
            .map_err(|error| {
                HarnessError::Http(format!("accepting M7 test 0-RTT ticket ack: {error}"))
            })?;
        let ticket_ack_body = ticket_ack.read_to_end(1024).await.map_err(|error| {
            HarnessError::Http(format!("reading M7 test 0-RTT ticket ack: {error}"))
        })?;
        if ticket_ack_body.as_slice() != b"ticket-ready" {
            return Err(HarnessError::Http(
                "M7 test 0-RTT ticket ack had an unexpected body".to_owned(),
            ));
        }
        if ticket_count.load(Ordering::SeqCst) == 0
            && timeout(CASE_TIMEOUT, async {
                loop {
                    if ticket_count.load(Ordering::SeqCst) > 0 {
                        break;
                    }
                    ticket_received.notified().await;
                }
            })
            .await
            .is_err()
        {
            return Err(HarnessError::Timeout(
                "M7 test 0-RTT warm-up did not receive a TLS session ticket".to_owned(),
            ));
        }
        warm_connection.close(quinn::VarInt::from_u32(0), b"test 0-rtt warm close");
        if timeout(CLEANUP_TIMEOUT, connection_closed.notified())
            .await
            .is_err()
        {
            return Err(HarnessError::Timeout(
                "M7 test 0-RTT warm connection did not close after ticket receipt".to_owned(),
            ));
        }
        if timeout(CLEANUP_TIMEOUT, client_endpoint.wait_idle())
            .await
            .is_err()
        {
            return Err(HarnessError::Timeout(
                "M7 test 0-RTT client endpoint did not become idle after warm close".to_owned(),
            ));
        }

        let connecting = client_endpoint
            .connect(server_address, SERVER_NAME)
            .map_err(|error| {
                HarnessError::Http(format!("starting M7 test 0-RTT conversion: {error}"))
            })?;
        let detected = match connecting.into_0rtt() {
            Ok((connection, _accepted)) => {
                connection.close(quinn::VarInt::from_u32(0), b"test 0-rtt detected");
                true
            }
            Err(connecting) => {
                let connection = timeout(Duration::from_secs(2), connecting)
                    .await
                    .map_err(|_| {
                        HarnessError::Timeout("M7 test 0-RTT second handshake timed out".to_owned())
                    })?
                    .map_err(|error| {
                        HarnessError::Http(format!("M7 test 0-RTT second handshake: {error}"))
                    })?;
                connection.close(quinn::VarInt::from_u32(0), b"test 0-rtt unavailable");
                false
            }
        };
        if !detected {
            return Err(HarnessError::Http(format!(
                "M7 test 0-RTT mutation control did not expose resumable early data after {} ticket(s) (max_early_data={}, take_attempts={}, take_hits={})",
                ticket_count.load(Ordering::SeqCst),
                ticket_max_early_data.load(Ordering::SeqCst),
                ticket_take_count.load(Ordering::SeqCst),
                ticket_take_hits.load(Ordering::SeqCst),
            )));
        }
        let idle = timeout(CLEANUP_TIMEOUT, client_endpoint.wait_idle())
            .await
            .is_ok();
        if !idle {
            return Err(HarnessError::Timeout(
                "M7 test 0-RTT mutation control detected early data but endpoint did not become idle"
                    .to_owned(),
            ));
        }
        Ok(true)
    }
    .await;

    cancel.cancel();
    let mut server_task = server_task;
    let server_shutdown = match timeout(CLEANUP_TIMEOUT, &mut server_task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(error),
        Ok(Err(error)) => Err(HarnessError::Http(format!(
            "M7 test 0-RTT server task: {error}"
        ))),
        Err(_) => {
            server_task.abort();
            let _ = server_task.await;
            Err(HarnessError::Timeout(
                "M7 test 0-RTT server shutdown timed out".to_owned(),
            ))
        }
    };
    server_shutdown?;
    result
}

async fn finish_client_and_server<T>(
    client: PeerClient,
    cancel: CancellationToken,
    mut server_task: tokio::task::JoinHandle<std::result::Result<(), PeerTransportError>>,
    result: std::result::Result<T, HarnessError>,
) -> Result<T> {
    let client_shutdown = match timeout(CLEANUP_TIMEOUT, client.shutdown()).await {
        Ok(result) => {
            result.map_err(|error| HarnessError::Http(format!("M7 peer client shutdown: {error}")))
        }
        Err(_) => Err(HarnessError::Timeout(
            "M7 peer client shutdown timed out".to_owned(),
        )),
    };
    drop(client);

    cancel.cancel();
    let server_shutdown = match timeout(CLEANUP_TIMEOUT, &mut server_task).await {
        Ok(Ok(Ok(()))) => Ok(()),
        Ok(Ok(Err(error))) => Err(HarnessError::Http(format!(
            "M7 peer server shutdown: {error}"
        ))),
        Ok(Err(error)) => Err(HarnessError::Http(format!("M7 peer server task: {error}"))),
        Err(_) => {
            server_task.abort();
            let _ = server_task.await;
            Err(HarnessError::Timeout(
                "M7 peer server shutdown timed out".to_owned(),
            ))
        }
    };

    let value = result?;
    client_shutdown?;
    server_shutdown?;
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A scripted chunk source: `None` is the end of the stream.
    struct Scripted(std::collections::VecDeque<Option<Bytes>>);

    impl EchoSource for Scripted {
        async fn next_echo_chunk(
            &mut self,
        ) -> std::result::Result<Option<Bytes>, PeerTransportError> {
            Ok(self.0.pop_front().flatten())
        }
    }

    /// Task row M7-C120.  The transport may deliver one 2-byte echo as two
    /// 1-byte chunks.  The body-budget case compared the first chunk with the
    /// whole payload, which reports that split as unreclaimed budget; the
    /// echo must be read whole.
    #[tokio::test]
    async fn a_split_echo_is_read_whole_and_the_old_comparison_would_have_failed() {
        let payload = budget_payload(3);
        let (first, second) = payload.split_at(1);
        let mut source = Scripted(
            [
                Some(Bytes::copy_from_slice(first)),
                Some(Bytes::copy_from_slice(second)),
                None,
            ]
            .into(),
        );
        // The comparison the case made before: the first chunk alone.
        assert_ne!(first, payload.as_ref());
        let (echoed, chunks) = recv_echo(&mut source, payload.len())
            .await
            .expect("scripted chunks");
        assert_eq!(echoed, payload.as_ref());
        // The split is counted, so a passing run can report that it occurred.
        assert_eq!(chunks, 2);
        // The terminal read after the echo still sees the end of the stream.
        assert!(source.next_echo_chunk().await.expect("end").is_none());
    }

    #[tokio::test]
    async fn a_short_echo_stops_at_the_end_of_the_stream() {
        let payload = budget_payload(4);
        let mut source = Scripted([Some(Bytes::copy_from_slice(&payload[..1])), None].into());
        let (echoed, chunks) = recv_echo(&mut source, payload.len())
            .await
            .expect("scripted chunks");
        assert_eq!(echoed.len(), 1);
        assert_eq!(chunks, 1);
        assert_ne!(echoed, payload.as_ref());
    }
}
