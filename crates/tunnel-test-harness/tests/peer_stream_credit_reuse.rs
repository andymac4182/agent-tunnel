//! Real loopback H3 stream-credit regression for the vendored quinn-proto patch.
//!
//! The transport keeps one connection at a fixed application stream limit.
//! Long-lived `/hold` requests leave only the completion budget free, each
//! completed `/short` request frees exactly one slot, and the next `/hold`
//! request must reuse that slot.  The final open proves the application ceiling
//! still rejects an over-cap request.  The 128-stream case repeats this seven
//! times, matching the production pressure shape where seven completions were
//! insufficient to pass quinn-proto's old one-eighth hysteresis threshold.

// The harness library is Unix-only (see `src/entry.rs`).
#![cfg(unix)]

use std::{net::SocketAddr, sync::Arc, time::Duration};

use bytes::Bytes;
use http::{Request, Response, StatusCode};
use tokio::{
    task::JoinHandle,
    time::{Instant as TokioInstant, timeout_at},
};
use tokio_util::sync::CancellationToken;
use tunnel_test_harness::{CertificateMaterial, FixturePki};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerClientRecv, PeerConnectionHandle, PeerDestination,
    PeerServer, PeerServerConnectionStats, PeerServerDiagnostics, PeerServerStream,
    PeerTransportError, PeerTransportLimits, SpkiSha256, TlsIdentity,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};

const SERVER_NAME: &str = "localhost";
const HOLD_PATH: &str = "/hold";
const SHORT_PATH: &str = "/short";
const RESPONSE_BYTES: &[u8] = b"ok";
const CASE_BOUND: Duration = Duration::from_secs(30);
const CLEANUP_BOUND: Duration = Duration::from_secs(5);
const REPLACEMENT_OPEN_BOUND: Duration = Duration::from_secs(1);
const OPEN_BOUND: Duration = Duration::from_millis(300);

struct ReuseFixture {
    client: PeerClient,
    connection: PeerConnectionHandle,
    diagnostics: Arc<PeerServerDiagnostics>,
    release: CancellationToken,
    server_cancel: CancellationToken,
    server_task: Option<JoinHandle<Result<(), PeerTransportError>>>,
}

impl ReuseFixture {
    async fn start(max_streams: usize) -> Result<Self, String> {
        let pki = FixturePki::new().map_err(|error| format!("fixture PKI: {error}"))?;
        let server_certificate = pki
            .issue_peer("stream-credit-server")
            .map_err(|error| format!("server certificate: {error}"))?;
        let client_certificate = pki
            .issue_peer("stream-credit-client")
            .map_err(|error| format!("client certificate: {error}"))?;
        let server_pin = spki(&server_certificate)?;
        let client_pin = spki(&client_certificate)?;
        let limits = limits(max_streams)?;

        let server_chain = certificate_chain(&server_certificate, &pki);
        let mut server_config = load_peer_server_config_from_pem(
            server_chain.as_bytes(),
            server_certificate.private_key_pem.as_bytes(),
            pki.peer_ca.certificate_pem.as_bytes(),
        )
        .map_err(|error| format!("server TLS config: {error}"))?;
        limits
            .apply_to_server_config(&mut server_config)
            .map_err(|error| format!("server QUIC limits: {error}"))?;
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .map_err(|error| format!("server endpoint: {error}"))?;
        let server_address = server_endpoint
            .local_addr()
            .map_err(|error| format!("server address: {error}"))?;

        let client_chain = certificate_chain(&client_certificate, &pki);
        let mut client_config = load_peer_client_config_from_pem(
            client_chain.as_bytes(),
            client_certificate.private_key_pem.as_bytes(),
            pki.peer_ca.certificate_pem.as_bytes(),
        )
        .map_err(|error| format!("client TLS config: {error}"))?;
        limits
            .apply_to_client_config(&mut client_config)
            .map_err(|error| format!("client QUIC limits: {error}"))?;
        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| format!("client endpoint: {error}"))?;
        client_endpoint.set_default_client_config(client_config);

        let release = CancellationToken::new();
        let handler_release = release.clone();
        let policy = |_: &TlsIdentity, request: &Request<()>| {
            let path = request.uri().path();
            path == HOLD_PATH || path == SHORT_PATH
        };
        let handler =
            move |_identity: TlsIdentity, request: Request<()>, stream: PeerServerStream| {
                let release = handler_release.clone();
                async move {
                    let hold = request.uri().path() == HOLD_PATH;
                    let (mut send, mut recv) = stream.split();
                    while recv.recv_chunk().await?.is_some() {}
                    if hold {
                        release.cancelled().await;
                    }
                    let response = Response::builder()
                        .status(StatusCode::OK)
                        .body(())
                        .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                    send.send_response(response).await?;
                    send.send_chunk(Bytes::from_static(RESPONSE_BYTES)).await?;
                    send.finish().await
                }
            };
        let server = PeerServer::new(
            server_endpoint,
            ApprovedPeerPins::new([client_pin]).map_err(|error| format!("client pin: {error}"))?,
            limits.clone(),
            policy,
            handler,
        )
        .map_err(|error| format!("server supervisor: {error}"))?;
        let diagnostics = server.diagnostics();
        let client = PeerClient::new(
            client_endpoint,
            ApprovedPeerPins::new([server_pin]).map_err(|error| format!("server pin: {error}"))?,
            limits,
        )
        .map_err(|error| format!("client supervisor: {error}"))?;
        let server_cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(server_cancel.clone()));
        let destination = PeerDestination::new(server_address, SERVER_NAME);
        let connection = match client.connect(destination.clone()).await {
            Ok(connection) => connection,
            Err(error) => {
                server_cancel.cancel();
                let mut server_task = server_task;
                server_task.abort();
                let _ = timeout_at(TokioInstant::now() + CLEANUP_BOUND, &mut server_task).await;
                return Err(format!("peer connection: {error}"));
            }
        };

        Ok(Self {
            client,
            connection,
            diagnostics,
            release,
            server_cancel,
            server_task: Some(server_task),
        })
    }

    async fn cleanup(mut self, mut held: Vec<PeerClientRecv>) -> Result<(), String> {
        self.release.cancel();
        let deadline = TokioInstant::now() + CLEANUP_BOUND;
        let mut first_error = None;
        for stream in &mut held {
            if let Err(error) = drain_response(stream, deadline).await {
                first_error.get_or_insert(error);
            }
        }
        drop(held);

        match timeout_at(deadline, self.client.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                first_error.get_or_insert(format!("client shutdown: {error}"));
            }
            Err(_) => {
                first_error.get_or_insert("client shutdown timed out".to_owned());
            }
        }

        self.server_cancel.cancel();
        if let Some(mut task) = self.server_task.take() {
            match timeout_at(deadline, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => {
                    first_error.get_or_insert(format!("server shutdown: {error}"));
                }
                Ok(Err(error)) => {
                    first_error.get_or_insert(format!("server task join: {error}"));
                }
                Err(_) => {
                    task.abort();
                    let forced_join_deadline = TokioInstant::now() + Duration::from_millis(250);
                    if timeout_at(forced_join_deadline, &mut task).await.is_err() {
                        first_error.get_or_insert("server task abort join timed out".to_owned());
                    }
                    first_error.get_or_insert("server shutdown timed out".to_owned());
                }
            }
        }

        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for ReuseFixture {
    fn drop(&mut self) {
        self.release.cancel();
        self.server_cancel.cancel();
        if let Some(task) = self.server_task.as_ref() {
            task.abort();
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_reuses_one_freed_stream_credit_at_limit_eight() {
    run_reuse_case(8, 7, 1)
        .await
        .expect("one-slot H3 reuse case");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h3_reuses_seven_freed_stream_credits_at_limit_128() {
    run_reuse_case(128, 121, 7)
        .await
        .expect("seven-slot H3 reuse case");
}

async fn run_reuse_case(
    max_streams: usize,
    initial_holds: usize,
    completions: usize,
) -> Result<(), String> {
    if initial_holds + completions != max_streams {
        return Err("reuse fixture must fill exactly one connection ceiling".to_owned());
    }
    let fixture = ReuseFixture::start(max_streams).await?;
    let mut held = Vec::with_capacity(max_streams);
    let result = run_case_body(&fixture, &mut held, initial_holds, completions).await;
    let cleanup = fixture.cleanup(held).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(cleanup_error)) => Err(format!("{error}; cleanup: {cleanup_error}")),
    }
}

async fn run_case_body(
    fixture: &ReuseFixture,
    held: &mut Vec<PeerClientRecv>,
    initial_holds: usize,
    completions: usize,
) -> Result<(), String> {
    let deadline = TokioInstant::now() + CASE_BOUND;
    for _ in 0..initial_holds {
        held.push(
            open_held(&fixture.connection)
                .await
                .map_err(|error| format!("initial hold {}: {error}", held.len() + 1))?,
        );
    }
    let initial = wait_for_stats(&fixture.diagnostics, deadline, |stats| {
        stats.active_streams == initial_holds as u64
            && stats.available_stream_permits == completions
            && stats.max_stream_permits == initial_holds + completions
    })
    .await?;

    for completed in 0..completions {
        complete_short(&fixture.connection).await?;
        let expected_holds = initial_holds;
        wait_for_stats(&fixture.diagnostics, deadline, |stats| {
            stats.active_streams == expected_holds as u64
                && stats.completed_streams >= (completed + 1) as u64
                && stats.available_stream_permits == completions
        })
        .await?;
    }

    for replacement in 0..completions {
        held.push(
            open_held_until(
                &fixture.connection,
                std::cmp::min(deadline, TokioInstant::now() + REPLACEMENT_OPEN_BOUND),
            )
            .await
            .map_err(|error| {
                format!(
                    "replacement {} after {completions} completed streams: {error}",
                    replacement + 1
                )
            })?,
        );
        wait_for_stats(&fixture.diagnostics, deadline, |stats| {
            stats.active_streams == (initial_holds + replacement + 1) as u64
                && stats.available_stream_permits == completions - replacement - 1
        })
        .await?;

        if replacement == 0 {
            wait_for_stats(&fixture.diagnostics, deadline, |stats| {
                stats.frame_tx_max_streams_bidi > initial.frame_tx_max_streams_bidi
            })
            .await?;
        }
    }

    let full = wait_for_stats(&fixture.diagnostics, deadline, |stats| {
        stats.active_streams == stats.max_stream_permits as u64
            && stats.available_stream_permits == 0
    })
    .await?;
    let expected_accepted = initial_holds + completions + completions;
    if full.accepted_streams != expected_accepted as u64 {
        return Err(format!(
            "unexpected accepted stream count before capacity probe: {}",
            full.accepted_streams
        ));
    }

    let over_cap = fixture
        .connection
        .open_until(request(HOLD_PATH), TokioInstant::now() + OPEN_BOUND)
        .await;
    match over_cap {
        Err(PeerTransportError::Capacity) => {}
        Err(error) => return Err(format!("over-cap stream error: {error}")),
        Ok(mut stream) => {
            stream.cancel();
            return Err("over-cap stream was dispatched".to_owned());
        }
    }
    wait_for_stats(&fixture.diagnostics, deadline, |stats| {
        stats.active_streams == stats.max_stream_permits as u64
            && stats.available_stream_permits == 0
            && stats.accepted_streams == full.accepted_streams
    })
    .await?;
    Ok(())
}

async fn open_held(connection: &PeerConnectionHandle) -> Result<PeerClientRecv, String> {
    open_held_until(connection, TokioInstant::now() + REPLACEMENT_OPEN_BOUND).await
}

async fn open_held_until(
    connection: &PeerConnectionHandle,
    deadline: TokioInstant,
) -> Result<PeerClientRecv, String> {
    let stream = connection
        .open_until(request(HOLD_PATH), deadline)
        .await
        .map_err(|error| format!("opening held stream: {error}"))?;
    let (mut send, recv) = stream.split();
    send.finish()
        .await
        .map_err(|error| format!("finishing held request: {error}"))?;
    Ok(recv)
}

async fn complete_short(connection: &PeerConnectionHandle) -> Result<(), String> {
    let stream = connection
        .open(request(SHORT_PATH))
        .await
        .map_err(|error| format!("opening short stream: {error}"))?;
    let (mut send, mut recv) = stream.split();
    send.finish()
        .await
        .map_err(|error| format!("finishing short request: {error}"))?;
    let response = recv
        .recv_response()
        .await
        .map_err(|error| format!("short response headers: {error}"))?;
    if response.status() != StatusCode::OK {
        return Err(format!("short response status: {}", response.status()));
    }
    let mut body = Vec::with_capacity(RESPONSE_BYTES.len());
    while let Some(chunk) = recv
        .recv_chunk()
        .await
        .map_err(|error| format!("short response body: {error}"))?
    {
        if chunk.len() > RESPONSE_BYTES.len().saturating_sub(body.len()) {
            return Err("response exceeded its exact bounded body".to_owned());
        }
        body.extend_from_slice(chunk.as_bytes());
    }
    if body != RESPONSE_BYTES {
        return Err("short response bytes changed".to_owned());
    }
    Ok(())
}

async fn drain_response(stream: &mut PeerClientRecv, deadline: TokioInstant) -> Result<(), String> {
    timeout_at(deadline, async {
        let response = stream
            .recv_response()
            .await
            .map_err(|error| format!("held response headers: {error}"))?;
        if response.status() != StatusCode::OK {
            return Err(format!("held response status: {}", response.status()));
        }
        let mut body = Vec::with_capacity(RESPONSE_BYTES.len());
        while let Some(chunk) = stream
            .recv_chunk()
            .await
            .map_err(|error| format!("held response body: {error}"))?
        {
            if chunk.len() > RESPONSE_BYTES.len().saturating_sub(body.len()) {
                return Err("response exceeded its exact bounded body".to_owned());
            }
            body.extend_from_slice(chunk.as_bytes());
        }
        if body != RESPONSE_BYTES {
            return Err("held response bytes changed".to_owned());
        }
        Ok(())
    })
    .await
    .map_err(|_| "held response drain timed out".to_owned())?
}

async fn wait_for_stats<F>(
    diagnostics: &PeerServerDiagnostics,
    deadline: TokioInstant,
    predicate: F,
) -> Result<PeerServerConnectionStats, String>
where
    F: Fn(&PeerServerConnectionStats) -> bool,
{
    timeout_at(deadline, async {
        loop {
            if let Some(stats) = diagnostics
                .snapshot()
                .connections
                .into_iter()
                .find(|stats| predicate(stats))
            {
                return stats;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .map_err(|_| {
        format!(
            "peer diagnostics condition timed out: {:?}",
            diagnostics.snapshot()
        )
    })
}

fn request(path: &str) -> Request<()> {
    Request::builder()
        .method("POST")
        .uri(format!("https://{SERVER_NAME}{path}"))
        .body(())
        .expect("valid H3 request URI")
}

fn limits(max_streams: usize) -> Result<PeerTransportLimits, String> {
    PeerTransportLimits::new_with_timeouts(
        64 * 1024,
        256 * 1024,
        8 * 1024 * 1024,
        1,
        max_streams,
        1,
        16 * 1024,
        Duration::from_secs(2),
        Duration::from_secs(2),
        // Synthetic held streams remain idle throughout the bounded 30s case
        // and 5s cleanup; this does not change production transport policy.
        Duration::from_secs(40),
        Duration::from_secs(2),
    )
    .map_err(|error| format!("peer limits: {error}"))
}

fn certificate_chain(certificate: &CertificateMaterial, pki: &FixturePki) -> String {
    format!(
        "{}{}",
        certificate.certificate_pem, pki.peer_ca.certificate_pem
    )
}

fn spki(certificate: &CertificateMaterial) -> Result<SpkiSha256, String> {
    spki_sha256_from_der(&certificate.certificate_der)
        .map_err(|error| format!("certificate SPKI: {error}"))
}
