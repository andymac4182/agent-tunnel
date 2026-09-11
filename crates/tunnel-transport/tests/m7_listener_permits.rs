//! M7-C31 real-socket regressions for bounded listener connection permits.
//!
//! The listener holds one of [`DEFAULT_MAX_CONCURRENT_HANDSHAKES`] permits for
//! the whole HTTP connection.  These tests use actual TCP sockets and actual
//! TLS 1.3 handshakes to prove that a connection which completes the handshake
//! and then sends nothing is closed within the configured pre-request bound and
//! returns its permit, while an in-flight request and a keep-alive connection
//! that already dispatched a request survive well past that bound.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, sleep, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    DEFAULT_MAX_CONCURRENT_HANDSHAKES, ListenerTimeouts, require_root_certificates,
    serve_with_listener_options,
};

const SERVER_NAME: &str = "localhost";
const QUICK_BODY: &str = "quick-ok";
const SLOW_BODY: &str = "slow-done";

/// Pre-request bound used by the permit-exhaustion fixture.  It is long enough
/// that 64 real handshakes complete well inside it, so the "further connection
/// is refused" observation cannot pass by accident.
const FILL_PRE_REQUEST: Duration = Duration::from_secs(2);
/// Pre-request bound used by the survival fixture, which needs a bound much
/// shorter than the in-flight request it must outlive.
const SURVIVAL_PRE_REQUEST: Duration = Duration::from_millis(300);
const SURVIVAL_HEADER_READ: Duration = Duration::from_millis(250);
/// Duration of the in-flight `/slow` request: five times the survival bound.
const SLOW_REQUEST: Duration = Duration::from_millis(1_500);

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Fixture {
    address: SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<Result<(), tunnel_transport::TransportError>>,
}

impl Fixture {
    async fn start(timeouts: ListenerTimeouts) -> TestResult<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M7 listener permit fixture");
        params
            .subject_alt_names
            .push(SanType::DnsName(SERVER_NAME.try_into()?));
        let certificate = params.self_signed(&key)?;
        let certificate_pem = certificate.pem();
        let private_key_pem = key.serialize_pem();

        let server_config = tunnel_transport::load_server_config_from_pem(
            certificate_pem.as_bytes(),
            private_key_pem.as_bytes(),
            None,
        )?;
        let roots = require_root_certificates(certificate_pem.as_bytes())?;
        let mut client_config = rustls::ClientConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_root_certificates(roots)
        .with_no_client_auth();
        client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

        let router = Router::new()
            .route("/quick", get(|| async { QUICK_BODY }))
            .route(
                "/slow",
                get(|| async {
                    sleep(SLOW_REQUEST).await;
                    SLOW_BODY
                }),
            );

        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_with_listener_options(
            listener,
            router,
            server_config,
            cancel.clone(),
            tunnel_transport::AcceptedSocketOptions::default(),
            timeouts,
        ));

        Ok(Self {
            address,
            client_config: Arc::new(client_config),
            cancel,
            server,
        })
    }

    /// Complete a real TCP connection and TLS 1.3 handshake without sending a
    /// single application byte.
    async fn handshake(&self) -> std::io::Result<TlsStream<TcpStream>> {
        let tcp = TcpStream::connect(self.address).await?;
        TlsConnector::from(self.client_config.clone())
            .connect(SERVER_NAME.try_into().expect("fixture server name"), tcp)
            .await
    }

    async fn shutdown(self) -> TestResult {
        self.cancel.cancel();
        let result = timeout(Duration::from_secs(5), self.server)
            .await
            .map_err(|_| "listener did not join after cancellation")??;
        result?;
        Ok(())
    }
}

async fn write_request(stream: &mut TlsStream<TcpStream>, path: &str, close: bool) -> TestResult {
    let connection = if close { "close" } else { "keep-alive" };
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: {connection}\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await?;
    Ok(())
}

/// Read one HTTP/1.1 response head plus its body, which the fixture always
/// returns with an explicit `content-length`.
async fn read_response(stream: &mut TlsStream<TcpStream>) -> TestResult<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&buffer);
        if let Some(head_end) = text.find("\r\n\r\n") {
            let body_length = text
                .split("\r\n")
                .find_map(|line| line.strip_prefix("content-length: "))
                .and_then(|value| value.trim().parse::<usize>().ok());
            if let Some(body_length) = body_length
                && buffer.len() >= head_end + 4 + body_length
            {
                break;
            }
        }
    }
    Ok(String::from_utf8_lossy(&buffer).into_owned())
}

/// Assert that a connection is closed without an HTTP response: the listener
/// drops a socket at permit capacity before the TLS handshake can complete.
async fn refused_at_capacity(fixture: &Fixture) -> TestResult<bool> {
    match timeout(Duration::from_secs(1), fixture.handshake()).await {
        Err(_) => Ok(true),
        Ok(Err(_)) => Ok(true),
        Ok(Ok(mut stream)) => {
            write_request(&mut stream, "/quick", true).await?;
            let response = read_response(&mut stream).await?;
            Ok(!response.contains(QUICK_BODY))
        }
    }
}

/// Red before the fix: the silent connections never released their permits, so
/// a further connection stayed refused forever.
#[tokio::test]
async fn silent_tls_connections_release_listener_permits_within_the_pre_request_bound() -> TestResult
{
    let timeouts = ListenerTimeouts {
        handshake_timeout: Duration::from_secs(5),
        pre_request_timeout: FILL_PRE_REQUEST,
        http1_header_read_timeout: Duration::from_millis(500),
    };
    let fixture = Fixture::start(timeouts).await?;

    // Fill every listener permit with handshaken-but-silent TLS connections.
    let mut handshakes = JoinSet::new();
    for _ in 0..DEFAULT_MAX_CONCURRENT_HANDSHAKES {
        let address = fixture.address;
        let config = fixture.client_config.clone();
        handshakes.spawn(async move {
            let tcp = TcpStream::connect(address).await?;
            TlsConnector::from(config)
                .connect(SERVER_NAME.try_into().expect("fixture server name"), tcp)
                .await
        });
    }
    let mut silent = Vec::new();
    while let Some(joined) = handshakes.join_next().await {
        silent.push(joined??);
    }
    let filled_at = Instant::now();
    assert_eq!(
        silent.len(),
        DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        "fixture did not establish one silent TLS connection per listener permit"
    );

    // Every permit is held by a connection that has sent no application byte.
    assert!(
        refused_at_capacity(&fixture).await?,
        "a further connection was served while every listener permit was held"
    );

    // The bound must close the silent connections and return their permits.
    for stream in &mut silent {
        let read = timeout(
            FILL_PRE_REQUEST + Duration::from_secs(3),
            stream.read(&mut [0_u8; 1]),
        )
        .await
        .map_err(|_| "a silent connection was still open after the pre-request bound")?;
        assert_eq!(
            read.unwrap_or(0),
            0,
            "a silent connection returned application bytes instead of being closed"
        );
    }
    let closed_after = filled_at.elapsed();
    assert!(
        closed_after < FILL_PRE_REQUEST + Duration::from_secs(3),
        "silent connections were closed after {closed_after:?}, beyond the configured bound"
    );

    // The permit count is back to full: every permit can be taken again, and a
    // further connection is served.
    let mut refilled = JoinSet::new();
    for _ in 0..DEFAULT_MAX_CONCURRENT_HANDSHAKES {
        let address = fixture.address;
        let config = fixture.client_config.clone();
        refilled.spawn(async move {
            let tcp = TcpStream::connect(address).await?;
            TlsConnector::from(config)
                .connect(SERVER_NAME.try_into().expect("fixture server name"), tcp)
                .await
        });
    }
    let mut reclaimed = Vec::new();
    while let Some(joined) = refilled.join_next().await {
        reclaimed.push(joined??);
    }
    assert_eq!(
        reclaimed.len(),
        DEFAULT_MAX_CONCURRENT_HANDSHAKES,
        "the listener did not return every permit after the pre-request bound"
    );
    let mut served = reclaimed.pop().expect("one reclaimed connection");
    write_request(&mut served, "/quick", true).await?;
    let response = timeout(Duration::from_secs(5), read_response(&mut served))
        .await
        .map_err(|_| "a reclaimed connection did not answer before the deadline")??;
    assert!(
        response.contains("200 OK") && response.contains(QUICK_BODY),
        "a reclaimed connection did not receive the fixture response: {response}"
    );

    drop(silent);
    drop(reclaimed);
    drop(served);
    fixture.shutdown().await
}

/// The pre-request bound must not touch an established connection: an in-flight
/// request that runs five times longer than the bound still completes, and the
/// same connection still serves a second keep-alive request afterwards.
#[tokio::test]
async fn established_request_survives_well_past_the_pre_request_bound() -> TestResult {
    let timeouts = ListenerTimeouts {
        handshake_timeout: Duration::from_secs(5),
        pre_request_timeout: SURVIVAL_PRE_REQUEST,
        http1_header_read_timeout: SURVIVAL_HEADER_READ,
    };
    let fixture = Fixture::start(timeouts).await?;

    let mut stream = fixture.handshake().await?;
    write_request(&mut stream, "/slow", false).await?;
    let started = Instant::now();
    let response = timeout(
        SLOW_REQUEST + Duration::from_secs(5),
        read_response(&mut stream),
    )
    .await
    .map_err(|_| "the in-flight request was cut off by the pre-request bound")??;
    assert!(
        response.contains("200 OK") && response.contains(SLOW_BODY),
        "the in-flight request did not complete: {response}"
    );
    assert!(
        started.elapsed() >= SLOW_REQUEST,
        "the fixture request returned before its own duration elapsed"
    );
    assert!(
        started.elapsed() > SURVIVAL_PRE_REQUEST * 4,
        "the in-flight request did not outlive the pre-request bound by a wide margin"
    );

    // The deadline is disarmed for good, so the same connection still serves a
    // second request long after the pre-request bound elapsed.
    write_request(&mut stream, "/quick", true).await?;
    let response = timeout(Duration::from_secs(5), read_response(&mut stream))
        .await
        .map_err(|_| "the keep-alive connection was closed after its first request")??;
    assert!(
        response.contains("200 OK") && response.contains(QUICK_BODY),
        "the keep-alive connection did not serve a second request: {response}"
    );

    drop(stream);
    fixture.shutdown().await
}

/// An HTTP/1 connection that has already dispatched a request and then goes
/// idle is bounded by the header-read deadline rather than the pre-request
/// deadline, so it also cannot hold a permit indefinitely.
#[tokio::test]
async fn idle_keep_alive_connection_is_closed_by_the_header_read_bound() -> TestResult {
    let timeouts = ListenerTimeouts {
        handshake_timeout: Duration::from_secs(5),
        pre_request_timeout: SURVIVAL_PRE_REQUEST,
        http1_header_read_timeout: SURVIVAL_HEADER_READ,
    };
    let fixture = Fixture::start(timeouts).await?;

    let mut stream = fixture.handshake().await?;
    write_request(&mut stream, "/quick", false).await?;
    let response = timeout(Duration::from_secs(5), read_response(&mut stream))
        .await
        .map_err(|_| "the first keep-alive request did not complete")??;
    assert!(
        response.contains(QUICK_BODY),
        "the first keep-alive request did not complete: {response}"
    );

    let read = timeout(
        SURVIVAL_HEADER_READ + Duration::from_secs(3),
        stream.read(&mut [0_u8; 1]),
    )
    .await
    .map_err(|_| "an idle keep-alive connection was never closed")?;
    assert_eq!(
        read.unwrap_or(0),
        0,
        "an idle keep-alive connection returned application bytes instead of being closed"
    );

    drop(stream);
    fixture.shutdown().await
}
