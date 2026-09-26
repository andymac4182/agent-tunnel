//! M6-C153: a connection beyond the listener's connection limit gets an
//! explicit, retryable refusal, never a bare TCP reset.
//!
//! Before the fix, a socket accepted while every listener permit was held was
//! dropped before TLS, so the client saw a connection reset -- the same as a
//! crashed relay (task row M6-C143).  These tests use real TCP sockets and
//! real TLS 1.3 handshakes: they fill the limit with served keep-alive
//! connections, then assert that the next connection completes TLS, receives
//! `503 CONNECTION_LIMIT` with `Retry-After`, and is then closed cleanly with a
//! TLS `close_notify` (a read returns end of stream, not an error).

use std::{net::SocketAddr, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use rcgen::{CertificateParams, DnType, KeyPair, SanType};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinSet,
    time::{Instant, timeout},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    AcceptedSocketOptions, DEFAULT_MAX_CONCURRENT_HANDSHAKES, ListenerTimeouts,
    require_root_certificates, serve_with_listener_options,
};

const SERVER_NAME: &str = "localhost";
const QUICK_BODY: &str = "quick-ok";

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Deadlines long enough that the served keep-alive connections keep their
/// permits for the whole test.
fn holding_timeouts() -> ListenerTimeouts {
    ListenerTimeouts {
        handshake_timeout: Duration::from_secs(10),
        pre_request_timeout: Duration::from_secs(60),
        http1_header_read_timeout: Duration::from_secs(60),
    }
}

struct Fixture {
    address: SocketAddr,
    client_config: Arc<rustls::ClientConfig>,
    cancel: CancellationToken,
    server: tokio::task::JoinHandle<Result<(), tunnel_transport::TransportError>>,
}

impl Fixture {
    async fn start(options: AcceptedSocketOptions) -> TestResult<Self> {
        let key = KeyPair::generate()?;
        let mut params = CertificateParams::default();
        params
            .distinguished_name
            .push(DnType::CommonName, "M6 listener capacity fixture");
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

        let router = Router::new().route("/quick", get(|| async { QUICK_BODY }));
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let server = tokio::spawn(serve_with_listener_options(
            listener,
            router,
            server_config,
            cancel.clone(),
            options,
            holding_timeouts(),
        ));
        Ok(Self {
            address,
            client_config: Arc::new(client_config),
            cancel,
            server,
        })
    }

    async fn shutdown(self) -> TestResult {
        self.cancel.cancel();
        let result = timeout(Duration::from_secs(10), self.server)
            .await
            .map_err(|_| "listener did not join after cancellation")??;
        result?;
        Ok(())
    }
}

async fn handshake(
    address: SocketAddr,
    config: Arc<rustls::ClientConfig>,
) -> std::io::Result<TlsStream<TcpStream>> {
    let tcp = TcpStream::connect(address).await?;
    TlsConnector::from(config)
        .connect(SERVER_NAME.try_into().expect("fixture server name"), tcp)
        .await
}

/// A POST with a small body, as the flood's echo workers send: the refusal
/// must read it before closing, or the unread bytes would turn the close into
/// a reset.
async fn write_request(stream: &mut TlsStream<TcpStream>, path: &str) -> std::io::Result<()> {
    let body = "synthetic-body";
    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: keep-alive\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await
}

async fn write_get(stream: &mut TlsStream<TcpStream>, path: &str) -> std::io::Result<()> {
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {SERVER_NAME}\r\nConnection: keep-alive\r\n\r\n");
    stream.write_all(request.as_bytes()).await?;
    stream.flush().await
}

/// Read one HTTP/1.1 response head plus its `content-length` body.
async fn read_response(stream: &mut TlsStream<TcpStream>) -> std::io::Result<String> {
    let mut buffer = Vec::new();
    let mut chunk = [0_u8; 1024];
    loop {
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            break;
        }
        buffer.extend_from_slice(&chunk[..read]);
        let text = String::from_utf8_lossy(&buffer).to_ascii_lowercase();
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

/// Open `count` connections that each complete one request and stay open, so
/// each holds one listener permit.
async fn hold_served(fixture: &Fixture, count: usize) -> TestResult<Vec<TlsStream<TcpStream>>> {
    let mut tasks = JoinSet::new();
    for _ in 0..count {
        let address = fixture.address;
        let config = fixture.client_config.clone();
        tasks.spawn(async move {
            let mut stream = handshake(address, config).await?;
            write_get(&mut stream, "/quick").await?;
            let response = read_response(&mut stream).await?;
            Ok::<_, std::io::Error>((stream, response))
        });
    }
    let mut held = Vec::new();
    while let Some(joined) = tasks.join_next().await {
        let (stream, response) = joined??;
        assert!(
            response.contains(QUICK_BODY),
            "a connection inside the limit was not served: {response}"
        );
        held.push(stream);
    }
    Ok(held)
}

/// The documented refusal: status, retry hint, stable code, not dispatched,
/// and the connection closed after it.
fn assert_connection_limit_refusal(response: &str) {
    let lower = response.to_ascii_lowercase();
    assert!(
        response.starts_with("HTTP/1.1 503"),
        "the over-limit connection did not get 503: {response}"
    );
    assert!(
        lower.contains("\r\nretry-after: 1\r\n"),
        "the refusal carries no Retry-After: {response}"
    );
    assert!(
        lower.contains("\r\nconnection: close\r\n"),
        "the refusal does not announce the close: {response}"
    );
    for field in [
        "\"code\":\"CONNECTION_LIMIT\"",
        "\"execution\":\"not_dispatched\"",
        "\"retryable\":true",
        "\"retry_after_ms\":1000",
    ] {
        assert!(
            response.contains(field),
            "the refusal body lacks {field}: {response}"
        );
    }
}

/// After the refusal the server closes with `close_notify`: end of stream,
/// not a reset and not a truncated TLS stream.
async fn assert_clean_close(stream: &mut TlsStream<TcpStream>) {
    let read = timeout(Duration::from_secs(5), stream.read(&mut [0_u8; 1]))
        .await
        .expect("the refused connection was not closed after the refusal");
    match read {
        Ok(0) => {}
        Ok(_) => panic!("the refused connection sent bytes after the refusal"),
        Err(error) => panic!("the refused connection was not closed cleanly: {error:?}"),
    }
}

/// Red before the fix: connection 65 was dropped before TLS, so the handshake
/// failed with a reset or an early end of stream and no HTTP status arrived.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn connection_over_the_limit_gets_a_retryable_503_not_a_reset() -> TestResult {
    let fixture = Fixture::start(AcceptedSocketOptions::default()).await?;
    let mut held = hold_served(&fixture, DEFAULT_MAX_CONCURRENT_HANDSHAKES).await?;
    assert_eq!(held.len(), DEFAULT_MAX_CONCURRENT_HANDSHAKES);

    let mut extra = timeout(
        Duration::from_secs(10),
        handshake(fixture.address, fixture.client_config.clone()),
    )
    .await
    .map_err(|_| "the over-limit TLS handshake did not complete")?
    .map_err(|error| {
        format!("the over-limit connection was dropped instead of refused: {error:?}")
    })?;
    write_request(&mut extra, "/quick")
        .await
        .map_err(|error| format!("the over-limit request could not be written: {error:?}"))?;
    let response = timeout(Duration::from_secs(10), read_response(&mut extra))
        .await
        .map_err(|_| "the over-limit connection got no answer")?
        .map_err(|error| format!("the over-limit connection was reset: {error:?}"))?;
    assert_connection_limit_refusal(&response);
    assert!(
        !response.contains(QUICK_BODY),
        "the over-limit request was dispatched to the router"
    );
    assert_clean_close(&mut extra).await;

    // The limit is unchanged, and a freed permit serves the next connection.
    drop(held.pop());
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let mut next = handshake(fixture.address, fixture.client_config.clone()).await?;
        write_get(&mut next, "/quick").await?;
        let response = read_response(&mut next).await?;
        if response.contains(QUICK_BODY) {
            break;
        }
        assert_connection_limit_refusal(&response);
        assert!(Instant::now() < deadline, "a freed permit was never reused");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    drop(held);
    fixture.shutdown().await
}

/// With the refusal margin also full, the listener stops accepting: a further
/// connection waits in the kernel listen backlog -- it is neither reset nor
/// answered -- and is refused with the same `503` once a refusal slot frees.
/// The limit, the margin and the refusal bound are configurable.
///
/// Red before the fix: there was no margin and no backlog hold, so every
/// connection over the limit was dropped before TLS.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn full_refusal_margin_holds_connections_in_the_backlog_not_reset() -> TestResult {
    let refusal_timeout = Duration::from_millis(1_500);
    let diagnostics = tunnel_transport::AcceptedSocketDiagnostics::new();
    let fixture = Fixture::start(AcceptedSocketOptions {
        diagnostics: Some(diagnostics.clone()),
        capacity: tunnel_transport::ListenerCapacity {
            max_connections: 2,
            refusal_margin: 1,
            refusal_timeout,
        },
        ..AcceptedSocketOptions::default()
    })
    .await?;
    let held = hold_served(&fixture, 2).await?;

    // A silent TCP connection takes the only refusal slot: it never sends a
    // ClientHello, so it holds the slot until the refusal bound closes it.
    let mut silent = TcpStream::connect(fixture.address).await?;
    let silent_since = Instant::now();
    // Let the listener accept it before the next connection arrives.
    let accepted = Instant::now() + Duration::from_secs(5);
    while diagnostics.capacity_refusals() < 1 {
        assert!(
            Instant::now() < accepted,
            "the silent connection was never accepted"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }

    let address = fixture.address;
    let config = fixture.client_config.clone();
    let mut waiting = tokio::spawn(async move {
        let mut stream = handshake(address, config).await?;
        write_request(&mut stream, "/quick").await?;
        let response = read_response(&mut stream).await?;
        Ok::<_, std::io::Error>((stream, response))
    });

    // While both the limit and the margin are full, the connection is held,
    // not reset and not answered.
    assert!(
        timeout(Duration::from_millis(500), &mut waiting)
            .await
            .is_err(),
        "a connection was answered or reset while the refusal margin was full"
    );
    assert_eq!(diagnostics.capacity_refusals(), 1);

    // The silent connection is closed by the refusal bound, freeing the slot.
    let read = timeout(
        refusal_timeout + Duration::from_secs(5),
        silent.read(&mut [0_u8; 1]),
    )
    .await
    .map_err(|_| "the silent over-capacity connection was never closed")?;
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "the silent over-capacity connection received bytes"
    );
    assert!(silent_since.elapsed() >= refusal_timeout.saturating_sub(Duration::from_millis(100)));

    let (mut stream, response) = timeout(Duration::from_secs(10), waiting)
        .await
        .map_err(|_| "the backlogged connection was never answered")??
        .map_err(|error| format!("the backlogged connection was reset: {error:?}"))?;
    assert_connection_limit_refusal(&response);
    assert_clean_close(&mut stream).await;
    assert_eq!(diagnostics.capacity_refusals(), 2);

    drop(held);
    fixture.shutdown().await
}

#[test]
fn listener_capacity_is_validated() {
    use tunnel_transport::ListenerCapacity;
    let valid = ListenerCapacity::default();
    assert_eq!(valid.max_connections, 64);
    assert_eq!(valid.refusal_margin, 16);
    assert!(valid.validate().is_ok());
    assert!(
        ListenerCapacity {
            refusal_margin: 0,
            ..valid
        }
        .validate()
        .is_ok()
    );
    for invalid in [
        ListenerCapacity {
            max_connections: 0,
            ..valid
        },
        ListenerCapacity {
            max_connections: 4097,
            ..valid
        },
        ListenerCapacity {
            refusal_margin: 257,
            ..valid
        },
        ListenerCapacity {
            refusal_timeout: Duration::from_millis(10),
            ..valid
        },
        ListenerCapacity {
            refusal_timeout: Duration::from_secs(301),
            ..valid
        },
    ] {
        assert!(invalid.validate().is_err(), "{invalid:?} was accepted");
    }
}
