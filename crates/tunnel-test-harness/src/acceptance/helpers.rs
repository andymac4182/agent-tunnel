use crate::{HarnessError, Result};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, StatusCode, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::TempDir;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    task::JoinHandle,
    time::{Duration, timeout},
};
use tokio_rustls::TlsConnector;
use tunnel_client::{ConnectConfig, CredentialConfig, LimitsConfig, LocalExport, LocalExportKind};
use tunnel_core::RotationConfig;
use uuid::Uuid;

// Echo responses include a device canary and a small JSON error envelope.  A
// bounded collector keeps a faulty relay from making the acceptance process
// retain an unbounded response while still leaving room above the 64 KiB
// public echo body limit.
const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// One generated client profile.  The temporary directory owns every file
/// referenced by the runtime config, so a process cannot outlive its secrets.
pub(crate) struct DeviceProfile {
    pub(crate) config: ConnectConfig,
    pub(crate) config_path: PathBuf,
    pub(crate) service_id: Uuid,
    pub(crate) canary: String,
    _directory: TempDir,
}

#[derive(Clone, Debug)]
pub(crate) struct HttpResponse {
    pub(crate) status: StatusCode,
    pub(crate) body: Vec<u8>,
}

/// Abort the Hyper connection task when the request future is cancelled or
/// returns an error before its normal cleanup path runs.
struct ConnectionTask(Option<JoinHandle<()>>);

impl ConnectionTask {
    fn new(task: JoinHandle<()>) -> Self {
        Self(Some(task))
    }

    async fn finish(mut self) {
        if let Some(mut task) = self.0.take()
            && timeout(Duration::from_secs(5), &mut task).await.is_err()
        {
            task.abort();
            let _ = task.await;
        }
    }
}

impl Drop for ConnectionTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.as_ref() {
            task.abort();
        }
    }
}

/// Bound on one interim or final response head read from a held request.
const MAX_HELD_RESPONSE_HEAD_BYTES: usize = 8 * 1024;
/// How long a held request may wait for the relay to admit it.
const HELD_ADMISSION_TIMEOUT: Duration = Duration::from_secs(10);

/// A consumer request the relay has admitted and whose declared body is
/// intentionally incomplete, so it holds the relay's pre-body admission
/// permits until it is released or dropped.
///
/// It is admitted, not merely sent: [`hold_consumer_request`] returns only
/// after the relay's `100 Continue`, which the relay's HTTP/1 server writes
/// the first time the handler reads the body, and the echo handler reads the
/// body only after it holds both the relay-global and the owner-scoped
/// permit.  A request that was only written could still be queued behind a
/// later one, which then takes its permit (M6-C85).
pub(crate) struct HeldConsumerRequest {
    stream: tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
}

impl HeldConsumerRequest {
    /// Close the connection with the body still incomplete and read the
    /// relay's response head, if any.  The caller may ignore the result: the
    /// relay can answer the incomplete body or simply see the close, and the
    /// recovery request afterwards is what proves the permits were released.
    pub(crate) async fn release(mut self) -> Result<HttpResponse> {
        let _ = self.stream.shutdown().await;
        let status = timeout(Duration::from_secs(5), read_response_head(&mut self.stream))
            .await
            .map_err(|_| {
                HarnessError::Timeout("held consumer request cleanup timed out".to_owned())
            })??;
        Ok(HttpResponse {
            status,
            body: Vec::new(),
        })
    }
}

/// Read one HTTP/1 response head and return its status.  The head is bounded
/// and only the status line is parsed; no header value is retained.
async fn read_response_head(
    stream: &mut tokio_rustls::client::TlsStream<tokio::net::TcpStream>,
) -> Result<StatusCode> {
    let mut head = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_HELD_RESPONSE_HEAD_BYTES {
            return Err(HarnessError::Http(
                "held consumer response head exceeded its bound".to_owned(),
            ));
        }
        // One byte at a time so nothing past this head (a final response
        // after `100 Continue`) is consumed here.
        if stream.read(&mut byte).await.map_err(HarnessError::Io)? == 0 {
            return Err(HarnessError::Http(
                "held consumer connection closed before a response head".to_owned(),
            ));
        }
        head.push(byte[0]);
    }
    parse_status_line(&head)
}

fn parse_status_line(head: &[u8]) -> Result<StatusCode> {
    let line = head.split(|byte| *byte == b'\r').next().unwrap_or_default();
    let mut parts = line.splitn(3, |byte| *byte == b' ');
    let (Some(b"HTTP/1.1"), Some(code)) = (parts.next(), parts.next()) else {
        return Err(HarnessError::Http(
            "held consumer response had no HTTP/1.1 status line".to_owned(),
        ));
    };
    StatusCode::from_bytes(code)
        .map_err(|_| HarnessError::Http("held consumer response status was invalid".to_owned()))
}

/// Write a complete client profile for one fixture device.  The same profile
/// is consumed by the library connector and by the CLI process smoke test.
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_device_profile(
    root: &Path,
    device_id: Uuid,
    service_id: Uuid,
    canary: &str,
    relay_addr: std::net::SocketAddr,
    certificate_pem: &str,
    private_key_pem: &str,
    server_ca_pem: &str,
) -> Result<DeviceProfile> {
    let directory = tempfile::tempdir_in(root).map_err(HarnessError::Io)?;
    let base = directory.path();
    let certificate_path = base.join("device-cert.pem");
    let key_path = base.join("device-key.pem");
    let server_ca_path = base.join("server-ca.pem");
    let config_path = base.join("client.toml");
    std::fs::write(&certificate_path, certificate_pem).map_err(HarnessError::Io)?;
    std::fs::write(&key_path, private_key_pem).map_err(HarnessError::Io)?;
    std::fs::write(&server_ca_path, server_ca_pem).map_err(HarnessError::Io)?;

    for path in [&certificate_path, &key_path, &server_ca_path, &config_path] {
        let path = path.to_string_lossy();
        crate::c11_capture::record_sentinel("filesystem_path", path.as_bytes())?;
    }

    let config = ConnectConfig {
        device_id: device_id.to_string(),
        relay_url: format!("wss://localhost:{}/v1/tunnel/control", relay_addr.port()),
        credentials: CredentialConfig {
            client_certificate: certificate_path.clone(),
            client_key: key_path.clone(),
            server_ca: server_ca_path.clone(),
        },
        exports: [(
            service_id.to_string(),
            LocalExport {
                kind: LocalExportKind::Echo,
                device_canary: Some(canary.to_owned()),
                mcp: None,
                acp: None,
                cua: None,
                fs: None,
            },
        )]
        .into_iter()
        .collect(),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
        reconnect: Default::default(),
        supervisor: Default::default(),
    };
    config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("generated client config is invalid: {error}"))
    })?;

    // Keep the file intentionally explicit rather than relying on a second
    // serializer path in the test harness.  This is the exact shape accepted
    // by `tunnel-client config check`/`check-config`.
    let config_text = format!(
        "device_id = {device_id}\nrelay_url = {relay_url}\n\n[credentials]\nclient_certificate = {certificate}\nclient_key = {key}\nserver_ca = {server_ca}\n\n[exports.{service}]\ntype = \"echo\"\ndevice_canary = {canary}\n",
        device_id = toml_string(&config.device_id),
        relay_url = toml_string(&config.relay_url),
        certificate = toml_string(&config.credentials.client_certificate.to_string_lossy()),
        key = toml_string(&config.credentials.client_key.to_string_lossy()),
        server_ca = toml_string(&config.credentials.server_ca.to_string_lossy()),
        service = toml_key(&service_id.to_string()),
        canary = toml_string(canary),
    );
    std::fs::write(&config_path, config_text).map_err(HarnessError::Io)?;

    Ok(DeviceProfile {
        config,
        config_path,
        service_id,
        canary: canary.to_owned(),
        _directory: directory,
    })
}

/// Send one public consumer request through the relay's real TLS listener.
/// Every request gets a fresh HTTP/1.1 connection, which keeps the helper
/// independent of connection reuse and makes cleanup deterministic.
pub(crate) async fn consumer_request(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
) -> Result<HttpResponse> {
    consumer_request_with_timeout(
        consumer_addr,
        server_ca_der,
        token,
        method,
        path,
        body,
        Duration::from_secs(30),
    )
    .await
}

/// Send one consumer request with a caller-selected deadline.  The short
/// variant is used only by admission probes, where a full request timeout
/// would obscure whether the relay rejected a request while all permits were
/// occupied.
pub(crate) async fn consumer_request_with_timeout(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    method: &str,
    path: &str,
    body: Vec<u8>,
    request_timeout: Duration,
) -> Result<HttpResponse> {
    let connector = consumer_connector(server_ca_der)?;
    let stream = timeout(
        request_timeout,
        tokio::net::TcpStream::connect(consumer_addr),
    )
    .await
    .map_err(|_| HarnessError::Timeout("consumer TCP connect timed out".to_owned()))?
    .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("building relay server name: {error}")))?;
    let tls_stream = timeout(request_timeout, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("consumer TLS handshake timed out".to_owned()))?
        .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
    let io = TokioIo::new(tls_stream);
    let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
        .await
        .map_err(|error| HarnessError::Http(format!("consumer HTTP handshake: {error}")))?;
    let connection_task = ConnectionTask::new(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let uri = format!("https://localhost{path}");
    let request = Request::builder()
        .method(method)
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::from(body)))
        .map_err(|error| HarnessError::Http(format!("building consumer request: {error}")))?;
    let response = timeout(request_timeout, sender.send_request(request))
        .await
        .map_err(|_| HarnessError::Timeout(format!("consumer request timed out: {method} {path}")))?
        .map_err(|error| HarnessError::Http(format!("consumer request failed: {error}")))?;
    let status = response.status();
    let body = timeout(
        request_timeout,
        Limited::new(response.into_body(), MAX_RESPONSE_BYTES).collect(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading consumer response timed out".to_owned()))?
    .map_err(|error| HarnessError::Http(format!("reading consumer response: {error}")))?
    .to_bytes()
    .to_vec();
    drop(sender);
    connection_task.finish().await;
    Ok(HttpResponse { status, body })
}

fn consumer_connector(server_ca_der: &[u8]) -> Result<TlsConnector> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("adding relay CA: {error}")))?;
    let client_config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| HarnessError::Http(format!("configuring consumer TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(client_config)))
}

/// Start a real public POST with `Expect: 100-continue`, wait until the relay
/// has admitted it, then send only its first body byte.  The request remains
/// open with its declared Content-Length, holding the relay's pre-body
/// admission permits until the caller drops or releases it.
///
/// A final response instead of `100 Continue` means the relay refused the
/// request before admitting it, and is returned as an error naming the
/// status: the caller asked for a held permit and did not get one.
pub(crate) async fn hold_consumer_request(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    path: &str,
    body_length: usize,
) -> Result<HeldConsumerRequest> {
    let connector = consumer_connector(server_ca_der)?;
    let stream = tokio::net::TcpStream::connect(consumer_addr)
        .await
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("building relay server name: {error}")))?;
    let mut stream = timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| HarnessError::Timeout("consumer TLS handshake timed out".to_owned()))?
    .map_err(|error| HarnessError::Http(format!("consumer TLS handshake: {error}")))?;
    let head = format!(
        "POST {path} HTTP/1.1\r\nhost: localhost\r\nauthorization: Bearer {token}\r\n\
         content-type: application/octet-stream\r\ncontent-length: {body_length}\r\n\
         expect: 100-continue\r\n\r\n"
    );
    stream
        .write_all(head.as_bytes())
        .await
        .map_err(HarnessError::Io)?;
    stream.flush().await.map_err(HarnessError::Io)?;
    let status = timeout(HELD_ADMISSION_TIMEOUT, read_response_head(&mut stream))
        .await
        .map_err(|_| {
            HarnessError::Timeout("held consumer request was not admitted in time".to_owned())
        })??;
    if status != StatusCode::CONTINUE {
        return Err(HarnessError::Http(format!(
            "held consumer request was answered {} before it was admitted",
            status.as_u16()
        )));
    }
    stream.write_all(b"\x01").await.map_err(HarnessError::Io)?;
    stream.flush().await.map_err(HarnessError::Io)?;
    Ok(HeldConsumerRequest { stream })
}

pub(crate) fn error_code(response: &HttpResponse) -> Option<String> {
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|body| {
            body.get("code")
                .and_then(serde_json::Value::as_str)
                .map(str::to_owned)
        })
}

pub(crate) fn toml_string(value: &str) -> String {
    let escaped = value.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn toml_key(value: &str) -> String {
    if value
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        value.to_owned()
    } else {
        toml_string(value)
    }
}

#[cfg(test)]
mod held_request_tests {
    //! M6-C85: a hold must not return until the server has admitted it.  The
    //! server here is a scripted TLS peer that plays the relay's part of the
    //! exchange, so the order of events is fixed by the test rather than by
    //! a scheduler.

    use super::{HarnessError, hold_consumer_request};
    use crate::FixturePki;
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
        sync::oneshot,
        time::{Duration, timeout},
    };
    use tokio_rustls::TlsAcceptor;

    const SYNTHETIC_TOKEN: &str = "synthetic-m6-c85-token";

    struct ScriptedServer {
        address: std::net::SocketAddr,
        head: oneshot::Receiver<Vec<u8>>,
        reply: oneshot::Sender<&'static [u8]>,
        body_prefix: oneshot::Receiver<Vec<u8>>,
    }

    /// Accept one TLS connection, hand the request head to the test, write
    /// whatever reply the test chooses, then report the first body byte.
    async fn scripted_server(pki: &FixturePki) -> ScriptedServer {
        let leaf = pki.issue_server("m6-c85-scripted").expect("server leaf");
        let chain = format!("{}{}", leaf.certificate_pem, pki.server_ca.certificate_pem);
        let config = tunnel_transport::load_server_config_from_pem(
            chain.as_bytes(),
            leaf.private_key_pem.as_bytes(),
            None,
        )
        .expect("server TLS config");
        let acceptor = TlsAcceptor::from(config);
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.expect("bind");
        let address = listener.local_addr().expect("address");
        let (head_tx, head) = oneshot::channel();
        let (reply, reply_rx) = oneshot::channel::<&'static [u8]>();
        let (prefix_tx, body_prefix) = oneshot::channel();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("accept");
            let mut stream = acceptor.accept(socket).await.expect("TLS accept");
            let mut head = Vec::new();
            let mut byte = [0_u8; 1];
            while !head.ends_with(b"\r\n\r\n") {
                stream.read_exact(&mut byte).await.expect("request head");
                head.push(byte[0]);
            }
            let _ = head_tx.send(head);
            let Ok(reply) = reply_rx.await else { return };
            stream.write_all(reply).await.expect("reply");
            stream.flush().await.expect("flush");
            let mut prefix = [0_u8; 1];
            if stream.read_exact(&mut prefix).await.is_ok() {
                let _ = prefix_tx.send(prefix.to_vec());
            }
            // Keep the connection open until the client closes it.
            let _ = stream.read(&mut prefix).await;
        });
        ScriptedServer {
            address,
            head,
            reply,
            body_prefix,
        }
    }

    #[tokio::test]
    async fn a_hold_returns_only_after_the_server_admits_it() {
        let pki = FixturePki::new().expect("fixture PKI");
        let server = scripted_server(&pki).await;
        let ca = pki.server_ca.certificate_der.clone();
        let address = server.address;
        let mut hold = tokio::spawn(async move {
            hold_consumer_request(address, &ca, SYNTHETIC_TOKEN, "/v1/echo/held", 100).await
        });

        let head = timeout(Duration::from_secs(10), server.head)
            .await
            .expect("request head in time")
            .expect("request head");
        // The server has the request but has not admitted it.  The hold must
        // still be waiting: returning now is the M6-C85 race, where a later
        // request can take the permit this one was about to hold.
        assert!(
            timeout(Duration::from_millis(300), &mut hold)
                .await
                .is_err(),
            "a hold returned before the server admitted it"
        );
        let head = String::from_utf8(head)
            .expect("ASCII head")
            .to_ascii_lowercase();
        assert!(head.starts_with("post /v1/echo/held http/1.1\r\n"));
        assert!(head.contains("\r\nexpect: 100-continue\r\n"));
        assert!(head.contains("\r\ncontent-length: 100\r\n"));

        let mut body_prefix = server.body_prefix;
        assert!(
            body_prefix.try_recv().is_err(),
            "no body byte may be sent before admission"
        );

        server
            .reply
            .send(b"HTTP/1.1 100 Continue\r\n\r\n")
            .expect("server waiting");
        let held = timeout(Duration::from_secs(10), hold)
            .await
            .expect("hold returns once admitted")
            .expect("hold task")
            .expect("admitted hold");
        let prefix = timeout(Duration::from_secs(10), body_prefix)
            .await
            .expect("body prefix in time")
            .expect("body prefix");
        assert_eq!(prefix, b"\x01");
        drop(held);
    }

    #[tokio::test]
    async fn a_hold_the_server_refuses_fails_with_its_status() {
        let pki = FixturePki::new().expect("fixture PKI");
        let server = scripted_server(&pki).await;
        let ca = pki.server_ca.certificate_der.clone();
        let address = server.address;
        let hold = tokio::spawn(async move {
            hold_consumer_request(address, &ca, SYNTHETIC_TOKEN, "/v1/echo/held", 100).await
        });
        timeout(Duration::from_secs(10), server.head)
            .await
            .expect("request head in time")
            .expect("request head");
        server
            .reply
            .send(b"HTTP/1.1 429 Too Many Requests\r\ncontent-length: 0\r\n\r\n")
            .expect("server waiting");
        let error = match timeout(Duration::from_secs(10), hold)
            .await
            .expect("hold answers in time")
            .expect("hold task")
        {
            Ok(_) => panic!("a refused request must not be returned as held"),
            Err(error) => error,
        };
        assert!(
            matches!(&error, HarnessError::Http(message) if message.contains("answered 429")),
            "unexpected error: {error}"
        );
        assert!(!error.to_string().contains(SYNTHETIC_TOKEN));
    }
}
