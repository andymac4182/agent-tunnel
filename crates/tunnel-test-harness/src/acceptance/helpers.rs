use crate::{HarnessError, Result};
use futures_util::stream::unfold;
use http_body_util::{BodyExt, Full, Limited, StreamBody};
use hyper::{
    Request, StatusCode,
    body::{Bytes, Frame},
};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use std::{
    convert::Infallible,
    path::{Path, PathBuf},
    sync::Arc,
};
use tempfile::TempDir;
use tokio::{
    sync::mpsc,
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

type HeldBodySender = mpsc::Sender<std::result::Result<Frame<Bytes>, Infallible>>;
type HeldResponseTask = JoinHandle<std::result::Result<HttpResponse, String>>;

/// A consumer request whose declared body is intentionally incomplete.  The
/// relay acquires its public admission permit before reading the body, so a
/// fixed number of these requests can deterministically exercise pre-body
/// admission without relying on scheduler timing or a slow device adapter.
pub(crate) struct HeldConsumerRequest {
    body_tx: Option<HeldBodySender>,
    response_task: Option<HeldResponseTask>,
    connection_task: Option<ConnectionTask>,
}

impl HeldConsumerRequest {
    /// End the incomplete body and wait for the relay's bounded rejection
    /// response.  The caller may ignore the response status because Hyper can
    /// report an incomplete Content-Length as a transport error after the
    /// relay has already released its admission permit.
    pub(crate) async fn release(mut self) -> Result<HttpResponse> {
        self.body_tx.take();
        let response = match self.response_task.take() {
            Some(mut task) => match timeout(Duration::from_secs(5), &mut task).await {
                Ok(Ok(Ok(response))) => Ok(response),
                Ok(Ok(Err(error))) => Err(HarnessError::Http(error)),
                Ok(Err(error)) => Err(HarnessError::Http(format!(
                    "held consumer request task failed: {error}"
                ))),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    Err(HarnessError::Timeout(
                        "held consumer request cleanup timed out".to_owned(),
                    ))
                }
            },
            None => Err(HarnessError::Http(
                "held consumer request task was already consumed".to_owned(),
            )),
        };
        if let Some(connection_task) = self.connection_task.take() {
            connection_task.finish().await;
        }
        response
    }
}

impl Drop for HeldConsumerRequest {
    fn drop(&mut self) {
        self.body_tx.take();
        if let Some(task) = self.response_task.as_ref() {
            task.abort();
        }
        self.connection_task.take();
    }
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
                fs: None,
            },
        )]
        .into_iter()
        .collect(),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
        reconnect: Default::default(),
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

/// Start a real public POST and send only its first body byte.  The request
/// remains open with its declared Content-Length, holding the relay's
/// pre-body admission permit until the caller drops or releases it.
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
    let tls_stream = timeout(
        Duration::from_secs(10),
        connector.connect(server_name, stream),
    )
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
    let (body_tx, body_rx) = mpsc::channel(1);
    let body_stream = unfold(body_rx, |mut receiver| async move {
        receiver.recv().await.map(|frame| (frame, receiver))
    });
    let uri = format!("https://localhost{path}");
    let request = Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .header("content-length", body_length.to_string())
        .body(StreamBody::new(body_stream))
        .map_err(|error| HarnessError::Http(format!("building consumer request: {error}")))?;
    let response_task = tokio::spawn(async move {
        let response = sender
            .send_request(request)
            .await
            .map_err(|error| format!("held consumer request failed: {error}"))?;
        let status = response.status();
        let body = timeout(
            Duration::from_secs(5),
            Limited::new(response.into_body(), MAX_RESPONSE_BYTES).collect(),
        )
        .await
        .map_err(|_| "reading held consumer response timed out".to_owned())?
        .map_err(|error| format!("reading held consumer response: {error}"))?
        .to_bytes()
        .to_vec();
        Ok(HttpResponse { status, body })
    });
    let prefix_sender = body_tx.clone();
    if let Err(error) = prefix_sender
        .send(Ok(Frame::data(Bytes::from_static(b"\x01"))))
        .await
    {
        response_task.abort();
        drop(connection_task);
        return Err(HarnessError::Http(format!(
            "sending held request prefix: {error}"
        )));
    }
    Ok(HeldConsumerRequest {
        body_tx: Some(body_tx),
        response_task: Some(response_task),
        connection_task: Some(connection_task),
    })
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
