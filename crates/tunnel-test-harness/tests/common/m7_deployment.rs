//! Shared bounded helpers for M7 process-bound deployment tests.
//
// The process acceptance and fault-matrix integration binaries consume
// different subsets of these helpers, so per-binary dead-code warnings are
// expected for this shared module.
#![allow(dead_code)]

use std::{
    collections::BTreeMap,
    env, fs, io,
    net::{IpAddr, SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::ExitStatus,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{DateTime, Utc};
use http_body_util::{BodyExt, Empty, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use redis::{ConnectionAddr, IntoConnectionInfo};
use rsa::{RsaPublicKey, pkcs8::DecodePublicKey, traits::PublicKeyParts};
use serde::Deserialize;
use tempfile::TempDir;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener as TokioTcpListener, TcpStream},
    task::JoinSet,
    time::{sleep, timeout},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_util::sync::CancellationToken;
use tunnel_test_harness::cluster_fixture::TestMembershipAuthority;
use tunnel_test_harness::{HarnessError, ManagedProcess, OidcFixture, Result};

pub(crate) const READY_DEADLINE: Duration = Duration::from_secs(20);
pub(crate) const PROBE_TIMEOUT: Duration = Duration::from_secs(1);
pub(crate) const HTTP_REQUEST_MAX: usize = 32 * 1024;
pub(crate) const HEALTH_BODY_MAX: usize = 128;
pub(crate) const AUXILIARY_CONNECTION_LIMIT: usize = 8;
pub(crate) const AUXILIARY_CONNECTION_DEADLINE: Duration = Duration::from_secs(5);
pub(crate) const AUXILIARY_SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

pub(crate) async fn wait_for_ready(
    process: &mut ManagedProcess,
    consumer_bind: SocketAddr,
    server_ca_der: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + READY_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "relay exited before health readiness with {status}"
            )));
        }
        let live = health_request(consumer_bind, server_ca_der, "/livez").await;
        let ready = health_request(consumer_bind, server_ca_der, "/readyz").await;
        if let (Ok(live), Ok(ready)) = (live, ready)
            && live.0 == 200
            && live.1.as_slice() == br#"{"status":"live"}"#
            && ready.0 == 200
            && ready.1.as_slice() == br#"{"status":"ready"}"#
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "relay /livez and /readyz did not converge before the bounded startup deadline"
                    .into(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

pub(crate) async fn health_request(
    address: SocketAddr,
    server_ca_der: &[u8],
    path: &'static str,
) -> Result<(u16, Vec<u8>)> {
    let deadline = Instant::now() + PROBE_TIMEOUT;
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            server_ca_der.to_vec(),
        ))
        .map_err(|error| HarnessError::Http(format!("health root: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("health TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout(
        health_remaining(deadline, "TCP connect")?,
        TcpStream::connect(address),
    )
    .await
    .map_err(|_| HarnessError::Timeout("health TCP connect".into()))??;
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("health server name: {error}")))?;
    let tls = timeout(
        health_remaining(deadline, "TLS handshake")?,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| HarnessError::Timeout("health TLS handshake".into()))?
    .map_err(|error| HarnessError::Http(format!("health TLS handshake: {error}")))?;
    let (mut sender, connection) = timeout(
        health_remaining(deadline, "HTTP handshake")?,
        hyper::client::conn::http1::handshake(TokioIo::new(tls)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("health HTTP handshake".into()))?
    .map_err(|error| HarnessError::Http(format!("health HTTP handshake: {error}")))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result: Result<(u16, Vec<u8>)> = async {
        let request = Request::builder()
            .method("GET")
            .uri(path)
            .header("host", "localhost")
            .body(Empty::<Bytes>::new())
            .map_err(|error| HarnessError::Http(format!("health request: {error}")))?;
        let response = timeout(
            health_remaining(deadline, "request")?,
            sender.send_request(request),
        )
        .await
        .map_err(|_| HarnessError::Timeout("health request".into()))?
        .map_err(|error| HarnessError::Http(format!("health response: {error}")))?;
        let status = response.status().as_u16();
        let body = timeout(
            health_remaining(deadline, "body")?,
            Limited::new(response.into_body(), HEALTH_BODY_MAX + 1).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("health body".into()))?
        .map_err(|error| HarnessError::Http(format!("health body: {error}")))?
        .to_bytes();
        if body.len() > HEALTH_BODY_MAX {
            return Err(HarnessError::Http("health body exceeded bound".into()));
        }
        Ok((status, body.to_vec()))
    }
    .await;
    connection_task.abort();
    if let Err(error) = connection_task.await
        && !error.is_cancelled()
        && result.is_ok()
    {
        return Err(HarnessError::Http(format!(
            "health HTTP connection task failed: {error}"
        )));
    }
    result
}

pub(crate) fn health_remaining(deadline: Instant, phase: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "health {phase} exceeded absolute probe deadline"
        )));
    }
    Ok(remaining)
}

pub(crate) async fn wait_for_ports_released(
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        let consumer = TcpListener::bind(consumer_bind);
        let device = TcpListener::bind(device_bind);
        let peer = UdpSocket::bind(peer_bind);
        if consumer.is_ok() && device.is_ok() && peer.is_ok() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "relay listener ports were not released after SIGINT".into(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

pub(crate) async fn wait_for_exit(
    process: &mut ManagedProcess,
    deadline: Duration,
) -> Result<ExitStatus> {
    let end = Instant::now() + deadline;
    loop {
        if let Some(status) = process.try_wait()? {
            return Ok(status);
        }
        if Instant::now() >= end {
            return Err(HarnessError::Timeout(
                "managed relay process deadline".into(),
            ));
        }
        sleep(Duration::from_millis(20)).await;
    }
}

pub(crate) fn process_diagnostic(process: &ManagedProcess) -> String {
    let stderr_bytes = process.stderr();
    let stdout_bytes = process.stdout();
    let stderr = String::from_utf8_lossy(&stderr_bytes);
    let stdout = String::from_utf8_lossy(&stdout_bytes);
    format!(
        "bounded relay output: stdout={} stderr={}",
        truncate(&stdout),
        truncate(&stderr)
    )
}

pub(crate) fn truncate(value: &str) -> String {
    value.chars().take(4_096).collect()
}

/// Send `SIGTERM`, what systemd and launchd send to stop a service
/// (M6-C23).
pub(crate) fn send_sigterm(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let status = std::process::Command::new("/bin/kill")
            .arg("-TERM")
            .arg(pid.to_string())
            .status()
            .map_err(|error| HarnessError::Process(format!("sending SIGTERM: {error}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "sending SIGTERM returned {status}"
            )))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err(HarnessError::Unsupported(
            "SIGTERM is unavailable on this host".into(),
        ))
    }
}

pub(crate) fn send_sigint(pid: u32) -> Result<()> {
    #[cfg(unix)]
    {
        let status = std::process::Command::new("/bin/kill")
            .arg("-INT")
            .arg(pid.to_string())
            .status()
            .map_err(|error| HarnessError::Process(format!("sending SIGINT: {error}")))?;
        if status.success() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "sending SIGINT returned {status}"
            )))
        }
    }
    #[cfg(not(unix))]
    {
        let _ = pid;
        Err(HarnessError::Unsupported(
            "SIGINT is unavailable on this host".into(),
        ))
    }
}

pub(crate) struct FixtureFiles {
    _root: TempDir,
    root_path: PathBuf,
}

impl FixtureFiles {
    pub(crate) fn new() -> Result<Self> {
        let root = tempfile::tempdir()?;
        let root_path = root.path().canonicalize()?;
        set_mode(&root_path, 0o700);
        fs::create_dir(root_path.join("state"))?;
        set_mode(&root_path.join("state"), 0o700);
        Ok(Self {
            _root: root,
            root_path,
        })
    }

    pub(crate) fn write(&self, name: &str, contents: &[u8]) -> Result<PathBuf> {
        let path = self.root_path.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            set_mode(parent, 0o700);
        }
        fs::write(&path, contents)?;
        set_mode(&path, 0o600);
        Ok(path)
    }

    pub(crate) fn state_path(&self) -> Result<PathBuf> {
        Ok(self.root_path.join("state/membership-state.json"))
    }
}

pub(crate) struct ProcessConfigFixture<'a> {
    pub(crate) consumer_bind: SocketAddr,
    pub(crate) device_bind: SocketAddr,
    pub(crate) peer_bind: SocketAddr,
    pub(crate) redis_url: &'a str,
    pub(crate) namespace: &'a str,
    pub(crate) deployment_id: &'a str,
    pub(crate) deployment_incarnation: &'a str,
    pub(crate) oidc: &'a OidcFixture,
    pub(crate) oidc_jwks_path: &'a Path,
    pub(crate) server_chain_path: &'a Path,
    pub(crate) server_key_path: &'a Path,
    pub(crate) server_ca_path: &'a Path,
    pub(crate) device_ca_path: &'a Path,
    pub(crate) peer_chain_path: &'a Path,
    pub(crate) peer_key_path: &'a Path,
    pub(crate) peer_ca_path: &'a Path,
    pub(crate) signer_trust_path: &'a Path,
    pub(crate) state_path: &'a Path,
    pub(crate) checkpoint_endpoint: &'a str,
    pub(crate) node_id: &'a str,
}

impl ProcessConfigFixture<'_> {
    pub(crate) fn render(&self) -> String {
        format!(
            "consumer_bind = {}\ndevice_bind = {}\noidc_issuer = {}\noidc_audience = [\"agent-tunnel\"]\noidc_jwks_path = {}\nredis_url = {}\nredis_namespace = {}\nredis_tls_root_ca_path = {}\ndevice_tls_cert_chain = {}\ndevice_tls_private_key = {}\ndevice_tls_client_ca = {}\nconsumer_tls_cert_chain = {}\nconsumer_tls_private_key = {}\nnode_id = {}\ndeployment_incarnation = {}\n\n[cluster]\ndeployment_id = {}\npeer_bind = {}\npeer_tls_cert_chain = {}\npeer_tls_private_key = {}\npeer_tls_client_ca = {}\nmembership_signer_trust_path = {}\ncheckpoint_authority_endpoint = {}\ncheckpoint_authority_trust_path = {}\nmembership_version_state_path = {}\nmembership_record_lifetime_seconds = 60\nmembership_refresh_seconds = 20\nmembership_reconcile_seconds = 2\ncheckpoint_timeout_seconds = 2\n\n[cluster.endpoint_policy]\nallowed_hosts = [\"127.0.0.1\"]\nallowed_server_names = [\"localhost\"]\nallowed_ports = [{}]\nrequire_private_ip = true\n",
            toml_string(&self.consumer_bind.to_string()),
            toml_string(&self.device_bind.to_string()),
            toml_string(&self.oidc.issuer),
            toml_path(self.oidc_jwks_path),
            toml_string(self.redis_url),
            toml_string(self.namespace),
            toml_path(self.server_ca_path),
            toml_path(self.server_chain_path),
            toml_path(self.server_key_path),
            toml_path(self.device_ca_path),
            toml_path(self.server_chain_path),
            toml_path(self.server_key_path),
            toml_string(self.node_id),
            toml_string(self.deployment_incarnation),
            toml_string(self.deployment_id),
            toml_string(&self.peer_bind.to_string()),
            toml_path(self.peer_chain_path),
            toml_path(self.peer_key_path),
            toml_path(self.peer_ca_path),
            toml_path(self.signer_trust_path),
            toml_string(self.checkpoint_endpoint),
            toml_path(self.server_ca_path),
            toml_path(self.state_path),
            self.peer_bind.port(),
        )
    }
}

pub(crate) fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("fixture TOML string")
}

pub(crate) fn toml_path(path: &Path) -> String {
    toml_string(path.to_str().expect("fixture path is UTF-8"))
}

pub(crate) fn jwks_json(oidc: &OidcFixture) -> Result<String> {
    let public_key = RsaPublicKey::from_public_key_pem(oidc.public_key_pem())
        .map_err(|error| HarnessError::Pki(format!("reading OIDC public key: {error}")))?;
    Ok(format!(
        "{{\"keys\":[{{\"kid\":{},\"kty\":\"RSA\",\"alg\":\"RS256\",\"n\":{},\"e\":{}}}]}}",
        serde_json::to_string(&oidc.key_id)?,
        serde_json::to_string(&base64_url(&public_key.n().to_bytes_be()))?,
        serde_json::to_string(&base64_url(&public_key.e().to_bytes_be()))?,
    ))
}

pub(crate) fn base64_url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut output = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let first = chunk[0] as usize;
        output.push(ALPHABET[first >> 2] as char);
        let second = if chunk.len() > 1 {
            chunk[1] as usize
        } else {
            0
        };
        output.push(ALPHABET[((first & 3) << 4) | (second >> 4)] as char);
        if chunk.len() > 1 {
            let third = chunk[2] as usize;
            output.push(ALPHABET[((second & 15) << 2) | (third >> 6)] as char);
            if chunk.len() > 2 {
                output.push(ALPHABET[third & 63] as char);
            }
        }
    }
    output
}

pub(crate) fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

pub(crate) fn free_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate process TCP address");
    listener.local_addr().expect("read process TCP address")
}

pub(crate) fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("set process fixture permissions");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

pub(crate) fn parse_plaintext_upstream(redis_url: &str) -> Result<SocketAddr> {
    let info = redis_url
        .into_connection_info()
        .map_err(|error| HarnessError::InvalidRedisUrl {
            message: error.to_string(),
        })?;
    let (host, port) = match info.addr() {
        ConnectionAddr::Tcp(host, port) => (host, *port),
        _ => {
            return Err(HarnessError::InvalidInput(
                "process gate requires a plaintext redis:// TCP upstream".into(),
            ));
        }
    };
    let ip: IpAddr = host.parse().map_err(|error| {
        HarnessError::InvalidInput(format!("Redis upstream must use a loopback IP: {error}"))
    })?;
    let address = SocketAddr::new(ip, port);
    if !address.ip().is_loopback() {
        return Err(HarnessError::InvalidInput(
            "process gate refuses a non-loopback Redis upstream".into(),
        ));
    }
    Ok(address)
}

pub(crate) fn relay_binary_path() -> Result<PathBuf> {
    if let Some(path) = env::var_os("TUNNEL_RELAY_BIN") {
        let path = PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(HarnessError::Process(format!(
            "TUNNEL_RELAY_BIN does not point to a file: {}",
            path.display()
        )));
    }

    let mut candidates = Vec::new();
    if let Ok(current) = env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join("tunnel-relay"));
        candidates.push(parent.join("tunnel-relay.exe"));
        if let Some(target_dir) = parent.parent() {
            candidates.push(target_dir.join("tunnel-relay"));
            candidates.push(target_dir.join("tunnel-relay.exe"));
        }
    }
    candidates.push(PathBuf::from("target/debug/tunnel-relay"));
    candidates.push(PathBuf::from("target/debug/tunnel-relay.exe"));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            HarnessError::Process(
                "built tunnel-relay binary is missing next to the test executable".into(),
            )
        })
}

pub(crate) struct RedisTlsProxy {
    address: SocketAddr,
    handshakes: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl RedisTlsProxy {
    pub(crate) async fn bind(
        upstream: SocketAddr,
        server_config: Arc<rustls::ServerConfig>,
    ) -> Result<Self> {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(run_redis_proxy(
            listener,
            upstream,
            TlsAcceptor::from(server_config),
            cancellation.clone(),
            handshakes.clone(),
        ));
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            handshakes,
            cancellation,
            task: Some(task),
        })
    }

    pub(crate) fn url(&self) -> String {
        format!("rediss://localhost:{}/0", self.address.port())
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        self.shutdown_with_activity(true).await
    }

    pub(crate) async fn shutdown_allow_unused(self) -> Result<()> {
        self.shutdown_with_activity(false).await
    }

    async fn shutdown_with_activity(mut self, require_activity: bool) -> Result<()> {
        self.cancellation.cancel();
        if let Some(mut task) = self.task.take() {
            match timeout(AUXILIARY_SHUTDOWN_DEADLINE, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => return Err(error),
                Ok(Err(error)) => {
                    return Err(HarnessError::Proxy(format!(
                        "Redis TLS proxy supervisor join failed: {error}"
                    )));
                }
                Err(_) => {
                    task.abort();
                    match task.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => {
                            if error.is_cancelled() {
                                return Err(HarnessError::Timeout(
                                    "Redis TLS proxy shutdown".into(),
                                ));
                            }
                            return Err(HarnessError::Proxy(format!(
                                "Redis TLS proxy supervisor join failed after timeout: {error}"
                            )));
                        }
                    }
                    return Err(HarnessError::Timeout("Redis TLS proxy shutdown".into()));
                }
            }
        }
        if require_activity && self.handshakes.load(Ordering::Acquire) == 0 {
            return Err(HarnessError::Proxy(
                "relay never completed a Redis TLS handshake".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for RedisTlsProxy {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            // The supervisor owns the JoinSet. Dropping its aborted task also
            // drops that JoinSet, which aborts every retained connection task.
            task.abort();
        }
    }
}

pub(crate) async fn run_redis_proxy(
    listener: TokioTcpListener,
    upstream: SocketAddr,
    acceptor: TlsAcceptor,
    cancellation: CancellationToken,
    handshakes: Arc<AtomicUsize>,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut active_connections = 0_usize;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                connections.abort_all();
                drain_aborted_connections(&mut connections, "Redis TLS proxy").await?;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        connections.abort_all();
                        drain_aborted_connections(&mut connections, "Redis TLS proxy").await?;
                        return Err(HarnessError::Proxy(format!(
                            "Redis TLS proxy accept failed: {error}"
                        )));
                    }
                };
                if active_connections >= AUXILIARY_CONNECTION_LIMIT {
                    drop(stream);
                    continue;
                }
                let acceptor = acceptor.clone();
                let handshakes = handshakes.clone();
                let cancellation = cancellation.clone();
                connections.spawn(run_redis_connection(
                    stream,
                    upstream,
                    acceptor,
                    handshakes,
                    cancellation,
                ));
                active_connections += 1;
            }
            Some(joined) = connections.join_next(), if active_connections > 0 => {
                active_connections -= 1;
                join_connection(joined, "Redis TLS proxy")?;
            }
        }
    }
}

pub(crate) async fn run_redis_connection(
    stream: TcpStream,
    upstream: SocketAddr,
    acceptor: TlsAcceptor,
    handshakes: Arc<AtomicUsize>,
    cancellation: CancellationToken,
) {
    let _ = timeout(AUXILIARY_CONNECTION_DEADLINE, async move {
        let mut tls = tokio::select! {
            _ = cancellation.cancelled() => return,
            accepted = acceptor.accept(stream) => match accepted {
                Ok(tls) => tls,
                Err(_) => return,
            },
        };
        handshakes.fetch_add(1, Ordering::Release);
        let mut upstream_stream = tokio::select! {
            _ = cancellation.cancelled() => return,
            connected = TcpStream::connect(upstream) => match connected {
                Ok(stream) => stream,
                Err(_) => return,
            },
        };
        tokio::select! {
            _ = cancellation.cancelled() => {}
            _ = tokio::io::copy_bidirectional(&mut tls, &mut upstream_stream) => {}
        }
    })
    .await;
}

pub(crate) fn join_connection(
    joined: std::result::Result<(), tokio::task::JoinError>,
    label: &str,
) -> Result<()> {
    joined.map_err(|error| HarnessError::Proxy(format!("{label} connection task failed: {error}")))
}

pub(crate) async fn drain_aborted_connections(
    connections: &mut JoinSet<()>,
    label: &str,
) -> Result<()> {
    while let Some(joined) = connections.join_next().await {
        if let Err(error) = joined
            && !error.is_cancelled()
        {
            return Err(HarnessError::Proxy(format!(
                "{label} connection task failed during shutdown: {error}"
            )));
        }
    }
    Ok(())
}

#[derive(Deserialize)]
pub(crate) struct WireCheckpointRequest {
    deployment_id: String,
    deployment_incarnation: String,
    nonce: String,
}

pub(crate) struct CheckpointContext {
    authority: Arc<TestMembershipAuthority>,
    deployment_id: String,
    deployment_incarnation: String,
    minimum_versions: BTreeMap<String, u64>,
    version: AtomicU64,
    requests: Arc<AtomicUsize>,
    /// A fixed signing instant reproduces the bounded-lifetime scenarios; a
    /// live signer stamps every response at request time so a longer staged
    /// process test stays within the 60-second record lifetime.
    signing_time: Option<DateTime<Utc>>,
}

pub(crate) struct CheckpointServer {
    address: SocketAddr,
    requests: Arc<AtomicUsize>,
    cancellation: CancellationToken,
    task: Option<tokio::task::JoinHandle<Result<()>>>,
}

impl CheckpointServer {
    pub(crate) async fn bind(
        server_config: Arc<rustls::ServerConfig>,
        authority: Arc<TestMembershipAuthority>,
        deployment_id: String,
        deployment_incarnation: String,
        minimum_versions: BTreeMap<String, u64>,
    ) -> Result<Self> {
        Self::bind_with_signing_time(
            server_config,
            authority,
            deployment_id,
            deployment_incarnation,
            minimum_versions,
            Some(Utc::now()),
        )
        .await
    }

    pub(crate) async fn bind_at(
        server_config: Arc<rustls::ServerConfig>,
        authority: Arc<TestMembershipAuthority>,
        deployment_id: String,
        deployment_incarnation: String,
        minimum_versions: BTreeMap<String, u64>,
        signing_time: DateTime<Utc>,
    ) -> Result<Self> {
        Self::bind_with_signing_time(
            server_config,
            authority,
            deployment_id,
            deployment_incarnation,
            minimum_versions,
            Some(signing_time),
        )
        .await
    }

    /// Bind a checkpoint authority that signs every response at request
    /// time.  Each checkpoint still carries the bounded fixture lifetime and
    /// the caller's nonce; only the issuance instant follows the wall clock,
    /// so a staged multi-phase process test stays inside the 60-second bound.
    pub(crate) async fn bind_live(
        server_config: Arc<rustls::ServerConfig>,
        authority: Arc<TestMembershipAuthority>,
        deployment_id: String,
        deployment_incarnation: String,
        minimum_versions: BTreeMap<String, u64>,
    ) -> Result<Self> {
        Self::bind_with_signing_time(
            server_config,
            authority,
            deployment_id,
            deployment_incarnation,
            minimum_versions,
            None,
        )
        .await
    }

    async fn bind_with_signing_time(
        server_config: Arc<rustls::ServerConfig>,
        authority: Arc<TestMembershipAuthority>,
        deployment_id: String,
        deployment_incarnation: String,
        minimum_versions: BTreeMap<String, u64>,
        signing_time: Option<DateTime<Utc>>,
    ) -> Result<Self> {
        let listener = TokioTcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let requests = Arc::new(AtomicUsize::new(0));
        let context = Arc::new(CheckpointContext {
            authority,
            deployment_id,
            deployment_incarnation,
            minimum_versions,
            version: AtomicU64::new(0),
            requests: requests.clone(),
            signing_time,
        });
        let task = tokio::spawn(run_checkpoint_server(
            listener,
            TlsAcceptor::from(server_config),
            context,
            cancellation.clone(),
        ));
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            requests,
            cancellation,
            task: Some(task),
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    /// Number of signed checkpoints fully written to a relay so far.
    pub(crate) fn request_count(&self) -> usize {
        self.requests.load(Ordering::Acquire)
    }

    pub(crate) async fn shutdown(self) -> Result<()> {
        self.shutdown_with_activity(true).await
    }

    pub(crate) async fn shutdown_allow_unused(self) -> Result<()> {
        self.shutdown_with_activity(false).await
    }

    async fn shutdown_with_activity(mut self, require_activity: bool) -> Result<()> {
        self.cancellation.cancel();
        if let Some(mut task) = self.task.take() {
            match timeout(AUXILIARY_SHUTDOWN_DEADLINE, &mut task).await {
                Ok(Ok(Ok(()))) => {}
                Ok(Ok(Err(error))) => return Err(error),
                Ok(Err(error)) => {
                    return Err(HarnessError::Http(format!(
                        "checkpoint authority supervisor join failed: {error}"
                    )));
                }
                Err(_) => {
                    task.abort();
                    match task.await {
                        Ok(Ok(())) => {}
                        Ok(Err(error)) => return Err(error),
                        Err(error) => {
                            if error.is_cancelled() {
                                return Err(HarnessError::Timeout(
                                    "checkpoint authority shutdown".into(),
                                ));
                            }
                            return Err(HarnessError::Http(format!(
                                "checkpoint authority supervisor join failed after timeout: {error}"
                            )));
                        }
                    }
                    return Err(HarnessError::Timeout(
                        "checkpoint authority shutdown".into(),
                    ));
                }
            }
        }
        if require_activity && self.requests.load(Ordering::Acquire) == 0 {
            return Err(HarnessError::Http(
                "relay never completed an HTTPS checkpoint request".into(),
            ));
        }
        Ok(())
    }
}

impl Drop for CheckpointServer {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            // The supervisor owns the JoinSet. Dropping its aborted task also
            // drops that JoinSet, which aborts every retained connection task.
            task.abort();
        }
    }
}

pub(crate) async fn run_checkpoint_server(
    listener: TokioTcpListener,
    acceptor: TlsAcceptor,
    context: Arc<CheckpointContext>,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut connections = JoinSet::new();
    let mut active_connections = 0_usize;
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => {
                connections.abort_all();
                drain_aborted_connections(&mut connections, "checkpoint authority").await?;
                return Ok(());
            }
            accepted = listener.accept() => {
                let (stream, _) = match accepted {
                    Ok(accepted) => accepted,
                    Err(error) => {
                        connections.abort_all();
                        drain_aborted_connections(&mut connections, "checkpoint authority").await?;
                        return Err(HarnessError::Http(format!(
                            "checkpoint authority accept failed: {error}"
                        )));
                    }
                };
                if active_connections >= AUXILIARY_CONNECTION_LIMIT {
                    drop(stream);
                    continue;
                }
                let acceptor = acceptor.clone();
                let context = context.clone();
                let cancellation = cancellation.clone();
                connections.spawn(run_checkpoint_connection(
                    stream,
                    acceptor,
                    context,
                    cancellation,
                ));
                active_connections += 1;
            }
            Some(joined) = connections.join_next(), if active_connections > 0 => {
                active_connections -= 1;
                join_connection(joined, "checkpoint authority")?;
            }
        }
    }
}

pub(crate) async fn run_checkpoint_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    context: Arc<CheckpointContext>,
    cancellation: CancellationToken,
) {
    let _ = timeout(AUXILIARY_CONNECTION_DEADLINE, async move {
        let mut tls = tokio::select! {
            _ = cancellation.cancelled() => return,
            accepted = acceptor.accept(stream) => match accepted {
                Ok(tls) => tls,
                Err(_) => return,
            },
        };
        let body = tokio::select! {
            _ = cancellation.cancelled() => return,
            body = read_http_body(&mut tls) => match body {
                Ok(body) => body,
                Err(_) => return,
            },
        };
        let Ok(request) = serde_json::from_slice::<WireCheckpointRequest>(&body) else {
            return;
        };
        if request.deployment_id != context.deployment_id
            || request.deployment_incarnation != context.deployment_incarnation
        {
            return;
        }
        let next_version = context.version.fetch_add(1, Ordering::Relaxed) + 1;
        let Ok(checkpoint) = context.authority.sign_checkpoint_with_version(
            &context.deployment_id,
            &context.deployment_incarnation,
            next_version,
            request.nonce,
            context.minimum_versions.clone(),
            context.signing_time.unwrap_or_else(Utc::now),
        ) else {
            return;
        };
        let bytes = checkpoint.encoded_bytes().to_vec();
        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            bytes.len()
        );
        let response_result = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = tls.write_all(response.as_bytes()) => result,
        };
        if response_result.is_err() {
            return;
        }
        let body_result = tokio::select! {
            _ = cancellation.cancelled() => return,
            result = tls.write_all(&bytes) => result,
        };
        if body_result.is_ok() {
            context.requests.fetch_add(1, Ordering::Release);
        }
        tokio::select! {
            _ = cancellation.cancelled() => {}
            _ = tls.shutdown() => {}
        }
    })
    .await;
}

pub(crate) async fn read_http_body<S>(stream: &mut S) -> io::Result<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = Vec::new();
    let mut chunk = [0_u8; 4096];
    loop {
        if let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") {
            let body_start = header_end + 4;
            let headers = std::str::from_utf8(&bytes[..header_end])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "request headers"))?;
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length").then_some(value)
                })
                .and_then(|value| value.trim().parse::<usize>().ok())
                .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "content length"))?;
            if content_length > HTTP_REQUEST_MAX
                || body_start.saturating_add(content_length) > HTTP_REQUEST_MAX
            {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "request too large",
                ));
            }
            let total = body_start + content_length;
            while bytes.len() < total {
                let read = stream.read(&mut chunk).await?;
                if read == 0 {
                    return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "request body"));
                }
                bytes.extend_from_slice(&chunk[..read]);
                if bytes.len() > HTTP_REQUEST_MAX {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "request too large",
                    ));
                }
            }
            return Ok(bytes[body_start..total].to_vec());
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "request headers",
            ));
        }
        bytes.extend_from_slice(&chunk[..read]);
        if bytes.len() > HTTP_REQUEST_MAX {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "request too large",
            ));
        }
    }
}
