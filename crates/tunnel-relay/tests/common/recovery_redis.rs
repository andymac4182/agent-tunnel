//! Shared Redis fixtures for recovery integration tests.
//!
//! The relay's recovery configuration requires TLS for Redis.  These tests
//! keep their catalog and raw RESP setup on the operator supplied plaintext
//! loopback Redis, then use this bounded local TLS forwarder for actual relay
//! CLI calls.  The forwarder only transports bytes and does not implement a
//! second catalog or alter the upstream state.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    sync::{Semaphore, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_rustls::TlsAcceptor;

const CONNECTION_LIMIT: usize = 8;
const CONNECTION_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(5);

/// A bounded TLS listener that forwards to the operator supplied Redis.
pub struct RedisTlsForwarder {
    pub url: String,
    pub root_ca: PathBuf,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl RedisTlsForwarder {
    /// Start a local `rediss://` endpoint forwarding to `upstream_url`.
    ///
    /// `root_ca` must be inside the caller's private, canonicalized test
    /// directory.  The generated CA is written with private-file permissions.
    pub async fn start(upstream_url: &str, root_ca: PathBuf) -> Self {
        let ca_key = KeyPair::generate().expect("Redis TLS forwarder CA key");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "recovery Redis TLS CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("self-sign Redis TLS forwarder CA");

        let server_key = KeyPair::generate().expect("Redis TLS forwarder server key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("Redis TLS server params");
        server_params
            .distinguished_name
            .push(DnType::CommonName, "recovery Redis TLS server");
        server_params.subject_alt_names.push(SanType::IpAddress(
            "127.0.0.1".parse().expect("Redis TLS forwarder IP SAN"),
        ));
        server_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("sign Redis TLS forwarder server certificate");

        write_private_file(&root_ca, ca.pem().as_bytes());
        let server_chain = format!("{}{}", server.pem(), ca.pem());
        let server_config = tunnel_transport::load_server_config_from_pem(
            server_chain.as_bytes(),
            server_key.serialize_pem().as_bytes(),
            None,
        )
        .expect("build Redis TLS forwarder server configuration");

        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind Redis TLS forwarder");
        let address = listener.local_addr().expect("Redis TLS forwarder address");
        let (stop, stop_rx) = oneshot::channel();
        let upstream = upstream_address(upstream_url);
        let task = tokio::spawn(run_forwarder(
            listener,
            TlsAcceptor::from(server_config),
            upstream,
            stop_rx,
        ));
        Self {
            url: format!("rediss://127.0.0.1:{}/0", address.port()),
            root_ca,
            stop: Some(stop),
            task: Some(task),
        }
    }

    pub async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(mut task) = self.task.take() else {
            return;
        };
        match timeout(SHUTDOWN_DEADLINE, &mut task).await {
            Ok(result) => result.expect("Redis TLS forwarder task"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("Redis TLS forwarder shutdown deadline");
            }
        }
    }
}

impl Drop for RedisTlsForwarder {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

fn upstream_address(url: &str) -> String {
    let rest = url
        .strip_prefix("redis://")
        .expect("recovery TLS forwarder requires redis:// upstream");
    assert!(
        !rest.contains('@'),
        "recovery TLS forwarder requires an unauthenticated Redis URL"
    );
    let authority = rest.split('/').next().expect("Redis authority");
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once(']')
            .and_then(|(host, remainder)| remainder.strip_prefix(':').map(|port| (host, port)))
            .unwrap_or((bracketed.trim_end_matches(']'), "6379"));
        format!("[{host}]:{port}")
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        format!("{host}:{port}")
    } else {
        format!("{authority}:6379")
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write private Redis TLS CA");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private Redis TLS CA mode");
    }
}

async fn run_forwarder(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: String,
    mut stop: oneshot::Receiver<()>,
) {
    let permits = Arc::new(Semaphore::new(CONNECTION_LIMIT));
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            Some(_) = workers.join_next(), if !workers.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { break };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                let acceptor = acceptor.clone();
                let upstream = upstream.clone();
                workers.spawn(async move {
                    let _permit = permit;
                    forward_connection(stream, acceptor, upstream).await;
                });
            }
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

async fn forward_connection(stream: TcpStream, acceptor: TlsAcceptor, upstream: String) {
    let Ok(Ok(mut tls_stream)) = timeout(CONNECTION_DEADLINE, acceptor.accept(stream)).await else {
        return;
    };
    let Ok(Ok(mut upstream_stream)) =
        timeout(CONNECTION_DEADLINE, TcpStream::connect(upstream)).await
    else {
        return;
    };
    let _ = timeout(
        CONNECTION_DEADLINE,
        copy_bidirectional(&mut tls_stream, &mut upstream_stream),
    )
    .await;
}
