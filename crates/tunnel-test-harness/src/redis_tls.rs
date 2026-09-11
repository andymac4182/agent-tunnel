//! Live Redis TLS verification against the production catalog connection.
//!
//! The dedicated Redis service remains plaintext on loopback. This fixture
//! terminates a synthetic TLS/mTLS connection and forwards bounded RESP bytes
//! to that service, so `RedisCatalog::connect_with_tls` performs the actual
//! redis-rs `rediss://` handshake and PING/INFO exchange. It is deliberately
//! separate from the ordinary plaintext Redis lease and never mutates the
//! Redis catalog.

use crate::{FixturePki, HarnessError, Result};
use redis::{ConnectionAddr, IntoConnectionInfo};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout},
};
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{RedisCatalog, RedisTlsOptions};
use uuid::Uuid;

const FORWARD_CONNECTION_LIMIT: usize = 8;
const FORWARD_DEADLINE: Duration = Duration::from_secs(5);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(2);

/// Results from the live TLS catalog probe.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisTlsEvidence {
    pub authenticated_catalog_connection: bool,
    pub wrong_ca_rejected: bool,
    pub wrong_server_name_rejected: bool,
    pub wrong_client_identity_rejected: bool,
}

/// Run the bounded TLS/mTLS Redis probe against a plaintext loopback Redis
/// URL. A fresh namespace is used for every catalog connection attempt.
pub async fn verify(redis_url: &str) -> Result<RedisTlsEvidence> {
    let upstream = parse_plaintext_upstream(redis_url)?;
    let pki = FixturePki::new()?;
    let server = pki
        .issue_server("redis-tls-forwarder")
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let client = pki
        .issue_peer("redis-tls-client")
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let server_chain = format!(
        "{}{}",
        server.certificate_pem, pki.server_ca.certificate_pem
    );
    let server_tls = tunnel_transport::load_server_config_from_pem(
        server_chain.as_bytes(),
        server.private_key_pem.as_bytes(),
        Some(pki.peer_ca.certificate_pem.as_bytes()),
    )
    .map_err(|error| HarnessError::Pki(format!("building Redis TLS forwarder: {error}")))?;
    let forwarder = RedisTlsForwarder::bind(upstream, server_tls).await?;
    crate::c11_capture::record_sentinel("credential", client.private_key_pem.as_bytes())?;

    let cases = run_cases(&pki, &client, &forwarder).await;
    let cleanup = forwarder.shutdown().await;
    match (cases, cleanup) {
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Ok(evidence), Ok(())) => Ok(evidence),
    }
}

async fn run_cases(
    pki: &FixturePki,
    client: &crate::CertificateMaterial,
    forwarder: &RedisTlsForwarder,
) -> Result<RedisTlsEvidence> {
    let valid_tls =
        RedisTlsOptions::with_root_cert_pem(pki.server_ca.certificate_pem.as_bytes().to_vec())
            .with_client_identity_pem(
                client.certificate_pem.as_bytes().to_vec(),
                client.private_key_pem.as_bytes().to_vec(),
            );
    let valid_url = format!("rediss://localhost:{}/0", forwarder.addr().port());
    connect_catalog(&valid_url, &valid_tls, "successful Redis TLS connection").await?;

    let wrong_ca_pki = FixturePki::new()?;
    let wrong_ca = RedisTlsOptions::with_root_cert_pem(
        wrong_ca_pki.server_ca.certificate_pem.as_bytes().to_vec(),
    )
    .with_client_identity_pem(
        client.certificate_pem.as_bytes().to_vec(),
        client.private_key_pem.as_bytes().to_vec(),
    );
    let wrong_ca_rejected =
        expect_rejected(forwarder, &valid_url, &wrong_ca, "wrong Redis server CA").await?;

    let wrong_name_url = format!("rediss://127.0.0.1:{}/0", forwarder.addr().port());
    let wrong_server_name_rejected = expect_rejected(
        forwarder,
        &wrong_name_url,
        &valid_tls,
        "wrong Redis server name",
    )
    .await?;

    let wrong_client_pki = FixturePki::new()?;
    let wrong_client = wrong_client_pki
        .issue_peer("wrong-redis-tls-client")
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let wrong_client_identity =
        RedisTlsOptions::with_root_cert_pem(pki.server_ca.certificate_pem.as_bytes().to_vec())
            .with_client_identity_pem(
                wrong_client.certificate_pem.as_bytes().to_vec(),
                wrong_client.private_key_pem.as_bytes().to_vec(),
            );
    let wrong_client_identity_rejected = expect_rejected(
        forwarder,
        &valid_url,
        &wrong_client_identity,
        "wrong Redis client identity",
    )
    .await?;

    connect_catalog(
        &valid_url,
        &valid_tls,
        "trusted Redis TLS connection after rejection cases",
    )
    .await?;

    Ok(RedisTlsEvidence {
        authenticated_catalog_connection: true,
        wrong_ca_rejected,
        wrong_server_name_rejected,
        wrong_client_identity_rejected,
    })
}

async fn connect_catalog(
    redis_url: &str,
    tls: &RedisTlsOptions,
    label: &str,
) -> Result<RedisCatalog> {
    let namespace = format!("test-redis-tls-{}", Uuid::new_v4());
    timeout(
        FORWARD_DEADLINE,
        RedisCatalog::connect_with_tls(redis_url, &namespace, tls.clone()),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{label} exceeded five seconds")))?
    .map_err(|error| HarnessError::Redis(format!("{label}: {error:?}")))
}

async fn expect_rejected(
    forwarder: &RedisTlsForwarder,
    redis_url: &str,
    tls: &RedisTlsOptions,
    label: &str,
) -> Result<bool> {
    let baseline = forwarder.handshake_snapshot();
    match connect_catalog(redis_url, tls, label).await {
        Ok(_) => Err(HarnessError::Process(format!(
            "{label} unexpectedly completed a Redis TLS connection"
        ))),
        Err(HarnessError::Redis(_)) => {
            forwarder
                .wait_for_handshake_rejection(baseline, label)
                .await?;
            Ok(true)
        }
        Err(HarnessError::Timeout(message)) => {
            Err(HarnessError::Timeout(format!("{label}: {message}")))
        }
        Err(error) => Err(HarnessError::Process(format!(
            "{label} failed before Redis TLS reported a rejection: {error}"
        ))),
    }
}

fn parse_plaintext_upstream(redis_url: &str) -> Result<SocketAddr> {
    let info = redis_url
        .into_connection_info()
        .map_err(|error| HarnessError::InvalidRedisUrl {
            message: error.to_string(),
        })?;
    let (host, port) = match info.addr() {
        ConnectionAddr::Tcp(host, port) => (host, port),
        _ => {
            return Err(HarnessError::InvalidInput(
                "Redis TLS fixture requires a plaintext redis:// TCP upstream".to_owned(),
            ));
        }
    };
    let ip = host.parse().map_err(|error| {
        HarnessError::InvalidInput(format!(
            "Redis TLS fixture requires a loopback IP upstream: {error}"
        ))
    })?;
    let address = SocketAddr::new(ip, *port);
    if !address.ip().is_loopback() {
        return Err(HarnessError::InvalidInput(
            "Redis TLS fixture refuses a non-loopback upstream".to_owned(),
        ));
    }
    Ok(address)
}

struct RedisTlsForwarder {
    address: SocketAddr,
    cancellation: CancellationToken,
    stats: Arc<RedisTlsForwarderStats>,
    task: Option<JoinHandle<()>>,
}

#[derive(Default)]
struct RedisTlsForwarderStats {
    handshake_completed: AtomicUsize,
    handshake_rejected: AtomicUsize,
}

#[derive(Clone, Copy)]
struct HandshakeSnapshot {
    completed: usize,
    rejected: usize,
}

impl RedisTlsForwarder {
    async fn bind(upstream: SocketAddr, server_tls: Arc<rustls::ServerConfig>) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
        let address = listener.local_addr()?;
        let target_text = upstream.to_string();
        let local_text = address.to_string();
        crate::c11_capture::record_sentinel("private_endpoint", target_text.as_bytes())?;
        crate::c11_capture::record_sentinel("private_endpoint", local_text.as_bytes())?;
        let cancellation = CancellationToken::new();
        let task_cancellation = cancellation.clone();
        let acceptor = TlsAcceptor::from(server_tls);
        let stats = Arc::new(RedisTlsForwarderStats::default());
        let task_stats = Arc::clone(&stats);
        let task = tokio::spawn(async move {
            run_forwarder(listener, acceptor, upstream, task_cancellation, task_stats).await;
        });
        // Give the listener task one scheduler turn before the first client
        // dial. Binding already reserves the port; this only makes startup
        // diagnostics deterministic without an unbounded readiness wait.
        sleep(Duration::from_millis(1)).await;
        Ok(Self {
            address,
            cancellation,
            stats,
            task: Some(task),
        })
    }

    fn addr(&self) -> SocketAddr {
        self.address
    }

    fn handshake_snapshot(&self) -> HandshakeSnapshot {
        HandshakeSnapshot {
            completed: self.stats.handshake_completed.load(Ordering::Acquire),
            rejected: self.stats.handshake_rejected.load(Ordering::Acquire),
        }
    }

    async fn wait_for_handshake_rejection(
        &self,
        baseline: HandshakeSnapshot,
        label: &str,
    ) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let current = self.handshake_snapshot();
            if current.rejected > baseline.rejected {
                return Ok(());
            }
            if current.completed > baseline.completed {
                return Err(HarnessError::Process(format!(
                    "{label} reached the forwarder without a TLS handshake rejection"
                )));
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "{label} did not produce a TLS handshake rejection"
                )));
            }
            sleep(Duration::from_millis(1)).await;
        }
    }

    async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(SHUTDOWN_DEADLINE, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(HarnessError::Process(format!(
                "Redis TLS forwarder task failed: {error}"
            ))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(HarnessError::Timeout(
                    "Redis TLS forwarder shutdown exceeded two seconds".to_owned(),
                ))
            }
        }
    }
}

impl Drop for RedisTlsForwarder {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_forwarder(
    listener: TcpListener,
    acceptor: TlsAcceptor,
    upstream: SocketAddr,
    cancellation: CancellationToken,
    stats: Arc<RedisTlsForwarderStats>,
) {
    let permits = Arc::new(tokio::sync::Semaphore::new(FORWARD_CONNECTION_LIMIT));
    let mut workers = JoinSet::new();
    loop {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            Some(_) = workers.join_next(), if !workers.is_empty() => {}
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else { break };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else { continue };
                let acceptor = acceptor.clone();
                let stats = Arc::clone(&stats);
                workers.spawn(async move {
                    let _permit = permit;
                    forward_connection(stream, acceptor, upstream, stats).await;
                });
            }
        }
    }
    workers.abort_all();
    while workers.join_next().await.is_some() {}
}

async fn forward_connection(
    stream: TcpStream,
    acceptor: TlsAcceptor,
    upstream: SocketAddr,
    stats: Arc<RedisTlsForwarderStats>,
) {
    let Ok(Ok(mut tls_stream)) = timeout(FORWARD_DEADLINE, acceptor.accept(stream)).await else {
        stats.handshake_rejected.fetch_add(1, Ordering::Release);
        return;
    };
    stats.handshake_completed.fetch_add(1, Ordering::Release);
    let Ok(Ok(mut upstream_stream)) = timeout(FORWARD_DEADLINE, TcpStream::connect(upstream)).await
    else {
        return;
    };
    let _ = timeout(
        FORWARD_DEADLINE,
        tokio::io::copy_bidirectional(&mut tls_stream, &mut upstream_stream),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::verify;

    /// Run explicitly with the dedicated plaintext Redis service. The test is
    /// ignored by the ordinary workspace suite because Redis is external.
    #[tokio::test]
    #[ignore = "requires the dedicated loopback Redis service"]
    async fn live_rediss_catalog_handshake_and_rejections() {
        let redis_url = std::env::var("TEST_REDIS_URL")
            .unwrap_or_else(|_| "redis://127.0.0.1:60278/".to_owned());
        let evidence = verify(&redis_url).await.expect("Redis TLS evidence");
        assert!(evidence.authenticated_catalog_connection);
        assert!(evidence.wrong_ca_rejected);
        assert!(evidence.wrong_server_name_rejected);
        assert!(evidence.wrong_client_identity_rejected);
    }
}
