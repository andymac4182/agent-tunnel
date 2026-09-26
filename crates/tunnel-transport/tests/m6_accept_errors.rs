//! M6-C155: descriptor exhaustion at `accept` does not end the listener.
//!
//! Before the fix any `accept` error ended `serve_with_listener_options`, so an
//! `EMFILE` under a connection flood made the relay exit.  This test lowers the
//! process's soft descriptor limit, fills it, and connects: the listener's
//! `accept` fails with `EMFILE`.  The listener must still be running, and must
//! serve a new connection once descriptors are free again.  It is a
//! separate test binary because the descriptor limit is process-wide.
#![cfg(unix)]

use std::{sync::Arc, time::Duration};

use axum::{Router, routing::get};
use rcgen::{CertificateParams, KeyPair, SanType};
use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    AcceptedSocketOptions, ListenerTimeouts, require_root_certificates, serve_with_listener_options,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Restores the soft descriptor limit when the test ends, pass or fail.
struct RestoreLimit(Rlimit);

impl Drop for RestoreLimit {
    fn drop(&mut self) {
        let _ = setrlimit(Resource::Nofile, self.0);
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn descriptor_exhaustion_at_accept_does_not_end_the_listener() -> TestResult {
    let key = KeyPair::generate()?;
    let mut params = CertificateParams::default();
    params
        .subject_alt_names
        .push(SanType::DnsName("localhost".try_into()?));
    let certificate = params.self_signed(&key)?;
    let server_config = tunnel_transport::load_server_config_from_pem(
        certificate.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        None,
    )?;
    let mut client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_root_certificates(require_root_certificates(certificate.pem().as_bytes())?)
    .with_no_client_auth();
    client_config.alpn_protocols = vec![b"http/1.1".to_vec()];

    let listener = TcpListener::bind(("127.0.0.1", 0)).await?;
    let address = listener.local_addr()?;
    let cancel = CancellationToken::new();
    let server = tokio::spawn(serve_with_listener_options(
        listener,
        Router::new().route("/quick", get(|| async { "quick-ok" })),
        server_config,
        cancel.clone(),
        AcceptedSocketOptions::default(),
        ListenerTimeouts::default(),
    ));

    let original = getrlimit(Resource::Nofile);
    let restore = RestoreLimit(original);
    setrlimit(
        Resource::Nofile,
        Rlimit {
            current: Some(256),
            maximum: original.maximum,
        },
    )?;
    // Fill every free descriptor, then free exactly one for the client.
    let mut fillers = Vec::new();
    loop {
        match std::fs::File::open("/dev/null") {
            Ok(file) => fillers.push(file),
            Err(error) if error.raw_os_error() == Some(rustix::io::Errno::MFILE.raw_os_error()) => {
                break;
            }
            Err(error) => return Err(error.into()),
        }
        assert!(fillers.len() < 4096, "the descriptor limit did not apply");
    }
    fillers.pop();
    let tcp = TcpStream::connect(address).await?;

    // The listener's accept now fails with EMFILE; it must keep running.
    tokio::time::sleep(Duration::from_millis(600)).await;
    let still_serving = !server.is_finished();
    fillers.clear();
    drop(restore);
    if !still_serving {
        let result = server.await?;
        panic!("the listener ended on EMFILE at accept: {result:?}");
    }

    // With descriptors free again, the listener serves.  The connection whose
    // accept failed is not asserted on: Linux leaves it queued, while macOS
    // (XNU) dequeues it before allocating the descriptor and closes it when
    // that fails, so its client sees end of stream.  Either way the listener
    // must still be accepting.
    drop(tcp);
    let tcp = TcpStream::connect(address).await?;
    let mut tls = timeout(
        Duration::from_secs(10),
        TlsConnector::from(Arc::new(client_config)).connect("localhost".try_into()?, tcp),
    )
    .await
    .map_err(|_| "a new connection was never accepted after EMFILE")??;
    tls.write_all(b"GET /quick HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await?;
    let mut response = Vec::new();
    timeout(Duration::from_secs(10), tls.read_to_end(&mut response))
        .await
        .map_err(|_| "the new connection got no response")??;
    let response = String::from_utf8_lossy(&response);
    assert!(
        response.starts_with("HTTP/1.1 200") && response.contains("quick-ok"),
        "the new connection was not served: {response}"
    );

    cancel.cancel();
    timeout(Duration::from_secs(10), server).await???;
    Ok(())
}
