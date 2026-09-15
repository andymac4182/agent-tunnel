//! The device adapter serves an exchange without any inbound local listener.
//!
//! This test lives in its own binary so no concurrent test can open sockets.
//! Two independent checks would each fail if a listener were introduced:
//!
//! 1. The exchange runs on a Tokio runtime built *without* the I/O driver.
//!    Any `tokio::net` listener or socket panics on such a runtime
//!    ("A Tokio 1.x context was found, but IO is disabled").
//! 2. Every open file descriptor of the process is classified with
//!    `fstat` via `/dev/fd`, and the number of sockets is compared before,
//!    during (inside the handler) and after the exchange.  This also catches
//!    a blocking `std::net` or Unix-domain listener.  A positive control
//!    first proves the detector counts a freshly created socket.
//!
//! The adapter API itself takes no address: `serve` receives frame queues and
//! calls the handler directly.

mod common;

use std::os::unix::fs::FileTypeExt;
use std::os::unix::net::UnixDatagram;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use common::*;
use http::{Request, Response, StatusCode};
use tunnel_http_bridge::{BridgeConfig, ChannelBody, Outcome, forward, serve};

fn open_sockets() -> usize {
    (0..4096)
        .filter(|fd| {
            std::fs::metadata(format!("/dev/fd/{fd}"))
                .is_ok_and(|metadata| metadata.file_type().is_socket())
        })
        .count()
}

#[test]
fn device_adapter_serves_without_opening_any_socket() {
    let baseline = open_sockets();
    let control = UnixDatagram::unbound().expect("create an unbound control socket");
    assert_eq!(open_sockets(), baseline + 1, "the detector sees sockets");
    drop(control);
    assert_eq!(open_sockets(), baseline);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_time()
        .build()
        .unwrap();
    let during = Arc::new(AtomicUsize::new(usize::MAX));
    let handler_during = Arc::clone(&during);
    runtime.block_on(async move {
        let Link {
            to_device,
            device_rx,
            to_owner,
            owner_rx,
            ..
        } = link(STREAM_CREDIT);
        let device = tokio::spawn(serve(
            profile(),
            BridgeConfig::default(),
            device_rx,
            to_owner,
            move |request: Request<ChannelBody>| async move {
                handler_during.store(open_sockets(), Ordering::SeqCst);
                let body = collect(request.into_body()).await.unwrap();
                Ok::<_, TestError>(Response::new(full(&body)))
            },
        ));
        let (response, handle) = forward(
            request("POST", "/echo", &[], full(b"in-process")),
            profile(),
            BridgeConfig::default(),
            to_device,
            owner_rx,
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(collect(response.into_body()).await.unwrap(), b"in-process");
        assert_eq!(handle.report().await.response, Outcome::Complete);
        assert_eq!(device.await.unwrap().response, Outcome::Complete);
    });
    assert_eq!(
        during.load(Ordering::SeqCst),
        baseline,
        "no socket was open while the handler ran"
    );
    assert_eq!(open_sockets(), baseline);
}
