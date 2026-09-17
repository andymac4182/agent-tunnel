//! Shared in-process plumbing for the M8 chunk 3 bridge tests.
//!
//! A loopback **HTTP/2** gateway fronts the gate-2 bridge: every request it
//! accepts is normalized by `tunnel_http_bridge::forward`, carried over a pair
//! of bounded frame queues, decoded by `tunnel_http_bridge::serve` and handed
//! to the ACP export's in-process handler.  The listener is the *host* side of
//! the conversation — the thing a relay ingress would be — and the device side
//! has no listener at all, which `tests/no_listener.rs` measures on the
//! process's own socket table.
//!
//! HTTP/2 is not a convenience here: the pinned profile accepts HTTP/2 only
//! (`tunnel_acp`, from the transport RFD), so the gateway speaks h2 with prior
//! knowledge and the pinned client is built the same way.
//!
//! Every response body the gateway returns passes through [`Tap`], which
//! records the bytes **at the transport**, in arrival order, before any client
//! handler sees them.  That is the only place wire order can honestly be
//! observed: M3-03 recorded rmcp delivering a client's notification handlers
//! out of order while the wire was intact, and the same hazard applies to any
//! SDK that runs handlers concurrently.

#![allow(dead_code)]

use std::convert::Infallible;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http::{Request, Response};
use http_body::{Body, Frame, SizeHint};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tunnel_acp_export::{AcpExport, AcpExportConfig};
use tunnel_http_bridge::{BridgeConfig, ChannelBody, Profile, channel, forward, serve};

pub const TIMEOUT: Duration = Duration::from_secs(30);
/// One logical stream's byte credit for a test exchange.
pub const STREAM_CREDIT: usize = 1 << 20;

pub async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(TIMEOUT, future)
        .await
        .expect("step timed out")
}

#[must_use]
pub fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-acp-fixture"))
}

/// An ACP export running the synthetic fixture agent in `workspace`.
#[must_use]
pub fn acp_export(workspace: &Path) -> AcpExport {
    acp_export_with(workspace, "")
}

/// An ACP export with extra top-level configuration lines (deadline
/// overrides, limits).
#[must_use]
pub fn acp_export_with(workspace: &Path, extra: &str) -> AcpExport {
    let text = format!(
        "profile = \"acp-http-v1\"\n{extra}[agent]\ncommand = \"{}\"\nargs = [\"agent\"]\nworkspace = \"{}\"\n",
        fixture_binary().display(),
        workspace.display(),
    );
    let config: AcpExportConfig = toml::from_str(&text).expect("export config");
    AcpExport::from_config(&config).expect("valid acp export")
}

/// A body that records every byte it yields, in the order it yields them.
pub struct Tap<B> {
    inner: B,
    log: Arc<Mutex<Vec<u8>>>,
}

impl<B> Tap<B> {
    pub fn new(inner: B, log: Arc<Mutex<Vec<u8>>>) -> Self {
        Self { inner, log }
    }
}

impl<B> Body for Tap<B>
where
    B: Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(data) = frame.data_ref()
        {
            self.log
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .extend_from_slice(data);
        }
        polled
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

/// One recorded exchange: the label it was opened under and its bytes.
type RecordedStream = (String, Arc<Mutex<Vec<u8>>>);

/// What the gateway recorded at the transport, keyed by the exchange it
/// belonged to.
#[derive(Clone, Debug, Default)]
pub struct WireLog {
    streams: Arc<Mutex<Vec<RecordedStream>>>,
}

impl WireLog {
    fn open(&self, label: String) -> Arc<Mutex<Vec<u8>>> {
        let log = Arc::new(Mutex::new(Vec::new()));
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .push((label, Arc::clone(&log)));
        log
    }

    /// The recorded bytes of every exchange whose label contains `needle`.
    #[must_use]
    pub fn bytes(&self, needle: &str) -> Vec<Vec<u8>> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(label, _)| label.contains(needle))
            .map(|(_, log)| {
                log.lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
            })
            .collect()
    }

    #[must_use]
    pub fn labels(&self) -> Vec<String> {
        self.streams
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(label, _)| label.clone())
            .collect()
    }
}

/// Split a recorded SSE stream into its `data:` payloads, in arrival order.
///
/// Deliberately strict: the encoding this profile emits is exactly
/// `data: <compact>\n\n`, so anything else is a difference worth failing on
/// rather than tolerating.
#[must_use]
pub fn sse_payloads(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut payloads = Vec::new();
    let mut rest = bytes;
    while !rest.is_empty() {
        let Some(stripped) = rest.strip_prefix(b"data: ") else {
            break;
        };
        // A stream cut mid-event has no terminator: report what is there
        // rather than silently dropping it, so a truncated stream is visible
        // to the caller instead of looking like a shorter intact one.
        let Some(end) = stripped.windows(2).position(|window| window == b"\n\n") else {
            payloads.push(stripped.to_vec());
            break;
        };
        payloads.push(stripped[..end].to_vec());
        rest = &stripped[end + 2..];
    }
    payloads
}

/// A stable digest over messages **in arrival order**.
///
/// The point of hashing rather than comparing sets is that a reordering
/// changes the value.  A multiset comparison would not, which is exactly the
/// mistake M3-03 recorded.
#[must_use]
pub fn order_digest(messages: &[Vec<u8>]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for message in messages {
        for byte in message {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

pub struct Gateway {
    pub address: SocketAddr,
    pub wire: WireLog,
    shutdown: CancellationToken,
}

impl Gateway {
    #[must_use]
    pub fn endpoint(&self) -> String {
        format!("http://{}/acp", self.address)
    }
}

impl Drop for Gateway {
    fn drop(&mut self) {
        self.shutdown.cancel();
    }
}

/// Forward one request through the in-process bridge to `export`.
pub async fn exchange<B>(
    export: &AcpExport,
    profile: Arc<Profile>,
    request: Request<B>,
) -> Response<ChannelBody>
where
    B: http_body::Body<Data = Bytes> + Send + 'static,
{
    let (to_device, from_owner, _) = channel(STREAM_CREDIT);
    let (to_owner, from_device, _) = channel(STREAM_CREDIT);
    let device_export = export.clone();
    tokio::spawn(serve(
        Arc::clone(&profile),
        BridgeConfig::default(),
        from_owner,
        to_owner,
        move |request: Request<ChannelBody>| async move { device_export.handle(request).await },
    ));
    let (response, _handle) = forward(
        request,
        profile,
        BridgeConfig::default(),
        to_device,
        from_device,
    )
    .await;
    response
}

/// Serve the bridge on a loopback HTTP/2 listener.
///
/// The listener belongs to the **test**, standing in for the relay ingress.
/// The device side of the bridge has no listener, which is the claim
/// `no_listener.rs` measures.
pub fn gateway(export: AcpExport) -> Gateway {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind loopback");
    listener.set_nonblocking(true).expect("nonblocking");
    let address = listener.local_addr().expect("address");
    let listener = TcpListener::from_std(listener).expect("tokio listener");
    let shutdown = CancellationToken::new();
    let stop = shutdown.clone();
    let wire = WireLog::default();
    let recorder = wire.clone();
    let profile = Arc::new(export.profile_policies().expect("profile"));
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                () = stop.cancelled() => return,
                accepted = listener.accept() => accepted,
            };
            let Ok((stream, _)) = accepted else { return };
            let export = export.clone();
            let profile = Arc::clone(&profile);
            let recorder = recorder.clone();
            tokio::spawn(async move {
                let service = service_fn(move |request: Request<Incoming>| {
                    let export = export.clone();
                    let profile = Arc::clone(&profile);
                    let recorder = recorder.clone();
                    async move {
                        let label = format!(
                            "{} {}",
                            request.method(),
                            request
                                .headers()
                                .get(tunnel_acp::headers::ACP_SESSION_ID)
                                .and_then(|value| value.to_str().ok())
                                .map_or_else(|| "connection".to_owned(), str::to_owned),
                        );
                        let response = exchange(&export, profile, request).await;
                        let log = recorder.open(label);
                        let (parts, body) = response.into_parts();
                        Ok::<_, Infallible>(Response::from_parts(parts, Tap::new(body, log)))
                    }
                });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            });
        }
    });
    Gateway {
        address,
        wire,
        shutdown,
    }
}

/// A `reqwest` client that speaks HTTP/2 with prior knowledge, which is what
/// this profile's cleartext HTTP/2-only rule requires of a consumer.
#[must_use]
pub fn http2_client() -> reqwest::Client {
    reqwest::Client::builder()
        .http2_prior_knowledge()
        .build()
        .expect("an http/2 client")
}

pub async fn body_text(response: Response<ChannelBody>) -> String {
    use http_body_util::BodyExt;
    let collected = within(response.into_body().collect())
        .await
        .map(http_body_util::Collected::to_bytes)
        .unwrap_or_default();
    String::from_utf8_lossy(&collected).into_owned()
}

pub async fn wait_for_file(path: &Path) -> bool {
    for _ in 0..600 {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    false
}

/// Whether `pid` names a live, unreaped process.
///
/// `kill -0` alone is not enough: it succeeds on a zombie, so a cleanup test
/// asserting only that would stay green for the wrong reason.  This reads the
/// process table's state column, exactly as the chunk-2 tests do.
#[must_use]
pub fn process_state(pid: u32) -> Option<String> {
    let output = std::process::Command::new("ps")
        .args(["-o", "state=", "-p", &pid.to_string()])
        .output()
        .ok()?;
    let state = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    if state.is_empty() { None } else { Some(state) }
}

#[must_use]
pub fn is_alive(pid: u32) -> bool {
    process_state(pid).is_some_and(|state| !state.starts_with('Z'))
}
