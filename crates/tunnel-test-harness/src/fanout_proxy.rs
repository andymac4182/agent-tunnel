//! A bounded, TLS-opaque TCP fanout fixture for multi-relay acceptance tests.
//!
//! A single listener is useful when the device derives its data endpoint from
//! the control endpoint: the first accepted socket can be sent to one relay
//! and later sockets can be sent to a deterministic sequence of relay
//! listeners.  The proxy never terminates TLS or interprets bytes.  It only
//! connects the accepted TCP socket to the selected target and copies bytes
//! in both directions.

use crate::error::{HarnessError, Result};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::io::copy_bidirectional_with_sizes;
use tokio::net::{TcpListener, TcpStream};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{timeout, timeout_at};
use tokio_util::sync::CancellationToken;

const DEFAULT_MAX_CONCURRENT_CONNECTIONS: usize = 8;
const DEFAULT_DIAGNOSTICS_CAPACITY: usize = 64;
const DEFAULT_READ_BUFFER_BYTES: usize = 16 * 1024;
const MAX_TARGETS: usize = 1024;
const MAX_CONNECTIONS: usize = 1024;
const MAX_DIAGNOSTICS_CAPACITY: usize = 4096;
const MAX_READ_BUFFER_BYTES: usize = 1024 * 1024;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Configuration for [`FanoutProxy`].
///
/// `targets` is supplied to [`FanoutProxy::bind`].  It is an ordered route
/// schedule: accepted index `0` uses `targets[0]`, index `1` uses
/// `targets[1]`, and so on.  Once the end is reached the schedule repeats.
/// This makes a control/data/replacement topology explicit, for example
/// `[relay_a, relay_b, relay_c, relay_b, relay_c]`.
#[derive(Clone, Debug)]
pub struct FanoutProxyConfig {
    /// Local address for the one listener.  Port zero asks the OS for an
    /// ephemeral port, which is the normal fixture setting.
    pub bind_addr: SocketAddr,
    /// Maximum number of accepted sockets retained by the fixture at once.
    /// New sockets remain in the kernel accept backlog while this limit is
    /// reached; they are not accumulated in an unbounded application queue.
    pub max_concurrent_connections: usize,
    /// Maximum number of closed route records retained in diagnostics.
    pub diagnostics_capacity: usize,
    /// Per-direction copy buffer size.  Bytes are never inspected or parsed.
    pub read_buffer_bytes: usize,
}

impl Default for FanoutProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            max_concurrent_connections: DEFAULT_MAX_CONCURRENT_CONNECTIONS,
            diagnostics_capacity: DEFAULT_DIAGNOSTICS_CAPACITY,
            read_buffer_bytes: DEFAULT_READ_BUFFER_BYTES,
        }
    }
}

impl FanoutProxyConfig {
    /// Create a default configuration with the requested concurrency limit.
    pub fn new(max_concurrent_connections: usize) -> Self {
        Self::with_max_concurrent_connections(max_concurrent_connections)
    }

    /// Create a configuration with the requested concurrency limit.
    pub fn with_max_concurrent_connections(max_concurrent_connections: usize) -> Self {
        Self {
            max_concurrent_connections,
            ..Self::default()
        }
    }

    /// Set the local listener address.
    pub fn with_bind_addr(mut self, bind_addr: SocketAddr) -> Self {
        self.bind_addr = bind_addr;
        self
    }

    /// Set the maximum number of retained closed records.
    pub fn with_diagnostics_capacity(mut self, diagnostics_capacity: usize) -> Self {
        self.diagnostics_capacity = diagnostics_capacity;
        self
    }

    /// Alias for callers that use the shorter concurrency terminology.
    pub fn with_max_connections(mut self, max_connections: usize) -> Self {
        self.max_concurrent_connections = max_connections;
        self
    }

    /// Set the copy buffer size used in each direction.
    pub fn with_read_buffer_bytes(mut self, read_buffer_bytes: usize) -> Self {
        self.read_buffer_bytes = read_buffer_bytes;
        self
    }
}

/// One accepted socket and its selected opaque target.
///
/// `index` is zero-based and is assigned in listener accept order.  It is
/// stable for the lifetime of the proxy and does not expose any payload or
/// TLS details.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FanoutConnection {
    pub index: u64,
    pub target: SocketAddr,
}

impl FanoutConnection {
    pub const fn accept_index(self) -> u64 {
        self.index
    }

    pub const fn target_addr(self) -> SocketAddr {
        self.target
    }
}

/// Bounded status for one fanout listener.
///
/// `open` contains all accepted sockets that are still connecting or being
/// forwarded.  `closed` is a bounded tail of completed routes.  The counters
/// remain useful after old closed records have been evicted from the tail.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FanoutProxyDiagnostics {
    /// Total sockets accepted since the listener started.
    pub accepted: u64,
    /// Total routes that have completed since the listener started.
    pub closed_count: u64,
    /// High-water mark for concurrently open accepted sockets.
    pub peak_open: usize,
    /// Currently open accepted sockets, including target connection setup.
    pub open: Vec<FanoutConnection>,
    /// Bounded oldest-to-newest tail of closed accepted sockets.
    pub closed: Vec<FanoutConnection>,
}

impl FanoutProxyDiagnostics {
    /// Number of currently open accepted sockets.
    pub fn open_count(&self) -> usize {
        self.open.len()
    }

    /// Number of retained closed records, which is bounded by configuration.
    pub fn retained_closed_count(&self) -> usize {
        self.closed.len()
    }
}

#[derive(Debug)]
struct DiagnosticsState {
    accepted: u64,
    closed_count: u64,
    peak_open: usize,
    open: BTreeMap<u64, FanoutConnection>,
    closed: VecDeque<FanoutConnection>,
    diagnostics_capacity: usize,
}

impl DiagnosticsState {
    fn new(diagnostics_capacity: usize) -> Self {
        Self {
            accepted: 0,
            closed_count: 0,
            peak_open: 0,
            open: BTreeMap::new(),
            closed: VecDeque::with_capacity(diagnostics_capacity),
            diagnostics_capacity,
        }
    }

    fn accepted(&mut self, target: SocketAddr) -> FanoutConnection {
        let index = self.accepted;
        self.accepted = self.accepted.saturating_add(1);
        let route = FanoutConnection { index, target };
        self.open.insert(index, route);
        self.peak_open = self.peak_open.max(self.open.len());
        route
    }

    fn closed(&mut self, route: FanoutConnection) {
        self.open.remove(&route.index);
        self.closed_count = self.closed_count.saturating_add(1);
        if self.diagnostics_capacity != 0 {
            if self.closed.len() == self.diagnostics_capacity {
                self.closed.pop_front();
            }
            self.closed.push_back(route);
        }
    }

    fn snapshot(&self) -> FanoutProxyDiagnostics {
        let mut closed = self.closed.iter().copied().collect::<Vec<_>>();
        closed.sort_unstable_by_key(|route| route.index);
        FanoutProxyDiagnostics {
            accepted: self.accepted,
            closed_count: self.closed_count,
            peak_open: self.peak_open,
            open: self.open.values().copied().collect(),
            closed,
        }
    }
}

type SharedDiagnostics = Arc<Mutex<DiagnosticsState>>;

/// A one-listener TCP fanout proxy.  The listener is intentionally
/// TLS-agnostic: mTLS handshakes pass through as opaque bytes.
pub struct FanoutProxy;

impl FanoutProxy {
    /// Bind a listener and route accepted sockets through the ordered target
    /// schedule in `targets`.
    pub async fn bind(
        targets: Vec<SocketAddr>,
        config: FanoutProxyConfig,
    ) -> Result<FanoutProxyHandle> {
        validate_targets(&targets)?;
        validate_config(&config)?;

        let listener = TcpListener::bind(config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let cancellation = CancellationToken::new();
        let diagnostics = Arc::new(Mutex::new(DiagnosticsState::new(
            config.diagnostics_capacity,
        )));
        let task_cancellation = cancellation.clone();
        let task_diagnostics = Arc::clone(&diagnostics);
        let task_targets = Arc::from(targets.into_boxed_slice());
        let listener_targets = Arc::clone(&task_targets);
        let task_config = config.clone();
        let task = tokio::spawn(async move {
            accept_loop(
                listener,
                listener_targets,
                task_config,
                task_diagnostics,
                task_cancellation,
            )
            .await
        });

        Ok(FanoutProxyHandle {
            local_addr,
            targets: task_targets,
            diagnostics,
            cancellation,
            task: Some(task),
        })
    }

    /// Bind using a configuration that carries the target schedule.
    ///
    /// This convenience form is useful for callers that construct fixture
    /// configuration as one value.  [`FanoutProxyConfig`] itself deliberately
    /// keeps the target schedule out of `Default`, so an empty schedule cannot
    /// be mistaken for a usable proxy.
    pub async fn bind_config(
        targets: Vec<SocketAddr>,
        config: FanoutProxyConfig,
    ) -> Result<FanoutProxyHandle> {
        Self::bind(targets, config).await
    }
}

/// A running fanout listener and its joined-shutdown control.
pub struct FanoutProxyHandle {
    local_addr: SocketAddr,
    targets: Arc<[SocketAddr]>,
    diagnostics: SharedDiagnostics,
    cancellation: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl fmt::Debug for FanoutProxyHandle {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FanoutProxyHandle")
            .field("local_addr", &self.local_addr)
            .field("targets", &self.targets)
            .field("diagnostics", &self.diagnostics())
            .finish()
    }
}

impl FanoutProxyHandle {
    /// Address shared by control and data clients.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The immutable ordered target schedule used by this listener.
    pub fn targets(&self) -> &[SocketAddr] {
        &self.targets
    }

    /// Resolve a zero-based accepted index without accepting a socket.
    pub fn target_for_accept_index(&self, index: u64) -> SocketAddr {
        self.targets[(index % self.targets.len() as u64) as usize]
    }

    /// Return the bounded listener diagnostics snapshot.
    pub fn diagnostics(&self) -> FanoutProxyDiagnostics {
        self.diagnostics
            .lock()
            .map(|state| state.snapshot())
            .unwrap_or_default()
    }

    /// Cancel the listener and join the accept and forwarding tasks.
    ///
    /// Joining is intentional: callers can safely tear down a fixture without
    /// leaving mTLS sockets or copy tasks running in the background.
    pub async fn shutdown(mut self) -> Result<()> {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.await
                .map_err(|error| HarnessError::Proxy(format!("fanout task failed: {error}")))??;
        }
        Ok(())
    }

    /// Cancel the listener and join its accept/forwarding task through a
    /// caller-owned absolute deadline.  If the task misses that deadline, it
    /// receives a short drain grace period, then is aborted and joined for one
    /// final bounded interval before the handle is allowed to drop.
    pub async fn shutdown_until(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        self.cancellation.cancel();
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        match timeout_at(deadline, &mut *task).await {
            Ok(Ok(Ok(()))) => {
                self.task.take();
                Ok(())
            }
            Ok(Ok(Err(error))) => {
                self.task.take();
                Err(HarnessError::Proxy(format!("fanout task failed: {error}")))
            }
            Ok(Err(error)) => {
                self.task.take();
                Err(HarnessError::Proxy(format!(
                    "fanout task join failed: {error}"
                )))
            }
            Err(_) => match timeout(Duration::from_secs(1), &mut *task).await {
                Ok(Ok(Ok(()))) => {
                    self.task.take();
                    Err(HarnessError::Timeout(
                        "fanout task joined after the shared deadline".into(),
                    ))
                }
                Ok(Ok(Err(error))) => {
                    self.task.take();
                    Err(HarnessError::Proxy(format!(
                        "fanout task failed after the shared deadline: {error}"
                    )))
                }
                Ok(Err(error)) => {
                    self.task.take();
                    Err(HarnessError::Proxy(format!(
                        "fanout task join failed after the shared deadline: {error}"
                    )))
                }
                Err(_) => {
                    task.abort();
                    match timeout(Duration::from_secs(1), &mut *task).await {
                        Ok(Ok(Ok(()))) => {
                            self.task.take();
                            Err(HarnessError::Timeout(
                                "fanout task required forced abort cleanup".into(),
                            ))
                        }
                        Ok(Ok(Err(error))) => {
                            self.task.take();
                            Err(HarnessError::Proxy(format!(
                                "fanout task forced abort join failed: {error}"
                            )))
                        }
                        Ok(Err(error)) => {
                            self.task.take();
                            Err(HarnessError::Proxy(format!(
                                "fanout task forced abort join failed: {error}"
                            )))
                        }
                        Err(_) => Err(HarnessError::Timeout(
                            "fanout task did not join after forced abort".into(),
                        )),
                    }
                }
            },
        }
    }
}

impl Drop for FanoutProxyHandle {
    fn drop(&mut self) {
        self.cancellation.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Alias matching the naming used by the existing single-target proxy.
pub type TcpFanoutProxy = FanoutProxy;
/// Alias matching the naming used by the existing single-target proxy.
pub type TcpFanoutProxyHandle = FanoutProxyHandle;
/// Alias matching the naming used by the existing single-target proxy.
pub type TcpFanoutProxyConfig = FanoutProxyConfig;

fn validate_targets(targets: &[SocketAddr]) -> Result<()> {
    if targets.is_empty() {
        return Err(HarnessError::InvalidInput(
            "fanout proxy requires at least one target".to_owned(),
        ));
    }
    if targets.len() > MAX_TARGETS {
        return Err(HarnessError::InvalidInput(format!(
            "fanout proxy target schedule cannot exceed {MAX_TARGETS} entries"
        )));
    }
    Ok(())
}

fn validate_config(config: &FanoutProxyConfig) -> Result<()> {
    if config.max_concurrent_connections == 0 || config.max_concurrent_connections > MAX_CONNECTIONS
    {
        return Err(HarnessError::InvalidInput(format!(
            "fanout proxy max_concurrent_connections must be between 1 and {MAX_CONNECTIONS}"
        )));
    }
    if config.diagnostics_capacity > MAX_DIAGNOSTICS_CAPACITY {
        return Err(HarnessError::InvalidInput(format!(
            "fanout proxy diagnostics_capacity cannot exceed {MAX_DIAGNOSTICS_CAPACITY}"
        )));
    }
    if config.read_buffer_bytes == 0 || config.read_buffer_bytes > MAX_READ_BUFFER_BYTES {
        return Err(HarnessError::InvalidInput(format!(
            "fanout proxy read_buffer_bytes must be between 1 and {MAX_READ_BUFFER_BYTES}"
        )));
    }
    Ok(())
}

async fn accept_loop(
    listener: TcpListener,
    targets: Arc<[SocketAddr]>,
    config: FanoutProxyConfig,
    diagnostics: SharedDiagnostics,
    cancellation: CancellationToken,
) -> Result<()> {
    let mut connections = JoinSet::new();

    loop {
        let open_count = diagnostics
            .lock()
            .map(|state| state.open.len())
            .unwrap_or(config.max_concurrent_connections);
        tokio::select! {
            _ = cancellation.cancelled() => break,
            Some(joined) = connections.join_next(), if open_count != 0 => {
                complete_connection(joined, &diagnostics);
            }
            result = listener.accept(), if open_count < config.max_concurrent_connections => {
                let (client, _source_addr) = result?;
                let accept_index = diagnostics
                    .lock()
                    .map(|state| state.accepted)
                    .unwrap_or(0);
                let target = targets[(accept_index % targets.len() as u64) as usize];
                let route = diagnostics
                    .lock()
                    .map(|mut state| state.accepted(target))
                    .unwrap_or(FanoutConnection {
                        index: accept_index,
                        target,
                    });
                let task_cancellation = cancellation.clone();
                connections.spawn(async move {
                    let _ = forward_connection(
                        client,
                        route.target,
                        config.read_buffer_bytes,
                        task_cancellation,
                    )
                    .await;
                    route
                });
            }
        }
    }

    cancellation.cancel();
    while let Some(joined) = connections.join_next().await {
        complete_connection(joined, &diagnostics);
    }
    Ok(())
}

fn complete_connection(
    joined: std::result::Result<FanoutConnection, tokio::task::JoinError>,
    diagnostics: &SharedDiagnostics,
) {
    let route = match joined {
        Ok(route) => route,
        Err(_) => return,
    };
    if let Ok(mut state) = diagnostics.lock() {
        state.closed(route);
    }
}

async fn forward_connection(
    client: TcpStream,
    target_addr: SocketAddr,
    read_buffer_bytes: usize,
    cancellation: CancellationToken,
) -> Result<()> {
    let target = tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target_addr)) => {
            result
                .map_err(|_| HarnessError::Timeout("fanout proxy target connection timed out".to_owned()))??
        }
    };
    let mut client = client;
    let mut target = target;
    tokio::select! {
        _ = cancellation.cancelled() => Ok(()),
        result = copy_bidirectional_with_sizes(
            &mut client,
            &mut target,
            read_buffer_bytes,
            read_buffer_bytes,
        ) => {
            result.map(|_| ()).map_err(HarnessError::Io)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FanoutProxy, FanoutProxyConfig};
    use std::net::SocketAddr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use tokio::task::JoinSet;
    use tokio::time::{Duration, sleep, timeout};

    async fn echo_listener(listener: TcpListener, expected_connections: usize) {
        let mut tasks = JoinSet::new();
        for _ in 0..expected_connections {
            let (mut stream, _) = listener.accept().await.expect("target accept");
            tasks.spawn(async move {
                let mut payload = vec![0_u8; 64];
                let length = stream.read(&mut payload).await.expect("target read");
                stream
                    .write_all(&payload[..length])
                    .await
                    .expect("target write");
            });
        }
        while tasks.join_next().await.is_some() {}
    }

    async fn connect_and_echo(address: SocketAddr, payload: &[u8]) {
        let mut stream = TcpStream::connect(address).await.expect("proxy connect");
        stream.write_all(payload).await.expect("proxy write");
        let mut echoed = vec![0_u8; payload.len()];
        stream.read_exact(&mut echoed).await.expect("proxy read");
        assert_eq!(echoed, payload);
        stream.shutdown().await.expect("proxy shutdown");
    }

    #[tokio::test]
    async fn fanout_routes_opaque_bytes_in_accept_order_and_joins_shutdown() {
        let mut target_listeners = Vec::new();
        for _ in 0..5 {
            target_listeners.push(TcpListener::bind(("127.0.0.1", 0)).await.expect("target"));
        }
        let target_addresses = target_listeners
            .iter()
            .map(|listener| listener.local_addr().expect("target addr"))
            .collect::<Vec<_>>();
        let mut target_tasks = JoinSet::new();
        for listener in target_listeners {
            target_tasks.spawn(echo_listener(listener, 1));
        }
        let proxy = FanoutProxy::bind(
            target_addresses,
            FanoutProxyConfig::with_max_concurrent_connections(3),
        )
        .await
        .expect("fanout proxy");
        let proxy_address = proxy.local_addr();
        let payloads = [
            [0_u8, 255, 1, 254],
            [9_u8, 0, 8, 247],
            [17_u8, 238, 16, 239],
            [32_u8, 223, 31, 224],
            [64_u8, 191, 63, 192],
        ];
        for payload in payloads {
            connect_and_echo(proxy_address, &payload).await;
        }
        timeout(Duration::from_secs(2), async {
            loop {
                if proxy.diagnostics().closed_count == 5 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("routes close");
        let diagnostics = proxy.diagnostics();
        assert_eq!(diagnostics.accepted, 5);
        assert_eq!(diagnostics.open_count(), 0);
        assert_eq!(diagnostics.closed_count, 5);
        assert_eq!(
            diagnostics
                .closed
                .iter()
                .map(|route| route.index)
                .collect::<Vec<_>>(),
            vec![0, 1, 2, 3, 4]
        );
        proxy.shutdown().await.expect("proxy shutdown");
        while target_tasks.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn fanout_caps_open_sockets_and_bounds_closed_diagnostics() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_address = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let mut held = Vec::new();
            for _ in 0..3 {
                let (stream, _) = target.accept().await.expect("target accept");
                held.push(stream);
            }
            sleep(Duration::from_millis(100)).await;
        });
        let proxy = FanoutProxy::bind(
            vec![target_address],
            FanoutProxyConfig::with_max_concurrent_connections(3).with_diagnostics_capacity(2),
        )
        .await
        .expect("fanout proxy");
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(
                TcpStream::connect(proxy.local_addr())
                    .await
                    .expect("client"),
            );
        }
        timeout(Duration::from_secs(2), async {
            loop {
                if proxy.diagnostics().open_count() == 3 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("three open routes");
        assert_eq!(proxy.diagnostics().peak_open, 3);
        drop(clients);
        target_task.await.expect("target task");
        timeout(Duration::from_secs(2), async {
            loop {
                if proxy.diagnostics().closed_count == 3 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("routes close");
        let diagnostics = proxy.diagnostics();
        assert_eq!(diagnostics.closed.len(), 2);
        assert_eq!(diagnostics.closed_count, 3);
        proxy.shutdown().await.expect("proxy shutdown");
    }

    #[tokio::test]
    async fn fanout_held_route_joins_with_expired_deadline_and_repeated_shutdown() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_address = target.local_addr().expect("target address");
        let mut proxy = FanoutProxy::bind(
            vec![target_address],
            FanoutProxyConfig::with_max_concurrent_connections(1),
        )
        .await
        .expect("fanout proxy");
        let _client = TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        timeout(Duration::from_secs(2), async {
            loop {
                if proxy.diagnostics().open_count() == 1 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("held route");

        // Cancellation can join in the first poll, even with an expired
        // deadline. Either outcome must leave this real route fully joined.
        let _graceful = proxy.shutdown_until(tokio::time::Instant::now()).await;
        assert!(proxy.task.is_none(), "fanout task was joined");
        assert_eq!(proxy.diagnostics().open_count(), 0);
        assert_eq!(proxy.diagnostics().closed_count, 1);
        proxy
            .shutdown_until(tokio::time::Instant::now() + Duration::from_secs(2))
            .await
            .expect("repeated shutdown after join is idempotent");
        assert_eq!(proxy.diagnostics().open_count(), 0);
    }
}
