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
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

/// One deterministic fixture fault for a single accepted route.  The proxy
/// never inspects bytes; the fault is keyed on the direction of opaque byte
/// bursts only, so it applies equally to any TLS-protected stream.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FanoutRouteFault {
    /// Forward client-to-target bytes normally but stop forwarding
    /// target-to-client bytes once the client's `client_flight`-th burst
    /// begins.  A burst is a run of client bytes that follows target bytes
    /// (the first client bytes count as burst one).  With a TLS 1.3 mutual
    /// handshake, burst three is the client `Finished` flight and the first
    /// application bytes that follow it, so the target receives the client's
    /// first application request while every response byte is withheld until
    /// the route is closed by the fixture.  The hold never releases on its
    /// own; it exists to make an attach-then-lose fault observable rather
    /// than timing dependent.
    HoldTargetToClientAfterClientFlight(u32),
}

/// Payload-free flow record for one accepted route.  Counters describe byte
/// volume and burst direction changes only.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct FanoutRouteFlow {
    pub index: u64,
    pub client_bursts: u32,
    pub target_bursts: u32,
    pub client_bytes: u64,
    pub target_bytes: u64,
    /// The target-to-client direction is currently withheld by a fault.
    pub held: bool,
    /// The fixture closed this route through [`FanoutProxyHandle::close_route`].
    pub closed_by_fixture: bool,
}

#[derive(Debug, Default)]
struct RouteControl {
    faults: BTreeMap<u64, FanoutRouteFault>,
    cancels: BTreeMap<u64, CancellationToken>,
    flows: BTreeMap<u64, Arc<Mutex<FanoutRouteFlow>>>,
}

type SharedRouteControl = Arc<Mutex<RouteControl>>;

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
        let routes = Arc::new(Mutex::new(RouteControl::default()));
        let task_cancellation = cancellation.clone();
        let task_diagnostics = Arc::clone(&diagnostics);
        let task_routes = Arc::clone(&routes);
        let task_targets = Arc::from(targets.into_boxed_slice());
        let listener_targets = Arc::clone(&task_targets);
        let task_config = config.clone();
        let task = tokio::spawn(async move {
            accept_loop(
                listener,
                listener_targets,
                task_config,
                task_diagnostics,
                task_routes,
                task_cancellation,
            )
            .await
        });

        Ok(FanoutProxyHandle {
            local_addr,
            targets: task_targets,
            diagnostics,
            routes,
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
    routes: SharedRouteControl,
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

    /// Arm one deterministic fault for a route that has not been accepted
    /// yet.  Faults are keyed by accept index so a fixture can name the exact
    /// future carrier (for example each recovery candidate) without racing
    /// the client's dial.  Arming an already accepted index is an error.
    pub fn set_route_fault(&self, accept_index: u64, fault: FanoutRouteFault) -> Result<()> {
        if let FanoutRouteFault::HoldTargetToClientAfterClientFlight(0) = fault {
            return Err(HarnessError::InvalidInput(
                "fanout route hold requires a nonzero client burst".to_owned(),
            ));
        }
        let accepted = self
            .diagnostics
            .lock()
            .map(|state| state.accepted)
            .map_err(|_| HarnessError::Proxy("fanout diagnostics poisoned".to_owned()))?;
        if accept_index < accepted {
            return Err(HarnessError::InvalidInput(format!(
                "fanout route {accept_index} was already accepted; faults must be armed first"
            )));
        }
        let mut routes = self
            .routes
            .lock()
            .map_err(|_| HarnessError::Proxy("fanout route control poisoned".to_owned()))?;
        if routes.faults.len() >= MAX_CONNECTIONS {
            return Err(HarnessError::InvalidInput(
                "fanout route fault table is full".to_owned(),
            ));
        }
        routes.faults.insert(accept_index, fault);
        Ok(())
    }

    /// Close one open route by accept index: both the accepted socket and its
    /// target socket are dropped once the route task observes the request.
    /// Returns `false` when the index is not currently open.
    pub fn close_route(&self, accept_index: u64) -> Result<bool> {
        let routes = self
            .routes
            .lock()
            .map_err(|_| HarnessError::Proxy("fanout route control poisoned".to_owned()))?;
        let Some(cancel) = routes.cancels.get(&accept_index) else {
            return Ok(false);
        };
        if let Some(flow) = routes.flows.get(&accept_index)
            && let Ok(mut flow) = flow.lock()
        {
            flow.closed_by_fixture = true;
        }
        cancel.cancel();
        Ok(true)
    }

    /// Payload-free flow record for one accepted route.  Records are retained
    /// for a bounded number of routes in accept order.
    pub fn route_flow(&self, accept_index: u64) -> Option<FanoutRouteFlow> {
        self.routes
            .lock()
            .ok()?
            .flows
            .get(&accept_index)
            .and_then(|flow| flow.lock().ok().map(|flow| *flow))
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
    routes: SharedRouteControl,
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
                let route_cancel = CancellationToken::new();
                let flow = Arc::new(Mutex::new(FanoutRouteFlow {
                    index: route.index,
                    ..FanoutRouteFlow::default()
                }));
                let fault = match routes.lock() {
                    Ok(mut control) => {
                        control.cancels.insert(route.index, route_cancel.clone());
                        if control.flows.len() >= MAX_CONNECTIONS
                            && let Some(oldest) = control.flows.keys().next().copied()
                        {
                            control.flows.remove(&oldest);
                        }
                        control.flows.insert(route.index, Arc::clone(&flow));
                        control.faults.get(&route.index).copied()
                    }
                    Err(_) => None,
                };
                let task_routes = Arc::clone(&routes);
                connections.spawn(async move {
                    let _ = forward_connection(
                        client,
                        route.target,
                        config.read_buffer_bytes,
                        task_cancellation,
                        RouteFault {
                            fault,
                            cancel: route_cancel,
                            flow,
                        },
                    )
                    .await;
                    if let Ok(mut control) = task_routes.lock() {
                        control.cancels.remove(&route.index);
                    }
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

/// Per-route fault state handed to the forwarding task.
struct RouteFault {
    fault: Option<FanoutRouteFault>,
    cancel: CancellationToken,
    flow: Arc<Mutex<FanoutRouteFlow>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BurstDirection {
    ClientToTarget,
    TargetToClient,
}

/// Record one opaque burst and return whether the target-to-client direction
/// must now be withheld.
fn record_burst(
    flow: &Arc<Mutex<FanoutRouteFlow>>,
    last: &mut Option<BurstDirection>,
    direction: BurstDirection,
    bytes: usize,
    fault: Option<FanoutRouteFault>,
) -> bool {
    let Ok(mut flow) = flow.lock() else {
        return false;
    };
    let bytes = u64::try_from(bytes).unwrap_or(u64::MAX);
    let new_burst = *last != Some(direction);
    *last = Some(direction);
    match direction {
        BurstDirection::ClientToTarget => {
            if new_burst {
                flow.client_bursts = flow.client_bursts.saturating_add(1);
            }
            flow.client_bytes = flow.client_bytes.saturating_add(bytes);
        }
        BurstDirection::TargetToClient => {
            if new_burst {
                flow.target_bursts = flow.target_bursts.saturating_add(1);
            }
            flow.target_bytes = flow.target_bytes.saturating_add(bytes);
        }
    }
    if let Some(FanoutRouteFault::HoldTargetToClientAfterClientFlight(flight)) = fault
        && flow.client_bursts >= flight
    {
        flow.held = true;
    }
    flow.held
}

async fn forward_connection(
    client: TcpStream,
    target_addr: SocketAddr,
    read_buffer_bytes: usize,
    cancellation: CancellationToken,
    route: RouteFault,
) -> Result<()> {
    let target = tokio::select! {
        _ = cancellation.cancelled() => return Ok(()),
        _ = route.cancel.cancelled() => return Ok(()),
        result = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(target_addr)) => {
            result
                .map_err(|_| HarnessError::Timeout("fanout proxy target connection timed out".to_owned()))??
        }
    };
    let mut client = client;
    let mut target = target;
    let (mut client_read, mut client_write) = client.split();
    let (mut target_read, mut target_write) = target.split();
    let mut client_buffer = vec![0_u8; read_buffer_bytes];
    let mut target_buffer = vec![0_u8; read_buffer_bytes];
    let mut last = None;
    let mut held = false;
    let mut client_open = true;
    let mut target_open = true;
    // A held route keeps its target bytes unread in the kernel; the route
    // ends only through cancellation or a client-side close.
    while client_open || (target_open && !held) {
        tokio::select! {
            _ = cancellation.cancelled() => break,
            _ = route.cancel.cancelled() => break,
            read = client_read.read(&mut client_buffer), if client_open => {
                let read = read.map_err(HarnessError::Io)?;
                if read == 0 {
                    client_open = false;
                    let _ = target_write.shutdown().await;
                    continue;
                }
                held = record_burst(
                    &route.flow,
                    &mut last,
                    BurstDirection::ClientToTarget,
                    read,
                    route.fault,
                );
                target_write
                    .write_all(&client_buffer[..read])
                    .await
                    .map_err(HarnessError::Io)?;
            }
            read = target_read.read(&mut target_buffer), if target_open && !held => {
                let read = read.map_err(HarnessError::Io)?;
                if read == 0 {
                    target_open = false;
                    let _ = client_write.shutdown().await;
                    continue;
                }
                held = record_burst(
                    &route.flow,
                    &mut last,
                    BurstDirection::TargetToClient,
                    read,
                    route.fault,
                );
                client_write
                    .write_all(&target_buffer[..read])
                    .await
                    .map_err(HarnessError::Io)?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{FanoutProxy, FanoutProxyConfig, FanoutRouteFault, HarnessError};
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

    /// The hold fault must deliver the client's third burst to the target
    /// while withholding every response byte after it, and `close_route`
    /// must end both sockets so the target observes the loss.
    #[tokio::test]
    async fn fanout_hold_fault_withholds_responses_after_client_flight_until_closed() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_address = target.local_addr().expect("target address");
        let proxy = FanoutProxy::bind(
            vec![target_address],
            FanoutProxyConfig::with_max_concurrent_connections(2),
        )
        .await
        .expect("fanout proxy");
        proxy
            .set_route_fault(0, FanoutRouteFault::HoldTargetToClientAfterClientFlight(3))
            .expect("arm route zero");
        assert!(matches!(
            proxy.set_route_fault(0, FanoutRouteFault::HoldTargetToClientAfterClientFlight(0)),
            Err(HarnessError::InvalidInput(_))
        ));
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("target accept");
            let mut buffer = [0_u8; 8];
            // Burst one and two from the client, one reply after each.
            for expected in [b"one\n", b"two\n"] {
                let mut read = 0;
                while read < expected.len() {
                    let n = stream.read(&mut buffer[read..]).await.expect("target read");
                    assert_ne!(n, 0);
                    read += n;
                }
                assert_eq!(&buffer[..read], expected);
                stream.write_all(b"ack\n").await.expect("target ack");
            }
            // Burst three reaches the target while its reply is withheld.
            let mut read = 0;
            while read < 6 {
                let n = stream.read(&mut buffer[read..]).await.expect("target read");
                assert_ne!(n, 0);
                read += n;
            }
            assert_eq!(&buffer[..6], b"three\n");
            stream.write_all(b"withheld\n").await.expect("target reply");
            // The fixture close must surface as a client loss at the target.
            let mut tail = [0_u8; 16];
            let closed = matches!(stream.read(&mut tail).await, Ok(0) | Err(_));
            assert!(closed, "target must observe the fixture-closed route");
        });
        let mut client = TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        let mut reply = [0_u8; 4];
        for burst in [b"one\n", b"two\n"] {
            client.write_all(burst).await.expect("client burst");
            client.read_exact(&mut reply).await.expect("client ack");
            assert_eq!(&reply, b"ack\n");
        }
        client
            .write_all(b"three\n")
            .await
            .expect("client burst three");
        let held = timeout(Duration::from_secs(2), async {
            loop {
                if let Some(flow) = proxy.route_flow(0)
                    && flow.held
                    && flow.client_bursts == 3
                {
                    break flow;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("route enters the hold");
        assert_eq!(held.target_bursts, 2);
        assert!(!held.closed_by_fixture);
        // Nothing arrives at the client while the route is held.
        let withheld = timeout(Duration::from_millis(200), client.read(&mut reply)).await;
        assert!(withheld.is_err(), "held route leaked target bytes");
        assert!(proxy.close_route(0).expect("close route zero"));
        assert!(!proxy.close_route(7).expect("unknown route is not open"));
        let ended = timeout(Duration::from_secs(2), client.read(&mut reply))
            .await
            .expect("client observes the close");
        assert!(matches!(ended, Ok(0) | Err(_)));
        timeout(Duration::from_secs(2), target_task)
            .await
            .expect("target task joins")
            .expect("target assertions");
        let flow = proxy.route_flow(0).expect("flow retained");
        assert!(flow.closed_by_fixture && flow.held);
        assert_eq!(flow.client_bytes, 14);
        assert_eq!(flow.target_bytes, 8);
        timeout(Duration::from_secs(2), async {
            loop {
                if proxy.diagnostics().closed_count == 1 {
                    break;
                }
                sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .expect("route closes");
        assert!(matches!(
            proxy.set_route_fault(0, FanoutRouteFault::HoldTargetToClientAfterClientFlight(3)),
            Err(HarnessError::InvalidInput(_))
        ));
        proxy.shutdown().await.expect("proxy shutdown");
    }
}
