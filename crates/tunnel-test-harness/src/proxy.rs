use crate::error::{HarnessError, Result};
use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Notify, broadcast, mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

/// A stable identifier assigned to one accepted TCP connection.
///
/// IDs start at one and are allocated in listener-accept order without
/// retaining an ever-growing history of connections.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ConnectionId(pub u64);

impl ConnectionId {
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    pub const fn as_u64(self) -> u64 {
        self.0
    }
}

impl From<u64> for ConnectionId {
    fn from(value: u64) -> Self {
        Self(value)
    }
}

impl From<ConnectionId> for u64 {
    fn from(value: ConnectionId) -> Self {
        value.0
    }
}

/// The bounded active-connection record exposed by the proxy.
///
/// `source_addr` is the peer address observed by the proxy when it accepts
/// the client socket.  It is intentionally only retained while the
/// connection is active, so callers can map a carrier's local address to the
/// stable connection ID without assigning protocol roles from ordinal order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProxyConnection {
    pub id: ConnectionId,
    pub source_addr: SocketAddr,
}

// Commands are deliberately bounded.  A test that floods the control surface
// receives a bounded-capacity error instead of creating an unbounded command
// backlog or one task per command.
const PROXY_COMMAND_CAPACITY: usize = 32;
const CONNECTION_COMMAND_CAPACITY: usize = 8;
const MAX_ACTIVE_CONNECTIONS: u64 = 1024;
const MAX_RECENT_CONNECTION_IDS: usize = 16;
const COMMAND_TIMEOUT: Duration = Duration::from_secs(1);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const PAUSE_TIMEOUT: Duration = Duration::from_secs(30);

type ActiveConnections = Arc<std::sync::Mutex<HashMap<ConnectionId, ProxyConnection>>>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Direction {
    ClientToTarget,
    TargetToClient,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum FaultAction {
    Pause(Duration),
    DropBytes(u64),
    CloseAfterBytes(u64),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FaultRule {
    pub direction: Direction,
    pub action: FaultAction,
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct FaultScript {
    pub rules: Vec<FaultRule>,
}

impl FaultScript {
    pub fn with_rule(mut self, direction: Direction, action: FaultAction) -> Self {
        self.rules.push(FaultRule { direction, action });
        self
    }

    fn for_direction(&self, direction: Direction) -> DirectionFault {
        let mut fault = DirectionFault::default();
        for rule in self.rules.iter().filter(|rule| rule.direction == direction) {
            match rule.action {
                FaultAction::Pause(duration) => fault.pause = Some(duration),
                FaultAction::DropBytes(bytes) => {
                    fault.drop_bytes = fault.drop_bytes.saturating_add(bytes)
                }
                FaultAction::CloseAfterBytes(bytes) => {
                    fault.close_after = Some(
                        fault
                            .close_after
                            .map_or(bytes, |current| current.min(bytes)),
                    )
                }
            }
        }
        fault
    }
}

#[derive(Clone, Debug)]
pub struct ProxyConfig {
    pub bind_addr: SocketAddr,
    pub fault_script: FaultScript,
    pub read_buffer_bytes: usize,
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            bind_addr: SocketAddr::from(([127, 0, 0, 1], 0)),
            fault_script: FaultScript::default(),
            read_buffer_bytes: 16 * 1024,
        }
    }
}

#[derive(Default)]
struct StatsInner {
    accepted: AtomicU64,
    active: AtomicU64,
    peak_active: AtomicU64,
    completed: AtomicU64,
    last_connection_id: AtomicU64,
    recent_connection_ids: std::sync::Mutex<VecDeque<ConnectionId>>,
    bytes_client_to_target: AtomicU64,
    bytes_target_to_client: AtomicU64,
    dropped_client_to_target: AtomicU64,
    dropped_target_to_client: AtomicU64,
    paused_client_to_target: AtomicU64,
    paused_target_to_client: AtomicU64,
    closes: AtomicU64,
}

/// A cheap snapshot suitable for assertions and diagnostics.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyStats {
    pub accepted: u64,
    pub active: u64,
    pub completed: u64,
    pub bytes_client_to_target: u64,
    pub bytes_target_to_client: u64,
    pub dropped_client_to_target: u64,
    pub dropped_target_to_client: u64,
    pub paused_client_to_target: u64,
    pub paused_target_to_client: u64,
    pub closes: u64,
}

impl ProxyStats {
    fn snapshot(inner: &StatsInner) -> Self {
        Self {
            accepted: inner.accepted.load(Ordering::Acquire),
            active: inner.active.load(Ordering::Relaxed),
            completed: inner.completed.load(Ordering::Relaxed),
            bytes_client_to_target: inner.bytes_client_to_target.load(Ordering::Relaxed),
            bytes_target_to_client: inner.bytes_target_to_client.load(Ordering::Relaxed),
            dropped_client_to_target: inner.dropped_client_to_target.load(Ordering::Relaxed),
            dropped_target_to_client: inner.dropped_target_to_client.load(Ordering::Relaxed),
            paused_client_to_target: inner.paused_client_to_target.load(Ordering::Relaxed),
            paused_target_to_client: inner.paused_target_to_client.load(Ordering::Relaxed),
            closes: inner.closes.load(Ordering::Relaxed),
        }
    }
}

/// A bounded diagnostic snapshot for M2 fault control and assertions.
///
/// The existing `ProxyStats` shape remains unchanged for M1 callers.  This
/// snapshot adds the M2 connection-ID tail, peak active count, and bounded
/// active peer records; accepted connections are never retained indefinitely.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyDiagnostics {
    pub stats: ProxyStats,
    pub peak_active: u64,
    pub last_connection_id: Option<ConnectionId>,
    pub recent_connection_ids: Vec<ConnectionId>,
    pub active_connections: Vec<ProxyConnection>,
}

impl std::ops::Deref for ProxyDiagnostics {
    type Target = ProxyStats;

    fn deref(&self) -> &Self::Target {
        &self.stats
    }
}

impl ProxyDiagnostics {
    fn snapshot(inner: &StatsInner, active_connections: &ActiveConnections) -> Self {
        Self {
            stats: ProxyStats::snapshot(inner),
            peak_active: inner.peak_active.load(Ordering::Relaxed),
            last_connection_id: match inner.last_connection_id.load(Ordering::Relaxed) {
                0 => None,
                value => Some(ConnectionId(value)),
            },
            recent_connection_ids: inner
                .recent_connection_ids
                .lock()
                .map(|ids| ids.iter().copied().collect())
                .unwrap_or_default(),
            active_connections: snapshot_active_connections(active_connections),
        }
    }
}

enum ProxyCommand {
    Close {
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
    Pause {
        direction: Direction,
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
    Resume {
        direction: Direction,
        connection_id: ConnectionId,
        reply: oneshot::Sender<Result<()>>,
    },
}

enum ConnectionCommand {
    Close {
        reply: oneshot::Sender<Result<()>>,
    },
    Pause {
        direction: Direction,
        reply: oneshot::Sender<Result<()>>,
    },
    Resume {
        direction: Direction,
        reply: oneshot::Sender<Result<()>>,
    },
}

type CloseReply = Arc<std::sync::Mutex<Option<oneshot::Sender<Result<()>>>>>;

struct ConnectionControl {
    shutdown: broadcast::Receiver<()>,
    commands: mpsc::Receiver<ConnectionCommand>,
    close_reply: CloseReply,
}

struct AcceptContext {
    listener: TcpListener,
    target_addr: SocketAddr,
    faults: FaultScript,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    active_connections: ActiveConnections,
}

/// A TCP proxy that leaves TLS opaque and can inject bounded transport faults.
pub struct TcpProxy;

impl TcpProxy {
    pub async fn bind(target_addr: SocketAddr, config: ProxyConfig) -> Result<ProxyHandle> {
        if config.read_buffer_bytes == 0 || config.read_buffer_bytes > 1024 * 1024 {
            return Err(HarnessError::InvalidInput(
                "proxy read_buffer_bytes must be between 1 and 1 MiB".to_owned(),
            ));
        }
        let listener = TcpListener::bind(config.bind_addr).await?;
        let local_addr = listener.local_addr()?;
        let (shutdown_tx, _) = broadcast::channel(2);
        let (command_tx, command_rx) = mpsc::channel(PROXY_COMMAND_CAPACITY);
        let stats = Arc::new(StatsInner::default());
        let active_connections: ActiveConnections = Arc::new(std::sync::Mutex::new(HashMap::new()));
        let accept_stats = Arc::clone(&stats);
        let accept_connections = Arc::clone(&active_connections);
        let accept_faults = config.fault_script.clone();
        let read_buffer_bytes = config.read_buffer_bytes;
        let accept_shutdown = shutdown_tx.subscribe();
        let accept_task = tokio::spawn(async move {
            accept_loop(
                AcceptContext {
                    listener,
                    target_addr,
                    faults: accept_faults,
                    read_buffer_bytes,
                    stats: accept_stats,
                    active_connections: accept_connections,
                },
                accept_shutdown,
                command_rx,
            )
            .await;
        });
        Ok(ProxyHandle {
            local_addr,
            target_addr,
            stats,
            active_connections,
            shutdown_tx,
            command_tx,
            accept_task: Some(accept_task),
        })
    }
}

pub struct ProxyHandle {
    local_addr: SocketAddr,
    target_addr: SocketAddr,
    stats: Arc<StatsInner>,
    active_connections: ActiveConnections,
    shutdown_tx: broadcast::Sender<()>,
    command_tx: mpsc::Sender<ProxyCommand>,
    accept_task: Option<JoinHandle<()>>,
}

impl std::fmt::Debug for ProxyHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ProxyHandle")
            .field("local_addr", &self.local_addr)
            .field("target_addr", &self.target_addr)
            .field("stats", &self.stats())
            .finish()
    }
}

impl ProxyHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    pub fn target_addr(&self) -> SocketAddr {
        self.target_addr
    }

    pub fn stats(&self) -> ProxyStats {
        ProxyStats::snapshot(&self.stats)
    }

    /// Return a bounded diagnostic snapshot suitable for status endpoints.
    pub fn diagnostics(&self) -> ProxyDiagnostics {
        ProxyDiagnostics::snapshot(&self.stats, &self.active_connections)
    }

    /// Return the currently active accepted connections and their client peer
    /// addresses.  The result is bounded by the proxy's active-connection
    /// limit and contains no historical address mapping.
    pub fn connections(&self) -> Vec<ProxyConnection> {
        snapshot_active_connections(&self.active_connections)
    }

    /// Close exactly one accepted connection.  The command is sent through a
    /// bounded queue and has a hard response deadline.
    pub async fn close(&self, connection_id: impl Into<ConnectionId>) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Close {
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    /// Pause forwarding in one direction of exactly one accepted connection.
    /// The pause is automatically failed closed after the bounded pause
    /// deadline if no matching `resume` command arrives.
    pub async fn pause(
        &self,
        direction: Direction,
        connection_id: impl Into<ConnectionId>,
    ) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Pause {
            direction,
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    /// Resume forwarding in one direction of exactly one accepted connection.
    pub async fn resume(
        &self,
        direction: Direction,
        connection_id: impl Into<ConnectionId>,
    ) -> Result<()> {
        let connection_id = connection_id.into();
        let (reply, response) = oneshot::channel();
        self.send_command(ProxyCommand::Resume {
            direction,
            connection_id,
            reply,
        })
        .await?;
        await_command_response(response).await
    }

    async fn send_command(&self, command: ProxyCommand) -> Result<()> {
        tokio::time::timeout(COMMAND_TIMEOUT, self.command_tx.send(command))
            .await
            .map_err(|_| HarnessError::Timeout("proxy command queue send timed out".to_owned()))?
            .map_err(|_| HarnessError::Proxy("proxy command loop is closed".to_owned()))
    }

    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        if let Some(task) = self.accept_task.take() {
            task.await
                .map_err(|error| HarnessError::Proxy(error.to_string()))?;
        }
        Ok(())
    }
}

async fn await_command_response(response: oneshot::Receiver<Result<()>>) -> Result<()> {
    tokio::time::timeout(COMMAND_TIMEOUT, response)
        .await
        .map_err(|_| HarnessError::Timeout("proxy command response timed out".to_owned()))?
        .map_err(|_| HarnessError::Proxy("proxy command response was dropped".to_owned()))?
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        let _ = self.shutdown_tx.send(());
        if let Some(task) = self.accept_task.take() {
            task.abort();
        }
    }
}

async fn accept_loop(
    context: AcceptContext,
    mut shutdown: broadcast::Receiver<()>,
    mut commands: mpsc::Receiver<ProxyCommand>,
) {
    let AcceptContext {
        listener,
        target_addr,
        faults,
        read_buffer_bytes,
        stats,
        active_connections,
    } = context;
    let mut connections = JoinSet::new();
    let mut routes = HashMap::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.recv() => break,
            Some(joined) = connections.join_next() => {
                if let Ok((connection_id, _result)) = joined {
                    routes.remove(&connection_id);
                }
                continue;
            }
            command = commands.recv() => {
                match command {
                    Some(command) => route_command(command, &routes),
                    None => break,
                }
                continue;
            }
            result = listener.accept() => result,
        };
        let (client, source_addr) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("tunnel-test-harness proxy accept failed: {error}");
                continue;
            }
        };
        let connection_stats = Arc::clone(&stats);
        let connection_active = Arc::clone(&active_connections);
        let connection_faults = faults.clone();
        let connection_id = record_accept(&stats, &active_connections, source_addr);
        let active = stats.active.load(Ordering::Relaxed);
        if active > MAX_ACTIVE_CONNECTIONS {
            // The listener has accepted the socket and assigned it a stable
            // ID, but refuses to retain an unbounded number of live routes.
            // Dropping the stream is the bounded overload behavior.
            remove_active_connection(&active_connections, connection_id);
            stats.active.fetch_sub(1, Ordering::Relaxed);
            stats.completed.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let (connection_commands_tx, connection_commands_rx) =
            mpsc::channel(CONNECTION_COMMAND_CAPACITY);
        let close_reply: CloseReply = Arc::new(std::sync::Mutex::new(None));
        let connection_shutdown = shutdown.resubscribe();
        routes.insert(connection_id, connection_commands_tx);
        connections.spawn(async move {
            let connection_control = ConnectionControl {
                shutdown: connection_shutdown,
                commands: connection_commands_rx,
                close_reply: Arc::clone(&close_reply),
            };
            let result = proxy_connection(
                client,
                target_addr,
                connection_faults,
                read_buffer_bytes,
                Arc::clone(&connection_stats),
                connection_control,
            )
            .await;
            if let Err(error) = &result {
                eprintln!("tunnel-test-harness proxy connection ended: {error}");
            }
            connection_stats.active.fetch_sub(1, Ordering::Relaxed);
            remove_active_connection(&connection_active, connection_id);
            connection_stats.completed.fetch_add(1, Ordering::Relaxed);
            if let Ok(mut close_reply) = close_reply.lock()
                && let Some(reply) = close_reply.take()
            {
                let _ = reply.send(Ok(()));
            }
            (connection_id, result)
        });
    }
    // A shutdown signal is forwarded to every active connection.  Join all
    // of them before the listener task completes so a test cannot leave a
    // TLS-pass-through socket or its copy tasks behind.
    while connections.join_next().await.is_some() {}
}

fn record_accept(
    stats: &StatsInner,
    active_connections: &ActiveConnections,
    source_addr: SocketAddr,
) -> ConnectionId {
    let connection_id = stats.accepted.load(Ordering::Relaxed) + 1;
    stats
        .last_connection_id
        .store(connection_id, Ordering::Relaxed);
    let active = stats.active.fetch_add(1, Ordering::Relaxed) + 1;
    update_peak(&stats.peak_active, active);
    if let Ok(mut recent) = stats.recent_connection_ids.lock() {
        recent.push_back(ConnectionId(connection_id));
        while recent.len() > MAX_RECENT_CONNECTION_IDS {
            recent.pop_front();
        }
    }
    if active <= MAX_ACTIVE_CONNECTIONS
        && let Ok(mut active_connections) = active_connections.lock()
    {
        active_connections.insert(
            ConnectionId(connection_id),
            ProxyConnection {
                id: ConnectionId(connection_id),
                source_addr,
            },
        );
    }
    stats.accepted.store(connection_id, Ordering::Release);
    ConnectionId(connection_id)
}

fn remove_active_connection(active_connections: &ActiveConnections, connection_id: ConnectionId) {
    if let Ok(mut active_connections) = active_connections.lock() {
        active_connections.remove(&connection_id);
    }
}

fn snapshot_active_connections(active_connections: &ActiveConnections) -> Vec<ProxyConnection> {
    let mut snapshot: Vec<ProxyConnection> = active_connections
        .lock()
        .map(|connections| connections.values().copied().collect())
        .unwrap_or_default();
    snapshot.sort_by_key(|connection| connection.id);
    snapshot
}

fn update_peak(peak: &AtomicU64, current: u64) {
    let mut observed = peak.load(Ordering::Relaxed);
    while current > observed {
        match peak.compare_exchange_weak(observed, current, Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => break,
            Err(next) => observed = next,
        }
    }
}

fn route_command(
    command: ProxyCommand,
    routes: &HashMap<ConnectionId, mpsc::Sender<ConnectionCommand>>,
) {
    let (connection_id, command) = match command {
        ProxyCommand::Close {
            connection_id,
            reply,
        } => (connection_id, ConnectionCommand::Close { reply }),
        ProxyCommand::Pause {
            direction,
            connection_id,
            reply,
        } => (connection_id, ConnectionCommand::Pause { direction, reply }),
        ProxyCommand::Resume {
            direction,
            connection_id,
            reply,
        } => (
            connection_id,
            ConnectionCommand::Resume { direction, reply },
        ),
    };
    let sender = match routes.get(&connection_id) {
        Some(sender) => sender,
        None => {
            reject_connection_command(
                command,
                format!("connection {connection_id:?} is not active"),
            );
            return;
        }
    };
    if let Err(error) = sender.try_send(command) {
        match error {
            mpsc::error::TrySendError::Full(command) => {
                reject_connection_command(command, "connection command queue is full".to_owned());
            }
            mpsc::error::TrySendError::Closed(command) => {
                reject_connection_command(command, "connection command loop is closed".to_owned());
            }
        }
    }
}

fn reject_connection_command(command: ConnectionCommand, message: String) {
    let result = Err(HarnessError::Proxy(message));
    match command {
        ConnectionCommand::Close { reply }
        | ConnectionCommand::Pause { reply, .. }
        | ConnectionCommand::Resume { reply, .. } => {
            let _ = reply.send(result);
        }
    }
}

async fn proxy_connection(
    client: TcpStream,
    target_addr: SocketAddr,
    faults: FaultScript,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    mut control: ConnectionControl,
) -> Result<()> {
    let client_to_target = Arc::new(DirectionControl::default());
    let target_to_client = Arc::new(DirectionControl::default());
    let target_connect = TcpStream::connect(target_addr);
    tokio::pin!(target_connect);
    let connect_deadline = Instant::now() + CONNECT_TIMEOUT;
    let target = loop {
        let remaining = connect_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "proxy target connection timed out".to_owned(),
            ));
        }
        tokio::select! {
            target = tokio::time::timeout(remaining, &mut target_connect) => {
                break target
                    .map_err(|_| HarnessError::Timeout("proxy target connection timed out".to_owned()))??;
            },
            Some(command) = control.commands.recv() => {
                if handle_connection_command(
                    command,
                    &stats,
                    &client_to_target,
                    &target_to_client,
                    false,
                    &control.close_reply,
                ) {
                    return Ok(());
                }
            },
            _ = control.shutdown.recv() => return Ok(()),
        }
    };
    let (client_read, client_write) = client.into_split();
    let (target_read, target_write) = target.into_split();
    let up = copy_direction(
        client_read,
        target_write,
        Direction::ClientToTarget,
        faults.for_direction(Direction::ClientToTarget),
        read_buffer_bytes,
        Arc::clone(&stats),
        Arc::clone(&client_to_target),
    );
    let down = copy_direction(
        target_read,
        client_write,
        Direction::TargetToClient,
        faults.for_direction(Direction::TargetToClient),
        read_buffer_bytes,
        Arc::clone(&stats),
        Arc::clone(&target_to_client),
    );
    let joined = async {
        tokio::pin!(up);
        tokio::pin!(down);
        tokio::select! {
            result = &mut up => match result {
                Ok(()) => down.await,
                Err(error) => Err(error),
            },
            result = &mut down => match result {
                Ok(()) => up.await,
                Err(error) => Err(error),
            },
        }
    };
    tokio::pin!(joined);
    loop {
        tokio::select! {
            joined = &mut joined => return joined,
            Some(command) = control.commands.recv() => {
                if handle_connection_command(
                    command,
                    &stats,
                    &client_to_target,
                    &target_to_client,
                    true,
                    &control.close_reply,
                ) {
                    return Ok(());
                }
            },
            _ = control.shutdown.recv() => return Ok(()),
        }
    }
}

struct DirectionControl {
    paused: AtomicBool,
    at_barrier: AtomicBool,
    ended: AtomicBool,
    changed: Notify,
    pause_state: std::sync::Mutex<PauseState>,
}

struct PauseState {
    deadline: Option<Instant>,
    reply: Option<oneshot::Sender<Result<()>>>,
}

impl Default for DirectionControl {
    fn default() -> Self {
        Self {
            paused: AtomicBool::new(false),
            at_barrier: AtomicBool::new(false),
            ended: AtomicBool::new(false),
            changed: Notify::new(),
            pause_state: std::sync::Mutex::new(PauseState {
                deadline: None,
                reply: None,
            }),
        }
    }
}

impl DirectionControl {
    fn pause(&self, reply: oneshot::Sender<Result<()>>, immediate: bool) {
        if self.ended.load(Ordering::Acquire) {
            let _ = reply.send(Ok(()));
            return;
        }
        let mut reject = Some(reply);
        if let Ok(mut state) = self.pause_state.lock() {
            if self.paused.load(Ordering::Acquire) {
                if self.at_barrier.load(Ordering::Acquire) {
                    if let Some(reply) = reject.take() {
                        let _ = reply.send(Ok(()));
                    }
                } else if state.reply.is_none() {
                    state.reply = reject.take();
                }
            } else {
                state.deadline = Some(Instant::now() + PAUSE_TIMEOUT);
                if !immediate {
                    state.reply = reject.take();
                }
                self.at_barrier.store(false, Ordering::Release);
                self.paused.store(true, Ordering::Release);
                if immediate {
                    self.at_barrier.store(true, Ordering::Release);
                    if let Some(reply) = reject.take() {
                        let _ = reply.send(Ok(()));
                    }
                }
            }
        }
        if let Some(reply) = reject {
            let _ = reply.send(Err(HarnessError::Proxy(
                "duplicate pause command is already pending".to_owned(),
            )));
        }
        self.changed.notify_one();
    }

    fn resume(&self, reply: oneshot::Sender<Result<()>>) {
        self.paused.store(false, Ordering::Release);
        self.at_barrier.store(false, Ordering::Release);
        if let Ok(mut state) = self.pause_state.lock() {
            state.deadline = None;
            if let Some(pause_reply) = state.reply.take() {
                let _ = pause_reply.send(Err(HarnessError::Proxy(
                    "pause superseded by resume".to_owned(),
                )));
            }
        }
        self.changed.notify_one();
        let _ = reply.send(Ok(()));
    }

    fn expire_pause(&self) {
        self.paused.store(false, Ordering::Release);
        self.at_barrier.store(false, Ordering::Release);
        if let Ok(mut state) = self.pause_state.lock() {
            state.deadline = None;
            if let Some(pause_reply) = state.reply.take() {
                let _ = pause_reply.send(Err(HarnessError::Timeout(
                    "proxy direction pause exceeded its hard timeout".to_owned(),
                )));
            }
        }
        self.changed.notify_one();
    }

    fn is_paused(&self) -> bool {
        self.paused.load(Ordering::Acquire)
    }

    fn pause_remaining(&self) -> Option<Duration> {
        self.pause_state
            .lock()
            .ok()
            .and_then(|state| state.deadline)
            .map(|deadline| deadline.saturating_duration_since(Instant::now()))
    }

    fn reach_barrier(&self) {
        if !self.is_paused() {
            return;
        }
        self.at_barrier.store(true, Ordering::Release);
        if let Ok(mut state) = self.pause_state.lock()
            && let Some(reply) = state.reply.take()
        {
            let _ = reply.send(Ok(()));
        }
    }

    fn end(&self, result: &Result<()>) {
        self.ended.store(true, Ordering::Release);
        if let Ok(mut state) = self.pause_state.lock()
            && let Some(reply) = state.reply.take()
        {
            let outcome = match result {
                Ok(()) => Ok(()),
                Err(error) => Err(HarnessError::Proxy(error.to_string())),
            };
            let _ = reply.send(outcome);
        }
    }

    fn cancel_pause(&self) {
        if let Ok(mut state) = self.pause_state.lock()
            && let Some(reply) = state.reply.take()
        {
            let _ = reply.send(Err(HarnessError::Proxy(
                "connection closed while pause was pending".to_owned(),
            )));
        }
    }
}

fn handle_connection_command(
    command: ConnectionCommand,
    stats: &StatsInner,
    client_to_target: &DirectionControl,
    target_to_client: &DirectionControl,
    immediate_pause: bool,
    close_reply: &CloseReply,
) -> bool {
    match command {
        ConnectionCommand::Close { reply } => {
            stats.closes.fetch_add(1, Ordering::Relaxed);
            client_to_target.cancel_pause();
            target_to_client.cancel_pause();
            if let Ok(mut close_reply) = close_reply.lock() {
                *close_reply = Some(reply);
            }
            true
        }
        ConnectionCommand::Pause { direction, reply } => {
            match direction {
                Direction::ClientToTarget => {
                    client_to_target.pause(reply, immediate_pause);
                }
                Direction::TargetToClient => {
                    target_to_client.pause(reply, immediate_pause);
                }
            }
            increment_pause(stats, direction);
            false
        }
        ConnectionCommand::Resume { direction, reply } => {
            match direction {
                Direction::ClientToTarget => {
                    client_to_target.resume(reply);
                }
                Direction::TargetToClient => {
                    target_to_client.resume(reply);
                }
            }
            false
        }
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectionFault {
    pause: Option<Duration>,
    drop_bytes: u64,
    close_after: Option<u64>,
}

async fn copy_direction<R, W>(
    reader: R,
    writer: W,
    direction: Direction,
    fault: DirectionFault,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    control: Arc<DirectionControl>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let result = copy_direction_inner(
        reader,
        writer,
        direction,
        fault,
        read_buffer_bytes,
        stats,
        Arc::clone(&control),
    )
    .await;
    control.end(&result);
    result
}

async fn copy_direction_inner<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    mut fault: DirectionFault,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    control: Arc<DirectionControl>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; read_buffer_bytes];
    let mut observed = 0_u64;
    loop {
        wait_if_paused(&control).await?;
        let read = loop {
            let notified = control.changed.notified();
            tokio::pin!(notified);
            if control.is_paused() {
                wait_if_paused(&control).await?;
                continue;
            }
            tokio::select! {
                read = reader.read(&mut buffer) => break read?,
                _ = &mut notified => {
                    // A pause command must interrupt an otherwise idle read
                    // so its hard timeout remains effective even with no
                    // incoming application bytes.
                    continue;
                }
            }
        };
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let read = read as u64;
        observed = observed.saturating_add(read);
        add_bytes(&stats, direction, read);
        if let Some(pause) = fault.pause {
            increment_pause(&stats, direction);
            tokio::time::sleep(pause).await;
            fault.pause = None;
        }
        // A command may have arrived while the read was in progress.  Check
        // again before writing so paused traffic never crosses the proxy.
        wait_if_paused(&control).await?;
        let mut start = 0_usize;
        if fault.drop_bytes > 0 {
            let drop = fault.drop_bytes.min(read) as usize;
            fault.drop_bytes -= drop as u64;
            start = drop;
            add_dropped(&stats, direction, drop as u64);
        }
        if let Some(close_after) = fault.close_after
            && observed >= close_after
        {
            stats.closes.fetch_add(1, Ordering::Relaxed);
            writer.shutdown().await?;
            return Ok(());
        }
        if start < read as usize {
            write_with_control(&mut writer, &buffer[start..read as usize], &control).await?;
        }
    }
}

async fn wait_if_paused(control: &DirectionControl) -> Result<()> {
    while control.is_paused() {
        let remaining = control.pause_remaining().unwrap_or(PAUSE_TIMEOUT);
        if remaining.is_zero() {
            control.expire_pause();
            return Err(HarnessError::Timeout(
                "proxy direction pause exceeded its hard timeout".to_owned(),
            ));
        }
        control.reach_barrier();
        let notified = control.changed.notified();
        if !control.is_paused() {
            continue;
        }
        if tokio::time::timeout(remaining, notified).await.is_err() {
            control.expire_pause();
            return Err(HarnessError::Timeout(
                "proxy direction pause exceeded its hard timeout".to_owned(),
            ));
        }
    }
    Ok(())
}

async fn write_with_control<W>(
    writer: &mut W,
    bytes: &[u8],
    control: &DirectionControl,
) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let mut offset = 0_usize;
    while offset < bytes.len() {
        wait_if_paused(control).await?;
        let written = writer.write(&bytes[offset..]).await?;
        if written == 0 {
            return Err(HarnessError::Proxy(
                "proxy target closed while forwarding bytes".to_owned(),
            ));
        }
        offset += written;
    }
    Ok(())
}

fn add_bytes(stats: &StatsInner, direction: Direction, bytes: u64) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .bytes_client_to_target
                .fetch_add(bytes, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .bytes_target_to_client
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

fn add_dropped(stats: &StatsInner, direction: Direction, bytes: u64) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .dropped_client_to_target
                .fetch_add(bytes, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .dropped_target_to_client
                .fetch_add(bytes, Ordering::Relaxed);
        }
    }
}

fn increment_pause(stats: &StatsInner, direction: Direction) {
    match direction {
        Direction::ClientToTarget => {
            stats
                .paused_client_to_target
                .fetch_add(1, Ordering::Relaxed);
        }
        Direction::TargetToClient => {
            stats
                .paused_target_to_client
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConnectionId, Direction, FaultAction, FaultScript, MAX_RECENT_CONNECTION_IDS, ProxyConfig,
        ProxyConnection, ProxyHandle, TcpProxy,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio::task::JoinSet;
    use tokio::time::{Duration, sleep, timeout};

    async fn wait_for_accepts(proxy: &ProxyHandle, count: u64) {
        for _ in 0..100 {
            if proxy.stats().accepted >= count {
                return;
            }
            sleep(Duration::from_millis(1)).await;
        }
        panic!(
            "proxy did not accept {count} connections: {:?}",
            proxy.stats()
        );
    }

    async fn spawn_echo_target(listener: TcpListener, count: usize) {
        let mut workers = JoinSet::new();
        for _ in 0..count {
            let (mut stream, _) = listener.accept().await.expect("accept");
            workers.spawn(async move {
                let mut buffer = [0_u8; 1024];
                loop {
                    let read = stream.read(&mut buffer).await.expect("read");
                    if read == 0 {
                        return;
                    }
                    stream.write_all(&buffer[..read]).await.expect("write");
                }
            });
        }
        while workers.join_next().await.is_some() {}
    }

    #[tokio::test]
    async fn opaque_proxy_forwards_bytes_and_records_counts() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept");
            let mut bytes = [0_u8; 5];
            stream.read_exact(&mut bytes).await.expect("read");
            stream.write_all(&bytes).await.expect("write");
        });
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        client.write_all(b"a\0b\xff\0").await.expect("client write");
        let mut response = [0_u8; 5];
        client.read_exact(&mut response).await.expect("client read");
        assert_eq!(&response, b"a\0b\xff\0");
        client.shutdown().await.expect("client shutdown");
        target_task.await.expect("target task");
        let stats = proxy.stats();
        assert_eq!(stats.accepted, 1);
        assert!(stats.bytes_client_to_target >= 5);
        assert!(stats.bytes_target_to_client >= 5);
        proxy.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn drop_fault_is_visible() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(async move {
            let (mut stream, _) = target.accept().await.expect("accept");
            let mut bytes = [0_u8; 2];
            let _ = stream.read_exact(&mut bytes).await;
        });
        let config = ProxyConfig {
            fault_script: FaultScript::default()
                .with_rule(Direction::ClientToTarget, FaultAction::DropBytes(2)),
            ..ProxyConfig::default()
        };
        let proxy = TcpProxy::bind(target_addr, config).await.expect("proxy");
        let mut client = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("client");
        client.write_all(b"drop").await.expect("client write");
        client.shutdown().await.expect("client shutdown");
        target_task.await.expect("target task");
        assert!(proxy.stats().dropped_client_to_target >= 2);
        proxy.shutdown().await.expect("shutdown");
    }

    #[tokio::test]
    async fn targeted_close_only_closes_the_selected_serialized_connection() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 2));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");

        let mut control = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("control");
        let control_source = control.local_addr().expect("control source");
        wait_for_accepts(&proxy, 1).await;
        let mut data = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("data");
        let data_source = data.local_addr().expect("data source");
        wait_for_accepts(&proxy, 2).await;
        let diagnostics = proxy.diagnostics();
        assert_eq!(diagnostics.recent_connection_ids[0], ConnectionId::new(1));
        assert_eq!(diagnostics.last_connection_id, Some(ConnectionId::new(2)));
        assert_eq!(
            diagnostics.active_connections,
            vec![
                ProxyConnection {
                    id: ConnectionId::new(1),
                    source_addr: control_source,
                },
                ProxyConnection {
                    id: ConnectionId::new(2),
                    source_addr: data_source,
                },
            ]
        );

        proxy.close(ConnectionId::new(2)).await.expect("close data");
        assert_eq!(proxy.stats().active, 1);
        assert_eq!(
            proxy.connections(),
            vec![ProxyConnection {
                id: ConnectionId::new(1),
                source_addr: control_source,
            }]
        );
        let mut closed = [0_u8; 1];
        assert_eq!(data.read(&mut closed).await.expect("data eof"), 0);

        control.write_all(b"control").await.expect("control write");
        let mut response = [0_u8; 7];
        control
            .read_exact(&mut response)
            .await
            .expect("control read");
        assert_eq!(&response, b"control");
        assert_eq!(proxy.stats().closes, 1);

        drop(data);
        control.shutdown().await.expect("control shutdown");
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn targeted_pause_and_resume_only_stall_one_direction() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 2));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut control = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("control");
        wait_for_accepts(&proxy, 1).await;
        let mut data = tokio::net::TcpStream::connect(proxy.local_addr())
            .await
            .expect("data");
        wait_for_accepts(&proxy, 2).await;
        let id = proxy
            .diagnostics()
            .last_connection_id
            .expect("data connection id");

        proxy
            .pause(Direction::ClientToTarget, id)
            .await
            .expect("pause");
        data.write_all(b"paused").await.expect("data write");
        let mut response = [0_u8; 6];
        assert!(
            timeout(Duration::from_millis(50), data.read(&mut response))
                .await
                .is_err()
        );
        control.write_all(b"control").await.expect("control write");
        let mut control_response = [0_u8; 7];
        control
            .read_exact(&mut control_response)
            .await
            .expect("control read");
        assert_eq!(&control_response, b"control");
        proxy
            .resume(Direction::ClientToTarget, id)
            .await
            .expect("resume");
        data.read_exact(&mut response).await.expect("resumed read");
        assert_eq!(&response, b"paused");
        assert_eq!(proxy.stats().paused_client_to_target, 1);

        control.shutdown().await.expect("control shutdown");
        data.shutdown().await.expect("data shutdown");
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }

    #[tokio::test]
    async fn snapshots_are_bounded_and_record_peak_active_connections() {
        let target = TcpListener::bind(("127.0.0.1", 0)).await.expect("target");
        let target_addr = target.local_addr().expect("target addr");
        let target_task = tokio::spawn(spawn_echo_target(target, 3));
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default())
            .await
            .expect("proxy");
        let mut clients = Vec::new();
        for _ in 0..3 {
            clients.push(
                tokio::net::TcpStream::connect(proxy.local_addr())
                    .await
                    .expect("client"),
            );
        }
        wait_for_accepts(&proxy, 3).await;
        let snapshot = proxy.diagnostics();
        assert_eq!(snapshot.peak_active, 3);
        assert_eq!(snapshot.last_connection_id, Some(ConnectionId::new(3)));
        assert!(snapshot.recent_connection_ids.len() <= MAX_RECENT_CONNECTION_IDS);
        assert_eq!(
            snapshot.recent_connection_ids,
            vec![
                ConnectionId::new(1),
                ConnectionId::new(2),
                ConnectionId::new(3),
            ]
        );
        assert_eq!(snapshot.active_connections.len(), 3);
        for (index, client) in clients.iter().enumerate() {
            assert_eq!(
                snapshot.active_connections[index].id,
                ConnectionId::new(index as u64 + 1)
            );
            assert_eq!(
                snapshot.active_connections[index].source_addr,
                client.local_addr().expect("client source")
            );
        }

        drop(clients);
        proxy.shutdown().await.expect("shutdown");
        target_task.await.expect("target task");
    }
}
