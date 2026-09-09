use crate::error::{HarnessError, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::task::{JoinHandle, JoinSet};

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
    completed: AtomicU64,
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
            accepted: inner.accepted.load(Ordering::Relaxed),
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
        let stats = Arc::new(StatsInner::default());
        let accept_stats = Arc::clone(&stats);
        let accept_faults = config.fault_script.clone();
        let read_buffer_bytes = config.read_buffer_bytes;
        let accept_shutdown = shutdown_tx.subscribe();
        let accept_task = tokio::spawn(async move {
            accept_loop(
                listener,
                target_addr,
                accept_faults,
                read_buffer_bytes,
                accept_stats,
                accept_shutdown,
            )
            .await;
        });
        Ok(ProxyHandle {
            local_addr,
            target_addr,
            stats,
            shutdown_tx,
            accept_task: Some(accept_task),
        })
    }
}

pub struct ProxyHandle {
    local_addr: SocketAddr,
    target_addr: SocketAddr,
    stats: Arc<StatsInner>,
    shutdown_tx: broadcast::Sender<()>,
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

    pub async fn shutdown(mut self) -> Result<()> {
        let _ = self.shutdown_tx.send(());
        if let Some(task) = self.accept_task.take() {
            task.await
                .map_err(|error| HarnessError::Proxy(error.to_string()))?;
        }
        Ok(())
    }
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
    listener: TcpListener,
    target_addr: SocketAddr,
    faults: FaultScript,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    mut shutdown: broadcast::Receiver<()>,
) {
    let mut connections = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            _ = shutdown.recv() => break,
            Some(_) = connections.join_next() => continue,
            result = listener.accept() => result,
        };
        let (client, _) = match accepted {
            Ok(connection) => connection,
            Err(error) => {
                eprintln!("tunnel-test-harness proxy accept failed: {error}");
                continue;
            }
        };
        let connection_stats = Arc::clone(&stats);
        let connection_faults = faults.clone();
        stats.accepted.fetch_add(1, Ordering::Relaxed);
        stats.active.fetch_add(1, Ordering::Relaxed);
        let connection_shutdown = shutdown.resubscribe();
        connections.spawn(async move {
            let result = proxy_connection(
                client,
                target_addr,
                connection_faults,
                read_buffer_bytes,
                Arc::clone(&connection_stats),
                connection_shutdown,
            )
            .await;
            if let Err(error) = result {
                eprintln!("tunnel-test-harness proxy connection ended: {error}");
            }
            connection_stats.active.fetch_sub(1, Ordering::Relaxed);
            connection_stats.completed.fetch_add(1, Ordering::Relaxed);
        });
    }
    // A shutdown signal is forwarded to every active connection.  Join all
    // of them before the listener task completes so a test cannot leave a
    // TLS-pass-through socket or its copy tasks behind.
    while connections.join_next().await.is_some() {}
}

async fn proxy_connection(
    client: TcpStream,
    target_addr: SocketAddr,
    faults: FaultScript,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
    mut shutdown: broadcast::Receiver<()>,
) -> Result<()> {
    let target = TcpStream::connect(target_addr).await?;
    let (client_read, client_write) = client.into_split();
    let (target_read, target_write) = target.into_split();
    let up = copy_direction(
        client_read,
        target_write,
        Direction::ClientToTarget,
        faults.for_direction(Direction::ClientToTarget),
        read_buffer_bytes,
        Arc::clone(&stats),
    );
    let down = copy_direction(
        target_read,
        client_write,
        Direction::TargetToClient,
        faults.for_direction(Direction::TargetToClient),
        read_buffer_bytes,
        Arc::clone(&stats),
    );
    tokio::select! {
        joined = async {
            let (up, down) = tokio::join!(up, down);
            up.and(down)
        } => joined,
        _ = shutdown.recv() => Ok(()),
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DirectionFault {
    pause: Option<Duration>,
    drop_bytes: u64,
    close_after: Option<u64>,
}

async fn copy_direction<R, W>(
    mut reader: R,
    mut writer: W,
    direction: Direction,
    mut fault: DirectionFault,
    read_buffer_bytes: usize,
    stats: Arc<StatsInner>,
) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut buffer = vec![0_u8; read_buffer_bytes];
    let mut observed = 0_u64;
    loop {
        let read = reader.read(&mut buffer).await?;
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
            writer.write_all(&buffer[start..read as usize]).await?;
        }
    }
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
    use super::{Direction, FaultAction, FaultScript, ProxyConfig, TcpProxy};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

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
}
