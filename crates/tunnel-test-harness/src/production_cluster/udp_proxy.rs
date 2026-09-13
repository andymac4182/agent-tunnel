//! Bounded loopback UDP path fault injection for the production cluster gate.
//!
//! The proxy is deliberately a byte forwarder.  It does not parse QUIC or
//! inspect application content.  Each client source address gets one
//! connected upstream socket, so replies cannot be delivered to a different
//! relay when several peer clients use the same advertised endpoint.

use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{net::UdpSocket, sync::mpsc, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;

use crate::{HarnessError, Result};

const MAX_CLIENT_FLOWS: usize = 32;
const MAX_DATAGRAM_BYTES: usize = 64 * 1024;
const FLOW_IDLE_TIMEOUT: Duration = Duration::from_secs(2);
const IO_TIMEOUT: Duration = Duration::from_millis(500);
const SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(5);

struct Flow {
    id: u64,
    socket: Arc<UdpSocket>,
    task: Option<JoinHandle<()>>,
}

struct FlowEnded {
    client: SocketAddr,
    id: u64,
}

#[derive(Clone)]
struct FlowDropControl {
    packets: Arc<AtomicBool>,
    clients: Arc<Mutex<HashSet<SocketAddr>>>,
}

impl Drop for Flow {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

/// A bounded one-destination UDP forwarder with a switchable packet drop.
pub(crate) struct UdpFaultProxy {
    address: SocketAddr,
    drop_packets: Arc<AtomicBool>,
    drop_clients: Arc<Mutex<HashSet<SocketAddr>>>,
    cancel: CancellationToken,
    task: Option<JoinHandle<Result<()>>>,
}

impl UdpFaultProxy {
    pub(crate) async fn bind(server_address: SocketAddr) -> Result<Self> {
        let socket = Arc::new(
            UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("binding M7 production UDP proxy: {error}"))
                })?,
        );
        let address = socket.local_addr().map_err(|error| {
            HarnessError::Http(format!("reading M7 production UDP proxy address: {error}"))
        })?;
        let target_text = server_address.to_string();
        let local_text = address.to_string();
        crate::c11_capture::record_sentinel("private_endpoint", target_text.as_bytes())?;
        crate::c11_capture::record_sentinel("private_endpoint", local_text.as_bytes())?;
        let drop_packets = Arc::new(AtomicBool::new(false));
        let drop_clients = Arc::new(Mutex::new(HashSet::new()));
        let cancel = CancellationToken::new();
        let (ended_tx, ended_rx) = mpsc::channel(MAX_CLIENT_FLOWS * 2);
        let task = tokio::spawn(run_proxy(
            socket,
            server_address,
            drop_packets.clone(),
            drop_clients.clone(),
            cancel.clone(),
            ended_rx,
            ended_tx,
        ));
        Ok(Self {
            address,
            drop_packets,
            drop_clients,
            cancel,
            task: Some(task),
        })
    }

    pub(crate) fn address(&self) -> SocketAddr {
        self.address
    }

    pub(crate) fn set_drop(&self, drop_packets: bool) {
        self.drop_packets.store(drop_packets, Ordering::Release);
    }

    pub(crate) fn set_drop_for_client(&self, client: SocketAddr, drop_packets: bool) -> Result<()> {
        let mut clients = self.drop_clients.lock().map_err(|_| {
            HarnessError::Process("M7 production UDP proxy client-drop state was poisoned".into())
        })?;
        if drop_packets {
            if clients.len() >= MAX_CLIENT_FLOWS && !clients.contains(&client) {
                return Err(HarnessError::Process(
                    "M7 production UDP proxy client-drop bound was exceeded".into(),
                ));
            }
            clients.insert(client);
        } else {
            clients.remove(&client);
        }
        Ok(())
    }

    pub(crate) async fn shutdown(&mut self) -> Result<()> {
        self.cancel.cancel();
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(SHUTDOWN_TIMEOUT, &mut task).await {
            Ok(Ok(Ok(()))) => Ok(()),
            Ok(Ok(Err(error))) => Err(error),
            Ok(Err(error)) => Err(HarnessError::Http(format!(
                "M7 production UDP proxy task: {error}"
            ))),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err(HarnessError::Timeout(
                    "M7 production UDP proxy shutdown timed out".to_owned(),
                ))
            }
        }
    }
}

impl Drop for UdpFaultProxy {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

async fn run_proxy(
    socket: Arc<UdpSocket>,
    server_address: SocketAddr,
    drop_packets: Arc<AtomicBool>,
    drop_clients: Arc<Mutex<HashSet<SocketAddr>>>,
    cancel: CancellationToken,
    mut ended_rx: mpsc::Receiver<FlowEnded>,
    ended_tx: mpsc::Sender<FlowEnded>,
) -> Result<()> {
    let mut flows = HashMap::<SocketAddr, Flow>::new();
    let mut next_id = 1_u64;
    let mut packet = [0_u8; MAX_DATAGRAM_BYTES];
    let mut ended_open = true;

    let result = loop {
        tokio::select! {
            _ = cancel.cancelled() => break Ok(()),
            event = ended_rx.recv(), if ended_open => {
                match event {
                    Some(event) => remove_flow(&mut flows, event).await,
                    None => ended_open = false,
                }
            }
            received = socket.recv_from(&mut packet) => {
                let (length, client) = match received {
                    Ok(received) => received,
                    Err(error) => break Err(HarnessError::Http(format!(
                        "receiving M7 production UDP proxy datagram: {error}"
                    ))),
                };
                if client == server_address || should_drop(&drop_packets, &drop_clients, client) {
                    continue;
                }

                if !flows.contains_key(&client) {
                    if flows.len() >= MAX_CLIENT_FLOWS {
                        // Saturation is a bounded drop.  There is no TCP or
                        // alternate endpoint fallback.
                        continue;
                    }
                    let upstream = match UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
                        .await
                    {
                        Ok(upstream) => Arc::new(upstream),
                        Err(error) => {
                            break Err(HarnessError::Http(format!(
                                "binding M7 UDP proxy flow: {error}"
                            )))
                        }
                    };
                    if let Err(error) = upstream.connect(server_address).await {
                        break Err(HarnessError::Http(format!(
                            "connecting M7 UDP proxy flow: {error}"
                        )));
                    }
                    let id = next_id;
                    next_id = next_id.wrapping_add(1).max(1);
                    let task = tokio::spawn(run_flow(
                        client,
                        id,
                        upstream.clone(),
                        socket.clone(),
                        FlowDropControl {
                            packets: drop_packets.clone(),
                            clients: drop_clients.clone(),
                        },
                        cancel.clone(),
                        ended_tx.clone(),
                    ));
                    flows.insert(
                        client,
                        Flow {
                            id,
                            socket: upstream,
                            task: Some(task),
                        },
                    );
                }

                let Some((flow_id, upstream)) = flows
                    .get(&client)
                    .map(|flow| (flow.id, flow.socket.clone()))
                else {
                    continue;
                };
                if !matches!(
                    timeout(IO_TIMEOUT, upstream.send(&packet[..length])).await,
                    Ok(Ok(_))
                ) {
                    remove_flow(
                        &mut flows,
                        FlowEnded {
                            client,
                            id: flow_id,
                        },
                    )
                    .await;
                }
            }
        }
    };

    for (_, mut flow) in flows {
        if let Some(task) = flow.task.take() {
            task.abort();
            let _ = task.await;
        }
    }
    result
}

async fn remove_flow(flows: &mut HashMap<SocketAddr, Flow>, event: FlowEnded) {
    let matches = flows
        .get(&event.client)
        .is_some_and(|flow| flow.id == event.id);
    if matches
        && let Some(mut flow) = flows.remove(&event.client)
        && let Some(task) = flow.task.take()
    {
        task.abort();
        let _ = task.await;
    }
}

async fn run_flow(
    client: SocketAddr,
    id: u64,
    upstream: Arc<UdpSocket>,
    downstream: Arc<UdpSocket>,
    drop_control: FlowDropControl,
    cancel: CancellationToken,
    ended_tx: mpsc::Sender<FlowEnded>,
) {
    let mut packet = [0_u8; MAX_DATAGRAM_BYTES];
    loop {
        let received = tokio::select! {
            _ = cancel.cancelled() => break,
            result = timeout(FLOW_IDLE_TIMEOUT, upstream.recv(&mut packet)) => result,
        };
        let Ok(Ok(length)) = received else {
            break;
        };
        if should_drop(&drop_control.packets, &drop_control.clients, client) {
            continue;
        }
        let sent = timeout(IO_TIMEOUT, downstream.send_to(&packet[..length], client)).await;
        if !matches!(sent, Ok(Ok(_))) {
            break;
        }
    }
    let _ = ended_tx.send(FlowEnded { client, id }).await;
}

fn should_drop(
    drop_packets: &AtomicBool,
    drop_clients: &Mutex<HashSet<SocketAddr>>,
    client: SocketAddr,
) -> bool {
    drop_packets.load(Ordering::Acquire)
        || drop_clients
            .lock()
            .map(|clients| clients.contains(&client))
            .unwrap_or(true)
}

#[cfg(test)]
mod tests {
    use super::UdpFaultProxy;
    use std::{
        net::SocketAddr,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{net::UdpSocket, task::JoinHandle, time::timeout};
    use tokio_util::sync::CancellationToken;

    async fn echo_server() -> (
        SocketAddr,
        Arc<AtomicUsize>,
        CancellationToken,
        JoinHandle<()>,
    ) {
        let socket = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("UDP echo server bind");
        let address = socket.local_addr().expect("UDP echo server address");
        let received = Arc::new(AtomicUsize::new(0));
        let count = received.clone();
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            let mut packet = [0_u8; 64 * 1024];
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    result = socket.recv_from(&mut packet) => {
                        let Ok((length, source)) = result else { break };
                        count.fetch_add(1, Ordering::AcqRel);
                        if socket.send_to(&packet[..length], source).await.is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (address, received, cancel, task)
    }

    async fn receive(socket: &UdpSocket) -> Vec<u8> {
        let mut packet = [0_u8; 128];
        let (length, _) = timeout(Duration::from_secs(1), socket.recv_from(&mut packet))
            .await
            .expect("UDP response deadline")
            .expect("UDP response");
        packet[..length].to_vec()
    }

    #[tokio::test]
    async fn simultaneous_clients_are_not_cross_routed() {
        let (server_address, received, server_cancel, server_task) = echo_server().await;
        let mut proxy = UdpFaultProxy::bind(server_address)
            .await
            .expect("UDP proxy bind");
        let first = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("first client bind");
        let second = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("second client bind");

        first
            .send_to(b"first", proxy.address())
            .await
            .expect("first datagram");
        second
            .send_to(b"second", proxy.address())
            .await
            .expect("second datagram");
        assert_eq!(receive(&first).await, b"first");
        assert_eq!(receive(&second).await, b"second");
        assert_eq!(received.load(Ordering::Acquire), 2);

        proxy.shutdown().await.expect("proxy shutdown");
        server_cancel.cancel();
        server_task.await.expect("server join");
    }

    #[tokio::test]
    async fn drop_and_restore_preserves_one_authenticated_udp_path() {
        let (server_address, received, server_cancel, server_task) = echo_server().await;
        let mut proxy = UdpFaultProxy::bind(server_address)
            .await
            .expect("UDP proxy bind");
        let client = UdpSocket::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .await
            .expect("client bind");

        client
            .send_to(b"before", proxy.address())
            .await
            .expect("baseline datagram");
        assert_eq!(receive(&client).await, b"before");

        proxy.set_drop(true);
        client
            .send_to(b"dropped", proxy.address())
            .await
            .expect("dropped datagram");
        let mut packet = [0_u8; 64];
        assert!(
            timeout(Duration::from_millis(250), client.recv_from(&mut packet))
                .await
                .is_err(),
            "dropped path produced a response"
        );
        assert_eq!(received.load(Ordering::Acquire), 1);

        proxy.set_drop(false);
        client
            .send_to(b"after", proxy.address())
            .await
            .expect("restored datagram");
        assert_eq!(receive(&client).await, b"after");
        assert_eq!(received.load(Ordering::Acquire), 2);

        proxy.shutdown().await.expect("proxy shutdown");
        server_cancel.cancel();
        server_task.await.expect("server join");
    }
}
