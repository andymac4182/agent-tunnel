//! Real device control/data attachment race for EC-041.
//!
//! This fixture is deliberately separate from C10.  C10 holds a public
//! consumer WSS admission; this fixture holds real device control WSS state,
//! captures the old attachment ticket/generation, replaces the complete Redis
//! owner token, and then exercises the owner-side data attachment through a
//! different relay.  The ticket itself is kept in memory only and never
//! enters evidence or diagnostics.

use super::ProductionCluster;
use crate::{
    ConnectionId, Direction, Harness, HarnessError, HarnessOptions, ProxyConfig, ProxyHandle,
    Result, RunningHarness as HarnessRuntime, TcpProxy,
};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    time::{Instant, sleep, timeout},
};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tunnel_catalog::OwnerClaim;
use tunnel_core::RotationConfig;
use tunnel_protocol::{
    ControlMessage, Hello, OwnerFenced, RotationPolicy, ServiceAdvertisement, Welcome,
    decode_control, encode_control,
};
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(90);
const PHASE_TIMEOUT: Duration = Duration::from_secs(15);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(20);
const QUIET_CONTROL_WINDOW: Duration = Duration::from_millis(300);
const POLL_INTERVAL: Duration = Duration::from_millis(25);

type DeviceSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

/// Payload-free evidence for the device control/data ticket race.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Ec041DeviceAttachmentEvidence {
    pub relay_count: usize,
    pub predecessor_owner_complete: bool,
    pub successor_owner_complete: bool,
    pub full_owner_token_replaced: bool,
    pub predecessor_generation: u64,
    pub successor_generation: u64,
    pub predecessor_ticket_captured: bool,
    pub successor_ticket_captured: bool,
    /// The stale predecessor ticket, presented through a remote data ingress
    /// to the successor owner, was refused with a transport close.
    pub stale_ticket_rejected: bool,
    pub stale_data_ready_absent: bool,
    pub stale_session_state_unchanged: bool,
    /// Two real device data attachments raced the same fresh successor ticket
    /// through two distinct non-owner ingress relays.
    pub concurrent_used_distinct_ingress: bool,
    /// Exactly one of the two concurrent presentations installed a carrier.
    pub concurrent_winner_count: usize,
    /// Exactly one of the two concurrent presentations was refused.
    pub concurrent_loser_count: usize,
    /// Exactly one `DATA_READY` reached the successor control channel across
    /// the whole concurrent race.
    pub concurrent_data_ready_count: usize,
    /// The generation carried by the winning attachment's `DATA_READY`.
    pub winner_generation: u64,
    /// The successor session moved control-only (one socket) to control+data
    /// (two sockets) exactly once at the ticket's own connection identity.
    pub winner_carrier_installed: bool,
    /// A second, sequential presentation of the now-consumed winning ticket
    /// (the loser's exact ticket) left the winner's session identity byte for
    /// byte unchanged: no counter reset, no reinstalled carrier.
    pub loser_caused_no_counter_reset: bool,
    pub fresh_ticket_reuse_rejected: bool,
    pub fresh_ticket_reuse_data_ready_absent: bool,
    pub cleanup_joined: bool,
}

pub fn validate_ec041_device_attachment_evidence(
    evidence: &Ec041DeviceAttachmentEvidence,
) -> Result<()> {
    let required = [
        ("three relays", evidence.relay_count == 3),
        ("predecessor owner", evidence.predecessor_owner_complete),
        ("successor owner", evidence.successor_owner_complete),
        ("full owner replacement", evidence.full_owner_token_replaced),
        (
            "predecessor ticket capture",
            evidence.predecessor_ticket_captured,
        ),
        (
            "successor ticket capture",
            evidence.successor_ticket_captured,
        ),
        ("stale ticket rejection", evidence.stale_ticket_rejected),
        ("stale DATA_READY absence", evidence.stale_data_ready_absent),
        (
            "stale session unchanged",
            evidence.stale_session_state_unchanged,
        ),
        (
            "distinct concurrent ingress",
            evidence.concurrent_used_distinct_ingress,
        ),
        (
            "winner carrier installed",
            evidence.winner_carrier_installed,
        ),
        (
            "loser caused no counter reset",
            evidence.loser_caused_no_counter_reset,
        ),
        (
            "fresh ticket one-use rejection",
            evidence.fresh_ticket_reuse_rejected,
        ),
        (
            "fresh ticket reuse DATA_READY absence",
            evidence.fresh_ticket_reuse_data_ready_absent,
        ),
        ("joined cleanup", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "EC-041 device attachment gate was false: {name}"
        )));
    }
    if evidence.predecessor_generation != 1 || evidence.successor_generation != 1 {
        return Err(HarnessError::Process(
            "EC-041 initial device attachment generation was not exactly one".into(),
        ));
    }
    if evidence.winner_generation != 1 {
        return Err(HarnessError::Process(
            "EC-041 winning attachment generation was not exactly one".into(),
        ));
    }
    if evidence.concurrent_winner_count != 1 {
        return Err(HarnessError::Process(format!(
            "EC-041 concurrent race did not have exactly one winner: {}",
            evidence.concurrent_winner_count
        )));
    }
    if evidence.concurrent_loser_count != 1 {
        return Err(HarnessError::Process(format!(
            "EC-041 concurrent race did not have exactly one loser: {}",
            evidence.concurrent_loser_count
        )));
    }
    if evidence.concurrent_data_ready_count != 1 {
        return Err(HarnessError::Process(format!(
            "EC-041 concurrent race did not produce exactly one DATA_READY: {}",
            evidence.concurrent_data_ready_count
        )));
    }
    Ok(())
}

/// Run the real three-relay device control/data attachment race.
pub async fn verify() -> Result<Ec041DeviceAttachmentEvidence> {
    let options = HarnessOptions::from_env()?
        // Keep this fixture on the normal long policy: it isolates owner/ticket
        // replacement and does not claim scheduled carrier-rotation coverage.
        .rotation(RotationConfig::default())
        .shared_device_uuid(true);
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("EC-041 harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; EC-041 harness cleanup failed: {cleanup}"
                ))),
            };
        }
    };

    let mut resources = AttachmentRaceResources::default();
    let scenario = timeout(
        SCENARIO_TIMEOUT,
        run_race(&mut cluster, &harness, &mut resources),
    )
    .await
    .map_err(|_| HarnessError::Timeout("EC-041 device attachment race timed out".into()))?;
    let cleanup = resources.cleanup().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    append_cleanup(&mut failure, "EC-041 attachment resources", cleanup);
    append_cleanup(&mut failure, "EC-041 relay cleanup", cluster_cleanup);
    append_cleanup(&mut failure, "EC-041 catalog cleanup", harness_cleanup);
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_ec041_device_attachment_evidence(evidence)
        {
            evidence.cleanup_joined = false;
            failure = Some(error);
        }
    }
    match (evidence, failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "EC-041 produced no evidence or failure".into(),
        )),
    }
}

/// The scenario returns its evidence before cleanup; keeping this helper
/// separate makes it impossible for the validator to mistake cleanup state for
/// a successful attachment assertion.
async fn run_race(
    cluster: &mut ProductionCluster,
    harness: &HarnessRuntime,
    resources: &mut AttachmentRaceResources,
) -> Result<Ec041DeviceAttachmentEvidence> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("EC-041 device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("EC-041 service is missing".into()))?;
    let tls = device_tls(harness, device)?;
    let scenario_deadline = Instant::now() + SCENARIO_TIMEOUT;

    let old_device_addr = relay_device_addr(cluster, "relay-a")?;
    let old_barrier = ControlOnlyBarrier::open(
        old_device_addr,
        Arc::clone(&tls),
        device.id,
        service_id,
        RotationConfig::default(),
    )
    .await?;
    resources.predecessor = Some(old_barrier);
    let predecessor_owner = wait_for_owner_on(
        cluster,
        device.tenant_id,
        device.id,
        "relay-a",
        scenario_deadline,
    )
    .await?;
    let predecessor_welcome = resources
        .predecessor
        .as_mut()
        .expect("predecessor barrier retained")
        .capture_control_only(&predecessor_owner.token, scenario_deadline)
        .await?;
    let predecessor_owner_complete =
        welcome_matches_owner(&predecessor_welcome, &predecessor_owner.token);
    if !predecessor_owner_complete {
        return Err(HarnessError::Process(
            "EC-041 predecessor WELCOME did not bind the complete owner token".into(),
        ));
    }
    let predecessor_ticket_captured = !predecessor_welcome.attachment_ticket.is_empty();
    let predecessor_generation = predecessor_welcome.generation;
    wait_for_control_only_session(
        cluster,
        device.id,
        &predecessor_owner.token,
        scenario_deadline,
    )
    .await?;

    // Drop only after the old owner has acknowledged OWNER_FENCED.  This
    // publishes a real complete owner transition instead of racing startup.
    let old = resources
        .predecessor
        .take()
        .expect("predecessor barrier retained");
    old.close(scenario_deadline).await?;
    wait_for_no_owner(cluster, device.tenant_id, device.id, scenario_deadline).await?;

    let successor_device_addr = relay_device_addr(cluster, "relay-b")?;
    let successor_barrier = ControlOnlyBarrier::open(
        successor_device_addr,
        Arc::clone(&tls),
        device.id,
        service_id,
        RotationConfig::default(),
    )
    .await?;
    resources.successor = Some(successor_barrier);
    let successor_owner = wait_for_owner_on(
        cluster,
        device.tenant_id,
        device.id,
        "relay-b",
        scenario_deadline,
    )
    .await?;
    let successor_welcome = resources
        .successor
        .as_mut()
        .expect("successor barrier retained")
        .capture_control_only(&successor_owner.token, scenario_deadline)
        .await?;
    let successor_owner_complete =
        welcome_matches_owner(&successor_welcome, &successor_owner.token);
    if !successor_owner_complete {
        return Err(HarnessError::Process(
            "EC-041 successor WELCOME did not bind the complete owner token".into(),
        ));
    }
    let successor_ticket_captured = !successor_welcome.attachment_ticket.is_empty();
    let successor_generation = successor_welcome.generation;
    let full_owner_token_replaced = full_owner_token_replaced(
        &predecessor_owner,
        &successor_owner,
        device.tenant_id,
        device.id,
    );
    if !full_owner_token_replaced {
        return Err(HarnessError::Process(
            "EC-041 successor did not replace the complete predecessor OwnerToken".into(),
        ));
    }

    // The successor session is control-only until a data socket attaches.
    wait_for_control_only_session(
        cluster,
        device.id,
        &successor_owner.token,
        scenario_deadline,
    )
    .await?;

    // ---- Stale predecessor ticket through a remote data ingress (relay-c) ----
    // relay-c is not the successor owner (relay-b), so this exercises the real
    // one-hop peer forward of a device data attachment to the owner.
    let before_stale =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    let stale_ingress = relay_device_addr(cluster, "relay-c")?;
    let stale_socket = open_data_socket(
        stale_ingress,
        Arc::clone(&tls),
        &predecessor_welcome.attachment_ticket,
        scenario_deadline,
    )
    .await?;
    let stale_ticket_rejected = expect_data_rejection(stale_socket, scenario_deadline).await?;
    let stale_data_ready_absent = resources
        .successor
        .as_mut()
        .expect("successor barrier retained")
        .expect_no_data_ready(scenario_deadline)
        .await?;
    let after_stale =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    let stale_session_state_unchanged = before_stale == after_stale;

    // ---- Concurrent fresh-ticket race through two distinct ingress relays ----
    // relay-a (the former owner, now a peer) and relay-c both forward the same
    // fresh successor ticket to owner relay-b.  The owner actor serializes the
    // one-use consume, so exactly one attachment wins.
    let ingress_a = relay_device_addr(cluster, "relay-a")?;
    let ingress_c = relay_device_addr(cluster, "relay-c")?;
    let concurrent_used_distinct_ingress = ingress_a != ingress_c
        && successor_owner.token.node_id == "relay-b"
        && successor_owner.token.node_id != "relay-a"
        && successor_owner.token.node_id != "relay-c";

    let before_race =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    let (socket_a, socket_c) = tokio::try_join!(
        open_data_socket(
            ingress_a,
            Arc::clone(&tls),
            &successor_welcome.attachment_ticket,
            scenario_deadline,
        ),
        open_data_socket(
            ingress_c,
            Arc::clone(&tls),
            &successor_welcome.attachment_ticket,
            scenario_deadline,
        ),
    )?;

    // Exactly one DATA_READY must reach the successor control channel for the
    // whole race; the winner's generation and reply binding are validated.
    let (winner_generation, first_ready_seen) = resources
        .successor
        .as_mut()
        .expect("successor barrier retained")
        .expect_data_ready_generation(&successor_welcome, scenario_deadline)
        .await?;
    let concurrent_data_ready_first = usize::from(first_ready_seen);

    // Classify both racing sockets: the winner stays open (its carrier is
    // installed and idle); the loser is closed by the owner.  Exactly one of
    // each is required.
    let outcome_a = classify_race_socket(socket_a, scenario_deadline).await?;
    let outcome_c = classify_race_socket(socket_c, scenario_deadline).await?;
    let mut concurrent_winner_count = 0_usize;
    let mut concurrent_loser_count = 0_usize;
    for outcome in [outcome_a, outcome_c] {
        match outcome {
            RaceSocketOutcome::Winner(socket) => {
                concurrent_winner_count += 1;
                // Retain the winning carrier socket for joined cleanup.
                resources.fresh_data = Some(*socket);
            }
            RaceSocketOutcome::Loser => concurrent_loser_count += 1,
        }
    }
    // No second DATA_READY may follow the winner's.
    let no_second_ready = resources
        .successor
        .as_mut()
        .expect("successor barrier retained")
        .expect_no_data_ready(scenario_deadline)
        .await?;
    let concurrent_data_ready_count = concurrent_data_ready_first + usize::from(!no_second_ready);

    let after_race =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    // The owner sends `DATA_READY` only after `attach_data_verified` installs
    // the carrier, and its context validates the winner's connection identity
    // and generation against the successor WELCOME.  Exactly one racing socket
    // stayed open.  So the carrier is proved installed exactly once, at the
    // initial generation, with no spurious rotation candidate, and the
    // successor session identity is otherwise unchanged.
    let winner_carrier_installed = concurrent_data_ready_first == 1
        && concurrent_winner_count == 1
        && after_race.generation == 1
        && after_race.candidate_generation.is_none()
        && after_race.epoch == before_race.epoch
        && after_race.session_id_digest == before_race.session_id_digest;

    // ---- Already-consumed reuse leaves the winner's state byte-for-byte intact ----
    // Present the now-spent winning ticket a third time through a remote
    // ingress.  It must be refused, produce no DATA_READY, and leave the
    // successor session identity exactly as the winner installed it: the losing
    // attachment resets no counter and reinstalls no carrier.
    let before_reuse =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    let reuse_socket = open_data_socket(
        ingress_c,
        Arc::clone(&tls),
        &successor_welcome.attachment_ticket,
        scenario_deadline,
    )
    .await?;
    let fresh_ticket_reuse_rejected =
        expect_data_rejection(reuse_socket, scenario_deadline).await?;
    let fresh_ticket_reuse_data_ready_absent = resources
        .successor
        .as_mut()
        .expect("successor barrier retained")
        .expect_no_data_ready(scenario_deadline)
        .await?;
    let after_reuse =
        session_identity(cluster, "relay-b", device.id, &successor_owner.token).await?;
    // The already-consumed ticket is a losing attachment.  Its rejection must
    // leave the winner's installed session identity byte for byte unchanged:
    // same generation, same active connection, no rotation candidate, no reset.
    let loser_caused_no_counter_reset = before_reuse == after_reuse;

    Ok(Ec041DeviceAttachmentEvidence {
        relay_count: cluster.relays.len(),
        predecessor_owner_complete,
        successor_owner_complete,
        full_owner_token_replaced,
        predecessor_generation,
        successor_generation,
        predecessor_ticket_captured,
        successor_ticket_captured,
        stale_ticket_rejected,
        stale_data_ready_absent,
        stale_session_state_unchanged,
        concurrent_used_distinct_ingress,
        concurrent_winner_count,
        concurrent_loser_count,
        concurrent_data_ready_count,
        winner_generation,
        winner_carrier_installed,
        loser_caused_no_counter_reset,
        fresh_ticket_reuse_rejected,
        fresh_ticket_reuse_data_ready_absent,
        cleanup_joined: false,
    })
}

/// The outcome of one racing data attachment socket.
enum RaceSocketOutcome {
    /// The owner installed this attachment; the socket remains open and idle.
    Winner(Box<DeviceSocket>),
    /// The owner refused this attachment; the socket was closed.
    Loser,
}

/// Classify a racing data socket.  A losing attachment is closed by the owner
/// (a transport close, an end of stream, or an error).  A winning attachment's
/// carrier is installed and idle, so its socket stays open through a bounded
/// quiet window and is returned for joined cleanup.  An application frame on a
/// racing socket is never expected and is a hard failure.
async fn classify_race_socket(
    mut socket: DeviceSocket,
    deadline: Instant,
) -> Result<RaceSocketOutcome> {
    let quiet_deadline = Instant::now()
        .checked_add(QUIET_CONTROL_WINDOW)
        .map_or(deadline, |candidate| candidate.min(deadline));
    loop {
        let remaining = quiet_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(RaceSocketOutcome::Winner(Box::new(socket)));
        }
        match timeout(remaining, socket.next()).await {
            Err(_) => return Ok(RaceSocketOutcome::Winner(Box::new(socket))),
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => {
                return Ok(RaceSocketOutcome::Loser);
            }
            Ok(Some(Ok(Message::Ping(payload)))) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| HarnessError::Http(format!("EC-041 race PONG: {error}")))?;
            }
            Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Frame(_)))) => {}
            Ok(Some(Ok(Message::Binary(_)))) | Ok(Some(Ok(Message::Text(_)))) => {
                return Err(HarnessError::Process(
                    "EC-041 racing data attachment produced an application frame".into(),
                ));
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct SessionIdentity {
    epoch: u64,
    generation: u64,
    session_id_digest: [u8; 32],
    connection_id_digest: [u8; 32],
    candidate_generation: Option<u64>,
    sockets: u8,
}

#[derive(Default)]
struct AttachmentRaceResources {
    predecessor: Option<ControlOnlyBarrier>,
    successor: Option<ControlOnlyBarrier>,
    fresh_data: Option<DeviceSocket>,
}

impl AttachmentRaceResources {
    async fn cleanup(&mut self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut first = None;
        if let Some(mut socket) = self.fresh_data.take() {
            let result = timeout(
                deadline.saturating_duration_since(Instant::now()),
                socket.close(None),
            )
            .await
            .map_err(|_| HarnessError::Timeout("EC-041 fresh data close timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("EC-041 fresh data close: {error}")));
            append_cleanup(&mut first, "EC-041 fresh data", result);
        }
        if let Some(barrier) = self.successor.take() {
            append_cleanup(
                &mut first,
                "EC-041 successor barrier",
                barrier.close(deadline).await,
            );
        }
        if let Some(barrier) = self.predecessor.take() {
            append_cleanup(
                &mut first,
                "EC-041 predecessor barrier",
                barrier.close(deadline).await,
            );
        }
        match first {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

struct ControlOnlyBarrier {
    proxy: Option<ProxyHandle>,
    connection_id: ConnectionId,
    paused: bool,
    control: Option<DeviceSocket>,
    hello_message_id: String,
}

impl ControlOnlyBarrier {
    async fn open(
        target_addr: SocketAddr,
        tls: Arc<ClientConfig>,
        device_id: Uuid,
        service_id: Uuid,
        rotation: RotationConfig,
    ) -> Result<Self> {
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default()).await?;
        let local_addr = proxy.local_addr();
        let hello = hello_message(device_id, service_id, rotation);
        let hello_message_id = match &hello {
            ControlMessage::Hello(message) => message.message_id.clone(),
            _ => unreachable!("hello_message returns HELLO"),
        };
        let control_url = format!("wss://localhost:{}/v1/tunnel/control", local_addr.port());
        let control = match open_device_socket(
            &control_url,
            Arc::clone(&tls),
            CONTROL_SUBPROTOCOL,
            None,
            PHASE_TIMEOUT,
        )
        .await
        {
            Ok(control) => control,
            Err(error) => {
                let _ = proxy.shutdown().await;
                return Err(error);
            }
        };
        let mut barrier = Self {
            proxy: Some(proxy),
            connection_id: ConnectionId::new(0),
            paused: false,
            control: Some(control),
            hello_message_id,
        };
        let connection_id = match barrier.wait_for_connection().await {
            Ok(connection_id) => connection_id,
            Err(error) => {
                let _ = barrier.close(Instant::now() + CLEANUP_TIMEOUT).await;
                return Err(error);
            }
        };
        barrier.connection_id = connection_id;
        if let Err(error) = barrier
            .proxy
            .as_ref()
            .expect("EC-041 proxy retained")
            .pause(Direction::TargetToClient, connection_id)
            .await
        {
            let _ = barrier.close(Instant::now() + CLEANUP_TIMEOUT).await;
            return Err(error);
        }
        barrier.paused = true;
        if let Err(error) = send_control(
            barrier.control.as_mut().expect("EC-041 control retained"),
            &hello,
            PHASE_TIMEOUT,
        )
        .await
        {
            let _ = barrier.close(Instant::now() + CLEANUP_TIMEOUT).await;
            return Err(error);
        }
        Ok(barrier)
    }

    async fn wait_for_connection(&self) -> Result<ConnectionId> {
        let deadline = Instant::now() + PHASE_TIMEOUT;
        loop {
            let connections = self
                .proxy
                .as_ref()
                .expect("EC-041 proxy retained")
                .connections();
            if connections.len() == 1 {
                return Ok(connections[0].id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "EC-041 control proxy did not observe one connection".into(),
                ));
            }
            sleep(POLL_INTERVAL).await;
        }
    }

    async fn capture_control_only(
        &mut self,
        expected_owner: &tunnel_catalog::OwnerToken,
        deadline: Instant,
    ) -> Result<Welcome> {
        if self.paused {
            self.proxy
                .as_ref()
                .expect("EC-041 proxy retained")
                .resume(Direction::TargetToClient, self.connection_id)
                .await?;
            self.paused = false;
        }
        let control = self.control.as_mut().expect("EC-041 control retained");
        let welcome = match next_control(control, deadline).await? {
            ControlMessage::Welcome(welcome) => welcome,
            _ => {
                return Err(HarnessError::Http(
                    "EC-041 control did not return WELCOME".into(),
                ));
            }
        };
        if welcome.reply_to != self.hello_message_id
            || welcome.protocol_major != PROTOCOL_MAJOR
            || welcome.protocol_minor != PROTOCOL_MINOR
            || welcome.generation == 0
            || welcome.session_id != expected_owner.session_id
            || welcome.epoch != expected_owner.epoch
            || welcome.connection_id.is_empty()
            || welcome.attachment_ticket.is_empty()
            || welcome.owner_id.as_deref() != Some(owner_digest(expected_owner).as_str())
        {
            return Err(HarnessError::Http(
                "EC-041 WELCOME did not match the complete owner/session/generation binding".into(),
            ));
        }
        let fence = match next_control(control, deadline).await? {
            ControlMessage::OwnerFence(fence) => fence,
            _ => {
                return Err(HarnessError::Http(
                    "EC-041 control did not return OWNER_FENCE".into(),
                ));
            }
        };
        fence
            .validate()
            .map_err(|error| HarnessError::Http(format!("EC-041 OWNER_FENCE: {error}")))?;
        if fence.session_id != welcome.session_id
            || fence.epoch != welcome.epoch
            || fence.owner_id != owner_digest(expected_owner)
        {
            return Err(HarnessError::Http(
                "EC-041 OWNER_FENCE did not match the complete owner token".into(),
            ));
        }
        send_control(
            control,
            &ControlMessage::OwnerFenced(OwnerFenced::from_fence(
                Uuid::new_v4().to_string(),
                &fence,
            )),
            deadline.saturating_duration_since(Instant::now()),
        )
        .await?;
        Ok(welcome)
    }

    /// Read the successor control channel until one `DATA_READY` arrives,
    /// validating its context and reply binding against `welcome`, and return
    /// the generation it carried plus `true`.
    async fn expect_data_ready_generation(
        &mut self,
        welcome: &Welcome,
        deadline: Instant,
    ) -> Result<(u64, bool)> {
        let control = self.control.as_mut().expect("EC-041 control retained");
        loop {
            match next_control(control, deadline).await? {
                ControlMessage::DataReady(ready) => {
                    ready
                        .validate_context(
                            &welcome.session_id,
                            welcome.epoch,
                            welcome.generation,
                            &welcome.connection_id,
                        )
                        .map_err(|error| {
                            HarnessError::Http(format!("EC-041 DATA_READY: {error}"))
                        })?;
                    if ready.reply_to != welcome.message_id {
                        return Err(HarnessError::Http(
                            "EC-041 DATA_READY reply did not match WELCOME".into(),
                        ));
                    }
                    return Ok((welcome.generation, true));
                }
                ControlMessage::Ping(ping) => {
                    send_control(
                        control,
                        &ControlMessage::Pong(tunnel_protocol::Pong::new(
                            Uuid::new_v4().to_string(),
                            ping.message_id,
                            ping.session_id,
                            ping.epoch,
                            ping.nonce,
                        )),
                        deadline.saturating_duration_since(Instant::now()),
                    )
                    .await?;
                }
                _ => {}
            }
        }
    }

    async fn expect_no_data_ready(&mut self, deadline: Instant) -> Result<bool> {
        let quiet_deadline = Instant::now()
            .checked_add(QUIET_CONTROL_WINDOW)
            .map_or(deadline, |candidate| candidate.min(deadline));
        let control = self.control.as_mut().expect("EC-041 control retained");
        loop {
            let remaining = quiet_deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Ok(true);
            }
            let item = match timeout(remaining, control.next()).await {
                Err(_) => return Ok(true),
                Ok(Some(Ok(item))) => item,
                Ok(Some(Err(error))) => {
                    return Err(HarnessError::Http(format!(
                        "EC-041 control read while checking stale DATA_READY: {error}"
                    )));
                }
                Ok(None) => {
                    return Err(HarnessError::Http(
                        "EC-041 control closed before stale DATA_READY check completed".into(),
                    ));
                }
            };
            match item {
                Message::Ping(payload) => {
                    timeout(remaining, control.send(Message::Pong(payload)))
                        .await
                        .map_err(|_| {
                            HarnessError::Timeout("EC-041 control PONG deadline elapsed".into())
                        })?
                        .map_err(|error| {
                            HarnessError::Http(format!("EC-041 control PONG: {error}"))
                        })?;
                }
                Message::Text(text) => {
                    let message = decode_control(text.as_bytes()).map_err(|error| {
                        HarnessError::Http(format!("EC-041 control decode: {error}"))
                    })?;
                    if matches!(message, ControlMessage::DataReady(_)) {
                        return Err(HarnessError::Process(
                            "EC-041 stale attachment unexpectedly produced DATA_READY".into(),
                        ));
                    }
                }
                Message::Binary(bytes) => {
                    let message = decode_control(&bytes).map_err(|error| {
                        HarnessError::Http(format!("EC-041 control decode: {error}"))
                    })?;
                    if matches!(message, ControlMessage::DataReady(_)) {
                        return Err(HarnessError::Process(
                            "EC-041 stale attachment unexpectedly produced DATA_READY".into(),
                        ));
                    }
                }
                Message::Close(_) => {
                    return Err(HarnessError::Http(
                        "EC-041 successor control closed during attachment check".into(),
                    ));
                }
                Message::Pong(_) | Message::Frame(_) => {}
            }
        }
    }

    async fn close(mut self, deadline: Instant) -> Result<()> {
        let mut first_error = None;
        if self.paused {
            match self.proxy.as_ref() {
                Some(proxy) => {
                    if let Err(error) = proxy
                        .resume(Direction::TargetToClient, self.connection_id)
                        .await
                    {
                        first_error = Some(error);
                    }
                }
                None => {
                    first_error = Some(HarnessError::Process(
                        "EC-041 control proxy was lost before cleanup".into(),
                    ));
                }
            }
            self.paused = false;
        }
        if let Some(mut control) = self.control.take() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if !remaining.is_zero()
                && let Err(error) = timeout(remaining, control.close(None))
                    .await
                    .map_err(|_| HarnessError::Timeout("EC-041 control close timed out".into()))
                    .and_then(|result| {
                        result.map_err(|error| {
                            HarnessError::Http(format!("EC-041 control close: {error}"))
                        })
                    })
            {
                first_error.get_or_insert(error);
            }
        }
        if let Some(proxy) = self.proxy.take() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                first_error.get_or_insert_with(|| {
                    HarnessError::Timeout("EC-041 control proxy cleanup deadline elapsed".into())
                });
            } else if let Err(error) = timeout(remaining, proxy.shutdown())
                .await
                .map_err(|_| HarnessError::Timeout("EC-041 control proxy cleanup timed out".into()))
                .and_then(|result| result)
            {
                first_error.get_or_insert(error);
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn hello_message(device_id: Uuid, service_id: Uuid, rotation: RotationConfig) -> ControlMessage {
    let mut hello = Hello::new(
        Uuid::new_v4().to_string(),
        device_id.to_string(),
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR,
    );
    hello.features = vec![
        "m1-control-data".to_owned(),
        "authorization-challenge".to_owned(),
        "echo".to_owned(),
        "ordered-rotation-v1".to_owned(),
        "owner-fencing-v1".to_owned(),
    ];
    hello.services = vec![ServiceAdvertisement::new(
        service_id.to_string(),
        "echo",
        "1",
        ["echo", "data", "fin", "ack"],
    )];
    hello.rotation_policy = Some(RotationPolicy::new(
        rotation.interval_seconds.saturating_mul(1_000),
        rotation.handshake_timeout_seconds.saturating_mul(1_000),
        rotation.overlap_seconds.saturating_mul(1_000),
    ));
    ControlMessage::Hello(hello)
}

async fn open_device_socket(
    url: &str,
    tls: Arc<ClientConfig>,
    subprotocol: &str,
    ticket: Option<&str>,
    budget: Duration,
) -> Result<DeviceSocket> {
    let mut request = url
        .into_client_request()
        .map_err(|error| HarnessError::Http(format!("EC-041 WebSocket request: {error}")))?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_str(subprotocol)
            .map_err(|error| HarnessError::Http(format!("EC-041 subprotocol: {error}")))?,
    );
    if let Some(ticket) = ticket {
        request.headers_mut().insert(
            "authorization",
            HeaderValue::from_str(&format!("Bearer {ticket}"))
                .map_err(|error| HarnessError::Http(format!("EC-041 ticket header: {error}")))?,
        );
    }
    let (socket, response) = timeout(
        budget,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(tls))),
    )
    .await
    .map_err(|_| HarnessError::Timeout("EC-041 device WebSocket handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("EC-041 device WebSocket handshake: {error}")))?;
    if response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        != Some(subprotocol)
    {
        return Err(HarnessError::Http(
            "EC-041 device WebSocket subprotocol was not negotiated".into(),
        ));
    }
    Ok(socket)
}

async fn open_data_socket(
    address: SocketAddr,
    tls: Arc<ClientConfig>,
    ticket: &str,
    deadline: Instant,
) -> Result<DeviceSocket> {
    let url = format!("wss://localhost:{}/v1/tunnel/data", address.port());
    open_device_socket(
        &url,
        tls,
        DATA_SUBPROTOCOL,
        Some(ticket),
        deadline.saturating_duration_since(Instant::now()),
    )
    .await
}

async fn expect_data_rejection(mut socket: DeviceSocket, deadline: Instant) -> Result<bool> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "EC-041 rejected data attachment did not close before deadline".into(),
            ));
        }
        match timeout(remaining, socket.next()).await {
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "EC-041 rejected data attachment close timed out".into(),
                ));
            }
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => return Ok(true),
            Ok(Some(Ok(Message::Ping(payload)))) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| HarnessError::Http(format!("EC-041 data PONG: {error}")))?;
            }
            Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Frame(_)))) => {}
            Ok(Some(Ok(Message::Binary(_)))) | Ok(Some(Ok(Message::Text(_)))) => {
                return Err(HarnessError::Process(
                    "EC-041 rejected data attachment produced an application frame".into(),
                ));
            }
        }
    }
}

async fn send_control(
    socket: &mut DeviceSocket,
    message: &ControlMessage,
    budget: Duration,
) -> Result<()> {
    let encoded = encode_control(message)
        .map_err(|error| HarnessError::Http(format!("EC-041 control encode: {error}")))?;
    let text = String::from_utf8(encoded)
        .map_err(|error| HarnessError::Http(format!("EC-041 control UTF-8: {error}")))?;
    timeout(budget, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| HarnessError::Timeout("EC-041 control send timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("EC-041 control send: {error}")))
}

async fn next_control(socket: &mut DeviceSocket, deadline: Instant) -> Result<ControlMessage> {
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "EC-041 control deadline elapsed".into(),
            ));
        }
        match timeout(remaining, socket.next()).await {
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "EC-041 control read timed out".into(),
                ));
            }
            Ok(Some(Ok(Message::Text(text)))) => {
                return decode_control(text.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("EC-041 control decode: {error}"))
                });
            }
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                return decode_control(&bytes).map_err(|error| {
                    HarnessError::Http(format!("EC-041 control decode: {error}"))
                });
            }
            Ok(Some(Ok(Message::Ping(payload)))) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| HarnessError::Http(format!("EC-041 control PONG: {error}")))?;
            }
            Ok(Some(Ok(Message::Pong(_)))) | Ok(Some(Ok(Message::Frame(_)))) => {}
            Ok(Some(Ok(Message::Close(_)))) | Ok(None) => {
                return Err(HarnessError::Http("EC-041 control socket closed".into()));
            }
            Ok(Some(Err(error))) => {
                return Err(HarnessError::Http(format!("EC-041 control read: {error}")));
            }
        }
    }
}

fn relay_device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relay(node_id)?
        .running
        .as_ref()
        .map(|relay| relay.device_addr)
        .ok_or_else(|| HarnessError::Process(format!("EC-041 relay {node_id} is not running")))
}

fn device_tls(
    harness: &HarnessRuntime,
    device: &crate::DeviceFixture,
) -> Result<Arc<ClientConfig>> {
    tunnel_transport::load_client_config_from_pem_with_alpn(
        device.certificate.certificate_pem.as_bytes(),
        device.certificate.private_key_pem.as_bytes(),
        harness.pki.server_ca.certificate_pem.as_bytes(),
        &[b"http/1.1"],
    )
    .map_err(|error| HarnessError::Pki(format!("EC-041 device TLS: {error}")))
}

fn owner_digest(owner: &tunnel_catalog::OwnerToken) -> String {
    Sha256::digest(serde_json::to_vec(owner).expect("OwnerToken serializes"))
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn welcome_matches_owner(welcome: &Welcome, owner: &tunnel_catalog::OwnerToken) -> bool {
    welcome.session_id == owner.session_id
        && welcome.epoch == owner.epoch
        && welcome.generation > 0
        && !welcome.connection_id.is_empty()
        && !welcome.attachment_ticket.is_empty()
        && welcome.owner_id.as_deref() == Some(owner_digest(owner).as_str())
}

fn full_owner_token_replaced(
    old: &OwnerClaim,
    new: &OwnerClaim,
    tenant_id: Uuid,
    device_id: Uuid,
) -> bool {
    old.token.tenant_id == tenant_id
        && old.token.device_id == device_id
        && new.token.tenant_id == tenant_id
        && new.token.device_id == device_id
        && old.token.deployment_incarnation == new.token.deployment_incarnation
        && old.token != new.token
        && old.token.node_id != new.token.node_id
        && old.token.boot_id != new.token.boot_id
        && old.token.session_id != new.token.session_id
        && new.token.epoch > old.token.epoch
}

async fn wait_for_owner_on(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    node_id: &str,
    deadline: Instant,
) -> Result<OwnerClaim> {
    loop {
        if let Some(owner) = cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("EC-041 owner read: {error}")))?
            && owner.token.node_id == node_id
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "EC-041 owner {node_id} did not become visible"
            )));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_no_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    deadline: Instant,
) -> Result<()> {
    loop {
        if cluster
            .catalog
            .current_owner(tenant_id, device_id, chrono::Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("EC-041 owner release read: {error}")))?
            .is_none()
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "EC-041 predecessor owner did not release".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn wait_for_control_only_session(
    cluster: &ProductionCluster,
    device_id: Uuid,
    owner: &tunnel_catalog::OwnerToken,
    deadline: Instant,
) -> Result<()> {
    loop {
        let snapshot = cluster.relay(&owner.node_id)?.snapshot().await?;
        if snapshot.sessions.iter().any(|session| {
            session.device_id == device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
                && session.active_generation == 1
                && session.candidate_generation.is_none()
                && session.phase == "active"
        }) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "EC-041 control-only session did not become observable".into(),
            ));
        }
        sleep(POLL_INTERVAL).await;
    }
}

async fn session_identity(
    cluster: &ProductionCluster,
    node_id: &str,
    device_id: Uuid,
    owner: &tunnel_catalog::OwnerToken,
) -> Result<SessionIdentity> {
    let snapshot = cluster.relay(node_id)?.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| {
            session.device_id == device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .ok_or_else(|| HarnessError::Process("EC-041 owner session disappeared".into()))?;
    Ok(SessionIdentity {
        epoch: session.epoch,
        generation: session.active_generation,
        session_id_digest: Sha256::digest(session.session_id.as_bytes()).into(),
        connection_id_digest: Sha256::digest(session.active_connection_id.as_bytes()).into(),
        candidate_generation: session.candidate_generation,
        sockets: session.sockets,
    })
}

fn append_cleanup(slot: &mut Option<HarnessError>, label: &str, result: Result<()>) {
    if let Err(error) = result {
        let combined = match slot.take() {
            Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
            None => HarnessError::Process(format!("{label}: {error}")),
        };
        *slot = Some(combined);
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::*;
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> Ec041DeviceAttachmentEvidence {
        Ec041DeviceAttachmentEvidence {
            relay_count: 3,
            predecessor_owner_complete: true,
            successor_owner_complete: true,
            full_owner_token_replaced: true,
            predecessor_generation: 1,
            successor_generation: 1,
            predecessor_ticket_captured: true,
            successor_ticket_captured: true,
            stale_ticket_rejected: true,
            stale_data_ready_absent: true,
            stale_session_state_unchanged: true,
            concurrent_used_distinct_ingress: true,
            concurrent_winner_count: 1,
            concurrent_loser_count: 1,
            concurrent_data_ready_count: 1,
            winner_generation: 1,
            winner_carrier_installed: true,
            loser_caused_no_counter_reset: true,
            fresh_ticket_reuse_rejected: true,
            fresh_ticket_reuse_data_ready_absent: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn ec041_validator_accepts_complete_evidence() {
        assert!(validate_ec041_device_attachment_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_ec041_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut Ec041DeviceAttachmentEvidence));
        let flags: [Disable; 14] = [
            ("predecessor_owner_complete", |e| {
                e.predecessor_owner_complete = false
            }),
            ("successor_owner_complete", |e| {
                e.successor_owner_complete = false
            }),
            ("full_owner_token_replaced", |e| {
                e.full_owner_token_replaced = false
            }),
            ("predecessor_ticket_captured", |e| {
                e.predecessor_ticket_captured = false
            }),
            ("successor_ticket_captured", |e| {
                e.successor_ticket_captured = false
            }),
            ("stale_ticket_rejected", |e| e.stale_ticket_rejected = false),
            ("stale_data_ready_absent", |e| {
                e.stale_data_ready_absent = false
            }),
            ("stale_session_state_unchanged", |e| {
                e.stale_session_state_unchanged = false
            }),
            ("concurrent_used_distinct_ingress", |e| {
                e.concurrent_used_distinct_ingress = false
            }),
            ("winner_carrier_installed", |e| {
                e.winner_carrier_installed = false
            }),
            ("loser_caused_no_counter_reset", |e| {
                e.loser_caused_no_counter_reset = false
            }),
            ("fresh_ticket_reuse_rejected", |e| {
                e.fresh_ticket_reuse_rejected = false
            }),
            ("fresh_ticket_reuse_data_ready_absent", |e| {
                e.fresh_ticket_reuse_data_ready_absent = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_failed(validate_ec041_device_attachment_evidence(&evidence));
        }
    }

    #[test]
    fn every_ec041_required_count_and_generation_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut Ec041DeviceAttachmentEvidence));
        let counts: [Mutate; 9] = [
            ("relay_count", |e| e.relay_count = 2),
            ("predecessor_generation", |e| e.predecessor_generation = 2),
            ("successor_generation", |e| e.successor_generation = 2),
            ("winner_generation", |e| e.winner_generation = 2),
            ("concurrent_winner_none", |e| e.concurrent_winner_count = 0),
            ("concurrent_winner_double", |e| {
                e.concurrent_winner_count = 2
            }),
            ("concurrent_loser_none", |e| e.concurrent_loser_count = 0),
            ("concurrent_loser_double", |e| e.concurrent_loser_count = 2),
            ("concurrent_data_ready_double", |e| {
                e.concurrent_data_ready_count = 2
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_ec041_device_attachment_evidence(&evidence),
                "EC-041",
            );
        }
    }
}
