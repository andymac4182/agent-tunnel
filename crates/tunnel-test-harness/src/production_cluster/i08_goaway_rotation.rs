//! M7-I08/EC-052 real three-relay planned GOAWAY during active rotation.
//!
//! This fixture is intentionally separate from the component H3 GOAWAY tests
//! and from the active-carrier-fault fixture.  It starts the existing real
//! three-relay `ProductionCluster`, drives an actual `tunnel-client` process,
//! opens a public consumer stream through relay-c, and requests the owner
//! relay-a's explicit planned private-listener drain while a scheduled M2
//! candidate is live.  The peer listener's payload-free diagnostics prove the
//! selected authenticated connection sent GOAWAY; the held public response
//! proves an already admitted stream completed afterward.  A later public
//! request is required to return the existing typed 503/not-dispatched class.
//!
//! This is a narrow listener-drain/rotation integration.  It does not claim a
//! browser close contract, a future adapter, or a successful successor after
//! the planned owner listener has stopped accepting new peer connections.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::{
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout, timeout_at};
use tokio_tungstenite::tungstenite::Message;
use tunnel_relay::{
    PeerAdmissionBarrier, PeerAdmissionScope, PeerConsumerDiagnosticRole,
    PeerTransportDiagnosticOutcome, RelaySessionSnapshot, RelaySnapshot,
};
use tunnel_transport::PeerServerStats;
use uuid::Uuid;

use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result, RunningHarness};

use super::admission::{
    AdmissionFailure, PublicStreamProbe, open_public_stream_with_authorization,
};
use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, ROTATION, SCENARIO_TIMEOUT,
    STARTUP_TIMEOUT, open_consumer_stream, start_cli_smoke, write_device_profile,
};

const POLL: Duration = Duration::from_millis(20);
const PEER_NODE: &str = "relay-c";
const OWNER_NODE: &str = "relay-a";

struct ReleasePeerAdmissionBarrier(Arc<PeerAdmissionBarrier>);

impl Drop for ReleasePeerAdmissionBarrier {
    fn drop(&mut self) {
        self.0.release();
    }
}

fn is_peer_goaway_failure(failure: &AdmissionFailure) -> bool {
    failure.status == 503
        && failure.code == Some("PEER_UNAVAILABLE")
        && failure.execution == Some("not_dispatched")
}

fn is_cluster_unready_failure(failure: &AdmissionFailure) -> bool {
    failure.status == 503
        && failure.code == Some("CLUSTER_UNREADY")
        && failure.execution == Some("not_dispatched")
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct I08GoawayRotationEvidence {
    pub scope: &'static str,
    pub relay_count: usize,
    pub actual_cli_process: bool,
    pub owner_relay: String,
    pub ingress_relay: String,
    pub tenant_id: String,
    pub device_id: String,
    pub service_id: String,
    pub session_id: String,
    pub epoch: u64,
    pub stream_id: u64,
    pub operation_id: String,
    pub candidate_generation: u64,
    pub candidate_connection_id: String,
    pub rotation_before: u64,
    pub rotation_after: u64,
    pub goaway_peer_node_id: String,
    pub goaway_connection_id: usize,
    pub active_stream_observed: bool,
    pub planned_goaway_sent: bool,
    pub admitted_response_completed: bool,
    pub pre_admission_goaway_not_dispatched: bool,
    pub post_goaway_not_dispatched: bool,
    pub ingress_goaway_observed: bool,
    pub post_goaway_dispatch_delta: u64,
    pub later_request_dispatch_delta: u64,
    pub cli_survived: bool,
    pub socket_high_water: usize,
    pub cleanup_joined: bool,
    pub elapsed_ms: u64,
}

pub fn validate_i08_goaway_rotation_evidence(evidence: &I08GoawayRotationEvidence) -> Result<()> {
    if evidence.scope != "three_relay_rotation_planned_goaway" {
        return Err(HarnessError::Process(
            "I08 GOAWAY evidence has an unexpected scope".into(),
        ));
    }
    if evidence.relay_count != 3
        || !evidence.actual_cli_process
        || evidence.owner_relay != OWNER_NODE
        || evidence.ingress_relay != PEER_NODE
        || evidence.tenant_id.is_empty()
        || evidence.device_id.is_empty()
        || evidence.service_id.is_empty()
        || evidence.session_id.is_empty()
        || evidence.epoch == 0
        || evidence.stream_id == 0
        || evidence.operation_id.is_empty()
        || evidence.candidate_generation == 0
        || evidence.candidate_connection_id.is_empty()
        || evidence.rotation_after <= evidence.rotation_before
        || evidence.goaway_peer_node_id != PEER_NODE
        || evidence.goaway_connection_id == 0
        || !evidence.active_stream_observed
        || !evidence.planned_goaway_sent
        || !evidence.admitted_response_completed
        || !evidence.pre_admission_goaway_not_dispatched
        || !evidence.post_goaway_not_dispatched
        || !evidence.ingress_goaway_observed
        || evidence.post_goaway_dispatch_delta != 1
        || evidence.later_request_dispatch_delta != 0
        || !evidence.cli_survived
        || evidence.socket_high_water == 0
        || evidence.socket_high_water > 3
        || !evidence.cleanup_joined
    {
        return Err(HarnessError::Process(
            "I08 GOAWAY evidence omitted a required three-relay, rotation, identity, dispatch, or joined-drain invariant"
                .into(),
        ));
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct GoawayScope<'a> {
    tenant_id: Uuid,
    device_id: Uuid,
    session_id: &'a str,
    epoch: u64,
    service_id: Option<Uuid>,
    stream_id: Option<u64>,
    operation_id: Option<&'a str>,
}

fn scope_context(scope: GoawayScope<'_>, phase: &str) -> String {
    format!(
        "phase={phase} tenant={} device={} session={} epoch={} service={} stream={} operation={}",
        scope.tenant_id,
        scope.device_id,
        scope.session_id,
        scope.epoch,
        scope
            .service_id
            .map_or_else(|| "<none>".to_owned(), |value| value.to_string()),
        scope
            .stream_id
            .map_or_else(|| "<none>".to_owned(), |value| value.to_string()),
        scope.operation_id.unwrap_or("<none>"),
    )
}

fn owner_context(snapshot: &RelaySnapshot, scope: GoawayScope<'_>, phase: &str) -> String {
    let prefix = scope_context(scope, phase);
    let Some(session) = snapshot.sessions.iter().find(|session| {
        session.tenant_id == scope.tenant_id.to_string()
            && session.device_id == scope.device_id.to_string()
            && session.session_id == scope.session_id
            && session.epoch == scope.epoch
    }) else {
        return format!(
            "{prefix} owner_session=missing owner_session_count={}",
            snapshot.sessions.len()
        );
    };
    let selected_stream = scope.stream_id.and_then(|stream_id| {
        session.streams.iter().find(|stream| {
            stream.stream_id == stream_id
                && scope
                    .operation_id
                    .is_none_or(|operation_id| stream.operation_id == operation_id)
        })
    });
    let selected = selected_stream.map_or_else(
        || "<none>".to_owned(),
        |stream| {
            format!(
                "id={} op={} terminal={} auth_in_flight={} failure={:?} queue_bytes={} emitted={} acked={} replay_frames={} replay_bytes={}",
                stream.stream_id,
                stream.operation_id,
                stream.terminal,
                stream.authorization_in_flight,
                stream.authorization_failure_code,
                stream.queue_bytes,
                stream.last_emitted_relay_to_connector,
                stream.peer_acked_relay_to_connector,
                stream.replay_frames_relay_to_connector,
                stream.replay_bytes_relay_to_connector,
            )
        },
    );
    format!(
        "{prefix} owner_phase={} active_generation={} active_connection={} candidate_generation={:?} candidate_connection={} sockets={} queue_bytes={} queue_messages={} rotations={} stream_count={} selected_stream=[{}]",
        session.phase,
        session.active_generation,
        session.active_connection_id,
        session.candidate_generation,
        session
            .candidate_connection_id
            .as_deref()
            .unwrap_or("<none>"),
        session.sockets,
        session.queue_bytes,
        session.queue_messages,
        session.rotations_completed,
        session.streams.len(),
        selected,
    )
}

fn peer_context(
    stats: Option<&PeerServerStats>,
    peer_node_id: &str,
    connection_id: usize,
    phase: &str,
) -> String {
    let Some(stats) = stats else {
        return format!(
            "phase={phase} peer={peer_node_id} connection={connection_id} peer_stats=unavailable"
        );
    };
    if connection_id == 0 {
        let accepted = stats
            .connections
            .iter()
            .filter(|connection| connection.peer_node_id == peer_node_id)
            .map(|connection| connection.accepted_streams)
            .sum::<u64>();
        let resolving = stats
            .connections
            .iter()
            .filter(|connection| connection.peer_node_id == peer_node_id)
            .map(|connection| connection.resolving_streams)
            .sum::<u64>();
        let active = stats
            .connections
            .iter()
            .filter(|connection| connection.peer_node_id == peer_node_id)
            .map(|connection| connection.active_streams)
            .sum::<u64>();
        return format!(
            "phase={phase} peer={peer_node_id} connection=<none> peer_connection_count={} accepted_total={} resolving_total={} active_total={}",
            stats.connections.len(),
            accepted,
            resolving,
            active,
        );
    }
    let Some(connection) = stats.connections.iter().find(|connection| {
        connection.peer_node_id == peer_node_id && connection.connection_id == connection_id
    }) else {
        return format!(
            "phase={phase} peer={peer_node_id} connection={connection_id} peer_connection=missing peer_connection_count={}",
            stats.connections.len()
        );
    };
    format!(
        "phase={phase} peer={} connection={} accepted={} resolving={} active={} completed={} cancelled={} errors={} planned_goaway={} forced_stream_cancel={} forced_connection_close={} join_incomplete={} peer_connection_count={}",
        connection.peer_node_id,
        connection.connection_id,
        connection.accepted_streams,
        connection.resolving_streams,
        connection.active_streams,
        connection.completed_streams,
        connection.cancelled_streams,
        connection.error_streams,
        connection.planned_goaway_sent,
        connection.forced_stream_cancellation,
        connection.forced_connection_close,
        connection.drain_join_incomplete,
        stats.connections.len(),
    )
}

fn ingress_context(snapshot: &RelaySnapshot, scope: GoawayScope<'_>, phase: &str) -> String {
    let diagnostics = &snapshot.peer_consumer_diagnostics;
    let event = diagnostics.last_ingress_send.as_ref().map_or_else(
        || "<none>".to_owned(),
        |event| {
            format!(
                "role={:?} outcome={:?} h3={:?} tenant={} device={} session={} epoch={} service={}",
                event.role,
                event.outcome,
                event.h3_code,
                event.tenant_id,
                event.device_id,
                event.session_id,
                event.epoch,
                event.service_id,
            )
        },
    );
    format!(
        "{} ingress_send_count={} ingress_receive_count={} last_ingress_send=[{}]",
        scope_context(scope, phase),
        diagnostics.ingress_send_count,
        diagnostics.ingress_receive_count,
        event,
    )
}

fn session_for(
    snapshot: &RelaySnapshot,
    scope: GoawayScope<'_>,
    phase: &str,
) -> Result<RelaySessionSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == scope.tenant_id.to_string()
                && session.device_id == scope.device_id.to_string()
                && session.session_id == scope.session_id
                && session.epoch == scope.epoch
        })
        .cloned()
        .ok_or_else(|| HarnessError::Process(owner_context(snapshot, scope, phase)))
}

async fn owner_snapshot_before(
    cluster: &ProductionCluster,
    deadline: Instant,
) -> Result<RelaySnapshot> {
    timeout_at(
        tokio::time::Instant::from_std(deadline),
        cluster.relay(OWNER_NODE)?.snapshot(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("I08 GOAWAY owner snapshot timed out".into()))?
}

async fn wait_for_owner_baseline(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    session_id: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = owner_snapshot_before(cluster, deadline).await?;
        if let Some(session) = snapshot.sessions.iter().find(|session| {
            session.tenant_id == tenant_id.to_string()
                && session.device_id == device_id.to_string()
                && session.session_id == session_id
                && session.epoch == epoch
                && session.phase == "active"
        }) {
            let mut streams = session.streams.iter().filter(|stream| {
                !stream.terminal
                    && !stream.authorization_in_flight
                    && stream.authorization_failure_code.is_none()
                    && !stream.operation_id.is_empty()
            });
            if streams.next().is_some() && streams.next().is_none() {
                return Ok(session.clone());
            }
        }
        if Instant::now() >= deadline {
            let scope = GoawayScope {
                tenant_id,
                device_id,
                session_id,
                epoch,
                service_id: Some(service_id),
                stream_id: None,
                operation_id: None,
            };
            return Err(HarnessError::Timeout(owner_context(
                &snapshot, scope, "baseline",
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_candidate(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    session_id: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = owner_snapshot_before(cluster, deadline).await?;
        let scope = GoawayScope {
            tenant_id,
            device_id,
            session_id,
            epoch,
            service_id: Some(service_id),
            stream_id: None,
            operation_id: None,
        };
        let session = session_for(&snapshot, scope, "candidate")?;
        if let (Some(generation), Some(connection_id)) = (
            session.candidate_generation,
            session.candidate_connection_id.clone(),
        ) && generation > session.active_generation
            && !connection_id.is_empty()
        {
            return Ok(session);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(owner_context(
                &snapshot,
                scope,
                "candidate",
            )));
        }
        sleep(POLL).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_active_peer_stream(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    session_id: &str,
    epoch: u64,
    stream_id: u64,
    operation_id: &str,
    baseline_emitted: u64,
    deadline: Instant,
) -> Result<usize> {
    loop {
        let snapshot = owner_snapshot_before(cluster, deadline).await?;
        let scope = GoawayScope {
            tenant_id,
            device_id,
            session_id,
            epoch,
            service_id: Some(service_id),
            stream_id: Some(stream_id),
            operation_id: Some(operation_id),
        };
        let session = session_for(&snapshot, scope, "held-forward")?;
        let stream_forwarded = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id && stream.operation_id == operation_id)
            .is_some_and(|stream| {
                !stream.terminal
                    && (stream.last_emitted_relay_to_connector > baseline_emitted
                        || stream.queue_bytes > 0)
            });
        if let Some(PeerServerStats { connections }) =
            cluster.relay(OWNER_NODE)?.peer_server_stats()
        {
            let matching = connections
                .into_iter()
                .filter(|connection| {
                    connection.peer_node_id == PEER_NODE
                        // `accepted_streams` is cumulative for this pooled H3
                        // connection, so completed readiness probes and earlier
                        // requests are valid history.  Current active ownership
                        // remains the attribution gate; multiple live candidates
                        // below still fail closed.
                        && connection.accepted_streams > 0
                        && connection.active_streams == 1
                        && stream_forwarded
                })
                .collect::<Vec<_>>();
            match matching.as_slice() {
                [connection] => {
                    return Ok(connection.connection_id);
                }
                [] => {}
                _ => {
                    return Err(HarnessError::Process(format!(
                        "I08 GOAWAY active peer attribution was ambiguous; {}",
                        owner_context(&snapshot, scope, "held-forward"),
                    )));
                }
            }
        }
        if Instant::now() >= deadline {
            let peer_stats = cluster.relay(OWNER_NODE)?.peer_server_stats();
            return Err(HarnessError::Timeout(format!(
                "I08 GOAWAY did not observe an admitted active peer stream before deadline; {}; {}",
                owner_context(&snapshot, scope, "held-forward"),
                peer_context(peer_stats.as_ref(), PEER_NODE, 0, "held-forward",),
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_goaway(
    cluster: &ProductionCluster,
    connection_id: usize,
    scope: GoawayScope<'_>,
    deadline: Instant,
) -> Result<()> {
    loop {
        if let Some(PeerServerStats { connections }) =
            cluster.relay(OWNER_NODE)?.peer_server_stats()
            && connections.into_iter().any(|connection| {
                connection.peer_node_id == PEER_NODE
                    && connection.connection_id == connection_id
                    && connection.accepted_streams > 0
                    && connection.planned_goaway_sent
            })
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let peer_stats = cluster.relay(OWNER_NODE)?.peer_server_stats();
            return Err(HarnessError::Timeout(format!(
                "{}; {}",
                scope_context(scope, "goaway"),
                peer_context(peer_stats.as_ref(), PEER_NODE, connection_id, "goaway"),
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_committed_rotation(
    cluster: &ProductionCluster,
    scope: GoawayScope<'_>,
    previous_rotation: u64,
    deadline: Instant,
) -> Result<RelaySessionSnapshot> {
    loop {
        let snapshot = owner_snapshot_before(cluster, deadline).await?;
        let session = session_for(&snapshot, scope, "commit")?;
        if session.rotations_completed > previous_rotation
            && session.candidate_generation.is_none()
            && session.active_generation > 1
            && session.phase == "active"
        {
            return Ok(session);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(owner_context(
                &snapshot, scope, "commit",
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_ingress_goaway(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    session_id: &str,
    epoch: u64,
    deadline: Instant,
) -> Result<()> {
    loop {
        let snapshot = timeout_at(
            tokio::time::Instant::from_std(deadline),
            cluster.relay(PEER_NODE)?.snapshot(),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!(
            "I08 GOAWAY phase=next-admission ingress snapshot timed out; tenant={tenant_id} device={device_id} session={session_id} epoch={epoch}"
        )))??;
        if let Some(event) = snapshot
            .peer_consumer_diagnostics
            .last_ingress_send
            .as_ref()
            && event.role == PeerConsumerDiagnosticRole::IngressSend
            && event.outcome == PeerTransportDiagnosticOutcome::GoAway
            && event.tenant_id == tenant_id
            && event.device_id == device_id
            && event.service_id == service_id
            && event.session_id == session_id
            && event.epoch == epoch
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let scope = GoawayScope {
                tenant_id,
                device_id,
                session_id,
                epoch,
                service_id: Some(service_id),
                stream_id: None,
                operation_id: None,
            };
            return Err(HarnessError::Timeout(ingress_context(
                &snapshot,
                scope,
                "next-admission",
            )));
        }
        sleep(POLL).await;
    }
}

async fn send_echo_without_read(
    stream: &mut ConsumerStream,
    payload: &[u8],
    deadline: Instant,
    scope: &str,
) -> Result<()> {
    if payload.len() > super::MAX_RECORD_BYTES {
        return Err(HarnessError::InvalidInput(
            "I08 GOAWAY held payload exceeds the bounded record limit".into(),
        ));
    }
    let length = u32::try_from(payload.len()).map_err(|_| {
        HarnessError::InvalidInput("I08 GOAWAY held payload length overflow".into())
    })?;
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(payload);
    timeout_at(
        tokio::time::Instant::from_std(deadline),
        stream.socket.send(Message::Binary(frame.into())),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout(format!(
            "I08 GOAWAY phase=held-forward held request send timed out; {scope}"
        ))
    })?
    .map_err(|error| {
        HarnessError::Http(format!(
            "I08 GOAWAY phase=held-forward held request send; {scope}: {error}"
        ))
    })
}

async fn receive_echo_after_goaway(
    stream: &mut ConsumerStream,
    payload: &[u8],
    canary: &[u8],
    deadline: Instant,
    scope: &str,
) -> Result<()> {
    let maximum = payload.len().saturating_add(canary.len()).saturating_add(4);
    let mut response = Vec::with_capacity(maximum);
    loop {
        let message = timeout_at(
            tokio::time::Instant::from_std(deadline),
            stream.socket.next(),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "I08 GOAWAY phase=response response drain timed out; {scope}"
            ))
        })?
        .ok_or_else(|| {
            HarnessError::Http(format!(
                "I08 GOAWAY phase=response response ended before completion; {scope}"
            ))
        })?
        .map_err(|error| {
            HarnessError::Http(format!(
                "I08 GOAWAY phase=response response read; {scope}: {error}"
            ))
        })?;
        match message {
            Message::Binary(bytes) => {
                if response.len().saturating_add(bytes.len()) > maximum {
                    return Err(HarnessError::Http(format!(
                        "I08 GOAWAY phase=response response exceeded its bounded frame; {scope}"
                    )));
                }
                response.extend_from_slice(&bytes);
                if response.len() < 4 {
                    continue;
                }
                let declared =
                    u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                        as usize;
                if declared != payload.len().saturating_add(canary.len())
                    || response.len() != declared.saturating_add(4)
                {
                    if response.len() < declared.saturating_add(4) {
                        continue;
                    }
                    return Err(HarnessError::Http(format!(
                        "I08 GOAWAY phase=response response framing changed; {scope}"
                    )));
                }
                let canary_end = 4 + canary.len();
                if response.get(4..canary_end) != Some(canary)
                    || response.get(canary_end..) != Some(payload)
                {
                    return Err(HarnessError::Http(format!(
                        "I08 GOAWAY phase=response admitted response was replayed or changed; {scope}"
                    )));
                }
                return Ok(());
            }
            Message::Ping(bytes) => {
                timeout_at(
                    tokio::time::Instant::from_std(deadline),
                    stream.socket.send(Message::Pong(bytes)),
                )
                .await
                .map_err(|_| {
                    HarnessError::Timeout(format!(
                        "I08 GOAWAY phase=response pong timed out; {scope}"
                    ))
                })?
                .map_err(|error| {
                    HarnessError::Http(format!("I08 GOAWAY phase=response pong; {scope}: {error}"))
                })?;
            }
            Message::Pong(_) | Message::Frame(_) => {}
            Message::Close(_) => {
                return Err(HarnessError::Http(format!(
                    "I08 GOAWAY phase=response admitted response closed before completion; {scope}"
                )));
            }
            Message::Text(_) => {
                return Err(HarnessError::Http(format!(
                    "I08 GOAWAY phase=response response returned text; {scope}"
                )));
            }
        }
    }
}

/// The ordinary request after the listener-wide planned drain must remain
/// fail-closed at the public readiness boundary. It is intentionally kept
/// separate from the already-resolved request held by `PeerAdmissionBarrier`.
#[allow(clippy::too_many_arguments)] // Exact authenticated route and owned operation/cleanup deadlines.
async fn expect_postdrain_cluster_unready(
    ingress: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    scenario_deadline: Instant,
    cleanup_deadline: Instant,
    scope_label: &str,
) -> Result<()> {
    let result = timeout_at(
        tokio::time::Instant::from_std(scenario_deadline),
        open_consumer_stream(ingress, server_ca_der, token, device_id, service_id),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("I08 GOAWAY post-drain readiness request timed out".into())
    })?;
    match result {
        Err(super::StreamConnectFailure::Status { status, body }) => {
            let value = body
                .as_deref()
                .and_then(|bytes| serde_json::from_slice::<serde_json::Value>(bytes).ok());
            let failure = AdmissionFailure {
                status,
                code: value
                    .as_ref()
                    .and_then(|value| value.get("code"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|code| match code {
                        "CLUSTER_UNREADY" => Some("CLUSTER_UNREADY"),
                        _ => None,
                    }),
                execution: value
                    .as_ref()
                    .and_then(|value| value.get("execution"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(|execution| match execution {
                        "not_dispatched" => Some("not_dispatched"),
                        _ => None,
                    }),
            };
            if is_cluster_unready_failure(&failure) {
                Ok(())
            } else {
                Err(HarnessError::Http(format!(
                    "I08 GOAWAY phase=post-drain-readiness returned an unapproved {} response ({}) [{}]",
                    status,
                    super::redacted_admission_failure(body.as_deref()),
                    scope_label,
                )))
            }
        }
        Err(super::StreamConnectFailure::Harness(_)) => Err(HarnessError::Process(format!(
            "I08 GOAWAY phase=post-drain-readiness failed before status; {scope_label}"
        ))),
        Ok(mut stream) => {
            let close_result = timeout_at(
                tokio::time::Instant::from_std(cleanup_deadline),
                stream.close(),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout(
                    "I08 GOAWAY post-drain unexpected 101 cleanup timed out".into(),
                )
            })
            .and_then(|result| result);
            match close_result {
                Ok(()) => Err(HarnessError::Process(format!(
                    "I08 GOAWAY phase=post-drain-readiness unexpectedly received HTTP 101; {scope_label}"
                ))),
                Err(error) => Err(HarnessError::Process(format!(
                    "I08 GOAWAY phase=post-drain-readiness received HTTP 101 and bounded cleanup failed: {error}; {scope_label}"
                ))),
            }
        }
    }
}

async fn round_trip_before(
    stream: &mut ConsumerStream,
    payload: &[u8],
    canary: &[u8],
    deadline: Instant,
) -> Result<()> {
    timeout_at(
        tokio::time::Instant::from_std(deadline),
        stream.round_trip(payload, canary),
    )
    .await
    .map_err(|_| HarnessError::Timeout("I08 GOAWAY bounded echo exchange timed out".into()))?
}

async fn run_scenario(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    peer_admission_barrier: Arc<PeerAdmissionBarrier>,
) -> Result<I08GoawayRotationEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(
            "I08 GOAWAY fixture requires exactly three relays".into(),
        ));
    }
    let device =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("I08 GOAWAY has no tenant-A device".into())
        })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("I08 GOAWAY has no device service".into()))?;
    let canary = format!("m7-i08-goaway:{}", device.id);
    let profile_directory = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("I08 GOAWAY client config: {error}"))
    })?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let ingress = cluster.relay(PEER_NODE)?.consumer_addr()?;
    let (mut cli_process, mut cli_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        &profile,
        &token,
        device.id,
        service_id,
    )
    .await?;
    let scenario_deadline = Instant::now() + SCENARIO_TIMEOUT.min(Duration::from_secs(90));
    let cleanup_deadline = scenario_deadline + CLEANUP_TIMEOUT;
    let result: Result<I08GoawayRotationEvidence> = async {
        round_trip_before(
            &mut cli_stream,
            b"i08-goaway-cli-baseline",
            canary.as_bytes(),
            scenario_deadline,
        )
        .await?;
        let owner_before = timeout_at(
            tokio::time::Instant::from_std(scenario_deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("I08 GOAWAY owner lookup timed out".into()))?
        .map_err(|error| HarnessError::Redis(format!("I08 GOAWAY owner lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process("I08 GOAWAY owner disappeared".into()))?;
        if owner_before.token.node_id != OWNER_NODE
            || owner_before.token.tenant_id != device.tenant_id
            || owner_before.token.device_id != device.id
        {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY owner binding mismatch: expected node {OWNER_NODE}, tenant {}, device {}; observed node {}, tenant {}, device {}",
                device.tenant_id,
                device.id,
                owner_before.token.node_id,
                owner_before.token.tenant_id,
                owner_before.token.device_id,
            )));
        }
        let baseline_session = wait_for_owner_baseline(
            cluster,
            device.tenant_id,
            device.id,
            service_id,
            &owner_before.token.session_id,
            owner_before.token.epoch,
            scenario_deadline,
        )
        .await?;
        let mut logical_streams = baseline_session
            .streams
            .iter()
            .filter(|stream| {
                !stream.terminal
                    && !stream.authorization_in_flight
                    && stream.authorization_failure_code.is_none()
                    && !stream.operation_id.is_empty()
            });
        let logical_stream = logical_streams
            .next()
            .ok_or_else(|| HarnessError::Process("I08 GOAWAY baseline stream missing".into()))?;
        if logical_streams.next().is_some() {
            return Err(HarnessError::Process(
                "I08 GOAWAY baseline had multiple admitted streams; target identity was ambiguous"
                    .into(),
            ));
        }
        if logical_stream.operation_id.is_empty() {
            return Err(HarnessError::Process(
                "I08 GOAWAY baseline stream omitted operation identity".into(),
            ));
        }
        let session_id = baseline_session.session_id.clone();
        let epoch = baseline_session.epoch;
        let stream_id = logical_stream.stream_id;
        let operation_id = logical_stream.operation_id.clone();
        let scope = GoawayScope {
            tenant_id: device.tenant_id,
            device_id: device.id,
            session_id: &session_id,
            epoch,
            service_id: Some(service_id),
            stream_id: Some(stream_id),
            operation_id: Some(&operation_id),
        };
        let scope_label = scope_context(scope, "held-forward");
        let baseline_emitted = logical_stream.last_emitted_relay_to_connector;
        let rotation_before = baseline_session.rotations_completed;
        let baseline_dispatches =
            owner_snapshot_before(cluster, scenario_deadline)
                .await?
                .lifetime_application_dispatches;
        let candidate = wait_for_candidate(
            cluster,
            device.tenant_id,
            device.id,
            service_id,
            &session_id,
            epoch,
            scenario_deadline,
        )
        .await?;
        let candidate_generation = candidate
            .candidate_generation
            .ok_or_else(|| HarnessError::Process("I08 GOAWAY candidate disappeared".into()))?;
        let candidate_connection_id =
            candidate.candidate_connection_id.clone().ok_or_else(|| {
                HarnessError::Process("I08 GOAWAY candidate connection missing".into())
            })?;
        // One maximum-sized, valid Echo record keeps the admitted H3 stream
        // observable while the response remains unread.  The fixture does
        // not use an unbounded pump or an arbitrary sleep to manufacture a
        // stream; it fails closed if the real peer diagnostics never observe
        // this exact forwarded stream as active.
        let mut held_payload = vec![b'g'; super::MAX_RECORD_BYTES];
        let marker = b"m7-i08-goaway-held-response";
        held_payload[..marker.len()].copy_from_slice(marker);
        send_echo_without_read(&mut cli_stream, &held_payload, scenario_deadline, &scope_label).await?;
        let active_connection_id = wait_for_active_peer_stream(
            cluster,
            device.tenant_id,
            device.id,
            service_id,
            &session_id,
            epoch,
            stream_id,
            &operation_id,
            baseline_emitted,
            scenario_deadline,
        )
        .await?;
        let before_planned_drain = owner_snapshot_before(cluster, scenario_deadline).await?;
        let post_goaway_dispatch_delta = before_planned_drain
            .lifetime_application_dispatches
            .saturating_sub(baseline_dispatches);
        if post_goaway_dispatch_delta != 1 {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY phase=held-record-before-drain dispatch delta was {}, expected exactly one [{}]",
                post_goaway_dispatch_delta, scope_label
            )));
        }
        let pre_admission_scope = PeerAdmissionScope::for_owner(&owner_before.token, service_id);
        if !peer_admission_barrier.arm(pre_admission_scope.clone()) {
            return Err(HarnessError::Process(
                "I08 GOAWAY pre-admission barrier was already armed".into(),
            ));
        }
        let _release_pre_admission =
            ReleasePeerAdmissionBarrier(Arc::clone(&peer_admission_barrier));
        let authorization = format!("Bearer {token}");
        let service_path = service_id.to_string();
        // Keep one real authenticated WSS request in flight after Axum has
        // completed auth/readiness/owner resolution. The server-side barrier
        // is inside `PeerRuntime::open_inner` immediately before pooled H3
        // admission, so this future must be polled while the fixture waits
        // for its exact scope rather than relying on sleep.
        let mut pre_admission_request = Box::pin(open_public_stream_with_authorization(
            ingress,
            &harness.pki.server_ca.certificate_der,
            &authorization,
            device.id,
            &service_path,
            &[],
        ));
        tokio::select! {
            result = &mut pre_admission_request => {
                match result {
                    Ok(PublicStreamProbe::Accepted(mut stream)) => {
                        let close_result = timeout_at(
                            tokio::time::Instant::from_std(cleanup_deadline),
                            stream.close(),
                        )
                        .await
                        .map_err(|_| {
                            HarnessError::Timeout(
                                "I08 GOAWAY pre-admission early 101 cleanup timed out".into(),
                            )
                        });
                        return Err(match close_result {
                            Ok(Ok(())) => HarnessError::Process(
                                "I08 GOAWAY pre-admission request upgraded before its exact barrier".into(),
                            ),
                            Ok(Err(error)) => HarnessError::Http(format!(
                                "I08 GOAWAY pre-admission early 101 cleanup failed: {error}"
                            )),
                            Err(error) => error,
                        });
                    }
                    Ok(PublicStreamProbe::Rejected(failure)) => {
                        return Err(HarnessError::Http(format!(
                            "I08 GOAWAY pre-admission request was rejected before its exact barrier: status={} code={:?} execution={:?}",
                            failure.status, failure.code, failure.execution,
                        )));
                    }
                    Err(error) => return Err(error),
                }
            }
            reached = timeout_at(
                tokio::time::Instant::from_std(scenario_deadline),
                peer_admission_barrier.wait_reached(),
            ) => {
                reached.map_err(|_| HarnessError::Timeout(
                    "I08 GOAWAY pre-admission barrier was not reached".into(),
                ))?;
            }
        }
        if peer_admission_barrier.hit_count() != 1
            || peer_admission_barrier.observed_scope() != Some(pre_admission_scope)
        {
            return Err(HarnessError::Process(
                "I08 GOAWAY pre-admission barrier observed an unexpected owner scope".into(),
            ));
        }
        cluster.relay(OWNER_NODE)?.request_peer_planned_drain()?;
        wait_for_goaway(cluster, active_connection_id, scope, scenario_deadline).await?;
        let seam_before_dispatches =
            owner_snapshot_before(cluster, scenario_deadline)
                .await?
                .lifetime_application_dispatches;
        // Release the same WSS request immediately after exact GOAWAY
        // observation.  The admitted response remains unread until this
        // already-resolved request has exercised the selected pooled H3 path.
        peer_admission_barrier.release();
        let pre_result = timeout_at(
            tokio::time::Instant::from_std(scenario_deadline),
            &mut pre_admission_request,
        )
        .await
        .map_err(|_| HarnessError::Timeout(
            "I08 GOAWAY pre-admission request did not finish after barrier release".into(),
        ))?;
        let pre_result = pre_result?;
        let pre_admission_goaway_not_dispatched = match pre_result {
            PublicStreamProbe::Rejected(failure) if is_peer_goaway_failure(&failure) => true,
            PublicStreamProbe::Rejected(failure) => {
                return Err(HarnessError::Http(format!(
                    "I08 GOAWAY phase=pre-admission returned status={} code={:?} execution={:?}; expected typed GOAWAY rejection",
                    failure.status, failure.code, failure.execution,
                )));
            }
            PublicStreamProbe::Accepted(mut stream) => {
                let close_result = timeout_at(
                    tokio::time::Instant::from_std(cleanup_deadline),
                    stream.close(),
                )
                .await
                .map_err(|_| HarnessError::Timeout(
                    "I08 GOAWAY pre-admission unexpected 101 cleanup timed out".into(),
                ))?
                .map_err(|error| HarnessError::Http(format!(
                    "I08 GOAWAY pre-admission unexpected 101 cleanup failed: {error}"
                )));
                return Err(match close_result {
                    Ok(()) => HarnessError::Process(
                        "I08 GOAWAY pre-admission request unexpectedly upgraded".into(),
                    ),
                    Err(error) => error,
                });
            }
        };
        let after_pre_admission = owner_snapshot_before(cluster, scenario_deadline).await?;
        if after_pre_admission
            .lifetime_application_dispatches
            .saturating_sub(seam_before_dispatches)
            != 0
        {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY phase=pre-admission changed owner dispatch after GOAWAY; {scope_label}"
            )));
        }
        receive_echo_after_goaway(
            &mut cli_stream,
            &held_payload,
            canary.as_bytes(),
            scenario_deadline,
            &scope_label,
        )
        .await?;
        let admitted_response_completed = true;
        let later_request_before_dispatches = after_pre_admission.lifetime_application_dispatches;
        // A fresh request that has not crossed the pre-resolution seam must
        // still stop at listener readiness and return CLUSTER_UNREADY. This
        // remains a separate gate from the typed GOAWAY attempt above.
        expect_postdrain_cluster_unready(
            ingress,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
            scenario_deadline,
            cleanup_deadline,
            &scope_label,
        )
        .await?;
        let post_goaway_not_dispatched = true;
        let after_later_request = owner_snapshot_before(cluster, scenario_deadline).await?;
        let later_request_dispatch_delta = after_later_request
            .lifetime_application_dispatches
            .saturating_sub(later_request_before_dispatches);
        if later_request_dispatch_delta != 0 {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY phase=post-drain-readiness request changed owner dispatch by {}, expected zero [{}]",
                later_request_dispatch_delta,
                scope_label
            )));
        }
        if !post_goaway_not_dispatched {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY phase=post-drain-readiness request crossed the planned admission boundary; {scope_label}"
            )));
        }
        wait_for_ingress_goaway(
            cluster,
            device.tenant_id,
            device.id,
            service_id,
            &session_id,
            epoch,
            scenario_deadline,
        )
        .await?;
        timeout_at(
            tokio::time::Instant::from_std(scenario_deadline),
            cli_stream.close(),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!(
            "I08 GOAWAY phase=response admitted stream close timed out; {scope_label}"
        )))?
        .map_err(|error| HarnessError::Http(format!(
            "I08 GOAWAY phase=response admitted stream close failed; {scope_label}: {error}"
        )))?;
        let ingress_goaway_observed = true;
        let committed = wait_for_committed_rotation(cluster, scope, rotation_before, scenario_deadline)
        .await?;
        if committed.active_generation != candidate_generation
            || committed.active_connection_id != candidate_connection_id
        {
            return Err(HarnessError::Process(
                "I08 GOAWAY committed rotation did not activate the observed candidate".into(),
            ));
        }
        let owner_after = timeout_at(
            tokio::time::Instant::from_std(scenario_deadline),
            cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now()),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("I08 GOAWAY phase=commit owner-after lookup timed out; {scope_label}")))?
        .map_err(|error| HarnessError::Redis(format!("I08 GOAWAY owner-after lookup: {error}")))?
        .ok_or_else(|| HarnessError::Process(format!("I08 GOAWAY phase=commit owner disappeared after rotation; {scope_label}")))?;
        if owner_after.token != owner_before.token
        {
            return Err(HarnessError::Process(format!(
                "I08 GOAWAY phase=commit owner token changed during planned rotation; {scope_label}"
            )));
        }
        let cli_survived = cli_process.try_wait()?.is_none();
        if !cli_survived {
            return Err(HarnessError::Process(
                "I08 GOAWAY CLI exited after the planned peer drain".into(),
            ));
        }
        let socket_high_water = cluster.device_fanout.diagnostics().peak_open;
        Ok(I08GoawayRotationEvidence {
            scope: "three_relay_rotation_planned_goaway",
            relay_count: cluster.relays.len(),
            actual_cli_process: cli_process.id().is_some(),
            owner_relay: OWNER_NODE.into(),
            ingress_relay: PEER_NODE.into(),
            tenant_id: device.tenant_id.to_string(),
            device_id: device.id.to_string(),
            service_id: service_id.to_string(),
            session_id,
            epoch,
            stream_id,
            operation_id,
            candidate_generation,
            candidate_connection_id,
            rotation_before,
            rotation_after: committed.rotations_completed,
            goaway_peer_node_id: PEER_NODE.into(),
            goaway_connection_id: active_connection_id,
            active_stream_observed: true,
            planned_goaway_sent: true,
            admitted_response_completed,
            pre_admission_goaway_not_dispatched,
            post_goaway_not_dispatched,
            ingress_goaway_observed,
            post_goaway_dispatch_delta,
            later_request_dispatch_delta,
            cli_survived,
            socket_high_water,
            cleanup_joined: false,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        })
    }
    .await;
    let mut cleanup_errors = Vec::new();
    let cli_stream_cleanup = timeout_at(
        tokio::time::Instant::from_std(cleanup_deadline),
        cli_stream.close(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("I08 GOAWAY CLI stream cleanup timed out".into()))
    .and_then(|result| result);
    if let Err(error) = cli_stream_cleanup {
        cleanup_errors.push(format!("I08 GOAWAY CLI stream cleanup: {error}"));
    }
    let cli_cleanup = {
        let remaining = cleanup_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            Err(HarnessError::Timeout(
                "I08 GOAWAY CLI cleanup timed out".into(),
            ))
        } else {
            cli_process
                .shutdown(remaining.min(Duration::from_secs(5)))
                .await
        }
    };
    if let Err(error) = cli_cleanup {
        cleanup_errors.push(format!("I08 GOAWAY CLI cleanup: {error}"));
    }
    match result {
        Ok(mut evidence) if cleanup_errors.is_empty() => {
            evidence.cleanup_joined = true;
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(cleanup_errors.join("; "))),
        Err(primary) if cleanup_errors.is_empty() => Err(primary),
        Err(primary) => Err(HarnessError::Process(format!(
            "{primary}; {}",
            cleanup_errors.join("; ")
        ))),
    }
}

/// Run the real three-relay M7-I08 planned-GOAWAY rotation fixture.
pub async fn verify() -> Result<I08GoawayRotationEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("I08 GOAWAY harness startup timed out".into()))??;
    let peer_admission_barrier = Arc::new(PeerAdmissionBarrier::default());
    let mut cluster = match timeout(
        STARTUP_TIMEOUT,
        ProductionCluster::start_with_peer_admission_barrier(
            &mut harness,
            PEER_NODE,
            Arc::clone(&peer_admission_barrier),
        ),
    )
    .await
    {
        Ok(Ok(cluster)) => cluster,
        Ok(Err(error)) => {
            let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 GOAWAY harness cleanup: {cleanup}"
                ))),
            };
        }
        Err(_) => {
            let error =
                HarnessError::Timeout("I08 GOAWAY production cluster startup timed out".into());
            let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; I08 GOAWAY harness cleanup: {cleanup}"
                ))),
            };
        }
    };
    let scenario = run_scenario(&mut cluster, &harness, peer_admission_barrier).await;
    let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("I08 GOAWAY cluster cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("I08 GOAWAY harness cleanup: {error}"));
    }
    match scenario {
        Ok(evidence) if cleanup_errors.is_empty() => {
            validate_i08_goaway_rotation_evidence(&evidence)?;
            Ok(evidence)
        }
        Ok(_) => Err(HarnessError::Process(cleanup_errors.join("; "))),
        Err(primary) if cleanup_errors.is_empty() => Err(primary),
        Err(primary) => Err(HarnessError::Process(format!(
            "{primary}; {}",
            cleanup_errors.join("; ")
        ))),
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{I08GoawayRotationEvidence, validate_i08_goaway_rotation_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> I08GoawayRotationEvidence {
        I08GoawayRotationEvidence {
            scope: "three_relay_rotation_planned_goaway",
            relay_count: 3,
            actual_cli_process: true,
            owner_relay: "relay-a".into(),
            ingress_relay: "relay-c".into(),
            tenant_id: "tenant-a".into(),
            device_id: "device-a".into(),
            service_id: "service-a".into(),
            session_id: "session-a".into(),
            epoch: 7,
            stream_id: 11,
            operation_id: "operation-a".into(),
            candidate_generation: 2,
            candidate_connection_id: "candidate-a".into(),
            rotation_before: 1,
            rotation_after: 2,
            goaway_peer_node_id: "relay-c".into(),
            goaway_connection_id: 9,
            active_stream_observed: true,
            planned_goaway_sent: true,
            admitted_response_completed: true,
            pre_admission_goaway_not_dispatched: true,
            post_goaway_not_dispatched: true,
            ingress_goaway_observed: true,
            post_goaway_dispatch_delta: 1,
            later_request_dispatch_delta: 0,
            cli_survived: true,
            socket_high_water: 3,
            cleanup_joined: true,
            elapsed_ms: 10,
        }
    }

    #[test]
    fn goaway_validator_accepts_complete_evidence() {
        assert!(validate_i08_goaway_rotation_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_goaway_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut I08GoawayRotationEvidence));
        let flags: [Disable; 9] = [
            ("actual_cli_process", |e| e.actual_cli_process = false),
            ("active_stream_observed", |e| {
                e.active_stream_observed = false
            }),
            ("planned_goaway_sent", |e| e.planned_goaway_sent = false),
            ("admitted_response_completed", |e| {
                e.admitted_response_completed = false
            }),
            ("pre_admission_goaway_not_dispatched", |e| {
                e.pre_admission_goaway_not_dispatched = false
            }),
            ("post_goaway_not_dispatched", |e| {
                e.post_goaway_not_dispatched = false
            }),
            ("ingress_goaway_observed", |e| {
                e.ingress_goaway_observed = false
            }),
            ("cli_survived", |e| e.cli_survived = false),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(
                validate_i08_goaway_rotation_evidence(&evidence),
                "I08 GOAWAY evidence",
            );
        }
    }

    #[test]
    fn every_goaway_identity_and_scope_requirement_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut I08GoawayRotationEvidence));
        let identities: [Mutate; 10] = [
            ("scope", |e| e.scope = "unexpected_scope"),
            ("owner_relay", |e| e.owner_relay = "relay-b".into()),
            ("ingress_relay", |e| e.ingress_relay = "relay-a".into()),
            ("tenant_id", |e| e.tenant_id.clear()),
            ("device_id", |e| e.device_id.clear()),
            ("service_id", |e| e.service_id.clear()),
            ("session_id", |e| e.session_id.clear()),
            ("operation_id", |e| e.operation_id.clear()),
            ("candidate_connection_id", |e| {
                e.candidate_connection_id.clear()
            }),
            ("goaway_peer_node_id", |e| {
                e.goaway_peer_node_id = "relay-b".into()
            }),
        ];
        for (_, mutate) in identities {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_i08_goaway_rotation_evidence(&evidence),
                "I08 GOAWAY evidence",
            );
        }
    }

    #[test]
    fn every_goaway_count_and_order_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut I08GoawayRotationEvidence));
        let bounds: [Mutate; 11] = [
            ("relay_count", |e| e.relay_count = 2),
            ("epoch", |e| e.epoch = 0),
            ("stream_id", |e| e.stream_id = 0),
            ("candidate_generation", |e| e.candidate_generation = 0),
            ("rotation_order", |e| e.rotation_after = e.rotation_before),
            ("goaway_connection_id", |e| e.goaway_connection_id = 0),
            ("post_goaway_dispatch_delta_zero", |e| {
                e.post_goaway_dispatch_delta = 0
            }),
            ("post_goaway_dispatch_delta_multiple", |e| {
                e.post_goaway_dispatch_delta = 2
            }),
            ("later_request_dispatch_delta", |e| {
                e.later_request_dispatch_delta = 1
            }),
            ("socket_high_water_zero", |e| e.socket_high_water = 0),
            ("socket_high_water_over_bound", |e| e.socket_high_water = 4),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_i08_goaway_rotation_evidence(&evidence),
                "I08 GOAWAY evidence",
            );
        }
    }
}
