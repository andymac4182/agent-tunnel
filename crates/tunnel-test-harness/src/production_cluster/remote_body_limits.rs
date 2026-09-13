//! M7-C24 remote-route body-limit boundaries through a non-owner ingress.
//!
//! The owner-local `handle_consumer_stream` and the forwarded
//! `handle_remote_consumer_stream` must make the same bounded body-limit
//! decision.  This gate drives the real three-relay fixture through a public
//! WSS listener that is **not** the selected owner, so every record crosses
//! the length-prefixed peer stream, and checks each boundary with payload-free
//! relay counters rather than inferred behaviour:
//!
//! * `maximum`: a `MAX_PAYLOAD_LEN` body echoes exactly, twice on one stream,
//!   with exactly one owner dispatch per record and no dispatch elsewhere.
//! * `zero`: an empty record echoes exactly with one owner dispatch.
//! * `limit + 1`: a length prefix one byte above the limit closes the public
//!   stream inside a bounded window before the owner reads any peer chunk,
//!   including when the prefix is split across two public frames.
//! * `truncated`: a legal prefix with a missing body is held open and never
//!   dispatched; the owner reads the forwarded prefix as C10 already proves.
//! * `coalesced`: two legal records in one public frame echo exactly in order;
//!   two legal records whose frame exceeds the bounded reassembly limit are
//!   rejected before any owner read.
//! * a sibling stream through the same ingress, refreshed immediately before
//!   the rejection stages, survives every rejection.
//! * `idle`: a stream that completed a maximum record and then carries no
//!   traffic is closed by the relay only after the fixture's peer HTTP/3 idle
//!   timeout.  This pins the bounded idle wait of the forwarded route, which
//!   is what makes a stalled or long-idle remote exchange fail to complete
//!   while the owner-local route has no equivalent bound.
//!
//! Every rejection is checked against `lifetime_consumer_chunk_reads` and
//! `lifetime_application_dispatches` on all three relays.  No request body,
//! token, or response payload is recorded in evidence.

use super::{
    ConsumerStream, PRODUCTION_PEER_IDLE_TIMEOUT, ProductionCluster, RunningHarness,
    STARTUP_TIMEOUT, connect_failure_to_harness, open_consumer_stream,
};
use crate::acceptance::helpers::{DeviceProfile, write_device_profile};
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result};
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tunnel_client::{ConnectOptions, TransportProfile};
use tunnel_protocol::MAX_PAYLOAD_LEN;

const ROTATION: tunnel_core::RotationConfig = tunnel_core::RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 5,
    overlap_seconds: 10,
};
const CANARY: &[u8] = b"m7-remote-body-limit-canary";
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(150);
/// The idle stage must observe the relay-initiated close inside this window,
/// which starts after the fixture's peer idle timeout has elapsed.
const IDLE_CLOSE_SLACK: Duration = Duration::from_secs(10);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);
/// A rejected prefix must close the public stream inside this window.  It is
/// deliberately far below the consumer credential lifetime so a relay that
/// merely waits for more input cannot pass by expiry.
const REJECTION_CLOSE_BUDGET: Duration = Duration::from_secs(5);
/// A legal truncated record must still be open after this window.
const TRUNCATED_HOLD_WINDOW: Duration = Duration::from_millis(750);
const OWNER_READ_BUDGET: Duration = Duration::from_secs(5);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_BODY_BYTES: usize = MAX_PAYLOAD_LEN;
const MAX_RESPONSE_RECORD: usize = MAX_BODY_BYTES + 256 + 4;
const COALESCED_RECORD_BYTES: usize = 1_000;
/// Two legal records whose combined frame exceeds the bounded reassembly limit.
const COALESCED_OVER_BUDGET_RECORD_BYTES: usize = 40_000;

/// Payload-free evidence from one remote-route body-limit run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RemoteBodyLimitEvidence {
    pub relay_count: usize,
    /// The public ingress used for every probe was not the selected owner.
    pub non_owner_ingress: bool,
    /// Configured body limit the boundaries were derived from.
    pub body_limit_bytes: usize,
    pub maximum_body_exact: bool,
    pub maximum_body_repeated_exact: bool,
    /// Owner dispatches for the two maximum records; other relays must be 0.
    pub maximum_body_owner_dispatches: u64,
    pub maximum_body_other_dispatches: u64,
    pub zero_body_exact: bool,
    pub zero_body_owner_dispatches: u64,
    pub zero_body_other_dispatches: u64,
    /// The stream carrying a `limit + 1` prefix was closed by the relay.
    pub over_limit_closed: bool,
    pub over_limit_close_ms: u64,
    /// Owner-side peer chunk reads during the `limit + 1` probe.
    pub over_limit_owner_reads: u64,
    pub over_limit_dispatches: u64,
    /// The same prefix split across two public frames was also rejected.
    pub split_over_limit_closed: bool,
    pub split_over_limit_close_ms: u64,
    pub split_over_limit_owner_reads: u64,
    pub split_over_limit_dispatches: u64,
    /// A legal prefix with no body stayed open across the hold window.
    pub truncated_held_open: bool,
    pub truncated_owner_read: bool,
    pub truncated_dispatches: u64,
    pub coalesced_exact: bool,
    pub coalesced_owner_dispatches: u64,
    pub coalesced_other_dispatches: u64,
    pub coalesced_over_budget_closed: bool,
    pub coalesced_over_budget_close_ms: u64,
    pub coalesced_over_budget_owner_reads: u64,
    pub coalesced_over_budget_dispatches: u64,
    /// The sibling echoed immediately before the rejection stages, so its
    /// survival afterwards is isolation evidence rather than an idle race.
    pub sibling_refreshed_before_rejections: bool,
    pub sibling_stream_survived: bool,
    /// An idle forwarded stream was closed by the relay, not by the consumer.
    pub idle_remote_closed: bool,
    /// Milliseconds from the last exchange to the observed close.
    pub idle_remote_close_ms: u64,
    /// Configured peer idle timeout the idle bound is derived from.
    pub peer_idle_timeout_ms: u64,
    pub cleanup_joined: bool,
}

/// Validate the mandatory remote-route body-limit evidence.
pub fn validate_remote_body_limit_evidence(evidence: &RemoteBodyLimitEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "remote body limits require exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.body_limit_bytes != MAX_BODY_BYTES {
        return Err(HarnessError::Process(format!(
            "remote body limits were derived from {} bytes, expected {MAX_BODY_BYTES}",
            evidence.body_limit_bytes
        )));
    }
    let required = [
        ("non_owner_ingress", evidence.non_owner_ingress),
        ("maximum_body_exact", evidence.maximum_body_exact),
        (
            "maximum_body_repeated_exact",
            evidence.maximum_body_repeated_exact,
        ),
        ("zero_body_exact", evidence.zero_body_exact),
        ("over_limit_closed", evidence.over_limit_closed),
        ("split_over_limit_closed", evidence.split_over_limit_closed),
        ("truncated_held_open", evidence.truncated_held_open),
        ("truncated_owner_read", evidence.truncated_owner_read),
        ("coalesced_exact", evidence.coalesced_exact),
        (
            "coalesced_over_budget_closed",
            evidence.coalesced_over_budget_closed,
        ),
        (
            "sibling_refreshed_before_rejections",
            evidence.sibling_refreshed_before_rejections,
        ),
        ("sibling_stream_survived", evidence.sibling_stream_survived),
        ("idle_remote_closed", evidence.idle_remote_closed),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "remote body limits required gate {name} was false"
        )));
    }
    let exact_counts = [
        (
            "maximum_body_owner_dispatches",
            evidence.maximum_body_owner_dispatches,
            2,
        ),
        (
            "maximum_body_other_dispatches",
            evidence.maximum_body_other_dispatches,
            0,
        ),
        (
            "zero_body_owner_dispatches",
            evidence.zero_body_owner_dispatches,
            1,
        ),
        (
            "zero_body_other_dispatches",
            evidence.zero_body_other_dispatches,
            0,
        ),
        ("over_limit_owner_reads", evidence.over_limit_owner_reads, 0),
        ("over_limit_dispatches", evidence.over_limit_dispatches, 0),
        (
            "split_over_limit_owner_reads",
            evidence.split_over_limit_owner_reads,
            0,
        ),
        (
            "split_over_limit_dispatches",
            evidence.split_over_limit_dispatches,
            0,
        ),
        ("truncated_dispatches", evidence.truncated_dispatches, 0),
        (
            "coalesced_owner_dispatches",
            evidence.coalesced_owner_dispatches,
            2,
        ),
        (
            "coalesced_other_dispatches",
            evidence.coalesced_other_dispatches,
            0,
        ),
        (
            "coalesced_over_budget_owner_reads",
            evidence.coalesced_over_budget_owner_reads,
            0,
        ),
        (
            "coalesced_over_budget_dispatches",
            evidence.coalesced_over_budget_dispatches,
            0,
        ),
    ];
    if let Some((name, observed, expected)) = exact_counts
        .into_iter()
        .find(|(_, observed, expected)| observed != expected)
    {
        return Err(HarnessError::Process(format!(
            "remote body limits counter {name} was {observed}, expected {expected}"
        )));
    }
    let close_budget_ms = u64::try_from(REJECTION_CLOSE_BUDGET.as_millis()).unwrap_or(u64::MAX);
    let bounded_closes = [
        ("over_limit_close_ms", evidence.over_limit_close_ms),
        (
            "split_over_limit_close_ms",
            evidence.split_over_limit_close_ms,
        ),
        (
            "coalesced_over_budget_close_ms",
            evidence.coalesced_over_budget_close_ms,
        ),
    ];
    if let Some((name, observed)) = bounded_closes
        .into_iter()
        .find(|(_, observed)| *observed > close_budget_ms)
    {
        return Err(HarnessError::Process(format!(
            "remote body limits rejection {name} took {observed}ms, bound {close_budget_ms}ms"
        )));
    }
    let peer_idle_ms = u64::try_from(PRODUCTION_PEER_IDLE_TIMEOUT.as_millis()).unwrap_or(u64::MAX);
    if evidence.peer_idle_timeout_ms != peer_idle_ms {
        return Err(HarnessError::Process(format!(
            "remote body limits peer_idle_timeout_ms was {}, expected {peer_idle_ms}",
            evidence.peer_idle_timeout_ms
        )));
    }
    // The transport idle timer is refreshed by the last transport operation,
    // so the public close cannot precede the idle timeout by more than the
    // final exchange's own latency; allow a small skew below and the bounded
    // slack above.
    let idle_lower = peer_idle_ms.saturating_sub(1_000);
    let idle_upper = peer_idle_ms
        .saturating_add(u64::try_from(IDLE_CLOSE_SLACK.as_millis()).unwrap_or(u64::MAX));
    if evidence.idle_remote_close_ms < idle_lower || evidence.idle_remote_close_ms > idle_upper {
        return Err(HarnessError::Process(format!(
            "remote body limits idle_remote_close_ms was {}, expected within {idle_lower}..={idle_upper}",
            evidence.idle_remote_close_ms
        )));
    }
    Ok(())
}

/// Run the bounded real three-relay remote-route body-limit matrix.
pub async fn verify() -> Result<RemoteBodyLimitEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("remote body limits harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "remote body limits scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    super::push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    super::push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    super::finish_scenario_with_cleanup(scenario, cleanup_errors).map(|mut evidence| {
        evidence.cleanup_joined = true;
        evidence
    })
}

struct Resources {
    profile_root: Option<TempDir>,
    profile: Option<DeviceProfile>,
    client: Option<tunnel_client::ConnectionHandle>,
    streams: Vec<ConsumerStream>,
}

impl Resources {
    async fn cleanup(&mut self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut failures = Vec::new();
        for mut stream in self.streams.drain(..) {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                failures.push("consumer cleanup deadline elapsed".to_owned());
                continue;
            }
            match timeout(remaining, stream.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => failures.push(format!("consumer cleanup: {error}")),
                Err(_) => failures.push("consumer cleanup timed out".to_owned()),
            }
        }
        if let Some(client) = self.client.take() {
            let result = client.stop().await;
            if let Err(error) = result {
                failures.push(format!("connector cleanup failed: {error}"));
            } else if Instant::now() >= deadline {
                failures.push("connector cleanup exceeded its deadline".to_owned());
            }
        }
        self.profile.take();
        self.profile_root.take();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(failures.join("; ")))
        }
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<RemoteBodyLimitEvidence> {
    let mut resources = Resources {
        profile_root: None,
        profile: None,
        client: None,
        streams: Vec::new(),
    };
    let scenario = run_inner(cluster, harness, &mut resources).await;
    let cleanup = resources.cleanup().await;
    match (scenario, cleanup) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Ok(_), Err(error)) => Err(HarnessError::Process(format!(
            "remote body limits cleanup failed: {error}"
        ))),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Process(format!(
            "{primary}; remote body limits cleanup failed: {cleanup}"
        ))),
    }
}

#[derive(Clone, Copy, Debug)]
struct Counters {
    dispatches: [u64; 3],
    reads: [u64; 3],
}

impl Counters {
    fn delta(self, before: Counters) -> Counters {
        let mut dispatches = [0; 3];
        let mut reads = [0; 3];
        for index in 0..3 {
            dispatches[index] = self.dispatches[index].saturating_sub(before.dispatches[index]);
            reads[index] = self.reads[index].saturating_sub(before.reads[index]);
        }
        Counters { dispatches, reads }
    }

    fn owner_and_others(values: [u64; 3], owner: usize) -> (u64, u64) {
        let owner_value = values[owner];
        let others = values
            .iter()
            .enumerate()
            .filter(|(index, _)| *index != owner)
            .map(|(_, value)| *value)
            .sum();
        (owner_value, others)
    }
}

async fn counters(cluster: &ProductionCluster) -> Result<Counters> {
    let mut dispatches = [0_u64; 3];
    let mut reads = [0_u64; 3];
    for (index, node_id) in ["relay-a", "relay-b", "relay-c"].into_iter().enumerate() {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        dispatches[index] = snapshot.lifetime_application_dispatches;
        reads[index] = snapshot.lifetime_consumer_chunk_reads;
    }
    Ok(Counters { dispatches, reads })
}

fn relay_index(node_id: &str) -> Result<usize> {
    ["relay-a", "relay-b", "relay-c"]
        .into_iter()
        .position(|candidate| candidate == node_id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("remote body limits owner was outside the relay set".into())
        })
}

async fn wait_for_owner_read(
    cluster: &ProductionCluster,
    owner: usize,
    before: u64,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        if counters(cluster).await?.reads[owner] > before {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

/// Outcome of waiting for the relay to close a public stream after a rejected
/// record.  `Closed` carries the observed close latency.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum CloseOutcome {
    Closed(Duration),
    Echoed,
    StillOpen,
}

/// Send raw public frames on a fresh stream and report whether the relay
/// closes it within the rejection budget.  Any Binary response is a failure
/// classification (`Echoed`), never a success.
async fn probe_rejection(stream: &mut ConsumerStream, frames: &[Vec<u8>]) -> Result<CloseOutcome> {
    let started = Instant::now();
    for frame in frames {
        stream
            .socket
            .send(Message::Binary(frame.clone().into()))
            .await
            .map_err(|error| {
                HarnessError::Http(format!("remote body limits probe send failed: {error}"))
            })?;
    }
    let deadline = started + REJECTION_CLOSE_BUDGET;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Ok(CloseOutcome::StillOpen);
        }
        match timeout(remaining, stream.socket.next()).await {
            Err(_) => return Ok(CloseOutcome::StillOpen),
            Ok(Some(Ok(Message::Close(_))) | None | Some(Err(_))) => {
                stream.closed = true;
                return Ok(CloseOutcome::Closed(started.elapsed()));
            }
            Ok(Some(Ok(Message::Binary(_)))) => return Ok(CloseOutcome::Echoed),
            Ok(Some(Ok(Message::Ping(payload)))) => {
                let _ = stream.socket.send(Message::Pong(payload)).await;
            }
            Ok(Some(Ok(Message::Text(_)))) => {
                return Err(HarnessError::Http(
                    "remote body limits probe received text".into(),
                ));
            }
            Ok(Some(Ok(_))) => {}
        }
    }
}

/// Read exactly one complete length-prefixed echo record, reassembling
/// across public frames, and check it against the offered payload.
async fn read_exact_echo(stream: &mut ConsumerStream, payload: &[u8]) -> Result<bool> {
    let expected_body = CANARY.len() + payload.len();
    let total = expected_body + 4;
    let deadline = Instant::now() + EXCHANGE_TIMEOUT;
    let mut response = Vec::with_capacity(total);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(
                "remote body limits echo response timed out".into(),
            ));
        }
        match timeout(remaining, stream.socket.next()).await {
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "remote body limits echo response timed out".into(),
                ));
            }
            Ok(Some(Ok(Message::Binary(bytes)))) => {
                if response.len().saturating_add(bytes.len()) > MAX_RESPONSE_RECORD {
                    return Err(HarnessError::Http(
                        "remote body limits echo exceeded bounded reassembly".into(),
                    ));
                }
                response.extend_from_slice(&bytes);
                if response.len() < 4 {
                    continue;
                }
                let declared =
                    u32::from_be_bytes([response[0], response[1], response[2], response[3]])
                        as usize;
                if declared.saturating_add(4) > MAX_RESPONSE_RECORD {
                    return Err(HarnessError::Http(
                        "remote body limits echo declared length exceeded bound".into(),
                    ));
                }
                if response.len() < declared + 4 {
                    continue;
                }
                if response.len() != declared + 4 {
                    return Err(HarnessError::Http(
                        "remote body limits echo contained trailing bytes".into(),
                    ));
                }
                return Ok(declared == expected_body
                    && response[4..4 + CANARY.len()] == *CANARY
                    && response[4 + CANARY.len()..] == *payload);
            }
            Ok(Some(Ok(Message::Ping(payload)))) => {
                stream
                    .socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| HarnessError::Http(format!("echo pong: {error}")))?;
            }
            Ok(Some(Ok(Message::Close(_))) | None) => {
                return Err(HarnessError::Http(
                    "remote body limits echo closed before response".into(),
                ));
            }
            Ok(Some(Ok(Message::Text(_)))) => {
                return Err(HarnessError::Http(
                    "remote body limits echo returned text".into(),
                ));
            }
            Ok(Some(Ok(_))) => {}
            Ok(Some(Err(error))) => {
                return Err(HarnessError::Http(format!(
                    "reading remote body limits echo: {error}"
                )));
            }
        }
    }
}

fn record(payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut Resources,
) -> Result<RemoteBodyLimitEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "remote body limits require three relays, observed {}",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;
    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("remote body limits tenant-A device is missing".into())
    })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("remote body limits service is missing".into())
        })?;
    resources.profile_root = Some(super::private_fixture_directory()?);
    let canary = std::str::from_utf8(CANARY)
        .map_err(|_| HarnessError::InvalidInput("remote body limits canary is not UTF-8".into()))?;
    let mut profile = write_device_profile(
        resources
            .profile_root
            .as_ref()
            .expect("owned profile root")
            .path(),
        device.id,
        service_id,
        canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = ROTATION;
    profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("remote body limits client config: {error}"))
    })?;
    let client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: profile.config.clone(),
            cancellation: tokio_util::sync::CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("remote body limits connector startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("remote body limits connector: {error}")))?;
    resources.profile = Some(profile);
    resources.client = Some(client);
    timeout(
        STARTUP_TIMEOUT,
        resources
            .client
            .as_mut()
            .expect("client resource installed")
            .wait_ready(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("remote body limits connector readiness timed out".into()))?
    .map_err(|error| {
        HarnessError::Process(format!("remote body limits connector not ready: {error}"))
    })?;
    let owner = {
        let deadline = Instant::now() + STARTUP_TIMEOUT;
        loop {
            match cluster
                .catalog
                .current_owner(device.tenant_id, device.id, Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("owner lookup: {error}")))?
            {
                Some(owner) => break owner,
                None if Instant::now() >= deadline => {
                    return Err(HarnessError::Timeout(
                        "remote body limits owner did not become visible".into(),
                    ));
                }
                None => sleep(Duration::from_millis(50)).await,
            }
        }
    };
    let owner_index = relay_index(&owner.token.node_id)?;
    let ingress_relay = cluster
        .relays
        .iter()
        .find(|relay| relay.node_id != owner.token.node_id)
        .ok_or_else(|| HarnessError::Process("no non-owner ingress relay".into()))?;
    let non_owner_ingress = ingress_relay.node_id != owner.token.node_id;
    let ingress = ingress_relay.consumer_addr()?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;
    let open = || async {
        open_consumer_stream(
            ingress,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)
    };

    // A sibling stream on the same ingress that must survive every rejection.
    let mut sibling = open().await?;
    sibling
        .round_trip(b"remote-body-limits-sibling-baseline", CANARY)
        .await?;

    // maximum, repeated on one stream, then zero.
    tracing::info!(stage = "maximum", "remote body limits stage");
    let mut primary = open().await?;
    let maximum = vec![0x5a_u8; MAX_BODY_BYTES];
    let before = counters(cluster).await?;
    primary
        .socket
        .send(Message::Binary(record(&maximum).into()))
        .await
        .map_err(|error| HarnessError::Http(format!("maximum record send: {error}")))?;
    let maximum_body_exact = read_exact_echo(&mut primary, &maximum).await?;
    let maximum_repeat = vec![0xa5_u8; MAX_BODY_BYTES];
    primary
        .socket
        .send(Message::Binary(record(&maximum_repeat).into()))
        .await
        .map_err(|error| HarnessError::Http(format!("repeated maximum record send: {error}")))?;
    let maximum_body_repeated_exact = read_exact_echo(&mut primary, &maximum_repeat).await?;
    let maximum_delta = counters(cluster).await?.delta(before);
    let (maximum_body_owner_dispatches, maximum_body_other_dispatches) =
        Counters::owner_and_others(maximum_delta.dispatches, owner_index);

    let before = counters(cluster).await?;
    primary
        .socket
        .send(Message::Binary(record(&[]).into()))
        .await
        .map_err(|error| HarnessError::Http(format!("zero record send: {error}")))?;
    let zero_body_exact = read_exact_echo(&mut primary, &[]).await?;
    let zero_delta = counters(cluster).await?.delta(before);
    let (zero_body_owner_dispatches, zero_body_other_dispatches) =
        Counters::owner_and_others(zero_delta.dispatches, owner_index);

    // coalesced: two legal records in one public frame.
    tracing::info!(stage = "coalesced", "remote body limits stage");
    let first = vec![0x11_u8; COALESCED_RECORD_BYTES];
    let second = vec![0x22_u8; COALESCED_RECORD_BYTES];
    let mut coalesced = record(&first);
    coalesced.extend_from_slice(&record(&second));
    let before = counters(cluster).await?;
    primary
        .socket
        .send(Message::Binary(coalesced.into()))
        .await
        .map_err(|error| HarnessError::Http(format!("coalesced record send: {error}")))?;
    let coalesced_exact = read_exact_echo(&mut primary, &first).await?
        && read_exact_echo(&mut primary, &second).await?;
    let coalesced_delta = counters(cluster).await?.delta(before);
    let (coalesced_owner_dispatches, coalesced_other_dispatches) =
        Counters::owner_and_others(coalesced_delta.dispatches, owner_index);
    resources.streams.push(primary);

    // limit + 1 in one frame.
    let sibling_refreshed_before_rejections = sibling
        .round_trip(b"remote-body-limits-sibling-before-rejections", CANARY)
        .await
        .is_ok();
    let rejection_stages_started = Instant::now();
    tracing::info!(stage = "over_limit", "remote body limits stage");
    let over_limit_prefix = ((MAX_BODY_BYTES + 1) as u32).to_be_bytes().to_vec();
    let mut stream = open().await?;
    let before = counters(cluster).await?;
    let outcome = probe_rejection(&mut stream, std::slice::from_ref(&over_limit_prefix)).await?;
    // A relay that forwards the prefix instead of rejecting it is observed on
    // the owner inside this settle window; the counter delta is the evidence.
    let _ = wait_for_owner_read(
        cluster,
        owner_index,
        before.reads[owner_index],
        TRUNCATED_HOLD_WINDOW,
    )
    .await?;
    let after = counters(cluster).await?.delta(before);
    resources.streams.push(stream);
    let (over_limit_closed, over_limit_close_ms) = match outcome {
        CloseOutcome::Closed(elapsed) => {
            (true, u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        }
        CloseOutcome::Echoed | CloseOutcome::StillOpen => (false, u64::MAX),
    };
    let over_limit_owner_reads = after.reads[owner_index];
    let over_limit_dispatches = after.dispatches.iter().sum();

    // limit + 1 split across two public frames.
    tracing::info!(stage = "split_over_limit", "remote body limits stage");
    let mut stream = open().await?;
    let before = counters(cluster).await?;
    let outcome = probe_rejection(
        &mut stream,
        &[
            over_limit_prefix[..2].to_vec(),
            over_limit_prefix[2..].to_vec(),
        ],
    )
    .await?;
    let _ = wait_for_owner_read(
        cluster,
        owner_index,
        before.reads[owner_index],
        TRUNCATED_HOLD_WINDOW,
    )
    .await?;
    let after = counters(cluster).await?.delta(before);
    resources.streams.push(stream);
    let (split_over_limit_closed, split_over_limit_close_ms) = match outcome {
        CloseOutcome::Closed(elapsed) => {
            (true, u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        }
        CloseOutcome::Echoed | CloseOutcome::StillOpen => (false, u64::MAX),
    };
    let split_over_limit_owner_reads = after.reads[owner_index];
    let split_over_limit_dispatches = after.dispatches.iter().sum();

    // truncated: a legal prefix whose body never arrives stays open.
    tracing::info!(stage = "truncated", "remote body limits stage");
    let mut stream = open().await?;
    let before = counters(cluster).await?;
    stream
        .socket
        .send(Message::Binary(vec![0, 0, 0, 1].into()))
        .await
        .map_err(|error| HarnessError::Http(format!("truncated record send: {error}")))?;
    let truncated_owner_read = wait_for_owner_read(
        cluster,
        owner_index,
        before.reads[owner_index],
        OWNER_READ_BUDGET,
    )
    .await?;
    let truncated_held_open = match timeout(TRUNCATED_HOLD_WINDOW, stream.socket.next()).await {
        Err(_) => true,
        Ok(Some(Ok(Message::Ping(payload)))) => {
            let _ = stream.socket.send(Message::Pong(payload)).await;
            true
        }
        Ok(_) => false,
    };
    let truncated_dispatches = counters(cluster)
        .await?
        .delta(before)
        .dispatches
        .iter()
        .sum();
    resources.streams.push(stream);

    // coalesced over budget: two legal records whose frame exceeds limit + 4.
    tracing::info!(stage = "coalesced_over_budget", "remote body limits stage");
    let mut over_budget = record(&vec![0x33_u8; COALESCED_OVER_BUDGET_RECORD_BYTES]);
    over_budget.extend_from_slice(&record(&vec![0x44_u8; COALESCED_OVER_BUDGET_RECORD_BYTES]));
    let mut stream = open().await?;
    let before = counters(cluster).await?;
    let outcome = probe_rejection(&mut stream, &[over_budget]).await?;
    let _ = wait_for_owner_read(
        cluster,
        owner_index,
        before.reads[owner_index],
        TRUNCATED_HOLD_WINDOW,
    )
    .await?;
    let after = counters(cluster).await?.delta(before);
    resources.streams.push(stream);
    let (coalesced_over_budget_closed, coalesced_over_budget_close_ms) = match outcome {
        CloseOutcome::Closed(elapsed) => {
            (true, u64::try_from(elapsed.as_millis()).unwrap_or(u64::MAX))
        }
        CloseOutcome::Echoed | CloseOutcome::StillOpen => (false, u64::MAX),
    };
    let coalesced_over_budget_owner_reads = after.reads[owner_index];
    let coalesced_over_budget_dispatches = after.dispatches.iter().sum();

    tracing::info!(stage = "sibling", "remote body limits stage");
    let sibling_stream_survived = match sibling
        .round_trip(b"remote-body-limits-sibling-after-rejections", CANARY)
        .await
    {
        Ok(()) => true,
        Err(error) => {
            // The harness error text is payload-free by construction.
            tracing::warn!(error = %error, "remote body limits sibling stream failed");
            false
        }
    };
    resources.streams.push(sibling);
    // The rejection stages plus the sibling check must stay well inside the
    // peer idle timeout, otherwise sibling survival would be an idle race.
    if rejection_stages_started.elapsed() >= PRODUCTION_PEER_IDLE_TIMEOUT / 2 {
        return Err(HarnessError::Timeout(format!(
            "remote body limits rejection stages took {}ms, too close to the {}ms peer idle bound",
            rejection_stages_started.elapsed().as_millis(),
            PRODUCTION_PEER_IDLE_TIMEOUT.as_millis()
        )));
    }

    // idle: a maximum record completes, then the forwarded stream carries no
    // traffic.  The relay must close it only after the peer idle timeout.
    tracing::info!(stage = "idle", "remote body limits stage");
    let mut idle = open().await?;
    let idle_payload = vec![0x66_u8; MAX_BODY_BYTES];
    idle.socket
        .send(Message::Binary(record(&idle_payload).into()))
        .await
        .map_err(|error| HarnessError::Http(format!("idle maximum record send: {error}")))?;
    if !read_exact_echo(&mut idle, &idle_payload).await? {
        return Err(HarnessError::Http(
            "remote body limits idle stage maximum echo mismatched".into(),
        ));
    }
    let idle_started = Instant::now();
    let idle_deadline = idle_started + PRODUCTION_PEER_IDLE_TIMEOUT + IDLE_CLOSE_SLACK;
    let (idle_remote_closed, idle_remote_close_ms) = loop {
        let remaining = idle_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            break (false, u64::MAX);
        }
        match timeout(remaining, idle.socket.next()).await {
            Err(_) => break (false, u64::MAX),
            Ok(Some(Ok(Message::Close(_))) | None | Some(Err(_))) => {
                idle.closed = true;
                break (
                    true,
                    u64::try_from(idle_started.elapsed().as_millis()).unwrap_or(u64::MAX),
                );
            }
            Ok(Some(Ok(Message::Ping(payload)))) => {
                let _ = idle.socket.send(Message::Pong(payload)).await;
            }
            Ok(Some(Ok(Message::Binary(_) | Message::Text(_)))) => {
                return Err(HarnessError::Http(
                    "remote body limits idle stream received unsolicited data".into(),
                ));
            }
            Ok(Some(Ok(_))) => {}
        }
    };
    resources.streams.push(idle);

    let evidence = RemoteBodyLimitEvidence {
        relay_count: cluster.relays.len(),
        non_owner_ingress,
        body_limit_bytes: MAX_BODY_BYTES,
        maximum_body_exact,
        maximum_body_repeated_exact,
        maximum_body_owner_dispatches,
        maximum_body_other_dispatches,
        zero_body_exact,
        zero_body_owner_dispatches,
        zero_body_other_dispatches,
        over_limit_closed,
        over_limit_close_ms,
        over_limit_owner_reads,
        over_limit_dispatches,
        split_over_limit_closed,
        split_over_limit_close_ms,
        split_over_limit_owner_reads,
        split_over_limit_dispatches,
        truncated_held_open,
        truncated_owner_read,
        truncated_dispatches,
        coalesced_exact,
        coalesced_owner_dispatches,
        coalesced_other_dispatches,
        coalesced_over_budget_closed,
        coalesced_over_budget_close_ms,
        coalesced_over_budget_owner_reads,
        coalesced_over_budget_dispatches,
        sibling_refreshed_before_rejections,
        sibling_stream_survived,
        idle_remote_closed,
        idle_remote_close_ms,
        peer_idle_timeout_ms: u64::try_from(PRODUCTION_PEER_IDLE_TIMEOUT.as_millis())
            .unwrap_or(u64::MAX),
        cleanup_joined: false,
    };
    // Payload-free: flags, counters and latencies only.
    tracing::info!(?evidence, "remote body limits evidence before validation");
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::{RemoteBodyLimitEvidence, validate_remote_body_limit_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn evidence() -> RemoteBodyLimitEvidence {
        RemoteBodyLimitEvidence {
            relay_count: 3,
            non_owner_ingress: true,
            body_limit_bytes: super::MAX_BODY_BYTES,
            maximum_body_exact: true,
            maximum_body_repeated_exact: true,
            maximum_body_owner_dispatches: 2,
            maximum_body_other_dispatches: 0,
            zero_body_exact: true,
            zero_body_owner_dispatches: 1,
            zero_body_other_dispatches: 0,
            over_limit_closed: true,
            over_limit_close_ms: 12,
            over_limit_owner_reads: 0,
            over_limit_dispatches: 0,
            split_over_limit_closed: true,
            split_over_limit_close_ms: 12,
            split_over_limit_owner_reads: 0,
            split_over_limit_dispatches: 0,
            truncated_held_open: true,
            truncated_owner_read: true,
            truncated_dispatches: 0,
            coalesced_exact: true,
            coalesced_owner_dispatches: 2,
            coalesced_other_dispatches: 0,
            coalesced_over_budget_closed: true,
            coalesced_over_budget_close_ms: 12,
            coalesced_over_budget_owner_reads: 0,
            coalesced_over_budget_dispatches: 0,
            sibling_refreshed_before_rejections: true,
            sibling_stream_survived: true,
            idle_remote_closed: true,
            idle_remote_close_ms: 10_050,
            peer_idle_timeout_ms: 10_000,
            cleanup_joined: true,
        }
    }

    #[test]
    fn remote_body_limit_validator_accepts_complete_evidence() {
        validate_remote_body_limit_evidence(&evidence()).expect("complete evidence is valid");
    }

    #[test]
    fn every_remote_body_limit_flag_count_and_bound_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut RemoteBodyLimitEvidence));
        let cases: [Mutate; 36] = [
            ("three relays", |e| e.relay_count = 2),
            ("derived from", |e| e.body_limit_bytes = 65_535),
            ("non_owner_ingress", |e| e.non_owner_ingress = false),
            ("maximum_body_exact", |e| e.maximum_body_exact = false),
            ("maximum_body_repeated_exact", |e| {
                e.maximum_body_repeated_exact = false
            }),
            ("maximum_body_owner_dispatches", |e| {
                e.maximum_body_owner_dispatches = 1
            }),
            ("maximum_body_other_dispatches", |e| {
                e.maximum_body_other_dispatches = 1
            }),
            ("zero_body_exact", |e| e.zero_body_exact = false),
            ("zero_body_owner_dispatches", |e| {
                e.zero_body_owner_dispatches = 0
            }),
            ("zero_body_other_dispatches", |e| {
                e.zero_body_other_dispatches = 1
            }),
            ("over_limit_closed", |e| e.over_limit_closed = false),
            ("over_limit_close_ms", |e| e.over_limit_close_ms = 5_001),
            ("over_limit_owner_reads", |e| e.over_limit_owner_reads = 1),
            ("over_limit_dispatches", |e| e.over_limit_dispatches = 1),
            ("split_over_limit_closed", |e| {
                e.split_over_limit_closed = false
            }),
            ("split_over_limit_close_ms", |e| {
                e.split_over_limit_close_ms = u64::MAX
            }),
            ("split_over_limit_owner_reads", |e| {
                e.split_over_limit_owner_reads = 1
            }),
            ("split_over_limit_dispatches", |e| {
                e.split_over_limit_dispatches = 1
            }),
            ("truncated_held_open", |e| e.truncated_held_open = false),
            ("truncated_owner_read", |e| e.truncated_owner_read = false),
            ("truncated_dispatches", |e| e.truncated_dispatches = 1),
            ("coalesced_exact", |e| e.coalesced_exact = false),
            ("coalesced_owner_dispatches", |e| {
                e.coalesced_owner_dispatches = 1
            }),
            ("coalesced_other_dispatches", |e| {
                e.coalesced_other_dispatches = 1
            }),
            ("coalesced_over_budget_closed", |e| {
                e.coalesced_over_budget_closed = false
            }),
            ("coalesced_over_budget_close_ms", |e| {
                e.coalesced_over_budget_close_ms = 5_001
            }),
            ("coalesced_over_budget_owner_reads", |e| {
                e.coalesced_over_budget_owner_reads = 1
            }),
            ("coalesced_over_budget_dispatches", |e| {
                e.coalesced_over_budget_dispatches = 1
            }),
            ("sibling_refreshed_before_rejections", |e| {
                e.sibling_refreshed_before_rejections = false
            }),
            ("sibling_stream_survived", |e| {
                e.sibling_stream_survived = false
            }),
            ("idle_remote_closed", |e| e.idle_remote_closed = false),
            ("idle_remote_close_ms", |e| e.idle_remote_close_ms = 8_999),
            ("idle_remote_close_ms", |e| e.idle_remote_close_ms = 20_001),
            ("idle_remote_close_ms", |e| {
                e.idle_remote_close_ms = u64::MAX
            }),
            ("peer_idle_timeout_ms", |e| e.peer_idle_timeout_ms = 60_000),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, mutate) in cases {
            let mut value = evidence();
            mutate(&mut value);
            assert_rejected(validate_remote_body_limit_evidence(&value), name);
        }
    }
}
