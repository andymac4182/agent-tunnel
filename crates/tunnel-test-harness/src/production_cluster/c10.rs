//! Focused actual-path coverage for the M7-C10 admission and framing gates.
//!
//! The parent module supplies the real three-relay setup, consumer streams,
//! and process helpers. The owner-token race uses the C27 server barrier so
//! the old raw bearer is admitted before the complete owner token changes and
//! the public 101 response is constructed.

use super::{
    ManagedProcess, ProductionCluster, RunningHarness, STARTUP_TIMEOUT, connect_failure_to_harness,
    open_consumer_stream, start_cli_smoke, wait_for_fanout_drained,
};
use crate::acceptance::helpers::DeviceProfile;
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result};
use chrono::Utc;
use futures_util::SinkExt;
use std::{collections::BTreeMap, sync::Arc, time::Duration};
use tempfile::TempDir;
use tokio::time::{Instant, sleep, timeout};
use tokio_tungstenite::tungstenite::Message;
use tunnel_client::{ConnectOptions, TransportProfile};
use tunnel_relay::ConsumerUpgradeBarrier;

use super::admission::{
    PublicEchoRequest, PublicStreamProbe, open_public_stream_with_authorization,
    public_echo_request,
};

const C10_ROTATION: tunnel_core::RotationConfig = tunnel_core::RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 5,
    overlap_seconds: 10,
};
const C10_BODY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
const C10_CANARY: &[u8] = b"m7-c10-canary";
const C10_RACE_TIMEOUT: Duration = Duration::from_secs(20);
const C10_RESOURCE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

fn cleanup_remaining(deadline: Instant, label: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        Err(HarnessError::Timeout(format!(
            "{label} cleanup deadline elapsed"
        )))
    } else {
        Ok(remaining)
    }
}

async fn close_stream_until(
    stream: &mut super::ConsumerStream,
    deadline: Instant,
    label: &str,
) -> Result<()> {
    let remaining = cleanup_remaining(deadline, label)?;
    timeout(remaining, stream.close())
        .await
        .map_err(|_| HarnessError::Timeout(format!("{label} cleanup timed out")))??;
    Ok(())
}

async fn shutdown_process_until(
    process: ManagedProcess,
    deadline: Instant,
    label: &str,
) -> Result<()> {
    // `ManagedProcess::shutdown` owns the child kill/reap and stdout/stderr
    // joins.  Do not wrap it in `timeout`: cancellation between the child
    // reap and those joins would detach the very handles this fixture must
    // prove were cleaned up.  Its grace/forced-reap/output-join bounds remain
    // active; the absolute deadline is checked after the owned operation.
    let remaining = deadline.saturating_duration_since(Instant::now());
    let result = process
        .shutdown(remaining.min(Duration::from_secs(5)))
        .await;
    let deadline_elapsed = Instant::now() >= deadline;
    match (result, deadline_elapsed) {
        (Ok(_), false) => Ok(()),
        (Err(error), false) => Err(HarnessError::Process(format!(
            "{label} cleanup failed: {error}"
        ))),
        (Ok(_), true) => Err(HarnessError::Timeout(format!(
            "{label} cleanup exceeded its absolute deadline"
        ))),
        (Err(error), true) => Err(HarnessError::Process(format!(
            "{label} cleanup failed after its absolute deadline: {error}"
        ))),
    }
}

async fn stop_client_until(
    client: &tunnel_client::ConnectionHandle,
    deadline: Instant,
    label: &str,
) -> Result<()> {
    // ConnectionHandle::stop joins its supervisor.  Await it to completion so
    // a race failure cannot leave a client task detached; enforce the shared
    // deadline by classifying an overrun after the owned join.
    let result = client.stop().await;
    if Instant::now() >= deadline {
        return match result {
            Ok(()) => Err(HarnessError::Timeout(format!(
                "{label} cleanup exceeded its absolute deadline"
            ))),
            Err(error) => Err(HarnessError::Process(format!(
                "{label} cleanup failed after its absolute deadline: {error}"
            ))),
        };
    }
    result.map_err(|error| HarnessError::Process(format!("{label} cleanup failed: {error}")))
}

async fn close_stream_preserving_primary(
    stream: &mut super::ConsumerStream,
    deadline: Instant,
    label: &str,
    primary: HarnessError,
) -> HarnessError {
    match close_stream_until(stream, deadline, label).await {
        Ok(()) => primary,
        Err(cleanup) => HarnessError::Process(format!("{primary}; {cleanup}")),
    }
}

struct C10UpgradeBarriers {
    by_node: BTreeMap<String, Arc<ConsumerUpgradeBarrier>>,
}

struct ReleaseUpgradeBarrier(Arc<ConsumerUpgradeBarrier>);

impl Drop for ReleaseUpgradeBarrier {
    fn drop(&mut self) {
        self.0.release();
    }
}

impl C10UpgradeBarriers {
    fn new() -> Self {
        Self {
            by_node: ["relay-a", "relay-b", "relay-c"]
                .into_iter()
                .map(|node| (node.to_owned(), Arc::new(ConsumerUpgradeBarrier::default())))
                .collect(),
        }
    }

    fn by_node(&self) -> BTreeMap<String, Arc<ConsumerUpgradeBarrier>> {
        self.by_node
            .iter()
            .map(|(node, barrier)| (node.clone(), Arc::clone(barrier)))
            .collect()
    }

    fn for_node(&self, node_id: &str) -> Result<Arc<ConsumerUpgradeBarrier>> {
        self.by_node.get(node_id).cloned().ok_or_else(|| {
            HarnessError::InvalidInput(format!("C10 barrier missing for relay {node_id}"))
        })
    }
}

/// Payload-free evidence from the complete real C10 path.  Every race flag is
/// required by the validator; a partial run cannot be presented as complete.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct C10ActualPathEvidence {
    pub relay_count: usize,
    pub fresh_control_after_no_live_owner: bool,
    pub fresh_epoch_advanced: bool,
    pub empty_body_single_prefix: bool,
    pub empty_body_owner_read: bool,
    pub empty_body_dispatch_delta: [u64; 3],
    pub empty_unary_body_response_exact: bool,
    pub empty_unary_body_owner_read: bool,
    pub empty_unary_body_dispatch_delta: [u64; 3],
    pub truncated_body_owner_read: bool,
    pub truncated_body_not_dispatched: bool,
    pub raw_bearer_owner_revalidated: bool,
    pub owner_token_changed_before_101: bool,
    pub owner_change_pre_101_rejected: bool,
    pub owner_change_pre_101_not_dispatched: bool,
    pub owner_change_pre_101_body_not_polled: bool,
    pub cleanup_joined: bool,
}

pub fn validate_c10_actual_path_evidence(evidence: &C10ActualPathEvidence) -> Result<()> {
    let selected_once = |delta: &[u64; 3]| {
        delta.iter().filter(|&&value| value == 1).count() == 1
            && delta.iter().all(|&value| value <= 1)
    };
    if evidence.relay_count != 3
        || !evidence.fresh_control_after_no_live_owner
        || !evidence.fresh_epoch_advanced
        || !evidence.empty_body_single_prefix
        || !evidence.empty_body_owner_read
        || !selected_once(&evidence.empty_body_dispatch_delta)
        || !evidence.empty_unary_body_response_exact
        || !evidence.empty_unary_body_owner_read
        || !selected_once(&evidence.empty_unary_body_dispatch_delta)
        || !evidence.truncated_body_owner_read
        || !evidence.truncated_body_not_dispatched
        || !evidence.raw_bearer_owner_revalidated
        || !evidence.owner_token_changed_before_101
        || !evidence.owner_change_pre_101_rejected
        || !evidence.owner_change_pre_101_not_dispatched
        || !evidence.owner_change_pre_101_body_not_polled
        || !evidence.cleanup_joined
    {
        return Err(HarnessError::Process(
            "C10 admission/framing evidence omitted a required invariant".into(),
        ));
    }
    Ok(())
}

struct C10Resources {
    profile_root: Option<TempDir>,
    profile: Option<DeviceProfile>,
    client: Option<tunnel_client::ConnectionHandle>,
    stream: Option<super::ConsumerStream>,
    fresh_process: Option<ManagedProcess>,
    fresh_stream: Option<super::ConsumerStream>,
    replacement_process: Option<ManagedProcess>,
    replacement_stream: Option<super::ConsumerStream>,
}

impl C10Resources {
    async fn cleanup(&mut self) -> Result<()> {
        let deadline = Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT;
        let mut failures = Vec::new();
        if let Some(mut stream) = self.fresh_stream.take()
            && let Err(error) = close_stream_until(&mut stream, deadline, "fresh consumer").await
        {
            failures.push(format!("fresh consumer cleanup: {error}"));
        }
        if let Some(mut stream) = self.replacement_stream.take()
            && let Err(error) =
                close_stream_until(&mut stream, deadline, "replacement consumer").await
        {
            failures.push(format!("replacement consumer cleanup: {error}"));
        }
        if let Some(process) = self.replacement_process.take()
            && let Err(error) = shutdown_process_until(process, deadline, "replacement CLI").await
        {
            failures.push(format!("replacement CLI cleanup: {error}"));
        }
        if let Some(process) = self.fresh_process.take()
            && let Err(error) = shutdown_process_until(process, deadline, "fresh CLI").await
        {
            failures.push(format!("fresh CLI cleanup: {error}"));
        }
        if let Some(mut stream) = self.stream.take()
            && let Err(error) = close_stream_until(&mut stream, deadline, "consumer").await
        {
            failures.push(format!("consumer cleanup: {error}"));
        }
        if let Some(client) = self.client.take()
            && let Err(error) = stop_client_until(&client, deadline, "connector").await
        {
            failures.push(format!("connector cleanup: {error}"));
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

/// Run the bounded real three-relay subset.
pub async fn verify() -> Result<C10ActualPathEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(C10_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("C10 harness startup timed out".into()))??;
    let upgrade_barriers = C10UpgradeBarriers::new();
    let mut cluster = match ProductionCluster::start_with_public_upgrade_barriers(
        &mut harness,
        upgrade_barriers.by_node(),
        64,
    )
    .await
    {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    // Every child operation below owns a bounded phase deadline. Do not wrap
    // this future in an outer timeout: dropping it would drop the live
    // ConnectionHandle/ManagedProcess before their owned join paths run.
    let scenario = run_actual_path(&mut cluster, &harness, &upgrade_barriers).await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    match (scenario, cluster_cleanup, harness_cleanup) {
        (Ok(mut evidence), Ok(()), Ok(())) => {
            evidence.cleanup_joined = true;
            Ok(evidence)
        }
        (Ok(_), cluster_error, harness_error) => Err(cleanup_failure(
            "C10 scenario succeeded",
            cluster_error,
            harness_error,
        )),
        (Err(primary), Ok(()), Ok(())) => Err(primary),
        (Err(primary), cluster_error, harness_error) => {
            let cleanup = cleanup_failure("C10 cleanup", cluster_error, harness_error);
            Err(HarnessError::Process(format!("{primary}; {cleanup}")))
        }
    }
}

fn cleanup_failure(
    label: &str,
    cluster: std::result::Result<(), HarnessError>,
    harness: std::result::Result<(), HarnessError>,
) -> HarnessError {
    let mut failures = Vec::new();
    if let Err(error) = cluster {
        failures.push(format!("cluster cleanup: {error}"));
    }
    if let Err(error) = harness {
        failures.push(format!("catalog cleanup: {error}"));
    }
    if failures.is_empty() {
        HarnessError::Process(format!("{label}: no cleanup error"))
    } else {
        HarnessError::Process(format!("{label}: {}", failures.join("; ")))
    }
}

async fn run_actual_path(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    upgrade_barriers: &C10UpgradeBarriers,
) -> Result<C10ActualPathEvidence> {
    let mut resources = C10Resources {
        profile_root: None,
        profile: None,
        client: None,
        stream: None,
        fresh_process: None,
        fresh_stream: None,
        replacement_process: None,
        replacement_stream: None,
    };
    let scenario = run_actual_path_inner(cluster, harness, &mut resources, upgrade_barriers).await;
    let cleanup = resources.cleanup().await;
    match (scenario, cleanup) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Ok(_), Err(error)) => Err(HarnessError::Process(format!(
            "C10 scenario cleanup failed: {error}"
        ))),
        (Err(primary), Ok(())) => Err(primary),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Process(format!(
            "{primary}; C10 scenario cleanup failed: {cleanup}"
        ))),
    }
}

async fn run_actual_path_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut C10Resources,
    upgrade_barriers: &C10UpgradeBarriers,
) -> Result<C10ActualPathEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "C10 requires three relays, observed {}",
            cluster.relays.len()
        )));
    }
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("C10 tenant-A device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("C10 echo service is missing".into()))?;
    resources.profile_root = Some(super::private_fixture_directory()?);
    let mut profile = write_device_profile(
        resources
            .profile_root
            .as_ref()
            .expect("owned profile root")
            .path(),
        device.id,
        service_id,
        "m7-c10-canary",
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = C10_ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("C10 client config: {error}")))?;

    resources.profile = Some(profile);
    let client = timeout(
        STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: resources
                .profile
                .as_ref()
                .expect("owned device profile")
                .config
                .clone(),
            cancellation: tokio_util::sync::CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("C10 initial connector startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("C10 initial connector failed: {error}")))?;
    resources.client = Some(client);
    let initial_session = timeout(
        STARTUP_TIMEOUT,
        resources
            .client
            .as_mut()
            .expect("C10 client resource installed")
            .wait_ready(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("C10 initial connector readiness timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("C10 initial connector not ready: {error}")))?;
    let initial_owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    if initial_owner.token.epoch != initial_session.epoch
        || initial_owner.token.session_id != initial_session.session_id
        || initial_owner.token.tenant_id != device.tenant_id
        || initial_owner.token.device_id != device.id
    {
        return Err(HarnessError::Process(
            "C10 initial owner epoch did not match the authenticated client session".into(),
        ));
    }

    let ingress = cluster
        .relays
        .iter()
        .find(|relay| relay.node_id != initial_owner.token.node_id)
        .ok_or_else(|| HarnessError::Process("C10 has no non-owner ingress relay".into()))?
        .consumer_addr()?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let stream = open_consumer_stream(
        ingress,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    .map_err(connect_failure_to_harness)?;
    resources.stream = Some(stream);

    // round_trip_capture rejects missing, duplicate, coalesced, and trailing
    // bytes. A zero-length request therefore proves the actual one-prefix
    // response envelope while also exercising a successful empty body.
    let before_empty = counters(cluster).await?;
    let empty_response = resources
        .stream
        .as_mut()
        .expect("C10 consumer resource installed")
        .round_trip_capture(&[], C10_CANARY)
        .await
        .map_err(|error| HarnessError::Http(format!("C10 empty echo: {error}")))?;
    if !empty_response.is_empty() {
        return Err(HarnessError::Http(
            "C10 empty echo returned a non-empty payload suffix".into(),
        ));
    }
    let after_empty = counters(cluster).await?;
    let empty_dispatch_delta = subtract(after_empty.0, before_empty.0);
    let empty_read_delta = subtract(after_empty.1, before_empty.1);
    let owner_index = relay_index(&initial_owner.token.node_id)?;
    let empty_body_single_prefix = empty_dispatch_delta[owner_index] == 1
        && empty_dispatch_delta
            .iter()
            .enumerate()
            .all(|(index, value)| index == owner_index || *value == 0);
    let empty_body_owner_read = empty_read_delta[owner_index] == 1
        && empty_read_delta
            .iter()
            .enumerate()
            .all(|(index, value)| index == owner_index || *value == 0);
    if !empty_body_single_prefix || !empty_body_owner_read {
        return Err(HarnessError::Process(format!(
            "C10 empty body counters were not selected-owner-only: dispatch={empty_dispatch_delta:?}, reads={empty_read_delta:?}"
        )));
    }

    // The unary HTTPS route reads the public body before forwarding the
    // authenticated ConsumerStreams envelope. Reuse the production helper
    // so the zero-byte HTTP request is observed at the public boundary, then
    // require one owner-side peer chunk and one owner dispatch as the effect
    // sentinel. The WSS exact-prefix check above and this unary check are
    // intentionally separate: a successful empty body must not be confused
    // with a body that was never polled.
    let service_text = service_id.to_string();
    let before_empty_unary = counters(cluster).await?;
    let (empty_unary_status, empty_unary_body) = public_echo_request(PublicEchoRequest {
        consumer_addr: ingress,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token: &token,
        device_id: device.id,
        service: &service_text,
        headers: &[],
        body: &[],
    })
    .await?;
    let after_empty_unary = counters(cluster).await?;
    let empty_unary_dispatch_delta = subtract(after_empty_unary.0, before_empty_unary.0);
    let empty_unary_read_delta = subtract(after_empty_unary.1, before_empty_unary.1);
    let empty_unary_body_response_exact =
        empty_unary_status == 200 && empty_unary_body.as_slice() == C10_CANARY;
    let empty_unary_body_owner_read = empty_unary_read_delta[owner_index] == 1
        && empty_unary_read_delta
            .iter()
            .enumerate()
            .all(|(index, value)| index == owner_index || *value == 0);
    let empty_unary_body_selected_dispatch = empty_unary_dispatch_delta[owner_index] == 1
        && empty_unary_dispatch_delta
            .iter()
            .enumerate()
            .all(|(index, value)| index == owner_index || *value == 0);
    if !empty_unary_body_response_exact
        || !empty_unary_body_owner_read
        || !empty_unary_body_selected_dispatch
    {
        return Err(HarnessError::Process(format!(
            "C10 empty unary body was not a selected-owner effect: status={empty_unary_status}, body_len={}, dispatch={empty_unary_dispatch_delta:?}, reads={empty_unary_read_delta:?}",
            empty_unary_body.len()
        )));
    }

    // A declared one-byte record with no body must be consumed as a bounded
    // peer chunk but can never reach the actor. This is the failed/unpolled
    // contrast to the successful zero-byte record above.
    let before_truncated = counters(cluster).await?;
    resources
        .stream
        .as_mut()
        .expect("C10 consumer resource installed")
        .socket
        .send(Message::Binary(vec![0, 0, 0, 1].into()))
        .await
        .map_err(|error| HarnessError::Http(format!("C10 truncated record send: {error}")))?;
    let truncated_read = wait_for_owner_read(
        cluster,
        owner_index,
        before_truncated.1[owner_index],
        C10_BODY_PROBE_TIMEOUT,
    )
    .await?;
    let truncated_cleanup_deadline = Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT;
    let mut stream = resources
        .stream
        .take()
        .expect("C10 consumer resource installed");
    let close_result = close_stream_until(
        &mut stream,
        truncated_cleanup_deadline,
        "C10 truncated-record consumer",
    )
    .await;
    resources.stream = Some(stream);
    close_result?;
    let after_truncated = counters(cluster).await?;
    let truncated_dispatch_delta = subtract(after_truncated.0, before_truncated.0);
    let truncated_body_not_dispatched = truncated_dispatch_delta == [0, 0, 0];
    if !truncated_read || !truncated_body_not_dispatched {
        return Err(HarnessError::Process(format!(
            "C10 truncated body was not a consumed/no-effect record: owner_read={truncated_read}, dispatch={truncated_dispatch_delta:?}"
        )));
    }

    let race = run_owner_token_race(
        cluster,
        harness,
        resources,
        upgrade_barriers,
        &initial_owner,
        ingress,
        device.id,
        service_id,
        &token,
    )
    .await?;

    let post_race_cleanup_deadline = Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT;

    // Stop the first owner and wait for the authoritative Redis absence before
    // starting the fresh CLI. The second control/data pair is therefore a
    // genuine admission after NoLiveOwner, rather than an overlapping claim.
    if let Some(client) = resources.client.take() {
        stop_client_until(&client, post_race_cleanup_deadline, "C10 initial connector").await?;
    }
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    wait_for_fanout_drained(&cluster.device_fanout, "C10 initial device").await?;
    let (fresh_process, fresh_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        resources.profile.as_ref().expect("owned device profile"),
        &token,
        device.id,
        service_id,
    )
    .await?;
    resources.fresh_process = Some(fresh_process);
    resources.fresh_stream = Some(fresh_stream);
    let fresh_owner = wait_for_owner(cluster, device.tenant_id, device.id).await?;
    let fresh_epoch_advanced = fresh_owner.token.epoch > initial_owner.token.epoch;
    let fresh_control_after_no_live_owner = fresh_epoch_advanced
        && fresh_owner.token.tenant_id == device.tenant_id
        && fresh_owner.token.device_id == device.id;
    let fresh_cleanup_deadline = Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT;
    resources
        .fresh_stream
        .as_mut()
        .expect("C10 fresh stream resource installed")
        .round_trip_capture(&[], C10_CANARY)
        .await
        .map_err(|error| HarnessError::Http(format!("C10 fresh CLI echo: {error}")))?;
    let mut fresh_stream = resources
        .fresh_stream
        .take()
        .expect("C10 fresh stream resource installed");
    let fresh_close = close_stream_until(
        &mut fresh_stream,
        fresh_cleanup_deadline,
        "C10 fresh consumer",
    )
    .await;
    resources.fresh_stream = Some(fresh_stream);
    fresh_close?;
    let fresh_process = resources
        .fresh_process
        .take()
        .expect("C10 fresh process resource installed");
    shutdown_process_until(fresh_process, fresh_cleanup_deadline, "C10 fresh CLI").await?;
    cluster
        .wait_for_no_owner(device.tenant_id, device.id)
        .await?;
    if !fresh_control_after_no_live_owner {
        return Err(HarnessError::Process(
            "C10 fresh CLI did not claim the exact scope at a higher epoch".into(),
        ));
    }

    Ok(C10ActualPathEvidence {
        relay_count: cluster.relays.len(),
        fresh_control_after_no_live_owner,
        fresh_epoch_advanced,
        empty_body_single_prefix,
        empty_body_owner_read,
        empty_body_dispatch_delta: empty_dispatch_delta,
        empty_unary_body_response_exact,
        empty_unary_body_owner_read,
        empty_unary_body_dispatch_delta: empty_unary_dispatch_delta,
        truncated_body_owner_read: truncated_read,
        truncated_body_not_dispatched,
        raw_bearer_owner_revalidated: race.raw_bearer_owner_revalidated,
        owner_token_changed_before_101: race.owner_token_changed_before_101,
        owner_change_pre_101_rejected: race.owner_change_pre_101_rejected,
        owner_change_pre_101_not_dispatched: race.owner_change_pre_101_not_dispatched,
        owner_change_pre_101_body_not_polled: race.owner_change_pre_101_body_not_polled,
        cleanup_joined: false,
    })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct C10OwnerRaceEvidence {
    raw_bearer_owner_revalidated: bool,
    owner_token_changed_before_101: bool,
    owner_change_pre_101_rejected: bool,
    owner_change_pre_101_not_dispatched: bool,
    owner_change_pre_101_body_not_polled: bool,
}

/// Hold the real remote consumer admission after the owner actor has accepted
/// the forwarded bearer and before the public 101 response is constructed.
/// Replacing the owner while this barrier is held makes the race causal: a
/// post-101 close or a timer coincidence cannot satisfy this check.
#[allow(clippy::too_many_arguments)] // Explicit identities for the owned race fixture.
async fn run_owner_token_race(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut C10Resources,
    upgrade_barriers: &C10UpgradeBarriers,
    initial_owner: &tunnel_catalog::OwnerClaim,
    ingress: std::net::SocketAddr,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    token: &str,
) -> Result<C10OwnerRaceEvidence> {
    let ingress_node = cluster
        .relays
        .iter()
        .find(|relay| relay.consumer_addr().ok() == Some(ingress))
        .map(|relay| relay.node_id.clone())
        .ok_or_else(|| HarnessError::Process("C10 race ingress relay was not found".into()))?;
    if ingress_node == initial_owner.token.node_id {
        return Err(HarnessError::Process(
            "C10 owner-token race requires a non-owner authenticated ingress".into(),
        ));
    }
    let barrier = upgrade_barriers.for_node(&ingress_node)?;
    if !barrier.arm() {
        return Err(HarnessError::Process(
            "C10 owner-token race barrier was already armed".into(),
        ));
    }
    let _release = ReleaseUpgradeBarrier(Arc::clone(&barrier));
    // One absolute deadline covers the held-admission race.  Individual
    // owner/catalog operations may have their own bounded waits, but they may
    // not silently restart this phase's budget.
    let race_deadline = Instant::now() + C10_RACE_TIMEOUT;

    let owner_index = relay_index(&initial_owner.token.node_id)?;
    let authorization = format!("bearer {token}");
    let service = service_id.to_string();
    let mut request = Box::pin(open_public_stream_with_authorization(
        ingress,
        &harness.pki.server_ca.certificate_der,
        &authorization,
        device_id,
        &service,
        &[],
    ));
    let barrier_wait_budget = cleanup_remaining(race_deadline, "C10 owner-token race barrier")?;
    tokio::select! {
        result = &mut request => {
            return Err(match result {
                Ok(PublicStreamProbe::Accepted(mut stream)) => {
                    close_stream_preserving_primary(
                        &mut stream,
                        Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT,
                        "unexpected pre-barrier accepted stream",
                        HarnessError::Process(
                            "C10 owner-token race upgraded before its authenticated barrier"
                                .into(),
                        ),
                    )
                    .await
                }
                Ok(PublicStreamProbe::Rejected(failure)) => HarnessError::Process(format!(
                    "C10 owner-token race rejected before its barrier: status={} code={:?} execution={:?}",
                    failure.status, failure.code, failure.execution
                )),
                Err(error) => HarnessError::Http(format!(
                    "C10 owner-token race ended before its authenticated barrier: {error}"
                )),
            });
        }
        waited = timeout(barrier_wait_budget, barrier.wait_reached()) => {
            waited.map_err(|_| {
                HarnessError::Timeout(
                    "C10 owner-token race barrier was not reached before its deadline".into(),
                )
            })?;
        }
    }
    if barrier.hit_count() != 1 {
        return Err(HarnessError::Process(
            "C10 owner-token race did not reach exactly one post-admission barrier".into(),
        ));
    }

    let selected_owner = cluster
        .catalog
        .current_owner(initial_owner.token.tenant_id, device_id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("C10 race selected-owner lookup: {error}")))?
        .ok_or_else(|| {
            HarnessError::Process("C10 race selected owner disappeared at barrier".into())
        })?;
    if selected_owner.token != initial_owner.token {
        return Err(HarnessError::Process(
            "C10 race barrier did not retain the exact selected owner token".into(),
        ));
    }

    let client = resources.client.take().ok_or_else(|| {
        HarnessError::Process("C10 race initial client was already released".into())
    })?;
    stop_client_until(&client, race_deadline, "C10 race initial connector").await?;
    cluster
        .wait_for_no_owner(initial_owner.token.tenant_id, device_id)
        .await?;
    wait_for_fanout_drained(&cluster.device_fanout, "C10 race predecessor").await?;
    cleanup_remaining(race_deadline, "C10 owner-token race predecessor")?;

    let (replacement_process, replacement_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        ingress,
        resources
            .profile
            .as_ref()
            .ok_or_else(|| HarnessError::Process("C10 race device profile was released".into()))?,
        token,
        device_id,
        service_id,
    )
    .await?;
    resources.replacement_process = Some(replacement_process);
    resources.replacement_stream = Some(replacement_stream);
    cleanup_remaining(race_deadline, "C10 owner-token race replacement startup")?;
    let replacement_owner =
        wait_for_owner(cluster, initial_owner.token.tenant_id, device_id).await?;
    let owner_token_changed_before_101 = replacement_owner.token.deployment_incarnation
        == initial_owner.token.deployment_incarnation
        && replacement_owner.token.tenant_id == initial_owner.token.tenant_id
        && replacement_owner.token.device_id == initial_owner.token.device_id
        && replacement_owner.token.epoch > initial_owner.token.epoch
        && replacement_owner.token.session_id != initial_owner.token.session_id;
    let owner_token_changed_before_101 = owner_token_changed_before_101
        && replacement_owner.token != initial_owner.token
        && !replacement_owner.token.node_id.is_empty()
        && !replacement_owner.token.boot_id.is_empty()
        && !replacement_owner.token.session_id.is_empty();
    if !owner_token_changed_before_101 {
        return Err(HarnessError::Process(
            "C10 race replacement did not publish a complete higher owner token".into(),
        ));
    }

    // The replacement CLI establishes its own authenticated stream and may
    // legitimately publish control/data observations while it starts.  Take
    // the no-body/no-dispatch baseline only after that owner token is visible,
    // immediately before releasing the raced admission, so the post-release
    // delta is attributable to this request rather than replacement startup.
    cleanup_remaining(race_deadline, "C10 owner-token race replacement owner")?;
    let before_race = counters(cluster).await?;

    // The barrier is released only after the replacement owner is committed.
    // The request must now be rejected before Axum sends 101; the raw bearer
    // was already accepted by the old owner, so this is an owner-fence result,
    // not an authentication or transport probe.
    if !barrier.is_held() {
        return Err(HarnessError::Process(
            "C10 owner-token race barrier released before replacement owner token was committed"
                .into(),
        ));
    }
    barrier.release();
    let probe = timeout(
        cleanup_remaining(race_deadline, "C10 owner-token race response")?,
        request,
    )
    .await
    .map_err(|_| HarnessError::Timeout("C10 owner-token race response timed out".into()))??;
    let (owner_change_pre_101_rejected, owner_change_pre_101_not_dispatched) = match probe {
        PublicStreamProbe::Rejected(failure) => {
            let bounded_code = failure.code == Some("PEER_UNAVAILABLE");
            let bounded_execution = matches!(failure.execution, Some("not_dispatched"));
            if failure.status != 503 || !bounded_code || !bounded_execution {
                return Err(HarnessError::Process(format!(
                    "C10 owner-token race returned an unexpected bounded rejection: status={} code={:?} execution={:?}",
                    failure.status, failure.code, failure.execution
                )));
            }
            (true, true)
        }
        PublicStreamProbe::Accepted(mut stream) => {
            return Err(close_stream_preserving_primary(
                &mut stream,
                Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT,
                "unexpected post-fence accepted stream",
                HarnessError::Process(
                    "C10 owner-token race sent 101 after the owner token changed".into(),
                ),
            )
            .await);
        }
    };

    let after_race = counters(cluster).await?;
    let read_delta = subtract(after_race.1, before_race.1);
    let dispatch_delta = subtract(after_race.0, before_race.0);
    let owner_change_pre_101_body_not_polled = read_delta == [0, 0, 0];
    if !owner_change_pre_101_body_not_polled || dispatch_delta != [0, 0, 0] {
        return Err(HarnessError::Process(format!(
            "C10 owner-token race consumed or dispatched a body: owner_index={owner_index}, reads={read_delta:?}, dispatch={dispatch_delta:?}"
        )));
    }

    let replacement_cleanup_deadline = Instant::now() + C10_RESOURCE_CLEANUP_TIMEOUT;
    if let Some(mut stream) = resources.replacement_stream.take() {
        close_stream_until(
            &mut stream,
            replacement_cleanup_deadline,
            "C10 race replacement consumer",
        )
        .await?;
    }
    if let Some(process) = resources.replacement_process.take() {
        shutdown_process_until(
            process,
            replacement_cleanup_deadline,
            "C10 race replacement CLI",
        )
        .await?;
    }
    cluster
        .wait_for_no_owner(initial_owner.token.tenant_id, device_id)
        .await?;

    Ok(C10OwnerRaceEvidence {
        // Reaching the post-admission barrier on a non-owner ingress proves
        // that the raw bearer was accepted by the remote owner before the
        // replacement fence was published.  The special lowercase scheme
        // exercises the exact bearer normalization/forwarding path.
        raw_bearer_owner_revalidated: barrier.hit_count() == 1
            && ingress_node != initial_owner.token.node_id
            && selected_owner.token == initial_owner.token,
        owner_token_changed_before_101,
        owner_change_pre_101_rejected,
        owner_change_pre_101_not_dispatched,
        owner_change_pre_101_body_not_polled,
    })
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: uuid::Uuid,
    device_id: uuid::Uuid,
) -> Result<tunnel_catalog::OwnerClaim> {
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        match cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("C10 owner lookup: {error}")))?
        {
            Some(owner) => return Ok(owner),
            None if Instant::now() >= deadline => {
                return Err(HarnessError::Timeout(
                    "C10 owner did not become visible before the bounded deadline".into(),
                ));
            }
            None => sleep(Duration::from_millis(50)).await,
        }
    }
}

async fn counters(cluster: &ProductionCluster) -> Result<([u64; 3], [u64; 3])> {
    let mut dispatch = [0_u64; 3];
    let mut reads = [0_u64; 3];
    for (index, node_id) in ["relay-a", "relay-b", "relay-c"].into_iter().enumerate() {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        dispatch[index] = snapshot.lifetime_application_dispatches;
        reads[index] = snapshot.lifetime_consumer_chunk_reads;
    }
    Ok((dispatch, reads))
}

async fn wait_for_owner_read(
    cluster: &ProductionCluster,
    owner_index: usize,
    before: u64,
    budget: Duration,
) -> Result<bool> {
    let deadline = Instant::now() + budget;
    loop {
        let current = counters(cluster).await?.1[owner_index];
        if current > before {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

fn relay_index(node_id: &str) -> Result<usize> {
    ["relay-a", "relay-b", "relay-c"]
        .into_iter()
        .position(|candidate| candidate == node_id)
        .ok_or_else(|| HarnessError::InvalidInput("C10 owner was outside the relay set".into()))
}

fn subtract(after: [u64; 3], before: [u64; 3]) -> [u64; 3] {
    [
        after[0].saturating_sub(before[0]),
        after[1].saturating_sub(before[1]),
        after[2].saturating_sub(before[2]),
    ]
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{C10ActualPathEvidence, validate_c10_actual_path_evidence};
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> C10ActualPathEvidence {
        C10ActualPathEvidence {
            relay_count: 3,
            fresh_control_after_no_live_owner: true,
            fresh_epoch_advanced: true,
            empty_body_single_prefix: true,
            empty_body_owner_read: true,
            empty_body_dispatch_delta: [0, 1, 0],
            empty_unary_body_response_exact: true,
            empty_unary_body_owner_read: true,
            empty_unary_body_dispatch_delta: [0, 0, 1],
            truncated_body_owner_read: true,
            truncated_body_not_dispatched: true,
            raw_bearer_owner_revalidated: true,
            owner_token_changed_before_101: true,
            owner_change_pre_101_rejected: true,
            owner_change_pre_101_not_dispatched: true,
            owner_change_pre_101_body_not_polled: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn c10_validator_accepts_complete_evidence() {
        assert!(validate_c10_actual_path_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn every_c10_required_flag_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut C10ActualPathEvidence));
        let flags: [Disable; 14] = [
            ("fresh_control_after_no_live_owner", |e| {
                e.fresh_control_after_no_live_owner = false
            }),
            ("fresh_epoch_advanced", |e| e.fresh_epoch_advanced = false),
            ("empty_body_single_prefix", |e| {
                e.empty_body_single_prefix = false
            }),
            ("empty_body_owner_read", |e| e.empty_body_owner_read = false),
            ("empty_unary_body_response_exact", |e| {
                e.empty_unary_body_response_exact = false
            }),
            ("empty_unary_body_owner_read", |e| {
                e.empty_unary_body_owner_read = false
            }),
            ("truncated_body_owner_read", |e| {
                e.truncated_body_owner_read = false
            }),
            ("truncated_body_not_dispatched", |e| {
                e.truncated_body_not_dispatched = false
            }),
            ("raw_bearer_owner_revalidated", |e| {
                e.raw_bearer_owner_revalidated = false
            }),
            ("owner_token_changed_before_101", |e| {
                e.owner_token_changed_before_101 = false
            }),
            ("owner_change_pre_101_rejected", |e| {
                e.owner_change_pre_101_rejected = false
            }),
            ("owner_change_pre_101_not_dispatched", |e| {
                e.owner_change_pre_101_not_dispatched = false
            }),
            ("owner_change_pre_101_body_not_polled", |e| {
                e.owner_change_pre_101_body_not_polled = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_failed(validate_c10_actual_path_evidence(&evidence));
        }
    }

    #[test]
    fn every_c10_required_count_and_dispatch_shape_reaches_the_shared_exit_path() {
        type Mutate = (&'static str, fn(&mut C10ActualPathEvidence));
        let counts: [Mutate; 7] = [
            ("relay_count", |e| e.relay_count = 2),
            ("empty_body_dispatch_delta_no_selection", |e| {
                e.empty_body_dispatch_delta = [0, 0, 0]
            }),
            ("empty_body_dispatch_delta_duplicate_selection", |e| {
                e.empty_body_dispatch_delta = [1, 1, 0]
            }),
            ("empty_body_dispatch_delta_overflow", |e| {
                e.empty_body_dispatch_delta = [0, 2, 0]
            }),
            ("empty_unary_body_dispatch_delta_no_selection", |e| {
                e.empty_unary_body_dispatch_delta = [0, 0, 0]
            }),
            ("empty_unary_body_dispatch_delta_duplicate_selection", |e| {
                e.empty_unary_body_dispatch_delta = [1, 1, 0]
            }),
            ("empty_unary_body_dispatch_delta_overflow", |e| {
                e.empty_unary_body_dispatch_delta = [0, 0, 2]
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_c10_actual_path_evidence(&evidence),
                "C10 admission/framing evidence",
            );
        }
    }
}
