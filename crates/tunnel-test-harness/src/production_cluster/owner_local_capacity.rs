//! M7-C27 owner-local public WebSocket capacity gate.
//!
//! It exercises the public TLS listener on the relay that owns the device,
//! keeping it distinct from the non-owner ingress load gate and from private
//! peer-pool capacity.  The abandoned-upgrade phase closes an authenticated
//! public handshake connection after the owner actor has registered it; the
//! listener-level test proves bounded reclamation, while the actor unit tests
//! remain the direct evidence for an unclaimed registration lease.

use super::{
    CLEANUP_TIMEOUT, ConsumerStream, ProductionCluster, ProductionRelay, RunningHarness,
    SCENARIO_TIMEOUT, STARTUP_TIMEOUT, connect_failure_to_harness, device_dispatch_counter,
    open_consumer_stream,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProcessSpec, Result,
};
use chrono::Utc;
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer, pki_types::ServerName};
use std::{sync::Arc, time::Duration};
use tempfile::tempdir;
use tokio::{
    io::AsyncWriteExt,
    net::TcpStream,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_rustls::{TlsConnector, client::TlsStream};
use tokio_tungstenite::tungstenite::handshake::client::generate_key;
use tunnel_core::RotationConfig;
use tunnel_relay::RelaySnapshot;
use uuid::Uuid;

const DEVICE_STREAM_CAP: usize = 64;
const PRE_ABANDON_ACTIVE_STREAMS: usize = DEVICE_STREAM_CAP - 1;
const OWNER_LOCAL_STREAMS_BEFORE_ABANDON: usize = PRE_ABANDON_ACTIVE_STREAMS - 1;
const OWNER_LOCAL_STREAMS_AT_CAP: usize = DEVICE_STREAM_CAP - 1;
const ABANDONED_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_COUNT_TIMEOUT: Duration = Duration::from_secs(8);
const STREAM_COUNT_POLL: Duration = Duration::from_millis(25);
const RECLAIM_BARRIER_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ERROR_BODY_BYTES: usize = 1024;
const MAX_RETRY_AFTER_MS: u64 = 60_000;
const ECHO_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const OWNER_LOCAL_CAPACITY_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 10,
    overlap_seconds: 30,
};
const DIAGNOSTIC_TIMEOUT: Duration = Duration::from_millis(750);
const DIAGNOSTIC_STREAM_LIMIT: usize = 4;
const DIAGNOSTIC_CLI_LINE_LIMIT: usize = 8;
const DIAGNOSTIC_VALUE_LIMIT: usize = 4;

/// Payload-free evidence from the owner-local public capacity gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OwnerLocalCapacityEvidence {
    pub relay_count: usize,
    pub owner_local_route: bool,
    pub cli_non_owner_ingress: bool,
    pub owner_session_epoch_stable: bool,
    pub baseline_active_streams: usize,
    pub owner_local_streams_before_abandon: usize,
    pub abandoned_connection_registration_observed: bool,
    pub abandoned_connection_reclaimed: bool,
    pub abandoned_retained_stream_bound: bool,
    pub connector_reclaim_barrier: bool,
    pub held_active_streams: usize,
    pub owner_local_streams_at_capacity: usize,
    pub capacity_status: u16,
    pub capacity_code_stream_limit: bool,
    pub capacity_execution_not_dispatched: bool,
    pub capacity_retry_after_bounded: bool,
    pub capacity_dispatch_delta: u64,
    pub held_customer_survived: bool,
    pub fresh_owner_local_canary: bool,
    pub cleanup_joined: bool,
}

/// Validate the owner-local capacity evidence contract.
pub fn validate_owner_local_capacity_evidence(evidence: &OwnerLocalCapacityEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "owner-local capacity expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.baseline_active_streams != PRE_ABANDON_ACTIVE_STREAMS {
        return Err(HarnessError::Process(format!(
            "owner-local capacity expected {} baseline active streams, observed {}",
            PRE_ABANDON_ACTIVE_STREAMS, evidence.baseline_active_streams
        )));
    }
    if evidence.owner_local_streams_before_abandon != OWNER_LOCAL_STREAMS_BEFORE_ABANDON
        || evidence.owner_local_streams_at_capacity != OWNER_LOCAL_STREAMS_AT_CAP
    {
        return Err(HarnessError::Process(format!(
            "owner-local listener occupancy was before={} at-capacity={}, expected {} and {}",
            evidence.owner_local_streams_before_abandon,
            evidence.owner_local_streams_at_capacity,
            OWNER_LOCAL_STREAMS_BEFORE_ABANDON,
            OWNER_LOCAL_STREAMS_AT_CAP
        )));
    }
    if evidence.held_active_streams != DEVICE_STREAM_CAP {
        return Err(HarnessError::Process(format!(
            "owner-local capacity expected {} held active streams, observed {}",
            DEVICE_STREAM_CAP, evidence.held_active_streams
        )));
    }
    if evidence.capacity_status != 429
        || !evidence.capacity_code_stream_limit
        || !evidence.capacity_execution_not_dispatched
        || !evidence.capacity_retry_after_bounded
    {
        return Err(HarnessError::Process(
            "owner-local capacity did not return the exact bounded pre-upgrade STREAM_LIMIT contract".into(),
        ));
    }
    if evidence.capacity_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "owner-local capacity rejection advanced dispatches by {}",
            evidence.capacity_dispatch_delta
        )));
    }
    for (name, passed) in [
        ("owner_local_route", evidence.owner_local_route),
        ("cli_non_owner_ingress", evidence.cli_non_owner_ingress),
        (
            "owner_session_epoch_stable",
            evidence.owner_session_epoch_stable,
        ),
        (
            "abandoned_connection_registration_observed",
            evidence.abandoned_connection_registration_observed,
        ),
        (
            "abandoned_connection_reclaimed",
            evidence.abandoned_connection_reclaimed,
        ),
        (
            "abandoned_retained_stream_bound",
            evidence.abandoned_retained_stream_bound,
        ),
        (
            "connector_reclaim_barrier",
            evidence.connector_reclaim_barrier,
        ),
        ("held_customer_survived", evidence.held_customer_survived),
        (
            "fresh_owner_local_canary",
            evidence.fresh_owner_local_canary,
        ),
        ("cleanup_joined", evidence.cleanup_joined),
    ] {
        if !passed {
            return Err(HarnessError::Process(format!(
                "owner-local capacity required gate {name} was false"
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        DEVICE_STREAM_CAP, OWNER_LOCAL_STREAMS_AT_CAP, OWNER_LOCAL_STREAMS_BEFORE_ABANDON,
        OwnerLocalCapacityEvidence, PRE_ABANDON_ACTIVE_STREAMS,
        validate_owner_local_capacity_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> OwnerLocalCapacityEvidence {
        OwnerLocalCapacityEvidence {
            relay_count: 3,
            owner_local_route: true,
            cli_non_owner_ingress: true,
            owner_session_epoch_stable: true,
            baseline_active_streams: PRE_ABANDON_ACTIVE_STREAMS,
            owner_local_streams_before_abandon: OWNER_LOCAL_STREAMS_BEFORE_ABANDON,
            abandoned_connection_registration_observed: true,
            abandoned_connection_reclaimed: true,
            abandoned_retained_stream_bound: true,
            connector_reclaim_barrier: true,
            held_active_streams: DEVICE_STREAM_CAP,
            owner_local_streams_at_capacity: OWNER_LOCAL_STREAMS_AT_CAP,
            capacity_status: 429,
            capacity_code_stream_limit: true,
            capacity_execution_not_dispatched: true,
            capacity_retry_after_bounded: true,
            capacity_dispatch_delta: 0,
            held_customer_survived: true,
            fresh_owner_local_canary: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn every_owner_local_flag_and_count_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut OwnerLocalCapacityEvidence));
        let flags: [Disable; 13] = [
            ("owner_local_route", |e| e.owner_local_route = false),
            ("cli_non_owner_ingress", |e| e.cli_non_owner_ingress = false),
            ("owner_session_epoch_stable", |e| {
                e.owner_session_epoch_stable = false
            }),
            ("abandoned_connection_registration_observed", |e| {
                e.abandoned_connection_registration_observed = false
            }),
            ("abandoned_connection_reclaimed", |e| {
                e.abandoned_connection_reclaimed = false
            }),
            ("abandoned_retained_stream_bound", |e| {
                e.abandoned_retained_stream_bound = false
            }),
            ("connector_reclaim_barrier", |e| {
                e.connector_reclaim_barrier = false
            }),
            ("capacity_code_stream_limit", |e| {
                e.capacity_code_stream_limit = false
            }),
            ("capacity_execution_not_dispatched", |e| {
                e.capacity_execution_not_dispatched = false
            }),
            ("capacity_retry_after_bounded", |e| {
                e.capacity_retry_after_bounded = false
            }),
            ("held_customer_survived", |e| {
                e.held_customer_survived = false
            }),
            ("fresh_owner_local_canary", |e| {
                e.fresh_owner_local_canary = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(
                validate_owner_local_capacity_evidence(&evidence),
                "owner-local",
            );
            let _ = name;
        }

        type Mutate = (&'static str, fn(&mut OwnerLocalCapacityEvidence));
        let counts: [Mutate; 7] = [
            ("relay_count", |e: &mut OwnerLocalCapacityEvidence| {
                e.relay_count = 2
            }),
            (
                "baseline_active_streams",
                |e: &mut OwnerLocalCapacityEvidence| e.baseline_active_streams = 1,
            ),
            (
                "owner_local_streams_before_abandon",
                |e: &mut OwnerLocalCapacityEvidence| e.owner_local_streams_before_abandon = 1,
            ),
            (
                "owner_local_streams_at_capacity",
                |e: &mut OwnerLocalCapacityEvidence| e.owner_local_streams_at_capacity = 1,
            ),
            (
                "held_active_streams",
                |e: &mut OwnerLocalCapacityEvidence| e.held_active_streams = 1,
            ),
            ("capacity_status", |e: &mut OwnerLocalCapacityEvidence| {
                e.capacity_status = 200
            }),
            (
                "capacity_dispatch_delta",
                |e: &mut OwnerLocalCapacityEvidence| e.capacity_dispatch_delta = 1,
            ),
        ];
        for (name, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_owner_local_capacity_evidence(&evidence),
                "owner-local",
            );
            let _ = name;
        }
    }

    #[test]
    fn owner_local_capacity_validator_accepts_complete_evidence() {
        validate_owner_local_capacity_evidence(&valid_evidence())
            .expect("complete owner-local capacity evidence is valid");
    }
}

/// Run the bounded owner-local public capacity gate.
pub async fn verify() -> Result<OwnerLocalCapacityEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(OWNER_LOCAL_CAPACITY_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("owner-local capacity harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    // Keep the resource owner outside the scenario timeout.  If the phase is
    // cancelled, the CLI and public sockets still have an explicit joined
    // cleanup opportunity before the relay and Redis fixtures are torn down.
    let mut resources = LocalCapacityResources::new();
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        run_inner(&mut cluster, &harness, &mut resources),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "owner-local capacity scenario exceeded its bounded deadline".into(),
        )),
    };
    // Keep process reaping outside cancellable outer cleanup timeouts.
    // Socket closes and process grace each use the internal absolute budget.
    let resource_cleanup = resources.shutdown().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;
    match (scenario, resource_cleanup, cluster_cleanup, harness_cleanup) {
        (Ok(mut evidence), Ok(()), Ok(()), Ok(())) => {
            evidence.cleanup_joined = true;
            validate_owner_local_capacity_evidence(&evidence)?;
            Ok(evidence)
        }
        (scenario, resource_cleanup, cluster_cleanup, harness_cleanup) => {
            let mut failure = scenario.err();
            if let Err(error) = resource_cleanup {
                append_cleanup_failure(
                    &mut failure,
                    "owner-local capacity resource cleanup",
                    error,
                );
            }
            if let Err(error) = cluster_cleanup {
                append_cleanup_failure(&mut failure, "owner-local capacity relay cleanup", error);
            }
            if let Err(error) = harness_cleanup {
                append_cleanup_failure(&mut failure, "owner-local capacity Redis cleanup", error);
            }
            Err(failure.expect("owner-local capacity cleanup failure was not recorded"))
        }
    }
}

fn append_cleanup_failure(slot: &mut Option<HarnessError>, label: &str, error: HarnessError) {
    *slot = Some(match slot.take() {
        Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
        None => HarnessError::Process(format!("{label}: {error}")),
    });
}

struct LocalCapacityResources {
    process: Option<ManagedProcess>,
    streams: Vec<ConsumerStream>,
    _profile_directory: Option<tempfile::TempDir>,
}

impl LocalCapacityResources {
    fn new() -> Self {
        Self {
            process: None,
            streams: Vec::new(),
            _profile_directory: None,
        }
    }

    async fn close_non_cli_streams(&mut self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut first_error = None;
        while self.streams.len() > 1 {
            let Some(mut stream) = self.streams.pop() else {
                break;
            };
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                first_error.get_or_insert_with(|| {
                    HarnessError::Timeout("owner-local non-CLI stream cleanup timed out".into())
                });
                continue;
            }
            match timeout_at(deadline, stream.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(_) => {
                    first_error.get_or_insert_with(|| {
                        HarnessError::Timeout("owner-local non-CLI stream cleanup timed out".into())
                    });
                }
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    async fn shutdown(mut self) -> Result<()> {
        let deadline = Instant::now() + CLEANUP_TIMEOUT;
        let mut errors = Vec::new();
        while let Some(mut stream) = self.streams.pop() {
            match timeout_at(deadline, stream.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!("consumer close: {error}")),
                Err(_) => errors.push("consumer close timed out".into()),
            }
        }
        if let Some(process) = self.process.take() {
            let remaining = deadline.saturating_duration_since(Instant::now());
            let grace = remaining.min(Duration::from_secs(5));
            match process.shutdown(grace).await {
                Ok(_) => {}
                Err(error) => errors.push(format!("CLI join: {error}")),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(format!(
                "owner-local capacity cleanup failed: {}",
                errors.join("; ")
            )))
        }
    }
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut LocalCapacityResources,
) -> Result<OwnerLocalCapacityEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "owner-local capacity started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await?;

    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("owner-local capacity device is missing".into())
    })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("owner-local capacity service is missing".into())
        })?;
    let canary = format!("m7-owner-local-capacity:{}", device.id);
    let profile_directory = tempdir().map_err(HarnessError::Io)?;
    let profile = write_device_profile(
        profile_directory.path(),
        device.id,
        service_id,
        &canary,
        cluster.device_fanout.local_addr(),
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("owner-local profile: {error}")))?;
    resources._profile_directory = Some(profile_directory);
    let consumer = harness.topology.consumers_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("owner-local capacity consumer is missing".into())
    })?;
    let token = harness.oidc.issue_with(
        &consumer.name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(120),
            ..OidcTokenOptions::default()
        },
    )?;

    // Start the real CLI first, but do not open its public consumer stream
    // through a guessed relay.  Once Redis reports the authoritative owner,
    // choose a different public listener for this baseline stream.  That
    // keeps one actor slot occupied without consuming the owner's independent
    // 64-permit public admission semaphore.
    let binary = super::client_binary_path()?;
    let process = ManagedProcess::spawn(
        "m7-owner-local-capacity-cli",
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    resources.process = Some(process);
    let owner_deadline = Instant::now() + STARTUP_TIMEOUT;
    let owner = loop {
        let process_exited = match resources.process.as_mut() {
            Some(process) => process.try_wait()?.is_some(),
            None => true,
        };
        if process_exited {
            return Err(HarnessError::Process(
                "owner-local capacity CLI exited before owner claim".into(),
            ));
        }
        if let Some(owner) = cluster
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading owner-local owner: {error}")))?
        {
            break owner;
        }
        if Instant::now() >= owner_deadline {
            return Err(HarnessError::Timeout(
                "owner-local capacity CLI did not claim an owner before its bound".into(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    };
    let owner_relay = cluster.relay(&owner.token.node_id)?;
    let owner_addr = owner_relay.consumer_addr()?;
    let owner_local_route = owner.token.node_id == owner_relay.node_id;
    if !owner_local_route {
        return Err(HarnessError::Process(
            "owner-local capacity did not select the authoritative owner listener".into(),
        ));
    }
    let non_owner_relay = cluster
        .relays
        .iter()
        .find(|relay| relay.node_id != owner.token.node_id)
        .ok_or_else(|| {
            HarnessError::Process("owner-local capacity has no non-owner ingress relay".into())
        })?;
    let non_owner_addr = non_owner_relay.consumer_addr()?;
    let cli_stream = match wait_for_consumer_stream(
        non_owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
        STARTUP_TIMEOUT,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(phase_failure(
                error,
                "cli",
                0,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    resources.streams.push(cli_stream);
    let cli_round_trip = match resources.streams.first_mut() {
        Some(stream) => {
            stream
                .round_trip(b"m7-owner-local-cli-baseline", canary.as_bytes())
                .await
        }
        None => Err(HarnessError::Process(
            "owner-local CLI stream was not retained".into(),
        )),
    };
    if let Err(error) = cli_round_trip {
        return Err(phase_failure(
            error,
            "cli",
            1,
            owner_relay,
            device.id,
            resources.process.as_mut(),
        )
        .await);
    }
    let owner_after_cli = cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading owner-local owner after CLI: {error}"))
        })?
        .ok_or_else(|| HarnessError::Process("owner-local device owner disappeared".into()))?;
    if owner_after_cli.token.node_id != owner.token.node_id
        || owner_after_cli.token.epoch != owner.token.epoch
    {
        return Err(HarnessError::Process(
            "owner-local CLI non-owner admission changed the owner token".into(),
        ));
    }
    let owner_identity = session_identity(owner_relay, device.tenant_id, device.id).await?;

    // The anchor is kept separately in the resource list at index one.  It
    // is the held customer whose canary is checked after the 65th rejection.
    let anchor = open_phase_stream(
        owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
        b"m7-owner-local-anchor",
        canary.as_bytes(),
        owner_relay,
        "anchor",
        0,
        resources.process.as_mut(),
    )
    .await?;
    resources.streams.push(anchor);
    for index in 0..(PRE_ABANDON_ACTIVE_STREAMS - 2) {
        let payload = local_payload(index);
        let stream = open_phase_stream(
            owner_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
            &payload,
            canary.as_bytes(),
            owner_relay,
            "fill",
            index,
            resources.process.as_mut(),
        )
        .await?;
        resources.streams.push(stream);
    }
    let (baseline_active, baseline_retained, baseline_identity) =
        match stream_counts(owner_relay, device.tenant_id, device.id).await {
            Ok(counts) => counts,
            Err(error) => {
                return Err(phase_failure(
                    error,
                    "fill",
                    PRE_ABANDON_ACTIVE_STREAMS,
                    owner_relay,
                    device.id,
                    resources.process.as_mut(),
                )
                .await);
            }
        };
    let owner_local_streams_before_abandon = resources.streams.len().saturating_sub(1);
    if baseline_identity != owner_identity || baseline_active != PRE_ABANDON_ACTIVE_STREAMS {
        return Err(HarnessError::Process(format!(
            "owner-local baseline was active={} retained={} with identity {:?}, expected active={} identity {:?}",
            baseline_active,
            baseline_retained,
            baseline_identity,
            PRE_ABANDON_ACTIVE_STREAMS,
            owner_identity
        )));
    }
    if owner_local_streams_before_abandon != OWNER_LOCAL_STREAMS_BEFORE_ABANDON {
        return Err(HarnessError::Process(format!(
            "owner-local listener held {} streams before abandonment, expected {}",
            owner_local_streams_before_abandon, OWNER_LOCAL_STREAMS_BEFORE_ABANDON
        )));
    }
    // This is deliberately a listener-level abandoned handshake.  The test
    // does not claim that the server had not already emitted 101 or that the
    // Axum OnUpgrade callback was unclaimed; the actor tests cover that exact
    // lease component.  It does prove that an authenticated public connection
    // abandoned after registration cannot consume the local slot forever.
    let abandoned = match open_raw_upgrade(
        owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            return Err(phase_failure(
                error,
                "abandon",
                0,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    let observed_active = match wait_for_active_count(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        PRE_ABANDON_ACTIVE_STREAMS + 1,
        baseline_retained + 1,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        Ok(active) => active,
        Err(error) => {
            return Err(phase_failure(
                error,
                "abandon",
                1,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    let abandoned_registration_observed = observed_active == PRE_ABANDON_ACTIVE_STREAMS + 1;
    // Identify the abandoned stream itself.  Stream IDs are allocated
    // monotonically and never reused, and this phase opens one stream at a
    // time, so the newest retained ID is the registration that was just
    // abandoned.  Its identity is what makes the connector-side retirement
    // barrier below observable rather than assumed.
    let abandoned_stream_id = match max_stream_id(owner_relay, device.tenant_id, device.id).await {
        Ok(Some(stream_id)) => stream_id,
        Ok(None) => {
            return Err(phase_failure(
                HarnessError::Process("owner-local abandoned stream is missing".into()),
                "abandon",
                2,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
        Err(error) => {
            return Err(phase_failure(
                error,
                "abandon",
                2,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    // Capture the owner state at the exact registration/drop boundary.  The
    // later reclaim poll preserves its last present snapshot, but this
    // before-drop sample is needed to distinguish a close caused immediately
    // by the abandoned stream from an owner that was already unhealthy.
    let pre_abandon_snapshot = bounded_owner_snapshot_diagnostic(owner_relay, device.id).await;
    // Abandon the transport immediately at the observed registration barrier;
    // intentionally do not wait for authorization or a 101 response here.
    // This preserves the original pre-auth/unclaimed-registration path.  The
    // actor tests separately cover lease expiry and a late OPENED after the
    // consumer registration has already been dropped.
    // A clean TLS shutdown exercises a different close path and can wait for
    // server progress beyond this fixture's intended abandonment point.
    drop(abandoned);
    let (reclaimed_active, reclaimed_retained, reclaimed_identity) = match wait_for_stream_counts(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        PRE_ABANDON_ACTIVE_STREAMS,
        baseline_retained + 1,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        Ok(counts) => counts,
        Err(error) => {
            let cluster_sessions = cluster_session_diagnostic(cluster, device.id).await;
            let error = HarnessError::Process(format!(
                "{error}; pre_abandon_snapshot={pre_abandon_snapshot}; cluster_sessions={cluster_sessions}"
            ));
            return Err(phase_failure(
                error,
                "reclaim",
                1,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    let abandoned_connection_reclaimed = reclaimed_active == PRE_ABANDON_ACTIVE_STREAMS;
    let abandoned_retained_stream_bound = reclaimed_retained <= baseline_retained + 1;
    let owner_session_epoch_stable = reclaimed_identity == owner_identity;

    // Relay-side active-count reclamation is not the connector-side admission
    // barrier.  The connector keeps charging the abandoned stream against its
    // own `max_streams` budget until it emits its own terminal frame for that
    // exact stream; until then a replacement OPEN the relay admits is refused
    // with a bounded RESOURCE_EXHAUSTED and the fresh public socket closes
    // without a response.
    //
    // A round trip on another stream does not prove that: the relay's FIN for
    // the abandoned stream and the anchor's record travel the same ordered
    // carrier, but the connector buffers an inbound FIN per stream while that
    // stream's authorization is unconfirmed, so the anchor's response can
    // overtake it.  Wait on the connector's own terminal frame for the
    // abandoned stream instead, which the owner snapshot reports as its
    // connector->relay receive cursor.  The anchor round trip is kept as well;
    // both must hold.
    if let Err(error) = wait_for_connector_stream_retirement(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        abandoned_stream_id,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        let cluster_sessions = cluster_session_diagnostic(cluster, device.id).await;
        let error = HarnessError::Process(format!(
            "{error}; pre_abandon_snapshot={pre_abandon_snapshot}; cluster_sessions={cluster_sessions}"
        ));
        return Err(phase_failure(
            error,
            "reclaim_barrier",
            1,
            owner_relay,
            device.id,
            resources.process.as_mut(),
        )
        .await);
    }
    let connector_reclaim_barrier = match resources.streams.get_mut(1) {
        Some(anchor) => match timeout(
            RECLAIM_BARRIER_TIMEOUT,
            anchor.round_trip(b"", canary.as_bytes()),
        )
        .await
        {
            Ok(Ok(())) => true,
            Ok(Err(error)) => {
                return Err(phase_failure(
                    error,
                    "reclaim_barrier",
                    0,
                    owner_relay,
                    device.id,
                    resources.process.as_mut(),
                )
                .await);
            }
            Err(_) => {
                return Err(phase_failure(
                    HarnessError::Timeout("owner-local connector reclaim barrier timed out".into()),
                    "reclaim_barrier",
                    0,
                    owner_relay,
                    device.id,
                    resources.process.as_mut(),
                )
                .await);
            }
        },
        None => {
            return Err(HarnessError::Process(
                "owner-local anchor stream disappeared before reclaim barrier".into(),
            ));
        }
    };

    // Reuse the reclaimed local slot, then fill the exact configured cap.
    let reclaimed_stream = match open_phase_stream(
        owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
        b"m7-owner-local-reclaimed",
        canary.as_bytes(),
        owner_relay,
        "reclaim",
        0,
        resources.process.as_mut(),
    )
    .await
    {
        Ok(stream) => stream,
        Err(error) => {
            let cluster_sessions = cluster_session_diagnostic(cluster, device.id).await;
            return Err(HarnessError::Process(format!(
                "{error}; pre_abandon_snapshot={pre_abandon_snapshot}; cluster_sessions={cluster_sessions}"
            )));
        }
    };
    resources.streams.push(reclaimed_stream);
    let (held_active_streams, held_retained, held_identity) = match wait_for_stream_counts(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        DEVICE_STREAM_CAP,
        DEVICE_STREAM_CAP * 2,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        Ok(counts) => counts,
        Err(error) => {
            return Err(phase_failure(
                error,
                "fill",
                DEVICE_STREAM_CAP,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    if held_identity != owner_identity || held_retained > DEVICE_STREAM_CAP * 2 {
        return Err(HarnessError::Process(
            "owner-local cap phase changed owner identity or exceeded retained stream bound".into(),
        ));
    }
    let owner_local_streams_at_capacity = resources.streams.len().saturating_sub(1);
    if owner_local_streams_at_capacity != OWNER_LOCAL_STREAMS_AT_CAP {
        return Err(HarnessError::Process(format!(
            "owner-local listener held {} streams at actor capacity, expected {}",
            owner_local_streams_at_capacity, OWNER_LOCAL_STREAMS_AT_CAP
        )));
    }

    let before_capacity = owner_relay.snapshot().await?;
    let before_dispatch = device_dispatch_counter(&before_capacity, device.id);
    let capacity = match open_consumer_stream(
        owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
    )
    .await
    {
        Err(super::StreamConnectFailure::Status { status, body }) => {
            parse_capacity_response(status, body.as_deref())?
        }
        Err(super::StreamConnectFailure::Harness(error)) => {
            return Err(phase_failure(
                error,
                "capacity",
                0,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
        Ok(mut stream) => {
            let _ = stream.close().await;
            return Err(HarnessError::Process(
                "owner-local 65th stream unexpectedly upgraded".into(),
            ));
        }
    };
    let after_capacity = owner_relay.snapshot().await?;
    let after_dispatch = device_dispatch_counter(&after_capacity, device.id);
    let capacity_dispatch_delta = after_dispatch.saturating_sub(before_dispatch);
    let (_, _, after_capacity_identity) =
        stream_counts(owner_relay, device.tenant_id, device.id).await?;
    if after_capacity_identity != owner_identity {
        return Err(HarnessError::Process(
            "owner-local capacity rejection changed the owner session identity".into(),
        ));
    }

    let held_customer_result = match resources.streams.get_mut(1) {
        Some(stream) => {
            stream
                .round_trip(b"m7-owner-local-survives-capacity", canary.as_bytes())
                .await
        }
        None => Err(HarnessError::Process(
            "owner-local held customer stream disappeared".into(),
        )),
    };
    let held_customer_survived = held_customer_result.is_ok();
    if !held_customer_survived {
        let error = held_customer_result.err().unwrap_or_else(|| {
            HarnessError::Http(
                "owner-local held customer stream failed after capacity rejection".into(),
            )
        });
        return Err(phase_failure(
            error,
            "held",
            0,
            owner_relay,
            device.id,
            resources.process.as_mut(),
        )
        .await);
    }

    // The streams the release phase is about to close: every live stream
    // except the CLI's own, which stays live.  Read before closing, so the
    // wait below names them exactly instead of inferring them from counts.
    let releasing = live_stream_ids(owner_relay, device.tenant_id, device.id).await?;
    resources.close_non_cli_streams().await?;
    let (released_active, _, released_identity) = match wait_for_stream_counts(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        1,
        DEVICE_STREAM_CAP * 2,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        Ok(counts) => counts,
        Err(error) => {
            return Err(phase_failure(
                error,
                "release",
                0,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    if released_active != 1 || released_identity != owner_identity {
        return Err(HarnessError::Process(
            "owner-local capacity release did not preserve the live CLI owner session".into(),
        ));
    }
    // The owner counts a released stream as free once it is terminal on its
    // side, but the connector charges it against its own `max_streams` until
    // it has processed the owner's terminal frame for it (the same ledger
    // `wait_for_connector_stream_retirement` documents for one stream).  All
    // 63 released streams free their slots in one burst, so a fresh OPEN can
    // reach the connector while it still counts some of them, and it refuses
    // that OPEN; the owner then closes the already upgraded canary and the
    // consumer reads a Close before its echo (task row M7-C106).  A released
    // stream leaves the owner's table only through STREAM_FORGET, which
    // follows the connector's own terminal frame, so waiting for that
    // removal waits for the connector's ledger.  It is a precondition on the
    // fresh canary, not a retry: the canary still has to succeed first time.
    if let Err(error) = wait_for_streams_forgotten(
        owner_relay,
        device.tenant_id,
        device.id,
        &owner_identity,
        &releasing,
        STREAM_COUNT_TIMEOUT,
    )
    .await
    {
        return Err(phase_failure(
            error,
            "releaseforget",
            0,
            owner_relay,
            device.id,
            resources.process.as_mut(),
        )
        .await);
    }
    let fresh = open_phase_stream(
        owner_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        device.id,
        service_id,
        b"m7-owner-local-fresh",
        canary.as_bytes(),
        owner_relay,
        "freshcanary",
        0,
        resources.process.as_mut(),
    )
    .await?;
    resources.streams.push(fresh);
    let (_, _, fresh_identity) = match stream_counts(owner_relay, device.tenant_id, device.id).await
    {
        Ok(counts) => counts,
        Err(error) => {
            return Err(phase_failure(
                error,
                "freshcanary",
                1,
                owner_relay,
                device.id,
                resources.process.as_mut(),
            )
            .await);
        }
    };
    let fresh_owner_local_canary = fresh_identity == owner_identity;

    Ok(OwnerLocalCapacityEvidence {
        relay_count: cluster.relays.len(),
        owner_local_route,
        cli_non_owner_ingress: non_owner_relay.node_id != owner.token.node_id,
        owner_session_epoch_stable,
        baseline_active_streams: baseline_active,
        owner_local_streams_before_abandon,
        abandoned_connection_registration_observed: abandoned_registration_observed,
        abandoned_connection_reclaimed,
        abandoned_retained_stream_bound,
        connector_reclaim_barrier,
        held_active_streams,
        owner_local_streams_at_capacity,
        capacity_status: capacity.status,
        capacity_code_stream_limit: capacity.code_stream_limit,
        capacity_execution_not_dispatched: capacity.execution_not_dispatched,
        capacity_retry_after_bounded: capacity.retry_after_bounded,
        capacity_dispatch_delta,
        held_customer_survived,
        fresh_owner_local_canary,
        cleanup_joined: false,
    })
}

struct CapacityResponse {
    status: u16,
    code_stream_limit: bool,
    execution_not_dispatched: bool,
    retry_after_bounded: bool,
}

fn parse_capacity_response(status: u16, body: Option<&[u8]>) -> Result<CapacityResponse> {
    let Some(body) = body else {
        return Err(HarnessError::Http(
            "owner-local capacity response omitted its bounded body".into(),
        ));
    };
    if body.len() > MAX_ERROR_BODY_BYTES {
        return Err(HarnessError::Http(
            "owner-local capacity response exceeded its body bound".into(),
        ));
    }
    let value = serde_json::from_slice::<serde_json::Value>(body)
        .map_err(|_| HarnessError::Http("owner-local capacity response was not JSON".into()))?;
    let code_stream_limit =
        value.get("code").and_then(|value| value.as_str()) == Some("STREAM_LIMIT");
    let execution_not_dispatched =
        value.get("execution").and_then(|value| value.as_str()) == Some("not_dispatched");
    let retry_after_bounded = value
        .get("retry_after_ms")
        .and_then(|value| value.as_u64())
        .is_some_and(|value| (1..=MAX_RETRY_AFTER_MS).contains(&value));
    if status != 429 || !code_stream_limit || !execution_not_dispatched || !retry_after_bounded {
        return Err(HarnessError::Http(format!(
            "owner-local capacity response was not exact: status={status}, code_stream_limit={code_stream_limit}, execution_not_dispatched={execution_not_dispatched}, retry_after_bounded={retry_after_bounded}"
        )));
    }
    Ok(CapacityResponse {
        status,
        code_stream_limit,
        execution_not_dispatched,
        retry_after_bounded,
    })
}

async fn wait_for_consumer_stream(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    budget: Duration,
) -> Result<ConsumerStream> {
    let deadline = Instant::now() + budget;
    let mut last_error = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(last_error
                .map(connect_failure_to_harness)
                .unwrap_or_else(|| {
                    HarnessError::Timeout("owner-local consumer admission timed out".into())
                }));
        }
        match timeout(
            remaining,
            open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                last_error = Some(error);
                let pause = Duration::from_millis(100).min(remaining);
                sleep(pause).await;
            }
            Err(_) => {
                return Err(last_error
                    .map(connect_failure_to_harness)
                    .unwrap_or_else(|| {
                        HarnessError::Timeout("owner-local consumer admission timed out".into())
                    }));
            }
        }
    }
}

async fn open_checked_local_stream(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    payload: &[u8],
    canary: &[u8],
) -> Result<ConsumerStream> {
    let mut stream =
        open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id)
            .await
            .map_err(connect_failure_to_harness)?;
    if let Err(error) = stream.round_trip(payload, canary).await {
        let _ = stream.close().await;
        return Err(error);
    }
    Ok(stream)
}

#[allow(clippy::too_many_arguments)]
async fn open_phase_stream(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    payload: &[u8],
    canary: &[u8],
    relay: &ProductionRelay,
    phase: &'static str,
    index: usize,
    process: Option<&mut ManagedProcess>,
) -> Result<ConsumerStream> {
    match open_checked_local_stream(
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service_id,
        payload,
        canary,
    )
    .await
    {
        Ok(stream) => Ok(stream),
        Err(error) => Err(phase_failure(error, phase, index, relay, device_id, process).await),
    }
}

/// Add bounded, payload-free phase context to a failed real stream operation.
///
/// The production harness has equivalent allowlisted diagnostics in its
/// lifecycle/readiness helpers.  This staged module keeps the same fields
/// local until the parent integrates the fixture, so a failing phase identifies
/// the exact fill/anchor/reclaim/fresh index without dumping request data.
async fn phase_failure(
    primary: HarnessError,
    phase: &'static str,
    index: usize,
    relay: &ProductionRelay,
    device_id: Uuid,
    process: Option<&mut ManagedProcess>,
) -> HarnessError {
    let final_snapshot = match timeout(DIAGNOSTIC_TIMEOUT, relay.snapshot()).await {
        Ok(Ok(snapshot)) => owner_snapshot_diagnostic(&snapshot, device_id),
        Ok(Err(_)) => "unavailable=relay_snapshot_error".to_owned(),
        Err(_) => "unavailable=relay_snapshot_timeout".to_owned(),
    };
    let cli_terminal = match process {
        Some(process) => cli_terminal_diagnostic(process).await,
        None => "state=absent".to_owned(),
    };
    HarnessError::Process(format!(
        "{primary}; owner_local_phase={phase}; owner_local_index={index}; final_snapshot={final_snapshot}; {cli_terminal}"
    ))
}

fn owner_snapshot_diagnostic(snapshot: &RelaySnapshot, device_id: Uuid) -> String {
    let peer = &snapshot.peer_transport_diagnostics;
    let last_owner_send = peer_transport_event_diagnostic(peer.last_owner_send.as_ref());
    let last_ingress_receive = peer_transport_event_diagnostic(peer.last_ingress_receive.as_ref());
    let Some(session) = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
    else {
        return format!(
            "session=missing,dispatches={},retained=0,active=0,consumer_write_timeouts={},peer_owner_send_count={},peer_ingress_receive_count={},peer_last_owner_send={},peer_last_ingress_receive={}",
            snapshot.lifetime_application_dispatches,
            snapshot.consumer_write_diagnostics.timeout_count,
            peer.owner_send_count,
            peer.ingress_receive_count,
            last_owner_send,
            last_ingress_receive,
        );
    };
    let streams = session
        .streams
        // Snapshot order is ascending by stream ID.  The abandoned and
        // reclaim streams are the newest entries, so retain the bounded tail
        // rather than spending the diagnostic budget on the oldest anchor.
        .iter()
        .rev()
        .take(DIAGNOSTIC_STREAM_LIMIT)
        .map(|stream| {
            format!(
                "{{id={},terminal={},emitted={},acked={},recv={},delivered={},queue_bytes={},auth_deadline={:?},auth_failure={:?}}}",
                stream.stream_id,
                stream.terminal,
                stream.last_emitted_relay_to_connector,
                stream.peer_acked_relay_to_connector,
                stream.recv_contiguous_connector_to_relay,
                stream.delivered_contiguous_connector_to_relay,
                stream.queue_bytes,
                stream.authorization_admission_deadline_ms,
                stream.authorization_failure_code,
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    // The newest task closures and stream terminal latches for this device
    // (EC-061): which exit each stream adapter took and why the actor closed
    // each stream, so a failed phase names its cause (task row M7-C106).
    let closures = snapshot
        .peer_fault_diagnostics
        .closures
        .iter()
        .rev()
        .filter(|closure| closure.device_id == device_id)
        .take(DIAGNOSTIC_STREAM_LIMIT * 2)
        .map(|closure| {
            format!(
                "{{stream={:?},stage={:?},cause={:?},at_ms={}}}",
                closure.stream_id, closure.stage, closure.cause, closure.observed_at_ms
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let device = device_id.to_string();
    let terminals = snapshot
        .stream_terminal_events
        .iter()
        .rev()
        .filter(|event| event.device_id == device)
        .take(DIAGNOSTIC_STREAM_LIMIT)
        .map(|event| {
            format!(
                "{{stream={},reason={},cause={:?},emitted={},recv={},delivered={},at_ms={}}}",
                event.stream_id,
                event.reason,
                event.cause,
                event.last_emitted_relay_to_connector,
                event.recv_contiguous_connector_to_relay,
                event.delivered_contiguous_connector_to_relay,
                event.closed_at_ms
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "session=present,session_id={:?},epoch={},phase={},active_generation={},candidate_generation={:?},rotation_recovery_reason={:?},rotation_deadline_forced_retirement={},sockets={},active={},retained={},queue_bytes={},queue_messages={},stream_sample=tail,streams=[{}],omitted_streams={},task_closures=[{closures}],stream_terminals=[{terminals}],dispatches={},consumer_write_timeouts={},peer_owner_send_count={},peer_ingress_receive_count={},peer_last_owner_send={},peer_last_ingress_receive={}",
        session.session_id,
        session.epoch,
        session.phase,
        session.active_generation,
        session.candidate_generation,
        session.rotation_recovery_reason,
        session.rotation_deadline_forced_retirement,
        session.sockets,
        session
            .streams
            .iter()
            .filter(|stream| !stream.terminal)
            .count(),
        session.streams.len(),
        session.queue_bytes,
        session.queue_messages,
        streams,
        session
            .streams
            .len()
            .saturating_sub(DIAGNOSTIC_STREAM_LIMIT),
        snapshot.lifetime_application_dispatches,
        snapshot.consumer_write_diagnostics.timeout_count,
        peer.owner_send_count,
        peer.ingress_receive_count,
        last_owner_send,
        last_ingress_receive,
    )
}

async fn bounded_owner_snapshot_diagnostic(relay: &ProductionRelay, device_id: Uuid) -> String {
    match timeout(DIAGNOSTIC_TIMEOUT, relay.snapshot()).await {
        Ok(Ok(snapshot)) => owner_snapshot_diagnostic(&snapshot, device_id),
        Ok(Err(_)) => "unavailable=relay_snapshot_error".to_owned(),
        Err(_) => "unavailable=relay_snapshot_timeout".to_owned(),
    }
}

/// Snapshot every still-running relay once when the owner session disappears.
///
/// The owner-local phase normally watches the authoritative relay only.  A
/// connector may, however, reconnect to a different relay after a session is
/// closed; reporting only `session=missing` would then hide the first visible
/// replacement session.  Keep this diagnostic bounded by one shared deadline
/// and include only relay labels plus the existing payload-free snapshot.
async fn cluster_session_diagnostic(cluster: &ProductionCluster, device_id: Uuid) -> String {
    let deadline = Instant::now() + DIAGNOSTIC_TIMEOUT;
    let mut diagnostics = Vec::with_capacity(cluster.relays.len());
    for relay in &cluster.relays {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            diagnostics.push(format!("node={},unavailable=deadline", relay.node_id));
            continue;
        }
        let diagnostic = match timeout(remaining, relay.snapshot()).await {
            Ok(Ok(snapshot)) => owner_snapshot_diagnostic(&snapshot, device_id),
            Ok(Err(_)) => "unavailable=relay_snapshot_error".to_owned(),
            Err(_) => "unavailable=relay_snapshot_timeout".to_owned(),
        };
        diagnostics.push(format!("node={},{}", relay.node_id, diagnostic));
    }
    diagnostics.join("|")
}

fn peer_transport_event_diagnostic(
    event: Option<&tunnel_relay::PeerTransportDiagnosticEventSnapshot>,
) -> String {
    event.map_or_else(
        || "none".to_owned(),
        |event| {
            format!(
                "sequence={},device_id={},session_id={},epoch={},generation={},connection_id={},role={},outcome={}",
                event.sequence,
                event.device_id,
                event.session_id,
                event.epoch,
                event.generation,
                event.connection_id,
                event.role.as_str(),
                event.outcome.as_str(),
            )
        },
    )
}

async fn cli_terminal_diagnostic(process: &mut ManagedProcess) -> String {
    let state = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={},signal={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            process_signal(status).map_or_else(|| "none".to_owned(), |signal| signal.to_string())
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };
    tokio::task::yield_now().await;
    let mut fields = CliDiagnosticFields::default();
    collect_cli_diagnostics(&process.stdout(), &mut fields);
    collect_cli_diagnostics(&process.stderr(), &mut fields);
    format!(
        "cli_terminal={state},cli_ready_records={},cli_stopped_records={},cli_last_state={:?},cli_epoch={:?},cli_generation={:?},cli_error_records={},cli_error_codes={:?},cli_error_phases={:?},cli_error_retryable={:?}",
        fields.ready_records,
        fields.stopped_records,
        fields.last_state,
        fields.epoch,
        fields.generation,
        fields.records,
        fields.codes,
        fields.phases,
        fields.retryable
    )
}

#[cfg(unix)]
fn process_signal(status: std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(&status)
}

#[cfg(not(unix))]
fn process_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

#[derive(Default)]
struct CliDiagnosticFields {
    records: usize,
    ready_records: usize,
    stopped_records: usize,
    last_state: Option<&'static str>,
    epoch: Option<u64>,
    generation: Option<u64>,
    codes: Vec<&'static str>,
    phases: Vec<&'static str>,
    retryable: Vec<bool>,
}

fn collect_cli_diagnostics(bytes: &[u8], fields: &mut CliDiagnosticFields) {
    for line in String::from_utf8_lossy(bytes)
        .lines()
        .take(DIAGNOSTIC_CLI_LINE_LIMIT)
    {
        if line.len() > 8 * 1024 {
            continue;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        if let Some(result) = value.get("result") {
            match result.get("state").and_then(serde_json::Value::as_str) {
                Some("ready") => {
                    fields.ready_records = fields.ready_records.saturating_add(1);
                    fields.last_state = Some("ready");
                }
                Some("stopped") => {
                    fields.stopped_records = fields.stopped_records.saturating_add(1);
                    fields.last_state = Some("stopped");
                }
                _ => {}
            }
            if let Some(epoch) = result.get("epoch").and_then(serde_json::Value::as_u64) {
                fields.epoch = Some(epoch);
            }
            if let Some(generation) = result.get("generation").and_then(serde_json::Value::as_u64) {
                fields.generation = Some(generation);
            }
        }
        let error = value.get("error").unwrap_or(&value);
        if error.get("code").is_none()
            && error.get("phase").is_none()
            && error.get("retryable").is_none()
        {
            continue;
        }
        fields.records = fields.records.saturating_add(1);
        if fields.codes.len() < DIAGNOSTIC_VALUE_LIMIT
            && let Some(code) = error.get("code").and_then(serde_json::Value::as_str)
        {
            fields.codes.push(safe_cli_code(code));
        }
        if fields.phases.len() < DIAGNOSTIC_VALUE_LIMIT
            && let Some(phase) = error.get("phase").and_then(serde_json::Value::as_str)
        {
            fields.phases.push(safe_cli_phase(phase));
        }
        if fields.retryable.len() < DIAGNOSTIC_VALUE_LIMIT
            && let Some(retryable) = error.get("retryable").and_then(serde_json::Value::as_bool)
        {
            fields.retryable.push(retryable);
        }
    }
}

fn safe_cli_code(code: &str) -> &'static str {
    match code {
        "INVALID_CONFIG" => "INVALID_CONFIG",
        "CREDENTIAL_ERROR" => "CREDENTIAL_ERROR",
        "INVALID_INVOCATION" => "INVALID_INVOCATION",
        "PROTOCOL_ERROR" => "PROTOCOL_ERROR",
        "TRANSPORT_ERROR" => "TRANSPORT_ERROR",
        "OWNER_BUSY" => "OWNER_BUSY",
        "DEADLINE_EXCEEDED" => "DEADLINE_EXCEEDED",
        "AUTHORIZATION_STALE" => "AUTHORIZATION_STALE",
        "RESOURCE_EXHAUSTED" => "RESOURCE_EXHAUSTED",
        "CANCELLED" => "CANCELLED",
        "SUPERVISOR_FAILED" => "SUPERVISOR_FAILED",
        "SESSION_CLOSED" => "SESSION_CLOSED",
        _ => "other",
    }
}

fn safe_cli_phase(phase: &str) -> &'static str {
    match phase {
        "connecting" => "connecting",
        "control_open" => "control_open",
        "data_opening" => "data_opening",
        "active" => "active",
        "preparing" => "preparing",
        "quiescing" => "quiescing",
        "draining" => "draining",
        "committing" => "committing",
        "retiring" => "retiring",
        "recovering" => "recovering",
        "stopping" => "stopping",
        "closed" => "closed",
        _ => "other",
    }
}

fn local_payload(index: usize) -> Vec<u8> {
    format!("m7-owner-local-fill-{index}").into_bytes()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct SessionIdentity {
    session_id: String,
    epoch: u64,
}

async fn session_identity(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<SessionIdentity> {
    let snapshot = relay.snapshot().await?;
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant_id.to_string() && session.device_id == device_id.to_string()
        })
        .map(|session| SessionIdentity {
            session_id: session.session_id.clone(),
            epoch: session.epoch,
        })
        .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))
}

async fn stream_counts(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<(usize, usize, SessionIdentity)> {
    let snapshot = relay.snapshot().await?;
    stream_counts_from_snapshot(&snapshot, tenant_id, device_id)
}

fn stream_counts_from_snapshot(
    snapshot: &RelaySnapshot,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<(usize, usize, SessionIdentity)> {
    let session = snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant_id.to_string() && session.device_id == device_id.to_string()
        })
        .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))?;
    Ok((
        session
            .streams
            .iter()
            .filter(|stream| !stream.terminal)
            .count(),
        session.streams.len(),
        SessionIdentity {
            session_id: session.session_id.clone(),
            epoch: session.epoch,
        },
    ))
}

async fn wait_for_stream_counts(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_identity: &SessionIdentity,
    expected_active: usize,
    max_retained: usize,
    budget: Duration,
) -> Result<(usize, usize, SessionIdentity)> {
    let deadline = Instant::now() + budget;
    let mut last_present_snapshot = None;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "owner-local stream count did not reach active={expected_active} within bound; last_present_snapshot={}",
                last_present_snapshot
                    .as_deref()
                    .unwrap_or("unavailable=none")
            )));
        }
        let snapshot = match timeout(remaining, relay.snapshot()).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(HarnessError::Timeout(format!(
                    "owner-local stream snapshot timed out before active={expected_active}; last_present_snapshot={}",
                    last_present_snapshot
                        .as_deref()
                        .unwrap_or("unavailable=none")
                )));
            }
        };
        if snapshot
            .sessions
            .iter()
            .any(|session| session.device_id == device_id.to_string())
        {
            last_present_snapshot = Some(owner_snapshot_diagnostic(&snapshot, device_id));
        }
        let current = match stream_counts_from_snapshot(&snapshot, tenant_id, device_id) {
            Ok(current) => current,
            Err(error) => {
                return Err(HarnessError::Process(format!(
                    "{error}; last_present_snapshot={}",
                    last_present_snapshot
                        .as_deref()
                        .unwrap_or("unavailable=none")
                )));
            }
        };
        if &current.2 != expected_identity {
            return Err(HarnessError::Process(format!(
                "owner-local stream-count phase changed session identity; last_present_snapshot={}",
                last_present_snapshot
                    .as_deref()
                    .unwrap_or("unavailable=none")
            )));
        }
        if current.0 == expected_active && current.1 <= max_retained {
            return Ok(current);
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "owner-local stream count did not reach active={expected_active} within bound (active={}, retained={}); last_present_snapshot={}",
                current.0,
                current.1,
                last_present_snapshot
                    .as_deref()
                    .unwrap_or("unavailable=none")
            )));
        }
        sleep(STREAM_COUNT_POLL.min(remaining)).await;
    }
}

/// Highest stream ID the owner relay currently retains for the device.
///
/// Relay stream IDs are allocated monotonically per session and are never
/// reused, so the newest admitted stream is the maximum retained ID.  The
/// phase opens streams one at a time, so this identifies the stream the
/// caller just opened without reaching into relay internals.
async fn max_stream_id(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<Option<u64>> {
    let snapshot = relay.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant_id.to_string() && session.device_id == device_id.to_string()
        })
        .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))?;
    Ok(session.streams.iter().map(|stream| stream.stream_id).max())
}

/// Wait for the connector to retire the abandoned stream's admission slot.
///
/// Relay-side reclamation is only one side of the admission ledger.  The
/// connector charges the stream against its own `max_streams` budget until it
/// emits its own terminal frame for that stream, and that frame is an
/// observable protocol event, not an elapsed interval: the owner relay's
/// snapshot exposes the connector->relay receive cursor per stream, and for a
/// stream that carried no application data the only frame that can advance it
/// is the connector's FIN or RESET.  A stream that has already left the
/// retained table has additionally completed its STREAM_FORGET, which happens
/// strictly after that terminal frame.
///
/// This waits on that event and fails the phase when it does not arrive
/// inside the existing bound.  It is a precondition on the reclaim probe, not
/// a retry of it and not a relaxation of anything the phase asserts: the
/// reclaim probe itself still has to succeed on its first attempt.
async fn wait_for_connector_stream_retirement(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_identity: &SessionIdentity,
    stream_id: u64,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "owner-local connector did not retire abandoned stream {stream_id} within bound"
            )));
        }
        let snapshot = match timeout(remaining, relay.snapshot()).await {
            Ok(result) => result?,
            Err(_) => {
                return Err(HarnessError::Timeout(format!(
                    "owner-local snapshot timed out before abandoned stream {stream_id} retired"
                )));
            }
        };
        let session = snapshot
            .sessions
            .iter()
            .find(|session| {
                session.tenant_id == tenant_id.to_string()
                    && session.device_id == device_id.to_string()
            })
            .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))?;
        if session.session_id != expected_identity.session_id
            || session.epoch != expected_identity.epoch
        {
            return Err(HarnessError::Process(
                "owner-local connector retirement phase changed session identity".into(),
            ));
        }
        let retired = session
            .streams
            .iter()
            .find(|stream| stream.stream_id == stream_id)
            .is_none_or(|stream| stream.recv_contiguous_connector_to_relay > 0);
        if retired {
            return Ok(());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "owner-local connector did not retire abandoned stream {stream_id} within bound"
            )));
        }
        sleep(STREAM_COUNT_POLL.min(remaining)).await;
    }
}

/// The IDs of the device session's live (non-terminal) streams.
async fn live_stream_ids(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<Vec<u64>> {
    let snapshot = relay.snapshot().await?;
    let session = snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == tenant_id.to_string() && session.device_id == device_id.to_string()
        })
        .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))?;
    Ok(session
        .streams
        .iter()
        .filter(|stream| !stream.terminal)
        .map(|stream| stream.stream_id)
        .collect())
}

/// Wait until every stream in `released` that is terminal has left the
/// owner's table, which it does only through STREAM_FORGET after the
/// connector's own terminal frame.  A stream in `released` that is still live
/// (the CLI's own) is not waited on.
async fn wait_for_streams_forgotten(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_identity: &SessionIdentity,
    released: &[u64],
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        let snapshot = match timeout(
            deadline.saturating_duration_since(Instant::now()),
            relay.snapshot(),
        )
        .await
        {
            Ok(result) => result?,
            Err(_) => {
                return Err(HarnessError::Timeout(
                    "owner-local snapshot timed out before the released streams were forgotten"
                        .into(),
                ));
            }
        };
        let session = snapshot
            .sessions
            .iter()
            .find(|session| {
                session.tenant_id == tenant_id.to_string()
                    && session.device_id == device_id.to_string()
            })
            .ok_or_else(|| HarnessError::Process("owner-local device session is missing".into()))?;
        if session.session_id != expected_identity.session_id
            || session.epoch != expected_identity.epoch
        {
            return Err(HarnessError::Process(
                "owner-local release phase changed session identity".into(),
            ));
        }
        let outstanding = session
            .streams
            .iter()
            .filter(|stream| stream.terminal && released.contains(&stream.stream_id))
            .count();
        if outstanding == 0 {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "owner-local connector did not retire {outstanding} released streams within bound"
            )));
        }
        sleep(STREAM_COUNT_POLL).await;
    }
}

async fn wait_for_active_count(
    relay: &ProductionRelay,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_identity: &SessionIdentity,
    expected_active: usize,
    max_retained: usize,
    budget: Duration,
) -> Result<usize> {
    Ok(wait_for_stream_counts(
        relay,
        tenant_id,
        device_id,
        expected_identity,
        expected_active,
        max_retained,
        budget,
    )
    .await?
    .0)
}

async fn open_raw_upgrade(
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> Result<TlsStream<TcpStream>> {
    if token.contains('\r') || token.contains('\n') || token.len() > 4096 {
        return Err(HarnessError::InvalidInput(
            "owner-local upgrade token is outside its header bound".into(),
        ));
    }
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("owner-local relay CA: {error}")))?;
    let config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| HarnessError::Http(format!("owner-local TLS config: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(config));
    let stream = timeout(
        ABANDONED_HANDSHAKE_TIMEOUT,
        TcpStream::connect(consumer_addr),
    )
    .await
    .map_err(|_| HarnessError::Timeout("owner-local upgrade TCP connect timed out".into()))?
    .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("owner-local server name: {error}")))?;
    let mut tls = timeout(
        ABANDONED_HANDSHAKE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| HarnessError::Timeout("owner-local upgrade TLS timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("owner-local upgrade TLS: {error}")))?;
    let key = generate_key();
    let request = format!(
        "GET /v1/devices/{device_id}/services/{service_id}/stream HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: {key}\r\nSec-WebSocket-Protocol: {ECHO_SUBPROTOCOL}\r\n\r\n"
    );
    timeout(
        ABANDONED_HANDSHAKE_TIMEOUT,
        tls.write_all(request.as_bytes()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("owner-local upgrade request write timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("owner-local upgrade request write: {error}")))?;
    Ok(tls)
}
