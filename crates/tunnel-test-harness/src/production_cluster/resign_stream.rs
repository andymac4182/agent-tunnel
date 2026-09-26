//! A long-lived peer stream across same-key membership re-signs, including a
//! back-to-back burst (M7-C80, M7-C81, M7-C83, M7-C86, M7-C90).
//!
//! One device is owned by relay-a and one public consumer stream enters at
//! relay-c, so every exchange rides the relay-c -> relay-a peer hop on one
//! pooled admission. The gate then re-signs every node's record at a higher
//! version for the same node and key -- first singly, then as a burst of
//! versions published with no gap between them -- and requires, on that same
//! consumer stream and without reopening it:
//!
//! * every exchange after every re-sign answers with the device's canary
//!   (the in-flight admission was re-bound, not invalidated -- M7-C80);
//! * no relay's membership invalidated any admission as `MembershipChanged`
//!   during the re-sign window (the direct witness, read from the runtime's
//!   own invalidation dispatcher rather than inferred from the stream);
//! * no relay's transport pin set was ever observed empty during the window
//!   (a same-key re-sign is never rejected trust evidence -- M7-C86/C90);
//! * every relay's peer readiness is back after the burst within the
//!   recovery bound (M7-C81/C83).
//!
//! Every field of the evidence is an identifier, a counter or a boolean.

use super::{
    ConsumerStream, ProductionCluster, connect_failure_to_harness, finish_scenario_with_cleanup,
    open_consumer_stream,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result, RunningHarness};
use chrono::Utc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tempfile::tempdir;
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use tunnel_client::{ConnectOptions, ConnectionHandle, TransportProfile};
use tunnel_relay::PeerInvalidationReason;

const OWNER_NODE: &str = "relay-a";
const INGRESS_NODE: &str = "relay-c";
const CANARY: &str = "m7-resign-stream";
/// Single re-signs before the burst.
const SINGLE_RESIGNS: usize = 2;
/// Versions published back to back with no wait between them.
const BURST_VERSIONS: u64 = 3;
/// Peer readiness must be back on every relay within this bound after the
/// burst settles: one fixture refresh tick is one second.
const READINESS_RECOVERY_BOUND: Duration = Duration::from_secs(5);
const OWNER_FENCE_READY_BOUND: Duration = Duration::from_secs(10);
const PIN_SAMPLE_INTERVAL: Duration = Duration::from_millis(5);

/// Payload-free evidence from the re-sign stream-survival gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ResignStreamEvidence {
    pub relay_count: usize,
    pub resigns: usize,
    pub burst_versions: u64,
    pub last_record_version: u64,
    pub exchanges_after_resign: usize,
    pub same_stream_survived: bool,
    pub membership_changed_invalidations: u64,
    pub other_invalidations: u64,
    pub pin_samples: u64,
    pub pins_ever_empty: bool,
    pub readiness_recovered_ms: u128,
    pub elapsed_ms: u128,
}

/// Validate every required observation.
pub fn validate_resign_stream_evidence(evidence: &ResignStreamEvidence) -> Result<()> {
    let failures = [
        (evidence.relay_count != 3, "relay_count"),
        (
            evidence.resigns != SINGLE_RESIGNS + 1 || evidence.burst_versions != BURST_VERSIONS,
            "resign schedule",
        ),
        (
            evidence.exchanges_after_resign != evidence.resigns,
            "exchanges_after_resign",
        ),
        (!evidence.same_stream_survived, "same_stream_survived"),
        (
            evidence.membership_changed_invalidations != 0,
            "membership_changed_invalidations",
        ),
        (evidence.pin_samples == 0, "pin_samples"),
        (evidence.pins_ever_empty, "pins_ever_empty"),
    ];
    let failed = failures
        .iter()
        .filter(|(failed, _)| *failed)
        .map(|(_, name)| *name)
        .collect::<Vec<_>>();
    if failed.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(format!(
            "M7 re-sign stream survival failed: {} ({evidence:?})",
            failed.join(", ")
        )))
    }
}

/// Run the gate against a fresh three-relay production cluster.
pub async fn verify() -> Result<ResignStreamEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("re-sign stream harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(super::SCENARIO_TIMEOUT, run(&mut cluster, &harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "re-sign stream scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster.shutdown().await {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness.shutdown().await {
        cleanup_errors.push(format!("catalog cleanup: {error}"));
    }
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// Counts every admission invalidation the relays' dispatchers deliver while
/// armed, chaining the fixture's own pin publication so recording changes
/// nothing about what the fixture does.
#[derive(Default)]
struct InvalidationCounter {
    armed: AtomicBool,
    membership_changed: AtomicU64,
    other: AtomicU64,
}

fn install_counter(cluster: &ProductionCluster, counter: &Arc<InvalidationCounter>) {
    for relay in &cluster.relays {
        let publish = super::fixture_pin_callback(
            &relay.membership,
            &relay.pins,
            &relay.pin_publication_pending,
        );
        let counter = Arc::clone(counter);
        relay
            .membership
            .set_invalidation_callback(Some(Arc::new(move |_identity, reason| {
                if counter.armed.load(Ordering::SeqCst) {
                    if reason == PeerInvalidationReason::MembershipChanged {
                        counter.membership_changed.fetch_add(1, Ordering::SeqCst);
                    } else {
                        counter.other.fetch_add(1, Ordering::SeqCst);
                    }
                }
                publish();
            })));
    }
}

fn restore_callbacks(cluster: &ProductionCluster) {
    for relay in &cluster.relays {
        let publish = super::fixture_pin_callback(
            &relay.membership,
            &relay.pins,
            &relay.pin_publication_pending,
        );
        relay
            .membership
            .set_invalidation_callback(Some(Arc::new(move |_identity, _reason| publish())));
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<ResignStreamEvidence> {
    let profile_directory = tempdir().map_err(HarnessError::Io)?;
    let mut client: Option<ConnectionHandle> = None;
    let mut stream: Option<ConsumerStream> = None;
    let counter = Arc::new(InvalidationCounter::default());
    install_counter(cluster, &counter);
    let result = run_inner(
        cluster,
        harness,
        profile_directory.path(),
        &mut client,
        &mut stream,
        &counter,
    )
    .await;
    restore_callbacks(cluster);
    let mut cleanup_errors = Vec::new();
    if let Some(stream) = stream.as_mut()
        && let Err(error) = stream.close().await
    {
        cleanup_errors.push(format!("consumer stream cleanup: {error}"));
    }
    if let Some(client) = client.take()
        && let Err(error) = client.stop().await
    {
        cleanup_errors.push(format!("device client cleanup: {error}"));
    }
    finish_scenario_with_cleanup(result, cleanup_errors)
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    profile_directory: &std::path::Path,
    client: &mut Option<ConnectionHandle>,
    stream: &mut Option<ConsumerStream>,
    counter: &Arc<InvalidationCounter>,
) -> Result<ResignStreamEvidence> {
    let started = Instant::now();
    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("re-sign stream tenant A device is missing".into())
    })?;
    let service = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("re-sign stream service is missing".into()))?;
    let owner_device = cluster
        .relay(OWNER_NODE)?
        .running
        .as_ref()
        .ok_or_else(|| HarnessError::Process("re-sign owner has no device listener".into()))?
        .device_addr;
    let ingress = cluster.relay(INGRESS_NODE)?.consumer_addr()?;

    let mut profile = write_device_profile(
        profile_directory,
        device.id,
        service,
        CANARY,
        owner_device,
        &device.certificate.certificate_pem,
        &device.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile.config.rotation = super::ROTATION;
    profile
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("re-sign device config: {error}")))?;
    let mut handle = timeout(
        super::STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config: profile.config.clone(),
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("re-sign device startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("re-sign device startup failed: {error}")))?;
    timeout(super::STARTUP_TIMEOUT, handle.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("re-sign device readiness timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("re-sign device not ready: {error}")))?;
    *client = Some(handle);
    let owner = cluster
        .catalog
        .current_owner(device.tenant_id, device.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading re-sign owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("re-sign device did not claim an owner".into()))?;
    if owner.token.node_id != OWNER_NODE {
        return Err(HarnessError::Process(format!(
            "re-sign owner landed on {} instead of {OWNER_NODE}",
            owner.token.node_id
        )));
    }
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(300),
            ..OidcTokenOptions::default()
        },
    )?;

    // Open the stream at the non-owner ingress, retrying only the owner's
    // bounded not-ready answer while its fence settles.
    let deadline = Instant::now() + OWNER_FENCE_READY_BOUND;
    let opened = loop {
        match open_consumer_stream(
            ingress,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service,
        )
        .await
        {
            Ok(opened) => break opened,
            Err(super::StreamConnectFailure::Status { status: 503, .. })
                if Instant::now() < deadline =>
            {
                sleep(Duration::from_millis(250)).await;
            }
            Err(error) => return Err(connect_failure_to_harness(error)),
        }
    };
    let consumer = stream.insert(opened);
    consumer
        .round_trip(b"m7-resign-baseline", CANARY.as_bytes())
        .await?;

    // Sample every relay's transport pin set for the whole re-sign window.
    let sampling = CancellationToken::new();
    let samples = Arc::new(AtomicU64::new(0));
    let ever_empty = Arc::new(AtomicBool::new(false));
    let sampler = {
        let pins = cluster
            .relays
            .iter()
            .map(|relay| relay.pins.clone())
            .collect::<Vec<_>>();
        let sampling = sampling.clone();
        let samples = Arc::clone(&samples);
        let ever_empty = Arc::clone(&ever_empty);
        tokio::spawn(async move {
            while !sampling.is_cancelled() {
                if pins.iter().any(|pins| pins.snapshot().is_empty()) {
                    ever_empty.store(true, Ordering::SeqCst);
                }
                samples.fetch_add(1, Ordering::SeqCst);
                sleep(PIN_SAMPLE_INTERVAL).await;
            }
        })
    };
    counter.armed.store(true, Ordering::SeqCst);

    let mut exchanges = 0usize;
    let mut resigns = 0usize;
    let mut last_version = 0u64;
    let outcome = async {
        for index in 0..SINGLE_RESIGNS {
            last_version = cluster.resign_membership_now().await?;
            resigns += 1;
            stream
                .as_mut()
                .expect("consumer stream installed")
                .round_trip(
                    format!("m7-resign-single-{index}").as_bytes(),
                    CANARY.as_bytes(),
                )
                .await?;
            exchanges += 1;
        }
        last_version = cluster.resign_membership_burst(BURST_VERSIONS).await?;
        resigns += 1;
        let settled = Instant::now();
        cluster
            .wait_for_peer_readiness(READINESS_RECOVERY_BOUND)
            .await?;
        let recovered_ms = settled.elapsed().as_millis();
        stream
            .as_mut()
            .expect("consumer stream installed")
            .round_trip(b"m7-resign-burst", CANARY.as_bytes())
            .await?;
        exchanges += 1;
        Ok::<u128, HarnessError>(recovered_ms)
    }
    .await;
    counter.armed.store(false, Ordering::SeqCst);
    sampling.cancel();
    let _ = sampler.await;
    let readiness_recovered_ms = outcome?;

    let evidence = ResignStreamEvidence {
        relay_count: cluster.relays.len(),
        resigns,
        burst_versions: BURST_VERSIONS,
        last_record_version: last_version,
        exchanges_after_resign: exchanges,
        same_stream_survived: exchanges == resigns,
        membership_changed_invalidations: counter.membership_changed.load(Ordering::SeqCst),
        other_invalidations: counter.other.load(Ordering::SeqCst),
        pin_samples: samples.load(Ordering::SeqCst),
        pins_ever_empty: ever_empty.load(Ordering::SeqCst),
        readiness_recovered_ms,
        elapsed_ms: started.elapsed().as_millis(),
    };
    Ok(evidence)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid() -> ResignStreamEvidence {
        ResignStreamEvidence {
            relay_count: 3,
            resigns: SINGLE_RESIGNS + 1,
            burst_versions: BURST_VERSIONS,
            last_record_version: 6,
            exchanges_after_resign: SINGLE_RESIGNS + 1,
            same_stream_survived: true,
            membership_changed_invalidations: 0,
            other_invalidations: 0,
            pin_samples: 100,
            pins_ever_empty: false,
            readiness_recovered_ms: 10,
            elapsed_ms: 1_000,
        }
    }

    #[test]
    fn the_validator_accepts_the_complete_shape_and_rejects_each_failure() {
        validate_resign_stream_evidence(&valid()).expect("complete evidence");
        type Mutation = fn(&mut ResignStreamEvidence);
        let cases: [(&str, Mutation); 5] = [
            ("same_stream_survived", |e| e.same_stream_survived = false),
            ("membership_changed_invalidations", |e| {
                e.membership_changed_invalidations = 1;
            }),
            ("pins_ever_empty", |e| e.pins_ever_empty = true),
            ("pin_samples", |e| e.pin_samples = 0),
            ("exchanges_after_resign", |e| e.exchanges_after_resign = 1),
        ];
        for (name, mutate) in cases {
            let mut evidence = valid();
            mutate(&mut evidence);
            let error = validate_resign_stream_evidence(&evidence)
                .expect_err("a failed observation must be rejected");
            assert!(error.to_string().contains(name), "{name}: {error}");
        }
    }
}
