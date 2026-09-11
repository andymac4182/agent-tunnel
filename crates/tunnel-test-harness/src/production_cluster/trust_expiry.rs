//! Real Redis-backed signed peer-key expiry with a missed invalidation hint.
//!
//! The initial record keeps the actual relay certificate usable until a
//! bounded key deadline while carrying a second, currently valid overlap pin
//! which is not presented by the relay.  This keeps the signed record and
//! checkpoint valid while the actual certificate trust expires.  The fixture
//! then checks an established remote consumer stream, a new admission, and a
//! separate established peer stream before publishing a higher signed record
//! that re-approves the actual certificate.
//!
//! `affected_stream_interrupted` is intentionally mandatory in the validator
//! so an integration run cannot count readiness or a failed new admission as
//! expiry proof.  The affected owner session and stream cursors are correlated
//! with the expiry observation without retaining payloads or credentials.

use super::{
    ConsumerStream, ProductionCluster, connect_failure_to_harness, finish_scenario_with_cleanup,
    open_consumer_stream, publish_verified_pins, wait_for_public_health_ready,
};
use crate::acceptance::helpers::write_device_profile;
use crate::cluster_fixture::{
    FixturePeerKey, M7_MEMBERSHIP_LIFETIME, MembershipRecordOptions, SignedMembershipFixture,
};
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result, RunningHarness};
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use tokio::time::{sleep, timeout, timeout_at};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{OwnerToken, RedisMembershipPublisher};
use tunnel_client::{ConnectOptions, ConnectionHandle, TransportProfile};
use tunnel_cluster::membership::SignedMembershipRecord;
use tunnel_relay::{
    MembershipReadiness, MembershipUnreadyReason, PeerConsumerDiagnosticRole, PeerProbeState,
    PeerTransportDiagnosticOutcome, RelaySnapshot, StreamTerminalCause, StreamTerminalEvent,
};

const TARGET_NODE: &str = "relay-a";
const AFFECTED_INGRESS: &str = "relay-c";
const SIBLING_INGRESS: &str = "relay-b";
const SIBLING_OWNER: &str = "relay-c";
const SHORT_KEY_LIFETIME: ChronoDuration = ChronoDuration::seconds(5);
const EXPIRY_GRACE: Duration = Duration::from_secs(3);
const MEMBERSHIP_RECONCILIATION_BOUND: Duration = Duration::from_secs(5);
const SIBLING_IDLE_BOUND: Duration = Duration::from_secs(10);
const OWNER_FENCE_READY_BOUND: Duration = Duration::from_secs(3);
const POLL: Duration = Duration::from_millis(50);

/// Payload-free evidence from the actual three-relay trust-expiry gate.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustExpiryEvidence {
    pub relay_count: usize,
    pub signed_record_version_before_expiry: u64,
    pub signed_record_retained_after_key_expiry: bool,
    pub no_record_change_before_expiry: bool,
    pub affected_membership_became_unready: bool,
    pub affected_ingress_membership_remained_ready: bool,
    pub affected_route_readiness_withdrew: bool,
    pub unrelated_route_readiness_survived: bool,
    pub affected_stream_interrupted: bool,
    pub affected_dispatch_unchanged: bool,
    pub affected_new_admission_rejected: bool,
    pub sibling_peer_stream_survived: bool,
    pub sibling_dispatch_advanced: bool,
    pub fresh_approved_record_version: u64,
    pub fresh_approved_trust_recovered: bool,
    pub recovery_echo: bool,
    pub fanout_peak_open: usize,
    pub elapsed_ms: u64,
}

/// Validate every required trust-expiry observation.
pub fn validate_trust_expiry_evidence(evidence: &TrustExpiryEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "trust-expiry expected three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        (
            "signed_record_retained_after_key_expiry",
            evidence.signed_record_retained_after_key_expiry,
        ),
        (
            "no_record_change_before_expiry",
            evidence.no_record_change_before_expiry,
        ),
        (
            "affected_membership_became_unready",
            evidence.affected_membership_became_unready,
        ),
        (
            "affected_route_readiness_withdrew",
            evidence.affected_route_readiness_withdrew,
        ),
        (
            "affected_ingress_membership_remained_ready",
            evidence.affected_ingress_membership_remained_ready,
        ),
        (
            "unrelated_route_readiness_survived",
            evidence.unrelated_route_readiness_survived,
        ),
        (
            "affected_stream_interrupted",
            evidence.affected_stream_interrupted,
        ),
        (
            "affected_dispatch_unchanged",
            evidence.affected_dispatch_unchanged,
        ),
        (
            "affected_new_admission_rejected",
            evidence.affected_new_admission_rejected,
        ),
        (
            "sibling_peer_stream_survived",
            evidence.sibling_peer_stream_survived,
        ),
        (
            "sibling_dispatch_advanced",
            evidence.sibling_dispatch_advanced,
        ),
        (
            "fresh_approved_trust_recovered",
            evidence.fresh_approved_trust_recovered,
        ),
        ("recovery_echo", evidence.recovery_echo),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "trust-expiry required gate {name} was false"
        )));
    }
    if evidence.signed_record_version_before_expiry == 0
        || evidence.fresh_approved_record_version <= evidence.signed_record_version_before_expiry
    {
        return Err(HarnessError::Process(
            "trust-expiry recovery did not advance the signed record version".into(),
        ));
    }
    if evidence.fanout_peak_open > 3 {
        return Err(HarnessError::Process(format!(
            "trust-expiry device fanout exceeded the three-socket bound: {}",
            evidence.fanout_peak_open
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{TrustExpiryEvidence, validate_trust_expiry_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> TrustExpiryEvidence {
        TrustExpiryEvidence {
            relay_count: 3,
            signed_record_version_before_expiry: 1,
            signed_record_retained_after_key_expiry: true,
            no_record_change_before_expiry: true,
            affected_membership_became_unready: true,
            affected_ingress_membership_remained_ready: true,
            affected_route_readiness_withdrew: true,
            unrelated_route_readiness_survived: true,
            affected_stream_interrupted: true,
            affected_dispatch_unchanged: true,
            affected_new_admission_rejected: true,
            sibling_peer_stream_survived: true,
            sibling_dispatch_advanced: true,
            fresh_approved_record_version: 2,
            fresh_approved_trust_recovered: true,
            recovery_echo: true,
            fanout_peak_open: 3,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_trust_expiry_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut TrustExpiryEvidence));
        let flags: [Disable; 13] = [
            ("signed_record_retained_after_key_expiry", |e| {
                e.signed_record_retained_after_key_expiry = false
            }),
            ("no_record_change_before_expiry", |e| {
                e.no_record_change_before_expiry = false
            }),
            ("affected_membership_became_unready", |e| {
                e.affected_membership_became_unready = false
            }),
            ("affected_ingress_membership_remained_ready", |e| {
                e.affected_ingress_membership_remained_ready = false
            }),
            ("affected_route_readiness_withdrew", |e| {
                e.affected_route_readiness_withdrew = false
            }),
            ("unrelated_route_readiness_survived", |e| {
                e.unrelated_route_readiness_survived = false
            }),
            ("affected_stream_interrupted", |e| {
                e.affected_stream_interrupted = false
            }),
            ("affected_dispatch_unchanged", |e| {
                e.affected_dispatch_unchanged = false
            }),
            ("affected_new_admission_rejected", |e| {
                e.affected_new_admission_rejected = false
            }),
            ("sibling_peer_stream_survived", |e| {
                e.sibling_peer_stream_survived = false
            }),
            ("sibling_dispatch_advanced", |e| {
                e.sibling_dispatch_advanced = false
            }),
            ("fresh_approved_trust_recovered", |e| {
                e.fresh_approved_trust_recovered = false
            }),
            ("recovery_echo", |e| e.recovery_echo = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_trust_expiry_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut TrustExpiryEvidence));
        let bounds: [Mutate; 4] = [
            ("relay_count", |e: &mut TrustExpiryEvidence| {
                e.relay_count = 2
            }),
            ("record_version", |e: &mut TrustExpiryEvidence| {
                e.signed_record_version_before_expiry = 0
            }),
            ("record_version_order", |e: &mut TrustExpiryEvidence| {
                e.fresh_approved_record_version = 1
            }),
            ("fanout_peak", |e: &mut TrustExpiryEvidence| {
                e.fanout_peak_open = 4
            }),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_trust_expiry_evidence(&evidence), "trust-expiry");
        }
    }

    #[test]
    fn trust_expiry_validator_accepts_complete_evidence() {
        validate_trust_expiry_evidence(&valid_evidence())
            .expect("complete trust-expiry evidence is valid");
    }
}

/// Run the bounded real Redis-backed signed peer-key expiry fixture.
pub async fn verify() -> Result<TrustExpiryEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    let startup_deadline = Instant::now() + super::STARTUP_TIMEOUT;
    let startup_cleanup_deadline = startup_deadline + super::CLEANUP_TIMEOUT;
    let mut harness_start = Box::pin(Harness::start(options));
    let mut harness = match timeout_at(
        tokio::time::Instant::from_std(startup_deadline),
        &mut harness_start,
    )
    .await
    {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => return Err(error),
        Err(_) => {
            // Keep the constructor pinned until it yields ownership.  The
            // constructor can still own Redis/proxy resources after the
            // first budget expires, so cancelling it here would detach those
            // resources before their joined cleanup path is available.
            let (completion, cleanup_budget_exceeded) = match timeout_at(
                tokio::time::Instant::from_std(startup_cleanup_deadline),
                &mut harness_start,
            )
            .await
            {
                Ok(completion) => (completion, false),
                Err(_) => (harness_start.as_mut().await, true),
            };
            let timeout_message = if cleanup_budget_exceeded {
                "trust-expiry harness startup timed out; startup future completed after the shared cleanup deadline"
            } else {
                "trust-expiry harness startup timed out"
            };
            return match completion {
                Ok(harness) => {
                    let cleanup = harness
                        .shutdown_until(tokio::time::Instant::from_std(startup_cleanup_deadline))
                        .await;
                    match cleanup {
                        Ok(()) => Err(HarnessError::Timeout(timeout_message.into())),
                        Err(cleanup) => Err(HarnessError::Process(format!(
                            "{timeout_message}; late harness cleanup: {cleanup}"
                        ))),
                    }
                }
                Err(error) => Err(HarnessError::Process(format!(
                    "{timeout_message}; startup cleanup: {error}"
                ))),
            };
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; trust-expiry startup cleanup: {cleanup}"
                ))),
            };
        }
    };

    let scenario = run(&mut cluster, &harness).await;
    let cleanup_deadline = tokio::time::Instant::now() + super::CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("catalog cleanup: {error}"));
    }
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

struct ScenarioResources {
    profile_a: TempDir,
    profile_b: TempDir,
    client_a: Option<ConnectionHandle>,
    client_b: Option<ConnectionHandle>,
    stream_a: Option<ConsumerStream>,
    stream_b: Option<ConsumerStream>,
}

impl ScenarioResources {
    fn new(profile_a: TempDir, profile_b: TempDir) -> Self {
        Self {
            profile_a,
            profile_b,
            client_a: None,
            client_b: None,
            stream_a: None,
            stream_b: None,
        }
    }

    async fn cleanup(&mut self, deadline: Instant) -> Vec<String> {
        let mut errors = Vec::new();
        if let Some(stream) = self.stream_a.as_mut()
            && let Err(error) = stream.close().await
        {
            errors.push(format!("affected stream cleanup: {error}"));
        }
        if let Some(stream) = self.stream_b.as_mut()
            && let Err(error) = stream.close().await
        {
            errors.push(format!("sibling stream cleanup: {error}"));
        }
        if let Some(client) = self.client_a.take()
            && let Err(error) = stop_client(&client, "affected client", deadline).await
        {
            errors.push(error.to_string());
        }
        if let Some(client) = self.client_b.take()
            && let Err(error) = stop_client(&client, "sibling client", deadline).await
        {
            errors.push(error.to_string());
        }
        if Instant::now() > deadline {
            errors.push("trust-expiry client cleanup exceeded its shared deadline".into());
        }
        errors
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<TrustExpiryEvidence> {
    let profile_a_directory = tempdir().map_err(HarnessError::Io)?;
    let profile_b_directory = tempdir().map_err(HarnessError::Io)?;
    let mut resources = ScenarioResources::new(profile_a_directory, profile_b_directory);
    let scenario = run_inner(cluster, harness, &mut resources).await;
    let cleanup_deadline = Instant::now() + super::CLEANUP_TIMEOUT;
    let cleanup_errors = resources.cleanup(cleanup_deadline).await;
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

async fn run_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    resources: &mut ScenarioResources,
) -> Result<TrustExpiryEvidence> {
    let started = Instant::now();
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "trust-expiry started {} relays, expected three",
            cluster.relays.len()
        )));
    }

    let device_a = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("trust-expiry tenant A device is missing".into())
    })?;
    let device_b = harness.topology.devices_b.first().ok_or_else(|| {
        HarnessError::InvalidInput("trust-expiry tenant B device is missing".into())
    })?;
    let service_a = *harness
        .topology
        .service_ids
        .get(&device_a.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("trust-expiry tenant A service is missing".into())
        })?;
    let service_b = *harness
        .topology
        .service_ids
        .get(&device_b.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("trust-expiry tenant B service is missing".into())
        })?;
    if device_a.id != device_b.id || service_a != service_b {
        return Err(HarnessError::InvalidInput(
            "trust-expiry sibling fixture did not share the required UUID route".into(),
        ));
    }

    let target_owner_device = cluster
        .relay(TARGET_NODE)?
        .running
        .as_ref()
        .ok_or_else(|| {
            HarnessError::Process("trust-expiry target owner has no device listener".into())
        })?
        .device_addr;
    let sibling_owner_device = cluster
        .relay(SIBLING_OWNER)?
        .running
        .as_ref()
        .ok_or_else(|| {
            HarnessError::Process("trust-expiry sibling owner has no device listener".into())
        })?
        .device_addr;
    let target_owner_ingress = cluster.relay(TARGET_NODE)?.consumer_addr()?;
    let sibling_owner_ingress = cluster.relay(SIBLING_OWNER)?.consumer_addr()?;
    let affected_ingress = cluster.relay(AFFECTED_INGRESS)?.consumer_addr()?;
    let sibling_ingress = cluster.relay(SIBLING_INGRESS)?.consumer_addr()?;

    // Keep the affected connector's control and data sockets on its committed
    // owner while publishing v2.  The shared fanout intentionally rotates
    // accepted sockets across relays; using it here creates a remote v1 peer
    // admission that v2 correctly invalidates, consuming the short expiry
    // window before the public baseline.  Public ingress still exercises the
    // real remote peer route to the owner below.
    let mut profile_a = write_device_profile(
        resources.profile_a.path(),
        device_a.id,
        service_a,
        "m7-trust-expiry-a",
        target_owner_device,
        &device_a.certificate.certificate_pem,
        &device_a.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_a.config.rotation = super::ROTATION;
    profile_a
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("trust-expiry A config: {error}")))?;
    let mut profile_b = write_device_profile(
        resources.profile_b.path(),
        device_b.id,
        service_b,
        "m7-trust-expiry-b",
        sibling_owner_device,
        &device_b.certificate.certificate_pem,
        &device_b.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    profile_b.config.rotation = super::ROTATION;
    profile_b
        .config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("trust-expiry B config: {error}")))?;
    resources.client_a = Some(connect_client(profile_a.config.clone()).await?);
    wait_ready(
        resources.client_a.as_mut().expect("client A installed"),
        "affected client",
    )
    .await?;
    resources.client_b = Some(connect_client(profile_b.config.clone()).await?);
    wait_ready(
        resources.client_b.as_mut().expect("client B installed"),
        "sibling client",
    )
    .await?;
    let owner_a = cluster
        .catalog
        .current_owner(device_a.tenant_id, device_a.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading affected owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("affected device did not claim an owner".into()))?;
    if owner_a.token.node_id != TARGET_NODE {
        return Err(HarnessError::Process(format!(
            "affected owner landed on {} instead of {TARGET_NODE}",
            owner_a.token.node_id
        )));
    }
    let owner_b = cluster
        .catalog
        .current_owner(device_b.tenant_id, device_b.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("reading sibling owner: {error}")))?
        .ok_or_else(|| HarnessError::Process("sibling device did not claim an owner".into()))?;
    if owner_b.token.node_id != SIBLING_OWNER {
        return Err(HarnessError::Process(format!(
            "sibling owner landed on {} instead of {SIBLING_OWNER}",
            owner_b.token.node_id
        )));
    }

    let token_a = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let token_b = harness.oidc.issue_with(
        &harness.topology.consumers_b[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;

    // `wait_ready` proves the connector has both M2 sockets, while the relay
    // admits a public stream only after its owner-fence/data-carrier gate is
    // complete.  Use the server's exact retry metadata as the bounded fence
    // barrier before starting the five-second trust window.  This keeps a
    // startup race from being mistaken for a peer-key expiry result and does
    // not dispatch an application body.
    wait_for_owner_admission(
        cluster,
        TARGET_NODE,
        target_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        device_a.id,
        service_a,
        "affected owner",
    )
    .await?;
    wait_for_owner_admission(
        cluster,
        SIBLING_OWNER,
        sibling_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_b,
        device_b.id,
        service_b,
        "sibling owner",
    )
    .await?;

    // Establish both owner sessions under the long-lived fixture record
    // first. The short key window starts only when the v2 record is actually
    // published, so client startup cannot consume the natural five-second
    // expiry interval. No catalog write occurs at the expiry deadline.
    let record_now = Utc::now();
    let target_spki = old_key_spki(cluster)?;
    let expiring_record = sign_expiring_record(cluster, record_now, 2)?;
    let old_key_expiry = expiring_record
        .payload
        .keys
        .iter()
        .find(|key| key.spki_sha256 == target_spki)
        .map(|key| key.expires_at)
        .ok_or_else(|| HarnessError::Process("trust-expiry record lost target SPKI".into()))?;
    let before_v2 = read_target_record(cluster).await?.ok_or_else(|| {
        HarnessError::Process("trust-expiry target has no catalog record before v2".into())
    })?;
    let before_v2_digest = sha256_hex(&before_v2.bytes);
    let expiring_digest = sha256_hex(expiring_record.encoded_bytes());
    if before_v2.record.record_version >= expiring_record.payload.record_version
        || before_v2.bytes == expiring_record.encoded_bytes()
    {
        return Err(HarnessError::Process(format!(
            "trust-expiry expected a distinct pre-v2 target record (version {}, digest {before_v2_digest})",
            before_v2.record.record_version
        )));
    }
    publish_membership(harness, &expiring_record).await?;
    cluster
        .fixture
        .memberships
        .insert(TARGET_NODE.to_owned(), expiring_record.clone());
    wait_for_record_version(cluster, 2, true).await?;
    cluster
        .wait_for_peer_readiness(super::KEY_REVOCATION_RECOVERY_TIMEOUT)
        .await?;
    let baseline_deadline =
        Instant::now() + (old_key_expiry - Utc::now()).to_std().unwrap_or_default();
    for ingress in [affected_ingress, sibling_ingress] {
        tokio::time::timeout_at(
            baseline_deadline.into(),
            wait_for_public_health_ready(ingress, &harness.pki.server_ca.certificate_der),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "trust-expiry public readiness did not recover before key expiry".into(),
            )
        })??;
    }
    let applied_v2 = read_target_record(cluster).await?.ok_or_else(|| {
        HarnessError::Process("trust-expiry v2 target record disappeared from catalog".into())
    })?;
    let applied_v2_digest = sha256_hex(&applied_v2.bytes);
    if applied_v2.record.record_version != 2
        || applied_v2.bytes != expiring_record.encoded_bytes()
        || applied_v2_digest != expiring_digest
    {
        return Err(HarnessError::Process(format!(
            "trust-expiry catalog v2 bytes did not match the signed fixture (observed version {}, digest {}, expected {expiring_digest})",
            applied_v2.record.record_version, applied_v2_digest
        )));
    }
    if target_key_window(&applied_v2.record, &target_spki) != Some((record_now, old_key_expiry)) {
        return Err(HarnessError::Process(
            "trust-expiry v2 record did not retain the exact target SPKI window".into(),
        ));
    }

    resources.stream_a = Some(
        open_baseline_consumer_stream(
            cluster,
            AFFECTED_INGRESS,
            affected_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_a,
            device_a.id,
            service_a,
            "affected baseline",
        )
        .await?,
    );
    resources
        .stream_a
        .as_mut()
        .expect("affected stream installed")
        .round_trip(b"before-expiry-a", b"m7-trust-expiry-a")
        .await?;
    resources.stream_b = Some(
        open_baseline_consumer_stream(
            cluster,
            SIBLING_INGRESS,
            sibling_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_b,
            device_b.id,
            service_b,
            "sibling baseline",
        )
        .await?,
    );
    resources
        .stream_b
        .as_mut()
        .expect("sibling stream installed")
        .round_trip(b"before-expiry-b", b"m7-trust-expiry-b")
        .await?;

    if Utc::now() >= old_key_expiry {
        return Err(HarnessError::Timeout(
            "trust-expiry baseline completed after the target SPKI expired".into(),
        ));
    }
    let owner_before_expiry = cluster.relay(TARGET_NODE)?.snapshot().await?;
    let sibling_owner_before_expiry = cluster.relay(SIBLING_OWNER)?.snapshot().await?;
    let authoritative_trust_deadline_ms = cluster
        .relay(TARGET_NODE)?
        .membership
        .snapshot()
        .trust_deadline_ms
        .ok_or_else(|| {
            HarnessError::Process(
                "trust-expiry target did not expose an authoritative monotonic trust deadline"
                    .into(),
            )
        })?;
    let owner_a_cursor_before = owner_session_cursor(&owner_before_expiry, &owner_a.token)
        .ok_or_else(|| {
            HarnessError::Process(
                "trust-expiry affected owner session was not present before expiry".into(),
            )
        })?;
    let sibling_cursor_before = owner_session_cursor(&sibling_owner_before_expiry, &owner_b.token)
        .ok_or_else(|| {
            HarnessError::Process(
                "trust-expiry sibling owner session was not present before expiry".into(),
            )
        })?;
    // Begin exact stream observation before wait_for_expiry.  The observer
    // remains active while readiness, retained-record, negative-admission, and
    // post-expiry probe checks run, and is joined below rather than detached.
    let affected_observer = wait_for_affected_owner_stream_interrupted(
        cluster,
        &owner_a.token,
        &owner_a_cursor_before,
        old_key_expiry,
        authoritative_trust_deadline_ms,
    );
    let scenario = async {
        let expiry_wait = wait_for_expiry(cluster, old_key_expiry).await?;
        if expiry_wait >= SIBLING_IDLE_BOUND {
            return Err(HarnessError::Timeout(format!(
                "trust-expiry sibling stream was idle for {} ms while waiting for revocation",
                expiry_wait.as_millis()
            )));
        }
        let target_readiness = cluster.relay(TARGET_NODE)?.membership.readiness();
        let affected_membership_became_unready = matches!(
            target_readiness,
            MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired)
        );
        if !affected_membership_became_unready {
            return Err(HarnessError::Process(format!(
                "target membership did not report signed key expiry; readiness={target_readiness:?}"
            )));
        }
        let affected_route_readiness_withdrew = route_has_state(
            cluster,
            AFFECTED_INGRESS,
            TARGET_NODE,
            PeerProbeState::Unreachable,
        )?;
        let affected_ingress_membership_remained_ready = matches!(
            cluster.relay(AFFECTED_INGRESS)?.membership.readiness(),
            MembershipReadiness::Ready
        );
        let unrelated_route_readiness_survived = route_has_state(
            cluster,
            AFFECTED_INGRESS,
            SIBLING_INGRESS,
            PeerProbeState::Reachable,
        )?;
        if !affected_ingress_membership_remained_ready
            || !affected_route_readiness_withdrew
            || !unrelated_route_readiness_survived
        {
            return Err(HarnessError::Process(
                "trust-expiry did not attribute relay-c route loss to expired relay-a while retaining relay-b and ingress membership readiness".into(),
            ));
        }
        let retained_record = read_target_record(cluster).await?;
        let exact_v2_retained = retained_record.as_ref().is_some_and(|observed| {
            observed.record.record_version == 2
                && observed.bytes == expiring_record.encoded_bytes()
                && observed.record.expires_at > Utc::now()
                && target_key_window(&observed.record, &target_spki)
                    == Some((record_now, old_key_expiry))
        });
        let signed_record_retained_after_key_expiry = exact_v2_retained;
        let retained_record_version = retained_record
            .as_ref()
            .map_or(0, |record| record.record.record_version);
        let retained_record_digest = retained_record
            .as_ref()
            .map_or_else(|| "missing".to_owned(), |record| sha256_hex(&record.bytes));
        let no_record_change_before_expiry = retained_record.as_ref().is_some_and(|observed| {
            observed.bytes == expiring_record.encoded_bytes()
                && retained_record_digest == expiring_digest
        });
        if !signed_record_retained_after_key_expiry || !no_record_change_before_expiry {
            return Err(HarnessError::Process(format!(
                "trust-expiry retained record changed after key expiry (observed digest {retained_record_digest}, expected {expiring_digest})"
            )));
        }

        let affected_outcome = resources
            .stream_a
            .as_mut()
            .expect("affected stream installed")
            .probe_after_pause(b"after-expiry-a")
            .await;
        if !affected_outcome.is_fail_closed() {
            return Err(HarnessError::Process(format!(
                "expired target pooled stream did not produce a bounded post-send close/error: {affected_outcome:?}"
            )));
        }
        let affected_dispatch_unchanged = super::wait_for_unchanged_application_dispatch(
            cluster.relay(TARGET_NODE)?,
            owner_before_expiry.lifetime_application_dispatches,
        )
        .await
        .is_ok();
        let dispatch_before_negative = cluster
            .relay(TARGET_NODE)?
            .snapshot()
            .await?
            .lifetime_application_dispatches;
        let affected_new_admission_rejected = match open_consumer_stream(
            affected_ingress,
            &harness.pki.server_ca.certificate_der,
            &token_a,
            device_a.id,
            service_a,
        )
        .await
        {
            Err(super::StreamConnectFailure::Status { status, body }) => {
                status == 503 && is_exact_cluster_unready(body.as_deref())
            }
            Err(super::StreamConnectFailure::Harness(error)) => return Err(error),
            Ok(mut stream) => {
                let _ = stream.close().await;
                false
            }
        };
        let dispatch_after_negative = cluster
            .relay(TARGET_NODE)?
            .snapshot()
            .await?
            .lifetime_application_dispatches;
        if dispatch_before_negative != dispatch_after_negative {
            return Err(HarnessError::Process(
                "expired target admission advanced the owner dispatch counter".into(),
            ));
        }
        if !affected_new_admission_rejected {
            return Err(HarnessError::Process(
                "expired target admission did not return exact CLUSTER_UNREADY/not_dispatched"
                    .into(),
            ));
        }

        resources
            .stream_b
            .as_mut()
            .expect("sibling stream installed")
            .round_trip(b"after-expiry-b", b"m7-trust-expiry-b")
            .await?;
        let sibling_after_expiry = cluster.relay(SIBLING_OWNER)?.snapshot().await?;
        let sibling_peer_stream_survived = sibling_owner_stream_advanced(
            &sibling_after_expiry,
            &owner_b.token,
            &sibling_cursor_before,
        );
        let sibling_dispatch_advanced = sibling_after_expiry.lifetime_application_dispatches
            > sibling_owner_before_expiry.lifetime_application_dispatches;
        if !sibling_peer_stream_survived || !sibling_dispatch_advanced {
            return Err(HarnessError::Process(
                "trust-expiry sibling owner session/cursor did not advance after affected expiry"
                    .into(),
            ));
        }

        let recovery_now = Utc::now();
        let recovery_record = sign_reapproved_record(cluster, recovery_now, 3)?;
        let recovery_record_version = recovery_record.payload.record_version;
        publish_membership(harness, &recovery_record).await?;
        wait_for_record_version(cluster, 3, true).await?;
        let target = cluster.relay(TARGET_NODE)?;
        wait_until_membership_ready(&target.membership, super::KEY_REVOCATION_RECOVERY_TIMEOUT)
            .await?;
        publish_verified_pins(&target.membership, &target.pins)?;
        cluster
            .wait_for_peer_readiness(super::KEY_REVOCATION_RECOVERY_TIMEOUT)
            .await?;
        let recovered_record = read_target_record(cluster).await?.ok_or_else(|| {
            HarnessError::Process("trust-expiry v3 target record missing after recovery".into())
        })?;
        let recovered_digest = sha256_hex(&recovered_record.bytes);
        let expected_recovered_digest = sha256_hex(recovery_record.encoded_bytes());
        if recovered_record.record.record_version != recovery_record.payload.record_version
            || recovered_record.bytes != recovery_record.encoded_bytes()
            || target_key_window(&recovered_record.record, &target_spki)
                != Some((recovery_now, recovery_now + M7_MEMBERSHIP_LIFETIME))
        {
            return Err(HarnessError::Process(format!(
                "trust-expiry v3 record did not exactly reapprove the target key (observed version {}, digest {recovered_digest}, expected {expected_recovered_digest})",
                recovered_record.record.record_version
            )));
        }
        let fresh_approved_trust_recovered = cluster.relays.iter().all(|relay| {
            relay
                .membership
                .snapshot()
                .memberships
                .iter()
                .any(|record| {
                    record.node_id == TARGET_NODE
                        && record.record_version == recovery_record.payload.record_version
                        && record.spki_sha256.iter().any(|spki| spki == &target_spki)
                        && record.valid_until == recovery_record.payload.expires_at
                })
        });
        if !fresh_approved_trust_recovered {
            return Err(HarnessError::Process(
                "fresh signed trust record did not reach every relay".into(),
            ));
        }
        if let Some(mut expired_stream) = resources.stream_a.take() {
            expired_stream.close().await?;
        }
        resources.stream_a = Some(
            open_consumer_stream(
                affected_ingress,
                &harness.pki.server_ca.certificate_der,
                &token_a,
                device_a.id,
                service_a,
            )
            .await
            .map_err(connect_failure_to_harness)?,
        );
        resources
            .stream_a
            .as_mut()
            .expect("recovery stream installed")
            .round_trip(b"after-recovery-a", b"m7-trust-expiry-a")
            .await?;
        let recovery_echo = true;
        let fanout_peak_open = cluster.device_fanout.diagnostics().peak_open;
        let evidence = TrustExpiryEvidence {
            relay_count: cluster.relays.len(),
            signed_record_version_before_expiry: retained_record_version,
            signed_record_retained_after_key_expiry,
            no_record_change_before_expiry,
            affected_membership_became_unready,
            affected_ingress_membership_remained_ready,
            affected_route_readiness_withdrew,
            unrelated_route_readiness_survived,
            // The exact observer is joined outside this scenario.
            affected_stream_interrupted: false,
            affected_dispatch_unchanged,
            affected_new_admission_rejected,
            sibling_peer_stream_survived,
            sibling_dispatch_advanced,
            fresh_approved_record_version: recovery_record_version,
            fresh_approved_trust_recovered,
            recovery_echo,
            fanout_peak_open,
            elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
        };
        Ok::<_, HarnessError>((evidence, recovery_record))
    };
    let (affected_session_correlated, scenario_result) = tokio::join!(affected_observer, scenario);
    let (mut evidence, recovery_record) = scenario_result?;
    // Update fixture bookkeeping only after both futures have joined. Live
    // recovery above reads the signed Redis record and each relay runtime.
    cluster
        .fixture
        .memberships
        .insert(TARGET_NODE.to_owned(), recovery_record);
    if let Err(last_sample) = affected_session_correlated? {
        return Err(HarnessError::Process(format!(
            "expired target pooled stream was not observed with its exact owner session/cursor before reclamation; last sample: {last_sample:?}"
        )));
    }
    evidence.affected_stream_interrupted = true;
    Ok(evidence)
}

fn sign_expiring_record(
    cluster: &ProductionCluster,
    now: DateTime<Utc>,
    record_version: u64,
) -> Result<SignedMembershipFixture> {
    let node = cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("trust-expiry target node is missing".into()))?;
    let peer_endpoint = cluster
        .peer_proxies
        .get(TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("trust-expiry target proxy is missing".into()))?
        .address();
    let old_spki = node.peer_spki_fingerprint()?;
    let overlap_spki = "0000000000000000000000000000000000000000000000000000000000000000";
    let overlap = FixturePeerKey {
        key_id: "relay-a-peer-overlap".into(),
        spki_sha256: overlap_spki.into(),
        not_before: now,
        expires_at: now + M7_MEMBERSHIP_LIFETIME,
        revoked: false,
    };
    let old = FixturePeerKey {
        key_id: "relay-a-peer-z-current".into(),
        spki_sha256: old_spki,
        not_before: now,
        expires_at: now + SHORT_KEY_LIFETIME,
        revoked: false,
    };
    cluster
        .checkpoint_authority
        .issuer
        .sign_membership_with_endpoint_and_keys(
            &cluster.fixture.deployment_id,
            &cluster.fixture.deployment_incarnation,
            node,
            MembershipRecordOptions {
                record_version,
                peer_endpoint,
                keys: vec![overlap, old],
                now,
                expires_at: now + M7_MEMBERSHIP_LIFETIME,
            },
        )
}

fn sign_reapproved_record(
    cluster: &ProductionCluster,
    now: DateTime<Utc>,
    record_version: u64,
) -> Result<SignedMembershipFixture> {
    let node = cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("trust-expiry target node is missing".into()))?;
    let peer_endpoint = cluster
        .peer_proxies
        .get(TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("trust-expiry target proxy is missing".into()))?
        .address();
    let key = FixturePeerKey {
        key_id: "relay-a-peer-z-reapproved".into(),
        spki_sha256: node.peer_spki_fingerprint()?,
        not_before: now,
        expires_at: now + M7_MEMBERSHIP_LIFETIME,
        revoked: false,
    };
    cluster
        .checkpoint_authority
        .issuer
        .sign_membership_with_endpoint_and_keys(
            &cluster.fixture.deployment_id,
            &cluster.fixture.deployment_incarnation,
            node,
            MembershipRecordOptions {
                record_version,
                peer_endpoint,
                keys: vec![key],
                now,
                expires_at: now + M7_MEMBERSHIP_LIFETIME,
            },
        )
}

async fn publish_membership(
    harness: &RunningHarness,
    record: &SignedMembershipFixture,
) -> Result<()> {
    let publisher =
        RedisMembershipPublisher::connect(harness.redis.redis_url(), harness.redis.namespace())
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("connecting trust-expiry publisher: {error}"))
            })?;
    publisher
        .publish_signed_membership_for_node(TARGET_NODE, &record.catalog_record())
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing trust-expiry record: {error}")))
}

#[derive(Clone, Debug)]
struct ObservedTargetRecord {
    record: SignedMembershipRecord,
    bytes: Vec<u8>,
}

#[derive(Clone, Debug)]
struct OwnerSessionCursor {
    tenant_id: String,
    device_id: String,
    session_id: String,
    epoch: u64,
    deployment_incarnation: String,
    node_id: String,
    boot_id: String,
    owner_id: String,
    active_generation: u64,
    active_connection_id: String,
    rotations_completed: u64,
    total_replayed_frames: u64,
    stream: StreamCursor,
}

#[derive(Clone, Debug)]
struct StreamCursor {
    stream_id: u64,
    operation_id: String,
    last_emitted: u64,
    peer_acked: u64,
    recv_contiguous: u64,
    delivered: u64,
    terminal: bool,
}

fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn owner_id_digest(owner: &OwnerToken) -> String {
    let canonical = serde_json::to_vec(owner).expect("OwnerToken is serializable");
    sha256_hex(&canonical)
}

fn old_key_spki(cluster: &ProductionCluster) -> Result<String> {
    cluster
        .fixture
        .nodes
        .iter()
        .find(|node| node.node_id == TARGET_NODE)
        .ok_or_else(|| HarnessError::InvalidInput("trust-expiry target node is missing".into()))?
        .peer_spki_fingerprint()
}

fn target_key_window(
    record: &SignedMembershipRecord,
    spki: &str,
) -> Option<(DateTime<Utc>, DateTime<Utc>)> {
    record
        .keys
        .iter()
        .find(|key| key.spki_sha256 == spki && !key.revoked)
        .map(|key| (key.not_before, key.expires_at))
}

fn owner_session_cursor(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
) -> Option<OwnerSessionCursor> {
    owner_session_cursor_for(snapshot, owner, None)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct LogicalStreamIdentity {
    stream_id: u64,
    operation_id: String,
}

fn owner_session_cursor_for(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    expected_stream: Option<&LogicalStreamIdentity>,
) -> Option<OwnerSessionCursor> {
    snapshot
        .sessions
        .iter()
        .find(|session| {
            session.tenant_id == owner.tenant_id.to_string()
                && session.device_id == owner.device_id.to_string()
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
        })
        .and_then(|session| {
            // The consumer handle does not expose the relay-assigned stream
            // ID.  Establish the logical target from the one nonterminal
            // stream present after the baseline exchange, and reject an
            // ambiguous warmup/session snapshot rather than selecting an
            // arbitrary stream.  Later samples must match this exact pair.
            let stream = match expected_stream {
                Some(expected) => session.streams.iter().find(|stream| {
                    stream.stream_id == expected.stream_id
                        && stream.operation_id == expected.operation_id
                })?,
                None => {
                    let mut candidates = session.streams.iter().filter(|stream| !stream.terminal);
                    let stream = candidates.next()?;
                    if candidates.next().is_some() {
                        return None;
                    }
                    stream
                }
            };
            Some(OwnerSessionCursor {
                tenant_id: session.tenant_id.clone(),
                device_id: session.device_id.clone(),
                session_id: session.session_id.clone(),
                epoch: session.epoch,
                deployment_incarnation: owner.deployment_incarnation.clone(),
                node_id: owner.node_id.clone(),
                boot_id: owner.boot_id.clone(),
                owner_id: owner_id_digest(owner),
                active_generation: session.active_generation,
                active_connection_id: session.active_connection_id.clone(),
                rotations_completed: session.rotations_completed,
                total_replayed_frames: session.total_replayed_frames,
                stream: StreamCursor {
                    stream_id: stream.stream_id,
                    operation_id: stream.operation_id.clone(),
                    last_emitted: stream.last_emitted_relay_to_connector,
                    peer_acked: stream.peer_acked_relay_to_connector,
                    recv_contiguous: stream.recv_contiguous_connector_to_relay,
                    delivered: stream.delivered_contiguous_connector_to_relay,
                    terminal: stream.terminal,
                },
            })
        })
}

fn verified_carrier_transition(before: &OwnerSessionCursor, after: &OwnerSessionCursor) -> bool {
    if before.active_generation == after.active_generation
        && before.active_connection_id == after.active_connection_id
    {
        return true;
    }
    // A new physical carrier is accepted only when the relay reports one or
    // more clean, scheduled rotation commits.  A connection replacement with
    // no completed rotation (including recovery/failover) cannot be used to
    // hide a logical stream identity change.
    let generation_delta = after
        .active_generation
        .saturating_sub(before.active_generation);
    let rotation_delta = after
        .rotations_completed
        .saturating_sub(before.rotations_completed);
    generation_delta > 0
        && rotation_delta > 0
        && generation_delta == rotation_delta
        && after.total_replayed_frames == before.total_replayed_frames
}

fn verified_terminal_carrier_transition(
    before: &OwnerSessionCursor,
    event: &StreamTerminalEvent,
) -> bool {
    if before.active_generation == event.active_generation
        && before.active_connection_id == event.active_connection_id
    {
        return true;
    }
    let generation_delta = event
        .active_generation
        .saturating_sub(before.active_generation);
    let rotation_delta = event
        .rotations_completed
        .saturating_sub(before.rotations_completed);
    generation_delta > 0
        && rotation_delta > 0
        && generation_delta == rotation_delta
        && event.total_replayed_frames == before.total_replayed_frames
}

/// Payload-free record of one exact-observation sample.  Every field is a
/// boolean, a counter, or a closed diagnostic label, so a failed gate can name
/// the first unmet correlation condition without retaining payloads,
/// credentials, or free-form transport text.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct AffectedObservationSample {
    target_deadline_passed: bool,
    matching_terminal_events: usize,
    stream_removed: bool,
    baseline_owner_identity_matches: bool,
    event_owner_identity_matches: bool,
    reason: Option<&'static str>,
    cause: Option<StreamTerminalCause>,
    authorization_failure_code: Option<&'static str>,
    closed_after_deadline: bool,
    cursors_monotonic: bool,
    carrier_transition_verified: bool,
    event_request_id_present: bool,
    ingress_receive_count: u64,
    ingress_last_receive: Option<(PeerConsumerDiagnosticRole, PeerTransportDiagnosticOutcome)>,
    ingress_owner_identity_matches: bool,
    ingress_request_id_matches: bool,
}

impl AffectedObservationSample {
    /// Every condition must hold on one sample.  A missing stream, a missing
    /// latch, or a generic close never satisfies the gate.
    fn satisfied(&self) -> bool {
        self.target_deadline_passed
            && self.matching_terminal_events == 1
            && self.stream_removed
            && self.baseline_owner_identity_matches
            && self.event_owner_identity_matches
            && self.reason == Some("STREAM_CLOSED")
            && self.cause == Some(StreamTerminalCause::PeerMembershipExpired)
            && self.authorization_failure_code.is_none()
            && self.closed_after_deadline
            && self.cursors_monotonic
            && self.carrier_transition_verified
            && self.event_request_id_present
            && self.ingress_last_receive
                == Some((
                    PeerConsumerDiagnosticRole::IngressReceive,
                    PeerTransportDiagnosticOutcome::TrustExpired,
                ))
            && self.ingress_owner_identity_matches
            && self.ingress_request_id_matches
    }
}

fn sample_affected_owner_stream(
    target_snapshot: &RelaySnapshot,
    source_snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    before: &OwnerSessionCursor,
    authoritative_deadline_ms: u64,
) -> AffectedObservationSample {
    let mut sample = AffectedObservationSample {
        target_deadline_passed: target_snapshot.monotonic_now_ms >= authoritative_deadline_ms,
        ..AffectedObservationSample::default()
    };
    let matching_events = target_snapshot
        .stream_terminal_events
        .iter()
        .filter(|event| {
            event.tenant_id == owner.tenant_id.to_string()
                && event.device_id == owner.device_id.to_string()
                && event.session_id == owner.session_id
                && event.epoch == owner.epoch
                && event.stream_id == before.stream.stream_id
                && event.operation_id == before.stream.operation_id
        })
        .collect::<Vec<_>>();
    sample.matching_terminal_events = matching_events.len();
    sample.stream_removed = target_snapshot.sessions.iter().all(|session| {
        !session.streams.iter().any(|stream| {
            stream.stream_id == before.stream.stream_id
                && stream.operation_id == before.stream.operation_id
        })
    });
    sample.baseline_owner_identity_matches = before.deployment_incarnation
        == owner.deployment_incarnation
        && before.node_id == owner.node_id
        && before.boot_id == owner.boot_id
        && before.owner_id == owner_id_digest(owner);
    let ingress = &source_snapshot.peer_consumer_diagnostics;
    sample.ingress_receive_count = ingress.ingress_receive_count;
    sample.ingress_last_receive = ingress
        .last_ingress_receive
        .as_ref()
        .map(|diagnostic| (diagnostic.role, diagnostic.outcome));
    sample.ingress_owner_identity_matches =
        ingress
            .last_ingress_receive
            .as_ref()
            .is_some_and(|diagnostic| {
                diagnostic.tenant_id == owner.tenant_id
                    && diagnostic.device_id == owner.device_id
                    && diagnostic.session_id == owner.session_id
                    && diagnostic.epoch == owner.epoch
            });
    // A second terminal record for the same exact stream identity is an
    // ambiguous lifecycle trace. Never reverse-search past an earlier
    // conflicting record to manufacture an expiry proof.
    let [event] = matching_events.as_slice() else {
        return sample;
    };
    sample.event_owner_identity_matches = event.deployment_incarnation
        == owner.deployment_incarnation
        && event.node_id == owner.node_id
        && event.boot_id == owner.boot_id
        && event.owner_id == owner_id_digest(owner);
    sample.reason = Some(event.reason);
    sample.cause = event.cause;
    sample.authorization_failure_code = event.authorization_failure_code;
    sample.closed_after_deadline = event.closed_at_ms >= authoritative_deadline_ms;
    sample.cursors_monotonic = event.active_generation >= before.active_generation
        && event.last_emitted_relay_to_connector >= before.stream.last_emitted
        && event.peer_acked_relay_to_connector >= before.stream.peer_acked
        && event.recv_contiguous_connector_to_relay >= before.stream.recv_contiguous
        && event.delivered_contiguous_connector_to_relay >= before.stream.delivered
        && event.rotations_completed >= before.rotations_completed
        && event.total_replayed_frames == before.total_replayed_frames;
    sample.carrier_transition_verified = verified_terminal_carrier_transition(before, event);
    sample.event_request_id_present = event.request_id.is_some();
    sample.ingress_request_id_matches = event.request_id.as_deref().is_some_and(|request_id| {
        ingress
            .last_ingress_receive
            .as_ref()
            .is_some_and(|diagnostic| diagnostic.request_id == request_id)
    });
    sample
}

fn sibling_owner_stream_advanced(
    snapshot: &RelaySnapshot,
    owner: &OwnerToken,
    before: &OwnerSessionCursor,
) -> bool {
    let expected_stream = LogicalStreamIdentity {
        stream_id: before.stream.stream_id,
        operation_id: before.stream.operation_id.clone(),
    };
    let Some(after) = owner_session_cursor_for(snapshot, owner, Some(&expected_stream)) else {
        return false;
    };
    if after.tenant_id != before.tenant_id
        || after.device_id != before.device_id
        || after.session_id != before.session_id
        || after.epoch != before.epoch
        || !verified_carrier_transition(before, &after)
        || after.stream.stream_id != before.stream.stream_id
        || after.stream.operation_id != before.stream.operation_id
    {
        return false;
    }
    !after.stream.terminal
        && (after.stream.last_emitted > before.stream.last_emitted
            || after.stream.delivered > before.stream.delivered)
}

async fn wait_for_affected_owner_stream_interrupted(
    cluster: &ProductionCluster,
    owner: &OwnerToken,
    before: &OwnerSessionCursor,
    expires_at: DateTime<Utc>,
    authoritative_deadline_ms: u64,
) -> Result<std::result::Result<(), AffectedObservationSample>> {
    // The observer starts before the credential deadline, so its budget must
    // cover the expiry instant and the bounded membership/route convergence
    // window.  A short post-expiry grace remains for the terminal FIN/ACK
    // snapshot before STREAM_FORGET reclaims the exact logical stream.
    let remaining = (expires_at - Utc::now()).to_std().unwrap_or_default();
    let deadline = Instant::now() + remaining + MEMBERSHIP_RECONCILIATION_BOUND + EXPIRY_GRACE;
    let mut last_sample = AffectedObservationSample::default();
    loop {
        let target_snapshot = cluster.relay(TARGET_NODE)?.snapshot().await?;
        let source_snapshot = cluster.relay(AFFECTED_INGRESS)?.snapshot().await?;
        // A pre-expiry close is a fixture/liveness failure, not credential
        // expiry evidence.  Start sampling now, but latch only after the
        // authoritative credential deadline has passed.
        if Utc::now() >= expires_at {
            last_sample = sample_affected_owner_stream(
                &target_snapshot,
                &source_snapshot,
                owner,
                before,
                authoritative_deadline_ms,
            );
            if last_sample.satisfied() {
                return Ok(Ok(()));
            }
        }
        if Instant::now() >= deadline {
            // The last payload-free sample names the unmet conditions.
            return Ok(Err(last_sample));
        }
        sleep(POLL).await;
    }
}

async fn read_target_record(cluster: &ProductionCluster) -> Result<Option<ObservedTargetRecord>> {
    let records = cluster
        .catalog
        .read_signed_memberships()
        .await
        .map_err(|error| HarnessError::Redis(format!("reading retained trust record: {error}")))?;
    records
        .into_iter()
        .filter(|record| record.bytes.len() <= super::MAX_RECORD_BYTES)
        .filter_map(|record| {
            let parsed = serde_json::from_slice::<SignedMembershipRecord>(&record.bytes).ok()?;
            Some(ObservedTargetRecord {
                record: parsed,
                bytes: record.bytes,
            })
        })
        .find(|record| record.record.node_id == TARGET_NODE)
        .map_or(Ok(None), |record| Ok(Some(record)))
}

async fn wait_for_record_version(
    cluster: &ProductionCluster,
    version: u64,
    require_ready: bool,
) -> Result<()> {
    let deadline = Instant::now() + super::KEY_REVOCATION_RECOVERY_TIMEOUT;
    loop {
        let applied = cluster.relays.iter().all(|relay| {
            let snapshot = relay.membership.snapshot();
            snapshot
                .memberships
                .iter()
                .any(|record| record.node_id == TARGET_NODE && record.record_version >= version)
                && (!require_ready || matches!(snapshot.readiness, MembershipReadiness::Ready))
        });
        if applied {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "trust-expiry signed record version {version} did not reach all relays"
            )));
        }
        sleep(POLL).await;
    }
}

async fn wait_for_expiry(
    cluster: &ProductionCluster,
    expires_at: DateTime<Utc>,
) -> Result<Duration> {
    let started = Instant::now();
    let remaining = (expires_at - Utc::now()).to_std().unwrap_or_default();
    let deadline = Instant::now() + remaining + MEMBERSHIP_RECONCILIATION_BOUND + EXPIRY_GRACE;
    loop {
        let target_unready = Utc::now() >= expires_at
            && matches!(
                cluster.relay(TARGET_NODE)?.membership.readiness(),
                MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired)
            );
        let affected_ingress_membership_ready = matches!(
            cluster.relay(AFFECTED_INGRESS)?.membership.readiness(),
            MembershipReadiness::Ready
        );
        let affected_route_withdrew = route_has_state(
            cluster,
            AFFECTED_INGRESS,
            TARGET_NODE,
            PeerProbeState::Unreachable,
        )?;
        let unrelated_route_survived = route_has_state(
            cluster,
            AFFECTED_INGRESS,
            SIBLING_INGRESS,
            PeerProbeState::Reachable,
        )?;
        if target_unready
            && affected_ingress_membership_ready
            && affected_route_withdrew
            && unrelated_route_survived
        {
            return Ok(started.elapsed());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "trust-expiry target did not become unready with an attributed relay-c to relay-a route withdrawal".into(),
            ));
        }
        sleep(POLL).await;
    }
}

fn route_has_state(
    cluster: &ProductionCluster,
    ingress_node: &str,
    target_node: &str,
    expected: PeerProbeState,
) -> Result<bool> {
    Ok(cluster
        .relay(ingress_node)?
        .peer_runtime
        .peer_readiness()
        .and_then(|readiness| readiness.route_readiness(target_node))
        .is_some_and(|route| route.node_id == target_node && route.state == expected))
}

async fn wait_until_membership_ready(
    membership: &tunnel_relay::MembershipRuntime,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    loop {
        if matches!(membership.readiness(), MembershipReadiness::Ready) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "trust-expiry reapproved membership did not become Ready".into(),
            ));
        }
        sleep(POLL).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_owner_admission(
    cluster: &ProductionCluster,
    ingress_node: &str,
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    label: &str,
) -> Result<()> {
    let deadline = Instant::now() + OWNER_FENCE_READY_BOUND;
    loop {
        let admission = tokio::time::timeout_at(
            deadline.into(),
            open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!(
                "trust-expiry {label} owner-fence admission deadline exceeded"
            ))
        })?;
        match admission {
            Ok(mut stream) => {
                tokio::time::timeout_at(deadline.into(), stream.close())
                    .await
                    .map_err(|_| {
                        HarnessError::Timeout(format!(
                            "trust-expiry {label} owner-fence probe close deadline exceeded"
                        ))
                    })?
                    .map_err(|error| {
                        HarnessError::Http(format!(
                            "trust-expiry {label} owner-fence probe cleanup failed: {error}"
                        ))
                    })?;
                return Ok(());
            }
            Err(super::StreamConnectFailure::Status { status, body })
                if is_retryable_owner_not_ready(status, body.as_deref()) =>
            {
                let remaining = deadline.saturating_duration_since(Instant::now());
                let Some(retry_after_ms) = retry_after_ms(body.as_deref()) else {
                    return Err(trust_expiry_consumer_failure(
                        cluster,
                        ingress_node,
                        label,
                        super::StreamConnectFailure::Status { status, body },
                    ));
                };
                let delay = Duration::from_millis(retry_after_ms.min(1_000));
                if remaining.is_zero() || delay >= remaining {
                    return Err(HarnessError::Timeout(format!(
                        "trust-expiry {label} owner-fence admission did not become ready within {} ms (status={status}, retry_after_ms={retry_after_ms}); {}",
                        OWNER_FENCE_READY_BOUND.as_millis(),
                        ingress_readiness_context(cluster, ingress_node)
                    )));
                }
                sleep(delay).await;
            }
            Err(error) => {
                return Err(trust_expiry_consumer_failure(
                    cluster,
                    ingress_node,
                    label,
                    error,
                ));
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn open_baseline_consumer_stream(
    cluster: &ProductionCluster,
    ingress_node: &str,
    consumer_addr: std::net::SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: uuid::Uuid,
    service_id: uuid::Uuid,
    label: &str,
) -> Result<ConsumerStream> {
    open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id)
        .await
        .map_err(|error| trust_expiry_consumer_failure(cluster, ingress_node, label, error))
}

fn trust_expiry_consumer_failure(
    cluster: &ProductionCluster,
    ingress_node: &str,
    label: &str,
    error: super::StreamConnectFailure,
) -> HarnessError {
    let context = ingress_readiness_context(cluster, ingress_node);
    match error {
        super::StreamConnectFailure::Status { status, body } => HarnessError::Http(format!(
            "trust-expiry {label} consumer admission returned HTTP status {status} ({}); {context}",
            redacted_admission_metadata(body.as_deref())
        )),
        super::StreamConnectFailure::Harness(error) => HarnessError::Http(format!(
            "trust-expiry {label} consumer admission failed: {error}; {context}"
        )),
    }
}

fn ingress_readiness_context(cluster: &ProductionCluster, ingress_node: &str) -> String {
    let Ok(relay) = cluster.relay(ingress_node) else {
        return format!("ingress_node={ingress_node},relay=<missing>");
    };
    let membership = relay.membership.snapshot();
    let target_record_version = membership
        .memberships
        .iter()
        .find(|record| record.node_id == TARGET_NODE)
        .map(|record| record.record_version);
    let peer_snapshot = relay
        .peer_runtime
        .peer_readiness()
        .map(|readiness| format!("{:?}", readiness.snapshot()))
        .unwrap_or_else(|| "none".to_owned());
    format!(
        "ingress_node={ingress_node},membership_readiness={:?},membership_generation={},target_record_version={target_record_version:?},active_peer_count={},peer_ready={},peer_readiness={peer_snapshot}",
        membership.readiness,
        membership.generation,
        membership.active_peer_count,
        relay.peer_runtime.is_ready(),
    )
}

fn redacted_admission_metadata(body: Option<&[u8]>) -> String {
    let summary = super::redacted_admission_failure(body);
    let Some(body) = body else {
        return format!("{summary},retryable=<missing>,retry_after_ms=<missing>");
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return format!("{summary},retryable=<invalid>,retry_after_ms=<invalid>");
    };
    let retryable = value
        .get("retryable")
        .and_then(serde_json::Value::as_bool)
        .map_or_else(|| "<missing>".to_owned(), |value| value.to_string());
    let retry_after = value
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
        .map_or_else(
            || "<missing>".to_owned(),
            |value| value.min(60_000).to_string(),
        );
    format!("{summary},retryable={retryable},retry_after_ms={retry_after}")
}

fn retry_after_ms(body: Option<&[u8]>) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(body?)
        .ok()?
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
}

fn is_retryable_owner_not_ready(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("code").and_then(serde_json::Value::as_str) == Some("PEER_UNAVAILABLE")
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
        && value.get("retryable").and_then(serde_json::Value::as_bool) == Some(true)
        && value
            .get("retry_after_ms")
            .and_then(serde_json::Value::as_u64)
            == Some(250)
}

fn is_exact_cluster_unready(body: Option<&[u8]>) -> bool {
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("code").and_then(serde_json::Value::as_str) == Some("CLUSTER_UNREADY")
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
}

async fn connect_client(config: tunnel_client::ConnectConfig) -> Result<ConnectionHandle> {
    timeout(
        super::STARTUP_TIMEOUT,
        tunnel_client::connect(ConnectOptions {
            config,
            cancellation: CancellationToken::new(),
            profile: TransportProfile::M2,
        }),
    )
    .await
    .map_err(|_| HarnessError::Timeout("trust-expiry client startup timed out".into()))?
    .map_err(|error| HarnessError::Process(format!("trust-expiry client startup failed: {error}")))
}

async fn wait_ready(client: &mut ConnectionHandle, label: &str) -> Result<()> {
    timeout(super::STARTUP_TIMEOUT, client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout(format!("trust-expiry {label} readiness timed out")))?
        .map(|_| ())
        .map_err(|error| HarnessError::Process(format!("trust-expiry {label} not ready: {error}")))
}

async fn stop_client(client: &ConnectionHandle, label: &str, deadline: Instant) -> Result<()> {
    // ConnectionHandle::stop owns the supervisor join and is cancellation-safe:
    // cancelling this future would only abandon the await while retaining the
    // task for a later caller.  Await the existing contract to completion so
    // the handle is never dropped with an unjoined owner, then report whether
    // the shared cleanup budget was exceeded as evidence.
    let result = client.stop().await;
    let exceeded_deadline = Instant::now() > deadline;
    match result {
        Ok(()) if exceeded_deadline => Err(HarnessError::Timeout(format!(
            "{label} shutdown joined after the cleanup deadline"
        ))),
        Ok(()) => Ok(()),
        Err(error) => Err(HarnessError::Process(format!(
            "{label} shutdown failed: {error}"
        ))),
    }
}
