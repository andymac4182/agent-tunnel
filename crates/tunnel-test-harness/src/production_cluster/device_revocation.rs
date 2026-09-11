//! Staged M7-I06 live device-credential revocation gate.
//!
//! This file is intentionally unreferenced.  It is a source fragment for a
//! child module of `production_cluster.rs`; the caller must provide the
//! expected public 503 code for the selected ingress path.

use super::*;
use tunnel_catalog::OwnerClaim;

const REVOCATION_TIMEOUT: Duration = Duration::from_secs(20);
const REVOCATION_STARTUP_TIMEOUT: Duration = Duration::from_secs(90);
const REVOCATION_POLL: Duration = Duration::from_millis(50);
const MAX_REVOCATION_ERROR_BODY_BYTES: usize = 4 * 1024;
const FANOUT_FORCED_JOIN_GRACE: Duration = Duration::from_secs(2);

/// Payload-free evidence for one live Redis credential-revocation phase.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceRevocationEvidence {
    pub credential_revoked: bool,
    pub existing_stream_terminated: bool,
    pub owner_released: bool,
    pub ingress_rejected: bool,
    pub owner_dispatch_unchanged: bool,
    pub sibling_owner_unchanged: bool,
    pub sibling_stream_survived: bool,
    pub elapsed_ms: u64,
}

pub fn validate_device_revocation_evidence(evidence: &DeviceRevocationEvidence) -> Result<()> {
    let required = [
        ("credential_revoked", evidence.credential_revoked),
        (
            "existing_stream_terminated",
            evidence.existing_stream_terminated,
        ),
        ("owner_released", evidence.owner_released),
        ("ingress_rejected", evidence.ingress_rejected),
        (
            "owner_dispatch_unchanged",
            evidence.owner_dispatch_unchanged,
        ),
        ("sibling_owner_unchanged", evidence.sibling_owner_unchanged),
        ("sibling_stream_survived", evidence.sibling_stream_survived),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "M7-I06 device revocation gate {name} was false"
        )));
    }
    if evidence.elapsed_ms == 0 {
        return Err(HarnessError::Process(
            "M7-I06 device revocation gate reported zero elapsed time".into(),
        ));
    }
    Ok(())
}

/// Borrowed context for one live revocation phase.  Grouping the two device
/// sides and their bounded probe values keeps the production gate's call
/// surface explicit without creating a broad test-only global fixture.
pub(crate) struct DeviceRevocationProbe<'a> {
    pub(crate) cluster: &'a super::ProductionCluster,
    pub(crate) harness: &'a RunningHarness,
    pub(crate) ingress_addr: SocketAddr,
    pub(crate) sibling_stream: &'a mut super::ConsumerStream,
    pub(crate) sibling_owner: &'a OwnerClaim,
    pub(crate) sibling_canary: &'a [u8],
    pub(crate) revoked_stream: &'a mut super::ConsumerStream,
    pub(crate) revoked_owner: &'a OwnerClaim,
    pub(crate) revoked_service_id: Uuid,
    pub(crate) revoked_canary: &'a [u8],
    pub(crate) revoked_spki: &'a str,
    pub(crate) revoked_token: &'a str,
    pub(crate) revoked_client: &'a ConnectionHandle,
    pub(crate) revoked_terminal_observed: &'a mut bool,
}

/// Revoke a live tenant-B credential, observe its owner/session withdrawal,
/// reject a new B ingress with the exact caller-selected typed outcome, and
/// prove an independent tenant-A owner/stream remains usable.
///
/// The standalone fixture deliberately selects relay C as the ingress while
/// tenant B's owner is relay B. After revocation this reaches the remote
/// `NoLiveOwner` mapping, whose exact public response is
/// `PEER_UNTRUSTED`/`not_dispatched` without retry metadata.
pub(crate) async fn verify(
    mut probe: DeviceRevocationProbe<'_>,
) -> Result<DeviceRevocationEvidence> {
    let primary = verify_inner(&mut probe).await;
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;

    // The caller retains the stream and connector handles, so this wrapper
    // closes the revoked consumer stream on both success and failure.  On a
    // primary failure it also joins the connector before returning, avoiding
    // a detached live owner during a failed scenario.
    match primary {
        Ok(evidence) => {
            let stream_cleanup = close_stream_until(
                probe.revoked_stream,
                cleanup_deadline,
                "revoked consumer stream",
            )
            .await;
            match stream_cleanup {
                Ok(()) => Ok(evidence),
                Err(stream_error) => {
                    let connector_cleanup = stop_client_until(
                        probe.revoked_client,
                        cleanup_deadline,
                        "revoked connector",
                        *probe.revoked_terminal_observed,
                    )
                    .await;
                    match connector_cleanup {
                        Ok(()) => Err(stream_error),
                        Err(connector_error) => Err(HarnessError::Process(format!(
                            "revoked stream cleanup failed: {stream_error}; connector cleanup failed: {connector_error}"
                        ))),
                    }
                }
            }
        }
        Err(primary_error) => {
            let connector_cleanup = stop_client_until(
                probe.revoked_client,
                cleanup_deadline,
                "revoked connector",
                *probe.revoked_terminal_observed,
            )
            .await;
            let stream_cleanup = close_stream_until(
                probe.revoked_stream,
                cleanup_deadline,
                "revoked consumer stream",
            )
            .await;
            let mut details = format!("device revocation failed: {primary_error}");
            if let Err(cleanup_error) = stream_cleanup {
                details.push_str(&format!("; revoked stream cleanup failed: {cleanup_error}"));
            }
            if let Err(cleanup_error) = connector_cleanup {
                details.push_str(&format!("; connector cleanup failed: {cleanup_error}"));
            }
            Err(HarnessError::Process(details))
        }
    }
}

async fn verify_inner(probe: &mut DeviceRevocationProbe<'_>) -> Result<DeviceRevocationEvidence> {
    let started = Instant::now();
    let deadline = started + REVOCATION_TIMEOUT;
    let owner_relay = probe.cluster.relay(&probe.revoked_owner.token.node_id)?;
    let baseline = snapshot_with_deadline(owner_relay, deadline, "owner dispatch baseline").await?;
    if baseline.lifetime_application_dispatches == 0 {
        return Err(HarnessError::Process(
            "device revocation phase had no positive owner dispatch baseline".into(),
        ));
    }
    let baseline_dispatches = baseline.lifetime_application_dispatches;

    let credential = timeout(
        bounded_remaining(deadline, "resolving revocation credential")?
            .min(REDIS_PARTITION_OPERATION_TIMEOUT),
        probe
            .cluster
            .catalog
            .resolve_credential(probe.revoked_spki, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("resolving revocation credential timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("resolving revocation credential: {error}")))?
    .ok_or_else(|| {
        HarnessError::Redis("live revocation credential was absent from Redis".into())
    })?;
    if credential.tenant_id != probe.revoked_owner.token.tenant_id
        || credential.device_id != probe.revoked_owner.token.device_id
        || credential.spki_fingerprint != probe.revoked_spki
    {
        return Err(HarnessError::Process(
            "revocation credential scope did not match the live owner".into(),
        ));
    }
    timeout(
        bounded_remaining(deadline, "revoking live credential")?
            .min(REDIS_PARTITION_OPERATION_TIMEOUT),
        probe.cluster.catalog.revoke_credential(
            credential.tenant_id,
            credential.device_id,
            credential.credential_id,
            Utc::now(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("revoking live credential timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("revoking live credential: {error}")))?;
    let credential_revoked = timeout(
        bounded_remaining(deadline, "reading revoked device")?
            .min(REDIS_PARTITION_OPERATION_TIMEOUT),
        probe
            .cluster
            .catalog
            .resolve_device(probe.revoked_spki, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading revoked device timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("reading revoked device: {error}")))?
    .is_none();
    if !credential_revoked {
        return Err(HarnessError::Process(
            "Redis credential revoke did not remove the live device identity".into(),
        ));
    }

    let owner_released = loop {
        let owner = timeout(
            bounded_remaining(deadline, "reading revoked owner")?
                .min(REDIS_PARTITION_OPERATION_TIMEOUT),
            probe.cluster.catalog.current_owner(
                probe.revoked_owner.token.tenant_id,
                probe.revoked_owner.token.device_id,
                Utc::now(),
            ),
        )
        .await
        .map_err(|_| HarnessError::Timeout("reading revoked owner timed out".into()))?
        .map_err(|error| HarnessError::Redis(format!("reading revoked owner: {error}")))?;
        if let Some(current) = owner.as_ref()
            && current.token != probe.revoked_owner.token
        {
            return Err(HarnessError::Process(
                "credential revocation observed an unexpected replacement owner".into(),
            ));
        }
        let status = probe.revoked_client.status_snapshot();
        if owner.is_none() && matches!(status.phase.as_str(), "closed" | "failed") {
            match revocation_terminal_observation(probe.revoked_client) {
                Some(true) => {
                    *probe.revoked_terminal_observed = true;
                    break true;
                }
                Some(false) => {
                    return Err(HarnessError::Process(
                        "credential revocation withdrew the owner without the expected control-read terminal result".into(),
                    ));
                }
                None => {}
            }
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(HarnessError::Timeout(format!(
                "credential revocation did not withdraw owner/client before deadline: phase={}",
                status.phase
            )));
        }
        sleep(REVOCATION_POLL.min(remaining)).await;
    };

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "credential revocation stream probe exceeded its absolute deadline".into(),
        ));
    }
    let existing_stream_terminated = match timeout(
        remaining,
        probe
            .revoked_stream
            .round_trip(b"m7-i06-revoked-existing-stream", probe.revoked_canary),
    )
    .await
    {
        Ok(Err(error)) if super::is_expected_revocation_close(&error) => true,
        Ok(Err(error)) => {
            return Err(HarnessError::Process(format!(
                "revoked existing stream ended with an unclassified bounded error: {error}"
            )));
        }
        Ok(Ok(())) => {
            return Err(HarnessError::Process(
                "revoked existing stream unexpectedly returned an echo".into(),
            ));
        }
        Err(_) => {
            return Err(HarnessError::Timeout(
                "revoked existing stream did not terminate before deadline".into(),
            ));
        }
    };

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "credential revocation ingress probe exceeded its absolute deadline".into(),
        ));
    }
    let ingress_rejected = match timeout(
        remaining,
        super::open_consumer_stream(
            probe.ingress_addr,
            &probe.harness.pki.server_ca.certificate_der,
            probe.revoked_token,
            probe.revoked_owner.token.device_id,
            probe.revoked_service_id,
        ),
    )
    .await
    {
        Ok(Err(super::StreamConnectFailure::Status { status, body }))
            if exact_no_owner_response(status, body.as_deref()) =>
        {
            true
        }
        Ok(Err(super::StreamConnectFailure::Status { status, .. })) => {
            return Err(HarnessError::Http(format!(
                "revoked consumer ingress returned unexpected HTTP status {status}"
            )));
        }
        Ok(Err(super::StreamConnectFailure::Harness(error))) => return Err(error),
        Ok(Ok(mut stream)) => {
            let close_result =
                close_stream_until(&mut stream, deadline, "unexpected ingress").await;
            if let Err(error) = close_result {
                return Err(HarnessError::Process(format!(
                    "revoked consumer ingress unexpectedly upgraded and cleanup failed: {error}"
                )));
            }
            return Err(HarnessError::Process(
                "revoked consumer ingress unexpectedly upgraded".into(),
            ));
        }
        Err(_) => {
            return Err(HarnessError::Timeout(
                "revoked consumer ingress did not return before deadline".into(),
            ));
        }
    };

    let after_ingress =
        snapshot_with_deadline(owner_relay, deadline, "post-ingress dispatch").await?;
    let owner_dispatch_unchanged =
        after_ingress.lifetime_application_dispatches == baseline_dispatches;
    if !owner_dispatch_unchanged {
        return Err(HarnessError::Process(
            "revoked consumer ingress advanced the former owner dispatch counter".into(),
        ));
    }

    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "sibling survival probe exceeded its absolute deadline".into(),
        ));
    }
    timeout(
        remaining,
        probe
            .sibling_stream
            .round_trip(b"m7-i06-sibling-after-revocation", probe.sibling_canary),
    )
    .await
    .map_err(|_| HarnessError::Timeout("sibling survival probe timed out".into()))??;
    let sibling_after = timeout(
        bounded_remaining(deadline, "reading sibling owner")?
            .min(REDIS_PARTITION_OPERATION_TIMEOUT),
        probe.cluster.catalog.current_owner(
            probe.sibling_owner.token.tenant_id,
            probe.sibling_owner.token.device_id,
            Utc::now(),
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("reading sibling owner timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("reading sibling owner: {error}")))?
    .ok_or_else(|| HarnessError::Process("revocation removed the sibling owner".into()))?;
    let sibling_owner_unchanged = sibling_after.token == probe.sibling_owner.token;
    if !sibling_owner_unchanged {
        return Err(HarnessError::Process(
            "revocation changed the independent sibling owner".into(),
        ));
    }
    let sibling_dispatch_check =
        snapshot_with_deadline(owner_relay, deadline, "post-sibling dispatch").await?;
    if sibling_dispatch_check.lifetime_application_dispatches != baseline_dispatches {
        return Err(HarnessError::Process(
            "sibling exchange advanced the revoked owner dispatch counter".into(),
        ));
    }

    Ok(DeviceRevocationEvidence {
        credential_revoked,
        existing_stream_terminated,
        owner_released,
        ingress_rejected,
        owner_dispatch_unchanged,
        sibling_owner_unchanged,
        sibling_stream_survived: true,
        elapsed_ms: u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX),
    })
}

fn bounded_remaining(deadline: Instant, phase: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "device revocation {phase} exceeded its absolute deadline"
        )));
    }
    Ok(remaining)
}

fn startup_remaining(deadline: Instant, phase: &str) -> Result<Duration> {
    Ok(bounded_remaining(deadline, phase)?.min(STARTUP_TIMEOUT))
}

async fn snapshot_with_deadline(
    relay: &super::ProductionRelay,
    deadline: Instant,
    phase: &str,
) -> Result<RelaySnapshot> {
    timeout(bounded_remaining(deadline, phase)?, relay.snapshot())
        .await
        .map_err(|_| HarnessError::Timeout(format!("device revocation {phase} timed out")))?
        .map_err(|error| HarnessError::Process(format!("device revocation {phase}: {error}")))
}

async fn close_stream_until(
    stream: &mut ConsumerStream,
    deadline: Instant,
    label: &str,
) -> Result<()> {
    let started_after_deadline = Instant::now() >= deadline;
    stream
        .close()
        .await
        .map_err(|error| HarnessError::Process(format!("{label} cleanup failed: {error}")))?;
    if started_after_deadline || Instant::now() >= deadline {
        return Err(HarnessError::Timeout(format!(
            "{label} cleanup joined after the shared deadline"
        )));
    }
    Ok(())
}

async fn stop_client_until(
    client: &ConnectionHandle,
    deadline: Instant,
    label: &str,
    allow_expected_revocation_terminal: bool,
) -> Result<()> {
    let started_after_deadline = Instant::now() >= deadline;
    // ConnectionHandle::stop owns the M2 supervisor's nested carrier joins;
    // cancelling this future would leave that join behind, so retain the
    // caller's Option and await the existing cancellation-safe stop directly.
    match client.stop().await {
        Ok(()) => {}
        Err(error) if allow_expected_revocation_terminal => {
            let readiness = client.readiness();
            if !is_expected_revocation_stop(&error, &readiness.borrow()) {
                return Err(HarnessError::Process(format!(
                    "{label} cleanup failed: {error}"
                )));
            }
        }
        Err(error) => {
            return Err(HarnessError::Process(format!(
                "{label} cleanup failed: {error}"
            )));
        }
    }
    if started_after_deadline || Instant::now() >= deadline {
        return Err(HarnessError::Timeout(format!(
            "{label} cleanup joined after the shared deadline"
        )));
    }
    Ok(())
}

fn revocation_terminal_observation(client: &ConnectionHandle) -> Option<bool> {
    let readiness = client.readiness();
    match &*readiness.borrow() {
        tunnel_client::Readiness::Closed { reason } => Some(reason == "control read failed"),
        _ => None,
    }
}

fn is_expected_revocation_stop(
    error: &tunnel_client::ClientError,
    readiness: &tunnel_client::Readiness,
) -> bool {
    matches!(
        error,
        tunnel_client::ClientError::Transport {
            scope: "control read",
            ..
        }
    ) && matches!(
        readiness,
        tunnel_client::Readiness::Closed { reason } if reason == "control read failed"
    )
}

fn exact_no_owner_response(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    if body.len() > MAX_REVOCATION_ERROR_BODY_BYTES {
        return false;
    }
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    if value.get("code").and_then(serde_json::Value::as_str) != Some("PEER_UNTRUSTED")
        || value.get("execution").and_then(serde_json::Value::as_str) != Some("not_dispatched")
    {
        return false;
    }
    value.get("retryable").is_none() && value.get("retry_after_ms").is_none()
}

/// Standalone entry point for the staged gate.  The caller wires this module
/// into `production_cluster.rs`; all Redis, relay, device and consumer
/// resources are then owned by this one bounded run and are joined before the
/// wrapper returns.
pub async fn verify_device_revocation() -> Result<DeviceRevocationEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("device revocation harness startup timed out".into())
        })??;

    let mut cluster = match super::ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
            let cleanup = harness
                .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
                .await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(HarnessError::Process(format!(
                    "device revocation cluster startup failed: {error}; Redis cleanup failed: {cleanup_error}"
                ))),
            };
        }
    };

    // `run_device_revocation` owns every acquired connector/stream handle and
    // runs its own absolute phase budget.  Do not wrap it in a cancellable
    // outer timeout: cancellation there would drop a partially acquired
    // handle before its bounded join path can run.
    let scenario = cluster.run_device_revocation(&harness).await;
    let cleanup_deadline = Instant::now() + CLEANUP_TIMEOUT;
    // Both resource managers remain owned by these cleanup futures. Their
    // task-bearing handles use cancellation-safe deadline joins; no outer
    // timeout may drop a consumed cluster or harness future mid-shutdown.
    let cluster_cleanup = shutdown_cluster_until(cluster, cleanup_deadline).await;
    let harness_cleanup = harness
        .shutdown_until(tokio::time::Instant::from_std(cleanup_deadline))
        .await;

    match scenario {
        Err(error) => match gate_cleanup_error(cluster_cleanup, harness_cleanup) {
            Some(cleanup_error) => Err(HarnessError::Process(format!(
                "device revocation scenario failed: {error}; cleanup failed: {cleanup_error}"
            ))),
            None => Err(error),
        },
        Ok(evidence) => {
            if let Some(cleanup_error) = gate_cleanup_error(cluster_cleanup, harness_cleanup) {
                return Err(cleanup_error);
            }
            validate_device_revocation_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

async fn shutdown_cluster_until(
    mut cluster: super::ProductionCluster,
    deadline: Instant,
) -> Result<()> {
    let tokio_deadline = tokio::time::Instant::from_std(deadline);
    let mut errors = Vec::new();
    if let Err(error) = shutdown_fanout_until(
        &mut cluster.tenant_b_fanout,
        tokio_deadline,
        "tenant-B fanout",
    )
    .await
    {
        errors.push(format!("tenant-B fanout cleanup: {error}"));
    }
    if let Err(error) =
        shutdown_fanout_until(&mut cluster.device_fanout, tokio_deadline, "device fanout").await
    {
        errors.push(format!("device fanout cleanup: {error}"));
    }
    // RunningRelay and UdpFaultProxy own their task joins and have internal
    // abort-and-join bounds. Await them directly so a cancellable outer
    // timeout cannot consume the owner of a still-running task.
    while let Some(relay) = cluster.relays.pop() {
        if let Err(error) = relay.shutdown().await {
            errors.push(format!("relay cleanup: {error}"));
        }
    }
    for (_, mut proxy) in cluster.peer_proxies {
        if let Err(error) = proxy.shutdown().await {
            errors.push(format!("peer proxy cleanup: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(errors.join("; ")))
    }
}

async fn shutdown_fanout_until(
    fanout: &mut super::FanoutProxyHandle,
    graceful_deadline: tokio::time::Instant,
    label: &str,
) -> Result<()> {
    let graceful = fanout.shutdown_until(graceful_deadline).await;
    let Err(graceful_error) = graceful else {
        return Ok(());
    };
    // Keep the handle owned after a failed forced join and give its already
    // cancelled task one final bounded join attempt. If this also fails, the
    // combined error makes the incomplete join observable instead of
    // claiming success.
    let forced_deadline = tokio::time::Instant::now() + FANOUT_FORCED_JOIN_GRACE;
    match fanout.shutdown_until(forced_deadline).await {
        Ok(()) => Err(HarnessError::Process(format!(
            "{label} exceeded its graceful shutdown deadline: {graceful_error}; bounded forced join completed"
        ))),
        Err(forced_error) => {
            let final_deadline = tokio::time::Instant::now() + FANOUT_FORCED_JOIN_GRACE;
            match fanout.shutdown_until(final_deadline).await {
                Ok(()) => Err(HarnessError::Process(format!(
                    "{label} graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join completed"
                ))),
                Err(final_error) => Err(HarnessError::Process(format!(
                    "{label} graceful shutdown failed: {graceful_error}; bounded forced join failed: {forced_error}; final bounded join failed: {final_error}"
                ))),
            }
        }
    }
}

fn gate_cleanup_error(
    cluster_cleanup: Result<()>,
    harness_cleanup: Result<()>,
) -> Option<HarnessError> {
    let mut errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        errors.push(format!("Redis cleanup: {error}"));
    }
    (!errors.is_empty()).then(|| HarnessError::Process(errors.join("; ")))
}

impl super::ProductionCluster {
    /// Run only the live credential-revocation phase.  This intentionally
    /// repeats the small tenant-A/B setup from the broader production gate so
    /// the standalone command does not depend on an earlier command's process
    /// state or on a partially consumed full-gate fixture.
    async fn run_device_revocation(
        &mut self,
        harness: &RunningHarness,
    ) -> Result<DeviceRevocationEvidence> {
        if self.relays.len() != 3 {
            return Err(HarnessError::Process(format!(
                "device revocation started {} relays, expected three",
                self.relays.len()
            )));
        }
        let ready_relays = self
            .relays
            .iter()
            .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
            .count();
        if ready_relays != self.relays.len() {
            return Err(HarnessError::Process(format!(
                "device revocation started with {ready_relays}/{} relays Ready",
                self.relays.len()
            )));
        }

        let relay_b_consumer_addr = self.relay("relay-b")?.consumer_addr()?;
        let relay_c_consumer_addr = self.relay("relay-c")?.consumer_addr()?;
        let device_a = harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant A has no production device".into())
        })?;
        let device_b = harness.topology.devices_b.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant B has no production device".into())
        })?;
        let service_id = *harness
            .topology
            .service_ids
            .get(&device_a.id)
            .ok_or_else(|| HarnessError::InvalidInput("tenant A has no echo service".into()))?;
        let service_b_id = *harness
            .topology
            .service_ids
            .get(&device_b.id)
            .ok_or_else(|| HarnessError::InvalidInput("tenant B has no echo service".into()))?;
        if device_a.tenant_id == device_b.tenant_id {
            return Err(HarnessError::InvalidInput(
                "device revocation fixture did not use distinct tenant scopes".into(),
            ));
        }
        if device_a.id != device_b.id || service_id != service_b_id {
            return Err(HarnessError::InvalidInput(
                "device revocation fixture did not reuse device/service UUIDs".into(),
            ));
        }

        let sibling_canary = format!("m7-i06:tenant-a:{}", device_a.id);
        let revoked_canary = format!("m7-i06:tenant-b:{}", device_b.id);
        let profile_directory = tempdir().map_err(HarnessError::Io)?;
        let revoked_profile_directory = tempdir().map_err(HarnessError::Io)?;
        let mut sibling_client = None;
        let mut revoked_client = None;
        let mut revoked_terminal_observed = false;
        let mut sibling_stream = None;
        let mut revoked_stream = None;
        let mut sibling_owner = None;
        let mut revoked_owner = None;
        let mut sibling_token = String::new();
        let mut revoked_token = String::new();
        let mut revoked_spki = String::new();
        let startup_deadline = Instant::now() + REVOCATION_STARTUP_TIMEOUT;

        let startup = async {
            let mut profile = write_device_profile(
                profile_directory.path(),
                device_a.id,
                service_id,
                &sibling_canary,
                self.device_fanout.local_addr(),
                &device_a.certificate.certificate_pem,
                &device_a.certificate.private_key_pem,
                &harness.pki.server_ca.certificate_pem,
            )?;
            profile.config.rotation = ROTATION;
            profile.config.validate().map_err(|error| {
                HarnessError::InvalidInput(format!("tenant-A client config: {error}"))
            })?;
            let client = timeout(
                startup_remaining(startup_deadline, "tenant-A connector startup")?,
                tunnel_client::connect(ConnectOptions {
                    config: profile.config,
                    cancellation: CancellationToken::new(),
                    profile: TransportProfile::M2,
                }),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-A connector startup timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-A connector failed: {error}"))
            })?;
            sibling_client = Some(client);
            let session = timeout(
                startup_remaining(startup_deadline, "tenant-A connector readiness")?,
                sibling_client
                    .as_mut()
                    .ok_or_else(|| HarnessError::Process("tenant-A handle missing".into()))?
                    .wait_ready(),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-A connector readiness timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-A connector not ready: {error}"))
            })?;
            if session.generation == 0 {
                return Err(HarnessError::Process(
                    "tenant-A connector reported an invalid initial generation".into(),
                ));
            }
            let owner = timeout(
                startup_remaining(startup_deadline, "reading tenant-A owner")?,
                self.catalog
                    .current_owner(device_a.tenant_id, device_a.id, Utc::now()),
            )
            .await
            .map_err(|_| HarnessError::Timeout("reading tenant-A owner timed out".into()))?
            .map_err(|error| HarnessError::Redis(format!("reading tenant-A owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("tenant-A device did not claim an owner".into())
            })?;
            if owner.token.node_id != "relay-a" || owner.token.tenant_id != device_a.tenant_id {
                return Err(HarnessError::Process(format!(
                    "tenant-A owner landed on {} instead of relay-a",
                    owner.token.node_id
                )));
            }
            sibling_owner = Some(owner);
            sibling_token = harness.oidc.issue_with(
                &harness.topology.consumers_a[0].name,
                OidcTokenOptions {
                    expires_in: Duration::from_secs(90),
                    ..OidcTokenOptions::default()
                },
            )?;
            let stream = timeout(
                startup_remaining(startup_deadline, "opening tenant-A consumer stream")?,
                open_consumer_stream(
                    relay_b_consumer_addr,
                    &harness.pki.server_ca.certificate_der,
                    &sibling_token,
                    device_a.id,
                    service_id,
                ),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout("tenant-A consumer stream startup timed out".into())
            })?
            .map_err(connect_failure_to_harness)?;
            sibling_stream = Some(stream);
            timeout(
                startup_remaining(startup_deadline, "tenant-A baseline exchange")?,
                sibling_stream
                    .as_mut()
                    .ok_or_else(|| HarnessError::Process("tenant-A stream missing".into()))?
                    .round_trip(b"m7-i06-baseline-a", sibling_canary.as_bytes()),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-A baseline exchange timed out".into()))??;

            let mut profile_b = write_device_profile(
                revoked_profile_directory.path(),
                device_b.id,
                service_b_id,
                &revoked_canary,
                self.tenant_b_fanout.local_addr(),
                &device_b.certificate.certificate_pem,
                &device_b.certificate.private_key_pem,
                &harness.pki.server_ca.certificate_pem,
            )?;
            profile_b.config.rotation = ROTATION;
            profile_b.config.validate().map_err(|error| {
                HarnessError::InvalidInput(format!("tenant-B client config: {error}"))
            })?;
            revoked_spki = device_b.certificate.spki_fingerprint_sha256()?;
            let client_b = timeout(
                startup_remaining(startup_deadline, "tenant-B connector startup")?,
                tunnel_client::connect(ConnectOptions {
                    config: profile_b.config,
                    cancellation: CancellationToken::new(),
                    profile: TransportProfile::M2,
                }),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B connector startup timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-B connector failed: {error}"))
            })?;
            revoked_client = Some(client_b);
            let session_b = timeout(
                startup_remaining(startup_deadline, "tenant-B connector readiness")?,
                revoked_client
                    .as_mut()
                    .ok_or_else(|| HarnessError::Process("tenant-B handle missing".into()))?
                    .wait_ready(),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B connector readiness timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-B connector not ready: {error}"))
            })?;
            if session_b.generation == 0 {
                return Err(HarnessError::Process(
                    "tenant-B connector reported an invalid initial generation".into(),
                ));
            }
            let owner_b = timeout(
                startup_remaining(startup_deadline, "reading tenant-B owner")?,
                self.catalog
                    .current_owner(device_b.tenant_id, device_b.id, Utc::now()),
            )
            .await
            .map_err(|_| HarnessError::Timeout("reading tenant-B owner timed out".into()))?
            .map_err(|error| HarnessError::Redis(format!("reading tenant-B owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("tenant-B device did not claim an owner".into())
            })?;
            if owner_b.token.node_id != "relay-b" || owner_b.token.tenant_id != device_b.tenant_id {
                return Err(HarnessError::Process(format!(
                    "tenant-B owner landed on {} instead of relay-b",
                    owner_b.token.node_id
                )));
            }
            revoked_owner = Some(owner_b);
            revoked_token = harness.oidc.issue_with(
                &harness.topology.consumers_b[0].name,
                OidcTokenOptions {
                    expires_in: Duration::from_secs(90),
                    ..OidcTokenOptions::default()
                },
            )?;
            let stream_b = timeout(
                startup_remaining(startup_deadline, "opening tenant-B consumer stream")?,
                open_consumer_stream(
                    relay_c_consumer_addr,
                    &harness.pki.server_ca.certificate_der,
                    &revoked_token,
                    device_b.id,
                    service_b_id,
                ),
            )
            .await
            .map_err(|_| {
                HarnessError::Timeout("tenant-B consumer stream startup timed out".into())
            })?
            .map_err(connect_failure_to_harness)?;
            revoked_stream = Some(stream_b);
            timeout(
                startup_remaining(startup_deadline, "tenant-B baseline exchange")?,
                revoked_stream
                    .as_mut()
                    .ok_or_else(|| HarnessError::Process("tenant-B stream missing".into()))?
                    .round_trip(b"m7-i06-baseline-b", revoked_canary.as_bytes()),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B baseline exchange timed out".into()))??;
            timeout(
                startup_remaining(startup_deadline, "tenant-A sibling exchange")?,
                sibling_stream
                    .as_mut()
                    .ok_or_else(|| {
                        HarnessError::Process("tenant-A stream missing after B setup".into())
                    })?
                    .round_trip(
                        b"m7-i06-sibling-before-revocation",
                        sibling_canary.as_bytes(),
                    ),
            )
            .await
            .map_err(|_| HarnessError::Timeout("tenant-A sibling exchange timed out".into()))??;
            Ok::<(), HarnessError>(())
        }
        .await;

        if let Err(error) = startup {
            let cleanup = cleanup_revocation_resources(
                &mut revoked_stream,
                &mut sibling_stream,
                &mut revoked_client,
                &mut sibling_client,
                revoked_terminal_observed,
            )
            .await;
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup_error) => Err(HarnessError::Process(format!(
                    "device revocation setup failed: {error}; cleanup failed: {cleanup_error}"
                ))),
            };
        }

        let phase = match (
            sibling_owner.as_ref(),
            revoked_owner.as_ref(),
            sibling_stream.as_mut(),
            revoked_stream.as_mut(),
            revoked_client.as_ref(),
        ) {
            (
                Some(sibling_owner),
                Some(revoked_owner),
                Some(sibling_stream),
                Some(revoked_stream),
                Some(revoked_client),
            ) => {
                verify(DeviceRevocationProbe {
                    cluster: self,
                    harness,
                    ingress_addr: relay_c_consumer_addr,
                    sibling_stream,
                    sibling_owner,
                    sibling_canary: sibling_canary.as_bytes(),
                    revoked_stream,
                    revoked_owner,
                    revoked_service_id: service_b_id,
                    revoked_canary: revoked_canary.as_bytes(),
                    revoked_spki: &revoked_spki,
                    revoked_token: &revoked_token,
                    revoked_client,
                    revoked_terminal_observed: &mut revoked_terminal_observed,
                })
                .await
            }
            _ => Err(HarnessError::Process(
                "device revocation setup completed without all live handles".into(),
            )),
        };
        let cleanup = cleanup_revocation_resources(
            &mut revoked_stream,
            &mut sibling_stream,
            &mut revoked_client,
            &mut sibling_client,
            revoked_terminal_observed,
        )
        .await;
        match (phase, cleanup) {
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(cleanup_error)) => Err(HarnessError::Process(format!(
                "device revocation failed: {error}; cleanup failed: {cleanup_error}"
            ))),
            (Ok(_), Err(cleanup_error)) => Err(cleanup_error),
            (Ok(evidence), Ok(())) => Ok(evidence),
        }
    }
}

async fn cleanup_revocation_resources(
    revoked_stream: &mut Option<ConsumerStream>,
    sibling_stream: &mut Option<ConsumerStream>,
    revoked_client: &mut Option<ConnectionHandle>,
    sibling_client: &mut Option<ConnectionHandle>,
    revoked_terminal_observed: bool,
) -> Result<()> {
    let mut errors = Vec::new();
    let deadline = Instant::now() + CLEANUP_TIMEOUT;
    // Stop device connectors first so a stalled consumer close cannot retain
    // an owner session for the remainder of the shared cleanup budget.
    if let Some(client) = revoked_client.as_ref()
        && let Err(error) = stop_client_until(
            client,
            deadline,
            "tenant-B revoked connector",
            revoked_terminal_observed,
        )
        .await
    {
        errors.push(error.to_string());
    }
    if let Some(client) = sibling_client.as_ref()
        && let Err(error) =
            stop_client_until(client, deadline, "tenant-A sibling connector", false).await
    {
        errors.push(error.to_string());
    }
    for (label, stream) in [
        ("tenant-B revoked stream", revoked_stream),
        ("tenant-A sibling stream", sibling_stream),
    ] {
        let Some(stream) = stream.as_mut() else {
            continue;
        };
        if let Err(error) = close_stream_until(stream, deadline, label).await {
            errors.push(error.to_string());
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(errors.join("; ")))
    }
}

#[cfg(test)]
mod terminal_cleanup_tests {
    use super::{
        DeviceRevocationEvidence, is_expected_revocation_stop, validate_device_revocation_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;
    use tunnel_client::{ClientError, Readiness};

    #[test]
    fn accepts_only_the_observed_revocation_terminal_result() {
        let expected = ClientError::Transport {
            scope: "control read",
            detail: "control socket closed".to_owned(),
        };
        let closed = Readiness::Closed {
            reason: "control read failed".to_owned(),
        };
        assert!(is_expected_revocation_stop(&expected, &closed));

        let wrong_scope = ClientError::Transport {
            scope: "data read",
            detail: "data socket closed".to_owned(),
        };
        assert!(!is_expected_revocation_stop(&wrong_scope, &closed));
        assert!(!is_expected_revocation_stop(
            &expected,
            &Readiness::Closed {
                reason: "cancelled".to_owned(),
            }
        ));
        assert!(!is_expected_revocation_stop(
            &expected,
            &Readiness::Stopping
        ));
    }

    fn valid_evidence() -> DeviceRevocationEvidence {
        DeviceRevocationEvidence {
            credential_revoked: true,
            existing_stream_terminated: true,
            owner_released: true,
            ingress_rejected: true,
            owner_dispatch_unchanged: true,
            sibling_owner_unchanged: true,
            sibling_stream_survived: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn every_revocation_gate_reaches_the_shared_nonzero_exit_path() {
        type Disable = (&'static str, fn(&mut DeviceRevocationEvidence));
        let gates: [Disable; 7] = [
            ("credential_revoked", |e| e.credential_revoked = false),
            ("existing_stream_terminated", |e| {
                e.existing_stream_terminated = false
            }),
            ("owner_released", |e| e.owner_released = false),
            ("ingress_rejected", |e| e.ingress_rejected = false),
            ("owner_dispatch_unchanged", |e| {
                e.owner_dispatch_unchanged = false
            }),
            ("sibling_owner_unchanged", |e| {
                e.sibling_owner_unchanged = false
            }),
            ("sibling_stream_survived", |e| {
                e.sibling_stream_survived = false
            }),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_device_revocation_evidence(&evidence), name);
        }
        let mut elapsed = valid_evidence();
        elapsed.elapsed_ms = 0;
        assert_rejected(
            validate_device_revocation_evidence(&elapsed),
            "zero elapsed time",
        );
    }
}
