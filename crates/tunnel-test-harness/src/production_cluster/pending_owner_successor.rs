//! Bounded successor-owner admission while the successor is not data-ready.
//!
//! This is a child of `pending_owner`, so it reuses the same TLS device,
//! owner-fence, peer-probe, and backend helpers without widening their public
//! API.  Relay B is deliberately selected as the successor; all post-ready
//! counter assertions therefore use the ordered relay scope `[0, 1, 0]`.
//! Public HTTP body consumption remains outside this proof.

use super::*;
use crate::production_cluster::STARTUP_TIMEOUT;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};

const SUCCESSOR_MAX_RESPONSE_BYTES: usize = 256 * 1024;
type SuccessorHttpConnectionSlot = Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>;

/// Payload-free evidence for a successor owner that is published before its
/// owner-fence and data carrier are ready.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SuccessorPendingOwnerEvidence {
    pub relay_count: usize,
    pub owner_a_token_observed: bool,
    pub owner_a_deployment_matches_fixture: bool,
    pub owner_a_boot_matches_fixture: bool,
    pub owner_a_released: bool,
    pub owner_a_epoch: u64,
    pub owner_b_token_observed: bool,
    pub owner_b_deployment_matches_a: bool,
    pub owner_b_deployment_matches_fixture: bool,
    pub owner_b_session_is_distinct: bool,
    pub owner_b_boot_is_distinct: bool,
    pub owner_b_boot_matches_fixture: bool,
    pub owner_b_node_is_relay_b: bool,
    pub owner_b_epoch: u64,
    pub successor_epoch_higher: bool,
    pub owner_b_control_only: bool,
    pub pre_ready_status: u16,
    pub pre_ready_peer_unavailable: bool,
    pub pre_ready_execution_not_dispatched: bool,
    pub pre_ready_retryable: bool,
    pub pre_ready_retry_after_ms: u64,
    pub pre_ready_dispatch_deltas: [u64; 3],
    pub pre_ready_consumer_chunk_read_deltas: [u64; 3],
    pub pre_ready_wss_status: u16,
    pub pre_ready_wss_upgrade_rejected: bool,
    pub pre_ready_wss_application_body_sent: bool,
    pub pre_ready_wss_peer_unavailable: bool,
    pub pre_ready_wss_execution_not_dispatched: bool,
    pub pre_ready_wss_retryable: bool,
    pub pre_ready_wss_retry_after_ms: u64,
    pub pre_ready_wss_retry_after_header_seconds: u64,
    pub pre_ready_wss_dispatch_deltas: [u64; 3],
    pub pre_ready_wss_consumer_chunk_read_deltas: [u64; 3],
    pub owner_b_token_preserved_before_release: bool,
    pub owner_b_fence_received: bool,
    pub data_attached: bool,
    pub owner_b_token_preserved_after_release: bool,
    pub post_ready_status: u16,
    pub post_ready_canary_matched: bool,
    pub post_ready_dispatch_deltas: [u64; 3],
    pub post_ready_consumer_chunk_read_deltas: [u64; 3],
    pub owner_b_token_preserved_after_post_ready: bool,
    pub cleanup_joined: bool,
}

#[derive(Clone, Copy)]
struct SuccessorIdentityEvidence {
    owner_a_token_observed: bool,
    owner_a_deployment_matches_fixture: bool,
    owner_a_boot_matches_fixture: bool,
    owner_a_released: bool,
    owner_b_token_observed: bool,
    owner_b_deployment_matches_a: bool,
    owner_b_deployment_matches_fixture: bool,
    owner_b_session_is_distinct: bool,
    owner_b_boot_is_distinct: bool,
    owner_b_boot_matches_fixture: bool,
    owner_b_node_is_relay_b: bool,
    successor_epoch_higher: bool,
    owner_b_control_only: bool,
}

const RESOURCE_CLEANUP_TIMEOUT: Duration = Duration::from_secs(90);
const FORCE_JOIN_TIMEOUT: Duration = Duration::from_secs(1);

/// Resources which can outlive the bounded scenario future.
///
/// The outer scenario deadline must cancel only the borrowed future. These
/// slots keep every accepted proxy and backend task available to one explicit
/// bounded cleanup pass, so cancellation cannot fall back to `Drop`'s abort
/// path and lose joined-task evidence.
#[derive(Default)]
struct SuccessorResources {
    barrier_a: Option<SuccessorBarrier>,
    barrier_b: Option<SuccessorBarrier>,
    backend: Option<BackendTask>,
    backend_join_result: Option<bool>,
    http_connections: Vec<SuccessorHttpConnectionSlot>,
}

struct SuccessorBarrier {
    proxy: Option<ProxyHandle>,
    pending: Option<PendingBarrier>,
}

struct SuccessorBContext<'a> {
    cluster: &'a mut super::ProductionCluster,
    harness: &'a HarnessRuntime,
    device: &'a crate::DeviceFixture,
    service_id: Uuid,
    token: &'a str,
    owner_a_epoch: u64,
    owner_b_epoch: u64,
    owner_b: tunnel_catalog::OwnerClaim,
    resources: &'a mut SuccessorResources,
    identity: SuccessorIdentityEvidence,
    scenario_deadline: Instant,
}

impl SuccessorBarrier {
    fn pending_mut(&mut self) -> Result<&mut PendingBarrier> {
        self.pending.as_mut().ok_or_else(|| {
            HarnessError::Process("successor pending-owner barrier setup was incomplete".into())
        })
    }

    async fn release_connection(&mut self) -> Result<()> {
        let pending = self.pending_mut()?;
        let connection_id = pending.connection_id;
        let proxy = pending.proxy.as_ref().ok_or_else(|| {
            HarnessError::Process("successor pending-owner barrier proxy was missing".into())
        })?;
        proxy.close(connection_id).await?;
        pending.control.take();
        pending.paused = false;
        Ok(())
    }
}

impl SuccessorResources {
    async fn cleanup(&mut self) -> Result<()> {
        let deadline = Instant::now() + RESOURCE_CLEANUP_TIMEOUT;
        let mut failure = None;
        for connection in &self.http_connections {
            append_cleanup_result(
                &mut failure,
                "successor pending-owner HTTP connection cleanup",
                join_successor_http_connection(connection, deadline).await,
            );
        }
        if self.backend.is_some() {
            match join_successor_backend(
                self.backend.as_mut().expect("backend is retained"),
                deadline,
            )
            .await
            {
                Ok(value) => {
                    self.backend_join_result = Some(value);
                    self.backend = None;
                }
                Err(error) => append_failure(
                    &mut failure,
                    "successor pending-owner backend cleanup",
                    error,
                ),
            }
        }
        if let Some(barrier) = self.barrier_b.as_mut() {
            let result = close_successor_barrier(barrier, deadline).await;
            if result.is_ok() {
                self.barrier_b = None;
            }
            append_cleanup_result(
                &mut failure,
                "successor pending-owner B barrier cleanup",
                result,
            );
        }
        if let Some(barrier) = self.barrier_a.as_mut() {
            let result = close_successor_barrier(barrier, deadline).await;
            if result.is_ok() {
                self.barrier_a = None;
            }
            append_cleanup_result(
                &mut failure,
                "successor pending-owner A barrier cleanup",
                result,
            );
        }
        match failure {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

fn append_cleanup_result(failure: &mut Option<HarnessError>, label: &str, result: Result<()>) {
    if let Err(error) = result {
        append_failure(failure, label, error);
    }
}

async fn close_successor_barrier(barrier: &mut SuccessorBarrier, deadline: Instant) -> Result<()> {
    if let Some(pending) = barrier.pending.as_mut() {
        close_successor_pending(pending, deadline).await?;
        barrier.pending = None;
        return Ok(());
    }
    if let Some(proxy) = barrier.proxy.as_mut() {
        proxy.shutdown_until(deadline).await?;
        barrier.proxy = None;
    }
    Ok(())
}

async fn close_successor_pending(pending: &mut PendingBarrier, deadline: Instant) -> Result<()> {
    let mut first_error = None;
    if pending.paused
        && let Some(proxy) = pending.proxy.as_ref()
    {
        match timeout_at(
            deadline,
            proxy.resume(Direction::TargetToClient, pending.connection_id),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => first_error = Some(error),
            Err(_) => {
                first_error = Some(HarnessError::Timeout(
                    "successor pending-owner barrier resume timed out".into(),
                ));
            }
        }
    }
    pending.paused = false;
    drop(pending.control.take());
    if let Some(proxy) = pending.proxy.as_mut() {
        let result = proxy.shutdown_until(deadline).await;
        match result {
            Ok(()) => {
                pending.proxy = None;
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    match first_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

async fn join_successor_backend(backend: &mut BackendTask, deadline: Instant) -> Result<bool> {
    if let Some(cancel) = backend.cancel.take() {
        let _ = cancel.send(());
    }
    let (joined, forced) = {
        let task = backend.task.as_mut().ok_or_else(|| {
            HarnessError::Process("successor pending-owner backend task was already joined".into())
        })?;
        match timeout_at(deadline, &mut *task).await {
            Ok(result) => (Some(result), false),
            Err(_) => {
                task.abort();
                match timeout(FORCE_JOIN_TIMEOUT, &mut *task).await {
                    Ok(result) => (Some(result), true),
                    Err(_) => (None, true),
                }
            }
        }
    };
    let Some(joined) = joined else {
        return Err(HarnessError::Timeout(
            "successor pending-owner backend did not join after forced abort".into(),
        ));
    };
    backend.task.take();
    if forced {
        return match joined {
            Ok(_) => Err(HarnessError::Timeout(
                "successor pending-owner backend required forced abort cleanup".into(),
            )),
            Err(error) => Err(HarnessError::Process(format!(
                "successor pending-owner backend forced abort join failed: {error}"
            ))),
        };
    }
    let task_result = match joined {
        Ok(Ok(result)) => result,
        Ok(Err(error)) => {
            return Err(HarnessError::Process(format!(
                "successor pending-owner backend task failed: {error}"
            )));
        }
        Err(error) => {
            return Err(HarnessError::Process(format!(
                "successor pending-owner backend task join failed: {error}"
            )));
        }
    };
    let response_attempted = backend.response_attempted.take().ok_or_else(|| {
        HarnessError::Process("successor pending-owner response signal was already consumed".into())
    })?;
    match timeout_at(deadline, response_attempted).await {
        Ok(Ok(())) => Ok(task_result),
        Ok(Err(_)) => Ok(false),
        Err(_) => Err(HarnessError::Timeout(
            "successor pending-owner response-attempt signal exceeded cleanup deadline".into(),
        )),
    }
}

/// Open a barrier while publishing its proxy into the external resource slot
/// before any socket/setup await.  If setup is cancelled, cleanup can still
/// shut down the accepted proxy rather than relying on `Drop`.
async fn start_successor_barrier(
    slot: &mut Option<SuccessorBarrier>,
    target_addr: SocketAddr,
    tls: Arc<ClientConfig>,
    device_id: Uuid,
    service_id: Uuid,
    rotation: RotationConfig,
) -> Result<()> {
    if slot.is_some() {
        return Err(HarnessError::Process(
            "successor pending-owner barrier slot was already occupied".into(),
        ));
    }
    let proxy = TcpProxy::bind(target_addr, ProxyConfig::default()).await?;
    let local_addr = proxy.local_addr();
    *slot = Some(SuccessorBarrier {
        proxy: Some(proxy),
        pending: None,
    });

    let control_url = format!("wss://localhost:{}/v1/tunnel/control", local_addr.port());
    let hello = hello_message(device_id, service_id, rotation);
    let hello_message_id = match &hello {
        ControlMessage::Hello(hello) => hello.message_id.clone(),
        _ => unreachable!("hello_message always returns HELLO"),
    };
    let control =
        open_device_socket(&control_url, Arc::clone(&tls), CONTROL_SUBPROTOCOL, None).await?;

    // Move the already-owned proxy into the pending barrier synchronously,
    // leaving the slot populated before the next await.
    let resource = slot.as_mut().ok_or_else(|| {
        HarnessError::Process("successor pending-owner barrier slot disappeared".into())
    })?;
    let proxy = resource.proxy.take().ok_or_else(|| {
        HarnessError::Process("successor pending-owner barrier proxy was lost".into())
    })?;
    resource.pending = Some(PendingBarrier {
        proxy: Some(proxy),
        connection_id: ConnectionId::new(0),
        paused: false,
        control: Some(control),
        tls,
        hello_message_id,
    });
    let pending = resource.pending_mut()?;
    let connection_id = pending.wait_for_connection().await?;
    pending.connection_id = connection_id;
    pending.pause().await?;
    send_control(
        pending
            .control
            .as_mut()
            .expect("successor barrier control socket is retained"),
        &hello,
    )
    .await
}

/// Validate the complete successor-owner evidence contract.
pub fn validate_successor_pending_owner_evidence(
    evidence: &SuccessorPendingOwnerEvidence,
) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "successor pending-owner admission requires three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        ("owner_a_token_observed", evidence.owner_a_token_observed),
        (
            "owner_a_deployment_matches_fixture",
            evidence.owner_a_deployment_matches_fixture,
        ),
        (
            "owner_a_boot_matches_fixture",
            evidence.owner_a_boot_matches_fixture,
        ),
        ("owner_a_released", evidence.owner_a_released),
        ("owner_b_token_observed", evidence.owner_b_token_observed),
        (
            "owner_b_deployment_matches_a",
            evidence.owner_b_deployment_matches_a,
        ),
        (
            "owner_b_deployment_matches_fixture",
            evidence.owner_b_deployment_matches_fixture,
        ),
        (
            "owner_b_session_is_distinct",
            evidence.owner_b_session_is_distinct,
        ),
        (
            "owner_b_boot_is_distinct",
            evidence.owner_b_boot_is_distinct,
        ),
        (
            "owner_b_boot_matches_fixture",
            evidence.owner_b_boot_matches_fixture,
        ),
        ("owner_b_node_is_relay_b", evidence.owner_b_node_is_relay_b),
        ("successor_epoch_higher", evidence.successor_epoch_higher),
        ("owner_b_control_only", evidence.owner_b_control_only),
        (
            "pre_ready_peer_unavailable",
            evidence.pre_ready_peer_unavailable,
        ),
        (
            "pre_ready_execution_not_dispatched",
            evidence.pre_ready_execution_not_dispatched,
        ),
        ("pre_ready_retryable", evidence.pre_ready_retryable),
        (
            "pre_ready_wss_upgrade_rejected",
            evidence.pre_ready_wss_upgrade_rejected,
        ),
        (
            "pre_ready_wss_application_body_not_sent",
            !evidence.pre_ready_wss_application_body_sent,
        ),
        (
            "pre_ready_wss_peer_unavailable",
            evidence.pre_ready_wss_peer_unavailable,
        ),
        (
            "pre_ready_wss_execution_not_dispatched",
            evidence.pre_ready_wss_execution_not_dispatched,
        ),
        ("pre_ready_wss_retryable", evidence.pre_ready_wss_retryable),
        (
            "owner_b_token_preserved_before_release",
            evidence.owner_b_token_preserved_before_release,
        ),
        ("owner_b_fence_received", evidence.owner_b_fence_received),
        ("data_attached", evidence.data_attached),
        (
            "owner_b_token_preserved_after_release",
            evidence.owner_b_token_preserved_after_release,
        ),
        (
            "owner_b_token_preserved_after_post_ready",
            evidence.owner_b_token_preserved_after_post_ready,
        ),
        (
            "post_ready_canary_matched",
            evidence.post_ready_canary_matched,
        ),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, value)| !value) {
        return Err(HarnessError::Process(format!(
            "successor pending-owner required gate {name} was false"
        )));
    }
    if evidence.owner_b_epoch <= evidence.owner_a_epoch {
        return Err(HarnessError::Process(format!(
            "successor pending-owner epoch did not increase: old={}, successor={}",
            evidence.owner_a_epoch, evidence.owner_b_epoch
        )));
    }
    if evidence.pre_ready_status != 503
        || evidence.pre_ready_wss_status != 503
        || evidence.post_ready_status != 200
    {
        return Err(HarnessError::Process(format!(
            "successor pending-owner statuses were HTTPS={}, WSS={}, post-ready={}, expected 503/503/200",
            evidence.pre_ready_status, evidence.pre_ready_wss_status, evidence.post_ready_status
        )));
    }
    if evidence.pre_ready_retry_after_ms != EXPECTED_RETRY_AFTER_MS
        || evidence.pre_ready_wss_retry_after_ms != EXPECTED_RETRY_AFTER_MS
        || evidence.pre_ready_wss_retry_after_header_seconds != EXPECTED_RETRY_AFTER_SECONDS
    {
        return Err(HarnessError::Process(
            "successor pending-owner retry metadata was not exact".into(),
        ));
    }
    if evidence.pre_ready_dispatch_deltas != [0, 0, 0]
        || evidence.pre_ready_consumer_chunk_read_deltas != [0, 0, 0]
        || evidence.pre_ready_wss_dispatch_deltas != [0, 0, 0]
        || evidence.pre_ready_wss_consumer_chunk_read_deltas != [0, 0, 0]
    {
        return Err(HarnessError::Process(
            "successor pending-owner pre-ready counters advanced".into(),
        ));
    }
    if evidence.post_ready_dispatch_deltas != [0, 1, 0]
        || evidence.post_ready_consumer_chunk_read_deltas != [0, 1, 0]
    {
        return Err(HarnessError::Process(format!(
            "successor pending-owner post-ready scope was dispatch={:?}, owner_reads={:?}, expected relay-b only",
            evidence.post_ready_dispatch_deltas, evidence.post_ready_consumer_chunk_read_deltas
        )));
    }
    Ok(())
}

/// Run the bounded successor-owner admission gate.
pub async fn verify() -> Result<SuccessorPendingOwnerEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(PENDING_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("successor pending-owner harness startup timed out".into())
        })??;

    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let harness_cleanup = harness.shutdown().await;
            return match harness_cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(combine_failures(
                    error,
                    "successor pending-owner catalog cleanup",
                    cleanup,
                )),
            };
        }
    };
    let mut resources = SuccessorResources::default();
    let scenario = {
        let scenario_future = run_successor_pending_owner(&mut cluster, &harness, &mut resources);
        tokio::pin!(scenario_future);
        match timeout(SCENARIO_TIMEOUT, &mut scenario_future).await {
            Ok(result) => result,
            Err(_) => Err(HarnessError::Timeout(
                "successor pending-owner scenario exceeded its bounded deadline".into(),
            )),
        }
    };
    // Resource cleanup owns one absolute deadline and its own forced
    // abort-and-join pass.  Do not wrap it in another timeout: cancellation
    // here would drop the remaining Arc<Mutex<JoinHandle>> slots and detach
    // the HTTP tasks that the evidence requires us to join.
    let resource_cleanup = resources.cleanup().await;
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    if let Err(error) = cluster_cleanup {
        append_failure(&mut failure, "successor pending-owner relay cleanup", error);
    }
    if let Err(error) = resource_cleanup {
        append_failure(
            &mut failure,
            "successor pending-owner resource cleanup",
            error,
        );
    }
    if let Err(error) = harness_cleanup {
        append_failure(
            &mut failure,
            "successor pending-owner catalog cleanup",
            error,
        );
    }
    if evidence.is_some() {
        match resources.backend_join_result {
            Some(true) => {}
            Some(false) => append_failure(
                &mut failure,
                "successor pending-owner backend completion",
                HarnessError::Process(
                    "successor pending-owner backend did not complete a response".into(),
                ),
            ),
            None => append_failure(
                &mut failure,
                "successor pending-owner backend completion",
                HarnessError::Process(
                    "successor pending-owner backend join evidence was missing".into(),
                ),
            ),
        }
    }
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_successor_pending_owner_evidence(evidence)
        {
            append_failure(
                &mut failure,
                "successor pending-owner evidence validation",
                error,
            );
            evidence.cleanup_joined = false;
        }
    }

    match (evidence.take(), failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "successor pending-owner scenario produced no evidence or failure".into(),
        )),
    }
}

async fn run_successor_pending_owner(
    cluster: &mut super::ProductionCluster,
    harness: &HarnessRuntime,
    resources: &mut SuccessorResources,
) -> Result<SuccessorPendingOwnerEvidence> {
    let scenario_deadline = Instant::now() + SCENARIO_TIMEOUT;
    let device = harness.topology.devices_a.first().ok_or_else(|| {
        HarnessError::InvalidInput("successor pending-owner device missing".into())
    })?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("successor pending-owner service missing".into())
        })?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    let expected_deployment_incarnation = cluster.fixture.deployment_incarnation.clone();
    let expected_a_boot_id = cluster
        .fixture
        .node("relay-a")
        .ok_or_else(|| HarnessError::InvalidInput("successor fixture relay-a missing".into()))?
        .boot_id
        .clone();
    let expected_b_boot_id = cluster
        .fixture
        .node("relay-b")
        .ok_or_else(|| HarnessError::InvalidInput("successor fixture relay-b missing".into()))?
        .boot_id
        .clone();
    let rotation = PENDING_ROTATION;
    start_successor_barrier(
        &mut resources.barrier_a,
        relay_device_addr(cluster, "relay-a")?,
        device_tls(harness, device)?,
        device.id,
        service_id,
        rotation.clone(),
    )
    .await?;
    let owner_a = wait_for_owner_until(
        cluster,
        device.tenant_id,
        device.id,
        "relay-a",
        scenario_deadline,
    )
    .await?;
    let owner_a_token_observed =
        owner_token_is_exact_for_device(&owner_a.token, device.tenant_id, device.id, "relay-a");
    let owner_a_deployment_matches_fixture =
        owner_a.token.deployment_incarnation == expected_deployment_incarnation;
    let owner_a_boot_matches_fixture = owner_a.token.boot_id == expected_a_boot_id;
    if !owner_a_token_observed
        || !owner_a_deployment_matches_fixture
        || !owner_a_boot_matches_fixture
    {
        return Err(HarnessError::Process(
            "successor pending-owner A catalog token or fixture membership was incomplete or mismatched".into(),
        ));
    }
    let owner_a_control_only = wait_for_control_only_exact(
        cluster,
        device.id,
        &owner_a.token,
        "relay-a",
        scenario_deadline,
    )
    .await?;
    if !owner_a_control_only {
        return Err(HarnessError::Process(
            "successor pending-owner A control-only state was not observed".into(),
        ));
    }
    let barrier_a = resources.barrier_a.as_mut().ok_or_else(|| {
        HarnessError::Process("successor pending-owner A barrier was not retained".into())
    })?;
    barrier_a.release_connection().await?;
    let owner_a_released =
        wait_for_owner_absent_until(cluster, device.tenant_id, device.id, scenario_deadline)
            .await?;
    if !owner_a_released {
        return Err(HarnessError::Process(
            "successor pending-owner A owner was not absent after barrier release".into(),
        ));
    }

    start_successor_barrier(
        &mut resources.barrier_b,
        relay_device_addr(cluster, "relay-b")?,
        device_tls(harness, device)?,
        device.id,
        service_id,
        rotation,
    )
    .await?;
    let owner_b = wait_for_owner_until(
        cluster,
        device.tenant_id,
        device.id,
        "relay-b",
        scenario_deadline,
    )
    .await?;
    let owner_b_token_observed =
        owner_token_is_exact_for_device(&owner_b.token, device.tenant_id, device.id, "relay-b");
    let owner_b_deployment_matches_a =
        owner_b.token.deployment_incarnation == owner_a.token.deployment_incarnation;
    let owner_b_deployment_matches_fixture =
        owner_b.token.deployment_incarnation == expected_deployment_incarnation;
    let owner_b_session_is_distinct = owner_b.token.session_id != owner_a.token.session_id;
    let owner_b_boot_is_distinct = owner_b.token.boot_id != owner_a.token.boot_id;
    let owner_b_boot_matches_fixture = owner_b.token.boot_id == expected_b_boot_id;
    let owner_b_node_is_relay_b = owner_b.token.node_id == "relay-b";
    let successor_epoch_higher = owner_b.token.epoch > owner_a.token.epoch;
    if !owner_b_token_observed
        || !owner_b_deployment_matches_a
        || !owner_b_deployment_matches_fixture
        || !owner_b_session_is_distinct
        || !owner_b_boot_is_distinct
        || !owner_b_boot_matches_fixture
        || !owner_b_node_is_relay_b
        || !successor_epoch_higher
    {
        return Err(HarnessError::Process(format!(
            "successor pending-owner transition identity was not exact: old_node={}, old_epoch={}, old_session={}, old_boot={}, new_node={}, new_epoch={}, new_session={}, new_boot={}",
            owner_a.token.node_id,
            owner_a.token.epoch,
            owner_a.token.session_id,
            owner_a.token.boot_id,
            owner_b.token.node_id,
            owner_b.token.epoch,
            owner_b.token.session_id,
            owner_b.token.boot_id
        )));
    }
    let owner_b_control_only = match wait_for_control_only_exact(
        cluster,
        device.id,
        &owner_b.token,
        "relay-b",
        scenario_deadline,
    )
    .await
    {
        Ok(control_only) => control_only,
        Err(error) => return Err(error),
    };
    if !owner_b_control_only {
        return Err(HarnessError::Process(
            "successor pending-owner B control-only state was not observed".into(),
        ));
    }
    run_successor_b_phase(SuccessorBContext {
        cluster,
        harness,
        device,
        service_id,
        token: &token,
        owner_a_epoch: owner_a.token.epoch,
        owner_b_epoch: owner_b.token.epoch,
        owner_b,
        resources,
        identity: SuccessorIdentityEvidence {
            owner_a_token_observed,
            owner_a_deployment_matches_fixture,
            owner_a_boot_matches_fixture,
            owner_a_released,
            owner_b_token_observed,
            owner_b_deployment_matches_a,
            owner_b_deployment_matches_fixture,
            owner_b_session_is_distinct,
            owner_b_boot_is_distinct,
            owner_b_boot_matches_fixture,
            owner_b_node_is_relay_b,
            successor_epoch_higher,
            owner_b_control_only,
        },
        scenario_deadline,
    })
    .await
}

/// Complete the M2 handshake while checking the complete catalog owner
/// identity before sending OWNER_FENCED.  The shared helper is intentionally
/// not used here because it acknowledges a WELCOME before a successor-specific
/// catalog comparison can be made.
async fn finish_successor_handshake_exact(
    barrier: &mut PendingBarrier,
    expected_owner: &OwnerToken,
    deadline: Instant,
) -> Result<(Welcome, DeviceSocket, bool)> {
    let hello_message_id = barrier.hello_message_id.clone();
    let proxy_addr = barrier
        .proxy
        .as_ref()
        .ok_or_else(|| HarnessError::Process("successor barrier proxy was consumed".into()))?
        .local_addr();
    let tls = Arc::clone(&barrier.tls);
    let control = barrier
        .control
        .as_mut()
        .ok_or_else(|| HarnessError::Process("successor barrier control was consumed".into()))?;
    let welcome = match next_control(
        control,
        min_deadline(deadline, Instant::now() + BARRIER_TIMEOUT),
    )
    .await?
    {
        ControlMessage::Welcome(welcome) => welcome,
        _ => {
            return Err(HarnessError::Http(
                "successor pending-owner control did not return WELCOME".into(),
            ));
        }
    };
    let expected_owner_id = owner_digest(expected_owner);
    if welcome.protocol_major != PROTOCOL_MAJOR
        || welcome.protocol_minor != PROTOCOL_MINOR
        || welcome.reply_to != hello_message_id
        || welcome.session_id != expected_owner.session_id
        || welcome.epoch != expected_owner.epoch
        || welcome.connection_id.is_empty()
        || welcome.attachment_ticket.is_empty()
        || welcome.generation != 1
        || welcome.owner_id.as_deref() != Some(expected_owner_id.as_str())
        || !welcome
            .supported_features
            .iter()
            .any(|feature| feature == "ordered-rotation-v1")
        || !welcome
            .supported_features
            .iter()
            .any(|feature| feature == "owner-fencing-v1")
    {
        return Err(HarnessError::Http(
            "successor pending-owner WELCOME did not match the complete catalog owner identity"
                .into(),
        ));
    }

    let fence = match next_control(
        control,
        min_deadline(deadline, Instant::now() + BARRIER_TIMEOUT),
    )
    .await?
    {
        ControlMessage::OwnerFence(fence) => fence,
        _ => {
            return Err(HarnessError::Http(
                "successor pending-owner control did not return OWNER_FENCE".into(),
            ));
        }
    };
    fence.validate().map_err(|error| {
        HarnessError::Http(format!("successor pending-owner OWNER_FENCE: {error}"))
    })?;
    let owner_fence_received = fence.session_id == welcome.session_id
        && fence.epoch == welcome.epoch
        && fence.owner_id == expected_owner_id;
    if !owner_fence_received {
        return Err(HarnessError::Http(
            "successor pending-owner OWNER_FENCE did not match the exact WELCOME owner".into(),
        ));
    }
    timeout_at(
        deadline,
        send_control(
            control,
            &ControlMessage::OwnerFenced(OwnerFenced::from_fence(
                Uuid::new_v4().to_string(),
                &fence,
            )),
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("successor pending-owner OWNER_FENCED send timed out".into())
    })??;

    let data_url = format!("wss://localhost:{}/v1/tunnel/data", proxy_addr.port());
    let data = timeout_at(
        deadline,
        open_device_socket(
            &data_url,
            tls,
            DATA_SUBPROTOCOL,
            Some(&welcome.attachment_ticket),
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("successor pending-owner data handshake timed out".into())
    })??;
    loop {
        match next_control(
            control,
            min_deadline(deadline, Instant::now() + BARRIER_TIMEOUT),
        )
        .await?
        {
            ControlMessage::DataReady(ready) => {
                ready
                    .validate_context(
                        &welcome.session_id,
                        welcome.epoch,
                        welcome.generation,
                        &welcome.connection_id,
                    )
                    .map_err(|error| {
                        HarnessError::Http(format!("successor pending-owner DATA_READY: {error}"))
                    })?;
                if ready.reply_to != welcome.message_id {
                    return Err(HarnessError::Http(
                        "successor pending-owner DATA_READY reply did not match WELCOME".into(),
                    ));
                }
                return Ok((welcome, data, owner_fence_received));
            }
            ControlMessage::Ping(ping) => {
                timeout_at(
                    deadline,
                    send_control(
                        control,
                        &ControlMessage::Pong(tunnel_protocol::Pong::new(
                            Uuid::new_v4().to_string(),
                            ping.message_id,
                            ping.session_id,
                            ping.epoch,
                            ping.nonce,
                        )),
                    ),
                )
                .await
                .map_err(|_| {
                    HarnessError::Timeout("successor pending-owner PONG timed out".into())
                })??;
            }
            _ => {}
        }
    }
}

async fn run_successor_b_phase(
    context: SuccessorBContext<'_>,
) -> Result<SuccessorPendingOwnerEvidence> {
    let SuccessorBContext {
        cluster,
        harness,
        device,
        service_id,
        token,
        owner_a_epoch,
        owner_b_epoch,
        owner_b,
        resources,
        identity,
        scenario_deadline,
    } = context;
    let SuccessorIdentityEvidence {
        owner_a_token_observed,
        owner_a_deployment_matches_fixture,
        owner_a_boot_matches_fixture,
        owner_a_released,
        owner_b_token_observed,
        owner_b_deployment_matches_a,
        owner_b_deployment_matches_fixture,
        owner_b_session_is_distinct,
        owner_b_boot_is_distinct,
        owner_b_boot_matches_fixture,
        owner_b_node_is_relay_b,
        successor_epoch_higher,
        owner_b_control_only,
    } = identity;
    let ingress_consumer_addr = cluster.relay("relay-c")?.consumer_addr()?;
    let held_phase_deadline = Instant::now() + HELD_PHASE_TIMEOUT;
    let wss_dispatch_before = dispatch_counters(cluster).await?;
    let wss_reads_before = consumer_chunk_read_counters(cluster).await?;
    let pre_ready_wss = timeout_at(
        min_deadline(held_phase_deadline, scenario_deadline),
        open_pending_owner_wss(
            ingress_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            device.id,
            service_id,
            held_phase_deadline,
        ),
    )
    .await
    .map_err(|_| {
        HarnessError::Timeout("successor pending-owner WSS probe exceeded its bound".into())
    })??;
    let pre_ready_wss_json = parse_wss_error_body(&pre_ready_wss.body)?;
    let pre_ready_wss_peer_unavailable = pre_ready_wss.status == 503
        && pre_ready_wss_json
            .get("code")
            .and_then(serde_json::Value::as_str)
            == Some("PEER_UNAVAILABLE");
    let pre_ready_wss_execution_not_dispatched = pre_ready_wss_peer_unavailable
        && pre_ready_wss_json
            .get("execution")
            .and_then(serde_json::Value::as_str)
            == Some("not_dispatched");
    let pre_ready_wss_retryable = pre_ready_wss_execution_not_dispatched
        && pre_ready_wss_json
            .get("retryable")
            .and_then(serde_json::Value::as_bool)
            == Some(true);
    let pre_ready_wss_retry_after_ms = pre_ready_wss_json
        .get("retry_after_ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or_default();
    let pre_ready_wss_retry_after_header_seconds =
        pre_ready_wss.retry_after_header_seconds.unwrap_or_default();
    if !pre_ready_wss.rejected_before_upgrade
        || pre_ready_wss.application_body_sent
        || !pre_ready_wss_peer_unavailable
        || !pre_ready_wss_execution_not_dispatched
        || !pre_ready_wss_retryable
        || pre_ready_wss_retry_after_ms != EXPECTED_RETRY_AFTER_MS
        || pre_ready_wss_retry_after_header_seconds != EXPECTED_RETRY_AFTER_SECONDS
    {
        return Err(HarnessError::Process(
            "successor pending-owner WSS did not reject before upgrade with exact retry metadata"
                .into(),
        ));
    }
    let pre_ready_wss_dispatch_deltas =
        subtract_counters(dispatch_counters(cluster).await?, wss_dispatch_before);
    let pre_ready_wss_consumer_chunk_read_deltas = subtract_counters(
        consumer_chunk_read_counters(cluster).await?,
        wss_reads_before,
    );
    if pre_ready_wss_dispatch_deltas != [0, 0, 0]
        || pre_ready_wss_consumer_chunk_read_deltas != [0, 0, 0]
    {
        return Err(HarnessError::Process(
            "successor pending-owner pre-ready WSS advanced owner counters".into(),
        ));
    }

    let dispatch_before = dispatch_counters(cluster).await?;
    let reads_before = consumer_chunk_read_counters(cluster).await?;
    let pre_ready = successor_public_echo(SuccessorHttpRequest {
        resources,
        consumer_addr: ingress_consumer_addr,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token,
        device_id: device.id,
        service_id,
        body: REQUEST_BODY,
        deadline: min_deadline(held_phase_deadline, scenario_deadline),
    })
    .await?;
    let pre_ready_peer_unavailable =
        pre_ready.status == 503 && error_code(&pre_ready).as_deref() == Some("PEER_UNAVAILABLE");
    let pre_ready_execution_not_dispatched =
        pre_ready_peer_unavailable && response_execution_not_dispatched(&pre_ready);
    let pre_ready_retryable = pre_ready_execution_not_dispatched && response_retryable(&pre_ready);
    let pre_ready_retry_after_ms = response_retry_after_ms(&pre_ready).unwrap_or_default();
    if !pre_ready_peer_unavailable
        || !pre_ready_execution_not_dispatched
        || !pre_ready_retryable
        || pre_ready_retry_after_ms != EXPECTED_RETRY_AFTER_MS
    {
        return Err(HarnessError::Process(
            "successor pending-owner HTTPS did not return exact not-dispatched retry metadata"
                .into(),
        ));
    }
    let pre_ready_dispatch_deltas =
        subtract_counters(dispatch_counters(cluster).await?, dispatch_before);
    let pre_ready_consumer_chunk_read_deltas =
        subtract_counters(consumer_chunk_read_counters(cluster).await?, reads_before);
    if pre_ready_dispatch_deltas != [0, 0, 0] || pre_ready_consumer_chunk_read_deltas != [0, 0, 0] {
        return Err(HarnessError::Process(
            "successor pending-owner pre-ready HTTPS advanced owner counters".into(),
        ));
    }
    let owner_b_before_release =
        current_owner_until(cluster, device.tenant_id, device.id, scenario_deadline).await?;
    let owner_b_token_preserved_before_release = owner_b_before_release
        .as_ref()
        .is_some_and(|claim| claim.token == owner_b.token);
    if !owner_b_token_preserved_before_release {
        return Err(HarnessError::Process(
            "successor pending-owner B token changed while readiness was held".into(),
        ));
    }

    let (welcome, data, owner_b_fence_received) = {
        let barrier_b = resources.barrier_b.as_mut().ok_or_else(|| {
            HarnessError::Process("successor pending-owner B barrier was not retained".into())
        })?;
        let pending = barrier_b.pending_mut()?;
        pending.resume().await?;
        finish_successor_handshake_exact(pending, &owner_b.token, scenario_deadline).await?
    };
    let data_attached =
        wait_for_data_attached(cluster, device.id, owner_b.token.epoch, "relay-b").await?;
    let owner_b_after_release =
        current_owner_until(cluster, device.tenant_id, device.id, scenario_deadline).await?;
    let owner_b_token_preserved_after_release = owner_b_after_release
        .as_ref()
        .is_some_and(|claim| claim.token == owner_b.token);
    if !owner_b_token_preserved_after_release {
        return Err(HarnessError::Process(
            "successor pending-owner B token changed after DATA_READY".into(),
        ));
    }

    let post_ready_dispatch_before = dispatch_counters(cluster).await?;
    let post_ready_reads_before = consumer_chunk_read_counters(cluster).await?;
    let control = resources
        .barrier_b
        .as_mut()
        .ok_or_else(|| {
            HarnessError::Process("successor pending-owner B barrier was not retained".into())
        })?
        .pending_mut()?
        .take_control()?;
    resources.backend = Some(spawn_backend(
        control,
        data,
        welcome,
        service_id,
        DEVICE_CANARY,
    ));
    let post_ready_result = successor_public_echo(SuccessorHttpRequest {
        resources,
        consumer_addr: ingress_consumer_addr,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token,
        device_id: device.id,
        service_id,
        body: REQUEST_BODY,
        deadline: scenario_deadline,
    })
    .await;
    let owner_b_after_post_ready_result =
        current_owner_until(cluster, device.tenant_id, device.id, scenario_deadline).await;
    let owner_b_after_post_ready = owner_b_after_post_ready_result?;
    let owner_b_token_preserved_after_post_ready = owner_b_after_post_ready
        .as_ref()
        .is_some_and(|claim| claim.token == owner_b.token);
    if !owner_b_token_preserved_after_post_ready {
        return Err(HarnessError::Process(
            "successor pending-owner B token changed before backend cleanup".into(),
        ));
    }
    let post_ready = post_ready_result?;
    let expected = DEVICE_CANARY
        .iter()
        .copied()
        .chain(REQUEST_BODY.iter().copied())
        .collect::<Vec<_>>();
    let post_ready_status = post_ready.status.as_u16();
    let post_ready_canary_matched = post_ready_status == 200 && post_ready.body == expected;
    let post_ready_dispatch_deltas = subtract_counters(
        dispatch_counters(cluster).await?,
        post_ready_dispatch_before,
    );
    let post_ready_consumer_chunk_read_deltas = subtract_counters(
        consumer_chunk_read_counters(cluster).await?,
        post_ready_reads_before,
    );
    if !post_ready_canary_matched {
        return Err(HarnessError::Process(
            "successor pending-owner post-ready canary failed".into(),
        ));
    }
    if post_ready_dispatch_deltas != [0, 1, 0] || post_ready_consumer_chunk_read_deltas != [0, 1, 0]
    {
        return Err(HarnessError::Process(
            "successor pending-owner post-ready scope was not relay-b only".into(),
        ));
    }

    Ok(SuccessorPendingOwnerEvidence {
        relay_count: cluster.relays.len(),
        owner_a_token_observed,
        owner_a_deployment_matches_fixture,
        owner_a_boot_matches_fixture,
        owner_a_released,
        owner_a_epoch,
        owner_b_token_observed,
        owner_b_deployment_matches_a,
        owner_b_deployment_matches_fixture,
        owner_b_session_is_distinct,
        owner_b_boot_is_distinct,
        owner_b_boot_matches_fixture,
        owner_b_node_is_relay_b,
        owner_b_epoch,
        successor_epoch_higher,
        owner_b_control_only,
        pre_ready_status: pre_ready.status.as_u16(),
        pre_ready_peer_unavailable,
        pre_ready_execution_not_dispatched,
        pre_ready_retryable,
        pre_ready_retry_after_ms,
        pre_ready_dispatch_deltas,
        pre_ready_consumer_chunk_read_deltas,
        pre_ready_wss_status: pre_ready_wss.status,
        pre_ready_wss_upgrade_rejected: pre_ready_wss.rejected_before_upgrade,
        pre_ready_wss_application_body_sent: pre_ready_wss.application_body_sent,
        pre_ready_wss_peer_unavailable,
        pre_ready_wss_execution_not_dispatched,
        pre_ready_wss_retryable,
        pre_ready_wss_retry_after_ms,
        pre_ready_wss_retry_after_header_seconds,
        pre_ready_wss_dispatch_deltas,
        pre_ready_wss_consumer_chunk_read_deltas,
        owner_b_token_preserved_before_release,
        owner_b_fence_received,
        data_attached,
        owner_b_token_preserved_after_release,
        post_ready_status,
        post_ready_canary_matched,
        post_ready_dispatch_deltas,
        post_ready_consumer_chunk_read_deltas,
        owner_b_token_preserved_after_post_ready,
        cleanup_joined: false,
    })
}

fn min_deadline(first: Instant, second: Instant) -> Instant {
    first.min(second)
}

fn successor_consumer_connector(server_ca_der: &[u8]) -> Result<TlsConnector> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("adding successor relay CA: {error}")))?;
    let tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("configuring successor consumer TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(tls)))
}

struct SuccessorHttpRequest<'a> {
    resources: &'a mut SuccessorResources,
    consumer_addr: SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
    device_id: Uuid,
    service_id: Uuid,
    body: &'a [u8],
    deadline: Instant,
}

/// Send the successor's public POST while retaining its Hyper connection task
/// in `SuccessorResources`.  Cancellation of the scenario future therefore
/// leaves the nested task joinable by the single cleanup pass.
async fn successor_public_echo(
    request: SuccessorHttpRequest<'_>,
) -> Result<crate::acceptance::helpers::HttpResponse> {
    let SuccessorHttpRequest {
        resources,
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service_id,
        body,
        deadline,
    } = request;
    let connector = successor_consumer_connector(server_ca_der)?;
    let stream = timeout_at(deadline, TcpStream::connect(consumer_addr))
        .await
        .map_err(|_| HarnessError::Timeout("successor consumer TCP connect timed out".into()))?
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("successor relay server name: {error}")))?;
    let tls_stream = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("successor consumer TLS handshake timed out".into()))?
        .map_err(|error| {
            HarnessError::Http(format!("successor consumer TLS handshake: {error}"))
        })?;
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("successor consumer HTTP handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("successor consumer HTTP handshake: {error}")))?;
    let connection_slot = Arc::new(tokio::sync::Mutex::new(Some(tokio::spawn(async move {
        let _ = connection.await;
    }))));
    resources
        .http_connections
        .push(Arc::clone(&connection_slot));
    let path = format!("/v1/devices/{device_id}/services/{service_id}/echo");
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://localhost{path}"))
        .header("host", "localhost")
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::copy_from_slice(body)))
        .map_err(|error| {
            HarnessError::Http(format!("building successor consumer request: {error}"))
        })?;
    let response = timeout_at(deadline, sender.send_request(request))
        .await
        .map_err(|_| HarnessError::Timeout("successor consumer request timed out".into()))?
        .map_err(|error| {
            HarnessError::Http(format!("successor consumer request failed: {error}"))
        })?;
    let status = response.status();
    let body = timeout_at(
        deadline,
        Limited::new(response.into_body(), SUCCESSOR_MAX_RESPONSE_BYTES).collect(),
    )
    .await
    .map_err(|_| HarnessError::Timeout("successor consumer response timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("reading successor consumer response: {error}")))?
    .to_bytes()
    .to_vec();
    drop(sender);
    Ok(crate::acceptance::helpers::HttpResponse { status, body })
}

async fn join_successor_http_connection(
    slot: &SuccessorHttpConnectionSlot,
    deadline: Instant,
) -> Result<()> {
    let mut guard = timeout_at(deadline, slot.lock())
        .await
        .map_err(|_| HarnessError::Timeout("successor HTTP connection lock timed out".into()))?;
    let Some(task) = guard.as_mut() else {
        return Ok(());
    };
    match timeout_at(deadline, &mut *task).await {
        Ok(Ok(())) => {
            guard.take();
            Ok(())
        }
        Ok(Err(error)) => {
            guard.take();
            Err(HarnessError::Process(format!(
                "successor HTTP connection task failed: {error}"
            )))
        }
        Err(_) => {
            task.abort();
            match timeout(FORCE_JOIN_TIMEOUT, &mut *task).await {
                Ok(Ok(())) => {
                    guard.take();
                    Ok(())
                }
                Ok(Err(error)) => {
                    guard.take();
                    Err(HarnessError::Process(format!(
                        "successor HTTP connection abort join failed: {error}"
                    )))
                }
                Err(_) => Err(HarnessError::Timeout(
                    "successor HTTP connection did not join after abort".into(),
                )),
            }
        }
    }
}

fn owner_token_is_exact_for_device(
    token: &OwnerToken,
    tenant_id: Uuid,
    device_id: Uuid,
    node_id: &str,
) -> bool {
    !token.deployment_incarnation.is_empty()
        && token.tenant_id == tenant_id
        && token.device_id == device_id
        && token.node_id == node_id
        && !token.boot_id.is_empty()
        && !token.session_id.is_empty()
        && token.epoch > 0
}

async fn wait_for_control_only_exact(
    cluster: &super::ProductionCluster,
    device_id: Uuid,
    owner: &OwnerToken,
    node_id: &str,
    scenario_deadline: Instant,
) -> Result<bool> {
    let deadline = min_deadline(Instant::now() + BARRIER_TIMEOUT, scenario_deadline);
    let device_id = device_id.to_string();
    loop {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        let ready = snapshot.sessions.iter().any(|session| {
            session.device_id == device_id
                && session.session_id == owner.session_id
                && session.epoch == owner.epoch
                && session.active_generation == 1
                && session.phase == "active"
                && session.candidate_generation.is_none()
        });
        if ready {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn current_owner_until(
    cluster: &super::ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    deadline: Instant,
) -> Result<Option<tunnel_catalog::OwnerClaim>> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(
            "successor pending-owner catalog deadline elapsed".into(),
        ));
    }
    timeout(remaining, current_owner(cluster, tenant_id, device_id))
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "successor pending-owner catalog read exceeded its deadline".into(),
            )
        })?
}

async fn wait_for_owner_until(
    cluster: &super::ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    node_id: &str,
    deadline: Instant,
) -> Result<tunnel_catalog::OwnerClaim> {
    loop {
        if let Some(owner) = current_owner_until(cluster, tenant_id, device_id, deadline).await?
            && owner.token.node_id == node_id
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "successor pending-owner catalog claim did not become visible".into(),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_owner_absent_until(
    cluster: &super::ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    deadline: Instant,
) -> Result<bool> {
    loop {
        if current_owner_until(cluster, tenant_id, device_id, deadline)
            .await?
            .is_none()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "successor pending-owner old catalog owner did not release".into(),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{
        EXPECTED_RETRY_AFTER_MS, EXPECTED_RETRY_AFTER_SECONDS, SuccessorPendingOwnerEvidence,
        validate_successor_pending_owner_evidence,
    };
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> SuccessorPendingOwnerEvidence {
        SuccessorPendingOwnerEvidence {
            relay_count: 3,
            owner_a_token_observed: true,
            owner_a_deployment_matches_fixture: true,
            owner_a_boot_matches_fixture: true,
            owner_a_released: true,
            owner_a_epoch: 2,
            owner_b_token_observed: true,
            owner_b_deployment_matches_a: true,
            owner_b_deployment_matches_fixture: true,
            owner_b_session_is_distinct: true,
            owner_b_boot_is_distinct: true,
            owner_b_boot_matches_fixture: true,
            owner_b_node_is_relay_b: true,
            owner_b_epoch: 3,
            successor_epoch_higher: true,
            owner_b_control_only: true,
            pre_ready_status: 503,
            pre_ready_peer_unavailable: true,
            pre_ready_execution_not_dispatched: true,
            pre_ready_retryable: true,
            pre_ready_retry_after_ms: EXPECTED_RETRY_AFTER_MS,
            pre_ready_dispatch_deltas: [0, 0, 0],
            pre_ready_consumer_chunk_read_deltas: [0, 0, 0],
            pre_ready_wss_status: 503,
            pre_ready_wss_upgrade_rejected: true,
            pre_ready_wss_application_body_sent: false,
            pre_ready_wss_peer_unavailable: true,
            pre_ready_wss_execution_not_dispatched: true,
            pre_ready_wss_retryable: true,
            pre_ready_wss_retry_after_ms: EXPECTED_RETRY_AFTER_MS,
            pre_ready_wss_retry_after_header_seconds: EXPECTED_RETRY_AFTER_SECONDS,
            pre_ready_wss_dispatch_deltas: [0, 0, 0],
            pre_ready_wss_consumer_chunk_read_deltas: [0, 0, 0],
            owner_b_token_preserved_before_release: true,
            owner_b_fence_received: true,
            data_attached: true,
            owner_b_token_preserved_after_release: true,
            post_ready_status: 200,
            post_ready_canary_matched: true,
            post_ready_dispatch_deltas: [0, 1, 0],
            post_ready_consumer_chunk_read_deltas: [0, 1, 0],
            owner_b_token_preserved_after_post_ready: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn every_successor_pending_owner_flag_and_bound_reaches_shared_exit() {
        type Disable = (&'static str, fn(&mut SuccessorPendingOwnerEvidence));
        let flags: [Disable; 28] = [
            ("owner_a_token_observed", |e| {
                e.owner_a_token_observed = false
            }),
            ("owner_a_deployment_matches_fixture", |e| {
                e.owner_a_deployment_matches_fixture = false
            }),
            ("owner_a_boot_matches_fixture", |e| {
                e.owner_a_boot_matches_fixture = false
            }),
            ("owner_a_released", |e| e.owner_a_released = false),
            ("owner_b_token_observed", |e| {
                e.owner_b_token_observed = false
            }),
            ("owner_b_deployment_matches_a", |e| {
                e.owner_b_deployment_matches_a = false
            }),
            ("owner_b_deployment_matches_fixture", |e| {
                e.owner_b_deployment_matches_fixture = false
            }),
            ("owner_b_session_is_distinct", |e| {
                e.owner_b_session_is_distinct = false
            }),
            ("owner_b_boot_is_distinct", |e| {
                e.owner_b_boot_is_distinct = false
            }),
            ("owner_b_boot_matches_fixture", |e| {
                e.owner_b_boot_matches_fixture = false
            }),
            ("owner_b_node_is_relay_b", |e| {
                e.owner_b_node_is_relay_b = false
            }),
            ("successor_epoch_higher", |e| {
                e.successor_epoch_higher = false
            }),
            ("owner_b_control_only", |e| e.owner_b_control_only = false),
            ("pre_ready_peer_unavailable", |e| {
                e.pre_ready_peer_unavailable = false
            }),
            ("pre_ready_execution_not_dispatched", |e| {
                e.pre_ready_execution_not_dispatched = false
            }),
            ("pre_ready_retryable", |e| e.pre_ready_retryable = false),
            ("pre_ready_wss_upgrade_rejected", |e| {
                e.pre_ready_wss_upgrade_rejected = false
            }),
            ("pre_ready_wss_application_body_not_sent", |e| {
                e.pre_ready_wss_application_body_sent = true
            }),
            ("pre_ready_wss_peer_unavailable", |e| {
                e.pre_ready_wss_peer_unavailable = false
            }),
            ("pre_ready_wss_execution_not_dispatched", |e| {
                e.pre_ready_wss_execution_not_dispatched = false
            }),
            ("pre_ready_wss_retryable", |e| {
                e.pre_ready_wss_retryable = false
            }),
            ("owner_b_token_preserved_before_release", |e| {
                e.owner_b_token_preserved_before_release = false
            }),
            ("owner_b_fence_received", |e| {
                e.owner_b_fence_received = false
            }),
            ("data_attached", |e| e.data_attached = false),
            ("owner_b_token_preserved_after_release", |e| {
                e.owner_b_token_preserved_after_release = false
            }),
            ("post_ready_canary_matched", |e| {
                e.post_ready_canary_matched = false
            }),
            ("owner_b_token_preserved_after_post_ready", |e| {
                e.owner_b_token_preserved_after_post_ready = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_successor_pending_owner_evidence(&evidence), name);
        }

        type Mutate = (&'static str, fn(&mut SuccessorPendingOwnerEvidence));
        let bounds: [Mutate; 14] = [
            ("relay_count", |e| e.relay_count = 2),
            ("epoch", |e| e.owner_b_epoch = e.owner_a_epoch),
            ("pre_ready_status", |e| e.pre_ready_status = 200),
            ("pre_ready_wss_status", |e| e.pre_ready_wss_status = 200),
            ("post_ready_status", |e| e.post_ready_status = 503),
            ("retry_after", |e| e.pre_ready_retry_after_ms = 0),
            ("wss_retry_after", |e| e.pre_ready_wss_retry_after_ms = 0),
            ("wss_retry_after_header", |e| {
                e.pre_ready_wss_retry_after_header_seconds = 0
            }),
            ("pre_ready_dispatch_deltas", |e| {
                e.pre_ready_dispatch_deltas = [1, 0, 0]
            }),
            ("pre_ready_consumer_chunk_read_deltas", |e| {
                e.pre_ready_consumer_chunk_read_deltas = [1, 0, 0]
            }),
            ("pre_ready_wss_dispatch_deltas", |e| {
                e.pre_ready_wss_dispatch_deltas = [1, 0, 0]
            }),
            ("pre_ready_wss_consumer_chunk_read_deltas", |e| {
                e.pre_ready_wss_consumer_chunk_read_deltas = [1, 0, 0]
            }),
            ("post_ready_dispatch_deltas", |e| {
                e.post_ready_dispatch_deltas = [1, 0, 0]
            }),
            ("post_ready_consumer_chunk_read_deltas", |e| {
                e.post_ready_consumer_chunk_read_deltas = [1, 0, 0]
            }),
        ];
        for (_, mutate) in bounds {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(
                validate_successor_pending_owner_evidence(&evidence),
                "successor pending-owner",
            );
        }
    }
}
