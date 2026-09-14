//! M7 admission while a catalog owner is present but its connector is not
//! ready for data.
//!
//! The fixture deliberately pauses only the server-to-device direction of one
//! TLS-opaque control connection after the relay has claimed the owner.  The
//! relay therefore has a committed Redis owner and one control socket, while
//! the OWNER_FENCE acknowledgement and DATA_READY exchange remain pending.
//! Public admission is probed through a different relay during that exact
//! state, then the barrier is released and the same route must complete one
//! bounded echo.  Evidence contains counters and boolean state only; tickets,
//! bearer tokens, endpoint strings, and application payloads never leave this
//! module.  The owner-not-ready response is checked at the public boundary for
//! its fixed `not_dispatched` certainty and bounded retry metadata.  Both the
//! unary HTTPS path and the WSS upgrade path are probed while the barrier is
//! held; the WSS probe must be rejected before an application frame exists.

use super::ProductionCluster;
use crate::acceptance::helpers::{consumer_request_with_timeout, error_code};
use crate::{
    ConnectionId, Direction, Harness, HarnessError, HarnessOptions, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, RunningHarness as HarnessRuntime, TcpProxy,
};
use futures_util::{SinkExt, StreamExt};
use rustls::ClientConfig;
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, str::from_utf8, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::oneshot,
    task::JoinHandle,
    time::{Instant, sleep, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{
        Message, client::IntoClientRequest, handshake::client::generate_key, http::HeaderValue,
    },
};
use tunnel_catalog::OwnerToken;
use tunnel_core::RotationConfig;
use tunnel_protocol::{
    AuthorizationChallenge, ControlMessage, Frame, FrameKind, Hello, OwnerFenced, RotationPolicy,
    ServiceAdvertisement, Welcome, decode_control, encode_control,
};
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const ECHO_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const BARRIER_TIMEOUT: Duration = Duration::from_secs(15);
// Keep the public probe shorter than the connector's owner-fence budget.  A
// single absolute deadline covers TCP/TLS/HTTP setup and the bounded body so
// the held phase cannot age out while the probe is still establishing.
const HELD_PHASE_TIMEOUT: Duration = Duration::from_secs(10);
const PENDING_ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 300,
    handshake_timeout_seconds: 5,
    overlap_seconds: 10,
};
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const PUBLIC_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const EXPECTED_RETRY_AFTER_MS: u64 = 250;
const EXPECTED_RETRY_AFTER_SECONDS: u64 = 1;
const MAX_WSS_ERROR_BODY_BYTES: usize = 4096;
const DEVICE_CANARY: &[u8] = b"m7-pending-owner-canary";
const REQUEST_BODY: &[u8] = b"m7-pending-owner-request";

type DeviceSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;

#[path = "pending_owner_successor.rs"]
pub(super) mod successor_unready;

/// Payload-free evidence from the pending-owner admission gate.
///
/// Dispatch arrays are ordered `relay-a`, `relay-b`, `relay-c`.  Keeping all
/// three values makes a sibling dispatch or fallback visible without retaining
/// route addresses or any catalog credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PendingOwnerEvidence {
    pub relay_count: usize,
    pub owner_token_observed: bool,
    pub control_only_pending: bool,
    pub pre_ready_status: u16,
    pub pre_ready_peer_unavailable: bool,
    pub pre_ready_execution_not_dispatched: bool,
    pub pre_ready_retryable: bool,
    pub pre_ready_retry_after_ms: u64,
    pub pre_ready_dispatch_deltas: [u64; 3],
    /// Owner-side peer reads; this does not describe public ingress body
    /// consumption, which occurs before readiness admission in the route.
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
    pub owner_token_preserved_before_release: bool,
    pub owner_fence_received: bool,
    pub data_attached: bool,
    pub owner_token_preserved_after_release: bool,
    pub post_ready_status: u16,
    pub post_ready_canary_matched: bool,
    pub post_ready_dispatch_deltas: [u64; 3],
    pub post_ready_consumer_chunk_read_deltas: [u64; 3],
    pub cleanup_joined: bool,
}

/// Validate the complete pending-owner evidence contract.
fn validate_pending_owner_evidence(evidence: &PendingOwnerEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "pending-owner admission requires three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        ("owner_token_observed", evidence.owner_token_observed),
        ("control_only_pending", evidence.control_only_pending),
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
            "owner_token_preserved_before_release",
            evidence.owner_token_preserved_before_release,
        ),
        ("owner_fence_received", evidence.owner_fence_received),
        ("data_attached", evidence.data_attached),
        (
            "owner_token_preserved_after_release",
            evidence.owner_token_preserved_after_release,
        ),
        (
            "post_ready_canary_matched",
            evidence.post_ready_canary_matched,
        ),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, value)| !value) {
        return Err(HarnessError::Process(format!(
            "pending-owner required gate {name} was false"
        )));
    }
    if evidence.pre_ready_status != 503 {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready public status was {}, expected 503",
            evidence.pre_ready_status
        )));
    }
    if evidence.pre_ready_retry_after_ms != EXPECTED_RETRY_AFTER_MS {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready retry_after_ms was {}, expected {EXPECTED_RETRY_AFTER_MS}",
            evidence.pre_ready_retry_after_ms
        )));
    }
    if evidence.pre_ready_wss_status != 503 {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready WSS status was {}, expected 503",
            evidence.pre_ready_wss_status
        )));
    }
    if evidence.pre_ready_wss_retry_after_ms != EXPECTED_RETRY_AFTER_MS {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready WSS retry_after_ms was {}, expected {EXPECTED_RETRY_AFTER_MS}",
            evidence.pre_ready_wss_retry_after_ms
        )));
    }
    if evidence.pre_ready_wss_retry_after_header_seconds != EXPECTED_RETRY_AFTER_SECONDS {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready WSS Retry-After was {}, expected {EXPECTED_RETRY_AFTER_SECONDS}",
            evidence.pre_ready_wss_retry_after_header_seconds
        )));
    }
    if evidence.post_ready_status != 200 {
        return Err(HarnessError::Process(format!(
            "pending-owner post-ready public status was {}, expected 200",
            evidence.post_ready_status
        )));
    }
    if evidence.pre_ready_dispatch_deltas != [0, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready dispatch counters advanced: {:?}",
            evidence.pre_ready_dispatch_deltas
        )));
    }
    if evidence.pre_ready_consumer_chunk_read_deltas != [0, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready owner ConsumerChunk read counters advanced: {:?}",
            evidence.pre_ready_consumer_chunk_read_deltas
        )));
    }
    if evidence.pre_ready_wss_dispatch_deltas != [0, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready WSS dispatch counters advanced: {:?}",
            evidence.pre_ready_wss_dispatch_deltas
        )));
    }
    if evidence.pre_ready_wss_consumer_chunk_read_deltas != [0, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner pre-ready WSS owner ConsumerChunk read counters advanced: {:?}",
            evidence.pre_ready_wss_consumer_chunk_read_deltas
        )));
    }
    if evidence.post_ready_dispatch_deltas != [1, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner post-ready dispatch counters were {:?}, expected selected owner only",
            evidence.post_ready_dispatch_deltas
        )));
    }
    if evidence.post_ready_consumer_chunk_read_deltas != [1, 0, 0] {
        return Err(HarnessError::Process(format!(
            "pending-owner post-ready owner ConsumerChunk read counters were {:?}, expected selected owner only",
            evidence.post_ready_consumer_chunk_read_deltas
        )));
    }
    Ok(())
}

/// Run the bounded real three-relay pending-owner gate.
pub async fn verify() -> Result<PendingOwnerEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(PENDING_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(super::STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("pending-owner harness startup timed out".into()))??;

    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let harness_cleanup = harness.shutdown().await;
            return match harness_cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(combine_failures(
                    error,
                    "pending-owner catalog cleanup",
                    cleanup,
                )),
            };
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, run_pending_owner(&mut cluster, &harness)).await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "pending-owner scenario exceeded its bounded deadline".into(),
        )),
    };
    let cluster_cleanup = cluster.shutdown().await;
    let harness_cleanup = harness.shutdown().await;

    let (mut evidence, mut failure) = match scenario {
        Ok(evidence) => (Some(evidence), None),
        Err(error) => (None, Some(error)),
    };
    if let Err(error) = cluster_cleanup {
        append_failure(&mut failure, "pending-owner relay cleanup", error);
    }
    if let Err(error) = harness_cleanup {
        append_failure(&mut failure, "pending-owner catalog cleanup", error);
    }
    if let Some(evidence) = evidence.as_mut() {
        evidence.cleanup_joined = failure.is_none();
        if failure.is_none()
            && let Err(error) = validate_pending_owner_evidence(evidence)
        {
            append_failure(&mut failure, "pending-owner evidence validation", error);
            evidence.cleanup_joined = false;
        }
    }

    match (evidence.take(), failure) {
        (Some(evidence), None) => Ok(evidence),
        (_, Some(error)) => Err(error),
        (None, None) => Err(HarnessError::Process(
            "pending-owner scenario produced no evidence or failure".into(),
        )),
    }
}

fn append_failure(slot: &mut Option<HarnessError>, label: &str, error: HarnessError) {
    let error = match slot.take() {
        Some(primary) => HarnessError::Process(format!("{primary}; {label}: {error}")),
        None => HarnessError::Process(format!("{label}: {error}")),
    };
    *slot = Some(error);
}

fn combine_failures(primary: HarnessError, label: &str, cleanup: HarnessError) -> HarnessError {
    HarnessError::Process(format!("{primary}; {label}: {cleanup}"))
}

async fn run_pending_owner(
    cluster: &mut ProductionCluster,
    harness: &HarnessRuntime,
) -> Result<PendingOwnerEvidence> {
    let device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("pending-owner device is missing".into()))?;
    let service_id = *harness
        .topology
        .service_ids
        .get(&device.id)
        .ok_or_else(|| HarnessError::InvalidInput("pending-owner service is missing".into()))?;
    let token = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;

    let owner_node = "relay-a";
    let ingress_node = "relay-c";
    let owner_device_addr = relay_device_addr(cluster, owner_node)?;
    let ingress_consumer_addr = cluster.relay(ingress_node)?.consumer_addr()?;
    let tls = device_tls(harness, device)?;
    let rotation = harness.rotation_config();
    let mut barrier =
        PendingBarrier::open(owner_device_addr, tls, device.id, service_id, rotation).await?;

    let scenario = async {
        let owner = wait_for_owner(cluster, device.tenant_id, device.id, owner_node).await?;
        let control_only_pending =
            wait_for_control_only(cluster, device.id, owner.token.epoch, owner_node).await?;
        let held_phase_deadline = Instant::now() + HELD_PHASE_TIMEOUT;
        let wss_dispatch_before = dispatch_counters(cluster).await?;
        let wss_consumer_chunk_reads_before = consumer_chunk_read_counters(cluster).await?;
        let pre_ready_wss = timeout_at(
            held_phase_deadline,
            open_pending_owner_wss(
                ingress_consumer_addr,
                &harness.pki.server_ca.certificate_der,
                &token,
                device.id,
                service_id,
                held_phase_deadline,
            ),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "pending-owner held-owner WSS admission exceeded its bounded phase deadline"
                    .into(),
            )
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
                "pending-owner pre-ready WSS admission did not return the fixed rejected-before-upgrade retryable contract".into(),
            ));
        }
        let wss_dispatch_after = dispatch_counters(cluster).await?;
        let pre_ready_wss_dispatch_deltas =
            subtract_counters(wss_dispatch_after, wss_dispatch_before);
        let wss_consumer_chunk_reads_after = consumer_chunk_read_counters(cluster).await?;
        let pre_ready_wss_consumer_chunk_read_deltas = subtract_counters(
            wss_consumer_chunk_reads_after,
            wss_consumer_chunk_reads_before,
        );
        if pre_ready_wss_dispatch_deltas != [0, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner pre-ready WSS request advanced a relay dispatch counter".into(),
            ));
        }
        if pre_ready_wss_consumer_chunk_read_deltas != [0, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner pre-ready WSS request consumed an owner ConsumerChunk".into(),
            ));
        }

        let dispatch_before = dispatch_counters(cluster).await?;
        let consumer_chunk_reads_before = consumer_chunk_read_counters(cluster).await?;
        let pre_ready = timeout_at(
            held_phase_deadline,
            public_echo(
                ingress_consumer_addr,
                &harness.pki.server_ca.certificate_der,
                &token,
                device.id,
                service_id,
                REQUEST_BODY,
            ),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "pending-owner held-owner admission exceeded its bounded phase deadline".into(),
            )
        })??;
        let pre_ready_peer_unavailable = pre_ready.status == 503
            && error_code(&pre_ready).as_deref() == Some("PEER_UNAVAILABLE");
        let pre_ready_execution_not_dispatched =
            pre_ready_peer_unavailable && response_execution_not_dispatched(&pre_ready);
        let pre_ready_retryable =
            pre_ready_execution_not_dispatched && response_retryable(&pre_ready);
        let pre_ready_retry_after_ms = response_retry_after_ms(&pre_ready).unwrap_or_default();
        if !pre_ready_peer_unavailable
            || !pre_ready_execution_not_dispatched
            || !pre_ready_retryable
            || pre_ready_retry_after_ms != EXPECTED_RETRY_AFTER_MS
        {
            return Err(HarnessError::Process(
                "pending-owner pre-ready public admission did not return the fixed retryable PEER_UNAVAILABLE contract".into(),
            ));
        }
        let dispatch_after_pre_ready = dispatch_counters(cluster).await?;
        let pre_ready_dispatch_deltas =
            subtract_counters(dispatch_after_pre_ready, dispatch_before);
        let consumer_chunk_reads_after = consumer_chunk_read_counters(cluster).await?;
        let pre_ready_consumer_chunk_read_deltas =
            subtract_counters(consumer_chunk_reads_after, consumer_chunk_reads_before);
        if pre_ready_dispatch_deltas != [0, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner pre-ready request advanced a relay dispatch counter".into(),
            ));
        }
        if pre_ready_consumer_chunk_read_deltas != [0, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner pre-ready request consumed an owner ConsumerChunk".into(),
            ));
        }
        let owner_before_release = current_owner(cluster, device.tenant_id, device.id).await?;
        let owner_token_preserved_before_release = owner_before_release
            .as_ref()
            .is_some_and(|claim| claim.token == owner.token);
        if !owner_token_preserved_before_release {
            return Err(HarnessError::Process(
                "pending-owner catalog token changed while control was held".into(),
            ));
        }

        barrier.resume().await?;
        let (welcome, data) = barrier.finish_handshake().await?;
        let expected_owner_id = owner_digest(&owner.token);
        if welcome.owner_id.as_deref() != Some(expected_owner_id.as_str()) {
            return Err(HarnessError::Process(
                "pending-owner WELCOME owner identity did not match the catalog owner".into(),
            ));
        }
        let owner_fence_received = true;
        let owner_after_release = current_owner(cluster, device.tenant_id, device.id).await?;
        let owner_token_preserved_after_release = owner_after_release
            .as_ref()
            .is_some_and(|claim| claim.token == owner.token);
        if !owner_token_preserved_after_release {
            return Err(HarnessError::Process(
                "pending-owner catalog token changed after control release".into(),
            ));
        }
        let data_attached =
            wait_for_data_attached(cluster, device.id, owner.token.epoch, owner_node).await?;

        let post_ready_before = dispatch_counters(cluster).await?;
        let post_ready_consumer_chunk_reads_before = consumer_chunk_read_counters(cluster).await?;
        let backend = spawn_backend(
            barrier.take_control()?,
            data,
            welcome,
            service_id,
            DEVICE_CANARY,
        );
        let post_ready_result = public_echo(
            ingress_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
            REQUEST_BODY,
        )
        .await;
        let expected = DEVICE_CANARY
            .iter()
            .copied()
            .chain(REQUEST_BODY.iter().copied())
            .collect::<Vec<_>>();
        // Keep the owner/device sockets alive while the public response is
        // observed and the catalog owner is sampled.  The backend is
        // cancelled and joined only after both observations complete.
        let owner_after_post_ready_result =
            current_owner(cluster, device.tenant_id, device.id).await;
        let backend_result = join_backend(backend).await?;
        let owner_after_post_ready = owner_after_post_ready_result?;
        let owner_token_preserved_after_post_ready = owner_after_post_ready
            .as_ref()
            .is_some_and(|claim| claim.token == owner.token);
        if !owner_token_preserved_after_post_ready {
            return Err(HarnessError::Process(
                "pending-owner catalog token changed before backend shutdown".into(),
            ));
        }
        let post_ready = match post_ready_result {
            Ok(response) => response,
            Err(error) => {
                let post_ready_after = dispatch_counters(cluster).await?;
                let post_ready_dispatch_deltas =
                    subtract_counters(post_ready_after, post_ready_before);
                return Err(HarnessError::Process(format!(
                    "pending-owner post-ready public request failed after backend completion={backend_result}, dispatch_deltas={post_ready_dispatch_deltas:?}: {error}"
                )));
            }
        };
        let post_ready_after = dispatch_counters(cluster).await?;
        let post_ready_dispatch_deltas = subtract_counters(post_ready_after, post_ready_before);
        let post_ready_consumer_chunk_reads_after = consumer_chunk_read_counters(cluster).await?;
        let post_ready_consumer_chunk_read_deltas = subtract_counters(
            post_ready_consumer_chunk_reads_after,
            post_ready_consumer_chunk_reads_before,
        );
        let status_ok = post_ready.status == 200;
        let body_len_matches = post_ready.body.len() == expected.len();
        let canary_prefix_matches = post_ready.body.starts_with(DEVICE_CANARY);
        let request_suffix_matches = post_ready.body.ends_with(REQUEST_BODY);
        let body_exact = post_ready.body == expected;
        let post_ready_canary_matched = status_ok && body_exact;
        if !backend_result || !post_ready_canary_matched {
            return Err(HarnessError::Process(format!(
                "pending-owner post-ready response mismatch: backend_completed={backend_result}, status={}, status_ok={status_ok}, expected_body_len={}, observed_body_len={}, body_len_matches={body_len_matches}, body_exact={body_exact}, canary_len={}, canary_prefix_matches={canary_prefix_matches}, request_len={}, request_suffix_matches={request_suffix_matches}, dispatch_deltas={post_ready_dispatch_deltas:?}, owner_consumer_chunk_read_deltas={post_ready_consumer_chunk_read_deltas:?}",
                post_ready.status.as_u16(),
                expected.len(),
                post_ready.body.len(),
                DEVICE_CANARY.len(),
                REQUEST_BODY.len(),
            )));
        }
        if post_ready_dispatch_deltas != [1, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner post-ready dispatch scope was not exactly the selected owner".into(),
            ));
        }
        if post_ready_consumer_chunk_read_deltas != [1, 0, 0] {
            return Err(HarnessError::Process(
                "pending-owner post-ready owner ConsumerChunk read scope was not exactly the selected owner".into(),
            ));
        }

        Ok(PendingOwnerEvidence {
            relay_count: cluster.relays.len(),
            owner_token_observed: true,
            control_only_pending,
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
            owner_token_preserved_before_release,
            owner_fence_received,
            data_attached,
            owner_token_preserved_after_release,
            post_ready_status: post_ready.status.as_u16(),
            post_ready_canary_matched,
            post_ready_dispatch_deltas,
            post_ready_consumer_chunk_read_deltas,
            cleanup_joined: false,
        })
    }
    .await;
    let barrier_cleanup = barrier.close().await;
    match (scenario, barrier_cleanup) {
        (Ok(evidence), Ok(())) => Ok(evidence),
        (Err(error), Ok(())) => Err(error),
        (Ok(_), Err(error)) => Err(error),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Process(format!(
            "{primary}; pending-owner barrier cleanup also failed: {cleanup}"
        ))),
    }
}

struct PendingWssResponse {
    status: u16,
    body: Vec<u8>,
    retry_after_header_seconds: Option<u64>,
    rejected_before_upgrade: bool,
    application_body_sent: bool,
}

const MAX_WSS_RESPONSE_HEADER_BYTES: usize = 16 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingWssResponseHeaders {
    status: u16,
    content_length: usize,
    retry_after_header_seconds: Option<u64>,
}

async fn open_pending_owner_wss(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    deadline: Instant,
) -> Result<PendingWssResponse> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(rustls::pki_types::CertificateDer::from(
            server_ca_der.to_vec(),
        ))
        .map_err(|error| HarnessError::Http(format!("pending-owner WSS CA: {error}")))?;
    let tls = ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Http(format!("pending-owner WSS TLS: {error}")))?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let stream = timeout_at(
        deadline,
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, consumer_addr.port())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("pending-owner WSS TCP connect timed out".into()))?
    .map_err(HarnessError::Io)?;
    let server_name = rustls::pki_types::ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("pending-owner WSS server name: {error}")))?;
    let mut stream = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("pending-owner WSS TLS timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("pending-owner WSS TLS: {error}")))?;

    let authorization = HeaderValue::from_str(&format!("Bearer {token}"))
        .map_err(|error| HarnessError::Http(format!("pending-owner consumer auth: {error}")))?;
    let authorization = authorization
        .to_str()
        .map_err(|error| HarnessError::Http(format!("pending-owner consumer auth: {error}")))?;
    let request = format!(
        "GET /v1/devices/{device_id}/services/{service_id}/stream HTTP/1.1\r\n\
Host: localhost\r\n\
Authorization: {authorization}\r\n\
Connection: Upgrade\r\n\
Upgrade: websocket\r\n\
Sec-WebSocket-Version: 13\r\n\
Sec-WebSocket-Key: {}\r\n\
Sec-WebSocket-Protocol: {ECHO_SUBPROTOCOL}\r\n\
Content-Length: 0\r\n\
\r\n",
        generate_key(),
    );
    timeout_at(deadline, stream.write_all(request.as_bytes()))
        .await
        .map_err(|_| HarnessError::Timeout("pending-owner WSS request write timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("pending-owner WSS request write: {error}")))?;
    read_pending_wss_response(&mut stream, deadline).await
}

async fn read_pending_wss_response<S>(
    mut stream: S,
    deadline: Instant,
) -> Result<PendingWssResponse>
where
    S: AsyncRead + Unpin,
{
    let mut response = Vec::with_capacity(MAX_WSS_RESPONSE_HEADER_BYTES);
    let mut chunk = [0_u8; 1024];
    let header_end = loop {
        let read = timeout_at(deadline, stream.read(&mut chunk))
            .await
            .map_err(|_| HarnessError::Timeout("pending-owner WSS headers timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("pending-owner WSS headers: {error}")))?;
        if read == 0 {
            return Err(HarnessError::Http(
                "pending-owner WSS closed before response headers".into(),
            ));
        }
        response.extend_from_slice(&chunk[..read]);
        if let Some(end) = response.windows(4).position(|window| window == b"\r\n\r\n") {
            if end + 4 > MAX_WSS_RESPONSE_HEADER_BYTES {
                return Err(HarnessError::Http(
                    "pending-owner WSS response headers exceeded their bound".into(),
                ));
            }
            break end + 4;
        }
        if response.len() > MAX_WSS_RESPONSE_HEADER_BYTES {
            return Err(HarnessError::Http(
                "pending-owner WSS response headers exceeded their bound".into(),
            ));
        }
    };
    let headers = parse_pending_wss_response_headers(&response[..header_end])?;
    let body_already_read = response.len().saturating_sub(header_end);
    if body_already_read > headers.content_length {
        return Err(HarnessError::Http(
            "pending-owner WSS response exceeded its declared body length".into(),
        ));
    }
    let mut body = response[header_end..].to_vec();
    body.resize(headers.content_length, 0);
    if body_already_read < headers.content_length {
        timeout_at(deadline, stream.read_exact(&mut body[body_already_read..]))
            .await
            .map_err(|_| HarnessError::Timeout("pending-owner WSS body timed out".into()))?
            .map_err(|error| HarnessError::Http(format!("pending-owner WSS body: {error}")))?;
    }
    Ok(PendingWssResponse {
        status: headers.status,
        body,
        retry_after_header_seconds: headers.retry_after_header_seconds,
        rejected_before_upgrade: headers.status != 101,
        application_body_sent: false,
    })
}

fn parse_pending_wss_response_headers(bytes: &[u8]) -> Result<PendingWssResponseHeaders> {
    let header_end = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|end| end + 4)
        .ok_or_else(|| HarnessError::Http("pending-owner WSS headers were incomplete".into()))?;
    let text = from_utf8(&bytes[..header_end])
        .map_err(|_| HarnessError::Http("pending-owner WSS headers were not UTF-8".into()))?;
    let mut lines = text.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| HarnessError::Http("pending-owner WSS status was invalid".into()))?;
    let mut content_length = None;
    let mut retry_after_header_seconds = None;
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(HarnessError::Http(
                "pending-owner WSS response header was malformed".into(),
            ));
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("content-length") {
            if content_length.is_some() {
                return Err(HarnessError::Http(
                    "pending-owner WSS response repeated content length".into(),
                ));
            }
            let parsed = value.parse::<usize>().map_err(|_| {
                HarnessError::Http("pending-owner WSS content length was invalid".into())
            })?;
            if parsed > MAX_WSS_ERROR_BODY_BYTES {
                return Err(HarnessError::Http(
                    "pending-owner WSS response body exceeded its bound".into(),
                ));
            }
            content_length = Some(parsed);
        } else if name.eq_ignore_ascii_case("retry-after") {
            retry_after_header_seconds = value.parse::<u64>().ok();
        }
    }
    let content_length = match content_length {
        Some(value) => value,
        None if status == 101 => 0,
        None => {
            return Err(HarnessError::Http(
                "pending-owner WSS response omitted content length".into(),
            ));
        }
    };
    Ok(PendingWssResponseHeaders {
        status,
        content_length,
        retry_after_header_seconds,
    })
}

fn parse_wss_error_body(body: &[u8]) -> Result<serde_json::Value> {
    if body.len() > MAX_WSS_ERROR_BODY_BYTES {
        return Err(HarnessError::Http(
            "pending-owner WSS error body exceeded its bound".into(),
        ));
    }
    serde_json::from_slice(body).map_err(|_| {
        HarnessError::Http("pending-owner WSS rejection omitted typed metadata".into())
    })
}

async fn public_echo(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    body: &[u8],
) -> Result<crate::acceptance::helpers::HttpResponse> {
    let path = format!("/v1/devices/{device_id}/services/{service_id}/echo");
    consumer_request_with_timeout(
        consumer_addr,
        server_ca_der,
        token,
        "POST",
        &path,
        body.to_vec(),
        PUBLIC_REQUEST_TIMEOUT,
    )
    .await
}

fn response_execution_not_dispatched(response: &crate::acceptance::helpers::HttpResponse) -> bool {
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .is_some_and(|value| {
            value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
        })
}

fn response_retryable(response: &crate::acceptance::helpers::HttpResponse) -> bool {
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .is_some_and(|value| {
            value.get("retryable").and_then(serde_json::Value::as_bool) == Some(true)
        })
}

fn response_retry_after_ms(response: &crate::acceptance::helpers::HttpResponse) -> Option<u64> {
    serde_json::from_slice::<serde_json::Value>(&response.body)
        .ok()
        .and_then(|value| {
            value
                .get("retry_after_ms")
                .and_then(serde_json::Value::as_u64)
        })
}

async fn current_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<Option<tunnel_catalog::OwnerClaim>> {
    cluster
        .catalog
        .current_owner(tenant_id, device_id, chrono::Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading pending-owner catalog state: {error}"))
        })
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    node_id: &str,
) -> Result<tunnel_catalog::OwnerClaim> {
    let deadline = Instant::now() + BARRIER_TIMEOUT;
    loop {
        if let Some(owner) = current_owner(cluster, tenant_id, device_id).await?
            && owner.token.node_id == node_id
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "pending-owner catalog claim did not become visible".into(),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_control_only(
    cluster: &ProductionCluster,
    device_id: Uuid,
    epoch: u64,
    node_id: &str,
) -> Result<bool> {
    let deadline = Instant::now() + BARRIER_TIMEOUT;
    let device_id = device_id.to_string();
    let mut saw_session = false;
    let mut saw_epoch = false;
    let mut saw_generation = false;
    let mut saw_active_phase = false;
    let mut saw_no_candidate = false;
    let mut saw_connection_id = false;
    let mut last_sockets = None;
    let mut last_connection_id_present = false;
    let mut last_candidate_present = false;
    loop {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        if let Some(session) = snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id)
        {
            saw_session = true;
            saw_epoch |= session.epoch == epoch;
            saw_generation |= session.active_generation == 1;
            saw_active_phase |= session.phase == "active";
            saw_no_candidate |= session.candidate_generation.is_none();
            saw_connection_id |= !session.active_connection_id.is_empty();
            last_sockets = Some(session.sockets);
            last_connection_id_present = !session.active_connection_id.is_empty();
            last_candidate_present = session.candidate_generation.is_some();

            // The M2 rotation state is installed when the control session is
            // registered, before DATA_READY.  Its snapshot reports the
            // logical control+data socket budget (two) even while the
            // physical data carrier is absent.  The paused TargetToClient
            // proxy is the no-carrier barrier; requiring sockets == 1 or a
            // non-empty active connection id here would therefore conflate
            // logical rotation state with data readiness.
            if session.epoch == epoch
                && session.active_generation == 1
                && session.phase == "active"
                && session.candidate_generation.is_none()
            {
                return Ok(true);
            }
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "pending-owner control-only session did not become observable: saw_session={saw_session}, saw_epoch={saw_epoch}, saw_generation={saw_generation}, saw_active_phase={saw_active_phase}, saw_no_candidate={saw_no_candidate}, saw_connection_id={saw_connection_id}, last_sockets={last_sockets:?}, last_connection_id_present={last_connection_id_present}, last_candidate_present={last_candidate_present}"
            )));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn wait_for_data_attached(
    cluster: &ProductionCluster,
    device_id: Uuid,
    epoch: u64,
    node_id: &str,
) -> Result<bool> {
    let deadline = Instant::now() + BARRIER_TIMEOUT;
    let device_id = device_id.to_string();
    loop {
        let snapshot = cluster.relay(node_id)?.snapshot().await?;
        if let Some(session) = snapshot
            .sessions
            .iter()
            .find(|session| session.device_id == device_id)
            && session.epoch == epoch
            && session.active_generation == 1
            && session.sockets == 2
            && session.candidate_generation.is_none()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "pending-owner data attachment did not become observable".into(),
            ));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

async fn dispatch_counters(cluster: &ProductionCluster) -> Result<[u64; 3]> {
    let mut values = [0_u64; 3];
    for (index, node_id) in ["relay-a", "relay-b", "relay-c"].into_iter().enumerate() {
        values[index] = cluster
            .relay(node_id)?
            .snapshot()
            .await?
            .lifetime_application_dispatches;
    }
    Ok(values)
}

async fn consumer_chunk_read_counters(cluster: &ProductionCluster) -> Result<[u64; 3]> {
    let mut values = [0_u64; 3];
    for (index, node_id) in ["relay-a", "relay-b", "relay-c"].into_iter().enumerate() {
        values[index] = cluster
            .relay(node_id)?
            .snapshot()
            .await?
            .lifetime_consumer_chunk_reads;
    }
    Ok(values)
}

fn subtract_counters(after: [u64; 3], before: [u64; 3]) -> [u64; 3] {
    [
        after[0].saturating_sub(before[0]),
        after[1].saturating_sub(before[1]),
        after[2].saturating_sub(before[2]),
    ]
}

fn relay_device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relay(node_id)?
        .running
        .as_ref()
        .map(|relay| relay.device_addr)
        .ok_or_else(|| HarnessError::Process("pending-owner relay is not running".into()))
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
    .map_err(|error| HarnessError::Pki(format!("pending-owner device TLS: {error}")))
}

fn owner_digest(owner: &OwnerToken) -> String {
    let canonical = serde_json::to_vec(owner).expect("OwnerToken is serializable");
    Sha256::digest(canonical)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

struct PendingBarrier {
    proxy: Option<ProxyHandle>,
    connection_id: ConnectionId,
    paused: bool,
    control: Option<DeviceSocket>,
    tls: Arc<ClientConfig>,
    hello_message_id: String,
}

impl PendingBarrier {
    async fn open(
        target_addr: SocketAddr,
        tls: Arc<ClientConfig>,
        device_id: Uuid,
        service_id: Uuid,
        rotation: RotationConfig,
    ) -> Result<Self> {
        let proxy = TcpProxy::bind(target_addr, ProxyConfig::default()).await?;
        let local_addr = proxy.local_addr();
        let control_url = format!("wss://localhost:{}/v1/tunnel/control", local_addr.port());
        let hello = hello_message(device_id, service_id, rotation);
        let hello_message_id = match &hello {
            ControlMessage::Hello(hello) => hello.message_id.clone(),
            _ => unreachable!("hello_message always returns HELLO"),
        };
        let control =
            match open_device_socket(&control_url, Arc::clone(&tls), CONTROL_SUBPROTOCOL, None)
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
            tls,
            hello_message_id,
        };
        let connection_id = match barrier.wait_for_connection().await {
            Ok(value) => value,
            Err(error) => {
                barrier.close().await?;
                return Err(error);
            }
        };
        barrier.connection_id = connection_id;
        if let Err(error) = barrier.pause().await {
            barrier.close().await?;
            return Err(error);
        }
        if let Err(error) = send_control(
            barrier
                .control
                .as_mut()
                .expect("control socket is retained"),
            &hello,
        )
        .await
        {
            barrier.close().await?;
            return Err(error);
        }
        Ok(barrier)
    }

    async fn wait_for_connection(&self) -> Result<crate::ConnectionId> {
        let deadline = Instant::now() + BARRIER_TIMEOUT;
        let proxy = self.proxy.as_ref().expect("proxy is retained");
        loop {
            let connections = proxy.connections();
            if connections.len() == 1 {
                return Ok(connections[0].id);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "pending-owner control proxy did not observe one connection".into(),
                ));
            }
            sleep(Duration::from_millis(10)).await;
        }
    }

    async fn pause(&mut self) -> Result<()> {
        self.proxy
            .as_ref()
            .expect("proxy is retained")
            .pause(Direction::TargetToClient, self.connection_id)
            .await?;
        self.paused = true;
        Ok(())
    }

    async fn resume(&mut self) -> Result<()> {
        if self.paused {
            self.proxy
                .as_ref()
                .expect("proxy is retained")
                .resume(Direction::TargetToClient, self.connection_id)
                .await?;
            self.paused = false;
        }
        Ok(())
    }

    async fn finish_handshake(&mut self) -> Result<(Welcome, DeviceSocket)> {
        let control = self.control.as_mut().expect("control socket is retained");
        let welcome = match next_control(control, Instant::now() + BARRIER_TIMEOUT).await? {
            ControlMessage::Welcome(welcome) => welcome,
            _ => {
                return Err(HarnessError::Http(
                    "pending-owner control did not return WELCOME".into(),
                ));
            }
        };
        if welcome.protocol_major != PROTOCOL_MAJOR
            || welcome.protocol_minor != PROTOCOL_MINOR
            || welcome.reply_to != self.hello_message_id
            || welcome.session_id.is_empty()
            || welcome.connection_id.is_empty()
            || welcome.attachment_ticket.is_empty()
            || welcome.generation != 1
            || welcome.owner_id.is_none()
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
                "pending-owner WELCOME did not negotiate the M2 owner profile".into(),
            ));
        }
        let fence = match next_control(control, Instant::now() + BARRIER_TIMEOUT).await? {
            ControlMessage::OwnerFence(fence) => fence,
            _ => {
                return Err(HarnessError::Http(
                    "pending-owner control did not return OWNER_FENCE".into(),
                ));
            }
        };
        fence
            .validate()
            .map_err(|error| HarnessError::Http(format!("pending-owner OWNER_FENCE: {error}")))?;
        if fence.session_id != welcome.session_id
            || fence.epoch != welcome.epoch
            || welcome.owner_id.as_deref() != Some(fence.owner_id.as_str())
        {
            return Err(HarnessError::Http(
                "pending-owner OWNER_FENCE did not match WELCOME".into(),
            ));
        }
        send_control(
            control,
            &ControlMessage::OwnerFenced(OwnerFenced::from_fence(
                Uuid::new_v4().to_string(),
                &fence,
            )),
        )
        .await?;

        let control_url = self.proxy.as_ref().expect("proxy is retained").local_addr();
        let data_url = format!("wss://localhost:{}/v1/tunnel/data", control_url.port());
        let data = open_device_socket(
            &data_url,
            Arc::clone(&self.tls),
            DATA_SUBPROTOCOL,
            Some(&welcome.attachment_ticket),
        )
        .await?;
        loop {
            match next_control(control, Instant::now() + BARRIER_TIMEOUT).await? {
                ControlMessage::DataReady(ready) => {
                    ready
                        .validate_context(
                            &welcome.session_id,
                            welcome.epoch,
                            welcome.generation,
                            &welcome.connection_id,
                        )
                        .map_err(|error| {
                            HarnessError::Http(format!("pending-owner DATA_READY: {error}"))
                        })?;
                    if ready.reply_to != welcome.message_id {
                        return Err(HarnessError::Http(
                            "pending-owner DATA_READY reply did not match WELCOME".into(),
                        ));
                    }
                    return Ok((welcome, data));
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
                    )
                    .await?;
                }
                _ => {}
            }
        }
    }

    fn take_control(&mut self) -> Result<DeviceSocket> {
        self.control.take().ok_or_else(|| {
            HarnessError::Process("pending-owner control socket was consumed".into())
        })
    }

    async fn close(mut self) -> Result<()> {
        let mut first_error = None;
        if self.paused
            && let Some(proxy) = self.proxy.as_ref()
            && let Err(error) = proxy
                .resume(Direction::TargetToClient, self.connection_id)
                .await
        {
            first_error = Some(error);
        }
        self.paused = false;
        drop(self.control.take());
        if let Some(proxy) = self.proxy.take() {
            match timeout(CLEANUP_TIMEOUT, proxy.shutdown()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error.get_or_insert(error);
                }
                Err(_) => {
                    first_error.get_or_insert_with(|| {
                        HarnessError::Timeout("pending-owner proxy cleanup timed out".into())
                    });
                }
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
) -> Result<DeviceSocket> {
    let mut request = url.into_client_request().map_err(|error| {
        HarnessError::Http(format!("building pending-owner WebSocket: {error}"))
    })?;
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_str(subprotocol)
            .map_err(|error| HarnessError::Http(format!("pending-owner subprotocol: {error}")))?,
    );
    if let Some(ticket) = ticket {
        let value = HeaderValue::from_str(&format!("Bearer {ticket}"))
            .map_err(|error| HarnessError::Http(format!("pending-owner ticket header: {error}")))?;
        request.headers_mut().insert("authorization", value);
    }
    let (socket, response) = timeout(
        BARRIER_TIMEOUT,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(tls))),
    )
    .await
    .map_err(|_| HarnessError::Timeout("pending-owner WebSocket handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("pending-owner WebSocket handshake: {error}")))?;
    if response
        .headers()
        .get("sec-websocket-protocol")
        .and_then(|value| value.to_str().ok())
        != Some(subprotocol)
    {
        return Err(HarnessError::Http(
            "pending-owner WebSocket subprotocol was not negotiated".into(),
        ));
    }
    Ok(socket)
}

async fn send_control(socket: &mut DeviceSocket, message: &ControlMessage) -> Result<()> {
    let encoded = encode_control(message)
        .map_err(|error| HarnessError::Http(format!("pending-owner control encode: {error}")))?;
    let text = String::from_utf8(encoded)
        .map_err(|error| HarnessError::Http(format!("pending-owner control UTF-8: {error}")))?;
    timeout(BARRIER_TIMEOUT, socket.send(Message::Text(text.into())))
        .await
        .map_err(|_| HarnessError::Timeout("pending-owner control send timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("pending-owner control send: {error}")))
}

async fn next_control(socket: &mut DeviceSocket, deadline: Instant) -> Result<ControlMessage> {
    loop {
        let item = timeout(
            deadline.saturating_duration_since(Instant::now()),
            socket.next(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("pending-owner control deadline elapsed".into()))?;
        match item {
            Some(Ok(Message::Text(text))) => {
                return decode_control(text.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("pending-owner control decode: {error}"))
                });
            }
            Some(Ok(Message::Binary(bytes))) => {
                return decode_control(&bytes).map_err(|error| {
                    HarnessError::Http(format!("pending-owner control decode: {error}"))
                });
            }
            Some(Ok(Message::Ping(payload))) => {
                timeout(BARRIER_TIMEOUT, socket.send(Message::Pong(payload)))
                    .await
                    .map_err(|_| {
                        HarnessError::Timeout("pending-owner control pong timed out".into())
                    })?
                    .map_err(|error| {
                        HarnessError::Http(format!("pending-owner control pong: {error}"))
                    })?;
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                return Err(HarnessError::Http(
                    "pending-owner control socket closed".into(),
                ));
            }
            Some(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "pending-owner control read: {error}"
                )));
            }
        }
    }
}

pub(super) struct BackendTask {
    pub(super) task: Option<JoinHandle<Result<bool>>>,
    pub(super) cancel: Option<oneshot::Sender<()>>,
    pub(super) response_attempted: Option<oneshot::Receiver<()>>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum BackendFrameOutcome {
    Continue,
    ResponseAttempted,
    Stop,
}

impl Drop for BackendTask {
    fn drop(&mut self) {
        // Normal and error returns call `join_backend`, which signals
        // cancellation and awaits both the task and its response-attempt
        // observation.  Drop is only the abort fallback when the enclosing
        // bounded scenario itself is cancelled.
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

fn pending_owner_frame_scope(kind: FrameKind, stream_matches: bool) -> &'static str {
    match kind {
        FrameKind::Ack | FrameKind::WindowUpdate => "control",
        FrameKind::Data => {
            if stream_matches {
                "selected_application"
            } else {
                "other_application"
            }
        }
        FrameKind::Fin | FrameKind::Reset => {
            if stream_matches {
                "selected_terminal"
            } else {
                "other_terminal"
            }
        }
    }
}

async fn process_authorized_backend_frame(
    frame: Frame,
    welcome: &Welcome,
    stream_id: u64,
    receive_window_limit: &mut Option<u64>,
    data: &mut DeviceSocket,
    canary: &'static [u8],
) -> Result<BackendFrameOutcome> {
    let stream_matches = frame.stream_id == stream_id;
    let scope = pending_owner_frame_scope(frame.kind, stream_matches);
    let epoch_matches = frame.epoch == welcome.epoch;
    let generation_matches = frame.generation == welcome.generation;
    if !epoch_matches || !generation_matches {
        return Err(pending_owner_data_context_error(
            &frame,
            Some(stream_id),
            true,
            epoch_matches,
            generation_matches,
            scope,
        ));
    }
    match frame.kind {
        FrameKind::Data => {
            if !stream_matches {
                return Err(pending_owner_data_context_error(
                    &frame,
                    Some(stream_id),
                    true,
                    epoch_matches,
                    generation_matches,
                    scope,
                ));
            }
            let body = decode_record(&frame.payload)?;
            let acknowledgement =
                Frame::ack(welcome.epoch, welcome.generation, stream_id, frame.sequence)
                    .encode()
                    .map_err(|error| {
                        HarnessError::Http(format!("pending-owner backend ACK encode: {error}"))
                    })?;
            data.send(Message::Binary(acknowledgement.into()))
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("pending-owner backend ACK send: {error}"))
                })?;
            if let Some(limit) = receive_window_limit.as_mut() {
                let released = u64::try_from(frame.payload.len()).map_err(|_| {
                    HarnessError::InvalidInput("pending-owner receive window overflow".into())
                })?;
                *limit = limit.checked_add(released).ok_or_else(|| {
                    HarnessError::InvalidInput("pending-owner receive window overflow".into())
                })?;
                let window =
                    Frame::window_update(welcome.epoch, welcome.generation, stream_id, *limit)
                        .encode()
                        .map_err(|error| {
                            HarnessError::Http(format!(
                                "pending-owner backend window encode: {error}"
                            ))
                        })?;
                data.send(Message::Binary(window.into()))
                    .await
                    .map_err(|error| {
                        HarnessError::Http(format!("pending-owner backend window send: {error}"))
                    })?;
            }
            let mut response =
                Vec::with_capacity(canary.len().saturating_add(body.len()).saturating_add(4));
            let response_len =
                u32::try_from(canary.len().saturating_add(body.len())).map_err(|_| {
                    HarnessError::InvalidInput("pending-owner response length overflow".into())
                })?;
            response.extend_from_slice(&response_len.to_be_bytes());
            response.extend_from_slice(canary);
            response.extend_from_slice(&body);
            let data_frame = Frame::data(
                welcome.epoch,
                welcome.generation,
                stream_id,
                1,
                frame.sequence,
                response,
            )
            .encode()
            .map_err(|error| {
                HarnessError::Http(format!("pending-owner backend frame encode: {error}"))
            })?;
            data.send(Message::Binary(data_frame.into()))
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("pending-owner backend response send: {error}"))
                })?;
            let fin = Frame::fin(
                welcome.epoch,
                welcome.generation,
                stream_id,
                2,
                frame.sequence,
            )
            .encode()
            .map_err(|error| {
                HarnessError::Http(format!("pending-owner backend FIN encode: {error}"))
            })?;
            data.send(Message::Binary(fin.into()))
                .await
                .map_err(|error| {
                    HarnessError::Http(format!("pending-owner backend FIN send: {error}"))
                })?;
            Ok(BackendFrameOutcome::ResponseAttempted)
        }
        FrameKind::Ack | FrameKind::WindowUpdate => Ok(BackendFrameOutcome::Continue),
        FrameKind::Fin | FrameKind::Reset if !stream_matches => Ok(BackendFrameOutcome::Continue),
        FrameKind::Fin | FrameKind::Reset => Ok(BackendFrameOutcome::Stop),
    }
}

pub(super) fn spawn_backend(
    mut control: DeviceSocket,
    mut data: DeviceSocket,
    welcome: Welcome,
    service_id: Uuid,
    canary: &'static [u8],
) -> BackendTask {
    let (cancel_tx, mut cancel_rx) = oneshot::channel();
    let (response_attempted_tx, response_attempted_rx) = oneshot::channel();
    BackendTask {
        cancel: Some(cancel_tx),
        response_attempted: Some(response_attempted_rx),
        task: Some(tokio::spawn(async move {
            let service_id_string = service_id.to_string();
            let mut stream_id = None;
            let mut challenge = None;
            let mut authorized = false;
            let mut receive_window_limit = None;
            let mut pending_data = None;
            let mut response_attempted = false;
            // The relay's FIN ends this backend's stream work, but it must not
            // end the backend: the scenario samples the catalog owner while
            // both device sockets are still attached, and returning here would
            // drop them, close the control socket and release the owner lease
            // before that sample.  Keep draining both sockets until the
            // scenario cancels this task.
            let mut stream_stopped = false;
            let mut response_attempted_tx = Some(response_attempted_tx);
            loop {
                if stream_stopped {
                    pending_data = None;
                }
                if authorized
                    && !stream_stopped
                    && let Some(frame) = pending_data.take()
                {
                    let Some(stream_id) = stream_id else {
                        return Err(HarnessError::Http(
                            "pending-owner buffered data lost its OPEN context".into(),
                        ));
                    };
                    match process_authorized_backend_frame(
                        frame,
                        &welcome,
                        stream_id,
                        &mut receive_window_limit,
                        &mut data,
                        canary,
                    )
                    .await?
                    {
                        BackendFrameOutcome::Continue => {}
                        BackendFrameOutcome::ResponseAttempted => {
                            response_attempted = true;
                            if let Some(signal) = response_attempted_tx.take() {
                                let _ = signal.send(());
                            }
                        }
                        BackendFrameOutcome::Stop => stream_stopped = true,
                    }
                    continue;
                }
                tokio::select! {
                    _ = &mut cancel_rx => return Ok(response_attempted),
                    control_item = control.next() => match control_item {
                        Some(Ok(Message::Text(text))) => {
                            let message = decode_control(text.as_bytes()).map_err(|error| HarnessError::Http(format!("pending-owner backend control decode: {error}")))?;
                            match message {
                                ControlMessage::Open(open) => {
                                    if open.session_id != welcome.session_id
                                        || open.epoch != welcome.epoch
                                        || open.service_id != service_id_string
                                        || !matches!(open.operation.as_str(), "echo" | "echo_stream")
                                    {
                                        return Err(HarnessError::Http("pending-owner backend OPEN context mismatch".into()));
                                    }
                                    stream_id = Some(open.stream_id);
                                    receive_window_limit = Some(open.initial_receive_window);
                                send_control(&mut control, &ControlMessage::Opened(tunnel_protocol::Opened::new(
                                    Uuid::new_v4().to_string(),
                                    open.message_id,
                                        welcome.session_id.clone(),
                                        welcome.epoch,
                                        open.stream_id,
                                        open.operation_id,
                                    open.initial_receive_window,
                                    open.initial_send_window,
                                ))).await?;
                                let permission_digest = open
                                    .metadata
                                    .get("permission_digest")
                                    .cloned()
                                    .unwrap_or_else(|| "m2-echo".to_owned());
                                let grant_revision = open
                                    .metadata
                                    .get("grant_revision")
                                    .and_then(|value| value.parse::<u64>().ok())
                                    .unwrap_or_default();
                                let next_challenge = AuthorizationChallenge::new(
                                    Uuid::new_v4().to_string(),
                                    welcome.session_id.clone(),
                                    welcome.epoch,
                                    open.stream_id,
                                    Uuid::new_v4().to_string(),
                                    Uuid::new_v4().to_string(),
                                    open.service_id,
                                    permission_digest,
                                    grant_revision,
                                );
                                send_control(
                                    &mut control,
                                    &ControlMessage::AuthorizationChallenge(
                                        next_challenge.clone(),
                                    ),
                                )
                                .await?;
                                challenge = Some(next_challenge);
                            }
                            ControlMessage::AuthorizationConfirmed(confirmed) => {
                                let Some(challenge) = challenge.as_ref() else {
                                    return Err(HarnessError::Http(
                                        "pending-owner backend received confirmation before challenge".into(),
                                    ));
                                };
                                if confirmed.reply_to != challenge.message_id
                                    || confirmed.session_id != welcome.session_id
                                    || confirmed.epoch != welcome.epoch
                                    || stream_id != Some(confirmed.stream_id)
                                    || confirmed.challenge_id != challenge.challenge_id
                                    || confirmed.nonce != challenge.nonce
                                    || confirmed.permission_digest != challenge.permission_digest
                                    || confirmed.grant_revision != challenge.grant_revision
                                    || !(1..=5_000).contains(&confirmed.remaining_ms)
                                {
                                    return Err(HarnessError::Http(
                                        "pending-owner backend authorization confirmation mismatch".into(),
                                    ));
                                }
                                authorized = true;
                            }
                                ControlMessage::Ping(ping) => {
                                    send_control(&mut control, &ControlMessage::Pong(tunnel_protocol::Pong::new(
                                        Uuid::new_v4().to_string(),
                                        ping.message_id,
                                        ping.session_id,
                                        ping.epoch,
                                        ping.nonce,
                                    ))).await?;
                                }
                                ControlMessage::Rejected(_) | ControlMessage::GoAway(_) => return Ok(false),
                                _ => {}
                            }
                        }
                        Some(Ok(Message::Ping(payload))) => { control.send(Message::Pong(payload)).await.map_err(|error| HarnessError::Http(format!("pending-owner backend control pong: {error}")))?; }
                        Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                        Some(Ok(Message::Close(_))) | None => return Ok(false),
                        Some(Ok(Message::Binary(_))) => return Err(HarnessError::Http("pending-owner backend received binary control data".into())),
                        Some(Err(error)) => return Err(HarnessError::Http(format!("pending-owner backend control read: {error}"))),
                    },
                        data_item = data.next() => match data_item {
                            Some(Ok(Message::Binary(bytes))) => {
                                let frame = Frame::decode(&bytes).map_err(|error| HarnessError::Http(format!("pending-owner backend data decode: {error}")))?;
                                let Some(stream_id) = stream_id else { continue; };
                                let stream_matches = frame.stream_id == stream_id;
                                let scope = pending_owner_frame_scope(frame.kind, stream_matches);
                                let epoch_matches = frame.epoch == welcome.epoch;
                                let generation_matches = frame.generation == welcome.generation;
                                if !epoch_matches || !generation_matches {
                                    return Err(pending_owner_data_context_error(
                                        &frame,
                                        Some(stream_id),
                                        authorized,
                                        epoch_matches,
                                        generation_matches,
                                        scope,
                                    ));
                                }
                                if !authorized {
                                    match frame.kind {
                                        FrameKind::Data => {
                                            if !stream_matches {
                                                return Err(pending_owner_data_context_error(
                                                    &frame,
                                                    Some(stream_id),
                                                    authorized,
                                                    epoch_matches,
                                                    generation_matches,
                                                    scope,
                                                ));
                                            }
                                            // Validate before retaining the one bounded
                                            // application frame.  The record remains
                                            // undispatched until AUTHORIZATION_CONFIRMED.
                                            decode_record(&frame.payload)?;
                                            if pending_data.is_some() {
                                                return Err(HarnessError::Http(
                                                    "pending-owner received multiple unauthorized data frames".into(),
                                                ));
                                            }
                                            pending_data = Some(frame);
                                        }
                                        FrameKind::Ack | FrameKind::WindowUpdate => {}
                                        FrameKind::Fin | FrameKind::Reset if !stream_matches => {}
                                        FrameKind::Fin | FrameKind::Reset => return Ok(false),
                                    }
                                    continue;
                                }
                                match process_authorized_backend_frame(
                                    frame,
                                    &welcome,
                                    stream_id,
                                    &mut receive_window_limit,
                                    &mut data,
                                    canary,
                                )
                                .await?
                                {
                                    BackendFrameOutcome::Continue => {}
                                    BackendFrameOutcome::ResponseAttempted => {
                                        response_attempted = true;
                                        if let Some(signal) = response_attempted_tx.take() {
                                            let _ = signal.send(());
                                        }
                                    }
                                    BackendFrameOutcome::Stop => stream_stopped = true,
                                }
                            }
                        Some(Ok(Message::Ping(payload))) => { data.send(Message::Pong(payload)).await.map_err(|error| HarnessError::Http(format!("pending-owner backend data pong: {error}")))?; }
                        Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                        Some(Ok(Message::Close(_))) | None => return Ok(false),
                        Some(Ok(Message::Text(_))) => return Err(HarnessError::Http("pending-owner backend received text data".into())),
                        Some(Err(error)) => return Err(HarnessError::Http(format!("pending-owner backend data read: {error}"))),
                    },
                }
            }
        })),
    }
}

fn decode_record(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() < 4 {
        return Err(HarnessError::Http(
            "pending-owner request record was truncated".into(),
        ));
    }
    let declared = u32::from_be_bytes(payload[..4].try_into().expect("four-byte length")) as usize;
    if declared != payload.len().saturating_sub(4) {
        return Err(HarnessError::Http(
            "pending-owner request record length mismatch".into(),
        ));
    }
    Ok(payload[4..].to_vec())
}

fn pending_owner_data_context_error(
    frame: &Frame,
    selected_stream_id: Option<u64>,
    authorized: bool,
    epoch_matches: bool,
    generation_matches: bool,
    scope: &str,
) -> HarnessError {
    HarnessError::Http(format!(
        "pending-owner backend data context mismatch: kind={:?}, scope={scope}, authorized={authorized}, epoch_match={epoch_matches}, generation_match={generation_matches}, selected_stream_present={}, stream_matches={}",
        frame.kind,
        selected_stream_id.is_some(),
        selected_stream_id.is_some_and(|selected| frame.stream_id == selected),
    ))
}

async fn join_backend(mut backend: BackendTask) -> Result<bool> {
    let mut task = backend.task.take().ok_or_else(|| {
        HarnessError::Process("pending-owner backend task was already joined".into())
    })?;
    let cancel = backend.cancel.take().ok_or_else(|| {
        HarnessError::Process("pending-owner backend cancellation was already consumed".into())
    })?;
    let response_attempted = backend.response_attempted.take().ok_or_else(|| {
        HarnessError::Process("pending-owner response-attempt signal was already consumed".into())
    })?;
    let _ = cancel.send(());
    let task_result = match timeout(BARRIER_TIMEOUT, &mut task).await {
        Ok(result) => result.map_err(|error| {
            HarnessError::Process(format!("pending-owner backend task failed: {error}"))
        })?,
        Err(_) => {
            task.abort();
            return match timeout(BARRIER_TIMEOUT, &mut task).await {
                Ok(Ok(_)) => Err(HarnessError::Timeout(
                    "pending-owner backend did not join before its abort deadline".into(),
                )),
                Ok(Err(error)) => Err(HarnessError::Process(format!(
                    "pending-owner backend abort join failed: {error}"
                ))),
                Err(_) => Err(HarnessError::Timeout(
                    "pending-owner backend did not join after abort".into(),
                )),
            };
        }
    };
    let response_attempted = match timeout(BARRIER_TIMEOUT, response_attempted).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => false,
        Err(_) => {
            return Err(HarnessError::Timeout(
                "pending-owner response-attempt signal did not arrive before its deadline".into(),
            ));
        }
    };
    Ok(task_result? && response_attempted)
}

#[cfg(test)]
mod tests {
    use super::{
        PendingOwnerEvidence, response_execution_not_dispatched, response_retry_after_ms,
        response_retryable, validate_pending_owner_evidence,
    };
    use crate::acceptance::helpers::HttpResponse;
    use crate::acceptance_test_support::assert_rejected;
    use http::StatusCode;
    use tokio::io::AsyncWriteExt;

    fn valid_evidence() -> PendingOwnerEvidence {
        PendingOwnerEvidence {
            relay_count: 3,
            owner_token_observed: true,
            control_only_pending: true,
            pre_ready_status: 503,
            pre_ready_peer_unavailable: true,
            pre_ready_execution_not_dispatched: true,
            pre_ready_retryable: true,
            pre_ready_retry_after_ms: super::EXPECTED_RETRY_AFTER_MS,
            pre_ready_dispatch_deltas: [0, 0, 0],
            pre_ready_consumer_chunk_read_deltas: [0, 0, 0],
            pre_ready_wss_status: 503,
            pre_ready_wss_upgrade_rejected: true,
            pre_ready_wss_application_body_sent: false,
            pre_ready_wss_peer_unavailable: true,
            pre_ready_wss_execution_not_dispatched: true,
            pre_ready_wss_retryable: true,
            pre_ready_wss_retry_after_ms: super::EXPECTED_RETRY_AFTER_MS,
            pre_ready_wss_retry_after_header_seconds: super::EXPECTED_RETRY_AFTER_SECONDS,
            pre_ready_wss_dispatch_deltas: [0, 0, 0],
            pre_ready_wss_consumer_chunk_read_deltas: [0, 0, 0],
            owner_token_preserved_before_release: true,
            owner_fence_received: true,
            data_attached: true,
            owner_token_preserved_after_release: true,
            post_ready_status: 200,
            post_ready_canary_matched: true,
            post_ready_dispatch_deltas: [1, 0, 0],
            post_ready_consumer_chunk_read_deltas: [1, 0, 0],
            cleanup_joined: true,
        }
    }

    #[test]
    fn validation_accepts_complete_evidence() {
        assert!(validate_pending_owner_evidence(&valid_evidence()).is_ok());
    }

    #[test]
    fn typed_pre_ready_metadata_is_parsed_without_borrowing_json() {
        let response = HttpResponse {
            status: StatusCode::SERVICE_UNAVAILABLE,
            body: br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":true,"retry_after_ms":250}"#.to_vec(),
        };
        assert!(response_execution_not_dispatched(&response));
        assert!(response_retryable(&response));
        assert_eq!(response_retry_after_ms(&response), Some(250));
    }

    #[test]
    fn typed_pre_ready_wss_metadata_is_bounded_and_exact() {
        let body =
            br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":true,"retry_after_ms":250}"#;
        let value = super::parse_wss_error_body(body).expect("bounded WSS error metadata");
        assert_eq!(value["code"], "PEER_UNAVAILABLE");
        assert_eq!(value["execution"], "not_dispatched");
        assert_eq!(value["retryable"], true);
        assert_eq!(value["retry_after_ms"], 250);
    }

    #[tokio::test]
    async fn pending_wss_reader_reassembles_fragmented_headers_and_body() {
        let body =
            br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","retryable":true,"retry_after_ms":250}"#;
        let headers = format!(
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: {}\r\nRetry-After: 1\r\n\r\n",
            body.len()
        );
        let mut response = headers.into_bytes();
        response.extend_from_slice(body);
        let (mut writer, reader) = tokio::io::duplex(256);
        let writer_task = tokio::spawn(async move {
            for chunk in response.chunks(3) {
                writer.write_all(chunk).await.expect("fragment write");
            }
        });
        let parsed = super::read_pending_wss_response(
            reader,
            tokio::time::Instant::now() + std::time::Duration::from_secs(5),
        )
        .await
        .expect("fragmented WSS response");
        writer_task.await.expect("fragment writer joined");
        assert_eq!(parsed.status, 503);
        assert_eq!(parsed.body, body);
        assert_eq!(
            parsed.retry_after_header_seconds,
            Some(super::EXPECTED_RETRY_AFTER_SECONDS)
        );
        assert!(parsed.rejected_before_upgrade);
        assert!(!parsed.application_body_sent);
    }

    #[test]
    fn validation_rejects_each_required_false_gate() {
        type GateDisabler = fn(&mut PendingOwnerEvidence);
        let gates: [(&str, GateDisabler); 16] = [
            ("owner_token_observed", |e| e.owner_token_observed = false),
            ("control_only_pending", |e| e.control_only_pending = false),
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
            ("owner_token_preserved_before_release", |e| {
                e.owner_token_preserved_before_release = false
            }),
            ("owner_fence_received", |e| e.owner_fence_received = false),
            ("data_attached", |e| e.data_attached = false),
            ("owner_token_preserved_after_release", |e| {
                e.owner_token_preserved_after_release = false
            }),
            ("post_ready_canary_matched", |e| {
                e.post_ready_canary_matched = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_pending_owner_evidence(&evidence), name);
        }
    }

    #[test]
    fn validation_rejects_wrong_status_or_dispatch_scope() {
        let mut evidence = valid_evidence();
        evidence.pre_ready_status = 200;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_retry_after_ms = 251;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_wss_status = 200;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_wss_retry_after_ms = 251;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_wss_retry_after_header_seconds = 2;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_wss_dispatch_deltas = [1, 0, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_dispatch_deltas = [1, 0, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_consumer_chunk_read_deltas = [1, 0, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.pre_ready_wss_consumer_chunk_read_deltas = [1, 0, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.post_ready_dispatch_deltas = [0, 1, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.post_ready_consumer_chunk_read_deltas = [0, 1, 0];
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.post_ready_status = 503;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");

        let mut evidence = valid_evidence();
        evidence.relay_count = 2;
        assert_rejected(validate_pending_owner_evidence(&evidence), "pending-owner");
    }
}
