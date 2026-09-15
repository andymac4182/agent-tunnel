//! Production M7 acceptance flow.
//!
//! `cluster_acceptance` is intentionally a contract-level transport fixture:
//! it builds peer runtimes and supplies a synthetic owner callback.  This
//! module exercises the serving boundary instead.  Every relay is started
//! through [`tunnel_relay::ServeConfig::start_with_peer`], every membership
//! record is read from the real Redis directory, and the device is attached
//! through the real client control/data WebSockets.  Public consumer streams
//! enter through two other relays and therefore cross the private HTTP/3 hop
//! to the live owner actor.

use crate::acceptance::helpers::write_device_profile;
use crate::cluster_fixture::{
    M7_MEMBERSHIP_LIFETIME, MembershipLifetimeOptions, MembershipNodeIdentity,
    TestMembershipAuthority,
};
use crate::{
    ClusterFixture, Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions,
    ProcessSpec, ProxyConfig, ProxyHandle, Result, RunningHarness, TcpProxy,
};
use crate::{FanoutProxy, FanoutProxyConfig, FanoutProxyHandle};
use bytes::Bytes;
use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{
    collections::BTreeMap,
    future::Future,
    net::{SocketAddr, ToSocketAddrs},
    path::{Path, PathBuf},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};
use tokio::{
    net::{TcpListener, TcpSocket},
    task::JoinHandle,
    time::{sleep, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, OwnerClaimRequest, RedisMembershipPublisher, SharedCatalog};
use tunnel_client::{ConnectOptions, ConnectionHandle, ConnectionStatus, TransportProfile};
use tunnel_core::RotationConfig;
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    ClusterConfig, ConsumerUpgradeBarrier, ControlAttachBarrier, ListenerSocketOptions,
    MembershipReadiness, MembershipRuntime, MembershipRuntimeConfig, MembershipRuntimeHandle,
    MembershipVersionStateIdentity, MembershipVersionStateStore, PeerAdmissionBarrier,
    PeerFaultEventSnapshot, PeerListenerConfig, PeerReadiness, PeerRouteTarget, PeerRuntime,
    RelayOptions, RelaySnapshot, RunningRelay, ServeConfig,
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    AcceptedSocketDiagnostics, AcceptedSocketOptions, PeerClient, PeerServerStats,
    PeerTransportLimits, SharedPeerPins, SpkiSha256, load_peer_client_config_from_pem,
    load_peer_server_config_from_pem, load_server_config_from_pem,
};
use uuid::Uuid;

mod c11_diagnostics;
mod concurrent_load;
mod i08_goaway_rotation;
mod i08_synthetic_rotation;
mod m7_i08_recovery_attempts;
mod m7_i08_rotation_faults;
mod pending_owner;
pub use c11_diagnostics::{
    C11MatrixReport, OG02_CORRELATION_FIELDS, Og02CorrelationReport, Og02RowReport, Og02Shortfall,
    PEER_FAULT_CAUSES, PEER_FAULT_STAGES, og02_row_shortfall, verify_c11_diagnostics,
    verify_og02_correlation,
};
pub use concurrent_load::{
    ConcurrentLoadEvidence, validate_concurrent_load_evidence, verify as verify_concurrent_load,
};
pub use i08_goaway_rotation::{
    I08GoawayRotationEvidence, validate_i08_goaway_rotation_evidence,
    verify as verify_i08_goaway_rotation,
};
pub use i08_synthetic_rotation::{
    I08Evidence, I08PartialResponseEvidence, I08RotationEvidence, validate_i08_evidence,
    validate_i08_partial_response_evidence, verify as verify_i08_synthetic_rotation,
    verify_partial_response_rotation as verify_i08_partial_response_rotation,
};
pub use m7_i08_recovery_attempts::{
    AttemptObservation, CursorSample, I08RecoveryAttemptEvidence, RecoveryEpisodeEvidence,
    validate_i08_recovery_attempt_evidence, validate_recovery_episode_evidence,
    verify as verify_i08_recovery_attempts,
};
pub use m7_i08_rotation_faults::{
    I08RotationFaultEvidence, validate_i08_rotation_fault_evidence,
    verify as verify_i08_rotation_faults,
};
pub use pending_owner::successor_unready::{
    SuccessorPendingOwnerEvidence, validate_successor_pending_owner_evidence,
    verify as verify_successor_pending_owner,
};
pub use pending_owner::{PendingOwnerEvidence, verify as verify_pending_owner};
mod side_effect;
pub use side_effect::{
    LateResponseEvidence, SideEffectEvidence, validate_late_response_evidence,
    validate_side_effect_evidence,
};
mod fp05;
pub use fp05::{Fp05Evidence, validate_fp05_evidence};
mod pressure;
pub use pressure::PressureEvidence;
mod queue_saturation;
pub use queue_saturation::{QueueSaturationEvidence, validate_queue_saturation_evidence};
mod http_forward_real_path;
pub use http_forward_real_path::{
    HttpForwardRealPathEvidence, validate_http_forward_real_path_evidence,
    verify as verify_http_forward_real_path,
};
mod http_forward_rotation;
pub use http_forward_rotation::{
    AdmissionProbeEvidence, CancelRaceEvidence, GATE_ROTATION, HttpForwardRotationEvidence,
    OutcomeUnknownEvidence, ROTATION_CASES, RotationCaseEvidence, position_matches,
    validate_http_forward_rotation_evidence, verify as verify_http_forward_rotation,
};
mod lifecycle;
pub use lifecycle::{LifecycleEvidence, validate_lifecycle_evidence, verify as verify_lifecycle};
mod key_rotation;
pub use key_rotation::{KeyRotationEvidence, validate_key_rotation_evidence};
mod readiness;
pub use readiness::{PeerReadinessEvidence, validate_peer_readiness_evidence};
mod owner_local_capacity;
pub use owner_local_capacity::{
    OwnerLocalCapacityEvidence, validate_owner_local_capacity_evidence,
    verify as verify_owner_local_capacity,
};
mod readiness_capacity;
pub use readiness_capacity::{
    PeerCapacityEvidence, validate_peer_capacity_evidence, verify as verify_peer_capacity,
};
mod timing_boundaries;
pub use timing_boundaries::{
    TimingBoundaryEvidence, validate_timing_boundary_evidence, verify as verify_timing_boundaries,
};
mod udp_proxy;
use udp_proxy::UdpFaultProxy;
mod chaos;
pub use chaos::{
    ChaosEvidence, InterruptionClass, validate_chaos_evidence, verify as verify_chaos,
};
mod ownership;
pub use ownership::{
    OwnershipEvidence, validate_ownership_evidence, verify as verify_owner_contention,
};
mod owner_lease_expiry;
pub use owner_lease_expiry::{
    OwnerLeaseExpiryEvidence, validate_owner_lease_expiry_evidence,
    verify as verify_owner_lease_expiry,
};
mod tenant_race;
pub use tenant_race::{
    ConcurrentTenantIsolationEvidence, OwnerRaceEvidence,
    validate_concurrent_tenant_isolation_evidence, validate_owner_race_evidence,
};
mod c10;
pub use c10::{
    C10ActualPathEvidence, validate_c10_actual_path_evidence, verify as verify_c10_actual_path,
};
mod ec041_device_attachment;
pub use ec041_device_attachment::{
    Ec041DeviceAttachmentEvidence, validate_ec041_device_attachment_evidence,
    verify as verify_ec041_device_attachment,
};
mod owner_death_admission;
pub use owner_death_admission::{
    Ec023OwnerDeathEvidence, validate_ec023_owner_death_evidence,
    verify as verify_ec023_owner_death,
};
mod handover_peer_grace;
pub use handover_peer_grace::{
    Ec025HandoverEvidence, Ec025TrustCrossing, validate_ec025_handover_evidence,
    verify as verify_ec025_handover,
};
mod public_abandoned_upgrade;
pub use public_abandoned_upgrade::{
    PublicAbandonedUpgradeEvidence, validate_public_abandoned_upgrade_evidence,
    verify as verify_public_abandoned_upgrade,
};
mod admission;
pub use admission::{
    AdmissionEvidence, validate_admission_evidence, verify as verify_public_admission,
};
mod remote_body_limits;
pub use remote_body_limits::{
    RemoteBodyLimitEvidence, validate_remote_body_limit_evidence,
    verify as verify_remote_body_limits,
};
mod i04_fail_closed;
pub use i04_fail_closed::{
    FailClosedEvidence, SentinelOutcome, validate_fail_closed_evidence,
    verify as verify_fail_closed_admission,
};
mod device_revocation;
pub use device_revocation::{
    DeviceRevocationEvidence, validate_device_revocation_evidence, verify_device_revocation,
};
mod credential_expiry_rotation;
pub use credential_expiry_rotation::{
    CredentialExpiryRotationEvidence, validate_credential_expiry_rotation_evidence,
};
mod liveness;
use liveness::{
    CLI_SHUTDOWN_JOIN_BOUND, HeartbeatScope, OwnerLeaseHeartbeat, heartbeat_maximum_interval,
    heartbeat_minimum_interval, join_cli_after_interrupt, owner_lease_ms,
};
pub use liveness::{ProductionLivenessEvidence, validate_production_liveness_evidence};

mod trust_expiry;
pub use trust_expiry::{
    TrustExpiryEvidence, validate_trust_expiry_evidence, verify as verify_trust_expiry,
};
mod membership_hint_drop;
pub use membership_hint_drop::{
    MembershipHintDropEvidence, WithdrawnAdmissionOutcome, validate_membership_hint_drop_evidence,
    verify as verify_membership_hint_drop,
};

const DEPLOYMENT_ID: &str = "m7-production-harness";
const DEPLOYMENT_INCARCATION: &str = "m1-local";
const ROTATION: RotationConfig = RotationConfig {
    interval_seconds: 3,
    handshake_timeout_seconds: 1,
    overlap_seconds: 2,
};
const ROTATION_COUNT: u64 = 3;
/// Owner lease every production-fixture relay is configured with.  It is the
/// `RelayOptions` default spelled out here so the heartbeat bounds in
/// [`liveness`] have a single named configuration source instead of a magic
/// duration, and so changing the fixture's lease policy moves those bounds
/// with it.  The relay renews a session's lease once a third of this has
/// elapsed, which is where the observable heartbeat cadence comes from.
pub(crate) const PRODUCTION_OWNER_LEASE: Duration = Duration::from_secs(30);
const STARTUP_TIMEOUT: Duration = Duration::from_secs(30);
/// Peer HTTP/3 idle timeout applied to every production-fixture relay.  A
/// pooled consumer stream with no transport operation in either direction
/// for this long is cancelled by the transport, so the fixture keeps it short
/// and names it so gates can assert the bound rather than rediscover it.
pub(crate) const PRODUCTION_PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
// The production gate now also runs the duplicate exact-scope owner race with
// three real CLI processes while the same-identifier tenant stays online, so
// the bounded scenario budget covers both phases.
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(240);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);
const REDIS_PARTITION_OPERATION_TIMEOUT: Duration = Duration::from_secs(10);
const REDIS_PARTITION_AUTHORIZATION_WAIT: Duration = Duration::from_secs(6);
/// How often the fixture re-signs and republishes every relay's membership
/// record once re-signing is started.
///
/// The records are signed at the fixture's normal lifetime and the relay's
/// verifier caps a record at the product maximum of 60 seconds, so a scenario
/// that runs longer than that cannot be given a longer record; it has to be
/// given fresh ones.  Nothing in the fixture did that, so a record signed once
/// at bootstrap became an absolute wall-clock deadline measured from cluster
/// startup, and membership trust lapsed partway through any longer run.  That
/// made post-fault recovery depend on *when* in the run the fault landed
/// rather than on the behaviour under test.
///
/// The interval is a small fraction of the record lifetime so a single missed
/// or slow publish cannot expire a record, and it matches how a real control
/// plane re-issues membership well before expiry.
const MEMBERSHIP_RESIGN_INTERVAL: Duration = Duration::from_secs(15);
/// How long publishing may keep failing before the re-signer is treated as
/// broken rather than as riding out a deliberate outage.
///
/// A scenario that pauses Redis on purpose makes the publish fail for as long
/// as the pause lasts, so a re-signer that gave up on the first error would die
/// in exactly the gate that needs it.  It retries instead, and gives up only
/// once the failures have spanned a full record lifetime, because past that the
/// record it would refresh has expired anyway and membership trust really has
/// lapsed.
///
/// This is measured as elapsed time rather than as a count of failed rounds.
/// A count at the normal interval is the same rule only while every retry is
/// exactly one interval apart: four failures at fifteen seconds is sixty
/// seconds precisely, so any slowness pushes an outage that is well inside the
/// lifetime over the threshold.  That is what happened on a loaded machine,
/// where a deliberate six-second pause was reported as a re-signer that had
/// failed for five consecutive rounds.
const MEMBERSHIP_RESIGN_FAILURE_GRACE: Duration =
    Duration::from_secs(M7_MEMBERSHIP_LIFETIME.num_seconds().unsigned_abs());
/// Retry interval while a publish is failing.
///
/// Much shorter than the ordinary interval so a brief outage is ridden out
/// within it rather than consuming whole scheduled rounds.
const MEMBERSHIP_RESIGN_RETRY_INTERVAL: Duration = Duration::from_secs(1);
const REDIS_PARTITION_POLL: Duration = Duration::from_millis(25);
const REDIS_RECOVERY_TIMEOUT: Duration = Duration::from_secs(15);
const PUBLIC_HEALTH_PROBE_TIMEOUT: Duration = Duration::from_secs(2);
const REDIS_PARTITION_OWNER_FENCE_TIMEOUT: Duration = Duration::from_secs(40);
const KEY_REVOCATION_RECOVERY_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_PAUSE_EXCHANGE_TIMEOUT: Duration = Duration::from_secs(8);
const PROCESS_PAUSE_SETTLE_TIMEOUT: Duration = Duration::from_secs(2);
const PROCESS_PAUSE_RECOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const PROCESS_PAUSE_MIN_DURATION: Duration = Duration::from_secs(6);
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_CANARY_BYTES: usize = 256;
const MAX_HEALTH_BODY_BYTES: usize = 256;
const ECHO_SUBPROTOCOL: &str = "agent-tunnel.echo.v1";
const LIVEZ_BODY: &[u8] = br#"{"status":"live"}"#;
const READYZ_BODY: &[u8] = br#"{"status":"ready"}"#;
const UNREADYZ_BODY: &[u8] = br#"{"status":"unready"}"#;

/// Payload-free evidence from one real three-relay run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProductionClusterEvidence {
    /// Number of relays started through the production serve boundary.
    pub relay_count: usize,
    /// Number of tenant scopes present in the Redis fixture.
    pub tenant_count: usize,
    /// Number of enrolled device identities in the Redis fixture.  This is
    /// fixture context; live tenant isolation is proved separately below.
    pub device_count: usize,
    /// Number of signed membership records read by each relay.
    pub signed_membership_records: usize,
    /// Number of relays whose membership runtime reached `Ready`.
    pub membership_ready_relays: usize,
    /// Number of non-owner ingress relays that completed a consumer exchange.
    pub h3_ingress_relays: usize,
    /// Number of real control WebSockets opened by the client.
    pub control_sockets: usize,
    /// Number of real data WebSockets opened by the client over the full run.
    pub data_sockets: usize,
    /// Number of distinct relay listeners that accepted device sockets.
    pub device_ingress_relays: usize,
    /// Whether the built `tunnel-client` CLI opened a real control/data pair.
    pub cli_control_data_sockets: bool,
    /// Number of actual committed M2 replacement generations observed.
    pub replacement_generations: usize,
    /// Number of ordered application records sent on one stream.
    pub ordered_records: usize,
    /// Whether expired OIDC and an unauthorized grant were rejected at ingress.
    pub authorization_negatives_rejected: bool,
    /// Whether both tenants used the same device/service UUIDs concurrently,
    /// with distinct device certificates and response canaries.  This flag is
    /// now derived from [`Self::tenant_isolation`] rather than asserted on its
    /// own, so an offline tenant-B device or a `503` accepted in place of a
    /// routed canary cannot satisfy it.
    pub same_uuid_tenant_isolation_verified: bool,
    /// Structured evidence that both same-identifier tenant sessions were
    /// simultaneously online with exact, distinct canaries, separated owners
    /// and the full rotation bound each.
    pub tenant_isolation: ConcurrentTenantIsolationEvidence,
    /// Structured evidence from the duplicate exact-scope owner race that ran
    /// while the other tenant's same-identifier session stayed online.
    pub owner_race: OwnerRaceEvidence,
    /// Whether a competing owner and stale release were fenced by Redis.
    pub stale_owner_rejected: bool,
    /// Whether removing the dynamic signed-peer pin set blocked H3 routing.
    pub key_revocation_rejected: bool,
    /// Whether owner shutdown produced an explicit no-owner interruption.
    pub owner_death_interrupted: bool,
    /// IN-10/OG-05 heartbeat, liveness/readiness and bounded CLI shutdown
    /// evidence recorded from the real CLI and relay during this run.
    pub liveness: ProductionLivenessEvidence,
    /// Wall-clock seconds elapsed before the three replacement generations.
    pub elapsed_seconds: u64,
}

/// Evidence from a real production Redis connectivity partition and recovery.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RedisPartitionEvidence {
    /// Number of production relays serving during the partition.
    pub relay_count: usize,
    /// Whether an authorized consumer stream worked before the partition.
    pub baseline_echo: bool,
    /// Whether new consumer admission failed closed during the partition.
    pub partition_admission_rejected: bool,
    /// Whether an already-admitted stream stopped dispatch after its bounded
    /// authorization deadline rather than returning an echo.
    pub partition_dispatch_interrupted: bool,
    /// Number of proxied Redis sockets paused, including sockets discovered
    /// after the initial partition snapshot.
    pub paused_redis_connections: usize,
    /// Whether Redis-backed ownership remained authoritative after recovery.
    pub recovery_owner_verified: bool,
    /// Whether a fresh post-recovery consumer stream returned its canary.
    pub recovery_echo: bool,
    /// Whether the public Axum `/livez` endpoint remained HTTP 200 during the
    /// Redis partition with its bounded redacted response body.
    pub public_livez_ok_during_partition: bool,
    /// Whether the public Axum `/readyz` endpoint failed closed with HTTP 503
    /// and its bounded redacted response body during the partition.
    pub public_readyz_unready_during_partition: bool,
    /// Whether the public Axum `/readyz` endpoint returned HTTP 200 with its
    /// bounded redacted response body after Redis connectivity was restored.
    pub public_readyz_ok_after_recovery: bool,
    /// Wall-clock milliseconds spent in the bounded partition phase.
    pub partition_elapsed_ms: u64,
}

/// Evidence from the bounded real CLI process-pause gate.
///
/// The paused probe is deliberately reported as a transport/application
/// interruption plus the relay's redacted dispatch counter.  A successful
/// echo is the only synthetic application effect in this fixture; the probe
/// must not produce one, and a fresh CLI epoch must return a canary after the
/// old process is joined.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProcessPauseEvidence {
    /// Number of production relays serving during the pause gate.
    pub relay_count: usize,
    /// The initial built CLI control/data pair completed a routed canary.
    pub cli_control_data_sockets: bool,
    /// The pause signal targeted a live PID owned by ManagedProcess.
    pub paused_pid_validated: bool,
    /// The sent probe ended in an explicit bounded close/transport outcome.
    pub pause_fail_closed: bool,
    /// The owner actor's lifetime application-dispatch counter did not
    /// advance while the managed process was stopped.  This is relay
    /// no-forward evidence, not a claim about desktop side effects.
    pub relay_dispatch_counter_unchanged: bool,
    /// The old process received CONT before its bounded join completed.
    pub resumed_and_joined: bool,
    /// The fresh CLI session claimed the same scope with a higher epoch.
    pub recovery_owner_verified: bool,
    /// The fresh CLI session returned its canary over the same production
    /// consumer route.
    pub recovery_echo: bool,
    /// The old paused payload was not returned by the fresh session.
    pub stale_payload_not_replayed: bool,
    /// Maximum number of simultaneously open device fanout sockets observed.
    pub fanout_peak_open: usize,
    /// Wall-clock milliseconds spent in the pause/recovery scenario.
    pub pause_elapsed_ms: u64,
}

/// Run the production M7 three-relay acceptance gate.
pub async fn verify() -> Result<ProductionClusterEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("production M7 harness startup timed out".into()))??;

    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, cluster.run(&harness)).await {
        Ok(Ok(evidence)) => validate_production_evidence(&evidence).map(|()| evidence),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(HarnessError::Timeout(
            "production M7 cluster scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// Run the bounded production peer-route loss/recovery gate.
pub async fn verify_peer_readiness_loss() -> Result<PeerReadinessEvidence> {
    let evidence = readiness::verify().await?;
    validate_peer_readiness_evidence(&evidence)?;
    Ok(evidence)
}

/// Run the bounded production Redis partition/recovery gate.
///
/// This intentionally uses a separate Redis proxy and scenario so the normal
/// three-relay production gate remains unchanged.  The proxy pauses both
/// directions of every active Redis socket and discovers/pauses new sockets
/// while the partition is active; it never mutates Redis data.
pub async fn verify_redis_partition() -> Result<RedisPartitionEvidence> {
    let base_options = HarnessOptions::from_env()?;
    let upstream_url =
        base_options
            .redis_url
            .clone()
            .ok_or_else(|| HarnessError::MissingRedisUrl {
                env_var: "TEST_REDIS_URL",
                guidance:
                    "The Redis partition gate requires TEST_REDIS_URL for its opaque TCP proxy."
                        .to_owned(),
            })?;
    let target = redis_target_address(&upstream_url)?;
    let redis_proxy = TcpProxy::bind(target, ProxyConfig::default()).await?;
    let proxy_url = format!("redis://{}", redis_proxy.local_addr());
    let options = base_options
        .redis_url(proxy_url)
        .namespace_prefix("m7-redis-partition")
        .rotation(ROTATION);
    let mut harness = match timeout(STARTUP_TIMEOUT, Harness::start(options)).await {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => {
            let _ = redis_proxy.shutdown().await;
            return Err(error);
        }
        Err(_) => {
            let _ = redis_proxy.shutdown().await;
            return Err(HarnessError::Timeout(
                "production Redis partition harness startup timed out".into(),
            ));
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            let _ = redis_proxy.shutdown().await;
            return Err(error);
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        cluster.run_redis_partition(&harness, &redis_proxy),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "production Redis partition scenario exceeded its bounded deadline".into(),
        )),
    };
    // The scenario always resumes the proxy before returning so catalog
    // namespace cleanup remains authoritative and bounded.
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    // Retain the proxy's accept-task owner through its final joined shutdown.
    let proxy_cleanup = redis_proxy.shutdown().await;
    push_cleanup_error(&mut cleanup_errors, "Redis proxy cleanup", proxy_cleanup);
    let evidence = finish_scenario_with_cleanup(scenario, cleanup_errors)?;
    validate_redis_partition_evidence(&evidence)?;
    Ok(evidence)
}

/// Run the bounded real CLI process-pause/recovery gate.
///
/// This is separate from [`verify`] so the normal production acceptance
/// remains a stable three-rotation run.  The gate pauses only the synthetic
/// `tunnel-client` child created by [`ManagedProcess`], waits past the
/// challenge authorization window, checks an explicit bounded interruption
/// and an unchanged relay dispatch counter, resumes and joins that child,
/// then requires a fresh higher-epoch CLI canary.
pub async fn verify_process_pause() -> Result<ProcessPauseEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("process-pause harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, cluster.run_process_pause(&harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "process-pause production scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// Run one admitted synthetic ordered-stream application effect through a selected peer
/// failure. The fixture keeps application execution separate from transport
/// receipt and verifies that the operation is never invoked a second time.
pub async fn verify_side_effect() -> Result<SideEffectEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(RotationConfig::default())
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("side-effect harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; side-effect startup cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        side_effect::verify(&mut cluster, &harness),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "side-effect scenario timed out".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    let evidence = finish_scenario_with_cleanup(scenario, cleanup_errors)?;
    validate_side_effect_evidence(&evidence)?;
    Ok(evidence)
}

/// Run the standalone late DATA/FIN boundary through the same production
/// cluster lifecycle as the ordinary side-effect command.  The late fixture
/// owns only its device, consumer, and peer-fault resources; this wrapper
/// always joins relay/catalog cleanup before returning evidence or an error.
pub async fn verify_side_effect_late() -> Result<LateResponseEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(RotationConfig::default())
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("late side-effect harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; late side-effect startup cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    // The fixture owns device/consumer/fault tasks and has per-operation
    // absolute deadlines.  Await it directly so cancellation cannot drop
    // those owned handles before its cleanup path runs.
    let scenario = side_effect::verify_late_response(&mut cluster, &harness).await;
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "late side-effect relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "late side-effect catalog cleanup",
        harness.shutdown().await,
    );
    let evidence = finish_scenario_with_cleanup(scenario, cleanup_errors)?;
    validate_late_response_evidence(&evidence)?;
    Ok(evidence)
}

/// Verify one admitted synthetic append and a held sibling through owner loss.
pub async fn verify_owner_loss_effect() -> Result<Fp05Evidence> {
    let options = HarnessOptions::from_env()?
        .rotation(RotationConfig::default())
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("owner-loss effect harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(primary) => {
            return match harness.shutdown().await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; owner-loss effect startup cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let scenario = match timeout(SCENARIO_TIMEOUT, fp05::verify(&mut cluster, &harness)).await {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "owner-loss effect scenario timed out".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    let evidence = finish_scenario_with_cleanup(scenario, cleanup_errors)?;
    validate_fp05_evidence(&evidence)?;
    Ok(evidence)
}

/// Run the bounded production three-relay resource-pressure and cancellation
/// gate.  This uses a real CLI/client session, an independent non-owner H3
/// consumer stream, Redis ownership, and a fresh post-cancellation canary.
pub async fn verify_pressure() -> Result<PressureEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("pressure harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, pressure::run(&mut cluster, &harness)).await {
        Ok(Ok(evidence)) => pressure::validate_pressure_evidence(&evidence).map(|()| evidence),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(HarnessError::Timeout(
            "production pressure scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// Run the configured message-queue saturation gate.
///
/// The rotation schedule is deliberately slower than the shared production
/// `ROTATION`: the saturation window must not collide with a scheduled
/// handover, and the correlated rotation must still fire inside the scenario
/// deadline.  See `queue_saturation` for the workload derivation.
pub async fn verify_queue_saturation() -> Result<QueueSaturationEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(queue_saturation::SATURATION_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("queue saturation harness startup timed out".into())
        })??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(
        SCENARIO_TIMEOUT,
        queue_saturation::run(&mut cluster, &harness),
    )
    .await
    {
        Ok(result) => result.and_then(|evidence| {
            validate_queue_saturation_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "queue saturation scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

/// Run the phase-observed peer-key revocation during scheduled M2 rotation
/// gate.  This is separate from the ordinary production flow; the focused
/// scenario fails closed if its post-withdrawal phase revalidation observes
/// that the rotation committed before the fault was exercised.
pub async fn verify_key_revocation_during_rotation() -> Result<KeyRotationEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| HarnessError::Timeout("key-rotation harness startup timed out".into()))??;
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let _ = harness.shutdown().await;
            return Err(error);
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, key_rotation::run(&mut cluster, &harness)).await
    {
        Ok(result) => result.and_then(|evidence| {
            validate_key_rotation_evidence(&evidence)?;
            Ok(evidence)
        }),
        Err(_) => Err(HarnessError::Timeout(
            "key-rotation scenario exceeded its bounded deadline".into(),
        )),
    };
    let mut cleanup_errors = Vec::new();
    push_cleanup_error(
        &mut cleanup_errors,
        "relay cleanup",
        cluster.shutdown().await,
    );
    push_cleanup_error(
        &mut cleanup_errors,
        "catalog cleanup",
        harness.shutdown().await,
    );
    finish_scenario_with_cleanup(scenario, cleanup_errors)
}

fn push_cleanup_error(errors: &mut Vec<String>, label: &str, result: Result<()>) {
    if let Err(error) = result {
        errors.push(format!("{label}: {error}"));
    }
}

fn finish_scenario_with_cleanup<T>(scenario: Result<T>, cleanup_errors: Vec<String>) -> Result<T> {
    if cleanup_errors.is_empty() {
        return scenario;
    }
    let cleanup = cleanup_errors.join("; ");
    match scenario {
        Ok(_) => Err(HarnessError::Process(format!("cleanup failed: {cleanup}"))),
        Err(primary) => Err(HarnessError::Process(format!(
            "{primary}; cleanup failed: {cleanup}"
        ))),
    }
}

/// Run the bounded consumer-credential expiry intersection while one scheduled
/// carrier rotation is active.  The staged fixture is a synthetic echo service
/// over the real three-relay/public route; it does not claim a deployed adapter.
pub async fn verify_credential_expiry_rotation() -> Result<CredentialExpiryRotationEvidence> {
    let options = HarnessOptions::from_env()?
        .rotation(credential_expiry_rotation::EXPIRY_ROTATION)
        .shared_device_uuid(true);
    let mut harness = timeout(STARTUP_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("credential-expiry rotation harness startup timed out".into())
        })??;
    let (catalog, authorization_gate) = match credential_expiry_rotation::gated_catalog(&harness) {
        Ok(value) => value,
        Err(primary) => {
            let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; credential-expiry rotation catalog setup cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    let mut cluster = match ProductionCluster::start_with_catalog(&mut harness, catalog).await {
        Ok(cluster) => cluster,
        Err(primary) => {
            let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
            return match harness.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(primary),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{primary}; credential-expiry rotation startup cleanup failed: {cleanup}"
                ))),
            };
        }
    };
    // The fixture owns a connection-scoped rotation hold and releases it
    // before returning.  A consuming timeout here could cancel that future
    // before its explicit resume/cleanup path runs.
    let scenario =
        credential_expiry_rotation::verify(&mut cluster, &harness, &authorization_gate).await;
    let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let mut cleanup_errors = Vec::new();
    if let Err(error) = cluster_cleanup {
        cleanup_errors.push(format!("relay cleanup: {error}"));
    }
    if let Err(error) = harness_cleanup {
        cleanup_errors.push(format!("catalog cleanup: {error}"));
    }
    match scenario {
        Err(primary) if !cleanup_errors.is_empty() => Err(HarnessError::Process(format!(
            "{primary}; credential-expiry rotation cleanup failed: {}",
            cleanup_errors.join("; ")
        ))),
        Err(primary) => Err(primary),
        Ok(_) if !cleanup_errors.is_empty() => Err(HarnessError::Process(format!(
            "credential-expiry rotation cleanup failed: {}",
            cleanup_errors.join("; ")
        ))),
        Ok(evidence) => {
            validate_credential_expiry_rotation_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

fn redis_target_address(url: &str) -> Result<SocketAddr> {
    let client = redis::Client::open(url).map_err(|error| HarnessError::InvalidRedisUrl {
        message: error.to_string(),
    })?;
    let (host, port) = match client.get_connection_info().addr() {
        redis::ConnectionAddr::Tcp(host, port) => (host.to_owned(), *port),
        redis::ConnectionAddr::TcpTls { host, port, .. } => (host.to_owned(), *port),
        _ => {
            return Err(HarnessError::Unsupported(
                "Redis partition gate requires a TCP Redis URL".into(),
            ));
        }
    };
    (host.as_str(), port)
        .to_socket_addrs()
        .map_err(|error| HarnessError::InvalidRedisUrl {
            message: format!("resolving Redis endpoint {host}:{port}: {error}"),
        })?
        .next()
        .ok_or_else(|| HarnessError::InvalidRedisUrl {
            message: format!("Redis endpoint {host}:{port} resolved to no addresses"),
        })
}

struct PublicHealthResponse {
    status: u16,
    body: Vec<u8>,
}

/// Query one of the production relay's public Axum health routes over the
/// same TLS listener used by consumer ingress.  The body collector is capped
/// and callers compare it to the fixed redacted health envelope without
/// including body bytes in diagnostics.
async fn public_health_request(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    path: &'static str,
) -> Result<PublicHealthResponse> {
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("health relay CA: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("health TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout(
        PUBLIC_HEALTH_PROBE_TIMEOUT,
        tokio::net::TcpStream::connect(consumer_addr),
    )
    .await
    .map_err(|_| HarnessError::Timeout("public health TCP connect timed out".into()))?
    .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("health server name: {error}")))?;
    let tls_stream = timeout(
        PUBLIC_HEALTH_PROBE_TIMEOUT,
        connector.connect(server_name, stream),
    )
    .await
    .map_err(|_| HarnessError::Timeout("public health TLS handshake timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("public health TLS handshake: {error}")))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
        .await
        .map_err(|error| HarnessError::Http(format!("public health HTTP handshake: {error}")))?;
    let mut connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result: Result<PublicHealthResponse> = async {
        let request = Request::builder()
            .method("GET")
            .uri(format!("https://localhost{path}"))
            .header("host", "localhost")
            .body(Full::new(Bytes::new()))
            .map_err(|error| {
                HarnessError::Http(format!("building public health request: {error}"))
            })?;
        let response = timeout(PUBLIC_HEALTH_PROBE_TIMEOUT, sender.send_request(request))
            .await
            .map_err(|_| HarnessError::Timeout("public health request timed out".into()))?
            .map_err(|error| {
                HarnessError::Http(format!("public health request failed: {error}"))
            })?;
        let status = response.status().as_u16();
        let body = timeout(
            PUBLIC_HEALTH_PROBE_TIMEOUT,
            Limited::new(response.into_body(), MAX_HEALTH_BODY_BYTES).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("reading public health response timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("reading public health response: {error}")))?
        .to_bytes()
        .to_vec();
        Ok(PublicHealthResponse { status, body })
    }
    .await;
    drop(sender);
    if timeout(PUBLIC_HEALTH_PROBE_TIMEOUT, &mut connection_task)
        .await
        .is_err()
    {
        connection_task.abort();
        let _ = connection_task.await;
    }
    result
}

fn validate_public_health_response(
    response: &PublicHealthResponse,
    path: &'static str,
    expected_status: u16,
    expected_body: &[u8],
) -> Result<()> {
    if response.status != expected_status || response.body.as_slice() != expected_body {
        return Err(HarnessError::Http(format!(
            "public health {path} returned unexpected status {} or bounded body length {}",
            response.status,
            response.body.len()
        )));
    }
    Ok(())
}

/// Bounded wait for readiness to fail closed after a peer route is lost.  It
/// matches the C20 peer-readiness gate's own loss deadline; it is a timeout,
/// not an asserted bound.
const PEER_ROUTE_READINESS_TIMEOUT: Duration = Duration::from_secs(12);
const HEALTH_SPLIT_POLL: Duration = Duration::from_millis(100);

/// Counted `/livez` and `/readyz` observations from one production run.
#[derive(Clone, Copy, Debug, Default)]
struct HealthSplitObservation {
    livez_probes: usize,
    livez_live: usize,
    readyz_probes: usize,
    readyz_ready: usize,
    readyz_unready: usize,
    liveness_up_while_readiness_false: bool,
}

/// Probe one relay's public `/livez` and `/readyz` once and classify both
/// answers into the fixed redacted envelopes.  Returns whether liveness
/// answered live and whether readiness failed closed.
async fn probe_health_pair(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    observation: &mut HealthSplitObservation,
) -> Result<(bool, bool)> {
    let live = public_health_request(consumer_addr, server_ca_der, "/livez").await?;
    observation.livez_probes += 1;
    let live_ok = validate_public_health_response(&live, "/livez", 200, LIVEZ_BODY).is_ok();
    if live_ok {
        observation.livez_live += 1;
    }
    let ready = public_health_request(consumer_addr, server_ca_der, "/readyz").await?;
    observation.readyz_probes += 1;
    let ready_ok = validate_public_health_response(&ready, "/readyz", 200, READYZ_BODY).is_ok();
    let unready_ok = validate_public_health_response(&ready, "/readyz", 503, UNREADYZ_BODY).is_ok();
    match (ready_ok, unready_ok) {
        (true, false) => observation.readyz_ready += 1,
        (false, true) => observation.readyz_unready += 1,
        _ => {
            return Err(HarnessError::Http(format!(
                "public /readyz returned neither the ready nor the unready envelope: status {}",
                ready.status
            )));
        }
    }
    if live_ok && unready_ok {
        observation.liveness_up_while_readiness_false = true;
    }
    Ok((live_ok, unready_ok))
}

async fn assert_public_health_ready(consumer_addr: SocketAddr, server_ca_der: &[u8]) -> Result<()> {
    let live = public_health_request(consumer_addr, server_ca_der, "/livez").await?;
    validate_public_health_response(&live, "/livez", 200, LIVEZ_BODY)?;
    let ready = public_health_request(consumer_addr, server_ca_der, "/readyz").await?;
    validate_public_health_response(&ready, "/readyz", 200, READYZ_BODY)
}

async fn assert_public_health_unready(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
) -> Result<()> {
    let live = public_health_request(consumer_addr, server_ca_der, "/livez").await?;
    validate_public_health_response(&live, "/livez", 200, LIVEZ_BODY)?;
    let ready = public_health_request(consumer_addr, server_ca_der, "/readyz").await?;
    validate_public_health_response(&ready, "/readyz", 503, UNREADYZ_BODY)
}

async fn wait_for_public_health_ready(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
) -> Result<()> {
    let deadline = Instant::now() + REDIS_RECOVERY_TIMEOUT;
    loop {
        let live = public_health_request(consumer_addr, server_ca_der, "/livez").await;
        let ready = public_health_request(consumer_addr, server_ca_der, "/readyz").await;
        if let (Ok(live), Ok(ready)) = (live, ready)
            && live.status == 200
            && live.body.as_slice() == LIVEZ_BODY
            && ready.status == 200
            && ready.body.as_slice() == READYZ_BODY
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "public /readyz did not recover before the Redis recovery deadline".into(),
            ));
        }
        sleep(REDIS_PARTITION_POLL).await;
    }
}

fn validate_production_evidence(evidence: &ProductionClusterEvidence) -> Result<()> {
    let required_flags = [
        (
            "cli_control_data_sockets",
            evidence.cli_control_data_sockets,
        ),
        (
            "authorization_negatives_rejected",
            evidence.authorization_negatives_rejected,
        ),
        (
            "same_uuid_tenant_isolation_verified",
            evidence.same_uuid_tenant_isolation_verified,
        ),
        ("stale_owner_rejected", evidence.stale_owner_rejected),
        ("key_revocation_rejected", evidence.key_revocation_rejected),
        ("owner_death_interrupted", evidence.owner_death_interrupted),
    ];
    if let Some((name, false)) = required_flags.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "production M7 required gate {name} was false"
        )));
    }

    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "production M7 requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    let minimum_counts = [
        (
            "signed_membership_records",
            evidence.signed_membership_records,
            evidence.relay_count,
        ),
        (
            "membership_ready_relays",
            evidence.membership_ready_relays,
            evidence.relay_count,
        ),
        ("h3_ingress_relays", evidence.h3_ingress_relays, 2),
        ("control_sockets", evidence.control_sockets, 3),
        (
            "data_sockets",
            evidence.data_sockets,
            ROTATION_COUNT as usize + 3,
        ),
        ("device_ingress_relays", evidence.device_ingress_relays, 3),
        (
            "replacement_generations",
            evidence.replacement_generations,
            ROTATION_COUNT as usize,
        ),
        (
            "ordered_records",
            evidence.ordered_records,
            ROTATION_COUNT as usize + 1,
        ),
    ];
    if let Some((name, observed, minimum)) = minimum_counts
        .into_iter()
        .find(|(_, observed, minimum)| observed < minimum)
    {
        return Err(HarnessError::Process(format!(
            "production M7 evidence {name}={observed} is below required minimum {minimum}"
        )));
    }
    let minimum_elapsed = ROTATION.interval_seconds.saturating_mul(ROTATION_COUNT);
    if evidence.elapsed_seconds < minimum_elapsed {
        return Err(HarnessError::Process(format!(
            "production M7 elapsed_seconds={} is below the real rotation bound {minimum_elapsed}",
            evidence.elapsed_seconds
        )));
    }
    // The structured same-identifier isolation and duplicate-owner race
    // contracts are mandatory parts of this gate, not optional extras.
    validate_concurrent_tenant_isolation_evidence(&evidence.tenant_isolation, ROTATION_COUNT)?;
    validate_owner_race_evidence(&evidence.owner_race)?;
    // IN-10/OG-05: heartbeat, liveness/readiness and the measured bounded
    // shutdown join are mandatory parts of this gate too.
    validate_production_liveness_evidence(&evidence.liveness)?;
    // The legacy summary flag must agree with the structured evidence.
    if !evidence.same_uuid_tenant_isolation_verified {
        return Err(HarnessError::Process(
            "production M7 same_uuid_tenant_isolation_verified disagrees with its structured evidence".into(),
        ));
    }
    Ok(())
}

/// Validate every mandatory gate from the real Redis partition scenario.
///
/// The CLI repeats these checks for a user-facing diagnostic, but keeping the
/// validator in this module makes the public health assertions mandatory even
/// when a caller uses [`verify_redis_partition`] directly.
pub fn validate_redis_partition_evidence(evidence: &RedisPartitionEvidence) -> Result<()> {
    let required_flags = [
        ("baseline_echo", evidence.baseline_echo),
        (
            "partition_admission_rejected",
            evidence.partition_admission_rejected,
        ),
        (
            "partition_dispatch_interrupted",
            evidence.partition_dispatch_interrupted,
        ),
        (
            "public_livez_ok_during_partition",
            evidence.public_livez_ok_during_partition,
        ),
        (
            "public_readyz_unready_during_partition",
            evidence.public_readyz_unready_during_partition,
        ),
        (
            "public_readyz_ok_after_recovery",
            evidence.public_readyz_ok_after_recovery,
        ),
        ("recovery_owner_verified", evidence.recovery_owner_verified),
        ("recovery_echo", evidence.recovery_echo),
    ];
    if let Some((name, false)) = required_flags.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "Redis partition required gate {name} was false"
        )));
    }
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "Redis partition requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.paused_redis_connections == 0 {
        return Err(HarnessError::Process(
            "Redis partition paused no Redis connections".into(),
        ));
    }
    Ok(())
}

/// Identifiers and exact canaries for the cross-tenant leak probe.  The device
/// and service UUIDs are deliberately one shared pair.
struct CrossTenantProbe<'a> {
    device_id: Uuid,
    service_id: Uuid,
    tenant_a_token: &'a str,
    tenant_b_token: &'a str,
    tenant_a_canary: &'a [u8],
    tenant_b_canary: &'a [u8],
}

struct KeyRevocationProbe<'a> {
    harness: &'a RunningHarness,
    consumer_addr: SocketAddr,
    token: &'a str,
    device_id: Uuid,
    service_id: Uuid,
    canary: &'a [u8],
    recovery_config: &'a tunnel_client::ConnectConfig,
    client: &'a ConnectionHandle,
}

struct ProductionCluster {
    fixture: ClusterFixture,
    _files: TempDir,
    relays: Vec<ProductionRelay>,
    peer_proxies: BTreeMap<String, UdpFaultProxy>,
    device_fanout: FanoutProxyHandle,
    tenant_b_fanout: FanoutProxyHandle,
    catalog: SharedCatalog,
    membership_records: usize,
    checkpoint_authority: Arc<FixtureCheckpointAuthority>,
    /// Everything a background re-signer needs to keep issuing fresh
    /// membership records, captured at startup while the harness is in scope.
    membership_resign_inputs: MembershipResignInputs,
    membership_resign_cancel: CancellationToken,
    membership_resign: Option<JoinHandle<()>>,
    /// First error the re-signer hit, if any.  A re-signer that died silently
    /// would turn into flakiness in whatever gate relied on it, so the failure
    /// is kept and surfaced instead of logged and forgotten.
    membership_resign_error: Arc<Mutex<Option<String>>>,
}

/// Startup-captured inputs for the membership re-signer.
#[derive(Clone)]
struct MembershipResignInputs {
    redis_url: String,
    redis_namespace: String,
    deployment_id: String,
    deployment_incarnation: String,
    /// Node identity and the peer endpoint its record advertises, in the same
    /// order the bootstrap records were signed.
    nodes: Vec<(MembershipNodeIdentity, SocketAddr)>,
    /// Record version the next re-signing round issues.  Bootstrap published
    /// version 1, and the verifier replaces a record only with a newer one.
    next_record_version: u64,
}

/// Inputs for one bounded IN-10/OG-05 CLI shutdown-join measurement.
#[derive(Clone, Copy)]
struct CliShutdownJoinContext<'a> {
    harness: &'a RunningHarness,
    device: &'a crate::fixture::DeviceFixture,
    service_id: Uuid,
    canary: &'a str,
    token: &'a str,
    consumer_addr: SocketAddr,
}

struct ProductionRelay {
    node_id: String,
    peer_source_addr: SocketAddr,
    running: Option<RunningRelay>,
    membership: Arc<MembershipRuntime>,
    membership_handle: Option<MembershipRuntimeHandle>,
    pins: SharedPeerPins,
    peer_runtime: Arc<PeerRuntime>,
    peer_capacity: usize,
    consumer_socket_diagnostics: Option<AcceptedSocketDiagnostics>,
    peer_refresh_cancel: CancellationToken,
    peer_refresh: Option<JoinHandle<()>>,
}

fn private_fixture_directory() -> Result<TempDir> {
    let files = tempdir().map_err(HarnessError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        std::fs::set_permissions(files.path(), std::fs::Permissions::from_mode(0o700))
            .map_err(HarnessError::Io)?;
        let metadata = std::fs::symlink_metadata(files.path()).map_err(HarnessError::Io)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(HarnessError::Process(
                "production fixture state directory is not a directory".into(),
            ));
        }
        if metadata.permissions().mode() & 0o7777 != 0o700 {
            return Err(HarnessError::Process(
                "production fixture state directory is not private".into(),
            ));
        }
    }
    let path = files.path().to_string_lossy();
    crate::c11_capture::record_sentinel("filesystem_path", path.as_bytes())?;
    Ok(files)
}

/// One relay's latest bounded peer-fault tuple for a stage, joined with the
/// node that recorded it and that stage's saturating count.
#[derive(Clone, Debug)]
pub(crate) struct RelayPeerFaultStage {
    pub(crate) node_id: String,
    pub(crate) stage: &'static str,
    pub(crate) count: u64,
    pub(crate) event: PeerFaultEventSnapshot,
}

/// The bounded correlation a gate requires of the tuple it induced.
///
/// Only identifiers the gate itself chose are named here: the relay mints the
/// peer `request_id` internally, so it is required to be present rather than
/// to equal a value the gate could not know.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PeerFaultCorrelation<'a> {
    pub(crate) tenant_id: Uuid,
    pub(crate) device_id: Uuid,
    /// When set, the tuple must name this relay as the selected owner.
    pub(crate) owner_node_id: Option<&'a str>,
    /// When set, the tuple's owner epoch must equal this claim's epoch.
    pub(crate) owner_epoch: Option<u64>,
    /// When set, the tuple must carry this exact service identifier.
    pub(crate) service_id: Option<Uuid>,
    /// Require a bounded session identifier and a peer request identifier.
    /// A fault raised before an owner token is selected carries neither.
    pub(crate) require_request_identity: bool,
}

/// The summed `stage_counts` entry for one stage label across every relay.
///
/// A gate takes this before and after the fault it induces so it asserts the
/// stage was *gained*, never that the cluster happens to carry one.
pub(crate) fn peer_fault_stage_count(stages: &[RelayPeerFaultStage], stage: &str) -> u64 {
    stages
        .iter()
        .filter(|candidate| candidate.stage == stage)
        .map(|candidate| candidate.count)
        .sum()
}

/// Render every observed stage tuple for a diagnostic message.
pub(crate) fn format_peer_fault_stages(stages: &[RelayPeerFaultStage]) -> String {
    if stages.is_empty() {
        return "none".to_owned();
    }
    stages
        .iter()
        .map(|stage| {
            format!(
                "{}:{}/{}/{}x{}",
                stage.node_id,
                stage.event.role.as_str(),
                stage.stage,
                stage.event.cause.as_str(),
                stage.count,
            )
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Require exactly one bounded `role/stage/cause` tuple with the correlation
/// identifiers of the request the gate issued.
///
/// `stage_counts` must have *gained* the stage against the pre-fault reading
/// in `before`, and `last_by_stage[stage]` must carry the gate's own scope.
/// The failure text lists everything that was observed instead, so a gate that
/// stops producing the fault reports what it produced rather than a bare
/// absence.
pub(crate) fn require_peer_fault_stage(
    gate: &str,
    before: &[RelayPeerFaultStage],
    stages: &[RelayPeerFaultStage],
    role: &str,
    stage: &str,
    cause: &str,
    correlation: PeerFaultCorrelation<'_>,
) -> Result<RelayPeerFaultStage> {
    let baseline = peer_fault_stage_count(before, stage);
    let gained = peer_fault_stage_count(stages, stage);
    if gained <= baseline {
        return Err(HarnessError::Process(format!(
            "{gate} did not gain a {stage} stage_counts entry ({baseline} before, {gained} after); observed {}",
            format_peer_fault_stages(stages)
        )));
    }
    let observed = stages
        .iter()
        .find(|candidate| {
            candidate.stage == stage
                && candidate.event.role.as_str() == role
                && candidate.event.cause.as_str() == cause
        })
        .ok_or_else(|| {
            HarnessError::Process(format!(
                "{gate} recorded no {role}/{stage}/{cause} peer fault; observed {}",
                format_peer_fault_stages(stages)
            ))
        })?
        .clone();
    if observed.count == 0 {
        return Err(HarnessError::Process(format!(
            "{gate} {role}/{stage}/{cause} carried a zero stage_counts entry"
        )));
    }
    let event = &observed.event;
    if event.tenant_id != correlation.tenant_id || event.device_id != correlation.device_id {
        return Err(HarnessError::Process(format!(
            "{gate} {role}/{stage}/{cause} tuple was recorded for a different tenant/device scope"
        )));
    }
    if let Some(expected) = correlation.owner_node_id
        && event.owner_node_id.as_deref() != Some(expected)
    {
        return Err(HarnessError::Process(format!(
            "{gate} {role}/{stage}/{cause} tuple named owner {:?}, expected {expected}",
            event.owner_node_id
        )));
    }
    if let Some(expected) = correlation.owner_epoch
        && event.owner_epoch != Some(expected)
    {
        return Err(HarnessError::Process(format!(
            "{gate} {role}/{stage}/{cause} tuple carried owner epoch {:?}, expected {expected}",
            event.owner_epoch
        )));
    }
    if let Some(expected) = correlation.service_id
        && event.service_id != Some(expected)
    {
        return Err(HarnessError::Process(format!(
            "{gate} {role}/{stage}/{cause} tuple carried service {:?}, expected {expected}",
            event.service_id
        )));
    }
    if correlation.require_request_identity {
        if event.session_id.as_deref().unwrap_or_default().is_empty() {
            return Err(HarnessError::Process(format!(
                "{gate} {role}/{stage}/{cause} tuple carried no session identifier"
            )));
        }
        if event.request_id.as_deref().unwrap_or_default().is_empty() {
            return Err(HarnessError::Process(format!(
                "{gate} {role}/{stage}/{cause} tuple carried no peer request identifier"
            )));
        }
    }
    // The accepted tuple is the row's evidence, so record it on the run's own
    // transcript.  Every field here is a closed label or a relay node id.
    eprintln!(
        "peer fault stage accepted: {gate} {}/{role}/{stage}/{cause} stage_counts {baseline}->{gained}",
        observed.node_id
    );
    Ok(observed)
}

impl ProductionRelay {
    fn consumer_addr(&self) -> Result<SocketAddr> {
        self.running
            .as_ref()
            .map(|relay| relay.consumer_addr)
            .ok_or_else(|| HarnessError::Process("production relay is not running".into()))
    }

    fn accepted_consumer_send_buffer_bytes(&self) -> Option<usize> {
        self.consumer_socket_diagnostics
            .as_ref()
            .and_then(AcceptedSocketDiagnostics::last_send_buffer_bytes)
    }

    async fn snapshot(&self) -> Result<RelaySnapshot> {
        let relay = self
            .running
            .as_ref()
            .ok_or_else(|| HarnessError::Process("production relay is not running".into()))?;
        relay
            .snapshot()
            .await
            .map_err(|error| HarnessError::Process(format!("reading relay snapshot: {error}")))
    }

    fn peer_server_stats(&self) -> Option<PeerServerStats> {
        self.running
            .as_ref()
            .and_then(RunningRelay::peer_server_diagnostics)
            .map(|diagnostics| diagnostics.snapshot())
    }

    fn request_peer_planned_drain(&self) -> Result<()> {
        let relay = self
            .running
            .as_ref()
            .ok_or_else(|| HarnessError::Process("production relay is not running".into()))?;
        relay.request_peer_planned_drain().map_err(|error| {
            HarnessError::Process(format!("requesting peer planned drain: {error}"))
        })
    }

    async fn shutdown_until(&mut self, deadline: tokio::time::Instant) -> Result<()> {
        let mut errors = Vec::new();
        self.peer_refresh_cancel.cancel();
        if let Some(mut task) = self.peer_refresh.take() {
            match timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!(
                    "peer readiness refresh task {} failed: {error}",
                    self.node_id
                )),
                Err(_) => {
                    task.abort();
                    match task.await {
                        Ok(()) => errors.push(format!(
                            "peer readiness refresh task {} exceeded its deadline and was aborted",
                            self.node_id
                        )),
                        Err(error) => errors.push(format!(
                            "peer readiness refresh task {} exceeded its deadline: {error}",
                            self.node_id
                        )),
                    }
                }
            }
        }
        if let Some(relay) = self.running.take()
            && let Err(error) = shutdown_running_relay_until(relay, deadline).await
        {
            errors.push(format!("stopping relay {}: {error}", self.node_id));
        }
        if let Some(handle) = self.membership_handle.take()
            && let Err(error) = shutdown_membership_task_until(handle, deadline).await
        {
            errors.push(format!(
                "stopping membership runtime {}: {error}",
                self.node_id
            ));
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }

    async fn shutdown(mut self) -> Result<()> {
        let mut first_error = None;
        self.peer_refresh_cancel.cancel();
        if let Some(mut task) = self.peer_refresh.take() {
            match timeout(CLEANUP_TIMEOUT, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => {
                    first_error = Some(HarnessError::Process(format!(
                        "peer readiness refresh task {} failed: {error}",
                        self.node_id
                    )))
                }
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    first_error = Some(HarnessError::Timeout(format!(
                        "peer readiness refresh task {} did not stop",
                        self.node_id
                    )));
                }
            }
        }
        if let Some(relay) = self.running.take()
            && let Err(error) = relay.shutdown().await
        {
            first_error = Some(HarnessError::Process(format!(
                "stopping relay {}: {error}",
                self.node_id
            )));
        }
        if let Some(handle) = self.membership_handle.take()
            && let Err(error) = handle.shutdown().await
        {
            first_error.get_or_insert_with(|| {
                HarnessError::Process(format!(
                    "stopping membership runtime {}: {error}",
                    self.node_id
                ))
            });
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

async fn shutdown_running_relay_until(
    relay: RunningRelay,
    deadline: tokio::time::Instant,
) -> Result<()> {
    // RunningRelay::shutdown owns the listener JoinHandles and has its own
    // absolute relay deadline.  Do not put that consuming future in an outer
    // timeout: aborting it would drop the RunningRelay and detach its nested
    // listener tasks.  Report a shared-deadline overrun after the owned
    // shutdown has actually joined them.
    let result = relay
        .shutdown()
        .await
        .map_err(|error| HarnessError::Process(error.to_string()));
    if tokio::time::Instant::now() > deadline {
        return match result {
            Ok(()) => Err(HarnessError::Timeout(
                "running relay shutdown exceeded the shared deadline after joining owned tasks"
                    .into(),
            )),
            Err(error) => Err(HarnessError::Process(format!(
                "{error}; running relay shutdown exceeded the shared deadline after joining owned tasks"
            ))),
        };
    }
    result
}

async fn shutdown_membership_task_until(
    handle: MembershipRuntimeHandle,
    deadline: tokio::time::Instant,
) -> Result<()> {
    // MembershipRuntimeHandle owns its supervisor JoinHandle.  Do not wrap
    // its consuming shutdown in an abortable outer task: aborting that task
    // would drop the handle and detach the supervisor.  The runtime's
    // authority calls have operation deadlines, but an in-progress blocking
    // persistence write cannot be cancelled. Retain that ownership and report
    // any shared-deadline overrun only after the supervisor actually joins;
    // this final join has no hard wall-clock bound.
    let result = handle
        .shutdown()
        .await
        .map_err(|error| HarnessError::Process(error.to_string()));
    if tokio::time::Instant::now() > deadline {
        return match result {
            Ok(()) => Err(HarnessError::Timeout(
                "membership shutdown exceeded the shared deadline after joining the supervisor"
                    .into(),
            )),
            Err(error) => Err(HarnessError::Process(format!(
                "{error}; membership shutdown exceeded the shared deadline after joining the supervisor"
            ))),
        };
    }
    result
}

async fn shutdown_relay_until(
    relay: &mut ProductionRelay,
    deadline: tokio::time::Instant,
) -> Result<()> {
    relay.shutdown_until(deadline).await
}

async fn shutdown_relays_until(
    relays: &mut Vec<ProductionRelay>,
    deadline: tokio::time::Instant,
) -> Vec<String> {
    let mut errors = Vec::new();
    while !relays.is_empty() {
        let index = relays.len() - 1;
        let result = {
            let relay = &mut relays[index];
            shutdown_relay_until(relay, deadline).await
        };
        if let Err(error) = result {
            errors.push(format!("relay cleanup: {error}"));
        }
        let _ = relays.swap_remove(index);
    }
    errors
}

async fn shutdown_peer_proxies_until(
    peer_proxies: &mut BTreeMap<String, UdpFaultProxy>,
    deadline: tokio::time::Instant,
) -> Vec<String> {
    let mut errors = Vec::new();
    for (node_id, mut proxy) in std::mem::take(peer_proxies) {
        // UdpFaultProxy::shutdown owns and joins its task, including the
        // forced-abort path.  Do not cancel that consuming borrow at the
        // caller deadline and leave its local JoinHandle detached.
        let result = proxy.shutdown().await;
        if tokio::time::Instant::now() > deadline {
            match result {
                Ok(()) => errors.push(format!(
                    "peer proxy {node_id} cleanup exceeded the shared deadline after joining"
                )),
                Err(error) => errors.push(format!(
                    "peer proxy {node_id} cleanup: {error}; exceeded the shared deadline after joining"
                )),
            }
        } else if let Err(error) = result {
            errors.push(format!("peer proxy {node_id} cleanup: {error}"));
        }
    }
    errors
}

async fn shutdown_startup_resources_until(
    relays: &mut Vec<ProductionRelay>,
    peer_proxies: &mut BTreeMap<String, UdpFaultProxy>,
    deadline: tokio::time::Instant,
) -> Vec<String> {
    let mut errors = shutdown_relays_until(relays, deadline).await;
    errors.extend(shutdown_peer_proxies_until(peer_proxies, deadline).await);
    errors
}

async fn shutdown_membership_until(
    handle: MembershipRuntimeHandle,
    deadline: tokio::time::Instant,
) -> Result<()> {
    shutdown_membership_task_until(handle, deadline).await
}

fn startup_cleanup_error(error: HarnessError, cleanup_errors: Vec<String>) -> HarnessError {
    if cleanup_errors.is_empty() {
        error
    } else {
        HarnessError::Process(format!(
            "{error}; startup cleanup: {}",
            cleanup_errors.join("; ")
        ))
    }
}

impl ProductionCluster {
    async fn start(harness: &mut RunningHarness) -> Result<Self> {
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_and_consumer_send_buffer(harness, catalog, None).await
    }

    /// Start the production cluster with an explicitly supplied catalog
    /// decorator.  The ordinary path above remains the real Redis catalog;
    /// focused acceptance fixtures can wrap that same catalog to gate one
    /// bounded result without changing production authority behavior.
    pub(super) async fn start_with_catalog(
        harness: &mut RunningHarness,
        catalog: SharedCatalog,
    ) -> Result<Self> {
        Self::start_with_catalog_and_consumer_send_buffer(harness, catalog, None).await
    }

    /// Start a three-relay cluster with one-shot public-upgrade barriers keyed
    /// by relay node ID.  This is used only by the C27 abandoned-upgrade
    /// fixture; an empty map preserves the ordinary production harness path.
    pub(super) async fn start_with_public_upgrade_barriers(
        harness: &mut RunningHarness,
        barriers: BTreeMap<String, Arc<ConsumerUpgradeBarrier>>,
        max_pending_operations: usize,
    ) -> Result<Self> {
        if !(1..=128).contains(&max_pending_operations) {
            return Err(HarnessError::InvalidInput(
                "public upgrade barrier max_pending_operations must be 1..=128".into(),
            ));
        }
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_send_buffer_and_barriers(
            harness,
            catalog,
            None,
            barriers,
            Some(max_pending_operations),
            None,
            BTreeMap::new(),
        )
        .await
    }

    /// Start a three-relay cluster with one exact pre-H3-admission barrier.
    /// The seam is disabled for every other relay and is intended only for a
    /// bounded planned-drain fixture that already authenticated/readied a
    /// public request and resolved its owner route.
    pub(super) async fn start_with_peer_admission_barrier(
        harness: &mut RunningHarness,
        target_node_id: &'static str,
        barrier: Arc<PeerAdmissionBarrier>,
    ) -> Result<Self> {
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_send_buffer_and_barriers(
            harness,
            catalog,
            None,
            BTreeMap::new(),
            None,
            Some((target_node_id, barrier)),
            BTreeMap::new(),
        )
        .await
    }

    /// Start a three-relay cluster with both a one-shot pre-H3-admission
    /// barrier and one-shot public-upgrade barriers on the same ingress relay.
    /// The EC-023 owner-death fixture arms one seam per phase so it can hold a
    /// real public request either before the owner sees it (peer admission) or
    /// after admission and before the 101 (upgrade), then kill the owner.
    pub(super) async fn start_with_peer_and_upgrade_barriers(
        harness: &mut RunningHarness,
        target_node_id: &'static str,
        peer_admission_barrier: Arc<PeerAdmissionBarrier>,
        upgrade_barriers: BTreeMap<String, Arc<ConsumerUpgradeBarrier>>,
        max_pending_operations: usize,
    ) -> Result<Self> {
        if !(1..=128).contains(&max_pending_operations) {
            return Err(HarnessError::InvalidInput(
                "peer/upgrade barrier max_pending_operations must be 1..=128".into(),
            ));
        }
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_send_buffer_and_barriers(
            harness,
            catalog,
            None,
            upgrade_barriers,
            Some(max_pending_operations),
            Some((target_node_id, peer_admission_barrier)),
            BTreeMap::new(),
        )
        .await
    }

    /// Start a three-relay cluster with one-shot device control-attach
    /// barriers keyed by relay node ID.  Each barrier holds exactly one
    /// owner-local device control socket between its `HELLO` and the
    /// registration that produces its `WELCOME`.  An empty map preserves the
    /// ordinary production harness path.  The barrier is single-use: once
    /// released it is a pass-through for every later control attach, so a
    /// caller must make its phase order explicit.
    pub(super) async fn start_with_control_attach_barriers(
        harness: &mut RunningHarness,
        control_attach_barriers: BTreeMap<String, Arc<ControlAttachBarrier>>,
    ) -> Result<Self> {
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_send_buffer_and_barriers(
            harness,
            catalog,
            None,
            BTreeMap::new(),
            None,
            None,
            control_attach_barriers,
        )
        .await
    }

    /// Start the production cluster with a test-only send-buffer request on
    /// one prebound consumer listener. The listener still crosses the normal
    /// `ServeConfig::start_with_peer` boundary; the option only makes the
    /// physical response-stall fixture deterministic without changing relay
    /// defaults or transport idle semantics.
    pub(super) async fn start_with_consumer_send_buffer(
        harness: &mut RunningHarness,
        target_node_id: &'static str,
        send_buffer_bytes: u32,
    ) -> Result<Self> {
        let catalog = Arc::new(harness.production_catalog()?.clone()) as SharedCatalog;
        Self::start_with_catalog_and_consumer_send_buffer(
            harness,
            catalog,
            Some((target_node_id, send_buffer_bytes)),
        )
        .await
    }

    async fn start_with_catalog_and_consumer_send_buffer(
        harness: &mut RunningHarness,
        catalog: SharedCatalog,
        consumer_send_buffer: Option<(&'static str, u32)>,
    ) -> Result<Self> {
        Self::start_with_catalog_send_buffer_and_barriers(
            harness,
            catalog,
            consumer_send_buffer,
            BTreeMap::new(),
            None,
            None,
            BTreeMap::new(),
        )
        .await
    }

    async fn start_with_catalog_send_buffer_and_barriers(
        harness: &mut RunningHarness,
        catalog: SharedCatalog,
        consumer_send_buffer: Option<(&'static str, u32)>,
        upgrade_barriers: BTreeMap<String, Arc<ConsumerUpgradeBarrier>>,
        max_pending_operations: Option<usize>,
        peer_admission_barrier: Option<(&'static str, Arc<PeerAdmissionBarrier>)>,
        control_attach_barriers: BTreeMap<String, Arc<ControlAttachBarrier>>,
    ) -> Result<Self> {
        let mut fixture =
            ClusterFixture::with_deployment(&harness.pki, DEPLOYMENT_ID, DEPLOYMENT_INCARCATION)?;
        for node in &mut fixture.nodes {
            node.release_ports();
        }

        // Keep the relay's real QUIC listeners on the fixture's reserved
        // addresses and advertise a distinct UDP proxy endpoint in signed
        // membership.  This gives the C20 scenario one switchable network
        // path per relay without changing membership or Redis authority.
        let startup_cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
        let mut peer_proxies = BTreeMap::new();
        for node in &fixture.nodes {
            match UdpFaultProxy::bind(node.addresses.udp).await {
                Ok(proxy) => {
                    peer_proxies.insert(node.node_id.clone(), proxy);
                }
                Err(error) => {
                    let cleanup_errors =
                        shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline)
                            .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            }
        }
        let advertised_peer_ports = peer_proxies
            .values()
            .map(|proxy| proxy.address().port())
            .collect::<Vec<_>>();

        let files = match private_fixture_directory() {
            Ok(files) => files,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let files_path = match files.path().canonicalize().map_err(HarnessError::Io) {
            Ok(path) => path,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let signer_trust_path = files_path.join("membership-signers.json");
        let server_ca_path = files_path.join("server-ca.pem");
        let oidc_jwks_path = files_path.join("oidc-jwks.pem");
        if let Err(error) = std::fs::write(
            &server_ca_path,
            harness.pki.server_ca.certificate_pem.as_bytes(),
        )
        .map_err(HarnessError::Io)
        {
            let cleanup_errors =
                shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
            return Err(startup_cleanup_error(error, cleanup_errors));
        }
        if let Err(error) =
            std::fs::write(&oidc_jwks_path, harness.oidc.public_key_pem().as_bytes())
                .map_err(HarnessError::Io)
        {
            let cleanup_errors =
                shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
            return Err(startup_cleanup_error(error, cleanup_errors));
        }
        // The fixture constructor signs its initial records for unit-level
        // checks.  Production bootstrap needs a signer that can also answer
        // each relay's fresh nonce-bound checkpoint request, so create one
        // issuer for this run and replace the fixture records with records
        // signed by that same issuer.  The private key remains inside this
        // harness authority; only its public key is written to the verifier
        // trust bundle.
        let membership_authority = match TestMembershipAuthority::new() {
            Ok(authority) => authority,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let membership_now = Utc::now();
        // Captured while the node fixtures are in scope so a background
        // re-signer can keep issuing fresh records without borrowing them.
        let mut resign_nodes: Vec<(MembershipNodeIdentity, SocketAddr)> = Vec::new();
        for node in &fixture.nodes {
            let peer_endpoint = match peer_proxies
                .get(&node.node_id)
                .map(UdpFaultProxy::address)
                .ok_or_else(|| {
                    HarnessError::InvalidInput(format!(
                        "missing UDP proxy for production relay {}",
                        node.node_id
                    ))
                }) {
                Ok(endpoint) => endpoint,
                Err(error) => {
                    let cleanup_errors =
                        shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline)
                            .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };
            let membership = match membership_authority.sign_membership_with_endpoint(
                &fixture.deployment_id,
                &fixture.deployment_incarnation,
                node,
                1,
                peer_endpoint,
                membership_now,
            ) {
                Ok(membership) => membership,
                Err(error) => {
                    let cleanup_errors =
                        shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline)
                            .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };
            let peer_spki_sha256 = match node.peer_spki_fingerprint() {
                Ok(digest) => digest,
                Err(error) => {
                    let cleanup_errors =
                        shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline)
                            .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };
            resign_nodes.push((
                MembershipNodeIdentity {
                    node_id: node.node_id.clone(),
                    peer_spki_sha256,
                },
                peer_endpoint,
            ));
            fixture.memberships.insert(node.node_id.clone(), membership);
        }
        let trusted_publisher = match membership_authority.trusted_key() {
            Ok(key) => key,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let signer_json = format!(
            "{{\"keys\":[{{\"key_id\":\"{}\",\"public_key\":\"{}\"}}]}}",
            membership_authority.key_id(),
            hex_encode(&membership_authority.public_key()),
        );
        if let Err(error) =
            std::fs::write(&signer_trust_path, signer_json.as_bytes()).map_err(HarnessError::Io)
        {
            let cleanup_errors =
                shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
            return Err(startup_cleanup_error(error, cleanup_errors));
        }

        let publisher = match RedisMembershipPublisher::connect(
            harness.redis.redis_url(),
            harness.redis.namespace(),
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("connecting membership publisher: {error}")))
        {
            Ok(publisher) => publisher,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        for node in &fixture.nodes {
            let membership = match fixture
                .membership(&node.node_id)
                .ok_or_else(|| HarnessError::InvalidInput("missing signed relay membership".into()))
            {
                Ok(membership) => membership,
                Err(error) => {
                    let cleanup_errors =
                        shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline)
                            .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };
            if let Err(error) = publisher
                .publish_signed_membership_for_node(&node.node_id, &membership.catalog_record())
                .await
                .map_err(|error| {
                    HarnessError::Redis(format!("publishing membership {}: {error}", node.node_id))
                })
            {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        }
        let membership_records = match catalog
            .read_signed_memberships()
            .await
            .map_err(|error| HarnessError::Redis(format!("reading membership directory: {error}")))
        {
            Ok(records) => records,
            Err(error) => {
                let cleanup_errors =
                    shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        if membership_records.len() != fixture.nodes.len() {
            let error = HarnessError::Redis(format!(
                "membership directory returned {} records, expected {}",
                membership_records.len(),
                fixture.nodes.len()
            ));
            let cleanup_errors =
                shutdown_peer_proxies_until(&mut peer_proxies, startup_cleanup_deadline).await;
            return Err(startup_cleanup_error(error, cleanup_errors));
        }

        let minimum_versions = fixture
            .memberships
            .iter()
            .map(|(node_id, record)| (node_id.clone(), record.payload.record_version))
            .collect::<BTreeMap<_, _>>();
        let authority = Arc::new(FixtureCheckpointAuthority {
            issuer: Arc::new(membership_authority),
            deployment_id: fixture.deployment_id.clone(),
            deployment_incarnation: fixture.deployment_incarnation.clone(),
            minimum_versions,
            next_checkpoint_version: Arc::new(AtomicU64::new(0)),
        });

        let mut relays = Vec::with_capacity(fixture.nodes.len());
        for node in &fixture.nodes {
            let send_buffer_bytes = consumer_send_buffer.and_then(|(target_node_id, bytes)| {
                (target_node_id == node.node_id.as_str()).then_some(bytes)
            });
            let upgrade_barrier = upgrade_barriers.get(&node.node_id).cloned();
            let control_attach_barrier = control_attach_barriers.get(&node.node_id).cloned();
            let peer_admission_barrier =
                peer_admission_barrier
                    .as_ref()
                    .and_then(|(target_node_id, barrier)| {
                        (*target_node_id == node.node_id.as_str()).then(|| Arc::clone(barrier))
                    });
            match start_relay(
                harness,
                &fixture,
                node,
                &files_path,
                signer_trust_path.clone(),
                server_ca_path.clone(),
                oidc_jwks_path.clone(),
                catalog.clone(),
                authority.clone(),
                trusted_publisher.clone(),
                &advertised_peer_ports,
                send_buffer_bytes,
                upgrade_barrier,
                peer_admission_barrier,
                control_attach_barrier,
                max_pending_operations,
                startup_cleanup_deadline,
            )
            .await
            {
                Ok(relay) => relays.push(relay),
                Err(error) => {
                    let cleanup_errors = shutdown_startup_resources_until(
                        &mut relays,
                        &mut peer_proxies,
                        startup_cleanup_deadline,
                    )
                    .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            }
        }

        // All three private and public listeners are now bound.  Start the
        // joined readiness supervisors only at this point so bootstrap never
        // waits on a route whose listener has not been created yet.
        for relay in &mut relays {
            let cancel = CancellationToken::new();
            let task = tokio::spawn(peer_refresh_loop(
                Arc::clone(&relay.membership),
                relay.pins.clone(),
                Arc::clone(&relay.peer_runtime),
                relay.node_id.clone(),
                relay.peer_capacity,
                Duration::from_secs(1),
                cancel.clone(),
            ));
            relay.peer_refresh_cancel = cancel;
            relay.peer_refresh = Some(task);
        }

        let device_targets = match [
            "relay-a", "relay-b", "relay-c", "relay-b", "relay-c", "relay-b", "relay-c",
        ]
        .into_iter()
        .map(|node_id| {
            relays
                .iter()
                .find(|relay| relay.node_id == node_id)
                .and_then(|relay| relay.running.as_ref().map(|running| running.device_addr))
                .ok_or_else(|| {
                    HarnessError::InvalidInput(format!(
                        "production relay {node_id} has no device listener"
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()
        {
            Ok(targets) => targets,
            Err(error) => {
                let cleanup_errors = shutdown_startup_resources_until(
                    &mut relays,
                    &mut peer_proxies,
                    startup_cleanup_deadline,
                )
                .await;
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let mut device_fanout =
            match FanoutProxy::bind(device_targets, FanoutProxyConfig::default()).await {
                Ok(proxy) => proxy,
                Err(error) => {
                    let cleanup_errors = shutdown_startup_resources_until(
                        &mut relays,
                        &mut peer_proxies,
                        startup_cleanup_deadline,
                    )
                    .await;
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };
        let tenant_b_targets = match ["relay-b", "relay-c"]
            .into_iter()
            .map(|node_id| {
                relays
                    .iter()
                    .find(|relay| relay.node_id == node_id)
                    .and_then(|relay| relay.running.as_ref().map(|running| running.device_addr))
                    .ok_or_else(|| {
                        HarnessError::InvalidInput(format!(
                            "production relay {node_id} has no tenant-B device listener"
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()
        {
            Ok(targets) => targets,
            Err(error) => {
                let mut cleanup_errors = Vec::new();
                if let Err(cleanup) = device_fanout.shutdown_until(startup_cleanup_deadline).await {
                    cleanup_errors.push(format!("device fanout cleanup: {cleanup}"));
                }
                cleanup_errors.extend(
                    shutdown_startup_resources_until(
                        &mut relays,
                        &mut peer_proxies,
                        startup_cleanup_deadline,
                    )
                    .await,
                );
                return Err(startup_cleanup_error(error, cleanup_errors));
            }
        };
        let tenant_b_fanout =
            match FanoutProxy::bind(tenant_b_targets, FanoutProxyConfig::default()).await {
                Ok(proxy) => proxy,
                Err(error) => {
                    let mut cleanup_errors = Vec::new();
                    if let Err(cleanup) =
                        device_fanout.shutdown_until(startup_cleanup_deadline).await
                    {
                        cleanup_errors.push(format!("device fanout cleanup: {cleanup}"));
                    }
                    cleanup_errors.extend(
                        shutdown_startup_resources_until(
                            &mut relays,
                            &mut peer_proxies,
                            startup_cleanup_deadline,
                        )
                        .await,
                    );
                    return Err(startup_cleanup_error(error, cleanup_errors));
                }
            };

        let resign_inputs = MembershipResignInputs {
            redis_url: harness.redis.redis_url().to_owned(),
            redis_namespace: harness.redis.namespace().to_owned(),
            deployment_id: fixture.deployment_id.clone(),
            deployment_incarnation: fixture.deployment_incarnation.clone(),
            nodes: resign_nodes,
            next_record_version: 2,
        };
        let cluster = Self {
            fixture,
            _files: files,
            relays,
            peer_proxies,
            device_fanout,
            tenant_b_fanout,
            catalog,
            membership_records: membership_records.len(),
            checkpoint_authority: authority,
            membership_resign_inputs: resign_inputs,
            membership_resign_cancel: CancellationToken::new(),
            membership_resign: None,
            membership_resign_error: Arc::new(Mutex::new(None)),
        };
        if let Err(error) = cluster.wait_for_peer_readiness(STARTUP_TIMEOUT).await {
            let cleanup_deadline = tokio::time::Instant::now() + CLEANUP_TIMEOUT;
            return match cluster.shutdown_until(cleanup_deadline).await {
                Ok(()) => Err(error),
                Err(cleanup) => Err(HarnessError::Process(format!(
                    "{error}; startup cleanup: {cleanup}"
                ))),
            };
        }
        Ok(cluster)
    }

    async fn run(&mut self, harness: &RunningHarness) -> Result<ProductionClusterEvidence> {
        if self.relays.len() != 3 {
            return Err(HarnessError::Process(format!(
                "production M7 started {} relays, expected three",
                self.relays.len()
            )));
        }
        let membership_ready_relays = self
            .relays
            .iter()
            .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
            .count();
        if membership_ready_relays != self.relays.len() {
            return Err(HarnessError::Process(format!(
                "production M7 started with {membership_ready_relays}/{} relays Ready",
                self.relays.len()
            )));
        }
        let relay_b_consumer_addr = self.relay("relay-b")?.consumer_addr()?;
        let relay_c_consumer_addr = self.relay("relay-c")?.consumer_addr()?;
        let device = harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant A has no production device".into())
        })?;
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("production device has no echo service".into())
            })?;
        let canary = format!("m7-production:{}", device.id);
        // IN-10/OG-05: start counting the relay's owner-lease heartbeat for
        // both tenant scopes before the first session claims an owner, so the
        // renewals are observed as they happen rather than reconstructed.
        let mut heartbeat_scopes = vec![HeartbeatScope {
            tenant_id: device.tenant_id,
            device_id: device.id,
        }];
        if let Some(tenant_b_device) = harness.topology.devices_b.first() {
            heartbeat_scopes.push(HeartbeatScope {
                tenant_id: tenant_b_device.tenant_id,
                device_id: tenant_b_device.id,
            });
        }
        let heartbeat = OwnerLeaseHeartbeat::start(self.catalog.clone(), heartbeat_scopes);
        let profile_directory = tempdir().map_err(HarnessError::Io)?;
        let mut profile = write_device_profile(
            profile_directory.path(),
            device.id,
            service_id,
            &canary,
            self.device_fanout.local_addr(),
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = ROTATION;
        profile.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("production client config: {error}"))
        })?;

        // Seed only tenant A's durable owner epoch above the JavaScript-safe
        // integer boundary, before any owner exists, so every later claim in
        // this run — including the duplicate exact-scope race below — proves
        // the epoch is retained as a full 64-bit value.  The guarded Lua
        // operation refuses anything but this run's fresh fixture namespace
        // with a zero epoch and no owner, and leaves catalog generation
        // metadata untouched.
        let high_epoch_setup =
            ownership::seed_high_owner_epoch(self, harness, device.tenant_id, device.id).await?;
        if !high_epoch_setup.catalog_generation_preserved {
            return Err(HarnessError::Process(
                "production M7 high-epoch seed mutated catalog generation metadata".into(),
            ));
        }

        let started = Instant::now();
        let mut client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect(ConnectOptions {
                config: profile.config.clone(),
                cancellation: CancellationToken::new(),
                profile: TransportProfile::M2,
            }),
        )
        .await
        .map_err(|_| HarnessError::Timeout("production device connector startup timed out".into()))?
        .map_err(|error| {
            HarnessError::Process(format!("production device connector failed: {error}"))
        })?;
        let session = timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("production device connector readiness timed out".into())
            })?
            .map_err(|error| {
                HarnessError::Process(format!("production device connector not ready: {error}"))
            })?;

        let owner = self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading production owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("production device did not claim an owner".into())
            })?;
        if owner.token.node_id != "relay-a" || owner.token.tenant_id != device.tenant_id {
            let _ = client.stop().await;
            return Err(HarnessError::Process(format!(
                "production owner landed on {} instead of relay-a",
                owner.token.node_id
            )));
        }

        let token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let mut stream_b = open_consumer_stream(
            relay_b_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;

        let mut ordered_records = 0usize;
        stream_b
            .round_trip(b"production-record-0", canary.as_bytes())
            .await
            .map_err(|error| HarnessError::Http(format!("initial routed canary: {error}")))?;
        ordered_records += 1;
        let maximum_payload = vec![0x5a; MAX_RECORD_BYTES];
        stream_b
            .socket
            .send(Message::Binary(Vec::new().into()))
            .await
            .map_err(|error| {
                HarnessError::Http(format!("sending empty production echo: {error}"))
            })?;
        stream_b
            .round_trip(&maximum_payload, canary.as_bytes())
            .await
            .map_err(|error| HarnessError::Http(format!("maximum routed canary: {error}")))?;
        ordered_records += 1;

        // Bring the tenant-B device online BEFORE tenant A's rotation loop so
        // both same-identifier sessions are genuinely live at the same time,
        // and so each tenant completes the full real rotation bound while the
        // other is connected.  The fixture deliberately gives both devices the
        // same device UUID and service UUID; only their enrolled certificates,
        // tenant scopes and canaries differ.  Tenant B's dedicated fanout
        // routes control to relay-b and active data to relay-c, so this also
        // exercises a second owner and a second H3 hop.
        let device_b = harness.topology.devices_b.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant B has no production device".into())
        })?;
        let service_b_id = *harness
            .topology
            .service_ids
            .get(&device_b.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("tenant B device has no echo service".into())
            })?;
        let shared_device_identifier = device_b.id == device.id;
        let shared_service_identifier = service_b_id == service_id;
        if !shared_device_identifier || !shared_service_identifier {
            return Err(HarnessError::InvalidInput(
                "tenant-isolation fixture did not reuse device/service UUIDs".into(),
            ));
        }
        let distinct_tenant_scopes = device_b.tenant_id != device.tenant_id;
        // Distinct enrolled credentials: the same device UUID in two tenants
        // must still be two different certificates and two different keys.
        let distinct_device_credentials = device_b.certificate.certificate_pem
            != device.certificate.certificate_pem
            && device_b.certificate.private_key_pem != device.certificate.private_key_pem;
        let tenant_b_canary = format!("m7-production:tenant-b:{}", device_b.id);
        let distinct_canaries = tenant_b_canary != canary;
        let profile_b_directory = tempdir().map_err(HarnessError::Io)?;
        let mut profile_b = write_device_profile(
            profile_b_directory.path(),
            device_b.id,
            service_b_id,
            &tenant_b_canary,
            self.tenant_b_fanout.local_addr(),
            &device_b.certificate.certificate_pem,
            &device_b.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile_b.config.rotation = ROTATION;
        profile_b.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("tenant-B client config: {error}"))
        })?;
        let mut client_b = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect(ConnectOptions {
                config: profile_b.config.clone(),
                cancellation: CancellationToken::new(),
                profile: TransportProfile::M2,
            }),
        )
        .await
        .map_err(|_| HarnessError::Timeout("tenant-B connector startup timed out".into()))?
        .map_err(|error| HarnessError::Process(format!("tenant-B connector failed: {error}")))?;
        let session_b = timeout(STARTUP_TIMEOUT, client_b.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B connector readiness timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-B connector not ready: {error}"))
            })?;
        if session_b.generation == 0 {
            let _ = client_b.stop().await;
            return Err(HarnessError::Process(
                "tenant-B connector reported an invalid initial generation".into(),
            ));
        }
        let owner_b = self
            .catalog
            .current_owner(device_b.tenant_id, device_b.id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading tenant-B owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("tenant-B device did not claim an owner".into())
            })?;
        if owner_b.token.node_id != "relay-b" || owner_b.token.tenant_id != device_b.tenant_id {
            let _ = client_b.stop().await;
            return Err(HarnessError::Process(format!(
                "tenant-B owner landed on {} instead of relay-b",
                owner_b.token.node_id
            )));
        }
        // Owner and node separation per tenant: two live complete owner tokens
        // for one device identifier, on different relay nodes, in different
        // tenant scopes, with different session identities.
        let distinct_owner_nodes = owner_b.token.node_id != owner.token.node_id;
        let distinct_owner_sessions = owner_b.token.session_id != owner.token.session_id
            && owner_b.token.tenant_id != owner.token.tenant_id;
        let mut concurrent_owner_samples = self
            .sample_concurrent_owners(device, device_b, &owner, &owner_b)
            .await?;
        let mut tenant_a_exact_canaries = 0usize;
        let mut tenant_b_exact_canaries = 0usize;
        let token_b = harness.oidc.issue_with(
            &harness.topology.consumers_b[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let mut stream_b_tenant_b = open_consumer_stream(
            relay_c_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token_b,
            device_b.id,
            service_b_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        stream_b_tenant_b
            .round_trip(b"production-record-tenant-b", tenant_b_canary.as_bytes())
            .await?;
        ordered_records += 1;
        tenant_b_exact_canaries += 1;
        // Tenant A's live stream must still return the tenant-A canary while
        // tenant B holds the identical device and service identifiers.
        stream_b
            .round_trip(b"production-record-tenant-a-with-b", canary.as_bytes())
            .await?;
        ordered_records += 1;
        tenant_a_exact_canaries += 1;
        // Neither route may emit the other tenant's canary.  Each probe uses
        // its own throwaway stream so the live streams stay untouched.
        let cross_tenant_canary_absent = self
            .cross_tenant_canary_absent(
                harness,
                relay_b_consumer_addr,
                relay_c_consumer_addr,
                CrossTenantProbe {
                    device_id: device.id,
                    service_id,
                    tenant_a_token: &token,
                    tenant_b_token: &token_b,
                    tenant_a_canary: canary.as_bytes(),
                    tenant_b_canary: tenant_b_canary.as_bytes(),
                },
            )
            .await?;
        let initial_status = client.status_snapshot();
        let original_control_local_addr = initial_status.control_local_addr.ok_or_else(|| {
            HarnessError::Process(
                "production device connector did not expose a bound control socket".into(),
            )
        })?;
        let mut previous_generation = session.generation;
        let mut previous_active_local_addr = initial_status.active_local_addr;
        for rotation in 1..=ROTATION_COUNT {
            let snapshot = self
                .wait_for_rotation(
                    &mut client,
                    previous_generation,
                    previous_active_local_addr,
                    rotation,
                )
                .await?;
            previous_generation = snapshot.active_generation;
            let status_after_rotation = client.status_snapshot();
            if status_after_rotation.control_local_addr != Some(original_control_local_addr) {
                let _ = stream_b.close().await;
                let _ = client.stop().await;
                return Err(HarnessError::Process(format!(
                    "production M7 rotation {rotation} replaced the control socket: expected {original_control_local_addr}, observed {:?}",
                    status_after_rotation.control_local_addr
                )));
            }
            previous_active_local_addr = status_after_rotation.active_local_addr;
            let payload = format!("production-record-{rotation}").into_bytes();
            stream_b.round_trip(&payload, canary.as_bytes()).await?;
            ordered_records += 1;
            tenant_a_exact_canaries += 1;
            // Exercise tenant B's stream on every tenant-A rotation.  This
            // keeps both tenants' canaries exact while both sessions are live
            // across the whole real rotation schedule, and keeps the pooled
            // consumer stream inside `PRODUCTION_PEER_IDLE_TIMEOUT` rather
            // than letting the transport cancel it between assertions.
            let payload_b = format!("production-record-tenant-b-{rotation}").into_bytes();
            stream_b_tenant_b
                .round_trip(&payload_b, tenant_b_canary.as_bytes())
                .await?;
            ordered_records += 1;
            tenant_b_exact_canaries += 1;
            concurrent_owner_samples = concurrent_owner_samples.saturating_add(
                self.sample_concurrent_owners(device, device_b, &owner, &owner_b)
                    .await?,
            );
            let owner_snapshot = self.relay("relay-a")?.snapshot().await?;
            assert_committed_rotation(
                &owner_snapshot,
                device.id,
                rotation,
                previous_generation,
                status_after_rotation.active_local_addr,
            )?;
        }
        let elapsed = started.elapsed();
        let required_elapsed = Duration::from_secs(ROTATION.interval_seconds * ROTATION_COUNT);
        if elapsed < required_elapsed {
            let _ = stream_b.close().await;
            let _ = client.stop().await;
            return Err(HarnessError::Process(format!(
                "production M7 observed three generations in {:.3}s, below the {}s real interval bound",
                elapsed.as_secs_f64(),
                required_elapsed.as_secs()
            )));
        }

        let mut stream_c = open_consumer_stream(
            relay_c_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        stream_c
            .round_trip(b"production-record-relay-c", canary.as_bytes())
            .await?;
        ordered_records += 1;
        stream_c.close().await?;

        // Tenant B stayed online for tenant A's whole rotation schedule, so it
        // must have completed the same real rotation bound on its own owner
        // relay.  This is the "three rotations per tenant" assertion: a tenant
        // that merely connected and echoed once cannot satisfy it.
        let tenant_b_rotations = self
            .wait_for_tenant_rotations(&mut client_b, &owner_b.token.node_id, ROTATION_COUNT)
            .await?;
        // Both tenants exchange their exact canaries again after both have
        // rotated, and both owners are sampled live once more.
        stream_b_tenant_b
            .round_trip(
                b"production-record-tenant-b-rotated",
                tenant_b_canary.as_bytes(),
            )
            .await?;
        ordered_records += 1;
        tenant_b_exact_canaries += 1;
        stream_b
            .round_trip(b"production-record-tenant-a-after-b", canary.as_bytes())
            .await?;
        ordered_records += 1;
        tenant_a_exact_canaries += 1;
        concurrent_owner_samples = concurrent_owner_samples.saturating_add(
            self.sample_concurrent_owners(device, device_b, &owner, &owner_b)
                .await?,
        );
        // Retire tenant B's pooled consumer stream here.  Tenant B's device
        // session stays online through the later negative, revocation and race
        // phases, but an application stream held idle across them would be
        // cancelled by the peer idle timeout; the later phases open fresh
        // tenant-B streams where they need one.
        stream_b_tenant_b.close().await?;
        let tenant_isolation = ConcurrentTenantIsolationEvidence {
            shared_device_identifier,
            shared_service_identifier,
            distinct_tenant_scopes,
            distinct_device_credentials,
            concurrent_owner_samples,
            distinct_owner_nodes,
            distinct_owner_sessions,
            tenant_a_exact_canaries,
            tenant_b_exact_canaries,
            distinct_canaries,
            cross_tenant_canary_absent,
            tenant_a_rotations: client.status_snapshot().rotations_completed,
            tenant_b_rotations,
        };
        validate_concurrent_tenant_isolation_evidence(&tenant_isolation, ROTATION_COUNT)?;
        let same_uuid_tenant_isolation_verified = true;

        let authorization_negatives_rejected =
            verify_authorization_negatives(harness, relay_b_consumer_addr, relay_c_consumer_addr)
                .await?;

        let stale_owner_rejected = self.verify_owner_fencing(&owner).await?;
        let key_revocation_probe = KeyRevocationProbe {
            harness,
            consumer_addr: relay_c_consumer_addr,
            token: &token,
            device_id: device.id,
            service_id,
            canary: canary.as_bytes(),
            recovery_config: &profile.config,
            client: &client,
        };
        let key_revocation_rejected = self.verify_key_revocation(&key_revocation_probe).await?;

        stream_b.close().await?;
        timeout(STARTUP_TIMEOUT, client.stop())
            .await
            .map_err(|_| HarnessError::Timeout("library connector shutdown timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("library connector shutdown: {error}"))
            })?;
        self.wait_for_no_owner(device.tenant_id, device.id).await?;
        wait_for_fanout_drained(&self.device_fanout, "library device").await?;

        // Tenant A's scope is now free, while tenant B's session at the
        // identical device and service UUIDs is still online with its
        // unchanged owner.  Race two real CLI processes for tenant A's exact
        // owner scope here, so the duplicate-owner property and the
        // same-identifier isolation property are shown to hold together: a
        // scope key that lost its tenant qualifier would evict the surviving
        // tenant instead of leaving it untouched.  The contenders connect to
        // relay device listeners directly rather than through tenant A's
        // fanout, so the fanout socket accounting below is unchanged.
        let race_sibling = harness.topology.devices_a.get(1).ok_or_else(|| {
            HarnessError::InvalidInput("tenant A has no sibling race device".into())
        })?;
        let race_sibling_service = *harness
            .topology
            .service_ids
            .get(&race_sibling.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("tenant A sibling has no echo service".into())
            })?;
        let race_sibling_canary = format!("m7-production-race-sibling:{}", race_sibling.id);
        let owner_race = tenant_race::race_exact_owner_scope(
            self,
            harness,
            tenant_race::OwnerRaceInputs {
                contested: device,
                contested_service: service_id,
                contested_canary: &canary,
                sibling: race_sibling,
                sibling_service: race_sibling_service,
                sibling_canary: &race_sibling_canary,
                same_identifier_owner: &owner_b,
                same_identifier_service: service_b_id,
                same_identifier_canary: &tenant_b_canary,
                same_identifier_token: &token_b,
                token: &token,
            },
        )
        .await?;
        validate_owner_race_evidence(&owner_race)?;

        // Tenant B's device session stayed online for the whole race; its
        // post-race canary is asserted inside the race itself through a fresh
        // public route, because a pooled consumer stream left idle for the
        // race's duration would be cancelled by the peer idle timeout rather
        // than proving anything about isolation.  Retire tenant B only now:
        // the owner-death phase below shuts a relay down.
        let tenant_b_status = client_b.status_snapshot();
        timeout(STARTUP_TIMEOUT, client_b.stop())
            .await
            .map_err(|_| HarnessError::Timeout("tenant-B connector shutdown timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("tenant-B connector shutdown: {error}"))
            })?;
        self.wait_for_no_owner(device_b.tenant_id, device_b.id)
            .await?;

        // IN-10/OG-05 bounded shutdown evidence.  A dedicated real CLI epoch
        // is interrupted and *joined with a measured duration* against a
        // bound taken from the fixture's rotation policy, and its Redis owner
        // must be released by that stop.
        //
        // It is deliberately a separate epoch on its own device fanout.  The
        // owner-death phase below still needs an owner that was abandoned
        // rather than released, so this measurement must not consume it; and
        // routing it through a private fanout keeps the shared fixture's
        // ordered route schedule, socket counts and three-socket peak exactly
        // as every other assertion in this gate already expects.
        let (cli_shutdown, cli_shutdown_owner_released) = self
            .measure_cli_shutdown_join(&CliShutdownJoinContext {
                harness,
                device,
                service_id,
                canary: &canary,
                token: &token,
                consumer_addr: relay_c_consumer_addr,
            })
            .await?;

        let (cli_process, mut cli_stream) = start_cli_smoke(
            harness,
            self.device_fanout.local_addr(),
            relay_c_consumer_addr,
            &profile,
            &token,
            device.id,
            service_id,
        )
        .await?;
        cli_stream
            .round_trip(b"production-record-cli", canary.as_bytes())
            .await?;
        cli_stream.close().await?;
        let cli_owner = self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading CLI owner: {error}")))?
            .ok_or_else(|| HarnessError::Process("CLI connector did not retain an owner".into()))?;
        let _ = cli_process
            .shutdown(Duration::from_secs(5))
            .await
            .map_err(|error| HarnessError::Process(format!("stopping CLI connector: {error}")))?;
        let cli_control_data_sockets = true;
        // Select a still-running ingress before removing the CLI's owner.
        // A fixed relay-C probe is invalid when the CLI fanout happened to
        // place the owner on relay-C: that would probe a dead listener and
        // turn a transport refusal into a false owner-death success.
        let owner_death_relay_addr = self
            .relays
            .iter()
            .find(|relay| relay.node_id != cli_owner.token.node_id)
            .ok_or_else(|| {
                HarnessError::Process(
                    "owner-death probe has no live ingress distinct from the CLI owner".into(),
                )
            })?
            .consumer_addr()?;
        let owner_death_token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        // IN-10/OG-05 liveness/readiness split.  Record the surviving
        // ingress answering both the live and the ready envelope first, so a
        // relay that was wedged unready all along cannot satisfy the split.
        let mut health = HealthSplitObservation::default();
        probe_health_pair(
            owner_death_relay_addr,
            &harness.pki.server_ca.certificate_der,
            &mut health,
        )
        .await?;
        self.shutdown_node(&cli_owner.token.node_id).await?;
        let owner_death_interrupted = match open_consumer_stream(
            owner_death_relay_addr,
            &harness.pki.server_ca.certificate_der,
            &owner_death_token,
            device.id,
            service_id,
        )
        .await
        {
            Err(StreamConnectFailure::Status { status, body })
                if is_explicit_no_owner_response(status, body.as_deref()) =>
            {
                true
            }
            Err(StreamConnectFailure::Status { status, .. }) => {
                return Err(HarnessError::Http(format!(
                    "owner-death probe returned unexpected HTTP status {status}"
                )));
            }
            Err(StreamConnectFailure::Harness(error)) => return Err(error),
            Ok(mut stream) => {
                let _ = stream.close().await;
                false
            }
        };
        if !owner_death_interrupted {
            return Err(HarnessError::Process(
                "owner shutdown did not produce a no-owner interruption".into(),
            ));
        }
        // Losing a required signed peer route must fail this relay's
        // readiness closed while its process-only liveness keeps answering:
        // docs/cluster.md's rule that liveness may stay up while readiness
        // goes false.
        let readiness_deadline = Instant::now() + PEER_ROUTE_READINESS_TIMEOUT;
        loop {
            let (live_ok, unready_ok) = probe_health_pair(
                owner_death_relay_addr,
                &harness.pki.server_ca.certificate_der,
                &mut health,
            )
            .await?;
            if unready_ok {
                if !live_ok {
                    return Err(HarnessError::Process(
                        "production /livez stopped answering when readiness failed closed".into(),
                    ));
                }
                break;
            }
            if Instant::now() >= readiness_deadline {
                return Err(HarnessError::Timeout(
                    "production /readyz did not fail closed after the owner relay was shut down"
                        .into(),
                ));
            }
            sleep(HEALTH_SPLIT_POLL).await;
        }

        let heartbeat = heartbeat.join().await?;
        let liveness = ProductionLivenessEvidence {
            owner_lease_ms: owner_lease_ms(),
            heartbeat_minimum_interval_ms: heartbeat_minimum_interval().as_millis() as u64,
            heartbeat_maximum_interval_ms: heartbeat_maximum_interval().as_millis() as u64,
            heartbeat_owner_tokens: heartbeat.owner_tokens,
            heartbeat_round_trips: heartbeat.round_trips,
            heartbeat_intervals: heartbeat.intervals_ms.len(),
            longest_heartbeat_run_intervals: heartbeat.longest_run_intervals,
            observed_minimum_interval_ms: heartbeat.minimum_interval_ms(),
            observed_maximum_interval_ms: heartbeat.maximum_interval_ms(),
            heartbeat_intervals_within_bounds: heartbeat.within_bounds(),
            livez_probes: health.livez_probes,
            livez_live: health.livez_live,
            readyz_probes: health.readyz_probes,
            readyz_ready: health.readyz_ready,
            readyz_unready: health.readyz_unready,
            liveness_up_while_readiness_false: health.liveness_up_while_readiness_false,
            cli_shutdown_join_bound_ms: CLI_SHUTDOWN_JOIN_BOUND.as_millis() as u64,
            cli_shutdown_join_ms: cli_shutdown.join_ms,
            cli_shutdown_joined_within_bound: cli_shutdown.within_bound,
            cli_shutdown_graceful_exit: cli_shutdown.graceful_exit,
            cli_shutdown_owner_released,
        };

        let final_status = client_status_after_stop(&client);
        let fanout = wait_for_fanout_drained(&self.device_fanout, "device").await?;
        let tenant_b_fanout =
            wait_for_fanout_drained(&self.tenant_b_fanout, "tenant-B device").await?;
        if fanout.peak_open > 3 || tenant_b_fanout.peak_open > 3 {
            return Err(HarnessError::Process(format!(
                "device fanout exceeded the bounded three-socket peak: tenant-A={}, tenant-B={}",
                fanout.peak_open, tenant_b_fanout.peak_open
            )));
        }
        let mut device_ingress_targets = fanout
            .closed
            .iter()
            .map(|route| route.target)
            .collect::<std::collections::BTreeSet<_>>();
        device_ingress_targets.extend(tenant_b_fanout.closed.iter().map(|route| route.target));
        let required_library_a_sockets = 2 + ROTATION_COUNT;
        let required_a_sockets = required_library_a_sockets + 2;
        if fanout.accepted < required_a_sockets
            || tenant_b_fanout.accepted < 2
            || device_ingress_targets.len() != 3
        {
            return Err(HarnessError::Process(format!(
                "device fanouts accepted {} tenant-A sockets and {} tenant-B sockets across {} relays; expected at least {} and 2 across three relays",
                fanout.accepted,
                tenant_b_fanout.accepted,
                device_ingress_targets.len(),
                required_a_sockets,
            )));
        }
        Ok(ProductionClusterEvidence {
            relay_count: 3,
            tenant_count: 2,
            device_count: harness.topology.all_devices().count(),
            signed_membership_records: self.membership_records,
            membership_ready_relays,
            h3_ingress_relays: 2,
            control_sockets: usize::from(final_status.control_local_addr.is_some())
                + usize::from(tenant_b_status.control_local_addr.is_some())
                + usize::from(cli_control_data_sockets),
            data_sockets: (final_status
                .rotations_completed
                .saturating_add(tenant_b_status.rotations_completed)
                .saturating_add(3)) as usize,
            device_ingress_relays: device_ingress_targets.len(),
            cli_control_data_sockets,
            replacement_generations: final_status.rotations_completed as usize,
            ordered_records,
            authorization_negatives_rejected,
            same_uuid_tenant_isolation_verified,
            tenant_isolation,
            owner_race,
            stale_owner_rejected,
            key_revocation_rejected,
            owner_death_interrupted,
            liveness,
            elapsed_seconds: elapsed.as_secs(),
        })
    }

    /// Run one real CLI epoch on a private device fanout, interrupt it, and
    /// measure the join plus the Redis owner release.
    ///
    /// The private fanout is the point: the shared fixture fanout carries an
    /// ordered route schedule and bounded socket accounting that the rest of
    /// this gate asserts on, so the shutdown epoch must not consume slots in
    /// it.  The fanout is always joined before returning, on success or
    /// failure.
    async fn measure_cli_shutdown_join(
        &mut self,
        context: &CliShutdownJoinContext<'_>,
    ) -> Result<(liveness::CliShutdownJoin, bool)> {
        let targets = ["relay-a", "relay-b", "relay-c"]
            .into_iter()
            .map(|node_id| {
                self.relays
                    .iter()
                    .find(|relay| relay.node_id == node_id)
                    .and_then(|relay| relay.running.as_ref().map(|running| running.device_addr))
                    .ok_or_else(|| {
                        HarnessError::InvalidInput(format!(
                            "shutdown-join fanout has no device listener for {node_id}"
                        ))
                    })
            })
            .collect::<Result<Vec<_>>>()?;
        let mut fanout = FanoutProxy::bind(targets, FanoutProxyConfig::default()).await?;
        let outcome = self.run_cli_shutdown_join(context, &fanout).await;
        let cleanup = fanout
            .shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await;
        match (outcome, cleanup) {
            (Ok(outcome), Ok(())) => Ok(outcome),
            (Ok(_), Err(cleanup)) => Err(HarnessError::Process(format!(
                "shutdown-join fanout cleanup: {cleanup}"
            ))),
            (Err(error), Ok(())) => Err(error),
            (Err(error), Err(cleanup)) => Err(HarnessError::Process(format!(
                "{error}; shutdown-join fanout cleanup: {cleanup}"
            ))),
        }
    }

    async fn run_cli_shutdown_join(
        &mut self,
        context: &CliShutdownJoinContext<'_>,
        fanout: &FanoutProxyHandle,
    ) -> Result<(liveness::CliShutdownJoin, bool)> {
        let CliShutdownJoinContext {
            harness,
            device,
            service_id,
            canary,
            token,
            consumer_addr,
        } = *context;
        let profile_directory = tempdir().map_err(HarnessError::Io)?;
        let mut profile = write_device_profile(
            profile_directory.path(),
            device.id,
            service_id,
            canary,
            fanout.local_addr(),
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = ROTATION;
        profile.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("shutdown-join client config: {error}"))
        })?;
        let (process, mut stream) = start_cli_smoke(
            harness,
            fanout.local_addr(),
            consumer_addr,
            &profile,
            token,
            device.id,
            service_id,
        )
        .await?;
        stream
            .round_trip(b"production-record-cli-shutdown", canary.as_bytes())
            .await?;
        stream.close().await?;
        let shutdown = join_cli_after_interrupt(process).await?;
        let owner_released = self
            .wait_for_no_owner(device.tenant_id, device.id)
            .await
            .is_ok();
        Ok((shutdown, owner_released))
    }

    async fn run_process_pause(
        &mut self,
        harness: &RunningHarness,
    ) -> Result<ProcessPauseEvidence> {
        if self.relays.len() != 3 {
            return Err(HarnessError::Process(format!(
                "process-pause gate started {} relays, expected three",
                self.relays.len()
            )));
        }
        let membership_ready_relays = self
            .relays
            .iter()
            .filter(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
            .count();
        if membership_ready_relays != self.relays.len() {
            return Err(HarnessError::Process(format!(
                "process-pause gate started with {membership_ready_relays}/{} relays Ready",
                self.relays.len()
            )));
        }
        let consumer_addr = self.relay("relay-c")?.consumer_addr()?;
        let device = harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant A has no process-pause device".into())
        })?;
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("process-pause device has no echo service".into())
            })?;
        let canary = format!("m7-process-pause:{}", device.id);
        let profile_directory = tempdir().map_err(HarnessError::Io)?;
        let mut profile = write_device_profile(
            profile_directory.path(),
            device.id,
            service_id,
            &canary,
            self.device_fanout.local_addr(),
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = ROTATION;
        profile.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("process-pause client config: {error}"))
        })?;

        let token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let (mut cli_process, mut cli_stream) = start_cli_smoke(
            harness,
            self.device_fanout.local_addr(),
            consumer_addr,
            &profile,
            &token,
            device.id,
            service_id,
        )
        .await?;
        if let Err(error) = cli_stream
            .round_trip(b"production-process-pause-baseline", canary.as_bytes())
            .await
        {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(Duration::from_secs(5)).await;
            return Err(error);
        }
        let mut pause_guard = match ProcessPauseGuard::new(&cli_process) {
            Ok(guard) => guard,
            Err(error) => {
                let _ = cli_stream.close().await;
                let _ = cli_process.shutdown(Duration::from_secs(5)).await;
                return Err(error);
            }
        };

        let owner_before = match self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
        {
            Ok(Some(owner)) => owner,
            Ok(None) => {
                let _ = cli_stream.close().await;
                let _ = cli_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Process(
                    "process-pause CLI did not retain an owner".into(),
                ));
            }
            Err(error) => {
                let _ = cli_stream.close().await;
                let _ = cli_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Redis(format!(
                    "reading process-pause owner: {error}"
                )));
            }
        };
        if owner_before.token.tenant_id != device.tenant_id
            || owner_before.token.device_id != device.id
            || !self
                .relays
                .iter()
                .any(|relay| relay.node_id == owner_before.token.node_id)
        {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Process(
                "process-pause CLI owner did not match the fixture scope".into(),
            ));
        }
        let owner_relay_id = owner_before.token.node_id.clone();
        let owner_relay = match self.relay(&owner_relay_id) {
            Ok(relay) => relay,
            Err(error) => {
                let _ = cli_stream.close().await;
                let _ = cli_process.shutdown(Duration::from_secs(5)).await;
                return Err(error);
            }
        };
        let baseline_snapshot = match owner_relay.snapshot().await {
            Ok(snapshot) => snapshot,
            Err(error) => {
                let _ = cli_stream.close().await;
                let _ = cli_process.shutdown(Duration::from_secs(5)).await;
                return Err(error);
            }
        };
        let baseline_dispatch_counter = baseline_snapshot.lifetime_application_dispatches;
        if baseline_dispatch_counter == 0 {
            let _ = cli_stream.close().await;
            let _ = cli_process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Process(
                "process-pause baseline echo did not advance the relay application-dispatch counter"
                    .into(),
            ));
        }

        // This probe always attempts CONT and a bounded child join below,
        // including when the stop signal or the paused exchange fails.  The
        // managed PID is read from the exact child returned by start_cli_smoke;
        // no process group or ambient desktop PID can be targeted.
        let pause_started = Instant::now();
        let pause_result = pause_guard.pause(&mut cli_process);
        let pause_observation = match pause_result {
            Ok(()) => {
                let remaining = PROCESS_PAUSE_MIN_DURATION.saturating_sub(pause_started.elapsed());
                if !remaining.is_zero() {
                    sleep(remaining).await;
                }
                // Wait out the existing challenge lease before sending the
                // probe.  This avoids treating a legitimate pre-expiry
                // relay emission as evidence of a stale paused process.
                let probe = cli_stream
                    .probe_after_pause(b"production-process-pause-stale")
                    .await;
                match wait_for_unchanged_application_dispatch(
                    owner_relay,
                    baseline_dispatch_counter,
                )
                .await
                {
                    Ok(dispatch_counter) => Ok((probe, dispatch_counter, pause_started.elapsed())),
                    Err(error) => Err(error),
                }
            }
            Err(error) => Err(error),
        };
        let resume_result = pause_guard.resume(&mut cli_process);
        let stream_cleanup = cli_stream.close().await;
        let process_cleanup = cli_process.shutdown(Duration::from_secs(5)).await;

        let (pause_probe, dispatch_counter_after, pause_duration) = pause_observation?;
        let pause_elapsed_ms = u64::try_from(pause_duration.as_millis()).unwrap_or(u64::MAX);
        if pause_duration < PROCESS_PAUSE_MIN_DURATION {
            return Err(HarnessError::Timeout(
                "paused CLI process resumed before the authorization-expiry bound".into(),
            ));
        }
        resume_result.map_err(|error| {
            HarnessError::Process(format!("resuming paused CLI process: {error}"))
        })?;
        stream_cleanup?;
        process_cleanup.map_err(|error| {
            HarnessError::Process(format!("joining paused CLI process: {error}"))
        })?;
        let paused_pid_validated = true;
        if !pause_probe.is_fail_closed() {
            return Err(HarnessError::Process(format!(
                "paused CLI probe produced {:?}; expected a bounded close/error without an echo",
                pause_probe
            )));
        }
        let relay_dispatch_counter_unchanged = dispatch_counter_after == baseline_dispatch_counter;
        if !relay_dispatch_counter_unchanged {
            return Err(HarnessError::Process(format!(
                "paused CLI probe advanced the relay dispatch counter from {} to {}",
                baseline_dispatch_counter, dispatch_counter_after
            )));
        }

        // The resumed process is deliberately joined before the recovery
        // client starts.  This proves the paused payload cannot be replayed by
        // a later epoch and avoids overlapping two owner sessions except for
        // the bounded handoff window enforced by the catalog.
        self.wait_for_no_owner(device.tenant_id, device.id).await?;
        wait_for_fanout_drained(&self.device_fanout, "paused CLI").await?;

        let (fresh_process, mut fresh_stream) = start_cli_smoke(
            harness,
            self.device_fanout.local_addr(),
            consumer_addr,
            &profile,
            &token,
            device.id,
            service_id,
        )
        .await?;
        let fresh_owner = self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("reading process-pause recovery owner: {error}"))
            });
        let successor_owner = match fresh_owner {
            Ok(Some(owner))
                if owner.token.tenant_id == device.tenant_id
                    && owner.token.device_id == device.id
                    && owner.token.epoch > owner_before.token.epoch
                    && self
                        .relays
                        .iter()
                        .any(|relay| relay.node_id == owner.token.node_id) =>
            {
                owner
            }
            Ok(Some(owner)) => {
                let _ = fresh_stream.close().await;
                let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Process(format!(
                    "process-pause recovery owner was not a fresh scoped epoch on {} (epoch {})",
                    owner.token.node_id, owner.token.epoch
                )));
            }
            Ok(None) => {
                let _ = fresh_stream.close().await;
                let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Process(
                    "process-pause recovery CLI did not retain an owner".into(),
                ));
            }
            Err(error) => {
                let _ = fresh_stream.close().await;
                let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
                return Err(error);
            }
        };
        let successor_token = successor_owner.token.clone();
        let stale_release = match self.catalog.release_owner(&owner_before.token).await {
            Ok(released) => released,
            Err(error) => {
                let _ = fresh_stream.close().await;
                let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Redis(format!(
                    "releasing stale process-pause owner: {error}"
                )));
            }
        };
        if stale_release {
            let _ = fresh_stream.close().await;
            let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Process(
                "stale process-pause owner release unexpectedly removed the successor".into(),
            ));
        }
        let owner_after_stale_release = match self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
        {
            Ok(owner) => owner,
            Err(error) => {
                let _ = fresh_stream.close().await;
                let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
                return Err(HarnessError::Redis(format!(
                    "re-reading process-pause successor owner: {error}"
                )));
            }
        };
        if owner_after_stale_release.as_ref().map(|owner| &owner.token) != Some(&successor_token) {
            let _ = fresh_stream.close().await;
            let _ = fresh_process.shutdown(Duration::from_secs(5)).await;
            return Err(HarnessError::Process(
                "stale process-pause owner release changed the successor token".into(),
            ));
        }
        let recovery_owner_verified = true;
        let fresh_exchange = timeout(
            PROCESS_PAUSE_RECOVERY_TIMEOUT,
            fresh_stream.round_trip(b"production-process-pause-fresh", canary.as_bytes()),
        )
        .await
        .map_err(|_| HarnessError::Timeout("process-pause recovery echo timed out".into()));
        let fresh_stream_cleanup = fresh_stream.close().await;
        let fresh_process_cleanup = fresh_process.shutdown(Duration::from_secs(5)).await;
        fresh_stream_cleanup?;
        fresh_process_cleanup.map_err(|error| {
            HarnessError::Process(format!("joining process-pause recovery CLI: {error}"))
        })?;
        let recovery_echo = fresh_exchange.as_ref().is_ok_and(|result| result.is_ok());
        fresh_exchange??;
        wait_for_fanout_drained(&self.device_fanout, "process-pause recovery").await?;
        let fanout = self.device_fanout.diagnostics();
        if fanout.peak_open > 3 {
            return Err(HarnessError::Process(format!(
                "process-pause fanout exceeded the bounded three-socket peak: {}",
                fanout.peak_open
            )));
        }

        Ok(ProcessPauseEvidence {
            relay_count: self.relays.len(),
            cli_control_data_sockets: true,
            paused_pid_validated,
            pause_fail_closed: true,
            relay_dispatch_counter_unchanged,
            resumed_and_joined: true,
            recovery_owner_verified,
            recovery_echo,
            stale_payload_not_replayed: recovery_echo,
            fanout_peak_open: fanout.peak_open,
            pause_elapsed_ms,
        })
    }

    async fn run_redis_partition(
        &mut self,
        harness: &RunningHarness,
        redis_proxy: &ProxyHandle,
    ) -> Result<RedisPartitionEvidence> {
        if self.relays.len() != 3 {
            return Err(HarnessError::Process(format!(
                "Redis partition gate started {} relays, expected three",
                self.relays.len()
            )));
        }
        let relay_b_consumer_addr = self.relay("relay-b")?.consumer_addr()?;
        let relay_c_consumer_addr = self.relay("relay-c")?.consumer_addr()?;
        let device = harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("tenant A has no Redis partition device".into())
        })?;
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("Redis partition device has no echo service".into())
            })?;
        let canary = format!("m7-redis-partition:{}", device.id);
        let profile_directory = tempdir().map_err(HarnessError::Io)?;
        let mut profile = write_device_profile(
            profile_directory.path(),
            device.id,
            service_id,
            &canary,
            self.device_fanout.local_addr(),
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?;
        profile.config.rotation = ROTATION;
        profile.config.validate().map_err(|error| {
            HarnessError::InvalidInput(format!("Redis partition client config: {error}"))
        })?;

        let mut client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect(ConnectOptions {
                config: profile.config.clone(),
                cancellation: CancellationToken::new(),
                profile: TransportProfile::M2,
            }),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("Redis partition device connector startup timed out".into())
        })?
        .map_err(|error| {
            HarnessError::Process(format!("Redis partition device connector failed: {error}"))
        })?;
        timeout(STARTUP_TIMEOUT, client.wait_ready())
            .await
            .map_err(|_| {
                HarnessError::Timeout("Redis partition device readiness timed out".into())
            })?
            .map_err(|error| {
                HarnessError::Process(format!("Redis partition device not ready: {error}"))
            })?;

        let owner_before = self
            .catalog
            .current_owner(device.tenant_id, device.id, Utc::now())
            .await
            .map_err(|error| HarnessError::Redis(format!("reading partition owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("Redis partition device did not claim an owner".into())
            })?;
        if owner_before.token.node_id != "relay-a"
            || owner_before.token.tenant_id != device.tenant_id
        {
            let _ = client.stop().await;
            return Err(HarnessError::Process(format!(
                "Redis partition owner landed on {} instead of relay-a",
                owner_before.token.node_id
            )));
        }

        let token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let mut stream = open_consumer_stream(
            relay_b_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        stream
            .round_trip(b"redis-partition-before", canary.as_bytes())
            .await?;
        let baseline_echo = true;
        assert_public_health_ready(
            relay_b_consumer_addr,
            &harness.pki.server_ca.certificate_der,
        )
        .await?;
        let owner_snapshot_before_partition = self.relay("relay-a")?.snapshot().await?;
        let dispatch_counter_before =
            device_dispatch_counter(&owner_snapshot_before_partition, device.id);

        let partition_started = Instant::now();
        redis_proxy.pause_all().await?;
        let partition_result: Result<(bool, bool, usize, bool, bool)> = async {
            // Let both the relay catalog calls and any reconnecting Redis
            // clients encounter the global barrier before probing.  The
            // proxy's pause_all contract covers sockets accepted after this
            // call as well as the sockets present at the barrier.
            sleep(REDIS_PARTITION_AUTHORIZATION_WAIT).await;

            assert_public_health_unready(
                relay_b_consumer_addr,
                &harness.pki.server_ca.certificate_der,
            )
            .await?;

            let admission_token = harness.oidc.issue_with(
                &harness.topology.consumers_a[0].name,
                OidcTokenOptions {
                    expires_in: Duration::from_secs(90),
                    ..OidcTokenOptions::default()
                },
            )?;
            let admission = timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT,
                open_consumer_stream(
                    relay_c_consumer_addr,
                    &harness.pki.server_ca.certificate_der,
                    &admission_token,
                    device.id,
                    service_id,
                ),
            )
            .await;
            let admission_rejected = match admission {
                Err(_) => {
                    return Err(HarnessError::Timeout(
                        "Redis partition admission did not fail closed before its bounded deadline"
                            .into(),
                    ));
                }
                Ok(Err(StreamConnectFailure::Status { status, body }))
                    if is_partition_admission_response(status, body.as_deref()) =>
                {
                    true
                }
                Ok(Err(StreamConnectFailure::Status { status, .. })) => {
                    return Err(HarnessError::Http(format!(
                        "Redis partition admission returned unexpected HTTP status {status}"
                    )));
                }
                Ok(Err(StreamConnectFailure::Harness(error))) => return Err(error),
                Ok(Ok(mut admitted)) => {
                    let _ = admitted.close().await;
                    return Err(HarnessError::Process(
                        "Redis partition admitted a new consumer stream".into(),
                    ));
                }
            };

            let dispatch = timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT,
                stream.round_trip(b"redis-partition-after-deadline", canary.as_bytes()),
            )
            .await;
            let dispatch_interrupted = match dispatch {
                Err(_) => {
                    return Err(HarnessError::Timeout(
                        "Redis partition dispatch did not stop before its bounded deadline".into(),
                    ));
                }
                Ok(Err(error)) if is_expected_revocation_close(&error) => true,
                Ok(Err(error)) => {
                    return Err(HarnessError::Process(format!(
                        "Redis partition active stream failed without a bounded close: {error}"
                    )));
                }
                Ok(Ok(())) => {
                    return Err(HarnessError::Process(
                        "Redis partition dispatched an active stream record".into(),
                    ));
                }
            };

            let owner_snapshot_after_dispatch = self.relay("relay-a")?.snapshot().await?;
            let dispatch_counter_after =
                device_dispatch_counter(&owner_snapshot_after_dispatch, device.id);
            if dispatch_counter_after > dispatch_counter_before {
                return Err(HarnessError::Process(
                    "Redis partition advanced the owner output counter after authorization expired"
                        .into(),
                ));
            }
            let paused_redis_connections = redis_proxy.diagnostics().active_connections.len();
            if paused_redis_connections == 0 {
                return Err(HarnessError::Process(
                    "Redis partition proxy paused no active Redis connections".into(),
                ));
            }
            Ok((
                admission_rejected,
                dispatch_interrupted,
                paused_redis_connections,
                true,
                true,
            ))
        }
        .await;
        let resume_result = redis_proxy.resume_all().await;
        let (
            partition_admission_rejected,
            partition_dispatch_interrupted,
            paused_redis_connections,
            public_livez_ok_during_partition,
            public_readyz_unready_during_partition,
        ) = match (partition_result, resume_result) {
            (Err(error), _) => return Err(error),
            (Ok(_), Err(error)) => return Err(error),
            (Ok(result), Ok(())) => result,
        };
        if !partition_admission_rejected || !partition_dispatch_interrupted {
            return Err(HarnessError::Process(
                "Redis partition did not prove fail-closed admission and dispatch".into(),
            ));
        }
        wait_for_public_health_ready(
            relay_b_consumer_addr,
            &harness.pki.server_ca.certificate_der,
        )
        .await?;
        let public_readyz_ok_after_recovery = true;

        // A Redis partition can make the predecessor session fail closed
        // before its lease-release command is delivered.  Stop it after the
        // barrier is lifted, join its device sockets, and wait for the exact
        // old owner token to disappear before starting a fresh session.
        let _ = stream.close().await;
        let _ = timeout(Duration::from_secs(5), client.stop()).await;
        self.wait_for_owner_clear(
            device.tenant_id,
            device.id,
            REDIS_PARTITION_OWNER_FENCE_TIMEOUT,
        )
        .await?;
        wait_for_fanout_drained(&self.device_fanout, "Redis partition predecessor").await?;

        let mut recovery_client = timeout(
            STARTUP_TIMEOUT,
            tunnel_client::connect(ConnectOptions {
                config: profile.config.clone(),
                cancellation: CancellationToken::new(),
                profile: TransportProfile::M2,
            }),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout("Redis recovery device connector startup timed out".into())
        })?
        .map_err(|error| {
            HarnessError::Process(format!("Redis recovery device connector failed: {error}"))
        })?;
        timeout(STARTUP_TIMEOUT, recovery_client.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("Redis recovery device readiness timed out".into()))?
            .map_err(|error| {
                HarnessError::Process(format!("Redis recovery device not ready: {error}"))
            })?;

        let recovery_deadline = Instant::now() + REDIS_RECOVERY_TIMEOUT;
        let recovery_owner_verified = loop {
            match timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT,
                self.catalog
                    .current_owner(device.tenant_id, device.id, Utc::now()),
            )
            .await
            {
                Ok(Ok(Some(owner)))
                    if owner.token.tenant_id == device.tenant_id
                        && owner.token.device_id == device.id
                        && self
                            .relays
                            .iter()
                            .any(|relay| relay.node_id == owner.token.node_id)
                        && owner.token.epoch > owner_before.token.epoch =>
                {
                    break true;
                }
                Ok(Ok(Some(owner)))
                    if owner.token.tenant_id != device.tenant_id
                        || owner.token.device_id != device.id
                        || !self
                            .relays
                            .iter()
                            .any(|relay| relay.node_id == owner.token.node_id) =>
                {
                    return Err(HarnessError::Process(format!(
                        "Redis recovery returned an owner on {} for the wrong authority scope",
                        owner.token.node_id
                    )));
                }
                Ok(Ok(Some(_))) | Ok(Ok(None)) => {}
                Ok(Err(error)) if Instant::now() >= recovery_deadline => {
                    let _ = recovery_client.stop().await;
                    return Err(HarnessError::Redis(format!(
                        "Redis recovery owner did not advance beyond predecessor: {error}"
                    )));
                }
                Err(_) if Instant::now() >= recovery_deadline => {
                    let _ = recovery_client.stop().await;
                    return Err(HarnessError::Timeout(
                        "Redis recovery owner exceeded its bounded deadline".into(),
                    ));
                }
                Ok(Err(_)) | Err(_) => {}
            }
            if Instant::now() >= recovery_deadline {
                let _ = recovery_client.stop().await;
                return Err(HarnessError::Timeout(
                    "Redis recovery owner exceeded its bounded deadline".into(),
                ));
            }
            sleep(REDIS_PARTITION_POLL).await;
        };

        let recovery_token = harness.oidc.issue_with(
            &harness.topology.consumers_a[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let mut recovery_stream = open_consumer_stream(
            relay_c_consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &recovery_token,
            device.id,
            service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        let recovery_echo = recovery_stream
            .round_trip(b"redis-partition-after-recovery", canary.as_bytes())
            .await
            .map(|()| true)?;
        recovery_stream.close().await?;

        timeout(STARTUP_TIMEOUT, recovery_client.stop())
            .await
            .map_err(|_| {
                HarnessError::Timeout("Redis partition connector shutdown timed out".into())
            })?
            .map_err(|error| {
                HarnessError::Process(format!("Redis partition connector shutdown: {error}"))
            })?;
        self.wait_for_no_owner(device.tenant_id, device.id).await?;

        Ok(RedisPartitionEvidence {
            relay_count: self.relays.len(),
            baseline_echo,
            partition_admission_rejected,
            partition_dispatch_interrupted,
            paused_redis_connections,
            recovery_owner_verified,
            recovery_echo,
            public_livez_ok_during_partition,
            public_readyz_unready_during_partition,
            public_readyz_ok_after_recovery,
            partition_elapsed_ms: u64::try_from(partition_started.elapsed().as_millis())
                .unwrap_or(u64::MAX),
        })
    }

    async fn wait_for_rotation(
        &self,
        client: &mut ConnectionHandle,
        previous_generation: u64,
        previous_active_local_addr: Option<SocketAddr>,
        expected_rotations: u64,
    ) -> Result<tunnel_relay::RelaySessionSnapshot> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let status = client.status_snapshot();
            if status.rotations_completed >= expected_rotations
                && status
                    .active_generation
                    .is_some_and(|generation| generation > previous_generation)
            {
                let owner = self.relay("relay-a")?;
                let snapshot = owner.snapshot().await?;
                let session = snapshot
                    .sessions
                    .into_iter()
                    .find(|session| {
                        session.session_id == status.session_id.as_deref().unwrap_or_default()
                    })
                    .ok_or_else(|| {
                        HarnessError::Process("owner snapshot lost production session".into())
                    })?;
                if session.rotations_completed < expected_rotations
                    || session.active_generation <= previous_generation
                    || session.candidate_generation.is_some()
                    || session.sockets > 2
                {
                    return Err(HarnessError::Process(format!(
                        "production M7 rotation {} was not committed: phase={}, generation={}, candidate={:?}, sockets={}",
                        expected_rotations,
                        session.phase,
                        session.active_generation,
                        session.candidate_generation,
                        session.sockets
                    )));
                }
                let active_local_addr = status.active_local_addr.ok_or_else(|| {
                    HarnessError::Process(format!(
                        "production M7 rotation {} committed without a bound active data socket",
                        expected_rotations
                    ))
                })?;
                if previous_active_local_addr == Some(active_local_addr) {
                    return Err(HarnessError::Process(format!(
                        "production M7 rotation {} reused the predecessor data socket {:?}",
                        expected_rotations, active_local_addr
                    )));
                }
                let active_connection_id =
                    status.active_connection_id.as_deref().ok_or_else(|| {
                        HarnessError::Process(format!(
                            "production M7 rotation {} committed without an active connection id",
                            expected_rotations
                        ))
                    })?;
                if session.active_connection_id != active_connection_id {
                    return Err(HarnessError::Process(format!(
                        "production M7 rotation {} owner/client active connection ids diverged",
                        expected_rotations
                    )));
                }
                return Ok(session);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "production M7 rotation {} did not commit: status={}",
                    expected_rotations,
                    redacted_status(&status)
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    /// Read both same-identifier tenants' owners at one instant and count the
    /// sample only when both are simultaneously live, scope-correct and
    /// unchanged.  An offline tenant-B device cannot produce a sample.
    async fn sample_concurrent_owners(
        &self,
        device_a: &crate::fixture::DeviceFixture,
        device_b: &crate::fixture::DeviceFixture,
        expected_a: &tunnel_catalog::OwnerClaim,
        expected_b: &tunnel_catalog::OwnerClaim,
    ) -> Result<usize> {
        let now = Utc::now();
        let live_a = self
            .catalog
            .current_owner(device_a.tenant_id, device_a.id, now)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("sampling tenant-A concurrent owner: {error}"))
            })?;
        let live_b = self
            .catalog
            .current_owner(device_b.tenant_id, device_b.id, now)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("sampling tenant-B concurrent owner: {error}"))
            })?;
        let (Some(live_a), Some(live_b)) = (live_a, live_b) else {
            return Err(HarnessError::Process(
                "same-identifier tenants were not both live at one owner sample".into(),
            ));
        };
        if live_a.token != expected_a.token || live_b.token != expected_b.token {
            return Err(HarnessError::Process(
                "a same-identifier tenant's complete owner token changed while both were live"
                    .into(),
            ));
        }
        if live_a.token.tenant_id == live_b.token.tenant_id
            || live_a.token.device_id != live_b.token.device_id
        {
            return Err(HarnessError::Process(
                "concurrent owner sample did not hold one device identifier in two tenant scopes"
                    .into(),
            ));
        }
        Ok(1)
    }

    /// Require that neither same-identifier tenant's route ever returns the
    /// other tenant's canary.  Each direction uses a throwaway stream so the
    /// live application streams are not disturbed.
    async fn cross_tenant_canary_absent(
        &self,
        harness: &RunningHarness,
        tenant_a_ingress: SocketAddr,
        tenant_b_ingress: SocketAddr,
        probe: CrossTenantProbe<'_>,
    ) -> Result<bool> {
        let mut tenant_a_stream = open_consumer_stream(
            tenant_a_ingress,
            &harness.pki.server_ca.certificate_der,
            probe.tenant_a_token,
            probe.device_id,
            probe.service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        // Expecting the OTHER tenant's canary on this route must fail.
        let tenant_a_leaked = tenant_a_stream
            .round_trip(b"production-cross-tenant-a", probe.tenant_b_canary)
            .await
            .is_ok();
        let _ = tenant_a_stream.close().await;
        let mut tenant_b_stream = open_consumer_stream(
            tenant_b_ingress,
            &harness.pki.server_ca.certificate_der,
            probe.tenant_b_token,
            probe.device_id,
            probe.service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        let tenant_b_leaked = tenant_b_stream
            .round_trip(b"production-cross-tenant-b", probe.tenant_a_canary)
            .await
            .is_ok();
        let _ = tenant_b_stream.close().await;
        Ok(!tenant_a_leaked && !tenant_b_leaked)
    }

    /// Wait until one tenant's connector and its own owner relay both report at
    /// least `required` committed scheduled replacement generations, with no
    /// candidate generation left open and the bounded socket count respected.
    async fn wait_for_tenant_rotations(
        &self,
        client: &mut ConnectionHandle,
        owner_node: &str,
        required: u64,
    ) -> Result<u64> {
        let deadline = Instant::now() + Duration::from_secs(45);
        loop {
            let status = client.status_snapshot();
            if status.rotations_completed >= required {
                let snapshot = self.relay(owner_node)?.snapshot().await?;
                let session = snapshot.sessions.into_iter().find(|session| {
                    session.session_id == status.session_id.as_deref().unwrap_or_default()
                });
                if let Some(session) = session
                    && session.rotations_completed >= required
                    && session.candidate_generation.is_none()
                    && session.sockets <= 2
                {
                    return Ok(session.rotations_completed);
                }
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "tenant session on {owner_node} reported {} of {required} committed rotations before its deadline",
                    status.rotations_completed
                )));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn verify_owner_fencing(&self, owner: &tunnel_catalog::OwnerClaim) -> Result<bool> {
        let competing_node = self
            .fixture
            .node("relay-c")
            .ok_or_else(|| HarnessError::InvalidInput("missing relay-c fixture".into()))?;
        let competing = self
            .catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: self.fixture.deployment_incarnation.clone(),
                tenant_id: owner.token.tenant_id,
                device_id: owner.token.device_id,
                node_id: competing_node.node_id.clone(),
                boot_id: competing_node.boot_id.clone(),
                session_id: Uuid::new_v4().to_string(),
                lease_expires_at: Utc::now() + chrono::Duration::seconds(20),
            })
            .await;
        if !matches!(competing, Err(tunnel_catalog::CatalogError::OwnerBusy)) {
            return Ok(false);
        }
        let mut stale = owner.token.clone();
        stale.epoch = stale.epoch.saturating_sub(1);
        stale.session_id = Uuid::new_v4().to_string();
        let stale_release = self
            .catalog
            .release_owner(&stale)
            .await
            .map_err(|error| HarnessError::Redis(format!("releasing stale owner: {error}")))?;
        Ok(!stale_release)
    }

    async fn verify_key_revocation(&self, probe: &KeyRevocationProbe<'_>) -> Result<bool> {
        let relay = self.relay("relay-c")?;
        let owner_before = self
            .catalog
            .current_owner(
                probe
                    .harness
                    .topology
                    .devices_a
                    .first()
                    .ok_or_else(|| {
                        HarnessError::InvalidInput("tenant A has no key-revocation device".into())
                    })?
                    .tenant_id,
                probe.device_id,
                Utc::now(),
            )
            .await
            .map_err(|error| HarnessError::Redis(format!("reading key-revocation owner: {error}")))?
            .ok_or_else(|| {
                HarnessError::Process("key-revocation probe started without a live owner".into())
            })?;
        // Prove the consumer upgrade and routed exchange before withdrawing
        // trust. A rejected new HTTP request alone cannot establish that an
        // already upgraded stream stops delivering after pin revocation.
        let mut revoked_stream = open_consumer_stream(
            probe.consumer_addr,
            &probe.harness.pki.server_ca.certificate_der,
            probe.token,
            probe.device_id,
            probe.service_id,
        )
        .await
        .map_err(connect_failure_to_harness)?;
        if let Err(error) = revoked_stream
            .round_trip(b"production-key-revocation-before", probe.canary)
            .await
        {
            let _ = revoked_stream.close().await;
            return Err(error);
        }
        relay
            .pins
            .replace(std::iter::empty::<SpkiSha256>())
            .map_err(|error| {
                HarnessError::Process(format!("revoking dynamic peer pins: {error}"))
            })?;
        sleep(Duration::from_millis(100)).await;
        let revoked_probe = async {
            let exchange = revoked_stream
                .round_trip(b"production-key-revocation-probe", probe.canary)
                .await;
            let _ = revoked_stream.close().await;
            match exchange {
                Err(error) if is_expected_revocation_close(&error) => Ok(()),
                Err(HarnessError::Timeout(message)) => Err(HarnessError::Timeout(format!(
                    "key-revocation probe did not close or error within the bounded exchange: {message}"
                ))),
                Err(error) => Err(HarnessError::Process(format!(
                    "key-revocation probe produced an unexpected result: {error}"
                ))),
                Ok(()) => Err(HarnessError::Process(
                    "key-revocation probe unexpectedly returned an echo after pins were revoked"
                        .into(),
                )),
            }
        }
        .await;
        let restore = publish_verified_pins(&relay.membership, &relay.pins);
        if let Err(error) = restore {
            return Err(HarnessError::Process(format!(
                "restoring dynamic peer pins after revocation probe: {error}"
            )));
        }
        revoked_probe?;

        // Pin removal may interrupt only the data carrier while control and
        // the owner remain live. M2 recovery preserves that exact owner token.
        // Match the recovered catalog owner to the actual client session;
        // an immediate consumer retry can race data reattachment. A terminal
        // client or an explicit owner-token change is a different outcome: the
        // old session must be joined before a fresh fenced session is admitted.
        let recovery_deadline = Instant::now() + KEY_REVOCATION_RECOVERY_TIMEOUT;
        let recovery_started = Instant::now();
        loop {
            let status = probe.client.status_snapshot();
            let owner = timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT,
                self.catalog.current_owner(
                    owner_before.token.tenant_id,
                    probe.device_id,
                    Utc::now(),
                ),
            )
            .await;
            let observed_owner = match owner.as_ref() {
                Ok(Ok(Some(owner))) => {
                    if owner.token.tenant_id != owner_before.token.tenant_id
                        || owner.token.device_id != probe.device_id
                    {
                        return Err(HarnessError::Process(format!(
                            "key-revocation recovery observed owner for the wrong authority scope: node={}, tenant={}, device={}",
                            owner.token.node_id, owner.token.tenant_id, owner.token.device_id
                        )));
                    }
                    if !self
                        .relays
                        .iter()
                        .any(|candidate| candidate.node_id == owner.token.node_id)
                    {
                        return Err(HarnessError::Process(format!(
                            "key-revocation recovery observed owner on unknown relay {}",
                            owner.token.node_id
                        )));
                    }
                    Some(owner)
                }
                _ => None,
            };
            let owner_changed =
                observed_owner.is_some_and(|owner| owner.token != owner_before.token);
            let owner_matches =
                observed_owner.is_some_and(|owner| owner.token == owner_before.token);
            if owner_changed
                && observed_owner.is_some_and(|owner| owner.token.epoch <= owner_before.token.epoch)
            {
                return Err(HarnessError::Process(
                    "key-revocation recovery observed a changed owner without a higher epoch"
                        .into(),
                ));
            }
            let owner_session_matches = observed_owner.is_some_and(|owner| {
                owner.token == owner_before.token
                    && status.epoch == Some(owner.token.epoch)
                    && status.session_id.as_deref() == Some(owner.token.session_id.as_str())
            });
            let status_matches = status.phase == "active"
                && status.active_local_addr.is_some()
                && status.control_local_addr.is_some()
                && owner_session_matches;
            let owner_summary = match owner.as_ref() {
                Ok(Ok(Some(owner))) => format!(
                    "present(node={},tenant_match={},device_match={},epoch={},same_token={},epoch_advanced={},session_match={},status_phase={})",
                    owner.token.node_id,
                    owner.token.tenant_id == owner_before.token.tenant_id,
                    owner.token.device_id == probe.device_id,
                    owner.token.epoch,
                    owner.token == owner_before.token,
                    owner.token.epoch > owner_before.token.epoch,
                    status.session_id.as_deref() == Some(owner.token.session_id.as_str()),
                    status.phase,
                ),
                Ok(Ok(None)) => "none".to_owned(),
                Ok(Err(_)) => "catalog_error".to_owned(),
                Err(_) => "catalog_timeout".to_owned(),
            };
            let pin_snapshot = relay.pins.snapshot();
            let recovery_diagnostics = format!(
                "elapsed_ms={},status={},owner={},owner_matches={},status_matches={},relay_c_pins={},relay_c_pin_revision={}",
                recovery_started.elapsed().as_millis(),
                redacted_status(&status),
                owner_summary,
                owner_matches,
                status_matches,
                pin_snapshot.len(),
                pin_snapshot.revision(),
            );
            if status_matches {
                break;
            }
            if owner_changed || matches!(status.phase.as_str(), "closed" | "failed") {
                self.recover_key_revocation_with_fresh_session(
                    probe,
                    &owner_before,
                    recovery_deadline,
                    &recovery_diagnostics,
                )
                .await?;
                return Ok(true);
            }
            if Instant::now() >= recovery_deadline {
                return Err(HarnessError::Timeout(format!(
                    "key-revocation owner/data recovery exceeded its bounded deadline: {recovery_diagnostics}"
                )));
            }
            sleep(Duration::from_millis(100)).await;
        }

        let mut restored_stream = loop {
            match open_consumer_stream(
                probe.consumer_addr,
                &probe.harness.pki.server_ca.certificate_der,
                probe.token,
                probe.device_id,
                probe.service_id,
            )
            .await
            {
                Ok(stream) => break stream,
                Err(StreamConnectFailure::Status { status, body })
                    if is_peer_recovery_response(status, body.as_deref())
                        && Instant::now() < recovery_deadline =>
                {
                    sleep(Duration::from_millis(100)).await;
                }
                Err(StreamConnectFailure::Status { status, body }) => {
                    return Err(HarnessError::Http(format!(
                        "restored key-revocation path was rejected with HTTP status {status} ({})",
                        redacted_admission_failure(body.as_deref())
                    )));
                }
                Err(StreamConnectFailure::Harness(error)) => return Err(error),
            }
        };
        let restored_exchange = restored_stream
            .round_trip(b"production-key-revocation-restored", probe.canary)
            .await;
        let _ = restored_stream.close().await;
        restored_exchange.map_err(|error| {
            HarnessError::Process(format!(
                "restored key-revocation path did not return an echo: {error}"
            ))
        })?;
        Ok(true)
    }

    async fn recover_key_revocation_with_fresh_session(
        &self,
        probe: &KeyRevocationProbe<'_>,
        predecessor: &tunnel_catalog::OwnerClaim,
        recovery_deadline: Instant,
        predecessor_diagnostics: &str,
    ) -> Result<()> {
        let stop_budget = bounded_recovery_budget(recovery_deadline, "joining predecessor")?;
        match timeout(STARTUP_TIMEOUT.min(stop_budget), probe.client.stop()).await {
            Ok(Ok(())) | Ok(Err(_)) => {}
            Err(_) => {
                return Err(HarnessError::Timeout(format!(
                    "key-revocation predecessor did not join before fresh-session recovery: {predecessor_diagnostics}"
                )));
            }
        }
        self.wait_for_key_revocation_owner_clear(probe.device_id, predecessor, recovery_deadline)
            .await?;

        let connect_budget = bounded_recovery_budget(recovery_deadline, "fresh connector")?;
        let mut fresh_client = timeout(
            STARTUP_TIMEOUT.min(connect_budget),
            tunnel_client::connect(ConnectOptions {
                config: probe.recovery_config.clone(),
                cancellation: CancellationToken::new(),
                profile: TransportProfile::M2,
            }),
        )
        .await
        .map_err(|_| {
            HarnessError::Timeout(
                "key-revocation fresh connector startup exceeded its bounded deadline".into(),
            )
        })?
        .map_err(|error| {
            HarnessError::Process(format!(
                "key-revocation fresh connector failed to start: {error}"
            ))
        })?;
        let ready_budget = bounded_recovery_budget(recovery_deadline, "fresh readiness")?;
        let fresh_session =
            match timeout(STARTUP_TIMEOUT.min(ready_budget), fresh_client.wait_ready()).await {
                Ok(Ok(session)) => session,
                Ok(Err(error)) => {
                    join_connector_with_cleanup_timeout(
                        &fresh_client,
                        "key-revocation fresh connector",
                    )
                    .await?;
                    return Err(HarnessError::Process(format!(
                        "key-revocation fresh connector did not become ready: {error}"
                    )));
                }
                Err(_) => {
                    join_connector_with_cleanup_timeout(
                        &fresh_client,
                        "key-revocation fresh connector",
                    )
                    .await?;
                    return Err(HarnessError::Timeout(
                        "key-revocation fresh connector readiness exceeded its bounded deadline"
                            .into(),
                    ));
                }
            };
        let fresh_owner = self
            .wait_for_key_revocation_fresh_owner(
                predecessor,
                &fresh_session.session_id,
                fresh_session.epoch,
                recovery_deadline,
            )
            .await;
        let fresh_owner = match fresh_owner {
            Ok(owner) => owner,
            Err(error) => {
                join_connector_with_cleanup_timeout(
                    &fresh_client,
                    "key-revocation fresh connector",
                )
                .await?;
                return Err(error);
            }
        };
        let mut restored_stream = loop {
            match open_consumer_stream(
                probe.consumer_addr,
                &probe.harness.pki.server_ca.certificate_der,
                probe.token,
                probe.device_id,
                probe.service_id,
            )
            .await
            {
                Ok(stream) => break stream,
                Err(StreamConnectFailure::Status { status, body })
                    if is_peer_recovery_response(status, body.as_deref())
                        && Instant::now() < recovery_deadline =>
                {
                    sleep(Duration::from_millis(100)).await;
                }
                Err(StreamConnectFailure::Status { status, body }) => {
                    join_connector_with_cleanup_timeout(
                        &fresh_client,
                        "key-revocation fresh connector",
                    )
                    .await?;
                    return Err(HarnessError::Http(format!(
                        "key-revocation fresh path was rejected with HTTP status {status} ({})",
                        redacted_admission_failure(body.as_deref())
                    )));
                }
                Err(StreamConnectFailure::Harness(error)) => {
                    join_connector_with_cleanup_timeout(
                        &fresh_client,
                        "key-revocation fresh connector",
                    )
                    .await?;
                    return Err(error);
                }
            }
        };
        let restored_exchange = restored_stream
            .round_trip(b"production-key-revocation-fresh", probe.canary)
            .await;
        let _ = restored_stream.close().await;
        if let Err(error) = restored_exchange {
            join_connector_with_cleanup_timeout(&fresh_client, "key-revocation fresh connector")
                .await?;
            return Err(HarnessError::Process(format!(
                "key-revocation fresh fenced session did not return an echo for owner epoch {}: {error}",
                fresh_owner.token.epoch
            )));
        }
        join_connector_with_cleanup_timeout(&fresh_client, "key-revocation fresh connector")
            .await?;
        Ok(())
    }

    async fn wait_for_key_revocation_owner_clear(
        &self,
        device_id: Uuid,
        predecessor: &tunnel_catalog::OwnerClaim,
        deadline: Instant,
    ) -> Result<()> {
        loop {
            let remaining = bounded_recovery_budget(deadline, "owner clearance")?;
            match timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT.min(remaining),
                self.catalog
                    .current_owner(predecessor.token.tenant_id, device_id, Utc::now()),
            )
            .await
            {
                Ok(Ok(None)) => return Ok(()),
                Ok(Ok(Some(owner)))
                    if owner.token.tenant_id != predecessor.token.tenant_id
                        || owner.token.device_id != predecessor.token.device_id
                        || !self
                            .relays
                            .iter()
                            .any(|relay| relay.node_id == owner.token.node_id) =>
                {
                    return Err(HarnessError::Process(
                        "key-revocation predecessor owner violated the authority scope".into(),
                    ));
                }
                Ok(Ok(Some(owner)))
                    if owner.token == predecessor.token
                        || owner.token.epoch <= predecessor.token.epoch => {}
                Ok(Ok(Some(owner))) => {
                    return Err(HarnessError::Process(format!(
                        "key-revocation owner changed to epoch {} before predecessor cleared",
                        owner.token.epoch
                    )));
                }
                Ok(Err(error)) if remaining <= REDIS_PARTITION_OPERATION_TIMEOUT => {
                    return Err(HarnessError::Redis(format!(
                        "key-revocation predecessor owner did not clear: {error}"
                    )));
                }
                Err(_) if remaining <= REDIS_PARTITION_OPERATION_TIMEOUT => {
                    return Err(HarnessError::Timeout(
                        "key-revocation predecessor owner did not clear before its bounded deadline"
                            .into(),
                    ));
                }
                Ok(Err(_)) | Err(_) => {}
            }
            let sleep_for =
                REDIS_PARTITION_POLL.min(bounded_recovery_budget(deadline, "owner clearance")?);
            sleep(sleep_for).await;
        }
    }

    async fn wait_for_key_revocation_fresh_owner(
        &self,
        predecessor: &tunnel_catalog::OwnerClaim,
        session_id: &str,
        epoch: u64,
        deadline: Instant,
    ) -> Result<tunnel_catalog::OwnerClaim> {
        loop {
            let remaining = bounded_recovery_budget(deadline, "fresh owner")?;
            match timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT.min(remaining),
                self.catalog.current_owner(
                    predecessor.token.tenant_id,
                    predecessor.token.device_id,
                    Utc::now(),
                ),
            )
            .await
            {
                Ok(Ok(Some(owner)))
                    if owner.token.tenant_id == predecessor.token.tenant_id
                        && owner.token.device_id == predecessor.token.device_id
                        && self
                            .relays
                            .iter()
                            .any(|relay| relay.node_id == owner.token.node_id)
                        && owner.token.epoch == epoch
                        && owner.token.epoch > predecessor.token.epoch
                        && owner.token.session_id == session_id =>
                {
                    return Ok(owner);
                }
                Ok(Ok(Some(owner)))
                    if owner.token.tenant_id != predecessor.token.tenant_id
                        || owner.token.device_id != predecessor.token.device_id
                        || !self
                            .relays
                            .iter()
                            .any(|relay| relay.node_id == owner.token.node_id) =>
                {
                    return Err(HarnessError::Process(
                        "key-revocation fresh owner violated the authority scope".into(),
                    ));
                }
                Ok(Ok(Some(owner)))
                    if owner.token.epoch > predecessor.token.epoch
                        && (owner.token.epoch != epoch || owner.token.session_id != session_id) =>
                {
                    return Err(HarnessError::Process(format!(
                        "key-revocation fresh owner epoch {} belonged to a different session",
                        owner.token.epoch
                    )));
                }
                Ok(Ok(Some(_))) | Ok(Ok(None)) => {}
                Ok(Err(error)) if remaining <= REDIS_PARTITION_OPERATION_TIMEOUT => {
                    return Err(HarnessError::Redis(format!(
                        "key-revocation fresh owner was not visible: {error}"
                    )));
                }
                Err(_) if remaining <= REDIS_PARTITION_OPERATION_TIMEOUT => {
                    return Err(HarnessError::Timeout(
                        "key-revocation fresh owner exceeded its bounded deadline".into(),
                    ));
                }
                Ok(Err(_)) | Err(_) => {}
            }
            let sleep_for =
                REDIS_PARTITION_POLL.min(bounded_recovery_budget(deadline, "fresh owner")?);
            sleep(sleep_for).await;
        }
    }

    async fn wait_for_no_owner(&self, tenant_id: Uuid, device_id: Uuid) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let owner = self
                .catalog
                .current_owner(tenant_id, device_id, Utc::now())
                .await
                .map_err(|error| HarnessError::Redis(format!("reading owner release: {error}")))?;
            if owner.is_none() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "device owner was not released before CLI handoff".into(),
                ));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    async fn wait_for_owner_clear(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        budget: Duration,
    ) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            match timeout(
                REDIS_PARTITION_OPERATION_TIMEOUT,
                self.catalog.current_owner(tenant_id, device_id, Utc::now()),
            )
            .await
            {
                Ok(Ok(None)) => return Ok(()),
                Ok(Ok(Some(_))) => {}
                Ok(Err(error)) if Instant::now() >= deadline => {
                    return Err(HarnessError::Redis(format!(
                        "Redis predecessor owner did not clear: {error}"
                    )));
                }
                Err(_) if Instant::now() >= deadline => {
                    return Err(HarnessError::Timeout(
                        "Redis predecessor owner did not clear before its lease bound".into(),
                    ));
                }
                Ok(Err(_)) | Err(_) => {}
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(
                    "Redis predecessor owner did not clear before its lease bound".into(),
                ));
            }
            sleep(REDIS_PARTITION_POLL).await;
        }
    }

    /// Observe, without forcing or failing, whether every relay's membership
    /// runtime returns to `Ready` within `budget`.
    ///
    /// A full Redis outage drives each relay's membership runtime Unready: its
    /// signed checkpoint cannot be refreshed against an unreachable catalog.
    /// The runtime is not latched -- its supervisor keeps reconciling and
    /// restores `Ready` once a strictly-newer signed checkpoint and a catalog
    /// snapshot land in the same pass.  With
    /// membership re-signing started (see [`MEMBERSHIP_RESIGN_INTERVAL`]) the
    /// re-arm no longer depends on when in the run the outage lands, so a
    /// caller that started re-signing may assert this rather than merely
    /// record it.  It still returns
    /// the observation instead of failing, so the caller owns the diagnostic.
    async fn observe_membership_readiness(&self, budget: Duration) -> bool {
        let deadline = Instant::now() + budget;
        loop {
            if self
                .relays
                .iter()
                .all(|relay| matches!(relay.membership.readiness(), MembershipReadiness::Ready))
            {
                return true;
            }
            if Instant::now() >= deadline {
                return false;
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Re-publish every relay's verified peer pins from its current membership
    /// snapshot, retrying until each relay's runtime is Ready enough to supply
    /// them.
    ///
    /// This fixture publishes peer pins from the membership *invalidation*
    /// callback only, which is edge-triggered: a full Redis outage drives
    /// membership Unready, that callback empties the pin set, and nothing
    /// re-publishes it when the runtime later returns to `Ready`.  The gap is
    /// in the fixture's wiring, not in the membership runtime (which does
    /// re-arm on its own) and not in the protocol, so a caller that has
    /// observed readiness return re-publishes explicitly -- exactly as the
    /// key-revocation probe does after it deliberately revokes pins.
    /// Start re-signing and republishing every relay's membership record on a
    /// fixed interval until shutdown.
    ///
    /// Opt-in, and started by the scenario that needs it rather than by every
    /// cluster, because a background version bump would collide with any gate
    /// that publishes its own record at a chosen version (the trust-expiry,
    /// key-overlap and handover gates all do).  Those gates keep the original
    /// behaviour of a record signed once at bootstrap.
    ///
    /// Each round issues a record at the fixture's normal lifetime with a
    /// strictly newer version, which is what the relay's verifier requires to
    /// replace one.  Nothing here widens what the relay will accept: the
    /// record lifetime stays inside the product maximum, and the record still
    /// names the same node and the same peer certificate digest.
    /// Issue one membership re-signing round now, and return once every
    /// running relay's verifier retains the new version for every node.
    ///
    /// A newer record version invalidates every peer admission bound to the
    /// old one, and with it every in-flight peer stream.  A gate whose
    /// streams must not straddle a refresh therefore re-signs at its own case
    /// boundaries instead of on a background timer.  It cannot be combined
    /// with [`Self::start_membership_resigning`].
    async fn resign_membership_now(&mut self) -> Result<u64> {
        if self.membership_resign.is_some() {
            return Err(HarnessError::InvalidInput(
                "membership re-signing is already running in the background".into(),
            ));
        }
        let inputs = &self.membership_resign_inputs;
        let version = inputs.next_record_version;
        let publisher =
            RedisMembershipPublisher::connect(&inputs.redis_url, &inputs.redis_namespace)
                .await
                .map_err(|error| {
                    HarnessError::Redis(format!("connecting membership re-signer: {error}"))
                })?;
        let now = Utc::now();
        for (identity, peer_endpoint) in &inputs.nodes {
            let signed = self
                .checkpoint_authority
                .issuer
                .sign_membership_identity(
                    &inputs.deployment_id,
                    &inputs.deployment_incarnation,
                    identity,
                    MembershipLifetimeOptions {
                        record_version: version,
                        peer_endpoint: *peer_endpoint,
                        now,
                        lifetime: M7_MEMBERSHIP_LIFETIME,
                    },
                )
                .map_err(|error| {
                    HarnessError::Pki(format!(
                        "re-signing membership for {}: {error}",
                        identity.node_id
                    ))
                })?;
            publisher
                .publish_signed_membership_for_node(&identity.node_id, &signed.catalog_record())
                .await
                .map_err(|error| {
                    HarnessError::Redis(format!(
                        "publishing membership for {}: {error}",
                        identity.node_id
                    ))
                })?;
        }
        self.membership_resign_inputs.next_record_version = version.saturating_add(1);
        let nodes = self.membership_resign_inputs.nodes.len();
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            let converged = self
                .relays
                .iter()
                .filter(|relay| relay.running.is_some())
                .all(|relay| {
                    let snapshot = relay.membership.snapshot();
                    snapshot.memberships.len() >= nodes
                        && snapshot
                            .memberships
                            .iter()
                            .all(|membership| membership.record_version >= version)
                });
            if converged {
                return Ok(version);
            }
            if Instant::now() >= deadline {
                return Err(HarnessError::Timeout(format!(
                    "membership version {version} did not reach every relay"
                )));
            }
            for relay in self.relays.iter().filter(|relay| relay.running.is_some()) {
                relay.membership.notify_membership_changed();
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    async fn start_membership_resigning(&mut self) -> Result<()> {
        if self.membership_resign.is_some() {
            return Err(HarnessError::InvalidInput(
                "membership re-signing is already running for this cluster".into(),
            ));
        }
        let inputs = self.membership_resign_inputs.clone();
        let publisher =
            RedisMembershipPublisher::connect(&inputs.redis_url, &inputs.redis_namespace)
                .await
                .map_err(|error| {
                    HarnessError::Redis(format!("connecting membership re-signer: {error}"))
                })?;
        let cancel = CancellationToken::new();
        let task = tokio::spawn(membership_resign_loop(
            Arc::clone(&self.checkpoint_authority),
            inputs,
            publisher,
            MEMBERSHIP_RESIGN_INTERVAL,
            Arc::clone(&self.membership_resign_error),
            cancel.clone(),
        ));
        self.membership_resign_cancel = cancel;
        self.membership_resign = Some(task);
        Ok(())
    }

    /// The first error the membership re-signer hit, if it hit one.
    fn membership_resign_failure(&self) -> Option<String> {
        self.membership_resign_error
            .lock()
            .ok()
            .and_then(|guard| guard.clone())
    }

    fn republish_peer_pins(&self) -> Result<()> {
        for relay in &self.relays {
            publish_verified_pins(&relay.membership, &relay.pins)?;
        }
        Ok(())
    }

    /// Wait until every relay's peer runtime reports ready, or fail with the
    /// count that got there before the budget expired.
    async fn wait_for_peer_readiness(&self, budget: Duration) -> Result<()> {
        let deadline = Instant::now() + budget;
        loop {
            if self
                .relays
                .iter()
                .all(|relay| relay.peer_runtime.is_ready())
            {
                return Ok(());
            }
            if Instant::now() >= deadline {
                let ready = self
                    .relays
                    .iter()
                    .filter(|relay| relay.peer_runtime.is_ready())
                    .count();
                return Err(HarnessError::Timeout(format!(
                    "production peer readiness reached {ready}/{} relays before its deadline",
                    self.relays.len()
                )));
            }
            sleep(Duration::from_millis(50)).await;
        }
    }

    /// Join every running relay's bounded `last_by_stage` peer-fault view with
    /// the node that produced it and the stage's saturating count.
    ///
    /// This reads only the typed relay snapshot, so it carries no error text
    /// and no endpoint: the tuple's own correlation identifiers are what a
    /// gate asserts on.
    async fn peer_fault_stages(&self) -> Result<Vec<RelayPeerFaultStage>> {
        let mut stages = Vec::new();
        for relay in &self.relays {
            if relay.running.is_none() {
                continue;
            }
            let snapshot = relay.snapshot().await?;
            let diagnostics = snapshot.peer_fault_diagnostics;
            for (stage, event) in diagnostics.last_by_stage {
                stages.push(RelayPeerFaultStage {
                    node_id: relay.node_id.clone(),
                    stage,
                    count: diagnostics.stage_counts.get(stage).copied().unwrap_or(0),
                    event,
                });
            }
        }
        Ok(stages)
    }

    fn set_peer_path_drop(&self, node_id: &str, drop_packets: bool) -> Result<()> {
        let proxy = self.peer_proxies.get(node_id).ok_or_else(|| {
            HarnessError::InvalidInput(format!("production relay {node_id} has no UDP proxy"))
        })?;
        proxy.set_drop(drop_packets);
        Ok(())
    }

    fn set_peer_path_drop_from(
        &self,
        target_node_id: &str,
        source_node_id: &str,
        drop_packets: bool,
    ) -> Result<()> {
        let proxy = self.peer_proxies.get(target_node_id).ok_or_else(|| {
            HarnessError::InvalidInput(format!(
                "production relay {target_node_id} has no UDP proxy"
            ))
        })?;
        let source_addr = self.relay(source_node_id)?.peer_source_addr;
        proxy.set_drop_for_client(source_addr, drop_packets)?;
        Ok(())
    }

    fn relay(&self, node_id: &str) -> Result<&ProductionRelay> {
        self.relays
            .iter()
            .find(|relay| relay.node_id == node_id)
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!("production relay {node_id} is missing"))
            })
    }

    async fn shutdown_node(&mut self, node_id: &str) -> Result<()> {
        self.shutdown_node_until(node_id, tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await
    }

    async fn shutdown_node_until(
        &mut self,
        node_id: &str,
        deadline: tokio::time::Instant,
    ) -> Result<()> {
        let index = self
            .relays
            .iter()
            .position(|relay| relay.node_id == node_id)
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!("production relay {node_id} is missing"))
            })?;
        // An owner-loss fixture removes the failed relay from `self.relays`
        // immediately after this method. Capture its final typed runtime
        // snapshot before consuming it so the C11 owner-fault window retains
        // evidence for all three relays. This is opt-in and keeps the
        // ordinary acceptance path unchanged.
        let capture_error = if crate::c11_capture::capture_dir().is_some() {
            let relay = &self.relays[index];
            match timeout_at(deadline, relay.snapshot()).await {
                Ok(Ok(snapshot)) => match serde_json::to_vec(&snapshot) {
                    Ok(bytes) => crate::c11_capture::record_snapshot(
                        &format!("relay-{}", relay.node_id),
                        &bytes,
                    )
                    .err()
                    .map(|error| {
                        format!(
                            "relay {} owner-loss snapshot capture: {error}",
                            relay.node_id
                        )
                    }),
                    Err(error) => Some(format!(
                        "relay {} owner-loss snapshot serialization: {error}",
                        relay.node_id
                    )),
                },
                Ok(Err(error)) => Some(format!(
                    "relay {} owner-loss snapshot: {error}",
                    self.relays[index].node_id
                )),
                Err(_) => Some(format!(
                    "relay {} owner-loss snapshot exceeded the cleanup deadline",
                    self.relays[index].node_id
                )),
            }
        } else {
            None
        };
        let node_id = self.relays[index].node_id.clone();
        let result = {
            let relay = &mut self.relays[index];
            shutdown_relay_until(relay, deadline).await
        };
        let result = match (result, capture_error) {
            (Ok(()), None) => Ok(()),
            (Err(error), None) => Err(error),
            (Ok(()), Some(capture)) => Err(HarnessError::Process(capture)),
            (Err(error), Some(capture)) => {
                Err(HarnessError::Process(format!("{error}; {capture}")))
            }
        };
        let _ = self.relays.swap_remove(index);
        if let Err(error) = &result {
            return Err(HarnessError::Process(format!(
                "stopping relay {node_id}: {error}"
            )));
        }
        result
    }

    async fn shutdown(self) -> Result<()> {
        self.shutdown_until(tokio::time::Instant::now() + CLEANUP_TIMEOUT)
            .await
    }

    async fn shutdown_until(mut self, deadline: tokio::time::Instant) -> Result<()> {
        let mut errors = Vec::new();
        self.membership_resign_cancel.cancel();
        if let Some(mut task) = self.membership_resign.take() {
            match timeout_at(deadline, &mut task).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => errors.push(format!("membership re-signer failed: {error}")),
                Err(_) => {
                    task.abort();
                    let _ = task.await;
                    errors.push("membership re-signer did not stop by its deadline".to_owned());
                }
            }
        }
        if let Some(failure) = self.membership_resign_failure() {
            errors.push(format!("membership re-signer reported: {failure}"));
        }
        if let Err(error) = capture_c11_cluster_diagnostics(&self, deadline).await {
            errors.push(format!("C11 cluster diagnostics: {error}"));
        }
        if let Err(error) = self.tenant_b_fanout.shutdown_until(deadline).await {
            errors.push(format!("tenant-B fanout cleanup: {error}"));
        }
        if let Err(error) = self.device_fanout.shutdown_until(deadline).await {
            errors.push(format!("device fanout cleanup: {error}"));
        }
        errors.extend(shutdown_relays_until(&mut self.relays, deadline).await);
        errors.extend(shutdown_peer_proxies_until(&mut self.peer_proxies, deadline).await);
        if errors.is_empty() {
            Ok(())
        } else {
            Err(HarnessError::Process(errors.join("; ")))
        }
    }
}

async fn capture_c11_cluster_diagnostics(
    cluster: &ProductionCluster,
    deadline: tokio::time::Instant,
) -> Result<()> {
    if crate::c11_capture::capture_dir().is_none() {
        return Ok(());
    }
    let mut errors = Vec::new();
    for relay in &cluster.relays {
        match timeout_at(deadline, relay.snapshot()).await {
            Ok(Ok(snapshot)) => match serde_json::to_vec(&snapshot) {
                Ok(bytes) => {
                    if let Err(error) = crate::c11_capture::record_snapshot(
                        &format!("relay-{}", relay.node_id),
                        &bytes,
                    ) {
                        errors.push(format!("relay {} snapshot capture: {error}", relay.node_id));
                    }
                }
                Err(error) => errors.push(format!(
                    "relay {} snapshot serialization: {error}",
                    relay.node_id
                )),
            },
            Ok(Err(error)) => errors.push(format!("relay {} snapshot: {error}", relay.node_id)),
            Err(_) => errors.push(format!(
                "relay {} snapshot exceeded the cleanup deadline",
                relay.node_id
            )),
        }
        if let Some(stats) = relay.peer_server_stats() {
            let mut text = format!(
                "route=peer_server relay={} connections={}",
                relay.node_id,
                stats.connections.len()
            );
            for connection in stats.connections {
                text.push_str(&format!(
                    " peer={} accepted={} resolving={} active={} completed={} cancelled={} errors={} available_permits={} max_permits={} goaway={} forced_cancel={} forced_close={} join_incomplete={}",
                    connection.peer_node_id,
                    connection.accepted_streams,
                    connection.resolving_streams,
                    connection.active_streams,
                    connection.completed_streams,
                    connection.cancelled_streams,
                    connection.error_streams,
                    connection.available_stream_permits,
                    connection.max_stream_permits,
                    connection.planned_goaway_sent,
                    connection.forced_stream_cancellation,
                    connection.forced_connection_close,
                    connection.drain_join_incomplete,
                ));
            }
            if let Err(error) = crate::c11_capture::record_snapshot(
                &format!("peer-server-{}", relay.node_id),
                text.as_bytes(),
            ) {
                errors.push(format!(
                    "relay {} peer snapshot capture: {error}",
                    relay.node_id
                ));
            }
        }
    }
    for (role, diagnostics) in [
        ("device_fanout", cluster.device_fanout.diagnostics()),
        ("tenant_b_fanout", cluster.tenant_b_fanout.diagnostics()),
    ] {
        let text = format!(
            "route=fanout_proxy role={} accepted={} closed={} peak_open={} open={}",
            role,
            diagnostics.accepted,
            diagnostics.closed_count,
            diagnostics.peak_open,
            diagnostics.open.len(),
        );
        if let Err(error) = crate::c11_capture::record_snapshot(role, text.as_bytes()) {
            errors.push(format!("{role} snapshot capture: {error}"));
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(HarnessError::Process(errors.join("; ")))
    }
}

#[allow(clippy::too_many_arguments)]
async fn start_relay(
    harness: &RunningHarness,
    fixture: &ClusterFixture,
    node: &crate::cluster_fixture::RelayNodeFixture,
    files: &Path,
    signer_trust_path: PathBuf,
    server_ca_path: PathBuf,
    oidc_jwks_path: PathBuf,
    catalog: SharedCatalog,
    authority: Arc<FixtureCheckpointAuthority>,
    trusted_publisher: tunnel_cluster::membership::TrustedPublisherKey,
    advertised_peer_ports: &[u16],
    consumer_send_buffer_bytes: Option<u32>,
    consumer_upgrade_barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    consumer_peer_admission_barrier: Option<Arc<PeerAdmissionBarrier>>,
    device_control_attach_barrier: Option<Arc<ControlAttachBarrier>>,
    max_pending_operations: Option<usize>,
    startup_cleanup_deadline: tokio::time::Instant,
) -> Result<ProductionRelay> {
    let peer_cert_path = files.join(format!("{}-peer-chain.pem", node.node_id));
    let peer_key_path = files.join(format!("{}-peer-key.pem", node.node_id));
    let peer_ca_path = files.join(format!("{}-peer-ca.pem", node.node_id));
    let server_cert_path = files.join(format!("{}-server-chain.pem", node.node_id));
    let server_key_path = files.join(format!("{}-server-key.pem", node.node_id));
    let device_ca_path = files.join(format!("{}-device-ca.pem", node.node_id));
    std::fs::write(
        &peer_cert_path,
        node.peer_certificate_chain_pem().as_bytes(),
    )
    .map_err(HarnessError::Io)?;
    std::fs::write(
        &peer_key_path,
        node.peer_certificate.private_key_pem.as_bytes(),
    )
    .map_err(HarnessError::Io)?;
    std::fs::write(&peer_ca_path, node.peer_ca_pem().as_bytes()).map_err(HarnessError::Io)?;

    let local_spki = node
        .peer_spki_fingerprint()
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let cluster_config = ClusterConfig {
        deployment_id: fixture.deployment_id.clone(),
        peer_bind: node.addresses.udp,
        peer_tls_cert_chain: peer_cert_path.clone(),
        peer_tls_private_key: peer_key_path.clone(),
        peer_tls_client_ca: peer_ca_path.clone(),
        membership_signer_public_key_path: None,
        membership_signer_key_id: None,
        membership_signer_trust_path: Some(signer_trust_path.clone()),
        checkpoint_authority_endpoint: "https://localhost:443/v1/checkpoint".to_owned(),
        checkpoint_authority_trust_path: server_ca_path.clone(),
        membership_version_state_path: files
            .join(format!("{}-membership-version-state.json", node.node_id)),
        endpoint_policy: tunnel_relay::PrivateEndpointPolicyConfig {
            allowed_hosts: vec!["127.0.0.1".to_owned()],
            allowed_server_names: vec!["localhost".to_owned()],
            allowed_ports: advertised_peer_ports.to_vec(),
            require_private_ip: false,
        },
        node_id: Some(node.node_id.clone()),
        membership_record_lifetime_seconds: 60,
        membership_refresh_seconds: 20,
        membership_reconcile_seconds: 1,
        peer_idle_timeout_seconds: 60,
        peer_drain_timeout_seconds: 5,
        checkpoint_timeout_seconds: 2,
        max_clock_skew_seconds: 1,
    };
    let membership_config = MembershipRuntimeConfig::from_cluster_config(
        &cluster_config,
        node.node_id.clone(),
        node.boot_id.clone(),
        fixture.deployment_incarnation.clone(),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("membership config: {error}")))?
    .with_local_spki_sha256(local_spki.clone())
    .map_err(|error| HarnessError::InvalidInput(format!("membership local pin: {error}")))?;
    let state_path = cluster_config.membership_version_state_path.clone();
    let state_identity = MembershipVersionStateIdentity::new(
        &fixture.deployment_id,
        &fixture.deployment_incarnation,
        &node.node_id,
    )
    .map_err(|error| HarnessError::InvalidInput(format!("membership state identity: {error}")))?;
    let bootstrapped_store =
        MembershipVersionStateStore::bootstrap(state_path.clone(), state_identity.clone())
            .map_err(|error| {
                HarnessError::Process(format!("bootstrapping membership state: {error}"))
            })?;
    drop(bootstrapped_store);
    let membership_store = MembershipVersionStateStore::open(state_path, state_identity)
        .map_err(|error| HarnessError::Process(format!("opening membership state: {error}")))?;
    let membership = MembershipRuntime::new_with_store(
        catalog.clone(),
        authority,
        membership_config,
        [trusted_publisher],
        Arc::new(membership_store),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("membership runtime: {error}")))?;
    let pins = SharedPeerPins::empty();
    let peer_readiness = Arc::new(
        PeerReadiness::new(1)
            .map_err(|error| HarnessError::Process(format!("peer readiness: {error}")))?,
    );

    // Membership invalidation owns pin publication for this fixture.  Keep
    // readiness route state under the authenticated peer probe loop: clearing
    // every route for one invalidated admission races a legitimate v2
    // refresh, and differs from the serving relay's callback contract.  The
    // transport pin watcher still closes connections whose certificate is no
    // longer approved; the next bounded probe records the affected route.
    let pin_membership = Arc::clone(&membership);
    let pin_updates = pins.clone();
    membership.set_invalidation_callback(Some(Arc::new(move |_identity, _reason| {
        if let Err(error) = publish_verified_pins(&pin_membership, &pin_updates) {
            tracing::warn!(
                ?error,
                "production membership pin publication failed closed"
            );
            let _ = pin_updates.replace(std::iter::empty::<SpkiSha256>());
        }
    })));

    let mut server = harness
        .pki
        .issue_server(format!("{}-server", node.node_id))
        .map_err(|error| HarnessError::Pki(error.to_string()))?;
    let server_chain = format!(
        "{}{}",
        server.certificate_pem, harness.pki.server_ca.certificate_pem
    );
    std::fs::write(&server_cert_path, server_chain.as_bytes()).map_err(HarnessError::Io)?;
    std::fs::write(&server_key_path, server.private_key_pem.as_bytes())
        .map_err(HarnessError::Io)?;
    std::fs::write(
        &device_ca_path,
        harness.pki.device_ca.certificate_pem.as_bytes(),
    )
    .map_err(HarnessError::Io)?;
    let device_tls = load_server_config_from_pem(
        server_chain.as_bytes(),
        server.private_key_pem.as_bytes(),
        Some(harness.pki.device_ca.certificate_pem.as_bytes()),
    )
    .map_err(|error| HarnessError::Pki(format!("device TLS {}: {error}", node.node_id)))?;
    let consumer_tls = load_server_config_from_pem(
        server_chain.as_bytes(),
        server.private_key_pem.as_bytes(),
        None,
    )
    .map_err(|error| HarnessError::Pki(format!("consumer TLS {}: {error}", node.node_id)))?;
    server.private_key_pem.clear();

    let mut peer_server = load_peer_server_config_from_pem(
        node.peer_certificate_chain_pem().as_bytes(),
        node.peer_certificate.private_key_pem.as_bytes(),
        node.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("peer server TLS {}: {error}", node.node_id)))?;
    let mut peer_client = load_peer_client_config_from_pem(
        node.peer_certificate_chain_pem().as_bytes(),
        node.peer_certificate.private_key_pem.as_bytes(),
        node.peer_ca_pem().as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("peer client TLS {}: {error}", node.node_id)))?;
    let peer_limits = PeerTransportLimits::default()
        .with_timeouts(PRODUCTION_PEER_IDLE_TIMEOUT, Duration::from_secs(5))
        .map_err(|error| HarnessError::Process(format!("peer limits: {error}")))?;
    peer_limits
        .apply_to_server_config(&mut peer_server)
        .map_err(|error| HarnessError::Process(format!("peer server limits: {error}")))?;
    peer_limits
        .apply_to_client_config(&mut peer_client)
        .map_err(|error| HarnessError::Process(format!("peer client limits: {error}")))?;
    let peer_capacity = peer_limits
        .max_connections
        .min(peer_limits.max_streams_per_connection);
    let peer_endpoint =
        quinn::Endpoint::server(peer_server, node.addresses.udp).map_err(|error| {
            HarnessError::Process(format!("binding peer {}: {error}", node.node_id))
        })?;
    let client_bind = SocketAddr::new(node.addresses.udp.ip(), 0);
    let mut client_endpoint = quinn::Endpoint::client(client_bind).map_err(|error| {
        HarnessError::Process(format!("binding peer client {}: {error}", node.node_id))
    })?;
    let peer_source_addr = client_endpoint.local_addr().map_err(|error| {
        HarnessError::Process(format!(
            "reading peer client {} address: {error}",
            node.node_id
        ))
    })?;
    if !peer_source_addr.ip().is_loopback() {
        return Err(HarnessError::Process(format!(
            "peer client {} source address {} is not loopback",
            node.node_id, peer_source_addr
        )));
    }
    client_endpoint.set_default_client_config(peer_client);
    let peer_client =
        PeerClient::new_with_pin_provider(client_endpoint, pins.clone(), peer_limits.clone())
            .map_err(|error| {
                HarnessError::Process(format!("creating peer client {}: {error}", node.node_id))
            })?;
    let identity = RelayIdentity::new(
        fixture.deployment_incarnation.clone(),
        node.node_id.clone(),
        node.boot_id.clone(),
    )
    .map_err(|error| HarnessError::InvalidInput(format!("relay identity: {error}")))?;
    let owner_router: Arc<OwnerRouter<dyn Catalog>> = Arc::new(
        OwnerRouter::new(catalog.clone(), identity)
            .map_err(|error| HarnessError::InvalidInput(format!("owner router: {error}")))?,
    );
    let peer_runtime = Arc::new(PeerRuntime::new_with_readiness(
        peer_client,
        owner_router,
        membership.clone(),
        node.node_id.clone(),
        node.boot_id.clone(),
        Arc::clone(&peer_readiness),
    ));
    let consumer_listener = bind_consumer_listener(consumer_send_buffer_bytes)?;
    let consumer_socket_diagnostics =
        consumer_send_buffer_bytes.map(|_| AcceptedSocketDiagnostics::new());
    let device_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .map_err(HarnessError::Io)?;
    let consumer_bind = consumer_listener.local_addr().map_err(HarnessError::Io)?;
    let device_bind = device_listener.local_addr().map_err(HarnessError::Io)?;
    let config = ServeConfig {
        consumer_bind,
        device_bind,
        oidc_issuer: harness.oidc.issuer.clone(),
        oidc_audience: vec![harness.oidc.audience.clone()],
        oidc_jwks_path,
        redis_url: harness.redis.redis_url().to_owned(),
        redis_namespace: harness.redis.namespace().to_owned(),
        redis_tls_root_ca_path: None,
        redis_tls_client_cert_path: None,
        redis_tls_client_key_path: None,
        device_tls_cert_chain: server_cert_path.clone(),
        device_tls_private_key: server_key_path.clone(),
        device_tls_client_ca: device_ca_path,
        consumer_tls_cert_chain: server_cert_path,
        consumer_tls_private_key: server_key_path,
        consumer_tls_client_ca: None,
        node_id: node.node_id.clone(),
        boot_id: String::new(),
        deployment_incarnation: fixture.deployment_incarnation.clone(),
        max_devices_per_user: 16,
        // The production fixture keeps the documented per-owner consumer
        // admission bound; scenarios that need a narrower relay-global bound
        // override `limits.max_pending_operations` below, and the effective
        // per-owner bound is clamped to it.
        max_pending_operations_per_owner: tunnel_relay::DEFAULT_MAX_PENDING_OPERATIONS_PER_OWNER,
        max_queue_bytes: 4 * 1024 * 1024,
        rotation: harness.rotation_config(),
        cluster: Some(cluster_config),
        recovery: None,
        http_forward: None,
    };
    let mut options = RelayOptions::new(harness.production_oidc_verifier()?);
    options.node_id = node.node_id.clone();
    options.boot_id = node.boot_id.clone();
    options.deployment_incarnation = fixture.deployment_incarnation.clone();
    options.rotation = harness.rotation_config();
    // Same value as `RelayOptions::new`, stated explicitly: the IN-10/OG-05
    // heartbeat bounds are derived from this configured lease, so the fixture
    // must name it rather than inherit it silently.
    options.owner_lease = PRODUCTION_OWNER_LEASE;
    if let Some(max_pending_operations) = max_pending_operations {
        options.limits.max_pending_operations = max_pending_operations;
    }
    let membership_handle = membership
        .start()
        .await
        .map_err(|error| HarnessError::Process(format!("starting membership runtime: {error}")))?;
    if !matches!(membership.readiness(), MembershipReadiness::Ready) {
        let cleanup = shutdown_membership_until(membership_handle, startup_cleanup_deadline).await;
        return Err(match cleanup {
            Ok(()) => HarnessError::Process(format!(
                "relay {} membership bootstrap did not reach Ready",
                node.node_id
            )),
            Err(cleanup) => HarnessError::Process(format!(
                "relay {} membership bootstrap did not reach Ready; membership cleanup: {cleanup}",
                node.node_id
            )),
        });
    }
    if let Err(error) = publish_verified_pins(&membership, &pins) {
        let cleanup = shutdown_membership_until(membership_handle, startup_cleanup_deadline).await;
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => {
                HarnessError::Process(format!("{error}; membership cleanup: {cleanup}"))
            }
        });
    }
    if let Err(error) = peer_readiness
        .replace_required_routes(required_peer_routes(&membership, &node.node_id))
        .map_err(|error| HarnessError::Process(format!("peer readiness routes: {error}")))
    {
        let cleanup = shutdown_membership_until(membership_handle, startup_cleanup_deadline).await;
        return Err(match cleanup {
            Ok(()) => error,
            Err(cleanup) => {
                HarnessError::Process(format!("{error}; membership cleanup: {cleanup}"))
            }
        });
    }
    let running = match config
        .start_with_peer_and_listener_options(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            PeerListenerConfig {
                endpoint: peer_endpoint,
                pins: pins.clone(),
                limits: peer_limits,
            },
            Arc::clone(&peer_runtime),
            ListenerSocketOptions {
                consumer: AcceptedSocketOptions {
                    send_buffer_bytes: consumer_send_buffer_bytes,
                    diagnostics: consumer_socket_diagnostics.clone(),
                },
                consumer_upgrade_barrier,
                consumer_peer_admission_barrier,
                device_control_attach_barrier,
                http_forward: harness.http_forward.clone(),
            },
        )
        .await
    {
        Ok(running) => running,
        Err(error) => {
            let cleanup =
                shutdown_membership_until(membership_handle, startup_cleanup_deadline).await;
            let cleanup_detail = match cleanup {
                Ok(()) => "membership cleanup completed".to_owned(),
                Err(cleanup) => format!("membership cleanup failed: {cleanup}"),
            };
            return Err(HarnessError::Process(format!(
                "starting production relay {}: {error}; {cleanup_detail}",
                node.node_id,
            )));
        }
    };
    Ok(ProductionRelay {
        node_id: node.node_id.clone(),
        peer_source_addr,
        running: Some(running),
        membership,
        membership_handle: Some(membership_handle),
        pins,
        peer_runtime,
        peer_capacity,
        consumer_socket_diagnostics,
        peer_refresh_cancel: CancellationToken::new(),
        peer_refresh: None,
    })
}

fn bind_consumer_listener(send_buffer_bytes: Option<u32>) -> Result<TcpListener> {
    let socket = TcpSocket::new_v4().map_err(HarnessError::Io)?;
    if let Some(bytes) = send_buffer_bytes {
        if !(1024..=1024 * 1024).contains(&bytes) {
            return Err(HarnessError::InvalidInput(
                "production consumer send buffer must be between 1 KiB and 1 MiB".into(),
            ));
        }
        socket
            .set_send_buffer_size(bytes)
            .map_err(HarnessError::Io)?;
    }
    socket
        .bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .map_err(HarnessError::Io)?;
    socket.listen(1024).map_err(HarnessError::Io)
}

/// Checkpoint authority used by the harness.  The checkpoint is signed by the
/// fixture's operator key for every fresh relay nonce; the membership records
/// themselves still come from Redis and are verified by each runtime.
#[derive(Clone)]
struct FixtureCheckpointAuthority {
    issuer: Arc<crate::cluster_fixture::TestMembershipAuthority>,
    deployment_id: String,
    deployment_incarnation: String,
    minimum_versions: BTreeMap<String, u64>,
    /// Every reconciliation nonce needs a fresh checkpoint version.  Sharing
    /// the counter across the three relay runtimes models the operator
    /// authority's single durable version fence and avoids equal-version
    /// conflicts when a runtime refreshes its signed checkpoint.
    next_checkpoint_version: Arc<AtomicU64>,
}

impl CheckpointAuthority for FixtureCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> Pin<
        Box<
            dyn Future<Output = std::result::Result<CheckpointResponse, CheckpointAuthorityError>>
                + Send
                + 'a,
        >,
    > {
        let issuer = self.issuer.clone();
        let deployment_id = self.deployment_id.clone();
        let deployment_incarnation = self.deployment_incarnation.clone();
        let minimum_versions = self.minimum_versions.clone();
        Box::pin(async move {
            let checkpoint_version = self
                .next_checkpoint_version
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |version| {
                    version.checked_add(1)
                })
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?
                + 1;
            let checkpoint = issuer
                .sign_checkpoint_with_version(
                    &deployment_id,
                    &deployment_incarnation,
                    checkpoint_version,
                    request.nonce,
                    minimum_versions,
                    Utc::now(),
                )
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
            CheckpointResponse::new(checkpoint.encoded_bytes().to_vec())
        })
    }
}

fn publish_verified_pins(membership: &MembershipRuntime, pins: &SharedPeerPins) -> Result<()> {
    let snapshot = membership.snapshot();
    if !matches!(snapshot.readiness, MembershipReadiness::Ready) {
        pins.replace(std::iter::empty::<SpkiSha256>())
            .map_err(|error| {
                HarnessError::Process(format!("publishing empty peer pins: {error}"))
            })?;
        return Err(HarnessError::Process(
            "membership runtime is not Ready".into(),
        ));
    }
    let mut digests = Vec::new();
    for record in snapshot.memberships {
        for digest in record.spki_sha256 {
            digests.push(parse_spki_digest(&digest)?);
        }
    }
    pins.replace(digests).map_err(|error| {
        HarnessError::Process(format!("publishing verified peer pins: {error}"))
    })?;
    Ok(())
}

fn required_peer_routes(
    membership: &MembershipRuntime,
    local_node_id: &str,
) -> Vec<PeerRouteTarget> {
    membership
        .verified_peer_route_targets()
        .into_iter()
        .filter(|target| target.node_id() != local_node_id)
        .collect()
}

/// Re-sign and republish every relay's membership record on a fixed interval.
///
/// The relay's verifier caps a record's lifetime at the product maximum, so a
/// scenario that outlives that cap cannot hold a longer record and has to be
/// issued fresh ones, exactly as a real control plane issues them.  The first
/// failure is kept in `failure` rather than only logged, so a re-signer that
/// dies cannot quietly become flakiness in the gate that depends on it.
async fn membership_resign_loop(
    authority: Arc<FixtureCheckpointAuthority>,
    inputs: MembershipResignInputs,
    publisher: RedisMembershipPublisher,
    interval: Duration,
    failure: Arc<Mutex<Option<String>>>,
    shutdown: CancellationToken,
) {
    let record_failure = |message: String| {
        if let Ok(mut guard) = failure.lock()
            && guard.is_none()
        {
            *guard = Some(message);
        }
    };
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // The first tick completes immediately; the bootstrap record was just
    // published, so skip it and re-sign one interval later.
    ticker.tick().await;
    let mut record_version = inputs.next_record_version;
    let mut failing_since: Option<Instant> = None;
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                let now = Utc::now();
                let mut round_failed = false;
                for (identity, peer_endpoint) in &inputs.nodes {
                    let signed = match authority.issuer.sign_membership_identity(
                        &inputs.deployment_id,
                        &inputs.deployment_incarnation,
                        identity,
                        MembershipLifetimeOptions {
                            record_version,
                            peer_endpoint: *peer_endpoint,
                            now,
                            lifetime: M7_MEMBERSHIP_LIFETIME,
                        },
                    ) {
                        Ok(signed) => signed,
                        Err(error) => {
                            record_failure(format!(
                                "re-signing membership for {}: {error}",
                                identity.node_id
                            ));
                            return;
                        }
                    };
                    if let Err(error) = publisher
                        .publish_signed_membership_for_node(
                            &identity.node_id,
                            &signed.catalog_record(),
                        )
                        .await
                    {
                        // A deliberate Redis outage makes this fail for as long
                        // as it lasts.  Retry on the next tick rather than
                        // dying inside the scenario that paused it.
                        round_failed = true;
                        tracing::debug!(
                            node_id = %identity.node_id,
                            ?error,
                            stage = "membership_resign_publish",
                            "membership republish failed; retrying on the next interval"
                        );
                        break;
                    }
                }
                if round_failed {
                    let since = *failing_since.get_or_insert_with(Instant::now);
                    let failing_for = since.elapsed();
                    if failing_for > MEMBERSHIP_RESIGN_FAILURE_GRACE {
                        record_failure(format!(
                            "membership republish kept failing for {} seconds, which is longer \
                             than one record lifetime",
                            failing_for.as_secs()
                        ));
                        return;
                    }
                    // Retry sooner than the ordinary interval so a brief
                    // deliberate outage is ridden out inside the grace rather
                    // than consuming whole scheduled rounds.
                    tokio::select! {
                        _ = shutdown.cancelled() => break,
                        () = sleep(MEMBERSHIP_RESIGN_RETRY_INTERVAL) => {}
                    }
                    continue;
                }
                failing_since = None;
                record_version = record_version.saturating_add(1);
            }
        }
    }
}

async fn peer_refresh_loop(
    membership: Arc<MembershipRuntime>,
    pins: SharedPeerPins,
    peer: Arc<PeerRuntime>,
    local_node_id: String,
    configured_capacity: usize,
    interval: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval.min(Duration::from_secs(5)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                // Pin publication is driven by verified membership invalidation
                // above.  Avoid refreshing it here so a focused key-revocation
                // fixture can hold an explicit withdrawal until restoration.
                if pins.snapshot().is_empty() {
                    // No approved peer key material is published, so there is
                    // no trust evidence to admit any peer.
                    peer.withdraw_peer_trust();
                    continue;
                }
                if !matches!(membership.readiness(), MembershipReadiness::Ready) {
                    // Readiness and admission fail closed, but the verified
                    // route and pin set stays installed so an authenticated
                    // peer's bounded reachability probe is still answered.
                    peer.withdraw_peer_readiness();
                    continue;
                }
                peer.set_peer_capacity(configured_capacity);
                let targets = required_peer_routes(&membership, &local_node_id);
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = peer.refresh_required_routes(targets) => {
                        if let Err(error) = result {
                            tracing::warn!(?error, "production peer readiness probe failed");
                        }
                    }
                }
            }
        }
    }
}

fn parse_spki_digest(value: &str) -> Result<SpkiSha256> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(HarnessError::Pki("invalid signed SPKI digest".into()));
    }
    let mut bytes = [0_u8; 32];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = (hex_value(chunk[0])? << 4) | hex_value(chunk[1])?;
    }
    Ok(SpkiSha256::from_bytes(bytes))
}

fn hex_value(value: u8) -> Result<u8> {
    match value {
        b'0'..=b'9' => Ok(value - b'0'),
        b'a'..=b'f' => Ok(value - b'a' + 10),
        b'A'..=b'F' => Ok(value - b'A' + 10),
        _ => Err(HarnessError::Pki("invalid hex digest".into())),
    }
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(HEX[(byte >> 4) as usize] as char);
        output.push(HEX[(byte & 0x0f) as usize] as char);
    }
    output
}

async fn start_cli_smoke(
    harness: &RunningHarness,
    device_fanout_addr: SocketAddr,
    consumer_addr: SocketAddr,
    profile: &crate::acceptance::helpers::DeviceProfile,
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> Result<(ManagedProcess, ConsumerStream)> {
    if !profile
        .config
        .relay_url
        .contains(&format!(":{}", device_fanout_addr.port()))
    {
        return Err(HarnessError::InvalidInput(
            "CLI profile does not point at the device fanout listener".into(),
        ));
    }
    let binary = client_binary_path()?;
    let process = ManagedProcess::spawn(
        "m7-production-cli",
        ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;
    let mut process = process;
    let deadline = Instant::now() + STARTUP_TIMEOUT;
    loop {
        let status = match process.try_wait() {
            Ok(status) => status,
            Err(error) => {
                return Err(cleanup_cli_startup_failure(
                    process,
                    HarnessError::Process(format!(
                        "could not inspect tunnel-client CLI before production readiness: {error}"
                    )),
                )
                .await);
            }
        };
        if let Some(status) = status {
            // Typed, not stringly: the CLI's exit code is its own closed
            // diagnostic vocabulary, so a caller (the chaos gate) can classify
            // this interruption instead of treating it as a harness failure.
            let diagnostic_code = cli_diagnostic_code(&process.stdout(), &process.stderr());
            return Err(cleanup_cli_startup_failure(
                process,
                HarnessError::CliExitedBeforeReady {
                    stage: "production",
                    code: status.code(),
                    diagnostic_code,
                },
            )
            .await);
        }
        match open_consumer_stream(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            device_id,
            service_id,
        )
        .await
        {
            Ok(stream) => return Ok((process, stream)),
            Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(200)).await;
            }
            Err(_) => {
                return Err(cleanup_cli_startup_failure(
                    process,
                    HarnessError::Timeout(
                        "tunnel-client CLI did not establish a routed session".into(),
                    ),
                )
                .await);
            }
        }
    }
}

/// Recognised `tunnel-client` diagnostic codes.  Only these are surfaced, so
/// a CLI failure can never smuggle free text or payload into harness evidence.
const CLI_DIAGNOSTIC_CODES: [&str; 12] = [
    "INVALID_INVOCATION",
    "CONFIG_ERROR",
    "INVALID_CONFIG",
    "CREDENTIAL_ERROR",
    "CREDENTIAL_MISSING",
    "CREDENTIAL_INVALID",
    "CREDENTIAL_KEY_MISMATCH",
    "CREDENTIAL_PERMISSIONS",
    "CREDENTIAL_EXPIRED",
    "CREDENTIAL_NOT_YET_VALID",
    "TRANSPORT_ERROR",
    "SUPERVISOR_ABSENT",
];

/// Extract the CLI's own typed diagnostic code from its `--json` output.
///
/// The CLI emits one JSON object per line with an optional `error.code`.  Only
/// a code in [`CLI_DIAGNOSTIC_CODES`] is returned, as a `'static` constant, so
/// the result is a closed vocabulary rather than captured process output.
fn cli_diagnostic_code(stdout: &[u8], stderr: &[u8]) -> Option<&'static str> {
    let mut found = None;
    for stream in [stdout, stderr] {
        for line in String::from_utf8_lossy(stream).lines() {
            let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
                continue;
            };
            let Some(code) = value.get("error").and_then(|error| error.get("code")) else {
                continue;
            };
            let Some(code) = code.as_str() else { continue };
            if let Some(known) = CLI_DIAGNOSTIC_CODES
                .iter()
                .find(|candidate| **candidate == code)
            {
                // Keep the last emitted code: it is the terminal one.
                found = Some(*known);
            }
        }
    }
    found
}

async fn cleanup_cli_startup_failure(
    process: ManagedProcess,
    primary: HarnessError,
) -> HarnessError {
    match process.shutdown(Duration::from_secs(2)).await {
        Ok(_) => primary,
        Err(cleanup) => {
            HarnessError::Process(format!("{primary}; CLI startup cleanup failed: {cleanup}"))
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ProcessPauseProbeOutcome {
    /// The consumer WebSocket completed a close after the request was sent.
    ClosedAfterSend,
    /// The consumer WebSocket returned a transport error after the request
    /// was sent.  No application response was observed.
    TransportAfterSend,
    /// The paused process returned an application echo, which is a failure.
    EchoAfterSend,
    /// No bounded close/error arrived before the authorization deadline.
    TimedOut,
    /// The request could not be sent, so the probe cannot prove dispatch was
    /// attempted.
    SendFailed,
    /// The consumer stream returned an unexpected protocol message.
    ProtocolAfterSend,
}

impl ProcessPauseProbeOutcome {
    fn is_fail_closed(self) -> bool {
        matches!(self, Self::ClosedAfterSend | Self::TransportAfterSend)
    }
}

#[cfg(unix)]
fn send_process_signal(pid: u32, signal: &str) -> Result<()> {
    if pid == 0 {
        return Err(HarnessError::Process(
            "managed CLI process returned an invalid PID".into(),
        ));
    }
    let status = std::process::Command::new("/bin/kill")
        .arg(signal)
        .arg(pid.to_string())
        .status()
        .map_err(|error| {
            HarnessError::Process(format!("sending {signal} to managed CLI process: {error}"))
        })?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "sending {signal} to managed CLI process returned {status}"
        )));
    }
    Ok(())
}

#[cfg(not(unix))]
fn send_process_signal(_pid: u32, signal: &str) -> Result<()> {
    Err(HarnessError::Unsupported(format!(
        "process-pause gate requires a Unix SIG{signal} implementation"
    )))
}

fn send_managed_process_signal(process: &mut ManagedProcess, signal: &str) -> Result<()> {
    let pid = process
        .id()
        .ok_or_else(|| HarnessError::Process("managed CLI process is no longer running".into()))?;
    if process.try_wait()?.is_some() {
        return Err(HarnessError::Process(
            "managed CLI process exited before the pause signal".into(),
        ));
    }
    send_process_signal(pid, signal)
}

fn pause_managed_process(process: &mut ManagedProcess) -> Result<()> {
    send_managed_process_signal(process, "-STOP")
}

fn resume_managed_process(process: &mut ManagedProcess) -> Result<()> {
    send_managed_process_signal(process, "-CONT")
}

struct ProcessPauseGuard {
    pid: u32,
    paused: bool,
}

impl ProcessPauseGuard {
    fn new(process: &ManagedProcess) -> Result<Self> {
        let pid = process
            .id()
            .ok_or_else(|| HarnessError::Process("managed CLI process has no live PID".into()))?;
        if pid == 0 {
            return Err(HarnessError::Process(
                "managed CLI process returned an invalid PID".into(),
            ));
        }
        Ok(Self { pid, paused: false })
    }

    fn pause(&mut self, process: &mut ManagedProcess) -> Result<()> {
        pause_managed_process(process)?;
        self.paused = true;
        Ok(())
    }

    fn resume(&mut self, process: &mut ManagedProcess) -> Result<()> {
        let result = resume_managed_process(process);
        if result.is_ok() {
            self.paused = false;
        }
        result
    }
}

impl Drop for ProcessPauseGuard {
    fn drop(&mut self) {
        if self.paused {
            // Drop cannot await ManagedProcess::shutdown.  It must still
            // release SIGSTOP before the ManagedProcess drop-kill path runs,
            // so a cancelled outer timeout cannot leave a stopped child.
            let _ = send_process_signal(self.pid, "-CONT");
            self.paused = false;
        }
    }
}

async fn wait_for_unchanged_application_dispatch(
    relay: &ProductionRelay,
    baseline: u64,
) -> Result<u64> {
    let deadline = Instant::now() + PROCESS_PAUSE_SETTLE_TIMEOUT;
    loop {
        let snapshot = relay.snapshot().await?;
        let observed = snapshot.lifetime_application_dispatches;
        if observed > baseline {
            return Err(HarnessError::Process(format!(
                "paused CLI probe advanced the relay dispatch counter from {baseline} to {observed}"
            )));
        }
        if Instant::now() >= deadline {
            return Ok(observed);
        }
        sleep(Duration::from_millis(50)).await;
    }
}

fn client_binary_path() -> Result<std::path::PathBuf> {
    if let Some(path) = std::env::var_os("TUNNEL_CLIENT_BIN") {
        let path = std::path::PathBuf::from(path);
        if path.is_file() {
            return Ok(path);
        }
        return Err(HarnessError::Process(format!(
            "TUNNEL_CLIENT_BIN does not point to a file: {}",
            path.display()
        )));
    }
    let mut candidates = Vec::new();
    if let Ok(current) = std::env::current_exe()
        && let Some(parent) = current.parent()
    {
        candidates.push(parent.join("tunnel-client"));
        candidates.push(parent.join("tunnel-client.exe"));
        if let Some(target_dir) = parent.parent() {
            candidates.push(target_dir.join("tunnel-client"));
            candidates.push(target_dir.join("tunnel-client.exe"));
        }
    }
    candidates.push(std::path::PathBuf::from("target/debug/tunnel-client"));
    candidates.push(std::path::PathBuf::from("target/debug/tunnel-client.exe"));
    candidates
        .into_iter()
        .find(|path| path.is_file())
        .ok_or_else(|| {
            HarnessError::Process(
                "built tunnel-client binary is missing next to the test executable".into(),
            )
        })
}

fn assert_committed_rotation(
    snapshot: &RelaySnapshot,
    device_id: Uuid,
    expected_rotations: u64,
    expected_generation: u64,
    active_local_addr: Option<SocketAddr>,
) -> Result<()> {
    let session = snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .ok_or_else(|| HarnessError::Process("owner snapshot lost rotated device".into()))?;
    if active_local_addr.is_none()
        || session.rotations_completed < expected_rotations
        || session.active_generation != expected_generation
        || session.candidate_generation.is_some()
        || session.sockets > 2
        || session.phase != "active"
    {
        return Err(HarnessError::Process(format!(
            "rotation {} did not retire its candidate: phase={}, generation={}, candidate={:?}, sockets={}",
            expected_rotations,
            session.phase,
            session.active_generation,
            session.candidate_generation,
            session.sockets
        )));
    }
    Ok(())
}

fn redacted_status(status: &ConnectionStatus) -> String {
    format!(
        "phase={},session={:?},epoch={:?},generation={:?},candidate={:?},rotations={},sockets={:?}",
        status.phase,
        status.session_id,
        status.epoch,
        status.active_generation,
        status.candidate_generation,
        status.rotations_completed,
        (
            status.control_local_addr.is_some(),
            status.active_local_addr.is_some(),
            status.candidate_local_addr.is_some()
        ),
    )
}

fn device_dispatch_counter(snapshot: &RelaySnapshot, device_id: Uuid) -> u64 {
    snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device_id.to_string())
        .map(|session| {
            session
                .streams
                .iter()
                .map(|stream| stream.last_emitted_relay_to_connector)
                .sum()
        })
        .unwrap_or_default()
}

fn client_status_after_stop(client: &ConnectionHandle) -> ConnectionStatus {
    client.status_snapshot()
}

fn bounded_recovery_budget(deadline: Instant, phase: &str) -> Result<Duration> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(HarnessError::Timeout(format!(
            "key-revocation {phase} exceeded its bounded recovery deadline"
        )));
    }
    Ok(remaining)
}

async fn join_connector_with_cleanup_timeout(client: &ConnectionHandle, label: &str) -> Result<()> {
    timeout(CLEANUP_TIMEOUT, client.stop())
        .await
        .map_err(|_| {
            HarnessError::Timeout(format!("{label} did not join before cleanup deadline"))
        })?
        .map_err(|error| HarnessError::Process(format!("{label} shutdown failed: {error}")))
}

async fn wait_for_fanout_drained(
    fanout: &FanoutProxyHandle,
    label: &str,
) -> Result<crate::FanoutProxyDiagnostics> {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let diagnostics = fanout.diagnostics();
        if diagnostics.closed_count >= diagnostics.accepted && diagnostics.open.is_empty() {
            return Ok(diagnostics);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "{label} fanout did not join {} accepted sockets (closed={}, open={})",
                diagnostics.accepted,
                diagnostics.closed_count,
                diagnostics.open.len()
            )));
        }
        sleep(Duration::from_millis(25)).await;
    }
}

fn is_expected_revocation_close(error: &HarnessError) -> bool {
    match error {
        HarnessError::Http(message) => {
            message.starts_with("production echo closed before response")
                || message.starts_with("reading production echo:")
                || message.starts_with("sending production echo:")
        }
        _ => false,
    }
}

fn is_explicit_no_owner_response(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    value.get("code").and_then(serde_json::Value::as_str) == Some("PEER_UNTRUSTED")
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
}

fn is_partition_admission_response(status: u16, body: Option<&[u8]>) -> bool {
    if !matches!(status, 401 | 503) {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let code = value.get("code").and_then(serde_json::Value::as_str);
    let expected_code = match status {
        401 => code == Some("UNAUTHORIZED"),
        503 => matches!(code, Some("AUTHORIZATION_UNAVAILABLE" | "CLUSTER_UNREADY")),
        _ => false,
    };
    expected_code
        && value.get("execution").and_then(serde_json::Value::as_str) == Some("not_dispatched")
}

fn is_peer_recovery_response(status: u16, body: Option<&[u8]>) -> bool {
    if status != 503 {
        return false;
    }
    let Some(body) = body else {
        return false;
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return false;
    };
    let code = value.get("code").and_then(serde_json::Value::as_str);
    let execution = value.get("execution").and_then(serde_json::Value::as_str);
    matches!(
        code,
        Some("CLUSTER_UNREADY") | Some("PEER_UNTRUSTED") | Some("PEER_UNAVAILABLE")
    ) && execution == Some("not_dispatched")
}

fn redacted_admission_failure(body: Option<&[u8]>) -> String {
    let Some(body) = body else {
        return "code=<missing>,execution=<missing>".into();
    };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(body) else {
        return "code=<invalid>,execution=<invalid>".into();
    };
    let code = match value.get("code").and_then(serde_json::Value::as_str) {
        Some("AUTHORIZATION_UNAVAILABLE") => "AUTHORIZATION_UNAVAILABLE",
        Some("CLUSTER_UNREADY") => "CLUSTER_UNREADY",
        Some("PEER_UNAVAILABLE") => "PEER_UNAVAILABLE",
        Some("PEER_UNTRUSTED") => "PEER_UNTRUSTED",
        Some("UNAUTHORIZED") => "UNAUTHORIZED",
        Some("FORBIDDEN") => "FORBIDDEN",
        _ => "<other>",
    };
    let execution = match value.get("execution").and_then(serde_json::Value::as_str) {
        Some("not_dispatched") => "not_dispatched",
        Some("dispatched") => "dispatched",
        Some("unknown") => "unknown",
        _ => "<other>",
    };
    format!("code={code},execution={execution}")
}

async fn verify_authorization_negatives(
    harness: &RunningHarness,
    relay_b: SocketAddr,
    relay_c: SocketAddr,
) -> Result<bool> {
    let expired = harness
        .oidc
        .issue_expired(&harness.topology.consumers_a[0].name)?;
    let shared_device = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no shared device".into()))?;
    let shared_service = *harness
        .topology
        .service_ids
        .get(&shared_device.id)
        .ok_or_else(|| HarnessError::InvalidInput("shared device has no echo service".into()))?;
    let expired_status = expect_consumer_rejection(
        relay_b,
        &harness.pki.server_ca.certificate_der,
        &expired,
        shared_device.id,
        shared_service,
        &[401],
    )
    .await?;
    let limited_device = harness.topology.devices_a.get(1).ok_or_else(|| {
        HarnessError::InvalidInput("tenant A has no scoped negative device".into())
    })?;
    let limited_service = *harness
        .topology
        .service_ids
        .get(&limited_device.id)
        .ok_or_else(|| HarnessError::InvalidInput("scoped device has no echo service".into()))?;
    let unauthorized_scope = harness
        .oidc
        .issue(&harness.topology.limited_member_a.name)?;
    let unauthorized_scope_status = expect_consumer_rejection(
        relay_c,
        &harness.pki.server_ca.certificate_der,
        &unauthorized_scope,
        limited_device.id,
        limited_service,
        &[403, 404],
    )
    .await?;
    Ok(expired_status && unauthorized_scope_status)
}

async fn expect_consumer_rejection(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
    expected: &[u16],
) -> Result<bool> {
    match open_consumer_stream(consumer_addr, server_ca_der, token, device_id, service_id).await {
        Err(StreamConnectFailure::Status { status, .. }) if expected.contains(&status) => Ok(true),
        Err(StreamConnectFailure::Status { status, .. }) => Err(HarnessError::Http(format!(
            "consumer negative returned unexpected HTTP status {status}"
        ))),
        Err(StreamConnectFailure::Harness(error)) => Err(error),
        Ok(mut stream) => {
            let _ = stream.close().await;
            Err(HarnessError::Process(
                "unauthorized consumer unexpectedly upgraded".into(),
            ))
        }
    }
}

type ConsumerSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

struct ConsumerStream {
    socket: ConsumerSocket,
    closed: bool,
}

impl ConsumerStream {
    /// Send one bounded Echo frame and return the actual response payload after
    /// the device canary.  The existing `round_trip` wrapper below preserves
    /// the established call sites while synthetic probes can verify response
    /// envelopes rather than counting request bytes.
    async fn round_trip_capture(&mut self, payload: &[u8], canary: &[u8]) -> Result<Vec<u8>> {
        if !payload.is_empty() {
            crate::c11_capture::record_sentinel("application_payload", payload)?;
        }
        if !canary.is_empty() {
            crate::c11_capture::record_sentinel("application_payload", canary)?;
        }
        if payload.len() > MAX_RECORD_BYTES || canary.len() > MAX_CANARY_BYTES {
            return Err(HarnessError::InvalidInput(
                "production echo record exceeds bounds".into(),
            ));
        }
        let length = u32::try_from(payload.len())
            .map_err(|_| HarnessError::InvalidInput("production echo length overflow".into()))?;
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        self.socket
            .send(Message::Binary(frame.into()))
            .await
            .map_err(|error| HarnessError::Http(format!("sending production echo: {error}")))?;
        let response = timeout(EXCHANGE_TIMEOUT, async {
            let maximum_response_body = MAX_RECORD_BYTES.saturating_add(MAX_CANARY_BYTES);
            let maximum_response_frame = maximum_response_body.saturating_add(4);
            let mut response = Vec::with_capacity(maximum_response_frame);
            loop {
                match self.socket.next().await {
                    Some(Ok(Message::Binary(bytes))) => {
                        if response.len().saturating_add(bytes.len()) > maximum_response_frame {
                            break Err(HarnessError::Http(
                                "production echo response exceeded bounded reassembly".into(),
                            ));
                        }
                        response.extend_from_slice(&bytes);
                        if response.len() < 4 {
                            continue;
                        }
                        let declared = u32::from_be_bytes([
                            response[0],
                            response[1],
                            response[2],
                            response[3],
                        ]) as usize;
                        if declared > maximum_response_body {
                            break Err(HarnessError::Http(
                                "production echo response declared length exceeded bound".into(),
                            ));
                        }
                        let Some(total) = declared.checked_add(4) else {
                            break Err(HarnessError::Http(
                                "production echo response length overflow".into(),
                            ));
                        };
                        if response.len() < total {
                            continue;
                        }
                        if response.len() != total {
                            break Err(HarnessError::Http(
                                "production echo response contained trailing bytes".into(),
                            ));
                        }
                        break Ok(response);
                    }
                    Some(Ok(Message::Ping(bytes))) => {
                        self.socket
                            .send(Message::Pong(bytes))
                            .await
                            .map_err(|error| HarnessError::Http(format!("echo pong: {error}")))?;
                    }
                    Some(Ok(Message::Close(_))) | None => {
                        break Err(HarnessError::Http(
                            "production echo closed before response".into(),
                        ));
                    }
                    Some(Ok(Message::Text(_))) => {
                        break Err(HarnessError::Http("production echo returned text".into()));
                    }
                    Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                    Some(Err(error)) => {
                        break Err(HarnessError::Http(format!(
                            "reading production echo: {error}"
                        )));
                    }
                }
            }
        })
        .await
        .map_err(|_| HarnessError::Timeout("production echo response timed out".into()))??;
        if response.len() < 4 {
            return Err(HarnessError::Http(
                "production echo response omitted length".into(),
            ));
        }
        let declared =
            u32::from_be_bytes([response[0], response[1], response[2], response[3]]) as usize;
        if declared != response.len() - 4
            || declared < canary.len()
            || response[4..4 + canary.len()] != *canary
            || response[4 + canary.len()..] != *payload
        {
            return Err(HarnessError::Http(
                "production echo response mismatch".into(),
            ));
        }
        Ok(response[4 + canary.len()..].to_vec())
    }

    async fn round_trip(&mut self, payload: &[u8], canary: &[u8]) -> Result<()> {
        self.round_trip_capture(payload, canary).await.map(|_| ())
    }

    async fn probe_after_pause(&mut self, payload: &[u8]) -> ProcessPauseProbeOutcome {
        if payload.len() > MAX_RECORD_BYTES {
            return ProcessPauseProbeOutcome::SendFailed;
        }
        let Ok(length) = u32::try_from(payload.len()) else {
            return ProcessPauseProbeOutcome::SendFailed;
        };
        let mut frame = Vec::with_capacity(payload.len() + 4);
        frame.extend_from_slice(&length.to_be_bytes());
        frame.extend_from_slice(payload);
        let deadline = Instant::now() + PROCESS_PAUSE_EXCHANGE_TIMEOUT;
        let send_remaining = deadline.saturating_duration_since(Instant::now());
        if send_remaining.is_zero()
            || !matches!(
                timeout(
                    send_remaining,
                    self.socket.send(Message::Binary(frame.into()))
                )
                .await,
                Ok(Ok(()))
            )
        {
            return ProcessPauseProbeOutcome::SendFailed;
        }

        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return ProcessPauseProbeOutcome::TimedOut;
            }
            let message = match timeout(remaining, self.socket.next()).await {
                Err(_) => return ProcessPauseProbeOutcome::TimedOut,
                Ok(message) => message,
            };
            match message {
                Some(Ok(Message::Binary(_))) => {
                    return ProcessPauseProbeOutcome::EchoAfterSend;
                }
                Some(Ok(Message::Close(_))) | None => {
                    return ProcessPauseProbeOutcome::ClosedAfterSend;
                }
                Some(Ok(Message::Ping(bytes))) => {
                    let pong_remaining = deadline.saturating_duration_since(Instant::now());
                    if pong_remaining.is_zero()
                        || !matches!(
                            timeout(pong_remaining, self.socket.send(Message::Pong(bytes)),).await,
                            Ok(Ok(()))
                        )
                    {
                        return ProcessPauseProbeOutcome::TransportAfterSend;
                    }
                }
                Some(Ok(Message::Text(_))) => {
                    return ProcessPauseProbeOutcome::ProtocolAfterSend;
                }
                Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
                Some(Err(_)) => return ProcessPauseProbeOutcome::TransportAfterSend,
            }
        }
    }

    async fn close(&mut self) -> Result<()> {
        if self.closed {
            return Ok(());
        }
        self.closed = true;
        let _ = timeout(
            Duration::from_secs(5),
            self.socket.send(Message::Close(None)),
        )
        .await;
        let _ = timeout(Duration::from_secs(5), async {
            while let Some(message) = self.socket.next().await {
                match message {
                    Ok(Message::Close(_)) | Err(_) => break,
                    Ok(Message::Ping(bytes)) => {
                        let _ = self.socket.send(Message::Pong(bytes)).await;
                    }
                    Ok(_) => {}
                }
            }
        })
        .await;
        Ok(())
    }
}

enum StreamConnectFailure {
    Status { status: u16, body: Option<Vec<u8>> },
    Harness(HarnessError),
}

async fn open_consumer_stream(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service_id: Uuid,
) -> std::result::Result<ConsumerStream, StreamConnectFailure> {
    open_consumer_stream_target(
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        &service_id.to_string(),
    )
    .await
}

/// Open the public stream route with a raw service path segment, which may be
/// a service-type label rather than an identifier.  Used to prove the stream
/// upgrade resolves labels through the same fail-closed path as the echo
/// route.
async fn open_consumer_stream_target(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service: &str,
) -> std::result::Result<ConsumerStream, StreamConnectFailure> {
    if service.is_empty() || service.len() > 128 || service.contains(['/', '?', '#']) {
        return Err(StreamConnectFailure::Harness(HarnessError::InvalidInput(
            "consumer stream service segment is outside its bound".into(),
        )));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| {
            StreamConnectFailure::Harness(HarnessError::Http(format!("consumer CA: {error}")))
        })?;
    let tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| {
        StreamConnectFailure::Harness(HarnessError::Http(format!("consumer TLS: {error}")))
    })?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let url = format!(
        "wss://localhost:{}/v1/devices/{device_id}/services/{service}/stream",
        consumer_addr.port()
    );
    let mut request = url.into_client_request().map_err(|error| {
        StreamConnectFailure::Harness(HarnessError::Http(format!("consumer request: {error}")))
    })?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).map_err(|error| {
            StreamConnectFailure::Harness(HarnessError::Http(format!("consumer auth: {error}")))
        })?,
    );
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static(ECHO_SUBPROTOCOL),
    );
    let connected = timeout(
        EXCHANGE_TIMEOUT,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(Arc::new(tls)))),
    )
    .await
    .map_err(|_| {
        StreamConnectFailure::Harness(HarnessError::Timeout("consumer handshake timed out".into()))
    })?;
    match connected {
        Ok((socket, response)) => {
            let selected = response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok());
            if selected != Some(ECHO_SUBPROTOCOL) {
                return Err(StreamConnectFailure::Harness(HarnessError::Http(
                    "consumer protocol was not selected".into(),
                )));
            }
            Ok(ConsumerStream {
                socket,
                closed: false,
            })
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            Err(StreamConnectFailure::Status {
                status: response.status().as_u16(),
                body: response.body().clone(),
            })
        }
        Err(error) => Err(StreamConnectFailure::Harness(HarnessError::Http(format!(
            "consumer handshake failed: {error}"
        )))),
    }
}

fn connect_failure_to_harness(error: StreamConnectFailure) -> HarnessError {
    match error {
        StreamConnectFailure::Status { status, .. } => HarnessError::Http(format!(
            "authorized consumer was rejected with HTTP status {status}"
        )),
        StreamConnectFailure::Harness(error) => error,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ConcurrentTenantIsolationEvidence, OwnerRaceEvidence, ProcessPauseProbeOutcome,
        ProductionClusterEvidence, ProductionLivenessEvidence, ROTATION_COUNT,
        RedisPartitionEvidence, is_explicit_no_owner_response, is_partition_admission_response,
        is_peer_recovery_response, redacted_admission_failure, validate_production_evidence,
        validate_redis_partition_evidence,
    };
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn valid_evidence() -> ProductionClusterEvidence {
        ProductionClusterEvidence {
            relay_count: 3,
            tenant_count: 2,
            device_count: 2,
            signed_membership_records: 3,
            membership_ready_relays: 3,
            h3_ingress_relays: 2,
            control_sockets: 3,
            data_sockets: 6,
            device_ingress_relays: 3,
            cli_control_data_sockets: true,
            replacement_generations: 3,
            ordered_records: 4,
            authorization_negatives_rejected: true,
            same_uuid_tenant_isolation_verified: true,
            tenant_isolation: valid_tenant_isolation(),
            owner_race: valid_owner_race(),
            stale_owner_rejected: true,
            key_revocation_rejected: true,
            owner_death_interrupted: true,
            liveness: valid_liveness(),
            elapsed_seconds: 9,
        }
    }

    fn valid_liveness() -> ProductionLivenessEvidence {
        let lease = super::owner_lease_ms();
        let minimum = super::heartbeat_minimum_interval().as_millis() as u64;
        ProductionLivenessEvidence {
            owner_lease_ms: lease,
            heartbeat_minimum_interval_ms: minimum,
            heartbeat_maximum_interval_ms: lease,
            heartbeat_owner_tokens: 2,
            heartbeat_round_trips: 3,
            heartbeat_intervals: 3,
            longest_heartbeat_run_intervals: 2,
            observed_minimum_interval_ms: minimum + 10,
            observed_maximum_interval_ms: minimum + 90,
            heartbeat_intervals_within_bounds: true,
            livez_probes: 3,
            livez_live: 3,
            readyz_probes: 3,
            readyz_ready: 1,
            readyz_unready: 2,
            liveness_up_while_readiness_false: true,
            cli_shutdown_join_bound_ms: super::CLI_SHUTDOWN_JOIN_BOUND.as_millis() as u64,
            cli_shutdown_join_ms: 150,
            cli_shutdown_joined_within_bound: true,
            cli_shutdown_graceful_exit: true,
            cli_shutdown_owner_released: true,
        }
    }

    fn valid_tenant_isolation() -> ConcurrentTenantIsolationEvidence {
        ConcurrentTenantIsolationEvidence {
            shared_device_identifier: true,
            shared_service_identifier: true,
            distinct_tenant_scopes: true,
            distinct_device_credentials: true,
            concurrent_owner_samples: 2,
            distinct_owner_nodes: true,
            distinct_owner_sessions: true,
            tenant_a_exact_canaries: 3,
            tenant_b_exact_canaries: 3,
            distinct_canaries: true,
            cross_tenant_canary_absent: true,
            tenant_a_rotations: ROTATION_COUNT,
            tenant_b_rotations: ROTATION_COUNT,
        }
    }

    fn valid_owner_race() -> OwnerRaceEvidence {
        OwnerRaceEvidence {
            concurrent_launches: true,
            one_atomic_winner: true,
            control_conflict_delta: 1,
            control_conflict_delta_after_settle: 1,
            loser_terminal_owner_busy: true,
            loser_exit_non_success: true,
            winner_token_unchanged: true,
            winner_canary_preserved: true,
            tenant_sibling_preserved: true,
            same_identifier_tenant_owner_unchanged: true,
            same_identifier_tenant_canary_preserved: true,
            winner_epoch: (1_u64 << 53) + 1,
            successor_epoch: (1_u64 << 53) + 2,
            successor_higher_epoch: true,
            epochs_above_js_safe_bound: true,
            stale_cleanup_rejected: true,
            successor_canary: true,
            elapsed_ms: 1,
        }
    }

    #[test]
    fn valid_production_evidence_is_accepted() {
        validate_production_evidence(&valid_evidence())
            .expect("baseline production evidence must pass the extended validator");
    }

    /// The extended gate must refuse a run whose same-identifier isolation or
    /// duplicate-owner race evidence is weakened, even when every pre-existing
    /// production flag still passes.  An offline tenant-B device shows up as a
    /// missing concurrent owner sample, and an accepted `503` in place of a
    /// routed canary as a missing exact canary.
    #[test]
    fn production_evidence_rejects_weakened_isolation_and_race_subgates() {
        // Each label is the evidence field the bounded diagnostic must name, so
        // the mutation proves the rejection came from that exact assertion.
        // The trailing comment records the production failure each one stands
        // for.
        type Mutate = (&'static str, fn(&mut ProductionClusterEvidence));
        let mutations: [Mutate; 10] = [
            // An offline tenant-B device.
            ("concurrent_owner_samples", |e| {
                e.tenant_isolation.concurrent_owner_samples = 1
            }),
            // A 503 accepted in place of tenant A's routed canary.
            ("tenant_a_exact_canaries", |e| {
                e.tenant_isolation.tenant_a_exact_canaries = 1
            }),
            // A 503 accepted in place of tenant B's routed canary.
            ("tenant_b_exact_canaries", |e| {
                e.tenant_isolation.tenant_b_exact_canaries = 1
            }),
            // Tenant B connected but never completed the rotation bound.
            ("tenant_b_rotations", |e| {
                e.tenant_isolation.tenant_b_rotations = ROTATION_COUNT - 1
            }),
            // One tenant's route emitted the other tenant's canary.
            ("cross_tenant_canary_absent", |e| {
                e.tenant_isolation.cross_tenant_canary_absent = false
            }),
            // Both owners landed on one relay, so node separation is unproven.
            ("distinct_owner_nodes", |e| {
                e.tenant_isolation.distinct_owner_nodes = false
            }),
            // A generic transport failure instead of the terminal OWNER_BUSY.
            ("loser_terminal_owner_busy", |e| {
                e.owner_race.loser_terminal_owner_busy = false
            }),
            // A reconnect storm after the loser terminated.
            ("control_conflict_delta_after_settle", |e| {
                e.owner_race.control_conflict_delta_after_settle = 2
            }),
            // The race evicted the same-identifier tenant's owner.
            ("same_identifier_tenant_owner_unchanged", |e| {
                e.owner_race.same_identifier_tenant_owner_unchanged = false
            }),
            // A stale predecessor cleanup was accepted.
            ("stale_cleanup_rejected", |e| {
                e.owner_race.stale_cleanup_rejected = false
            }),
        ];
        for (name, mutate) in mutations {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_production_evidence(&evidence), name);
        }
    }

    /// IN-10/OG-05: the production gate must fail when the heartbeat,
    /// liveness/readiness or bounded-shutdown evidence is missing or
    /// weakened, exactly like the isolation and race sub-gates.  Without
    /// these the row's `records heartbeat/liveness and shutdown evidence`
    /// clause is unasserted and the run only proves the gateway path.
    #[test]
    fn production_evidence_rejects_weakened_liveness_subgate() {
        type Mutate = (&'static str, fn(&mut ProductionClusterEvidence));
        let mutations: [Mutate; 7] = [
            // The session stayed up but no heartbeat was ever counted.
            ("counted owner-lease renewals", |e| {
                e.liveness.heartbeat_round_trips = 0;
                e.liveness.heartbeat_intervals = 0;
                e.liveness.longest_heartbeat_run_intervals = 0;
            }),
            // A renewal landed outside the configured lease window.
            ("escaped the configured window", |e| {
                e.liveness.observed_maximum_interval_ms =
                    e.liveness.heartbeat_maximum_interval_ms + 1;
            }),
            // The bound was invented instead of derived from the lease.
            ("is not derived from owner_lease_ms", |e| {
                e.liveness.heartbeat_minimum_interval_ms += 1;
            }),
            // Readiness never failed closed, so the two endpoints were never
            // distinguished.
            ("readyz_unready was zero", |e| {
                e.liveness.readyz_probes = e.liveness.readyz_ready;
                e.liveness.readyz_unready = 0;
            }),
            ("were never distinguished", |e| {
                e.liveness.liveness_up_while_readiness_false = false;
            }),
            // The CLI ignored its interrupt and had to be force-killed.
            ("force-killed rather than joined", |e| {
                e.liveness.cli_shutdown_graceful_exit = false;
            }),
            // The measured join outran its bound.
            ("exceeded its bound", |e| {
                e.liveness.cli_shutdown_join_ms = e.liveness.cli_shutdown_join_bound_ms + 1;
            }),
        ];
        for (expected, mutate) in mutations {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_production_evidence(&evidence), expected);
        }
    }

    /// The legacy summary flag can no longer be the only isolation assertion:
    /// it must agree with the structured evidence.
    #[test]
    fn production_evidence_rejects_summary_flag_disagreeing_with_structure() {
        let mut evidence = valid_evidence();
        evidence.same_uuid_tenant_isolation_verified = false;
        assert_rejected(
            validate_production_evidence(&evidence),
            "same_uuid_tenant_isolation_verified",
        );
    }

    #[test]
    fn production_evidence_rejects_each_required_false_gate() {
        fn disable_cli(evidence: &mut ProductionClusterEvidence) {
            evidence.cli_control_data_sockets = false;
        }
        fn disable_authorization(evidence: &mut ProductionClusterEvidence) {
            evidence.authorization_negatives_rejected = false;
        }
        fn disable_isolation(evidence: &mut ProductionClusterEvidence) {
            evidence.same_uuid_tenant_isolation_verified = false;
        }
        fn disable_stale_owner(evidence: &mut ProductionClusterEvidence) {
            evidence.stale_owner_rejected = false;
        }
        fn disable_revocation(evidence: &mut ProductionClusterEvidence) {
            evidence.key_revocation_rejected = false;
        }
        fn disable_owner_death(evidence: &mut ProductionClusterEvidence) {
            evidence.owner_death_interrupted = false;
        }

        type GateDisabler = fn(&mut ProductionClusterEvidence);
        let gates: [(&str, GateDisabler); 6] = [
            ("cli_control_data_sockets", disable_cli),
            ("authorization_negatives_rejected", disable_authorization),
            ("same_uuid_tenant_isolation_verified", disable_isolation),
            ("stale_owner_rejected", disable_stale_owner),
            ("key_revocation_rejected", disable_revocation),
            ("owner_death_interrupted", disable_owner_death),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_production_evidence(&evidence), name);
        }
    }

    #[test]
    fn production_evidence_rejects_insufficient_counts() {
        type Mutate = (&'static str, fn(&mut ProductionClusterEvidence));
        let counts: [Mutate; 10] = [
            ("relay_count", |e| e.relay_count = 2),
            ("signed_membership_records", |e| {
                e.signed_membership_records = 2
            }),
            ("membership_ready_relays", |e| e.membership_ready_relays = 2),
            ("h3_ingress_relays", |e| e.h3_ingress_relays = 1),
            ("control_sockets", |e| e.control_sockets = 2),
            ("data_sockets", |e| e.data_sockets = 5),
            ("device_ingress_relays", |e| e.device_ingress_relays = 2),
            ("replacement_generations", |e| e.replacement_generations = 2),
            ("ordered_records", |e| e.ordered_records = 3),
            ("elapsed_seconds", |e| e.elapsed_seconds = 8),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_failed(validate_production_evidence(&evidence));
        }
    }

    fn valid_partition_evidence() -> RedisPartitionEvidence {
        RedisPartitionEvidence {
            relay_count: 3,
            baseline_echo: true,
            partition_admission_rejected: true,
            partition_dispatch_interrupted: true,
            paused_redis_connections: 1,
            recovery_owner_verified: true,
            recovery_echo: true,
            public_livez_ok_during_partition: true,
            public_readyz_unready_during_partition: true,
            public_readyz_ok_after_recovery: true,
            partition_elapsed_ms: 1,
        }
    }

    #[test]
    fn redis_partition_evidence_requires_public_health_gates() {
        fn disable_livez(evidence: &mut RedisPartitionEvidence) {
            evidence.public_livez_ok_during_partition = false;
        }
        fn disable_partition_ready(evidence: &mut RedisPartitionEvidence) {
            evidence.public_readyz_unready_during_partition = false;
        }
        fn disable_recovery_ready(evidence: &mut RedisPartitionEvidence) {
            evidence.public_readyz_ok_after_recovery = false;
        }

        type DisabledGate = (&'static str, fn(&mut RedisPartitionEvidence));
        let gates: [DisabledGate; 3] = [
            ("public_livez_ok_during_partition", disable_livez),
            (
                "public_readyz_unready_during_partition",
                disable_partition_ready,
            ),
            ("public_readyz_ok_after_recovery", disable_recovery_ready),
        ];
        for (name, disable) in gates {
            let mut evidence = valid_partition_evidence();
            disable(&mut evidence);
            assert_rejected(validate_redis_partition_evidence(&evidence), name);
        }

        let mut evidence = valid_partition_evidence();
        evidence.relay_count = 2;
        assert_failed(validate_redis_partition_evidence(&evidence));
        let mut evidence = valid_partition_evidence();
        evidence.paused_redis_connections = 0;
        assert_failed(validate_redis_partition_evidence(&evidence));
    }

    #[test]
    fn production_validator_exit_path_is_bounded_for_each_count_failure() {
        let mut evidence = valid_evidence();
        evidence.elapsed_seconds = 0;
        let diagnostic = assert_failed(validate_production_evidence(&evidence));
        assert!(diagnostic.len() <= 4 * 1024);
    }

    #[test]
    fn redis_partition_validator_exit_path_is_bounded_for_each_count_failure() {
        let mut evidence = valid_partition_evidence();
        evidence.paused_redis_connections = 0;
        let diagnostic = assert_failed(validate_redis_partition_evidence(&evidence));
        assert!(diagnostic.len() <= 4 * 1024);
    }

    #[test]
    fn owner_death_classifier_requires_explicit_not_dispatched_peer_error() {
        let no_owner = br#"{"code":"PEER_UNTRUSTED","execution":"not_dispatched"}"#;
        assert!(is_explicit_no_owner_response(503, Some(no_owner)));
        assert!(!is_explicit_no_owner_response(503, None));
        assert!(!is_explicit_no_owner_response(
            503,
            Some(br#"{"code":"PEER_UNAVAILABLE","execution":"unknown"}"#)
        ));
        assert!(!is_explicit_no_owner_response(502, Some(no_owner)));
    }

    #[test]
    fn restored_path_classifier_accepts_only_bounded_readiness_or_peer_retry() {
        assert!(is_peer_recovery_response(
            503,
            Some(br#"{"code":"CLUSTER_UNREADY","execution":"not_dispatched"}"#)
        ));
        assert!(is_peer_recovery_response(
            503,
            Some(br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched"}"#)
        ));
        assert!(!is_peer_recovery_response(
            503,
            Some(br#"{"code":"CLUSTER_UNREADY","execution":"unknown"}"#)
        ));
        assert!(!is_peer_recovery_response(503, None));
        assert!(!is_peer_recovery_response(
            503,
            Some(br#"{"code":"OTHER_FAILURE","execution":"not_dispatched"}"#)
        ));
    }

    /// The peer-readiness recovery loop must retry the owner-not-ready
    /// envelope the relay actually returns while the selected owner is still
    /// re-establishing its device session. The partition classifier alone does
    /// not cover it -- that is the gap which reported a correct, explicitly
    /// retryable `PEER_UNAVAILABLE` as an unexpected 503 -- so the loop must
    /// consult the peer-recovery classifier as well.
    #[test]
    fn recovery_loop_retries_the_relays_owner_not_ready_envelope() {
        // The exact envelope pinned by tunnel-relay's
        // `http::tests::owner_not_ready_response_is_retryable_before_dispatch`.
        let owner_not_ready = br#"{"code":"PEER_UNAVAILABLE","execution":"not_dispatched","message":"selected owner is not ready; retry after the bounded hint","retryable":true,"retry_after_ms":250}"#;
        assert!(
            !is_partition_admission_response(503, Some(owner_not_ready)),
            "the partition classifier must not be the only retry source"
        );
        assert!(
            is_peer_recovery_response(503, Some(owner_not_ready)),
            "recovery must retry the documented bounded owner-not-ready outcome"
        );
        // A dispatched or unknown outcome is never retried, and neither is an
        // unrelated code: the recovery loop stays fail-closed for those.
        assert!(!is_peer_recovery_response(
            503,
            Some(br#"{"code":"PEER_UNAVAILABLE","execution":"unknown"}"#)
        ));
        assert!(!is_peer_recovery_response(
            503,
            Some(br#"{"code":"RESOURCE_EXHAUSTED","execution":"not_dispatched"}"#)
        ));
        assert!(!is_partition_admission_response(500, Some(owner_not_ready)));
    }

    #[test]
    fn restored_path_diagnostics_are_redacted_to_known_code_and_execution() {
        assert_eq!(
            redacted_admission_failure(Some(
                br#"{"code":"CLUSTER_UNREADY","execution":"not_dispatched","message":"secret"}"#,
            )),
            "code=CLUSTER_UNREADY,execution=not_dispatched"
        );
        assert_eq!(
            redacted_admission_failure(Some(br#"{"code":"PRIVATE_CODE","execution":"secret"}"#,)),
            "code=<other>,execution=<other>"
        );
        assert_eq!(
            redacted_admission_failure(None),
            "code=<missing>,execution=<missing>"
        );
    }

    #[test]
    fn partition_admission_classifier_requires_known_fail_closed_body() {
        let unavailable = br#"{"code":"AUTHORIZATION_UNAVAILABLE","execution":"not_dispatched"}"#;
        let unauthorized = br#"{"code":"UNAUTHORIZED","execution":"not_dispatched"}"#;
        assert!(is_partition_admission_response(503, Some(unavailable)));
        assert!(is_partition_admission_response(401, Some(unauthorized)));
        // Membership reconciliation may withdraw readiness before the
        // authorization lookup runs; either path proves no body admission.
        let unready = br#"{"code":"CLUSTER_UNREADY","execution":"not_dispatched"}"#;
        assert!(is_partition_admission_response(503, Some(unready)));
        assert!(!is_partition_admission_response(401, Some(unready)));
        assert!(!is_partition_admission_response(
            503,
            Some(br#"{"code":"CLUSTER_UNREADY","execution":"unknown"}"#)
        ));
        assert!(!is_partition_admission_response(
            503,
            Some(br#"{"code":"OTHER_FAILURE","execution":"not_dispatched"}"#)
        ));
        assert!(!is_partition_admission_response(503, None));
        assert!(!is_partition_admission_response(
            503,
            Some(br#"{"code":"AUTHORIZATION_UNAVAILABLE","execution":"unknown"}"#)
        ));
        assert!(!is_partition_admission_response(404, Some(unavailable)));
    }

    #[test]
    fn process_pause_probe_accepts_only_terminal_after_send_outcomes() {
        assert!(ProcessPauseProbeOutcome::ClosedAfterSend.is_fail_closed());
        assert!(ProcessPauseProbeOutcome::TransportAfterSend.is_fail_closed());
        for outcome in [
            ProcessPauseProbeOutcome::EchoAfterSend,
            ProcessPauseProbeOutcome::TimedOut,
            ProcessPauseProbeOutcome::SendFailed,
            ProcessPauseProbeOutcome::ProtocolAfterSend,
        ] {
            assert!(
                !outcome.is_fail_closed(),
                "unexpected process-pause outcome accepted: {outcome:?}"
            );
        }
    }

    #[test]
    fn production_and_partition_validators_accept_complete_evidence() {
        validate_production_evidence(&valid_evidence())
            .expect("complete production evidence is valid");
        validate_redis_partition_evidence(&valid_partition_evidence())
            .expect("complete Redis partition evidence is valid");
    }

    #[test]
    fn every_redis_partition_flag_and_bound_names_its_rejection() {
        type Case = (&'static str, &'static str, fn(&mut RedisPartitionEvidence));
        let cases: &[Case] = &[
            ("baseline_echo", "baseline_echo", |e| {
                e.baseline_echo = false
            }),
            (
                "partition_admission_rejected",
                "partition_admission_rejected",
                |e| e.partition_admission_rejected = false,
            ),
            (
                "partition_dispatch_interrupted",
                "partition_dispatch_interrupted",
                |e| e.partition_dispatch_interrupted = false,
            ),
            ("recovery_owner_verified", "recovery_owner_verified", |e| {
                e.recovery_owner_verified = false
            }),
            ("recovery_echo", "recovery_echo", |e| {
                e.recovery_echo = false
            }),
            ("relay_count", "exactly three relays", |e| e.relay_count = 2),
            (
                "paused_redis_connections",
                "paused no Redis connections",
                |e| e.paused_redis_connections = 0,
            ),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_partition_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_redis_partition_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }

    #[test]
    fn every_production_count_names_its_rejection() {
        type Case = (
            &'static str,
            &'static str,
            fn(&mut ProductionClusterEvidence),
        );
        let cases: &[Case] = &[
            ("relay_count", "exactly three relays", |e| e.relay_count = 2),
            (
                "signed_membership_records",
                "signed_membership_records=2 is below required minimum 3",
                |e| e.signed_membership_records = 2,
            ),
            (
                "membership_ready_relays",
                "membership_ready_relays=2 is below required minimum 3",
                |e| e.membership_ready_relays = 2,
            ),
            (
                "h3_ingress_relays",
                "h3_ingress_relays=1 is below required minimum 2",
                |e| e.h3_ingress_relays = 1,
            ),
            (
                "control_sockets",
                "control_sockets=2 is below required minimum 3",
                |e| e.control_sockets = 2,
            ),
            (
                "data_sockets",
                "data_sockets=5 is below required minimum 6",
                |e| e.data_sockets = 5,
            ),
            (
                "device_ingress_relays",
                "device_ingress_relays=2 is below required minimum 3",
                |e| e.device_ingress_relays = 2,
            ),
            (
                "replacement_generations",
                "replacement_generations=2 is below required minimum 3",
                |e| e.replacement_generations = 2,
            ),
            (
                "ordered_records",
                "ordered_records=3 is below required minimum 4",
                |e| e.ordered_records = 3,
            ),
            ("elapsed_seconds", "below the real rotation bound 9", |e| {
                e.elapsed_seconds = 8
            }),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_production_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}
