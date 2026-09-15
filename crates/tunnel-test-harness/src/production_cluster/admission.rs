//! M7 public negative-admission and selected-owner fault acceptance.
//!
//! This module deliberately uses the production three-relay fixture, the
//! fixture's real Redis authority, the built `tunnel-client` process, and the
//! public consumer HTTPS listener.  It does not add a route or an adapter
//! endpoint.  Every negative is classified from the bounded public error
//! envelope and from relay application-dispatch counters; no request body,
//! token, or response payload is included in evidence.

use super::{
    ConsumerStream, ProductionCluster, RunningHarness, assert_public_health_ready,
    public_health_request, start_cli_smoke, validate_public_health_response,
};
use crate::acceptance::helpers::write_device_profile;
use crate::{
    Harness, HarnessError, HarnessOptions, ManagedProcess, OidcTokenOptions, ProxyConfig,
    ProxyHandle, Result, TcpProxy,
};
use bytes::Bytes;
use chrono::Utc;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::CertificateDer;
use rustls::pki_types::ServerName;
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{Instant as TokioInstant, sleep, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tokio_tungstenite::{
    Connector, connect_async_tls_with_config,
    tungstenite::{
        client::IntoClientRequest,
        http::{HeaderName, HeaderValue},
    },
};
use tunnel_catalog::OwnerToken;
use uuid::Uuid;

const SCENARIO_TIMEOUT: Duration = Duration::from_secs(120);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(30);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const CLI_FAILURE_DIAGNOSTIC_WAIT: Duration = Duration::from_secs(2);
const CLI_FAILURE_DIAGNOSTIC_POLL: Duration = Duration::from_millis(25);
const MAX_ERROR_BODY_BYTES: usize = 1024;
const MAX_PUBLIC_ECHO_BODY_BYTES: usize = 64 * 1024;
const MAX_PUBLIC_ECHO_RESPONSE_BYTES: usize = MAX_PUBLIC_ECHO_BODY_BYTES + 256;
const FORGED_TENANT_HEADER: &str = "x-agent-tunnel-tenant-id";
const FORGED_DEVICE_HEADER: &str = "x-agent-tunnel-device-id";
const FORGED_PRINCIPAL_HEADER: &str = "x-agent-tunnel-principal-id";
const FORGED_SERVICE_HEADER: &str = "x-agent-tunnel-service-id";
const FORGED_OWNER_HEADER: &str = "x-agent-tunnel-owner-id";

/// Payload-free evidence from one public three-relay admission matrix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdmissionEvidence {
    /// Number of relays in the production fixture before the selected-owner
    /// fault is injected.
    pub relay_count: usize,
    /// Application dispatches observed on the two selected owner actors after
    /// their baseline canaries.
    pub baseline_target_dispatches: u64,
    pub baseline_sibling_dispatches: u64,
    /// No target, inactive-device, unknown-service, route-label, or forged
    /// negative advanced any relay's application-dispatch counter.
    pub negative_dispatch_delta: u64,
    /// A Redis lookup that could not prove authorization failed closed without
    /// dispatching an application record.
    pub lookup_error_dispatch_delta: u64,
    /// The surviving sibling owner handled exactly one canary after the
    /// selected owner peer path was faulted.
    pub sibling_dispatch_delta_after_owner_loss: u64,
    /// The selected owner handled no application dispatch after its peer path
    /// was faulted.
    pub owner_loss_dispatch_delta: u64,
    pub absent_target_rejected: bool,
    pub inactive_target_rejected: bool,
    pub unknown_target_rejected: bool,
    pub selected_owner_unavailable: bool,
    pub route_allowlist_rejected: bool,
    pub forged_identity_headers_ignored: bool,
    /// An authenticated HTTPS echo ignored caller-supplied tenant, device,
    /// service, and owner headers and returned the path/token-authorized
    /// device canary instead.
    pub forged_identity_http_headers_ignored: bool,
    /// An authenticated HTTPS echo rejected a cross-tenant target before any
    /// application dispatch, even when caller headers supplied a different
    /// tenant, device, service, and owner identity.
    pub forged_identity_http_cross_scope_rejected: bool,
    pub lookup_error_rejected: bool,
    pub sibling_canary_survived: bool,
    /// Set by [`verify`] only after all child processes, sockets, relays, the
    /// Redis namespace, and the Redis proxy have completed bounded cleanup.
    pub cleanup_joined: bool,
}

/// Validate the mandatory public negative-admission evidence.
pub fn validate_admission_evidence(evidence: &AdmissionEvidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "public admission requires exactly three relays, observed {}",
            evidence.relay_count
        )));
    }
    let required = [
        ("absent_target_rejected", evidence.absent_target_rejected),
        (
            "inactive_target_rejected",
            evidence.inactive_target_rejected,
        ),
        ("unknown_target_rejected", evidence.unknown_target_rejected),
        (
            "selected_owner_unavailable",
            evidence.selected_owner_unavailable,
        ),
        (
            "route_allowlist_rejected",
            evidence.route_allowlist_rejected,
        ),
        (
            "forged_identity_headers_ignored",
            evidence.forged_identity_headers_ignored,
        ),
        (
            "forged_identity_http_headers_ignored",
            evidence.forged_identity_http_headers_ignored,
        ),
        (
            "forged_identity_http_cross_scope_rejected",
            evidence.forged_identity_http_cross_scope_rejected,
        ),
        ("lookup_error_rejected", evidence.lookup_error_rejected),
        ("sibling_canary_survived", evidence.sibling_canary_survived),
        ("cleanup_joined", evidence.cleanup_joined),
    ];
    if let Some((name, false)) = required.into_iter().find(|(_, passed)| !passed) {
        return Err(HarnessError::Process(format!(
            "public admission required gate {name} was false"
        )));
    }
    if evidence.baseline_target_dispatches == 0 || evidence.baseline_sibling_dispatches == 0 {
        return Err(HarnessError::Process(
            "baseline canaries did not advance both selected owner counters".into(),
        ));
    }
    if evidence.negative_dispatch_delta != 0 || evidence.lookup_error_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "negative admission dispatched application work: negative_delta={}, lookup_delta={}",
            evidence.negative_dispatch_delta, evidence.lookup_error_dispatch_delta
        )));
    }
    if evidence.owner_loss_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "selected-owner fault dispatched application work: delta={}",
            evidence.owner_loss_dispatch_delta
        )));
    }
    if evidence.sibling_dispatch_delta_after_owner_loss != 1 {
        return Err(HarnessError::Process(format!(
            "sibling canary dispatch count after selected-owner loss was {}, expected one",
            evidence.sibling_dispatch_delta_after_owner_loss
        )));
    }
    Ok(())
}

/// Run the bounded real three-relay public admission matrix.
///
/// The Redis proxy forwards to the same configured Redis service.  It is
/// paused only for the lookup-error row and is resumed before any cleanup.
pub async fn verify() -> Result<AdmissionEvidence> {
    let base_options = HarnessOptions::from_env()?;
    let upstream_url = base_options
        .redis_url
        .clone()
        .ok_or_else(|| HarnessError::MissingRedisUrl {
            env_var: "TEST_REDIS_URL",
            guidance: "The public admission gate requires TEST_REDIS_URL for its bounded Redis lookup fault.".to_owned(),
        })?;
    let redis_target = super::redis_target_address(&upstream_url)?;
    let redis_proxy = TcpProxy::bind(redis_target, ProxyConfig::default()).await?;
    let proxy_url = format!("redis://{}", redis_proxy.local_addr());
    let mut options = base_options
        .redis_url(proxy_url)
        .namespace_prefix("m7-public-admission")
        .rotation(super::ROTATION)
        .shared_device_uuid(true);
    // The acceptance owns its Redis proxy.  Do not accidentally create a
    // second proxy when a developer has a generic proxy setting in the
    // environment.
    options.proxy_target = None;

    let mut harness = match timeout(super::STARTUP_TIMEOUT, Harness::start(options)).await {
        Ok(Ok(harness)) => harness,
        Ok(Err(error)) => {
            return Err(with_admission_cleanup_failures(
                error,
                [(
                    "public admission Redis proxy cleanup",
                    redis_proxy.shutdown().await,
                )],
            ));
        }
        Err(_) => {
            return Err(with_admission_cleanup_failures(
                HarnessError::Timeout("public admission harness startup timed out".into()),
                [(
                    "public admission Redis proxy cleanup",
                    redis_proxy.shutdown().await,
                )],
            ));
        }
    };
    let mut cluster = match ProductionCluster::start(&mut harness).await {
        Ok(cluster) => cluster,
        Err(error) => {
            let harness_cleanup = harness.shutdown().await;
            let proxy_cleanup = redis_proxy.shutdown().await;
            return Err(with_admission_cleanup_failures(
                error,
                [
                    ("public admission Redis cleanup", harness_cleanup),
                    ("public admission Redis proxy cleanup", proxy_cleanup),
                ],
            ));
        }
    };

    let scenario = match timeout(SCENARIO_TIMEOUT, run(&mut cluster, &harness, &redis_proxy)).await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "public admission scenario exceeded its bounded deadline".into(),
        )),
    };
    // A failed probe must not leave the lookup proxy paused while the
    // namespace is being cleaned.  `resume_all` is idempotent for this proxy.
    let proxy_resume = timeout(CLEANUP_TIMEOUT, redis_proxy.resume_all()).await;
    let proxy_resume = match proxy_resume {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "public admission Redis proxy resume timed out".into(),
        )),
    };
    // The relay and Redis namespace share one caller-owned diagnostic
    // deadline.  Their deadline-aware shutdowns retain task-bearing owners
    // while joining; membership persistence's final supervisor join may
    // exceed this deadline, so the deadline is not a hard cancellation of
    // every join.  The proxy is consumed directly so its accept task remains
    // owned until its joined shutdown completes.
    let cleanup_deadline = TokioInstant::now() + super::CLEANUP_TIMEOUT;
    let cluster_cleanup = cluster.shutdown_until(cleanup_deadline).await;
    let harness_cleanup = harness.shutdown_until(cleanup_deadline).await;
    let proxy_cleanup = redis_proxy.shutdown().await;
    let cleanup = [
        ("public admission Redis proxy resume", proxy_resume),
        ("public admission relay cleanup", cluster_cleanup),
        ("public admission Redis cleanup", harness_cleanup),
        ("public admission Redis proxy cleanup", proxy_cleanup),
    ];
    match scenario {
        Err(error) => Err(with_admission_cleanup_failures(error, cleanup)),
        Ok(mut evidence) => {
            if cleanup.iter().any(|(_, result)| result.is_err()) {
                return Err(with_admission_cleanup_failures(
                    HarnessError::Process(
                        "public admission scenario completed but cleanup failed".into(),
                    ),
                    cleanup,
                ));
            }
            evidence.cleanup_joined = true;
            validate_admission_evidence(&evidence)?;
            Ok(evidence)
        }
    }
}

fn with_admission_cleanup_failures<const N: usize>(
    primary: HarnessError,
    failures: [(&str, Result<()>); N],
) -> HarnessError {
    let failures = failures
        .into_iter()
        .filter_map(|(label, result)| result.err().map(|error| format!("{label}: {error}")))
        .collect::<Vec<_>>();
    if failures.is_empty() {
        return primary;
    }
    HarnessError::Process(format!(
        "{primary}; cleanup failures: {}",
        failures.join("; ")
    ))
}

struct LiveCli {
    process: ManagedProcess,
    stream: Option<ConsumerStream>,
}

impl LiveCli {
    async fn close_stream(&mut self) -> Result<()> {
        if let Some(mut stream) = self.stream.take() {
            stream.close().await?;
        }
        Ok(())
    }

    async fn shutdown(mut self) -> Result<()> {
        let stream_result = self.close_stream().await;
        let process_result = self.process.shutdown(Duration::from_secs(5)).await;
        stream_result?;
        process_result.map(|_| ()).map_err(|error| {
            HarnessError::Process(format!("joining public admission CLI: {error}"))
        })
    }
}

async fn run(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
    redis_proxy: &ProxyHandle,
) -> Result<AdmissionEvidence> {
    if cluster.relays.len() != 3 {
        return Err(HarnessError::Process(format!(
            "public admission started {} relays, expected three",
            cluster.relays.len()
        )));
    }
    cluster
        .wait_for_peer_readiness(super::STARTUP_TIMEOUT)
        .await?;
    assert_public_health_ready(
        cluster.relay("relay-a")?.consumer_addr()?,
        &harness.pki.server_ca.certificate_der,
    )
    .await?;

    let target =
        harness.topology.devices_a.first().ok_or_else(|| {
            HarnessError::InvalidInput("public admission target is missing".into())
        })?;
    let sibling =
        harness.topology.devices_a.get(2).ok_or_else(|| {
            HarnessError::InvalidInput("public admission sibling is missing".into())
        })?;
    let inactive = harness.topology.devices_a.get(1).ok_or_else(|| {
        HarnessError::InvalidInput("public admission inactive target is missing".into())
    })?;
    let target_service = *harness
        .topology
        .service_ids
        .get(&target.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("public admission target service is missing".into())
        })?;
    let sibling_service = *harness
        .topology
        .service_ids
        .get(&sibling.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("public admission sibling service is missing".into())
        })?;
    let inactive_service = *harness
        .topology
        .service_ids
        .get(&inactive.id)
        .ok_or_else(|| {
            HarnessError::InvalidInput("public admission inactive service is missing".into())
        })?;
    let target_service_path = target_service.to_string();
    let sibling_service_path = sibling_service.to_string();
    let inactive_service_path = inactive_service.to_string();
    let target_canary = format!("m7-admission-target:{}", target.id);
    let sibling_canary = format!("m7-admission-sibling:{}", sibling.id);
    let target_profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut target_profile = write_device_profile(
        target_profile_dir.path(),
        target.id,
        target_service,
        &target_canary,
        cluster.device_fanout.local_addr(),
        &target.certificate.certificate_pem,
        &target.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    target_profile.config.rotation = super::ROTATION;
    target_profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("public admission target config: {error}"))
    })?;
    let sibling_profile_dir = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut sibling_profile = write_device_profile(
        sibling_profile_dir.path(),
        sibling.id,
        sibling_service,
        &sibling_canary,
        // This TLS-opaque fanout starts at relay-B, so the sibling control
        // owner and its public consumer ingress are the same relay.  The
        // target device continues to use the A-first fanout above.
        cluster.tenant_b_fanout.local_addr(),
        &sibling.certificate.certificate_pem,
        &sibling.certificate.private_key_pem,
        &harness.pki.server_ca.certificate_pem,
    )?;
    sibling_profile.config.rotation = super::ROTATION;
    sibling_profile.config.validate().map_err(|error| {
        HarnessError::InvalidInput(format!("public admission sibling config: {error}"))
    })?;

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
    let initial_target_ingress = cluster.relay("relay-c")?.consumer_addr()?;
    let (target_process, target_stream) = start_cli_smoke(
        harness,
        cluster.device_fanout.local_addr(),
        initial_target_ingress,
        &target_profile,
        &token_a,
        target.id,
        target_service,
    )
    .await?;
    let mut target_cli = LiveCli {
        process: target_process,
        stream: Some(target_stream),
    };
    if let Err(error) = target_cli
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("target stream was not retained".into()))?
        .round_trip(
            b"public-admission-target-baseline",
            target_canary.as_bytes(),
        )
        .await
    {
        let _ = target_cli.shutdown().await;
        return Err(HarnessError::Http(format!(
            "public admission target baseline canary failed: {error}"
        )));
    }
    let target_owner = match cluster
        .catalog
        .current_owner(target.tenant_id, target.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading public admission target owner: {error}"))
        })? {
        Some(owner) => owner,
        None => {
            let _ = target_cli.shutdown().await;
            return Err(HarnessError::Process(
                "target CLI did not retain a public admission owner".into(),
            ));
        }
    };
    let (sibling_process, sibling_stream) = match start_cli_smoke(
        harness,
        cluster.tenant_b_fanout.local_addr(),
        cluster.relay("relay-b")?.consumer_addr()?,
        &sibling_profile,
        &token_a,
        sibling.id,
        sibling_service,
    )
    .await
    {
        Ok(value) => value,
        Err(error) => {
            let _ = target_cli.shutdown().await;
            return Err(error);
        }
    };
    let mut sibling_cli = LiveCli {
        process: sibling_process,
        stream: Some(sibling_stream),
    };
    if let Err(error) = sibling_cli
        .stream
        .as_mut()
        .ok_or_else(|| HarnessError::Process("sibling stream was not retained".into()))?
        .round_trip(
            b"public-admission-sibling-baseline",
            sibling_canary.as_bytes(),
        )
        .await
    {
        let _ = sibling_cli.shutdown().await;
        let _ = target_cli.shutdown().await;
        return Err(HarnessError::Http(format!(
            "public admission sibling baseline canary failed: {error}"
        )));
    }
    let sibling_owner = match cluster
        .catalog
        .current_owner(sibling.tenant_id, sibling.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading public admission sibling owner: {error}"))
        })? {
        Some(owner) => owner,
        None => {
            let _ = sibling_cli.shutdown().await;
            let _ = target_cli.shutdown().await;
            return Err(HarnessError::Process(
                "sibling CLI did not retain a public admission owner".into(),
            ));
        }
    };
    if target_owner.token.node_id == sibling_owner.token.node_id {
        let _ = sibling_cli.shutdown().await;
        let _ = target_cli.shutdown().await;
        return Err(HarnessError::Process(
            "public admission target and sibling owners shared one relay".into(),
        ));
    }
    let target_owner_node = target_owner.token.node_id.clone();
    let sibling_owner_node = sibling_owner.token.node_id.clone();
    if target_owner_node != "relay-a" || sibling_owner_node != "relay-b" {
        let _ = sibling_cli.shutdown().await;
        let _ = target_cli.shutdown().await;
        return Err(HarnessError::Process(format!(
            "public admission fixture owner assignment was not deterministic: target={}, sibling={}, expected target=relay-a and sibling=relay-b",
            target_owner_node, sibling_owner_node
        )));
    }
    let target_owner_relay = cluster.relay(&target_owner_node)?.snapshot().await?;
    let sibling_owner_relay = cluster.relay(&sibling_owner_node)?.snapshot().await?;
    let baseline_target_dispatches = target_owner_relay.lifetime_application_dispatches;
    let baseline_sibling_dispatches = sibling_owner_relay.lifetime_application_dispatches;
    if baseline_target_dispatches == 0 || baseline_sibling_dispatches == 0 {
        let _ = sibling_cli.shutdown().await;
        let _ = target_cli.shutdown().await;
        return Err(HarnessError::Process(
            "public admission baseline canaries did not dispatch".into(),
        ));
    }

    let matrix_result = async {
    let target_ingress = choose_ingress(cluster, &target_owner_node)?;
    let target_public = PublicClient::new(
        target_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
    );
    let target_owner_ingress = cluster.relay(&target_owner_node)?.consumer_addr()?;
    let target_owner_public = PublicClient::new(
        target_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
    );
    // The first target stream is no longer needed.  Keep the sibling stream
    // open across owner loss so the surviving canary exercises an already
    // admitted public route.
    target_cli.close_stream().await?;
    let forged_target_headers = forged_headers(
        harness.topology.tenant_b.id,
        harness.topology.consumers_b[0].id,
        target.id,
        target_service,
        &sibling_owner_node,
    );
    let forged_identity_headers_ignored = forged_stream_canary(
        &target_public,
        target.id,
        target_service_path.as_str(),
        &forged_target_headers,
        target_canary.as_bytes(),
    )
    .await?
        && forged_stream_canary(
            &target_owner_public,
            target.id,
            target_service_path.as_str(),
            &forged_target_headers,
            target_canary.as_bytes(),
        )
        .await?;
    if !forged_identity_headers_ignored {
        return Err(HarnessError::Process(
            "forged public identity headers changed an otherwise valid admission".into(),
        ));
    }

    let forged_http_headers = forged_headers(
        harness.topology.tenant_b.id,
        harness.topology.consumers_b[0].id,
        sibling.id,
        sibling_service,
        &sibling_owner_node,
    );
    let forged_http_before = dispatch_snapshot(cluster).await?;
    let forged_http_remote = forged_http_probe_set(ForgedHttpCorpus {
        ingress_label: "remote",
        consumer_addr: target_ingress,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token: &token_a,
        device_id: target.id,
        service: target_service_path.as_str(),
        headers: &forged_http_headers,
        canary: target_canary.as_bytes(),
    })
    .await?;
    let forged_http_local = forged_http_probe_set(ForgedHttpCorpus {
        ingress_label: "owner-local",
        consumer_addr: target_owner_ingress,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token: &token_a,
        device_id: target.id,
        service: target_service_path.as_str(),
        headers: &forged_http_headers,
        canary: target_canary.as_bytes(),
    })
    .await?;
    let forged_http_after = dispatch_snapshot(cluster).await?;
    let forged_http_target_dispatch_delta = forged_http_after
        .get(&target_owner_node)
        .copied()
        .unwrap_or_default()
        .saturating_sub(
            forged_http_before
                .get(&target_owner_node)
                .copied()
                .unwrap_or_default(),
        );
    let forged_http_other_dispatch_delta = forged_http_after
        .iter()
        .filter(|(node, _)| node.as_str() != target_owner_node.as_str())
        .map(|(node, value)| {
            value.saturating_sub(
                forged_http_before
                    .get(node)
                    .copied()
                    .unwrap_or_default(),
            )
        })
        .fold(0_u64, u64::saturating_add);
    let forged_identity_http_headers_ignored = forged_http_remote
        && forged_http_local
        && forged_http_target_dispatch_delta == 8
        && forged_http_other_dispatch_delta == 0;
    if !forged_identity_http_headers_ignored {
        return Err(HarnessError::Process(format!(
            "HTTPS forged identity headers changed owner-local/remote scope or dispatch: remote_ok={}, local_ok={}, target_dispatch_delta={}, other_dispatch_delta={forged_http_other_dispatch_delta}",
            forged_http_remote,
            forged_http_local,
            forged_http_target_dispatch_delta,
        )));
    }

    let forged_http_cross_scope_headers = forged_headers(
        harness.topology.tenant_b.id,
        harness.topology.consumers_b[0].id,
        target.id,
        target_service,
        &sibling_owner_node,
    );
    let forged_http_cross_scope_before = dispatch_snapshot(cluster).await?;
    let forged_http_cross_scope_failure_remote = public_echo_failure_with_headers(PublicEchoRequest {
        consumer_addr: target_ingress,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token: &token_b,
        device_id: sibling.id,
        service: sibling_service_path.as_str(),
        headers: &forged_http_cross_scope_headers,
        body: b"public-admission-forged-http-cross-scope",
    })
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "public admission remote HTTPS forged cross-scope probe failed: {error}"
        ))
    })?;
    let forged_http_cross_scope_failure_local = public_echo_failure_with_headers(PublicEchoRequest {
        consumer_addr: target_owner_ingress,
        server_ca_der: &harness.pki.server_ca.certificate_der,
        token: &token_b,
        device_id: sibling.id,
        service: sibling_service_path.as_str(),
        headers: &forged_http_cross_scope_headers,
        body: b"public-admission-forged-http-cross-scope",
    })
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "public admission local HTTPS forged cross-scope probe failed: {error}"
        ))
    })?;
    let forged_http_cross_scope_after = dispatch_snapshot(cluster).await?;
    let forged_http_cross_scope_dispatch_delta = common_dispatch_delta(
        &forged_http_cross_scope_before,
        &forged_http_cross_scope_after,
    );
    let forged_identity_http_cross_scope_rejected = [
        forged_http_cross_scope_failure_remote.clone(),
        forged_http_cross_scope_failure_local.clone(),
    ]
    .into_iter()
    .all(|failure| {
        failure.status == 404
            && failure.code == Some("DEVICE_NOT_FOUND")
            && failure.execution == Some("not_dispatched")
    })
        && forged_http_cross_scope_dispatch_delta == 0;
    if !forged_identity_http_cross_scope_rejected {
        return Err(HarnessError::Process(format!(
            "HTTPS forged cross-scope identity was not rejected before owner-local/remote dispatch: remote=({},{:?},{:?}), local=({},{:?},{:?}), dispatch_delta={forged_http_cross_scope_dispatch_delta}",
            forged_http_cross_scope_failure_remote.status,
            forged_http_cross_scope_failure_remote.code,
            forged_http_cross_scope_failure_remote.execution,
            forged_http_cross_scope_failure_local.status,
            forged_http_cross_scope_failure_local.code,
            forged_http_cross_scope_failure_local.execution,
        )));
    }

    cluster
        .catalog
        .revoke_device(inactive.tenant_id, inactive.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("revoking inactive admission fixture: {error}"))
        })?;
    let negative_before = dispatch_snapshot(cluster).await?;
    let absent_device_id = Uuid::new_v4();
    let absent_service_path = Uuid::new_v4().to_string();
    let unknown_service_path = Uuid::new_v4().to_string();
    let absent_probe_remote = target_public
        .reject_named(
            absent_device_id,
            absent_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "absent target",
        )
        .await?;
    let absent_probe_local = target_owner_public
        .reject_named(
            absent_device_id,
            absent_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "absent target through owner-local ingress",
        )
        .await?;
    let inactive_probe_remote = target_public
        .reject_named(
            inactive.id,
            inactive_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "inactive target",
        )
        .await?;
    let inactive_probe_local = target_owner_public
        .reject_named(
            inactive.id,
            inactive_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "inactive target through owner-local ingress",
        )
        .await?;
    let unknown_service_probe_remote = target_public
        .reject_named(
            target.id,
            unknown_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("SERVICE_NOT_FOUND"),
            "unknown service target",
        )
        .await?;
    let unknown_service_probe_local = target_owner_public
        .reject_named(
            target.id,
            unknown_service_path.as_str(),
            &[],
            |failure| failure.status == 404 && failure.code == Some("SERVICE_NOT_FOUND"),
            "unknown service target through owner-local ingress",
        )
        .await?;
    let forged_negative_headers = forged_headers(
        harness.topology.tenant_a.id,
        harness.topology.consumers_a[0].id,
        sibling.id,
        sibling_service,
        &target_owner_node,
    );
    let forged_public = PublicClient::new(
        target_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_b,
    );
    let forged_owner_public = PublicClient::new(
        target_owner_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_b,
    );
    let forged_negative_remote = forged_public
        .reject_named(
            sibling.id,
            sibling_service_path.as_str(),
            &forged_negative_headers,
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "forged cross-tenant target",
        )
        .await?;
    let forged_negative_local = forged_owner_public
        .reject_named(
            sibling.id,
            sibling_service_path.as_str(),
            &forged_negative_headers,
            |failure| failure.status == 404 && failure.code == Some("DEVICE_NOT_FOUND"),
            "forged cross-tenant target through owner-local ingress",
        )
        .await?;
    let route_allowlist_rejected = route_allowlist_negatives(&target_public, target.id).await?;
    let negative_after = dispatch_snapshot(cluster).await?;
    let negative_dispatch_delta = common_dispatch_delta(&negative_before, &negative_after);
    if negative_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "public admission negative matrix advanced application dispatches by {negative_dispatch_delta}"
        )));
    }

    let owner_loss_before = dispatch_snapshot(cluster).await?;
    let selected_owner = cluster
        .catalog
        .current_owner(target.tenant_id, target.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading selected owner before loss: {error}"))
        })?
        .ok_or_else(|| {
            HarnessError::Process("selected owner disappeared before relay loss".into())
        })?;
    if selected_owner.token.node_id != target_owner_node {
        return Err(HarnessError::Process(
            "selected owner changed before the unavailable-owner probe".into(),
        ));
    }
    // Stop only the signed peer path from relay-C (the selected public
    // ingress) to relay-A (the selected owner).  The sibling deliberately
    // uses a local relay-B route in this three-node fixture.  This proves
    // owner admission isolation while keeping the scope explicit; it does
    // not claim two independent cross-relay sibling paths.
    let surviving_ingress_relay = cluster.relay("relay-c")?;
    let surviving_ingress_node = surviving_ingress_relay.node_id.clone();
    if surviving_ingress_node == target_owner_node
        || surviving_ingress_node == sibling_owner_node
        || surviving_ingress_node == "relay-b"
    {
        return Err(HarnessError::Process(
            "public admission fault ingress overlaps an owner or sibling ingress".into(),
        ));
    }
    let surviving_ingress = surviving_ingress_relay.consumer_addr()?;
    cluster.set_peer_path_drop_from(&target_owner_node, &surviving_ingress_node, true)?;
    let selected_owner_after_fault = cluster
        .catalog
        .current_owner(target.tenant_id, target.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("reading selected owner after peer fault: {error}"))
        })?;
    if selected_owner_after_fault
        .as_ref()
        .map(|owner| owner.token.node_id.as_str())
        != Some(target_owner_node.as_str())
    {
        return Err(HarnessError::Process(
            "selected-owner peer fault cleared or changed the owner instead of testing unavailable state".into(),
        ));
    }
    // The public stream route emits its WebSocket 101 before the remote H3
    // exchange starts.  Use the existing HTTPS echo route for this fault row
    // so the response itself proves a typed owner-path failure before any
    // application record can be dispatched.
    let owner_loss_failure = public_echo_failure(
        surviving_ingress,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        target.id,
        target_service_path.as_str(),
        b"public-admission-owner-loss",
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "public admission selected-owner HTTPS fault probe failed: {error}"
        ))
    })?;
    let selected_owner_unavailable = is_selected_owner_failure(&owner_loss_failure);
    if !selected_owner_unavailable {
        return Err(HarnessError::Process(format!(
            "selected-owner loss returned status {} and bounded code {:?}",
            owner_loss_failure.status, owner_loss_failure.code
        )));
    }
    let sibling_stream = sibling_cli.stream.as_mut().ok_or_else(|| {
        HarnessError::Process("sibling stream was not retained after owner loss".into())
    })?;
    if let Err(error) = sibling_stream
        .round_trip(
            b"public-admission-sibling-after-owner-loss",
            sibling_canary.as_bytes(),
        )
        .await
    {
        return Err(HarnessError::Http(format!(
            "public admission sibling canary after selected-owner peer fault failed: {error}; {}",
            admission_fault_context(
                cluster,
                &target_owner_node,
                &sibling_owner_node,
                &surviving_ingress_node,
            )
        )));
    }
    let owner_loss_after = dispatch_snapshot(cluster).await?;
    let owner_loss_dispatch_delta = owner_loss_after
        .get(&target_owner_node)
        .copied()
        .unwrap_or_default()
        .saturating_sub(
            owner_loss_before
                .get(&target_owner_node)
                .copied()
                .unwrap_or_default(),
        );
    if owner_loss_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "selected-owner fault advanced application dispatches by {owner_loss_dispatch_delta}"
        )));
    }
    let sibling_dispatch_delta_after_owner_loss = owner_loss_after
        .get(&sibling_owner_node)
        .copied()
        .unwrap_or_default()
        .saturating_sub(
            owner_loss_before
                .get(&sibling_owner_node)
                .copied()
                .unwrap_or_default(),
        );
    let sibling_canary_survived = sibling_dispatch_delta_after_owner_loss == 1;
    if !sibling_canary_survived {
        return Err(HarnessError::Process(format!(
            "sibling canary dispatch delta after selected-owner loss was {sibling_dispatch_delta_after_owner_loss}"
        )));
    }
    cluster.set_peer_path_drop_from(&target_owner_node, &surviving_ingress_node, false)?;

    // The Redis lookup-failure row runs last of the fault rows because its
    // fault is a *global* authority outage, not a scoped one: `pause_all`
    // stalls every relay's Redis connections, and the row must hold the pause
    // until the relay's own 2 second authority deadline elapses for the typed
    // lookup failure to be produced at all (measured: a 2009 ms window). The
    // relay's maintenance tick runs every 500 ms, so several ticks always fall
    // inside that window; per docs/cluster.md a maintenance read that exceeds
    // the 2 second deadline correctly closes its session with
    // `AUTHORITY_UNAVAILABLE`. Running this row earlier therefore let it close
    // the very device sessions the selected-owner and sibling-canary rows then
    // depended on -- nondeterministically, according to which maintenance
    // commands happened to be in flight when the pause opened -- so those rows
    // failed with "selected owner disappeared"/"cleared or changed the owner"
    // or a dead retained sibling stream. Ordering the global-outage row after
    // every row that needs a live pre-existing session removes that coupling
    // without relaxing anything either row asserts.
    let lookup_before = dispatch_snapshot(cluster).await?;
    let pause_result = redis_proxy.pause_all().await;
    let lookup_probe = match pause_result {
        Ok(()) => {
            target_public
                .open(target.id, target_service_path.as_str(), &[])
                .await
        }
        Err(error) => Err(error),
    };
    let resume_result = redis_proxy.resume_all().await;
    let lookup_error_rejected = match lookup_probe {
        Ok(PublicStreamProbe::Rejected(failure)) if is_lookup_failure(&failure) => true,
        Ok(PublicStreamProbe::Rejected(failure)) => {
            let _ = resume_result;
            return Err(HarnessError::Process(format!(
                "Redis lookup negative returned status {} and bounded code {:?}",
                failure.status, failure.code
            )));
        }
        Ok(PublicStreamProbe::Accepted(mut stream)) => {
            let _ = stream.close().await;
            let _ = resume_result;
            return Err(HarnessError::Process(
                "Redis lookup failure unexpectedly upgraded a consumer stream".into(),
            ));
        }
        Err(error) => {
            let _ = resume_result;
            return Err(error);
        }
    };
    resume_result?;
    super::wait_for_public_health_ready(target_ingress, &harness.pki.server_ca.certificate_der)
        .await?;
    let lookup_after = dispatch_snapshot(cluster).await?;
    let lookup_error_dispatch_delta = common_dispatch_delta(&lookup_before, &lookup_after);
    if !lookup_error_rejected || lookup_error_dispatch_delta != 0 {
        return Err(HarnessError::Process(format!(
            "Redis lookup failure was not a typed no-dispatch result: rejected={}, delta={lookup_error_dispatch_delta}",
            lookup_error_rejected
        )));
    }

    let absent_target_rejected = absent_probe_remote && absent_probe_local;
    let inactive_target_rejected = inactive_probe_remote && inactive_probe_local;
    let unknown_target_rejected =
        unknown_service_probe_remote && unknown_service_probe_local && forged_negative_remote
            && forged_negative_local;
    Ok::<AdmissionEvidence, HarnessError>(AdmissionEvidence {
        relay_count: 3,
        baseline_target_dispatches,
        baseline_sibling_dispatches,
        negative_dispatch_delta,
        lookup_error_dispatch_delta,
        sibling_dispatch_delta_after_owner_loss,
        owner_loss_dispatch_delta,
        absent_target_rejected,
        inactive_target_rejected,
        unknown_target_rejected,
        selected_owner_unavailable,
        route_allowlist_rejected,
        forged_identity_headers_ignored,
        forged_identity_http_headers_ignored,
        forged_identity_http_cross_scope_rejected,
        lookup_error_rejected,
        sibling_canary_survived,
        cleanup_joined: false,
    })
    }
    .await;
    let matrix_result = match matrix_result {
        Ok(evidence) => Ok(evidence),
        Err(error) => Err(annotate_admission_matrix_failure(
            error,
            cluster,
            &target_owner.token,
            &mut target_cli.process,
        )
        .await),
    };
    let sibling_cleanup = sibling_cli.shutdown().await;
    let target_cleanup = target_cli.shutdown().await;
    match (matrix_result, sibling_cleanup, target_cleanup) {
        (Err(error), _, _) => Err(error),
        (Ok(_), Err(error), _) => Err(error),
        (Ok(_), Ok(()), Err(error)) => Err(error),
        (Ok(evidence), Ok(()), Ok(())) => Ok(evidence),
    }
}

/// Attach bounded phase and owner diagnostics before the CLI and relay are
/// cleaned up.  The matrix error already carries the ingress/corpus labels
/// for HTTPS failures; this adds the target process state and the exact
/// payload-free owner snapshot observed at that same failure point.
async fn annotate_admission_matrix_failure(
    error: HarnessError,
    cluster: &ProductionCluster,
    target_owner: &OwnerToken,
    target_process: &mut ManagedProcess,
) -> HarnessError {
    // Let the bounded stdout/stderr drain observe a terminal client record;
    // the helper's fixed wait remains inside the failure diagnostic path.
    tokio::task::yield_now().await;
    let cli = admission_cli_failure_diagnostic(target_process).await;
    let owner = admission_owner_snapshot(cluster, target_owner).await;
    HarnessError::Process(format!(
        "{error}; public admission failure diagnostics: {cli}; {owner}"
    ))
}

async fn admission_owner_snapshot(cluster: &ProductionCluster, owner: &OwnerToken) -> String {
    let relay = match cluster.relay(&owner.node_id) {
        Ok(relay) => relay,
        Err(_) => return format!("target_owner={},snapshot_error=relay_lookup", owner.node_id),
    };
    let snapshot = match timeout(Duration::from_secs(2), relay.snapshot()).await {
        Ok(Ok(snapshot)) => snapshot,
        Ok(Err(_)) => {
            return format!(
                "target_owner={},snapshot_error=relay_snapshot",
                owner.node_id
            );
        }
        Err(_) => return format!("target_owner={},snapshot_timeout=true", owner.node_id),
    };
    let tenant = owner.tenant_id.to_string();
    let device = owner.device_id.to_string();
    let session = snapshot.sessions.iter().find(|session| {
        session.tenant_id == tenant
            && session.device_id == device
            && session.session_id == owner.session_id
            && session.epoch == owner.epoch
    });
    let terminal_reason = snapshot
        .session_terminal_events
        .iter()
        .filter(|event| {
            event.tenant_id == tenant
                && event.device_id == device
                && event.session_id == owner.session_id
                && event.epoch == owner.epoch
        })
        .max_by_key(|event| event.closed_at_ms)
        .map_or("none", |event| event.reason);
    let session_fields = session.map_or_else(
        || format!("session=missing,terminal_reason={terminal_reason}"),
        |session| {
            format!(
                "session=present,session_id={},epoch={},phase={},sockets={},queue_bytes={},queue_messages={},streams={},drain_fences={},drain_proofs={},replay_frames={},replay_bytes={},rotation_deadline_ms={},terminal_reason={terminal_reason}",
                session.session_id,
                session.epoch,
                session.phase,
                session.sockets,
                session.queue_bytes,
                session.queue_messages,
                session.streams.len(),
                session.drain_fences,
                session.drain_proofs,
                session.replay_frames,
                session.replay_bytes,
                session
                    .rotation_deadline_ms
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
            )
        },
    );
    let peer_transport = &snapshot.peer_transport_diagnostics;
    let peer_consumer = &snapshot.peer_consumer_diagnostics;
    format!(
        "target_owner={},expected_tenant={},expected_device={},expected_session={},expected_epoch={},snapshot_monotonic_ms={},session_count={},lifetime_dispatches={},consumer_write_timeout_count={},peer_owner_send_count={},peer_ingress_receive_count={},peer_consumer_owner_send_count={},peer_consumer_owner_receive_count={},peer_consumer_ingress_send_count={},peer_consumer_ingress_receive_count={},terminal_event_count={},{}",
        owner.node_id,
        owner.tenant_id,
        owner.device_id,
        owner.session_id,
        owner.epoch,
        snapshot.monotonic_now_ms,
        snapshot.sessions.len(),
        snapshot.lifetime_application_dispatches,
        snapshot.consumer_write_diagnostics.timeout_count,
        peer_transport.owner_send_count,
        peer_transport.ingress_receive_count,
        peer_consumer.owner_send_count,
        peer_consumer.owner_receive_count,
        peer_consumer.ingress_send_count,
        peer_consumer.ingress_receive_count,
        snapshot.session_terminal_events.len(),
        session_fields,
    )
}

fn admission_cli_diagnostic(process: &mut ManagedProcess) -> String {
    let terminal = match process.try_wait() {
        Ok(Some(status)) => format!(
            "state=exited,success={},exit_code={},signal={}",
            status.success(),
            status
                .code()
                .map_or_else(|| "none".to_owned(), |code| code.to_string()),
            admission_process_signal(status)
                .map_or_else(|| "none".to_owned(), |signal| signal.to_string()),
        ),
        Ok(None) => "state=running".to_owned(),
        Err(_) => "state=unknown".to_owned(),
    };
    let mut protocol_causes = Vec::new();
    collect_admission_protocol_causes(&process.stdout(), &mut protocol_causes);
    collect_admission_protocol_causes(&process.stderr(), &mut protocol_causes);
    format!("target_cli={terminal},target_cli_protocol_causes={protocol_causes:?}")
}

/// Capture a second bounded process snapshot after an admission failure.  A
/// relay can observe CONTROL_CLOSED before the client has flushed its typed
/// protocol error to the bounded stdout/stderr drains; polling `try_wait`
/// keeps the process owned by the normal cleanup path while allowing that
/// terminal record to become observable.  The original failure remains the
/// returned result, and only the fixed protocol-cause allowlist is included.
async fn admission_cli_failure_diagnostic(process: &mut ManagedProcess) -> String {
    let at_failure = admission_cli_diagnostic(process);
    let deadline = TokioInstant::now() + CLI_FAILURE_DIAGNOSTIC_WAIT;
    while TokioInstant::now() < deadline {
        match process.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) | Err(_) => sleep(CLI_FAILURE_DIAGNOSTIC_POLL).await,
        }
    }
    let after_bounded_wait = admission_cli_diagnostic(process);
    format!("target_cli_at_failure={at_failure},target_cli_after_bounded_wait={after_bounded_wait}")
}

#[cfg(unix)]
fn admission_process_signal(status: std::process::ExitStatus) -> Option<i32> {
    std::os::unix::process::ExitStatusExt::signal(&status)
}

#[cfg(not(unix))]
fn admission_process_signal(_status: std::process::ExitStatus) -> Option<i32> {
    None
}

fn collect_admission_protocol_causes(bytes: &[u8], causes: &mut Vec<&'static str>) {
    const MAX_LINES: usize = 64;
    const MAX_CAUSES: usize = 8;
    for line in String::from_utf8_lossy(bytes).lines().take(MAX_LINES) {
        if line.len() > 8 * 1024 || causes.len() >= MAX_CAUSES {
            break;
        }
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line.trim()) else {
            continue;
        };
        let Some(error) = value.get("error").and_then(serde_json::Value::as_object) else {
            continue;
        };
        if error.get("code").and_then(serde_json::Value::as_str) != Some("PROTOCOL_ERROR") {
            continue;
        }
        let Some(message) = error.get("message").and_then(serde_json::Value::as_str) else {
            continue;
        };
        let cause = super::lifecycle::classify_protocol_cause(message);
        if !causes.contains(&cause) {
            causes.push(cause);
        }
    }
}

fn choose_ingress(cluster: &ProductionCluster, owner_node: &str) -> Result<SocketAddr> {
    cluster
        .relays
        .iter()
        .find(|relay| relay.node_id != owner_node)
        .or_else(|| cluster.relays.first())
        .ok_or_else(|| HarnessError::Process("public admission has no consumer ingress".into()))?
        .consumer_addr()
}

/// Return bounded, payload-free routing/readiness context for a sibling
/// isolation failure.  The context identifies the owner/ingress permutation
/// and reports redacted readiness snapshots; it intentionally omits private
/// endpoints and application data.
fn admission_fault_context(
    cluster: &ProductionCluster,
    target_owner_node: &str,
    sibling_owner_node: &str,
    surviving_ingress_node: &str,
) -> String {
    let source_addrs = cluster
        .relays
        .iter()
        .map(|relay| relay.peer_source_addr)
        .collect::<Vec<_>>();
    let source_addrs_distinct = source_addrs.iter().enumerate().all(|(index, address)| {
        source_addrs[index + 1..]
            .iter()
            .all(|other| other != address)
    });
    let surviving_source = cluster
        .relay(surviving_ingress_node)
        .ok()
        .map(|relay| relay.peer_source_addr);
    let sibling_ingress_node = "relay-b";
    let sibling_ingress_source = cluster
        .relay(sibling_ingress_node)
        .ok()
        .map(|relay| relay.peer_source_addr);
    let snapshots = cluster
        .relays
        .iter()
        .map(|relay| {
            let readiness = relay
                .peer_runtime
                .peer_readiness()
                .map(|state| {
                    format!(
                        "ready={},snapshot={:?}",
                        relay.peer_runtime.is_ready(),
                        state.snapshot()
                    )
                })
                .unwrap_or_else(|| "unconfigured".to_owned());
            format!(
                "{}:membership={:?},{}",
                relay.node_id,
                relay.membership.readiness(),
                readiness
            )
        })
        .collect::<Vec<_>>()
        .join("|");
    format!(
        "target_owner={target_owner_node},sibling_owner={sibling_owner_node},fault_ingress={surviving_ingress_node},sibling_ingress={sibling_ingress_node},sibling_owner_is_sibling_ingress={},fault_ingress_is_sibling_ingress={},source_addrs_distinct={source_addrs_distinct},fault_source_is_sibling_source={},relays=[{snapshots}]",
        sibling_owner_node == sibling_ingress_node,
        surviving_ingress_node == sibling_ingress_node,
        surviving_source == sibling_ingress_source,
    )
}

async fn dispatch_snapshot(cluster: &ProductionCluster) -> Result<BTreeMap<String, u64>> {
    let mut snapshot = BTreeMap::new();
    for relay in &cluster.relays {
        snapshot.insert(
            relay.node_id.clone(),
            relay.snapshot().await?.lifetime_application_dispatches,
        );
    }
    Ok(snapshot)
}

fn common_dispatch_delta(before: &BTreeMap<String, u64>, after: &BTreeMap<String, u64>) -> u64 {
    before
        .iter()
        .filter_map(|(node, value)| {
            after
                .get(node)
                .map(|observed| observed.saturating_sub(*value))
        })
        .fold(0_u64, u64::saturating_add)
}

fn forged_headers(
    tenant_id: Uuid,
    principal_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    owner_id: &str,
) -> Vec<(&'static str, String)> {
    vec![
        (FORGED_TENANT_HEADER, tenant_id.to_string()),
        (FORGED_PRINCIPAL_HEADER, principal_id.to_string()),
        (FORGED_DEVICE_HEADER, device_id.to_string()),
        (FORGED_SERVICE_HEADER, service_id.to_string()),
        (FORGED_OWNER_HEADER, owner_id.to_owned()),
    ]
}

struct PublicClient<'a> {
    consumer_addr: SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
}

impl<'a> PublicClient<'a> {
    fn new(consumer_addr: SocketAddr, server_ca_der: &'a [u8], token: &'a str) -> Self {
        Self {
            consumer_addr,
            server_ca_der,
            token,
        }
    }

    async fn open(
        &self,
        device_id: Uuid,
        service: &str,
        headers: &[(&'static str, String)],
    ) -> Result<PublicStreamProbe> {
        open_public_stream(
            self.consumer_addr,
            self.server_ca_der,
            self.token,
            device_id,
            service,
            headers,
        )
        .await
    }

    async fn reject_named<F>(
        &self,
        device_id: Uuid,
        service: &str,
        headers: &[(&'static str, String)],
        expected: F,
        label: &'static str,
    ) -> Result<bool>
    where
        F: FnOnce(&AdmissionFailure) -> bool,
    {
        match self.open(device_id, service, headers).await? {
            PublicStreamProbe::Rejected(failure) if expected(&failure) => Ok(true),
            PublicStreamProbe::Rejected(failure) => Err(HarnessError::Process(format!(
                "{label} returned status {} and bounded code {:?}",
                failure.status, failure.code
            ))),
            PublicStreamProbe::Accepted(mut stream) => {
                let _ = stream.close().await;
                Err(HarnessError::Process(format!(
                    "{label} unexpectedly upgraded a consumer stream"
                )))
            }
        }
    }
}

/// Exercise the real consumer WSS upgrade and one bounded echo exchange.  The
/// caller supplies the ingress address, so the same authenticated target is
/// checked through both its owner-local listener and a remote relay listener.
async fn forged_stream_canary(
    client: &PublicClient<'_>,
    device_id: Uuid,
    service: &str,
    headers: &[(&'static str, String)],
    canary: &[u8],
) -> Result<bool> {
    match client.open(device_id, service, headers).await? {
        PublicStreamProbe::Accepted(mut stream) => {
            let result = stream
                .round_trip(b"public-admission-forged-header-canary", canary)
                .await;
            let _ = stream.close().await;
            Ok(result.is_ok())
        }
        PublicStreamProbe::Rejected(_) => Ok(false),
    }
}

async fn route_allowlist_negatives(client: &PublicClient<'_>, device_id: Uuid) -> Result<bool> {
    let service_labels = ["control", "health", "membership", "diagnostic"];
    for label in service_labels {
        let probe = client.open(device_id, label, &[]).await?;
        match probe {
            PublicStreamProbe::Rejected(failure)
                if failure.status == 404
                    && failure.code == Some("SERVICE_NOT_FOUND")
                    && failure.execution == Some("not_dispatched") => {}
            PublicStreamProbe::Rejected(failure) => {
                return Err(HarnessError::Process(format!(
                    "route label {label} returned status {} and bounded code {:?}",
                    failure.status, failure.code
                )));
            }
            PublicStreamProbe::Accepted(mut stream) => {
                let _ = stream.close().await;
                return Err(HarnessError::Process(format!(
                    "route label {label} unexpectedly reached an adapter"
                )));
            }
        }
    }

    let live = public_health_request(client.consumer_addr, client.server_ca_der, "/livez").await?;
    validate_public_health_response(&live, "/livez", 200, super::LIVEZ_BODY)?;
    let ready =
        public_health_request(client.consumer_addr, client.server_ca_der, "/readyz").await?;
    validate_public_health_response(&ready, "/readyz", 200, super::READYZ_BODY)?;
    for path in ["/v1/tunnel/control", "/v1/membership", "/diagnostics"] {
        let response =
            public_health_request(client.consumer_addr, client.server_ca_der, path).await?;
        if response.status != 404 {
            return Err(HarnessError::Process(format!(
                "public route {path} returned status {}, expected 404",
                response.status
            )));
        }
    }
    Ok(true)
}

fn is_lookup_failure(failure: &AdmissionFailure) -> bool {
    (failure.status == 401 && failure.code == Some("UNAUTHORIZED")
        || failure.status == 503
            && matches!(
                failure.code,
                Some("AUTHORIZATION_UNAVAILABLE") | Some("CLUSTER_UNREADY")
            ))
        && matches!(failure.execution, Some("not_dispatched") | Some("unknown"))
}

fn is_selected_owner_failure(failure: &AdmissionFailure) -> bool {
    failure.status == 503
        && matches!(
            failure.code,
            Some("PEER_UNAVAILABLE") | Some("PEER_UNTRUSTED")
        )
        && matches!(failure.execution, Some("not_dispatched") | Some("unknown"))
}

fn echo_body_matches(response: &[u8], canary: &[u8], payload: &[u8]) -> bool {
    response.len() == canary.len().saturating_add(payload.len())
        && response.starts_with(canary)
        && response.get(canary.len()..) == Some(payload)
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct AdmissionFailure {
    pub(super) status: u16,
    pub(super) code: Option<&'static str>,
    pub(super) execution: Option<&'static str>,
}

pub(super) struct PublicEchoRequest<'a> {
    pub(super) consumer_addr: SocketAddr,
    pub(super) server_ca_der: &'a [u8],
    pub(super) token: &'a str,
    pub(super) device_id: Uuid,
    pub(super) service: &'a str,
    pub(super) headers: &'a [(&'static str, String)],
    pub(super) body: &'a [u8],
}

pub(super) enum PublicStreamProbe {
    Accepted(Box<ConsumerStream>),
    Rejected(AdmissionFailure),
}

async fn public_echo_failure(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service: &str,
    body: &'static [u8],
) -> Result<AdmissionFailure> {
    public_echo_failure_with_headers(PublicEchoRequest {
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service,
        headers: &[],
        body,
    })
    .await
}

async fn public_echo_failure_with_headers(
    request: PublicEchoRequest<'_>,
) -> Result<AdmissionFailure> {
    let (status, body) = public_echo_request(request).await?;
    if status == 200 {
        return Ok(AdmissionFailure {
            status,
            code: None,
            execution: None,
        });
    }
    let value = serde_json::from_slice::<serde_json::Value>(&body).map_err(|_| {
        HarnessError::Http("public admission echo error was not bounded JSON".into())
    })?;
    Ok(AdmissionFailure {
        status,
        code: value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .and_then(known_failure_code),
        execution: value
            .get("execution")
            .and_then(serde_json::Value::as_str)
            .and_then(known_execution),
    })
}

/// Run the bounded HTTPS body corpus through one ingress.  The response must
/// contain the owner canary followed by exactly the supplied consumer body;
/// this catches a caller identity header changing the selected tenant/device/
/// service while keeping the request and response sizes bounded.
struct ForgedHttpCorpus<'a> {
    ingress_label: &'static str,
    consumer_addr: SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
    device_id: Uuid,
    service: &'a str,
    headers: &'a [(&'static str, String)],
    canary: &'a [u8],
}

async fn forged_http_probe_set(corpus: ForgedHttpCorpus<'_>) -> Result<bool> {
    let ForgedHttpCorpus {
        ingress_label,
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service,
        headers,
        canary,
    } = corpus;
    let small_input = b"public-admission-forged-http-header-canary";
    let small_body = public_echo_success(
        PublicEchoRequest {
            consumer_addr,
            server_ca_der,
            token,
            device_id,
            service,
            headers,
            body: small_input,
        },
        ingress_label,
        "small",
    )
    .await?;
    let empty_input: &[u8] = &[];
    let empty_body = public_echo_success(
        PublicEchoRequest {
            consumer_addr,
            server_ca_der,
            token,
            device_id,
            service,
            headers,
            body: empty_input,
        },
        ingress_label,
        "empty",
    )
    .await?;
    let maximum_input = vec![0x5a; MAX_PUBLIC_ECHO_BODY_BYTES];
    let maximum_body = public_echo_success(
        PublicEchoRequest {
            consumer_addr,
            server_ca_der,
            token,
            device_id,
            service,
            headers,
            body: &maximum_input,
        },
        ingress_label,
        "maximum",
    )
    .await?;
    let repeated_input = b"public-admission-forged-http-repeat";
    let repeated_body = public_echo_success(
        PublicEchoRequest {
            consumer_addr,
            server_ca_der,
            token,
            device_id,
            service,
            headers,
            body: repeated_input,
        },
        ingress_label,
        "repeated",
    )
    .await?;
    let checks = [
        ("small", &small_body[..], small_input.as_slice()),
        ("empty", &empty_body[..], empty_input),
        ("maximum", &maximum_body[..], &maximum_input[..]),
        ("repeated", &repeated_body[..], repeated_input.as_slice()),
    ];
    for (corpus_label, response, input) in checks {
        if !echo_body_matches(response, canary, input) {
            return Err(HarnessError::Process(format!(
                "public admission HTTPS forged-header body mismatch: ingress={ingress_label},corpus={corpus_label},response_len={},canary_len={},request_len={}",
                response.len(),
                canary.len(),
                input.len(),
            )));
        }
    }
    Ok(true)
}

/// Send a successful authenticated HTTPS echo while retaining caller-supplied
/// headers for admission-boundary tests.  The handler currently ignores
/// identity headers by design; this helper verifies the authenticated token
/// and path still select the expected device export and returns only the
/// bounded response body.
async fn public_echo_success(
    request: PublicEchoRequest<'_>,
    ingress_label: &'static str,
    corpus_label: &'static str,
) -> Result<Vec<u8>> {
    let (status, response_body) = public_echo_request(request).await.map_err(|error| {
        HarnessError::Http(format!(
            "public admission HTTPS forged-header echo transport failure: ingress={ingress_label},corpus={corpus_label},kind={}",
            admission_error_kind(&error),
        ))
    })?;
    if status != 200 {
        let value = serde_json::from_slice::<serde_json::Value>(&response_body).map_err(|_| {
            HarnessError::Http(format!(
                "public admission HTTPS forged-header response was not bounded JSON: ingress={ingress_label},corpus={corpus_label},status={status}"
            ))
        })?;
        let code = value
            .get("code")
            .and_then(serde_json::Value::as_str)
            .and_then(known_failure_code)
            .unwrap_or("UNKNOWN");
        let execution = value
            .get("execution")
            .and_then(serde_json::Value::as_str)
            .and_then(known_execution)
            .unwrap_or("unknown");
        return Err(HarnessError::Http(format!(
            "public admission HTTPS forged-header echo failed: ingress={ingress_label},corpus={corpus_label},status={status},code={code},execution={execution}"
        )));
    }
    Ok(response_body)
}

pub(super) async fn public_echo_request(request: PublicEchoRequest<'_>) -> Result<(u16, Vec<u8>)> {
    let PublicEchoRequest {
        consumer_addr,
        server_ca_der,
        token,
        device_id,
        service,
        headers,
        body,
    } = request;
    // The public echo handler can spend the relay's configured operation
    // budget in peer/H3 admission.  Use the harness's established exchange
    // bound for this route instead of the shorter WebSocket handshake bound.
    let deadline = TokioInstant::now() + super::EXCHANGE_TIMEOUT;
    if service.is_empty() || service.len() > 128 || body.len() > MAX_PUBLIC_ECHO_BODY_BYTES {
        return Err(HarnessError::InvalidInput(
            "public admission echo probe is outside its bound".into(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("admission echo CA: {error}")))?;
    let client_config = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("admission echo TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(deadline, tokio::net::TcpStream::connect(consumer_addr))
        .await
        .map_err(|_| HarnessError::Timeout("public admission echo TCP connect timed out".into()))?
        .map_err(HarnessError::Io)?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("admission echo server name: {error}")))?;
    let tls_stream = timeout_at(deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout("public admission echo TLS timed out".into()))?
        .map_err(|error| HarnessError::Http(format!("public admission echo TLS: {error}")))?;
    let (mut sender, connection) = timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    .map_err(|_| HarnessError::Timeout("public admission echo HTTP timed out".into()))?
    .map_err(|error| HarnessError::Http(format!("public admission echo HTTP: {error}")))?;
    let mut connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let result: Result<(u16, Vec<u8>)> = async {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!(
                "https://localhost:{}/v1/devices/{device_id}/services/{service}/echo",
                consumer_addr.port()
            ))
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream");
        for (name, value) in headers {
            request = request.header(*name, value.as_str());
        }
        let request = request
            .body(Full::new(Bytes::copy_from_slice(body)))
            .map_err(|error| {
                HarnessError::Http(format!("building public admission echo: {error}"))
            })?;
        let response = timeout_at(deadline, sender.send_request(request))
            .await
            .map_err(|_| HarnessError::Timeout("public admission echo timed out".into()))?
            .map_err(|error| {
                HarnessError::Http(format!("public admission echo failed: {error}"))
            })?;
        let status = response.status().as_u16();
        let body = timeout_at(
            deadline,
            Limited::new(response.into_body(), MAX_PUBLIC_ECHO_RESPONSE_BYTES).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout("reading public admission echo timed out".into()))?
        .map_err(|_| HarnessError::Http("public admission echo body exceeded its bound".into()))?
        .to_bytes();
        Ok((status, body.to_vec()))
    }
    .await;
    drop(sender);
    if timeout_at(deadline, &mut connection_task).await.is_err() {
        connection_task.abort();
        let _ = connection_task.await;
    }
    result
}

async fn open_public_stream(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    token: &str,
    device_id: Uuid,
    service: &str,
    headers: &[(&'static str, String)],
) -> Result<PublicStreamProbe> {
    let authorization = format!("Bearer {token}");
    open_public_stream_with_authorization(
        consumer_addr,
        server_ca_der,
        &authorization,
        device_id,
        service,
        headers,
    )
    .await
}

/// Open the same bounded public WSS route with an explicit authorization
/// header.  C10 uses the lowercase bearer scheme to exercise the raw-token
/// forwarding path without exposing token material in diagnostics.
pub(super) async fn open_public_stream_with_authorization(
    consumer_addr: SocketAddr,
    server_ca_der: &[u8],
    authorization: &str,
    device_id: Uuid,
    service: &str,
    headers: &[(&'static str, String)],
) -> Result<PublicStreamProbe> {
    if service.is_empty() || service.len() > 128 {
        return Err(HarnessError::InvalidInput(
            "public admission service path is outside its bound".into(),
        ));
    }
    let mut roots = rustls::RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("admission consumer CA: {error}")))?;
    let tls = rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    .map_err(|error| HarnessError::Http(format!("admission consumer TLS: {error}")))?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let url = format!(
        "wss://localhost:{}/v1/devices/{device_id}/services/{service}/stream",
        consumer_addr.port()
    );
    let mut request = url.into_client_request().map_err(|error| {
        HarnessError::Http(format!("building public admission request: {error}"))
    })?;
    request.headers_mut().insert(
        "authorization",
        HeaderValue::from_str(authorization)
            .map_err(|error| HarnessError::Http(format!("admission auth header: {error}")))?,
    );
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("agent-tunnel.echo.v1"),
    );
    for (name, value) in headers {
        request.headers_mut().insert(
            HeaderName::from_static(name),
            HeaderValue::from_str(value)
                .map_err(|error| HarnessError::Http(format!("admission forged header: {error}")))?,
        );
    }
    let connected = timeout(
        REQUEST_TIMEOUT,
        connect_async_tls_with_config(request, None, true, Some(Connector::Rustls(Arc::new(tls)))),
    )
    .await
    .map_err(|_| HarnessError::Timeout("public admission handshake timed out".into()))?;
    match connected {
        Ok((socket, response)) => {
            let selected = response
                .headers()
                .get("sec-websocket-protocol")
                .and_then(|value| value.to_str().ok());
            if selected != Some("agent-tunnel.echo.v1") {
                return Err(HarnessError::Http(
                    "public admission selected an unexpected subprotocol".into(),
                ));
            }
            Ok(PublicStreamProbe::Accepted(Box::new(ConsumerStream {
                socket,
                closed: false,
            })))
        }
        Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
            let body = response.body().as_deref().unwrap_or_default();
            if body.len() > MAX_ERROR_BODY_BYTES {
                return Err(HarnessError::Http(
                    "public admission error body exceeded its bound".into(),
                ));
            }
            let value = serde_json::from_slice::<serde_json::Value>(body).map_err(|_| {
                HarnessError::Http("public admission error was not bounded JSON".into())
            })?;
            let code = value
                .get("code")
                .and_then(serde_json::Value::as_str)
                .and_then(known_failure_code);
            let execution = value
                .get("execution")
                .and_then(serde_json::Value::as_str)
                .and_then(known_execution);
            Ok(PublicStreamProbe::Rejected(AdmissionFailure {
                status: response.status().as_u16(),
                code,
                execution,
            }))
        }
        Err(error) => Err(HarnessError::Http(format!(
            "public admission handshake failed: {error}"
        ))),
    }
}

fn known_failure_code(value: &str) -> Option<&'static str> {
    match value {
        "ADMISSION_LIMIT" => Some("ADMISSION_LIMIT"),
        "BODY_LIMIT" => Some("BODY_LIMIT"),
        "BODY_TIMEOUT" => Some("BODY_TIMEOUT"),
        "DEVICE_NOT_FOUND" => Some("DEVICE_NOT_FOUND"),
        "DEVICE_MTLS_REQUIRED" => Some("DEVICE_MTLS_REQUIRED"),
        "DATA_TICKET_REQUIRED" => Some("DATA_TICKET_REQUIRED"),
        "FORBIDDEN" => Some("FORBIDDEN"),
        "NOT_FOUND" => Some("NOT_FOUND"),
        "REVERSE_CHANNEL_INTERRUPTED" => Some("REVERSE_CHANNEL_INTERRUPTED"),
        "REVERSE_CHANNEL_UNAVAILABLE" => Some("REVERSE_CHANNEL_UNAVAILABLE"),
        "SERVICE_NOT_FOUND" => Some("SERVICE_NOT_FOUND"),
        "SOCKET_LIMIT" => Some("SOCKET_LIMIT"),
        "STREAM_LIMIT" => Some("STREAM_LIMIT"),
        "AUTHORIZATION_UNAVAILABLE" => Some("AUTHORIZATION_UNAVAILABLE"),
        "CLUSTER_UNREADY" => Some("CLUSTER_UNREADY"),
        "UNAUTHORIZED" => Some("UNAUTHORIZED"),
        "PEER_UNAVAILABLE" => Some("PEER_UNAVAILABLE"),
        "PEER_UNTRUSTED" => Some("PEER_UNTRUSTED"),
        "SUBPROTOCOL_REQUIRED" => Some("SUBPROTOCOL_REQUIRED"),
        _ => None,
    }
}

fn admission_error_kind(error: &HarnessError) -> &'static str {
    match error {
        HarnessError::Timeout(_) => "timeout",
        HarnessError::Http(_) => "http",
        HarnessError::Io(_) => "io",
        HarnessError::Json(_) => "json",
        HarnessError::InvalidInput(_) => "invalid_input",
        HarnessError::Process(_) => "process",
        HarnessError::CliExitedBeforeReady { .. } => "cli_exited_before_ready",
        HarnessError::Redis(_) => "redis",
        HarnessError::Proxy(_) => "proxy",
        HarnessError::Pki(_) => "pki",
        HarnessError::Jwt(_) => "jwt",
        HarnessError::MissingRedisUrl { .. } => "missing_redis_url",
        HarnessError::InvalidRedisUrl { .. } => "invalid_redis_url",
        HarnessError::Unsupported(_) => "unsupported",
    }
}

fn known_execution(value: &str) -> Option<&'static str> {
    match value {
        "not_dispatched" => Some("not_dispatched"),
        "unknown" => Some("unknown"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{AdmissionEvidence, validate_admission_evidence};
    use crate::acceptance_test_support::{assert_failed, assert_rejected};

    fn evidence() -> AdmissionEvidence {
        AdmissionEvidence {
            relay_count: 3,
            baseline_target_dispatches: 1,
            baseline_sibling_dispatches: 1,
            negative_dispatch_delta: 0,
            lookup_error_dispatch_delta: 0,
            sibling_dispatch_delta_after_owner_loss: 1,
            owner_loss_dispatch_delta: 0,
            absent_target_rejected: true,
            inactive_target_rejected: true,
            unknown_target_rejected: true,
            selected_owner_unavailable: true,
            route_allowlist_rejected: true,
            forged_identity_headers_ignored: true,
            forged_identity_http_headers_ignored: true,
            forged_identity_http_cross_scope_rejected: true,
            lookup_error_rejected: true,
            sibling_canary_survived: true,
            cleanup_joined: true,
        }
    }

    #[test]
    fn admission_evidence_requires_zero_negative_dispatch() {
        let mut value = evidence();
        value.negative_dispatch_delta = 1;
        assert!(validate_admission_evidence(&value).is_err());
    }

    #[test]
    fn admission_evidence_requires_selected_owner_fault_and_cleanup() {
        let mut value = evidence();
        value.selected_owner_unavailable = false;
        assert!(validate_admission_evidence(&value).is_err());
        value = evidence();
        value.cleanup_joined = false;
        assert!(validate_admission_evidence(&value).is_err());
        value = evidence();
        value.owner_loss_dispatch_delta = 1;
        assert!(validate_admission_evidence(&value).is_err());
    }

    #[test]
    fn every_admission_flag_and_dispatch_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut AdmissionEvidence));
        let flags: [Disable; 11] = [
            ("absent_target_rejected", |e| {
                e.absent_target_rejected = false
            }),
            ("inactive_target_rejected", |e| {
                e.inactive_target_rejected = false
            }),
            ("unknown_target_rejected", |e| {
                e.unknown_target_rejected = false
            }),
            ("selected_owner_unavailable", |e| {
                e.selected_owner_unavailable = false
            }),
            ("route_allowlist_rejected", |e| {
                e.route_allowlist_rejected = false
            }),
            ("forged_identity_headers_ignored", |e| {
                e.forged_identity_headers_ignored = false
            }),
            ("forged_identity_http_headers_ignored", |e| {
                e.forged_identity_http_headers_ignored = false
            }),
            ("forged_identity_http_cross_scope_rejected", |e| {
                e.forged_identity_http_cross_scope_rejected = false
            }),
            ("lookup_error_rejected", |e| e.lookup_error_rejected = false),
            ("sibling_canary_survived", |e| {
                e.sibling_canary_survived = false
            }),
            ("cleanup_joined", |e| e.cleanup_joined = false),
        ];
        for (name, disable) in flags {
            let mut value = evidence();
            disable(&mut value);
            assert_rejected(validate_admission_evidence(&value), name);
        }

        type Mutate = (&'static str, fn(&mut AdmissionEvidence));
        let bounds: [Mutate; 5] = [
            ("baseline_target_dispatches", |e| {
                e.baseline_target_dispatches = 0
            }),
            ("baseline_sibling_dispatches", |e| {
                e.baseline_sibling_dispatches = 0
            }),
            ("negative_dispatch_delta", |e| e.negative_dispatch_delta = 1),
            ("lookup_error_dispatch_delta", |e| {
                e.lookup_error_dispatch_delta = 1
            }),
            ("sibling_dispatch_delta_after_owner_loss", |e| {
                e.sibling_dispatch_delta_after_owner_loss = 0
            }),
        ];
        for (_, mutate) in bounds {
            let mut value = evidence();
            mutate(&mut value);
            assert_failed(validate_admission_evidence(&value));
        }
        let mut owner_loss = evidence();
        owner_loss.owner_loss_dispatch_delta = 1;
        assert_rejected(
            validate_admission_evidence(&owner_loss),
            "selected-owner fault",
        );
        let mut relay_count = evidence();
        relay_count.relay_count = 2;
        assert_rejected(
            validate_admission_evidence(&relay_count),
            "public admission",
        );
    }

    #[test]
    fn admission_validator_accepts_complete_evidence() {
        validate_admission_evidence(&evidence()).expect("complete admission evidence is valid");
    }

    #[test]
    fn sibling_dispatch_after_owner_loss_must_be_exactly_one() {
        let mut value = evidence();
        value.sibling_dispatch_delta_after_owner_loss = 2;
        assert_rejected(validate_admission_evidence(&value), "expected one");
    }
}
