//! Process-bound recovery acceptance for one configured relay.
//!
//! This ignored gate intentionally crosses the executable and socket boundaries:
//! a configured relay serves an authenticated device before recovery, the
//! operator recovery CLI consumes a signed approval while every writer is
//! quiesced, and a fresh candidate-incarnation relay serves a new device
//! session afterward.  A separate device is revoked before the approval and
//! remains unauthorized after the candidate starts.

use std::{
    collections::BTreeMap,
    env,
    path::Path,
    process::{Child, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore,
    pki_types::{CertificateDer, ServerName},
};
use sha2::{Digest, Sha256};
use tokio::time::{sleep, timeout, timeout_at};
use tokio_rustls::TlsConnector;
use tunnel_catalog::{
    Catalog, CatalogError, OwnerClaimRequest, RecoveryApproval, RecoveryApprovalIssuer,
    RedisCatalog, RedisMembershipPublisher,
};
use tunnel_client::{
    ConnectConfig, ConnectOptions, CredentialConfig, LimitsConfig, LocalExport, LocalExportKind,
    connect,
};
use tunnel_core::RotationConfig;
use tunnel_test_harness::{
    ClusterFixture, FixturePki, FixtureTopology, HarnessError, ManagedProcess, OidcFixture,
    ProcessSpec, Result,
};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

#[path = "common/m7_deployment.rs"]
mod common;
use common::{
    CheckpointServer, FixtureFiles, ProcessConfigFixture, RedisTlsProxy, free_tcp_addr,
    health_request, hex_encode, jwks_json, parse_plaintext_upstream, process_diagnostic,
    relay_binary_path, send_sigint, wait_for_exit, wait_for_ports_released, wait_for_ready,
};

const TEST_DEADLINE: Duration = Duration::from_secs(180);
const CLI_DEADLINE: Duration = Duration::from_secs(20);
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);
const EXCHANGE_DEADLINE: Duration = Duration::from_secs(30);
const SHUTDOWN_DEADLINE: Duration = Duration::from_secs(8);
const CATALOG_TICKET_QUIESCENCE: Duration = Duration::from_secs(11);
const OWNER_DEVICE_PERMISSION_LIFETIME: Duration = Duration::from_secs(30);
const MEMBERSHIP_TRUST_LIFETIME: Duration = Duration::from_secs(60);
const ALLOWED_MEMBERSHIP_CLOCK_SKEW: Duration = Duration::from_secs(1);
const DEPLOYMENT_ID_PREFIX: &str = "m7-recovery-process-deployment";
const INITIAL_INCARC_PREFIX: &str = "m7-recovery-process-initial";
const CANDIDATE_INCARC_PREFIX: &str = "m7-recovery-process-candidate";
const APPROVAL_NONCE: &str = "m7-recovery-process-nonce-0001";
/// Quiescence acknowledgement identifier used only for the refused
/// older-digest attempt, so the accepted run keeps its own identifier.
const STALE_DIGEST_ACKNOWLEDGEMENT: &str = "m7-recovery-process-stale-digest";
/// The acknowledgement identifier for the accepted recovery.
const RECOVERY_ACKNOWLEDGEMENT: &str = "m7-recovery-process-quiescence";
/// The bounded operator diagnostic for an approval bound to a catalog digest
/// that no longer matches the observed durable catalog. This is the sole
/// `Display` text for `RecoveryWorkflowError::CatalogDigestMismatch`, so
/// matching it distinguishes the digest fence from every other refusal.
const CATALOG_DIGEST_MISMATCH_DIAGNOSTIC: &str =
    "recovery approval does not match the live catalog observation";
/// The typed catalog conflict cause for a write against a superseded
/// deployment incarnation.
const ACTIVE_INCARNATION_CONFLICT: &str = "active deployment incarnation";
const OPERATOR_KEY_ID: &str = "m7-recovery-process-operator";
const CANARY: &str = "m7-recovery-process-canary";
const PAYLOAD: &[u8] = b"post-recovery-configured-serve";

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TEST_REDIS_URL; run explicitly as the configured recovery process gate"]
async fn m7_configured_recovery_process_preserves_revocation_and_fresh_echo() {
    let evidence = timeout(TEST_DEADLINE, run_process_recovery_gate())
        .await
        .expect("configured recovery process gate exceeded its overall deadline")
        .expect("configured recovery process gate");
    validate_configured_recovery_evidence(&evidence)
        .expect("configured recovery evidence contract");
    println!(
        "M7 configured recovery passed: quiescence_ms={} revocation_before_recovery={} \
         digest_drift_observed={} stale_digest_approval_refused={} \
         unfenced_writer_claim_refused={} stale_writer_connect_refused={} \
         stale_serve_failed_closed={} candidate_revocation_retained={} \
         fresh_session_generation={} fresh_candidate_echo={} revoked_device_refused={}",
        evidence.quiescence_wait_ms,
        evidence.revocation_enforced_before_recovery,
        evidence.digest_drift_observed,
        evidence.stale_digest_approval_refused,
        evidence.unfenced_writer_claim_refused,
        evidence.stale_writer_connect_refused,
        evidence.stale_serve_process_failed_closed,
        evidence.candidate_revocation_retained,
        evidence.fresh_session_generation,
        evidence.fresh_candidate_echo,
        evidence.revoked_device_refused_after_recovery,
    );
}

/// Payload-free evidence from the configured recovery process gate.
#[derive(Clone, Debug, Eq, PartialEq)]
struct ConfiguredRecoveryEvidence {
    /// Measured wall-clock milliseconds waited after both the old relay and
    /// the old checkpoint stopped, covering the configured owner/device
    /// permission lifetime, the signed membership trust lifetime and the
    /// configured clock skew.
    quiescence_wait_ms: u64,
    /// The retained device revocation was already enforced before recovery.
    revocation_enforced_before_recovery: bool,
    /// An unfenced writer moved durable catalog state after the operator
    /// observed its digest, and the next observation reported a different one.
    digest_drift_observed: bool,
    /// An approval bound to the earlier catalog digest was refused with the
    /// bounded catalog-digest cause.
    stale_digest_approval_refused: bool,
    /// A never-fenced writer that still held its connection and its old
    /// configured incarnation was refused an ownership claim after activation,
    /// with the typed active-incarnation conflict.
    unfenced_writer_claim_refused: bool,
    /// A fresh connect on the superseded incarnation was refused.
    stale_writer_connect_refused: bool,
    /// A stale configured serve process failed closed without exposing
    /// readiness and released its listeners.
    stale_serve_process_failed_closed: bool,
    /// The candidate incarnation still refused the revoked device credential.
    candidate_revocation_retained: bool,
    /// Generation reported by the fresh post-recovery device session.
    fresh_session_generation: u64,
    /// The fresh candidate session returned its canary over public HTTP.
    fresh_candidate_echo: bool,
    /// The revoked device could not establish an authenticated session after
    /// recovery.
    revoked_device_refused_after_recovery: bool,
}

/// Validate the configured recovery evidence contract.
fn validate_configured_recovery_evidence(evidence: &ConfiguredRecoveryEvidence) -> Result<()> {
    let required = [
        (
            "revocation_enforced_before_recovery",
            evidence.revocation_enforced_before_recovery,
        ),
        ("digest_drift_observed", evidence.digest_drift_observed),
        (
            "stale_digest_approval_refused",
            evidence.stale_digest_approval_refused,
        ),
        (
            "unfenced_writer_claim_refused",
            evidence.unfenced_writer_claim_refused,
        ),
        (
            "stale_writer_connect_refused",
            evidence.stale_writer_connect_refused,
        ),
        (
            "stale_serve_process_failed_closed",
            evidence.stale_serve_process_failed_closed,
        ),
        (
            "candidate_revocation_retained",
            evidence.candidate_revocation_retained,
        ),
        ("fresh_candidate_echo", evidence.fresh_candidate_echo),
        (
            "revoked_device_refused_after_recovery",
            evidence.revoked_device_refused_after_recovery,
        ),
    ];
    for (field, satisfied) in required {
        if !satisfied {
            return Err(HarnessError::Process(format!(
                "configured recovery evidence is incomplete: {field}"
            )));
        }
    }
    if evidence.fresh_session_generation == 0 {
        return Err(HarnessError::Process(
            "configured recovery fresh session reported generation zero".into(),
        ));
    }
    let minimum_quiescence = MEMBERSHIP_TRUST_LIFETIME
        .saturating_add(ALLOWED_MEMBERSHIP_CLOCK_SKEW)
        .max(OWNER_DEVICE_PERMISSION_LIFETIME);
    let minimum_quiescence_ms = u64::try_from(minimum_quiescence.as_millis()).unwrap_or(u64::MAX);
    if evidence.quiescence_wait_ms < minimum_quiescence_ms {
        return Err(HarnessError::Process(format!(
            "configured recovery waited only {} ms, below the {minimum_quiescence_ms} ms lifetime-plus-skew boundary",
            evidence.quiescence_wait_ms
        )));
    }
    Ok(())
}

#[cfg(unix)]
async fn run_process_recovery_gate() -> Result<ConfiguredRecoveryEvidence> {
    let relay_binary = relay_binary_path()?;
    let upstream_url = env::var("TEST_REDIS_URL").map_err(|_| HarnessError::MissingRedisUrl {
        env_var: "TEST_REDIS_URL",
        guidance:
            "the configured recovery process gate requires a disposable plaintext Redis upstream"
                .into(),
    })?;
    let upstream = parse_plaintext_upstream(&upstream_url)?;

    let run_id = Uuid::new_v4().simple().to_string();
    let deployment_id = format!("{DEPLOYMENT_ID_PREFIX}-{run_id}");
    let initial_incarnation = format!("{INITIAL_INCARC_PREFIX}-{run_id}");
    let candidate_incarnation = format!("{CANDIDATE_INCARC_PREFIX}-{run_id}");
    let namespace = format!("m7-recovery-process-fixture-{run_id}");
    let node_id = "relay-a".to_owned();

    let files = FixtureFiles::new()?;
    let pki = FixturePki::new()?;
    let oidc = OidcFixture::new(
        format!("https://m7-recovery-process-oidc-{run_id}.invalid"),
        "agent-tunnel",
    )?;
    let topology = FixtureTopology::new(&pki)?;
    let catalog_fixture = topology.catalog_fixture(&oidc)?;
    let active_device = topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("missing active canary device".into()))?;
    let revoked_device = topology
        .devices_a
        .get(1)
        .ok_or_else(|| HarnessError::InvalidInput("missing revoked device".into()))?;
    // A third device exists only so an unfenced writer can move durable
    // catalog state after the operator observed its digest.
    let drift_device = topology
        .devices_a
        .get(2)
        .ok_or_else(|| HarnessError::InvalidInput("missing digest-drift device".into()))?;
    let active_service = *topology
        .service_ids
        .get(&active_device.id)
        .ok_or_else(|| HarnessError::InvalidInput("active canary service missing".into()))?;
    let revoked_spki = revoked_device.certificate.spki_fingerprint_sha256()?;
    let consumer = topology
        .consumers_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("missing consumer fixture".into()))?;

    let cluster = ClusterFixture::with_deployment(&pki, &deployment_id, &initial_incarnation)?;
    let (peer_bind, peer_chain, peer_key, membership) = {
        let node = cluster
            .node(&node_id)
            .ok_or_else(|| HarnessError::InvalidInput("recovery process node missing".into()))?;
        let membership = cluster
            .membership(&node_id)
            .ok_or_else(|| {
                HarnessError::InvalidInput("recovery process membership missing".into())
            })?
            .catalog_record();
        (
            node.addresses.udp,
            node.peer_certificate_chain_pem(),
            node.peer_certificate.private_key_pem.clone(),
            membership,
        )
    };
    let mut node = cluster
        .nodes
        .into_iter()
        .find(|candidate| candidate.node_id == node_id)
        .ok_or_else(|| HarnessError::InvalidInput("recovery process node missing".into()))?;
    node.release_ports();
    let signer = Arc::new(cluster.membership_authority);

    let server_leaf = pki.issue_server("m7-recovery-process-relay")?;
    let checkpoint_leaf = pki.issue_server("m7-recovery-process-checkpoint")?;
    let redis_leaf = pki.issue_server("m7-recovery-process-redis")?;
    let server_chain = format!(
        "{}{}",
        server_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let checkpoint_chain = format!(
        "{}{}",
        checkpoint_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let redis_chain = format!(
        "{}{}",
        redis_leaf.certificate_pem, pki.server_ca.certificate_pem
    );
    let redis_tls = load_server_config_from_pem(
        redis_chain.as_bytes(),
        redis_leaf.private_key_pem.as_bytes(),
        None,
    )
    .map_err(|error| HarnessError::Pki(format!("building recovery Redis TLS proxy: {error}")))?;
    let redis_proxy = RedisTlsProxy::bind(upstream, redis_tls).await?;
    let relay_redis_url = redis_proxy.url();

    let catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, &initial_incarnation)
            .await
            .map_err(|error| {
                HarnessError::Redis(format!("opening recovery process catalog: {error}"))
            })?;
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("activating recovery process catalog: {error}"))
        })?;
    catalog
        .seed_fixture(&catalog_fixture)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("seeding recovery process catalog: {error}"))
        })?;

    let publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("opening recovery membership publisher: {error}"))
        })?;
    publisher
        .publish_signed_membership_for_node(&node_id, &membership)
        .await
        .map_err(|error| HarnessError::Redis(format!("publishing initial membership: {error}")))?;
    drop(publisher);

    let signer_trust_path = files.write(
        "membership-trust.json",
        format!(
            "{{\"keys\":[{{\"key_id\":{},\"public_key\":{}}}]}}",
            serde_json::to_string(signer.key_id())?,
            serde_json::to_string(&hex_encode(&signer.public_key()))?,
        )
        .as_bytes(),
    )?;
    let oidc_jwks_path = files.write("oidc-jwks.json", jwks_json(&oidc)?.as_bytes())?;
    let server_chain_path = files.write("relay-cert-chain.pem", server_chain.as_bytes())?;
    let server_key_path = files.write("relay-key.pem", server_leaf.private_key_pem.as_bytes())?;
    let server_ca_path = files.write("server-ca.pem", pki.server_ca.certificate_pem.as_bytes())?;
    let device_ca_path = files.write("device-ca.pem", pki.device_ca.certificate_pem.as_bytes())?;
    let peer_chain_path = files.write("peer-cert-chain.pem", peer_chain.as_bytes())?;
    let peer_key_path = files.write("peer-key.pem", peer_key.as_bytes())?;
    let peer_ca_path = files.write("peer-ca.pem", pki.peer_ca.certificate_pem.as_bytes())?;
    let state_path = files.state_path()?;
    let state_parent = state_path
        .parent()
        .ok_or_else(|| HarnessError::InvalidInput("membership state has no parent".into()))?
        .to_owned();
    let fence_path = state_parent.join("recovery-fence.json");
    let trusted_keys_path = state_parent.join("recovery-trusted-keys.json");
    let approval_path = state_parent.join("recovery-approval.json");
    let candidate_state_path = state_parent.join("candidate-membership-state.json");

    let consumer_bind = free_tcp_addr();
    let device_bind = distinct_tcp_addr(consumer_bind);
    let old_checkpoint = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| HarnessError::Pki(format!("building initial checkpoint TLS: {error}")))?,
        signer.clone(),
        deployment_id.clone(),
        initial_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), 1)]),
    )
    .await?;
    let old_checkpoint_endpoint = format!(
        "https://localhost:{}/v1/checkpoint",
        old_checkpoint.address().port()
    );

    let old_config_fixture = ProcessConfigFixture {
        consumer_bind,
        device_bind,
        peer_bind,
        redis_url: &relay_redis_url,
        namespace: &namespace,
        deployment_id: &deployment_id,
        deployment_incarnation: &initial_incarnation,
        oidc: &oidc,
        oidc_jwks_path: &oidc_jwks_path,
        server_chain_path: &server_chain_path,
        server_key_path: &server_key_path,
        server_ca_path: &server_ca_path,
        device_ca_path: &device_ca_path,
        peer_chain_path: &peer_chain_path,
        peer_key_path: &peer_key_path,
        peer_ca_path: &peer_ca_path,
        signer_trust_path: &signer_trust_path,
        state_path: &state_path,
        checkpoint_endpoint: &old_checkpoint_endpoint,
        node_id: &node_id,
    };
    let old_config_path = files.write(
        "relay-initial.toml",
        with_recovery_config(
            &old_config_fixture.render(),
            &fence_path,
            &trusted_keys_path,
            &candidate_incarnation,
        )
        .as_bytes(),
    )?;
    initialize_state(&relay_binary, &old_config_path).await?;
    let old_process = start_relay(
        &relay_binary,
        &old_config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        &pki.server_ca.certificate_der,
        "m7-recovery-process-old",
    )
    .await?;

    let active_client_config = write_client_config(
        &files,
        "active-device",
        active_device.id,
        active_service,
        CANARY,
        device_bind,
        &active_device.certificate.certificate_pem,
        &active_device.certificate.private_key_pem,
        &pki.device_ca.certificate_pem,
        &pki.server_ca.certificate_pem,
    )?;
    let mut active_client = connect_fresh(&active_client_config).await?;
    let old_session = timeout(CONNECT_DEADLINE, active_client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("initial device DataReady deadline".into()))?
        .map_err(|error| HarnessError::Process(format!("initial device DataReady: {error}")))?;
    if old_session.generation == 0 {
        return Err(HarnessError::Process(
            "initial device session reported generation zero".into(),
        ));
    }
    let token = oidc.issue(&consumer.name)?;
    echo_http(EchoProbe {
        consumer_bind,
        server_ca_der: &pki.server_ca.certificate_der,
        token: &token,
        device_id: active_device.id,
        service_id: active_service,
        payload: PAYLOAD,
        canary: CANARY.as_bytes(),
        phase: "initial",
    })
    .await?;
    active_client.stop().await.map_err(|error| {
        HarnessError::Process(format!("stopping initial device session: {error}"))
    })?;

    stop_relay(
        old_process,
        consumer_bind,
        device_bind,
        peer_bind,
        "initial relay",
    )
    .await?;
    old_checkpoint.shutdown().await?;
    let fenced_at = Instant::now();

    catalog
        .revoke_device(revoked_device.tenant_id, revoked_device.id, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("revoking retained device: {error}")))?;
    if catalog
        .resolve_device(&revoked_spki, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("checking retained revocation: {error}")))?
        .is_some()
    {
        return Err(HarnessError::Process(
            "revoked device remained authorized before recovery".into(),
        ));
    }
    let revocation_enforced_before_recovery = true;

    // The initial cluster registration consumes its one-use catalog
    // attachment ticket. Redis marks the ticket hash spent and removes its
    // ticket-index member, then retains the spent hash until the fixed
    // ten-second ticket TTL expires. The recovery scanner deliberately
    // rejects that transient orphan, so quiesce past natural expiry rather
    // than deleting catalog state or weakening the scanner's relationship
    // check.
    sleep(CATALOG_TICKET_QUIESCENCE).await;

    // The operator declaration supplied to `recover` records that fencing
    // happened, but the CLI cannot prove elapsed time. This fixture supplies
    // that temporal boundary explicitly: the configured relay owner/device
    // permission is 30s, signed membership trust is 60s, and the configured
    // maximum membership clock skew is 1s. Wait for max(30s, 60s) + 1s from
    // the point at which the old relay and checkpoint are both stopped.
    let fencing_quiescence = MEMBERSHIP_TRUST_LIFETIME
        .saturating_add(ALLOWED_MEMBERSHIP_CLOCK_SKEW)
        .max(OWNER_DEVICE_PERMISSION_LIFETIME);
    sleep(fencing_quiescence.saturating_sub(fenced_at.elapsed())).await;
    let quiescence_wait_ms = u64::try_from(fenced_at.elapsed().as_millis()).unwrap_or(u64::MAX);

    initialize_recovery(&relay_binary, &old_config_path).await?;
    let first_observation = observe_recovery(&relay_binary, &old_config_path).await?;
    let redis_run_id = first_observation["redis_run_id"]
        .as_str()
        .ok_or_else(|| HarnessError::Process("recovery observation omitted Redis run ID".into()))?
        .to_owned();
    let stale_catalog_digest = first_observation["catalog_digest"]
        .as_str()
        .ok_or_else(|| HarnessError::Process("recovery observation omitted catalog digest".into()))?
        .to_owned();
    if first_observation["deployment_incarnation"] != candidate_incarnation {
        return Err(HarnessError::Process(
            "recovery observation did not bind candidate incarnation".into(),
        ));
    }

    // An operator's fencing declaration is not proof. A writer that was never
    // fenced still holds this catalog handle on the *initial* incarnation, and
    // it mutates durable state after the digest above was observed. The
    // approval the operator signed against that earlier digest must therefore
    // be refused rather than activated against a catalog that has since moved.
    catalog
        .revoke_device(drift_device.tenant_id, drift_device.id, Utc::now())
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("unfenced writer drift revocation: {error}"))
        })?;
    let drifted_observation = observe_recovery(&relay_binary, &old_config_path).await?;
    let catalog_digest = drifted_observation["catalog_digest"]
        .as_str()
        .ok_or_else(|| {
            HarnessError::Process("drifted recovery observation omitted catalog digest".into())
        })?
        .to_owned();
    if catalog_digest == stale_catalog_digest {
        return Err(HarnessError::Process(
            "unfenced writer drift did not change the observed catalog digest".into(),
        ));
    }
    let digest_drift_observed = true;
    write_approval(
        &trusted_keys_path,
        &approval_path,
        &namespace,
        &deployment_id,
        &candidate_incarnation,
        &redis_run_id,
        &stale_catalog_digest,
    )?;
    let stale_digest_refusal = run_recover_cli(
        &relay_binary,
        &old_config_path,
        &approval_path,
        STALE_DIGEST_ACKNOWLEDGEMENT,
    )
    .await?;
    if stale_digest_refusal.status.success() {
        return Err(HarnessError::Process(
            "recover accepted an approval bound to an older catalog digest".into(),
        ));
    }
    let stale_digest_diagnostic = String::from_utf8_lossy(&stale_digest_refusal.stderr).to_string();
    if !stale_digest_diagnostic.contains(CATALOG_DIGEST_MISMATCH_DIAGNOSTIC) {
        return Err(HarnessError::Process(format!(
            "older-digest approval was refused without the catalog-digest cause: {stale_digest_diagnostic}"
        )));
    }
    let stale_digest_approval_refused = true;

    // The digest refusal happens before the approval version is persisted, so
    // the operator's corrected approval may reuse that version. Binding the
    // current digest is the only change.
    write_approval(
        &trusted_keys_path,
        &approval_path,
        &namespace,
        &deployment_id,
        &candidate_incarnation,
        &redis_run_id,
        &catalog_digest,
    )?;
    recover_relay(&relay_binary, &old_config_path, &approval_path).await?;

    // This handle was opened before recovery and was never fenced: it still
    // holds its connection and its configured initial incarnation. A durable
    // ownership claim through it must now be refused by Redis itself, not only
    // by a fresh connect-time check.
    let unfenced_claim = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: initial_incarnation.clone(),
            tenant_id: active_device.tenant_id,
            device_id: active_device.id,
            node_id: node_id.clone(),
            boot_id: format!("m7-recovery-unfenced-boot-{run_id}"),
            session_id: format!("m7-recovery-unfenced-session-{run_id}"),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(10),
        })
        .await;
    let unfenced_writer_claim_refused = match unfenced_claim {
        Err(CatalogError::Conflict(cause)) => {
            if cause != ACTIVE_INCARNATION_CONFLICT {
                return Err(HarnessError::Process(format!(
                    "unfenced writer claim was refused with an unexpected cause: {cause}"
                )));
            }
            true
        }
        Err(error) => {
            return Err(HarnessError::Process(format!(
                "unfenced writer claim was refused without the incarnation fence: {error}"
            )));
        }
        Ok(claim) => {
            return Err(HarnessError::Process(format!(
                "unfenced writer claimed ownership at epoch {} after approved recovery",
                claim.token.epoch
            )));
        }
    };

    drop(catalog);
    if RedisCatalog::connect_with_deployment_incarnation(
        &upstream_url,
        &namespace,
        &initial_incarnation,
    )
    .await
    .is_ok()
    {
        return Err(HarnessError::Redis(
            "old writer incarnation connected after approved recovery".into(),
        ));
    }
    let stale_writer_connect_refused = true;

    // A stale configured process must fail closed before the new membership is
    // published. This isolates the writer-fence proof from membership refresh.
    assert_old_writer_refused(
        &relay_binary,
        &old_config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        &pki.server_ca.certificate_der,
    )
    .await?;
    let stale_serve_process_failed_closed = true;

    let candidate_membership =
        signer.sign_membership(&deployment_id, &candidate_incarnation, &node, 2, Utc::now())?;
    let candidate_publisher = RedisMembershipPublisher::connect(&upstream_url, &namespace)
        .await
        .map_err(|error| HarnessError::Redis(format!("opening candidate publisher: {error}")))?;
    let candidate_record = candidate_membership.catalog_record();
    candidate_publisher
        .publish_signed_membership_for_node(&node_id, &candidate_record)
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("publishing candidate membership: {error}"))
        })?;
    drop(candidate_publisher);

    let candidate_checkpoint = CheckpointServer::bind(
        load_server_config_from_pem(
            checkpoint_chain.as_bytes(),
            checkpoint_leaf.private_key_pem.as_bytes(),
            None,
        )
        .map_err(|error| {
            HarnessError::Pki(format!("building candidate checkpoint TLS: {error}"))
        })?,
        signer.clone(),
        deployment_id.clone(),
        candidate_incarnation.clone(),
        BTreeMap::from([(node_id.clone(), 2)]),
    )
    .await?;
    let candidate_checkpoint_endpoint = format!(
        "https://localhost:{}/v1/checkpoint",
        candidate_checkpoint.address().port()
    );
    let candidate_config_fixture = ProcessConfigFixture {
        consumer_bind,
        device_bind,
        peer_bind,
        redis_url: &relay_redis_url,
        namespace: &namespace,
        deployment_id: &deployment_id,
        deployment_incarnation: &candidate_incarnation,
        oidc: &oidc,
        oidc_jwks_path: &oidc_jwks_path,
        server_chain_path: &server_chain_path,
        server_key_path: &server_key_path,
        server_ca_path: &server_ca_path,
        device_ca_path: &device_ca_path,
        peer_chain_path: &peer_chain_path,
        peer_key_path: &peer_key_path,
        peer_ca_path: &peer_ca_path,
        signer_trust_path: &signer_trust_path,
        state_path: &candidate_state_path,
        checkpoint_endpoint: &candidate_checkpoint_endpoint,
        node_id: &node_id,
    };
    let candidate_config_path = files.write(
        "relay-candidate.toml",
        with_recovery_config(
            &candidate_config_fixture.render(),
            &fence_path,
            &trusted_keys_path,
            &candidate_incarnation,
        )
        .as_bytes(),
    )?;
    initialize_state(&relay_binary, &candidate_config_path).await?;
    let candidate_process = start_relay(
        &relay_binary,
        &candidate_config_path,
        consumer_bind,
        device_bind,
        peer_bind,
        &pki.server_ca.certificate_der,
        "m7-recovery-process-candidate",
    )
    .await?;

    let candidate_catalog = RedisCatalog::connect_with_deployment_incarnation(
        &upstream_url,
        &namespace,
        &candidate_incarnation,
    )
    .await
    .map_err(|error| HarnessError::Redis(format!("opening candidate catalog: {error}")))?;
    if candidate_catalog
        .resolve_device(&revoked_spki, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("checking candidate revocation: {error}")))?
        .is_some()
    {
        return Err(HarnessError::Process(
            "candidate serve silently re-authorized the revoked device".into(),
        ));
    }
    let candidate_revocation_retained = true;

    let mut fresh_client = connect_fresh(&active_client_config).await?;
    let fresh_session = timeout(CONNECT_DEADLINE, fresh_client.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("fresh device DataReady deadline".into()))?
        .map_err(|error| HarnessError::Process(format!("fresh device DataReady: {error}")))?;
    if fresh_session.generation == 0 {
        return Err(HarnessError::Process(
            "fresh device session reported generation zero".into(),
        ));
    }
    let fresh_session_generation = fresh_session.generation;
    echo_http(EchoProbe {
        consumer_bind,
        server_ca_der: &pki.server_ca.certificate_der,
        token: &token,
        device_id: active_device.id,
        service_id: active_service,
        payload: PAYLOAD,
        canary: CANARY.as_bytes(),
        phase: "fresh-candidate",
    })
    .await?;
    let fresh_candidate_echo = true;
    fresh_client.stop().await.map_err(|error| {
        HarnessError::Process(format!("stopping fresh device session: {error}"))
    })?;

    let revoked_client_config = write_client_config(
        &files,
        "revoked-device",
        revoked_device.id,
        *topology
            .service_ids
            .get(&revoked_device.id)
            .ok_or_else(|| HarnessError::InvalidInput("revoked service missing".into()))?,
        "revoked-device",
        device_bind,
        &revoked_device.certificate.certificate_pem,
        &revoked_device.certificate.private_key_pem,
        &pki.device_ca.certificate_pem,
        &pki.server_ca.certificate_pem,
    )?;
    let revoked_result = timeout(CONNECT_DEADLINE, connect_fresh(&revoked_client_config))
        .await
        .map_err(|_| HarnessError::Timeout("revoked device connect timed out".into()))?;
    if revoked_result.is_ok() {
        return Err(HarnessError::Process(
            "revoked device established an authenticated session after recovery".into(),
        ));
    }
    let revoked_device_refused_after_recovery = true;

    stop_relay(
        candidate_process,
        consumer_bind,
        device_bind,
        peer_bind,
        "candidate relay",
    )
    .await?;
    candidate_checkpoint.shutdown().await?;
    candidate_catalog
        .cleanup_fixture_namespace()
        .await
        .map_err(|error| {
            HarnessError::Redis(format!("cleaning recovery process fixture: {error}"))
        })?;
    redis_proxy.shutdown().await?;
    Ok(ConfiguredRecoveryEvidence {
        quiescence_wait_ms,
        revocation_enforced_before_recovery,
        digest_drift_observed,
        stale_digest_approval_refused,
        unfenced_writer_claim_refused,
        stale_writer_connect_refused,
        stale_serve_process_failed_closed,
        candidate_revocation_retained,
        fresh_session_generation,
        fresh_candidate_echo,
        revoked_device_refused_after_recovery,
    })
}

fn distinct_tcp_addr(other: std::net::SocketAddr) -> std::net::SocketAddr {
    loop {
        let address = free_tcp_addr();
        if address != other {
            return address;
        }
    }
}

fn with_recovery_config(
    base: &str,
    fence_path: &Path,
    trusted_keys_path: &Path,
    candidate_incarnation: &str,
) -> String {
    format!(
        "{base}\n[recovery]\nfence_path = {}\ntrusted_keys_path = {}\ndeployment_incarnation = {}\n",
        toml_path(fence_path),
        toml_path(trusted_keys_path),
        toml_string(candidate_incarnation),
    )
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("quote recovery-process TOML string")
}

fn toml_path(path: &Path) -> String {
    toml_string(
        path.to_str()
            .expect("recovery-process fixture path should be UTF-8"),
    )
}

async fn initialize_state(binary: &Path, config: &Path) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-recovery-process-initialize",
        ProcessSpec::new(binary)
            .arg("initialize")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let status = wait_for_exit(&mut process, CLI_DEADLINE).await?;
    let diagnostic = process_diagnostic(&process);
    let _ = process.shutdown(Duration::from_millis(100)).await?;
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "recovery process initialize exited {status}; {diagnostic}"
        )));
    }
    Ok(())
}

async fn start_relay(
    binary: &Path,
    config: &Path,
    consumer_bind: std::net::SocketAddr,
    device_bind: std::net::SocketAddr,
    peer_bind: std::net::SocketAddr,
    server_ca_der: &[u8],
    name: &str,
) -> Result<ManagedProcess> {
    let mut process = ManagedProcess::spawn(
        name,
        ProcessSpec::new(binary)
            .arg("serve")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    if let Err(error) = wait_for_ready(&mut process, consumer_bind, server_ca_der).await {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "{name} recovery process readiness: {error}; {diagnostic}"
        )));
    }
    if process.id().is_none() {
        let diagnostic = process_diagnostic(&process);
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "{name} recovery process exited after readiness: {diagnostic}"
        )));
    }
    // Keep the peer address in the helper signature so every started process
    // is released through the same exact listener set.
    let _ = peer_bind;
    let _ = device_bind;
    Ok(process)
}

async fn stop_relay(
    mut process: ManagedProcess,
    consumer_bind: std::net::SocketAddr,
    device_bind: std::net::SocketAddr,
    peer_bind: std::net::SocketAddr,
    label: &str,
) -> Result<()> {
    let pid = process
        .id()
        .ok_or_else(|| HarnessError::Process(format!("{label} lost its process ID")))?;
    send_sigint(pid)?;
    let status = wait_for_exit(&mut process, SHUTDOWN_DEADLINE).await?;
    let diagnostic = process_diagnostic(&process);
    if !status.success() {
        let _ = process.shutdown(Duration::from_millis(100)).await;
        return Err(HarnessError::Process(format!(
            "{label} exited {status} during graceful shutdown; {diagnostic}"
        )));
    }
    let _ = process.shutdown(Duration::from_millis(100)).await?;
    wait_for_ports_released(consumer_bind, device_bind, peer_bind).await?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn write_client_config(
    files: &FixtureFiles,
    name: &str,
    device_id: Uuid,
    service_id: Uuid,
    canary: &str,
    device_bind: std::net::SocketAddr,
    certificate_pem: &str,
    private_key_pem: &str,
    device_ca_pem: &str,
    server_ca_pem: &str,
) -> Result<ConnectConfig> {
    let certificate_path = files.write(
        &format!("{name}-device-cert.pem"),
        format!("{certificate_pem}{device_ca_pem}").as_bytes(),
    )?;
    let key_path = files.write(
        &format!("{name}-device-key.pem"),
        private_key_pem.as_bytes(),
    )?;
    let server_ca_path = files.write(&format!("{name}-server-ca.pem"), server_ca_pem.as_bytes())?;
    let config = ConnectConfig {
        device_id: device_id.to_string(),
        relay_url: format!("wss://localhost:{}/v1/tunnel/control", device_bind.port()),
        credentials: CredentialConfig {
            client_certificate: certificate_path,
            client_key: key_path,
            server_ca: server_ca_path,
        },
        exports: BTreeMap::from([(
            service_id.to_string(),
            LocalExport {
                kind: LocalExportKind::Echo,
                device_canary: Some(canary.to_owned()),
                mcp: None,
                acp: None,
                fs: None,
            },
        )]),
        limits: LimitsConfig::default(),
        rotation: RotationConfig::default(),
    };
    config
        .validate()
        .map_err(|error| HarnessError::InvalidInput(format!("client config: {error}")))?;
    Ok(config)
}

async fn connect_fresh(config: &ConnectConfig) -> Result<tunnel_client::ConnectionHandle> {
    let handle = timeout(
        CONNECT_DEADLINE,
        connect(ConnectOptions::new(config.clone())),
    )
    .await
    .map_err(|_| HarnessError::Timeout("device connect deadline".into()))?
    .map_err(|error| HarnessError::Process(format!("device connect: {error}")))?;
    Ok(handle)
}

const ECHO_CONNECTION_CLEANUP_DEADLINE: Duration = Duration::from_secs(2);

struct EchoConnectionGuard {
    task: Option<tokio::task::JoinHandle<()>>,
}

impl EchoConnectionGuard {
    fn new(task: tokio::task::JoinHandle<()>) -> Self {
        Self { task: Some(task) }
    }

    async fn shutdown(mut self, phase: &str) -> Result<()> {
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        task.abort();
        match timeout(ECHO_CONNECTION_CLEANUP_DEADLINE, &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) if error.is_cancelled() => Ok(()),
            Ok(Err(error)) => Err(HarnessError::Http(format!(
                "{phase} echo connection task join failed: {error}"
            ))),
            Err(_) => Err(HarnessError::Timeout(format!(
                "{phase} echo connection cleanup deadline"
            ))),
        }
    }
}

impl Drop for EchoConnectionGuard {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

struct EchoProbe<'a> {
    consumer_bind: std::net::SocketAddr,
    server_ca_der: &'a [u8],
    token: &'a str,
    device_id: Uuid,
    service_id: Uuid,
    payload: &'a [u8],
    canary: &'a [u8],
    phase: &'a str,
}

async fn echo_http(probe: EchoProbe<'_>) -> Result<()> {
    let EchoProbe {
        consumer_bind,
        server_ca_der,
        token,
        device_id,
        service_id,
        payload,
        canary,
        phase,
    } = probe;
    let exchange_deadline = tokio::time::Instant::now() + EXCHANGE_DEADLINE;
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(server_ca_der.to_vec()))
        .map_err(|error| HarnessError::Http(format!("{phase} echo root: {error}")))?;
    let client_config =
        ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|error| HarnessError::Http(format!("{phase} echo TLS: {error}")))?
            .with_root_certificates(roots)
            .with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(client_config));
    let stream = timeout_at(
        exchange_deadline,
        tokio::net::TcpStream::connect(consumer_bind),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} echo TCP connect")))?
    .map_err(|error| HarnessError::Http(format!("{phase} echo TCP connect: {error}")))?;
    let server_name = ServerName::try_from("localhost".to_owned())
        .map_err(|error| HarnessError::Http(format!("{phase} echo server name: {error}")))?;
    let tls = timeout_at(exchange_deadline, connector.connect(server_name, stream))
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo TLS handshake")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo TLS handshake: {error}")))?;
    let (mut sender, connection) = timeout_at(
        exchange_deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls)),
    )
    .await
    .map_err(|_| HarnessError::Timeout(format!("{phase} echo HTTP handshake")))?
    .map_err(|error| HarnessError::Http(format!("{phase} echo HTTP handshake: {error}")))?;
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let connection_guard = EchoConnectionGuard::new(connection_task);
    let result: Result<()> = async {
        let path = format!("/v1/devices/{device_id}/services/{service_id}/echo");
        let request = Request::builder()
            .method("POST")
            .uri(format!("https://localhost{path}"))
            .header("host", "localhost")
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", "application/octet-stream")
            .body(Full::new(Bytes::copy_from_slice(payload)))
            .map_err(|error| HarnessError::Http(format!("{phase} echo request: {error}")))?;
        let response = timeout_at(exchange_deadline, sender.send_request(request))
            .await
            .map_err(|_| HarnessError::Timeout(format!("{phase} echo request")))?
            .map_err(|error| HarnessError::Http(format!("{phase} echo response: {error}")))?;
        let status = response.status();
        let body = timeout_at(
            exchange_deadline,
            Limited::new(response.into_body(), 256 * 1024).collect(),
        )
        .await
        .map_err(|_| HarnessError::Timeout(format!("{phase} echo body")))?
        .map_err(|error| HarnessError::Http(format!("{phase} echo body: {error}")))?
        .to_bytes();
        if status != 200 {
            return Err(HarnessError::Http(format!(
                "{phase} echo returned HTTP {status}: body_len={} body_sha256={}",
                body.len(),
                digest_hex(&body),
            )));
        }
        // The public HTTP adapter strips the internal tunnel record framing;
        // the configured non-streaming echo export therefore returns the
        // device canary followed by the request payload.
        let mut expected = Vec::with_capacity(canary.len().saturating_add(payload.len()));
        expected.extend_from_slice(canary);
        expected.extend_from_slice(payload);
        if body != expected.as_slice() {
            let actual_payload_tail_length = body.len().saturating_sub(canary.len());
            return Err(HarnessError::Http(format!(
                "{phase} echo canary response mismatch: actual_len={} expected_len={} canary_prefix={} expected_payload_len={} actual_payload_tail_len={} actual_sha256={} expected_sha256={}",
                body.len(),
                expected.len(),
                body.starts_with(canary),
                payload.len(),
                actual_payload_tail_length,
                digest_hex(&body),
                digest_hex(&expected),
            )));
        }
        Ok(())
    }
    .await;
    let cleanup = connection_guard.shutdown(phase).await;
    match (result, cleanup) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(primary), Ok(())) => Err(primary),
        (Ok(()), Err(cleanup)) => Err(cleanup),
        (Err(primary), Err(cleanup)) => Err(HarnessError::Http(format!(
            "{phase} echo primary failure: {primary}; connection cleanup failure: {cleanup}"
        ))),
    }
}

fn digest_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex_encode(digest.as_ref())
}

async fn initialize_recovery(binary: &Path, config: &Path) -> Result<()> {
    let output = run_relay_cli(
        binary,
        &[
            "recovery-initialize".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
        ],
    )
    .await?;
    if !output.status.success() {
        return Err(HarnessError::Process(format!(
            "recovery-initialize failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

async fn observe_recovery(binary: &Path, config: &Path) -> Result<serde_json::Value> {
    let output = run_relay_cli(
        binary,
        &[
            "recovery-observe".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
        ],
    )
    .await?;
    if !output.status.success() {
        return Err(HarnessError::Process(format!(
            "recovery-observe failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    serde_json::from_slice(&output.stdout)
        .map_err(|error| HarnessError::Process(format!("recovery-observe JSON: {error}")))
}

/// Run one `recover` invocation and return its raw output.
///
/// Both the refused older-digest attempt and the accepted recovery go through
/// this single path, so the refusal cannot come from a differently shaped
/// command line.
async fn run_recover_cli(
    binary: &Path,
    config: &Path,
    approval: &Path,
    acknowledgement_id: &str,
) -> Result<Output> {
    run_relay_cli(
        binary,
        &[
            "recover".to_owned(),
            "--config".to_owned(),
            config.display().to_string(),
            "--approval".to_owned(),
            approval.display().to_string(),
            "--expected-nonce".to_owned(),
            APPROVAL_NONCE.to_owned(),
            "--acknowledgement-id".to_owned(),
            acknowledgement_id.to_owned(),
            "--old-primary-fenced".to_owned(),
            "--old-relays-fenced".to_owned(),
        ],
    )
    .await
}

async fn recover_relay(binary: &Path, config: &Path, approval: &Path) -> Result<()> {
    let output = run_recover_cli(binary, config, approval, RECOVERY_ACKNOWLEDGEMENT).await?;
    if !output.status.success() {
        return Err(HarnessError::Process(format!(
            "recover failed: {}",
            String::from_utf8_lossy(&output.stderr)
        )));
    }
    Ok(())
}

async fn run_relay_cli(binary: &Path, args: &[String]) -> Result<Output> {
    let mut child = std::process::Command::new(binary)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|error| HarnessError::Process(format!("spawn recovery CLI: {error}")))?;
    let deadline = Instant::now() + CLI_DEADLINE;
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => sleep(Duration::from_millis(20)).await,
            Ok(None) => return fail_cli_child(child, "recovery CLI deadline"),
            Err(error) => {
                return fail_cli_child(child, &format!("poll recovery CLI: {error}"));
            }
        }
    }
    child
        .wait_with_output()
        .map_err(|error| HarnessError::Process(format!("join recovery CLI: {error}")))
}

fn fail_cli_child(mut child: Child, reason: &str) -> Result<Output> {
    let kill_result = child.kill();
    let wait_result = child.wait_with_output();
    Err(HarnessError::Process(format!(
        "{reason}; kill={kill_result:?}; wait={wait_result:?}"
    )))
}

fn write_approval(
    trusted_keys_path: &Path,
    approval_path: &Path,
    namespace: &str,
    deployment_id: &str,
    candidate_incarnation: &str,
    redis_run_id: &str,
    catalog_digest: &str,
) -> Result<()> {
    let (issuer, _) = RecoveryApprovalIssuer::generate(OPERATOR_KEY_ID)
        .map_err(|error| HarnessError::Pki(format!("recovery operator key: {error}")))?;
    let public_key = issuer
        .public_key()
        .map_err(|error| HarnessError::Pki(format!("recovery operator public key: {error}")))?;
    let trusted = serde_json::json!({
        "schema_version": 1,
        "keys": [{
            "key_id": OPERATOR_KEY_ID,
            "public_key": public_key.iter().map(|byte| format!("{byte:02x}")).collect::<String>(),
        }]
    });
    write_private(trusted_keys_path, serde_json::to_vec(&trusted)?.as_slice())?;
    let now = Utc::now();
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: deployment_id.to_owned(),
        redis_namespace: namespace.to_owned(),
        redis_run_id: redis_run_id.to_owned(),
        deployment_incarnation: candidate_incarnation.to_owned(),
        approval_version: 1,
        nonce: APPROVAL_NONCE.to_owned(),
        catalog_digest: catalog_digest.to_owned(),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let bytes = issuer
        .sign_approval_bytes(approval)
        .map_err(|error| HarnessError::Pki(format!("sign recovery approval: {error}")))?;
    write_private(approval_path, &bytes)
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    std::fs::write(path, bytes).map_err(HarnessError::Io)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .map_err(HarnessError::Io)?;
    }
    Ok(())
}

async fn assert_old_writer_refused(
    binary: &Path,
    config: &Path,
    consumer_bind: std::net::SocketAddr,
    device_bind: std::net::SocketAddr,
    peer_bind: std::net::SocketAddr,
    server_ca_der: &[u8],
) -> Result<()> {
    let mut process = ManagedProcess::spawn(
        "m7-recovery-process-stale-relay",
        ProcessSpec::new(binary)
            .arg("serve")
            .arg("--config")
            .arg(config.display().to_string()),
    )
    .await?;
    let deadline = Instant::now() + CLI_DEADLINE;
    loop {
        if let Some(status) = process.try_wait()? {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(Duration::from_millis(100)).await?;
            if status.success() {
                return Err(HarnessError::Process(format!(
                    "stale relay exited successfully after recovery; {diagnostic}"
                )));
            }
            wait_for_ports_released(consumer_bind, device_bind, peer_bind).await?;
            return Ok(());
        }
        if health_request(consumer_bind, server_ca_der, "/readyz")
            .await
            .is_ok()
        {
            let pid = process.id();
            if let Some(pid) = pid {
                let _ = send_sigint(pid);
            }
            let _ = process.shutdown(Duration::from_millis(100)).await;
            let _ = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
            return Err(HarnessError::Process(
                "stale relay exposed readiness after recovery".into(),
            ));
        }
        if Instant::now() >= deadline {
            let diagnostic = process_diagnostic(&process);
            let _ = process.shutdown(Duration::from_millis(100)).await?;
            let _ = wait_for_ports_released(consumer_bind, device_bind, peer_bind).await;
            return Err(HarnessError::Timeout(format!(
                "stale relay did not fail closed: {diagnostic}"
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

/// C17 mutation coverage for the configured recovery evidence contract.
///
/// The gate itself needs a Redis primary and two relay processes, so these
/// cases are the only cheap guard against the validator drifting into
/// accepting an incomplete run.
mod c17_validator_tests {
    use super::{
        ALLOWED_MEMBERSHIP_CLOCK_SKEW, ConfiguredRecoveryEvidence, MEMBERSHIP_TRUST_LIFETIME,
        OWNER_DEVICE_PERMISSION_LIFETIME, validate_configured_recovery_evidence,
    };

    fn valid_evidence() -> ConfiguredRecoveryEvidence {
        let quiescence = MEMBERSHIP_TRUST_LIFETIME
            .saturating_add(ALLOWED_MEMBERSHIP_CLOCK_SKEW)
            .max(OWNER_DEVICE_PERMISSION_LIFETIME);
        ConfiguredRecoveryEvidence {
            quiescence_wait_ms: u64::try_from(quiescence.as_millis()).unwrap_or(u64::MAX),
            revocation_enforced_before_recovery: true,
            digest_drift_observed: true,
            stale_digest_approval_refused: true,
            unfenced_writer_claim_refused: true,
            stale_writer_connect_refused: true,
            stale_serve_process_failed_closed: true,
            candidate_revocation_retained: true,
            fresh_session_generation: 1,
            fresh_candidate_echo: true,
            revoked_device_refused_after_recovery: true,
        }
    }

    fn assert_rejected(evidence: &ConfiguredRecoveryEvidence, expected: &str) {
        let diagnostic = validate_configured_recovery_evidence(evidence)
            .err()
            .map(|error| error.to_string())
            .unwrap_or_else(|| {
                panic!("incomplete configured recovery evidence unexpectedly passed: {expected}")
            });
        assert!(
            diagnostic.contains(expected),
            "{expected} missing from bounded diagnostic: {diagnostic}"
        );
    }

    #[test]
    fn configured_recovery_validator_accepts_complete_evidence() {
        validate_configured_recovery_evidence(&valid_evidence())
            .expect("complete configured recovery evidence is valid");
    }

    #[test]
    fn every_configured_recovery_flag_and_bound_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut ConfiguredRecoveryEvidence));
        let flags: [Disable; 9] = [
            ("revocation_enforced_before_recovery", |e| {
                e.revocation_enforced_before_recovery = false
            }),
            ("digest_drift_observed", |e| e.digest_drift_observed = false),
            ("stale_digest_approval_refused", |e| {
                e.stale_digest_approval_refused = false
            }),
            ("unfenced_writer_claim_refused", |e| {
                e.unfenced_writer_claim_refused = false
            }),
            ("stale_writer_connect_refused", |e| {
                e.stale_writer_connect_refused = false
            }),
            ("stale_serve_process_failed_closed", |e| {
                e.stale_serve_process_failed_closed = false
            }),
            ("candidate_revocation_retained", |e| {
                e.candidate_revocation_retained = false
            }),
            ("fresh_candidate_echo", |e| e.fresh_candidate_echo = false),
            ("revoked_device_refused_after_recovery", |e| {
                e.revoked_device_refused_after_recovery = false
            }),
        ];
        for (name, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(&evidence, name);
        }

        let mut zero_generation = valid_evidence();
        zero_generation.fresh_session_generation = 0;
        assert_rejected(&zero_generation, "generation zero");

        let mut short_wait = valid_evidence();
        short_wait.quiescence_wait_ms -= 1;
        assert_rejected(&short_wait, "lifetime-plus-skew boundary");
    }
}
