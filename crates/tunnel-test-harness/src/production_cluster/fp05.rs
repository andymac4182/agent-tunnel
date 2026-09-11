//! Narrow FP-05 admitted non-idempotent side-effect gate.
//!
//! This fixture is intentionally separate from the EC-054 peer-loss fixture.
//! It enters through the real public HTTPS POST route on relay-C, reaches the
//! synthetic device attached to relay-A, commits one append to a task-local
//! backend, holds the application response, and then stops relay-A.  The
//! surviving tenant-B device is a separate authority scope and supplies the
//! post-fault canary.  The synthetic append is an evidence fixture only; it
//! does not claim a deployed privileged adapter or a released client.

use super::side_effect::{DeviceConfig, DeviceFixture, EffectState};
use super::{EXCHANGE_TIMEOUT, ProductionCluster};
use crate::{HarnessError, OidcTokenOptions, Result, RunningHarness};
use bytes::Bytes;
use chrono::Utc;
use futures_util::FutureExt;
use http_body_util::{BodyExt, Full, Limited};
use hyper::Request;
use hyper_util::rt::TokioIo;
use rustls::pki_types::{CertificateDer, ServerName};
use std::{net::SocketAddr, panic::AssertUnwindSafe, sync::Arc, time::Duration};
use tokio::{
    net::TcpStream,
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout, timeout_at},
};
use tokio_rustls::TlsConnector;
use tunnel_catalog::OwnerToken;
use uuid::Uuid;

const OWNER_READY_TIMEOUT: Duration = Duration::from_secs(15);
const POST_OBSERVATION_TIMEOUT: Duration =
    Duration::from_millis(tunnel_cluster::envelope::MAX_ADMISSION_REMAINING_MS as u64);
const POST_CLEANUP_TIMEOUT: Duration = Duration::from_secs(5);
const POST_FAILURE_OBSERVATION: Duration = Duration::from_millis(500);
const MAX_POST_RESPONSE_BYTES: usize = 64 * 1024;
const APPEND_BODY: &[u8] = b"m7-fp05-append-once";
const SIBLING_BODY: &[u8] = b"m7-fp05-tenant-b-canary";

/// Payload-free evidence for the real public POST/owner-loss slice of FP-05.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Fp05Evidence {
    pub relay_count: usize,
    pub owner_relay: String,
    pub ingress_relay: String,
    pub owner_shutdown: bool,
    pub owner_loss_close_observed: bool,
    pub owner_not_replaced_after_shutdown: bool,
    pub response_held_before_owner_shutdown: bool,
    pub control_admitted: bool,
    pub owner_fenced: bool,
    pub data_admitted: bool,
    pub operation_opened: bool,
    pub authorization_confirmed: bool,
    pub post_terminal: String,
    pub post_status: Option<u16>,
    pub post_elapsed_ms: u64,
    pub post_observation_deadline_ms: u64,
    pub post_connection_joined: bool,
    pub append_entries: usize,
    pub raw_data_frames: usize,
    pub raw_fin_frames: usize,
    pub raw_frame_observations: usize,
    pub backend_effect_invocations: u64,
    pub duplicate_request_observations: u64,
    pub post_failure_effect_invocations: u64,
    pub sibling_canary_survived: bool,
    pub sibling_response_held_before_owner_shutdown: bool,
    pub sibling_owner_retained_after_response: bool,
    pub sibling_owner_relay: String,
    pub sibling_terminal: String,
    pub sibling_status: Option<u16>,
    pub sibling_response_matches_request: bool,
    pub sibling_connection_joined: bool,
    pub sibling_append_entries: usize,
    pub sibling_effect_invocations: u64,
}

/// Validate the exact FP-05 scope.  HTTP success, an observer deadline, an
/// unresolved append count, or a missing unrelated-tenant canary keeps this
/// row open rather than being treated as a narrow failure proof.
pub fn validate_fp05_evidence(evidence: &Fp05Evidence) -> Result<()> {
    if evidence.relay_count != 3 {
        return Err(HarnessError::Process(format!(
            "FP-05 requires three production relays, observed {}",
            evidence.relay_count
        )));
    }
    if evidence.owner_relay != "relay-a" || evidence.ingress_relay != "relay-c" {
        return Err(HarnessError::Process(format!(
            "FP-05 route was {} -> {} rather than relay-c -> relay-a",
            evidence.ingress_relay, evidence.owner_relay
        )));
    }
    if !evidence.owner_shutdown {
        return Err(HarnessError::Process(
            "FP-05 did not stop the selected owner relay after the admitted effect".into(),
        ));
    }
    for (name, value) in [
        (
            "owner_loss_close_observed",
            evidence.owner_loss_close_observed,
        ),
        (
            "owner_not_replaced_after_shutdown",
            evidence.owner_not_replaced_after_shutdown,
        ),
    ] {
        if !value {
            return Err(HarnessError::Process(format!(
                "FP-05 required evidence {name} was false"
            )));
        }
    }
    for (name, value) in [
        ("control_admitted", evidence.control_admitted),
        ("owner_fenced", evidence.owner_fenced),
        ("data_admitted", evidence.data_admitted),
        ("operation_opened", evidence.operation_opened),
        ("authorization_confirmed", evidence.authorization_confirmed),
        (
            "response_held_before_owner_shutdown",
            evidence.response_held_before_owner_shutdown,
        ),
        ("sibling_canary_survived", evidence.sibling_canary_survived),
        ("post_connection_joined", evidence.post_connection_joined),
        (
            "sibling_connection_joined",
            evidence.sibling_connection_joined,
        ),
        (
            "sibling_response_held_before_owner_shutdown",
            evidence.sibling_response_held_before_owner_shutdown,
        ),
        (
            "sibling_owner_retained_after_response",
            evidence.sibling_owner_retained_after_response,
        ),
    ] {
        if !value {
            return Err(HarnessError::Process(format!(
                "FP-05 required evidence {name} was false"
            )));
        }
    }
    if evidence.post_observation_deadline_ms != duration_millis(POST_OBSERVATION_TIMEOUT) {
        return Err(HarnessError::Process(format!(
            "FP-05 POST observation bound was {}ms, expected {}ms",
            evidence.post_observation_deadline_ms,
            duration_millis(POST_OBSERVATION_TIMEOUT)
        )));
    }
    if evidence.post_elapsed_ms > evidence.post_observation_deadline_ms {
        return Err(HarnessError::Timeout(format!(
            "FP-05 POST terminal exceeded its bound: {}ms > {}ms",
            evidence.post_elapsed_ms, evidence.post_observation_deadline_ms
        )));
    }
    match evidence.post_terminal.as_str() {
        "http-unknown" if evidence.post_status == Some(503) => {}
        "transport-error" if evidence.post_status.is_none() => {}
        "observer-deadline" => {
            return Err(HarnessError::Timeout(
                "FP-05 POST outcome was only an observer deadline, not a terminal result".into(),
            ));
        }
        terminal => {
            return Err(HarnessError::Process(format!(
                "FP-05 admitted POST terminal was {terminal} with status {:?}; expected HTTP 503 explicit unknown or transport error",
                evidence.post_status
            )));
        }
    }
    if evidence.append_entries != 1
        || evidence.raw_data_frames != 1
        || evidence.raw_fin_frames != 1
        || evidence.raw_frame_observations != 2
        || evidence.backend_effect_invocations != 1
        || evidence.duplicate_request_observations != 0
        || evidence.post_failure_effect_invocations != 0
    {
        return Err(HarnessError::Process(format!(
            "FP-05 append/effect evidence was append={}, DATA={}, FIN={}, raw={}, effects={}, duplicates={}, post_failure_effects={}; expected 1,1,1,2,1,0,0",
            evidence.append_entries,
            evidence.raw_data_frames,
            evidence.raw_fin_frames,
            evidence.raw_frame_observations,
            evidence.backend_effect_invocations,
            evidence.duplicate_request_observations,
            evidence.post_failure_effect_invocations
        )));
    }
    if evidence.sibling_owner_relay != "relay-b"
        || evidence.sibling_terminal != "success"
        || evidence.sibling_status != Some(200)
        || !evidence.sibling_response_matches_request
        || evidence.sibling_append_entries != 1
        || evidence.sibling_effect_invocations != 1
    {
        return Err(HarnessError::Process(format!(
            "FP-05 sibling canary was owner={}, terminal={}, status={:?}, response_match={}, append={}, effects={}; expected relay-b/HTTP-200/matching response/one effect",
            evidence.sibling_owner_relay,
            evidence.sibling_terminal,
            evidence.sibling_status,
            evidence.sibling_response_matches_request,
            evidence.sibling_append_entries,
            evidence.sibling_effect_invocations
        )));
    }
    Ok(())
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{Fp05Evidence, POST_OBSERVATION_TIMEOUT, duration_millis, validate_fp05_evidence};
    use crate::acceptance_test_support::assert_rejected;

    fn valid_evidence() -> Fp05Evidence {
        Fp05Evidence {
            relay_count: 3,
            owner_relay: "relay-a".into(),
            ingress_relay: "relay-c".into(),
            owner_shutdown: true,
            owner_loss_close_observed: true,
            owner_not_replaced_after_shutdown: true,
            response_held_before_owner_shutdown: true,
            control_admitted: true,
            owner_fenced: true,
            data_admitted: true,
            operation_opened: true,
            authorization_confirmed: true,
            post_terminal: "http-unknown".into(),
            post_status: Some(503),
            post_elapsed_ms: 1,
            post_observation_deadline_ms: duration_millis(POST_OBSERVATION_TIMEOUT),
            post_connection_joined: true,
            append_entries: 1,
            raw_data_frames: 1,
            raw_fin_frames: 1,
            raw_frame_observations: 2,
            backend_effect_invocations: 1,
            duplicate_request_observations: 0,
            post_failure_effect_invocations: 0,
            sibling_canary_survived: true,
            sibling_response_held_before_owner_shutdown: true,
            sibling_owner_retained_after_response: true,
            sibling_owner_relay: "relay-b".into(),
            sibling_terminal: "success".into(),
            sibling_status: Some(200),
            sibling_response_matches_request: true,
            sibling_connection_joined: true,
            sibling_append_entries: 1,
            sibling_effect_invocations: 1,
        }
    }

    #[test]
    fn every_fp05_flag_and_count_reaches_the_shared_exit_path() {
        type Disable = (&'static str, fn(&mut Fp05Evidence));
        let flags: [Disable; 14] = [
            ("owner_shutdown", |e| e.owner_shutdown = false),
            ("owner_loss_close_observed", |e| {
                e.owner_loss_close_observed = false
            }),
            ("owner_not_replaced_after_shutdown", |e| {
                e.owner_not_replaced_after_shutdown = false
            }),
            ("response_held_before_owner_shutdown", |e| {
                e.response_held_before_owner_shutdown = false
            }),
            ("control_admitted", |e| e.control_admitted = false),
            ("owner_fenced", |e| e.owner_fenced = false),
            ("data_admitted", |e| e.data_admitted = false),
            ("operation_opened", |e| e.operation_opened = false),
            ("authorization_confirmed", |e| {
                e.authorization_confirmed = false
            }),
            ("sibling_canary_survived", |e| {
                e.sibling_canary_survived = false
            }),
            ("sibling_owner_retained_after_response", |e| {
                e.sibling_owner_retained_after_response = false
            }),
            ("post_connection_joined", |e| {
                e.post_connection_joined = false
            }),
            ("sibling_connection_joined", |e| {
                e.sibling_connection_joined = false
            }),
            ("sibling_response_held_before_owner_shutdown", |e| {
                e.sibling_response_held_before_owner_shutdown = false
            }),
        ];
        for (_, disable) in flags {
            let mut evidence = valid_evidence();
            disable(&mut evidence);
            assert_rejected(validate_fp05_evidence(&evidence), "FP-05");
        }

        type Mutate = (&'static str, fn(&mut Fp05Evidence));
        let counts: [Mutate; 18] = [
            ("relay_count", |e| e.relay_count = 2),
            ("post_observation_deadline_ms", |e| {
                e.post_observation_deadline_ms = 0
            }),
            ("post_elapsed_ms", |e| {
                e.post_elapsed_ms = duration_millis(POST_OBSERVATION_TIMEOUT) + 1
            }),
            ("append_entries", |e| e.append_entries = 0),
            ("raw_data_frames", |e| e.raw_data_frames = 0),
            ("raw_fin_frames", |e| e.raw_fin_frames = 0),
            ("raw_frame_observations", |e| e.raw_frame_observations = 0),
            ("backend_effect_invocations", |e| {
                e.backend_effect_invocations = 0
            }),
            ("duplicate_request_observations", |e| {
                e.duplicate_request_observations = 1
            }),
            ("post_failure_effect_invocations", |e| {
                e.post_failure_effect_invocations = 1
            }),
            ("post_terminal", |e| {
                e.post_terminal = "observer-deadline".into()
            }),
            ("post_status", |e| e.post_status = Some(200)),
            ("sibling_owner_relay", |e| {
                e.sibling_owner_relay = "relay-c".into()
            }),
            ("sibling_terminal", |e| e.sibling_terminal = "close".into()),
            ("sibling_status", |e| e.sibling_status = Some(503)),
            ("sibling_response_matches_request", |e| {
                e.sibling_response_matches_request = false
            }),
            ("sibling_append_entries", |e| e.sibling_append_entries = 0),
            ("sibling_effect_invocations", |e| {
                e.sibling_effect_invocations = 0
            }),
        ];
        for (_, mutate) in counts {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            assert_rejected(validate_fp05_evidence(&evidence), "FP-05");
        }
    }

    #[test]
    fn fp05_validator_accepts_complete_evidence_for_both_typed_terminals() {
        validate_fp05_evidence(&valid_evidence()).expect("HTTP 503 explicit unknown is valid");
        let mut transport_error = valid_evidence();
        transport_error.post_terminal = "transport-error".into();
        transport_error.post_status = None;
        validate_fp05_evidence(&transport_error)
            .expect("transport error without a status is valid");
    }

    #[test]
    fn every_fp05_route_and_terminal_shape_names_its_rejection() {
        use crate::acceptance_test_support::assert_failed;

        const ROUTE: &str = "rather than relay-c -> relay-a";
        const TERMINAL: &str = "expected HTTP 503 explicit unknown or transport error";
        type Case = (&'static str, &'static str, fn(&mut Fp05Evidence));
        let cases: &[Case] = &[
            ("owner_relay", ROUTE, |e| e.owner_relay = "relay-b".into()),
            ("ingress_relay", ROUTE, |e| {
                e.ingress_relay = "relay-a".into()
            }),
            ("transport_error_with_status", TERMINAL, |e| {
                e.post_terminal = "transport-error".into();
                e.post_status = Some(503);
            }),
            ("http_unknown_without_status", TERMINAL, |e| {
                e.post_status = None
            }),
            ("success_terminal", TERMINAL, |e| {
                e.post_terminal = "success".into()
            }),
            ("observer_deadline", "only an observer deadline", |e| {
                e.post_terminal = "observer-deadline".into()
            }),
            ("post_elapsed_over_bound", "exceeded its bound", |e| {
                e.post_elapsed_ms = duration_millis(POST_OBSERVATION_TIMEOUT) + 1
            }),
            (
                "post_observation_deadline_mismatch",
                "POST observation bound was",
                |e| e.post_observation_deadline_ms = 1,
            ),
        ];
        for &(name, fragment, mutate) in cases {
            let mut evidence = valid_evidence();
            mutate(&mut evidence);
            let diagnostic = assert_failed(validate_fp05_evidence(&evidence));
            assert!(
                diagnostic.contains(fragment),
                "{name}: expected {fragment:?} in diagnostic {diagnostic}"
            );
        }
    }
}

/// Run the bounded admitted non-idempotent owner-loss scenario.
pub(crate) async fn verify(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<Fp05Evidence> {
    let evidence = match AssertUnwindSafe(verify_inner(cluster, harness))
        .catch_unwind()
        .await
    {
        Ok(result) => result?,
        Err(_) => {
            return Err(HarnessError::Process("FP-05 scenario panicked".into()));
        }
    };
    validate_fp05_evidence(&evidence)?;
    Ok(evidence)
}

async fn verify_inner(
    cluster: &mut ProductionCluster,
    harness: &RunningHarness,
) -> Result<Fp05Evidence> {
    let relay_count = cluster.relays.len();
    let owner_relay = "relay-a";
    let ingress_relay = "relay-c";
    let ingress_addr = cluster.relay(ingress_relay)?.consumer_addr()?;
    let device_a = harness
        .topology
        .devices_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no FP-05 device".into()))?;
    let service_a = *harness
        .topology
        .service_ids
        .get(&device_a.id)
        .ok_or_else(|| HarnessError::InvalidInput("tenant A device has no service".into()))?;
    let token_a = harness.oidc.issue_with(
        &harness.topology.consumers_a[0].name,
        OidcTokenOptions {
            expires_in: Duration::from_secs(90),
            ..OidcTokenOptions::default()
        },
    )?;
    // The public unary route sends the raw HTTP body to the ingress relay;
    // forward_unary frames it once before the owner-side echo_stream dispatch.
    // The device therefore observes the length-prefixed record, while the
    // public HTTP response is unframed again by the relay.
    let state_a = Arc::new(EffectState::new_append_framed(APPEND_BODY.to_vec())?);
    let fixture_a = DeviceFixture::start(
        DeviceConfig::new(
            relay_device_addr(cluster, owner_relay)?,
            device_a.id,
            service_a,
            "echo_stream",
            device_a.certificate.certificate_pem.clone(),
            device_a.certificate.private_key_pem.clone(),
            harness.pki.server_ca.certificate_pem.clone(),
        )
        .allow_expected_owner_loss(),
        state_a.clone(),
    )
    .await?;
    let mut fixture_a = Some(fixture_a);
    let mut post_a = None;
    let mut fixture_b = None;
    let mut post_b = None;
    let scenario = match AssertUnwindSafe(async {
        // Admit and hold the unrelated tenant's response before the selected
        // owner fault.  This makes the canary an already-established sibling,
        // rather than a new admission attempted after relay-A is gone.
        let device_b = harness
            .topology
            .devices_b
            .first()
            .ok_or_else(|| HarnessError::InvalidInput("tenant B has no FP-05 sibling".into()))?;
        let service_b = *harness
            .topology
            .service_ids
            .get(&device_b.id)
            .ok_or_else(|| HarnessError::InvalidInput("tenant B sibling has no service".into()))?;
        let token_b = harness.oidc.issue_with(
            &harness.topology.consumers_b[0].name,
            OidcTokenOptions {
                expires_in: Duration::from_secs(90),
                ..OidcTokenOptions::default()
            },
        )?;
        let state_b = Arc::new(EffectState::new_append_framed(SIBLING_BODY.to_vec())?);
        fixture_b = Some(
            DeviceFixture::start(
                DeviceConfig::new(
                    relay_device_addr(cluster, "relay-b")?,
                    device_b.id,
                    service_b,
                    "echo_stream",
                    device_b.certificate.certificate_pem.clone(),
                    device_b.certificate.private_key_pem.clone(),
                    harness.pki.server_ca.certificate_pem.clone(),
                ),
                state_b.clone(),
            )
            .await?,
        );
        let owner_b = wait_for_owner(cluster, device_b.tenant_id, device_b.id, "relay-b").await?;
        post_b = Some(spawn_public_echo_post(PostRequest {
            consumer_addr: ingress_addr,
            server_ca_der: harness.pki.server_ca.certificate_der.clone(),
            token: token_b,
            device_id: device_b.id,
            service_id: service_b,
            body: SIBLING_BODY.to_vec(),
        }));
        wait_for_effect(&state_b).await?;
        let sibling_response_held_before_owner_shutdown = !state_b.response_send_attempted();

        let owner_before =
            wait_for_owner(cluster, device_a.tenant_id, device_a.id, owner_relay).await?;
        post_a = Some(spawn_public_echo_post(PostRequest {
            consumer_addr: ingress_addr,
            server_ca_der: harness.pki.server_ca.certificate_der.clone(),
            token: token_a,
            device_id: device_a.id,
            service_id: service_a,
            body: APPEND_BODY.to_vec(),
        }));
        wait_for_effect(&state_a).await?;
        let response_held_before_owner_shutdown = !state_a.response_send_attempted();
        let owner_at_effect = current_owner(cluster, device_a.tenant_id, device_a.id)
            .await?
            .ok_or_else(|| {
                HarnessError::Process("FP-05 owner disappeared before selected owner loss".into())
            })?;
        if owner_at_effect != owner_before {
            return Err(HarnessError::Process(
                "FP-05 owner token changed before selected owner loss".into(),
            ));
        }
        let effects_at_loss = state_a.effect_count();
        state_a.arm_expected_owner_loss();
        cluster.shutdown_node(owner_relay).await?;
        wait_for_owner_loss_close(&state_a).await?;
        let owner_loss_close_observed = state_a.owner_loss_close_observed();
        let owner_after_shutdown = current_owner(cluster, device_a.tenant_id, device_a.id).await?;
        let owner_not_replaced_after_shutdown = owner_after_shutdown
            .as_ref()
            .is_none_or(|owner| owner == &owner_before);
        state_b.notify_response();
        let outcome_b = await_post(&mut post_b).await?;
        let owner_b_after_response = current_owner(cluster, device_b.tenant_id, device_b.id).await?;
        let sibling_owner_retained_after_response = owner_b_after_response
            .as_ref()
            .is_some_and(|owner| owner == &owner_b);
        if !matches!(outcome_b.terminal, PostTerminal::Success)
            || outcome_b.status != Some(200)
            || !outcome_b.response_matches_expected
        {
            return Err(HarnessError::Process(format!(
                "FP-05 tenant-B sibling did not survive owner loss: terminal={}, status={:?}, response_match={}",
                outcome_b.terminal.as_str(),
                outcome_b.status,
                outcome_b.response_matches_expected
            )));
        }
        state_a.notify_response();

        let outcome_a = await_post(&mut post_a).await?;
        let deadline = Instant::now() + POST_FAILURE_OBSERVATION;
        sleep_until(deadline).await;
        let post_failure_effects = state_a.effect_count().saturating_sub(effects_at_loss);

        Ok((
            outcome_a,
            post_failure_effects,
            response_held_before_owner_shutdown,
            sibling_response_held_before_owner_shutdown,
            owner_loss_close_observed,
            owner_not_replaced_after_shutdown,
            sibling_owner_retained_after_response,
            owner_b,
            outcome_b,
            state_b,
        ))
    })
    .catch_unwind()
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Process("FP-05 scenario panicked".into())),
    };

    let post_a_cleanup = cleanup_post(post_a.take()).await;
    let post_b_cleanup = cleanup_post(post_b.take()).await;
    let fixture_a_cleanup = if let Some(fixture) = fixture_a.take() {
        fixture.shutdown().await
    } else {
        Ok(())
    };
    let fixture_b_cleanup = if let Some(fixture) = fixture_b.take() {
        fixture.shutdown().await
    } else {
        Ok(())
    };
    let cleanup = [
        post_a_cleanup,
        post_b_cleanup,
        fixture_a_cleanup,
        fixture_b_cleanup,
    ]
    .into_iter()
    .filter_map(Result::err)
    .reduce(|first, next| {
        HarnessError::Process(format!("{first}; additional FP-05 cleanup error: {next}"))
    });
    let (
        outcome_a,
        post_failure_effects,
        response_held_before_owner_shutdown,
        sibling_response_held_before_owner_shutdown,
        owner_loss_close_observed,
        owner_not_replaced_after_shutdown,
        sibling_owner_retained_after_response,
        owner_b,
        outcome_b,
        state_b,
    ) = match (scenario, cleanup) {
        (Err(primary), Some(cleanup)) => {
            return Err(HarnessError::Process(format!(
                "{primary}; FP-05 cleanup also failed: {cleanup}"
            )));
        }
        (Err(primary), None) => return Err(primary),
        (Ok(_), Some(cleanup)) => return Err(cleanup),
        (Ok(value), None) => value,
    };
    Ok(Fp05Evidence {
        relay_count,
        owner_relay: owner_relay.to_owned(),
        ingress_relay: ingress_relay.to_owned(),
        owner_shutdown: true,
        owner_loss_close_observed,
        owner_not_replaced_after_shutdown,
        response_held_before_owner_shutdown,
        control_admitted: state_a.control_admitted(),
        owner_fenced: state_a.owner_fenced(),
        data_admitted: state_a.data_admitted(),
        operation_opened: state_a.operation_opened(),
        authorization_confirmed: state_a.authorization_confirmed(),
        post_terminal: outcome_a.terminal.as_str().to_owned(),
        post_status: outcome_a.status,
        post_elapsed_ms: outcome_a.elapsed_ms,
        post_observation_deadline_ms: duration_millis(POST_OBSERVATION_TIMEOUT),
        post_connection_joined: outcome_a.connection_joined,
        append_entries: state_a.append_entries()?.len(),
        raw_data_frames: state_a.data_count()?,
        raw_fin_frames: state_a.fin_count()?,
        raw_frame_observations: state_a.raw_count()?,
        backend_effect_invocations: state_a.effect_count(),
        duplicate_request_observations: state_a.duplicate_count(),
        post_failure_effect_invocations: post_failure_effects,
        sibling_canary_survived: sibling_owner_retained_after_response,
        sibling_response_held_before_owner_shutdown,
        sibling_owner_retained_after_response,
        sibling_owner_relay: owner_b.node_id,
        sibling_terminal: outcome_b.terminal.as_str().to_owned(),
        sibling_status: outcome_b.status,
        sibling_response_matches_request: outcome_b.response_matches_expected,
        sibling_connection_joined: outcome_b.connection_joined,
        sibling_append_entries: state_b.append_entries()?.len(),
        sibling_effect_invocations: state_b.effect_count(),
    })
}

async fn wait_for_effect(state: &EffectState) -> Result<()> {
    let deadline = Instant::now() + OWNER_READY_TIMEOUT;
    loop {
        let count = state.effect_count();
        if count == 1 {
            return Ok(());
        }
        if count > 1 {
            return Err(HarnessError::Process(format!(
                "FP-05 synthetic backend observed {count} effects before its fault boundary"
            )));
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "FP-05 backend append was not observed before its bound".into(),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_owner_loss_close(state: &EffectState) -> Result<()> {
    let deadline = Instant::now() + POST_CLEANUP_TIMEOUT;
    loop {
        if state.owner_loss_close_observed() {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(
                "FP-05 selected-owner close was not observed while the response was held".into(),
            ));
        }
        sleep(Duration::from_millis(10)).await;
    }
}

async fn wait_for_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
    expected_node: &str,
) -> Result<OwnerToken> {
    let deadline = Instant::now() + OWNER_READY_TIMEOUT;
    loop {
        if let Some(owner) = current_owner(cluster, tenant_id, device_id).await?
            && owner.node_id == expected_node
        {
            return Ok(owner);
        }
        if Instant::now() >= deadline {
            return Err(HarnessError::Timeout(format!(
                "FP-05 owner {expected_node} was not visible before its bound"
            )));
        }
        sleep(Duration::from_millis(50)).await;
    }
}

async fn current_owner(
    cluster: &ProductionCluster,
    tenant_id: Uuid,
    device_id: Uuid,
) -> Result<Option<OwnerToken>> {
    timeout(
        EXCHANGE_TIMEOUT,
        cluster
            .catalog
            .current_owner(tenant_id, device_id, Utc::now()),
    )
    .await
    .map_err(|_| HarnessError::Timeout("FP-05 owner read timed out".into()))?
    .map_err(|error| HarnessError::Redis(format!("FP-05 owner read failed: {error}")))
    .map(|claim| claim.map(|owner| owner.token))
}

fn relay_device_addr(cluster: &ProductionCluster, node_id: &str) -> Result<SocketAddr> {
    cluster
        .relays
        .iter()
        .find(|relay| relay.node_id == node_id)
        .and_then(|relay| relay.running.as_ref().map(|running| running.device_addr))
        .ok_or_else(|| {
            HarnessError::Process(format!("FP-05 relay {node_id} has no device listener"))
        })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PostTerminal {
    Success,
    CaptureError,
    HttpUnknown,
    HttpFailure,
    TransportError,
    ObserverDeadline,
}

impl PostTerminal {
    fn as_str(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::CaptureError => "capture-error",
            Self::HttpUnknown => "http-unknown",
            Self::HttpFailure => "http-failure",
            Self::TransportError => "transport-error",
            Self::ObserverDeadline => "observer-deadline",
        }
    }
}

#[derive(Debug)]
struct PostOutcome {
    terminal: PostTerminal,
    status: Option<u16>,
    elapsed_ms: u64,
    connection_joined: bool,
    response_matches_expected: bool,
}

struct PostRequest {
    consumer_addr: SocketAddr,
    server_ca_der: Vec<u8>,
    token: String,
    device_id: Uuid,
    service_id: Uuid,
    body: Vec<u8>,
}

type ConnectionTaskSlot = Arc<tokio::sync::Mutex<Option<JoinHandle<()>>>>;

struct PostTask {
    task: JoinHandle<PostOutcome>,
    connection: ConnectionTaskSlot,
}

fn spawn_public_echo_post(request: PostRequest) -> PostTask {
    let connection = Arc::new(tokio::sync::Mutex::new(None));
    let task_connection = connection.clone();
    let task = tokio::spawn(public_echo_post(request, task_connection));
    PostTask { task, connection }
}

async fn public_echo_post(
    request: PostRequest,
    connection_slot: ConnectionTaskSlot,
) -> PostOutcome {
    if !request.body.is_empty()
        && crate::c11_capture::record_sentinel("application_payload", &request.body).is_err()
    {
        return PostOutcome {
            terminal: PostTerminal::CaptureError,
            status: None,
            elapsed_ms: 0,
            connection_joined: true,
            response_matches_expected: false,
        };
    }
    let started = Instant::now();
    let deadline = started + POST_OBSERVATION_TIMEOUT;
    let expected_body = request.body.clone();
    let deadline_outcome = || PostOutcome {
        terminal: PostTerminal::ObserverDeadline,
        status: None,
        elapsed_ms: duration_millis(started.elapsed()),
        connection_joined: false,
        response_matches_expected: false,
    };
    let transport_outcome = || PostOutcome {
        terminal: PostTerminal::TransportError,
        status: None,
        elapsed_ms: duration_millis(started.elapsed()),
        connection_joined: false,
        response_matches_expected: false,
    };

    let mut roots = rustls::RootCertStore::empty();
    if roots
        .add(CertificateDer::from(request.server_ca_der))
        .is_err()
    {
        return transport_outcome();
    }
    let builder = match rustls::ClientConfig::builder_with_provider(
        rustls::crypto::ring::default_provider().into(),
    )
    .with_protocol_versions(&[&rustls::version::TLS13])
    {
        Ok(builder) => builder,
        Err(_) => return transport_outcome(),
    };
    let tls = builder.with_root_certificates(roots).with_no_client_auth();
    let connector = TlsConnector::from(Arc::new(tls));
    let stream = match timeout_at(deadline, TcpStream::connect(request.consumer_addr)).await {
        Err(_) => return deadline_outcome(),
        Ok(Err(_)) => return transport_outcome(),
        Ok(Ok(stream)) => stream,
    };
    let server_name = match ServerName::try_from("localhost".to_owned()) {
        Ok(name) => name,
        Err(_) => return transport_outcome(),
    };
    let tls_stream = match timeout_at(deadline, connector.connect(server_name, stream)).await {
        Err(_) => return deadline_outcome(),
        Ok(Err(_)) => return transport_outcome(),
        Ok(Ok(stream)) => stream,
    };
    let (mut sender, connection) = match timeout_at(
        deadline,
        hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
    )
    .await
    {
        Err(_) => return deadline_outcome(),
        Ok(Err(_)) => return transport_outcome(),
        Ok(Ok(value)) => value,
    };
    let mut connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    if let Ok(mut slot) = connection_slot.try_lock() {
        *slot = Some(connection_task);
    } else {
        connection_task.abort();
        let _ = timeout(POST_CLEANUP_TIMEOUT, &mut connection_task).await;
        return transport_outcome();
    }
    let uri = format!(
        "https://localhost:{}/v1/devices/{}/services/{}/echo",
        request.consumer_addr.port(),
        request.device_id,
        request.service_id
    );
    let http_request = match Request::builder()
        .method("POST")
        .uri(uri)
        .header("host", "localhost")
        .header("authorization", format!("Bearer {}", request.token))
        .header("content-type", "application/octet-stream")
        .body(Full::new(Bytes::from(request.body)))
    {
        Ok(request) => request,
        Err(_) => {
            drop(sender);
            let joined = join_connection_slot(&connection_slot, deadline).await;
            return PostOutcome {
                terminal: PostTerminal::TransportError,
                status: None,
                elapsed_ms: duration_millis(started.elapsed()),
                connection_joined: joined,
                response_matches_expected: false,
            };
        }
    };
    let response = match timeout_at(deadline, sender.send_request(http_request)).await {
        Err(_) => {
            drop(sender);
            let joined = join_connection_slot(&connection_slot, deadline).await;
            return PostOutcome {
                terminal: PostTerminal::ObserverDeadline,
                status: None,
                elapsed_ms: duration_millis(started.elapsed()),
                connection_joined: joined,
                response_matches_expected: false,
            };
        }
        Ok(Err(_)) => {
            drop(sender);
            let joined = join_connection_slot(&connection_slot, deadline).await;
            return PostOutcome {
                terminal: PostTerminal::TransportError,
                status: None,
                elapsed_ms: duration_millis(started.elapsed()),
                connection_joined: joined,
                response_matches_expected: false,
            };
        }
        Ok(Ok(response)) => response,
    };
    let status = response.status().as_u16();
    let body = match timeout_at(
        deadline,
        Limited::new(response.into_body(), MAX_POST_RESPONSE_BYTES).collect(),
    )
    .await
    {
        Err(_) => {
            drop(sender);
            let joined = join_connection_slot(&connection_slot, deadline).await;
            return PostOutcome {
                terminal: PostTerminal::ObserverDeadline,
                status: Some(status),
                elapsed_ms: duration_millis(started.elapsed()),
                connection_joined: joined,
                response_matches_expected: false,
            };
        }
        Ok(Err(_)) => {
            drop(sender);
            let joined = join_connection_slot(&connection_slot, deadline).await;
            return PostOutcome {
                terminal: PostTerminal::TransportError,
                status: Some(status),
                elapsed_ms: duration_millis(started.elapsed()),
                connection_joined: joined,
                response_matches_expected: false,
            };
        }
        Ok(Ok(body)) => body.to_bytes(),
    };
    let explicit_unknown = serde_json::from_slice::<serde_json::Value>(&body)
        .ok()
        .is_some_and(|value| {
            value.get("execution").and_then(serde_json::Value::as_str) == Some("unknown")
        });
    let terminal = if status == 200 {
        PostTerminal::Success
    } else if status == 503 && explicit_unknown {
        PostTerminal::HttpUnknown
    } else {
        PostTerminal::HttpFailure
    };
    drop(sender);
    let connection_joined = join_connection_slot(&connection_slot, deadline).await;
    PostOutcome {
        terminal,
        status: Some(status),
        elapsed_ms: duration_millis(started.elapsed()),
        connection_joined,
        response_matches_expected: status == 200 && body.as_ref() == expected_body.as_slice(),
    }
}

async fn join_connection_slot(slot: &ConnectionTaskSlot, deadline: Instant) -> bool {
    let mut guard = slot.lock().await;
    let Some(task) = guard.as_mut() else {
        return true;
    };
    let joined = join_connection(task, deadline).await;
    let _ = guard.take();
    joined
}

async fn join_connection(task: &mut JoinHandle<()>, deadline: Instant) -> bool {
    match timeout_at(deadline, &mut *task).await {
        Ok(Ok(())) => true,
        Ok(Err(_)) => true,
        Err(_) => {
            task.abort();
            let _ = timeout(POST_CLEANUP_TIMEOUT, task).await;
            false
        }
    }
}

async fn await_post(slot: &mut Option<PostTask>) -> Result<PostOutcome> {
    let Some(mut post) = slot.take() else {
        return Err(HarnessError::Process("FP-05 POST task was missing".into()));
    };
    match timeout(
        POST_OBSERVATION_TIMEOUT + POST_CLEANUP_TIMEOUT,
        &mut post.task,
    )
    .await
    {
        Ok(Ok(mut outcome)) => {
            if !join_connection_slot(&post.connection, Instant::now() + POST_CLEANUP_TIMEOUT).await
            {
                outcome.connection_joined = false;
            }
            Ok(outcome)
        }
        Ok(Err(error)) => {
            let connection_joined =
                join_connection_slot(&post.connection, Instant::now() + POST_CLEANUP_TIMEOUT).await;
            if connection_joined {
                Err(HarnessError::Process(format!(
                    "FP-05 POST task failed: {error}"
                )))
            } else {
                Err(HarnessError::Process(format!(
                    "FP-05 POST task failed: {error}; connection cleanup also failed"
                )))
            }
        }
        Err(_) => {
            post.task.abort();
            let _ = post.task.await;
            let connection_joined =
                join_connection_slot(&post.connection, Instant::now() + POST_CLEANUP_TIMEOUT).await;
            Ok(PostOutcome {
                terminal: PostTerminal::ObserverDeadline,
                status: None,
                elapsed_ms: duration_millis(POST_OBSERVATION_TIMEOUT),
                connection_joined,
                response_matches_expected: false,
            })
        }
    }
}

async fn cleanup_post(slot: Option<PostTask>) -> Result<()> {
    let Some(mut post) = slot else {
        return Ok(());
    };
    let outer = match timeout(POST_CLEANUP_TIMEOUT, &mut post.task).await {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(error)) => Err(HarnessError::Process(format!(
            "FP-05 POST cleanup task failed: {error}"
        ))),
        Err(_) => {
            post.task.abort();
            let _ = post.task.await;
            Err(HarnessError::Timeout("FP-05 POST cleanup timed out".into()))
        }
    };
    let connection =
        join_connection_slot(&post.connection, Instant::now() + POST_CLEANUP_TIMEOUT).await;
    match (outer, connection) {
        (Ok(()), true) => Ok(()),
        (Err(primary), true) => Err(primary),
        (Ok(()), false) => Err(HarnessError::Timeout(
            "FP-05 POST connection cleanup timed out".into(),
        )),
        (Err(primary), false) => Err(HarnessError::Process(format!(
            "{primary}; FP-05 connection cleanup also failed"
        ))),
    }
}

fn duration_millis(duration: Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}
