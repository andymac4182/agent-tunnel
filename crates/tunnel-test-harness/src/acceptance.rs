//! Real-socket M1 acceptance flow.
//!
//! This module deliberately drives the public HTTPS listener and the client
//! WSS runtime.  The catalog, TLS identities, authorization snapshots and
//! relay actor all remain production implementations; this file only creates
//! synthetic inputs and records bounded evidence.

pub(crate) mod helpers;

use crate::{Direction, FaultAction, FaultScript, ProxyConfig, ProxyHandle, TcpProxy};
use crate::{Harness, HarnessError, HarnessOptions, OidcTokenOptions, Result, RunningHarness};
use futures_util::future::join_all;
use helpers::{
    DeviceProfile, HeldConsumerRequest, HttpResponse, consumer_request,
    consumer_request_with_timeout, error_code, hold_consumer_request, write_device_profile,
};
use std::{
    collections::BTreeSet,
    path::Path,
    time::{Duration, Instant},
};
use tokio::time::{sleep, timeout};
use tunnel_catalog::{Catalog, DeviceSummary};
use tunnel_client::{ConnectConfig, ConnectOptions, ConnectionHandle, TransportProfile};
use tunnel_relay::RelayLimits;
use uuid::Uuid;

const SUITE_TIMEOUT: Duration = Duration::from_secs(150);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
const REVOCATION_DEADLINE: Duration = Duration::from_secs(5);

/// Keep the legacy M1 acceptance on its explicit finite profile now that new
/// library callers default to M2.  The fixtures still prove the original M1
/// contract and must not accidentally start a rotation runtime.
fn m1_options(config: ConnectConfig) -> ConnectOptions {
    let mut options = ConnectOptions::new(config);
    options.profile = TransportProfile::M1;
    options
}

/// Run the M1 acceptance gate against the harness's real durable catalog,
/// real relay TLS listeners, and five real connector sessions.
pub async fn verify() -> Result<()> {
    let options = HarnessOptions::from_env()?;
    let started = Instant::now();
    let mut harness = timeout(SUITE_TIMEOUT, Harness::start(options))
        .await
        .map_err(|_| {
            HarnessError::Timeout("M1 harness startup exceeded suite deadline".to_owned())
        })??;
    let mut clients = Vec::new();
    let remaining = SUITE_TIMEOUT.saturating_sub(started.elapsed());
    // Keep the deadline inside the scope that owns the proxy.  If the suite
    // times out, `run_with_cleanup` still gets to close the proxy before this
    // function stops clients and tears down the isolated catalog namespace.
    let result = run_with_cleanup(&mut harness, &mut clients, remaining).await;
    let clients_result = stop_clients(&mut clients).await;
    let harness_result = harness.shutdown().await;

    match (result, clients_result, harness_result) {
        (Err(error), _, _) => Err(error),
        (Ok(()), Err(error), _) => Err(error),
        (Ok(()), Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_with_cleanup(
    harness: &mut RunningHarness,
    clients: &mut Vec<ConnectionHandle>,
    budget: Duration,
) -> Result<()> {
    let deadline = Instant::now() + budget;
    let limits = RelayLimits {
        max_pending_operations: 8,
        ..RelayLimits::default()
    };
    let (consumer_addr, device_addr) =
        timeout(budget, harness.start_production_relay_with_limits(limits))
            .await
            .map_err(|_| {
                HarnessError::Timeout("starting production relay timed out".to_owned())
            })??;
    let bind_budget = deadline.saturating_duration_since(Instant::now());
    let proxy = timeout(
        bind_budget,
        TcpProxy::bind(
            device_addr,
            ProxyConfig {
                fault_script: FaultScript::default()
                    .with_rule(
                        Direction::ClientToTarget,
                        FaultAction::CloseAfterBytes(64 * 1024),
                    )
                    .with_rule(
                        Direction::TargetToClient,
                        FaultAction::CloseAfterBytes(64 * 1024),
                    ),
                ..ProxyConfig::default()
            },
        ),
    )
    .await
    .map_err(|_| HarnessError::Timeout("binding acceptance proxy timed out".to_owned()))??;
    let run_budget = deadline.saturating_duration_since(Instant::now());
    let result = match timeout(
        run_budget,
        run_with_proxy(
            harness,
            consumer_addr,
            device_addr,
            proxy.local_addr(),
            &proxy,
            clients,
        ),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(HarnessError::Timeout(
            "M1 acceptance exceeded suite deadline".to_owned(),
        )),
    };
    let proxy_result = proxy.shutdown().await;
    match (result, proxy_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

async fn run_with_proxy(
    harness: &mut RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_addr: std::net::SocketAddr,
    proxy_addr: std::net::SocketAddr,
    proxy: &ProxyHandle,
    clients: &mut Vec<ConnectionHandle>,
) -> Result<()> {
    let profile_root = tempfile::tempdir().map_err(HarnessError::Io)?;
    let mut profiles = make_profiles(harness, device_addr, profile_root.path())?;
    if profiles.len() != crate::M1_DEVICE_COUNT {
        return Err(HarnessError::InvalidInput(format!(
            "M1 topology produced {} device profiles, expected {}",
            profiles.len(),
            crate::M1_DEVICE_COUNT
        )));
    }
    profiles[0].config.relay_url =
        format!("wss://localhost:{}/v1/tunnel/control", proxy_addr.port());

    connect_all(&profiles, clients).await?;
    let mut evidence = Evidence {
        devices_connected: clients.len(),
        ..Evidence::default()
    };
    let proxy_connections = proxy.stats().accepted;
    assert_named(
        proxy_connections >= 2,
        "control and data WSS both traversed the TLS-pass-through proxy",
    )?;
    evidence.proxy_connections = proxy_connections;

    let phase_result = run_acceptance_phases(
        harness,
        consumer_addr,
        device_addr,
        &mut profiles,
        clients,
        proxy,
        &mut evidence,
    )
    .await;

    // The raw transport and private-peer checks own their own socket clients.
    // Stop the five foreground connectors first so those checks cannot pass
    // because a fixture-only actor remains registered in the relay.
    stop_clients(clients).await?;
    if phase_result.is_ok() {
        crate::admission::verify(harness, consumer_addr, device_addr).await?;
        crate::peer::verify(harness).await?;
    }
    phase_result?;

    println!(
        "M1 acceptance passed: clients={} echo_requests={} list_assertions={} auth_rejections={} revocation_ms={} disconnects={} proxy_connections={} proxy_closes={} quota_assertions={} queue_rejections={} cli_echoes={} cli_smoke=1",
        evidence.devices_connected,
        evidence.echo_requests,
        evidence.list_assertions,
        evidence.auth_rejections,
        evidence.revocation_elapsed_ms,
        evidence.disconnects,
        evidence.proxy_connections,
        evidence.proxy_closes,
        evidence.quota_assertions,
        evidence.queue_rejections,
        evidence.cli_echoes,
    );
    drop(profile_root);
    Ok(())
}

#[derive(Default)]
struct Evidence {
    devices_connected: usize,
    echo_requests: usize,
    list_assertions: usize,
    auth_rejections: usize,
    revocation_elapsed_ms: u128,
    disconnects: usize,
    proxy_connections: u64,
    proxy_closes: u64,
    quota_assertions: usize,
    queue_rejections: usize,
    cli_echoes: usize,
}

fn make_profiles(
    harness: &RunningHarness,
    device_addr: std::net::SocketAddr,
    root: &Path,
) -> Result<Vec<DeviceProfile>> {
    let mut service_ids = BTreeSet::new();
    let mut profiles = Vec::with_capacity(crate::M1_DEVICE_COUNT);
    for device in harness.topology.all_devices() {
        let service_id = *harness
            .topology
            .service_ids
            .get(&device.id)
            .ok_or_else(|| {
                HarnessError::InvalidInput(format!("device {} has no service", device.id))
            })?;
        if !service_ids.insert(service_id) {
            return Err(HarnessError::InvalidInput(format!(
                "duplicate service id {service_id} in M1 fixture"
            )));
        }
        let canary = format!("m1-canary:{service_id}");
        profiles.push(write_device_profile(
            root,
            device.id,
            service_id,
            &canary,
            device_addr,
            &device.certificate.certificate_pem,
            &device.certificate.private_key_pem,
            &harness.pki.server_ca.certificate_pem,
        )?);
    }
    Ok(profiles)
}

async fn connect_all(
    profiles: &[DeviceProfile],
    clients: &mut Vec<ConnectionHandle>,
) -> Result<()> {
    for profile in profiles {
        let mut handle = tunnel_client::connect(m1_options(profile.config.clone()))
            .await
            .map_err(|error| {
                HarnessError::Process(format!("device connector failed to connect: {error}"))
            })?;
        timeout(REQUEST_TIMEOUT, handle.wait_ready())
            .await
            .map_err(|_| HarnessError::Timeout("device connector readiness timed out".to_owned()))?
            .map_err(|error| {
                HarnessError::Process(format!("device connector did not become ready: {error}"))
            })?;
        clients.push(handle);
    }
    Ok(())
}

async fn run_acceptance_phases(
    harness: &mut RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_addr: std::net::SocketAddr,
    profiles: &mut [DeviceProfile],
    clients: &mut Vec<ConnectionHandle>,
    proxy: &ProxyHandle,
    evidence: &mut Evidence,
) -> Result<()> {
    // Keep the complete acceptance flow bounded even when a relay or client
    // stops responding.  Cleanup is performed by the caller after this future
    // returns, including on timeout.
    verify_listing_and_isolation(harness, consumer_addr, profiles, evidence).await?;
    verify_jwt_rejections(harness, consumer_addr, profiles, evidence).await?;
    verify_echoes(harness, consumer_addr, profiles, evidence).await?;
    verify_proxy_drop_and_fresh_session(
        harness,
        consumer_addr,
        device_addr,
        profiles,
        clients,
        proxy,
        evidence,
    )
    .await?;
    verify_quotas(harness, consumer_addr, profiles, evidence).await?;
    verify_revocation(harness, consumer_addr, profiles, evidence).await?;
    verify_disconnect_and_fresh_session(
        harness,
        consumer_addr,
        device_addr,
        profiles,
        clients,
        evidence,
    )
    .await?;
    verify_cli_smoke(
        harness,
        consumer_addr,
        device_addr,
        profiles,
        clients,
        evidence,
    )
    .await
}

async fn verify_listing_and_isolation(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    evidence: &mut Evidence,
) -> Result<()> {
    let owner_a = harness
        .topology
        .consumers_a
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant A has no consumer".to_owned()))?;
    let owner_b = harness
        .topology
        .consumers_b
        .first()
        .ok_or_else(|| HarnessError::InvalidInput("tenant B has no consumer".to_owned()))?;
    let token_a = harness.oidc.issue(&owner_a.name)?;
    let token_b = harness.oidc.issue(&owner_b.name)?;
    let response_a = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        "GET",
        "/v1/devices",
        Vec::new(),
    )
    .await?;
    assert_status(
        &response_a,
        hyper::StatusCode::OK,
        "tenant A device listing",
    )?;
    let listing_a = parse_listing(&response_a)?;
    let expected_a = harness
        .topology
        .devices_a
        .iter()
        .map(|device| device.id)
        .collect::<BTreeSet<_>>();
    let actual_a = listing_a
        .iter()
        .map(|device| device.device_id)
        .collect::<BTreeSet<_>>();
    assert_named(actual_a == expected_a, "tenant A listing is grant-filtered")?;
    evidence.list_assertions += 1;

    let response_b = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token_b,
        "GET",
        "/v1/devices",
        Vec::new(),
    )
    .await?;
    assert_status(
        &response_b,
        hyper::StatusCode::OK,
        "tenant B device listing",
    )?;
    let listing_b = parse_listing(&response_b)?;
    let expected_b = harness
        .topology
        .devices_b
        .iter()
        .map(|device| device.id)
        .collect::<BTreeSet<_>>();
    let actual_b = listing_b
        .iter()
        .map(|device| device.device_id)
        .collect::<BTreeSet<_>>();
    assert_named(
        actual_b == expected_b,
        "tenant B listing is tenant-isolated",
    )?;
    evidence.list_assertions += 1;

    let limited = harness
        .oidc
        .issue(&harness.topology.limited_member_a.name)?;
    let limited_response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &limited,
        "GET",
        "/v1/devices",
        Vec::new(),
    )
    .await?;
    assert_status(
        &limited_response,
        hyper::StatusCode::OK,
        "limited member listing",
    )?;
    let limited_listing = parse_listing(&limited_response)?;
    assert_named(
        limited_listing.len() == 1
            && limited_listing[0].device_id == harness.topology.devices_a[0].id,
        "same-tenant limited member sees only its grant",
    )?;
    evidence.list_assertions += 1;

    let cross_tenant = &harness.topology.devices_b[0];
    let cross_service = service_id(harness, cross_tenant.id)?;
    let cross_response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        "POST",
        &format!(
            "/v1/devices/{}/services/{cross_service}/echo",
            cross_tenant.id
        ),
        b"cross-tenant".to_vec(),
    )
    .await?;
    assert_status(
        &cross_response,
        hyper::StatusCode::NOT_FOUND,
        "cross-tenant echo denial",
    )?;
    evidence.list_assertions += 1;

    let unshared = &harness.topology.devices_a[1];
    let unshared_service = service_id(harness, unshared.id)?;
    let unshared_response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &limited,
        "POST",
        &format!(
            "/v1/devices/{}/services/{unshared_service}/echo",
            unshared.id
        ),
        b"unshared".to_vec(),
    )
    .await?;
    assert_status(
        &unshared_response,
        hyper::StatusCode::NOT_FOUND,
        "unshared same-tenant echo denial",
    )?;
    evidence.list_assertions += 1;
    let _ = profiles;
    Ok(())
}

async fn verify_jwt_rejections(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    evidence: &mut Evidence,
) -> Result<()> {
    let subject = &harness.topology.consumers_a[0].name;
    let invalid_tokens = [
        (
            "wrong issuer",
            harness.oidc.issue_with_wrong_issuer(subject)?,
        ),
        (
            "wrong audience",
            harness.oidc.issue_with_wrong_audience(subject)?,
        ),
        ("expired", harness.oidc.issue_expired(subject)?),
    ];
    for (name, token) in invalid_tokens {
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "GET",
            "/v1/devices",
            Vec::new(),
        )
        .await?;
        assert_status(&response, hyper::StatusCode::UNAUTHORIZED, name)?;
        evidence.auth_rejections += 1;
    }
    let missing_scope = harness.oidc.issue_with(
        subject,
        OidcTokenOptions {
            scope: Some("devices:read".to_owned()),
            ..OidcTokenOptions::default()
        },
    )?;
    let device = &harness.topology.devices_a[0];
    let service = service_id(harness, device.id)?;
    let response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &missing_scope,
        "POST",
        &format!("/v1/devices/{}/services/{service}/echo", device.id),
        b"scope".to_vec(),
    )
    .await?;
    // M6-C53: a token whose signature, claims and consumer all pass but that
    // lacks the route's scope is `403` -- the token is fine, the route is not
    // in it -- where it was `401` before.
    assert_status(
        &response,
        hyper::StatusCode::FORBIDDEN,
        "missing echo scope",
    )?;
    evidence.auth_rejections += 1;
    let _ = profiles;
    Ok(())
}

async fn verify_echoes(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    evidence: &mut Evidence,
) -> Result<()> {
    let token_a = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let first = &harness.topology.devices_a[0];
    let second_consumer = &harness.topology.consumers_a[1];
    assert_named(
        harness.topology.grant(second_consumer.id, first.id, "echo"),
        "second tenant-A consumer has an independent grant to the shared device",
    )?;
    let token_a_second = harness.oidc.issue(&second_consumer.name)?;
    let token_b = harness.oidc.issue(&harness.topology.consumers_b[0].name)?;
    let first_service = service_id(harness, first.id)?;
    let first_path = format!("/v1/devices/{}/services/{first_service}/echo", first.id);
    let first_body = first.binary_canary.clone();
    let concurrent_one = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token_a,
        "POST",
        &first_path,
        first_body.clone(),
    );
    let concurrent_two = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token_a_second,
        "POST",
        &first_path,
        b"second-concurrent-consumer".to_vec(),
    );
    let (one, two) = tokio::join!(concurrent_one, concurrent_two);
    let one = one?;
    let two = two?;
    assert_echo(
        &one,
        &profiles[0].canary,
        &first_body,
        "consumer-a-1 concurrent echo",
    )?;
    assert_echo(
        &two,
        &profiles[0].canary,
        b"second-concurrent-consumer",
        "consumer-a-2 concurrent echo",
    )?;
    evidence.echo_requests += 2;

    for (index, device) in harness.topology.all_devices().enumerate() {
        let token = if device.tenant_id == harness.topology.tenant_a.id {
            &token_a
        } else {
            &token_b
        };
        let service = service_id(harness, device.id)?;
        assert_named(
            profiles[index].service_id == service,
            "device profile service id matches catalog service id",
        )?;
        let path = format!("/v1/devices/{}/services/{service}/echo", device.id);
        let body = device.binary_canary.clone();
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            "POST",
            &path,
            body.clone(),
        )
        .await?;
        assert_echo(
            &response,
            &profiles[index].canary,
            &body,
            "binary echo per device",
        )?;
        evidence.echo_requests += 1;
    }
    Ok(())
}

async fn verify_quotas(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    evidence: &mut Evidence,
) -> Result<()> {
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let device = &harness.topology.devices_a[2];
    let service = service_id(harness, device.id)?;
    let path = format!("/v1/devices/{}/services/{service}/echo", device.id);
    let bounded_body = vec![0xA5; 63 * 1024];
    let response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        bounded_body.clone(),
    )
    .await?;
    assert_echo(
        &response,
        &profiles[2].canary,
        &bounded_body,
        "bounded echo body",
    )?;
    evidence.quota_assertions += 1;

    let max_body = vec![0x4D; 64 * 1024];
    let max_response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        max_body.clone(),
    )
    .await?;
    assert_echo(
        &max_response,
        &profiles[2].canary,
        &max_body,
        "maximum accepted 64 KiB echo body",
    )?;
    evidence.echo_requests += 1;
    evidence.quota_assertions += 1;

    let oversized = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        vec![0x5A; 65 * 1024 + 1],
    )
    .await?;
    assert_status(
        &oversized,
        hyper::StatusCode::PAYLOAD_TOO_LARGE,
        "oversized echo body",
    )?;
    evidence.quota_assertions += 1;

    // A bounded concurrent burst exercises the actor and both per-session
    // queues without assuming a M2 rotation/replay implementation exists.
    let requests = (0..8)
        .map(|index| {
            consumer_request(
                consumer_addr,
                &harness.pki.server_ca.certificate_der,
                &token,
                "POST",
                &path,
                format!("bounded-burst-{index}").into_bytes(),
            )
        })
        .collect::<Vec<_>>();
    for response in join_all(requests).await {
        let response = response?;
        assert_status(&response, hyper::StatusCode::OK, "bounded concurrent burst")?;
        evidence.echo_requests += 1;
    }
    evidence.quota_assertions += 1;

    verify_prebody_admission(harness, consumer_addr, profiles, &token, &path, evidence).await?;
    Ok(())
}

async fn verify_prebody_admission(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    token: &str,
    path: &str,
    evidence: &mut Evidence,
) -> Result<()> {
    const HELD_REQUESTS: usize = 8;
    // Each hold returns only once the relay has admitted it (M6-C85), so all
    // eight permits are held before the ninth request is sent.  A hold the
    // relay refuses fails here, naming its position, rather than leaving a
    // free permit for the ninth request to take.
    let mut held = Vec::<HeldConsumerRequest>::with_capacity(HELD_REQUESTS);
    for index in 0..HELD_REQUESTS {
        let request = hold_consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            path,
            100,
        )
        .await
        .map_err(|error| {
            HarnessError::Http(format!(
                "pre-body admission hold {} of {HELD_REQUESTS} was not admitted: {error}",
                index + 1
            ))
        })?;
        held.push(request);
    }

    // With every permit held, the ninth request must be refused on its first
    // attempt: there is nothing to wait for and nothing to retry.
    let probe = consumer_request_with_timeout(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        token,
        "POST",
        path,
        b"admission-probe".to_vec(),
        Duration::from_secs(5),
    )
    .await?;
    assert_named(
        probe.status == hyper::StatusCode::TOO_MANY_REQUESTS
            && error_code(&probe).as_deref() == Some("ADMISSION_LIMIT"),
        "ninth request receives bounded pre-body admission HTTP 429",
    )?;
    evidence.queue_rejections += 1;
    evidence.quota_assertions += 1;

    // Closing the incomplete bodies releases every permit.  An incomplete
    // Content-Length is expected to make these individual responses fail;
    // recovery below is the meaningful assertion that cleanup happened.
    for request in held.drain(..) {
        let _ = request.release().await;
    }

    let recovery_body = b"post-admission-recovery".to_vec();
    let recovery_started = Instant::now();
    loop {
        match consumer_request_with_timeout(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            "POST",
            path,
            recovery_body.clone(),
            Duration::from_millis(500),
        )
        .await
        {
            Ok(response) if response.status == hyper::StatusCode::OK => {
                assert_echo(
                    &response,
                    &profiles[2].canary,
                    &recovery_body,
                    "device recovers after pre-body admission release",
                )?;
                evidence.echo_requests += 1;
                break;
            }
            Ok(response)
                if response.status == hyper::StatusCode::TOO_MANY_REQUESTS
                    || response.status == hyper::StatusCode::SERVICE_UNAVAILABLE => {}
            Ok(response) => {
                return Err(HarnessError::Http(format!(
                    "admission recovery returned unexpected status {} code {:?}",
                    response.status,
                    error_code(&response),
                )));
            }
            Err(_) => {}
        }
        if recovery_started.elapsed() >= Duration::from_secs(5) {
            return Err(HarnessError::Timeout(
                "pre-body admission permits did not recover within five seconds".to_owned(),
            ));
        }
        sleep(Duration::from_millis(50)).await;
    }

    let unrelated = &harness.topology.devices_b[0];
    let unrelated_service = service_id(harness, unrelated.id)?;
    let unrelated_token = harness.oidc.issue(&harness.topology.consumers_b[0].name)?;
    let unrelated_body = b"unrelated-after-admission-release".to_vec();
    let unrelated_response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &unrelated_token,
        "POST",
        &format!(
            "/v1/devices/{}/services/{unrelated_service}/echo",
            unrelated.id
        ),
        unrelated_body.clone(),
    )
    .await?;
    assert_echo(
        &unrelated_response,
        &profiles[3].canary,
        &unrelated_body,
        "unrelated device recovers after admission release",
    )?;
    evidence.echo_requests += 1;
    evidence.quota_assertions += 1;
    Ok(())
}

async fn verify_revocation(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    _profiles: &[DeviceProfile],
    evidence: &mut Evidence,
) -> Result<()> {
    let principal = harness.topology.consumers_a[0].id;
    let device = harness.topology.devices_a[0].id;
    let service = service_id(harness, device)?;
    // Reuse the harness-owned production backend.  This keeps the acceptance
    // path storage-neutral: the current run may be backed by Redis (or a
    // future durable catalog) while the revocation mutation still targets the
    // exact namespace used by the live relay.
    let catalog = harness.production_catalog()?;
    catalog
        .revoke_grant(
            harness.topology.tenant_a.id,
            principal,
            device,
            service,
            chrono::Utc::now(),
        )
        .await
        .map_err(|error| {
            HarnessError::Process(format!(
                "revoking fixture grant through production catalog: {error}"
            ))
        })?;

    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let path = format!("/v1/devices/{device}/services/{service}/echo");
    let started = Instant::now();
    loop {
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "POST",
            &path,
            b"revocation-probe".to_vec(),
        )
        .await?;
        // The public route intentionally hides an unshared/revoked grant as
        // NOT_FOUND; a direct authorization failure may instead be FORBIDDEN.
        if matches!(
            response.status,
            hyper::StatusCode::FORBIDDEN | hyper::StatusCode::NOT_FOUND
        ) {
            evidence.revocation_elapsed_ms = started.elapsed().as_millis();
            assert_named(
                evidence.revocation_elapsed_ms <= REVOCATION_DEADLINE.as_millis(),
                "grant revocation enforced within five seconds",
            )?;
            return Ok(());
        }
        if started.elapsed() >= REVOCATION_DEADLINE {
            return Err(HarnessError::Timeout(format!(
                "grant revocation was not visible within {} ms (last status {}, code {:?})",
                REVOCATION_DEADLINE.as_millis(),
                response.status,
                error_code(&response),
            )));
        }
        sleep(Duration::from_millis(100)).await;
    }
}

async fn verify_proxy_drop_and_fresh_session(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_addr: std::net::SocketAddr,
    profiles: &mut [DeviceProfile],
    clients: &mut Vec<ConnectionHandle>,
    proxy: &ProxyHandle,
    evidence: &mut Evidence,
) -> Result<()> {
    let device = &harness.topology.devices_a[0];
    let service = service_id(harness, device.id)?;
    let path = format!("/v1/devices/{}/services/{service}/echo", device.id);
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let body = vec![0xC3; 63 * 1024];
    let started = Instant::now();
    let mut close_seen = false;
    while started.elapsed() < Duration::from_secs(10) {
        let _ = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "POST",
            &path,
            body.clone(),
        )
        .await;
        let stats = proxy.stats();
        if stats.closes > 0 {
            close_seen = true;
            evidence.proxy_closes = stats.closes;
            break;
        }
        sleep(Duration::from_millis(100)).await;
    }
    assert_named(
        close_seen,
        "TLS-pass-through proxy forced a transport close",
    )?;

    // The connector treats a data/control transport failure as a terminal
    // session.  Stop the old handle even if its supervisor already observed
    // the close, then prove the relay no longer dispatches to that session.
    let old = clients.remove(0);
    let mut readiness = old.readiness();
    let transport_closed = timeout(Duration::from_secs(5), async {
        loop {
            if matches!(
                &*readiness.borrow(),
                tunnel_client::Readiness::Closed { .. }
            ) {
                return true;
            }
            if readiness.changed().await.is_err() {
                return true;
            }
        }
    })
    .await
    .unwrap_or(false);
    assert_named(
        transport_closed,
        "connector observed the proxy data/control transport closure",
    )?;
    let _ = timeout(Duration::from_secs(5), old.stop()).await;
    evidence.disconnects += 1;
    let small_body = b"proxy-after-close".to_vec();
    let unavailable_started = Instant::now();
    loop {
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "POST",
            &path,
            small_body.clone(),
        )
        .await?;
        if response.status == hyper::StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
        if unavailable_started.elapsed() > Duration::from_secs(5) {
            return Err(HarnessError::Timeout(
                "proxy-dropped connector remained dispatchable".to_owned(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }

    // Switch the same generated profile back to the direct relay endpoint and
    // establish a fresh epoch after the proxy-induced pair failure.
    profiles[0].config.relay_url =
        format!("wss://localhost:{}/v1/tunnel/control", device_addr.port());
    let mut fresh = tunnel_client::connect(m1_options(profiles[0].config.clone()))
        .await
        .map_err(|error| {
            HarnessError::Process(format!("fresh post-proxy connector failed: {error}"))
        })?;
    timeout(REQUEST_TIMEOUT, fresh.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("post-proxy connector readiness timed out".to_owned()))?
        .map_err(|error| {
            HarnessError::Process(format!(
                "post-proxy connector did not become ready: {error}"
            ))
        })?;
    clients.insert(0, fresh);
    let response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        small_body.clone(),
    )
    .await?;
    assert_echo(
        &response,
        &profiles[0].canary,
        &small_body,
        "fresh session after proxy transport drop",
    )?;
    evidence.echo_requests += 1;
    Ok(())
}

async fn verify_disconnect_and_fresh_session(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    clients: &mut Vec<ConnectionHandle>,
    evidence: &mut Evidence,
) -> Result<()> {
    let index = 1_usize;
    let handle = clients.remove(index);
    handle
        .stop()
        .await
        .map_err(|error| HarnessError::Process(format!("stopping device pair: {error}")))?;
    evidence.disconnects += 1;

    let device = &harness.topology.devices_a[index];
    let service = service_id(harness, device.id)?;
    let path = format!("/v1/devices/{}/services/{service}/echo", device.id);
    let token = harness.oidc.issue(&harness.topology.consumers_a[0].name)?;
    let started = Instant::now();
    loop {
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "POST",
            &path,
            b"after-disconnect".to_vec(),
        )
        .await?;
        if response.status == hyper::StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
        if started.elapsed() > Duration::from_secs(5) {
            return Err(HarnessError::Timeout(
                "relay retained a disconnected device session".to_owned(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }

    let mut fresh = tunnel_client::connect(m1_options(profiles[index].config.clone()))
        .await
        .map_err(|error| {
            HarnessError::Process(format!("fresh connector failed to connect: {error}"))
        })?;
    timeout(REQUEST_TIMEOUT, fresh.wait_ready())
        .await
        .map_err(|_| HarnessError::Timeout("fresh connector readiness timed out".to_owned()))?
        .map_err(|error| HarnessError::Process(format!("fresh connector not ready: {error}")))?;
    clients.insert(index, fresh);
    let body = b"fresh-session".to_vec();
    let response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        body.clone(),
    )
    .await?;
    assert_echo(
        &response,
        &profiles[index].canary,
        &body,
        "fresh session echo",
    )?;
    evidence.echo_requests += 1;
    let _ = device_addr;
    Ok(())
}

async fn verify_cli_smoke(
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    device_addr: std::net::SocketAddr,
    profiles: &[DeviceProfile],
    clients: &mut Vec<ConnectionHandle>,
    evidence: &mut Evidence,
) -> Result<()> {
    let profile = profiles.last().ok_or_else(|| {
        HarnessError::InvalidInput("no generated profile for CLI smoke".to_owned())
    })?;
    let device =
        harness.topology.devices_b.last().ok_or_else(|| {
            HarnessError::InvalidInput("tenant B has no CLI smoke device".to_owned())
        })?;
    let service = service_id(harness, device.id)?;
    let path = format!("/v1/devices/{}/services/{service}/echo", device.id);
    let token = harness.oidc.issue(&harness.topology.consumers_b[0].name)?;

    // Free the designated fixture device so the process smoke owns the real
    // certificate-bound control/data pair for the duration of this check.
    let designated = clients.pop().ok_or_else(|| {
        HarnessError::InvalidInput("CLI smoke has no designated device client".to_owned())
    })?;
    designated.stop().await.map_err(|error| {
        HarnessError::Process(format!("stopping CLI designated client: {error}"))
    })?;
    evidence.disconnects += 1;

    let binary = client_binary_path()?;
    let mut process = crate::ManagedProcess::spawn(
        "m1-cli-connect-smoke",
        crate::ProcessSpec::new(binary)
            .arg("connect")
            .arg("--config")
            .arg(profile.config_path.to_string_lossy().to_string())
            .arg("--json"),
    )
    .await?;

    let live_result = drive_cli_process(
        &mut process,
        harness,
        consumer_addr,
        &path,
        &token,
        &profile.canary,
        evidence,
    )
    .await;

    // Stop the live CLI the way a service manager does: SIGTERM (M6-C23).
    // Before M6-C23 nothing handled SIGTERM and this smoke could only
    // force-kill the process after a five-second grace. Now it must take the
    // orderly path -- exit 0, a `stopped` event naming the signal, promptly
    // -- and the relay checks below then observe an orderly release rather
    // than a dead socket. `shutdown` stays the bounded fallback: if the
    // signal were ignored it force-kills, and the status check reports it.
    let stop_result = match live_result {
        Ok(()) => stop_cli_with_sigterm(process).await,
        Err(error) => {
            let _ = process.shutdown(Duration::from_secs(5)).await;
            Err(error)
        }
    };
    stop_result?;
    let stopped_at = Instant::now();
    loop {
        let response = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            &token,
            "POST",
            &path,
            b"after-cli-stop".to_vec(),
        )
        .await?;
        if response.status == hyper::StatusCode::SERVICE_UNAVAILABLE {
            break;
        }
        if stopped_at.elapsed() > Duration::from_secs(5) {
            return Err(HarnessError::Timeout(
                "CLI process shutdown did not clean up its device session".to_owned(),
            ));
        }
        sleep(Duration::from_millis(100)).await;
    }

    let mut fresh = None;
    let retry_started = Instant::now();
    while retry_started.elapsed() < Duration::from_secs(10) {
        match tunnel_client::connect(m1_options(profile.config.clone())).await {
            Ok(mut candidate) => match timeout(REQUEST_TIMEOUT, candidate.wait_ready()).await {
                Ok(Ok(_)) => {
                    fresh = Some(candidate);
                    break;
                }
                Ok(Err(_)) | Err(_) => {
                    let _ = candidate.stop().await;
                }
            },
            Err(_) => sleep(Duration::from_millis(200)).await,
        }
    }
    let fresh = fresh.ok_or_else(|| {
        HarnessError::Timeout("fresh library client could not claim CLI device".to_owned())
    })?;
    clients.push(fresh);
    let body = b"cli-fresh".to_vec();
    let response = consumer_request(
        consumer_addr,
        &harness.pki.server_ca.certificate_der,
        &token,
        "POST",
        &path,
        body.clone(),
    )
    .await?;
    assert_echo(
        &response,
        &profile.canary,
        &body,
        "fresh library session after CLI process",
    )?;
    evidence.echo_requests += 1;
    let _ = device_addr;
    Ok(())
}

/// Bound on the CLI's orderly stop after SIGTERM. Measured in tens of
/// milliseconds; well under the five-second grace after which `shutdown`
/// force-kills, so a signal that was ignored cannot pass as a slow stop.
const CLI_SIGTERM_STOP_BOUND: Duration = Duration::from_secs(3);

async fn stop_cli_with_sigterm(process: crate::ManagedProcess) -> Result<()> {
    let pid = process.id().ok_or_else(|| {
        HarnessError::Process("tunnel-client exited before its SIGTERM stop".to_owned())
    })?;
    let signalled = Instant::now();
    let kill = std::process::Command::new("/bin/kill")
        .arg("-TERM")
        .arg(pid.to_string())
        .status()
        .map_err(|error| HarnessError::Process(format!("sending SIGTERM: {error}")))?;
    if !kill.success() {
        return Err(HarnessError::Process(format!(
            "sending SIGTERM returned {kill}"
        )));
    }
    let mut process = process;
    let status = loop {
        if let Some(status) = process.try_wait()? {
            break Some(status);
        }
        if signalled.elapsed() > CLI_SIGTERM_STOP_BOUND {
            break None;
        }
        sleep(Duration::from_millis(10)).await;
    };
    let elapsed = signalled.elapsed();
    // The `stopped` event is the last line the CLI prints; poll briefly
    // because the pipe drain can trail the exit.
    let mut stdout = String::new();
    for _ in 0..100 {
        stdout = String::from_utf8_lossy(&process.stdout()).into_owned();
        if stdout.contains(r#""state":"stopped""#) {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    let reaped = process
        .shutdown(Duration::from_secs(5))
        .await
        .map_err(|error| HarnessError::Process(format!("reaping CLI smoke process: {error}")))?;
    let Some(status) = status else {
        return Err(HarnessError::Timeout(format!(
            "tunnel-client did not stop within {CLI_SIGTERM_STOP_BOUND:?} of SIGTERM; forced stop status {reaped}"
        )));
    };
    if !status.success() {
        return Err(HarnessError::Process(format!(
            "tunnel-client SIGTERM stop exited {status}, not the orderly 0"
        )));
    }
    let stopped = stdout
        .lines()
        .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
        .any(|event| {
            event["command"] == "connect"
                && event["result"]["state"] == "stopped"
                && event["result"]["signal"] == "SIGTERM"
        });
    if !stopped {
        return Err(HarnessError::Process(
            "tunnel-client SIGTERM stop printed no `stopped` event naming SIGTERM".to_owned(),
        ));
    }
    eprintln!(
        "M1 CLI smoke: SIGTERM orderly stop exit 0 after {} ms",
        elapsed.as_millis()
    );
    Ok(())
}

async fn drive_cli_process(
    process: &mut crate::ManagedProcess,
    harness: &RunningHarness,
    consumer_addr: std::net::SocketAddr,
    path: &str,
    token: &str,
    canary: &str,
    evidence: &mut Evidence,
) -> Result<()> {
    let body = b"cli-live".to_vec();
    let started = Instant::now();
    while started.elapsed() < Duration::from_secs(20) {
        if let Some(status) = process.try_wait()? {
            return Err(HarnessError::Process(format!(
                "tunnel-client connect exited before live readiness with {status}"
            )));
        }
        if let Ok(response) = consumer_request(
            consumer_addr,
            &harness.pki.server_ca.certificate_der,
            token,
            "POST",
            path,
            body.clone(),
        )
        .await
            && response.status == hyper::StatusCode::OK
        {
            assert_echo(&response, canary, &body, "CLI live echo")?;
            evidence.cli_echoes += 1;
            return Ok(());
        }
        sleep(Duration::from_millis(200)).await;
    }
    Err(HarnessError::Timeout(
        "tunnel-client connect did not become live within 20 seconds".to_owned(),
    ))
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
                "built tunnel-client binary is missing next to the test executable".to_owned(),
            )
        })
}

async fn stop_clients(clients: &mut Vec<ConnectionHandle>) -> Result<()> {
    let mut first_error = None;
    while let Some(client) = clients.pop() {
        match timeout(Duration::from_secs(5), client.stop()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                first_error.get_or_insert(HarnessError::Process(format!(
                    "stopping device connector: {error}"
                )));
            }
            Err(_) => {
                first_error.get_or_insert(HarnessError::Timeout(
                    "device connector shutdown exceeded five seconds".to_owned(),
                ));
            }
        }
    }
    first_error.map_or(Ok(()), Err)
}

fn service_id(harness: &RunningHarness, device_id: Uuid) -> Result<Uuid> {
    harness
        .topology
        .service_ids
        .get(&device_id)
        .copied()
        .ok_or_else(|| HarnessError::InvalidInput(format!("device {device_id} has no service id")))
}

fn parse_listing(response: &HttpResponse) -> Result<Vec<DeviceSummary>> {
    serde_json::from_slice(&response.body)
        .map_err(|error| HarnessError::Http(format!("decoding device listing: {error}")))
}

fn assert_echo(response: &HttpResponse, canary: &str, body: &[u8], name: &str) -> Result<()> {
    assert_status(response, hyper::StatusCode::OK, name)?;
    let mut expected = canary.as_bytes().to_vec();
    expected.extend_from_slice(body);
    assert_named(response.body == expected, name)
}

fn assert_status(response: &HttpResponse, expected: hyper::StatusCode, name: &str) -> Result<()> {
    assert_named(
        response.status == expected,
        &format!("{name}: expected {expected}, got {}", response.status),
    )
}

fn assert_named(condition: bool, name: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(HarnessError::Http(format!(
            "acceptance assertion failed: {name}"
        )))
    }
}

#[cfg(test)]
mod c17_validator_tests {
    use super::{HttpResponse, assert_echo, assert_named, assert_status};
    use crate::acceptance_test_support::assert_rejected;

    fn echo_response(canary: &str, body: &[u8]) -> HttpResponse {
        let mut bytes = canary.as_bytes().to_vec();
        bytes.extend_from_slice(body);
        HttpResponse {
            status: hyper::StatusCode::OK,
            body: bytes,
        }
    }

    #[test]
    fn m1_named_assertions_accept_matching_observations() {
        assert_named(true, "gate").expect("true condition passes");
        let response = echo_response("canary-", b"fixture-secret-token");
        assert_status(&response, hyper::StatusCode::OK, "status").expect("matching status passes");
        assert_echo(&response, "canary-", b"fixture-secret-token", "echo")
            .expect("matching echo passes");
    }

    #[test]
    fn m1_named_assertions_reach_the_shared_exit_path_without_echoing_bodies() {
        assert_rejected(assert_named(false, "named-gate"), "named-gate");
        let response = echo_response("canary-", b"fixture-secret-token");
        assert_rejected(
            assert_status(&response, hyper::StatusCode::FORBIDDEN, "status-gate"),
            "status-gate: expected 403",
        );
        assert_rejected(
            assert_echo(
                &response,
                "other-canary-",
                b"fixture-secret-token",
                "echo-gate",
            ),
            "echo-gate",
        );
        let mut wrong_status = echo_response("canary-", b"fixture-secret-token");
        wrong_status.status = hyper::StatusCode::SERVICE_UNAVAILABLE;
        assert_rejected(
            assert_echo(
                &wrong_status,
                "canary-",
                b"fixture-secret-token",
                "echo-status-gate",
            ),
            "echo-status-gate",
        );
    }
}
