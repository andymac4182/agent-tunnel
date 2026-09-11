//! Real-socket private HTTP/3 mutual-TLS proof for M1.
//!
//! This module exercises the production `tunnel-transport` QUIC/H3 helpers
//! with an ephemeral fixture PKI.  It deliberately stops at one bounded body
//! exchange; Redis approval distribution, relay routing, stream ownership,
//! and recovery remain M7 responsibilities.

use std::{net::SocketAddr, time::Duration};

use tokio_util::sync::CancellationToken;
use tunnel_transport::{
    ApprovedPeerPins, PeerProbeLimits, PeerProbeResponse, load_peer_client_config_from_pem,
    load_peer_server_config_from_pem, peer_probe, serve_peer_probe, spki_sha256_from_der,
};
use uuid::Uuid;

use crate::{CertificateMaterial, CertificateProfile, HarnessError, Result, RunningHarness};

/// Run the bounded, bidirectional HTTP/3 peer proof against ephemeral
/// localhost sockets.
///
/// The successful case verifies mutual TLS, peer-role SAN parsing, the
/// separately approved server/client SPKI pins, and request/response body
/// exchange.  Negative cases prove that wrong pins, a wrong trust root, and a
/// device-role leaf cannot use the peer route.  The final cases exercise the
/// body-size and handshake deadline limits before returning.
pub async fn verify(harness: &RunningHarness) -> Result<()> {
    let tenant_id = Uuid::new_v4();
    let server = issue_peer_with_localhost(harness, "m1-peer-server")?;
    let client = issue_peer_with_localhost(harness, "m1-peer-client")?;
    let server_chain = chain(&server, &harness.pki.peer_ca.certificate_pem);
    let client_chain = chain(&client, &harness.pki.peer_ca.certificate_pem);
    let server_pin = spki_sha256_from_der(&server.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("peer server SPKI: {error}")))?;
    let client_pin = spki_sha256_from_der(&client.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("peer client SPKI: {error}")))?;
    let approved_server_pin = pins([server_pin])?;
    let approved_client_pin = pins([client_pin])?;
    let body = b"m1-private-peer-body\0\xff".to_vec();

    let success = run_case(ProbeCase {
        server_chain: &server_chain,
        server_key: &server.private_key_pem,
        server_client_ca: &harness.pki.peer_ca.certificate_pem,
        client_chain: &client_chain,
        client_key: &client.private_key_pem,
        client_server_ca: &harness.pki.peer_ca.certificate_pem,
        server_pins: approved_client_pin.clone(),
        client_pins: approved_server_pin.clone(),
        body: body.clone(),
        limits: PeerProbeLimits::default(),
    })
    .await?;
    assert_echo(success, &body, "approved peer probe")?;

    let wrong_pin = pins([tunnel_transport::SpkiSha256::from_bytes([0xa5; 32])])?;
    let wrong_pin_result = run_case(ProbeCase {
        server_chain: &server_chain,
        server_key: &server.private_key_pem,
        server_client_ca: &harness.pki.peer_ca.certificate_pem,
        client_chain: &client_chain,
        client_key: &client.private_key_pem,
        client_server_ca: &harness.pki.peer_ca.certificate_pem,
        server_pins: approved_client_pin.clone(),
        client_pins: wrong_pin,
        body: body.clone(),
        limits: PeerProbeLimits::default(),
    })
    .await;
    expect_rejected(wrong_pin_result, "unapproved server SPKI pin")?;

    let wrong_ca_result = run_case(ProbeCase {
        server_chain: &server_chain,
        server_key: &server.private_key_pem,
        server_client_ca: &harness.pki.peer_ca.certificate_pem,
        client_chain: &client_chain,
        client_key: &client.private_key_pem,
        client_server_ca: &harness.pki.device_ca.certificate_pem,
        server_pins: approved_client_pin.clone(),
        client_pins: approved_server_pin.clone(),
        body: body.clone(),
        limits: PeerProbeLimits::default(),
    })
    .await;
    expect_rejected(wrong_ca_result, "wrong peer server trust root")?;

    // A device leaf is signed by a deliberately trusted CA in this isolated
    // case, so the failure proves the role gate rather than only CA rejection.
    let device = harness.pki.issue_device(tenant_id, Uuid::new_v4())?;
    let device_chain = chain(&device, &harness.pki.device_ca.certificate_pem);
    let device_pin = spki_sha256_from_der(&device.certificate_der)
        .map_err(|error| HarnessError::Pki(format!("device SPKI: {error}")))?;
    let wrong_role_server = load_peer_server_config_from_pem(
        server_chain.as_bytes(),
        server.private_key_pem.as_bytes(),
        harness.pki.device_ca.certificate_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building role-gate server TLS: {error}")))?;
    let wrong_role_client = load_peer_client_config_from_pem(
        device_chain.as_bytes(),
        device.private_key_pem.as_bytes(),
        harness.pki.peer_ca.certificate_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building role-gate client TLS: {error}")))?;
    let wrong_role_result = run_endpoint_case(
        wrong_role_server,
        wrong_role_client,
        pins([device_pin])?,
        approved_server_pin.clone(),
        body.clone(),
        PeerProbeLimits::default(),
    )
    .await;
    expect_rejected(wrong_role_result, "device role on peer route")?;

    let bounded_result = run_case(ProbeCase {
        server_chain: &server_chain,
        server_key: &server.private_key_pem,
        server_client_ca: &harness.pki.peer_ca.certificate_pem,
        client_chain: &client_chain,
        client_key: &client.private_key_pem,
        client_server_ca: &harness.pki.peer_ca.certificate_pem,
        server_pins: approved_client_pin.clone(),
        client_pins: approved_server_pin.clone(),
        body: b"too-large".to_vec(),
        limits: PeerProbeLimits::new(4, Duration::from_secs(2), 1)
            .map_err(|error| HarnessError::Http(format!("building body limit: {error}")))?,
    })
    .await;
    expect_rejected(bounded_result, "peer body limit")?;

    let deadline_result = run_case(ProbeCase {
        server_chain: &server_chain,
        server_key: &server.private_key_pem,
        server_client_ca: &harness.pki.peer_ca.certificate_pem,
        client_chain: &client_chain,
        client_key: &client.private_key_pem,
        client_server_ca: &harness.pki.peer_ca.certificate_pem,
        server_pins: approved_client_pin,
        client_pins: approved_server_pin,
        body,
        limits: PeerProbeLimits::new(64 * 1024, Duration::from_nanos(1), 1)
            .map_err(|error| HarnessError::Http(format!("building deadline: {error}")))?,
    })
    .await;
    expect_rejected(deadline_result, "peer handshake/body deadline")?;
    Ok(())
}

struct ProbeCase<'a> {
    server_chain: &'a str,
    server_key: &'a str,
    server_client_ca: &'a str,
    client_chain: &'a str,
    client_key: &'a str,
    client_server_ca: &'a str,
    server_pins: ApprovedPeerPins,
    client_pins: ApprovedPeerPins,
    body: Vec<u8>,
    limits: PeerProbeLimits,
}

async fn run_case(case: ProbeCase<'_>) -> Result<PeerProbeResponse> {
    let server_config = load_peer_server_config_from_pem(
        case.server_chain.as_bytes(),
        case.server_key.as_bytes(),
        case.server_client_ca.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building peer server TLS: {error}")))?;
    let client_config = load_peer_client_config_from_pem(
        case.client_chain.as_bytes(),
        case.client_key.as_bytes(),
        case.client_server_ca.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building peer client TLS: {error}")))?;
    run_endpoint_case(
        server_config,
        client_config,
        case.server_pins,
        case.client_pins,
        case.body,
        case.limits,
    )
    .await
}

async fn run_endpoint_case(
    server_config: quinn::ServerConfig,
    client_config: quinn::ClientConfig,
    server_pins: ApprovedPeerPins,
    client_pins: ApprovedPeerPins,
    body: Vec<u8>,
    limits: PeerProbeLimits,
) -> Result<PeerProbeResponse> {
    let server_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| HarnessError::Http(format!("binding peer H3 server: {error}")))?;
    let address = server_endpoint
        .local_addr()
        .map_err(|error| HarnessError::Http(format!("reading peer H3 server address: {error}")))?;
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(serve_peer_probe(
        server_endpoint,
        server_pins,
        limits.clone(),
        cancel.clone(),
    ));

    let result = async {
        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|error| HarnessError::Http(format!("binding peer H3 client: {error}")))?;
        client_endpoint.set_default_client_config(client_config);
        let response = peer_probe(
            &client_endpoint,
            address,
            "localhost",
            body.into(),
            limits,
            &client_pins,
        )
        .await
        .map_err(|error| HarnessError::Http(format!("peer H3 probe: {error}")))?;
        client_endpoint.close(quinn::VarInt::from_u32(0), b"peer probe complete");
        Ok::<_, HarnessError>(response)
    }
    .await;

    cancel.cancel();
    match server_task.await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            return Err(HarnessError::Http(format!("peer H3 server: {error}")));
        }
        Err(error) => {
            return Err(HarnessError::Http(format!("peer H3 server task: {error}")));
        }
    }
    result
}

fn issue_peer_with_localhost(
    harness: &RunningHarness,
    node_id: &str,
) -> Result<CertificateMaterial> {
    let mut profile = CertificateProfile::peer(node_id);
    profile.dns_names.push("localhost".to_owned());
    harness.pki.issue(profile)
}

fn chain(leaf: &CertificateMaterial, ca_pem: &str) -> String {
    format!("{}{}", leaf.certificate_pem, ca_pem)
}

fn pins<I>(pins: I) -> Result<ApprovedPeerPins>
where
    I: IntoIterator<Item = tunnel_transport::SpkiSha256>,
{
    ApprovedPeerPins::new(pins)
        .map_err(|error| HarnessError::Http(format!("building approved peer pins: {error}")))
}

fn assert_echo(response: PeerProbeResponse, expected: &[u8], label: &str) -> Result<()> {
    if response.status.as_u16() != 200 || response.body.as_ref() != expected {
        return Err(HarnessError::Http(format!(
            "{label} returned status {} and {} body bytes",
            response.status,
            response.body.len()
        )));
    }
    Ok(())
}

fn expect_rejected<T>(result: Result<T>, label: &str) -> Result<()> {
    if result.is_ok() {
        return Err(HarnessError::Http(format!(
            "{label} unexpectedly succeeded"
        )));
    }
    Ok(())
}
