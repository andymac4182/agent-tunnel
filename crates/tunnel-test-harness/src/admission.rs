//! Real-socket M1 device admission checks.
//!
//! These checks deliberately use the production relay listeners, rustls, and
//! the canonical tunnel-protocol codec.  The harness creates a small set of
//! extra catalog devices for this module so a concurrently running routing
//! scenario cannot have its control owner or data socket replaced by an
//! adversarial probe.

use crate::{
    CertificateMaterial, FixturePki, FixtureTopology, HarnessError, Result, RunningHarness,
};
use chrono::{DateTime, Utc};
use futures_util::{SinkExt, StreamExt};
use rustls::{ClientConfig, RootCertStore, pki_types::CertificateDer};
use std::{io::ErrorKind, net::SocketAddr, sync::Arc, time::Duration};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::{
    Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
    tungstenite::{Message, client::IntoClientRequest, http::HeaderValue},
};
use tunnel_catalog::{Catalog, CatalogFixture, CredentialRecord, FixtureDevice, RedisCatalog};
use tunnel_protocol::{
    ControlMessage, DataReady, Frame, Hello, ServiceAdvertisement, Welcome, decode_control,
    encode_control,
};
use uuid::Uuid;

const CONTROL_SUBPROTOCOL: &str = "agent-tunnel.control.v1";
const DATA_SUBPROTOCOL: &str = "agent-tunnel.data.v1";
const PROTOCOL_MAJOR: u16 = 1;
const PROTOCOL_MINOR: u16 = 0;
const TICKET_TTL: Duration = Duration::from_secs(10);
const OPERATION_DEADLINE: Duration = Duration::from_secs(4);
const QUIET_SOCKET_WINDOW: Duration = Duration::from_millis(250);
const ADMISSION_DEVICE_COUNT: usize = 6;

type DeviceSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;
type HandshakeResponse = tokio_tungstenite::tungstenite::http::Response<Option<Vec<u8>>>;
type ConnectResult = std::result::Result<(DeviceSocket, HandshakeResponse), ConnectFailure>;

/// Run the M1 device TLS/WebSocket admission matrix against the production
/// relay.
///
/// The consumer address is accepted as part of the common harness contract;
/// this module only needs the device listener because admission happens before
/// a consumer operation is dispatched.  The address is still validated so a
/// caller cannot accidentally pass an unstarted relay to this gate.
pub async fn verify(
    harness: &RunningHarness,
    consumer_addr: SocketAddr,
    device_addr: SocketAddr,
) -> Result<()> {
    if consumer_addr.port() == 0 || device_addr.port() == 0 {
        return Err(HarnessError::InvalidInput(
            "admission checks require bound consumer and device listeners".to_owned(),
        ));
    }

    let devices = harness.admission_devices.clone();
    if devices.len() != ADMISSION_DEVICE_COUNT {
        return Err(HarnessError::InvalidInput(format!(
            "harness prepared {} admission devices; expected {ADMISSION_DEVICE_COUNT}",
            devices.len()
        )));
    }
    verify_positive_control(harness, device_addr, &devices[5]).await?;

    // TLS failures happen before an HTTP upgrade.  Each assertion checks that
    // the error is an authentication/handshake failure, rather than accepting
    // an arbitrary connection error as evidence of a denial.
    verify_missing_client_certificate(harness, device_addr).await?;
    verify_wrong_ca(harness, device_addr).await?;
    verify_wrong_role(harness, device_addr).await?;
    verify_expired_certificate(harness, device_addr).await?;

    // These certificates pass TLS and are rejected only after the production
    // relay has extracted the peer identity and consulted its catalog.
    verify_unmapped_certificate(harness, device_addr).await?;
    revoke_credential(harness, &devices[3]).await?;
    verify_revoked_certificate(harness, device_addr, &devices[3]).await?;

    verify_wrong_subprotocol(harness, device_addr, &devices[0]).await?;
    verify_forged_hello(harness, device_addr, &devices[1], devices[0].id).await?;
    verify_stolen_ticket(harness, device_addr, &devices[0]).await?;
    verify_ticket_reuse_and_duplicate_bound(harness, device_addr, &devices[1]).await?;
    verify_ticket_expiry(harness, device_addr, &devices[2]).await?;
    verify_stale_epoch(harness, device_addr, &devices[4]).await?;

    Ok(())
}

async fn verify_positive_control(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let session = open_control(harness, device_addr, device).await?;
    close_socket(session.socket).await;
    Ok(())
}

#[derive(Clone, Debug)]
pub(crate) struct AdmissionDevice {
    id: Uuid,
    certificate: CertificateMaterial,
}

struct ControlSession {
    socket: DeviceSocket,
    welcome: Welcome,
}

#[derive(Debug)]
enum ConnectFailure {
    Timeout,
    HttpStatus(u16),
    Tls(String),
    Closed(String),
    Other(String),
}

impl std::fmt::Display for ConnectFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Timeout => formatter.write_str("WebSocket handshake deadline elapsed"),
            Self::HttpStatus(status) => write!(formatter, "HTTP upgrade returned status {status}"),
            Self::Tls(message) | Self::Closed(message) | Self::Other(message) => {
                formatter.write_str(message)
            }
        }
    }
}

/// Prepare dedicated device credentials before the harness performs its one
/// authoritative catalog seed.  This function only appends new device and
/// credential records; existing tenant, owner, membership, grant, and service
/// records remain the responsibility of the caller's fixture.
pub(crate) fn prepare_admission_devices(
    pki: &FixturePki,
    topology: &FixtureTopology,
    fixture: &mut CatalogFixture,
) -> Result<Vec<AdmissionDevice>> {
    let tenant = &topology.tenant_a;
    let owner = &topology.owner_a;
    let mut devices = Vec::with_capacity(ADMISSION_DEVICE_COUNT);
    for index in 0..ADMISSION_DEVICE_COUNT {
        let id = Uuid::new_v4();
        let certificate = pki.issue_device(tenant.id, id)?;
        fixture.devices.push(FixtureDevice {
            tenant_id: tenant.id,
            device_id: id,
            owner_user_id: owner.id,
            display_name: format!("m1-admission-{index}"),
            active: true,
            last_seen_at: None,
        });
        fixture.credentials.push(CredentialRecord {
            tenant_id: tenant.id,
            device_id: id,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: certificate.spki_fingerprint_sha256()?,
            serial: None,
            not_before: as_chrono(certificate.not_before)?,
            expires_at: as_chrono(certificate.not_after)?,
            revoked_at: None,
            active: true,
        });
        devices.push(AdmissionDevice { id, certificate });
    }
    Ok(devices)
}

fn as_chrono(value: time::OffsetDateTime) -> Result<DateTime<Utc>> {
    DateTime::from_timestamp(value.unix_timestamp(), value.nanosecond()).ok_or_else(|| {
        HarnessError::InvalidInput("certificate validity is outside chrono range".to_owned())
    })
}

async fn verify_missing_client_certificate(
    harness: &RunningHarness,
    device_addr: SocketAddr,
) -> Result<()> {
    let tls = server_only_tls(harness)?;
    let result = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await;
    match result {
        Err(ConnectFailure::Timeout) => Err(HarnessError::Timeout(
            "missing client certificate handshake timed out; expected an immediate TLS alert"
                .to_owned(),
        )),
        result => assert_tls_rejection("missing client certificate", result),
    }
}

async fn verify_wrong_ca(harness: &RunningHarness, device_addr: SocketAddr) -> Result<()> {
    let other_pki = crate::FixturePki::new()?;
    let id = Uuid::new_v4();
    let certificate = other_pki.issue_device(harness.topology.tenant_a.id, id)?;
    let tls = client_tls(&certificate, &harness.pki.server_ca.certificate_pem)?;
    let result = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await;
    assert_tls_rejection("wrong device CA", result)
}

async fn verify_wrong_role(harness: &RunningHarness, device_addr: SocketAddr) -> Result<()> {
    let certificate = harness
        .pki
        .issue_wrong_role_device(harness.topology.tenant_a.id, Uuid::new_v4())?;
    let tls = client_tls(&certificate, &harness.pki.server_ca.certificate_pem)?;
    let result = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await;
    match result {
        Ok((mut socket, _)) => {
            send_hello(&mut socket, Uuid::new_v4(), Uuid::new_v4()).await?;
            assert_control_registration_denied("peer-role device certificate", socket).await
        }
        Err(ConnectFailure::HttpStatus(status)) => Err(HarnessError::Http(format!(
            "peer-role device certificate reached HTTP with status {status}"
        ))),
        Err(ConnectFailure::Timeout) => Err(HarnessError::Timeout(
            "peer-role device certificate handshake timed out; expected an immediate TLS alert"
                .to_owned(),
        )),
        Err(ConnectFailure::Tls(_)) | Err(ConnectFailure::Closed(_)) => Ok(()),
        Err(ConnectFailure::Other(detail)) => Err(HarnessError::Http(format!(
            "peer-role device certificate failed for an unrelated reason: {detail}"
        ))),
    }
}

async fn verify_expired_certificate(
    harness: &RunningHarness,
    device_addr: SocketAddr,
) -> Result<()> {
    let certificate = harness
        .pki
        .issue_expired_device(harness.topology.tenant_a.id, Uuid::new_v4())?;
    let tls = client_tls(&certificate, &harness.pki.server_ca.certificate_pem)?;
    let result = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await;
    assert_tls_rejection("expired device certificate", result)
}

async fn verify_unmapped_certificate(
    harness: &RunningHarness,
    device_addr: SocketAddr,
) -> Result<()> {
    let certificate = harness
        .pki
        .issue_device(harness.topology.tenant_a.id, Uuid::new_v4())?;
    let tls = client_tls(&certificate, &harness.pki.server_ca.certificate_pem)?;
    let (mut socket, _) = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "unmapped certificate did not reach admission: {error}"
        ))
    })?;
    send_hello(&mut socket, Uuid::new_v4(), Uuid::new_v4()).await?;
    assert_control_registration_denied("unmapped certificate", socket).await
}

async fn revoke_credential(harness: &RunningHarness, device: &AdmissionDevice) -> Result<()> {
    let fingerprint = device.certificate.spki_fingerprint_sha256()?;
    let catalog = RedisCatalog::connect(harness.redis.redis_url(), harness.redis.namespace())
        .await
        .map_err(|error| HarnessError::Redis(format!("connecting admission catalog: {error}")))?;
    let credential = catalog
        .resolve_credential(&fingerprint, Utc::now())
        .await
        .map_err(|error| HarnessError::Redis(format!("resolving admission credential: {error}")))?
        .ok_or_else(|| {
            HarnessError::Redis(
                "revocation fixture credential was not present in the Redis catalog".to_owned(),
            )
        })?;
    catalog
        .revoke_credential(
            credential.tenant_id,
            credential.device_id,
            credential.credential_id,
            Utc::now(),
        )
        .await
        .map_err(|error| HarnessError::Redis(format!("revoking admission credential: {error}")))?;
    Ok(())
}

async fn verify_revoked_certificate(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let tls = client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?;
    let (mut socket, _) = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "revoked certificate did not reach admission: {error}"
        ))
    })?;
    send_hello(&mut socket, device.id, device.id).await?;
    assert_control_registration_denied("revoked certificate", socket).await
}

async fn verify_wrong_subprotocol(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let tls = client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?;
    match connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some("agent-tunnel.invalid.v1"),
        None,
    )
    .await
    {
        Err(ConnectFailure::HttpStatus(426)) => Ok(()),
        Err(error) => Err(HarnessError::Http(format!(
            "wrong subprotocol was rejected with {error}, expected HTTP 426"
        ))),
        Ok(_) => Err(HarnessError::Http(
            "wrong subprotocol unexpectedly upgraded".to_owned(),
        )),
    }
}

async fn verify_forged_hello(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
    claimed_id: Uuid,
) -> Result<()> {
    let tls = client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?;
    let (mut socket, _) = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!("forged HELLO did not reach admission: {error}"))
    })?;
    send_hello(&mut socket, device.id, claimed_id).await?;
    assert_control_registration_denied("forged HELLO connector identity", socket).await
}

async fn verify_stolen_ticket(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let mut owner = open_control(harness, device_addr, device).await?;
    let thief = harness.topology.devices_b.first().ok_or_else(|| {
        HarnessError::InvalidInput("fixture has no enrolled thief device".to_owned())
    })?;
    let thief_tls = client_tls(&thief.certificate, &harness.pki.server_ca.certificate_pem)?;
    let stolen = connect_socket(
        device_addr,
        "/v1/tunnel/data",
        thief_tls,
        Some(DATA_SUBPROTOCOL),
        Some(&owner.welcome.attachment_ticket),
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "stolen ticket did not reach data admission: {error}"
        ))
    })?;
    assert_data_attachment_denied("ticket used with another enrolled certificate", stolen.0)
        .await?;
    assert_no_data_ready(&mut owner.socket).await?;
    close_socket(owner.socket).await;
    Ok(())
}

async fn verify_ticket_reuse_and_duplicate_bound(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let mut owner = open_control(harness, device_addr, device).await?;
    let mut data = open_data(
        harness,
        device_addr,
        device,
        &owner.welcome.attachment_ticket,
    )
    .await?;
    let ready = receive_data_ready(&mut owner.socket).await?;
    validate_data_ready(&ready, &owner.welcome)?;

    let duplicate = connect_socket(
        device_addr,
        "/v1/tunnel/data",
        client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?,
        Some(DATA_SUBPROTOCOL),
        Some(&owner.welcome.attachment_ticket),
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "duplicate data socket did not reach admission: {error}"
        ))
    })?;
    assert_data_attachment_denied("reused attachment ticket", duplicate.0).await?;

    // A failed duplicate must not replace or close the admitted data socket.
    assert_socket_quiet("active data socket after duplicate", &mut data).await?;
    close_socket(data).await;
    close_socket(owner.socket).await;
    Ok(())
}

async fn verify_ticket_expiry(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let mut owner = open_control(harness, device_addr, device).await?;
    sleep(TICKET_TTL + Duration::from_secs(2)).await;
    let expired = connect_socket(
        device_addr,
        "/v1/tunnel/data",
        client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?,
        Some(DATA_SUBPROTOCOL),
        Some(&owner.welcome.attachment_ticket),
    )
    .await
    .map_err(|error| {
        HarnessError::Http(format!(
            "expired ticket did not reach data admission: {error}"
        ))
    })?;
    assert_data_attachment_denied("expired attachment ticket", expired.0).await?;
    assert_no_data_ready(&mut owner.socket).await?;
    close_socket(owner.socket).await;
    Ok(())
}

async fn verify_stale_epoch(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<()> {
    let mut owner = open_control(harness, device_addr, device).await?;
    let mut data = open_data(
        harness,
        device_addr,
        device,
        &owner.welcome.attachment_ticket,
    )
    .await?;
    let ready = receive_data_ready(&mut owner.socket).await?;
    validate_data_ready(&ready, &owner.welcome)?;
    let stale_epoch = owner.welcome.epoch.saturating_add(1);
    let frame = Frame::data(stale_epoch, owner.welcome.generation, 1, 1, 0, vec![0xA5])
        .encode()
        .map_err(|error| HarnessError::Http(format!("encoding stale epoch probe: {error}")))?;
    data.send(Message::Binary(frame.into()))
        .await
        .map_err(|error| HarnessError::Http(format!("sending stale epoch probe: {error}")))?;
    assert_control_closed("stale data epoch", owner.socket).await?;
    close_socket(data).await;
    Ok(())
}

async fn open_control(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
) -> Result<ControlSession> {
    let tls = client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?;
    let (mut socket, _) = connect_socket(
        device_addr,
        "/v1/tunnel/control",
        tls,
        Some(CONTROL_SUBPROTOCOL),
        None,
    )
    .await
    .map_err(|error| HarnessError::Http(format!("valid control admission failed: {error}")))?;
    send_hello(&mut socket, device.id, device.id).await?;
    let welcome = receive_welcome(&mut socket).await?;
    validate_welcome(&welcome)?;
    Ok(ControlSession { socket, welcome })
}

async fn open_data(
    harness: &RunningHarness,
    device_addr: SocketAddr,
    device: &AdmissionDevice,
    ticket: &str,
) -> Result<DeviceSocket> {
    connect_socket(
        device_addr,
        "/v1/tunnel/data",
        client_tls(&device.certificate, &harness.pki.server_ca.certificate_pem)?,
        Some(DATA_SUBPROTOCOL),
        Some(ticket),
    )
    .await
    .map(|(socket, _)| socket)
    .map_err(|error| HarnessError::Http(format!("valid data admission failed: {error}")))
}

async fn send_hello(
    socket: &mut DeviceSocket,
    certificate_id: Uuid,
    claimed_id: Uuid,
) -> Result<()> {
    let mut hello = Hello::new(
        Uuid::new_v4().to_string(),
        claimed_id.to_string(),
        PROTOCOL_MAJOR,
        PROTOCOL_MINOR,
    );
    hello.features = vec![
        "m1-control-data".to_owned(),
        "authorization-challenge".to_owned(),
        "echo".to_owned(),
    ];
    hello.services = vec![ServiceAdvertisement::new(
        certificate_id.to_string(),
        "echo",
        "1",
        ["echo", "data", "fin", "ack"],
    )];
    send_control(socket, &ControlMessage::Hello(hello)).await
}

async fn send_control(socket: &mut DeviceSocket, message: &ControlMessage) -> Result<()> {
    let encoded = encode_control(message)
        .map_err(|error| HarnessError::Http(format!("encoding control probe: {error}")))?;
    let text = String::from_utf8(encoded)
        .map_err(|error| HarnessError::Http(format!("control probe was not UTF-8: {error}")))?;
    socket
        .send(Message::Text(text.into()))
        .await
        .map_err(|error| HarnessError::Http(format!("sending control probe: {error}")))
}

async fn receive_control(socket: &mut DeviceSocket) -> Result<ControlMessage> {
    let deadline = tokio::time::Instant::now() + OPERATION_DEADLINE;
    loop {
        let item = timeout_at(deadline, socket.next()).await?;
        match item {
            Some(Ok(Message::Text(text))) => {
                return decode_control(text.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("decoding control probe: {error}"))
                });
            }
            Some(Ok(Message::Ping(payload))) => {
                socket.send(Message::Pong(payload)).await.map_err(|error| {
                    HarnessError::Http(format!("sending control pong: {error}"))
                })?;
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
            Some(Ok(Message::Close(_))) | None => {
                return Err(HarnessError::Http(
                    "relay closed control socket before the expected message".to_owned(),
                ));
            }
            Some(Ok(Message::Binary(_))) => {
                return Err(HarnessError::Http(
                    "binary message arrived on control socket".to_owned(),
                ));
            }
            Some(Err(error)) => {
                return Err(HarnessError::Http(format!(
                    "control probe read failed: {error}"
                )));
            }
        }
    }
}

async fn receive_welcome(socket: &mut DeviceSocket) -> Result<Welcome> {
    match receive_control(socket).await? {
        ControlMessage::Welcome(welcome) => Ok(welcome),
        other => Err(HarnessError::Http(format!(
            "expected WELCOME, received {}",
            other.kind_name()
        ))),
    }
}

async fn receive_data_ready(socket: &mut DeviceSocket) -> Result<DataReady> {
    match receive_control(socket).await? {
        ControlMessage::DataReady(ready) => Ok(ready),
        other => Err(HarnessError::Http(format!(
            "expected DATA_READY, received {}",
            other.kind_name()
        ))),
    }
}

fn validate_welcome(welcome: &Welcome) -> Result<()> {
    if welcome.protocol_major != PROTOCOL_MAJOR
        || welcome.protocol_minor != PROTOCOL_MINOR
        || welcome.generation != 1
        || welcome.session_id.is_empty()
        || welcome.connection_id.is_empty()
        || welcome.attachment_ticket.is_empty()
    {
        return Err(HarnessError::Http(
            "WELCOME did not contain the canonical M1 session binding".to_owned(),
        ));
    }
    if welcome.reconnect_credential.is_some()
        || welcome.rotation_interval_ms.is_some()
        || welcome
            .supported_features
            .iter()
            .any(|feature| feature.eq_ignore_ascii_case("resume") || feature.contains("rotate"))
    {
        return Err(HarnessError::Http(
            "WELCOME advertised M2 reconnect or rotation state".to_owned(),
        ));
    }
    Ok(())
}

fn validate_data_ready(ready: &DataReady, welcome: &Welcome) -> Result<()> {
    if ready.session_id != welcome.session_id
        || ready.epoch != welcome.epoch
        || ready.generation != welcome.generation
        || ready.connection_id != welcome.connection_id
        || ready.reply_to != welcome.message_id
    {
        return Err(HarnessError::Http(
            "DATA_READY did not match the WELCOME session binding".to_owned(),
        ));
    }
    Ok(())
}

async fn assert_control_registration_denied(label: &str, mut socket: DeviceSocket) -> Result<()> {
    match timeout(OPERATION_DEADLINE, socket.next()).await {
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => Ok(()),
        Ok(Some(Ok(Message::Text(_)))) => Err(HarnessError::Http(format!(
            "{label} unexpectedly received a control response"
        ))),
        Ok(Some(Ok(Message::Ping(_)))) | Ok(Some(Ok(Message::Pong(_)))) => Err(HarnessError::Http(
            format!("{label} remained admitted after the denial"),
        )),
        Ok(Some(Ok(Message::Binary(_)))) | Ok(Some(Ok(Message::Frame(_)))) => Err(
            HarnessError::Http(format!("{label} returned an invalid control message")),
        ),
        Err(_) => Err(HarnessError::Timeout(format!(
            "{label} was not rejected before the admission deadline"
        ))),
    }
}

async fn assert_data_attachment_denied(label: &str, mut socket: DeviceSocket) -> Result<()> {
    let deadline = tokio::time::Instant::now() + OPERATION_DEADLINE;
    loop {
        match timeout_at(deadline, socket.next()).await? {
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => return Ok(()),
            Some(Ok(Message::Ping(payload))) => {
                socket
                    .send(Message::Pong(payload))
                    .await
                    .map_err(|error| HarnessError::Http(format!("{label} pong failed: {error}")))?;
            }
            Some(Ok(Message::Text(_))) | Some(Ok(Message::Binary(_))) => {
                return Err(HarnessError::Http(format!(
                    "{label} delivered data before attachment was authorized"
                )));
            }
            Some(Ok(Message::Pong(_))) | Some(Ok(Message::Frame(_))) => {}
        }
    }
}

async fn assert_no_data_ready(socket: &mut DeviceSocket) -> Result<()> {
    match timeout(QUIET_SOCKET_WINDOW, socket.next()).await {
        Err(_) => Ok(()),
        Ok(Some(Ok(Message::Text(text)))) => {
            let message = decode_control(text.as_bytes()).map_err(|error| {
                HarnessError::Http(format!("decoding unexpected control message: {error}"))
            })?;
            Err(HarnessError::Http(format!(
                "rejected data attachment produced {}",
                message.kind_name()
            )))
        }
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => Err(HarnessError::Http(
            "control socket closed after a data attachment denial".to_owned(),
        )),
        Ok(Some(Ok(_))) => Err(HarnessError::Http(
            "unexpected WebSocket message after a data attachment denial".to_owned(),
        )),
    }
}

async fn assert_socket_quiet(label: &str, socket: &mut DeviceSocket) -> Result<()> {
    match timeout(QUIET_SOCKET_WINDOW, socket.next()).await {
        Err(_) => Ok(()),
        Ok(Some(Ok(Message::Close(_)))) | Ok(None) | Ok(Some(Err(_))) => Err(HarnessError::Http(
            format!("{label} closed after a duplicate attachment"),
        )),
        Ok(Some(Ok(_))) => Err(HarnessError::Http(format!(
            "{label} received unexpected data after a duplicate attachment"
        ))),
    }
}

async fn assert_control_closed(label: &str, mut socket: DeviceSocket) -> Result<()> {
    let deadline = tokio::time::Instant::now() + OPERATION_DEADLINE;
    let mut saw_rejection = false;
    loop {
        match timeout_at(deadline, socket.next()).await? {
            Some(Ok(Message::Text(text))) => {
                let message = decode_control(text.as_bytes()).map_err(|error| {
                    HarnessError::Http(format!("decoding {label} rejection: {error}"))
                })?;
                match message {
                    ControlMessage::Rejected(rejected) if rejected.code == "STALE_DATA" => {
                        saw_rejection = true;
                    }
                    other => {
                        return Err(HarnessError::Http(format!(
                            "{label} returned unexpected {} before close",
                            other.kind_name()
                        )));
                    }
                }
            }
            Some(Ok(Message::Close(_))) | None | Some(Err(_)) => {
                if saw_rejection {
                    return Ok(());
                }
                return Err(HarnessError::Http(format!(
                    "{label} closed without a STALE_DATA rejection"
                )));
            }
            Some(Ok(_)) => {
                return Err(HarnessError::Http(format!(
                    "{label} did not fence the stale session"
                )));
            }
        }
    }
}

fn client_tls(certificate: &CertificateMaterial, server_ca_pem: &str) -> Result<Arc<ClientConfig>> {
    tunnel_transport::load_client_config_from_pem(
        certificate.certificate_pem.as_bytes(),
        certificate.private_key_pem.as_bytes(),
        server_ca_pem.as_bytes(),
    )
    .map_err(|error| HarnessError::Pki(format!("building device TLS client: {error}")))
}

fn server_only_tls(harness: &RunningHarness) -> Result<Arc<ClientConfig>> {
    let mut roots = RootCertStore::empty();
    roots
        .add(CertificateDer::from(
            harness.pki.server_ca.certificate_der.clone(),
        ))
        .map_err(|error| HarnessError::Pki(format!("adding server CA: {error}")))?;
    ClientConfig::builder_with_provider(rustls::crypto::ring::default_provider().into())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| HarnessError::Pki(format!("configuring TLS 1.3: {error}")))
        .map(|builder| builder.with_root_certificates(roots).with_no_client_auth())
        .map(Arc::new)
        .map_err(|error| HarnessError::Pki(format!("building anonymous TLS client: {error}")))
}

async fn connect_socket(
    address: SocketAddr,
    path: &str,
    tls: Arc<ClientConfig>,
    subprotocol: Option<&str>,
    ticket: Option<&str>,
) -> ConnectResult {
    let mut request = format!("wss://localhost:{}{path}", address.port())
        .into_client_request()
        .map_err(|error| ConnectFailure::Other(format!("building WebSocket request: {error}")))?;
    if let Some(subprotocol) = subprotocol {
        let value = HeaderValue::from_str(subprotocol).map_err(|error| {
            ConnectFailure::Other(format!("building subprotocol header: {error}"))
        })?;
        request
            .headers_mut()
            .insert("sec-websocket-protocol", value);
    }
    if let Some(ticket) = ticket {
        let value = HeaderValue::from_str(&format!("Bearer {ticket}"))
            .map_err(|error| ConnectFailure::Other(format!("building ticket header: {error}")))?;
        request.headers_mut().insert("authorization", value);
    }
    let connector = Connector::Rustls(tls);
    match timeout(
        OPERATION_DEADLINE,
        connect_async_tls_with_config(request, None, true, Some(connector)),
    )
    .await
    {
        Err(_) => Err(ConnectFailure::Timeout),
        Ok(Ok(value)) => Ok(value),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Http(response))) => {
            Err(ConnectFailure::HttpStatus(response.status().as_u16()))
        }
        Ok(Err(tokio_tungstenite::tungstenite::Error::Tls(error))) => {
            Err(ConnectFailure::Tls(error.to_string()))
        }
        Ok(Err(tokio_tungstenite::tungstenite::Error::ConnectionClosed)) => Err(
            ConnectFailure::Closed("TLS peer closed the connection during admission".to_owned()),
        ),
        Ok(Err(tokio_tungstenite::tungstenite::Error::AlreadyClosed)) => Err(
            ConnectFailure::Closed("TLS peer closed the connection during admission".to_owned()),
        ),
        Ok(Err(tokio_tungstenite::tungstenite::Error::Io(error))) if is_rustls_alert(&error) => {
            Err(ConnectFailure::Tls(error.to_string()))
        }
        Ok(Err(tokio_tungstenite::tungstenite::Error::Io(error))) if is_closed_io(&error) => {
            Err(ConnectFailure::Closed(error.to_string()))
        }
        Ok(Err(error)) => Err(ConnectFailure::Other(error.to_string())),
    }
}

fn is_rustls_alert(error: &std::io::Error) -> bool {
    error
        .get_ref()
        .and_then(|source| source.downcast_ref::<rustls::Error>())
        .is_some_and(|error| matches!(error, rustls::Error::AlertReceived(_)))
}

fn is_closed_io(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        ErrorKind::BrokenPipe
            | ErrorKind::ConnectionAborted
            | ErrorKind::ConnectionReset
            | ErrorKind::UnexpectedEof
    )
}

fn assert_tls_rejection(label: &str, result: ConnectResult) -> Result<()> {
    match result {
        Ok(_) => Err(HarnessError::Http(format!(
            "{label} unexpectedly completed a WebSocket upgrade"
        ))),
        Err(ConnectFailure::HttpStatus(status)) => Err(HarnessError::Http(format!(
            "{label} reached HTTP with status {status}; expected TLS rejection"
        ))),
        Err(ConnectFailure::Timeout) => Err(HarnessError::Timeout(format!(
            "{label} TLS handshake timed out; expected an immediate TLS rejection"
        ))),
        Err(ConnectFailure::Tls(_)) | Err(ConnectFailure::Closed(_)) => Ok(()),
        Err(ConnectFailure::Other(detail)) => Err(HarnessError::Http(format!(
            "{label} failed without a TLS alert or closed connection: {detail}"
        ))),
    }
}

async fn timeout_at<T>(deadline: tokio::time::Instant, future: T) -> Result<T::Output>
where
    T: std::future::Future,
{
    timeout_at_result(deadline, future).await
}

async fn timeout_at_result<T>(deadline: tokio::time::Instant, future: T) -> Result<T::Output>
where
    T: std::future::Future,
{
    timeout(
        deadline.saturating_duration_since(tokio::time::Instant::now()),
        future,
    )
    .await
    .map_err(|_| HarnessError::Timeout("admission socket deadline elapsed".to_owned()))
}

async fn close_socket(mut socket: DeviceSocket) {
    let _ = timeout(Duration::from_millis(500), socket.close(None)).await;
}
