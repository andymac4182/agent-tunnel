// M7-C07 coverage linked from `peer_cleanup_tests.rs`.  It is a child of the
// existing cleanup fixture so `super::*` can reuse the private PKI,
// membership, catalog, handler, and record helpers.  The tests intentionally
// use public `PeerClientStream` HTTP/3 requests and send a valid admitted
// envelope before a declared-but-truncated peer record.

use super::*;

use crate::runtime::{RelaySessionSnapshot, RelaySnapshot};
use chrono::Duration as ChronoDuration;
use tokio::task::JoinHandle;
use tunnel_catalog::{Catalog, DeviceIdentity, MemoryCatalog, OwnerClaim, OwnerToken};
use tunnel_cluster::envelope::{
    ConsumerStreamsRequest, Destination, DeviceAuthenticationContext, DeviceControlRequest,
    DeviceDataRequest, ForwardedConsumerBearer, IngressRequestBinding, InternalRequest,
    PeerIdentity, VerifiedDeviceCertificate,
};
use tunnel_transport::{
    PeerClientStream, PeerHandlerFuture, PeerRequestHandler, PeerServerStream, PeerTransportError,
    TlsIdentity,
};

const SIBLING_SPKI: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn sibling_tenant_id() -> Uuid {
    Uuid::from_u128(0x1100_0000_0000_0000_0000_0000_0000_0002)
}

fn sibling_device_id() -> Uuid {
    Uuid::from_u128(0x3300_0000_0000_0000_0000_0000_0000_0002)
}

fn sibling_service_id() -> Uuid {
    Uuid::from_u128(0x4400_0000_0000_0000_0000_0000_0000_0002)
}

fn catalog_fixture_with_sibling(now: chrono::DateTime<Utc>) -> CatalogFixture {
    let mut fixture = super::catalog_fixture(now);
    fixture.tenants.push(TenantRecord {
        tenant_id: sibling_tenant_id(),
        display_name: "cleanup sibling tenant".to_owned(),
        active: true,
    });
    fixture.memberships.push(CatalogMembershipRecord {
        tenant_id: sibling_tenant_id(),
        user_id: user_id(),
        role: tunnel_catalog::MembershipRole::Member,
        active: true,
    });
    fixture.devices.push(FixtureDevice {
        tenant_id: sibling_tenant_id(),
        device_id: sibling_device_id(),
        owner_user_id: user_id(),
        display_name: "cleanup sibling device".to_owned(),
        active: true,
        last_seen_at: Some(now),
    });
    fixture.credentials.push(CredentialRecord {
        tenant_id: sibling_tenant_id(),
        device_id: sibling_device_id(),
        credential_id: Uuid::from_u128(0x5500_0000_0000_0000_0000_0000_0000_0002),
        spki_fingerprint: SIBLING_SPKI.to_owned(),
        serial: Some("cleanup-sibling-device".to_owned()),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::minutes(5),
        revoked_at: None,
        active: true,
    });
    fixture.services.push(ServiceSpec {
        tenant_id: sibling_tenant_id(),
        device_id: sibling_device_id(),
        service_id: sibling_service_id(),
        service_type: "echo".to_owned(),
        display_name: "Sibling Echo".to_owned(),
        capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
        version: 1,
        active: true,
    });
    fixture.grants.push(GrantSpec {
        tenant_id: sibling_tenant_id(),
        principal_id: user_id(),
        device_id: sibling_device_id(),
        service_id: sibling_service_id(),
        permissions: PermissionSet {
            operations: BTreeSet::from(["echo:invoke".to_owned()]),
        },
        constraints: serde_json::json!({}),
        expires_at: Some(now + ChronoDuration::minutes(5)),
        active: true,
    });
    fixture
}

/// The H3 fixture deliberately has one authoritative catalog shared by the
/// owner router, ingress handler, and relay actor.  Data admission therefore
/// exercises the same owner fence that production uses; the control cleanup
/// test uses the direct component boundary below because a successful
/// top-level duplicate cannot pass both the owner preflight and a fresh
/// `claim_owner` in one catalog.
struct H3PeerFixture {
    catalog: Arc<MemoryCatalog>,
    handle: RelayHandle,
    raw_client: PeerClient,
    destination_addr: SocketAddr,
    runtime: Arc<PeerRuntime>,
    server_cancel: CancellationToken,
    server_task: Option<JoinHandle<Result<(), PeerTransportError>>>,
    returned_errors: Arc<AtomicUsize>,
    consumer_token: String,
    consumer_signer: jsonwebtoken::EncodingKey,
}

impl H3PeerFixture {
    async fn new() -> Self {
        Self::new_with(|runtime, handle, catalog, oidc, _device, returned_errors| {
            let production_handler = peer_ingress_handler(
                handle,
                catalog,
                oidc,
                DESTINATION_NODE.to_owned(),
                DESTINATION_BOOT.to_owned(),
            );
            runtime.server_handler(RecordingHandler {
                inner: production_handler,
                returned_errors,
            })
        })
        .await
    }

    /// Build a server whose H3 callback enters the already-admitted control
    /// handler directly.  This is intentionally a component-scope test seam:
    /// it still runs TLS, route, membership, envelope, and peer-record
    /// admission through `PeerRuntime`, then invokes the production handler
    /// whose returned error owns the cleanup guard.
    async fn new_component_control() -> Self {
        Self::new_with(
            |runtime, handle, _catalog, _oidc, device, returned_errors| DirectControlHandler {
                runtime,
                handle,
                device,
                returned_errors,
            },
        )
        .await
    }

    async fn new_with<H, F>(handler_factory: F) -> Self
    where
        H: PeerRequestHandler,
        F: FnOnce(
            Arc<PeerRuntime>,
            RelayHandle,
            Arc<MemoryCatalog>,
            Arc<OidcVerifier>,
            DeviceIdentity,
            Arc<AtomicUsize>,
        ) -> H,
    {
        let now = Utc::now();
        let fixture = catalog_fixture_with_sibling(now);
        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&fixture)
            .await
            .expect("seed shared cleanup catalog");

        let (oidc, consumer_token, consumer_signer) = oidc_fixture_with_signer();
        let mut options = RelayOptions::new(oidc.clone());
        options.node_id = DESTINATION_NODE.to_owned();
        options.boot_id = DESTINATION_BOOT.to_owned();
        options.deployment_incarnation = DEPLOYMENT_INCARNATION.to_owned();
        let handle = RelayHandle::spawn(options, catalog.clone());

        let pki = FixturePki::new();
        let source_leaf = pki.issue_peer(SOURCE_NODE);
        let destination_leaf = pki.issue_peer(DESTINATION_NODE);
        let destination_chain = pki.chain(&destination_leaf);
        let server_config = load_peer_server_config_from_pem(
            destination_chain.as_bytes(),
            destination_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("peer server TLS config");
        let server_endpoint =
            quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
                .expect("peer server endpoint");
        let destination_addr = server_endpoint.local_addr().expect("server address");
        let mut client_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("peer client endpoint");
        let source_addr = client_endpoint.local_addr().expect("client address");
        let source_chain = pki.chain(&source_leaf);
        let client_config = load_peer_client_config_from_pem(
            source_chain.as_bytes(),
            source_leaf.private_key_pem.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("peer client TLS config");
        client_endpoint.set_default_client_config(client_config);

        let (source_binding, destination_binding) = membership_bindings(
            &source_leaf,
            &destination_leaf,
            source_addr,
            destination_addr,
        );
        let source_binding_for_provider = source_binding.clone();
        let destination_binding_for_provider = destination_binding.clone();
        let provider = move |node_id: &str, boot_id: &str, _now| {
            let result = if node_id == SOURCE_NODE && boot_id == SOURCE_BOOT {
                Ok(source_binding_for_provider.clone())
            } else if node_id == DESTINATION_NODE && boot_id == DESTINATION_BOOT {
                Ok(destination_binding_for_provider.clone())
            } else {
                Err(PeerRuntimeError::Membership(
                    "unknown staged cleanup peer".to_owned(),
                ))
            };
            async move { result }
        };
        let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, SOURCE_BOOT)
            .expect("source relay identity");
        let router: Arc<OwnerRouter<dyn Catalog>> =
            Arc::new(OwnerRouter::new(catalog.clone(), identity).expect("owner router"));
        let limits = test_limits();
        let client = PeerClient::new(
            client_endpoint,
            approved_pin(&destination_leaf),
            limits.clone(),
        )
        .expect("peer client");
        let raw_client = client.clone();
        let runtime = Arc::new(PeerRuntime::new(
            client,
            router,
            Arc::new(provider),
            SOURCE_NODE,
            SOURCE_BOOT,
        ));
        let returned_errors = Arc::new(AtomicUsize::new(0));
        let device = catalog
            .resolve_device(DEVICE_SPKI, Utc::now())
            .await
            .expect("resolve cleanup target device")
            .expect("cleanup target device identity");
        let server_handler = handler_factory(
            Arc::clone(&runtime),
            handle.clone(),
            Arc::clone(&catalog),
            oidc,
            device,
            Arc::clone(&returned_errors),
        );
        let server = PeerServer::new(
            server_endpoint,
            approved_pin(&source_leaf),
            limits,
            PeerRuntime::server_policy(),
            server_handler,
        )
        .expect("peer server");
        let server_cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(server_cancel.clone()));

        Self {
            catalog,
            handle,
            raw_client,
            destination_addr,
            runtime,
            server_cancel,
            server_task: Some(server_task),
            returned_errors,
            consumer_token,
            consumer_signer,
        }
    }

    /// Mint a consumer token whose `exp` is `lifetime_secs` from now.  The
    /// owner derives the stream's absolute authorization deadline from that
    /// claim, so a short lifetime bounds the stream deterministically.
    fn mint_consumer_token(&self, lifetime_secs: i64) -> String {
        mint_consumer_token(&self.consumer_signer, lifetime_secs)
    }

    async fn stop_server(&mut self) {
        let Some(server_task) = self.server_task.take() else {
            return;
        };
        self.server_cancel.cancel();
        let server_result = timeout(Duration::from_secs(3), server_task)
            .await
            .expect("peer server shutdown deadline")
            .expect("peer server join");
        assert!(
            server_result.is_ok(),
            "peer server returned {server_result:?}"
        );
    }

    async fn shutdown(mut self) {
        self.stop_server().await;
        self.runtime
            .shutdown()
            .await
            .expect("peer runtime shutdown");
        self.handle.shutdown().await.expect("relay shutdown");
    }
}

/// Test-only H3 boundary adapter for the post-admission control component.
/// `PeerRuntime::accept_inbound` remains the production transport boundary;
/// this adapter only skips the top-level owner lookup so the cleanup guard
/// can be exercised after a real registration succeeds in the shared catalog.
struct DirectControlHandler {
    runtime: Arc<PeerRuntime>,
    handle: RelayHandle,
    device: DeviceIdentity,
    returned_errors: Arc<AtomicUsize>,
}

impl PeerRequestHandler for DirectControlHandler {
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let runtime = Arc::clone(&self.runtime);
        let handle = self.handle.clone();
        let device = self.device.clone();
        let returned_errors = Arc::clone(&self.returned_errors);
        Box::pin(async move {
            let result = async {
                let inbound = runtime
                    .accept_inbound(identity, request, stream)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                super::super::handle_peer_device_control(inbound, handle, device)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))
            }
            .await;
            if result.is_err() {
                returned_errors.fetch_add(1, Ordering::AcqRel);
            }
            result
        })
    }
}

struct RegisteredControl {
    session_id: String,
    epoch: u64,
    ticket: String,
    rx: mpsc::Receiver<ControlOutbound>,
}

async fn register_control(
    fixture: &H3PeerFixture,
    spki_fingerprint: &str,
    device: Uuid,
    message_id: &str,
) -> RegisteredControl {
    let identity = fixture
        .catalog
        .resolve_device(spki_fingerprint, Utc::now())
        .await
        .expect("resolve staged control device")
        .expect("staged control device identity");
    let mut hello = Hello::new(message_id, device.to_string(), 1, 0);
    hello.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    let registration = fixture
        .handle
        .register_forwarded_control(identity, spki_fingerprint.to_owned(), hello)
        .await
        .expect("admit staged control");
    let session_id = registration.key.session_id.clone();
    let epoch = registration.key.epoch;
    let ticket = match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
        ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
        other => panic!("unexpected staged registration response: {other:?}"),
    };
    RegisteredControl {
        session_id,
        epoch,
        ticket,
        rx: registration.rx,
    }
}

fn device_envelope(
    route: InternalRoute,
    request_id: &str,
    stream_id: &str,
    owner: &OwnerToken,
) -> RequestEnvelope {
    let now = Utc::now();
    let source = PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT);
    let destination = Destination::new(owner.clone(), Uuid::nil());
    let authentication = DeviceAuthenticationContext {
        certificate: VerifiedDeviceCertificate {
            certificate_identity: device_id().to_string(),
            spki_fingerprint: DEVICE_SPKI.to_owned(),
            serial: "cleanup-device".to_owned(),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            tenant_id: tenant_id(),
            device_id: device_id(),
        },
        ingress: IngressRequestBinding {
            request_id: request_id.to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            expires_at: now + ChronoDuration::seconds(10),
        },
    };
    let request = match route {
        InternalRoute::DeviceControl => InternalRequest::DeviceControl(DeviceControlRequest {
            stream_id: stream_id.to_owned(),
            authentication,
        }),
        InternalRoute::DeviceData => InternalRequest::DeviceData(DeviceDataRequest {
            stream_id: stream_id.to_owned(),
            sequence: 1,
            authentication,
            bytes: Vec::new(),
        }),
        other => panic!("staged cleanup route must be a device route, got {other:?}"),
    };
    RequestEnvelope::new(
        route,
        request_id,
        source,
        destination,
        20_000,
        None,
        request,
    )
}

fn consumer_envelope(
    request_id: &str,
    stream_id: &str,
    owner: &OwnerToken,
    token: &str,
) -> RequestEnvelope {
    let source = PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT);
    let destination = Destination::new(owner.clone(), service_id());
    let bearer =
        ForwardedConsumerBearer::new(token.to_owned(), owner.clone()).expect("consumer bearer");
    RequestEnvelope::new(
        InternalRoute::ConsumerStreams,
        request_id,
        source,
        destination,
        20_000,
        Some(20_000),
        InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
            stream_id: stream_id.to_owned(),
            required_scope: crate::ECHO_OPERATION.to_owned(),
            bearer,
            bytes: Vec::new(),
        }),
    )
}

fn component_owner_token() -> OwnerToken {
    OwnerToken {
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        tenant_id: tenant_id(),
        device_id: device_id(),
        node_id: DESTINATION_NODE.to_owned(),
        boot_id: DESTINATION_BOOT.to_owned(),
        session_id: "component-cleanup-owner".to_owned(),
        epoch: 1,
    }
}

fn hello_record(message_id: &str, device: Uuid) -> Bytes {
    let mut hello = Hello::new(message_id, device.to_string(), 1, 0);
    hello.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    let encoded =
        wire::encode_control_message(&ControlMessage::Hello(hello)).expect("encode staged HELLO");
    encode_peer_record(PeerRecordKind::CompleteControlText, encoded.as_bytes())
}

async fn current_target_owner(fixture: &H3PeerFixture) -> OwnerClaim {
    fixture
        .catalog
        .current_owner(tenant_id(), device_id(), Utc::now())
        .await
        .expect("read shared target owner")
        .expect("shared target owner")
}

async fn open_raw(fixture: &H3PeerFixture, route: InternalRoute) -> PeerClientStream {
    let request = Request::builder()
        .method("POST")
        .uri(format!("https://localhost{}", PeerRuntime::path(route)))
        .header("content-type", "application/octet-stream")
        .body(())
        .expect("staged raw peer request");
    fixture
        .raw_client
        .open(
            PeerDestination::new(fixture.destination_addr, "localhost"),
            request,
        )
        .await
        .expect("open staged raw peer request")
}

fn truncated_record(kind: PeerRecordKind) -> Bytes {
    let mut prefix = Vec::with_capacity(8);
    prefix.extend_from_slice(&1_u32.to_be_bytes());
    prefix.extend_from_slice(&[kind.code(), 0, 0, 0]);
    Bytes::from(prefix)
}

async fn wait_handler_error(fixture: &H3PeerFixture, before: usize) {
    timeout(Duration::from_secs(3), async {
        loop {
            if fixture.returned_errors.load(Ordering::Acquire) > before {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("staged peer handler error deadline");
}

async fn wait_snapshot<F>(handle: &RelayHandle, mut ready: F) -> RelaySnapshot
where
    F: FnMut(&RelaySnapshot) -> bool,
{
    wait_snapshot_for(handle, Duration::from_secs(3), &mut ready).await
}

async fn wait_snapshot_for<F>(
    handle: &RelayHandle,
    deadline: Duration,
    ready: &mut F,
) -> RelaySnapshot
where
    F: FnMut(&RelaySnapshot) -> bool,
{
    timeout(deadline, async {
        loop {
            let snapshot = handle.snapshot().await.expect("staged cleanup snapshot");
            if ready(&snapshot) {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("staged cleanup snapshot deadline")
}

async fn wait_owner_released(catalog: &MemoryCatalog) {
    timeout(Duration::from_secs(3), async {
        loop {
            if catalog
                .current_owner(tenant_id(), device_id(), Utc::now())
                .await
                .expect("read staged target owner")
                .is_none()
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("staged target owner cleanup deadline");
}

fn find_session(snapshot: &RelaySnapshot, device: Uuid) -> Option<&RelaySessionSnapshot> {
    snapshot
        .sessions
        .iter()
        .find(|session| session.device_id == device.to_string())
}

fn assert_sibling_preserved(
    snapshot: &RelaySnapshot,
    expected_session_id: &str,
    expected_epoch: u64,
) {
    let sibling = find_session(snapshot, sibling_device_id()).expect("sibling session remains");
    assert_eq!(sibling.session_id, expected_session_id);
    assert_eq!(sibling.epoch, expected_epoch);
    assert_eq!(sibling.device_id, sibling_device_id().to_string());
}

async fn drain_control_queue(control_rx: &mut mpsc::Receiver<ControlOutbound>) {
    loop {
        let mut drained = false;
        while let Ok(item) = control_rx.try_recv() {
            drained = true;
            if let ControlOutbound::Text(mut text) = item {
                text.release();
            }
        }
        if !drained {
            break;
        }
        tokio::task::yield_now().await;
    }
}

async fn admit_component_control(
    stream: &mut PeerClientStream,
    request_id: &str,
    stream_id: &str,
    hello_id: &str,
) {
    let envelope = device_envelope(
        InternalRoute::DeviceControl,
        request_id,
        stream_id,
        &component_owner_token(),
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope
                .encode()
                .expect("encode component control envelope"),
        ))
        .await
        .expect("send component control envelope");
    stream
        .send_chunk(hello_record(hello_id, device_id()))
        .await
        .expect("send component control HELLO");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("component control response deadline")
        .expect("component control response headers");
    assert!(response.status().is_success());
    assert!(
        timeout(Duration::from_secs(3), stream.recv_chunk())
            .await
            .expect("component control WELCOME deadline")
            .expect("component control WELCOME result")
            .is_some(),
        "admitted component control stream must send WELCOME"
    );
}

async fn admit_device_data(
    stream: &mut PeerClientStream,
    owner: &OwnerToken,
    ticket: &str,
    request_id: &str,
    stream_id: &str,
) {
    let envelope = device_envelope(InternalRoute::DeviceData, request_id, stream_id, owner);
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode device data envelope"),
        ))
        .await
        .expect("send device data envelope");
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            format!("Bearer {ticket}").as_bytes(),
        ))
        .await
        .expect("send device data ticket");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("device data response deadline")
        .expect("device data response headers");
    assert!(response.status().is_success());
}

async fn admit_consumer(
    stream: &mut PeerClientStream,
    owner: &OwnerToken,
    token: &str,
    request_id: &str,
    stream_id: &str,
) {
    let envelope = consumer_envelope(request_id, stream_id, owner, token);
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode consumer envelope"),
        ))
        .await
        .expect("send consumer envelope");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("consumer response deadline")
        .expect("consumer response headers");
    assert!(response.status().is_success());
}

#[tokio::test]
async fn peer_device_control_truncated_record_detaches_only_owned_registration() {
    // Component cleanup scope: the direct H3 callback enters the production
    // post-admission handler after `PeerRuntime` has accepted the envelope.
    let fixture = H3PeerFixture::new_component_control().await;
    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-sibling-control",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let mut stream = open_raw(&fixture, InternalRoute::DeviceControl).await;
    let component_owner = component_owner_token();
    let envelope = device_envelope(
        InternalRoute::DeviceControl,
        "staged-device-control-request",
        "staged-device-control-stream",
        &component_owner,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode control envelope"),
        ))
        .await
        .expect("send admitted control envelope");
    stream
        .send_chunk(hello_record("staged-device-control-hello", device_id()))
        .await
        .expect("send admitted control HELLO");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("control response deadline")
        .expect("control response headers");
    assert!(response.status().is_success());
    assert!(
        timeout(Duration::from_secs(3), stream.recv_chunk())
            .await
            .expect("control WELCOME deadline")
            .expect("control WELCOME result")
            .is_some(),
        "admitted control stream must send WELCOME before the malformed record"
    );

    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some()
    })
    .await;
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("sibling session after target admission")
        .clone();
    let returned_errors_before = fixture.returned_errors.load(Ordering::Acquire);
    stream
        .send_chunk(truncated_record(PeerRecordKind::CompleteControlText))
        .await
        .expect("send truncated control record");
    let _ = stream.finish().await;
    wait_handler_error(&fixture, returned_errors_before).await;

    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_none()
            && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
    })
    .await;
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);
    wait_owner_released(&fixture.catalog).await;

    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_control_cancel_closes_exact_registration_and_preserves_sibling() {
    // Component-scope cancellation: the request is admitted through the real
    // H3/TLS/runtime boundary, then a client reset must release only the
    // registration owned by this request.
    let fixture = H3PeerFixture::new_component_control().await;
    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-cancel-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let mut stream = open_raw(&fixture, InternalRoute::DeviceControl).await;
    admit_component_control(
        &mut stream,
        "staged-cancel-control-request",
        "staged-cancel-control-stream",
        "staged-cancel-control-hello",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some()
            && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("cancel target session after admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("cancel sibling after admission")
        .clone();

    stream.cancel();
    drop(stream);
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_none()
            && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
    })
    .await;
    assert_ne!(target_before.session_id, sibling_before.session_id);
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);
    wait_owner_released(&fixture.catalog).await;

    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_control_idle_deadline_closes_exact_registration_and_preserves_sibling() {
    // Component-scope deadline: after admission no further request bytes are
    // sent, so the real H3 receive idle timeout must run the same cleanup
    // guard without a client reset.
    let fixture = H3PeerFixture::new_component_control().await;
    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-idle-control-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let mut stream = open_raw(&fixture, InternalRoute::DeviceControl).await;
    admit_component_control(
        &mut stream,
        "staged-idle-control-request",
        "staged-idle-control-stream",
        "staged-idle-control-hello",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some()
            && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("idle target session after admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("idle sibling after admission")
        .clone();
    let returned_errors_before = fixture.returned_errors.load(Ordering::Acquire);

    // Keep `stream` alive.  The configured two-second H3 idle deadline, not
    // client drop, must drive the handler to its terminal cleanup path.
    let final_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_none()
                && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                    session.session_id == sibling_before.session_id
                        && session.epoch == sibling_before.epoch
                })
        })
        .await;
    wait_handler_error(&fixture, returned_errors_before).await;
    assert_ne!(target_before.session_id, sibling_before.session_id);
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);
    wait_owner_released(&fixture.catalog).await;

    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_control_duplicate_owner_is_refused_before_admission_cleanup() {
    // Top-level production scope: the shared catalog has one live owner, so
    // ingress preflight succeeds and the actor rejects the fresh duplicate
    // claim before the post-admission cleanup guard is installed.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-duplicate-target",
    )
    .await;
    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-duplicate-sibling",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _target_rx = target.rx;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let returned_errors_before = fixture.returned_errors.load(Ordering::Acquire);
    let mut stream = open_raw(&fixture, InternalRoute::DeviceControl).await;
    let envelope = device_envelope(
        InternalRoute::DeviceControl,
        "staged-duplicate-request",
        "staged-duplicate-stream",
        &owner.token,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode duplicate envelope"),
        ))
        .await
        .expect("send duplicate control envelope");
    stream
        .send_chunk(hello_record("staged-duplicate-hello", device_id()))
        .await
        .expect("send duplicate control HELLO");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("duplicate response deadline");
    assert!(
        response.is_err(),
        "duplicate owner must be refused before a response is committed"
    );
    wait_handler_error(&fixture, returned_errors_before).await;

    let snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id && session.epoch == target_epoch
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_session_id && session.epoch == sibling_epoch
        })
    })
    .await;
    assert_sibling_preserved(&snapshot, &sibling_session_id, sibling_epoch);
    let owner_after = current_target_owner(&fixture).await;
    assert_eq!(owner_after.token.session_id, target_session_id);
    assert_eq!(owner_after.token.epoch, target_epoch);

    fixture.shutdown().await;
}

// Full top-level data ingress scope: the owner fence, device admission, data
// attachment, and recovery all use the same authoritative catalog.
#[tokio::test]
async fn peer_device_data_truncated_record_interrupts_only_owned_carrier() {
    let fixture = H3PeerFixture::new().await;
    let target =
        register_control(&fixture, DEVICE_SPKI, device_id(), "staged-target-control").await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let _target_rx = target.rx;
    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-sibling-data-control",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let mut stream = open_raw(&fixture, InternalRoute::DeviceData).await;
    let owner = current_target_owner(&fixture).await;
    let envelope = device_envelope(
        InternalRoute::DeviceData,
        "staged-device-data-request",
        "staged-device-data-stream",
        &owner.token,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode data envelope"),
        ))
        .await
        .expect("send admitted data envelope");
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            format!("Bearer {target_ticket}").as_bytes(),
        ))
        .await
        .expect("send data attachment ticket");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("data response deadline")
        .expect("data response headers");
    assert!(response.status().is_success());
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| session.sockets == 2)
    })
    .await;
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("sibling session after data admission")
        .clone();
    let returned_errors_before = fixture.returned_errors.load(Ordering::Acquire);
    stream
        .send_chunk(truncated_record(PeerRecordKind::CompleteDeviceData))
        .await
        .expect("send truncated data record");
    let _ = stream.finish().await;
    wait_handler_error(&fixture, returned_errors_before).await;

    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.phase == "recovering"
                && session.sockets == 1
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id && session.epoch == sibling_before.epoch
        })
    })
    .await;
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);
    let target_owner = fixture
        .catalog
        .current_owner(tenant_id(), device_id(), Utc::now())
        .await
        .expect("read interrupted target owner")
        .expect("data loss keeps control owner");
    assert_eq!(target_owner.token.session_id, target_session_id);
    assert_eq!(target_owner.token.epoch, target_epoch);

    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_data_idle_deadline_reclaims_exact_carrier_and_preserves_sibling() {
    // The fixture's transport idle deadline is two seconds.  Leaving an
    // admitted data request open lets the real H3 receive deadline terminate
    // the handler; the post-admission guard must remove only its exact
    // carrier while preserving the control session and sibling.
    let fixture = H3PeerFixture::new().await;
    let target =
        register_control(&fixture, DEVICE_SPKI, device_id(), "staged-deadline-target").await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let mut target_rx = target.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-deadline-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    // Release the registration welcome charge before measuring the exact
    // carrier cleanup budget below.  The H3 data handler owns its data
    // receiver, so this component only needs to release the control welcome.
    while let Ok(item) = target_rx.try_recv() {
        if let ControlOutbound::Text(mut text) = item {
            text.release();
        }
    }
    let owner = current_target_owner(&fixture).await;
    let mut stream = open_raw(&fixture, InternalRoute::DeviceData).await;
    let envelope = device_envelope(
        InternalRoute::DeviceData,
        "staged-deadline-data-request",
        "staged-deadline-data-stream",
        &owner.token,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode deadline data envelope"),
        ))
        .await
        .expect("send deadline data envelope");
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            format!("Bearer {}", target.ticket).as_bytes(),
        ))
        .await
        .expect("send deadline data ticket");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("deadline data response deadline")
        .expect("deadline data response headers");
    assert!(response.status().is_success());

    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("deadline target session after carrier admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("deadline sibling after target admission")
        .clone();

    // No finish or cancel is sent.  The bounded six-second wait is longer
    // than the configured two-second H3 idle deadline and only accepts the
    // exact target session/carrier transition plus an unchanged sibling.
    let _recovering_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_some_and(|session| {
                session.session_id == target_session_id
                    && session.epoch == target_epoch
                    && session.phase == "recovering"
                    && session.sockets == 1
                    && session.active_generation == target_before.active_generation
                    && session.active_connection_id == target_before.active_connection_id
            }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
        })
        .await;
    // Recovery emits bounded BEGIN/CLOSED control records.  Release those
    // exact charges before checking that carrier cleanup left no budget.
    while let Ok(item) = target_rx.try_recv() {
        if let ControlOutbound::Text(mut text) = item {
            text.release();
        }
    }
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.phase == "recovering"
                && session.sockets == 1
                && session.active_generation == target_before.active_generation
                && session.active_connection_id == target_before.active_connection_id
                && session.queue_bytes == 0
                && session.queue_messages == 0
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id && session.epoch == sibling_before.epoch
        })
    })
    .await;
    let final_target =
        find_session(&final_snapshot, device_id()).expect("deadline target final session");
    assert_eq!(
        final_target.active_generation, target_before.active_generation,
        "idle cleanup must retain the exact target carrier generation"
    );
    assert_eq!(
        final_target.active_connection_id, target_before.active_connection_id,
        "idle cleanup must retain the exact target carrier identity"
    );
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);

    stream.cancel();
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_data_transport_shutdown_reclaims_exact_carrier_and_preserves_sibling() {
    // Full top-level data scope: explicit peer-server shutdown drops the
    // admitted request task.  The target carrier must enter recovery while
    // retaining its control session and exact active carrier identity.
    let mut fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-shutdown-data-target",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-shutdown-data-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let mut stream = open_raw(&fixture, InternalRoute::DeviceData).await;
    admit_device_data(
        &mut stream,
        &owner.token,
        &target_ticket,
        "staged-shutdown-data-request",
        "staged-shutdown-data-stream",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("shutdown data target session after admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("shutdown data sibling after admission")
        .clone();
    drain_control_queue(&mut target_rx).await;

    // Keep the client stream open.  Stopping the server cancels the request
    // task and exercises TerminalCleanupGuard::drop for the data carrier.
    fixture.stop_server().await;
    let recovering_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_some_and(|session| {
                session.session_id == target_session_id
                    && session.epoch == target_epoch
                    && session.phase == "recovering"
                    && session.sockets == 1
                    && session.active_generation == target_before.active_generation
                    && session.active_connection_id == target_before.active_connection_id
            }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
        })
        .await;
    drain_control_queue(&mut target_rx).await;
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.phase == "recovering"
                && session.sockets == 1
                && session.active_generation == target_before.active_generation
                && session.active_connection_id == target_before.active_connection_id
                && session.queue_bytes == 0
                && session.queue_messages == 0
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id && session.epoch == sibling_before.epoch
        })
    })
    .await;
    assert_eq!(
        find_session(&recovering_snapshot, device_id())
            .expect("shutdown data target recovering session")
            .active_connection_id,
        target_before.active_connection_id,
        "transport shutdown must retain the exact target carrier identity"
    );
    let final_target =
        find_session(&final_snapshot, device_id()).expect("shutdown data target final session");
    assert_eq!(
        final_target.active_generation, target_before.active_generation,
        "transport shutdown must retain the exact target carrier generation"
    );
    assert_eq!(
        final_target.active_connection_id, target_before.active_connection_id,
        "transport shutdown must retain the exact target carrier identity"
    );
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_consumer_cancel_closes_exact_stream_and_preserves_sibling() {
    // Full top-level consumer scope: owner lookup, JWT/catalog validation,
    // stream registration, and cancellation all cross the real HTTP/3 peer
    // boundary. The target data carrier is attached so the actor can emit its
    // terminal FIN while the sibling remains independently live.
    let fixture = H3PeerFixture::new().await;
    let target =
        register_control(&fixture, DEVICE_SPKI, device_id(), "staged-consumer-target").await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let _target_rx = target.rx;
    let target_device = fixture
        .catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve consumer target device")
        .expect("consumer target device identity");
    let target_data = fixture
        .handle
        .attach_forwarded_data(target_device, DEVICE_SPKI.to_owned(), target_ticket)
        .await
        .expect("attach consumer target carrier");
    let _target_data_rx = target_data.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-consumer-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    let envelope = consumer_envelope(
        "staged-consumer-request",
        "staged-consumer-stream",
        &owner.token,
        &fixture.consumer_token,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode consumer envelope"),
        ))
        .await
        .expect("send consumer envelope");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("consumer response deadline")
        .expect("consumer response headers");
    assert!(response.status().is_success());

    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| session.streams.len() == 1)
            && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_stream_id = find_session(&admitted, device_id())
        .expect("consumer target session after admission")
        .streams
        .first()
        .expect("consumer stream after admission")
        .stream_id;
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("consumer sibling session after admission")
        .clone();

    // Cancel both HTTP/3 directions and drop the client handle. The owner's
    // exact stream identity must be terminalized without touching the sibling.
    stream.cancel();
    drop(stream);
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
                && session
                    .streams
                    .iter()
                    .any(|stream| stream.stream_id == target_stream_id && stream.terminal)
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id
                && session.epoch == sibling_before.epoch
                && session.session_id == sibling_session_id
                && session.epoch == sibling_epoch
        })
    })
    .await;
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);

    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_consumer_idle_deadline_closes_exact_stream_and_preserves_sibling() {
    // Full top-level consumer scope: after admission, the real H3 receive
    // idle deadline must close exactly this stream and emit its terminal FIN
    // on the target carrier while the sibling remains unchanged.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-idle-consumer-target",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;
    let target_device = fixture
        .catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve idle consumer target device")
        .expect("idle consumer target device identity");
    let target_data = fixture
        .handle
        .attach_forwarded_data(target_device, DEVICE_SPKI.to_owned(), target_ticket)
        .await
        .expect("attach idle consumer target carrier");
    let mut target_data_rx = target_data.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-idle-consumer-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    admit_consumer(
        &mut stream,
        &owner.token,
        &fixture.consumer_token,
        "staged-idle-consumer-request",
        "staged-idle-consumer-stream",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
                && session.streams.len() == 1
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("idle consumer target session after admission")
        .clone();
    let target_stream_before = target_before
        .streams
        .first()
        .expect("idle consumer target stream after admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("idle consumer sibling after admission")
        .clone();
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    // Keep the client stream open so the configured two-second H3 receive
    // deadline, rather than client reset, drives consumer cleanup.
    let _terminal_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_some_and(|session| {
                session.session_id == target_session_id
                    && session.epoch == target_epoch
                    && session.sockets == 2
                    && session.active_generation == target_before.active_generation
                    && session.active_connection_id == target_before.active_connection_id
                    && session.streams.iter().any(|stream| {
                        stream.stream_id == target_stream_before.stream_id
                            && stream.operation_id == target_stream_before.operation_id
                            && stream.terminal
                    })
            }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
        })
        .await;
    drain_queues(&mut target_rx, &mut target_data_rx).await;
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
                && session.active_generation == target_before.active_generation
                && session.active_connection_id == target_before.active_connection_id
                && session.queue_bytes == 0
                && session.queue_messages == 1
                && session.streams.iter().any(|stream| {
                    stream.stream_id == target_stream_before.stream_id
                        && stream.operation_id == target_stream_before.operation_id
                        && stream.terminal
                        && stream.queue_bytes == 0
                })
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id && session.epoch == sibling_before.epoch
        })
    })
    .await;
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_consumer_outstanding_write_is_bounded_by_consumer_expiry() {
    // Full top-level consumer scope: the owner handler awaits an actor write
    // that can never complete because the device never confirms the stream's
    // authorization, so the actor parks the record.  Neither the H3 receive
    // idle deadline (the handler is not reading) nor registration closure (no
    // one closes the stream) can end that wait.  The consumer's absolute
    // authorization deadline must bound the outstanding write and terminalize
    // exactly this stream while the sibling stays untouched.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-outstanding-write-target",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;
    let target_device = fixture
        .catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve outstanding-write target device")
        .expect("outstanding-write target device identity");
    let target_data = fixture
        .handle
        .attach_forwarded_data(target_device, DEVICE_SPKI.to_owned(), target_ticket)
        .await
        .expect("attach outstanding-write target carrier");
    let mut target_data_rx = target_data.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-outstanding-write-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let short_lived_token = fixture.mint_consumer_token(2);
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    admit_consumer(
        &mut stream,
        &owner.token,
        &short_lived_token,
        "staged-outstanding-write-request",
        "staged-outstanding-write-stream",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.streams.len() == 1
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_stream_before = find_session(&admitted, device_id())
        .expect("outstanding-write target session after admission")
        .streams
        .first()
        .expect("outstanding-write target stream after admission")
        .clone();
    assert!(!target_stream_before.terminal);
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("outstanding-write sibling after admission")
        .clone();
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    // One complete length-prefixed application record.  Without a device
    // authorization confirmation the actor cannot dispatch it, so the owner
    // handler's write stays outstanding.
    let body = b"outstanding-write";
    let mut record = (body.len() as u32).to_be_bytes().to_vec();
    record.extend_from_slice(body);
    stream
        .send_chunk(encode_peer_record(PeerRecordKind::ConsumerChunk, &record))
        .await
        .expect("send parked consumer record");

    // Keep the client stream open: only the consumer's two-second absolute
    // deadline may end the outstanding write.  A stranded handler would keep
    // this stream live far beyond the bound below.
    let started = tokio::time::Instant::now();
    let terminal_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_some_and(|session| {
                session.session_id == target_session_id
                    && session.epoch == target_epoch
                    && session.streams.iter().any(|stream| {
                        stream.stream_id == target_stream_before.stream_id
                            && stream.operation_id == target_stream_before.operation_id
                            && stream.terminal
                    })
            }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
        })
        .await;
    assert!(
        started.elapsed() < Duration::from_secs(6),
        "the outstanding write must be bounded by the consumer's absolute deadline"
    );
    assert_sibling_preserved(&terminal_snapshot, &sibling_session_id, sibling_epoch);
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_consumer_transport_shutdown_closes_exact_stream_and_preserves_sibling() {
    // Explicit PeerServer shutdown cancels the active H3 request task.  Keep
    // the client stream open so this exercises transport cancellation/drop,
    // rather than a client-issued reset, while the target data carrier and
    // sibling control session remain live.
    let mut fixture = H3PeerFixture::new().await;
    let target =
        register_control(&fixture, DEVICE_SPKI, device_id(), "staged-shutdown-target").await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let mut target_rx = target.rx;
    let target_device = fixture
        .catalog
        .resolve_device(DEVICE_SPKI, Utc::now())
        .await
        .expect("resolve shutdown target device")
        .expect("shutdown target device identity");
    let target_data = fixture
        .handle
        .attach_forwarded_data(target_device, DEVICE_SPKI.to_owned(), target.ticket.clone())
        .await
        .expect("attach shutdown target carrier");
    let mut target_data_rx = target_data.rx;

    let sibling = register_control(
        &fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        "staged-shutdown-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    let envelope = consumer_envelope(
        "staged-shutdown-consumer-request",
        "staged-shutdown-consumer-stream",
        &owner.token,
        &fixture.consumer_token,
    );
    stream
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope
                .encode()
                .expect("encode shutdown consumer envelope"),
        ))
        .await
        .expect("send shutdown consumer envelope");
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("shutdown consumer response deadline")
        .expect("shutdown consumer response headers");
    assert!(response.status().is_success());

    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
                && session.streams.len() == 1
        })
    })
    .await;
    let target_before = find_session(&admitted, device_id())
        .expect("shutdown target session after stream admission")
        .clone();
    let target_stream_before = target_before
        .streams
        .first()
        .expect("shutdown target stream after admission")
        .clone();
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("shutdown sibling after target admission")
        .clone();
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    // This cancels the server-side H3 transport and waits for its bounded
    // drain.  The still-live client stream is deliberately not cancelled.
    fixture.stop_server().await;
    let _terminal_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(6), &mut |snapshot| {
            find_session(snapshot, device_id()).is_some_and(|session| {
                session.session_id == target_session_id
                    && session.epoch == target_epoch
                    && session.sockets == 2
                    && session.active_generation == target_before.active_generation
                    && session.active_connection_id == target_before.active_connection_id
                    && session.streams.iter().any(|stream| {
                        stream.stream_id == target_stream_before.stream_id
                            && stream.operation_id == target_stream_before.operation_id
                            && stream.terminal
                            && stream.queue_bytes == 0
                    })
            }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
                session.session_id == sibling_before.session_id
                    && session.epoch == sibling_before.epoch
            })
        })
        .await;

    // Closing an admitted consumer stream emits one FIN on the target data
    // carrier.  Drain that exact receiver and then require the actor's queue
    // budget to return to zero while retaining exactly one terminal stream.
    drain_queues(&mut target_rx, &mut target_data_rx).await;
    let final_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
                && session.active_generation == target_before.active_generation
                && session.active_connection_id == target_before.active_connection_id
                && session.queue_bytes == 0
                && session.queue_messages == 1
                && session.streams.iter().any(|stream| {
                    stream.stream_id == target_stream_before.stream_id
                        && stream.operation_id == target_stream_before.operation_id
                        && stream.terminal
                        && stream.queue_bytes == 0
                })
        }) && find_session(snapshot, sibling_device_id()).is_some_and(|session| {
            session.session_id == sibling_before.session_id && session.epoch == sibling_before.epoch
        })
    })
    .await;
    assert_sibling_preserved(&final_snapshot, &sibling_session_id, sibling_epoch);

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}
