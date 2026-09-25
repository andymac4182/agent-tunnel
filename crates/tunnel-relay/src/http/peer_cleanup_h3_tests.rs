// M7-C07 coverage linked from `peer_cleanup_tests.rs`.  It is a child of the
// existing cleanup fixture so `super::*` can reuse the private PKI,
// membership, catalog, handler, and record helpers.  The tests intentionally
// use public `PeerClientStream` HTTP/3 requests and send a valid admitted
// envelope before a declared-but-truncated peer record.

use super::*;

use crate::peer_fault_diagnostics::{PeerFaultContext, PeerFaultObserver, PeerFaultRole};
use crate::routing::OwnerScope;
use crate::{
    peer_consumer_transport_diagnostics::{
        PeerConsumerDiagnosticH3Code, PeerConsumerDiagnosticRole,
    },
    peer_transport_diagnostics::PeerTransportDiagnosticOutcome,
    runtime::{RelaySessionSnapshot, RelaySnapshot, RelayStreamSnapshot},
};
use chrono::Duration as ChronoDuration;
use http::StatusCode;
use tokio::task::JoinHandle;
use tunnel_catalog::{
    Catalog, DeviceIdentity, MemoryCatalog, OwnerClaim, OwnerClaimRequest, OwnerToken,
};
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

    /// Build a server whose H3 callback answers the ingress request head and
    /// then deliberately withholds the response record past the transport's
    /// receive idle window.  Everything before the hold is the production
    /// admission path (`PeerRuntime::accept_inbound`); only the response
    /// timing is staged, which is what the ingress read bound is about.
    async fn new_holding_owner() -> Self {
        Self::new_with(
            |runtime, _handle, _catalog, _oidc, _device, returned_errors| HoldingOwnerHandler {
                runtime,
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
                let fault = PeerFaultObserver::new(
                    PeerFaultRole::Owner,
                    PeerFaultContext::unrouted(Uuid::nil(), device.device_id, None),
                );
                super::super::handle_peer_device_control(inbound, handle, device, &fault)
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

/// Longer than the fixture's two-second transport receive idle timeout, so a
/// response read still bounded by that window cannot observe the record.
const INGRESS_OWNER_HOLD: Duration = Duration::from_millis(3_200);
/// The fixture's transport receive idle timeout (`test_limits`).
const INGRESS_IDLE_WINDOW: Duration = Duration::from_secs(2);
/// Stands in for the consumer's absolute authorization deadline.  It is well
/// past the hold above, so the record must arrive before it.
const INGRESS_CONSUMER_LIFETIME: Duration = Duration::from_secs(7);
/// Scheduling slack around the deadline the silent owner must be ended by.
const INGRESS_DEADLINE_SLACK: Duration = Duration::from_millis(2_500);
const INGRESS_HELD_BODY: &[u8] = b"ingress-parked-response";

/// Owner stub for the ingress-role bound: it accepts a real forwarded
/// consumer request, answers the head immediately, withholds the single
/// response record for [`INGRESS_OWNER_HOLD`], and then stays silent so only
/// the ingress's own absolute deadline can end the exchange.
struct HoldingOwnerHandler {
    runtime: Arc<PeerRuntime>,
    returned_errors: Arc<AtomicUsize>,
}

impl PeerRequestHandler for HoldingOwnerHandler {
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let runtime = Arc::clone(&self.runtime);
        let returned_errors = Arc::clone(&self.returned_errors);
        Box::pin(async move {
            let result = async {
                let inbound = runtime
                    .accept_inbound(identity, request, stream)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                let (mut send, _recv) = inbound.split();
                send.respond(StatusCode::OK)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                tokio::time::sleep(INGRESS_OWNER_HOLD).await;
                send.send_message(PeerRecordKind::ConsumerChunk, INGRESS_HELD_BODY)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                // Deliberately never finish: the exchange must be ended by
                // the ingress deadline, not by the owner closing.  The
                // fixture's server shutdown cancels this task.
                std::future::pending::<()>().await;
                Ok::<_, PeerTransportError>(())
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
    // The property this case is about is that the duplicate claim is refused
    // before any post-admission cleanup guard is installed, and that neither
    // the live owner nor the sibling is disturbed.  It used to observe that by
    // asserting no response was committed at all, which is the one wire
    // behaviour the relay must NOT have: finishing the request stream without
    // response headers is a connection-level error at the ingress and takes
    // every other forwarded carrier on that connection down with it (see
    // `peer_device_control_refusal_responds_and_preserves_the_connection_sibling_carrier`).
    // The refusal is now committed as a status, and the assertions below are
    // the same ones, made against the outcome rather than against the absence
    // of one.
    let response = timeout(Duration::from_secs(3), stream.recv_response())
        .await
        .expect("duplicate response deadline")
        .expect("a duplicate owner claim must be answered, not dropped bare");
    assert_eq!(
        response.status(),
        StatusCode::CONFLICT,
        "a duplicate exact-scope owner keeps its own refusal status"
    );
    // The refusal is still counted, in the place that names what it was: the
    // actor's control registration conflict counter rather than a transport
    // error return.
    let conflicts = wait_snapshot(&fixture.handle, |snapshot| {
        snapshot.control_registration_conflicts > 0
    })
    .await;
    assert!(
        conflicts.control_registration_conflicts > 0,
        "a refused duplicate owner must be recorded as a registration conflict"
    );
    assert_eq!(
        fixture.returned_errors.load(Ordering::Acquire),
        returned_errors_before,
        "an answered refusal is not a returned handler error"
    );

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

/// Read the one queued consumer OPEN from a staged target control
/// registration and admit it exactly as a real connector would.  The cleanup
/// paths under test close an admitted stream and emit its terminal FIN; the
/// owner defers the close of an unadmitted OPEN until its outcome instead.
/// Admit the queued OPEN exactly as a real connector would and return it so a
/// caller can later answer the owner's authorization challenge for the same
/// stream.
async fn admit_queued_open(
    fixture: &H3PeerFixture,
    control_rx: &mut mpsc::Receiver<ControlOutbound>,
    session_id: &str,
    epoch: u64,
) -> tunnel_protocol::Open {
    let open = loop {
        let item = timeout(Duration::from_secs(3), control_rx.recv())
            .await
            .expect("staged OPEN queue deadline")
            .expect("staged control registration remains live");
        match item {
            ControlOutbound::Text(text) => {
                let (text, mut charge) = text.into_parts();
                let parsed = wire::parse_control(text.as_bytes()).expect("staged OPEN control");
                charge.release();
                if let ControlMessage::Open(open) = parsed {
                    break open;
                }
            }
            ControlOutbound::Close => {}
        }
    };
    let key = crate::actor::SessionKey {
        tenant_id: tenant_id(),
        device_id: device_id(),
        session_id: session_id.to_owned(),
        epoch,
    };
    admit_open(&fixture.handle, &key, &open).await;
    open
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
    let mut target_rx = target.rx;
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

    admit_queued_open(&fixture, &mut target_rx, &target_session_id, target_epoch).await;

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
    admit_queued_open(&fixture, &mut target_rx, &target_session_id, target_epoch).await;
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
    // authorization, so the actor parks the record.  Registration closure (no
    // one closes the stream) cannot end that wait, and the consumer's
    // one-second absolute deadline is deliberately below the fixture's
    // two-second H3 receive idle deadline, which the handler keeps observing
    // while parked (EC-045).  The consumer's absolute authorization deadline
    // must therefore bound the outstanding write itself and terminalize
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
    let short_lived_token = fixture.mint_consumer_token(1);
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    admit_consumer(
        &mut stream,
        &owner.token,
        &short_lived_token,
        "staged-outstanding-write-request",
        "staged-outstanding-write-stream",
    )
    .await;
    // Admit the OPEN exactly as a real connector would.  The parked record
    // below is waiting for the device's authorization confirmation, not for
    // admission; an unadmitted OPEN would have its close deferred until the
    // owner proves OPENED or REJECTED, so the bound under test would not be
    // observable as this stream's terminal state.
    admit_queued_open(&fixture, &mut target_rx, &target_session_id, target_epoch).await;
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

    // Keep the client stream open: only the consumer's one-second absolute
    // deadline may end the outstanding write.  A stranded handler would keep
    // this stream live far beyond the bound below.
    let owner_receive_before = fixture
        .handle
        .snapshot()
        .await
        .expect("outstanding-write baseline snapshot")
        .peer_consumer_diagnostics
        .owner_receive_count;
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
    // The bound came from the consumer deadline, not from the receive idle
    // deadline: no owner receive outcome was recorded.
    assert_eq!(
        terminal_snapshot
            .peer_consumer_diagnostics
            .owner_receive_count,
        owner_receive_before,
        "the consumer deadline, not a receive failure, must end the parked write"
    );
    assert_sibling_preserved(&terminal_snapshot, &sibling_session_id, sibling_epoch);
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_consumer_outstanding_write_outlives_the_receive_idle_timeout() {
    // Regression for the queue-saturation gate: a parked actor write must not
    // be ended by the transport's two-second receive idle timeout.  The
    // ingress peer is legitimately silent while it waits for this response,
    // so the serviced receive direction (EC-045) is bounded by the consumer's
    // absolute deadline only.  With a five-second consumer deadline the
    // stream must still be live and unfaulted after the idle window has
    // passed, then end at the consumer deadline with no owner receive
    // outcome recorded.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-parked-past-idle-target",
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
        "staged-parked-past-idle-sibling",
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let _sibling_rx = sibling.rx;

    let owner = current_target_owner(&fixture).await;
    let short_lived_token = fixture.mint_consumer_token(5);
    let mut stream = open_raw(&fixture, InternalRoute::ConsumerStreams).await;
    admit_consumer(
        &mut stream,
        &owner.token,
        &short_lived_token,
        "staged-parked-past-idle-request",
        "staged-parked-past-idle-stream",
    )
    .await;
    // Admit the OPEN exactly as a real connector would.  The parked record
    // below is waiting for the device's authorization confirmation, not for
    // admission; an unadmitted OPEN would have its close deferred until the
    // owner proves OPENED or REJECTED, so the bound under test would not be
    // observable as this stream's terminal state.
    admit_queued_open(&fixture, &mut target_rx, &target_session_id, target_epoch).await;
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

    // Keep the client stream open: only the consumer's one-second absolute
    // deadline may end the outstanding write.  A stranded handler would keep
    // this stream live far beyond the bound below.
    let owner_receive_before = fixture
        .handle
        .snapshot()
        .await
        .expect("outstanding-write baseline snapshot")
        .peer_consumer_diagnostics
        .owner_receive_count;
    let started = tokio::time::Instant::now();
    // Well past the two-second receive idle timeout, the parked stream is
    // still live and no receive outcome has been recorded against it.
    tokio::time::sleep(Duration::from_millis(3200)).await;
    let parked_snapshot = fixture
        .handle
        .snapshot()
        .await
        .expect("parked-past-idle snapshot");
    let parked_stream = find_session(&parked_snapshot, device_id())
        .expect("parked-past-idle target session after the idle window")
        .streams
        .iter()
        .find(|stream| stream.stream_id == target_stream_before.stream_id)
        .cloned()
        .expect("parked-past-idle target stream after the idle window");
    assert!(
        !parked_stream.terminal,
        "the receive idle timeout must not end a parked consumer write"
    );
    assert_eq!(
        parked_snapshot
            .peer_consumer_diagnostics
            .owner_receive_count,
        owner_receive_before,
        "no owner receive outcome may be recorded while the peer waits on the parked write"
    );
    let terminal_snapshot =
        wait_snapshot_for(&fixture.handle, Duration::from_secs(8), &mut |snapshot| {
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
    // The 3.2 s liveness check above is the lower bound that matters: it is
    // measured on a real clock and is well past the 2 s receive idle deadline
    // the parked read must outlive.  The consumer's own deadline runs from
    // token issue rather than from this instant, so no lower bound on the
    // total elapsed time here would be meaningful under load.
    assert!(
        started.elapsed() < Duration::from_secs(8),
        "the parked write must still end at the consumer's absolute deadline"
    );
    assert_eq!(
        terminal_snapshot
            .peer_consumer_diagnostics
            .owner_receive_count,
        owner_receive_before,
        "the consumer deadline, not a receive failure, must end the parked write"
    );
    assert_sibling_preserved(&terminal_snapshot, &sibling_session_id, sibling_epoch);
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    stream.cancel();
    drop(stream);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_ingress_response_read_outlives_the_receive_idle_timeout() {
    // M7-C70 regression, the ingress mirror of
    // `peer_consumer_outstanding_write_outlives_the_receive_idle_timeout`.
    // A saturated-but-healthy owner is legitimately silent while it queues
    // the consumer's response, so the ingress's read of that response must be
    // bounded by the consumer's absolute authorization deadline rather than
    // by the peer transport's two-second receive idle window.  The stub owner
    // holds its record past that window: the record must still arrive, the
    // read must then end at the consumer deadline rather than one idle window
    // after the record, and nothing may be cancelled in between.
    let fixture = H3PeerFixture::new_holding_owner().await;
    let owner = fixture
        .catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            tenant_id: tenant_id(),
            device_id: device_id(),
            node_id: DESTINATION_NODE.to_owned(),
            boot_id: DESTINATION_BOOT.to_owned(),
            session_id: "ingress-parked-response-owner".to_owned(),
            lease_expires_at: Utc::now() + ChronoDuration::minutes(5),
        })
        .await
        .expect("claim the staged remote owner");
    let route = fixture
        .runtime
        .resolve(OwnerScope::new(tenant_id(), device_id()), Utc::now())
        .await
        .expect("resolve the staged remote owner route");
    assert!(
        !route.is_local(),
        "the staged owner must route remotely so the ingress client path runs"
    );
    assert_eq!(route.owner_token(), &owner.token);

    let envelope = consumer_envelope(
        "ingress-parked-response-request",
        "ingress-parked-response-stream",
        route.owner_token(),
        &fixture.consumer_token,
    );
    let exchange = fixture
        .runtime
        .open(&route, envelope)
        .await
        .expect("open the staged ingress exchange");
    let (mut send, mut recv) = exchange.split();
    recv.accept_response()
        .await
        .expect("staged owner response head");

    let before = fixture
        .handle
        .snapshot()
        .await
        .expect("ingress parked-response baseline snapshot")
        .peer_consumer_diagnostics
        .ingress_receive_count;
    let stub_errors_before = fixture.returned_errors.load(Ordering::Acquire);
    let started = tokio::time::Instant::now();
    let consumer_deadline = started + INGRESS_CONSUMER_LIFETIME;

    // The owner holds well past the idle window.  Bounded by the idle
    // timeout this read fails with a transport timeout and resets the owner
    // with H3_REQUEST_CANCELLED; bounded by the consumer deadline it waits.
    let record = recv
        .recv_message_until(consumer_deadline)
        .await
        .expect("the held owner record must outlive the receive idle timeout")
        .expect("the staged owner sends one record before it goes silent");
    let held_for = started.elapsed();
    assert_eq!(record.kind(), PeerRecordKind::ConsumerChunk);
    assert_eq!(record.body(), INGRESS_HELD_BODY);
    assert!(
        held_for >= INGRESS_IDLE_WINDOW,
        "the record must have been withheld past the idle window, waited {held_for:?}"
    );
    assert_eq!(
        fixture.returned_errors.load(Ordering::Acquire),
        stub_errors_before,
        "the ingress must not have reset the parked owner while it waited"
    );
    assert_eq!(
        fixture
            .handle
            .snapshot()
            .await
            .expect("ingress parked-response snapshot after the record")
            .peer_consumer_diagnostics
            .ingress_receive_count,
        before,
        "no ingress receive cancellation diagnostic may be recorded while the owner is parked"
    );

    // The owner is now silent for good.  The read is ended by the consumer's
    // absolute deadline, not one idle window after the record above.
    let error = match recv.recv_message_until(consumer_deadline).await {
        Ok(_) => panic!("the silent owner must end the read at the consumer deadline"),
        Err(error) => error,
    };
    let total = started.elapsed();
    assert!(
        matches!(
            error,
            PeerRuntimeError::Transport(PeerTransportError::Timeout)
        ),
        "the deadline must surface as a transport timeout, got {error:?}"
    );
    assert!(
        total >= INGRESS_CONSUMER_LIFETIME.saturating_sub(INGRESS_DEADLINE_SLACK)
            && total >= held_for + INGRESS_IDLE_WINDOW,
        "the read must not end before the consumer deadline, ended after {total:?}"
    );
    assert!(
        total < INGRESS_CONSUMER_LIFETIME + INGRESS_DEADLINE_SLACK,
        "the read must still end at the consumer deadline, ended after {total:?}"
    );

    recv.cancel();
    send.cancel();
    drop(recv);
    drop(send);
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
    admit_queued_open(&fixture, &mut target_rx, &target_session_id, target_epoch).await;
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

// ---------------------------------------------------------------------------
// EC-049 owner-side negative: a peer whose envelope owner, scope, digest, or
// declared length is invalid must be refused before the owner reads or
// forwards any request body.  Each case drives the real production
// `peer_ingress_handler` behind a real HTTP/3 `PeerClient`, sends a body
// sentinel record immediately after the (invalid) envelope, and proves through
// the payload-free relay snapshot counters that the owner performed zero
// `ConsumerChunk` body reads and zero application dispatches before the typed
// rejection.  The consumer-ingress preflight is proven separately by
// `verify-m7-i04-fail-closed`; this closes the owner peer-leg negative.

/// One sentinel body record that must never be read or dispatched by the owner.
const OWNER_NEGATIVE_SENTINEL: &[u8] = b"ec049-owner-negative-body-sentinel";

/// Build a `ConsumerStreams` envelope with an explicit source identity and
/// owner token so a single case can corrupt exactly one field.
fn consumer_envelope_with_source(
    request_id: &str,
    stream_id: &str,
    source: PeerIdentity,
    owner: &OwnerToken,
    token: &str,
) -> RequestEnvelope {
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

/// Read the payload-free owner-side reads/dispatch counters.
async fn owner_leg_counters(handle: &RelayHandle) -> (u64, u64) {
    let snapshot = handle.snapshot().await.expect("owner-negative snapshot");
    (
        snapshot.lifetime_consumer_chunk_reads,
        snapshot.lifetime_application_dispatches,
    )
}

/// Drive one owner-side negative case: open a fresh raw peer stream, send the
/// pre-encoded first peer record (an invalid envelope, or an over-length
/// record), then the body sentinel, then finish.  Returns whether the owner
/// refused the request (a non-OK response, a response body error, or the raw
/// send failing because the owner reset the stream).
async fn drive_owner_negative_case(
    fixture: &H3PeerFixture,
    first_record: Bytes,
    sentinel_kind: PeerRecordKind,
) -> bool {
    let mut stream = open_raw(fixture, InternalRoute::ConsumerStreams).await;
    let mut refused = false;
    if timeout(Duration::from_secs(3), stream.send_chunk(first_record))
        .await
        .expect("owner-negative first-record deadline")
        .is_err()
    {
        refused = true;
    }
    if !refused {
        let sentinel = encode_peer_record(sentinel_kind, OWNER_NEGATIVE_SENTINEL);
        if timeout(Duration::from_secs(3), stream.send_chunk(sentinel))
            .await
            .expect("owner-negative sentinel deadline")
            .is_err()
        {
            refused = true;
        }
    }
    if !refused {
        let _ = timeout(Duration::from_secs(3), stream.finish()).await;
    }
    match timeout(Duration::from_secs(3), stream.recv_response()).await {
        Ok(Ok(response)) => {
            if !response.status().is_success() {
                refused = true;
            } else {
                // A 200 head is only acceptable if the owner nonetheless
                // failed the request before any body read; drain the body and
                // require it to error or end without ever dispatching.
                loop {
                    match timeout(Duration::from_secs(3), stream.recv_chunk()).await {
                        Ok(Ok(Some(_))) => {}
                        Ok(Ok(None)) => break,
                        Ok(Err(_)) => {
                            refused = true;
                            break;
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        Ok(Err(_)) => refused = true,
        Err(_) => {}
    }
    stream.cancel();
    drop(stream);
    refused
}

#[tokio::test]
async fn peer_owner_refuses_body_before_preflight_on_invalid_envelope() {
    let fixture = H3PeerFixture::new().await;
    // A live owner exists so a valid destination lookup is possible; the
    // negatives below still fail closed before any body is read.
    let _target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "ec049-owner-negative-owner",
    )
    .await;
    let owner = current_target_owner(&fixture).await;

    // Baseline: nothing has been read or dispatched from any peer body yet.
    let (reads_before, dispatches_before) = owner_leg_counters(&fixture.handle).await;
    assert_eq!(
        (reads_before, dispatches_before),
        (0, 0),
        "owner-negative baseline must start with zero peer body reads and dispatches"
    );

    // Case 1: a mismatched owner token (wrong session id) is refused before
    // the peer stream is split or any body sentinel is read.
    let mut wrong_owner = owner.token.clone();
    wrong_owner.session_id = format!("{}-mismatch", wrong_owner.session_id);
    let wrong_owner_envelope = consumer_envelope_with_source(
        "ec049-wrong-owner-request",
        "ec049-wrong-owner-stream",
        PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT),
        &wrong_owner,
        &fixture.consumer_token,
    );
    let refused = drive_owner_negative_case(
        &fixture,
        encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &wrong_owner_envelope
                .encode()
                .expect("encode wrong-owner envelope"),
        ),
        PeerRecordKind::ConsumerChunk,
    )
    .await;
    assert!(refused, "mismatched owner token must be refused");

    // Case 2: a bearer the owner cannot authenticate is refused; the owner
    // validates the JWT itself and never reads the request body on failure.
    let bad_bearer_envelope = consumer_envelope_with_source(
        "ec049-bad-bearer-request",
        "ec049-bad-bearer-stream",
        PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT),
        &owner.token,
        "ec049-not-a-valid-consumer-token",
    );
    let refused = drive_owner_negative_case(
        &fixture,
        encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &bad_bearer_envelope
                .encode()
                .expect("encode bad-bearer envelope"),
        ),
        PeerRecordKind::ConsumerChunk,
    )
    .await;
    assert!(refused, "unauthenticated consumer bearer must be refused");

    // Case 3: a source identity that does not match the authenticated peer
    // certificate is refused by the runtime before owner lookup.
    let wrong_source_envelope = consumer_envelope_with_source(
        "ec049-wrong-source-request",
        "ec049-wrong-source-stream",
        PeerIdentity::new("ec049-not-the-authenticated-node", SOURCE_BOOT),
        &owner.token,
        &fixture.consumer_token,
    );
    let refused = drive_owner_negative_case(
        &fixture,
        encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &wrong_source_envelope
                .encode()
                .expect("encode wrong-source envelope"),
        ),
        PeerRecordKind::ConsumerChunk,
    )
    .await;
    assert!(refused, "mismatched source identity must be refused");

    // Case 4: an over-length first record (declared length above the envelope
    // ceiling of 8 KiB) is refused before the JSON is decoded and before the
    // body sentinel is read.  The record is a legal control-text kind whose
    // body exceeds the envelope-record bound.
    let oversized_body = vec![0x5a_u8; 9_000];
    let refused = drive_owner_negative_case(
        &fixture,
        encode_peer_record(PeerRecordKind::CompleteControlText, &oversized_body),
        PeerRecordKind::ConsumerChunk,
    )
    .await;
    assert!(refused, "over-length envelope declaration must be refused");

    // Every negative case must have left the owner-side body-read and dispatch
    // counters untouched: no peer body was read and nothing was forwarded.
    let (reads_after, dispatches_after) = owner_leg_counters(&fixture.handle).await;
    assert_eq!(
        reads_after, 0,
        "owner performed a peer ConsumerChunk read despite an invalid envelope"
    );
    assert_eq!(
        dispatches_after, 0,
        "owner dispatched an application record despite an invalid envelope"
    );

    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_owner_refuses_device_body_on_bad_certificate_digest() {
    // The device routes resolve the forwarded certificate digest against the
    // active device catalog before any control/data record is read.  A digest
    // that does not resolve to an active device is refused with zero reads and
    // zero dispatches.
    let fixture = H3PeerFixture::new().await;
    let _target = register_control(&fixture, DEVICE_SPKI, device_id(), "ec049-digest-owner").await;
    let owner = current_target_owner(&fixture).await;

    let (reads_before, dispatches_before) = owner_leg_counters(&fixture.handle).await;
    assert_eq!((reads_before, dispatches_before), (0, 0));

    // A device-control envelope whose forwarded certificate carries a digest
    // that is not a registered active device.
    let now = Utc::now();
    let source = PeerIdentity::new(SOURCE_NODE, SOURCE_BOOT);
    let destination = Destination::new(owner.token.clone(), Uuid::nil());
    let authentication = DeviceAuthenticationContext {
        certificate: VerifiedDeviceCertificate {
            certificate_identity: device_id().to_string(),
            spki_fingerprint: "ec049eec049eec049eec049eec049eec049eec049eec049eec049eec049eec04"
                .to_owned(),
            serial: "ec049-bad-digest".to_owned(),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(5),
            tenant_id: tenant_id(),
            device_id: device_id(),
        },
        ingress: IngressRequestBinding {
            request_id: "ec049-bad-digest-request".to_owned(),
            source: source.clone(),
            destination: destination.clone(),
            expires_at: now + ChronoDuration::seconds(10),
        },
    };
    let envelope = RequestEnvelope::new(
        InternalRoute::DeviceControl,
        "ec049-bad-digest-request",
        source,
        destination,
        20_000,
        None,
        InternalRequest::DeviceControl(DeviceControlRequest {
            stream_id: "ec049-bad-digest-stream".to_owned(),
            authentication,
        }),
    );

    let mut stream = open_raw(&fixture, InternalRoute::DeviceControl).await;
    let mut refused = false;
    if timeout(
        Duration::from_secs(3),
        stream.send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode bad-digest envelope"),
        )),
    )
    .await
    .expect("bad-digest envelope deadline")
    .is_err()
    {
        refused = true;
    }
    if !refused {
        // A control-text body sentinel that must never be dispatched.
        let sentinel = encode_peer_record(PeerRecordKind::CompleteControlText, b"{}");
        let _ = timeout(Duration::from_secs(3), stream.send_chunk(sentinel)).await;
        let _ = timeout(Duration::from_secs(3), stream.finish()).await;
    }
    match timeout(Duration::from_secs(3), stream.recv_response()).await {
        Ok(Ok(response)) => refused = refused || !response.status().is_success(),
        Ok(Err(_)) => refused = true,
        Err(_) => {}
    }
    stream.cancel();
    drop(stream);
    assert!(
        refused,
        "a device certificate with a bad digest must be refused"
    );

    let (reads_after, dispatches_after) = owner_leg_counters(&fixture.handle).await;
    assert_eq!(reads_after, 0);
    assert_eq!(
        dispatches_after, 0,
        "a bad device digest must not reach application dispatch"
    );

    fixture.shutdown().await;
}

// ---------------------------------------------------------------------------
// EC-045 / EC-046: duplex independence on the owner-side peer path.
// ---------------------------------------------------------------------------

/// One admitted forwarded consumer stream with its connector-side queues, the
/// accepted OPEN, and an independently live sibling.  Both duplex cases below
/// start from exactly this state.
struct AdmittedConsumerStream {
    target_session_id: String,
    target_epoch: u64,
    target_rx: mpsc::Receiver<ControlOutbound>,
    target_data_rx: mpsc::Receiver<DataOutbound>,
    sibling_session_id: String,
    sibling_epoch: u64,
    _sibling_rx: mpsc::Receiver<ControlOutbound>,
    stream: Option<PeerClientStream>,
    open: tunnel_protocol::Open,
    request_id: String,
    target_stream: RelayStreamSnapshot,
    sibling_before: RelaySessionSnapshot,
}

async fn admit_consumer_with_open(
    fixture: &H3PeerFixture,
    token: &str,
    label: &str,
) -> AdmittedConsumerStream {
    let target = register_control(
        fixture,
        DEVICE_SPKI,
        device_id(),
        &format!("{label}-target"),
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
        .expect("resolve duplex target device")
        .expect("duplex target device identity");
    let target_data = fixture
        .handle
        .attach_forwarded_data(target_device, DEVICE_SPKI.to_owned(), target_ticket)
        .await
        .expect("attach duplex target carrier");
    let mut target_data_rx = target_data.rx;

    let sibling = register_control(
        fixture,
        SIBLING_SPKI,
        sibling_device_id(),
        &format!("{label}-sibling"),
    )
    .await;
    let sibling_session_id = sibling.session_id.clone();
    let sibling_epoch = sibling.epoch;
    let sibling_rx = sibling.rx;

    let owner = current_target_owner(fixture).await;
    let request_id = format!("{label}-request");
    let mut stream = open_raw(fixture, InternalRoute::ConsumerStreams).await;
    admit_consumer(
        &mut stream,
        &owner.token,
        token,
        &request_id,
        &format!("{label}-stream"),
    )
    .await;
    let open = admit_queued_open(fixture, &mut target_rx, &target_session_id, target_epoch).await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.streams.len() == 1
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let target_stream = find_session(&admitted, device_id())
        .expect("duplex target session after admission")
        .streams
        .first()
        .expect("duplex target stream after admission")
        .clone();
    assert!(!target_stream.terminal);
    assert_eq!(target_stream.stream_id, open.stream_id);
    let sibling_before = find_session(&admitted, sibling_device_id())
        .expect("duplex sibling after admission")
        .clone();
    drain_queues(&mut target_rx, &mut target_data_rx).await;

    AdmittedConsumerStream {
        target_session_id,
        target_epoch,
        target_rx,
        target_data_rx,
        sibling_session_id,
        sibling_epoch,
        _sibling_rx: sibling_rx,
        stream: Some(stream),
        open,
        request_id,
        target_stream,
        sibling_before,
    }
}

/// One complete length-prefixed application record carried as a peer
/// ConsumerChunk.  The body is synthetic test data.
fn application_record(body: &[u8]) -> Bytes {
    let mut record = (body.len() as u32).to_be_bytes().to_vec();
    record.extend_from_slice(body);
    encode_peer_record(PeerRecordKind::ConsumerChunk, &record)
}

/// Wait until the connector data carrier receives a frame of `kind` for
/// `stream_id`, releasing every queue charge on the way.
async fn wait_data_frame(
    data_rx: &mut mpsc::Receiver<DataOutbound>,
    stream_id: u64,
    kind: tunnel_protocol::frame::FrameKind,
    deadline: Duration,
) {
    timeout(deadline, async {
        loop {
            match data_rx
                .recv()
                .await
                .expect("duplex data carrier remains live")
            {
                DataOutbound::Binary(bytes) => {
                    let (bytes, mut charge) = bytes.into_parts();
                    charge.release();
                    let frame = wire::decode_frame(&bytes).expect("carrier frame decodes");
                    if frame.stream_id == stream_id && frame.kind == kind {
                        break;
                    }
                }
                DataOutbound::Barrier(done) => {
                    let _ = done.send(());
                }
                DataOutbound::Close => panic!("duplex data carrier closed before {kind:?}"),
            }
        }
    })
    .await
    .unwrap_or_else(|_| panic!("connector carrier must receive {kind:?} for stream {stream_id}"));
}

fn assert_owner_receive_recorded(
    snapshot: &RelaySnapshot,
    admitted: &AdmittedConsumerStream,
    owner_receive_before: u64,
    owner_send_before: u64,
    outcome: PeerTransportDiagnosticOutcome,
    h3_code: Option<PeerConsumerDiagnosticH3Code>,
) {
    let diagnostics = &snapshot.peer_consumer_diagnostics;
    assert_eq!(
        diagnostics.owner_receive_count,
        owner_receive_before + 1,
        "exactly one owner receive outcome must be recorded"
    );
    let last = diagnostics
        .last_owner_receive
        .as_ref()
        .expect("owner receive diagnostic");
    assert_eq!(last.role, PeerConsumerDiagnosticRole::OwnerReceive);
    assert_eq!(last.outcome, outcome);
    assert_eq!(last.h3_code, h3_code);
    assert_eq!(last.request_id, admitted.request_id);
    assert_eq!(last.session_id, admitted.target_session_id);
    assert_eq!(last.epoch, admitted.target_epoch);
    assert_eq!(last.device_id, device_id());
    assert_eq!(last.service_id, service_id());
    // The owner cancelled its own send direction; that local cancellation is
    // never recorded as a failed remote write.
    assert_eq!(
        diagnostics.owner_send_count, owner_send_before,
        "a locally cancelled send direction must not be reported as a remote send failure"
    );
}

fn assert_stream_closed_event(snapshot: &RelaySnapshot, admitted: &AdmittedConsumerStream) {
    assert!(
        snapshot.stream_terminal_events.iter().any(|event| {
            event.stream_id == admitted.open.stream_id
                && event.operation_id == admitted.target_stream.operation_id
                && event.session_id == admitted.target_session_id
                && event.epoch == admitted.target_epoch
                && event.request_id.as_deref() == Some(admitted.request_id.as_str())
                && event.reason == "STREAM_CLOSED"
                && event.cause.is_none()
        }),
        "the owner must retain the exact STREAM_CLOSED event for the cancelled stream"
    );
}

/// EC-045: a cancellation on the receive direction while the send direction is
/// parked on an actor write.  The parked write can never complete because the
/// connector never answers the stream's authorization challenge, so only the
/// owner's own handling of the receive direction can end it before the
/// consumer's absolute deadline.
#[tokio::test]
async fn peer_consumer_receive_cancel_releases_parked_send_direction_before_deadline() {
    let fixture = H3PeerFixture::new().await;
    // The consumer deadline is deliberately far beyond the prompt bound below;
    // a handler that only honours the cancel at that deadline fails the case.
    let token = fixture.mint_consumer_token(8);
    let mut admitted = admit_consumer_with_open(&fixture, &token, "ec045").await;
    let before = fixture
        .handle
        .snapshot()
        .await
        .expect("duplex baseline snapshot");
    let reads_before = before.lifetime_consumer_chunk_reads;
    let dispatches_before = before.lifetime_application_dispatches;
    let owner_receive_before = before.peer_consumer_diagnostics.owner_receive_count;
    let owner_send_before = before.peer_consumer_diagnostics.owner_send_count;
    let returned_before = fixture.returned_errors.load(Ordering::Acquire);

    // Park the send direction: the owner reads the record and awaits the actor
    // write that waits for an authorization confirmation which never comes.
    admitted
        .stream
        .as_mut()
        .expect("client stream is still whole")
        .send_chunk(application_record(b"ec045-parked-record"))
        .await
        .expect("send the record that parks the owner write");
    let parked = wait_snapshot(&fixture.handle, |snapshot| {
        snapshot.lifetime_consumer_chunk_reads > reads_before
    })
    .await;
    assert_eq!(parked.lifetime_application_dispatches, dispatches_before);
    assert!(
        find_session(&parked, device_id()).is_some_and(|session| {
            session
                .streams
                .iter()
                .any(|stream| stream.stream_id == admitted.open.stream_id && !stream.terminal)
        }),
        "the stream must still be live while the write is parked"
    );

    // Cancel only the receive direction (the request body).  The response
    // direction stays open on the client so nothing but the owner itself can
    // release the parked send direction.
    let (mut client_send, mut client_recv) = admitted
        .stream
        .take()
        .expect("client stream is still whole")
        .split();
    let cancelled_at = tokio::time::Instant::now();
    client_send.cancel();

    // The parked direction is released: the handler exits, the exact stream
    // is terminal, and both happen well below the eight-second deadline.
    wait_handler_error(&fixture, returned_before).await;
    let terminal_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == admitted.target_session_id
                && session.epoch == admitted.target_epoch
                && session.streams.iter().any(|stream| {
                    stream.stream_id == admitted.open.stream_id
                        && stream.operation_id == admitted.target_stream.operation_id
                        && stream.terminal
                })
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    let honoured_after = cancelled_at.elapsed();
    assert!(
        honoured_after < Duration::from_millis(1500),
        "the receive-direction cancel must be honoured promptly, not at the deadline; observed {honoured_after:?}"
    );

    // The owner records the cancellation outcome on the receive direction and
    // never dispatched the parked record with an unknown outcome.
    assert_owner_receive_recorded(
        &terminal_snapshot,
        &admitted,
        owner_receive_before,
        owner_send_before,
        PeerTransportDiagnosticOutcome::H3Error,
        Some(PeerConsumerDiagnosticH3Code::RequestCancelled),
    );
    assert_eq!(
        terminal_snapshot.lifetime_application_dispatches, dispatches_before,
        "a record abandoned by the cancel must not be dispatched"
    );

    // The blocked send direction was released by the cancel: the client's
    // still-open response half observes the owner's reset promptly instead of
    // idling until the consumer deadline.
    let response_half = timeout(Duration::from_millis(1500), client_recv.recv_chunk())
        .await
        .expect("the owner must release the parked send direction promptly");
    assert!(
        matches!(
            &response_half,
            Err(PeerTransportError::H3(message)) if message.contains("H3_REQUEST_CANCELLED")
        ),
        "the released send direction must be a local cancellation, observed {response_half:?}"
    );

    // Close and owner events were not suppressed by the blocked direction: the
    // connector carrier receives the stream's FIN and the owner retains the
    // exact terminal event, while the sibling is untouched.
    wait_data_frame(
        &mut admitted.target_data_rx,
        admitted.open.stream_id,
        tunnel_protocol::frame::FrameKind::Fin,
        Duration::from_millis(1500),
    )
    .await;
    assert_stream_closed_event(&terminal_snapshot, &admitted);
    assert_eq!(
        find_session(&terminal_snapshot, sibling_device_id())
            .expect("sibling survives")
            .session_id,
        admitted.sibling_before.session_id
    );
    assert_sibling_preserved(
        &terminal_snapshot,
        &admitted.sibling_session_id,
        admitted.sibling_epoch,
    );
    drain_queues(&mut admitted.target_rx, &mut admitted.target_data_rx).await;

    client_recv.cancel();
    drop(client_send);
    drop(client_recv);
    fixture.shutdown().await;
}

/// EC-046 in one scenario on the owner-side peer path: a safe record is
/// decoded and delivered to the connector carrier, then a malformed record
/// surfaces the decoder's typed bounded failure while the safe record's write
/// is still outstanding.  The owner must cancel both halves, join the
/// handler, and report its own cancellation as local rather than as a remote
/// rejection.
#[tokio::test]
async fn peer_consumer_decode_failure_drains_safe_events_and_cancels_both_halves() {
    let fixture = H3PeerFixture::new().await;
    let token = fixture.mint_consumer_token(8);
    let mut admitted = admit_consumer_with_open(&fixture, &token, "ec046").await;
    let before = fixture
        .handle
        .snapshot()
        .await
        .expect("duplex baseline snapshot");
    let reads_before = before.lifetime_consumer_chunk_reads;
    let dispatches_before = before.lifetime_application_dispatches;
    let owner_receive_before = before.peer_consumer_diagnostics.owner_receive_count;
    let owner_send_before = before.peer_consumer_diagnostics.owner_send_count;
    let returned_before = fixture.returned_errors.load(Ordering::Acquire);

    // 1. One safe record.  The owner decodes it and starts the actor write.
    admitted
        .stream
        .as_mut()
        .expect("client stream is still whole")
        .send_chunk(application_record(b"ec046-safe-record"))
        .await
        .expect("send the safe record");
    wait_snapshot(&fixture.handle, |snapshot| {
        snapshot.lifetime_consumer_chunk_reads > reads_before
    })
    .await;

    // 2. The connector answers the authorization challenge, so the safe
    //    record is dispatched to the carrier.  The connector never echoes, so
    //    the owner's write for it stays outstanding.
    let open = &admitted.open;
    let challenge = tunnel_protocol::AuthorizationChallenge::new(
        "ec046-challenge",
        admitted.target_session_id.clone(),
        admitted.target_epoch,
        open.stream_id,
        "ec046-challenge-id",
        "ec046-nonce",
        open.service_id.clone(),
        open.metadata
            .get("permission_digest")
            .expect("OPEN permission digest")
            .clone(),
        open.metadata
            .get("grant_revision")
            .expect("OPEN grant revision")
            .parse()
            .expect("grant revision"),
    );
    let key = crate::actor::SessionKey {
        tenant_id: tenant_id(),
        device_id: device_id(),
        session_id: admitted.target_session_id.clone(),
        epoch: admitted.target_epoch,
    };
    fixture
        .handle
        .inbound_control(key, ControlMessage::AuthorizationChallenge(challenge))
        .await
        .expect("deliver authorization challenge");
    wait_data_frame(
        &mut admitted.target_data_rx,
        open.stream_id,
        tunnel_protocol::frame::FrameKind::Data,
        Duration::from_secs(3),
    )
    .await;
    let delivered = wait_snapshot(&fixture.handle, |snapshot| {
        snapshot.lifetime_application_dispatches > dispatches_before
    })
    .await;
    assert_eq!(
        delivered.lifetime_application_dispatches,
        dispatches_before + 1
    );
    assert_eq!(
        fixture.returned_errors.load(Ordering::Acquire),
        returned_before
    );

    // 3. A malformed record (unassigned kind byte) followed, in the same
    //    chunk, by a well-formed record that must never be dispatched.
    let mut malformed = Vec::with_capacity(8);
    malformed.extend_from_slice(&0_u32.to_be_bytes());
    malformed.extend_from_slice(&[0x7f, 0, 0, 0]);
    malformed.extend_from_slice(&application_record(b"ec046-must-not-dispatch"));
    admitted
        .stream
        .as_mut()
        .expect("client stream is still whole")
        .send_chunk(Bytes::from(malformed))
        .await
        .expect("send the malformed record");

    // The decoder surfaces its typed bounded failure while the safe record's
    // write is outstanding; the handler returns and the stream is terminal.
    wait_handler_error(&fixture, returned_before).await;
    let terminal_snapshot = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == admitted.target_session_id
                && session.epoch == admitted.target_epoch
                && session.streams.iter().any(|stream| {
                    stream.stream_id == admitted.open.stream_id
                        && stream.operation_id == admitted.target_stream.operation_id
                        && stream.terminal
                })
        }) && find_session(snapshot, sibling_device_id()).is_some()
    })
    .await;
    assert_owner_receive_recorded(
        &terminal_snapshot,
        &admitted,
        owner_receive_before,
        owner_send_before,
        PeerTransportDiagnosticOutcome::ProtocolError,
        None,
    );
    // Exactly the safe record was read and dispatched; nothing after the
    // malformed record was counted or dispatched.
    assert_eq!(
        terminal_snapshot.lifetime_consumer_chunk_reads,
        reads_before + 1
    );
    assert_eq!(
        terminal_snapshot.lifetime_application_dispatches,
        dispatches_before + 1
    );

    // Both halves are cancelled.  On the client each half observes the
    // owner's local cancellation as a reset, never as a not-processed
    // rejection (GoAway) or a transport timeout.
    let (mut client_send, mut client_recv) = admitted
        .stream
        .take()
        .expect("client stream is still whole")
        .split();
    let response_half = timeout(Duration::from_secs(3), client_recv.recv_chunk())
        .await
        .expect("the owner must cancel its send half promptly");
    assert!(
        matches!(
            &response_half,
            Err(PeerTransportError::H3(message)) if message.contains("H3_REQUEST_CANCELLED")
        ),
        "the owner's send half must be a local cancellation, observed {response_half:?}"
    );
    let request_half = timeout(Duration::from_secs(3), async {
        loop {
            match client_send
                .send_chunk(application_record(b"ec046-after-cancel"))
                .await
            {
                Ok(()) => tokio::task::yield_now().await,
                Err(error) => break error,
            }
        }
    })
    .await
    .expect("the owner must cancel its receive half promptly");
    assert!(
        !matches!(
            request_half,
            PeerTransportError::GoAway | PeerTransportError::Timeout
        ),
        "the owner's receive half must not be reported as a rejection or timeout, observed {request_half:?}"
    );

    // The close reached the connector and the owner retained the exact
    // terminal event; the sibling is untouched.
    wait_data_frame(
        &mut admitted.target_data_rx,
        admitted.open.stream_id,
        tunnel_protocol::frame::FrameKind::Fin,
        Duration::from_secs(3),
    )
    .await;
    assert_stream_closed_event(&terminal_snapshot, &admitted);
    assert_sibling_preserved(
        &terminal_snapshot,
        &admitted.sibling_session_id,
        admitted.sibling_epoch,
    );
    drain_queues(&mut admitted.target_rx, &mut admitted.target_data_rx).await;

    // Joined: the handler already returned; the server and runtime shut down
    // within their bounded deadlines with no stranded stream task.
    drop(client_send);
    drop(client_recv);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_control_refusal_responds_and_preserves_the_connection_sibling_carrier() {
    // The forwarded control path has the same shape as the forwarded data path
    // and the same defect.  A duplicate owner claim is an ordinary refusal:
    // this relay already holds a session for the device, so a second forwarded
    // HELLO is answered `OwnerBusy`.  Returning there without ever sending
    // response headers finishes the HTTP/3 request stream bare, which the
    // ingress relay's client raises as a CONNECTION-level error and which
    // takes every other forwarded carrier on that connection down with it.
    //
    // This admits a healthy data carrier first, then presents a second
    // forwarded HELLO for the same device over the same peer connection.  The
    // refusal must be a responded, stream-scoped outcome and the healthy
    // carrier must still be attached afterwards.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-refusal-control-target",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;

    let owner = current_target_owner(&fixture).await;
    let mut carrier = open_raw(&fixture, InternalRoute::DeviceData).await;
    admit_device_data(
        &mut carrier,
        &owner.token,
        &target_ticket,
        "staged-refusal-control-request",
        "staged-refusal-control-stream",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    let carrier_before = find_session(&admitted, device_id())
        .expect("refusal target session after admission")
        .clone();
    drain_control_queue(&mut target_rx).await;

    // A second forwarded HELLO for a device this relay already owns.
    let mut refused = open_raw(&fixture, InternalRoute::DeviceControl).await;
    let envelope = device_envelope(
        InternalRoute::DeviceControl,
        "staged-refusal-duplicate-request",
        "staged-refusal-duplicate-stream",
        &owner.token,
    );
    refused
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope
                .encode()
                .expect("encode duplicate control envelope"),
        ))
        .await
        .expect("send duplicate control envelope");
    let mut hello = Hello::new(
        "staged-refusal-duplicate-hello",
        device_id().to_string(),
        1,
        0,
    );
    hello.features = vec![
        wire::M1_PROFILE_FEATURE.to_owned(),
        wire::ORDERED_ROTATION_FEATURE.to_owned(),
        "echo".to_owned(),
    ];
    refused
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            wire::encode_control_message(&ControlMessage::Hello(hello))
                .expect("encode duplicate HELLO")
                .as_bytes(),
        ))
        .await
        .expect("send duplicate HELLO");

    let response = timeout(Duration::from_secs(3), refused.recv_response())
        .await
        .expect("refused control response deadline")
        .expect("a refused forwarded control attach must answer with response headers");
    assert!(
        !response.status().is_success(),
        "a refused forwarded control attach must report a non-success status, got {}",
        response.status()
    );

    // The healthy carrier on the same connection is untouched.
    let after = wait_snapshot_for(&fixture.handle, Duration::from_secs(3), &mut |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    let carrier_after = find_session(&after, device_id())
        .expect("refusal target session survives the duplicate control claim");
    assert_eq!(
        carrier_after.active_generation, carrier_before.active_generation,
        "a refused control attach must not disturb the installed carrier generation"
    );
    assert_eq!(
        carrier_after.active_connection_id, carrier_before.active_connection_id,
        "a refused control attach must not disturb the installed carrier identity"
    );
    assert_eq!(
        carrier_after.phase, carrier_before.phase,
        "a refused control attach must not move the session out of its phase"
    );

    refused.cancel();
    drop(refused);
    carrier.cancel();
    drop(carrier);
    fixture.shutdown().await;
}

#[tokio::test]
async fn peer_device_data_refusal_responds_and_preserves_the_connection_sibling_carrier() {
    // A refused forwarded device data attachment is an ordinary outcome, not a
    // peer protocol violation.  The owner must answer it with response headers
    // and finish that one request stream.  Finishing the stream without ever
    // responding makes the ingress relay's HTTP/3 client raise a
    // CONNECTION-level `H3_FRAME_UNEXPECTED`, which tears down the shared peer
    // connection to this owner and takes every other forwarded carrier
    // multiplexed on it with it -- including a healthy installed one, whose
    // loss the owner then reports as `RECOVERY_START_FAILED`.
    //
    // So this opens a healthy carrier first, then presents the same
    // already-consumed ticket on a second request over the same connection.
    // The refusal must be a responded, stream-scoped outcome and the healthy
    // carrier must still be attached afterwards.
    let fixture = H3PeerFixture::new().await;
    let target = register_control(
        &fixture,
        DEVICE_SPKI,
        device_id(),
        "staged-refusal-data-target",
    )
    .await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;

    let owner = current_target_owner(&fixture).await;
    let mut carrier = open_raw(&fixture, InternalRoute::DeviceData).await;
    admit_device_data(
        &mut carrier,
        &owner.token,
        &target_ticket,
        "staged-refusal-data-request",
        "staged-refusal-data-stream",
    )
    .await;
    let admitted = wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    let carrier_before = find_session(&admitted, device_id())
        .expect("refusal target session after admission")
        .clone();
    drain_control_queue(&mut target_rx).await;

    // The one-use ticket above is now spent.  Present it again on a second
    // request over the same peer connection.
    let mut refused = open_raw(&fixture, InternalRoute::DeviceData).await;
    let envelope = device_envelope(
        InternalRoute::DeviceData,
        "staged-refusal-reuse-request",
        "staged-refusal-reuse-stream",
        &owner.token,
    );
    refused
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode refused data envelope"),
        ))
        .await
        .expect("send refused data envelope");
    refused
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            format!("Bearer {target_ticket}").as_bytes(),
        ))
        .await
        .expect("send refused data ticket");

    let response = timeout(Duration::from_secs(3), refused.recv_response())
        .await
        .expect("refused data response deadline")
        .expect("a refused forwarded data attach must answer with response headers");
    assert!(
        !response.status().is_success(),
        "a refused forwarded data attach must report a non-success status, got {}",
        response.status()
    );

    // The healthy carrier on the same connection is untouched: same session,
    // same epoch, still two sockets, same active carrier identity.
    let after = wait_snapshot_for(&fixture.handle, Duration::from_secs(3), &mut |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    let carrier_after =
        find_session(&after, device_id()).expect("refusal target session survives the refusal");
    assert_eq!(
        carrier_after.active_generation, carrier_before.active_generation,
        "a refused attach must not disturb the installed carrier generation"
    );
    assert_eq!(
        carrier_after.active_connection_id, carrier_before.active_connection_id,
        "a refused attach must not disturb the installed carrier identity"
    );
    assert_eq!(
        carrier_after.phase, carrier_before.phase,
        "a refused attach must not move the session out of its phase"
    );

    refused.cancel();
    drop(refused);
    carrier.cancel();
    drop(carrier);
    fixture.shutdown().await;
}

/// Which pre-admission refusal the staged owner answers with.
#[derive(Clone, Copy)]
enum StagedOwnerRefusal {
    OwnerNotReady,
    RotationFreeze,
}

/// An owner that runs the production peer admission and then refuses the
/// request before any body record, exactly as the owner handlers do for a
/// `RelayError::OwnerNotReady` or `RelayError::RotationFreeze` admission
/// answer (task row M3-15).
struct RefusingOwnerHandler {
    runtime: Arc<PeerRuntime>,
    refusal: StagedOwnerRefusal,
    returned_errors: Arc<AtomicUsize>,
}

impl PeerRequestHandler for RefusingOwnerHandler {
    fn handle(
        &self,
        identity: TlsIdentity,
        request: Request<()>,
        stream: PeerServerStream,
    ) -> PeerHandlerFuture {
        let runtime = Arc::clone(&self.runtime);
        let refusal = self.refusal;
        let returned_errors = Arc::clone(&self.returned_errors);
        Box::pin(async move {
            let result = async {
                let inbound = runtime
                    .accept_inbound(identity, request, stream)
                    .await
                    .map_err(|error| PeerTransportError::H3(error.to_string()))?;
                match refusal {
                    StagedOwnerRefusal::OwnerNotReady => inbound.reject_owner_not_ready().await,
                    StagedOwnerRefusal::RotationFreeze => inbound.reject_rotation_freeze().await,
                }
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

/// Over real HTTP/3, the owner's scheduled-freeze refusal reaches the ingress
/// as its own typed error and the consumer as `ROTATION_FREEZE`, while the
/// fault refusal still arrives as `OwnerNotReady` and the old body (task row
/// M3-15).  Witness: before the distinct marker the owner could only send the
/// owner-not-ready marker, so the freeze arm below could not be told apart.
#[tokio::test]
async fn forwarded_rotation_freeze_refusal_keeps_its_distinct_reason() {
    for refusal in [
        StagedOwnerRefusal::RotationFreeze,
        StagedOwnerRefusal::OwnerNotReady,
    ] {
        let fixture = H3PeerFixture::new_with(
            move |runtime, _handle, _catalog, _oidc, _device, returned_errors| {
                RefusingOwnerHandler {
                    runtime,
                    refusal,
                    returned_errors,
                }
            },
        )
        .await;
        let owner = fixture
            .catalog
            .claim_owner(&OwnerClaimRequest {
                deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
                tenant_id: tenant_id(),
                device_id: device_id(),
                node_id: DESTINATION_NODE.to_owned(),
                boot_id: DESTINATION_BOOT.to_owned(),
                session_id: "forwarded-freeze-owner".to_owned(),
                lease_expires_at: Utc::now() + ChronoDuration::minutes(5),
            })
            .await
            .expect("claim the staged remote owner");
        let route = fixture
            .runtime
            .resolve(OwnerScope::new(tenant_id(), device_id()), Utc::now())
            .await
            .expect("resolve the staged remote owner route");
        assert!(!route.is_local());
        assert_eq!(route.owner_token(), &owner.token);
        let envelope = consumer_envelope(
            "forwarded-freeze-request",
            "forwarded-freeze-stream",
            route.owner_token(),
            &fixture.consumer_token,
        );
        let exchange = fixture
            .runtime
            .open(&route, envelope)
            .await
            .expect("open the staged ingress exchange");
        let (_send, mut recv) = exchange.split();
        let error = recv
            .accept_response()
            .await
            .expect_err("the staged owner refuses before admission");
        let body = match (refusal, &error) {
            (
                StagedOwnerRefusal::RotationFreeze,
                PeerRuntimeError::RotationFreeze {
                    retry_after_ms: 250,
                },
            )
            | (
                StagedOwnerRefusal::OwnerNotReady,
                PeerRuntimeError::OwnerNotReady {
                    retry_after_ms: 250,
                },
            ) => {
                let response = crate::http::peer_failure_response(error);
                assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
                assert_eq!(
                    response
                        .headers()
                        .get(axum::http::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok()),
                    Some("1")
                );
                let body = axum::body::to_bytes(response.into_body(), 1024)
                    .await
                    .expect("bounded refusal body");
                serde_json::from_slice::<serde_json::Value>(&body).expect("refusal JSON")
            }
            (_, other) => panic!("unexpected ingress error {other:?}"),
        };
        assert_eq!(body["execution"], "not_dispatched");
        assert_eq!(body["retryable"], true);
        match refusal {
            StagedOwnerRefusal::RotationFreeze => assert_eq!(body["code"], "ROTATION_FREEZE"),
            StagedOwnerRefusal::OwnerNotReady => {
                assert_eq!(body["code"], "PEER_UNAVAILABLE");
                assert_eq!(
                    body["message"],
                    "selected owner is not ready; retry after the bounded hint"
                );
            }
        }
        fixture.shutdown().await;
    }
}

/// Task row M7-C110, at the owner.  A forwarded request whose envelope names
/// an owner token this relay no longer holds (a superseded session of the same
/// owner relay) must be answered on its own stream with the typed, retryable
/// `OWNER_CHANGED` admission marker.  Before the fix the owner returned before
/// any response, quinn finished the stream bare, and the ingress's HTTP/3
/// client raised `H3_FRAME_UNEXPECTED` as a CONNECTION error, taking down every
/// other request multiplexed on that peer connection.  So a healthy carrier is
/// opened first on the same connection and must survive the refusal.
#[tokio::test]
async fn a_superseded_owner_token_is_refused_owner_changed_on_its_own_stream() {
    let fixture = H3PeerFixture::new().await;
    let target = register_control(&fixture, DEVICE_SPKI, device_id(), "m7c110-target").await;
    let target_session_id = target.session_id.clone();
    let target_epoch = target.epoch;
    let target_ticket = target.ticket.clone();
    let mut target_rx = target.rx;

    let owner = current_target_owner(&fixture).await;
    let mut carrier = open_raw(&fixture, InternalRoute::DeviceData).await;
    admit_device_data(
        &mut carrier,
        &owner.token,
        &target_ticket,
        "m7c110-carrier-request",
        "m7c110-carrier-stream",
    )
    .await;
    wait_snapshot(&fixture.handle, |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    drain_control_queue(&mut target_rx).await;

    // The same owner relay, an earlier session: a token the catalog no
    // longer names, exactly what a stale ingress route cache carries.
    let mut superseded = owner.token.clone();
    superseded.session_id = "m7c110-superseded-session".to_owned();
    let mut refused = open_raw(&fixture, InternalRoute::DeviceData).await;
    let envelope = device_envelope(
        InternalRoute::DeviceData,
        "m7c110-superseded-request",
        "m7c110-superseded-stream",
        &superseded,
    );
    refused
        .send_chunk(encode_peer_record(
            PeerRecordKind::CompleteControlText,
            &envelope.encode().expect("encode superseded envelope"),
        ))
        .await
        .expect("send superseded envelope");

    let response = timeout(Duration::from_secs(3), refused.recv_response())
        .await
        .expect("superseded request response deadline")
        .expect("a superseded owner token must be answered with response headers");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let header = |name: &str| {
        response
            .headers()
            .get(name)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned)
    };
    assert_eq!(
        header("x-agent-tunnel-admission").as_deref(),
        Some("owner_changed")
    );
    assert_eq!(
        header("x-agent-tunnel-execution").as_deref(),
        Some("not_dispatched")
    );
    assert_eq!(header("x-agent-tunnel-retryable").as_deref(), Some("true"));

    // The healthy carrier multiplexed on the same peer connection survives.
    let after = wait_snapshot_for(&fixture.handle, Duration::from_secs(3), &mut |snapshot| {
        find_session(snapshot, device_id()).is_some_and(|session| {
            session.session_id == target_session_id
                && session.epoch == target_epoch
                && session.sockets == 2
        })
    })
    .await;
    assert!(find_session(&after, device_id()).is_some());

    refused.cancel();
    drop(refused);
    carrier.cancel();
    drop(carrier);
    fixture.shutdown().await;
}

/// Task row M7-C110, at the ingress.  The ingress resolved and cached an
/// owner route; the device then reattached to the same owner relay under a new
/// epoch.  Opening through the stale route reaches the production owner, which
/// refuses `OWNER_CHANGED`; the ingress must surface the typed, retryable,
/// `not_dispatched` outcome and drop the cached route so the consumer's retry
/// performs a fresh lookup.  Before the fix the refusal was a connection-level
/// HTTP/3 error, the consumer saw an `unknown` outcome, and the stale route
/// stayed cached.
#[tokio::test]
async fn the_ingress_drops_a_stale_route_on_owner_changed_and_answers_typed() {
    let fixture = H3PeerFixture::new().await;
    let claim = |session_id: &str| OwnerClaimRequest {
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        tenant_id: tenant_id(),
        device_id: device_id(),
        node_id: DESTINATION_NODE.to_owned(),
        boot_id: DESTINATION_BOOT.to_owned(),
        session_id: session_id.to_owned(),
        lease_expires_at: Utc::now() + ChronoDuration::minutes(5),
    };
    let first = fixture
        .catalog
        .claim_owner(&claim("m7c110-first"))
        .await
        .expect("claim the first owner session");
    let scope = OwnerScope::new(tenant_id(), device_id());
    let stale_route = fixture
        .runtime
        .resolve(scope, Utc::now())
        .await
        .expect("resolve and cache the first owner route");
    assert_eq!(stale_route.owner_token(), &first.token);
    assert_eq!(
        fixture
            .runtime
            .owner_router()
            .cached_owner_epoch(scope)
            .await,
        Some(first.token.epoch),
        "the ingress cached the first route"
    );

    assert!(
        fixture
            .catalog
            .release_owner(&first.token)
            .await
            .expect("release the first owner session")
    );
    let second = fixture
        .catalog
        .claim_owner(&claim("m7c110-second"))
        .await
        .expect("claim the second owner session");
    assert!(second.token.epoch > first.token.epoch);

    let envelope = consumer_envelope(
        "m7c110-stale-request",
        "m7c110-stale-stream",
        stale_route.owner_token(),
        &fixture.consumer_token,
    );
    let exchange = fixture
        .runtime
        .open(&stale_route, envelope)
        .await
        .expect("open through the stale route");
    let (_send, mut recv) = exchange.split();
    let error = timeout(Duration::from_secs(3), recv.accept_response())
        .await
        .expect("stale route response deadline")
        .expect_err("the owner refuses a superseded owner token");
    assert!(
        matches!(
            error,
            PeerRuntimeError::OwnerChanged {
                retry_after_ms: 250
            }
        ),
        "unexpected ingress error {error:?}"
    );
    assert_eq!(
        fixture
            .runtime
            .owner_router()
            .cached_owner_epoch(scope)
            .await,
        None,
        "OWNER_CHANGED must drop the stale cached route"
    );
    let response = crate::http::peer_failure_response(error);
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = axum::body::to_bytes(response.into_body(), 1024)
        .await
        .expect("bounded refusal body");
    let body: serde_json::Value = serde_json::from_slice(&body).expect("refusal JSON");
    assert_eq!(body["code"], "OWNER_CHANGED");
    assert_eq!(body["execution"], "not_dispatched");
    assert_eq!(body["retryable"], true);

    let fresh = fixture
        .runtime
        .resolve(scope, Utc::now())
        .await
        .expect("a retry resolves afresh");
    assert_eq!(fresh.owner_token(), &second.token);
    fixture.shutdown().await;
}
