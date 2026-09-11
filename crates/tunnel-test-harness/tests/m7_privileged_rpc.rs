//! Bounded M7 privileged-RPC analogue coverage.
//!
//! This is deliberately a transport-and-envelope proof rather than an
//! adapter implementation.  The synthetic manager is reached only through
//! the production [`tunnel_relay::PeerRuntime`] server/client path.  Its
//! dispatch counter stands in for a privileged manager call so that rejected
//! owner, assignment, generation, role, route, and body cases can be checked
//! without introducing SQLite or starting a later adapter.

use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use http::StatusCode;
use tokio::{sync::Notify, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{Catalog, MemoryCatalog, OwnerClaim, OwnerToken, SharedCatalog};
use tunnel_cluster::{
    envelope::{
        ConsumerStreamsRequest, Destination, ForwardedConsumerBearer, InternalRequest,
        InternalRoute, OperationStatusRequest, PeerIdentity, RequestEnvelope, VerifiedPeerIdentity,
    },
    membership::{
        MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipPolicy,
        MembershipRecord, MembershipVerifier, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey,
        TrustedPublisherKey, VerifiedPeerBinding,
    },
    peer_frame::{PeerRecord, PeerRecordKind, STREAM_BYTE_BUDGET},
};
use tunnel_relay::{
    InboundPeerRequest, PeerBindingProvider, PeerIngressHandler, PeerRuntime, PeerRuntimeError,
    peer_runtime::{InboundPeerRecv, InboundPeerSend, PeerExchangeRecv},
    routing::{OwnerRoute, OwnerRouter, RelayIdentity},
};
use tunnel_test_harness::{CertificateMaterial, FixturePki};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerServer, PeerTransportError, PeerTransportLimits, SpkiSha256,
    load_peer_client_config_from_pem, load_peer_server_config_from_pem, spki_sha256_from_der,
};
use uuid::Uuid;

#[path = "m7_privileged_rpc/edge_cases.rs"]
mod edge_cases;

const DEPLOYMENT_ID: &str = "m7-privileged-rpc-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-privileged-rpc-incarnation";
const SOURCE_NODE: &str = "m7-rpc-source";
const SOURCE_BOOT: &str = "m7-rpc-source-boot";
const DESTINATION_NODE: &str = "m7-rpc-owner";
const DESTINATION_BOOT: &str = "m7-rpc-owner-boot";
const ASSIGNMENT: &str = "assignment-1";
const MEMBERSHIP_NONCE: &str = "m7-privileged-rpc-nonce";
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_PRIVILEGED_BODY_BYTES: usize = 1024;
const PRIVILEGED_TERMINAL_BODY: &[u8] = b"privileged-rpc-committed";

fn tenant_id() -> Uuid {
    Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0001)
}

fn device_id() -> Uuid {
    Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0001)
}

fn service_id() -> Uuid {
    Uuid::from_u128(0x3000_0000_0000_0000_0000_0000_0000_0001)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ResponseMode {
    Complete,
    Partial,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionState {
    Ready,
    Frozen,
    Fenced,
    Pending,
    Poisoned,
    Stopped,
    Uncertain,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AdmissionOutcome {
    Unavailable,
    Unknown,
}

impl AdmissionState {
    fn outcome(self) -> Option<AdmissionOutcome> {
        match self {
            Self::Ready => None,
            Self::Frozen | Self::Fenced | Self::Pending | Self::Stopped => {
                Some(AdmissionOutcome::Unavailable)
            }
            // A poisoned state means that the owner cannot prove whether a
            // prior privileged step took effect.  It is therefore surfaced as
            // an unknown outcome, just like an explicit uncertainty marker.
            Self::Poisoned | Self::Uncertain => Some(AdmissionOutcome::Unknown),
        }
    }
}

impl AdmissionOutcome {
    fn status(self) -> StatusCode {
        match self {
            // The request never reached the synthetic manager in this state.
            AdmissionOutcome::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            // Keep uncertainty distinct from both unavailable and malformed
            // input.  A future adapter owns its public error projection; this
            // bounded analogue only needs an unambiguous transport outcome.
            AdmissionOutcome::Unknown => StatusCode::BAD_GATEWAY,
        }
    }
}

/// Synthetic owner actor.  It validates the complete envelope and admission
/// state before spawning one bounded worker, and the worker is awaited before
/// the response is sent.  Dispatch/effect, transport-finish, and
/// caller-confirmed success counters remain separate so a partial response
/// cannot masquerade as a completed privileged action.
#[derive(Clone)]
struct PrivilegedManager {
    expected_owner: OwnerToken,
    expected_service: Uuid,
    expected_assignment: String,
    response_mode: ResponseMode,
    admission_state: AdmissionState,
    seen: Arc<AtomicUsize>,
    rejected: Arc<AtomicUsize>,
    malformed_bad_requests: Arc<AtomicUsize>,
    unavailable_outcomes: Arc<AtomicUsize>,
    unknown_outcomes: Arc<AtomicUsize>,
    dispatches: Arc<AtomicUsize>,
    worker_effects: Arc<AtomicUsize>,
    workers_started: Arc<AtomicUsize>,
    workers_joined: Arc<AtomicUsize>,
    partial_responses: Arc<AtomicUsize>,
    transport_finishes: Arc<AtomicUsize>,
    application_success_acks: Arc<AtomicUsize>,
    unknown_effect_outcomes: Arc<AtomicUsize>,
    events: Arc<Notify>,
}

impl PrivilegedManager {
    fn new(
        owner: OwnerToken,
        service: Uuid,
        assignment: &str,
        response_mode: ResponseMode,
        admission_state: AdmissionState,
    ) -> Self {
        Self {
            expected_owner: owner,
            expected_service: service,
            expected_assignment: assignment.to_owned(),
            response_mode,
            admission_state,
            seen: Arc::new(AtomicUsize::new(0)),
            rejected: Arc::new(AtomicUsize::new(0)),
            malformed_bad_requests: Arc::new(AtomicUsize::new(0)),
            unavailable_outcomes: Arc::new(AtomicUsize::new(0)),
            unknown_outcomes: Arc::new(AtomicUsize::new(0)),
            dispatches: Arc::new(AtomicUsize::new(0)),
            worker_effects: Arc::new(AtomicUsize::new(0)),
            workers_started: Arc::new(AtomicUsize::new(0)),
            workers_joined: Arc::new(AtomicUsize::new(0)),
            partial_responses: Arc::new(AtomicUsize::new(0)),
            transport_finishes: Arc::new(AtomicUsize::new(0)),
            application_success_acks: Arc::new(AtomicUsize::new(0)),
            unknown_effect_outcomes: Arc::new(AtomicUsize::new(0)),
            events: Arc::new(Notify::new()),
        }
    }

    fn signal(&self) {
        self.events.notify_one();
    }

    fn reject(&self) {
        self.rejected.fetch_add(1, Ordering::AcqRel);
        self.signal();
    }

    fn record_outcome(&self, outcome: AdmissionOutcome) {
        match outcome {
            AdmissionOutcome::Unavailable => {
                self.unavailable_outcomes.fetch_add(1, Ordering::AcqRel);
            }
            AdmissionOutcome::Unknown => {
                self.unknown_outcomes.fetch_add(1, Ordering::AcqRel);
            }
        }
        self.signal();
    }

    /// Record a success only after the caller has validated the complete
    /// response and its application-level terminal record.  Transport
    /// `finish()` alone is deliberately insufficient evidence.
    fn confirm_application_success(&self) {
        self.application_success_acks.fetch_add(1, Ordering::AcqRel);
        self.signal();
    }

    /// Classify a partial response after the caller observes the bounded
    /// interruption.  The worker effect remains counted separately.
    fn record_unknown_effect(&self) {
        self.unknown_effect_outcomes.fetch_add(1, Ordering::AcqRel);
        self.signal();
    }

    async fn respond_and_finish(
        &self,
        send: &mut InboundPeerSend,
        recv: &mut InboundPeerRecv,
        status: StatusCode,
    ) -> Result<(), PeerRuntimeError> {
        send.respond(status).await?;
        // The caller may cancel its request direction as soon as it observes
        // the bounded status.  The response status is the authoritative
        // outcome; a race while terminating the body must not poison the peer
        // server supervisor.
        let _ = send.finish().await;
        recv.cancel();
        Ok(())
    }

    async fn reject_malformed(
        &self,
        send: &mut InboundPeerSend,
        recv: &mut InboundPeerRecv,
    ) -> Result<(), PeerRuntimeError> {
        self.reject();
        self.malformed_bad_requests.fetch_add(1, Ordering::AcqRel);
        self.signal();
        self.respond_and_finish(send, recv, StatusCode::BAD_REQUEST)
            .await
    }

    async fn wait_for(&self, counter: &AtomicUsize, expected: usize) {
        timeout(RESPONSE_TIMEOUT, async {
            loop {
                if counter.load(Ordering::Acquire) >= expected {
                    return;
                }
                self.events.notified().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("manager counter did not reach {expected}"));
    }

    async fn handle_request(&self, request: InboundPeerRequest) -> Result<(), PeerRuntimeError> {
        self.seen.fetch_add(1, Ordering::AcqRel);
        self.signal();

        let envelope = request.envelope().clone();
        let binding = request.binding().clone();
        let (mut send, mut recv) = request.split();
        let verified_peer = match VerifiedPeerIdentity::from_verified_peer_binding(&binding) {
            Ok(peer) => peer,
            Err(_) => {
                return self.reject_malformed(&mut send, &mut recv).await;
            }
        };
        let expected_destination =
            Destination::new(self.expected_owner.clone(), self.expected_service);

        // There is no URL, endpoint, or bearer fallback in this analogue:
        // owner, tenant/device/service scope, and epoch all come from the
        // canonical expected destination and the verified peer binding.
        if envelope
            .validate(Utc::now(), &verified_peer, &expected_destination, None)
            .is_err()
        {
            return self.reject_malformed(&mut send, &mut recv).await;
        }
        let assignment_matches = envelope.operation_id.as_deref()
            == Some(self.expected_assignment.as_str())
            && matches!(
                &envelope.request,
                InternalRequest::OperationStatus(status)
                    if status.operation_id == self.expected_assignment
            );
        if !assignment_matches {
            return self.reject_malformed(&mut send, &mut recv).await;
        }

        if let Some(outcome) = self.admission_state.outcome() {
            self.reject();
            self.record_outcome(outcome);
            return self
                .respond_and_finish(&mut send, &mut recv, outcome.status())
                .await;
        }

        let record = match recv.recv_message().await {
            Ok(Some(record)) => record,
            Ok(None) | Err(_) => {
                self.reject();
                return Ok(());
            }
        };
        if record.kind() != PeerRecordKind::ConsumerChunk
            || record.body_len() > MAX_PRIVILEGED_BODY_BYTES
        {
            return self.reject_malformed(&mut send, &mut recv).await;
        }

        let dispatches = Arc::clone(&self.dispatches);
        let worker_effects = Arc::clone(&self.worker_effects);
        self.workers_started.fetch_add(1, Ordering::AcqRel);
        self.signal();
        let worker = tokio::spawn(async move {
            tokio::task::yield_now().await;
            dispatches.fetch_add(1, Ordering::AcqRel);
            worker_effects.fetch_add(1, Ordering::AcqRel);
        });
        worker
            .await
            .map_err(|error| PeerRuntimeError::Transport(PeerTransportError::Task(error)))?;
        self.workers_joined.fetch_add(1, Ordering::AcqRel);
        self.signal();

        send.respond(StatusCode::OK).await?;
        send.send_message(PeerRecordKind::ConsumerChunk, b"privileged-rpc-accepted")
            .await?;
        if self.response_mode == ResponseMode::Partial {
            // A response record without the terminal finish is an interrupted
            // outcome.  The caller must classify it as unknown and must not
            // automatically replay the already-dispatched operation.
            self.partial_responses.fetch_add(1, Ordering::AcqRel);
            self.signal();
            return Ok(());
        }
        send.send_message(
            PeerRecordKind::CompleteControlText,
            PRIVILEGED_TERMINAL_BODY,
        )
        .await?;
        let result = send.finish().await;
        if result.is_ok() {
            self.transport_finishes.fetch_add(1, Ordering::AcqRel);
            self.signal();
        }
        result
    }
}

impl PeerIngressHandler for PrivilegedManager {
    fn handle(
        &self,
        request: InboundPeerRequest,
    ) -> tunnel_relay::peer_runtime::PeerIngressHandlerFuture {
        let manager = self.clone();
        Box::pin(async move { manager.handle_request(request).await })
    }
}

struct RpcFixture {
    runtime: Arc<PeerRuntime>,
    wrong_role_runtime: Arc<PeerRuntime>,
    owner: OwnerClaim,
    service: Uuid,
    route: OwnerRoute,
    manager: Arc<PrivilegedManager>,
    cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
}

/// The transport and identity material shared by the normal privileged-RPC
/// fixture and the EC064/EC067 handlers.  Keeping this setup single-sourced
/// means every handler receives the same signed owner claim, route, and
/// mTLS-bound runtime that the validated tests exercise.
struct RpcFixtureBase {
    runtime: Arc<PeerRuntime>,
    wrong_role_runtime: Arc<PeerRuntime>,
    owner: OwnerClaim,
    service: Uuid,
    route: OwnerRoute,
    source_binding: VerifiedPeerBinding,
    server_endpoint: quinn::Endpoint,
    source_pin: SpkiSha256,
    limits: PeerTransportLimits,
}

/// Generic fixture parts used by the edge-case handlers.  The factory
/// receives the exact owner token constructed by the fixture, preventing a
/// test manager from accidentally using a different epoch, boot, or session.
struct RpcFixtureParts<H> {
    runtime: Arc<PeerRuntime>,
    wrong_role_runtime: Arc<PeerRuntime>,
    owner: OwnerClaim,
    service: Uuid,
    route: OwnerRoute,
    source_binding: VerifiedPeerBinding,
    manager: Arc<H>,
    cancel: CancellationToken,
    server_task: JoinHandle<Result<(), PeerTransportError>>,
}

impl<H> RpcFixtureParts<H> {
    fn privileged_envelope(&self) -> RequestEnvelope {
        operation_envelope(
            self.runtime.source().clone(),
            self.owner.token.clone(),
            self.service,
            edge_cases::SHARED_APPLICATION_ID,
        )
    }

    fn privileged_envelope_with_deadline(&self, milliseconds: u32) -> RequestEnvelope {
        let mut envelope = self.privileged_envelope();
        envelope.remaining_admission_ms = milliseconds;
        // Keep the synthetic stream lifetime authoritative for the selected
        // admission window.  The base envelope's one-second lifetime is
        // intentionally suitable for ordinary requests, but an active-worker
        // case needs a five-second admission deadline so it remains valid
        // through dispatch and explicit shutdown.
        envelope.stream_lifetime_ms = Some(milliseconds);
        envelope
    }

    fn customer_envelope(&self) -> RequestEnvelope {
        let bearer =
            ForwardedConsumerBearer::new("m7-synthetic-customer.jwt", self.owner.token.clone())
                .expect("synthetic customer bearer");
        let mut envelope = RequestEnvelope::new(
            InternalRoute::ConsumerStreams,
            "m7-rpc-customer-request",
            self.runtime.source().clone(),
            Destination::new(self.owner.token.clone(), self.service),
            1_000,
            Some(1_000),
            InternalRequest::ConsumerStreams(ConsumerStreamsRequest {
                stream_id: edge_cases::SHARED_APPLICATION_ID.to_owned(),
                required_scope: edge_cases::SHARED_REQUIRED_SCOPE.to_owned(),
                bearer,
                bytes: Vec::new(),
            }),
        );
        envelope.operation_id = Some(edge_cases::SHARED_APPLICATION_ID.to_owned());
        envelope
    }
}

fn build_rpc_fixture_base(limits: PeerTransportLimits) -> RpcFixtureBase {
    let pki = FixturePki::new().expect("fixture PKI");
    let source_certificate = pki
        .issue_peer(SOURCE_NODE)
        .expect("source peer certificate");
    let destination_certificate = pki
        .issue_peer(DESTINATION_NODE)
        .expect("destination peer certificate");
    let wrong_role_certificate = pki
        .issue_device_signed_by_peer_ca(tenant_id(), device_id())
        .expect("wrong-role peer certificate");

    let destination_chain = certificate_chain(&destination_certificate, &pki);
    let server_config = load_peer_server_config_from_pem(
        destination_chain.as_bytes(),
        destination_certificate.private_key_pem.as_bytes(),
        pki.peer_ca.certificate_pem.as_bytes(),
    )
    .expect("server peer TLS config");
    let server_endpoint =
        quinn::Endpoint::server(server_config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .expect("server endpoint");
    let server_address = server_endpoint.local_addr().expect("server address");

    let source_chain = certificate_chain(&source_certificate, &pki);
    let mut client_endpoint =
        quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).expect("client endpoint");
    let client_address = client_endpoint.local_addr().expect("client address");
    let client_config = load_peer_client_config_from_pem(
        source_chain.as_bytes(),
        source_certificate.private_key_pem.as_bytes(),
        pki.peer_ca.certificate_pem.as_bytes(),
    )
    .expect("client peer TLS config");
    client_endpoint.set_default_client_config(client_config);

    let source_pin = spki(&source_certificate);
    let destination_pin = spki(&destination_certificate);
    let bindings = verified_bindings(
        (
            &source_certificate,
            SOURCE_NODE,
            SOURCE_BOOT,
            client_address,
        ),
        (
            &destination_certificate,
            DESTINATION_NODE,
            DESTINATION_BOOT,
            server_address,
        ),
    );
    let destination_binding = bindings
        .get(&(DESTINATION_NODE.to_owned(), DESTINATION_BOOT.to_owned()))
        .cloned()
        .expect("destination binding");
    let source_binding = bindings
        .get(&(SOURCE_NODE.to_owned(), SOURCE_BOOT.to_owned()))
        .cloned()
        .expect("source binding");

    let owner = OwnerClaim {
        token: OwnerToken {
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            tenant_id: tenant_id(),
            device_id: device_id(),
            node_id: DESTINATION_NODE.to_owned(),
            boot_id: DESTINATION_BOOT.to_owned(),
            session_id: "m7-rpc-owner-session".to_owned(),
            epoch: 7,
        },
        lease_expires_at: Utc::now() + ChronoDuration::seconds(60),
    };
    let service = service_id();
    let route = OwnerRoute::Remote {
        owner: owner.clone(),
        peer: Some(destination_binding),
    };

    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let identity = RelayIdentity::new(DEPLOYMENT_INCARNATION, SOURCE_NODE, SOURCE_BOOT)
        .expect("source relay identity");
    let router: Arc<OwnerRouter<dyn Catalog>> =
        Arc::new(OwnerRouter::new(catalog, identity).expect("owner router"));
    let bindings = Arc::new(bindings);
    let provider = binding_provider(Arc::clone(&bindings));
    let client = PeerClient::new(
        client_endpoint,
        approved_pins(destination_pin),
        limits.clone(),
    )
    .expect("source peer client");
    let runtime = Arc::new(PeerRuntime::new(
        client,
        Arc::clone(&router),
        Arc::clone(&provider),
        SOURCE_NODE,
        SOURCE_BOOT,
    ));

    let wrong_role_chain = certificate_chain(&wrong_role_certificate, &pki);
    let mut wrong_role_endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("wrong-role client endpoint");
    let wrong_role_config = load_peer_client_config_from_pem(
        wrong_role_chain.as_bytes(),
        wrong_role_certificate.private_key_pem.as_bytes(),
        pki.peer_ca.certificate_pem.as_bytes(),
    )
    .expect("wrong-role client TLS config");
    wrong_role_endpoint.set_default_client_config(wrong_role_config);
    let wrong_role_client = PeerClient::new(
        wrong_role_endpoint,
        approved_pins(destination_pin),
        limits.clone(),
    )
    .expect("wrong-role peer client");
    let wrong_role_runtime = Arc::new(PeerRuntime::new(
        wrong_role_client,
        router,
        provider,
        SOURCE_NODE,
        SOURCE_BOOT,
    ));

    RpcFixtureBase {
        runtime,
        wrong_role_runtime,
        owner,
        service,
        route,
        source_binding,
        server_endpoint,
        source_pin,
        limits,
    }
}

impl RpcFixture {
    async fn start(response_mode: ResponseMode) -> Self {
        Self::start_with_admission_state(response_mode, AdmissionState::Ready).await
    }

    async fn start_with_admission_state(
        response_mode: ResponseMode,
        admission_state: AdmissionState,
    ) -> Self {
        let base = build_rpc_fixture_base(test_limits());

        let manager = Arc::new(PrivilegedManager::new(
            base.owner.token.clone(),
            base.service,
            ASSIGNMENT,
            response_mode,
            admission_state,
        ));
        let handler = base.runtime.server_handler((*manager).clone());
        let server = PeerServer::new(
            base.server_endpoint,
            approved_pins(base.source_pin),
            base.limits,
            PeerRuntime::server_policy(),
            handler,
        )
        .expect("peer server");
        let cancel = CancellationToken::new();
        let server_task = tokio::spawn(server.serve(cancel.clone()));

        Self {
            runtime: base.runtime,
            wrong_role_runtime: base.wrong_role_runtime,
            owner: base.owner,
            service: base.service,
            route: base.route,
            manager,
            cancel,
            server_task,
        }
    }

    fn envelope(&self, assignment: &str) -> RequestEnvelope {
        operation_envelope(
            self.runtime.source().clone(),
            self.owner.token.clone(),
            self.service,
            assignment,
        )
    }

    async fn shutdown(self) {
        self.cancel.cancel();
        let server_result = timeout(RESPONSE_TIMEOUT, self.server_task)
            .await
            .expect("peer server shutdown deadline")
            .expect("peer server task join");
        assert!(
            server_result.is_ok(),
            "peer server returned {server_result:?}"
        );
        self.runtime
            .shutdown()
            .await
            .expect("source peer runtime joins client workers");
        self.wrong_role_runtime
            .shutdown()
            .await
            .expect("wrong-role peer runtime joins client workers");
        assert_eq!(
            self.manager.workers_started.load(Ordering::Acquire),
            self.manager.workers_joined.load(Ordering::Acquire),
            "every synthetic privileged worker must be joined",
        );
    }
}

fn test_limits() -> PeerTransportLimits {
    PeerTransportLimits::new_with_timeouts(
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        4,
        4,
        4,
        16 * 1024,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .expect("bounded peer limits")
}

fn shared_pool_limits() -> PeerTransportLimits {
    PeerTransportLimits::new_with_timeouts(
        64 * 1024,
        256 * 1024,
        1024 * 1024,
        1,
        4,
        4,
        16 * 1024,
        Duration::from_secs(3),
        Duration::from_secs(3),
        Duration::from_secs(2),
        Duration::from_secs(3),
    )
    .expect("bounded shared-pool peer limits")
}

async fn start_rpc_fixture_with_handler<H, F>(
    handler_factory: F,
    limits: PeerTransportLimits,
) -> RpcFixtureParts<H>
where
    H: PeerIngressHandler + Clone,
    F: FnOnce(OwnerToken, Uuid) -> Arc<H>,
{
    let base = build_rpc_fixture_base(limits);
    let manager = handler_factory(base.owner.token.clone(), base.service);
    let handler = base.runtime.server_handler((*manager).clone());
    let server = PeerServer::new(
        base.server_endpoint,
        approved_pins(base.source_pin),
        base.limits,
        PeerRuntime::server_policy(),
        handler,
    )
    .expect("peer server");
    let cancel = CancellationToken::new();
    let server_task = tokio::spawn(server.serve(cancel.clone()));

    RpcFixtureParts {
        runtime: base.runtime,
        wrong_role_runtime: base.wrong_role_runtime,
        owner: base.owner,
        service: base.service,
        route: base.route,
        source_binding: base.source_binding,
        manager,
        cancel,
        server_task,
    }
}

async fn shutdown_rpc_fixture<H>(fixture: RpcFixtureParts<H>)
where
    H: PeerIngressHandler + Clone,
{
    fixture.cancel.cancel();
    let server_result = timeout(RESPONSE_TIMEOUT, fixture.server_task)
        .await
        .expect("peer server shutdown deadline")
        .expect("peer server task join");
    assert!(
        server_result.is_ok(),
        "peer server returned {server_result:?}"
    );
    fixture
        .runtime
        .shutdown()
        .await
        .expect("source peer runtime joins client workers");
    fixture
        .wrong_role_runtime
        .shutdown()
        .await
        .expect("wrong-role peer runtime joins client workers");
}

fn certificate_chain(certificate: &CertificateMaterial, pki: &FixturePki) -> String {
    format!(
        "{}{}",
        certificate.certificate_pem, pki.peer_ca.certificate_pem
    )
}

fn spki(certificate: &CertificateMaterial) -> SpkiSha256 {
    spki_sha256_from_der(&certificate.certificate_der).expect("peer SPKI")
}

fn approved_pins(pin: SpkiSha256) -> ApprovedPeerPins {
    ApprovedPeerPins::new([pin]).expect("approved peer pin")
}

fn verified_bindings(
    source: (&CertificateMaterial, &str, &str, SocketAddr),
    destination: (&CertificateMaterial, &str, &str, SocketAddr),
) -> HashMap<(String, String), VerifiedPeerBinding> {
    let endpoint_policy = PrivateEndpointPolicy::allowlisted(
        ["127.0.0.1"],
        ["localhost"],
        [source.3.port(), destination.3.port()],
    )
    .expect("endpoint policy");
    let policy = MembershipPolicy::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, endpoint_policy)
        .expect("membership policy");
    let (issuer, _) = MembershipIssuer::generate("m7-rpc-publisher").expect("membership issuer");
    let trusted =
        TrustedPublisherKey::new("m7-rpc-publisher", issuer.public_key().expect("issuer key"))
            .expect("trusted publisher key");
    let mut verifier = MembershipVerifier::new(policy, [trusted]).expect("membership verifier");
    let now = Utc::now();
    let checkpoint = MembershipCheckpoint {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        checkpoint_version: 1,
        nonce: MEMBERSHIP_NONCE.to_owned(),
        minimum_versions: BTreeMap::from([(source.1.to_owned(), 1), (destination.1.to_owned(), 1)]),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let checkpoint_bytes = issuer
        .sign_checkpoint_bytes(checkpoint)
        .expect("signed checkpoint");
    verifier
        .verify_checkpoint(&checkpoint_bytes, MEMBERSHIP_NONCE, now)
        .expect("verified checkpoint");

    let mut bindings = HashMap::new();
    for (certificate, node_id, boot_id, endpoint) in [source, destination] {
        let spki = certificate
            .spki_fingerprint_sha256()
            .expect("membership SPKI");
        let record = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: node_id.to_owned(),
            record_version: 1,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: endpoint.to_string(),
            server_name: "localhost".to_owned(),
            keys: vec![RelayKey {
                key_id: format!("{node_id}-key"),
                spki_sha256: spki.clone(),
                not_before: now - ChronoDuration::seconds(1),
                expires_at: now + ChronoDuration::seconds(30),
                revoked: false,
            }],
            issued_at: now - ChronoDuration::seconds(1),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::seconds(30),
        };
        let bytes = issuer
            .sign_membership_bytes(record)
            .expect("signed membership");
        verifier
            .verify_membership(&bytes, now)
            .expect("verified membership");
        let binding = verifier
            .bind_peer(node_id, boot_id, &spki, now)
            .expect("verified peer binding");
        bindings.insert((node_id.to_owned(), boot_id.to_owned()), binding);
    }
    bindings
}

fn binding_provider(
    bindings: Arc<HashMap<(String, String), VerifiedPeerBinding>>,
) -> Arc<dyn PeerBindingProvider> {
    Arc::new(move |node_id: &str, boot_id: &str, _now| {
        let binding = bindings
            .get(&(node_id.to_owned(), boot_id.to_owned()))
            .cloned()
            .ok_or_else(|| PeerRuntimeError::Membership("peer binding unavailable".to_owned()));
        async move { binding }
    })
}

fn operation_envelope(
    source: PeerIdentity,
    owner: OwnerToken,
    service: Uuid,
    assignment: &str,
) -> RequestEnvelope {
    let mut envelope = RequestEnvelope::new(
        InternalRoute::OperationStatus,
        format!("m7-rpc-request-{assignment}"),
        source,
        Destination::new(owner, service),
        1_000,
        Some(1_000),
        InternalRequest::OperationStatus(OperationStatusRequest {
            operation_id: assignment.to_owned(),
        }),
    );
    envelope.operation_id = Some(assignment.to_owned());
    envelope
}

async fn sent_exchange(
    runtime: &PeerRuntime,
    route: &OwnerRoute,
    envelope: RequestEnvelope,
    body: &[u8],
) -> Result<PeerExchangeRecv, PeerRuntimeError> {
    let exchange = runtime.open(route, envelope).await?;
    let (mut send, recv) = exchange.split();
    send.send_message(PeerRecordKind::ConsumerChunk, body)
        .await?;
    send.finish().await?;
    Ok(recv)
}

async fn complete_exchange(
    runtime: &PeerRuntime,
    route: &OwnerRoute,
    envelope: RequestEnvelope,
    body: &[u8],
) -> Result<(PeerRecord, PeerRecord), PeerRuntimeError> {
    let mut recv = sent_exchange(runtime, route, envelope, body).await?;
    let accepted = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .map_err(|_| PeerRuntimeError::Closed)??
        .ok_or(PeerRuntimeError::Closed)?;
    let terminal = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .map_err(|_| PeerRuntimeError::Closed)??
        .ok_or(PeerRuntimeError::Closed)?;
    let end = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .map_err(|_| PeerRuntimeError::Closed)??;
    if end.is_some() {
        return Err(PeerRuntimeError::Closed);
    }
    Ok((accepted, terminal))
}

async fn rejected_exchange(
    runtime: &PeerRuntime,
    route: &OwnerRoute,
    envelope: RequestEnvelope,
    body: &[u8],
) {
    let Ok(mut recv) = sent_exchange(runtime, route, envelope, body).await else {
        // A receiver-side envelope rejection can race the request body send;
        // the manager counter below is the authoritative rejection proof.
        return;
    };
    let observed = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .expect("rejected peer request must terminate within its bound");
    if let Ok(Some(record)) = observed {
        panic!("rejected peer request returned {record:?}");
    }
}

async fn expect_remote_status(
    runtime: &PeerRuntime,
    route: &OwnerRoute,
    envelope: RequestEnvelope,
    expected: StatusCode,
) {
    let exchange = runtime
        .open(route, envelope)
        .await
        .expect("open status-only privileged RPC");
    let (mut send, mut recv) = exchange.split();
    let observed = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .expect("status-only privileged RPC must terminate within its bound");
    let status_matches = matches!(
        &observed,
        Err(PeerRuntimeError::RemoteStatus(status)) if *status == expected
    );
    assert!(
        status_matches,
        "expected remote status {expected}, observed {observed:?}"
    );
    send.cancel();
    recv.cancel();
}

#[tokio::test]
async fn privileged_rpc_requires_mtls_exact_owner_assignment_epoch_and_route() {
    let fixture = RpcFixture::start(ResponseMode::Complete).await;

    let (accepted, terminal) = complete_exchange(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope(ASSIGNMENT),
        b"privileged-request",
    )
    .await
    .expect("exact owner and assignment request");
    assert_eq!(accepted.kind(), PeerRecordKind::ConsumerChunk);
    assert_eq!(accepted.body(), b"privileged-rpc-accepted");
    assert_eq!(terminal.kind(), PeerRecordKind::CompleteControlText);
    assert_eq!(terminal.body(), PRIVILEGED_TERMINAL_BODY);
    fixture.manager.wait_for(&fixture.manager.seen, 1).await;
    fixture
        .manager
        .wait_for(&fixture.manager.workers_joined, 1)
        .await;
    fixture
        .manager
        .wait_for(&fixture.manager.transport_finishes, 1)
        .await;
    // The caller confirms success only after validating both the accepted
    // record and the explicit application terminal marker above.
    fixture.manager.confirm_application_success();
    fixture
        .manager
        .wait_for(&fixture.manager.application_success_acks, 1)
        .await;
    assert_eq!(fixture.manager.worker_effects.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture
            .manager
            .application_success_acks
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        fixture
            .manager
            .unknown_effect_outcomes
            .load(Ordering::Acquire),
        0
    );
    assert_eq!(fixture.manager.partial_responses.load(Ordering::Acquire), 0);

    let mut stale_token = fixture.owner.token.clone();
    stale_token.epoch += 1;
    let stale_owner = OwnerClaim {
        token: stale_token.clone(),
        lease_expires_at: fixture.owner.lease_expires_at,
    };
    let stale_route = OwnerRoute::Remote {
        owner: stale_owner,
        peer: fixture.route.peer_binding().cloned(),
    };
    rejected_exchange(
        &fixture.runtime,
        &stale_route,
        operation_envelope(
            fixture.runtime.source().clone(),
            stale_token,
            fixture.service,
            ASSIGNMENT,
        ),
        b"stale-epoch",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 2).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 1).await;

    let mut wrong_boot_token = fixture.owner.token.clone();
    wrong_boot_token.boot_id = "m7-rpc-owner-boot-forged".to_owned();
    let wrong_boot_route = OwnerRoute::Remote {
        owner: OwnerClaim {
            token: wrong_boot_token.clone(),
            lease_expires_at: fixture.owner.lease_expires_at,
        },
        peer: fixture.route.peer_binding().cloned(),
    };
    let wrong_boot_result = fixture
        .runtime
        .open(
            &wrong_boot_route,
            operation_envelope(
                fixture.runtime.source().clone(),
                wrong_boot_token,
                fixture.service,
                ASSIGNMENT,
            ),
        )
        .await;
    assert!(matches!(
        wrong_boot_result,
        Err(PeerRuntimeError::PeerIdentityMismatch)
    ));
    assert_eq!(
        fixture.manager.seen.load(Ordering::Acquire),
        2,
        "a boot-id mismatch must fail before a peer request is admitted"
    );

    let wrong_service = Uuid::from_u128(0x4000_0000_0000_0000_0000_0000_0000_0001);
    rejected_exchange(
        &fixture.runtime,
        &fixture.route,
        operation_envelope(
            fixture.runtime.source().clone(),
            fixture.owner.token.clone(),
            wrong_service,
            ASSIGNMENT,
        ),
        b"wrong-service",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 3).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 2).await;

    // Keep the authenticated destination peer binding unchanged while
    // forging only the owner scope.  Matching the route owner to each forged
    // envelope lets the request reach the H3 handler; the authoritative
    // destination comparison must reject it before a second worker dispatch.
    let mut wrong_tenant_token = fixture.owner.token.clone();
    wrong_tenant_token.tenant_id = Uuid::from_u128(0x1000_0000_0000_0000_0000_0000_0000_0002);
    let wrong_tenant_route = OwnerRoute::Remote {
        owner: OwnerClaim {
            token: wrong_tenant_token.clone(),
            lease_expires_at: fixture.owner.lease_expires_at,
        },
        peer: fixture.route.peer_binding().cloned(),
    };
    rejected_exchange(
        &fixture.runtime,
        &wrong_tenant_route,
        operation_envelope(
            fixture.runtime.source().clone(),
            wrong_tenant_token,
            fixture.service,
            ASSIGNMENT,
        ),
        b"wrong-tenant",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 4).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 3).await;

    let mut wrong_device_token = fixture.owner.token.clone();
    wrong_device_token.device_id = Uuid::from_u128(0x2000_0000_0000_0000_0000_0000_0000_0002);
    let wrong_device_route = OwnerRoute::Remote {
        owner: OwnerClaim {
            token: wrong_device_token.clone(),
            lease_expires_at: fixture.owner.lease_expires_at,
        },
        peer: fixture.route.peer_binding().cloned(),
    };
    rejected_exchange(
        &fixture.runtime,
        &wrong_device_route,
        operation_envelope(
            fixture.runtime.source().clone(),
            wrong_device_token,
            fixture.service,
            ASSIGNMENT,
        ),
        b"wrong-device",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 5).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 4).await;
    assert_eq!(
        fixture.manager.dispatches.load(Ordering::Acquire),
        1,
        "tenant/device scope mismatches must fail before manager dispatch"
    );

    let mut wrong_route = fixture.envelope(ASSIGNMENT);
    wrong_route.route = InternalRoute::Health;
    rejected_exchange(
        &fixture.runtime,
        &fixture.route,
        wrong_route,
        b"wrong-route",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 6).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 5).await;

    rejected_exchange(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope("assignment-forged"),
        b"wrong-assignment",
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 7).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 6).await;
    assert_eq!(fixture.manager.dispatches.load(Ordering::Acquire), 1);

    let mut forged_source = fixture.envelope(ASSIGNMENT);
    forged_source.source = PeerIdentity::new("forged-source", "forged-boot");
    let source_result = fixture.runtime.open(&fixture.route, forged_source).await;
    assert!(matches!(
        source_result,
        Err(PeerRuntimeError::PeerIdentityMismatch)
    ));

    let wrong_role_result = sent_exchange(
        &fixture.wrong_role_runtime,
        &fixture.route,
        fixture.envelope(ASSIGNMENT),
        b"wrong-role",
    )
    .await;
    if let Ok(mut recv) = wrong_role_result {
        let observed = timeout(RESPONSE_TIMEOUT, recv.recv_message())
            .await
            .expect("wrong-role peer request must terminate within its bound");
        if let Ok(Some(record)) = observed {
            panic!("wrong-role peer request returned {record:?}");
        }
    }
    assert_eq!(
        fixture.manager.seen.load(Ordering::Acquire),
        7,
        "wrong-role TLS must be rejected before the relay ingress handler"
    );
    assert_eq!(fixture.manager.dispatches.load(Ordering::Acquire), 1);

    fixture.shutdown().await;
}

#[tokio::test]
async fn privileged_rpc_bounds_body_before_manager_dispatch() {
    let fixture = RpcFixture::start(ResponseMode::Complete).await;
    let manager = Arc::clone(&fixture.manager);

    let (accepted, terminal) = complete_exchange(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope(ASSIGNMENT),
        b"bounded-positive-control",
    )
    .await
    .expect("bounded positive control");
    assert_eq!(accepted.body(), b"privileged-rpc-accepted");
    assert_eq!(terminal.kind(), PeerRecordKind::CompleteControlText);
    assert_eq!(terminal.body(), PRIVILEGED_TERMINAL_BODY);
    fixture.manager.wait_for(&fixture.manager.seen, 1).await;
    fixture
        .manager
        .wait_for(&fixture.manager.workers_joined, 1)
        .await;
    fixture
        .manager
        .wait_for(&fixture.manager.transport_finishes, 1)
        .await;
    fixture.manager.confirm_application_success();
    fixture
        .manager
        .wait_for(&fixture.manager.application_success_acks, 1)
        .await;

    // The synthetic adapter bound is stricter than the transport record bound;
    // the owner must consume and reject this body before spawning a second worker.
    rejected_exchange(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope(ASSIGNMENT),
        &vec![b'x'; MAX_PRIVILEGED_BODY_BYTES + 1],
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 2).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 1).await;

    let exchange = fixture
        .runtime
        .open(&fixture.route, fixture.envelope(ASSIGNMENT))
        .await
        .expect("open bounded peer stream");
    let (mut send, mut recv) = exchange.split();
    let oversized = vec![b'x'; STREAM_BYTE_BUDGET + 1];
    let result = send
        .send_message(PeerRecordKind::ConsumerChunk, &oversized)
        .await;
    assert!(matches!(result, Err(PeerRuntimeError::Frame(_))));
    send.cancel();
    recv.cancel();
    drop(send);
    drop(recv);

    fixture.shutdown().await;
    assert_eq!(manager.dispatches.load(Ordering::Acquire), 1);
    assert_eq!(manager.worker_effects.load(Ordering::Acquire), 1);
    assert_eq!(manager.workers_started.load(Ordering::Acquire), 1);
    assert_eq!(manager.transport_finishes.load(Ordering::Acquire), 1);
    assert_eq!(manager.application_success_acks.load(Ordering::Acquire), 1);
    assert_eq!(manager.unknown_effect_outcomes.load(Ordering::Acquire), 0);
    assert!(manager.rejected.load(Ordering::Acquire) >= 1);
}

#[tokio::test]
async fn privileged_rpc_partial_response_is_transport_interruption_analogue_without_internal_replay()
 {
    let fixture = RpcFixture::start(ResponseMode::Partial).await;
    let manager = Arc::clone(&fixture.manager);
    let mut recv = sent_exchange(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope(ASSIGNMENT),
        b"partial-request",
    )
    .await
    .expect("open partial privileged RPC");

    let first = timeout(RESPONSE_TIMEOUT, recv.recv_message())
        .await
        .expect("partial response deadline")
        .expect("partial response transport");
    assert_eq!(
        first.expect("partial response record").body(),
        b"privileged-rpc-accepted"
    );
    let terminal = timeout(RESPONSE_TIMEOUT, recv.recv_message()).await;
    let transport_interrupted_without_terminal =
        matches!(terminal, Err(_) | Ok(Ok(None)) | Ok(Err(_)));
    assert!(
        transport_interrupted_without_terminal,
        "partial response must end as a bounded transport interruption"
    );
    fixture
        .manager
        .wait_for(&fixture.manager.workers_joined, 1)
        .await;
    fixture.manager.record_unknown_effect();
    fixture
        .manager
        .wait_for(&fixture.manager.unknown_effect_outcomes, 1)
        .await;
    assert_eq!(fixture.manager.partial_responses.load(Ordering::Acquire), 1);

    // This is a transport-interruption analogue: the harness callback performs
    // no internal retry after dispatch.  Adapter policy still owns the final
    // application-level unknown outcome in a later integration layer.
    fixture.shutdown().await;
    assert_eq!(manager.dispatches.load(Ordering::Acquire), 1);
    assert_eq!(
        manager.workers_started.load(Ordering::Acquire),
        manager.workers_joined.load(Ordering::Acquire),
    );
    assert_eq!(manager.worker_effects.load(Ordering::Acquire), 1);
    assert_eq!(manager.transport_finishes.load(Ordering::Acquire), 0);
    assert_eq!(manager.application_success_acks.load(Ordering::Acquire), 0);
    assert_eq!(manager.unknown_effect_outcomes.load(Ordering::Acquire), 1);
}

#[tokio::test]
async fn privileged_rpc_admission_states_fail_closed_before_manager_action() {
    let cases = [
        (
            AdmissionState::Frozen,
            AdmissionOutcome::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AdmissionState::Fenced,
            AdmissionOutcome::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AdmissionState::Pending,
            AdmissionOutcome::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AdmissionState::Poisoned,
            AdmissionOutcome::Unknown,
            StatusCode::BAD_GATEWAY,
        ),
        (
            AdmissionState::Stopped,
            AdmissionOutcome::Unavailable,
            StatusCode::SERVICE_UNAVAILABLE,
        ),
        (
            AdmissionState::Uncertain,
            AdmissionOutcome::Unknown,
            StatusCode::BAD_GATEWAY,
        ),
    ];

    for (state, outcome, expected_status) in cases {
        let fixture = RpcFixture::start_with_admission_state(ResponseMode::Complete, state).await;
        expect_remote_status(
            &fixture.runtime,
            &fixture.route,
            fixture.envelope(ASSIGNMENT),
            expected_status,
        )
        .await;
        fixture.manager.wait_for(&fixture.manager.seen, 1).await;
        fixture.manager.wait_for(&fixture.manager.rejected, 1).await;

        // The state gate runs after envelope validation but before body
        // consumption or worker creation.  A denied/unknown admission must
        // not dispatch, commit, ACK success, or retry internally.
        assert_eq!(fixture.manager.seen.load(Ordering::Acquire), 1);
        assert_eq!(fixture.manager.dispatches.load(Ordering::Acquire), 0);
        assert_eq!(fixture.manager.workers_started.load(Ordering::Acquire), 0);
        assert_eq!(fixture.manager.workers_joined.load(Ordering::Acquire), 0);
        assert_eq!(fixture.manager.worker_effects.load(Ordering::Acquire), 0);
        assert_eq!(
            fixture.manager.transport_finishes.load(Ordering::Acquire),
            0
        );
        assert_eq!(
            fixture
                .manager
                .application_success_acks
                .load(Ordering::Acquire),
            0
        );
        assert_eq!(
            fixture
                .manager
                .unknown_effect_outcomes
                .load(Ordering::Acquire),
            0
        );
        match outcome {
            AdmissionOutcome::Unavailable => {
                assert_eq!(
                    fixture.manager.unavailable_outcomes.load(Ordering::Acquire),
                    1
                );
                assert_eq!(fixture.manager.unknown_outcomes.load(Ordering::Acquire), 0);
            }
            AdmissionOutcome::Unknown => {
                assert_eq!(fixture.manager.unknown_outcomes.load(Ordering::Acquire), 1);
                assert_eq!(
                    fixture.manager.unavailable_outcomes.load(Ordering::Acquire),
                    0
                );
            }
        }
        assert_eq!(
            fixture
                .manager
                .malformed_bad_requests
                .load(Ordering::Acquire),
            0
        );
        fixture.shutdown().await;
    }

    // A malformed assignment is a distinct 400 validation result.  The
    // unavailable/unknown state results above must never be collapsed into
    // this malformed-input path.
    let fixture = RpcFixture::start(ResponseMode::Complete).await;
    expect_remote_status(
        &fixture.runtime,
        &fixture.route,
        fixture.envelope("assignment-forged"),
        StatusCode::BAD_REQUEST,
    )
    .await;
    fixture.manager.wait_for(&fixture.manager.seen, 1).await;
    fixture.manager.wait_for(&fixture.manager.rejected, 1).await;
    assert_eq!(
        fixture
            .manager
            .malformed_bad_requests
            .load(Ordering::Acquire),
        1
    );
    assert_eq!(
        fixture.manager.unavailable_outcomes.load(Ordering::Acquire),
        0
    );
    assert_eq!(fixture.manager.unknown_outcomes.load(Ordering::Acquire), 0);
    assert_eq!(fixture.manager.dispatches.load(Ordering::Acquire), 0);
    fixture.shutdown().await;
}
