use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use super::{
    Command, ControlOutbound, DataOutbound, Relay, RelayError, RelayHandle, RelayOptions,
    RunningRelay, spawn_transport_listener,
};
use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use rcgen::{CertificateParams, KeyPair};
use tokio::{
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    CredentialRecord, DeviceIdentity, DeviceListFilter, DeviceSummary, FixtureDevice,
    GrantSnapshot, GrantSpec, MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig,
    OidcVerifier, OwnerClaim, OwnerClaimRequest, OwnerToken, PermissionSet, SignedMembershipRecord,
    TenantRecord, UserRecord,
};
use tunnel_protocol::{ControlMessage, Opened, frame::FrameKind};
use tunnel_transport::load_server_config_from_pem;
use uuid::Uuid;

fn test_oidc() -> Arc<OidcVerifier> {
    let jwk = ApprovedJwk::from_ed25519_der("lifecycle", &[0_u8; 32]).expect("test OIDC key");
    let oidc_config = OidcConfig::new("https://issuer.example", ["audience".to_owned()], vec![jwk])
        .expect("test OIDC config");
    Arc::new(OidcVerifier::new(oidc_config).expect("test OIDC verifier"))
}

fn test_handle_with_cancel(cancel: CancellationToken) -> RelayHandle {
    test_handle_with_catalog(
        cancel,
        Arc::new(MemoryCatalog::new()),
        Duration::from_secs(30),
    )
}

fn test_handle_with_catalog(
    cancel: CancellationToken,
    catalog: Arc<dyn Catalog>,
    owner_lease: Duration,
) -> RelayHandle {
    let mut options = RelayOptions::new(test_oidc());
    options.shutdown = cancel;
    options.owner_lease = owner_lease;
    RelayHandle::spawn(options, catalog)
}

fn test_handle() -> RelayHandle {
    test_handle_with_cancel(CancellationToken::new())
}

fn listener_until_cancel(
    cancel: CancellationToken,
    finished: Arc<AtomicUsize>,
) -> JoinHandle<Result<(), tunnel_transport::TransportError>> {
    tokio::spawn(async move {
        cancel.cancelled().await;
        finished.fetch_add(1, Ordering::AcqRel);
        Ok::<(), tunnel_transport::TransportError>(())
    })
}

async fn panic_listener() -> Result<(), tunnel_transport::TransportError> {
    panic!("synthetic listener panic");
}

const LIFECYCLE_SPKI: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

fn lifecycle_fixture() -> (CatalogFixture, Uuid, Uuid) {
    let tenant_id = Uuid::from_u128(101);
    let user_id = Uuid::from_u128(111);
    let device_id = Uuid::from_u128(121);
    let now = Utc::now();
    (
        CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "lifecycle-tenant".to_owned(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "Lifecycle User".to_owned(),
            }],
            memberships: vec![MembershipRecord {
                tenant_id,
                user_id,
                role: MembershipRole::Member,
                active: true,
            }],
            devices: vec![FixtureDevice {
                tenant_id,
                device_id,
                owner_user_id: user_id,
                display_name: "Lifecycle Device".to_owned(),
                active: true,
                last_seen_at: Some(now),
            }],
            credentials: vec![CredentialRecord {
                tenant_id,
                device_id,
                credential_id: Uuid::from_u128(141),
                spki_fingerprint: LIFECYCLE_SPKI.to_owned(),
                serial: Some("lifecycle".to_owned()),
                not_before: now - ChronoDuration::seconds(1),
                expires_at: now + ChronoDuration::hours(1),
                revoked_at: None,
                active: true,
            }],
            ..CatalogFixture::default()
        },
        tenant_id,
        device_id,
    )
}

fn lifecycle_hello(device_id: Uuid) -> tunnel_protocol::Hello {
    let mut hello = tunnel_protocol::Hello::new(
        "lifecycle-registration",
        device_id.to_string(),
        u16::from(crate::PROTOCOL_MAJOR),
        0,
    );
    hello.features.push("echo".to_owned());
    hello
}

#[derive(Clone)]
struct HeldCatalog {
    inner: MemoryCatalog,
    claim_committed: Arc<AtomicBool>,
    claim_seen: Arc<Notify>,
    release_claim: Arc<Notify>,
    hold_claim_after_commit: Arc<AtomicBool>,
    panic_on_claim: Arc<AtomicBool>,
    renew_seen: Arc<Notify>,
    renew_started: Arc<AtomicBool>,
    release_renew: Arc<Notify>,
    hold_renew: Arc<AtomicBool>,
}

impl HeldCatalog {
    fn new() -> Self {
        Self {
            inner: MemoryCatalog::new(),
            claim_committed: Arc::new(AtomicBool::new(false)),
            claim_seen: Arc::new(Notify::new()),
            release_claim: Arc::new(Notify::new()),
            hold_claim_after_commit: Arc::new(AtomicBool::new(false)),
            panic_on_claim: Arc::new(AtomicBool::new(false)),
            renew_seen: Arc::new(Notify::new()),
            renew_started: Arc::new(AtomicBool::new(false)),
            release_renew: Arc::new(Notify::new()),
            hold_renew: Arc::new(AtomicBool::new(false)),
        }
    }

    async fn wait_for(flag: &AtomicBool, seen: &Notify) {
        loop {
            if flag.load(Ordering::Acquire) {
                return;
            }
            let notified = seen.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if flag.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    async fn wait_for_claim(&self) {
        Self::wait_for(&self.claim_committed, &self.claim_seen).await;
    }

    async fn wait_for_renewal(&self) {
        Self::wait_for(&self.renew_started, &self.renew_seen).await;
    }

    async fn identity(&self, at: DateTime<Utc>) -> DeviceIdentity {
        self.inner
            .resolve_device(LIFECYCLE_SPKI, at)
            .await
            .expect("lifecycle identity lookup")
            .expect("lifecycle fixture identity")
    }
}

#[async_trait]
impl Catalog for HeldCatalog {
    async fn resolve_device(
        &self,
        spki_fingerprint: &str,
        at: DateTime<Utc>,
    ) -> Result<Option<DeviceIdentity>, CatalogError> {
        self.inner.resolve_device(spki_fingerprint, at).await
    }

    async fn resolve_consumer(
        &self,
        issuer: &str,
        subject: &str,
        tenant_id: Option<Uuid>,
    ) -> Result<Option<AuthenticatedConsumer>, CatalogError> {
        self.inner
            .resolve_consumer(issuer, subject, tenant_id)
            .await
    }

    async fn authorize(
        &self,
        principal: &AuthenticatedConsumer,
        device_id: Uuid,
        service_id: Uuid,
        read_started_at: DateTime<Utc>,
        at: DateTime<Utc>,
    ) -> Result<Option<GrantSnapshot>, CatalogError> {
        self.inner
            .authorize(principal, device_id, service_id, read_started_at, at)
            .await
    }

    async fn list_devices_filtered(
        &self,
        principal: &AuthenticatedConsumer,
        filter: &DeviceListFilter,
        at: DateTime<Utc>,
    ) -> Result<Vec<DeviceSummary>, CatalogError> {
        self.inner
            .list_devices_filtered(principal, filter, at)
            .await
    }

    async fn upsert_grant(&self, spec: &GrantSpec) -> Result<GrantSnapshot, CatalogError> {
        self.inner.upsert_grant(spec).await
    }

    async fn revoke_grant(
        &self,
        tenant_id: Uuid,
        principal_id: Uuid,
        device_id: Uuid,
        service_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner
            .revoke_grant(tenant_id, principal_id, device_id, service_id, at)
            .await
    }

    async fn revoke_device(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner.revoke_device(tenant_id, device_id, at).await
    }

    async fn revoke_credential(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        credential_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<u64, CatalogError> {
        self.inner
            .revoke_credential(tenant_id, device_id, credential_id, at)
            .await
    }

    async fn seed_fixture(&self, fixture: &CatalogFixture) -> Result<(), CatalogError> {
        self.inner.seed_fixture(fixture).await
    }

    async fn claim_owner(&self, request: &OwnerClaimRequest) -> Result<OwnerClaim, CatalogError> {
        if self.panic_on_claim.load(Ordering::Acquire) {
            panic!("synthetic background registration panic");
        }
        let claim = self.inner.claim_owner(request).await?;
        self.claim_committed.store(true, Ordering::Release);
        self.claim_seen.notify_waiters();
        if self.hold_claim_after_commit.load(Ordering::Acquire) {
            self.release_claim.notified().await;
        }
        Ok(claim)
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        if self.hold_renew.load(Ordering::Acquire) {
            self.renew_started.store(true, Ordering::Release);
            self.renew_seen.notify_waiters();
            self.release_renew.notified().await;
        }
        self.inner.renew_owner(token, lease_expires_at).await
    }

    async fn release_owner(&self, token: &OwnerToken) -> Result<bool, CatalogError> {
        self.inner.release_owner(token).await
    }

    async fn current_owner(
        &self,
        tenant_id: Uuid,
        device_id: Uuid,
        at: DateTime<Utc>,
    ) -> Result<Option<OwnerClaim>, CatalogError> {
        self.inner.current_owner(tenant_id, device_id, at).await
    }

    async fn issue_attachment_ticket(
        &self,
        request: &AttachmentTicketIssueRequest,
    ) -> Result<AttachmentTicket, CatalogError> {
        self.inner.issue_attachment_ticket(request).await
    }

    async fn consume_attachment_ticket(
        &self,
        request: &AttachmentTicketConsumeRequest,
    ) -> Result<ConsumedAttachmentTicket, CatalogError> {
        self.inner.consume_attachment_ticket(request).await
    }

    async fn read_signed_membership(&self) -> Result<Option<SignedMembershipRecord>, CatalogError> {
        self.inner.read_signed_membership().await
    }
}

async fn prepared_lifecycle_catalog() -> (HeldCatalog, Uuid, Uuid, DeviceIdentity) {
    let catalog = HeldCatalog::new();
    let (fixture, tenant_id, device_id) = lifecycle_fixture();
    catalog
        .seed_fixture(&fixture)
        .await
        .expect("seed lifecycle catalog fixture");
    let identity = catalog.identity(Utc::now()).await;
    (catalog, tenant_id, device_id, identity)
}

#[tokio::test]
async fn listener_failure_cancels_shared_relay_and_sibling() {
    let cancel = CancellationToken::new();
    let sibling_cancelled = Arc::new(AtomicBool::new(false));
    let sibling_seen = Arc::clone(&sibling_cancelled);
    let sibling_token = cancel.clone();
    let sibling = tokio::spawn(async move {
        sibling_token.cancelled().await;
        sibling_seen.store(true, Ordering::Release);
    });

    let failure = tunnel_transport::TransportError::Accept(std::io::Error::other(
        "synthetic listener failure",
    ));
    let listener = spawn_transport_listener(cancel.clone(), async move { Err(failure) });
    assert!(listener.await.expect("listener task joined").is_err());
    timeout(Duration::from_secs(1), sibling)
        .await
        .expect("sibling observed cancellation")
        .expect("sibling task joined");
    assert!(cancel.is_cancelled());
    assert!(sibling_cancelled.load(Ordering::Acquire));
}

#[tokio::test]
async fn listener_unexpected_exit_is_typed_and_cancels_shared_relay() {
    let cancel = CancellationToken::new();
    let listener = spawn_transport_listener(cancel.clone(), async { Ok(()) });
    let result = listener.await.expect("listener task joined");
    assert!(matches!(
        result,
        Err(tunnel_transport::TransportError::Http(message))
            if message == "listener stopped unexpectedly"
    ));
    assert!(cancel.is_cancelled());
}

#[tokio::test]
async fn listener_panic_is_typed_and_cancels_shared_relay() {
    let cancel = CancellationToken::new();
    let listener = spawn_transport_listener(cancel.clone(), panic_listener());
    let result = listener.await.expect("listener task joined");
    assert!(matches!(
        result,
        Err(tunnel_transport::TransportError::Http(message))
            if message == "listener task panicked"
    ));
    assert!(cancel.is_cancelled());
}

#[tokio::test]
async fn dropping_running_relay_stops_actor_and_maintenance_sender() {
    let cancel = CancellationToken::new();
    let handle = test_handle_with_cancel(cancel.clone());
    let observed = handle.clone();
    let listeners_finished = Arc::new(AtomicUsize::new(0));
    let running = RunningRelay {
        handle,
        cancel: cancel.clone(),
        consumer_task: listener_until_cancel(cancel.clone(), Arc::clone(&listeners_finished)),
        device_task: listener_until_cancel(cancel.clone(), Arc::clone(&listeners_finished)),
        peer_task: None,
        peer_runtime: None,
        peer_diagnostics: None,
        peer_planned_cancel: None,
        authority: None,
        consumer_addr: "127.0.0.1:0".parse().expect("consumer address"),
        device_addr: "127.0.0.1:0".parse().expect("device address"),
    };

    drop(running);
    assert!(cancel.is_cancelled());
    timeout(Duration::from_secs(1), async {
        while listeners_finished.load(Ordering::Acquire) != 2 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both listener tasks observed drop cancellation");
    timeout(Duration::from_secs(1), async {
        loop {
            if matches!(observed.snapshot().await, Err(RelayError::Shutdown)) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("actor exits after RunningRelay drop");
}

#[tokio::test]
async fn shutdown_reports_aborted_actor_task_outcome() {
    let cancel = CancellationToken::new();
    let handle = test_handle_with_cancel(cancel);
    handle.abort_actor_task().await;

    let result = timeout(Duration::from_secs(1), handle.shutdown())
        .await
        .expect("aborted actor shutdown is bounded");
    assert!(matches!(
        result,
        Err(RelayError::Transport(message)) if message == "relay actor task failed"
    ));
}

#[tokio::test]
async fn shutdown_joins_siblings_after_first_listener_error() {
    let finished = Arc::new(AtomicUsize::new(0));
    let sibling_finished = Arc::clone(&finished);
    let peer_finished = Arc::clone(&finished);
    let consumer_error = tokio::spawn(async {
        Err::<(), tunnel_transport::TransportError>(tunnel_transport::TransportError::Accept(
            std::io::Error::other("consumer listener failed"),
        ))
    });
    let device_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        sibling_finished.fetch_add(1, Ordering::AcqRel);
        Ok::<(), tunnel_transport::TransportError>(())
    });
    let peer_task = tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(10)).await;
        peer_finished.fetch_add(1, Ordering::AcqRel);
        Err::<(), tunnel_transport::PeerTransportError>(tunnel_transport::PeerTransportError::H3(
            "peer listener failed".to_owned(),
        ))
    });
    let running = RunningRelay {
        handle: test_handle(),
        cancel: CancellationToken::new(),
        consumer_task: consumer_error,
        device_task,
        peer_task: Some(peer_task),
        peer_runtime: None,
        peer_diagnostics: None,
        peer_planned_cancel: None,
        authority: None,
        consumer_addr: "127.0.0.1:0".parse().expect("consumer address"),
        device_addr: "127.0.0.1:0".parse().expect("device address"),
    };

    let result = running.shutdown().await;
    assert!(result.is_err(), "the first listener failure is reported");
    assert_eq!(finished.load(Ordering::Acquire), 2);
}

fn test_server_config() -> Arc<rustls::ServerConfig> {
    let key = KeyPair::generate().expect("lifecycle TLS key");
    let params = CertificateParams::new(vec!["localhost".to_owned()])
        .expect("lifecycle TLS certificate parameters");
    let certificate = params.self_signed(&key).expect("lifecycle TLS certificate");
    load_server_config_from_pem(
        certificate.pem().as_bytes(),
        key.serialize_pem().as_bytes(),
        None,
    )
    .expect("lifecycle TLS server config")
}

#[tokio::test]
async fn dropping_started_relay_releases_both_listener_sockets() {
    let consumer_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind lifecycle consumer listener");
    let device_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind lifecycle device listener");
    let consumer_addr = consumer_listener.local_addr().expect("consumer address");
    let device_addr = device_listener.local_addr().expect("device address");
    let tls = test_server_config();
    let running = Relay::start(
        RelayOptions::new(test_oidc()),
        Arc::new(MemoryCatalog::new()),
        consumer_listener,
        device_listener,
        tls.clone(),
        tls,
    )
    .await
    .expect("start lifecycle relay");
    let actor = running.handle.clone();

    // A successful connection to each address proves the real serve tasks
    // have taken ownership of both bound sockets before the value is dropped.
    let consumer = TcpStream::connect(consumer_addr)
        .await
        .expect("consumer listener accepts a connection");
    let device = TcpStream::connect(device_addr)
        .await
        .expect("device listener accepts a connection");
    tokio::task::yield_now().await;
    drop((consumer, device));
    drop(running);

    let shutdown = timeout(Duration::from_secs(2), actor.shutdown())
        .await
        .expect("actor and maintenance tasks stop after relay drop");
    assert!(matches!(shutdown, Ok(()) | Err(RelayError::Shutdown)));

    timeout(Duration::from_secs(2), async {
        loop {
            let consumer = TcpListener::bind(consumer_addr).await;
            let device = TcpListener::bind(device_addr).await;
            if consumer.is_ok() && device.is_ok() {
                break;
            }
            drop(consumer);
            drop(device);
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("both listener addresses become reusable after relay drop");
}

#[tokio::test]
async fn shutdown_releases_claim_committed_before_registration_result_delivery() {
    let (catalog, tenant_id, device_id, identity) = prepared_lifecycle_catalog().await;
    catalog
        .hold_claim_after_commit
        .store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let handle = test_handle_with_catalog(
        cancel.clone(),
        Arc::new(catalog.clone()),
        Duration::from_secs(30),
    );
    let registration_task = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .register_forwarded_control(
                    identity,
                    LIFECYCLE_SPKI.to_owned(),
                    lifecycle_hello(device_id),
                )
                .await
        })
    };

    timeout(Duration::from_secs(1), catalog.wait_for_claim())
        .await
        .expect("catalog claim committed before result delivery");
    assert!(
        catalog
            .inner
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .expect("read committed lifecycle owner")
            .is_some()
    );

    // The claim future is still held after the authoritative write.  Release
    // it only after relay cancellation so its late result must either be
    // drained from the actor queue or have its exact cleanup guard dropped.
    cancel.cancel();
    catalog
        .hold_claim_after_commit
        .store(false, Ordering::Release);
    catalog.release_claim.notify_one();

    let shutdown = timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("registration shutdown is bounded");
    assert!(matches!(shutdown, Ok(()) | Err(RelayError::Shutdown)));
    let registration = timeout(Duration::from_secs(1), registration_task)
        .await
        .expect("registration task joined")
        .expect("registration task did not panic");
    assert!(matches!(
        registration,
        Ok(_) | Err(RelayError::Shutdown) | Err(RelayError::OwnerBusy)
    ));
    assert!(
        catalog
            .inner
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .expect("read lifecycle owner after shutdown")
            .is_none(),
        "a claim committed before cancellation must be released by its exact guard"
    );
}

/// **Task row M6-C178.** A registration task aborted mid-claim together with
/// its actor must not leave the committed claim fenced until its lease
/// expires.  The claim commits and is then held inside `claim_owner`, so the
/// task is still running when the actor is aborted; the actor's `JoinSet`
/// aborts it, and its guard, armed with the full claim request, used to be
/// dropped onto a cleanup worker that was aborted with the actor.  The guard
/// is now parked by the actor before the task starts, so the supervisor finds
/// it and releases the exact claim.  The lease is 30 s; the bound is 2 s.
#[tokio::test]
async fn an_actor_aborted_while_a_claim_is_in_flight_releases_that_claim() {
    let (catalog, tenant_id, device_id, identity) = prepared_lifecycle_catalog().await;
    catalog
        .hold_claim_after_commit
        .store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let handle = test_handle_with_catalog(
        cancel.clone(),
        Arc::new(catalog.clone()),
        Duration::from_secs(30),
    );
    let registration_task = {
        let handle = handle.clone();
        tokio::spawn(async move {
            handle
                .register_forwarded_control(
                    identity,
                    LIFECYCLE_SPKI.to_owned(),
                    lifecycle_hello(device_id),
                )
                .await
        })
    };
    timeout(Duration::from_secs(1), catalog.wait_for_claim())
        .await
        .expect("catalog claim committed while the task is still running");

    // No relay cancellation first: the actor is aborted as a panic would end
    // it, with the claim future still held inside the registration task.
    handle.abort_actor_task().await;

    let mut released = false;
    for _ in 0..200 {
        if catalog
            .inner
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .expect("read lifecycle owner")
            .is_none()
        {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    catalog.release_claim.notify_one();
    let _ = timeout(Duration::from_secs(1), registration_task).await;
    assert!(
        released,
        "a claim committed by a registration task aborted with its actor must be released, \
         not left fenced until its lease expires"
    );
}

#[tokio::test]
async fn shutdown_joins_inflight_owner_renewal_before_cleanup_worker() {
    let (catalog, tenant_id, device_id, identity) = prepared_lifecycle_catalog().await;
    catalog.hold_renew.store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let handle = test_handle_with_catalog(
        cancel.clone(),
        Arc::new(catalog.clone()),
        Duration::from_secs(6),
    );
    let _registration = handle
        .register_forwarded_control(
            identity,
            LIFECYCLE_SPKI.to_owned(),
            lifecycle_hello(device_id),
        )
        .await
        .expect("register lifecycle device before renewal");

    timeout(Duration::from_secs(4), catalog.wait_for_renewal())
        .await
        .expect("maintenance renewal entered the held catalog call");

    cancel.cancel();
    let shutdown_task = {
        let handle = handle.clone();
        tokio::spawn(async move { handle.shutdown().await })
    };
    // Let close_all begin while renew_owner is still awaiting the gate.  The
    // release then exercises the cancellation-aware result send and the
    // session's exact owner cleanup before the worker is joined.
    tokio::time::sleep(Duration::from_millis(20)).await;
    catalog.hold_renew.store(false, Ordering::Release);
    catalog.release_renew.notify_one();

    let shutdown = timeout(Duration::from_secs(2), shutdown_task)
        .await
        .expect("held renewal shutdown is bounded")
        .expect("shutdown task did not panic");
    assert!(matches!(shutdown, Ok(()) | Err(RelayError::Shutdown)));
    assert!(
        catalog
            .inner
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .expect("read lifecycle owner after renewal shutdown")
            .is_none(),
        "session cleanup must release the owner before the cleanup worker joins"
    );
}

#[tokio::test]
async fn background_registration_panic_is_reported_by_shutdown() {
    let (catalog, tenant_id, device_id, identity) = prepared_lifecycle_catalog().await;
    catalog.panic_on_claim.store(true, Ordering::Release);
    let cancel = CancellationToken::new();
    let handle =
        test_handle_with_catalog(cancel, Arc::new(catalog.clone()), Duration::from_secs(30));

    let registration = timeout(
        Duration::from_secs(2),
        handle.register_forwarded_control(
            identity,
            LIFECYCLE_SPKI.to_owned(),
            lifecycle_hello(device_id),
        ),
    )
    .await
    .expect("background panic registration is bounded");
    assert!(matches!(registration, Err(RelayError::Shutdown)));

    let shutdown = timeout(Duration::from_secs(2), handle.shutdown())
        .await
        .expect("background panic shutdown is bounded");
    assert!(matches!(
        shutdown,
        Err(RelayError::Transport(message))
            if message == "relay background task shutdown failed"
    ));
    assert!(
        catalog
            .inner
            .current_owner(tenant_id, device_id, Utc::now())
            .await
            .expect("read lifecycle owner after panic")
            .is_none(),
        "a registration panic must not leave an owner claim behind"
    );
}

/// M7-C71 regression.
///
/// A consumer close that races relay shutdown must still reach the device
/// carrier as a FIN, and it must reach it *before* the carrier `Close` that
/// tears the session down.  Both halves of the recorded design are on this
/// path: the `CloseEchoStream` command is deliberately queued behind the
/// `Shutdown` command, so it can only be observed by the shutdown drain, and
/// the drain must complete it rather than discard it.
///
/// The device carrier receiver is held and never polled, which is the unit
/// stand-in for a device socket whose writer has not yet drained.  This
/// proves the FIN reaches the writer's queue ahead of the close; it does
/// **not** prove the peer read it, which no unit test can show.
#[tokio::test]
async fn shutdown_drain_flushes_a_racing_stream_fin_before_the_device_close() {
    let (catalog, tenant_id, device_id, identity) = prepared_lifecycle_catalog().await;
    let user_id = Uuid::from_u128(111);
    let service_id = Uuid::from_u128(151);
    let cancel = CancellationToken::new();
    let handle = test_handle_with_catalog(
        cancel.clone(),
        Arc::new(catalog.clone()),
        Duration::from_secs(30),
    );

    let mut hello = lifecycle_hello(device_id);
    // The ordered-stream profile is what admits an echo stream at all.
    hello
        .features
        .push(crate::wire::ORDERED_ROTATION_FEATURE.to_owned());
    let mut control = handle
        .register_forwarded_control(identity.clone(), LIFECYCLE_SPKI.to_owned(), hello)
        .await
        .expect("register lifecycle device");
    let key = control.key.clone();
    let ticket =
        match serde_json::from_str::<ControlMessage>(&control.welcome).expect("WELCOME decodes") {
            ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
            other => panic!("registration returned {other:?} instead of a WELCOME"),
        };

    // Registration advanced the owner epoch, so the carrier must attach with
    // the identity as the catalog holds it now.
    let attached_identity = catalog.identity(Utc::now()).await;
    let data = handle
        .attach_forwarded_data(attached_identity, LIFECYCLE_SPKI.to_owned(), ticket)
        .await
        .expect("attach lifecycle device carrier");
    // Deliberately never polled: the queued frames stay observable in order.
    let mut carrier_rx = data.rx;

    let now = Utc::now();
    let consumer = AuthenticatedConsumer {
        tenant_id,
        principal_id: user_id,
    };
    let grant = GrantSnapshot {
        tenant_id,
        principal_id: user_id,
        device_id,
        service_id,
        revision: 1,
        permissions: PermissionSet {
            operations: BTreeSet::from([crate::ECHO_OPERATION.to_owned()]),
        },
        constraints: serde_json::json!({}),
        valid_until: now + ChronoDuration::minutes(5),
        read_started_at: now,
    };
    let registration = handle
        .open_echo_stream(
            consumer,
            device_id,
            service_id,
            grant,
            now + ChronoDuration::minutes(5),
        )
        .await
        .expect("open lifecycle echo stream");
    registration.claim_admission();
    let stream_id = registration.stream_id;
    let operation_id = registration.operation_id.clone();

    // Admit the stream: an OPEN the connector has not acknowledged defers its
    // terminal instead of emitting a FIN, so the race under test needs a real
    // admitted stream.
    let open_message_id = loop {
        let Some(ControlOutbound::Text(mut text)) =
            timeout(Duration::from_secs(2), control.rx.recv())
                .await
                .expect("stream OPEN was queued")
        else {
            panic!("control carrier closed before the stream OPEN");
        };
        let message: ControlMessage =
            serde_json::from_slice(text.as_bytes()).expect("control message decodes");
        text.release();
        if matches!(message, ControlMessage::Open(_)) {
            break message.message_id().to_owned();
        }
    };
    handle
        .inbound_control(
            key.clone(),
            ControlMessage::Opened(Opened::new(
                "lifecycle-opened",
                open_message_id,
                key.session_id.clone(),
                key.epoch,
                stream_id,
                operation_id.clone(),
                crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
                crate::wire::M2_INITIAL_WINDOW_BYTES as u64,
            )),
        )
        .await
        .expect("admit the lifecycle stream");

    // Reserve both queue slots first, then push Shutdown and the close
    // back-to-back with no await between them.  That makes the ordering
    // exact: the actor leaves its command loop on the Shutdown and can only
    // ever see the close from the shutdown drain.
    let shutdown_permit = handle.tx.reserve().await.expect("reserve shutdown slot");
    let close_permit = handle.tx.reserve().await.expect("reserve close slot");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let (close_tx, close_rx) = tokio::sync::oneshot::channel();
    shutdown_permit.send(Command::Shutdown(shutdown_tx));
    close_permit.send(Command::CloseEchoStream {
        key: key.clone(),
        stream_id,
        operation_id,
        cause: None,
        response: close_tx,
    });

    let shutdown = timeout(Duration::from_secs(5), handle.shutdown())
        .await
        .expect("relay shutdown is bounded");
    assert!(matches!(shutdown, Ok(()) | Err(RelayError::Shutdown)));
    assert!(
        shutdown_rx.await.is_ok(),
        "the queued shutdown command is answered"
    );

    let mut drained = Vec::new();
    while let Ok(item) = carrier_rx.try_recv() {
        match item {
            DataOutbound::Binary(mut bytes) => {
                let frame = tunnel_protocol::frame::decode(bytes.as_slice())
                    .expect("device carrier frame decodes");
                bytes.release();
                drained.push(format!("{:?}", frame.kind));
            }
            DataOutbound::Barrier(done) => {
                let _ = done.send(());
                drained.push("Barrier".to_owned());
            }
            DataOutbound::Close => drained.push("Close".to_owned()),
        }
    }
    let fin = drained
        .iter()
        .position(|entry| entry == &format!("{:?}", FrameKind::Fin));
    let close = drained.iter().position(|entry| entry == "Close");
    assert!(
        matches!((fin, close), (Some(fin), Some(close)) if fin < close),
        "the device carrier must observe the stream FIN before the carrier close, drained {drained:?}"
    );
    assert_eq!(
        close_rx.await,
        Ok(true),
        "the racing close is answered by the shutdown drain"
    );
}
