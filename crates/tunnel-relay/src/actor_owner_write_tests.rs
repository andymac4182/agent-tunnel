//! M7-C63 / EC-020: a lost owner-write reply keeps the session unready.
//!
//! docs/cluster.md: "An unknown acquire/renew result leaves the actor unready
//! for dispatch. It can read back its exact token while sufficient verified
//! lease lifetime remains; it must not assume success or acquire a competing
//! token under another identity."  The catalog reports a lost reply after
//! dispatch as `CatalogError::WriteOutcomeUnknown`; the actor must then refuse
//! dispatch and admission for that session, never replay the renewal, and
//! reconcile only through a fresh authoritative owner read.

use std::{
    collections::BTreeSet,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use chrono::{DateTime, Duration as ChronoDuration, Utc};
use tokio::sync::{mpsc, oneshot};
use tunnel_catalog::{
    AttachmentTicket, AttachmentTicketConsumeRequest, AttachmentTicketIssueRequest,
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, ConsumedAttachmentTicket,
    DeviceIdentity, DeviceListFilter, DeviceSummary, GrantSnapshot, GrantSpec, MemoryCatalog,
    OwnerClaim, OwnerClaimRequest, OwnerToken, PermissionSet, SharedCatalog,
    SignedMembershipRecord, UnknownWriteCause,
};
use uuid::Uuid;

use super::stream_identity_tests::{admitted_control_actor, shared_device_fixture};
use super::{
    AUTHORITY_UNAVAILABLE, DispatchRequest, EchoOutcome, MaintenanceAuthorityCategory,
    MaintenanceAuthorityFailure, MaintenanceAuthorityOperation, RelayActor, SessionKey,
    maintenance_authority_category,
};

/// The owner lease the fixture claims and the actor is configured with.
const OWNER_LEASE: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OwnerReadMode {
    /// Answer from the real memory catalog.
    Authoritative,
    /// The read itself fails (authority unreachable).
    Fail,
    /// The authority reports no owner at all.
    Absent,
}

/// A memory catalog whose owner renewal can lose its reply after committing
/// and whose owner read can be steered, with every owner-affecting call
/// counted so replay is observable.
struct LostReplyCatalog {
    inner: MemoryCatalog,
    lose_renew_reply: AtomicBool,
    renew_calls: AtomicUsize,
    current_owner_calls: AtomicUsize,
    owner_read: Mutex<OwnerReadMode>,
}

impl LostReplyCatalog {
    fn new() -> Self {
        Self {
            inner: MemoryCatalog::new(),
            lose_renew_reply: AtomicBool::new(false),
            renew_calls: AtomicUsize::new(0),
            current_owner_calls: AtomicUsize::new(0),
            owner_read: Mutex::new(OwnerReadMode::Authoritative),
        }
    }

    fn set_owner_read(&self, mode: OwnerReadMode) {
        *self.owner_read.lock().expect("owner read mode") = mode;
    }
}

#[async_trait]
impl Catalog for LostReplyCatalog {
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
        self.inner.claim_owner(request).await
    }

    async fn renew_owner(
        &self,
        token: &OwnerToken,
        lease_expires_at: DateTime<Utc>,
    ) -> Result<bool, CatalogError> {
        self.renew_calls.fetch_add(1, Ordering::AcqRel);
        // The write commits on the authority either way; only the reply is
        // withheld, exactly like the severing-proxy Redis regression.
        let renewed = self.inner.renew_owner(token, lease_expires_at).await?;
        if self.lose_renew_reply.load(Ordering::Acquire) {
            return Err(CatalogError::WriteOutcomeUnknown(
                UnknownWriteCause::ConnectionLost,
            ));
        }
        Ok(renewed)
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
        self.current_owner_calls.fetch_add(1, Ordering::AcqRel);
        let mode = *self.owner_read.lock().expect("owner read mode");
        match mode {
            OwnerReadMode::Authoritative => {
                self.inner.current_owner(tenant_id, device_id, at).await
            }
            OwnerReadMode::Fail => Err(CatalogError::Database(
                std::io::Error::from(std::io::ErrorKind::ConnectionReset).into(),
            )),
            OwnerReadMode::Absent => Ok(None),
        }
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

struct Fixture {
    actor: RelayActor,
    catalog: Arc<LostReplyCatalog>,
    key: SessionKey,
    claim: OwnerClaim,
    service_id: Uuid,
    principal_id: Uuid,
    _control_rx: mpsc::Receiver<super::ControlOutbound>,
    _data_rx: mpsc::Receiver<super::DataOutbound>,
}

/// An admitted session whose owner token is really claimed in the catalog,
/// with a live data channel so the dispatch gate is the only thing that can
/// refuse a consumer, and a lease renewal that is due on the next tick.
async fn owned_session_fixture(session_id: &str) -> Fixture {
    let (fixture, device_id, tenant_id, _tenant_b, spki, _spki_b) = shared_device_fixture();
    let catalog = Arc::new(LostReplyCatalog::new());
    catalog
        .seed_fixture(&fixture)
        .await
        .expect("seed owner-write fixture");
    let identity = catalog
        .resolve_device(&spki, Utc::now())
        .await
        .expect("resolve owner-write identity")
        .expect("owner-write identity present");
    let claim = catalog
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: "test-incarnation".to_owned(),
            tenant_id,
            device_id,
            node_id: "test-node".to_owned(),
            boot_id: "test-boot".to_owned(),
            session_id: session_id.to_owned(),
            lease_expires_at: Utc::now()
                + ChronoDuration::from_std(OWNER_LEASE).expect("owner lease"),
        })
        .await
        .expect("claim the session owner");
    let key = SessionKey {
        tenant_id,
        device_id,
        session_id: session_id.to_owned(),
        epoch: claim.token.epoch,
    };
    let (mut actor, registration) = admitted_control_actor(identity, key.clone());
    actor.catalog = Arc::clone(&catalog) as SharedCatalog;
    actor.options.owner_lease = OWNER_LEASE;
    let (data_tx, data_rx) = mpsc::channel(actor.options.limits.max_queue_messages);
    let owner_lease = OWNER_LEASE;
    {
        let session = actor
            .sessions
            .get_mut(&key.scope())
            .expect("admitted session");
        assert_eq!(
            session.owner, claim.token,
            "the session owns its claimed token"
        );
        session.data_tx = Some(data_tx);
        // Renewal is due: the lease is a third consumed plus a margin.
        session.last_lease_renewal = Instant::now()
            .checked_sub(owner_lease / 3 + Duration::from_secs(1))
            .expect("renewal-due anchor");
    }
    Fixture {
        actor,
        catalog,
        key,
        claim,
        service_id: fixture.services[0].service_id,
        principal_id: fixture.grants[0].principal_id,
        _control_rx: registration.rx,
        _data_rx: data_rx,
    }
}

/// One maintenance round: the tick starts the background authority work and
/// the resulting command is handled by the actor.
async fn maintenance_round(actor: &mut RelayActor) {
    actor.tick().await;
    let command = tokio::time::timeout(Duration::from_secs(5), actor.rx.recv())
        .await
        .expect("maintenance must report within its bound")
        .expect("command channel remains open");
    actor.handle(command).await;
}

/// Attempt a consumer dispatch and return the immediate gate outcome, if any.
async fn dispatch_outcome(fixture: &mut Fixture) -> Option<EchoOutcome> {
    let now = Utc::now();
    let (response_tx, mut response_rx) = oneshot::channel();
    let consumer = AuthenticatedConsumer {
        tenant_id: fixture.key.tenant_id,
        principal_id: fixture.principal_id,
    };
    fixture
        .actor
        .dispatch_echo(DispatchRequest {
            consumer: consumer.clone(),
            device_id: fixture.key.device_id,
            service_id: fixture.service_id,
            grant: GrantSnapshot {
                tenant_id: fixture.key.tenant_id,
                principal_id: fixture.principal_id,
                device_id: fixture.key.device_id,
                service_id: fixture.service_id,
                revision: 1,
                permissions: PermissionSet {
                    operations: BTreeSet::from(["echo:invoke".to_owned()]),
                },
                constraints: serde_json::json!({}),
                valid_until: now + ChronoDuration::minutes(1),
                read_started_at: now,
            },
            body: b"ping".to_vec(),
            consumer_expires_at: now + ChronoDuration::minutes(1),
            response: response_tx,
        })
        .await;
    response_rx.try_recv().ok()
}

#[test]
fn lost_reply_is_its_own_maintenance_category_with_a_payload_free_cause() {
    let error = CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout);
    assert_eq!(
        maintenance_authority_category(&error),
        MaintenanceAuthorityCategory::OutcomeUnknown
    );
    assert_eq!(
        MaintenanceAuthorityCategory::OutcomeUnknown.as_str(),
        "outcome_unknown"
    );
    let failure = MaintenanceAuthorityFailure::from_catalog(
        MaintenanceAuthorityOperation::RenewOwner,
        &error,
        Duration::from_millis(2_000),
    );
    assert_eq!(
        failure.category,
        MaintenanceAuthorityCategory::OutcomeUnknown
    );
    assert_eq!(failure.unknown_cause, Some(UnknownWriteCause::ReplyTimeout));
    assert_eq!(
        MaintenanceAuthorityOperation::CurrentOwner.as_str(),
        "current_owner"
    );
    // Definite failures never carry a lost-reply cause.
    let definite = MaintenanceAuthorityFailure::from_catalog(
        MaintenanceAuthorityOperation::RenewOwner,
        &CatalogError::StaleOwner,
        Duration::from_millis(1),
    );
    assert_eq!(definite.unknown_cause, None);
}

#[tokio::test]
async fn lost_renewal_reply_keeps_the_session_unready_without_replay_until_the_owner_is_read_back()
{
    let mut fixture = owned_session_fixture("owner-write-unknown").await;
    let key = fixture.key.clone();
    assert!(
        dispatch_outcome(&mut fixture).await.is_none(),
        "before the lost reply the owner is ready and the dispatch passes the gate"
    );
    fixture
        .catalog
        .lose_renew_reply
        .store(true, Ordering::Release);

    maintenance_round(&mut fixture.actor).await;

    let session = fixture
        .actor
        .sessions
        .get(&key.scope())
        .expect("a lost reply is not a failed authority: the session stays");
    assert!(!session.closed);
    let unknown = session
        .owner_write_unknown
        .expect("the session records the unknown owner write");
    assert_eq!(unknown.cause, Some(UnknownWriteCause::ConnectionLost));
    assert_eq!(fixture.catalog.renew_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.catalog.current_owner_calls.load(Ordering::Acquire),
        0,
        "the renewal round itself does not read the owner back"
    );
    assert!(
        fixture.actor.session_terminal_events.is_empty(),
        "no terminal event: the session is unready, not closed"
    );
    assert!(
        matches!(
            dispatch_outcome(&mut fixture).await,
            Some(EchoOutcome::Failure {
                code: "OWNER_AUTHORITY_UNKNOWN",
                execution: "not_dispatched",
            })
        ),
        "dispatch is refused while the owner write is unknown"
    );
    let snapshot = fixture.actor.snapshot();
    let session_snapshot = snapshot
        .sessions
        .iter()
        .find(|session| session.session_id == key.session_id)
        .expect("session snapshot");
    assert_eq!(
        session_snapshot.owner_write_unknown,
        Some("connection_lost"),
        "diagnostics surface the unknown owner write with its payload-free cause"
    );

    // The next round reads the owner back instead of renewing again.
    fixture
        .catalog
        .lose_renew_reply
        .store(false, Ordering::Release);
    maintenance_round(&mut fixture.actor).await;

    let session = fixture
        .actor
        .sessions
        .get(&key.scope())
        .expect("the reconciled session stays live");
    assert!(
        session.owner_write_unknown.is_none(),
        "the authoritative read confirmed the exact token and cleared the unknown state"
    );
    assert_eq!(
        fixture.catalog.renew_calls.load(Ordering::Acquire),
        1,
        "the lost-reply renewal is never replayed"
    );
    assert_eq!(
        fixture.catalog.current_owner_calls.load(Ordering::Acquire),
        1
    );
    assert!(
        session.last_lease_renewal.elapsed() < Duration::from_secs(5),
        "the local lease clock is re-anchored on the lease the lost write committed"
    );
    let reconciled = fixture
        .catalog
        .current_owner(key.tenant_id, key.device_id, Utc::now())
        .await
        .expect("owner read")
        .expect("owner present");
    assert_eq!(reconciled.token, fixture.claim.token);
    assert!(
        reconciled.lease_expires_at > fixture.claim.lease_expires_at,
        "the lost-reply renewal did commit on the authority"
    );
    assert!(
        !matches!(
            dispatch_outcome(&mut fixture).await,
            Some(EchoOutcome::Failure {
                code: "OWNER_AUTHORITY_UNKNOWN",
                ..
            })
        ),
        "dispatch is admitted again once the owner state is confirmed"
    );
    assert!(fixture.actor.session_terminal_events.is_empty());
}

#[tokio::test]
async fn failed_owner_read_keeps_the_session_unready_until_the_confirmed_lease_runs_out() {
    let mut fixture = owned_session_fixture("owner-write-read-fails").await;
    let key = fixture.key.clone();
    let owner_lease = fixture.actor.options.owner_lease;
    fixture
        .catalog
        .lose_renew_reply
        .store(true, Ordering::Release);
    maintenance_round(&mut fixture.actor).await;
    assert!(
        fixture.actor.sessions[&key.scope()]
            .owner_write_unknown
            .is_some()
    );

    fixture.catalog.set_owner_read(OwnerReadMode::Fail);
    maintenance_round(&mut fixture.actor).await;
    let session = fixture
        .actor
        .sessions
        .get(&key.scope())
        .expect("an unreadable authority keeps the session while the confirmed lease lasts");
    assert!(
        session.owner_write_unknown.is_some(),
        "the session stays unready until a read succeeds"
    );
    assert_eq!(fixture.catalog.renew_calls.load(Ordering::Acquire), 1);
    assert_eq!(
        fixture.catalog.current_owner_calls.load(Ordering::Acquire),
        1
    );
    assert!(matches!(
        dispatch_outcome(&mut fixture).await,
        Some(EchoOutcome::Failure {
            code: "OWNER_AUTHORITY_UNKNOWN",
            ..
        })
    ));

    // The unknown write never extended the local lease clock.  Once the
    // last confirmed lease has run out the owner may be fenced elsewhere,
    // so the session closes explicitly rather than dispatching under it.
    fixture
        .actor
        .sessions
        .get_mut(&key.scope())
        .expect("session")
        .last_lease_renewal = Instant::now()
        .checked_sub(owner_lease)
        .expect("expired-lease anchor");
    fixture.actor.tick().await;
    assert!(
        !fixture.actor.sessions.contains_key(&key.scope()),
        "the confirmed lease ran out without a successful owner read"
    );
    assert_eq!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some(AUTHORITY_UNAVAILABLE)
    );
    assert_eq!(
        fixture.catalog.renew_calls.load(Ordering::Acquire),
        1,
        "no renewal replay even at lease expiry"
    );
}

#[tokio::test]
async fn owner_read_without_the_exact_token_fences_the_session() {
    let mut fixture = owned_session_fixture("owner-write-fenced").await;
    let key = fixture.key.clone();
    fixture
        .catalog
        .lose_renew_reply
        .store(true, Ordering::Release);
    maintenance_round(&mut fixture.actor).await;
    assert!(
        fixture.actor.sessions[&key.scope()]
            .owner_write_unknown
            .is_some()
    );

    fixture.catalog.set_owner_read(OwnerReadMode::Absent);
    maintenance_round(&mut fixture.actor).await;
    assert!(
        !fixture.actor.sessions.contains_key(&key.scope()),
        "an authority that no longer holds the exact token fences the session"
    );
    assert_eq!(
        fixture
            .actor
            .session_terminal_events
            .back()
            .map(|event| event.reason),
        Some("OWNER_FENCED")
    );
    assert_eq!(fixture.catalog.renew_calls.load(Ordering::Acquire), 1);
}
