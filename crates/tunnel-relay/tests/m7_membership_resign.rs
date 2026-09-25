//! Membership re-sign and peer-trust wiring regressions (M7-C80, M7-C83,
//! M7-C86, M7-C90, M7-C91).
//!
//! Each test drives the real `MembershipRuntime` through signed checkpoint
//! and record bytes from an in-memory source, and the real library pin
//! wiring (`PeerPinPublisher`, `peer_trust_tick`) that both the serving relay
//! and the production-cluster fixture install. No Redis, no checkpoint
//! service and no network: the synthetic endpoint is never dialled.

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{MemoryCatalog, SharedCatalog, SignedMembershipRecord};
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
    PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
};
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
    MembershipRuntimeConfig, MembershipUnreadyReason, PeerInvalidationReason, PeerListenerState,
    PeerReadiness, PeerRuntime,
    membership_runtime::{MembershipFuture, MembershipSourceError},
    peer_pins::{PeerPinPublisher, PeerTrustTick, PinPublication, peer_trust_tick},
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    ApprovedPeerPins, PeerClient, PeerTransportLimits, SharedPeerPins, SpkiSha256,
};

const DEPLOYMENT_ID: &str = "m7-resign-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-resign-incarnation";
const NODE_ID: &str = "relay-resign";
const BOOT_ID: &str = "boot-resign";
const PUBLISHER_KEY_ID: &str = "publisher-resign";
const SPKI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_SPKI_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

struct TestCheckpointAuthority {
    issuer: Arc<MembershipIssuer>,
    next_version: AtomicU64,
}

impl CheckpointAuthority for TestCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            let now = Utc::now();
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: BTreeMap::from([(NODE_ID.to_owned(), 1)]),
                issued_at: now - chrono::Duration::seconds(1),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(30),
            };
            let bytes = self
                .issuer
                .sign_checkpoint_bytes(checkpoint)
                .map_err(|_| CheckpointAuthorityError::InvalidResponse)?;
            CheckpointResponse::new(bytes)
        })
    }
}

#[derive(Clone)]
struct TestMembershipSource {
    records: Arc<RwLock<Vec<SignedMembershipRecord>>>,
    fail_reads: Arc<AtomicBool>,
}

impl MembershipRecordSource for TestMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<SignedMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            if self.fail_reads.load(Ordering::Acquire) {
                return Err(MembershipSourceError::Catalog);
            }
            Ok(self.records.read().await.clone())
        })
    }
}

struct Fixture {
    issuer: Arc<MembershipIssuer>,
    source: TestMembershipSource,
    runtime: Arc<MembershipRuntime>,
}

impl Fixture {
    async fn ready() -> Self {
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic publisher");
        let issuer = Arc::new(issuer);
        let authority = Arc::new(TestCheckpointAuthority {
            issuer: Arc::clone(&issuer),
            next_version: AtomicU64::new(1),
        });
        let source = TestMembershipSource {
            records: Arc::new(RwLock::new(Vec::new())),
            fail_reads: Arc::new(AtomicBool::new(false)),
        };
        let config = MembershipRuntimeConfig::new(
            DEPLOYMENT_ID,
            DEPLOYMENT_INCARNATION,
            NODE_ID,
            BOOT_ID,
            PrivateEndpointPolicy::private_ip_only(),
            Duration::from_secs(60),
            Duration::from_secs(20),
            Duration::from_secs(1),
            Duration::from_secs(1),
            Duration::from_secs(1),
        )
        .expect("bounded membership configuration")
        .with_local_spki_sha256(SPKI_SHA256)
        .expect("synthetic local SPKI");
        let trusted_key = TrustedPublisherKey::new(
            PUBLISHER_KEY_ID,
            issuer.public_key().expect("publisher public key"),
        )
        .expect("trusted publisher key");
        let runtime = MembershipRuntime::with_source(
            Arc::new(source.clone()),
            authority,
            config,
            [trusted_key],
        )
        .expect("membership runtime");
        let fixture = Self {
            issuer,
            source,
            runtime,
        };
        fixture
            .publish(fixture.record(1, "key-1", SPKI_SHA256, 30))
            .await;
        fixture
            .runtime
            .bootstrap()
            .await
            .expect("signed fixture should become ready");
        assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
        fixture
    }

    /// A record for this node approving one key, valid for `lifetime_s`.
    fn record(
        &self,
        version: u64,
        key_id: &str,
        spki: &str,
        lifetime_s: i64,
    ) -> SignedMembershipRecord {
        let now = Utc::now();
        let record = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: NODE_ID.to_owned(),
            record_version: version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: "10.0.0.1:8443".to_owned(),
            server_name: "10.0.0.1".to_owned(),
            keys: vec![RelayKey {
                key_id: key_id.to_owned(),
                spki_sha256: spki.to_owned(),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(lifetime_s),
                revoked: false,
            }],
            issued_at: now - chrono::Duration::seconds(1),
            not_before: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::seconds(lifetime_s),
        };
        SignedMembershipRecord {
            version,
            bytes: self
                .issuer
                .sign_membership_bytes(record)
                .expect("signed membership record"),
        }
    }

    async fn publish(&self, record: SignedMembershipRecord) {
        *self.source.records.write().await = vec![record];
    }

    /// Publish a re-signed record at `version` for the same node and key.
    async fn resign(&self, version: u64) {
        self.publish(self.record(version, "key-1", SPKI_SHA256, 30))
            .await;
        self.runtime
            .reconcile_once()
            .await
            .expect("a same-key re-sign reconciles Ready");
    }

    fn identity() -> MembershipPeerIdentity {
        MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256)
    }
}

fn local_pin() -> SpkiSha256 {
    let mut bytes = [0_u8; 32];
    for (index, chunk) in SPKI_SHA256.as_bytes().chunks_exact(2).enumerate() {
        let text = std::str::from_utf8(chunk).expect("ascii digest");
        bytes[index] = u8::from_str_radix(text, 16).expect("hex digest");
    }
    SpkiSha256::from_bytes(bytes)
}

/// A cluster-shaped peer runtime with every readiness input other than the
/// pin set and membership held true: listener bound, a one-node (empty)
/// required route set, capacity at the floor.
struct Wired {
    peer: Arc<PeerRuntime>,
    readiness: Arc<PeerReadiness>,
    publisher: Arc<PeerPinPublisher>,
}

fn wired(runtime: &Arc<MembershipRuntime>) -> Wired {
    let catalog: SharedCatalog = Arc::new(MemoryCatalog::new());
    let identity =
        RelayIdentity::new(DEPLOYMENT_INCARNATION, NODE_ID, BOOT_ID).expect("relay identity");
    let router: Arc<OwnerRouter<dyn tunnel_catalog::Catalog>> =
        Arc::new(OwnerRouter::new(catalog, identity).expect("owner router"));
    let endpoint = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0)))
        .expect("local synthetic QUIC endpoint");
    let pins = SharedPeerPins::new(ApprovedPeerPins::new([local_pin()]).expect("own pin"))
        .expect("dynamic pin set");
    let client =
        PeerClient::new_with_pin_provider(endpoint, pins.clone(), PeerTransportLimits::default())
            .expect("peer client");
    let readiness = Arc::new(PeerReadiness::new(1).expect("capacity floor"));
    readiness.set_listener_state(PeerListenerState::Bound);
    readiness
        .replace_required_routes(std::iter::empty())
        .expect("one-node route set");
    readiness.set_available_capacity(1);
    let peer = Arc::new(PeerRuntime::new_with_readiness(
        client,
        router,
        Arc::clone(runtime) as Arc<dyn tunnel_relay::PeerBindingProvider>,
        NODE_ID,
        BOOT_ID,
        Arc::clone(&readiness),
    ));
    let publisher = PeerPinPublisher::new(Arc::clone(runtime), pins);
    publisher.install();
    Wired {
        peer,
        readiness,
        publisher,
    }
}

// ---------------------------------------------------------------- M7-C80

/// **M7-C80.** A re-signed record for the same node and key at a higher
/// version, with a later signed boundary, keeps the active admission: its
/// cancellation token is not cancelled (so every stream riding it survives),
/// the next admission reuses it, and its deadline moves to the new boundary.
#[tokio::test]
async fn a_same_key_resign_keeps_the_active_admission() {
    let fixture = Fixture::ready().await;
    let invalidations = Arc::new(AtomicU64::new(0));
    {
        let invalidations = Arc::clone(&invalidations);
        fixture
            .runtime
            .set_invalidation_callback(Some(Arc::new(move |_identity, _reason| {
                invalidations.fetch_add(1, Ordering::AcqRel);
            })));
    }
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    let first_deadline = stream.expires_at().expect("a monotonic deadline");

    // Two seconds later, so the re-signed record's boundary is later.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    fixture.resign(2).await;
    fixture.resign(3).await;

    assert!(
        !stream.is_cancelled(),
        "M7-C80: a same-key re-sign at a higher record version cancelled the admission \
         (reason {:?}), killing every in-flight peer stream riding it",
        stream.reason()
    );
    assert_eq!(invalidations.load(Ordering::Acquire), 0);
    let renewed = stream.expires_at().expect("still bounded");
    assert!(
        renewed > first_deadline,
        "the re-bound admission carries the renewed signed boundary"
    );
    let again = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("admission after the re-sign");
    assert!(
        !admission.is_invalidated() && !again.is_invalidated(),
        "a new stream after the re-sign reuses the live admission instead of replacing it"
    );
    assert_eq!(fixture.runtime.snapshot().active_peer_count, 1);
}

/// The control for M7-C80: a re-sign that changes the key still invalidates.
/// Keeping streams must never keep a binding the new record withdrew.
#[tokio::test]
async fn a_resign_that_changes_the_key_still_invalidates_the_admission() {
    let fixture = Fixture::ready().await;
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    // Same SPKI, different key identifier: the binding changed.
    fixture
        .publish(fixture.record(2, "key-2", SPKI_SHA256, 30))
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("a key-changing re-sign still reconciles Ready");
    assert!(
        stream.is_cancelled(),
        "a changed key binding must invalidate"
    );
    assert_eq!(
        stream.reason(),
        Some(PeerInvalidationReason::MembershipChanged)
    );
}

// ---------------------------------------------------------------- M7-C86

/// **M7-C86.** A *local* unready state -- this relay's own certificate no
/// longer approved by its own record -- keeps the verified pin set installed
/// and withdraws readiness instead; a *rejected* record withdraws the set.
#[tokio::test]
async fn only_rejected_trust_evidence_withdraws_the_pin_set() {
    let fixture = Fixture::ready().await;
    let wired = wired(&fixture.runtime);
    assert_eq!(wired.publisher.publish(), PinPublication::Published);

    // Local: a record that no longer approves this relay's own key.
    fixture
        .publish(fixture.record(2, "key-2", OTHER_SPKI_SHA256, 30))
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("an unapproved local key makes membership unready");
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalKey)
    );
    assert!(
        !wired.publisher.pins().snapshot().is_empty(),
        "M7-C86: a local unready state withdrew every verified peer pin"
    );
    assert!(!wired.peer.is_ready(), "readiness is withdrawn instead");

    // Rejected evidence: a record that fails verification.
    *fixture.source.records.write().await = vec![SignedMembershipRecord {
        version: 3,
        bytes: b"not a signed membership record".to_vec(),
    }];
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("a rejected record makes membership unready");
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    assert!(
        wired.publisher.pins().snapshot().is_empty(),
        "rejected trust evidence must withdraw the pin set"
    );
}

/// Every reason is classified, so a new one has to choose deliberately.
#[test]
fn the_retention_split_names_every_unready_reason() {
    for reason in [
        MembershipUnreadyReason::UnknownAuthority,
        MembershipUnreadyReason::MembershipRejected,
        MembershipUnreadyReason::CheckpointExpired,
    ] {
        assert!(reason.withdraws_peer_trust(), "{reason:?} must fail closed");
    }
    for reason in [
        MembershipUnreadyReason::MissingLocalMembership,
        MembershipUnreadyReason::MissingLocalKey,
        MembershipUnreadyReason::CatalogUnavailable,
        MembershipUnreadyReason::PersistenceUnavailable,
        MembershipUnreadyReason::Cancelled,
    ] {
        assert!(
            !reason.withdraws_peer_trust(),
            "{reason:?} is local or transient and keeps the verified set"
        );
    }
}

// ---------------------------------------------------------------- M7-C90

/// **M7-C90.** The refresh tick, with no admission active and membership
/// unready for a transient reason (a failed catalog read), keeps the verified
/// pin set and withdraws readiness only -- the branch whose comment it always
/// carried and could never reach, because the tick had already emptied the
/// set.
#[tokio::test]
async fn the_refresh_tick_keeps_the_verified_set_while_transiently_unready() {
    let fixture = Fixture::ready().await;
    let wired = wired(&fixture.runtime);
    wired.publisher.publish();
    assert_eq!(fixture.runtime.snapshot().active_peer_count, 0);

    fixture.source.fail_reads.store(true, Ordering::Release);
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("a failed catalog read makes membership unready");
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::CatalogUnavailable)
    );
    let tick = peer_trust_tick(
        &wired.publisher,
        &wired.peer,
        NODE_ID,
        1,
        &CancellationToken::new(),
    )
    .await;
    assert_eq!(
        tick,
        PeerTrustTick::ReadinessWithdrawn,
        "M7-C90: the tick withdrew peer trust (emptied the pin set) for a transient \
         unready state with no admission active"
    );
    assert!(!wired.publisher.pins().snapshot().is_empty());
    assert!(!wired.peer.is_ready());
}

/// The control for M7-C90: rejected trust evidence withdraws the pin set at
/// the transition itself, with no admission active and no tick.
#[tokio::test]
async fn rejected_evidence_withdraws_the_pin_set_with_no_admission_and_no_tick() {
    let fixture = Fixture::ready().await;
    let wired = wired(&fixture.runtime);
    wired.publisher.publish();
    *fixture.source.records.write().await = vec![SignedMembershipRecord {
        version: 2,
        bytes: b"not a signed membership record".to_vec(),
    }];
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("a rejected record makes membership unready");
    assert!(
        wired.publisher.pins().snapshot().is_empty(),
        "the readiness transition alone must withdraw rejected trust"
    );
}

// ---------------------------------------------------------------- M7-C91

/// **M7-C91.** The reconcile that returns membership to `Ready` republishes
/// the verified pin set at once, so readiness returns within that reconcile
/// rather than on the next refresh tick. No tick runs in this test.
#[tokio::test]
async fn readiness_returns_within_the_reconcile_that_restores_membership() {
    let fixture = Fixture::ready().await;
    let wired = wired(&fixture.runtime);
    wired.publisher.publish();
    let _admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission for the invalidation to reach");
    assert!(wired.peer.is_ready(), "control: ready before the blip");

    *fixture.source.records.write().await = vec![SignedMembershipRecord {
        version: 2,
        bytes: b"not a signed membership record".to_vec(),
    }];
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("a rejected record makes membership unready");
    assert!(wired.publisher.pins().snapshot().is_empty());
    assert!(!wired.peer.is_ready());

    fixture
        .publish(fixture.record(3, "key-1", SPKI_SHA256, 30))
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("membership recovers");
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    assert!(
        wired.readiness.is_ready(),
        "precondition: route, listener and capacity readiness were never withdrawn"
    );
    assert!(
        !wired.publisher.pins().snapshot().is_empty(),
        "M7-C91: the reconcile that restored membership did not republish the pin set"
    );
    assert!(
        wired.peer.is_ready(),
        "M7-C91: readiness did not return within the reconcile that restored membership"
    );
}

// ---------------------------------------------------------------- M7-C83

/// **M7-C83 part 1.** Back-to-back re-signs -- three versions reconciled with
/// no gap, one of them racing a failed catalog read and one an unapproved
/// local key -- never leave peer trust withdrawn, and peer readiness is back
/// after the last reconcile without any refresh tick. The admission taken
/// before the first re-sign survives every one of them (M7-C80).
#[tokio::test]
async fn back_to_back_resigns_recover_peer_readiness_without_a_tick() {
    let fixture = Fixture::ready().await;
    let wired = wired(&fixture.runtime);
    wired.publisher.publish();
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();

    let mut version = 2;
    for blip in [None, Some("catalog"), None, Some("local-key"), None] {
        match blip {
            Some("catalog") => {
                fixture.source.fail_reads.store(true, Ordering::Release);
                let _ = fixture.runtime.reconcile_once().await;
                fixture.source.fail_reads.store(false, Ordering::Release);
            }
            Some(_) => {
                fixture
                    .publish(fixture.record(version, "key-x", OTHER_SPKI_SHA256, 30))
                    .await;
                version += 1;
                let _ = fixture.runtime.reconcile_once().await;
            }
            None => {}
        }
        assert!(
            !wired.publisher.pins().snapshot().is_empty(),
            "M7-C83: a re-sign racing a transient unready state emptied the pin set"
        );
        fixture.resign(version).await;
        version += 1;
    }
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    assert!(
        wired.peer.is_ready(),
        "M7-C83: peer readiness did not recover after back-to-back re-signs"
    );
    // The local-key blip invalidated the admission (this relay stopped being
    // allowed to serve); the admission retaken after it must survive the
    // later same-key re-signs.
    assert!(
        stream.is_cancelled(),
        "the local-key blip is a real invalidation"
    );
    let retaken = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("admission after recovery");
    let retaken_stream = retaken.cancellation();
    fixture.resign(version).await;
    fixture.resign(version + 1).await;
    assert!(
        !retaken_stream.is_cancelled(),
        "back-to-back same-key re-signs must not cancel a live admission"
    );
}
