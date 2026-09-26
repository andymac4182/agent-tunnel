//! Membership re-sign regressions (M7-C80, M7-C83). The peer-trust wiring
//! tests (M7-C86, M7-C90, M7-C91) are held on the draft M7-C86 branch.
//!
//! Each test drives the real `MembershipRuntime` through signed checkpoint
//! and record bytes from an in-memory source. No Redis, no checkpoint
//! service and no network: the synthetic endpoint is never dialled.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::Utc;
use tokio::sync::RwLock;
use tunnel_catalog::SignedMembershipRecord;
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipIssuer, MembershipRecord,
    PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
};
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
    MembershipRuntimeConfig, MembershipUnreadyReason, PeerInvalidationReason,
    membership_runtime::{MembershipFuture, MembershipSourceError},
};

const DEPLOYMENT_ID: &str = "m7-resign-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-resign-incarnation";
const NODE_ID: &str = "relay-resign";
const BOOT_ID: &str = "boot-resign";
const PUBLISHER_KEY_ID: &str = "publisher-resign";
const SPKI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const OTHER_SPKI_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
/// A second relay in the same signed directory, so retention can be seen to
/// keep -- or, after a revocation, drop -- a *peer's* pin.
const PEER_NODE_ID: &str = "relay-resign-peer";
const PEER_SPKI_SHA256: &str = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
const REPLACEMENT_SPKI_SHA256: &str =
    "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd";

struct TestCheckpointAuthority {
    issuer: Arc<MembershipIssuer>,
    next_version: AtomicU64,
    /// Seconds each issued checkpoint stays valid; shrinking it shrinks the
    /// signed trust window of every admission.
    lifetime_s: AtomicI64,
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
                minimum_versions: BTreeMap::from([
                    (NODE_ID.to_owned(), 1),
                    (PEER_NODE_ID.to_owned(), 1),
                ]),
                issued_at: now - chrono::Duration::seconds(1),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now
                    + chrono::Duration::seconds(self.lifetime_s.load(Ordering::Acquire)),
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
    authority: Arc<TestCheckpointAuthority>,
    source: TestMembershipSource,
    runtime: Arc<MembershipRuntime>,
    /// The peer relay's current record, republished with every local one.
    peer_record: RwLock<SignedMembershipRecord>,
}

impl Fixture {
    async fn ready() -> Self {
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic publisher");
        let issuer = Arc::new(issuer);
        let authority = Arc::new(TestCheckpointAuthority {
            issuer: Arc::clone(&issuer),
            next_version: AtomicU64::new(1),
            lifetime_s: AtomicI64::new(30),
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
            Arc::clone(&authority) as Arc<dyn CheckpointAuthority>,
            config,
            [trusted_key],
        )
        .expect("membership runtime");
        let peer_record = sign_record(
            &issuer,
            PEER_NODE_ID,
            1,
            "peer-key-1",
            PEER_SPKI_SHA256,
            30,
            false,
        );
        let fixture = Self {
            issuer,
            authority,
            source,
            runtime,
            peer_record: RwLock::new(peer_record),
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
        sign_record(
            &self.issuer,
            NODE_ID,
            version,
            key_id,
            spki,
            lifetime_s,
            false,
        )
    }

    /// Publish this node's record alongside the peer's current one.
    async fn publish(&self, record: SignedMembershipRecord) {
        let peer = self.peer_record.read().await.clone();
        *self.source.records.write().await = vec![record, peer];
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

fn sign_record(
    issuer: &MembershipIssuer,
    node_id: &str,
    version: u64,
    key_id: &str,
    spki: &str,
    lifetime_s: i64,
    revoked: bool,
) -> SignedMembershipRecord {
    let now = Utc::now();
    let host = if node_id == NODE_ID {
        "10.0.0.1"
    } else {
        "10.0.0.2"
    };
    let record = MembershipRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        node_id: node_id.to_owned(),
        record_version: version,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: format!("{host}:8443"),
        server_name: host.to_owned(),
        keys: {
            let mut keys = vec![RelayKey {
                key_id: key_id.to_owned(),
                spki_sha256: spki.to_owned(),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + chrono::Duration::seconds(lifetime_s),
                revoked,
            }];
            // A record must approve at least one key, so a revocation ships
            // with the replacement key that stays approved.
            if revoked {
                keys.push(RelayKey {
                    key_id: format!("{key_id}-replacement"),
                    spki_sha256: REPLACEMENT_SPKI_SHA256.to_owned(),
                    not_before: now - chrono::Duration::seconds(1),
                    expires_at: now + chrono::Duration::seconds(lifetime_s),
                    revoked: false,
                });
            }
            keys
        },
        issued_at: now - chrono::Duration::seconds(1),
        not_before: now - chrono::Duration::seconds(1),
        expires_at: now + chrono::Duration::seconds(lifetime_s),
    };
    SignedMembershipRecord {
        version,
        bytes: issuer
            .sign_membership_bytes(record)
            .expect("signed membership record"),
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

/// The rebind guard, part 1: a same-key record at an *equal* version whose
/// validity ends earlier is not a renewal. The verifier refuses the
/// conflicting bytes and the admission is invalidated.
#[tokio::test]
async fn an_equal_version_same_key_record_invalidates_the_admission() {
    let fixture = Fixture::ready().await;
    fixture.resign(2).await;
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    fixture
        .publish(fixture.record(2, "key-1", SPKI_SHA256, 10))
        .await;
    let _ = fixture.runtime.reconcile_once().await;
    assert!(
        stream.is_cancelled(),
        "an equal-version record with an earlier boundary must not keep the admission"
    );
}

/// The rebind guard, part 2: a *lower* version is a rollback, never a renewal.
#[tokio::test]
async fn a_lower_version_same_key_record_invalidates_the_admission() {
    let fixture = Fixture::ready().await;
    fixture.resign(3).await;
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    fixture
        .publish(fixture.record(2, "key-1", SPKI_SHA256, 10))
        .await;
    let _ = fixture.runtime.reconcile_once().await;
    assert!(
        stream.is_cancelled(),
        "a lower-version record must not keep the admission"
    );
}

/// The rebind guard, part 3: a higher version whose own validity ends
/// earlier shrinks the signed boundary and invalidates.
#[tokio::test]
async fn a_higher_version_with_an_earlier_boundary_invalidates_the_admission() {
    let fixture = Fixture::ready().await;
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    fixture
        .publish(fixture.record(2, "key-1", SPKI_SHA256, 10))
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("a shorter record still reconciles Ready");
    assert!(
        stream.is_cancelled(),
        "a shrunk record boundary must invalidate"
    );
    assert_eq!(
        stream.reason(),
        Some(PeerInvalidationReason::MembershipChanged)
    );
}

/// The rebind guard, part 4: a shrunk *checkpoint* window shrinks the trust
/// boundary of every admission and invalidates, even with the record
/// unchanged.
#[tokio::test]
async fn a_shrunk_checkpoint_window_invalidates_the_admission() {
    let fixture = Fixture::ready().await;
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("an active admission");
    let stream = admission.cancellation();
    fixture.authority.lifetime_s.store(5, Ordering::Release);
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("a shorter checkpoint still reconciles Ready");
    assert!(
        stream.is_cancelled(),
        "a shrunk checkpoint window must invalidate the admission"
    );
}

// ---------------------------------------------------------------- M7-C86

/// **M7-C86 is held on this branch.** Every unready reason withdraws the
/// pin set, as before the split, because the split regresses
/// `verify-m7-trust-expiry` (base 20/20, split 10/20). Naming every reason
/// keeps that a deliberate, one-line decision.
#[test]
fn while_the_retention_split_is_held_every_unready_reason_withdraws() {
    for reason in [
        MembershipUnreadyReason::UnknownAuthority,
        MembershipUnreadyReason::MembershipRejected,
        MembershipUnreadyReason::CheckpointExpired,
        MembershipUnreadyReason::MissingLocalMembership,
        MembershipUnreadyReason::MissingLocalKey,
        MembershipUnreadyReason::CatalogUnavailable,
        MembershipUnreadyReason::PersistenceUnavailable,
        MembershipUnreadyReason::Cancelled,
    ] {
        assert!(reason.withdraws_peer_trust(), "{reason:?} must fail closed");
    }
}

// ---------------------------------------------------------------- M7-C90

// ---------------------------------------------------------------- M7-C91

// ---------------------------------------------------------------- M7-C83

/// **M7-C83 part 1, at the membership runtime.** Back-to-back same-key
/// re-signs reconciled with no gap -- one racing a failed catalog read, one
/// an unapproved local key -- end with membership `Ready`, and an admission
/// taken after the last blip survives every later same-key re-sign (M7-C80).
/// Peer readiness recovery through the pin wiring is held with M7-C86 and
/// its wiring rows (M7-C90, M7-C91) on the draft branch.
#[tokio::test]
async fn back_to_back_resigns_end_ready_and_keep_a_live_admission() {
    let fixture = Fixture::ready().await;
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
        fixture.resign(version).await;
        version += 1;
        assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
    }
    let admission = fixture
        .runtime
        .admit_peer(Fixture::identity())
        .expect("admission after recovery");
    let stream = admission.cancellation();
    for _ in 0..3 {
        fixture.resign(version).await;
        version += 1;
    }
    assert!(
        !stream.is_cancelled(),
        "M7-C83: back-to-back same-key re-signs cancelled a live admission"
    );
}
