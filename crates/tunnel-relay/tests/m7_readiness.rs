//! M7 startup and readiness regressions.
//!
//! These tests stay at the public membership-runtime boundary.  They use an
//! in-memory signed checkpoint authority and an opaque membership source so
//! the failure paths remain deterministic and do not require Redis, a private
//! listener, or a production desktop.

use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use chrono::{DateTime, Utc};
use tokio::sync::RwLock;
use tunnel_catalog::SignedMembershipRecord as CatalogMembershipRecord;
use tunnel_cluster::membership::{
    MEMBERSHIP_SCHEMA_VERSION, MembershipCheckpoint, MembershipError, MembershipIssuer,
    MembershipRecord, PrivateEndpointPolicy, RELAY_PEER_ROLE, RelayKey, TrustedPublisherKey,
};
use tunnel_relay::membership_runtime::{
    LocalKeyApproval, LocalServingSwitchError, MembershipFuture, MembershipSourceError,
    MembershipUnreadyReason,
};
use tunnel_relay::{
    CheckpointAuthority, CheckpointAuthorityError, CheckpointRequest, CheckpointResponse,
    MembershipPeerIdentity, MembershipReadiness, MembershipRecordSource, MembershipRuntime,
    MembershipRuntimeConfig, MembershipRuntimeError,
};

const DEPLOYMENT_ID: &str = "m7-readiness-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-readiness-incarnation";
const NODE_ID: &str = "relay-a";
const BOOT_ID: &str = "boot-a";
const PUBLISHER_KEY_ID: &str = "publisher-1";
const SPKI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const NEXT_SPKI_SHA256: &str = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
const RELAY_KEY_ID: &str = "relay-key-1";
const NEXT_RELAY_KEY_ID: &str = "relay-key-2";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum AuthorityMode {
    Ready = 0,
    Failed = 1,
    ExpiredCheckpoint = 2,
}

struct TestCheckpointAuthority {
    issuer: Arc<MembershipIssuer>,
    next_checkpoint_version: AtomicU64,
    mode: AtomicU8,
    include_local_membership: AtomicBool,
    /// While set, a fetch parks until `release` is notified, so a test can
    /// hold a reconciliation pass -- and with it the reconcile gate -- open.
    hold: AtomicBool,
    held: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

impl TestCheckpointAuthority {
    fn new(issuer: Arc<MembershipIssuer>, include_local_membership: bool) -> Self {
        Self {
            issuer,
            next_checkpoint_version: AtomicU64::new(1),
            mode: AtomicU8::new(AuthorityMode::Ready as u8),
            include_local_membership: AtomicBool::new(include_local_membership),
            hold: AtomicBool::new(false),
            held: tokio::sync::Notify::new(),
            release: tokio::sync::Notify::new(),
        }
    }

    fn set_mode(&self, mode: AuthorityMode) {
        self.mode.store(mode as u8, Ordering::Release);
    }

    fn mode(&self) -> AuthorityMode {
        match self.mode.load(Ordering::Acquire) {
            value if value == AuthorityMode::Failed as u8 => AuthorityMode::Failed,
            value if value == AuthorityMode::ExpiredCheckpoint as u8 => {
                AuthorityMode::ExpiredCheckpoint
            }
            _ => AuthorityMode::Ready,
        }
    }
}

impl CheckpointAuthority for TestCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            if self.hold.swap(false, Ordering::AcqRel) {
                self.held.notify_one();
                self.release.notified().await;
            }
            if self.mode() == AuthorityMode::Failed {
                return Err(CheckpointAuthorityError::Transport);
            }

            let now = Utc::now();
            let (issued_at, not_before, expires_at) =
                if self.mode() == AuthorityMode::ExpiredCheckpoint {
                    (
                        now - chrono::Duration::seconds(10),
                        now - chrono::Duration::seconds(10),
                        now - chrono::Duration::seconds(2),
                    )
                } else {
                    (
                        now - chrono::Duration::seconds(1),
                        now - chrono::Duration::seconds(1),
                        now + chrono::Duration::seconds(30),
                    )
                };

            let mut minimum_versions = BTreeMap::new();
            if self.include_local_membership.load(Ordering::Acquire) {
                minimum_versions.insert(NODE_ID.to_owned(), 1);
            }
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_checkpoint_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions,
                issued_at,
                not_before,
                expires_at,
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
    records: Arc<RwLock<Vec<CatalogMembershipRecord>>>,
    fail_reads: Arc<AtomicBool>,
    read_count: Arc<AtomicUsize>,
}

impl TestMembershipSource {
    fn new(records: Vec<CatalogMembershipRecord>) -> Self {
        Self {
            records: Arc::new(RwLock::new(records)),
            fail_reads: Arc::new(AtomicBool::new(false)),
            read_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    async fn replace(&self, records: Vec<CatalogMembershipRecord>) {
        *self.records.write().await = records;
    }

    fn set_fail_reads(&self, fail: bool) {
        self.fail_reads.store(fail, Ordering::Release);
    }

    fn read_count(&self) -> usize {
        self.read_count.load(Ordering::Acquire)
    }
}

impl MembershipRecordSource for TestMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            self.read_count.fetch_add(1, Ordering::AcqRel);
            if self.fail_reads.load(Ordering::Acquire) {
                return Err(MembershipSourceError::Catalog);
            }
            Ok(self.records.read().await.clone())
        })
    }
}

struct RuntimeFixture {
    trusted_issuer: Arc<MembershipIssuer>,
    authority: Arc<TestCheckpointAuthority>,
    source: TestMembershipSource,
    runtime: Arc<MembershipRuntime>,
}

impl RuntimeFixture {
    fn new(include_local_membership: bool) -> Self {
        Self::new_with_local_spki(include_local_membership, SPKI_SHA256)
    }

    fn new_with_local_spki(include_local_membership: bool, local_spki_sha256: &str) -> Self {
        let (issuer, _private_key) =
            MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic membership issuer");
        let trusted_issuer = Arc::new(issuer);
        let authority = Arc::new(TestCheckpointAuthority::new(
            Arc::clone(&trusted_issuer),
            include_local_membership,
        ));
        let source = TestMembershipSource::new(Vec::new());
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
        .expect("bounded runtime configuration")
        .with_local_spki_sha256(local_spki_sha256)
        .expect("synthetic local SPKI pin");
        let trusted_key = TrustedPublisherKey::new(
            PUBLISHER_KEY_ID,
            trusted_issuer.public_key().expect("issuer public key"),
        )
        .expect("trusted publisher key");
        let runtime = MembershipRuntime::with_source(
            Arc::new(source.clone()),
            authority.clone(),
            config,
            [trusted_key],
        )
        .expect("membership runtime");
        Self {
            trusted_issuer,
            authority,
            source,
            runtime,
        }
    }

    fn record(
        issuer: &MembershipIssuer,
        record_version: u64,
        expires_at: DateTime<Utc>,
    ) -> CatalogMembershipRecord {
        let now = Utc::now();
        let not_before = if expires_at <= now {
            expires_at - chrono::Duration::seconds(10)
        } else {
            now - chrono::Duration::seconds(1)
        };
        Self::record_with_keys(
            issuer,
            record_version,
            not_before,
            expires_at,
            vec![RelayKey {
                key_id: RELAY_KEY_ID.to_owned(),
                spki_sha256: SPKI_SHA256.to_owned(),
                not_before,
                expires_at,
                revoked: false,
            }],
        )
    }

    fn record_with_keys(
        issuer: &MembershipIssuer,
        record_version: u64,
        not_before: DateTime<Utc>,
        expires_at: DateTime<Utc>,
        keys: Vec<RelayKey>,
    ) -> CatalogMembershipRecord {
        let record = MembershipRecord {
            schema_version: MEMBERSHIP_SCHEMA_VERSION,
            deployment_id: DEPLOYMENT_ID.to_owned(),
            deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
            node_id: NODE_ID.to_owned(),
            record_version,
            roles: vec![RELAY_PEER_ROLE.to_owned()],
            peer_endpoint: "10.0.0.1:8443".to_owned(),
            server_name: "10.0.0.1".to_owned(),
            keys,
            issued_at: not_before,
            not_before,
            expires_at,
        };
        CatalogMembershipRecord {
            version: record_version,
            bytes: issuer
                .sign_membership_bytes(record)
                .expect("synthetic signed membership"),
        }
    }

    fn valid_record(&self, record_version: u64) -> CatalogMembershipRecord {
        Self::record(
            &self.trusted_issuer,
            record_version,
            Utc::now() + chrono::Duration::seconds(30),
        )
    }

    fn expired_record(&self, record_version: u64) -> CatalogMembershipRecord {
        Self::record(
            &self.trusted_issuer,
            record_version,
            Utc::now() - chrono::Duration::seconds(2),
        )
    }

    fn overlap_record(&self, record_version: u64) -> CatalogMembershipRecord {
        let now = Utc::now();
        let record_not_before = now - chrono::Duration::seconds(10);
        let old_not_before = now - chrono::Duration::seconds(10);
        let new_not_before = now - chrono::Duration::seconds(5);
        Self::record_with_keys(
            &self.trusted_issuer,
            record_version,
            record_not_before,
            now + chrono::Duration::seconds(30),
            vec![
                RelayKey {
                    key_id: RELAY_KEY_ID.to_owned(),
                    spki_sha256: SPKI_SHA256.to_owned(),
                    not_before: old_not_before,
                    expires_at: now + chrono::Duration::seconds(10),
                    revoked: false,
                },
                RelayKey {
                    key_id: NEXT_RELAY_KEY_ID.to_owned(),
                    spki_sha256: NEXT_SPKI_SHA256.to_owned(),
                    not_before: new_not_before,
                    expires_at: now + chrono::Duration::seconds(30),
                    revoked: false,
                },
            ],
        )
    }

    fn next_key_only_record(&self, record_version: u64) -> CatalogMembershipRecord {
        let now = Utc::now();
        Self::record_with_keys(
            &self.trusted_issuer,
            record_version,
            now - chrono::Duration::seconds(5),
            now + chrono::Duration::seconds(30),
            vec![RelayKey {
                key_id: NEXT_RELAY_KEY_ID.to_owned(),
                spki_sha256: NEXT_SPKI_SHA256.to_owned(),
                not_before: now - chrono::Duration::seconds(5),
                expires_at: now + chrono::Duration::seconds(30),
                revoked: false,
            }],
        )
    }

    fn expired_old_key_record(&self, record_version: u64) -> CatalogMembershipRecord {
        let now = Utc::now();
        Self::record_with_keys(
            &self.trusted_issuer,
            record_version,
            now - chrono::Duration::seconds(10),
            now + chrono::Duration::seconds(30),
            vec![
                RelayKey {
                    key_id: RELAY_KEY_ID.to_owned(),
                    spki_sha256: SPKI_SHA256.to_owned(),
                    not_before: now - chrono::Duration::seconds(10),
                    expires_at: now - chrono::Duration::seconds(2),
                    revoked: false,
                },
                RelayKey {
                    key_id: NEXT_RELAY_KEY_ID.to_owned(),
                    spki_sha256: NEXT_SPKI_SHA256.to_owned(),
                    not_before: now - chrono::Duration::seconds(5),
                    expires_at: now + chrono::Duration::seconds(30),
                    revoked: false,
                },
            ],
        )
    }

    fn peer_identity() -> MembershipPeerIdentity {
        MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256)
    }

    fn peer_identity_with(boot_id: &str, spki_sha256: &str) -> MembershipPeerIdentity {
        MembershipPeerIdentity::new(NODE_ID, boot_id, spki_sha256)
    }
}

#[tokio::test]
async fn fp10_ec010_invalid_membership_signature_keeps_startup_unready() {
    let fixture = RuntimeFixture::new(true);
    let (rogue_issuer, _private_key) =
        MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic rogue issuer");
    fixture
        .source
        .replace(vec![RuntimeFixture::record(
            &rogue_issuer,
            1,
            Utc::now() + chrono::Duration::seconds(30),
        )])
        .await;

    let error = fixture
        .runtime
        .bootstrap()
        .await
        .expect_err("invalid signature must fail startup");
    assert!(matches!(
        error,
        MembershipRuntimeError::Membership(MembershipError::SignatureInvalid)
    ));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    assert_eq!(fixture.source.read_count(), 1);
}

#[tokio::test]
async fn fp10_ec010_expired_checkpoint_keeps_startup_unready_before_catalog_read() {
    let fixture = RuntimeFixture::new(true);
    fixture.source.replace(vec![fixture.valid_record(1)]).await;
    fixture.authority.set_mode(AuthorityMode::ExpiredCheckpoint);

    let error = fixture
        .runtime
        .bootstrap()
        .await
        .expect_err("expired checkpoint must fail startup");
    assert!(matches!(error, MembershipRuntimeError::CheckpointExpired));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired)
    );
    assert_eq!(
        fixture.source.read_count(),
        0,
        "untrusted catalog data must not be read after checkpoint expiry"
    );
}

#[tokio::test]
async fn fp10_ec010_missing_local_membership_keeps_runtime_unready() {
    let fixture = RuntimeFixture::new(false);

    let error = fixture
        .runtime
        .bootstrap()
        .await
        .expect_err("a checkpoint without the local node must not become ready");
    assert!(matches!(error, MembershipRuntimeError::NotReady));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MissingLocalMembership)
    );
    assert_eq!(fixture.source.read_count(), 1);
}

#[tokio::test]
async fn ec011_failed_catalog_refresh_blocks_new_admission() {
    let fixture = RuntimeFixture::new(true);
    fixture.source.replace(vec![fixture.valid_record(1)]).await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("initial signed directory should become ready");
    let admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity())
        .expect("ready runtime should admit the signed peer");

    fixture.source.set_fail_reads(true);
    let error = fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("failed catalog refresh must fail closed");
    assert!(matches!(
        error,
        MembershipRuntimeError::Source(MembershipSourceError::Catalog)
    ));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::CatalogUnavailable)
    );
    assert!(!admission.is_invalidated());
    assert!(matches!(
        fixture.runtime.admit_peer(RuntimeFixture::peer_identity()),
        Err(MembershipRuntimeError::NotReady)
    ));
}

#[tokio::test]
async fn ec011_expired_membership_refresh_withdraws_admitted_peer() {
    let fixture = RuntimeFixture::new(true);
    fixture.source.replace(vec![fixture.valid_record(1)]).await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("initial signed directory should become ready");
    let admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity())
        .expect("ready runtime should admit the signed peer");

    fixture
        .source
        .replace(vec![fixture.expired_record(1)])
        .await;
    let error = fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("expired membership must fail closed");
    assert!(matches!(
        error,
        MembershipRuntimeError::Membership(MembershipError::Expired)
    ));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    assert!(admission.is_invalidated());
    assert_eq!(fixture.runtime.snapshot().active_peer_count, 0);
}

#[tokio::test]
async fn ec010_staged_key_overlap_accepts_old_and_new_peer_pins() {
    let fixture = RuntimeFixture::new_with_local_spki(true, NEXT_SPKI_SHA256);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("overlap record should make the runtime ready");

    let old_admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity_with("boot-old", SPKI_SHA256))
        .expect("the old pin remains valid during overlap");
    let new_admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity_with(
            "boot-new",
            NEXT_SPKI_SHA256,
        ))
        .expect("the staged pin is valid during overlap");
    assert_eq!(old_admission.binding().key_id(), RELAY_KEY_ID);
    assert_eq!(new_admission.binding().key_id(), NEXT_RELAY_KEY_ID);
}

#[tokio::test]
async fn ec010_local_pin_survives_overlap_then_expires_independently() {
    // The local relay still presents the old certificate while the signed
    // directory carries a newer, unrelated overlap pin.  Readiness must use
    // the configured local SPKI rather than whichever valid key is last in
    // the signed list.
    let fixture = RuntimeFixture::new(true);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("the configured old pin should remain ready during overlap");
    let old_admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity())
        .expect("the configured old pin should remain admissible during overlap");
    assert_eq!(old_admission.binding().key_id(), RELAY_KEY_ID);

    fixture
        .source
        .replace(vec![fixture.expired_old_key_record(2)])
        .await;
    let error = fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("an expired configured local pin must fail closed as expiry");
    assert!(matches!(error, MembershipRuntimeError::CheckpointExpired));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::CheckpointExpired)
    );
    assert!(old_admission.is_invalidated());
}

#[tokio::test]
async fn ec010_key_removal_withdraws_old_peer_and_rejects_old_pin() {
    let fixture = RuntimeFixture::new_with_local_spki(true, NEXT_SPKI_SHA256);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("overlap record should make the runtime ready");
    let old_identity = RuntimeFixture::peer_identity_with("boot-old", SPKI_SHA256);
    let old_admission = fixture
        .runtime
        .admit_peer(old_identity.clone())
        .expect("the old pin should be admitted before retirement");

    fixture
        .source
        .replace(vec![fixture.next_key_only_record(2)])
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("higher revision removing the old key should reconcile");

    assert!(old_admission.is_invalidated());
    assert!(matches!(
        fixture.runtime.admit_peer(old_identity),
        Err(MembershipRuntimeError::PeerRejected)
    ));
    let new_admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity_with(
            "boot-new",
            NEXT_SPKI_SHA256,
        ))
        .expect("the replacement pin should remain admitted");
    assert_eq!(new_admission.binding().key_id(), NEXT_RELAY_KEY_ID);
}

#[tokio::test]
async fn ec010_expired_old_key_withdraws_old_peer_and_rejects_old_pin() {
    let fixture = RuntimeFixture::new_with_local_spki(true, NEXT_SPKI_SHA256);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("overlap record should make the runtime ready");
    let old_identity = RuntimeFixture::peer_identity_with("boot-old", SPKI_SHA256);
    let old_admission = fixture
        .runtime
        .admit_peer(old_identity.clone())
        .expect("the old pin should be admitted before expiry");

    fixture
        .source
        .replace(vec![fixture.expired_old_key_record(2)])
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("higher revision with an expired old key should reconcile");

    assert!(old_admission.is_invalidated());
    assert!(matches!(
        fixture.runtime.admit_peer(old_identity),
        Err(MembershipRuntimeError::PeerRejected)
    ));
    let new_admission = fixture
        .runtime
        .admit_peer(RuntimeFixture::peer_identity_with(
            "boot-new",
            NEXT_SPKI_SHA256,
        ))
        .expect("the replacement pin should remain admitted");
    assert_eq!(new_admission.binding().key_id(), NEXT_RELAY_KEY_ID);
}

#[tokio::test]
async fn ec011_periodic_reconcile_applies_rotation_without_refresh_hint() {
    let fixture = RuntimeFixture::new_with_local_spki(true, NEXT_SPKI_SHA256);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture
        .runtime
        .bootstrap()
        .await
        .expect("overlap record should make the runtime ready");
    let old_identity = RuntimeFixture::peer_identity_with("boot-old", SPKI_SHA256);
    let old_admission = fixture
        .runtime
        .admit_peer(old_identity.clone())
        .expect("the old pin should be admitted before polling");
    let reads_before_rotation = fixture.source.read_count();

    // Deliberately do not call notify_membership_changed: this pass models
    // the periodic authenticated read required when Pub/Sub loses a hint.
    fixture
        .source
        .replace(vec![fixture.next_key_only_record(2)])
        .await;
    let snapshot = fixture
        .runtime
        .reconcile_once()
        .await
        .expect("periodic reconciliation should observe the new revision");

    assert_eq!(fixture.source.read_count(), reads_before_rotation + 1);
    assert_eq!(snapshot.generation, 2);
    assert!(old_admission.is_invalidated());
    assert!(matches!(
        fixture.runtime.admit_peer(old_identity),
        Err(MembershipRuntimeError::PeerRejected)
    ));
    assert!(
        fixture
            .runtime
            .admit_peer(RuntimeFixture::peer_identity_with(
                "boot-new",
                NEXT_SPKI_SHA256
            ))
            .is_ok()
    );
}

// ---- M8-C45: a relay switches the identity it serves without restarting ----

#[tokio::test]
async fn m8c45_switching_the_served_key_keeps_the_relay_ready_when_the_old_key_is_withdrawn() {
    // The relay starts serving the old key; the record approves old + next.
    let fixture = RuntimeFixture::new(true);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture.runtime.bootstrap().await.expect("overlap ready");
    assert_eq!(
        fixture.runtime.local_serving_spki().as_deref(),
        Some(SPKI_SHA256)
    );
    assert!(
        fixture
            .runtime
            .local_key_approval(NEXT_SPKI_SHA256)
            .is_approved()
    );

    let mut installed = false;
    fixture
        .runtime
        .switch_local_serving_spki(NEXT_SPKI_SHA256, || {
            installed = true;
            Ok::<(), ()>(())
        })
        .await
        .expect("an approved successor may be served");
    assert!(installed);
    assert_eq!(
        fixture.runtime.local_serving_spki().as_deref(),
        Some(NEXT_SPKI_SHA256)
    );
    assert_eq!(
        fixture
            .runtime
            .local_peer_identity()
            .map(|identity| identity.spki_sha256),
        Some(NEXT_SPKI_SHA256.to_owned())
    );

    // The publisher withdraws the predecessor.  The relay now serves the
    // successor, so it stays Ready: this is the interval M8-C28 said the
    // product could not have.
    fixture
        .source
        .replace(vec![fixture.next_key_only_record(2)])
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("withdrawing the predecessor must not unready a relay serving the successor");
    assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
}

#[tokio::test]
async fn m8c45_without_the_switch_withdrawing_the_served_key_still_fails_closed() {
    // The control: the same records, no switch.  Readiness is bound to the
    // key actually served, so withdrawing it unreadies the relay exactly as
    // before -- a staged or merely approved successor never stands in.
    let fixture = RuntimeFixture::new(true);
    fixture
        .source
        .replace(vec![fixture.overlap_record(1)])
        .await;
    fixture.runtime.bootstrap().await.expect("overlap ready");
    fixture
        .source
        .replace(vec![fixture.next_key_only_record(2)])
        .await;
    let error = fixture
        .runtime
        .reconcile_once()
        .await
        .expect_err("the served key left the record");
    assert!(matches!(error, MembershipRuntimeError::PeerRejected));
    assert_eq!(
        fixture.runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
}

#[tokio::test]
async fn m8c45_a_switch_to_an_unapproved_key_is_refused_before_anything_is_installed() {
    let fixture = RuntimeFixture::new(true);
    fixture.source.replace(vec![fixture.valid_record(1)]).await;
    fixture.runtime.bootstrap().await.expect("single-key ready");
    assert_eq!(
        fixture.runtime.local_key_approval(NEXT_SPKI_SHA256),
        LocalKeyApproval::Absent
    );
    let mut installed = false;
    let refused = fixture
        .runtime
        .switch_local_serving_spki(NEXT_SPKI_SHA256, || {
            installed = true;
            Ok::<(), ()>(())
        })
        .await;
    assert!(matches!(
        refused,
        Err(LocalServingSwitchError::NotApproved(
            LocalKeyApproval::Absent
        ))
    ));
    assert!(!installed, "nothing may be installed for an unapproved key");
    assert_eq!(
        fixture.runtime.local_serving_spki().as_deref(),
        Some(SPKI_SHA256)
    );

    // An install failure leaves readiness bound to the previous key.
    fixture
        .source
        .replace(vec![fixture.overlap_record(2)])
        .await;
    fixture
        .runtime
        .reconcile_once()
        .await
        .expect("overlap ready");
    let failed = fixture
        .runtime
        .switch_local_serving_spki(NEXT_SPKI_SHA256, || Err::<(), _>("transport refused"))
        .await;
    assert!(matches!(failed, Err(LocalServingSwitchError::Install(_))));
    assert_eq!(
        fixture.runtime.local_serving_spki().as_deref(),
        Some(SPKI_SHA256)
    );
}

// ---- M8-C45, M7-C151..M7-C153: the rotation state machine ------------------

mod rekey {
    use super::*;
    use tunnel_relay::peer_rekey::{
        PeerRekey, PeerRekeyConfig, PeerRekeyError, PeerRekeyPhase, PeerRekeyRetirement,
    };
    use tunnel_transport::{PeerIdentityError, RotatingPeerIdentity, StagedPeerIdentity};

    struct Pki {
        ca: rcgen::Certificate,
        ca_key: rcgen::KeyPair,
        ca_pem: String,
    }

    struct Leaf {
        chain: String,
        key: String,
        spki: String,
    }

    impl Pki {
        fn new() -> Self {
            let ca_key = rcgen::KeyPair::generate().expect("CA key");
            let mut params = rcgen::CertificateParams::default();
            params
                .distinguished_name
                .push(rcgen::DnType::CommonName, "rekey CA");
            params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            params.key_usages = vec![
                rcgen::KeyUsagePurpose::KeyCertSign,
                rcgen::KeyUsagePurpose::CrlSign,
            ];
            let ca = params.self_signed(&ca_key).expect("CA");
            Self {
                ca_pem: ca.pem(),
                ca,
                ca_key,
            }
        }

        fn peer(&self, node: &str) -> Leaf {
            let key = rcgen::KeyPair::generate().expect("leaf key");
            let mut params =
                rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
            params.subject_alt_names.push(rcgen::SanType::URI(
                format!("urn:agent-tunnel:peer:{node}")
                    .try_into()
                    .expect("URI"),
            ));
            params.key_usages = vec![rcgen::KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![
                rcgen::ExtendedKeyUsagePurpose::ServerAuth,
                rcgen::ExtendedKeyUsagePurpose::ClientAuth,
            ];
            let certificate = params
                .signed_by(&key, &self.ca, &self.ca_key)
                .expect("leaf");
            Leaf {
                chain: format!("{}{}", certificate.pem(), self.ca_pem),
                key: key.serialize_pem(),
                spki: tunnel_transport::spki_sha256_from_der(certificate.der())
                    .expect("SPKI")
                    .to_hex(),
            }
        }
    }

    /// A record for this node approving `spkis` (in that activation order),
    /// with `revoked` marking any of them revoked.
    fn record(
        fixture: &RuntimeFixture,
        version: u64,
        spkis: &[&str],
        revoked: &[&str],
    ) -> CatalogMembershipRecord {
        let now = Utc::now();
        let keys = spkis
            .iter()
            .enumerate()
            .map(|(index, spki)| RelayKey {
                key_id: format!("rekey-{index}"),
                spki_sha256: (*spki).to_owned(),
                not_before: now - chrono::Duration::seconds(10 - index as i64),
                expires_at: now + chrono::Duration::seconds(30),
                revoked: revoked.contains(spki),
            })
            .collect();
        RuntimeFixture::record_with_keys(
            &fixture.trusted_issuer,
            version,
            now - chrono::Duration::seconds(10),
            now + chrono::Duration::seconds(30),
            keys,
        )
    }

    const HOLD: Duration = Duration::from_millis(300);

    fn machine(fixture: &RuntimeFixture, pki: &Pki, current: &Leaf) -> Arc<PeerRekey> {
        let identity = RotatingPeerIdentity::from_pem_at_startup(
            current.chain.as_bytes(),
            current.key.as_bytes(),
        )
        .expect("current identity");
        PeerRekey::new(
            identity,
            Arc::clone(&fixture.runtime),
            None,
            pki.ca_pem.as_bytes().to_vec(),
            PeerRekeyConfig {
                convergence_hold: HOLD,
                overlap: Duration::from_secs(600),
                tick: Duration::from_millis(50),
            },
        )
    }

    #[tokio::test(start_paused = true)]
    async fn m8c45_stage_waits_for_a_continuous_approval_then_switches_and_retires_on_withdrawal() {
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        fixture
            .source
            .replace(vec![record(&fixture, 1, &[&current.spki], &[])])
            .await;
        fixture.runtime.bootstrap().await.expect("ready");
        let rekey = machine(&fixture, &pki, &current);

        let staged = rekey
            .stage_pem(next.chain.as_bytes(), next.key.as_bytes())
            .expect("staged");
        assert_eq!(staged, next.spki);
        // Not approved: staged, never served.
        let snapshot = rekey.tick().await;
        assert_eq!(snapshot.phase, PeerRekeyPhase::Staged);
        assert_eq!(snapshot.staged_approval, Some("absent"));
        assert_eq!(snapshot.serving_spki, current.spki);

        // Approved, but not yet for the hold.
        fixture
            .source
            .replace(vec![record(&fixture, 2, &[&current.spki, &next.spki], &[])])
            .await;
        fixture.runtime.reconcile_once().await.expect("overlap");
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Staged);
        tokio::time::sleep(HOLD / 2).await;
        // Approval lost before the hold elapsed: the hold restarts (M7-C152).
        fixture
            .source
            .replace(vec![record(&fixture, 3, &[&current.spki], &[])])
            .await;
        fixture.runtime.reconcile_once().await.expect("single key");
        assert_eq!(rekey.tick().await.staged_approval, Some("absent"));
        fixture
            .source
            .replace(vec![record(&fixture, 4, &[&current.spki, &next.spki], &[])])
            .await;
        fixture
            .runtime
            .reconcile_once()
            .await
            .expect("overlap again");
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Staged);
        tokio::time::sleep(HOLD / 2).await;
        assert_eq!(
            rekey.tick().await.phase,
            PeerRekeyPhase::Staged,
            "the hold restarted when approval was lost, so half of it is not enough"
        );
        tokio::time::sleep(HOLD).await;
        let switched = rekey.tick().await;
        assert_eq!(switched.phase, PeerRekeyPhase::Overlap);
        assert_eq!(switched.serving_spki, next.spki);
        assert_eq!(
            switched.previous_spki.as_deref(),
            Some(current.spki.as_str())
        );
        assert_eq!(
            fixture.runtime.local_serving_spki().as_deref(),
            Some(next.spki.as_str())
        );

        // The publisher withdraws the predecessor: still Ready, and retired.
        fixture
            .source
            .replace(vec![record(&fixture, 5, &[&next.spki], &[])])
            .await;
        fixture
            .runtime
            .reconcile_once()
            .await
            .expect("successor only");
        assert_eq!(fixture.runtime.readiness(), MembershipReadiness::Ready);
        let retired = rekey.tick().await;
        assert_eq!(retired.phase, PeerRekeyPhase::Stable);
        assert_eq!(
            retired.last_retirement,
            Some(PeerRekeyRetirement::Withdrawn)
        );
        assert_eq!(
            (retired.stages, retired.switches, retired.retirements),
            (1, 1, 1)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn m7c152_a_transient_unready_state_neither_restarts_the_hold_nor_switches() {
        // A failed catalog read or checkpoint fetch takes the runtime Unready
        // for one pass.  That is not an observation that approval was lost:
        // the hold already served is kept, and nothing switches while Unready.
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        fixture
            .source
            .replace(vec![record(&fixture, 1, &[&current.spki, &next.spki], &[])])
            .await;
        fixture.runtime.bootstrap().await.expect("overlap ready");
        let rekey = machine(&fixture, &pki, &current);
        rekey
            .stage_pem(next.chain.as_bytes(), next.key.as_bytes())
            .expect("staged");
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Staged);
        tokio::time::sleep(HOLD * 3 / 4).await;
        fixture.authority.set_mode(AuthorityMode::Failed);
        let _ = fixture.runtime.reconcile_once().await;
        assert!(!matches!(
            fixture.runtime.readiness(),
            MembershipReadiness::Ready
        ));
        tokio::time::sleep(HOLD / 2).await;
        let unready = rekey.tick().await;
        assert_eq!(
            unready.phase,
            PeerRekeyPhase::Staged,
            "never switch while Unready"
        );
        assert_eq!(unready.staged_approval, Some("not_ready"));
        fixture.authority.set_mode(AuthorityMode::Ready);
        fixture.runtime.reconcile_once().await.expect("ready again");
        // More than a hold has passed since approval was first seen, and it
        // was never observed withdrawn: the first Ready tick switches.
        let switched = rekey.tick().await;
        assert_eq!(switched.phase, PeerRekeyPhase::Overlap);
        assert_eq!(switched.serving_spki, next.spki);
    }

    #[tokio::test(start_paused = true)]
    async fn m7c151_a_staged_key_the_record_revokes_is_discarded_and_never_served() {
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        fixture
            .source
            .replace(vec![record(
                &fixture,
                1,
                &[&current.spki, &next.spki],
                &[&next.spki],
            )])
            .await;
        fixture.runtime.bootstrap().await.expect("ready");
        let rekey = machine(&fixture, &pki, &current);
        rekey
            .stage_pem(next.chain.as_bytes(), next.key.as_bytes())
            .expect("staged");
        tokio::time::sleep(HOLD * 2).await;
        let snapshot = rekey.tick().await;
        assert_eq!(snapshot.phase, PeerRekeyPhase::Stable);
        assert_eq!(snapshot.serving_spki, current.spki);
        assert_eq!(snapshot.last_refusal, Some("staged_key_revoked"));
        assert_eq!(snapshot.switches, 0);
    }

    #[tokio::test(start_paused = true)]
    async fn m7c153_staging_is_refused_while_a_rotation_is_in_progress_or_for_the_wrong_identity() {
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let another = pki.peer(NODE_ID);
        let foreign = pki.peer("relay-z");
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        fixture
            .source
            .replace(vec![record(&fixture, 1, &[&current.spki], &[])])
            .await;
        fixture.runtime.bootstrap().await.expect("ready");
        let rekey = machine(&fixture, &pki, &current);
        assert!(matches!(
            rekey.stage_pem(current.chain.as_bytes(), current.key.as_bytes()),
            Err(PeerRekeyError::SameKey)
        ));
        assert!(matches!(
            rekey.stage_pem(foreign.chain.as_bytes(), foreign.key.as_bytes()),
            Err(PeerRekeyError::Identity(PeerIdentityError::DifferentNode))
        ));
        assert!(matches!(
            rekey.stage_pem(next.chain.as_bytes(), another.key.as_bytes()),
            Err(PeerRekeyError::Identity(PeerIdentityError::KeyMismatch))
        ));
        rekey
            .stage_pem(next.chain.as_bytes(), next.key.as_bytes())
            .expect("staged");
        assert!(matches!(
            rekey.stage_pem(another.chain.as_bytes(), another.key.as_bytes()),
            Err(PeerRekeyError::InProgress("staged"))
        ));
        // A validated candidate that is not staged changes nothing either.
        let _ = StagedPeerIdentity::from_pem(
            another.chain.as_bytes(),
            another.key.as_bytes(),
            pki.ca_pem.as_bytes(),
        )
        .expect("valid candidate");
        assert_eq!(
            rekey.snapshot().staged_spki.as_deref(),
            Some(next.spki.as_str())
        );
    }

    /// Stage, approve, and wait out the hold so the next tick switches.
    async fn staged_and_approved(
        fixture: &RuntimeFixture,
        pki: &Pki,
        current: &Leaf,
        next: &Leaf,
    ) -> Arc<PeerRekey> {
        fixture
            .source
            .replace(vec![record(fixture, 1, &[&current.spki, &next.spki], &[])])
            .await;
        fixture.runtime.bootstrap().await.expect("overlap ready");
        let rekey = machine(fixture, pki, current);
        rekey
            .stage_pem(next.chain.as_bytes(), next.key.as_bytes())
            .expect("staged");
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Staged);
        tokio::time::sleep(HOLD * 2).await;
        rekey
    }

    #[tokio::test]
    async fn m7c153_a_trigger_during_a_switch_is_refused_rather_than_lost() {
        // Deterministic: a reconciliation pass is held open inside the
        // checkpoint fetch, so it owns the reconcile gate; the switch then
        // waits on that gate in the `switching` phase, and a second staging
        // attempt made there must be refused, not overwritten when the switch
        // lands.  (Real time, not paused: a paused clock would fire the
        // held fetch's own timeout at once.)
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let late = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        let rekey = staged_and_approved(&fixture, &pki, &current, &next).await;

        fixture.authority.hold.store(true, Ordering::Release);
        let runtime = Arc::clone(&fixture.runtime);
        let reconcile = tokio::spawn(async move { runtime.reconcile_once().await });
        fixture.authority.held.notified().await;

        let switching = {
            let rekey = Arc::clone(&rekey);
            tokio::spawn(async move { rekey.tick().await })
        };
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while rekey.phase() != PeerRekeyPhase::Switching {
            assert!(
                std::time::Instant::now() < deadline,
                "the switch never started"
            );
            tokio::task::yield_now().await;
        }
        let refused = rekey.stage_pem(late.chain.as_bytes(), late.key.as_bytes());
        assert!(
            matches!(refused, Err(PeerRekeyError::InProgress("switching"))),
            "a trigger during a switch must be refused, got {refused:?}"
        );
        assert_eq!(rekey.snapshot().last_refusal, Some("rotation_in_progress"));

        fixture.authority.release.notify_one();
        reconcile.await.expect("reconcile join").expect("reconcile");
        let switched = switching.await.expect("switch join");
        assert_eq!(switched.phase, PeerRekeyPhase::Overlap);
        assert_eq!(switched.serving_spki, next.spki);
        assert_eq!(switched.stages, 1, "the refused trigger staged nothing");
    }

    #[tokio::test(start_paused = true)]
    async fn m7c153_a_retired_key_cannot_be_restaged() {
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        let rekey = staged_and_approved(&fixture, &pki, &current, &next).await;
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Overlap);
        fixture
            .source
            .replace(vec![record(&fixture, 2, &[&next.spki], &[])])
            .await;
        fixture
            .runtime
            .reconcile_once()
            .await
            .expect("successor only");
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Stable);
        // Rolling back to the key this process just retired is refused.
        let rollback = rekey.stage_pem(current.chain.as_bytes(), current.key.as_bytes());
        assert!(
            matches!(rollback, Err(PeerRekeyError::Retired)),
            "{rollback:?}"
        );
        assert_eq!(rekey.snapshot().last_refusal, Some("staged_retired_key"));
        // A fresh key is still accepted.
        let fresh = pki.peer(NODE_ID);
        rekey
            .stage_pem(fresh.chain.as_bytes(), fresh.key.as_bytes())
            .expect("a fresh key stages");
    }

    #[tokio::test(start_paused = true)]
    async fn m8c45_an_overlap_that_elapses_while_the_predecessor_is_approved_is_counted() {
        let pki = Pki::new();
        let current = pki.peer(NODE_ID);
        let next = pki.peer(NODE_ID);
        let fixture = RuntimeFixture::new_with_local_spki(true, &current.spki);
        let rekey = staged_and_approved(&fixture, &pki, &current, &next).await;
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Overlap);
        // Just short of the overlap: nothing happens.
        tokio::time::advance(Duration::from_secs(599)).await;
        assert_eq!(rekey.tick().await.phase, PeerRekeyPhase::Overlap);
        // The overlap elapses with the record still approving both keys: the
        // relay retires the predecessor locally, and says so, because peers
        // keep trusting it until the publisher withdraws it.
        tokio::time::advance(Duration::from_secs(2)).await;
        let retired = rekey.tick().await;
        assert_eq!(retired.phase, PeerRekeyPhase::Stable);
        assert_eq!(
            retired.last_retirement,
            Some(PeerRekeyRetirement::OverlapElapsed)
        );
        assert_eq!(retired.overlap_elapsed_while_approved, 1);
        assert!(
            fixture
                .runtime
                .local_key_approval(&current.spki)
                .is_approved(),
            "the record still approves the predecessor: only the publisher can withdraw it"
        );
    }
}
