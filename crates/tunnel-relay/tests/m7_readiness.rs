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
    MembershipFuture, MembershipSourceError, MembershipUnreadyReason,
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
}

impl TestCheckpointAuthority {
    fn new(issuer: Arc<MembershipIssuer>, include_local_membership: bool) -> Self {
        Self {
            issuer,
            next_checkpoint_version: AtomicU64::new(1),
            mode: AtomicU8::new(AuthorityMode::Ready as u8),
            include_local_membership: AtomicBool::new(include_local_membership),
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
