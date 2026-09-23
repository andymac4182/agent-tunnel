//! Durable membership-fence runtime regressions.
//!
//! These tests exercise the public runtime boundary with a synthetic signed
//! authority and catalog source.  They cover the ordering guarantees that
//! matter at restart and refresh: an accepted candidate is durable before it
//! becomes ready, ordinary checkpoint refreshes preserve active admissions,
//! and a failed write fails closed.

use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
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
    MembershipRuntimeConfig, MembershipRuntimeError, MembershipVersionStateIdentity,
    MembershipVersionStateStore,
};
// Only the Unix-only insecure-permissions case names it; unconditionally it is
// an unused import on Windows, where `clippy -D warnings` refuses the target.
#[cfg(unix)]
use tunnel_relay::MembershipVersionStateStoreError;

const DEPLOYMENT_ID: &str = "m7-persistence-deployment";
const DEPLOYMENT_INCARNATION: &str = "m7-persistence-incarnation";
const NODE_ID: &str = "relay-a";
const BOOT_ID: &str = "boot-a";
const PUBLISHER_KEY_ID: &str = "publisher-1";
const SPKI_SHA256: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

static TEST_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn new() -> Self {
        let counter = TEST_COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "agent-tunnel-membership-runtime-{}-{counter}",
            std::process::id()
        ));
        fs::create_dir(&path).expect("create test directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("private test directory");
        }
        Self {
            path: fs::canonicalize(path).expect("canonical test directory"),
        }
    }

    fn state_path(&self) -> PathBuf {
        self.path.join("membership-version-state.json")
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

struct TestCheckpointAuthority {
    issuer: Arc<MembershipIssuer>,
    next_checkpoint_version: AtomicU64,
    checkpoint_lifetime: Arc<RwLock<ChronoDuration>>,
}

impl TestCheckpointAuthority {
    fn new(issuer: Arc<MembershipIssuer>) -> Self {
        Self {
            issuer,
            next_checkpoint_version: AtomicU64::new(1),
            checkpoint_lifetime: Arc::new(RwLock::new(ChronoDuration::seconds(30))),
        }
    }

    async fn set_checkpoint_lifetime(&self, lifetime: ChronoDuration) {
        *self.checkpoint_lifetime.write().await = lifetime;
    }
}

impl CheckpointAuthority for TestCheckpointAuthority {
    fn fetch_checkpoint<'a>(
        &'a self,
        request: CheckpointRequest,
    ) -> MembershipFuture<'a, Result<CheckpointResponse, CheckpointAuthorityError>> {
        Box::pin(async move {
            let now = Utc::now();
            let checkpoint_lifetime = *self.checkpoint_lifetime.read().await;
            let checkpoint = MembershipCheckpoint {
                schema_version: MEMBERSHIP_SCHEMA_VERSION,
                deployment_id: request.deployment_id,
                deployment_incarnation: request.deployment_incarnation,
                checkpoint_version: self.next_checkpoint_version.fetch_add(1, Ordering::AcqRel),
                nonce: request.nonce,
                minimum_versions: BTreeMap::from([(NODE_ID.to_owned(), 1)]),
                issued_at: now - chrono::Duration::seconds(1),
                not_before: now - chrono::Duration::seconds(1),
                expires_at: now + checkpoint_lifetime,
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
    make_state_insecure_on_read: Arc<AtomicBool>,
    // Read only by the Unix-only permission fault below.
    #[cfg_attr(not(unix), allow(dead_code))]
    state_path: PathBuf,
}

impl TestMembershipSource {
    fn new(state_path: PathBuf) -> Self {
        Self {
            records: Arc::new(RwLock::new(Vec::new())),
            make_state_insecure_on_read: Arc::new(AtomicBool::new(false)),
            state_path,
        }
    }

    async fn replace(&self, records: Vec<CatalogMembershipRecord>) {
        *self.records.write().await = records;
    }

    #[cfg_attr(not(unix), allow(dead_code))]
    fn fail_next_persistence(&self) {
        self.make_state_insecure_on_read
            .store(true, Ordering::Release);
    }
}

impl MembershipRecordSource for TestMembershipSource {
    fn read_signed_memberships<'a>(
        &'a self,
    ) -> MembershipFuture<'a, Result<Vec<CatalogMembershipRecord>, MembershipSourceError>> {
        Box::pin(async move {
            let records = self.records.read().await.clone();
            if self
                .make_state_insecure_on_read
                .swap(false, Ordering::AcqRel)
            {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    let permissions = fs::Permissions::from_mode(0o644);
                    fs::set_permissions(&self.state_path, permissions)
                        .expect("make state file insecure");
                }
            }
            Ok(records)
        })
    }
}

fn issuer_and_trusted_key() -> (Arc<MembershipIssuer>, TrustedPublisherKey) {
    let (issuer, _pkcs8) =
        MembershipIssuer::generate(PUBLISHER_KEY_ID).expect("synthetic publisher issuer");
    let issuer = Arc::new(issuer);
    let trusted = TrustedPublisherKey::new(
        PUBLISHER_KEY_ID,
        issuer.public_key().expect("publisher public key"),
    )
    .expect("trusted publisher key");
    (issuer, trusted)
}

fn runtime_config(boot_id: &str) -> MembershipRuntimeConfig {
    MembershipRuntimeConfig::new(
        DEPLOYMENT_ID,
        DEPLOYMENT_INCARNATION,
        NODE_ID,
        boot_id,
        PrivateEndpointPolicy::private_ip_only(),
        Duration::from_secs(60),
        Duration::from_secs(20),
        Duration::from_secs(1),
        Duration::from_secs(1),
        Duration::from_secs(1),
    )
    .expect("bounded runtime configuration")
    .with_local_spki_sha256(SPKI_SHA256)
    .expect("synthetic local SPKI pin")
}

fn record(issuer: &MembershipIssuer, record_version: u64) -> CatalogMembershipRecord {
    let now = Utc::now();
    let record = MembershipRecord {
        schema_version: MEMBERSHIP_SCHEMA_VERSION,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        deployment_incarnation: DEPLOYMENT_INCARNATION.to_owned(),
        node_id: NODE_ID.to_owned(),
        record_version,
        roles: vec![RELAY_PEER_ROLE.to_owned()],
        peer_endpoint: "10.0.0.1:8443".to_owned(),
        server_name: "10.0.0.1".to_owned(),
        keys: vec![RelayKey {
            key_id: "relay-key-1".to_owned(),
            spki_sha256: SPKI_SHA256.to_owned(),
            not_before: now - chrono::Duration::seconds(1),
            expires_at: now + chrono::Duration::seconds(30),
            revoked: false,
        }],
        issued_at: now - chrono::Duration::seconds(1),
        not_before: now - chrono::Duration::seconds(1),
        expires_at: now + chrono::Duration::seconds(30),
    };
    CatalogMembershipRecord {
        version: record_version,
        bytes: issuer
            .sign_membership_bytes(record)
            .expect("synthetic signed membership"),
    }
}

fn open_store(directory: &TestDirectory) -> Arc<MembershipVersionStateStore> {
    let identity =
        MembershipVersionStateIdentity::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, NODE_ID)
            .expect("state identity");
    Arc::new(
        MembershipVersionStateStore::bootstrap(directory.state_path(), identity)
            .expect("bootstrap state store"),
    )
}

fn build_runtime(
    source: &TestMembershipSource,
    authority: &Arc<TestCheckpointAuthority>,
    issuer: &Arc<MembershipIssuer>,
    store: Arc<MembershipVersionStateStore>,
    boot_id: &str,
) -> Arc<MembershipRuntime> {
    let trusted = TrustedPublisherKey::new(
        PUBLISHER_KEY_ID,
        issuer.public_key().expect("publisher public key"),
    )
    .expect("trusted publisher key");
    MembershipRuntime::with_source_and_store(
        Arc::new(source.clone()),
        authority.clone(),
        runtime_config(boot_id),
        [trusted],
        store,
    )
    .expect("membership runtime")
}

#[tokio::test]
async fn durable_refresh_preserves_existing_peer_admission() {
    let directory = TestDirectory::new();
    let store = open_store(&directory);
    let (issuer, _trusted) = issuer_and_trusted_key();
    let authority = Arc::new(TestCheckpointAuthority::new(Arc::clone(&issuer)));
    let source = TestMembershipSource::new(directory.state_path());
    let signed_record = record(&issuer, 1);
    source.replace(vec![signed_record.clone()]).await;
    let runtime = build_runtime(&source, &authority, &issuer, Arc::clone(&store), BOOT_ID);

    runtime.bootstrap().await.expect("initial bootstrap");
    let admission = runtime
        .admit_peer(MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256))
        .expect("ready runtime admits peer");

    // The signed record is unchanged. Only the nonce-bound checkpoint
    // advances, so persistence must not revoke the healthy admission.
    source.replace(vec![signed_record]).await;
    let snapshot = runtime
        .reconcile_once()
        .await
        .expect("checkpoint refresh persists");

    assert_eq!(snapshot.readiness, MembershipReadiness::Ready);
    assert_eq!(snapshot.active_peer_count, 1);
    assert!(!admission.is_invalidated());
    assert_eq!(
        store.load().expect("durable state").checkpoint_version,
        Some(2)
    );
}

#[tokio::test]
async fn pooled_admissions_reuse_deadline_and_reject_real_checkpoint_shrink() {
    let directory = TestDirectory::new();
    let store = open_store(&directory);
    let (issuer, _trusted) = issuer_and_trusted_key();
    let authority = Arc::new(TestCheckpointAuthority::new(Arc::clone(&issuer)));
    let source = TestMembershipSource::new(directory.state_path());
    let signed_record = record(&issuer, 1);
    source.replace(vec![signed_record.clone()]).await;
    let runtime = build_runtime(&source, &authority, &issuer, Arc::clone(&store), BOOT_ID);

    runtime.bootstrap().await.expect("initial bootstrap");
    let identity = MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256);
    let first_stream = runtime
        .admit_peer(identity.clone())
        .expect("first pooled stream admission");
    let first_deadline = first_stream.deadline();
    let second_stream = runtime
        .admit_peer(identity.clone())
        .expect("second pooled stream admission");
    let second_deadline = second_stream.deadline();

    // A pooled peer has one process-local cancellation edge. Equal admission
    // timestamps and deadlines prove the second checkout reused the first
    // edge rather than replacing and cancelling an existing stream.
    assert_eq!(
        first_deadline.started_at(),
        second_deadline.started_at(),
        "pooled streams must reuse the original monotonic start"
    );
    assert_eq!(
        first_deadline.expires_at(),
        second_deadline.expires_at(),
        "pooled streams must retain the original monotonic deadline"
    );
    assert_eq!(
        first_deadline.trust_expires_at(),
        second_deadline.trust_expires_at(),
        "pooled streams must share the signed trust boundary"
    );
    assert!(!first_stream.is_invalidated());
    assert!(!second_stream.is_invalidated());
    assert_eq!(runtime.snapshot().active_peer_count, 1);

    source.replace(vec![signed_record.clone()]).await;
    let unchanged = runtime
        .reconcile_once()
        .await
        .expect("unchanged signed checkpoint refresh");
    assert_eq!(unchanged.active_peer_count, 1);
    assert!(!first_stream.is_invalidated());
    assert!(!second_stream.is_invalidated());

    // The next checkpoint is still valid but has a genuinely shorter signed
    // expiry. This must invalidate the old admission even though converting
    // the same boundary to a fresh Instant would otherwise be ambiguous.
    authority
        .set_checkpoint_lifetime(ChronoDuration::seconds(5))
        .await;
    source.replace(vec![signed_record]).await;
    let shortened = runtime
        .reconcile_once()
        .await
        .expect("shortened checkpoint remains currently valid");
    assert_eq!(shortened.active_peer_count, 0);
    assert!(first_stream.is_invalidated());
    assert!(second_stream.is_invalidated());
}

#[cfg(unix)]
#[tokio::test]
async fn failed_candidate_persistence_keeps_runtime_unready_and_withdraws_peer() {
    use std::os::unix::fs::PermissionsExt;

    let directory = TestDirectory::new();
    let store = open_store(&directory);
    let (issuer, _trusted) = issuer_and_trusted_key();
    let authority = Arc::new(TestCheckpointAuthority::new(Arc::clone(&issuer)));
    let source = TestMembershipSource::new(directory.state_path());
    let signed_record = record(&issuer, 1);
    source.replace(vec![signed_record.clone()]).await;
    let runtime = build_runtime(&source, &authority, &issuer, Arc::clone(&store), BOOT_ID);

    runtime.bootstrap().await.expect("initial bootstrap");
    let admission = runtime
        .admit_peer(MembershipPeerIdentity::new(NODE_ID, BOOT_ID, SPKI_SHA256))
        .expect("ready runtime admits peer");

    // Advance the signed record so the final candidate has a new node fence.
    // The source changes the state-file mode after checkpoint persistence and
    // before that final candidate save. This models a durable write failure
    // after valid record verification.
    source.replace(vec![record(&issuer, 2)]).await;
    source.fail_next_persistence();
    let error = runtime
        .reconcile_once()
        .await
        .expect_err("failed save must fail closed");
    assert!(matches!(
        error,
        MembershipRuntimeError::Persistence(MembershipVersionStateStoreError::InsecurePermissions)
    ));
    assert_eq!(
        runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::PersistenceUnavailable)
    );
    assert!(admission.is_invalidated());

    // Restore test permissions so the old durable fence can be inspected.
    fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600))
        .expect("restore state permissions");
    let durable = store.load().expect("old durable state");
    assert_eq!(durable.checkpoint_version, Some(2));
    assert_eq!(durable.node_versions.get(NODE_ID), Some(&1));
}

#[tokio::test]
async fn partially_verified_records_are_fenced_before_later_record_failure() {
    let directory = TestDirectory::new();
    let store = open_store(&directory);
    let (issuer, _trusted) = issuer_and_trusted_key();
    let authority = Arc::new(TestCheckpointAuthority::new(Arc::clone(&issuer)));
    let source = TestMembershipSource::new(directory.state_path());
    source
        .replace(vec![
            record(&issuer, 2),
            CatalogMembershipRecord {
                version: 3,
                bytes: b"{".to_vec(),
            },
        ])
        .await;
    let runtime = build_runtime(&source, &authority, &issuer, Arc::clone(&store), BOOT_ID);

    let error = runtime
        .bootstrap()
        .await
        .expect_err("later malformed record must keep runtime unready");
    assert!(matches!(
        error,
        MembershipRuntimeError::Source(MembershipSourceError::InvalidRecordEnvelope)
    ));
    assert_eq!(
        runtime.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
    let state = store.load().expect("partial high water state");
    assert_eq!(state.checkpoint_version, Some(1));
    assert_eq!(state.node_versions.get(NODE_ID), Some(&2));
}

#[tokio::test]
async fn restart_restores_fences_and_rejects_a_lower_membership_version() {
    let directory = TestDirectory::new();
    let store = open_store(&directory);
    let (issuer, _trusted) = issuer_and_trusted_key();
    let authority = Arc::new(TestCheckpointAuthority::new(Arc::clone(&issuer)));
    let source = TestMembershipSource::new(directory.state_path());
    source.replace(vec![record(&issuer, 2)]).await;
    let runtime = build_runtime(&source, &authority, &issuer, Arc::clone(&store), BOOT_ID);
    runtime.bootstrap().await.expect("initial bootstrap");
    assert_eq!(
        store.load().expect("persisted state").node_versions[NODE_ID],
        2
    );

    drop(runtime);
    drop(store);

    let identity =
        MembershipVersionStateIdentity::new(DEPLOYMENT_ID, DEPLOYMENT_INCARNATION, NODE_ID)
            .expect("state identity");
    let restarted_store = Arc::new(
        MembershipVersionStateStore::open(directory.state_path(), identity)
            .expect("reopen durable state"),
    );
    source.replace(vec![record(&issuer, 1)]).await;
    let restarted = build_runtime(
        &source,
        &authority,
        &issuer,
        Arc::clone(&restarted_store),
        "boot-b",
    );
    let error = restarted
        .bootstrap()
        .await
        .expect_err("restart must reject a lower record version");
    assert!(matches!(
        error,
        MembershipRuntimeError::Membership(MembershipError::VersionRollback {
            highest: 2,
            received: 1,
            ..
        })
    ));
    assert_eq!(
        restarted.readiness(),
        MembershipReadiness::Unready(MembershipUnreadyReason::MembershipRejected)
    );
}
