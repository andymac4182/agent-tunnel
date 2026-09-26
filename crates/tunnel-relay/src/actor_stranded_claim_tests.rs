//! Task row M6-C170: a `Command::RegisterResolved` stranded behind a relay
//! actor that has ended must not keep its committed owner claim fenced until
//! the lease expires.
//!
//! The M6-C162 fixture strands a command the same way: a `send` that reserved
//! its slot before the actor's receiver was dropped and stored its value
//! after the drain leaves the command in a channel nobody reads, alive for as
//! long as a sender is.  Here the command is parked in a channel the test
//! keeps open for the whole test, so it is never dropped; the guard it names
//! was armed with the claim's exact token on a cleanup worker that has
//! already ended, as the actor's own worker has once the actor is gone.  The
//! only thing that can release the claim is the actor's end.

use std::{sync::Arc, time::Duration};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::sync::{mpsc, oneshot};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, FixtureDevice, MembershipRecord, MembershipRole,
    MemoryCatalog, OidcConfig, OidcVerifier, OwnerClaimRequest, SharedCatalog, TenantRecord,
    UserRecord,
};
use uuid::Uuid;

use super::{
    CleanupWorker, Command, OwnerClaimCleanup, RegisterControlFailure, RelayHandle, RelayOptions,
};

const TENANT: Uuid = Uuid::from_u128(0x0170_0001);
const DEVICE: Uuid = Uuid::from_u128(0x0170_0002);
const USER: Uuid = Uuid::from_u128(0x0170_0003);

async fn seeded_catalog() -> MemoryCatalog {
    let catalog = MemoryCatalog::new();
    catalog
        .seed_fixture(&CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id: TENANT,
                display_name: "stranded-claim-tenant".into(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id: USER,
                display_name: "stranded-claim-user".into(),
            }],
            identities: vec![],
            memberships: vec![MembershipRecord {
                tenant_id: TENANT,
                user_id: USER,
                role: MembershipRole::Member,
                active: true,
            }],
            devices: vec![FixtureDevice {
                tenant_id: TENANT,
                device_id: DEVICE,
                owner_user_id: USER,
                display_name: "stranded-claim-device".into(),
                active: true,
                last_seen_at: None,
            }],
            credentials: vec![],
            services: vec![],
            grants: vec![],
        })
        .await
        .expect("catalog fixture");
    catalog
}

/// A lease far longer than any test, so a released claim cannot be mistaken
/// for an expired one.
fn claim_request(session_id: &str) -> OwnerClaimRequest {
    OwnerClaimRequest {
        deployment_incarnation: "stranded-claim".into(),
        tenant_id: TENANT,
        device_id: DEVICE,
        node_id: "stranded-node".into(),
        boot_id: "stranded-boot".into(),
        session_id: session_id.into(),
        lease_expires_at: Utc::now() + ChronoDuration::hours(1),
    }
}

fn relay(catalog: &MemoryCatalog) -> RelayHandle {
    let jwk = ApprovedJwk::from_ed25519_der("stranded-claim", &[0_u8; 32]).expect("test OIDC key");
    let config = OidcConfig::new("https://issuer.example", ["audience".to_owned()], vec![jwk])
        .expect("test OIDC config");
    let mut options = RelayOptions::new(Arc::new(OidcVerifier::new(config).expect("verifier")));
    options.shutdown = CancellationToken::new();
    RelayHandle::spawn(options, Arc::new(catalog.clone()) as SharedCatalog)
}

/// Park a `RegisterResolved` whose guard holds `token`'s claim in a channel
/// the caller keeps open, through the relay's own handoff registry, exactly
/// as a registration task does.  Returns both halves of the parked channel:
/// keep them alive, so nothing ever drops the command.
async fn strand_register_resolved(
    handle: &RelayHandle,
    catalog: &MemoryCatalog,
    token: tunnel_catalog::OwnerToken,
) -> (mpsc::Sender<Command>, mpsc::Receiver<Command>) {
    // The cleanup worker has already ended, as the actor's own worker has
    // once the actor is gone: a guard dropped now can only fail closed.
    let worker = CleanupWorker::spawn(Arc::new(catalog.clone()) as SharedCatalog);
    let dispatcher = worker.dispatcher();
    worker.shutdown().await;
    let mut guard = OwnerClaimCleanup::new(dispatcher);
    guard.arm_token(token);

    let (parked_tx, parked) = mpsc::channel(1);
    let (response, _reply) = oneshot::channel();
    parked_tx
        .send(Command::RegisterResolved {
            device_id: DEVICE,
            tenant_id: Some(TENANT),
            spki: "stranded-claim-spki".into(),
            hello: tunnel_protocol::Hello::new(
                "stranded-claim",
                DEVICE.to_string(),
                u16::from(crate::PROTOCOL_MAJOR),
                0,
            ),
            data_connection_id: "stranded-claim-data".into(),
            response,
            owner_cleanup: handle.claim_handoffs.deposit(Some(guard)),
            result: Box::new(Err(RegisterControlFailure::OwnerBusy)),
        })
        .await
        .expect("park the command");
    assert_eq!(handle.claim_handoffs.parked(), 1);
    (parked_tx, parked)
}

async fn current_session(catalog: &MemoryCatalog) -> Option<String> {
    catalog
        .current_owner(TENANT, DEVICE, Utc::now())
        .await
        .expect("current owner")
        .map(|claim| claim.token.session_id)
}

#[tokio::test]
async fn a_stranded_register_resolved_releases_its_owner_claim_when_the_actor_ends() {
    let catalog = seeded_catalog().await;
    let claim = catalog
        .claim_owner(&claim_request("stranded-owner"))
        .await
        .expect("claim owner");
    let handle = relay(&catalog);
    let (_parked_tx, parked) = strand_register_resolved(&handle, &catalog, claim.token).await;
    assert_eq!(
        current_session(&catalog).await.as_deref(),
        Some("stranded-owner")
    );

    // Ending the actor is the only thing that happens.  `shutdown()` joins the
    // actor's supervisor, so no polling: the release has run by the time it
    // returns, or it never will.
    let _ = handle.shutdown().await;

    assert_eq!(
        parked.len(),
        1,
        "the command must still be stranded unread; the release cannot depend on dropping it"
    );
    assert_eq!(
        current_session(&catalog).await,
        None,
        "an owner claim stranded behind an ended actor must be released when the actor ends, \
         not left fenced until its lease expires"
    );
    assert_eq!(handle.claim_handoffs.parked(), 0);
}

#[tokio::test]
async fn a_stranded_register_resolved_is_released_when_the_actor_is_aborted() {
    let catalog = seeded_catalog().await;
    let claim = catalog
        .claim_owner(&claim_request("aborted-owner"))
        .await
        .expect("claim owner");
    let handle = relay(&catalog);
    let (_parked_tx, parked) = strand_register_resolved(&handle, &catalog, claim.token).await;

    // An abort drops the supervisor before it can await anything; the release
    // is handed to the runtime from its drop.
    handle.abort_actor_task().await;

    let mut released = false;
    for _ in 0..200 {
        if current_session(&catalog).await.is_none() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(parked.len(), 1, "the command must still be stranded unread");
    assert!(
        released,
        "an owner claim stranded behind an aborted actor must be released, not left to its lease"
    );
}

#[tokio::test]
async fn a_stranded_claim_never_releases_an_owner_that_has_since_changed() {
    let catalog = seeded_catalog().await;
    let stale = catalog
        .claim_owner(&claim_request("stale-owner"))
        .await
        .expect("claim owner");
    // The stale claim is released and another owner takes the device.
    assert!(catalog.release_owner(&stale.token).await.expect("release"));
    catalog
        .claim_owner(&claim_request("successor-owner"))
        .await
        .expect("successor claim");
    let handle = relay(&catalog);
    let (_parked_tx, _parked) = strand_register_resolved(&handle, &catalog, stale.token).await;

    let _ = handle.shutdown().await;

    assert_eq!(
        handle.claim_handoffs.parked(),
        0,
        "the stranded guard was consumed"
    );
    assert_eq!(
        current_session(&catalog).await.as_deref(),
        Some("successor-owner"),
        "a stranded claim's release is fenced on its exact token and must never delete a successor"
    );
}

/// Queue a `RegisterResolved` for the relay's own handoff registry, then drop
/// the queue and the cleanup worker in the order a panicking or aborted
/// `RelayActor` drops its fields: `rx` first (the drain drops the queued
/// command), then `cleanup` (its join handle aborts the worker).  Found by the
/// review of PR #208: the first version of this fix dropped the guard with
/// the command, onto a worker about to be aborted, and the claim was lost.
async fn drop_queued_register_resolved_in_actor_field_order(
    handle: &RelayHandle,
    catalog: &MemoryCatalog,
    token: tunnel_catalog::OwnerToken,
) {
    let worker = CleanupWorker::spawn(Arc::new(catalog.clone()) as SharedCatalog);
    let mut guard = OwnerClaimCleanup::new(worker.dispatcher());
    guard.arm_token(token);
    let (queue_tx, queue_rx) = mpsc::channel(1);
    let (response, _reply) = oneshot::channel();
    queue_tx
        .send(Command::RegisterResolved {
            device_id: DEVICE,
            tenant_id: Some(TENANT),
            spki: "queued-claim-spki".into(),
            hello: tunnel_protocol::Hello::new(
                "queued-claim",
                DEVICE.to_string(),
                u16::from(crate::PROTOCOL_MAJOR),
                0,
            ),
            data_connection_id: "queued-claim-data".into(),
            response,
            owner_cleanup: handle.claim_handoffs.deposit(Some(guard)),
            result: Box::new(Err(RegisterControlFailure::OwnerBusy)),
        })
        .await
        .expect("queue the command");
    drop(queue_rx);
    drop(worker);
    // Let the aborted worker actually end before anything else runs.
    tokio::task::yield_now().await;
}

#[tokio::test]
async fn a_register_resolved_queued_when_the_actor_is_aborted_releases_its_claim() {
    let catalog = seeded_catalog().await;
    let claim = catalog
        .claim_owner(&claim_request("queued-owner"))
        .await
        .expect("claim owner");
    let handle = relay(&catalog);
    drop_queued_register_resolved_in_actor_field_order(&handle, &catalog, claim.token).await;
    assert_eq!(
        handle.claim_handoffs.parked(),
        1,
        "a dropped command leaves its guard parked rather than dropping it onto a dying worker"
    );

    // An abort, as for a panic: the actor's `close_all` never runs, so only the
    // supervisor's release can reach the parked guard.
    handle.abort_actor_task().await;
    let mut released = false;
    for _ in 0..200 {
        if current_session(&catalog).await.is_none() {
            released = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        released,
        "a claim whose command was queued when the actor ended must be released, not left fenced"
    );
}

#[tokio::test]
async fn a_register_resolved_queued_at_shutdown_releases_its_claim() {
    let catalog = seeded_catalog().await;
    let claim = catalog
        .claim_owner(&claim_request("queued-owner"))
        .await
        .expect("claim owner");
    let handle = relay(&catalog);
    drop_queued_register_resolved_in_actor_field_order(&handle, &catalog, claim.token).await;
    let _ = handle.shutdown().await;
    assert_eq!(
        current_session(&catalog).await,
        None,
        "queued claim left fenced"
    );
}

/// **The supervisor's release has one overall deadline.**  Against an
/// authority that never answers, N parked claims used to cost N times the
/// per-operation timeout.  The release here never completes; the call must
/// still return at the deadline, count every claim it did not release, and
/// leave nothing parked.
#[tokio::test]
async fn the_stranded_release_ends_at_its_deadline_and_counts_what_it_left() {
    let catalog = seeded_catalog().await;
    let handoffs = super::ClaimHandoffs::default();
    let worker = CleanupWorker::spawn(Arc::new(catalog.clone()) as SharedCatalog);
    let dispatcher = worker.dispatcher();
    let mut parked = Vec::new();
    for index in 0..3 {
        let mut guard = OwnerClaimCleanup::new(dispatcher.clone());
        guard.arm_request(claim_request(&format!("deadline-{index}")));
        parked.push(handoffs.deposit(Some(guard)));
    }
    assert_eq!(handoffs.parked(), 3);
    let started = tokio::time::Instant::now();
    let outcome = tokio::time::timeout(
        Duration::from_secs(2),
        super::release_parked_until(&handoffs, started + Duration::from_millis(100), |_item| {
            std::future::pending::<()>()
        }),
    )
    .await
    .expect("the stranded release must end at its own deadline, not wait on the authority");
    assert_eq!(
        outcome,
        (0, 3),
        "nothing was released and all three claims are counted as left to lease expiry"
    );
    assert!(started.elapsed() >= Duration::from_millis(100));
    assert_eq!(handoffs.parked(), 0);
    drop(parked);
    worker.shutdown().await;
}
