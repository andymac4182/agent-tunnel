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
