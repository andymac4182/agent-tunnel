//! Task row M6-C162: a relay handle request stranded behind an actor that
//! has ended must return the typed shutdown outcome promptly.
//!
//! Dropping a tokio mpsc receiver drains its queue, but a `send` that
//! reserved its slot before the drop and stores its value after the drain
//! leaves the command, with its reply sender, in the channel for as long as
//! any handle holds a sender. The fixture reproduces that end state
//! deterministically: the owner parks its receiver unread with the command
//! in it and then ends, recording its completion exactly as the actor task
//! does after `run()` returns or panics.

use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::{sync::mpsc, task::JoinHandle, time::timeout};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{ApprovedJwk, DeviceIdentity, MemoryCatalog, OidcConfig, OidcVerifier};
use uuid::Uuid;

use super::{
    ActorCompletion, Command, EchoOutcome, RelayError, RelayHandle, RelayOptions, SessionKey,
};

const BOUND: Duration = Duration::from_secs(2);

fn spawned_handle() -> RelayHandle {
    let jwk = ApprovedJwk::from_ed25519_der("stranded", &[0_u8; 32]).expect("test OIDC key");
    let config = OidcConfig::new("https://issuer.example", ["audience".to_owned()], vec![jwk])
        .expect("test OIDC config");
    let mut options = RelayOptions::new(Arc::new(OidcVerifier::new(config).expect("verifier")));
    options.shutdown = CancellationToken::new();
    RelayHandle::spawn(options, Arc::new(MemoryCatalog::new()))
}

/// A handle whose actor ends with the next command stranded in its queue.
/// The returned task owns the parked receiver; keep it until the test ends
/// so the stranded command, and its reply sender, stay alive.
async fn stranded_handle() -> (RelayHandle, JoinHandle<mpsc::Receiver<Command>>) {
    let real = spawned_handle();
    real.shutdown()
        .await
        .expect("the real actor shuts down cleanly");
    let (tx, mut parked) = mpsc::channel(8);
    let mut handle = real.clone();
    handle.tx = tx;
    handle.actor_completion = ActorCompletion::default();
    handle.maintenance_completion = ActorCompletion::default();
    handle.maintenance_completion.mark_done(false);
    handle.background_failure = Arc::new(AtomicBool::new(false));
    handle.actor_task = Arc::new(Mutex::new(None));
    handle.maintenance_task = Arc::new(Mutex::new(None));
    let completion = handle.actor_completion.clone();
    let owner = tokio::spawn(async move {
        // Wait until the caller's send has stored its command, then end
        // without reading it: the command is stranded behind a finished
        // owner, which is what a panic or abort leaves behind.
        while parked.is_empty() {
            tokio::task::yield_now().await;
        }
        parked.close();
        completion.mark_done(false);
        parked
    });
    (handle, owner)
}

fn key() -> SessionKey {
    SessionKey {
        tenant_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        session_id: "stranded-session".to_owned(),
        epoch: 1,
    }
}

async fn assert_parked(owner: JoinHandle<mpsc::Receiver<Command>>) {
    let parked = owner.await.expect("owner task");
    assert_eq!(
        parked.len(),
        1,
        "the command must have been stranded unread in the ended owner's queue"
    );
}

#[tokio::test]
async fn a_stranded_snapshot_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(BOUND, handle.snapshot())
        .await
        .expect("a snapshot stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_forwarded_attach_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let now = Utc::now();
    let device = DeviceIdentity {
        tenant_id: Uuid::from_u128(1),
        device_id: Uuid::from_u128(2),
        owner_user_id: Uuid::from_u128(3),
        credential_id: Uuid::from_u128(4),
        spki_fingerprint: "stranded-spki".to_owned(),
        credential_not_before: now - ChronoDuration::minutes(1),
        expires_at: now + ChronoDuration::minutes(1),
        credential_revoked_at: None,
        device_active: true,
        credential_active: true,
        device_version: 1,
        owner_epoch: 1,
        last_seen_at: Some(now),
    };
    let outcome = timeout(
        BOUND,
        handle.attach_forwarded_data(device, "stranded-spki".to_owned(), "ticket".to_owned()),
    )
    .await
    .expect("an attach stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_echo_write_returns_an_interrupted_outcome() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.write_echo_stream(key(), 1, "op".to_owned(), b"x".to_vec()),
    )
    .await
    .expect("a write stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(
        outcome,
        Err(EchoOutcome::Failure {
            code: "REVERSE_CHANNEL_INTERRUPTED",
            execution: "unknown",
        })
    ));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_http_finish_returns_false() {
    let (handle, owner) = stranded_handle().await;
    let queued = timeout(BOUND, handle.finish_http_stream(key(), 1, "op".to_owned()))
        .await
        .expect("a FIN stranded behind an ended actor waited for a reply it could never get");
    assert!(!queued);
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_http_reset_returns_false() {
    let (handle, owner) = stranded_handle().await;
    let queued = timeout(
        BOUND,
        handle.reset_http_stream(key(), 1, "op".to_owned(), 1),
    )
    .await
    .expect("a RESET stranded behind an ended actor waited for a reply it could never get");
    assert!(!queued);
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_stream_close_returns_false() {
    let (handle, owner) = stranded_handle().await;
    let closed = timeout(
        BOUND,
        handle.close_echo_stream_with_cause(key(), 1, "op".to_owned(), None),
    )
    .await
    .expect("a close stranded behind an ended actor waited for a reply it could never get");
    assert!(!closed);
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_http_read_reads_nothing() {
    let (handle, owner) = stranded_handle().await;
    let mut receiver = handle
        .begin_read_http_stream(key(), 1, "op".to_owned())
        .await
        .expect("the read is queued before the owner ends");
    let read = timeout(BOUND, handle.http_read_reply(&mut receiver))
        .await
        .expect("a read stranded behind an ended actor waited for a reply it could never get");
    assert!(read.is_none());
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_shutdown_stranded_after_its_completion_check_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    // The owner is still running when shutdown() checks completion, so the
    // Shutdown command is sent and then stranded.
    assert!(!handle.actor_completion.done.load(Ordering::Acquire));
    let outcome = timeout(BOUND, handle.shutdown())
        .await
        .expect("a shutdown stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}
