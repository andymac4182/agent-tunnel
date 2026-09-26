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
use tunnel_catalog::{
    ApprovedJwk, AuthenticatedConsumer, DeviceIdentity, GrantSnapshot, MemoryCatalog, OidcConfig,
    OidcVerifier, PermissionSet,
};
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

const TENANT: Uuid = Uuid::from_u128(1);
const DEVICE: Uuid = Uuid::from_u128(2);
const PRINCIPAL: Uuid = Uuid::from_u128(3);
const SERVICE: Uuid = Uuid::from_u128(5);

fn device_identity() -> DeviceIdentity {
    let now = Utc::now();
    DeviceIdentity {
        tenant_id: TENANT,
        device_id: DEVICE,
        owner_user_id: PRINCIPAL,
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
    }
}

/// A device TLS identity parsed by the transport crate's own leaf parser
/// from a synthetic self-signed certificate carrying the device role URI.
fn tls_identity() -> tunnel_transport::TlsIdentity {
    let key = rcgen::KeyPair::generate().expect("synthetic key");
    let mut params = rcgen::CertificateParams::new(vec!["localhost".to_owned()]).expect("params");
    params.subject_alt_names.push(rcgen::SanType::URI(
        format!("urn:agent-tunnel:device:{DEVICE}")
            .try_into()
            .expect("URI"),
    ));
    let certificate = params.self_signed(&key).expect("synthetic certificate");
    tunnel_transport::leaf_identity_from_der(certificate.der()).expect("device identity")
}

fn hello() -> tunnel_protocol::Hello {
    tunnel_protocol::Hello::new(
        "stranded-registration",
        DEVICE.to_string(),
        u16::from(crate::PROTOCOL_MAJOR),
        0,
    )
}

fn consumer() -> AuthenticatedConsumer {
    AuthenticatedConsumer {
        tenant_id: TENANT,
        principal_id: PRINCIPAL,
    }
}

fn grant() -> GrantSnapshot {
    let now = Utc::now();
    GrantSnapshot {
        tenant_id: TENANT,
        principal_id: PRINCIPAL,
        device_id: DEVICE,
        service_id: SERVICE,
        revision: 1,
        permissions: PermissionSet {
            operations: std::collections::BTreeSet::from(["echo:invoke".to_owned()]),
        },
        constraints: serde_json::json!({}),
        valid_until: now + ChronoDuration::minutes(1),
        read_started_at: now,
    }
}

fn expires() -> chrono::DateTime<Utc> {
    Utc::now() + ChronoDuration::minutes(1)
}

#[tokio::test]
async fn a_stranded_control_registration_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.register_control(
            tls_identity(),
            tunnel_protocol::ControlMessage::Hello(hello()),
        ),
    )
    .await
    .expect("a registration stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_forwarded_control_registration_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.register_forwarded_control(device_identity(), "stranded-spki".to_owned(), hello()),
    )
    .await
    .expect("a registration stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_data_attach_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.attach_data(tls_identity(), "ticket".to_owned()),
    )
    .await
    .expect("an attach stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_forwarded_echo_open_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.open_forwarded_echo_stream(
            consumer(),
            DEVICE,
            SERVICE,
            grant(),
            expires(),
            "request".to_owned(),
        ),
    )
    .await
    .expect("an OPEN stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_http_open_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.open_http_stream(consumer(), DEVICE, SERVICE, grant(), expires(), None),
    )
    .await
    .expect("an OPEN stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_fs_open_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.open_fs_stream(
            consumer(),
            DEVICE,
            SERVICE,
            grant(),
            expires(),
            None,
            "read".to_owned(),
        ),
    )
    .await
    .expect("an OPEN stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

#[tokio::test]
async fn a_stranded_echo_dispatch_returns_shutdown() {
    let (handle, owner) = stranded_handle().await;
    let outcome = timeout(
        BOUND,
        handle.dispatch_echo(
            consumer(),
            DEVICE,
            SERVICE,
            grant(),
            b"x".to_vec(),
            expires(),
        ),
    )
    .await
    .expect("a dispatch stranded behind an ended actor waited for a reply it could never get");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
    assert_parked(owner).await;
}

/// The completion arm must still return a reply the actor sent before it
/// ended: the reply is sent, then completion is recorded, then waited on.
#[tokio::test]
async fn a_reply_sent_before_the_actor_ended_is_still_returned() {
    let completion = ActorCompletion::default();
    let (response, mut receiver) = tokio::sync::oneshot::channel();
    response.send(42_u32).expect("receiver alive");
    completion.mark_done(false);
    let reply = timeout(BOUND, completion.reply(&mut receiver))
        .await
        .expect("the reply wait returns once the actor has ended");
    assert_eq!(reply, Some(42));
}

/// Aborting the actor or maintenance task by any route -- here the join
/// handle directly, not `abort_actor_task` -- must still record completion,
/// or every later reply wait on the handle would be unbounded again.
#[tokio::test]
async fn aborting_the_actor_and_maintenance_tasks_records_their_completion() {
    let handle = spawned_handle();
    let actor = handle
        .actor_task
        .lock()
        .expect("actor slot")
        .take()
        .expect("actor task");
    let maintenance = handle
        .maintenance_task
        .lock()
        .expect("maintenance slot")
        .take()
        .expect("maintenance task");
    actor.abort();
    maintenance.abort();
    let _ = actor.await;
    let _ = maintenance.await;
    assert!(
        handle.actor_completion.done.load(Ordering::Acquire),
        "an aborted actor task left its completion unset"
    );
    assert!(handle.actor_completion.failed());
    assert!(
        handle.maintenance_completion.done.load(Ordering::Acquire),
        "an aborted maintenance task left its completion unset"
    );
    let outcome = timeout(BOUND, handle.snapshot())
        .await
        .expect("a request to an aborted actor returns");
    assert!(matches!(outcome, Err(RelayError::Shutdown)));
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
