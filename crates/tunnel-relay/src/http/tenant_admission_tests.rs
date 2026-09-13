//! Real-socket stage for M7-C33: the consumer admission bound must be
//! tenant-scoped, not only relay-global.
//!
//! The relay-global [`Semaphore`] is held for the whole operation round trip,
//! so one tenant's in-flight public streams used to refuse every other
//! tenant's public request with the typed admission-limit outcome.  These
//! regressions run two tenants, each with its own user, device, service and
//! device credential, through the real consumer route on a loopback TCP
//! listener: the upgrade, the refusal body and the permit accounting all cross
//! the real handler boundary.  A fake connector (forwarded control/data
//! registrations) stands in for each device, so an accepted stream holds its
//! admission permits exactly as a live public stream does.
//!
//! Consumer TLS is not part of this stage; the transport crate covers it
//! separately.

use std::{collections::BTreeSet, sync::Arc, time::Duration};

use axum::{Router, routing::get};
use chrono::{Duration as ChronoDuration, Utc};
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use rcgen::KeyPair;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, mpsc},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;
use tunnel_catalog::{
    ApprovedJwk, Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, MemoryCatalog, OidcConfig, OidcVerifier, PermissionSet,
    PrincipalIdentity, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_protocol::{ControlMessage, Hello};
use uuid::Uuid;

use super::{
    ConsumerUpgradeBarrier, ECHO_STREAM_SUBPROTOCOL, HttpState, ScopedAdmission, echo_stream, wire,
};
use crate::{
    actor::{ControlOutbound, DataOutbound, RelayHandle},
    config::{RelayLimits, RelayOptions},
    routing::OwnerScope,
};

const ISSUER: &str = "https://tenant-admission-issuer.example";
const AUDIENCE: &str = "tenant-admission-audience";
const POLL_BUDGET: Duration = Duration::from_secs(5);
/// A refused request must answer from the handler, never hang.
const RESPONSE_BUDGET: Duration = Duration::from_secs(5);

/// One tenant's complete, independent identity: its own user, device, service
/// and device credential.  Nothing but the relay process is shared, so a
/// refusal observed for one tenant can only come from a bound the relay
/// applies across tenants.
#[derive(Clone)]
struct Tenant {
    label: &'static str,
    tenant_id: Uuid,
    user_id: Uuid,
    device_id: Uuid,
    service_id: Uuid,
    credential_id: Uuid,
    spki: String,
    subject: String,
}

impl Tenant {
    fn new(label: &'static str, index: u128, spki_byte: char) -> Self {
        let id = |suffix: u128| Uuid::from_u128(0xC33_0000_0000_0000_0000 + index * 0x100 + suffix);
        Self {
            label,
            tenant_id: id(1),
            user_id: id(2),
            device_id: id(3),
            service_id: id(4),
            credential_id: id(5),
            spki: std::iter::repeat_n(spki_byte, 64).collect(),
            subject: format!("tenant-admission-{label}"),
        }
    }

    fn scope(&self) -> OwnerScope {
        OwnerScope::new(self.tenant_id, self.device_id)
    }
}

#[derive(serde::Serialize)]
struct Claims {
    iss: String,
    sub: String,
    aud: String,
    exp: usize,
    scope: String,
}

/// One verifier and one signing key for both tenants: the tokens differ only
/// in their subject, which the catalog maps to each tenant's own member.
fn oidc_fixture(tenants: &[Tenant]) -> (Arc<OidcVerifier>, Vec<String>) {
    let key = KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("OIDC signing key");
    let approved = ApprovedJwk::from_ed25519_der("tenant-admission", key.public_key_raw())
        .expect("OIDC verification key");
    let config =
        OidcConfig::new(ISSUER, [AUDIENCE.to_owned()], vec![approved]).expect("OIDC config");
    let verifier = Arc::new(OidcVerifier::new(config).expect("OIDC verifier"));
    let mut header = Header::new(Algorithm::EdDSA);
    header.kid = Some("tenant-admission".to_owned());
    let tokens = tenants
        .iter()
        .map(|tenant| {
            let claims = Claims {
                iss: ISSUER.to_owned(),
                sub: tenant.subject.clone(),
                aud: AUDIENCE.to_owned(),
                exp: (Utc::now().timestamp() + 300) as usize,
                scope: crate::ECHO_OPERATION.to_owned(),
            };
            encode(
                &header,
                &claims,
                &EncodingKey::from_ed_der(key.serialized_der()),
            )
            .expect("OIDC token")
        })
        .collect();
    (verifier, tokens)
}

fn catalog_fixture(tenants: &[Tenant]) -> CatalogFixture {
    let now = Utc::now();
    let mut fixture = CatalogFixture::default();
    for tenant in tenants {
        fixture.tenants.push(TenantRecord {
            tenant_id: tenant.tenant_id,
            display_name: format!("tenant-admission {}", tenant.label),
            active: true,
        });
        fixture.users.push(UserRecord {
            user_id: tenant.user_id,
            display_name: format!("tenant-admission consumer {}", tenant.label),
        });
        fixture.identities.push(PrincipalIdentity {
            issuer: ISSUER.to_owned(),
            subject: tenant.subject.clone(),
            user_id: tenant.user_id,
        });
        fixture.memberships.push(MembershipRecord {
            tenant_id: tenant.tenant_id,
            user_id: tenant.user_id,
            role: MembershipRole::Member,
            active: true,
        });
        fixture.devices.push(FixtureDevice {
            tenant_id: tenant.tenant_id,
            device_id: tenant.device_id,
            owner_user_id: tenant.user_id,
            display_name: format!("tenant-admission device {}", tenant.label),
            active: true,
            last_seen_at: Some(now),
        });
        fixture.credentials.push(CredentialRecord {
            tenant_id: tenant.tenant_id,
            device_id: tenant.device_id,
            credential_id: tenant.credential_id,
            spki_fingerprint: tenant.spki.clone(),
            serial: Some(format!("tenant-admission-{}", tenant.label)),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::minutes(10),
            revoked_at: None,
            active: true,
        });
        fixture.services.push(ServiceSpec {
            tenant_id: tenant.tenant_id,
            device_id: tenant.device_id,
            service_id: tenant.service_id,
            service_type: "echo".to_owned(),
            display_name: "Echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        });
        fixture.grants.push(GrantSpec {
            tenant_id: tenant.tenant_id,
            principal_id: tenant.user_id,
            device_id: tenant.device_id,
            service_id: tenant.service_id,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({}),
            expires_at: Some(now + ChronoDuration::minutes(10)),
            active: true,
        });
    }
    fixture
}

/// One public upgrade attempt's outcome, read off the real socket.
struct Attempt {
    status: u16,
    body: Option<serde_json::Value>,
    /// Retained for an accepted upgrade so the stream -- and therefore its
    /// admission permits -- stays live for the assertions that follow.
    socket: Option<TcpStream>,
}

impl Attempt {
    fn code(&self) -> Option<&str> {
        self.body.as_ref()?.get("code")?.as_str()
    }

    fn execution(&self) -> Option<&str> {
        self.body.as_ref()?.get("execution")?.as_str()
    }

    fn retry_after_ms(&self) -> Option<u64> {
        self.body.as_ref()?.get("retry_after_ms")?.as_u64()
    }

    fn retryable(&self) -> Option<bool> {
        self.body.as_ref()?.get("retryable")?.as_bool()
    }
}

/// Send one real consumer stream upgrade and read its response head, plus a
/// bounded JSON error body when the handler refused instead of upgrading.
async fn attempt(address: std::net::SocketAddr, tenant: &Tenant, token: &str) -> Attempt {
    let mut socket = TcpStream::connect(address)
        .await
        .expect("connect consumer client");
    let request = format!(
        "GET /v1/devices/{}/services/{}/stream HTTP/1.1\r\n\
         Host: 127.0.0.1\r\n\
         Connection: Upgrade\r\n\
         Upgrade: websocket\r\n\
         Sec-WebSocket-Version: 13\r\n\
         Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Protocol: {ECHO_STREAM_SUBPROTOCOL}\r\n\
         Authorization: Bearer {token}\r\n\
         \r\n",
        tenant.device_id, tenant.service_id,
    );
    socket
        .write_all(request.as_bytes())
        .await
        .expect("write upgrade request");
    timeout(RESPONSE_BUDGET, async {
        let mut head = Vec::new();
        let mut byte = [0_u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            let read = socket.read(&mut byte).await.expect("read response head");
            assert!(read == 1, "the handler closed before answering");
            head.push(byte[0]);
            assert!(head.len() <= 8 * 1024, "response head exceeded its bound");
        }
        let head = String::from_utf8(head).expect("response head is UTF-8");
        let status = head
            .split_whitespace()
            .nth(1)
            .and_then(|code| code.parse::<u16>().ok())
            .expect("response status");
        let length = head
            .lines()
            .find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().ok())?
            })
            .unwrap_or(0);
        assert!(length <= 8 * 1024, "error body exceeded its bound");
        let body = if length == 0 {
            None
        } else {
            let mut bytes = vec![0_u8; length];
            socket
                .read_exact(&mut bytes)
                .await
                .expect("read response body");
            Some(serde_json::from_slice(&bytes).expect("error body is JSON"))
        };
        Attempt {
            status,
            body,
            socket: (status == 101).then_some(socket),
        }
    })
    .await
    .expect("the handler answered within its bound")
}

/// The relay, both fake connectors, the public route and the two admission
/// bounds under test.
struct Stage {
    address: std::net::SocketAddr,
    handle: RelayHandle,
    admission: Arc<Semaphore>,
    scoped: Arc<ScopedAdmission>,
    global_permits: usize,
    tokens: Vec<String>,
    #[allow(dead_code)]
    control: Vec<mpsc::Receiver<ControlOutbound>>,
    #[allow(dead_code)]
    data: Vec<mpsc::Receiver<DataOutbound>>,
    barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    server_cancel: CancellationToken,
    server_task: JoinHandle<()>,
}

impl Stage {
    async fn start(
        label: &str,
        tenants: &[Tenant],
        global_permits: usize,
        per_owner_permits: usize,
        barrier: Option<Arc<ConsumerUpgradeBarrier>>,
    ) -> Self {
        let catalog = Arc::new(MemoryCatalog::new());
        catalog
            .seed_fixture(&catalog_fixture(tenants))
            .await
            .expect("seed tenant-admission catalog");
        let (oidc, tokens) = oidc_fixture(tenants);
        let mut options = RelayOptions::new(oidc.clone());
        options.node_id = format!("{label}-node");
        options.boot_id = format!("{label}-boot");
        options.limits = RelayLimits {
            max_pending_operations: global_permits,
            max_pending_operations_per_owner: per_owner_permits,
            ..RelayLimits::default()
        };
        options.limits.validate().expect("stage limits validate");
        let limits = options.limits.clone();
        let handle = RelayHandle::spawn(options, catalog.clone());

        let mut control = Vec::new();
        let mut data = Vec::new();
        for tenant in tenants {
            let device = catalog
                .resolve_device(&tenant.spki, Utc::now())
                .await
                .expect("resolve device")
                .expect("device identity");
            let mut hello = Hello::new(
                format!("{label}-hello-{}", tenant.label),
                tenant.device_id.to_string(),
                1,
                0,
            );
            hello.features = vec![
                wire::M1_PROFILE_FEATURE.to_owned(),
                wire::ORDERED_ROTATION_FEATURE.to_owned(),
                "echo".to_owned(),
            ];
            let registration = handle
                .register_forwarded_control(device, tenant.spki.clone(), hello)
                .await
                .expect("admit control session");
            let ticket =
                match wire::parse_control(registration.welcome.as_bytes()).expect("WELCOME") {
                    ControlMessage::Welcome(welcome) => welcome.attachment_ticket,
                    other => panic!("unexpected registration response: {other:?}"),
                };
            let data_device = catalog
                .resolve_device(&tenant.spki, Utc::now())
                .await
                .expect("resolve data device")
                .expect("data device identity");
            let data_registration = handle
                .attach_forwarded_data(data_device, tenant.spki.clone(), ticket)
                .await
                .expect("attach data carrier");
            control.push(registration.rx);
            data.push(data_registration.rx);
        }

        let admission = Arc::new(Semaphore::new(limits.max_pending_operations));
        let scoped = ScopedAdmission::new(
            limits.max_pending_operations_per_owner,
            limits.max_pending_operations,
        );
        let state = HttpState {
            handle: handle.clone(),
            catalog: Some(catalog.clone()),
            oidc: Some(oidc),
            limits: limits.clone(),
            admission: Arc::clone(&admission),
            scoped_admission: Arc::clone(&scoped),
            peer: None,
            consumer_upgrade_barrier: barrier.clone(),
            peer_admission_barrier: None,
        };
        let router = Router::new()
            .route(
                "/v1/devices/{device}/services/{service}/stream",
                get(echo_stream),
            )
            .with_state(state);
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let address = listener.local_addr().expect("listener address");
        let server_cancel = CancellationToken::new();
        let shutdown = server_cancel.clone();
        let server_task = tokio::spawn(async move {
            axum::serve(listener, router.into_make_service())
                .with_graceful_shutdown(async move { shutdown.cancelled().await })
                .await
                .expect("consumer route server");
        });

        assert_eq!(admission.available_permits(), limits.max_pending_operations);
        assert_eq!(scoped.tracked_scopes(), 0);
        Self {
            address,
            handle,
            admission,
            scoped,
            global_permits: limits.max_pending_operations,
            tokens,
            control,
            data,
            barrier,
            server_cancel,
            server_task,
        }
    }

    async fn attempt(&self, tenants: &[Tenant], index: usize) -> Attempt {
        attempt(self.address, &tenants[index], &self.tokens[index]).await
    }

    /// Wait until every admission permit, global and per-scope, is back.
    async fn wait_drained(&self, what: &str) {
        timeout(POLL_BUDGET, async {
            while self.admission.available_permits() != self.global_permits
                || self.scoped.tracked_scopes() != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("{what}: admission permits were not released"));
    }

    async fn shutdown(self) {
        self.server_cancel.cancel();
        timeout(POLL_BUDGET, self.server_task)
            .await
            .expect("server shutdown deadline")
            .expect("server task joins");
        self.handle.shutdown().await.expect("relay shutdown");
        if let Some(barrier) = self.barrier.as_ref() {
            assert_eq!(barrier.hit_count(), 1);
        }
    }
}

/// Assert the exact typed admission refusal, including its retry metadata.
fn assert_admission_refusal(attempt: &Attempt, what: &str) {
    assert_eq!(attempt.status, 429, "{what}: status");
    assert_eq!(attempt.code(), Some("ADMISSION_LIMIT"), "{what}: code");
    assert_eq!(
        attempt.execution(),
        Some("not_dispatched"),
        "{what}: execution"
    );
    assert_eq!(attempt.retryable(), Some(true), "{what}: retryable");
    let retry_after_ms = attempt
        .retry_after_ms()
        .unwrap_or_else(|| panic!("{what}: the refusal must carry a bounded retry hint"));
    assert!(
        (1..=5_000).contains(&retry_after_ms),
        "{what}: retry hint {retry_after_ms} exceeded its bound"
    );
}

#[tokio::test]
async fn one_tenant_at_its_per_owner_bound_cannot_refuse_another_tenant() {
    let tenants = [Tenant::new("a", 1, 'a'), Tenant::new("b", 2, 'b')];
    // Four relay-global permits, two per owner scope.  Tenant A then attempts
    // one stream for every relay-global permit: without a tenant-scoped bound
    // it takes all four and tenant B's public request is refused, which is the
    // defect under regression.
    let global_permits = 4;
    let per_owner_permits = 2;
    let stage = Stage::start(
        "c33-two-tenant",
        &tenants,
        global_permits,
        per_owner_permits,
        None,
    )
    .await;

    let mut held = Vec::new();
    let mut refusals = Vec::new();
    for index in 0..global_permits {
        let mut attempt = stage.attempt(&tenants, 0).await;
        match attempt.status {
            101 => held.push(attempt.socket.take().expect("accepted socket")),
            _ => {
                assert_admission_refusal(
                    &attempt,
                    &format!("tenant A attempt {index} beyond its per-owner bound"),
                );
                assert!(
                    attempt.socket.is_none(),
                    "a refused attempt must not be upgraded"
                );
                refusals.push(attempt);
            }
        }
    }

    // This is the regression: tenant B's public request still succeeds while
    // tenant A pushes against the relay-global bound.
    let mut sibling = stage.attempt(&tenants, 1).await;
    assert_eq!(
        sibling.status, 101,
        "tenant B must still be admitted while tenant A holds its full allowance"
    );
    let sibling_socket = sibling.socket.take().expect("tenant B socket");

    // Tenant A was held to its own bound, and every attempt above it received
    // the existing typed refusal rather than silently queueing.
    assert_eq!(
        held.len(),
        per_owner_permits,
        "tenant A must be admitted exactly up to its per-owner bound"
    );
    assert_eq!(
        refusals.len(),
        global_permits - per_owner_permits,
        "every tenant A attempt above its bound must be refused"
    );
    assert_eq!(
        stage.scoped.in_flight(tenants[0].scope()),
        per_owner_permits,
        "tenant A must hold exactly its per-owner allowance"
    );
    assert_eq!(
        stage.scoped.in_flight(tenants[1].scope()),
        1,
        "tenant B holds its own per-owner permit"
    );
    assert_eq!(
        stage.admission.available_permits(),
        global_permits - per_owner_permits - 1,
        "a refused attempt must release the relay-global permit it reserved"
    );
    assert_eq!(
        stage.scoped.tracked_scopes(),
        2,
        "exactly the two live owner scopes are tracked"
    );

    // Releasing one of tenant A's streams restores exactly one permit to its
    // scope, and tenant A is admitted again.
    drop(held.pop().expect("a held tenant A socket"));
    timeout(POLL_BUDGET, async {
        while stage.scoped.in_flight(tenants[0].scope()) != per_owner_permits - 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("the closed tenant A stream releases exactly one per-owner permit");
    let mut readmitted = stage.attempt(&tenants, 0).await;
    assert_eq!(
        readmitted.status, 101,
        "tenant A must be readmitted once it is below its own bound"
    );
    held.push(readmitted.socket.take().expect("readmitted socket"));

    drop(held);
    drop(sibling_socket);
    stage.wait_drained("closed tenant streams").await;
    stage.shutdown().await;
}

#[tokio::test]
async fn the_relay_global_admission_bound_still_protects_the_process() {
    let tenants = [Tenant::new("a", 3, 'c'), Tenant::new("b", 4, 'd')];
    // Two relay-global permits and a per-owner allowance equal to them: tenant
    // A exhausts the process bound without reaching a scope bound of its own,
    // so tenant B's refusal can only come from the relay-global bound.
    let stage = Stage::start("c33-global-bound", &tenants, 2, 2, None).await;

    let mut held = Vec::new();
    for attempt_index in 0..2 {
        let mut accepted = stage.attempt(&tenants, 0).await;
        assert_eq!(
            accepted.status, 101,
            "tenant A attempt {attempt_index} must be admitted"
        );
        held.push(accepted.socket.take().expect("accepted socket"));
    }
    assert_eq!(
        stage.admission.available_permits(),
        0,
        "the relay-global bound must be exhausted"
    );

    let refused = stage.attempt(&tenants, 1).await;
    assert_admission_refusal(&refused, "tenant B beyond the relay-global bound");
    assert_eq!(
        stage.scoped.in_flight(tenants[1].scope()),
        0,
        "tenant B never reached its own scope bound"
    );
    assert_eq!(
        stage.scoped.tracked_scopes(),
        1,
        "a refusal at the relay-global bound must not create a scope entry"
    );

    drop(held);
    stage.wait_drained("closed tenant A streams").await;
    let mut readmitted = stage.attempt(&tenants, 1).await;
    assert_eq!(
        readmitted.status, 101,
        "tenant B is admitted once the process bound clears"
    );
    drop(readmitted.socket.take());
    stage.wait_drained("closed tenant B stream").await;
    stage.shutdown().await;
}

#[tokio::test]
async fn an_abandoned_upgrade_releases_its_per_owner_permit_exactly_once() {
    let tenants = [Tenant::new("a", 5, 'e'), Tenant::new("b", 6, 'f')];
    let barrier = Arc::new(ConsumerUpgradeBarrier::default());
    assert!(barrier.arm());
    // One permit per owner scope: a leaked permit would permanently refuse
    // this tenant, so the post-cancellation readmission below is exact.
    let stage = Stage::start("c33-cancelled", &tenants, 4, 1, Some(Arc::clone(&barrier))).await;

    // Hold the handler after owner admission and before the 101, then abandon
    // the request: the handler future is dropped mid-flight.
    let tenant = tenants[0].clone();
    let token = stage.tokens[0].clone();
    let address = stage.address;
    let abandoning = tokio::spawn(async move {
        let mut socket = TcpStream::connect(address)
            .await
            .expect("connect abandoning client");
        let request = format!(
            "GET /v1/devices/{}/services/{}/stream HTTP/1.1\r\n\
             Host: 127.0.0.1\r\n\
             Connection: Upgrade\r\n\
             Upgrade: websocket\r\n\
             Sec-WebSocket-Version: 13\r\n\
             Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
             Sec-WebSocket-Protocol: {ECHO_STREAM_SUBPROTOCOL}\r\n\
             Authorization: Bearer {token}\r\n\
             \r\n",
            tenant.device_id, tenant.service_id,
        );
        socket
            .write_all(request.as_bytes())
            .await
            .expect("write upgrade request");
        socket
    });
    timeout(POLL_BUDGET, barrier.wait_reached())
        .await
        .expect("upgrade barrier reached");
    assert!(barrier.is_held());
    assert_eq!(
        stage.scoped.in_flight(tenants[0].scope()),
        1,
        "the held handler owns its per-owner permit"
    );
    assert_eq!(stage.admission.available_permits(), 3);

    let socket = timeout(POLL_BUDGET, abandoning)
        .await
        .expect("abandoning client deadline")
        .expect("abandoning client task joins");
    drop(socket);
    barrier.release();

    stage.wait_drained("abandoned upgrade").await;
    assert_eq!(
        stage.scoped.in_flight(tenants[0].scope()),
        0,
        "the cancelled handler must release its per-owner permit"
    );

    // Exactly once, not twice: a double release would raise the scope's
    // capacity above its bound and admit two concurrent streams.
    let mut first = stage.attempt(&tenants, 0).await;
    assert_eq!(first.status, 101, "the released permit is reusable");
    let first_socket = first.socket.take().expect("first socket");
    let second = stage.attempt(&tenants, 0).await;
    assert_admission_refusal(&second, "a second stream beyond the one-permit bound");
    assert_eq!(
        stage.scoped.in_flight(tenants[0].scope()),
        1,
        "the per-owner bound must still be exactly one permit"
    );

    drop(first_socket);
    stage.wait_drained("closed reused stream").await;
    stage.shutdown().await;
}

/// The registry's own release contract, independent of the HTTP boundary: a
/// cancelled acquisition releases exactly one permit and leaves no entry
/// behind, so the map stays bounded by the live permit count.
#[tokio::test]
async fn scoped_admission_releases_exactly_one_permit_per_cancelled_acquisition() {
    let scoped = ScopedAdmission::new(2, 8);
    assert_eq!(scoped.permits(), 2);
    let scope = OwnerScope::new(Uuid::from_u128(0xC33_1001), Uuid::from_u128(0xC33_1002));
    let other = OwnerScope::new(Uuid::from_u128(0xC33_2001), Uuid::from_u128(0xC33_2002));

    for round in 0..3 {
        let ready = Arc::new(tokio::sync::Notify::new());
        let observed = Arc::clone(&ready);
        let registry = Arc::clone(&scoped);
        let task = tokio::spawn(async move {
            let _permit = registry
                .try_acquire(scope)
                .expect("a cancelled round must not leak its permit");
            observed.notify_one();
            // Cancelled while holding the permit.
            std::future::pending::<()>().await;
        });
        ready.notified().await;
        assert_eq!(scoped.in_flight(scope), 1, "round {round}");
        task.abort();
        let _ = task.await;
        timeout(POLL_BUDGET, async {
            while scoped.in_flight(scope) != 0 || scoped.tracked_scopes() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap_or_else(|_| panic!("round {round}: the cancelled permit was not released"));
    }

    // A double release would let a third concurrent permit through.
    let first = scoped.try_acquire(scope).expect("first permit");
    let second = scoped.try_acquire(scope).expect("second permit");
    assert_eq!(scoped.in_flight(scope), 2);
    assert!(
        scoped.try_acquire(scope).is_none(),
        "the bound must refuse a third permit for the same scope"
    );
    let sibling = scoped
        .try_acquire(other)
        .expect("an unrelated scope keeps its own allowance");
    assert_eq!(scoped.tracked_scopes(), 2);
    drop(first);
    assert_eq!(
        scoped.in_flight(scope),
        1,
        "one release must return exactly one permit"
    );
    drop(second);
    assert_eq!(scoped.in_flight(scope), 0);
    assert_eq!(
        scoped.tracked_scopes(),
        1,
        "an idle scope entry must be reclaimed"
    );
    drop(sibling);
    assert_eq!(
        scoped.tracked_scopes(),
        0,
        "no scope entry may outlive its permits"
    );
}

/// The effective bound is the lower of the two configured bounds, so a
/// per-owner allowance above the process bound cannot be advertised.
#[test]
fn scoped_admission_clamps_a_per_owner_bound_above_the_global_bound() {
    assert_eq!(ScopedAdmission::new(48, 1).permits(), 1);
    assert_eq!(ScopedAdmission::new(2, 64).permits(), 2);
    assert_eq!(ScopedAdmission::new(0, 64).permits(), 1);
}
