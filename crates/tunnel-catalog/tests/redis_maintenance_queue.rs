//! M7-C32: a queueing delay on the maintenance path is not authority loss.
//!
//! A loopback TCP forwarder between the catalog and the disposable Redis
//! primary delays every reply chunk by a fixed latency, concurrently and in
//! order, the way a slow network path does.  Many concurrent `resolve_device`
//! and `renew_owner` calls, the two commands the relay's maintenance tick
//! issues per session, must each be measured against that per-reply latency
//! rather than against each other: with forty callers and a 100 ms reply the
//! serialized wait alone would exceed the two-second authority deadline while
//! no single reply is late.  A reply that genuinely exceeds the deadline must
//! still fail closed as a `timeout`, a severed connection must still fail
//! closed as a transport loss, and the two must remain distinguishable so the
//! relay's closed maintenance vocabulary can report them separately.  The
//! same-primary reconnect contract from `redis_lane_reconnect` is unchanged:
//! the discovering command never retries, the next command reconnects once.

use std::{
    collections::{BTreeSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use redis::IntoConnectionInfo;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{oneshot, watch},
    task::JoinSet,
    time::{Instant, timeout},
};
use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, OwnerClaimRequest, OwnerToken, PermissionSet,
    PrincipalIdentity, RedisCatalog, ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m7-maintenance-queue";
const OPERATION_DEADLINE: StdDuration = StdDuration::from_secs(8);
const SCENARIO_DEADLINE: StdDuration = StdDuration::from_secs(60);
const MAX_PROXY_CONNECTIONS: usize = 16;
const MAX_PENDING_CHUNKS: usize = 4_096;
/// The catalog's documented per-command authority deadline.
const AUTHORITY_DEADLINE: StdDuration = StdDuration::from_secs(2);
/// Concurrent maintenance callers per command.  Eighty commands behind a
/// 100 ms reply would take eight seconds one at a time.
const CALLERS: usize = 40;
const REPLY_DELAY: StdDuration = StdDuration::from_millis(100);
/// A reply slower than the authority deadline with nobody else queued.
const STALLED_REPLY_DELAY: StdDuration = StdDuration::from_millis(2_600);

struct DelayingProxy {
    url: String,
    accepted: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    reply_delay_ms: Arc<AtomicU64>,
    sever: watch::Sender<u64>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl DelayingProxy {
    async fn start(upstream: SocketAddr, db: i64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind delaying proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let reply_delay_ms = Arc::new(AtomicU64::new(0));
        let (sever, _) = watch::channel(0_u64);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run_proxy(
            listener,
            upstream,
            Arc::clone(&accepted),
            Arc::clone(&active),
            Arc::clone(&reply_delay_ms),
            sever.subscribe(),
            shutdown_rx,
        ));
        Self {
            url: format!("redis://127.0.0.1:{port}/{db}"),
            accepted,
            active,
            reply_delay_ms,
            sever,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }

    /// Delay applied to every reply chunk from now on, measured from the
    /// chunk's arrival at the proxy.  Chunks stay in order.
    fn set_reply_delay(&self, delay: StdDuration) {
        self.reply_delay_ms.store(
            u64::try_from(delay.as_millis()).expect("bounded reply delay"),
            Ordering::Release,
        );
    }

    async fn sever_all(&self) {
        self.sever.send_modify(|generation| *generation += 1);
        let deadline = Instant::now() + OPERATION_DEADLINE;
        while self.active.load(Ordering::Acquire) != 0 {
            assert!(
                Instant::now() < deadline,
                "delaying proxy did not drop its forwarded connections"
            );
            tokio::time::sleep(StdDuration::from_millis(5)).await;
        }
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        if let Some(task) = self.task.take() {
            timeout(OPERATION_DEADLINE, task)
                .await
                .expect("proxy shutdown deadline")
                .expect("proxy task");
        }
    }
}

async fn run_proxy(
    listener: TcpListener,
    upstream: SocketAddr,
    accepted: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    reply_delay_ms: Arc<AtomicU64>,
    sever: watch::Receiver<u64>,
    mut shutdown: oneshot::Receiver<()>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut shutdown => {
                connections.abort_all();
                while connections.join_next().await.is_some() {}
                return;
            }
            accepted_stream = listener.accept() => {
                let Ok((client, _)) = accepted_stream else { return; };
                if active.load(Ordering::Acquire) >= MAX_PROXY_CONNECTIONS {
                    drop(client);
                    continue;
                }
                accepted.fetch_add(1, Ordering::AcqRel);
                active.fetch_add(1, Ordering::AcqRel);
                connections.spawn(forward(
                    client,
                    upstream,
                    Arc::clone(&reply_delay_ms),
                    sever.clone(),
                    Arc::clone(&active),
                ));
            }
            Some(_) = connections.join_next() => {}
        }
    }
}

async fn forward(
    client: TcpStream,
    upstream: SocketAddr,
    reply_delay_ms: Arc<AtomicU64>,
    mut sever: watch::Receiver<u64>,
    active: Arc<AtomicUsize>,
) {
    sever.mark_unchanged();
    let connected = tokio::select! {
        _ = sever.changed() => None,
        connected = TcpStream::connect(upstream) => connected.ok(),
    };
    if let Some(upstream_stream) = connected {
        let (mut client_read, client_write) = client.into_split();
        let (upstream_read, mut upstream_write) = upstream_stream.into_split();
        let requests = async move {
            let _ = tokio::io::copy(&mut client_read, &mut upstream_write).await;
        };
        let replies = delay_replies(upstream_read, client_write, reply_delay_ms);
        tokio::select! {
            // Dropping both halves of both sockets is the injected loss.
            _ = sever.changed() => {}
            _ = requests => {}
            _ = replies => {}
        }
    }
    active.fetch_sub(1, Ordering::AcqRel);
}

/// Forward reply chunks in order, each written once its own delay from
/// arrival has elapsed; later chunks never wait for earlier delays.
async fn delay_replies(
    mut upstream_read: OwnedReadHalf,
    mut client_write: OwnedWriteHalf,
    reply_delay_ms: Arc<AtomicU64>,
) {
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut due: VecDeque<(Instant, Vec<u8>)> = VecDeque::new();
    let mut upstream_open = true;
    loop {
        if !upstream_open && due.is_empty() {
            return;
        }
        let next_due = due.front().map(|(at, _)| *at);
        tokio::select! {
            read = upstream_read.read(&mut buffer), if upstream_open => {
                match read {
                    Ok(0) | Err(_) => upstream_open = false,
                    Ok(read) => {
                        let delay = StdDuration::from_millis(reply_delay_ms.load(Ordering::Acquire));
                        due.push_back((Instant::now() + delay, buffer[..read].to_vec()));
                        if due.len() > MAX_PENDING_CHUNKS {
                            return;
                        }
                    }
                }
            }
            _ = async {
                match next_due {
                    Some(at) => tokio::time::sleep_until(at).await,
                    None => std::future::pending::<()>().await,
                }
            } => {
                let Some((_, chunk)) = due.pop_front() else { continue };
                if client_write.write_all(&chunk).await.is_err() {
                    return;
                }
            }
        }
    }
}

fn upstream_address(url: &str) -> (SocketAddr, i64) {
    let info = url
        .into_connection_info()
        .expect("TUNNEL_CATALOG_REDIS_URL must be a Redis URL");
    let address = match info.addr() {
        redis::ConnectionAddr::Tcp(host, port) => {
            let ip: std::net::IpAddr = host
                .parse()
                .expect("maintenance queue test requires a loopback IP Redis URL");
            assert!(
                ip.is_loopback(),
                "maintenance queue test refuses a non-loopback upstream"
            );
            SocketAddr::new(ip, *port)
        }
        other => panic!("maintenance queue test requires a plaintext TCP upstream, got {other:?}"),
    };
    (address, info.redis_settings().db())
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, String) {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    let spki_fingerprint = format!("{:064x}", user_id.as_u128());
    let now = Utc::now();
    (
        CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "maintenance queue tenant".into(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "maintenance queue user".into(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: "https://issuer.maintenance-queue.fixture.invalid".into(),
                subject: format!("subject-{user_id}"),
                user_id,
            }],
            memberships: vec![MembershipRecord {
                tenant_id,
                user_id,
                role: MembershipRole::Member,
                active: true,
            }],
            devices: vec![FixtureDevice {
                tenant_id,
                device_id,
                owner_user_id: user_id,
                display_name: "maintenance queue device".into(),
                active: true,
                last_seen_at: Some(now),
            }],
            credentials: vec![CredentialRecord {
                tenant_id,
                device_id,
                credential_id: Uuid::new_v4(),
                spki_fingerprint: spki_fingerprint.clone(),
                serial: Some(format!("serial-{device_id}")),
                not_before: now - Duration::seconds(1),
                expires_at: now + Duration::hours(1),
                revoked_at: None,
                active: true,
            }],
            services: vec![ServiceSpec {
                tenant_id,
                device_id,
                service_id,
                service_type: "echo".into(),
                display_name: "maintenance queue echo".into(),
                capabilities: serde_json::json!({"operations":["echo:invoke"]}),
                version: 1,
                active: true,
            }],
            grants: vec![GrantSpec {
                tenant_id,
                principal_id: user_id,
                device_id,
                service_id,
                permissions: PermissionSet {
                    operations: BTreeSet::from(["echo:invoke".into()]),
                },
                constraints: serde_json::json!({"max_bytes":4096}),
                expires_at: Some(now + Duration::hours(1)),
                active: true,
            }],
        },
        tenant_id,
        device_id,
        user_id,
        spki_fingerprint,
    )
}

fn database_error<'a>(error: &'a CatalogError, context: &str) -> &'a redis::RedisError {
    match error {
        CatalogError::Database(database) => database,
        other => panic!("{context}: reported {other} instead of a database error"),
    }
}

async fn run_scenario(proxied: RedisCatalog, proxy: &DelayingProxy) {
    let (fixture, tenant_id, device_id, _user_id, spki_fingerprint) = fixture_values();
    proxied
        .seed_fixture(&fixture)
        .await
        .expect("seed maintenance queue fixture through the proxy");
    let claim = proxied
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: INCARNATION.to_owned(),
            tenant_id,
            device_id,
            node_id: "maintenance-queue-node".to_owned(),
            boot_id: "maintenance-queue-boot".to_owned(),
            session_id: "maintenance-queue-session".to_owned(),
            lease_expires_at: Utc::now() + Duration::seconds(25),
        })
        .await
        .expect("claim the maintenance owner lease");
    let owner: OwnerToken = claim.token;
    let lanes_at_startup = proxy.accepted();

    let resolve = |catalog: &RedisCatalog| {
        let fingerprint = spki_fingerprint.clone();
        let catalog = catalog.clone();
        async move {
            timeout(
                OPERATION_DEADLINE,
                catalog.resolve_device(&fingerprint, Utc::now()),
            )
            .await
            .expect("bounded resolve_device")
        }
    };
    let renew = |catalog: &RedisCatalog| {
        let catalog = catalog.clone();
        let owner = owner.clone();
        async move {
            timeout(
                OPERATION_DEADLINE,
                catalog.renew_owner(&owner, Utc::now() + Duration::seconds(25)),
            )
            .await
            .expect("bounded renew_owner")
        }
    };

    // Forty sessions' worth of identity re-checks and owner renewals, each
    // reply 100 ms late, all at once.
    proxy.set_reply_delay(REPLY_DELAY);
    let started = Instant::now();
    let mut resolves = JoinSet::new();
    let mut renewals = JoinSet::new();
    for _ in 0..CALLERS {
        resolves.spawn(resolve(&proxied));
        renewals.spawn(renew(&proxied));
    }
    let mut resolve_failures = Vec::new();
    while let Some(joined) = resolves.join_next().await {
        match joined.expect("resolve task") {
            Ok(Some(identity)) => assert_eq!(identity.device_id, device_id),
            Ok(None) => panic!("queued resolve_device lost the seeded device"),
            Err(error) => resolve_failures.push(error.to_string()),
        }
    }
    let mut renew_failures = Vec::new();
    while let Some(joined) = renewals.join_next().await {
        match joined.expect("renew task") {
            Ok(true) => {}
            Ok(false) => panic!("queued renew_owner reported the live owner as stale"),
            Err(error) => renew_failures.push(error.to_string()),
        }
    }
    let elapsed = started.elapsed();
    assert!(
        resolve_failures.is_empty() && renew_failures.is_empty(),
        "queued maintenance commands failed after {elapsed:?} although every reply took \
         {REPLY_DELAY:?}: resolve_device {resolve_failures:?}, renew_owner {renew_failures:?}"
    );
    assert!(
        elapsed < AUTHORITY_DEADLINE,
        "{} queued maintenance commands took {elapsed:?}; they were serialized behind each other",
        2 * CALLERS
    );
    assert_eq!(
        proxy.accepted(),
        lanes_at_startup,
        "queueing must not open connections"
    );

    // A reply that is genuinely late is a timeout: reported as such, never as
    // a severed connection, never retried, and the lane re-verifies the same
    // primary on its next command.
    proxy.set_reply_delay(STALLED_REPLY_DELAY);
    let stalled_started = Instant::now();
    let stalled = resolve(&proxied)
        .await
        .expect_err("a reply slower than the authority deadline must fail closed");
    let stalled_elapsed = stalled_started.elapsed();
    let database = database_error(&stalled, "stalled authority");
    assert!(
        database.is_timeout() && !database.is_connection_dropped(),
        "stalled authority reported {database} instead of a timeout"
    );
    assert!(
        stalled_elapsed >= AUTHORITY_DEADLINE && stalled_elapsed < STALLED_REPLY_DELAY,
        "the timeout fired after {stalled_elapsed:?}, outside the authority deadline"
    );
    assert_eq!(
        proxy.accepted(),
        lanes_at_startup,
        "a timeout never reconnects in place"
    );
    proxy.set_reply_delay(StdDuration::ZERO);
    // The maintenance lanes rotate: the next command lands on the sibling
    // lane, whose probe finds its connection live, and the command after
    // that returns to the timed-out lane, which re-verifies the same primary
    // on one fresh connection.
    let sibling = resolve(&proxied)
        .await
        .expect("the sibling maintenance lane probes and keeps its connection");
    assert_eq!(sibling.map(|identity| identity.device_id), Some(device_id));
    assert_eq!(
        proxy.accepted(),
        lanes_at_startup,
        "a live sibling lane opens no connection"
    );
    let recovered = resolve(&proxied)
        .await
        .expect("the command after a timeout re-verifies the same primary");
    assert_eq!(
        recovered.map(|identity| identity.device_id),
        Some(device_id)
    );
    assert_eq!(
        proxy.accepted(),
        lanes_at_startup + 1,
        "exactly one fresh connection replaces the timed-out lane"
    );

    // A severed connection is a transport loss, distinguishable from a
    // timeout; the discovering command fails closed once and the next
    // command reconnects once.
    proxy.sever_all().await;
    let lost = resolve(&proxied)
        .await
        .expect_err("the first command after the loss must fail closed");
    let database = database_error(&lost, "severed lane");
    assert!(
        (database.is_io_error() || database.is_connection_dropped()) && !database.is_timeout(),
        "severed lane reported {database} instead of a transport loss"
    );
    assert_eq!(
        proxy.accepted(),
        lanes_at_startup + 1,
        "the discovering command must neither retry nor reconnect"
    );
    let after = resolve(&proxied)
        .await
        .expect("the next command reconnects to the same primary");
    assert_eq!(after.map(|identity| identity.device_id), Some(device_id));
    assert_eq!(proxy.accepted(), lanes_at_startup + 2);
    let renewed = renew(&proxied)
        .await
        .expect("the sibling maintenance lane probes and reconnects before its caller's command");
    assert!(renewed, "the owner lease survives the transport loss");
    assert_eq!(proxy.accepted(), lanes_at_startup + 3);
    assert!(
        proxied
            .release_owner(&owner)
            .await
            .expect("release the maintenance owner lease")
    );
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_maintenance_queue_delay_is_not_authority_loss() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("maintenance queue test requires TUNNEL_CATALOG_REDIS_URL");
    let (upstream, db) = upstream_address(&upstream_url);
    let namespace = format!("test-maintenance-queue-{}", Uuid::new_v4());
    let cleanup_catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, INCARNATION)
            .await
            .expect("connect cleanup catalog");
    cleanup_catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate maintenance queue incarnation");

    let proxy = DelayingProxy::start(upstream, db).await;
    let proxied = RedisCatalog::connect_for_recovery(&proxy.url, &namespace, INCARNATION)
        .await
        .expect("connect proxied catalog");
    let scenario = timeout(SCENARIO_DEADLINE, run_scenario(proxied, &proxy)).await;
    proxy.shutdown().await;
    let cleanup = timeout(
        OPERATION_DEADLINE,
        cleanup_catalog.cleanup_fixture_namespace(),
    )
    .await;
    scenario.expect("maintenance queue scenario exceeded its deadline");
    cleanup
        .expect("namespace cleanup exceeded its deadline")
        .expect("namespace cleanup");
}
