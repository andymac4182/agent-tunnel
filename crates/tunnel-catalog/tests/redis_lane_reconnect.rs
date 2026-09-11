//! Same-primary reconnection after a severed Redis connection.
//!
//! A plain loopback TCP forwarder sits between the catalog and the disposable
//! Redis primary.  Severing every forwarded socket while keeping the listener
//! models a transient partition that closes connections without restarting
//! Redis.  The command that discovers the loss must fail closed exactly once
//! without any retry or background reconnect; the next command on that lane
//! must open one fresh connection to the same verified primary and succeed,
//! and every sibling lane must probe and reconnect before its next caller
//! command rather than failing that caller too.  Identity refusal for a
//! changed `run_id` and live-sibling retention are covered by the in-crate
//! lane unit tests, because they need a fake authority.

use std::{
    collections::BTreeSet,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use redis::IntoConnectionInfo;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{oneshot, watch},
    task::JoinSet,
    time::timeout,
};
use tunnel_catalog::{
    AuthenticatedConsumer, Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice,
    GrantSpec, MembershipRecord, MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog,
    ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m7-lane-reconnect";
const OPERATION_DEADLINE: StdDuration = StdDuration::from_secs(5);
const SCENARIO_DEADLINE: StdDuration = StdDuration::from_secs(40);
const MAX_PROXY_CONNECTIONS: usize = 16;
/// The catalog opens one catalog lane, four authorization lanes and two
/// maintenance lanes (`resolve_device`, `renew_owner`).
const LANES: usize = 7;
const AUTHORIZATION_LANES: usize = 4;
const MAINTENANCE_LANES: usize = 2;

struct SeveringProxy {
    url: String,
    accepted: Arc<AtomicUsize>,
    active: Arc<AtomicUsize>,
    sever: watch::Sender<u64>,
    shutdown: Option<oneshot::Sender<()>>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl SeveringProxy {
    async fn start(upstream: SocketAddr, db: i64) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind severing proxy");
        let port = listener.local_addr().expect("proxy address").port();
        let accepted = Arc::new(AtomicUsize::new(0));
        let active = Arc::new(AtomicUsize::new(0));
        let (sever, _) = watch::channel(0_u64);
        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let task = tokio::spawn(run_proxy(
            listener,
            upstream,
            Arc::clone(&accepted),
            Arc::clone(&active),
            sever.subscribe(),
            shutdown_rx,
        ));
        Self {
            url: format!("redis://127.0.0.1:{port}/{db}"),
            accepted,
            active,
            sever,
            shutdown: Some(shutdown_tx),
            task: Some(task),
        }
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }

    /// Close every forwarded connection and wait until the proxy has dropped
    /// all of them.  The listener keeps accepting new connections.
    async fn sever_all(&self) {
        self.sever.send_modify(|generation| *generation += 1);
        let deadline = tokio::time::Instant::now() + OPERATION_DEADLINE;
        while self.active.load(Ordering::Acquire) != 0 {
            assert!(
                tokio::time::Instant::now() < deadline,
                "severing proxy did not drop its forwarded connections"
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
                connections.spawn(forward(client, upstream, sever.clone(), Arc::clone(&active)));
            }
            Some(_) = connections.join_next() => {}
        }
    }
}

async fn forward(
    mut client: TcpStream,
    upstream: SocketAddr,
    mut sever: watch::Receiver<u64>,
    active: Arc<AtomicUsize>,
) {
    // Only a sever signalled after this connection was accepted applies to
    // it; a receiver cloned from the accept loop still sees earlier
    // generations as unobserved.
    sever.mark_unchanged();
    let connected = tokio::select! {
        _ = sever.changed() => None,
        connected = TcpStream::connect(upstream) => connected.ok(),
    };
    if let Some(mut upstream_stream) = connected {
        tokio::select! {
            // Dropping both sockets is the injected transport loss.
            _ = sever.changed() => {}
            _ = tokio::io::copy_bidirectional(&mut client, &mut upstream_stream) => {}
        }
    }
    active.fetch_sub(1, Ordering::AcqRel);
}

fn upstream_address(url: &str) -> (SocketAddr, i64) {
    let info = url
        .into_connection_info()
        .expect("TUNNEL_CATALOG_REDIS_URL must be a Redis URL");
    let address = match info.addr() {
        redis::ConnectionAddr::Tcp(host, port) => {
            let ip: std::net::IpAddr = host
                .parse()
                .expect("lane reconnect test requires a loopback IP Redis URL");
            assert!(
                ip.is_loopback(),
                "lane reconnect test refuses a non-loopback upstream"
            );
            SocketAddr::new(ip, *port)
        }
        other => panic!("lane reconnect test requires a plaintext TCP upstream, got {other:?}"),
    };
    (address, info.redis_settings().db())
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, Uuid, String) {
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
                display_name: "lane reconnect tenant".into(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "lane reconnect user".into(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: "https://issuer.lane-reconnect.fixture.invalid".into(),
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
                display_name: "lane reconnect device".into(),
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
                display_name: "lane reconnect echo".into(),
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
        user_id,
        device_id,
        service_id,
        spki_fingerprint,
    )
}

fn assert_transport_loss(error: &CatalogError, context: &str) {
    match error {
        CatalogError::Database(database) => assert!(
            database.is_io_error() || database.is_connection_dropped(),
            "{context}: severed lane reported a non-transport database error"
        ),
        other => panic!("{context}: severed lane reported {other} instead of a transport loss"),
    }
}

async fn run_scenario(proxied: RedisCatalog, proxy: &SeveringProxy) {
    let (fixture, tenant_id, user_id, device_id, service_id, spki_fingerprint) = fixture_values();
    proxied
        .seed_fixture(&fixture)
        .await
        .expect("seed lane reconnect fixture through the proxy");
    let consumer = AuthenticatedConsumer {
        tenant_id,
        principal_id: user_id,
    };
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
    let authorize = |catalog: &RedisCatalog| {
        let catalog = catalog.clone();
        let consumer = consumer.clone();
        async move {
            let now = Utc::now();
            timeout(
                OPERATION_DEADLINE,
                catalog.authorize(&consumer, device_id, service_id, now, now),
            )
            .await
            .expect("bounded authorize")
        }
    };

    let resolve_consumer = |catalog: &RedisCatalog| {
        let catalog = catalog.clone();
        let issuer = fixture.identities[0].issuer.clone();
        let subject = fixture.identities[0].subject.clone();
        async move {
            timeout(
                OPERATION_DEADLINE,
                catalog.resolve_consumer(&issuer, &subject, Some(tenant_id)),
            )
            .await
            .expect("bounded resolve_consumer")
        }
    };

    // Baseline: maintenance lane 0 resolves the device, authorization lane 0
    // authorizes, and the seed already used the catalog lane.
    let before = resolve(&proxied).await.expect("baseline device resolution");
    assert_eq!(before.map(|identity| identity.device_id), Some(device_id));
    let grant = authorize(&proxied).await.expect("baseline authorization");
    assert!(
        grant.is_some(),
        "baseline authorization must see the seeded grant"
    );
    assert_eq!(
        proxy.accepted(),
        LANES,
        "startup opens exactly one catalog lane, four authorization lanes and two maintenance lanes"
    );

    proxy.sever_all().await;
    // Maintenance lane 1 discovers the loss: it fails closed exactly once
    // and neither retries nor reconnects in place.
    let lost = resolve(&proxied)
        .await
        .expect_err("the first maintenance-lane command after the loss must fail closed");
    assert_transport_loss(&lost, "maintenance lane");
    assert_eq!(
        proxy.accepted(),
        LANES,
        "the failed maintenance-lane command must neither retry nor reconnect"
    );
    // Maintenance lane 0 was severed by the same event; its loss-generation
    // probe finds that out and it reconnects before its caller's command.
    // Maintenance lane 1 then reconnects on its own next command.
    for lane in 0..MAINTENANCE_LANES {
        let after = resolve(&proxied).await.unwrap_or_else(|error| {
            panic!("maintenance lane {lane} must reconnect to the same primary: {error}")
        });
        assert_eq!(after.map(|identity| identity.device_id), Some(device_id));
        assert_eq!(
            proxy.accepted(),
            LANES + 1 + lane,
            "maintenance lane {lane} reconnects exactly once"
        );
    }
    let reconnected = LANES + MAINTENANCE_LANES;

    // The authorization lanes rotate round-robin.  The maintenance lane's
    // loss told them to probe, so each severed lane reconnects before its
    // first caller command instead of failing that caller closed.
    for lane in 0..AUTHORIZATION_LANES {
        let grant = authorize(&proxied).await.unwrap_or_else(|error| {
            panic!("authorization lane {lane} must probe and reconnect: {error}")
        });
        assert!(
            grant.is_some(),
            "reconnected authorization lane {lane} must see the grant"
        );
        assert_eq!(
            proxy.accepted(),
            reconnected + 1 + lane,
            "authorization lane {lane} reconnects exactly once"
        );
    }
    let reconnected = reconnected + AUTHORIZATION_LANES;

    // The catalog lane probes and reconnects the same way.
    let consumer_after = resolve_consumer(&proxied)
        .await
        .expect("the catalog lane must probe and reconnect");
    assert_eq!(
        consumer_after.map(|consumer| consumer.principal_id),
        Some(user_id)
    );
    assert_eq!(
        proxy.accepted(),
        reconnected + 1,
        "the catalog lane reconnects exactly once"
    );
    let reconnected = reconnected + 1;

    let reused = authorize(&proxied)
        .await
        .expect("reconnected lanes are reused");
    assert!(reused.is_some());
    let reused = resolve(&proxied)
        .await
        .expect("reconnected lanes are reused");
    assert_eq!(reused.map(|identity| identity.device_id), Some(device_id));
    assert_eq!(proxy.accepted(), reconnected, "no further reconnects");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_severed_redis_lanes_fail_once_then_reconnect_to_the_same_primary() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("lane reconnect test requires TUNNEL_CATALOG_REDIS_URL");
    let (upstream, db) = upstream_address(&upstream_url);
    let namespace = format!("test-lane-reconnect-{}", Uuid::new_v4());
    let cleanup_catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, INCARNATION)
            .await
            .expect("connect cleanup catalog");
    cleanup_catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate lane reconnect incarnation");

    let proxy = SeveringProxy::start(upstream, db).await;
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
    scenario.expect("lane reconnect scenario exceeded its deadline");
    cleanup
        .expect("namespace cleanup exceeded its deadline")
        .expect("namespace cleanup");
}
