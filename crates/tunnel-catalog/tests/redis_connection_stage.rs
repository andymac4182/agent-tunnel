//! Task row M6-C72 (M6-C71 on `m6-fly-deploy`): a failed Redis authority
//! connection keeps its bounded stage, the lane that failed, and a fixed
//! failure class, against a real Redis primary.
//!
//! Each case forces one specific failure: an unknown ACL user (`auth` while
//! establishing the connection), an ACL user without `INFO` (`noperm` at the
//! primary-identity check), and a lane connection that a forwarder accepts
//! but never answers (`timeout` on lane 3 of 6, after the primary connection
//! and two lanes succeeded, once the ten-second connect budget of M6-C73
//! expires).  None of these writes a catalog key.

use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use redis::IntoConnectionInfo;
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpStream},
    sync::Mutex,
};
use tunnel_catalog::{
    CatalogConnectionFailure, CatalogConnectionLane, CatalogConnectionStage, RedisCatalog,
};
use uuid::Uuid;

const INCARNATION: &str = "test-m6c72-incarnation";

fn redis_url() -> String {
    std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("M6-C72 stage tests require TUNNEL_CATALOG_REDIS_URL")
}

fn upstream(url: &str) -> (SocketAddr, i64) {
    let info = url.into_connection_info().expect("Redis URL");
    let redis::ConnectionAddr::Tcp(host, port) = info.addr().clone() else {
        panic!("M6-C72 stage tests need a plaintext TCP Redis URL");
    };
    let address = format!("{host}:{port}")
        .parse()
        .expect("Redis URL must name an IP:port");
    (address, info.redis_settings().db())
}

fn with_credentials(address: SocketAddr, database: i64, user: &str, password: &str) -> String {
    format!("redis://{user}:{password}@{address}/{database}")
}

async fn admin(url: &str) -> redis::aio::MultiplexedConnection {
    redis::Client::open(url)
        .expect("admin client")
        .get_multiplexed_async_connection()
        .await
        .expect("admin connection")
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m6c72_unknown_acl_user_reports_auth_while_establishing() {
    let url = redis_url();
    let (address, database) = upstream(&url);
    let nonce = Uuid::new_v4().simple().to_string();
    let password = format!("m6c72-wrong-{nonce}");
    let bad_url = with_credentials(
        address,
        database,
        &format!("m6c72-nouser-{nonce}"),
        &password,
    );
    let error = RedisCatalog::connect_for_recovery_staged(
        &bad_url,
        &format!("test-m6c72-{nonce}"),
        INCARNATION,
    )
    .await
    .expect_err("an unknown ACL user must be refused");
    assert_eq!(
        error.stage(),
        CatalogConnectionStage::ConnectionEstablishment
    );
    assert_eq!(error.lane(), None);
    assert_eq!(error.failure(), CatalogConnectionFailure::Auth);
    println!("m6c72-real ok case=auth nonce={nonce}");
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m6c72_acl_user_without_info_reports_noperm_at_primary_identity() {
    let url = redis_url();
    let (address, database) = upstream(&url);
    let nonce = Uuid::new_v4().simple().to_string();
    let user = format!("m6c72-noinfo-{nonce}");
    let password = format!("m6c72-pass-{nonce}");
    let mut admin = admin(&url).await;
    let () = redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&user)
        .arg("on")
        .arg(format!(">{password}"))
        .arg("~*")
        .arg("+@all")
        .arg("-info")
        .query_async(&mut admin)
        .await
        .expect("create the no-INFO ACL user");
    let result = RedisCatalog::connect_for_recovery_staged(
        &with_credentials(address, database, &user, &password),
        &format!("test-m6c72-{nonce}"),
        INCARNATION,
    )
    .await;
    let _: i64 = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&user)
        .query_async(&mut admin)
        .await
        .expect("delete the no-INFO ACL user");
    let error = result.expect_err("a user without INFO must be refused");
    assert_eq!(error.stage(), CatalogConnectionStage::PrimaryIdentity);
    assert_eq!(error.lane(), None);
    assert_eq!(error.failure(), CatalogConnectionFailure::NoPerm);
    println!("m6c72-real ok case=noperm nonce={nonce}");
}

/// Forwards each accepted connection to Redis, except connection number
/// `silent` (1-based), which is accepted and held open without a byte.
async fn forwarder(upstream: SocketAddr, silent: usize) -> (SocketAddr, Arc<AtomicUsize>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind forwarder");
    let address = listener.local_addr().expect("forwarder address");
    let accepted = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&accepted);
    let held: Arc<Mutex<Vec<TcpStream>>> = Arc::default();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                return;
            };
            let number = counter.fetch_add(1, Ordering::SeqCst) + 1;
            if number == silent {
                held.lock().await.push(socket);
                continue;
            }
            tokio::spawn(async move {
                let Ok(mut plain) = TcpStream::connect(upstream).await else {
                    let _ = socket.shutdown().await;
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut socket, &mut plain).await;
            });
        }
    });
    (address, accepted)
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m6c72_silent_lane_reports_its_lane_and_a_timeout() {
    let url = redis_url();
    let (upstream, database) = upstream(&url);
    let nonce = Uuid::new_v4().simple().to_string();
    // Connection 1 is the primary; connections 2..=7 are lanes 1..=6.
    let (address, accepted) = forwarder(upstream, 4).await;
    let started = std::time::Instant::now();
    let error = RedisCatalog::connect_for_recovery_staged(
        &format!("redis://{address}/{database}"),
        &format!("test-m6c72-{nonce}"),
        INCARNATION,
    )
    .await
    .expect_err("a silent lane must fail the connection");
    let elapsed = started.elapsed();
    assert_eq!(
        error.lane(),
        Some(CatalogConnectionLane { index: 3, total: 6 })
    );
    assert_eq!(error.failure(), CatalogConnectionFailure::Timeout);
    assert_eq!(
        error.stage(),
        CatalogConnectionStage::ConnectionEstablishment
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        4,
        "no lane after the silent one"
    );
    // The catalog's explicit ten-second connect budget decided (M6-C73),
    // not redis-rs's one-second default.
    assert!(
        elapsed >= Duration::from_millis(9_500) && elapsed < Duration::from_secs(13),
        "the ten-second connect budget decided the failure: {elapsed:?}"
    );
    println!(
        "m6c72-real ok case=lane-timeout stage={} nonce={nonce}",
        error.stage().as_str()
    );
}
