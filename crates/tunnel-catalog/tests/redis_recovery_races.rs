//! Deterministic recovery cancellation and phantom-race integration coverage.
//!
//! The file stays unlinked until the recovery proxy has passed a compile
//! checkpoint. Tests use a unique fixture namespace and require an operator
//! supplied TUNNEL_CATALOG_REDIS_URL. The loopback proxy is deliberately
//! bounded and RESP-aware: it holds one selected command boundary, not an
//! arbitrary sleep or an unbounded byte stream.

use std::{
    collections::BTreeSet,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use chrono::{Duration as ChronoDuration, Utc};
use redis::{AsyncCommands, IntoConnectionInfo};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, DurableCatalogObservation, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, PermissionSet, PrincipalIdentity, RecoveryApproval,
    RecoveryApprovalIssuer, RecoveryApprovalVerifier, RecoveryPolicy, RedisCatalog, ServiceSpec,
    TenantRecord, TrustedRecoveryKey, UserRecord,
};
use uuid::Uuid;

const DEPLOYMENT_ID: &str = "m7-recovery-race-deployment";
const INITIAL_INCARC: &str = "m7-recovery-race-initial";
const MAX_RESP_FRAME: usize = 8 * 1024 * 1024;
const MAX_RESP_ITEMS: usize = 16_384;

#[derive(Clone)]
struct ProxyControl {
    hold_watch: Arc<AtomicBool>,
    watch_seen: Arc<Notify>,
    release_watch: Arc<Notify>,
    hold_exec: Arc<AtomicBool>,
    exec_seen: Arc<Notify>,
    release_exec: Arc<Notify>,
}

impl ProxyControl {
    fn new() -> Self {
        Self {
            hold_watch: Arc::new(AtomicBool::new(false)),
            watch_seen: Arc::new(Notify::new()),
            release_watch: Arc::new(Notify::new()),
            hold_exec: Arc::new(AtomicBool::new(false)),
            exec_seen: Arc::new(Notify::new()),
            release_exec: Arc::new(Notify::new()),
        }
    }

    fn arm_watch(&self) {
        self.hold_watch.store(true, Ordering::Release);
    }

    async fn wait_watch(&self) -> Result<(), &'static str> {
        timeout(Duration::from_secs(5), self.watch_seen.notified())
            .await
            .map(|_| ())
            .map_err(|_| "proxy did not observe WATCH")
    }

    fn release_watch(&self) {
        self.release_watch.notify_one();
    }

    fn arm_exec(&self) {
        self.hold_exec.store(true, Ordering::Release);
    }

    async fn wait_exec(&self) -> Result<(), &'static str> {
        timeout(Duration::from_secs(5), self.exec_seen.notified())
            .await
            .map(|_| ())
            .map_err(|_| "proxy did not observe activation EXEC")
    }

    fn release_exec(&self) {
        self.release_exec.notify_one();
    }
}

struct LoopbackProxy {
    url: String,
    control: ProxyControl,
    stop: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl LoopbackProxy {
    async fn start(upstream_url: &str) -> Self {
        let upstream = upstream_address(upstream_url);
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind Redis loopback proxy");
        let address = listener.local_addr().expect("proxy address");
        let control = ProxyControl::new();
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run_proxy(listener, upstream, control.clone(), stop_rx));
        Self {
            url: format!("redis://127.0.0.1:{}", address.port()),
            control,
            stop: Some(stop),
            task,
        }
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let mut task = self.task;
        match timeout(Duration::from_secs(5), &mut task).await {
            Ok(result) => result.expect("Redis proxy task"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("Redis proxy shutdown deadline");
            }
        }
    }
}

fn upstream_address(url: &str) -> String {
    let info = url
        .into_connection_info()
        .expect("parse Redis URL for recovery proxy");
    // The proxy reconnects to the upstream with a raw TCP stream and exposes
    // a loopback URL to the catalog client.  Do not silently discard an ACL
    // credential or select a different database in that translation: this
    // deterministic fixture only accepts the unauthenticated database-0
    // shape.  The assertion deliberately contains no URL or secret.
    let settings = info.redis_settings();
    assert!(
        settings.username().is_none() && settings.password().is_none() && settings.db() == 0,
        "deterministic recovery proxy requires an unauthenticated Redis database 0 URL"
    );
    match info.addr() {
        redis::ConnectionAddr::Tcp(host, port) => {
            if host.contains(':') {
                format!("[{host}]:{port}")
            } else {
                format!("{host}:{port}")
            }
        }
        redis::ConnectionAddr::TcpTls { .. } => {
            panic!("deterministic recovery proxy requires a plaintext Redis URL")
        }
        redis::ConnectionAddr::Unix(path) => {
            panic!("deterministic recovery proxy does not support Unix Redis socket {path:?}")
        }
        _ => panic!("unsupported Redis address for deterministic recovery proxy"),
    }
}

async fn run_proxy(
    listener: TcpListener,
    upstream: String,
    control: ProxyControl,
    mut stop: oneshot::Receiver<()>,
) {
    let mut connections = JoinSet::new();
    loop {
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((client, _peer)) = accepted else { break };
                connections.spawn(proxy_connection(client, upstream.clone(), control.clone()));
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn proxy_connection(mut client: TcpStream, upstream: String, control: ProxyControl) {
    let Ok(mut server) = TcpStream::connect(upstream).await else {
        return;
    };
    loop {
        let request = match read_resp_frame(&mut client).await {
            Ok(request) => request,
            Err(_) => return,
        };
        let command = command_name(&request);
        let hold_exec =
            command.as_deref() == Some("EXEC") && control.hold_exec.swap(false, Ordering::AcqRel);
        if hold_exec {
            control.exec_seen.notify_one();
            control.release_exec.notified().await;
        }
        if server.write_all(&request).await.is_err() {
            return;
        }
        let response = match read_resp_frame(&mut server).await {
            Ok(response) => response,
            Err(_) => return,
        };
        let hold_watch =
            command.as_deref() == Some("WATCH") && control.hold_watch.swap(false, Ordering::AcqRel);
        if hold_watch {
            control.watch_seen.notify_one();
            control.release_watch.notified().await;
        }
        if client.write_all(&response).await.is_err() {
            return;
        }
    }
}

fn read_resp_frame<'a, R>(
    reader: &'a mut R,
) -> Pin<Box<dyn Future<Output = io::Result<Vec<u8>>> + Send + 'a>>
where
    R: AsyncRead + Unpin + Send + 'a,
{
    Box::pin(async move {
        let mut raw = Vec::new();
        let mut marker = [0_u8; 1];
        reader.read_exact(&mut marker).await?;
        raw.push(marker[0]);
        match marker[0] {
            b'+' | b'-' | b':' | b',' | b'#' | b'_' | b'(' => {
                read_resp_line(reader, &mut raw).await?;
            }
            b'$' | b'!' | b'=' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let length = parse_resp_integer(&line)?;
                if length < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP bulk length",
                    ));
                }
                if length >= 0 {
                    let length = usize::try_from(length).map_err(|_| {
                        io::Error::new(io::ErrorKind::InvalidData, "RESP bulk length overflow")
                    })?;
                    if length > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP bulk frame bound",
                        ));
                    }
                    let mut payload = vec![0_u8; length.saturating_add(2)];
                    reader.read_exact(&mut payload).await?;
                    if payload[length..] != *b"\r\n" {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP bulk terminator",
                        ));
                    }
                    raw.extend(payload);
                }
            }
            b'*' | b'~' | b'>' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let count = parse_resp_integer(&line)?;
                if count < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP array count",
                    ));
                }
                if count == -1 {
                    return Ok(raw);
                }
                let count = usize::try_from(count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "RESP array count overflow")
                })?;
                if count > MAX_RESP_ITEMS {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "RESP array bound",
                    ));
                }
                for _ in 0..count {
                    raw.extend(read_resp_frame(reader).await?);
                    if raw.len() > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP frame bound",
                        ));
                    }
                }
            }
            b'%' => {
                let line = read_resp_line(reader, &mut raw).await?;
                let count = parse_resp_integer(&line)?;
                if count < -1 {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "invalid RESP map count",
                    ));
                }
                if count == -1 {
                    return Ok(raw);
                }
                let count = usize::try_from(count)
                    .ok()
                    .and_then(|count| count.checked_mul(2))
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidData, "RESP map count overflow")
                    })?;
                if count > MAX_RESP_ITEMS {
                    return Err(io::Error::new(io::ErrorKind::InvalidData, "RESP map bound"));
                }
                for _ in 0..count {
                    raw.extend(read_resp_frame(reader).await?);
                    if raw.len() > MAX_RESP_FRAME {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            "RESP frame bound",
                        ));
                    }
                }
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported RESP marker",
                ));
            }
        }
        if raw.len() > MAX_RESP_FRAME {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP frame bound",
            ));
        }
        Ok(raw)
    })
}

async fn read_resp_line<R>(reader: &mut R, raw: &mut Vec<u8>) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        reader.read_exact(&mut byte).await?;
        raw.push(byte[0]);
        line.push(byte[0]);
        if line.len() > 128 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "RESP line bound",
            ));
        }
        if line.ends_with(b"\r\n") {
            return Ok(line);
        }
    }
}

fn parse_resp_integer(line: &[u8]) -> io::Result<i64> {
    let line = line
        .strip_suffix(b"\r\n")
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "RESP line terminator"))?;
    std::str::from_utf8(line)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RESP integer encoding"))?
        .parse::<i64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "RESP integer"))
}

fn command_name(request: &[u8]) -> Option<String> {
    let mut cursor = 0;
    if request.get(cursor).copied()? != b'*' {
        return None;
    }
    cursor += 1;
    let (_, next) = raw_line(request, cursor)?;
    cursor = next;
    if request.get(cursor).copied()? != b'$' {
        return None;
    }
    cursor += 1;
    let (length, next) = raw_line(request, cursor)?;
    cursor = next;
    let length = std::str::from_utf8(length).ok()?.parse::<usize>().ok()?;
    let end = cursor.checked_add(length)?;
    let command = request.get(cursor..end)?;
    if request.get(end..end.checked_add(2)?)? != b"\r\n" {
        return None;
    }
    Some(std::str::from_utf8(command).ok()?.to_ascii_uppercase())
}

fn raw_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
    let relative_end = bytes
        .get(start..)?
        .windows(2)
        .position(|pair| pair == b"\r\n")?;
    let end = start.checked_add(relative_end)?;
    Some((&bytes[start..end], end.checked_add(2)?))
}

struct Fixture {
    catalog: RedisCatalog,
    upstream_url: String,
    namespace: String,
    user: Uuid,
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    let credential = CredentialRecord {
        tenant_id: tenant,
        device_id: device,
        credential_id: Uuid::new_v4(),
        spki_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
            .to_owned(),
        serial: Some("recovery-race-credential".to_owned()),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::hours(1),
        revoked_at: None,
        active: true,
    };
    let fixture = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "recovery race tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "recovery race user".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.recovery-race.invalid".to_owned(),
            subject: format!("recovery-race-subject-{user}"),
            user_id: user,
        }],
        memberships: vec![MembershipRecord {
            tenant_id: tenant,
            user_id: user,
            role: MembershipRole::Member,
            active: true,
        }],
        devices: vec![FixtureDevice {
            tenant_id: tenant,
            device_id: device,
            owner_user_id: user,
            display_name: "recovery race device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![credential],
        services: vec![ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".to_owned(),
            display_name: "recovery race echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant,
            principal_id: user,
            device_id: device,
            service_id: service,
            permissions: PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({"max_bytes": 4096}),
            expires_at: Some(now + ChronoDuration::hours(1)),
            active: true,
        }],
    };
    (fixture, tenant, user, device, service)
}

async fn fixture(upstream_url: &str, proxy_url: &str) -> Fixture {
    let namespace = format!("test-recovery-race-{}", Uuid::new_v4());
    let catalog = RedisCatalog::connect_for_recovery(proxy_url, &namespace, INITIAL_INCARC)
        .await
        .expect("connect recovery-race catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate recovery-race fixture");
    let (records, _tenant, user, _device, _service) = fixture_values();
    catalog
        .seed_fixture(&records)
        .await
        .expect("seed recovery-race fixture");
    Fixture {
        catalog,
        upstream_url: upstream_url.to_owned(),
        namespace,
        user,
    }
}

async fn cleanup(fixture: &Fixture) {
    fixture
        .catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup recovery-race namespace");
}

async fn active_incarnation(url: &str, namespace: &str) -> String {
    let client = redis::Client::open(url).expect("open direct Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect direct Redis client");
    connection
        .get(format!(
            "tunnel-catalog:{namespace}:meta:active_incarnation"
        ))
        .await
        .expect("read active recovery incarnation")
}

async fn bump_generation(url: &str, namespace: &str) {
    let client = redis::Client::open(url).expect("open generation Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect generation Redis client");
    let _: i64 = redis::cmd("INCR")
        .arg(format!(
            "tunnel-catalog:{namespace}:meta:catalog_generation"
        ))
        .query_async(&mut connection)
        .await
        .expect("bump watched catalog generation");
}

async fn insert_unindexed_user_and_bump_generation(url: &str, namespace: &str) -> Uuid {
    let client = redis::Client::open(url).expect("open phantom Redis client");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect phantom Redis client");
    let user = Uuid::new_v4();
    let prefix = format!("tunnel-catalog:{namespace}:");
    let script = r#"
        redis.call('HSET', KEYS[1], 'user_id', ARGV[1], 'display_name', ARGV[2])
        return redis.call('INCR', KEYS[2])
    "#;
    let _: i64 = redis::cmd("EVAL")
        .arg(script)
        .arg(2_i64)
        .arg(format!("{prefix}user:{user}"))
        .arg(format!("{prefix}meta:catalog_generation"))
        .arg(user.to_string())
        .arg("phantom recovery user")
        .query_async(&mut connection)
        .await
        .expect("insert valid durable user and bump generation");
    user
}

fn signed_approval(
    fixture: &Fixture,
    observation: &DurableCatalogObservation,
    incarnation: &str,
) -> tunnel_catalog::VerifiedRecoveryApproval {
    let (issuer, _) =
        RecoveryApprovalIssuer::generate("recovery-race-publisher").expect("recovery issuer");
    let trusted = TrustedRecoveryKey::new(
        "recovery-race-publisher",
        issuer.public_key().expect("recovery publisher key"),
    )
    .expect("trusted recovery publisher");
    let policy = RecoveryPolicy::new(
        DEPLOYMENT_ID,
        &fixture.namespace,
        observation.redis_run_id(),
        incarnation,
    )
    .expect("recovery race policy");
    let verifier =
        RecoveryApprovalVerifier::new(policy, [trusted]).expect("recovery race verifier");
    let now = Utc::now();
    let nonce = format!("recovery-race-{incarnation}");
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: observation.redis_run_id().to_owned(),
        deployment_incarnation: incarnation.to_owned(),
        approval_version: 1,
        nonce: nonce.clone(),
        catalog_digest: observation.catalog_digest().to_owned(),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::milliseconds(500),
        expires_at: now + ChronoDuration::seconds(20),
    };
    let bytes = issuer
        .sign_approval_bytes(approval)
        .expect("sign recovery race approval");
    verifier
        .verify(&bytes, &nonce, now, None)
        .expect("verify recovery race approval")
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn cancelled_recovery_watch_does_not_contaminate_ordinary_catalog_transaction() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery race Redis URL");
    let proxy = LoopbackProxy::start(&upstream_url).await;
    let fixture = fixture(&upstream_url, &proxy.url).await;

    proxy.control.arm_watch();
    let recovery_catalog = fixture.catalog.clone();
    let observation = tokio::spawn(async move { recovery_catalog.observe_durable_catalog().await });
    if let Err(message) = proxy.control.wait_watch().await {
        observation.abort();
        let _ = observation.await;
        panic!("{message}");
    }

    observation.abort();
    let join_error = observation.await.expect_err("cancelled recovery task");
    assert!(join_error.is_cancelled());

    // The cancelled operation had already established WATCH on the recovery
    // connection. Mutate that watched root before reusing the original
    // catalog handle for a real atomic fixture transaction. A contaminated
    // connection would abort or misroute the following seed operation.
    bump_generation(&fixture.upstream_url, &fixture.namespace).await;
    proxy.control.release_watch();

    // cleanup_fixture_namespace and seed_fixture both use this catalog's
    // shared physical connection. Re-seeding a fresh valid row proves that
    // the cancellation did not leave a WATCH/MULTI state on the handle; the
    // resolver then verifies that the transaction's row is actually usable.
    fixture
        .catalog
        .cleanup_fixture_namespace()
        .await
        .expect("atomic fixture cleanup after recovery cancellation");
    fixture
        .catalog
        .activate_deployment_incarnation()
        .await
        .expect("restore fixture incarnation after atomic cleanup");
    let (replacement, _, _, replacement_device, _) = fixture_values();
    let replacement_fingerprint = replacement
        .credentials
        .first()
        .expect("replacement credential")
        .spki_fingerprint
        .clone();
    fixture
        .catalog
        .seed_fixture(&replacement)
        .await
        .expect("atomic fixture seed after recovery cancellation");
    let resolved = fixture
        .catalog
        .resolve_device(&replacement_fingerprint, Utc::now())
        .await
        .expect("resolve replacement row after atomic fixture seed")
        .expect("replacement credential remains usable");
    assert_eq!(resolved.device_id, replacement_device);
    cleanup(&fixture).await;
    drop(fixture);
    proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn durable_key_and_generation_phantom_before_exec_refuse_activation() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery race Redis URL");
    let proxy = LoopbackProxy::start(&upstream_url).await;
    let fixture = fixture(&upstream_url, &proxy.url).await;
    let observation = fixture
        .catalog
        .observe_durable_catalog()
        .await
        .expect("observe approval catalog");
    let approval = signed_approval(&fixture, &observation, "recovery-race-new-incarnation");
    let recovery = RedisCatalog::connect_for_recovery(
        &proxy.url,
        &fixture.namespace,
        "recovery-race-new-incarnation",
    )
    .await
    .expect("connect recovery activation catalog");

    proxy.control.arm_exec();
    let activation_catalog = recovery.clone();
    let activation = tokio::spawn(async move {
        activation_catalog
            .activate_deployment_incarnation_with_approval(&approval)
            .await
    });
    if let Err(message) = proxy.control.wait_exec().await {
        activation.abort();
        let _ = activation.await;
        panic!("{message}");
    }

    // MULTI/EVAL has been queued, but EXEC is held before Redis receives it.
    // The direct mutation creates a new durable-looking user hash without
    // touching an existing index. It changes only the generation root among
    // keys watched by the first attempt, so the retry must rescan and reject
    // the orphan rather than commit the stale approval.
    let inserted_user =
        insert_unindexed_user_and_bump_generation(&fixture.upstream_url, &fixture.namespace).await;
    assert_ne!(inserted_user, fixture.user);
    proxy.control.release_exec();

    let mut activation = activation;
    let result = match timeout(Duration::from_secs(15), &mut activation).await {
        Ok(result) => result.expect("activation task join"),
        Err(_) => {
            activation.abort();
            let _ = activation.await;
            panic!("bounded activation retry deadline");
        }
    };
    // Named rather than asserted with a bare `matches!`.  This case failed
    // three times inside the full gate survey and passed every standalone run,
    // and the bare assertion said only "assertion failed", which made those
    // failures unexplainable.  The distinction that matters is whether the
    // activation was refused for some other reason, which is noise, or
    // committed, which would be this safety property failing open under load.
    match &result {
        Err(tunnel_catalog::CatalogError::Serialization(message))
            if message == "orphan Redis index or direct lookup" => {}
        Ok(()) => panic!(
            "activation committed a stale approval over an orphan durable key; \
             this safety property failed open"
        ),
        other => panic!(
            "activation was refused, but not as the orphan rejection this case \
             requires: {other:?}"
        ),
    }
    assert_eq!(
        active_incarnation(&fixture.upstream_url, &fixture.namespace).await,
        INITIAL_INCARC
    );
    cleanup(&fixture).await;
    drop(recovery);
    drop(fixture);
    proxy.shutdown().await;
}
