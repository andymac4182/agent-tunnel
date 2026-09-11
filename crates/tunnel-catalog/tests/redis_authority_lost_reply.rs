//! EC-014 lost-reply evidence for one committed Redis owner mutation.
//!
//! A bounded RESP-aware loopback proxy forwards the selected `EVAL` to Redis,
//! reads the committed response, and drops it before it reaches the catalog
//! client.  A fresh direct observer then checks the durable owner epoch and
//! generation.  The selected command count proves this path did not retry or
//! replay through a generic pool.  This remains an unknown-outcome test: it
//! does not add or imply a typed lost-write API.

use std::{
    collections::BTreeSet,
    future::Future,
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration as StdDuration,
};

use chrono::{Duration, Utc};
use redis::{AsyncCommands, IntoConnectionInfo};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, OwnerClaimRequest, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m7-ec014-lost-reply";
const MAX_RESP_FRAME: usize = 8 * 1024 * 1024;
const MAX_RESP_ITEMS: usize = 16_384;
const MAX_PROXY_CONNECTIONS: usize = 8;
const PROXY_IO_DEADLINE: StdDuration = StdDuration::from_secs(5);

#[derive(Clone)]
struct ProxyControl {
    armed: Arc<AtomicBool>,
    selected_seen: Arc<Notify>,
    selected_count: Arc<AtomicUsize>,
}

impl ProxyControl {
    fn new() -> Self {
        Self {
            armed: Arc::new(AtomicBool::new(false)),
            selected_seen: Arc::new(Notify::new()),
            selected_count: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn arm_selected_mutation(&self) {
        self.armed.store(true, Ordering::Release);
    }

    async fn wait_selected_mutation(&self) {
        timeout(PROXY_IO_DEADLINE, self.selected_seen.notified())
            .await
            .expect("proxy did not observe selected mutation")
    }

    fn selected_count(&self) -> usize {
        self.selected_count.load(Ordering::Acquire)
    }
}

struct LoopbackProxy {
    url: String,
    control: ProxyControl,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
}

impl Drop for LoopbackProxy {
    fn drop(&mut self) {
        if let Some(task) = self.task.as_ref() {
            task.abort();
        }
    }
}

impl LoopbackProxy {
    async fn start(upstream_url: &str) -> Self {
        let upstream = upstream_address(upstream_url);
        let listener = TcpListener::bind(("127.0.0.1", 0))
            .await
            .expect("bind lost-reply Redis loopback proxy");
        let address = listener
            .local_addr()
            .expect("read lost-reply proxy address");
        let control = ProxyControl::new();
        let (stop, stop_rx) = oneshot::channel();
        let task = tokio::spawn(run_proxy(listener, upstream, control.clone(), stop_rx));
        Self {
            url: format!("redis://127.0.0.1:{}", address.port()),
            control,
            stop: Some(stop),
            task: Some(task),
        }
    }

    async fn shutdown(mut self) {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(mut task) = self.task.take() else {
            return;
        };
        match timeout(PROXY_IO_DEADLINE, &mut task).await {
            Ok(result) => result.expect("lost-reply proxy task"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("lost-reply proxy shutdown deadline");
            }
        }
    }
}

fn upstream_address(url: &str) -> String {
    let info = url
        .into_connection_info()
        .expect("parse Redis URL for lost-reply proxy");
    let settings = info.redis_settings();
    assert!(
        settings.username().is_none() && settings.password().is_none() && settings.db() == 0,
        "lost-reply proxy requires an unauthenticated Redis database 0 URL"
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
            panic!("lost-reply proxy requires a plaintext Redis URL")
        }
        redis::ConnectionAddr::Unix(path) => {
            panic!("lost-reply proxy does not support Unix Redis socket {path:?}")
        }
        _ => panic!("unsupported Redis address for lost-reply proxy"),
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
        while connections.try_join_next().is_some() {}
        tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => {
                let Ok((client, _peer)) = accepted else { break };
                if connections.len() >= MAX_PROXY_CONNECTIONS {
                    // Keep accepted connection tasks bounded. Completed
                    // tasks are drained at the top of every loop iteration.
                    drop(client);
                    continue;
                }
                connections.spawn(proxy_connection(client, upstream.clone(), control.clone()));
            }
        }
    }
    connections.abort_all();
    while connections.join_next().await.is_some() {}
}

async fn proxy_connection(mut client: TcpStream, upstream: String, control: ProxyControl) {
    let Ok(Ok(mut server)) = timeout(PROXY_IO_DEADLINE, TcpStream::connect(upstream)).await else {
        return;
    };
    loop {
        let request = match timeout(PROXY_IO_DEADLINE, read_resp_frame(&mut client)).await {
            Ok(Ok(request)) => request,
            Ok(Err(_)) | Err(_) => return,
        };
        let command = command_name(&request);
        match timeout(PROXY_IO_DEADLINE, server.write_all(&request)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
        }
        let response = match timeout(PROXY_IO_DEADLINE, read_resp_frame(&mut server)).await {
            Ok(Ok(response)) => response,
            Ok(Err(_)) | Err(_) => return,
        };
        if command.as_deref() == Some("EVAL") && control.armed.load(Ordering::Acquire) {
            control.selected_count.fetch_add(1, Ordering::AcqRel);
            control.selected_seen.notify_one();
            // Redis has already executed the script and returned its reply.
            // Closing this client leg deliberately makes the caller observe
            // an error/unknown result rather than a successful owner claim.
            return;
        }
        match timeout(PROXY_IO_DEADLINE, client.write_all(&response)).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return,
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

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, Uuid) {
    let tenant_id = Uuid::new_v4();
    let user_id = Uuid::new_v4();
    let device_id = Uuid::new_v4();
    let service_id = Uuid::new_v4();
    let now = Utc::now();
    (
        CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id,
                display_name: "EC-014 lost-reply tenant".into(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id,
                display_name: "EC-014 lost-reply user".into(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: "https://issuer.ec014-lost-reply.fixture.invalid".into(),
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
                display_name: "EC-014 lost-reply device".into(),
                active: true,
                last_seen_at: Some(now),
            }],
            credentials: vec![CredentialRecord {
                tenant_id,
                device_id,
                credential_id: Uuid::new_v4(),
                spki_fingerprint: format!("{:064x}", user_id.as_u128()),
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
                display_name: "EC-014 lost-reply echo".into(),
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
    )
}

async fn run_scenario(catalog: RedisCatalog, upstream_url: String, namespace: String) {
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate EC-014 lost-reply incarnation");
    let (fixture, tenant_id, _user_id, device_id, _service_id) = fixture_values();
    catalog
        .seed_fixture(&fixture)
        .await
        .expect("seed EC-014 lost-reply fixture");

    let epoch_key = format!("tunnel-catalog:{namespace}:coord:epoch:{tenant_id}:{device_id}");
    let generation_key = format!("tunnel-catalog:{namespace}:meta:catalog_generation");
    let owner_key =
        format!("tunnel-catalog:{namespace}:coord:owner:{INCARNATION}:{tenant_id}:{device_id}");
    let observer_client =
        redis::Client::open(upstream_url.as_str()).expect("open baseline observer");
    let mut observer = observer_client
        .get_multiplexed_async_connection()
        .await
        .expect("connect baseline observer");
    let epoch_before: String = observer
        .get(&epoch_key)
        .await
        .expect("read baseline owner epoch");
    let generation_before: String = observer
        .get(&generation_key)
        .await
        .expect("read baseline catalog generation");

    let proxy = LoopbackProxy::start(&upstream_url).await;
    let control = proxy.control.clone();
    let proxied = RedisCatalog::connect_for_recovery(&proxy.url, &namespace, INCARNATION)
        .await
        .expect("connect proxied catalog");
    control.arm_selected_mutation();
    let request = OwnerClaimRequest {
        deployment_incarnation: INCARNATION.into(),
        tenant_id,
        device_id,
        node_id: "lost-reply-node".into(),
        boot_id: "lost-reply-boot".into(),
        session_id: "lost-reply-session".into(),
        lease_expires_at: Utc::now() + Duration::seconds(10),
    };
    let outcome = timeout(StdDuration::from_secs(5), proxied.claim_owner(&request)).await;
    control.wait_selected_mutation().await;
    match outcome {
        Ok(Ok(_)) => panic!("lost reply was incorrectly reported as a successful owner claim"),
        Ok(Err(tunnel_catalog::CatalogError::Database(_))) => {}
        Ok(Err(error)) => panic!("unexpected typed lost-reply outcome: {error}"),
        Err(_) => {
            // The catalog has no typed unknown-write result. Its bounded
            // timeout is accepted here and resolved below from Redis state.
        }
    }
    // Keep the failed catalog handle and proxy listener alive briefly. If the
    // Redis driver had a background retry/reconnect path, a second selected
    // EVAL would be counted here rather than being hidden by immediate drop.
    timeout(
        StdDuration::from_secs(1),
        tokio::time::sleep(StdDuration::from_millis(250)),
    )
    .await
    .expect("bounded post-error retry observation");
    assert_eq!(control.selected_count(), 1, "no post-error EVAL replay");
    drop(proxied);
    proxy.shutdown().await;
    assert_eq!(control.selected_count(), 1, "selected EVAL must run once");

    let observer_client = redis::Client::open(upstream_url.as_str()).expect("open commit observer");
    let mut observer = observer_client
        .get_multiplexed_async_connection()
        .await
        .expect("connect commit observer");
    let epoch_after: String = observer
        .get(&epoch_key)
        .await
        .expect("read committed owner epoch");
    let generation_after: String = observer
        .get(&generation_key)
        .await
        .expect("read committed catalog generation");
    let owner_node: Option<String> = observer
        .hget(&owner_key, "node_id")
        .await
        .expect("read committed owner node");
    let owner_epoch: Option<String> = observer
        .hget(&owner_key, "owner_epoch")
        .await
        .expect("read committed owner hash epoch");
    assert_eq!(owner_node.as_deref(), Some("lost-reply-node"));
    assert_eq!(owner_epoch.as_deref(), Some(epoch_after.as_str()));
    assert_eq!(
        epoch_after.parse::<u64>().expect("parse committed epoch"),
        epoch_before.parse::<u64>().expect("parse baseline epoch") + 1
    );
    assert_eq!(
        generation_after
            .parse::<u64>()
            .expect("parse committed generation"),
        generation_before
            .parse::<u64>()
            .expect("parse baseline generation")
            + 1
    );
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn m7_ec014_committed_owner_write_withheld_reply_is_bounded_unknown_once() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("EC-014 lost-reply test requires TUNNEL_CATALOG_REDIS_URL");
    let namespace = format!("test-ec014-lost-reply-{}", Uuid::new_v4());
    let cleanup_catalog =
        RedisCatalog::connect_for_recovery(&upstream_url, &namespace, INCARNATION)
            .await
            .expect("connect cleanup catalog");
    let scenario_catalog = cleanup_catalog.clone();
    let scenario_upstream = upstream_url.clone();
    let scenario_namespace = namespace.clone();
    let mut scenario = tokio::spawn(async move {
        run_scenario(scenario_catalog, scenario_upstream, scenario_namespace).await;
    });

    let primary = match timeout(StdDuration::from_secs(30), &mut scenario).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(join_error)) if join_error.is_panic() => {
            Err(format!("scenario panicked: {join_error}"))
        }
        Ok(Err(join_error)) => Err(format!("scenario did not complete: {join_error}")),
        Err(_) => {
            scenario.abort();
            let _ = scenario.await;
            Err("scenario deadline exceeded after 30 seconds".into())
        }
    };
    let cleanup = match timeout(
        StdDuration::from_secs(5),
        cleanup_catalog.cleanup_fixture_namespace(),
    )
    .await
    {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => Err(format!("cleanup failed: {error}")),
        Err(_) => Err("cleanup deadline exceeded after 5 seconds".into()),
    };
    match (primary, cleanup) {
        (Ok(()), Ok(())) => {}
        (primary, cleanup) => {
            panic!("EC-014 lost-reply scenario failed: primary={primary:?}; cleanup={cleanup:?}")
        }
    }
}
