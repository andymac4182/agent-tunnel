//! Deterministic Redis authorization-lane concurrency coverage.
//!
//! The test uses a unique fixture namespace and requires an operator supplied
//! TUNNEL_CATALOG_REDIS_URL. The loopback proxy is deliberately bounded and
//! RESP-aware: it holds one selected EVAL response, not an arbitrary sleep or
//! an unbounded byte stream.

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
use redis::IntoConnectionInfo;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout, timeout_at},
};
use tunnel_catalog::{
    Catalog, CatalogError, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec,
    MembershipRecord, MembershipRole, PermissionSet, PrincipalIdentity, RedisCatalog, ServiceSpec,
    TenantRecord, UserRecord,
};
use uuid::Uuid;

const INCARNATION: &str = "m7-authorize-concurrency";
const MAX_RESP_FRAME: usize = 8 * 1024 * 1024;
const MAX_RESP_ITEMS: usize = 16_384;
const MAX_PROXY_CONNECTIONS: usize = 16;
const UNRELATED_AUTHORIZATION_DEADLINE: Duration = Duration::from_millis(250);
const PROXY_IO_DEADLINE: Duration = Duration::from_secs(5);

#[derive(Clone)]
struct ProxyControl {
    hold_eval: Arc<AtomicBool>,
    eval_seen: Arc<Notify>,
    release_eval: Arc<Notify>,
}

impl ProxyControl {
    fn new() -> Self {
        Self {
            hold_eval: Arc::new(AtomicBool::new(false)),
            eval_seen: Arc::new(Notify::new()),
            release_eval: Arc::new(Notify::new()),
        }
    }

    fn arm_eval(&self) {
        self.hold_eval.store(true, Ordering::Release);
    }

    async fn wait_eval(&self) -> Result<(), &'static str> {
        timeout(Duration::from_secs(5), self.eval_seen.notified())
            .await
            .map(|_| ())
            .map_err(|_| "proxy did not observe EVAL")
    }

    fn release_eval(&self) {
        self.release_eval.notify_one();
    }
}

struct LoopbackProxy {
    url: String,
    control: ProxyControl,
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<()>>,
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
            task: Some(task),
        }
    }

    async fn shutdown(mut self) -> Result<(), String> {
        if let Some(stop) = self.stop.take() {
            let _ = stop.send(());
        }
        let Some(mut task) = self.task.take() else {
            return Ok(());
        };
        match timeout(Duration::from_secs(5), &mut task).await {
            Ok(Ok(())) => Ok(()),
            Ok(Err(error)) => Err(format!("Redis proxy task failed: {error}")),
            Err(_) => {
                task.abort();
                let _ = task.await;
                Err("Redis proxy shutdown deadline".to_owned())
            }
        }
    }
}

fn upstream_address(url: &str) -> String {
    let info = url
        .into_connection_info()
        .expect("parse Redis URL for authorization proxy");
    // The proxy reconnects to the upstream with a raw TCP stream and exposes
    // a loopback URL to the catalog client.  Do not silently discard an ACL
    // credential or select a different database in that translation: this
    // deterministic fixture only accepts the unauthenticated database-0
    // shape.  The assertion deliberately contains no URL or secret.
    let settings = info.redis_settings();
    assert!(
        settings.username().is_none() && settings.password().is_none() && settings.db() == 0,
        "deterministic authorization proxy requires an unauthenticated Redis database 0 URL"
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
            panic!("deterministic authorization proxy requires a plaintext Redis URL")
        }
        redis::ConnectionAddr::Unix(path) => {
            panic!("deterministic authorization proxy does not support Unix Redis socket {path:?}")
        }
        _ => panic!("unsupported Redis address for deterministic authorization proxy"),
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
        if command.as_deref() == Some("EVAL") && control.hold_eval.swap(false, Ordering::AcqRel) {
            control.eval_seen.notify_one();
            let _ = timeout(PROXY_IO_DEADLINE, control.release_eval.notified()).await;
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

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, Uuid, Uuid, Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device_a = Uuid::new_v4();
    let device_b = Uuid::new_v4();
    let service_a = Uuid::new_v4();
    let service_b = Uuid::new_v4();
    let now = Utc::now();
    let credential = |device_id: Uuid, serial: &str| CredentialRecord {
        tenant_id: tenant,
        device_id,
        credential_id: Uuid::new_v4(),
        spki_fingerprint: format!("{:064x}", device_id.as_u128()),
        serial: Some(serial.to_owned()),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::hours(1),
        revoked_at: None,
        active: true,
    };
    let service = |device_id: Uuid, service_id: Uuid, name: &str| ServiceSpec {
        tenant_id: tenant,
        device_id,
        service_id,
        service_type: "echo".to_owned(),
        display_name: name.to_owned(),
        capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
        version: 1,
        active: true,
    };
    let grant = |device_id: Uuid, service_id: Uuid| GrantSpec {
        tenant_id: tenant,
        principal_id: user,
        device_id,
        service_id,
        permissions: PermissionSet {
            operations: BTreeSet::from(["echo:invoke".to_owned()]),
        },
        constraints: serde_json::json!({"max_bytes": 4096}),
        expires_at: Some(now + ChronoDuration::hours(1)),
        active: true,
    };
    (
        CatalogFixture {
            tenants: vec![TenantRecord {
                tenant_id: tenant,
                display_name: "authorization lane tenant".to_owned(),
                active: true,
            }],
            users: vec![UserRecord {
                user_id: user,
                display_name: "authorization lane user".to_owned(),
            }],
            identities: vec![PrincipalIdentity {
                issuer: "https://issuer.authorization-lane.invalid".to_owned(),
                subject: format!("authorization-lane-subject-{user}"),
                user_id: user,
            }],
            memberships: vec![MembershipRecord {
                tenant_id: tenant,
                user_id: user,
                role: MembershipRole::Member,
                active: true,
            }],
            devices: vec![
                FixtureDevice {
                    tenant_id: tenant,
                    device_id: device_a,
                    owner_user_id: user,
                    display_name: "authorization lane device A".to_owned(),
                    active: true,
                    last_seen_at: Some(now),
                },
                FixtureDevice {
                    tenant_id: tenant,
                    device_id: device_b,
                    owner_user_id: user,
                    display_name: "authorization lane device B".to_owned(),
                    active: true,
                    last_seen_at: Some(now),
                },
            ],
            credentials: vec![
                credential(device_a, "authorization-lane-a"),
                credential(device_b, "authorization-lane-b"),
            ],
            services: vec![
                service(device_a, service_a, "authorization lane service A"),
                service(device_b, service_b, "authorization lane service B"),
            ],
            grants: vec![grant(device_a, service_a), grant(device_b, service_b)],
        },
        tenant,
        user,
        device_a,
        service_a,
        device_b,
        service_b,
    )
}

fn catalog_error_category(error: &CatalogError) -> &'static str {
    match error {
        CatalogError::Database(_) => "database",
        CatalogError::WriteOutcomeUnknown(_) => "write_outcome_unknown",
        CatalogError::InvalidInput(_) => "invalid_input",
        CatalogError::NotFound => "not_found",
        CatalogError::Unauthorized => "unauthorized",
        CatalogError::Conflict(_) => "conflict",
        CatalogError::OwnerBusy => "owner_busy",
        CatalogError::StaleOwner => "stale_owner",
        CatalogError::InvalidOwner => "invalid_owner",
        CatalogError::RevisionOverflow => "revision_overflow",
        CatalogError::Serialization(_) => "serialization",
    }
}

async fn finish_authorization_task<T: Send + 'static>(
    mut task: JoinHandle<T>,
    label: &str,
) -> Result<T, String> {
    match timeout(Duration::from_secs(3), &mut task).await {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(format!("{label} task failed: {error}")),
        Err(_) => {
            task.abort();
            match timeout(Duration::from_secs(3), task).await {
                Ok(Ok(_)) => Err(format!("{label} task exceeded its deadline")),
                Ok(Err(error)) => Err(format!("{label} task cancelled: {error}")),
                Err(_) => Err(format!("{label} task abort join exceeded its deadline")),
            }
        }
    }
}

async fn run_authorization_lane_scenario(
    catalog: &RedisCatalog,
    proxy: &LoopbackProxy,
) -> Result<(), String> {
    catalog
        .activate_deployment_incarnation()
        .await
        .map_err(|error| format!("activate authorization concurrency fixture: {error}"))?;
    let (fixture, tenant, user, device_a, service_a, device_b, service_b) = fixture_values();
    catalog
        .seed_fixture(&fixture)
        .await
        .map_err(|error| format!("seed authorization concurrency fixture: {error}"))?;

    let principal = tunnel_catalog::AuthenticatedConsumer {
        tenant_id: tenant,
        principal_id: user,
    };
    let baseline_at = Utc::now();
    let baseline = catalog
        .authorize(&principal, device_a, service_a, baseline_at, baseline_at)
        .await
        .map_err(|error| {
            format!(
                "fixture precondition: unheld authorization category {}",
                catalog_error_category(&error)
            )
        })?;
    match baseline {
        Some(snapshot) if snapshot.device_id == device_a => {}
        Some(_) => {
            return Err("fixture precondition: unheld authorization device mismatch".to_owned());
        }
        None => {
            return Err("fixture precondition: unheld authorization returned no grant".to_owned());
        }
    }
    let first_catalog = catalog.clone();
    let first_principal = principal.clone();
    proxy.control.arm_eval();
    let first = tokio::spawn(async move {
        let at = Utc::now();
        first_catalog
            .authorize(&first_principal, device_a, service_a, at, at)
            .await
    });

    if let Err(error) = proxy.control.wait_eval().await {
        proxy.control.release_eval();
        let first_cleanup = finish_authorization_task(first, "held authorization").await;
        return Err(match first_cleanup {
            Ok(_) => error.to_owned(),
            Err(cleanup) => format!("{error}; {cleanup}"),
        });
    }

    let owner_catalog = catalog.clone();
    let mut owner_read = tokio::spawn(async move {
        owner_catalog
            .current_owner(tenant, device_a, Utc::now())
            .await
    });
    let second_catalog = catalog.clone();
    let second_principal = principal.clone();
    let mut second = tokio::spawn(async move {
        let at = Utc::now();
        second_catalog
            .authorize(&second_principal, device_b, service_b, at, at)
            .await
    });
    let observation_deadline = Instant::now() + UNRELATED_AUTHORIZATION_DEADLINE;
    let owner_wait = timeout_at(observation_deadline, &mut owner_read).await;
    let second_wait = timeout_at(observation_deadline, &mut second).await;

    // Release the held physical lane before joining either task. This keeps
    // the proxy and every authorization handle joinable on both pass and
    // failure paths.
    proxy.control.release_eval();
    let first_result = finish_authorization_task(first, "held authorization").await;
    let owner_result = match owner_wait {
        Ok(Ok(owner)) => owner.map_err(|error| {
            format!(
                "base connection owner read category {}",
                catalog_error_category(&error)
            )
        }),
        Ok(Err(error)) => Err(format!("base connection owner read task failed: {error}")),
        Err(_) => {
            owner_read.abort();
            let cleanup = timeout(Duration::from_secs(3), owner_read).await;
            let mut diagnostic =
                "base connection owner read did not complete while the first EVAL reply was held"
                    .to_owned();
            match cleanup {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    diagnostic.push_str(&format!("; cleanup join: {error}"));
                }
                Err(_) => {
                    diagnostic.push_str("; cleanup abort join exceeded its deadline");
                }
            }
            Err(diagnostic)
        }
    };
    let second_result = match second_wait {
        Ok(Ok(authorization)) => authorization.map_err(|error| {
            format!(
                "unrelated authorization category {}",
                catalog_error_category(&error)
            )
        }),
        Ok(Err(error)) => Err(format!("unrelated authorization task failed: {error}")),
        Err(_) => {
            second.abort();
            let cleanup = timeout(Duration::from_secs(3), second).await;
            let mut diagnostic =
                "unrelated authorization did not complete while the first EVAL reply was held"
                    .to_owned();
            match cleanup {
                Ok(Ok(_)) => {}
                Ok(Err(error)) => {
                    diagnostic.push_str(&format!("; cleanup join: {error}"));
                }
                Err(_) => {
                    diagnostic.push_str("; cleanup abort join exceeded its deadline");
                }
            };
            Err(diagnostic)
        }
    };

    let mut failures = Vec::new();
    let held_authorization_succeeded = match first_result {
        Ok(Ok(Some(snapshot))) if snapshot.device_id == device_a => true,
        Ok(Ok(Some(snapshot))) => {
            failures.push(format!(
                "fixture precondition: held authorization returned unexpected device {}",
                snapshot.device_id
            ));
            false
        }
        Ok(Ok(None)) => {
            failures.push("fixture precondition: held authorization returned no grant".to_owned());
            false
        }
        Ok(Err(error)) => {
            failures.push(format!(
                "fixture precondition: held authorization category {}",
                catalog_error_category(&error)
            ));
            false
        }
        Err(error) => {
            failures.push(format!("fixture precondition: {error}"));
            false
        }
    };
    if !held_authorization_succeeded {
        failures.push(
            "unrelated authorization observation is inconclusive because the held fixture authorization failed"
                .to_owned(),
        );
    } else {
        match owner_result {
            Ok(None) => {}
            Ok(Some(_)) => {
                failures.push("base connection owner read returned an unexpected owner".to_owned())
            }
            Err(error) => failures.push(error),
        }
        match second_result {
            Ok(Some(snapshot)) if snapshot.device_id == device_b => {}
            Ok(Some(snapshot)) => failures.push(format!(
                "unrelated authorization returned unexpected device {}",
                snapshot.device_id
            )),
            Ok(None) => failures.push("unrelated authorization returned no grant".to_owned()),
            Err(error) => failures.push(error),
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(failures.join("; "))
    }
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn authorization_evals_do_not_head_of_line_block_unrelated_reads() {
    let upstream_url = std::env::var("TUNNEL_CATALOG_REDIS_URL")
        .expect("authorization concurrency test requires TUNNEL_CATALOG_REDIS_URL");
    let proxy = LoopbackProxy::start(&upstream_url).await;
    let namespace = format!("test-authorize-lane-{}", Uuid::new_v4());
    let catalog =
        match RedisCatalog::connect_for_recovery(&proxy.url, &namespace, INCARNATION).await {
            Ok(catalog) => catalog,
            Err(error) => {
                let proxy_shutdown = proxy.shutdown().await;
                let shutdown_error = match proxy_shutdown {
                    Ok(()) => String::new(),
                    Err(shutdown) => format!("; proxy cleanup: {shutdown}"),
                };
                panic!("connect authorization concurrency catalog: {error}{shutdown_error}");
            }
        };
    let scenario = run_authorization_lane_scenario(&catalog, &proxy).await;
    proxy.control.release_eval();
    let cleanup = timeout(Duration::from_secs(5), catalog.cleanup_fixture_namespace())
        .await
        .map_err(|_| "catalog fixture cleanup deadline".to_owned())
        .and_then(|result| result.map_err(|error| format!("catalog fixture cleanup: {error}")));
    let proxy_shutdown = proxy.shutdown().await;

    let mut failures = Vec::new();
    if let Err(error) = scenario {
        failures.push(format!("scenario: {error}"));
    }
    if let Err(error) = cleanup {
        failures.push(error);
    }
    if let Err(error) = proxy_shutdown {
        failures.push(error);
    }
    assert!(
        failures.is_empty(),
        "authorization lane regression: {}",
        failures.join("; ")
    );
}
