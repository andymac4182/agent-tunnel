//! Redis-backed recovery workflow tests.
//!
//! These executable integration tests call the public `recover` workflow
//! instead of duplicating its ordering. The Redis fixture is operator supplied
//! and every test uses a fresh fixture namespace and owner-private temporary
//! control directory.
//!
//! Enable with `TUNNEL_CATALOG_REDIS_URL` set to an unauthenticated plaintext
//! database-0 Redis URL.  The bounded loopback proxy holds a selected RESP
//! `EXEC` *response after reading it from Redis*.  That distinction proves
//! Redis applied the command before the client sees a delayed or dropped
//! response.  The ignored binary workflow terminates a synthetic TLS listener
//! and forwards to that same Redis authority; it does not use a fake catalog.

use std::{
    collections::BTreeSet,
    future::Future,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Notify, oneshot},
    task::{JoinHandle, JoinSet},
    time::{sleep, timeout},
};
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, OwnerClaimRequest, PrincipalIdentity, RecoveryApproval, RecoveryApprovalIssuer,
    RedisCatalog, ServiceSpec, TenantRecord, UserRecord,
};
use tunnel_relay::{
    recovery::{
        QuiescenceAcknowledgement, RecoverRequest, RecoveryApprovalVersionStore,
        RecoveryFenceIdentity, RecoveryWorkflowConfig, RecoveryWorkflowError, recover,
        recovery_observe,
    },
    redis_connection::RedisTlsMaterialPaths,
};
use uuid::Uuid;

#[path = "common/recovery_redis.rs"]
mod recovery_redis;

const DEPLOYMENT_ID: &str = "m7-recovery-workflow-deployment";
const INITIAL_INCARC: &str = "m7-recovery-workflow-initial";
const CANDIDATE_INCARC: &str = "m7-recovery-workflow-candidate";
const ALREADY_ACTIVE_INCARC: &str = "m7-recovery-workflow-already-active";
const EXPECTED_NONCE: &str = "m7-recovery-workflow-nonce-0001";
const MAX_RESP_FRAME: usize = 8 * 1024 * 1024;
const MAX_RESP_ITEMS: usize = 16_384;

#[derive(Clone)]
struct ProxyControl {
    exec_count: Arc<AtomicU64>,
    hold_exec_response_at: Arc<AtomicU64>,
    exec_response_seen: Arc<Notify>,
    release_exec_response: Arc<Notify>,
}

impl ProxyControl {
    fn new() -> Self {
        Self {
            exec_count: Arc::new(AtomicU64::new(0)),
            hold_exec_response_at: Arc::new(AtomicU64::new(0)),
            exec_response_seen: Arc::new(Notify::new()),
            release_exec_response: Arc::new(Notify::new()),
        }
    }

    fn current_exec_count(&self) -> u64 {
        self.exec_count.load(Ordering::Acquire)
    }

    fn arm_exec_response_at(&self, count: u64) {
        assert!(count > 0, "EXEC response sequence is one-based");
        self.hold_exec_response_at.store(count, Ordering::Release);
    }

    async fn wait_exec_response(&self) -> Result<(), &'static str> {
        timeout(Duration::from_secs(5), self.exec_response_seen.notified())
            .await
            .map(|_| ())
            .map_err(|_| "proxy did not observe the selected EXEC response")
    }

    fn release_exec_response(&self) {
        self.release_exec_response.notify_one();
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
            .expect("bind Redis recovery proxy");
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
            Ok(result) => result.expect("Redis recovery proxy task"),
            Err(_) => {
                task.abort();
                let _ = task.await;
                panic!("Redis recovery proxy shutdown deadline");
            }
        }
    }
}

fn upstream_address(url: &str) -> String {
    let rest = url
        .strip_prefix("redis://")
        .expect("staged recovery proxy requires redis://");
    assert!(
        !rest.contains('@'),
        "staged recovery proxy requires an unauthenticated Redis URL"
    );
    let authority = rest.split('/').next().expect("Redis authority");
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once(']')
            .and_then(|(host, remainder)| remainder.strip_prefix(':').map(|port| (host, port)))
            .unwrap_or((bracketed.trim_end_matches(']'), "6379"));
        format!("[{host}]:{port}")
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        format!("{host}:{port}")
    } else {
        format!("{authority}:6379")
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
        if server.write_all(&request).await.is_err() {
            return;
        }
        let response = match read_resp_frame(&mut server).await {
            Ok(response) => response,
            Err(_) => return,
        };

        if command.as_deref() == Some("EXEC") {
            let sequence = control.exec_count.fetch_add(1, Ordering::AcqRel) + 1;
            let target = control.hold_exec_response_at.load(Ordering::Acquire);
            if target == sequence
                && control
                    .hold_exec_response_at
                    .compare_exchange(target, 0, Ordering::AcqRel, Ordering::Acquire)
                    .is_ok()
            {
                // The upstream response was already read. Redis has applied
                // the transaction even though the client is still blocked.
                control.exec_response_seen.notify_one();
                control.release_exec_response.notified().await;
            }
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

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agent-tunnel-recovery-workflow-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir(&path).expect("create recovery control directory");
        let path = std::fs::canonicalize(path).expect("canonicalize recovery control directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("private recovery control directory");
        }
        Self(path)
    }

    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }

    fn fence(&self) -> PathBuf {
        self.path("recovery-fence.json")
    }

    fn approval(&self) -> PathBuf {
        self.path("approval.json")
    }

    fn trusted_keys(&self) -> PathBuf {
        self.path("trusted-keys.json")
    }

    #[cfg(unix)]
    fn set_mode(&self, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&self.0, std::fs::Permissions::from_mode(mode))
            .expect("set recovery control directory mode");
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

struct Fixture {
    upstream_url: String,
    namespace: String,
    tenant: Uuid,
    device: Uuid,
    credential_spki_fingerprint: String,
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    let fixture = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "recovery workflow tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "recovery workflow user".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.recovery-workflow.invalid".to_owned(),
            subject: format!("recovery-workflow-subject-{user}"),
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
            display_name: "recovery workflow device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
                .to_owned(),
            serial: Some("recovery-workflow-credential".to_owned()),
            not_before: now - ChronoDuration::seconds(1),
            expires_at: now + ChronoDuration::hours(1),
            revoked_at: None,
            active: true,
        }],
        services: vec![ServiceSpec {
            tenant_id: tenant,
            device_id: device,
            service_id: service,
            service_type: "echo".to_owned(),
            display_name: "recovery workflow echo".to_owned(),
            capabilities: serde_json::json!({"operations": ["echo:invoke"]}),
            version: 1,
            active: true,
        }],
        grants: vec![GrantSpec {
            tenant_id: tenant,
            principal_id: user,
            device_id: device,
            service_id: service,
            permissions: tunnel_catalog::PermissionSet {
                operations: BTreeSet::from(["echo:invoke".to_owned()]),
            },
            constraints: serde_json::json!({"max_bytes": 4096}),
            expires_at: Some(now + ChronoDuration::hours(1)),
            active: true,
        }],
    };
    (fixture, tenant, device)
}

async fn fixture(upstream_url: &str, connection_url: &str) -> Fixture {
    let namespace = format!("test-recovery-workflow-{}", Uuid::new_v4().simple());
    let (records, tenant, device) = fixture_values();
    let credential_spki_fingerprint = records
        .credentials
        .first()
        .expect("recovery fixture credential")
        .spki_fingerprint
        .clone();
    let catalog = RedisCatalog::connect_for_recovery(connection_url, &namespace, INITIAL_INCARC)
        .await
        .expect("connect recovery workflow catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate recovery workflow fixture");
    catalog
        .seed_fixture(&records)
        .await
        .expect("seed recovery workflow fixture");
    Fixture {
        upstream_url: upstream_url.to_owned(),
        namespace,
        tenant,
        device,
        credential_spki_fingerprint,
    }
}

async fn cleanup(fixture: &Fixture) {
    let catalog = RedisCatalog::connect_for_recovery(
        &fixture.upstream_url,
        &fixture.namespace,
        "cleanup-incarnation",
    )
    .await
    .expect("connect recovery cleanup catalog");
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup recovery workflow namespace");
}

async fn active_is(fixture: &Fixture, incarnation: &str) -> bool {
    RedisCatalog::connect_with_deployment_incarnation(
        &fixture.upstream_url,
        &fixture.namespace,
        incarnation,
    )
    .await
    .is_ok()
}

fn workflow_config(
    connection_url: &str,
    fixture: &Fixture,
    directory: &TestDirectory,
    incarnation: &str,
) -> RecoveryWorkflowConfig {
    RecoveryWorkflowConfig::new(
        connection_url,
        DEPLOYMENT_ID,
        &fixture.namespace,
        incarnation,
        directory.fence(),
        directory.trusted_keys(),
        RedisTlsMaterialPaths::default(),
    )
    .expect("recovery workflow configuration")
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write private recovery file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private recovery file mode");
    }
}

fn write_approval(
    directory: &TestDirectory,
    fixture: &Fixture,
    redis_run_id: &str,
    catalog_digest: &str,
    incarnation: &str,
    approval_version: u64,
) -> RecoverRequest {
    let (issuer, _) =
        RecoveryApprovalIssuer::generate("m7-recovery-workflow-operator").expect("issuer");
    let public_key = issuer.public_key().expect("operator public key");
    let public_key = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let trusted_document = serde_json::json!({
        "schema_version": 1,
        "keys": [{
            "key_id": "m7-recovery-workflow-operator",
            "public_key": public_key,
        }]
    });
    write_private_file(
        &directory.trusted_keys(),
        &serde_json::to_vec(&trusted_document).expect("trusted public key JSON"),
    );

    let now = Utc::now();
    let approval = RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: redis_run_id.to_owned(),
        deployment_incarnation: incarnation.to_owned(),
        approval_version,
        nonce: EXPECTED_NONCE.to_owned(),
        catalog_digest: catalog_digest.to_owned(),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let bytes = issuer
        .sign_approval_bytes(approval)
        .expect("signed recovery approval");
    write_private_file(&directory.approval(), &bytes);

    RecoverRequest {
        expected_nonce: EXPECTED_NONCE.to_owned(),
        approval_path: directory.approval(),
        quiescence: QuiescenceAcknowledgement::new(
            "m7-recovery-workflow-operator-declaration",
            true,
            true,
        )
        .expect("quiescence acknowledgement"),
    }
}

fn bootstrap_fence(directory: &TestDirectory, fixture: &Fixture) {
    let identity = RecoveryFenceIdentity::new(DEPLOYMENT_ID, &fixture.namespace)
        .expect("recovery fence identity");
    RecoveryApprovalVersionStore::bootstrap(directory.fence(), identity)
        .expect("explicit recovery fence bootstrap");
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn persistence_failure_after_observation_refuses_activation() {
    let upstream_url =
        std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery workflow Redis URL");
    let proxy = LoopbackProxy::start(&upstream_url).await;
    let fixture = fixture(&upstream_url, &proxy.url).await;
    let directory = TestDirectory::new();
    bootstrap_fence(&directory, &fixture);
    let config = workflow_config(&proxy.url, &fixture, &directory, CANDIDATE_INCARC);
    let observation = recovery_observe(&config)
        .await
        .expect("observe catalog before persistence-failure test");
    let request = write_approval(
        &directory,
        &fixture,
        &observation.redis_run_id,
        &observation.catalog_digest,
        CANDIDATE_INCARC,
        1,
    );

    // `recover` performs one observation EXEC before its local persistence
    // phase. Hold that response only after Redis has replied, then make the
    // private parent mode invalid. The activation API must never be reached.
    proxy
        .control
        .arm_exec_response_at(proxy.control.current_exec_count() + 1);
    let task_config = config.clone();
    let task_request = request.clone();
    let task = tokio::spawn(async move { recover(&task_config, &task_request).await });
    proxy
        .control
        .wait_exec_response()
        .await
        .expect("recover observation response held");
    #[cfg(unix)]
    directory.set_mode(0o750);
    proxy.control.release_exec_response();
    let result = timeout(Duration::from_secs(5), task)
        .await
        .expect("persistence-failure workflow deadline")
        .expect("persistence-failure workflow task")
        .expect_err("insecure parent must refuse persistence");
    assert_eq!(
        result,
        RecoveryWorkflowError::Fence(
            tunnel_relay::recovery::RecoveryFenceStoreError::ParentDirectoryNotPrivate
        )
    );
    #[cfg(unix)]
    directory.set_mode(0o700);

    assert!(active_is(&fixture, INITIAL_INCARC).await);
    assert!(!active_is(&fixture, CANDIDATE_INCARC).await);
    let store = RecoveryApprovalVersionStore::open(
        directory.fence(),
        RecoveryFenceIdentity::new(DEPLOYMENT_ID, &fixture.namespace).expect("identity"),
    )
    .expect("inspect unchanged fence");
    assert_eq!(
        store
            .load()
            .expect("unchanged fence state")
            .highest_approval_version,
        None
    );
    drop(store);
    cleanup(&fixture).await;
    proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn unknown_activation_response_is_ambiguous_after_redis_commit_and_consumes_version() {
    let upstream_url =
        std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery workflow Redis URL");
    let proxy = LoopbackProxy::start(&upstream_url).await;
    let fixture = fixture(&upstream_url, &proxy.url).await;
    let directory = TestDirectory::new();
    bootstrap_fence(&directory, &fixture);
    let config = workflow_config(&proxy.url, &fixture, &directory, CANDIDATE_INCARC);
    let observation = recovery_observe(&config)
        .await
        .expect("observe catalog before unknown-outcome test");
    let request = write_approval(
        &directory,
        &fixture,
        &observation.redis_run_id,
        &observation.catalog_digest,
        CANDIDATE_INCARC,
        1,
    );

    // The preliminary recovery observation consumes one more EXEC. The next
    // EXEC is the approval-gated activation. Hold its response after Redis
    // applied the Lua transition, then let the catalog deadline classify the
    // result as unknown rather than allowing the response to arrive in time.
    proxy
        .control
        .arm_exec_response_at(proxy.control.current_exec_count() + 2);
    let task_config = config.clone();
    let task_request = request.clone();
    let task = tokio::spawn(async move { recover(&task_config, &task_request).await });
    proxy
        .control
        .wait_exec_response()
        .await
        .expect("activation response held after Redis commit");
    assert!(active_is(&fixture, CANDIDATE_INCARC).await);
    assert!(!active_is(&fixture, INITIAL_INCARC).await);

    // Release after the catalog's ten-second activation deadline has expired;
    // this allows its bounded UNWATCH cleanup to complete without converting
    // the held response into a successful activation return.
    let release_control = proxy.control.clone();
    let release_task = tokio::spawn(async move {
        sleep(Duration::from_secs(11)).await;
        release_control.release_exec_response();
    });
    let result = timeout(Duration::from_secs(15), task)
        .await
        .expect("unknown-outcome workflow deadline")
        .expect("unknown-outcome workflow task")
        .expect_err("held activation response must be ambiguous");
    assert_eq!(result, RecoveryWorkflowError::ActivationOutcomeUnknown);
    let _ = release_task.await;

    let store = RecoveryApprovalVersionStore::open(
        directory.fence(),
        RecoveryFenceIdentity::new(DEPLOYMENT_ID, &fixture.namespace).expect("identity"),
    )
    .expect("inspect consumed recovery fence");
    assert_eq!(
        store
            .load()
            .expect("consumed fence state")
            .highest_approval_version,
        Some(1)
    );
    drop(store);

    // A restart/retry with the same signed approval is rejected locally before
    // any second activation attempt. The Redis readback remains the candidate
    // incarnation that was already committed behind the unknown response.
    let mut retry_config = config.clone();
    retry_config.redis_url = fixture.upstream_url.clone();
    assert_eq!(
        recover(&retry_config, &request)
            .await
            .expect_err("same approval must not retry"),
        RecoveryWorkflowError::ApprovalRejected
    );
    assert!(active_is(&fixture, CANDIDATE_INCARC).await);
    cleanup(&fixture).await;
    proxy.shutdown().await;
}

#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn activation_failure_consumes_version_and_rejects_replay() {
    let upstream_url =
        std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery workflow Redis URL");
    let fixture = fixture(&upstream_url, &upstream_url).await;
    let already_active = RedisCatalog::connect_for_recovery(
        &upstream_url,
        &fixture.namespace,
        ALREADY_ACTIVE_INCARC,
    )
    .await
    .expect("connect already-active fixture catalog");
    already_active
        .activate_deployment_incarnation()
        .await
        .expect("activate already-active fixture incarnation");

    let directory = TestDirectory::new();
    bootstrap_fence(&directory, &fixture);
    let config = workflow_config(&upstream_url, &fixture, &directory, CANDIDATE_INCARC);

    // Claim a real owner lease before observing/signing. The owner claim
    // advances durable coordination state, which must be covered by the
    // approval digest; activation will still reject the candidate while this
    // live lease remains present.
    already_active
        .claim_owner(&OwnerClaimRequest {
            deployment_incarnation: ALREADY_ACTIVE_INCARC.to_owned(),
            tenant_id: fixture.tenant,
            device_id: fixture.device,
            node_id: "live-recovery-workflow-owner".to_owned(),
            boot_id: "live-recovery-workflow-boot".to_owned(),
            session_id: "live-recovery-workflow-session".to_owned(),
            lease_expires_at: Utc::now() + ChronoDuration::seconds(10),
        })
        .await
        .expect("claim live recovery workflow owner");

    let observation = recovery_observe(&config)
        .await
        .expect("observe catalog before activation-failure test");
    let request = write_approval(
        &directory,
        &fixture,
        &observation.redis_run_id,
        &observation.catalog_digest,
        CANDIDATE_INCARC,
        1,
    );

    assert_eq!(
        recover(&config, &request)
            .await
            .expect_err("live owner must refuse activation"),
        RecoveryWorkflowError::ActivationFailed
    );
    assert!(active_is(&fixture, ALREADY_ACTIVE_INCARC).await);

    let store = RecoveryApprovalVersionStore::open(
        directory.fence(),
        RecoveryFenceIdentity::new(DEPLOYMENT_ID, &fixture.namespace).expect("identity"),
    )
    .expect("inspect consumed activation-failure fence");
    assert_eq!(
        store
            .load()
            .expect("activation-failure fence state")
            .highest_approval_version,
        Some(1)
    );
    drop(store);
    assert_eq!(
        recover(&config, &request)
            .await
            .expect_err("same approval must be rejected after activation failure"),
        RecoveryWorkflowError::ApprovalRejected
    );
    cleanup(&fixture).await;
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("quote recovery CLI TOML string")
}

fn toml_path(path: &Path) -> String {
    toml_string(
        path.to_str()
            .expect("recovery CLI fixture path should be valid UTF-8"),
    )
}

fn write_cli_config(
    directory: &TestDirectory,
    fixture: &Fixture,
    redis_url: &str,
    redis_root_ca: &Path,
) -> PathBuf {
    let path = directory.path("relay.toml");
    let text = format!(
        "oidc_issuer = \"https://issuer.recovery-workflow.invalid\"\noidc_audience = [\"recovery-cli-test\"]\noidc_jwks_path = {}\nredis_url = {}\nredis_tls_root_ca_path = {}\nredis_namespace = {}\ndevice_tls_cert_chain = {}\ndevice_tls_private_key = {}\ndevice_tls_client_ca = {}\nconsumer_tls_cert_chain = {}\nconsumer_tls_private_key = {}\nnode_id = \"recovery-cli-test-node\"\ndeployment_incarnation = {}\n\n[cluster]\ndeployment_id = {}\npeer_bind = \"127.0.0.1:1\"\npeer_tls_cert_chain = {}\npeer_tls_private_key = {}\npeer_tls_client_ca = {}\nmembership_signer_trust_path = {}\ncheckpoint_authority_endpoint = \"https://checkpoint.recovery-workflow.invalid\"\ncheckpoint_authority_trust_path = {}\nmembership_version_state_path = {}\n\n[recovery]\nfence_path = {}\ntrusted_keys_path = {}\ndeployment_incarnation = {}\n",
        toml_path(&directory.path("unused-jwks.json")),
        toml_string(redis_url),
        toml_path(redis_root_ca),
        toml_string(&fixture.namespace),
        toml_path(&directory.path("unused-device-cert.pem")),
        toml_path(&directory.path("unused-device-key.pem")),
        toml_path(&directory.path("unused-device-ca.pem")),
        toml_path(&directory.path("unused-consumer-cert.pem")),
        toml_path(&directory.path("unused-consumer-key.pem")),
        toml_string(INITIAL_INCARC),
        toml_string(DEPLOYMENT_ID),
        toml_path(&directory.path("unused-peer-cert.pem")),
        toml_path(&directory.path("unused-peer-key.pem")),
        toml_path(&directory.path("unused-peer-ca.pem")),
        toml_path(&directory.path("unused-membership-trust.json")),
        toml_path(&directory.path("unused-checkpoint-ca.pem")),
        toml_path(&directory.path("unused-membership-state.json")),
        toml_path(&directory.fence()),
        toml_path(&directory.trusted_keys()),
        toml_string(CANDIDATE_INCARC),
    );
    write_private_file(&path, text.as_bytes());
    path
}

async fn run_relay_cli(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tunnel-relay"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tunnel-relay recovery CLI");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) if Instant::now() < deadline => {
                sleep(Duration::from_millis(20)).await;
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("tunnel-relay recovery CLI exceeded its bounded test deadline");
            }
            Err(error) => {
                let _ = child.kill();
                let _ = child.wait_with_output();
                panic!("poll tunnel-relay recovery CLI: {error}");
            }
        }
    }
    child
        .wait_with_output()
        .expect("join tunnel-relay recovery CLI")
}

fn parse_cli_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "recovery CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        output.stderr.is_empty(),
        "successful JSON recovery CLI output wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().count(),
        1,
        "recovery CLI JSON must contain one object: {stdout}"
    );
    serde_json::from_str(stdout.trim()).expect("parse recovery CLI JSON")
}

fn assert_cli_redacted(output: &Output, directory: &TestDirectory) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let private_directory = directory.0.to_string_lossy();
    for marker in [
        "redis://",
        "m7-recovery-workflow-operator",
        "BEGIN PRIVATE",
        "BEGIN CERTIFICATE",
    ] {
        assert!(!stdout.contains(marker), "recovery CLI leaked {marker:?}");
    }
    assert!(
        !stdout.contains(private_directory.as_ref()),
        "recovery CLI leaked a private control path"
    );
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn cli_recovery_promotes_fresh_incarnation_and_rejects_approval_replay() {
    let upstream_url =
        std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("recovery workflow Redis URL");
    let fixture = fixture(&upstream_url, &upstream_url).await;
    let directory = TestDirectory::new();
    let tls_forwarder = recovery_redis::RedisTlsForwarder::start(
        &upstream_url,
        directory.path("redis-forwarder-ca.pem"),
    )
    .await;
    let config = write_cli_config(
        &directory,
        &fixture,
        &tls_forwarder.url,
        &tls_forwarder.root_ca,
    );

    // Preserve a durable revocation in the catalog before the replacement is
    // approved. The candidate must inherit this state after activation.
    let catalog = RedisCatalog::connect_with_deployment_incarnation(
        &fixture.upstream_url,
        &fixture.namespace,
        INITIAL_INCARC,
    )
    .await
    .expect("connect active recovery fixture catalog");
    catalog
        .revoke_device(fixture.tenant, fixture.device, Utc::now())
        .await
        .expect("revoke recovery fixture device before replacement");

    let initialize = run_relay_cli(&[
        "recovery-initialize",
        "--config",
        config.to_str().expect("recovery config path"),
    ])
    .await;
    assert!(
        initialize.status.success(),
        "recovery-initialize failed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );
    assert!(
        String::from_utf8_lossy(&initialize.stdout).contains("Initialized recovery approval fence")
    );

    let initialize_again = run_relay_cli(&[
        "recovery-initialize",
        "--config",
        config.to_str().expect("recovery config path"),
    ])
    .await;
    assert!(!initialize_again.status.success());
    assert!(
        String::from_utf8_lossy(&initialize_again.stderr)
            .contains("recovery approval fence already exists")
    );

    let observation_output = run_relay_cli(&[
        "recovery-observe",
        "--config",
        config.to_str().expect("recovery config path"),
    ])
    .await;
    let observation_json = parse_cli_json(&observation_output);
    assert_eq!(observation_json["deployment_id"], DEPLOYMENT_ID);
    assert_eq!(observation_json["redis_namespace"], fixture.namespace);
    assert_eq!(observation_json["deployment_incarnation"], CANDIDATE_INCARC);
    assert_eq!(observation_json["quiescence"], "unproven");
    assert_cli_redacted(&observation_output, &directory);
    let redis_run_id = observation_json["redis_run_id"]
        .as_str()
        .expect("observation Redis run ID")
        .to_owned();
    let catalog_digest = observation_json["catalog_digest"]
        .as_str()
        .expect("observation catalog digest")
        .to_owned();
    let request = write_approval(
        &directory,
        &fixture,
        &redis_run_id,
        &catalog_digest,
        CANDIDATE_INCARC,
        1,
    );

    // The CLI must require the explicit old-primary and old-relay fencing
    // declaration before it reads the approval or reaches Redis activation.
    let missing_quiescence = run_relay_cli(&[
        "recover",
        "--config",
        config.to_str().expect("recovery config path"),
        "--approval",
        request.approval_path.to_str().expect("approval path"),
        "--expected-nonce",
        EXPECTED_NONCE,
        "--acknowledgement-id",
        "m7-recovery-workflow-operator-declaration",
    ])
    .await;
    assert!(!missing_quiescence.status.success());
    assert!(
        String::from_utf8_lossy(&missing_quiescence.stderr).contains(
            "recover requires --approval, --expected-nonce, --acknowledgement-id, --old-primary-fenced, and --old-relays-fenced"
        )
    );

    let recovered = run_relay_cli(&[
        "recover",
        "--config",
        config.to_str().expect("recovery config path"),
        "--approval",
        request.approval_path.to_str().expect("approval path"),
        "--expected-nonce",
        EXPECTED_NONCE,
        "--acknowledgement-id",
        "m7-recovery-workflow-operator-declaration",
        "--old-primary-fenced",
        "--old-relays-fenced",
    ])
    .await;
    let recovered_json = parse_cli_json(&recovered);
    assert_eq!(recovered_json["approval_version"], 1);
    assert_eq!(recovered_json["deployment_incarnation"], CANDIDATE_INCARC);
    assert!(
        recovered_json["quiescence_declared"]
            .as_bool()
            .is_some_and(|declared| declared)
    );
    assert_cli_redacted(&recovered, &directory);

    assert!(active_is(&fixture, CANDIDATE_INCARC).await);
    assert!(!active_is(&fixture, INITIAL_INCARC).await);
    let candidate = RedisCatalog::connect_with_deployment_incarnation(
        &fixture.upstream_url,
        &fixture.namespace,
        CANDIDATE_INCARC,
    )
    .await
    .expect("connect recovered candidate catalog");
    assert!(
        candidate
            .resolve_device(&fixture.credential_spki_fingerprint, Utc::now())
            .await
            .expect("read preserved device revocation")
            .is_none(),
        "recovery must preserve the durable device revocation"
    );

    let replay = run_relay_cli(&[
        "recover",
        "--config",
        config.to_str().expect("recovery config path"),
        "--approval",
        request.approval_path.to_str().expect("approval path"),
        "--expected-nonce",
        EXPECTED_NONCE,
        "--acknowledgement-id",
        "m7-recovery-workflow-operator-declaration",
        "--old-primary-fenced",
        "--old-relays-fenced",
    ])
    .await;
    assert!(!replay.status.success());
    assert!(String::from_utf8_lossy(&replay.stderr).contains("recovery approval was rejected"));

    cleanup(&fixture).await;
    tls_forwarder.shutdown().await;
}
