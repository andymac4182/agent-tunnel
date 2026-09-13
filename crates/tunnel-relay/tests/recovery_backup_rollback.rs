//! Namespace-scoped Redis backup/rollback recovery evidence.
//!
//! This fixture uses a tiny RESP client instead of a second catalog
//! implementation. It snapshots only durable catalog keys in a test
//! namespace with DUMP/PTTL, restores them with a bounded MULTI/RESTORE
//! transaction, and invokes the real recovery CLI for approval and
//! activation. It never flushes Redis or touches keys outside its namespace,
//! apart from one sentinel key created by the test.

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    io,
    path::{Path, PathBuf},
    pin::Pin,
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};

use chrono::{Duration as ChronoDuration, Utc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{sleep, timeout},
};
use tunnel_catalog::{
    Catalog, CatalogFixture, CredentialRecord, FixtureDevice, GrantSpec, MembershipRecord,
    MembershipRole, PermissionSet, PrincipalIdentity, RecoveryApprovalIssuer, RedisCatalog,
    ServiceSpec, TenantRecord, UserRecord,
};
use uuid::Uuid;

#[path = "common/recovery_redis.rs"]
mod recovery_redis;

const DEPLOYMENT_ID: &str = "m7-recovery-backup-deployment";
const INITIAL_INCARC: &str = "m7-recovery-backup-initial";
const CANDIDATE_INCARC: &str = "m7-recovery-backup-candidate";
const EXPECTED_NONCE: &str = "m7-recovery-backup-nonce-0001";
const OPERATOR_KEY_ID: &str = "m7-recovery-backup-operator";
const RESP_LINE_LIMIT: usize = 512;
const RESP_BULK_LIMIT: usize = 4 * 1024 * 1024;
const RESP_ARRAY_LIMIT: usize = 32_768;
const REDIS_OPERATION_DEADLINE: Duration = Duration::from_secs(10);
const TEST_DEADLINE: Duration = Duration::from_secs(180);

#[derive(Debug)]
struct Fixture {
    upstream_url: String,
    namespace: String,
    tenant: Uuid,
    device: Uuid,
    credential_spki_fingerprint: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableRecord {
    key: String,
    payload: Vec<u8>,
    ttl_ms: i64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct DurableSnapshot {
    records: BTreeMap<String, DurableRecord>,
}

#[derive(Debug)]
enum RespValue {
    Simple(Vec<u8>),
    Error(Vec<u8>),
    Integer(i64),
    Bulk(Option<Vec<u8>>),
    Array(Option<Vec<RespValue>>),
}

struct RawRedis {
    stream: TcpStream,
}

impl RawRedis {
    async fn connect(url: &str) -> io::Result<Self> {
        let address = redis_address(url)?;
        let stream = timeout(REDIS_OPERATION_DEADLINE, TcpStream::connect(address))
            .await
            .map_err(|_| redis_deadline_error("connect"))??;
        Ok(Self { stream })
    }

    async fn command(&mut self, args: &[Vec<u8>]) -> io::Result<RespValue> {
        let request = encode_command(args);
        timeout(REDIS_OPERATION_DEADLINE, async {
            self.stream.write_all(&request).await?;
            self.stream.flush().await?;
            read_resp(&mut self.stream).await
        })
        .await
        .map_err(|_| redis_deadline_error("command"))?
    }

    async fn transaction(&mut self, commands: &[Vec<Vec<u8>>]) -> io::Result<RespValue> {
        let mut request = encode_command(&[b"MULTI".to_vec()]);
        for command in commands {
            request.extend_from_slice(&encode_command(command));
        }
        request.extend_from_slice(&encode_command(&[b"EXEC".to_vec()]));
        let command_count = commands.len();
        timeout(REDIS_OPERATION_DEADLINE, async {
            self.stream.write_all(&request).await?;
            self.stream.flush().await?;
            expect_simple(read_resp(&mut self.stream).await?, b"OK")?;
            for _ in 0..command_count {
                expect_simple(read_resp(&mut self.stream).await?, b"QUEUED")?;
            }
            read_resp(&mut self.stream).await
        })
        .await
        .map_err(|_| redis_deadline_error("transaction"))?
    }
}

fn redis_deadline_error(operation: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        format!("Redis {operation} exceeded {REDIS_OPERATION_DEADLINE:?} deadline"),
    )
}

fn redis_address(url: &str) -> io::Result<String> {
    let rest = url.strip_prefix("redis://").ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup fixture requires a plaintext redis:// URL",
        )
    })?;
    if rest.contains('@') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup fixture does not accept Redis credentials",
        ));
    }
    let authority = rest.split('/').next().unwrap_or_default();
    if authority.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "backup fixture Redis authority is empty",
        ));
    }
    if let Some(bracketed) = authority.strip_prefix('[') {
        let (host, port) = bracketed
            .split_once(']')
            .and_then(|(host, remainder)| remainder.strip_prefix(':').map(|port| (host, port)))
            .unwrap_or((bracketed.trim_end_matches(']'), "6379"));
        return Ok(format!("[{host}]:{port}"));
    }
    if authority.contains(':') {
        Ok(authority.to_owned())
    } else {
        Ok(format!("{authority}:6379"))
    }
}

fn encode_command(args: &[Vec<u8>]) -> Vec<u8> {
    let mut encoded = format!("*{}\r\n", args.len()).into_bytes();
    for arg in args {
        encoded.push(b'$');
        encoded.extend_from_slice(arg.len().to_string().as_bytes());
        encoded.extend_from_slice(b"\r\n");
        encoded.extend_from_slice(arg);
        encoded.extend_from_slice(b"\r\n");
    }
    encoded
}

fn read_resp<'a>(
    stream: &'a mut TcpStream,
) -> Pin<Box<dyn Future<Output = io::Result<RespValue>> + 'a>> {
    Box::pin(async move {
        let mut kind = [0_u8; 1];
        stream.read_exact(&mut kind).await?;
        match kind[0] {
            b'+' => Ok(RespValue::Simple(read_resp_line(stream).await?)),
            b'-' => Ok(RespValue::Error(read_resp_line(stream).await?)),
            b':' => Ok(RespValue::Integer(parse_i64(
                &read_resp_line(stream).await?,
            )?)),
            b'$' => {
                let size = parse_i64(&read_resp_line(stream).await?)?;
                if size < 0 {
                    return Ok(RespValue::Bulk(None));
                }
                let size = usize::try_from(size).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "negative Redis bulk size")
                })?;
                if size > RESP_BULK_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Redis bulk response exceeds fixture bound",
                    ));
                }
                let mut bytes = vec![0_u8; size + 2];
                stream.read_exact(&mut bytes).await?;
                if !bytes.ends_with(b"\r\n") {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Redis bulk terminator",
                    ));
                }
                bytes.truncate(size);
                Ok(RespValue::Bulk(Some(bytes)))
            }
            b'*' => {
                let count = parse_i64(&read_resp_line(stream).await?)?;
                if count < 0 {
                    return Ok(RespValue::Array(None));
                }
                let count = usize::try_from(count).map_err(|_| {
                    io::Error::new(io::ErrorKind::InvalidData, "negative Redis array size")
                })?;
                if count > RESP_ARRAY_LIMIT {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "Redis array response exceeds fixture bound",
                    ));
                }
                let mut values = Vec::with_capacity(count);
                for _ in 0..count {
                    values.push(read_resp(stream).await?);
                }
                Ok(RespValue::Array(Some(values)))
            }
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported Redis RESP type",
            )),
        }
    })
}

async fn read_resp_line(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        stream.read_exact(&mut byte).await?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Ok(line);
        }
        if line.len() > RESP_LINE_LIMIT {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Redis response line exceeds fixture bound",
            ));
        }
    }
}

fn parse_i64(bytes: &[u8]) -> io::Result<i64> {
    std::str::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Redis integer UTF-8"))?
        .parse::<i64>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "Redis integer"))
}

fn expect_simple(value: RespValue, expected: &[u8]) -> io::Result<()> {
    match value {
        RespValue::Simple(actual) if actual == expected => Ok(()),
        RespValue::Error(error) => Err(io::Error::other(format!(
            "Redis error: {}",
            String::from_utf8_lossy(&error)
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected Redis simple response",
        )),
    }
}

fn expect_integer(value: RespValue) -> io::Result<i64> {
    match value {
        RespValue::Integer(value) => Ok(value),
        RespValue::Error(error) => Err(io::Error::other(format!(
            "Redis error: {}",
            String::from_utf8_lossy(&error)
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Redis integer",
        )),
    }
}

fn expect_bulk(value: RespValue) -> io::Result<Vec<u8>> {
    match value {
        RespValue::Bulk(Some(value)) => Ok(value),
        RespValue::Bulk(None) => Err(io::Error::new(
            io::ErrorKind::NotFound,
            "Redis key disappeared during snapshot",
        )),
        RespValue::Error(error) => Err(io::Error::other(format!(
            "Redis error: {}",
            String::from_utf8_lossy(&error)
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Redis bulk response",
        )),
    }
}

fn expect_array(value: RespValue) -> io::Result<Vec<RespValue>> {
    match value {
        RespValue::Array(Some(value)) => Ok(value),
        RespValue::Array(None) => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unexpected null Redis array",
        )),
        RespValue::Error(error) => Err(io::Error::other(format!(
            "Redis error: {}",
            String::from_utf8_lossy(&error)
        ))),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "expected Redis array response",
        )),
    }
}

fn command_args(args: &[&[u8]]) -> Vec<Vec<u8>> {
    args.iter().map(|arg| arg.to_vec()).collect()
}

async fn scan_keys(redis: &mut RawRedis, prefix: &str) -> io::Result<Vec<String>> {
    let mut cursor = 0_i64;
    let mut keys = BTreeSet::new();
    let pattern = format!("{prefix}*");
    loop {
        let cursor_arg = cursor.to_string();
        let response = redis
            .command(&command_args(&[
                b"SCAN",
                cursor_arg.as_bytes(),
                b"MATCH",
                pattern.as_bytes(),
                b"COUNT",
                b"256",
            ]))
            .await?;
        let parts = expect_array(response)?;
        if parts.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Redis SCAN response shape",
            ));
        }
        let mut parts = parts.into_iter();
        cursor = match parts.next().expect("SCAN cursor") {
            RespValue::Bulk(Some(value)) | RespValue::Simple(value) => parse_i64(&value)?,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Redis SCAN cursor shape",
                ));
            }
        };
        for key in expect_array(parts.next().expect("SCAN key array"))? {
            let key = String::from_utf8(expect_bulk(key)?).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "Redis key is not UTF-8")
            })?;
            if !key.starts_with(prefix) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Redis SCAN escaped namespace prefix",
                ));
            }
            keys.insert(key);
        }
        if cursor == 0 {
            return Ok(keys.into_iter().collect());
        }
    }
}

fn is_durable_key(prefix: &str, key: &str) -> bool {
    let Some(suffix) = key.strip_prefix(prefix) else {
        return false;
    };
    // The live Redis run/incarnation metadata remains authoritative across
    // restore. Owner/ticket state and signed membership caches are ephemeral;
    // the epoch and catalog-generation strings remain part of the durable
    // catalog state used by this fixture's rollback snapshots.
    !suffix.starts_with("coord:owner:")
        && !suffix.starts_with("coord:ticket:")
        && !suffix.starts_with("coord:tickets:")
        && !suffix.starts_with("membership:operator:")
        && suffix != "meta:active_incarnation"
        && suffix != "meta:redis_run_id"
}

async fn snapshot_durable(redis: &mut RawRedis, prefix: &str) -> io::Result<DurableSnapshot> {
    let mut records = BTreeMap::new();
    for key in scan_keys(redis, prefix).await? {
        if !is_durable_key(prefix, &key) {
            continue;
        }
        let key_bytes = key.as_bytes().to_vec();
        let payload = expect_bulk(
            redis
                .command(&command_args(&[b"DUMP", key_bytes.as_slice()]))
                .await?,
        )?;
        let ttl_ms = expect_integer(
            redis
                .command(&command_args(&[b"PTTL", key_bytes.as_slice()]))
                .await?,
        )?;
        if ttl_ms < -1 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Redis snapshot key expired during DUMP",
            ));
        }
        records.insert(
            key.clone(),
            DurableRecord {
                key,
                payload,
                ttl_ms,
            },
        );
    }
    if records.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "durable Redis snapshot was empty",
        ));
    }
    Ok(DurableSnapshot { records })
}

async fn restore_durable(
    redis: &mut RawRedis,
    prefix: &str,
    snapshot: &DurableSnapshot,
) -> io::Result<()> {
    let current = snapshot_durable(redis, prefix).await?;
    let mut commands = Vec::new();
    for key in current.records.keys() {
        if !snapshot.records.contains_key(key) {
            commands.push(command_args(&[b"DEL", key.as_bytes()]));
        }
    }
    for record in snapshot.records.values() {
        let ttl = if record.ttl_ms < 0 {
            b"0".to_vec()
        } else {
            record.ttl_ms.to_string().into_bytes()
        };
        commands.push(vec![
            b"RESTORE".to_vec(),
            record.key.as_bytes().to_vec(),
            ttl,
            record.payload.clone(),
            b"REPLACE".to_vec(),
        ]);
    }
    let response = redis.transaction(&commands).await?;
    let replies = expect_array(response)?;
    if replies.len() != commands.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Redis restore transaction response shape",
        ));
    }
    if replies
        .into_iter()
        .any(|reply| matches!(reply, RespValue::Error(_)))
    {
        return Err(io::Error::other(
            "Redis restore transaction contained an error",
        ));
    }
    Ok(())
}

async fn set_sentinel(redis: &mut RawRedis, key: &str, value: &[u8]) -> io::Result<()> {
    expect_simple(
        redis
            .command(&command_args(&[b"SET", key.as_bytes(), value]))
            .await?,
        b"OK",
    )
}

async fn get_sentinel(redis: &mut RawRedis, key: &str) -> io::Result<Vec<u8>> {
    expect_bulk(
        redis
            .command(&command_args(&[b"GET", key.as_bytes()]))
            .await?,
    )
}

async fn delete_key(redis: &mut RawRedis, key: &str) -> io::Result<()> {
    let deleted = expect_integer(
        redis
            .command(&command_args(&[b"DEL", key.as_bytes()]))
            .await?,
    )?;
    if deleted != 1 {
        return Err(io::Error::new(
            io::ErrorKind::NotFound,
            "backup sentinel was not deleted",
        ));
    }
    Ok(())
}

fn fixture_values() -> (CatalogFixture, Uuid, Uuid, String) {
    let tenant = Uuid::new_v4();
    let user = Uuid::new_v4();
    let device = Uuid::new_v4();
    let service = Uuid::new_v4();
    let now = Utc::now();
    let spki = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
    let fixture = CatalogFixture {
        tenants: vec![TenantRecord {
            tenant_id: tenant,
            display_name: "backup rollback tenant".to_owned(),
            active: true,
        }],
        users: vec![UserRecord {
            user_id: user,
            display_name: "backup rollback user".to_owned(),
        }],
        identities: vec![PrincipalIdentity {
            issuer: "https://issuer.recovery-backup.invalid".to_owned(),
            subject: format!("backup-rollback-subject-{user}"),
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
            display_name: "backup rollback device".to_owned(),
            active: true,
            last_seen_at: Some(now),
        }],
        credentials: vec![CredentialRecord {
            tenant_id: tenant,
            device_id: device,
            credential_id: Uuid::new_v4(),
            spki_fingerprint: spki.to_owned(),
            serial: Some("backup-rollback-credential".to_owned()),
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
            display_name: "backup rollback echo".to_owned(),
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
    (fixture, tenant, device, spki.to_owned())
}

async fn setup(redis_url: &str) -> Fixture {
    let namespace = format!("test-recovery-backup-{}", Uuid::new_v4().simple());
    let (records, tenant, device, credential_spki_fingerprint) = fixture_values();
    let catalog = RedisCatalog::connect_for_recovery(redis_url, &namespace, INITIAL_INCARC)
        .await
        .expect("connect backup rollback fixture catalog");
    catalog
        .activate_deployment_incarnation()
        .await
        .expect("activate backup rollback fixture");
    catalog
        .seed_fixture(&records)
        .await
        .expect("seed backup rollback fixture");
    Fixture {
        upstream_url: redis_url.to_owned(),
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
        CANDIDATE_INCARC,
    )
    .await
    .expect("connect backup rollback cleanup catalog");
    catalog
        .cleanup_fixture_namespace()
        .await
        .expect("cleanup backup rollback namespace");
}

struct TestDirectory(PathBuf);

impl TestDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "agent-tunnel-recovery-backup-{}-{}",
            std::process::id(),
            Uuid::new_v4()
        ));
        std::fs::create_dir(&path).expect("create backup recovery directory");
        let path = std::fs::canonicalize(path).expect("canonicalize backup recovery directory");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                .expect("private backup recovery directory");
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
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn write_private_file(path: &Path, bytes: &[u8]) {
    std::fs::write(path, bytes).expect("write private backup recovery file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
            .expect("private backup recovery file mode");
    }
}

fn toml_string(value: &str) -> String {
    serde_json::to_string(value).expect("quote backup recovery TOML string")
}

fn toml_path(path: &Path) -> String {
    toml_string(path.to_str().expect("backup recovery path is UTF-8"))
}

fn write_cli_config(
    directory: &TestDirectory,
    fixture: &Fixture,
    redis_url: &str,
    redis_root_ca: &Path,
) -> PathBuf {
    let path = directory.path("relay.toml");
    let text = format!(
        "oidc_issuer = \"https://issuer.recovery-backup.invalid\"\noidc_audience = [\"recovery-backup-test\"]\noidc_jwks_path = {}\nredis_url = {}\nredis_tls_root_ca_path = {}\nredis_namespace = {}\ndevice_tls_cert_chain = {}\ndevice_tls_private_key = {}\ndevice_tls_client_ca = {}\nconsumer_tls_cert_chain = {}\nconsumer_tls_private_key = {}\nnode_id = \"recovery-backup-test-node\"\ndeployment_incarnation = {}\n\n[cluster]\ndeployment_id = {}\npeer_bind = \"127.0.0.1:1\"\npeer_tls_cert_chain = {}\npeer_tls_private_key = {}\npeer_tls_client_ca = {}\nmembership_signer_trust_path = {}\ncheckpoint_authority_endpoint = \"https://checkpoint.recovery-backup.invalid\"\ncheckpoint_authority_trust_path = {}\nmembership_version_state_path = {}\n\n[recovery]\nfence_path = {}\ntrusted_keys_path = {}\ndeployment_incarnation = {}\n",
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

fn prepare_signer(directory: &TestDirectory) -> RecoveryApprovalIssuer {
    let (issuer, _) =
        RecoveryApprovalIssuer::generate(OPERATOR_KEY_ID).expect("backup recovery issuer");
    let public_key = issuer.public_key().expect("backup recovery public key");
    let public_key = public_key
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let trusted = serde_json::json!({
        "schema_version": 1,
        "keys": [{"key_id": OPERATOR_KEY_ID, "public_key": public_key}]
    });
    write_private_file(
        &directory.trusted_keys(),
        &serde_json::to_vec(&trusted).expect("backup recovery trusted key JSON"),
    );
    issuer
}

fn write_approval(
    directory: &TestDirectory,
    issuer: &RecoveryApprovalIssuer,
    fixture: &Fixture,
    redis_run_id: &str,
    catalog_digest: &str,
    approval_version: u64,
) -> PathBuf {
    let now = Utc::now();
    let approval = tunnel_catalog::RecoveryApproval {
        schema_version: 1,
        deployment_id: DEPLOYMENT_ID.to_owned(),
        redis_namespace: fixture.namespace.clone(),
        redis_run_id: redis_run_id.to_owned(),
        deployment_incarnation: CANDIDATE_INCARC.to_owned(),
        approval_version,
        nonce: EXPECTED_NONCE.to_owned(),
        catalog_digest: catalog_digest.to_owned(),
        issued_at: now - ChronoDuration::seconds(1),
        not_before: now - ChronoDuration::seconds(1),
        expires_at: now + ChronoDuration::seconds(30),
    };
    let bytes = issuer
        .sign_approval_bytes(approval)
        .expect("sign backup recovery approval");
    write_private_file(&directory.approval(), &bytes);
    directory.approval()
}

async fn run_relay_cli(args: &[&str]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_tunnel-relay"))
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn backup recovery CLI");
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => sleep(Duration::from_millis(20)).await,
            Ok(None) => {
                fail_cli_child(child, "backup recovery CLI exceeded bounded deadline");
            }
            Err(error) => {
                fail_cli_child(child, &format!("poll backup recovery CLI: {error}"));
            }
        }
    }
    child.wait_with_output().expect("join backup recovery CLI")
}

fn fail_cli_child(mut child: Child, reason: &str) -> ! {
    let kill_result = child.kill();
    match child.wait_with_output() {
        Ok(output) => panic!(
            "{reason}; kill={kill_result:?}; status={}; stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        ),
        Err(wait_error) => {
            panic!("{reason}; kill={kill_result:?}; wait={wait_error}")
        }
    }
}

fn parse_cli_json(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "backup recovery CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(output.stdout.as_slice()).expect("parse backup recovery CLI JSON")
}

fn assert_cli_failure(output: &Output, marker: &str) {
    assert!(!output.status.success());
    assert!(
        String::from_utf8_lossy(&output.stderr).contains(marker),
        "backup recovery CLI error did not contain {marker:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cli_args(command: &str, config: &Path, approval: Option<&Path>, flags: bool) -> Vec<String> {
    let mut args = vec![
        command.to_owned(),
        "--config".to_owned(),
        config
            .to_str()
            .expect("backup recovery config path")
            .to_owned(),
    ];
    if let Some(approval) = approval {
        args.extend([
            "--approval".to_owned(),
            approval
                .to_str()
                .expect("backup recovery approval path")
                .to_owned(),
            "--expected-nonce".to_owned(),
            EXPECTED_NONCE.to_owned(),
            "--acknowledgement-id".to_owned(),
            "m7-recovery-backup-quiescence".to_owned(),
        ]);
        if flags {
            args.extend([
                "--old-primary-fenced".to_owned(),
                "--old-relays-fenced".to_owned(),
            ]);
        }
    }
    args
}

fn argv_refs(args: &[String]) -> Vec<&str> {
    args.iter().map(String::as_str).collect()
}

#[cfg(unix)]
#[tokio::test]
#[ignore = "requires TUNNEL_CATALOG_REDIS_URL Redis primary fixture"]
async fn namespace_backup_rollback_requires_exact_approval_and_preserves_revocation() {
    timeout(
        TEST_DEADLINE,
        namespace_backup_rollback_requires_exact_approval_and_preserves_revocation_inner(),
    )
    .await
    .expect("backup rollback fixture exceeded its overall deadline");
}

async fn namespace_backup_rollback_requires_exact_approval_and_preserves_revocation_inner() {
    let redis_url = std::env::var("TUNNEL_CATALOG_REDIS_URL").expect("backup rollback Redis URL");
    let fixture = setup(&redis_url).await;
    let prefix = format!("tunnel-catalog:{}:", fixture.namespace);
    let sentinel_key = format!("m7-recovery-backup-unrelated-{}", Uuid::new_v4().simple());
    let sentinel_value = b"unrelated-live-state";
    let mut raw = RawRedis::connect(&redis_url)
        .await
        .expect("connect raw Redis backup client");
    set_sentinel(&mut raw, &sentinel_key, sentinel_value)
        .await
        .expect("seed unrelated Redis sentinel");

    let active_snapshot = snapshot_durable(&mut raw, &prefix)
        .await
        .expect("snapshot active durable catalog before revocation");
    let directory = TestDirectory::new();
    let tls_forwarder = recovery_redis::RedisTlsForwarder::start(
        &redis_url,
        directory.path("redis-forwarder-ca.pem"),
    )
    .await;
    let config = write_cli_config(
        &directory,
        &fixture,
        &tls_forwarder.url,
        &tls_forwarder.root_ca,
    );
    let signer = prepare_signer(&directory);
    let initialize = run_relay_cli(&argv_refs(&cli_args(
        "recovery-initialize",
        &config,
        None,
        false,
    )))
    .await;
    assert!(
        initialize.status.success(),
        "recovery-initialize failed: {}",
        String::from_utf8_lossy(&initialize.stderr)
    );

    let observation_before = run_relay_cli(&argv_refs(&cli_args(
        "recovery-observe",
        &config,
        None,
        false,
    )))
    .await;
    let observation_before_json = parse_cli_json(&observation_before);
    let active_digest = observation_before_json["catalog_digest"]
        .as_str()
        .expect("active backup digest")
        .to_owned();
    let redis_run_id = observation_before_json["redis_run_id"]
        .as_str()
        .expect("active Redis run id")
        .to_owned();

    let catalog = RedisCatalog::connect_with_deployment_incarnation(
        &redis_url,
        &fixture.namespace,
        INITIAL_INCARC,
    )
    .await
    .expect("connect active catalog before revocation");
    catalog
        .revoke_device(fixture.tenant, fixture.device, Utc::now())
        .await
        .expect("revoke live credential");
    assert!(
        catalog
            .resolve_device(&fixture.credential_spki_fingerprint, Utc::now())
            .await
            .expect("resolve revoked credential")
            .is_none(),
        "live revocation must stop authorization before backup restore"
    );

    let revoked_snapshot = snapshot_durable(&mut raw, &prefix)
        .await
        .expect("snapshot revoked durable catalog");
    let observation_revoked = run_relay_cli(&argv_refs(&cli_args(
        "recovery-observe",
        &config,
        None,
        false,
    )))
    .await;
    let observation_revoked_json = parse_cli_json(&observation_revoked);
    let revoked_digest = observation_revoked_json["catalog_digest"]
        .as_str()
        .expect("revoked catalog digest")
        .to_owned();
    assert_ne!(
        active_digest, revoked_digest,
        "revocation must change durable digest"
    );
    let stale_approval = write_approval(
        &directory,
        &signer,
        &fixture,
        &redis_run_id,
        &revoked_digest,
        1,
    );

    // Restore the older active-record backup while the revoked state is the
    // current live observation. No relay or device writer is running, and the
    // restore is one namespace-scoped Redis transaction under explicit
    // quiescence below.
    restore_durable(&mut raw, &prefix, &active_snapshot)
        .await
        .expect("restore older active-record backup");
    assert_eq!(
        get_sentinel(&mut raw, &sentinel_key)
            .await
            .expect("read unrelated sentinel after active restore"),
        sentinel_value
    );
    let restored_active_observation = run_relay_cli(&argv_refs(&cli_args(
        "recovery-observe",
        &config,
        None,
        false,
    )))
    .await;
    let restored_active_json = parse_cli_json(&restored_active_observation);
    assert_eq!(
        restored_active_json["catalog_digest"], active_digest,
        "active-record restore must reproduce the captured durable digest"
    );
    let restored_active = RedisCatalog::connect_with_deployment_incarnation(
        &redis_url,
        &fixture.namespace,
        INITIAL_INCARC,
    )
    .await
    .expect("connect restored active-record catalog");
    assert!(
        restored_active
            .resolve_device(&fixture.credential_spki_fingerprint, Utc::now())
            .await
            .expect("resolve restored active record")
            .is_some(),
        "backup restore should reproduce the captured pre-revocation record"
    );

    // The approval is bound to the exact revoked observation, so it cannot
    // activate the rollbacked active record. Ordinary startup alone cannot
    // detect arbitrary backup rollback.
    let stale_args = cli_args("recover", &config, Some(&stale_approval), true);
    let stale_result = run_relay_cli(&argv_refs(&stale_args)).await;
    assert_cli_failure(
        &stale_result,
        "recovery approval does not match the live catalog observation",
    );
    assert!(
        RedisCatalog::connect_with_deployment_incarnation(
            &redis_url,
            &fixture.namespace,
            INITIAL_INCARC,
        )
        .await
        .is_ok(),
        "failed stale approval must not activate candidate incarnation"
    );

    // Reconcile the lost revocation from the verified post-revocation backup,
    // then obtain a fresh higher approval version for that exact digest.
    restore_durable(&mut raw, &prefix, &revoked_snapshot)
        .await
        .expect("restore reconciled revoked backup");
    assert_eq!(
        get_sentinel(&mut raw, &sentinel_key)
            .await
            .expect("read unrelated sentinel after revoked restore"),
        sentinel_value
    );
    let reconciled_observation = run_relay_cli(&argv_refs(&cli_args(
        "recovery-observe",
        &config,
        None,
        false,
    )))
    .await;
    let reconciled_json = parse_cli_json(&reconciled_observation);
    assert_eq!(
        reconciled_json["catalog_digest"], revoked_digest,
        "revoked restore must reproduce the reconciled durable digest"
    );
    let reconciled = RedisCatalog::connect_with_deployment_incarnation(
        &redis_url,
        &fixture.namespace,
        INITIAL_INCARC,
    )
    .await
    .expect("connect reconciled catalog");
    assert!(
        reconciled
            .resolve_device(&fixture.credential_spki_fingerprint, Utc::now())
            .await
            .expect("resolve reconciled revoked record")
            .is_none(),
        "restored revoked record must remain unauthorized"
    );
    let fresh_approval = write_approval(
        &directory,
        &signer,
        &fixture,
        &redis_run_id,
        &revoked_digest,
        2,
    );
    let fresh_args = cli_args("recover", &config, Some(&fresh_approval), true);
    let recovered = run_relay_cli(&argv_refs(&fresh_args)).await;
    let recovered_json = parse_cli_json(&recovered);
    assert_eq!(recovered_json["approval_version"], 2);
    assert_eq!(recovered_json["deployment_incarnation"], CANDIDATE_INCARC);
    assert!(
        recovered_json["quiescence_declared"]
            .as_bool()
            .is_some_and(|declared| declared)
    );

    assert!(
        RedisCatalog::connect_with_deployment_incarnation(
            &redis_url,
            &fixture.namespace,
            INITIAL_INCARC,
        )
        .await
        .is_err(),
        "old writer incarnation must be refused after approved activation"
    );
    // This is a fresh catalog session after activation and proves the
    // restored record is still revoked. A full device/serve handshake needs
    // separate device TLS fixtures and remains outside this Redis-only gate.
    let candidate = RedisCatalog::connect_with_deployment_incarnation(
        &redis_url,
        &fixture.namespace,
        CANDIDATE_INCARC,
    )
    .await
    .expect("connect fresh candidate catalog");
    assert!(
        candidate
            .resolve_device(&fixture.credential_spki_fingerprint, Utc::now())
            .await
            .expect("resolve candidate revoked record")
            .is_none(),
        "candidate activation must preserve restored revocation"
    );
    assert_eq!(
        get_sentinel(&mut raw, &sentinel_key)
            .await
            .expect("read unrelated sentinel after activation"),
        sentinel_value
    );

    let replay = run_relay_cli(&argv_refs(&fresh_args)).await;
    assert_cli_failure(&replay, "recovery approval was rejected");

    cleanup(&fixture).await;
    delete_key(&mut raw, &sentinel_key)
        .await
        .expect("delete owned unrelated sentinel");
    tls_forwarder.shutdown().await;
}
