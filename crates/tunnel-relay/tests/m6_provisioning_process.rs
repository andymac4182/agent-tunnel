//! Task row M6-C21: one relay and one device brought up from an empty Redis
//! namespace **with shipped binaries only**, then one real operation through
//! the tunnel.
//!
//! Every step that an operator or a device owner performs is a `tunnel-relay`
//! or `tunnel-client` process: device key and CSR (`credentials create`),
//! certificate import (`credentials import`), a records dry run, first
//! incarnation activation, catalog provisioning, `serve` and `connect`.  No
//! harness or catalog library call writes Redis.  What stands in for the
//! outside world is stated, not hidden:
//!
//! * **the device certificate issuer** is `openssl x509 -req`, exactly as
//!   docs/operator.md rehearses it;
//! * **the relay's server certificates and the Redis TLS endpoint** come from
//!   a synthetic CA built here, and Redis TLS is a local forwarder in front of
//!   the plaintext `TEST_REDIS_URL` because `serve` accepts only `rediss://`;
//! * **the identity issuer** is an RSA key from `openssl genpkey` whose public
//!   half is the relay's JWKS; this test signs the consumer's access token;
//! * **the consumer** is an HTTPS request made from this test.
//!
//! The gate is ignored by the ordinary workspace run because it needs a
//! disposable Redis (`TEST_REDIS_URL`) and a freshly built client
//! (`TUNNEL_CLIENT_BIN`); `scripts/m6-provisioning-verify.sh` builds both
//! binaries and runs it.  Each step names itself on failure, and the run
//! prints `m6c21-e2e ok nonce=...` only after the echo returned the device's
//! canary and the bytes sent, so a filtered or skipped run cannot be read as a
//! pass.

use std::{
    env, fs,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    sync::Arc,
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

const ISSUER: &str = "https://issuer.m6c21.invalid/";
const AUDIENCE: &str = "agent-tunnel";
const CANARY: &str = "m1-device-a-synthetic";
const STEP_DEADLINE: Duration = Duration::from_secs(20);

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn free_port() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .expect("bind a free port")
        .local_addr()
        .expect("free port address")
}

struct Workdir(PathBuf);

impl Drop for Workdir {
    fn drop(&mut self) {
        if env::var_os("M6C21_KEEP_WORKDIR").is_none() {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
}

/// Run one step to completion; a non-zero exit fails the gate naming it.
fn step(name: &str, command: &mut Command) -> Output {
    let output = command.output().unwrap_or_else(|error| {
        panic!("step {name}: could not start: {error}");
    });
    if !output.status.success() {
        panic!(
            "step {name}: exited {:?}\nstdout: {}\nstderr: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    output
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Replace a top-level `key = value` line of a shipped example.
fn set_key(document: &str, key: &str, value: &str) -> String {
    let prefix = format!("{key} = ");
    let mut found = false;
    let lines: Vec<String> = document
        .lines()
        .map(|line| {
            if line.starts_with(&prefix) {
                found = true;
                format!("{key} = {value}")
            } else {
                line.to_owned()
            }
        })
        .collect();
    assert!(found, "the shipped example has no `{key}` line to replace");
    lines.join("\n") + "\n"
}

fn toml_string(value: &Path) -> String {
    format!("\"{}\"", value.display())
}

/// Synthetic server PKI for the relay's two listeners and the Redis TLS
/// endpoint.  One leaf serves all three: the gate is about provisioning, not
/// about listener identity separation.
struct ServerPki {
    ca_pem: String,
    chain_pem: String,
    key_pem: String,
}

fn server_pki() -> ServerPki {
    let ca_key = KeyPair::generate().expect("server CA key");
    let mut ca_params = CertificateParams::default();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C21 synthetic server CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("server CA");
    let leaf_key = KeyPair::generate().expect("server leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C21 synthetic relay");
    leaf_params.subject_alt_names.push(SanType::IpAddress(
        "127.0.0.1".parse().expect("loopback SAN"),
    ));
    leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    leaf_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let leaf = leaf_params
        .signed_by(&leaf_key, &ca, &ca_key)
        .expect("server leaf");
    ServerPki {
        ca_pem: ca.pem(),
        chain_pem: format!("{}{}", leaf.pem(), ca.pem()),
        key_pem: leaf_key.serialize_pem(),
    }
}

/// A TLS terminator in front of the plaintext test Redis.  It stands in for a
/// `rediss://` Redis; it neither reads nor alters the RESP stream.
async fn redis_tls_forwarder(upstream: SocketAddr, pki: &ServerPki) -> SocketAddr {
    let server_config = tunnel_transport::load_server_config_from_pem(
        pki.chain_pem.as_bytes(),
        pki.key_pem.as_bytes(),
        None,
    )
    .expect("Redis forwarder TLS config");
    let acceptor = TlsAcceptor::from(server_config);
    let listener = TokioTcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind Redis forwarder");
    let address = listener.local_addr().expect("forwarder address");
    tokio::spawn(async move {
        loop {
            let Ok((socket, _)) = listener.accept().await else {
                return;
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut tls) = acceptor.accept(socket).await else {
                    return;
                };
                let Ok(mut plain) = TcpStream::connect(upstream).await else {
                    return;
                };
                let _ = tokio::io::copy_bidirectional(&mut tls, &mut plain).await;
            });
        }
    });
    address
}

fn parse_plaintext_redis(url: &str) -> (SocketAddr, u32) {
    let rest = url
        .strip_prefix("redis://")
        .expect("TEST_REDIS_URL must be a plaintext redis:// URL");
    let (authority, path) = rest.split_once('/').unwrap_or((rest, ""));
    let address = authority
        .parse::<SocketAddr>()
        .expect("TEST_REDIS_URL must name an IP:port");
    let database = path.trim_matches('/').parse().unwrap_or(0);
    (address, database)
}

/// Minimal blocking RESP client used only to delete this run's keys, so the
/// cleanup can also run from `Drop` when a step panics.
fn redis_command(upstream: SocketAddr, database: u32, parts: &[&str]) -> Vec<u8> {
    use std::io::{Read, Write};
    let Ok(mut stream) = std::net::TcpStream::connect_timeout(&upstream, Duration::from_secs(2))
    else {
        return Vec::new();
    };
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut request = Vec::new();
    let select = ["SELECT".to_owned(), database.to_string()];
    let command: Vec<String> = parts.iter().map(|part| (*part).to_owned()).collect();
    for command in [&select[..], &command[..]] {
        request.extend_from_slice(format!("*{}\r\n", command.len()).as_bytes());
        for part in command {
            request.extend_from_slice(format!("${}\r\n{part}\r\n", part.len()).as_bytes());
        }
    }
    if stream.write_all(&request).is_err() {
        return Vec::new();
    }
    let _ = stream.shutdown(std::net::Shutdown::Write);
    let mut reply = Vec::new();
    let _ = stream.read_to_end(&mut reply);
    reply
}

/// Delete every key of this run's namespace; returns how many there were.
fn delete_namespace(upstream: SocketAddr, database: u32, namespace: &str) -> usize {
    let reply = redis_command(
        upstream,
        database,
        &["KEYS", &format!("tunnel-catalog:{namespace}:*")],
    );
    let text = String::from_utf8_lossy(&reply);
    let keys: Vec<&str> = text
        .split("\r\n")
        .filter(|line| line.starts_with("tunnel-catalog:"))
        .collect();
    if !keys.is_empty() {
        let mut command = vec!["DEL"];
        command.extend(keys.iter().copied());
        redis_command(upstream, database, &command);
    }
    keys.len()
}

/// Removes the run's namespace however the test ends.
struct NamespaceGuard {
    upstream: SocketAddr,
    database: u32,
    namespace: String,
}

impl Drop for NamespaceGuard {
    fn drop(&mut self) {
        delete_namespace(self.upstream, self.database, &self.namespace);
    }
}

/// The identity issuer stand-in: an RSA key from `openssl genpkey`, published
/// to the relay as a one-key JWKS.
fn oidc_issuer(dir: &Path) -> (jsonwebtoken::EncodingKey, PathBuf) {
    let key = dir.join("oidc-key.pem");
    step(
        "issuer key (openssl genpkey)",
        Command::new("openssl")
            .args([
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-out",
            ])
            .arg(&key),
    );
    let modulus = stdout(&step(
        "issuer modulus (openssl rsa)",
        Command::new("openssl")
            .args(["rsa", "-noout", "-modulus", "-in"])
            .arg(&key),
    ));
    let hex = modulus
        .trim()
        .strip_prefix("Modulus=")
        .expect("openssl prints Modulus=HEX");
    let bytes: Vec<u8> = (0..hex.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&hex[index..index + 2], 16).expect("modulus hex"))
        .collect();
    let jwks = dir.join("oidc-jwks.json");
    fs::write(
        &jwks,
        serde_json::json!({"keys": [{
            "kid": "m6c21-issuer", "kty": "RSA", "alg": "RS256",
            "n": URL_SAFE_NO_PAD.encode(bytes), "e": "AQAB"
        }]})
        .to_string(),
    )
    .expect("write JWKS");
    let pem = fs::read(&key).expect("read issuer key");
    (
        jsonwebtoken::EncodingKey::from_rsa_pem(&pem).expect("issuer signing key"),
        jwks,
    )
}

fn access_token(key: &jsonwebtoken::EncodingKey, subject: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("m6c21-issuer".to_owned());
    jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": subject,
            "iat": now, "exp": now + 300, "scope": "echo:invoke"
        }),
        key,
    )
    .expect("sign access token")
}

/// One HTTPS POST to the relay's consumer listener.
async fn consumer_post(
    consumer: SocketAddr,
    server_ca_pem: &str,
    path: &str,
    token: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>), String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut server_ca_pem.as_bytes()) {
        roots
            .add(certificate.map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    }
    let config = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| error.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth();
    let tcp = TcpStream::connect(consumer)
        .await
        .map_err(|error| format!("consumer connect: {error}"))?;
    let tls = TlsConnector::from(Arc::new(config))
        .connect(
            rustls::pki_types::ServerName::try_from("127.0.0.1").expect("IP server name"),
            tcp,
        )
        .await
        .map_err(|error| format!("consumer TLS: {error}"))?;
    let (mut sender, connection) = hyper::client::conn::http1::handshake(TokioIo::new(tls))
        .await
        .map_err(|error| format!("consumer HTTP: {error}"))?;
    tokio::spawn(connection);
    let request = hyper::Request::post(path)
        .header("host", consumer.to_string())
        .header("authorization", format!("Bearer {token}"))
        .header("content-type", "application/octet-stream")
        .body(Full::new(bytes::Bytes::copy_from_slice(body)))
        .map_err(|error| error.to_string())?;
    let response = sender
        .send_request(request)
        .await
        .map_err(|error| format!("consumer request: {error}"))?;
    let status = response.status().as_u16();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("consumer body: {error}"))?
        .to_bytes()
        .to_vec();
    Ok((status, bytes))
}

/// Run `connect --json` once for a profile the relay must not admit, and
/// return its exit status, its last JSON diagnostic and its raw stdout.
fn connect_refused(
    name: &str,
    client_bin: &Path,
    config: &Path,
) -> (Option<i32>, serde_json::Value, String) {
    let mut child = Command::new(client_bin)
        .args(["connect", "--config"])
        .arg(config)
        .arg("--json")
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap_or_else(|error| panic!("step {name}: could not start connect: {error}"));
    let deadline = Instant::now() + STEP_DEADLINE;
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll connect") {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("step {name}: connect did not exit within {STEP_DEADLINE:?}");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    let mut out = String::new();
    use std::io::Read as _;
    child
        .stdout
        .take()
        .expect("connect stdout")
        .read_to_string(&mut out)
        .expect("read connect stdout");
    let last = out.lines().last().unwrap_or_default();
    let diagnostic: serde_json::Value = serde_json::from_str(last)
        .unwrap_or_else(|error| panic!("step {name}: not a JSON diagnostic ({error}): {out}"));
    (status.code(), diagnostic, out)
}

/// Task row M6-C32: a profile the relay must refuse on identity gets the
/// typed, terminal refusal.  Before M6-C32 the relay dropped the socket and
/// this printed a retryable `TRANSPORT_ERROR` "control read failed" with
/// exit 4.  The close code and reason are asserted transitively: the message
/// below is produced only by `classify_initial_control_close`, which requires
/// the exact `1008 DEVICE_IDENTITY_REJECTED` close.
fn expect_identity_refusal(name: &str, client_bin: &Path, config: &Path) {
    let (code, diagnostic, out) = connect_refused(name, client_bin, config);
    assert_eq!(
        (
            code,
            diagnostic["error"]["code"].as_str(),
            diagnostic["error"]["retryable"].as_bool(),
        ),
        (Some(3), Some("CREDENTIAL_ERROR"), Some(false)),
        "step {name}: the relay's identity refusal must reach the device as a terminal \
         credential error: {out}"
    );
    let message = diagnostic["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("refused this device's identity"),
        "step {name}: {message}"
    );
    println!("m6c32 {name} exit=3 code=CREDENTIAL_ERROR retryable=false");
}

/// Review of M6-C32: a credential that is not valid *yet* is a clock
/// disagreement that heals by itself, so the device must see a retryable
/// failure, not the terminal identity refusal.
fn expect_retryable_refusal(name: &str, client_bin: &Path, config: &Path) {
    let (code, diagnostic, out) = connect_refused(name, client_bin, config);
    assert_eq!(
        (
            code,
            diagnostic["error"]["code"].as_str(),
            diagnostic["error"]["retryable"].as_bool(),
        ),
        (Some(4), Some("TRANSPORT_ERROR"), Some(true)),
        "step {name}: a not-yet-valid credential must stay retryable: {out}"
    );
    println!("m6c32 {name} exit=4 code=TRANSPORT_ERROR retryable=true");
}

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Rotation timing written into both shipped examples' `[rotation]` tables.
#[derive(Clone, Copy)]
struct Rotation {
    interval_seconds: u64,
    handshake_timeout_seconds: u64,
    overlap_seconds: u64,
}

fn with_rotation(document: &str, rotation: Rotation) -> String {
    let document = set_key(
        document,
        "interval_seconds",
        &rotation.interval_seconds.to_string(),
    );
    let document = set_key(
        &document,
        "handshake_timeout_seconds",
        &rotation.handshake_timeout_seconds.to_string(),
    );
    set_key(
        &document,
        "overlap_seconds",
        &rotation.overlap_seconds.to_string(),
    )
}

/// One relay brought up from an empty Redis namespace with the shipped
/// binaries: device key, CSR and certificate import, records dry run, first
/// incarnation, catalog provisioning and a listening `serve`.  The device is
/// not connected; each gate starts its own `connect`.
///
/// Fields drop in declaration order: the relay process stops before the
/// namespace is deleted and the work directory removed.
struct Provisioned {
    relay: Running,
    /// `serve`'s stderr lines after `tunnel-relay listening`, for failure
    /// messages.
    relay_log: std::sync::mpsc::Receiver<String>,
    nonce: String,
    namespace: String,
    work: PathBuf,
    pki: ServerPki,
    issuer_key: jsonwebtoken::EncodingKey,
    consumer: SocketAddr,
    device: Uuid,
    service: Uuid,
    subject: String,
    client_bin: PathBuf,
    client_config: PathBuf,
    server_ca: PathBuf,
    device_ca: PathBuf,
    device_ca_key: PathBuf,
    extensions: PathBuf,
    dry: String,
    upstream: SocketAddr,
    database: u32,
    _namespace_guard: NamespaceGuard,
    _dir: Workdir,
}

async fn provision_and_serve(tag: &str, rotation: Option<Rotation>) -> Provisioned {
    let redis_url = env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL (plaintext) is required");
    let client_bin = PathBuf::from(
        env::var_os("TUNNEL_CLIENT_BIN")
            .expect("TUNNEL_CLIENT_BIN must name a freshly built tunnel-client"),
    );
    // `TUNNEL_RELAY_BIN` points the gate at another relay build, such as a
    // release bundle's `bin/`; by default it is the one Cargo built for it.
    let relay_bin = env::var_os("TUNNEL_RELAY_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_tunnel-relay")));
    let (upstream, database) = parse_plaintext_redis(&redis_url);

    let nonce = Uuid::new_v4().simple().to_string();
    let namespace = format!("{tag}-{nonce}");
    let incarnation = format!("{tag}-{nonce}");
    // The records and the device profile are the shipped examples, used as
    // docs/operator.md uses them: an example whose identifiers disagree with
    // its partner makes this gate red.
    let examples = repository().join("examples");
    let catalog_example =
        fs::read_to_string(examples.join("m6-catalog.toml")).expect("read m6-catalog.toml");
    let catalog_value: toml::Value = toml::from_str(&catalog_example).expect("parse catalog");
    let id = |table: &str| -> Uuid {
        catalog_value[table]["id"]
            .as_str()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("m6-catalog.toml [{table}].id"))
    };
    let (device, service) = (id("device"), id("service"));
    let subject = catalog_value["user"]["oidc_subject"]
        .as_str()
        .expect("m6-catalog.toml [user].oidc_subject")
        .to_owned();
    let _namespace_guard = NamespaceGuard {
        upstream,
        database,
        namespace: namespace.clone(),
    };
    let dir = Workdir(env::temp_dir().join(format!("{tag}-{nonce}")));
    fs::create_dir_all(&dir.0).expect("create workdir");
    let work = dir.0.canonicalize().expect("canonical workdir");
    println!(
        "{tag} start nonce={nonce} namespace={namespace} relay={} client={} workdir={}",
        relay_bin.display(),
        client_bin.display(),
        work.display()
    );

    // Relay listener and Redis TLS stand-ins.
    let pki = server_pki();
    let server_ca = work.join("server-ca.pem");
    fs::write(&server_ca, &pki.ca_pem).expect("server CA");
    let server_chain = work.join("relay-cert-chain.pem");
    fs::write(&server_chain, &pki.chain_pem).expect("server chain");
    let server_key = work.join("relay-key.pem");
    fs::write(&server_key, &pki.key_pem).expect("server key");
    let redis_tls = redis_tls_forwarder(upstream, &pki).await;
    let (issuer_key, jwks) = oidc_issuer(&work);

    let consumer = free_port();
    let device_listener = free_port();

    // --- The device owner's steps, with the shipped client. ---
    let mut client_toml =
        fs::read_to_string(examples.join("m1-client.toml")).expect("read m1-client.toml");
    client_toml = set_key(
        &client_toml,
        "relay_url",
        &format!(
            "\"wss://127.0.0.1:{}/v1/tunnel/control\"",
            device_listener.port()
        ),
    );
    if let Some(rotation) = rotation {
        client_toml = with_rotation(&client_toml, rotation);
    }
    fs::create_dir_all(work.join("device")).expect("device dir");
    let client_config = work.join("device/client.toml");
    fs::write(&client_config, client_toml).expect("client config");
    step(
        "device key and CSR (tunnel-client credentials create)",
        Command::new(&client_bin)
            .args(["credentials", "create", "--config"])
            .arg(&client_config)
            .args(["--csr-out", "device.csr"]),
    );

    // --- The issuer's step: sign the CSR with the device role SAN. ---
    let device_ca_key = work.join("device-ca-key.pem");
    let device_ca = work.join("device-ca.pem");
    step(
        "device CA (openssl req -x509)",
        Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            ])
            .args(["-subj", "/CN=M6-C21 synthetic device CA", "-keyout"])
            .arg(&device_ca_key)
            .arg("-out")
            .arg(&device_ca)
            .stderr(Stdio::null()),
    );
    let extensions = work.join("device-ext.cnf");
    fs::write(
        &extensions,
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n\
             subjectAltName=URI:urn:agent-tunnel:device:{device}\n"
        ),
    )
    .expect("extensions");
    let device_cert = work.join("device/device-cert.pem");
    step(
        "issue device certificate (openssl x509 -req)",
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(work.join("device/device.csr"))
            .arg("-CA")
            .arg(&device_ca)
            .arg("-CAkey")
            .arg(&device_ca_key)
            .args(["-CAcreateserial", "-days", "1", "-extfile"])
            .arg(&extensions)
            .arg("-out")
            .arg(&device_cert),
    );
    step(
        "certificate import (tunnel-client credentials import)",
        Command::new(&client_bin)
            .args(["credentials", "import", "--config"])
            .arg(&client_config)
            .args(["--certificate", "device-cert.pem", "--server-ca"])
            .arg(&server_ca),
    );

    // --- The operator's steps, with the shipped relay. ---
    let mut relay_toml =
        fs::read_to_string(examples.join("m1-relay.toml")).expect("read m1-relay.toml");
    for (key, value) in [
        ("consumer_bind", format!("\"{consumer}\"")),
        ("device_bind", format!("\"{device_listener}\"")),
        ("oidc_issuer", format!("\"{ISSUER}\"")),
        ("oidc_jwks_path", toml_string(&jwks)),
        (
            "redis_url",
            format!("\"rediss://localhost:{}/{database}\"", redis_tls.port()),
        ),
        ("redis_namespace", format!("\"{namespace}\"")),
        ("device_tls_cert_chain", toml_string(&server_chain)),
        ("device_tls_private_key", toml_string(&server_key)),
        ("device_tls_client_ca", toml_string(&device_ca)),
        ("consumer_tls_cert_chain", toml_string(&server_chain)),
        ("consumer_tls_private_key", toml_string(&server_key)),
        ("boot_id", format!("\"m6c21-boot-{nonce}\"")),
        ("deployment_incarnation", format!("\"{incarnation}\"")),
    ] {
        relay_toml = set_key(&relay_toml, key, &value);
    }
    if let Some(rotation) = rotation {
        relay_toml = with_rotation(&relay_toml, rotation);
    }
    relay_toml = format!(
        "redis_tls_root_ca_path = {}\n{relay_toml}",
        toml_string(&server_ca)
    );
    let relay_config = work.join("relay.toml");
    fs::write(&relay_config, relay_toml).expect("relay config");

    // The records document sits beside the device certificate, as in the
    // guide, so its relative `certificate` path resolves unchanged.
    let records = work.join("device/catalog.toml");
    fs::write(&records, &catalog_example).expect("records");

    let dry = stdout(&step(
        "records dry run (tunnel-relay provision-catalog --dry-run)",
        Command::new(&relay_bin)
            .arg("provision-catalog")
            .arg("--config")
            .arg(&relay_config)
            .arg("--records")
            .arg(&records)
            .arg("--dry-run"),
    ));
    assert!(
        dry.contains(&format!("device={device}")) && dry.contains("contacted no Redis"),
        "dry run output: {dry}"
    );

    // `serve` refuses the empty namespace: this is what M6-C21 blocked on.
    let refused = Command::new(&relay_bin)
        .args(["serve", "--config"])
        .arg(&relay_config)
        .output()
        .expect("run serve before provisioning");
    let refused_stderr = String::from_utf8_lossy(&refused.stderr);
    assert!(
        refused.status.code() == Some(1)
            && refused_stderr.contains("Redis catalog connection failed; stage=authority_identity"),
        "step serve-before-activation: expected the incarnation fence refusal, got {:?}: {refused_stderr}",
        refused.status.code()
    );

    let activated = stdout(&step(
        "first incarnation (tunnel-relay activate-first-incarnation)",
        Command::new(&relay_bin)
            .args(["activate-first-incarnation", "--config"])
            .arg(&relay_config),
    ));
    assert!(activated.contains(&incarnation), "{activated}");
    let provisioned = stdout(&step(
        "catalog records (tunnel-relay provision-catalog)",
        Command::new(&relay_bin)
            .args(["provision-catalog", "--config"])
            .arg(&relay_config)
            .arg("--records")
            .arg(&records),
    ));
    assert!(
        provisioned.contains(&format!("device={device}"))
            && provisioned.contains(&format!("service={service}")),
        "{provisioned}"
    );

    let mut relay = Running(
        Command::new(&relay_bin)
            .args(["serve", "--config"])
            .arg(&relay_config)
            .env("RUST_LOG", "warn")
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn serve"),
    );
    let relay_stderr = relay.0.stderr.take().expect("serve stderr");
    let (listening_tx, listening_rx) = std::sync::mpsc::channel::<String>();
    std::thread::spawn(move || {
        for line in BufReader::new(relay_stderr).lines().map_while(Result::ok) {
            let _ = listening_tx.send(line);
        }
    });
    let deadline = Instant::now() + STEP_DEADLINE;
    let mut relay_lines = Vec::new();
    loop {
        match listening_rx.recv_timeout(Duration::from_millis(200)) {
            Ok(line) if line.starts_with("tunnel-relay listening") => break,
            Ok(line) => relay_lines.push(line),
            Err(_) => {}
        }
        if let Ok(Some(status)) = relay.0.try_wait() {
            panic!("step serve: exited {status} before listening: {relay_lines:?}");
        }
        assert!(
            Instant::now() < deadline,
            "step serve: not listening within {STEP_DEADLINE:?}: {relay_lines:?}"
        );
    }

    Provisioned {
        relay,
        relay_log: listening_rx,
        nonce,
        namespace,
        work,
        pki,
        issuer_key,
        consumer,
        device,
        service,
        subject,
        client_bin,
        client_config,
        server_ca,
        device_ca,
        device_ca_key,
        extensions,
        dry,
        upstream,
        database,
        _namespace_guard,
        _dir: dir,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m6c21_shipped_binaries_provision_one_relay_and_one_device_end_to_end() {
    let Provisioned {
        relay,
        relay_log: _,
        nonce,
        namespace,
        work,
        pki,
        issuer_key,
        consumer,
        device,
        service,
        subject,
        client_bin,
        client_config,
        server_ca,
        device_ca,
        device_ca_key,
        extensions,
        dry,
        upstream,
        database,
        _namespace_guard,
        _dir,
    } = provision_and_serve("m6c21-e2e", None).await;
    let client_log = work.join("connect.log");
    let _device = Running(
        Command::new(&client_bin)
            .args(["connect", "--config"])
            .arg(&client_config)
            .arg("--json")
            .stdout(fs::File::create(&client_log).expect("client log"))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect"),
    );

    // --- The consumer: one real echo through the relay to the device. ---
    let token = access_token(&issuer_key, &subject);
    let payload = format!("m6c21-e2e-payload-{nonce}");
    let path = format!("/v1/devices/{device}/services/{service}/echo");
    let deadline = Instant::now() + STEP_DEADLINE;
    let (status, body) = loop {
        let attempt = consumer_post(consumer, &pki.ca_pem, &path, &token, payload.as_bytes()).await;
        match attempt {
            Ok((200, body)) => break (200, body),
            Ok(other) if Instant::now() >= deadline => break other,
            Err(error) if Instant::now() >= deadline => {
                panic!(
                    "step echo: {error}; connect log: {}",
                    fs::read_to_string(&client_log).unwrap_or_default()
                )
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    };
    assert_eq!(
        status,
        200,
        "step echo: HTTP {status} {}; connect log: {}",
        String::from_utf8_lossy(&body),
        fs::read_to_string(&client_log).unwrap_or_default()
    );
    let expected = format!("{CANARY}{payload}");
    assert_eq!(
        String::from_utf8_lossy(&body),
        expected,
        "step echo: the reply must be the device's canary followed by the bytes sent"
    );

    // The same request under an identity nothing provisioned is refused, so
    // the 200 above was the provisioned grant's doing, not an open relay.
    let stranger = access_token(&issuer_key, "m6c21-unprovisioned-subject");
    let (stranger_status, _) =
        consumer_post(consumer, &pki.ca_pem, &path, &stranger, payload.as_bytes())
            .await
            .expect("stranger request completes");
    assert!(
        matches!(stranger_status, 401 | 403 | 404),
        "step stranger: an unprovisioned subject got HTTP {stranger_status}"
    );

    drop(_device);

    // --- M6-C32: identity refusals are terminal and say so. ---
    // (a) The profile's device_id is not the certificate's device.  The
    // certificate and catalog are the ones that just served the echo.
    let other_device = Uuid::new_v4();
    let mismatch_config = work.join("device/mismatched-device-id.toml");
    fs::write(
        &mismatch_config,
        set_key(
            &fs::read_to_string(&client_config).expect("read client config"),
            "device_id",
            &format!("\"{other_device}\""),
        ),
    )
    .expect("mismatched profile");
    expect_identity_refusal("device_id mismatch", &client_bin, &mismatch_config);

    // (b) A correctly issued certificate for the provisioned device whose key
    // the catalog does not know.
    fs::create_dir_all(work.join("stranger")).expect("stranger dir");
    let stranger_config = work.join("stranger/client.toml");
    fs::copy(&client_config, &stranger_config).expect("stranger profile");
    step(
        "stranger key and CSR (tunnel-client credentials create)",
        Command::new(&client_bin)
            .args(["credentials", "create", "--config"])
            .arg(&stranger_config)
            .args(["--csr-out", "device.csr"]),
    );
    step(
        "issue stranger certificate (openssl x509 -req)",
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(work.join("stranger/device.csr"))
            .arg("-CA")
            .arg(&device_ca)
            .arg("-CAkey")
            .arg(&device_ca_key)
            .args(["-CAcreateserial", "-days", "1", "-extfile"])
            .arg(&extensions)
            .arg("-out")
            .arg(work.join("stranger/device-cert.pem")),
    );
    step(
        "stranger certificate import (tunnel-client credentials import)",
        Command::new(&client_bin)
            .args(["credentials", "import", "--config"])
            .arg(&stranger_config)
            .args(["--certificate", "device-cert.pem", "--server-ca"])
            .arg(&server_ca),
    );
    expect_identity_refusal("unknown credential key", &client_bin, &stranger_config);

    // (c) The provisioned credential with its catalog `not_before` moved an
    // hour ahead: the certificate still passes TLS, and the catalog says the
    // credential is not valid yet.  This is the relay-behind-issuer clock
    // case; it must not be reported as a refused identity.
    let spki = dry
        .split_whitespace()
        .find_map(|field| field.strip_prefix("spki_sha256="))
        .expect("the dry run prints spki_sha256=")
        .trim_end_matches('.')
        .to_owned();
    let index = format!("tunnel-catalog:{namespace}:idx:fingerprint:{spki}");
    let reply = redis_command(upstream, database, &["GET", &index]);
    let credential_key = String::from_utf8_lossy(&reply)
        .split("\r\n")
        .find(|line| line.starts_with("tunnel-catalog:"))
        .expect("the provisioned credential's index resolves to its key")
        .to_owned();
    let future_us = (chrono::Utc::now().timestamp() + 3600) * 1_000_000;
    redis_command(
        upstream,
        database,
        &[
            "HSET",
            &credential_key,
            "not_before_us",
            &future_us.to_string(),
        ],
    );
    expect_retryable_refusal("credential not yet valid", &client_bin, &client_config);

    drop(relay);
    let removed = delete_namespace(upstream, database, &namespace);
    println!(
        "m6c21-e2e ok nonce={nonce} namespace={namespace} echo_status={status} \
         echo_bytes={} stranger_status={stranger_status} keys_removed={removed}",
        body.len()
    );
}

/// Parse the `--json` status lines `connect` has written so far and return
/// the distinct session IDs and the highest completed-rotation count.
fn connect_sessions_and_rotations(log: &Path) -> (Vec<String>, u64) {
    let text = fs::read_to_string(log).unwrap_or_default();
    let mut sessions: Vec<String> = Vec::new();
    let mut rotations = 0;
    for line in text.lines() {
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let result = &value["result"];
        if let Some(session) = result["session_id"].as_str()
            && !sessions.iter().any(|known| known == session)
        {
            sessions.push(session.to_owned());
        }
        rotations = rotations.max(result["rotations_completed"].as_u64().unwrap_or(0));
    }
    (sessions, rotations)
}

/// The connector's OPEN retention: `retained_stream_limit(DEFAULT_MAX_STREAMS)`
/// = min(64 x 2, `MAX_JOURNAL_ENTRIES` = 128).  Restated, not imported, so
/// the gates keep their meaning if either constant moves.
const CONNECTOR_OPEN_RETENTION: usize = 128;
/// A rotation pauses echo admission with a retryable `RESOURCE_EXHAUSTED`
/// that was `not_dispatched`; one request may be refused this many times.
const MAX_FREEZE_REFUSALS: usize = 400;
/// The shortest rotation timing the policy accepts (handshake < overlap <
/// interval, whole seconds), in both the relay and the device profile.
const FAST_ROTATION: Rotation = Rotation {
    interval_seconds: 3,
    handshake_timeout_seconds: 1,
    overlap_seconds: 2,
};

/// What one sequential-echo gate must show.
struct EchoRun {
    tag: &'static str,
    /// Echoes that must be answered 200, after one uncounted warm-up.
    required_echoes: usize,
    /// Completed data rotations the same session must also cross.
    required_rotations: u64,
    /// Pause after each echo, so a run spans rotations with few requests.
    pace: Duration,
    /// Upper bound on counted echoes; `None` for no bound.
    max_echoes: Option<usize>,
}

struct EchoRunResult {
    served: usize,
    rotations: u64,
    freeze_refusals: usize,
    elapsed: Duration,
    nonce: String,
    namespace: String,
}

/// Bring up one relay and one device with the shipped binaries and send
/// sequential unary echoes through one device session until `run` is
/// satisfied.  Every echo must return 200 with the canary and exactly the
/// bytes sent; the only tolerated refusal is a rotation freeze's retryable
/// `RESOURCE_EXHAUSTED`/`not_dispatched`.  One session ID across the run
/// proves nothing was served by a reconnect.
async fn run_sequential_echoes(run: EchoRun) -> EchoRunResult {
    let fixture = provision_and_serve(run.tag, Some(FAST_ROTATION)).await;
    let client_log = fixture.work.join("connect.log");
    let client_stderr = fixture.work.join("connect.stderr.log");
    let mut device = Running(
        Command::new(&fixture.client_bin)
            .args(["connect", "--config"])
            .arg(&fixture.client_config)
            .arg("--json")
            .env("RUST_LOG", "info")
            .stdout(fs::File::create(&client_log).expect("client log"))
            .stderr(fs::File::create(&client_stderr).expect("client stderr"))
            .spawn()
            .expect("spawn connect"),
    );
    let token = access_token(&fixture.issuer_key, &fixture.subject);
    let path = format!(
        "/v1/devices/{}/services/{}/echo",
        fixture.device, fixture.service
    );
    // Failure context: the device's `--json` events, the tail of its log
    // and the relay's warnings.
    let log = || {
        let stderr = fs::read_to_string(&client_stderr).unwrap_or_default();
        let tail: Vec<&str> = stderr.lines().rev().take(40).collect();
        format!(
            "{}\nconnect stderr (last 40 lines, newest first):\n{}\nrelay stderr:\n{}",
            fs::read_to_string(&client_log).unwrap_or_default(),
            tail.join("\n"),
            fixture.relay_log.try_iter().collect::<Vec<_>>().join("\n")
        )
    };

    // Wait for the device: the first request is retried only until the
    // session is up, and is not counted.
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        match consumer_post(
            fixture.consumer,
            &fixture.pki.ca_pem,
            &path,
            &token,
            b"warm",
        )
        .await
        {
            Ok((200, _)) => break,
            _ if Instant::now() >= deadline => {
                panic!("step warm-up: device not serving; connect log: {}", log())
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
    let (initial_sessions, _) = connect_sessions_and_rotations(&client_log);

    let started = Instant::now();
    let run_deadline = started + Duration::from_secs(120);
    let mut served = 0_usize;
    let mut freeze_refusals = 0_usize;
    let mut rotations = 0;
    while served < run.required_echoes || rotations < run.required_rotations {
        assert!(
            Instant::now() < run_deadline,
            "step sequential echoes: {served} served and {rotations} rotations within 120 s; \
             connect log: {}",
            log()
        );
        if let Some(max_echoes) = run.max_echoes {
            assert!(
                served < max_echoes,
                "step sequential echoes: {rotations} of {} rotations after the {max_echoes} \
                 echoes this gate may send; connect log: {}",
                run.required_rotations,
                log()
            );
        }
        if let Ok(Some(status)) = device.0.try_wait() {
            panic!(
                "step sequential echoes: connect exited {status} after {served} echoes; \
                 connect log: {}",
                log()
            );
        }
        let request = served + 1;
        // Vary the size so the defect cannot hide behind one body length:
        // empty, small and the 64 KiB frame maximum all recur.
        let size = match request % 4 {
            0 => 0,
            1 => 17,
            2 => 4096,
            _ => 65_536,
        };
        let payload: Vec<u8> = (0..size)
            .map(|index| (index * 31 + request) as u8)
            .collect();
        let mut refusals = 0;
        let (status, body) = loop {
            let (status, body) = consumer_post(
                fixture.consumer,
                &fixture.pki.ca_pem,
                &path,
                &token,
                &payload,
            )
            .await
            .unwrap_or_else(|error| panic!("step echo {request}: {error}; connect log: {}", log()));
            let text = String::from_utf8_lossy(&body);
            let frozen = status == 503
                && text.contains("\"RESOURCE_EXHAUSTED\"")
                && text.contains("\"not_dispatched\"");
            if frozen && refusals < MAX_FREEZE_REFUSALS {
                refusals += 1;
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            break (status, body);
        };
        freeze_refusals += refusals;
        assert_eq!(
            status,
            200,
            "step echo {request} (session request {}, after one warm-up): HTTP {status} {} \
             after {refusals} rotation refusals, {rotations} rotations so far; connect log: {}",
            request + 1,
            String::from_utf8_lossy(&body),
            log()
        );
        let mut expected = CANARY.as_bytes().to_vec();
        expected.extend_from_slice(&payload);
        assert!(
            body == expected,
            "step echo {request}: the reply must be the canary followed by the {size} bytes sent"
        );
        served = request;
        if !run.pace.is_zero() {
            tokio::time::sleep(run.pace).await;
        }
        if served.is_multiple_of(10) || served >= run.required_echoes {
            rotations = connect_sessions_and_rotations(&client_log).1;
        }
    }
    let elapsed = started.elapsed();
    let (sessions, rotations) = connect_sessions_and_rotations(&client_log);
    assert_eq!(
        sessions.len(),
        1,
        "every echo must be served by one device session, not by reconnects: {sessions:?} \
         (before the run: {initial_sessions:?})"
    );
    drop(device);
    let nonce = fixture.nonce.clone();
    let namespace = fixture.namespace.clone();
    drop(fixture);
    EchoRunResult {
        served,
        rotations,
        freeze_refusals,
        elapsed,
        nonce,
        namespace,
    }
}

/// Task row M7-C92 (M6-C62 on branch `m6-dogfood-local`): the unary echo
/// path must serve an unbounded number of sequential requests in one device
/// session, across data rotations.  Before M7-C92 the relay never issued the
/// owner `STREAM_FORGET` for a completed unary echo, so the connector's OPEN
/// journal filled at 128 entries and request 129 of every session failed
/// `503 DEVICE_REJECTED` until the device restarted.  The run sends more
/// than twice the retention, so a fix that merely doubled it stays red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m7c92_sequential_unary_echoes_outlive_the_connector_open_retention() {
    let required = 2 * CONNECTOR_OPEN_RETENTION + 44;
    let result = run_sequential_echoes(EchoRun {
        tag: "m7c92-echo",
        required_echoes: required,
        required_rotations: 2,
        pace: Duration::ZERO,
        max_echoes: None,
    })
    .await;
    println!(
        "m7c92-echo ok nonce={} namespace={} echoes={} required={required} sessions=1 \
         rotations={} freeze_refusals={} retention={CONNECTOR_OPEN_RETENTION} elapsed_ms={}",
        result.nonce,
        result.namespace,
        result.served,
        result.rotations,
        result.freeze_refusals,
        result.elapsed.as_millis()
    );
}

/// Task row M7-C93: a unary echo in flight when a data rotation freezes the
/// writers must neither kill the session nor be lost.  Before M7-C93 the
/// relay fenced a dispatched echo at its DATA sequence although its FIN was
/// already sent, so the connector failed the session with "local drain
/// rejected: stream N acknowledgement 2 is above fence 1"; an echo that
/// finished after QUIESCE vanished from the fence ("rotation fence rosters
/// differ"); and an authorization result during the freeze dispatched DATA
/// and FIN past the frozen fence.  The echoes are paced so two rotations
/// fit inside the connector's 128-entry retention: this gate is red for the
/// rotation defect alone, never for M7-C92's.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m7c93_unary_echoes_in_flight_cross_data_rotations() {
    let max_echoes = CONNECTOR_OPEN_RETENTION - 8;
    let result = run_sequential_echoes(EchoRun {
        tag: "m7c93-rotation",
        required_echoes: 1,
        required_rotations: 2,
        pace: Duration::from_millis(60),
        max_echoes: Some(max_echoes),
    })
    .await;
    println!(
        "m7c93-rotation ok nonce={} namespace={} echoes={} max={max_echoes} sessions=1 \
         rotations={} freeze_refusals={} elapsed_ms={}",
        result.nonce,
        result.namespace,
        result.served,
        result.rotations,
        result.freeze_refusals,
        result.elapsed.as_millis()
    );
}
