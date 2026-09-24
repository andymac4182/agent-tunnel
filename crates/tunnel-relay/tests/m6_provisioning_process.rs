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
//! * **the consumer** is an HTTPS request made from this test;
//! * **the M6-C57 backends** are the repository's synthetic MCP server and
//!   ACP agent (`TUNNEL_MCP_FIXTURE_BIN`, `TUNNEL_ACP_FIXTURE_BIN`) and a
//!   temporary directory holding one generated file.
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
async fn redis_tls_forwarder(
    upstream: SocketAddr,
    pki: &ServerPki,
    client_ca_pem: Option<&str>,
) -> SocketAddr {
    let server_config = tunnel_transport::load_server_config_from_pem(
        pki.chain_pem.as_bytes(),
        pki.key_pem.as_bytes(),
        client_ca_pem.map(str::as_bytes),
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

/// Removes this run's ACL user however the test ends.
struct AclUserGuard {
    upstream: SocketAddr,
    database: u32,
    user: String,
}

impl Drop for AclUserGuard {
    fn drop(&mut self) {
        redis_command(
            self.upstream,
            self.database,
            &["ACL", "DELUSER", &self.user],
        );
    }
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
    access_token_with_scope(key, subject, "echo:invoke")
}

fn access_token_with_scope(key: &jsonwebtoken::EncodingKey, subject: &str, scope: &str) -> String {
    let now = chrono::Utc::now().timestamp();
    let mut header = jsonwebtoken::Header::new(jsonwebtoken::Algorithm::RS256);
    header.kid = Some("m6c21-issuer".to_owned());
    jsonwebtoken::encode(
        &header,
        &serde_json::json!({
            "iss": ISSUER, "aud": AUDIENCE, "sub": subject,
            "iat": now, "exp": now + 300, "scope": scope
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
    consumer_request(
        consumer,
        server_ca_pem,
        "POST",
        path,
        token,
        &[("content-type", "application/octet-stream")],
        body,
    )
    .await
    .map(|(status, _, body)| (status, body))
}

/// A TLS client configuration trusting only the synthetic server CA.
fn consumer_tls(server_ca_pem: &str) -> Result<rustls::ClientConfig, String> {
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut server_ca_pem.as_bytes()) {
        roots
            .add(certificate.map_err(|error| error.to_string())?)
            .map_err(|error| error.to_string())?;
    }
    Ok(rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .map_err(|error| error.to_string())?
    .with_root_certificates(roots)
    .with_no_client_auth())
}

/// One HTTPS request to the relay's consumer listener with the caller's
/// headers, bounded by [`STEP_DEADLINE`].  Sends no `User-Agent` (M6-C58).
async fn consumer_request(
    consumer: SocketAddr,
    server_ca_pem: &str,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, hyper::HeaderMap, Vec<u8>), String> {
    tokio::time::timeout(
        STEP_DEADLINE,
        consumer_request_unbounded(
            consumer,
            server_ca_pem,
            false,
            method,
            path,
            token,
            headers,
            body,
        ),
    )
    .await
    .map_err(|_| format!("consumer {method} {path}: no answer within {STEP_DEADLINE:?}"))?
}

/// [`consumer_request`] over HTTP/2 (ALPN `h2`), which the ACP profile
/// requires.
async fn consumer_request_h2(
    consumer: SocketAddr,
    server_ca_pem: &str,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, hyper::HeaderMap, Vec<u8>), String> {
    tokio::time::timeout(
        STEP_DEADLINE,
        consumer_request_unbounded(
            consumer,
            server_ca_pem,
            true,
            method,
            path,
            token,
            headers,
            body,
        ),
    )
    .await
    .map_err(|_| format!("consumer {method} {path}: no answer within {STEP_DEADLINE:?}"))?
}

#[allow(clippy::too_many_arguments)]
async fn consumer_request_unbounded(
    consumer: SocketAddr,
    server_ca_pem: &str,
    http2: bool,
    method: &str,
    path: &str,
    token: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> Result<(u16, hyper::HeaderMap, Vec<u8>), String> {
    let mut config = consumer_tls(server_ca_pem)?;
    if http2 {
        config.alpn_protocols = vec![b"h2".to_vec()];
    }
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
    let mut request = hyper::Request::builder().method(method);
    request = if http2 {
        request
            .version(hyper::Version::HTTP_2)
            .uri(format!("https://127.0.0.1:{}{path}", consumer.port()))
    } else {
        request.uri(path).header("host", consumer.to_string())
    };
    request = request.header("authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        request = request.header(*name, *value);
    }
    let request = request
        .body(Full::new(bytes::Bytes::copy_from_slice(body)))
        .map_err(|error| error.to_string())?;
    let io = TokioIo::new(tls);
    let response = if http2 {
        let (mut sender, connection) =
            hyper::client::conn::http2::handshake(hyper_util::rt::TokioExecutor::new(), io)
                .await
                .map_err(|error| format!("consumer HTTP/2: {error}"))?;
        tokio::spawn(connection);
        sender.send_request(request).await
    } else {
        let (mut sender, connection) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|error| format!("consumer HTTP: {error}"))?;
        tokio::spawn(connection);
        sender.send_request(request).await
    }
    .map_err(|error| format!("consumer request: {error}"))?;
    let status = response.status().as_u16();
    let response_headers = response.headers().clone();
    let bytes = response
        .into_body()
        .collect()
        .await
        .map_err(|error| format!("consumer body: {error}"))?
        .to_bytes()
        .to_vec();
    Ok((status, response_headers, bytes))
}

/// Run `connect --json` once for a profile the relay must not admit, and
/// return its exit status, its last JSON diagnostic and its raw stdout.
fn connect_refused(
    name: &str,
    client_bin: &Path,
    config: &Path,
    extra: &[&str],
) -> (Option<i32>, serde_json::Value, String) {
    let mut child = Command::new(client_bin)
        .args(["connect", "--config"])
        .arg(config)
        .arg("--json")
        .args(extra)
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
///
/// Run with `connect`'s default reconnect policy on (M6-C23): the refusal
/// must end the process after one attempt, with no `backoff` event.
fn expect_identity_refusal(name: &str, client_bin: &Path, config: &Path) {
    let (code, diagnostic, out) = connect_refused(name, client_bin, config, &[]);
    assert!(
        !out.contains("\"state\":\"backoff\""),
        "step {name}: a terminal identity refusal must not be retried: {out}"
    );
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
///
/// Run with `--no-reconnect`: with reconnect on (M6-C23) a retryable refusal
/// is retried rather than reported as the exit, and this helper is about the
/// status the first attempt selects.
fn expect_retryable_refusal(name: &str, client_bin: &Path, config: &Path) {
    let (code, diagnostic, out) = connect_refused(name, client_bin, config, &["--no-reconnect"]);
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

/// Start `serve` and wait for `tunnel-relay listening`; its stderr lines
/// after that arrive on the returned channel.
fn start_serve(
    relay_bin: &Path,
    relay_config: &Path,
) -> (Running, std::sync::mpsc::Receiver<String>) {
    let mut relay = Running(
        Command::new(relay_bin)
            .args(["serve", "--config"])
            .arg(relay_config)
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
    (relay, listening_rx)
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
    /// The relay binary and configuration the day-2 commands use (M6-C31).
    relay_bin: PathBuf,
    relay_config: PathBuf,
}

/// The service type one gate provisions (task row M6-C57), and what the relay
/// configuration and the device profile need in order to serve it.  Each
/// provisions from its own shipped records example, verbatim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ServiceKind {
    Echo,
    Mcp,
    Acp,
    Fs,
}

/// The synthetic file the filesystem gate reads through the relay.
const FS_FILE_NAME: &str = "synthetic.txt";

impl ServiceKind {
    fn records_example(self) -> &'static str {
        match self {
            Self::Echo => "m6-catalog.toml",
            Self::Mcp => "m6-catalog-mcp.toml",
            Self::Acp => "m6-catalog-acp.toml",
            Self::Fs => "m6-catalog-fs.toml",
        }
    }

    /// Tables appended to the relay configuration: the `[http_forward]`
    /// profile the records example names, as that example's comment says.
    fn relay_tables(self, records: &toml::Value) -> String {
        match records["service"].get("http_forward_profile") {
            Some(profile) => format!("\n[http_forward]\nprofiles = [{profile}]\n"),
            None => String::new(),
        }
    }

    /// The export table replacing `examples/m1-client.toml`'s echo export,
    /// shaped as the records example's comment documents it.  Every backend
    /// is synthetic: the repository's MCP and ACP fixture binaries and a
    /// temporary directory holding one generated file.
    fn client_export(self, work: &Path, service: Uuid, nonce: &str) -> Option<String> {
        let fixture = |variable: &str| -> PathBuf {
            PathBuf::from(
                env::var_os(variable)
                    .unwrap_or_else(|| panic!("{variable} must name a freshly built fixture")),
            )
        };
        let workspace = |name: &str| -> PathBuf {
            let path = work.join("device").join(name);
            fs::create_dir_all(&path).expect("export workspace");
            path
        };
        match self {
            Self::Echo => None,
            Self::Mcp => Some(format!(
                "[exports.\"{service}\"]\ntype = \"http-forward\"\n\n\
                 [exports.\"{service}\".mcp]\nprofile = \"mcp-2025-11-25\"\n\n\
                 [exports.\"{service}\".mcp.backend]\nkind = \"stdio\"\ncommand = {}\n\
                 args = [\"stdio\"]\nworkspace = {}\n",
                toml_string(&fixture("TUNNEL_MCP_FIXTURE_BIN")),
                toml_string(&workspace("mcp-workspace")),
            )),
            Self::Acp => Some(format!(
                "[exports.\"{service}\"]\ntype = \"http-forward\"\n\n\
                 [exports.\"{service}\".acp]\nprofile = \"acp-http-v1\"\n\n\
                 [exports.\"{service}\".acp.agent]\ncommand = {}\nargs = [\"agent\"]\n\
                 workspace = {}\n",
                toml_string(&fixture("TUNNEL_ACP_FIXTURE_BIN")),
                toml_string(&workspace("acp-workspace")),
            )),
            Self::Fs => {
                let root = workspace("fs-root");
                fs::write(
                    root.join(FS_FILE_NAME),
                    format!("m6c57 synthetic file {nonce}\n"),
                )
                .expect("synthetic file");
                Some(format!(
                    "[exports.\"{service}\"]\ntype = \"fs\"\n\n\
                     [exports.\"{service}\".fs]\nroot = {}\ncapabilities = [\"read\", \"list\"]\n",
                    toml_string(&root),
                ))
            }
        }
    }
}

/// Replace the one `[exports.*]` table of a shipped client example (the
/// header and its lines up to the next blank line) with `export`.
fn replace_export(document: &str, export: &str) -> String {
    let lines: Vec<&str> = document.lines().collect();
    let start = lines
        .iter()
        .position(|line| line.starts_with("[exports."))
        .expect("the shipped client example has an [exports.*] table");
    let end = lines[start..]
        .iter()
        .position(|line| line.trim().is_empty())
        .map_or(lines.len(), |offset| start + offset);
    assert!(
        !lines[end..]
            .iter()
            .any(|line| line.starts_with("[exports.")),
        "the shipped client example has more than one export table"
    );
    let mut out: Vec<String> = lines[..start]
        .iter()
        .map(|line| (*line).to_owned())
        .collect();
    out.push(export.trim_end().to_owned());
    out.extend(lines[end..].iter().map(|line| (*line).to_owned()));
    out.join("\n") + "\n"
}

async fn provision_and_serve(tag: &str, rotation: Option<Rotation>) -> Provisioned {
    provision_and_serve_kind(tag, rotation, ServiceKind::Echo).await
}

async fn provision_and_serve_kind(
    tag: &str,
    rotation: Option<Rotation>,
    kind: ServiceKind,
) -> Provisioned {
    provision_and_serve_with(tag, rotation, kind, ProvisionOptions::default()).await
}

/// What a gate may change in the shared bring-up.
#[derive(Default)]
struct ProvisionOptions {
    /// A plaintext Redis the gate owns, instead of `TEST_REDIS_URL`.
    redis_url: Option<String>,
    /// Top-level relay configuration lines added to the shipped example.
    relay_top_level: String,
    /// Skip the four M6-C72 failing activations (other gates prove them).
    skip_stage_cases: bool,
}

async fn provision_and_serve_with(
    tag: &str,
    rotation: Option<Rotation>,
    kind: ServiceKind,
    options: ProvisionOptions,
) -> Provisioned {
    let redis_url = options.redis_url.clone().unwrap_or_else(|| {
        env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL (plaintext) is required")
    });
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
    let records_example = kind.records_example();
    let catalog_example = fs::read_to_string(examples.join(records_example))
        .unwrap_or_else(|error| panic!("read {records_example}: {error}"));
    let catalog_value: toml::Value = toml::from_str(&catalog_example).expect("parse catalog");
    let id = |table: &str| -> Uuid {
        catalog_value[table]["id"]
            .as_str()
            .and_then(|value| value.parse().ok())
            .unwrap_or_else(|| panic!("{records_example} [{table}].id"))
    };
    let (device, service) = (id("device"), id("service"));
    let subject = catalog_value["user"]["oidc_subject"]
        .as_str()
        .unwrap_or_else(|| panic!("{records_example} [user].oidc_subject"))
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
    let redis_tls = redis_tls_forwarder(upstream, &pki, None).await;
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
    if let Some(export) = kind.client_export(&work, service, &nonce) {
        client_toml = replace_export(&client_toml, &export);
    }
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
        "redis_tls_root_ca_path = {}\n{}{relay_toml}{}",
        toml_string(&server_ca),
        options.relay_top_level,
        kind.relay_tables(&catalog_value)
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

    // M6-C72 (M6-C71 on `m6-fly-deploy`, M6-C59): a Redis connection
    // failure during the first activation names its own stage and class,
    // and prints neither the URL nor a password.  Each case fails before any
    // write, so the namespace stays empty for the real activation below.
    let redis_authority = format!("localhost:{}/{database}", redis_tls.port());
    let wrong_ca = work.join("unrelated-ca.pem");
    fs::write(&wrong_ca, server_pki().ca_pem).expect("unrelated CA");
    let base_toml = fs::read_to_string(&relay_config).expect("relay config");
    // A Redis endpoint that requires a client certificate the relay does not
    // present (the configuration has no client certificate fields).
    let mtls_redis = redis_tls_forwarder(upstream, &pki, Some(&server_pki().ca_pem)).await;
    let wrong_password = format!("m6c72-wrong-{nonce}");
    let acl_user = format!("m6c72-noinfo-{nonce}");
    let acl_password = format!("m6c72-pass-{nonce}");
    let _acl_guard = AclUserGuard {
        upstream,
        database,
        user: acl_user.clone(),
    };
    let created = redis_command(
        upstream,
        database,
        &[
            "ACL",
            "SETUSER",
            &acl_user,
            "on",
            &format!(">{acl_password}"),
            "~*",
            "+@all",
            "-info",
        ],
    );
    assert!(
        String::from_utf8_lossy(&created).matches("+OK").count() >= 2,
        "create the no-INFO ACL user: {}",
        String::from_utf8_lossy(&created)
    );
    let stage_cases = if options.skip_stage_cases {
        Vec::new()
    } else {
        vec![
            (
                "wrong Redis CA",
                base_toml.replace(&toml_string(&server_ca), &toml_string(&wrong_ca)),
                None,
                "Redis catalog connection failed; stage=connection_establishment class=tls_certificate",
            ),
            (
                "wrong Redis password",
                set_key(
                    &base_toml,
                    "redis_url",
                    &format!(
                        "\"rediss://m6c72-nouser-{nonce}:{wrong_password}@{redis_authority}\""
                    ),
                ),
                Some(wrong_password.as_str()),
                "Redis catalog connection failed; stage=connection_establishment class=auth",
            ),
            (
                "ACL user without INFO",
                set_key(
                    &base_toml,
                    "redis_url",
                    &format!("\"rediss://{acl_user}:{acl_password}@{redis_authority}\""),
                ),
                Some(acl_password.as_str()),
                "Redis catalog connection failed; stage=primary_identity class=noperm",
            ),
            (
                "missing client certificate",
                set_key(
                    &base_toml,
                    "redis_url",
                    &format!("\"rediss://localhost:{}/{database}\"", mtls_redis.port()),
                ),
                None,
                "Redis catalog connection failed; stage=connection_establishment class=tls_alert",
            ),
        ]
    };
    for (case, toml, secret, expected) in stage_cases {
        let config = work.join(format!("relay-{}.toml", case.replace(' ', "-")));
        fs::write(&config, toml).expect("case config");
        let output = Command::new(&relay_bin)
            .args(["activate-first-incarnation", "--config"])
            .arg(&config)
            .output()
            .expect("run activate-first-incarnation");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.code() == Some(1) && stderr.contains(expected),
            "step activate with {case}: expected `{expected}`, got {:?}: {stderr}",
            output.status.code()
        );
        assert!(
            !stderr.contains("rediss://") && !stderr.contains(&redis_authority),
            "step activate with {case}: stderr names the Redis URL: {stderr}"
        );
        if let Some(secret) = secret {
            assert!(
                !stderr.contains(secret),
                "step activate with {case}: stderr prints the password"
            );
        }
        println!("m6c72-stage ok case={case} expected={expected}");
    }

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

    let (relay, listening_rx) = start_serve(&relay_bin, &relay_config);

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
        relay_bin,
        relay_config,
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
        ..
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

// ---------------------------------------------------------------------------
// Task row M6-C57: every service type the alpha serves can be provisioned.
//
// Before M6-C57 `provision-catalog` wrote `{"operations": [...]}` as every
// service's capabilities, which serves echo only: the relay selects an
// http-forward profile by `http_forward_profile` and describes a filesystem
// export only with `fs_case_sensitivity`, so a provisioned MCP, ACP or
// filesystem service was answered 404 on every request after a dry run and a
// write that both succeeded.  Each gate below provisions from its shipped
// records example with the shipped commands, starts `serve` and `connect`
// with the export that example documents, and requires one real consumer
// request to be answered by the device-side backend.

/// Bring up the relay and the device for `kind`, returning the fixture and the
/// running `connect` with its log paths.
async fn serve_kind(tag: &str, kind: ServiceKind) -> (Provisioned, Running, PathBuf, PathBuf) {
    let fixture = provision_and_serve_kind(tag, None, kind).await;
    assert!(
        fixture
            .dry
            .contains(&format!("service={}", fixture.service)),
        "dry run output: {}",
        fixture.dry
    );
    let client_log = fixture.work.join("connect.log");
    let client_stderr = fixture.work.join("connect.stderr.log");
    let device = Running(
        Command::new(&fixture.client_bin)
            .args(["connect", "--config"])
            .arg(&fixture.client_config)
            .arg("--json")
            .env("RUST_LOG", "warn")
            .stdout(fs::File::create(&client_log).expect("client log"))
            .stderr(fs::File::create(&client_stderr).expect("client stderr"))
            .spawn()
            .expect("spawn connect"),
    );
    (fixture, device, client_log, client_stderr)
}

/// Failure context: the device's `--json` events and stderr tail.
fn device_log(client_log: &Path, client_stderr: &Path) -> String {
    let stderr = fs::read_to_string(client_stderr).unwrap_or_default();
    let tail: Vec<&str> = stderr.lines().rev().take(20).collect();
    format!(
        "{}\nconnect stderr (last 20 lines, newest first):\n{}",
        fs::read_to_string(client_log).unwrap_or_default(),
        tail.join("\n")
    )
}

/// The JSON-RPC reply carrying `id` in a JSON or `text/event-stream` body.
fn jsonrpc_reply(body: &[u8], id: &serde_json::Value) -> Option<serde_json::Value> {
    let text = String::from_utf8_lossy(body);
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&text) {
        return (value.get("id") == Some(id)).then_some(value);
    }
    text.split("\n\n").find_map(|event| {
        let data: Vec<&str> = event
            .lines()
            .filter_map(|line| line.strip_prefix("data:"))
            .map(str::trim_start)
            .collect();
        let value: serde_json::Value = serde_json::from_str(&data.join("\n")).ok()?;
        (value.get("id") == Some(id)).then_some(value)
    })
}

type Answer = (u16, hyper::HeaderMap, Vec<u8>);

/// Send `request` until the device session is up: a refusal before the
/// device registers is retried until [`STEP_DEADLINE`], then reported.
async fn until_served<F, Fut>(name: &str, mut request: F, context: impl Fn() -> String) -> Answer
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<Answer, String>>,
{
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        match request().await {
            Ok(answer) if answer.0 == 200 => return answer,
            Ok((status, _, body)) if Instant::now() >= deadline => panic!(
                "step {name}: HTTP {status} {}; {}",
                String::from_utf8_lossy(&body),
                context()
            ),
            Err(error) if Instant::now() >= deadline => {
                panic!("step {name}: {error}; {}", context())
            }
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

const MCP_HEADERS: [(&str, &str); 2] = [
    ("content-type", "application/json"),
    ("accept", "application/json, text/event-stream"),
];

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL, TUNNEL_CLIENT_BIN and TUNNEL_MCP_FIXTURE_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m6c57_provisioned_mcp_service_answers_initialize_and_a_tool_call() {
    let (fixture, device, client_log, client_stderr) =
        serve_kind("m6c57-mcp", ServiceKind::Mcp).await;
    assert!(
        fixture
            .dry
            .contains("service_type=http-forward http_forward_profile=mcp-2025-11-25"),
        "dry run output: {}",
        fixture.dry
    );
    let context = || device_log(&client_log, &client_stderr);
    let token = access_token_with_scope(&fixture.issuer_key, &fixture.subject, "http:invoke");
    let path = format!(
        "/v1/devices/{}/services/{}/http/mcp",
        fixture.device, fixture.service
    );

    // 1. initialize, retried only until the device session is up.
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {"name": "m6c57-gate", "version": "1"},
        },
    })
    .to_string();
    let (_, headers, body) = until_served(
        "mcp initialize",
        || {
            consumer_request(
                fixture.consumer,
                &fixture.pki.ca_pem,
                "POST",
                &path,
                &token,
                &MCP_HEADERS,
                initialize.as_bytes(),
            )
        },
        context,
    )
    .await;
    let initialized = jsonrpc_reply(&body, &serde_json::json!(1)).unwrap_or_else(|| {
        panic!(
            "step mcp initialize: no JSON-RPC reply with id 1: {}",
            String::from_utf8_lossy(&body)
        )
    });
    assert_eq!(
        initialized["result"]["protocolVersion"].as_str(),
        Some("2025-11-25"),
        "step mcp initialize: {initialized}"
    );
    let session = headers
        .get("mcp-session-id")
        .and_then(|value| value.to_str().ok())
        .expect("step mcp initialize: the 2025-11-25 profile returns an Mcp-Session-Id")
        .to_owned();
    let mut session_headers = MCP_HEADERS.to_vec();
    session_headers.push(("mcp-protocol-version", "2025-11-25"));
    session_headers.push(("mcp-session-id", session.as_str()));

    // 2. notifications/initialized.
    let (notification_status, _, body) = consumer_request(
        fixture.consumer,
        &fixture.pki.ca_pem,
        "POST",
        &path,
        &token,
        &session_headers,
        br#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
    )
    .await
    .expect("step mcp initialized notification");
    assert_eq!(
        notification_status,
        202,
        "step mcp initialized notification: {}",
        String::from_utf8_lossy(&body)
    );

    // 3. tools/call of the fixture's `echo` tool with a per-run marker.
    let marker = format!("m6c57-mcp-{}", fixture.nonce);
    let call = serde_json::json!({
        "jsonrpc": "2.0", "id": 2, "method": "tools/call",
        "params": {"name": "echo", "arguments": {"marker": marker}},
    })
    .to_string();
    let (status, _, body) = consumer_request(
        fixture.consumer,
        &fixture.pki.ca_pem,
        "POST",
        &path,
        &token,
        &session_headers,
        call.as_bytes(),
    )
    .await
    .expect("step mcp tools/call");
    assert_eq!(
        status,
        200,
        "step mcp tools/call: {}; {}",
        String::from_utf8_lossy(&body),
        context()
    );
    let called = jsonrpc_reply(&body, &serde_json::json!(2)).unwrap_or_else(|| {
        panic!(
            "step mcp tools/call: no JSON-RPC reply with id 2: {}",
            String::from_utf8_lossy(&body)
        )
    });
    let text = called["result"]["content"][0]["text"]
        .as_str()
        .unwrap_or_default();
    assert!(
        text.contains(&marker),
        "step mcp tools/call: the tool result must carry the marker sent: {called}"
    );
    // The device-side server itself recorded the invocation in its
    // configured workspace, so the answer came from the export's backend.
    // The fixture records only the tool name (`FixtureServer::call_tool`
    // writes `request.name`), so the marker cannot appear here; what binds
    // the record to this run is that the workspace was created empty for
    // this run and must now hold exactly the one call this gate made.
    let invocations = fs::read_to_string(fixture.work.join("device/mcp-workspace/invocations.log"))
        .unwrap_or_default();
    let backend_invocations = invocations.lines().count();
    assert_eq!(
        invocations, "echo\n",
        "step mcp tools/call: the fixture server must have recorded exactly this gate's one \
         echo call in its fresh workspace"
    );

    // Control: the same initialize with a token for an unprovisioned
    // subject is refused, so the 200 above was the provisioned grant's.
    let stranger =
        access_token_with_scope(&fixture.issuer_key, "m6c57-unprovisioned", "http:invoke");
    let (stranger_status, _, _) = consumer_request(
        fixture.consumer,
        &fixture.pki.ca_pem,
        "POST",
        &path,
        &stranger,
        &MCP_HEADERS,
        initialize.as_bytes(),
    )
    .await
    .expect("stranger request completes");
    assert!(
        stranger_status == 401,
        "step mcp stranger: an unprovisioned subject got HTTP {stranger_status}"
    );

    drop(device);
    let (nonce, namespace) = (fixture.nonce.clone(), fixture.namespace.clone());
    drop(fixture);
    println!(
        "m6c57-mcp ok nonce={nonce} namespace={namespace} initialize=200 \
         notification={notification_status} tools_call={status} marker_echoed=true \
         backend_invocations={backend_invocations} stranger_status={stranger_status}"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL, TUNNEL_CLIENT_BIN and TUNNEL_ACP_FIXTURE_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m6c57_provisioned_acp_service_answers_initialize() {
    let (fixture, device, client_log, client_stderr) =
        serve_kind("m6c57-acp", ServiceKind::Acp).await;
    assert!(
        fixture
            .dry
            .contains("service_type=http-forward http_forward_profile=acp-http-v1"),
        "dry run output: {}",
        fixture.dry
    );
    let context = || device_log(&client_log, &client_stderr);
    let token = access_token_with_scope(&fixture.issuer_key, &fixture.subject, "http:invoke");
    let path = format!(
        "/v1/devices/{}/services/{}/http/acp",
        fixture.device, fixture.service
    );
    let request_id = format!("m6c57-acp-{}", fixture.nonce);
    let initialize = serde_json::json!({
        "jsonrpc": "2.0", "id": request_id, "method": "initialize",
        "params": {
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": {"name": "m6c57-gate", "version": "1"},
        },
    })
    .to_string();
    let acp_headers = [
        ("content-type", "application/json"),
        ("accept", "application/json"),
    ];
    let (_, headers, body) = until_served(
        "acp initialize",
        || {
            consumer_request_h2(
                fixture.consumer,
                &fixture.pki.ca_pem,
                "POST",
                &path,
                &token,
                &acp_headers,
                initialize.as_bytes(),
            )
        },
        context,
    )
    .await;
    let reply = jsonrpc_reply(&body, &serde_json::json!(request_id)).unwrap_or_else(|| {
        panic!(
            "step acp initialize: no JSON-RPC reply with the request id: {}",
            String::from_utf8_lossy(&body)
        )
    });
    // The fixture agent answers initialize with exactly this result, so the
    // reply came from the device-side agent the export supervises.
    assert_eq!(
        reply["result"],
        serde_json::json!({"protocolVersion": 1, "agentCapabilities": {}}),
        "step acp initialize: {reply}"
    );
    let connection = headers
        .get("acp-connection-id")
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default();
    assert!(
        !connection.is_empty(),
        "step acp initialize: the bridge returns an Acp-Connection-Id"
    );

    let stranger =
        access_token_with_scope(&fixture.issuer_key, "m6c57-unprovisioned", "http:invoke");
    let (stranger_status, _, _) = consumer_request_h2(
        fixture.consumer,
        &fixture.pki.ca_pem,
        "POST",
        &path,
        &stranger,
        &acp_headers,
        initialize.as_bytes(),
    )
    .await
    .expect("stranger request completes");
    assert!(
        stranger_status == 401,
        "step acp stranger: an unprovisioned subject got HTTP {stranger_status}"
    );

    drop(device);
    let (nonce, namespace) = (fixture.nonce.clone(), fixture.namespace.clone());
    drop(fixture);
    println!(
        "m6c57-acp ok nonce={nonce} namespace={namespace} initialize=200 \
         agent_protocol_version=1 connection_id=present stranger_status={stranger_status}"
    );
}

/// A minimal 9P2000.L consumer over the relay's filesystem WebSocket: every
/// byte is encoded and decoded by `tunnel_fs_ninep`, as the M4 gates' client
/// in `tunnel-test-harness` does.
mod ninep {
    use std::{net::SocketAddr, sync::Arc, time::Duration};

    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::{
        Connector, MaybeTlsStream, WebSocketStream, connect_async_tls_with_config,
        tungstenite::{Message as WsMessage, client::IntoClientRequest, http::HeaderValue},
    };
    use tunnel_fs_ninep::{DIALECT, Frame, MAX_MESSAGE_BYTES, Message, NOFID, NONUNAME, NOTAG};

    const IO_TIMEOUT: Duration = Duration::from_secs(20);

    pub struct Client {
        socket: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
        msize: u32,
        tag: u16,
    }

    fn unexpected(expected: &str, got: &Message) -> String {
        format!("expected {expected}, got {:?}", got.message_type())
    }

    impl Client {
        /// Upgrade; an HTTP answer instead of `101` is returned as an error
        /// naming its status.
        pub async fn connect(
            consumer: SocketAddr,
            path: &str,
            tls: rustls::ClientConfig,
            token: &str,
        ) -> Result<Self, String> {
            let mut request = format!("wss://127.0.0.1:{}{path}", consumer.port())
                .into_client_request()
                .map_err(|error| error.to_string())?;
            request.headers_mut().insert(
                "authorization",
                HeaderValue::from_str(&format!("Bearer {token}"))
                    .map_err(|error| error.to_string())?,
            );
            request.headers_mut().insert(
                "sec-websocket-protocol",
                HeaderValue::from_static(tunnel_fs_core::TRANSPORT_SUBPROTOCOL),
            );
            let connected = tokio::time::timeout(
                IO_TIMEOUT,
                connect_async_tls_with_config(
                    request,
                    None,
                    false,
                    Some(Connector::Rustls(Arc::new(tls))),
                ),
            )
            .await
            .map_err(|_| "fs upgrade timed out".to_owned())?;
            match connected {
                Ok((socket, _)) => Ok(Self {
                    socket,
                    msize: MAX_MESSAGE_BYTES,
                    tag: 0,
                }),
                Err(tokio_tungstenite::tungstenite::Error::Http(response)) => {
                    Err(format!("fs upgrade answered HTTP {}", response.status()))
                }
                Err(error) => Err(format!("fs upgrade failed: {error}")),
            }
        }

        async fn exchange(&mut self, tag: u16, message: Message) -> Result<Message, String> {
            let bytes = Frame::new(tag, message)
                .to_bytes(self.msize)
                .map_err(|error| format!("9P encode: {error:?}"))?;
            tokio::time::timeout(
                IO_TIMEOUT,
                self.socket.send(WsMessage::Binary(bytes.into())),
            )
            .await
            .map_err(|_| "9P send timed out".to_owned())?
            .map_err(|error| format!("9P send: {error}"))?;
            loop {
                let next = tokio::time::timeout(IO_TIMEOUT, self.socket.next())
                    .await
                    .map_err(|_| "9P receive timed out".to_owned())?;
                match next {
                    Some(Ok(WsMessage::Binary(bytes))) => {
                        let frame = tunnel_fs_ninep::decode_exact(&bytes, MAX_MESSAGE_BYTES)
                            .map_err(|error| format!("9P decode: {error:?}"))?;
                        if frame.tag != tag {
                            return Err(format!("9P reply tag {} for {tag}", frame.tag));
                        }
                        return Ok(frame.message);
                    }
                    Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_) | WsMessage::Frame(_))) => {}
                    Some(Ok(WsMessage::Close(frame))) => {
                        return Err(format!("9P socket closed: {frame:?}"));
                    }
                    Some(Ok(WsMessage::Text(_))) => {
                        return Err("9P socket sent text".to_owned());
                    }
                    Some(Err(error)) => return Err(format!("9P socket failed: {error}")),
                    None => return Err("9P socket ended".to_owned()),
                }
            }
        }

        async fn call(&mut self, message: Message) -> Result<Message, String> {
            self.tag = self.tag.wrapping_add(1) % NOTAG;
            self.exchange(self.tag, message).await
        }

        /// Version, attach the export root as fid 0, walk to `name` as fid 1,
        /// open it read-only and read it whole.
        pub async fn read_file(&mut self, name: &str) -> Result<Vec<u8>, String> {
            let version = Message::Tversion {
                msize: MAX_MESSAGE_BYTES,
                version: DIALECT.to_owned(),
            };
            match self.exchange(NOTAG, version).await? {
                Message::Rversion { msize, .. } => self.msize = msize,
                other => return Err(unexpected("Rversion", &other)),
            }
            let attach = Message::Tattach {
                fid: 0,
                afid: NOFID,
                uname: String::new(),
                aname: String::new(),
                n_uname: NONUNAME,
            };
            match self.call(attach).await? {
                Message::Rattach { .. } => {}
                other => return Err(unexpected("Rattach", &other)),
            }
            let walk = Message::Twalk {
                fid: 0,
                newfid: 1,
                names: vec![name.to_owned()],
            };
            match self.call(walk).await? {
                Message::Rwalk { .. } => {}
                other => return Err(unexpected("Rwalk", &other)),
            }
            match self.call(Message::Tlopen { fid: 1, flags: 0 }).await? {
                Message::Rlopen { .. } => {}
                other => return Err(unexpected("Rlopen", &other)),
            }
            let count = self.msize - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;
            let mut data = Vec::new();
            loop {
                let read = Message::Tread {
                    fid: 1,
                    offset: data.len() as u64,
                    count,
                };
                match self.call(read).await? {
                    Message::Rread { data: chunk } if chunk.is_empty() => return Ok(data),
                    Message::Rread { data: chunk } => data.extend_from_slice(&chunk),
                    other => return Err(unexpected("Rread", &other)),
                }
            }
        }

        pub async fn close(mut self) {
            let _ =
                tokio::time::timeout(IO_TIMEOUT, self.socket.send(WsMessage::Close(None))).await;
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m6c57_provisioned_fs_service_serves_a_file_read() {
    let (fixture, device, client_log, client_stderr) =
        serve_kind("m6c57-fs", ServiceKind::Fs).await;
    assert!(
        fixture
            .dry
            .contains("service_type=fs fs_case_sensitivity=insensitive-preserving"),
        "dry run output: {}",
        fixture.dry
    );
    let context = || device_log(&client_log, &client_stderr);
    let token = access_token_with_scope(&fixture.issuer_key, &fixture.subject, "fs:connect");
    let path = format!(
        "/v1/devices/{}/services/{}/fs",
        fixture.device, fixture.service
    );

    // 1. The descriptor: a GET without an upgrade.  Before M6-C57 this was
    // 404 EXPORT_NOT_FOUND for every provisioned filesystem service.
    let (_, _, descriptor) = until_served(
        "fs descriptor",
        || {
            consumer_request(
                fixture.consumer,
                &fixture.pki.ca_pem,
                "GET",
                &path,
                &token,
                &[],
                b"",
            )
        },
        context,
    )
    .await;
    let described = String::from_utf8_lossy(&descriptor).into_owned();
    assert!(
        described.contains("insensitive-preserving"),
        "step fs descriptor: the provisioned case behaviour must be reported: {described}"
    );

    // 2. A 9P session reading the synthetic file the export root holds.
    let expected = fs::read(fixture.work.join("device/fs-root").join(FS_FILE_NAME))
        .expect("read the synthetic file back");
    let deadline = Instant::now() + STEP_DEADLINE;
    let read = loop {
        let tls = consumer_tls(&fixture.pki.ca_pem).expect("consumer TLS");
        let attempt = match ninep::Client::connect(fixture.consumer, &path, tls, &token).await {
            Ok(mut client) => {
                let read = client.read_file(FS_FILE_NAME).await;
                client.close().await;
                read
            }
            Err(error) => Err(error),
        };
        match attempt {
            Ok(bytes) => break bytes,
            Err(error) if Instant::now() >= deadline => {
                panic!("step fs read: {error}; {}", context())
            }
            Err(_) => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    };
    assert_eq!(
        read, expected,
        "step fs read: the bytes read through the relay must be the synthetic file's"
    );

    // Control: an unprovisioned subject gets no descriptor.
    let stranger =
        access_token_with_scope(&fixture.issuer_key, "m6c57-unprovisioned", "fs:connect");
    let (stranger_status, _, _) = consumer_request(
        fixture.consumer,
        &fixture.pki.ca_pem,
        "GET",
        &path,
        &stranger,
        &[],
        b"",
    )
    .await
    .expect("stranger request completes");
    assert!(
        stranger_status == 401,
        "step fs stranger: an unprovisioned subject got HTTP {stranger_status}"
    );

    drop(device);
    let (nonce, namespace) = (fixture.nonce.clone(), fixture.namespace.clone());
    drop(fixture);
    println!(
        "m6c57-fs ok nonce={nonce} namespace={namespace} descriptor=200 \
         case_sensitivity=insensitive-preserving read_bytes={} matches_file=true \
         stranger_status={stranger_status}",
        read.len()
    );
}

/// Run one day-2 `tunnel-relay` command to success; returns its stdout.
fn relay_change(fixture: &Provisioned, name: &str, args: &[&str]) -> String {
    stdout(&step(
        name,
        Command::new(&fixture.relay_bin)
            .args(args)
            .arg("--config")
            .arg(&fixture.relay_config),
    ))
}

/// Run one day-2 command that must be refused; returns its stderr.
fn relay_change_refused(fixture: &Provisioned, name: &str, args: &[&str]) -> String {
    let output = Command::new(&fixture.relay_bin)
        .args(args)
        .arg("--config")
        .arg(&fixture.relay_config)
        .output()
        .unwrap_or_else(|error| panic!("step {name}: could not start: {error}"));
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert_eq!(
        output.status.code(),
        Some(1),
        "step {name}: must be refused with exit 1: {stderr}"
    );
    stderr
}

/// One echo; the HTTP status and body.
async fn echo_once(
    fixture: &Provisioned,
    token: &str,
    device: Uuid,
    service: Uuid,
    payload: &str,
) -> (u16, Vec<u8>) {
    consumer_post(
        fixture.consumer,
        &fixture.pki.ca_pem,
        &format!("/v1/devices/{device}/services/{service}/echo"),
        token,
        payload.as_bytes(),
    )
    .await
    .unwrap_or_else(|error| panic!("echo to {device}: {error}"))
}

/// Read one Redis string of the run's namespace with the raw RESP client.
fn namespace_get(fixture: &Provisioned, key: &str) -> String {
    let reply = redis_command(
        fixture.upstream,
        fixture.database,
        &[
            "GET",
            &format!("tunnel-catalog:{}:{key}", fixture.namespace),
        ],
    );
    // SELECT's `+OK`, then the bulk string's header and value.
    String::from_utf8_lossy(&reply)
        .split("\r\n")
        .skip(1)
        .nth(1)
        .unwrap_or_default()
        .to_owned()
}

/// Task row M6-C31: with `serve` running and never restarted, the shipped
/// day-2 commands add a second user, a second device (a new certificate from
/// this test's synthetic device CA), its service and grants; the second
/// device connects and serves the second user an echo; then a grant
/// revocation and a device revocation each take effect within the bound
/// docs/operator.md states, measured here.
///
/// Red without the commands: every step below `add-user` is a `tunnel-relay`
/// subcommand that did not exist, and each effect -- the second user's
/// identity, the second device's credential, the grants, the revocations --
/// is asserted through the relay, not read back from Redis.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-provisioning-verify.sh"]
async fn m6c31_day2_catalog_changes_take_effect_on_a_serving_relay() {
    let mut fixture = provision_and_serve("m6c31-e2e", None).await;
    let nonce = fixture.nonce.clone();
    let records: toml::Value = toml::from_str(
        &fs::read_to_string(repository().join("examples/m6-catalog.toml")).expect("records"),
    )
    .expect("parse records");
    let tenant: Uuid = records["tenant"]["id"]
        .as_str()
        .and_then(|id| id.parse().ok())
        .expect("tenant id");
    let (device_a, service_a) = (fixture.device, fixture.service);
    let relay_pid = fixture.relay.0.id();
    let operator = fixture.work.join("operator");
    fs::create_dir_all(&operator).expect("operator dir");

    // --- The first device serves the first user, as provisioned. ---
    let log_a = fixture.work.join("connect-a.log");
    let _device_a = Running(
        Command::new(&fixture.client_bin)
            .args(["connect", "--config"])
            .arg(&fixture.client_config)
            .arg("--json")
            .stdout(fs::File::create(&log_a).expect("client log"))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect"),
    );
    let token_a = access_token(&fixture.issuer_key, &fixture.subject);
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        let (status, _) = echo_once(&fixture, &token_a, device_a, service_a, "warm-up").await;
        if status == 200 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "step first echo: HTTP {status}; {}",
            fs::read_to_string(&log_a).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    // --- add-user: a second user in the provisioned tenant. ---
    let user_b = Uuid::new_v4();
    let subject_b = format!("m6c31-second-user-{nonce}");
    let token_b = access_token(&fixture.issuer_key, &subject_b);
    let (before_user, _) = echo_once(&fixture, &token_b, device_a, service_a, "x").await;
    assert_eq!(
        before_user, 401,
        "an unknown subject is refused before add-user"
    );
    let user_doc = operator.join("user.toml");
    fs::write(
        &user_doc,
        format!(
            "[user]\ntenant = \"{tenant}\"\nid = \"{user_b}\"\ndisplay_name = \"Second user\"\n\
             oidc_subject = \"{subject_b}\"\n"
        ),
    )
    .expect("user document");
    let user_doc_arg = user_doc.to_str().expect("path");
    let dry = relay_change(
        &fixture,
        "add-user --dry-run",
        &["add-user", "--records", user_doc_arg, "--dry-run"],
    );
    assert!(
        dry.contains(&format!("user={user_b}")) && dry.contains("contacted no Redis"),
        "{dry}"
    );
    let (after_dry, _) = echo_once(&fixture, &token_b, device_a, service_a, "x").await;
    assert_eq!(after_dry, 401, "the dry run wrote nothing");
    let added = relay_change(
        &fixture,
        "add-user",
        &["add-user", "--records", user_doc_arg],
    );
    assert!(added.contains(&format!("user={user_b}")), "{added}");
    let (no_grant, _) = echo_once(&fixture, &token_b, device_a, service_a, "x").await;
    assert!(
        matches!(no_grant, 403 | 404),
        "the added user is known but has no grant yet: HTTP {no_grant}"
    );
    let duplicate = relay_change_refused(
        &fixture,
        "add-user again",
        &["add-user", "--records", user_doc_arg],
    );
    assert!(duplicate.contains("user already exists"), "{duplicate}");

    // --- set-grant on the running first device: pickup with no restart. ---
    let grant_a_doc = operator.join("grant-a.toml");
    fs::write(
        &grant_a_doc,
        format!(
            "[grant]\ntenant = \"{tenant}\"\nuser = \"{user_b}\"\ndevice = \"{device_a}\"\n\
             service = \"{service_a}\"\noperations = [\"echo:invoke\"]\n"
        ),
    )
    .expect("grant document");
    let grant_a_arg = grant_a_doc.to_str().expect("path");
    let granted = relay_change(
        &fixture,
        "set-grant",
        &["set-grant", "--records", grant_a_arg],
    );
    let granted_at = Instant::now();
    assert!(
        granted.contains("Added grant") && granted.contains("revision=1"),
        "{granted}"
    );
    let (grant_pickup_status, _) =
        echo_once(&fixture, &token_b, device_a, service_a, "pickup").await;
    let grant_pickup_ms = granted_at.elapsed().as_millis();
    assert_eq!(
        grant_pickup_status, 200,
        "the first request after set-grant must be served: the relay caches no grant"
    );
    // Replacing it advances the revision.
    let replaced = relay_change(
        &fixture,
        "set-grant replace",
        &["set-grant", "--records", grant_a_arg],
    );
    assert!(
        replaced.contains("Replaced grant") && replaced.contains("revision=2"),
        "{replaced}"
    );

    // --- add-device, add-service, set-grant: a second device for the second
    // user, with a new key and a certificate from the test's device CA. ---
    let device_b = Uuid::new_v4();
    let service_b = Uuid::new_v4();
    let dir_b = fixture.work.join("device-b");
    fs::create_dir_all(&dir_b).expect("device b dir");
    let profile_b = fs::read_to_string(&fixture.client_config)
        .expect("client config")
        .replace(&device_a.to_string(), &device_b.to_string())
        .replace(&service_a.to_string(), &service_b.to_string());
    let config_b = dir_b.join("client.toml");
    fs::write(&config_b, profile_b).expect("device b profile");
    step(
        "device b key and CSR (tunnel-client credentials create)",
        Command::new(&fixture.client_bin)
            .args(["credentials", "create", "--config"])
            .arg(&config_b)
            .args(["--csr-out", "device.csr"]),
    );
    let extensions_b = fixture.work.join("device-b-ext.cnf");
    fs::write(
        &extensions_b,
        format!(
            "basicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=clientAuth\n\
             subjectAltName=URI:urn:agent-tunnel:device:{device_b}\n"
        ),
    )
    .expect("device b extensions");
    step(
        "issue device b certificate (openssl x509 -req)",
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(dir_b.join("device.csr"))
            .arg("-CA")
            .arg(&fixture.device_ca)
            .arg("-CAkey")
            .arg(&fixture.device_ca_key)
            .args(["-CAcreateserial", "-days", "1", "-extfile"])
            .arg(&extensions_b)
            .arg("-out")
            .arg(dir_b.join("device-cert.pem")),
    );
    step(
        "device b certificate import (tunnel-client credentials import)",
        Command::new(&fixture.client_bin)
            .args(["credentials", "import", "--config"])
            .arg(&config_b)
            .args(["--certificate", "device-cert.pem", "--server-ca"])
            .arg(&fixture.server_ca),
    );
    let device_doc = dir_b.join("device.toml");
    fs::write(
        &device_doc,
        format!(
            "[device]\ntenant = \"{tenant}\"\nowner = \"{user_b}\"\nid = \"{device_b}\"\n\
             display_name = \"Second device\"\ncertificate = \"device-cert.pem\"\n"
        ),
    )
    .expect("device document");
    let device_doc_arg = device_doc.to_str().expect("path");
    let dry = relay_change(
        &fixture,
        "add-device --dry-run",
        &["add-device", "--records", device_doc_arg, "--dry-run"],
    );
    assert!(dry.contains(&format!("device={device_b}")), "{dry}");
    let added = relay_change(
        &fixture,
        "add-device",
        &["add-device", "--records", device_doc_arg],
    );
    let credential_b: Uuid = added
        .split_whitespace()
        .find_map(|field| field.strip_prefix("credential="))
        .and_then(|id| id.parse().ok())
        .unwrap_or_else(|| panic!("add-device prints credential=: {added}"));
    let duplicate = relay_change_refused(
        &fixture,
        "add-device again",
        &["add-device", "--records", device_doc_arg],
    );
    assert!(duplicate.contains("already exists"), "{duplicate}");
    let service_doc = operator.join("service.toml");
    fs::write(
        &service_doc,
        format!(
            "[service]\ntenant = \"{tenant}\"\ndevice = \"{device_b}\"\nid = \"{service_b}\"\n\
             type = \"echo\"\ndisplay_name = \"Second echo\"\noperations = [\"echo:invoke\"]\n"
        ),
    )
    .expect("service document");
    relay_change(
        &fixture,
        "add-service",
        &[
            "add-service",
            "--records",
            service_doc.to_str().expect("path"),
        ],
    );
    let grant_b_doc = operator.join("grant-b.toml");
    fs::write(
        &grant_b_doc,
        format!(
            "[grant]\ntenant = \"{tenant}\"\nuser = \"{user_b}\"\ndevice = \"{device_b}\"\n\
             service = \"{service_b}\"\noperations = [\"echo:invoke\"]\n"
        ),
    )
    .expect("grant document");
    relay_change(
        &fixture,
        "set-grant device b",
        &[
            "set-grant",
            "--records",
            grant_b_doc.to_str().expect("path"),
        ],
    );

    let log_b = fixture.work.join("connect-b.log");
    let started_b = Instant::now();
    let mut device_b_process = Running(
        Command::new(&fixture.client_bin)
            .args(["connect", "--config"])
            .arg(&config_b)
            .arg("--json")
            .stdout(fs::File::create(&log_b).expect("client b log"))
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect b"),
    );
    let payload = format!("m6c31-second-device-{nonce}");
    let deadline = Instant::now() + STEP_DEADLINE;
    let body_b = loop {
        let (status, body) = echo_once(&fixture, &token_b, device_b, service_b, &payload).await;
        if status == 200 {
            break body;
        }
        assert!(
            Instant::now() < deadline,
            "step second device echo: HTTP {status} {}; connect log: {}",
            String::from_utf8_lossy(&body),
            fs::read_to_string(&log_b).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    let device_pickup_ms = started_b.elapsed().as_millis();
    assert_eq!(
        String::from_utf8_lossy(&body_b),
        format!("{CANARY}{payload}"),
        "the second device's echo"
    );
    // Isolation: the first user has no grant on the second device.
    let (cross, _) = echo_once(&fixture, &token_a, device_b, service_b, "x").await;
    assert!(
        matches!(cross, 403 | 404),
        "the first user must not reach the second user's device: HTTP {cross}"
    );
    assert!(
        fixture.relay.0.try_wait().expect("poll serve").is_none()
            && fixture.relay.0.id() == relay_pid,
        "serve must still be the process started before the changes"
    );

    // --- revoke-grant: the next request is refused. ---
    let revoked = relay_change(
        &fixture,
        "revoke-grant",
        &[
            "revoke-grant",
            "--tenant",
            &tenant.to_string(),
            "--user",
            &user_b.to_string(),
            "--device",
            &device_a.to_string(),
            "--service",
            &service_a.to_string(),
        ],
    );
    let revoked_at = Instant::now();
    assert!(revoked.contains("revision=3"), "{revoked}");
    let (after_revoke, _) = echo_once(&fixture, &token_b, device_a, service_a, "x").await;
    let revoke_grant_ms = revoked_at.elapsed().as_millis();
    assert!(
        matches!(after_revoke, 403 | 404),
        "the first request after revoke-grant must be refused: HTTP {after_revoke}"
    );
    // Only that grant: the same user's other grant and the first user's
    // grant on the same service still serve.
    assert_eq!(
        echo_once(&fixture, &token_b, device_b, service_b, "x")
            .await
            .0,
        200
    );
    assert_eq!(
        echo_once(&fixture, &token_a, device_a, service_a, "x")
            .await
            .0,
        200
    );

    // --- revoke-device: the live session is closed within the bound. ---
    while fixture.relay_log.try_recv().is_ok() {}
    let revoked = relay_change(
        &fixture,
        "revoke-device",
        &[
            "revoke-device",
            "--tenant",
            &tenant.to_string(),
            "--device",
            &device_b.to_string(),
        ],
    );
    let device_revoked_at = Instant::now();
    assert!(revoked.contains(&format!("device={device_b}")), "{revoked}");
    let (after_device_revoke, _) = echo_once(&fixture, &token_b, device_b, service_b, "x").await;
    let device_request_ms = device_revoked_at.elapsed().as_millis();
    assert!(
        matches!(after_device_revoke, 403 | 404 | 503),
        "the first request after revoke-device must be refused: HTTP {after_device_revoke}"
    );
    // The relay's owner actor closes the session at its next maintenance
    // check; the device reports the end of its session.
    let close_deadline = device_revoked_at + Duration::from_secs(5);
    let mut relay_close: Option<(u128, String)> = None;
    let mut device_end: Option<(u128, String)> = None;
    while (relay_close.is_none() || device_end.is_none()) && Instant::now() < close_deadline {
        while let Ok(line) = fixture.relay_log.try_recv() {
            if relay_close.is_none()
                && line.contains("owner_check_failed")
                && line.contains(&device_b.to_string())
            {
                let reason = serde_json::from_str::<serde_json::Value>(&line)
                    .ok()
                    .and_then(|value| value["fields"]["reason"].as_str().map(str::to_owned))
                    .unwrap_or_else(|| "unparsed".to_owned());
                relay_close = Some((device_revoked_at.elapsed().as_millis(), reason));
            }
        }
        if device_end.is_none() {
            let log = fs::read_to_string(&log_b).unwrap_or_default();
            if log.contains("\"state\":\"disconnected\"") {
                device_end = Some((
                    device_revoked_at.elapsed().as_millis(),
                    "disconnected".to_owned(),
                ));
            } else if let Some(status) = device_b_process.0.try_wait().expect("poll connect b") {
                device_end = Some((
                    device_revoked_at.elapsed().as_millis(),
                    format!("exit={}", status.code().unwrap_or(-1)),
                ));
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    let (relay_close_ms, close_reason) = relay_close.unwrap_or_else(|| {
        panic!(
            "step revoke-device: the relay did not close the second device's session within \
             5 s; connect log: {}",
            fs::read_to_string(&log_b).unwrap_or_default()
        )
    });
    // The revocation is the cause, whether or not a lease renewal landed on
    // the same maintenance tick (M6-C31 review: that race used to report
    // OWNER_FENCED).
    assert_eq!(
        close_reason, "AUTHORIZATION_REVOKED",
        "step revoke-device: the relay must report the revocation"
    );
    let (device_end_ms, device_end_event) = device_end.unwrap_or_else(|| {
        panic!(
            "step revoke-device: the second device did not see its session end within 5 s; \
             connect log: {}",
            fs::read_to_string(&log_b).unwrap_or_default()
        )
    });
    // The device may not come back: its reconnect is an identity refusal.
    let exit_deadline = Instant::now() + STEP_DEADLINE;
    let exit = loop {
        if let Some(status) = device_b_process.0.try_wait().expect("poll connect b") {
            break status.code();
        }
        assert!(
            Instant::now() < exit_deadline,
            "step revoke-device: the revoked device kept retrying: {}",
            fs::read_to_string(&log_b).unwrap_or_default()
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(
        exit,
        Some(3),
        "a revoked device ends with a terminal credential refusal: {}",
        fs::read_to_string(&log_b).unwrap_or_default()
    );
    // The first device and user are untouched.
    assert_eq!(
        echo_once(&fixture, &token_a, device_a, service_a, "x")
            .await
            .0,
        200
    );
    // A grant on the revoked device is refused, not reported as added.
    let regrant = relay_change_refused(
        &fixture,
        "set-grant on a revoked device",
        &[
            "set-grant",
            "--records",
            grant_b_doc.to_str().expect("path"),
        ],
    );
    assert!(regrant.contains("the device is revoked"), "{regrant}");
    // revoke-credential and a revocation of nothing are refused clearly.
    let missing = relay_change_refused(
        &fixture,
        "revoke-credential of a revoked device",
        &[
            "revoke-credential",
            "--tenant",
            &tenant.to_string(),
            "--device",
            &device_b.to_string(),
            "--credential",
            &credential_b.to_string(),
        ],
    );
    assert!(missing.contains("no active credential"), "{missing}");
    let missing = relay_change_refused(
        &fixture,
        "revoke-grant of nothing",
        &[
            "revoke-grant",
            "--tenant",
            &tenant.to_string(),
            "--user",
            &Uuid::new_v4().to_string(),
            "--device",
            &device_a.to_string(),
            "--service",
            &service_a.to_string(),
        ],
    );
    assert!(missing.contains("no grant"), "{missing}");

    // The authority records are intact, and serve never restarted.
    assert_eq!(
        namespace_get(&fixture, "meta:active_incarnation"),
        format!("m6c31-e2e-{nonce}")
    );
    assert_eq!(namespace_get(&fixture, "meta:fixture_seeded"), "1");
    assert!(
        fixture.relay.0.try_wait().expect("poll serve").is_none(),
        "serve kept running through every change"
    );

    let namespace = fixture.namespace.clone();
    drop(device_b_process);
    drop(_device_a);
    drop(fixture);
    println!(
        "m6c31-catalog ok nonce={nonce} namespace={namespace} serve_restarts=0 \
         grant_pickup_ms={grant_pickup_ms} grant_pickup_attempts=1 \
         device_pickup_ms={device_pickup_ms} revoke_grant_ms={revoke_grant_ms} \
         revoke_grant_attempts=1 device_revoked_request_ms={device_request_ms} \
         device_revoked_request_status={after_device_revoke} \
         relay_session_close_ms={relay_close_ms} close_reason={close_reason} \
         device_session_end_ms={device_end_ms} device_end={device_end_event} \
         device_exit={} revoked_device_grant_refused=true",
        exit.unwrap_or(-1)
    );
}

// ---------------------------------------------------------------------------
// Task row M6-C65: a Redis restart must not end the namespace.
// ---------------------------------------------------------------------------

/// The Redis image the gate runs (the Fly Redis image's base), pinned by
/// digest as the M1 and M7 restart gates pin it.
const M6C65_REDIS_IMAGE: &str =
    "redis:8.4.0-alpine@sha256:6cbef353e480a8a6e7f10ec545f13d7d3fa85a212cdcc5ffaf5a1c818b9d3798";
/// Continuity interval the gate configures (`redis_restart_continuity_seconds`).
const M6C65_CONTINUITY_SECONDS: u64 = 1;
/// A device reconnect after a Redis restart can wait out the previous
/// session's owner lease (30 s, M6-C40) before its claim succeeds.
const M6C65_RECOVERY_DEADLINE: Duration = Duration::from_secs(75);

/// A disposable Redis container this gate owns on a fixed loopback port, so
/// it can be restarted, replaced by one loaded from an older RDB, and
/// replaced by an empty one while the relay keeps the same address.  Every
/// container it creates carries a label with the run's nonce and is removed
/// with its volume on drop.  The shared `TEST_REDIS_URL` Redis is never
/// touched.
struct DockerRedis {
    label: String,
    name: String,
    port: u16,
    generation: u32,
}

impl DockerRedis {
    fn docker(args: &[&str]) -> Output {
        let output = Command::new("docker")
            .args(args)
            .output()
            .unwrap_or_else(|error| panic!("docker {args:?}: could not start: {error}"));
        assert!(
            output.status.success(),
            "docker {args:?}: exited {:?}: {}",
            output.status.code(),
            String::from_utf8_lossy(&output.stderr)
        );
        output
    }

    /// Start the first container: AOF on, `appendfsync always`,
    /// `aof-load-truncated no`, as `deploy/fly/redis/entrypoint.sh` does.
    fn start(nonce: &str) -> Self {
        let port = free_port().port();
        let mut redis = Self {
            label: format!("agent-tunnel.m6c65-owner={nonce}"),
            name: String::new(),
            port,
            generation: 0,
        };
        redis.create(&[
            "--appendonly",
            "yes",
            "--appendfsync",
            "always",
            "--aof-load-truncated",
            "no",
        ]);
        redis.start_current();
        redis
    }

    fn create(&mut self, redis_args: &[&str]) {
        self.generation += 1;
        self.name = format!(
            "agent-tunnel-m6c65-{}-{}",
            self.label.rsplit('=').next().unwrap_or("run"),
            self.generation
        );
        let publish = format!("127.0.0.1:{}:6379/tcp", self.port);
        let mut args = vec![
            "create",
            "--name",
            &self.name,
            "--label",
            &self.label,
            "--publish",
            &publish,
            "--memory",
            "256m",
            M6C65_REDIS_IMAGE,
            "redis-server",
            "--protected-mode",
            "no",
            "--bind",
            "0.0.0.0",
            "--maxmemory-policy",
            "noeviction",
        ];
        args.extend_from_slice(redis_args);
        Self::docker(&args);
    }

    fn start_current(&self) {
        Self::docker(&["start", &self.name]);
        self.wait_ready();
    }

    fn upstream(&self) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], self.port))
    }

    fn url(&self) -> String {
        format!("redis://127.0.0.1:{}/0", self.port)
    }

    fn wait_ready(&self) {
        let deadline = Instant::now() + STEP_DEADLINE;
        loop {
            let reply = redis_command(self.upstream(), 0, &["PING"]);
            if String::from_utf8_lossy(&reply).contains("+PONG") {
                return;
            }
            assert!(
                Instant::now() < deadline,
                "Redis container {} did not answer PING",
                self.name
            );
            std::thread::sleep(Duration::from_millis(100));
        }
    }

    fn run_id(&self) -> String {
        let reply = redis_command(self.upstream(), 0, &["INFO", "server"]);
        String::from_utf8_lossy(&reply)
            .lines()
            .find_map(|line| line.strip_prefix("run_id:"))
            .map(|value| value.trim().to_owned())
            .unwrap_or_else(|| panic!("INFO server without run_id from {}", self.name))
    }

    /// `docker restart`: SIGTERM, so Redis shuts down in order and writes
    /// its AOF; the container keeps its volume.
    fn restart(&self) {
        Self::docker(&["restart", "--time", "30", &self.name]);
        self.wait_ready();
    }

    /// `SAVE` now, then copy the RDB out: an older snapshot to restore later.
    fn snapshot(&self, to: &Path) {
        let reply = redis_command(self.upstream(), 0, &["SAVE"]);
        assert!(
            String::from_utf8_lossy(&reply).matches("+OK").count() >= 2,
            "SAVE: {}",
            String::from_utf8_lossy(&reply)
        );
        Self::docker(&[
            "cp",
            &format!("{}:/data/dump.rdb", self.name),
            &to.display().to_string(),
        ]);
    }

    /// `docker kill`: SIGKILL, a crash with no orderly shutdown; then start
    /// the same container from its volume.
    fn crash_and_start(&self) {
        Self::docker(&["kill", &self.name]);
        self.start_current();
    }

    /// `CONFIG SET` on this gate's own Redis.
    fn config_set(&self, name: &str, value: &str) {
        let reply = redis_command(self.upstream(), 0, &["CONFIG", "SET", name, value]);
        assert!(
            String::from_utf8_lossy(&reply).matches("+OK").count() >= 2,
            "CONFIG SET {name} {value}: {}",
            String::from_utf8_lossy(&reply)
        );
    }

    /// Stop the current container in order, copy its data into a new
    /// container started with `redis_args`, and keep the old one stopped;
    /// returns the old container's name for [`Self::switch_back`].
    fn swap_to_copy(&mut self, copy_dir: &Path, redis_args: &[&str]) -> String {
        Self::docker(&["stop", "--time", "30", &self.name]);
        fs::create_dir_all(copy_dir).expect("copy dir");
        Self::docker(&[
            "cp",
            &format!("{}:/data/.", self.name),
            &copy_dir.display().to_string(),
        ]);
        let previous = self.name.clone();
        self.create(redis_args);
        Self::docker(&[
            "cp",
            &format!("{}/.", copy_dir.display()),
            &format!("{}:/data", self.name),
        ]);
        self.start_current();
        previous
    }

    /// Remove the current container and start `previous` again.
    fn switch_back(&mut self, previous: String) {
        self.remove_current();
        self.name = previous;
        self.start_current();
    }

    /// Stop and remove the current container with its volume.
    fn remove_current(&self) {
        Self::docker(&["rm", "--force", "--volumes", &self.name]);
    }

    /// Replace the current container by one that starts from `rdb` alone
    /// (AOF off, so Redis loads the RDB): a restore of an older backup.  AOF
    /// with `appendfsync always` is then switched on, so the restored Redis
    /// passes the persistence check and only the continuity token can
    /// refuse it.
    fn replace_with_rdb(&mut self, rdb: &Path) {
        self.remove_current();
        self.create(&["--appendonly", "no"]);
        Self::docker(&[
            "cp",
            &rdb.display().to_string(),
            &format!("{}:/data/dump.rdb", self.name),
        ]);
        self.start_current();
        self.config_set("appendfsync", "always");
        self.config_set("appendonly", "yes");
    }

    /// Replace the current container by an empty one: Redis lost its data.
    fn replace_empty(&mut self) {
        self.remove_current();
        self.create(&["--appendonly", "yes", "--appendfsync", "always"]);
        self.start_current();
    }
}

impl Drop for DockerRedis {
    fn drop(&mut self) {
        let listed = Command::new("docker")
            .args(["ps", "--all", "--quiet", "--filter"])
            .arg(format!("label={}", self.label))
            .output();
        if let Ok(listed) = listed {
            for id in String::from_utf8_lossy(&listed.stdout).split_whitespace() {
                let _ = Command::new("docker")
                    .args(["rm", "--force", "--volumes", id])
                    .output();
            }
        }
    }
}

/// `connect --json` for the gate's device, respawned if it exits, so the
/// gate measures the relay and not the device's own reconnect policy.
struct Device {
    process: Option<Running>,
    bin: PathBuf,
    config: PathBuf,
    log: PathBuf,
    spawns: u32,
}

impl Device {
    fn start(fixture: &Provisioned) -> Self {
        let mut device = Self {
            process: None,
            bin: fixture.client_bin.clone(),
            config: fixture.client_config.clone(),
            log: fixture.work.join("connect.log"),
            spawns: 0,
        };
        device.ensure_running();
        device
    }

    fn ensure_running(&mut self) {
        if let Some(process) = self.process.as_mut()
            && matches!(process.0.try_wait(), Ok(None))
        {
            return;
        }
        self.spawns += 1;
        let log = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log)
            .expect("client log");
        self.process = Some(Running(
            Command::new(&self.bin)
                .args(["connect", "--config"])
                .arg(&self.config)
                .arg("--json")
                .stdout(log)
                .stderr(Stdio::null())
                .spawn()
                .expect("spawn connect"),
        ));
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }
}

/// Echo until HTTP 200 with the canary, or panic after `deadline`.
async fn m6c65_echo_until_served(
    step: &str,
    fixture: &Provisioned,
    device: &mut Device,
    token: &str,
    deadline: Duration,
) -> Duration {
    let started = Instant::now();
    let payload = format!("m6c65-{step}-{}", fixture.nonce);
    loop {
        device.ensure_running();
        let last = match consumer_post(
            fixture.consumer,
            &fixture.pki.ca_pem,
            &format!(
                "/v1/devices/{}/services/{}/echo",
                fixture.device, fixture.service
            ),
            token,
            payload.as_bytes(),
        )
        .await
        {
            Ok((200, body)) => {
                assert_eq!(
                    String::from_utf8_lossy(&body),
                    format!("{CANARY}{payload}"),
                    "step {step}: the reply must be the canary and the bytes sent"
                );
                return started.elapsed();
            }
            Ok((status, body)) => format!("HTTP {status} {}", String::from_utf8_lossy(&body)),
            Err(error) => error,
        };
        assert!(
            started.elapsed() < deadline,
            "step {step}: no 200 within {deadline:?}; last {last}; connect log: {}",
            device.log()
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

/// Echo status only (a refusal is expected).
async fn m6c65_echo_status(fixture: &Provisioned, token: &str) -> u16 {
    consumer_post(
        fixture.consumer,
        &fixture.pki.ca_pem,
        &format!(
            "/v1/devices/{}/services/{}/echo",
            fixture.device, fixture.service
        ),
        token,
        b"m6c65-refused",
    )
    .await
    .map_or(0, |(status, _)| status)
}

/// Wait for a relay stderr line containing `needle`; returns it.
fn m6c65_wait_line(
    log: &std::sync::mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    needle: &str,
    deadline: Duration,
) -> String {
    if let Some(line) = seen.iter().find(|line| line.contains(needle)) {
        return line.clone();
    }
    let until = Instant::now() + deadline;
    while Instant::now() < until {
        if let Ok(line) = log.recv_timeout(Duration::from_millis(200)) {
            let found = line.contains(needle);
            seen.push(line.clone());
            if found {
                return line;
            }
        }
    }
    panic!("relay printed no line with `{needle}` within {deadline:?}: {seen:?}");
}

/// Wait for the relay's report of its `count`-th re-binding in this process.
///
/// The relay prints `... re-bound to the new Redis run: rebinds=N` on its
/// continuity loop's next tick, up to one interval plus that tick's token
/// write after the re-binding itself, so an echo can be served before the
/// line exists (236 ms after a crash on the hosted Linux runner).  Every
/// phase that expects an adoption waits for its own numbered line here,
/// before the next phase opens a window in which no re-binding may be
/// reported; otherwise a late line from the phase before lands in that
/// window (the first hosted run of this gate, M6-C65).
fn m6c65_expect_rebinds(
    log: &std::sync::mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    count: u32,
) -> String {
    m6c65_wait_line(
        log,
        seen,
        &format!("namespace re-bound to the new Redis run: rebinds={count}"),
        STEP_DEADLINE,
    )
}

/// Take every relay stderr line already printed, then return how many
/// lines have been seen: lines after this mark were printed after it.
fn m6c65_mark(log: &std::sync::mpsc::Receiver<String>, seen: &mut Vec<String>) -> usize {
    // Anything already in flight on the reader thread lands within this.
    std::thread::sleep(Duration::from_millis(200));
    while let Ok(line) = log.try_recv() {
        seen.push(line);
    }
    seen.len()
}

/// Collect relay stderr for `duration`, then require that no line since
/// `from` reports a re-binding: a refused Redis must never be adopted, not
/// even in memory.
fn m6c65_assert_not_rebound(
    log: &std::sync::mpsc::Receiver<String>,
    seen: &mut Vec<String>,
    from: usize,
    duration: Duration,
) {
    let until = Instant::now() + duration;
    while Instant::now() < until {
        if let Ok(line) = log.recv_timeout(Duration::from_millis(200)) {
            seen.push(line);
        }
    }
    let rebound: Vec<&String> = seen[from..]
        .iter()
        .filter(|line| line.contains("re-bound"))
        .collect();
    assert!(
        rebound.is_empty(),
        "the relay adopted a Redis it must refuse: {rebound:?}"
    );
}

/// Stop `serve` with SIGTERM and wait for its exit.
fn m6c65_stop_relay(relay: &mut Running) {
    let pid = relay.0.id().to_string();
    let _ = Command::new("kill").args(["-TERM", &pid]).status();
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        if let Ok(Some(status)) = relay.0.try_wait() {
            assert_eq!(status.code(), Some(0), "serve must stop cleanly on SIGTERM");
            return;
        }
        assert!(Instant::now() < deadline, "serve did not stop on SIGTERM");
        std::thread::sleep(Duration::from_millis(100));
    }
}

/// `serve` must refuse to start: exit 1 with `expected` on stderr.
/// A `serve` that starts instead is stopped after `STEP_DEADLINE` and fails
/// the gate, rather than hanging it.
fn m6c65_serve_refused(fixture: &Provisioned, expected: &str) -> String {
    let stderr_path = fixture
        .work
        .join(format!("serve-refused-{}.log", Uuid::new_v4().simple()));
    let mut child = Running(
        Command::new(&fixture.relay_bin)
            .args(["serve", "--config"])
            .arg(&fixture.relay_config)
            .stdout(Stdio::null())
            .stderr(fs::File::create(&stderr_path).expect("serve stderr file"))
            .spawn()
            .expect("run serve"),
    );
    let deadline = Instant::now() + STEP_DEADLINE;
    let status = loop {
        if let Ok(Some(status)) = child.0.try_wait() {
            break status;
        }
        if Instant::now() >= deadline {
            drop(child);
            panic!(
                "serve must refuse with `{expected}`, but it was still running after {STEP_DEADLINE:?}: {}",
                fs::read_to_string(&stderr_path).unwrap_or_default()
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    };
    let output = std::process::Output {
        status,
        stdout: Vec::new(),
        stderr: fs::read(&stderr_path).unwrap_or_default(),
    };
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.code() == Some(1) && stderr.contains(expected),
        "serve must refuse with `{expected}`, got {:?}: {stderr}",
        output.status.code()
    );
    stderr.lines().last().unwrap_or_default().to_owned()
}

/// Task row M6-C65: a single relay keeps serving the **same namespace**
/// across in-place Redis restarts, and still refuses a Redis that came back
/// older, empty or not durable.  Everything is the shipped binaries against
/// a Redis container this gate owns (AOF, `appendfsync always`, as the Fly
/// Redis), pinned by digest:
///
/// 1. provision, `serve` with `redis_restart_continuity_seconds`, `connect`,
///    echo;
/// 2. `docker restart` Redis (orderly shutdown, AOF kept, new `run_id`) with
///    the relay running: the same relay process re-binds by itself and the
///    echo answers again;
/// 2b. `docker kill` Redis (a crash) and start it again: the same;
/// 2c. the same data in a Redis with `appendfsync everysec`: refused
///    (`class=persistence`), nothing re-bound; back on the durable Redis the
///    relay re-binds;
/// 2d. `CONFIG SET appendfsync everysec` at runtime on the bound Redis
///    (`class=persistence` from the token loop), then a crash that brings it
///    back with `always`: refused as `run_changed`, because no token was
///    acknowledged as durable within the freshness bound; `rebind-redis-run`
///    then lets the serving relay adopt the run without a restart;
/// 3. stop the relay, restart Redis, start `serve`: refused with
///    `class=run_changed`; `rebind-redis-run` without the declaration is
///    refused; with it, it says the declaration was not verified; `serve`
///    with continuity refuses a Redis set to `everysec` (`class=persistence`)
///    and starts on `always`, and the echo answers;
/// 4. take an RDB snapshot, revoke the grant, let the relay write newer
///    continuity tokens, then replace Redis by one loaded from the snapshot:
///    the serving relay refuses it (`class=continuity`) and never serves the
///    restored grant; a fresh `serve` is refused too; an operator who wrongly
///    re-attests it with `rebind-redis-run` does not make the serving relay
///    accept it;
/// 5. replace Redis by an empty one: refused with `class=unbound` by the
///    serving relay, by a fresh `serve` and by `rebind-redis-run`.
///
/// Red without M6-C65: step 2's echo never answers (every lane refuses the
/// new run for good), and step 3's `rebind-redis-run` does not exist.  Each
/// refusal is proved able to fail by defeating its own check (recorded in
/// docs/tasks.md).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Docker and TUNNEL_CLIENT_BIN; run by scripts/m6-redis-restart-verify.sh"]
async fn m6c65_redis_restart_keeps_the_namespace_and_refuses_lost_data() {
    let mut redis = DockerRedis::start(&Uuid::new_v4().simple().to_string());
    let mut fixture = provision_and_serve_with(
        "m6c65-restart",
        None,
        ServiceKind::Echo,
        ProvisionOptions {
            redis_url: Some(redis.url()),
            relay_top_level: format!(
                "redis_restart_continuity_seconds = {M6C65_CONTINUITY_SECONDS}\n"
            ),
            skip_stage_cases: true,
        },
    )
    .await;
    assert_eq!(fixture.upstream, redis.upstream());
    let nonce = fixture.nonce.clone();
    let records: toml::Value = toml::from_str(
        &fs::read_to_string(repository().join("examples/m6-catalog.toml")).expect("records"),
    )
    .expect("parse records");
    let id = |table: &str| -> String {
        records[table]["id"]
            .as_str()
            .unwrap_or_else(|| panic!("m6-catalog.toml [{table}].id"))
            .to_owned()
    };
    let (tenant, user) = (id("tenant"), id("user"));
    let mut relay_lines = Vec::new();
    let token = access_token(&fixture.issuer_key, &fixture.subject);

    // --- 1. Provisioned, serving, echo. ---
    m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis restart continuity: interval_seconds=1",
        STEP_DEADLINE,
    );
    let mut device = Device::start(&fixture);
    m6c65_echo_until_served("first", &fixture, &mut device, &token, STEP_DEADLINE).await;
    let run_1 = redis.run_id();
    let relay_pid = fixture.relay.0.id();
    let keys_before = redis_command(
        redis.upstream(),
        0,
        &["KEYS", &format!("tunnel-catalog:{}:*", fixture.namespace)],
    );
    let keys_before = String::from_utf8_lossy(&keys_before)
        .split("\r\n")
        .filter(|line| line.starts_with("tunnel-catalog:"))
        .count();

    // --- 2. Redis restarts under the running relay. ---
    redis.restart();
    let run_2 = redis.run_id();
    assert_ne!(run_1, run_2, "a Redis restart must draw a new run_id");
    let unattended = m6c65_echo_until_served(
        "unattended",
        &fixture,
        &mut device,
        &token,
        M6C65_RECOVERY_DEADLINE,
    )
    .await;
    let rebound = m6c65_expect_rebinds(&fixture.relay_log, &mut relay_lines, 1);
    assert_eq!(
        fixture.relay.0.id(),
        relay_pid,
        "the same relay process must serve across the Redis restart"
    );
    assert!(
        matches!(fixture.relay.0.try_wait(), Ok(None)),
        "serve must still be running"
    );
    assert_eq!(namespace_get(&fixture, "meta:redis_run_id"), run_2);
    println!(
        "m6c65-unattended ok nonce={nonce} run_before={run_1} run_after={run_2} \
         keys={keys_before} echo_after_ms={} relay_restarts=0 line={rebound:?}",
        unattended.as_millis()
    );

    // --- 2b. Redis crashes (SIGKILL) under the running relay. ---
    redis.crash_and_start();
    let run_crash = redis.run_id();
    assert_ne!(run_2, run_crash);
    let crash = m6c65_echo_until_served(
        "crash",
        &fixture,
        &mut device,
        &token,
        M6C65_RECOVERY_DEADLINE,
    )
    .await;
    assert_eq!(fixture.relay.0.id(), relay_pid);
    assert_eq!(namespace_get(&fixture, "meta:redis_run_id"), run_crash);
    m6c65_expect_rebinds(&fixture.relay_log, &mut relay_lines, 2);
    println!(
        "m6c65-crash ok nonce={nonce} run_before={run_2} run_after={run_crash} \
         echo_after_ms={} relay_restarts=0",
        crash.as_millis()
    );

    // --- 2c. The same data under `appendfsync everysec` is refused. ---
    // The copy holds the relay's last token, so only the persistence check
    // can refuse it.
    let lines_before_everysec = m6c65_mark(&fixture.relay_log, &mut relay_lines);
    let durable = redis.swap_to_copy(
        &fixture.work.join("everysec-copy"),
        &["--appendonly", "yes", "--appendfsync", "everysec"],
    );
    let run_everysec = redis.run_id();
    let persistence = m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis authority continuity check failed; stage=authority_identity class=persistence",
        STEP_DEADLINE,
    );
    m6c65_assert_not_rebound(
        &fixture.relay_log,
        &mut relay_lines,
        lines_before_everysec,
        Duration::from_secs(3),
    );
    assert_eq!(namespace_get(&fixture, "meta:redis_run_id"), run_crash);
    assert_ne!(m6c65_echo_status(&fixture, &token).await, 200);
    // Back to the durable Redis, restarted from its own AOF: accepted.
    redis.switch_back(durable);
    let run_2 = redis.run_id();
    let back = m6c65_echo_until_served(
        "back-from-everysec",
        &fixture,
        &mut device,
        &token,
        M6C65_RECOVERY_DEADLINE,
    )
    .await;
    assert_eq!(namespace_get(&fixture, "meta:redis_run_id"), run_2);
    m6c65_expect_rebinds(&fixture.relay_log, &mut relay_lines, 3);
    println!(
        "m6c65-persistence ok nonce={nonce} everysec_run={run_everysec} line={persistence:?} \
         durable_run={run_2} echo_after_ms={}",
        back.as_millis()
    );

    // --- 2d. A runtime downgrade of the bound Redis, then a crash. ---
    // `CONFIG SET appendfsync everysec` on the running Redis, not written to
    // its configuration: after a crash it comes back with `always`, so only
    // the relay's check of the *bound* run can have noticed the window in
    // which acknowledged writes were not durable.
    // Only lines printed from here on count.
    m6c65_mark(&fixture.relay_log, &mut relay_lines);
    relay_lines.clear();
    redis.config_set("appendfsync", "everysec");
    let downgrade = m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis authority continuity check failed; stage=authority_identity class=persistence",
        STEP_DEADLINE,
    );
    // Past the freshness bound: one interval plus 5 s.
    tokio::time::sleep(Duration::from_secs(M6C65_CONTINUITY_SECONDS + 7)).await;
    let lines_before_downgrade_crash = m6c65_mark(&fixture.relay_log, &mut relay_lines);
    let run_before_downgrade = redis.run_id();
    redis.crash_and_start();
    let run_after_downgrade = redis.run_id();
    let stale = m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis authority continuity check failed; stage=authority_identity class=run_changed",
        STEP_DEADLINE,
    );
    m6c65_assert_not_rebound(
        &fixture.relay_log,
        &mut relay_lines,
        lines_before_downgrade_crash,
        Duration::from_secs(4),
    );
    assert_eq!(
        namespace_get(&fixture, "meta:redis_run_id"),
        run_before_downgrade,
        "a relay whose last durable token is stale must not re-bind"
    );
    // The operator re-attests it; the serving relay, which refused the run
    // as `run_changed` and not for continuity, picks the binding up.
    let reattested = stdout(&step(
        "rebind-redis-run after the downgrade",
        Command::new(&fixture.relay_bin)
            .args(["rebind-redis-run", "--config"])
            .arg(&fixture.relay_config)
            .arg("--redis-restarted-in-place"),
    ));
    assert!(
        reattested.contains(&format!(
            "from Redis run {run_before_downgrade} to {run_after_downgrade}"
        )),
        "{reattested}"
    );
    let adopted = m6c65_echo_until_served(
        "adopt-reattested",
        &fixture,
        &mut device,
        &token,
        M6C65_RECOVERY_DEADLINE,
    )
    .await;
    assert_eq!(fixture.relay.0.id(), relay_pid);
    m6c65_expect_rebinds(&fixture.relay_log, &mut relay_lines, 4);
    println!(
        "m6c65-downgrade ok nonce={nonce} downgrade={downgrade:?} refused={stale:?} \
         adopted_after_rebind_ms={} relay_restarts=0",
        adopted.as_millis()
    );
    let run_2 = run_after_downgrade;

    // --- 3. Relay stopped, Redis restarted, relay started: operator command. ---
    m6c65_stop_relay(&mut fixture.relay);
    redis.restart();
    let run_3 = redis.run_id();
    assert_ne!(run_2, run_3);
    let refused = m6c65_serve_refused(
        &fixture,
        "Redis catalog connection failed; stage=authority_identity class=run_changed",
    );
    let undeclared = relay_change_refused(
        &fixture,
        "rebind without declaration",
        &["rebind-redis-run"],
    );
    assert!(
        undeclared.contains("--redis-restarted-in-place"),
        "{undeclared}"
    );
    let rebind = stdout(&step(
        "rebind-redis-run",
        Command::new(&fixture.relay_bin)
            .args(["rebind-redis-run", "--config"])
            .arg(&fixture.relay_config)
            .arg("--redis-restarted-in-place"),
    ));
    assert!(
        rebind.contains(&format!("from Redis run {run_2} to {run_3}"))
            && rebind.contains(&fixture.namespace),
        "{rebind}"
    );
    let again = stdout(&step(
        "rebind-redis-run again",
        Command::new(&fixture.relay_bin)
            .args(["rebind-redis-run", "--config"])
            .arg(&fixture.relay_config)
            .arg("--redis-restarted-in-place"),
    ));
    assert!(again.contains("nothing changed"), "{again}");
    assert!(
        rebind.contains("on the operator's declaration") && rebind.contains("not verified"),
        "{rebind}"
    );
    // Continuity refuses to start on a Redis that acknowledges before fsync.
    redis.config_set("appendfsync", "everysec");
    let unsound = m6c65_serve_refused(
        &fixture,
        "Redis restart continuity could not start; stage=authority_identity class=persistence",
    );
    redis.config_set("appendfsync", "always");
    let (relay, relay_log) = start_serve(&fixture.relay_bin, &fixture.relay_config);
    fixture.relay = relay;
    fixture.relay_log = relay_log;
    relay_lines.clear();
    let operator = m6c65_echo_until_served(
        "operator",
        &fixture,
        &mut device,
        &token,
        M6C65_RECOVERY_DEADLINE,
    )
    .await;
    println!(
        "m6c65-operator ok nonce={nonce} run_before={run_2} run_after={run_3} \
         refused={refused:?} unsound={unsound:?} echo_after_ms={}",
        operator.as_millis()
    );

    // --- 4. A restore of an older snapshot is refused. ---
    let snapshot = fixture.work.join("older.rdb");
    redis.snapshot(&snapshot);
    let revoked = relay_change(
        &fixture,
        "revoke-grant after the snapshot",
        &[
            "revoke-grant",
            "--tenant",
            &tenant,
            "--user",
            &user,
            "--device",
            &fixture.device.to_string(),
            "--service",
            &fixture.service.to_string(),
        ],
    );
    assert!(revoked.contains("revision="), "{revoked}");
    let status = m6c65_echo_status(&fixture, &token).await;
    assert!(
        matches!(status, 403 | 404),
        "the revoked grant must be refused: HTTP {status}"
    );
    // Let the relay write continuity tokens after the snapshot.
    let before_tokens = namespace_get(&fixture, "meta:continuity");
    tokio::time::sleep(Duration::from_secs(3 * M6C65_CONTINUITY_SECONDS)).await;
    assert_ne!(namespace_get(&fixture, "meta:continuity"), before_tokens);
    let lines_before_restore = m6c65_mark(&fixture.relay_log, &mut relay_lines);
    redis.replace_with_rdb(&snapshot);
    let run_4 = redis.run_id();
    // The restored snapshot holds the grant as active again.  For as long
    // as a device would take to come back (the owner lease included), the
    // relay must never serve it.
    let watched = Instant::now();
    let mut statuses = std::collections::BTreeMap::<u16, u32>::new();
    while watched.elapsed() < M6C65_RECOVERY_DEADLINE {
        device.ensure_running();
        let status = m6c65_echo_status(&fixture, &token).await;
        assert_ne!(
            status,
            200,
            "a relay served from a Redis restored to before the grant was revoked; connect log: {}",
            device.log()
        );
        *statuses.entry(status).or_default() += 1;
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    let continuity = m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis authority continuity check failed; stage=authority_identity class=continuity",
        STEP_DEADLINE,
    );
    assert_eq!(
        namespace_get(&fixture, "meta:redis_run_id"),
        run_3,
        "the refused relay must not re-bind the restored namespace"
    );
    m6c65_assert_not_rebound(
        &fixture.relay_log,
        &mut relay_lines,
        lines_before_restore,
        Duration::from_secs(2),
    );
    let fresh = m6c65_serve_refused(
        &fixture,
        "Redis catalog connection failed; stage=authority_identity class=run_changed",
    );
    // An operator who wrongly re-attests the restored Redis changes the
    // binding, but a relay that already refused that run for continuity
    // keeps refusing it.
    let wrongly = stdout(&step(
        "rebind-redis-run on the restored Redis",
        Command::new(&fixture.relay_bin)
            .args(["rebind-redis-run", "--config"])
            .arg(&fixture.relay_config)
            .arg("--redis-restarted-in-place"),
    ));
    assert!(
        wrongly.contains(&format!("from Redis run {run_3} to {run_4}")),
        "{wrongly}"
    );
    let lines_before_attest = m6c65_mark(&fixture.relay_log, &mut relay_lines);
    m6c65_assert_not_rebound(
        &fixture.relay_log,
        &mut relay_lines,
        lines_before_attest,
        Duration::from_secs(4),
    );
    for _ in 0..5 {
        device.ensure_running();
        assert_ne!(
            m6c65_echo_status(&fixture, &token).await,
            200,
            "a relay that refused a run for continuity served it after an operator re-attested it"
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    println!("m6c65-reattest-refused ok nonce={nonce} run={run_4}");
    println!(
        "m6c65-rollback ok nonce={nonce} run={run_4} line={continuity:?} \
         echo_statuses={statuses:?} watched_ms={} fresh_serve={fresh:?}",
        watched.elapsed().as_millis()
    );

    // --- 5. An empty Redis is refused. ---
    let lines_before_empty = m6c65_mark(&fixture.relay_log, &mut relay_lines);
    redis.replace_empty();
    let unbound = m6c65_wait_line(
        &fixture.relay_log,
        &mut relay_lines,
        "Redis authority continuity check failed; stage=authority_identity class=unbound",
        STEP_DEADLINE,
    );
    assert_ne!(m6c65_echo_status(&fixture, &token).await, 200);
    m6c65_assert_not_rebound(
        &fixture.relay_log,
        &mut relay_lines,
        lines_before_empty,
        Duration::from_secs(3),
    );
    let keys_left = redis_command(
        redis.upstream(),
        0,
        &["KEYS", &format!("tunnel-catalog:{}:*", fixture.namespace)],
    );
    assert!(
        !String::from_utf8_lossy(&keys_left).contains("tunnel-catalog:"),
        "nothing may be written into the empty Redis: {}",
        String::from_utf8_lossy(&keys_left)
    );
    let fresh = m6c65_serve_refused(
        &fixture,
        "Redis catalog connection failed; stage=authority_identity class=unbound",
    );
    let command = relay_change_refused(
        &fixture,
        "rebind on an empty Redis",
        &["rebind-redis-run", "--redis-restarted-in-place"],
    );
    assert!(
        command.contains("stage=authority_identity class=unbound"),
        "{command}"
    );
    println!(
        "m6c65-empty ok nonce={nonce} line={unbound:?} fresh_serve={fresh:?} \
         device_spawns={}",
        device.spawns
    );
    drop(device);
    drop(fixture);
    drop(redis);
}
