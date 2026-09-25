//! Task row M6-06: clean shutdown from every rotation phase, on the shipped
//! binaries against a real Redis.
//!
//! For each data-socket rotation phase -- `active`, `preparing`,
//! `quiescing`, `draining`, `committing`, `aborting` -- the client and, in a
//! second test, the relay is sent SIGTERM while it **reports** that phase,
//! and must stop in order:
//!
//! * **The phase is pinned, not raced.** A `tunnel-client` built with
//!   `--features test-hooks` reads `TUNNEL_CLIENT_TEST_HOLD`, a list of
//!   inbound rotation message kinds it drops (and `candidate-dial`, which
//!   withholds the candidate data socket), so both state machines stop
//!   advancing at a chosen step and stay there until the overlap deadline.
//!   The owner drives a rotation and the two machines move at different
//!   messages, so each side's phase needs its own hold (`cases`). The
//!   hook exists only in that build; the shipped client has no such
//!   variable.
//! * **The phase is witnessed before the signal.** The client's phase is
//!   read through `tunnel-client status --json` -- the supervisor IPC this
//!   row adds -- and the relay's from its private metrics listener's
//!   `tunnel_relay_sessions_by_rotation_phase`, also added here. The signal
//!   is sent only once the side being stopped reports the case's phase.
//! * **Orderly means:** exit `0`; the client's `stopped` event naming
//!   SIGTERM, or the relay's `tunnel-relay stopped: signal=SIGTERM`; no
//!   process left in the group the binary led; the client's supervisor
//!   socket removed; and the owner slot released in order, so a fresh
//!   connector (client stopped) or the same connector against a restarted
//!   relay (relay stopped) is admitted at once rather than after the 30 s
//!   stale-lease window, and serves an echo.
//! * **In-flight work gets an explicit outcome.** An echo is sent 200 ms
//!   before each signal; it must end as the device's answer or as a typed
//!   refusal whose `execution` is `not_dispatched` or `unknown` -- never a
//!   dropped connection and never a hang.
//!
//! Each case prints `m606-shutdown ok case=...` only after all of it held,
//! and each test `m606-shutdown matrix ok`, so a filtered or skipped run
//! cannot be read as a pass. Ignored in the ordinary workspace run (Redis,
//! and a client built with the hook); `scripts/m6-shutdown-phases-verify.sh`
//! builds both and runs it. Deployment helpers are copied from
//! `m6_reconnect_process.rs`, as that file copies them, so neither gate's
//! evidence moves with the other.

#![cfg(unix)]

use std::{
    env, fs,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    os::unix::process::CommandExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Output, Stdio},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::TokioIo;
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::Value;
use tokio::net::{TcpListener as TokioTcpListener, TcpStream};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use uuid::Uuid;

const ISSUER: &str = "https://issuer.m606.invalid/";
const AUDIENCE: &str = "agent-tunnel";
const CANARY: &str = "m1-device-a-synthetic";
const STEP_DEADLINE: Duration = Duration::from_secs(30);
const RECONNECT: &str = "\n[reconnect]\ninitial_delay_ms = 200\nmax_delay_ms = 1000\n";

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
        if env::var_os("M606_KEEP_WORKDIR").is_none() {
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
        .push(DnType::CommonName, "M6-06 synthetic server CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("server CA");
    let leaf_key = KeyPair::generate().expect("server leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "M6-06 synthetic relay");
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
            "kid": "m606-issuer", "kty": "RSA", "alg": "RS256",
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
    header.kid = Some("m606-issuer".to_owned());
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

struct Running(Child);

impl Drop for Running {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Relay {
    process: Running,
    lines: Arc<Mutex<Vec<String>>>,
}

/// One provisioned relay and device, with nothing running yet.
struct Deployment {
    nonce: String,
    relay_bin: PathBuf,
    client_bin: PathBuf,
    relay_config: PathBuf,
    client_config: PathBuf,
    /// The client's supervisor socket, set with `[supervisor] ipc_path`: the
    /// default beside the key would not fit `sun_path` under macOS's long
    /// temporary directory.
    supervisor_socket: PathBuf,
    consumer: SocketAddr,
    metrics: SocketAddr,
    server_ca_pem: String,
    issuer_key: jsonwebtoken::EncodingKey,
    subject: String,
    echo_path: String,
    _namespace: NamespaceGuard,
    _workdir: Workdir,
    _socket_dir: Workdir,
}

impl Deployment {
    /// The M6-C21 operator procedure with shipped binaries, as
    /// `m6_reconnect_process.rs` does it, plus the rotation policy and the
    /// private metrics listener this gate reads the relay's phase from.
    async fn provision(label: &str) -> Self {
        let redis_url = env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL (plaintext) is required");
        let client_bin = PathBuf::from(env::var_os("TUNNEL_CLIENT_BIN").expect(
            "TUNNEL_CLIENT_BIN must name a tunnel-client built with --features test-hooks",
        ));
        let relay_bin = env::var_os("TUNNEL_RELAY_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_tunnel-relay")));
        let (upstream, database) = parse_plaintext_redis(&redis_url);
        let nonce = Uuid::new_v4().simple().to_string();
        let namespace = format!("m606-{label}-{nonce}");
        let incarnation = format!("m606-{label}-{nonce}");
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
        let namespace_guard = NamespaceGuard {
            upstream,
            database,
            namespace: namespace.clone(),
        };
        // Short: the supervisor socket lives beside the device key, and a
        // Unix socket path must fit `sun_path`.
        let dir = Workdir(env::temp_dir().join(format!("m606-{}", &nonce[..12])));
        fs::create_dir_all(&dir.0).expect("create workdir");
        let work = dir.0.canonicalize().expect("canonical workdir");
        println!(
            "m606-shutdown start label={label} nonce={nonce} namespace={namespace} relay={} client={} workdir={}",
            relay_bin.display(),
            client_bin.display(),
            work.display()
        );

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
        let metrics = free_port();

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
        client_toml = set_rotation(&client_toml);
        client_toml.push_str(RECONNECT);
        let socket_dir = Workdir(PathBuf::from(format!("/tmp/m606-{}", &nonce[..8])));
        fs::create_dir_all(&socket_dir.0).expect("socket dir");
        fs::set_permissions(&socket_dir.0, fs::Permissions::from_mode(0o700))
            .expect("socket dir mode");
        let supervisor_socket = socket_dir.0.join("s.sock");
        client_toml.push_str(&format!(
            "\n[supervisor]\nipc_path = {}\n",
            toml_string(&supervisor_socket)
        ));
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
        let device_ca_key = work.join("device-ca-key.pem");
        let device_ca = work.join("device-ca.pem");
        step(
            "device CA (openssl req -x509)",
            Command::new("openssl")
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
                ])
                .args(["-subj", "/CN=M6-06 synthetic device CA", "-keyout"])
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
            ("boot_id", format!("\"m606-boot-{nonce}\"")),
            ("deployment_incarnation", format!("\"{incarnation}\"")),
        ] {
            relay_toml = set_key(&relay_toml, key, &value);
        }
        relay_toml = set_rotation(&relay_toml);
        relay_toml = format!(
            "metrics_bind = \"{metrics}\"\nredis_tls_root_ca_path = {}\n{relay_toml}",
            toml_string(&server_ca)
        );
        let relay_config = work.join("relay.toml");
        fs::write(&relay_config, relay_toml).expect("relay config");
        let records = work.join("device/catalog.toml");
        fs::write(&records, &catalog_example).expect("records");
        step(
            "first incarnation (tunnel-relay activate-first-incarnation)",
            Command::new(&relay_bin)
                .args(["activate-first-incarnation", "--config"])
                .arg(&relay_config),
        );
        step(
            "catalog records (tunnel-relay provision-catalog)",
            Command::new(&relay_bin)
                .args(["provision-catalog", "--config"])
                .arg(&relay_config)
                .arg("--records")
                .arg(&records),
        );
        Self {
            nonce,
            relay_bin,
            client_bin,
            relay_config,
            client_config,
            supervisor_socket,
            consumer,
            metrics,
            server_ca_pem: pki.ca_pem,
            issuer_key,
            subject,
            echo_path: format!("/v1/devices/{device}/services/{service}/echo"),
            _namespace: namespace_guard,
            _workdir: dir,
            _socket_dir: socket_dir,
        }
    }

    /// Start `serve` in its own process group and wait until it listens.
    fn serve(&self, name: &str) -> Relay {
        let mut process = Running(
            Command::new(&self.relay_bin)
                .args(["serve", "--config"])
                .arg(&self.relay_config)
                .env("RUST_LOG", "warn")
                .process_group(0)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn serve"),
        );
        let stderr = process.0.stderr.take().expect("serve stderr");
        let lines = Arc::new(Mutex::new(Vec::new()));
        let (tx, rx) = std::sync::mpsc::channel::<()>();
        {
            let lines = Arc::clone(&lines);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    let listening = line.starts_with("tunnel-relay listening");
                    lines.lock().expect("relay log").push(line);
                    if listening {
                        let _ = tx.send(());
                    }
                }
            });
        }
        let deadline = Instant::now() + STEP_DEADLINE;
        loop {
            if rx.recv_timeout(Duration::from_millis(100)).is_ok() {
                return Relay { process, lines };
            }
            if let Ok(Some(status)) = process.0.try_wait() {
                panic!(
                    "step {name}: serve exited {status} before listening: {:?}",
                    lines.lock().expect("relay log")
                );
            }
            assert!(
                Instant::now() < deadline,
                "step {name}: serve not listening within {STEP_DEADLINE:?}"
            );
        }
    }

    /// Start `connect --json` in its own process group, holding the named
    /// rotation steps (`TUNNEL_CLIENT_TEST_HOLD`, a `test-hooks` build only).
    fn connect(&self, hold: &str) -> Client {
        let mut command = Command::new(&self.client_bin);
        command
            .args(["connect", "--config"])
            .arg(&self.client_config)
            .arg("--json")
            .process_group(0)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !hold.is_empty() {
            command.env("TUNNEL_CLIENT_TEST_HOLD", hold);
        }
        let mut child = command.spawn().expect("spawn connect");
        let events = Arc::new(Mutex::new(Vec::new()));
        let stderr_lines = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("connect stdout");
        let stderr = child.stderr.take().expect("connect stderr");
        {
            let events = Arc::clone(&events);
            std::thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    let value = serde_json::from_str(&line)
                        .unwrap_or_else(|_| Value::String(format!("non-JSON stdout: {line}")));
                    events.lock().expect("events").push((Instant::now(), value));
                }
            });
        }
        {
            let stderr_lines = Arc::clone(&stderr_lines);
            std::thread::spawn(move || {
                for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                    stderr_lines.lock().expect("stderr").push(line);
                }
            });
        }
        Client {
            process: Running(child),
            events,
            stderr: stderr_lines,
        }
    }

    /// The relay's one session's rotation phase, from its private metrics.
    fn relay_phase(&self) -> Option<String> {
        use std::io::{Read, Write};
        let mut stream =
            std::net::TcpStream::connect_timeout(&self.metrics, Duration::from_secs(1)).ok()?;
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        stream
            .write_all(b"GET /metrics HTTP/1.0\r\nHost: metrics\r\n\r\n")
            .ok()?;
        let mut text = String::new();
        let _ = stream.read_to_string(&mut text);
        text.lines().find_map(|line| {
            let rest = line.strip_prefix("tunnel_relay_sessions_by_rotation_phase{phase=\"")?;
            let (phase, value) = rest.split_once("\"} ")?;
            (value.trim() != "0").then(|| phase.to_owned())
        })
    }

    /// The client's rotation phase, read through its own supervisor IPC:
    /// `tunnel-client status --json`, the surface this row adds.
    fn client_phase(&self) -> Option<String> {
        let output = Command::new(&self.client_bin)
            .args(["status", "--config"])
            .arg(&self.client_config)
            .arg("--json")
            .output()
            .ok()?;
        let report: Value =
            serde_json::from_slice(output.stdout.split(|b| *b == b'\n').next()?).ok()?;
        report["result"]["session"]["phase"]
            .as_str()
            .map(str::to_owned)
    }

    async fn echo_once(&self, payload: &str) -> Result<(u16, Vec<u8>), String> {
        let token = access_token(&self.issuer_key, &self.subject);
        consumer_post(
            self.consumer,
            &self.server_ca_pem,
            &self.echo_path,
            &token,
            payload.as_bytes(),
        )
        .await
    }

    /// One echo through the relay to the device, retried until it succeeds.
    async fn echo(&self, step_name: &str) {
        let payload = format!("m606-{step_name}-{}", self.nonce);
        let deadline = Instant::now() + STEP_DEADLINE;
        loop {
            let attempt = self.echo_once(&payload).await;
            if let Ok((200, body)) = &attempt {
                assert_eq!(String::from_utf8_lossy(body), format!("{CANARY}{payload}"));
                return;
            }
            assert!(
                Instant::now() < deadline,
                "step {step_name}: no echo within {STEP_DEADLINE:?}; last {attempt:?}"
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }
}

/// Replace the example's 300/10/30 s rotation policy with a short one, the
/// same on both ends: a rotation starts 12 s after a session is ready, the
/// candidate has 4 s to attach and the whole attempt 10 s.
fn set_rotation(document: &str) -> String {
    let document = set_key(document, "interval_seconds", "12");
    let document = set_key(&document, "handshake_timeout_seconds", "4");
    set_key(&document, "overlap_seconds", "10")
}

/// A running `tunnel-client connect --json`: its events and stderr.
struct Client {
    process: Running,
    events: Arc<Mutex<Vec<(Instant, Value)>>>,
    stderr: Arc<Mutex<Vec<String>>>,
}

impl Client {
    fn states(&self, state: &str) -> Vec<(Instant, Value)> {
        self.events
            .lock()
            .expect("events")
            .iter()
            .filter(|(_, event)| event["result"]["state"] == state)
            .cloned()
            .collect()
    }

    fn context(&self) -> String {
        let events: Vec<Value> = self
            .events
            .lock()
            .expect("events")
            .iter()
            .map(|(_, event)| event.clone())
            .collect();
        format!(
            "events {events:?} stderr {:?}",
            self.stderr.lock().expect("stderr")
        )
    }

    fn wait_for(&mut self, step_name: &str, state: &str, count: usize, within: Duration) {
        let deadline = Instant::now() + within;
        loop {
            if self.states(state).len() >= count {
                return;
            }
            if let Ok(Some(status)) = self.process.0.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                panic!(
                    "step {step_name}: the client exited ({status}) instead of reaching {count} `{state}`: {}",
                    self.context()
                );
            }
            assert!(
                Instant::now() < deadline,
                "step {step_name}: fewer than {count} `{state}` within {within:?}: {}",
                self.context()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn pid(&self) -> u32 {
        self.process.0.id()
    }
}

fn sigterm(pid: u32) {
    let status = Command::new("/bin/kill")
        .args(["-TERM", &pid.to_string()])
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -TERM {pid}");
}

/// Wait for a signalled process's exit, bounded; returns its status and how
/// long after the signal it came.
fn wait_exit(process: &mut Running, signalled: Instant, what: &str) -> (ExitStatus, Duration) {
    let deadline = signalled + STEP_DEADLINE;
    loop {
        if let Some(status) = process.0.try_wait().expect("poll") {
            return (status, signalled.elapsed());
        }
        assert!(
            Instant::now() < deadline,
            "{what} did not exit within {STEP_DEADLINE:?} of SIGTERM"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

/// No process is left in the group the binary led: nothing it started
/// outlived it.
fn assert_group_empty(pgid: u32, what: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let found = Command::new("pgrep")
            .args(["-g", &pgid.to_string()])
            .output()
            .expect("run pgrep");
        if !found.status.success() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: processes outlived it in its group {pgid}: {}",
            String::from_utf8_lossy(&found.stdout)
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// An echo in flight when the signal arrived must end in an explicit
/// outcome: the device's answer, or a typed refusal naming whether the work
/// was dispatched. A dropped connection or a hang is not an outcome.
fn explicit_outcome(
    result: Result<Result<(u16, Vec<u8>), String>, tokio::time::error::Elapsed>,
    expected: &str,
    case: &str,
) -> String {
    match result {
        Err(_) => panic!("case {case}: the in-flight echo hung past {INFLIGHT_BOUND:?}"),
        Ok(Err(error)) => {
            panic!("case {case}: the in-flight echo ended without an explicit outcome: {error}")
        }
        Ok(Ok((200, body))) => {
            assert_eq!(String::from_utf8_lossy(&body), expected, "case {case}");
            "completed".to_owned()
        }
        Ok(Ok((status, body))) => {
            let body: Value = serde_json::from_slice(&body).unwrap_or_else(|_| {
                panic!(
                    "case {case}: status {status} with a non-JSON body: {}",
                    String::from_utf8_lossy(&body)
                )
            });
            let execution = body["execution"].as_str().unwrap_or_default();
            assert!(
                matches!(execution, "not_dispatched" | "unknown"),
                "case {case}: status {status} without an explicit execution outcome: {body}"
            );
            format!(
                "{status}:{}:{execution}",
                body["code"].as_str().unwrap_or("?")
            )
        }
    }
}

const INFLIGHT_BOUND: Duration = Duration::from_secs(20);

/// Which binary a case stops.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Side {
    Client,
    Relay,
}

/// For each phase, the rotation steps the client holds so that the side
/// being stopped sits in that phase.  The owner (relay) drives a rotation
/// and the two state machines advance at different messages, so the same
/// phase needs a different hold on each side; every hold is a single
/// dropped inbound message kind or the candidate dial, and the witness --
/// the stopped side's own reported phase -- is required before the signal.
///
/// **A hold drops the message it names and the one that would follow it**
/// wherever the owner sends both. Holding `ROTATE_FROZEN` alone leaves the
/// client quiescing while the relay, which has both fences, moves on and
/// sends its `ROTATE_DRAINED`; the client then rejects a drain proof in the
/// wrong phase and ends the session `PROTOCOL_ERROR` (measured: the first
/// run's relay-draining case, log nonce `m606-shutdown-1790349672-24478`).
/// A real owner never sends DRAINED before FROZEN on the ordered control
/// socket, so that is the hook's artefact, not a product defect.
fn cases(side: Side) -> [(&'static str, &'static str); 6] {
    match side {
        Side::Client => [
            ("active", ""),
            ("preparing", "candidate-dial"),
            ("quiescing", "ROTATE_FROZEN,ROTATE_DRAINED"),
            ("draining", "ROTATE_DRAINED,ROTATE_COMMIT"),
            ("committing", "ROTATE_COMMIT"),
            ("aborting", "candidate-dial,ROTATE_ABORTED"),
        ],
        Side::Relay => [
            ("active", ""),
            ("preparing", "candidate-dial"),
            ("quiescing", "ROTATE_QUIESCE"),
            ("draining", "ROTATE_FROZEN,ROTATE_DRAINED"),
            ("committing", "ROTATE_COMMIT"),
            ("aborting", "candidate-dial,ROTATE_ABORT"),
        ],
    }
}

/// Wait until the stopped side reports `phase`, and return both sides'.
fn witness(
    deployment: &Deployment,
    side: Side,
    phase: &str,
    client: &Client,
) -> (Option<String>, Option<String>) {
    // A rotation starts 12 s after ready; an abort needs the 4 s handshake
    // budget on top.  `active` is witnessed before the first rotation.
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        let client_phase = deployment.client_phase();
        let relay_phase = deployment.relay_phase();
        let observed = match side {
            Side::Client => client_phase.as_deref(),
            Side::Relay => relay_phase.as_deref(),
        };
        if observed == Some(phase) {
            return (client_phase, relay_phase);
        }
        assert!(
            Instant::now() < deadline,
            "{side:?} never reported phase {phase}: client {client_phase:?} relay {relay_phase:?}; {}",
            client.context()
        );
        std::thread::sleep(Duration::from_millis(40));
    }
}

async fn run_matrix(side: Side) {
    let label = match side {
        Side::Client => "client",
        Side::Relay => "relay",
    };
    let deployment = Deployment::provision(label).await;
    let mut relay = deployment.serve("serve");
    let mut outcomes = Vec::new();
    for (phase, hold) in cases(side) {
        let case = format!("{label}-{phase}");
        let mut client = deployment.connect(hold);
        client.wait_for(&case, "ready", 1, STEP_DEADLINE);
        deployment.echo(&format!("{case}-before")).await;
        let (client_phase, relay_phase) = witness(&deployment, side, phase, &client);

        // Work in flight at the signal.
        let payload = format!("m606-{case}-inflight-{}", deployment.nonce);
        let expected = format!("{CANARY}{payload}");
        let inflight = {
            let token = access_token(&deployment.issuer_key, &deployment.subject);
            let (consumer, ca, path) = (
                deployment.consumer,
                deployment.server_ca_pem.clone(),
                deployment.echo_path.clone(),
            );
            tokio::spawn(async move {
                tokio::time::timeout(
                    INFLIGHT_BOUND,
                    consumer_post(consumer, &ca, &path, &token, payload.as_bytes()),
                )
                .await
            })
        };
        tokio::time::sleep(Duration::from_millis(200)).await;

        match side {
            Side::Client => {
                let pid = client.pid();
                let signalled = Instant::now();
                sigterm(pid);
                let (status, latency) = wait_exit(&mut client.process, signalled, "connect");
                std::thread::sleep(Duration::from_millis(100));
                assert_eq!(status.code(), Some(0), "case {case}: {}", client.context());
                let stopped = client.states("stopped");
                assert!(
                    stopped
                        .last()
                        .is_some_and(|(_, event)| event["result"]["signal"] == "SIGTERM"),
                    "case {case}: a `stopped` event naming SIGTERM: {}",
                    client.context()
                );
                assert_group_empty(pid, &case);
                assert!(
                    !deployment.supervisor_socket.exists(),
                    "case {case}: the supervisor socket outlived the orderly stop"
                );
                let outcome = explicit_outcome(inflight.await.expect("join"), &expected, &case);
                // The owner slot was released in order: a fresh connector is
                // admitted at once, not after the 30 s stale-lease window.
                let released = Instant::now();
                let mut fresh = deployment.connect("");
                fresh.wait_for(&case, "ready", 1, Duration::from_secs(10));
                let readmitted = released.elapsed();
                deployment.echo(&format!("{case}-after")).await;
                let fresh_pid = fresh.pid();
                let signalled = Instant::now();
                sigterm(fresh_pid);
                let (fresh_status, _) = wait_exit(&mut fresh.process, signalled, "fresh connect");
                assert_eq!(
                    fresh_status.code(),
                    Some(0),
                    "case {case}: {}",
                    fresh.context()
                );
                assert_group_empty(fresh_pid, &case);
                println!(
                    "m606-shutdown ok case={case} hold={hold:?} client_phase={client_phase:?} \
                     relay_phase={relay_phase:?} exit=0 stop_ms={} inflight={outcome} \
                     readmitted_ms={} nonce={}",
                    latency.as_millis(),
                    readmitted.as_millis(),
                    deployment.nonce
                );
                outcomes.push(outcome);
            }
            Side::Relay => {
                let pid = relay.process.0.id();
                let signalled = Instant::now();
                sigterm(pid);
                let (status, latency) = wait_exit(&mut relay.process, signalled, "serve");
                std::thread::sleep(Duration::from_millis(100));
                let lines = relay.lines.lock().expect("relay log").clone();
                assert_eq!(status.code(), Some(0), "case {case}: {lines:?}");
                assert!(
                    lines
                        .iter()
                        .any(|line| line.contains("tunnel-relay stopped: signal=SIGTERM")),
                    "case {case}: {lines:?}"
                );
                assert_group_empty(pid, &case);
                let outcome = explicit_outcome(inflight.await.expect("join"), &expected, &case);
                // The client lost its session, retryably, and did not exit.
                client.wait_for(&case, "disconnected", 1, STEP_DEADLINE);
                let lost = client.states("disconnected");
                let code = lost[0].1["result"]["code"]
                    .as_str()
                    .unwrap_or("?")
                    .to_owned();
                // The relay released the owner slot in order: a restarted
                // relay admits the reconnect at once, not after the lease.
                relay = deployment.serve("restart");
                let restarted = Instant::now();
                client.wait_for(&case, "ready", 2, Duration::from_secs(15));
                let readmitted = restarted.elapsed();
                deployment.echo(&format!("{case}-after")).await;
                let client_pid = client.pid();
                let signalled = Instant::now();
                sigterm(client_pid);
                let (client_status, _) = wait_exit(&mut client.process, signalled, "connect");
                assert_eq!(
                    client_status.code(),
                    Some(0),
                    "case {case}: {}",
                    client.context()
                );
                assert_group_empty(client_pid, &case);
                println!(
                    "m606-shutdown ok case={case} hold={hold:?} client_phase={client_phase:?} \
                     relay_phase={relay_phase:?} exit=0 stop_ms={} inflight={outcome} \
                     client_lost={code} readmitted_ms={} nonce={}",
                    latency.as_millis(),
                    readmitted.as_millis(),
                    deployment.nonce
                );
                outcomes.push(outcome);
            }
        }
    }
    let relay_pid = relay.process.0.id();
    let signalled = Instant::now();
    sigterm(relay_pid);
    let (status, _) = wait_exit(&mut relay.process, signalled, "serve");
    assert_eq!(status.code(), Some(0));
    println!(
        "m606-shutdown matrix ok side={label} cases=6 outcomes={outcomes:?} client={} nonce={}",
        deployment.client_bin.display(),
        deployment.nonce
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and a test-hooks TUNNEL_CLIENT_BIN; run by scripts/m6-shutdown-phases-verify.sh"]
async fn m606_sigterm_the_client_in_every_rotation_phase() {
    run_matrix(Side::Client).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and a test-hooks TUNNEL_CLIENT_BIN; run by scripts/m6-shutdown-phases-verify.sh"]
async fn m606_sigterm_the_relay_in_every_rotation_phase() {
    run_matrix(Side::Relay).await;
}
