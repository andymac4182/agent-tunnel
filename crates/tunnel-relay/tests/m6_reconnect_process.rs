//! Task row M6-C23: `tunnel-client connect` reconnects after losing its relay,
//! proved with the shipped binaries against a real Redis.
//!
//! The deployment is brought up exactly as `m6_provisioning_process.rs` does
//! it (whose helpers are copied here rather than shared, so that gate's
//! evidence is untouched): device key and CSR, an `openssl`-issued device
//! certificate, `activate-first-incarnation`, `provision-catalog`, `serve`.
//! Then the relay is taken away underneath a running `connect`:
//!
//! * `m6c23_connect_reconnects_after_the_relay_is_killed_and_after_it_is_stopped`
//!   -- a ready session, one echo; the relay is **SIGKILLed**, stays down long
//!   enough for the client to back off at least twice, and is restarted: the
//!   client must reconnect to a new session and serve an echo again. Then the
//!   relay is stopped **in order (SIGTERM)** and restarted, and the same must
//!   hold. Finally the client is stopped with SIGTERM and must exit `0`.
//! * `m6c23_connect_started_before_its_relay_backs_off_until_the_relay_appears`
//!   -- the client starts while nothing listens, backs off at least twice with
//!   `TRANSPORT_ERROR`, and connects once `serve` starts.
//! * `m6c23_a_device_certificate_not_yet_valid_is_retried_until_it_is` --
//!   clock skew: a device certificate re-issued with `notBefore` 20 s ahead is
//!   refused by `serve`'s TLS verifier with `certificate_expired`, retried,
//!   and accepted once valid.
//! * `m6c23_an_expired_device_certificate_exits_three_without_retrying` -- the
//!   same alert for a certificate past `notAfter` on the client's clock too:
//!   exit `3`, no backoff.
//! * `m6c23_a_rogue_device_ca_and_a_wrong_server_ca_exit_three_without_retrying`
//!   -- M6-C54's two issuer cases against a real relay: a device certificate
//!   from a CA the relay does not trust, and a profile whose `server_ca` did
//!   not sign the relay's certificate; each exits `3` after one attempt.
//! * `m6c23_an_identity_mismatch_exits_three_without_retrying` -- the
//!   integration with M6-C32: a `device_id` that is not the certificate's
//!   device draws `1008 DEVICE_IDENTITY_REJECTED`, and the loop exits `3`
//!   after one attempt instead of backing off.
//!
//! * `m6c38_a_hello_on_another_protocol_major_is_closed_typed` -- task row
//!   M6-C38, the relay half against the real `serve`: a device, holding the
//!   provisioned certificate, sends a HELLO naming protocol major 2 and must
//!   be answered with the typed `1002 PROTOCOL_UNSUPPORTED` close (the client
//!   half, the real `tunnel-client` exiting `1` on that close without a
//!   backoff, is `crates/tunnel-client/tests/reconnect_cli.rs`), and the
//!   relay must log one payload-free refusal line for it (M6-C52).  The
//!   identity-mismatch case above also requires its refusal line.
//!
//! * `m6c68_a_relay_evicts_a_device_whose_path_vanished_and_admits_its_reconnect`
//!   -- task row M6-C68, the M6-C23 reviewer's cut path: the client reaches
//!   the relay through a TCP proxy. A healthy session is first left idle for
//!   longer than the relay's idle timeout and must survive (the relay's Pings
//!   are answered). Then the proxy drops the client's half of every
//!   connection while holding the relay's half open and silent, as a laptop
//!   changing networks or a NAT rebinding does. The client is refused
//!   `OWNER_BUSY` while the relay still holds the dead session, and must see
//!   a second `ready` within the relay's stated bound
//!   (`DEVICE_CONTROL_IDLE_TIMEOUT` plus the disconnect hand-off), inside the
//!   client's 60 s `OWNER_BUSY` window.
//!
//! Every step asserts on the client's `--json` events and on a real echo
//! through the relay, and each run prints `m6c23-reconnect ok ...` only after
//! all of it held, so a filtered or skipped run cannot be read as a pass.
//! Ignored in the ordinary workspace run (Redis); `scripts/m6-reconnect-verify.sh`
//! builds both binaries and runs it.

use std::{
    env, fs,
    io::{BufRead, BufReader},
    net::{SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
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
use tunnel_protocol::{DEVICE_CONTROL_IDLE_TIMEOUT, DEVICE_CONTROL_PING_INTERVAL};
use uuid::Uuid;

const ISSUER: &str = "https://issuer.m6c23.invalid/";
const AUDIENCE: &str = "agent-tunnel";
const CANARY: &str = "m1-device-a-synthetic";
const STEP_DEADLINE: Duration = Duration::from_secs(30);

/// Bound on the reconnect after the relay was SIGKILLed: its owner record
/// outlives it in Redis until the lease lapses, and the client is refused
/// `OWNER_BUSY` until then (measured; see docs/runtime.md).
const STALE_OWNER_DEADLINE: Duration = Duration::from_secs(150);

/// The client's reconnect policy in these runs: small, so the gate is quick,
/// and a cap well under the step deadline.
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
        if env::var_os("M6C23_KEEP_WORKDIR").is_none() {
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
        .push(DnType::CommonName, "M6-C23 synthetic server CA");
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let ca = ca_params.self_signed(&ca_key).expect("server CA");
    let leaf_key = KeyPair::generate().expect("server leaf key");
    let mut leaf_params =
        CertificateParams::new(vec!["localhost".to_owned()]).expect("server leaf params");
    leaf_params
        .distinguished_name
        .push(DnType::CommonName, "M6-C23 synthetic relay");
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
            "kid": "m6c23-issuer", "kty": "RSA", "alg": "RS256",
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
    header.kid = Some("m6c23-issuer".to_owned());
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

/// One provisioned relay and device, with nothing running yet.
struct Deployment {
    nonce: String,
    relay_bin: PathBuf,
    client_bin: PathBuf,
    relay_config: PathBuf,
    client_config: PathBuf,
    consumer: SocketAddr,
    /// The relay's device listener, for a test that puts a proxy in front.
    device_listener: SocketAddr,
    server_ca_pem: String,
    issuer_key: jsonwebtoken::EncodingKey,
    subject: String,
    echo_path: String,
    /// What re-issuing the device certificate needs: the CSR, the device CA
    /// and its key, the extensions file, and the path the profile reads.
    reissue: Reissue,
    _namespace: NamespaceGuard,
    _workdir: Workdir,
}

impl Deployment {
    /// The M6-C21 operator procedure, with shipped binaries only.
    async fn provision(label: &str) -> Self {
        let redis_url = env::var("TEST_REDIS_URL").expect("TEST_REDIS_URL (plaintext) is required");
        let client_bin = PathBuf::from(
            env::var_os("TUNNEL_CLIENT_BIN")
                .expect("TUNNEL_CLIENT_BIN must name a freshly built tunnel-client"),
        );
        let relay_bin = env::var_os("TUNNEL_RELAY_BIN")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_tunnel-relay")));
        let (upstream, database) = parse_plaintext_redis(&redis_url);
        let nonce = Uuid::new_v4().simple().to_string();
        let namespace = format!("m6c23-{label}-{nonce}");
        let incarnation = format!("m6c23-{label}-{nonce}");
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
        let dir = Workdir(env::temp_dir().join(format!("m6c23-{label}-{nonce}")));
        fs::create_dir_all(&dir.0).expect("create workdir");
        let work = dir.0.canonicalize().expect("canonical workdir");
        println!(
            "m6c23-reconnect start label={label} nonce={nonce} namespace={namespace} relay={} client={} workdir={}",
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
        client_toml.push_str(RECONNECT);
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
                .args(["-subj", "/CN=M6-C23 synthetic device CA", "-keyout"])
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
            ("boot_id", format!("\"m6c23-boot-{nonce}\"")),
            ("deployment_incarnation", format!("\"{incarnation}\"")),
        ] {
            relay_toml = set_key(&relay_toml, key, &value);
        }
        relay_toml = format!(
            "redis_tls_root_ca_path = {}\n{relay_toml}",
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
            consumer,
            device_listener,
            server_ca_pem: pki.ca_pem,
            issuer_key,
            subject,
            echo_path: format!("/v1/devices/{device}/services/{service}/echo"),
            reissue: Reissue {
                csr: work.join("device/device.csr"),
                ca: device_ca,
                ca_key: device_ca_key,
                extensions,
                installed: work.join("device/credentials/device-cert-chain.pem"),
            },
            _namespace: namespace_guard,
            _workdir: dir,
        }
    }

    /// Start `serve` and wait until it prints `tunnel-relay listening`.
    fn serve(&self, name: &str) -> Running {
        self.serve_at(name, "warn", None)
    }

    /// [`Deployment::serve`] at the relay's default `info` level, keeping
    /// every stderr line after `listening` for the caller (M6-C52).
    fn serve_logged(&self, name: &str) -> (Running, Arc<Mutex<Vec<String>>>) {
        let lines = Arc::new(Mutex::new(Vec::new()));
        let relay = self.serve_at(name, "info", Some(Arc::clone(&lines)));
        (relay, lines)
    }

    fn serve_at(&self, name: &str, level: &str, keep: Option<Arc<Mutex<Vec<String>>>>) -> Running {
        let mut relay = Running(
            Command::new(&self.relay_bin)
                .args(["serve", "--config"])
                .arg(&self.relay_config)
                .env("RUST_LOG", level)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()
                .expect("spawn serve"),
        );
        let stderr = relay.0.stderr.take().expect("serve stderr");
        let (tx, rx) = std::sync::mpsc::channel::<String>();
        std::thread::spawn(move || {
            for line in BufReader::new(stderr).lines().map_while(Result::ok) {
                let _ = tx.send(line);
            }
        });
        let deadline = Instant::now() + STEP_DEADLINE;
        let mut lines = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(100)) {
                Ok(line) if line.starts_with("tunnel-relay listening") => break,
                Ok(line) => lines.push(line),
                Err(_) => {}
            }
            if let Ok(Some(status)) = relay.0.try_wait() {
                panic!("step {name}: serve exited {status} before listening: {lines:?}");
            }
            assert!(
                Instant::now() < deadline,
                "step {name}: serve not listening within {STEP_DEADLINE:?}: {lines:?}"
            );
        }
        // Keep draining so a full pipe can never stall the relay.
        std::thread::spawn(move || {
            while let Ok(line) = rx.recv() {
                if let Some(keep) = &keep {
                    keep.lock().expect("relay log").push(line);
                }
            }
        });
        relay
    }

    /// One echo through the relay to the device, retried until the step
    /// deadline; returns only on the device's canary followed by the bytes.
    async fn echo(&self, step_name: &str, client: &Client) {
        let token = access_token(&self.issuer_key, &self.subject);
        let payload = format!("m6c23-{step_name}-{}", self.nonce);
        let deadline = Instant::now() + STEP_DEADLINE;
        let expected = format!("{CANARY}{payload}");
        loop {
            let attempt = consumer_post(
                self.consumer,
                &self.server_ca_pem,
                &self.echo_path,
                &token,
                payload.as_bytes(),
            )
            .await;
            if let Ok((200, body)) = &attempt {
                assert_eq!(
                    String::from_utf8_lossy(body),
                    expected,
                    "step {step_name}: the reply must be the canary and the bytes sent"
                );
                return;
            }
            assert!(
                Instant::now() < deadline,
                "step {step_name}: no echo within {STEP_DEADLINE:?}; last {attempt:?}; client {}",
                client.context()
            );
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    }

    fn connect(&self) -> Client {
        self.connect_with(&self.client_config)
    }

    fn connect_with(&self, profile: &Path) -> Client {
        let mut child = Command::new(&self.client_bin)
            .args(["connect", "--config"])
            .arg(profile)
            .arg("--json")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn connect");
        let events = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("connect stdout");
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
        Client {
            process: Running(child),
            events,
        }
    }
}

struct Reissue {
    csr: PathBuf,
    ca: PathBuf,
    ca_key: PathBuf,
    extensions: PathBuf,
    installed: PathBuf,
}

impl Deployment {
    /// The issuer re-signs the same CSR (same key, so the catalog's SPKI
    /// still matches) with the validity window `[not_before, not_after]`,
    /// unix seconds, and it replaces the certificate the profile reads.
    fn reissue_device_certificate(&self, not_before: i64, not_after: i64) {
        let stamp = |unix: i64| {
            chrono::DateTime::from_timestamp(unix, 0)
                .expect("representable time")
                .format("%Y%m%d%H%M%SZ")
                .to_string()
        };
        let issued = self.reissue.installed.with_extension("reissued.pem");
        step(
            "re-issue the device certificate (openssl x509 -req -not_before -not_after)",
            Command::new("openssl")
                .args(["x509", "-req", "-in"])
                .arg(&self.reissue.csr)
                .arg("-CA")
                .arg(&self.reissue.ca)
                .arg("-CAkey")
                .arg(&self.reissue.ca_key)
                .args(["-CAcreateserial", "-not_before"])
                .arg(stamp(not_before))
                .arg("-not_after")
                .arg(stamp(not_after))
                .arg("-extfile")
                .arg(&self.reissue.extensions)
                .arg("-out")
                .arg(&issued),
        );
        fs::copy(&issued, &self.reissue.installed).expect("install re-issued certificate");
    }
}

fn unix_now() -> i64 {
    chrono::Utc::now().timestamp()
}

/// A running `tunnel-client connect --json` and its timestamped events.
struct Client {
    process: Running,
    events: Arc<Mutex<Vec<(Instant, Value)>>>,
}

impl Client {
    fn events(&self) -> Vec<(Instant, Value)> {
        self.events.lock().expect("events").clone()
    }

    fn states(&self, state: &str) -> Vec<(Instant, Value)> {
        self.events()
            .into_iter()
            .filter(|(_, event)| {
                // `lost` is a `disconnected` event that ended a ready
                // session; the others end an attempt that never got one.
                if state == "lost" {
                    event["result"]["state"] == "disconnected"
                        && event["result"]["session_id"].is_string()
                } else {
                    event["result"]["state"] == state
                }
            })
            .collect()
    }

    fn context(&self) -> String {
        let events: Vec<Value> = self.events().into_iter().map(|(_, event)| event).collect();
        format!("{events:?}")
    }

    /// Wait until at least `count` events of `state` exist; the client must
    /// stay running meanwhile.
    fn wait_for(&mut self, step_name: &str, state: &str, count: usize) -> Vec<(Instant, Value)> {
        self.wait_for_within(step_name, state, count, STEP_DEADLINE)
    }

    fn wait_for_within(
        &mut self,
        step_name: &str,
        state: &str,
        count: usize,
        within: Duration,
    ) -> Vec<(Instant, Value)> {
        let deadline = Instant::now() + within;
        loop {
            let found = self.states(state);
            if found.len() >= count {
                return found;
            }
            if let Ok(Some(status)) = self.process.0.try_wait() {
                std::thread::sleep(Duration::from_millis(100));
                panic!(
                    "step {step_name}: the client exited ({status}) instead of reaching {count} `{state}` event(s): {}",
                    self.context()
                );
            }
            assert!(
                Instant::now() < deadline,
                "step {step_name}: fewer than {count} `{state}` events within {within:?}: {}",
                self.context()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// Wait for the process to exit by itself.
    fn wait_exit(&mut self, step_name: &str) -> std::process::ExitStatus {
        let deadline = Instant::now() + STEP_DEADLINE;
        loop {
            if let Some(exit) = self.process.0.try_wait().expect("poll client") {
                std::thread::sleep(Duration::from_millis(100));
                return exit;
            }
            assert!(
                Instant::now() < deadline,
                "step {step_name}: the client did not exit: {}",
                self.context()
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    /// SIGTERM, then the orderly stop: exit `0` and a `stopped` event.
    fn stop(mut self) {
        let status = Command::new("/bin/kill")
            .arg("-TERM")
            .arg(self.process.0.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success());
        let deadline = Instant::now() + STEP_DEADLINE;
        let exit = loop {
            if let Some(exit) = self.process.0.try_wait().expect("poll client") {
                break exit;
            }
            assert!(Instant::now() < deadline, "client did not stop");
            std::thread::sleep(Duration::from_millis(10));
        };
        std::thread::sleep(Duration::from_millis(100));
        assert_eq!(exit.code(), Some(0), "orderly stop: {}", self.context());
        let stopped = self.states("stopped");
        assert!(
            stopped
                .last()
                .is_some_and(|(_, event)| event["result"]["signal"] == "SIGTERM"),
            "a `stopped` event naming SIGTERM: {}",
            self.context()
        );
    }
}

fn session_id(event: &Value) -> String {
    event["result"]["session_id"]
        .as_str()
        .unwrap_or_else(|| panic!("event without session_id: {event}"))
        .to_owned()
}

/// Stop a relay with SIGTERM and wait for its orderly exit.
fn stop_relay(mut relay: Running) {
    let status = Command::new("/bin/kill")
        .arg("-TERM")
        .arg(relay.0.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success());
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        if let Some(status) = relay.0.try_wait().expect("poll relay") {
            assert_eq!(status.code(), Some(0), "relay orderly stop");
            return;
        }
        assert!(Instant::now() < deadline, "relay did not stop");
        std::thread::sleep(Duration::from_millis(10));
    }
}

/// Wait until the client has backed off at least twice since `since`, every
/// time for a cause other than a credential or configuration refusal.
fn wait_for_backoffs_since(
    client: &mut Client,
    step_name: &str,
    since: Instant,
    count: usize,
) -> Vec<Value> {
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        let recent: Vec<Value> = client
            .states("backoff")
            .into_iter()
            .filter(|(at, _)| *at >= since)
            .map(|(_, event)| event)
            .collect();
        if recent.len() >= count {
            return recent;
        }
        if let Ok(Some(status)) = client.process.0.try_wait() {
            std::thread::sleep(Duration::from_millis(100));
            panic!(
                "step {step_name}: the client exited ({status}) instead of backing off: {}",
                client.context()
            );
        }
        assert!(
            Instant::now() < deadline,
            "step {step_name}: fewer than {count} backoffs: {}",
            client.context()
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_connect_reconnects_after_the_relay_is_killed_and_after_it_is_stopped() {
    let deployment = Deployment::provision("restart").await;
    let relay = deployment.serve("serve 1");
    let mut client = deployment.connect();
    let first = session_id(&client.wait_for("session 1", "ready", 1)[0].1);
    deployment.echo("echo 1", &client).await;

    // 1. The relay dies without a word.
    drop(relay);
    let killed = Instant::now();
    let disconnected = client.wait_for("disconnect after SIGKILL", "lost", 1);
    let lost = &disconnected[0].1["result"];
    assert_eq!(lost["session_id"], first.as_str(), "{lost}");
    assert_eq!(lost["sessions"], 1, "{lost}");
    let down = wait_for_backoffs_since(&mut client, "relay down after SIGKILL", killed, 2);
    let relay = deployment.serve("serve 2");
    let restarted = Instant::now();
    let reconnected = client.wait_for_within(
        "reconnect after SIGKILL",
        "reconnected",
        1,
        STALE_OWNER_DEADLINE,
    );
    let readies = client.wait_for("session 2", "ready", 2);
    let second = session_id(&readies[1].1);
    assert_ne!(second, first, "a new session, not the old one");
    assert_eq!(session_id(&reconnected[0].1), second);
    let kill_reconnect = reconnected[0].0.duration_since(restarted);
    deployment.echo("echo 2", &client).await;

    // 2. The relay is stopped in order, as a service manager would.
    stop_relay(relay);
    let stopped = Instant::now();
    let disconnected = client.wait_for("disconnect after SIGTERM", "lost", 2);
    let lost = &disconnected[1].1["result"];
    assert_eq!(lost["session_id"], second.as_str(), "{lost}");
    assert_eq!(lost["sessions"], 2, "{lost}");
    wait_for_backoffs_since(&mut client, "relay down after SIGTERM", stopped, 2);
    let relay = deployment.serve("serve 3");
    let restarted = Instant::now();
    let reconnected = client.wait_for("reconnect after SIGTERM", "reconnected", 2);
    let readies = client.wait_for("session 3", "ready", 3);
    let third = session_id(&readies[2].1);
    assert!(third != first && third != second);
    let stop_reconnect = reconnected[1].0.duration_since(restarted);
    deployment.echo("echo 3", &client).await;

    let causes: Vec<String> = client
        .states("disconnected")
        .iter()
        .chain(client.states("backoff").iter())
        .map(|(_, event)| event["result"]["code"].as_str().unwrap_or("?").to_owned())
        .collect();
    let backoffs = client.states("backoff").len();
    client.stop();
    drop(relay);
    println!(
        "m6c23-reconnect ok label=restart nonce={} sessions=3 backoffs={backoffs} \
         down_backoffs_after_kill={} reconnect_after_kill_restart_ms={} \
         reconnect_after_orderly_restart_ms={} causes={causes:?}",
        deployment.nonce,
        down.len(),
        kill_reconnect.as_millis(),
        stop_reconnect.as_millis()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_connect_started_before_its_relay_backs_off_until_the_relay_appears() {
    let deployment = Deployment::provision("late-relay").await;
    let mut client = deployment.connect();
    let started = Instant::now();
    let backoffs = wait_for_backoffs_since(&mut client, "relay absent", started, 2);
    for event in &backoffs {
        assert_eq!(event["result"]["code"], "TRANSPORT_ERROR", "{event}");
    }
    assert!(client.states("ready").is_empty());
    let relay = deployment.serve("serve");
    let appeared = Instant::now();
    let reconnected = client.wait_for("connect once the relay appears", "reconnected", 1);
    let ready = client.wait_for("ready", "ready", 1);
    assert_eq!(session_id(&reconnected[0].1), session_id(&ready[0].1));
    let attempts = reconnected[0].1["result"]["attempt"].as_u64().unwrap_or(0);
    let waited = reconnected[0].0.duration_since(appeared);
    deployment.echo("echo", &client).await;
    client.stop();
    drop(relay);
    println!(
        "m6c23-reconnect ok label=late-relay nonce={} backoffs_before_relay={} \
         reconnected_attempt={attempts} ready_after_relay_ms={}",
        deployment.nonce,
        backoffs.len(),
        waited.as_millis()
    );
}

/// Clock skew against a real relay: a device certificate whose `notBefore`
/// is 20 s ahead is refused by `serve`'s TLS verifier with
/// `certificate_expired` -- the same alert as a genuinely expired one. The
/// client, reading its own certificate, finds it not yet valid, retries with
/// a message naming the clock, and connects once it is valid.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_a_device_certificate_not_yet_valid_is_retried_until_it_is() {
    let deployment = Deployment::provision("not-yet-valid").await;
    let valid_from = unix_now() + 20;
    deployment.reissue_device_certificate(valid_from, valid_from + 86_400);
    let relay = deployment.serve("serve");
    let mut client = deployment.connect();
    let refused = client.wait_for("refused while not yet valid", "disconnected", 1);
    let first = &refused[0].1["result"];
    assert_eq!(first["code"], "TRANSPORT_ERROR", "{first}");
    let message = first["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("as expired or not yet valid on the relay's clock")
            && message.contains("not valid until unix time"),
        "the relay's alert, and the client's own reading of its certificate: {first}"
    );
    let ready = client.wait_for_within("connect once valid", "ready", 1, Duration::from_secs(60));
    let ready_at = unix_now();
    assert!(
        ready_at >= valid_from,
        "a session before the certificate was valid: {}",
        client.context()
    );
    let backoffs = client.states("backoff").len();
    deployment.echo("echo", &client).await;
    client.stop();
    drop(relay);
    println!(
        "m6c23-reconnect ok label=not-yet-valid nonce={} session={} backoffs_before_valid={backoffs} \
         ready_after_not_before_s={}",
        deployment.nonce,
        session_id(&ready[0].1),
        ready_at - valid_from
    );
}

/// A genuinely expired device certificate against a real relay: the same
/// alert, but past `notAfter` on the client's clock too, so terminal --
/// exit `3`, `CREDENTIAL_ERROR` naming the expiry, no backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_an_expired_device_certificate_exits_three_without_retrying() {
    let deployment = Deployment::provision("expired").await;
    let now = unix_now();
    deployment.reissue_device_certificate(now - 172_800, now - 3_600);
    let (relay, relay_log) = deployment.serve_logged("serve");
    let mut client = deployment.connect();
    let exit = client.wait_exit("expired certificate");
    let events: Vec<Value> = client
        .events()
        .into_iter()
        .map(|(_, event)| event)
        .collect();
    let last = events.last().cloned().unwrap_or(Value::Null);
    assert_eq!(exit.code(), Some(3), "{events:?}");
    assert_eq!(last["error"]["code"], "CREDENTIAL_ERROR", "{events:?}");
    let message = last["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("this device's certificate expired at unix time"),
        "{events:?}"
    );
    assert!(client.states("backoff").is_empty(), "{events:?}");
    // M6-C52: the relay's side of the same refusal, at its default level.
    let refusal = wait_for_log_line(&relay_log, "TLS handshake refused");
    assert!(
        refusal.contains("\"refusal\":\"client_certificate_expired\""),
        "{refusal}"
    );
    drop(relay);
    println!(
        "m6c23-reconnect ok label=expired nonce={} exit=3 code=CREDENTIAL_ERROR backoffs=0 \
         relay_tls_refusal_logged=true",
        deployment.nonce
    );
}

/// The integration with M6-C32: the relay closes a `device_id` mismatch with
/// `1008 DEVICE_IDENTITY_REJECTED`, the client reports `CREDENTIAL_ERROR`,
/// and the reconnect loop -- on, with its default policy apart from short
/// delays -- exits `3` after that one attempt instead of backing off.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_an_identity_mismatch_exits_three_without_retrying() {
    let deployment = Deployment::provision("identity").await;
    let mismatched = deployment
        .client_config
        .with_file_name("mismatched-device-id.toml");
    fs::write(
        &mismatched,
        set_key(
            &fs::read_to_string(&deployment.client_config).expect("read profile"),
            "device_id",
            &format!("\"{}\"", Uuid::new_v4()),
        ),
    )
    .expect("mismatched profile");
    let (relay, relay_log) = deployment.serve_logged("serve");
    let mut client = deployment.connect_with(&mismatched);
    let exit = client.wait_exit("identity mismatch");
    let events: Vec<Value> = client
        .events()
        .into_iter()
        .map(|(_, event)| event)
        .collect();
    let last = events.last().cloned().unwrap_or(Value::Null);
    assert_eq!(exit.code(), Some(3), "{events:?}");
    assert_eq!(last["error"]["code"], "CREDENTIAL_ERROR", "{events:?}");
    assert_eq!(last["error"]["retryable"], false, "{events:?}");
    assert!(
        last["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("refused this device's identity"),
        "the message only the 1008 DEVICE_IDENTITY_REJECTED close produces: {events:?}"
    );
    assert!(client.states("backoff").is_empty(), "{events:?}");
    assert!(client.states("disconnected").is_empty(), "{events:?}");
    // M6-C52: the relay says why, in one bounded line naming the stage and
    // the certificate's device, and nothing the device sent.
    let refusal = wait_for_log_line(&relay_log, "device session refused");
    assert!(refusal.contains("\"stage\":\"control_hello\""), "{refusal}");
    assert!(refusal.contains("identity_rejected"), "{refusal}");
    let mismatched_id = fs::read_to_string(&mismatched)
        .expect("read mismatched profile")
        .lines()
        .find_map(|line| line.strip_prefix("device_id = "))
        .map(|value| value.trim_matches('"').to_owned())
        .expect("mismatched device_id");
    assert!(
        !refusal.contains(&mismatched_id),
        "the HELLO's connector_id is not logged: {refusal}"
    );
    drop(relay);
    println!(
        "m6c23-reconnect ok label=identity nonce={} exit=3 code=CREDENTIAL_ERROR backoffs=0 \
         relay_refusal_logged=true",
        deployment.nonce
    );
}

/// Wait up to the step deadline for a relay log line containing `needle`.
fn wait_for_log_line(lines: &Arc<Mutex<Vec<String>>>, needle: &str) -> String {
    let deadline = Instant::now() + STEP_DEADLINE;
    loop {
        if let Some(line) = lines
            .lock()
            .expect("relay log")
            .iter()
            .find(|line| line.contains(needle))
        {
            return line.clone();
        }
        assert!(
            Instant::now() < deadline,
            "no relay log line containing {needle:?} within {STEP_DEADLINE:?}: {:?}",
            lines.lock().expect("relay log")
        );
        std::thread::sleep(Duration::from_millis(50));
    }
}

/// M6-C38, the relay half, against the real `serve`: a HELLO naming another
/// protocol major is closed with the typed `1002 PROTOCOL_UNSUPPORTED`, not
/// dropped.  The device is a raw WebSocket holding the provisioned device
/// certificate and key, because the shipped client cannot be made to send
/// another major; the client half of the row is proved with the real client
/// binary against a stand-in relay (`reconnect_cli.rs`).
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c38_a_hello_on_another_protocol_major_is_closed_typed() {
    use futures_util::{SinkExt as _, StreamExt as _};
    use tokio_tungstenite::{
        Connector, connect_async_tls_with_config,
        tungstenite::{Message as WsMessage, client::IntoClientRequest, http::HeaderValue},
    };

    let deployment = Deployment::provision("protocol-major").await;
    let (relay, relay_log) = deployment.serve_logged("serve");
    let credentials = deployment
        .client_config
        .parent()
        .expect("profile directory")
        .join("credentials");
    let tls = tunnel_transport::load_client_config_from_pem_with_alpn(
        &fs::read(credentials.join("device-cert-chain.pem")).expect("device certificate"),
        &fs::read(credentials.join("device-key.pem")).expect("device key"),
        &fs::read(credentials.join("relay-ca.pem")).expect("relay CA"),
        &[b"http/1.1"],
    )
    .expect("device TLS configuration");
    let mut request = format!(
        "wss://127.0.0.1:{}/v1/tunnel/control",
        deployment.device_listener.port()
    )
    .into_client_request()
    .expect("control request");
    request.headers_mut().insert(
        "sec-websocket-protocol",
        HeaderValue::from_static("agent-tunnel.control.v1"),
    );
    let (mut socket, _) = tokio::time::timeout(
        STEP_DEADLINE,
        connect_async_tls_with_config(request, None, false, Some(Connector::Rustls(tls))),
    )
    .await
    .expect("control upgrade in time")
    .expect("control upgrade");
    let device = fs::read_to_string(&deployment.client_config)
        .expect("profile")
        .lines()
        .find_map(|line| line.strip_prefix("device_id = "))
        .map(|value| value.trim_matches('"').to_owned())
        .expect("device_id");
    let mut hello = tunnel_protocol::Hello::new(Uuid::new_v4().to_string(), device, 2, 0);
    hello.features.push("echo".to_owned());
    let text = tunnel_protocol::encode_control(&tunnel_protocol::ControlMessage::Hello(hello))
        .expect("encode HELLO");
    socket
        .send(WsMessage::Text(
            String::from_utf8(text).expect("UTF-8 HELLO").into(),
        ))
        .await
        .expect("send HELLO");
    let close = loop {
        match tokio::time::timeout(STEP_DEADLINE, socket.next())
            .await
            .expect("the relay answers the HELLO in time")
        {
            Some(Ok(WsMessage::Close(frame))) => break frame,
            Some(Ok(WsMessage::Ping(_) | WsMessage::Pong(_))) => {}
            other => panic!("expected a close frame, got {other:?}"),
        }
    };
    let frame = close.expect("a close frame with a code and a reason");
    assert_eq!(
        u16::from(frame.code),
        tunnel_protocol::CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_CODE
    );
    assert_eq!(
        frame.reason.as_str(),
        tunnel_protocol::CONTROL_PROTOCOL_UNSUPPORTED_CLOSE_REASON
    );
    let refusal = wait_for_log_line(&relay_log, "device session refused");
    assert!(refusal.contains("protocol_major_unsupported"), "{refusal}");
    assert!(refusal.contains("\"stage\":\"control_hello\""), "{refusal}");
    drop(relay);
    println!(
        "m6c38-protocol ok nonce={} close_code={} close_reason={} relay_refusal_logged=true",
        deployment.nonce,
        u16::from(frame.code),
        frame.reason
    );
}

/// Wait for a terminal exit `3` `CREDENTIAL_ERROR` whose message contains
/// `reason`, after one attempt and no backoff.
fn expect_terminal_credential(client: &mut Client, step_name: &str, reason: &str) {
    let exit = client.wait_exit(step_name);
    let events: Vec<Value> = client
        .events()
        .into_iter()
        .map(|(_, event)| event)
        .collect();
    let last = events.last().cloned().unwrap_or(Value::Null);
    assert_eq!(exit.code(), Some(3), "step {step_name}: {events:?}");
    assert_eq!(
        last["error"]["code"], "CREDENTIAL_ERROR",
        "step {step_name}: {events:?}"
    );
    assert_eq!(
        last["error"]["retryable"], false,
        "step {step_name}: {events:?}"
    );
    assert!(
        last["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains(reason),
        "step {step_name}: expected {reason:?}: {events:?}"
    );
    assert!(
        client.states("backoff").is_empty(),
        "step {step_name}: {events:?}"
    );
    println!("m6c23-issuer {step_name} exit=3 code=CREDENTIAL_ERROR backoffs=0");
}

/// M6-C54's two issuer cases, re-measured against a real `serve` with
/// reconnect on: a device certificate from a rogue CA (the relay's TLS
/// verifier refuses it with an `unknown_ca` alert) and a profile whose
/// `server_ca` did not sign the relay's certificate (this client refuses
/// the relay: unknown issuer). Both are terminal: exit `3`, no backoff.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c23_a_rogue_device_ca_and_a_wrong_server_ca_exit_three_without_retrying() {
    let deployment = Deployment::provision("issuer").await;
    let credentials = deployment
        .reissue
        .installed
        .parent()
        .expect("credentials dir")
        .to_path_buf();
    let profile_text = fs::read_to_string(&deployment.client_config).expect("read profile");

    // Wrong server CA: trust the device CA, which did not sign the relay.
    let wrong_ca = credentials.join("wrong-server-ca.pem");
    fs::copy(&deployment.reissue.ca, &wrong_ca).expect("wrong server CA");
    let wrong_ca_profile = deployment
        .client_config
        .with_file_name("wrong-server-ca.toml");
    fs::write(
        &wrong_ca_profile,
        set_key(
            &profile_text,
            "server_ca",
            "\"credentials/wrong-server-ca.pem\"",
        ),
    )
    .expect("wrong server CA profile");

    // Rogue device CA: the same CSR signed by a CA the relay does not trust.
    let rogue_key = credentials.join("rogue-ca-key.pem");
    let rogue_ca = credentials.join("rogue-ca.pem");
    step(
        "rogue CA (openssl req -x509)",
        Command::new("openssl")
            .args([
                "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
            ])
            .args(["-subj", "/CN=M6-C23 synthetic rogue CA", "-keyout"])
            .arg(&rogue_key)
            .arg("-out")
            .arg(&rogue_ca)
            .stderr(Stdio::null()),
    );
    let rogue_cert = credentials.join("rogue-device-cert.pem");
    step(
        "rogue device certificate (openssl x509 -req)",
        Command::new("openssl")
            .args(["x509", "-req", "-in"])
            .arg(&deployment.reissue.csr)
            .arg("-CA")
            .arg(&rogue_ca)
            .arg("-CAkey")
            .arg(&rogue_key)
            .args(["-CAcreateserial", "-days", "1", "-extfile"])
            .arg(&deployment.reissue.extensions)
            .arg("-out")
            .arg(&rogue_cert),
    );
    let rogue_profile = deployment.client_config.with_file_name("rogue-ca.toml");
    fs::write(
        &rogue_profile,
        set_key(
            &profile_text,
            "client_certificate",
            "\"credentials/rogue-device-cert.pem\"",
        ),
    )
    .expect("rogue CA profile");

    let relay = deployment.serve("serve");
    let mut client = deployment.connect_with(&wrong_ca_profile);
    expect_terminal_credential(
        &mut client,
        "wrong server CA",
        "the relay's certificate was refused: unknown issuer",
    );
    let mut client = deployment.connect_with(&rogue_profile);
    expect_terminal_credential(
        &mut client,
        "rogue device CA",
        "the relay refused this device's certificate",
    );
    drop(relay);
    println!(
        "m6c23-reconnect ok label=issuer nonce={} wrong_server_ca=exit3 rogue_device_ca=exit3",
        deployment.nonce
    );
}

/// A TCP proxy in front of the relay's device listener that can cut the
/// device's side of every connection it carries while holding the relay's
/// side open and silent -- what the relay sees when a device's network path
/// vanishes without a FIN or RST reaching it.  Connections accepted after a
/// cut are forwarded normally.
struct CutPathProxy {
    address: SocketAddr,
    generation: tokio::sync::watch::Sender<u64>,
    /// The relay-side halves of cut connections, never read or written again
    /// until the test ends.
    held: Arc<Mutex<Vec<TcpStream>>>,
}

impl CutPathProxy {
    async fn start(upstream: SocketAddr) -> Self {
        let listener = TokioTcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind cut-path proxy");
        let address = listener.local_addr().expect("proxy address");
        let (generation, _) = tokio::sync::watch::channel(0_u64);
        let held = Arc::new(Mutex::new(Vec::new()));
        let accept_generation = generation.clone();
        let accept_held = Arc::clone(&held);
        tokio::spawn(async move {
            loop {
                let Ok((mut device, _)) = listener.accept().await else {
                    return;
                };
                let mut cut = accept_generation.subscribe();
                let born = *cut.borrow_and_update();
                let held = Arc::clone(&accept_held);
                tokio::spawn(async move {
                    let Ok(mut relay) = TcpStream::connect(upstream).await else {
                        return;
                    };
                    let was_cut = tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut device, &mut relay) => false,
                        _ = cut.wait_for(|now| *now > born) => true,
                    };
                    if was_cut {
                        drop(device);
                        held.lock().expect("held").push(relay);
                    }
                });
            }
        });
        Self {
            address,
            generation,
            held,
        }
    }

    /// Cut every connection open now; returns how many relay-side halves are
    /// held after the cut settles.
    async fn cut(&self) -> usize {
        self.generation.send_modify(|now| *now += 1);
        tokio::time::sleep(Duration::from_millis(200)).await;
        self.held.lock().expect("held").len()
    }
}

impl Deployment {
    /// Point the device profile at `address` instead of the relay itself.
    fn route_client_through(&self, address: SocketAddr) {
        let profile = fs::read_to_string(&self.client_config).expect("read profile");
        fs::write(
            &self.client_config,
            set_key(
                &profile,
                "relay_url",
                &format!("\"wss://127.0.0.1:{}/v1/tunnel/control\"", address.port()),
            ),
        )
        .expect("rewrite profile");
    }
}

/// The bound, stated in docs/operator.md, within which a relay ends the
/// session of a device whose path vanished: its idle timeout, plus the
/// bounded (5 s) disconnect hand-off to the actor, plus the client's largest
/// backoff step in this run (1 s) and scheduling slack.  It must stay inside
/// the client's 60 s `OWNER_BUSY` window, or the test would only measure the
/// client giving up.
const CUT_PATH_RECONNECT_BOUND: Duration =
    Duration::from_secs(DEVICE_CONTROL_IDLE_TIMEOUT.as_secs() + 5 + 1 + 4);
const _: () = assert!(CUT_PATH_RECONNECT_BOUND.as_secs() < 60);

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires TEST_REDIS_URL and TUNNEL_CLIENT_BIN; run by scripts/m6-reconnect-verify.sh"]
async fn m6c68_a_relay_evicts_a_device_whose_path_vanished_and_admits_its_reconnect() {
    let deployment = Deployment::provision("cut-path").await;
    let proxy = CutPathProxy::start(deployment.device_listener).await;
    deployment.route_client_through(proxy.address);
    let relay = deployment.serve("serve");
    let mut client = deployment.connect();
    let first = session_id(&client.wait_for("session 1", "ready", 1)[0].1);
    deployment.echo("echo 1", &client).await;

    // 1. A healthy device that sends nothing for longer than the idle
    //    timeout is not evicted: the relay's Pings draw Pongs, and a Pong is
    //    an inbound frame.  Without the Pong arm the relay would drop the
    //    session at its first Pong; without the deadline reset, at the idle
    //    timeout.
    let quiet = DEVICE_CONTROL_IDLE_TIMEOUT + DEVICE_CONTROL_PING_INTERVAL;
    tokio::time::sleep(quiet).await;
    assert!(
        client.states("disconnected").is_empty() && client.states("backoff").is_empty(),
        "a healthy idle session must survive {quiet:?}: {}",
        client.context()
    );
    deployment.echo("echo after idle", &client).await;

    // 2. The device's path vanishes; the relay's half stays open and silent.
    let held = proxy.cut().await;
    let cut = Instant::now();
    assert!(held >= 2, "control and data relay halves held, got {held}");
    let lost = client.wait_for("disconnect after the cut", "lost", 1);
    assert_eq!(lost[0].1["result"]["session_id"], first.as_str());
    let reconnected = client.wait_for_within(
        "reconnect after the cut",
        "reconnected",
        1,
        CUT_PATH_RECONNECT_BOUND,
    );
    let readies = client.wait_for("session 2", "ready", 2);
    let second = session_id(&readies[1].1);
    assert_ne!(second, first, "a new session, not the old one");
    assert_eq!(session_id(&reconnected[0].1), second);
    let reconnect_after_cut = reconnected[0].0.duration_since(cut);
    let owner_busy = client
        .states("backoff")
        .iter()
        .filter(|(_, event)| event["result"]["code"] == "OWNER_BUSY")
        .count();
    // The test reproduces the defect rather than passing around it: the
    // relay really did hold the dead session for a while, and refused the
    // device while it did.
    assert!(
        owner_busy >= 1,
        "the relay must have refused OWNER_BUSY while it still held the dead session: {}",
        client.context()
    );
    deployment.echo("echo after reconnect", &client).await;
    client.stop();
    drop(relay);
    println!(
        "m6c68-liveness ok label=cut-path nonce={} idle_survived_ms={} held_relay_halves={held} \
         owner_busy_refusals={owner_busy} reconnect_after_cut_ms={} bound_ms={}",
        deployment.nonce,
        quiet.as_millis(),
        reconnect_after_cut.as_millis(),
        CUT_PATH_RECONNECT_BOUND.as_millis()
    );
}
