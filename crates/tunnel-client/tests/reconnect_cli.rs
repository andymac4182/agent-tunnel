//! Process-level coverage for `tunnel-client connect`'s reconnect loop
//! (task row M6-C23), against local stand-ins for the relay.
//!
//! What a real relay is needed for -- a session that becomes ready, is lost
//! and comes back -- is `crates/tunnel-relay/tests/m6_reconnect_process.rs`.
//! This file holds the parts that are decided before any session exists, so
//! they run in the ordinary workspace suite:
//!
//! * a **retryable** failure backs off with growing, jittered, bounded delays
//!   and gives up at `reconnect.max_attempts` with the last cause;
//! * both sides of the TLS line the loop depends on: a relay that **resets**
//!   or **closes** the connection mid-handshake is retried, while a relay
//!   certificate the profile's `server_ca` does not trust, and a relay that
//!   **refuses the device certificate** with a TLS alert, exit `3`
//!   `CREDENTIAL_ERROR` after one connection and no backoff;
//! * a relay that completes the WebSocket upgrade and then closes the
//!   control socket with the typed `PROTOCOL_UNSUPPORTED` refusal exits `1`
//!   `PROTOCOL_ERROR` after one connection and no backoff (M6-C38), while an
//!   untyped close at the same point is still retried;
//! * a stop request during the backoff wait exits `130` promptly;
//! * `--no-reconnect` and `[reconnect] enabled = false` restore the old
//!   exit-at-once behaviour.
//!
//! Every assertion reads the real process: its exit status, its `--json`
//! events, and what the stand-in relay counted.

#![cfg(unix)]

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::Value;
use std::{
    fs,
    io::{BufRead, BufReader, Read},
    net::{Ipv4Addr, SocketAddrV4, TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

/// A stop request during backoff must end the process within this. The
/// backoff delay in those tests is at least 2.5 s, so an implementation that
/// sleeps out the delay before looking at the signal is red here.
const PROMPT_EXIT: Duration = Duration::from_secs(1);

/// Upper bound on any one run, so a regression cannot hang the suite.
const RUN_BOUND: Duration = Duration::from_secs(30);

/// A certificate authority with a relay leaf for `127.0.0.1` and a device
/// identity, all synthetic.
struct Pki {
    ca_pem: String,
    server_chain_pem: String,
    server_key_pem: String,
    device_pem: String,
    device_key_pem: String,
}

/// Unix seconds now, and offsets from it for certificate validity windows.
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after 1970")
        .as_secs()
}

impl Pki {
    fn new(name: &str) -> Self {
        Self::with_windows(name, None, None)
    }

    /// `server` and `device` override a leaf's validity window, as unix
    /// seconds `(not_before, not_after)`.
    fn with_windows(name: &str, server: Option<(u64, u64)>, device: Option<(u64, u64)>) -> Self {
        let ca_key = KeyPair::generate().expect("reconnect fixture CA key");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, format!("reconnect fixture CA {name}"));
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("reconnect fixture CA");

        let server_key = KeyPair::generate().expect("reconnect fixture relay key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("relay leaf params");
        server_params.subject_alt_names.push(SanType::IpAddress(
            "127.0.0.1".parse().expect("loopback SAN"),
        ));
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        if let Some((not_before, not_after)) = server {
            server_params.not_before =
                rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_before);
            server_params.not_after =
                rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_after);
        }
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("reconnect fixture relay leaf");

        let device_key = KeyPair::generate().expect("reconnect fixture device key");
        let mut device_params = CertificateParams::default();
        device_params
            .distinguished_name
            .push(DnType::CommonName, "reconnect-fixture-device");
        device_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        if let Some((not_before, not_after)) = device {
            device_params.not_before =
                rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_before);
            device_params.not_after =
                rcgen::date_time_ymd(1970, 1, 1) + Duration::from_secs(not_after);
        }
        let device = device_params
            .signed_by(&device_key, &ca, &ca_key)
            .expect("reconnect fixture device leaf");

        Self {
            ca_pem: ca.pem(),
            server_chain_pem: format!("{}{}", server.pem(), ca.pem()),
            server_key_pem: server_key.serialize_pem(),
            device_pem: device.pem(),
            device_key_pem: device_key.serialize_pem(),
        }
    }
}

fn provider() -> Arc<rustls::crypto::CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn server_identity(
    pki: &Pki,
) -> (
    Vec<rustls::pki_types::CertificateDer<'static>>,
    rustls::pki_types::PrivateKeyDer<'static>,
) {
    let certificates = rustls_pemfile::certs(&mut pki.server_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse relay chain");
    let key = rustls_pemfile::private_key(&mut pki.server_key_pem.as_bytes())
        .expect("parse relay key")
        .expect("relay key present");
    (certificates, key)
}

/// A relay TLS configuration that does not ask for a client certificate.
fn server_without_client_auth(pki: &Pki) -> Arc<rustls::ServerConfig> {
    let (certificates, key) = server_identity(pki);
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("relay protocol versions")
            .with_no_client_auth()
            .with_single_cert(certificates, key)
            .expect("relay server config"),
    )
}

/// A relay TLS configuration that requires a device certificate issued by
/// `device_issuer` -- which the device under test does not have.
fn server_requiring_devices_of(pki: &Pki, device_issuer: &Pki) -> Arc<rustls::ServerConfig> {
    let (certificates, key) = server_identity(pki);
    let mut roots = rustls::RootCertStore::empty();
    for certificate in rustls_pemfile::certs(&mut device_issuer.ca_pem.as_bytes()) {
        roots
            .add(certificate.expect("parse device issuer"))
            .expect("add device issuer");
    }
    let verifier =
        rustls::server::WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider())
            .build()
            .expect("client verifier");
    Arc::new(
        rustls::ServerConfig::builder_with_provider(provider())
            .with_safe_default_protocol_versions()
            .expect("relay protocol versions")
            .with_client_cert_verifier(verifier)
            .with_single_cert(certificates, key)
            .expect("relay server config"),
    )
}

/// What the stand-in relay does with each accepted connection.
#[derive(Clone)]
enum Mode {
    /// Read the ClientHello, then reset the connection (`SO_LINGER` 0).
    ResetAfterClientHello,
    /// Read the ClientHello, then close the connection in order (FIN).
    CloseAfterClientHello,
    /// Run the server side of the TLS handshake with this configuration,
    /// then hold the connection briefly and close it.
    Tls(Arc<rustls::ServerConfig>),
    /// Complete TLS and the control WebSocket upgrade, read the device's
    /// first message (its HELLO), then send a close frame with this code and
    /// reason -- what a relay refusing the HELLO does (M6-C38).
    ControlClose(Arc<rustls::ServerConfig>, u16, &'static str),
}

/// A local stand-in for the relay's device listener that counts the
/// connections it accepts.
struct FakeRelay {
    port: u16,
    stop: Arc<AtomicBool>,
    accepted: Arc<AtomicUsize>,
    tls_errors: Arc<Mutex<Vec<String>>>,
    tls_completed: Arc<AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}

impl FakeRelay {
    fn start(mode: Mode) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake relay");
        listener
            .set_nonblocking(true)
            .expect("make fake relay pollable");
        let port = listener.local_addr().expect("fake relay address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(AtomicUsize::new(0));
        let tls_errors = Arc::new(Mutex::new(Vec::new()));
        let tls_completed = Arc::new(AtomicUsize::new(0));
        let thread = {
            let stop = Arc::clone(&stop);
            let accepted = Arc::clone(&accepted);
            let tls_errors = Arc::clone(&tls_errors);
            let tls_completed = Arc::clone(&tls_completed);
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            accepted.fetch_add(1, Ordering::AcqRel);
                            stream
                                .set_nonblocking(false)
                                .expect("fake relay blocking stream");
                            match serve(stream, &mode) {
                                Some(error) => {
                                    tls_errors.lock().expect("tls errors").push(error);
                                }
                                None if matches!(mode, Mode::Tls(_) | Mode::ControlClose(..)) => {
                                    tls_completed.fetch_add(1, Ordering::AcqRel);
                                }
                                None => {}
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => return,
                    }
                }
            })
        };
        Self {
            port,
            stop,
            accepted,
            tls_errors,
            tls_completed,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("wss://127.0.0.1:{}/v1/tunnel/control", self.port)
    }

    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Acquire)
    }
}

impl Drop for FakeRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Handle one connection; returns the server-side TLS error, if any.
fn serve(mut stream: TcpStream, mode: &Mode) -> Option<String> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded fake relay read");
    match mode {
        Mode::ResetAfterClientHello | Mode::CloseAfterClientHello => {
            // A TLS record header: the ClientHello has arrived.
            let mut header = [0_u8; 5];
            if stream.read_exact(&mut header).is_err() {
                return None;
            }
            if matches!(mode, Mode::ResetAfterClientHello) {
                rustix::net::sockopt::set_socket_linger(&stream, Some(Duration::ZERO))
                    .expect("SO_LINGER 0 so the close is a reset");
            }
            drop(stream);
            None
        }
        Mode::Tls(config) => {
            let mut connection =
                rustls::ServerConnection::new(Arc::clone(config)).expect("relay TLS session");
            while connection.is_handshaking() {
                if let Err(error) = connection.complete_io(&mut stream) {
                    // `complete_io` has already written the alert.
                    return Some(error.to_string());
                }
            }
            // Read the client's first record, so a client-certificate
            // refusal (sent after a TLS 1.3 client's Finished) surfaces here
            // rather than being counted as a completed handshake.
            let mut tls = rustls::Stream::new(&mut connection, &mut stream);
            let mut byte = [0_u8; 1];
            if let Err(error) = tls.read_exact(&mut byte) {
                return Some(error.to_string());
            }
            thread::sleep(Duration::from_millis(200));
            None
        }
        Mode::ControlClose(config, code, reason) => {
            let mut connection =
                rustls::ServerConnection::new(Arc::clone(config)).expect("relay TLS session");
            while connection.is_handshaking() {
                if let Err(error) = connection.complete_io(&mut stream) {
                    return Some(error.to_string());
                }
            }
            let mut tls = rustls::Stream::new(&mut connection, &mut stream);
            if let Err(error) = websocket_upgrade(&mut tls) {
                return Some(error);
            }
            // The HELLO: one masked client frame, read and discarded.
            if let Err(error) = read_client_frame(&mut tls) {
                return Some(error);
            }
            let mut close = vec![0x88, u8::try_from(2 + reason.len()).expect("short reason")];
            close.extend_from_slice(&code.to_be_bytes());
            close.extend_from_slice(reason.as_bytes());
            if let Err(error) = std::io::Write::write_all(&mut tls, &close) {
                return Some(error.to_string());
            }
            let _ = std::io::Write::flush(&mut tls);
            thread::sleep(Duration::from_millis(200));
            None
        }
    }
}

/// Answer one WebSocket upgrade request (RFC 6455 section 4.2.2), echoing
/// the subprotocol the client offered.
fn websocket_upgrade(tls: &mut (impl Read + std::io::Write)) -> Result<(), String> {
    let mut request = Vec::new();
    let mut byte = [0_u8; 1];
    while !request.ends_with(b"\r\n\r\n") {
        tls.read_exact(&mut byte)
            .map_err(|error| error.to_string())?;
        request.push(byte[0]);
        if request.len() > 16 * 1024 {
            return Err("upgrade request too large".to_owned());
        }
    }
    let request = String::from_utf8(request).map_err(|error| error.to_string())?;
    let header = |name: &str| {
        request.lines().find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.trim()
                .eq_ignore_ascii_case(name)
                .then(|| value.trim().to_owned())
        })
    };
    let key = header("sec-websocket-key").ok_or("no Sec-WebSocket-Key")?;
    let protocol = header("sec-websocket-protocol").ok_or("no Sec-WebSocket-Protocol")?;
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    let response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: {protocol}\r\n\r\n",
        base64(digest.as_ref())
    );
    std::io::Write::write_all(tls, response.as_bytes()).map_err(|error| error.to_string())?;
    std::io::Write::flush(tls).map_err(|error| error.to_string())
}

/// Read one masked client frame and discard it.
fn read_client_frame(tls: &mut (impl Read + std::io::Write)) -> Result<(), String> {
    let mut head = [0_u8; 2];
    tls.read_exact(&mut head)
        .map_err(|error| error.to_string())?;
    let length = match head[1] & 0x7f {
        126 => {
            let mut extended = [0_u8; 2];
            tls.read_exact(&mut extended)
                .map_err(|error| error.to_string())?;
            u64::from(u16::from_be_bytes(extended))
        }
        127 => {
            let mut extended = [0_u8; 8];
            tls.read_exact(&mut extended)
                .map_err(|error| error.to_string())?;
            u64::from_be_bytes(extended)
        }
        short => u64::from(short),
    };
    let mask = if head[1] & 0x80 != 0 { 4 } else { 0 };
    let mut rest = vec![0_u8; usize::try_from(length).map_err(|error| error.to_string())? + mask];
    tls.read_exact(&mut rest).map_err(|error| error.to_string())
}

fn base64(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in bytes.chunks(3) {
        let block = [
            chunk[0],
            chunk.get(1).copied().unwrap_or(0),
            chunk.get(2).copied().unwrap_or(0),
        ];
        let value = (u32::from(block[0]) << 16) | (u32::from(block[1]) << 8) | u32::from(block[2]);
        for index in 0..4 {
            if index <= chunk.len() {
                out.push(char::from(
                    ALPHABET[((value >> (18 - 6 * index)) & 0x3f) as usize],
                ));
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// The refused target: loopback port 1 (task row M6-C177).
///
/// The port used to be picked by binding `127.0.0.1:0` and then **releasing**
/// it, and the freed number was dialled as the refused target.  Tests in this
/// binary run in parallel and every `FakeRelay` binds `127.0.0.1:0`, so the
/// kernel could hand the freed port to another test's TLS stand-in, whose CA
/// the device does not trust: the refused dial then failed as
/// `CREDENTIAL_ERROR` "unknown issuer" instead of `TRANSPORT_ERROR`, as
/// hosted Linux run 36237768855 did once.
///
/// Port 1 cannot be handed out that way: it is below every default
/// ephemeral range, so no bind of port 0 in this binary can return it, and
/// nothing in this binary binds it explicitly.  That is the whole guarantee.
/// It is not a privilege guarantee: port 1 is privileged only on Linux for a
/// non-root process outside a container; macOS lets an ordinary user bind the
/// wildcard address on it, and root or a container can bind it anywhere, so a
/// process outside this binary could still answer on it.  A dial to it is
/// otherwise refused at once (`exit_codes_cli.rs` relies on the same).  This
/// file is `#![cfg(unix)]`.  Holding a
/// freshly picked port bound but never listening was tried first and
/// rejected: Linux resets a SYN to such a port, but macOS drops it, so the
/// dial timed out instead of being refused (measured locally).
const REFUSED_PORT: u16 = 1;

fn refused_url() -> String {
    format!("wss://127.0.0.1:{REFUSED_PORT}/v1/tunnel/control")
}

struct Profile {
    _root: TempDir,
    config: PathBuf,
}

/// A device profile whose device identity comes from `device`, which trusts
/// `trusted`'s CA for the relay, and whose `[reconnect]` table is `reconnect`.
fn profile(relay_url: &str, device: &Pki, trusted: &Pki, reconnect: &str) -> Profile {
    let root = tempdir().expect("create reconnect fixture directory");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("make reconnect fixture private");
    let write = |name: &str, contents: &str, mode: u32| {
        let path = root.path().join(name);
        fs::write(&path, contents).expect("write reconnect fixture file");
        fs::set_permissions(&path, fs::Permissions::from_mode(mode))
            .expect("set reconnect fixture mode");
        path
    };
    let certificate = write("device-cert.pem", &device.device_pem, 0o644);
    let key = write("device-key.pem", &device.device_key_pem, 0o600);
    let ca = write("relay-ca.pem", &trusted.ca_pem, 0o644);
    let config = write(
        "client.toml",
        &format!(
            "device_id = \"reconnect-fixture\"\nrelay_url = \"{relay_url}\"\nclient_cert = {}\nprivate_key = {}\nserver_ca = {}\n\n[reconnect]\n{reconnect}\n",
            toml_string(&certificate),
            toml_string(&key),
            toml_string(&ca),
        ),
        0o600,
    );
    Profile {
        _root: root,
        config,
    }
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

/// A running `tunnel-client connect --json` whose stdout events are
/// collected as they arrive.
struct Run {
    child: Child,
    started: Instant,
    events: Arc<Mutex<Vec<Value>>>,
    stderr: Arc<Mutex<String>>,
}

impl Run {
    fn start(profile: &Profile, extra: &[&str]) -> Self {
        let mut child = Command::new(env!("CARGO_BIN_EXE_tunnel-client"))
            .arg("connect")
            .arg("--config")
            .arg(&profile.config)
            .arg("--json")
            .args(extra)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn tunnel-client connect");
        let events = Arc::new(Mutex::new(Vec::new()));
        let stdout = child.stdout.take().expect("stdout pipe");
        {
            let events = Arc::clone(&events);
            thread::spawn(move || {
                for line in BufReader::new(stdout).lines().map_while(Result::ok) {
                    let value = serde_json::from_str(&line)
                        .unwrap_or_else(|_| Value::String(format!("non-JSON stdout: {line}")));
                    events.lock().expect("events").push(value);
                }
            });
        }
        let stderr = Arc::new(Mutex::new(String::new()));
        let pipe = child.stderr.take().expect("stderr pipe");
        {
            let stderr = Arc::clone(&stderr);
            thread::spawn(move || {
                let mut text = String::new();
                let _ = BufReader::new(pipe).read_to_string(&mut text);
                stderr.lock().expect("stderr").push_str(&text);
            });
        }
        Self {
            child,
            started: Instant::now(),
            events,
            stderr,
        }
    }

    fn events(&self) -> Vec<Value> {
        self.events.lock().expect("events").clone()
    }

    fn states(&self, state: &str) -> Vec<Value> {
        self.events()
            .into_iter()
            .filter(|event| event["result"]["state"] == state)
            .collect()
    }

    fn context(&self) -> String {
        format!(
            "events={:?} stderr={:?}",
            self.events(),
            self.stderr.lock().expect("stderr")
        )
    }

    /// Wait until an event with `state` has been printed; the process must
    /// still be running.
    fn wait_for_state(&mut self, state: &str) -> Value {
        loop {
            if let Some(event) = self.states(state).into_iter().next() {
                return event;
            }
            if let Some(status) = self.child.try_wait().expect("poll tunnel-client") {
                thread::sleep(Duration::from_millis(50));
                panic!(
                    "tunnel-client exited ({status}) before a `{state}` event: {}",
                    self.context()
                );
            }
            assert!(
                self.started.elapsed() < RUN_BOUND,
                "no `{state}` event within {RUN_BOUND:?}: {}",
                self.context()
            );
            thread::sleep(Duration::from_millis(5));
        }
    }

    /// Wait for the exit; returns the status and how long after `since` it
    /// was observed.
    fn wait_exit(&mut self, since: Instant) -> (ExitStatus, Duration) {
        loop {
            if let Some(status) = self.child.try_wait().expect("poll tunnel-client") {
                let after = since.elapsed();
                // Let the reader threads drain the pipes.
                thread::sleep(Duration::from_millis(50));
                return (status, after);
            }
            if self.started.elapsed() > RUN_BOUND {
                let _ = self.child.kill();
                let _ = self.child.wait();
                panic!(
                    "tunnel-client did not exit within {RUN_BOUND:?}: {}",
                    self.context()
                );
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("/bin/kill")
            .arg(format!("-{signal}"))
            .arg(self.child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} failed: {status}");
    }

    /// The final `ok:false` diagnostic.
    fn final_error(&self) -> Value {
        let events = self.events();
        let last = events
            .last()
            .unwrap_or_else(|| panic!("no events: {}", self.context()))
            .clone();
        assert_eq!(last["ok"], Value::Bool(false), "{}", self.context());
        last["error"].clone()
    }
}

impl Drop for Run {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn delay_ms(event: &Value) -> u64 {
    event["result"]["delay_ms"]
        .as_u64()
        .unwrap_or_else(|| panic!("backoff event without delay_ms: {event}"))
}

/// Task row M6-C177: the refused target is refused, and no socket in this
/// binary can be given it.  A `FakeRelay` binds `127.0.0.1:0`, which only
/// ever returns a port from the ephemeral range, and nothing in this binary
/// binds a port below 1024 explicitly.  A helper that picks a port by
/// binding port 0 and releasing it again (as the old `refused_url` did) is
/// red here: its port is ephemeral.
#[test]
fn the_refused_target_is_refused_and_outside_every_ephemeral_range() {
    let url = refused_url();
    let port: u16 = url
        .strip_prefix("wss://127.0.0.1:")
        .and_then(|rest| rest.split('/').next())
        .and_then(|port| port.parse().ok())
        .unwrap_or_else(|| panic!("a loopback refused target: {url}"));
    assert!(
        port != 0 && port < 1024,
        "the refused target {port} is a port `127.0.0.1:0` can hand to a FakeRelay"
    );
    let address = SocketAddrV4::new(Ipv4Addr::LOCALHOST, port).into();
    for _ in 0..20 {
        let error = TcpStream::connect_timeout(&address, Duration::from_secs(5))
            .expect_err("nothing may accept on the refused port");
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::ConnectionRefused,
            "a dial to the refused target is refused, not timed out: {error}"
        );
    }
}

/// A refused relay is retried: each consecutive attempt's delay lies in
/// `[ceiling/2, ceiling]` with the ceiling doubling from `initial_delay_ms`
/// and capped at `max_delay_ms`, and after `max_attempts` retries the
/// process exits with the last cause, `4` `TRANSPORT_ERROR`.
#[test]
fn a_refused_relay_backs_off_with_bounded_jittered_delays_and_gives_up_at_the_limit() {
    let pki = Pki::new("a");
    let profile = profile(
        &refused_url(),
        &pki,
        &pki,
        "initial_delay_ms = 200\nmax_delay_ms = 800\nmax_attempts = 4",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, elapsed) = run.wait_exit(run.started);
    let context = run.context();
    assert_eq!(status.code(), Some(4), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "TRANSPORT_ERROR", "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("gave up after 4 consecutive reconnect attempts"),
        "{context}"
    );

    let backoffs = run.states("backoff");
    let attempts: Vec<u64> = backoffs
        .iter()
        .map(|event| event["result"]["attempt"].as_u64().unwrap_or_default())
        .collect();
    assert_eq!(attempts, [1, 2, 3, 4], "one backoff per retry: {context}");
    let ceilings = [200_u64, 400, 800, 800];
    let mut total = 0;
    for (event, ceiling) in backoffs.iter().zip(ceilings) {
        let delay = delay_ms(event);
        assert!(
            (ceiling / 2..=ceiling).contains(&delay),
            "delay {delay} ms outside [{}, {ceiling}]: {context}",
            ceiling / 2
        );
        assert_eq!(event["result"]["code"], "TRANSPORT_ERROR", "{context}");
        total += delay;
    }
    assert!(
        elapsed >= Duration::from_millis(total),
        "the process slept {elapsed:?}, less than the {total} ms it announced: {context}"
    );
    let disconnected = run.states("disconnected");
    assert_eq!(disconnected.len(), 4, "{context}");
    for event in &disconnected {
        assert_eq!(event["result"]["code"], "TRANSPORT_ERROR", "{context}");
        assert_eq!(event["result"]["sessions"], 0, "{context}");
        assert!(
            event["result"].get("session_id").is_none(),
            "no session was ready: {context}"
        );
    }
    assert_eq!(run.states("reconnecting").len(), 4, "{context}");
    assert!(run.states("reconnected").is_empty(), "{context}");
}

/// The jitter is real: two processes that fail at the same instant do not
/// announce the same delays. (Each delay is drawn from 0..=ceiling/2 ms above
/// the floor; four equal draws in a row at these ceilings is below one in
/// 10^9.)
#[test]
fn two_devices_failing_together_draw_different_delays() {
    let pki = Pki::new("a");
    let url = refused_url();
    let reconnect = "initial_delay_ms = 400\nmax_delay_ms = 1600\nmax_attempts = 4";
    let first = profile(&url, &pki, &pki, reconnect);
    let second = profile(&url, &pki, &pki, reconnect);
    let mut runs = [Run::start(&first, &[]), Run::start(&second, &[])];
    let mut delays = Vec::new();
    for run in &mut runs {
        let (status, _) = run.wait_exit(run.started);
        assert_eq!(status.code(), Some(4), "{}", run.context());
        delays.push(
            run.states("backoff")
                .iter()
                .map(delay_ms)
                .collect::<Vec<_>>(),
        );
    }
    assert_eq!(delays[0].len(), 4);
    assert_ne!(
        delays[0], delays[1],
        "two devices drew identical delays: no jitter"
    );
}

/// The retryable side of the TLS line: a relay that accepts TCP and then
/// **resets** the connection mid-handshake is what a middlebox or a relay
/// crashing mid-accept produces, and it is retried.
#[test]
fn a_relay_that_resets_mid_handshake_is_retried() {
    handshake_loss_is_retried(Mode::ResetAfterClientHello);
}

/// Likewise a relay that **closes** the connection in order mid-handshake.
#[test]
fn a_relay_that_closes_mid_handshake_is_retried() {
    handshake_loss_is_retried(Mode::CloseAfterClientHello);
}

fn handshake_loss_is_retried(mode: Mode) {
    let pki = Pki::new("a");
    let relay = FakeRelay::start(mode);
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200\nmax_attempts = 3",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, _) = run.wait_exit(run.started);
    let context = format!("accepted={} {}", relay.accepted(), run.context());
    assert_eq!(
        status.code(),
        Some(4),
        "a lost handshake is TRANSPORT_ERROR, not a credential refusal: {context}"
    );
    assert_eq!(run.final_error()["code"], "TRANSPORT_ERROR", "{context}");
    assert_eq!(run.states("backoff").len(), 3, "{context}");
    assert_eq!(
        relay.accepted(),
        4,
        "the first attempt and three retries all reached the relay: {context}"
    );
}

/// The terminal side: the relay's certificate is signed by a CA the profile
/// does not trust (the wrong `server_ca`). No retry can fix that, so the
/// process exits `3` `CREDENTIAL_ERROR` naming the reason, after exactly one
/// connection and without a backoff.
#[test]
fn an_untrusted_relay_certificate_exits_credential_error_without_retrying() {
    let relay_pki = Pki::new("relay");
    let other = Pki::new("other");
    let relay = FakeRelay::start(Mode::Tls(server_without_client_auth(&relay_pki)));
    let profile = profile(
        &relay.url(),
        &other,
        &other,
        "initial_delay_ms = 100\nmax_delay_ms = 200",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, elapsed) = run.wait_exit(run.started);
    // Give a (wrong) retry time to reach the relay before counting.
    thread::sleep(Duration::from_millis(400));
    let context = format!(
        "accepted={} relay_errors={:?} elapsed={elapsed:?} {}",
        relay.accepted(),
        relay.tls_errors.lock().expect("tls errors"),
        run.context()
    );
    assert_eq!(status.code(), Some(3), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "CREDENTIAL_ERROR", "{context}");
    assert_eq!(error["retryable"], Value::Bool(false), "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("relay's certificate was refused: unknown issuer"),
        "{context}"
    );
    assert!(run.states("backoff").is_empty(), "{context}");
    assert!(run.states("disconnected").is_empty(), "{context}");
    assert_eq!(relay.accepted(), 1, "exactly one attempt: {context}");
}

/// The terminal side, relay's half: the relay requires a device certificate
/// from an issuer this device's certificate is not from, and refuses it with
/// a certificate TLS alert. Exit `3` after one connection, no backoff.
#[test]
fn a_relay_refusing_the_device_certificate_exits_credential_error_without_retrying() {
    let pki = Pki::new("relay");
    let other_devices = Pki::new("other-devices");
    let relay = FakeRelay::start(Mode::Tls(server_requiring_devices_of(&pki, &other_devices)));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, elapsed) = run.wait_exit(run.started);
    thread::sleep(Duration::from_millis(400));
    let context = format!(
        "accepted={} relay_errors={:?} elapsed={elapsed:?} {}",
        relay.accepted(),
        relay.tls_errors.lock().expect("tls errors"),
        run.context()
    );
    assert!(
        !relay.tls_errors.lock().expect("tls errors").is_empty(),
        "the relay stand-in must have refused the device certificate: {context}"
    );
    assert_eq!(status.code(), Some(3), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "CREDENTIAL_ERROR", "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the relay refused this device's certificate"),
        "{context}"
    );
    assert!(run.states("backoff").is_empty(), "{context}");
    assert_eq!(relay.accepted(), 1, "exactly one attempt: {context}");
}

/// M6-C38: a relay that refuses the HELLO because it does not speak this
/// client's protocol major closes the control socket with the typed
/// `PROTOCOL_UNSUPPORTED` close.  With reconnect **on**, the process exits
/// `1` `PROTOCOL_ERROR` naming the cause after exactly one connection and no
/// `backoff` event.  Before the fix the relay dropped the socket and the loop
/// retried it indefinitely; here, before the client-side fix, the typed close
/// was read as a retryable transport loss.
#[test]
fn a_protocol_major_refusal_exits_protocol_error_without_retrying() {
    let pki = Pki::new("relay");
    let relay = FakeRelay::start(Mode::ControlClose(
        server_requiring_devices_of(&pki, &pki),
        1002,
        "PROTOCOL_UNSUPPORTED",
    ));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, elapsed) = run.wait_exit(run.started);
    thread::sleep(Duration::from_millis(400));
    let context = format!(
        "accepted={} completed={} relay_errors={:?} elapsed={elapsed:?} {}",
        relay.accepted(),
        relay.tls_completed.load(Ordering::Acquire),
        relay.tls_errors.lock().expect("tls errors"),
        run.context()
    );
    assert_eq!(
        relay.tls_completed.load(Ordering::Acquire),
        1,
        "the stand-in must have upgraded the socket and sent its close: {context}"
    );
    assert_eq!(status.code(), Some(1), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "PROTOCOL_ERROR", "{context}");
    assert_eq!(error["retryable"], Value::Bool(false), "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("refused this client's protocol major"),
        "{context}"
    );
    assert!(run.states("backoff").is_empty(), "{context}");
    assert_eq!(relay.accepted(), 1, "exactly one attempt: {context}");
}

/// The control for the case above: the same stand-in closing at the same
/// point with a close it does not type is still a retryable loss, so the
/// test above is red for the classification and not for the stand-in.
#[test]
fn an_untyped_close_after_the_hello_is_still_retried() {
    let pki = Pki::new("relay");
    let relay = FakeRelay::start(Mode::ControlClose(
        server_requiring_devices_of(&pki, &pki),
        1011,
        "internal",
    ));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200\nmax_attempts = 1",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, _) = run.wait_exit(run.started);
    thread::sleep(Duration::from_millis(400));
    let context = format!("accepted={} {}", relay.accepted(), run.context());
    assert_eq!(run.states("backoff").len(), 1, "{context}");
    assert_eq!(status.code(), Some(4), "{context}");
    assert_eq!(run.final_error()["code"], "TRANSPORT_ERROR", "{context}");
    assert_eq!(relay.accepted(), 2, "{context}");
}

/// A stop request while the process sleeps in backoff ends it at once with
/// `130` `CANCELLED` -- not after the delay, and not `0`: no session is live.
fn stop_during_backoff(signal: &str) {
    let pki = Pki::new("a");
    let profile = profile(
        &refused_url(),
        &pki,
        &pki,
        "initial_delay_ms = 5000\nmax_delay_ms = 5000",
    );
    let mut run = Run::start(&profile, &[]);
    let backoff = run.wait_for_state("backoff");
    let delay = delay_ms(&backoff);
    assert!(
        delay >= 2_500,
        "the delay must outlast the prompt bound: {backoff}"
    );
    thread::sleep(Duration::from_millis(100));
    assert!(
        run.child.try_wait().expect("poll").is_none(),
        "still in backoff: {}",
        run.context()
    );
    run.signal(signal);
    let signalled = Instant::now();
    let (status, after) = run.wait_exit(signalled);
    let context = format!("after_signal={after:?} {}", run.context());
    assert_eq!(status.code(), Some(130), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "CANCELLED", "{context}");
    let message = error["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&format!("SIG{signal} received while waiting to reconnect"))
            && message.contains("TRANSPORT_ERROR"),
        "{context}"
    );
    assert!(
        run.states("reconnecting").is_empty(),
        "no attempt after the stop: {context}"
    );
    assert!(
        after <= PROMPT_EXIT,
        "the exit must follow the signal, not the {delay} ms delay: {context}"
    );
}

#[test]
fn sigterm_during_backoff_exits_cancelled_promptly() {
    stop_during_backoff("TERM");
}

#[test]
fn sigint_during_backoff_exits_cancelled_promptly() {
    stop_during_backoff("INT");
}

/// `--no-reconnect` restores the pre-M6-C23 behaviour for one run, for a
/// supervisor that owns restarts: the first failure is the exit.
#[test]
fn no_reconnect_exits_on_the_first_failure() {
    let pki = Pki::new("a");
    let profile = profile(&refused_url(), &pki, &pki, "initial_delay_ms = 100");
    let mut run = Run::start(&profile, &["--no-reconnect"]);
    let (status, _) = run.wait_exit(run.started);
    let context = run.context();
    assert_eq!(status.code(), Some(4), "{context}");
    assert_eq!(run.final_error()["code"], "TRANSPORT_ERROR", "{context}");
    assert!(run.states("backoff").is_empty(), "{context}");
}

/// So does `[reconnect] enabled = false` in the profile.
#[test]
fn reconnect_disabled_in_the_profile_exits_on_the_first_failure() {
    let pki = Pki::new("a");
    let profile = profile(
        &refused_url(),
        &pki,
        &pki,
        "enabled = false\ninitial_delay_ms = 100",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, _) = run.wait_exit(run.started);
    let context = run.context();
    assert_eq!(status.code(), Some(4), "{context}");
    assert!(run.states("backoff").is_empty(), "{context}");
}

/// Clock skew, the device side: the relay refuses a certificate whose
/// `notBefore` is still ahead with the same `certificate_expired` alert it
/// sends for an expired one. The client reads its own certificate, finds it
/// not yet valid rather than expired, retries with a message naming the
/// clock -- and once the certificate becomes valid the relay accepts it,
/// with nothing restarted.
#[test]
fn a_device_certificate_not_yet_valid_is_retried_until_the_relay_accepts_it() {
    let now = unix_now();
    let pki = Pki::with_windows("skew", None, Some((now + 5, now + 86_400)));
    let relay = FakeRelay::start(Mode::Tls(server_requiring_devices_of(&pki, &pki)));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 500\nmax_delay_ms = 1000",
    );
    let mut run = Run::start(&profile, &[]);
    let first = run.wait_for_state("disconnected");
    fn context(relay: &FakeRelay, run: &Run) -> String {
        format!(
            "accepted={} tls_completed={} relay_errors={:?} {}",
            relay.accepted(),
            relay.tls_completed.load(Ordering::Acquire),
            relay.tls_errors.lock().expect("tls errors"),
            run.context()
        )
    }
    assert_eq!(
        first["result"]["code"],
        "TRANSPORT_ERROR",
        "{}",
        context(&relay, &run)
    );
    let message = first["result"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains("as expired or not yet valid on the relay's clock")
            && message.contains("not valid until unix time"),
        "the event must say the certificate is not yet valid, not expired: {}",
        context(&relay, &run)
    );
    let deadline = Instant::now() + Duration::from_secs(20);
    while relay.tls_completed.load(Ordering::Acquire) == 0 {
        assert!(
            run.child.try_wait().expect("poll").is_none(),
            "the client exited instead of retrying: {}",
            context(&relay, &run)
        );
        assert!(
            Instant::now() < deadline,
            "the relay never accepted the certificate: {}",
            context(&relay, &run)
        );
        thread::sleep(Duration::from_millis(20));
    }
    assert!(
        !relay.tls_errors.lock().expect("tls errors").is_empty(),
        "the relay refused it first: {}",
        context(&relay, &run)
    );
    run.signal("TERM");
    let (status, _) = run.wait_exit(Instant::now());
    assert_eq!(status.code(), Some(130), "{}", context(&relay, &run));
}

/// The device side, genuinely expired: past `notAfter` on this host's clock
/// too. Terminal, exit `3`, naming the expiry, after one connection.
#[test]
fn an_expired_device_certificate_exits_credential_error_without_retrying() {
    let now = unix_now();
    let pki = Pki::with_windows("expired", None, Some((now - 172_800, now - 3_600)));
    let relay = FakeRelay::start(Mode::Tls(server_requiring_devices_of(&pki, &pki)));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, _) = run.wait_exit(run.started);
    thread::sleep(Duration::from_millis(400));
    let context = format!(
        "accepted={} relay_errors={:?} {}",
        relay.accepted(),
        relay.tls_errors.lock().expect("tls errors"),
        run.context()
    );
    assert_eq!(status.code(), Some(3), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "CREDENTIAL_ERROR", "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("this device's certificate expired at unix time"),
        "{context}"
    );
    assert!(run.states("backoff").is_empty(), "{context}");
    assert_eq!(relay.accepted(), 1, "exactly one attempt: {context}");
}

/// The relay side: its certificate is expired on this host's clock. The
/// relay's certificate can be renewed and this host's clock can be wrong,
/// so it is retried, with the reason, not treated as a wrong `server_ca`.
#[test]
fn a_relay_certificate_expired_on_this_clock_is_retried() {
    let now = unix_now();
    let pki = Pki::with_windows("relay-expired", Some((now - 172_800, now - 3_600)), None);
    let relay = FakeRelay::start(Mode::Tls(server_without_client_auth(&pki)));
    let profile = profile(
        &relay.url(),
        &pki,
        &pki,
        "initial_delay_ms = 100\nmax_delay_ms = 200\nmax_attempts = 2",
    );
    let mut run = Run::start(&profile, &[]);
    let (status, _) = run.wait_exit(run.started);
    let context = format!("accepted={} {}", relay.accepted(), run.context());
    assert_eq!(status.code(), Some(4), "{context}");
    let error = run.final_error();
    assert_eq!(error["code"], "TRANSPORT_ERROR", "{context}");
    assert!(
        error["message"]
            .as_str()
            .unwrap_or_default()
            .contains("the relay's certificate is expired on this host's clock"),
        "{context}"
    );
    assert_eq!(run.states("backoff").len(), 2, "{context}");
    assert_eq!(relay.accepted(), 3, "{context}");
}
