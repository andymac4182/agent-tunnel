//! Process-level coverage for how `tunnel-client connect` stops on a signal
//! before its session is ready (task rows M6-C23 and M6-C27).
//!
//! **What was wrong.** The only stop handler was a `tokio::signal::ctrl_c()`
//! future armed after `connect_with_http_handlers` returned. During the
//! TLS/WebSocket handshake SIGINT kept the inherited disposition -- killed by
//! the signal with no output at the default, ignored until the 10 s handshake
//! deadline reported `DEADLINE_EXCEEDED` when inherited as ignored -- and
//! SIGTERM, which systemd and launchd send, killed the process in every phase
//! with no output at all.
//!
//! **What these tests hold.** The real binary is held in a named phase of its
//! handshake by a local listener that never answers, sent SIGTERM or SIGINT,
//! and must exit `130` with a `CANCELLED` diagnostic naming the signal. Each
//! test asserts three things, in an order chosen so that each defeat reddens
//! a different line:
//!
//! 1. the phase was **reached and held**: the silent relay witnessed it
//!    (connection accepted; for the upgrade phase, TLS completed and the
//!    request line read) and the process was still running when the signal
//!    was sent -- so the exit cannot be the handshake ending on its own, and
//!    the signal cannot have landed before `main` armed anything;
//! 2. the exit status and the diagnostic -- a defeated handler reddens here
//!    (killed by the signal: no status; ignored: exit `5`);
//! 3. the exit arrived **promptly** after the signal, well inside the 10 s
//!    handshake deadline -- a handler that fires but does not cancel the
//!    attempt reddens here, because the attempt then runs out its bounded
//!    unwind before the process reports.
//!
//! Phases after the session is ready need a relay and are covered by the M1
//! harness's CLI smoke (`crates/tunnel-test-harness/src/acceptance.rs`),
//! which stops the real binary with SIGTERM.

#![cfg(unix)]

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

/// How long after the phase is witnessed the signal is sent.
const SIGNAL_AFTER_PHASE: Duration = Duration::from_millis(100);

/// Bound on reaching the phase. Generous because the first exec of a freshly
/// linked binary on macOS can be delayed by the system's executable scan;
/// the phase is therefore witnessed by the silent relay (connection accepted,
/// and for the upgrade phase TLS completed and the request line read) rather
/// than assumed from elapsed time.
const PHASE_BOUND: Duration = Duration::from_secs(8);

/// The exit must follow the signal within this. Measured at 1--6 ms; the
/// bound is generous for a loaded machine and still well under both the
/// 2 s bounded unwind a non-cancelling handler would run out and the 10 s
/// handshake deadline.
const PROMPT_EXIT: Duration = Duration::from_secs(1);

/// Upper bound on the whole run, so a regression cannot hang the suite.
const RUN_BOUND: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug)]
enum Phase {
    /// TCP accepted, TLS ClientHello never answered.
    TlsHandshake,
    /// TLS complete, the WebSocket upgrade request never answered.
    WebSocketUpgrade,
}

#[derive(Clone, Copy, Debug)]
enum Disposition {
    /// The signal disposition a process started by a supervisor, or by
    /// Python's `subprocess`, normally has.
    Default,
    /// SIGINT and SIGTERM inherited as ignored, as a background job of a
    /// non-interactive shell inherits SIGINT. `trap "" INT TERM` sets
    /// `SIG_IGN`, which survives `exec`.
    InheritedIgnored,
}

/// A certificate authority, a relay leaf for `127.0.0.1`, and a device
/// identity, all synthetic.
struct Pki {
    ca_pem: String,
    server_chain_pem: String,
    server_key_pem: String,
    device_pem: String,
    device_key_pem: String,
}

impl Pki {
    fn new() -> Self {
        let ca_key = KeyPair::generate().expect("signal fixture CA key");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "signal fixture CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params.self_signed(&ca_key).expect("signal fixture CA");

        let server_key = KeyPair::generate().expect("signal fixture relay key");
        let mut server_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("relay leaf params");
        server_params.subject_alt_names.push(SanType::IpAddress(
            "127.0.0.1".parse().expect("loopback SAN"),
        ));
        server_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
        let server = server_params
            .signed_by(&server_key, &ca, &ca_key)
            .expect("signal fixture relay leaf");

        let device_key = KeyPair::generate().expect("signal fixture device key");
        let mut device_params = CertificateParams::default();
        device_params
            .distinguished_name
            .push(DnType::CommonName, "signal-fixture-device");
        device_params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ClientAuth];
        let device = device_params
            .signed_by(&device_key, &ca, &ca_key)
            .expect("signal fixture device leaf");

        Self {
            ca_pem: ca.pem(),
            server_chain_pem: format!("{}{}", server.pem(), ca.pem()),
            server_key_pem: server_key.serialize_pem(),
            device_pem: device.pem(),
            device_key_pem: device_key.serialize_pem(),
        }
    }
}

/// A local "relay" that accepts connections and never answers in the chosen
/// phase. It holds every accepted socket open until dropped, so the client
/// is never released by a close.
struct SilentRelay {
    port: u16,
    stop: Arc<AtomicBool>,
    accepted: Arc<Mutex<Vec<TcpStream>>>,
    tls_completed: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl SilentRelay {
    fn start(phase: Phase, pki: &Pki) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent relay");
        listener
            .set_nonblocking(true)
            .expect("make silent relay pollable");
        let port = listener.local_addr().expect("silent relay address").port();
        let stop = Arc::new(AtomicBool::new(false));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let tls_completed = Arc::new(AtomicBool::new(false));
        let server_config = match phase {
            Phase::TlsHandshake => None,
            Phase::WebSocketUpgrade => Some(server_config(pki)),
        };
        let thread = {
            let stop = Arc::clone(&stop);
            let accepted = Arc::clone(&accepted);
            let tls_completed = Arc::clone(&tls_completed);
            thread::spawn(move || {
                while !stop.load(Ordering::Acquire) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            stream
                                .set_nonblocking(false)
                                .expect("silent relay blocking stream");
                            let stream = match &server_config {
                                None => stream,
                                Some(config) => {
                                    match complete_tls_then_read(stream, Arc::clone(config)) {
                                        Some(stream) => {
                                            tls_completed.store(true, Ordering::Release);
                                            stream
                                        }
                                        None => continue,
                                    }
                                }
                            };
                            accepted.lock().expect("silent relay sockets").push(stream);
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
            tls_completed,
            thread: Some(thread),
        }
    }

    fn url(&self) -> String {
        format!("wss://127.0.0.1:{}/v1/tunnel/control", self.port)
    }

    fn accepted(&self) -> usize {
        self.accepted.lock().expect("silent relay sockets").len()
    }
}

impl Drop for SilentRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn server_config(pki: &Pki) -> Arc<rustls::ServerConfig> {
    let certificates = rustls_pemfile::certs(&mut pki.server_chain_pem.as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse relay chain");
    let key = rustls_pemfile::private_key(&mut pki.server_key_pem.as_bytes())
        .expect("parse relay key")
        .expect("relay key present");
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("relay protocol versions")
    .with_no_client_auth()
    .with_single_cert(certificates, key)
    .expect("relay server config");
    Arc::new(config)
}

/// Complete the TLS handshake, then read (and discard) the start of the
/// WebSocket upgrade request so the client is known to be waiting for the
/// response. Returns the socket, which is then held without a reply.
fn complete_tls_then_read(
    mut stream: TcpStream,
    config: Arc<rustls::ServerConfig>,
) -> Option<TcpStream> {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .expect("bounded TLS fixture read");
    let mut connection = rustls::ServerConnection::new(config).expect("relay TLS session");
    while connection.is_handshaking() {
        connection.complete_io(&mut stream).ok()?;
    }
    let mut tls = rustls::Stream::new(&mut connection, &mut stream);
    let mut request = [0_u8; 16];
    tls.read_exact(&mut request).ok()?;
    if !request.starts_with(b"GET ") {
        return None;
    }
    Some(stream)
}

struct Fixture {
    _root: TempDir,
    config: PathBuf,
    relay: SilentRelay,
}

impl Fixture {
    fn new(phase: Phase) -> Self {
        let pki = Pki::new();
        let relay = SilentRelay::start(phase, &pki);
        let root = tempdir().expect("create signal fixture directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("make signal fixture private");
        let write = |name: &str, contents: &str, mode: u32| {
            let path = root.path().join(name);
            fs::write(&path, contents).expect("write signal fixture file");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode))
                .expect("set signal fixture mode");
            path
        };
        let certificate = write("device-cert.pem", &pki.device_pem, 0o644);
        let key = write("device-key.pem", &pki.device_key_pem, 0o600);
        let ca = write("relay-ca.pem", &pki.ca_pem, 0o644);
        let config = write(
            "client.toml",
            &format!(
                "device_id = \"signal-fixture\"\nrelay_url = \"{}\"\nclient_cert = {}\nprivate_key = {}\nserver_ca = {}\n",
                relay.url(),
                toml_string(&certificate),
                toml_string(&key),
                toml_string(&ca),
            ),
            0o600,
        );
        Self {
            _root: root,
            config,
            relay,
        }
    }
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

fn client_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-client"))
}

fn spawn_connect(fixture: &Fixture, disposition: Disposition, json: bool) -> Child {
    let binary = client_binary();
    let mut command = match disposition {
        Disposition::Default => Command::new(&binary),
        Disposition::InheritedIgnored => {
            let mut command = Command::new("/bin/sh");
            command
                .arg("-c")
                .arg("trap '' INT TERM; exec \"$0\" \"$@\"")
                .arg(&binary);
            command
        }
    };
    command
        .arg("connect")
        .arg("--config")
        .arg(&fixture.config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if json {
        command.arg("--json");
    }
    command.spawn().expect("spawn tunnel-client connect")
}

fn send_signal(child: &Child, signal: &str) {
    let status = Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} failed: {status}");
}

struct Observed {
    status: ExitStatus,
    after_signal: Duration,
    stdout: String,
    stderr: String,
}

/// Hold the process in `phase`, signal it, and collect how it ended.
fn signal_during(
    fixture: &Fixture,
    phase: Phase,
    disposition: Disposition,
    signal: &str,
    json: bool,
) -> Observed {
    let mut child = spawn_connect(fixture, disposition, json);
    let started = Instant::now();
    let reached = || match phase {
        Phase::TlsHandshake => fixture.relay.accepted() >= 1,
        Phase::WebSocketUpgrade => fixture.relay.tls_completed.load(Ordering::Acquire),
    };
    while !reached() && started.elapsed() < PHASE_BOUND {
        if child.try_wait().expect("poll tunnel-client").is_some() {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }
    thread::sleep(SIGNAL_AFTER_PHASE);

    // (1) The phase was really held: the process is alive, the relay has
    // the connection, and for the upgrade phase TLS has completed.
    let early = child.try_wait().expect("poll tunnel-client");
    if let Some(status) = early {
        let output = child.wait_with_output().expect("collect early exit");
        panic!(
            "tunnel-client exited before the signal ({status}); the phase was not held: stdout={} stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
    assert!(
        fixture.relay.accepted() >= 1,
        "the silent relay never received the connection, so {phase:?} was not reached"
    );
    if matches!(phase, Phase::WebSocketUpgrade) {
        assert!(
            fixture.relay.tls_completed.load(Ordering::Acquire),
            "TLS did not complete, so the WebSocket upgrade phase was not reached"
        );
    }

    send_signal(&child, signal);
    let signalled = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("poll tunnel-client") {
            break status;
        }
        if started.elapsed() > RUN_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("tunnel-client did not exit within {RUN_BOUND:?} of starting");
        }
        thread::sleep(Duration::from_millis(2));
    };
    let after_signal = signalled.elapsed();
    let mut stdout = String::new();
    let mut stderr = String::new();
    child
        .stdout
        .take()
        .expect("stdout pipe")
        .read_to_string(&mut stdout)
        .expect("read stdout");
    child
        .stderr
        .take()
        .expect("stderr pipe")
        .read_to_string(&mut stderr)
        .expect("read stderr");
    Observed {
        status,
        after_signal,
        stdout,
        stderr,
    }
}

/// (2) and (3): exit `130`, a `CANCELLED` diagnostic naming the signal, and
/// promptly.
fn assert_cancelled_promptly(observed: &Observed, signal: &str) {
    let context = format!(
        "status={} after_signal={:?} stdout={:?} stderr={:?}",
        observed.status, observed.after_signal, observed.stdout, observed.stderr
    );
    assert_eq!(
        observed.status.code(),
        Some(130),
        "a stop request before the session is ready must exit 130 CANCELLED, \
         not die by the signal (no status) or run out the handshake deadline (5): {context}"
    );
    let line = observed
        .stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("no JSON diagnostic on stdout: {context}"));
    let report: Value = serde_json::from_str(line)
        .unwrap_or_else(|error| panic!("diagnostic is not JSON ({error}): {context}"));
    assert_eq!(report["command"], "connect", "{context}");
    assert_eq!(report["ok"], Value::Bool(false), "{context}");
    assert_eq!(report["error"]["code"], "CANCELLED", "{context}");
    let message = report["error"]["message"].as_str().unwrap_or_default();
    assert!(
        message.contains(&format!("SIG{signal}"))
            && message.contains("before the session was ready"),
        "the diagnostic must name the signal and the phase: {context}"
    );
    assert!(
        observed.after_signal <= PROMPT_EXIT,
        "the exit must follow the signal promptly, not the bounded unwind or \
         the handshake deadline: {context}"
    );
}

#[test]
fn sigterm_during_the_tls_handshake_exits_cancelled() {
    let fixture = Fixture::new(Phase::TlsHandshake);
    let observed = signal_during(
        &fixture,
        Phase::TlsHandshake,
        Disposition::Default,
        "TERM",
        true,
    );
    assert_cancelled_promptly(&observed, "TERM");
}

#[test]
fn sigint_during_the_tls_handshake_exits_cancelled() {
    let fixture = Fixture::new(Phase::TlsHandshake);
    let observed = signal_during(
        &fixture,
        Phase::TlsHandshake,
        Disposition::Default,
        "INT",
        true,
    );
    assert_cancelled_promptly(&observed, "INT");
}

#[test]
fn sigterm_during_the_websocket_upgrade_exits_cancelled() {
    let fixture = Fixture::new(Phase::WebSocketUpgrade);
    let observed = signal_during(
        &fixture,
        Phase::WebSocketUpgrade,
        Disposition::Default,
        "TERM",
        true,
    );
    assert_cancelled_promptly(&observed, "TERM");
}

#[test]
fn sigint_during_the_websocket_upgrade_exits_cancelled() {
    let fixture = Fixture::new(Phase::WebSocketUpgrade);
    let observed = signal_during(
        &fixture,
        Phase::WebSocketUpgrade,
        Disposition::Default,
        "INT",
        true,
    );
    assert_cancelled_promptly(&observed, "INT");
}

/// The disposition M6-C27 measured being ignored for ten seconds. The binary
/// installs its handler over an inherited `SIG_IGN` on purpose; see
/// `docs/runtime.md`, "Stopping `connect`".
#[test]
fn sigint_inherited_as_ignored_still_cancels_the_handshake() {
    let fixture = Fixture::new(Phase::TlsHandshake);
    let observed = signal_during(
        &fixture,
        Phase::TlsHandshake,
        Disposition::InheritedIgnored,
        "INT",
        true,
    );
    assert_cancelled_promptly(&observed, "INT");
}

#[test]
fn sigterm_inherited_as_ignored_still_cancels_the_handshake() {
    let fixture = Fixture::new(Phase::TlsHandshake);
    let observed = signal_during(
        &fixture,
        Phase::TlsHandshake,
        Disposition::InheritedIgnored,
        "TERM",
        true,
    );
    assert_cancelled_promptly(&observed, "TERM");
}

/// Without `--json` the same cause reaches stderr as the one-line message.
#[test]
fn sigterm_without_json_reports_the_cancellation_on_stderr() {
    let fixture = Fixture::new(Phase::TlsHandshake);
    let observed = signal_during(
        &fixture,
        Phase::TlsHandshake,
        Disposition::Default,
        "TERM",
        false,
    );
    let context = format!(
        "status={} after_signal={:?} stdout={:?} stderr={:?}",
        observed.status, observed.after_signal, observed.stdout, observed.stderr
    );
    assert_eq!(observed.status.code(), Some(130), "{context}");
    assert!(observed.stdout.is_empty(), "{context}");
    assert_eq!(
        observed.stderr.trim_end(),
        "tunnel-client: SIGTERM received before the session was ready; the connect attempt was cancelled",
        "{context}"
    );
    assert!(observed.after_signal <= PROMPT_EXIT, "{context}");
}
