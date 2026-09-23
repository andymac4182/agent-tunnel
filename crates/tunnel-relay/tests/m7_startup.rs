//! Bounded startup-failure coverage for the executable M7 boundary.
//!
//! These tests deliberately start the `tunnel-relay` binary instead of calling
//! config or membership helpers directly.  A failure is useful only when the
//! process exits promptly, emits the typed/redacted reason, and leaves no
//! public or peer listener behind.

use std::{
    ffi::OsStr,
    fs, io,
    net::{SocketAddr, TcpListener, UdpSocket},
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose, SanType,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener as TokioTcpListener,
    task::JoinSet,
    time::sleep,
};
use tokio_rustls::TlsAcceptor;
use tunnel_transport::load_server_config_from_pem;

const DIAGNOSTIC_SECRET: &str = "m7-startup-fixture-secret-9f7c";
const PROCESS_DEADLINE: Duration = Duration::from_secs(5);
const REDIS_RUN_ID: &str = "m7-startup-fixture-redis-run";

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct FixtureDirectory {
    root: PathBuf,
}

impl FixtureDirectory {
    fn new(prefix: &str) -> Self {
        let base = std::env::temp_dir();
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        for attempt in 0..32 {
            let suffix = if attempt == 0 {
                format!("{}-{serial}", std::process::id())
            } else {
                format!("{}-{serial}-{attempt}", std::process::id())
            };
            let root = base.join(format!("{prefix}-{suffix}"));
            match fs::create_dir(&root) {
                Ok(()) => {
                    set_mode(&root, 0o700);
                    return Self {
                        root: fs::canonicalize(root).expect("canonicalize startup fixture"),
                    };
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
                Err(error) => panic!("create startup fixture directory: {error}"),
            }
        }
        panic!("could not allocate startup fixture directory")
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, contents).expect("write startup fixture file");
        set_mode(&path, 0o600);
        path
    }
}

impl Drop for FixtureDirectory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

/// Files and bindings used by a real `serve` invocation.  The generated
/// certificate is intentionally reused for the three relay roles because the
/// failure cases stop before any role admission; the test still exercises the
/// executable's actual file and TLS construction order.
struct StartupFixture {
    files: FixtureDirectory,
    certificate_chain: PathBuf,
    private_key: PathBuf,
    ca: PathBuf,
    oidc_jwks: PathBuf,
    membership_trust: PathBuf,
    state: PathBuf,
    redis_root_ca: PathBuf,
    config: PathBuf,
    consumer_bind: SocketAddr,
    device_bind: SocketAddr,
    peer_bind: SocketAddr,
}

impl StartupFixture {
    fn new() -> Self {
        let files = FixtureDirectory::new("agent-tunnel-m7-startup");
        let ca_key = KeyPair::generate().expect("startup fixture CA key");
        let mut ca_params = CertificateParams::default();
        ca_params
            .distinguished_name
            .push(DnType::CommonName, "M7 startup fixture CA");
        ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
        ca_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
        let ca = ca_params
            .self_signed(&ca_key)
            .expect("startup fixture CA certificate");

        let leaf_key = KeyPair::generate().expect("startup fixture leaf key");
        let mut leaf_params =
            CertificateParams::new(vec!["localhost".to_owned()]).expect("startup leaf params");
        leaf_params
            .distinguished_name
            .push(DnType::CommonName, "M7 startup fixture relay");
        leaf_params.subject_alt_names.push(SanType::IpAddress(
            "127.0.0.1".parse().expect("fixture IP SAN"),
        ));
        leaf_params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
        leaf_params.extended_key_usages = vec![
            ExtendedKeyUsagePurpose::ServerAuth,
            ExtendedKeyUsagePurpose::ClientAuth,
        ];
        let leaf = leaf_params
            .signed_by(&leaf_key, &ca, &ca_key)
            .expect("startup fixture leaf certificate");

        let ca = files.write("startup-ca.pem", ca.pem().as_bytes());
        let certificate_chain = files.write(
            "startup-cert-chain.pem",
            format!(
                "{}{}",
                leaf.pem(),
                fs::read_to_string(&ca).expect("read fixture CA")
            )
            .as_bytes(),
        );
        let private_key = files.write("startup-key.pem", leaf_key.serialize_pem().as_bytes());
        // A throwaway 2048-bit RSA public modulus generated with OpenSSL (the
        // private half was discarded).  The verifier refuses placeholder keys
        // at startup, and these tests must get past OIDC configuration to
        // reach the Redis and membership checks they target.
        let oidc_jwks = files.write(
            "startup-jwks.json",
            concat!(
                r#"{"keys":[{"kid":"startup-fixture","kty":"RSA","alg":"RS256","n":""#,
                "wpzxK4YhVbeIGQkBFuC8Lwc5iX4NpKHeWN6c1zg6xBCJ2oDK-KD_Q19VR-_OeOcQvzeWHPnHM1c6Mg2vrBm-",
                "6obc5R4gNQd-CZz9H4QS6SUQ-S2rjWVzCWpx0SWIzS4Uw7_yu_qHsoUWQVBVZIBQ49AUBNLg6pCr-r6dwkxc",
                "r67-m5Jjw1-E9-Vq54tgGMzRocZWU79N75jXzLRzDOLbOJex-CrCcek2owQ-Cv5f61-5gacszQjnu8kjt2Zs",
                "mnr0PVzNcaBwvbt66qJLAnXLZghu6JmWEGoeGYpG7XjX9S_A8n_9pA58xDnrsxSNnlRTy3LQMUtlDcDCd0jL",
                "vBLw3w",
                r#"","e":"AQAB"}]}"#
            )
            .as_bytes(),
        );
        let membership_key =
            KeyPair::generate_for(&rcgen::PKCS_ED25519).expect("startup membership key");
        let membership_public_key = membership_key
            .public_key_raw()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>();
        let membership_trust = files.write(
            "startup-membership-trust.json",
            format!(
                r#"{{"keys":[{{"key_id":"startup-publisher","public_key":"{membership_public_key}"}}]}}"#
            )
            .as_bytes(),
        );
        let state = files.path("startup-membership-state.json");
        let config = files.path("relay.toml");

        Self {
            redis_root_ca: ca.clone(),
            files,
            certificate_chain,
            private_key,
            ca,
            oidc_jwks,
            membership_trust,
            state,
            config,
            consumer_bind: free_tcp_addr(),
            device_bind: free_tcp_addr(),
            peer_bind: free_udp_addr(),
        }
    }

    fn write_config(
        &self,
        redis_url: &str,
        checkpoint_endpoint: &str,
        top_level_node_id: &str,
        cluster_node_id: Option<&str>,
        include_state_path: bool,
    ) -> PathBuf {
        let cluster_node = cluster_node_id
            .map(|node_id| format!("node_id = {}\n", quote(node_id)))
            .unwrap_or_default();
        let state_path = if include_state_path {
            format!(
                "membership_version_state_path = {}\n",
                quote_path(&self.state)
            )
        } else {
            String::new()
        };
        let text = format!(
            r#"consumer_bind = {consumer_bind}
device_bind = {device_bind}
oidc_issuer = "https://issuer.m7-startup.invalid/"
oidc_audience = ["agent-tunnel"]
oidc_jwks_path = {oidc_jwks}
redis_url = {redis_url}
redis_namespace = "fixture-m7-startup"
redis_tls_root_ca_path = {redis_root_ca}
deployment_incarnation = "m7-startup-incarnation"
device_tls_cert_chain = {certificate_chain}
device_tls_private_key = {private_key}
device_tls_client_ca = {ca}
consumer_tls_cert_chain = {certificate_chain}
consumer_tls_private_key = {private_key}
node_id = {top_level_node_id}

[cluster]
deployment_id = "m7-startup-deployment"
peer_bind = {peer_bind}
peer_tls_cert_chain = {certificate_chain}
peer_tls_private_key = {private_key}
peer_tls_client_ca = {ca}
membership_signer_trust_path = {membership_trust}
checkpoint_authority_endpoint = {checkpoint_endpoint}
checkpoint_authority_trust_path = {ca}
{state_path}{cluster_node}
[cluster.endpoint_policy]
allowed_ports = [{peer_port}]
require_private_ip = true
"#,
            consumer_bind = quote(&self.consumer_bind.to_string()),
            device_bind = quote(&self.device_bind.to_string()),
            oidc_jwks = quote_path(&self.oidc_jwks),
            redis_url = quote(redis_url),
            redis_root_ca = quote_path(&self.redis_root_ca),
            certificate_chain = quote_path(&self.certificate_chain),
            private_key = quote_path(&self.private_key),
            ca = quote_path(&self.ca),
            top_level_node_id = quote(top_level_node_id),
            peer_bind = quote(&self.peer_bind.to_string()),
            membership_trust = quote_path(&self.membership_trust),
            checkpoint_endpoint = quote(checkpoint_endpoint),
            state_path = state_path,
            cluster_node = cluster_node,
            peer_port = self.peer_bind.port(),
        );
        fs::write(&self.config, text).expect("write startup relay config");
        set_mode(&self.config, 0o600);
        self.config.clone()
    }

    fn valid_config(&self, redis_url: &str) -> PathBuf {
        self.write_config(
            redis_url,
            "https://checkpoint.m7-startup.invalid/v1/checkpoint",
            "relay-startup",
            None,
            true,
        )
    }

    fn assert_bindings_available(&self) {
        TcpListener::bind(self.consumer_bind)
            .expect("consumer listener was not left serving after startup failure");
        TcpListener::bind(self.device_bind)
            .expect("device listener was not left serving after startup failure");
        UdpSocket::bind(self.peer_bind)
            .expect("peer listener was not left serving after startup failure");
    }
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("quote startup fixture TOML value")
}

fn quote_path(path: &Path) -> String {
    quote(path.to_str().expect("startup fixture path is UTF-8"))
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("set startup fixture permissions");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn free_tcp_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("allocate startup TCP port");
    listener.local_addr().expect("read startup TCP port")
}

fn free_udp_addr() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").expect("allocate startup UDP port");
    socket.local_addr().expect("read startup UDP port")
}

fn relay_binary() -> std::ffi::OsString {
    std::ffi::OsString::from(env!("CARGO_BIN_EXE_tunnel-relay"))
}

fn run_relay_bounded<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    let mut child = Command::new(relay_binary())
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tunnel-relay startup case");
    let deadline = Instant::now() + PROCESS_DEADLINE;
    loop {
        if child
            .try_wait()
            .expect("poll tunnel-relay startup case")
            .is_some()
        {
            return child
                .wait_with_output()
                .expect("collect tunnel-relay startup output");
        }
        if Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            panic!("tunnel-relay startup case exceeded five-second bound");
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn assert_failure(output: &Output, expected: &str) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let diagnostics = format!("{stdout}\n{stderr}");
    assert!(
        !output.status.success(),
        "startup unexpectedly succeeded; diagnostics: {diagnostics}"
    );
    assert!(
        diagnostics.contains(expected),
        "startup diagnostics did not contain {expected:?}: {diagnostics}"
    );
    assert!(
        !diagnostics.contains("tunnel-relay listening:"),
        "startup emitted a serving marker before failing: {diagnostics}"
    );
    assert!(
        !diagnostics.contains(DIAGNOSTIC_SECRET),
        "startup diagnostics leaked fixture secret: {diagnostics}"
    );
}

fn initialize_state(fixture: &StartupFixture, redis_url: &str) {
    let config = fixture.valid_config(redis_url);
    let output = run_relay_bounded([
        OsStr::new("initialize"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert!(
        output.status.success(),
        "initialize failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        fixture.state.exists(),
        "initialize did not create state file"
    );
}

#[test]
fn serve_rejects_malformed_and_unknown_toml_before_any_listener() {
    let fixture = StartupFixture::new();
    let malformed = fixture.files.write("malformed.toml", b"oidc_issuer = [\n");
    let malformed_output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        malformed.as_os_str(),
    ]);
    assert_failure(&malformed_output, "invalid relay TOML");

    let valid = fixture.valid_config("rediss://127.0.0.1:1/0");
    let mut unknown = fs::read_to_string(valid).expect("read startup config");
    unknown.push_str(&format!("unknown_startup_field = {DIAGNOSTIC_SECRET:?}\n"));
    let unknown_path = fixture.files.write("unknown.toml", unknown.as_bytes());
    let unknown_output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        unknown_path.as_os_str(),
    ]);
    assert_failure(&unknown_output, "unknown field");
    fixture.assert_bindings_available();
}

#[test]
fn serve_rejects_required_and_mismatched_cluster_identity() {
    let fixture = StartupFixture::new();
    let mismatch = fixture.write_config(
        &format!("rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:1/0"),
        "https://checkpoint.m7-startup.invalid/v1/checkpoint",
        "relay-local",
        Some("relay-other"),
        true,
    );
    let mismatch_output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        mismatch.as_os_str(),
    ]);
    assert_failure(
        &mismatch_output,
        "cluster.node_id must match the relay node_id",
    );

    let missing_identity = fixture.write_config(
        &format!("rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:1/0"),
        "https://checkpoint.m7-startup.invalid/v1/checkpoint",
        "",
        None,
        true,
    );
    let missing_identity_output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        missing_identity.as_os_str(),
    ]);
    assert_failure(
        &missing_identity_output,
        "cluster mode requires a top-level node_id",
    );

    let missing_state = fixture.write_config(
        &format!("rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:1/0"),
        "https://checkpoint.m7-startup.invalid/v1/checkpoint",
        "relay-local",
        None,
        false,
    );
    let missing_state_output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        missing_state.as_os_str(),
    ]);
    assert_failure(&missing_state_output, "membership_version_state_path");
    fixture.assert_bindings_available();
}

#[test]
fn serve_rejects_unavailable_verified_redis_before_binding() {
    let fixture = StartupFixture::new();
    let closed_port = free_tcp_addr().port();
    let config = fixture.valid_config(&format!(
        "rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:{closed_port}/0"
    ));
    let output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert_failure(&output, "Redis catalog connection failed");
    fixture.assert_bindings_available();
}

#[test]
fn serve_rejects_corrupt_membership_state_through_the_binary() {
    let fixture = StartupFixture::new();
    let placeholder_url = "rediss://127.0.0.1:1/0";
    initialize_state(&fixture, placeholder_url);
    fixture.files.write(
        "startup-membership-state.json",
        DIAGNOSTIC_SECRET.as_bytes(),
    );

    let redis = FakeRedisTls::start(&fixture);
    let config = fixture.valid_config(&redis.url());
    let output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert_failure(&output, "membership state is corrupt");
    fixture.assert_bindings_available();
}

#[cfg(unix)]
#[test]
fn serve_rejects_insecure_membership_state_through_the_binary() {
    let fixture = StartupFixture::new();
    initialize_state(&fixture, "rediss://127.0.0.1:1/0");
    set_mode(&fixture.state, 0o644);

    let redis = FakeRedisTls::start(&fixture);
    let config = fixture.valid_config(&redis.url());
    let output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert_failure(&output, "membership state permissions are too broad");
    fixture.assert_bindings_available();
}

#[test]
fn serve_rejects_unavailable_checkpoint_before_public_serving() {
    let fixture = StartupFixture::new();
    initialize_state(&fixture, "rediss://127.0.0.1:1/0");
    let redis = FakeRedisTls::start(&fixture);
    let checkpoint_port = free_tcp_addr().port();
    let config = fixture.write_config(
        &redis.url(),
        &format!("https://127.0.0.1:{checkpoint_port}/v1/checkpoint"),
        "relay-startup",
        None,
        true,
    );
    let output = run_relay_bounded([
        OsStr::new("serve"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    // `MembershipRuntime::start` records the authority failure in its
    // redacted readiness state; the executable refuses to serve with the
    // bounded, stable startup-level reason.
    assert_failure(&output, "cluster membership bootstrap did not reach ready");
    fixture.assert_bindings_available();
}

// ------------------------------------------------------------------------
// Stop requests during startup (task row M6-C23).
//
// Before M6-C23 `serve` awaited `tokio::signal::ctrl_c()` only after its
// listeners were up. A SIGTERM -- what systemd and launchd send -- killed it
// in every phase without running `RunningRelay::shutdown`, and a SIGINT did
// the same during startup. These hold the real binary in a startup phase
// with a peer that accepts and never answers, send the signal, and require:
// (1) the peer the phase waits on has accepted the relay's connection and
// the process is still running when signalled, so the phase was held;
// (2) exit `130` with the startup-interruption diagnostic and no serving
// marker -- a defeated handler reddens here (death by signal has no status);
// (3) the exit followed the signal promptly, not the phase's own timeout;
// (4) nothing was left bound.

/// A TCP peer that accepts every connection and never sends a byte, holding
/// each socket open so the relay is never released by a close.
struct SilentPeer {
    address: SocketAddr,
    accepted: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl SilentPeer {
    fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind silent peer");
        listener
            .set_nonblocking(true)
            .expect("make silent peer pollable");
        let address = listener.local_addr().expect("silent peer address");
        let accepted = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let task_accepted = Arc::clone(&accepted);
        let task = thread::spawn(move || {
            let mut held = Vec::new();
            while !task_stop.load(Ordering::Acquire) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        held.push(stream);
                        task_accepted.fetch_add(1, Ordering::AcqRel);
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => return,
                }
            }
        });
        Self {
            address,
            accepted,
            stop,
            task: Some(task),
        }
    }
}

impl Drop for SilentPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

/// How long after the phase is reached the signal is sent.
const SIGNAL_AFTER_PHASE: Duration = Duration::from_millis(100);
/// The exit must follow the signal within this. Measured at a few
/// milliseconds. Each held phase also ends by itself, and measured with the
/// handler defeated (log nonce `m6c23-relay-startup-red-*`) that came about
/// 0.9 s after a signal sent 100 ms into the Redis phase and 1.9 s into the
/// checkpoint phase -- each with exit `1`, which the status assertion
/// already refuses; this bound additionally refuses a `130` that only
/// arrived when the phase gave up.
const SIGNAL_PROMPT_EXIT: Duration = Duration::from_millis(500);
/// Bound on reaching the phase. Generous because the first exec of a freshly
/// linked binary on macOS can be delayed by the system's executable scan --
/// which is exactly why the phase is witnessed by the peer rather than
/// assumed from elapsed time: a first run of these tests that signalled on
/// a fixed 800 ms timer signalled a process that had not reached `main` yet.
const SIGNAL_PHASE_BOUND: Duration = Duration::from_secs(20);
const SIGNAL_RUN_BOUND: Duration = Duration::from_secs(30);

/// Start `serve`, wait until `phase_peer` has accepted its connection (the
/// witness that the startup phase is reached and held), signal it, and
/// return the output plus the time from the signal to the exit.
fn signal_serve_during_startup(
    config: &Path,
    phase_peer: &SilentPeer,
    signal: &str,
    inherited_ignored: bool,
) -> (Output, Duration) {
    let mut command = if inherited_ignored {
        // `trap ''` sets SIG_IGN, which survives `exec`.
        let mut command = Command::new("/bin/sh");
        command
            .arg("-c")
            .arg("trap '' INT TERM; exec \"$0\" \"$@\"")
            .arg(relay_binary());
        command
    } else {
        Command::new(relay_binary())
    };
    let mut child = command
        .arg("serve")
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tunnel-relay serve");
    let started = Instant::now();
    while phase_peer.accepted.load(Ordering::Acquire) == 0 {
        if child.try_wait().expect("poll tunnel-relay").is_some() {
            let output = child.wait_with_output().expect("collect early exit");
            panic!(
                "serve exited before reaching the held phase: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        if started.elapsed() > SIGNAL_PHASE_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve did not reach the held phase within {SIGNAL_PHASE_BOUND:?}");
        }
        thread::sleep(Duration::from_millis(2));
    }
    thread::sleep(SIGNAL_AFTER_PHASE);
    if child.try_wait().expect("poll tunnel-relay").is_some() {
        let output = child.wait_with_output().expect("collect early exit");
        panic!(
            "serve exited before the signal, so the startup phase was not held: status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let status = Command::new("/bin/kill")
        .arg(format!("-{signal}"))
        .arg(child.id().to_string())
        .status()
        .expect("run kill");
    assert!(status.success(), "kill -{signal} failed: {status}");
    let signalled = Instant::now();
    loop {
        if child.try_wait().expect("poll tunnel-relay").is_some() {
            break;
        }
        if started.elapsed() > SIGNAL_RUN_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("serve did not exit within {SIGNAL_RUN_BOUND:?}");
        }
        thread::sleep(Duration::from_millis(2));
    }
    let after_signal = signalled.elapsed();
    (
        child.wait_with_output().expect("collect serve output"),
        after_signal,
    )
}

fn assert_interrupted_during_startup(output: &Output, after_signal: Duration, signal: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!(
        "status={} after_signal={after_signal:?} stderr={stderr}",
        output.status
    );
    assert_eq!(
        output.status.code(),
        Some(130),
        "a stop request during startup must exit 130, not die by the signal: {context}"
    );
    assert!(
        stderr.contains(&format!(
            "tunnel-relay: SIG{signal} received during startup; serve stopped before any listener was serving"
        )),
        "the diagnostic must name the signal and the phase: {context}"
    );
    assert!(
        !stderr.contains("tunnel-relay listening:"),
        "serve reported serving before it was stopped: {context}"
    );
    assert!(
        !stderr.contains(DIAGNOSTIC_SECRET),
        "the startup diagnostic leaked the fixture secret: {context}"
    );
    assert!(
        after_signal <= SIGNAL_PROMPT_EXIT,
        "the exit must follow the signal promptly, not the phase's own timeout: {context}"
    );
}

/// Held in the TLS handshake of the Redis catalog connection.
fn signal_while_connecting_to_redis(signal: &str, inherited_ignored: bool) {
    let fixture = StartupFixture::new();
    let redis = SilentPeer::start();
    let config = fixture.valid_config(&format!(
        "rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:{}/0",
        redis.address.port()
    ));
    let (output, after_signal) =
        signal_serve_during_startup(&config, &redis, signal, inherited_ignored);
    assert_interrupted_during_startup(&output, after_signal, signal);
    fixture.assert_bindings_available();
}

#[cfg(unix)]
#[test]
fn serve_sigterm_while_connecting_to_redis_exits_interrupted() {
    signal_while_connecting_to_redis("TERM", false);
}

#[cfg(unix)]
#[test]
fn serve_sigint_while_connecting_to_redis_exits_interrupted() {
    signal_while_connecting_to_redis("INT", false);
}

/// The binary installs its handlers over an inherited `SIG_IGN`, as the
/// client does; see `docs/runtime.md`, "Stopping `connect` and `serve`".
#[cfg(unix)]
#[test]
fn serve_sigterm_inherited_as_ignored_still_stops_startup() {
    signal_while_connecting_to_redis("TERM", true);
}

/// Held later in startup: Redis answers (the fake), and the membership
/// bootstrap waits on a checkpoint authority that never answers.
#[cfg(unix)]
#[test]
fn serve_sigterm_during_the_membership_bootstrap_exits_interrupted() {
    let fixture = StartupFixture::new();
    initialize_state(&fixture, "rediss://127.0.0.1:1/0");
    let redis = FakeRedisTls::start(&fixture);
    let checkpoint = SilentPeer::start();
    let config = fixture.write_config(
        &redis.url(),
        &format!(
            "https://127.0.0.1:{}/v1/checkpoint",
            checkpoint.address.port()
        ),
        "relay-startup",
        None,
        true,
    );
    let (output, after_signal) = signal_serve_during_startup(&config, &checkpoint, "TERM", false);
    assert_interrupted_during_startup(&output, after_signal, "TERM");
    fixture.assert_bindings_available();
}

// ------------------------------------------------------------------------
// Stop requests during a finite writing command (M6-C23, after M6-C21).
//
// `activate-first-incarnation`, `provision-catalog`, `initialize`,
// `recovery-initialize` and `recover` write state that cannot be half-undone,
// so a first stop request lets the bounded command finish and report its own
// outcome, and a second abandons it with 130. Held here in the Redis TLS
// handshake of `activate-first-incarnation`, which is the same wrapper every
// one of those commands goes through.

/// Spawn `tunnel-relay <args>`, wait for `phase_peer` to witness the Redis
/// connection, send each signal in turn (100 ms apart), and return the
/// output and the time from the **last** signal to the exit.
fn signal_relay_command(
    args: &[&OsStr],
    phase_peer: &SilentPeer,
    signals: &[&str],
) -> (Output, Duration) {
    let mut child = Command::new(relay_binary())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tunnel-relay command");
    let started = Instant::now();
    while phase_peer.accepted.load(Ordering::Acquire) == 0 {
        if child.try_wait().expect("poll tunnel-relay").is_some() {
            let output = child.wait_with_output().expect("collect early exit");
            panic!(
                "the command exited before reaching the held phase: status={} stderr={}",
                output.status,
                String::from_utf8_lossy(&output.stderr)
            );
        }
        assert!(
            started.elapsed() <= SIGNAL_PHASE_BOUND,
            "the command did not reach the held phase within {SIGNAL_PHASE_BOUND:?}"
        );
        thread::sleep(Duration::from_millis(2));
    }
    let mut signalled = Instant::now();
    for signal in signals {
        thread::sleep(SIGNAL_AFTER_PHASE);
        assert!(
            child.try_wait().expect("poll tunnel-relay").is_none(),
            "the command exited before SIG{signal} was sent"
        );
        let status = Command::new("/bin/kill")
            .arg(format!("-{signal}"))
            .arg(child.id().to_string())
            .status()
            .expect("run kill");
        assert!(status.success(), "kill -{signal} failed: {status}");
        signalled = Instant::now();
    }
    loop {
        if child.try_wait().expect("poll tunnel-relay").is_some() {
            break;
        }
        if started.elapsed() > SIGNAL_RUN_BOUND {
            let _ = child.kill();
            let _ = child.wait();
            panic!("the command did not exit within {SIGNAL_RUN_BOUND:?}");
        }
        thread::sleep(Duration::from_millis(2));
    }
    let after_signal = signalled.elapsed();
    (
        child.wait_with_output().expect("collect command output"),
        after_signal,
    )
}

/// A first SIGTERM does not kill a writing command: it is acknowledged, the
/// command reaches its own outcome -- here the Redis connection's own
/// failure, because the peer never answers -- and that outcome sets the exit
/// status. With the handler defeated the process dies by the signal instead.
#[cfg(unix)]
#[test]
fn a_writing_command_finishes_and_reports_its_own_outcome_after_one_sigterm() {
    let fixture = StartupFixture::new();
    let redis = SilentPeer::start();
    let config = fixture.valid_config(&format!(
        "rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:{}/0",
        redis.address.port()
    ));
    let (output, _) = signal_relay_command(
        &[
            OsStr::new("activate-first-incarnation"),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
        &redis,
        &["TERM"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!("status={} stderr={stderr}", output.status);
    assert_eq!(
        output.status.code(),
        Some(1),
        "the command's own outcome (the Redis connection failing) must set the \
         status, not the signal: {context}"
    );
    assert!(
        stderr.contains(
            "tunnel-relay: SIGTERM received during activate-first-incarnation; letting it finish"
        ),
        "the stop request must be acknowledged: {context}"
    );
    assert!(
        stderr.contains("Redis catalog connection failed"),
        "the command's own outcome must still be reported: {context}"
    );
    assert!(!stderr.contains(DIAGNOSTIC_SECRET), "{context}");
}

/// A second stop request abandons the write at once, with 130 and a
/// diagnostic saying the outcome is unknown.
#[cfg(unix)]
#[test]
fn a_second_stop_request_abandons_a_writing_command() {
    let fixture = StartupFixture::new();
    let redis = SilentPeer::start();
    let config = fixture.valid_config(&format!(
        "rediss://{DIAGNOSTIC_SECRET}@127.0.0.1:{}/0",
        redis.address.port()
    ));
    let (output, after_signal) = signal_relay_command(
        &[
            OsStr::new("activate-first-incarnation"),
            OsStr::new("--config"),
            config.as_os_str(),
        ],
        &redis,
        &["TERM", "INT"],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    let context = format!(
        "status={} after_signal={after_signal:?} stderr={stderr}",
        output.status
    );
    assert_eq!(output.status.code(), Some(130), "{context}");
    assert!(
        stderr.contains(
            "tunnel-relay: SIGINT received while activate-first-incarnation was finishing after SIGTERM; exiting without waiting for it, so its outcome is unknown"
        ),
        "{context}"
    );
    assert!(
        after_signal <= SIGNAL_PROMPT_EXIT,
        "the second request must end the command promptly, not at the Redis timeout: {context}"
    );
}

struct FakeRedisTls {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<JoinHandle<()>>,
}

impl FakeRedisTls {
    fn start(fixture: &StartupFixture) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind fake Redis TLS listener");
        listener
            .set_nonblocking(true)
            .expect("make fake Redis TLS listener bounded");
        let address = listener.local_addr().expect("read fake Redis TLS address");
        let server_config = load_server_config_from_pem(
            &fs::read(&fixture.certificate_chain).expect("read fake Redis certificate"),
            &fs::read(&fixture.private_key).expect("read fake Redis private key"),
            None,
        )
        .expect("build fake Redis TLS server");
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let task = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("build fake Redis runtime");
            runtime.block_on(async move {
                let listener =
                    TokioTcpListener::from_std(listener).expect("adopt fake Redis listener");
                let acceptor = TlsAcceptor::from(server_config);
                let mut connections = JoinSet::new();
                loop {
                    if task_stop.load(Ordering::Acquire) {
                        break;
                    }
                    while connections.try_join_next().is_some() {}
                    tokio::select! {
                        _ = sleep(Duration::from_millis(10)) => {}
                        accepted = listener.accept() => {
                            let Ok((stream, _)) = accepted else { break };
                            // One base connection plus four authorization lanes;
                            // retain a small fixed fixture allowance for teardown.
                            if connections.len() >= 8 {
                                drop(stream);
                                continue;
                            }
                            let acceptor = acceptor.clone();
                            let connection_stop = Arc::clone(&task_stop);
                            connections.spawn(async move {
                                let Ok(mut tls) = acceptor.accept(stream).await else { return };
                                serve_fake_redis(&mut tls, &connection_stop).await;
                            });
                        }
                    }
                }
                connections.abort_all();
                while connections.join_next().await.is_some() {}
            });
        });
        Self {
            address,
            stop,
            task: Some(task),
        }
    }

    fn url(&self) -> String {
        format!("rediss://127.0.0.1:{}/0", self.address.port())
    }
}

impl Drop for FakeRedisTls {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            let _ = task.join();
        }
    }
}

async fn serve_fake_redis<S>(stream: &mut S, stop: &AtomicBool)
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    while !stop.load(Ordering::Acquire) {
        let Some(command) = read_resp_command(stream).await else {
            return;
        };
        let name = command
            .first()
            .map(|part| String::from_utf8_lossy(part).to_ascii_uppercase());
        let response = match name.as_deref() {
            Some("PING") => b"+PONG\r\n".to_vec(),
            Some("INFO") => {
                let body = format!("# Server\r\nrun_id:{REDIS_RUN_ID}\r\n\r\n");
                format!("${}\r\n{}\r\n", body.len(), body).into_bytes()
            }
            Some("EVAL") => b"*1\r\n$2\r\nok\r\n".to_vec(),
            _ => b"+OK\r\n".to_vec(),
        };
        if stream.write_all(&response).await.is_err() {
            return;
        }
    }
}

async fn read_resp_command<S>(stream: &mut S) -> Option<Vec<Vec<u8>>>
where
    S: AsyncRead + Unpin,
{
    let line = read_resp_line(stream).await?;
    let count = std::str::from_utf8(line.strip_prefix(b"*")?)
        .ok()?
        .parse::<usize>()
        .ok()?;
    if count == 0 || count > 64 {
        return None;
    }
    let mut command = Vec::with_capacity(count);
    for _ in 0..count {
        let length_line = read_resp_line(stream).await?;
        let length = std::str::from_utf8(length_line.strip_prefix(b"$")?)
            .ok()?
            .parse::<usize>()
            .ok()?;
        if length > 1024 * 1024 {
            return None;
        }
        let mut value = vec![0_u8; length];
        stream.read_exact(&mut value).await.ok()?;
        let mut terminator = [0_u8; 2];
        stream.read_exact(&mut terminator).await.ok()?;
        if terminator != *b"\r\n" {
            return None;
        }
        command.push(value);
    }
    Some(command)
}

async fn read_resp_line<S>(stream: &mut S) -> Option<Vec<u8>>
where
    S: AsyncRead + Unpin,
{
    let mut line = Vec::new();
    loop {
        let mut byte = [0_u8; 1];
        tokio::time::timeout(Duration::from_millis(250), stream.read_exact(&mut byte))
            .await
            .ok()?
            .ok()?;
        line.push(byte[0]);
        if line.ends_with(b"\r\n") {
            line.truncate(line.len() - 2);
            return Some(line);
        }
        if line.len() > 128 {
            return None;
        }
    }
}
