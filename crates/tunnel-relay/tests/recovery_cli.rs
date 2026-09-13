//! Binary-level coverage for the operator recovery commands.
//!
//! These tests deliberately keep Redis out of the create-only and fail-closed
//! cases. The observation case uses one loopback listener as a deterministic
//! connection fixture and places malformed control files at both paths; a
//! recovery fence or trusted-key read would therefore produce a different
//! error before the expected Redis connection failure.

use std::{
    ffi::OsStr,
    fs, io,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Command, Output},
    sync::atomic::{AtomicU64, Ordering},
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

static NEXT_FIXTURE: AtomicU64 = AtomicU64::new(0);

struct CliFixture {
    root: PathBuf,
}

impl CliFixture {
    fn new() -> Self {
        let base = std::env::temp_dir();
        let serial = NEXT_FIXTURE.fetch_add(1, Ordering::Relaxed);
        let mut root = base.join(format!(
            "agent-tunnel-recovery-cli-{}-{serial}",
            std::process::id()
        ));
        for attempt in 0..32 {
            match fs::create_dir(&root) {
                Ok(()) => break,
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    root = base.join(format!(
                        "agent-tunnel-recovery-cli-{}-{serial}-{attempt}",
                        std::process::id()
                    ));
                }
                Err(error) => panic!("create recovery CLI fixture directory: {error}"),
            }
            assert!(
                attempt < 31,
                "could not allocate recovery CLI fixture directory"
            );
        }
        let root = fs::canonicalize(root).expect("canonicalize recovery CLI fixture directory");
        set_mode(&root, 0o700);
        Self { root }
    }

    fn path(&self, name: &str) -> PathBuf {
        self.root.join(name)
    }

    fn write(&self, name: &str, contents: &[u8]) -> PathBuf {
        let path = self.path(name);
        fs::write(&path, contents).expect("write recovery CLI fixture file");
        set_mode(&path, 0o600);
        path
    }

    fn config(&self, redis_url: &str) -> PathBuf {
        let config = format!(
            r#"consumer_bind = "127.0.0.1:0"
device_bind = "127.0.0.1:0"
oidc_issuer = "https://issuer.recovery-cli.invalid/"
oidc_audience = ["agent-tunnel"]
oidc_jwks_path = {oidc_jwks}
redis_url = {redis_url}
redis_namespace = "recovery-cli-test"
deployment_incarnation = "recovery-cli-initial"
device_tls_cert_chain = {device_cert}
device_tls_private_key = {device_key}
device_tls_client_ca = {device_ca}
consumer_tls_cert_chain = {consumer_cert}
consumer_tls_private_key = {consumer_key}
node_id = "recovery-cli-relay"

[cluster]
deployment_id = "recovery-cli-deployment"
peer_bind = "127.0.0.1:8443"
peer_tls_cert_chain = {peer_cert}
peer_tls_private_key = {peer_key}
peer_tls_client_ca = {peer_ca}
membership_signer_trust_path = {membership_trust}
checkpoint_authority_endpoint = "https://checkpoint.recovery-cli.invalid:443/v1/checkpoint"
checkpoint_authority_trust_path = {checkpoint_trust}
membership_version_state_path = {membership_state}

[cluster.endpoint_policy]
allowed_ports = [8443]
require_private_ip = true

[recovery]
fence_path = {fence}
trusted_keys_path = {trusted_keys}
"#,
            oidc_jwks = quote_path(&self.path("oidc-jwks.json")),
            redis_url = quote(redis_url),
            device_cert = quote_path(&self.path("device-cert.pem")),
            device_key = quote_path(&self.path("device-key.pem")),
            device_ca = quote_path(&self.path("device-ca.pem")),
            consumer_cert = quote_path(&self.path("consumer-cert.pem")),
            consumer_key = quote_path(&self.path("consumer-key.pem")),
            peer_cert = quote_path(&self.path("peer-cert.pem")),
            peer_key = quote_path(&self.path("peer-key.pem")),
            peer_ca = quote_path(&self.path("peer-ca.pem")),
            membership_trust = quote_path(&self.path("membership-trust.pem")),
            checkpoint_trust = quote_path(&self.path("checkpoint-ca.pem")),
            membership_state = quote_path(&self.path("membership-state.json")),
            fence = quote_path(&self.path("recovery-fence.json")),
            trusted_keys = quote_path(&self.path("trusted-keys.json")),
        );
        self.write("relay.toml", config.as_bytes())
    }
}

impl Drop for CliFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

fn quote(value: &str) -> String {
    serde_json::to_string(value).expect("quote synthetic TOML string")
}

fn quote_path(path: &Path) -> String {
    quote(
        path.to_str()
            .expect("recovery CLI fixture path is valid UTF-8"),
    )
}

fn set_mode(path: &Path, mode: u32) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode))
            .expect("set recovery CLI fixture permissions");
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
}

fn relay_binary() -> std::ffi::OsString {
    std::env::var_os("CARGO_BIN_EXE_tunnel-relay")
        .expect("Cargo must provide the tunnel-relay binary for CLI tests")
}

fn run_cli<I, S>(args: I) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(relay_binary())
        .args(args)
        .output()
        .expect("run tunnel-relay recovery CLI")
}

fn assert_failure(output: &Output, expected: &str) {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "CLI unexpectedly succeeded; stderr: {stderr}"
    );
    assert!(
        stderr.contains(expected),
        "CLI stderr did not contain {expected:?}: {stderr}"
    );
}

fn loopback_connection_fixture() -> (String, JoinHandle<()>) {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback recovery fixture");
    let port = listener
        .local_addr()
        .expect("read loopback recovery fixture address")
        .port();
    listener
        .set_nonblocking(true)
        .expect("make loopback recovery fixture bounded");
    let task = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            match listener.accept() {
                Ok(_) => break,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        break;
                    }
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });
    (format!("rediss://127.0.0.1:{port}/0"), task)
}

#[test]
fn recovery_cli_rejects_unknown_duplicate_and_missing_arguments() {
    assert_failure(
        &run_cli(["recovery-observe", "--unknown"]),
        "unknown recovery argument: --unknown",
    );
    assert_failure(
        &run_cli([
            "recovery-observe",
            "--config",
            "first.toml",
            "--config",
            "second.toml",
        ]),
        "duplicate --config argument",
    );
    assert_failure(
        &run_cli(["recovery-observe"]),
        "recovery commands require --config PATH",
    );
    assert_failure(
        &run_cli(["recover", "--config", "recovery.toml"]),
        "recover requires --approval, --expected-nonce, --acknowledgement-id, --old-primary-fenced, and --old-relays-fenced",
    );
    assert_failure(
        &run_cli(["recovery-observe", "--config"]),
        "--config requires a value",
    );
}

#[test]
fn recovery_initialize_is_create_only() {
    let fixture = CliFixture::new();
    let config = fixture.config("rediss://redis.recovery-cli.invalid:6379/0");
    let fence = fixture.path("recovery-fence.json");

    let first = run_cli([
        OsStr::new("recovery-initialize"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert!(
        first.status.success(),
        "recovery-initialize failed: {}",
        String::from_utf8_lossy(&first.stderr)
    );
    let initial = fs::read(&fence).expect("initialize creates recovery fence");
    assert!(String::from_utf8_lossy(&initial).contains("recovery-cli-deployment"));

    let second = run_cli([
        OsStr::new("recovery-initialize"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    assert_failure(&second, "recovery approval fence already exists");
    assert_eq!(
        fs::read(&fence).expect("create-only retry leaves fence"),
        initial
    );
}

#[test]
fn recover_missing_fence_fails_closed_before_reading_approval_or_redis() {
    let fixture = CliFixture::new();
    let config = fixture.config("rediss://redis.recovery-cli.invalid:6379/0");
    fixture.write("approval.json", b"synthetic approval bytes");
    fixture.write("trusted-keys.json", b"synthetic trusted key bytes");

    let output = run_cli([
        OsStr::new("recover"),
        OsStr::new("--config"),
        config.as_os_str(),
        OsStr::new("--approval"),
        fixture.path("approval.json").as_os_str(),
        OsStr::new("--expected-nonce"),
        OsStr::new("recovery-cli-nonce"),
        OsStr::new("--acknowledgement-id"),
        OsStr::new("recovery-cli-ack"),
        OsStr::new("--old-primary-fenced"),
        OsStr::new("--old-relays-fenced"),
    ]);
    assert_failure(&output, "recovery approval fence is missing");
    assert!(!fixture.path("recovery-fence.json").exists());
}

#[test]
fn recovery_observe_does_not_read_recovery_fence_or_trusted_keys() {
    let fixture = CliFixture::new();
    let (redis_url, listener_task) = loopback_connection_fixture();
    let config = fixture.config(&redis_url);
    fixture.write("recovery-fence.json", b"malformed fence bytes");
    fixture.write("trusted-keys.json", b"malformed trusted key bytes");

    let output = run_cli([
        OsStr::new("recovery-observe"),
        OsStr::new("--config"),
        config.as_os_str(),
    ]);
    listener_task
        .join()
        .expect("join loopback recovery fixture");

    assert_failure(&output, "recovery Redis connection failed");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!stderr.contains("recovery fence is corrupt"), "{stderr}");
    assert!(
        !stderr.contains("trusted recovery key document"),
        "{stderr}"
    );
}
