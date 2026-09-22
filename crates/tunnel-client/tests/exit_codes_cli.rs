//! Process-level coverage for the `tunnel-client` exit-code vocabulary.
//!
//! **Why this file exists.** `crates/tunnel-client/tests/doctor_cli.rs`
//! asserts exit statuses `0`, `2` and `3`, but every one of them comes from
//! `doctor.rs`, which computes its own exit code and returns from `main`
//! before the async command runner is reached. The mapping in
//! `Cause::exit_code` -- the one every *other* command uses -- had no
//! process-level assertion at all: nothing proved that a code chosen there
//! ever reached a caller's `$?`. A unit test on `exit_code()` cannot prove
//! that, because it never runs the binary.
//!
//! So these tests invoke the built binary and read the real exit status.
//! They also check the redaction boundary on the *error* path specifically:
//! an error surface prints internal state by construction, and a failure
//! report that named the relay host or the private-key path would leak
//! exactly the two things the configuration keeps private.

#![cfg(unix)]

use rcgen::{CertificateParams, KeyPair};
use serde_json::Value;
use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Command, Output},
};
use tempfile::{TempDir, tempdir};

/// A synthetic profile whose credentials are valid but whose relay is a
/// closed loopback port, so `connect` fails at the transport and nowhere
/// earlier.
struct DeadRelayFixture {
    _root: TempDir,
    config: PathBuf,
}

impl DeadRelayFixture {
    /// Port 1 is reserved and never listening, so the connection is refused
    /// immediately. This keeps the test bounded without a timeout: a refused
    /// connection is a transport failure, not a deadline.
    const DEAD_RELAY: &'static str = "wss://127.0.0.1:1/v1/tunnel/control";

    fn new() -> Self {
        let root = tempdir().expect("create exit-code fixture directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("make exit-code fixture directory private");

        let key_pair = KeyPair::generate().expect("generate exit-code fixture key");
        let mut params = CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2023, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let certificate = params
            .self_signed(&key_pair)
            .expect("self-sign exit-code fixture certificate");

        let certificate_path = root.path().join("client-cert.pem");
        let key_path = root.path().join("secret-credential-key.pem");
        let server_ca_path = root.path().join("server-ca.pem");
        fs::write(&certificate_path, certificate.pem()).expect("write fixture certificate");
        fs::write(&key_path, key_pair.serialize_pem()).expect("write fixture private key");
        fs::write(&server_ca_path, certificate.pem()).expect("write fixture server CA");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("make fixture private key private");

        let config = root.path().join("client.toml");
        fs::write(
            &config,
            format!(
                "device_id = \"exit-code-fixture\"\nrelay_url = \"{}\"\nclient_cert = {}\nprivate_key = {}\nserver_ca = {}\n",
                Self::DEAD_RELAY,
                toml_string(&certificate_path),
                toml_string(&key_path),
                toml_string(&server_ca_path),
            ),
        )
        .expect("write exit-code fixture configuration");

        Self {
            _root: root,
            config,
        }
    }
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

fn client_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-client"))
}

fn run(args: &[&str]) -> Output {
    Command::new(client_binary())
        .args(args)
        .output()
        .expect("run tunnel-client")
}

/// Parse the single JSON diagnostic a `--json` command emits on stdout.
fn diagnostic(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("expected a JSON diagnostic on stdout, got: {stdout}"));
    serde_json::from_str(line).expect("parse tunnel-client JSON diagnostic")
}

/// The error surface must not name the private-key file, any credential
/// body, or the relay endpoint. Asserted over the whole process output, not
/// only the parsed JSON, so a stray `eprintln!` cannot slip past it.
///
/// **What this covers, measured rather than assumed.** These are *absence*
/// assertions, and an absence assertion over a value the code could never
/// emit is green over an empty domain -- the M5-C11 defect. So this
/// fixture's error path was probed with both of the connector's redaction
/// layers defeated at once (`sanitize_error` returning its input, and
/// `ClientError::safe_message`'s generic transport arm appending `detail`).
/// The worst output it then produces is
/// `websocket handshake failed: IO error: Connection refused (os error 61)`
/// -- **no path, no certificate, no endpoint**. Every entry below is
/// therefore belt and braces on this path and none of them can redden here.
///
/// `assert_transport_message_is_bounded` is the assertion that *can* redden,
/// and it is what the redaction case in `scripts/m0-guard-exit-codes.py`
/// drives. This list stays because these tests will grow commands whose
/// error paths do handle paths and endpoints, and because it costs nothing
/// -- but it is not evidence, and nothing should count it as any.
fn assert_redacted(output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    for secret in [
        "secret-credential-key.pem",
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE",
        "client-cert.pem",
        "server-ca.pem",
        "127.0.0.1",
    ] {
        assert!(
            !stdout.contains(secret),
            "stdout leaked {secret:?}: {stdout}"
        );
        assert!(
            !stderr.contains(secret),
            "stderr leaked {secret:?}: {stderr}"
        );
    }
}

/// A transport diagnostic must be the bounded scope label and nothing else.
///
/// `runtime.md` requires an external error to carry only a stable safe code,
/// a short explanation, an identifier where available and a retry hint, and
/// forbids leaking raw TLS or backend errors through it. The connector
/// enforces that in **two independent places**: `sanitize_error` discards the
/// underlying error at construction, and `safe_message`'s generic transport
/// arm drops `detail` at display.
///
/// Defeating either one alone changes nothing observable -- measured, not
/// inferred: the first run of the guard suite defeated the display arm by
/// itself and this fixture stayed green. Both have to go before the OS error
/// reaches an operator, which is why the harness case applies both edits.
fn assert_transport_message_is_bounded(report: &Value) {
    let message = report["error"]["message"]
        .as_str()
        .expect("error message is a string");
    assert_eq!(
        message, "websocket handshake failed",
        "a transport diagnostic must be the bounded scope label alone; an \
         underlying OS, TLS or backend error must not reach the operator"
    );
}

#[test]
fn an_unknown_subcommand_exits_two_and_prints_usage() {
    let output = run(&["definitely-not-a-command"]);
    assert_eq!(output.status.code(), Some(2), "invalid invocation");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:"),
        "an invalid invocation must show the usage it violated: {stderr}"
    );
    assert_redacted(&output);
}

#[test]
fn an_unreadable_configuration_exits_two_through_the_cli_error_path() {
    let root = tempdir().expect("create missing-config directory");
    let missing = root.path().join("absent.toml");
    let output = run(&[
        "config",
        "check",
        "--config",
        missing.to_str().expect("utf-8 path"),
        "--json",
    ]);
    assert_eq!(output.status.code(), Some(2), "unreadable configuration");
    let report = diagnostic(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["ok"], Value::Bool(false));
    assert_eq!(report["error"]["code"], "CONFIG_ERROR");
    assert_eq!(report["error"]["retryable"], Value::Bool(false));
}

/// The load-bearing one: a status other than `0`/`2`/`3`, chosen by
/// `Cause::exit_code` and observed on a real process.
///
/// Before this change a refused connection and a panicked supervisor were
/// both exit `1`; `4` is now reachable and distinct, and this is the test
/// that would notice if `ExitCode::from` ever stopped carrying the value.
#[test]
fn a_refused_relay_connection_exits_four_and_names_the_transport() {
    let fixture = DeadRelayFixture::new();
    let output = run(&[
        "connect",
        "--config",
        fixture.config.to_str().expect("utf-8 path"),
        "--json",
    ]);
    assert_eq!(
        output.status.code(),
        Some(4),
        "a refused relay is a service-unavailable exit, not an internal one; \
         stdout: {} stderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    let report = diagnostic(&output);
    assert_eq!(report["command"], "connect");
    assert_eq!(report["ok"], Value::Bool(false));
    assert_eq!(report["error"]["code"], "TRANSPORT_ERROR");
    assert_eq!(
        report["error"]["retryable"],
        Value::Bool(true),
        "a refused connection is safe to retry once the relay returns"
    );
    assert_transport_message_is_bounded(&report);
    assert_redacted(&output);
}
