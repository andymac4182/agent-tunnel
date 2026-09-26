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
//! They also hold the redaction boundary on the *error* path, which is where
//! internal state is printed by construction -- but only where a violation is
//! reachable; see the note above `assert_transport_message_is_bounded` for
//! what was removed and why.

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

// **There is deliberately no `assert_redacted` here, and its absence is the
// point.**
//
// An earlier draft of this file swept the process output for the fixture's
// private-key filename, its PEM bodies and its relay endpoint. Every one of
// those assertions was green over an empty domain: the error path was probed
// with *both* of the connector's redaction layers defeated at once
// (`sanitize_error` returning its input, and `ClientError::safe_message`'s
// generic transport arm appending `detail`), and the worst output it can
// produce is
// `websocket handshake failed: IO error: Connection refused (os error 61)` --
// no path, no certificate, no endpoint. Nothing in this binary's failing
// `connect` path handles those values at all, so nothing could ever have put
// them there.
//
// They were kept for one round with a comment saying so. That was the wrong
// call, and it is worth naming: this same branch filed M5-C11 instance
// thirteen for a test that was green over an empty domain, and then added a
// fresh instance of exactly that shape one file over. A comment admitting a
// check cannot fail does not make it evidence, it makes it a check nobody
// will re-examine -- and a later reader counting "redaction assertions" finds
// six and stops. Deleted rather than annotated. When a command lands whose
// error path genuinely handles a path or an endpoint, the assertion belongs
// with that command, where defeating the redaction reddens it.
//
// `assert_transport_message_is_bounded` below is what remains, and it is the
// real thing: the redaction case in `scripts/m0-guard-exit-codes.py` names it
// as its required witness and the harness refuses the case if anything else
// reddens instead.

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
}

/// Demo-readiness defect D6: `connect --help` printed a one-line usage and
/// the global help to stderr and exited `2`. Every subcommand now treats
/// `--help`/`-h` as a request for help: the usage on stdout, exit `0`,
/// wherever the flag sits -- including after other flags, and when the
/// subcommand's own required arguments are absent.
#[test]
fn help_on_every_subcommand_exits_zero_and_prints_usage() {
    let invocations: &[&[&str]] = &[
        &["connect", "--help"],
        &["connect", "-h"],
        &[
            "connect",
            "--config",
            "profile.toml",
            "--no-reconnect",
            "--help",
        ],
        &["config", "--help"],
        &["config", "check", "--help"],
        &["doctor", "--help"],
        &["doctor", "--json", "-h"],
        &["credentials", "--help"],
        &["credentials", "create", "--help"],
        &["credentials", "import", "--config", "p.toml", "--help"],
        &["check-config", "--help"],
    ];
    for args in invocations {
        let output = run(args);
        assert_eq!(output.status.code(), Some(0), "{args:?} must exit 0");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("Usage:")
                && stdout.contains("connect --config PATH [--json] [--no-reconnect]"),
            "{args:?} must print the usage on stdout: {stdout}"
        );
    }
}

/// `--help` as the *value* of a PATH flag is a path, not a help request, so
/// the subcommand still runs (and here fails on the missing file, exit 2).
/// The one-line usage an invalid `connect` prints names every flag the
/// global usage names.
#[test]
fn help_as_a_path_value_is_not_a_help_request() {
    let output = run(&["config", "check", "--config", "--help"]);
    assert_eq!(
        output.status.code(),
        Some(2),
        "a missing config is still an error"
    );
    let output = run(&["connect", "--bogus"]);
    assert_eq!(output.status.code(), Some(2));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("usage: tunnel-client connect --config PATH [--json] [--no-reconnect]"),
        "the one-line usage must match the global usage: {stderr}"
    );
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
    // `--no-reconnect`: with the default policy a refused relay is retried
    // (M6-C23, `reconnect_cli.rs`); this test is about the status the first
    // failure selects.
    let output = run(&[
        "connect",
        "--config",
        fixture.config.to_str().expect("utf-8 path"),
        "--json",
        "--no-reconnect",
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
}
