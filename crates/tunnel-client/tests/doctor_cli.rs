//! Process-level coverage for the local-only `tunnel-client doctor` command.
//!
//! These tests invoke the built binary so they cover argument parsing, exit
//! status selection, JSON serialization, and the redaction boundary together.

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

/// The synthetic device the fixture certificate names in its role SAN, and
/// the profile's `device_id` (M6-C44).
const FIXTURE_DEVICE: &str = "3a3b3c3d-3e3f-4a3b-8c3d-3e3f3a3b3c3d";

struct Fixture {
    root: TempDir,
    config: PathBuf,
    key: PathBuf,
}

impl Fixture {
    fn valid() -> Self {
        let root = tempdir().expect("create doctor fixture directory");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
            .expect("make doctor fixture directory private");

        let key_pair = KeyPair::generate().expect("generate doctor fixture key");
        let mut params = CertificateParams::default();
        params.not_before = rcgen::date_time_ymd(2023, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        params.subject_alt_names = vec![rcgen::SanType::URI(
            format!("urn:agent-tunnel:device:{FIXTURE_DEVICE}")
                .try_into()
                .expect("device role URI SAN"),
        )];
        let certificate = params
            .self_signed(&key_pair)
            .expect("self-sign doctor fixture certificate");

        let certificate_path = root.path().join("client-cert.pem");
        let key_path = root.path().join("secret-credential-key.pem");
        let server_ca_path = root.path().join("server-ca.pem");
        fs::write(&certificate_path, certificate.pem()).expect("write doctor certificate");
        fs::write(&key_path, key_pair.serialize_pem()).expect("write doctor private key");
        fs::write(&server_ca_path, certificate.pem()).expect("write doctor server CA");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))
            .expect("make doctor private key private");

        let config = root.path().join("client.toml");
        let config_text = format!(
            "device_id = \"{FIXTURE_DEVICE}\"\nrelay_url = \"wss://relay.example.test/v1/tunnel/control\"\nclient_cert = {}\nprivate_key = {}\nserver_ca = {}\n",
            toml_string(&certificate_path),
            toml_string(&key_path),
            toml_string(&server_ca_path),
        );
        fs::write(&config, config_text).expect("write doctor configuration");

        Self {
            root,
            config,
            key: key_path,
        }
    }

    fn missing_key_config(&self) -> PathBuf {
        let config = self.root.path().join("missing-key.toml");
        let missing_key = self.root.path().join("secret-credential-key.pem");
        fs::remove_file(&self.key).expect("remove doctor private key");
        let config_text = format!(
            "device_id = \"doctor-cli-missing\"\nrelay_url = \"wss://relay.example.test/v1/tunnel/control\"\nclient_cert = {}\nprivate_key = {}\nserver_ca = {}\n",
            toml_string(&self.root.path().join("client-cert.pem")),
            toml_string(&missing_key),
            toml_string(&self.root.path().join("server-ca.pem")),
        );
        fs::write(&config, config_text).expect("write missing-key doctor configuration");
        config
    }
}

fn toml_string(path: &Path) -> String {
    serde_json::to_string(
        path.to_str()
            .expect("doctor fixture path should be valid UTF-8"),
    )
    .expect("quote doctor fixture path")
}

fn client_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-client"))
}

fn run_doctor(config: &Path) -> Output {
    Command::new(client_binary())
        .args(["doctor", "--config"])
        .arg(config)
        .arg("--json")
        .output()
        .expect("run tunnel-client doctor")
}

fn report(output: &Output) -> Value {
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.stderr.is_empty(),
        "JSON doctor output must keep diagnostics on stdout; stderr: {stderr}"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(
        stdout.lines().count(),
        1,
        "doctor --json must emit exactly one JSON object: {stdout}"
    );
    serde_json::from_str(stdout.trim()).expect("parse doctor JSON report")
}

fn assert_redacted(report: &Value, output: &Output) {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let rendered = report.to_string();
    for secret in [
        "secret-credential-key.pem",
        "relay.example.test",
        "BEGIN PRIVATE KEY",
        "BEGIN CERTIFICATE",
    ] {
        assert!(!stdout.contains(secret), "doctor output leaked {secret:?}");
        assert!(
            !rendered.contains(secret),
            "doctor report leaked {secret:?}"
        );
    }
}

/// A failing run still reports the host capability checks (M6-C07).
///
/// `supervisor_ipc` and `process_containment` describe the machine, not the
/// configuration, so a bad configuration or a missing credential is no reason
/// to withhold them -- and an unprovisioned machine, where every one of these
/// runs fails, is exactly the population that needs to read them. `result`
/// was `null` on every failing path until M6-C07; asserting the two fields
/// are populated, rather than merely that `result` is an object, is what
/// makes this fail if the discard is reintroduced one layer down.
fn assert_capabilities_reported(report: &Value) {
    assert!(
        report["result"].is_object(),
        "a failing doctor run must still report its checks: {report}"
    );
    assert_eq!(
        report["result"]["supervisor_ipc"]["code"],
        "SUPERVISOR_IPC_NOT_IMPLEMENTED"
    );
    let containment = report["result"]["process_containment"]["code"]
        .as_str()
        .unwrap_or_default();
    assert!(
        containment.starts_with("PROCESS_CONTAINMENT_"),
        "containment must be reported on a failing run, got {containment:?}"
    );
}

#[test]
fn doctor_binary_reports_private_fixture_success_and_pending_supervisor_ipc() {
    let fixture = Fixture::valid();
    let output = run_doctor(&fixture.config);
    assert_eq!(output.status.code(), Some(0));
    let report = report(&output);
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["command"], "doctor");
    assert!(report["ok"].as_bool().is_some_and(|ok| ok));
    assert_eq!(report["result"]["config"]["status"], "ok");
    assert_eq!(report["result"]["credential_key_match"]["status"], "ok");
    assert_eq!(report["result"]["permissions"]["status"], "ok");
    assert_eq!(report["result"]["expiry"]["status"], "ok");
    assert_eq!(report["result"]["device_identity"]["status"], "ok");
    assert_eq!(
        report["result"]["supervisor_ipc"]["status"],
        "not_implemented"
    );
    assert_redacted(&report, &output);
}

/// M6-C44, through the real binary: a profile whose `device_id` was edited
/// after `credentials import` to another device is refused by the relay on
/// every HELLO, so `doctor` must not report it healthy.  Before the fix this
/// exited `0` with `"ok":true`.
#[test]
fn doctor_binary_returns_exit_three_when_device_id_is_not_the_certificates_device() {
    let fixture = Fixture::valid();
    let text = fs::read_to_string(&fixture.config).expect("read doctor configuration");
    let edited = text.replacen(FIXTURE_DEVICE, "44444444-4444-4444-8444-444444444444", 1);
    assert_ne!(text, edited);
    fs::write(&fixture.config, edited).expect("edit doctor configuration");
    let output = run_doctor(&fixture.config);
    assert_eq!(output.status.code(), Some(3));
    let report = report(&output);
    assert!(!report["ok"].as_bool().unwrap_or(true));
    assert_eq!(report["error"]["code"], "CREDENTIAL_DEVICE_MISMATCH");
    assert_eq!(report["result"]["device_identity"]["status"], "failed");
    assert_eq!(
        report["result"]["device_identity"]["code"],
        "CREDENTIAL_DEVICE_MISMATCH"
    );
    assert_eq!(report["result"]["credential_key_match"]["status"], "ok");
    assert_capabilities_reported(&report);
    assert_redacted(&report, &output);
}

#[test]
fn doctor_binary_returns_exit_three_for_permissive_private_key() {
    let fixture = Fixture::valid();
    fs::set_permissions(&fixture.key, fs::Permissions::from_mode(0o644))
        .expect("make doctor private key permissive");
    let output = run_doctor(&fixture.config);
    assert_eq!(output.status.code(), Some(3));
    let report = report(&output);
    assert!(!report["ok"].as_bool().unwrap_or(true));
    assert_eq!(report["error"]["code"], "CREDENTIAL_PERMISSIONS");
    assert_capabilities_reported(&report);
    assert_eq!(report["result"]["config"]["status"], "ok");
    assert_redacted(&report, &output);
}

#[test]
fn doctor_binary_returns_exit_three_for_permissive_credential_directory() {
    let fixture = Fixture::valid();
    fs::set_permissions(fixture.root.path(), fs::Permissions::from_mode(0o755))
        .expect("make doctor credential directory permissive");
    let output = run_doctor(&fixture.config);
    assert_eq!(output.status.code(), Some(3));
    let report = report(&output);
    assert!(!report["ok"].as_bool().unwrap_or(true));
    assert_eq!(report["error"]["code"], "CREDENTIAL_PERMISSIONS");
    assert_capabilities_reported(&report);
    assert_eq!(report["result"]["config"]["status"], "ok");
    assert_redacted(&report, &output);
}

#[test]
fn doctor_binary_redacts_missing_credential_and_returns_exit_three() {
    let fixture = Fixture::valid();
    let config = fixture.missing_key_config();
    let output = run_doctor(&config);
    assert_eq!(output.status.code(), Some(3));
    let report = report(&output);
    assert!(!report["ok"].as_bool().unwrap_or(true));
    assert_eq!(report["error"]["code"], "CREDENTIAL_MISSING");
    assert_capabilities_reported(&report);
    assert_eq!(report["result"]["config"]["status"], "ok");
    assert_redacted(&report, &output);
}

#[test]
fn doctor_binary_rejects_invalid_configuration_with_exit_two() {
    let root = tempdir().expect("create invalid doctor fixture directory");
    let config = root.path().join("invalid.toml");
    fs::write(
        &config,
        "device_id = \"invalid fixture\"\nrelay_url = \"ws://relay.example.test/v1/tunnel/control\"\nprivate_key = \"secret-credential-key.pem\"\n",
    )
    .expect("write invalid doctor configuration");
    let output = run_doctor(&config);
    assert_eq!(output.status.code(), Some(2));
    let report = report(&output);
    assert!(!report["ok"].as_bool().unwrap_or(true));
    assert_eq!(report["error"]["code"], "INVALID_CONFIG");
    assert_capabilities_reported(&report);
    // The configuration failed and the credential checks were therefore not
    // attempted -- a distinction the report can now make, and which a null
    // result could not.
    assert_eq!(report["result"]["config"]["status"], "failed");
    assert_eq!(report["result"]["config"]["code"], "INVALID_CONFIG");
    assert_eq!(
        report["result"]["credential_key_match"]["status"],
        "not_run"
    );
    assert_eq!(report["result"]["permissions"]["status"], "not_run");
    assert_eq!(report["result"]["expiry"]["status"], "not_run");
    assert_eq!(report["result"]["device_identity"]["status"], "not_run");
    assert_redacted(&report, &output);
}
