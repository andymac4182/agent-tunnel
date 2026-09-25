//! Task row M6-06, the runtime operations gate, on the real binary.
//!
//! * **Local IPC authorization.** A running `connect` is the supervisor: it
//!   binds `supervisor.sock` beside the client key, owner-only, and answers
//!   `status` and `doctor`. These tests hold the socket's mode, the profile
//!   lock a second `connect` meets (`SUPERVISOR_RUNNING`, exit `7`), the
//!   refusal of a socket other users could reach (`IPC_UNAUTHORIZED`, exit
//!   `3`), the stale file a SIGKILLed supervisor leaves (`SUPERVISOR_ABSENT`,
//!   exit `8`, then replaced by the next `connect`), and the socket's removal
//!   on an orderly stop. The peer-UID check itself needs a second user, which
//!   a test process does not have; it is held below the process level by
//!   `supervisor_ipc`'s unit tests, which drive the real `peer_cred` path
//!   with the expected UID shifted.
//! * **Redacted status and doctor output.** A profile is planted with
//!   canaries wherever a secret or a payload could hide -- the credential
//!   directory's name, the relay endpoint's path, an echo export's device
//!   canary, a stdio MCP export's arguments and environment, a Streamable
//!   HTTP MCP export's URL and bearer token file, the client certificate's
//!   subject -- plus the private key's and certificate's PEM bodies, and
//!   every surface an operator reads (`status`, `doctor`, each with and
//!   without `--json`, and `connect`'s own stdout and stderr) must carry none
//!   of them. The supervisor holds every one of these values in memory, so
//!   the domain is not empty; `scripts/m0-guard-exit-codes.py` leaks two of
//!   them into the status snapshot in turn and requires this test to redden.
//! * **Deterministic exit codes.** Every subcommand's success and failure
//!   statuses, against `docs/runtime.md`'s table.
//!
//! No relay is involved: the profile's relay is a refused loopback port, so
//! the supervisor sits in its reconnect loop, alive and answering, for as
//! long as a test needs it.

#![cfg(unix)]

use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use serde_json::Value;
use std::{
    fs,
    io::Read,
    os::unix::fs::{FileTypeExt, PermissionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    time::{Duration, Instant},
};
use tempfile::{TempDir, tempdir};

const STEP: Duration = Duration::from_secs(15);
const DEVICE: &str = "4a4b4c4d-4e4f-4a4b-8c4d-4e4f4a4b4c4d";

fn client_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-client"))
}

fn toml_string(path: &Path) -> String {
    format!("\"{}\"", path.display().to_string().replace('\\', "\\\\"))
}

fn nonce() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .subsec_nanos();
    format!("{:08x}", nanos ^ std::process::id())
}

/// Every planted value that no operator surface may print.
struct Canaries {
    values: Vec<String>,
}

/// A synthetic profile whose relay is a refused loopback port.
struct Profile {
    _root: TempDir,
    dir: PathBuf,
    config: PathBuf,
    canaries: Canaries,
}

impl Profile {
    fn new() -> Self {
        let root = tempdir().expect("fixture root");
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).expect("chmod root");
        let tag = nonce();
        // The credential directory's own name is a canary: a status that
        // printed a path would print it.
        let dir = root.path().join(format!("cnry-dir-{tag}"));
        fs::create_dir(&dir).expect("credential directory");
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o700)).expect("chmod dir");

        let subject = format!("cnry-subject-{tag}");
        let key_pair = KeyPair::generate().expect("key");
        let mut params = CertificateParams::default();
        params.subject_alt_names = vec![
            rcgen::SanType::URI(
                format!("urn:agent-tunnel:device:{DEVICE}")
                    .try_into()
                    .expect("device role SAN"),
            ),
            rcgen::SanType::DnsName(format!("{subject}.invalid").try_into().expect("DNS SAN")),
        ];
        let mut name = DistinguishedName::new();
        name.push(DnType::CommonName, subject.clone());
        params.distinguished_name = name;
        params.not_before = rcgen::date_time_ymd(2023, 1, 1);
        params.not_after = rcgen::date_time_ymd(2035, 1, 1);
        let certificate = params.self_signed(&key_pair).expect("certificate");
        let certificate_pem = certificate.pem();
        let key_pem = key_pair.serialize_pem();

        let certificate_path = dir.join("client-cert.pem");
        let key_path = dir.join("client-key.pem");
        let server_ca_path = dir.join("server-ca.pem");
        fs::write(&certificate_path, &certificate_pem).expect("certificate");
        fs::write(&key_path, &key_pem).expect("key");
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).expect("chmod key");
        fs::write(&server_ca_path, &certificate_pem).expect("server CA");

        let token_path = dir.join("mcp-token");
        let token = format!("cnry-token-{tag}");
        fs::write(&token_path, &token).expect("token");
        fs::set_permissions(&token_path, fs::Permissions::from_mode(0o600)).expect("chmod token");
        let workspace = root.path().join("workspace");
        fs::create_dir(&workspace).expect("workspace");

        let endpoint = format!("cnry-endpoint-{tag}");
        let device_canary = format!("cnry-device-{tag}");
        let argument = format!("cnry-argument-{tag}");
        let environment = format!("cnry-environment-{tag}");
        let mcp_url = format!("cnry-mcp-url-{tag}");
        let config = dir.join("client.toml");
        fs::write(
            &config,
            format!(
                "device_id = \"{DEVICE}\"\n\
                 relay_url = \"wss://127.0.0.1:1/{endpoint}/control\"\n\
                 client_cert = {cert}\nprivate_key = {key}\nserver_ca = {ca}\n\n\
                 [reconnect]\ninitial_delay_ms = 200\nmax_delay_ms = 400\n\n\
                 [exports.echo]\ntype = \"echo\"\ndevice_canary = \"{device_canary}\"\n\n\
                 [exports.22222222-2222-4222-8222-222222222222]\ntype = \"http-forward\"\n\n\
                 [exports.22222222-2222-4222-8222-222222222222.mcp]\nprofile = \"mcp-2026-07-28\"\n\n\
                 [exports.22222222-2222-4222-8222-222222222222.mcp.backend]\nkind = \"stdio\"\n\
                 command = \"/usr/bin/true\"\nargs = [\"--token\", \"{argument}\"]\n\
                 workspace = {workspace}\nenv = {{ SYNTHETIC_SECRET = \"{environment}\" }}\n\n\
                 [exports.33333333-3333-4333-8333-333333333333]\ntype = \"http-forward\"\n\n\
                 [exports.33333333-3333-4333-8333-333333333333.mcp]\nprofile = \"mcp-2026-07-28\"\n\n\
                 [exports.33333333-3333-4333-8333-333333333333.mcp.backend]\n\
                 kind = \"streamable-http\"\nurl = \"http://127.0.0.1:9/{mcp_url}\"\n\
                 bearer_token_file = {token_file}\n",
                cert = toml_string(&certificate_path),
                key = toml_string(&key_path),
                ca = toml_string(&server_ca_path),
                workspace = toml_string(&workspace),
                token_file = toml_string(&token_path),
            ),
        )
        .expect("config");

        let mut values = vec![
            format!("cnry-dir-{tag}"),
            subject,
            token,
            endpoint,
            device_canary,
            argument,
            environment,
            mcp_url,
        ];
        // A distinctive interior line of each PEM body: key bytes and
        // certificate bytes must never be echoed either.
        for pem in [&key_pem, &certificate_pem] {
            let body = pem
                .lines()
                .filter(|line| !line.starts_with("-----"))
                .max_by_key(|line| line.len())
                .expect("PEM body");
            values.push(body.to_owned());
        }
        Self {
            _root: root,
            dir,
            config,
            canaries: Canaries { values },
        }
    }

    fn socket(&self) -> PathBuf {
        self.dir.join("supervisor.sock")
    }

    fn config_arg(&self) -> String {
        self.config.display().to_string()
    }
}

fn run(args: &[&str]) -> Output {
    Command::new(client_binary())
        .args(args)
        .output()
        .expect("run tunnel-client")
}

/// `run`, bounded: a command that should exit at once but does not is
/// killed and reported, instead of hanging the suite (a second supervisor
/// that failed to meet the profile lock would otherwise run forever).
fn run_bounded(args: &[&str]) -> Output {
    let mut child = Command::new(client_binary())
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn tunnel-client");
    let deadline = Instant::now() + STEP;
    while child.try_wait().expect("try_wait").is_none() {
        if Instant::now() >= deadline {
            let _ = child.kill();
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    child.wait_with_output().expect("collect output")
}

fn json(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    let line = stdout
        .lines()
        .last()
        .unwrap_or_else(|| panic!("expected JSON on stdout, got {stdout:?}"));
    serde_json::from_str(line).unwrap_or_else(|error| panic!("{error}: {line}"))
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

/// A running `connect`, stopped and reaped on drop.
struct Supervisor {
    child: Option<Child>,
}

impl Supervisor {
    fn start(profile: &Profile) -> Self {
        let child = Command::new(client_binary())
            .args(["connect", "--config", &profile.config_arg(), "--json"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn connect");
        let supervisor = Self { child: Some(child) };
        let deadline = Instant::now() + STEP;
        loop {
            if fs::symlink_metadata(profile.socket())
                .is_ok_and(|metadata| metadata.file_type().is_socket())
                && run(&["status", "--config", &profile.config_arg(), "--json"])
                    .status
                    .success()
            {
                return supervisor;
            }
            assert!(
                Instant::now() < deadline,
                "the supervisor never answered on its socket"
            );
            std::thread::sleep(Duration::from_millis(50));
        }
    }

    fn pid(&self) -> u32 {
        self.child.as_ref().expect("child").id()
    }

    fn signal(&self, signal: &str) {
        let status = Command::new("/bin/kill")
            .args([format!("-{signal}"), self.pid().to_string()])
            .status()
            .expect("kill");
        assert!(status.success());
    }

    /// Wait for the exit and return (status, stdout + stderr).
    fn wait(mut self) -> (std::process::ExitStatus, String) {
        let mut child = self.child.take().expect("child");
        let deadline = Instant::now() + STEP;
        let status = loop {
            if let Some(status) = child.try_wait().expect("try_wait") {
                break status;
            }
            assert!(Instant::now() < deadline, "connect did not exit");
            std::thread::sleep(Duration::from_millis(20));
        };
        let mut output = String::new();
        if let Some(mut stdout) = child.stdout.take() {
            let _ = stdout.read_to_string(&mut output);
        }
        if let Some(mut stderr) = child.stderr.take() {
            let _ = stderr.read_to_string(&mut output);
        }
        (status, output)
    }
}

impl Drop for Supervisor {
    fn drop(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

fn assert_no_canary(canaries: &Canaries, surface: &str, output: &str) {
    for canary in &canaries.values {
        assert!(
            !output.contains(canary.as_str()),
            "{surface} printed a planted canary ({canary}):\n{output}"
        );
    }
}

#[test]
fn status_without_a_supervisor_exits_eight_and_says_so() {
    let profile = Profile::new();
    let output = run(&["status", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(output.status.code(), Some(8), "{}", text(&output));
    let report = json(&output);
    assert_eq!(report["command"], "status");
    assert_eq!(report["ok"], false);
    assert_eq!(report["error"]["code"], "SUPERVISOR_ABSENT");
    let human = run(&["status", "--config", &profile.config_arg()]);
    assert_eq!(human.status.code(), Some(8));
    assert!(
        text(&human).contains("no supervisor is running"),
        "{}",
        text(&human)
    );
}

#[test]
fn a_live_supervisor_answers_status_and_doctor_and_holds_the_profile() {
    let profile = Profile::new();
    let supervisor = Supervisor::start(&profile);

    let mode = fs::symlink_metadata(profile.socket())
        .expect("socket")
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "the supervisor socket must be owner-only");

    let output = run(&["status", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    let report = json(&output);
    assert_eq!(report["command"], "status");
    let result = &report["result"];
    assert_eq!(result["pid"], supervisor.pid());
    assert_eq!(result["device_id"], DEVICE);
    assert!(
        matches!(result["state"].as_str(), Some("connecting" | "backoff")),
        "{result}"
    );
    assert_eq!(result["rotation_policy"]["interval_seconds"], 300);
    let exports: Vec<&str> = result["exports"]
        .as_array()
        .expect("exports")
        .iter()
        .filter_map(|export| export["name"].as_str())
        .collect();
    assert_eq!(
        exports,
        [
            "22222222-2222-4222-8222-222222222222",
            "33333333-3333-4333-8333-333333333333",
            "echo"
        ]
    );
    assert!(result["ipc"]["requests_served"].as_u64() >= Some(1));

    let doctor = run(&["doctor", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(doctor.status.code(), Some(0), "{}", text(&doctor));
    let doctor = json(&doctor);
    assert_eq!(doctor["result"]["supervisor_ipc"]["status"], "ok");
    assert_eq!(
        doctor["result"]["supervisor_ipc"]["code"],
        "SUPERVISOR_IPC_OK"
    );

    // The bind is the profile lock: a second supervisor is refused before it
    // reaches a relay, and the first keeps answering.
    let second = run_bounded(&["connect", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(second.status.code(), Some(7), "{}", text(&second));
    assert_eq!(json(&second)["error"]["code"], "SUPERVISOR_RUNNING");
    assert!(
        run(&["status", "--config", &profile.config_arg()])
            .status
            .success(),
        "the refused second connect must not disturb the first supervisor"
    );

    // An orderly stop (in the reconnect wait: exit 130) removes the socket.
    supervisor.signal("TERM");
    let (status, _) = supervisor.wait();
    assert_eq!(status.code(), Some(130));
    assert!(
        !profile.socket().exists(),
        "an orderly stop must remove the supervisor socket"
    );
    let after = run(&["status", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(after.status.code(), Some(8));
}

#[test]
fn a_socket_other_users_could_reach_is_refused() {
    let profile = Profile::new();
    let _supervisor = Supervisor::start(&profile);
    fs::set_permissions(profile.socket(), fs::Permissions::from_mode(0o666)).expect("chmod");
    let output = run(&["status", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(output.status.code(), Some(3), "{}", text(&output));
    assert_eq!(json(&output)["error"]["code"], "IPC_UNAUTHORIZED");
    // `doctor` reports it and still judges only the credential checks.
    let doctor = run(&["doctor", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(doctor.status.code(), Some(0), "{}", text(&doctor));
    let doctor = json(&doctor);
    assert_eq!(doctor["result"]["supervisor_ipc"]["status"], "failed");
    assert_eq!(
        doctor["result"]["supervisor_ipc"]["code"],
        "IPC_UNAUTHORIZED"
    );
}

#[test]
fn a_killed_supervisors_stale_socket_is_absent_and_then_replaced() {
    let profile = Profile::new();
    let supervisor = Supervisor::start(&profile);
    supervisor.signal("KILL");
    let (status, _) = supervisor.wait();
    assert_eq!(status.code(), None, "SIGKILL leaves no exit status");
    assert!(
        fs::symlink_metadata(profile.socket()).is_ok(),
        "a killed supervisor cannot remove its socket"
    );
    let output = run(&["status", "--config", &profile.config_arg(), "--json"]);
    assert_eq!(output.status.code(), Some(8), "{}", text(&output));
    assert_eq!(json(&output)["error"]["code"], "SUPERVISOR_ABSENT");
    // The next supervisor takes the profile over the stale file.
    let next = Supervisor::start(&profile);
    next.signal("TERM");
    let (status, _) = next.wait();
    assert_eq!(status.code(), Some(130));
}

#[test]
fn status_and_doctor_never_print_a_planted_canary() {
    let profile = Profile::new();
    let supervisor = Supervisor::start(&profile);
    let mut surfaces = Vec::new();
    for args in [
        vec![
            "status",
            "--config",
            profile.config.to_str().unwrap(),
            "--json",
        ],
        vec!["status", "--config", profile.config.to_str().unwrap()],
        vec![
            "doctor",
            "--config",
            profile.config.to_str().unwrap(),
            "--json",
        ],
        vec!["doctor", "--config", profile.config.to_str().unwrap()],
    ] {
        let output = run(&args);
        assert!(output.status.success(), "{args:?}: {}", text(&output));
        surfaces.push((args.join(" "), text(&output)));
    }
    // Not vacuous: the surfaces said something, including the fields a
    // careless snapshot would have copied the canaries alongside.
    let status_json = &surfaces[0].1;
    let device = format!("\"device_id\":\"{DEVICE}\"");
    for expected in [device.as_str(), "\"exports\"", "\"kind\":\"echo\""] {
        assert!(status_json.contains(expected), "{expected}: {status_json}");
    }
    supervisor.signal("TERM");
    let (_, connect_output) = supervisor.wait();
    surfaces.push(("connect --json".to_owned(), connect_output));
    for (surface, output) in &surfaces {
        assert_no_canary(&profile.canaries, surface, output);
    }
}

#[test]
fn every_subcommand_exits_by_the_published_table() {
    let profile = Profile::new();
    let config = profile.config_arg();
    let missing = profile.dir.join("absent.toml").display().to_string();
    let cases: Vec<(Vec<&str>, i32)> = vec![
        (vec![], 0),
        (vec!["--help"], 0),
        (vec!["--version"], 0),
        (vec!["no-such-command"], 2),
        (vec!["check-config"], 0),
        (vec!["check-config", &missing], 2),
        (vec!["check-config", "a", "b"], 2),
        (vec!["config", "check", "--config", &config], 0),
        (vec!["config", "check", "--config", &missing], 2),
        (vec!["config", "check"], 2),
        (vec!["config", "frobnicate"], 2),
        (vec!["credentials"], 2),
        (vec!["credentials", "create", "--config", &config], 2),
        // The key already exists: never overwritten.
        (
            vec![
                "credentials",
                "create",
                "--config",
                &config,
                "--csr-out",
                "x.csr",
            ],
            3,
        ),
        (vec!["credentials", "import", "--config", &config], 2),
        (vec!["doctor", "--config", &config], 0),
        (vec!["doctor", "--config", &missing], 2),
        (vec!["doctor", "--config", &config, "--network"], 2),
        (vec!["status"], 2),
        (vec!["status", "--config", &missing], 2),
        (vec!["status", "--config", &config], 8),
        (vec!["status", "--config", &config, "--network"], 2),
        (vec!["connect"], 2),
        (vec!["connect", "--config", &missing], 2),
    ];
    for (args, expected) in cases {
        let output = run(&args);
        assert_eq!(
            output.status.code(),
            Some(expected),
            "tunnel-client {args:?}: {}",
            text(&output)
        );
    }
}
