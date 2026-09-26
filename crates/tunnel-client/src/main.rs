use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::SystemTime,
};

mod doctor;

use serde::Serialize;
use tokio_util::sync::CancellationToken;
use tunnel_client::{
    ClientError, ConnectConfig, ConnectOptions, M1_TRANSPORT_FAILURE_POLICY,
    credentials::{create_csr, import_certificate},
};
use tunnel_core::ClientConfig;

const DIAGNOSTICS_SCHEMA_VERSION: u8 = 1;

#[derive(Debug)]
enum Command {
    Help,
    Version,
    LegacyCheckConfig(Option<PathBuf>),
    CheckRuntimeConfig {
        path: PathBuf,
        json: bool,
    },
    Connect {
        path: PathBuf,
        json: bool,
        no_reconnect: bool,
    },
    CreateCredentials {
        config: PathBuf,
        csr_out: PathBuf,
    },
    ImportCredentials {
        config: PathBuf,
        certificate: PathBuf,
        server_ca: PathBuf,
    },
    Doctor {
        path: PathBuf,
        json: bool,
    },
    Status {
        path: PathBuf,
        json: bool,
    },
}

/// Every terminal cause `tunnel-client` can report, as a closed set.
///
/// **This type exists because a string table could not be checked.** The
/// previous mapping matched `&'static str` with a `_ => 1` arm, so a cause
/// whose code was absent from the table silently became exit `1`,
/// "unexpected internal failure". Eight distinct causes were landing there,
/// including the two an operator is most likely to meet: another connector
/// already owns the device (`OWNER_BUSY`), and an interrupted session
/// (`CANCELLED`). Each needs a different action, and the exit code — the
/// only thing a supervisor, a script or a tester reads before anything
/// else — said the same thing about all of them.
///
/// Both `code` and `exit_code` below match this enum exhaustively and have
/// **no fallback arm**, and `from_client` matches `ClientError` exhaustively
/// for the same reason. A new failure cause therefore cannot compile until
/// someone states which operator action it implies. That is the whole point:
/// the old table's defect was not a wrong entry, it was that nothing could
/// ever report a missing one.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Cause {
    InvalidInvocation,
    ConfigError,
    InvalidConfig,
    CredentialError,
    AuthorizationStale,
    TransportError,
    SessionClosed,
    DeadlineExceeded,
    OwnerBusy,
    ResourceExhausted,
    Cancelled,
    ProtocolError,
    SupervisorFailed,
    SignalError,
    /// `status`: no supervisor is listening for this profile (M6-06).
    SupervisorAbsent,
    /// `connect`: another supervisor already holds this profile (M6-06).
    SupervisorRunning,
    /// `connect`: the profile lock could not be taken for another reason
    /// (M6-06 review); the supervisor fails closed.
    SupervisorLockFailed,
    /// The local supervisor IPC failed its same-user check (M6-06).
    IpcUnauthorized,
}

impl Cause {
    /// The stable diagnostic code published in `--json` output.
    ///
    /// These strings are the external vocabulary and are matched by
    /// operators and scripts; they are not free to drift.
    fn code(self) -> &'static str {
        match self {
            Self::InvalidInvocation => "INVALID_INVOCATION",
            Self::ConfigError => "CONFIG_ERROR",
            Self::InvalidConfig => "INVALID_CONFIG",
            Self::CredentialError => "CREDENTIAL_ERROR",
            Self::AuthorizationStale => "AUTHORIZATION_STALE",
            Self::TransportError => "TRANSPORT_ERROR",
            Self::SessionClosed => "SESSION_CLOSED",
            Self::DeadlineExceeded => "DEADLINE_EXCEEDED",
            Self::OwnerBusy => "OWNER_BUSY",
            Self::ResourceExhausted => "RESOURCE_EXHAUSTED",
            Self::Cancelled => "CANCELLED",
            Self::ProtocolError => "PROTOCOL_ERROR",
            Self::SupervisorFailed => "SUPERVISOR_FAILED",
            Self::SignalError => "SIGNAL_ERROR",
            Self::SupervisorAbsent => "SUPERVISOR_ABSENT",
            Self::SupervisorRunning => "SUPERVISOR_RUNNING",
            Self::SupervisorLockFailed => "SUPERVISOR_LOCK_FAILED",
            Self::IpcUnauthorized => "IPC_UNAUTHORIZED",
        }
    }

    /// The stable process exit code, per the table in `docs/runtime.md`.
    ///
    /// Causes share a code only when they imply the *same* operator action.
    /// Where they imply different actions they are kept apart even though
    /// that costs a table entry:
    ///
    /// * `2` — the invocation or the configuration document is wrong; fix
    ///   local input. Nothing was attempted.
    /// * `3` — the credential or the authorization behind it was refused.
    ///   Nothing else: a retry cannot help, and the fix is to re-enroll or
    ///   re-authorize.
    /// * `4` — the relay or the network could not be reached, or closed the
    ///   session. A retry is meaningful once reachability returns.
    ///   `AUTHORIZATION_STALE` belongs here and not at `3` (M6-C39, owner
    ///   decision 2026-09-25): it is produced only when a stream's
    ///   operation-authorization window lapsed before its queued frame was
    ///   written, so the session was failed and restarted. Nothing about the
    ///   credential or grant was refused; the likeliest cause is a stalled or
    ///   congested data path, and the reconnect loop already retries it.
    /// * `5` — a bounded deadline elapsed.
    /// * `7` — the work was **refused before dispatch**: the device owner
    ///   slot is already held, or a bounded local budget was exhausted. No
    ///   session work started, so a later retry is safe. This is separated
    ///   from `4` because nothing is wrong with the network and from `1`
    ///   because nothing is wrong with the build: the operator's action is
    ///   to stop the other connector, or to wait.
    /// * `130` — interrupted before an orderly completion could be
    ///   recorded: a stop request (SIGINT or SIGTERM) that arrived before
    ///   the session was ready, a second one that abandoned the drain, or
    ///   an orderly stop whose join overran its bound.
    ///   A stop request while the session is live drains and exits `0`
    ///   with a `stopped` event instead (M6-C23, M6-C27).
    /// * `8` — `status` found no supervisor running for the profile (M6-06).
    ///   Not a failure of anything: nothing is running. Kept apart from `4`
    ///   because the action is to start `connect`, not to check a network.
    ///   A supervisor socket, lock or peer that fails the same-user check is
    ///   `3` (`IPC_UNAUTHORIZED`, authorization denied).
    /// * `9` — `connect` did not start because it cannot hold the profile
    ///   lock: another supervisor holds it (`SUPERVISOR_RUNNING`), or it
    ///   could not be taken (`SUPERVISOR_LOCK_FAILED`). Its own status, and
    ///   not `7`, since the M6-06 review: `7` is restarted by the example
    ///   service unit (a relay's stale `OWNER_BUSY` heals by waiting), while
    ///   a second supervisor never heals by restarting, so the unit lists `9`
    ///   in `RestartPreventExitStatus`.
    /// * `1` — genuinely unexpected: a protocol violation, a failed
    ///   supervisor, or a signal subsystem error. After this change `1`
    ///   means what it says.
    ///
    /// Exit `6` (`OUTCOME_UNKNOWN`) stays documented in `docs/runtime.md`
    /// and is deliberately **absent** here: no path in this binary can
    /// currently produce it. A variant nothing constructs would be a
    /// surface that looks covered and is not, so the gap is named in the
    /// documentation instead of being faked in the type.
    fn exit_code(self) -> u8 {
        match self {
            Self::InvalidInvocation | Self::ConfigError | Self::InvalidConfig => 2,
            Self::CredentialError | Self::IpcUnauthorized => 3,
            Self::TransportError | Self::SessionClosed | Self::AuthorizationStale => 4,
            Self::DeadlineExceeded => 5,
            Self::OwnerBusy | Self::ResourceExhausted => 7,
            Self::SupervisorRunning | Self::SupervisorLockFailed => 9,
            Self::SupervisorAbsent => 8,
            Self::Cancelled => 130,
            Self::ProtocolError | Self::SupervisorFailed | Self::SignalError => 1,
        }
    }

    /// Classify a connector error. Exhaustive over `ClientError` on purpose:
    /// a new variant there must be classified here or the binary does not
    /// build.
    fn from_client(error: &ClientError) -> Self {
        match error {
            ClientError::Config(_) => Self::InvalidConfig,
            ClientError::Credential(_) => Self::CredentialError,
            ClientError::Invalid(_) => Self::InvalidInvocation,
            ClientError::Protocol(_) => Self::ProtocolError,
            ClientError::Transport { .. } => Self::TransportError,
            ClientError::OwnerBusy => Self::OwnerBusy,
            ClientError::TlsRefused(_) => Self::CredentialError,
            ClientError::HandshakeTimeout => Self::DeadlineExceeded,
            ClientError::AuthorizationExpired => Self::AuthorizationStale,
            ClientError::QueueLimit | ClientError::OpenRetentionFull => Self::ResourceExhausted,
            ClientError::Cancelled => Self::Cancelled,
            ClientError::SupervisorPanicked => Self::SupervisorFailed,
        }
    }
}

impl Cause {
    /// Classify a supervisor IPC failure (M6-06). Exhaustive, no fallback.
    fn from_ipc(error: tunnel_client::supervisor_ipc::IpcError) -> Self {
        use tunnel_client::supervisor_ipc::IpcError;
        match error {
            IpcError::Absent => Self::SupervisorAbsent,
            IpcError::Busy => Self::SupervisorRunning,
            IpcError::Unauthorized(_) => Self::IpcUnauthorized,
            IpcError::PathTooLong => Self::ConfigError,
            IpcError::Timeout => Self::DeadlineExceeded,
            IpcError::Malformed => Self::ProtocolError,
            IpcError::Io(_) => Self::TransportError,
            IpcError::LockFailed(_) => Self::SupervisorLockFailed,
            IpcError::Unsupported => Self::InvalidInvocation,
        }
    }
}

#[derive(Debug)]
struct CliError {
    cause: Cause,
    message: String,
    retryable: bool,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            cause: Cause::InvalidInvocation,
            message: message.into(),
            retryable: false,
        }
    }

    fn from_client(error: ClientError) -> Self {
        Self {
            cause: Cause::from_client(&error),
            message: error.to_string(),
            retryable: error.retryable(),
        }
    }

    fn from_ipc(error: tunnel_client::supervisor_ipc::IpcError) -> Self {
        Self {
            cause: Cause::from_ipc(error),
            message: error.to_string(),
            retryable: matches!(
                error,
                tunnel_client::supervisor_ipc::IpcError::Absent
                    | tunnel_client::supervisor_ipc::IpcError::Timeout
            ),
        }
    }

    fn code(&self) -> &'static str {
        self.cause.code()
    }

    fn exit_code(&self) -> u8 {
        self.cause.exit_code()
    }
}

#[derive(Serialize)]
struct Diagnostic<'a, T: Serialize> {
    schema_version: u8,
    command: &'a str,
    ok: bool,
    result: Option<T>,
    error: Option<DiagnosticError<'a>>,
}

#[derive(Serialize)]
struct DiagnosticError<'a> {
    code: &'a str,
    message: &'a str,
    retryable: bool,
}

#[derive(Serialize)]
struct ConnectResult<'a> {
    state: &'a str,
    session_id: Option<&'a str>,
    epoch: Option<u64>,
    generation: Option<u64>,
    failure_policy: &'a str,
    /// Which stop request ended the session, on the `stopped` event only.
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<&'static str>,
}

/// Bounded `--json` status events used by real-process acceptance probes.
/// These fields expose connector identity and socket lifecycle metadata only;
/// no application payload, credential, or adapter argument is serialized.
#[derive(Serialize)]
struct ConnectStatusResult {
    state: &'static str,
    phase: String,
    session_id: Option<String>,
    epoch: Option<u64>,
    generation: Option<u64>,
    active_connection_id: Option<String>,
    rotations_completed: u64,
    recovery_attempt: Option<u64>,
    recovery_attempt_started_at_ms: Option<u64>,
    recovery_attempt_deadline_ms: Option<u64>,
    recovery_episode_deadline_ms: Option<u64>,
    recovery_closed_connection_ids: Vec<String>,
    recovery_reset_reason: Option<&'static str>,
    recovery_old_generation: Option<u64>,
    recovery_old_connection_id: Option<String>,
    recovery_successor_generation: Option<u64>,
    recovery_successor_connection_id: Option<String>,
    control_local_addr: Option<String>,
    active_local_addr: Option<String>,
    candidate_local_addr: Option<String>,
    drain_fences: usize,
    drain_acks: usize,
    /// OPEN refusals this session sent, one entry per fixed code in
    /// `tunnel_protocol::open_refusal::CODES`, zeros included (M7-C167).
    open_refusals_sent: OpenRefusalCountsJson,
}

/// Serializes `OpenRefusalCounts` as `{"GOAWAY": n, ...}` with every fixed
/// code present, so the object's keys never depend on what happened.
struct OpenRefusalCountsJson(tunnel_client::OpenRefusalCounts);

impl Serialize for OpenRefusalCountsJson {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_map(self.0.iter())
    }
}

/// How long `main` waits, after the command has returned, for work still
/// running on the runtime's **blocking** pool before exiting anyway.
///
/// `#[tokio::main]` dropped the runtime, and dropping a runtime waits
/// **indefinitely** for blocking tasks (M6-C23 review): a stop request that
/// abandoned startup while a `spawn_blocking` file open or write sat on a
/// hung mount would print its diagnostic and then never exit. With this
/// bound the process exits at most this long after its diagnostic; the
/// blocking work still in flight is abandoned with the process -- a state
/// file write already guarded by its own write-then-rename discipline, or a
/// sentinel stand-down whose sentinel then fires on end of file. Ordinary
/// exits have no blocking work left and do not wait at all.
const RUNTIME_SHUTDOWN_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("tunnel-client: could not start the async runtime: {error}");
            return ExitCode::FAILURE;
        }
    };
    let status = runtime.block_on(async_main());
    runtime.shutdown_timeout(RUNTIME_SHUTDOWN_BOUND);
    status
}

async fn async_main() -> ExitCode {
    // The process-wide `rustls` provider is chosen here, explicitly, rather
    // than inferred from which provider features happen to be enabled across
    // the whole dependency graph (task row M8-C09). An error means something
    // installed one before this line, which is fatal: whatever that is has
    // decided this process's cryptography.
    if let Err(error) = tunnel_transport::install_process_crypto_provider() {
        eprintln!("tunnel: {error}");
        return ExitCode::FAILURE;
    }
    debug_assert!(tunnel_transport::process_provider_is_ring());
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("tunnel-client: {}", error.message);
            eprintln!("{}", usage());
            return ExitCode::from(error.exit_code());
        }
    };
    if let Command::Doctor { path, json } = &command {
        return run_doctor(path.clone(), *json).await;
    }
    let json_command = diagnostic_command(&command);
    match run(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(command) = json_command {
                print_error_json(command, &error);
            } else {
                eprintln!("tunnel-client: {}", error.message);
            }
            ExitCode::from(error.exit_code())
        }
    }
}

async fn run(command: Command) -> Result<(), CliError> {
    match command {
        Command::Help => {
            println!("{}", usage());
            Ok(())
        }
        Command::Version => {
            println!("tunnel-client {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::LegacyCheckConfig(path) => run_legacy_check_config(path),
        Command::CheckRuntimeConfig { path, json } => {
            let _ = load_runtime_config(&path)?;
            if json {
                print_ok_json("config check", serde_json::json!({"state": "valid"}));
            } else {
                println!("Runtime client configuration is valid.");
            }
            Ok(())
        }
        Command::Connect {
            path,
            json,
            no_reconnect,
        } => run_connect(path, json, no_reconnect).await,
        Command::CreateCredentials { config, csr_out } => {
            let runtime = load_runtime_config(&config)?;
            let csr_out = resolve_cli_path(&config, &csr_out);
            let output = create_csr(&runtime, csr_out).map_err(|error| CliError {
                cause: Cause::CredentialError,
                message: error.to_string(),
                retryable: false,
            })?;
            println!(
                "Created local credential request at {} and private key at {}.",
                output.csr_path.display(),
                output.key_path.display()
            );
            Ok(())
        }
        Command::ImportCredentials {
            config,
            certificate,
            server_ca,
        } => {
            let runtime = load_runtime_config(&config)?;
            let certificate = resolve_cli_path(&config, &certificate);
            let server_ca = resolve_cli_path(&config, &server_ca);
            let output =
                import_certificate(&runtime, certificate, server_ca).map_err(|error| CliError {
                    cause: Cause::CredentialError,
                    message: error.to_string(),
                    retryable: false,
                })?;
            println!(
                "Imported {} client certificate(s) and {} server CA certificate(s).",
                output.certificate_count, output.ca_certificate_count
            );
            // M6-C54: imported, because a host clock behind the issuer's sees
            // every fresh certificate this way, but not a plain success.
            if let Some(not_before) = output.not_yet_valid_until {
                eprintln!(
                    "tunnel-client: warning: the imported client certificate is not valid \
                     until unix time {not_before} on this host's clock; `doctor` reports \
                     CREDENTIAL_NOT_YET_VALID and `connect` retries until then (check this \
                     host's clock if the issuer's is correct)"
                );
            }
            Ok(())
        }
        Command::Doctor { .. } => unreachable!("doctor is handled before the async command runner"),
        Command::Status { path, json } => run_status(&path, json).await,
    }
}

/// `tunnel-client status`: read the running supervisor's redacted snapshot
/// through the profile's local IPC socket (M6-06). Read-only: it opens no
/// network connection, starts no tunnel and changes nothing.
async fn run_status(path: &Path, json: bool) -> Result<(), CliError> {
    let config = load_runtime_config(path)?;
    let status = tunnel_client::supervisor_ipc::query_status(&config.supervisor_socket_path())
        .await
        .map_err(CliError::from_ipc)?;
    if json {
        print_ok_json("status", &status);
        return Ok(());
    }
    println!(
        "Supervisor: pid={} state={} sessions={}",
        status.pid, status.state, status.sessions
    );
    match &status.session {
        Some(session) => println!(
            "Session: {} epoch={} generation={} phase={} rotations={} streams={} queue_bytes={}",
            session.session_id.as_deref().unwrap_or("-"),
            session.epoch.unwrap_or_default(),
            session.active_generation.unwrap_or_default(),
            session.phase,
            session.rotations_completed,
            session.streams,
            session.queue_bytes
        ),
        None => println!("Session: none"),
    }
    if let Some(code) = &status.last_error_code {
        println!("Last session end: {code}");
    }
    Ok(())
}

async fn run_doctor(path: PathBuf, json: bool) -> ExitCode {
    let supervisor_ipc = doctor_supervisor_ipc(&path).await;
    let inspection = doctor::inspect(&path, SystemTime::now(), supervisor_ipc);
    if json {
        println!(
            "{}",
            serde_json::to_string(&inspection.output).expect("doctor diagnostics serialize")
        );
    } else if inspection.output.ok {
        println!("Local configuration, credential key match, permissions, and expiry are healthy.");
        let ipc = &inspection.output.result.supervisor_ipc;
        println!("Supervisor IPC: {} ({})", ipc.status, ipc.code);
    } else if let Some(error) = &inspection.output.error {
        eprintln!("tunnel-client doctor: {}", error.message);
    } else {
        eprintln!("tunnel-client doctor: local checks failed");
    }
    ExitCode::from(inspection.exit_code)
}

/// The doctor's supervisor IPC check (M6-06): read the profile's supervisor
/// socket the way `status` does and report only a status and a closed code.
/// A supervisor that is simply not running is `not_running`, not a failure:
/// `doctor` is also run before the first `connect`.
async fn doctor_supervisor_ipc(path: &Path) -> doctor::CapabilityCheck {
    let Ok(config) = ConnectConfig::load(path) else {
        return doctor::CapabilityCheck {
            status: "not_run",
            code: "SUPERVISOR_IPC_NOT_RUN",
        };
    };
    let config = config.resolve_relative_to(path.parent().unwrap_or_else(|| Path::new(".")));
    match tunnel_client::supervisor_ipc::query_status(&config.supervisor_socket_path()).await {
        Ok(_) => doctor::CapabilityCheck {
            status: "ok",
            code: "SUPERVISOR_IPC_OK",
        },
        Err(tunnel_client::supervisor_ipc::IpcError::Absent) => doctor::CapabilityCheck {
            status: "not_running",
            code: "SUPERVISOR_ABSENT",
        },
        Err(tunnel_client::supervisor_ipc::IpcError::Unsupported) => doctor::CapabilityCheck {
            status: "unsupported",
            code: "IPC_UNSUPPORTED",
        },
        Err(error) => doctor::CapabilityCheck {
            status: "failed",
            code: error.code(),
        },
    }
}

fn run_legacy_check_config(path: Option<PathBuf>) -> Result<(), CliError> {
    match path {
        None => {
            ClientConfig::default()
                .validate()
                .map_err(|error| CliError::usage(error.to_string()))?;
            println!(
                "Default client configuration is valid. This command only checks configuration; use connect to start the tunnel."
            );
        }
        Some(path) => {
            let input = fs::read_to_string(path).map_err(|error| CliError {
                cause: Cause::ConfigError,
                message: format!("could not read legacy configuration: {error}"),
                retryable: false,
            })?;
            ClientConfig::parse(&input).map_err(|error| CliError {
                cause: Cause::ConfigError,
                message: error.to_string(),
                retryable: false,
            })?;
            println!(
                "Client configuration is valid. This command only checks configuration; use connect to start the tunnel."
            );
        }
    }
    Ok(())
}

/// A request to stop, as delivered to this process.
///
/// SIGINT and SIGTERM are **one** request with two spellings: Ctrl-C at a
/// terminal sends the first, and a service manager (systemd, launchd) sends
/// the second by default. Both take the same orderly path below; the name is
/// kept only so the diagnostic can say which one arrived.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StopSignal {
    Interrupt,
    // SIGTERM has no Windows counterpart here: Ctrl-C arrives as `Interrupt`.
    #[cfg_attr(not(unix), allow(dead_code))]
    Terminate,
}

impl StopSignal {
    fn name(self) -> &'static str {
        match self {
            Self::Interrupt => "SIGINT",
            Self::Terminate => "SIGTERM",
        }
    }
}

/// The process's stop requests, armed **before** anything else `connect`
/// does (task rows M6-C23 and M6-C27).
///
/// Before this, the only handler was a `tokio::signal::ctrl_c()` future
/// created inside the post-connect select loop. Until that line ran, SIGINT
/// kept the disposition the process inherited and SIGTERM always did: a
/// signal during the TLS/WebSocket handshake either killed the process with
/// no output (default disposition) or was ignored until the handshake
/// deadline reported `DEADLINE_EXCEEDED` (inherited `SIG_IGN`), and SIGTERM
/// killed it in every phase.
///
/// **Inherited `SIG_IGN` is overridden, deliberately.** Installing a handler
/// replaces whatever disposition the process inherited, so a `tunnel-client`
/// started as a background job of a non-interactive shell (which sets SIGINT
/// and SIGQUIT to ignored) now stops on SIGINT too. The reasons, and the
/// alternative that was rejected, are in `docs/runtime.md` ("Stopping
/// `connect` and `serve`"); in short, a stop request that is silently ignored for ten
/// seconds and then reported as a deadline is the defect M6-C27 recorded, and
/// a process that must survive a terminal's Ctrl-C belongs in its own session
/// or under a service manager, not behind an inherited disposition. SIGHUP is
/// **not** handled, so `nohup` keeps working.
struct StopSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl StopSignals {
    fn install() -> Result<Self, CliError> {
        let signal_error = |error: std::io::Error| CliError {
            cause: Cause::SignalError,
            message: format!("could not install the stop-signal handlers: {error}"),
            retryable: false,
        };
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt()).map_err(signal_error)?,
                terminate: signal(SignalKind::terminate()).map_err(signal_error)?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                ctrl_c: tokio::signal::windows::ctrl_c().map_err(signal_error)?,
            })
        }
    }

    /// Wait for the next stop request. Cancel-safe, so it can sit in a
    /// `select!` loop without losing a delivery.
    async fn recv(&mut self) -> Result<StopSignal, CliError> {
        let closed = || CliError {
            cause: Cause::SignalError,
            message: "the stop-signal stream closed".to_owned(),
            retryable: false,
        };
        #[cfg(unix)]
        {
            tokio::select! {
                received = self.interrupt.recv() => received.map(|()| StopSignal::Interrupt).ok_or_else(closed),
                received = self.terminate.recv() => received.map(|()| StopSignal::Terminate).ok_or_else(closed),
            }
        }
        #[cfg(windows)]
        {
            self.ctrl_c
                .recv()
                .await
                .map(|()| StopSignal::Interrupt)
                .ok_or_else(closed)
        }
    }
}

/// How long a cancelled connect attempt may take to unwind before it is
/// dropped. The attempt observes its cancellation token at every await, so
/// this is a ceiling on a defect, not an expected wait; dropping the future
/// closes whatever socket it still owns either way.
const CANCELLED_CONNECT_UNWIND: std::time::Duration = std::time::Duration::from_secs(2);

/// The diagnostic for a stop request that arrived before the session was
/// ready: `CANCELLED`, exit `130`. Nothing was established, so there is no
/// orderly completion to record -- which is exactly what `130` means.
fn interrupted_before_ready(signal: StopSignal) -> CliError {
    CliError {
        cause: Cause::Cancelled,
        message: format!(
            "{} received before the session was ready; the connect attempt was cancelled",
            signal.name()
        ),
        retryable: false,
    }
}

/// How a bounded wait ended.
#[derive(Debug)]
enum Bounded<T> {
    Done(T),
    TimedOut,
    /// Another stop request arrived first.
    Interrupted(StopSignal),
}

/// Wait for `work` for at most `bound`, unless another stop request arrives
/// first -- **every** wait on the stop path goes through this, so that "a
/// second signal always exits at once" and "nothing waits forever" hold in
/// each window rather than in the ones someone remembered (M6-C23 review).
/// `biased` so a stop request that is already pending wins over work that
/// happens to be ready in the same poll.
async fn bounded<F, S>(
    work: F,
    bound: std::time::Duration,
    next_stop: S,
) -> Result<Bounded<F::Output>, CliError>
where
    F: std::future::Future,
    S: std::future::Future<Output = Result<StopSignal, CliError>>,
{
    tokio::select! {
        biased;
        second = next_stop => Ok(Bounded::Interrupted(second?)),
        result = tokio::time::timeout(bound, work) => {
            Ok(result.map_or(Bounded::TimedOut, Bounded::Done))
        }
    }
}

/// `CANCELLED` for a stop request that abandoned a wait on the stop path.
fn abandoned(second: StopSignal, first: Option<StopSignal>, waiting_for: &str) -> CliError {
    let message = match first {
        Some(first) => format!(
            "{} received during the orderly stop {} began, while waiting for {waiting_for}; exiting without waiting",
            second.name(),
            first.name()
        ),
        None => format!(
            "{} received while waiting for {waiting_for}; exiting without waiting",
            second.name()
        ),
    };
    CliError {
        cause: Cause::Cancelled,
        message,
        retryable: false,
    }
}

/// Join the connector after a stop request: bounded by `bound`, and
/// abandoned at once by a **second** request.
///
/// Once the handlers are installed a signal no longer kills the process, so
/// without this a drain that hung would leave an operator with nothing short
/// of `SIGKILL`. Either way out reports `CANCELLED` (exit `130`): the drain
/// did not complete, which is what that status means. The join's own result
/// is not the diagnostic: the stop was requested, and the connector reports
/// a requested stop as success, unchanged from the SIGINT-only path.
async fn join_after_stop<J, S>(
    join: J,
    bound: std::time::Duration,
    next_stop: S,
    first: StopSignal,
) -> Result<(), CliError>
where
    J: std::future::Future,
    S: std::future::Future<Output = Result<StopSignal, CliError>>,
{
    match bounded(join, bound, next_stop).await? {
        Bounded::Done(_) => Ok(()),
        Bounded::Interrupted(second) => {
            Err(abandoned(second, Some(first), "the connector to drain"))
        }
        Bounded::TimedOut => Err(CliError {
            cause: Cause::Cancelled,
            message: format!(
                "the orderly stop {} began did not complete within {} s; exiting without it",
                first.name(),
                bound.as_secs()
            ),
            retryable: false,
        }),
    }
}

/// Bound on joining the connector after a stop request: the configured
/// replacement handshake deadline plus the rotation overlap, the longest a
/// drain that was mid-rotation can legitimately need (40 s with the
/// defaults). The same derivation as the M7 liveness gate's join bound,
/// minus the interval, which a stop does not wait for.
fn stop_join_bound(config: &ConnectConfig) -> std::time::Duration {
    std::time::Duration::from_secs(
        config
            .rotation
            .handshake_timeout_seconds
            .saturating_add(config.rotation.overlap_seconds),
    )
}

/// How one session of `connect` ended, as the reconnect loop needs it.
enum SessionEnd {
    /// A stop request ended it in order; the `stopped` event is printed.
    Stopped,
    /// It ended by itself, or never became ready.
    Failed {
        error: CliError,
        /// The session that was ready, if one was, and for how long.
        ready: Option<(String, std::time::Duration)>,
    },
}

/// Whether `connect` may reconnect after a session ended with this cause
/// (task row M6-C23). **Exhaustive with no fallback arm**, like
/// `Cause::exit_code`: a new cause cannot compile until someone decides
/// whether retrying it could ever help. The justification of each arm, from
/// the code that produces the cause, is in docs/runtime.md ("Reconnecting").
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReconnectClass {
    Retryable,
    /// Retryable only while the owner slot the relay reports busy can be
    /// this process's own previous session, whose lease has not yet lapsed.
    OwnerBusy,
    Terminal,
}

impl Cause {
    fn reconnect_class(self) -> ReconnectClass {
        match self {
            // Local input: nothing a retry does changes the file or the flags,
            // and the profile is not re-read.
            Self::InvalidInvocation | Self::ConfigError | Self::InvalidConfig => {
                ReconnectClass::Terminal
            }
            // The local credential could not be loaded, or TLS verification
            // refused a certificate on either side (`ClientError::TlsRefused`).
            Self::CredentialError => ReconnectClass::Terminal,
            // Refused TCP, a reset, EOF, a closed socket, a failed rotation or
            // retained recovery, a relay that closed the session: exactly what a
            // relay restart, a network change or a laptop waking produce.
            Self::TransportError | Self::SessionClosed => ReconnectClass::Retryable,
            // A handshake that did not finish in 10 s: a blackholed route or a
            // relay too busy to answer; a later attempt can succeed.
            Self::DeadlineExceeded => ReconnectClass::Retryable,
            // Produced when one stream's operation-authorization deadline
            // lapsed with a frame already queued (lib.rs, the data writer and
            // `dispatch_fin`): the session is failed so the queued side effect
            // cannot be replayed. It is not a revoked credential; a fresh
            // session starts with no streams and fresh authorizations.
            Self::AuthorizationStale => ReconnectClass::Retryable,
            // A per-session local budget (queue or OPEN retention); the
            // library's own doc says the caller must start a fresh session.
            Self::ResourceExhausted => ReconnectClass::Retryable,
            Self::OwnerBusy => ReconnectClass::OwnerBusy,
            // Our own cancellation; a protocol violation (version skew or a
            // defect: TLS rules out corruption); a panicked supervisor; a
            // broken signal subsystem. A retry repeats each of them.
            Self::Cancelled | Self::ProtocolError | Self::SupervisorFailed | Self::SignalError => {
                ReconnectClass::Terminal
            }
            // Supervisor IPC causes arise before the first attempt (the
            // profile lock) or in `status`, never from a session.
            Self::SupervisorAbsent
            | Self::SupervisorRunning
            | Self::SupervisorLockFailed
            | Self::IpcUnauthorized => ReconnectClass::Terminal,
        }
    }
}

/// How long after this process's own session ended an `OWNER_BUSY` refusal
/// is still read as that session's lease rather than another connector.
/// The relay bounds its owner lease to 6..=30 s (`owner_lease` in
/// `tunnel-relay`'s config), which is how long a **dead relay's** owner
/// record outlives it (measured about 30 s); twice the maximum covers that.
/// It also covers a relay that is still running and still holds the old
/// session because the device's side of the path vanished (a network change,
/// a NAT or VPN drop): since M6-C68 that relay pings the control socket every
/// `DEVICE_CONTROL_PING_INTERVAL` and ends a session that has sent nothing
/// for `DEVICE_CONTROL_IDLE_TIMEOUT` (30 s), releasing the owner slot, so the
/// refusals stop well inside this window (asserted below). Before M6-C68 the
/// relay never noticed and every reconnect was refused until this window
/// ended and the process exited 7 (measured by the M6-C23 review: 78
/// refusals, exit 7 at 60.7 s). Outside the window -- including a
/// fresh process's first attempt, which has no previous session --
/// `OWNER_BUSY` is terminal, so a second connector for the same device still
/// exits 7 at once; the only witness of that first-attempt rule with
/// reconnect on is the unit test
/// `owner_busy_is_retried_only_within_the_window_after_our_own_session`.
const OWNER_BUSY_RECONNECT_WINDOW: std::time::Duration = std::time::Duration::from_secs(60);
// M6-C68: a relay that lost the device's path evicts it after at most
// `DEVICE_CONTROL_IDLE_TIMEOUT` of silence plus its bounded 5 s disconnect
// hand-off; the window must outlast that with room for a backoff step.
const _: () = assert!(
    OWNER_BUSY_RECONNECT_WINDOW.as_secs()
        >= tunnel_protocol::DEVICE_CONTROL_IDLE_TIMEOUT.as_secs() + 5 + 15
);

/// The reconnect policy for this run: the profile's `[reconnect]` table,
/// with `--no-reconnect` able to switch it off.
#[derive(Clone, Copy, Debug)]
struct ReconnectPolicy {
    enabled: bool,
    initial: std::time::Duration,
    max: std::time::Duration,
    max_attempts: u32,
}

impl ReconnectPolicy {
    fn new(config: &tunnel_client::ReconnectConfig, no_reconnect: bool) -> Self {
        Self {
            enabled: config.enabled && !no_reconnect,
            initial: std::time::Duration::from_millis(config.initial_delay_ms),
            max: std::time::Duration::from_millis(config.max_delay_ms),
            max_attempts: config.max_attempts,
        }
    }

    /// The upper bound of the delay before the `attempt`-th consecutive
    /// retry: `initial * 2^(attempt-1)`, capped at `max`.
    fn ceiling(&self, attempt: u32) -> std::time::Duration {
        let factor = 1u32
            .checked_shl(attempt.saturating_sub(1).min(31))
            .unwrap_or(u32::MAX);
        self.initial.saturating_mul(factor).min(self.max)
    }

    /// The delay before the `attempt`-th consecutive retry: uniform in
    /// `[ceiling/2, ceiling]` ("equal jitter"). The floor keeps a relay that
    /// refuses at once from turning the loop into a busy loop; the spread of
    /// half the ceiling is what separates devices that lost the same relay at
    /// the same instant.
    fn delay(&self, attempt: u32, random: u64) -> std::time::Duration {
        let ceiling = u64::try_from(self.ceiling(attempt).as_millis()).unwrap_or(u64::MAX);
        let floor = ceiling / 2;
        let spread = ceiling - floor;
        std::time::Duration::from_millis(floor + random % (spread + 1))
    }
}

/// The `failure_policy` a `ready` or `stopped` event publishes. The library's
/// [`M1_TRANSPORT_FAILURE_POLICY`] says "no automatic reconnect", which is
/// true of one `connect` call and was true of this binary before M6-C23; with
/// the reconnect loop on it is not, so the event says what this process does.
const RECONNECTING_FAILURE_POLICY: &str = "close control and data and require a fresh session; no retained replay; a retryable end is retried as a fresh session after bounded backoff";

impl ReconnectPolicy {
    fn failure_policy(&self) -> &'static str {
        if self.enabled {
            RECONNECTING_FAILURE_POLICY
        } else {
            M1_TRANSPORT_FAILURE_POLICY
        }
    }
}

fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_secs()).unwrap_or(i64::MAX)
        })
}

/// The validity window of this device's certificate chain -- the latest
/// `notBefore` and the earliest `notAfter`, as unix seconds, the rule
/// `doctor` applies -- or `None` if it cannot be read.
fn device_certificate_window(config: &ConnectConfig) -> Option<(i64, i64)> {
    let chain =
        tunnel_client::credentials::load_certificates(&config.credentials.client_certificate)
            .ok()?;
    let mut window: Option<(i64, i64)> = None;
    for certificate in &chain {
        let (not_before, not_after) = doctor::certificate_validity(certificate.as_ref()).ok()?;
        window = Some(match window {
            None => (not_before, not_after),
            Some((before, after)) => (before.max(not_before), after.min(not_after)),
        });
    }
    window
}

/// Classify a failed connect attempt, which differs from
/// `CliError::from_client` in exactly one case (task row M6-C23).
///
/// The relay refused this device's certificate with `certificate_expired`,
/// which rustls sends for an expired **and** for a not-yet-valid
/// certificate, judged on the relay's clock. The relay cannot say which; this
/// process can, because it holds the certificate and its own clock:
///
/// * `notAfter` has passed here too: the certificate is expired. No retry
///   fixes that, so it is terminal `CREDENTIAL_ERROR` (exit `3`) naming the
///   time -- the tester needs to see this error, not a backoff loop.
/// * Otherwise -- not yet valid here either (a CA clock ahead, or a
///   `notBefore` stamped at signing time), or valid here (the relay's clock
///   differs from this host's): retryable `TRANSPORT_ERROR`, and the message
///   says clock skew is the likely cause. A certificate that becomes valid
///   is then accepted on a later attempt without anyone restarting anything.
///
/// A certificate that cannot be read here keeps the retryable transport
/// classification: nothing proves it expired.
fn attempt_error(error: ClientError, config: &ConnectConfig, now: i64) -> CliError {
    let ClientError::Transport { scope, .. } = &error else {
        return CliError::from_client(error);
    };
    if *scope != tunnel_client::DEVICE_CERTIFICATE_NOT_CURRENT_SCOPE {
        return CliError::from_client(error);
    }
    let reported = error.to_string();
    match device_certificate_window(config) {
        Some((_, not_after)) if not_after <= now => CliError {
            cause: Cause::CredentialError,
            message: format!(
                "{reported}; this device's certificate expired at unix time {not_after} on this host's clock too: renew it"
            ),
            retryable: false,
        },
        Some((not_before, _)) if not_before > now => CliError {
            cause: Cause::TransportError,
            message: format!(
                "{reported}; it is not valid until unix time {not_before} on this host's clock either (its issuer's clock is likely ahead); retrying"
            ),
            retryable: true,
        },
        Some((not_before, not_after)) => CliError {
            cause: Cause::TransportError,
            message: format!(
                "{reported}; it is valid on this host's clock (unix time {not_before} to {not_after}), so the relay's clock likely differs from this host's; retrying"
            ),
            retryable: true,
        },
        None => CliError::from_client(error),
    }
}

/// A random value for the jitter. `uuid`'s v4 generator draws from the
/// operating system's generator, which is what jitter needs: independent
/// across devices, not reproducible.
fn jitter_random() -> u64 {
    uuid::Uuid::new_v4().as_u64_pair().0
}

/// What the loop decided after a session ended.
#[derive(Debug, Eq, PartialEq)]
enum ReconnectDecision {
    Exit,
    Retry {
        attempt: u32,
        delay: std::time::Duration,
    },
}

/// The loop's memory between sessions.
#[derive(Debug, Default)]
struct ReconnectState {
    /// Consecutive attempts that failed, or whose session did not stay ready
    /// for `max` (so a relay that accepts and drops at once still backs off).
    failures: u32,
    /// Sessions that became ready in this process.
    sessions: u64,
    /// When this process's most recent ready session ended.
    last_ready_end: Option<tokio::time::Instant>,
}

impl ReconnectState {
    fn decide(
        &mut self,
        policy: &ReconnectPolicy,
        cause: Cause,
        ready: Option<std::time::Duration>,
        now: tokio::time::Instant,
        random: u64,
    ) -> ReconnectDecision {
        if let Some(lasted) = ready {
            self.sessions += 1;
            self.last_ready_end = Some(now);
            if lasted >= policy.max {
                self.failures = 0;
            }
        }
        let retryable = match cause.reconnect_class() {
            ReconnectClass::Retryable => true,
            ReconnectClass::Terminal => false,
            ReconnectClass::OwnerBusy => self
                .last_ready_end
                .is_some_and(|ended| now.duration_since(ended) < OWNER_BUSY_RECONNECT_WINDOW),
        };
        if !policy.enabled || !retryable {
            return ReconnectDecision::Exit;
        }
        self.failures = self.failures.saturating_add(1);
        if policy.max_attempts != 0 && self.failures > policy.max_attempts {
            return ReconnectDecision::Exit;
        }
        ReconnectDecision::Retry {
            attempt: self.failures,
            delay: policy.delay(self.failures, random),
        }
    }
}

/// `--json` events of the reconnect loop. Identifiers, counters, durations
/// and the cause's code and bounded message only -- never payloads.
#[derive(Serialize)]
struct ReconnectEvent<'a> {
    state: &'static str,
    /// The retry this event belongs to: 1 for the first after a failure.
    attempt: u32,
    /// Sessions that became ready in this process so far.
    sessions: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ready_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    delay_ms: Option<u64>,
}

fn millis(duration: std::time::Duration) -> u64 {
    u64::try_from(duration.as_millis()).unwrap_or(u64::MAX)
}

/// `CANCELLED` for a stop request that arrived while waiting to reconnect.
///
/// Exit `130`, not `0`: no session is live, so there is no orderly stop to
/// complete -- the same phase rule as a stop before the first session was
/// ready, and the same status a stop 1 ms later, during the next attempt's
/// handshake, gives.
fn interrupted_during_backoff(signal: StopSignal, attempt: u32, last: &CliError) -> CliError {
    CliError {
        cause: Cause::Cancelled,
        message: format!(
            "{} received while waiting to reconnect (attempt {attempt}, after {}); no session was live",
            signal.name(),
            last.code()
        ),
        retryable: false,
    }
}

/// The supervisor's side of the local status IPC (M6-06): the snapshot it
/// publishes and the server task answering `status` and `doctor`.
struct SupervisorPublisher {
    status: tokio::sync::watch::Sender<tunnel_client::supervisor_ipc::SupervisorStatus>,
    server: Option<(CancellationToken, tokio::task::JoinHandle<()>)>,
    /// The profile lock, held until the publisher is dropped at the end of
    /// `run_connect` (and released by the kernel on any exit).
    _lock: ProfileLockHold,
}

/// What holds the profile lock: the `flock` on Unix; nothing on other
/// platforms, which have no supervisor IPC and so no lock yet (documented
/// in docs/runtime.md, "Supervisor status IPC").
#[cfg(unix)]
type ProfileLockHold = Option<tunnel_client::supervisor_ipc::ProfileLock>;
#[cfg(not(unix))]
type ProfileLockHold = Option<()>;

type IpcServer = Option<(CancellationToken, tokio::task::JoinHandle<()>)>;

impl SupervisorPublisher {
    /// Take the profile lock, then bind the profile's supervisor socket.
    ///
    /// **The lock fails closed** (M6-06 review, task row M6-C132): another
    /// supervisor holding it is refused `SUPERVISOR_RUNNING`, exit `9`, and
    /// a lock that cannot be taken for any other reason -- a missing
    /// directory, one other users can write, a lock file that is a symlink or
    /// open to others -- refuses to start as well (`SUPERVISOR_LOCK_FAILED`,
    /// exit `9`, or `IPC_UNAUTHORIZED`, exit `3`): two connectors on one
    /// profile would share one credential and fight over one owner slot, and
    /// a supervisor that cannot prove it is alone must not run. **Only the
    /// socket is optional:** with the lock held, a socket that cannot be
    /// bound (a path too long for `sun_path`, say) leaves this supervisor
    /// running without IPC, with one stderr line naming the code; `status`
    /// then reports no supervisor.
    fn start(config: &ConnectConfig) -> Result<Self, CliError> {
        use tunnel_client::supervisor_ipc::{ExportStatus, RotationPolicyStatus, SupervisorStatus};
        let initial = SupervisorStatus {
            pid: std::process::id(),
            state: "starting".to_owned(),
            device_id: config.device_id.clone(),
            certificate_expires_at_unix: device_certificate_window(config)
                .map(|(_, not_after)| not_after),
            rotation_policy: RotationPolicyStatus {
                interval_seconds: config.rotation.interval_seconds,
                handshake_timeout_seconds: config.rotation.handshake_timeout_seconds,
                overlap_seconds: config.rotation.overlap_seconds,
            },
            exports: config
                .exports
                .iter()
                .map(|(name, export)| ExportStatus {
                    name: name.clone(),
                    kind: serde_json::to_value(export.kind)
                        .ok()
                        .and_then(|kind| kind.as_str().map(str::to_owned))
                        .unwrap_or_default(),
                })
                .collect(),
            ..SupervisorStatus::default()
        };
        let (status, receiver) = tokio::sync::watch::channel(initial);
        let (server, lock) = start_ipc_server(config, receiver)?;
        Ok(Self {
            status,
            server,
            _lock: lock,
        })
    }

    fn update(&self, change: impl FnOnce(&mut tunnel_client::supervisor_ipc::SupervisorStatus)) {
        self.status.send_modify(change);
    }

    /// Stop answering and remove the socket, bounded.
    async fn shutdown(mut self) {
        if let Some((cancel, task)) = self.server.take() {
            cancel.cancel();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), task).await;
        }
    }
}

#[cfg(unix)]
fn start_ipc_server(
    config: &ConnectConfig,
    receiver: tokio::sync::watch::Receiver<tunnel_client::supervisor_ipc::SupervisorStatus>,
) -> Result<(IpcServer, ProfileLockHold), CliError> {
    use tunnel_client::supervisor_ipc::{IpcError, ProfileLock, SupervisorIpc};
    let socket = config.supervisor_socket_path();
    let lock = match ProfileLock::acquire(&socket) {
        Ok(lock) => lock,
        // Fail closed: never run without the lock.
        Err(error) => return Err(CliError::from_ipc(error)),
    };
    match SupervisorIpc::bind(&socket, &lock) {
        Ok(ipc) => {
            let cancel = CancellationToken::new();
            let task = tokio::spawn(ipc.serve(receiver, cancel.clone()));
            Ok((Some((cancel, task)), Some(lock)))
        }
        Err(IpcError::Busy) => Err(CliError::from_ipc(IpcError::Busy)),
        Err(error) => {
            eprintln!(
                "tunnel-client: warning: supervisor status IPC unavailable ({}): {error}; \
                 `status` will report no supervisor",
                error.code()
            );
            Ok((None, Some(lock)))
        }
    }
}

#[cfg(not(unix))]
fn start_ipc_server(
    _config: &ConnectConfig,
    _receiver: tokio::sync::watch::Receiver<tunnel_client::supervisor_ipc::SupervisorStatus>,
) -> Result<(IpcServer, ProfileLockHold), CliError> {
    Ok((None, None))
}

async fn run_connect(path: PathBuf, json: bool, no_reconnect: bool) -> Result<(), CliError> {
    // First, before any file is read or socket opened: from here on a stop
    // request in any phase reaches the orderly path below instead of the
    // inherited disposition.
    let mut stop = StopSignals::install()?;
    let config = load_runtime_config(&path)?;
    let publisher = SupervisorPublisher::start(&config)?;
    let result = run_supervised(&config, &mut stop, &publisher, json, no_reconnect).await;
    publisher.update(|status| {
        status.state = "stopping".to_owned();
        status.session = None;
    });
    publisher.shutdown().await;
    result
}

async fn run_supervised(
    config: &ConnectConfig,
    stop: &mut StopSignals,
    publisher: &SupervisorPublisher,
    json: bool,
    no_reconnect: bool,
) -> Result<(), CliError> {
    let config = config.clone();
    let stop_bound = stop_join_bound(&config);
    let policy = ReconnectPolicy::new(&config.reconnect, no_reconnect);
    let mut state = ReconnectState::default();
    // The retry in progress, if this attempt follows a failure.
    let mut retry: Option<u32> = None;
    loop {
        publisher.update(|status| {
            status.state = "connecting".to_owned();
            status.attempt = retry;
            status.retry_delay_ms = None;
            status.session = None;
        });
        let end = run_one_session(
            &config,
            stop,
            stop_bound,
            json,
            policy.failure_policy(),
            (retry, &state),
            publisher,
        )
        .await?;
        let (error, ready) = match end {
            SessionEnd::Stopped => return Ok(()),
            SessionEnd::Failed { error, ready } => (error, ready),
        };
        let decision = state.decide(
            &policy,
            error.cause,
            ready.as_ref().map(|(_, lasted)| *lasted),
            tokio::time::Instant::now(),
            jitter_random(),
        );
        let ReconnectDecision::Retry { attempt, delay } = decision else {
            if policy.enabled && policy.max_attempts != 0 && state.failures > policy.max_attempts {
                return Err(CliError {
                    message: format!(
                        "{} (gave up after {} consecutive reconnect attempts)",
                        error.message, policy.max_attempts
                    ),
                    ..error
                });
            }
            return Err(error);
        };
        let session_id = ready.as_ref().map(|(id, _)| id.as_str());
        publisher.update(|status| {
            status.state = "backoff".to_owned();
            status.attempt = Some(attempt);
            status.retry_delay_ms = Some(millis(delay));
            status.last_error_code = Some(error.code().to_owned());
            status.sessions = state.sessions;
            status.session = None;
        });
        if json {
            print_ok_json(
                "connect",
                ReconnectEvent {
                    state: "disconnected",
                    attempt,
                    sessions: state.sessions,
                    session_id,
                    ready_ms: ready.as_ref().map(|(_, lasted)| millis(*lasted)),
                    code: Some(error.code()),
                    message: Some(&error.message),
                    delay_ms: None,
                },
            );
            print_ok_json(
                "connect",
                ReconnectEvent {
                    state: "backoff",
                    attempt,
                    sessions: state.sessions,
                    session_id: None,
                    ready_ms: None,
                    code: Some(error.code()),
                    message: None,
                    delay_ms: Some(millis(delay)),
                },
            );
        } else {
            eprintln!(
                "tunnel-client: session ended ({}: {}); reconnecting in {} ms (attempt {attempt})",
                error.code(),
                error.message,
                millis(delay)
            );
        }
        // The wait races the stop request, `biased` toward it: a process
        // sleeping in backoff exits on the first signal, not after the delay.
        tokio::select! {
            biased;
            signal = stop.recv() => {
                return Err(interrupted_during_backoff(signal?, attempt, &error));
            }
            () = tokio::time::sleep(delay) => {}
        }
        if json {
            print_ok_json(
                "connect",
                ReconnectEvent {
                    state: "reconnecting",
                    attempt,
                    sessions: state.sessions,
                    session_id: None,
                    ready_ms: None,
                    code: None,
                    message: None,
                    delay_ms: None,
                },
            );
        }
        retry = Some(attempt);
    }
}

/// One connect attempt and, if it becomes ready, its session, up to its end.
///
/// **Handlers, and so supervised MCP and ACP children, are per session.**
/// They are built here for each attempt and dropped with the connector when
/// the session ends, which ends every MCP/ACP protocol session and kills each
/// child's process group; the loop waits (bounded) for MCP children to be
/// reaped before it backs off. A child therefore never outlives the device
/// session its consumer's requests arrived on, which is the M3-04 rule, and
/// a reconnect is to the children exactly what a process restart would be.
async fn run_one_session(
    config: &ConnectConfig,
    stop: &mut StopSignals,
    stop_bound: std::time::Duration,
    json: bool,
    failure_policy: &'static str,
    // The retry in progress, if this attempt follows a failure, and the
    // loop's state.
    (retry, state): (Option<u32>, &ReconnectState),
    publisher: &SupervisorPublisher,
) -> Result<SessionEnd, CliError> {
    // Configured MCP and ACP exports become in-process http-forward/1
    // handlers; an http-forward export without one is still refused at OPEN.
    // **Both registrations run**, because an `[exports.<id>.acp]` table that
    // was parsed and validated and then never registered would be an export
    // the operator configured and the binary silently refused.
    let handlers = tunnel_client::http_forward::HttpHandlers::new()
        .with_mcp_exports(config)
        .map_err(|error| CliError {
            cause: Cause::ConfigError,
            message: error.to_string(),
            retryable: false,
        })?
        .with_acp_exports(config)
        .map_err(|error| CliError {
            cause: Cause::ConfigError,
            message: error.to_string(),
            retryable: false,
        })?
        // M5 Lane B: refused unless this build has the `cua` feature and the
        // device opted in through the environment.
        .with_cua_exports(
            config,
            std::env::var(tunnel_client::CUA_OPT_IN_ENV).is_ok_and(|value| value == "1"),
        )
        .map_err(|error| CliError {
            cause: Cause::ConfigError,
            message: error.to_string(),
            retryable: false,
        })?;
    // Kept across the move so the stop path can wait for supervised MCP
    // children to be reaped (M6-C29).
    let mcp_children = handlers.mcp_diagnostics_source();
    let cancellation = CancellationToken::new();
    let options = ConnectOptions {
        config: config.clone(),
        cancellation: cancellation.clone(),
        profile: tunnel_client::TransportProfile::M2,
    };
    let connect = tunnel_client::connect_with_http_handlers(options, handlers);
    tokio::pin!(connect);
    // `biased`, connect first: when the attempt completes in the same poll
    // as a stop request, the session **is** ready (`connect_m2` published
    // `Readiness::Ready` before returning), so it must take the orderly path
    // and print its `stopped` event rather than be reported as a pre-ready
    // cancellation. The pending signal is not lost; the session loop's first
    // poll receives it.
    let (handle, stop_requested) = tokio::select! {
        biased;
        result = &mut connect => match result {
            Ok(handle) => (handle, None),
            // The attempt failed before a session was ready; the handlers
            // went with it, and no child was started.
            Err(error) => {
                return Ok(SessionEnd::Failed { error: attempt_error(error, config, unix_now()), ready: None });
            }
        },
        signal = stop.recv() => {
            let signal = signal?;
            // Cancel, then let the attempt unwind so the sockets it opened
            // are closed by their owner rather than by process exit.
            cancellation.cancel();
            match bounded(&mut connect, CANCELLED_CONNECT_UNWIND, stop.recv()).await? {
                // It finished before it saw the cancellation: that session
                // was ready, so it is stopped in order, `stopped` included.
                Bounded::Done(Ok(handle)) => (handle, Some(signal)),
                Bounded::Interrupted(second) => {
                    return Err(abandoned(second, Some(signal), "the cancelled connect attempt to unwind"));
                }
                Bounded::Done(Err(_)) | Bounded::TimedOut => {
                    return Err(interrupted_before_ready(signal));
                }
            }
        }
    };
    let ready_at = tokio::time::Instant::now();
    let session_id = handle.status().borrow().session_id.clone();
    let outcome = match stop_requested {
        Some(signal) => Ok(signal),
        None => {
            if let Some(attempt) = retry
                && json
            {
                print_ok_json(
                    "connect",
                    ReconnectEvent {
                        state: "reconnected",
                        attempt,
                        sessions: state.sessions + 1,
                        session_id: session_id.as_deref(),
                        ready_ms: None,
                        code: None,
                        message: None,
                        delay_ms: None,
                    },
                );
            }
            publisher.update(|status| {
                status.state = "ready".to_owned();
                status.sessions = state.sessions + 1;
            });
            run_session(&handle, stop, stop_bound, json, failure_policy, publisher).await
        }
    };
    publisher.update(|status| {
        status.state = "stopping".to_owned();
    });
    match outcome {
        Ok(first) => {
            cancellation.cancel();
            join_after_stop(handle.stop(), stop_bound, stop.recv(), first).await?;
            let unreaped = wait_for_supervised_children(
                || mcp_children.children_running(),
                stop.recv(),
                Some(first),
            )
            .await?;
            report_unreaped(json, unreaped);
            if json {
                print_ok_json(
                    "connect",
                    ConnectResult {
                        state: "stopped",
                        session_id: None,
                        epoch: None,
                        generation: None,
                        failure_policy,
                        signal: Some(first.name()),
                    },
                );
            } else {
                println!("Stopped.");
            }
            Ok(SessionEnd::Stopped)
        }
        // A second stop request already abandoned the drain; that operator
        // has asked not to wait, and the children's kill was never requested.
        Err(error) if error.cause == Cause::Cancelled => Err(error),
        Err(error) => {
            let lasted = ready_at.elapsed();
            let unreaped =
                wait_for_supervised_children(|| mcp_children.children_running(), stop.recv(), None)
                    .await?;
            report_unreaped(json, unreaped);
            Ok(SessionEnd::Failed {
                error,
                ready: Some((session_id.unwrap_or_default(), lasted)),
            })
        }
    }
}

/// Bound on waiting for supervised MCP children to be reaped after the
/// connector stops. Their kill is `SIGKILL` to the process group, so a reap
/// takes milliseconds; the bound only caps a defect, and when it fires the
/// process exits anyway and the sentinel, if installed, fires.
const SUPERVISED_CHILD_REAP_BOUND: std::time::Duration = std::time::Duration::from_secs(5);

/// Wait, bounded, until `running()` reaches zero, unless another stop
/// request arrives first.
///
/// The session actor dropped its handlers inside `handle.stop()`, which
/// *requests* every supervised MCP child's group kill; the kill, the reap
/// and the sentinel stand-down run on a spawned task. Returning from `main`
/// before they ran would tear the runtime down with that task possibly
/// never polled -- measured (M6-C29) to leave an in-group helper alive in 7
/// of 50 runs on this runtime flavour, and every time on a current-thread
/// one, when no sentinel is installed. Since M6-C28 a `ChildHandle` dropped
/// by that teardown signals its group synchronously, so the helper no longer
/// survives it; the wait still keeps the reap and the sentinel's stand-down,
/// rather than its firing, on the orderly path. A timed-out wait is not an error, but
/// it is not silent either: the result is how many children were still
/// unreaped at the bound, and the caller reports a non-zero count
/// (`report_unreaped`).
async fn wait_for_supervised_children<R, S>(
    running: R,
    next_stop: S,
    first: Option<StopSignal>,
) -> Result<u64, CliError>
where
    R: Fn() -> u64,
    S: std::future::Future<Output = Result<StopSignal, CliError>>,
{
    wait_for_supervised_children_within(running, SUPERVISED_CHILD_REAP_BOUND, next_stop, first)
        .await
}

async fn wait_for_supervised_children_within<R, S>(
    running: R,
    bound: std::time::Duration,
    next_stop: S,
    first: Option<StopSignal>,
) -> Result<u64, CliError>
where
    R: Fn() -> u64,
    S: std::future::Future<Output = Result<StopSignal, CliError>>,
{
    let reaped = async {
        while running() > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    match bounded(reaped, bound, next_stop).await? {
        Bounded::Done(()) => Ok(0),
        Bounded::TimedOut => Ok(running()),
        Bounded::Interrupted(second) => Err(abandoned(
            second,
            first,
            "supervised MCP children to be reaped",
        )),
    }
}

/// The event for supervised MCP children still unreaped when the reap wait's
/// bound ran out (M6-C23 review): the process goes on -- to exit, or to back
/// off and reconnect -- and the sentinel, if installed, is what ends them.
#[derive(Serialize)]
struct UnreapedEvent {
    state: &'static str,
    unreaped: u64,
    bound_ms: u64,
}

fn report_unreaped(json: bool, unreaped: u64) {
    if unreaped == 0 {
        return;
    }
    let bound_ms = millis(SUPERVISED_CHILD_REAP_BOUND);
    if json {
        print_ok_json(
            "connect",
            UnreapedEvent {
                state: "children_unreaped",
                unreaped,
                bound_ms,
            },
        );
    } else {
        eprintln!(
            "tunnel-client: {unreaped} supervised MCP child process(es) not reaped within {bound_ms} ms; continuing"
        );
    }
}

/// Join a connector whose session ended by itself, bounded and abandonable
/// like every other wait on the stop path. Its supervisor has normally
/// returned already, so this is immediate; the bound caps a defect.
async fn join_after_close(
    handle: &tunnel_client::ConnectionHandle,
    stop: &mut StopSignals,
    bound: std::time::Duration,
) -> Result<Result<(), ClientError>, CliError> {
    match bounded(handle.stop(), bound, stop.recv()).await? {
        Bounded::Done(result) => Ok(result),
        Bounded::Interrupted(second) => {
            Err(abandoned(second, None, "the closed connector to join"))
        }
        Bounded::TimedOut => Err(CliError {
            cause: Cause::SupervisorFailed,
            message: format!(
                "the connector did not join within {} s after its session closed",
                bound.as_secs()
            ),
            retryable: false,
        }),
    }
}

/// The live session, from ready to its end: an orderly stop on request, or
/// the connector's own terminal cause.
///
/// Returns the stop request that ended it; the caller runs the orderly stop,
/// so the ready-boundary case in `run_connect` shares it exactly.
async fn run_session(
    handle: &tunnel_client::ConnectionHandle,
    stop: &mut StopSignals,
    bound: std::time::Duration,
    json: bool,
    failure_policy: &'static str,
    publisher: &SupervisorPublisher,
) -> Result<StopSignal, CliError> {
    let mut readiness = handle.readiness();
    let initial = readiness.borrow_and_update().clone();
    if let tunnel_client::Readiness::Closed { reason } = initial {
        return Err(closed_session_error(
            reason,
            join_after_close(handle, stop, bound).await?,
        ));
    }
    if let tunnel_client::Readiness::Ready(info) = &initial {
        if json {
            print_ok_json(
                "connect",
                ConnectResult {
                    state: "ready",
                    session_id: Some(&info.session_id),
                    epoch: Some(info.epoch),
                    generation: Some(info.generation),
                    failure_policy,
                    signal: None,
                },
            );
        } else {
            println!(
                "Connected: session={} epoch={} generation={}",
                info.session_id, info.epoch, info.generation
            );
        }
    }

    let mut status = handle.status();
    let mut last_status = status.borrow().clone();
    publisher.update(|published| {
        published.session = Some((&last_status).into());
    });
    if json {
        // Publish the already-ready snapshot once.  A watch receiver cloned
        // after connect observes the current value, so waiting only for
        // `changed()` would otherwise omit the first bounded identity event.
        print_connect_status(&last_status);
    }
    loop {
        tokio::select! {
            signal = stop.recv() => {
                // The same orderly path for SIGINT and SIGTERM, and for every
                // phase a live session can be in, rotation included: this
                // loop runs for the whole life of the session.
                return signal;
            }
            changed = readiness.changed() => {
                if changed.is_err() {
                    return Err(stopped_connector_error(&mut readiness, handle, stop, bound, "connector supervisor stopped").await?);
                }
                let state = readiness.borrow_and_update().clone();
                if let tunnel_client::Readiness::Closed { reason } = state {
                    return Err(closed_session_error(reason, join_after_close(handle, stop, bound).await?));
                }
            }
            changed = status.changed() => {
                if changed.is_err() {
                    // The status publisher stopping must not outrank the
                    // typed terminal cause the readiness channel still holds.
                    return Err(stopped_connector_error(&mut readiness, handle, stop, bound, "connector status publisher stopped").await?);
                }
                let current = status.borrow_and_update().clone();
                publisher.update(|published| {
                    published.session = Some((&current).into());
                });
                if json && should_emit_connect_status(&last_status, &current) {
                    print_connect_status(&current);
                }
                last_status = current;
            }
        }
    }
}

fn should_emit_connect_status(
    previous: &tunnel_client::ConnectionStatus,
    current: &tunnel_client::ConnectionStatus,
) -> bool {
    current.session_id.is_some()
        && current.control_local_addr.is_some()
        && (previous.session_id != current.session_id
            || previous.epoch != current.epoch
            || previous.active_generation != current.active_generation
            || previous.active_connection_id != current.active_connection_id
            || previous.candidate_generation != current.candidate_generation
            || previous.candidate_connection_id != current.candidate_connection_id
            || previous.phase != current.phase
            || previous.rotations_completed != current.rotations_completed
            || previous.recovery_attempt != current.recovery_attempt
            || previous.recovery_attempt_started_at_ms != current.recovery_attempt_started_at_ms
            || previous.recovery_attempt_deadline_ms != current.recovery_attempt_deadline_ms
            || previous.recovery_episode_deadline_ms != current.recovery_episode_deadline_ms
            || previous.recovery_closed_connection_ids != current.recovery_closed_connection_ids
            || previous.recovery_reset_reason != current.recovery_reset_reason
            || previous.recovery_old_generation != current.recovery_old_generation
            || previous.recovery_old_connection_id != current.recovery_old_connection_id
            || previous.recovery_successor_generation != current.recovery_successor_generation
            || previous.recovery_successor_connection_id
                != current.recovery_successor_connection_id
            || previous.control_local_addr != current.control_local_addr
            || previous.active_local_addr != current.active_local_addr
            || previous.candidate_local_addr != current.candidate_local_addr
            || previous.drain_fences != current.drain_fences
            || previous.drain_acks != current.drain_acks
            || previous.open_refusals_sent != current.open_refusals_sent)
}

fn print_connect_status(status: &tunnel_client::ConnectionStatus) {
    print_ok_json("connect-status", connect_status_result(status));
}

fn connect_status_result(status: &tunnel_client::ConnectionStatus) -> ConnectStatusResult {
    ConnectStatusResult {
        state: "status",
        phase: status.phase.clone(),
        session_id: status.session_id.clone(),
        epoch: status.epoch,
        generation: status.active_generation,
        active_connection_id: status.active_connection_id.clone(),
        rotations_completed: status.rotations_completed,
        recovery_attempt: status.recovery_attempt,
        recovery_attempt_started_at_ms: status.recovery_attempt_started_at_ms,
        recovery_attempt_deadline_ms: status.recovery_attempt_deadline_ms,
        recovery_episode_deadline_ms: status.recovery_episode_deadline_ms,
        recovery_closed_connection_ids: status.recovery_closed_connection_ids.clone(),
        recovery_reset_reason: status.recovery_reset_reason,
        recovery_old_generation: status.recovery_old_generation,
        recovery_old_connection_id: status.recovery_old_connection_id.clone(),
        recovery_successor_generation: status.recovery_successor_generation,
        recovery_successor_connection_id: status.recovery_successor_connection_id.clone(),
        control_local_addr: status.control_local_addr.map(|value| value.to_string()),
        active_local_addr: status.active_local_addr.map(|value| value.to_string()),
        candidate_local_addr: status.candidate_local_addr.map(|value| value.to_string()),
        drain_fences: status.drain_fences,
        drain_acks: status.drain_acks,
        open_refusals_sent: OpenRefusalCountsJson(status.open_refusals_sent),
    }
}

/// Recover the connector's typed terminal cause after one of its channels
/// has stopped.
///
/// The supervisor publishes its closed status and then `Readiness::Closed`
/// with the typed reason, and only afterwards returns, which drops both watch
/// senders.  Both channels therefore become ready at the same moment, and
/// `tokio::select!` picks a ready branch at random: whichever branch observes
/// its sender drop first would otherwise report a generic supervisor failure
/// and discard the typed reason the other channel is still holding.  That is
/// how an exhausted recovery episode lost its diagnostic under load.
///
/// A dropped sender does not erase a watch channel's last value, so the
/// retained readiness remains authoritative and is consulted first.  `None`
/// means there really is no terminal reason to report — a panicked or aborted
/// supervisor that never published one — and the caller's generic failure
/// stands.
fn retained_closed_reason(
    readiness: &mut tokio::sync::watch::Receiver<tunnel_client::Readiness>,
) -> Option<String> {
    match readiness.borrow_and_update().clone() {
        tunnel_client::Readiness::Closed { reason } => Some(reason),
        _ => None,
    }
}

/// Terminal error for a connector channel that has stopped, preferring the
/// retained typed cause over the generic supervisor failure.
async fn stopped_connector_error(
    readiness: &mut tokio::sync::watch::Receiver<tunnel_client::Readiness>,
    handle: &tunnel_client::ConnectionHandle,
    stop: &mut StopSignals,
    bound: std::time::Duration,
    fallback_message: &'static str,
) -> Result<CliError, CliError> {
    Ok(match retained_closed_reason(readiness) {
        Some(reason) => closed_session_error(reason, join_after_close(handle, stop, bound).await?),
        None => CliError {
            cause: Cause::SupervisorFailed,
            message: fallback_message.to_owned(),
            retryable: false,
        },
    })
}

fn closed_session_error(reason: String, stop_result: Result<(), ClientError>) -> CliError {
    match stop_result {
        Ok(()) => CliError {
            cause: Cause::SessionClosed,
            message: reason,
            retryable: true,
        },
        Err(error) => CliError::from_client(error),
    }
}

fn diagnostic_command(command: &Command) -> Option<&'static str> {
    match command {
        Command::CheckRuntimeConfig { json: true, .. } => Some("config check"),
        Command::Connect { json: true, .. } => Some("connect"),
        Command::Status { json: true, .. } => Some("status"),
        _ => None,
    }
}

fn load_runtime_config(path: &Path) -> Result<ConnectConfig, CliError> {
    let config = ConnectConfig::load(path).map_err(|error| CliError {
        cause: Cause::ConfigError,
        message: error.to_string(),
        retryable: false,
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let config = config.resolve_relative_to(base);
    config.validate().map_err(|error| CliError {
        cause: Cause::ConfigError,
        message: error.to_string(),
        retryable: false,
    })?;
    Ok(config)
}

fn resolve_cli_path(config_path: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_owned()
    } else {
        config_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(path)
    }
}

fn parse_command(args: &[OsString]) -> Result<Command, CliError> {
    if args.is_empty() {
        return Ok(Command::Help);
    }
    let command = args[0]
        .to_str()
        .ok_or_else(|| CliError::usage("arguments must be valid UTF-8"))?;
    match command {
        "--help" | "-h" => Ok(Command::Help),
        "--version" | "-V" => Ok(Command::Version),
        // `--help`/`-h` after a subcommand is a request for help, not an
        // invalid invocation (demo-readiness defect D6: `connect --help`
        // exited 2). It prints the one usage text every subcommand shares
        // and exits 0, wherever the flag sits among the subcommand's
        // arguments -- except as the value of a flag that takes a PATH.
        "check-config" | "config" | "connect" | "credentials" | "doctor"
            if asks_for_help(&args[1..]) =>
        {
            Ok(Command::Help)
        }
        "check-config" => {
            if args.len() > 2 {
                return Err(CliError::usage("check-config accepts at most one PATH"));
            }
            Ok(Command::LegacyCheckConfig(args.get(1).map(PathBuf::from)))
        }
        "config" => parse_config_command(args),
        "connect" => parse_connect_command(args),
        "credentials" => parse_credentials_command(args),
        "doctor" => {
            let (path, json) = parse_path_and_json(&args[1..], "doctor")?;
            Ok(Command::Doctor { path, json })
        }
        "status" => {
            let (path, json) = parse_path_and_json(&args[1..], "status")?;
            Ok(Command::Status { path, json })
        }
        _ => Err(CliError::usage("unknown command")),
    }
}

/// Flags whose next argument is a value, so a `--help` there is a PATH.
const VALUE_FLAGS: [&str; 4] = ["--config", "--csr-out", "--certificate", "--server-ca"];

/// Whether a subcommand's arguments ask for help: a `--help` or `-h` in a
/// flag position (not the value of one of [`VALUE_FLAGS`]).
fn asks_for_help(args: &[OsString]) -> bool {
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--help" | "-h") => return true,
            Some(flag) if VALUE_FLAGS.contains(&flag) => index += 2,
            _ => index += 1,
        }
    }
    false
}

fn parse_config_command(args: &[OsString]) -> Result<Command, CliError> {
    if args.get(1).and_then(|value| value.to_str()) != Some("check") {
        return Err(CliError::usage(
            "usage: tunnel-client config check --config PATH [--json]",
        ));
    }
    let (path, json) = parse_path_and_json(&args[2..], "config check")?;
    Ok(Command::CheckRuntimeConfig { path, json })
}

fn parse_connect_command(args: &[OsString]) -> Result<Command, CliError> {
    // `--no-reconnect` is `connect`'s own flag; the rest is the shared
    // `--config PATH [--json]` grammar.
    let mut no_reconnect = false;
    let rest: Vec<OsString> = args[1..]
        .iter()
        .filter(|arg| {
            let flag = arg.to_str() == Some("--no-reconnect");
            no_reconnect |= flag;
            !flag
        })
        .cloned()
        .collect();
    let (path, json) = parse_path_and_json(&rest, "connect")?;
    Ok(Command::Connect {
        path,
        json,
        no_reconnect,
    })
}

fn parse_path_and_json(args: &[OsString], command: &str) -> Result<(PathBuf, bool), CliError> {
    let mut path = None;
    let mut json = false;
    let mut index = 0;
    while index < args.len() {
        match args[index].to_str() {
            Some("--config") => {
                index += 1;
                let value = args
                    .get(index)
                    .ok_or_else(|| CliError::usage(format!("{command}: --config requires PATH")))?;
                path = Some(PathBuf::from(value));
            }
            Some("--json") => json = true,
            _ => {
                return Err(CliError::usage(format!(
                    "usage: tunnel-client {command} --config PATH [--json]{}",
                    if command == "connect" {
                        " [--no-reconnect]"
                    } else {
                        ""
                    }
                )));
            }
        }
        index += 1;
    }
    path.map(|path| (path, json))
        .ok_or_else(|| CliError::usage(format!("{command}: --config is required")))
}

fn parse_credentials_command(args: &[OsString]) -> Result<Command, CliError> {
    let subcommand = args
        .get(1)
        .ok_or_else(|| CliError::usage("credentials requires create or import"))?;
    match subcommand.to_str() {
        Some("create") => {
            let (config, csr_out) = parse_required_paths(&args[2..], &["--config", "--csr-out"])?;
            Ok(Command::CreateCredentials { config, csr_out })
        }
        Some("import") => {
            let values =
                parse_named_paths(&args[2..], &["--config", "--certificate", "--server-ca"])?;
            Ok(Command::ImportCredentials {
                config: values[0].clone(),
                certificate: values[1].clone(),
                server_ca: values[2].clone(),
            })
        }
        _ => Err(CliError::usage("credentials requires create or import")),
    }
}

fn parse_required_paths(
    args: &[OsString],
    flags: &[&str; 2],
) -> Result<(PathBuf, PathBuf), CliError> {
    let values = parse_named_paths(args, flags)?;
    Ok((values[0].clone(), values[1].clone()))
}

fn parse_named_paths<const N: usize>(
    args: &[OsString],
    flags: &[&str; N],
) -> Result<Vec<PathBuf>, CliError> {
    let mut values = vec![None; N];
    let mut index = 0;
    while index < args.len() {
        let Some(flag) = args[index].to_str() else {
            return Err(CliError::usage("arguments must be valid UTF-8"));
        };
        let Some(position) = flags.iter().position(|candidate| *candidate == flag) else {
            return Err(CliError::usage("unknown credentials option"));
        };
        index += 1;
        let value = args
            .get(index)
            .ok_or_else(|| CliError::usage(format!("{flag} requires PATH")))?;
        values[position] = Some(PathBuf::from(value));
        index += 1;
    }
    values
        .into_iter()
        .enumerate()
        .map(|(index, value)| {
            value.ok_or_else(|| CliError::usage(format!("{} requires PATH", flags[index])))
        })
        .collect()
}

fn print_ok_json<T: Serialize>(command: &str, result: T) {
    let diagnostic = Diagnostic {
        schema_version: DIAGNOSTICS_SCHEMA_VERSION,
        command,
        ok: true,
        result: Some(result),
        error: None,
    };
    println!(
        "{}",
        serde_json::to_string(&diagnostic).expect("diagnostics serialize")
    );
}

fn print_error_json(command: &str, error: &CliError) {
    let diagnostic = Diagnostic::<serde_json::Value> {
        schema_version: DIAGNOSTICS_SCHEMA_VERSION,
        command,
        ok: false,
        result: None,
        error: Some(DiagnosticError {
            code: error.code(),
            message: &error.message,
            retryable: error.retryable,
        }),
    };
    println!(
        "{}",
        serde_json::to_string(&diagnostic).expect("diagnostics serialize")
    );
}

fn usage() -> &'static str {
    "tunnel-client — Agent Uplink device connector\n\n\
Usage:\n\
  tunnel-client --help | --version\n\
  tunnel-client check-config [PATH]\n\
  tunnel-client config check --config PATH [--json]\n\
  tunnel-client doctor --config PATH [--json]\n\
  tunnel-client status --config PATH [--json]\n\
  tunnel-client connect --config PATH [--json] [--no-reconnect]\n\
  tunnel-client credentials create --config PATH --csr-out PATH\n\
  tunnel-client credentials import --config PATH --certificate PATH --server-ca PATH\n\n\
connect holds one mTLS control socket and one mTLS data socket and replaces\n\
the data socket on the profile's [rotation] interval. A transport failure\n\
ends the session; connect then starts a fresh one with bounded, jittered\n\
backoff, or exits at once with --no-reconnect."
}

#[cfg(test)]
mod tests {
    use super::*;

    /// M7-C167: `connect-status` reports the OPEN refusals the session sent,
    /// one counter per fixed code, every code always present, and nothing
    /// else changes shape.  A new count also emits a status event.
    #[test]
    fn m7c167_connect_status_reports_open_refusals_by_fixed_code_with_a_stable_schema() {
        use tunnel_protocol::open_refusal;

        let mut status = tunnel_client::ConnectionStatus {
            session_id: Some("session".to_owned()),
            control_local_addr: Some("127.0.0.1:1".parse().expect("address")),
            ..tunnel_client::ConnectionStatus::default()
        };
        let before = status.clone();
        status
            .open_refusals_sent
            .record(open_refusal::CONNECTOR_DRAINING);
        assert!(
            should_emit_connect_status(&before, &status),
            "a new refusal count emits a connect-status event"
        );

        let value = serde_json::to_value(connect_status_result(&status)).expect("serialize");
        let object = value.as_object().expect("result object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        let mut expected = vec![
            "state",
            "phase",
            "session_id",
            "epoch",
            "generation",
            "active_connection_id",
            "rotations_completed",
            "recovery_attempt",
            "recovery_attempt_started_at_ms",
            "recovery_attempt_deadline_ms",
            "recovery_episode_deadline_ms",
            "recovery_closed_connection_ids",
            "recovery_reset_reason",
            "recovery_old_generation",
            "recovery_old_connection_id",
            "recovery_successor_generation",
            "recovery_successor_connection_id",
            "control_local_addr",
            "active_local_addr",
            "candidate_local_addr",
            "drain_fences",
            "drain_acks",
            "open_refusals_sent",
        ];
        expected.sort_unstable();
        assert_eq!(keys, expected, "connect-status result schema changed");

        let refusals = object
            .get("open_refusals_sent")
            .and_then(serde_json::Value::as_object)
            .expect("open_refusals_sent is an object");
        let mut codes: Vec<&str> = refusals.keys().map(String::as_str).collect();
        codes.sort_unstable();
        let mut fixed = open_refusal::CODES.to_vec();
        fixed.sort_unstable();
        assert_eq!(
            codes, fixed,
            "exactly the fixed code labels, zeros included"
        );
        for (code, count) in refusals {
            let expected = u64::from(code == "GOAWAY");
            assert_eq!(count.as_u64(), Some(expected), "{code}");
        }
        let text = value.to_string();
        for refusal in open_refusal::ALL {
            assert!(
                !text.contains(refusal.reason()) && !text.contains(refusal.category()),
                "connect-status carries no refusal reason: {text}"
            );
        }
    }

    // ---------------------------------------------- bounded stop-path waits
    //
    // Every wait on the stop path goes through `bounded`, with the next stop
    // request as its competitor. These drive the three waits the review
    // named with a synthetic stop request, because reaching them in a real
    // process needs a relay (and, for the reap, a live MCP session). They
    // prove the waits' own logic and bounds; that `run_connect` calls them
    // is source-read (M6-C23).

    /// A stop request that fires after `delay`.
    async fn stop_after(delay: std::time::Duration) -> Result<StopSignal, CliError> {
        tokio::time::sleep(delay).await;
        Ok(StopSignal::Interrupt)
    }

    async fn never_stops() -> Result<StopSignal, CliError> {
        std::future::pending().await
    }

    /// A second signal during the reap wait exits 130 promptly, even while
    /// a child is still "running" and the 5 s bound is far away.
    #[tokio::test]
    async fn a_second_stop_during_the_reap_wait_exits_cancelled_promptly() {
        let started = std::time::Instant::now();
        let error = wait_for_supervised_children(
            || 1,
            stop_after(std::time::Duration::from_millis(50)),
            Some(StopSignal::Terminate),
        )
        .await
        .expect_err("a second stop request must abandon the reap wait");
        assert_eq!(error.exit_code(), 130);
        assert!(
            error
                .message
                .contains("SIGINT received during the orderly stop SIGTERM began"),
            "{}",
            error.message
        );
        assert!(
            started.elapsed() < std::time::Duration::from_secs(1),
            "the second stop request must end the wait at once, not at its {SUPERVISED_CHILD_REAP_BOUND:?} bound"
        );
    }

    /// A reap wait that runs out its bound reports how many children are
    /// still running, so the caller can say so, instead of returning as if
    /// they were reaped.
    #[tokio::test]
    async fn a_timed_out_reap_wait_reports_the_unreaped_count() {
        let unreaped = wait_for_supervised_children_within(
            || 2,
            std::time::Duration::from_millis(50),
            never_stops(),
            None,
        )
        .await
        .expect("a timed-out reap wait is not an error");
        assert_eq!(unreaped, 2);
        let reaped = wait_for_supervised_children_within(
            || 0,
            std::time::Duration::from_millis(50),
            never_stops(),
            None,
        )
        .await
        .expect("reaped");
        assert_eq!(reaped, 0);
    }

    /// A drain that never completes still ends within its bound, as 130.
    #[tokio::test]
    async fn a_stop_whose_join_hangs_exits_cancelled_within_the_bound() {
        let started = std::time::Instant::now();
        let error = join_after_stop(
            std::future::pending::<()>(),
            std::time::Duration::from_millis(100),
            never_stops(),
            StopSignal::Terminate,
        )
        .await
        .expect_err("a join that never completes must time out");
        assert_eq!(error.exit_code(), 130);
        assert!(
            error.message.contains("did not complete within"),
            "{}",
            error.message
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// And a second stop request ends that hung join at once, long before
    /// its bound.
    #[tokio::test]
    async fn a_second_stop_during_a_hung_join_exits_cancelled_promptly() {
        let started = std::time::Instant::now();
        let error = join_after_stop(
            std::future::pending::<()>(),
            std::time::Duration::from_secs(60),
            stop_after(std::time::Duration::from_millis(50)),
            StopSignal::Terminate,
        )
        .await
        .expect_err("a second stop request must abandon the join");
        assert_eq!(error.exit_code(), 130);
        assert!(
            error
                .message
                .contains("SIGINT received during the orderly stop"),
            "{}",
            error.message
        );
        assert!(started.elapsed() < std::time::Duration::from_secs(1));
    }

    /// The default derivation: 10 s handshake plus 30 s overlap.
    #[test]
    fn the_stop_join_bound_is_the_handshake_deadline_plus_the_overlap() {
        let config = ConnectConfig {
            rotation: tunnel_core::RotationConfig::default(),
            ..ConnectConfig::default()
        };
        assert_eq!(stop_join_bound(&config), std::time::Duration::from_secs(40));
    }

    #[test]
    fn doctor_parser_accepts_only_local_config_and_json_flags() {
        let command = parse_command(&[
            OsString::from("doctor"),
            OsString::from("--config"),
            OsString::from("profile.toml"),
            OsString::from("--json"),
        ])
        .expect("doctor command parses");
        assert!(matches!(
            command,
            Command::Doctor { path, json }
                if path == Path::new("profile.toml") && json
        ));
    }

    /// Every `Usage:` line of `--help` must agree with the parser it
    /// documents (M6-C26 item 4). The help said `doctor --config PATH --json`
    /// while the parser treats `--json` as optional, and nothing compared the
    /// two. Each line is parsed as written, with a placeholder for every
    /// `PATH`; then each bracketed flag is dropped and the line must still
    /// parse, and each unbracketed flag is dropped and the line must be
    /// refused. So a flag the help calls required is required, and one it
    /// calls optional is optional.
    #[test]
    fn every_help_usage_line_matches_the_parser() {
        let help = usage();
        let lines: Vec<&str> = help
            .lines()
            // The usage lines are the block between `Usage:` and the next
            // blank line; the title line also starts with the binary's name.
            .skip_while(|line| line.trim() != "Usage:")
            .skip(1)
            .take_while(|line| !line.trim().is_empty())
            .filter_map(|line| line.trim().strip_prefix("tunnel-client "))
            .filter(|line| !line.starts_with("--help"))
            .collect();
        assert!(
            lines.len() >= 6,
            "parsed only {} usage lines from --help",
            lines.len()
        );
        let argv = |words: &[&str]| -> Vec<OsString> {
            words
                .iter()
                .map(|word| OsString::from(if *word == "PATH" { "p.toml" } else { word }))
                .collect()
        };
        let mut optional_seen = 0;
        let mut required_seen = 0;
        for line in lines {
            let words: Vec<&str> = line.split_whitespace().collect();
            let full: Vec<&str> = words
                .iter()
                .map(|word| word.trim_start_matches('[').trim_end_matches(']'))
                .collect();
            // `check-config [PATH]` brackets a positional, not a flag.
            let full: Vec<&str> = full.into_iter().filter(|word| !word.is_empty()).collect();
            parse_command(&argv(&full))
                .unwrap_or_else(|error| panic!("`{line}` as written: {}", error.message));
            for (index, word) in words.iter().enumerate() {
                let bare = word.trim_start_matches('[').trim_end_matches(']');
                if !bare.starts_with("--") || index == 0 {
                    continue;
                }
                // A flag followed by `PATH` is removed with its value.
                let takes_value =
                    words.get(index + 1).map(|next| next.trim_end_matches(']')) == Some("PATH");
                let without: Vec<&str> = full
                    .iter()
                    .enumerate()
                    .filter(|(position, _)| {
                        *position != index && !(takes_value && *position == index + 1)
                    })
                    .map(|(_, word)| *word)
                    .collect();
                let parsed = parse_command(&argv(&without));
                if word.starts_with('[') {
                    optional_seen += 1;
                    assert!(
                        parsed.is_ok(),
                        "`{line}` marks {bare} optional, and the parser refuses the line without it"
                    );
                } else {
                    required_seen += 1;
                    assert!(
                        parsed.is_err(),
                        "`{line}` shows {bare} as required, and the parser accepts the line without it"
                    );
                }
            }
        }
        assert!(optional_seen >= 3 && required_seen >= 6);
        // M2 rotation is delivered; the help must not describe it as a future
        // milestone.
        assert!(
            !help.contains("are M2"),
            "--help still calls rotation future work"
        );
    }

    #[test]
    fn network_doctor_is_rejected_without_touching_the_network() {
        let error = parse_command(&[
            OsString::from("doctor"),
            OsString::from("--config"),
            OsString::from("profile.toml"),
            OsString::from("--network"),
            OsString::from("--json"),
        ])
        .expect_err("network doctor is outside this slice");
        assert_eq!(error.code(), "INVALID_INVOCATION");
        assert_eq!(error.exit_code(), 2);
    }

    /// Pin the code and exit status of **every** `ClientError` variant.
    ///
    /// The test this replaces asserted the old string table mapped
    /// `"CREDENTIAL_EXPIRED"` to `3` and `"TRANSPORT_ERROR"` to `4`. It was
    /// green, and it proved nothing about this binary: `CREDENTIAL_EXPIRED`
    /// is a **doctor** code, computed in `doctor.rs` against its own exit
    /// constants, and no `ClientError` has ever produced it. The table entry
    /// it exercised was dead, so the test could not redden for the failure
    /// that was actually present — six live causes falling through to
    /// `_ => 1`. See the M5-C11 list in `docs/tasks.md`.
    ///
    /// Every case below therefore starts from a constructed `ClientError`,
    /// the value a real failure path hands the CLI, rather than from a code
    /// string the test chose itself.
    #[test]
    fn every_client_error_variant_maps_to_an_actionable_exit_code() {
        let cases: [(ClientError, &str, u8); 12] = [
            (
                ClientError::Config(tunnel_client::RuntimeConfigError::Invalid("synthetic")),
                "INVALID_CONFIG",
                2,
            ),
            (
                ClientError::Credential(tunnel_client::credentials::CredentialError::KeyMismatch(
                    "synthetic".to_owned(),
                )),
                "CREDENTIAL_ERROR",
                3,
            ),
            (ClientError::Invalid("synthetic"), "INVALID_INVOCATION", 2),
            (
                ClientError::Protocol("synthetic".to_owned()),
                "PROTOCOL_ERROR",
                1,
            ),
            (
                ClientError::Transport {
                    scope: "control",
                    detail: "synthetic".to_owned(),
                },
                "TRANSPORT_ERROR",
                4,
            ),
            (ClientError::OwnerBusy, "OWNER_BUSY", 7),
            (
                ClientError::TlsRefused("synthetic fixed reason"),
                "CREDENTIAL_ERROR",
                3,
            ),
            (ClientError::HandshakeTimeout, "DEADLINE_EXCEEDED", 5),
            (ClientError::AuthorizationExpired, "AUTHORIZATION_STALE", 4),
            (ClientError::QueueLimit, "RESOURCE_EXHAUSTED", 7),
            (ClientError::OpenRetentionFull, "RESOURCE_EXHAUSTED", 7),
            (ClientError::Cancelled, "CANCELLED", 130),
        ];
        let mut seen = std::collections::BTreeSet::new();
        for (error, expected_code, expected_exit) in cases {
            let described = format!("{error:?}");
            let cli = CliError::from_client(error);
            assert_eq!(cli.code(), expected_code, "code for {described}");
            assert_eq!(cli.exit_code(), expected_exit, "exit code for {described}");
            seen.insert(expected_code);
        }
        // `SupervisorPanicked` is the thirteenth variant and is covered by
        // `only_protocol_and_supervisor_failures_exit_one` below, which also
        // states why it is one of the two that may stay at `1`.
        assert_eq!(
            CliError::from_client(ClientError::SupervisorPanicked).exit_code(),
            1,
            "a failed supervisor is genuinely internal"
        );
        assert_eq!(seen.len(), 10, "ten distinct codes across twelve variants");
    }

    /// The point of the change: causes that need different operator actions
    /// must not share an exit code, and `1` must mean "unexpected".
    ///
    /// Before this change all four of the values compared here were `1`, so
    /// every one of these assertions fails on the old mapping. That is the
    /// red half, and `scripts/m0-guard-exit-codes.py` reproduces it by
    /// restoring the fallback arm in the product body.
    #[test]
    fn causes_needing_different_actions_do_not_share_an_exit_code() {
        let owner_busy = CliError::from_client(ClientError::OwnerBusy).exit_code();
        let cancelled = CliError::from_client(ClientError::Cancelled).exit_code();
        let stale = CliError::from_client(ClientError::AuthorizationExpired).exit_code();
        let internal = CliError::from_client(ClientError::SupervisorPanicked).exit_code();

        assert_ne!(
            owner_busy, internal,
            "another connector holding the device is not an internal failure: \
             the operator stops that connector"
        );
        assert_ne!(
            cancelled, internal,
            "an interrupted session is not an internal failure: the operator \
             re-runs it"
        );
        assert_ne!(
            stale, internal,
            "a lapsed stream authorization window is not an internal failure: \
             the operator checks the data path and retries"
        );
        assert_ne!(
            owner_busy, cancelled,
            "a held owner slot and an interruption need different actions"
        );

        // …and the separations are the documented ones, not merely *some*
        // three different numbers. An `assert_ne!` triple is satisfied by any
        // distinct values, including nonsense ones, so pin the table too.
        assert_eq!(owner_busy, 7, "refused before dispatch");
        assert_eq!(cancelled, 130, "interrupted before orderly completion");
        assert_eq!(
            stale, 4,
            "a lapsed stream authorization window is transport class (M6-C39)"
        );
        assert_eq!(internal, 1, "unexpected internal failure");
    }

    /// Every status this binary can produce must be in the vocabulary the
    /// library publishes, because other crates classify against that.
    ///
    /// The production-cluster chaos gate buckets a connector's pre-readiness
    /// exit, and it used to hold its own copy of the list beside a comment
    /// naming `CliError::exit_code` as the source. Adding `7` and `130` here
    /// made that copy wrong, and nothing could have said so: a comment is
    /// not a link. The copy is gone, and this is the assertion that keeps
    /// the remaining one honest in the other direction — a cause mapped to
    /// an unpublished status fails here rather than at a release gate.
    /// Every `Cause`, in declaration order.
    ///
    /// **This list used to be able to fall behind the enum silently, and
    /// did** (task row M6-C131): its comment said a new variant "breaks the
    /// build" in `Cause::code` first, which is true and irrelevant -- the
    /// author then adds the arm there and nothing touches this list. Adding
    /// `SUPERVISOR_ABSENT` with exit `8` left the test green while `8` was
    /// missing from `CLI_DIAGNOSTIC_EXIT_CODES`. `cause_index` is an
    /// exhaustive match with no fallback arm into this array, and the test
    /// below requires the two to agree, so a new variant now fails to build
    /// until it is listed here.
    const ALL_CAUSES: [Cause; 18] = [
        Cause::InvalidInvocation,
        Cause::ConfigError,
        Cause::InvalidConfig,
        Cause::CredentialError,
        Cause::AuthorizationStale,
        Cause::TransportError,
        Cause::SessionClosed,
        Cause::DeadlineExceeded,
        Cause::OwnerBusy,
        Cause::ResourceExhausted,
        Cause::Cancelled,
        Cause::ProtocolError,
        Cause::SupervisorFailed,
        Cause::SignalError,
        Cause::SupervisorAbsent,
        Cause::SupervisorRunning,
        Cause::IpcUnauthorized,
        Cause::SupervisorLockFailed,
    ];

    fn cause_index(cause: Cause) -> usize {
        match cause {
            Cause::InvalidInvocation => 0,
            Cause::ConfigError => 1,
            Cause::InvalidConfig => 2,
            Cause::CredentialError => 3,
            Cause::AuthorizationStale => 4,
            Cause::TransportError => 5,
            Cause::SessionClosed => 6,
            Cause::DeadlineExceeded => 7,
            Cause::OwnerBusy => 8,
            Cause::ResourceExhausted => 9,
            Cause::Cancelled => 10,
            Cause::ProtocolError => 11,
            Cause::SupervisorFailed => 12,
            Cause::SignalError => 13,
            Cause::SupervisorAbsent => 14,
            Cause::SupervisorRunning => 15,
            Cause::IpcUnauthorized => 16,
            Cause::SupervisorLockFailed => 17,
        }
    }

    #[test]
    fn the_cause_list_is_every_cause_exactly_once() {
        for (index, cause) in ALL_CAUSES.iter().enumerate() {
            assert_eq!(
                cause_index(*cause),
                index,
                "{cause:?} is listed out of place"
            );
        }
    }

    #[test]
    fn every_exit_status_is_in_the_published_vocabulary() {
        let causes = ALL_CAUSES;
        for cause in causes {
            let status = cause.exit_code();
            assert!(
                tunnel_client::CLI_DIAGNOSTIC_EXIT_CODES.contains(&status),
                "{cause:?} exits {status}, which is not in \
                 CLI_DIAGNOSTIC_EXIT_CODES; add it there and to the table in \
                 docs/runtime.md, or classify the cause differently"
            );
        }
        let codes: std::collections::BTreeSet<&str> =
            causes.iter().map(|cause| cause.code()).collect();
        assert_eq!(
            codes.len(),
            causes.len(),
            "every cause publishes a distinct code"
        );
    }

    /// One of every `ClientError` variant, for tests that must sweep them.
    ///
    /// Hand-written, and it cannot fall behind silently: `Cause::from_client`
    /// is an exhaustive match, so a new variant breaks the build there before
    /// any test runs, and the sweeps below pin this list's length.
    fn every_client_error() -> Vec<ClientError> {
        vec![
            ClientError::Config(tunnel_client::RuntimeConfigError::Invalid("s")),
            ClientError::Credential(tunnel_client::credentials::CredentialError::KeyMismatch(
                "s".to_owned(),
            )),
            ClientError::Invalid("s"),
            ClientError::Protocol("s".to_owned()),
            ClientError::Transport {
                scope: "control",
                detail: "s".to_owned(),
            },
            ClientError::OwnerBusy,
            ClientError::HandshakeTimeout,
            ClientError::AuthorizationExpired,
            ClientError::QueueLimit,
            ClientError::OpenRetentionFull,
            ClientError::Cancelled,
            ClientError::SupervisorPanicked,
        ]
    }

    /// The CLI and the library must publish the **same** diagnostic string
    /// for the same failure.
    ///
    /// `ClientError::code` is `pub` and still consumed by the library itself
    /// and by the production-cluster harness. `Cause::code` is a second,
    /// hand-maintained table of the same eleven strings, introduced by this
    /// row: before it, the CLI called `error.code()` and there was one table.
    /// Two tables with no assertion between them is precisely the pattern
    /// this row removed from the chaos gate one crate over -- a copy beside
    /// a comment -- and it would drift the same way, leaving `--json` output
    /// and harness messages naming the same failure differently.
    ///
    /// `Cause` deliberately has three variants with no `ClientError`
    /// counterpart (`ConfigError`, `SessionClosed`, `SignalError`), which is
    /// why this is an assertion rather than a derivation.
    #[test]
    fn the_cli_and_the_library_publish_the_same_diagnostic_code() {
        let errors = every_client_error();
        assert_eq!(errors.len(), 12, "one entry per ClientError variant");
        for error in errors {
            let described = format!("{error:?}");
            assert_eq!(
                Cause::from_client(&error).code(),
                error.code(),
                "the CLI and the library disagree about the code for {described}"
            );
        }
    }

    /// Exit `1` is reserved for a protocol violation and a failed supervisor.
    /// Anything else landing there is the regression this row exists to stop.
    #[test]
    fn only_protocol_and_supervisor_failures_exit_one() {
        let internal: Vec<&'static str> = every_client_error()
            .into_iter()
            .map(CliError::from_client)
            .filter(|error| error.exit_code() == 1)
            .map(|error| error.code())
            .collect();
        assert_eq!(
            internal,
            vec!["PROTOCOL_ERROR", "SUPERVISOR_FAILED"],
            "only a protocol violation and a failed supervisor may exit 1; \
             anything else here has no operator action and needs its own code"
        );
    }

    #[test]
    fn owner_busy_cli_diagnostic_is_terminal_and_actionable() {
        let error = CliError::from_client(ClientError::OwnerBusy);
        assert_eq!(error.code(), "OWNER_BUSY");
        assert!(!error.retryable);
        // Was `1`. A held owner slot is not an internal failure: the
        // operator stops the other connector. See `Cause::exit_code`.
        assert_eq!(error.exit_code(), 7);
        assert!(
            error
                .message
                .contains("stop it before starting another session")
        );
        assert!(!error.message.contains("token"));
        assert!(!error.message.contains("redis"));
    }

    #[test]
    fn closed_session_preserves_the_supervisor_error() {
        let error =
            closed_session_error("closed: owner busy".to_owned(), Err(ClientError::OwnerBusy));
        assert_eq!(error.code(), "OWNER_BUSY");
        assert!(!error.retryable);
        assert!(
            error
                .message
                .contains("stop it before starting another session")
        );
    }

    #[test]
    fn closed_session_falls_back_only_after_a_clean_stop() {
        let error = closed_session_error("stopped".to_owned(), Ok(()));
        assert_eq!(error.code(), "SESSION_CLOSED");
        assert!(error.retryable);
        assert_eq!(error.message, "stopped");
    }

    /// IN-09: an exhausted recovery episode must report its typed cause even
    /// when the connector's channels have already stopped.
    ///
    /// The supervisor publishes `Readiness::Closed` with the typed reason and
    /// then returns, dropping both watch senders at once, so the CLI's select
    /// loop can observe a stopped status publisher in the same poll as the
    /// retained terminal readiness.  This drops the publisher *before* the
    /// terminal is consulted -- the exact ordering that made a loaded sweep
    /// report `SUPERVISOR_FAILED` for an episode that had really exhausted
    /// its third attempt -- and requires the typed diagnostic to survive.
    #[test]
    fn stopped_status_publisher_still_reports_the_typed_terminal_cause() {
        let terminal = concat!(
            "retained recovery failed: control socket closed during retained recovery; ",
            "recovery_trigger=data_reader_closed; recovery_role=active; ",
            "recovery_generation=1; recovery_attempt=3"
        );
        let (readiness_tx, mut readiness) =
            tokio::sync::watch::channel(tunnel_client::Readiness::Connecting);
        readiness_tx
            .send(tunnel_client::Readiness::Closed {
                reason: terminal.to_owned(),
            })
            .expect("the supervisor publishes its typed terminal readiness");
        // The publisher stops before the caller classifies the failure.
        drop(readiness_tx);

        let reason = retained_closed_reason(&mut readiness)
            .expect("a stopped publisher must not erase the retained terminal cause");
        assert_eq!(reason, terminal);

        // Joining the already-finished supervisor normally yields its own
        // typed error, which is the same retained-recovery cause.
        let joined = closed_session_error(
            reason.clone(),
            Err(ClientError::Transport {
                scope: "retained recovery",
                detail: concat!(
                    "control socket closed during retained recovery; ",
                    "recovery_trigger=data_reader_closed; recovery_role=active; ",
                    "recovery_generation=1; recovery_attempt=3"
                )
                .to_owned(),
            }),
        );
        assert_eq!(joined.code(), "TRANSPORT_ERROR");
        assert!(joined.message.contains("recovery_attempt=3"));
        assert!(
            joined
                .message
                .contains("recovery_trigger=data_reader_closed")
        );

        // A supervisor that was already reaped reports a clean stop, and the
        // retained reason is then the diagnostic itself.
        let reaped = closed_session_error(reason, Ok(()));
        assert_eq!(reaped.code(), "SESSION_CLOSED");
        assert!(reaped.message.contains("recovery_attempt=3"));

        for error in [joined, reaped] {
            assert_ne!(error.code(), "SUPERVISOR_FAILED");
            assert!(!error.message.contains("status publisher stopped"));
        }
    }

    /// The generic supervisor failure is still the right answer when the
    /// connector stopped without ever publishing a terminal reason, so the
    /// fix above cannot invent a typed cause for a panicked supervisor.
    #[test]
    fn stopped_publisher_without_a_terminal_reason_stays_a_supervisor_failure() {
        let (readiness_tx, mut readiness) =
            tokio::sync::watch::channel(tunnel_client::Readiness::Connecting);
        readiness_tx
            .send(tunnel_client::Readiness::Stopping)
            .expect("a non-terminal readiness is published");
        drop(readiness_tx);
        assert!(retained_closed_reason(&mut readiness).is_none());
    }

    // ------------------------------------------------ reconnect (M6-C23)

    fn policy(initial_ms: u64, max_ms: u64, max_attempts: u32) -> ReconnectPolicy {
        ReconnectPolicy::new(
            &tunnel_client::ReconnectConfig {
                enabled: true,
                initial_delay_ms: initial_ms,
                max_delay_ms: max_ms,
                max_attempts,
            },
            false,
        )
    }

    /// The classification docs/runtime.md publishes, cause by cause. A
    /// change to any arm must change this table and the document together.
    #[test]
    fn reconnect_classification_matches_the_documented_table() {
        use ReconnectClass::{OwnerBusy, Retryable, Terminal};
        let table = [
            (Cause::InvalidInvocation, Terminal),
            (Cause::ConfigError, Terminal),
            (Cause::InvalidConfig, Terminal),
            (Cause::CredentialError, Terminal),
            (Cause::AuthorizationStale, Retryable),
            (Cause::TransportError, Retryable),
            (Cause::SessionClosed, Retryable),
            (Cause::DeadlineExceeded, Retryable),
            (Cause::OwnerBusy, OwnerBusy),
            (Cause::ResourceExhausted, Retryable),
            (Cause::Cancelled, Terminal),
            (Cause::ProtocolError, Terminal),
            (Cause::SupervisorFailed, Terminal),
            (Cause::SignalError, Terminal),
        ];
        for (cause, class) in table {
            assert_eq!(cause.reconnect_class(), class, "{cause:?}");
        }
        // A TLS certificate refusal is a credential error, so terminal.
        let refused = CliError::from_client(ClientError::TlsRefused("synthetic"));
        assert_eq!(refused.cause.reconnect_class(), Terminal);
        assert!(!refused.retryable);
    }

    /// `OWNER_BUSY` on a fresh process's first attempt is another
    /// connector: exit `7` at once, as before. After this process's own
    /// session ended it is that session's lease, retried -- but only inside
    /// the window.
    #[test]
    fn owner_busy_is_retried_only_within_the_window_after_our_own_session() {
        let policy = policy(1_000, 60_000, 0);
        let start = tokio::time::Instant::now();
        let mut fresh = ReconnectState::default();
        assert_eq!(
            fresh.decide(&policy, Cause::OwnerBusy, None, start, 0),
            ReconnectDecision::Exit
        );

        let mut state = ReconnectState::default();
        let lost = start;
        assert!(matches!(
            state.decide(
                &policy,
                Cause::TransportError,
                Some(std::time::Duration::from_secs(5)),
                lost,
                0
            ),
            ReconnectDecision::Retry { attempt: 1, .. }
        ));
        assert!(matches!(
            state.decide(
                &policy,
                Cause::OwnerBusy,
                None,
                lost + std::time::Duration::from_secs(30),
                0
            ),
            ReconnectDecision::Retry { attempt: 2, .. }
        ));
        assert_eq!(
            state.decide(
                &policy,
                Cause::OwnerBusy,
                None,
                lost + OWNER_BUSY_RECONNECT_WINDOW,
                0
            ),
            ReconnectDecision::Exit
        );
    }

    /// Consecutive failures double the ceiling; a session that stayed ready
    /// for `max_delay` resets it, a shorter one does not (a relay that
    /// accepts and drops at once still backs off).
    #[test]
    fn backoff_grows_is_capped_and_resets_only_after_a_stable_session() {
        let policy = policy(1_000, 60_000, 0);
        let ceilings: Vec<u64> = (1..=9)
            .map(|attempt| policy.ceiling(attempt).as_millis() as u64)
            .collect();
        assert_eq!(
            ceilings,
            [
                1_000, 2_000, 4_000, 8_000, 16_000, 32_000, 60_000, 60_000, 60_000
            ]
        );
        assert_eq!(policy.ceiling(u32::MAX).as_millis(), 60_000);
        for random in [0, 1, 499, 500, 501, u64::MAX] {
            let delay = policy.delay(3, random).as_millis() as u64;
            assert!((2_000..=4_000).contains(&delay), "{random} -> {delay}");
        }
        assert_eq!(policy.delay(3, 0).as_millis(), 2_000);
        assert_eq!(policy.delay(3, 2_000).as_millis(), 4_000);

        let now = tokio::time::Instant::now();
        let mut state = ReconnectState::default();
        for expected in 1..=3 {
            assert!(matches!(
                state.decide(&policy, Cause::TransportError, None, now, 0),
                ReconnectDecision::Retry { attempt, .. } if attempt == expected
            ));
        }
        // Ready for 10 s, less than max_delay: keeps counting.
        assert!(matches!(
            state.decide(
                &policy,
                Cause::SessionClosed,
                Some(std::time::Duration::from_secs(10)),
                now,
                0
            ),
            ReconnectDecision::Retry { attempt: 4, .. }
        ));
        // Ready for max_delay: starts again at 1.
        assert!(matches!(
            state.decide(
                &policy,
                Cause::SessionClosed,
                Some(std::time::Duration::from_secs(60)),
                now,
                0
            ),
            ReconnectDecision::Retry { attempt: 1, .. }
        ));
        assert_eq!(state.sessions, 2);
    }

    /// `max_attempts` bounds consecutive retries; `--no-reconnect` and a
    /// terminal cause never retry.
    #[test]
    fn attempt_limit_no_reconnect_and_terminal_causes_exit() {
        let now = tokio::time::Instant::now();
        let limited = policy(100, 200, 2);
        let mut state = ReconnectState::default();
        for _ in 0..2 {
            assert!(matches!(
                state.decide(&limited, Cause::TransportError, None, now, 0),
                ReconnectDecision::Retry { .. }
            ));
        }
        assert_eq!(
            state.decide(&limited, Cause::TransportError, None, now, 0),
            ReconnectDecision::Exit
        );

        let off = ReconnectPolicy::new(&tunnel_client::ReconnectConfig::default(), true);
        assert!(!off.enabled);
        assert_eq!(
            ReconnectState::default().decide(&off, Cause::TransportError, None, now, 0),
            ReconnectDecision::Exit
        );
        assert_eq!(
            ReconnectState::default().decide(
                &policy(100, 200, 0),
                Cause::CredentialError,
                None,
                now,
                0
            ),
            ReconnectDecision::Exit
        );
    }

    #[test]
    fn connect_accepts_no_reconnect_anywhere_among_its_flags() {
        for args in [
            &["connect", "--no-reconnect", "--config", "p.toml", "--json"][..],
            &["connect", "--config", "p.toml", "--no-reconnect"][..],
        ] {
            let args: Vec<OsString> = args.iter().map(OsString::from).collect();
            let Ok(Command::Connect { no_reconnect, .. }) = parse_command(&args) else {
                panic!("{args:?} did not parse as connect");
            };
            assert!(no_reconnect);
        }
        let args: Vec<OsString> = ["connect", "--config", "p.toml"]
            .iter()
            .map(OsString::from)
            .collect();
        assert!(matches!(
            parse_command(&args),
            Ok(Command::Connect {
                no_reconnect: false,
                ..
            })
        ));
    }
}
