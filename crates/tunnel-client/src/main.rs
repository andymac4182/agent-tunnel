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
    ///   `AUTHORIZATION_STALE` belongs here and not in the generic bucket:
    ///   the documented meaning is "untrusted credentials / authorization
    ///   denied", and the fix is to re-authorize, not to retry.
    /// * `4` — the relay or the network could not be reached, or closed the
    ///   session. A retry is meaningful once reachability returns.
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
            Self::CredentialError | Self::AuthorizationStale => 3,
            Self::TransportError | Self::SessionClosed => 4,
            Self::DeadlineExceeded => 5,
            Self::OwnerBusy | Self::ResourceExhausted => 7,
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
            ClientError::HandshakeTimeout => Self::DeadlineExceeded,
            ClientError::AuthorizationExpired => Self::AuthorizationStale,
            ClientError::QueueLimit | ClientError::OpenRetentionFull => Self::ResourceExhausted,
            ClientError::Cancelled => Self::Cancelled,
            ClientError::SupervisorPanicked => Self::SupervisorFailed,
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
        return run_doctor(path.clone(), *json);
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
        Command::Connect { path, json } => run_connect(path, json).await,
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
            Ok(())
        }
        Command::Doctor { .. } => unreachable!("doctor is handled before the async command runner"),
    }
}

fn run_doctor(path: PathBuf, json: bool) -> ExitCode {
    let inspection = doctor::inspect(&path, SystemTime::now());
    if json {
        println!(
            "{}",
            serde_json::to_string(&inspection.output).expect("doctor diagnostics serialize")
        );
    } else if inspection.output.ok {
        println!("Local configuration, credential key match, permissions, and expiry are healthy.");
        println!("Supervisor IPC: not implemented in this operations slice.");
    } else if let Some(error) = &inspection.output.error {
        eprintln!("tunnel-client doctor: {}", error.message);
    } else {
        eprintln!("tunnel-client doctor: local checks failed");
    }
    ExitCode::from(inspection.exit_code)
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

async fn run_connect(path: PathBuf, json: bool) -> Result<(), CliError> {
    // First, before any file is read or socket opened: from here on a stop
    // request in any phase reaches the orderly path below instead of the
    // inherited disposition.
    let mut stop = StopSignals::install()?;
    let config = load_runtime_config(&path)?;
    let stop_bound = stop_join_bound(&config);
    // Configured MCP and ACP exports become in-process http-forward/1
    // handlers; an http-forward export without one is still refused at OPEN.
    // **Both registrations run**, because an `[exports.<id>.acp]` table that
    // was parsed and validated and then never registered would be an export
    // the operator configured and the binary silently refused.
    let handlers = tunnel_client::http_forward::HttpHandlers::new()
        .with_mcp_exports(&config)
        .map_err(|error| CliError {
            cause: Cause::ConfigError,
            message: error.to_string(),
            retryable: false,
        })?
        .with_acp_exports(&config)
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
        config,
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
        result = &mut connect => (result.map_err(CliError::from_client)?, None),
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
    let outcome = match stop_requested {
        Some(signal) => Ok(signal),
        None => run_session(&handle, &mut stop, stop_bound, json).await,
    };
    match outcome {
        Ok(first) => {
            cancellation.cancel();
            join_after_stop(handle.stop(), stop_bound, stop.recv(), first).await?;
            wait_for_supervised_children(
                || mcp_children.children_running(),
                stop.recv(),
                Some(first),
            )
            .await?;
            if json {
                print_ok_json(
                    "connect",
                    ConnectResult {
                        state: "stopped",
                        session_id: None,
                        epoch: None,
                        generation: None,
                        failure_policy: M1_TRANSPORT_FAILURE_POLICY,
                        signal: Some(first.name()),
                    },
                );
            } else {
                println!("Stopped.");
            }
            Ok(())
        }
        // A second stop request already abandoned the drain; that operator
        // has asked not to wait, and the children's kill was never requested.
        Err(error) if error.cause == Cause::Cancelled => Err(error),
        Err(error) => {
            wait_for_supervised_children(|| mcp_children.children_running(), stop.recv(), None)
                .await?;
            Err(error)
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
/// one, when no sentinel is installed. A timed-out wait is not an error.
async fn wait_for_supervised_children<R, S>(
    running: R,
    next_stop: S,
    first: Option<StopSignal>,
) -> Result<(), CliError>
where
    R: Fn() -> u64,
    S: std::future::Future<Output = Result<StopSignal, CliError>>,
{
    let reaped = async {
        while running() > 0 {
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };
    match bounded(reaped, SUPERVISED_CHILD_REAP_BOUND, next_stop).await? {
        Bounded::Done(()) | Bounded::TimedOut => Ok(()),
        Bounded::Interrupted(second) => Err(abandoned(
            second,
            first,
            "supervised MCP children to be reaped",
        )),
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
                    failure_policy: M1_TRANSPORT_FAILURE_POLICY,
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
            || previous.drain_acks != current.drain_acks)
}

fn print_connect_status(status: &tunnel_client::ConnectionStatus) {
    print_ok_json(
        "connect-status",
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
        },
    );
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
        _ => Err(CliError::usage("unknown command")),
    }
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
    let (path, json) = parse_path_and_json(&args[1..], "connect")?;
    Ok(Command::Connect { path, json })
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
                    "usage: tunnel-client {command} --config PATH"
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
    "tunnel-client — Agent Tunnel M1 connector\n\n\
Usage:\n\
  tunnel-client --help | --version\n\
  tunnel-client check-config [PATH]\n\
  tunnel-client config check --config PATH [--json]\n\
  tunnel-client doctor --config PATH --json\n\
  tunnel-client connect --config PATH [--json]\n\
  tunnel-client credentials create --config PATH --csr-out PATH\n\
  tunnel-client credentials import --config PATH --certificate PATH --server-ca PATH\n\n\
M1 uses one mTLS control socket and one mTLS data socket. Transport failure\n\
closes both sockets and requires a fresh session; rotation and resume are M2."
}

#[cfg(test)]
mod tests {
    use super::*;

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
        let cases: [(ClientError, &str, u8); 11] = [
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
            (ClientError::HandshakeTimeout, "DEADLINE_EXCEEDED", 5),
            (ClientError::AuthorizationExpired, "AUTHORIZATION_STALE", 3),
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
        // `SupervisorPanicked` is the twelfth variant and is covered by
        // `only_protocol_and_supervisor_failures_exit_one` below, which also
        // states why it is one of the two that may stay at `1`.
        assert_eq!(
            CliError::from_client(ClientError::SupervisorPanicked).exit_code(),
            1,
            "a failed supervisor is genuinely internal"
        );
        assert_eq!(seen.len(), 10, "ten distinct codes across eleven variants");
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
            "a stale authorization is not an internal failure: the operator \
             re-authorizes"
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
        assert_eq!(stale, 3, "authorization denied");
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
    #[test]
    fn every_exit_status_is_in_the_published_vocabulary() {
        let causes = [
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
        ];
        for cause in causes {
            let status = cause.exit_code();
            assert!(
                tunnel_client::CLI_DIAGNOSTIC_EXIT_CODES.contains(&status),
                "{cause:?} exits {status}, which is not in \
                 CLI_DIAGNOSTIC_EXIT_CODES; add it there and to the table in \
                 docs/runtime.md, or classify the cause differently"
            );
        }
        // The list above is a hand-written enumeration and could fall behind
        // the enum. It cannot fall behind silently: `Cause::code` is an
        // exhaustive match, so a new variant breaks the build there first,
        // and the codes below pin this list's size and contents against the
        // set of published codes.
        let codes: std::collections::BTreeSet<&str> =
            causes.iter().map(|cause| cause.code()).collect();
        assert_eq!(causes.len(), 14, "one entry per Cause variant");
        assert_eq!(codes.len(), 14, "every cause publishes a distinct code");
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
}
