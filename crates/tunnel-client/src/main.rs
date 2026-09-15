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
    ClientError, ConnectConfig, ConnectOptions, M1_TRANSPORT_FAILURE_POLICY, connect,
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

#[derive(Debug)]
struct CliError {
    code: &'static str,
    message: String,
    retryable: bool,
}

impl CliError {
    fn usage(message: impl Into<String>) -> Self {
        Self {
            code: "INVALID_INVOCATION",
            message: message.into(),
            retryable: false,
        }
    }

    fn from_client(error: ClientError) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
            retryable: error.retryable(),
        }
    }

    fn exit_code(&self) -> u8 {
        match self.code {
            "INVALID_INVOCATION" | "CONFIG_ERROR" | "INVALID_CONFIG" => 2,
            "CREDENTIAL_ERROR"
            | "CREDENTIAL_MISSING"
            | "CREDENTIAL_INVALID"
            | "CREDENTIAL_KEY_MISMATCH"
            | "CREDENTIAL_PERMISSIONS"
            | "CREDENTIAL_EXPIRED"
            | "CREDENTIAL_NOT_YET_VALID" => 3,
            "TRANSPORT_ERROR" | "SUPERVISOR_ABSENT" => 4,
            "DEADLINE_EXCEEDED" => 5,
            "OUTCOME_UNKNOWN" => 6,
            _ => 1,
        }
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

#[tokio::main]
async fn main() -> ExitCode {
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
                code: "CREDENTIAL_ERROR",
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
                    code: "CREDENTIAL_ERROR",
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
                code: "CONFIG_ERROR",
                message: format!("could not read legacy configuration: {error}"),
                retryable: false,
            })?;
            ClientConfig::parse(&input).map_err(|error| CliError {
                code: "CONFIG_ERROR",
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

async fn run_connect(path: PathBuf, json: bool) -> Result<(), CliError> {
    let config = load_runtime_config(&path)?;
    // Configured MCP exports become in-process http-forward/1 handlers; an
    // http-forward export without one is still refused at OPEN.
    let handlers = tunnel_client::http_forward::HttpHandlers::new()
        .with_mcp_exports(&config)
        .map_err(|error| CliError {
            code: "CONFIG_ERROR",
            message: error.to_string(),
            retryable: false,
        })?;
    let cancellation = CancellationToken::new();
    let options = ConnectOptions {
        config,
        cancellation: cancellation.clone(),
        profile: tunnel_client::TransportProfile::M2,
    };
    let handle = match tunnel_client::connect_with_http_handlers(options, handlers).await {
        Ok(handle) => handle,
        Err(error) => {
            let error = CliError::from_client(error);
            return Err(error);
        }
    };
    let mut readiness = handle.readiness();
    let initial = readiness.borrow_and_update().clone();
    if let tunnel_client::Readiness::Closed { reason } = initial {
        return Err(closed_session_error(reason, handle.stop().await));
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
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|error| CliError { code: "SIGNAL_ERROR", message: error.to_string(), retryable: false })?;
                cancellation.cancel();
                let _ = handle.stop().await;
                if json {
                    print_ok_json("connect", ConnectResult { state: "stopped", session_id: None, epoch: None, generation: None, failure_policy: M1_TRANSPORT_FAILURE_POLICY });
                } else {
                    println!("Stopped.");
                }
                return Ok(());
            }
            changed = readiness.changed() => {
                if changed.is_err() {
                    return Err(stopped_connector_error(&mut readiness, &handle, "connector supervisor stopped").await);
                }
                let state = readiness.borrow_and_update().clone();
                if let tunnel_client::Readiness::Closed { reason } = state {
                    return Err(closed_session_error(reason, handle.stop().await));
                }
            }
            changed = status.changed() => {
                if changed.is_err() {
                    // The status publisher stopping must not outrank the
                    // typed terminal cause the readiness channel still holds.
                    return Err(stopped_connector_error(&mut readiness, &handle, "connector status publisher stopped").await);
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
    fallback_message: &'static str,
) -> CliError {
    match retained_closed_reason(readiness) {
        Some(reason) => closed_session_error(reason, handle.stop().await),
        None => CliError {
            code: "SUPERVISOR_FAILED",
            message: fallback_message.to_owned(),
            retryable: false,
        },
    }
}

fn closed_session_error(reason: String, stop_result: Result<(), ClientError>) -> CliError {
    match stop_result {
        Ok(()) => CliError {
            code: "SESSION_CLOSED",
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
        code: "CONFIG_ERROR",
        message: error.to_string(),
        retryable: false,
    })?;
    let base = path.parent().unwrap_or_else(|| Path::new("."));
    let config = config.resolve_relative_to(base);
    config.validate().map_err(|error| CliError {
        code: "CONFIG_ERROR",
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
            code: error.code,
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
        assert_eq!(error.code, "INVALID_INVOCATION");
        assert_eq!(error.exit_code(), 2);
    }

    #[test]
    fn cli_exit_codes_distinguish_config_credentials_and_transport() {
        assert_eq!(
            CliError::usage("bad invocation").exit_code(),
            2,
            "invalid invocation"
        );
        assert_eq!(
            CliError {
                code: "CREDENTIAL_EXPIRED",
                message: String::new(),
                retryable: false,
            }
            .exit_code(),
            3,
            "credential failure"
        );
        assert_eq!(
            CliError {
                code: "TRANSPORT_ERROR",
                message: String::new(),
                retryable: true,
            }
            .exit_code(),
            4,
            "transport failure"
        );
    }

    #[test]
    fn owner_busy_cli_diagnostic_is_terminal_and_actionable() {
        let error = CliError::from_client(ClientError::OwnerBusy);
        assert_eq!(error.code, "OWNER_BUSY");
        assert!(!error.retryable);
        assert_eq!(error.exit_code(), 1);
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
        assert_eq!(error.code, "OWNER_BUSY");
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
        assert_eq!(error.code, "SESSION_CLOSED");
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
        assert_eq!(joined.code, "TRANSPORT_ERROR");
        assert!(joined.message.contains("recovery_attempt=3"));
        assert!(
            joined
                .message
                .contains("recovery_trigger=data_reader_closed")
        );

        // A supervisor that was already reaped reports a clean stop, and the
        // retained reason is then the diagnostic itself.
        let reaped = closed_session_error(reason, Ok(()));
        assert_eq!(reaped.code, "SESSION_CLOSED");
        assert!(reaped.message.contains("recovery_attempt=3"));

        for error in [joined, reaped] {
            assert_ne!(error.code, "SUPERVISOR_FAILED");
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
