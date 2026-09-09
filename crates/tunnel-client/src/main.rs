use std::{
    env,
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

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

#[tokio::main]
async fn main() -> ExitCode {
    let args = env::args_os().skip(1).collect::<Vec<_>>();
    let command = match parse_command(&args) {
        Ok(command) => command,
        Err(error) => {
            eprintln!("tunnel-client: {}", error.message);
            eprintln!("{}", usage());
            return ExitCode::FAILURE;
        }
    };
    let json_command = diagnostic_command(&command);
    match run(command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            if let Some(command) = json_command {
                print_error_json(command, &error);
            } else {
                eprintln!("tunnel-client: {}", error.message);
            }
            ExitCode::FAILURE
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
    let cancellation = CancellationToken::new();
    let options = ConnectOptions {
        config,
        cancellation: cancellation.clone(),
        profile: tunnel_client::TransportProfile::M2,
    };
    let handle = match connect(options).await {
        Ok(handle) => handle,
        Err(error) => {
            let error = CliError::from_client(error);
            return Err(error);
        }
    };
    let mut readiness = handle.readiness();
    let initial = readiness.borrow_and_update().clone();
    if let tunnel_client::Readiness::Closed { reason } = initial {
        let error = CliError {
            code: "SESSION_CLOSED",
            message: reason,
            retryable: true,
        };
        let _ = handle.stop().await;
        return Err(error);
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
                changed.map_err(|_| CliError { code: "SUPERVISOR_FAILED", message: "connector supervisor stopped".to_owned(), retryable: false })?;
                let state = readiness.borrow_and_update().clone();
                if let tunnel_client::Readiness::Closed { reason } = state {
                    let error = CliError { code: "SESSION_CLOSED", message: reason, retryable: true };
                    let _ = handle.stop().await;
                    return Err(error);
                }
            }
        }
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
  tunnel-client connect --config PATH [--json]\n\
  tunnel-client credentials create --config PATH --csr-out PATH\n\
  tunnel-client credentials import --config PATH --certificate PATH --server-ca PATH\n\n\
M1 uses one mTLS control socket and one mTLS data socket. Transport failure\n\
closes both sockets and requires a fresh session; rotation and resume are M2."
}
