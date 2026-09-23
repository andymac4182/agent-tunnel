use std::{
    env,
    error::Error,
    ffi::{OsStr, OsString},
    fs,
    io::Cursor,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use jsonwebtoken::{Algorithm, DecodingKey};
use serde::Deserialize;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;
use tracing_subscriber::{EnvFilter, fmt};
use tunnel_catalog::{
    ApprovedJwk, CatalogConnectionFailure, OidcConfig, OidcVerifier, RedisCatalog, SharedCatalog,
};
use tunnel_cluster::membership::TrustedPublisherKey;
use tunnel_core::RelayConfig;
use tunnel_relay::{
    MembershipReadiness, MembershipRuntime, MembershipRuntimeConfig, MembershipRuntimeError,
    MembershipUnreadyReason, MembershipVersionStateIdentity, MembershipVersionStateStore,
    PeerListenerConfig, PeerListenerState, PeerReadiness, PeerRouteTarget, PeerRuntime,
    RelayOptions, ServeConfig,
    recovery::{
        QuiescenceAcknowledgement, RecoverRequest, RecoveryApprovalVersionStore,
        RecoveryFenceIdentity, RecoveryWorkflowConfig,
    },
    redis_connection::{self, RedisTlsMaterialPaths},
    routing::{OwnerRouter, RelayIdentity},
};
use tunnel_transport::{
    PeerClient, PeerTransportLimits, SharedPeerPins, SpkiSha256, load_peer_client_config_from_pem,
    load_peer_server_config_from_pem, load_server_config_from_pem, spki_sha256_from_der,
};

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
            eprintln!("tunnel-relay: could not start the async runtime: {error}");
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
    init_tracing();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("tunnel-relay: {error}");
            // A stop request that arrived before `serve` was ready, or a
            // second one that abandoned the drain, is not a failure of the
            // relay; it is reported as the client reports `CANCELLED`.
            if error.downcast_ref::<ServeInterrupted>().is_some() {
                ExitCode::from(SERVE_INTERRUPTED_EXIT)
            } else {
                ExitCode::FAILURE
            }
        }
    }
}

/// Exit status of a `serve` that a stop request ended before it could
/// complete an orderly shutdown; the same value `tunnel-client` uses for
/// `CANCELLED`.
const SERVE_INTERRUPTED_EXIT: u8 = 130;

/// A request to stop `serve`. SIGINT (Ctrl-C) and SIGTERM (what systemd and
/// launchd send) are the same request and take the same path (M6-C23).
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

/// `serve`'s stop requests, armed before the configuration is read so that
/// no phase -- startup, serving or the drain -- is left at the inherited
/// disposition. Before M6-C23 the only handler was `tokio::signal::ctrl_c()`
/// awaited after the listeners were up: SIGTERM killed the relay in every
/// phase without running `RunningRelay::shutdown`, and SIGINT during startup
/// did the same.
///
/// Installing the handlers replaces an inherited `SIG_IGN` as well, for the
/// reason `docs/runtime.md` gives under "Stopping `connect` and `serve`": a stop request
/// is honoured whatever disposition the process inherited. SIGHUP is not
/// handled.
struct StopSignals {
    #[cfg(unix)]
    interrupt: tokio::signal::unix::Signal,
    #[cfg(unix)]
    terminate: tokio::signal::unix::Signal,
    #[cfg(windows)]
    ctrl_c: tokio::signal::windows::CtrlC,
}

impl StopSignals {
    fn install() -> Result<Self, Box<dyn Error>> {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            Ok(Self {
                interrupt: signal(SignalKind::interrupt())?,
                terminate: signal(SignalKind::terminate())?,
            })
        }
        #[cfg(windows)]
        {
            Ok(Self {
                ctrl_c: tokio::signal::windows::ctrl_c()?,
            })
        }
    }

    /// Wait for the next stop request. Cancel-safe.
    async fn recv(&mut self) -> Result<StopSignal, Box<dyn Error>> {
        #[cfg(unix)]
        let received = tokio::select! {
            received = self.interrupt.recv() => received.map(|()| StopSignal::Interrupt),
            received = self.terminate.recv() => received.map(|()| StopSignal::Terminate),
        };
        #[cfg(windows)]
        let received = self.ctrl_c.recv().await.map(|()| StopSignal::Interrupt);
        received.ok_or_else(|| "the stop-signal stream closed".into())
    }
}

/// `serve` ended by a stop request before an orderly completion.
#[derive(Debug)]
struct ServeInterrupted {
    signal: StopSignal,
    phase: ServePhase,
}

#[derive(Clone, Copy, Debug)]
enum ServePhase {
    Startup,
    Drain(StopSignal),
    /// A finite writing command abandoned by a second stop request.
    Command {
        name: &'static str,
        first: StopSignal,
    },
}

impl std::fmt::Display for ServeInterrupted {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.phase {
            ServePhase::Startup => write!(
                formatter,
                "{} received during startup; serve stopped before any listener was serving",
                self.signal.name()
            ),
            ServePhase::Drain(first) => write!(
                formatter,
                "{} received during the orderly shutdown {} began; exiting without waiting for the drain",
                self.signal.name(),
                first.name()
            ),
            ServePhase::Command { name, first } => write!(
                formatter,
                "{} received while {name} was finishing after {}; exiting without waiting for it, so its outcome is unknown",
                self.signal.name(),
                first.name()
            ),
        }
    }
}

impl Error for ServeInterrupted {}

/// Run a finite command that **writes** -- Redis authority records or local
/// state files -- with the stop handlers armed (M6-C23).
///
/// These commands end by themselves within their own bounded timeouts, and
/// what they write cannot be half-undone: `provision-catalog` reserves the
/// namespace before its first record and a namespace left partial is
/// discarded, not repaired (M6-C35); `recover` consumes an approval. Taking
/// the default action on SIGTERM part-way would leave exactly that state and
/// print nothing. So a **first** stop request is acknowledged on stderr and
/// the command runs to its own outcome, which is printed and sets the exit
/// status as usual; a **second** abandons it at once with exit `130` and says
/// the outcome is unknown. Read-only commands (`check-config`,
/// `check-serve-config`, `recovery-observe`) are left at the default action:
/// there is nothing for a stop to damage.
async fn run_to_completion<F, T>(name: &'static str, command: F) -> Result<T, Box<dyn Error>>
where
    F: std::future::Future<Output = Result<T, Box<dyn Error>>>,
{
    let mut stop = StopSignals::install()?;
    tokio::pin!(command);
    let first = tokio::select! {
        result = &mut command => return result,
        signal = stop.recv() => signal?,
    };
    eprintln!(
        "tunnel-relay: {} received during {name}; letting it finish, because an interrupted write cannot be undone (send the signal again to abandon it)",
        first.name()
    );
    tokio::select! {
        result = &mut command => result,
        second = stop.recv() => Err(ServeInterrupted {
            signal: second?,
            phase: ServePhase::Command { name, first },
        }
        .into()),
    }
}

/// Run an orderly shutdown to completion unless a **second** stop request
/// arrives first, in which case the drain is abandoned and `serve` exits
/// `130`. Without this, an operator whose drain hung would have nothing
/// short of `SIGKILL` once the handlers are installed.
async fn drain_unless_interrupted<F>(
    stop: &mut StopSignals,
    first: StopSignal,
    drain: F,
) -> Result<(), Box<dyn Error>>
where
    F: std::future::Future<Output = Result<(), Box<dyn Error>>>,
{
    tokio::select! {
        result = drain => result,
        second = stop.recv() => Err(ServeInterrupted { signal: second?, phase: ServePhase::Drain(first) }.into()),
    }
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    let _ = fmt()
        .json()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .try_init();
}

async fn run() -> Result<(), Box<dyn Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    match args.as_slice() {
        [] => print_help(),
        [flag] if flag == OsStr::new("--help") || flag == OsStr::new("-h") => print_help(),
        [command] if command == OsStr::new("check-config") => {
            RelayConfig::default().validate()?;
            println!("Default relay configuration is valid.");
        }
        [command, path] if command == OsStr::new("check-config") => {
            let input = fs::read_to_string(path)?;
            RelayConfig::parse(&input)?;
            println!("Relay configuration is valid.");
        }
        [command, flag, path]
            if command == OsStr::new("check-serve-config") && flag == OsStr::new("--config") =>
        {
            check_serve_config(Path::new(path))?;
        }
        [command, flag, path]
            if command == OsStr::new("serve") && flag == OsStr::new("--config") =>
        {
            serve(Path::new(path)).await?;
        }
        [command, flag, path]
            if command == OsStr::new("initialize") && flag == OsStr::new("--config") =>
        {
            run_to_completion("initialize", initialize(Path::new(path))).await?;
        }
        [command, flag, path]
            if command == OsStr::new("activate-first-incarnation")
                && flag == OsStr::new("--config") =>
        {
            let line = run_to_completion(
                "activate-first-incarnation",
                tunnel_relay::provisioning::activate_first_incarnation(Path::new(path)),
            )
            .await?;
            println!("{line}");
        }
        // M6-C65: re-attest a namespace to a Redis that restarted in place.
        // One atomic script, so like `provision-catalog` a first stop
        // request lets it finish.
        [command, rest @ ..] if command == OsStr::new("rebind-redis-run") => {
            let line = run_to_completion(
                "rebind-redis-run",
                tunnel_relay::provisioning::rebind_redis_run(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("provision-catalog") => {
            let line = run_to_completion(
                "provision-catalog",
                tunnel_relay::provisioning::provision_catalog(rest),
            )
            .await?;
            println!("{line}");
        }
        // Day-2 catalog changes on a provisioned namespace (M6-C31).  Each is
        // one atomic Redis script, so like `provision-catalog` a first stop
        // request lets it finish rather than abandoning it part-way.
        [command, rest @ ..] if command == OsStr::new("add-user") => {
            let line = run_to_completion("add-user", tunnel_relay::catalog_changes::add_user(rest))
                .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("add-device") => {
            let line = run_to_completion(
                "add-device",
                tunnel_relay::catalog_changes::add_device(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("add-service") => {
            let line = run_to_completion(
                "add-service",
                tunnel_relay::catalog_changes::add_service(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("set-grant") => {
            let line =
                run_to_completion("set-grant", tunnel_relay::catalog_changes::set_grant(rest))
                    .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("revoke-grant") => {
            let line = run_to_completion(
                "revoke-grant",
                tunnel_relay::catalog_changes::revoke_grant(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("revoke-device") => {
            let line = run_to_completion(
                "revoke-device",
                tunnel_relay::catalog_changes::revoke_device(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("revoke-credential") => {
            let line = run_to_completion(
                "revoke-credential",
                tunnel_relay::catalog_changes::revoke_credential(rest),
            )
            .await?;
            println!("{line}");
        }
        [command, rest @ ..] if command == OsStr::new("recovery-initialize") => {
            run_to_completion("recovery-initialize", recovery_initialize(rest)).await?;
        }
        [command, rest @ ..] if command == OsStr::new("recovery-observe") => {
            recovery_observe(rest).await?;
        }
        [command, rest @ ..] if command == OsStr::new("recover") => {
            run_to_completion("recover", recover(rest)).await?;
        }
        _ => {
            return Err(
                "usage: tunnel-relay [--help | check-config [PATH] | check-serve-config --config PATH | initialize --config PATH | recovery-initialize --config PATH | recovery-observe --config PATH | recover --config PATH --approval PATH --expected-nonce NONCE --acknowledgement-id ID --old-primary-fenced --old-relays-fenced | activate-first-incarnation --config PATH | rebind-redis-run --config PATH --redis-restarted-in-place | provision-catalog --config PATH --records PATH [--dry-run] | add-user|add-device|add-service|set-grant --config PATH --records PATH [--dry-run] | revoke-grant|revoke-device|revoke-credential --config PATH --tenant UUID ... [--dry-run] | serve --config PATH]".into(),
            );
        }
    }
    Ok(())
}

/// Read-only dry run of the configuration `serve` actually serves with.
///
/// `check-config` parses only the legacy `tunnel_core::RelayConfig`, which
/// cannot even represent a serving document, so nothing validated
/// `serve --config` input before startup.  This command closes that gap with
/// the same `ServeConfig::parse` that `serve` calls first, so every rule
/// `serve` applies to the configuration document — the Redis authority
/// namespace, the Redis TLS/scheme pairing, rotation timing, and the cluster
/// and recovery cross-field rules — produces its verdict here.
///
/// The run is deliberately inert and deterministic: it reads the one
/// configuration file named on the command line and nothing else.  It opens no
/// listener, makes no Redis or peer connection, reads no credential, key or
/// JWKS material, and creates or modifies no file, so it is safe against a
/// production configuration and gives the same answer on a checkout whose
/// placeholder credential paths do not exist.  Validating the referenced
/// material is `serve`'s own startup work and stays there.
///
/// There is no flag to override a configured value: a dry run that could
/// select a different authority file than `serve` would prove nothing about the
/// deployment.
///
/// Exit codes follow the relay's implemented bootstrap behavior: `0` when the
/// configuration is valid, `1` with a redacted field-level diagnostic on
/// stderr when it is not.  The wider exit-code table in docs/runtime.md remains
/// a proposal for the relay until CLI parsing and its compatibility tests land.
fn check_serve_config(path: &Path) -> Result<(), Box<dyn Error>> {
    let config = ServeConfig::parse(&fs::read_to_string(path)?)?;
    println!(
        "Relay serving configuration is valid: consumer_bind={} device_bind={} cluster={} recovery={}. \
         This command validated the configuration document only; it opened no socket, contacted no Redis authority, and read no credential material.",
        config.consumer_bind,
        config.device_bind,
        if config.cluster.is_some() {
            "configured"
        } else {
            "absent"
        },
        if config.recovery.is_some() {
            "configured"
        } else {
            "absent"
        },
    );
    Ok(())
}

/// Explicitly create the identity-bound empty membership fence for a new
/// deployment.  Serving never calls this path implicitly: an operator must
/// provision the parent directory and opt into initialization separately.
async fn initialize(path: &Path) -> Result<(), Box<dyn Error>> {
    let config = ServeConfig::parse(&fs::read_to_string(path)?)?;
    let cluster = config
        .cluster
        .as_ref()
        .ok_or("initialize requires [cluster] configuration")?;
    let identity = MembershipVersionStateIdentity::new(
        &cluster.deployment_id,
        &config.deployment_incarnation,
        &config.node_id,
    )?;
    let state_path = cluster.membership_version_state_path.clone();
    tokio::task::spawn_blocking(move || {
        MembershipVersionStateStore::bootstrap(state_path, identity)
    })
    .await
    .map_err(|_| "membership state initialization task failed")??;
    println!(
        "Initialized membership version state for deployment {} node {}.",
        cluster.deployment_id, config.node_id
    );
    Ok(())
}

#[derive(Default)]
struct RecoveryCliArguments {
    config_path: Option<PathBuf>,
    approval_path: Option<PathBuf>,
    expected_nonce: Option<String>,
    acknowledgement_id: Option<String>,
    old_primary_fenced: bool,
    old_relays_fenced: bool,
}

fn parse_recovery_arguments(
    args: &[OsString],
    require_recovery_request: bool,
) -> Result<RecoveryCliArguments, Box<dyn Error>> {
    let mut parsed = RecoveryCliArguments::default();
    let mut index = 0;
    while index < args.len() {
        let argument = args[index]
            .to_str()
            .ok_or("recovery arguments must be valid UTF-8")?;
        match argument {
            "--config" => {
                if parsed.config_path.is_some() {
                    return Err("duplicate --config argument".into());
                }
                let value = next_recovery_argument(args, &mut index, "--config")?;
                parsed.config_path = Some(PathBuf::from(value));
            }
            "--approval" => {
                if parsed.approval_path.is_some() {
                    return Err("duplicate --approval argument".into());
                }
                let value = next_recovery_argument(args, &mut index, "--approval")?;
                parsed.approval_path = Some(PathBuf::from(value));
            }
            "--expected-nonce" => {
                if parsed.expected_nonce.is_some() {
                    return Err("duplicate --expected-nonce argument".into());
                }
                parsed.expected_nonce = Some(next_recovery_argument(
                    args,
                    &mut index,
                    "--expected-nonce",
                )?);
            }
            "--acknowledgement-id" => {
                if parsed.acknowledgement_id.is_some() {
                    return Err("duplicate --acknowledgement-id argument".into());
                }
                parsed.acknowledgement_id = Some(next_recovery_argument(
                    args,
                    &mut index,
                    "--acknowledgement-id",
                )?);
            }
            "--old-primary-fenced" => {
                if parsed.old_primary_fenced {
                    return Err("duplicate --old-primary-fenced argument".into());
                }
                parsed.old_primary_fenced = true;
            }
            "--old-relays-fenced" => {
                if parsed.old_relays_fenced {
                    return Err("duplicate --old-relays-fenced argument".into());
                }
                parsed.old_relays_fenced = true;
            }
            _ => return Err(format!("unknown recovery argument: {argument}").into()),
        }
        index += 1;
    }

    if parsed.config_path.is_none() {
        return Err("recovery commands require --config PATH".into());
    }
    if require_recovery_request {
        if parsed.approval_path.is_none()
            || parsed.expected_nonce.is_none()
            || parsed.acknowledgement_id.is_none()
            || !parsed.old_primary_fenced
            || !parsed.old_relays_fenced
        {
            return Err(
                "recover requires --approval, --expected-nonce, --acknowledgement-id, --old-primary-fenced, and --old-relays-fenced"
                    .into(),
            );
        }
    } else if parsed.approval_path.is_some()
        || parsed.expected_nonce.is_some()
        || parsed.acknowledgement_id.is_some()
        || parsed.old_primary_fenced
        || parsed.old_relays_fenced
    {
        return Err("this recovery command accepts only --config PATH".into());
    }
    Ok(parsed)
}

fn next_recovery_argument(
    args: &[OsString],
    index: &mut usize,
    flag: &str,
) -> Result<String, Box<dyn Error>> {
    *index += 1;
    let value = args
        .get(*index)
        .ok_or_else(|| format!("{flag} requires a value"))?
        .to_str()
        .ok_or_else(|| format!("{flag} value must be valid UTF-8"))?;
    if value.is_empty() || value.starts_with('-') {
        return Err(format!("{flag} requires a non-empty value").into());
    }
    Ok(value.to_owned())
}

fn checked_recovery_config(config: &ServeConfig) -> Result<RecoveryWorkflowConfig, Box<dyn Error>> {
    let recovery = config
        .recovery
        .as_ref()
        .ok_or("recovery commands require a [recovery] configuration section")?;
    let cluster = config
        .cluster
        .as_ref()
        .ok_or("recovery commands require [cluster].deployment_id")?;
    let redis_tls_material = RedisTlsMaterialPaths {
        root_ca_path: recovery
            .redis_tls_root_ca_path
            .clone()
            .or_else(|| config.redis_tls_root_ca_path.clone()),
        client_cert_path: recovery
            .redis_tls_client_cert_path
            .clone()
            .or_else(|| config.redis_tls_client_cert_path.clone()),
        client_key_path: recovery
            .redis_tls_client_key_path
            .clone()
            .or_else(|| config.redis_tls_client_key_path.clone()),
    };
    let redis_url = recovery.redis_url.as_deref().unwrap_or(&config.redis_url);
    let deployment_incarnation = recovery
        .deployment_incarnation
        .as_deref()
        .unwrap_or(&config.deployment_incarnation);
    Ok(RecoveryWorkflowConfig::new(
        redis_url,
        &cluster.deployment_id,
        &config.redis_namespace,
        deployment_incarnation,
        recovery.fence_path.clone(),
        recovery.trusted_keys_path.clone(),
        redis_tls_material,
    )?)
}

async fn recovery_initialize(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    let parsed = parse_recovery_arguments(args, false)?;
    let config_path = parsed.config_path.expect("validated recovery config path");
    let config = ServeConfig::parse(&fs::read_to_string(&config_path)?)?;
    let workflow = checked_recovery_config(&config)?;
    let identity = RecoveryFenceIdentity::new(
        workflow.deployment_id.clone(),
        workflow.redis_namespace.clone(),
    )?;
    let fence_path = workflow.fence_path.clone();
    tokio::task::spawn_blocking(move || {
        RecoveryApprovalVersionStore::bootstrap(fence_path, identity)
    })
    .await
    .map_err(|_| "recovery fence initialization task failed")??;
    println!(
        "Initialized recovery approval fence for deployment {} namespace {}.",
        workflow.deployment_id, workflow.redis_namespace
    );
    Ok(())
}

async fn recovery_observe(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    let parsed = parse_recovery_arguments(args, false)?;
    let config_path = parsed.config_path.expect("validated recovery config path");
    let config = ServeConfig::parse(&fs::read_to_string(&config_path)?)?;
    let workflow = checked_recovery_config(&config)?;
    let observation = tunnel_relay::recovery::recovery_observe(&workflow).await?;
    println!("{}", serde_json::to_string(&observation)?);
    Ok(())
}

async fn recover(args: &[OsString]) -> Result<(), Box<dyn Error>> {
    let parsed = parse_recovery_arguments(args, true)?;
    let config_path = parsed.config_path.expect("validated recovery config path");
    let config = ServeConfig::parse(&fs::read_to_string(&config_path)?)?;
    let workflow = checked_recovery_config(&config)?;
    let request = RecoverRequest {
        expected_nonce: parsed.expected_nonce.expect("validated recovery nonce"),
        approval_path: parsed.approval_path.expect("validated approval path"),
        quiescence: QuiescenceAcknowledgement::new(
            parsed
                .acknowledgement_id
                .expect("validated acknowledgement id"),
            parsed.old_primary_fenced,
            parsed.old_relays_fenced,
        )?,
    };
    let outcome = tunnel_relay::recovery::recover(&workflow, &request).await?;
    println!("{}", serde_json::to_string(&outcome)?);
    Ok(())
}

async fn serve(path: &Path) -> Result<(), Box<dyn Error>> {
    // Armed first: a stop request during startup (reading files, the Redis
    // connection, the membership bootstrap, binding) abandons startup with a
    // diagnostic instead of taking the default action. Startup work is
    // dropped, not drained -- nothing is serving yet -- and blocking work
    // already handed to the runtime (the membership state store) still
    // completes, because dropping the runtime waits for blocking tasks.
    let mut stop = StopSignals::install()?;
    let serving = tokio::select! {
        started = start_serving(path) => started?,
        signal = stop.recv() => {
            return Err(ServeInterrupted { signal: signal?, phase: ServePhase::Startup }.into());
        }
    };
    match serving {
        Serving::Single(running, continuity) => {
            let signal = stop.recv().await?;
            eprintln!("tunnel-relay stopping: signal={}", signal.name());
            if let Some(continuity) = continuity {
                continuity.abort();
            }
            drain_unless_interrupted(&mut stop, signal, async move {
                running.shutdown().await.map_err(Into::into)
            })
            .await?;
            eprintln!("tunnel-relay stopped: signal={}", signal.name());
            Ok(())
        }
        Serving::Cluster(cluster) => cluster.run_until_stopped(&mut stop).await,
    }
}

/// A relay that finished startup and is serving.
enum Serving {
    /// A relay without `[cluster]`, and its Redis restart continuity task
    /// when `redis_restart_continuity_seconds` is set (M6-C65).
    Single(
        tunnel_relay::RunningRelay,
        Option<tokio::task::JoinHandle<()>>,
    ),
    Cluster(ClusterServing),
}

async fn start_serving(path: &Path) -> Result<Serving, Box<dyn Error>> {
    let config = ServeConfig::parse(&fs::read_to_string(path)?)?;
    let jwks = parse_jwks(&fs::read(&config.oidc_jwks_path)?)?;
    let oidc = Arc::new(OidcVerifier::new(OidcConfig::new(
        config.oidc_issuer.clone(),
        config.oidc_audience.clone(),
        jwks,
    )?)?);
    let redis_tls_material = RedisTlsMaterialPaths {
        root_ca_path: config.redis_tls_root_ca_path.clone(),
        client_cert_path: config.redis_tls_client_cert_path.clone(),
        client_key_path: config.redis_tls_client_key_path.clone(),
    };
    let catalog = redis_connection::connect(
        &config.redis_url,
        &config.redis_namespace,
        &config.deployment_incarnation,
        &redis_tls_material,
    )
    .await?;
    // M6-C65: a single relay that opted in keeps a continuity witness, so a
    // Redis restart that kept this relay's last acknowledged write is
    // re-bound without an operator.  The first token is written before the
    // relay listens; a failure here refuses to start.
    let continuity = match config.redis_restart_continuity_seconds {
        Some(seconds) if config.cluster.is_none() => {
            catalog.enable_restart_continuity().await.map_err(|error| {
                format!(
                    "Redis restart continuity could not start; {}",
                    continuity_stage(&error)
                )
            })?;
            Some((catalog.clone(), Duration::from_secs(seconds)))
        }
        _ => None,
    };
    let catalog: SharedCatalog = Arc::new(catalog);
    let options = RelayOptions::new(oidc);
    let consumer_listener = TcpListener::bind(config.consumer_bind).await?;
    let device_listener = TcpListener::bind(config.device_bind).await?;
    let consumer_cert = fs::read(&config.consumer_tls_cert_chain)?;
    let consumer_key = fs::read(&config.consumer_tls_private_key)?;
    let consumer_ca = config
        .consumer_tls_client_ca
        .as_ref()
        .map(fs::read)
        .transpose()?;
    let consumer_tls =
        load_server_config_from_pem(&consumer_cert, &consumer_key, consumer_ca.as_deref())?;
    let device_cert = fs::read(&config.device_tls_cert_chain)?;
    let device_key = fs::read(&config.device_tls_private_key)?;
    let device_ca = fs::read(&config.device_tls_client_ca)?;
    let device_tls = load_server_config_from_pem(&device_cert, &device_key, Some(&device_ca))?;
    if config.cluster.is_some() {
        return start_cluster(
            &config,
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
        )
        .await
        .map(Serving::Cluster);
    }
    let running = config
        .start(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
        )
        .await?;
    eprintln!(
        "tunnel-relay listening: consumer={} device={}",
        running.consumer_addr, running.device_addr
    );
    let continuity = continuity.map(|(catalog, interval)| {
        eprintln!(
            "tunnel-relay Redis restart continuity: interval_seconds={}",
            interval.as_secs()
        );
        tokio::spawn(restart_continuity_loop(catalog, interval))
    });
    Ok(Serving::Single(running, continuity))
}

/// `stage=... class=...` for a continuity failure, fixed words only: a
/// refusal of the namespace is `authority_identity`, anything else (Redis
/// down, a timeout) `authority_connection`.
fn continuity_stage(error: &tunnel_catalog::CatalogError) -> String {
    let class = CatalogConnectionFailure::classify(error);
    let stage = match class {
        CatalogConnectionFailure::Unbound
        | CatalogConnectionFailure::RunChanged
        | CatalogConnectionFailure::Continuity
        | CatalogConnectionFailure::Catalog => "authority_identity",
        _ => "authority_connection",
    };
    format!("stage={stage} class={}", class.as_str())
}

/// Write a new continuity token every `interval` (M6-C65) and report, once
/// per change, a re-binding to a restarted Redis run, a failure and a
/// recovery.  It never exits the relay: while Redis is refused, requests
/// fail closed as they would without it.
async fn restart_continuity_loop(catalog: RedisCatalog, interval: Duration) {
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The first tick completes at once; startup already wrote a token.
    ticker.tick().await;
    let mut rebinds = catalog.redis_run_rebinds();
    let mut failing: Option<String> = None;
    loop {
        ticker.tick().await;
        let result = catalog.advance_restart_continuity().await;
        let current = catalog.redis_run_rebinds();
        if current != rebinds {
            rebinds = current;
            eprintln!(
                "tunnel-relay: Redis authority restarted; namespace re-bound to the new Redis run after its continuity check: rebinds={current}"
            );
        }
        match result {
            Ok(()) => {
                if failing.take().is_some() {
                    eprintln!("tunnel-relay: Redis authority continuity restored");
                }
            }
            Err(error) => {
                let line = continuity_stage(&error);
                if failing.as_deref() != Some(line.as_str()) {
                    eprintln!("tunnel-relay: Redis authority continuity check failed; {line}");
                    failing = Some(line);
                }
            }
        }
    }
}

/// Start the M7 private peer path after constructing every trust input from
/// operator-provisioned files and a fresh checkpoint authority response.
///
/// Cluster startup deliberately lives at the executable boundary: this is the
/// only place that reads private TLS keys and membership trust files.  The
/// relay library receives already-authenticated TLS configs, an empty-or
/// verified dynamic pin set, and a typed owner runtime.  Redis records never
/// become trust anchors and an unready membership runtime never starts public
/// listeners.
async fn start_cluster(
    config: &ServeConfig,
    mut options: RelayOptions,
    catalog: SharedCatalog,
    consumer_listener: TcpListener,
    device_listener: TcpListener,
    consumer_tls: Arc<rustls::ServerConfig>,
    device_tls: Arc<rustls::ServerConfig>,
) -> Result<ClusterServing, Box<dyn Error>> {
    let cluster = config
        .cluster
        .as_ref()
        .ok_or("cluster startup requested without cluster configuration")?;

    // ServeConfig::start_with_peer applies these fields too, but the owner
    // router and membership runtime must use the exact same fresh identity.
    options.node_id = config.node_id.clone();
    options.deployment_incarnation = config.deployment_incarnation.clone();
    let shutdown = options.shutdown.clone();

    let peer_cert = fs::read(&cluster.peer_tls_cert_chain)?;
    let peer_key = fs::read(&cluster.peer_tls_private_key)?;
    let peer_ca = fs::read(&cluster.peer_tls_client_ca)?;
    let local_spki = first_certificate_spki(&peer_cert)?;

    let trusted_publishers = load_membership_publishers(cluster)?;
    let authority = tunnel_relay::HttpsCheckpointAuthority::from_cluster_config(cluster)?;
    let membership_config = MembershipRuntimeConfig::from_cluster_config(
        cluster,
        options.node_id.clone(),
        options.boot_id.clone(),
        options.deployment_incarnation.clone(),
    )?
    .with_local_spki_sha256(local_spki.to_hex())?;
    let state_path = cluster.membership_version_state_path.clone();
    let state_identity = MembershipVersionStateIdentity::new(
        &cluster.deployment_id,
        &config.deployment_incarnation,
        &config.node_id,
    )?;
    let authority: Arc<dyn tunnel_relay::CheckpointAuthority> = Arc::new(authority);
    let membership_catalog = catalog.clone();
    let membership = tokio::task::spawn_blocking(move || {
        let store = MembershipVersionStateStore::open(state_path, state_identity)
            .map_err(tunnel_relay::MembershipRuntimeError::Persistence)?;
        MembershipRuntime::new_with_store(
            membership_catalog,
            authority,
            membership_config,
            trusted_publishers,
            Arc::new(store),
        )
    })
    .await
    .map_err(|_| "membership state load task failed")??;

    let pins = SharedPeerPins::empty();

    let peer_limits = PeerTransportLimits::default().with_timeouts(
        Duration::from_secs(cluster.peer_idle_timeout_seconds),
        Duration::from_secs(cluster.peer_drain_timeout_seconds),
    )?;
    let mut peer_server_config = load_peer_server_config_from_pem(&peer_cert, &peer_key, &peer_ca)?;
    peer_limits.apply_to_server_config(&mut peer_server_config)?;
    let mut peer_client_config = load_peer_client_config_from_pem(&peer_cert, &peer_key, &peer_ca)?;
    peer_limits.apply_to_client_config(&mut peer_client_config)?;
    let peer_server_endpoint = quinn::Endpoint::server(peer_server_config, cluster.peer_bind)?;
    let client_bind = std::net::SocketAddr::new(cluster.peer_bind.ip(), 0);
    let mut peer_client_endpoint = quinn::Endpoint::client(client_bind)?;
    peer_client_endpoint.set_default_client_config(peer_client_config);
    let peer_client =
        PeerClient::new_with_pin_provider(peer_client_endpoint, pins.clone(), peer_limits.clone())?;

    let local_identity = RelayIdentity::new(
        options.deployment_incarnation.clone(),
        options.node_id.clone(),
        options.boot_id.clone(),
    )?;
    let owner_router = Arc::new(OwnerRouter::new(catalog.clone(), local_identity)?);
    let bindings: Arc<dyn tunnel_relay::PeerBindingProvider> = membership.clone();
    let peer_capacity = peer_limits
        .max_connections
        .min(peer_limits.max_streams_per_connection);
    let peer_readiness = Arc::new(PeerReadiness::new(1)?);
    let peer_runtime = Arc::new(PeerRuntime::new_with_readiness(
        peer_client,
        owner_router,
        bindings,
        options.node_id.clone(),
        options.boot_id.clone(),
        Arc::clone(&peer_readiness),
    ));

    // `start` performs the nonce-bound bootstrap before spawning its joined
    // reconciliation task.  Refuse to bind any listener unless that first
    // pass reached Ready; an unready supervisor is useful for an explicit
    // operator restart but is unsafe for a serving process.
    let membership_handle = membership.start().await?;
    let membership_readiness = membership.readiness();
    if !matches!(&membership_readiness, MembershipReadiness::Ready) {
        membership_handle.cancel();
        let shutdown_result = membership_handle.shutdown().await;
        return Err(membership_bootstrap_error(
            &membership_readiness,
            shutdown_result.as_ref().err(),
        )
        .into());
    }
    if let Err(error) = publish_membership_pins(&membership, &pins) {
        membership_handle.cancel();
        let _ = membership_handle.shutdown().await;
        return Err(std::io::Error::other(error.to_string()).into());
    }
    if pins.snapshot().is_empty() {
        membership_handle.cancel();
        let _ = membership_handle.shutdown().await;
        return Err("cluster membership contains no approved peer keys".into());
    }
    peer_readiness.replace_required_routes(required_peer_routes(&membership, &config.node_id))?;

    // Membership changes revoke the dynamic SPKI snapshot immediately.  The
    // transport's pin watcher closes connections whose certificate is no
    // longer approved, while the admission token carried by each forwarded
    // stream handles same-pin record/deadline changes.  Do not clear the
    // entire readiness route set for one peer: unrelated owner routes remain
    // usable and every new request still performs its exact binding check.
    let pin_membership = Arc::clone(&membership);
    let pin_updates = pins.clone();
    membership.set_invalidation_callback(Some(Arc::new(move |_identity, _reason| {
        if let Err(error) = publish_membership_pins(&pin_membership, &pin_updates) {
            tracing::warn!(?error, "membership pin publication failed closed");
            let _ = pin_updates.replace(std::iter::empty::<SpkiSha256>());
        }
    })));
    let running = match config
        .start_with_peer(
            options,
            catalog,
            consumer_listener,
            device_listener,
            consumer_tls,
            device_tls,
            PeerListenerConfig {
                endpoint: peer_server_endpoint,
                pins: pins.clone(),
                limits: peer_limits,
            },
            Arc::clone(&peer_runtime),
        )
        .await
    {
        Ok(running) => running,
        Err(error) => {
            shutdown.cancel();
            membership_handle.cancel();
            let _ = membership_handle.shutdown().await;
            return Err(error.into());
        }
    };

    // Private health requests can be served before outbound probes succeed.
    // Public admission remains unready until the first authenticated pass,
    // avoiding a startup dependency cycle between otherwise trusted relays.
    let peer_task = tokio::spawn(peer_refresh_loop(
        Arc::clone(&membership),
        pins,
        Arc::clone(&peer_runtime),
        config.node_id.clone(),
        peer_capacity,
        Duration::from_secs(cluster.membership_reconcile_seconds),
        shutdown.clone(),
    ));

    eprintln!(
        "tunnel-relay listening: consumer={} device={} peer={}",
        running.consumer_addr, running.device_addr, cluster.peer_bind
    );
    Ok(ClusterServing {
        running,
        peer_runtime,
        peer_task,
        membership_handle,
        shutdown,
    })
}

/// A serving cluster relay and everything its orderly shutdown must join.
struct ClusterServing {
    running: tunnel_relay::RunningRelay,
    peer_runtime: Arc<PeerRuntime>,
    peer_task: tokio::task::JoinHandle<()>,
    membership_handle: tunnel_relay::MembershipRuntimeHandle,
    shutdown: CancellationToken,
}

impl ClusterServing {
    async fn run_until_stopped(self, stop: &mut StopSignals) -> Result<(), Box<dyn Error>> {
        let Self {
            running,
            peer_runtime,
            peer_task,
            membership_handle,
            shutdown,
        } = self;
        // The relay's own shutdown token takes the same drain as a stop
        // request, as it did before M6-C23.
        let requested = tokio::select! {
            requested = stop.recv() => Some(requested),
            () = shutdown.cancelled() => None,
        };
        let first = match &requested {
            Some(Ok(signal)) => {
                eprintln!("tunnel-relay stopping: signal={}", signal.name());
                *signal
            }
            // Nothing to name. A later stop request still abandons the drain;
            // the diagnostic then reads as if SIGTERM had begun it.
            Some(Err(_)) | None => {
                eprintln!("tunnel-relay stopping: internal shutdown requested");
                StopSignal::Terminate
            }
        };
        drain_unless_interrupted(stop, first, async move {
            peer_runtime.set_peer_listener_state(PeerListenerState::Draining);
            shutdown.cancel();
            membership_handle.cancel();
            let running_result = running.shutdown().await;
            let peer_result = peer_task
                .await
                .map_err(|error| format!("peer readiness task failed: {error}"));
            let membership_result = membership_handle.shutdown().await;
            running_result?;
            peer_result?;
            membership_result?;
            Ok(())
        })
        .await?;
        match requested {
            Some(requested) => {
                eprintln!("tunnel-relay stopped: signal={}", requested?.name());
            }
            None => eprintln!("tunnel-relay stopped"),
        }
        Ok(())
    }
}

fn membership_bootstrap_error(
    readiness: &MembershipReadiness,
    shutdown_error: Option<&MembershipRuntimeError>,
) -> String {
    let (readiness_state, reason, category) = membership_readiness_code(readiness);
    let mut message = format!(
        "cluster membership bootstrap did not reach ready: readiness={readiness_state} reason={reason} category={category}"
    );
    if let Some(error) = shutdown_error {
        message.push_str(&format!(
            "; cleanup=membership_shutdown_failed reason={}",
            membership_shutdown_code(error)
        ));
    }
    message
}

fn membership_readiness_code(
    readiness: &MembershipReadiness,
) -> (&'static str, &'static str, &'static str) {
    match readiness {
        MembershipReadiness::Starting => ("starting", "starting", "bootstrap"),
        MembershipReadiness::Ready => ("ready", "ready", "bootstrap"),
        MembershipReadiness::Unready(reason) => match reason {
            MembershipUnreadyReason::UnknownAuthority => {
                ("unready", "unknown_authority", "authority")
            }
            MembershipUnreadyReason::CheckpointExpired => {
                ("unready", "checkpoint_expired", "checkpoint")
            }
            MembershipUnreadyReason::CatalogUnavailable => {
                ("unready", "catalog_unavailable", "catalog")
            }
            MembershipUnreadyReason::MembershipRejected => {
                ("unready", "membership_rejected", "membership")
            }
            MembershipUnreadyReason::MissingLocalMembership => {
                ("unready", "missing_local_membership", "membership")
            }
            MembershipUnreadyReason::PersistenceUnavailable => {
                ("unready", "persistence_unavailable", "persistence")
            }
            MembershipUnreadyReason::Cancelled => ("unready", "cancelled", "lifecycle"),
        },
    }
}

fn membership_shutdown_code(error: &MembershipRuntimeError) -> &'static str {
    match error {
        MembershipRuntimeError::InvalidConfiguration => "invalid_configuration",
        MembershipRuntimeError::Authority(_) => "authority",
        MembershipRuntimeError::Source(_) => "source",
        MembershipRuntimeError::Membership(_) => "membership",
        MembershipRuntimeError::Persistence(_) => "persistence",
        MembershipRuntimeError::PersistenceTimeout => "persistence_timeout",
        MembershipRuntimeError::NotReady => "not_ready",
        MembershipRuntimeError::PeerRejected => "peer_rejected",
        MembershipRuntimeError::CheckpointExpired => "checkpoint_expired",
        MembershipRuntimeError::Cancelled => "cancelled",
        MembershipRuntimeError::Join => "join",
    }
}

/// Reconcile the transport's dynamic pins from verifier-filtered current
/// route targets. Any malformed digest or unready state publishes an empty
/// snapshot, which makes both peer directions fail closed.
fn publish_membership_pins(
    membership: &MembershipRuntime,
    pins: &SharedPeerPins,
) -> Result<(), Box<dyn Error + Send + Sync>> {
    if !matches!(membership.readiness(), MembershipReadiness::Ready) {
        pins.replace(std::iter::empty::<SpkiSha256>())?;
        return Ok(());
    }
    // Derive the pin set from current, verifier-filtered route targets rather
    // than the redacted diagnostic snapshot.  The latter intentionally keeps
    // bounded historical key metadata, so publishing it could retain an
    // expired/revoked SPKI in the transport trust set until the next full
    // candidate swap.  Route targets filter record/key windows at `now` and
    // are the same evidence used by readiness probes.
    let mut digests = Vec::new();
    for target in membership.verified_peer_route_targets() {
        for digest in target.approved_spki_sha256() {
            let bytes = decode_hex_digest(digest).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid membership SPKI digest",
                )
            })?;
            digests.push(SpkiSha256::from_bytes(bytes));
        }
    }
    pins.replace(digests)?;
    Ok(())
}

fn required_peer_routes(
    membership: &MembershipRuntime,
    local_node_id: &str,
) -> Vec<PeerRouteTarget> {
    membership
        .verified_peer_route_targets()
        .into_iter()
        .filter(|target| target.node_id() != local_node_id)
        .collect()
}

async fn peer_refresh_loop(
    membership: Arc<MembershipRuntime>,
    pins: SharedPeerPins,
    peer: Arc<PeerRuntime>,
    local_node_id: String,
    configured_capacity: usize,
    interval: Duration,
    shutdown: CancellationToken,
) {
    let mut ticker = tokio::time::interval(interval.min(Duration::from_secs(5)));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = shutdown.cancelled() => break,
            _ = ticker.tick() => {
                if let Err(error) = publish_membership_pins(&membership, &pins) {
                    tracing::warn!(?error, "membership pin refresh failed closed");
                    let _ = pins.replace(std::iter::empty::<SpkiSha256>());
                }
                if let Err(error) = peer.refresh_peer_pins().await {
                    tracing::warn!(?error, "stale peer pin connection cleanup failed");
                }
                if pins.snapshot().is_empty() {
                    // No current signed peer key material could be published,
                    // so there is no trust evidence for any peer at all.
                    peer.withdraw_peer_trust();
                    continue;
                }
                if !matches!(membership.readiness(), MembershipReadiness::Ready) {
                    // This relay's own cluster prerequisites are unmet, so
                    // readiness and admission fail closed. The verified route
                    // and pin set stays installed so an authenticated peer's
                    // bounded reachability probe is still answered; otherwise
                    // two relays wait on each other and neither converges.
                    peer.withdraw_peer_readiness();
                    continue;
                }
                // The configured ceiling supplies the global capacity floor;
                // every successful route probe separately proves an actual
                // HTTP/3 request slot and response path for that destination.
                peer.set_peer_capacity(configured_capacity);
                let targets = required_peer_routes(&membership, &local_node_id);
                tokio::select! {
                    _ = shutdown.cancelled() => break,
                    result = peer.refresh_required_routes(targets) => {
                        if result.is_err() {
                            tracing::warn!("authenticated peer readiness probe failed");
                        }
                    }
                }
            }
        }
    }
}

fn first_certificate_spki(certificate_pem: &[u8]) -> Result<SpkiSha256, Box<dyn Error>> {
    let mut reader = Cursor::new(certificate_pem);
    let certificate = rustls_pemfile::certs(&mut reader)
        .next()
        .ok_or("peer certificate chain is empty")??;
    Ok(spki_sha256_from_der(certificate.as_ref())?)
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipTrustDocument {
    keys: Vec<MembershipTrustKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct MembershipTrustKey {
    key_id: String,
    public_key: String,
}

fn load_membership_publishers(
    cluster: &tunnel_relay::ClusterConfig,
) -> Result<Vec<TrustedPublisherKey>, Box<dyn Error>> {
    let mut publishers = Vec::new();
    if let Some(path) = &cluster.membership_signer_trust_path {
        let bytes = fs::read(path)?;
        if bytes.len() > tunnel_cluster::membership::MAX_RECORD_BYTES {
            return Err("membership signer trust document is too large".into());
        }
        let document: MembershipTrustDocument = serde_json::from_slice(&bytes)?;
        if document.keys.is_empty()
            || document.keys.len() > tunnel_cluster::membership::MAX_AUTHORIZED_NODES
        {
            return Err("membership signer trust document has an invalid key count".into());
        }
        for key in document.keys {
            let public_key = decode_public_key(key.public_key.as_bytes())?;
            publishers.push(TrustedPublisherKey::new(key.key_id, public_key)?);
        }
    }
    // A direct public-key file is intentionally only accepted when its key ID
    // is explicit.  If a named trust document was supplied, the legacy direct
    // path is ignored so a placeholder cannot silently become authority.
    if cluster.membership_signer_trust_path.is_none()
        && let (Some(path), Some(key_id)) = (
            &cluster.membership_signer_public_key_path,
            cluster.membership_signer_key_id.as_deref(),
        )
    {
        let bytes = fs::read(path)?;
        publishers.push(TrustedPublisherKey::new(
            key_id,
            decode_public_key(&bytes)?,
        )?);
    }
    if publishers.is_empty() {
        return Err("no membership signer public keys were configured".into());
    }
    Ok(publishers)
}

fn decode_public_key(bytes: &[u8]) -> Result<[u8; 32], Box<dyn Error>> {
    if bytes.len() == 32 {
        let mut key = [0_u8; 32];
        key.copy_from_slice(bytes);
        return Ok(key);
    }
    let text = std::str::from_utf8(bytes)?.trim();
    if text.len() == 64 {
        return decode_hex_digest(text).ok_or_else(|| "invalid public-key hex".into());
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(text)
        .map_err(|_| "public key must be raw, lower-case hex, or URL-safe base64")?;
    if decoded.len() != 32 {
        return Err("decoded membership public key must contain 32 bytes".into());
    }
    let mut key = [0_u8; 32];
    key.copy_from_slice(&decoded);
    Ok(key)
}

fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

#[derive(Deserialize)]
struct Jwks {
    keys: Vec<Jwk>,
}

#[derive(Deserialize)]
struct Jwk {
    kid: String,
    kty: String,
    alg: Option<String>,
    n: Option<String>,
    e: Option<String>,
}

fn parse_jwks(bytes: &[u8]) -> Result<Vec<ApprovedJwk>, Box<dyn Error>> {
    let jwks: Jwks = serde_json::from_slice(bytes)?;
    let mut approved = Vec::with_capacity(jwks.keys.len());
    for key in jwks.keys {
        if key.kty != "RSA" || key.alg.as_deref().unwrap_or("RS256") != "RS256" {
            return Err("OIDC JWKS contains a non-RS256 key; configure an approved RSA key".into());
        }
        let decoding = DecodingKey::from_rsa_components(
            key.n.as_deref().ok_or("OIDC RSA key has no modulus")?,
            key.e.as_deref().ok_or("OIDC RSA key has no exponent")?,
        )?;
        approved.push(ApprovedJwk::from_decoding_key(
            key.kid,
            Algorithm::RS256,
            decoding,
        )?);
    }
    if approved.is_empty() {
        return Err("OIDC JWKS contains no approved keys".into());
    }
    Ok(approved)
}

fn print_help() {
    println!(
        "tunnel-relay — authenticated multi-user Agent Tunnel relay\n\n\
         Usage: tunnel-relay [--help | check-config [PATH] | check-serve-config --config PATH | initialize --config PATH | recovery-initialize --config PATH | recovery-observe --config PATH | recover --config PATH --approval PATH --expected-nonce NONCE --acknowledgement-id ID --old-primary-fenced --old-relays-fenced | activate-first-incarnation --config PATH | rebind-redis-run --config PATH --redis-restarted-in-place | provision-catalog --config PATH --records PATH [--dry-run] | add-user|add-device|add-service|set-grant --config PATH --records PATH [--dry-run] | revoke-grant|revoke-device|revoke-credential --config PATH --tenant UUID ... [--dry-run] | serve --config PATH]\n\n\
         check-config [PATH]       Validate legacy relay TOML without opening listeners.\n\
         check-serve-config --config PATH\n\
                                  Dry-run the configuration serve uses: full validation,\n\
                                  no socket, no Redis connection, no credential read.\n\
                                  Exits 0 when valid and 1 with a field-level reason.\n\
         initialize --config PATH Create the empty cluster membership fence explicitly.\n\
         recovery-initialize --config PATH\n\
                                  Create the empty recovery approval fence explicitly.\n\
         recovery-observe --config PATH\n\
                                  Read a bounded durable-catalog observation.\n\
         recover --config PATH --approval PATH --expected-nonce NONCE\n\
           --acknowledgement-id ID --old-primary-fenced --old-relays-fenced\n\
                                  Consume one approval and activate the candidate.\n\
         activate-first-incarnation --config PATH\n\
                                  Bind the configured incarnation to an empty namespace.\n\
         rebind-redis-run --config PATH --redis-restarted-in-place\n\
                                  After Redis restarted from its own persistence, bind\n\
                                  the namespace to the new Redis run (single relay).\n\
         provision-catalog --config PATH --records PATH [--dry-run]\n\
                                  Write one tenant, user, device, credential, service\n\
                                  and grant into a newly activated namespace.\n\
         add-user | add-device | add-service | set-grant --config PATH --records PATH [--dry-run]\n\
                                  Add one user, device (with its certificate's\n\
                                  credential) or service, or add or replace one grant,\n\
                                  in a provisioned namespace while the relay serves.\n\
         revoke-grant --config PATH --tenant UUID --user UUID --device UUID --service UUID [--dry-run]\n\
         revoke-device --config PATH --tenant UUID --device UUID [--dry-run]\n\
         revoke-credential --config PATH --tenant UUID --device UUID --credential UUID [--dry-run]\n\
                                  Revoke a grant, a device (its credentials, grants and\n\
                                  live session) or one device credential.\n\
         serve --config PATH      Start consumer HTTPS and device mTLS WSS listeners."
    );
}

#[cfg(test)]
mod tests {
    use super::{
        MembershipReadiness, MembershipRuntimeError, MembershipUnreadyReason,
        membership_bootstrap_error, membership_readiness_code, parse_jwks,
    };
    use jsonwebtoken::Algorithm;
    use serde_json::{Value, json};

    /// JWK `n` of a throwaway 2048-bit RSA key generated with OpenSSL; the
    /// private half was discarded.
    const RSA_2048_MODULUS: &str = "wpzxK4YhVbeIGQkBFuC8Lwc5iX4NpKHeWN6c1zg6xBCJ2oDK-KD_Q19VR-_OeOcQvzeWHPnHM1c6Mg2vrBm-6obc5R4gNQd-CZz9H4QS6SUQ-S2rjWVzCWpx0SWIzS4Uw7_yu_qHsoUWQVBVZIBQ49AUBNLg6pCr-r6dwkxcr67-m5Jjw1-E9-Vq54tgGMzRocZWU79N75jXzLRzDOLbOJex-CrCcek2owQ-Cv5f61-5gacszQjnu8kjt2Zsmnr0PVzNcaBwvbt66qJLAnXLZghu6JmWEGoeGYpG7XjX9S_A8n_9pA58xDnrsxSNnlRTy3LQMUtlDcDCd0jLvBLw3w";
    /// JWK `n` of a throwaway 1024-bit RSA key: too small to approve.
    const RSA_1024_MODULUS: &str = "0bud3ILQKZXasKMJB10Q-QJZ1O9Ru63NITg3Zt2opp9wK5I985oc65LYKTCmIKPkFGNSa7CZyTbUbqyKoaz8E0nGY0ZoZj8G301LpcSbCV3wE9bE_dVjqvdUqapSDIxzsiCFKojsDnDai1YQnxGnMGeQ8yaJhadKAC9QpMFRaxE";

    fn jwks(keys: &[Value]) -> Vec<u8> {
        serde_json::to_vec(&json!({ "keys": keys })).expect("JWKS document")
    }

    fn rsa_jwk(kid: &str, modulus: &str) -> Value {
        json!({ "kid": kid, "kty": "RSA", "alg": "RS256", "use": "sig", "n": modulus, "e": "AQAB" })
    }

    #[test]
    fn parse_jwks_approves_only_rs256_rsa_keys_of_verifiable_size() {
        let approved = parse_jwks(&jwks(&[
            rsa_jwk("primary", RSA_2048_MODULUS),
            // `alg` is optional and defaults to RS256.
            json!({ "kid": "next", "kty": "RSA", "n": RSA_2048_MODULUS, "e": "AQAB" }),
        ]))
        .expect("RS256 JWKS parses");
        assert_eq!(approved.len(), 2);
        assert_eq!(approved[0].kid, "primary");
        assert_eq!(approved[1].kid, "next");
        assert!(approved.iter().all(|key| key.algorithm == Algorithm::RS256));

        let rejected: [(&str, Vec<u8>); 13] = [
            ("empty key set", jwks(&[])),
            ("not a JWKS document", b"[]".to_vec()),
            (
                "EC key",
                jwks(&[
                    json!({ "kid": "ec", "kty": "EC", "alg": "ES256", "crv": "P-256", "x": "AA", "y": "AA" }),
                ]),
            ),
            (
                "octet key",
                jwks(&[json!({ "kid": "oct", "kty": "oct", "alg": "HS256", "k": "c2VjcmV0" })]),
            ),
            (
                "RS384",
                jwks(&[
                    json!({ "kid": "k", "kty": "RSA", "alg": "RS384", "n": RSA_2048_MODULUS, "e": "AQAB" }),
                ]),
            ),
            (
                "PS256",
                jwks(&[
                    json!({ "kid": "k", "kty": "RSA", "alg": "PS256", "n": RSA_2048_MODULUS, "e": "AQAB" }),
                ]),
            ),
            (
                "missing modulus",
                jwks(&[json!({ "kid": "k", "kty": "RSA", "e": "AQAB" })]),
            ),
            (
                "missing exponent",
                jwks(&[json!({ "kid": "k", "kty": "RSA", "n": RSA_2048_MODULUS })]),
            ),
            (
                "modulus is not base64url",
                jwks(&[json!({ "kid": "k", "kty": "RSA", "n": "not base64!", "e": "AQAB" })]),
            ),
            (
                "1024-bit modulus",
                jwks(&[rsa_jwk("small", RSA_1024_MODULUS)]),
            ),
            (
                "even exponent",
                jwks(&[json!({ "kid": "k", "kty": "RSA", "n": RSA_2048_MODULUS, "e": "AQAC" })]),
            ),
            ("empty kid", jwks(&[rsa_jwk("", RSA_2048_MODULUS)])),
            (
                "one unusable key rejects the whole set",
                jwks(&[
                    rsa_jwk("primary", RSA_2048_MODULUS),
                    rsa_jwk("small", RSA_1024_MODULUS),
                ]),
            ),
        ];
        for (name, document) in rejected {
            assert!(parse_jwks(&document).is_err(), "{name} was approved");
        }
    }

    #[test]
    fn membership_bootstrap_reason_codes_are_stable() {
        let cases = [
            (
                MembershipUnreadyReason::UnknownAuthority,
                "unknown_authority",
                "authority",
            ),
            (
                MembershipUnreadyReason::CheckpointExpired,
                "checkpoint_expired",
                "checkpoint",
            ),
            (
                MembershipUnreadyReason::CatalogUnavailable,
                "catalog_unavailable",
                "catalog",
            ),
            (
                MembershipUnreadyReason::MembershipRejected,
                "membership_rejected",
                "membership",
            ),
            (
                MembershipUnreadyReason::MissingLocalMembership,
                "missing_local_membership",
                "membership",
            ),
            (
                MembershipUnreadyReason::PersistenceUnavailable,
                "persistence_unavailable",
                "persistence",
            ),
            (MembershipUnreadyReason::Cancelled, "cancelled", "lifecycle"),
        ];
        for (reason, expected_reason, expected_category) in cases {
            let readiness = MembershipReadiness::Unready(reason);
            assert_eq!(
                membership_readiness_code(&readiness),
                ("unready", expected_reason, expected_category)
            );
        }
    }

    #[test]
    fn membership_bootstrap_error_redacts_shutdown_details() {
        let readiness = MembershipReadiness::Unready(MembershipUnreadyReason::CatalogUnavailable);
        let message = membership_bootstrap_error(&readiness, Some(&MembershipRuntimeError::Join));
        assert_eq!(
            message,
            "cluster membership bootstrap did not reach ready: readiness=unready reason=catalog_unavailable category=catalog; cleanup=membership_shutdown_failed reason=join"
        );
    }
}
