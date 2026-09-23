#![forbid(unsafe_code)]
//! A deterministic synthetic MCP server built with the pinned official Rust
//! SDK (rmcp 3.4.0).  It touches nothing but an optional marker directory
//! the test owns.
//!
//! Tools:
//!
//! * `echo` — returns one text block holding `{"arguments", "meta"}` as the
//!   server received them (so `_meta` preservation is observable) plus a
//!   fixed synthetic image block;
//! * `progress` — sends `steps` progress notifications with the request's
//!   progress token, then returns `done`;
//! * `sleep` — waits until the request is cancelled and records
//!   `cancelled-<label>` in the marker directory (or gives up after 60 s);
//!   with `descendant`, it first starts a synthetic descendant process in its
//!   own process group (see [`DESCENDANT_MODE`]);
//! * `crash` — writes a synthetic marker to stderr and exits with status 3;
//!   with `label`, it first sends one progress notification and waits for
//!   the test's release marker, so the crash lands mid-stream;
//! * `stderr_flood` — writes `bytes` synthetic bytes to stderr and returns;
//! * `big` — returns a text block of `bytes` synthetic bytes;
//! * `log` — sends `count` `notifications/message` log notifications whose
//!   data is [`log_data`], then returns `logged-<count>`;
//! * `stream` — sends `events` progress notifications whose messages are
//!   [`stream_event_message`], pausing after each index listed in `gates`
//!   until the test releases it, then returns [`stream_result`];
//! * `gate` — waits for the test's release marker, then returns
//!   `released-<label>`;
//! * `detach` — starts a descendant that **deliberately leaves** this
//!   server's process group by `route` (`setsid` or `daemon`), waits for it
//!   to publish its pid, and says whether it did.  It is the fixture task row
//!   M3-09 asks for, and it records whether the escape syscall actually
//!   succeeded so a test can refuse to draw a containment conclusion from a
//!   descendant that never detached.
//!
//! Every call appends `<tool>` to `invocations.log` in the marker directory,
//! so a test can prove a tool ran exactly once.  `initialize`,
//! `server/discover` and `tools/list` append their method to
//! `discovery.log`.
//!
//! **Release markers.**  A tool that waits writes `waiting-<name>` and polls
//! for `release-<name>` (bounded by [`RELEASE_WAIT`]).  `tools/list` waits
//! the same way under the name `discovery` when the test created
//! `hold-discovery`, and consumes that request marker so only one listing is
//! held.  The markers are the only coupling between a test and a server
//! process; the waiting server polls, the test never sleeps on them.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use rmcp::model::{
    CallToolRequestParams, CallToolResponse, CallToolResult, ContentBlock, DiscoverResult,
    Implementation, InitializeRequestParams, InitializeResult, ListToolsResult,
    PaginatedRequestParams, ProgressNotificationParam, ServerCapabilities, ServerConfig, Tool,
};
use rmcp::service::RequestContext;
use rmcp::{ErrorData, RoleServer, ServerHandler};
use tokio::io::AsyncWriteExt;

/// The synthetic stderr marker `crash` writes.  Tests assert it never
/// reaches a consumer.
pub const STDERR_MARKER: &str = "SYNTHETIC-FIXTURE-STDERR-MARKER";
/// A 1x1 transparent PNG, base64.
pub const IMAGE_PNG_BASE64: &str =
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII=";
/// The binary's first argument that runs a synthetic descendant: it writes
/// its process ID to the path given as the second argument and then waits,
/// bounded by [`DESCENDANT_LIFETIME`], without leaving its process group.
pub const DESCENDANT_MODE: &str = "descendant";
/// The binary's first argument that runs a descendant which **deliberately
/// leaves** the server's process group: `detached <route> <pid-file>`.  See
/// [`DetachRoute`].
pub const DETACHED_MODE: &str = "detached";
/// The binary's first argument for the middle process of the `daemon` route.
/// It starts the real descendant in a new process group and exits at once, so
/// the descendant is orphaned and reparented exactly as a double-forked
/// daemon is.
pub const DAEMONIZER_MODE: &str = "daemonize";
/// The binary's first argument that runs the `npx`-shaped wrapper the
/// `supervise` probe supervises: `wrapper <pid-file> <helper-pid-file>`.
pub const WRAPPER_MODE: &str = "wrapper";
/// The binary's first argument that runs a real export supervisor a test can
/// `SIGKILL`: `supervise <workspace>`.
pub const SUPERVISE_MODE: &str = "supervise";
/// The binary's first argument that runs a real export supervisor which, on
/// a trigger, requests its child's kill and then **returns from `main` at
/// once**: `supervise-return <workspace> <wait|nowait> <multi|single>`.  That is the shape
/// of `tunnel-client connect`'s orderly stop, whose session actor drops its
/// handlers (requesting every child's kill) immediately before `main`
/// returns and the runtime is torn down (task row M6-C29).  `wait` first
/// waits, bounded, for the supervisor's `running` counter to reach zero.
/// `multi` runs on the binary's multi-thread runtime, as `tunnel-client`
/// does; `single` on a current-thread runtime of its own, where nothing can
/// poll the supervisor task before teardown.
pub const SUPERVISE_RETURN_MODE: &str = "supervise-return";
/// The file whose appearance tells a `supervise-return` probe to stop.
pub const SUPERVISE_RETURN_TRIGGER: &str = "supervise.return";
/// The binary's first argument that runs a backend which starts one escaping
/// descendant and then behaves like an ordinary stdio server:
/// `detach-host <route> <pid-file>`.
///
/// The host exists so the escaping process is a **descendant** of the
/// supervised child rather than the supervised child itself.  A supervisor
/// signals its own child by pid as well as by group, so a child that detached
/// from its own group would still be killed and the measurement would be of
/// the direct signal, not of the group's reach.
pub const DETACH_HOST_MODE: &str = "detach-host";
/// The longest a synthetic descendant lives on its own.
pub const DESCENDANT_LIFETIME: Duration = Duration::from_secs(180);

/// How a descendant gets out of the supervised child's process group.
///
/// **Both routes must be measured, not one.**  They leave by different
/// syscalls and a containment mechanism can close one and not the other: a
/// mechanism that only tracked sessions would stop `setsid` and miss
/// `setpgid`, and one that only tracked parentage would stop neither.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachRoute {
    /// `setsid`: a brand new session *and* process group, and no controlling
    /// terminal.  The classic server-goes-into-the-background move.
    Setsid,
    /// A double fork: the descendant is started by a middle process which
    /// exits immediately, so the descendant is reparented to `init` and its
    /// ancestry back to the supervisor is destroyed, and it is placed in a
    /// process group of its own.  This is what a daemonizing server does, and
    /// it defeats containment by parent-chain walking as well as containment
    /// by process group.
    Daemon,
}

impl DetachRoute {
    /// The wire spelling used in tool arguments and argv.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Setsid => "setsid",
            Self::Daemon => "daemon",
        }
    }

    /// Parse the wire spelling.  An unknown route is [`None`] rather than a
    /// silent default: a typo in a test must not quietly measure the other
    /// route and report it under the wrong name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "setsid" => Some(Self::Setsid),
            "daemon" => Some(Self::Daemon),
            _ => None,
        }
    }
}

/// Written next to a detached descendant's pid file: `ok` when the escape
/// syscall succeeded, `err` when it did not.
///
/// **A test must read this and refuse to conclude anything when it says
/// `err`.**  A fixture that failed to detach makes every containment claim
/// built on it vacuous: the descendant would be killed by the plain group
/// signal and the mechanism under test would never have been exercised.
pub const ESCAPE_MARKER_EXTENSION: &str = "escape";
/// The longest the `detach` tool waits for its descendant to publish a pid
/// before answering.  The tool answers either way and says what happened; it
/// never blocks a test indefinitely on a process that failed to start.
pub const DETACH_PUBLISH_WAIT: Duration = Duration::from_secs(10);
/// The longest a server waits for a release marker.
pub const RELEASE_WAIT: Duration = Duration::from_secs(120);
/// How often a waiting server looks for its release marker.
const RELEASE_POLL: Duration = Duration::from_millis(10);
/// The `tools/list` hold request marker.
pub const HOLD_DISCOVERY: &str = "hold-discovery";
/// The release name of a held `tools/list`.
pub const DISCOVERY_RELEASE: &str = "discovery";

/// The message of `stream` event `index` for `label`: a fixed prefix and
/// `bytes` deterministic synthetic ASCII characters.
#[must_use]
pub fn stream_event_message(label: &str, index: u64, bytes: usize) -> String {
    let mut message = format!("{label}:{index}:");
    let mut state = 0x9E37_79B9_7F4A_7C15u64 ^ index.wrapping_mul(0x0100_0000_01B3);
    for _ in 0..bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        let offset = u8::try_from(state % 62).unwrap_or(0);
        message.push(char::from(match offset {
            0..=9 => b'0' + offset,
            10..=35 => b'a' + offset - 10,
            _ => b'A' + offset - 36,
        }));
    }
    message
}

/// The text `stream` returns once every event was sent.
#[must_use]
pub fn stream_result(label: &str, events: u64, bytes: usize) -> String {
    format!("stream-done:{label}:{events}:{bytes}")
}

/// The data of log notification `index` for `label`.
#[must_use]
pub fn log_data(label: &str, index: u64) -> serde_json::Value {
    serde_json::json!({"label": label, "seq": index, "synthetic": true})
}

/// The file name a waiting server writes.
#[must_use]
pub fn waiting_marker(name: &str) -> String {
    format!("waiting-{name}")
}

/// The file name that releases a waiting server.
#[must_use]
pub fn release_marker(name: &str) -> String {
    format!("release-{name}")
}

/// The pid file a `descendant` label writes.
#[must_use]
pub fn descendant_pid_file(label: &str) -> String {
    format!("descendant-{label}.pid")
}

/// The pid file a `detach` label writes.
#[must_use]
pub fn detached_pid_file(label: &str) -> String {
    format!("detached-{label}.pid")
}

/// Where a detached descendant records whether its escape syscall succeeded.
#[must_use]
pub fn escape_marker(pid_file: &Path) -> PathBuf {
    pid_file.with_extension(ESCAPE_MARKER_EXTENSION)
}

/// The fixture server.
#[derive(Clone, Debug, Default)]
pub struct FixtureServer {
    marker_dir: Option<Arc<PathBuf>>,
}

impl FixtureServer {
    #[must_use]
    pub fn new(marker_dir: Option<PathBuf>) -> Self {
        Self {
            marker_dir: marker_dir.map(Arc::new),
        }
    }

    async fn record(&self, name: &str, line: &str) {
        let Some(dir) = &self.marker_dir else { return };
        if let Ok(mut file) = tokio::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(dir.join(name))
            .await
        {
            let _ = file.write_all(format!("{line}\n").as_bytes()).await;
            let _ = file.flush().await;
        }
    }

    /// Write `waiting-<name>` and wait for `release-<name>`.  Returns whether
    /// the release arrived.  Without a marker directory nothing waits.
    async fn wait_release(&self, name: &str) -> bool {
        let Some(dir) = &self.marker_dir else {
            return true;
        };
        let _ = tokio::fs::write(dir.join(waiting_marker(name)), b"waiting").await;
        let release = dir.join(release_marker(name));
        let deadline = tokio::time::Instant::now() + RELEASE_WAIT;
        while tokio::time::Instant::now() < deadline {
            if tokio::fs::try_exists(&release).await.unwrap_or(false) {
                return true;
            }
            tokio::time::sleep(RELEASE_POLL).await;
        }
        false
    }

    /// Consume the `tools/list` hold request, if the test created one.
    async fn take_discovery_hold(&self) -> bool {
        let Some(dir) = &self.marker_dir else {
            return false;
        };
        // A rename is atomic, so exactly one listing claims the hold.
        tokio::fs::rename(dir.join(HOLD_DISCOVERY), dir.join("hold-discovery-claimed"))
            .await
            .is_ok()
    }

    fn spawn_descendant(&self, label: &str) {
        let Some(dir) = &self.marker_dir else { return };
        let Ok(executable) = std::env::current_exe() else {
            return;
        };
        // Same process group as this server: only a group kill reaches it.
        let spawned = std::process::Command::new(executable)
            .arg(DESCENDANT_MODE)
            .arg(dir.join(descendant_pid_file(label)))
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = spawned {
            // Reap it whenever it ends, so it never lingers as a zombie.
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }

    /// Start a descendant that deliberately leaves this server's process
    /// group by `route`.  Returns whether the process started at all.
    fn spawn_detached(&self, label: &str, route: DetachRoute) -> bool {
        let Some(dir) = &self.marker_dir else {
            return false;
        };
        let Ok(executable) = std::env::current_exe() else {
            return false;
        };
        let pid_file = dir.join(detached_pid_file(label));
        let mut command = std::process::Command::new(executable);
        match route {
            // One hop: the descendant itself calls `setsid`.
            DetachRoute::Setsid => {
                command
                    .arg(DETACHED_MODE)
                    .arg(route.as_str())
                    .arg(&pid_file);
            }
            // Two hops: a middle process starts the descendant and exits, so
            // the descendant is reparented away from this server entirely.
            DetachRoute::Daemon => {
                command.arg(DAEMONIZER_MODE).arg(&pid_file);
            }
        }
        let spawned = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        let Ok(mut child) = spawned else {
            return false;
        };
        // Reap it so it never lingers as a zombie.  For the daemon route this
        // is the middle process, which exits immediately.
        std::thread::spawn(move || {
            let _ = child.wait();
        });
        true
    }

    /// Wait, bounded, for a detached descendant to publish its pid.
    async fn await_detached(&self, label: &str) -> bool {
        let Some(dir) = &self.marker_dir else {
            return false;
        };
        let pid_file = dir.join(detached_pid_file(label));
        let deadline = tokio::time::Instant::now() + DETACH_PUBLISH_WAIT;
        while tokio::time::Instant::now() < deadline {
            if tokio::fs::try_exists(&pid_file).await.unwrap_or(false) {
                return true;
            }
            tokio::time::sleep(RELEASE_POLL).await;
        }
        false
    }
}

/// The file the `supervise` probe writes, three space-separated fields:
/// `<wrapper-pid> <helper-pid> <sentinels-armed>`.  The third is what lets a
/// test tell "the mechanism ran and contained this" from "the mechanism was
/// never there", which is the difference between the two `SIGKILL`
/// measurements in `tests/process_residue.rs`.
pub const SUPERVISE_REPORT: &str = "supervise.report";
/// The wrapper's own pid file inside the probe's workspace.
pub const WRAPPER_PID_FILE: &str = "wrapper.pid";
/// The wrapper's in-group helper pid file inside the probe's workspace.
pub const HELPER_PID_FILE: &str = "helper.pid";

/// Run one real [`tunnel_mcp_export::child`] supervisor over [`run_wrapper`],
/// report the pids it created, and then **park forever**.
///
/// This exists because the supervisor's most dangerous end of life cannot be
/// reached from inside a test process: a `SIGKILL` runs no `Drop`, no
/// `kill_on_drop` and no handler, so to measure it something other than the
/// test has to be the supervisor and the test has to kill it.  A test that
/// dropped a handle and asserted the handle was closed would prove nothing
/// about this at all.
pub async fn run_supervise(workspace: &Path) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let backend = tunnel_mcp_export::config::StdioBackend {
        command: executable,
        args: vec![
            WRAPPER_MODE.to_owned(),
            workspace.join(WRAPPER_PID_FILE).display().to_string(),
            workspace.join(HELPER_PID_FILE).display().to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        inherit_env: Vec::new(),
        workspace: workspace.to_path_buf(),
        max_children: 1,
        session_idle: Duration::from_secs(600),
    };
    let counters = std::sync::Arc::new(tunnel_mcp_export::child::ChildCounters::default());
    let Ok((handle, _events)) = tunnel_mcp_export::child::spawn(&backend, 1 << 20, &counters)
    else {
        return;
    };
    let wrapper = read_pid(&workspace.join(WRAPPER_PID_FILE)).await;
    let helper = read_pid(&workspace.join(HELPER_PID_FILE)).await;
    let armed = counters
        .deadman_armed
        .load(std::sync::atomic::Ordering::Relaxed);
    let temporary = workspace.join("supervise.tmp");
    if tokio::fs::write(&temporary, format!("{wrapper} {helper} {armed}"))
        .await
        .is_ok()
    {
        let _ = tokio::fs::rename(&temporary, workspace.join(SUPERVISE_REPORT)).await;
    }
    // Hold the handle so nothing drops it, and wait to be killed.
    std::future::pending::<()>().await;
    drop(handle);
}

/// Supervise [`run_wrapper`] exactly as [`run_supervise`] does, then, once
/// [`SUPERVISE_RETURN_TRIGGER`] appears, request the child's kill and return
/// -- after waiting for `running` to reach zero when `wait_for_reap` is set.
///
/// The kill request is `ChildHandle::kill`, which is what an export's
/// `shutdown_sessions` calls and therefore what dropping `HttpHandlers` does.
/// Returning from `main` right after it tears the runtime down with the
/// supervisor task's group kill, reap and sentinel stand-down possibly not
/// yet run.
pub async fn run_supervise_then_return(workspace: &Path, wait_for_reap: bool) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let backend = tunnel_mcp_export::config::StdioBackend {
        command: executable,
        args: vec![
            WRAPPER_MODE.to_owned(),
            workspace.join(WRAPPER_PID_FILE).display().to_string(),
            workspace.join(HELPER_PID_FILE).display().to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        inherit_env: Vec::new(),
        workspace: workspace.to_path_buf(),
        max_children: 1,
        session_idle: Duration::from_secs(600),
    };
    let counters = std::sync::Arc::new(tunnel_mcp_export::child::ChildCounters::default());
    let Ok((handle, _events)) = tunnel_mcp_export::child::spawn(&backend, 1 << 20, &counters)
    else {
        return;
    };
    let wrapper = read_pid(&workspace.join(WRAPPER_PID_FILE)).await;
    let helper = read_pid(&workspace.join(HELPER_PID_FILE)).await;
    let armed = counters
        .deadman_armed
        .load(std::sync::atomic::Ordering::Relaxed);
    let temporary = workspace.join("supervise.tmp");
    if tokio::fs::write(&temporary, format!("{wrapper} {helper} {armed}"))
        .await
        .is_err()
        || tokio::fs::rename(&temporary, workspace.join(SUPERVISE_REPORT))
            .await
            .is_err()
    {
        return;
    }
    let trigger = workspace.join(SUPERVISE_RETURN_TRIGGER);
    let deadline = tokio::time::Instant::now() + DETACH_PUBLISH_WAIT;
    while !trigger.exists() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(RELEASE_POLL).await;
    }
    handle.kill();
    if wait_for_reap {
        let deadline = tokio::time::Instant::now() + DETACH_PUBLISH_WAIT;
        while counters.running.load(std::sync::atomic::Ordering::Acquire) != 0
            && tokio::time::Instant::now() < deadline
        {
            tokio::time::sleep(RELEASE_POLL).await;
        }
    }
    drop(handle);
}

/// Read a published pid, bounded.  Empty when it never appeared.
async fn read_pid(path: &Path) -> String {
    let deadline = tokio::time::Instant::now() + DETACH_PUBLISH_WAIT;
    while tokio::time::Instant::now() < deadline {
        let pid = tokio::fs::read_to_string(path)
            .await
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !pid.is_empty() {
            return pid;
        }
        tokio::time::sleep(RELEASE_POLL).await;
    }
    String::new()
}

/// Run the wrapper the `supervise` probe uses as an export backend.
///
/// It models the shape that makes the process group kill worth having in the
/// first place: an `npx`/`uvx`/`/bin/sh` wrapper that starts a helper which
/// **does not read stdin**, and then reads stdin itself.  When the supervisor
/// goes away the wrapper sees end of file and exits, but the helper has no
/// way to notice and no reason to stop.  Only something that signals the
/// group ends it — and if the supervisor was `SIGKILL`ed, the supervisor is
/// not there to be that something.
///
/// Both pids are published so a test asserts against the process table rather
/// than against anybody's belief about what it started.
pub async fn run_wrapper(pid_file: &Path, helper_pid_file: &Path) {
    publish_pid(pid_file).await;
    if let Ok(executable) = std::env::current_exe() {
        // No `process_group`: the helper stays in the wrapper's group, which
        // is the supervised child's group.  It is exactly what a group kill
        // is supposed to reach.
        let spawned = std::process::Command::new(executable)
            .arg(DESCENDANT_MODE)
            .arg(helper_pid_file)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = spawned {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    // Drain stdin to end of file, then exit, as a wrapper does.
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0u8; 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut stdin, &mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Run the backend that starts one escaping descendant and then drains stdin.
///
/// For [`DetachRoute::Setsid`] the descendant is this process's direct child
/// and calls `setsid` itself; for [`DetachRoute::Daemon`] this process starts
/// the middle process, which starts the descendant in a new group and exits.
/// Either way the escaping process is a descendant of the supervised child,
/// never the supervised child itself.
pub async fn run_detach_host(route: DetachRoute, pid_file: &Path) {
    if let Ok(executable) = std::env::current_exe() {
        let mut command = std::process::Command::new(executable);
        match route {
            DetachRoute::Setsid => {
                command.arg(DETACHED_MODE).arg(route.as_str()).arg(pid_file);
            }
            DetachRoute::Daemon => {
                command.arg(DAEMONIZER_MODE).arg(pid_file);
            }
        }
        let spawned = command
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn();
        if let Ok(mut child) = spawned {
            std::thread::spawn(move || {
                let _ = child.wait();
            });
        }
    }
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0u8; 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut stdin, &mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Publish a pid atomically, so a reader never sees a half-written file.
async fn publish_pid(pid_file: &Path) {
    let temporary = pid_file.with_extension("tmp");
    if tokio::fs::write(&temporary, std::process::id().to_string())
        .await
        .is_ok()
    {
        let _ = tokio::fs::rename(&temporary, pid_file).await;
    }
}

/// Run the middle process of the [`DetachRoute::Daemon`] route.
///
/// It starts the real descendant in a **new process group** and returns at
/// once.  The caller (the binary's `main`) then exits, so the descendant is
/// orphaned and reparented to `init`: nothing in the process table records
/// that the supervised server ever started it.  This is the half of a
/// double-forked daemon that matters for containment, reached without
/// `fork`, so this crate stays `forbid(unsafe_code)`.
pub fn run_daemonizer(pid_file: &Path) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let mut command = std::process::Command::new(executable);
    command
        .arg(DETACHED_MODE)
        .arg(DetachRoute::Daemon.as_str())
        .arg(pid_file)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    // Deliberately not waited on: exiting now is what orphans it.
    let _ = command.spawn();
}

/// Run a descendant that has escaped the supervised child's process group.
///
/// For [`DetachRoute::Setsid`] it calls `setsid` here; for
/// [`DetachRoute::Daemon`] the escape already happened, in the new process
/// group its middle process placed it in.  Either way it records **whether
/// the escape really happened** next to the pid, because a fixture that
/// failed to detach would make every containment measurement built on it
/// vacuous.
pub async fn run_detached(route: DetachRoute, pid_file: &Path) {
    let escaped = match route {
        #[cfg(unix)]
        DetachRoute::Setsid => rustix::process::setsid().is_ok(),
        #[cfg(not(unix))]
        DetachRoute::Setsid => false,
        // The middle process placed this one in a group of its own, and it
        // has already exited, so this process is both out of the group and
        // orphaned.  Confirm the group rather than assume it: the pid of a
        // process that leads its own group is its own group id.
        #[cfg(unix)]
        DetachRoute::Daemon => {
            rustix::process::getpgrp().as_raw_nonzero().get()
                == i32::try_from(std::process::id()).unwrap_or(-1)
        }
        #[cfg(not(unix))]
        DetachRoute::Daemon => false,
    };
    let _ = tokio::fs::write(escape_marker(pid_file), if escaped { "ok" } else { "err" }).await;
    let temporary = pid_file.with_extension("tmp");
    if tokio::fs::write(&temporary, std::process::id().to_string())
        .await
        .is_ok()
    {
        let _ = tokio::fs::rename(&temporary, pid_file).await;
    }
    tokio::time::sleep(DESCENDANT_LIFETIME).await;
}

/// Run a synthetic descendant: publish the pid atomically, then wait.
pub async fn run_descendant(pid_file: &Path) {
    let temporary = pid_file.with_extension("tmp");
    if tokio::fs::write(&temporary, std::process::id().to_string())
        .await
        .is_ok()
    {
        let _ = tokio::fs::rename(&temporary, pid_file).await;
    }
    tokio::time::sleep(DESCENDANT_LIFETIME).await;
}

fn schema(properties: serde_json::Value) -> Arc<serde_json::Map<String, serde_json::Value>> {
    let serde_json::Value::Object(map) = serde_json::json!({
        "type": "object",
        "properties": properties,
    }) else {
        unreachable!("literal object")
    };
    Arc::new(map)
}

fn tools() -> Vec<Tool> {
    vec![
        Tool::new(
            "echo",
            "Echo arguments and _meta",
            schema(serde_json::json!({})),
        ),
        Tool::new(
            "progress",
            "Send progress notifications",
            schema(serde_json::json!({"steps": {"type": "integer"}})),
        ),
        Tool::new(
            "sleep",
            "Wait until cancelled",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "descendant": {"type": "boolean"},
            })),
        ),
        Tool::new(
            "crash",
            "Exit the process",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "descendant": {"type": "boolean"},
            })),
        ),
        Tool::new(
            "stderr_flood",
            "Write synthetic stderr",
            schema(serde_json::json!({"bytes": {"type": "integer"}})),
        ),
        Tool::new(
            "big",
            "Return a large text block",
            schema(serde_json::json!({"bytes": {"type": "integer"}})),
        ),
        Tool::new(
            "log",
            "Send log notifications",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "count": {"type": "integer"},
            })),
        ),
        Tool::new(
            "stream",
            "Stream gated progress events",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "events": {"type": "integer"},
                "bytes": {"type": "integer"},
                "gates": {"type": "array", "items": {"type": "integer"}},
            })),
        ),
        Tool::new(
            "gate",
            "Wait for a release marker",
            schema(serde_json::json!({"label": {"type": "string"}})),
        ),
        Tool::new(
            "detach",
            "Start a descendant that leaves this server's process group",
            schema(serde_json::json!({
                "label": {"type": "string"},
                "route": {"type": "string", "enum": ["setsid", "daemon"]},
            })),
        ),
    ]
}

fn argument_u64(request: &CallToolRequestParams, name: &str, default: u64) -> u64 {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get(name))
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(default)
}

fn argument_bool(request: &CallToolRequestParams, name: &str) -> bool {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get(name))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// A label argument reduced to ASCII letters and digits (it names files).
fn argument_label(request: &CallToolRequestParams) -> Option<String> {
    request
        .arguments
        .as_ref()
        .and_then(|arguments| arguments.get("label"))
        .and_then(serde_json::Value::as_str)
        .map(|label| {
            label
                .chars()
                .filter(char::is_ascii_alphanumeric)
                .take(64)
                .collect::<String>()
        })
        .filter(|label| !label.is_empty())
}

impl ServerHandler for FixtureServer {
    // Logging is deprecated by SEP-2577 but still part of both pinned
    // profiles; the gate exercises `notifications/message` deliberately.
    #[allow(deprecated)]
    fn get_info(&self) -> ServerConfig {
        ServerConfig::new(
            ServerCapabilities::builder()
                .enable_tools()
                .enable_logging()
                .build(),
        )
        .with_server_info(Implementation::new("tunnel-mcp-fixture", "0.1.0"))
    }

    async fn initialize(
        &self,
        request: InitializeRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<InitializeResult, ErrorData> {
        self.record("discovery.log", "initialize").await;
        context.peer.set_peer_info(request.clone());
        self.negotiate_initialize(&request)
    }

    async fn discover(
        &self,
        _context: RequestContext<RoleServer>,
    ) -> Result<DiscoverResult, ErrorData> {
        self.record("discovery.log", "server/discover").await;
        Ok(DiscoverResult::from_server_info(
            self.supported_protocol_versions().into_owned(),
            self.get_info(),
        ))
    }

    async fn list_tools(
        &self,
        _request: Option<PaginatedRequestParams>,
        _context: RequestContext<RoleServer>,
    ) -> Result<ListToolsResult, ErrorData> {
        self.record("discovery.log", "tools/list").await;
        if self.take_discovery_hold().await && !self.wait_release(DISCOVERY_RELEASE).await {
            return Err(ErrorData::internal_error("discovery hold expired", None));
        }
        Ok(ListToolsResult::with_all_items(tools()))
    }

    #[allow(clippy::too_many_lines)]
    async fn call_tool(
        &self,
        request: CallToolRequestParams,
        context: RequestContext<RoleServer>,
    ) -> Result<CallToolResponse, ErrorData> {
        self.record("invocations.log", &request.name).await;
        match request.name.as_ref() {
            "echo" => {
                let text = serde_json::json!({
                    "arguments": request.arguments,
                    "meta": context.meta,
                })
                .to_string();
                Ok(CallToolResult::success(vec![
                    ContentBlock::text(text),
                    ContentBlock::image(IMAGE_PNG_BASE64, "image/png"),
                ])
                .into())
            }
            "progress" => {
                let steps = argument_u64(&request, "steps", 3).min(100);
                if let Some(token) = context.meta.get_progress_token() {
                    for step in 0..steps {
                        #[allow(clippy::cast_precision_loss)]
                        let _ = context
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), (step + 1) as f64)
                                    .with_total(steps as f64),
                            )
                            .await;
                        tokio::time::sleep(Duration::from_millis(5)).await;
                    }
                }
                Ok(CallToolResult::success(vec![ContentBlock::text("done")]).into())
            }
            "detach" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                let route = request
                    .arguments
                    .as_ref()
                    .and_then(|arguments| arguments.get("route"))
                    .and_then(serde_json::Value::as_str)
                    .and_then(DetachRoute::parse);
                let Some(route) = route else {
                    return Err(ErrorData::invalid_params("unknown detach route", None));
                };
                let started = self.spawn_detached(&label, route);
                // Answer only once the descendant exists, so a test that
                // kills the server next cannot win a race against a process
                // that had not been created yet.
                let published = started && self.await_detached(&label).await;
                Ok(CallToolResult::success(vec![ContentBlock::text(format!(
                    "detached:{}:{label}:{published}",
                    route.as_str()
                ))])
                .into())
            }
            "sleep" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                if argument_bool(&request, "descendant") {
                    self.spawn_descendant(&label);
                }
                tokio::select! {
                    () = context.ct.cancelled() => {
                        self.record(&format!("cancelled-{label}"), "cancelled").await;
                        Ok(CallToolResult::success(vec![ContentBlock::text("cancelled")]).into())
                    }
                    () = tokio::time::sleep(Duration::from_secs(60)) => {
                        Ok(CallToolResult::success(vec![ContentBlock::text("slept")]).into())
                    }
                }
            }
            "crash" => {
                if let Some(label) = argument_label(&request) {
                    if argument_bool(&request, "descendant") {
                        self.spawn_descendant(&label);
                    }
                    if let Some(token) = context.meta.get_progress_token() {
                        let _ = context
                            .peer
                            .notify_progress(
                                ProgressNotificationParam::new(token.clone(), 1.0)
                                    .with_message(format!("before-crash:{label}")),
                            )
                            .await;
                    }
                    let _ = self.wait_release(&format!("crash{label}")).await;
                }
                let mut stderr = tokio::io::stderr();
                let _ = stderr.write_all(STDERR_MARKER.as_bytes()).await;
                let _ = stderr.flush().await;
                std::process::exit(3);
            }
            "stderr_flood" => {
                let bytes = argument_u64(&request, "bytes", 1 << 20).min(64 << 20);
                let chunk = vec![b'e'; 64 * 1024];
                let mut stderr = tokio::io::stderr();
                let mut written = 0u64;
                while written < bytes {
                    let take = usize::try_from((bytes - written).min(chunk.len() as u64))
                        .unwrap_or(chunk.len());
                    if stderr.write_all(&chunk[..take]).await.is_err() {
                        break;
                    }
                    written += take as u64;
                }
                let _ = stderr.flush().await;
                Ok(CallToolResult::success(vec![ContentBlock::text("flooded")]).into())
            }
            "big" => {
                let bytes = usize::try_from(argument_u64(&request, "bytes", 1024).min(64 << 20))
                    .unwrap_or(1024);
                Ok(CallToolResult::success(vec![ContentBlock::text("b".repeat(bytes))]).into())
            }
            "log" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                let count = argument_u64(&request, "count", 3).min(100);
                for index in 0..count {
                    #[allow(deprecated)]
                    let _ = context
                        .peer
                        .notify_logging_message(
                            rmcp::model::LoggingMessageNotificationParam::new(
                                rmcp::model::LoggingLevel::Info,
                                log_data(&label, index),
                            )
                            .with_logger("tunnel-mcp-fixture"),
                        )
                        .await;
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(format!("logged-{count}"))])
                        .into(),
                )
            }
            "stream" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                let events = argument_u64(&request, "events", 8).min(4096);
                let bytes = usize::try_from(argument_u64(&request, "bytes", 64).min(64 * 1024))
                    .unwrap_or(64);
                let gates = request
                    .arguments
                    .as_ref()
                    .and_then(|arguments| arguments.get("gates"))
                    .and_then(serde_json::Value::as_array)
                    .map(|gates| {
                        gates
                            .iter()
                            .filter_map(serde_json::Value::as_u64)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let Some(token) = context.meta.get_progress_token() else {
                    return Err(ErrorData::invalid_params(
                        "stream needs a progress token",
                        None,
                    ));
                };
                for index in 0..events {
                    #[allow(clippy::cast_precision_loss)]
                    let sent = context
                        .peer
                        .notify_progress(
                            ProgressNotificationParam::new(token.clone(), (index + 1) as f64)
                                .with_total(events as f64)
                                .with_message(stream_event_message(&label, index, bytes)),
                        )
                        .await;
                    if sent.is_err() {
                        return Err(ErrorData::internal_error("stream peer closed", None));
                    }
                    if gates.contains(&index)
                        && !self.wait_release(&format!("stream{label}g{index}")).await
                    {
                        return Err(ErrorData::internal_error("stream gate expired", None));
                    }
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(stream_result(
                        &label, events, bytes,
                    ))])
                    .into(),
                )
            }
            "gate" => {
                let label = argument_label(&request).unwrap_or_else(|| "default".to_owned());
                if !self.wait_release(&format!("gate{label}")).await {
                    return Err(ErrorData::internal_error("gate expired", None));
                }
                Ok(
                    CallToolResult::success(vec![ContentBlock::text(format!("released-{label}"))])
                        .into(),
                )
            }
            _ => Err(ErrorData::invalid_params("unknown tool", None)),
        }
    }
}

/// Serve the fixture with the official rmcp Streamable HTTP server on
/// `listener` until `shutdown`.  `legacy_sessions` selects rmcp's
/// 2025-11-25 session mode; otherwise requests are served statelessly.
pub async fn serve_http(
    listener: tokio::net::TcpListener,
    legacy_sessions: bool,
    marker_dir: PathBuf,
    shutdown: tokio_util::sync::CancellationToken,
) {
    use hyper_util::rt::TokioIo;
    use rmcp::transport::streamable_http_server::session::local::LocalSessionManager;
    use rmcp::transport::{StreamableHttpServerConfig, StreamableHttpService};
    let server = FixtureServer::new(Some(marker_dir));
    let config = StreamableHttpServerConfig::default()
        .with_legacy_session_mode(legacy_sessions)
        .with_sse_keep_alive(None)
        .with_cancellation_token(shutdown.child_token());
    let service: StreamableHttpService<FixtureServer, LocalSessionManager> =
        StreamableHttpService::new(
            move || Ok(server.clone()),
            Arc::new(LocalSessionManager::default()),
            config,
        );
    loop {
        let accepted = tokio::select! {
            () = shutdown.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let stream = match accepted {
            Ok((stream, _)) => stream,
            // A per-connection accept error (a peer that vanished, a
            // momentary descriptor limit) is not the end of the listener.
            Err(error) => {
                eprintln!("tunnel-mcp-fixture: accept failed: {}", error.kind());
                continue;
            }
        };
        let service = hyper_util::service::TowerToHyperService::new(service.clone());
        tokio::spawn(async move {
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(TokioIo::new(stream), service)
                .await;
        });
    }
}
