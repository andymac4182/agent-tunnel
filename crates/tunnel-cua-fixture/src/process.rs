//! The fixture's process-shaped modes: the supervised backend, the helpers
//! that model what a real backend leaves behind, and a real supervisor in a
//! process a test can `SIGKILL`.
//!
//! # Why any of this exists
//!
//! `docs/tasks.md` M3-09 and M8-C07 split process containment into two holes
//! that need two different answers, and a test that cannot tell them apart
//! proves neither:
//!
//! * **Reach.** A descendant that calls `setsid` or double-forks is not in the
//!   backend's process group, so no group signal reaches it. [`run_detached`]
//!   is that descendant, and it **records whether its escape syscall actually
//!   succeeded** — a fixture that failed to detach would be killed by the
//!   plain group signal and every containment conclusion drawn from it would
//!   be vacuous.
//! * **Trigger.** A `SIGKILL` of the supervising process runs no `Drop`, so
//!   without a sentinel nobody signals the group at all and even an ordinary
//!   in-group helper survives. [`run_supervise`] puts a real supervisor in a
//!   separate process **because a `SIGKILL` cannot be simulated from inside
//!   the process holding the handle**.
//!
//! [`run_backend`]'s in-group helper is what makes the trigger half worth
//! measuring: it does not read stdin, so when the supervisor goes away it has
//! no way to notice and no reason to stop. Only something that signals the
//! group ends it — and if the supervisor was `SIGKILL`ed, the supervisor is
//! not there to be that something.

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::{FixtureBackend, Ledger};

/// Serve the fixture backend, publish its address, and hold an in-group
/// helper: `backend <address-file> <journal> <helper-pid-file> [<hang-command>]`.
///
/// The optional fifth argument names one backend command that should
/// [`crate::Fault::HangAfterLedger`]. A backend in another process has no
/// in-process fault knob, and the alternative -- a control channel a test
/// pokes at runtime -- would be a second way into the backend that the
/// containment tests would then have to reason about. An argument is read once,
/// at start, and cannot be confused for traffic.
pub const BACKEND_MODE: &str = "backend";
/// A worker that stays in the backend's process group and never reads stdin:
/// `helper <pid-file>`.
pub const HELPER_MODE: &str = "helper";
/// A descendant that deliberately leaves the group: `detached <route> <pid-file>`.
pub const DETACHED_MODE: &str = "detached";
/// The middle process of the double-fork route: `daemonize <pid-file>`.
pub const DAEMONIZER_MODE: &str = "daemonize";
/// A backend that also starts one escaping descendant:
/// `detach-host <route> <address-file> <journal> <pid-file>`.
pub const DETACH_HOST_MODE: &str = "detach-host";
/// A real supervisor in a process a test can `SIGKILL`: `supervise <workspace>`.
pub const SUPERVISE_MODE: &str = "supervise";

/// The supervised backend's address file inside a probe's workspace.
pub const ADDRESS_FILE: &str = "backend.address";
/// The supervised backend's effect journal inside a probe's workspace.
pub const JOURNAL_FILE: &str = "backend.journal";
/// The supervised backend's own pid file inside a probe's workspace.
pub const BACKEND_PID_FILE: &str = "backend.pid";
/// The in-group helper's pid file inside a probe's workspace.
pub const HELPER_PID_FILE: &str = "helper.pid";
/// What the `supervise` probe reports: `<backend> <helper> <armed>`.
pub const SUPERVISE_REPORT: &str = "supervise.report";

/// The longest a synthetic helper or descendant lives on its own.
///
/// Bounded so a failed test run leaves nothing behind for three minutes
/// rather than forever.
pub const HELPER_LIFETIME: Duration = Duration::from_secs(180);

/// The longest anything here waits for a pid or an address to appear.
pub const PUBLISH_WAIT: Duration = Duration::from_secs(10);

/// How often a wait looks again.
pub const POLL: Duration = Duration::from_millis(10);

/// Written next to a detached descendant's pid: `ok` when the escape syscall
/// succeeded, `err` when it did not.
///
/// **A test must read this and refuse to conclude anything when it says
/// `err`.** A fixture that failed to detach makes every containment claim
/// built on it vacuous.
pub const ESCAPE_MARKER_EXTENSION: &str = "escape";

/// Where a detached descendant records whether its escape really happened.
#[must_use]
pub fn escape_marker(pid_file: &Path) -> PathBuf {
    pid_file.with_extension(ESCAPE_MARKER_EXTENSION)
}

/// How a descendant gets out of the backend's process group.
///
/// **Both routes must be measured, not one.** They leave by different
/// syscalls and a containment mechanism can close one and not the other.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DetachRoute {
    /// `setsid`: a new session *and* process group, and no controlling
    /// terminal.
    Setsid,
    /// A double fork: the descendant is started by a middle process which
    /// exits at once, so it is reparented to `init` and placed in a group of
    /// its own. This defeats containment by parent-chain walking as well as
    /// containment by process group.
    Daemon,
}

impl DetachRoute {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Setsid => "setsid",
            Self::Daemon => "daemon",
        }
    }

    /// Parse the wire spelling. An unknown route is [`None`] rather than a
    /// silent default: a typo must not quietly measure the other route and
    /// report it under the wrong name.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        match text {
            "setsid" => Some(Self::Setsid),
            "daemon" => Some(Self::Daemon),
            _ => None,
        }
    }
}

/// Publish a pid atomically, so a reader never sees a half-written file.
async fn publish(path: &Path, contents: &str) {
    let temporary = path.with_extension("tmp");
    if tokio::fs::write(&temporary, contents).await.is_ok() {
        let _ = tokio::fs::rename(&temporary, path).await;
    }
}

/// Read a published value, bounded. Empty when it never appeared.
pub async fn read_published(path: &Path) -> String {
    let deadline = tokio::time::Instant::now() + PUBLISH_WAIT;
    while tokio::time::Instant::now() < deadline {
        let text = tokio::fs::read_to_string(path)
            .await
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !text.is_empty() {
            return text;
        }
        tokio::time::sleep(POLL).await;
    }
    String::new()
}

/// Drain stdin to end of file. What a supervised process waits on.
async fn wait_for_stdin_eof() {
    let mut stdin = tokio::io::stdin();
    let mut buffer = [0u8; 1024];
    loop {
        match tokio::io::AsyncReadExt::read(&mut stdin, &mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

/// Start a helper **in this process's group**, and reap it when it ends.
///
/// No `process_group`: the helper stays in the backend's group, which is what
/// a group kill is supposed to reach.
fn spawn_in_group_helper(pid_file: &Path) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let spawned = std::process::Command::new(executable)
        .arg(HELPER_MODE)
        .arg(pid_file)
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

/// Run the supervised backend: serve `/cmd`, publish the bound address, start
/// an in-group helper, and wait for stdin to close.
///
/// The helper is started **before** the address is published, so a supervisor
/// that has an endpoint has a helper too and a test never races one against
/// the other.
pub async fn run_backend(
    address_file: &Path,
    journal: &Path,
    helper_pid_file: &Path,
    hang: Option<&str>,
) {
    publish(
        &address_file.with_file_name(BACKEND_PID_FILE),
        &std::process::id().to_string(),
    )
    .await;
    // **Remove the previous generation's helper pid before starting ours**,
    // for the same reason the supervisor removes the address file: after a
    // restart a reader would otherwise take a dead helper's pid for this
    // one's, and a test that killed it would report a clean run while this
    // generation's helper survived. The supervisor cannot do this for us --
    // it does not know the backend starts a helper at all.
    let _ = tokio::fs::remove_file(helper_pid_file).await;
    spawn_in_group_helper(helper_pid_file);
    // Wait for the helper to publish before the address goes out, so a
    // supervisor that has an endpoint has a helper pid too.
    //
    // **This narrows a race; it does not close one, and it is not
    // load-bearing.** An earlier comment claimed it was, and a guard case
    // written to defend it came back `still green`: the helper publishes
    // within microseconds here, so removing this wait changes nothing
    // observable. The pid is not lost even if it did, because
    // `PidGuard::watch_workspace` re-reads `helper.pid` at drop. Kept because
    // it makes the ordinary path deterministic, not because anything depends
    // on it.
    let _ = read_published(helper_pid_file).await;
    let Ok(backend) = FixtureBackend::start_with(Ledger::with_journal(journal.to_path_buf())).await
    else {
        return;
    };
    if let Some(command) = hang {
        backend.faults().set(command, crate::Fault::HangAfterLedger);
    }
    publish(address_file, &backend.address().to_string()).await;
    wait_for_stdin_eof().await;
}

/// Run a backend that also starts one **escaping** descendant.
///
/// The escaping process is a descendant of the supervised backend, never the
/// backend itself: a supervisor signals its own child by pid as well as by
/// group, so a child that detached from its own group would be killed by the
/// direct signal and the group's reach would never be tested.
pub async fn run_detach_host(
    route: DetachRoute,
    address_file: &Path,
    journal: &Path,
    pid_file: &Path,
) {
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
    let Ok(backend) = FixtureBackend::start_with(Ledger::with_journal(journal.to_path_buf())).await
    else {
        return;
    };
    publish(address_file, &backend.address().to_string()).await;
    wait_for_stdin_eof().await;
}

/// Run the in-group helper: publish a pid, then wait.
///
/// **It never reads stdin.** That is the whole shape: when the supervisor goes
/// away, the backend sees end of file and exits, and this has no way to notice.
pub async fn run_helper(pid_file: &Path) {
    publish(pid_file, &std::process::id().to_string()).await;
    tokio::time::sleep(HELPER_LIFETIME).await;
}

/// Run the middle process of the [`DetachRoute::Daemon`] route.
///
/// It starts the real descendant in a **new process group** and returns at
/// once. The caller's `main` then exits, orphaning the descendant exactly as a
/// double-forked daemon is — reached without `fork`, so this crate stays
/// `forbid(unsafe_code)`.
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

/// Run a descendant that has escaped the backend's process group, recording
/// **whether the escape really happened**.
pub async fn run_detached(route: DetachRoute, pid_file: &Path) {
    let escaped = match route {
        #[cfg(unix)]
        DetachRoute::Setsid => rustix::process::setsid().is_ok(),
        #[cfg(not(unix))]
        DetachRoute::Setsid => false,
        // The middle process placed this one in a group of its own and has
        // already exited. Confirm the group rather than assume it: a process
        // that leads its own group has its own pid as its group id.
        #[cfg(unix)]
        DetachRoute::Daemon => {
            rustix::process::getpgrp().as_raw_nonzero().get()
                == i32::try_from(std::process::id()).unwrap_or(-1)
        }
        #[cfg(not(unix))]
        DetachRoute::Daemon => false,
    };
    let _ = tokio::fs::write(escape_marker(pid_file), if escaped { "ok" } else { "err" }).await;
    publish(pid_file, &std::process::id().to_string()).await;
    tokio::time::sleep(HELPER_LIFETIME).await;
}

/// Run one real [`tunnel_cua_export`] supervisor over [`run_backend`], report
/// the pids it created, and then **park forever**.
///
/// This exists because the supervisor's most dangerous end of life cannot be
/// reached from inside a test process: a `SIGKILL` runs no `Drop`, no
/// `kill_on_drop` and no handler, so to measure it something other than the
/// test has to be the supervisor and the test has to kill it. A test that
/// dropped a handle and asserted the handle was closed would prove nothing
/// about this at all.
pub async fn run_supervise(workspace: &Path) {
    let Ok(executable) = std::env::current_exe() else {
        return;
    };
    let Ok(process) = tunnel_cua_export::BackendProcess::new(
        executable,
        vec![
            BACKEND_MODE.to_owned(),
            workspace.join(ADDRESS_FILE).display().to_string(),
            workspace.join(JOURNAL_FILE).display().to_string(),
            workspace.join(HELPER_PID_FILE).display().to_string(),
        ],
        workspace.to_path_buf(),
        workspace.join(ADDRESS_FILE),
    ) else {
        return;
    };
    let mut supervisor = tunnel_cua_export::Supervisor::new(process);
    if supervisor.start().await.is_err() {
        return;
    }
    let backend = supervisor
        .pid()
        .map_or_else(String::new, |pid| pid.to_string());
    let helper = read_published(&workspace.join(HELPER_PID_FILE)).await;
    let armed = supervisor
        .counters()
        .deadman_armed
        .load(std::sync::atomic::Ordering::Relaxed);
    publish(
        &workspace.join(SUPERVISE_REPORT),
        &format!("{backend} {helper} {armed}"),
    )
    .await;
    // Hold the supervisor so nothing drops it, and wait to be killed.
    std::future::pending::<()>().await;
    drop(supervisor);
}
