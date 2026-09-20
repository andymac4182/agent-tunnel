//! Lifecycle of one supervised CUA backend process. **Nothing here knows what
//! `computer.v1` is**, and that is the separation: a module that could both
//! start a process and form an opinion about whether the automation backend
//! works would eventually report the first as the second.
//!
//! It follows `tunnel-mcp-export`'s and `tunnel-acp-export`'s `child.rs`
//! exactly, because the mechanism is the same one and a second spelling of it
//! would be a second thing to keep right:
//!
//! * The executable, arguments, environment and working directory come only
//!   from validated configuration. The environment is cleared before the
//!   explicit and inherited names are set; nothing runs through a shell.
//! * The child is started in **its own process group**, and every end of its
//!   life this process lives to see signals the whole group with `SIGKILL`,
//!   through `rustix`, so a wrapper (`uvx`, a shell script, a Python launcher)
//!   cannot leave the real backend or its helpers running. The group is
//!   signalled while the leader is still unreaped, so the group id cannot have
//!   been reissued.
//! * stdin is a pipe the supervisor holds, so a wrapper that drains stdin sees
//!   end of file when the supervisor goes away. stdout and stderr are drained
//!   so the child cannot block on them, and **only their byte counts are
//!   kept**: a CUA backend's output can quote a window title or a path, and
//!   `AGENTS.md` keeps payloads out of diagnostics.
//! * That group kill only happens on an end of life **this process lives to
//!   see**. A `SIGKILL`, a `process::exit` or a crash runs no `Drop` at all,
//!   so each child is also watched by a [`tunnel_deadman`] sentinel, stood
//!   down only after the child has been killed and reaped.
//!
//! # What the sentinel closes, and what it does not
//!
//! **Read this from `tunnel_deadman`'s module documentation rather than from
//! memory; it cost the MCP branch four review rounds.**
//!
//! The sentinel closes **trigger** and not **reach**. It sends the same group
//! signal the supervisor would have sent, from a different process, so a
//! descendant that called `setsid`, called `setpgid` or double-forked escapes
//! it exactly as it escapes the supervisor. For a CUA backend that residue is
//! a process that can move the mouse and type, so it is stated plainly in
//! `docs/cua.md` and in `docs/tasks.md` M5-C08 rather than left to be inferred
//! from an absence.
//!
//! # The stand-down ordering, and the trade it makes
//!
//! The sentinel is stood down only **after** the child is killed and reaped.
//! The reason is **not** pid reuse: a stood-down sentinel never signals at all
//! — `tunnel_deadman::watch` returns before it reaches `kill_group` — so no
//! ordering of an orderly stand-down can fire against any id, reissued or not.
//! What the late ordering guards is a **crash window**: standing down before
//! the kill leaves the group alive and no longer watched, and a `SIGKILL` of
//! this process inside that interval leaks it.
//!
//! It is a **stated trade, not a free win.** On the token-failure path — the
//! write fails because the pipe is already gone, so the sentinel sees a bare
//! end of file and *fires* — the late ordering is the exposed one, because by
//! then the group has been reaped and its id may already be free. The crash
//! window is the larger exposure, so the late ordering stays, and the residual
//! race is `docs/tasks.md` M3-18 rather than a sentence nobody wrote down.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use tokio::io::AsyncReadExt;
use tokio::process::Command;
use tokio::sync::watch;

use crate::config::BackendProcess;

/// Payload-free counters for one supervised backend.
///
/// Every one of them is a count of something that **happened**, never of
/// something that was asked for. `deadman_stood_down` in particular reads the
/// sentinel's own exit status: a sentinel that fired a group signal on the way
/// out must never be recorded as an orderly shutdown.
#[derive(Debug, Default)]
pub struct ChildCounters {
    /// Backend processes started.
    pub spawned: AtomicU64,
    /// Starts that failed before a process existed.
    pub spawn_failed: AtomicU64,
    /// Backend processes reaped.
    pub exited: AtomicU64,
    /// Ends of life driven by this supervisor rather than by the child.
    pub killed: AtomicU64,
    /// Backend processes currently running.
    pub running: AtomicU64,
    /// Process-group kills sent. One per end of a backend's life.
    pub group_kills: AtomicU64,
    /// Backends for which a parent-death sentinel was armed. **A backend
    /// counted in `spawned` but not here is one whose process group survives
    /// this process being `SIGKILL`ed**, which for CUA means a process that
    /// can still drive a desktop.
    pub deadman_armed: AtomicU64,
    /// Sentinels that **reported** standing down, read from their own exit
    /// status rather than from this supervisor having asked.
    pub deadman_stood_down: AtomicU64,
    /// Bytes drained from the backend's stdout. The bytes themselves are
    /// discarded.
    pub stdout_bytes: AtomicU64,
    /// Bytes drained from the backend's stderr, likewise discarded.
    pub stderr_bytes: AtomicU64,
}

/// A start that produced no process.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnError;

/// The owner's handle on one running backend. **Dropping it kills the
/// backend**, which is the safe direction: an unexpected drop ends the process
/// group rather than leaking it.
#[derive(Debug)]
pub struct BackendChild {
    pid: u32,
    kill: tokio::sync::watch::Sender<bool>,
    exited: watch::Receiver<bool>,
}

impl BackendChild {
    /// The backend's process id, which is also its process group id.
    #[must_use]
    pub const fn pid(&self) -> u32 {
        self.pid
    }

    /// Ask for the backend to be killed. Returns immediately; use
    /// [`BackendChild::wait_exited`] to wait for the reap.
    pub fn kill(&self) {
        let _ = self.kill.send(true);
    }

    /// Resolves once the process has been killed, reaped and its group
    /// signalled, and its sentinel resolved.
    pub async fn wait_exited(&self) {
        let mut exited = self.exited.clone();
        let _ = exited.wait_for(|done| *done).await;
    }

    /// Whether the backend has already ended.
    #[must_use]
    pub fn has_exited(&self) -> bool {
        *self.exited.borrow()
    }
}

impl Drop for BackendChild {
    fn drop(&mut self) {
        let _ = self.kill.send(true);
    }
}

/// Start the configured backend process.
///
/// # Errors
/// [`SpawnError`] when no process could be created.
pub fn spawn(
    backend: &BackendProcess,
    counters: &Arc<ChildCounters>,
) -> Result<BackendChild, SpawnError> {
    let mut command = Command::new(&backend.command);
    command
        .args(&backend.args)
        .env_clear()
        .current_dir(&backend.workspace)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    for name in &backend.inherit_env {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(&backend.env);

    let mut child = command.spawn().map_err(|_| {
        counters.spawn_failed.fetch_add(1, Ordering::Relaxed);
        SpawnError
    })?;
    let (Some(stdin), Some(stdout), Some(stderr)) =
        (child.stdin.take(), child.stdout.take(), child.stderr.take())
    else {
        counters.spawn_failed.fetch_add(1, Ordering::Relaxed);
        return Err(SpawnError);
    };
    let Some(pid) = child.id() else {
        counters.spawn_failed.fetch_add(1, Ordering::Relaxed);
        return Err(SpawnError);
    };
    counters.spawned.fetch_add(1, Ordering::Relaxed);
    counters.running.fetch_add(1, Ordering::Relaxed);

    // Armed before any task can end the child. **A window remains** between
    // the spawn above and this line, in which a crash of this process leaves
    // this group unwatched. It is microseconds wide and cannot be closed
    // without arming a sentinel for a pid that does not yet exist; it is
    // `docs/tasks.md` M8-C29 and is not claimed to be zero.
    let deadman = tunnel_deadman::Deadman::arm(pid);
    if deadman.is_some() {
        counters.deadman_armed.fetch_add(1, Ordering::Relaxed);
    }

    let (kill_tx, mut kill_rx) = watch::channel(false);
    let (exited_tx, exited_rx) = watch::channel(false);

    tokio::spawn(drain(stdout, Arc::clone(counters), Drained::Stdout));
    tokio::spawn(drain(stderr, Arc::clone(counters), Drained::Stderr));

    let supervisor_counters = Arc::clone(counters);
    tokio::spawn(async move {
        // Held so the child's stdin stays open for as long as it is meant to
        // run: a wrapper that drains stdin sees end of file when this is
        // dropped, which is on every path out of this task.
        let stdin = stdin;
        tokio::select! {
            _ = child.wait() => {}
            () = asked_to_kill(&mut kill_rx) => {
                supervisor_counters.killed.fetch_add(1, Ordering::Relaxed);
                // Signal the group while its leader is still unreaped, so the
                // group id cannot have been reissued to another process.
                let _ = kill_group(pid);
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
        drop(stdin);
        // Whatever ended the leader, no member of its group may outlive it.
        if kill_group(pid) {
            supervisor_counters
                .group_kills
                .fetch_add(1, Ordering::Relaxed);
        }
        supervisor_counters.exited.fetch_add(1, Ordering::Relaxed);
        supervisor_counters.running.fetch_sub(1, Ordering::Relaxed);
        // Only now: the leader is reaped and the group is signalled, so the
        // sentinel has nothing left to watch. Standing it down any earlier
        // reopens the trigger hole for the length of the gap -- see the module
        // documentation for why that, and not pid reuse, is the reason.
        if let Some(deadman) = deadman {
            // `stand_down` writes a byte and reaps; it blocks for as long as
            // the sentinel takes to exit, so it does not belong on a runtime
            // worker. The counter follows the sentinel's own exit status.
            if tokio::task::spawn_blocking(move || deadman.stand_down())
                .await
                .unwrap_or(false)
            {
                supervisor_counters
                    .deadman_stood_down
                    .fetch_add(1, Ordering::Relaxed);
            }
        }
        let _ = exited_tx.send(true);
    });

    Ok(BackendChild {
        pid,
        kill: kill_tx,
        exited: exited_rx,
    })
}

/// Resolve once the owner has asked for the backend to be killed.
///
/// A dropped sender resolves it too, and that is the safe direction: the
/// owner's handle is gone, so nothing will ever ask again, and leaving the
/// backend running would leak a process that can drive a desktop.
async fn asked_to_kill(kill: &mut watch::Receiver<bool>) {
    loop {
        if *kill.borrow_and_update() {
            return;
        }
        if kill.changed().await.is_err() {
            return;
        }
    }
}

/// Send `SIGKILL` to the process group led by `leader`. Returns whether a
/// group signal was attempted.
#[cfg(unix)]
fn kill_group(leader: u32) -> bool {
    let Some(pid) = i32::try_from(leader)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    // ESRCH (no surviving member) is expected and ignored.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    true
}

#[cfg(not(unix))]
fn kill_group(_leader: u32) -> bool {
    false
}

/// Which stream a drain is counting.
#[derive(Clone, Copy)]
enum Drained {
    Stdout,
    Stderr,
}

/// Read a child stream to exhaustion, counting bytes and keeping none.
///
/// The backend must not block on a full pipe, and its output must not reach a
/// consumer or a log: a CUA backend writes window titles, file paths and
/// occasionally the text it was asked to type.
async fn drain<S>(mut stream: S, counters: Arc<ChildCounters>, which: Drained)
where
    S: tokio::io::AsyncRead + Unpin,
{
    let mut buffer = [0u8; 4096];
    loop {
        match stream.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                let counter = match which {
                    Drained::Stdout => &counters.stdout_bytes,
                    Drained::Stderr => &counters.stderr_bytes,
                };
                counter.fetch_add(read as u64, Ordering::Relaxed);
            }
        }
    }
}

#[cfg(test)]
mod tests;
