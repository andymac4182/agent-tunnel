//! Supervision of one MCP stdio child process.
//!
//! * The executable, arguments, environment and working directory come only
//!   from validated configuration.  The environment is cleared before the
//!   explicit and inherited names are set; nothing runs through a shell.
//! * stdout is reserved for newline-delimited JSON-RPC.  Each line must be one
//!   strict JSON object of at most the message limit, or the child is killed
//!   and its consumers see an interruption.
//! * stderr is drained so the child cannot block on it, and only its byte
//!   count is kept: it is never forwarded, logged or retained.
//! * The child is started in its own process group, and every end of its
//!   life (kill, crash, normal exit, session end) signals the whole group
//!   with `SIGKILL`, so a wrapper (`npx`, `uvx`, a shell script) cannot leave
//!   the real server or its helpers running.  The group signal goes through
//!   `rustix` (a maintained safe wrapper), keeping this crate
//!   `forbid(unsafe_code)`.  A descendant that leaves the group (`setsid`,
//!   `setpgid`, a daemon double fork) is outside this boundary and is not
//!   killed.  The group is signalled after the leader is reaped; POSIX keeps
//!   a process-group ID from being reused while any member lives, so the
//!   signal reaches only surviving members of this group.
//! * That group kill only happens on an end of life **this process lives to
//!   see**.  A `SIGKILL`, a `process::exit` or a crash of the device runs no
//!   `Drop` at all, so before this it left the whole group orphaned — not
//!   only an escaping descendant, but the ordinary `npx` wrapper's real
//!   server, the case the group kill exists for.  Each child is therefore
//!   also watched by a [`tunnel_deadman`] sentinel: a sibling process holding
//!   the read end of a pipe this process holds the write end of, which
//!   `SIGKILL`s the group when that pipe reaches end of file for any reason.
//!   The sentinel is stood down only after the child has been killed and
//!   reaped.  **It does not widen the group kill's reach**: a descendant that
//!   left the group escapes the sentinel exactly as it escapes the
//!   supervisor, and `docs/tasks.md` M3-09 records which mechanisms would and
//!   would not close that on which platform.
//! * Dropping the [`ChildHandle`] kills the process group; the supervisor
//!   reaps the leader.
//!   No lock is held across child I/O: a writer task owns stdin, a reader
//!   task owns stdout and a supervisor task owns the process.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tunnel_mcp::json::compact_object;

use crate::config::StdioBackend;

/// Queued lines towards the child's stdin.
pub const STDIN_QUEUE: usize = 32;
/// Queued messages from the child's stdout.
pub const STDOUT_QUEUE: usize = 32;

/// One JSON-RPC message the child wrote.  `Debug` prints no payload.
pub struct ChildMessage {
    pub compact: Bytes,
    pub value: Value,
}

impl std::fmt::Debug for ChildMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildMessage")
            .field("bytes", &self.compact.len())
            .finish()
    }
}

/// Why the child's message stream ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildEnd {
    /// stdout reached end of file (the child exited or closed it).
    Closed,
    /// A stdout line was not one strict JSON object.
    InvalidOutput,
    /// A stdout line exceeded the message limit.
    OversizedMessage,
    /// stdout failed to read.
    ReadFailed,
}

/// An event from the child's stdout.
#[derive(Debug)]
pub enum ChildEvent {
    Message(ChildMessage),
    Ended(ChildEnd),
}

/// Payload-free counters shared by every child of one export.
#[derive(Debug, Default)]
pub struct ChildCounters {
    pub spawned: AtomicU64,
    pub spawn_failed: AtomicU64,
    pub exited: AtomicU64,
    pub killed: AtomicU64,
    pub invalid_output: AtomicU64,
    pub stderr_bytes: AtomicU64,
    pub running: AtomicU64,
    /// Process-group kills sent (each end of a child's life sends one).
    pub group_kills: AtomicU64,
    /// Children for which a parent-death sentinel was armed.  A child counted
    /// in `spawned` but not here is one whose group survives this process
    /// being `SIGKILL`ed.
    pub deadman_armed: AtomicU64,
    /// Sentinels that **reported** standing down after their child was killed
    /// and reaped.  Counted from the sentinel's own exit status, not from the
    /// supervisor having asked, so a sentinel that fired on the way out is
    /// not recorded here.
    pub deadman_stood_down: AtomicU64,
}

/// A spawn failure.  Carries no path or OS message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnError;

/// The owner's handle.  Dropping it kills the child.
#[derive(Debug)]
pub struct ChildHandle {
    stdin: mpsc::Sender<Bytes>,
    kill: CancellationToken,
    exited: watch::Receiver<bool>,
}

impl ChildHandle {
    /// Queue one compact JSON-RPC message as a line.  `Err` when the child's
    /// stdin is gone.
    pub async fn send(&self, compact: &[u8]) -> Result<(), ()> {
        let mut line = Vec::with_capacity(compact.len() + 1);
        line.extend_from_slice(compact);
        line.push(b'\n');
        self.stdin.send(Bytes::from(line)).await.map_err(|_| ())
    }

    /// Kill the child now.
    pub fn kill(&self) {
        self.kill.cancel();
    }

    /// Resolves once the process has been reaped.
    pub async fn wait_exited(&self) {
        let mut exited = self.exited.clone();
        let _ = exited.wait_for(|done| *done).await;
    }

    /// A token that kills the child when cancelled.
    #[must_use]
    pub fn kill_token(&self) -> CancellationToken {
        self.kill.clone()
    }
}

impl Drop for ChildHandle {
    fn drop(&mut self) {
        self.kill.cancel();
    }
}

/// Spawn the configured child.
///
/// # Errors
/// [`SpawnError`] when the process cannot be started.
pub fn spawn(
    backend: &StdioBackend,
    message_limit: u64,
    counters: &Arc<ChildCounters>,
) -> Result<(ChildHandle, mpsc::Receiver<ChildEvent>), SpawnError> {
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
    let group = child.id();
    counters.spawned.fetch_add(1, Ordering::Relaxed);
    counters.running.fetch_add(1, Ordering::Relaxed);
    // Armed before any task can end the child.  A window remains, between the
    // spawn above and this line, in which a device crash leaves this group
    // unwatched; it is microseconds and cannot be closed without arming the
    // sentinel before the pid it watches exists, but it is not zero and is not
    // claimed to be.
    let deadman = group.and_then(tunnel_deadman::Deadman::arm);
    if deadman.is_some() {
        counters.deadman_armed.fetch_add(1, Ordering::Relaxed);
    }

    let kill = CancellationToken::new();
    let (exited_tx, exited_rx) = watch::channel(false);
    let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(STDOUT_QUEUE);

    tokio::spawn(write_stdin(stdin, stdin_rx, kill.clone()));
    tokio::spawn(read_stdout(
        stdout,
        events_tx,
        message_limit,
        kill.clone(),
        Arc::clone(counters),
    ));
    tokio::spawn(drain_stderr(stderr, Arc::clone(counters)));
    let supervisor_counters = Arc::clone(counters);
    let supervisor_kill = kill.clone();
    tokio::spawn(async move {
        tokio::select! {
            _ = child.wait() => {}
            () = supervisor_kill.cancelled() => {
                supervisor_counters.killed.fetch_add(1, Ordering::Relaxed);
                // Signal the group while its leader is still unreaped, so the
                // group id cannot have been reissued to another process.
                let _ = kill_group(group);
                let _ = child.start_kill();
                let _ = child.wait().await;
            }
        }
        // Whatever ended the leader, no member of its group may outlive it.
        if kill_group(group) {
            supervisor_counters
                .group_kills
                .fetch_add(1, Ordering::Relaxed);
        }
        supervisor_counters.exited.fetch_add(1, Ordering::Relaxed);
        supervisor_counters.running.fetch_sub(1, Ordering::Relaxed);
        // Only now: the leader is reaped and the group is signalled, so the
        // sentinel has nothing left to watch.  (It *does* briefly outlive the
        // freed group id — that is a trade the deadman module documents, not
        // the reason for this ordering.)
        //
        // **Standing it down any earlier reopens the trigger hole for the
        // length of the gap.**  The sentinel exits on the stand-down token
        // *without signalling anything* — `tunnel_deadman::watch` returns
        // before it reaches `kill_group` — so between an early stand-down and
        // the kill above, the group would be alive and unwatched, and a
        // `SIGKILL` of this process in that interval would leak it.
        //
        // Nothing observable distinguishes the two orderings, which was
        // measured rather than assumed: with the block hoisted above the kill,
        // all six tests in `tunnel-mcp-fixture`'s `process_residue` stay green,
        // `deadman_stood_down` included — in both orderings the group dies from
        // the `kill_group` above and the sentinel exits stood-down.  So
        // `docs/tasks.md` M3-09 names this ordering as held by construction
        // with no test, instead of pretending a test covers it.
        if let Some(deadman) = deadman {
            // `stand_down` writes a byte and reaps; it blocks only for as long
            // as the sentinel takes to exit, but it does block, so it does not
            // belong on a runtime worker.  The counter follows the sentinel's
            // own exit status, never the fact that it was asked: a sentinel
            // that fired anyway must not be recorded as an orderly shutdown.
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

    Ok((
        ChildHandle {
            stdin: stdin_tx,
            kill,
            exited: exited_rx,
        },
        events_rx,
    ))
}

/// Send `SIGKILL` to the process group led by `leader`.  Returns whether a
/// group signal was attempted.
#[cfg(unix)]
fn kill_group(leader: Option<u32>) -> bool {
    let Some(pid) = leader
        .and_then(|pid| i32::try_from(pid).ok())
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    // ESRCH (no surviving member) is expected and ignored.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
    true
}

#[cfg(not(unix))]
fn kill_group(_leader: Option<u32>) -> bool {
    false
}

async fn write_stdin(
    mut stdin: tokio::process::ChildStdin,
    mut lines: mpsc::Receiver<Bytes>,
    kill: CancellationToken,
) {
    loop {
        let line = tokio::select! {
            () = kill.cancelled() => return,
            line = lines.recv() => line,
        };
        let Some(line) = line else { return };
        let written = tokio::select! {
            () = kill.cancelled() => return,
            written = async {
                stdin.write_all(&line).await?;
                stdin.flush().await
            } => written,
        };
        if written.is_err() {
            return;
        }
    }
}

async fn read_stdout(
    stdout: tokio::process::ChildStdout,
    events: mpsc::Sender<ChildEvent>,
    limit: u64,
    kill: CancellationToken,
    counters: Arc<ChildCounters>,
) {
    let limit = usize::try_from(limit).unwrap_or(usize::MAX);
    let mut reader = BufReader::new(stdout);
    let mut line: Vec<u8> = Vec::new();
    let end = loop {
        let buffer = tokio::select! {
            () = kill.cancelled() => break ChildEnd::Closed,
            buffer = reader.fill_buf() => buffer,
        };
        let buffer = match buffer {
            Ok(buffer) => buffer,
            Err(_) => break ChildEnd::ReadFailed,
        };
        if buffer.is_empty() {
            break ChildEnd::Closed;
        }
        let (take, complete) = match buffer.iter().position(|byte| *byte == b'\n') {
            Some(index) => (index, true),
            None => (buffer.len(), false),
        };
        if line.len().saturating_add(take) > limit {
            break ChildEnd::OversizedMessage;
        }
        line.extend_from_slice(&buffer[..take]);
        reader.consume(if complete { take + 1 } else { take });
        if !complete {
            continue;
        }
        if line.last() == Some(&b'\r') {
            line.pop();
        }
        if line.iter().all(u8::is_ascii_whitespace) {
            line.clear();
            continue;
        }
        let Ok(compact) = compact_object(&line) else {
            break ChildEnd::InvalidOutput;
        };
        let Ok(value) = serde_json::from_slice::<Value>(&compact) else {
            break ChildEnd::InvalidOutput;
        };
        line.clear();
        let message = ChildEvent::Message(ChildMessage {
            compact: Bytes::from(compact),
            value,
        });
        if events.send(message).await.is_err() {
            // Nobody listens any more: the owner dropped the child.
            return;
        }
    };
    if matches!(end, ChildEnd::InvalidOutput | ChildEnd::OversizedMessage) {
        counters.invalid_output.fetch_add(1, Ordering::Relaxed);
        kill.cancel();
    }
    let _ = events.send(ChildEvent::Ended(end)).await;
}

async fn drain_stderr(mut stderr: tokio::process::ChildStderr, counters: Arc<ChildCounters>) {
    let mut buffer = [0u8; 4096];
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                counters
                    .stderr_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
            }
        }
    }
}
