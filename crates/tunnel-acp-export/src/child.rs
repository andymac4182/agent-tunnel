//! Supervision of one ACP stdio child process.
//!
//! Lifted from `tunnel-mcp-export`'s `child.rs`, which is the worked precedent
//! for a supervised stdio child in this repository, and narrowed to ACP:
//!
//! * The executable, arguments, environment and working directory come only
//!   from configuration. The environment is cleared before the explicit and
//!   inherited names are set; nothing runs through a shell.
//! * stdout is protocol-only. Each line is validated by
//!   [`tunnel_acp::message::parse_message`] and the profile's method set, so an
//!   oversized line, a malformed line, a **batch** and an unaccepted method
//!   each end the child **by their own rule**, which the [`ChildEnd`] carries.
//!   The oversize check fires *before* a newline is found, so a 2 MiB line is
//!   never reassembled.
//! * stderr is drained so the child cannot block on it, and only counted.
//!   Nothing of it is retained, forwarded or logged.
//! * The child runs in its own process group and **every end the supervisor
//!   lives to see** signals the whole group with `SIGKILL` through `rustix`,
//!   keeping this crate `forbid(unsafe_code)`. That includes the ends that run
//!   none of this crate's async code: [`ChildHandle::drop`] sends the group
//!   signal *synchronously*, because a runtime torn down by a panic drops its
//!   tasks instead of running them and would otherwise leave the group behind
//!   with only the leader reaped. That was the M8-C07 review's first finding,
//!   and the process-table tests in `tunnel-acp-fixture` — a child that exits
//!   by itself, a supervisor dropped without draining, and a runtime torn down
//!   with the supervisor still live — are what now hold it.
//! * **"Every end the supervisor lives to see" is the exact claim, and one
//!   route is deliberately outside it: the device process dying.** On a
//!   `SIGKILL`, a `process::exit` or a crash, no `Drop` of any kind runs. The
//!   child then sees stdin at end of file and exits on its own, but nobody
//!   signals its group, so a wrapper's grandchild is orphaned. This is not
//!   closable from inside the process: it needs a kernel-side parent-death
//!   facility (Linux has `PR_SET_PDEATHSIG`; macOS has no equivalent) or the
//!   same containment boundary the escaping-descendant hole needs. Recorded on
//!   M8-C07 as a sibling gap rather than left as a gap in this sentence. **A descendant that leaves the group — `setsid`,
//!   `setpgid`, a daemon double fork — is outside this boundary and is not
//!   killed.** That is inherited hole M3-09, and this crate ships a fixture
//!   that demonstrates it rather than a claim that it does not exist. Group
//!   signalling is Unix-only; macOS is the only host this has run on.
//! * No lock is held across child I/O: a writer task owns stdin, a reader task
//!   owns stdout and a supervisor task owns the process.

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use bytes::Bytes;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::process::Command;
use tokio::sync::{mpsc, watch};
use tokio_util::sync::CancellationToken;
use tunnel_acp::is_accepted_method;
use tunnel_acp::message::{AcpMessage, AcpRule, parse_message};

/// Queued lines towards the child's stdin.
pub const STDIN_QUEUE: usize = 32;
/// Queued messages from the child's stdout.
pub const STDOUT_QUEUE: usize = 32;

/// How the child is started. Nothing here can come from a host request:
/// `docs/acp.md` requires that HTTP input cannot install an agent, select an
/// executable, add arguments, inject environment or switch workspaces.
#[derive(Clone, Debug)]
pub struct ChildConfig {
    pub command: PathBuf,
    pub args: Vec<String>,
    pub workspace: PathBuf,
    /// Names copied from this process's environment, if present.
    pub inherit_env: Vec<String>,
    /// Explicit values, applied after the inherited names.
    pub env: BTreeMap<String, String>,
    /// The largest stdout line, in bytes. `docs/acp.md`: 1 MiB, rejected
    /// before unbounded reassembly.
    pub message_limit: u64,
    /// The stderr byte count beyond which the diagnostic sink reports itself
    /// truncated. Draining never stops, so the child can always exit.
    pub stderr_cap: u64,
}

/// Why the child's message stream ended.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ChildEnd {
    /// stdout reached end of file (the child exited or closed it).
    Closed,
    /// A stdout line reached the message limit before a newline did. The line
    /// was never reassembled.
    OversizedLine,
    /// A stdout line was refused by the profile, **by this rule**: a batch is
    /// [`AcpRule::BatchNotSupported`], a broken line is
    /// [`AcpRule::NotStrictJson`], an extension method is
    /// [`AcpRule::MethodNotAccepted`].
    InvalidLine(AcpRule),
    /// stdout failed to read.
    ReadFailed,
}

/// One validated message the child wrote. `Debug` prints no payload.
pub struct ChildMessage {
    pub message: AcpMessage,
}

impl std::fmt::Debug for ChildMessage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ChildMessage")
            .field("bytes", &self.message.compact.len())
            .finish()
    }
}

/// An event from the child's stdout.
#[derive(Debug)]
pub enum ChildEvent {
    Message(Box<ChildMessage>),
    Ended(ChildEnd),
}

/// Payload-free counters. Identifiers, phases and counts only.
#[derive(Debug, Default)]
pub struct ChildCounters {
    pub spawned: AtomicU64,
    pub spawn_failed: AtomicU64,
    pub exited: AtomicU64,
    pub killed: AtomicU64,
    pub invalid_output: AtomicU64,
    pub oversized_output: AtomicU64,
    pub batch_output: AtomicU64,
    pub stderr_bytes: AtomicU64,
    pub stderr_over_cap: AtomicU64,
    pub running: AtomicU64,
    /// Process-group kills sent (each end of a child's life sends one).
    pub group_kills: AtomicU64,
    /// Supervisor background tasks currently alive for this child.
    ///
    /// A task that outlives its child holds an `Arc<ChildHandle>`, which keeps
    /// [`ChildHandle::drop`] — the synchronous cleanup — from ever running.
    /// The M8-C07 review found exactly that, so "every background task ended
    /// with the child" is something a test can now read rather than assume.
    pub background_tasks: AtomicU64,
}

/// A spawn failure. Carries no path and no OS message.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SpawnError;

impl core::fmt::Display for SpawnError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the ACP child process could not be started")
    }
}

impl std::error::Error for SpawnError {}

/// The owner's handle. Dropping it kills the child's process group.
#[derive(Debug)]
pub struct ChildHandle {
    stdin: mpsc::Sender<Bytes>,
    kill: CancellationToken,
    exited: watch::Receiver<bool>,
    pid: Option<u32>,
}

impl ChildHandle {
    /// Queue one compact JSON-RPC message as a line.
    ///
    /// # Errors
    /// `Err` when the child's stdin is gone, or when the bounded queue is
    /// full and the child is not draining it.
    pub async fn send(&self, compact: &[u8]) -> Result<(), SendError> {
        let mut line = Vec::with_capacity(compact.len() + 1);
        line.extend_from_slice(compact);
        line.push(b'\n');
        self.stdin
            .send(Bytes::from(line))
            .await
            .map_err(|_| SendError)
    }

    /// The child's process id, which is also its process-group id.
    #[must_use]
    pub const fn pid(&self) -> Option<u32> {
        self.pid
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

    #[must_use]
    pub fn kill_token(&self) -> CancellationToken {
        self.kill.clone()
    }
}

impl Drop for ChildHandle {
    /// Kill the child's process group **synchronously, here**.
    ///
    /// Cancelling the token is not enough and was the M8-C07 review's first
    /// finding: the task that acts on the token is a tokio task, and when a
    /// runtime is torn down — a panicking `#[tokio::test]`, a process exiting
    /// — that task is dropped rather than run. `kill_on_drop` then reaps the
    /// **leader only**, and the group is left behind. This is one `rustix`
    /// syscall, so it can run in `Drop` on any thread with no runtime at all.
    ///
    /// The signal is sent only while `exited` says the leader has not been
    /// reaped, which **narrows** the window in which `group` could mean some
    /// other group; it does not close it. POSIX keeps a process-group ID from
    /// being reused while any member lives, but that argument assumes the
    /// supervisor task is the only reaper, and it is not: during runtime
    /// teardown tokio's own orphan reaper can reap the `kill_on_drop`ped
    /// leader before this runs, while `exited` is still false. The remaining
    /// race is microseconds wide and needs pid wraparound on top, so it is
    /// theoretical — but it is narrowed, not eliminated, and saying otherwise
    /// would be the kind of claim this chunk is not allowed to make.
    fn drop(&mut self) {
        self.kill.cancel();
        if !*self.exited.borrow() {
            let _ = kill_group(self.pid);
        }
    }
}

/// The child's stdin is gone.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SendError;

impl core::fmt::Display for SendError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("the ACP child's stdin is gone")
    }
}

impl std::error::Error for SendError {}

/// Spawn the configured child.
///
/// # Errors
/// [`SpawnError`] when the process cannot be started.
pub fn spawn(
    config: &ChildConfig,
    counters: &Arc<ChildCounters>,
) -> Result<(ChildHandle, mpsc::Receiver<ChildEvent>), SpawnError> {
    let mut command = Command::new(&config.command);
    command
        .args(&config.args)
        .env_clear()
        .current_dir(&config.workspace)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .kill_on_drop(true);
    #[cfg(unix)]
    command.process_group(0);
    for name in &config.inherit_env {
        if let Some(value) = std::env::var_os(name) {
            command.env(name, value);
        }
    }
    command.envs(&config.env);
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

    let kill = CancellationToken::new();
    let (exited_tx, exited_rx) = watch::channel(false);
    let (stdin_tx, stdin_rx) = mpsc::channel(STDIN_QUEUE);
    let (events_tx, events_rx) = mpsc::channel(STDOUT_QUEUE);

    tokio::spawn(write_stdin(stdin, stdin_rx, kill.clone()));
    tokio::spawn(read_stdout(
        stdout,
        events_tx,
        config.message_limit,
        kill.clone(),
        Arc::clone(counters),
    ));
    tokio::spawn(drain_stderr(
        stderr,
        config.stderr_cap,
        Arc::clone(counters),
    ));
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
        let _ = exited_tx.send(true);
    });

    Ok((
        ChildHandle {
            stdin: stdin_tx,
            kill,
            exited: exited_rx,
            pid: group,
        },
        events_rx,
    ))
}

/// Send `SIGKILL` to the process group led by `leader`. Returns whether a
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
        // Before the append, so an oversized line is refused rather than
        // reassembled.
        if line.len().saturating_add(take) > limit {
            break ChildEnd::OversizedLine;
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
        // The profile's own rules, so a refusal names the rule that refused.
        let message = match parse_message(&line) {
            Ok(message) => message,
            Err(rejection) => break ChildEnd::InvalidLine(rejection.rule),
        };
        if let Some(method) = message.method.as_deref()
            && !is_accepted_method(method)
        {
            break ChildEnd::InvalidLine(AcpRule::MethodNotAccepted);
        }
        line.clear();
        if events
            .send(ChildEvent::Message(Box::new(ChildMessage { message })))
            .await
            .is_err()
        {
            // Nobody listens any more: the owner dropped the child.
            return;
        }
    };
    match end {
        ChildEnd::OversizedLine => {
            counters.oversized_output.fetch_add(1, Ordering::Relaxed);
            counters.invalid_output.fetch_add(1, Ordering::Relaxed);
            kill.cancel();
        }
        ChildEnd::InvalidLine(rule) => {
            if rule == AcpRule::BatchNotSupported {
                counters.batch_output.fetch_add(1, Ordering::Relaxed);
            }
            counters.invalid_output.fetch_add(1, Ordering::Relaxed);
            kill.cancel();
        }
        ChildEnd::Closed | ChildEnd::ReadFailed => {}
    }
    let _ = events.send(ChildEvent::Ended(end)).await;
}

/// Drain stderr so the child can never block on it.
///
/// Reading continues to end of file whatever the cap says: a cap that stopped
/// reading would be a cap that blocks child exit. Nothing read here is
/// retained, forwarded or logged — only the byte count, and whether that count
/// passed the cap.
async fn drain_stderr(
    mut stderr: tokio::process::ChildStderr,
    cap: u64,
    counters: Arc<ChildCounters>,
) {
    let mut buffer = [0u8; 4096];
    let mut total: u64 = 0;
    let mut reported = false;
    loop {
        match stderr.read(&mut buffer).await {
            Ok(0) | Err(_) => return,
            Ok(read) => {
                total = total.saturating_add(read as u64);
                counters
                    .stderr_bytes
                    .fetch_add(read as u64, Ordering::Relaxed);
                if total > cap && !reported {
                    reported = true;
                    counters.stderr_over_cap.fetch_add(1, Ordering::Relaxed);
                }
            }
        }
    }
}
