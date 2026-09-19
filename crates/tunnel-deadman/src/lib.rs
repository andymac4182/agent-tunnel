#![forbid(unsafe_code)]
//! A parent-death sentinel for a supervised process group.
//!
//! # What this closes, and what it does not
//!
//! A supervisor that kills its child's process group on every end of life
//! still leaves two holes, and they are **different holes with different
//! fixes**.  Conflating them is the mistake this crate exists to stop:
//!
//! * **Reach.**  A descendant that calls `setsid`, calls `setpgid` or
//!   daemonizes with a double fork is no longer in the child's process group,
//!   so no group signal reaches it however it is sent.  **This crate does not
//!   fix that** and must never be described as if it did: the sentinel sends
//!   the same group signal the supervisor would have sent, from a different
//!   process, so it inherits exactly the same reach.  Closing the reach hole
//!   needs a kernel containment boundary — cgroup v2 on Linux, a job object
//!   on Windows, a sandbox, container or VM elsewhere.  macOS has no
//!   in-process equivalent.  See `docs/tasks.md` rows M3-09 and M8-C07.
//! * **Trigger.**  If the supervising process itself dies by `SIGKILL`, by
//!   `process::exit` or by a crash, **no `Drop` of any kind runs**: no
//!   destructor, no `kill_on_drop`, no signal handler.  Nobody signals the
//!   group at all, so even a descendant that stayed *inside* the group — the
//!   `npx`/`uvx`/`/bin/sh` wrapper's real server, the case the group kill was
//!   built for — is orphaned and survives.  **This crate closes that hole**,
//!   and it is the only one of the two that is closable from inside the
//!   process on every Unix.
//!
//! # The mechanism
//!
//! Containment inverts.  Because the supervisor cannot be relied upon to
//! reach the end of its own life, the decision to kill is moved out of it:
//!
//! 1. The supervisor spawns a **sentinel**, a sibling process in a process
//!    group of its own, whose stdin is the read end of a pipe.
//! 2. The supervisor holds the only write end.  Rust's `Command` marks the
//!    pipes it creates close-on-exec, so no other child inherits a copy and
//!    the pipe is held open by exactly one process.
//! 3. The sentinel blocks reading stdin.  When the supervisor dies for **any**
//!    reason the kernel closes every descriptor it held, the pipe reaches end
//!    of file, and the sentinel wakes.
//! 4. On a **bare** end of file the sentinel signals the supervised process
//!    group with `SIGKILL`.  On an end of file preceded by [`STAND_DOWN`] it
//!    exits without signalling.
//!
//! `SIGKILL` cannot be caught, blocked or handled, which is precisely why the
//! signal must be delivered by a process other than the one being killed.
//!
//! # Why the stand-down token, and the one race it leaves
//!
//! A process-group ID is not reused while any member of the group is alive,
//! so a sentinel that fires while the group still exists cannot hit an
//! unrelated group.  Once the last member has been reaped the id is free
//! again.  The supervisor therefore calls [`Deadman::stand_down`] **after** it
//! has killed and reaped its own child, so the ordinary path never leaves a
//! sentinel that could fire against a reissued id.
//!
//! The residual race is named rather than implied: if the supervisor is
//! `SIGKILL`ed, the orphaned child may exit on its own (it sees its stdin at
//! end of file), be reaped by `init`, and have its group id reissued before
//! the sentinel is scheduled.  The sentinel would then signal a group it does
//! not own.  The window is the sentinel's wakeup latency *and* a full wrap of
//! the host's pid space, so it is vanishingly unlikely, but it is real and is
//! recorded as a task row rather than left to be rediscovered.
//!
//! # Platforms
//!
//! Unix only.  On a non-Unix host [`Deadman::arm`] returns [`None`] and the
//! caller is no worse off than before; Windows wants a job object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, which is both the reach fix and the
//! trigger fix at once and is not implemented here.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};

/// The byte string the supervisor writes before closing the pipe when it is
/// ending the child in an orderly way and has already killed the group
/// itself.  Any other content, or none at all, is a parent death.
pub const STAND_DOWN: &[u8] = b"stand-down\n";

/// The sentinel executable's file name.
pub const SENTINEL_BIN: &str = "tunnel-deadman";

/// An environment variable naming the sentinel executable explicitly.  It
/// overrides the search next to the running executable, which is what a test
/// binary in `target/debug/deps` needs.
pub const SENTINEL_PATH_ENV: &str = "TUNNEL_DEADMAN_BIN";

/// The sentinel's exit status when it signalled the group.
pub const EXIT_FIRED: i32 = 10;
/// The sentinel's exit status when it was stood down.
pub const EXIT_STOOD_DOWN: i32 = 0;

/// An armed sentinel watching one process group.
///
/// Dropping this without [`stand_down`](Self::stand_down) closes the pipe and
/// lets the sentinel fire, which is the safe direction: an unexpected drop
/// kills the group rather than leaking it.
#[derive(Debug)]
pub struct Deadman {
    sentinel: Child,
}

impl Deadman {
    /// Spawn a sentinel that `SIGKILL`s the process group led by `leader` when
    /// this process's write end of its stdin closes.
    ///
    /// Returns [`None`] when the host is not Unix, when the sentinel
    /// executable cannot be located, or when it cannot be spawned.  A caller
    /// that gets [`None`] keeps whatever containment it already had; the
    /// sentinel only ever adds.
    #[must_use]
    pub fn arm(leader: u32) -> Option<Self> {
        if !cfg!(unix) {
            return None;
        }
        let executable = sentinel_path()?;
        let mut command = Command::new(executable);
        command
            .arg(leader.to_string())
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        // Its own group, so a signal aimed at the supervisor's group — or at
        // the group it is itself watching — does not take the watcher with it.
        #[cfg(unix)]
        {
            use std::os::unix::process::CommandExt as _;
            command.process_group(0);
        }
        let sentinel = command.spawn().ok()?;
        Some(Self { sentinel })
    }

    /// The sentinel's own process id, for tests that must prove it is gone.
    #[must_use]
    pub fn sentinel_pid(&self) -> u32 {
        self.sentinel.id()
    }

    /// Tell the sentinel not to fire, then wait for it to exit.
    ///
    /// Call this **only after** the supervised child has been killed and
    /// reaped, so that the sentinel can never outlive the group id it was
    /// given.
    ///
    /// Returns whether the sentinel really did stand down, read from its exit
    /// status ([`EXIT_STOOD_DOWN`] rather than [`EXIT_FIRED`]).  **The return
    /// value is the only honest witness there is**: a caller that merely
    /// called this function knows it asked, not that the sentinel agreed, and
    /// a counter incremented on the call rather than on the answer would
    /// report an orderly shutdown for a sentinel that fired a group signal on
    /// the way out.
    #[must_use]
    pub fn stand_down(mut self) -> bool {
        if let Some(pipe) = self.sentinel.stdin.as_mut() {
            let _ = pipe.write_all(STAND_DOWN);
            let _ = pipe.flush();
        }
        // Closing the write end is what the sentinel is blocked on.
        drop(self.sentinel.stdin.take());
        self.sentinel
            .wait()
            .ok()
            .and_then(|status| status.code())
            .is_some_and(|code| code == EXIT_STOOD_DOWN)
    }
}

impl Drop for Deadman {
    fn drop(&mut self) {
        // The pipe closes with the handle, so the sentinel fires.  Reap it so
        // a long-lived supervisor does not accumulate zombies; the sentinel
        // exits immediately after signalling, so this does not block.
        drop(self.sentinel.stdin.take());
        let _ = self.sentinel.wait();
    }
}

/// Locate the sentinel executable: [`SENTINEL_PATH_ENV`] if set, otherwise
/// [`SENTINEL_BIN`] beside the running executable.  A test binary lives in
/// `target/<profile>/deps`, so the parent of `deps` is searched too.
#[must_use]
pub fn sentinel_path() -> Option<PathBuf> {
    if let Some(explicit) = std::env::var_os(SENTINEL_PATH_ENV) {
        let path = PathBuf::from(explicit);
        return path.is_file().then_some(path);
    }
    let executable = std::env::current_exe().ok()?;
    let directory = executable.parent()?;
    let beside = directory.join(SENTINEL_BIN);
    if beside.is_file() {
        return Some(beside);
    }
    if directory.file_name().is_some_and(|name| name == "deps") {
        let above = directory.parent()?.join(SENTINEL_BIN);
        if above.is_file() {
            return Some(above);
        }
    }
    None
}

/// The sentinel's body: read `stdin` to end of file, then decide.
///
/// Returns the process exit status: [`EXIT_STOOD_DOWN`] when the supervisor
/// asked it to stand down, [`EXIT_FIRED`] when it signalled the group.
#[must_use]
pub fn watch(leader: u32) -> i32 {
    use std::io::Read as _;
    let mut received = Vec::new();
    // A short read is not an end of file, so read to exhaustion.  An error is
    // treated as a death: failing closed kills the group, failing open leaks
    // it.
    let _ = std::io::stdin().read_to_end(&mut received);
    if received == STAND_DOWN {
        return EXIT_STOOD_DOWN;
    }
    kill_group(leader);
    EXIT_FIRED
}

#[cfg(unix)]
fn kill_group(leader: u32) {
    let Some(pid) = i32::try_from(leader)
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return;
    };
    // ESRCH (no surviving member) is expected and ignored.
    let _ = rustix::process::kill_process_group(pid, rustix::process::Signal::KILL);
}

#[cfg(not(unix))]
fn kill_group(_leader: u32) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_exact_stand_down_token_is_the_only_thing_that_stands_a_sentinel_down() {
        // The decision is on the exact bytes, not on a prefix or a substring:
        // a truncated write from a supervisor that died mid-write must read
        // as a death, not as an orderly shutdown.
        assert_eq!(STAND_DOWN, b"stand-down\n");
        assert_ne!(STAND_DOWN, b"stand-down".as_slice());
    }

    #[test]
    fn a_leader_id_too_large_for_a_pid_signals_nothing_rather_than_guessing() {
        // No panic, no wrapped-around pid, no signal.
        kill_group(u32::MAX);
    }
}
