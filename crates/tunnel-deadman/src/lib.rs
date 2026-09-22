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
//! # Why the stand-down token, and where the ordering matters
//!
//! **The obvious story about the ordering is wrong, and it is written down
//! here because it took two review rounds to stop repeating it.**  The
//! tempting account is: a group id can be reissued once the group is gone, so
//! stand the sentinel down *after* the kill and the reap, or it might fire at
//! a reissued id.  That does not hold.  A stood-down sentinel **never signals
//! at all** — [`watch`] returns [`EXIT_STOOD_DOWN`] before it reaches
//! `kill_group` — so on the orderly path no stand-down ordering can produce a
//! fire against any id, reissued or not.  The reuse race is orthogonal to
//! this ordering.
//!
//! What the ordering actually guards is a **crash window**.  Standing the
//! sentinel down *before* the supervisor's own group kill leaves an interval
//! in which the child's group is alive and **no longer watched**; a `SIGKILL`
//! of the supervisor inside that interval leaks the group, which is the exact
//! hole this crate exists to close.  So: stand down only after the kill and
//! the reap, because until then the group still needs a watcher.
//!
//! And the reuse race, where it does touch this ordering, argues the **other
//! way**.  If the token never arrives — the write fails, the pipe is already
//! gone — the sentinel sees a bare end of file and *fires*
//! ([`EXIT_FIRED`]).  In the late ordering that firing happens after the
//! group has been reaped, so the id may already be free; an early stand-down
//! would have fired while the group was still alive and therefore still
//! unreusable.  The crash window is the larger and more likely exposure, so
//! the late ordering stays, but it is a trade and not a free win.
//!
//! # The residual reuse race
//!
//! Named rather than implied, and it lives on the `SIGKILL` path rather than
//! in the ordering above: if the supervisor is killed, the orphaned child may
//! exit on its own (it sees its stdin at end of file), be reaped by `init`,
//! and have its group id reissued before the sentinel is scheduled.  The
//! sentinel would then signal a group it does not own.  The window is the
//! sentinel's wakeup latency *and* a full wrap of the host's pid space, so it
//! is vanishingly unlikely, but it is real and is recorded as a task row
//! rather than left to be rediscovered.
//!
//! # Platforms
//!
//! Unix only.  On a non-Unix host [`Deadman::arm`] returns [`None`] and the
//! caller is no worse off than before; Windows wants a job object with
//! `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, which is both the reach fix and the
//! trigger fix at once and is not implemented here.

use std::io::Write as _;
use std::path::{Path, PathBuf};
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
    ///
    /// **A [`None`] on a Unix host is a silent reversion to the behaviour this
    /// crate exists to fix, so it is not silent.**  The sentinel is a separate
    /// executable, so a packaging slip — shipping the device binary without
    /// `tunnel-deadman` beside it — produces a supervisor that runs perfectly
    /// and leaks its children's process group on every crash, which is
    /// indistinguishable from correct operation to anyone watching.  This
    /// warns on stderr, once per process, and [`availability`] lets a
    /// startup or diagnostic path report it before anything is supervised.
    #[must_use]
    pub fn arm(leader: u32) -> Option<Self> {
        if !cfg!(unix) {
            return None;
        }
        let executable = match resolution() {
            Resolution::Usable(path) => path,
            // Named separately because the fix differs and the "install one
            // alongside the device binary" advice is wrong here: there is
            // already a `tunnel-deadman` at that path and it is the problem.
            Resolution::Unusable(path) => {
                warn_sentinel_unusable(&path);
                return None;
            }
            Resolution::Absent => {
                warn_sentinel_missing();
                return None;
            }
        };
        let mut command = Command::new(&executable);
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
        // **A spawn can still fail after resolution said `Usable`**, and this
        // is deliberately not `warn_sentinel_missing()`.  Resolution asks the
        // kernel for execute *permission*; it does not ask whether `execve`
        // will accept the bytes, so an `ENOEXEC` file, a bad interpreter line
        // or a permission that changed between the two calls all land here
        // with a real `tunnel-deadman` sitting at that path.  Telling that
        // operator to install one is the advice M6-C08 added a third status
        // to stop giving.  The path and the OS error are both named, because
        // they are the whole content of the diagnostic.
        let sentinel = match command.spawn() {
            Ok(sentinel) => sentinel,
            Err(error) => {
                warn_sentinel_unspawnable(&executable, &error);
                return None;
            }
        };
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
    /// reaped — not because a sentinel stood down earlier might fire at a
    /// reissued id (a stood-down sentinel does not fire at all), but because
    /// until the kill lands the group still needs a watcher: standing down
    /// first leaves it alive and unwatched, and a `SIGKILL` of this process in
    /// that interval leaks it.  See the module docs for the trade this makes
    /// against the token-failure path.
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

/// Whether a sentinel could be armed on this host at all.
///
/// Call it from a startup or diagnostic path: it answers the question
/// "**will** the children of this process be watched?" before any child
/// exists, which is the only moment at which a missing sentinel is cheap to
/// fix.  It reads a path and starts nothing.
///
/// [`Availability::SentinelMissing`] means this build will behave exactly as
/// it did before the sentinel existed: every supervised process group
/// survives a crash of this process.
#[must_use]
pub fn availability() -> Availability {
    if !cfg!(unix) {
        return Availability::UnsupportedPlatform;
    }
    match resolution() {
        Resolution::Usable(_) => Availability::Armable,
        Resolution::Unusable(_) => Availability::SentinelUnusable,
        Resolution::Absent => Availability::SentinelMissing,
    }
}

/// What [`availability`] found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Availability {
    /// A regular file of the sentinel's name is where one is expected, and
    /// the kernel says this process may execute it.
    ///
    /// **This is not an identity check and must not be reported as one.**  It
    /// establishes that the candidate is a regular file `access(EXEC_OK)`
    /// permits; it does not establish that the file *is* `tunnel-deadman`,
    /// and it does not establish that spawning it will succeed — an
    /// executable script of the right name passes, and so does a file whose
    /// contents `execve` will reject with `ENOEXEC`.  A spawn can still fail
    /// after this answer, which is why [`Deadman::arm`] has its own
    /// diagnostic for that case rather than treating it as absence.  See
    /// [`resolve_sentinel`] for why the runtime stops here and where the
    /// stronger check lives.
    Armable,
    /// A Unix host where the resolved location **holds a file** this process
    /// cannot execute as a sentinel: not a regular file, or one the kernel
    /// refuses execute permission on.
    ///
    /// Distinct from [`SentinelMissing`](Self::SentinelMissing) because the
    /// operator's fix differs.  "Missing" means install the sentinel;
    /// "unusable" means something of that name is already there and is not a
    /// usable sentinel, so installing one means replacing it -- and advice to
    /// "install `tunnel-deadman` alongside the device binary" is actively
    /// unhelpful to someone who is looking straight at a `tunnel-deadman`.
    SentinelUnusable,
    /// A Unix host with no sentinel executable beside the running one and no
    /// [`SENTINEL_PATH_ENV`] pointing at one.  Containment silently reverts
    /// to the pre-sentinel behaviour.
    SentinelMissing,
    /// Not a Unix host.  Neither the group kill nor the sentinel exists here.
    UnsupportedPlatform,
}

/// Warn once per process that containment has silently reverted.
///
/// Once, not per child: an export may supervise up to 64 children and a line
/// per child would bury the fact rather than report it.
/// Warn once per process that a file of the sentinel's name is in the way.
///
/// Separate from [`warn_sentinel_missing`] and separately `Once`-guarded: the
/// two conditions need different actions, and a reader who has just been told
/// to install a `tunnel-deadman` that is plainly sitting there learns nothing.
/// The path is named because the whole difficulty is knowing *which* file.
fn warn_sentinel_unusable(path: &Path) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        eprintln!(
            "tunnel-deadman: {} is not a regular executable file, so it cannot be \
             run as a sentinel: supervised child process groups will NOT be cleaned \
             up if this process is killed or crashes. Replace it with the real \
             `{SENTINEL_BIN}` binary (a working one exits 2 when run with no \
             arguments).",
            path.display()
        );
    });
}

/// Warn once per process that a resolved sentinel could not be spawned.
///
/// The third of three, and it exists because resolution answering `Usable` is
/// a statement about permission rather than a promise that `execve` will
/// accept the file.  Folding this into [`warn_sentinel_missing`] would hand
/// the "install one alongside the device binary" advice to an operator whose
/// `tunnel-deadman` is present and permitted, which is the exact mistake
/// M6-C08 added a third status to avoid.
fn warn_sentinel_unspawnable(path: &Path, error: &std::io::Error) {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        eprintln!(
            "tunnel-deadman: {} resolved as a sentinel but could not be started \
             ({error}): supervised child process groups will NOT be cleaned up if \
             this process is killed or crashes. The file is present and executable, \
             so this is not a missing install: check that it is the real \
             `{SENTINEL_BIN}` binary for this architecture (a working one exits 2 \
             when run with no arguments).",
            path.display()
        );
    });
}

fn warn_sentinel_missing() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        eprintln!(
            "tunnel-deadman: no `{SENTINEL_BIN}` executable found beside this binary \
             (and no {SENTINEL_PATH_ENV} set): supervised child process groups will \
             NOT be cleaned up if this process is killed or crashes. Install \
             `{SENTINEL_BIN}` alongside the device binary."
        );
    });
}

/// Locate the sentinel executable: [`SENTINEL_PATH_ENV`] if set, otherwise
/// [`SENTINEL_BIN`] beside the running executable.  A test binary lives in
/// `target/<profile>/deps`, so the parent of `deps` is searched too.
#[must_use]
pub fn sentinel_path() -> Option<PathBuf> {
    match resolution() {
        Resolution::Usable(path) => Some(path),
        // A file that is there and cannot be executed is not a path to arm
        // from.  It is reported through [`availability`] instead, which is
        // the surface that can say *which* of the two it is.
        Resolution::Unusable(_) | Resolution::Absent => None,
    }
}

/// [`resolve_sentinel`] applied to this process's real inputs.
fn resolution() -> Resolution {
    let Ok(executable) = std::env::current_exe() else {
        return Resolution::Absent;
    };
    resolve_sentinel(std::env::var_os(SENTINEL_PATH_ENV).as_deref(), &executable)
}

/// What the search found at the place it was looking.
///
/// Three-valued rather than `Option<PathBuf>` because "nothing is there" and
/// "something is there and it is not a sentinel" are different findings with
/// different fixes, and collapsing them is exactly the defect row M6-C08
/// records -- one direction of it.  The other direction was collapsing
/// "something is there" into "a sentinel is there".
#[derive(Clone, Debug, Eq, PartialEq)]
enum Resolution {
    /// A regular file with an execute bit.  See [`Availability::Armable`] for
    /// what this does and does not establish.
    Usable(PathBuf),
    /// An entry exists at the candidate location and cannot be executed.
    Unusable(PathBuf),
    /// Nothing exists at any candidate location.
    Absent,
}

/// Whether `path` is something this process could execute as the sentinel.
///
/// **Deliberately follows symlinks**, unlike `scripts/client-bundle-
/// sentinel.sh`, which rejects a symlinked sentinel outright.  The two are
/// asking different questions and the divergence is intended: the script is
/// asserting that a *bundle* is self-contained, where a symlink is a bundle
/// that will break when it is moved; this is asking whether a sentinel can be
/// spawned *here, now*, and a symlink to a real sentinel spawns perfectly.
/// # Why `access` and not a mode-bit test
///
/// The obvious spelling is `mode() & 0o111 != 0`, and it answers a **different
/// question than the caller is asking**: "some execute bit is set somewhere",
/// not "this process may execute it".  The gap is reachable, not theoretical
/// — the Fable review measured it. The real sentinel's own bytes, mode
/// `0o010` (group-execute only) and owned by the running user, pass a
/// mode-bit test while `execve` returns `EACCES`. That would report
/// containment present for a sentinel this process cannot run, which is the
/// defect this rule exists to close, one bit narrower.
///
/// `access(EXEC_OK)` asks the kernel the question directly and gets ACLs and
/// mount flags with it. **One limit, stated rather than left to be found:**
/// it resolves against the **real** uid and gid, not the effective ones, so
/// a setuid process could be told it may not execute a file it in fact may.
/// No `tunnel-` binary is setuid, and the failure direction is to
/// under-report rather than over-report, which is the safe one here.
///
/// The regular-file test stays and is not redundant: a **directory** carries
/// execute bits meaning "searchable", and `access(EXEC_OK)` succeeds on one.
#[cfg(unix)]
fn is_executable_regular_file(path: &Path) -> bool {
    std::fs::metadata(path).is_ok_and(|metadata| metadata.is_file())
        && rustix::fs::access(path, rustix::fs::Access::EXEC_OK).is_ok()
}

#[cfg(not(unix))]
fn is_executable_regular_file(path: &Path) -> bool {
    // No execute bit to read.  `availability` answers `UnsupportedPlatform`
    // before reaching here and `arm` returns `None`, so this only keeps the
    // resolution rule compiling and testable off Unix.
    path.is_file()
}

/// Classify one candidate location.
fn classify(path: PathBuf) -> Resolution {
    // `symlink_metadata` answers "is there an entry here at all", which is
    // what separates `Absent` from `Unusable` -- including for a dangling
    // symlink, where `metadata` alone would report the same `NotFound` as an
    // empty directory and lose the distinction.
    if std::fs::symlink_metadata(&path).is_err() {
        return Resolution::Absent;
    }
    if is_executable_regular_file(&path) {
        Resolution::Usable(path)
    } else {
        Resolution::Unusable(path)
    }
}

/// The resolution rule itself, with both inputs passed in.
///
/// Split out from [`sentinel_path`] so it can be tested without mutating the
/// process environment — which, since the 2024 edition, is `unsafe`, and this
/// crate forbids `unsafe`.  Testing it matters because the rule is what
/// decides whether an installation is watched at all, and because an explicit
/// path that names nothing must resolve to [`Resolution::Absent`] rather than
/// be taken on trust.
///
/// # What this check establishes, and the ceiling it stops at (M6-C08)
///
/// The rule used to accept any `is_file()`, so a **zero-byte, mode 0644 file
/// named `tunnel-deadman`** beside the client made `availability` answer
/// `Armable` and `doctor` report `PROCESS_CONTAINMENT_SENTINEL_PRESENT`.
/// That is worse than reporting containment missing: every arming attempt
/// against that file fails, and the one surface built to show the problem
/// announced the opposite.
///
/// The rule now requires a **regular file with an execute bit**.  That is a
/// genuine narrowing -- it rejects the measured decoy and every
/// non-executable or non-regular candidate -- and it is **all** it is.  It
/// **cannot distinguish an executable script named `tunnel-deadman` from the
/// real sentinel**, so `Armable` means "something spawnable of that name is
/// there", never "containment is known to work".
///
/// **Why the runtime stops there rather than probing.**  The stronger check
/// is behavioural: `tunnel-deadman` exits 2 on a wrong argument list, so
/// running it distinguishes it from a file wearing its name.  The runtime
/// does not do that, for two independent reasons:
///
/// * `tunnel-client doctor` documents that it "reads a path and starts
///   nothing" (`crates/tunnel-client/src/doctor.rs`).  A probe here would
///   make the diagnostic surface execute an unknown binary found beside
///   itself, which is a worse property than the one it would be checking.
/// * This runs on the resolution path taken before **every** supervised
///   child, so a probe spends a process launch per arming -- and against an
///   unknown binary, whose behaviour on being run is exactly what is in
///   question.
///
/// So the behavioural probe stays where it is already paid for and where a
/// failure is free to fix: assembly time, in
/// `scripts/client-bundle-sentinel.sh` and `scripts/m6-release-artifact.py`.
/// Those two and this rule are **not** in disagreement; they are answering
/// different questions at different moments, and neither is an identity
/// check.  Bytes are bound by checksum and provenance, not by either.
#[must_use]
fn resolve_sentinel(explicit: Option<&std::ffi::OsStr>, executable: &Path) -> Resolution {
    if let Some(explicit) = explicit {
        // An explicit path is not a search.  It names one file, and if that
        // file is unusable the answer is about *that* file: falling back to
        // the beside-`current_exe` search would let a misconfigured override
        // resolve to something else and report success, hiding the
        // misconfiguration rather than reporting it.
        return classify(PathBuf::from(explicit));
    }
    let Some(directory) = executable.parent() else {
        return Resolution::Absent;
    };
    let mut candidates = vec![directory.join(SENTINEL_BIN)];
    if directory.file_name().is_some_and(|name| name == "deps")
        && let Some(above) = directory.parent()
    {
        candidates.push(above.join(SENTINEL_BIN));
    }
    // The first unusable candidate is remembered rather than returned, so a
    // decoy beside a test binary cannot shadow the real sentinel one
    // directory up -- the old rule returned on the first `is_file()` and
    // would have.  If nothing usable turns up, the remembered candidate is
    // the answer, because "there is a file there and it is not runnable" is
    // a better report than "there is nothing there".
    //
    // **What the old rule's consequence actually was, corrected by the Fable
    // review after a first draft overstated it.**  It is a wrong-candidate
    // bug, not a silent-green one: `process_residue.rs` passes the resolved
    // path to its probe through `SENTINEL_PATH_ENV` and asserts `armed ==
    // "1"` *before* measuring anything, so an unspawnable candidate fails
    // that assertion with the message written for exactly that case.  Loud
    // red, reading as a broken mechanism rather than a missing fixture --
    // itself an M5-C11 shape, and worth fixing -- but nothing would have gone
    // quietly green.  It also needs a hand-placed file: cargo never writes a
    // `tunnel-deadman` into `deps/`.
    let mut rejected: Option<PathBuf> = None;
    for candidate in candidates {
        match classify(candidate) {
            Resolution::Usable(path) => return Resolution::Usable(path),
            Resolution::Unusable(path) => rejected = rejected.or(Some(path)),
            Resolution::Absent => {}
        }
    }
    rejected.map_or(Resolution::Absent, Resolution::Unusable)
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
    fn an_explicit_path_to_a_non_file_resolves_to_no_sentinel() {
        // The state a packaging slip produces: a path is configured and
        // nothing is there. It must resolve to None — reported as missing —
        // rather than be taken on trust, because a supervisor that believes
        // it is watched and is not is the failure this crate exists to make
        // visible. The end-to-end consequence is measured in
        // `tunnel-mcp-fixture`'s
        // `without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group`;
        // this is the resolution rule underneath it.
        let directory = tempfile::tempdir().expect("directory");
        let absent = directory.path().join("not-a-sentinel");
        assert_eq!(
            resolve_sentinel(Some(absent.as_os_str()), Path::new("/usr/bin/device")),
            Resolution::Absent
        );
    }

    /// Write a file that could actually be executed, which since M6-C08 is
    /// what the resolution rule requires.  A helper rather than three copies
    /// so a future test cannot accidentally take the 0644 path the decoy
    /// takes and look like it proved something about a usable sentinel.
    fn write_executable(path: &Path) {
        std::fs::write(path, b"#!/bin/sh\nexit 2\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x");
        }
    }

    #[test]
    fn an_explicit_path_to_a_real_file_is_taken_over_the_search() {
        let directory = tempfile::tempdir().expect("directory");
        let present = directory.path().join("some-sentinel");
        write_executable(&present);
        assert_eq!(
            resolve_sentinel(Some(present.as_os_str()), Path::new("/usr/bin/device")),
            Resolution::Usable(present)
        );
    }

    #[test]
    fn a_test_binary_in_deps_finds_the_sentinel_one_directory_up() {
        // Without this, every measurement in `process_residue.rs` would run
        // against an unarmed supervisor and silently measure nothing.
        let directory = tempfile::tempdir().expect("directory");
        let deps = directory.path().join("deps");
        std::fs::create_dir(&deps).expect("deps");
        let sentinel = directory.path().join(SENTINEL_BIN);
        write_executable(&sentinel);
        assert_eq!(
            resolve_sentinel(None, &deps.join("some_test-abc123")),
            Resolution::Usable(sentinel)
        );
    }

    #[test]
    fn a_binary_with_no_sentinel_beside_it_resolves_to_none() {
        let directory = tempfile::tempdir().expect("directory");
        assert_eq!(
            resolve_sentinel(None, &directory.path().join("device")),
            Resolution::Absent
        );
    }

    // ------------------------------------------------------------- M6-C08

    /// **The measured defect, as a test.**
    ///
    /// A zero-byte, mode 0644 file named `tunnel-deadman` beside the client
    /// made `availability()` answer `Armable` and `doctor` report
    /// `PROCESS_CONTAINMENT_SENTINEL_PRESENT`, while every arming attempt
    /// against it would fail.  The exact artefact from the row is rebuilt
    /// here -- zero bytes, mode 0644 -- rather than a merely-similar one, so
    /// this fails if the rule is relaxed back.
    #[test]
    fn a_zero_byte_decoy_wearing_the_sentinels_name_is_not_a_sentinel() {
        let directory = tempfile::tempdir().expect("directory");
        let decoy = directory.path().join(SENTINEL_BIN);
        std::fs::write(&decoy, b"").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }

        let resolved = resolve_sentinel(None, &directory.path().join("tunnel-client"));
        assert_eq!(
            resolved,
            Resolution::Unusable(decoy),
            "a non-executable file of the sentinel's name must not resolve as usable"
        );
        // The end-to-end consequence, on the value the operator reads: not
        // merely "not Armable" but the state that says which problem it is.
        assert_ne!(resolved, Resolution::Absent);
    }

    /// **The case that separates "some execute bit is set" from "this process
    /// may execute it"**, found by the Fable review against a first draft
    /// that tested `mode() & 0o111 != 0`.
    ///
    /// Mode `0o010` is group-execute only. On a file owned by the running
    /// user, the owner class is consulted and denies, so `execve` returns
    /// `EACCES` — while a mode-bit test sees a set execute bit and reports
    /// the sentinel present. That is the row's own defect one bit narrower:
    /// a surface telling an operator containment is present for a sentinel
    /// this process cannot run.
    ///
    /// Written with the real sentinel's byte pattern rather than a stub,
    /// because the point is that **only the permission differs**.
    #[test]
    #[cfg(unix)]
    fn a_sentinel_this_process_may_not_execute_is_not_a_sentinel() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().expect("directory");
        let denied = directory.path().join(SENTINEL_BIN);
        std::fs::write(&denied, b"#!/bin/sh\nexit 2\n").expect("write");
        std::fs::set_permissions(&denied, std::fs::Permissions::from_mode(0o010)).expect("chmod");

        // The instrument first: if this file were somehow executable, the
        // assertion below would pass for the wrong reason. Running as root
        // would do it, and root ignores permission bits entirely.
        if rustix::fs::access(&denied, rustix::fs::Access::EXEC_OK).is_ok() {
            eprintln!(
                "SKIPPED a_sentinel_this_process_may_not_execute_is_not_a_sentinel: DID \
                 NOT RUN -- this process may execute a mode 0o010 file (running as root?), \
                 so the case it is written for does not exist here"
            );
            return;
        }

        assert_eq!(
            resolve_sentinel(None, &directory.path().join("tunnel-client")),
            Resolution::Unusable(denied),
            "a mode-bit test would accept this: the execute bit IS set, just not for \
             the class this process falls in. The rule must ask whether this process \
             may execute the file, not whether anybody may."
        );
    }

    /// The distinction the new status exists for.
    ///
    /// Asserted as an inequality against the *other* two answers rather than
    /// only as an equality, because a rule that collapsed every candidate to
    /// `Unusable` would satisfy an equality-only test.
    #[test]
    fn a_file_that_is_there_and_unusable_is_reported_apart_from_nothing_being_there() {
        let occupied = tempfile::tempdir().expect("directory");
        let decoy = occupied.path().join(SENTINEL_BIN);
        std::fs::write(&decoy, b"not a sentinel").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&decoy, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
        }
        let empty = tempfile::tempdir().expect("directory");

        let there = resolve_sentinel(None, &occupied.path().join("tunnel-client"));
        let nothing = resolve_sentinel(None, &empty.path().join("tunnel-client"));
        assert_eq!(there, Resolution::Unusable(decoy));
        assert_eq!(nothing, Resolution::Absent);
        assert_ne!(
            there, nothing,
            "a file that is present and unusable must not report as nothing being \
             present: the two need different fixes"
        );
    }

    /// A directory named `tunnel-deadman` is not a sentinel either.
    ///
    /// The old rule got this right by accident -- `is_file()` is false for a
    /// directory -- and the mode check alone would get it wrong, because a
    /// directory carries execute bits meaning "searchable".  So the regular-
    /// file half of the check is load-bearing and is measured on its own.
    #[test]
    fn a_directory_wearing_the_sentinels_name_is_not_a_sentinel() {
        let directory = tempfile::tempdir().expect("directory");
        let masquerade = directory.path().join(SENTINEL_BIN);
        std::fs::create_dir(&masquerade).expect("mkdir");
        assert_eq!(
            resolve_sentinel(None, &directory.path().join("tunnel-client")),
            Resolution::Unusable(masquerade)
        );
    }

    /// An unusable candidate beside the test binary must not shadow the real
    /// sentinel one directory up.
    ///
    /// The old rule returned on the first `is_file()`, so a decoy in `deps`
    /// would have hidden a working sentinel in `target/debug` and turned
    /// every containment measurement into a measurement of nothing.
    #[test]
    fn a_decoy_in_deps_does_not_shadow_the_real_sentinel_above_it() {
        let directory = tempfile::tempdir().expect("directory");
        let deps = directory.path().join("deps");
        std::fs::create_dir(&deps).expect("deps");
        std::fs::write(deps.join(SENTINEL_BIN), b"").expect("decoy");
        let real = directory.path().join(SENTINEL_BIN);
        write_executable(&real);
        assert_eq!(
            resolve_sentinel(None, &deps.join("some_test-abc123")),
            Resolution::Usable(real)
        );
    }

    /// An explicit path is not a search, and an unusable one does not fall
    /// back.
    ///
    /// Falling back would let a misconfigured `TUNNEL_DEADMAN_BIN` resolve to
    /// some other file and report success, hiding the misconfiguration rather
    /// than reporting it -- which is the shape of M6-C08 itself.  The
    /// executable sentinel beside the binary is what a fallback would find,
    /// so its presence is what makes this test able to fail.
    #[test]
    fn an_explicit_unusable_path_does_not_fall_back_to_the_search() {
        let directory = tempfile::tempdir().expect("directory");
        let beside = directory.path().join(SENTINEL_BIN);
        write_executable(&beside);
        let configured = directory.path().join("configured-sentinel");
        std::fs::write(&configured, b"").expect("write");

        assert_eq!(
            resolve_sentinel(
                Some(configured.as_os_str()),
                &directory.path().join("tunnel-client")
            ),
            Resolution::Unusable(configured)
        );
    }

    /// The ceiling, stated as a test so it is not quietly overstated later.
    ///
    /// An executable shell script named `tunnel-deadman` **passes** this
    /// rule.  That is not a defect to fix here -- the runtime cannot tell
    /// without executing the file, and `doctor` promises not to -- it is the
    /// documented limit, and a reader who assumes `Armable` means "the real
    /// sentinel" is wrong.  If someone later makes the runtime probe, this
    /// test fails and the claim in the docs has to be revisited with it.
    #[test]
    fn the_rule_cannot_tell_an_executable_impostor_from_the_real_sentinel() {
        let directory = tempfile::tempdir().expect("directory");
        let impostor = directory.path().join(SENTINEL_BIN);
        std::fs::write(&impostor, b"#!/bin/sh\nexit 0\n").expect("write");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(&impostor, std::fs::Permissions::from_mode(0o755))
                .expect("chmod +x");
        }
        assert_eq!(
            resolve_sentinel(None, &directory.path().join("tunnel-client")),
            Resolution::Usable(impostor),
            "the runtime check is a mode check, not an identity check; if this \
             changed, the docs on `resolve_sentinel` and `doctor`'s \
             `process_containment` must change with it"
        );
    }

    #[test]
    fn a_leader_id_too_large_for_a_pid_signals_nothing_rather_than_guessing() {
        // No panic, no wrapped-around pid, no signal.
        kill_group(u32::MAX);
    }
}
