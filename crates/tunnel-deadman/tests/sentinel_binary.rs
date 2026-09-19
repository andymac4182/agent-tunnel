//! The sentinel **executable**, driven directly.
//!
//! # Two reasons this file exists, and the second is not obvious
//!
//! 1. It tests the binary rather than the library. `watch` being correct says
//!    nothing about argv parsing, about the exit status actually reaching the
//!    parent, or about the process really signalling a group it was told about
//!    on the command line. Every one of those sits between
//!    `Deadman::stand_down`'s return value and the truth.
//!
//! 2. **It is what makes `cargo test --workspace` link
//!    `target/<profile>/tunnel-deadman` at all.** `cargo test` builds a
//!    package's `[[bin]]` as a *test harness* when it has unit tests, but it
//!    only links the plain executable when the package has **integration
//!    tests** — because those may reference `CARGO_BIN_EXE_<name>`. Before
//!    this file existed, a from-scratch `cargo test --workspace` left no
//!    sentinel executable on disk, and `tunnel-mcp-fixture`'s process-residue
//!    measurements ran against a supervisor that could not arm one. They
//!    failed loudly rather than measuring nothing, which is the only reason
//!    this was caught; see `docs/tasks.md` M3-19. **Do not delete this file to
//!    tidy up: deleting it silently unbuilds the sentinel for the whole
//!    workspace test command.**
//!
//! The stand-down test below is also the executable statement of the premise
//! this chunk got wrong twice: a stood-down sentinel does not fire at all, so
//! no ordering of the stand-down can produce a group signal.

#![cfg(unix)]

use std::io::Write as _;
use std::process::{Command, Stdio};
use std::time::Duration;

use tunnel_deadman::{EXIT_FIRED, EXIT_STOOD_DOWN, STAND_DOWN};

/// Kills a pid when it goes out of scope, however the test left.
struct PidGuard(String);

impl Drop for PidGuard {
    fn drop(&mut self) {
        let _ = Command::new("/bin/kill")
            .args(["-9", &self.0])
            .stderr(Stdio::null())
            .status();
    }
}

/// `stat` from the process table, or `None` when the pid is gone.  A zombie
/// is not a survivor, so the state is carried rather than a bare pid lookup.
fn state(pid: &str) -> Option<String> {
    let output = Command::new("/bin/ps")
        .args(["-o", "stat=", "-p", pid])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.trim();
    (!line.is_empty()).then(|| line.to_owned())
}

fn alive(pid: &str) -> bool {
    state(pid).is_some_and(|state| !state.starts_with('Z'))
}

/// A process in a group of its own, so its pid is its group id and a group
/// signal aimed at that id reaches exactly it.
fn victim() -> (std::process::Child, String) {
    let mut command = Command::new("/bin/sleep");
    command
        .arg("300")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    {
        use std::os::unix::process::CommandExt as _;
        command.process_group(0);
    }
    let child = command.spawn().expect("the victim started");
    let pid = child.id().to_string();
    (child, pid)
}

fn sentinel(group: &str) -> std::process::Child {
    Command::new(env!("CARGO_BIN_EXE_tunnel-deadman"))
        .arg(group)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the sentinel started")
}

#[test]
fn a_bare_end_of_file_makes_the_sentinel_kill_the_group_it_was_given() {
    let (mut child, pid) = victim();
    let _guard = PidGuard(pid.clone());
    let mut watcher = sentinel(&pid);
    assert!(alive(&pid), "the victim runs before the pipe closes");

    // Closing the write end with nothing written is a parent death.
    drop(watcher.stdin.take());
    let status = watcher.wait().expect("the sentinel exited");
    assert_eq!(
        status.code(),
        Some(EXIT_FIRED),
        "the sentinel reported that it fired"
    );

    // The process table, not the exit status: the sentinel's own report of
    // what it did is not evidence that the group actually died.
    for _ in 0..500 {
        if !alive(&pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.wait();
    assert!(
        !alive(&pid),
        "the group is gone from the process table, state {:?}",
        state(&pid)
    );
}

#[test]
fn a_stood_down_sentinel_does_not_signal_the_group_at_all() {
    // **The premise this chunk recorded wrongly twice, as a test.** The
    // tempting story is that a stand-down must come after the group kill or
    // the sentinel might fire at a reissued id. It cannot fire at anything:
    // it returns before it reaches `kill_group`. That is asserted here
    // against the process table, so the prose in `lib.rs` and in M3-09 is
    // checkable rather than merely careful.
    let (mut child, pid) = victim();
    let _guard = PidGuard(pid.clone());
    let mut watcher = sentinel(&pid);
    assert!(alive(&pid));

    let mut pipe = watcher.stdin.take().expect("the sentinel has a stdin");
    pipe.write_all(STAND_DOWN).expect("the token was written");
    pipe.flush().expect("flushed");
    drop(pipe);

    let status = watcher.wait().expect("the sentinel exited");
    assert_eq!(
        status.code(),
        Some(EXIT_STOOD_DOWN),
        "the sentinel reported that it stood down"
    );
    // Generous in the safe direction: a longer wait gives a signal that was
    // sent more time to land, so survival observed after it is a stronger
    // claim, not a weaker one.
    std::thread::sleep(Duration::from_millis(500));
    assert!(
        alive(&pid),
        "the group was NEVER signalled: a stood-down sentinel does not fire. \
         State {:?}",
        state(&pid)
    );
    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn a_partial_token_is_a_death_rather_than_a_stand_down() {
    // A supervisor that died mid-write leaves a truncated token. Failing open
    // there would leak exactly the group the sentinel exists to kill, so the
    // comparison is on the exact bytes and anything else fires.
    let (mut child, pid) = victim();
    let _guard = PidGuard(pid.clone());
    let mut watcher = sentinel(&pid);

    let mut pipe = watcher.stdin.take().expect("the sentinel has a stdin");
    pipe.write_all(&STAND_DOWN[..STAND_DOWN.len() - 1])
        .expect("a truncated token was written");
    pipe.flush().expect("flushed");
    drop(pipe);

    let status = watcher.wait().expect("the sentinel exited");
    assert_eq!(status.code(), Some(EXIT_FIRED), "a partial token fires");
    for _ in 0..500 {
        if !alive(&pid) {
            break;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    let _ = child.wait();
    assert!(!alive(&pid), "and the group really died");
}

#[test]
fn argv_that_is_not_one_process_group_id_is_refused() {
    for arguments in [vec![], vec!["not-a-pid"], vec!["123", "456"]] {
        let status = Command::new(env!("CARGO_BIN_EXE_tunnel-deadman"))
            .args(&arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("the sentinel ran");
        assert_eq!(
            status.code(),
            Some(2),
            "refused rather than watching something it guessed: {arguments:?}"
        );
    }
}
