//! Task row M5-C08: what supervising a CUA backend contains, measured against
//! the process table.
//!
//! # Two holes, and for CUA the second one has teeth
//!
//! `docs/tasks.md` M3-09 and M8-C07 established the split; this file measures
//! it again for the CUA supervisor, because **the residue here is a process
//! that can move the mouse and type on a real desktop**:
//!
//! * **Trigger** — whether anything sends the group signal at all. A
//!   `SIGKILL`, a `process::exit` or a crash of the supervisor runs **no
//!   `Drop`**, so without a sentinel even an ordinary **in-group** child is
//!   orphaned. [`a_sigkilled_supervisor_still_kills_the_backends_group`]
//!   measures that it no longer is, and it has **two controls**, because on
//!   its own it would show only that a helper was gone and not that anything
//!   here removed it.
//! * **Reach** — which processes a signal can touch. **Not closable on
//!   macOS, and a deadman does not close it**: the sentinel sends the same
//!   group signal from a different process, and `killpg`'s delivery set does
//!   not mention the sender.
//!   [`a_setsid_descendant_of_the_backend_escapes_even_with_the_sentinel_armed`]
//!   and its double-fork sibling measure the escape **with the sentinel
//!   armed**, so nothing here can be read as a reach claim.
//!
//! # The controls, named
//!
//! 1. **The fixture genuinely escapes the old mechanism.**
//!    [`without_a_sentinel_a_sigkilled_supervisor_leaks_the_backends_group`]
//!    runs the identical probe with the sentinel deliberately unlocatable —
//!    the state before this chunk — and requires the helper to **survive**.
//! 2. **An in-group helper of the same shape dies.**
//!    [`the_group_kill_reaches_the_backends_in_group_helper`] kills one on the
//!    orderly path, so "containment" is not claimed for something nothing
//!    could ever have contained.
//!
//! Every assertion reads `/bin/ps` for a pid **and its state**, and rejects
//! `Z`: `kill -0` and a bare pid lookup both succeed on an unreaped zombie, so
//! a process something really did kill would otherwise read as a survivor.
//!
//! Every pid this file creates is registered with a [`PidGuard`] **before** the
//! first assertion that could panic, so a failure anywhere leaves nothing
//! behind.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tunnel_cua_export::child::{BackendChild, ChildCounters, spawn};
use tunnel_cua_export::config::BackendProcess;
use tunnel_cua_fixture::process::{
    ADDRESS_FILE, BACKEND_MODE, DETACH_HOST_MODE, DetachRoute, HELPER_PID_FILE, JOURNAL_FILE,
    SUPERVISE_MODE, SUPERVISE_REPORT, escape_marker,
};

/// Long enough that a `SIGKILL` aimed at a live group member has certainly
/// landed.
///
/// Generous in the **safe** direction: a group signal takes effect
/// immediately, so a slower machine makes survival harder to observe, never
/// easier. It can only make a survival claim weaker.
const SETTLE: Duration = Duration::from_millis(500);

// ------------------------------------------------------------------ helpers

fn beside_this_binary(name: &str) -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.join(name)
}

fn fixture_binary() -> PathBuf {
    let binary = beside_this_binary("tunnel-cua-fixture");
    assert!(
        binary.is_file(),
        "the fixture binary must be built; run the workspace test command, not a bare -p run"
    );
    binary
}

/// The two places [`tunnel_deadman::sentinel_path`] looks, read straight off
/// the filesystem.
///
/// Deliberately **not** expressed in terms of that function: this is the
/// independent side of [`the_skip_cannot_hide_a_helper_that_is_on_disk`], and
/// an `assert_eq!` whose two sides are computed by the same code is task row
/// M5-C10 -- both sides move together and the check cannot fail.
fn helper_is_on_disk() -> bool {
    let mut directory = std::env::current_exe().expect("test binary path");
    directory.pop();
    if directory.join(tunnel_deadman::SENTINEL_BIN).is_file() {
        return true;
    }
    // A test binary lives in `target/<profile>/deps`, so the parent is the
    // other candidate -- the same two-place search, spelled out here.
    directory.file_name().is_some_and(|name| name == "deps")
        && directory
            .parent()
            .is_some_and(|above| above.join(tunnel_deadman::SENTINEL_BIN).is_file())
}

/// The sentinel helper's path, or `None` having reported that this test **did
/// not run** and why (task row M5-C11).
///
/// A package-scoped run -- `cargo test -p tunnel-cua -p tunnel-cua-fixture` --
/// builds no binary of `crates/tunnel-deadman`, so the helper these tests
/// `exec` is **absent rather than broken**. Asserting `armed == 1` against an
/// absent helper fails identically whether the fixture is missing or the
/// arming code regressed, so a reader taking a package-scoped baseline before
/// their own change cannot tell a missing fixture from a real regression.
/// `AGENTS.md`'s rule that green is not evidence unless the check could have
/// gone red has an exact converse here: **red is not evidence unless the check
/// actually ran.**
///
/// Deliberately not a `#[cfg]` guard, which M5-C11 records as rejected: a
/// guard makes the coverage vanish silently, which is the same defect one
/// level up. A skip that could hide a helper that *is* present would be that
/// defect again, and is guarded by
/// [`the_skip_cannot_hide_a_helper_that_is_on_disk`].
fn sentinel_or_skip(test: &str) -> Option<PathBuf> {
    match tunnel_deadman::availability() {
        tunnel_deadman::Availability::Armable => Some(
            tunnel_deadman::sentinel_path()
                .expect("availability() reported Armable, so a path resolves"),
        ),
        absent => {
            eprintln!(
                "SKIPPED {test}: DID NOT RUN ({absent:?}) -- no `{bin}` executable \
                 beside this test binary and no {env} set, so no parent-death \
                 sentinel can be armed and this test would measure nothing. This \
                 is a missing fixture, NOT a broken mechanism: build the helper \
                 beside the tests (`cargo build -p tunnel-deadman --bins`) or run \
                 the workspace test command. Task row M5-C11.",
                bin = tunnel_deadman::SENTINEL_BIN,
                env = tunnel_deadman::SENTINEL_PATH_ENV,
            );
            None
        }
    }
}

/// `(pgid, state)` from the process table, or `None` when the pid is gone.
fn process_row(pid: &str) -> Option<(String, String)> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=,stat=", "-p", pid])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&output.stdout);
    let line = text.trim();
    if line.is_empty() {
        return None;
    }
    let mut fields = line.split_whitespace();
    let pgid = fields.next()?.to_owned();
    let state = fields.next().unwrap_or("").to_owned();
    Some((pgid, state))
}

/// Whether a process-table row is a **live** process.
///
/// Absent is gone, and so is `Z`. Written once, so no caller can spell it in a
/// way that quietly accepts a corpse as a survivor.
fn is_live(row: Option<&(String, String)>) -> bool {
    row.is_some_and(|(_, state)| !state.starts_with('Z'))
}

fn alive(pid: &str) -> bool {
    is_live(process_row(pid).as_ref())
}

/// Wait, bounded, for `pid` to stop being live. Returns the last row seen, so
/// a failure reports *what* survived rather than only that something did.
async fn wait_not_alive(pid: &str) -> Option<(String, String)> {
    for _ in 0..600 {
        let row = process_row(pid);
        if !is_live(row.as_ref()) {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    process_row(pid)
}

async fn read_published(path: &Path) -> String {
    for _ in 0..1000 {
        let text = std::fs::read_to_string(path)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !text.is_empty() {
            return text;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    String::new()
}

/// Kills a pid when it goes out of scope, however the test left — including
/// through a panic in an assertion above the cleanup. This file creates
/// processes **designed** to escape process cleanup, so nothing may be killed
/// only on the happy path.
struct PidGuard(Vec<String>);

impl PidGuard {
    fn watch(pid: &str) -> Self {
        Self(vec![pid.to_owned()])
    }

    fn also(&mut self, pid: &str) {
        self.0.push(pid.to_owned());
    }
}

impl Drop for PidGuard {
    fn drop(&mut self) {
        for pid in &self.0 {
            if pid.is_empty() {
                continue;
            }
            let _ = std::process::Command::new("/bin/kill")
                .args(["-9", pid])
                .stderr(Stdio::null())
                .status();
        }
    }
}

// --------------------------------------------------- reach: the escape holds

/// Start one supervised backend that hosts an escaping descendant, and wait
/// until the descendant has published its pid.
///
/// The escaping process is a **descendant** of the supervised backend, never
/// the backend itself: the supervisor signals its own child by pid as well as
/// by group, so a child that detached from its own group would be killed by
/// the direct signal and the group's reach would never be tested.
async fn detaching_backend(
    workspace: &Path,
    route: DetachRoute,
) -> (BackendChild, Arc<ChildCounters>, String) {
    let pid_file = workspace.join(format!("detached-{}.pid", route.as_str()));
    let process = BackendProcess::new(
        fixture_binary(),
        vec![
            DETACH_HOST_MODE.to_owned(),
            route.as_str().to_owned(),
            workspace.join(ADDRESS_FILE).display().to_string(),
            workspace.join(JOURNAL_FILE).display().to_string(),
            pid_file.display().to_string(),
        ],
        workspace.to_path_buf(),
        workspace.join(ADDRESS_FILE),
    )
    .expect("valid");
    let counters = Arc::new(ChildCounters::default());
    let child = spawn(&process, &counters).expect("the backend started");
    let pid = read_published(&pid_file).await;
    (child, counters, pid)
}

/// Shared body of the two reach measurements.
async fn measure_escape(name: &str, child: BackendChild, counters: &ChildCounters, pid: &str) {
    child.kill();
    child.wait_exited().await;
    let group_kills = counters.group_kills.load(Ordering::Relaxed);
    let armed = counters.deadman_armed.load(Ordering::Relaxed);
    tokio::time::sleep(SETTLE).await;
    let row = process_row(pid);
    eprintln!(
        "MEASURED {name}: descendant pid {pid}, group kills {group_kills}, \
         sentinels armed {armed}, process table {SETTLE:?} after the group SIGKILL: {row:?}"
    );

    assert!(group_kills >= 1, "a group signal was actually sent");
    assert_eq!(
        armed, 1,
        "the parent-death sentinel was armed, so this measures the NEW mechanism \
         and not merely the old one -- and the caller's skip already established \
         that the helper resolves, so a zero here is the arming code regressing \
         rather than an absent fixture (M5-C11)"
    );
    let (pgid, state) = row.expect(
        "MEASUREMENT (M5-C08): the escaping descendant was expected to survive. If it did \
         not, process-tree containment on this host changed and the recorded limitation \
         must be re-derived rather than quietly relaxed.",
    );
    assert!(
        !state.starts_with('Z'),
        "it is alive, not an unreaped corpse: state {state}"
    );
    assert_ne!(
        pgid, "0",
        "the process table returned a usable process group id"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_setsid_descendant_of_the_backend_escapes_even_with_the_sentinel_armed() {
    if sentinel_or_skip("a_setsid_descendant_of_the_backend_escapes_even_with_the_sentinel_armed")
        .is_none()
    {
        return;
    }
    let workspace = tempfile::tempdir().expect("workspace");
    let (child, counters, pid) = detaching_backend(workspace.path(), DetachRoute::Setsid).await;
    let _guard = PidGuard::watch(&pid);
    assert!(!pid.is_empty(), "the descendant published a pid");

    // Refuse to conclude anything from a fixture that did not detach: it
    // would be killed by the plain group signal and this would be a
    // measurement of nothing.
    let escaped =
        std::fs::read_to_string(escape_marker(&workspace.path().join("detached-setsid.pid")))
            .unwrap_or_default();
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean anything"
    );
    // It is its own session and group leader, so its group id is its own pid.
    let (pgid, _) = process_row(&pid).expect("it is running before the kill");
    assert_eq!(pgid, pid, "setsid made it the leader of a group of its own");

    measure_escape("setsid escape", child, &counters, &pid).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_forked_descendant_of_the_backend_escapes_even_with_the_sentinel_armed() {
    if sentinel_or_skip(
        "a_double_forked_descendant_of_the_backend_escapes_even_with_the_sentinel_armed",
    )
    .is_none()
    {
        return;
    }
    let workspace = tempfile::tempdir().expect("workspace");
    let (child, counters, pid) = detaching_backend(workspace.path(), DetachRoute::Daemon).await;
    let _guard = PidGuard::watch(&pid);
    assert!(!pid.is_empty(), "the descendant published a pid");

    let escaped =
        std::fs::read_to_string(escape_marker(&workspace.path().join("detached-daemon.pid")))
            .unwrap_or_default();
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean anything"
    );

    measure_escape("double-fork escape", child, &counters, &pid).await;
}

// --------------------------- skip control: the skip cannot hide a helper

/// **The guard on the skip itself (task row M5-C11).**
///
/// [`sentinel_or_skip`] removes an ambiguity by *not running* four tests when
/// the helper is absent. That buys a new hazard, and it is the one the row
/// names: if the skip ever decided "absent" while the helper was in fact
/// present, all four would skip and the coverage would vanish **silently** --
/// which is precisely the failure mode that makes a `#[cfg]` guard the
/// rejected option there. A skip that could never be reached, or that
/// swallowed a genuine arming regression, is the same defect one level up.
///
/// So this compares the skip's own decision against the filesystem, read by
/// [`helper_is_on_disk`], which does not call
/// [`tunnel_deadman::sentinel_path`] -- the two sides are computed
/// independently, so this is not an `assert_eq!` whose halves move together
/// (M5-C10).
///
/// **It is reachable and falsifiable in both modes**, which is what makes it a
/// positive control rather than another unfalsifiable check: in a
/// package-scoped run it asserts `false == false`, in a workspace run
/// `true == true`, and it goes red the moment those disagree. It reports the
/// pair it measured, so a green result also reports that it ran.
#[test]
fn the_skip_cannot_hide_a_helper_that_is_on_disk() {
    if std::env::var_os(tunnel_deadman::SENTINEL_PATH_ENV).is_some() {
        // An explicit path overrides the beside-the-binary search, so the
        // filesystem side below is not the question being answered. Named
        // rather than silent, for the same reason as the skip itself.
        eprintln!(
            "SKIPPED the_skip_cannot_hide_a_helper_that_is_on_disk: DID NOT RUN \
             -- {env} is set, which overrides the beside-the-binary resolution \
             this control compares against. Task row M5-C11.",
            env = tunnel_deadman::SENTINEL_PATH_ENV,
        );
        return;
    }
    let on_disk = helper_is_on_disk();
    let resolved = sentinel_or_skip("the_skip_cannot_hide_a_helper_that_is_on_disk").is_some();
    eprintln!("MEASURED skip control: helper on disk {on_disk}, skip resolved it {resolved}");
    assert_eq!(
        on_disk, resolved,
        "the skip's decision must track whether the helper is actually there. \
         `on disk true, resolved false` means the four sentinel tests are \
         skipping while the helper is present -- the coverage has vanished \
         silently, which is the defect M5-C11 exists to stop. `on disk false, \
         resolved true` means the skip can never be reached and the four tests \
         will fail on an absent fixture as though the mechanism were broken."
    );
}

// ------------------------------- reach control: an in-group helper does die

/// **Control 2**: a descendant of the very same shape that stayed in the group
/// is reached.
///
/// If one that stayed in the group *also* survived, the escapes above would
/// prove nothing about `setsid` and everything about a group kill that never
/// worked. This one differs from them in exactly one respect — it did not
/// leave the group — and it dies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_group_kill_reaches_the_backends_in_group_helper() {
    let workspace = tempfile::tempdir().expect("workspace");
    let helper_pid_file = workspace.path().join(HELPER_PID_FILE);
    let process = BackendProcess::new(
        fixture_binary(),
        vec![
            BACKEND_MODE.to_owned(),
            workspace.path().join(ADDRESS_FILE).display().to_string(),
            workspace.path().join(JOURNAL_FILE).display().to_string(),
            helper_pid_file.display().to_string(),
        ],
        workspace.path().to_path_buf(),
        workspace.path().join(ADDRESS_FILE),
    )
    .expect("valid");
    let counters = Arc::new(ChildCounters::default());
    let child = spawn(&process, &counters).expect("the backend started");
    let backend = child.pid().to_string();
    let helper = read_published(&helper_pid_file).await;
    let mut guard = PidGuard::watch(&helper);
    guard.also(&backend);
    assert!(!helper.is_empty(), "the backend started a helper");
    assert!(alive(&helper), "the helper runs before the kill");
    let (helper_group, _) = process_row(&helper).expect("the helper is in the table");
    assert_eq!(
        helper_group, backend,
        "the helper is in the supervised backend's own process group, so what \
         follows is about the signal being sent and not about its reach"
    );

    child.kill();
    child.wait_exited().await;
    let row = wait_not_alive(&helper).await;
    eprintln!("MEASURED in-group helper: pid {helper}, process table after the kill: {row:?}");
    assert!(
        !is_live(row.as_ref()),
        "an in-group helper IS reached by the group kill, so the escapes measured \
         elsewhere in this file are about leaving the group and not about a group \
         kill that never worked"
    );
}

// ----------------------------------------- trigger: SIGKILL of the supervisor

/// **The half CUA supervision depends on, and the one an orderly shutdown test
/// cannot reach.**
///
/// The supervisor is a **separate process** here because a `SIGKILL` runs no
/// `Drop`, no `kill_on_drop` and no handler: it **cannot be simulated from
/// inside the process that owns the handle**. The test kills it outright and
/// then reads the process table for the helper the dead supervisor was
/// supposed to clean up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sigkilled_supervisor_still_kills_the_backends_group() {
    // This one already refused with a named reason -- it asserted the helper
    // was a file before spawning -- but a refusal is still a red test that
    // never ran. M5-C11: it skips for the same reason as the rest, and the
    // resolved path is what the probe is pointed at.
    let Some(sentinel) = sentinel_or_skip("a_sigkilled_supervisor_still_kills_the_backends_group")
    else {
        return;
    };
    let workspace = tempfile::tempdir().expect("workspace");
    let mut probe = std::process::Command::new(fixture_binary())
        .arg(SUPERVISE_MODE)
        .arg(workspace.path())
        .env(tunnel_deadman::SENTINEL_PATH_ENV, sentinel)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the supervisor probe started");
    let probe_pid = probe.id().to_string();
    let mut guard = PidGuard::watch(&probe_pid);

    let report = read_published(&workspace.path().join(SUPERVISE_REPORT)).await;
    let fields = report.split_whitespace().collect::<Vec<_>>();
    assert_eq!(
        fields.len(),
        3,
        "the probe reported <backend> <helper> <armed>, got {report:?}"
    );
    let (backend, helper, armed) = (fields[0], fields[1], fields[2]);
    guard.also(backend);
    guard.also(helper);
    assert_eq!(
        armed, "1",
        "the probe's supervised backend armed a parent-death sentinel; without one \
         this test would measure the absence of a mechanism rather than its effect"
    );
    assert!(alive(helper), "the helper runs before the supervisor dies");
    let (helper_group, _) = process_row(helper).expect("the helper is in the table");
    assert_eq!(
        helper_group, backend,
        "the helper is in the supervised backend's own process group, so what \
         follows is about the group signal being SENT at all and not about its reach"
    );

    // No Drop, no destructor, no handler runs in the probe from here on.
    assert!(
        std::process::Command::new("/bin/kill")
            .args(["-9", &probe_pid])
            .status()
            .expect("kill ran")
            .success(),
        "the supervisor was SIGKILLed"
    );
    let _ = probe.wait();

    let helper_row = wait_not_alive(helper).await;
    let backend_row = process_row(backend);
    eprintln!(
        "MEASURED SIGKILLed CUA supervisor: probe {probe_pid}, backend {backend}, \
         helper {helper}, backend row {backend_row:?}, helper row {helper_row:?}"
    );
    assert!(
        !is_live(helper_row.as_ref()),
        "MEASUREMENT (M5-C08): the in-group helper of a SIGKILLed supervisor's CUA \
         backend must be gone from the process table, not merely detached from a \
         closed handle. It was still {helper_row:?}"
    );
}

/// **Control 1: the leak this chunk closes, asserted as still present when the
/// mechanism is absent.**
///
/// The green test alone proves only that a helper was gone; it cannot say
/// whether the sentinel was what removed it, or whether the helper would have
/// died anyway on this host. So the same probe runs again with the sentinel
/// executable deliberately unlocatable — the state before a sentinel existed —
/// and the helper is required to **survive**.
///
/// The two tests differ in one respect and reach opposite outcomes, which is
/// what makes the pair evidence rather than a pair of observations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_sentinel_a_sigkilled_supervisor_leaks_the_backends_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut probe = std::process::Command::new(fixture_binary())
        .arg(SUPERVISE_MODE)
        .arg(workspace.path())
        // Not a file, so `Deadman::arm` finds no sentinel and returns None:
        // the supervisor is exactly as unarmed as it was before this chunk.
        .env(
            tunnel_deadman::SENTINEL_PATH_ENV,
            workspace.path().join("no-such-sentinel"),
        )
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the supervisor probe started");
    let probe_pid = probe.id().to_string();
    let mut guard = PidGuard::watch(&probe_pid);

    let report = read_published(&workspace.path().join(SUPERVISE_REPORT)).await;
    let fields = report.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields.len(), 3, "the probe reported three fields");
    let (backend, helper, armed) = (fields[0], fields[1], fields[2]);
    guard.also(backend);
    guard.also(helper);
    assert_eq!(armed, "0", "no sentinel was armed, which is the point");
    assert!(alive(helper), "the helper runs before the supervisor dies");

    assert!(
        std::process::Command::new("/bin/kill")
            .args(["-9", &probe_pid])
            .status()
            .expect("kill ran")
            .success()
    );
    let _ = probe.wait();
    // Generous in the safe direction: a longer wait can only give the helper
    // more chance to die, so a survival seen after it is a stronger claim.
    tokio::time::sleep(SETTLE).await;
    let helper_row = process_row(helper);
    let backend_row = process_row(backend);
    eprintln!(
        "MEASURED unarmed CUA supervisor (the pre-sentinel behaviour): probe \
         {probe_pid}, backend {backend}, helper {helper}, backend row \
         {backend_row:?}, helper row {helper_row:?}"
    );
    assert!(
        is_live(helper_row.as_ref()),
        "MEASUREMENT (M5-C08): without a sentinel the in-group helper of a SIGKILLed \
         supervisor's CUA backend SURVIVES -- that is the leak, and here it is a \
         process that could drive a desktop. If this ever passes by dying, the \
         sibling test proves nothing and both must be re-derived. It was {helper_row:?}"
    );
    let (helper_group, state) = helper_row.expect("it is in the table");
    assert!(!state.starts_with('Z'), "alive, not an unreaped corpse");
    assert_eq!(
        helper_group, backend,
        "and it survives inside the very process group nobody signalled"
    );
}

/// The sentinel must not fire when the supervisor ends its backend in an
/// orderly way.
///
/// The reason is **not** that a firing sentinel might hit a reissued group id.
/// It is that a sentinel which fires on an orderly shutdown is a sentinel
/// whose stand-down path does not work, and the stand-down path is the only
/// thing keeping an ordinary shutdown from carrying a redundant group
/// `SIGKILL` at a group the supervisor has already killed and reaped — the one
/// moment at which the id genuinely may have been freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it() {
    if sentinel_or_skip("an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it")
        .is_none()
    {
        return;
    }
    let workspace = tempfile::tempdir().expect("workspace");
    let helper_pid_file = workspace.path().join(HELPER_PID_FILE);
    let process = BackendProcess::new(
        fixture_binary(),
        vec![
            BACKEND_MODE.to_owned(),
            workspace.path().join(ADDRESS_FILE).display().to_string(),
            workspace.path().join(JOURNAL_FILE).display().to_string(),
            helper_pid_file.display().to_string(),
        ],
        workspace.path().to_path_buf(),
        workspace.path().join(ADDRESS_FILE),
    )
    .expect("valid");
    let counters = Arc::new(ChildCounters::default());
    let child = spawn(&process, &counters).expect("the backend started");
    let helper = read_published(&helper_pid_file).await;
    let mut guard = PidGuard::watch(&helper);
    guard.also(&child.pid().to_string());
    assert_eq!(
        counters.deadman_armed.load(Ordering::Relaxed),
        1,
        // The skip above already established that the helper resolves, so a
        // zero here is the arming code and not a missing fixture (M5-C11).
        "the helper resolved, so the sentinel was armable: a zero here is the \
         arming code regressing, not an absent fixture"
    );

    child.kill();
    child.wait_exited().await;
    assert_eq!(
        counters.deadman_stood_down.load(Ordering::Relaxed),
        1,
        // Deliberately says only what it checks. The counter reads the
        // sentinel's own exit status, so this proves the sentinel stood down
        // rather than fired. It proves nothing about *when* it was asked, and
        // that ordering is named as untested in M5-C08 rather than implied to
        // be covered here.
        "the sentinel exited stood-down rather than fired"
    );
    let row = wait_not_alive(&helper).await;
    assert!(
        !is_live(row.as_ref()),
        "the supervisor's own group kill did the work on the orderly path"
    );
}
