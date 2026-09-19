//! Task row M8-C07's **trigger** half: whether anything signals the ACP
//! child's process group when the supervising process dies without running a
//! single `Drop`.
//!
//! # Two holes, and why they must not be reported as one
//!
//! M3-09 established the split and this file inherits it rather than
//! rediscovering it. Process-group containment has two independent halves:
//!
//! * **Reach** — which processes a group signal can touch. A descendant that
//!   calls `setsid`, calls `setpgid` or double-forks is no longer in the
//!   child's process group, so no group signal reaches it however it is sent.
//!   [`a_setsid_descendant_escapes_even_with_the_sentinel_armed`] measures that
//!   it escapes **with the sentinel armed**, because a sentinel sends the same
//!   group signal from a different process and `killpg`'s delivery set does not
//!   mention the sender. A test that omitted the armed case would be evidence
//!   proving less than this file claims.
//! * **Trigger** — whether anything sends the signal at all. A `SIGKILL`, a
//!   `process::exit` or a crash of the supervising process runs **no `Drop` of
//!   any kind**, so before this chunk nobody signalled the group and even an
//!   ordinary **in-group** helper survived.
//!   [`a_sigkilled_supervisor_still_kills_the_group`] measures that it no
//!   longer does.
//!
//! # Why the trigger test has two controls
//!
//! On its own, a green [`a_sigkilled_supervisor_still_kills_the_group`] shows
//! only that a helper was gone. It cannot say whether the sentinel removed it
//! or whether a helper of that shape would have died anyway on this host. So:
//!
//! * [`without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group`] runs
//!   the identical probe with the sentinel executable deliberately
//!   unlocatable — the state of `origin/main` before this chunk — and
//!   **requires the helper to survive**. The two differ in exactly one respect
//!   and reach opposite outcomes, which is what makes the pair evidence rather
//!   than a pair of observations.
//! * [`the_group_kill_reaches_an_in_group_helper`] shows that a helper of this
//!   shape is the sort of thing a group signal reaches at all, so "containment"
//!   is not being claimed for a probe nothing could ever have contained.
//!
//! # How the assertions are made
//!
//! Every one of them reads `/bin/ps` for a **pid**, never a handle: a test that
//! kills a process and asserts a handle closed proves nothing about that
//! process's descendants. Every one of them also checks the process **state**,
//! because `kill -0` and a bare pid lookup both succeed on an unreaped zombie —
//! a descendant that something really did kill but that nobody had reaped yet
//! would otherwise read as a survivor and keep a survival assertion green for
//! entirely the wrong reason.
//!
//! Every pid this file creates is registered with a [`PidGuard`] **before** the
//! first assertion that could panic, so a failure anywhere leaves nothing
//! behind. This file deliberately creates processes designed to escape process
//! cleanup; nothing here may be killed only on the happy path.
//!
//! # Not covered, named rather than implied
//!
//! * **Reach is not closed and this chunk does not close it.** Closing it needs
//!   a kernel containment boundary: `cgroup v2` on Linux, a job object on
//!   Windows, a sandbox/container/VM elsewhere. **macOS has neither**, and
//!   macOS is the only host any of this has run on, so there the answer is a
//!   documented operator constraint rather than a mechanism.
//! * **Linux and Windows are not exercised at all.** Process groups and
//!   `SIGKILL` are Unix-only (this file is `#![cfg(unix)]`), and no run of any
//!   test here has happened on anything but macOS.
//! * **The stand-down *ordering* is not tested**, only its outcome. M3-09
//!   records it as held by construction, and `docs/tasks.md` M3-18 carries the
//!   pid-reuse race the ordering trades against.
//! * **The arming window is not tested.** Between `Command::spawn` returning
//!   and `Deadman::arm` running, a crash of the supervisor leaves the group
//!   unwatched. It is microseconds and cannot be closed without arming a
//!   sentinel for a pid that does not yet exist, but it is not zero.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tunnel_acp_export::child::{ChildConfig, ChildCounters, spawn};
use tunnel_acp_fixture::{
    HELPER_PID_FILE, SUPERVISE_MODE, SUPERVISE_REPORT, WRAPPER_MODE, WRAPPER_PID_FILE, marker_file,
};

/// Long enough that a `SIGKILL` aimed at a live group member has certainly
/// landed.
///
/// The bound is generous in the **safe** direction: a group signal takes effect
/// immediately, so a slower machine makes a survival harder to observe, never
/// easier. It can only make a survival claim weaker, never stronger.
const SETTLE: Duration = Duration::from_millis(500);

// ------------------------------------------------------------------ helpers

/// The fixture executable. `CARGO_BIN_EXE_*` is set for the integration tests
/// of the crate that defines the binary, which is why these tests live here
/// rather than in `tunnel-acp-export`.
fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-acp-fixture"))
}

/// The sentinel executable, built beside this test binary.
///
/// **This assertion is load-bearing (task row M3-19).** `cargo test -p
/// tunnel-acp-fixture` builds no binary belonging to another package, so
/// `tunnel-deadman` is whatever happened to be left in the target directory.
/// Without this check a run against a missing — or stale — sentinel would arm
/// nothing and measure nothing, while staying green.
fn sentinel_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    let binary = path.join(tunnel_deadman::SENTINEL_BIN);
    assert!(
        binary.is_file(),
        "the sentinel binary must be built; run the workspace test command, not a bare -p run"
    );
    binary
}

/// `(pgid, state)` from the process table, or `None` when the pid is gone.
///
/// The state is carried because a pid lookup alone cannot tell a survivor from
/// an unreaped corpse.
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
/// way that quietly accepts a zombie as a survivor.
fn is_live(row: Option<&(String, String)>) -> bool {
    row.is_some_and(|(_, state)| !state.starts_with('Z'))
}

fn alive(pid: &str) -> bool {
    is_live(process_row(pid).as_ref())
}

/// Wait, bounded, for `pid` to stop being a live process. Returns the last row
/// seen, so a failure reports *what* survived rather than only that something
/// did.
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

async fn read_pid(path: &Path) -> String {
    for _ in 0..1000 {
        let pid = std::fs::read_to_string(path)
            .unwrap_or_default()
            .trim()
            .to_owned();
        if !pid.is_empty() {
            return pid;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    String::new()
}

/// Kills every registered pid when it goes out of scope, however the test left
/// — including through a panic in an assertion above the cleanup.
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

/// A child config that runs the `npx`-shaped wrapper: it starts an in-group
/// helper which never reads stdin, then drains stdin itself.
fn wrapper_config(workspace: &Path) -> ChildConfig {
    ChildConfig {
        command: fixture_binary(),
        args: vec![
            WRAPPER_MODE.to_owned(),
            workspace.join(WRAPPER_PID_FILE).display().to_string(),
            workspace.join(HELPER_PID_FILE).display().to_string(),
        ],
        workspace: workspace.to_path_buf(),
        inherit_env: Vec::new(),
        env: std::collections::BTreeMap::new(),
        message_limit: 1 << 20,
        stderr_cap: 1 << 16,
    }
}

/// Start the `supervise` probe with `sentinel` as its sentinel path, wait for
/// its report, and return `(child, probe pid, wrapper pid, helper pid, armed)`.
fn start_probe(workspace: &Path, sentinel: &Path) -> std::process::Child {
    std::process::Command::new(fixture_binary())
        .arg(SUPERVISE_MODE)
        .arg(workspace)
        // Passed through the environment of a *child process*, never through
        // `std::env::set_var`: since the 2024 edition that is `unsafe`, and
        // every crate in this workspace is `forbid(unsafe_code)`.
        .env(tunnel_deadman::SENTINEL_PATH_ENV, sentinel)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the supervisor probe started")
}

// ------------------------------- trigger: SIGKILL of the supervising process

/// **The case the sentinel exists for, and the one no orderly-shutdown test can
/// reach.**
///
/// The supervisor is a **separate process** here because a `SIGKILL` runs no
/// `Drop`, no `kill_on_drop` and no handler: it cannot be simulated from inside
/// the process that owns the handle. The test kills it outright and then reads
/// the process table for the in-group helper the dead supervisor was supposed
/// to clean up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sigkilled_supervisor_still_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut probe = start_probe(workspace.path(), &sentinel_binary());
    let probe_pid = probe.id().to_string();
    let mut guard = PidGuard::watch(&probe_pid);

    let report = read_pid(&workspace.path().join(SUPERVISE_REPORT)).await;
    let fields = report.split_whitespace().collect::<Vec<_>>();
    assert_eq!(
        fields.len(),
        3,
        "the probe reported <wrapper> <helper> <armed>, got {report:?}"
    );
    let (wrapper, helper, armed) = (fields[0], fields[1], fields[2]);
    guard.also(wrapper);
    guard.also(helper);
    assert_eq!(
        armed, "1",
        "the probe's export child armed a parent-death sentinel; without one this \
         test would measure the absence of a mechanism rather than its effect"
    );
    assert!(alive(helper), "the helper runs before the supervisor dies");
    let (helper_group, _) = process_row(helper).expect("the helper is in the table");
    assert_eq!(
        helper_group, wrapper,
        "the helper is in the supervised child's own process group, so what follows \
         is about the group signal being SENT at all and not about its reach"
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
    let wrapper_row = process_row(wrapper);
    eprintln!(
        "MEASURED (M8-C07) SIGKILLed ACP supervisor: probe {probe_pid}, wrapper \
         {wrapper}, helper {helper}, wrapper row {wrapper_row:?}, helper row \
         {helper_row:?}"
    );
    assert!(
        !is_live(helper_row.as_ref()),
        "MEASUREMENT (M8-C07): the in-group helper of a SIGKILLed ACP supervisor's \
         child must be gone from the process table, not merely detached from a \
         closed handle. It was still {helper_row:?}"
    );
}

/// **The control for the test above: the leak this chunk closes, asserted as
/// still present when the mechanism is absent.**
///
/// The same probe runs again with the sentinel executable deliberately
/// unlocatable — exactly the state of `origin/main`, where the ACP export armed
/// no sentinel at all — and the helper is required to **survive**. Without this,
/// the green test above would be consistent with a host on which such a helper
/// dies anyway, and would prove nothing about the sentinel.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    // Not a file, so `Deadman::arm` finds no sentinel and returns None: the
    // supervisor is exactly as unarmed as it was before this chunk.
    let absent = workspace.path().join("no-such-sentinel");
    let mut probe = start_probe(workspace.path(), &absent);
    let probe_pid = probe.id().to_string();
    let mut guard = PidGuard::watch(&probe_pid);

    let report = read_pid(&workspace.path().join(SUPERVISE_REPORT)).await;
    let fields = report.split_whitespace().collect::<Vec<_>>();
    assert_eq!(fields.len(), 3, "the probe reported three fields");
    let (wrapper, helper, armed) = (fields[0], fields[1], fields[2]);
    guard.also(wrapper);
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
    let wrapper_row = process_row(wrapper);
    eprintln!(
        "MEASURED (M8-C07) unarmed ACP supervisor, the pre-chunk behaviour: probe \
         {probe_pid}, wrapper {wrapper}, helper {helper}, wrapper row \
         {wrapper_row:?}, helper row {helper_row:?}"
    );
    assert!(
        is_live(helper_row.as_ref()),
        "MEASUREMENT (M8-C07): without a sentinel the in-group helper of a SIGKILLed \
         ACP supervisor's child SURVIVES — that is the leak. If this ever passes by \
         dying, the sibling test proves nothing and both must be re-derived. It was \
         {helper_row:?}"
    );
    let (helper_group, state) = helper_row.expect("it is in the table");
    assert!(!state.starts_with('Z'), "alive, not an unreaped corpse");
    assert_eq!(
        helper_group, wrapper,
        "and it survives inside the very process group nobody signalled"
    );
}

// -------------------------- control: an in-group helper is reachable at all

/// **The second control.**
///
/// If a helper of the very same shape could not be killed by a group signal
/// even on the orderly path, then "containment" would be untested and the
/// `SIGKILL` pair above would be measuring something else entirely. This one
/// differs from the escaping descendant in exactly one respect — it never left
/// the group — and it dies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_group_kill_reaches_an_in_group_helper() {
    let _ = sentinel_binary();
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let (handle, _events) =
        spawn(&wrapper_config(workspace.path()), &counters).expect("the child started");
    let helper = read_pid(&workspace.path().join(HELPER_PID_FILE)).await;
    let mut guard = PidGuard::watch(&helper);
    let wrapper = read_pid(&workspace.path().join(WRAPPER_PID_FILE)).await;
    guard.also(&wrapper);
    assert!(!helper.is_empty(), "the wrapper started a helper");
    assert!(alive(&helper), "the helper runs before the kill");

    handle.kill();
    handle.wait_exited().await;
    let row = wait_not_alive(&helper).await;
    eprintln!(
        "MEASURED (M8-C07) in-group helper on the orderly path: pid {helper}, \
         process table after the kill: {row:?}"
    );
    assert!(
        !is_live(row.as_ref()),
        "an in-group helper IS reached by the group kill, so the escape measured \
         elsewhere in this file is about leaving the group and not about a group \
         kill that never worked"
    );
}

// ------------------------------------------------- the orderly stand-down

/// The sentinel must not fire when the supervisor ends its child in an orderly
/// way.
///
/// The reason is **not** that a firing sentinel might hit a reissued group id.
/// It is that a sentinel which fires on an orderly shutdown is a sentinel whose
/// stand-down path does not work — and that path is the only thing keeping an
/// ordinary shutdown from carrying a redundant group `SIGKILL` at a group this
/// supervisor has already killed and reaped, which is the one moment at which
/// the id genuinely may have been freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it() {
    let _ = sentinel_binary();
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let (handle, _events) =
        spawn(&wrapper_config(workspace.path()), &counters).expect("the child started");
    let helper = read_pid(&workspace.path().join(HELPER_PID_FILE)).await;
    let _guard = PidGuard::watch(&helper);
    assert_eq!(
        counters.deadman_armed.load(Ordering::Relaxed),
        1,
        "the child was watched at all"
    );

    handle.kill();
    handle.wait_exited().await;
    assert_eq!(
        counters.deadman_stood_down.load(Ordering::Relaxed),
        1,
        // Deliberately says only what it checks. The counter reads the
        // sentinel's *exit status*, so this proves the sentinel stood down
        // rather than fired. It proves nothing about *when* it was asked, and
        // that ordering is named as untested in this file's "Not covered"
        // list rather than implied to be covered here.
        "the sentinel exited stood-down rather than fired"
    );
    // And the orderly path still cleaned the group up itself.
    let row = wait_not_alive(&helper).await;
    assert!(
        !is_live(row.as_ref()),
        "the supervisor's own group kill did the work on the orderly path"
    );
}

// --------------------------------------------------- reach: still not closed

/// **The escaping descendant still escapes, with the sentinel armed.**
///
/// M3-09's finding, re-measured on the ACP path rather than assumed to carry
/// across. The sentinel sends the *same* group signal from a different process,
/// so it was never going to widen the reach — but a chunk that armed a sentinel
/// and did not check would be one review round away from claiming it had.
///
/// It asserts the **mechanism**, not only the outcome: the descendant must be
/// in a different process group from the child and in a state that is not `Z`,
/// so what is proven is that it survived *because* it left the group, and not
/// that a corpse nobody reaped was mistaken for a survivor.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_setsid_descendant_escapes_even_with_the_sentinel_armed() {
    use tunnel_acp_export::{ConnectionScope, Supervisor, SupervisorConfig};

    // Resolved by the search beside this test binary, because `Deadman::arm`
    // runs *in this process* here and the environment cannot be mutated
    // safely. The assertion inside is what stops an unbuilt sentinel turning
    // this into a measurement of nothing.
    let _ = sentinel_binary();
    let workspace = tempfile::tempdir().expect("workspace");
    let config = SupervisorConfig::new(
        ChildConfig {
            command: fixture_binary(),
            args: vec!["agent".to_owned()],
            workspace: workspace.path().to_path_buf(),
            inherit_env: Vec::new(),
            env: std::collections::BTreeMap::new(),
            message_limit: 1 << 20,
            stderr_cap: 1 << 16,
        },
        ConnectionScope {
            tenant: "tenant-a".to_owned(),
            principal: "principal-a".to_owned(),
            device: "device-a".to_owned(),
            service: "service-a".to_owned(),
            connection: "connection-a".to_owned(),
        },
    );
    let (supervisor, _events) = Supervisor::start(config).expect("spawn");
    supervisor.initialize().await.expect("initialize");
    let session = supervisor
        .new_session("/workspace/demo")
        .await
        .expect("session");
    supervisor.subscriber_ready(&session).expect("subscriber");
    let child_group = supervisor.pid().expect("a child pid").to_string();
    let pid_path = workspace.path().join("detached.pid");
    let ticket = supervisor
        .prompt(&session, "detach:detached.pid")
        .expect("prompt");
    ticket.stop_reason().await.expect("turn completed");

    let pid = read_pid(&pid_path).await;
    // Registered before any assertion, so nothing below can leak it.
    let _guard = PidGuard::watch(&pid);
    assert!(!pid.is_empty(), "the agent started a descendant");
    let escaped = std::fs::read_to_string(marker_file(&pid_path)).unwrap_or_default();

    supervisor.drain().await;
    let diagnostics = supervisor.diagnostics();
    // Give the group kill, and the sentinel, every chance to reach it.
    tokio::time::sleep(SETTLE).await;
    let row = process_row(&pid);
    eprintln!(
        "MEASURED (M8-C07) escaping descendant with a sentinel armed: pid {pid}, \
         setsid marker {escaped:?}, child process group {child_group}, group kills \
         {}, sentinels armed {}, stood down {}, process table {SETTLE:?} after the \
         group SIGKILL: {row:?}",
        diagnostics.group_kills, diagnostics.deadman_armed, diagnostics.deadman_stood_down
    );

    assert!(
        diagnostics.group_kills >= 1,
        "a group signal was actually sent"
    );
    assert_eq!(
        diagnostics.deadman_armed, 1,
        "the parent-death sentinel was armed, so this measures the NEW mechanism \
         and not merely the old one"
    );
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean \
         anything"
    );
    let (pgid, state) = row.expect(
        "MEASUREMENT (M8-C07, inherited from M3-09): the escaping descendant was \
         expected to survive, sentinel or no sentinel. If it did not, process-tree \
         containment on this host changed and the recorded limitation must be \
         re-derived rather than quietly relaxed.",
    );
    assert!(
        !state.starts_with('Z'),
        "it is alive, not an unreaped corpse: state {state}"
    );
    assert_ne!(
        pgid, child_group,
        "it survived *because* it left the child's process group, not by outrunning \
         the signal — and the sentinel, which sends the same group signal from \
         elsewhere, does not change that"
    );
}
