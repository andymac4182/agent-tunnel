//! Task row M3-09: what the stdio export's process-group kill does and does
//! not contain, measured against the process table.
//!
//! # Two holes, and why they must not be reported as one
//!
//! The row asks for a fixture that detaches and a regression around it.  The
//! measurement it produces splits the problem in two, and the split is the
//! finding:
//!
//! * **Reach** — a descendant that calls `setsid` or daemonizes with a double
//!   fork is not in the child's process group, so no group signal reaches it.
//!   [`a_setsid_descendant_escapes_the_group_kill`] and
//!   [`a_double_forked_descendant_escapes_the_group_kill`] measure that it
//!   escapes, **and still escapes with the parent-death sentinel armed**.
//!   The sentinel sends the same signal from a different process; it was
//!   never going to widen the reach, and a test that did not say so would be
//!   evidence proving less than it claimed.
//! * **Trigger** — a `SIGKILL` of the supervising process runs no `Drop`, so
//!   before this chunk nobody signalled the group at all and even an
//!   ordinary in-group helper survived.
//!   [`a_sigkilled_supervisor_still_kills_the_group`] measures that it no
//!   longer does.  It has **two** controls, because on its own it would only
//!   show that a helper was gone and not that anything here removed it:
//!   [`without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group`]
//!   runs the identical probe with no sentinel — the state of `origin/main` —
//!   and requires the helper to survive, and
//!   [`the_group_kill_reaches_an_in_group_helper`] shows a helper of this
//!   shape is the sort of thing a group signal reaches at all.
//!
//! Every assertion here is against `/bin/ps`, and every one of them checks
//! the process **state** as well as the pid, because `kill -0` and a bare pid
//! lookup both succeed on an unreaped zombie: a process something really did
//! kill would otherwise read as a survivor.
//!
//! Every pid this file creates is registered with a [`PidGuard`] **before**
//! the first assertion that could panic, so a failure anywhere leaves nothing
//! behind.

#![cfg(unix)]

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;

use tunnel_mcp_export::child::{ChildCounters, ChildHandle, spawn};
use tunnel_mcp_export::config::StdioBackend;
use tunnel_mcp_fixture::{
    DETACH_HOST_MODE, DetachRoute, HELPER_PID_FILE, SUPERVISE_MODE, SUPERVISE_REPORT, WRAPPER_MODE,
    WRAPPER_PID_FILE, detached_pid_file, escape_marker,
};

/// Long enough that a `SIGKILL` aimed at a live group member has certainly
/// landed.  The bound is generous in the **safe** direction: a group signal
/// takes effect immediately, so a slower machine makes survival harder to
/// observe, never easier.  It can only make a survival claim weaker.
const SETTLE: Duration = Duration::from_millis(500);

// ------------------------------------------------------------------ helpers

/// The fixture executable, built beside this test binary.
fn fixture_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    let binary = path.join("tunnel-mcp-fixture");
    assert!(
        binary.is_file(),
        "the fixture binary must be built; run the workspace test command, not a bare -p run"
    );
    binary
}

/// The sentinel executable, built beside this test binary.
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
/// The state is carried because a pid lookup alone cannot tell a survivor
/// from an unreaped corpse.
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
/// Absent is gone, and so is `Z`: a pid lookup alone cannot tell a survivor
/// from a corpse nobody has reaped, and every containment claim in this file
/// turns on that difference.  Written once, so no caller can spell it in a
/// way that quietly accepts a zombie as a survivor.
fn is_live(row: Option<&(String, String)>) -> bool {
    row.is_some_and(|(_, state)| !state.starts_with('Z'))
}

/// Whether `pid` is a live process.
fn alive(pid: &str) -> bool {
    is_live(process_row(pid).as_ref())
}

/// Wait, bounded, for `pid` to stop being a live process.  Returns the last
/// row seen, so a failure can report *what* survived rather than only that
/// something did.
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

/// Kills a pid when it goes out of scope, however the test left — including
/// through a panic in an assertion above the cleanup.  This file creates
/// processes designed to escape process cleanup, so nothing may be killed
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

/// Start one export child that hosts an escaping descendant, and wait until
/// the descendant has published its pid.  Returns the handle, the counters
/// and that pid.
///
/// The escaping process is a **descendant** of the export child, never the
/// child itself: the supervisor signals its own child by pid as well as by
/// group, so a child that detached from its own group would be killed by the
/// direct signal and the group's reach would never be tested.
async fn detaching_child(
    workspace: &Path,
    route: DetachRoute,
) -> (ChildHandle, Arc<ChildCounters>, String) {
    let pid_file = workspace.join(detached_pid_file(route.as_str()));
    let backend = StdioBackend {
        command: fixture_binary(),
        args: vec![
            DETACH_HOST_MODE.to_owned(),
            route.as_str().to_owned(),
            pid_file.display().to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        inherit_env: Vec::new(),
        workspace: workspace.to_path_buf(),
        max_children: 1,
        session_idle: Duration::from_secs(600),
    };
    let counters = Arc::new(ChildCounters::default());
    let (handle, _events) = spawn(&backend, 1 << 20, &counters).expect("the child started");
    let pid = read_pid(&pid_file).await;
    (handle, counters, pid)
}

/// Shared body of the two reach measurements.
///
/// `child_group` is the export child's pid, which is also its process group
/// id, because the export starts every child as its own group leader.
async fn measure_escape(name: &str, handle: ChildHandle, counters: &ChildCounters, pid: &str) {
    handle.kill();
    handle.wait_exited().await;
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
         and not merely the old one"
    );
    let (pgid, state) = row.expect(
        "MEASUREMENT (M3-09): the escaping descendant was expected to survive. If it did \
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
async fn a_setsid_descendant_escapes_the_group_kill() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (handle, counters, pid) = detaching_child(workspace.path(), DetachRoute::Setsid).await;
    let _guard = PidGuard::watch(&pid);
    assert!(!pid.is_empty(), "the descendant published a pid");

    // Refuse to conclude anything from a fixture that did not detach: it
    // would be killed by the plain group signal and this would be a
    // measurement of nothing.
    let escaped = std::fs::read_to_string(escape_marker(
        &workspace.path().join(detached_pid_file("setsid")),
    ))
    .unwrap_or_default();
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean anything"
    );
    // It is its own session and group leader, so its group id is its own pid.
    let (pgid, _) = process_row(&pid).expect("it is running before the kill");
    assert_eq!(pgid, pid, "setsid made it the leader of a group of its own");

    measure_escape("setsid escape", handle, &counters, &pid).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_double_forked_descendant_escapes_the_group_kill() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (handle, counters, pid) = detaching_child(workspace.path(), DetachRoute::Daemon).await;
    let _guard = PidGuard::watch(&pid);
    assert!(!pid.is_empty(), "the descendant published a pid");

    let escaped = std::fs::read_to_string(escape_marker(
        &workspace.path().join(detached_pid_file("daemon")),
    ))
    .unwrap_or_default();
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean anything"
    );

    measure_escape("double-fork escape", handle, &counters, &pid).await;
}

// -------------------------------------- reach control: an in-group helper dies

/// The control that makes the two escapes above mean something.
///
/// If a descendant of the very same shape stayed in the group and *also*
/// survived, the escapes would prove nothing about `setsid` and everything
/// about a group kill that never worked.  This one differs from them in
/// exactly one respect — it did not leave the group — and it dies.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_group_kill_reaches_an_in_group_helper() {
    let workspace = tempfile::tempdir().expect("workspace");
    let wrapper_pid_file = workspace.path().join(WRAPPER_PID_FILE);
    let helper_pid_file = workspace.path().join(HELPER_PID_FILE);
    let backend = StdioBackend {
        command: fixture_binary(),
        args: vec![
            WRAPPER_MODE.to_owned(),
            wrapper_pid_file.display().to_string(),
            helper_pid_file.display().to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        inherit_env: Vec::new(),
        workspace: workspace.path().to_path_buf(),
        max_children: 1,
        session_idle: Duration::from_secs(600),
    };
    let counters = Arc::new(ChildCounters::default());
    let (handle, _events) = spawn(&backend, 1 << 20, &counters).expect("the child started");
    let helper = read_pid(&helper_pid_file).await;
    let mut guard = PidGuard::watch(&helper);
    let wrapper = read_pid(&wrapper_pid_file).await;
    guard.also(&wrapper);
    assert!(!helper.is_empty(), "the wrapper started a helper");
    assert!(alive(&helper), "the helper runs before the kill");

    handle.kill();
    handle.wait_exited().await;
    let row = wait_not_alive(&helper).await;
    eprintln!("MEASURED in-group helper: pid {helper}, process table after the kill: {row:?}");
    assert!(
        !is_live(row.as_ref()),
        "an in-group helper IS reached by the group kill, so the escapes measured \
         elsewhere in this file are about leaving the group and not about a group \
         kill that never worked"
    );
}

// ------------------------------------------- trigger: SIGKILL of the supervisor

/// The half CUA supervision depends on, and the one an orderly shutdown test
/// cannot reach.
///
/// The supervisor is a **separate process** here because a `SIGKILL` runs no
/// `Drop`, no `kill_on_drop` and no handler: it cannot be simulated from
/// inside the process that owns the handle.  The test kills it outright and
/// then reads the process table for the helper that the dead supervisor was
/// supposed to clean up.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_sigkilled_supervisor_still_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut probe = std::process::Command::new(fixture_binary())
        .arg(SUPERVISE_MODE)
        .arg(workspace.path())
        .env(tunnel_deadman::SENTINEL_PATH_ENV, sentinel_binary())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the supervisor probe started");
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
        "MEASURED SIGKILLed supervisor: probe {probe_pid}, wrapper {wrapper}, helper \
         {helper}, wrapper row {wrapper_row:?}, helper row {helper_row:?}"
    );
    assert!(
        !is_live(helper_row.as_ref()),
        "MEASUREMENT (M3-09): the in-group helper of a SIGKILLed supervisor's child must \
         be gone from the process table, not merely detached from a closed handle. It \
         was still {helper_row:?}"
    );
}

/// **The control for the test above: the leak this chunk closes, asserted as
/// still present when the mechanism is absent.**
///
/// The green test alone proves only that a helper was gone; it cannot say
/// whether the sentinel was what removed it, or whether the helper would have
/// died anyway on this host.  So the same probe runs again with the sentinel
/// executable deliberately unlocatable — which is exactly the state of
/// `origin/main`, where no sentinel exists at all — and the helper is
/// required to **survive**.
///
/// The two tests differ in one respect and reach opposite outcomes, which is
/// what makes the pair evidence rather than a pair of observations.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn without_a_sentinel_a_sigkilled_supervisor_leaks_its_childs_group() {
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
        "MEASURED unarmed supervisor (the pre-chunk behaviour): probe {probe_pid}, \
         wrapper {wrapper}, helper {helper}, wrapper row {wrapper_row:?}, helper row \
         {helper_row:?}"
    );
    assert!(
        is_live(helper_row.as_ref()),
        "MEASUREMENT (M3-09): without a sentinel the in-group helper of a SIGKILLed \
         supervisor's child SURVIVES — that is the leak. If this ever passes by dying, \
         the sibling test proves nothing and both must be re-derived. It was \
         {helper_row:?}"
    );
    let (helper_group, state) = helper_row.expect("it is in the table");
    assert!(!state.starts_with('Z'), "alive, not an unreaped corpse");
    assert_eq!(
        helper_group, wrapper,
        "and it survives inside the very process group nobody signalled"
    );
}

/// The sentinel must not fire when the supervisor ends its child in an
/// orderly way.
///
/// The reason is **not** that a firing sentinel might hit a reissued group id
/// — that framing is the one this chunk kept getting wrong. It is that a
/// sentinel which fires on an orderly shutdown is a sentinel whose stand-down
/// path does not work, and the stand-down path is the only thing keeping an
/// ordinary shutdown from carrying a redundant group `SIGKILL` at a group the
/// supervisor has already killed and reaped — the one moment at which the id
/// genuinely may have been freed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_shutdown_stands_the_sentinel_down_instead_of_firing_it() {
    let workspace = tempfile::tempdir().expect("workspace");
    let wrapper_pid_file = workspace.path().join(WRAPPER_PID_FILE);
    let helper_pid_file = workspace.path().join(HELPER_PID_FILE);
    let backend = StdioBackend {
        command: fixture_binary(),
        args: vec![
            WRAPPER_MODE.to_owned(),
            wrapper_pid_file.display().to_string(),
            helper_pid_file.display().to_string(),
        ],
        env: std::collections::BTreeMap::new(),
        inherit_env: Vec::new(),
        workspace: workspace.path().to_path_buf(),
        max_children: 1,
        session_idle: Duration::from_secs(600),
    };
    let counters = Arc::new(ChildCounters::default());
    let (handle, _events) = spawn(&backend, 1 << 20, &counters).expect("the child started");
    let helper = read_pid(&helper_pid_file).await;
    let _guard = PidGuard::watch(&helper);
    assert_eq!(counters.deadman_armed.load(Ordering::Relaxed), 1);

    handle.kill();
    handle.wait_exited().await;
    assert_eq!(
        counters.deadman_stood_down.load(Ordering::Relaxed),
        1,
        // Deliberately says only what it checks. The counter reads the
        // sentinel's exit status, so this proves the sentinel stood down
        // rather than fired. It proves nothing about *when* it was asked,
        // and the ordering it was asked in is named as untested in M3-09's
        // "Not covered" list rather than implied to be covered here.
        "the sentinel exited stood-down rather than fired"
    );
    // And the orderly path still cleaned the group up itself.
    let row = wait_not_alive(&helper).await;
    assert!(
        !is_live(row.as_ref()),
        "the supervisor's own group kill did the work on the orderly path"
    );
}

// ------------------------------------ an orderly return right after the kill

/// One `supervise-return` probe: start it, let it report, trigger its stop,
/// wait for it to exit, and return the helper's process-table row after
/// [`SETTLE`] plus whether a sentinel was armed and the probe's exit status.
async fn orderly_return(
    sentinel: bool,
    wait_for_reap: bool,
    single_thread: bool,
) -> (Option<(String, String)>, String, Option<i32>) {
    let workspace = tempfile::tempdir().expect("workspace");
    let sentinel_path = if sentinel {
        sentinel_binary()
    } else {
        workspace.path().join("no-such-sentinel")
    };
    let mut probe = std::process::Command::new(fixture_binary())
        .arg(tunnel_mcp_fixture::SUPERVISE_RETURN_MODE)
        .arg(workspace.path())
        .arg(if wait_for_reap { "wait" } else { "nowait" })
        .arg(if single_thread { "single" } else { "multi" })
        .env(tunnel_deadman::SENTINEL_PATH_ENV, sentinel_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the supervisor probe started");
    let probe_pid = probe.id().to_string();
    let mut guard = PidGuard::watch(&probe_pid);
    let report = read_pid(&workspace.path().join(SUPERVISE_REPORT)).await;
    let fields = report.split_whitespace().collect::<Vec<_>>();
    assert_eq!(
        fields.len(),
        3,
        "the probe reported three fields: {report:?}"
    );
    let (wrapper, helper, armed) = (fields[0], fields[1], fields[2].to_owned());
    guard.also(wrapper);
    guard.also(helper);
    assert!(alive(helper), "the helper runs before the stop");
    std::fs::write(
        workspace
            .path()
            .join(tunnel_mcp_fixture::SUPERVISE_RETURN_TRIGGER),
        b"stop",
    )
    .expect("trigger the probe's stop");
    let status = tokio::task::spawn_blocking(move || probe.wait())
        .await
        .expect("join the probe wait")
        .expect("the probe exited");
    tokio::time::sleep(SETTLE).await;
    (process_row(helper), armed, status.code())
}

/// Runs per multi-thread orderly-return measurement. On that flavour the
/// leak is a race -- whether the runtime polls the supervisor task before
/// it is torn down -- so one run proves nothing either way.
const ORDERLY_RETURN_RUNS: usize = 10;

/// **M6-C29, the defect, made deterministic.** Requesting the kill and
/// returning from `main` at once -- what `tunnel-client connect` did after
/// its orderly stop -- tears the runtime down without polling the
/// supervisor task. The leader is killed only by `kill_on_drop`, and with no
/// sentinel nobody signals its group: the in-group helper **survives**. On a
/// current-thread runtime nothing else can poll the task first, so this is
/// the race's losing side every time. It is the control for the test below:
/// the two differ only in `nowait` against `wait`.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_return_that_does_not_wait_leaks_the_helper_without_a_sentinel() {
    let (row, armed, code) = orderly_return(false, false, true).await;
    assert_eq!(armed, "0", "no sentinel was armed, which is the point");
    assert_eq!(code, Some(0), "the probe returned from main normally");
    assert!(
        is_live(row.as_ref()),
        "MEASUREMENT (M6-C29): returning straight after the kill request must leave the \
         in-group helper alive when no sentinel is installed -- if it does not, the test \
         below proves nothing and both must be re-derived. It was {row:?}"
    );
}

/// **M6-C29, the remedy `tunnel-client connect` now applies.** Waiting for
/// the supervisor's `running` counter to reach zero before returning means
/// the group kill has been sent and the leader reaped, so even with **no**
/// sentinel the in-group helper is gone. `tunnel-client` waits on the same
/// counter, summed over its MCP exports
/// (`McpExportDiagnostics::children_running`), after its orderly stop.
/// Defeated by passing `nowait`, this is the test above, and goes red.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_return_that_waits_for_the_reap_leaves_no_helper_without_a_sentinel() {
    let (row, armed, code) = orderly_return(false, true, true).await;
    assert_eq!(armed, "0", "no sentinel was armed, which is the point");
    assert_eq!(code, Some(0), "the probe returned from main normally");
    assert!(
        !is_live(row.as_ref()),
        "MEASUREMENT (M6-C29): waiting for the reap before returning must leave no \
         in-group helper even without a sentinel; it was {row:?}"
    );
}

/// **M6-C29 on the runtime flavour `tunnel-client` actually uses.** On a
/// multi-thread runtime another worker may poll the supervisor task before
/// teardown, so the leak is a race: measured 7 in 50 runs across five
/// sequential batches (log nonces `m6c29-measure-20260923T012226Z-12550`
/// and `m6c29-rate-20260923T012555Z-15600`), and 0 in 10 with a sentinel,
/// because the sentinel **fires** on the bare end of file -- the orderly
/// path had silently become the crash path.
///
/// Ignored because it is a race and asserts only that the leak is reachable
/// (at least one survivor in [`ORDERLY_RETURN_RUNS`] runs); run it
/// explicitly, on a quiet machine.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "M6-C29 measurement of a race; run explicitly"]
async fn an_orderly_return_without_waiting_can_leak_the_helper_without_a_sentinel() {
    let mut survivors = 0;
    for run in 0..ORDERLY_RETURN_RUNS {
        let (row, armed, code) = orderly_return(false, false, false).await;
        assert_eq!(armed, "0", "no sentinel was armed, which is the point");
        assert_eq!(code, Some(0), "the probe returned from main normally");
        if is_live(row.as_ref()) {
            survivors += 1;
        }
        eprintln!("MEASURED M6-C29 nowait run {run}: helper row {row:?}");
    }
    eprintln!("MEASURED M6-C29 nowait: {survivors} of {ORDERLY_RETURN_RUNS} helpers survived");
    assert!(
        survivors > 0,
        "MEASUREMENT (M6-C29): no run leaked the helper; the race was not reproduced \
         on this host, which is not evidence that it is gone"
    );
}
