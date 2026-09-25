//! The supervisor against a real child process (M8-02's supervisor half and
//! M8-03's lifecycle half).
//!
//! Every test here drives the supervisor's own decision, and every refusal is
//! asserted **by its rule**. Where a claim would otherwise rest on the
//! parent's belief, the evidence is read from somewhere the parent does not
//! write: the process table for a kill, and a marker file the agent itself
//! wrote for a permission outcome.
//!
//! **Not covered here, and not implied anywhere:** HTTP, SSE, the tunnel, a
//! relay, and any real ACP client. macOS is the only host this has run on.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use tokio::sync::mpsc;
use tunnel_acp::lifecycle::{ChildLifecycle, Direction, LifecycleRule, PermissionOutcome};
use tunnel_acp::message::AcpRule;
use tunnel_acp_export::{
    AgentEvent, ChildConfig, ChildEnd, ConnectionScope, Supervisor, SupervisorConfig,
    SupervisorError,
};
use tunnel_acp_fixture::{PERMISSION_OUTCOME_FILE, PERMIT_OPTION, marker_file};

const STEP: Duration = Duration::from_secs(30);

fn fixture_binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_tunnel-acp-fixture"))
}

async fn within<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(STEP, future)
        .await
        .expect("step timed out")
}

fn scope() -> ConnectionScope {
    ConnectionScope {
        tenant: "tenant-a".to_owned(),
        principal: "principal-a".to_owned(),
        device: "device-a".to_owned(),
        service: "service-a".to_owned(),
        connection: "connection-a".to_owned(),
    }
}

fn child_config(workspace: &Path, command: &Path, args: &[&str]) -> ChildConfig {
    ChildConfig {
        command: command.to_path_buf(),
        args: args.iter().map(|value| (*value).to_owned()).collect(),
        workspace: workspace.to_path_buf(),
        inherit_env: Vec::new(),
        env: BTreeMap::new(),
        message_limit: 1 << 20,
        stderr_cap: 1 << 16,
    }
}

fn config(workspace: &Path) -> SupervisorConfig {
    SupervisorConfig::new(
        child_config(workspace, &fixture_binary(), &["agent"]),
        scope(),
    )
}

/// A `/bin/sh` wrapper that starts a grandchild and then `exec`s the fixture,
/// the same shape `tunnel-mcp-fixture`'s process-group tests use.
fn wrapper_script(dir: &Path) -> PathBuf {
    let script = dir.join("wrapper.sh");
    write_executable(
        &script,
        &format!(
            "#!/bin/sh\n/bin/sleep 300 &\necho $! > grandchild.pid\nexec \"{}\" \"$@\"\n",
            fixture_binary().display()
        ),
    );
    script
}

/// Write an executable script that no descriptor of **this** process has
/// ever held open for writing (task row M3-35).
///
/// Tests in one binary run on parallel threads, and each spawn briefly
/// shares this process's descriptor table with a child that has not yet
/// `exec`ed.  A script written here with `std::fs::write` can therefore still
/// be open for writing in such a child when another thread `exec`s it, and
/// Linux refuses that `exec` with `ETXTBSY` -- seen once on hosted
/// `ubuntu-latest` as `spawn: SpawnError`.  So the text is written to a
/// side file and `/bin/cp` creates the script: the only writer of the
/// script's inode is the `cp` process, which exits before this returns.
fn write_executable(script: &Path, text: &str) {
    let source = script.with_extension("src");
    std::fs::write(&source, text).expect("script source");
    for (program, args) in [
        ("/bin/cp", vec![source.as_os_str(), script.as_os_str()]),
        ("/bin/chmod", vec!["755".as_ref(), script.as_os_str()]),
    ] {
        let status = std::process::Command::new(program)
            .args(args)
            .status()
            .expect("run a script writer");
        assert!(status.success(), "{program} failed");
    }
}

/// Read the process table, not a handle. `kill -0` asks the kernel whether a
/// pid the test does not own is still there.
fn alive(pid: &str) -> bool {
    std::process::Command::new("/bin/kill")
        .args(["-0", pid])
        .stderr(std::process::Stdio::null())
        .status()
        .is_ok_and(|status| status.success())
}

async fn read_pid(path: &Path) -> String {
    for _ in 0..500 {
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

async fn wait_gone(pid: &str) -> bool {
    for _ in 0..500 {
        if !alive(pid) {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    false
}

/// `(pgid, state)` from the process table, or `None` if the pid is gone.
///
/// The state matters because `kill -0` succeeds on a **zombie**: a descendant
/// that something did kill but that nobody has reaped yet would read as
/// "survived" and pass a survival assertion for entirely the wrong reason.
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

/// Kills a pid when it goes out of scope, however the test left — including
/// through a panic in an `expect` several lines above the cleanup.
///
/// The M8-C07 review found a leaked 300-second descendant that came from
/// exactly that: an assertion sitting above the `kill -9`.
struct PidGuard(String);

impl Drop for PidGuard {
    fn drop(&mut self) {
        if self.0.is_empty() {
            return;
        }
        let _ = std::process::Command::new("/bin/kill")
            .args(["-9", &self.0])
            .stderr(std::process::Stdio::null())
            .status();
    }
}

async fn next_event(events: &mut mpsc::Receiver<AgentEvent>) -> AgentEvent {
    within(events.recv()).await.expect("an agent event")
}

/// Start a supervisor, initialize it and open one subscribed session.
async fn ready(config: SupervisorConfig) -> (Supervisor, mpsc::Receiver<AgentEvent>, String) {
    let (supervisor, events) = Supervisor::start(config).expect("spawn");
    within(supervisor.initialize()).await.expect("initialize");
    assert_eq!(supervisor.lifecycle(), ChildLifecycle::Ready);
    let session = within(supervisor.new_session("/workspace/demo"))
        .await
        .expect("session");
    supervisor.subscriber_ready(&session).expect("subscriber");
    (supervisor, events, session)
}

// ------------------------------------------------------------ the happy path

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_runs_a_turn_and_the_lifecycle_drives_it() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, mut events, session) = ready(config(workspace.path())).await;

    let ticket = supervisor.prompt(&session, "ok").expect("prompt");
    // The update arrives on the reader while the prompt is outstanding.
    assert!(matches!(
        next_event(&mut events).await,
        AgentEvent::Update { .. }
    ));
    let stop = within(ticket.stop_reason()).await.expect("turn completed");
    assert_eq!(stop, "end_turn");

    // A second turn may start, which is only true if the first one ended in
    // the state machine rather than in a flag this test set.
    supervisor.prompt(&session, "ok").expect("a second turn");
    supervisor.drain().await;
    assert_eq!(supervisor.lifecycle(), ChildLifecycle::Stopped);
    assert!(supervisor.diagnostics().group_kills >= 1);
}

// ------------------------------- a callback handled while a prompt is pending

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_reader_handles_a_callback_while_a_prompt_is_pending() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, mut events, session) = ready(config(workspace.path())).await;

    let ticket = supervisor.prompt(&session, "permission").expect("prompt");
    let AgentEvent::Permission { id, session: on } = next_event(&mut events).await else {
        panic!("the agent's permission request must reach the host");
    };
    assert_eq!(on, session);
    // The prompt is still outstanding: the reader is a different task.
    assert_eq!(supervisor.pending(Direction::HostToAgent), 1);
    assert_eq!(supervisor.pending(Direction::AgentToHost), 1);

    within(
        supervisor.answer_permission(&id, PermissionOutcome::Selected(PERMIT_OPTION.to_owned())),
    )
    .await
    .expect("answer");

    // A duplicate answer that would reverse the decision is refused, by name.
    let duplicate = within(supervisor.answer_permission(&id, PermissionOutcome::Cancelled))
        .await
        .expect_err("a duplicate answer");
    assert_eq!(duplicate.rule(), Some(LifecycleRule::UnknownRequestId));

    let stop = within(ticket.stop_reason()).await.expect("turn completed");
    assert_eq!(stop, "end_turn");
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(PERMISSION_OUTCOME_FILE))
            .expect("the agent recorded what it received"),
        format!("selected:{PERMIT_OPTION}")
    );
    supervisor.drain().await;
}

// ------------------------------------------------------ the permission timeout

/// The roadmap gate: **a permission timeout resolves as cancelled, never
/// approved.**
///
/// The bound is shortened to 150 ms so the timeout can actually elapse, and
/// three things are asserted that a constant in a config struct could not
/// produce: the supervisor's measured elapsed time exceeds the configured
/// bound, the test's own wall clock also passed the bound, and the **agent**
/// recorded receiving `cancelled` — which the supervisor did not write.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_permission_timeout_resolves_as_cancelled_never_approved() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut config = config(workspace.path());
    config.permission_timeout = Duration::from_millis(150);
    config.deadline_tick = Duration::from_millis(10);
    let (supervisor, mut events, session) = ready(config).await;

    let started = Instant::now();
    let ticket = supervisor.prompt(&session, "permission").expect("prompt");
    let AgentEvent::Permission { id, .. } = next_event(&mut events).await else {
        panic!("the permission request must arrive");
    };
    // Nobody answers.
    let expired = next_event(&mut events).await;
    let wall = started.elapsed();
    let AgentEvent::PermissionExpired {
        id: expired_id,
        elapsed_ms,
        bound_ms,
        outcome,
        ..
    } = expired
    else {
        panic!("the deadline must expire the permission, and say so");
    };
    // The measurement itself is the evidence; `--nocapture` prints it.
    eprintln!(
        "MEASURED permission timeout: supervisor elapsed {elapsed_ms} ms, bound {bound_ms} ms, test wall clock {} ms",
        wall.as_millis()
    );
    assert_eq!(expired_id, id);
    assert_eq!(outcome, PermissionOutcome::Cancelled);
    assert_eq!(bound_ms, 150);
    assert!(
        elapsed_ms > bound_ms,
        "the measured elapsed {elapsed_ms} ms must exceed the bound {bound_ms} ms"
    );
    assert!(
        wall >= Duration::from_millis(150),
        "the test's own clock also passed the bound: {wall:?}"
    );

    // The host's late approval cannot revive or reverse the cancellation.
    let late = within(
        supervisor.answer_permission(&id, PermissionOutcome::Selected(PERMIT_OPTION.to_owned())),
    )
    .await
    .expect_err("a late approval");
    assert_eq!(late.rule(), Some(LifecycleRule::UnknownRequestId));

    let stop = within(ticket.stop_reason()).await.expect("the turn ends");
    assert_eq!(stop, "cancelled");
    // Wire evidence: the agent wrote what it received, not what we believe we
    // sent.
    assert_eq!(
        std::fs::read_to_string(workspace.path().join(PERMISSION_OUTCOME_FILE))
            .expect("the agent recorded what it received"),
        "cancelled:"
    );
    assert_eq!(supervisor.diagnostics().permission_expirations, 1);
    supervisor.drain().await;
}

// -------------------------------------------------- pathological child output

async fn child_output_ends_with(directive: &str, message_limit: u64) -> (ChildEnd, u64) {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut config = config(workspace.path());
    config.child.message_limit = message_limit;
    let (supervisor, mut events, session) = ready(config).await;
    let _ticket = supervisor.prompt(&session, directive).expect("prompt");
    loop {
        match next_event(&mut events).await {
            AgentEvent::Ended(end) => {
                within(supervisor.wait_exited()).await;
                let diagnostics = supervisor.diagnostics();
                assert!(
                    diagnostics.group_kills >= 1,
                    "every end of life signals the process group"
                );
                // The supervisor *killed* it, rather than the child happening
                // to exit on its own when the writer dropped stdin. Without
                // this the group-kill counter alone would not distinguish the
                // two, and a refusal that never killed anything would pass.
                assert_eq!(
                    diagnostics.killed, 1,
                    "the refusal cancelled the child, it did not wait for EOF"
                );
                assert_eq!(supervisor.lifecycle(), ChildLifecycle::Failed);
                return (end, diagnostics.invalid_output);
            }
            _ => continue,
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_oversized_stdout_line_kills_the_child_rather_than_being_reassembled() {
    // 64 KiB of filler with no newline in it, against a 4 KiB limit.
    let (end, invalid) = child_output_ends_with("oversized:65536", 4096).await;
    assert_eq!(end, ChildEnd::OversizedLine);
    assert_eq!(invalid, 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_malformed_stdout_line_kills_the_child_for_being_malformed() {
    let (end, invalid) = child_output_ends_with("malformed", 1 << 20).await;
    // The rule, not merely "it ended": a malformed line must not be reported
    // as a batch, and a batch must not be reported as malformed.
    assert_eq!(end, ChildEnd::InvalidLine(AcpRule::NotStrictJson));
    assert_eq!(invalid, 1);
}

/// M8-C02: the pinned SDK preserves JSON-RPC batch frames, the pinned RFD
/// revision answers 501, and this profile refuses. A child that deliberately
/// emits one meets the disagreement instead of avoiding it.
///
/// This is the **stdio** half only. The row's acceptance is about the SSE
/// stream, which this chunk does not have, so M8-C02 stays open.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_batch_line_from_the_child_is_refused_for_being_a_batch() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, mut events, session) = ready(config(workspace.path())).await;
    let _ticket = supervisor.prompt(&session, "batch").expect("prompt");
    loop {
        if let AgentEvent::Ended(end) = next_event(&mut events).await {
            assert_eq!(end, ChildEnd::InvalidLine(AcpRule::BatchNotSupported));
            assert_eq!(AcpRule::BatchNotSupported.status(), 501);
            within(supervisor.wait_exited()).await;
            let diagnostics = supervisor.diagnostics();
            assert_eq!(diagnostics.batch_output, 1);
            assert_eq!(
                diagnostics.killed, 1,
                "the batch cancelled the child, it did not wait for EOF"
            );
            return;
        }
    }
}

// ------------------------------------------------------------ a stderr flood

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stderr_flood_is_drained_and_counted_without_blocking_child_exit() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut config = config(workspace.path());
    config.child.stderr_cap = 1 << 16;
    let (supervisor, _events, session) = ready(config).await;

    const FLOOD: u64 = 4 << 20;
    let ticket = supervisor
        .prompt(&session, &format!("stderr-flood:{FLOOD}"))
        .expect("prompt");
    // The turn still completes: the drain never backs the child up.
    let stop = within(ticket.stop_reason()).await.expect("turn completed");
    assert_eq!(stop, "end_turn");

    // `write_all` returns once the pipe absorbs the tail, so some of the flood
    // can still be unread when the completion arrives. Poll rather than
    // sampling once: a single sample would produce a **false red**, which is
    // the worse kind of flake in a suite whose whole point is that a green
    // result means something.
    let mut diagnostics = supervisor.diagnostics();
    for _ in 0..500 {
        if diagnostics.stderr_bytes >= FLOOD {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        diagnostics = supervisor.diagnostics();
    }
    assert_eq!(
        diagnostics.stderr_bytes, FLOOD,
        "every byte was drained and counted, and not one more"
    );
    assert_eq!(diagnostics.stderr_over_cap, 1, "the sink reported its cap");

    // And the child can still exit: a cap that stopped reading would hang it.
    supervisor.drain().await;
    assert_eq!(supervisor.lifecycle(), ChildLifecycle::Stopped);
}

// ----------------------------------------------------------------- the bounds

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_session_bound_is_exact_at_the_supervisor() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, _events, first) = ready(config(workspace.path())).await;
    assert_eq!(supervisor.session_count(), 1);
    let _ = first;
    for index in 1..tunnel_acp::lifecycle::MAX_SESSIONS_PER_CONNECTION {
        within(supervisor.new_session("/workspace/demo"))
            .await
            .unwrap_or_else(|error| panic!("session {index} within the bound: {error}"));
    }
    assert_eq!(
        supervisor.session_count(),
        tunnel_acp::lifecycle::MAX_SESSIONS_PER_CONNECTION
    );
    let refused = within(supervisor.new_session("/workspace/demo"))
        .await
        .expect_err("one beyond the bound");
    assert_eq!(refused.rule(), Some(LifecycleRule::SessionLimit));
    supervisor.drain().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_active_prompt_per_session_at_the_supervisor() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, _events, session) = ready(config(workspace.path())).await;
    // `silent` never answers, so the first turn stays active.
    let _first = supervisor.prompt(&session, "silent").expect("first prompt");
    let refused = supervisor
        .prompt(&session, "ok")
        .expect_err("a second concurrent prompt");
    assert_eq!(refused.rule(), Some(LifecycleRule::PromptAlreadyActive));
    supervisor.drain().await;
}

/// The **16 agent callbacks per direction** bound, exact at the boundary and
/// refused one beyond, against a real child.
///
/// One turn asks for seventeen permissions at once, so the bound is actually
/// reached rather than merely configured. The host direction is untouched by
/// this: the single `session/prompt` is its only outstanding request, which is
/// what makes the bound per-direction rather than shared.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_agent_callback_bound_is_exact_at_sixteen_against_a_real_child() {
    const LIMIT: usize = tunnel_acp::lifecycle::MAX_PENDING_PER_DIRECTION;
    let workspace = tempfile::tempdir().expect("workspace");
    let mut config = config(workspace.path());
    // Long enough that no deadline interferes with the bound being reached.
    config.permission_timeout = Duration::from_secs(60);
    let (supervisor, mut events, session) = ready(config).await;

    let _ticket = supervisor
        .prompt(&session, &format!("permission:{}", LIMIT + 1))
        .expect("prompt");

    let mut accepted = 0;
    let mut refused = Vec::new();
    while accepted + refused.len() < LIMIT + 1 {
        match next_event(&mut events).await {
            AgentEvent::Permission { .. } => accepted += 1,
            AgentEvent::PermissionRefused { rule, .. } => refused.push(rule),
            _ => {}
        }
    }
    assert_eq!(accepted, LIMIT, "exactly the bound was admitted");
    assert_eq!(LIMIT, 16, "docs/acp.md's bounds table");
    assert_eq!(refused, vec![LifecycleRule::PendingLimit]);
    assert_eq!(
        supervisor.pending(Direction::AgentToHost),
        LIMIT,
        "the table is full at the bound, not merely refusing"
    );
    assert_eq!(
        supervisor.pending(Direction::HostToAgent),
        1,
        "the host direction has its own budget: only the prompt is outstanding"
    );
    supervisor.drain().await;
}

// ------------------------------------------------------ process-group cleanup

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrapper_grandchild_dies_with_the_process_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let mut config =
        SupervisorConfig::new(child_config(workspace.path(), &script, &["agent"]), scope());
    config.child.command = script;
    let (supervisor, _events, session) = ready(config).await;
    let ticket = supervisor.prompt(&session, "ok").expect("prompt");
    within(ticket.stop_reason()).await.expect("turn completed");

    let pid = read_pid(&workspace.path().join("grandchild.pid")).await;
    // The guard kills it however this test leaves, including through a panic
    // in an assertion below.
    let _guard = PidGuard(pid.clone());
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    assert!(alive(&pid), "the grandchild is running before the kill");

    supervisor.drain().await;
    // The process table, not the parent's belief.
    assert!(
        wait_gone(&pid).await,
        "grandchild {pid} outlived its process group"
    );
    assert!(supervisor.diagnostics().group_kills >= 1);
}

/// **The end of life that runs none of the supervisor's kill path.**
///
/// The child exits by itself: nothing cancels the kill token, nothing calls
/// `start_kill`, and only the post-wait group signal is left to reach the
/// grandchild. The M8-C07 review found that `ChildEnd::Closed` was never
/// exercised end to end, and that the guard-deletion case for the group kill
/// reddened on a **counter** rather than on a surviving process.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grandchild_dies_when_the_child_exits_by_itself() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let mut config =
        SupervisorConfig::new(child_config(workspace.path(), &script, &["agent"]), scope());
    config.child.command = script;
    let (supervisor, mut events, session) = ready(config).await;
    let pid = read_pid(&workspace.path().join("grandchild.pid")).await;
    let _guard = PidGuard(pid.clone());
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    assert!(alive(&pid), "the grandchild is running before the exit");

    let _ticket = supervisor.prompt(&session, "exit:0").expect("prompt");
    loop {
        if let AgentEvent::Ended(end) = next_event(&mut events).await {
            assert_eq!(end, ChildEnd::Closed, "the child ended by itself");
            break;
        }
    }
    within(supervisor.wait_exited()).await;
    assert_eq!(
        supervisor.diagnostics().killed,
        0,
        "nothing cancelled the child: this is the natural-exit path"
    );
    assert!(
        wait_gone(&pid).await,
        "grandchild {pid} outlived a child that exited by itself"
    );
    assert!(supervisor.diagnostics().group_kills >= 1);
}

/// **A supervisor dropped without `drain()` still ends its child's group.**
///
/// This is what connection loss looks like from the device side, and the
/// M8-C07 review found it leaking the agent's whole process tree: the deadline
/// ticker looped forever holding an `Arc<ChildHandle>`, so the handle's `Drop`
/// — which is where cleanup lives — never ran.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_supervisor_dropped_without_draining_still_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let mut config =
        SupervisorConfig::new(child_config(workspace.path(), &script, &["agent"]), scope());
    config.child.command = script;
    let child_pid;
    let pid;
    {
        let (supervisor, events, session) = ready(config).await;
        let ticket = supervisor.prompt(&session, "ok").expect("prompt");
        within(ticket.stop_reason()).await.expect("turn completed");
        child_pid = supervisor.pid().expect("a child pid");
        pid = read_pid(&workspace.path().join("grandchild.pid")).await;
        assert!(!pid.is_empty(), "the wrapper started a grandchild");
        assert!(alive(&pid), "the grandchild is running before the drop");
        // No `drain()`, no `kill()`, no `wait_exited()`: the owner simply goes
        // away, exactly as it would if its connection were lost.
        drop(events);
        drop(supervisor);
    }
    let _guard = PidGuard(pid.clone());
    let leader = child_pid.to_string();
    assert!(
        wait_gone(&leader).await,
        "the child leader {leader} outlived its supervisor"
    );
    assert!(
        wait_gone(&pid).await,
        "grandchild {pid} outlived a supervisor that was dropped rather than drained"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_grandchild_dies_when_the_child_is_killed_for_bad_output() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let mut config =
        SupervisorConfig::new(child_config(workspace.path(), &script, &["agent"]), scope());
    config.child.command = script;
    let (supervisor, mut events, session) = ready(config).await;
    let pid = read_pid(&workspace.path().join("grandchild.pid")).await;
    let _guard = PidGuard(pid.clone());
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    // The control the first wrapper test has: without it this passes
    // vacuously if `sleep` had already died for some unrelated reason.
    assert!(alive(&pid), "the grandchild is running before the kill");

    let _ticket = supervisor.prompt(&session, "malformed").expect("prompt");
    loop {
        if let AgentEvent::Ended(end) = next_event(&mut events).await {
            assert_eq!(end, ChildEnd::InvalidLine(AcpRule::NotStrictJson));
            break;
        }
    }
    within(supervisor.wait_exited()).await;
    assert!(
        wait_gone(&pid).await,
        "grandchild {pid} outlived a killed child"
    );
}

/// **Nothing still holds the child handle once the child is gone.**
///
/// This is the mechanism behind the other cleanup tests rather than a
/// tidiness check: the synchronous process-group kill lives in
/// `ChildHandle::drop`, which runs when the **last `Arc` goes**, so anything
/// still holding one keeps it from running. The M8-C07 review found the
/// deadline ticker doing exactly that, and there was nothing a test could read
/// to notice, because the child still died by another route.
///
/// The assertion is on `child_handle_holders`, read from `Arc::strong_count`,
/// and **not** on the `background_tasks` counter. A future task that clones
/// the handle without taking a `TaskGuard` would be invisible to the counter
/// and would recreate the defect with this test still green; `strong_count` is
/// the quantity that actually gates the drop and cannot be forgotten.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn nothing_holds_the_child_handle_once_the_child_is_gone() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, mut events, session) = ready(config(workspace.path())).await;
    let ticket = supervisor.prompt(&session, "ok").expect("prompt");
    within(ticket.stop_reason()).await.expect("turn completed");
    let before = supervisor.diagnostics();
    // Exactly two, not "more than none": `> 0` would pass with only one of the
    // reader and the deadline ticker running, which is the very state this
    // test exists to rule out.
    assert_eq!(
        before.background_tasks, 2,
        "the reader and the deadline ticker are both running"
    );
    assert_eq!(
        // Exactly two: the reader and the deadline ticker.  This is read after
        // `stop_reason()` has returned, which matters -- `dispatch` spawns
        // short-lived send tasks that also clone the handle, so taken earlier
        // this count is timing-dependent.  If it ever fails at 3, the fix is to
        // find the task still holding the handle, not to loosen this to `>= 2`:
        // a task holding the handle without ending with the child is the exact
        // defect this test exists to catch.
        before.child_handle_holders,
        2,
        "and both of them hold the child handle"
    );

    supervisor.drain().await;
    // Drain the event channel so the reader's final send cannot be what holds
    // it open; the claim is about the handle, not about a blocked consumer.
    while events.try_recv().is_ok() {}

    let mut live = supervisor.diagnostics();
    for _ in 0..500 {
        if live.child_handle_holders == 0 {
            assert_eq!(
                live.background_tasks, 0,
                "the instrumented counter agrees with the strong count"
            );
            return;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
        while events.try_recv().is_ok() {}
        live = supervisor.diagnostics();
    }
    panic!(
        "{} holder(s) of the child handle outlived the child, so its Drop -- where \
         the process-group kill lives -- can never run ({} instrumented task(s))",
        live.child_handle_holders, live.background_tasks
    );
}

/// **A runtime torn down mid-flight still kills the group.**
///
/// This is the shape the M8-C07 review actually caught: a panicking
/// `#[tokio::test]`. When a runtime is dropped, its tasks are **dropped, not
/// run**, so nothing in this crate's async code executes — `kill_on_drop`
/// reaps the leader and the group would be left behind. Only a synchronous
/// `Drop` can act here, which is why the group signal lives in
/// `ChildHandle::drop` and not only in the supervisor task.
///
/// Deliberately not a `#[tokio::test]`: the point is to own the runtime and
/// destroy it.
#[test]
fn a_runtime_torn_down_without_draining_still_kills_the_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let script = wrapper_script(workspace.path());
    let mut config =
        SupervisorConfig::new(child_config(workspace.path(), &script, &["agent"]), scope());
    config.child.command = script;

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .enable_all()
        .build()
        .expect("runtime");
    let pid = runtime.block_on(async move {
        // Everything is moved into the runtime and never handed back, so the
        // only thing that can end the child is the teardown below.
        let (supervisor, events, session) = ready(config).await;
        let ticket = supervisor.prompt(&session, "ok").expect("prompt");
        within(ticket.stop_reason()).await.expect("turn completed");
        let pid = read_pid(&workspace.path().join("grandchild.pid")).await;
        // Park the supervisor inside the runtime, so nothing outside it can
        // end the child and the teardown is the only thing left.
        tokio::spawn(async move {
            let _live = (supervisor, events);
            std::future::pending::<()>().await;
        });
        pid
    });
    let _guard = PidGuard(pid.clone());
    assert!(!pid.is_empty(), "the wrapper started a grandchild");
    assert!(alive(&pid), "the grandchild is running before the teardown");

    // No drain and no explicit kill: just the runtime going away, which is
    // what a panicking test does.
    //
    // This deliberately leaves the child leader as a **zombie of this test
    // process** — nothing is left to `wait()` on it once the runtime is gone.
    // That is harmless (the test binary exits shortly after and init reaps it)
    // and it is not what this test measures: the claim is about the
    // *grandchild*, which is not our child and cannot be a zombie of ours.
    // Please do not "fix" it by reaping here; doing so would need a handle the
    // teardown has already destroyed, which is the whole point.
    drop(runtime);

    for _ in 0..500 {
        if !alive(&pid) {
            return;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    panic!("grandchild {pid} outlived the runtime that supervised it");
}

/// **The escaping descendant, measured rather than assumed.**
///
/// `docs/tasks.md` M3-09 records that a descendant which leaves the process
/// group escapes a group `SIGKILL`. This test ships one — the fixture's
/// `detached` mode calls `setsid` — kills the group, and then **reads the
/// process table**. The expected result is that the descendant is *still
/// alive*: that is the hole, and this test records it instead of implying a
/// containment that does not exist.
///
/// If `setsid` did not succeed, the test says so and makes no claim either
/// way, because an escape that never happened proves nothing about one that
/// does.
///
/// It asserts the **mechanism**, not only the outcome. `kill -0` succeeds on a
/// zombie, so a descendant that a future containment really did kill but that
/// nobody had reaped yet would read as "survived" and keep this test green for
/// the wrong reason. The process table must show it in a different process
/// group from the child, and in a state that is not `Z`. 500 ms is generous in
/// the right direction: `SIGKILL` to a group member takes effect immediately,
/// so a slow machine makes survival harder to observe, not easier.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_descendant_that_calls_setsid_survives_the_process_group_kill() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, _events, session) = ready(config(workspace.path())).await;
    let child_group = supervisor.pid().expect("a child pid").to_string();
    let pid_path = workspace.path().join("detached.pid");
    let ticket = supervisor
        .prompt(&session, "detach:detached.pid")
        .expect("prompt");
    within(ticket.stop_reason()).await.expect("turn completed");

    let pid = read_pid(&pid_path).await;
    // Registered before any assertion, so nothing below can leak it.
    let _guard = PidGuard(pid.clone());
    assert!(!pid.is_empty(), "the agent started a descendant");
    let escaped = std::fs::read_to_string(marker_file(&pid_path)).unwrap_or_default();

    supervisor.drain().await;
    let group_kills = supervisor.diagnostics().group_kills;
    // Give the group kill every chance to reach it.
    tokio::time::sleep(Duration::from_millis(500)).await;
    let row = process_row(&pid);
    eprintln!(
        "MEASURED escaping descendant: pid {pid}, setsid marker {escaped:?}, \
         child process group {child_group}, group kills {group_kills}, \
         process table 500 ms after the group SIGKILL: {row:?}"
    );

    assert!(group_kills >= 1, "a group signal was actually sent");
    assert_eq!(
        escaped, "ok",
        "the fixture must actually have left the group for this measurement to mean anything"
    );
    let (pgid, state) = row.expect(
        "MEASUREMENT: the escaping descendant was expected to survive the group kill \
         (M3-09, inherited). If it did not, process-tree containment changed and this \
         chunk's recorded limitation must be revisited rather than quietly relaxed.",
    );
    assert!(
        !state.starts_with('Z'),
        "the descendant is alive, not an unreaped zombie: state {state}"
    );
    assert_ne!(
        pgid, child_group,
        "it survived *because* it left the child's process group, not by outrunning the signal"
    );
}

// ------------------------------------------------------------- startup failure

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_child_that_cannot_start_is_a_spawn_failure_not_a_retry() {
    let workspace = tempfile::tempdir().expect("workspace");
    let config = SupervisorConfig::new(
        child_config(
            workspace.path(),
            Path::new("/nonexistent/acp-agent"),
            &["agent"],
        ),
        scope(),
    );
    assert!(Supervisor::start(config).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_session_before_initialize_is_refused_for_readiness() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, _events) = Supervisor::start(config(workspace.path())).expect("spawn");
    assert_eq!(supervisor.lifecycle(), ChildLifecycle::Starting);
    let refused = within(supervisor.new_session("/workspace/demo"))
        .await
        .expect_err("before initialize");
    assert_eq!(refused.rule(), Some(LifecycleRule::ConnectionNotReady));
    supervisor.drain().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_prompt_after_the_child_ended_reports_an_unknown_outcome() {
    let workspace = tempfile::tempdir().expect("workspace");
    let (supervisor, mut events, session) = ready(config(workspace.path())).await;
    let _ticket = supervisor.prompt(&session, "malformed").expect("prompt");
    loop {
        if let AgentEvent::Ended(_) = next_event(&mut events).await {
            break;
        }
    }
    within(supervisor.wait_exited()).await;
    let refused = supervisor
        .prompt(&session, "ok")
        .expect_err("the connection is gone");
    // Never a silent restart, and never a replay of the prompt.
    assert!(matches!(
        refused,
        SupervisorError::Lifecycle(_) | SupervisorError::ChildGone
    ));
    assert_eq!(supervisor.lifecycle(), ChildLifecycle::Failed);
}
