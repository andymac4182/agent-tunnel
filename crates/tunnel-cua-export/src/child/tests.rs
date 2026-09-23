//! Lifecycle unit tests.
//!
//! **The pid-level containment evidence is not here.** It needs a supervisor
//! in a separate process a test can `SIGKILL`, and it needs a backend that
//! deliberately escapes, so it lives in
//! `crates/tunnel-cua-fixture/tests/process_residue.rs` where the fixture
//! binary can be executed. What these tests cover is the part that is
//! measurable in one process: that a backend is started in its own group, that
//! dropping the handle ends it, and that the sentinel counters follow what
//! happened rather than what was asked for.

#![cfg(unix)]

use super::*;

use std::path::PathBuf;
use std::time::Duration;

fn sleeper(workspace: &std::path::Path) -> BackendProcess {
    BackendProcess::new(
        PathBuf::from("/bin/sh"),
        vec!["-c".to_owned(), "exec sleep 180".to_owned()],
        workspace.to_path_buf(),
        workspace.join("address"),
    )
    .expect("valid")
}

/// `(pgid, state)` from the process table, or `None` when the pid is gone.
fn process_row(pid: u32) -> Option<(String, String)> {
    let output = std::process::Command::new("/bin/ps")
        .args(["-o", "pgid=,stat=", "-p", &pid.to_string()])
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

/// Absent is gone, and so is `Z`: a pid lookup alone cannot tell a survivor
/// from a corpse nobody has reaped.
fn is_live(row: Option<&(String, String)>) -> bool {
    row.is_some_and(|(_, state)| !state.starts_with('Z'))
}

async fn wait_not_alive(pid: u32) -> Option<(String, String)> {
    for _ in 0..600 {
        let row = process_row(pid);
        if !is_live(row.as_ref()) {
            return row;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    process_row(pid)
}

fn sentinel_binary() -> PathBuf {
    let mut path = std::env::current_exe().expect("test binary path");
    path.pop();
    if path.file_name().is_some_and(|name| name == "deps") {
        path.pop();
    }
    path.join(tunnel_deadman::SENTINEL_BIN)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_is_started_as_the_leader_of_its_own_process_group() {
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let child = spawn(&sleeper(workspace.path()), &counters).expect("started");
    let pid = child.pid();

    let (pgid, state) = process_row(pid).expect("it is in the process table");
    assert!(!state.starts_with('Z'), "alive, not a corpse: {state}");
    assert_eq!(
        pgid,
        pid.to_string(),
        "the backend leads a process group of its own, so a group signal \
         aimed at it cannot reach the device's own group"
    );
    assert_eq!(counters.spawned.load(Ordering::Relaxed), 1);
    assert_eq!(counters.running.load(Ordering::Relaxed), 1);

    child.kill();
    child.wait_exited().await;
    assert!(!is_live(wait_not_alive(pid).await.as_ref()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dropping_the_handle_ends_the_backend() {
    // The safe direction: an unexpected drop kills the group rather than
    // leaking it. For a CUA backend the leak is a process that can type.
    //
    // **Wait for the supervisor, not for the process table.** `is_live` counts
    // a zombie as gone, and the drop path's first, pre-reap `kill_group` makes
    // the leader a zombie *before* the supervisor task reaps it and sends the
    // post-reap group signal that `group_kills` counts. Reading the counter as
    // soon as `ps` showed `Z` was a race the counter lost about one run in
    // twenty (`docs/tasks.md` M5-C18). The supervisor's own completion signal
    // is sent after every counter below has moved, so a clone of it is held
    // across the drop and waited on under a bound.
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let (pid, mut finished) = {
        let child = spawn(&sleeper(workspace.path()), &counters).expect("started");
        (child.pid(), child.exited.clone())
    };
    tokio::time::timeout(Duration::from_secs(10), finished.wait_for(|done| *done))
        .await
        .expect("the supervisor finished within the bound after the drop")
        .expect("the supervisor reported its end rather than vanishing");
    assert!(!is_live(wait_not_alive(pid).await.as_ref()));
    assert_eq!(
        counters.killed.load(Ordering::Relaxed),
        1,
        "the drop drove the end of life; the backend did not exit on its own"
    );
    assert_eq!(counters.group_kills.load(Ordering::Relaxed), 1);
    assert_eq!(
        counters.deadman_stood_down.load(Ordering::Relaxed),
        counters.deadman_armed.load(Ordering::Relaxed),
        "an armed sentinel stood down rather than fired, so it was not what \
         ended the backend"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_orderly_kill_stands_the_sentinel_down_rather_than_firing_it() {
    // Skipped rather than silently passing when the sentinel is not built:
    // a green result from an unarmed run would measure the absence of the
    // mechanism and report it as its presence.
    if !sentinel_binary().is_file() {
        eprintln!(
            "SKIPPED: no {} beside this test binary; run the workspace test \
             command rather than a bare -p run",
            tunnel_deadman::SENTINEL_BIN
        );
        return;
    }
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let child = spawn(&sleeper(workspace.path()), &counters).expect("started");
    let pid = child.pid();
    assert_eq!(
        counters.deadman_armed.load(Ordering::Relaxed),
        1,
        "a sentinel was armed; without one this test measures nothing"
    );

    child.kill();
    child.wait_exited().await;

    assert_eq!(
        counters.deadman_stood_down.load(Ordering::Relaxed),
        1,
        // Says only what it checks: the counter reads the sentinel's own exit
        // status, so this proves the sentinel stood down rather than fired.
        // It proves nothing about *when* it was asked; that ordering is held
        // by construction and is named as untested in M5-C08.
        "the sentinel exited stood-down rather than fired"
    );
    assert!(!is_live(wait_not_alive(pid).await.as_ref()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_cannot_be_started_is_counted_and_not_reported_as_running() {
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let missing = BackendProcess::new(
        workspace.path().join("no-such-backend"),
        Vec::new(),
        workspace.path().to_path_buf(),
        workspace.path().join("address"),
    )
    .expect("valid configuration, absent executable");
    assert!(spawn(&missing, &counters).is_err());
    assert_eq!(counters.spawn_failed.load(Ordering::Relaxed), 1);
    assert_eq!(counters.spawned.load(Ordering::Relaxed), 0);
    assert_eq!(counters.running.load(Ordering::Relaxed), 0);
    assert_eq!(
        counters.deadman_armed.load(Ordering::Relaxed),
        0,
        "nothing was armed for a process that never existed"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_backends_environment_is_cleared_before_anything_is_set() {
    // A CUA backend inherits no ambient credential, no `CONTAINER_NAME`, no
    // proxy setting. `docs/integrations.md` records that a local-mode
    // computer-server needs no authentication, which is exactly why nothing
    // resembling one may drift in.
    let workspace = tempfile::tempdir().expect("workspace");
    let counters = Arc::new(ChildCounters::default());
    let dump = workspace.path().join("env");
    let process = BackendProcess::new(
        PathBuf::from("/bin/sh"),
        vec!["-c".to_owned(), format!("env > {}", dump.display())],
        workspace.path().to_path_buf(),
        workspace.path().join("address"),
    )
    .expect("valid")
    .with_env("TUNNEL_CUA_SYNTHETIC", "1");

    let child = spawn(&process, &counters).expect("started");
    child.wait_exited().await;

    let text = std::fs::read_to_string(&dump).unwrap_or_default();
    let names: Vec<&str> = text
        .lines()
        .filter_map(|line| line.split('=').next())
        .collect();
    assert!(
        names.contains(&"TUNNEL_CUA_SYNTHETIC"),
        "the explicitly set name is present: {names:?}"
    );
    assert!(
        !names.contains(&"PATH"),
        "the environment was cleared, so an inherited PATH is absent: {names:?}"
    );
}
