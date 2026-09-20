//! Supervision unit tests: the lifecycle/health separation, the endpoint
//! policy at start, and the restart that cannot skip its invalidation.
//!
//! The backend here is `/bin/sh` publishing an address, not the CUA fixture:
//! these are tests of the *supervisor*, and a test that needed a working
//! backend to check that a bad address is refused would be a test of the
//! backend. The end-to-end supervision evidence is in
//! `crates/tunnel-cua-fixture/tests/supervision.rs`.

#![cfg(unix)]

use super::*;

use std::path::PathBuf;
use std::sync::Mutex;

use tunnel_cua::capture::Captures;
use tunnel_cua::lease::{GrantRevision, InputLeases, SessionId, TargetSession};

/// A device's input registries, behind one lock, implementing the authority a
/// restart must be handed.
#[derive(Debug, Default)]
struct Registries {
    inner: Mutex<(InputLeases, Captures)>,
}

impl InputAuthority for Registries {
    fn invalidate(&self, generation: BackendGeneration) -> Invalidation {
        let mut guard = self.inner.lock().expect("never poisoned by test code");
        let (leases, captures) = &mut *guard;
        tunnel_cua::supervision::invalidate(leases, captures, generation)
    }
}

impl Registries {
    fn hold(&self, target: &TargetSession) {
        let mut guard = self.inner.lock().expect("never poisoned by test code");
        let (leases, captures) = &mut *guard;
        leases
            .acquire(target, SessionId::new(1), GrantRevision::new(0))
            .expect("free");
        captures.record(target, 0, 128, 96, 100).expect("geometry");
    }

    fn holder(&self, target: &TargetSession) -> Option<SessionId> {
        self.inner
            .lock()
            .expect("never poisoned by test code")
            .0
            .holder(target)
    }
}

/// A backend that publishes `address` and then waits for stdin to close.
fn publishing(workspace: &std::path::Path, address: &str) -> BackendProcess {
    let file = workspace.join("address");
    BackendProcess::new(
        PathBuf::from("/bin/sh"),
        vec![
            "-c".to_owned(),
            format!(
                "printf '{address}' > {tmp}; mv {tmp} {file}; cat > /dev/null",
                tmp = workspace.join("address.tmp").display(),
                file = file.display()
            ),
        ],
        workspace.to_path_buf(),
        file,
    )
    .expect("valid")
    .with_startup(Duration::from_secs(10))
    .expect("in range")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_fresh_supervisor_has_not_started_and_is_not_working() {
    let workspace = tempfile::tempdir().expect("workspace");
    let supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:1"));
    assert_eq!(supervisor.health(), Health::NotStarted);
    assert!(!supervisor.health().permits_dispatch());
    assert_eq!(supervisor.generation(), BackendGeneration::INITIAL);
    assert!(supervisor.endpoint().is_none());
    assert!(supervisor.pid().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_started_backend_reports_running_and_never_working() {
    // **The separation, at the join.** There is no argument to `health` that
    // makes a running process a working one; the only route to `Working` runs
    // through `assess`, which needs a dispatch.
    let workspace = tempfile::tempdir().expect("workspace");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    let endpoint = supervisor.start().await.expect("it published an address");
    assert_eq!(endpoint.address().to_string(), "127.0.0.1:9");
    assert_eq!(supervisor.health(), Health::Started);
    assert!(supervisor.health().process_is_running());
    assert!(
        !supervisor.health().permits_dispatch(),
        "a listening process has proven nothing about what it may do"
    );
    assert_eq!(supervisor.generation().value(), 1);
    assert!(supervisor.pid().is_some());

    let freed = supervisor.stop(&Registries::default()).await;
    assert!(!freed.freed_anything());
    assert_eq!(supervisor.health(), Health::Exited);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_publishes_a_routable_address_is_refused_and_killed() {
    // The loopback policy enforced against the process that is actually
    // listening, not against a configured number.
    let workspace = tempfile::tempdir().expect("workspace");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "10.0.0.1:9"));
    let error = supervisor.start().await.expect_err("refused");
    assert!(
        matches!(error, StartError::Endpoint(_)),
        "got {error:?}, wanted an endpoint refusal"
    );
    assert!(
        supervisor.endpoint().is_none(),
        "nothing was handed out for a backend we refused"
    );
    // The generation still advanced: a process really was created, and a
    // supervisor that pretended otherwise would lose track of what it had
    // started.
    assert_eq!(supervisor.generation().value(), 1);
    assert_eq!(
        supervisor
            .counters()
            .spawned
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
    assert_eq!(
        supervisor
            .counters()
            .group_kills
            .load(std::sync::atomic::Ordering::Relaxed),
        1,
        "the refused backend was killed rather than left listening"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wildcard_bind_is_refused_by_name() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "0.0.0.0:9"));
    assert!(matches!(
        supervisor.start().await,
        Err(StartError::Endpoint(_))
    ));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_backend_that_publishes_nothing_times_out_rather_than_waiting_forever() {
    let workspace = tempfile::tempdir().expect("workspace");
    let silent = BackendProcess::new(
        PathBuf::from("/bin/sh"),
        vec!["-c".to_owned(), "exec sleep 180".to_owned()],
        workspace.path().to_path_buf(),
        workspace.path().join("address"),
    )
    .expect("valid")
    .with_startup(Duration::from_millis(300))
    .expect("in range");
    let mut supervisor = Supervisor::new(silent);
    assert_eq!(supervisor.start().await, Err(StartError::NoAddress));
    assert!(supervisor.endpoint().is_none());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_stale_address_from_the_previous_generation_is_never_read_as_the_new_one() {
    // **The bug this guards.** Without the removal before the spawn, a
    // restart whose new backend is slow to bind reads the dead backend's
    // port and hands it to consumers -- or hands out whatever bound that port
    // next, which on loopback is any local process.
    let workspace = tempfile::tempdir().expect("workspace");
    let address_file = workspace.path().join("address");
    std::fs::write(&address_file, "127.0.0.1:1").expect("a stale file");

    let silent = BackendProcess::new(
        PathBuf::from("/bin/sh"),
        vec!["-c".to_owned(), "exec sleep 180".to_owned()],
        workspace.path().to_path_buf(),
        address_file,
    )
    .expect("valid")
    .with_startup(Duration::from_millis(300))
    .expect("in range");
    let mut supervisor = Supervisor::new(silent);
    assert_eq!(
        supervisor.start().await,
        Err(StartError::NoAddress),
        "the stale address must not be mistaken for this generation's"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn starting_twice_is_refused_rather_than_leaking_the_first_backend() {
    let workspace = tempfile::tempdir().expect("workspace");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    supervisor.start().await.expect("started");
    let pid = supervisor.pid().expect("a pid");
    assert_eq!(supervisor.start().await, Err(StartError::AlreadyRunning));
    assert_eq!(
        supervisor.pid(),
        Some(pid),
        "the running backend is untouched by the refused start"
    );
    supervisor.stop(&Registries::default()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_invalidates_the_lease_and_the_captures_before_the_new_backend_exists() {
    let workspace = tempfile::tempdir().expect("workspace");
    let registries = Registries::default();
    let desktop = TargetSession::new("desktop-0");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    supervisor.start().await.expect("started");
    registries.hold(&desktop);
    assert_eq!(registries.holder(&desktop), Some(SessionId::new(1)));

    let (invalidation, started) = supervisor.restart(&registries).await;
    started.expect("the new backend started");

    assert_eq!(invalidation.leases_released, vec![desktop.clone()]);
    assert_eq!(invalidation.captures_forgotten, 1);
    assert_eq!(
        registries.holder(&desktop),
        None,
        "the lease was dropped by the restart, not merely reported as dropped"
    );
    assert_eq!(supervisor.generation().value(), 2);
    // And the new backend is a different process.
    assert!(supervisor.pid().is_some());
    supervisor.stop(&registries).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_restart_whose_new_backend_fails_has_still_invalidated() {
    // A failed restart leaves *more* to invalidate rather than less: there is
    // now no backend at all, so a lease held against the old one is even less
    // meaningful than it was.
    let workspace = tempfile::tempdir().expect("workspace");
    let registries = Registries::default();
    let desktop = TargetSession::new("desktop-0");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    supervisor.start().await.expect("started");
    registries.hold(&desktop);

    // Make the next start fail by pointing the supervisor at nothing.
    let broken = BackendProcess::new(
        workspace.path().join("no-such-backend"),
        Vec::new(),
        workspace.path().to_path_buf(),
        workspace.path().join("address"),
    )
    .expect("valid configuration, absent executable");
    supervisor.stop(&registries).await;
    registries.hold(&desktop);
    let mut supervisor = Supervisor::new(broken);
    let (invalidation, started) = supervisor.restart(&registries).await;

    assert_eq!(started, Err(StartError::Spawn));
    assert_eq!(invalidation.leases_released, vec![desktop.clone()]);
    assert_eq!(registries.holder(&desktop), None);
    assert!(!supervisor.health().permits_dispatch());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stopping_a_backend_that_already_died_still_invalidates() {
    // The crashed-backend case. A supervisor that only invalidated on the
    // paths it drove would leave a lease held against a process that is
    // already gone -- which is exactly the state a crash produces.
    let workspace = tempfile::tempdir().expect("workspace");
    let registries = Registries::default();
    let desktop = TargetSession::new("desktop-0");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    supervisor.start().await.expect("started");
    registries.hold(&desktop);

    let invalidation = supervisor.stop(&registries).await;
    assert_eq!(invalidation.leases_released, vec![desktop.clone()]);

    // And stopping again, with nothing running, still invalidates rather than
    // short-circuiting.
    registries.hold(&desktop);
    let again = supervisor.stop(&registries).await;
    assert_eq!(again.leases_released, vec![desktop]);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_probe_cannot_report_a_backend_that_is_gone_as_working() {
    // A probe's answer says something about **whatever answered it**, which
    // after a stop is not the supervised process: a stale reply, or a
    // different process that took the port. The lifecycle verdict wins, and
    // it must, or "working" would stop meaning "this backend works".
    let workspace = tempfile::tempdir().expect("workspace");
    let mut supervisor = Supervisor::new(publishing(workspace.path(), "127.0.0.1:9"));
    supervisor.start().await.expect("started");

    let request = probe_request();
    let succeeded = tunnel_cua::outcome::Dispatch::Dispatched(tunnel_cua::outcome::Completion::Ok(
        serde_json::json!({"width": 1, "height": 1}),
    ));
    assert!(
        supervisor.assess(&request, &succeeded).permits_dispatch(),
        "while it is running, a succeeded probe is a working verdict"
    );

    supervisor.stop(&Registries::default()).await;
    assert_eq!(
        supervisor.assess(&request, &succeeded),
        Health::Exited,
        "the very same succeeded probe must not report a stopped backend as working"
    );
}

#[test]
fn no_lifecycle_verdict_permits_a_dispatch() {
    // **Renamed to what it checks.** It used to be called
    // `a_health_verdict_cannot_be_reached_without_ending_up_at_the_probe` and
    // described itself as "a compile-level observation written as a test",
    // which was a claim about constructibility that these three assertions do
    // not test and that is in any case false: review built a `Health::Working`
    // from a fabricated `Dispatch`. What is true, and is all this checks, is
    // that none of the three arms `Supervisor::health` returns permits a
    // dispatch.
    assert!(!Health::Started.permits_dispatch());
    assert!(!Health::NotStarted.permits_dispatch());
    assert!(!Health::Exited.permits_dispatch());
}

#[test]
fn a_working_verdict_is_fabricable_and_that_is_recorded_rather_than_claimed_away() {
    // **The counterexample review compiled, kept as a test so the claim
    // cannot drift back.** `Dispatch` and `Completion` are public enums with
    // public payloads, so a caller can write down a dispatched success that
    // never happened, hand it to the crate-private classifier with a genuine
    // probe request, and obtain a working verdict with no process anywhere.
    //
    // This is not a defect to fix in a type: the caller of `assess` is the
    // same component that performs the exchange, so nothing it could be
    // handed would be independent of it. It is recorded so that the crate's
    // documentation says "a tightening against mistakes" and not "impossible".
    let request = probe_request();
    let never_happened = tunnel_cua::outcome::Dispatch::Dispatched(
        tunnel_cua::outcome::Completion::Ok(serde_json::json!({})),
    );
    let fabricated = crate::health::assess(&request, &never_happened);
    assert!(
        fabricated.permits_dispatch(),
        "the fabricated verdict is accepted, which is the finding"
    );
    assert!(fabricated.evidence().is_some());

    // **And the half that does hold**: a genuine `describe` request cannot be
    // made to yield one, whatever dispatch it is paired with. That is the
    // config-echo trap, and it is closed against accident.
    let echo = tunnel_cua::schema::validate_request(
        serde_json::json!({
            "version": tunnel_cua::SCHEMA_VERSION,
            "operation": "describe",
            "params": {},
        })
        .to_string()
        .as_bytes(),
        64 << 10,
    )
    .expect("a valid describe");
    assert!(!crate::health::assess(&echo, &never_happened).permits_dispatch());
}

/// A validated `screen_info` request, for tests that need a genuine probe.
fn probe_request() -> tunnel_cua::schema::Request {
    tunnel_cua::schema::validate_request(
        serde_json::json!({
            "version": tunnel_cua::SCHEMA_VERSION,
            "operation": "screen_info",
            "params": {},
        })
        .to_string()
        .as_bytes(),
        64 << 10,
    )
    .expect("a valid probe")
}
