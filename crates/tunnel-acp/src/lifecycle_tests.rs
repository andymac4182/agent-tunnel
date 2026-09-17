//! Lifecycle tests.
//!
//! Two rules these tests hold themselves to, because this project keeps
//! producing evidence that proves less than it claims:
//!
//! 1. **Assert the rule and its code**, never that "something errored". A
//!    duplicate id refused for being over the pending bound would otherwise
//!    read as a pass.
//! 2. **Drive the state machine's decision**, never a local constant. Every
//!    bound below is read from the module's own constant *and* reached by
//!    repeated real calls, so a bound that was never reached cannot pass.
//!
//! The permission deadline here is driven by a caller clock, which is what
//! this module takes. The *elapsed, wall-clock* observation of that same rule
//! — a real timeout measured against a real bound — is in
//! `tunnel-acp-export`'s `permission_deadline` test, because a deadline that
//! never elapses would pass a test like this one and prove nothing.

use super::*;

fn scope(connection: &str, direction: Direction) -> IdScope {
    IdScope::new(
        "tenant-a",
        "principal-a",
        "device-a",
        "service-a",
        connection,
        direction,
    )
}

fn ready_connection() -> AcpConnection {
    let mut connection = AcpConnection::default();
    connection
        .advance(LifecycleEvent::Initialized)
        .expect("initialize");
    connection
}

// ------------------------------------------------------------- id scoping

#[test]
fn identical_host_and_agent_ids_coexist() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    let agent = host.reversed();
    assert_eq!(agent.direction, Direction::AgentToHost);

    table
        .register(
            &host,
            RequestId::Number(7),
            PendingKind::Prompt,
            Some("session-1"),
            0,
            0,
        )
        .expect("the host's id 7");
    // The same id, the same tenant, principal, device, service and
    // connection -- only the direction differs.
    table
        .register(
            &agent,
            RequestId::Number(7),
            PendingKind::Permission,
            Some("session-1"),
            0,
            60,
        )
        .expect("the agent's id 7 is a different request");

    assert_eq!(table.pending_in(&host), 1);
    assert_eq!(table.pending_in(&agent), 1);

    // Answering the agent's permission must not resolve the host's prompt.
    let resolved = table
        .resolve(
            &agent,
            &RequestId::Number(7),
            Outcome::Permission(PermissionOutcome::Selected("permit-one".to_owned())),
            10,
        )
        .expect("the agent's callback resolves");
    assert_eq!(resolved.kind, PendingKind::Permission);
    assert_eq!(
        table.pending_in(&host),
        1,
        "the prompt is still outstanding"
    );
}

#[test]
fn a_string_id_and_a_number_id_are_not_the_same_request() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    table
        .register(&host, RequestId::Number(1), PendingKind::Call, None, 0, 0)
        .expect("number 1");
    table
        .register(&host, RequestId::text("1"), PendingKind::Call, None, 0, 0)
        .expect("string \"1\" is a different id, not a duplicate");
    assert_eq!(table.pending_in(&host), 2);

    // Resolving the string must leave the number outstanding.
    table
        .resolve(
            &host,
            &RequestId::text("1"),
            Outcome::Completed("ok".to_owned()),
            1,
        )
        .expect("the string id resolves");
    assert_eq!(table.pending_in(&host), 1);
    let refused = table
        .resolve(
            &host,
            &RequestId::text("1"),
            Outcome::Completed("ok".to_owned()),
            2,
        )
        .expect_err("the string id is gone");
    assert_eq!(refused.rule, LifecycleRule::UnknownRequestId);
}

#[test]
fn two_tenants_may_use_the_same_id_on_the_same_device_and_service() {
    let mut table = CallbackTable::default();
    let mut one = scope("connection-1", Direction::HostToAgent);
    one.tenant = "tenant-one".to_owned();
    let mut two = one.clone();
    two.tenant = "tenant-two".to_owned();

    table
        .register(
            &one,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            None,
            0,
            0,
        )
        .expect("tenant one");
    table
        .register(
            &two,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            None,
            0,
            0,
        )
        .expect("tenant two's identical id is a different request");
    assert_eq!(table.pending_in(&one), 1);
    assert_eq!(table.pending_in(&two), 1);
}

#[test]
fn a_duplicate_pending_id_conflicts_before_dispatch() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    table
        .register(
            &host,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            None,
            0,
            0,
        )
        .expect("first");
    let refused = table
        .register(
            &host,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            None,
            1,
            0,
        )
        .expect_err("second");
    assert_eq!(refused.rule, LifecycleRule::DuplicatePendingId);
    assert_eq!(refused.code(), "ACP_DUPLICATE_PENDING_ID");
    // Refused *before dispatch*: the table is unchanged, so nothing was
    // recorded that a second dispatch could later resolve.
    assert_eq!(table.pending_in(&host), 1);
}

#[test]
fn an_id_reused_after_completion_is_accepted() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    table
        .register(&host, RequestId::Number(5), PendingKind::Call, None, 0, 0)
        .expect("first use");
    table
        .resolve(
            &host,
            &RequestId::Number(5),
            Outcome::Completed("ok".to_owned()),
            1,
        )
        .expect("completed");
    // Legitimate ACP: ids need only be distinct while outstanding. This is
    // not cross-restart deduplication and is not treated as one.
    table
        .register(&host, RequestId::Number(5), PendingKind::Call, None, 2, 0)
        .expect("the same id is free again once it completed");
    assert_eq!(table.pending_in(&host), 1);
}

// --------------------------------------------------- resolve exactly once

#[test]
fn a_callback_resolves_exactly_once_and_a_late_response_cannot_repeat_it() {
    let mut table = CallbackTable::default();
    let agent = scope("connection-1", Direction::AgentToHost);
    table
        .register(
            &agent,
            RequestId::text("permission-1"),
            PendingKind::Permission,
            Some("session-1"),
            0,
            60,
        )
        .expect("register");

    let first = table
        .resolve(
            &agent,
            &RequestId::text("permission-1"),
            Outcome::Permission(PermissionOutcome::Selected("deny-one".to_owned())),
            5,
        )
        .expect("the first valid response wins");
    assert_eq!(
        first.outcome,
        Outcome::Permission(PermissionOutcome::Selected("deny-one".to_owned()))
    );
    assert_eq!(first.elapsed, 5);
    assert_eq!(table.resolutions(), 1);

    // A duplicate that would have *reversed* the decision.
    let duplicate = table
        .resolve(
            &agent,
            &RequestId::text("permission-1"),
            Outcome::Permission(PermissionOutcome::Selected("permit-one".to_owned())),
            6,
        )
        .expect_err("a duplicate cannot repeat the decision");
    assert_eq!(duplicate.rule, LifecycleRule::UnknownRequestId);
    assert_eq!(
        table.resolutions(),
        1,
        "exactly one decision left this table"
    );
}

#[test]
fn a_permission_answer_cannot_resolve_a_prompt() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    table
        .register(
            &host,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            Some("session-1"),
            0,
            0,
        )
        .expect("register");
    let refused = table
        .resolve(
            &host,
            &RequestId::text("prompt-1"),
            Outcome::Permission(PermissionOutcome::Selected("permit-one".to_owned())),
            1,
        )
        .expect_err("kind mismatch");
    assert_eq!(refused.rule, LifecycleRule::CallbackKindMismatch);
    assert_eq!(
        table.pending_in(&host),
        1,
        "the prompt is still outstanding"
    );
}

// ------------------------------------------------------------- the bounds

#[test]
fn the_pending_bound_is_exact_at_sixteen_per_direction() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    let agent = host.reversed();
    for index in 0..MAX_PENDING_PER_DIRECTION {
        table
            .register(
                &host,
                RequestId::Number(index as i64),
                PendingKind::Call,
                None,
                0,
                0,
            )
            .unwrap_or_else(|error| panic!("request {index} within the bound: {error}"));
    }
    assert_eq!(table.pending_in(&host), MAX_PENDING_PER_DIRECTION);
    assert_eq!(MAX_PENDING_PER_DIRECTION, 16, "docs/acp.md's bounds table");

    let refused = table
        .register(
            &host,
            RequestId::Number(MAX_PENDING_PER_DIRECTION as i64),
            PendingKind::Call,
            None,
            0,
            0,
        )
        .expect_err("one beyond the bound");
    assert_eq!(refused.rule, LifecycleRule::PendingLimit);

    // The bound is per direction: a full host table leaves the agent's empty.
    table
        .register(
            &agent,
            RequestId::Number(0),
            PendingKind::Permission,
            None,
            0,
            60,
        )
        .expect("the other direction has its own budget");

    // And it reopens when one completes, rather than being a one-way ratchet.
    table
        .resolve(
            &host,
            &RequestId::Number(0),
            Outcome::Completed("ok".to_owned()),
            1,
        )
        .expect("complete one");
    table
        .register(
            &host,
            RequestId::Number(MAX_PENDING_PER_DIRECTION as i64),
            PendingKind::Call,
            None,
            1,
            0,
        )
        .expect("the freed slot is usable");
}

#[test]
fn the_session_bound_is_exact_at_eight_per_connection() {
    let mut connection = ready_connection();
    for index in 0..MAX_SESSIONS_PER_CONNECTION {
        connection
            .open_session(&format!("session-{index}"), 0)
            .unwrap_or_else(|error| panic!("session {index} within the bound: {error}"));
    }
    assert_eq!(connection.session_count(), MAX_SESSIONS_PER_CONNECTION);
    assert_eq!(MAX_SESSIONS_PER_CONNECTION, 8, "docs/acp.md's bounds table");

    let refused = connection
        .open_session("session-8", 0)
        .expect_err("one beyond the bound");
    assert_eq!(refused.rule, LifecycleRule::SessionLimit);
    assert_eq!(refused.code(), "ACP_SESSION_LIMIT");
    assert_eq!(connection.session_count(), MAX_SESSIONS_PER_CONNECTION);
}

#[test]
fn a_duplicate_session_identifier_is_refused_for_being_a_duplicate() {
    let mut connection = ready_connection();
    connection.open_session("session-1", 0).expect("first");
    let refused = connection.open_session("session-1", 0).expect_err("second");
    // Not SessionLimit: the connection is nowhere near the bound.
    assert_eq!(refused.rule, LifecycleRule::DuplicateSession);
    assert_eq!(connection.session_count(), 1);
}

// ------------------------------------------------- one prompt per session

#[test]
fn one_active_prompt_per_session() {
    let mut connection = ready_connection();
    connection.open_session("session-1", 0).expect("session");
    connection
        .subscriber_ready("session-1")
        .expect("subscriber");
    connection.begin_prompt("session-1").expect("first prompt");
    assert_eq!(connection.phase("session-1"), Some(SessionPhase::Prompting));

    let refused = connection
        .begin_prompt("session-1")
        .expect_err("a second concurrent prompt");
    assert_eq!(refused.rule, LifecycleRule::PromptAlreadyActive);

    connection.end_prompt("session-1").expect("turn ended");
    assert_eq!(connection.phase("session-1"), Some(SessionPhase::Ready));
    connection
        .begin_prompt("session-1")
        .expect("the next turn may start");
}

#[test]
fn a_prompt_before_the_subscriber_is_refused_for_readiness_not_for_the_bound() {
    let mut connection = ready_connection();
    connection.open_session("session-1", 0).expect("session");
    assert_eq!(
        connection.phase("session-1"),
        Some(SessionPhase::AwaitingSubscriber)
    );
    let refused = connection
        .begin_prompt("session-1")
        .expect_err("no subscriber yet");
    assert_eq!(refused.rule, LifecycleRule::SessionNotReady);

    // The wait is a caller-clock measurement, not a clock read here.
    assert_eq!(
        connection.subscriber_wait("session-1", 10_000),
        Some(10_000)
    );
    connection
        .subscriber_ready("session-1")
        .expect("subscriber");
    assert_eq!(connection.subscriber_wait("session-1", 10_000), None);
}

#[test]
fn a_prompt_on_an_unknown_session_names_the_session_rule() {
    let mut connection = ready_connection();
    let refused = connection
        .begin_prompt("session-nope")
        .expect_err("unknown");
    assert_eq!(refused.rule, LifecycleRule::UnknownSession);
}

// ------------------------------------------------- the permission deadline

#[test]
fn a_permission_deadline_resolves_as_cancelled_never_approved() {
    let mut table = CallbackTable::default();
    let agent = scope("connection-1", Direction::AgentToHost);
    let bound = 60;
    table
        .register(
            &agent,
            RequestId::text("permission-1"),
            PendingKind::Permission,
            Some("session-1"),
            1_000,
            bound,
        )
        .expect("register");

    // Exactly at the bound is not yet over it.
    assert!(table.observe(1_060).is_empty());
    assert_eq!(table.pending_in(&agent), 1);

    let expired = table.observe(1_061);
    assert_eq!(expired.len(), 1);
    let expired = &expired[0];
    assert_eq!(expired.outcome, PermissionOutcome::Cancelled);
    assert!(
        expired.elapsed > expired.bound,
        "the measured elapsed {} must exceed the bound {}",
        expired.elapsed,
        expired.bound
    );
    assert_eq!(expired.bound, bound);
    assert_eq!(table.expirations(), 1);

    // The host's late "permit" cannot revive or reverse it.
    let late = table
        .resolve(
            &agent,
            &RequestId::text("permission-1"),
            Outcome::Permission(PermissionOutcome::Selected("permit-one".to_owned())),
            2_000,
        )
        .expect_err("a late approval after the deadline");
    assert_eq!(late.rule, LifecycleRule::UnknownRequestId);
}

#[test]
fn only_a_permission_expires_on_the_permission_deadline() {
    let mut table = CallbackTable::default();
    let host = scope("connection-1", Direction::HostToAgent);
    table
        .register(
            &host,
            RequestId::text("prompt-1"),
            PendingKind::Prompt,
            Some("session-1"),
            0,
            1,
        )
        .expect("register a prompt with a timeout argument");
    // A prompt has no permission deadline: its wall-time bound belongs to the
    // supervisor, and ending it cancels a turn, not a callback.
    assert!(table.observe(u64::MAX / 2).is_empty());
    assert_eq!(table.pending_in(&host), 1);
}

#[test]
fn a_non_monotonic_caller_clock_counts_as_no_elapsed_time() {
    let mut table = CallbackTable::default();
    let agent = scope("connection-1", Direction::AgentToHost);
    table
        .register(
            &agent,
            RequestId::text("permission-1"),
            PendingKind::Permission,
            None,
            5_000,
            60,
        )
        .expect("register");
    assert!(
        table.observe(10).is_empty(),
        "a clock that went backwards has not elapsed anything"
    );
}

#[test]
fn session_cancel_cancels_that_sessions_permissions_only() {
    let mut table = CallbackTable::default();
    let agent = scope("connection-1", Direction::AgentToHost);
    table
        .register(
            &agent,
            RequestId::text("permission-1"),
            PendingKind::Permission,
            Some("session-1"),
            0,
            60,
        )
        .expect("session 1");
    table
        .register(
            &agent,
            RequestId::text("permission-2"),
            PendingKind::Permission,
            Some("session-2"),
            0,
            60,
        )
        .expect("session 2");
    let cancelled = table.cancel_session_permissions("session-1", 1);
    assert_eq!(cancelled.len(), 1);
    assert_eq!(cancelled[0].1, RequestId::text("permission-1"));
    assert_eq!(table.pending_in(&agent), 1);
}

// ---------------------------------------------------------- the lifecycle

#[test]
fn the_child_lifecycle_is_a_transition_table_not_a_label() {
    let mut connection = AcpConnection::default();
    assert_eq!(connection.lifecycle(), ChildLifecycle::Starting);
    assert!(!connection.lifecycle().admits());

    // Starting cannot be reaped into Stopped: a child that vanished while it
    // was still starting did not stop in an orderly way.
    let vanished = ChildLifecycle::Starting
        .advance(LifecycleEvent::Reaped)
        .expect("a vanished child is a state, not an error");
    assert_eq!(vanished, ChildLifecycle::Failed);

    assert_eq!(
        connection
            .advance(LifecycleEvent::Initialized)
            .expect("initialize"),
        ChildLifecycle::Ready
    );
    assert!(connection.lifecycle().admits());
    assert_eq!(
        connection
            .advance(LifecycleEvent::DrainRequested)
            .expect("drain"),
        ChildLifecycle::Draining
    );
    assert!(!connection.lifecycle().admits());
    assert_eq!(
        connection.advance(LifecycleEvent::Reaped).expect("reaped"),
        ChildLifecycle::Stopped
    );
    assert!(connection.lifecycle().is_terminal());

    // Nothing leaves a terminal state.
    for event in [
        LifecycleEvent::Initialized,
        LifecycleEvent::DrainRequested,
        LifecycleEvent::Reaped,
        LifecycleEvent::Failed,
    ] {
        let refused = connection
            .advance(event)
            .expect_err("a terminal state is terminal");
        assert_eq!(refused.rule, LifecycleRule::LifecycleTransition);
    }
}

#[test]
fn initialize_twice_is_refused_by_the_transition_table() {
    let mut connection = ready_connection();
    let refused = connection
        .advance(LifecycleEvent::Initialized)
        .expect_err("a second initialize");
    assert_eq!(refused.rule, LifecycleRule::LifecycleTransition);
    assert_eq!(refused.code(), "ACP_LIFECYCLE_TRANSITION");
}

#[test]
fn draining_stops_admission_and_closes_every_session() {
    let mut connection = ready_connection();
    connection.open_session("session-1", 0).expect("session");
    connection
        .subscriber_ready("session-1")
        .expect("subscriber");
    connection
        .advance(LifecycleEvent::DrainRequested)
        .expect("drain");

    assert_eq!(connection.phase("session-1"), Some(SessionPhase::Closed));
    let refused = connection
        .open_session("session-2", 0)
        .expect_err("no new sessions while draining");
    assert_eq!(refused.rule, LifecycleRule::ConnectionNotReady);
    let refused = connection
        .begin_prompt("session-1")
        .expect_err("no new prompts while draining");
    assert_eq!(refused.rule, LifecycleRule::ConnectionNotReady);
}

#[test]
fn a_session_cannot_be_opened_before_initialize() {
    let mut connection = AcpConnection::default();
    let refused = connection
        .open_session("session-1", 0)
        .expect_err("before initialize");
    assert_eq!(refused.rule, LifecycleRule::ConnectionNotReady);
}
