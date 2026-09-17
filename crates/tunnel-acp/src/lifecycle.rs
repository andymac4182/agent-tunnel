//! The pure ACP connection and session lifecycle (task row M8-03's lifecycle
//! half).
//!
//! **Clock-free and socket-free.** Nothing here reads a clock, opens a socket
//! or spawns a process. Every deadline is an *observation supplied by the
//! caller*, exactly as `tunnel_http_forward::RecordDeadline` already does: the
//! owner of the real clock calls [`CallbackTable::observe`] with its own
//! monotonic reading, in whatever unit it chose, and this module decides. That
//! is what lets a test elapse a real 120 ms against a 60 ms bound and record
//! the measurement, instead of asserting that a constant equals itself.
//!
//! **What this module is not.** It is not HTTP, SSE, a tunnel, a relay or a
//! child process. It holds no bytes of a prompt and no credential. The
//! supervisor that owns a real child is `tunnel-acp-export`; the wire is
//! chunks 3 to 5.
//!
//! Every refusal carries a [`LifecycleRule`] so a test can assert *which rule*
//! refused, not merely that something errored.

use std::collections::BTreeMap;

/// Sessions per ACP connection (`docs/acp.md`, "Initial bounds").
pub const MAX_SESSIONS_PER_CONNECTION: usize = 8;
/// Pending host requests, and separately agent callbacks, per connection.
pub const MAX_PENDING_PER_DIRECTION: usize = 16;

/// Which way a JSON-RPC request travels.
///
/// It is part of the correlation scope because ACP runs requests in both
/// directions at once: a host `session/prompt` and an agent
/// `session/request_permission` may legitimately carry the same `id`.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Direction {
    /// The host asked the agent (`initialize`, `session/new`, `session/prompt`).
    HostToAgent,
    /// The agent asked the host (`session/request_permission`).
    AgentToHost,
}

/// A JSON-RPC id, keeping its JSON type.
///
/// `Text("1")` and `Number(1)` are **different ids**. Conflating them would let
/// an agent's numeric callback resolve a host's string request.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum RequestId {
    Text(String),
    Number(i64),
}

impl RequestId {
    #[must_use]
    pub fn text(value: &str) -> Self {
        Self::Text(value.to_owned())
    }
}

/// The full correlation scope of a JSON-RPC id:
/// `(tenant, principal, device, service, connection, direction)`.
///
/// Two ACP connections, two tenants or two directions may use the same id
/// concurrently; the same id twice inside one scope is a conflict.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct IdScope {
    pub tenant: String,
    pub principal: String,
    pub device: String,
    pub service: String,
    pub connection: String,
    pub direction: Direction,
}

impl IdScope {
    /// Build a scope from borrowed identifiers.
    #[must_use]
    pub fn new(
        tenant: &str,
        principal: &str,
        device: &str,
        service: &str,
        connection: &str,
        direction: Direction,
    ) -> Self {
        Self {
            tenant: tenant.to_owned(),
            principal: principal.to_owned(),
            device: device.to_owned(),
            service: service.to_owned(),
            connection: connection.to_owned(),
            direction,
        }
    }

    /// The same scope in the other direction.
    #[must_use]
    pub fn reversed(&self) -> Self {
        let mut other = self.clone();
        other.direction = match self.direction {
            Direction::HostToAgent => Direction::AgentToHost,
            Direction::AgentToHost => Direction::HostToAgent,
        };
        other
    }
}

/// The rule that refused an operation.
///
/// A test asserts the rule, not the fact that an error occurred: "refused"
/// means refused *for the stated reason*.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifecycleRule {
    /// A ninth session on one connection.
    SessionLimit,
    /// A seventeenth outstanding request in one direction.
    PendingLimit,
    /// The same id is already outstanding in this scope. Raised **before
    /// dispatch**, so nothing was sent twice.
    DuplicatePendingId,
    /// No such outstanding request: never registered, or already resolved.
    /// A duplicate or late response lands here.
    UnknownRequestId,
    /// A response whose shape does not match what was outstanding (a
    /// permission answer to a prompt, say).
    CallbackKindMismatch,
    /// A permission response naming an `optionId` the agent did not offer.
    ///
    /// `docs/acp.md`: "Validate the response against the outstanding callback,
    /// principal, session, direction, and **offered option**."  A host that
    /// answers with an option nobody offered has not answered the question
    /// that was asked, and letting it through would let a host invent
    /// decisions the agent has no branch for.
    OptionNotOffered,
    /// A second session with an identifier already in use.
    DuplicateSession,
    /// No such session on this connection.
    UnknownSession,
    /// A prompt while one is already active on that session.
    PromptAlreadyActive,
    /// A prompt before the session's subscriber is ready, or after it closed.
    SessionNotReady,
    /// An operation that the child lifecycle's current state forbids.
    LifecycleTransition,
    /// The connection is not `Ready`: admission has stopped.
    ConnectionNotReady,
}

impl LifecycleRule {
    /// A stable, payload-free code for diagnostics and for tests to assert.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::SessionLimit => "ACP_SESSION_LIMIT",
            Self::PendingLimit => "ACP_PENDING_LIMIT",
            Self::DuplicatePendingId => "ACP_DUPLICATE_PENDING_ID",
            Self::UnknownRequestId => "ACP_UNKNOWN_REQUEST_ID",
            Self::CallbackKindMismatch => "ACP_CALLBACK_KIND_MISMATCH",
            Self::OptionNotOffered => "ACP_OPTION_NOT_OFFERED",
            Self::DuplicateSession => "ACP_DUPLICATE_SESSION",
            Self::UnknownSession => "ACP_UNKNOWN_SESSION",
            Self::PromptAlreadyActive => "ACP_PROMPT_ALREADY_ACTIVE",
            Self::SessionNotReady => "ACP_SESSION_NOT_READY",
            Self::LifecycleTransition => "ACP_LIFECYCLE_TRANSITION",
            Self::ConnectionNotReady => "ACP_CONNECTION_NOT_READY",
        }
    }
}

/// A refusal. Carries the rule and a fixed explanation — never a payload, an
/// identifier value or a credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LifecycleRejection {
    pub rule: LifecycleRule,
    pub detail: &'static str,
}

impl LifecycleRejection {
    #[must_use]
    pub const fn new(rule: LifecycleRule, detail: &'static str) -> Self {
        Self { rule, detail }
    }

    #[must_use]
    pub const fn code(&self) -> &'static str {
        self.rule.code()
    }
}

impl core::fmt::Display for LifecycleRejection {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(formatter, "{}: {}", self.rule.code(), self.detail)
    }
}

impl std::error::Error for LifecycleRejection {}

// ------------------------------------------------------------ child lifecycle

/// The supervised child's lifecycle, as `docs/acp.md` names it.
///
/// This is a *transition table*, not a label a supervisor sets by hand: a
/// test that drives `advance` is driving the state machine's own decision.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ChildLifecycle {
    /// Spawned; `initialize` has not completed.
    Starting,
    /// Initialized; admission is open.
    Ready,
    /// Admission has stopped; outstanding work is being resolved.
    Draining,
    /// Admission had already stopped when the process was reaped.
    ///
    /// This records **who ended the child** — the supervisor, deliberately,
    /// having drained first — not *how the process died*. There is no graceful
    /// stdin close or grace period behind it; `docs/acp.md`'s bounded grace
    /// period is not implemented. Do not read `Stopped` as "exited cleanly".
    Stopped,
    /// The process is gone after startup failure, a protocol violation or a
    /// crash.
    Failed,
}

impl ChildLifecycle {
    /// Whether this state admits new work.
    #[must_use]
    pub const fn admits(self) -> bool {
        matches!(self, Self::Ready)
    }

    /// Whether the process is gone for good.
    #[must_use]
    pub const fn is_terminal(self) -> bool {
        matches!(self, Self::Stopped | Self::Failed)
    }

    /// Apply one lifecycle event.
    ///
    /// # Errors
    /// [`LifecycleRule::LifecycleTransition`] when the event is not legal in
    /// this state. In particular no event leaves a terminal state, and
    /// `Stopped` is reachable only through `Draining`: a process that vanished
    /// while it was still admitting work `Failed`.
    pub const fn advance(self, event: LifecycleEvent) -> Result<Self, LifecycleRejection> {
        let refused = LifecycleRejection::new(
            LifecycleRule::LifecycleTransition,
            "the lifecycle does not allow this event in this state",
        );
        match (self, event) {
            (Self::Starting, LifecycleEvent::Initialized) => Ok(Self::Ready),
            (Self::Starting | Self::Ready, LifecycleEvent::DrainRequested) => Ok(Self::Draining),
            (Self::Draining, LifecycleEvent::Reaped) => Ok(Self::Stopped),
            (Self::Starting | Self::Ready | Self::Draining, LifecycleEvent::Failed) => {
                Ok(Self::Failed)
            }
            // A child that disappeared while still admitting work did not stop
            // in an orderly way, whatever the exit status said.
            (Self::Starting | Self::Ready, LifecycleEvent::Reaped) => Ok(Self::Failed),
            _ => Err(refused),
        }
    }
}

/// What happened to the child.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum LifecycleEvent {
    /// `initialize` completed and was accepted.
    Initialized,
    /// Shutdown, revocation, deadline expiry or subscriber loss.
    DrainRequested,
    /// The process was waited on.
    Reaped,
    /// Startup failure, a protocol violation on stdout, or a crash.
    Failed,
}

// ------------------------------------------------------------ callback table

/// What an outstanding request is waiting for.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PendingKind {
    /// A host `session/prompt` awaiting its `stopReason`.
    Prompt,
    /// An agent `session/request_permission` awaiting the host's choice. This
    /// is the only kind with a deadline.
    Permission,
    /// Any other correlated request (`initialize`, `session/new`,
    /// `session/load`).
    Call,
}

/// How an outstanding request ended.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Outcome {
    /// A prompt or call completed. The string is the payload-free terminal
    /// label (a `stopReason`, or `ok`), never the result body.
    Completed(String),
    /// A permission decision.
    Permission(PermissionOutcome),
    /// A JSON-RPC error, by its sanitized code.
    Failed(String),
}

/// The host's answer to a permission request.
///
/// There is deliberately no `Approved` variant reachable from a timeout: see
/// [`CallbackTable::observe`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PermissionOutcome {
    /// The host chose an offered option, by its `optionId`.
    Selected(String),
    /// Cancelled: by `session/cancel`, by connection loss, or by the deadline.
    Cancelled,
}

/// One outstanding request.
#[derive(Clone, Debug, Eq, PartialEq)]
struct Pending {
    kind: PendingKind,
    session: Option<String>,
    registered_at: u64,
    /// The `optionId`s the agent offered, for a [`PendingKind::Permission`].
    ///
    /// `None` means they were **not recorded**, and no option check is then
    /// possible.  Every production path registers a permission through
    /// [`CallbackTable::register_permission`], which always records them; the
    /// plain [`CallbackTable::register`] leaves this `None` and is used for
    /// prompts and calls, which have no options.  `Some(list)` is checked on
    /// resolution, and an empty list admits no selection at all.
    offered: Option<Vec<String>>,
    /// Only a [`PendingKind::Permission`] carries one.
    deadline: Option<u64>,
}

/// A resolved decision, handed to the caller exactly once.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Resolution {
    pub scope: IdScope,
    pub id: RequestId,
    pub kind: PendingKind,
    pub session: Option<String>,
    pub outcome: Outcome,
    /// Caller-clock time from registration to resolution, in the caller's own
    /// unit.
    pub elapsed: u64,
}

/// A permission the caller's clock says has run out of time.
///
/// Its `outcome` is [`PermissionOutcome::Cancelled`] and there is no
/// constructor that makes it anything else.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredPermission {
    pub scope: IdScope,
    pub id: RequestId,
    pub session: Option<String>,
    /// The measured caller-clock time the permission was outstanding.
    pub elapsed: u64,
    /// The configured bound it exceeded. `elapsed > bound` always holds.
    pub bound: u64,
    pub outcome: PermissionOutcome,
}

/// The bounded per-connection callback table.
///
/// One table may hold several scopes at once — that is how identical ids under
/// two tenants, two connections or two directions are shown to coexist — and
/// the pending bound is applied **per scope**, which is per connection and
/// direction.
#[derive(Clone, Debug)]
pub struct CallbackTable {
    limit: usize,
    pending: BTreeMap<(IdScope, RequestId), Pending>,
    resolutions: u64,
    expirations: u64,
}

impl Default for CallbackTable {
    fn default() -> Self {
        Self::new(MAX_PENDING_PER_DIRECTION)
    }
}

impl CallbackTable {
    #[must_use]
    pub const fn new(limit: usize) -> Self {
        Self {
            limit,
            pending: BTreeMap::new(),
            resolutions: 0,
            expirations: 0,
        }
    }

    /// How many requests are outstanding in one scope.
    #[must_use]
    pub fn pending_in(&self, scope: &IdScope) -> usize {
        self.pending.keys().filter(|(key, _)| key == scope).count()
    }

    /// How many decisions this table has handed out. A duplicate or late
    /// response must not move it.
    #[must_use]
    pub const fn resolutions(&self) -> u64 {
        self.resolutions
    }

    /// How many permissions this table has cancelled on a deadline.
    #[must_use]
    pub const fn expirations(&self) -> u64 {
        self.expirations
    }

    /// Register an outstanding request **before it is dispatched**.
    ///
    /// `now` is the caller's clock. `timeout` is the permission bound in the
    /// same unit, and is ignored for every other kind.
    ///
    /// # Errors
    /// [`LifecycleRule::DuplicatePendingId`] when that id is already
    /// outstanding in that scope — raised before dispatch, so the duplicate is
    /// never sent. [`LifecycleRule::PendingLimit`] at one beyond the bound.
    pub fn register(
        &mut self,
        scope: &IdScope,
        id: RequestId,
        kind: PendingKind,
        session: Option<&str>,
        now: u64,
        timeout: u64,
    ) -> Result<(), LifecycleRejection> {
        let key = (scope.clone(), id);
        if self.pending.contains_key(&key) {
            return Err(LifecycleRejection::new(
                LifecycleRule::DuplicatePendingId,
                "that request id is already outstanding in this scope",
            ));
        }
        if self.pending_in(scope) >= self.limit {
            return Err(LifecycleRejection::new(
                LifecycleRule::PendingLimit,
                "too many outstanding requests in this direction",
            ));
        }
        let deadline = match kind {
            PendingKind::Permission => Some(now.saturating_add(timeout)),
            PendingKind::Prompt | PendingKind::Call => None,
        };
        self.pending.insert(
            key,
            Pending {
                kind,
                session: session.map(ToOwned::to_owned),
                registered_at: now,
                offered: None,
                deadline,
            },
        );
        Ok(())
    }

    /// Register an agent `session/request_permission`, recording the options
    /// it offered so the host's answer can be checked against them.
    ///
    /// This is the only way a permission should be registered: the plain
    /// [`CallbackTable::register`] records no options, and a permission
    /// registered through it can never have its `optionId` validated.
    ///
    /// # Errors
    /// As [`CallbackTable::register`].
    pub fn register_permission(
        &mut self,
        scope: &IdScope,
        id: RequestId,
        session: Option<&str>,
        now: u64,
        timeout: u64,
        offered: Vec<String>,
    ) -> Result<(), LifecycleRejection> {
        self.register(
            scope,
            id.clone(),
            PendingKind::Permission,
            session,
            now,
            timeout,
        )?;
        if let Some(entry) = self.pending.get_mut(&(scope.clone(), id)) {
            entry.offered = Some(offered);
        }
        Ok(())
    }

    /// Resolve an outstanding request. The **first** valid response wins; the
    /// entry is removed atomically, so a duplicate or late response finds
    /// nothing and cannot repeat the decision.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownRequestId`] when nothing is outstanding under
    /// that scope and id — which is what a duplicate, a late and a forged
    /// response all look like. [`LifecycleRule::CallbackKindMismatch`] when
    /// the outcome does not match the kind that was outstanding.
    pub fn resolve(
        &mut self,
        scope: &IdScope,
        id: &RequestId,
        outcome: Outcome,
        now: u64,
    ) -> Result<Resolution, LifecycleRejection> {
        let key = (scope.clone(), id.clone());
        let Some(entry) = self.pending.get(&key) else {
            return Err(LifecycleRejection::new(
                LifecycleRule::UnknownRequestId,
                "no request is outstanding under that scope and id",
            ));
        };
        let matches = match (entry.kind, &outcome) {
            (PendingKind::Permission, Outcome::Permission(_))
            | (PendingKind::Prompt | PendingKind::Call, Outcome::Completed(_))
            | (_, Outcome::Failed(_)) => true,
            (PendingKind::Permission, _) | (PendingKind::Prompt | PendingKind::Call, _) => false,
        };
        if !matches {
            return Err(LifecycleRejection::new(
                LifecycleRule::CallbackKindMismatch,
                "that response does not answer the kind of request outstanding",
            ));
        }
        // `docs/acp.md`: validate the response against the **offered option**.
        // The entry is still in the table at this point, so a refusal here
        // leaves the callback outstanding and the genuine answer can still
        // arrive -- which is the whole point: an invented option must not
        // consume the decision.
        if let Outcome::Permission(PermissionOutcome::Selected(option)) = &outcome
            && let Some(offered) = entry.offered.as_ref()
            && !offered.iter().any(|candidate| candidate == option)
        {
            return Err(LifecycleRejection::new(
                LifecycleRule::OptionNotOffered,
                "that optionId was not offered by the request it answers",
            ));
        }
        // Remove before returning: the decision leaves this table once.
        let entry = self.pending.remove(&key).unwrap_or_else(|| unreachable!());
        self.resolutions = self.resolutions.saturating_add(1);
        Ok(Resolution {
            scope: scope.clone(),
            id: id.clone(),
            kind: entry.kind,
            session: entry.session,
            outcome,
            elapsed: now.saturating_sub(entry.registered_at),
        })
    }

    /// Observe the caller's clock and cancel every permission whose measured
    /// elapsed time has **exceeded** its bound.
    ///
    /// The returned outcome is [`PermissionOutcome::Cancelled`]. There is no
    /// branch of this function that produces
    /// [`PermissionOutcome::Selected`]: a timeout is never an approval, and a
    /// host that never answered has not consented to anything. Only a
    /// permission expires; a prompt's wall-time bound is the supervisor's, and
    /// ending it is a cancellation of the turn, not of a callback.
    ///
    /// A non-monotonic caller clock counts as no elapsed time, as
    /// `RecordDeadline` does.
    pub fn observe(&mut self, now: u64) -> Vec<ExpiredPermission> {
        let expired: Vec<(IdScope, RequestId)> = self
            .pending
            .iter()
            .filter(|(_, entry)| {
                // The kind check is **deliberately redundant** with `register`
                // only ever giving a permission a deadline. "Only a permission
                // expires here" is the rule, and it is worth stating on both
                // sides: a later kind that acquires a deadline for some other
                // purpose must not silently start being cancelled as though a
                // host had failed to answer it. The guard-deletion case
                // defeats both halves together for that reason.
                entry.kind == PendingKind::Permission
                    && entry.deadline.is_some_and(|deadline| now > deadline)
            })
            .map(|((scope, id), _)| (scope.clone(), id.clone()))
            .collect();
        let mut out = Vec::with_capacity(expired.len());
        for key in expired {
            let Some(entry) = self.pending.remove(&key) else {
                continue;
            };
            let elapsed = now.saturating_sub(entry.registered_at);
            let bound = entry
                .deadline
                .unwrap_or(entry.registered_at)
                .saturating_sub(entry.registered_at);
            self.expirations = self.expirations.saturating_add(1);
            self.resolutions = self.resolutions.saturating_add(1);
            out.push(ExpiredPermission {
                scope: key.0,
                id: key.1,
                session: entry.session,
                elapsed,
                bound,
                outcome: PermissionOutcome::Cancelled,
            });
        }
        out
    }

    /// Cancel every permission outstanding in one session, as `session/cancel`
    /// and connection loss both require.
    pub fn cancel_session_permissions(
        &mut self,
        session: &str,
        now: u64,
    ) -> Vec<(IdScope, RequestId)> {
        let keys: Vec<(IdScope, RequestId)> = self
            .pending
            .iter()
            .filter(|(_, entry)| {
                entry.kind == PendingKind::Permission && entry.session.as_deref() == Some(session)
            })
            .map(|(key, _)| key.clone())
            .collect();
        for key in &keys {
            let _ = self.resolve(
                &key.0,
                &key.1,
                Outcome::Permission(PermissionOutcome::Cancelled),
                now,
            );
        }
        keys
    }
}

// ----------------------------------------------------------------- sessions

/// Where one ACP session is in its life.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum SessionPhase {
    /// Created; its scoped subscriber has not arrived. Prompts are refused.
    AwaitingSubscriber,
    /// Subscribed and idle.
    Ready,
    /// One prompt is active.
    Prompting,
    /// Ended.
    Closed,
}

#[derive(Clone, Debug)]
struct Session {
    phase: SessionPhase,
    created_at: u64,
}

/// One ACP transport connection: its child lifecycle and its bounded sessions.
#[derive(Clone, Debug)]
pub struct AcpConnection {
    lifecycle: ChildLifecycle,
    sessions: BTreeMap<String, Session>,
    session_limit: usize,
}

impl Default for AcpConnection {
    fn default() -> Self {
        Self::new(MAX_SESSIONS_PER_CONNECTION)
    }
}

impl AcpConnection {
    #[must_use]
    pub const fn new(session_limit: usize) -> Self {
        Self {
            lifecycle: ChildLifecycle::Starting,
            sessions: BTreeMap::new(),
            session_limit,
        }
    }

    #[must_use]
    pub const fn lifecycle(&self) -> ChildLifecycle {
        self.lifecycle
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    #[must_use]
    pub fn phase(&self, session: &str) -> Option<SessionPhase> {
        self.sessions.get(session).map(|entry| entry.phase)
    }

    /// Drive the child lifecycle.
    ///
    /// # Errors
    /// [`LifecycleRule::LifecycleTransition`] for an illegal transition.
    pub fn advance(&mut self, event: LifecycleEvent) -> Result<ChildLifecycle, LifecycleRejection> {
        self.lifecycle = self.lifecycle.advance(event)?;
        if self.lifecycle.is_terminal() || self.lifecycle == ChildLifecycle::Draining {
            for session in self.sessions.values_mut() {
                session.phase = SessionPhase::Closed;
            }
        }
        Ok(self.lifecycle)
    }

    /// Open a session.
    ///
    /// # Errors
    /// [`LifecycleRule::ConnectionNotReady`] before `initialize` or after
    /// draining began; [`LifecycleRule::DuplicateSession`]; and
    /// [`LifecycleRule::SessionLimit`] at one session beyond the bound.
    pub fn open_session(&mut self, id: &str, now: u64) -> Result<(), LifecycleRejection> {
        if !self.lifecycle.admits() {
            return Err(LifecycleRejection::new(
                LifecycleRule::ConnectionNotReady,
                "the connection is not admitting new sessions",
            ));
        }
        if self.sessions.contains_key(id) {
            return Err(LifecycleRejection::new(
                LifecycleRule::DuplicateSession,
                "a session with that identifier already exists",
            ));
        }
        if self.sessions.len() >= self.session_limit {
            return Err(LifecycleRejection::new(
                LifecycleRule::SessionLimit,
                "too many sessions on this connection",
            ));
        }
        self.sessions.insert(
            id.to_owned(),
            Session {
                phase: SessionPhase::AwaitingSubscriber,
                created_at: now,
            },
        );
        Ok(())
    }

    /// The session's scoped subscriber arrived.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownSession`], or
    /// [`LifecycleRule::SessionNotReady`] once the session has closed.
    pub fn subscriber_ready(&mut self, id: &str) -> Result<(), LifecycleRejection> {
        let session = self.session_mut(id)?;
        if session.phase == SessionPhase::Closed {
            return Err(LifecycleRejection::new(
                LifecycleRule::SessionNotReady,
                "the session is closed",
            ));
        }
        if session.phase == SessionPhase::AwaitingSubscriber {
            session.phase = SessionPhase::Ready;
        }
        Ok(())
    }

    /// How long a session has waited for its subscriber, on the caller's
    /// clock. `None` once it has one.
    #[must_use]
    pub fn subscriber_wait(&self, id: &str, now: u64) -> Option<u64> {
        let session = self.sessions.get(id)?;
        (session.phase == SessionPhase::AwaitingSubscriber)
            .then(|| now.saturating_sub(session.created_at))
    }

    /// Begin the session's one active prompt.
    ///
    /// # Errors
    /// [`LifecycleRule::ConnectionNotReady`] when admission has stopped;
    /// [`LifecycleRule::UnknownSession`];
    /// [`LifecycleRule::SessionNotReady`] before the subscriber arrives or
    /// after the session closes; [`LifecycleRule::PromptAlreadyActive`] for a
    /// second concurrent prompt.
    pub fn begin_prompt(&mut self, id: &str) -> Result<(), LifecycleRejection> {
        if !self.lifecycle.admits() {
            return Err(LifecycleRejection::new(
                LifecycleRule::ConnectionNotReady,
                "the connection is not admitting prompts",
            ));
        }
        let session = self.session_mut(id)?;
        match session.phase {
            SessionPhase::Ready => {
                session.phase = SessionPhase::Prompting;
                Ok(())
            }
            SessionPhase::Prompting => Err(LifecycleRejection::new(
                LifecycleRule::PromptAlreadyActive,
                "this session already has an active prompt",
            )),
            SessionPhase::AwaitingSubscriber | SessionPhase::Closed => {
                Err(LifecycleRejection::new(
                    LifecycleRule::SessionNotReady,
                    "the session has no subscriber, or has closed",
                ))
            }
        }
    }

    /// End the active prompt, whatever its `stopReason` was.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownSession`], or
    /// [`LifecycleRule::SessionNotReady`] when no prompt is active.
    pub fn end_prompt(&mut self, id: &str) -> Result<(), LifecycleRejection> {
        let session = self.session_mut(id)?;
        if session.phase != SessionPhase::Prompting {
            return Err(LifecycleRejection::new(
                LifecycleRule::SessionNotReady,
                "no prompt is active on this session",
            ));
        }
        session.phase = SessionPhase::Ready;
        Ok(())
    }

    /// Close one session.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownSession`].
    pub fn close_session(&mut self, id: &str) -> Result<(), LifecycleRejection> {
        self.session_mut(id)?.phase = SessionPhase::Closed;
        Ok(())
    }

    fn session_mut(&mut self, id: &str) -> Result<&mut Session, LifecycleRejection> {
        self.sessions.get_mut(id).ok_or(LifecycleRejection::new(
            LifecycleRule::UnknownSession,
            "no such session on this connection",
        ))
    }
}

#[cfg(test)]
#[path = "lifecycle_tests.rs"]
mod tests;
