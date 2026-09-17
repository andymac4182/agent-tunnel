//! One supervisor task per ACP transport connection.
//!
//! It owns the child, the clock and the bounded channels. Every **decision**
//! is `tunnel_acp::lifecycle`'s, which owns none of those: the supervisor
//! reads `Instant` and hands the reading to [`CallbackTable::observe`], the
//! way `tunnel-http-forward`'s `RecordDeadline` is driven. That is the only
//! clock in this path, and it is deliberately on this side of the boundary.
//!
//! **A separate reader.** The task that reads the child's stdout is not the
//! task that is waiting for a prompt's `stopReason`, so an agent callback is
//! handled while a prompt is pending. A prompt hands the caller a
//! [`PromptTicket`] instead of blocking, and no lock is held across any child
//! I/O: the shared state is a `std::sync::Mutex` taken only for short,
//! await-free critical sections.
//!
//! **What is not here.** HTTP, SSE, sessions over the wire, the tunnel, a
//! relay and any real ACP client. Chunks 3 to 5.

use std::collections::HashMap;
use std::sync::atomic::Ordering;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

use serde_json::{Value, json};
use tokio::sync::{mpsc, oneshot};
use tunnel_acp::lifecycle::{
    AcpConnection, CallbackTable, ChildLifecycle, Direction, IdScope, LifecycleEvent,
    LifecycleRejection, LifecycleRule, MAX_PENDING_PER_DIRECTION, MAX_SESSIONS_PER_CONNECTION,
    Outcome, PendingKind, PermissionOutcome, RequestId,
};
use tunnel_acp::message::{AcpRule, MessageKind, read_turn_completion};

use crate::child::{ChildConfig, ChildCounters, ChildEnd, ChildEvent, ChildHandle, SpawnError};

/// The identifiers a JSON-RPC id is scoped by, minus the direction.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConnectionScope {
    pub tenant: String,
    pub principal: String,
    pub device: String,
    pub service: String,
    pub connection: String,
}

impl ConnectionScope {
    #[must_use]
    pub fn id_scope(&self, direction: Direction) -> IdScope {
        IdScope::new(
            &self.tenant,
            &self.principal,
            &self.device,
            &self.service,
            &self.connection,
            direction,
        )
    }
}

/// Supervisor configuration. Bounds default to `docs/acp.md`'s table; the
/// deadlines are shortened by tests so a timeout can actually elapse.
#[derive(Clone, Debug)]
pub struct SupervisorConfig {
    pub child: ChildConfig,
    pub scope: ConnectionScope,
    /// `docs/acp.md`: 60 seconds, then cancel the prompt and the pending
    /// permission.
    pub permission_timeout: Duration,
    /// How often the supervisor reads its clock and observes the table.
    pub deadline_tick: Duration,
    pub session_limit: usize,
    pub pending_limit: usize,
}

impl SupervisorConfig {
    /// The documented bounds, with a child configuration supplied.
    #[must_use]
    pub fn new(child: ChildConfig, scope: ConnectionScope) -> Self {
        Self {
            child,
            scope,
            permission_timeout: Duration::from_secs(60),
            deadline_tick: Duration::from_millis(20),
            session_limit: MAX_SESSIONS_PER_CONNECTION,
            pending_limit: MAX_PENDING_PER_DIRECTION,
        }
    }
}

/// What the supervisor refused, or what went wrong.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SupervisorError {
    /// The pure lifecycle refused, and named its rule.
    Lifecycle(LifecycleRejection),
    /// The child's output was refused by the profile, and named its rule.
    Protocol(AcpRule),
    /// The child is gone, so the outcome of anything already dispatched is
    /// unknown.
    ChildGone,
}

impl SupervisorError {
    /// The lifecycle rule, when one refused.
    #[must_use]
    pub const fn rule(self) -> Option<LifecycleRule> {
        match self {
            Self::Lifecycle(rejection) => Some(rejection.rule),
            Self::Protocol(_) | Self::ChildGone => None,
        }
    }
}

impl From<LifecycleRejection> for SupervisorError {
    fn from(rejection: LifecycleRejection) -> Self {
        Self::Lifecycle(rejection)
    }
}

impl core::fmt::Display for SupervisorError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Lifecycle(rejection) => write!(formatter, "{rejection}"),
            Self::Protocol(rule) => write!(formatter, "ACP_PROTOCOL: {}", rule.code()),
            Self::ChildGone => formatter.write_str("ACP_CHILD_GONE"),
        }
    }
}

impl std::error::Error for SupervisorError {}

/// What the host learns from the agent while a prompt is pending.
///
/// Carries identifiers, phases and counters. Never a prompt, a thought chunk,
/// a permission body or a credential.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AgentEvent {
    /// A `session/update` notification arrived.
    Update { session: Option<String> },
    /// The agent is asking the host for permission.
    Permission { id: RequestId, session: String },
    /// The agent asked, and the bounded callback table refused before the
    /// host ever saw it.
    PermissionRefused { id: RequestId, rule: LifecycleRule },
    /// The permission deadline elapsed. `outcome` is always
    /// [`PermissionOutcome::Cancelled`].
    PermissionExpired {
        id: RequestId,
        session: Option<String>,
        /// Measured supervisor-clock milliseconds the permission was
        /// outstanding. Strictly greater than `bound_ms`.
        elapsed_ms: u64,
        bound_ms: u64,
        outcome: PermissionOutcome,
    },
    /// The child's message stream ended, for this reason.
    Ended(ChildEnd),
}

/// One agent→host message on its way to an SSE stream.
///
/// **This is the transport path, and it is deliberately separate from
/// [`AgentEvent`].** `AgentEvent` is diagnostics — identifiers, phases and
/// counters, never a payload — and widening it to carry bytes would have made
/// every existing consumer of it a payload consumer. This carries the exact
/// compact bytes the child wrote, already validated by the profile, and
/// nothing else: it is read only by the bridge that frames it as an SSE event.
///
/// Ordering is the reason it is one channel from one task: the supervisor's
/// single stdout reader sends here in the order the agent wrote, so wire order
/// is the channel's order and not a property anything downstream has to
/// reconstruct.
#[derive(Clone)]
pub struct OutboundMessage {
    /// `params.sessionId`, when the message carries one.
    pub session: Option<String>,
    pub kind: MessageKind,
    /// The compact message bytes, exactly as the child wrote them.
    pub compact: Vec<u8>,
}

impl core::fmt::Debug for OutboundMessage {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("OutboundMessage")
            .field("kind", &self.kind)
            .field("session", &self.session)
            .field("bytes", &self.compact.len())
            .finish()
    }
}

/// A dispatched prompt. Awaiting it does not stop the reader.
#[derive(Debug)]
pub struct PromptTicket {
    session: String,
    id: RequestId,
    reply: oneshot::Receiver<Result<Value, SupervisorError>>,
}

impl PromptTicket {
    #[must_use]
    pub fn session(&self) -> &str {
        &self.session
    }

    #[must_use]
    pub const fn id(&self) -> &RequestId {
        &self.id
    }

    /// Await the turn's `stopReason`.
    ///
    /// # Errors
    /// [`SupervisorError::Protocol`] when the result is not a v1 turn
    /// completion — notably a v2 acknowledgement with no `stopReason`, which
    /// the pinned profile refuses by its own rule. [`SupervisorError::ChildGone`]
    /// when the child ended first.
    pub async fn stop_reason(self) -> Result<String, SupervisorError> {
        let value = self.reply.await.map_err(|_| SupervisorError::ChildGone)??;
        let stop = read_turn_completion(&value)
            .map_err(|rejection| SupervisorError::Protocol(rejection.rule))?;
        // The pinned crate's own serialization, so the vocabulary is the
        // schema's rather than a string retyped here.
        serde_json::to_value(stop)
            .ok()
            .and_then(|value| value.as_str().map(ToOwned::to_owned))
            .ok_or(SupervisorError::Protocol(AcpRule::UnknownStopReason))
    }
}

/// Payload-free diagnostics.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Diagnostics {
    pub lifecycle_is_terminal: bool,
    pub spawned: u64,
    pub killed: u64,
    pub exited: u64,
    pub invalid_output: u64,
    pub oversized_output: u64,
    pub batch_output: u64,
    pub stderr_bytes: u64,
    pub stderr_over_cap: u64,
    pub group_kills: u64,
    /// Holders of the child handle other than this `Supervisor`, read from
    /// `Arc::strong_count`.
    ///
    /// **This is the quantity that actually gates cleanup.** The synchronous
    /// process-group kill lives in `ChildHandle::drop`, which runs when the
    /// last `Arc` goes; anything still holding one keeps it from running. It
    /// must reach 0 once the child has been reaped.
    ///
    /// It is deliberately preferred to `background_tasks` below for that
    /// assertion: a future task that clones the `Arc` without taking a
    /// `TaskGuard` would be invisible to the counter and would recreate the
    /// M8-C07 defect **with the test still green**. `strong_count` needs no
    /// instrumentation and cannot be forgotten.
    pub child_handle_holders: u64,
    /// Supervisor background tasks still alive, by explicit instrumentation.
    ///
    /// Kept alongside `child_handle_holders` because it names *what* is still
    /// running rather than only that something is; it is the more readable of
    /// the two and the weaker of the two.
    pub background_tasks: u64,
    pub resolutions: u64,
    pub permission_expirations: u64,
}

type Waiters = HashMap<(IdScope, RequestId), oneshot::Sender<Result<Value, SupervisorError>>>;

struct Shared {
    connection: AcpConnection,
    callbacks: CallbackTable,
    waiters: Waiters,
    next_id: u64,
    session_limit: usize,
    /// Session identifiers this connection has opened, so a drain can cancel
    /// each one's outstanding permissions.
    open_sessions: Vec<String>,
}

/// One supervised ACP child and its connection state.
pub struct Supervisor {
    shared: Arc<Mutex<Shared>>,
    child: Arc<ChildHandle>,
    counters: Arc<ChildCounters>,
    scope: ConnectionScope,
    started: Instant,
    permission_timeout_ms: u64,
}

impl Supervisor {
    /// Spawn the child and start the reader and deadline tasks.
    ///
    /// # Errors
    /// [`SpawnError`] when the process cannot be started.
    pub fn start(
        config: SupervisorConfig,
    ) -> Result<(Self, mpsc::Receiver<AgentEvent>), SpawnError> {
        Self::start_forwarding(config, None)
    }

    /// Spawn the child with an additional **transport** sink for agent→host
    /// messages.
    ///
    /// `forward` receives every notification and every agent-originated
    /// request, in the order the child wrote them, carrying the compact bytes
    /// the HTTP bridge frames as SSE events. Responses to the supervisor's own
    /// dispatched requests are not forwarded: those resolve a waiter here, and
    /// the bridge composes its answer with the *host's* JSON-RPC id, which is
    /// a different id in a different scope.
    ///
    /// # Errors
    /// [`SpawnError`] when the process cannot be started.
    pub fn start_forwarding(
        config: SupervisorConfig,
        forward: Option<mpsc::Sender<OutboundMessage>>,
    ) -> Result<(Self, mpsc::Receiver<AgentEvent>), SpawnError> {
        let counters = Arc::new(ChildCounters::default());
        let (child, events) = crate::child::spawn(&config.child, &counters)?;
        let child = Arc::new(child);
        let shared = Arc::new(Mutex::new(Shared {
            connection: AcpConnection::new(config.session_limit),
            callbacks: CallbackTable::new(config.pending_limit),
            waiters: HashMap::new(),
            next_id: 0,
            session_limit: config.session_limit,
            open_sessions: Vec::new(),
        }));
        let (to_host, from_agent) = mpsc::channel(crate::child::STDOUT_QUEUE);
        let supervisor = Self {
            shared: Arc::clone(&shared),
            child: Arc::clone(&child),
            counters: Arc::clone(&counters),
            scope: config.scope.clone(),
            started: Instant::now(),
            permission_timeout_ms: u64::try_from(config.permission_timeout.as_millis())
                .unwrap_or(u64::MAX),
        };
        tokio::spawn(read_agent(
            events,
            ReaderContext {
                shared: Arc::clone(&shared),
                child: Arc::clone(&child),
                to_host: to_host.clone(),
                scope: config.scope.clone(),
                started: supervisor.started,
                permission_timeout_ms: supervisor.permission_timeout_ms,
                counters: Arc::clone(&counters),
                forward,
            },
        ));
        tokio::spawn(observe_deadlines(
            Arc::clone(&shared),
            Arc::clone(&child),
            to_host,
            config.deadline_tick,
            supervisor.started,
            Arc::clone(&counters),
        ));
        Ok((supervisor, from_agent))
    }

    /// The supervisor's own clock, in milliseconds since it started. This is
    /// the only clock in the ACP path, and it is on the impure side of the
    /// boundary on purpose.
    #[must_use]
    pub fn now_ms(&self) -> u64 {
        u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    #[must_use]
    pub fn lifecycle(&self) -> ChildLifecycle {
        self.with(|shared| shared.connection.lifecycle())
    }

    /// The child's process id, which is its process-group id.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.child.pid()
    }

    /// `initialize` the agent and open admission.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`], or the lifecycle's refusal of a second
    /// `initialize`.
    pub async fn initialize(&self) -> Result<Value, SupervisorError> {
        self.initialize_with(json!({
            "protocolVersion": 1,
            "clientCapabilities": {},
            "clientInfo": {"name": "tunnel-acp-export", "version": "0.1.0"},
        }))
        .await
    }

    /// `initialize` the agent with the caller's own params.
    ///
    /// The HTTP bridge forwards the **host's** `initialize` params verbatim
    /// rather than substituting its own: capability negotiation is between the
    /// host's ACP client and the agent, and a bridge that rewrote it would be
    /// negotiating on the host's behalf.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`], or the lifecycle's refusal of a second
    /// `initialize`.
    pub async fn initialize_with(&self, params: Value) -> Result<Value, SupervisorError> {
        let (_, reply) = self.dispatch("initialize", params, PendingKind::Call, None, false)?;
        let value = reply.await.map_err(|_| SupervisorError::ChildGone)??;
        self.try_with(|shared| {
            shared
                .connection
                .advance(LifecycleEvent::Initialized)
                .map(|_| ())
        })?;
        Ok(value)
    }

    /// Create a session.
    ///
    /// # Errors
    /// [`LifecycleRule::SessionLimit`] at one session beyond the bound, and
    /// [`LifecycleRule::ConnectionNotReady`] before `initialize`.
    pub async fn new_session(&self, cwd: &str) -> Result<String, SupervisorError> {
        self.new_session_with(json!({"cwd": cwd, "mcpServers": []}))
            .await
    }

    /// Create a session from the caller's own params.
    ///
    /// # Errors
    /// As [`Supervisor::new_session`].
    pub async fn new_session_with(&self, params: Value) -> Result<String, SupervisorError> {
        // The bound is checked before dispatch, so a ninth session is never
        // asked for.
        self.try_with(|shared| {
            if !shared.connection.lifecycle().admits() {
                return Err(LifecycleRejection::new(
                    LifecycleRule::ConnectionNotReady,
                    "the connection is not admitting new sessions",
                ));
            }
            if shared.connection.session_count() >= shared.session_limit {
                return Err(LifecycleRejection::new(
                    LifecycleRule::SessionLimit,
                    "too many sessions on this connection",
                ));
            }
            Ok(())
        })?;
        let (_, reply) = self.dispatch("session/new", params, PendingKind::Call, None, true)?;
        let value = reply.await.map_err(|_| SupervisorError::ChildGone)??;
        let session = value
            .get("sessionId")
            .and_then(Value::as_str)
            .ok_or(SupervisorError::Protocol(AcpRule::NotJsonRpcMessage))?
            .to_owned();
        let now = self.now_ms();
        self.try_with(|shared| {
            shared.connection.open_session(&session, now)?;
            shared.open_sessions.push(session.clone());
            Ok(())
        })?;
        Ok(session)
    }

    /// The session's scoped subscriber arrived.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownSession`] or [`LifecycleRule::SessionNotReady`].
    pub fn subscriber_ready(&self, session: &str) -> Result<(), SupervisorError> {
        self.try_with(|shared| shared.connection.subscriber_ready(session))
    }

    /// Start the session's one active prompt.
    ///
    /// Returns immediately with a [`PromptTicket`]; the reader keeps handling
    /// agent callbacks while it is outstanding.
    ///
    /// # Errors
    /// [`LifecycleRule::PromptAlreadyActive`] for a second concurrent prompt,
    /// [`LifecycleRule::SessionNotReady`] before the subscriber arrives, and
    /// [`LifecycleRule::ConnectionNotReady`] once admission has stopped.
    pub fn prompt(&self, session: &str, text: &str) -> Result<PromptTicket, SupervisorError> {
        self.prompt_with(
            session,
            json!({"sessionId": session, "prompt": [{"type": "text", "text": text}]}),
        )
    }

    /// Start the session's one active prompt from the caller's own params.
    ///
    /// The HTTP bridge forwards the host's `session/prompt` params verbatim:
    /// a v1 prompt is a list of content blocks, and a bridge that rebuilt it
    /// from the first text block would silently drop the rest.
    ///
    /// # Errors
    /// As [`Supervisor::prompt`].
    pub fn prompt_with(
        &self,
        session: &str,
        params: Value,
    ) -> Result<PromptTicket, SupervisorError> {
        self.try_with(|shared| shared.connection.begin_prompt(session))?;
        let reply = self.dispatch(
            "session/prompt",
            params,
            PendingKind::Prompt,
            Some(session),
            true,
        );
        match reply {
            Ok((id, reply)) => Ok(PromptTicket {
                session: session.to_owned(),
                id,
                reply,
            }),
            Err(error) => {
                // The turn never started; put the session back.
                let _ = self.try_with(|shared| shared.connection.end_prompt(session));
                Err(error)
            }
        }
    }

    /// Answer an outstanding permission request.
    ///
    /// # Errors
    /// [`LifecycleRule::UnknownRequestId`] when that permission is not
    /// outstanding — which is exactly what a duplicate answer, and an answer
    /// that lost the race with the deadline, both are.
    pub async fn answer_permission(
        &self,
        id: &RequestId,
        outcome: PermissionOutcome,
    ) -> Result<(), SupervisorError> {
        let scope = self.scope.id_scope(Direction::AgentToHost);
        let now = self.now_ms();
        self.try_with(|shared| {
            shared
                .callbacks
                .resolve(&scope, id, Outcome::Permission(outcome.clone()), now)
                .map(|_| ())
        })?;
        let body = permission_response(id, &outcome);
        self.child
            .send(&body)
            .await
            .map_err(|_| SupervisorError::ChildGone)
    }

    /// Forward a `session/cancel` notification.
    ///
    /// `docs/acp.md`: the bridge resolves pending permission callbacks with
    /// `cancelled`, forwards cancellation, and then **waits for the original
    /// prompt response**. It does not synthesize one: a confirmed cancelled
    /// turn has `stopReason: "cancelled"` and only the agent can say so.
    ///
    /// # Errors
    /// [`SupervisorError::ChildGone`].
    pub async fn cancel_session(
        &self,
        session: &str,
        params: Value,
    ) -> Result<(), SupervisorError> {
        let now = self.now_ms();
        let cancelled =
            self.with(|shared| shared.callbacks.cancel_session_permissions(session, now));
        for (_, id) in cancelled {
            // Tell the agent on the wire, exactly as the deadline path does.
            let _ = self
                .child
                .send(&permission_response(&id, &PermissionOutcome::Cancelled))
                .await;
        }
        let body = serde_json::to_vec(&json!({
            "jsonrpc": "2.0",
            "method": "session/cancel",
            "params": params,
        }))
        .unwrap_or_default();
        self.child
            .send(&body)
            .await
            .map_err(|_| SupervisorError::ChildGone)
    }

    /// Whether this connection opened `session`.
    #[must_use]
    pub fn has_session(&self, session: &str) -> bool {
        self.with(|shared| shared.open_sessions.iter().any(|open| open == session))
    }

    /// Every session this connection has open.
    #[must_use]
    pub fn open_sessions(&self) -> Vec<String> {
        self.with(|shared| shared.open_sessions.clone())
    }

    /// Resolve every outstanding permission on every open session as
    /// **cancelled**, tell the agent on the wire, and report how many there
    /// were.
    ///
    /// This is the "resolve pending permissions as cancelled" half of
    /// `docs/acp.md`'s subscriber-loss policy.  [`Supervisor::drain`] cancels
    /// them too, but discards the count and never tells the agent; the
    /// termination path needs both, because "how many permissions were
    /// cancelled" is the observation a test reads instead of trusting that
    /// cancellation happened.
    ///
    /// A timeout and a lost subscriber therefore resolve a callback the same
    /// way, which is the point: `docs/acp.md` says timeout and disconnect never
    /// mean permission.
    pub async fn cancel_all_permissions(&self) -> usize {
        let now = self.now_ms();
        let cancelled = self.with(|shared| {
            let sessions: Vec<String> = shared.open_sessions.clone();
            let mut all = Vec::new();
            for session in sessions {
                all.extend(shared.callbacks.cancel_session_permissions(&session, now));
            }
            all
        });
        for (_, id) in &cancelled {
            // The agent learns on the wire, exactly as the deadline path and
            // `session/cancel` do.  A supervisor's belief about what it
            // resolved is not evidence that the agent was told.
            let _ = self
                .child
                .send(&permission_response(id, &PermissionOutcome::Cancelled))
                .await;
        }
        cancelled.len()
    }

    /// Stop admission, cancel outstanding permissions, and end the child's
    /// life — which signals its process group.
    ///
    /// **This is not a graceful shutdown.** It does not close stdin, and it
    /// does not give the child a grace period to finish and exit by itself;
    /// `docs/acp.md`'s bounded grace period is not implemented. It cancels and
    /// kills. The [`ChildLifecycle::Stopped`] that results therefore records
    /// *who ended the child* — the supervisor, deliberately — and not *how the
    /// process died.
    pub async fn drain(&self) {
        let now = self.now_ms();
        self.with(|shared| {
            let _ = shared.connection.advance(LifecycleEvent::DrainRequested);
            // Every outstanding permission is cancelled, never approved.
            let sessions: Vec<String> = shared.open_sessions.clone();
            for session in sessions {
                shared.callbacks.cancel_session_permissions(&session, now);
            }
        });
        self.child.kill();
        self.child.wait_exited().await;
        self.with(|shared| {
            // Draining then reaped is what reaches `Stopped`; the transition
            // table decides, not this line.
            let _ = shared.connection.advance(LifecycleEvent::Reaped);
        });
    }

    /// End the child's life without awaiting anything.
    ///
    /// The synchronous form of the kill half of [`Supervisor::drain`], for a
    /// connector whose own teardown is not async — `HttpHandlers::drop` is
    /// exactly that. It signals the child's process group; it does not wait
    /// for the reap, and it is idempotent.
    pub fn kill(&self) {
        self.child.kill();
    }

    /// Wait for the child to be reaped, however its life ended.
    pub async fn wait_exited(&self) {
        self.child.wait_exited().await;
    }

    #[must_use]
    pub fn diagnostics(&self) -> Diagnostics {
        let (resolutions, permission_expirations, terminal) = self.with(|shared| {
            (
                shared.callbacks.resolutions(),
                shared.callbacks.expirations(),
                shared.connection.lifecycle().is_terminal(),
            )
        });
        Diagnostics {
            lifecycle_is_terminal: terminal,
            spawned: self.counters.spawned.load(Ordering::Relaxed),
            killed: self.counters.killed.load(Ordering::Relaxed),
            exited: self.counters.exited.load(Ordering::Relaxed),
            invalid_output: self.counters.invalid_output.load(Ordering::Relaxed),
            oversized_output: self.counters.oversized_output.load(Ordering::Relaxed),
            batch_output: self.counters.batch_output.load(Ordering::Relaxed),
            stderr_bytes: self.counters.stderr_bytes.load(Ordering::Relaxed),
            stderr_over_cap: self.counters.stderr_over_cap.load(Ordering::Relaxed),
            group_kills: self.counters.group_kills.load(Ordering::Relaxed),
            // Minus one for this `Supervisor`'s own handle.
            child_handle_holders: (Arc::strong_count(&self.child) as u64).saturating_sub(1),
            background_tasks: self.counters.background_tasks.load(Ordering::Relaxed),
            resolutions,
            permission_expirations,
        }
    }

    /// Outstanding requests in one direction, for the bound tests.
    #[must_use]
    pub fn pending(&self, direction: Direction) -> usize {
        let scope = self.scope.id_scope(direction);
        self.with(|shared| shared.callbacks.pending_in(&scope))
    }

    #[must_use]
    pub fn session_count(&self) -> usize {
        self.with(|shared| shared.connection.session_count())
    }

    fn with<R>(&self, apply: impl FnOnce(&mut Shared) -> R) -> R {
        let mut guard = self.shared.lock().unwrap_or_else(PoisonError::into_inner);
        apply(&mut guard)
    }

    fn try_with<R>(
        &self,
        apply: impl FnOnce(&mut Shared) -> Result<R, LifecycleRejection>,
    ) -> Result<R, SupervisorError> {
        self.with(apply).map_err(SupervisorError::from)
    }

    /// Register a host request and write its line. The critical section holds
    /// no await.
    fn dispatch(
        &self,
        method: &str,
        params: Value,
        kind: PendingKind,
        session: Option<&str>,
        require_ready: bool,
    ) -> Result<(RequestId, oneshot::Receiver<Result<Value, SupervisorError>>), SupervisorError>
    {
        let scope = self.scope.id_scope(Direction::HostToAgent);
        let now = self.now_ms();
        let (sender, receiver) = oneshot::channel();
        let (id, body) = self.try_with(|shared| {
            if require_ready && !shared.connection.lifecycle().admits() {
                return Err(LifecycleRejection::new(
                    LifecycleRule::ConnectionNotReady,
                    "the connection is not admitting requests",
                ));
            }
            shared.next_id += 1;
            let id = RequestId::Number(i64::try_from(shared.next_id).unwrap_or(i64::MAX));
            shared
                .callbacks
                .register(&scope, id.clone(), kind, session, now, 0)?;
            shared.waiters.insert((scope.clone(), id.clone()), sender);
            let body = serde_json::to_vec(&json!({
                "jsonrpc": "2.0",
                "id": id_value(&id),
                "method": method,
                "params": params,
            }))
            .unwrap_or_default();
            Ok((id, body))
        })?;
        let child = Arc::clone(&self.child);
        let shared = Arc::clone(&self.shared);
        let key = (scope, id.clone());
        tokio::spawn(async move {
            if child.send(&body).await.is_err() {
                let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                if let Some(waiter) = guard.waiters.remove(&key) {
                    let _ = waiter.send(Err(SupervisorError::ChildGone));
                }
            }
        });
        Ok((id, receiver))
    }
}

/// Counts one live supervisor background task for as long as it exists.
///
/// The count is what makes "this task ended with its child" observable. A task
/// that loops forever holds an `Arc<ChildHandle>` and silently disables the
/// synchronous cleanup in `ChildHandle::drop`; before the M8-C07 review there
/// was nothing a test could read to notice.
struct TaskGuard(Arc<ChildCounters>);

impl TaskGuard {
    fn new(counters: &Arc<ChildCounters>) -> Self {
        counters.background_tasks.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(counters))
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.background_tasks.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Drop for Supervisor {
    /// A supervisor that goes away ends its child, whether or not anyone
    /// called [`Supervisor::drain`].
    ///
    /// Connection loss in a later chunk is exactly "the owner went away
    /// without draining", so a cleanup path that only ran on the happy path
    /// would leak the agent's whole process tree at the moment it matters
    /// most. Cancelling here makes the supervisor task send the group signal
    /// while the leader is still unreaped; if the runtime is being torn down
    /// and that task never runs, [`crate::child::ChildHandle::drop`] sends it
    /// synchronously instead.
    fn drop(&mut self) {
        self.child.kill();
    }
}

fn id_value(id: &RequestId) -> Value {
    match id {
        RequestId::Text(text) => Value::String(text.clone()),
        RequestId::Number(number) => Value::from(*number),
    }
}

/// The `optionId`s a `session/request_permission` offered, in the order the
/// agent listed them.
///
/// An agent that offers none yields an empty list, which admits no selection
/// at all — which is right: there was nothing to select.
fn offered_options(message: &serde_json::Value) -> Vec<String> {
    message
        .pointer("/params/options")
        .and_then(serde_json::Value::as_array)
        .map(|options| {
            options
                .iter()
                .filter_map(|option| {
                    option
                        .get("optionId")
                        .and_then(serde_json::Value::as_str)
                        .map(ToOwned::to_owned)
                })
                .collect()
        })
        .unwrap_or_default()
}

fn id_from_value(value: &Value) -> Option<RequestId> {
    match value {
        Value::String(text) => Some(RequestId::Text(text.clone())),
        Value::Number(number) => number.as_i64().map(RequestId::Number),
        _ => None,
    }
}

fn permission_response(id: &RequestId, outcome: &PermissionOutcome) -> Vec<u8> {
    let outcome = match outcome {
        PermissionOutcome::Selected(option) => {
            json!({"outcome": "selected", "optionId": option})
        }
        PermissionOutcome::Cancelled => json!({"outcome": "cancelled"}),
    };
    serde_json::to_vec(&json!({
        "jsonrpc": "2.0",
        "id": id_value(id),
        "result": {"outcome": outcome},
    }))
    .unwrap_or_default()
}

/// The separate reader: it keeps handling agent callbacks while a prompt is
/// pending, because it is not the task awaiting the prompt.
/// Everything the reader task needs. A struct rather than eight arguments,
/// which is also what `clippy::too_many_arguments` asks for.
struct ReaderContext {
    shared: Arc<Mutex<Shared>>,
    child: Arc<ChildHandle>,
    to_host: mpsc::Sender<AgentEvent>,
    scope: ConnectionScope,
    started: Instant,
    permission_timeout_ms: u64,
    counters: Arc<ChildCounters>,
    /// The transport sink, when a bridge asked for one.
    forward: Option<mpsc::Sender<OutboundMessage>>,
}

async fn read_agent(mut events: mpsc::Receiver<ChildEvent>, context: ReaderContext) {
    let ReaderContext {
        shared,
        child,
        to_host,
        scope,
        started,
        permission_timeout_ms,
        counters,
        forward,
    } = context;
    let _alive = TaskGuard::new(&counters);
    let host_scope = scope.id_scope(Direction::HostToAgent);
    let agent_scope = scope.id_scope(Direction::AgentToHost);
    while let Some(event) = events.recv().await {
        let now = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        match event {
            ChildEvent::Message(message) => {
                let message = message.message;
                match message.kind {
                    MessageKind::Notification => {
                        let session = message.session_id().map(ToOwned::to_owned);
                        // The transport copy goes first, and from this one
                        // task, so the order an SSE stream sees is the order
                        // the agent wrote.
                        if let Some(forward) = &forward
                            && forward
                                .send(OutboundMessage {
                                    session: session.clone(),
                                    kind: MessageKind::Notification,
                                    compact: message.compact.clone(),
                                })
                                .await
                                .is_err()
                        {
                            return;
                        }
                        if to_host.send(AgentEvent::Update { session }).await.is_err() {
                            return;
                        }
                    }
                    MessageKind::Request => {
                        let Some(id) = message.id.as_ref().and_then(id_from_value) else {
                            continue;
                        };
                        let session = message.session_id().unwrap_or_default().to_owned();
                        let registered = {
                            let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                            // The options the agent offered are recorded with
                            // the callback, so the host's answer can be
                            // checked against them (`docs/acp.md`: "Validate
                            // the response against ... the offered option").
                            guard.callbacks.register_permission(
                                &agent_scope,
                                id.clone(),
                                Some(&session),
                                now,
                                permission_timeout_ms,
                                offered_options(&message.value),
                            )
                        };
                        let event = match registered {
                            Ok(()) => {
                                // Only an admitted callback reaches the host.
                                // One the bounded table refused was answered
                                // `cancelled` below and must never appear on a
                                // stream as if it were outstanding.
                                if let Some(forward) = &forward
                                    && forward
                                        .send(OutboundMessage {
                                            session: Some(session.clone()),
                                            kind: MessageKind::Request,
                                            compact: message.compact.clone(),
                                        })
                                        .await
                                        .is_err()
                                {
                                    return;
                                }
                                AgentEvent::Permission {
                                    id: id.clone(),
                                    session,
                                }
                            }
                            Err(rejection) => {
                                // Refused before the host ever saw it; tell the
                                // agent so its own wait ends.
                                let _ = child
                                    .send(&permission_response(&id, &PermissionOutcome::Cancelled))
                                    .await;
                                AgentEvent::PermissionRefused {
                                    id: id.clone(),
                                    rule: rejection.rule,
                                }
                            }
                        };
                        if to_host.send(event).await.is_err() {
                            return;
                        }
                    }
                    MessageKind::Response => {
                        let Some(id) = message.id.as_ref().and_then(id_from_value) else {
                            continue;
                        };
                        let result = message.value.get("result").cloned();
                        let outcome = result.as_ref().map_or_else(
                            || Outcome::Failed("agent_error".to_owned()),
                            |_| Outcome::Completed("ok".to_owned()),
                        );
                        let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                        let Ok(resolution) =
                            guard.callbacks.resolve(&host_scope, &id, outcome, now)
                        else {
                            // A duplicate, a late, or an unsolicited response.
                            // It cannot repeat a decision, so it is dropped.
                            continue;
                        };
                        if resolution.kind == PendingKind::Prompt
                            && let Some(session) = resolution.session.as_deref()
                        {
                            let _ = guard.connection.end_prompt(session);
                        }
                        if let Some(waiter) = guard.waiters.remove(&(host_scope.clone(), id)) {
                            let _ = waiter.send(match result {
                                Some(value) => Ok(value),
                                None => Err(SupervisorError::Protocol(AcpRule::NotJsonRpcMessage)),
                            });
                        }
                    }
                }
            }
            ChildEvent::Ended(end) => {
                let waiters: Vec<_> = {
                    let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
                    let event = match end {
                        ChildEnd::Closed => LifecycleEvent::Reaped,
                        ChildEnd::OversizedLine
                        | ChildEnd::InvalidLine(_)
                        | ChildEnd::ReadFailed => LifecycleEvent::Failed,
                    };
                    let _ = guard.connection.advance(event);
                    guard.waiters.drain().map(|(_, sender)| sender).collect()
                };
                for waiter in waiters {
                    let _ = waiter.send(Err(SupervisorError::ChildGone));
                }
                let _ = to_host.send(AgentEvent::Ended(end)).await;
                return;
            }
        }
    }
}

/// Read the clock, hand the reading to the pure table, and act on what it
/// decided. A permission that ran out of time is **cancelled**; there is no
/// path here that approves one.
async fn observe_deadlines(
    shared: Arc<Mutex<Shared>>,
    child: Arc<ChildHandle>,
    to_host: mpsc::Sender<AgentEvent>,
    tick: Duration,
    started: Instant,
    counters: Arc<ChildCounters>,
) {
    let _alive = TaskGuard::new(&counters);
    let mut ticker = tokio::time::interval(tick);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // **This task must end when the child does.** It holds an
        // `Arc<ChildHandle>`, and a ticker that loops forever keeps that
        // strong count above zero, so `ChildHandle::drop` — which is where the
        // synchronous process-group kill lives — would never run for a
        // supervisor that was dropped rather than drained. That was the
        // M8-C07 review's first finding, and it left real `sleep` grandchildren
        // behind with their leaders already reaped.
        tokio::select! {
            () = child.wait_exited() => return,
            _ = ticker.tick() => {}
        }
        let now = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
        let expired = {
            let mut guard = shared.lock().unwrap_or_else(PoisonError::into_inner);
            guard.callbacks.observe(now)
        };
        for permission in expired {
            // Tell the agent, on the wire, that its request was cancelled.
            let _ = child
                .send(&permission_response(
                    &permission.id,
                    &PermissionOutcome::Cancelled,
                ))
                .await;
            let event = AgentEvent::PermissionExpired {
                id: permission.id,
                session: permission.session,
                elapsed_ms: permission.elapsed,
                bound_ms: permission.bound,
                outcome: permission.outcome,
            };
            if to_host.send(event).await.is_err() {
                return;
            }
        }
    }
}
