//! Verified physical lanes to the Redis authority.
//!
//! The catalog keeps a plain redis-rs `MultiplexedConnection` per lane and
//! never hides a transport failure behind a generic reconnecting pool.  The
//! command that observes the failure returns it, so authorization, ownership
//! and recovery callers keep their fail-closed and unknown-outcome semantics;
//! nothing is replayed and nothing reconnects in the background.  A lane
//! re-establishes its connection only for a *later* command, and only after
//! repeating the bounded PING/INFO identity check used at startup.
//!
//! A primary whose `run_id` differs from the one the catalog is bound to has
//! restarted, been restored or been replaced.  The lanes of one catalog share
//! one [`RunBinding`].  A catalog that did not opt in (every `[cluster]`
//! catalog, every library caller) refuses any other run, as before task row
//! M6-C65.  A single relay's catalog (`enable_run_rebinding`) decides with one
//! atomic script on the new connection, before any caller command runs there:
//!
//! * it adopts the new run when the namespace's stored run binding already
//!   names it -- an operator re-attested it (`tunnel-relay rebind-redis-run`)
//!   or a sibling lane has just re-bound it -- and its incarnation is the
//!   configured one, which is exactly what a relay started now would accept;
//!   except that a run this process already refused for continuity stays
//!   refused, whatever an operator later declares;
//! * with a continuity witness (`redis_restart_continuity_seconds`), it moves
//!   the binding when the namespace's continuity token is one this process
//!   wrote and Redis acknowledged (or one whose write outcome it could not
//!   learn), the last acknowledgement was at most one token interval plus the
//!   command deadlines before this process's last reply from the old run, and
//!   `CONFIG GET` on the new run shows `appendonly yes`, `appendfsync always`
//!   and `no-appendfsync-on-rewrite no`.
//!
//! **What the token proves, and what it does not.**  It is sound for one
//! Redis restarting from its own AOF: AOF replay restores a prefix of the
//! command history, so a Redis holding this process's last acknowledged token
//! holds every write acknowledged before it, and with `appendfsync always`
//! nothing acknowledged after it was lost.  It only detects a copy **older
//! than the last token**: an empty Redis, or a snapshot, backup or replica
//! taken before it.  It is **not** sound across failover or replica
//! promotion: an asynchronous replica usually holds the last token and can
//! still lack writes the old primary acknowledged after it.  Likewise a
//! restore or a replica taken within about one interval before Redis went
//! away (plus any time the token loop was failing while Redis still
//! answered) holds the token and can lack writes acknowledged after it,
//! including operator-CLI revocations.  Anything that is not an in-place
//! restart must go through recovery or a new namespace.
//!
//! Lanes of one catalog share a loss generation.  When one lane observes a
//! transport loss, every sibling lane probes its own connection with the same
//! startup `PING` before its next caller command: a connection severed by the
//! same event reconnects there instead of failing one more caller closed,
//! while a live connection keeps its place.  The probe is never the caller's
//! command.
//!
//! A lane does not serialize its callers.  The lane lock is held only across
//! the bounded probe or reconnect that verifies the physical connection;
//! every caller then runs its own command on a handle to that multiplexed
//! connection, so concurrent commands pipeline on one socket and the
//! per-command deadline measures the authority's reply, never the time spent
//! waiting behind other callers.  A queueing delay therefore cannot be
//! reported as an authority timeout, while a stalled or severed authority
//! still fails exactly the commands that observed it.

use std::{
    collections::VecDeque,
    sync::{
        Arc, PoisonError, RwLock, RwLockReadGuard, RwLockWriteGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};

use redis::{FromRedisValue, RedisError, aio::MultiplexedConnection};
use tokio::sync::Mutex;

use super::{
    BOUND_RUN_MARKER, REDIS_OPERATION_TIMEOUT, bound_run_id, eval_command,
    open_verified_connection, redis_timeout,
};
use crate::{CatalogConnectionError, CatalogError, UnknownWriteCause};

/// The closed conflict label returned when a reconnect reaches a primary
/// whose `run_id` differs from the bound identity and the namespace does not
/// allow the new run to be adopted.
pub(super) const RUN_ID_CONFLICT: &str = "Redis server run id";

/// The namespace has no deployment incarnation or no run binding: it was
/// never activated, or Redis came back without its data (M6-C65).
pub(crate) const NAMESPACE_UNBOUND: &str =
    "namespace has no deployment incarnation or Redis run binding";

/// The namespace is bound to an earlier Redis server run: Redis restarted
/// since the binding was written, and nothing re-attested it (M6-C65).
pub(crate) const RUN_BINDING_CHANGED: &str = "namespace is bound to an earlier Redis server run";

/// The namespace's continuity token is not one this relay wrote: Redis came
/// back without this relay's last acknowledged write (M6-C65).
pub(crate) const CONTINUITY_MISMATCH: &str = "Redis authority continuity token";

/// The restarted Redis does not prove its acknowledged writes are durable
/// (`appendonly yes`, `appendfsync always`, `no-appendfsync-on-rewrite no`,
/// read with `CONFIG GET`), so a continuity token proves nothing (M6-C65).
pub(crate) const PERSISTENCE_UNSOUND: &str =
    "Redis persistence does not make acknowledged writes durable";

/// Most continuity tokens whose write outcome is unknown that a witness keeps
/// as candidates.  Beyond it the oldest is forgotten, which can only make a
/// later re-binding refuse.
const MAX_CONTINUITY_CANDIDATES: usize = 8;

/// Most Redis runs a binding remembers having refused for continuity.
const MAX_CONTINUITY_REFUSED_RUNS: usize = 8;

/// The Redis persistence a token re-binding requires, read with `CONFIG GET`
/// on the new run: every acknowledged write is on disk before the reply,
/// including while the AOF is being rewritten.
const REQUIRED_PERSISTENCE: [(&str, &str); 3] = [
    ("appendonly", "yes"),
    ("appendfsync", "always"),
    ("no-appendfsync-on-rewrite", "no"),
];

/// One atomic re-binding decision on a connection to a new Redis run.
///
/// KEYS[1] active incarnation, [2] run binding, [3] continuity token.
/// ARGV[1] configured incarnation, [2] the new run id, [3] `1` when a
/// continuity witness may re-bind, [4..] the witness's candidate tokens.
const SCRIPT_REBIND_RUN: &str = r#"
local incarnation = redis.call('GET', KEYS[1])
local run = redis.call('GET', KEYS[2])
if not incarnation or not run then return {'unbound'} end
if incarnation ~= ARGV[1] then return {'incarnation'} end
if run == ARGV[2] then return {'ok'} end
if ARGV[3] ~= '1' then return {'run'} end
local token = redis.call('GET', KEYS[3])
if not token then return {'continuity'} end
for index = 4, #ARGV do
  if token == ARGV[index] then
    redis.call('SET', KEYS[2], ARGV[2])
    return {'rebound'}
  end
end
return {'continuity'}
"#;

/// The keys and incarnation a lane needs to decide a re-binding on its own
/// connection.  Set only for a single relay (`enable_run_rebinding`); a
/// catalog without it refuses every other run, as before M6-C65.
#[derive(Clone)]
pub(super) struct RebindScope {
    pub(super) incarnation: String,
    pub(super) incarnation_key: String,
    pub(super) run_key: String,
    pub(super) continuity_key: String,
}

/// Continuity tokens this process wrote: the last one Redis acknowledged and
/// any written since whose outcome is unknown.  Only these can be in Redis
/// if Redis still holds this process's acknowledged writes.
struct ContinuityWitness {
    candidates: VecDeque<String>,
    /// The token interval the relay runs, which bounds how stale the last
    /// acknowledged token may be when Redis went away.
    interval: Duration,
    /// When Redis last acknowledged a token, in the binding's clock.
    last_ack_ms: Option<u64>,
}

#[derive(Default)]
struct BindingState {
    run_id: String,
    scope: Option<RebindScope>,
    witness: Option<ContinuityWitness>,
    /// Runs refused for continuity; they stay refused in this process even if
    /// an operator later re-attests them (M6-C65 review).
    continuity_refused: VecDeque<String>,
    /// Advanced every time the binding moves to a new run.
    rebinds: u64,
}

/// Whether a token re-binding is still sound: the last acknowledged token
/// was written at most one interval plus the command deadlines before the
/// last reply this process had from the bound Redis run.  A token loop that
/// stopped or kept failing while Redis still answered leaves a larger gap,
/// in which writes the witness never saw may have been acknowledged.
pub(super) fn token_is_fresh(
    last_ack_ms: Option<u64>,
    last_contact_ms: u64,
    interval: Duration,
) -> bool {
    let Some(last_ack_ms) = last_ack_ms else {
        return false;
    };
    let bound = interval + 2 * REDIS_OPERATION_TIMEOUT + Duration::from_secs(1);
    let bound_ms = u64::try_from(bound.as_millis()).unwrap_or(u64::MAX);
    last_contact_ms.saturating_sub(last_ack_ms) <= bound_ms
}

/// Whether `CONFIG GET` pairs show the persistence a token re-binding needs.
pub(super) fn persistence_is_sound(pairs: &[String]) -> bool {
    REQUIRED_PERSISTENCE.iter().all(|(name, required)| {
        pairs
            .chunks(2)
            .any(|pair| pair.len() == 2 && pair[0] == *name && pair[1] == *required)
    })
}

/// Read the persistence settings on `connection` (M6-C65).  A refused
/// `CONFIG GET` (for example an ACL user without `+config|get`) is unsound,
/// not an error: nothing proves the writes are durable.
pub(super) async fn persistence_verified(connection: &mut MultiplexedConnection) -> bool {
    let mut command = redis::cmd("CONFIG");
    command.arg("GET");
    for (name, _) in REQUIRED_PERSISTENCE {
        command.arg(name);
    }
    match command.query_async::<Vec<String>>(connection).await {
        Ok(pairs) => persistence_is_sound(&pairs),
        Err(_) => false,
    }
}

/// The Redis server run a catalog is bound to, shared by all of its lanes.
pub(super) struct RunBinding {
    state: RwLock<BindingState>,
    /// The binding's clock origin.
    origin: Instant,
    /// Milliseconds since `origin` of the last reply any lane received from
    /// the bound run.  Updated lock-free on every successful command.
    last_contact_ms: AtomicU64,
}

impl Default for RunBinding {
    fn default() -> Self {
        Self {
            state: RwLock::default(),
            origin: Instant::now(),
            last_contact_ms: AtomicU64::new(0),
        }
    }
}

impl RunBinding {
    fn read(&self) -> RwLockReadGuard<'_, BindingState> {
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    fn write(&self) -> RwLockWriteGuard<'_, BindingState> {
        self.state.write().unwrap_or_else(PoisonError::into_inner)
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    /// A lane received a reply from the bound run.
    pub(super) fn contact(&self) {
        self.last_contact_ms
            .fetch_max(self.now_ms(), Ordering::AcqRel);
    }

    /// The run the catalog is currently bound to.
    pub(super) fn run_id(&self) -> String {
        self.read().run_id.clone()
    }

    /// How many times the binding has moved to a new run in this process.
    pub(super) fn rebinds(&self) -> u64 {
        self.read().rebinds
    }

    fn initialize(&self, run_id: &str) {
        let mut state = self.write();
        if state.run_id.is_empty() {
            run_id.clone_into(&mut state.run_id);
        }
    }

    pub(super) fn set_scope(&self, scope: RebindScope) {
        self.write().scope = Some(scope);
    }

    pub(super) fn has_scope(&self) -> bool {
        self.read().scope.is_some()
    }

    /// Start keeping a continuity witness.  Idempotent.
    pub(super) fn enable_witness(&self, interval: Duration) {
        let mut state = self.write();
        if state.witness.is_none() {
            state.witness = Some(ContinuityWitness {
                candidates: VecDeque::new(),
                interval,
                last_ack_ms: None,
            });
        }
    }

    /// Stop re-binding on tokens: the token loop is gone (M6-C65 review).
    pub(super) fn disable_witness(&self) {
        self.write().witness = None;
    }

    pub(super) fn witness_enabled(&self) -> bool {
        self.read().witness.is_some()
    }

    /// Record a token about to be written, before it is dispatched, so a
    /// re-binding that races the write still recognizes it.
    pub(super) fn continuity_dispatching(&self, token: &str) {
        if let Some(witness) = self.write().witness.as_mut() {
            witness.candidates.push_back(token.to_owned());
            while witness.candidates.len() > MAX_CONTINUITY_CANDIDATES {
                witness.candidates.pop_front();
            }
        }
    }

    /// Redis acknowledged `token`: it is now the only candidate.
    pub(super) fn continuity_acknowledged(&self, token: &str) {
        let now = self.now_ms();
        self.contact();
        if let Some(witness) = self.write().witness.as_mut() {
            witness.candidates.clear();
            witness.candidates.push_back(token.to_owned());
            witness.last_ack_ms = Some(now);
        }
    }

    /// The write of `token` definitely did not happen.
    pub(super) fn continuity_not_written(&self, token: &str) {
        if let Some(witness) = self.write().witness.as_mut() {
            witness.candidates.retain(|candidate| candidate != token);
        }
    }

    fn adopt(&self, run_id: &str) {
        let mut state = self.write();
        if state.run_id != run_id {
            run_id.clone_into(&mut state.run_id);
            state.rebinds += 1;
        }
    }

    fn refuse_for_continuity(&self, run_id: &str) {
        let mut state = self.write();
        if !state.continuity_refused.iter().any(|run| run == run_id) {
            state.continuity_refused.push_back(run_id.to_owned());
            while state.continuity_refused.len() > MAX_CONTINUITY_REFUSED_RUNS {
                state.continuity_refused.pop_front();
            }
        }
    }

    /// Decide on `connection`, already verified to be Redis run `run_id`,
    /// whether the catalog may move its binding there.
    async fn rebind(
        &self,
        connection: &mut MultiplexedConnection,
        run_id: &str,
    ) -> Result<(), CatalogError> {
        // Decide, under the lock, whether a token re-binding is even
        // possible; the persistence read happens after it is released.
        let (keys, incarnation, candidates) = {
            let state = self.read();
            if state.run_id == run_id {
                return Ok(());
            }
            let Some(scope) = state.scope.as_ref() else {
                return Err(CatalogError::Conflict(RUN_ID_CONFLICT));
            };
            if state.continuity_refused.iter().any(|run| run == run_id) {
                return Err(CatalogError::Conflict(CONTINUITY_MISMATCH));
            }
            let candidates = state.witness.as_ref().and_then(|witness| {
                token_is_fresh(
                    witness.last_ack_ms,
                    self.last_contact_ms.load(Ordering::Acquire),
                    witness.interval,
                )
                .then(|| witness.candidates.iter().cloned().collect::<Vec<_>>())
            });
            (
                vec![
                    scope.incarnation_key.clone(),
                    scope.run_key.clone(),
                    scope.continuity_key.clone(),
                ],
                scope.incarnation.clone(),
                candidates,
            )
        };
        let mut persistence_unsound = false;
        let candidates = match candidates {
            Some(candidates) if persistence_verified(connection).await => Some(candidates),
            Some(_) => {
                persistence_unsound = true;
                None
            }
            None => None,
        };
        let mut args = vec![incarnation, run_id.to_owned()];
        match candidates {
            Some(candidates) => {
                args.push("1".to_owned());
                args.extend(candidates);
            }
            None => args.push("0".to_owned()),
        }
        let reply: Vec<String> = eval_command(SCRIPT_REBIND_RUN, &keys, &args)
            .query_async(connection)
            .await
            .map_err(CatalogError::Database)?;
        match reply.first().map(String::as_str) {
            Some("ok" | "rebound") => {
                self.adopt(run_id);
                Ok(())
            }
            Some("unbound") => Err(CatalogError::Conflict(NAMESPACE_UNBOUND)),
            Some("continuity") => {
                self.refuse_for_continuity(run_id);
                Err(CatalogError::Conflict(CONTINUITY_MISMATCH))
            }
            Some("incarnation") => Err(CatalogError::Conflict(
                "active deployment incarnation or Redis authority run",
            )),
            // No token re-binding was attempted: why not decides the class.
            Some("run") if persistence_unsound => Err(CatalogError::Conflict(PERSISTENCE_UNSOUND)),
            Some("run") => Err(CatalogError::Conflict(RUN_BINDING_CHANGED)),
            _ => Err(CatalogError::Serialization(
                "invalid Redis run binding reply".into(),
            )),
        }
    }
}

/// Transport-loss signal and run binding shared by every lane of one catalog.
#[derive(Default)]
pub(super) struct LaneGroup {
    loss_generation: AtomicU64,
    binding: RunBinding,
}

impl LaneGroup {
    pub(super) fn binding(&self) -> &RunBinding {
        &self.binding
    }
}

struct LaneState {
    connection: Option<MultiplexedConnection>,
    /// The Redis run the current connection was verified against.
    verified_run_id: String,
    /// The group loss generation this connection was last verified against.
    verified_generation: u64,
    /// Advanced whenever the connection slot is cleared or replaced, so a
    /// caller that observed a loss on an older connection cannot release one
    /// that a sibling caller has since re-established.
    connection_generation: u64,
}

pub(super) struct AuthorityLane {
    client: redis::Client,
    group: Arc<LaneGroup>,
    state: Mutex<LaneState>,
}

/// A verified connection handed to one caller, and the run it belongs to.
struct Admitted {
    connection: MultiplexedConnection,
    connection_generation: u64,
    run_id: String,
}

impl AuthorityLane {
    pub(super) fn new(
        client: redis::Client,
        connection: MultiplexedConnection,
        verified_run_id: String,
        group: Arc<LaneGroup>,
    ) -> Self {
        group.binding.initialize(&verified_run_id);
        let verified_generation = group.loss_generation.load(Ordering::Acquire);
        Self {
            client,
            group,
            state: Mutex::new(LaneState {
                connection: Some(connection),
                verified_run_id,
                verified_generation,
                connection_generation: 0,
            }),
        }
    }

    /// Run one bounded command on this lane.
    ///
    /// A transport failure releases the lane's connection so the *next*
    /// command reconnects; the failed command itself is never retried and its
    /// error is returned unchanged.
    pub(super) async fn query<T: FromRedisValue>(
        &self,
        command: &redis::Cmd,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection, _run_id| command.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    /// Run one script on this lane.  Every argument equal to
    /// `bound_run_id()` is replaced, after the lane has verified its
    /// connection, by the run that connection was verified against, so a
    /// script's run fence always names the run it executes on -- including
    /// the first command after the lane adopted a new run.
    ///
    /// With `owner_write` the script is an owner-affecting write.  Once it
    /// has been dispatched, a lost reply no longer proves the write failed:
    /// the script may have committed on the authority before the reply
    /// deadline passed or the connection was severed.  Those two failures are
    /// reported as the typed [`CatalogError::WriteOutcomeUnknown`] so the
    /// caller can stay unready until it re-reads the authority; a failure
    /// before dispatch (lane admission) and an actual authority reply keep
    /// their definite shapes.  The write itself is never replayed.
    pub(super) async fn query_eval<T: FromRedisValue>(
        &self,
        script: &str,
        keys: &[String],
        args: &[String],
        owner_write: bool,
    ) -> Result<T, CatalogError> {
        let dispatched = if owner_write {
            DispatchedFailure::Unknown
        } else {
            DispatchedFailure::Definite
        };
        let placeholder = bound_run_id();
        // Only the catalog's own placeholder may start with the marker, so no
        // caller-supplied value is ever taken for it.
        if args
            .iter()
            .any(|arg| arg.starts_with(BOUND_RUN_MARKER) && arg != placeholder)
        {
            return Err(CatalogError::InvalidInput(
                "script argument starts with a reserved control character",
            ));
        }
        self.execute(
            async |connection, run_id| {
                let args: Vec<String> = args
                    .iter()
                    .map(|arg| {
                        if arg == placeholder {
                            run_id.to_owned()
                        } else {
                            arg.clone()
                        }
                    })
                    .collect();
                eval_command(script, keys, &args)
                    .query_async::<T>(connection)
                    .await
            },
            dispatched,
        )
        .await
    }

    /// Run one bounded pipeline on this lane with the same failure contract
    /// as [`Self::query`].
    pub(super) async fn query_pipeline<T: FromRedisValue>(
        &self,
        pipeline: &redis::Pipeline,
    ) -> Result<T, CatalogError> {
        self.execute(
            async |connection, _run_id| pipeline.query_async::<T>(connection).await,
            DispatchedFailure::Definite,
        )
        .await
    }

    async fn execute<T>(
        &self,
        operation: impl AsyncFnOnce(&mut MultiplexedConnection, &str) -> Result<T, RedisError>,
        dispatched: DispatchedFailure,
    ) -> Result<T, CatalogError> {
        let Admitted {
            mut connection,
            connection_generation,
            run_id,
        } = self.admit().await?;
        // The lane lock is no longer held: this deadline covers only the
        // authority's handling of the caller's own command.  From here on the
        // command may have reached the authority, so `dispatched` decides
        // how a lost reply is reported.
        match tokio::time::timeout(REDIS_OPERATION_TIMEOUT, operation(&mut connection, &run_id))
            .await
        {
            Ok(Ok(value)) => {
                self.group.binding.contact();
                Ok(value)
            }
            // A reply that missed the deadline is a timeout however it was
            // observed.  redis-rs's own response timeout (set to the same
            // bound, and surfacing as an I/O `TimedOut`) and this outer
            // deadline race for the same instant; which one wins used to
            // decide whether the lane kept a connection that still owes the
            // stalled reply (M7-C113).  Both now release it, so the next
            // command re-verifies the primary on a fresh connection instead
            // of queueing its reply behind the stalled one, and both report
            // the typed timeout rather than, for an owner write, a lost
            // connection.  The command itself is never replayed.
            Ok(Err(error)) if error.is_timeout() => {
                self.release_lost(connection_generation).await;
                Err(dispatched.timeout())
            }
            Ok(Err(error)) => {
                let lost = lane_lost(&error);
                if lost {
                    // Release the dead connection and tell sibling lanes to
                    // probe theirs.  This command stays failed and is never
                    // replayed.
                    self.release_lost(connection_generation).await;
                }
                Err(dispatched.classify(error, lost))
            }
            Err(_) => {
                self.release_lost(connection_generation).await;
                Err(dispatched.timeout())
            }
        }
    }

    /// Hand out a handle to this lane's verified physical connection.
    ///
    /// Waiting for the lane lock is not part of any authority deadline: the
    /// lock is only ever held across the bounded probe or reconnect in
    /// [`Self::verify`], so a caller queued behind a sibling waits at most one
    /// such verification and then shares the same multiplexed connection.
    /// A verification that exceeds its deadline leaves the lane state as it
    /// found it; a caller's command that times out releases the connection
    /// (see [`Self::execute`]).
    async fn admit(&self) -> Result<Admitted, CatalogError> {
        let mut state = self.state.lock().await;
        tokio::time::timeout(REDIS_OPERATION_TIMEOUT, self.verify(&mut state))
            .await
            .map_err(|_| CatalogError::Database(redis_timeout()))?
    }

    async fn verify(&self, state: &mut LaneState) -> Result<Admitted, CatalogError> {
        let loss_generation = self.group.loss_generation.load(Ordering::Acquire);
        if state.verified_generation != loss_generation
            && let Some(connection) = state.connection.as_mut()
        {
            // A sibling lane observed a transport loss since this
            // connection was last verified.  Probe before the caller's
            // command so a connection severed by the same event
            // reconnects here instead of failing this caller closed.
            match redis::cmd("PING").query_async::<String>(connection).await {
                Ok(_) => {}
                Err(error) if lane_lost(&error) => {
                    state.connection = None;
                    state.connection_generation += 1;
                }
                Err(error) => return Err(CatalogError::Database(error)),
            }
        }
        if state.connection.is_none() {
            let (connection, run_id) = self.reconnect().await?;
            state.connection = Some(connection);
            state.verified_run_id = run_id;
            state.connection_generation += 1;
        }
        state.verified_generation = loss_generation;
        let connection = state
            .connection
            .clone()
            .ok_or(CatalogError::Conflict("Redis authority lane"))?;
        Ok(Admitted {
            connection,
            connection_generation: state.connection_generation,
            run_id: state.verified_run_id.clone(),
        })
    }

    /// Release the connection a caller observed a transport loss on, unless a
    /// sibling caller already released or replaced it.  Only the first
    /// observer of one loss advances the group loss generation.
    async fn release_lost(&self, connection_generation: u64) {
        let mut state = self.state.lock().await;
        if state.connection_generation == connection_generation && state.connection.is_some() {
            state.connection = None;
            state.connection_generation += 1;
            self.group.loss_generation.fetch_add(1, Ordering::AcqRel);
        }
    }

    async fn reconnect(&self) -> Result<(MultiplexedConnection, String), CatalogError> {
        let (mut connection, run_id) = open_verified_connection(&self.client)
            .await
            .map_err(CatalogConnectionError::into_catalog_error)?;
        // A different run is adopted only when the namespace proves it may
        // (see the module documentation); until then no caller command runs
        // on this connection.
        self.group.binding.rebind(&mut connection, &run_id).await?;
        Ok((connection, run_id))
    }
}

/// How a failure observed after the command was handed to the connection is
/// reported.  Reads and non-owner writes keep the definite `Database` shape;
/// owner-affecting writes report a lost reply as the typed unknown outcome.
#[derive(Clone, Copy)]
enum DispatchedFailure {
    Definite,
    Unknown,
}

impl DispatchedFailure {
    fn classify(self, error: RedisError, lost: bool) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(error),
            Self::Unknown if lost => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ConnectionLost)
            }
            Self::Unknown if error.is_timeout() => {
                CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout)
            }
            // An actual authority reply (server error, parse failure) is a
            // definite outcome even for an owner write.
            Self::Unknown => CatalogError::Database(error),
        }
    }

    fn timeout(self) -> CatalogError {
        match self {
            Self::Definite => CatalogError::Database(redis_timeout()),
            Self::Unknown => CatalogError::WriteOutcomeUnknown(UnknownWriteCause::ReplyTimeout),
        }
    }
}

/// Whether a command failure means the physical connection is gone.  Server
/// replies and parse failures keep the connection; a reply timeout is
/// classified before this is consulted and releases it.
fn lane_lost(error: &RedisError) -> bool {
    error.is_io_error() || error.is_connection_dropped()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        collections::VecDeque,
        sync::{
            Mutex as StdMutex,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::{TcpListener, TcpStream},
        sync::{Mutex as AsyncMutex, oneshot},
        task::JoinSet,
    };

    const TEST_DEADLINE: Duration = Duration::from_secs(5);
    const MAX_REQUEST_BYTES: usize = 16 * 1024;
    const MAX_PENDING_REPLIES: usize = 1_024;
    /// Concurrent callers on one lane in the queueing regression.  With the
    /// per-reply delay below, serializing them takes three seconds while any
    /// single reply arrives well inside the two-second operation deadline.
    const QUEUED_CALLERS: usize = 20;
    const QUEUED_REPLY_DELAY: Duration = Duration::from_millis(150);
    /// A stalled authority: one reply takes longer than the operation
    /// deadline even with no other caller queued.
    const STALLED_REPLY_DELAY: Duration = Duration::from_millis(2_600);

    /// A bounded RESP2 authority double: answers the redis-rs handshake,
    /// `PING`, and `INFO` with a configurable `run_id`, and can sever any
    /// accepted connection while keeping its listener.
    struct FakeAuthority {
        port: u16,
        run_id: Arc<AsyncMutex<String>>,
        /// Delay applied to every reply, measured from the command's arrival.
        /// Replies stay in command order but are delayed concurrently, like a
        /// network path that adds latency to each reply rather than a server
        /// that spends that long on each command.
        reply_delay_ms: Arc<AtomicU64>,
        severs: Arc<StdMutex<Vec<Option<oneshot::Sender<()>>>>>,
        active: Arc<AtomicUsize>,
        shutdown: Option<oneshot::Sender<()>>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    impl FakeAuthority {
        async fn start(run_id: &str) -> Self {
            Self::start_with_reply_delay(run_id, Duration::ZERO).await
        }

        async fn start_with_reply_delay(run_id: &str, reply_delay: Duration) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind fake authority");
            let port = listener
                .local_addr()
                .expect("fake authority address")
                .port();
            let run_id = Arc::new(AsyncMutex::new(run_id.to_owned()));
            let reply_delay_ms = Arc::new(AtomicU64::new(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
            ));
            let severs = Arc::new(StdMutex::new(Vec::new()));
            let active = Arc::new(AtomicUsize::new(0));
            let (shutdown_tx, shutdown_rx) = oneshot::channel();
            let task = tokio::spawn(run_fake_authority(
                listener,
                Arc::clone(&run_id),
                Arc::clone(&reply_delay_ms),
                Arc::clone(&severs),
                Arc::clone(&active),
                shutdown_rx,
            ));
            Self {
                port,
                run_id,
                reply_delay_ms,
                severs,
                active,
                shutdown: Some(shutdown_tx),
                task: Some(task),
            }
        }

        fn set_reply_delay(&self, reply_delay: Duration) {
            self.reply_delay_ms.store(
                u64::try_from(reply_delay.as_millis()).expect("bounded reply delay"),
                Ordering::Release,
            );
        }

        fn url(&self) -> String {
            format!("redis://127.0.0.1:{}/", self.port)
        }

        /// Connections accepted so far, in accept order.
        fn accepted(&self) -> usize {
            self.severs.lock().expect("sever registry").len()
        }

        async fn set_run_id(&self, run_id: &str) {
            *self.run_id.lock().await = run_id.to_owned();
        }

        /// Sever the connection with this accept index and wait until the
        /// server has dropped it.  The listener keeps accepting.
        async fn sever(&self, index: usize) {
            let before = self.active.load(Ordering::Acquire);
            let sender = self
                .severs
                .lock()
                .expect("sever registry")
                .get_mut(index)
                .and_then(Option::take)
                .expect("connection index was accepted and not yet severed");
            sender.send(()).expect("connection task is live");
            self.wait_active(before - 1).await;
        }

        /// Sever every live connection and wait until all are dropped.
        async fn sever_all(&self) {
            let senders: Vec<_> = self
                .severs
                .lock()
                .expect("sever registry")
                .iter_mut()
                .filter_map(Option::take)
                .collect();
            for sender in senders {
                let _ = sender.send(());
            }
            self.wait_active(0).await;
        }

        async fn wait_active(&self, expected: usize) {
            let deadline = tokio::time::Instant::now() + TEST_DEADLINE;
            while self.active.load(Ordering::Acquire) != expected {
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "fake authority did not sever its connections"
                );
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        }

        async fn shutdown(mut self) {
            if let Some(shutdown) = self.shutdown.take() {
                let _ = shutdown.send(());
            }
            if let Some(task) = self.task.take() {
                tokio::time::timeout(TEST_DEADLINE, task)
                    .await
                    .expect("fake authority shutdown deadline")
                    .expect("fake authority task");
            }
        }
    }

    async fn run_fake_authority(
        listener: TcpListener,
        run_id: Arc<AsyncMutex<String>>,
        reply_delay_ms: Arc<AtomicU64>,
        severs: Arc<StdMutex<Vec<Option<oneshot::Sender<()>>>>>,
        active: Arc<AtomicUsize>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown => {
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                    return;
                }
                accepted_stream = listener.accept() => {
                    let Ok((stream, _)) = accepted_stream else { return; };
                    let (sever_tx, sever_rx) = oneshot::channel();
                    active.fetch_add(1, Ordering::AcqRel);
                    severs.lock().expect("sever registry").push(Some(sever_tx));
                    connections.spawn(serve_fake_connection(
                        stream,
                        Arc::clone(&run_id),
                        Arc::clone(&reply_delay_ms),
                        sever_rx,
                        Arc::clone(&active),
                    ));
                }
                Some(_) = connections.join_next() => {}
            }
        }
    }

    async fn serve_fake_connection(
        mut stream: TcpStream,
        run_id: Arc<AsyncMutex<String>>,
        reply_delay_ms: Arc<AtomicU64>,
        mut sever: oneshot::Receiver<()>,
        active: Arc<AtomicUsize>,
    ) {
        let mut pending = Vec::new();
        let mut buffer = [0_u8; 1024];
        // Replies due in command order; each is written once its own delay,
        // counted from the command's arrival, has elapsed.
        let mut due: VecDeque<(tokio::time::Instant, Vec<u8>)> = VecDeque::new();
        loop {
            let next_due = due.front().map(|(at, _)| *at);
            tokio::select! {
                // Dropping the stream is the injected transport loss.
                _ = &mut sever => break,
                read = stream.read(&mut buffer) => {
                    let read = match read {
                        Ok(0) | Err(_) => break,
                        Ok(read) => read,
                    };
                    pending.extend_from_slice(&buffer[..read]);
                    if pending.len() > MAX_REQUEST_BYTES {
                        break;
                    }
                    let delay = Duration::from_millis(reply_delay_ms.load(Ordering::Acquire));
                    let arrived = tokio::time::Instant::now();
                    while let Some((command, consumed)) = parse_command(&pending) {
                        pending.drain(..consumed);
                        let reply = match command.as_str() {
                            "CLIENT" => b"+OK\r\n".to_vec(),
                            "PING" => b"+PONG\r\n".to_vec(),
                            "INFO" => {
                                let body =
                                    format!("# Server\r\nrun_id:{}\r\n", run_id.lock().await);
                                format!("${}\r\n{body}\r\n", body.len()).into_bytes()
                            }
                            _ => b"-ERR unsupported fake authority command\r\n".to_vec(),
                        };
                        due.push_back((arrived + delay, reply));
                    }
                    if due.len() > MAX_PENDING_REPLIES {
                        break;
                    }
                }
                _ = async {
                    match next_due {
                        Some(at) => tokio::time::sleep_until(at).await,
                        None => std::future::pending::<()>().await,
                    }
                } => {
                    let Some((_, reply)) = due.pop_front() else { continue };
                    if stream.write_all(&reply).await.is_err() {
                        break;
                    }
                }
            }
        }
        active.fetch_sub(1, Ordering::AcqRel);
    }

    /// Parse one complete RESP2 command array, returning its upper-cased
    /// name and the consumed byte count, or `None` while incomplete.
    fn parse_command(bytes: &[u8]) -> Option<(String, usize)> {
        let (count_line, mut offset) = resp_line(bytes, 0)?;
        let count: usize = std::str::from_utf8(count_line.strip_prefix(b"*")?)
            .ok()?
            .parse()
            .ok()?;
        let mut name = None;
        for index in 0..count {
            let (length_line, next) = resp_line(bytes, offset)?;
            let length: usize = std::str::from_utf8(length_line.strip_prefix(b"$")?)
                .ok()?
                .parse()
                .ok()?;
            let end = next.checked_add(length)?;
            if bytes.len() < end.checked_add(2)? {
                return None;
            }
            if index == 0 {
                name = Some(String::from_utf8_lossy(&bytes[next..end]).to_ascii_uppercase());
            }
            offset = end + 2;
        }
        Some((name?, offset))
    }

    fn resp_line(bytes: &[u8], start: usize) -> Option<(&[u8], usize)> {
        let rest = bytes.get(start..)?;
        let end = rest.windows(2).position(|window| window == b"\r\n")?;
        Some((&rest[..end], start + end + 2))
    }

    async fn verified_lane(
        client: &redis::Client,
        expected_run_id: &str,
        group: &Arc<LaneGroup>,
    ) -> AuthorityLane {
        let (connection, run_id) =
            tokio::time::timeout(TEST_DEADLINE, open_verified_connection(client))
                .await
                .expect("bounded startup connection")
                .expect("verified startup connection");
        assert_eq!(run_id, expected_run_id);
        AuthorityLane::new(client.clone(), connection, run_id, Arc::clone(group))
    }

    async fn ping(lane: &AuthorityLane) -> Result<String, CatalogError> {
        tokio::time::timeout(TEST_DEADLINE, lane.query::<String>(&redis::cmd("PING")))
            .await
            .expect("bounded lane command")
    }

    fn assert_lost(result: Result<String, CatalogError>, context: &str) {
        match result {
            Err(CatalogError::Database(error)) if lane_lost(&error) => {}
            Err(other) => panic!("{context}: reported {other} instead of a transport loss"),
            Ok(reply) => panic!("{context}: succeeded with {reply} on a severed connection"),
        }
    }

    #[tokio::test]
    async fn severed_lane_fails_once_then_reconnects_only_to_the_same_primary() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(ping(&lane).await.expect("healthy lane"), "PONG");
        assert_eq!(server.accepted(), 1);

        server.sever_all().await;
        assert_lost(ping(&lane).await, "severed lane");
        assert_eq!(
            server.accepted(),
            1,
            "the failed command must neither retry nor reconnect"
        );

        server.set_run_id("lane-run-b").await;
        for _ in 0..2 {
            let refused = ping(&lane)
                .await
                .expect_err("a changed primary identity must be refused");
            assert!(
                matches!(refused, CatalogError::Conflict(RUN_ID_CONFLICT)),
                "changed primary reported {refused}"
            );
        }
        assert_eq!(
            server.accepted(),
            3,
            "each refused reconnect verifies identity on a fresh connection"
        );

        server.set_run_id("lane-run-a").await;
        assert_eq!(ping(&lane).await.expect("same primary reconnects"), "PONG");
        assert_eq!(
            ping(&lane).await.expect("reconnected lane is reused"),
            "PONG"
        );
        assert_eq!(server.accepted(), 4);
        server.shutdown().await;
    }

    #[tokio::test]
    async fn sibling_lanes_probe_after_a_loss_without_failing_their_callers() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let discovering = verified_lane(&client, "lane-run-a", &group).await;
        let severed_sibling = verified_lane(&client, "lane-run-a", &group).await;
        let live_sibling = verified_lane(&client, "lane-run-a", &group).await;
        assert_eq!(server.accepted(), 3);

        // Connections 0 and 1 are lost by the same event; connection 2 stays.
        server.sever(0).await;
        server.sever(1).await;
        assert_lost(ping(&discovering).await, "discovering lane");
        assert_eq!(server.accepted(), 3, "discovery never reconnects in place");

        assert_eq!(
            ping(&severed_sibling)
                .await
                .expect("a severed sibling reconnects before its caller's command"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the severed sibling opened one connection"
        );
        assert_eq!(
            ping(&live_sibling)
                .await
                .expect("a live sibling passes its probe and keeps its connection"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            4,
            "the live sibling opened no connection"
        );

        assert_eq!(
            ping(&discovering)
                .await
                .expect("the discovering lane reconnects on its next command"),
            "PONG"
        );
        assert_eq!(server.accepted(), 5);
        for lane in [&discovering, &severed_sibling, &live_sibling] {
            assert_eq!(ping(lane).await.expect("verified lanes are reused"), "PONG");
        }
        assert_eq!(server.accepted(), 5, "no further probe reconnects");
        server.shutdown().await;
    }

    fn timed_out(error: &RedisError) -> bool {
        error.is_timeout()
    }

    /// M7-C32 regression: callers queued on one lane must be measured
    /// against the authority's reply, not against each other.  Twenty
    /// callers whose replies each take 150 ms would take three seconds if the
    /// lane served them one at a time, so the last of them would report a
    /// two-second "authority timeout" that Redis never caused.  A genuinely
    /// stalled reply and a severed connection must still fail closed, with
    /// distinguishable transport classes and no reconnect in place.
    #[tokio::test]
    async fn queued_callers_are_measured_against_the_authority_not_the_queue() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(verified_lane(&client, "lane-run-a", &group).await);
        assert_eq!(server.accepted(), 1);

        let started = tokio::time::Instant::now();
        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { ping(&lane).await });
        }
        let mut replies = Vec::with_capacity(QUEUED_CALLERS);
        while let Some(joined) = callers.join_next().await {
            replies.push(joined.expect("queued caller task"));
        }
        let elapsed = started.elapsed();
        let failures: Vec<String> = replies
            .iter()
            .filter_map(|reply| reply.as_ref().err().map(ToString::to_string))
            .collect();
        assert!(
            failures.is_empty(),
            "{} of {QUEUED_CALLERS} queued callers failed after {elapsed:?} although every \
             reply took {QUEUED_REPLY_DELAY:?}: {failures:?}",
            failures.len()
        );
        assert!(
            elapsed < REDIS_OPERATION_TIMEOUT,
            "queued callers took {elapsed:?}; the lane serialized them behind each other"
        );
        assert_eq!(server.accepted(), 1, "queueing must not open connections");

        // A reply that genuinely exceeds the deadline is a timeout, reported
        // as such rather than as a severed connection.  The stalled command
        // is never retried; the lane releases the connection so the next
        // command re-verifies the primary before it is trusted again.
        server.set_reply_delay(STALLED_REPLY_DELAY);
        let stalled_started = tokio::time::Instant::now();
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                timed_out(&error) && !error.is_connection_dropped(),
                "stalled authority reported {error} instead of a timeout"
            ),
            other => panic!("stalled authority reported {other:?} instead of a timeout"),
        }
        assert!(
            stalled_started.elapsed() >= REDIS_OPERATION_TIMEOUT,
            "the authority deadline fired before the documented bound"
        );
        assert_eq!(server.accepted(), 1, "a timeout never reconnects in place");
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(
            ping(&lane)
                .await
                .expect("the command after a timeout re-verifies the same primary"),
            "PONG"
        );
        assert_eq!(server.accepted(), 2);

        // A severed connection is a transport loss, never a timeout, and the
        // discovering command fails closed exactly once.
        server.sever_all().await;
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                lane_lost(&error) && !timed_out(&error),
                "severed lane reported {error} instead of a transport loss"
            ),
            other => panic!("severed lane reported {other:?} instead of a transport loss"),
        }
        assert_eq!(
            server.accepted(),
            2,
            "the discovering command never reconnects"
        );
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects"),
            "PONG"
        );
        assert_eq!(server.accepted(), 3);
        server.shutdown().await;
    }

    /// Callers that observe the same loss concurrently release the lane once
    /// and advance the group loss generation once; a sibling that has already
    /// reconnected is never released by a late observer.
    #[tokio::test]
    async fn concurrent_loss_observers_release_the_lane_once() {
        let server = FakeAuthority::start_with_reply_delay("lane-run-a", QUEUED_REPLY_DELAY).await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let lane = Arc::new(verified_lane(&client, "lane-run-a", &group).await);

        let mut callers = JoinSet::new();
        for _ in 0..QUEUED_CALLERS {
            let lane = Arc::clone(&lane);
            callers.spawn(async move { ping(&lane).await });
        }
        // Every caller is in flight behind the delayed replies when the
        // connection is severed, so all of them observe the same loss.
        tokio::time::sleep(QUEUED_REPLY_DELAY / 3).await;
        server.sever_all().await;
        while let Some(joined) = callers.join_next().await {
            assert_lost(joined.expect("queued caller task"), "concurrent observer");
        }
        assert_eq!(
            group.loss_generation.load(Ordering::Acquire),
            1,
            "one loss event advances the group generation once"
        );
        assert_eq!(server.accepted(), 1, "no observer reconnects in place");
        assert_eq!(
            ping(&lane).await.expect("the next command reconnects once"),
            "PONG"
        );
        assert_eq!(server.accepted(), 2);
        server.shutdown().await;
    }

    #[test]
    fn lane_loss_classification_is_transport_only() {
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::BrokenPipe
        ))));
        assert!(lane_lost(&RedisError::from(std::io::Error::from(
            std::io::ErrorKind::ConnectionReset
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::UnexpectedReturnType,
            "wrong value type"
        ))));
        assert!(!lane_lost(&RedisError::from((
            redis::ErrorKind::Parse,
            "malformed reply"
        ))));
    }

    /// M6-C65 review: a token re-binding needs a token acknowledged at most
    /// one interval plus the command deadlines (and one second) before the
    /// last reply from Redis; a loop that stopped or kept failing while
    /// Redis answered leaves a larger gap and is refused.
    #[test]
    fn a_token_is_fresh_only_within_one_interval_of_the_last_reply() {
        let interval = Duration::from_secs(5);
        let bound = 5_000 + 2 * 2_000 + 1_000;
        assert!(token_is_fresh(Some(10_000), 10_000, interval));
        assert!(token_is_fresh(Some(10_000), 10_000 + bound, interval));
        assert!(!token_is_fresh(Some(10_000), 10_000 + bound + 1, interval));
        assert!(!token_is_fresh(None, 0, interval), "no acknowledged token");
        // A reply recorded before the acknowledgement is not a gap.
        assert!(token_is_fresh(Some(10_000), 9_000, interval));
    }

    /// M6-C65 review: all three settings, exactly.
    #[test]
    fn persistence_needs_aof_always_and_fsync_during_rewrite() {
        let pairs = |fsync: &str, rewrite: &str, aof: &str| -> Vec<String> {
            [
                "appendonly",
                aof,
                "appendfsync",
                fsync,
                "no-appendfsync-on-rewrite",
                rewrite,
            ]
            .map(str::to_owned)
            .to_vec()
        };
        assert!(persistence_is_sound(&pairs("always", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("everysec", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("no", "no", "yes")));
        assert!(!persistence_is_sound(&pairs("always", "yes", "yes")));
        assert!(!persistence_is_sound(&pairs("always", "no", "no")));
        assert!(!persistence_is_sound(&[]), "a refused or empty CONFIG GET");
    }

    /// M7-C113 regression: a reply timeout reported by the lane's own outer
    /// deadline releases the connection exactly as one reported by redis-rs.
    ///
    /// The startup connection here has no redis-rs response timeout, so the
    /// outer deadline is the only one that can fire.  Before the fix that
    /// branch kept the connection still owed the stalled reply, and the next
    /// command queued behind it instead of re-verifying on a fresh one.
    #[tokio::test]
    async fn an_outer_deadline_timeout_releases_the_connection() {
        let server = FakeAuthority::start("lane-run-a").await;
        let client = redis::Client::open(server.url()).expect("fake authority URL");
        let group = Arc::new(LaneGroup::default());
        let config = redis::AsyncConnectionConfig::new().set_response_timeout(None);
        let connection = tokio::time::timeout(
            TEST_DEADLINE,
            client.get_multiplexed_async_connection_with_config(&config),
        )
        .await
        .expect("bounded startup connection")
        .expect("startup connection without a response timeout");
        let lane = AuthorityLane::new(
            client.clone(),
            connection,
            "lane-run-a".to_owned(),
            Arc::clone(&group),
        );
        assert_eq!(server.accepted(), 1);

        server.set_reply_delay(STALLED_REPLY_DELAY);
        match ping(&lane).await {
            Err(CatalogError::Database(error)) => assert!(
                timed_out(&error),
                "the outer deadline reported {error} instead of a timeout"
            ),
            other => panic!("stalled authority reported {other:?} instead of a timeout"),
        }
        server.set_reply_delay(Duration::ZERO);
        assert_eq!(
            ping(&lane)
                .await
                .expect("the command after a timeout re-verifies the primary"),
            "PONG"
        );
        assert_eq!(
            server.accepted(),
            2,
            "the timed-out connection must be replaced, not reused"
        );
    }
}
