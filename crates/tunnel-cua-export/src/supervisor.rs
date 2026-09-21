//! The join: lifecycle from [`crate::child`], health from [`crate::health`],
//! and a restart that cannot forget to invalidate.
//!
//! # The join is one-directional, on purpose
//!
//! A running process is never *reported* as working — [`Supervisor::health`]
//! returns [`Health::Started`] until a probe has answered, and only
//! [`Supervisor::assess`] can move it on. In the other direction, a working
//! verdict **from this type** implies a running process, because
//! [`Supervisor::assess`] checks the lifecycle first and returns
//! [`Health::Exited`] for a backend that has gone whatever the probe said.
//! That asymmetry is the separation: it is why "the backend is up" cannot be
//! quietly substituted for "the backend can act".
//!
//! **The second half is a property of this route, not of the [`Health`] type.**
//! `crate::health::assess` is crate-private precisely because it cannot make
//! that check — it sees no process — and review obtained a `Working` verdict
//! from it with nothing running. Nor is either half proof against a caller
//! that fabricates a dispatch: `Dispatch` and `Completion` are public enums
//! with public payloads, so a `Dispatched(Ok(..))` that never happened is a
//! value anyone can write. This is a tightening against mistakes. See
//! [`crate::health`]'s header.
//!
//! # Why the invalidation cannot be skipped
//!
//! [`Supervisor::stop`] and [`Supervisor::restart`] take an
//! [`InputAuthority`] as a **required argument**. There is no variant that
//! ends a backend's life without it, so the restart contract is enforced by
//! the signature rather than by whoever calls it remembering. A caller that
//! genuinely has nothing to invalidate passes something that frees nothing and
//! [`tunnel_cua::supervision::Invalidation::freed_anything`] says so.
//!
//! # And why the endpoint is re-read on every start
//!
//! The backend publishes the loopback address it bound; the supervisor reads
//! it back and puts it through [`BackendEndpoint`], which refuses anything
//! that is not loopback. The address file is **removed before every start**,
//! so a stale file from the generation just killed cannot be read as the new
//! backend's address — which would hand consumers a port belonging to a dead
//! process, or to whatever bound it next.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tunnel_cua::endpoint::{BackendEndpoint, EndpointError};
use tunnel_cua::supervision::{BackendGeneration, Invalidation, LifecycleEpoch};

use crate::child::{BackendChild, ChildCounters, SpawnError, spawn};
use crate::config::{ADDRESS_POLL, BackendProcess};
use crate::health::Health;

/// The device-side state a restart must invalidate.
///
/// A trait rather than the registries themselves, because the registries live
/// behind the device's own locks and this crate must not own them — and
/// because `std::env::set_var` is `unsafe` since the 2024 edition, so every
/// predicate this crate needs is injected rather than reached for.
///
/// Implementors do exactly one thing: call
/// [`tunnel_cua::supervision::invalidate`] over both registries and report
/// what it freed. It is **not** a hook with a choice in it: there is no
/// correct implementation that keeps a lease.
pub trait InputAuthority {
    /// Drop every input lease and forget every capture identity, stamping the
    /// new generation, and report what was freed.
    fn invalidate(&self, generation: BackendGeneration) -> Invalidation;
}

/// A [`LifecycleEpoch`] a dispatcher can read while the supervisor owning it
/// is busy elsewhere.
///
/// **Shared by clone, published by exactly one writer.** The supervisor is the
/// only holder that ever calls [`LifecycleEpochHandle::disturb`]; every other
/// holder reads.
///
/// The store is `Release` and the loads `Acquire`, which is the conservative
/// choice rather than a load-bearing one, and **the earlier note here
/// overclaimed what it buys.** Rust's memory model orders this store against
/// other Rust memory operations; it does not order it against a `kill`
/// syscall in another process's address space. What actually makes the
/// ordering work is program order — `disturb()` is executed before `kill()` is
/// issued — and the operating system, which is the edge that carries the
/// socket close to the dispatcher. `Relaxed` would almost certainly be
/// sufficient for a single `u64` counter read for equality; the stronger
/// ordering is kept because it costs nothing measurable here and because a
/// future reader adding a second field would be right to expect it.
///
/// # This is not a clock and not a lock
///
/// A dispatcher reading a changed epoch learns that the supervisor *began* a
/// disturbance somewhere across its exchange. It does not learn when, and it
/// must not: an exchange that failed for an unrelated reason during a restart
/// is still correctly attributed to the restart, because after a restart
/// nobody can establish which of the two it was. Attribution is deliberately
/// the pessimistic reading, and
/// [`tunnel_cua::supervision::attribute_restart`] keeps it from ever being
/// the more retryable one.
///
/// # It advances on every stop, including the ones that never restart
///
/// [`Supervisor::stop`] advances it unconditionally, so a bare stop, a
/// `restart` whose `start` fails, and a stop with nothing running all rename
/// an in-flight `Unknown(_)` to `BackendRestarted`. Each of those really did
/// take the backend away underneath the exchange, so the verdict is right and
/// only the word overstates the sequel; **retryability is identical on every
/// one of those paths**, so it cannot produce a second click. Advancing only
/// on a *successful* restart would reintroduce the race this type exists to
/// remove. See `attribute_restart`'s own documentation.
#[derive(Clone, Debug, Default)]
pub struct LifecycleEpochHandle(Arc<AtomicU64>);

impl LifecycleEpochHandle {
    /// A detached handle that nothing advances.
    ///
    /// For a dispatcher built without a supervisor — a fixture talking to a
    /// backend it did not spawn. Its epoch never changes, so attribution is a
    /// no-op and the transport's own reason survives, which is the honest
    /// answer when there is no supervisor to blame.
    #[must_use]
    pub fn detached() -> Self {
        Self::default()
    }

    /// The current epoch.
    #[must_use]
    pub fn read(&self) -> LifecycleEpoch {
        LifecycleEpoch::new(self.0.load(Ordering::Acquire))
    }

    /// Announce that the supervisor is about to disturb the backend.
    ///
    /// **Called before the disturbance, never after**, which is the entire
    /// correctness argument; see [`LifecycleEpoch`]'s own documentation for
    /// why the [`BackendGeneration`] counter cannot be used in its place.
    fn disturb(&self) {
        self.0.fetch_add(1, Ordering::Release);
    }
}

/// Why a backend could not be started.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StartError {
    /// A backend is already running under this supervisor.
    AlreadyRunning,
    /// No process could be created.
    Spawn,
    /// The backend did not publish an address within its startup wait.
    NoAddress,
    /// The backend published something that is not a usable loopback address.
    ///
    /// **The process is killed when this happens.** A backend listening
    /// somewhere this device will not talk to is a backend that any local
    /// process can drive while the tunnel path refuses to, which is worse
    /// than no backend at all.
    Endpoint(EndpointError),
}

impl core::fmt::Display for StartError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::AlreadyRunning => formatter.write_str("a backend is already running"),
            Self::Spawn => formatter.write_str("the backend process could not be started"),
            Self::NoAddress => formatter.write_str("the backend published no address in time"),
            Self::Endpoint(error) => {
                write!(formatter, "the backend's address is unusable: {error}")
            }
        }
    }
}

impl std::error::Error for StartError {}

/// One supervised `computer.v1` backend.
#[derive(Debug)]
pub struct Supervisor {
    process: BackendProcess,
    counters: Arc<ChildCounters>,
    generation: BackendGeneration,
    epoch: LifecycleEpochHandle,
    running: Option<Running>,
}

#[derive(Debug)]
struct Running {
    child: BackendChild,
    endpoint: BackendEndpoint,
}

impl Supervisor {
    /// Build a supervisor for one backend. Starts nothing.
    #[must_use]
    pub fn new(process: BackendProcess) -> Self {
        Self {
            process,
            counters: Arc::new(ChildCounters::default()),
            generation: BackendGeneration::INITIAL,
            epoch: LifecycleEpochHandle::detached(),
            running: None,
        }
    }

    /// A handle on this supervisor's lifecycle epoch, for a dispatcher that
    /// must attribute a failed exchange to a restart.
    ///
    /// Handed out by clone so the dispatcher can read it while the supervisor
    /// is inside `restart`. A dispatcher that never takes one attributes
    /// nothing, which is why this is the seam rather than a global.
    #[must_use]
    pub fn lifecycle_epoch(&self) -> LifecycleEpochHandle {
        self.epoch.clone()
    }

    /// The counters, for a diagnostic or a test that must read what happened
    /// rather than what was asked for.
    #[must_use]
    pub fn counters(&self) -> &Arc<ChildCounters> {
        &self.counters
    }

    /// Which generation of the backend is current.
    #[must_use]
    pub const fn generation(&self) -> BackendGeneration {
        self.generation
    }

    /// The running backend's loopback endpoint, if one is running.
    #[must_use]
    pub fn endpoint(&self) -> Option<BackendEndpoint> {
        self.running.as_ref().map(|running| running.endpoint)
    }

    /// The running backend's process id, which is also its group id.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.running.as_ref().map(|running| running.child.pid())
    }

    /// Whether a sentinel could be armed on this host at all.
    ///
    /// Answers before any child exists, which is the only moment a missing
    /// sentinel is cheap to fix. A
    /// [`tunnel_deadman::Availability::SentinelMissing`] here means this
    /// build will leak a supervised backend's process group on every crash of
    /// this process — for CUA, a process that can still drive a desktop.
    #[must_use]
    pub fn containment_availability() -> tunnel_deadman::Availability {
        tunnel_deadman::availability()
    }

    /// The lifecycle verdict, with **no probe involved**.
    ///
    /// It returns exactly three of [`Health`]'s five arms --
    /// [`Health::NotStarted`], [`Health::Started`] and [`Health::Exited`] --
    /// and **this function never returns [`Health::Working`]**: it is handed no
    /// [`ProbeEvidence`] and constructs none, so there is nothing for it to
    /// return one from. That is a statement about this function's three
    /// literal return values, which is all it was ever entitled to be; an
    /// earlier draft phrased it as "no path to `Working`", which reads as a
    /// claim about the *type* and is false — see [`crate::health`]'s header.
    /// Moving past `Started` requires [`Supervisor::assess`].
    ///
    /// [`ProbeEvidence`]: tunnel_cua::capability::ProbeEvidence
    #[must_use]
    pub fn health(&self) -> Health {
        match &self.running {
            None if self.generation.has_started() => Health::Exited,
            None => Health::NotStarted,
            Some(running) if running.child.has_exited() => Health::Exited,
            Some(_) => Health::Started,
        }
    }

    /// Fold a probe exchange into a verdict.
    ///
    /// **The public route, and the only one that checks the lifecycle.**
    /// Returns [`Health::Exited`] whatever the probe said if the process is
    /// gone: a probe answered by something other than the supervised process
    /// -- a stale reply, or a different process that took the port -- must not
    /// report the supervised process as working. `crate::health::assess` makes
    /// no such check and is crate-private for that reason.
    ///
    /// It does **not** establish that the exchange really happened; the
    /// `dispatch` argument is whatever the caller passes. See
    /// [`crate::health`]'s header for what the evidence type does and does not
    /// establish.
    #[must_use]
    pub fn assess(
        &self,
        request: &tunnel_cua::schema::Request,
        dispatch: &tunnel_cua::outcome::Dispatch,
    ) -> Health {
        let lifecycle = self.health();
        if !lifecycle.process_is_running() {
            return lifecycle;
        }
        crate::health::assess(request, dispatch)
    }

    /// Start the backend and return the loopback endpoint it published.
    ///
    /// # Errors
    /// [`StartError`] for a backend already running, a spawn failure, no
    /// address in time, or an address that is not loopback.
    pub async fn start(&mut self) -> Result<BackendEndpoint, StartError> {
        if self.running.is_some() {
            return Err(StartError::AlreadyRunning);
        }
        // **Before the spawn**, so a stale address from the generation just
        // killed cannot be read as this one's.
        let _ = tokio::fs::remove_file(&self.process.address_file).await;

        let child = spawn(&self.process, &self.counters).map_err(|SpawnError| StartError::Spawn)?;
        self.generation = self.generation.next();

        let endpoint = match read_endpoint(&self.process.address_file, self.process.startup).await {
            Ok(endpoint) => endpoint,
            Err(error) => {
                // Kill it rather than leave it listening somewhere this
                // device will not use: `AGENTS.md`'s trusted-local backend
                // label already means any local process can drive it, and an
                // abandoned one has no supervisor at all.
                child.kill();
                child.wait_exited().await;
                return Err(error);
            }
        };
        self.running = Some(Running { child, endpoint });
        Ok(endpoint)
    }

    /// Stop the backend and invalidate everything held against it.
    ///
    /// Returns what the invalidation freed. Stopping a backend that is not
    /// running still invalidates: the registries may hold state from a
    /// backend that died on its own, and a supervisor that only invalidated
    /// on the paths it drove would leave exactly the crashed-backend case
    /// uncovered.
    pub async fn stop(&mut self, authority: &dyn InputAuthority) -> Invalidation {
        // **Before the kill, and unconditionally.** Every exchange that could
        // see this backend's socket die must be guaranteed to read a changed
        // epoch afterwards, and an exchange racing us reads its "after" value
        // the instant the socket closes -- which is here, not at the
        // replacement's spawn. Advancing after the kill leaves a window in
        // which a restart-killed exchange still reports `TransportLost`:
        // measured, and it is not a narrow race but the whole outcome --
        // moving this one line below the kill fails
        // `a_restart_mid_operation_is_unknown_and_the_click_does_not_land_twice`
        // on every run. That is also why `BackendGeneration`, which advances
        // later still (at the replacement's spawn), cannot be used here.
        // Unconditional because a backend that died on its own is stopped
        // through here too, and the exchange it killed is no less disturbed
        // for the supervisor having arrived second.
        self.epoch.disturb();
        if let Some(running) = self.running.take() {
            running.child.kill();
            running.child.wait_exited().await;
        }
        authority.invalidate(self.generation)
    }

    /// Stop, then start again, invalidating in between.
    ///
    /// **The invalidation happens after the old backend is gone and before
    /// the new one is reachable**, so there is no interval in which a caller
    /// could present a pre-restart lease or capture identity to the new
    /// backend. A restart that invalidated afterwards would have one.
    ///
    /// # Errors
    /// Any [`StartError`] the new start produces. The invalidation has
    /// already happened when it does, and is returned alongside, because a
    /// failed restart leaves *more* to invalidate rather than less.
    pub async fn restart(
        &mut self,
        authority: &dyn InputAuthority,
    ) -> (Invalidation, Result<BackendEndpoint, StartError>) {
        let invalidation = self.stop(authority).await;
        let started = self.start().await;
        (invalidation, started)
    }
}

/// Read the address the backend published, bounded, and refuse anything that
/// is not loopback.
async fn read_endpoint(
    address_file: &std::path::Path,
    startup: Duration,
) -> Result<BackendEndpoint, StartError> {
    let deadline = tokio::time::Instant::now() + startup;
    while tokio::time::Instant::now() < deadline {
        let text = tokio::fs::read_to_string(address_file)
            .await
            .unwrap_or_default();
        let trimmed = text.trim();
        if !trimmed.is_empty() {
            let Ok(address) = trimmed.parse::<std::net::SocketAddr>() else {
                // A half-written file reads as unparseable; keep waiting
                // rather than failing, because the publisher renames into
                // place and the next read will see the whole thing.
                tokio::time::sleep(ADDRESS_POLL).await;
                continue;
            };
            return BackendEndpoint::new(address).map_err(StartError::Endpoint);
        }
        tokio::time::sleep(ADDRESS_POLL).await;
    }
    Err(StartError::NoAddress)
}

#[cfg(test)]
mod tests;
