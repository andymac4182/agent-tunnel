//! Live re-keying of this relay's private HTTP/3 peer identity (task rows
//! M8-C28, M8-C45..M8-C47).
//!
//! `docs/cluster.md` "Certificate and key lifecycle" describes a planned
//! rotation: authorize the next key before use, publish a signed record with
//! both keys, wait for verification convergence, switch new handshakes to the
//! next certificate, and retire the previous key after an overlap.  Before
//! this module a relay could not take part: it bound one peer certificate for
//! the life of its process.  [`PeerRekey`] is the explicit state machine that
//! drives the relay's half of that procedure without a restart:
//!
//! 1. **Stage** ([`PeerRekey::stage`]): a new certificate and private key are
//!    loaded *locally*, validated against the peer CA, and held.  Nothing is
//!    served with them and nothing about them leaves the process except the
//!    public SPKI digest, which the operator's membership publisher must
//!    approve.  A relay never authorizes its own key and never writes a key --
//!    private or public -- to Redis.
//! 2. **Switch**: once the verified signed record for this node has approved
//!    the staged SPKI **continuously for the convergence hold**, the relay
//!    binds readiness to that SPKI and installs it for new handshakes in one
//!    step under the membership reconcile gate
//!    ([`MembershipRuntime::switch_local_serving_spki`]).  Established
//!    connections keep the identity they negotiated.
//! 3. **Overlap**: the predecessor keeps serving what it already carries.
//!    Pooled outbound connections under it are drained, never reused for new
//!    streams, within the peer drain budget.
//! 4. **Retire**: when the verified record stops approving the predecessor
//!    (the publisher withdrew or revoked it) or the overlap elapses, every
//!    remaining outbound connection under it is closed and the machine returns
//!    to `Stable`.
//!
//! Readiness is bound only to the **served** key, never to a staged one: a
//! relay whose served key the record stops approving still fails closed, as
//! before.

use std::{
    fmt,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::{task::JoinHandle, time::Instant};
use tokio_util::sync::CancellationToken;
use tunnel_transport::{PeerClient, PeerIdentityError, RotatingPeerIdentity, StagedPeerIdentity};

use crate::{
    ClusterConfig,
    membership_runtime::{LocalKeyApproval, LocalServingSwitchError, MembershipRuntime},
};

/// The default overlap after a switch before the predecessor is retired
/// locally even if the record still approves it (`docs/cluster.md`:
/// "initially ten minutes").
pub const DEFAULT_PEER_REKEY_OVERLAP: Duration = Duration::from_secs(600);

/// How often the rotation state machine re-reads verified membership state.
pub const DEFAULT_PEER_REKEY_TICK: Duration = Duration::from_secs(1);

/// Rotation timing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PeerRekeyConfig {
    /// How long the verified record must have approved the staged key,
    /// continuously, before new handshakes present it.  The conservative
    /// default is one full membership record lifetime plus the accepted clock
    /// skew: after that, every peer still Ready must hold a record at least as
    /// new as the one that first approved the staged key.
    pub convergence_hold: Duration,
    /// How long the predecessor may keep serving after the switch before it
    /// is retired locally.
    pub overlap: Duration,
    /// State machine tick.
    pub tick: Duration,
}

impl PeerRekeyConfig {
    /// Derive the conservative defaults from the operator's cluster settings,
    /// then apply the optional overrides it carries.
    #[must_use]
    pub fn from_cluster_config(cluster: &ClusterConfig) -> Self {
        let default_hold = Duration::from_secs(
            cluster
                .membership_record_lifetime_seconds
                .saturating_add(cluster.max_clock_skew_seconds),
        );
        Self {
            convergence_hold: cluster
                .peer_rekey_convergence_seconds
                .map_or(default_hold, Duration::from_secs),
            overlap: cluster
                .peer_rekey_overlap_seconds
                .map_or(DEFAULT_PEER_REKEY_OVERLAP, Duration::from_secs),
            tick: DEFAULT_PEER_REKEY_TICK,
        }
    }
}

/// The rotation phase, as a bounded label set.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRekeyPhase {
    /// One identity; nothing staged.
    Stable,
    /// A successor is loaded locally and awaits approval and convergence.
    Staged,
    /// The successor serves; the predecessor is draining.
    Overlap,
}

impl PeerRekeyPhase {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Stable => "stable",
            Self::Staged => "staged",
            Self::Overlap => "overlap",
        }
    }
}

/// Why the predecessor was retired.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerRekeyRetirement {
    /// The verified record no longer approves the predecessor.
    Withdrawn,
    /// The configured overlap elapsed first.
    OverlapElapsed,
}

impl PeerRekeyRetirement {
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Withdrawn => "withdrawn",
            Self::OverlapElapsed => "overlap_elapsed",
        }
    }
}

/// Why a staging request was refused.
#[derive(Debug)]
pub enum PeerRekeyError {
    /// A rotation is already staged or overlapping; finish it first.
    InProgress(&'static str),
    /// The staged key is the one already served.
    SameKey,
    /// The candidate identity was refused before staging.
    Identity(PeerIdentityError),
}

impl fmt::Display for PeerRekeyError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InProgress(phase) => write!(
                formatter,
                "a peer-key rotation is already in progress (phase {phase})"
            ),
            Self::SameKey => formatter.write_str("the staged peer key is the key already served"),
            Self::Identity(error) => fmt::Display::fmt(error, formatter),
        }
    }
}

impl std::error::Error for PeerRekeyError {}

impl From<PeerIdentityError> for PeerRekeyError {
    fn from(error: PeerIdentityError) -> Self {
        Self::Identity(error)
    }
}

/// Payload-free, key-free rotation diagnostics.  Every digest is a public
/// SPKI pin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PeerRekeySnapshot {
    pub phase: PeerRekeyPhase,
    pub serving_spki: String,
    pub serving_generation: u64,
    pub staged_spki: Option<String>,
    /// How the verified record treats the staged key, when one is staged.
    pub staged_approval: Option<&'static str>,
    pub previous_spki: Option<String>,
    pub stages: u64,
    pub switches: u64,
    pub retirements: u64,
    pub last_retirement: Option<PeerRekeyRetirement>,
    pub last_refusal: Option<&'static str>,
    pub draining_connections: usize,
}

struct StagedState {
    identity: StagedPeerIdentity,
    spki: String,
    approved_since: Option<Instant>,
    last_approval: LocalKeyApproval,
}

struct OverlapState {
    previous_spki: String,
    serving_generation: u64,
    switched_at: Instant,
}

enum RekeyState {
    Stable,
    Staged(StagedState),
    Overlap(OverlapState),
}

impl RekeyState {
    const fn phase(&self) -> PeerRekeyPhase {
        match self {
            Self::Stable => PeerRekeyPhase::Stable,
            Self::Staged(_) => PeerRekeyPhase::Staged,
            Self::Overlap(_) => PeerRekeyPhase::Overlap,
        }
    }
}

#[derive(Default)]
struct Counters {
    stages: u64,
    switches: u64,
    retirements: u64,
    last_retirement: Option<PeerRekeyRetirement>,
    last_refusal: Option<&'static str>,
}

/// The relay's peer-key rotation coordinator.
pub struct PeerRekey {
    identity: Arc<RotatingPeerIdentity>,
    membership: Arc<MembershipRuntime>,
    peer_client: Option<PeerClient>,
    peer_ca_pem: Vec<u8>,
    config: PeerRekeyConfig,
    state: Mutex<RekeyState>,
    counters: Mutex<Counters>,
    // Serializes `tick` so a switch/retire pass is never interleaved.
    tick_gate: tokio::sync::Mutex<()>,
}

impl fmt::Debug for PeerRekey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerRekey")
            .field("phase", &self.phase())
            .field("identity", &self.identity)
            .finish_non_exhaustive()
    }
}

impl PeerRekey {
    /// Build a coordinator for a relay whose peer server and client
    /// configurations both resolve through `identity`.  `peer_client` is the
    /// relay's outbound pool, which must have been built
    /// [`with_local_identity`](PeerClient::with_local_identity) on the same
    /// slot so superseded connections drain.
    #[must_use]
    pub fn new(
        identity: Arc<RotatingPeerIdentity>,
        membership: Arc<MembershipRuntime>,
        peer_client: Option<PeerClient>,
        peer_ca_pem: Vec<u8>,
        config: PeerRekeyConfig,
    ) -> Arc<Self> {
        Arc::new(Self {
            identity,
            membership,
            peer_client,
            peer_ca_pem,
            config,
            state: Mutex::new(RekeyState::Stable),
            counters: Mutex::new(Counters::default()),
            tick_gate: tokio::sync::Mutex::new(()),
        })
    }

    fn lock_state(&self) -> std::sync::MutexGuard<'_, RekeyState> {
        self.state.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn lock_counters(&self) -> std::sync::MutexGuard<'_, Counters> {
        self.counters
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn refuse(&self, label: &'static str) {
        self.lock_counters().last_refusal = Some(label);
    }

    /// The current phase.
    #[must_use]
    pub fn phase(&self) -> PeerRekeyPhase {
        self.lock_state().phase()
    }

    /// The configured timing.
    #[must_use]
    pub const fn config(&self) -> PeerRekeyConfig {
        self.config
    }

    /// Validate PEM input against the local peer CA and stage it.
    ///
    /// The caller clears its PEM buffers afterwards; this keeps only the
    /// parsed signing key, in memory.
    pub fn stage_pem(
        &self,
        certificate_pem: &[u8],
        private_key_pem: &[u8],
    ) -> Result<String, PeerRekeyError> {
        let staged = StagedPeerIdentity::from_pem(certificate_pem, private_key_pem, &self.peer_ca_pem)
            .inspect_err(|_| self.refuse("staged_identity_invalid"))?;
        self.stage(staged)
    }

    /// Stage an already validated successor identity and return its public
    /// SPKI digest -- the value the membership publisher must approve.
    pub fn stage(&self, staged: StagedPeerIdentity) -> Result<String, PeerRekeyError> {
        self.identity
            .check_replacement(&staged)
            .inspect_err(|_| self.refuse("staged_identity_mismatch"))?;
        let spki = staged.spki_sha256().to_hex();
        let mut state = self.lock_state();
        match &*state {
            RekeyState::Stable => {}
            other => {
                let phase = other.phase().label();
                drop(state);
                self.refuse("rotation_in_progress");
                return Err(PeerRekeyError::InProgress(phase));
            }
        }
        if spki == self.identity.current_spki().to_hex() {
            drop(state);
            self.refuse("staged_same_key");
            return Err(PeerRekeyError::SameKey);
        }
        *state = RekeyState::Staged(StagedState {
            identity: staged,
            spki: spki.clone(),
            approved_since: None,
            last_approval: LocalKeyApproval::Absent,
        });
        drop(state);
        self.lock_counters().stages += 1;
        tracing::info!(
            phase = "staged",
            staged_spki_sha256 = %spki,
            serving_spki_sha256 = %self.identity.current_spki(),
            "peer identity staged; awaiting a signed membership record approving it"
        );
        Ok(spki)
    }

    /// Advance the state machine once from verified membership state.
    pub async fn tick(&self) -> PeerRekeySnapshot {
        let _gate = self.tick_gate.lock().await;
        let now = Instant::now();
        let action = {
            let mut state = self.lock_state();
            match &mut *state {
                RekeyState::Stable => Action::None,
                RekeyState::Staged(staged) => {
                    let approval = self.membership.local_key_approval(&staged.spki);
                    staged.last_approval = approval;
                    match approval {
                        LocalKeyApproval::Approved { .. } => {
                            let since = *staged.approved_since.get_or_insert(now);
                            if now.saturating_duration_since(since) >= self.config.convergence_hold {
                                Action::Switch
                            } else {
                                Action::None
                            }
                        }
                        LocalKeyApproval::Revoked => Action::AbandonRevoked,
                        // Lost approval (or never had it): the hold restarts.
                        // `NotReady` restarts it too: convergence is measured
                        // only while this relay can see the record.
                        _ => {
                            staged.approved_since = None;
                            Action::None
                        }
                    }
                }
                RekeyState::Overlap(overlap) => {
                    match self.membership.local_key_approval(&overlap.previous_spki) {
                        LocalKeyApproval::Absent
                        | LocalKeyApproval::Revoked
                        | LocalKeyApproval::OutsideWindow => {
                            Action::Retire(PeerRekeyRetirement::Withdrawn)
                        }
                        // A transient unready state is not evidence the
                        // predecessor was withdrawn.
                        LocalKeyApproval::NotReady | LocalKeyApproval::Approved { .. } => {
                            if now.saturating_duration_since(overlap.switched_at)
                                >= self.config.overlap
                            {
                                Action::Retire(PeerRekeyRetirement::OverlapElapsed)
                            } else {
                                Action::None
                            }
                        }
                    }
                }
            }
        };
        match action {
            Action::None => {}
            Action::AbandonRevoked => {
                let mut state = self.lock_state();
                if let RekeyState::Staged(staged) = &*state {
                    tracing::warn!(
                        phase = "stable",
                        staged_spki_sha256 = %staged.spki,
                        "staged peer identity was revoked by the signed record; discarded"
                    );
                }
                *state = RekeyState::Stable;
                drop(state);
                self.refuse("staged_key_revoked");
            }
            Action::Switch => self.switch().await,
            Action::Retire(cause) => self.retire(cause).await,
        }
        self.snapshot()
    }

    async fn switch(&self) {
        let staged = {
            let mut state = self.lock_state();
            match std::mem::replace(&mut *state, RekeyState::Stable) {
                RekeyState::Staged(staged) => staged,
                other => {
                    *state = other;
                    return;
                }
            }
        };
        let previous_spki = self.identity.current_spki().to_hex();
        let spki = staged.spki.clone();
        let identity = Arc::clone(&self.identity);
        let mut slot = Some(staged.identity);
        let mut generation = 0;
        let result = self
            .membership
            .switch_local_serving_spki(&spki, || {
                let staged = slot.take().ok_or(PeerIdentityError::KeyMismatch)?;
                generation = identity.install(staged)?;
                Ok::<(), PeerIdentityError>(())
            })
            .await;
        match result {
            Ok(()) => {
                *self.lock_state() = RekeyState::Overlap(OverlapState {
                    previous_spki: previous_spki.clone(),
                    serving_generation: generation,
                    switched_at: Instant::now(),
                });
                self.lock_counters().switches += 1;
                tracing::info!(
                    phase = "overlap",
                    serving_spki_sha256 = %spki,
                    previous_spki_sha256 = %previous_spki,
                    serving_generation = generation,
                    "peer identity switched; new handshakes present the successor"
                );
            }
            Err(error) => {
                let label = match &error {
                    LocalServingSwitchError::InvalidDigest => "switch_invalid_digest",
                    LocalServingSwitchError::NotApproved(_) => "switch_not_approved",
                    LocalServingSwitchError::Install(_) => "switch_install_failed",
                };
                // Put the staged identity back (if install never consumed it)
                // and restart the convergence hold.
                if let Some(identity) = slot.take() {
                    *self.lock_state() = RekeyState::Staged(StagedState {
                        identity,
                        spki,
                        approved_since: None,
                        last_approval: LocalKeyApproval::Absent,
                    });
                }
                self.refuse(label);
                tracing::warn!(reason = label, "peer identity switch refused");
            }
        }
    }

    async fn retire(&self, cause: PeerRekeyRetirement) {
        let (previous, generation) = {
            let mut state = self.lock_state();
            match std::mem::replace(&mut *state, RekeyState::Stable) {
                RekeyState::Overlap(overlap) => (overlap.previous_spki, overlap.serving_generation),
                other => {
                    *state = other;
                    return;
                }
            }
        };
        let closed = match &self.peer_client {
            Some(client) => client.retire_local_generations_before(generation).await,
            None => 0,
        };
        {
            let mut counters = self.lock_counters();
            counters.retirements += 1;
            counters.last_retirement = Some(cause);
        }
        tracing::info!(
            phase = "stable",
            retired_spki_sha256 = %previous,
            cause = cause.label(),
            closed_connections = closed,
            "previous peer identity retired"
        );
    }

    /// Payload-free rotation diagnostics.
    #[must_use]
    pub fn snapshot(&self) -> PeerRekeySnapshot {
        let state = self.lock_state();
        let (staged_spki, staged_approval, previous_spki) = match &*state {
            RekeyState::Stable => (None, None, None),
            RekeyState::Staged(staged) => (
                Some(staged.spki.clone()),
                Some(staged.last_approval.label()),
                None,
            ),
            RekeyState::Overlap(overlap) => (None, None, Some(overlap.previous_spki.clone())),
        };
        let phase = state.phase();
        drop(state);
        let counters = self.lock_counters();
        PeerRekeySnapshot {
            phase,
            serving_spki: self.identity.current_spki().to_hex(),
            serving_generation: self.identity.generation(),
            staged_spki,
            staged_approval,
            previous_spki,
            stages: counters.stages,
            switches: counters.switches,
            retirements: counters.retirements,
            last_retirement: counters.last_retirement,
            last_refusal: counters.last_refusal,
            draining_connections: self
                .peer_client
                .as_ref()
                .map_or(0, PeerClient::draining_connection_count),
        }
    }

    /// Run the state machine every `config.tick` until `cancel` fires.
    pub fn spawn(self: &Arc<Self>, cancel: CancellationToken) -> JoinHandle<()> {
        let rekey = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(rekey.config.tick);
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                tokio::select! {
                    () = cancel.cancelled() => return,
                    _ = interval.tick() => {
                        rekey.tick().await;
                    }
                }
            }
        })
    }
}

enum Action {
    None,
    Switch,
    AbandonRevoked,
    Retire(PeerRekeyRetirement),
}
