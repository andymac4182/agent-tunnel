//! Reconciling the transport's dynamic peer pin set from verified membership,
//! and the peer-trust refresh tick that keeps readiness honest about it.
//!
//! This lives in the library rather than in the serving binary for two
//! reasons. Which unready states withdraw a relay's approved peer keys is a
//! security contract with a recorded owner decision behind it (M7-C86), and a
//! contract that can only be exercised by starting a relay process gets
//! regressed. And the serving relay and the production-cluster fixture used to
//! carry two diverging copies of this wiring (M7-C90): the fixture derived its
//! pins from a different view of membership and never republished on its
//! tick, so no gate described what the product actually did. Both now build
//! their wiring from [`PeerPinPublisher`] and [`peer_trust_tick`].

use std::{
    error::Error,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};

use tokio_util::sync::CancellationToken;
use tunnel_transport::{SharedPeerPins, SpkiSha256};

use crate::{
    PeerRouteTarget, PeerRuntime,
    membership_runtime::{
        MembershipChangeObserver, MembershipReadiness, MembershipRuntime, PeerInvalidationCallback,
    },
};

/// What one pin publication attempt did to the installed snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PinPublication {
    /// A fresh set was derived from verifier-filtered route targets and
    /// installed.
    Published,
    /// A `Ready` runtime derived no approved key at all, so an empty set was
    /// installed and both peer directions now fail closed.
    PublishedEmpty,
    /// The membership runtime was not `Ready` for a local or transient
    /// reason, so no fresh set could be derived and the previously verified
    /// one was left installed.
    RetainedWhileUnready,
    /// The membership runtime was not `Ready` because the trust evidence
    /// itself was rejected, so the pin set was withdrawn.
    WithdrawnWhileUntrusted,
    /// The set could not be derived (a malformed digest), so an empty set was
    /// installed and the failure is remembered for the next retry.
    FailedClosed,
    /// An explicit withdrawal is being held; nothing was published.
    Held,
    /// Publication is suppressed; the installed set was left untouched.
    Suppressed,
    /// Another publication was already running; it re-derives from the
    /// newest state before it returns.
    Coalesced,
}

/// A pin set that could not be derived from verified membership.
#[derive(Debug)]
pub struct PinDerivationError(Box<dyn Error + Send + Sync>);

impl fmt::Display for PinDerivationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "peer pin derivation failed: {}", self.0)
    }
}

impl Error for PinDerivationError {}

/// What the current membership state says the pin set should be.
enum PinDecision {
    Install(Vec<SpkiSha256>),
    Withdraw,
    Retain,
}

/// Derive the pin decision for the runtime's current state without touching
/// the installed set. Reading readiness may dispatch expiry invalidations,
/// and so may re-enter a publisher; nothing is locked here.
fn derive_pins(membership: &MembershipRuntime) -> Result<PinDecision, PinDerivationError> {
    match membership.readiness() {
        MembershipReadiness::Ready => {}
        MembershipReadiness::Unready(reason) if reason.withdraws_peer_trust() => {
            return Ok(PinDecision::Withdraw);
        }
        MembershipReadiness::Starting | MembershipReadiness::Unready(_) => {
            return Ok(PinDecision::Retain);
        }
    }
    // Derive the pin set from current, verifier-filtered route targets rather
    // than the redacted diagnostic snapshot.  The latter intentionally keeps
    // bounded historical key metadata, so publishing it could retain an
    // expired/revoked SPKI in the transport trust set until the next full
    // candidate swap.
    let mut digests = Vec::new();
    for target in membership.verified_peer_route_targets() {
        for digest in target.approved_spki_sha256() {
            let bytes = decode_hex_digest(digest).ok_or_else(|| {
                PinDerivationError(Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "invalid membership SPKI digest",
                )))
            })?;
            digests.push(SpkiSha256::from_bytes(bytes));
        }
    }
    Ok(PinDecision::Install(digests))
}

fn apply_pins(
    pins: &SharedPeerPins,
    decision: PinDecision,
) -> Result<PinPublication, PinDerivationError> {
    match decision {
        PinDecision::Retain => Ok(PinPublication::RetainedWhileUnready),
        PinDecision::Withdraw => {
            if !pins.snapshot().is_empty() {
                tracing::warn!("membership trust evidence was rejected; withdrawing peer pins");
            }
            pins.replace(std::iter::empty::<SpkiSha256>())
                .map_err(|error| PinDerivationError(Box::new(error)))?;
            Ok(PinPublication::WithdrawnWhileUntrusted)
        }
        PinDecision::Install(digests) => {
            let empty = digests.is_empty();
            pins.replace(digests)
                .map_err(|error| PinDerivationError(Box::new(error)))?;
            Ok(if empty {
                PinPublication::PublishedEmpty
            } else {
                PinPublication::Published
            })
        }
    }
}

/// Reconcile the transport's dynamic pins from verifier-filtered current
/// route targets -- the rule, with no retry, coalescing or hold state.
///
/// An unready runtime splits in two, on the recorded owner decision behind
/// [`crate::MembershipUnreadyReason::withdraws_peer_trust`]: rejected trust
/// evidence withdraws the pin set, a local or transient unready state leaves
/// the verified set installed (M7-C86). A retained pin proves only that a
/// certificate was approved when the set was published; the signed record
/// and key windows are enforced at admission (`bind_peer`/`admit_peer`).
///
/// A `Ready` runtime derives the set from current route targets, which filter
/// record and key windows at `now`, so a key that has left its own signed
/// window leaves the set -- and its pooled connections close through the
/// transport pin watcher -- at the next publication, even with no reconcile.
pub fn publish_membership_pins(
    membership: &MembershipRuntime,
    pins: &SharedPeerPins,
) -> Result<PinPublication, PinDerivationError> {
    apply_pins(pins, derive_pins(membership)?)
}

#[derive(Default)]
struct PublisherControl {
    held: bool,
    suppressed: bool,
}

/// The one wiring between a relay's membership runtime and its transport pin
/// set, shared by the serving relay and the production-cluster fixture.
///
/// It publishes from three triggers: every admission invalidation (the
/// runtime's invalidation callback), every readiness transition or verified
/// directory change (the runtime's change observer, M7-C91), and the bounded
/// refresh tick ([`peer_trust_tick`]). Publications are serialized and each
/// reads the runtime's *current* state inside the lock, so the last one to run
/// reflects the newest state and an out-of-order stale publication cannot be
/// left behind.
pub struct PeerPinPublisher {
    membership: Arc<MembershipRuntime>,
    pins: SharedPeerPins,
    control: Mutex<PublisherControl>,
    pending: AtomicBool,
    running: AtomicBool,
    dirty: AtomicBool,
}

impl fmt::Debug for PeerPinPublisher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PeerPinPublisher")
            .field("pins", &self.pins.snapshot().len())
            .field("pending", &self.pending.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl PeerPinPublisher {
    #[must_use]
    pub fn new(membership: Arc<MembershipRuntime>, pins: SharedPeerPins) -> Arc<Self> {
        Arc::new(Self {
            membership,
            pins,
            control: Mutex::new(PublisherControl::default()),
            pending: AtomicBool::new(false),
            running: AtomicBool::new(false),
            dirty: AtomicBool::new(false),
        })
    }

    #[must_use]
    pub fn pins(&self) -> &SharedPeerPins {
        &self.pins
    }

    #[must_use]
    pub fn membership(&self) -> &Arc<MembershipRuntime> {
        &self.membership
    }

    /// Publish the pin set for the runtime's current state.
    ///
    /// A derivation failure fails closed to an empty set, is logged, and is
    /// remembered as pending until a later publication succeeds.
    ///
    /// Publications coalesce rather than block: deriving the set reads
    /// membership readiness, which can dispatch an expiry invalidation whose
    /// callback publishes again on this very thread. A publication requested
    /// while another is running marks the state dirty and returns
    /// [`PinPublication::Coalesced`]; the running one then derives again, so
    /// the last derivation always reads the newest state.
    pub fn publish(&self) -> PinPublication {
        self.dirty.store(true, Ordering::Release);
        if self.running.swap(true, Ordering::AcqRel) {
            return PinPublication::Coalesced;
        }
        let mut outcome;
        loop {
            self.dirty.store(false, Ordering::Release);
            outcome = self.publish_once();
            self.running.store(false, Ordering::Release);
            if !self.dirty.load(Ordering::Acquire) || self.running.swap(true, Ordering::AcqRel) {
                break;
            }
        }
        outcome
    }

    fn publish_once(&self) -> PinPublication {
        let decision = derive_pins(&self.membership);
        let control = match self.control.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        if control.suppressed {
            return PinPublication::Suppressed;
        }
        if control.held {
            let _ = self.pins.replace(std::iter::empty::<SpkiSha256>());
            return PinPublication::Held;
        }
        let outcome = match decision.and_then(|decision| apply_pins(&self.pins, decision)) {
            Ok(outcome) => outcome,
            Err(error) => {
                tracing::warn!(%error, "membership pin publication failed closed");
                let _ = self.pins.replace(std::iter::empty::<SpkiSha256>());
                PinPublication::FailedClosed
            }
        };
        self.pending.store(
            matches!(outcome, PinPublication::FailedClosed),
            Ordering::Release,
        );
        outcome
    }

    /// Whether the last publication failed closed and has not been retried
    /// successfully.
    #[must_use]
    pub fn publication_pending(&self) -> bool {
        self.pending.load(Ordering::Acquire)
    }

    /// Retry a publication that failed closed, if one is pending.
    pub fn retry_pending(&self) -> Option<PinPublication> {
        self.publication_pending().then(|| self.publish())
    }

    /// The invalidation callback that republishes after an admission is
    /// invalidated.
    #[must_use]
    pub fn invalidation_callback(self: &Arc<Self>) -> PeerInvalidationCallback {
        let publisher = Arc::clone(self);
        Arc::new(move |_identity, _reason| {
            publisher.publish();
        })
    }

    /// The change observer that republishes on every readiness transition and
    /// verified directory change -- in particular on the reconcile that
    /// returns membership to `Ready`, which invalidates no admission and so
    /// never reached the invalidation callback (M7-C91).
    #[must_use]
    pub fn change_observer(self: &Arc<Self>) -> MembershipChangeObserver {
        let publisher = Arc::clone(self);
        Arc::new(move |_readiness| {
            publisher.publish();
        })
    }

    /// Install both triggers on the membership runtime.
    pub fn install(self: &Arc<Self>) {
        self.membership
            .set_invalidation_callback(Some(self.invalidation_callback()));
        self.membership
            .set_change_observer(Some(self.change_observer()));
    }

    /// Fault injection: withdraw every pin and hold the withdrawal against
    /// every trigger until [`Self::release_hold`].
    pub fn withdraw_and_hold(&self) -> Result<(), tunnel_transport::PeerTransportError> {
        let mut control = match self.control.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        control.held = true;
        self.pins.replace(std::iter::empty::<SpkiSha256>())
    }

    /// End a held withdrawal and publish the current state.
    pub fn release_hold(&self) -> PinPublication {
        {
            let mut control = match self.control.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            control.held = false;
        }
        self.publish()
    }

    /// Fault injection: while suppressed, every trigger leaves the installed
    /// set untouched (the dropped-hint gate).
    pub fn set_suppressed(&self, suppressed: bool) {
        let mut control = match self.control.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        control.suppressed = suppressed;
    }
}

/// Verified peer routes this relay must probe: every current route target
/// except its own.
#[must_use]
pub fn required_peer_routes(
    membership: &MembershipRuntime,
    local_node_id: &str,
) -> Vec<PeerRouteTarget> {
    membership
        .verified_peer_route_targets()
        .into_iter()
        .filter(|target| target.node_id() != local_node_id)
        .collect()
}

/// What one [`peer_trust_tick`] did with peer readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerTrustTick {
    /// No approved pin is installed, so peer trust was withdrawn.
    TrustWithdrawn,
    /// Membership is not `Ready`; the verified pins and routes stay installed
    /// and only readiness was withdrawn.
    ReadinessWithdrawn,
    /// Routes were probed.
    Probed,
    /// Shutdown was requested while probing.
    Shutdown,
}

/// One bounded peer-trust refresh pass, shared by the serving relay and the
/// fixture (M7-C90).
///
/// It republishes the pin set, reconciles pooled connections against it, and
/// then keeps readiness honest: an empty set withdraws peer trust; an unready
/// membership withdraws readiness while the verified pins and routes stay
/// installed, so an authenticated peer's bounded reachability probe is still
/// answered; otherwise the required routes are probed.
pub async fn peer_trust_tick(
    publisher: &PeerPinPublisher,
    peer: &PeerRuntime,
    local_node_id: &str,
    configured_capacity: usize,
    shutdown: &CancellationToken,
) -> PeerTrustTick {
    publisher.publish();
    if let Err(error) = peer.refresh_peer_pins().await {
        tracing::warn!(?error, "stale peer pin connection cleanup failed");
    }
    if publisher.pins().snapshot().is_empty() {
        peer.withdraw_peer_trust();
        return PeerTrustTick::TrustWithdrawn;
    }
    let membership = publisher.membership();
    if !matches!(membership.readiness(), MembershipReadiness::Ready) {
        peer.withdraw_peer_readiness();
        return PeerTrustTick::ReadinessWithdrawn;
    }
    // The configured ceiling supplies the global capacity floor; every
    // successful route probe separately proves an actual HTTP/3 request slot
    // and response path for that destination.
    peer.set_peer_capacity(configured_capacity);
    let targets = required_peer_routes(membership, local_node_id);
    tokio::select! {
        _ = shutdown.cancelled() => PeerTrustTick::Shutdown,
        result = peer.refresh_required_routes(targets) => {
            if let Err(error) = result {
                tracing::warn!(?error, "authenticated peer readiness probe failed");
            }
            PeerTrustTick::Probed
        }
    }
}

/// Decode a lower- or upper-case 64-character hex SPKI digest.
#[must_use]
pub fn decode_hex_digest(value: &str) -> Option<[u8; 32]> {
    if value.len() != 64 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut bytes = [0_u8; 32];
    for (index, pair) in value.as_bytes().chunks_exact(2).enumerate() {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        bytes[index] = (high << 4) | low;
    }
    Some(bytes)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
