//! **Is the backend working?** — answered by a probe, never by a config echo.
//!
//! `<scratchpad>/m5-scoping-and-decisions.md` puts this on the trap list, and
//! the trap is specific: `version` or `/commands` answering proves the **HTTP
//! server** is up, not that the automation backend can act. A CUA backend can
//! be present, listening and cheerfully answering while being entirely unable
//! to move a pointer, because macOS gates accessibility and screen-recording
//! behind grants the process may not hold. On such a host every config-echo
//! health check is green and every click silently fails.
//!
//! # What the probe actually exercises, and why that makes it a probe
//!
//! The probe is `screen_info` (`get_screen_size`) or `cursor_position`
//! (`get_cursor_position`). Three properties together are what make it a
//! probe rather than an echo:
//!
//! 1. **It crosses the dispatch boundary.** The verdict is read from a
//!    [`Dispatch`], so a backend that never answered cannot produce one.
//! 2. **The OS permission layer gates it.** Reading the screen geometry and
//!    the pointer position goes through the same grants a capture and a click
//!    go through, so a backend that is present but unpermitted fails it. That
//!    is the property a `version` reading does not have, at any cost.
//! 3. **It changes nothing.** Never a click. A health check that moved a
//!    pointer would be a health check that typed on somebody's desktop every
//!    supervision cycle, and it would make the fixture's effect ledger a
//!    record of this crate's polling rather than of consumer intent.
//!
//! # It is not this module's opinion that enforces (2)
//!
//! [`Health::Working`] carries a [`ProbeEvidence`], and that type is
//! constructible **only** from a dispatched, succeeded request whose operation
//! is `screen_info` or `cursor_position`. So `assess` cannot report a working
//! backend from a `describe`, from a `version`, or from a `/commands`
//! listing — not because it checks for them, but because there is no value it
//! could build. An operation outside the pair is
//! [`Unhealthy::NotAProbe`], which is a different answer from a probe that
//! ran and failed, and deliberately so: the first is a bug in the caller and
//! the second is a fact about the host.
//!
//! # Capture authority is read separately, and absent is not denied
//!
//! `desktop_capture_authorized` lives in the **`version`** response, not in
//! the probe's, and chunk 1 measured that the released 0.3.46 server **omits
//! it entirely** on the supported 0.22.x SDK. So it is read through
//! [`tunnel_cua::capability::CaptureAuthority::from_version_reading`], which
//! answers `Unknown` for an absent key, and `Unknown` permits the attempt.
//! Reading absence as denial would refuse capture on every correctly
//! permissioned host.
//!
//! A `version` reading is therefore part of *capability*, never part of
//! *health*: it is carried alongside the verdict and can never produce one.

use tunnel_cua::Operation;
use tunnel_cua::capability::{CaptureAuthority, ProbeEvidence};
use tunnel_cua::outcome::{Completion, Dispatch, FailureCode, NotDispatched};
use tunnel_cua::schema::Request;

/// The operations that may stand as a health probe.
///
/// Both are read-only and both are gated by the OS permission layer. Written
/// as data so a reader can see the whole set, and asserted against
/// [`ProbeEvidence`]'s own rule by a test rather than kept in step by hand.
pub const PROBE_OPERATIONS: &[Operation] = &[Operation::ScreenInfo, Operation::CursorPosition];

/// What supervision knows about the backend.
///
/// Ordered from "nothing is running" to "something is running and has been
/// shown to act". **The last is the only one that permits an operation to be
/// dispatched**, and it is the only one that carries evidence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Health {
    /// No backend has been started under this supervisor.
    ///
    /// Distinct from [`Health::Exited`]: "never started" and "started and
    /// gone" call for different operator actions, and a supervisor that
    /// collapsed them would report a crashed backend as an idle one.
    NotStarted,
    /// A backend process is running and no probe has been taken yet.
    ///
    /// **Not a working verdict.** A supervisor that treated a running process
    /// as a working backend would be the config echo wearing a lifecycle
    /// costume.
    Started,
    /// A probe was dispatched and succeeded. The evidence is carried, so a
    /// caller can see *which* probe answered.
    Working(ProbeEvidence),
    /// A backend process is running and the probe did not succeed.
    Unhealthy(Unhealthy),
    /// The backend process is gone.
    Exited,
}

impl Health {
    /// Whether this verdict permits dispatching a consumer operation.
    ///
    /// `true` for [`Health::Working`] and nothing else. In particular a
    /// [`Health::Started`] backend does **not** qualify: the point of the
    /// probe is that answering on a socket is not acting on a desktop.
    #[must_use]
    pub const fn permits_dispatch(&self) -> bool {
        matches!(self, Self::Working(_))
    }

    /// Whether a backend process exists at all, whatever it can do.
    ///
    /// Deliberately separate from [`Health::permits_dispatch`]: this is the
    /// lifecycle question and that is the health question, and the whole
    /// module exists because they are different.
    #[must_use]
    pub const fn process_is_running(&self) -> bool {
        matches!(self, Self::Started | Self::Working(_) | Self::Unhealthy(_))
    }

    /// The probe evidence behind a working verdict, if there is one.
    #[must_use]
    pub const fn evidence(&self) -> Option<&ProbeEvidence> {
        match self {
            Self::Working(evidence) => Some(evidence),
            _ => None,
        }
    }
}

/// Why a running backend is not working.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Unhealthy {
    /// The probe never reached the backend. The process is up and the socket
    /// is not answering, or the device refused the probe above the dispatch
    /// boundary.
    ProbeNotDispatched(NotDispatched),
    /// The backend answered and reported a failure.
    ///
    /// [`FailureCode::PermissionDenied`] is the case this whole module is
    /// built for: a backend that is present and unpermitted. It is preserved
    /// as a permission denial rather than retried or escalated under another
    /// backend.
    ProbeFailed(FailureCode),
    /// The probe was dispatched and its outcome is not known. The backend is
    /// not shown to be working, and it is not shown to be broken either.
    ProbeUnknown,
    /// **The operation offered as a probe is not one.**
    ///
    /// A caller's bug, not a fact about the host, and it is a distinct arm so
    /// it can never be mistaken for one. `describe` and `version` land here,
    /// which is the whole anti-echo rule: an operation the OS does not gate
    /// cannot report that the OS has permitted anything.
    NotAProbe,
}

/// Read a health verdict from one probe exchange.
///
/// `request` is the **validated request that produced `dispatch`**, not a
/// label the caller supplies alongside it. That is the same tightening
/// [`ProbeEvidence::from_probe`] documents: it narrows a mislabelled probe to
/// a caller deliberately pairing one request with another request's dispatch,
/// which the types cannot prevent, so it is a tightening rather than a proof.
///
/// # The direction this fails in
///
/// Every answer that is not a dispatched success is some flavour of
/// [`Health::Unhealthy`]. There is no arm that reads "probably fine": a
/// supervisor whose job is to decide whether a process may drive a desktop
/// has no business guessing in the permissive direction.
#[must_use]
pub fn assess(request: &Request, dispatch: &Dispatch) -> Health {
    if !PROBE_OPERATIONS.contains(&request.operation()) {
        return Health::Unhealthy(Unhealthy::NotAProbe);
    }
    match ProbeEvidence::from_probe(request, dispatch) {
        Some(evidence) => Health::Working(evidence),
        None => Health::Unhealthy(match dispatch {
            Dispatch::NotDispatched(why) => Unhealthy::ProbeNotDispatched(*why),
            Dispatch::Dispatched(Completion::Failed { code }) => Unhealthy::ProbeFailed(*code),
            Dispatch::Dispatched(Completion::Unknown(_)) => Unhealthy::ProbeUnknown,
            // A locally-answered probe never spoke to the backend, so it
            // cannot report on one. It is only reachable for `describe`,
            // which `PROBE_OPERATIONS` has already refused above -- kept as a
            // total match rather than an `unreachable!`, because an
            // unreachable arm in a health check is the shape that starts
            // returning the wrong answer when the plan changes.
            Dispatch::AnsweredLocally(_) | Dispatch::Dispatched(Completion::Ok(_)) => {
                Unhealthy::NotAProbe
            }
        }),
    }
}

/// What a `version` reading says about capture authority.
///
/// Carried **beside** a health verdict and never able to produce one. It is a
/// capability input: `CaptureAuthority::Unknown` is the normal answer on the
/// supported SDK and permits the attempt, so a supervisor that treated this
/// as health would call a completely unpermitted backend healthy.
#[must_use]
pub fn capture_authority(version: &Dispatch) -> CaptureAuthority {
    CaptureAuthority::from_version_reading(version)
}

#[cfg(test)]
mod tests;
