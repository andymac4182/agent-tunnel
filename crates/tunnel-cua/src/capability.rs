//! Capability discovery: **the intersection of three sets, one of which can
//! only come from a probe.**
//!
//! `docs/integrations.md`: "Capability discovery is the intersection of local
//! configuration, upstream backend support and the caller's grant. Unknown
//! commands fail closed."
//!
//! # The trap this module is shaped around
//!
//! *A config echo standing in for a probe.* It is easy to write a
//! "capability negotiation" in which all three inputs are read from the same
//! configuration file, so the device advertises what it was told to advertise
//! and the word "negotiation" does no work. `version` or `/commands`
//! answering does not close the gap either: it proves the HTTP server is up,
//! not that the automation backend can act. CUA backends can be present but
//! unpermitted — macOS accessibility and screen-recording grants are exactly
//! this.
//!
//! So [`UpstreamSupport`] cannot be constructed from configuration. It needs a
//! [`ProbeEvidence`], and a `ProbeEvidence` can only be made from a
//! [`Completion::Ok`] of a dispatched read-only probe. A `NotDispatched`
//! produces none; a `Failed` produces none; an `Unknown` produces none. There
//! is no constructor that takes a boolean.
//!
//! # `desktop_capture_authorized` is absent-by-default, not false
//!
//! Chunk 1 measured this on the released artifact: `handlers/cua_driver.py`
//! made the key conditional on `hasattr`, so on the supported 0.22.x SDK the
//! server **omits it** rather than reporting `false` or inferring authority
//! from `desktop_unlocked`. [`CaptureAuthority`] therefore has three states,
//! and [`CaptureAuthority::from_status`] maps an absent key to
//! [`CaptureAuthority::Unknown`]. Reading absence as "denied" is a live bug
//! waiting to happen: a device that did so would refuse capture on every
//! correctly-permissioned host running the supported SDK.
//!
//! **And it is read from the right response.** The key is a member of the
//! **`version`** payload, not of `get_screen_size` or `get_cursor_position`.
//! An earlier revision of this module derived capture authority from the probe
//! result, which meant that against the pinned backend it could only ever be
//! `Unknown` and the capture gate at [`negotiate`] could never refuse — an
//! unreachable rule, the same defect class as the dead marker check deleted
//! from `marker.rs` in this chunk, and caught by the same review. It is now a
//! separate input to [`UpstreamSupport::new`], produced by
//! [`CaptureAuthority::from_version_reading`] from a dispatched `version`
//! command.
//!
//! **Two consequences to hold together.** The key is absent by default *and*
//! it lives on a response this profile only reads during discovery. So
//! [`CaptureAuthority::Denied`] is **modelled, not measured**: no real backend
//! has been seen to emit `false`, the fixture is what exercises that arm, and
//! task row M5-C03 says so rather than letting a tri-state imply three
//! observed states.

use std::collections::BTreeSet;

use serde_json::Value;

use crate::Operation;
use crate::outcome::{Completion, Dispatch};
use crate::schema::Request;

/// What the device operator has turned on locally.
///
/// The one input that *is* configuration, and it is named as such.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct LocalConfiguration {
    enabled: BTreeSet<Operation>,
}

impl LocalConfiguration {
    /// Nothing enabled. The default, because a CUA export that was configured
    /// by forgetting to configure it must export nothing.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, operation: Operation) -> Self {
        self.enabled.insert(operation);
        self
    }

    #[must_use]
    pub fn contains(&self, operation: Operation) -> bool {
        self.enabled.contains(&operation)
    }
}

/// The consumer's grant, as the relay ingress authorized it.
///
/// Separate from [`LocalConfiguration`] and carrying the same shape on
/// purpose: they are different facts that happen to be the same type of set,
/// and merging them into one "config" is how the intersection stops being one.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct CallerGrant {
    granted: BTreeSet<Operation>,
}

impl CallerGrant {
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with(mut self, operation: Operation) -> Self {
        self.granted.insert(operation);
        self
    }

    #[must_use]
    pub fn contains(&self, operation: Operation) -> bool {
        self.granted.contains(&operation)
    }
}

/// Evidence that a backend **acted**, not merely that it answered.
///
/// Constructible only from a dispatched, succeeded read-only probe. This type
/// is the whole mechanism: without a value of it there is no
/// [`UpstreamSupport`], and there is no way to make one out of a configuration
/// value, a boolean, or a `/commands` listing.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProbeEvidence {
    probe: Operation,
}

impl ProbeEvidence {
    /// Read evidence out of a probe's dispatch result.
    ///
    /// Returns `None` unless the probe was **dispatched and succeeded**. The
    /// probe must be an operation that the OS permission layer gates and that
    /// changes nothing: `screen_info` or `cursor_position`. `describe` is
    /// refused because it is the config echo; `capture` is refused because a
    /// probe must be cheap enough to run on every supervision cycle.
    ///
    /// **The probe is taken from the validated [`Request`] that produced the
    /// dispatch, not from a free-standing label.** The first review found the
    /// old signature took an `Operation` the caller simply asserted, so the
    /// *which-probe* half of this evidence was unverified: a caller could
    /// dispatch `cursor_position` and label it `screen_info`. Requiring the
    /// request narrows that to a caller deliberately pairing a request with
    /// another request's dispatch, which the type cannot prevent — nothing in
    /// the value links them — so this is a tightening, not a proof, and is
    /// labelled as one.
    #[must_use]
    pub fn from_probe(request: &Request, dispatch: &Dispatch) -> Option<Self> {
        let probe = request.operation();
        if !matches!(probe, Operation::ScreenInfo | Operation::CursorPosition) {
            return None;
        }
        if !matches!(dispatch, Dispatch::Dispatched(Completion::Ok(_))) {
            return None;
        }
        Some(Self { probe })
    }

    #[must_use]
    pub const fn probe(&self) -> Operation {
        self.probe
    }
}

/// What the backend advertises **and** has been shown to do.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UpstreamSupport {
    commands: BTreeSet<String>,
    evidence: ProbeEvidence,
    capture_authority: CaptureAuthority,
}

impl UpstreamSupport {
    /// Build from a `/commands` reading, probe evidence, and a capture
    /// authority read from a **`version`** reading.
    ///
    /// All three are required, and the third is separate from the second for a
    /// reason the first review of this chunk had to point out: **`desktop_capture_authorized`
    /// is a member of the `version` response, not of `get_screen_size` or
    /// `get_cursor_position`.** The old code derived it from the probe result,
    /// so against the pinned backend it could only ever be `Unknown` and the
    /// capture gate could never refuse — an unreachable rule of exactly the
    /// kind deleted from `marker.rs` in this same chunk. Use
    /// [`CaptureAuthority::from_version_reading`] to produce it.
    #[must_use]
    pub fn new(
        advertised_commands: &[String],
        evidence: ProbeEvidence,
        capture_authority: CaptureAuthority,
    ) -> Self {
        Self {
            commands: advertised_commands.iter().cloned().collect(),
            evidence,
            capture_authority,
        }
    }

    /// The capture authority read from the `version` response.
    #[must_use]
    pub const fn capture_authority(&self) -> CaptureAuthority {
        self.capture_authority
    }

    #[must_use]
    pub fn advertises(&self, command: &str) -> bool {
        self.commands.contains(command)
    }

    #[must_use]
    pub const fn evidence(&self) -> &ProbeEvidence {
        &self.evidence
    }

    /// Whether the backend supports one `computer.v1` operation.
    ///
    /// `describe` maps to no single command, so it is supported whenever the
    /// backend answered the probe at all — which is the only honest reading:
    /// describing is exactly what this evidence is.
    #[must_use]
    pub fn supports(&self, operation: Operation) -> bool {
        match operation.upstream_command() {
            None => true,
            Some(command) => self.advertises(command),
        }
    }
}

/// Whether the backend may capture the screen.
///
/// **Three states.** On the supported 0.22.x SDK the released server omits
/// `desktop_capture_authorized` entirely, so `Unknown` is the normal answer on
/// a working host, not an error.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureAuthority {
    /// The backend said `true`.
    Granted,
    /// The backend said `false`.
    Denied,
    /// The backend did not say. **This is the default on the supported SDK.**
    Unknown,
}

/// The status member whose absence is not a denial.
pub const CAPTURE_AUTHORITY_MEMBER: &str = "desktop_capture_authorized";

/// The command whose response carries [`CAPTURE_AUTHORITY_MEMBER`].
///
/// **Not the probe.** `get_screen_size` and `get_cursor_position` do not carry
/// it, which is why reading capture authority from a probe result could only
/// ever produce [`CaptureAuthority::Unknown`].
pub const CAPTURE_AUTHORITY_COMMAND: &str = "version";

impl CaptureAuthority {
    /// Read the authority out of a **`version`** response payload.
    ///
    /// An absent key is [`CaptureAuthority::Unknown`]. A non-boolean value is
    /// also `Unknown` rather than `Denied`: this profile reports what it does
    /// not know as not known.
    #[must_use]
    pub fn from_status(status: &Value) -> Self {
        match status.get(CAPTURE_AUTHORITY_MEMBER) {
            Some(Value::Bool(true)) => Self::Granted,
            Some(Value::Bool(false)) => Self::Denied,
            _ => Self::Unknown,
        }
    }

    /// Read the authority out of a dispatched `version` command's result.
    ///
    /// Anything other than a dispatched success is [`CaptureAuthority::Unknown`]:
    /// a backend that did not answer has told us nothing about capture, and
    /// "told us nothing" is not "said no".
    ///
    /// **What this can and cannot observe on the pinned backend.** 0.3.46 made
    /// the key conditional on `hasattr`, so on the supported 0.22.x SDK the
    /// server **omits it** and the honest answer here is `Unknown` on every
    /// correctly-permissioned host. [`CaptureAuthority::Denied`] is therefore
    /// **modelled, not measured**: this repository has never seen a real
    /// backend emit `false`, and the fixture is what exercises that arm. Task
    /// row M5-C03 records it as modelled rather than letting the tri-state
    /// imply three observed states.
    #[must_use]
    pub fn from_version_reading(dispatch: &Dispatch) -> Self {
        match dispatch {
            Dispatch::Dispatched(Completion::Ok(result)) => Self::from_status(result),
            _ => Self::Unknown,
        }
    }

    /// Whether a capture may be attempted.
    ///
    /// `Unknown` means **yes, attempt it** — and that is a deliberate,
    /// argued choice rather than an oversight. Absence is the normal reading
    /// on the supported SDK, so refusing on absence would refuse capture on
    /// every correctly-permissioned host. The backend's own permission error
    /// is preserved when it comes (see
    /// [`crate::outcome::FailureCode::PermissionDenied`]), which is a real
    /// answer; refusing locally on a guess is not.
    #[must_use]
    pub const fn permits_attempt(self) -> bool {
        match self {
            Self::Granted | Self::Unknown => true,
            Self::Denied => false,
        }
    }
}

/// The negotiated capability set: the intersection of all three inputs.
///
/// Empty is a legitimate answer and the safe one.
#[must_use]
pub fn negotiate(
    local: &LocalConfiguration,
    upstream: &UpstreamSupport,
    grant: &CallerGrant,
) -> BTreeSet<Operation> {
    Operation::ALL
        .into_iter()
        .filter(|operation| {
            local.contains(*operation)
                && upstream.supports(*operation)
                && grant.contains(*operation)
        })
        .filter(|operation| {
            // Capture carries one extra gate, and only in the direction that
            // refuses: a backend that said `false` is taken at its word.
            *operation != Operation::Capture || upstream.capture_authority().permits_attempt()
        })
        .collect()
}

#[cfg(test)]
mod tests;
