//! **Capture identity carried into actions**, and the rejection of stale or
//! mismatched capture coordinates.
//!
//! `docs/integrations.md`: "Carry capture identity, coordinate dimensions,
//! display scale and target identity into subsequent actions, and reject stale
//! or mismatched capture coordinates."
//!
//! # Why a coordinate needs a capture to mean anything
//!
//! A consumer picks a point by looking at an image. The number it sends is a
//! pixel of *that* image. Three things can make the same number mean something
//! else by the time it arrives:
//!
//! * **A different target.** The image came from another OS session.
//! * **A newer capture.** The screen changed — a window moved, the resolution
//!   changed, the display was rotated — and the point now names different
//!   content. This is the *stale* case, and it is refused
//!   ([`CaptureRefusal::Superseded`]) rather than clamped or best-guessed.
//! * **A different scale.** A 2× display returns an image whose pixels are
//!   half a backend point each. A pixel forwarded as a point clicks at half
//!   the intended position, on the correct screen, with no error anywhere —
//!   the failure mode that is hardest to notice and most expensive to have.
//!
//! So [`CaptureIdentity`] carries all four — capture identity, dimensions,
//! scale and target — and [`Captures::resolve`] refuses anything it cannot
//! place. [`CaptureIdentity::to_backend_point`] is where the scale is actually
//! applied; it is not advisory.
//!
//! # Scale is an integer percentage, deliberately
//!
//! No floats anywhere in this crate. A capture reports
//! [`CaptureIdentity::scale_percent`] — 100 for a 1× display, 200 for a 2× one
//! — and the conversion is integer arithmetic, so the same request produces
//! the same backend coordinate on every host and in every test run. A float
//! would make a coordinate a rounding question.
//!
//! # What "current" means, and the cost of that choice
//!
//! [`Captures`] keeps the **most recent capture per (target, display)**.
//! Anything older is [`CaptureRefusal::Superseded`]. That is stricter than
//! necessary in one benign case — a consumer that captured, captured again,
//! and then clicked on the first image — and the strictness is the point: the
//! alternative is a device deciding for itself which stale image is still
//! close enough, which is exactly the judgement it cannot make. A consumer
//! that wants to act on what it saw captures again and acts on that.

use std::collections::BTreeMap;

use crate::lease::TargetSession;

/// Identifies one capture. Fresh per capture, never reused.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct CaptureId(u64);

impl CaptureId {
    #[must_use]
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A point in **capture pixel space** — the coordinate space of the image the
/// consumer actually looked at, not the backend's.
///
/// The distinction is the whole reason this type exists rather than a bare
/// pair: [`CaptureIdentity::to_backend_point`] is the only thing that produces
/// the other space, and it needs a capture to do it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Point {
    pub x: u32,
    pub y: u32,
}

impl Point {
    #[must_use]
    pub const fn new(x: u32, y: u32) -> Self {
        Self { x, y }
    }
}

/// Everything one capture carries forward into a later action.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CaptureIdentity {
    id: CaptureId,
    target: TargetSession,
    display: u32,
    width: u32,
    height: u32,
    scale_percent: u32,
}

/// The scale a 1× display reports. Conversion at this value is the identity,
/// which is why a test written only against it proves nothing about scaling.
pub const IDENTITY_SCALE_PERCENT: u32 = 100;

/// The largest scale this profile accepts. 8× is far past any shipping
/// display; the bound exists so the conversion cannot be handed a value that
/// makes every coordinate zero.
pub const MAX_SCALE_PERCENT: u32 = 800;

/// The largest capture dimension this profile records, in pixels.
///
/// Matches [`crate::schema::MAX_COORDINATE`], because a capture larger than
/// the largest coordinate a request may carry has a region no request could
/// ever point at. Bounded where a capture is *recorded*, so that
/// [`CaptureIdentity::contains`] and [`CaptureIdentity::to_backend_point`]
/// never see a dimension nobody checked.
pub const MAX_CAPTURE_DIMENSION: u32 = 65_535;

impl CaptureIdentity {
    #[must_use]
    pub const fn id(&self) -> CaptureId {
        self.id
    }

    #[must_use]
    pub fn target(&self) -> &TargetSession {
        &self.target
    }

    #[must_use]
    pub const fn display(&self) -> u32 {
        self.display
    }

    /// Image width in capture pixels.
    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    /// Image height in capture pixels.
    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Capture pixels per backend point, as a percentage.
    #[must_use]
    pub const fn scale_percent(&self) -> u32 {
        self.scale_percent
    }

    /// Whether a point lies inside this capture.
    ///
    /// Half-open: the pixel at `width` does not exist. An off-by-one here is a
    /// click one pixel outside the image the consumer looked at.
    #[must_use]
    pub const fn contains(&self, point: Point) -> bool {
        point.x < self.width && point.y < self.height
    }

    /// Convert a capture-space point into the backend's point space.
    ///
    /// **This is the display-scale carry-forward, and it is the arithmetic
    /// rather than a field that is passed along.** At
    /// [`IDENTITY_SCALE_PERCENT`] it is the identity, which is exactly why the
    /// fixture can serve a 2× capture: a rule that is only ever exercised at
    /// its identity value is not exercised.
    ///
    /// Truncating division. A capture pixel is a *sub-point* on a scaled
    /// display, so there is no exact answer for odd pixels; truncation keeps
    /// the point inside the same backend point as the pixel, which rounding
    /// would not.
    /// The multiplication is done in `u64` and the division brings it back.
    /// Review pointed out that `point.x * IDENTITY_SCALE_PERCENT` wraps in
    /// release for an x above ~42.9M. That is unreachable with real geometry
    /// *and* with [`MAX_CAPTURE_DIMENSION`], which bounds it three orders of
    /// magnitude lower — but an arithmetic guard that depends on a bound
    /// somewhere else stops being true when that bound moves, and the wider
    /// intermediate costs nothing.
    #[must_use]
    pub const fn to_backend_point(&self, point: Point) -> (u32, u32) {
        let scale = self.scale_percent as u64;
        let identity = IDENTITY_SCALE_PERCENT as u64;
        (
            (point.x as u64 * identity / scale) as u32,
            (point.y as u64 * identity / scale) as u32,
        )
    }
}

/// Why a capture reference was refused.
///
/// **Every variant means nothing was dispatched.**
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum CaptureRefusal {
    /// No capture with that identity was ever issued by this device, or it has
    /// been forgotten. Never treated as "probably fine".
    Unknown,
    /// The capture belongs to a different target OS session than the one this
    /// tunnel session is driving. A coordinate from another machine's screen.
    TargetMismatch,
    /// A newer capture exists for the same target and display. **This is the
    /// stale case.**
    Superseded,
    /// The point lies outside the capture's dimensions.
    OutsideCapture,
}

impl core::fmt::Display for CaptureRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "the capture identity is not known to this device",
            Self::TargetMismatch => "the capture belongs to a different target session",
            Self::Superseded => "the capture has been superseded by a newer one",
            Self::OutsideCapture => "the coordinates lie outside the capture",
        })
    }
}

impl std::error::Error for CaptureRefusal {}

/// A rejected capture geometry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GeometryError;

impl core::fmt::Display for GeometryError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str("a capture must have non-zero dimensions and a scale within range")
    }
}

impl std::error::Error for GeometryError {}

/// The captures this device has issued, and which is current per display.
///
/// Pure state; no clock. A capture is superseded by a later one for the same
/// `(target, display)`, never by the passage of time.
#[derive(Clone, Debug, Default)]
pub struct Captures {
    next: u64,
    by_id: BTreeMap<CaptureId, CaptureIdentity>,
    current: BTreeMap<(TargetSession, u32), CaptureId>,
}

impl Captures {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Record a capture that has just succeeded, and make it current for its
    /// display.
    ///
    /// Called by the device-side facade **after** a `capture` has come back
    /// [`crate::outcome::Completion::Ok`]. A capture that failed, or whose
    /// outcome is unknown, issues no identity: there is no image the consumer
    /// could have looked at.
    ///
    /// # Errors
    /// [`GeometryError`] for a dimension outside
    /// `1..=`[`MAX_CAPTURE_DIMENSION`] or a scale outside
    /// `1..=`[`MAX_SCALE_PERCENT`].
    pub fn record(
        &mut self,
        target: &TargetSession,
        display: u32,
        width: u32,
        height: u32,
        scale_percent: u32,
    ) -> Result<CaptureIdentity, GeometryError> {
        if width == 0
            || height == 0
            || width > MAX_CAPTURE_DIMENSION
            || height > MAX_CAPTURE_DIMENSION
            || scale_percent == 0
            || scale_percent > MAX_SCALE_PERCENT
        {
            return Err(GeometryError);
        }
        self.next += 1;
        let identity = CaptureIdentity {
            id: CaptureId(self.next),
            target: target.clone(),
            display,
            width,
            height,
            scale_percent,
        };
        self.by_id.insert(identity.id, identity.clone());
        self.current.insert((target.clone(), display), identity.id);
        Ok(identity)
    }

    /// Resolve a capture reference for a session driving `target`.
    ///
    /// The order of the three refusals is deliberate and is asserted: unknown,
    /// then target, then staleness. A capture from another target must report
    /// the target mismatch even when it is also stale, because "you are
    /// pointing at the wrong machine" is the more urgent fact.
    ///
    /// # Errors
    /// [`CaptureRefusal::Unknown`], [`CaptureRefusal::TargetMismatch`] or
    /// [`CaptureRefusal::Superseded`].
    pub fn resolve(
        &self,
        id: CaptureId,
        target: &TargetSession,
    ) -> Result<&CaptureIdentity, CaptureRefusal> {
        let identity = self.by_id.get(&id).ok_or(CaptureRefusal::Unknown)?;
        if identity.target() != target {
            return Err(CaptureRefusal::TargetMismatch);
        }
        if self.current.get(&(target.clone(), identity.display())) != Some(&id) {
            return Err(CaptureRefusal::Superseded);
        }
        Ok(identity)
    }

    /// Resolve a reference and check that a point lies inside it.
    ///
    /// # Errors
    /// Anything [`Captures::resolve`] refuses, plus
    /// [`CaptureRefusal::OutsideCapture`].
    pub fn resolve_point(
        &self,
        id: CaptureId,
        target: &TargetSession,
        point: Point,
    ) -> Result<&CaptureIdentity, CaptureRefusal> {
        let identity = self.resolve(id, target)?;
        if !identity.contains(point) {
            return Err(CaptureRefusal::OutsideCapture);
        }
        Ok(identity)
    }

    /// Forget **every** capture identity, and report how many were forgotten.
    ///
    /// What a **supervised backend restart** does. Every identity this device
    /// issued describes an image produced by a backend that is gone: the
    /// screen it was read from may have changed while the backend was being
    /// replaced, and nothing observed it. A coordinate picked from such an
    /// image is a coordinate on a screen nobody can vouch for, which is
    /// exactly the condition [`CaptureRefusal`] exists to refuse.
    ///
    /// **`next` is deliberately not reset, and that is load-bearing.** A
    /// consumer holding a pre-restart [`CaptureId`] must get
    /// [`CaptureRefusal::Unknown`] from [`Captures::resolve`] — not a
    /// *different image that happens to have been given the same number*. If
    /// the counter restarted, the first capture after a restart would reissue
    /// id 1, a stale click would resolve against it, pass the bounds check,
    /// and be dispatched at coordinates picked from an image nobody is
    /// looking at. Monotonicity is what makes "unknown" mean unknown.
    pub fn invalidate_all(&mut self) -> usize {
        let forgotten = self.by_id.len();
        self.by_id.clear();
        self.current.clear();
        forgotten
    }

    /// The current capture for one display, if any.
    #[must_use]
    pub fn current(&self, target: &TargetSession, display: u32) -> Option<&CaptureIdentity> {
        self.current
            .get(&(target.clone(), display))
            .and_then(|id| self.by_id.get(id))
    }

    /// How many capture identities have been issued and retained.
    #[must_use]
    pub fn len(&self) -> usize {
        self.by_id.len()
    }

    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_id.is_empty()
    }
}

#[cfg(test)]
mod tests;
