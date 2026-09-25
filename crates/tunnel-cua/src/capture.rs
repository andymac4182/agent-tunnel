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
    /// `None` when nothing declared the scale (M5-C14). See
    /// [`CaptureRefusal::ScaleUndeclared`].
    scale_percent: Option<u32>,
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

    /// Capture pixels per backend point, as a percentage, **if anything
    /// declared it**.
    ///
    /// `None` is the ordinary case against a released backend: no pinned
    /// `screenshot` reports a scale (M5-C14), and on macOS the handler also
    /// resizes any capture wider than 1,920 px before encoding it, so the
    /// image's own pixel count is not the point space either. A capture with
    /// no declared scale still has an identity and still bounds-checks, but
    /// its coordinates cannot be placed in the backend's space, so
    /// [`Captures::resolve_point`] refuses them.
    #[must_use]
    pub const fn scale_percent(&self) -> Option<u32> {
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
    ///
    /// **`None` when the scale was never declared**, and there is deliberately
    /// no default: assuming 1x on a 2x display is a click at twice the
    /// intended position with no error anywhere, which is the failure this
    /// type exists to make impossible (M5-C14).
    #[must_use]
    pub const fn to_backend_point(&self, point: Point) -> Option<(u32, u32)> {
        let Some(scale) = self.scale_percent else {
            return None;
        };
        let scale = scale as u64;
        let identity = IDENTITY_SCALE_PERCENT as u64;
        Some((
            (point.x as u64 * identity / scale) as u32,
            (point.y as u64 * identity / scale) as u32,
        ))
    }
}

/// The target display's size in **input point space**, as a device operator
/// declares it (task row M5-C19, option (b); applied by default pending owner
/// confirmation, 2026-09-25).
///
/// # Why a size and not a factor
///
/// A declared *factor* is right for exactly one capture width: the pinned
/// macOS handler resizes any capture wider than 1,920 px before encoding it,
/// so the same display yields a 2x image at one resolution and a 1.27x image
/// at another. A declared *point size* survives that: the ratio is derived
/// **per capture**, from the image the consumer actually looked at, by
/// [`PointSpace::scale_percent_for`].
///
/// # What refuses rather than clicks elsewhere
///
/// * **Missing.** No declaration at all is the M5-C14 behaviour: every
///   coordinate is refused with [`CaptureRefusal::ScaleUndeclared`].
/// * **Inconsistent with the image.** A capture whose aspect ratio does not
///   match the declared size, or whose derived ratio is outside
///   `1..=`[`MAX_SCALE_PERCENT`], yields a [`ScaleDerivationError`]; the device then
///   records the capture with *no* scale, so every coordinate on it is
///   refused.
/// * **Inconsistent with the backend.** [`PointSpace::agrees_with_screen_size`]
///   compares the declaration with a dispatched `screen_info` reading; a
///   device refuses to declare a point space the backend contradicts.
///
/// **What it cannot catch, stated rather than implied:** a declaration that is
/// an exact integer fraction of the real point size on a platform whose
/// `get_screen_size` reports pixels (macOS: `ImageGrab`) has the same aspect
/// ratio and divides the screen size exactly, so it passes both checks. On
/// Linux X11 there is no scale, so the device requires the reading to equal
/// the declaration exactly and that case is refused too.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PointSpace {
    width: u32,
    height: u32,
}

/// Why a capture's scale could not be derived from a declared [`PointSpace`].
///
/// Every variant leaves the capture with **no** scale, so each is a refusal of
/// every coordinate on that capture, never a best guess.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ScaleDerivationError {
    /// The capture's aspect ratio disagrees with the declared point space by
    /// more than one percentage point of scale: a wrong declaration, a rotated
    /// display, or a capture of something other than the whole screen.
    AspectMismatch,
    /// The derived ratio is zero or above [`MAX_SCALE_PERCENT`].
    OutOfRange,
    /// The capture itself has a dimension outside
    /// `1..=`[`MAX_CAPTURE_DIMENSION`].
    Geometry,
}

impl core::fmt::Display for ScaleDerivationError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::AspectMismatch => {
                "the capture's aspect ratio disagrees with the declared point size"
            }
            Self::OutOfRange => "the capture-to-point ratio is out of range",
            Self::Geometry => "the capture has a dimension out of range",
        })
    }
}

impl std::error::Error for ScaleDerivationError {}

impl PointSpace {
    /// Declare a point-space size.
    ///
    /// # Errors
    /// [`GeometryError`] for a dimension outside `1..=`[`MAX_CAPTURE_DIMENSION`].
    pub fn new(width: u32, height: u32) -> Result<Self, GeometryError> {
        let bounded = 1..=MAX_CAPTURE_DIMENSION;
        if !bounded.contains(&width) || !bounded.contains(&height) {
            return Err(GeometryError);
        }
        Ok(Self { width, height })
    }

    #[must_use]
    pub const fn width(&self) -> u32 {
        self.width
    }

    #[must_use]
    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Derive the scale of one capture of this display, as a percentage of
    /// capture pixels per point (the unit [`Captures::record`] takes).
    ///
    /// Integer arithmetic only. Each axis's ratio is rounded **up** to a whole
    /// percent, and the two must agree within one percent. Rounding up is what
    /// keeps every pixel inside the display: with `p >= 100 * pixels / points`,
    /// the last pixel converts (with [`CaptureIdentity::to_backend_point`]'s
    /// truncation) to at most `(pixels - 1) * points / pixels < points`.
    /// Rounding to nearest would round 1,004 pixels over 1,000 points down to
    /// 100% and send the last three pixels past the display's edge.
    ///
    /// # Errors
    /// [`ScaleDerivationError`]; see its variants.
    pub fn scale_percent_for(
        &self,
        image_width: u32,
        image_height: u32,
    ) -> Result<u32, ScaleDerivationError> {
        let bounded = 1..=MAX_CAPTURE_DIMENSION;
        if !bounded.contains(&image_width) || !bounded.contains(&image_height) {
            return Err(ScaleDerivationError::Geometry);
        }
        let identity = u64::from(IDENTITY_SCALE_PERCENT);
        let rounded = |pixels: u32, points: u32| -> u64 {
            (u64::from(pixels) * identity).div_ceil(u64::from(points))
        };
        let horizontal = rounded(image_width, self.width);
        let vertical = rounded(image_height, self.height);
        if horizontal.abs_diff(vertical) > 1 {
            return Err(ScaleDerivationError::AspectMismatch);
        }
        let percent = horizontal.max(vertical);
        if percent == 0 || percent > u64::from(MAX_SCALE_PERCENT) {
            return Err(ScaleDerivationError::OutOfRange);
        }
        u32::try_from(percent).map_err(|_| ScaleDerivationError::OutOfRange)
    }

    /// Whether a dispatched `screen_info` reading is consistent with this
    /// declaration.
    ///
    /// `pixel_multiples` is the set of whole factors by which the backend's
    /// `get_screen_size` may exceed the point space on this platform:
    /// `&[1]` on Linux X11, which has no scale; `&[1, 2, 3]` where the pinned
    /// handler reports `ImageGrab` pixels (macOS). Both axes must use the
    /// same factor.
    #[must_use]
    pub fn agrees_with_screen_size(
        &self,
        reported_width: u32,
        reported_height: u32,
        pixel_multiples: &[u32],
    ) -> bool {
        pixel_multiples.iter().any(|factor| {
            u64::from(self.width) * u64::from(*factor) == u64::from(reported_width)
                && u64::from(self.height) * u64::from(*factor) == u64::from(reported_height)
        })
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
    /// The capture is known, current and contains the point, but **nothing
    /// declared its display scale**, so the point cannot be placed in the
    /// backend's coordinate space (M5-C14).
    ///
    /// No pinned backend reports a scale. This used to be defaulted to 1x,
    /// which on a scaled display is a click at the wrong place with no error;
    /// it is now a refusal the consumer can see, and the remedy is on the
    /// device (declare the scale), not a retry.
    ScaleUndeclared,
}

impl core::fmt::Display for CaptureRefusal {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(match self {
            Self::Unknown => "the capture identity is not known to this device",
            Self::TargetMismatch => "the capture belongs to a different target session",
            Self::Superseded => "the capture has been superseded by a newer one",
            Self::OutsideCapture => "the coordinates lie outside the capture",
            Self::ScaleUndeclared => "the capture's display scale was never declared",
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
        Ok(self.insert(target, display, width, height, Some(scale_percent)))
    }

    /// Record a capture whose display scale **nobody declared**.
    ///
    /// What a device does against a released backend with no configured scale
    /// (M5-C14): the capture has an identity, is current for its display and
    /// bounds-checks a point, and every coordinate that refers to it is
    /// refused with [`CaptureRefusal::ScaleUndeclared`] rather than defaulted.
    ///
    /// # Errors
    /// [`GeometryError`] for a dimension outside `1..=`[`MAX_CAPTURE_DIMENSION`].
    pub fn record_undeclared_scale(
        &mut self,
        target: &TargetSession,
        display: u32,
        width: u32,
        height: u32,
    ) -> Result<CaptureIdentity, GeometryError> {
        let bounded = 1..=MAX_CAPTURE_DIMENSION;
        if !bounded.contains(&width) || !bounded.contains(&height) {
            return Err(GeometryError);
        }
        Ok(self.insert(target, display, width, height, None))
    }

    fn insert(
        &mut self,
        target: &TargetSession,
        display: u32,
        width: u32,
        height: u32,
        scale_percent: Option<u32>,
    ) -> CaptureIdentity {
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
        identity
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
    /// The scale check runs last: a point outside the image is the more
    /// specific fact, and "declare the scale" is a device remedy the consumer
    /// cannot act on.
    ///
    /// # Errors
    /// Anything [`Captures::resolve`] refuses, plus
    /// [`CaptureRefusal::OutsideCapture`] and
    /// [`CaptureRefusal::ScaleUndeclared`].
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
        if identity.scale_percent.is_none() {
            return Err(CaptureRefusal::ScaleUndeclared);
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
