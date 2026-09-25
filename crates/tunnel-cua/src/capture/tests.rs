use super::*;

fn target() -> TargetSession {
    TargetSession::new("console:1")
}

/// The happy path, and the four facts a capture carries forward.
#[test]
fn a_capture_carries_its_identity_dimensions_scale_and_target() {
    let mut captures = Captures::new();
    let target = target();
    let identity = captures
        .record(&target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();

    assert_eq!(identity.target(), &target);
    assert_eq!(identity.display(), 0);
    assert_eq!(identity.width(), 128);
    assert_eq!(identity.height(), 96);
    assert_eq!(identity.scale_percent(), Some(IDENTITY_SCALE_PERCENT));
    assert_eq!(captures.resolve(identity.id(), &target).unwrap(), &identity);
}

/// **The scale carry-forward, at a value where it is not the identity.**
///
/// A 2× capture is 256×192 pixels of a 128×96-point screen. The point the
/// consumer picked at pixel (100, 80) is backend point (50, 40). A
/// device that forwarded the pixel would click at (100, 80) — on the right
/// screen, at the wrong place, with no error raised anywhere.
#[test]
fn a_scaled_capture_converts_pixels_into_backend_points() {
    let mut captures = Captures::new();
    let identity = captures.record(&target(), 0, 256, 192, 200).unwrap();

    assert_eq!(
        identity.to_backend_point(Point::new(100, 80)),
        Some((50, 40))
    );
    assert_eq!(identity.to_backend_point(Point::new(0, 0)), Some((0, 0)));
    // Truncating: pixel 101 is still inside backend point 50.
    assert_eq!(
        identity.to_backend_point(Point::new(101, 81)),
        Some((50, 40))
    );

    // The control: at 1x the same arithmetic is the identity, so a test
    // written only against a 1x capture could not tell scaling from a
    // pass-through.
    let unscaled = captures
        .record(&target(), 1, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert_eq!(
        unscaled.to_backend_point(Point::new(100, 80)),
        Some((100, 80))
    );
}

/// The bounds check is half-open, so the pixel at `width` is outside.
#[test]
fn coordinates_outside_the_capture_are_refused_and_the_last_inside_pixel_is_not() {
    let mut captures = Captures::new();
    let target = target();
    let identity = captures
        .record(&target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    let id = identity.id();

    assert!(
        captures
            .resolve_point(id, &target, Point::new(127, 95))
            .is_ok()
    );
    for outside in [
        Point::new(128, 95),
        Point::new(127, 96),
        Point::new(128, 96),
        Point::new(u32::MAX, 0),
    ] {
        assert_eq!(
            captures.resolve_point(id, &target, outside).err(),
            Some(CaptureRefusal::OutsideCapture),
            "{outside:?} is outside a 128x96 capture"
        );
    }
}

/// **Staleness.** A newer capture for the same display supersedes the older
/// one, and the older reference is refused rather than best-guessed.
#[test]
fn a_superseded_capture_is_refused_and_the_newest_one_is_not() {
    let mut captures = Captures::new();
    let target = target();

    let first = captures
        .record(&target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert!(captures.resolve(first.id(), &target).is_ok());

    let second = captures
        .record(&target, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert_ne!(
        first.id(),
        second.id(),
        "a capture identity is never reused"
    );
    assert_eq!(
        captures.resolve(first.id(), &target).err(),
        Some(CaptureRefusal::Superseded)
    );
    assert!(captures.resolve(second.id(), &target).is_ok());

    // A capture of a *different* display does not supersede this one: the
    // currency is per (target, display), which is what makes a two-display
    // consumer workable at all.
    let other_display = captures
        .record(&target, 1, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert!(captures.resolve(second.id(), &target).is_ok());
    assert!(captures.resolve(other_display.id(), &target).is_ok());
}

/// A capture of another target is a mismatch, and the mismatch is reported
/// even when the capture is also stale — the ordering the module documents.
#[test]
fn a_capture_from_another_target_is_a_mismatch_before_it_is_stale() {
    let mut captures = Captures::new();
    let mine = target();
    let theirs = TargetSession::new("console:2");

    let hers = captures
        .record(&theirs, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert_eq!(
        captures.resolve(hers.id(), &mine).err(),
        Some(CaptureRefusal::TargetMismatch)
    );

    // Now make it stale as well. The answer must not change.
    captures
        .record(&theirs, 0, 128, 96, IDENTITY_SCALE_PERCENT)
        .unwrap();
    assert_eq!(
        captures.resolve(hers.id(), &mine).err(),
        Some(CaptureRefusal::TargetMismatch),
        "wrong machine is the more urgent fact"
    );
    // Non-vacuity: for its own target it is now genuinely stale, so the
    // assertion above is reading the target check rather than a blanket
    // refusal.
    assert_eq!(
        captures.resolve(hers.id(), &theirs).err(),
        Some(CaptureRefusal::Superseded)
    );
}

/// An identity nobody issued is refused. There is no "looks plausible" path.
#[test]
fn an_unissued_capture_identity_is_unknown() {
    let captures = Captures::new();
    assert_eq!(
        captures.resolve(CaptureId::new(1), &target()).err(),
        Some(CaptureRefusal::Unknown)
    );
    assert_eq!(
        captures.resolve(CaptureId::new(u64::MAX), &target()).err(),
        Some(CaptureRefusal::Unknown)
    );
}

/// A capture with impossible geometry is refused at the point it would be
/// recorded, so no later coordinate check has to reason about a zero-sized or
/// zero-scaled image — the shapes that would make every coordinate refused or
/// every backend point zero.
#[test]
fn impossible_capture_geometry_is_refused_rather_than_recorded() {
    let mut captures = Captures::new();
    let target = target();
    for (width, height, scale) in [
        (0, 96, IDENTITY_SCALE_PERCENT),
        (128, 0, IDENTITY_SCALE_PERCENT),
        (128, 96, 0),
        (128, 96, MAX_SCALE_PERCENT + 1),
        (MAX_CAPTURE_DIMENSION + 1, 96, IDENTITY_SCALE_PERCENT),
        (128, MAX_CAPTURE_DIMENSION + 1, IDENTITY_SCALE_PERCENT),
    ] {
        assert_eq!(
            captures.record(&target, 0, width, height, scale).err(),
            Some(GeometryError),
            "{width}x{height} at {scale}% must not be recorded"
        );
    }
    assert!(captures.is_empty(), "a refused capture issues no identity");
    // Non-vacuity: every boundary value itself is accepted.
    assert!(captures.record(&target, 0, 1, 1, MAX_SCALE_PERCENT).is_ok());
    assert!(
        captures
            .record(
                &target,
                1,
                MAX_CAPTURE_DIMENSION,
                MAX_CAPTURE_DIMENSION,
                IDENTITY_SCALE_PERCENT
            )
            .is_ok()
    );
    assert_eq!(captures.len(), 2);

    // And the widest accepted capture converts without wrapping, which is the
    // arithmetic the u64 intermediate exists for.
    let widest = captures
        .record(&target, 2, MAX_CAPTURE_DIMENSION, 8, MAX_SCALE_PERCENT)
        .unwrap();
    assert_eq!(
        widest.to_backend_point(Point::new(MAX_CAPTURE_DIMENSION - 1, 0)),
        Some(((MAX_CAPTURE_DIMENSION - 1) / 8, 0))
    );
}

/// **M5-C14: a capture whose scale nobody declared is recorded, bounds-checks,
/// and refuses to place a point -- it never defaults to 1x.**
#[test]
fn an_undeclared_scale_is_refused_at_resolution_and_never_defaulted() {
    let mut captures = Captures::new();
    let target = target();
    let identity = captures
        .record_undeclared_scale(&target, 0, 256, 192)
        .unwrap();
    assert_eq!(identity.scale_percent(), None);
    assert_eq!(identity.to_backend_point(Point::new(100, 80)), None);

    // It is a real, current identity: resolving it succeeds...
    assert_eq!(captures.resolve(identity.id(), &target).unwrap(), &identity);
    // ...a point outside it is refused as outside, the more specific fact...
    assert_eq!(
        captures.resolve_point(identity.id(), &target, Point::new(256, 0)),
        Err(CaptureRefusal::OutsideCapture)
    );
    // ...and a point inside it is refused for the missing scale.
    assert_eq!(
        captures.resolve_point(identity.id(), &target, Point::new(100, 80)),
        Err(CaptureRefusal::ScaleUndeclared)
    );

    // The control: the same geometry with a declared scale resolves, so the
    // refusal is the declaration and not the geometry.
    let declared = captures.record(&target, 0, 256, 192, 200).unwrap();
    assert!(
        captures
            .resolve_point(declared.id(), &target, Point::new(100, 80))
            .is_ok()
    );

    // Geometry is still validated without a scale.
    assert_eq!(
        captures.record_undeclared_scale(&target, 0, 0, 1),
        Err(GeometryError)
    );
    assert_eq!(
        captures.record_undeclared_scale(&target, 0, MAX_CAPTURE_DIMENSION + 1, 1),
        Err(GeometryError)
    );
}
