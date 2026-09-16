//! The error vocabulary, outcome monotonicity, and the payload-free rule.

mod common;

use tunnel_fs_core::{FsError, FsErrorCode, LimitField, Outcome, PathRule, SessionErrorCode};

#[test]
fn every_code_round_trips_and_has_a_unique_spelling_and_errno() {
    let mut spellings = Vec::new();
    let mut errnos = Vec::new();
    for code in FsErrorCode::ALL {
        assert_eq!(FsErrorCode::parse(code.as_str()), Some(code));
        assert_eq!(format!("{code}"), code.as_str());
        spellings.push(code.as_str());
        errnos.push(code.errno());
    }
    spellings.sort_unstable();
    let before = spellings.len();
    spellings.dedup();
    assert_eq!(before, spellings.len(), "codes must be unique");

    errnos.sort_unstable();
    let before = errnos.len();
    errnos.dedup();
    assert_eq!(before, errnos.len(), "errnos must be unique");

    for code in SessionErrorCode::ALL {
        assert_eq!(SessionErrorCode::parse(code.as_str()), Some(code));
    }
    assert_eq!(FsErrorCode::parse("EWOULDBLOCK"), None);
    assert_eq!(SessionErrorCode::parse("OK"), None);
}

#[test]
fn every_defined_errno_maps_back_to_its_own_code() {
    for code in FsErrorCode::ALL {
        assert_eq!(
            FsErrorCode::from_errno(code.errno()),
            code,
            "{code} did not survive an errno round trip"
        );
    }
}

#[test]
fn an_unmapped_errno_becomes_einval_rather_than_passing_through() {
    let defined: Vec<u32> = FsErrorCode::ALL.iter().map(|code| code.errno()).collect();
    let mut checked = 0;
    for errno in 0u32..256 {
        if defined.contains(&errno) {
            continue;
        }
        assert_eq!(
            FsErrorCode::from_errno(errno),
            FsErrorCode::Einval,
            "errno {errno} must not widen the vocabulary"
        );
        checked += 1;
    }
    assert!(
        checked > 200,
        "the sweep must actually cover unmapped values"
    );
}

#[test]
fn outcomes_never_weaken() {
    // Once partial or unknown has been observed, nothing may report the
    // operation as never having started.
    for earlier in Outcome::ALL {
        for later in Outcome::ALL {
            let merged = earlier.merge(later);
            assert!(merged >= earlier, "{earlier} weakened to {merged}");
            assert!(merged >= later, "{later} weakened to {merged}");
        }
    }

    assert_eq!(
        Outcome::Partial.merge(Outcome::NotStarted),
        Outcome::Partial,
        "a rejection after a confirmed partial chunk cannot become not_started"
    );
    assert_eq!(
        Outcome::Unknown.merge(Outcome::Failed),
        Outcome::Unknown,
        "an unknown outcome cannot be downgraded to a clean failure"
    );
    assert_eq!(
        Outcome::NotStarted.merge(Outcome::Unknown),
        Outcome::Unknown
    );
    assert_eq!(
        Outcome::NotStarted.merge(Outcome::NotStarted),
        Outcome::NotStarted
    );
}

#[test]
fn only_a_settled_outcome_claims_no_side_effect() {
    assert!(Outcome::NotStarted.is_settled());
    assert!(Outcome::Failed.is_settled());
    assert!(
        !Outcome::Partial.is_settled(),
        "a partial mutation had a side effect"
    );
    assert!(
        !Outcome::Unknown.is_settled(),
        "an unknown mutation may have had a side effect"
    );

    for outcome in Outcome::ALL {
        assert_eq!(Outcome::parse(outcome.as_str()), Some(outcome));
    }
    assert_eq!(Outcome::parse("succeeded"), None);
}

#[test]
fn a_refusal_this_crate_produces_never_started() {
    // Nothing here dispatches anything, so every error it can build on its own
    // must be `not_started`.  A variant added without that property fails here.
    for rule in PathRule::ALL {
        let error = FsError::Path(rule);
        assert_eq!(error.outcome(), Outcome::NotStarted, "{rule}");
        assert!(error.did_not_start());
    }
    for field in LimitField::ALL {
        let error = FsError::Limit(field);
        assert_eq!(error.outcome(), Outcome::NotStarted, "{field}");
    }
    assert_eq!(FsError::NotPermitted.outcome(), Outcome::NotStarted);
    assert_eq!(FsError::NotPermitted.code(), FsErrorCode::Eperm);

    for code in FsErrorCode::ALL {
        assert_eq!(FsError::refused(code).outcome(), Outcome::NotStarted);
        assert_eq!(FsError::refused(code).code(), code);
    }
}

#[test]
fn a_dispatched_failure_keeps_the_outcome_it_was_built_with() {
    for outcome in Outcome::ALL {
        let error = FsError::Filesystem {
            code: FsErrorCode::Eacces,
            outcome,
        };
        assert_eq!(error.outcome(), outcome);
        assert_eq!(error.did_not_start(), outcome == Outcome::NotStarted);

        let session = FsError::Session {
            code: SessionErrorCode::SessionLost,
            outcome,
        };
        assert_eq!(session.outcome(), outcome);
    }
}

#[test]
fn path_and_limit_failures_translate_to_a_stable_errno() {
    assert_eq!(
        FsError::Path(PathRule::TooLongBytes).code(),
        FsErrorCode::Enametoolong
    );
    assert_eq!(
        FsError::Path(PathRule::ComponentTooLong).code(),
        FsErrorCode::Enametoolong
    );
    for rule in PathRule::ALL {
        let expected = match rule {
            PathRule::TooLongBytes | PathRule::ComponentTooLong => FsErrorCode::Enametoolong,
            _ => FsErrorCode::Einval,
        };
        assert_eq!(FsError::Path(rule).code(), expected, "{rule}");
    }

    assert_eq!(
        FsError::Limit(LimitField::MaxBufferedFileBytes).code(),
        FsErrorCode::Efbig
    );
    assert_eq!(
        FsError::Limit(LimitField::MaxPathBytes).code(),
        FsErrorCode::Enametoolong
    );
    assert_eq!(
        FsError::Limit(LimitField::SessionIdleSeconds).code(),
        FsErrorCode::Einval
    );
}

#[test]
fn session_failures_carry_the_documented_close_codes() {
    assert_eq!(SessionErrorCode::ProtocolViolation.close_code(), 1002);
    assert_eq!(SessionErrorCode::AuthExpired.close_code(), 1008);
    assert_eq!(SessionErrorCode::CapabilitiesChanged.close_code(), 1008);
    assert_eq!(SessionErrorCode::ResourceExhausted.close_code(), 1013);
    assert_eq!(SessionErrorCode::SessionLost.close_code(), 1011);

    for code in SessionErrorCode::ALL {
        let close = code.close_code();
        assert!(
            (1002..=1013).contains(&close),
            "{code} used an out-of-range close code {close}"
        );
    }
}

#[test]
fn absence_is_distinguishable_from_unavailability() {
    // `exists` may convert only a confirmed ENOENT into false.  Session
    // failures live in a separate type precisely so that cannot be confused.
    let absent = FsError::refused(FsErrorCode::Enoent);
    assert_eq!(absent.code(), FsErrorCode::Enoent);

    for code in SessionErrorCode::ALL {
        let session = FsError::Session {
            code,
            outcome: Outcome::Unknown,
        };
        assert_ne!(
            session.code(),
            FsErrorCode::Enoent,
            "{code} must never look like absence"
        );
    }
}

/// A marker that must never appear in any rendering of an error.
const SECRET: &str = "/home/user/secret-directory/confidential.key";

#[test]
fn no_error_rendering_can_contain_a_path_or_content() {
    // Every error this crate can build, in Debug and Display.  Because every
    // variant is Copy over field-free enums, there is no value to leak; this
    // test is the assertion that the property still holds.
    let mut errors = Vec::new();
    for rule in PathRule::ALL {
        errors.push(FsError::Path(rule));
    }
    for field in LimitField::ALL {
        errors.push(FsError::Limit(field));
    }
    errors.push(FsError::NotPermitted);
    for code in FsErrorCode::ALL {
        for outcome in Outcome::ALL {
            errors.push(FsError::Filesystem { code, outcome });
        }
    }
    for code in SessionErrorCode::ALL {
        for outcome in Outcome::ALL {
            errors.push(FsError::Session { code, outcome });
        }
    }

    assert!(
        errors.len() > 80,
        "the sweep must cover the whole vocabulary"
    );
    for error in errors {
        for rendered in [format!("{error:?}"), format!("{error}")] {
            assert!(!rendered.is_empty());
            for fragment in [
                SECRET,
                "secret-directory",
                "confidential",
                "/home",
                ".key",
                "user",
            ] {
                assert!(
                    !rendered.contains(fragment),
                    "rendering {rendered:?} leaked {fragment:?}"
                );
            }
            // Only ASCII, and nothing that looks like a path.
            assert!(rendered.is_ascii(), "rendering {rendered:?} is not ASCII");
            assert!(
                !rendered.contains('/'),
                "rendering {rendered:?} contains a separator"
            );
        }
    }
}

#[test]
fn display_is_a_code_and_an_outcome_or_rule() {
    assert_eq!(
        format!("{}", FsError::refused(FsErrorCode::Enoent)),
        "ENOENT (not_started)"
    );
    assert_eq!(format!("{}", FsError::NotPermitted), "EPERM (not_started)");
    assert_eq!(
        format!("{}", FsError::Path(PathRule::DotDotComponent)),
        "EINVAL (PATH_DOTDOT_COMPONENT)"
    );
    assert_eq!(
        format!("{}", FsError::Limit(LimitField::MaxBufferedFileBytes)),
        "EFBIG (maxBufferedFileBytes)"
    );
    assert_eq!(
        format!(
            "{}",
            FsError::Session {
                code: SessionErrorCode::SessionLost,
                outcome: Outcome::Unknown,
            }
        ),
        "SESSION_LOST (unknown)"
    );
}

#[test]
fn a_path_rule_converts_into_an_error_without_carrying_the_path() {
    let bounds = tunnel_fs_core::Limits::PROFILE_DEFAULT.path_bounds();
    let rule = tunnel_fs_core::VirtualPath::parse("/a/../../etc/shadow", bounds)
        .expect_err("an escape must be refused");
    let error: FsError = rule.into();

    assert_eq!(error, FsError::Path(PathRule::DotDotComponent));
    for rendered in [format!("{error:?}"), format!("{error}")] {
        assert!(!rendered.contains("etc"), "{rendered}");
        assert!(!rendered.contains("shadow"), "{rendered}");
    }
}
