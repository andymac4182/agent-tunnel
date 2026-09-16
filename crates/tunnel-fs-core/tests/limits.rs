//! Exact boundary behaviour on every limit, and the absence of an unlimited
//! sentinel.

mod common;

use tunnel_fs_core::{
    LimitError, LimitField, LimitRule, Limits, MAX_BUFFERED_FILE_BYTES_CEILING, MAX_FIDS_CEILING,
    MAX_MESSAGE_BYTES_CEILING, MAX_PATH_BYTES_CEILING, MAX_PATH_COMPONENTS_CEILING,
    MAX_QUEUED_BYTES_CEILING, MAX_TOTAL_BUFFERED_BYTES_CEILING, MIN_MESSAGE_BYTES,
};

/// The profile default, as an array in `LimitField::ALL` order.
const PROFILE: [u64; 14] = [
    65_536, 64, 256, 1_048_576, 16_777_216, 33_554_432, 4_096, 256, 10_000, 64, 30, 300, 3_600, 300,
];

#[test]
fn the_profile_default_is_itself_a_valid_limit_set() {
    let built = Limits::new(PROFILE).expect("the profile default must validate");
    assert_eq!(built, Limits::PROFILE_DEFAULT);
    assert_eq!(Limits::default(), Limits::PROFILE_DEFAULT);
}

#[test]
fn every_field_is_exact_at_its_ceiling_and_refused_one_beyond() {
    for (index, field) in LimitField::ALL.into_iter().enumerate() {
        let ceiling = field.ceiling();

        let mut at = PROFILE;
        at[index] = ceiling;
        let limits = Limits::new(at)
            .unwrap_or_else(|error| panic!("{field} at its ceiling was refused: {error}"));
        assert_eq!(limits.get(field), ceiling);

        let mut beyond = PROFILE;
        beyond[index] = ceiling + 1;
        let error =
            Limits::new(beyond).expect_err("a value one beyond the ceiling must be refused");
        assert_eq!(error.field(), field);
        assert_eq!(error.rule(), LimitRule::AboveCeiling);
    }
}

#[test]
fn zero_is_refused_for_every_field_so_it_cannot_mean_unlimited() {
    for (index, field) in LimitField::ALL.into_iter().enumerate() {
        let mut values = PROFILE;
        values[index] = 0;
        let error = Limits::new(values).expect_err("zero must be refused");
        assert_eq!(
            error.field(),
            field,
            "zero in {field} blamed the wrong field"
        );
        assert_eq!(error.rule(), LimitRule::Zero);
    }
}

#[test]
fn the_largest_representable_value_is_refused_for_every_field() {
    // A caller reaching for `u64::MAX` as "no limit" is refused by the ceiling,
    // not accepted as a sentinel.
    for (index, field) in LimitField::ALL.into_iter().enumerate() {
        let mut values = PROFILE;
        values[index] = u64::MAX;
        let error = Limits::new(values).expect_err("u64::MAX must be refused");
        assert_eq!(error.field(), field);
        assert_eq!(error.rule(), LimitRule::AboveCeiling);
    }
}

#[test]
fn a_smaller_configured_value_is_accepted_for_every_field() {
    for (index, field) in LimitField::ALL.into_iter().enumerate() {
        let mut values = PROFILE;
        // Reduce this field while keeping the cross-field rules satisfiable.
        values[index] = match field {
            LimitField::MaxMessageBytes => MIN_MESSAGE_BYTES,
            LimitField::MaxQueuedBytes => PROFILE[0],
            LimitField::MaxBufferedFileBytes => 1,
            LimitField::MaxTotalBufferedBytes => PROFILE[4],
            LimitField::RequestTimeoutSeconds => 1,
            LimitField::DefaultOperationTimeoutSeconds => PROFILE[10],
            LimitField::MaxOperationTimeoutSeconds => PROFILE[11],
            _ => 1,
        };
        let limits = Limits::new(values)
            .unwrap_or_else(|error| panic!("a reduced {field} was refused: {error}"));
        assert_eq!(limits.get(field), values[index]);
    }
}

#[test]
fn msize_has_a_floor_as_well_as_a_ceiling() {
    let mut values = PROFILE;
    values[0] = MIN_MESSAGE_BYTES;
    assert!(
        Limits::new(values).is_ok(),
        "256 bytes is the smallest msize"
    );

    values[0] = MIN_MESSAGE_BYTES - 1;
    let error = Limits::new(values).expect_err("a smaller dialect is rejected, not clamped");
    assert_eq!(error.field(), LimitField::MaxMessageBytes);
    assert_eq!(error.rule(), LimitRule::MessageBytesTooSmall);

    assert_eq!(MAX_MESSAGE_BYTES_CEILING, 65_536);
}

#[test]
fn cross_field_rules_are_enforced_at_their_own_boundaries() {
    let cases: &[(usize, u64, LimitField, LimitRule)] = &[
        // A queue smaller than one maximum-size message.
        (
            3,
            PROFILE[0] - 1,
            LimitField::MaxQueuedBytes,
            LimitRule::QueuedBytesBelowMessageBytes,
        ),
        // One materialized file larger than the whole concurrent budget.
        (
            5,
            PROFILE[4] - 1,
            LimitField::MaxBufferedFileBytes,
            LimitRule::BufferedFileAboveTotalBuffer,
        ),
        // A default operation deadline above the maximum.
        (
            12,
            PROFILE[11] - 1,
            LimitField::DefaultOperationTimeoutSeconds,
            LimitRule::DefaultOperationTimeoutAboveMaximum,
        ),
        // A single-request deadline above the operation default.
        (
            11,
            PROFILE[10] - 1,
            LimitField::RequestTimeoutSeconds,
            LimitRule::RequestTimeoutAboveOperationDefault,
        ),
    ];

    for (index, value, field, rule) in cases {
        let mut at = PROFILE;
        at[*index] = *value + 1;
        assert!(
            Limits::new(at).is_ok(),
            "{field} must be valid exactly at the boundary"
        );

        let mut beyond = PROFILE;
        beyond[*index] = *value;
        let error = Limits::new(beyond)
            .unwrap_err_or_panic(format!("{field} one past the boundary must be refused"));
        assert_eq!(error.field(), *field);
        assert_eq!(error.rule(), *rule);
    }
}

/// Small helper so the assertion above reads in one line.
trait UnwrapErrOrPanic {
    fn unwrap_err_or_panic(self, message: String) -> LimitError;
}

impl UnwrapErrOrPanic for Result<Limits, LimitError> {
    fn unwrap_err_or_panic(self, message: String) -> LimitError {
        match self {
            Ok(_) => panic!("{message}"),
            Err(error) => error,
        }
    }
}

#[test]
fn negotiation_only_ever_reduces() {
    let limits = Limits::PROFILE_DEFAULT;

    let reduced = limits
        .reduce_to(LimitField::MaxFids, 32)
        .expect("reducing is allowed");
    assert_eq!(reduced.max_fids(), 32);

    // Reducing to the same value is a no-op, not an error.
    assert_eq!(
        reduced
            .reduce_to(LimitField::MaxFids, 32)
            .expect("an equal value is still a reduction")
            .max_fids(),
        32
    );

    // Raising it back is refused, even though it is below the ceiling.
    let error = reduced
        .reduce_to(LimitField::MaxFids, 64)
        .expect_err("negotiation must never raise a limit");
    assert_eq!(error.field(), LimitField::MaxFids);
    assert_eq!(error.rule(), LimitRule::NotAReduction);
    const {
        // The refused value is below the ceiling, so only the reduction rule
        // can account for the refusal above.
        assert!(64 <= MAX_FIDS_CEILING);
    }

    // Zero is still refused through the negotiating path.
    assert_eq!(
        limits
            .reduce_to(LimitField::MaxFids, 0)
            .expect_err("zero")
            .rule(),
        LimitRule::Zero
    );

    // A reduction that breaks a cross-field rule is refused there.
    assert_eq!(
        limits
            .reduce_to(LimitField::MaxQueuedBytes, 1)
            .expect_err("a queue below one message")
            .rule(),
        LimitRule::QueuedBytesBelowMessageBytes
    );
}

#[test]
fn every_field_reduction_is_refused_when_it_would_raise() {
    for field in LimitField::ALL {
        let limits = Limits::PROFILE_DEFAULT;
        if limits.get(field) == field.ceiling() {
            // Already at the ceiling; anything larger must be refused as a
            // non-reduction before the ceiling rule is ever consulted.
            let error = limits
                .reduce_to(field, field.ceiling() + 1)
                .expect_err("above the current value");
            assert_eq!(error.field(), field);
            assert_eq!(error.rule(), LimitRule::NotAReduction);
        }
    }
}

#[test]
fn accessors_agree_with_the_field_table() {
    let limits = Limits::PROFILE_DEFAULT;
    assert_eq!(limits.max_message_bytes(), MAX_MESSAGE_BYTES_CEILING);
    assert_eq!(limits.max_inflight_requests(), 64);
    assert_eq!(limits.max_fids(), MAX_FIDS_CEILING);
    assert_eq!(limits.max_queued_bytes(), MAX_QUEUED_BYTES_CEILING);
    assert_eq!(
        limits.max_buffered_file_bytes(),
        MAX_BUFFERED_FILE_BYTES_CEILING
    );
    assert_eq!(
        limits.max_total_buffered_bytes(),
        MAX_TOTAL_BUFFERED_BYTES_CEILING
    );
    assert_eq!(limits.max_path_bytes(), MAX_PATH_BYTES_CEILING);
    assert_eq!(limits.max_path_components(), MAX_PATH_COMPONENTS_CEILING);
    assert_eq!(limits.max_traversal_entries(), 10_000);
    assert_eq!(limits.max_traversal_depth(), 64);
    assert_eq!(limits.request_timeout_seconds(), 30);
    assert_eq!(limits.default_operation_timeout_seconds(), 300);
    assert_eq!(limits.max_operation_timeout_seconds(), 3_600);
    assert_eq!(limits.session_idle_seconds(), 300);

    for field in LimitField::ALL {
        assert!(limits.get(field) > 0, "{field} must be positive");
        assert!(limits.get(field) <= field.ceiling(), "{field}");
    }
}

#[test]
fn path_bounds_follow_the_negotiated_limits() {
    let bounds = Limits::PROFILE_DEFAULT.path_bounds();
    assert_eq!(bounds.max_bytes(), 4_096);
    assert_eq!(bounds.max_components(), 256);

    let reduced = Limits::PROFILE_DEFAULT
        .reduce_to(LimitField::MaxPathBytes, 64)
        .expect("reducible")
        .reduce_to(LimitField::MaxPathComponents, 4)
        .expect("reducible");
    assert_eq!(reduced.path_bounds().max_bytes(), 64);
    assert_eq!(reduced.path_bounds().max_components(), 4);
}

#[test]
fn limit_diagnostics_are_static_strings_only() {
    for rule in LimitRule::ALL {
        assert_eq!(LimitRule::parse(rule.as_str()), Some(rule));
    }
    let mut names: Vec<&str> = LimitField::ALL.iter().map(|field| field.as_str()).collect();
    assert_eq!(names.len(), 14);
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "field spellings must be unique");
}
