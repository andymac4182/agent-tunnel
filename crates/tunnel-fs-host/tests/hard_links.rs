//! Rule 4 of `docs/filesystem-api.md`: the hard-link policy, stated in terms of
//! what is observable — `st_nlink` and file identity — because a hard link is
//! not observable during a path walk.

mod support;

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, FsErrorCode, Primitive};
use tunnel_fs_host::Intent;

#[test]
fn tlink_is_refused_without_the_feature_and_permitted_with_it() {
    let fixture = Fixture::new();

    let without = fixture.open_default();
    assert_eq!(
        without
            .authorize(Primitive::Link)
            .expect_err("no Tlink without the hardLinks feature")
            .code(),
        FsErrorCode::Eperm
    );

    let with = fixture.open(
        full_grant(),
        FeatureSet::from_slice(&[Feature::HardLinks]),
        bounds(),
    );
    with.authorize(Primitive::Link)
        .expect("the feature plus write permits Tlink");
}

#[test]
fn a_multiply_linked_file_refuses_every_size_changing_primitive() {
    let fixture = Fixture::new();
    fixture.file("original.txt", b"synthetic-content");
    std::fs::hard_link(
        fixture.inside("original.txt"),
        fixture.inside("second-name.txt"),
    )
    .expect("create the second link");

    let export = fixture.open_default();
    let path = vpath("/original.txt");

    let handle = export
        .resolve(&path, Intent::Inspect)
        .expect("the file resolves");
    assert_eq!(handle.identity().links(), 2);
    assert!(handle.identity().is_multiply_linked_file());

    assert_eq!(
        export
            .open_write(&path)
            .expect_err("OpenWrite is refused")
            .code(),
        FsErrorCode::Eperm
    );
    assert_eq!(
        export
            .open_truncate(&path)
            .expect_err("OpenTruncate is refused")
            .code(),
        FsErrorCode::Eperm
    );
    assert_eq!(
        export
            .set_size(&path, 0)
            .expect_err("a size-changing Tsetattr is refused")
            .code(),
        FsErrorCode::Eperm
    );

    // The refusal is a refusal, not a refusal after the damage: the contract's
    // reason for never putting `O_TRUNC` in the resolving open.
    assert_eq!(
        std::fs::read(fixture.inside("original.txt")).expect("read back"),
        b"synthetic-content"
    );
    assert_eq!(
        std::fs::read(fixture.inside("second-name.txt")).expect("read back"),
        b"synthetic-content"
    );
}

#[test]
fn reads_of_a_multiply_linked_file_are_unaffected() {
    let fixture = Fixture::new();
    fixture.file("original.txt", b"synthetic-content");
    std::fs::hard_link(
        fixture.inside("original.txt"),
        fixture.inside("second-name.txt"),
    )
    .expect("create the second link");

    let export = fixture.open_default();
    let handle = export
        .open_read(&vpath("/original.txt"))
        .expect("a read grant is not narrowed by the link count");
    assert_eq!(handle.identity().links(), 2);
}

#[test]
fn a_singly_linked_file_is_writable_and_truncatable() {
    let fixture = Fixture::new();
    fixture.file("alone.txt", b"synthetic-content");

    let export = fixture.open_default();
    let path = vpath("/alone.txt");
    export.open_write(&path).expect("one link, so writable");
    export
        .open_truncate(&path)
        .expect("one link, so truncatable");
    assert_eq!(
        std::fs::read(fixture.inside("alone.txt")).expect("read back"),
        b""
    );
}

#[test]
fn advertising_hard_links_restores_the_write() {
    let fixture = Fixture::new();
    fixture.file("original.txt", b"synthetic-content");
    std::fs::hard_link(
        fixture.inside("original.txt"),
        fixture.inside("second-name.txt"),
    )
    .expect("create the second link");

    let export = fixture.open(
        full_grant(),
        FeatureSet::from_slice(&[Feature::HardLinks]),
        bounds(),
    );
    export
        .open_write(&vpath("/original.txt"))
        .expect("an export that advertises hardLinks writes multiply linked files");
}

#[test]
fn a_directory_link_count_does_not_trigger_the_rule() {
    let fixture = Fixture::new();
    fixture.dir("parent/child-one");
    fixture.dir("parent/child-two");

    let export = fixture.open_default();
    let handle = export
        .resolve(&vpath("/parent"), Intent::Inspect)
        .expect("the directory resolves");
    assert!(
        handle.identity().links() > 1,
        "a directory with children always has a link count above one"
    );
    assert!(
        !handle.identity().is_multiply_linked_file(),
        "the rule covers regular files only"
    );
}

#[test]
fn the_mode_and_time_setattr_primitives_are_outside_the_rule() {
    let fixture = Fixture::new();
    fixture.file("original.txt", b"synthetic-content");
    std::fs::hard_link(
        fixture.inside("original.txt"),
        fixture.inside("second-name.txt"),
    )
    .expect("create the second link");

    let export = fixture.open_default();
    let identity = export
        .resolve(&vpath("/original.txt"), Intent::Inspect)
        .expect("resolves")
        .identity();

    for primitive in [Primitive::SetattrMode, Primitive::SetattrTimes] {
        tunnel_fs_host::policy::check_hard_link_write(primitive, identity, false)
            .expect("mode and time changes are not size changes");
    }
    for primitive in [
        Primitive::OpenWrite,
        Primitive::OpenTruncate,
        Primitive::SetattrSize,
    ] {
        tunnel_fs_host::policy::check_hard_link_write(primitive, identity, false)
            .expect_err("the three named primitives are refused");
    }
}

#[test]
fn a_write_grant_is_still_required_before_the_link_count_is_consulted() {
    let fixture = Fixture::new();
    fixture.file("original.txt", b"synthetic-content");

    let read_only = fixture.open(
        CapabilitySet::from_slice(&[Capability::Read, Capability::List]),
        FeatureSet::NONE,
        bounds(),
    );
    let error = read_only
        .open_write(&vpath("/original.txt"))
        .expect_err("a read-only grant denies OpenWrite");
    assert_eq!(error, tunnel_fs_core::FsError::NotPermitted);
}
