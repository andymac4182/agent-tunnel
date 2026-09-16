//! The symbolic-link policy of `docs/filesystem-api.md` rule 3, against a real
//! temporary filesystem.

mod support;

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::{FeatureSet, FsErrorCode, Primitive};
use tunnel_fs_host::{ExportRoot, FileIdentity, Intent};

/// The identity of the file an escape would reach, obtained by exporting the
/// outside directory in its own right.  An escape is then not "an error did not
/// happen" but "this exact inode was handed out".
fn outside_identity(fixture: &Fixture) -> FileIdentity {
    let outside = ExportRoot::open(&fixture.outside(), full_grant(), FeatureSet::NONE, bounds())
        .expect("open the outside tree as its own export");
    outside
        .resolve(&vpath("/secret.txt"), Intent::Inspect)
        .expect("the outside file exists")
        .identity()
}

#[test]
fn an_absolute_link_out_of_the_root_is_not_followed_without_the_feature() {
    let fixture = Fixture::new();
    let target = fixture.outside().join("secret.txt");
    fixture.link("escape.txt", target.to_str().expect("utf-8 fixture path"));

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/escape.txt"), Intent::Inspect)
        .expect_err("a link must fail the walk when symlinks are off");
    assert_eq!(error.code(), FsErrorCode::Eloop);
}

#[test]
fn an_absolute_link_out_of_the_root_is_rerooted_with_the_feature() {
    let fixture = Fixture::new();
    let target = fixture.outside().join("secret.txt");
    fixture.link("escape.txt", target.to_str().expect("utf-8 fixture path"));

    let export = fixture.open_with_symlinks();
    // The target is resolved against the exported virtual root, so it names
    // `<root>/private/.../outside/secret.txt`, which does not exist.
    let error = export
        .resolve(&vpath("/escape.txt"), Intent::Inspect)
        .expect_err("an absolute target is re-rooted, not followed to host /");
    assert_eq!(error.code(), FsErrorCode::Enoent);
}

#[test]
fn a_rerooted_absolute_link_reaches_the_file_of_that_name_inside_the_export() {
    let fixture = Fixture::new();
    fixture.file("etc/hosts", b"synthetic-inside");
    fixture.link("alias", "/etc/hosts");

    let export = fixture.open_with_symlinks();
    let through_link = export
        .resolve(&vpath("/alias"), Intent::Inspect)
        .expect("the re-rooted target exists inside the export");
    let direct = export
        .resolve(&vpath("/etc/hosts"), Intent::Inspect)
        .expect("the target resolves directly too");
    assert!(through_link.identity().is_same_file(direct.identity()));
}

#[test]
fn an_absolute_target_is_resolved_from_the_root_not_from_the_links_own_directory() {
    let fixture = Fixture::new();
    fixture.file("etc/hosts", b"synthetic-inside");
    fixture.dir("sub");
    fixture.file("sub/etc/hosts", b"synthetic-decoy");
    fixture.link("sub/alias", "/etc/hosts");

    let export = fixture.open_with_symlinks();
    let through_link = export
        .resolve(&vpath("/sub/alias"), Intent::Inspect)
        .expect("the absolute target resolves");
    let from_root = export
        .resolve(&vpath("/etc/hosts"), Intent::Inspect)
        .expect("resolves directly");
    let decoy = export
        .resolve(&vpath("/sub/etc/hosts"), Intent::Inspect)
        .expect("the decoy exists");

    assert!(
        through_link.identity().is_same_file(from_root.identity()),
        "an absolute link target is anchored at the export root"
    );
    assert!(
        !through_link.identity().is_same_file(decoy.identity()),
        "not at the directory the link happens to live in"
    );
}

#[test]
fn a_relative_parent_link_is_clamped_at_the_root() {
    let fixture = Fixture::new();
    fixture.dir("sub");
    fixture.link("sub/escape.txt", "../../outside/secret.txt");

    let export = fixture.open_with_symlinks();
    let error = export
        .resolve(&vpath("/sub/escape.txt"), Intent::Inspect)
        .expect_err("`..` cannot climb above the export root");
    assert_eq!(error.code(), FsErrorCode::Enoent);
}

#[test]
fn a_chain_of_links_resolves_to_the_file_it_ends_at() {
    let fixture = Fixture::new();
    fixture.file("real.txt", b"synthetic");
    fixture.link("one", "two");
    fixture.link("two", "three");
    fixture.link("three", "real.txt");

    let export = fixture.open_with_symlinks();
    let through_chain = export
        .resolve(&vpath("/one"), Intent::Inspect)
        .expect("a three-link chain resolves");
    let direct = export
        .resolve(&vpath("/real.txt"), Intent::Inspect)
        .expect("the file resolves directly");
    assert!(through_chain.identity().is_same_file(direct.identity()));
}

#[test]
fn a_chain_longer_than_the_hop_budget_is_refused_by_count() {
    let fixture = Fixture::new();
    fixture.file("real.txt", b"synthetic");
    // 40 links, above the contract's budget of 32.
    fixture.link("link39", "real.txt");
    for step in (0..39).rev() {
        fixture.link(&format!("link{step}"), &format!("link{}", step + 1));
    }

    let export = fixture.open_with_symlinks();
    let error = export
        .resolve(&vpath("/link0"), Intent::Inspect)
        .expect_err("a 40-link chain exceeds the 32-hop budget");
    assert_eq!(error.code(), FsErrorCode::Eloop);
}

#[test]
fn a_link_cycle_is_refused_by_count_rather_than_by_hanging() {
    let fixture = Fixture::new();
    fixture.link("loop-a", "loop-b");
    fixture.link("loop-b", "loop-a");

    let export = fixture.open_with_symlinks();
    let error = export
        .resolve(&vpath("/loop-a"), Intent::Inspect)
        .expect_err("a cycle is refused");
    assert_eq!(error.code(), FsErrorCode::Eloop);
}

#[test]
fn a_dangling_link_is_absence_not_an_escape() {
    let fixture = Fixture::new();
    fixture.link("dangling", "no-such-file");

    let export = fixture.open_with_symlinks();
    let error = export
        .resolve(&vpath("/dangling"), Intent::Inspect)
        .expect_err("a dangling link resolves to nothing");
    assert_eq!(error.code(), FsErrorCode::Enoent);
}

#[test]
fn a_directory_link_swapped_for_a_real_directory_is_resolved_afresh() {
    let fixture = Fixture::new();
    let outside = fixture.outside();
    fixture.link("swap", outside.to_str().expect("utf-8 fixture path"));
    let export = fixture.open_with_symlinks();

    // As a link out of the root: re-rooted, so the outside file is unreachable.
    let error = export
        .resolve(&vpath("/swap/secret.txt"), Intent::Inspect)
        .expect_err("the link target is re-rooted at the export root");
    assert_eq!(error.code(), FsErrorCode::Enoent);

    // Replaced by a real directory with a file of the same name: reachable,
    // and it is the inside inode, not the outside one.
    std::fs::remove_file(fixture.inside("swap")).expect("remove the link");
    fixture.file("swap/secret.txt", b"synthetic-inside");
    let handle = export
        .resolve(&vpath("/swap/secret.txt"), Intent::Inspect)
        .expect("the replacement directory resolves");
    assert!(!handle.identity().is_same_file(outside_identity(&fixture)));

    // And back again: a real directory replaced by a link out of the root is
    // refused once more, so nothing about the first resolution was retained.
    std::fs::remove_dir_all(fixture.inside("swap")).expect("remove the directory");
    fixture.link("swap", outside.to_str().expect("utf-8 fixture path"));
    let error = export
        .resolve(&vpath("/swap/secret.txt"), Intent::Inspect)
        .expect_err("the restored link is re-rooted again");
    assert_eq!(error.code(), FsErrorCode::Enoent);
}

#[test]
fn a_link_in_an_intermediate_component_cannot_escape_either() {
    let fixture = Fixture::new();
    let outside = fixture.outside();
    fixture.dir("a");
    fixture.link("a/b", outside.to_str().expect("utf-8 fixture path"));

    let without = fixture.open_default();
    assert_eq!(
        without
            .resolve(&vpath("/a/b/secret.txt"), Intent::Inspect)
            .expect_err("no links without the feature")
            .code(),
        FsErrorCode::Eloop
    );

    let with = fixture.open_with_symlinks();
    assert_eq!(
        with.resolve(&vpath("/a/b/secret.txt"), Intent::Inspect)
            .expect_err("re-rooted, so unreachable")
            .code(),
        FsErrorCode::Enoent
    );
}

#[test]
fn a_link_target_with_more_components_than_the_bound_is_refused() {
    let fixture = Fixture::new();
    fixture.link("deep", "a/b/c/d/e/f");

    let export = fixture.open(
        full_grant(),
        FeatureSet::from_slice(&[tunnel_fs_core::Feature::Symlinks]),
        tunnel_fs_core::PathBounds::new(4096, 4).expect("valid bounds"),
    );
    let error = export
        .resolve(&vpath("/deep"), Intent::Inspect)
        .expect_err("a six-component target exceeds a four-component bound");
    assert_eq!(error.code(), FsErrorCode::Enametoolong);
}

#[test]
fn the_symlink_primitives_are_refused_without_the_feature() {
    let fixture = Fixture::new();
    let export = fixture.open_default();
    for primitive in [Primitive::Symlink, Primitive::Readlink] {
        let error = export
            .authorize(primitive)
            .expect_err("no symlink primitive without the feature");
        assert_eq!(error.code(), FsErrorCode::Eperm);
    }

    let with = fixture.open_with_symlinks();
    for primitive in [Primitive::Symlink, Primitive::Readlink] {
        with.authorize(primitive)
            .expect("the feature plus a full grant permits both");
    }
}

#[test]
fn a_rename_destination_behind_a_link_out_of_the_root_is_refused() {
    let fixture = Fixture::new();
    fixture.file("moveme.txt", b"synthetic");
    let outside = fixture.outside();
    fixture.link("away", outside.to_str().expect("utf-8 fixture path"));

    let export = fixture.open(
        full_grant(),
        FeatureSet::from_slice(&[
            tunnel_fs_core::Feature::Symlinks,
            tunnel_fs_core::Feature::AtomicRename,
        ]),
        bounds(),
    );
    let error = export
        .rename(&vpath("/moveme.txt"), &vpath("/away/moveme.txt"))
        .expect_err("the destination parent is re-rooted and does not exist");
    assert_eq!(error.code(), FsErrorCode::Enoent);
    assert!(
        !fixture.outside().join("moveme.txt").exists(),
        "nothing may be written outside the export"
    );
}

#[test]
fn an_error_rendering_carries_no_path() {
    let fixture = Fixture::new();
    fixture.link("distinctive-secret-name", "../../outside/secret.txt");

    let export = fixture.open_with_symlinks();
    let error = export
        .resolve(&vpath("/distinctive-secret-name"), Intent::Inspect)
        .expect_err("clamped at the root");
    let debug = format!("{error:?}");
    let display = format!("{error}");
    for rendering in [&debug, &display] {
        assert!(!rendering.contains("distinctive-secret-name"));
        assert!(!rendering.contains("outside"));
        assert!(!rendering.contains('/'));
    }
}
