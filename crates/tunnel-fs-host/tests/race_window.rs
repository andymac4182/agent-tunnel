//! The window itself, occupied deliberately.
//!
//! `toctou.rs` races a writer thread against the resolver and proves nothing
//! escapes; what it cannot promise is that it ever landed in the few
//! microseconds between a component being inspected and that component being
//! opened.  These tests step into exactly that instant, using the
//! `race-window-hook` feature, so the two guards that cover it — `O_NOFOLLOW`
//! on the open, and the comparison of the opened descriptor's identity against
//! the one that was inspected — are proven rather than assumed.
//!
//! Run with `cargo test -p tunnel-fs-host --features race-window-hook`.

// Both halves matter: the hook exists only under the feature, and the resolver
// it hooks exists only on a Unix host, so a Windows build **with** the feature
// must compile to nothing here rather than to unresolved imports.
#![cfg(all(unix, feature = "race-window-hook"))]

mod support;

use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::FeatureSet;
use tunnel_fs_host::resolver::race_window;
use tunnel_fs_host::{ExportRoot, FileIdentity, Intent};

fn outside_identity(fixture: &Fixture, name: &str) -> FileIdentity {
    ExportRoot::open(&fixture.outside(), full_grant(), FeatureSet::NONE, bounds())
        .expect("open the outside tree as its own export")
        .resolve(&vpath(name), Intent::Inspect)
        .expect("the outside file exists")
        .identity()
}

static DIRECTORY_SWAP: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
static FILE_SWAP: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();
static REPLACEMENT_SWAP: OnceLock<(PathBuf, PathBuf)> = OnceLock::new();

fn swap_directory_for_a_link() {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    let (name, target) = DIRECTORY_SWAP.get().expect("the swap is configured");
    std::fs::remove_dir_all(name).expect("remove the real directory");
    std::os::unix::fs::symlink(target, name).expect("put a link out of the export in its place");
}

fn swap_file_for_a_link() {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    let (name, target) = FILE_SWAP.get().expect("the swap is configured");
    std::fs::remove_file(name).expect("remove the real file");
    std::os::unix::fs::symlink(target, name).expect("put a link out of the export in its place");
}

fn swap_file_for_another_file() {
    static DONE: AtomicBool = AtomicBool::new(false);
    if DONE.swap(true, Ordering::Relaxed) {
        return;
    }
    let (name, replacement) = REPLACEMENT_SWAP.get().expect("the swap is configured");
    std::fs::rename(replacement, name).expect("rename a different inode onto the name");
}

#[test]
fn a_directory_swapped_for_a_link_inside_the_window_does_not_escape() {
    let fixture = Fixture::new();
    fixture.file("dir/target.txt", b"synthetic-inside");
    DIRECTORY_SWAP
        .set((fixture.inside("dir"), fixture.outside()))
        .expect("configure the swap");
    let forbidden = outside_identity(&fixture, "/secret.txt");

    let export = fixture.open_with_symlinks();
    race_window::set(swap_directory_for_a_link);
    let outcome = export.resolve(&vpath("/dir/secret.txt"), Intent::Inspect);
    race_window::clear();

    match outcome {
        Ok(handle) => assert!(
            !handle.identity().is_same_file(forbidden),
            "the resolver followed a link that replaced a directory mid-walk"
        ),
        Err(error) => assert_eq!(
            error.code(),
            tunnel_fs_core::FsErrorCode::Enoent,
            "a component that changed under the resolver takes one uniform answer, so a \
             racer cannot learn which kind of swap it performed"
        ),
    }
}

#[test]
fn a_file_swapped_for_a_link_inside_the_window_does_not_escape() {
    let fixture = Fixture::new();
    fixture.file("victim.txt", b"synthetic-inside");
    FILE_SWAP
        .set((
            fixture.inside("victim.txt"),
            fixture.outside().join("secret.txt"),
        ))
        .expect("configure the swap");
    let forbidden = outside_identity(&fixture, "/secret.txt");

    let export = fixture.open_with_symlinks();
    race_window::set(swap_file_for_a_link);
    let outcome = export.resolve(&vpath("/victim.txt"), Intent::Inspect);
    race_window::clear();

    match outcome {
        Ok(handle) => assert!(
            !handle.identity().is_same_file(forbidden),
            "the resolver opened a link that replaced a file mid-walk"
        ),
        Err(error) => assert_eq!(
            error.code(),
            tunnel_fs_core::FsErrorCode::Enoent,
            "a component that changed under the resolver takes one uniform answer, so a \
             racer cannot learn which kind of swap it performed"
        ),
    }
}

#[test]
fn a_file_replaced_by_another_inode_inside_the_window_is_not_handed_back() {
    let fixture = Fixture::new();
    fixture.file("victim.txt", b"synthetic-inside");
    fixture.file("usurper.txt", b"synthetic-other");
    REPLACEMENT_SWAP
        .set((fixture.inside("victim.txt"), fixture.inside("usurper.txt")))
        .expect("configure the swap");

    let export = fixture.open_default();
    let usurper = export
        .resolve(&vpath("/usurper.txt"), Intent::Inspect)
        .expect("the replacement exists")
        .identity();

    race_window::set(swap_file_for_another_file);
    let outcome = export.resolve(&vpath("/victim.txt"), Intent::Inspect);
    race_window::clear();

    match outcome {
        Ok(handle) => assert!(
            !handle.identity().is_same_file(usurper),
            "the resolver handed back an inode it had not inspected"
        ),
        Err(error) => assert_eq!(
            error.code(),
            tunnel_fs_core::FsErrorCode::Enoent,
            "a component that changed under the resolver takes one uniform answer, so a \
             racer cannot learn which kind of swap it performed"
        ),
    }
}
