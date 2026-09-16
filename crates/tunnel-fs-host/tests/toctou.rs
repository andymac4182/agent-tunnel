//! The race gate 1 could not prove.
//!
//! A writer thread swaps a path component between a real directory inside the
//! export and a symbolic link out of it, in a loop, while the resolver runs.
//! The assertion is not "the resolver always succeeds" — it is allowed to fail,
//! and under a swap it often must — but that **every** descriptor it hands back
//! is the inode inside the export.  A single handle on the outside inode fails
//! the test.

// The resolver exists only on a Unix host; on Windows this crate is the
// declaration that filesystem exports are unsupported, and there is nothing
// here to test.
#![cfg(unix)]

mod support;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::FeatureSet;
use tunnel_fs_host::{ExportRoot, FileIdentity, Intent};

fn outside_identity(fixture: &Fixture) -> FileIdentity {
    let outside = ExportRoot::open(&fixture.outside(), full_grant(), FeatureSet::NONE, bounds())
        .expect("open the outside tree as its own export");
    outside
        .resolve(&vpath("/target.txt"), Intent::Inspect)
        .expect("the outside file exists")
        .identity()
}

#[test]
fn a_component_swapped_under_the_resolver_never_yields_a_file_outside_the_root() {
    let fixture = Fixture::new();
    std::fs::write(fixture.outside().join("target.txt"), b"synthetic-outside")
        .expect("write the outside file");
    fixture.file("swap/target.txt", b"synthetic-inside");

    let forbidden = outside_identity(&fixture);
    let export = fixture.open_with_symlinks();
    let permitted = export
        .resolve(&vpath("/swap/target.txt"), Intent::Inspect)
        .expect("the inside file resolves before the race starts")
        .identity();
    assert!(!permitted.is_same_file(forbidden));

    let swap = fixture.inside("swap");
    // `swap-staging` must **not** exist: the swapper moves the real directory
    // aside and back, and a rename onto an existing non-empty directory would
    // fail, leaving a loop that spins without ever swapping anything.
    let staging = fixture.inside("swap-staging");
    let outside_target = fixture
        .outside()
        .to_str()
        .expect("utf-8 fixture path")
        .to_owned();

    let stop = Arc::new(AtomicBool::new(false));
    let swaps = Arc::new(AtomicU64::new(0));
    let swapper = {
        let stop = Arc::clone(&stop);
        let swaps = Arc::clone(&swaps);
        let swap = swap.clone();
        let staging = staging.clone();
        std::thread::spawn(move || {
            while !stop.load(Ordering::Relaxed) {
                // Real directory -> symbolic link out of the export.  Only a
                // swap that actually happened is counted, so a loop that
                // silently failed cannot be mistaken for a race.
                if std::fs::rename(&swap, &staging).is_ok()
                    && std::os::unix::fs::symlink(&outside_target, &swap).is_ok()
                {
                    swaps.fetch_add(1, Ordering::Relaxed);
                }
                // Symbolic link -> real directory again.
                if std::fs::remove_file(&swap).is_ok() && std::fs::rename(&staging, &swap).is_ok() {
                    swaps.fetch_add(1, Ordering::Relaxed);
                }
            }
            // Leave the tree in a removable state.
            let _ = std::fs::remove_file(&swap);
            let _ = std::fs::rename(&staging, &swap);
        })
    };

    let mut resolved_inside: u64 = 0;
    let mut refused: u64 = 0;
    let path = vpath("/swap/target.txt");
    for _ in 0..20_000 {
        match export.resolve(&path, Intent::Inspect) {
            Ok(handle) => {
                let identity = handle.identity();
                assert!(
                    !identity.is_same_file(forbidden),
                    "the resolver handed back a descriptor for the inode outside the export"
                );
                assert!(
                    identity.is_same_file(permitted),
                    "the resolver handed back an inode that is neither the expected one nor a \
                     refusal"
                );
                resolved_inside += 1;
            }
            Err(_) => refused += 1,
        }
    }

    stop.store(true, Ordering::Relaxed);
    swapper.join().expect("the swapping thread finishes");

    eprintln!(
        "RECORDED: {} swaps, {resolved_inside} resolutions inside the export, {refused} refusals",
        swaps.load(Ordering::Relaxed)
    );
    assert!(
        swaps.load(Ordering::Relaxed) > 100,
        "the swapping thread must actually have raced the resolver"
    );
    assert!(
        resolved_inside > 0,
        "a run in which nothing ever resolved would prove nothing"
    );
    assert!(
        refused > 0,
        "a run in which the swap was never observed would prove nothing"
    );
}

#[test]
fn a_file_swapped_for_a_link_between_resolution_and_use_does_not_redirect_the_descriptor() {
    let fixture = Fixture::new();
    std::fs::write(fixture.outside().join("target.txt"), b"synthetic-outside")
        .expect("write the outside file");
    fixture.file("victim.txt", b"synthetic-inside");

    let export = fixture.open_with_symlinks();
    let handle = export
        .resolve(&vpath("/victim.txt"), Intent::Inspect)
        .expect("resolves");
    let identity = handle.identity();
    let forbidden = ExportRoot::open(&fixture.outside(), full_grant(), FeatureSet::NONE, bounds())
        .expect("open the outside tree as its own export")
        .resolve(&vpath("/target.txt"), Intent::Inspect)
        .expect("the outside file exists")
        .identity();

    // Replace the name with a link out of the export, exactly the window a
    // path-taking syscall would lose.  The descriptor still refers to the file
    // it resolved.
    std::fs::remove_file(fixture.inside("victim.txt")).expect("unlink the name");
    std::os::unix::fs::symlink(
        fixture.outside().join("target.txt"),
        fixture.inside("victim.txt"),
    )
    .expect("put a link in its place");

    let after = handle
        .current_identity()
        .expect("the descriptor is still usable");
    assert!(
        after.is_same_file(identity),
        "the descriptor still names the file that was resolved"
    );
    assert!(
        !after.is_same_file(forbidden),
        "and it was not redirected by the link that replaced its name"
    );

    // Resolving the name again now answers with the re-rooted link's absence,
    // which is the difference between a descriptor and a path.
    assert_eq!(
        export
            .resolve(&vpath("/victim.txt"), Intent::Inspect)
            .expect_err("the name now holds a link out of the export")
            .code(),
        tunnel_fs_core::FsErrorCode::Enoent
    );
}
