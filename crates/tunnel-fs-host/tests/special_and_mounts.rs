//! Rule 5 of `docs/filesystem-api.md` — special files, sockets, FIFOs and
//! device nodes — and the mount-point boundary gate 2 owes.
//!
//! Where the host refuses to let a test create the node it needs, the test
//! records precisely what could not be demonstrated instead of passing
//! silently.

mod support;

use std::process::Command;

use support::{Fixture, vpath};
use tunnel_fs_core::FsErrorCode;
use tunnel_fs_host::{FileKind, Intent};

/// `rustix` does not expose `mknodat`/`mkfifoat` on Apple hosts — macOS has no
/// such syscall — and this workspace forbids `unsafe`, so the FIFO and the
/// device node are created with the host's own tools rather than by reaching
/// for `libc` directly.  Both create nodes **inside the temporary export**.
fn run(program: &str, arguments: &[&std::ffi::OsStr]) -> bool {
    matches!(
        Command::new(program).args(arguments).output(),
        Ok(output) if output.status.success()
    )
}

#[test]
fn a_fifo_is_refused_rather_than_opened() {
    let fixture = Fixture::new();
    let pipe = fixture.inside("pipe");
    assert!(
        run("mkfifo", &[pipe.as_os_str()]),
        "mkfifo must create a FIFO inside the temporary export"
    );

    let export = fixture.open_default();
    // A FIFO opened for reading blocks until a writer arrives.  This test
    // completing at all is part of the assertion: the refusal is taken from
    // the `statat`, before any open.
    let error = export
        .resolve(&vpath("/pipe"), Intent::Read)
        .expect_err("a FIFO is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
}

#[test]
fn a_unix_socket_is_refused() {
    let fixture = Fixture::new();
    let socket_path = fixture.inside("s");
    let Ok(listener) = std::os::unix::net::UnixListener::bind(&socket_path) else {
        eprintln!(
            "RECORDED SKIP: this host refused to bind a unix-domain socket inside the temporary \
             export (the sun_path limit is about 104 bytes and the temporary directory is \
             already long); the socket refusal is therefore not demonstrated here."
        );
        return;
    };

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/s"), Intent::Inspect)
        .expect_err("a socket is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
    drop(listener);
}

#[test]
fn a_device_node_is_refused_where_one_can_be_created() {
    let fixture = Fixture::new();
    // Creating a device node needs privilege on every host this runs on.  The
    // attempt is made rather than assumed to fail, so the skip below reports
    // what the host actually did.
    let node = fixture.inside("device");
    let made = run(
        "mknod",
        &[
            node.as_os_str(),
            std::ffi::OsStr::new("c"),
            std::ffi::OsStr::new("3"),
            std::ffi::OsStr::new("2"),
        ],
    );
    if !made {
        eprintln!(
            "RECORDED SKIP: this host refused to create a character device node inside the \
             temporary export (mknod needs privilege); the device-node refusal is proven only \
             through the shared kind decision below, not against a real device node."
        );
        // The decision itself is still exhaustive over the kind enum.
        for kind in FileKind::ALL {
            assert_eq!(
                kind.is_exportable(),
                matches!(kind, FileKind::Directory | FileKind::RegularFile),
                "only directories and regular files are exportable"
            );
            assert_eq!(
                tunnel_fs_host::policy::check_exportable(kind).is_ok(),
                kind.is_exportable()
            );
        }
        return;
    }

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/device"), Intent::Read)
        .expect_err("a device node is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
}

/// Detaches a mounted disk image however the test ends.
struct Mounted {
    mountpoint: String,
}

impl Drop for Mounted {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-force", &self.mountpoint])
            .output();
    }
}

#[test]
#[cfg(target_os = "macos")]
fn a_mount_point_inside_the_export_is_not_crossed() {
    let fixture = Fixture::new();
    fixture.dir("mnt");
    let image = fixture.base().join("probe.dmg");
    let mountpoint = fixture
        .inside("mnt")
        .to_str()
        .expect("utf-8 fixture path")
        .to_owned();

    let created = Command::new("hdiutil")
        .args(["create", "-size", "10m", "-fs", "HFS+", "-volname", "probe"])
        .arg(&image)
        .output();
    let created = matches!(&created, Ok(output) if output.status.success());
    if !created {
        eprintln!(
            "RECORDED SKIP: this host could not create a disk image with hdiutil, so the \
             mount-point boundary is not demonstrated against a real mount."
        );
        return;
    }

    let attached = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-mountpoint", &mountpoint])
        .arg(&image)
        .output();
    let attached = matches!(&attached, Ok(output) if output.status.success());
    if !attached {
        eprintln!(
            "RECORDED SKIP: this host refused to attach a disk image without privilege, so the \
             mount-point boundary is not demonstrated against a real mount."
        );
        return;
    }
    let _guard = Mounted {
        mountpoint: mountpoint.clone(),
    };

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/mnt"), Intent::Inspect)
        .expect_err("a directory on another device is not crossed");
    assert_eq!(error.code(), FsErrorCode::Exdev);

    // And nothing under it is reachable either.
    let error = export
        .resolve(&vpath("/mnt/anything"), Intent::Inspect)
        .expect_err("nor is anything beneath it");
    assert_eq!(error.code(), FsErrorCode::Exdev);
}

#[test]
fn the_root_itself_resolves_to_a_directory() {
    let fixture = Fixture::new();
    let export = fixture.open_default();
    let handle = export
        .resolve(&vpath("/"), Intent::Inspect)
        .expect("the export root resolves");
    assert_eq!(handle.kind(), FileKind::Directory);
    assert!(handle.identity().is_same_file(export.identity()));
}

#[test]
fn a_file_used_as_a_directory_component_is_not_a_directory() {
    let fixture = Fixture::new();
    fixture.file("plain.txt", b"synthetic");
    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/plain.txt/inner"), Intent::Inspect)
        .expect_err("a regular file has no children");
    assert_eq!(error.code(), FsErrorCode::Enotdir);
}
