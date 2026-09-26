//! Rule 5 of `docs/filesystem-api.md` — special files, sockets, FIFOs and
//! device nodes — and the mount-point boundary gate 2 owes.
//!
//! A node this host cannot create is an `#[ignore]` with a reason, never a
//! test that prints a skip and passes: `cargo test` hides stderr for a passing
//! test, so a printed skip would leave the same green count whether the case
//! ran or not.  Everything that can be created here — a FIFO, a unix socket,
//! and a real mount point from an unprivileged disk image — is a hard failure
//! if it cannot be.

#![cfg(unix)]

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
    // A hard failure, not a skip.  The fixture name is deliberately short
    // because `sun_path` is about 104 bytes on macOS and the temporary
    // directory is already long; if that ever stops being enough, this test
    // must say so rather than quietly stop covering the socket case.
    let listener = std::os::unix::net::UnixListener::bind(&socket_path)
        .expect("bind a unix-domain socket inside the temporary export");

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/s"), Intent::Inspect)
        .expect_err("a socket is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
    drop(listener);
}

#[test]
fn the_exportable_kinds_are_exactly_directories_and_regular_files() {
    // This is what stands in for a real device node on a host where one cannot
    // be created: the decision is exhaustive over the kind enum, and the FIFO
    // and socket cases above prove the same decision against real nodes.
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
}

#[test]
#[ignore = "creating a character device node needs privilege; run as root with \
            `cargo test -p tunnel-fs-host -- --ignored` to exercise it"]
fn a_real_device_node_is_refused() {
    let fixture = Fixture::new();
    let node = fixture.inside("device");
    assert!(
        run(
            "mknod",
            &[
                node.as_os_str(),
                std::ffi::OsStr::new("c"),
                std::ffi::OsStr::new("3"),
                std::ffi::OsStr::new("2"),
            ],
        ),
        "mknod must create a character device node inside the temporary export"
    );

    let export = fixture.open_default();
    let error = export
        .resolve(&vpath("/device"), Intent::Read)
        .expect_err("a device node is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
}

/// Detaches a mounted disk image however the test ends.
#[cfg(target_os = "macos")]
struct Mounted {
    mountpoint: String,
}

#[cfg(target_os = "macos")]
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

    // `hdiutil` ships with macOS and attaching an image the test just created
    // needs no privilege, so a failure here is a failure of the test, not a
    // property of the host to be skipped past: this is the only place the
    // mount boundary meets a real mount.
    let created = Command::new("hdiutil")
        .args(["create", "-size", "10m", "-fs", "HFS+", "-volname", "probe"])
        .arg(&image)
        .output();
    assert!(
        matches!(&created, Ok(output) if output.status.success()),
        "hdiutil must create a disk image inside the temporary tree"
    );

    let attached = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-mountpoint", &mountpoint])
        .arg(&image)
        .output();
    assert!(
        matches!(&attached, Ok(output) if output.status.success()),
        "hdiutil must attach that image at a mount point inside the export"
    );
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

/// Task row M4-08's last gap: on Linux the mount boundary is the kernel's
/// `RESOLVE_NO_XDEV` inside `openat2`, and until this no test had ever put a
/// real mount inside an export there -- `hdiutil` above is macOS-only.
///
/// Mounting needs privilege this test does not have and must not take, so the
/// mount is prepared **outside** it: CI's M4 job runs `sudo mount -t tmpfs`
/// at `<export>/mnt`, writes `<export>/mnt/inside.txt` and
/// `<export>/plain/beside.txt`, and names the export in
/// `TUNNEL_FS_LINUX_MOUNT_EXPORT`. It is `#[ignore]`d so an ordinary run does
/// not need that, and it **fails** rather than skips when run without it, so
/// `--ignored` can never pass vacuously. Its positive controls prove the
/// mount is real and the export is otherwise served, so the `EXDEV` it
/// asserts can only come from the boundary.
#[test]
#[cfg(target_os = "linux")]
#[ignore = "needs a tmpfs mounted inside an export by root (CI: TUNNEL_FS_LINUX_MOUNT_EXPORT)"]
fn a_mount_point_inside_the_export_is_not_crossed_on_linux() {
    use std::os::unix::fs::MetadataExt as _;
    let export_path = std::env::var_os("TUNNEL_FS_LINUX_MOUNT_EXPORT")
        .map(std::path::PathBuf::from)
        .expect("TUNNEL_FS_LINUX_MOUNT_EXPORT must name an export with a tmpfs mounted at mnt/");
    let root_dev = std::fs::metadata(&export_path).expect("export").dev();
    let mount_dev = std::fs::metadata(export_path.join("mnt"))
        .expect("mnt")
        .dev();
    // Positive control 1: `mnt` really is another filesystem.
    assert_ne!(
        root_dev, mount_dev,
        "mnt must be a mount point on another device"
    );
    // Positive control 2: the file behind the boundary exists and is readable
    // by this process directly, so a refusal is not a missing file.
    assert!(
        !std::fs::read(export_path.join("mnt/inside.txt"))
            .expect("the file inside the mount is readable directly")
            .is_empty()
    );
    let export = tunnel_fs_host::ExportRoot::open(
        &export_path,
        support::full_grant(),
        tunnel_fs_core::FeatureSet::NONE,
        support::bounds(),
    )
    .expect("open the prepared export");
    // Positive control 3: the same export serves a file on its own device.
    let beside = export
        .resolve(&vpath("/plain/beside.txt"), Intent::Read)
        .expect("a file on the export's own device resolves");
    assert_eq!(beside.kind(), FileKind::RegularFile);

    let error = export
        .resolve(&vpath("/mnt"), Intent::Inspect)
        .expect_err("a directory on another device is not crossed");
    assert_eq!(error.code(), FsErrorCode::Exdev);
    let error = export
        .resolve(&vpath("/mnt/inside.txt"), Intent::Read)
        .expect_err("nor is anything beneath it");
    assert_eq!(error.code(), FsErrorCode::Exdev);
    println!(
        "m4-08-linux-mount ok root_dev={root_dev} mount_dev={mount_dev} mnt=EXDEV inside=EXDEV beside=served"
    );
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
