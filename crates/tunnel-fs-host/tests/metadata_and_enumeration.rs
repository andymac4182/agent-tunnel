//! The two gate-4 obligations gate 2's crate discharges.
//!
//! * The **metadata-only open** a `list`-without-`read` grant needs, which gate
//!   2 recorded as still open because `Intent::Inspect` requires read permission
//!   on both hosts.
//! * The **outward `OsStr` refusal**: a directory entry whose host name is not
//!   representable in UTF-8 fails the whole enumeration with `EINVAL` rather
//!   than being skipped.
//!
//! Every fixture here is synthetic and lives inside a temporary directory this
//! test created.

#![cfg(unix)]

mod support;

use std::os::unix::ffi::OsStrExt as _;
use std::process::Command;

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, FsErrorCode};
use tunnel_fs_host::{FileKind, Intent};

/// The read-only profile the contract names: `read` + `list`.
fn read_only() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Read, Capability::List])
}

/// `list` alone — the grant whose `Tgetattr` gate 4 has to be able to answer.
fn list_only() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::List])
}

/// `read` alone — read-by-name, with no metadata rights at all.
fn read_only_no_list() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Read])
}

/// The traversal-entry budget a resume may spend, from the contract's limits.
const ENTRY_BUDGET: u64 = 10_000;

#[test]
fn metadata_answers_for_a_file_no_grant_may_read() {
    let fixture = Fixture::new();
    fixture.file("/unreadable.txt", b"synthetic");
    let host = fixture.inside("unreadable.txt");
    // Mode 000: the host itself will refuse to open it, so an implementation
    // that reached this metadata through an open would fail here.
    assert!(
        Command::new("chmod")
            .args([std::ffi::OsStr::new("000"), host.as_os_str()])
            .output()
            .is_ok_and(|output| output.status.success()),
        "chmod must make the fixture unopenable"
    );

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let path = vpath("/unreadable.txt");

    // The state gate 2 left: an inspecting resolution opens the file, so it is
    // refused by the host.  This assertion is what makes the metadata answer
    // below evidence rather than a coincidence.
    let refused = export
        .resolve(&path, Intent::Inspect)
        .expect_err("a mode-000 file cannot be opened");
    assert_eq!(refused.code(), FsErrorCode::Eacces);

    let metadata = export
        .metadata(&path)
        .expect("metadata needs no read permission on the file");
    assert_eq!(metadata.kind(), FileKind::RegularFile);
    assert_eq!(metadata.size(), 9);
    assert_eq!(metadata.links(), 1);
    assert_eq!(metadata.mode() & 0o777, 0);
}

#[test]
fn metadata_is_governed_by_list_not_by_read() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let path = vpath("/notes.txt");

    let listing = fixture.open(list_only(), FeatureSet::NONE, bounds());
    let metadata = listing
        .metadata(&path)
        .expect("a list grant may stat a file it may not read");
    assert_eq!(metadata.size(), 9);
    // And it may not read it.
    assert_eq!(
        listing
            .open_read(&path)
            .expect_err("list does not imply read")
            .code(),
        FsErrorCode::Eperm
    );

    let reading = fixture.open(read_only_no_list(), FeatureSet::NONE, bounds());
    assert_eq!(
        reading
            .metadata(&path)
            .expect_err("read alone has no stat")
            .code(),
        FsErrorCode::Eperm
    );
    // But it can still read by name, which is the whole point of that grant.
    reading.open_read(&path).expect("read by name");
}

#[test]
fn metadata_of_the_export_root_is_the_root_directory() {
    let fixture = Fixture::new();
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let metadata = export.metadata(&vpath("/")).expect("root metadata");
    assert_eq!(metadata.kind(), FileKind::Directory);
    assert!(metadata.identity().is_same_file(export.identity()));
}

#[test]
fn metadata_of_a_symbolic_link_is_refused_without_the_feature() {
    let fixture = Fixture::new();
    fixture.file("/target.txt", b"synthetic");
    fixture.link("/alias", "target.txt");

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let error = export
        .metadata(&vpath("/alias"))
        .expect_err("rule 3 refuses a link when the feature is off");
    assert_eq!(error.code(), FsErrorCode::Eloop);
}

#[test]
fn metadata_of_a_symbolic_link_follows_it_when_the_feature_is_on() {
    let fixture = Fixture::new();
    fixture.file("/target.txt", b"synthetic-body");
    fixture.link("/alias", "target.txt");

    let export = fixture.open(
        read_only(),
        FeatureSet::from_slice(&[Feature::Symlinks]),
        bounds(),
    );
    let metadata = export.metadata(&vpath("/alias")).expect("link followed");
    assert_eq!(metadata.kind(), FileKind::RegularFile);
    assert_eq!(metadata.size(), 14);
}

#[test]
fn metadata_refuses_a_special_file_without_opening_it() {
    let fixture = Fixture::new();
    let pipe = fixture.inside("pipe");
    assert!(
        Command::new("mkfifo")
            .args([pipe.as_os_str()])
            .output()
            .is_ok_and(|output| output.status.success()),
        "mkfifo must create a FIFO inside the temporary export"
    );

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    // Reaching this assertion at all is part of the evidence: opening a FIFO
    // for reading blocks until a writer arrives.
    let error = export
        .metadata(&vpath("/pipe"))
        .expect_err("a FIFO is not exportable");
    assert_eq!(error.code(), FsErrorCode::Enotsup);
}

#[test]
fn metadata_of_a_missing_name_is_absence() {
    let fixture = Fixture::new();
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    assert_eq!(
        export
            .metadata(&vpath("/absent.txt"))
            .expect_err("no such file")
            .code(),
        FsErrorCode::Enoent
    );
}

#[test]
fn metadata_renders_without_a_path_or_a_size() {
    let fixture = Fixture::new();
    fixture.file("/secret-name.txt", b"synthetic");
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let metadata = export.metadata(&vpath("/secret-name.txt")).expect("stat");
    let rendered = format!("{metadata:?}");
    assert!(!rendered.contains("secret-name"), "{rendered}");
    assert!(!rendered.contains('9'), "{rendered}");
}

// ------------------------------------------------------------ enumeration

#[test]
fn enumeration_lists_children_and_never_dot_or_dotdot() {
    let fixture = Fixture::new();
    fixture.file("/a.txt", b"synthetic");
    fixture.file("/b.txt", b"synthetic");
    fixture.dir("/child");

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate the root");
    let mut names = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        names.push(entry.name().to_owned());
    }
    names.sort();
    assert_eq!(names, vec!["a.txt", "b.txt", "child"]);
}

#[test]
fn enumeration_needs_list_and_not_read() {
    let fixture = Fixture::new();
    fixture.file("/a.txt", b"synthetic");

    let reading = fixture.open(read_only_no_list(), FeatureSet::NONE, bounds());
    assert_eq!(
        reading
            .read_directory(&vpath("/"), ENTRY_BUDGET)
            .expect_err("read alone cannot enumerate")
            .code(),
        FsErrorCode::Eperm
    );

    let listing = fixture.open(list_only(), FeatureSet::NONE, bounds());
    listing
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("list alone enumerates");
}

#[test]
fn enumeration_leaves_out_a_special_file() {
    let fixture = Fixture::new();
    fixture.file("/ordinary.txt", b"synthetic");
    let pipe = fixture.inside("pipe");
    assert!(
        Command::new("mkfifo")
            .args([pipe.as_os_str()])
            .output()
            .is_ok_and(|output| output.status.success()),
        "mkfifo must create a FIFO inside the temporary export"
    );

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");
    let mut names = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        names.push(entry.name().to_owned());
    }
    assert_eq!(names, vec!["ordinary.txt"]);
}

/// The outward refusal against a real directory.
///
/// `#[ignore]`d with its reason rather than printed as a skip: **APFS enforces
/// UTF-8 on file names**, so `std::fs::write` of `bad-\x80-name` answers
/// `EILSEQ` on this host and the fixture cannot be built at all. The decision is
/// unit-tested in `tunnel_fs_host::metadata`, where the conversion lives; this
/// case exists so a host that *can* hold such a name runs it, and so the gap is
/// visible rather than absent.
#[test]
#[ignore = "APFS refuses to create a non-UTF-8 file name (EILSEQ); run on a host whose filesystem stores arbitrary bytes"]
fn an_entry_name_that_is_not_utf8_fails_the_whole_enumeration() {
    let fixture = Fixture::new();
    fixture.file("/ordinary.txt", b"synthetic");
    // A lone 0x80 continuation byte is not valid UTF-8 anywhere, and APFS
    // accepts it: the host stores bytes, and this is the case the contract's
    // refuse-never-repair rule exists for.
    let raw = std::ffi::OsStr::from_bytes(b"bad-\x80-name");
    std::fs::write(fixture.export().join(raw), b"synthetic")
        .expect("the host must accept a non-UTF-8 file name for this test to mean anything");

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");

    // The whole listing fails.  Which entry the host returns first is not
    // determined, so the assertion is that the enumeration cannot complete
    // without the refusal — never that the refusal is the first answer.
    let mut refused = false;
    loop {
        match reader.next_entry() {
            Ok(Some(entry)) => assert_eq!(entry.name(), "ordinary.txt"),
            Ok(None) => break,
            Err(error) => {
                assert_eq!(error.code(), FsErrorCode::Einval);
                refused = true;
                break;
            }
        }
    }
    assert!(
        refused,
        "an unrepresentable entry name must fail the enumeration, not be skipped"
    );
}

#[test]
fn a_cookie_resumes_where_it_was_taken() {
    let fixture = Fixture::new();
    for index in 0..8 {
        fixture.file(&format!("/f{index}.txt"), b"synthetic");
    }

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");

    let mut first = Vec::new();
    let mut cookie = 0;
    for _ in 0..3 {
        let entry = reader.next_entry().expect("entry").expect("eight entries");
        cookie = entry.cookie();
        first.push(entry.name().to_owned());
    }
    assert_eq!(cookie, 3, "the cookie counts servable entries");
    assert_eq!(reader.position(), 3);

    // Resuming at the position the reader already holds is a no-op, which is
    // the ordinary sequential case.
    reader.seek(cookie, ENTRY_BUDGET).expect("resume in place");
    let mut rest = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        rest.push(entry.name().to_owned());
    }
    assert_eq!(first.len() + rest.len(), 8);

    // And resuming from the start re-reads everything.
    reader.seek(0, ENTRY_BUDGET).expect("rewind");
    let mut all = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        all.push(entry.name().to_owned());
    }
    assert_eq!(all.len(), 8);
    let mut expected: Vec<String> = first.into_iter().chain(rest).collect();
    expected.sort();
    all.sort();
    assert_eq!(all, expected);
}

#[test]
fn a_run_of_unservable_entries_is_bounded_rather_than_walked() {
    // The block a `Treaddir` fills bounds the entries it returns and bounds
    // nothing about the entries it skips: each special file costs a `statat`
    // and takes no space in the reply. A directory of them would otherwise make
    // one call perform arbitrarily many host calls for an empty block.
    let fixture = Fixture::new();
    for index in 0..6 {
        let pipe = fixture.inside(&format!("p{index}"));
        assert!(
            Command::new("mkfifo")
                .args([pipe.as_os_str()])
                .output()
                .is_ok_and(|output| output.status.success()),
            "mkfifo must create a FIFO inside the temporary export"
        );
    }
    fixture.file("/z-ordinary.txt", b"synthetic");

    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    // A budget of two cannot cross six FIFOs, whatever order the host returns
    // them in: the one ordinary file splits them into at most two runs, so one
    // run is at least three long, and three skips exceed a budget of two. The
    // budget used to be three, which a split of exactly three and three passes
    // without a refusal -- the order an overlayfs directory returned on Linux
    // (`.., p1, p3, p5, ., z-ordinary.txt, p0, p4, p2`), where the test failed.
    let mut reader = export
        .read_directory(&vpath("/"), 2)
        .expect("enumerate the root");
    let mut refused = false;
    loop {
        match reader.next_entry() {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(error) => {
                assert_eq!(error.code(), FsErrorCode::Einval);
                refused = true;
                break;
            }
        }
    }
    assert!(
        refused,
        "a run of unservable entries longer than the budget must be refused"
    );

    // The same directory under the contract's own traversal-entry limit lists
    // normally: the budget bounds work, and is not a claim about the directory.
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate the root");
    let mut names = Vec::new();
    while let Some(entry) = reader.next_entry().expect("entry") {
        names.push(entry.name().to_owned());
    }
    assert_eq!(names, vec!["z-ordinary.txt"]);
}

#[test]
fn a_cookie_past_the_end_is_refused() {
    let fixture = Fixture::new();
    fixture.file("/only.txt", b"synthetic");
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");
    assert_eq!(
        reader
            .seek(5, ENTRY_BUDGET)
            .expect_err("no fifth entry")
            .code(),
        FsErrorCode::Einval
    );
}

#[test]
fn a_cookie_beyond_the_budget_is_refused_without_reading() {
    let fixture = Fixture::new();
    fixture.file("/only.txt", b"synthetic");
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");
    assert_eq!(
        reader
            .seek(ENTRY_BUDGET + 1, ENTRY_BUDGET)
            .expect_err("beyond the traversal budget")
            .code(),
        FsErrorCode::Einval
    );
}

#[test]
fn enumerating_a_file_is_not_a_directory() {
    let fixture = Fixture::new();
    fixture.file("/a.txt", b"synthetic");
    let export = fixture.open(full_grant(), FeatureSet::NONE, bounds());
    assert_eq!(
        export
            .read_directory(&vpath("/a.txt"), ENTRY_BUDGET)
            .expect_err("a file is not enumerable")
            .code(),
        FsErrorCode::Enotdir
    );
}

#[test]
fn an_entry_renders_without_its_name() {
    let fixture = Fixture::new();
    fixture.file("/secret-name.txt", b"synthetic");
    let export = fixture.open(read_only(), FeatureSet::NONE, bounds());
    let mut reader = export
        .read_directory(&vpath("/"), ENTRY_BUDGET)
        .expect("enumerate");
    let entry = reader.next_entry().expect("entry").expect("one entry");
    let rendered = format!("{entry:?}");
    assert!(!rendered.contains("secret-name"), "{rendered}");
}
