//! File identity, and the four two-spellings-one-file classes.
//!
//! Every assertion below is of the shape "the host said these two spellings
//! reached one inode, or the host said one of them does not exist" — never "the
//! two strings compare equal under a fold".  That is the whole point of the
//! class: no string comparison can decide it, so the test does not make one
//! either, and it therefore passes unchanged on a case-sensitive and a
//! case-insensitive volume while reporting which one it met.

// The resolver exists only on a Unix host; on Windows this crate is the
// declaration that filesystem exports are unsupported, and there is nothing
// here to test.
#![cfg(unix)]

mod support;

use support::{Fixture, bounds, full_grant, vpath};
use tunnel_fs_core::{Feature, FeatureSet, FsErrorCode, PathBounds, VirtualPath};
use tunnel_fs_host::Intent;

/// The host's verdict for one alias pair.
#[derive(Debug, Eq, PartialEq)]
enum Verdict {
    /// Both spellings resolved, to one inode: the volume aliases them.
    OneFile,
    /// Both spellings resolved, to different inodes: two files.
    TwoFiles,
    /// Only the created spelling resolved: the volume does not alias them.
    SecondAbsent,
}

/// Create `created`, then ask the host what `other` names.
///
/// The question is put through [`ExportRoot::same_file`] — the API a provider
/// would use — rather than re-implemented here, so this test exercises the
/// decision that ships instead of a copy of it that cannot disagree with it.
fn verdict(fixture: &Fixture, created: &str, other: &str) -> Verdict {
    fixture.file(created, b"synthetic");
    let export = fixture.open_default();
    export
        .resolve(&vpath(created), Intent::Inspect)
        .expect("the created spelling resolves");
    match export.same_file(&vpath(created), &vpath(other)) {
        Ok(true) => Verdict::OneFile,
        Ok(false) => Verdict::TwoFiles,
        Err(error) => {
            assert_eq!(
                error.code(),
                FsErrorCode::Enoent,
                "the only other answer the host may give is absence"
            );
            Verdict::SecondAbsent
        }
    }
}

/// The two acceptable verdicts.  `TwoFiles` would mean the host created a
/// second file for a spelling that must alias, which is the failure this whole
/// class is about.
fn assert_decided(class: &str, verdict: Verdict) {
    assert_ne!(
        verdict,
        Verdict::TwoFiles,
        "{class}: two spellings resolved to two different inodes"
    );
    eprintln!("RECORDED: {class} decided by the host as {verdict:?}");
}

#[test]
fn ascii_case_is_decided_by_the_host() {
    let fixture = Fixture::new();
    fixture.dir("Dir");
    let verdict = verdict(&fixture, "/Dir/File.TXT", "/dir/file.txt");
    assert_decided("ASCII case", verdict);
}

#[test]
fn a_unicode_case_pair_is_decided_by_the_host() {
    let fixture = Fixture::new();
    let verdict = verdict(&fixture, "/\u{3c3}", "/\u{3a3}");
    assert_decided("Unicode case pair sigma", verdict);
}

#[test]
fn nfc_and_nfd_are_decided_by_the_host() {
    let fixture = Fixture::new();
    // "café" precomposed, then the same text decomposed.
    let verdict = verdict(&fixture, "/caf\u{e9}", "/cafe\u{301}");
    assert_decided("NFC versus NFD", verdict);
}

#[test]
fn ntfs_short_names_are_out_of_reach_on_this_host() {
    // The fourth class needs an NTFS volume with 8.3 generation enabled, which
    // exists only on Windows — the host this implementation declares filesystem
    // exports unsupported on.  That declaration is what closes the class: an
    // export is never served where the alias can arise.
    assert_eq!(
        tunnel_fs_host::unsupported_host_reason(),
        None,
        "this host is a supported one"
    );
    eprintln!(
        "RECORDED: the NTFS 8.3 short-name class is not demonstrated on this host.  It is \
         closed by declaration rather than by test: filesystem exports are unsupported on \
         Windows, and 8.3 short names exist nowhere else."
    );
}

#[test]
fn identity_survives_a_rename() {
    let fixture = Fixture::new();
    fixture.file("before.txt", b"synthetic");
    let export = fixture.open(
        full_grant(),
        FeatureSet::from_slice(&[Feature::AtomicRename]),
        bounds(),
    );

    let before = export
        .resolve(&vpath("/before.txt"), Intent::Inspect)
        .expect("resolves")
        .identity();
    export
        .rename(&vpath("/before.txt"), &vpath("/after.txt"))
        .expect("rename inside the export");
    let after = export
        .resolve(&vpath("/after.txt"), Intent::Inspect)
        .expect("resolves under its new name")
        .identity();

    assert!(
        before.is_same_file(after),
        "a rename does not change a file"
    );
    assert_eq!(before.qid_path(), after.qid_path());
    assert_eq!(
        export
            .resolve(&vpath("/before.txt"), Intent::Inspect)
            .expect_err("the old name is gone")
            .code(),
        FsErrorCode::Enoent
    );
}

#[test]
fn two_names_of_one_inode_are_one_file_and_two_files_are_not() {
    let fixture = Fixture::new();
    fixture.file("one.txt", b"identical");
    fixture.file("other.txt", b"identical");
    std::fs::hard_link(fixture.inside("one.txt"), fixture.inside("link.txt"))
        .expect("create a second link");

    let export = fixture.open_default();
    assert!(
        export
            .same_file(&vpath("/one.txt"), &vpath("/link.txt"))
            .expect("both resolve")
    );
    assert!(
        !export
            .same_file(&vpath("/one.txt"), &vpath("/other.txt"))
            .expect("both resolve"),
        "identical content is not identity"
    );
    assert!(
        export
            .same_file(&vpath("/one.txt"), &vpath("/one.txt"))
            .expect("both resolve")
    );
}

#[test]
fn a_qid_path_discloses_no_host_detail() {
    let fixture = Fixture::new();
    fixture.file("a.txt", b"synthetic");
    let export = fixture.open_default();
    let identity = export
        .resolve(&vpath("/a.txt"), Intent::Inspect)
        .expect("resolves")
        .identity();

    let rendering = format!("{identity:?}");
    assert!(rendering.contains("regular_file"));
    assert!(!rendering.contains("device"));
    assert!(!rendering.contains("inode"));
    assert!(!rendering.contains(&identity.qid_path().to_string()));
}

#[test]
fn a_path_at_the_component_limit_resolves_and_one_beyond_is_refused() {
    let fixture = Fixture::new();
    let limit = 32;
    let bounds = PathBounds::new(4096, limit).expect("valid bounds");

    let mut relative = String::new();
    let mut virtual_path = String::new();
    for step in 0..limit {
        if step > 0 {
            relative.push('/');
        }
        relative.push('d');
        virtual_path.push_str("/d");
    }
    fixture.dir(&relative);

    let export = fixture.open(full_grant(), FeatureSet::NONE, bounds);
    let at_limit = VirtualPath::parse(&virtual_path, bounds).expect("a path at the limit is valid");
    export
        .resolve(&at_limit, Intent::Inspect)
        .expect("a path at the component limit resolves");

    let beyond = format!("{virtual_path}/d");
    VirtualPath::parse(&beyond, bounds)
        .expect_err("one component beyond the limit is refused before any host call");
}
