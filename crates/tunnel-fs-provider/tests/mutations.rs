//! Implementation gate 5 against a real temporary filesystem.
//!
//! What lives here rather than in the harness gate is everything that needs no
//! socket: the mutating primitives themselves, the read-only grant's refusal of
//! every one of them, the hard-link write rule on a genuinely multiply-linked
//! file, and — the part the wire cannot reach at all — the **outcome ledger**.
//!
//! The ledger is the heart of this gate. Gate 4 refused every mutation at three
//! layers and every refusal it could produce was `not_started`; gate 5 is where
//! a request can actually have happened, so the interesting question stops
//! being "was it allowed" and becomes "how far did it get". The four answers
//! and where each is decided:
//!
//! | Outcome | What it means here | Decided by |
//! | --- | --- | --- |
//! | `not_started` | Refused before the effecting syscall | the grant, the flags, the namespace, or resolving the parent |
//! | `failed` | The syscall was made and the host reported no change | `tunnel_fs_host::mutation_error` |
//! | `partial` | Some of it applied | a short `Rwrite`, or a multi-field `Tsetattr` whose later field failed |
//! | `unknown` | It applied and the reply never reached the consumer | the connector settling the ledger, or the session ending with it open |
//!
//! Driving `accept` and `step` by hand is what makes the last one reachable
//! without a socket: a test can perform a mutation and then end the session
//! without confirming delivery, which is exactly the shape a dropped consumer
//! connection has.

#![cfg(unix)]

mod support;

use support::{
    Fixture, error_code, exchange, full_grant, handshake, one_frame, read_and_list, tclunk,
    tgetattr, tlcreate, tlink, tlopen, tmkdir, tread, treadlink, tremove, trenameat, tsetattr,
    tsetattr_mode, tsetattr_mtime, tsetattr_size, tsymlink, tunlinkat, twalk, twrite,
    write_and_delete, write_features, written,
};
use tunnel_fs_core::{FsErrorCode, Outcome};
use tunnel_fs_ninep::flags::{
    AT_REMOVEDIR, GETATTR_BASIC, O_APPEND, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY, SETATTR_MODE,
    SETATTR_SIZE,
};
use tunnel_fs_ninep::{Message, QidKind};

/// The root fid every test attaches to.
const ROOT: u32 = 0;

/// Deterministic synthetic bytes.
///
/// 251 is prime and below 256, so the pattern aligns with no power of two the
/// transport uses and a duplicated or dropped block changes the content.
fn synthetic(len: usize) -> Vec<u8> {
    (0..len).map(|index| (index % 251) as u8).collect()
}

/// A provider over a write-serving export.
fn writer(fixture: &Fixture) -> tunnel_fs_provider::Provider<support::TestAuthority> {
    let (provider, _authority) = fixture.provider_with(
        full_grant(),
        write_features(),
        tunnel_fs_provider::default_limits(),
    );
    provider
}

// ------------------------------------------------------------------- creates

#[test]
fn a_create_makes_a_file_writes_it_and_reads_it_back_byte_for_byte() {
    let fixture = Fixture::new();
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);

    // The parent fid becomes the created file's fid, which is 9P's own rule and
    // is where gate 3 stamps a fresh generation.
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        tlcreate(3, parent, "made.bin", O_WRONLY, 0o644),
    ));
    match reply.message {
        Message::Rlcreate { qid, .. } => assert_eq!(qid.kind, QidKind::File),
        other => panic!("expected Rlcreate, got {other:?}"),
    }

    // Enough to span several messages at the default `msize`, so the write path
    // is exercised across records rather than in one.
    let body = synthetic(200_000);
    let chunk = 60_000;
    let mut offset = 0_usize;
    let mut tag = 4_u16;
    while offset < body.len() {
        let end = (offset + chunk).min(body.len());
        let reply = one_frame(exchange(
            &mut provider,
            twrite(tag, parent, offset as u64, &body[offset..end]),
        ));
        let count = written(&reply) as usize;
        assert!(count > 0, "a write that acknowledged nothing");
        offset += count;
        tag += 1;
    }
    let _ = exchange(&mut provider, tclunk(tag, parent));

    // Byte for byte on the host, at exactly the length that was sent: a
    // replayed chunk would change both the length and the content.
    let on_disk = std::fs::read(fixture.inside("made.bin")).expect("the created file");
    assert_eq!(on_disk.len(), body.len());
    assert_eq!(on_disk, body);

    let stats = provider.stats();
    assert_eq!(stats.bytes_written, body.len() as u64);
    assert_eq!(stats.mutations_applied, stats.mutations_acknowledged);
    assert_eq!(stats.mutation_unknown, 0);
    assert_eq!(stats.mutation_failed, 0);
}

#[test]
fn a_create_is_always_exclusive_even_without_the_flag() {
    // The pinned narrowing: `Tlcreate` opens `O_CREAT | O_EXCL` whatever the
    // request's flag word said, so a create can never open — or truncate — a
    // file that already exists. Overwriting is what `OpenTruncate` names, and a
    // create that silently did it would apply the `Create` authorization to a
    // mutation the primitive does not describe.
    let fixture = Fixture::new();
    fixture.file("/taken.bin", b"existing-content");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));

    // No `O_EXCL` in the request at all.
    let reply = one_frame(exchange(
        &mut provider,
        tlcreate(3, parent, "taken.bin", O_WRONLY, 0o644),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eexist);
    assert_eq!(
        std::fs::read(fixture.inside("taken.bin")).expect("untouched"),
        b"existing-content"
    );
    // Dispatched — the `openat` was made — and reported `failed`, which is the
    // distinction gate 4 could not draw.
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 1);
    assert_eq!(stats.mutation_failed, 1);
    assert_eq!(stats.mutations_applied, 0);
}

#[test]
fn a_create_that_is_not_writable_is_refused_rather_than_served() {
    // Gate 3's `create_primitives` already refuses a read-only create, for the
    // same reason this dispatcher would: a fid that just made a file and cannot
    // write to it is a request with no meaning, and the fid's two descriptions
    // — the session's and the host descriptor's — would disagree. So the answer
    // is `ENOTSUP` from the codec's flag set and not `EINVAL` from here, and
    // the dispatcher's own check is unreachable in practice. It is kept and
    // recorded rather than removed, the way gate 2 keeps its `EINTR` retry:
    // this file is the only caller of `ExportRoot::create` today, and a second
    // one would not have gate 3 in front of it.
    let fixture = Fixture::new();
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        tlcreate(3, parent, "readonly.bin", O_RDONLY, 0o644),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Enotsup);
    assert!(!fixture.inside("readonly.bin").exists());
}

#[test]
fn a_mode_outside_the_permission_bits_is_refused_and_never_masked() {
    // Refuse, never repair — the namespace's own rule, applied to a mode.
    // Quietly dropping the set-user-ID bit would report a mode that was not
    // applied.
    let fixture = Fixture::new();
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));
    for mode in [0o4755, 0o2755, 0o1777] {
        let reply = one_frame(exchange(
            &mut provider,
            tlcreate(3, parent, "suid.bin", O_WRONLY, mode),
        ));
        assert_eq!(error_code(&reply), FsErrorCode::Einval, "mode {mode:#o}");
        assert!(!fixture.inside("suid.bin").exists());
    }
}

#[test]
fn an_append_open_is_refused_because_the_two_hosts_disagree_about_it() {
    // `pwrite` on an `O_APPEND` descriptor honours its offset on one host and
    // appends on the other, so accepting the flag would make the wire's meaning
    // depend on the serving operating system.
    let fixture = Fixture::new();
    fixture.file("/notes.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["notes.bin"]));
    let reply = one_frame(exchange(&mut provider, tlopen(3, fid, O_WRONLY | O_APPEND)));
    assert_eq!(error_code(&reply), FsErrorCode::Enotsup);
    assert_eq!(
        std::fs::read(fixture.inside("notes.bin")).expect("untouched"),
        b"synthetic"
    );
}

// ------------------------------------------------------- names and the tree

#[test]
fn mkdir_unlink_and_rename_each_change_exactly_what_they_name() {
    let fixture = Fixture::new();
    fixture.file("/movable.bin", b"synthetic");
    fixture.file("/doomed.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));

    let reply = one_frame(exchange(
        &mut provider,
        tmkdir(3, root_clone, "tree", 0o755),
    ));
    match reply.message {
        Message::Rmkdir { qid } => assert_eq!(qid.kind, QidKind::Directory),
        other => panic!("expected Rmkdir, got {other:?}"),
    }
    assert!(fixture.inside("tree").is_dir());

    let tree = 2_u32;
    let _ = exchange(&mut provider, twalk(4, ROOT, tree, &["tree"]));
    let reply = one_frame(exchange(
        &mut provider,
        trenameat(5, root_clone, "movable.bin", tree, "moved.bin"),
    ));
    assert!(matches!(reply.message, Message::Rrenameat));
    assert!(!fixture.inside("movable.bin").exists());
    assert_eq!(
        std::fs::read(fixture.inside("tree/moved.bin")).expect("moved"),
        b"synthetic"
    );

    let reply = one_frame(exchange(
        &mut provider,
        tunlinkat(6, root_clone, "doomed.bin", 0),
    ));
    assert!(matches!(reply.message, Message::Runlinkat));
    assert!(!fixture.inside("doomed.bin").exists());

    // A directory needs `AT_REMOVEDIR`, which gate 3 decoded and gate 1
    // authorizes as its own primitive.
    let reply = one_frame(exchange(&mut provider, tunlinkat(7, tree, "moved.bin", 0)));
    assert!(matches!(reply.message, Message::Runlinkat));
    let reply = one_frame(exchange(
        &mut provider,
        tunlinkat(8, root_clone, "tree", AT_REMOVEDIR),
    ));
    assert!(matches!(reply.message, Message::Runlinkat));
    assert!(!fixture.inside("tree").exists());
}

#[test]
fn a_remove_decides_the_kind_from_the_resolver_rather_than_from_the_walk() {
    // The same obligation gate 4 discharged for `Tlopen`, applied to removal:
    // `unlinkat` without `AT_REMOVEDIR` refuses a directory and with it refuses
    // a file, so a kind taken from the walk would answer `EISDIR` for a node
    // that had changed kind since. The only experiment that separates the two
    // is to walk to a file and replace the name with a directory before the
    // remove.
    let fixture = Fixture::new();
    fixture.file("/swap", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["swap"]));

    fixture.remove("/swap");
    fixture.dir("/swap");

    let reply = one_frame(exchange(&mut provider, tremove(3, fid)));
    assert!(
        matches!(reply.message, Message::Rremove),
        "a node that changed kind is still removed: {:?}",
        reply.message
    );
    assert!(!fixture.inside("swap").exists());
}

#[test]
fn a_special_file_cannot_be_removed_or_renamed_away() {
    // The pinned narrowing, and the cost it carries. The profile refuses a
    // FIFO, a socket and a device node at every other operation and leaves
    // them out of a listing, so a `delete` grant that could nonetheless unlink
    // one would be the single place their existence was observable through the
    // export. A rename is covered by the same check for the same reason:
    // renaming away removes a name, so a spelling that got around the refusal
    // would be a refusal in name only.
    //
    // The cost is that a special file placed inside an export out of band
    // cannot be cleared through it, and that is accepted rather than hidden.
    //
    // A unix-domain socket is what the fixture uses, because `std` can bind
    // one and this crate has no way to call `mknod`; the decision under test is
    // the node *kind*, and a socket is one of the kinds.
    let fixture = Fixture::new();
    let socket_path = fixture.inside("socket.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).expect("bind a fixture socket");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));

    let reply = one_frame(exchange(
        &mut provider,
        tunlinkat(3, root_clone, "socket.sock", 0),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Enotsup);
    let reply = one_frame(exchange(
        &mut provider,
        trenameat(4, root_clone, "socket.sock", root_clone, "moved.sock"),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Enotsup);
    assert!(socket_path.exists(), "the socket is still there");
    assert!(!fixture.inside("moved.sock").exists());
    // Refused before the host was asked to change anything.
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 0);
    assert_eq!(stats.mutations_applied, 0);

    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn a_symbolic_link_name_can_be_removed_although_the_feature_is_off() {
    // The one place this module is more permissive than the resolver, and it is
    // deliberate: `unlinkat` never follows its final component, so removing a
    // link's *name* cannot be steered outside the root by it, and refusing
    // would leave a link an export cannot traverse also one it can never clear.
    let fixture = Fixture::new();
    fixture.file("/target.bin", b"synthetic");
    std::os::unix::fs::symlink("target.bin", fixture.inside("alias"))
        .expect("a fixture symbolic link");
    // No `symlinks` feature: this export cannot read the link or create one.
    let (mut provider, _authority) = fixture.provider_with(
        full_grant(),
        tunnel_fs_core::FeatureSet::NONE
            .with(tunnel_fs_core::Feature::AtomicRename)
            .with(tunnel_fs_core::Feature::ExclusiveCreate),
        tunnel_fs_provider::default_limits(),
    );
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        tunlinkat(3, root_clone, "alias", 0),
    ));
    assert!(
        matches!(reply.message, Message::Runlinkat),
        "a symbolic link's name is removable: {:?}",
        reply.message
    );
    assert!(!fixture.inside("alias").exists());
    // And the file it pointed at is untouched: `unlinkat` removed the name, not
    // what the name referred to.
    assert_eq!(
        std::fs::read(fixture.inside("target.bin")).expect("the target"),
        b"synthetic"
    );
}

#[test]
fn a_symbolic_link_is_created_and_read_back_and_the_target_is_not_resolved() {
    let fixture = Fixture::new();
    fixture.file("/target.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));

    let reply = one_frame(exchange(
        &mut provider,
        tsymlink(3, root_clone, "alias", "target.bin"),
    ));
    match reply.message {
        Message::Rsymlink { qid } => assert_eq!(qid.kind, QidKind::Symlink),
        other => panic!("expected Rsymlink, got {other:?}"),
    }

    let link = 2_u32;
    let _ = exchange(&mut provider, twalk(4, ROOT, link, &["alias"]));
    let reply = one_frame(exchange(&mut provider, treadlink(5, link)));
    match reply.message {
        Message::Rreadlink { target } => assert_eq!(target, "target.bin"),
        other => panic!("expected Rreadlink, got {other:?}"),
    }

    // An **absolute** target is written verbatim and is not host `/`: the
    // re-rooting happens in the resolver on every later traversal, not at
    // creation, so what comes back is exactly what went in.
    let reply = one_frame(exchange(
        &mut provider,
        tsymlink(6, root_clone, "absolute", "/target.bin"),
    ));
    assert!(matches!(reply.message, Message::Rsymlink { .. }));
    let absolute = 3_u32;
    let _ = exchange(&mut provider, twalk(7, ROOT, absolute, &["absolute"]));
    let reply = one_frame(exchange(&mut provider, treadlink(8, absolute)));
    match reply.message {
        Message::Rreadlink { target } => assert_eq!(target, "/target.bin"),
        other => panic!("expected Rreadlink, got {other:?}"),
    }
}

#[test]
fn a_hard_link_is_refused_because_the_feature_is_not_advertised() {
    // `Tlink` is the one part of the hard-link rule that is a simple capability
    // check, and it is taken by gate 1's own table before any host call. The
    // feature stays off precisely so the `st_nlink` write refusal below is
    // reachable.
    let fixture = Fixture::new();
    fixture.file("/original.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let source = 1_u32;
    let root_clone = 2_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, source, &["original.bin"]));
    let _ = exchange(&mut provider, twalk(3, ROOT, root_clone, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        tlink(4, root_clone, source, "second-name.bin"),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert!(!fixture.inside("second-name.bin").exists());
    assert_eq!(provider.stats().mutations_dispatched, 0);
}

// ------------------------------------------------------- the hard-link rule

#[test]
fn a_multiply_linked_file_cannot_be_written_truncated_or_resized() {
    // Rule 4 of the confinement model, reachable on a **real write** for the
    // first time: gate 2 proved it in the resolver's own tests, and gate 4 could
    // not reach it because it would not open a writable fid at all. With
    // `hardLinks` off, a regular file whose `st_nlink` exceeds 1 may be read and
    // may not be written, because the inode may also be linked outside the root
    // and writing through it would be an escape no path check can see.
    let fixture = Fixture::new();
    fixture.file("/shared.bin", b"original-content");
    // The second link is made **out of band**, the way one would exist in a
    // real export: the profile itself refuses to create one without the
    // feature, so a test that made it through the wire would be proving
    // something else.
    std::fs::hard_link(fixture.inside("shared.bin"), fixture.inside("second.bin"))
        .expect("a second link");

    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["shared.bin"]));

    // The **truncating** open is deliberately not in this loop; it has its own
    // test below. A guard-deletion case that makes the hard-link rule
    // disappear panics on whichever iteration comes first, so a loop that
    // reached the truncating case last would never measure it — the reported
    // red would be about a different assertion entirely.
    for (label, flags) in [("write", O_WRONLY), ("read-write", O_RDWR)] {
        let reply = one_frame(exchange(&mut provider, tlopen(3, fid, flags)));
        assert_eq!(error_code(&reply), FsErrorCode::Eperm, "{label}");
        assert_eq!(
            std::fs::read(fixture.inside("shared.bin")).expect("intact"),
            b"original-content",
            "{label}"
        );
    }

    // A size-changing `Tsetattr` on a fid that was never opened takes the same
    // refusal, through the same rule.
    let reply = one_frame(exchange(&mut provider, tsetattr_size(4, fid, 0)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert_eq!(
        std::fs::read(fixture.inside("shared.bin")).expect("intact"),
        b"original-content"
    );

    // And reading is unaffected: the link count discloses nothing the grant
    // does not already permit.
    let reply = one_frame(exchange(&mut provider, tlopen(5, fid, O_RDONLY)));
    assert!(matches!(reply.message, Message::Rlopen { .. }));
    let reply = one_frame(exchange(&mut provider, tread(6, fid, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"original-content"),
        other => panic!("expected Rread, got {other:?}"),
    }

    // Every one of those refusals is `not_started`: nothing was dispatched.
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 0);
    assert_eq!(stats.mutations_applied, 0);
}

#[test]
fn a_truncating_open_of_a_multiply_linked_file_leaves_its_content_intact() {
    // **Its own test, and the ordering is the point.** Gate 2 pinned that
    // truncation happens through the descriptor *after* the hard-link rule has
    // permitted it, so the resolving open never carries `O_TRUNC`; the
    // observable form of that is a refused truncating open whose file still has
    // its bytes. An implementation that put `O_TRUNC` on the resolving open
    // would answer the same `EPERM` and leave an empty file behind, and only
    // this assertion tells them apart.
    //
    // Separated from the loop above so a guard deletion that reaches this
    // *does* reach it: with the rule gone the open is admitted, the truncation
    // happens, and the content assertion is what goes red.
    let fixture = Fixture::new();
    fixture.file("/shared.bin", b"original-content");
    std::fs::hard_link(fixture.inside("shared.bin"), fixture.inside("second.bin"))
        .expect("a second link");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["shared.bin"]));

    let reply = one_frame(exchange(&mut provider, tlopen(3, fid, O_WRONLY | O_TRUNC)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert_eq!(
        std::fs::read(fixture.inside("shared.bin")).expect("intact"),
        b"original-content",
        "the refusal must not follow a truncation that already happened"
    );
    assert_eq!(provider.stats().mutations_dispatched, 0);
}

#[test]
fn a_size_change_the_host_refuses_is_failed_and_not_not_started() {
    // The unopened-fid path: `ExportRoot::set_size` resolves, applies the
    // hard-link rule and then truncates. The truncation **is** the effecting
    // syscall, so its failure is `failed` — the host was asked and reported it
    // changed nothing — where routing it through `host_error` would report
    // `not_started` for a call that was made.
    //
    // A size no filesystem can represent is what makes the host refuse: the
    // exact code is the host's business and the vocabulary's, and what this
    // asserts is the *outcome*, which is the profile's.
    let fixture = Fixture::new();
    fixture.file("/resize.bin", &synthetic(1_024));
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["resize.bin"]));

    let reply = one_frame(exchange(&mut provider, tsetattr_size(3, fid, u64::MAX)));
    assert!(
        matches!(reply.message, Message::Rlerror { .. }),
        "a size the host cannot represent is refused: {:?}",
        reply.message
    );
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 1, "the host was asked");
    assert_eq!(stats.mutation_failed, 1, "and reported it changed nothing");
    assert_eq!(stats.mutations_refused, 0, "not a pre-dispatch refusal");
    assert_eq!(stats.mutations_applied, 0);
    // And it really did change nothing.
    assert_eq!(
        std::fs::metadata(fixture.inside("resize.bin"))
            .expect("the file")
            .len(),
        1_024
    );
}

#[test]
fn a_rename_onto_a_special_files_name_is_refused() {
    // `renameat` removes whatever occupies the destination, so a rename onto a
    // socket's name is a spelling of the special-file removal this profile
    // otherwise refuses — which would make that refusal a refusal in name only.
    // Both endpoints are inspected, not just the source.
    let fixture = Fixture::new();
    fixture.file("/ordinary.bin", b"synthetic");
    let socket_path = fixture.inside("socket.sock");
    let listener =
        std::os::unix::net::UnixListener::bind(&socket_path).expect("bind a fixture socket");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));

    let reply = one_frame(exchange(
        &mut provider,
        trenameat(3, root_clone, "ordinary.bin", root_clone, "socket.sock"),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Enotsup);
    assert!(socket_path.exists(), "the socket survives");
    assert!(
        fixture.inside("ordinary.bin").exists(),
        "and so does the source"
    );
    assert_eq!(provider.stats().mutations_dispatched, 0);

    // A rename onto a **free** name is the ordinary case and still works: the
    // destination inspection refuses an occupant it may not remove, not every
    // destination.
    let reply = one_frame(exchange(
        &mut provider,
        trenameat(4, root_clone, "ordinary.bin", root_clone, "moved.bin"),
    ));
    assert!(matches!(reply.message, Message::Rrenameat));
    assert!(fixture.inside("moved.bin").exists());

    drop(listener);
    let _ = std::fs::remove_file(&socket_path);
}

#[test]
fn a_setattr_mode_carrying_the_file_type_bits_still_applies() {
    // Linux's own v9fs client sends `Tsetattr`'s `mode` as the kernel's
    // `ia_mode`, which carries the node's type bits alongside its permissions.
    // Refusing them would refuse every `chmod` from the reference client, and
    // they grant nothing — a type bit *describes* a node and cannot change one,
    // and `fchmod` ignores them — so they are discarded rather than refused.
    // The set-user-ID, set-group-ID and sticky bits are a different case and
    // stay refused, because those do grant.
    let fixture = Fixture::new();
    fixture.file("/attrs.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["attrs.bin"]));

    // `S_IFREG | 0o640`, which is exactly what v9fs sends for `chmod 640`.
    let reply = one_frame(exchange(&mut provider, tsetattr_mode(3, fid, 0o100_640)));
    assert!(
        matches!(reply.message, Message::Rsetattr),
        "the reference client's chmod is served: {:?}",
        reply.message
    );
    let reply = one_frame(exchange(&mut provider, tgetattr(4, fid, GETATTR_BASIC)));
    match reply.message {
        Message::Rgetattr(attributes) => assert_eq!(attributes.mode & 0o7777, 0o640),
        other => panic!("expected Rgetattr, got {other:?}"),
    }

    // And a set-user-ID bit is still refused, type bits or no type bits.
    let reply = one_frame(exchange(&mut provider, tsetattr_mode(5, fid, 0o104_755)));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
}

#[test]
fn a_file_that_gains_a_link_after_its_open_is_refused_at_the_resize() {
    // The link count the rule consults is the one the descriptor reports
    // **now**, not the one it reported when it was opened. A file that gained a
    // second link since is one this rule must refuse, and a count cached at open
    // time would not see it.
    let fixture = Fixture::new();
    fixture.file("/growing.bin", b"original-content");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["growing.bin"]));
    let reply = one_frame(exchange(&mut provider, tlopen(3, fid, O_WRONLY)));
    assert!(matches!(reply.message, Message::Rlopen { .. }));

    std::fs::hard_link(fixture.inside("growing.bin"), fixture.inside("late.bin"))
        .expect("a second link");

    let reply = one_frame(exchange(&mut provider, tsetattr_size(4, fid, 0)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert_eq!(
        std::fs::read(fixture.inside("growing.bin")).expect("intact"),
        b"original-content"
    );
}

// ------------------------------------------------------------- the outcomes

#[test]
fn a_host_permission_failure_is_reported_failed_and_names_no_path() {
    // A real host failure rather than an injected one: a directory the export
    // may traverse and may not write to. `EACCES` is the host's own answer and
    // the closed vocabulary's, and the rendering carries no name.
    let fixture = Fixture::new();
    fixture.dir("/locked");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let locked = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, locked, &["locked"]));
    set_mode(&fixture.inside("locked"), 0o500);

    let reply = one_frame(exchange(
        &mut provider,
        tlcreate(3, locked, "denied.bin", O_WRONLY, 0o644),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eacces);
    // The whole rendering, not just the code: no name, no host path, no
    // content. The error type is `Copy` over field-free enums, so this is a
    // property of the type and the assertion is the demonstration.
    let rendered = format!("{:?} {}", reply.message, FsErrorCode::Eacces);
    assert!(!rendered.contains("denied"), "{rendered}");
    assert!(!rendered.contains("locked"), "{rendered}");
    assert!(
        !rendered.contains(&fixture.export().to_string_lossy().into_owned()),
        "{rendered}"
    );

    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 1);
    assert_eq!(stats.mutation_failed, 1);
    assert_eq!(stats.mutations_applied, 0);
    assert_eq!(stats.mutation_unknown, 0);

    // Restore the mode so the fixture's own cleanup can remove the directory.
    set_mode(&fixture.inside("locked"), 0o700);
}

#[test]
fn a_write_the_consumer_never_received_is_unknown_and_is_not_replayed() {
    // The contract: "Session loss during a potentially dispatched mutation
    // carries `outcome: unknown`." The effect happened and the consumer will
    // never be told what it was, so the operation is `unknown` — never
    // `not_started`, which would invite a replay, and never `failed`, which
    // would be a claim the host did not make.
    //
    // Driving `accept` and `step` by hand is what makes this reachable without
    // a socket: the connector is what confirms delivery, so a test that simply
    // does not confirm it has exactly the shape of a consumer that went away
    // between the host call and the send.
    let fixture = Fixture::new();
    fixture.file("/live.bin", b"original");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["live.bin"]));
    let _ = exchange(&mut provider, tlopen(3, fid, O_WRONLY));

    let body = b"replacement-body";
    let admitted = provider.accept(&twrite(4, fid, 0, body));
    assert!(admitted.is_empty(), "a queued request answers nothing yet");
    let out = provider.step();
    assert_eq!(out.len(), 1, "the write produced its reply");
    // The reply exists and carries an effect that has already happened.
    assert!(
        provider.reply_carries_effect(),
        "an applied mutation opens the ledger"
    );
    // The consumer is gone: the connector never confirms the send.
    provider.note_effect_undelivered();

    let stats = provider.stats();
    assert_eq!(stats.mutations_applied, 1);
    assert_eq!(stats.mutation_unknown, 1, "reported unknown, not failed");
    assert_eq!(stats.mutation_failed, 0);
    assert_eq!(stats.mutations_refused, 0);
    // Monotonic: a second report cannot add a second unknown for one effect,
    // and cannot weaken the first.
    provider.note_effect_undelivered();
    assert_eq!(provider.stats().mutation_unknown, 1);

    // The effect really did happen, exactly once. A replay would show as a
    // doubled prefix; a lost write would show as the original content.
    assert_eq!(
        std::fs::read(fixture.inside("live.bin")).expect("the file"),
        body
    );
}

#[test]
fn a_session_that_ends_holding_an_effect_reports_it_unknown() {
    // The same fact at the other end: `Provider::close` is the last moment an
    // outstanding effect can be recorded, and a queued request that was never
    // performed is deliberately **not** counted with it — that one was never
    // dispatched, so it is `not_started` and there is nothing ambiguous about
    // it.
    let fixture = Fixture::new();
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));

    let _ = provider.accept(&tmkdir(3, parent, "made", 0o755));
    let out = provider.step();
    assert_eq!(out.len(), 1);
    assert!(provider.reply_carries_effect());

    // A second request is admitted and never performed.
    let _ = provider.accept(&tmkdir(4, parent, "never", 0o755));
    assert!(provider.has_work());

    provider.close();
    let stats = provider.stats();
    assert_eq!(stats.mutation_unknown, 1, "the performed one, and only it");
    assert!(fixture.inside("made").is_dir());
    assert!(
        !fixture.inside("never").exists(),
        "a queued request is never performed by close"
    );
}

#[test]
fn a_composite_setattr_that_fails_after_a_field_applied_is_partial() {
    // The one composite mutation in the profile, and the only place a genuine
    // partial outcome arises without the wire's help. The order is fixed —
    // size, then mode, then times — so one request has one answer, and a
    // failure after an earlier field succeeded can never be reported
    // `not_started`.
    let fixture = Fixture::new();
    fixture.file("/attrs.bin", &synthetic(4_096));
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["attrs.bin"]));

    // The size applies; the mode is refused by this profile rather than by the
    // host, because it carries a bit outside `0o777`.
    let reply = one_frame(exchange(
        &mut provider,
        tsetattr(3, fid, SETATTR_SIZE | SETATTR_MODE, 0o4755, 16),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
    // The truncation happened, which is what makes the outcome partial rather
    // than not-started.
    assert_eq!(
        std::fs::metadata(fixture.inside("attrs.bin"))
            .expect("the file")
            .len(),
        16
    );
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 1);
    assert_eq!(stats.mutations_applied, 1);
    // **`partial`, not `unknown`, and the difference is what the consumer was
    // told.** An `Rlerror` *is* delivered here — the caller learns that the
    // mode field failed — so labelling it `unknown` would describe a reply that
    // arrived as one that did not. What the caller cannot tell from that
    // `Rlerror` alone is that the size field already applied, and `partial` is
    // the name for exactly that.
    assert_eq!(stats.mutation_partial, 1);
    assert_eq!(stats.mutation_unknown, 0);
    // Delivered, like any other effect-carrying reply: the ledger opened and
    // the connector — `exchange`, here — settled it.
    assert_eq!(stats.mutations_acknowledged, 1);
    assert_eq!(stats.mutations_refused, 0);
    assert_eq!(stats.mutation_failed, 0);

    // And the ordering claim itself: gate 1's merge is what forbids the
    // weakening, and it is asserted rather than assumed.
    assert_eq!(
        Outcome::Partial.merge(Outcome::NotStarted),
        Outcome::Partial
    );
}

#[test]
fn a_timestamp_field_without_its_set_companion_is_touch_and_applies() {
    // `.L` gives each timestamp two mask bits, and **the field bit without its
    // `_SET` companion is the ordinary spelling, not an exotic one**: it means
    // "use the current time", it is what `utimes(NULL)` sends, and that is what
    // `touch` sends. An earlier round of this gate dropped it silently and
    // still answered `Rsetattr`, reporting success for a request that partly
    // did not happen — which the contract forbids. Refusing it would have been
    // the other wrong answer: it would refuse `touch`.
    //
    // The clock is the **host's**: `UTIME_NOW` is resolved by the kernel inside
    // `futimens`, and nothing in this profile reads one. So this is not the
    // clock enforcement gate 5 deliberately does not do.
    let fixture = Fixture::new();
    fixture.file("/attrs.bin", b"synthetic");
    // Backdated well past any plausible run, so "the time moved" is a
    // comparison rather than a race with the filesystem's timestamp
    // granularity.
    let backdated = std::time::SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_000_000);
    let file = std::fs::File::options()
        .write(true)
        .open(fixture.inside("attrs.bin"))
        .expect("open the fixture");
    file.set_modified(backdated).expect("backdate the fixture");
    drop(file);
    let before = std::fs::metadata(fixture.inside("attrs.bin"))
        .and_then(|metadata| metadata.modified())
        .expect("the backdated time");
    assert_eq!(before, backdated);

    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["attrs.bin"]));
    let reply = one_frame(exchange(
        &mut provider,
        tsetattr(3, fid, tunnel_fs_ninep::flags::SETATTR_MTIME, 0, 0),
    ));
    assert!(
        matches!(reply.message, Message::Rsetattr),
        "a touch is answered, not refused: {:?}",
        reply.message
    );
    let after = std::fs::metadata(fixture.inside("attrs.bin"))
        .and_then(|metadata| metadata.modified())
        .expect("the touched time");
    assert!(
        after > before,
        "the Rsetattr reported a mutation that must have happened"
    );
    let stats = provider.stats();
    assert_eq!(stats.mutations_applied, 1);
    assert_eq!(stats.mutation_partial, 0);
    assert_eq!(stats.mutation_unknown, 0);
}

#[test]
fn an_explicit_timestamp_is_applied_exactly_as_supplied() {
    // The other half of the mask: with `_SET` alongside the field bit, the
    // caller's own value is what lands — no normalisation, no rounding to the
    // host's clock.
    let fixture = Fixture::new();
    fixture.file("/attrs.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["attrs.bin"]));
    let reply = one_frame(exchange(
        &mut provider,
        tsetattr_mtime(3, fid, 1_700_000_000, 123_456_789),
    ));
    assert!(matches!(reply.message, Message::Rsetattr));
    let reply = one_frame(exchange(&mut provider, tgetattr(4, fid, GETATTR_BASIC)));
    match reply.message {
        Message::Rgetattr(attributes) => {
            assert_eq!(attributes.mtime_sec, 1_700_000_000);
            assert_eq!(attributes.mtime_nsec, 123_456_789);
        }
        other => panic!("expected Rgetattr, got {other:?}"),
    }

    // And a nanosecond field at or above one second is refused rather than
    // normalised into the seconds field — which is also what keeps the two
    // host sentinels unreachable from a caller's own value.
    let reply = one_frame(exchange(
        &mut provider,
        tsetattr_mtime(5, fid, 1_700_000_000, 1_000_000_000),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
}

#[test]
fn a_mode_change_applies_and_is_visible_to_a_stat() {
    let fixture = Fixture::new();
    fixture.file("/attrs.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["attrs.bin"]));
    let reply = one_frame(exchange(&mut provider, tsetattr_mode(3, fid, 0o640)));
    assert!(matches!(reply.message, Message::Rsetattr));
    let reply = one_frame(exchange(&mut provider, tgetattr(4, fid, GETATTR_BASIC)));
    match reply.message {
        Message::Rgetattr(attributes) => assert_eq!(attributes.mode & 0o777, 0o640),
        other => panic!("expected Rgetattr, got {other:?}"),
    }
}

// ------------------------------------------------- the grant, not the opcode

#[test]
fn a_write_grant_without_read_writes_and_cannot_read_back() {
    // The contract's `Twalk` disclosure note made concrete: a grant holding
    // `write` and `delete` can reach a name and change it, and can observe
    // nothing about it but a qid. This is the shape that makes "the server
    // enforces primitives, not labels" observable.
    let fixture = Fixture::new();
    let (mut provider, _authority) = fixture.provider_with(
        write_and_delete(),
        write_features(),
        tunnel_fs_provider::default_limits(),
    );
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        tlcreate(3, parent, "blind.bin", O_WRONLY, 0o644),
    ));
    assert!(matches!(reply.message, Message::Rlcreate { .. }));
    let reply = one_frame(exchange(&mut provider, twrite(4, parent, 0, b"written")));
    assert_eq!(written(&reply), 7);
    let _ = exchange(&mut provider, tclunk(5, parent));

    // `Tgetattr` needs `list` and `Tlopen` for reading needs `read`; neither is
    // held, so nothing about the file it just wrote is observable.
    let fid = 2_u32;
    let _ = exchange(&mut provider, twalk(6, ROOT, fid, &["blind.bin"]));
    let reply = one_frame(exchange(&mut provider, tgetattr(7, fid, GETATTR_BASIC)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    let reply = one_frame(exchange(&mut provider, tlopen(8, fid, O_RDONLY)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);

    // The bytes really are there, read from the host rather than through the
    // session that may not see them.
    assert_eq!(
        std::fs::read(fixture.inside("blind.bin")).expect("written"),
        b"written"
    );
}

#[test]
fn a_write_grant_without_delete_cannot_remove_what_it_created() {
    // `Trenameat` requires **both** `write` and `delete`, because renaming away
    // removes a name; a grant that may create and not remove must not be able
    // to remove one by renaming it.
    let fixture = Fixture::new();
    fixture.file("/kept.bin", b"synthetic");
    let (mut provider, _authority) = fixture.provider_with(
        tunnel_fs_core::CapabilitySet::from_slice(&[
            tunnel_fs_core::Capability::Write,
            tunnel_fs_core::Capability::List,
        ]),
        write_features(),
        tunnel_fs_provider::default_limits(),
    );
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));

    let reply = one_frame(exchange(
        &mut provider,
        tunlinkat(3, root_clone, "kept.bin", 0),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    let reply = one_frame(exchange(
        &mut provider,
        trenameat(4, root_clone, "kept.bin", root_clone, "renamed.bin"),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert!(fixture.inside("kept.bin").exists());
    assert!(!fixture.inside("renamed.bin").exists());
    assert_eq!(provider.stats().mutations_dispatched, 0);
}

#[test]
fn a_rename_without_the_atomic_rename_feature_is_refused() {
    // The feature gate, separate from the capability gate: a provider that
    // cannot offer a native single-namespace rename must not be asked for one,
    // and the contract forbids emulating it by copy-and-delete.
    let fixture = Fixture::new();
    fixture.file("/kept.bin", b"synthetic");
    let (mut provider, _authority) = fixture.provider_with(
        full_grant(),
        tunnel_fs_core::FeatureSet::NONE,
        tunnel_fs_provider::default_limits(),
    );
    handshake(&mut provider, ROOT);
    let root_clone = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, root_clone, &[]));
    let reply = one_frame(exchange(
        &mut provider,
        trenameat(3, root_clone, "kept.bin", root_clone, "renamed.bin"),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert!(fixture.inside("kept.bin").exists());
}

#[test]
fn a_narrowed_grant_refuses_a_queued_write_before_the_host_is_touched() {
    // The recheck after the queue wait, on a mutation. The request was
    // authorized when it arrived and is refused when it is performed, which is
    // the whole reason the dispatcher has a queue at all.
    let fixture = Fixture::new();
    fixture.file("/live.bin", b"original");
    let (mut provider, authority) = fixture.provider_with(
        full_grant(),
        write_features(),
        tunnel_fs_provider::default_limits(),
    );
    handshake(&mut provider, ROOT);
    let fid = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, fid, &["live.bin"]));
    let _ = exchange(&mut provider, tlopen(3, fid, O_WRONLY));

    let admitted = provider.accept(&twrite(4, fid, 0, b"replacement"));
    assert!(admitted.is_empty());
    // Narrowed while the request waits, without moving the revision.
    authority.narrow(read_and_list());
    let reply = one_frame(provider.step());
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert_eq!(
        std::fs::read(fixture.inside("live.bin")).expect("untouched"),
        b"original"
    );
    let stats = provider.stats();
    assert_eq!(stats.grant_refusals, 1);
    assert_eq!(stats.mutations_dispatched, 0, "refused before the host");
    assert_eq!(stats.mutations_refused, 1);
}

// ------------------------------------- the window after an effect, on a hook

// Where the fixture's export root goes, so a hook can reach it from a `fn()`
// that takes no arguments.  A line comment rather than a doc comment: rustdoc
// generates nothing for a macro invocation and says so as a hard error.
#[cfg(feature = "post-effect-hook")]
thread_local! {
    static HOOKED_ROOT: std::cell::RefCell<Option<std::path::PathBuf>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(feature = "post-effect-hook")]
#[test]
fn a_mkdir_whose_identity_read_loses_a_race_is_unknown_and_never_not_started() {
    // **The window this measures is microseconds wide**, so it is stepped into
    // deliberately rather than raced for — exactly the way gate 2 measures the
    // window between inspecting a name and opening it, and under a feature no
    // shipped build enables.
    //
    // `mkdirat` creates a directory and returns nothing, so the qid the
    // `Rmkdir` has to carry costs a second syscall. If that second syscall
    // loses a race — another process removed or replaced the name — the
    // directory **still exists**, and answering with the race's own `ENOENT`
    // unchanged would tell the caller its `Tmkdir` never started. A caller that
    // believed it and retried would meet `EEXIST` on a name it does not believe
    // it created.
    let fixture = Fixture::new();
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));

    HOOKED_ROOT.with(|slot| *slot.borrow_mut() = Some(fixture.export()));
    tunnel_fs_host::write::post_effect::set(|| {
        // Stand in for the racing process: remove the directory that was just
        // created, between the `mkdirat` and the `statat` that reads it back.
        HOOKED_ROOT.with(|slot| {
            if let Some(root) = slot.borrow().as_ref() {
                let _ = std::fs::remove_dir(root.join("raced"));
            }
        });
    });
    let reply = one_frame(exchange(&mut provider, tmkdir(3, parent, "raced", 0o755)));
    tunnel_fs_host::write::post_effect::clear();
    HOOKED_ROOT.with(|slot| *slot.borrow_mut() = None);

    // The uniform race answer, which is `ENOENT` and discloses nothing about
    // the host's concurrent activity.
    assert_eq!(error_code(&reply), FsErrorCode::Enoent);
    let stats = provider.stats();
    // And the outcome is the point: dispatched, applied, and **unknown** — not
    // `not_started`, which is what an unwrapped `host_error` would have said.
    assert_eq!(stats.mutations_dispatched, 1);
    assert_eq!(stats.mutations_applied, 1);
    assert_eq!(stats.mutation_unknown, 1);
    assert_eq!(stats.mutations_refused, 0, "the host was asked");
    assert_eq!(stats.mutation_failed, 0, "and it did change something");
    // Gate 1's ordering is what forbids the weakening, asserted rather than
    // assumed.
    assert_eq!(
        Outcome::Unknown.merge(Outcome::NotStarted),
        Outcome::Unknown
    );
}

#[cfg(feature = "post-effect-hook")]
#[test]
fn a_symlink_whose_identity_read_loses_a_race_is_unknown_too() {
    // The same shape for `symlinkat`, which also creates a node and returns
    // nothing. Listed separately rather than looped, so a guard deletion that
    // reaches one is reported against the operation it belongs to.
    let fixture = Fixture::new();
    fixture.file("/target.bin", b"synthetic");
    let mut provider = writer(&fixture);
    handshake(&mut provider, ROOT);
    let parent = 1_u32;
    let _ = exchange(&mut provider, twalk(2, ROOT, parent, &[]));

    HOOKED_ROOT.with(|slot| *slot.borrow_mut() = Some(fixture.export()));
    tunnel_fs_host::write::post_effect::set(|| {
        HOOKED_ROOT.with(|slot| {
            if let Some(root) = slot.borrow().as_ref() {
                let _ = std::fs::remove_file(root.join("raced"));
            }
        });
    });
    let reply = one_frame(exchange(
        &mut provider,
        tsymlink(3, parent, "raced", "target.bin"),
    ));
    tunnel_fs_host::write::post_effect::clear();
    HOOKED_ROOT.with(|slot| *slot.borrow_mut() = None);

    assert_eq!(error_code(&reply), FsErrorCode::Enoent);
    let stats = provider.stats();
    assert_eq!(stats.mutations_applied, 1);
    assert_eq!(stats.mutation_unknown, 1);
    assert_eq!(stats.mutations_refused, 0);
}

// ------------------------------------------------------------------ helpers

fn set_mode(path: &std::path::Path, mode: u32) {
    use std::os::unix::fs::PermissionsExt as _;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode))
        .expect("set fixture permissions");
}
