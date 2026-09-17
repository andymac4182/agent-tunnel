//! The gate-4 dispatcher against a real temporary filesystem.
//!
//! Everything here is proven without a socket, a relay or a clock: the live
//! authorization is moved by hand and the queue is stepped by hand, so a recheck
//! and a flush race are each proven by the answer they produce rather than by a
//! sleep. What needs the real Axum → owner → device path is the harness gate;
//! what needs neither is here, where it can be red-then-green by deletion.

#![cfg(unix)]

mod support;

use support::{
    Fixture, error_code, exchange, full_grant, handshake, list_only, one_close, one_frame,
    read_and_list, read_only, tattach, tclunk, tflush, tgetattr, tlopen, tread, treaddir, tversion,
    twalk,
};
use tunnel_fs_core::{FsErrorCode, SessionErrorCode};
use tunnel_fs_ninep::flags::{O_DIRECTORY, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY};
use tunnel_fs_ninep::{GETATTR_BASIC, Message, NOFID, NONUNAME, QidKind, parse_entries};

/// The root fid every test attaches to.
const ROOT: u32 = 0;

// ------------------------------------------------------------------- session

#[test]
fn an_empty_grant_admits_no_session() {
    let fixture = Fixture::new();
    let authority = support::TestAuthority::new(tunnel_fs_core::CapabilitySet::DENY);
    let root = tunnel_fs_host::ExportRoot::open(
        &fixture.export(),
        tunnel_fs_core::CapabilitySet::DENY,
        tunnel_fs_core::FeatureSet::NONE,
        support::bounds(),
    )
    .expect("open export root");
    assert!(
        tunnel_fs_provider::Provider::new(root, tunnel_fs_provider::default_limits(), authority)
            .is_none(),
        "an export granting nothing admits no session at all"
    );
}

#[test]
fn the_handshake_negotiates_the_dialect_and_attaches_the_root() {
    let fixture = Fixture::new();
    let (mut provider, _authority) = fixture.provider(read_and_list());

    let reply = one_frame(exchange(&mut provider, tversion(65_536)));
    match reply.message {
        Message::Rversion { msize, version } => {
            assert_eq!(msize, 65_536);
            assert_eq!(version, tunnel_fs_ninep::DIALECT);
        }
        other => panic!("expected Rversion, got {other:?}"),
    }

    let qid = one_frame(exchange(&mut provider, tattach(1, ROOT)));
    match qid.message {
        Message::Rattach { qid } => assert_eq!(qid.kind, QidKind::Directory),
        other => panic!("expected Rattach, got {other:?}"),
    }
}

#[test]
fn a_reduced_msize_is_honoured_and_never_raised() {
    let fixture = Fixture::new();
    let (mut provider, _authority) = fixture.provider(read_and_list());
    let reply = one_frame(exchange(&mut provider, tversion(4_096)));
    match reply.message {
        Message::Rversion { msize, .. } => assert_eq!(msize, 4_096),
        other => panic!("expected Rversion, got {other:?}"),
    }
    assert_eq!(provider.msize(), 4_096);
}

#[test]
fn a_forged_attach_cannot_choose_an_identity_or_an_export() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");

    // Each forged field on its own, so a refusal cannot be credited to the
    // wrong one.  The session's answer to every one of them is a 1002 close,
    // because a value in those fields is a request the profile has no way to
    // honour rather than one it can refuse and continue from.
    let forgeries = [
        Message::Tattach {
            fid: ROOT,
            afid: 3,
            uname: String::new(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: ROOT,
            afid: NOFID,
            uname: "root".to_owned(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: ROOT,
            afid: NOFID,
            uname: String::new(),
            aname: "/etc".to_owned(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: ROOT,
            afid: NOFID,
            uname: String::new(),
            aname: String::new(),
            n_uname: 0,
        },
    ];
    for forged in forgeries {
        let (mut provider, _authority) = fixture.provider(read_and_list());
        let _ = exchange(&mut provider, tversion(65_536));
        let closed = one_close(exchange(
            &mut provider,
            tunnel_fs_ninep::Frame::new(1, forged.clone()),
        ));
        assert_eq!(
            closed,
            SessionErrorCode::ProtocolViolation,
            "forged attach {forged:?} must not be admitted"
        );
    }
}

#[test]
fn a_forged_attach_cannot_exceed_the_grant_it_was_admitted_for() {
    // The positive half of the same claim: a *well-formed* attach succeeds, and
    // the session it opens carries the grant the export was configured with,
    // not anything the message could name.  A `list`-only session cannot read
    // even though its attach was accepted.
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(list_only());
    handshake(&mut provider, ROOT);

    let reply = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"])));
    assert!(matches!(reply.message, Message::Rwalk { .. }));
    let reply = one_frame(exchange(&mut provider, tlopen(3, 1, O_RDONLY)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
}

// ---------------------------------------------------------------- read path

#[test]
fn a_file_larger_than_one_message_reads_back_byte_for_byte() {
    let fixture = Fixture::new();
    // Deliberately not a multiple of any message size, so the last read is
    // short and the short read is part of the evidence.
    let body: Vec<u8> = (0..300_007_u32).map(|index| (index % 251) as u8).collect();
    fixture.file("/big.bin", &body);

    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &["big.bin"])));
    let reply = one_frame(exchange(&mut provider, tlopen(3, 1, O_RDONLY)));
    let iounit = match reply.message {
        Message::Rlopen { iounit, .. } => iounit,
        other => panic!("expected Rlopen, got {other:?}"),
    };
    assert!(iounit > 0 && iounit < provider.msize());

    let mut collected = Vec::new();
    let mut offset = 0_u64;
    let mut messages = 0_u32;
    loop {
        let reply = one_frame(exchange(&mut provider, tread(4, 1, offset, iounit)));
        let data = match reply.message {
            Message::Rread { data } => data,
            other => panic!("expected Rread, got {other:?}"),
        };
        if data.is_empty() {
            break;
        }
        messages += 1;
        offset += data.len() as u64;
        collected.extend_from_slice(&data);
    }
    assert!(messages > 4, "the file must span many messages: {messages}");
    assert_eq!(collected.len(), body.len());
    assert_eq!(fnv1a(&collected), fnv1a(&body));
    assert_eq!(collected, body);
    assert_eq!(provider.stats().bytes_read, body.len() as u64);
}

#[test]
fn a_read_at_an_offset_past_the_end_is_an_empty_reply_not_an_error() {
    let fixture = Fixture::new();
    fixture.file("/small.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["small.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));
    let reply = one_frame(exchange(&mut provider, tread(4, 1, 10_000, 64)));
    match reply.message {
        Message::Rread { data } => assert!(data.is_empty()),
        other => panic!("expected an empty Rread, got {other:?}"),
    }
}

#[test]
fn a_read_of_a_fid_that_was_never_opened_is_refused() {
    let fixture = Fixture::new();
    fixture.file("/small.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["small.txt"]));
    let reply = one_frame(exchange(&mut provider, tread(4, 1, 0, 64)));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
}

#[test]
fn a_walk_that_leaves_the_root_is_refused_by_the_namespace() {
    let fixture = Fixture::new();
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    // `..` never reaches the resolver: gate 1 refuses it, and gate 3 refuses the
    // frame before this dispatcher sees it.  The assertion is that the refusal
    // happens at all and names the namespace rather than the host.
    let reply = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &[".."])));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
}

#[test]
fn a_partial_walk_returns_the_qids_it_reached_and_binds_nothing() {
    let fixture = Fixture::new();
    fixture.dir("/a/b");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let reply = one_frame(exchange(
        &mut provider,
        twalk(2, ROOT, 1, &["a", "b", "absent"]),
    ));
    match reply.message {
        Message::Rwalk { qids } => assert_eq!(qids.len(), 2),
        other => panic!("expected a short Rwalk, got {other:?}"),
    }
    // A partial walk binds nothing, so the new fid is unusable.
    let reply = one_frame(exchange(&mut provider, tgetattr(3, 1, GETATTR_BASIC)));
    assert_eq!(error_code(&reply), FsErrorCode::Einval);
}

#[test]
fn a_walk_whose_first_element_fails_is_an_error_reply() {
    let fixture = Fixture::new();
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let reply = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &["absent"])));
    assert_eq!(error_code(&reply), FsErrorCode::Enoent);
}

// ------------------------------------------------------------- enumeration

#[test]
fn a_directory_enumerates_across_pages_with_opaque_cookies() {
    let fixture = Fixture::new();
    fixture.dir("/tree");
    for index in 0..40 {
        fixture.file(&format!("/tree/entry-{index:03}.txt"), b"synthetic");
    }

    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["tree"]));
    let _ = one_frame(exchange(
        &mut provider,
        tlopen(3, 1, O_RDONLY | O_DIRECTORY),
    ));

    // A small `count` forces several pages, which is what makes the cookie
    // load-bearing rather than decorative.
    let mut names = Vec::new();
    let mut cookie = 0_u64;
    let mut pages = 0_u32;
    loop {
        let reply = one_frame(exchange(&mut provider, treaddir(4, 1, cookie, 256)));
        let data = match reply.message {
            Message::Rreaddir { data } => data,
            other => panic!("expected Rreaddir, got {other:?}"),
        };
        if data.is_empty() {
            break;
        }
        pages += 1;
        let entries = parse_entries(&data).expect("a well-formed block");
        assert!(!entries.is_empty());
        cookie = entries.last().expect("a last entry").offset;
        for entry in entries {
            assert_eq!(entry.qid.kind, QidKind::File);
            names.push(entry.name);
        }
    }
    assert!(pages > 4, "the listing must span many pages: {pages}");
    names.sort();
    names.dedup();
    assert_eq!(names.len(), 40, "every entry exactly once");
    assert_eq!(provider.stats().readdir_entries, 40);
}

#[test]
fn a_readdir_of_a_file_is_refused() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));
    let reply = one_frame(exchange(&mut provider, treaddir(4, 1, 0, 4_096)));
    assert_eq!(error_code(&reply), FsErrorCode::Enotdir);
}

#[test]
fn a_read_of_an_open_directory_is_eisdir_not_raw_bytes() {
    let fixture = Fixture::new();
    fixture.dir("/tree");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["tree"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY | O_DIRECTORY));
    let reply = one_frame(exchange(&mut provider, tread(4, 1, 0, 4_096)));
    // `ENOTDIR` rather than `EISDIR`, and taken by gate 3's session rather than
    // by this dispatcher: the session knows the fid is open as a directory and
    // refuses `Tread` on it as a wrongly-used fid before the host is reached.
    // Either answer would be defensible; what matters is that no directory byte
    // is ever served as file content, and the refusal happening one layer
    // earlier is recorded here rather than papered over.
    assert_eq!(error_code(&reply), FsErrorCode::Enotdir);
}

// -------------------------------------------------- the authorization matrix

#[test]
fn list_without_read_can_stat_and_enumerate_but_not_read() {
    let fixture = Fixture::new();
    fixture.dir("/tree");
    fixture.file("/tree/notes.txt", b"synthetic");

    let (mut provider, _authority) = fixture.provider(list_only());
    handshake(&mut provider, ROOT);

    // Enumeration: permitted.
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["tree"]));
    let _ = one_frame(exchange(
        &mut provider,
        tlopen(3, 1, O_RDONLY | O_DIRECTORY),
    ));
    let reply = one_frame(exchange(&mut provider, treaddir(4, 1, 0, 4_096)));
    let data = match reply.message {
        Message::Rreaddir { data } => data,
        other => panic!("expected Rreaddir, got {other:?}"),
    };
    assert_eq!(parse_entries(&data).expect("block").len(), 1);

    // `Tgetattr` on a file this grant may not read: the metadata-only open.
    let _ = exchange(&mut provider, twalk(5, ROOT, 2, &["tree", "notes.txt"]));
    let reply = one_frame(exchange(&mut provider, tgetattr(6, 2, GETATTR_BASIC)));
    match reply.message {
        Message::Rgetattr(attributes) => {
            assert_eq!(attributes.size, 9);
            // And it discloses no host identity.
            assert_eq!(attributes.uid, 0);
            assert_eq!(attributes.gid, 0);
        }
        other => panic!("expected Rgetattr, got {other:?}"),
    }

    // Content: refused.
    let reply = one_frame(exchange(&mut provider, tlopen(7, 2, O_RDONLY)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
}

#[test]
fn read_without_list_can_read_by_name_but_not_stat_or_enumerate() {
    let fixture = Fixture::new();
    fixture.dir("/tree");
    fixture.file("/tree/notes.txt", b"synthetic");

    let (mut provider, _authority) = fixture.provider(read_only());
    handshake(&mut provider, ROOT);

    // Read by name: permitted.  `Twalk` needs no capability, which is what
    // makes this grant shape usable at all.
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["tree", "notes.txt"]));
    let _ = one_frame(exchange(&mut provider, tlopen(3, 1, O_RDONLY)));
    let reply = one_frame(exchange(&mut provider, tread(4, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"synthetic"),
        other => panic!("expected Rread, got {other:?}"),
    }

    // Metadata: refused, so a Files SDK `head` has nothing to call.
    let reply = one_frame(exchange(&mut provider, tgetattr(5, 1, GETATTR_BASIC)));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);

    // Enumeration: refused, and refused at the **open**, not only at the
    // `Treaddir` — which is the gate-3 obligation.
    let _ = exchange(&mut provider, twalk(6, ROOT, 2, &["tree"]));
    let reply = one_frame(exchange(
        &mut provider,
        tlopen(7, 2, O_RDONLY | O_DIRECTORY),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
}

#[test]
fn an_open_is_reclassified_with_the_resolvers_kind_not_the_recorded_qid() {
    // The gate-3 obligation in the only shape that can distinguish it from the
    // session's own qid-based decision: walk to a **file**, so the session
    // records `QTFILE` and classifies a read-only open as `OpenRead`, then
    // replace the name with a **directory** before the open. A
    // `read`-without-`list` grant must be refused, because `Treaddir` would
    // refuse it and the two decisions may not disagree.
    let fixture = Fixture::new();
    fixture.file("/swap", b"synthetic");

    let (mut provider, _authority) = fixture.provider(read_only());
    handshake(&mut provider, ROOT);
    let reply = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &["swap"])));
    match reply.message {
        Message::Rwalk { qids } => assert_eq!(qids[0].kind, QidKind::File),
        other => panic!("expected Rwalk, got {other:?}"),
    }

    fixture.remove("/swap");
    fixture.dir("/swap");

    let reply = one_frame(exchange(&mut provider, tlopen(3, 1, O_RDONLY)));
    assert_eq!(
        error_code(&reply),
        FsErrorCode::Eperm,
        "a read-without-list grant must not open a directory Treaddir would refuse"
    );
    let stats = provider.stats();
    assert_eq!(stats.reclassified_opens, 1);
    assert_eq!(stats.reclassification_refusals, 1);
}

#[test]
fn the_same_reclassification_admits_the_open_for_a_grant_that_holds_list() {
    let fixture = Fixture::new();
    fixture.file("/swap", b"synthetic");

    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = one_frame(exchange(&mut provider, twalk(2, ROOT, 1, &["swap"])));

    fixture.remove("/swap");
    fixture.dir("/swap");
    fixture.file("/swap/inside.txt", b"synthetic");

    let reply = one_frame(exchange(&mut provider, tlopen(3, 1, O_RDONLY)));
    match reply.message {
        Message::Rlopen { qid, .. } => assert_eq!(qid.kind, QidKind::Directory),
        other => panic!("expected Rlopen, got {other:?}"),
    }
    assert_eq!(provider.stats().reclassified_opens, 1);
    assert_eq!(provider.stats().reclassification_refusals, 0);
    // And the fid really is a directory: it enumerates.
    let reply = one_frame(exchange(&mut provider, treaddir(4, 1, 0, 4_096)));
    match reply.message {
        Message::Rreaddir { data } => {
            assert_eq!(parse_entries(&data).expect("block").len(), 1);
        }
        other => panic!("expected Rreaddir, got {other:?}"),
    }
}

// --------------------------------------- the read-only grant's own refusals

#[test]
fn every_mutating_opcode_is_refused_under_a_read_only_grant() {
    // A fresh provider per opcode, because several of them change the session's
    // own fid state on either answer — `Tremove` releases its fid whatever the
    // reply is — and a shared session would make one refusal depend on the
    // previous one.
    let mutations: Vec<Message> = vec![
        Message::Tlcreate {
            fid: 2,
            name: "new.txt".to_owned(),
            flags: O_WRONLY,
            mode: 0o644,
            gid: 0,
        },
        Message::Twrite {
            fid: 1,
            offset: 0,
            data: b"overwrite".to_vec(),
        },
        Message::Tmkdir {
            dfid: 2,
            name: "sub".to_owned(),
            mode: 0o755,
            gid: 0,
        },
        Message::Tunlinkat {
            dirfid: ROOT,
            name: "notes.txt".to_owned(),
            flags: 0,
        },
        Message::Tremove { fid: 1 },
        Message::Trename {
            fid: 1,
            dfid: 2,
            name: "moved.txt".to_owned(),
        },
        Message::Trenameat {
            olddirfid: ROOT,
            oldname: "notes.txt".to_owned(),
            newdirfid: 2,
            newname: "moved.txt".to_owned(),
        },
        Message::Tsetattr {
            fid: 1,
            // `P9_SETATTR_SIZE`, the one mask bit gate 2 already implements and
            // gate 4 still refuses.
            valid: 0x0000_0008,
            mode: 0,
            uid: 0,
            gid: 0,
            size: 0,
            atime_sec: 0,
            atime_nsec: 0,
            mtime_sec: 0,
            mtime_nsec: 0,
        },
        Message::Tsymlink {
            fid: ROOT,
            name: "alias".to_owned(),
            target: "notes.txt".to_owned(),
            gid: 0,
        },
        Message::Tlink {
            dfid: ROOT,
            fid: 1,
            name: "hard".to_owned(),
        },
    ];
    assert_eq!(mutations.len(), 10, "every mutating opcode in the profile");
    // The two refusals a mutation meets under a `read`+`list` grant, each taken
    // by a different layer and **both of them before the host**, which is what
    // makes every one of them `not_started`:
    //
    // * `EPERM` — gate 1's capability table, which is where a missing `write`
    //   or `delete` and an unadvertised `symlinks` or `hardLinks` feature are
    //   all decided.
    // * `EINVAL` — gate 3's session, for a fid used in a way its state forbids:
    //   a `Twrite` needs a fid open for writing, and this grant cannot open
    //   one, so the flag is rejected before any backend access.
    const REFUSALS: [FsErrorCode; 2] = [FsErrorCode::Eperm, FsErrorCode::Einval];

    for mutation in mutations {
        let fixture = Fixture::new();
        fixture.file("/notes.txt", b"synthetic");
        fixture.dir("/tree");
        let (mut provider, _authority) = fixture.provider(read_and_list());
        handshake(&mut provider, ROOT);
        let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
        let _ = exchange(&mut provider, twalk(3, ROOT, 2, &["tree"]));

        let described = format!("{:?}", mutation.message_type());
        let reply = one_frame(exchange(
            &mut provider,
            tunnel_fs_ninep::Frame::new(10, mutation),
        ));
        let code = error_code(&reply);
        assert!(
            REFUSALS.contains(&code),
            "{described} must be refused by one of the pinned codes, got {code:?}"
        );
        // Nothing was dispatched, so nothing is ambiguous: the whole of this
        // matrix is `not_started`, and the ledger says so rather than the
        // comment claiming it.
        let stats = provider.stats();
        assert_eq!(
            stats.mutations_dispatched, 0,
            "{described} must be refused before the host is touched"
        );
        assert_eq!(stats.mutations_applied, 0);
        assert_eq!(stats.mutation_unknown, 0);
        assert_eq!(stats.mutation_partial, 0);
        // `mutations_refused` is deliberately **not** asserted at one: most of
        // these are refused by gate 3's session inside `accept`, before the
        // request is queued at all, so they never reach the dispatcher's own
        // ledger. That is the refusal happening a layer earlier than this
        // counter, and saying so is better than moving the counter to make the
        // number look tidy.

        // And nothing happened to the export.
        assert_eq!(
            std::fs::read(fixture.inside("notes.txt")).expect("the file survives"),
            b"synthetic"
        );
        assert!(!fixture.inside("new.txt").exists());
        assert!(!fixture.inside("tree/sub").exists());
        assert!(!fixture.inside("alias").exists());
        assert!(!fixture.inside("hard").exists());
        assert!(!fixture.inside("tree/moved.txt").exists());
    }
}

#[test]
fn a_write_flag_on_an_open_is_refused_before_the_host_is_touched() {
    // The contract's own words: "Read-only policy denies every mutating opcode
    // and flag, including `O_TRUNC` on open". The flag word is what is refused
    // here, not the opcode — a `Tlopen` this grant would happily serve
    // read-only is refused the moment it carries a write or a truncate bit,
    // and `O_TRUNC` is refused **before** the host is asked, so the file cannot
    // have been emptied by a request that was then denied.
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));

    // Two pre-dispatch refusals, taken by two layers and both `not_started`:
    // gate 1's capability table answers `EPERM` for a write or truncate
    // primitive this grant does not hold, and gate 3's flag decoding answers
    // `ENOTSUP` for `O_TRUNC` on a *read-only* access mode, which is a
    // combination the profile refuses outright rather than a permission it
    // lacks. Both are listed because collapsing them would hide which layer
    // made the decision.
    for (flags, expected) in [
        (O_WRONLY, FsErrorCode::Eperm),
        (O_RDWR, FsErrorCode::Eperm),
        (O_WRONLY | O_TRUNC, FsErrorCode::Eperm),
        (O_RDONLY | O_TRUNC, FsErrorCode::Enotsup),
    ] {
        let reply = one_frame(exchange(&mut provider, tlopen(3, 1, flags)));
        assert_eq!(error_code(&reply), expected, "flags {flags:#o}");
    }
    assert_eq!(provider.stats().mutations_dispatched, 0);
    assert_eq!(
        std::fs::read(fixture.inside("notes.txt")).expect("the file survives"),
        b"synthetic"
    );
}

// --------------------------------------------------------------- flush race

#[test]
fn a_reply_whose_tag_was_flushed_is_dropped_and_never_completed() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));

    // The read is admitted and queued, but not performed.
    let admitted = provider.accept(&tread(9, 1, 0, 64));
    assert!(admitted.is_empty(), "a queued request answers nothing yet");
    assert!(provider.has_work());

    // The flush arrives first and is answered immediately.
    let flushed = provider.accept(&tflush(10, 9));
    assert!(matches!(one_frame(flushed).message, Message::Rflush));

    // Now the queue is stepped.  The read must produce **nothing**: its tag is
    // gone from the session, and handing its reply to `Session::complete` would
    // be indistinguishable from a peer inventing a tag, which is a 1002 close.
    let out = provider.step();
    assert!(
        out.is_empty(),
        "a flushed request's reply must be dropped, not answered: {out:?}"
    );
    assert_eq!(provider.stats().dropped_after_flush, 1);

    // The session survives, and the next request is answered normally.
    let reply = one_frame(exchange(&mut provider, tread(11, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"synthetic"),
        other => panic!("expected Rread, got {other:?}"),
    }
}

#[test]
fn a_tag_re_issued_and_flushed_again_drops_both_and_keeps_the_session() {
    // A number is not a request. The client here does nothing wrong: it flushes
    // tag 9, the `Rflush` releases the number, it re-issues on 9 — which 9P
    // permits as soon as the flush is answered — and flushes that too. Both
    // requests are legitimately flushed and both must be dropped.
    //
    // A mark held per tag *number* can only be spent once: the first entry
    // popped would clear it and the second would be performed, its reply handed
    // to `Session::complete` for a tag nothing is waiting on, closing a
    // well-behaved client's session with 1002. The mark is therefore on the
    // queue entry.
    //
    // Reachable from a real client precisely because the device admits every
    // frame already available before performing any of them, so both reads and
    // both flushes can be queued together.
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));

    // The original, queued and then flushed.
    assert!(provider.accept(&tread(9, 1, 0, 64)).is_empty());
    assert!(matches!(
        one_frame(provider.accept(&tflush(10, 9))).message,
        Message::Rflush
    ));
    // The number is free again, so the client re-issues on it — and flushes
    // that one too, while the original is still waiting to be performed.
    assert!(provider.accept(&tread(9, 1, 0, 64)).is_empty());
    assert!(matches!(
        one_frame(provider.accept(&tflush(11, 9))).message,
        Message::Rflush
    ));

    // Both are dropped, and neither closes the session.
    let first = provider.step();
    assert!(first.is_empty(), "the original must be dropped: {first:?}");
    let second = provider.step();
    assert!(
        second.is_empty(),
        "the re-issue must be dropped too: {second:?}"
    );
    assert_eq!(provider.stats().dropped_after_flush, 2);

    // The session survives and answers the next request normally.
    let reply = one_frame(exchange(&mut provider, tread(12, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"synthetic"),
        other => panic!("the session must survive, got {other:?}"),
    }
}

#[test]
fn a_flush_of_a_tag_that_was_already_answered_still_answers_rflush() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));

    // Answered first, then flushed: `Tflush` is cancellation, not rollback, and
    // a flush of a completed request is an ordinary `Rflush`.
    let _ = exchange(&mut provider, tgetattr(9, 1, GETATTR_BASIC));
    let reply = one_frame(exchange(&mut provider, tflush(10, 9)));
    assert!(matches!(reply.message, Message::Rflush));
    assert_eq!(provider.stats().dropped_after_flush, 0);

    // And the number is immediately re-usable.  Gate 3's session releases a
    // flushed tag when its `Rflush` is answered, so a dispatcher that had
    // marked this victim anyway would now silently drop the **new** request's
    // reply — which is the defect this assertion exists to catch.
    let reply = one_frame(exchange(&mut provider, tgetattr(9, 1, GETATTR_BASIC)));
    match reply.message {
        Message::Rgetattr(attributes) => assert_eq!(attributes.size, 9),
        other => panic!("a re-issued tag must be answered, got {other:?}"),
    }
    assert_eq!(provider.stats().dropped_after_flush, 0);
}

// -------------------------------------------------- the fid-generation rule

#[test]
fn a_descriptor_is_keyed_by_fid_generation_and_never_by_fid_number() {
    let fixture = Fixture::new();
    fixture.file("/first.txt", b"first-body");
    fixture.file("/second.txt", b"second-body-which-is-longer");

    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);

    // Bind fid 1 to the first file and open it.
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["first.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));
    let reply = one_frame(exchange(&mut provider, tread(4, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"first-body"),
        other => panic!("expected Rread, got {other:?}"),
    }

    // Clunk it and walk the **same number** to a different file.
    let _ = exchange(&mut provider, tclunk(5, 1));
    let _ = exchange(&mut provider, twalk(6, ROOT, 1, &["second.txt"]));

    // The number now carries a new binding, and the descriptor the first one
    // resolved must not answer for it: the fid is not open, so a read is
    // refused rather than answered from the previous file's bytes.
    let reply = one_frame(exchange(&mut provider, tread(7, 1, 0, 64)));
    assert_eq!(
        error_code(&reply),
        FsErrorCode::Einval,
        "the previous binding's descriptor must not answer for a re-bound number"
    );

    // Opening the new binding reads the new file.
    let _ = exchange(&mut provider, tlopen(8, 1, O_RDONLY));
    let reply = one_frame(exchange(&mut provider, tread(9, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"second-body-which-is-longer"),
        other => panic!("expected Rread, got {other:?}"),
    }
}

#[test]
fn a_refused_remove_releases_its_fid_and_the_descriptor_with_it() {
    // 9P releases a fid on **either** answer to `Tclunk` and `Tremove`, so a
    // refused `Tremove` frees the number through the session's error path — and
    // this gate's dispatcher has to release what it holds for that fid there
    // too, or a refused `Tremove` on an open fid would leak a descriptor for
    // the life of the session.
    //
    // It is also the closest a client can get to the descriptor cache's
    // staleness guards, and it does not reach them: gate 3's session refuses
    // the read below because the re-bound fid is not open at its current
    // binding, before this dispatcher is asked anything. That is recorded on
    // `Provider::cached` rather than hidden, and it is why those guards are
    // measured as defence in depth instead of counted as load-bearing.
    //
    // The refusal is the **host's**, not the grant's: a full grant removing a
    // directory that still has a child is `ENOTEMPTY`. That matters for gate 5,
    // because a grant refusal is taken by gate 3's session inside `accept` and
    // never reaches the queue at all, where 9P's release-on-either-answer rule
    // is about a request that *was* admitted and then failed. The host refusal
    // is the only way to reach that path from a client.
    let fixture = Fixture::new();
    fixture.dir("/first");
    fixture.file("/first/child.txt", b"first-body");
    fixture.file("/second.txt", b"second-body-which-is-longer");

    let (mut provider, _authority) = fixture.provider(full_grant());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["first"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY | O_DIRECTORY));
    let reply = one_frame(exchange(&mut provider, treaddir(4, 1, 0, 4_096)));
    match reply.message {
        Message::Rreaddir { data } => {
            assert_eq!(parse_entries(&data).expect("block").len(), 1);
        }
        other => panic!("expected Rreaddir, got {other:?}"),
    }

    // Dispatched and refused by the host, and the fid is released anyway.
    let reply = one_frame(exchange(
        &mut provider,
        tunnel_fs_ninep::Frame::new(5, Message::Tremove { fid: 1 }),
    ));
    assert_eq!(error_code(&reply), FsErrorCode::Enotempty);
    assert!(
        fixture.inside("first/child.txt").exists(),
        "a refused remove removes nothing"
    );
    // Dispatched, and reported `failed` rather than `not_started`: the host was
    // asked and answered that it changed nothing, which gate 4 had no way to
    // say.
    let stats = provider.stats();
    assert_eq!(stats.mutations_dispatched, 1);
    assert_eq!(stats.mutation_failed, 1);
    assert_eq!(stats.mutations_applied, 0);
    assert_eq!(stats.mutations_refused, 0);

    // The number is free, so the client may bind it to a different file.
    let reply = one_frame(exchange(&mut provider, twalk(6, ROOT, 1, &["second.txt"])));
    assert!(matches!(reply.message, Message::Rwalk { .. }));

    // The new binding is not open. A read must be refused rather than answered
    // from the descriptor the previous binding left behind.
    let reply = one_frame(exchange(&mut provider, tread(7, 1, 0, 64)));
    assert_eq!(
        error_code(&reply),
        FsErrorCode::Einval,
        "the previous binding's descriptor must not answer for a re-bound number"
    );

    let _ = exchange(&mut provider, tlopen(8, 1, O_RDONLY));
    let reply = one_frame(exchange(&mut provider, tread(9, 1, 0, 64)));
    match reply.message {
        Message::Rread { data } => assert_eq!(data, b"second-body-which-is-longer"),
        other => panic!("expected Rread, got {other:?}"),
    }
}

// ------------------------------------------- the recheck after a queue wait

#[test]
fn a_grant_revision_that_moves_under_a_queued_request_closes_the_session() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
    let _ = exchange(&mut provider, tlopen(3, 1, O_RDONLY));

    // Queued under the admitted revision...
    let admitted = provider.accept(&tread(4, 1, 0, 64));
    assert!(admitted.is_empty());
    // ...and the revision moves while it waits.
    authority.advance_revision();

    let closed = one_close(provider.step());
    assert_eq!(closed, SessionErrorCode::CapabilitiesChanged);
    assert_eq!(closed.close_code(), Some(1008));
    assert_eq!(provider.stats().revision_closures, 1);
}

#[test]
fn an_expired_authorization_snapshot_closes_the_session_before_the_host_is_touched() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));

    let admitted = provider.accept(&tlopen(3, 1, O_RDONLY));
    assert!(admitted.is_empty());
    authority.expire();

    let closed = one_close(provider.step());
    assert_eq!(closed, SessionErrorCode::AuthExpired);
    assert_eq!(provider.stats().freshness_closures, 1);
}

#[test]
fn a_grant_narrowed_inside_one_revision_refuses_the_queued_request() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));

    let admitted = provider.accept(&tlopen(3, 1, O_RDONLY));
    assert!(admitted.is_empty());
    // The revision did not move, so the session survives; the request does not.
    authority.narrow(list_only());

    let reply = one_frame(provider.step());
    assert_eq!(error_code(&reply), FsErrorCode::Eperm);
    assert_eq!(provider.stats().grant_refusals, 1);
    assert_eq!(provider.stats().revision_closures, 0);
}

#[test]
fn the_recheck_happens_once_per_queued_request() {
    let fixture = Fixture::new();
    fixture.file("/notes.txt", b"synthetic");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let before = provider.stats().grant_rechecks;
    let _ = exchange(&mut provider, twalk(2, ROOT, 1, &["notes.txt"]));
    let _ = exchange(&mut provider, tgetattr(3, 1, GETATTR_BASIC));
    assert_eq!(provider.stats().grant_rechecks, before + 2);
}

// ---------------------------------------------------------------- renderings

#[test]
fn no_provider_rendering_carries_a_path_or_a_name() {
    let fixture = Fixture::new();
    fixture.file("/a-very-distinctive-name.txt", b"synthetic-secret-body");
    let (mut provider, _authority) = fixture.provider(read_and_list());
    handshake(&mut provider, ROOT);
    let _ = exchange(
        &mut provider,
        twalk(2, ROOT, 1, &["a-very-distinctive-name.txt"]),
    );
    let rendered = format!("{:?}", provider.stats());
    assert!(!rendered.contains("distinctive"), "{rendered}");
    assert!(!rendered.contains("secret"), "{rendered}");
}

// ------------------------------------------------------------------ helpers

/// A 64-bit FNV-1a checksum, so a read can be compared without holding two
/// copies of a large body in an assertion message.
fn fnv1a(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325_u64;
    for byte in bytes {
        hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}
