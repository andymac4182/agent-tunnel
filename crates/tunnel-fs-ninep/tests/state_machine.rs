//! The session state machine: lifecycle order, repeats, tag and fid quotas,
//! flush, flag decoding and grant enforcement.

mod common;

use common::{
    all_features, attach, attached_session, full_grant, open, session, version_handshake, walk,
};
use tunnel_fs_core::{
    Capability, CapabilitySet, Feature, FeatureSet, FsErrorCode, Limits, PathRule, Primitive,
    SessionErrorCode,
};
use tunnel_fs_ninep::{
    AT_REMOVEDIR, Answer, DIALECT, Frame, GETATTR_BASIC, Message, NOFID, NONUNAME, NOTAG, Phase,
    Qid, QidKind, RequestPaths, Session, SessionError,
};

fn tversion(msize: u32) -> Frame {
    Frame::new(
        NOTAG,
        Message::Tversion {
            msize,
            version: DIALECT.to_owned(),
        },
    )
}

fn tattach(fid: u32, tag: u16) -> Frame {
    Frame::new(
        tag,
        Message::Tattach {
            fid,
            afid: NOFID,
            uname: String::new(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
    )
}

fn twalk(tag: u16, fid: u32, newfid: u32, names: &[&str]) -> Frame {
    Frame::new(
        tag,
        Message::Twalk {
            fid,
            newfid,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        },
    )
}

// ------------------------------------------------------------- lifecycle

#[test]
fn the_happy_path_walks_opens_reads_and_clunks() {
    let mut session = session();
    assert_eq!(session.phase(), Phase::AwaitingVersion);
    version_handshake(&mut session);
    assert_eq!(session.phase(), Phase::Versioned);
    assert_eq!(session.msize(), common::FIXTURE_MSIZE);

    attach(&mut session, 0, 1);
    assert_eq!(session.phase(), Phase::Attached);
    assert_eq!(session.live_fids(), 1);
    assert_eq!(session.fid(0).unwrap().path().as_str(), "/");

    walk(
        &mut session,
        2,
        0,
        1,
        &["projects", "notes.txt"],
        QidKind::File,
    );
    assert_eq!(session.live_fids(), 2);
    assert_eq!(
        session.fid(1).unwrap().path().as_str(),
        "/projects/notes.txt"
    );
    assert!(session.fid(1).unwrap().open().is_none());

    open(&mut session, 3, 1, 0, QidKind::File);
    let mode = session.fid(1).unwrap().open().expect("open");
    assert!(mode.read && !mode.write && !mode.directory);

    session
        .request(&Frame::new(
            4,
            Message::Tread {
                fid: 1,
                offset: 0,
                count: 1_024,
            },
        ))
        .expect("Tread admitted");
    session
        .complete(&Frame::new(
            4,
            Message::Rread {
                data: vec![1, 2, 3],
            },
        ))
        .expect("Rread");

    session
        .request(&Frame::new(5, Message::Tclunk { fid: 1 }))
        .expect("Tclunk admitted");
    session
        .complete(&Frame::new(5, Message::Rclunk))
        .expect("Rclunk");
    assert_eq!(session.live_fids(), 1);
    assert_eq!(session.outstanding_tags(), 0);
}

#[test]
fn nothing_but_tversion_is_accepted_before_the_handshake() {
    for frame in [
        tattach(0, 1),
        twalk(1, 0, 1, &["x"]),
        Frame::new(1, Message::Tclunk { fid: 0 }),
        Frame::new(1, Message::Tflush { oldtag: 0 }),
    ] {
        let mut session = session();
        assert_eq!(
            session.request(&frame),
            Err(SessionError::BeforeVersion),
            "{}",
            frame.message_type().as_str()
        );
    }
}

#[test]
fn ordinary_requests_are_refused_between_version_and_attach() {
    let mut session = session();
    version_handshake(&mut session);
    for frame in [
        twalk(1, 0, 1, &["x"]),
        Frame::new(1, Message::Tclunk { fid: 0 }),
        Frame::new(
            1,
            Message::Tgetattr {
                fid: 0,
                request_mask: GETATTR_BASIC,
            },
        ),
    ] {
        assert_eq!(
            session.request(&frame),
            Err(SessionError::BeforeAttach),
            "{}",
            frame.message_type().as_str()
        );
    }
    // A flush is legal here: it may target the attach itself.
    assert!(
        session
            .request(&Frame::new(9, Message::Tflush { oldtag: 1 }))
            .is_ok()
    );
}

#[test]
fn a_second_tversion_terminates_the_session_in_every_phase() {
    for phase in [Phase::Versioned, Phase::Attached] {
        let mut session = session();
        version_handshake(&mut session);
        if phase == Phase::Attached {
            attach(&mut session, 0, 1);
        }
        let error = session.request(&tversion(4_096)).unwrap_err();
        assert_eq!(error, SessionError::RepeatedVersion);
        assert_eq!(
            error.answer(),
            Answer::Close(SessionErrorCode::ProtocolViolation),
            "a repeated Tversion terminates rather than resetting hidden state"
        );
    }
}

#[test]
fn a_second_tattach_is_refused_because_a_session_has_one_root() {
    let mut session = attached_session();
    let error = session.request(&tattach(5, 9)).unwrap_err();
    assert_eq!(error, SessionError::RepeatedAttach);
    assert!(error.is_fatal());
}

#[test]
fn tattach_refuses_every_field_that_could_choose_an_identity_or_export() {
    let cases = [
        Message::Tattach {
            fid: 0,
            afid: 3,
            uname: String::new(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: 0,
            afid: NOFID,
            uname: "root".to_owned(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: 0,
            afid: NOFID,
            uname: String::new(),
            aname: "other-export".to_owned(),
            n_uname: NONUNAME,
        },
        Message::Tattach {
            fid: 0,
            afid: NOFID,
            uname: String::new(),
            aname: String::new(),
            n_uname: 0,
        },
    ];
    for message in cases {
        let mut session = session();
        version_handshake(&mut session);
        assert_eq!(
            session.request(&Frame::new(1, message)),
            Err(SessionError::AttachFieldNotPermitted)
        );
        assert_eq!(session.live_fids(), 0, "a refused attach reserves nothing");
    }
}

#[test]
fn a_forged_attach_cannot_reach_a_path_outside_the_root() {
    // The root fid is always the virtual root; `aname` cannot choose another.
    let session = attached_session();
    assert_eq!(session.fid(0).unwrap().path().as_str(), "/");
    assert!(session.fid(0).unwrap().is_directory());
}

#[test]
fn the_version_reply_must_carry_the_negotiated_msize() {
    let mut session = session();
    session.request(&tversion(70_000)).expect("Tversion");
    let reply = session.version_reply().expect("pending");
    let Message::Rversion { msize, .. } = reply.message else {
        panic!("wrong reply");
    };
    assert_eq!(msize, 65_536, "reduced to the ceiling");
    assert_eq!(
        session.complete(&Frame::new(
            NOTAG,
            Message::Rversion {
                msize: 70_000,
                version: DIALECT.to_owned(),
            }
        )),
        Err(SessionError::MalformedReply),
        "a reply may not restore what negotiation reduced"
    );
}

#[test]
fn a_closed_session_accepts_nothing_and_forgets_its_fids() {
    let mut session = attached_session();
    session.close();
    assert_eq!(session.phase(), Phase::Closed);
    assert_eq!(session.live_fids(), 0);
    assert!(session.fid(0).is_none());
    assert_eq!(
        session.request(&twalk(9, 0, 1, &["x"])),
        Err(SessionError::Closed)
    );
}

// ------------------------------------------------------------------- tags

#[test]
fn a_tag_already_outstanding_is_refused_and_freed_by_its_reply() {
    let mut session = attached_session();
    session.request(&twalk(7, 0, 1, &["a"])).expect("first");
    assert_eq!(
        session.request(&twalk(7, 0, 2, &["b"])),
        Err(SessionError::TagInUse)
    );
    session
        .complete(&Frame::new(
            7,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::Directory, 1)],
            },
        ))
        .expect("Rwalk");
    assert_eq!(session.outstanding_tags(), 0);
    // Reusable once the reply has arrived, and not before.
    assert!(session.request(&twalk(7, 0, 2, &["b"])).is_ok());
}

#[test]
fn the_tag_quota_is_exact_at_its_limit_and_closes_one_beyond() {
    let limit = Limits::PROFILE_DEFAULT.max_inflight_requests();
    let mut session = attached_session();
    for tag in 0..u16::try_from(limit).unwrap() {
        session
            .request(&Frame::new(
                tag,
                Message::Tgetattr {
                    fid: 0,
                    request_mask: GETATTR_BASIC,
                },
            ))
            .unwrap_or_else(|error| panic!("tag {tag}: {error}"));
    }
    assert_eq!(session.outstanding_tags(), usize::try_from(limit).unwrap());

    let over = session
        .request(&Frame::new(
            u16::try_from(limit).unwrap(),
            Message::Tgetattr {
                fid: 0,
                request_mask: GETATTR_BASIC,
            },
        ))
        .unwrap_err();
    assert_eq!(over, SessionError::TagQuotaExhausted);
    assert_eq!(
        over.answer(),
        Answer::Close(SessionErrorCode::ResourceExhausted),
        "a tag beyond the quota has no correlatable Rlerror, so the session closes"
    );
    assert_eq!(over.answer().close_code(), Some(1013));
}

#[test]
fn a_reply_on_an_unknown_tag_is_refused() {
    let mut session = attached_session();
    assert_eq!(
        session.complete(&Frame::new(44, Message::Rclunk)),
        Err(SessionError::TagNotInUse)
    );
    assert_eq!(session.fail(44), Err(SessionError::TagNotInUse));
}

#[test]
fn a_reply_of_the_wrong_type_is_refused() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    assert_eq!(
        session.complete(&Frame::new(3, Message::Rclunk)),
        Err(SessionError::UnexpectedReply)
    );
}

#[test]
fn a_second_reply_on_the_same_tag_is_refused() {
    let mut session = attached_session();
    session
        .request(&Frame::new(3, Message::Tclunk { fid: 0 }))
        .expect("Tclunk");
    session
        .complete(&Frame::new(3, Message::Rclunk))
        .expect("first");
    assert_eq!(
        session.complete(&Frame::new(3, Message::Rclunk)),
        Err(SessionError::TagNotInUse)
    );
}

// ----------------------------------------------------------------- flush

#[test]
fn a_flushed_tag_stays_reserved_until_the_flush_is_answered() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    session
        .request(&Frame::new(4, Message::Tflush { oldtag: 3 }))
        .expect("Tflush");

    // The original reply arrives before the Rflush.  It is honoured — the walk
    // binds — but tag 3 is not reusable yet.
    session
        .complete(&Frame::new(
            3,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::Directory, 1)],
            },
        ))
        .expect("original reply honoured");
    assert!(session.fid(1).is_some(), "the original reply took effect");
    assert!(session.has_tag(3), "tag 3 is still reserved");
    assert_eq!(
        session
            .request(&Frame::new(3, Message::Tclunk { fid: 1 }))
            .unwrap_err(),
        SessionError::TagReservedByFlush
    );

    session
        .complete(&Frame::new(4, Message::Rflush))
        .expect("Rflush");
    assert!(!session.has_tag(3), "the Rflush released the flushed tag");
    assert!(
        session
            .request(&Frame::new(3, Message::Tclunk { fid: 1 }))
            .is_ok()
    );
}

#[test]
fn an_rflush_releases_a_tag_whose_original_reply_never_arrived() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    session
        .request(&Frame::new(4, Message::Tflush { oldtag: 3 }))
        .expect("Tflush");
    session
        .complete(&Frame::new(4, Message::Rflush))
        .expect("Rflush");
    assert_eq!(session.outstanding_tags(), 0);
    assert!(
        session.fid(1).is_none(),
        "a flushed walk that never replied binds nothing"
    );
    // `fid(1).is_none()` is also true of a fid that is merely *reserved*, so it
    // cannot tell a released reservation from a stranded one.  `live_fids()`
    // counts reservations, which is what the quota counts.
    assert_eq!(
        session.live_fids(),
        1,
        "the flush released the walk's reservation, not only its tag"
    );
}

#[test]
fn an_rflush_releases_the_flushed_requests_reservation_not_only_its_tag() {
    // A reservation outlives only an outstanding request.  If the `Rflush`
    // released the tag but not the reservation, the target fid would be
    // stranded for the life of the session: no reply can ever bind it, and no
    // `Tclunk` can release it because it is not bound.  A client that flushes
    // walks would exhaust its own fid quota with nothing to clunk.
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    assert_eq!(session.live_fids(), 2, "the walk reserved fid 1");
    session
        .request(&Frame::new(4, Message::Tflush { oldtag: 3 }))
        .expect("Tflush");
    session
        .complete(&Frame::new(4, Message::Rflush))
        .expect("Rflush");
    assert_eq!(session.outstanding_tags(), 0);
    assert_eq!(session.live_fids(), 1, "fid 1 is free again");
    // ...and provably free: it can be walked to.
    walk(&mut session, 5, 0, 1, &["a"], QidKind::Directory);
    assert_eq!(session.fid(1).unwrap().path().as_str(), "/a");
}

#[test]
fn a_flushed_attach_leaves_the_session_able_to_attach_again() {
    let mut session = session();
    version_handshake(&mut session);
    session.request(&tattach(0, 1)).expect("Tattach");
    assert_eq!(session.live_fids(), 1, "the attach reserved fid 0");
    session
        .request(&Frame::new(2, Message::Tflush { oldtag: 1 }))
        .expect("Tflush");
    session
        .complete(&Frame::new(2, Message::Rflush))
        .expect("Rflush");
    assert_eq!(session.phase(), Phase::Versioned);
    assert_eq!(session.live_fids(), 0, "the root fid is free again");
    // A second attempt on the same fid is admitted, where a stranded
    // reservation would have answered FidInUse for the life of the session.
    attach(&mut session, 0, 3);
    assert_eq!(session.phase(), Phase::Attached);
    assert_eq!(session.fid(0).unwrap().path().as_str(), "/");
}

#[test]
fn a_late_rattach_after_its_flush_binds_nothing() {
    let mut session = session();
    version_handshake(&mut session);
    session.request(&tattach(0, 1)).expect("Tattach");
    session
        .request(&Frame::new(2, Message::Tflush { oldtag: 1 }))
        .expect("Tflush");
    session
        .complete(&Frame::new(2, Message::Rflush))
        .expect("Rflush");
    // The tag is gone, so a dispatcher that fed this reply here would get a
    // 1002 close — which is why dropping late replies is gate 4's obligation.
    assert_eq!(
        session.complete(&Frame::new(
            1,
            Message::Rattach {
                qid: Qid::new(QidKind::Directory, 1),
            }
        )),
        Err(SessionError::TagNotInUse)
    );
    assert_eq!(session.phase(), Phase::Versioned);
    assert_eq!(session.live_fids(), 0);
}

#[test]
fn flushing_a_tag_that_is_not_outstanding_is_a_no_op_that_still_replies() {
    let mut session = attached_session();
    session
        .request(&Frame::new(4, Message::Tflush { oldtag: 99 }))
        .expect("a flush of an unknown tag is answered, not refused");
    session
        .complete(&Frame::new(4, Message::Rflush))
        .expect("Rflush");
    assert_eq!(session.outstanding_tags(), 0);
}

#[test]
fn multiple_flushes_of_one_tag_are_accepted() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    session
        .request(&Frame::new(4, Message::Tflush { oldtag: 3 }))
        .expect("first flush");
    session
        .request(&Frame::new(5, Message::Tflush { oldtag: 3 }))
        .expect("second flush");
    session
        .complete(&Frame::new(5, Message::Rflush))
        .expect("Rflush 5");
    session
        .complete(&Frame::new(4, Message::Rflush))
        .expect("Rflush 4");
    assert_eq!(session.outstanding_tags(), 0);
}

// ------------------------------------------------------------------ fids

#[test]
fn an_unknown_fid_is_an_rlerror_not_a_close() {
    let mut session = attached_session();
    let error = session.request(&twalk(3, 77, 1, &["a"])).unwrap_err();
    assert_eq!(error, SessionError::UnknownFid);
    assert_eq!(
        error.answer(),
        Answer::Rlerror(tunnel_fs_core::FsError::refused(FsErrorCode::Einval))
    );
    assert!(!error.is_fatal());
}

#[test]
fn nofid_is_never_a_usable_fid() {
    let mut session = attached_session();
    assert_eq!(
        session.request(&twalk(3, NOFID, 1, &["a"])),
        Err(SessionError::UnknownFid)
    );
    assert_eq!(
        session.request(&twalk(3, 0, NOFID, &["a"])),
        Err(SessionError::UnknownFid)
    );
}

#[test]
fn a_newfid_already_in_use_is_refused_including_while_a_walk_is_in_flight() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["a"], QidKind::Directory);
    assert_eq!(
        session.request(&twalk(3, 0, 1, &["b"])),
        Err(SessionError::FidInUse),
        "a bound fid"
    );
    session.request(&twalk(4, 0, 2, &["c"])).expect("in flight");
    assert_eq!(
        session.request(&twalk(5, 0, 2, &["d"])),
        Err(SessionError::FidInUse),
        "a fid reserved by a walk that has not replied"
    );
}

#[test]
fn the_fid_quota_is_exact_at_its_limit_and_refuses_one_beyond() {
    let limit = usize::try_from(Limits::PROFILE_DEFAULT.max_fids()).unwrap();
    let mut session = attached_session();
    // The root fid is already one of them.
    for index in 1..limit {
        let tag = u16::try_from(index % 60).unwrap();
        let fid = u32::try_from(index).unwrap();
        session
            .request(&twalk(tag, 0, fid, &["d"]))
            .unwrap_or_else(|error| panic!("fid {fid}: {error}"));
        session
            .complete(&Frame::new(
                tag,
                Message::Rwalk {
                    qids: vec![Qid::new(QidKind::Directory, u64::from(fid))],
                },
            ))
            .expect("Rwalk");
    }
    assert_eq!(session.live_fids(), limit);

    let error = session
        .request(&twalk(61, 0, u32::try_from(limit).unwrap(), &["d"]))
        .unwrap_err();
    assert_eq!(error, SessionError::FidQuotaExhausted);
    assert_eq!(
        error.answer(),
        Answer::Rlerror(tunnel_fs_core::FsError::Limit(
            tunnel_fs_core::LimitField::MaxFids
        )),
        "the fid quota is recoverable by clunking, so it is an Rlerror"
    );
    assert!(!error.is_fatal());
}

#[test]
fn a_partial_walk_binds_nothing_and_releases_its_reservation() {
    let mut session = attached_session();
    session
        .request(&twalk(3, 0, 1, &["a", "b", "c"]))
        .expect("Twalk");
    assert_eq!(session.live_fids(), 2, "the reservation counts");
    session
        .complete(&Frame::new(
            3,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::Directory, 1)],
            },
        ))
        .expect("a partial Rwalk");
    assert!(session.fid(1).is_none(), "a partial walk binds nothing");
    assert_eq!(session.live_fids(), 1);
}

#[test]
fn an_rwalk_longer_than_its_twalk_is_refused() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    assert_eq!(
        session.complete(&Frame::new(
            3,
            Message::Rwalk {
                qids: vec![
                    Qid::new(QidKind::Directory, 1),
                    Qid::new(QidKind::Directory, 2)
                ],
            }
        )),
        Err(SessionError::MalformedReply)
    );
}

#[test]
fn a_zero_element_walk_clones_the_fid_at_the_same_path() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &[])).expect("Twalk");
    session
        .complete(&Frame::new(3, Message::Rwalk { qids: Vec::new() }))
        .expect("Rwalk");
    assert_eq!(session.fid(1).unwrap().path().as_str(), "/");
    assert_eq!(session.fid(1).unwrap().qid(), session.fid(0).unwrap().qid());
}

#[test]
fn a_walk_in_place_moves_the_fid_without_spending_quota() {
    let mut session = attached_session();
    let before = session.live_fids();
    session.request(&twalk(3, 0, 0, &["a"])).expect("Twalk");
    assert_eq!(session.live_fids(), before, "no new fid is reserved");
    session
        .complete(&Frame::new(
            3,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::Directory, 9)],
            },
        ))
        .expect("Rwalk");
    assert_eq!(session.fid(0).unwrap().path().as_str(), "/a");
    assert_eq!(session.live_fids(), before);
}

#[test]
fn a_failed_walk_releases_its_reservation() {
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    assert_eq!(session.live_fids(), 2);
    session.fail(3).expect("Rlerror");
    assert_eq!(session.live_fids(), 1);
    assert!(session.fid(1).is_none());
    // The fid is free again.
    assert!(session.request(&twalk(4, 0, 1, &["b"])).is_ok());
}

#[test]
fn a_walk_from_an_open_fid_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(&mut session, 3, 1, 0, QidKind::File);
    assert_eq!(
        session.request(&twalk(4, 1, 2, &["x"])),
        Err(SessionError::FidIsOpen)
    );
}

#[test]
fn a_fid_cannot_be_opened_twice() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(&mut session, 3, 1, 0, QidKind::File);
    assert_eq!(
        session.request(&Frame::new(4, Message::Tlopen { fid: 1, flags: 0 })),
        Err(SessionError::FidIsOpen)
    );
}

#[test]
fn reading_or_writing_an_unopened_fid_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    assert_eq!(
        session.request(&Frame::new(
            3,
            Message::Tread {
                fid: 1,
                offset: 0,
                count: 16
            }
        )),
        Err(SessionError::FidNotOpen)
    );
    assert_eq!(
        session.request(&Frame::new(
            3,
            Message::Twrite {
                fid: 1,
                offset: 0,
                data: vec![1]
            }
        )),
        Err(SessionError::FidNotOpen)
    );
}

#[test]
fn a_read_only_open_cannot_be_written_and_a_write_only_open_cannot_be_read() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(&mut session, 3, 1, 0, QidKind::File);
    assert_eq!(
        session.request(&Frame::new(
            4,
            Message::Twrite {
                fid: 1,
                offset: 0,
                data: vec![1]
            }
        )),
        Err(SessionError::FidNotOpen)
    );

    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(
        &mut session,
        3,
        1,
        tunnel_fs_ninep::flags::O_WRONLY,
        QidKind::File,
    );
    assert_eq!(
        session.request(&Frame::new(
            4,
            Message::Tread {
                fid: 1,
                offset: 0,
                count: 8
            }
        )),
        Err(SessionError::FidNotOpen)
    );
}

#[test]
fn a_directory_is_enumerated_and_never_byte_read() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["d"], QidKind::Directory);
    open(
        &mut session,
        3,
        1,
        tunnel_fs_ninep::flags::O_DIRECTORY,
        QidKind::Directory,
    );
    assert!(session.fid(1).unwrap().open().unwrap().directory);
    assert_eq!(
        session.request(&Frame::new(
            4,
            Message::Tread {
                fid: 1,
                offset: 0,
                count: 8
            }
        )),
        Err(SessionError::FidWrongKind)
    );
    assert!(
        session
            .request(&Frame::new(
                5,
                Message::Treaddir {
                    fid: 1,
                    offset: 0,
                    count: 1_024
                }
            ))
            .is_ok()
    );
}

#[test]
fn treaddir_on_a_file_fid_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(&mut session, 3, 1, 0, QidKind::File);
    assert_eq!(
        session.request(&Frame::new(
            4,
            Message::Treaddir {
                fid: 1,
                offset: 0,
                count: 16
            }
        )),
        Err(SessionError::FidWrongKind)
    );
}

#[test]
fn clunk_and_remove_release_their_fid_on_either_answer() {
    for succeed in [true, false] {
        let mut session = attached_session();
        walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
        session
            .request(&Frame::new(3, Message::Tclunk { fid: 1 }))
            .expect("Tclunk");
        if succeed {
            session.complete(&Frame::new(3, Message::Rclunk)).unwrap();
        } else {
            session.fail(3).unwrap();
        }
        assert!(
            session.fid(1).is_none(),
            "a clunk releases its fid whether or not it succeeded"
        );

        let mut session = attached_session();
        walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
        session
            .request(&Frame::new(3, Message::Tremove { fid: 1 }))
            .expect("Tremove");
        if succeed {
            session.complete(&Frame::new(3, Message::Rremove)).unwrap();
        } else {
            session.fail(3).unwrap();
        }
        assert!(session.fid(1).is_none());
    }
}

#[test]
fn a_clunked_fid_is_unknown_afterwards() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    session
        .request(&Frame::new(3, Message::Tclunk { fid: 1 }))
        .expect("Tclunk");
    session.complete(&Frame::new(3, Message::Rclunk)).unwrap();
    assert_eq!(
        session.request(&Frame::new(4, Message::Tclunk { fid: 1 })),
        Err(SessionError::UnknownFid)
    );
}

#[test]
fn tlcreate_rebinds_the_parent_fid_to_the_created_child() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["dir"], QidKind::Directory);
    let accepted = session
        .request(&Frame::new(
            3,
            Message::Tlcreate {
                fid: 1,
                name: "new.txt".to_owned(),
                flags: tunnel_fs_ninep::flags::O_WRONLY,
                mode: 0o644,
                gid: 0,
            },
        ))
        .expect("Tlcreate");
    assert_eq!(
        accepted.paths,
        RequestPaths::Child {
            parent: session.fid(1).unwrap().path().clone(),
            child: tunnel_fs_core::VirtualPath::parse(
                "/dir/new.txt",
                Limits::PROFILE_DEFAULT.path_bounds()
            )
            .unwrap(),
        }
    );
    assert_eq!(session.live_fids(), 2, "no new fid is allocated");
    session
        .complete(&Frame::new(
            3,
            Message::Rlcreate {
                qid: Qid::new(QidKind::File, 5),
                iounit: 0,
            },
        ))
        .expect("Rlcreate");
    assert_eq!(session.fid(1).unwrap().path().as_str(), "/dir/new.txt");
    assert!(session.fid(1).unwrap().open().unwrap().write);
}

#[test]
fn tlcreate_on_a_file_fid_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    assert_eq!(
        session.request(&Frame::new(
            3,
            Message::Tlcreate {
                fid: 1,
                name: "x".to_owned(),
                flags: tunnel_fs_ninep::flags::O_WRONLY,
                mode: 0o644,
                gid: 0,
            }
        )),
        Err(SessionError::FidWrongKind)
    );
}

// ------------------------------------------------------------------ paths

#[test]
fn a_walk_name_the_namespace_refuses_is_refused_by_its_own_rule() {
    let cases = [
        ("..", PathRule::DotDotComponent),
        (".", PathRule::DotComponent),
        ("", PathRule::EmptyComponent),
        ("a/b", PathRule::Separator),
        ("a\\b", PathRule::Backslash),
        ("a:b", PathRule::Colon),
        ("CON.txt", PathRule::WindowsDeviceName),
        ("trailing ", PathRule::TrailingSpaceOrDot),
        ("trailing.", PathRule::TrailingSpaceOrDot),
    ];
    for (name, rule) in cases {
        let mut session = attached_session();
        let error = session.request(&twalk(3, 0, 1, &[name])).unwrap_err();
        assert_eq!(error, SessionError::Path(rule), "name {name:?}");
        assert_eq!(
            error.answer(),
            Answer::Rlerror(tunnel_fs_core::FsError::Path(rule))
        );
        assert_eq!(session.live_fids(), 1, "a refused walk reserves nothing");
    }
}

#[test]
fn a_create_or_rename_name_is_validated_the_same_way() {
    let mut session = attached_session();
    for message in [
        Message::Tmkdir {
            dfid: 0,
            name: "..".to_owned(),
            mode: 0o755,
            gid: 0,
        },
        Message::Tunlinkat {
            dirfid: 0,
            name: "..".to_owned(),
            flags: 0,
        },
        Message::Trenameat {
            olddirfid: 0,
            oldname: "ok".to_owned(),
            newdirfid: 0,
            newname: "..".to_owned(),
        },
    ] {
        assert_eq!(
            session.request(&Frame::new(3, message)),
            Err(SessionError::Path(PathRule::DotDotComponent))
        );
    }
}

#[test]
fn a_walk_past_the_path_component_limit_is_refused() {
    let limit = usize::try_from(Limits::PROFILE_DEFAULT.max_path_components()).unwrap();
    let mut session = attached_session();
    // Walk in steps of MAXWELEM until one step would exceed the limit.
    let mut depth = 0usize;
    let mut fid = 0u32;
    let mut tag = 0u16;
    while depth + tunnel_fs_ninep::MAX_WALK_NAMES <= limit {
        let names: Vec<&str> = vec!["d"; tunnel_fs_ninep::MAX_WALK_NAMES];
        let next = fid + 1;
        walk(&mut session, tag, fid, next, &names, QidKind::Directory);
        depth += tunnel_fs_ninep::MAX_WALK_NAMES;
        fid = next;
        tag = tag.wrapping_add(1);
    }
    let remaining = limit - depth;
    let names: Vec<&str> = vec!["d"; remaining];
    walk(&mut session, 200, fid, fid + 1, &names, QidKind::Directory);
    assert_eq!(
        session.fid(fid + 1).unwrap().path().component_count(),
        limit
    );

    // One component beyond the limit.
    assert_eq!(
        session.request(&twalk(201, fid + 1, fid + 2, &["d"])),
        Err(SessionError::Path(PathRule::TooManyComponents))
    );
}

// ------------------------------------------------------------------ flags

#[test]
fn tlopen_flags_outside_the_profile_are_refused() {
    use tunnel_fs_ninep::flags::{O_APPEND, O_CREAT, O_DIRECTORY, O_EXCL, O_RDWR, O_TRUNC};

    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    for flags in [
        O_CREAT,              // creation is Tlcreate
        O_EXCL,               // exclusive create without a create
        0o3,                  // the invalid access mode
        0o20_000_000,         // an undefined bit
        O_TRUNC,              // truncating a read-only open
        O_APPEND,             // appending to a read-only open
        O_DIRECTORY | O_RDWR, // a writable directory
    ] {
        assert_eq!(
            session.request(&Frame::new(3, Message::Tlopen { fid: 1, flags })),
            Err(SessionError::FlagNotInProfile),
            "flags {flags:#o}"
        );
    }
}

#[test]
fn tlopen_flags_decode_into_the_right_primitives() {
    use tunnel_fs_core::Primitive as P;
    use tunnel_fs_ninep::flags::{
        O_APPEND, O_DIRECTORY, O_NOFOLLOW, O_RDONLY, O_RDWR, O_TRUNC, O_WRONLY,
    };
    use tunnel_fs_ninep::open_primitives_from_flags;

    let cases: Vec<(u32, Vec<P>)> = vec![
        (O_RDONLY, vec![P::OpenRead]),
        (O_RDONLY | O_NOFOLLOW, vec![P::OpenRead]),
        (O_WRONLY, vec![P::OpenWrite]),
        (O_WRONLY | O_TRUNC, vec![P::OpenWrite, P::OpenTruncate]),
        (O_WRONLY | O_APPEND, vec![P::OpenWrite]),
        (O_RDWR, vec![P::OpenRead, P::OpenWrite]),
        (
            O_RDWR | O_TRUNC,
            vec![P::OpenRead, P::OpenWrite, P::OpenTruncate],
        ),
        (O_DIRECTORY, vec![P::OpenDir]),
    ];
    for (flags, expected) in cases {
        let primitives: Vec<P> = open_primitives_from_flags(flags)
            .unwrap_or_else(|error| panic!("flags {flags:#o}: {error}"))
            .iter()
            .collect();
        assert_eq!(primitives, expected, "flags {flags:#o}");
    }
}

#[test]
fn a_directory_fid_opened_without_o_directory_still_needs_list() {
    // The codec classifies from flags alone; the session knows the fid's kind
    // and re-runs the decision with it, so a read-only open of a directory is
    // `OpenDir` even when the client did not say `O_DIRECTORY`.
    let mut session = Session::new(
        CapabilitySet::DENY.with(Capability::Read),
        FeatureSet::NONE,
        Limits::PROFILE_DEFAULT,
    )
    .unwrap();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    walk(&mut session, 2, 0, 1, &["d"], QidKind::Directory);
    assert_eq!(
        session.request(&Frame::new(3, Message::Tlopen { fid: 1, flags: 0 })),
        Err(SessionError::NotPermitted),
        "a read-without-list grant cannot open a directory"
    );
}

#[test]
fn tsetattr_masks_decode_into_the_right_primitives_and_reject_ownership() {
    use tunnel_fs_core::Primitive as P;
    use tunnel_fs_ninep::flags::{
        SETATTR_ATIME, SETATTR_ATIME_SET, SETATTR_CTIME, SETATTR_GID, SETATTR_MODE, SETATTR_MTIME,
        SETATTR_SIZE, SETATTR_UID,
    };
    use tunnel_fs_ninep::setattr_primitives;

    assert_eq!(
        setattr_primitives(SETATTR_MODE)
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        vec![P::SetattrMode]
    );
    assert_eq!(
        setattr_primitives(SETATTR_SIZE)
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        vec![P::SetattrSize]
    );
    for bit in [SETATTR_ATIME, SETATTR_MTIME, SETATTR_ATIME_SET] {
        assert_eq!(
            setattr_primitives(bit).unwrap().iter().collect::<Vec<_>>(),
            vec![P::SetattrTimes],
            "bit {bit:#x}"
        );
    }
    assert_eq!(
        setattr_primitives(SETATTR_MODE | SETATTR_SIZE | SETATTR_MTIME)
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        vec![P::SetattrMode, P::SetattrSize, P::SetattrTimes]
    );
    for refused in [0, SETATTR_UID, SETATTR_GID, SETATTR_CTIME, 1 << 31] {
        assert_eq!(
            setattr_primitives(refused),
            Err(SessionError::FlagNotInProfile),
            "mask {refused:#x}"
        );
    }
}

#[test]
fn tunlinkat_and_tremove_split_by_kind_and_flag() {
    use tunnel_fs_ninep::unlinkat_primitives;

    assert_eq!(
        unlinkat_primitives(0).unwrap().iter().collect::<Vec<_>>(),
        vec![Primitive::Unlink]
    );
    assert_eq!(
        unlinkat_primitives(AT_REMOVEDIR)
            .unwrap()
            .iter()
            .collect::<Vec<_>>(),
        vec![Primitive::RemoveDir]
    );
    assert_eq!(
        unlinkat_primitives(0x400),
        Err(SessionError::FlagNotInProfile)
    );

    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    walk(&mut session, 3, 0, 2, &["d"], QidKind::Directory);
    let file = session
        .request(&Frame::new(4, Message::Tremove { fid: 1 }))
        .unwrap();
    assert_eq!(
        file.primitives.iter().collect::<Vec<_>>(),
        vec![Primitive::Unlink]
    );
    let directory = session
        .request(&Frame::new(5, Message::Tremove { fid: 2 }))
        .unwrap();
    assert_eq!(
        directory.primitives.iter().collect::<Vec<_>>(),
        vec![Primitive::RemoveDir],
        "Tremove on a directory carries the same authority as AT_REMOVEDIR"
    );
}

#[test]
fn a_getattr_mask_outside_the_profile_is_refused() {
    use tunnel_fs_ninep::getattr_primitives;
    assert!(getattr_primitives(GETATTR_BASIC).is_ok());
    assert!(getattr_primitives(tunnel_fs_ninep::GETATTR_ALL).is_ok());
    for refused in [0u64, 1 << 20, u64::MAX] {
        assert_eq!(
            getattr_primitives(refused),
            Err(SessionError::FlagNotInProfile),
            "mask {refused:#x}"
        );
    }
}

// ------------------------------------------------------------------ grant

#[test]
fn a_read_only_grant_denies_every_mutating_request_before_dispatch() {
    let grant = CapabilitySet::from_slice(&[Capability::Read, Capability::List]);
    let mut session = Session::new(grant, all_features(), Limits::PROFILE_DEFAULT).unwrap();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    walk(&mut session, 3, 0, 2, &["d"], QidKind::Directory);

    let mutating = [
        Message::Tlopen {
            fid: 1,
            flags: tunnel_fs_ninep::flags::O_WRONLY,
        },
        Message::Tlopen {
            fid: 1,
            flags: tunnel_fs_ninep::flags::O_RDWR | tunnel_fs_ninep::flags::O_TRUNC,
        },
        Message::Tlcreate {
            fid: 2,
            name: "x".to_owned(),
            flags: tunnel_fs_ninep::flags::O_WRONLY,
            mode: 0o644,
            gid: 0,
        },
        Message::Tmkdir {
            dfid: 0,
            name: "x".to_owned(),
            mode: 0o755,
            gid: 0,
        },
        Message::Tunlinkat {
            dirfid: 0,
            name: "x".to_owned(),
            flags: 0,
        },
        Message::Tunlinkat {
            dirfid: 0,
            name: "x".to_owned(),
            flags: AT_REMOVEDIR,
        },
        Message::Trename {
            fid: 1,
            dfid: 0,
            name: "x".to_owned(),
        },
        Message::Trenameat {
            olddirfid: 0,
            oldname: "a".to_owned(),
            newdirfid: 0,
            newname: "b".to_owned(),
        },
        Message::Tsetattr {
            fid: 1,
            valid: tunnel_fs_ninep::flags::SETATTR_SIZE,
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
            fid: 0,
            name: "l".to_owned(),
            target: "t".to_owned(),
            gid: 0,
        },
        Message::Tlink {
            dfid: 0,
            fid: 1,
            name: "l".to_owned(),
        },
        Message::Tremove { fid: 1 },
    ];
    for message in mutating {
        let name = message.message_type().as_str();
        let error = session.request(&Frame::new(9, message)).unwrap_err();
        assert_eq!(error, SessionError::NotPermitted, "{name}");
        assert_eq!(
            error.answer(),
            Answer::Rlerror(tunnel_fs_core::FsError::NotPermitted)
        );
        assert_eq!(session.outstanding_tags(), 0, "{name} took no tag");
    }
    // ...while the read-only requests it does hold are admitted.
    assert!(
        session
            .request(&Frame::new(10, Message::Tlopen { fid: 1, flags: 0 }))
            .is_ok()
    );
}

#[test]
fn a_feature_that_is_absent_denies_its_primitives() {
    let grant = full_grant();
    let mut session = Session::new(grant, FeatureSet::NONE, Limits::PROFILE_DEFAULT).unwrap();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);

    for message in [
        Message::Tsymlink {
            fid: 0,
            name: "l".to_owned(),
            target: "t".to_owned(),
            gid: 0,
        },
        Message::Treadlink { fid: 1 },
        Message::Tlink {
            dfid: 0,
            fid: 1,
            name: "l".to_owned(),
        },
        Message::Trename {
            fid: 1,
            dfid: 0,
            name: "x".to_owned(),
        },
    ] {
        let name = message.message_type().as_str();
        assert_eq!(
            session.request(&Frame::new(9, message)),
            Err(SessionError::NotPermitted),
            "{name} without its feature"
        );
    }

    // With the features, the same requests are admitted.
    let mut session = Session::new(
        full_grant(),
        FeatureSet::NONE
            .with(Feature::Symlinks)
            .with(Feature::HardLinks)
            .with(Feature::AtomicRename),
        Limits::PROFILE_DEFAULT,
    )
    .unwrap();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    assert!(
        session
            .request(&Frame::new(9, Message::Treadlink { fid: 1 }))
            .is_ok()
    );
}

#[test]
fn walk_needs_no_capability_but_discloses_only_qids() {
    // A delete-only grant can probe existence through `Rwalk` — the recorded
    // cost of `Twalk` requiring no capability — and can observe nothing else.
    let grant = CapabilitySet::DENY.with(Capability::Delete);
    let mut session = Session::new(grant, all_features(), Limits::PROFILE_DEFAULT).unwrap();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    session
        .request(&twalk(2, 0, 1, &["f"]))
        .expect("Twalk needs nothing");
    session
        .complete(&Frame::new(
            2,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::File, 3)],
            },
        ))
        .unwrap();
    assert_eq!(
        session.request(&Frame::new(
            3,
            Message::Tgetattr {
                fid: 1,
                request_mask: GETATTR_BASIC
            }
        )),
        Err(SessionError::NotPermitted),
        "Tgetattr needs list, so the qid is all such a grant may observe"
    );
    assert_eq!(
        session.request(&Frame::new(3, Message::Tlopen { fid: 1, flags: 0 })),
        Err(SessionError::NotPermitted)
    );
}

// --------------------------------------------- replies after a clunk

#[test]
fn an_in_place_walk_whose_fid_was_clunked_binds_nothing() {
    // Re-creating a clunked fid here would put a number back into the table
    // that the quota had already released, so `live_fids()` could exceed
    // `maxFids` — the bound gate 4 relies on to cap open descriptors.
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::Directory);
    session.request(&twalk(3, 1, 1, &["x"])).expect("Twalk");
    session
        .request(&Frame::new(4, Message::Tclunk { fid: 1 }))
        .expect("Tclunk");
    session
        .complete(&Frame::new(4, Message::Rclunk))
        .expect("Rclunk");
    assert_eq!(session.live_fids(), 1);

    session
        .complete(&Frame::new(
            3,
            Message::Rwalk {
                qids: vec![Qid::new(QidKind::Directory, 9)],
            },
        ))
        .expect("a reply for a clunked fid applies nothing rather than failing");
    assert!(session.fid(1).is_none());
    assert_eq!(session.live_fids(), 1, "the quota did not gain a fid");
    assert_eq!(session.outstanding_tags(), 0, "the tag was released");
}

#[test]
fn a_clone_walk_whose_origin_was_clunked_releases_its_reservation() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::Directory);
    // A zero-element clone takes its qid from the origin, which is about to go.
    session.request(&twalk(3, 1, 2, &[])).expect("Twalk");
    assert_eq!(session.live_fids(), 3, "fid 2 is reserved");
    session
        .request(&Frame::new(4, Message::Tclunk { fid: 1 }))
        .expect("Tclunk");
    session
        .complete(&Frame::new(4, Message::Rclunk))
        .expect("Rclunk");

    session
        .complete(&Frame::new(3, Message::Rwalk { qids: Vec::new() }))
        .expect("applies nothing rather than failing");
    assert!(session.fid(2).is_none());
    assert_eq!(
        session.live_fids(),
        1,
        "the reservation went with the tag, not stranded"
    );
    assert_eq!(session.outstanding_tags(), 0);
}

#[test]
fn an_open_or_create_reply_for_a_clunked_fid_applies_nothing() {
    for created in [false, true] {
        let mut session = attached_session();
        walk(&mut session, 2, 0, 1, &["d"], QidKind::Directory);
        let request = if created {
            Message::Tlcreate {
                fid: 1,
                name: "new.txt".to_owned(),
                flags: tunnel_fs_ninep::flags::O_WRONLY,
                mode: 0o644,
                gid: 0,
            }
        } else {
            Message::Tlopen {
                fid: 1,
                flags: tunnel_fs_ninep::flags::O_DIRECTORY,
            }
        };
        session.request(&Frame::new(3, request)).expect("request");
        session
            .request(&Frame::new(4, Message::Tclunk { fid: 1 }))
            .expect("Tclunk");
        session
            .complete(&Frame::new(4, Message::Rclunk))
            .expect("Rclunk");

        let reply = if created {
            Message::Rlcreate {
                qid: Qid::new(QidKind::File, 5),
                iounit: 0,
            }
        } else {
            Message::Rlopen {
                qid: Qid::new(QidKind::Directory, 5),
                iounit: 0,
            }
        };
        session
            .complete(&Frame::new(3, reply))
            .expect("a reply is not a request: there is no Rlerror to send for it");
        assert!(session.fid(1).is_none(), "created={created}");
        assert_eq!(session.live_fids(), 1, "created={created}");
        assert_eq!(session.outstanding_tags(), 0, "created={created}");
    }
}

// ------------------------------------------------------ pipelined handshake

#[test]
fn two_tversions_before_any_rversion_are_refused() {
    // The phase moves only when the `Rversion` arrives, so without the
    // pending-negotiation check a pipelined client could land two `Tversion`s
    // and the second would silently overwrite what the first settled.
    let mut session = session();
    session.request(&tversion(65_536)).expect("first Tversion");
    let error = session.request(&tversion(256)).unwrap_err();
    assert_eq!(error, SessionError::RepeatedVersion);
    assert!(error.is_fatal());
    // The first negotiation is intact.
    let Message::Rversion { msize, .. } = session.version_reply().unwrap().message else {
        panic!("wrong reply");
    };
    assert_eq!(msize, 65_536, "the second Tversion did not overwrite it");
}

#[test]
fn two_tattachs_before_any_rattach_are_refused() {
    let mut session = session();
    version_handshake(&mut session);
    session.request(&tattach(0, 1)).expect("first Tattach");
    let error = session.request(&tattach(7, 2)).unwrap_err();
    assert_eq!(error, SessionError::RepeatedAttach);
    assert!(error.is_fatal());
    assert_eq!(session.live_fids(), 1, "only one root fid was ever claimed");
}

// -------------------------------------------------------- reply bounds

#[test]
fn a_reply_carrying_more_bytes_than_its_request_asked_for_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["f"], QidKind::File);
    open(
        &mut session,
        3,
        1,
        tunnel_fs_ninep::flags::O_RDWR,
        QidKind::File,
    );

    // Tread count 2: two bytes back is fine, three is not.
    for (data, ok) in [(vec![1u8, 2], true), (vec![1u8, 2, 3], false)] {
        let mut session = session.clone();
        session
            .request(&Frame::new(
                4,
                Message::Tread {
                    fid: 1,
                    offset: 0,
                    count: 2,
                },
            ))
            .expect("Tread");
        let result = session.complete(&Frame::new(4, Message::Rread { data }));
        assert_eq!(result.is_ok(), ok);
        if !ok {
            assert_eq!(result, Err(SessionError::MalformedReply));
        }
    }

    // Twrite of three bytes: acknowledging three is fine, four is not.
    for (count, ok) in [(3u32, true), (4u32, false)] {
        let mut session = session.clone();
        session
            .request(&Frame::new(
                5,
                Message::Twrite {
                    fid: 1,
                    offset: 0,
                    data: vec![9, 9, 9],
                },
            ))
            .expect("Twrite");
        let result = session.complete(&Frame::new(5, Message::Rwrite { count }));
        assert_eq!(result.is_ok(), ok, "count {count}");
    }
}

#[test]
fn an_rreaddir_larger_than_its_treaddir_asked_for_is_refused() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["d"], QidKind::Directory);
    open(
        &mut session,
        3,
        1,
        tunnel_fs_ninep::flags::O_DIRECTORY,
        QidKind::Directory,
    );
    session
        .request(&Frame::new(
            4,
            Message::Treaddir {
                fid: 1,
                offset: 0,
                count: 32,
            },
        ))
        .expect("Treaddir");
    assert_eq!(
        session.complete(&Frame::new(
            4,
            Message::Rreaddir {
                data: vec![0u8; 33]
            }
        )),
        Err(SessionError::MalformedReply)
    );
}

#[test]
fn an_rwalk_with_no_qids_for_a_nonempty_twalk_is_refused() {
    // 9P answers an error reply when the first element cannot be walked, not
    // an `Rwalk` carrying no qids, which the client is supposed to read as a
    // successful zero-element clone.
    let mut session = attached_session();
    session.request(&twalk(3, 0, 1, &["a"])).expect("Twalk");
    assert_eq!(
        session.complete(&Frame::new(3, Message::Rwalk { qids: Vec::new() })),
        Err(SessionError::MalformedReply)
    );
}

#[test]
fn the_getattr_mask_bits_are_the_values_9p2000l_defines() {
    use tunnel_fs_ninep::flags::{
        GETATTR_ATIME, GETATTR_BLOCKS, GETATTR_BTIME, GETATTR_CTIME, GETATTR_DATA_VERSION,
        GETATTR_GEN, GETATTR_GID, GETATTR_INO, GETATTR_MODE, GETATTR_MTIME, GETATTR_NLINK,
        GETATTR_RDEV, GETATTR_SIZE, GETATTR_UID,
    };

    // Each is one bit, in the reference's order, with no two sharing one.
    let basic = [
        GETATTR_MODE,
        GETATTR_NLINK,
        GETATTR_UID,
        GETATTR_GID,
        GETATTR_RDEV,
        GETATTR_ATIME,
        GETATTR_MTIME,
        GETATTR_CTIME,
        GETATTR_INO,
        GETATTR_SIZE,
        GETATTR_BLOCKS,
    ];
    for (index, bit) in basic.iter().enumerate() {
        assert_eq!(*bit, 1u64 << index, "bit {index}");
    }
    assert_eq!(basic.iter().fold(0, |all, bit| all | bit), GETATTR_BASIC);
    assert_eq!(
        GETATTR_BASIC | GETATTR_BTIME | GETATTR_GEN | GETATTR_DATA_VERSION,
        tunnel_fs_ninep::GETATTR_ALL
    );
    // The two the review caught: `nlink` is not `uid`, and `size` is not
    // `atime`.
    assert_eq!(GETATTR_NLINK, 0x2);
    assert_eq!(GETATTR_SIZE, 0x200);
}

#[test]
fn the_paths_a_request_names_are_handed_over_already_validated() {
    let mut session = attached_session();
    walk(&mut session, 2, 0, 1, &["dir"], QidKind::Directory);

    let accepted = session
        .request(&Frame::new(
            3,
            Message::Trenameat {
                olddirfid: 0,
                oldname: "a.txt".to_owned(),
                newdirfid: 1,
                newname: "b.txt".to_owned(),
            },
        ))
        .unwrap();
    match accepted.paths {
        RequestPaths::Pair {
            source,
            destination,
        } => {
            assert_eq!(source.as_str(), "/a.txt");
            assert_eq!(destination.as_str(), "/dir/b.txt");
        }
        other => panic!("expected a confined pair, got {other:?}"),
    }
    assert_eq!(
        accepted.primitives.iter().collect::<Vec<_>>(),
        vec![Primitive::Rename]
    );
}
