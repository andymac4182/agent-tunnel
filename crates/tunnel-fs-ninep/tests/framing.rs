//! Strictness: `msize` boundaries, malformed and truncated frames, bad sizes,
//! unknown and unexpected types, reserved tags, and non-UTF-8 strings.

mod common;

use common::{INVALID_UTF8, decode_chunks, raw_frame, raw_frame_with_size, raw_string, session};
use tunnel_fs_core::{FsErrorCode, MIN_MESSAGE_BYTES, SessionErrorCode};
use tunnel_fs_ninep::{
    Answer, CodecError, DIALECT, Frame, MAX_MESSAGE_BYTES, MAX_WALK_NAMES, MIN_MSIZE, Message,
    MessageType, NOTAG, Qid, QidKind, SessionError, StringField, decode_exact, negotiate,
};

// ------------------------------------------------------------ msize itself

#[test]
fn msize_negotiation_is_exact_at_every_boundary() {
    assert_eq!(MIN_MSIZE, MIN_MESSAGE_BYTES as u32);
    assert_eq!(MAX_MESSAGE_BYTES, 65_536);

    assert_eq!(
        negotiate(255, DIALECT, MAX_MESSAGE_BYTES),
        Err(SessionError::MsizeBelowFloor),
        "255 is one below the floor"
    );
    assert_eq!(negotiate(256, DIALECT, MAX_MESSAGE_BYTES), Ok(256));
    assert_eq!(negotiate(65_536, DIALECT, MAX_MESSAGE_BYTES), Ok(65_536));
    assert_eq!(
        negotiate(65_537, DIALECT, MAX_MESSAGE_BYTES),
        Ok(65_536),
        "one above the ceiling is reduced, never accepted"
    );
    assert_eq!(negotiate(u32::MAX, DIALECT, MAX_MESSAGE_BYTES), Ok(65_536));
    assert_eq!(
        negotiate(0, DIALECT, MAX_MESSAGE_BYTES),
        Err(SessionError::MsizeBelowFloor),
        "zero is never an unlimited sentinel"
    );
}

#[test]
fn negotiation_reduces_to_the_smaller_of_the_two_offers() {
    assert_eq!(negotiate(4_096, DIALECT, 1_024), Ok(1_024));
    assert_eq!(negotiate(1_024, DIALECT, 4_096), Ok(1_024));
    assert_eq!(
        negotiate(4_096, DIALECT, 128),
        Err(SessionError::MsizeBelowFloor),
        "a server ceiling below the floor cannot be negotiated to"
    );
}

#[test]
fn only_the_9p2000l_dialect_is_accepted() {
    for offered in ["9P2000", "9P2000.u", "9p2000.L", "9P2000.L ", "", "unknown"] {
        assert_eq!(
            negotiate(4_096, offered, MAX_MESSAGE_BYTES),
            Err(SessionError::UnsupportedDialect),
            "{offered:?} must be refused"
        );
    }
    assert!(negotiate(4_096, DIALECT, MAX_MESSAGE_BYTES).is_ok());
    assert_eq!(
        SessionError::UnsupportedDialect.answer(),
        Answer::Close(SessionErrorCode::ProtocolViolation),
        "an unsupported dialect terminates rather than replying `unknown`"
    );
}

/// A `Twrite` whose complete frame is exactly `size` bytes.
fn write_of_exactly(size: u32) -> Frame {
    let payload = usize::try_from(size).unwrap() - 23;
    Frame::new(
        1,
        Message::Twrite {
            fid: 1,
            offset: 0,
            data: vec![0xAB; payload],
        },
    )
}

/// One byte above `msize` is `FrameAboveMsize`, except at the profile
/// ceiling, where the same byte is also above [`MAX_MESSAGE_BYTES`] and the
/// ceiling check — which comes first, deliberately — answers instead.
fn over_msize_error(msize: u32) -> CodecError {
    if msize >= MAX_MESSAGE_BYTES {
        CodecError::FrameAboveCeiling
    } else {
        CodecError::FrameAboveMsize
    }
}

#[test]
fn a_frame_exactly_at_msize_encodes_and_one_byte_above_does_not() {
    for msize in [MIN_MSIZE, 257, 1_024, MAX_MESSAGE_BYTES] {
        let exact = write_of_exactly(msize);
        let bytes = exact.to_bytes(msize).expect("exactly msize is legal");
        assert_eq!(bytes.len(), msize as usize);

        let over = write_of_exactly(msize + 1);
        assert_eq!(
            over.to_bytes(msize),
            Err(over_msize_error(msize)),
            "one byte above msize {msize}"
        );
    }
}

#[test]
fn a_frame_exactly_at_msize_decodes_and_one_byte_above_does_not() {
    for msize in [MIN_MSIZE, 257, 1_024, MAX_MESSAGE_BYTES] {
        let bytes = write_of_exactly(msize).to_bytes(msize).unwrap();
        assert!(decode_exact(&bytes, msize).is_ok());

        // The same bytes under a decoder one byte smaller.
        assert_eq!(
            decode_exact(&bytes, msize - 1),
            Err(CodecError::FrameAboveMsize)
        );

        // A frame one byte larger, declared honestly, under this `msize`.
        let over = raw_frame_with_size(
            msize + 1,
            MessageType::Twrite.code(),
            1,
            &vec![0u8; usize::try_from(msize + 1).unwrap() - 7],
        );
        assert_eq!(
            decode_exact(&over, msize),
            Err(over_msize_error(msize)),
            "msize {msize}"
        );
    }
}

#[test]
fn the_ceiling_is_checked_before_the_negotiated_msize() {
    // A declared size above the absolute ceiling reports the ceiling, not the
    // session's own bound, whatever `msize` is in force.  The checking order is
    // fixed so one input has one answer.
    for msize in [MIN_MSIZE, MAX_MESSAGE_BYTES] {
        let bytes = raw_frame_with_size(MAX_MESSAGE_BYTES + 1, MessageType::Tclunk.code(), 1, &[]);
        assert_eq!(
            decode_exact(&bytes, msize),
            Err(CodecError::FrameAboveCeiling)
        );
    }
}

#[test]
fn a_size_below_the_header_is_refused_before_anything_is_read() {
    for size in 0..7u32 {
        let bytes = raw_frame_with_size(size, MessageType::Tclunk.code(), 1, &1u32.to_le_bytes());
        assert_eq!(
            decode_exact(&bytes, MAX_MESSAGE_BYTES),
            Err(CodecError::FrameBelowHeader),
            "declared size {size}"
        );
    }
}

#[test]
fn a_declared_size_that_disagrees_with_the_bytes_is_refused_both_ways() {
    let body = 1u32.to_le_bytes();
    let honest = raw_frame(MessageType::Tclunk.code(), 1, &body);
    assert!(decode_exact(&honest, MAX_MESSAGE_BYTES).is_ok());

    // Over-declared: the buffer is shorter than the frame claims.
    let mut over = honest.clone();
    over[0] = 12;
    assert_eq!(
        decode_exact(&over, MAX_MESSAGE_BYTES),
        Err(CodecError::TruncatedBody)
    );

    // Under-declared: the buffer is longer than the frame claims.
    let mut under = honest.clone();
    under[0] = 10;
    assert_eq!(
        decode_exact(&under, MAX_MESSAGE_BYTES),
        Err(CodecError::TrailingBytes)
    );
}

#[test]
fn a_body_with_bytes_left_over_is_refused_rather_than_truncated() {
    let mut body = 1u32.to_le_bytes().to_vec();
    body.push(0xFF);
    let bytes = raw_frame(MessageType::Tclunk.code(), 1, &body);
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::TrailingBytes)
    );
}

#[test]
fn a_body_that_ends_inside_a_field_is_truncated() {
    // `Tclunk` needs four bytes of fid; give it three.
    let bytes = raw_frame(MessageType::Tclunk.code(), 1, &[0, 0, 0]);
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::TruncatedBody)
    );
}

#[test]
fn two_messages_in_one_consumer_message_are_refused() {
    // The consumer WebSocket rule: exactly one complete 9P message per binary
    // message.  Packing two is `TrailingBytes`, and half of one is truncation.
    let one = Frame::new(1, Message::Tclunk { fid: 1 })
        .to_bytes(MAX_MESSAGE_BYTES)
        .unwrap();
    let mut two = one.clone();
    two.extend_from_slice(&one);
    assert_eq!(
        decode_exact(&two, MAX_MESSAGE_BYTES),
        Err(CodecError::TrailingBytes)
    );
    for cut in 0..one.len() {
        assert_eq!(
            decode_exact(&one[..cut], MAX_MESSAGE_BYTES),
            Err(CodecError::TruncatedBody),
            "a message split across binary messages, cut at {cut}"
        );
    }
}

// ------------------------------------------------------------ message types

#[test]
fn every_opcode_outside_the_profile_is_refused_and_the_two_reasons_differ() {
    let profile: Vec<u8> = MessageType::ALL
        .into_iter()
        .map(MessageType::code)
        .collect();
    let mut denied = 0;
    let mut unknown = 0;
    for code in 0..=255u8 {
        if profile.contains(&code) {
            continue;
        }
        let bytes = raw_frame(code, 1, &[]);
        match decode_exact(&bytes, MAX_MESSAGE_BYTES) {
            Err(CodecError::MessageTypeNotInProfile(reported)) => {
                assert_eq!(reported, code);
                assert!(
                    tunnel_fs_ninep::KNOWN_OUTSIDE_PROFILE.contains(&code),
                    "{code} reported as a denied opcode but is not one"
                );
                denied += 1;
            }
            Err(CodecError::UnknownMessageType(reported)) => {
                assert_eq!(reported, code);
                unknown += 1;
            }
            other => panic!("opcode {code} was not refused: {other:?}"),
        }
    }
    assert_eq!(
        denied,
        tunnel_fs_ninep::KNOWN_OUTSIDE_PROFILE.len(),
        "every known-but-denied opcode reports as such"
    );
    assert_eq!(denied + unknown, 256 - MessageType::ALL.len());
}

#[test]
fn tauth_is_denied_as_a_known_opcode_not_as_an_unknown_one() {
    // "No custom `Tauth` bearer-token scheme": an export that answered `Tauth`
    // would advertise an authentication path that does not exist.
    let bytes = raw_frame(102, 1, &[]);
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::MessageTypeNotInProfile(102))
    );
}

#[test]
fn a_reply_where_a_request_belongs_is_refused_by_the_session() {
    let mut session = common::attached_session();
    let reply = Frame::new(50, Message::Rclunk);
    assert_eq!(session.request(&reply), Err(SessionError::UnexpectedReply));
}

// -------------------------------------------------------------------- tags

#[test]
fn notag_is_required_by_tversion_and_forbidden_everywhere_else() {
    let version = Frame::new(
        7,
        Message::Tversion {
            msize: 4_096,
            version: DIALECT.to_owned(),
        },
    );
    assert_eq!(
        version.to_bytes(MAX_MESSAGE_BYTES),
        Err(CodecError::NotagRequired)
    );
    let bytes = {
        let mut body = 4_096u32.to_le_bytes().to_vec();
        body.extend_from_slice(&raw_string(DIALECT.as_bytes()));
        raw_frame(MessageType::Tversion.code(), 7, &body)
    };
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::NotagRequired)
    );

    let clunk = Frame::new(NOTAG, Message::Tclunk { fid: 1 });
    assert_eq!(
        clunk.to_bytes(MAX_MESSAGE_BYTES),
        Err(CodecError::NotagNotPermitted)
    );
    let bytes = raw_frame(MessageType::Tclunk.code(), NOTAG, &1u32.to_le_bytes());
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::NotagNotPermitted)
    );
}

#[test]
fn a_refused_encode_leaves_the_output_buffer_untouched() {
    let mut out = b"already here".to_vec();
    let before = out.clone();
    let over = write_of_exactly(MIN_MSIZE + 1);
    assert_eq!(
        over.encode(MIN_MSIZE, &mut out),
        Err(CodecError::FrameAboveMsize)
    );
    assert_eq!(out, before, "half a frame must never be left behind");
}

// ---------------------------------------------------------------- strings

#[test]
fn a_string_that_is_not_utf8_is_refused_in_every_field_that_has_one() {
    // The contract assigns non-UTF-8 to this gate.  Each case builds a frame
    // by hand, because the encoder takes `&str` and so cannot produce one.
    let cases: Vec<(MessageType, Vec<u8>, StringField)> = vec![
        (
            MessageType::Tversion,
            {
                let mut body = 4_096u32.to_le_bytes().to_vec();
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body
            },
            StringField::Version,
        ),
        (
            MessageType::Tattach,
            {
                let mut body = Vec::new();
                body.extend_from_slice(&0u32.to_le_bytes());
                body.extend_from_slice(&u32::MAX.to_le_bytes());
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body.extend_from_slice(&raw_string(b""));
                body.extend_from_slice(&u32::MAX.to_le_bytes());
                body
            },
            StringField::Uname,
        ),
        (
            MessageType::Tattach,
            {
                let mut body = Vec::new();
                body.extend_from_slice(&0u32.to_le_bytes());
                body.extend_from_slice(&u32::MAX.to_le_bytes());
                body.extend_from_slice(&raw_string(b""));
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body.extend_from_slice(&u32::MAX.to_le_bytes());
                body
            },
            StringField::Aname,
        ),
        (
            MessageType::Twalk,
            {
                let mut body = Vec::new();
                body.extend_from_slice(&0u32.to_le_bytes());
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&1u16.to_le_bytes());
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body
            },
            StringField::WalkName,
        ),
        (
            MessageType::Tmkdir,
            {
                let mut body = 0u32.to_le_bytes().to_vec();
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body.extend_from_slice(&0o755u32.to_le_bytes());
                body.extend_from_slice(&0u32.to_le_bytes());
                body
            },
            StringField::Name,
        ),
        (
            MessageType::Tsymlink,
            {
                let mut body = 0u32.to_le_bytes().to_vec();
                body.extend_from_slice(&raw_string(b"link"));
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body.extend_from_slice(&0u32.to_le_bytes());
                body
            },
            StringField::SymlinkTarget,
        ),
        (
            MessageType::Rreadlink,
            raw_string(&INVALID_UTF8),
            StringField::LinkTarget,
        ),
        (
            MessageType::Trenameat,
            {
                let mut body = 0u32.to_le_bytes().to_vec();
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&raw_string(b"new"));
                body
            },
            StringField::OldName,
        ),
        (
            MessageType::Trenameat,
            {
                let mut body = 0u32.to_le_bytes().to_vec();
                body.extend_from_slice(&raw_string(b"old"));
                body.extend_from_slice(&1u32.to_le_bytes());
                body.extend_from_slice(&raw_string(&INVALID_UTF8));
                body
            },
            StringField::NewName,
        ),
    ];
    for (message_type, body, field) in cases {
        let tag = if message_type == MessageType::Tversion {
            NOTAG
        } else {
            1
        };
        let bytes = raw_frame(message_type.code(), tag, &body);
        assert_eq!(
            decode_exact(&bytes, MAX_MESSAGE_BYTES),
            Err(CodecError::StringNotUtf8(field)),
            "{} / {field}",
            message_type.as_str()
        );
    }
}

#[test]
fn the_same_bytes_are_accepted_when_they_are_valid_utf8() {
    // The refusal above is about encoding, not about the byte values: the same
    // frame with a well-formed multi-byte name decodes.
    let mut body = Vec::new();
    body.extend_from_slice(&0u32.to_le_bytes());
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&raw_string("caf\u{e9}".as_bytes()));
    let bytes = raw_frame(MessageType::Twalk.code(), 1, &body);
    let frame = decode_exact(&bytes, MAX_MESSAGE_BYTES).expect("valid UTF-8 decodes");
    let Message::Twalk { names, .. } = frame.message else {
        panic!("wrong message");
    };
    assert_eq!(names, vec!["caf\u{e9}".to_owned()]);
}

#[test]
fn no_decoded_string_is_ever_replaced_or_repaired() {
    // A lossy conversion would produce U+FFFD and succeed.  Nothing in this
    // crate does that, so the refusal above is the only possible outcome — and
    // this asserts the replacement character is not what came back.
    let mut body = 0u32.to_le_bytes().to_vec();
    body.extend_from_slice(&raw_string(&[0xFF, 0xFE, 0xFD]));
    body.extend_from_slice(&0o755u32.to_le_bytes());
    body.extend_from_slice(&0u32.to_le_bytes());
    let bytes = raw_frame(MessageType::Tmkdir.code(), 1, &body);
    match decode_exact(&bytes, MAX_MESSAGE_BYTES) {
        Err(CodecError::StringNotUtf8(StringField::Name)) => {}
        Ok(frame) => panic!("invalid UTF-8 was accepted as {frame:?}"),
        Err(other) => panic!("wrong refusal: {other:?}"),
    }
}

// ----------------------------------------------------------------- fields

#[test]
fn a_qid_type_outside_the_profile_is_refused() {
    for bits in 0..=255u8 {
        let mut body = vec![bits];
        body.extend_from_slice(&0u32.to_le_bytes());
        body.extend_from_slice(&0u64.to_le_bytes());
        let bytes = raw_frame(MessageType::Rattach.code(), 1, &body);
        let decoded = decode_exact(&bytes, MAX_MESSAGE_BYTES);
        if matches!(bits, 0x00 | 0x80 | 0x02) {
            assert!(decoded.is_ok(), "qid type {bits:#04x} is in the profile");
        } else {
            assert_eq!(
                decoded,
                Err(CodecError::QidTypeNotInProfile),
                "qid type {bits:#04x}"
            );
        }
    }
}

#[test]
fn the_rlerror_errno_vocabulary_is_closed_in_both_directions() {
    for code in FsErrorCode::ALL {
        let frame = Frame::new(1, Message::Rlerror { code });
        let bytes = frame.to_bytes(MAX_MESSAGE_BYTES).unwrap();
        assert_eq!(decode_exact(&bytes, MAX_MESSAGE_BYTES), Ok(frame));
    }
    let mapped: Vec<u32> = FsErrorCode::ALL
        .into_iter()
        .map(FsErrorCode::errno)
        .collect();
    for errno in [0u32, 5, 11, 28, 40_000, u32::MAX] {
        if mapped.contains(&errno) {
            continue;
        }
        let bytes = raw_frame(MessageType::Rlerror.code(), 1, &errno.to_le_bytes());
        assert_eq!(
            decode_exact(&bytes, MAX_MESSAGE_BYTES),
            Err(CodecError::ErrnoNotInVocabulary),
            "errno {errno}"
        );
    }
}

#[test]
fn a_walk_above_maxwelem_is_refused_on_encode_and_on_decode() {
    let names: Vec<String> = (0..=MAX_WALK_NAMES)
        .map(|index| format!("d{index}"))
        .collect();
    assert_eq!(names.len(), MAX_WALK_NAMES + 1);
    let frame = Frame::new(
        1,
        Message::Twalk {
            fid: 0,
            newfid: 1,
            names: names.clone(),
        },
    );
    assert_eq!(
        frame.to_bytes(MAX_MESSAGE_BYTES),
        Err(CodecError::TooManyWalkNames)
    );

    let mut body = 0u32.to_le_bytes().to_vec();
    body.extend_from_slice(&1u32.to_le_bytes());
    body.extend_from_slice(&u16::try_from(names.len()).unwrap().to_le_bytes());
    for name in &names {
        body.extend_from_slice(&raw_string(name.as_bytes()));
    }
    let bytes = raw_frame(MessageType::Twalk.code(), 1, &body);
    assert_eq!(
        decode_exact(&bytes, MAX_MESSAGE_BYTES),
        Err(CodecError::TooManyWalkNames),
        "the count is refused before a single name is reserved"
    );

    // Exactly MAXWELEM is legal.
    let exact = Frame::new(
        1,
        Message::Twalk {
            fid: 0,
            newfid: 1,
            names: names[..MAX_WALK_NAMES].to_vec(),
        },
    );
    assert!(exact.to_bytes(MAX_MESSAGE_BYTES).is_ok());
}

#[test]
fn a_count_that_could_not_fit_its_own_reply_is_refused() {
    let msize = 1_024u32;
    let limit = msize - tunnel_fs_ninep::COUNTED_REPLY_OVERHEAD;
    for (count, expected) in [(limit, true), (limit + 1, false)] {
        let frame = Frame::new(
            1,
            Message::Tread {
                fid: 1,
                offset: 0,
                count,
            },
        );
        assert_eq!(
            frame.to_bytes(msize).is_ok(),
            expected,
            "Tread count {count} at msize {msize}"
        );
        let mut body = 1u32.to_le_bytes().to_vec();
        body.extend_from_slice(&0u64.to_le_bytes());
        body.extend_from_slice(&count.to_le_bytes());
        let bytes = raw_frame(MessageType::Tread.code(), 1, &body);
        assert_eq!(
            decode_exact(&bytes, msize).is_ok(),
            expected,
            "decoded Tread count {count}"
        );
    }
}

// --------------------------------------------------------------- readdir

#[test]
fn directory_entries_round_trip_and_a_truncated_block_is_refused() {
    use tunnel_fs_ninep::{DirEntry, pack_entries, parse_entries};

    let entries = vec![
        DirEntry::new(Qid::new(QidKind::Directory, 1), 1, "sub"),
        DirEntry::new(Qid::new(QidKind::File, 2), 2, common::UNICODE_NAME),
        DirEntry::new(Qid::new(QidKind::Symlink, 3), 3, "link"),
    ];
    let (block, written) = pack_entries(&entries, 4_096).unwrap();
    assert_eq!(written, entries.len());
    assert_eq!(parse_entries(&block).unwrap(), entries);

    // An entry boundary is a legal short block; anything else is malformed.
    let boundaries: Vec<usize> = entries
        .iter()
        .scan(0usize, |total, entry| {
            *total += entry.encoded_len();
            Some(*total)
        })
        .collect();
    let mut refused = 0;
    for cut in 1..block.len() {
        if boundaries.contains(&cut) {
            assert!(
                parse_entries(&block[..cut]).is_ok(),
                "an entry boundary at {cut} is a legal short block"
            );
            continue;
        }
        assert!(
            parse_entries(&block[..cut]).is_err(),
            "a block cut at {cut} must not parse as whole entries"
        );
        refused += 1;
    }
    assert!(refused > 50, "only {refused} interior cuts were refused");
}

#[test]
fn a_directory_entry_name_that_is_not_utf8_is_refused() {
    use tunnel_fs_ninep::parse_entries;

    let mut block = Vec::new();
    block.push(QidKind::File.bits());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&0u64.to_le_bytes());
    block.extend_from_slice(&1u64.to_le_bytes());
    block.push(8); // DT_REG
    block.extend_from_slice(&raw_string(&INVALID_UTF8));
    assert_eq!(
        parse_entries(&block),
        Err(CodecError::StringNotUtf8(StringField::DirEntryName)),
        "a host name that is not UTF-8 is refused on the way out, not mangled"
    );
}

#[test]
fn a_directory_entry_whose_type_byte_contradicts_its_qid_is_refused() {
    use tunnel_fs_ninep::parse_entries;

    let mut block = Vec::new();
    block.push(QidKind::File.bits());
    block.extend_from_slice(&0u32.to_le_bytes());
    block.extend_from_slice(&0u64.to_le_bytes());
    block.extend_from_slice(&1u64.to_le_bytes());
    block.push(4); // DT_DIR, disagreeing with the file qid
    block.extend_from_slice(&raw_string(b"name"));
    assert_eq!(parse_entries(&block), Err(CodecError::MalformedDirEntry));
}

#[test]
fn packing_leaves_out_an_entry_that_does_not_fit_rather_than_splitting_it() {
    use tunnel_fs_ninep::{DirEntry, ENTRY_OVERHEAD, pack_entries, parse_entries};

    let entries: Vec<DirEntry> = (0..8)
        .map(|index| DirEntry::new(Qid::new(QidKind::File, index), index, format!("f{index}")))
        .collect();
    let limit = (ENTRY_OVERHEAD + 2) * 3 + 1;
    let (block, written) = pack_entries(&entries, limit).unwrap();
    assert_eq!(written, 3);
    assert_eq!(parse_entries(&block).unwrap(), entries[..3].to_vec());
}

// --------------------------------------------------------- error renderings

#[test]
fn no_error_rendering_can_contain_a_name_or_a_path() {
    let mut rendered = Vec::new();
    for field in StringField::ALL {
        rendered.push(format!("{}", CodecError::StringNotUtf8(field)));
        rendered.push(format!("{:?}", CodecError::StringTooLong(field)));
    }
    for code in 0..=255u8 {
        rendered.push(format!("{}", CodecError::UnknownMessageType(code)));
        rendered.push(format!("{}", CodecError::MessageTypeNotInProfile(code)));
    }
    for message_type in MessageType::ALL {
        rendered.push(format!("{}", CodecError::UnexpectedDirection(message_type)));
    }
    for error in [
        CodecError::FrameBelowHeader,
        CodecError::FrameAboveMsize,
        CodecError::FrameAboveCeiling,
        CodecError::TruncatedBody,
        CodecError::TrailingBytes,
        CodecError::CountAboveMsize,
        CodecError::TooManyWalkNames,
        CodecError::NotagNotPermitted,
        CodecError::NotagRequired,
        CodecError::NofidNotPermitted,
        CodecError::QidTypeNotInProfile,
        CodecError::ErrnoNotInVocabulary,
        CodecError::MalformedDirEntry,
    ] {
        rendered.push(format!("{error}"));
        rendered.push(format!("{error:?}"));
    }
    for error in session_errors() {
        rendered.push(format!("{error}"));
        rendered.push(format!("{error:?}"));
        rendered.push(format!("{:?}", error.answer()));
    }
    // Pinned exactly, so the sweep cannot quietly shrink: 10 string fields x 2,
    // 256 opcode bytes x 2, 41 message types, 13 codec errors x 2, and 39
    // session errors x 3.
    assert_eq!(rendered.len(), 716, "the payload-free sweep changed size");
    for text in &rendered {
        for forbidden in [
            "caf",
            "draft.txt",
            "projects",
            "/",
            "notes",
            "secret",
            "\u{fffd}",
        ] {
            assert!(!text.contains(forbidden), "{text:?} contains {forbidden:?}");
        }
    }
}

fn session_errors() -> Vec<SessionError> {
    let mut errors = vec![
        SessionError::BeforeVersion,
        SessionError::BeforeAttach,
        SessionError::RepeatedVersion,
        SessionError::RepeatedAttach,
        SessionError::UnsupportedDialect,
        SessionError::MsizeBelowFloor,
        SessionError::MsizeNotAReduction,
        SessionError::MidFrame,
        SessionError::AttachFieldNotPermitted,
        SessionError::TagInUse,
        SessionError::TagNotInUse,
        SessionError::TagReservedByFlush,
        SessionError::TagQuotaExhausted,
        SessionError::UnknownFid,
        SessionError::FidInUse,
        SessionError::FidQuotaExhausted,
        SessionError::FidIsOpen,
        SessionError::FidNotOpen,
        SessionError::FidWrongKind,
        SessionError::NotPermitted,
        SessionError::FlagNotInProfile,
        SessionError::UnexpectedReply,
        SessionError::MalformedReply,
        SessionError::Closed,
    ];
    errors.extend(
        tunnel_fs_core::PathRule::ALL
            .into_iter()
            .map(SessionError::Path),
    );
    errors
}

#[test]
fn every_codec_error_closes_with_1002_and_is_never_an_rlerror() {
    for error in [
        CodecError::FrameBelowHeader,
        CodecError::FrameAboveMsize,
        CodecError::FrameAboveCeiling,
        CodecError::TruncatedBody,
        CodecError::TrailingBytes,
        CodecError::UnknownMessageType(200),
        CodecError::MessageTypeNotInProfile(8),
        CodecError::StringNotUtf8(StringField::Name),
        CodecError::QidTypeNotInProfile,
        CodecError::ErrnoNotInVocabulary,
        CodecError::MalformedDirEntry,
    ] {
        assert_eq!(error.close_code(), 1002);
        assert_eq!(error.session_code(), SessionErrorCode::ProtocolViolation);
    }
}

#[test]
fn the_stream_decoder_and_the_exact_decoder_agree_on_refusals() {
    let cases: Vec<Vec<u8>> = vec![
        raw_frame_with_size(3, MessageType::Tclunk.code(), 1, &[]),
        raw_frame(200, 1, &[]),
        raw_frame(8, 1, &[]),
        raw_frame(MessageType::Tclunk.code(), NOTAG, &1u32.to_le_bytes()),
        raw_frame(MessageType::Tclunk.code(), 1, &[0, 0, 0, 0, 9]),
        raw_frame(MessageType::Rlerror.code(), 1, &777u32.to_le_bytes()),
    ];
    for bytes in cases {
        let exact = decode_exact(&bytes, MAX_MESSAGE_BYTES).unwrap_err();
        let (_, streamed) = decode_chunks(&[&bytes], MAX_MESSAGE_BYTES);
        assert_eq!(Some(exact), streamed, "{bytes:02x?}");
    }
}

#[test]
fn an_empty_grant_admits_no_session() {
    assert!(
        tunnel_fs_ninep::Session::new(
            tunnel_fs_core::CapabilitySet::DENY,
            tunnel_fs_core::FeatureSet::NONE,
            tunnel_fs_core::Limits::PROFILE_DEFAULT,
        )
        .is_none()
    );
    // ...and a non-empty one does.
    assert_eq!(session().phase(), tunnel_fs_ninep::Phase::AwaitingVersion);
}
