//! Shared synthetic fixtures and helpers for the 9P2000.L codec tests.
//!
//! Every value here is invented.  No path, name or byte string in this file
//! came from a real filesystem.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, FsErrorCode, Limits};
use tunnel_fs_ninep::{
    Attributes, CodecError, DirEntry, Frame, FrameDecoder, Message, MessageType, NOFID, NONUNAME,
    NOTAG, Qid, QidKind, Session, pack_entries,
};

/// The `msize` every golden fixture is encoded at.
pub const FIXTURE_MSIZE: u32 = 65_536;

/// The fixture directory.
pub fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures")
}

/// A name with multi-byte UTF-8 in it, so the `string[s]` length is a **byte**
/// count in the golden bytes rather than a character count.
pub const UNICODE_NAME: &str = "caf\u{e9}-\u{1f5c2}";

/// Every golden fixture: a stable file stem and the frame it must encode to.
///
/// One per message type in the profile, checked exhaustively by
/// `tests/golden.rs`.
pub fn fixtures() -> Vec<(&'static str, Frame)> {
    let file_qid = Qid {
        kind: QidKind::File,
        version: 7,
        path: 0x0123_4567_89AB_CDEF,
    };
    let dir_qid = Qid {
        kind: QidKind::Directory,
        version: 1,
        path: 0x1122_3344_5566_7788,
    };
    let link_qid = Qid {
        kind: QidKind::Symlink,
        version: 0,
        path: 0x00FF_00FF_00FF_00FF,
    };
    let attributes = Attributes {
        valid: tunnel_fs_ninep::GETATTR_BASIC,
        qid: file_qid,
        mode: 0o100_644,
        uid: 1000,
        gid: 1000,
        nlink: 1,
        rdev: 0,
        size: 0x0000_0001_0000_0000,
        blksize: 4096,
        blocks: 8,
        atime_sec: 1_770_000_000,
        atime_nsec: 123_456_789,
        mtime_sec: 1_770_000_001,
        mtime_nsec: 987_654_321,
        ctime_sec: 1_770_000_002,
        ctime_nsec: 1,
        btime_sec: 0,
        btime_nsec: 0,
        generation: 0,
        data_version: 0,
    };
    let (entries, _) = pack_entries(
        &[
            DirEntry::new(dir_qid, 1, "notes"),
            DirEntry::new(file_qid, 2, UNICODE_NAME),
            DirEntry::new(link_qid, 3, "shortcut"),
        ],
        4096,
    )
    .expect("fixture entries pack");

    vec![
        (
            "tversion",
            Frame::new(
                NOTAG,
                Message::Tversion {
                    msize: 65_536,
                    version: "9P2000.L".to_owned(),
                },
            ),
        ),
        (
            "rversion",
            Frame::new(
                NOTAG,
                Message::Rversion {
                    msize: 65_536,
                    version: "9P2000.L".to_owned(),
                },
            ),
        ),
        (
            "tattach",
            Frame::new(
                1,
                Message::Tattach {
                    fid: 0,
                    afid: NOFID,
                    uname: String::new(),
                    aname: String::new(),
                    n_uname: NONUNAME,
                },
            ),
        ),
        ("rattach", Frame::new(1, Message::Rattach { qid: dir_qid })),
        ("tflush", Frame::new(2, Message::Tflush { oldtag: 1 })),
        ("rflush", Frame::new(2, Message::Rflush)),
        (
            "twalk",
            Frame::new(
                3,
                Message::Twalk {
                    fid: 0,
                    newfid: 1,
                    names: vec!["projects".to_owned(), UNICODE_NAME.to_owned()],
                },
            ),
        ),
        (
            "rwalk",
            Frame::new(
                3,
                Message::Rwalk {
                    qids: vec![dir_qid, file_qid],
                },
            ),
        ),
        (
            "tlopen",
            Frame::new(4, Message::Tlopen { fid: 1, flags: 0 }),
        ),
        (
            "rlopen",
            Frame::new(
                4,
                Message::Rlopen {
                    qid: file_qid,
                    iounit: 8192,
                },
            ),
        ),
        (
            "tlcreate",
            Frame::new(
                5,
                Message::Tlcreate {
                    fid: 2,
                    name: "draft.txt".to_owned(),
                    flags: 0o1,
                    mode: 0o644,
                    gid: 1000,
                },
            ),
        ),
        (
            "rlcreate",
            Frame::new(
                5,
                Message::Rlcreate {
                    qid: file_qid,
                    iounit: 8192,
                },
            ),
        ),
        (
            "tsymlink",
            Frame::new(
                6,
                Message::Tsymlink {
                    fid: 0,
                    name: "shortcut".to_owned(),
                    target: "projects/draft.txt".to_owned(),
                    gid: 1000,
                },
            ),
        ),
        (
            "rsymlink",
            Frame::new(6, Message::Rsymlink { qid: link_qid }),
        ),
        ("treadlink", Frame::new(7, Message::Treadlink { fid: 3 })),
        (
            "rreadlink",
            Frame::new(
                7,
                Message::Rreadlink {
                    target: "projects/draft.txt".to_owned(),
                },
            ),
        ),
        (
            "tgetattr",
            Frame::new(
                8,
                Message::Tgetattr {
                    fid: 1,
                    request_mask: tunnel_fs_ninep::GETATTR_BASIC,
                },
            ),
        ),
        ("rgetattr", Frame::new(8, Message::Rgetattr(attributes))),
        (
            "tsetattr",
            Frame::new(
                9,
                Message::Tsetattr {
                    fid: 1,
                    valid: tunnel_fs_ninep::SETATTR_ALLOWED,
                    mode: 0o600,
                    uid: 0,
                    gid: 0,
                    size: 1_024,
                    atime_sec: 1_770_000_000,
                    atime_nsec: 0,
                    mtime_sec: 1_770_000_001,
                    mtime_nsec: 0,
                },
            ),
        ),
        ("rsetattr", Frame::new(9, Message::Rsetattr)),
        (
            "treaddir",
            Frame::new(
                10,
                Message::Treaddir {
                    fid: 2,
                    offset: 0,
                    count: 4_096,
                },
            ),
        ),
        (
            "rreaddir",
            Frame::new(10, Message::Rreaddir { data: entries }),
        ),
        (
            "tlink",
            Frame::new(
                11,
                Message::Tlink {
                    dfid: 0,
                    fid: 1,
                    name: "hardlink.txt".to_owned(),
                },
            ),
        ),
        ("rlink", Frame::new(11, Message::Rlink)),
        (
            "tmkdir",
            Frame::new(
                12,
                Message::Tmkdir {
                    dfid: 0,
                    name: "archive".to_owned(),
                    mode: 0o755,
                    gid: 1000,
                },
            ),
        ),
        ("rmkdir", Frame::new(12, Message::Rmkdir { qid: dir_qid })),
        (
            "trename",
            Frame::new(
                13,
                Message::Trename {
                    fid: 1,
                    dfid: 0,
                    name: "renamed.txt".to_owned(),
                },
            ),
        ),
        ("rrename", Frame::new(13, Message::Rrename)),
        (
            "trenameat",
            Frame::new(
                14,
                Message::Trenameat {
                    olddirfid: 0,
                    oldname: "draft.txt".to_owned(),
                    newdirfid: 2,
                    newname: "final.txt".to_owned(),
                },
            ),
        ),
        ("rrenameat", Frame::new(14, Message::Rrenameat)),
        (
            "tunlinkat",
            Frame::new(
                15,
                Message::Tunlinkat {
                    dirfid: 0,
                    name: "draft.txt".to_owned(),
                    flags: 0,
                },
            ),
        ),
        (
            "tunlinkat-removedir",
            Frame::new(
                16,
                Message::Tunlinkat {
                    dirfid: 0,
                    name: "archive".to_owned(),
                    flags: tunnel_fs_ninep::AT_REMOVEDIR,
                },
            ),
        ),
        ("runlinkat", Frame::new(15, Message::Runlinkat)),
        (
            "tread",
            Frame::new(
                17,
                Message::Tread {
                    fid: 1,
                    offset: 0x0000_0001_0000_0000,
                    count: 4_096,
                },
            ),
        ),
        (
            "rread",
            Frame::new(
                17,
                Message::Rread {
                    // Every byte value, so a fixture that survived a text
                    // transform somewhere would not compare equal.
                    data: (0..=255u8).collect(),
                },
            ),
        ),
        (
            "twrite",
            Frame::new(
                18,
                Message::Twrite {
                    fid: 1,
                    offset: 0x0000_0001_0000_0000,
                    data: (0..=255u8).rev().collect(),
                },
            ),
        ),
        ("rwrite", Frame::new(18, Message::Rwrite { count: 256 })),
        ("tclunk", Frame::new(19, Message::Tclunk { fid: 1 })),
        ("rclunk", Frame::new(19, Message::Rclunk)),
        ("tremove", Frame::new(20, Message::Tremove { fid: 2 })),
        ("rremove", Frame::new(20, Message::Rremove)),
        (
            "rlerror-enoent",
            Frame::new(
                21,
                Message::Rlerror {
                    code: FsErrorCode::Enoent,
                },
            ),
        ),
        (
            "rlerror-eperm",
            Frame::new(
                22,
                Message::Rlerror {
                    code: FsErrorCode::Eperm,
                },
            ),
        ),
    ]
}

/// The bytes of one fixture file, ignoring `#` comment lines and whitespace.
pub fn read_fixture(stem: &str) -> Vec<u8> {
    let path = fixture_dir().join(format!("{stem}.hex"));
    let text =
        std::fs::read_to_string(&path).unwrap_or_else(|error| panic!("fixture {stem}: {error}"));
    decode_hex(&text)
}

/// Decode whitespace-separated hex, skipping `#` comment lines.
pub fn decode_hex(text: &str) -> Vec<u8> {
    let mut digits = String::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        digits.extend(line.chars().filter(|character| !character.is_whitespace()));
    }
    assert!(digits.len().is_multiple_of(2), "odd hex digit count");
    (0..digits.len() / 2)
        .map(|index| {
            u8::from_str_radix(&digits[index * 2..index * 2 + 2], 16).expect("fixture hex digit")
        })
        .collect()
}

/// Render bytes as the fixture file's 32-bytes-per-line hex body.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::new();
    for chunk in bytes.chunks(32) {
        for byte in chunk {
            out.push_str(&format!("{byte:02x}"));
        }
        out.push('\n');
    }
    out
}

/// A grant with every capability, for tests about framing rather than
/// authorization.
pub fn full_grant() -> CapabilitySet {
    CapabilitySet::from_slice(&[
        Capability::Read,
        Capability::Write,
        Capability::List,
        Capability::Delete,
    ])
}

/// Every optional feature, for the same reason.
pub fn all_features() -> FeatureSet {
    FeatureSet::from_slice(&[
        Feature::AtomicRename,
        Feature::NativeAppend,
        Feature::ExclusiveCreate,
        Feature::Symlinks,
        Feature::HardLinks,
        Feature::BirthTime,
        Feature::Fsync,
    ])
}

/// A session with every capability and feature, still in `AwaitingVersion`.
pub fn session() -> Session {
    Session::new(full_grant(), all_features(), Limits::PROFILE_DEFAULT)
        .expect("a non-empty grant admits a session")
}

/// A session driven through `Tversion` and `Tattach` so it is `Attached` with
/// fid 0 bound to the root.
pub fn attached_session() -> Session {
    let mut session = session();
    version_handshake(&mut session);
    attach(&mut session, 0, 1);
    session
}

/// Run the version handshake on `session`.
pub fn version_handshake(session: &mut Session) {
    let request = Frame::new(
        NOTAG,
        Message::Tversion {
            msize: FIXTURE_MSIZE,
            version: "9P2000.L".to_owned(),
        },
    );
    session.request(&request).expect("Tversion admitted");
    let reply = session.version_reply().expect("a pending Rversion");
    session.complete(&reply).expect("Rversion accepted");
}

/// Attach `fid` to the root under `tag`.
pub fn attach(session: &mut Session, fid: u32, tag: u16) {
    let request = Frame::new(
        tag,
        Message::Tattach {
            fid,
            afid: NOFID,
            uname: String::new(),
            aname: String::new(),
            n_uname: NONUNAME,
        },
    );
    session.request(&request).expect("Tattach admitted");
    session
        .complete(&Frame::new(
            tag,
            Message::Rattach {
                qid: Qid::new(QidKind::Directory, 1),
            },
        ))
        .expect("Rattach accepted");
}

/// Walk `names` from `fid` to `newfid`, answering with `kind` qids.
pub fn walk(session: &mut Session, tag: u16, fid: u32, newfid: u32, names: &[&str], kind: QidKind) {
    let request = Frame::new(
        tag,
        Message::Twalk {
            fid,
            newfid,
            names: names.iter().map(|name| (*name).to_owned()).collect(),
        },
    );
    session.request(&request).expect("Twalk admitted");
    let qids = (0..names.len())
        .map(|index| {
            let leaf = index + 1 == names.len();
            Qid::new(
                if leaf { kind } else { QidKind::Directory },
                100 + index as u64,
            )
        })
        .collect();
    session
        .complete(&Frame::new(tag, Message::Rwalk { qids }))
        .expect("Rwalk accepted");
}

/// Open `fid` with `flags`, answering with a qid of `kind`.
pub fn open(session: &mut Session, tag: u16, fid: u32, flags: u32, kind: QidKind) {
    session
        .request(&Frame::new(tag, Message::Tlopen { fid, flags }))
        .expect("Tlopen admitted");
    session
        .complete(&Frame::new(
            tag,
            Message::Rlopen {
                qid: Qid::new(kind, 42),
                iounit: 0,
            },
        ))
        .expect("Rlopen accepted");
}

/// Every message type the profile defines, for exhaustiveness assertions.
pub fn all_message_types() -> Vec<MessageType> {
    MessageType::ALL.to_vec()
}

/// Build a raw frame by hand: `size[4] type[1] tag[2] body`, with the size
/// filled in from the actual length.
///
/// The tests use this to construct frames the encoder would refuse, which is
/// the only way to prove the decoder refuses them too.
pub fn raw_frame(type_code: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let size = u32::try_from(7 + body.len()).expect("test frame fits u32");
    raw_frame_with_size(size, type_code, tag, body)
}

/// The same, with a deliberately wrong declared size.
pub fn raw_frame_with_size(size: u32, type_code: u8, tag: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&size.to_le_bytes());
    out.push(type_code);
    out.extend_from_slice(&tag.to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// A `string[s]` with arbitrary, possibly non-UTF-8, bytes.
pub fn raw_string(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let len = u16::try_from(bytes.len()).expect("test string fits u16");
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(bytes);
    out
}

/// A lone continuation byte after an ASCII one: never valid UTF-8.
pub const INVALID_UTF8: [u8; 2] = [0x61, 0x80];

/// Split `bytes` into one-byte chunks.
pub fn one_byte_chunks(bytes: &[u8]) -> Vec<&[u8]> {
    bytes.chunks(1).collect()
}

/// Feed `chunks` to a fresh [`FrameDecoder`] bounded by `msize`, returning the
/// frames decoded and the first error.
pub fn decode_chunks(chunks: &[&[u8]], msize: u32) -> (Vec<Frame>, Option<CodecError>) {
    let mut decoder = FrameDecoder::with_msize(msize);
    let mut frames = Vec::new();
    for chunk in chunks {
        let mut input = *chunk;
        loop {
            match decoder.decode(&mut input) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => {
                    assert!(input.is_empty(), "decoder stopped with unread input");
                    break;
                }
                Err(error) => return (frames, Some(error)),
            }
        }
        assert!(
            decoder.retained_len() <= msize as usize,
            "decoder retained more than msize"
        );
    }
    (frames, None)
}

/// As [`decode_chunks`], but also reporting the end of the stream, so a frame
/// left half-received is `TruncatedBody` rather than silently absent.
pub fn decode_chunks_fin(chunks: &[&[u8]], msize: u32) -> (Vec<Frame>, Option<CodecError>) {
    let mut decoder = FrameDecoder::with_msize(msize);
    let mut frames = Vec::new();
    for chunk in chunks {
        let mut input = *chunk;
        loop {
            match decoder.decode(&mut input) {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break,
                Err(error) => return (frames, Some(error)),
            }
        }
        assert!(decoder.retained_len() <= msize as usize);
    }
    match decoder.fin() {
        Ok(()) => (frames, None),
        Err(error) => (frames, Some(error)),
    }
}

/// A deterministic xorshift64* generator; no external dependency, the same
/// shape gate 1 and the M3 codec use.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed.max(1))
    }

    pub fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    pub fn below(&mut self, bound: usize) -> usize {
        usize::try_from(self.next_u64() % bound.max(1) as u64).unwrap_or(0)
    }

    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        (0..len).map(|_| self.next_u64() as u8).collect()
    }
}
