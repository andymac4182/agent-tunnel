//! The message set this profile implements, and its exact body layout.
//!
//! The opcode numbers and field orders follow the pinned 9P2000.L reference
//! `docs/testing.md` names.  Only the messages the contract's primitive
//! authorization table needs are here; every other 9P or 9P2000.L opcode is
//! refused, and the two ways of being refused are kept apart:
//!
//! * A **known** 9P2000.L opcode outside this profile — `Tstatfs`, `Tmknod`,
//!   `Txattrwalk`, `Txattrcreate`, `Tfsync`, `Tlock`, `Tgetlock`, `Tauth` — is
//!   [`CodecError::MessageTypeNotInProfile`].  So are the plain-9P2000 opcodes
//!   `Topen`, `Tcreate`, `Tstat`, `Twstat` and `Rerror`, which a client that
//!   negotiated the wrong dialect would send.
//! * Anything else is [`CodecError::UnknownMessageType`].
//!
//! `Tauth` is in the first group rather than simply unimplemented: the contract
//! says "No custom `Tauth` bearer-token scheme", and an export that answered
//! `Tauth` at all would be advertising an authentication path that does not
//! exist.

use tunnel_fs_core::FsErrorCode;

use crate::error::{CodecError, StringField};
use crate::wire::{MAX_WALK_NAMES, Qid, Reader, Writer};

/// A message type in this profile.
///
/// The discriminant is the wire `type[1]` byte.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[repr(u8)]
pub enum MessageType {
    /// A `.L` error reply, carrying a Linux errno.
    Rlerror = 7,
    /// Open an existing file or directory.
    Tlopen = 12,
    /// Reply to [`MessageType::Tlopen`].
    Rlopen = 13,
    /// Create a regular file.
    Tlcreate = 14,
    /// Reply to [`MessageType::Tlcreate`].
    Rlcreate = 15,
    /// Create a symbolic link.
    Tsymlink = 16,
    /// Reply to [`MessageType::Tsymlink`].
    Rsymlink = 17,
    /// Rename a fid into a directory fid under a new name.
    Trename = 20,
    /// Reply to [`MessageType::Trename`].
    Rrename = 21,
    /// Read a symbolic-link target.
    Treadlink = 22,
    /// Reply to [`MessageType::Treadlink`].
    Rreadlink = 23,
    /// Read metadata.
    Tgetattr = 24,
    /// Reply to [`MessageType::Tgetattr`].
    Rgetattr = 25,
    /// Change metadata.
    Tsetattr = 26,
    /// Reply to [`MessageType::Tsetattr`].
    Rsetattr = 27,
    /// Enumerate a directory.
    Treaddir = 40,
    /// Reply to [`MessageType::Treaddir`].
    Rreaddir = 41,
    /// Create a hard link.
    Tlink = 70,
    /// Reply to [`MessageType::Tlink`].
    Rlink = 71,
    /// Create a directory.
    Tmkdir = 72,
    /// Reply to [`MessageType::Tmkdir`].
    Rmkdir = 73,
    /// Rename between two directory fids.
    Trenameat = 74,
    /// Reply to [`MessageType::Trenameat`].
    Rrenameat = 75,
    /// Remove a name from a directory fid.
    Tunlinkat = 76,
    /// Reply to [`MessageType::Tunlinkat`].
    Runlinkat = 77,
    /// Negotiate the dialect and `msize`.
    Tversion = 100,
    /// Reply to [`MessageType::Tversion`].
    Rversion = 101,
    /// Bind the session to its export root.
    Tattach = 104,
    /// Reply to [`MessageType::Tattach`].
    Rattach = 105,
    /// Cancel an outstanding request.
    Tflush = 108,
    /// Reply to [`MessageType::Tflush`].
    Rflush = 109,
    /// Traverse names from a fid.
    Twalk = 110,
    /// Reply to [`MessageType::Twalk`].
    Rwalk = 111,
    /// Read bytes.
    Tread = 116,
    /// Reply to [`MessageType::Tread`].
    Rread = 117,
    /// Write bytes.
    Twrite = 118,
    /// Reply to [`MessageType::Twrite`].
    Rwrite = 119,
    /// Release a fid.
    Tclunk = 120,
    /// Reply to [`MessageType::Tclunk`].
    Rclunk = 121,
    /// Remove the file a fid names and release the fid.
    Tremove = 122,
    /// Reply to [`MessageType::Tremove`].
    Rremove = 123,
}

/// Known 9P and 9P2000.L opcodes this profile deliberately does not implement.
///
/// Listed so a peer using one is told it reached for a real opcode the profile
/// denies, rather than being told its byte means nothing.
pub const KNOWN_OUTSIDE_PROFILE: [u8; 25] = [
    8, 9, // Tstatfs / Rstatfs
    18, 19, // Tmknod / Rmknod
    30, 31, // Txattrwalk / Rxattrwalk
    32, 33, // Txattrcreate / Rxattrcreate
    50, 51, // Tfsync / Rfsync
    52, 53, // Tlock / Rlock
    54, 55, // Tgetlock / Rgetlock
    102, 103, // Tauth / Rauth — no custom bearer-token scheme
    // The plain-9P2000 opcodes, **both** directions of each: a peer that
    // negotiated the wrong dialect sends the request, and a client reading a
    // wrongly-configured server's stream sees the reply.
    107, // Rerror
    112, 113, // Topen / Ropen
    114, 115, // Tcreate / Rcreate
    124, 125, // Tstat / Rstat
    126, 127, // Twstat / Rwstat
];

impl MessageType {
    /// Every type in this profile, in wire order.
    pub const ALL: [Self; 41] = [
        Self::Rlerror,
        Self::Tlopen,
        Self::Rlopen,
        Self::Tlcreate,
        Self::Rlcreate,
        Self::Tsymlink,
        Self::Rsymlink,
        Self::Trename,
        Self::Rrename,
        Self::Treadlink,
        Self::Rreadlink,
        Self::Tgetattr,
        Self::Rgetattr,
        Self::Tsetattr,
        Self::Rsetattr,
        Self::Treaddir,
        Self::Rreaddir,
        Self::Tlink,
        Self::Rlink,
        Self::Tmkdir,
        Self::Rmkdir,
        Self::Trenameat,
        Self::Rrenameat,
        Self::Tunlinkat,
        Self::Runlinkat,
        Self::Tversion,
        Self::Rversion,
        Self::Tattach,
        Self::Rattach,
        Self::Tflush,
        Self::Rflush,
        Self::Twalk,
        Self::Rwalk,
        Self::Tread,
        Self::Rread,
        Self::Twrite,
        Self::Rwrite,
        Self::Tclunk,
        Self::Rclunk,
        Self::Tremove,
        Self::Rremove,
    ];

    /// The wire `type[1]` byte.
    #[must_use]
    pub const fn code(self) -> u8 {
        self as u8
    }

    /// The diagnostic spelling, which is the message's 9P name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rlerror => "Rlerror",
            Self::Tlopen => "Tlopen",
            Self::Rlopen => "Rlopen",
            Self::Tlcreate => "Tlcreate",
            Self::Rlcreate => "Rlcreate",
            Self::Tsymlink => "Tsymlink",
            Self::Rsymlink => "Rsymlink",
            Self::Trename => "Trename",
            Self::Rrename => "Rrename",
            Self::Treadlink => "Treadlink",
            Self::Rreadlink => "Rreadlink",
            Self::Tgetattr => "Tgetattr",
            Self::Rgetattr => "Rgetattr",
            Self::Tsetattr => "Tsetattr",
            Self::Rsetattr => "Rsetattr",
            Self::Treaddir => "Treaddir",
            Self::Rreaddir => "Rreaddir",
            Self::Tlink => "Tlink",
            Self::Rlink => "Rlink",
            Self::Tmkdir => "Tmkdir",
            Self::Rmkdir => "Rmkdir",
            Self::Trenameat => "Trenameat",
            Self::Rrenameat => "Rrenameat",
            Self::Tunlinkat => "Tunlinkat",
            Self::Runlinkat => "Runlinkat",
            Self::Tversion => "Tversion",
            Self::Rversion => "Rversion",
            Self::Tattach => "Tattach",
            Self::Rattach => "Rattach",
            Self::Tflush => "Tflush",
            Self::Rflush => "Rflush",
            Self::Twalk => "Twalk",
            Self::Rwalk => "Rwalk",
            Self::Tread => "Tread",
            Self::Rread => "Rread",
            Self::Twrite => "Twrite",
            Self::Rwrite => "Rwrite",
            Self::Tclunk => "Tclunk",
            Self::Rclunk => "Rclunk",
            Self::Tremove => "Tremove",
            Self::Rremove => "Rremove",
        }
    }

    /// Whether this is a request rather than a reply.
    ///
    /// 9P encodes the direction in the opcode's low bit: requests are even,
    /// replies odd.  `Rlerror` (7) is a reply and follows the same rule.
    #[must_use]
    pub const fn is_request(self) -> bool {
        (self as u8).is_multiple_of(2)
    }

    /// Decode a `type[1]` byte.
    ///
    /// # Errors
    ///
    /// [`CodecError::MessageTypeNotInProfile`] for a real 9P2000.L opcode this
    /// profile denies, and [`CodecError::UnknownMessageType`] otherwise.
    pub fn from_code(code: u8) -> Result<Self, CodecError> {
        if let Some(found) = Self::ALL.into_iter().find(|value| value.code() == code) {
            return Ok(found);
        }
        // Reported as a real opcode the profile denies only when it is one.
        // The two branches carry different information and the distinction is
        // static protocol knowledge, so it discloses nothing about the export.
        if KNOWN_OUTSIDE_PROFILE.contains(&code) {
            return Err(CodecError::MessageTypeNotInProfile(code));
        }
        Err(CodecError::UnknownMessageType(code))
    }
}

impl core::fmt::Display for MessageType {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The `Rgetattr` body, which is large enough to deserve its own type.
///
/// Every field is the width 9P2000.L gives it; the 64-bit times and sizes are
/// the reason the contract tells a JavaScript client to "decode 64-bit fields
/// as BigInt".
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Attributes {
    /// Which fields below the provider actually filled in.
    pub valid: u64,
    /// The node's qid.
    pub qid: Qid,
    /// POSIX mode bits including the file type.
    pub mode: u32,
    /// Owner uid, as the provider chooses to present it.
    pub uid: u32,
    /// Owner gid, as the provider chooses to present it.
    pub gid: u32,
    /// Hard-link count.  Gate 2's write rule is stated in terms of this.
    pub nlink: u64,
    /// Device number for a device node; zero for everything this profile serves.
    pub rdev: u64,
    /// Size in bytes.
    pub size: u64,
    /// Preferred block size.
    pub blksize: u64,
    /// Allocated blocks.
    pub blocks: u64,
    /// Access time, seconds.
    pub atime_sec: u64,
    /// Access time, nanoseconds.
    pub atime_nsec: u64,
    /// Modification time, seconds.
    pub mtime_sec: u64,
    /// Modification time, nanoseconds.
    pub mtime_nsec: u64,
    /// Status-change time, seconds.
    pub ctime_sec: u64,
    /// Status-change time, nanoseconds.
    pub ctime_nsec: u64,
    /// Birth time, seconds.  Absent on hosts that do not record one.
    pub btime_sec: u64,
    /// Birth time, nanoseconds.
    pub btime_nsec: u64,
    /// Inode generation number.  The wire field is `gen`, which is a reserved
    /// keyword in this edition, so the field is spelled out.
    pub generation: u64,
    /// Data version counter.
    pub data_version: u64,
}

/// One decoded message body, with its tag carried separately in a [`Frame`].
///
/// Owning rather than borrowing: `msize` bounds every field at 64 KiB, so an
/// owned body is bounded by construction, and the session machine retains
/// names from a `Twalk` after the input buffer is gone.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Message {
    /// `ecode[4]`, restricted to the closed gate-1 vocabulary.
    Rlerror {
        /// The error code.
        code: FsErrorCode,
    },
    /// `msize[4] version[s]`.
    Tversion {
        /// The largest message the sender will send or receive.
        msize: u32,
        /// The offered dialect.
        version: String,
    },
    /// `msize[4] version[s]`.
    Rversion {
        /// The negotiated maximum, never above the offer.
        msize: u32,
        /// The accepted dialect.
        version: String,
    },
    /// `fid[4] afid[4] uname[s] aname[s] n_uname[4]`.
    Tattach {
        /// The fid to bind to the export root.
        fid: u32,
        /// Must be `NOFID`.
        afid: u32,
        /// Must be empty.
        uname: String,
        /// Must be empty.
        aname: String,
        /// Must be `NONUNAME`.
        n_uname: u32,
    },
    /// `qid[13]`.
    Rattach {
        /// The root's qid.
        qid: Qid,
    },
    /// `oldtag[2]`.
    Tflush {
        /// The tag to cancel.
        oldtag: u16,
    },
    /// Empty body.
    Rflush,
    /// `fid[4] newfid[4] nwname[2] nwname*(wname[s])`.
    Twalk {
        /// The fid to walk from.
        fid: u32,
        /// The fid to bind the result to.
        newfid: u32,
        /// At most [`MAX_WALK_NAMES`] names.
        names: Vec<String>,
    },
    /// `nwqid[2] nwqid*(qid[13])`.
    Rwalk {
        /// One qid per name successfully walked; fewer than asked means a
        /// partial walk, and `newfid` is then unbound.
        qids: Vec<Qid>,
    },
    /// `fid[4] flags[4]`.
    Tlopen {
        /// The fid to open.
        fid: u32,
        /// Linux open flags.
        flags: u32,
    },
    /// `qid[13] iounit[4]`.
    Rlopen {
        /// The opened node's qid.
        qid: Qid,
        /// The largest single I/O the provider guarantees, or zero for
        /// "`msize` minus the header".
        iounit: u32,
    },
    /// `fid[4] name[s] flags[4] mode[4] gid[4]`.
    Tlcreate {
        /// The parent directory fid, which becomes the new file's fid.
        fid: u32,
        /// The name to create.
        name: String,
        /// Linux open flags.
        flags: u32,
        /// Permission bits.
        mode: u32,
        /// Group id.
        gid: u32,
    },
    /// `qid[13] iounit[4]`.
    Rlcreate {
        /// The created file's qid.
        qid: Qid,
        /// As [`Message::Rlopen`].
        iounit: u32,
    },
    /// `fid[4] name[s] symtgt[s] gid[4]`.
    Tsymlink {
        /// The parent directory fid.
        fid: u32,
        /// The link's name.
        name: String,
        /// The link's target.
        target: String,
        /// Group id.
        gid: u32,
    },
    /// `qid[13]`.
    Rsymlink {
        /// The created link's qid.
        qid: Qid,
    },
    /// `fid[4]`.
    Treadlink {
        /// The link's fid.
        fid: u32,
    },
    /// `target[s]`.
    Rreadlink {
        /// The link's target, refused if the host's bytes are not UTF-8.
        target: String,
    },
    /// `fid[4] request_mask[8]`.
    Tgetattr {
        /// The fid to inspect.
        fid: u32,
        /// Which fields the caller wants.
        request_mask: u64,
    },
    /// The full attribute reply.
    Rgetattr(Attributes),
    /// `fid[4] valid[4] mode[4] uid[4] gid[4] size[8] atime_sec[8]
    /// atime_nsec[8] mtime_sec[8] mtime_nsec[8]`.
    Tsetattr {
        /// The fid to change.
        fid: u32,
        /// Which fields below are meaningful.
        valid: u32,
        /// New mode bits.
        mode: u32,
        /// New uid.  Outside the accepted mask, so always ignored.
        uid: u32,
        /// New gid.  Outside the accepted mask, so always ignored.
        gid: u32,
        /// New size.
        size: u64,
        /// New access time, seconds.
        atime_sec: u64,
        /// New access time, nanoseconds.
        atime_nsec: u64,
        /// New modification time, seconds.
        mtime_sec: u64,
        /// New modification time, nanoseconds.
        mtime_nsec: u64,
    },
    /// Empty body.
    Rsetattr,
    /// `fid[4] offset[8] count[4]`.
    Treaddir {
        /// The open directory fid.
        fid: u32,
        /// An opaque cookie from a previous entry, or zero to start.
        offset: u64,
        /// The largest reply the caller will accept.
        count: u32,
    },
    /// `count[4] data[count]`, a packed array of directory entries.
    Rreaddir {
        /// The packed entries.  Parse with [`crate::readdir::parse_entries`].
        data: Vec<u8>,
    },
    /// `dfid[4] fid[4] name[s]`.
    Tlink {
        /// The directory the new name goes in.
        dfid: u32,
        /// The existing file.
        fid: u32,
        /// The new name.
        name: String,
    },
    /// Empty body.
    Rlink,
    /// `dfid[4] name[s] mode[4] gid[4]`.
    Tmkdir {
        /// The parent directory fid.
        dfid: u32,
        /// The directory name to create.
        name: String,
        /// Permission bits.
        mode: u32,
        /// Group id.
        gid: u32,
    },
    /// `qid[13]`.
    Rmkdir {
        /// The created directory's qid.
        qid: Qid,
    },
    /// `fid[4] dfid[4] name[s]`.
    Trename {
        /// The file to rename.
        fid: u32,
        /// The destination directory.
        dfid: u32,
        /// The new name.
        name: String,
    },
    /// Empty body.
    Rrename,
    /// `olddirfid[4] oldname[s] newdirfid[4] newname[s]`.
    Trenameat {
        /// The source directory fid.
        olddirfid: u32,
        /// The source name.
        oldname: String,
        /// The destination directory fid.
        newdirfid: u32,
        /// The destination name.
        newname: String,
    },
    /// Empty body.
    Rrenameat,
    /// `dirfid[4] name[s] flags[4]`.
    Tunlinkat {
        /// The directory fid.
        dirfid: u32,
        /// The name to remove.
        name: String,
        /// Zero, or `AT_REMOVEDIR`.
        flags: u32,
    },
    /// Empty body.
    Runlinkat,
    /// `fid[4] offset[8] count[4]`.
    Tread {
        /// The open fid.
        fid: u32,
        /// Byte offset.
        offset: u64,
        /// Bytes requested.
        count: u32,
    },
    /// `count[4] data[count]`.
    Rread {
        /// The bytes read.  A short read is normal and is not an error.
        data: Vec<u8>,
    },
    /// `fid[4] offset[8] count[4] data[count]`.
    Twrite {
        /// The open fid.
        fid: u32,
        /// Byte offset.
        offset: u64,
        /// The bytes to write.
        data: Vec<u8>,
    },
    /// `count[4]`.
    Rwrite {
        /// Bytes actually written.  A short write is normal and is not an
        /// error; the contract's `bytesAcknowledged` is built from these.
        count: u32,
    },
    /// `fid[4]`.
    Tclunk {
        /// The fid to release.
        fid: u32,
    },
    /// Empty body.
    Rclunk,
    /// `fid[4]`.
    Tremove {
        /// The fid to remove and release.
        fid: u32,
    },
    /// Empty body.
    Rremove,
}

impl Message {
    /// This message's type.
    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        match self {
            Self::Rlerror { .. } => MessageType::Rlerror,
            Self::Tversion { .. } => MessageType::Tversion,
            Self::Rversion { .. } => MessageType::Rversion,
            Self::Tattach { .. } => MessageType::Tattach,
            Self::Rattach { .. } => MessageType::Rattach,
            Self::Tflush { .. } => MessageType::Tflush,
            Self::Rflush => MessageType::Rflush,
            Self::Twalk { .. } => MessageType::Twalk,
            Self::Rwalk { .. } => MessageType::Rwalk,
            Self::Tlopen { .. } => MessageType::Tlopen,
            Self::Rlopen { .. } => MessageType::Rlopen,
            Self::Tlcreate { .. } => MessageType::Tlcreate,
            Self::Rlcreate { .. } => MessageType::Rlcreate,
            Self::Tsymlink { .. } => MessageType::Tsymlink,
            Self::Rsymlink { .. } => MessageType::Rsymlink,
            Self::Treadlink { .. } => MessageType::Treadlink,
            Self::Rreadlink { .. } => MessageType::Rreadlink,
            Self::Tgetattr { .. } => MessageType::Tgetattr,
            Self::Rgetattr(_) => MessageType::Rgetattr,
            Self::Tsetattr { .. } => MessageType::Tsetattr,
            Self::Rsetattr => MessageType::Rsetattr,
            Self::Treaddir { .. } => MessageType::Treaddir,
            Self::Rreaddir { .. } => MessageType::Rreaddir,
            Self::Tlink { .. } => MessageType::Tlink,
            Self::Rlink => MessageType::Rlink,
            Self::Tmkdir { .. } => MessageType::Tmkdir,
            Self::Rmkdir { .. } => MessageType::Rmkdir,
            Self::Trename { .. } => MessageType::Trename,
            Self::Rrename => MessageType::Rrename,
            Self::Trenameat { .. } => MessageType::Trenameat,
            Self::Rrenameat => MessageType::Rrenameat,
            Self::Tunlinkat { .. } => MessageType::Tunlinkat,
            Self::Runlinkat => MessageType::Runlinkat,
            Self::Tread { .. } => MessageType::Tread,
            Self::Rread { .. } => MessageType::Rread,
            Self::Twrite { .. } => MessageType::Twrite,
            Self::Rwrite { .. } => MessageType::Rwrite,
            Self::Tclunk { .. } => MessageType::Tclunk,
            Self::Rclunk => MessageType::Rclunk,
            Self::Tremove { .. } => MessageType::Tremove,
            Self::Rremove => MessageType::Rremove,
        }
    }

    /// Whether this is a request.
    #[must_use]
    pub const fn is_request(&self) -> bool {
        self.message_type().is_request()
    }

    /// Append this message's body to `writer`.
    ///
    /// # Errors
    /// [`CodecError::StringTooLong`] for a string beyond the 16-bit prefix, and
    /// [`CodecError::TooManyWalkNames`] for an over-long `Twalk`.
    #[allow(clippy::too_many_lines)]
    pub fn encode_body(&self, writer: &mut Writer<'_>) -> Result<(), CodecError> {
        use StringField as F;
        match self {
            Self::Rlerror { code } => writer.u32(code.errno()),
            Self::Tversion { msize, version } | Self::Rversion { msize, version } => {
                writer.u32(*msize);
                writer.string(F::Version, version)?;
            }
            Self::Tattach {
                fid,
                afid,
                uname,
                aname,
                n_uname,
            } => {
                writer.u32(*fid);
                writer.u32(*afid);
                writer.string(F::Uname, uname)?;
                writer.string(F::Aname, aname)?;
                writer.u32(*n_uname);
            }
            Self::Rattach { qid } | Self::Rsymlink { qid } | Self::Rmkdir { qid } => {
                writer.qid(*qid)
            }
            Self::Tflush { oldtag } => writer.u16(*oldtag),
            Self::Rflush
            | Self::Rsetattr
            | Self::Rlink
            | Self::Rrename
            | Self::Rrenameat
            | Self::Runlinkat
            | Self::Rclunk
            | Self::Rremove => {}
            Self::Twalk { fid, newfid, names } => {
                if names.len() > MAX_WALK_NAMES {
                    return Err(CodecError::TooManyWalkNames);
                }
                writer.u32(*fid);
                writer.u32(*newfid);
                writer.u16(u16::try_from(names.len()).map_err(|_| CodecError::TooManyWalkNames)?);
                for name in names {
                    writer.string(F::WalkName, name)?;
                }
            }
            Self::Rwalk { qids } => {
                if qids.len() > MAX_WALK_NAMES {
                    return Err(CodecError::TooManyWalkNames);
                }
                writer.u16(u16::try_from(qids.len()).map_err(|_| CodecError::TooManyWalkNames)?);
                for qid in qids {
                    writer.qid(*qid);
                }
            }
            Self::Tlopen { fid, flags } => {
                writer.u32(*fid);
                writer.u32(*flags);
            }
            Self::Rlopen { qid, iounit } | Self::Rlcreate { qid, iounit } => {
                writer.qid(*qid);
                writer.u32(*iounit);
            }
            Self::Tlcreate {
                fid,
                name,
                flags,
                mode,
                gid,
            } => {
                writer.u32(*fid);
                writer.string(F::Name, name)?;
                writer.u32(*flags);
                writer.u32(*mode);
                writer.u32(*gid);
            }
            Self::Tsymlink {
                fid,
                name,
                target,
                gid,
            } => {
                writer.u32(*fid);
                writer.string(F::Name, name)?;
                writer.string(F::SymlinkTarget, target)?;
                writer.u32(*gid);
            }
            Self::Treadlink { fid } | Self::Tclunk { fid } | Self::Tremove { fid } => {
                writer.u32(*fid)
            }
            Self::Rreadlink { target } => writer.string(F::LinkTarget, target)?,
            Self::Tgetattr { fid, request_mask } => {
                writer.u32(*fid);
                writer.u64(*request_mask);
            }
            Self::Rgetattr(attributes) => encode_attributes(writer, attributes),
            Self::Tsetattr {
                fid,
                valid,
                mode,
                uid,
                gid,
                size,
                atime_sec,
                atime_nsec,
                mtime_sec,
                mtime_nsec,
            } => {
                writer.u32(*fid);
                writer.u32(*valid);
                writer.u32(*mode);
                writer.u32(*uid);
                writer.u32(*gid);
                writer.u64(*size);
                writer.u64(*atime_sec);
                writer.u64(*atime_nsec);
                writer.u64(*mtime_sec);
                writer.u64(*mtime_nsec);
            }
            Self::Treaddir { fid, offset, count } | Self::Tread { fid, offset, count } => {
                writer.u32(*fid);
                writer.u64(*offset);
                writer.u32(*count);
            }
            Self::Rreaddir { data } | Self::Rread { data } => {
                // `data` is bounded by `msize`, checked before a frame is
                // written, so this cast cannot truncate a legal message.
                writer.u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
                writer.raw(data);
            }
            Self::Tlink { dfid, fid, name } => {
                writer.u32(*dfid);
                writer.u32(*fid);
                writer.string(F::Name, name)?;
            }
            Self::Tmkdir {
                dfid,
                name,
                mode,
                gid,
            } => {
                writer.u32(*dfid);
                writer.string(F::Name, name)?;
                writer.u32(*mode);
                writer.u32(*gid);
            }
            Self::Trename { fid, dfid, name } => {
                writer.u32(*fid);
                writer.u32(*dfid);
                writer.string(F::Name, name)?;
            }
            Self::Trenameat {
                olddirfid,
                oldname,
                newdirfid,
                newname,
            } => {
                writer.u32(*olddirfid);
                writer.string(F::OldName, oldname)?;
                writer.u32(*newdirfid);
                writer.string(F::NewName, newname)?;
            }
            Self::Tunlinkat {
                dirfid,
                name,
                flags,
            } => {
                writer.u32(*dirfid);
                writer.string(F::Name, name)?;
                writer.u32(*flags);
            }
            Self::Twrite { fid, offset, data } => {
                writer.u32(*fid);
                writer.u64(*offset);
                writer.u32(u32::try_from(data.len()).unwrap_or(u32::MAX));
                writer.raw(data);
            }
            Self::Rwrite { count } => writer.u32(*count),
        }
        Ok(())
    }

    /// Decode a body of the given type, requiring the body to be fully
    /// consumed.
    ///
    /// # Errors
    ///
    /// Every [`CodecError`] the field rules can produce, and in particular
    /// [`CodecError::TrailingBytes`] when the declared size left bytes over and
    /// [`CodecError::TruncatedBody`] when it left too few.
    #[allow(clippy::too_many_lines)]
    pub fn decode_body(message_type: MessageType, body: &[u8]) -> Result<Self, CodecError> {
        use StringField as F;
        let reader = &mut Reader::new(body);
        let message = match message_type {
            MessageType::Rlerror => {
                let errno = reader.u32()?;
                let code = FsErrorCode::ALL
                    .into_iter()
                    .find(|candidate| candidate.errno() == errno)
                    .ok_or(CodecError::ErrnoNotInVocabulary)?;
                Self::Rlerror { code }
            }
            MessageType::Tversion => Self::Tversion {
                msize: reader.u32()?,
                version: reader.string(F::Version)?.to_owned(),
            },
            MessageType::Rversion => Self::Rversion {
                msize: reader.u32()?,
                version: reader.string(F::Version)?.to_owned(),
            },
            MessageType::Tattach => Self::Tattach {
                fid: reader.u32()?,
                afid: reader.u32()?,
                uname: reader.string(F::Uname)?.to_owned(),
                aname: reader.string(F::Aname)?.to_owned(),
                n_uname: reader.u32()?,
            },
            MessageType::Rattach => Self::Rattach { qid: reader.qid()? },
            MessageType::Tflush => Self::Tflush {
                oldtag: reader.u16()?,
            },
            MessageType::Rflush => Self::Rflush,
            MessageType::Twalk => {
                let fid = reader.u32()?;
                let newfid = reader.u32()?;
                let count = usize::from(reader.u16()?);
                if count > MAX_WALK_NAMES {
                    return Err(CodecError::TooManyWalkNames);
                }
                // Bounded by MAX_WALK_NAMES before a single element is
                // reserved, so a declared count cannot drive an allocation.
                let mut names = Vec::with_capacity(count);
                for _ in 0..count {
                    names.push(reader.string(F::WalkName)?.to_owned());
                }
                Self::Twalk { fid, newfid, names }
            }
            MessageType::Rwalk => {
                let count = usize::from(reader.u16()?);
                if count > MAX_WALK_NAMES {
                    return Err(CodecError::TooManyWalkNames);
                }
                let mut qids = Vec::with_capacity(count);
                for _ in 0..count {
                    qids.push(reader.qid()?);
                }
                Self::Rwalk { qids }
            }
            MessageType::Tlopen => Self::Tlopen {
                fid: reader.u32()?,
                flags: reader.u32()?,
            },
            MessageType::Rlopen => Self::Rlopen {
                qid: reader.qid()?,
                iounit: reader.u32()?,
            },
            MessageType::Tlcreate => Self::Tlcreate {
                fid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
                flags: reader.u32()?,
                mode: reader.u32()?,
                gid: reader.u32()?,
            },
            MessageType::Rlcreate => Self::Rlcreate {
                qid: reader.qid()?,
                iounit: reader.u32()?,
            },
            MessageType::Tsymlink => Self::Tsymlink {
                fid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
                target: reader.string(F::SymlinkTarget)?.to_owned(),
                gid: reader.u32()?,
            },
            MessageType::Rsymlink => Self::Rsymlink { qid: reader.qid()? },
            MessageType::Treadlink => Self::Treadlink { fid: reader.u32()? },
            MessageType::Rreadlink => Self::Rreadlink {
                target: reader.string(F::LinkTarget)?.to_owned(),
            },
            MessageType::Tgetattr => Self::Tgetattr {
                fid: reader.u32()?,
                request_mask: reader.u64()?,
            },
            MessageType::Rgetattr => Self::Rgetattr(decode_attributes(reader)?),
            MessageType::Tsetattr => Self::Tsetattr {
                fid: reader.u32()?,
                valid: reader.u32()?,
                mode: reader.u32()?,
                uid: reader.u32()?,
                gid: reader.u32()?,
                size: reader.u64()?,
                atime_sec: reader.u64()?,
                atime_nsec: reader.u64()?,
                mtime_sec: reader.u64()?,
                mtime_nsec: reader.u64()?,
            },
            MessageType::Rsetattr => Self::Rsetattr,
            MessageType::Treaddir => Self::Treaddir {
                fid: reader.u32()?,
                offset: reader.u64()?,
                count: reader.u32()?,
            },
            MessageType::Rreaddir => Self::Rreaddir {
                data: read_counted(reader)?,
            },
            MessageType::Tlink => Self::Tlink {
                dfid: reader.u32()?,
                fid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
            },
            MessageType::Rlink => Self::Rlink,
            MessageType::Tmkdir => Self::Tmkdir {
                dfid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
                mode: reader.u32()?,
                gid: reader.u32()?,
            },
            MessageType::Rmkdir => Self::Rmkdir { qid: reader.qid()? },
            MessageType::Trename => Self::Trename {
                fid: reader.u32()?,
                dfid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
            },
            MessageType::Rrename => Self::Rrename,
            MessageType::Trenameat => Self::Trenameat {
                olddirfid: reader.u32()?,
                oldname: reader.string(F::OldName)?.to_owned(),
                newdirfid: reader.u32()?,
                newname: reader.string(F::NewName)?.to_owned(),
            },
            MessageType::Rrenameat => Self::Rrenameat,
            MessageType::Tunlinkat => Self::Tunlinkat {
                dirfid: reader.u32()?,
                name: reader.string(F::Name)?.to_owned(),
                flags: reader.u32()?,
            },
            MessageType::Runlinkat => Self::Runlinkat,
            MessageType::Tread => Self::Tread {
                fid: reader.u32()?,
                offset: reader.u64()?,
                count: reader.u32()?,
            },
            MessageType::Rread => Self::Rread {
                data: read_counted(reader)?,
            },
            MessageType::Twrite => Self::Twrite {
                fid: reader.u32()?,
                offset: reader.u64()?,
                data: read_counted(reader)?,
            },
            MessageType::Rwrite => Self::Rwrite {
                count: reader.u32()?,
            },
            MessageType::Tclunk => Self::Tclunk { fid: reader.u32()? },
            MessageType::Rclunk => Self::Rclunk,
            MessageType::Tremove => Self::Tremove { fid: reader.u32()? },
            MessageType::Rremove => Self::Rremove,
        };
        reader.finish()?;
        Ok(message)
    }
}

/// Read a `count[4] data[count]` pair.
///
/// The declared count is checked against the bytes actually present **before**
/// anything is reserved, so an over-declared count cannot drive an allocation:
/// the body itself is already bounded by `msize`.
fn read_counted(reader: &mut Reader<'_>) -> Result<Vec<u8>, CodecError> {
    let count = usize::try_from(reader.u32()?).unwrap_or(usize::MAX);
    if count > reader.remaining() {
        return Err(CodecError::TruncatedBody);
    }
    Ok(reader.raw(count)?.to_vec())
}

fn encode_attributes(writer: &mut Writer<'_>, attributes: &Attributes) {
    writer.u64(attributes.valid);
    writer.qid(attributes.qid);
    writer.u32(attributes.mode);
    writer.u32(attributes.uid);
    writer.u32(attributes.gid);
    for value in [
        attributes.nlink,
        attributes.rdev,
        attributes.size,
        attributes.blksize,
        attributes.blocks,
        attributes.atime_sec,
        attributes.atime_nsec,
        attributes.mtime_sec,
        attributes.mtime_nsec,
        attributes.ctime_sec,
        attributes.ctime_nsec,
        attributes.btime_sec,
        attributes.btime_nsec,
        attributes.generation,
        attributes.data_version,
    ] {
        writer.u64(value);
    }
}

fn decode_attributes(reader: &mut Reader<'_>) -> Result<Attributes, CodecError> {
    Ok(Attributes {
        valid: reader.u64()?,
        qid: reader.qid()?,
        mode: reader.u32()?,
        uid: reader.u32()?,
        gid: reader.u32()?,
        nlink: reader.u64()?,
        rdev: reader.u64()?,
        size: reader.u64()?,
        blksize: reader.u64()?,
        blocks: reader.u64()?,
        atime_sec: reader.u64()?,
        atime_nsec: reader.u64()?,
        mtime_sec: reader.u64()?,
        mtime_nsec: reader.u64()?,
        ctime_sec: reader.u64()?,
        ctime_nsec: reader.u64()?,
        btime_sec: reader.u64()?,
        btime_nsec: reader.u64()?,
        generation: reader.u64()?,
        data_version: reader.u64()?,
    })
}
