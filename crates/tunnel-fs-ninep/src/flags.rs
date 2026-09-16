//! `.L` flag and mask decoding, and the primitives each combination requires.
//!
//! `docs/filesystem-api.md` requires the `.L` flags to be **decoded
//! explicitly** — "check read vs write access, create/exclusive/truncate/append
//! permissions and node type before opening or changing anything" — and gate 1
//! already split `Tlopen` into four separate authorization decisions.  This
//! module is where a flag word becomes those decisions.
//!
//! The numeric values are **Linux's**, not the host's.  9P2000.L carries Linux
//! flag and errno numbers on the wire whatever operating system serves it, the
//! same reason gate 2 refuses to translate a host errno through
//! `FsErrorCode::from_errno`.  They are written out here rather than taken from
//! a libc binding so a macOS build and a Linux build agree byte for byte.
//!
//! Everything outside the allowed mask is **refused**, never ignored.  A flag
//! that is accepted and then not implemented is the failure mode the contract's
//! "deny unless the negotiated profile specifies, implements and tests them"
//! exists to prevent.

use tunnel_fs_core::Primitive;

use crate::error::SessionError;

/// `O_RDONLY`.
pub const O_RDONLY: u32 = 0o0;
/// `O_WRONLY`.
pub const O_WRONLY: u32 = 0o1;
/// `O_RDWR`.
pub const O_RDWR: u32 = 0o2;
/// The access-mode field of an open flag word.
pub const O_ACCMODE: u32 = 0o3;
/// `O_CREAT`.  Refused on `Tlopen`: creation is `Tlcreate`.
pub const O_CREAT: u32 = 0o100;
/// `O_EXCL`.
pub const O_EXCL: u32 = 0o200;
/// `O_TRUNC`.
pub const O_TRUNC: u32 = 0o1000;
/// `O_APPEND`.
pub const O_APPEND: u32 = 0o2000;
/// `O_DIRECTORY`.
pub const O_DIRECTORY: u32 = 0o200_000;
/// `O_NOFOLLOW`.
pub const O_NOFOLLOW: u32 = 0o400_000;

/// Every `Tlopen` flag bit this profile accepts.
///
/// `O_NOFOLLOW` is in the mask because gate 2's resolver applies it to every
/// open unconditionally, so honouring a client that asks for it is not a
/// widening — it is already true.  `O_CREAT`, `O_EXCL`, `O_CLOEXEC`, `O_SYNC`,
/// `O_DIRECT`, `O_NOATIME` and every other bit are refused.
pub const OPEN_FLAGS_ALLOWED: u32 = O_ACCMODE | O_TRUNC | O_APPEND | O_DIRECTORY | O_NOFOLLOW;

/// Every `Tlcreate` flag bit this profile accepts.
///
/// `Tlcreate` always creates, so `O_CREAT` is implicit and must not be set
/// explicitly; `O_EXCL` selects exclusive creation, which is the contract's
/// `overwrite:false`, and `O_DIRECTORY` is meaningless on a call that creates a
/// regular file.
pub const CREATE_FLAGS_ALLOWED: u32 = O_ACCMODE | O_TRUNC | O_APPEND | O_EXCL;

/// `Tsetattr` `valid` bit for `mode`.
pub const SETATTR_MODE: u32 = 0x0000_0001;
/// `Tsetattr` `valid` bit for `uid`.  Refused: ownership is not settable.
pub const SETATTR_UID: u32 = 0x0000_0002;
/// `Tsetattr` `valid` bit for `gid`.  Refused: ownership is not settable.
pub const SETATTR_GID: u32 = 0x0000_0004;
/// `Tsetattr` `valid` bit for `size`.
pub const SETATTR_SIZE: u32 = 0x0000_0008;
/// `Tsetattr` `valid` bit: set atime to now.
pub const SETATTR_ATIME: u32 = 0x0000_0010;
/// `Tsetattr` `valid` bit: set mtime to now.
pub const SETATTR_MTIME: u32 = 0x0000_0020;
/// `Tsetattr` `valid` bit for `ctime`.  Refused: not settable anywhere.
pub const SETATTR_CTIME: u32 = 0x0000_0040;
/// `Tsetattr` `valid` bit: set atime to the supplied value.
pub const SETATTR_ATIME_SET: u32 = 0x0000_0080;
/// `Tsetattr` `valid` bit: set mtime to the supplied value.
pub const SETATTR_MTIME_SET: u32 = 0x0000_0100;

/// Every `Tsetattr` `valid` bit this profile accepts.
///
/// The contract: "Validate the mask field by field; size changes require
/// write/truncate authority, mode/time changes require their explicit
/// permissions; reject unsupported ownership fields."  `uid`, `gid` and `ctime`
/// are therefore outside the mask.
pub const SETATTR_ALLOWED: u32 = SETATTR_MODE
    | SETATTR_SIZE
    | SETATTR_ATIME
    | SETATTR_MTIME
    | SETATTR_ATIME_SET
    | SETATTR_MTIME_SET;

/// `AT_REMOVEDIR`, the only `Tunlinkat` flag this profile accepts.
pub const AT_REMOVEDIR: u32 = 0x200;

// `Tgetattr` `request_mask` bits, `P9_GETATTR_*`.  The complete set is spelled
// out rather than the handful this crate happens to reference: these are
// exported, a TypeScript client will read them, and a partial list invites a
// caller to guess the gaps.  Each is one bit, in the order the 9P2000.L
// reference defines them.
/// `mode`.
pub const GETATTR_MODE: u64 = 0x0000_0001;
/// `nlink`.
pub const GETATTR_NLINK: u64 = 0x0000_0002;
/// `uid`.
pub const GETATTR_UID: u64 = 0x0000_0004;
/// `gid`.
pub const GETATTR_GID: u64 = 0x0000_0008;
/// `rdev`.
pub const GETATTR_RDEV: u64 = 0x0000_0010;
/// `atime`.
pub const GETATTR_ATIME: u64 = 0x0000_0020;
/// `mtime`.
pub const GETATTR_MTIME: u64 = 0x0000_0040;
/// `ctime`.
pub const GETATTR_CTIME: u64 = 0x0000_0080;
/// `ino`, which this profile answers from the qid path rather than a host
/// inode number.
pub const GETATTR_INO: u64 = 0x0000_0100;
/// `size`.
pub const GETATTR_SIZE: u64 = 0x0000_0200;
/// `blocks`, which carries `blksize` with it.
pub const GETATTR_BLOCKS: u64 = 0x0000_0400;
/// The `P9_GETATTR_BASIC` set: every bit above.
pub const GETATTR_BASIC: u64 = 0x0000_07FF;
/// `btime`.
pub const GETATTR_BTIME: u64 = 0x0000_0800;
/// `gen`.
pub const GETATTR_GEN: u64 = 0x0000_1000;
/// `data_version`.
pub const GETATTR_DATA_VERSION: u64 = 0x0000_2000;
/// `P9_GETATTR_ALL`: the basic set plus `btime`, `gen` and `data_version`.
pub const GETATTR_ALL: u64 = 0x0000_3FFF;

/// Up to four primitives one request requires, as a conjunction.
///
/// A fixed-size set rather than a `Vec`: the largest combination this profile
/// produces is three (`Tsetattr` with mode, size and times in one mask), and an
/// authorization decision should not allocate.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct Primitives {
    items: [Option<Primitive>; 4],
}

impl Primitives {
    /// The empty set, which no request produces.
    pub const EMPTY: Self = Self { items: [None; 4] };

    /// A set of exactly one.
    #[must_use]
    pub const fn one(primitive: Primitive) -> Self {
        Self {
            items: [Some(primitive), None, None, None],
        }
    }

    /// Add one primitive, ignoring a repeat.
    #[must_use]
    pub fn with(mut self, primitive: Primitive) -> Self {
        for slot in &mut self.items {
            match slot {
                Some(existing) if *existing == primitive => return self,
                Some(_) => {}
                None => {
                    *slot = Some(primitive);
                    return self;
                }
            }
        }
        self
    }

    /// The primitives, in insertion order.
    pub fn iter(self) -> impl Iterator<Item = Primitive> {
        self.items.into_iter().flatten()
    }

    /// How many primitives are in the set.
    #[must_use]
    pub fn len(self) -> usize {
        self.iter().count()
    }

    /// Whether the set is empty.
    #[must_use]
    pub fn is_empty(self) -> bool {
        self.items[0].is_none()
    }
}

/// The primitives a `Tlopen` flag word requires, from the flags alone.
///
/// **This is only half the decision, and the half a codec can take.**  A
/// directory is named by the fid, not by the flag word, so a client that opens
/// a directory read-only without `O_DIRECTORY` classifies here as
/// [`Primitive::OpenRead`].  Gate 4 must re-run [`open_primitives`] with the
/// node kind the resolver reports and require [`Primitive::OpenDir`] for a
/// directory whatever the flags said — otherwise a `read`-without-`list` grant
/// could open a directory that `Treaddir` would then refuse, and the two
/// decisions would disagree.  `Treaddir` requires `list` on its own, so the
/// enumeration itself is gated either way; this is about the open agreeing with
/// it.
///
/// # Errors
///
/// [`SessionError::FlagNotInProfile`] for any bit outside
/// [`OPEN_FLAGS_ALLOWED`], for the invalid access mode `3`, for `O_DIRECTORY`
/// combined with any write, append or truncate bit, and for `O_TRUNC` or
/// `O_APPEND` on a read-only open.
pub fn open_primitives_from_flags(flags: u32) -> Result<Primitives, SessionError> {
    open_primitives(flags, false)
}

/// The primitives a `Tlopen` requires, given the flags and whether the fid is
/// known to name a directory.
///
/// # Errors
///
/// As [`open_primitives_from_flags`], and additionally when `is_directory` is
/// true and any write, append or truncate bit is set: a directory is not
/// writable through this profile.
pub fn open_primitives(flags: u32, is_directory: bool) -> Result<Primitives, SessionError> {
    if flags & !OPEN_FLAGS_ALLOWED != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
    let access = flags & O_ACCMODE;
    if access == O_ACCMODE {
        return Err(SessionError::FlagNotInProfile);
    }
    let writing = access == O_WRONLY || access == O_RDWR;
    let mutating = writing || flags & (O_TRUNC | O_APPEND) != 0;
    let directory = is_directory || flags & O_DIRECTORY != 0;

    if directory && mutating {
        // A directory is opened to be enumerated.  `O_WRONLY|O_DIRECTORY` is
        // `EISDIR` on Linux; refusing it here keeps the decision in one place.
        return Err(SessionError::FlagNotInProfile);
    }
    if !writing && flags & (O_TRUNC | O_APPEND) != 0 {
        // Truncating or appending through a read-only descriptor is not a
        // thing the host will do, and accepting it would advertise an
        // authorization decision the provider could not honour.
        return Err(SessionError::FlagNotInProfile);
    }

    if directory {
        return Ok(Primitives::one(Primitive::OpenDir));
    }
    let mut required = Primitives::EMPTY;
    if access == O_RDONLY || access == O_RDWR {
        required = required.with(Primitive::OpenRead);
    }
    if writing {
        required = required.with(Primitive::OpenWrite);
    }
    if flags & O_TRUNC != 0 {
        required = required.with(Primitive::OpenTruncate);
    }
    Ok(required)
}

/// The primitives a `Tlcreate` flag word requires.
///
/// # Errors
///
/// [`SessionError::FlagNotInProfile`] for any bit outside
/// [`CREATE_FLAGS_ALLOWED`], for the invalid access mode `3`, and for a
/// read-only create — a fid that just created a file and cannot write to it is
/// a request with no meaning.
pub fn create_primitives(flags: u32) -> Result<Primitives, SessionError> {
    if flags & !CREATE_FLAGS_ALLOWED != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
    let access = flags & O_ACCMODE;
    if access == O_ACCMODE || access == O_RDONLY {
        return Err(SessionError::FlagNotInProfile);
    }
    let mut required = Primitives::one(Primitive::Create).with(Primitive::OpenWrite);
    if access == O_RDWR {
        required = required.with(Primitive::OpenRead);
    }
    if flags & O_TRUNC != 0 {
        required = required.with(Primitive::OpenTruncate);
    }
    Ok(required)
}

/// The primitives a `Tsetattr` `valid` mask requires.
///
/// # Errors
///
/// [`SessionError::FlagNotInProfile`] for an empty mask — a `Tsetattr` that
/// changes nothing is a request with no meaning, and answering it `Rsetattr`
/// would report a mutation that did not happen — and for any bit outside
/// [`SETATTR_ALLOWED`], which is how the contract's "reject unsupported
/// ownership fields" is enforced.
pub fn setattr_primitives(valid: u32) -> Result<Primitives, SessionError> {
    if valid == 0 || valid & !SETATTR_ALLOWED != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
    let mut required = Primitives::EMPTY;
    if valid & SETATTR_MODE != 0 {
        required = required.with(Primitive::SetattrMode);
    }
    if valid & SETATTR_SIZE != 0 {
        required = required.with(Primitive::SetattrSize);
    }
    if valid & (SETATTR_ATIME | SETATTR_MTIME | SETATTR_ATIME_SET | SETATTR_MTIME_SET) != 0 {
        required = required.with(Primitive::SetattrTimes);
    }
    Ok(required)
}

/// The primitive a `Tunlinkat` flag word requires.
///
/// # Errors
///
/// [`SessionError::FlagNotInProfile`] for any bit other than
/// [`AT_REMOVEDIR`].
pub fn unlinkat_primitives(flags: u32) -> Result<Primitives, SessionError> {
    match flags {
        0 => Ok(Primitives::one(Primitive::Unlink)),
        AT_REMOVEDIR => Ok(Primitives::one(Primitive::RemoveDir)),
        _ => Err(SessionError::FlagNotInProfile),
    }
}

/// Validate a `Tgetattr` `request_mask`.
///
/// # Errors
///
/// [`SessionError::FlagNotInProfile`] for an empty mask or any bit outside
/// [`GETATTR_ALL`].
pub fn getattr_primitives(request_mask: u64) -> Result<Primitives, SessionError> {
    if request_mask == 0 || request_mask & !GETATTR_ALL != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
    Ok(Primitives::one(Primitive::Getattr))
}
