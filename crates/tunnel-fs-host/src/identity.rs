//! Host file identity and node kind.
//!
//! Identity is what decides the four two-spellings-one-file classes of
//! `docs/filesystem-api.md`: two virtual paths name one file when the host
//! reports the same `(device, inode)` pair for the descriptors they resolved
//! to, never when their text compares equal under some fold.
//!
//! The device and inode numbers are host details, so they are deliberately
//! **not** reachable through a getter, a `Debug` rendering or a `Display`
//! impl.  Comparison ([`FileIdentity::is_same_file`]) and a hashed scoped qid
//! path ([`FileIdentity::qid_path`]) are the only ways out, which keeps the
//! payload-free construction rule from gate 1 intact here.

use core::fmt;

use rustix::fs::{FileType, Stat};

/// What kind of node a resolved descriptor refers to.
///
/// Only [`FileKind::Directory`] and [`FileKind::RegularFile`] are ever
/// returned by the resolver; the remaining variants exist so that the refusal
/// of special files is a decision over an exhaustive enum rather than an
/// `else` arm.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum FileKind {
    /// A directory.
    Directory,
    /// A regular file.
    RegularFile,
    /// A symbolic link, seen only while walking and never returned.
    Symlink,
    /// A named pipe.
    Fifo,
    /// A unix-domain socket bound into the filesystem.
    Socket,
    /// A character device node.
    CharacterDevice,
    /// A block device node.
    BlockDevice,
    /// A node kind this profile does not name, such as a Solaris door.
    Unknown,
}

impl FileKind {
    /// Every kind.
    pub const ALL: [Self; 8] = [
        Self::Directory,
        Self::RegularFile,
        Self::Symlink,
        Self::Fifo,
        Self::Socket,
        Self::CharacterDevice,
        Self::BlockDevice,
        Self::Unknown,
    ];

    /// The diagnostic spelling.  Static text only.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::RegularFile => "regular_file",
            Self::Symlink => "symlink",
            Self::Fifo => "fifo",
            Self::Socket => "socket",
            Self::CharacterDevice => "character_device",
            Self::BlockDevice => "block_device",
            Self::Unknown => "unknown",
        }
    }

    /// Whether this profile will ever hand a caller a descriptor of this kind.
    ///
    /// Rule 5 of the confinement model: special files, sockets, FIFOs and
    /// device nodes are refused.
    #[must_use]
    pub const fn is_exportable(self) -> bool {
        matches!(self, Self::Directory | Self::RegularFile)
    }

    fn from_stat(stat: &Stat) -> Self {
        match FileType::from_raw_mode(stat.st_mode) {
            FileType::Directory => Self::Directory,
            FileType::RegularFile => Self::RegularFile,
            FileType::Symlink => Self::Symlink,
            FileType::Fifo => Self::Fifo,
            FileType::Socket => Self::Socket,
            FileType::CharacterDevice => Self::CharacterDevice,
            FileType::BlockDevice => Self::BlockDevice,
            _ => Self::Unknown,
        }
    }
}

impl fmt::Display for FileKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// The host's answer to "which file is this?".
///
/// `device` and `inode` are held as `i128` because `dev_t` is a signed 32-bit
/// value on macOS and an unsigned 64-bit value on Linux; widening both into a
/// type that holds either without loss keeps the comparison exact on both
/// hosts instead of relying on a truncating cast.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct FileIdentity {
    device: i128,
    inode: i128,
    links: u64,
    kind: FileKind,
}

impl FileIdentity {
    /// Read the identity of an already-opened descriptor's `Stat`.
    #[must_use]
    #[allow(
        clippy::useless_conversion,
        reason = "st_nlink is u16 on macOS and already u64 on Linux; the conversion is a \
                  no-op on one host and load-bearing on the other, and writing it as a cast \
                  would trade this lint for `unnecessary_cast` on the other host"
    )]
    pub(crate) fn from_stat(stat: &Stat) -> Self {
        Self {
            device: i128::from(stat.st_dev),
            inode: i128::from(stat.st_ino),
            links: u64::from(stat.st_nlink),
            kind: FileKind::from_stat(stat),
        }
    }

    /// Whether both identities name the same host file.
    ///
    /// This is the only collision decision this profile makes.  It is the
    /// answer for ASCII case, Unicode case pairs and NFC/NFD alike, because
    /// the host, not this code, decided whether the two names reached one
    /// inode.
    #[must_use]
    pub const fn is_same_file(self, other: Self) -> bool {
        self.device == other.device && self.inode == other.inode
    }

    /// Whether both identities are on the same host filesystem.
    #[must_use]
    pub const fn is_same_device(self, other: Self) -> bool {
        self.device == other.device
    }

    /// The node kind.
    #[must_use]
    pub const fn kind(self) -> FileKind {
        self.kind
    }

    /// The host link count.
    ///
    /// Exposed because rule 4 of the confinement model is stated in terms of
    /// it: it is a count, not a path, a name or a host identifier.
    #[must_use]
    pub const fn links(self) -> u64 {
        self.links
    }

    /// Whether this is a regular file with more than one directory entry.
    ///
    /// Directories carry a link count of at least two from `.` and their
    /// children, so they are excluded here exactly as the contract excludes
    /// them from the write refusal.
    #[must_use]
    pub const fn is_multiply_linked_file(self) -> bool {
        matches!(self.kind, FileKind::RegularFile) && self.links > 1
    }

    /// A stable session-scoped qid path.
    ///
    /// A 9P qid needs a value that is equal for two names of one file and
    /// different for two files.  Sending the host inode itself would disclose
    /// a host detail the contract keeps out of the wire, so this is a 64-bit
    /// FNV-1a fold of the `(device, inode)` pair.  Equality is what the
    /// protocol needs and is preserved exactly; the host numbers are not
    /// recoverable from it.
    #[must_use]
    pub const fn qid_path(self) -> u64 {
        const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const PRIME: u64 = 0x0000_0100_0000_01b3;

        let mut hash = OFFSET;
        let mut index = 0;
        while index < 16 {
            let byte = ((self.device >> (index * 8)) & 0xff) as u8;
            hash = (hash ^ byte as u64).wrapping_mul(PRIME);
            index += 1;
        }
        let mut index = 0;
        while index < 16 {
            let byte = ((self.inode >> (index * 8)) & 0xff) as u8;
            hash = (hash ^ byte as u64).wrapping_mul(PRIME);
            index += 1;
        }
        hash
    }
}

impl fmt::Debug for FileIdentity {
    /// Redacting, like [`tunnel_fs_core::VirtualPath`]'s.
    ///
    /// The device and inode numbers are host details, so a derived `Debug`
    /// would put them into every log line that formatted a resolved handle.
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FileIdentity")
            .field("kind", &self.kind.as_str())
            .field("multiply_linked", &self.is_multiply_linked_file())
            .finish_non_exhaustive()
    }
}
