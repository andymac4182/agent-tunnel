//! The 9P2000.L primitive field layout, hand-written in both directions.
//!
//! Everything is little-endian, which is the one thing 9P never negotiates.
//! A `string[s]` is a 16-bit byte count followed by that many bytes, **which
//! this profile requires to be valid UTF-8** — see [`Reader::string`].  A
//! `qid[13]` is `type[1] version[4] path[8]`.
//!
//! There is no serializer and no derive here on purpose.  Field order, the
//! exact width of every integer and the strictness of every refusal are the
//! contract, so they are written out rather than configured.

use crate::error::{CodecError, StringField};

/// `size[4] type[1] tag[2]`, the fixed header every 9P message begins with.
///
/// `size` counts itself, so the smallest legal message is exactly this many
/// bytes.
pub const HEADER_LEN: usize = 7;

/// The wire length of a `qid[13]`.
pub const QID_LEN: usize = 13;

/// The reserved tag, used by `Tversion` and by nothing else.
pub const NOTAG: u16 = 0xFFFF;

/// The reserved fid, used by `Tattach`'s `afid` and by nothing else.
pub const NOFID: u32 = 0xFFFF_FFFF;

/// The reserved numeric user id `Tattach` must carry.
///
/// Authentication has already happened at the HTTP upgrade, and the provider
/// maps the session to its own configured OS identity, so this field cannot
/// choose one.
pub const NONUNAME: u32 = 0xFFFF_FFFF;

/// The largest number of names one `Twalk` may carry.
///
/// This is 9P's own `MAXWELEM`.  It bounds the reply — `Rwalk` carries one qid
/// per name — and it bounds the work one message can ask the resolver for.
pub const MAX_WALK_NAMES: usize = 16;

/// The kind of node a qid names.
///
/// 9P's `type[1]` is a bit field with eight defined bits.  This profile emits
/// and accepts **three**: `QTFILE` (zero), `QTDIR` and `QTSYMLINK`.  `QTAPPEND`,
/// `QTEXCL`, `QTMOUNT`, `QTAUTH` and `QTTMP` describe behaviours this profile
/// does not implement, so a qid carrying one is refused rather than masked off:
/// masking would let a peer's claim about a node silently disappear.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum QidKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A symbolic link.  Only reachable when the `symlinks` feature is on.
    Symlink,
}

/// `QTDIR`.
pub const QTDIR: u8 = 0x80;
/// `QTSYMLINK`.
pub const QTSYMLINK: u8 = 0x02;

impl QidKind {
    /// Every kind this profile defines.
    pub const ALL: [Self; 3] = [Self::File, Self::Directory, Self::Symlink];

    /// The `type[1]` byte.
    #[must_use]
    pub const fn bits(self) -> u8 {
        match self {
            Self::File => 0x00,
            Self::Directory => QTDIR,
            Self::Symlink => QTSYMLINK,
        }
    }

    /// The diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "dir",
            Self::Symlink => "symlink",
        }
    }

    /// Decode a `type[1]` byte, refusing every bit outside this profile.
    ///
    /// # Errors
    ///
    /// [`CodecError::QidTypeNotInProfile`] for any other value, including a
    /// combination such as `QTDIR | QTSYMLINK` that names two kinds at once.
    pub const fn from_bits(bits: u8) -> Result<Self, CodecError> {
        match bits {
            0x00 => Ok(Self::File),
            QTDIR => Ok(Self::Directory),
            QTSYMLINK => Ok(Self::Symlink),
            _ => Err(CodecError::QidTypeNotInProfile),
        }
    }
}

/// A 9P qid: the server's unique, stable handle for a node.
///
/// The `path` is a 64-bit identifier the provider derives from host file
/// identity.  Gate 2 folds `(st_dev, st_ino)` into it with FNV-1a, so equality
/// is preserved exactly and the host numbers are not recoverable; nothing here
/// depends on how it was produced.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct Qid {
    /// What kind of node this is.
    pub kind: QidKind,
    /// A version counter for the node's contents.
    pub version: u32,
    /// The provider's stable identifier for the node.
    pub path: u64,
}

impl Qid {
    /// A qid with a zero version, the common case for a provider that does not
    /// maintain a content version counter.
    #[must_use]
    pub const fn new(kind: QidKind, path: u64) -> Self {
        Self {
            kind,
            version: 0,
            path,
        }
    }
}

impl Default for Qid {
    /// A zero-path regular-file qid, so [`crate::Attributes`] can derive
    /// `Default` for tests and for a provider that fills fields in stages.
    fn default() -> Self {
        Self::new(QidKind::File, 0)
    }
}

/// A bounds-checked, allocation-free reader over one message body.
#[derive(Clone, Debug)]
pub struct Reader<'input> {
    bytes: &'input [u8],
    at: usize,
}

impl<'input> Reader<'input> {
    /// Read from the whole of `bytes`.
    #[must_use]
    pub const fn new(bytes: &'input [u8]) -> Self {
        Self { bytes, at: 0 }
    }

    /// How many bytes remain unread.
    #[must_use]
    pub const fn remaining(&self) -> usize {
        self.bytes.len() - self.at
    }

    fn take(&mut self, count: usize) -> Result<&'input [u8], CodecError> {
        if self.remaining() < count {
            return Err(CodecError::TruncatedBody);
        }
        let slice = &self.bytes[self.at..self.at + count];
        self.at += count;
        Ok(slice)
    }

    /// Read a `u8`.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] if the body ended.
    pub fn u8(&mut self) -> Result<u8, CodecError> {
        Ok(self.take(1)?[0])
    }

    /// Read a little-endian `u16`.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] if the body ended.
    pub fn u16(&mut self) -> Result<u16, CodecError> {
        let bytes = self.take(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    /// Read a little-endian `u32`.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] if the body ended.
    pub fn u32(&mut self) -> Result<u32, CodecError> {
        let bytes = self.take(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    /// Read a little-endian `u64`.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] if the body ended.
    pub fn u64(&mut self) -> Result<u64, CodecError> {
        let bytes = self.take(8)?;
        let mut value = [0u8; 8];
        value.copy_from_slice(bytes);
        Ok(u64::from_le_bytes(value))
    }

    /// Read a `string[s]`, **requiring valid UTF-8**.
    ///
    /// This is where `docs/filesystem-api.md`'s non-UTF-8 obligation is
    /// discharged.  A 9P string is a byte count and bytes; nothing in the
    /// format requires them to be text.  Gate 1's `VirtualPath` is a `&str` by
    /// construction and therefore cannot carry the refusal, so the refusal is
    /// here, at the only boundary those bytes cross:
    ///
    /// * The bytes are **refused**, never replaced.  There is no
    ///   `from_utf8_lossy` anywhere in this crate: a U+FFFD substitution would
    ///   turn one host name into a different one and hand gate 2 a path that
    ///   names a file the caller did not ask for.
    /// * The refusal happens **before** the length is trusted for anything
    ///   else, and before any decoded name reaches path validation.
    /// * It applies to every `string[s]` in the profile in both directions,
    ///   including `Rreadlink`'s target and the names inside an `Rreaddir`
    ///   payload — so a host name that is not UTF-8 produces an explicit
    ///   refusal rather than a mangled name, on the way out as well as in.
    ///
    /// # Errors
    ///
    /// [`CodecError::TruncatedBody`] if the body ended, and
    /// [`CodecError::StringNotUtf8`] naming `field` for invalid UTF-8.
    pub fn string(&mut self, field: StringField) -> Result<&'input str, CodecError> {
        let len = usize::from(self.u16()?);
        let bytes = self.take(len)?;
        core::str::from_utf8(bytes).map_err(|_| CodecError::StringNotUtf8(field))
    }

    /// Read `count` raw bytes, which are **not** required to be UTF-8.
    ///
    /// Used only for `Tread`/`Rread`/`Twrite` payloads and the `Rreaddir`
    /// block, which are file content and a packed record array, not text.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] if the body ended.
    pub fn raw(&mut self, count: usize) -> Result<&'input [u8], CodecError> {
        self.take(count)
    }

    /// Read a `qid[13]`.
    ///
    /// # Errors
    /// [`CodecError::TruncatedBody`] or [`CodecError::QidTypeNotInProfile`].
    pub fn qid(&mut self) -> Result<Qid, CodecError> {
        let kind = QidKind::from_bits(self.u8()?)?;
        let version = self.u32()?;
        let path = self.u64()?;
        Ok(Qid {
            kind,
            version,
            path,
        })
    }

    /// Require that the body is fully consumed.
    ///
    /// # Errors
    ///
    /// [`CodecError::TrailingBytes`] when anything is left.  A message whose
    /// declared `size` exceeds the fields its type defines is refused rather
    /// than truncated, so a peer cannot smuggle bytes past a decoder by
    /// over-declaring a length.
    pub const fn finish(&self) -> Result<(), CodecError> {
        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }
    }
}

/// An appending writer over a caller-owned buffer.
#[derive(Debug)]
pub struct Writer<'out> {
    out: &'out mut Vec<u8>,
}

impl<'out> Writer<'out> {
    /// Append to `out`.
    pub fn new(out: &'out mut Vec<u8>) -> Self {
        Self { out }
    }

    /// How many bytes have been written through this writer's buffer in total.
    #[must_use]
    pub fn len(&self) -> usize {
        self.out.len()
    }

    /// Whether the underlying buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.out.is_empty()
    }

    /// Append a `u8`.
    pub fn u8(&mut self, value: u8) {
        self.out.push(value);
    }

    /// Append a little-endian `u16`.
    pub fn u16(&mut self, value: u16) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u32`.
    pub fn u32(&mut self, value: u32) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a little-endian `u64`.
    pub fn u64(&mut self, value: u64) {
        self.out.extend_from_slice(&value.to_le_bytes());
    }

    /// Append a `string[s]`.
    ///
    /// The input is already `&str`, so it is UTF-8 by construction; the only
    /// failure is a string too long for the 16-bit prefix.
    ///
    /// # Errors
    /// [`CodecError::StringTooLong`] naming `field`.
    pub fn string(&mut self, field: StringField, value: &str) -> Result<(), CodecError> {
        let len = u16::try_from(value.len()).map_err(|_| CodecError::StringTooLong(field))?;
        self.u16(len);
        self.out.extend_from_slice(value.as_bytes());
        Ok(())
    }

    /// Append raw bytes with no length prefix.
    pub fn raw(&mut self, value: &[u8]) {
        self.out.extend_from_slice(value);
    }

    /// Append a `qid[13]`.
    pub fn qid(&mut self, qid: Qid) {
        self.u8(qid.kind.bits());
        self.u32(qid.version);
        self.u64(qid.path);
    }
}
