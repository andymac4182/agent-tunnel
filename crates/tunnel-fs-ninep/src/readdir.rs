//! The packed entry array inside an `Rreaddir` payload.
//!
//! `Rreaddir` carries `count[4] data[count]`, and `data` is a sequence of
//! `qid[13] offset[8] type[1] name[s]` records with no count of its own: the
//! reader stops when the block runs out, and a block that ends part-way through
//! a record is malformed.  That is why this is its own module rather than a few
//! lines inside [`crate::message`] — the strictness is in the framing of the
//! *inner* array, and it is easy to write a parser that silently ignores a
//! trailing fragment.
//!
//! Three rules are enforced here, each of which the contract requires
//! somewhere:
//!
//! * Entry names are **UTF-8 or refused**, the same rule every other
//!   `string[s]` in this profile follows.  A block carrying one that is not
//!   UTF-8 is refused, never mangled.
//!
//!   On the **encoding** side [`DirEntry`] takes a `String`, so a non-UTF-8
//!   name cannot be expressed here at all; the conversion from the host's
//!   bytes happens in gate 4.  **Gate 4's obligation, pinned here because this
//!   is where a reader will look for it:** when an entry's host name is not
//!   representable in UTF-8, fail the whole `Treaddir` with `EINVAL` — do
//!   **not** skip the entry.  The two are not equivalent and the choice is not
//!   free: skipping hides a file from a caller that believes it received the
//!   whole listing, which is exactly the silent-substitution failure the
//!   refuse-never-repair rule exists to prevent, while refusing makes one
//!   unrepresentable name render its directory unlistable.  `docs/testing.md`
//!   requires "the documented explicit result", and the explicit result is the
//!   error — the same answer gate 2 already gives for a symbolic-link target
//!   that is not valid UTF-8.
//! * The `type[1]` byte is restricted to directory, regular file and symbolic
//!   link.  Gate 2 refuses special files, sockets, FIFOs and device nodes, so a
//!   provider cannot enumerate one, and a client cannot be told one exists.
//! * The `offset` is an **opaque cookie**.  Nothing here interprets it, orders
//!   by it, or assumes it is a byte offset.

use crate::error::{CodecError, StringField};
use crate::wire::{QID_LEN, Qid, QidKind, Reader, Writer};

/// `DT_DIR`.
pub const DT_DIR: u8 = 4;
/// `DT_REG`.
pub const DT_REG: u8 = 8;
/// `DT_LNK`.
pub const DT_LNK: u8 = 10;

/// The fixed part of one entry: `qid[13] offset[8] type[1] name_len[2]`.
pub const ENTRY_OVERHEAD: usize = QID_LEN + 8 + 1 + 2;

/// One directory entry.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DirEntry {
    /// The entry's qid.
    pub qid: Qid,
    /// The opaque cookie a later `Treaddir` resumes from.  Never interpreted.
    pub offset: u64,
    /// The entry's name, one path component.
    pub name: String,
}

impl DirEntry {
    /// Build an entry.
    #[must_use]
    pub fn new(qid: Qid, offset: u64, name: impl Into<String>) -> Self {
        Self {
            qid,
            offset,
            name: name.into(),
        }
    }

    /// The `type[1]` byte for this entry's qid kind.
    #[must_use]
    pub const fn dirent_type(&self) -> u8 {
        match self.qid.kind {
            QidKind::Directory => DT_DIR,
            QidKind::File => DT_REG,
            QidKind::Symlink => DT_LNK,
        }
    }

    /// The number of bytes this entry occupies in a packed block.
    #[must_use]
    pub fn encoded_len(&self) -> usize {
        ENTRY_OVERHEAD + self.name.len()
    }
}

/// Decode the `type[1]` byte, refusing everything outside the profile.
fn kind_from_dirent(byte: u8, qid: Qid) -> Result<(), CodecError> {
    let expected = match qid.kind {
        QidKind::Directory => DT_DIR,
        QidKind::File => DT_REG,
        QidKind::Symlink => DT_LNK,
    };
    // The `type[1]` byte duplicates what the qid already says.  Two sources
    // that can disagree is one too many, so they are required to agree rather
    // than one being preferred: a provider that emitted a mismatched pair is
    // broken, and a peer that sent one is probing.
    if byte == expected {
        Ok(())
    } else {
        Err(CodecError::MalformedDirEntry)
    }
}

/// Parse a complete `Rreaddir` payload.
///
/// # Errors
///
/// [`CodecError::MalformedDirEntry`] when the block ends part-way through an
/// entry or the `type[1]` byte disagrees with the qid, and
/// [`CodecError::StringNotUtf8`] for a name that is not UTF-8.
pub fn parse_entries(data: &[u8]) -> Result<Vec<DirEntry>, CodecError> {
    let mut reader = Reader::new(data);
    let mut entries = Vec::new();
    while reader.remaining() > 0 {
        // A block that runs out mid-record is malformed wherever it runs out,
        // so truncation is reported the same way in every field.  A qid whose
        // *type byte* is outside the profile keeps its own refusal, because
        // that is a different failure: the bytes were all there.
        let qid = reader.qid().map_err(|error| match error {
            CodecError::TruncatedBody => CodecError::MalformedDirEntry,
            other => other,
        })?;
        let offset = reader.u64().map_err(|_| CodecError::MalformedDirEntry)?;
        let dirent_type = reader.u8().map_err(|_| CodecError::MalformedDirEntry)?;
        kind_from_dirent(dirent_type, qid)?;
        // A non-UTF-8 name is refused here and not replaced, exactly as
        // `Reader::string` does everywhere else.  Truncation of the name — as
        // distinct from a bad encoding — is the malformed-block case.
        let name = match reader.string(StringField::DirEntryName) {
            Ok(name) => name.to_owned(),
            Err(CodecError::StringNotUtf8(field)) => {
                return Err(CodecError::StringNotUtf8(field));
            }
            Err(_) => return Err(CodecError::MalformedDirEntry),
        };
        entries.push(DirEntry { qid, offset, name });
    }
    Ok(entries)
}

/// Pack entries into a block no larger than `limit` bytes.
///
/// Returns the block and the number of entries it holds.  An entry that does
/// not fit is **left out entirely**; a partially written entry would be
/// unparseable, and silently dropping its tail would invent a name.  A caller
/// resumes from the last included entry's `offset`, which is what the cookie is
/// for.
///
/// # Errors
/// [`CodecError::StringTooLong`] for a name beyond the 16-bit prefix.
pub fn pack_entries(entries: &[DirEntry], limit: usize) -> Result<(Vec<u8>, usize), CodecError> {
    let mut out = Vec::new();
    let mut written = 0usize;
    for entry in entries {
        if out.len() + entry.encoded_len() > limit {
            break;
        }
        let mut writer = Writer::new(&mut out);
        writer.qid(entry.qid);
        writer.u64(entry.offset);
        writer.u8(entry.dirent_type());
        writer.string(StringField::DirEntryName, &entry.name)?;
        written += 1;
    }
    Ok((out, written))
}
