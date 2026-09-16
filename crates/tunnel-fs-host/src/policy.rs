//! The decisions the resolver takes, kept separate from the traversal that
//! applies them so each one can be tested on its own.
//!
//! Every function here is pure and every error it produces is a field-free
//! [`FsError`] from the gate-1 core, so no host path, host errno number, file
//! name or inode can reach a diagnostic through this module.

use rustix::io::Errno;
use tunnel_fs_core::{FsError, FsErrorCode, Outcome, Primitive};

use crate::identity::{FileIdentity, FileKind};

/// The most link hops one resolution may take before it is refused.
///
/// The contract fixes 32 for the provider-side re-rooting walk so a cycle is
/// refused by count rather than by hanging.  The same budget is applied on
/// every host, including the one where the kernel would have its own.
pub const MAX_LINK_HOPS: u32 = 32;

/// Translate a host errno into the closed gate-1 vocabulary.
///
/// [`FsErrorCode::from_errno`] maps **Linux wire** errno numbers, which is what
/// an `Rlerror` carries; it is not usable for a host errno, because the numbers
/// differ between the hosts this crate runs on — `ELOOP` is 62 on macOS and 40
/// on Linux, and `ENOTEMPTY` is 66 and 39.  Matching on `rustix`'s symbolic
/// constants translates by meaning instead, on either host.
///
/// Anything unmapped becomes [`FsErrorCode::Einval`], per the closed-vocabulary
/// rule: a host must not be able to disclose which of its own failure modes
/// occurred by widening what a consumer has to handle.
#[must_use]
pub fn code_from_errno(errno: Errno) -> FsErrorCode {
    if errno == Errno::NOENT {
        FsErrorCode::Enoent
    } else if errno == Errno::ACCESS {
        FsErrorCode::Eacces
    } else if errno == Errno::PERM {
        FsErrorCode::Eperm
    } else if errno == Errno::ROFS {
        FsErrorCode::Erofs
    } else if errno == Errno::EXIST {
        FsErrorCode::Eexist
    } else if errno == Errno::NOTDIR {
        FsErrorCode::Enotdir
    } else if errno == Errno::ISDIR {
        FsErrorCode::Eisdir
    } else if errno == Errno::NOTEMPTY {
        FsErrorCode::Enotempty
    } else if errno == Errno::LOOP {
        FsErrorCode::Eloop
    } else if errno == Errno::XDEV {
        FsErrorCode::Exdev
    } else if errno == Errno::NOTSUP || errno == Errno::OPNOTSUPP {
        FsErrorCode::Enotsup
    } else if errno == Errno::FBIG {
        FsErrorCode::Efbig
    } else if errno == Errno::NAMETOOLONG {
        FsErrorCode::Enametoolong
    } else {
        FsErrorCode::Einval
    }
}

/// A host failure, refused before anything was dispatched on the caller's
/// behalf.
#[must_use]
pub fn host_error(errno: Errno) -> FsError {
    FsError::refused(code_from_errno(errno))
}

/// A resolution that observed the filesystem change underneath it.
///
/// Reported as `ENOENT`: the entry this resolution had identified is not there
/// any more, which is what the caller would have seen had the swap happened one
/// instant earlier.  It is deliberately not a distinct code — the vocabulary is
/// closed, and a dedicated "you lost a race" code would tell a caller something
/// about the host's concurrent activity that the grant does not entitle it to.
#[must_use]
pub const fn lost_race() -> FsError {
    FsError::refused(FsErrorCode::Enoent)
}

/// Whether `kind` may be handed to a caller, per rule 5.
///
/// # Errors
///
/// [`FsErrorCode::Enotsup`] for a FIFO, a socket, a device node or an unnamed
/// kind: the profile does not implement them, as opposed to the host denying
/// them (`EACCES`) or their being absent (`ENOENT`).
pub const fn check_exportable(kind: FileKind) -> Result<(), FsError> {
    if kind.is_exportable() {
        Ok(())
    } else {
        Err(FsError::refused(FsErrorCode::Enotsup))
    }
}

/// Whether an entry on `entry` may be crossed from a root on `root`.
///
/// What this compares is the entry's device against the **export root's**, not
/// against its parent's: an export is one host filesystem, and anything on
/// another one is outside it. That catches an ordinary mount point, a macOS
/// firmlink, and a cross-filesystem bind mount. It does **not** catch a
/// same-filesystem bind mount, whose device is the root's by definition; on
/// Linux that case is the kernel's to refuse, through `RESOLVE_NO_XDEV` on the
/// `openat2` path, and this comparison is the coarser check that remains on a
/// host without it.
///
/// Crossing out is `EXDEV` — the same answer the contract fixes for a
/// cross-export operation, and for the same reason: the target is not in this
/// export.
///
/// # Errors
///
/// [`FsErrorCode::Exdev`] when the devices differ.
pub const fn check_same_device(root: FileIdentity, entry: FileIdentity) -> Result<(), FsError> {
    if root.is_same_device(entry) {
        Ok(())
    } else {
        Err(FsError::refused(FsErrorCode::Exdev))
    }
}

/// Whether `primitive` is one of the three the hard-link rule governs.
///
/// Rule 4 names exactly `OpenWrite`, `OpenTruncate` and a size-changing
/// `Tsetattr`.  `SetattrMode` and `SetattrTimes` are **not** covered: changing
/// a mode or a timestamp through a second link discloses nothing the link count
/// does not already, and does not write content through it.
#[must_use]
pub const fn is_size_changing(primitive: Primitive) -> bool {
    matches!(
        primitive,
        Primitive::OpenWrite | Primitive::OpenTruncate | Primitive::SetattrSize
    )
}

/// Apply rule 4 to a resolved file.
///
/// With the `hardLinks` feature off, a regular file whose `st_nlink` exceeds 1
/// may be read but not written, truncated or resized: the inode may also be
/// linked outside the export root, and writing through it would be an escape no
/// path check can observe.  Reads are unaffected, so this never narrows a read
/// grant.
///
/// # Errors
///
/// [`FsErrorCode::Eperm`] with [`Outcome::NotStarted`] — refused before the
/// host is asked to change anything.
pub const fn check_hard_link_write(
    primitive: Primitive,
    identity: FileIdentity,
    hard_links_advertised: bool,
) -> Result<(), FsError> {
    if hard_links_advertised || !is_size_changing(primitive) || !identity.is_multiply_linked_file()
    {
        return Ok(());
    }
    Err(FsError::Filesystem {
        code: FsErrorCode::Eperm,
        outcome: Outcome::NotStarted,
    })
}

#[cfg(test)]
mod tests {
    use super::{MAX_LINK_HOPS, code_from_errno, is_size_changing};
    use rustix::io::Errno;
    use tunnel_fs_core::{FsErrorCode, Primitive};

    #[test]
    fn every_translated_errno_keeps_its_meaning_on_this_host() {
        let expected = [
            (Errno::NOENT, FsErrorCode::Enoent),
            (Errno::ACCESS, FsErrorCode::Eacces),
            (Errno::PERM, FsErrorCode::Eperm),
            (Errno::ROFS, FsErrorCode::Erofs),
            (Errno::EXIST, FsErrorCode::Eexist),
            (Errno::NOTDIR, FsErrorCode::Enotdir),
            (Errno::ISDIR, FsErrorCode::Eisdir),
            (Errno::NOTEMPTY, FsErrorCode::Enotempty),
            (Errno::LOOP, FsErrorCode::Eloop),
            (Errno::XDEV, FsErrorCode::Exdev),
            (Errno::NOTSUP, FsErrorCode::Enotsup),
            (Errno::FBIG, FsErrorCode::Efbig),
            (Errno::NAMETOOLONG, FsErrorCode::Enametoolong),
        ];
        for (errno, code) in expected {
            assert_eq!(code_from_errno(errno), code);
        }
    }

    #[test]
    fn an_unmapped_host_errno_becomes_einval_rather_than_passing_through() {
        // `EMLINK` is a real host errno with no place in the closed vocabulary.
        assert_eq!(code_from_errno(Errno::MLINK), FsErrorCode::Einval);
    }

    #[test]
    fn the_linux_wire_table_is_not_usable_for_a_host_errno() {
        // The reason `code_from_errno` exists.  On a host whose numbering
        // differs from Linux's, translating a host errno through the wire
        // table lands on the wrong code; on Linux the two agree.  Either way
        // the symbolic translation is right, which is what is asserted last.
        let host_loop = u32::try_from(Errno::LOOP.raw_os_error()).expect("a positive errno");
        let through_wire_table = FsErrorCode::from_errno(host_loop);
        if cfg!(target_os = "linux") {
            assert_eq!(through_wire_table, FsErrorCode::Eloop);
        } else {
            assert_ne!(
                through_wire_table,
                FsErrorCode::Eloop,
                "this host numbers ELOOP differently from Linux, so the wire table would \
                 mistranslate it"
            );
        }
        assert_eq!(code_from_errno(Errno::LOOP), FsErrorCode::Eloop);
    }

    #[test]
    fn exactly_three_primitives_are_size_changing() {
        let covered: Vec<Primitive> = Primitive::ALL
            .into_iter()
            .filter(|primitive| is_size_changing(*primitive))
            .collect();
        assert_eq!(
            covered,
            vec![
                Primitive::OpenWrite,
                Primitive::OpenTruncate,
                Primitive::SetattrSize
            ]
        );
    }

    #[test]
    fn the_hop_budget_is_the_contract_value() {
        assert_eq!(MAX_LINK_HOPS, 32);
    }
}
