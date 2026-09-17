//! The mutating primitives, anchored.
//!
//! **This module is gate 2's crate serving implementation gate 5.** Gate 2
//! already resolved, opened for writing, truncated, resized and renamed; what
//! was missing was every operation that creates or removes a *name*, and the
//! positioned write itself. They live here rather than in the dispatcher for
//! the same reason [`crate::metadata`] does: each one ends in a syscall that
//! names a final component relative to a directory descriptor this crate
//! resolved, and a name reaching the host anywhere else would leave the
//! anchoring behind.
//!
//! # The shape every mutation here has
//!
//! 1. Authorize the gate-1 [`Primitive`], which is where a missing capability
//!    or an unadvertised feature is refused, before a host call is made at all.
//! 2. Resolve the **parent** by [`ExportRoot::resolve_parent`], the ordinary
//!    anchored walk. A symbolic link, a mount boundary, a special file or a
//!    component that changed underneath it is refused there, unchanged.
//! 3. Inspect the final component relative to that descriptor, with
//!    `AT_SYMLINK_NOFOLLOW`, when the operation needs to know what is there.
//! 4. Perform exactly one `*at` syscall against the same descriptor.
//!
//! Step 4 is the only step that can change the host, and it is the only step
//! whose failure is reported as [`Outcome::Failed`]. Everything before it is
//! [`Outcome::NotStarted`], which is the distinction gate 5 exists to make: a
//! refusal that demonstrably changed nothing and a dispatched operation that
//! reported it changed nothing are different facts, and gate 4 could only ever
//! produce the first.
//!
//! # Deliberate narrowings, each recorded rather than left implicit
//!
//! * **A create is always exclusive.** `Tlcreate` opens with `O_CREAT | O_EXCL`
//!   whatever the request's flag word said, so a create can never open a file
//!   that already exists. Overwriting an existing file is what `OpenTruncate`
//!   names and what `write` separately permits; a create that silently opened
//!   one would apply the [`Primitive::Create`] authorization to a mutation the
//!   caller did not ask for and the primitive does not describe. A client's own
//!   `O_EXCL` is therefore redundant here rather than meaningful, and the
//!   `exclusiveCreate` feature describes a property this implementation always
//!   has.
//! * **A mode carrying anything outside `0o777` is refused, never masked.**
//!   Set-user-ID, set-group-ID and the sticky bit are not bits this profile
//!   grants, and quietly dropping them would report a mode that was not
//!   applied. The namespace rule is refuse, never repair, and a mode is no
//!   different from a path.
//! * **A special file cannot be removed or renamed.** The profile refuses a
//!   FIFO, a socket and a device node at every other operation and leaves them
//!   out of a listing, so a `delete` grant that could nonetheless unlink one
//!   would be the one place their existence was observable. The cost is that a
//!   special file placed inside an export out of band cannot be removed
//!   through it, and that cost is accepted.
//! * **A symbolic link *name* can be removed and renamed with the `symlinks`
//!   feature off.** `unlinkat` and `renameat` never follow the final component,
//!   so neither can be steered outside the root by one, and refusing would make
//!   a link an export cannot see also a link it can never clear.

use rustix::fs::{AtFlags, Mode, OFlags};

use tunnel_fs_core::{Feature, FsError, FsErrorCode, Outcome, Primitive, VirtualPath};

use crate::identity::{FileIdentity, FileKind};
use crate::policy::{
    check_exportable, check_hard_link_write, check_same_device, host_error, mutation_error,
};
use crate::resolver::{ExportRoot, Handle, retry};

/// The permission bits a caller may set.
///
/// `0o777` exactly: no set-user-ID, no set-group-ID and no sticky bit. A mode
/// outside it is refused rather than masked.
pub const MODE_BITS_ALLOWED: u32 = 0o777;

/// Translate a requested permission word, refusing anything outside
/// [`MODE_BITS_ALLOWED`].
fn mode_of(mode: u32) -> Result<Mode, FsError> {
    if mode & !MODE_BITS_ALLOWED != 0 {
        return Err(FsError::refused(FsErrorCode::Einval));
    }
    // The host's raw mode word is `u16` on Apple and `u32` on Linux, so the
    // conversion is a fallible one written once rather than a cast per host.
    // It cannot fail: the check above bounds `mode` at `0o777`.
    let raw = mode
        .try_into()
        .map_err(|_| FsError::refused(FsErrorCode::Einval))?;
    Ok(Mode::from_bits_truncate(raw))
}

impl Handle {
    /// Write to this descriptor at an absolute offset.
    ///
    /// **Positioned, never seek-then-write**, for the same reason
    /// [`Handle::read_at`] is: a 9P `Twrite` carries its own offset, several may
    /// be outstanding on one fid at once, and a shared file position would let
    /// two concurrent writes of one fid each move the other's.
    ///
    /// A **short write is an ordinary result and is not an error.** It is the
    /// only partial outcome this profile can express on the wire: the `Rwrite`
    /// carries the count the host acknowledged, and the contract's
    /// `bytesAcknowledged` is built from exactly these. A caller that wanted the
    /// rest issues another `Twrite`; nothing here retries on its behalf, because
    /// a retry is a second dispatch and this profile never replays a mutation.
    ///
    /// # Errors
    ///
    /// A translated host failure, marked [`Outcome::Failed`]: the write was
    /// dispatched and the host reported it applied nothing. `EINTR` is retried
    /// rather than surfaced, exactly as everywhere else in this crate — and a
    /// `pwrite` interrupted *after* transferring bytes returns the count rather
    /// than `EINTR`, so the retry cannot hide a partial transfer.
    pub fn write_at(&self, offset: u64, data: &[u8]) -> Result<usize, FsError> {
        retry(|| rustix::io::pwrite(self.as_fd(), data, offset)).map_err(mutation_error)
    }

    /// Truncate or extend this descriptor to `size`.
    ///
    /// The caller is responsible for having applied the hard-link rule to the
    /// identity this descriptor reports; [`ExportRoot::set_size_through`] is the
    /// entry point that does.
    ///
    /// # Errors
    ///
    /// A translated host failure, marked [`Outcome::Failed`].
    pub fn set_size(&self, size: u64) -> Result<(), FsError> {
        retry(|| rustix::fs::ftruncate(self.as_fd(), size)).map_err(mutation_error)
    }

    /// Change this descriptor's permission bits.
    ///
    /// # Errors
    ///
    /// [`FsErrorCode::Einval`] for a mode outside [`MODE_BITS_ALLOWED`], or a
    /// translated host failure marked [`Outcome::Failed`].
    pub fn set_mode(&self, mode: u32) -> Result<(), FsError> {
        let mode = mode_of(mode)?;
        retry(|| rustix::fs::fchmod(self.as_fd(), mode)).map_err(mutation_error)
    }

    /// Change this descriptor's access and modification times.
    ///
    /// Each half is either a supplied `(seconds, nanoseconds)` pair or `None`,
    /// which leaves that timestamp alone. The `ctime` is the host's and is never
    /// settable, which is how gate 3's mask refusal of `ctime` is honoured here
    /// rather than only there.
    ///
    /// # Errors
    ///
    /// A translated host failure marked [`Outcome::Failed`], or
    /// [`FsErrorCode::Einval`] for a nanosecond field outside its range.
    pub fn set_times(
        &self,
        atime: Option<(u64, u64)>,
        mtime: Option<(u64, u64)>,
    ) -> Result<(), FsError> {
        let times = rustix::fs::Timestamps {
            last_access: timespec_of(atime)?,
            last_modification: timespec_of(mtime)?,
        };
        retry(|| rustix::fs::futimens(self.as_fd(), &times)).map_err(mutation_error)
    }
}

/// A supplied timestamp, or the host's own "leave this one alone" sentinel.
///
/// `UTIME_OMIT` is written out as its Linux value the way every other numeric
/// constant in this profile is, rather than taken from a libc binding: the two
/// hosts agree on it, and a build that took it from a binding would agree with
/// whichever host it was compiled on instead of with the wire.
fn timespec_of(value: Option<(u64, u64)>) -> Result<rustix::fs::Timespec, FsError> {
    /// `UTIME_OMIT`, the `tv_nsec` value meaning "do not change this field".
    const OMIT: i64 = 0x3fff_ffff;
    let Some((seconds, nanoseconds)) = value else {
        return Ok(rustix::fs::Timespec {
            tv_sec: 0,
            tv_nsec: OMIT as _,
        });
    };
    if nanoseconds >= 1_000_000_000 {
        // A nanosecond field at or above one second is not a time this host can
        // represent, and normalising it into the seconds field would apply a
        // different timestamp from the one the caller named.
        return Err(FsError::refused(FsErrorCode::Einval));
    }
    let tv_sec = i64::try_from(seconds).map_err(|_| FsError::refused(FsErrorCode::Einval))?;
    Ok(rustix::fs::Timespec {
        tv_sec: tv_sec as _,
        tv_nsec: i64::try_from(nanoseconds).unwrap_or(0) as _,
    })
}

impl ExportRoot {
    /// Open an existing file for writing, optionally readable and optionally
    /// truncating.
    ///
    /// The four `Tlopen` shapes that can reach this — write, read-write, and
    /// either of those truncating — differ only in the primitive they are
    /// authorized under and the descriptor's own access mode. **The truncation
    /// is applied to the descriptor afterwards, never as `O_TRUNC` on the
    /// resolving open**, which is gate 2's pinned choice unchanged: the
    /// hard-link rule runs between the open and the truncation, so a refused
    /// write cannot follow a truncation that already destroyed the content.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::open_write`], under [`Primitive::OpenTruncate`] when
    /// `truncate` is set.
    pub fn open_writable(
        &self,
        path: &VirtualPath,
        truncate: bool,
        readable: bool,
    ) -> Result<Handle, FsError> {
        let primitive = if truncate {
            Primitive::OpenTruncate
        } else {
            Primitive::OpenWrite
        };
        let intent = if readable {
            crate::resolver::Intent::ReadWrite
        } else {
            crate::resolver::Intent::Write
        };
        let handle = self.open_for_size_change_with(path, primitive, intent)?;
        if truncate {
            handle.set_size(0)?;
        }
        Ok(handle)
    }

    /// Create a regular file, exclusively, and return its descriptor.
    ///
    /// The created file's parent is resolved by the anchored walk and the name
    /// is opened relative to that descriptor with `O_CREAT | O_EXCL |
    /// O_NOFOLLOW`. `O_EXCL` is unconditional, so this can only ever create:
    /// an existing name — a regular file, a directory or a symbolic link alike
    /// — is `EEXIST` and nothing is opened.
    ///
    /// The descriptor is the one the creating `openat` produced. Nothing
    /// reopens the name afterwards, so the file a caller writes through is the
    /// file this call made.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `write`; [`FsErrorCode::Einval`] for a
    /// mode outside [`MODE_BITS_ALLOWED`] or for the export root itself;
    /// [`FsErrorCode::Eexist`] when the name is taken; any confinement refusal
    /// from resolving the parent, all of which are [`Outcome::NotStarted`]; or
    /// a translated host failure from the `openat`, which is
    /// [`Outcome::Failed`].
    pub fn create(
        &self,
        path: &VirtualPath,
        mode: u32,
        truncating: bool,
        readable: bool,
    ) -> Result<Handle, FsError> {
        self.authorize(Primitive::Create)?;
        if truncating {
            // A create carrying `O_TRUNC` needs the truncate authority too,
            // even though an exclusively created file has nothing to truncate:
            // the grant is checked against what the request asked for, never
            // against what it turned out to need.
            self.authorize(Primitive::OpenTruncate)?;
        }
        let mode = mode_of(mode)?;
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        let descriptor = retry(|| {
            rustix::fs::openat(
                parent.as_fd(),
                name,
                OFlags::CREATE
                    | OFlags::EXCL
                    | if readable {
                        OFlags::RDWR
                    } else {
                        OFlags::WRONLY
                    }
                    | OFlags::NOFOLLOW
                    | OFlags::CLOEXEC,
                mode,
            )
        })
        .map_err(mutation_error)?;
        // The identity is taken from the descriptor `openat` returned, not from
        // a `statat` on the name: the two can already disagree, and only the
        // first is the file this call created.
        self.adopt(descriptor)
    }

    /// Create a directory.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::create`], under [`Primitive::Mkdir`].
    pub fn make_directory(&self, path: &VirtualPath, mode: u32) -> Result<FileIdentity, FsError> {
        self.authorize(Primitive::Mkdir)?;
        let mode = mode_of(mode)?;
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        retry(|| rustix::fs::mkdirat(parent.as_fd(), name, mode)).map_err(mutation_error)?;
        // The qid the reply carries has to describe the directory that was
        // made, and the only way to learn its identity is to ask.  A `statat`
        // on the same anchored parent descriptor cannot re-resolve an earlier
        // component; what it can observe is another process having replaced the
        // name in between, which is reported as the race it is rather than as a
        // successful `Rmkdir` naming something else.
        let stat = rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(host_error)?;
        let identity = FileIdentity::from_stat(&stat);
        if identity.kind() != FileKind::Directory {
            return Err(crate::policy::lost_race());
        }
        check_same_device(self.identity(), identity)?;
        Ok(identity)
    }

    /// Remove a name from its directory.
    ///
    /// `remove_directory` selects the `AT_REMOVEDIR` form, which gate 3 decoded
    /// from `Tunlinkat`'s flag word and gate 1 authorizes as a separate
    /// primitive: removing a directory and removing a file are two decisions,
    /// not one with an argument.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `delete`; [`FsErrorCode::Enotsup`]
    /// when the name is a special file; [`FsErrorCode::Exdev`] when it is a
    /// mount point; any confinement refusal, all [`Outcome::NotStarted`]; or a
    /// translated host failure from the `unlinkat`, which is
    /// [`Outcome::Failed`].
    pub fn remove(&self, path: &VirtualPath, remove_directory: bool) -> Result<(), FsError> {
        self.authorize(if remove_directory {
            Primitive::RemoveDir
        } else {
            Primitive::Unlink
        })?;
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        inspect_removable(&parent, name)?;
        let flags = if remove_directory {
            AtFlags::REMOVEDIR
        } else {
            AtFlags::empty()
        };
        retry(|| rustix::fs::unlinkat(parent.as_fd(), name, flags)).map_err(mutation_error)
    }

    /// Rename inside this export, with both endpoints independently confined.
    ///
    /// This is [`ExportRoot::rename`]'s rule, plus the source inspection every
    /// other name-removing operation takes: a rename removes a name at the
    /// source, so a special file must be as unrenameable as it is unremovable
    /// or the refusal would have a spelling that got around it.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::remove`], under [`Primitive::Rename`], which
    /// additionally needs `write` **and** `delete` and the `atomicRename`
    /// feature.
    pub fn rename_checked(&self, from: &VirtualPath, to: &VirtualPath) -> Result<(), FsError> {
        self.authorize(Primitive::Rename)?;
        let from_name = from
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let to_name = to
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let from_parent = self.resolve_parent(from)?;
        let to_parent = self.resolve_parent(to)?;
        inspect_removable(&from_parent, from_name)?;
        retry(|| {
            rustix::fs::renameat(
                from_parent.as_fd(),
                from_name,
                to_parent.as_fd(),
                to_name,
            )
        })
        .map_err(mutation_error)
    }

    /// Create a symbolic link.
    ///
    /// Refused without the `symlinks` feature, by gate 1's own table, before
    /// any host call. The target is host text and is **not** resolved here: it
    /// is written verbatim and interpreted by the resolver's own re-rooting on
    /// every later traversal, which is what makes an absolute target refer to
    /// the exported virtual root rather than to host `/`. A target validated
    /// at creation and then trusted would be exactly the check-then-use bug the
    /// anchoring exists to remove.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::create`], under [`Primitive::Symlink`].
    pub fn symlink(&self, path: &VirtualPath, target: &str) -> Result<FileIdentity, FsError> {
        self.authorize(Primitive::Symlink)?;
        if target.is_empty() || target.as_bytes().contains(&0) {
            // An empty target names nothing and a NUL truncates the link in
            // every C-string host API, which is the same rule the namespace
            // applies to a path.
            return Err(FsError::refused(FsErrorCode::Einval));
        }
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        retry(|| rustix::fs::symlinkat(target, parent.as_fd(), name)).map_err(mutation_error)?;
        let stat = rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW)
            .map_err(host_error)?;
        let identity = FileIdentity::from_stat(&stat);
        if identity.kind() != FileKind::Symlink {
            return Err(crate::policy::lost_race());
        }
        Ok(identity)
    }

    /// Create a hard link to an already-resolved descriptor.
    ///
    /// Refused without the `hardLinks` feature. The source is a descriptor this
    /// crate resolved rather than a path, so the inode the new name refers to
    /// is the one the walk verified was inside the export; naming the source by
    /// path a second time would let it be replaced in between.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::create`], under [`Primitive::Link`].
    pub fn link(&self, source: &Handle, path: &VirtualPath) -> Result<(), FsError> {
        self.authorize(Primitive::Link)?;
        if source.kind() != FileKind::RegularFile {
            // A hard link to a directory is refused by every host this profile
            // serves, and to a special file by the profile itself.
            return Err(FsError::refused(FsErrorCode::Eperm));
        }
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        // `AT_EMPTY_PATH` with an empty name is the only spelling that links a
        // descriptor rather than a path, and it is not available on every host
        // this profile serves; `linkat` from the source's parent by name is
        // therefore not what happens here. What happens instead is a `/proc`
        // reopen on Linux and a refusal elsewhere — recorded, because a hard
        // link this profile cannot create anchored is one it must not create at
        // all.
        link_descriptor(source, &parent, name)
    }

    /// Change a file's size through an already-open descriptor.
    ///
    /// The hard-link rule is applied to the identity the descriptor reports
    /// **now**, not to the one it reported when it was opened: a file that has
    /// gained a second link since is one this rule must refuse, and a link
    /// count cached at open time would not see that.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `write`; `EPERM` when `hardLinks` is
    /// not advertised and the file now has `st_nlink > 1`; or a translated host
    /// failure marked [`Outcome::Failed`].
    pub fn set_size_through(&self, handle: &Handle, size: u64) -> Result<(), FsError> {
        self.authorize(Primitive::SetattrSize)?;
        let identity = handle.current_identity()?;
        if identity.kind() == FileKind::Directory {
            return Err(FsError::refused(FsErrorCode::Eisdir));
        }
        check_hard_link_write(
            Primitive::SetattrSize,
            identity,
            self.features().has(Feature::HardLinks),
        )?;
        handle.set_size(size)
    }

    /// Open a descriptor for an owned raw descriptor, verifying it as this
    /// crate verifies every other one.
    fn adopt(&self, descriptor: rustix::fd::OwnedFd) -> Result<Handle, FsError> {
        let handle = Handle::from_verified(descriptor)?;
        check_exportable(handle.kind())?;
        check_same_device(self.identity(), handle.identity())?;
        Ok(handle)
    }
}

/// Refuse a name this profile may not remove or rename away.
///
/// The inspection is a `statat` with `AT_SYMLINK_NOFOLLOW` on the anchored
/// parent descriptor, so it observes the entry itself and never what a symbolic
/// link points at.
///
/// A **symbolic link is permitted here** with the `symlinks` feature off, which
/// is the one place this module is more permissive than the resolver: neither
/// `unlinkat` nor `renameat` follows its final component, so neither can be
/// steered outside the root by one, and refusing would leave a link an export
/// cannot traverse also one it can never clear.
fn inspect_removable(parent: &Handle, name: &str) -> Result<(), FsError> {
    let stat =
        rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(host_error)?;
    let identity = FileIdentity::from_stat(&stat);
    if identity.kind() == FileKind::Symlink {
        return Ok(());
    }
    check_exportable(identity.kind())?;
    // A mount point is not this export's to remove even when its name is.
    let parent_identity = parent.current_identity()?;
    check_same_device(parent_identity, identity)
}

/// Link the file a descriptor holds into `parent` under `name`.
///
/// On Linux this is `linkat` through `/proc/self/fd`, which names the open
/// descriptor rather than a path a caller supplied. On every other host this
/// profile serves there is no spelling that links a descriptor, so the
/// operation is refused with `ENOTSUP` rather than implemented by re-resolving
/// the source's name — which would be the check-then-use bug rule 2 forbids,
/// applied to the one operation whose whole purpose is to create a second name
/// for an inode.
#[cfg(target_os = "linux")]
fn link_descriptor(source: &Handle, parent: &Handle, name: &str) -> Result<(), FsError> {
    use rustix::fs::CWD;
    let spelling = format!("/proc/self/fd/{}", rustix::fd::AsRawFd::as_raw_fd(&source.as_fd()));
    retry(|| {
        rustix::fs::linkat(
            CWD,
            spelling.as_str(),
            parent.as_fd(),
            name,
            AtFlags::SYMLINK_FOLLOW,
        )
    })
    .map_err(mutation_error)
}

#[cfg(not(target_os = "linux"))]
fn link_descriptor(source: &Handle, parent: &Handle, name: &str) -> Result<(), FsError> {
    let _ = (source, parent, name);
    Err(FsError::refused(FsErrorCode::Enotsup))
}

/// The outcome the *effecting* syscall's failure carries in this module, named
/// once so a reader can find the claim rather than infer it from nine call
/// sites. Everything a mutation does before that syscall keeps
/// [`Outcome::NotStarted`].
pub const EFFECTING_FAILURE_OUTCOME: Outcome = Outcome::Failed;
