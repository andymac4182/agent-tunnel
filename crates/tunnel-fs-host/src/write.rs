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
//! * **A mode carrying anything outside `0o777` is refused, never masked —
//!   once a `Tsetattr` mode's file-type bits have been discarded.**
//!   Set-user-ID, set-group-ID and the sticky bit are not bits this profile
//!   grants, and quietly dropping them would report a mode that was not
//!   applied. The namespace rule is refuse, never repair, and a mode is no
//!   different from a path. The file-type bits are the one exception, for the
//!   reason [`MODE_TYPE_BITS`] gives, and they are named here rather than left
//!   to contradict this sentence from further down the file.
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
    after_effect, check_exportable, check_hard_link_write, check_same_device, host_error,
    mutation_error,
};
use crate::resolver::{ExportRoot, Handle, retry};

/// The test-only hook that occupies the window between a creating syscall and
/// the identity read that gives its reply a qid.
///
/// This module exists **only** under the `post-effect-hook` feature, which no
/// shipped build enables: with the feature off there is no hook, no
/// thread-local and no call site. It is here on exactly the terms
/// [`crate::resolver::race_window`] is, and for the same reason — the window is
/// microseconds wide, and the rule it protects is one this gate would otherwise
/// have to assert rather than measure: after the effect, a failure is
/// `unknown`, never `not_started`.
#[cfg(feature = "post-effect-hook")]
pub mod post_effect {
    use std::cell::Cell;

    thread_local! {
        static HOOK: Cell<Option<fn()>> = const { Cell::new(None) };
    }

    /// Run `hook` on this thread after each creating syscall in this module and
    /// before the identity read that follows it.
    pub fn set(hook: fn()) {
        HOOK.with(|slot| slot.set(Some(hook)));
    }

    /// Stop running any hook on this thread.
    pub fn clear() {
        HOOK.with(|slot| slot.set(None));
    }

    pub(crate) fn fire() {
        if let Some(hook) = HOOK.with(Cell::get) {
            hook();
        }
    }
}

/// Fire the post-effect hook, or do nothing when it is not compiled in.
#[inline]
fn fire_post_effect_hook() {
    #[cfg(feature = "post-effect-hook")]
    post_effect::fire();
}

/// The permission bits a caller may set.
///
/// `0o777` exactly: no set-user-ID, no set-group-ID and no sticky bit. A mode
/// outside it is refused rather than masked — **once a `Tsetattr` mode's
/// file-type bits have been discarded**, which is the one exception and is
/// [`MODE_TYPE_BITS`]'s own business rather than this constant's.
pub const MODE_BITS_ALLOWED: u32 = 0o777;

/// `S_IFMT`: the file-type bits of a mode word.
///
/// **Discarded from a `Tsetattr` mode rather than refused**, and this is the one
/// place a mode is repaired rather than rejected — so the reason had better be
/// good. It is: Linux's own v9fs client sends `Tsetattr`'s `mode` as the
/// kernel's `ia_mode`, which carries the node's type bits alongside its
/// permissions, so refusing them would refuse every `chmod` from the reference
/// client. They are not a grant of anything either — a type bit *describes* a
/// node and cannot change one; `fchmod` ignores them — so dropping them cannot
/// apply a permission the caller did not ask for, which is what the
/// refuse-never-repair rule exists to prevent. The set-user-ID, set-group-ID
/// and sticky bits are a different case and stay refused: those do grant.
pub const MODE_TYPE_BITS: u32 = 0o170_000;

/// Translate a requested permission word, refusing anything outside
/// [`MODE_BITS_ALLOWED`].
fn mode_of(mode: u32) -> Result<Mode, FsError> {
    if mode & !MODE_BITS_ALLOWED != 0 {
        return Err(FsError::refused(FsErrorCode::Einval));
    }
    // The host's raw mode word is `u16` on Apple and `u32` on Linux, so this
    // is a narrowing on one host and the identity on the other — which is
    // exactly what the `allow` is for, and why a cast is the wrong fix: `as`
    // compiles on both and would silently truncate if the bound above ever
    // moved, where the fallible conversion cannot. It cannot fail today: the
    // check above bounds `mode` at `0o777`.
    #[allow(clippy::useless_conversion)]
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
    /// [`FsErrorCode::Einval`] for a mode outside [`MODE_BITS_ALLOWED`] once
    /// its file-type bits are discarded, or a translated host failure marked
    /// [`Outcome::Failed`].
    pub fn set_mode(&self, mode: u32) -> Result<(), FsError> {
        let mode = mode_of(mode & !MODE_TYPE_BITS)?;
        retry(|| rustix::fs::fchmod(self.as_fd(), mode)).map_err(mutation_error)
    }

    /// Change this descriptor's access and modification times.
    ///
    /// The `ctime` is the host's and is never settable, which is how gate 3's
    /// mask refusal of `ctime` is honoured here rather than only there.
    ///
    /// # Errors
    ///
    /// A translated host failure marked [`Outcome::Failed`], or
    /// [`FsErrorCode::Einval`] for a nanosecond field outside its range.
    pub fn set_times(&self, atime: TimeChange, mtime: TimeChange) -> Result<(), FsError> {
        let times = rustix::fs::Timestamps {
            last_access: timespec_of(atime)?,
            last_modification: timespec_of(mtime)?,
        };
        retry(|| rustix::fs::futimens(self.as_fd(), &times)).map_err(mutation_error)
    }
}

/// What a `Tsetattr` asks of one timestamp.
///
/// `.L` gives each timestamp two mask bits: one saying "change this field" and
/// one saying "use the value I supplied rather than the current time". The
/// second is optional, and **the field bit without it is the ordinary case, not
/// an exotic one**: it is what `utimes(NULL)` sends, which is what `touch`
/// sends, so a profile that refused it would refuse `touch`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TimeChange {
    /// Leave this timestamp alone.
    Omit,
    /// Set it to the host's current time.
    ///
    /// **The host's clock, not this profile's.** `UTIME_NOW` is resolved by the
    /// kernel inside `futimens`; nothing here reads a clock. So this is not the
    /// clock enforcement the gate deliberately does not do — it is the absence
    /// of one, handed to the only party that has it.
    Now,
    /// Set it to a supplied `(seconds, nanoseconds)`.
    Explicit(u64, u64),
}

/// Translate one [`TimeChange`] into the host's own representation.
///
/// **`UTIME_NOW` and `UTIME_OMIT` are taken from `rustix`, not written out**,
/// and that is the opposite of what this profile does with the `.L` flag masks
/// — deliberately, because they are the opposite kind of constant. A flag mask
/// is a **wire** value: it arrives in a 9P message and must mean the same thing
/// on every serving host, so writing Linux's numbers out by hand is what keeps
/// a macOS build and a Linux build agreeing with each other. These two are
/// **host** values that legitimately differ — Apple spells them `-1` and `-2`,
/// Linux `(1 << 30) - 1` and `(1 << 30) - 2` — and hand-writing either set
/// would be the same mistake gate 2 already refuses for errnos, where using
/// `FsErrorCode::from_errno` on a host errno mistranslates on every non-Linux
/// host. An earlier round of this gate did write them out, with the two
/// swapped, and a `touch` silently changed nothing.
fn timespec_of(value: TimeChange) -> Result<rustix::fs::Timespec, FsError> {
    let (seconds, nanoseconds) = match value {
        TimeChange::Omit => {
            return Ok(rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_OMIT,
            });
        }
        TimeChange::Now => {
            return Ok(rustix::fs::Timespec {
                tv_sec: 0,
                tv_nsec: rustix::fs::UTIME_NOW,
            });
        }
        TimeChange::Explicit(seconds, nanoseconds) => (seconds, nanoseconds),
    };
    if nanoseconds >= 1_000_000_000 {
        // A nanosecond field at or above one second is not a time this host can
        // represent, and normalising it into the seconds field would apply a
        // different timestamp from the one the caller named. It is also what
        // keeps both sentinels unreachable from a caller's own value on the
        // host that spells them inside that range.
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
        // **Past this point the file exists**, so this read reports `unknown`
        // like every other post-effect read in this module — the `fstat`, the
        // exportable-kind check and the device check alike. Unreachable in
        // practice, because the descriptor `openat` just returned is a regular
        // file on the parent's own device by construction; kept and wrapped
        // anyway, because the pinned section says *every* post-effect read is
        // `unknown` and one that was not would make that sentence false.
        //
        // The identity is taken from the descriptor `openat` returned, not from
        // a `statat` on the name: the two can already disagree, and only the
        // first is the file this call created.
        self.adopt(descriptor).map_err(after_effect)
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
        // **Past this point the directory exists**, so every failure below is
        // reported through [`after_effect`] and is `unknown`, never
        // `not_started`.  The qid the reply carries has to describe the
        // directory that was made, and the only way to learn its identity is to
        // ask; a `statat` on the same anchored parent descriptor cannot
        // re-resolve an earlier component, but it *can* observe another process
        // having replaced or removed the name in between.  Reporting that
        // race's own `ENOENT` unchanged would tell a caller its `Tmkdir` never
        // started, with a directory on the host to show otherwise.
        identify_after_effect(&parent, name, FileKind::Directory)
            .and_then(|identity| check_same_device(self.identity(), identity).map(|()| identity))
            .map_err(after_effect)
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
        // **Both endpoints, not just the source.** `renameat` removes whatever
        // occupies the destination, so a rename onto a socket's or a FIFO's
        // name is a spelling of the special-file removal this module otherwise
        // refuses — which would make that refusal a refusal in name only.
        inspect_replaceable(&to_parent, to_name)?;
        retry(|| rustix::fs::renameat(from_parent.as_fd(), from_name, to_parent.as_fd(), to_name))
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
        // As in [`ExportRoot::make_directory`]: the link exists from here on,
        // so the identity read that gives the reply its qid reports `unknown`
        // when it fails rather than claiming the request never started.
        identify_after_effect(&parent, name, FileKind::Symlink).map_err(after_effect)
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

/// Read back the node a just-performed creation made, by name on its anchored
/// parent.
///
/// Split out because both callers need the same three steps and the same
/// answer, and because it is the one read in this module that happens **after**
/// an effect: its caller wraps it in [`after_effect`], and a reader should be
/// able to see that the wrapping covers the whole of it rather than one line.
///
/// A kind other than the one just created can only mean the name was replaced
/// between the creating syscall and this one. That is the race, and it takes
/// the uniform `ENOENT` answer the resolver already gives one — with the
/// outcome the caller adds, because here the race followed a real effect.
fn identify_after_effect(
    parent: &Handle,
    name: &str,
    expected: FileKind,
) -> Result<FileIdentity, FsError> {
    fire_post_effect_hook();
    let stat =
        rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW).map_err(host_error)?;
    let identity = FileIdentity::from_stat(&stat);
    if identity.kind() == expected {
        Ok(identity)
    } else {
        Err(crate::policy::lost_race())
    }
}

/// Refuse a destination whose current occupant this profile may not remove.
///
/// Absence is the ordinary case and is fine: a rename onto a free name replaces
/// nothing. An occupant is held to exactly the rule
/// [`inspect_removable`] applies, because `renameat` removes it.
///
/// **The window between this inspection and the `renameat` is not closed by
/// it**, and that is recorded rather than implied: another process can put a
/// socket at the destination in between, and the rename will then replace it.
/// Closing that window would need a `renameat` variant that refuses to replace
/// — `RENAME_NOREPLACE` exists on Linux and has no portable equivalent on the
/// only host this profile has run on — so what this narrowing buys is that a
/// *caller* cannot spell the removal, not that the host cannot race into it.
/// The escape it would be is bounded the same way every other race here is: the
/// destination parent is an anchored descriptor inside the export, so whatever
/// is replaced is inside the export too.
fn inspect_replaceable(parent: &Handle, name: &str) -> Result<(), FsError> {
    match rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(stat) => {
            let identity = FileIdentity::from_stat(&stat);
            if identity.kind() == FileKind::Symlink {
                return Ok(());
            }
            check_exportable(identity.kind())?;
            let parent_identity = parent.current_identity()?;
            check_same_device(parent_identity, identity)
        }
        Err(errno) if errno == rustix::io::Errno::NOENT => Ok(()),
        Err(errno) => Err(host_error(errno)),
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
    let spelling = format!(
        "/proc/self/fd/{}",
        rustix::fd::AsRawFd::as_raw_fd(&source.as_fd())
    );
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
