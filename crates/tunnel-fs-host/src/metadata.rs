//! Metadata without content, and directory enumeration.
//!
//! **This module is gate 2's crate discharging two named gate-4 obligations.**
//! It is kept here, rather than in the endpoint, because both of them are
//! decisions about the host and neither may be taken anywhere the resolver's
//! anchoring does not already hold.
//!
//! # The metadata-only open
//!
//! "Pinned in code (gate 2)" closed with: *"gate 4 needs a metadata-only
//! open that does not require read permission, because `Tgetattr` is governed by
//! `list`, not by `read`, and a `list`-only grant must be able to stat a file it
//! may not read."* [`ExportRoot::metadata`] is that open — except that it is not
//! an open at all, which is the point. It resolves the **parent** by the same
//! anchored traversal every other operation uses and then answers from a
//! `statat` on the parent descriptor with `AT_SYMLINK_NOFOLLOW`. The file itself
//! is never opened, so a mode-`000` regular file answers metadata rather than
//! `EACCES`, and no permission but the traversal's own is consulted.
//!
//! That is not a weakening of the one rule. The authority is still a descriptor
//! this crate resolved: the *parent's*. The final component is named relative to
//! it in one syscall that cannot re-resolve an earlier component, which is the
//! same property `openat` gives the resolving open. What the caller loses is the
//! ability to act on the result — there is no descriptor to act with — and
//! `Tgetattr` needs none.
//!
//! # Directory enumeration and the outward `OsStr` refusal
//!
//! "Pinned in code (gate 3)" pinned the policy and named this as the
//! place it is implemented: *"an entry whose host name is not representable in
//! UTF-8 fails the **whole** `Treaddir` with `EINVAL`; it is not skipped."*
//! [`DirReader::next_entry`] is where an `OsStr` becomes a `String`, so it is
//! where the refusal is taken. Skipping would hide a file from a caller that
//! believes it received the entire listing, which is the silent substitution the
//! refuse-never-repair rule exists to prevent.
//!
//! **A special file is a different case and is skipped, deliberately.** A FIFO,
//! a socket, a device node or anything else outside the three kinds the profile
//! serves is left out of the listing, because the profile refuses it at every
//! other operation too — the `type[1]` byte of an `Rreaddir` record has no
//! spelling for one, and a client that was told it existed could do nothing with
//! it but be refused. That absence *agrees* with the rest of the profile, which
//! is exactly what the unrepresentable name's absence would not.

use rustix::fs::{AtFlags, Dir, Stat};

use tunnel_fs_core::{FsError, FsErrorCode, LimitField, Primitive, VirtualPath};

use crate::identity::{FileIdentity, FileKind};
use crate::policy::{check_exportable, check_same_device, host_error};
use crate::resolver::{ExportRoot, Handle, Intent};

/// Widen a host `Stat` field into the wire's 64-bit unsigned form.
///
/// The field types differ by host and by `rustix` backend — `st_blksize` is
/// `u32` on the Linux raw backend and `i64` through libc, `st_atime_nsec` is
/// `u32` on one and `c_long` on another — so the conversion is written once,
/// generically, rather than as a cast per field. A negative or impossible value
/// becomes zero rather than wrapping: a timestamp this profile cannot represent
/// is reported absent, never as a different time.
fn widen<T: TryInto<u64>>(value: T) -> u64 {
    value.try_into().unwrap_or(0)
}

/// The outward conversion, and the only one in this profile.
///
/// This is the `OsStr`-to-`String` boundary gate 3 named as gate 4's, and the
/// refusal is taken here because this is the only place it can be. It is a
/// **refusal, never a repair**: a `from_utf8_lossy` would turn one host name
/// into a different one and hand a caller a name that does not exist, and the
/// caller's whole listing fails rather than quietly losing one entry.
///
/// A separate function, rather than two lines inside the loop, because on a host
/// whose filesystem enforces UTF-8 — APFS does — no directory can be built that
/// reaches it, so this is the only form in which the decision can be tested at
/// all. See the unit test below and the `#[ignore]`d integration case.
///
/// # Errors
///
/// [`FsErrorCode::Einval`], the same answer gate 2 already gives for a symbolic
/// link target that is not valid UTF-8.
fn entry_name(raw: &core::ffi::CStr) -> Result<&str, FsError> {
    core::str::from_utf8(raw.to_bytes()).map_err(|_| FsError::refused(FsErrorCode::Einval))
}

/// What the host says about one node, without its content.
///
/// Payload-free in the sense the contract requires of a *rendering*: the owner
/// uid and gid are deliberately **not** here at all, so there is no accessor
/// through which a host identity could reach the wire, and the inode number
/// reaches it only as the qid fold [`FileIdentity::qid_path`] already performs.
/// `Debug` shows the node kind and nothing else.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct Metadata {
    identity: FileIdentity,
    mode: u32,
    size: u64,
    blksize: u64,
    blocks: u64,
    atime_sec: u64,
    atime_nsec: u64,
    mtime_sec: u64,
    mtime_nsec: u64,
    ctime_sec: u64,
    ctime_nsec: u64,
}

impl Metadata {
    fn from_stat(stat: &Stat) -> Self {
        Self {
            identity: FileIdentity::from_stat(stat),
            mode: u32::try_from(widen(stat.st_mode)).unwrap_or(0),
            size: widen(stat.st_size),
            blksize: widen(stat.st_blksize),
            blocks: widen(stat.st_blocks),
            atime_sec: widen(stat.st_atime),
            atime_nsec: widen(stat.st_atime_nsec),
            mtime_sec: widen(stat.st_mtime),
            mtime_nsec: widen(stat.st_mtime_nsec),
            ctime_sec: widen(stat.st_ctime),
            ctime_nsec: widen(stat.st_ctime_nsec),
        }
    }

    /// The node's identity, which is also where its qid comes from.
    #[must_use]
    pub const fn identity(self) -> FileIdentity {
        self.identity
    }

    /// The node kind.
    #[must_use]
    pub const fn kind(self) -> FileKind {
        self.identity.kind()
    }

    /// POSIX mode bits, including the file-type bits.
    #[must_use]
    pub const fn mode(self) -> u32 {
        self.mode
    }

    /// Size in bytes.
    #[must_use]
    pub const fn size(self) -> u64 {
        self.size
    }

    /// Preferred block size.
    #[must_use]
    pub const fn blksize(self) -> u64 {
        self.blksize
    }

    /// Allocated blocks.
    #[must_use]
    pub const fn blocks(self) -> u64 {
        self.blocks
    }

    /// Access time, as `(seconds, nanoseconds)`.
    #[must_use]
    pub const fn atime(self) -> (u64, u64) {
        (self.atime_sec, self.atime_nsec)
    }

    /// Modification time, as `(seconds, nanoseconds)`.
    #[must_use]
    pub const fn mtime(self) -> (u64, u64) {
        (self.mtime_sec, self.mtime_nsec)
    }

    /// Status-change time, as `(seconds, nanoseconds)`.
    #[must_use]
    pub const fn ctime(self) -> (u64, u64) {
        (self.ctime_sec, self.ctime_nsec)
    }

    /// The hard-link count.
    #[must_use]
    pub const fn links(self) -> u64 {
        self.identity.links()
    }
}

impl core::fmt::Debug for Metadata {
    /// Redacting, like [`FileIdentity`]'s.
    ///
    /// A size and a modification time are not a path, but they are the contents
    /// of a reply, and a `Debug` that carried them would put one file's
    /// observable state into every log line that formatted this type.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("Metadata")
            .field("kind", &self.identity.kind().as_str())
            .finish_non_exhaustive()
    }
}

/// One directory entry, already converted out of the host's bytes.
#[derive(Clone, Eq, PartialEq)]
pub struct HostEntry {
    name: String,
    kind: FileKind,
    qid_path: u64,
    cookie: u64,
}

impl HostEntry {
    /// The entry's name, one path component.
    ///
    /// An explicit accessor, exactly as [`VirtualPath::as_str`] is: the name
    /// leaves this type only where a caller asked for it.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The entry's node kind, always one of the three the profile serves.
    #[must_use]
    pub const fn kind(&self) -> FileKind {
        self.kind
    }

    /// The qid path for this entry, folded the same way every other qid is.
    #[must_use]
    pub const fn qid_path(&self) -> u64 {
        self.qid_path
    }

    /// The opaque cookie a later `Treaddir` resumes from.
    ///
    /// A position in the [`DirReader`] that produced it — the number of servable
    /// entries returned since its last rewind — and **not** the host's own
    /// `d_off`, for the reason recorded on `DirReader`: `rustix` exposes
    /// `DirEntry::offset` on Linux and not on Apple, and a cookie that existed
    /// on one host and not another would make the wire protocol's behaviour
    /// depend on the serving operating system. Nothing in this profile
    /// interprets it or orders by it; it is carried back unchanged.
    #[must_use]
    pub const fn cookie(&self) -> u64 {
        self.cookie
    }
}

impl core::fmt::Debug for HostEntry {
    /// Redacting: the name is a file name, which no rendering may carry.
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter
            .debug_struct("HostEntry")
            .field("kind", &self.kind.as_str())
            .finish_non_exhaustive()
    }
}

/// An open directory being enumerated.
///
/// # The cookie is a position in this reader, not the host's `d_off`
///
/// 9P2000.L's `Treaddir` offset is an opaque cookie, and this profile takes it
/// literally. The obvious implementation would hand back the host's own
/// directory offset — but `d_off` and `seekdir` are **not available on every
/// host this crate serves**: `rustix` exposes `DirEntry::offset` on Linux and
/// the Solarish and a few other systems, and not on Apple, which is the only
/// host gate 2 has ever run on. A cookie that existed on one host and not
/// another would make the wire protocol's behaviour depend on the serving
/// operating system, which is the thing the namespace rules exist to prevent.
///
/// So the cookie is the number of servable entries this reader has returned
/// since its last rewind: `0` before the first, `n` after the `n`th. Resuming
/// at a cookie the reader is already positioned at costs nothing; resuming
/// anywhere else rewinds and re-reads, bounded by the caller's own budget. The
/// contract promises no snapshot and no stable order, and this promises
/// neither: entries added or removed between two `Treaddir`s can shift what a
/// re-read sees, exactly as `seekdir` on a live directory can.
pub struct DirReader {
    dir: Dir,
    /// How many servable entries have been returned since the last rewind.
    position: u64,
    /// The export root's identity, for the mount-boundary check on each entry.
    root: FileIdentity,
    /// How many unservable entries one call may pass over before refusing.
    ///
    /// The block a `Treaddir` fills bounds the entries it *returns*, and bounds
    /// nothing about the entries it skips: `.`, `..`, a special file, an entry
    /// on another filesystem and one removed between `readdir` and `statat` all
    /// cost a `statat` and take no space in the reply. A directory of ten
    /// thousand FIFOs would therefore make one `Treaddir` perform ten thousand
    /// host calls for an empty block, which is unbounded work behind a bounded
    /// answer. This is the contract's recursive-traversal entry limit applied
    /// to that work.
    skip_budget: u64,
}

impl core::fmt::Debug for DirReader {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        formatter.debug_struct("DirReader").finish_non_exhaustive()
    }
}

impl DirReader {
    /// Rewind to the start of the directory.
    pub fn rewind(&mut self) {
        self.dir.rewind();
        self.position = 0;
    }

    /// How many servable entries have been returned since the last rewind.
    #[must_use]
    pub const fn position(&self) -> u64 {
        self.position
    }

    /// Position the reader at `cookie`.
    ///
    /// `budget` bounds how many entries a re-read may consume, so a client
    /// cannot make one `Treaddir` walk an arbitrarily large directory by naming
    /// a large cookie. The contract's recursive-traversal entry limit is what a
    /// caller passes.
    ///
    /// # Errors
    ///
    /// [`FsErrorCode::Einval`] for a cookie past the end of the directory or
    /// beyond `budget`, and any translated host failure from the re-read.
    pub fn seek(&mut self, cookie: u64, budget: u64) -> Result<(), FsError> {
        if cookie == self.position {
            return Ok(());
        }
        // The budget refusal and the end-of-directory refusal below answer the
        // same code, so no test can tell them apart and this one is green when
        // deleted on its own. It is kept because it bounds the *work* a single
        // `Treaddir` can demand — a client naming a large cookie would otherwise
        // walk the whole directory before being refused — and that is a bound,
        // not an answer.
        if cookie > budget {
            return Err(FsError::refused(FsErrorCode::Einval));
        }
        self.rewind();
        while self.position < cookie {
            if self.next_entry()?.is_none() {
                // The cookie names a position this directory no longer has.
                // `EINVAL` rather than an empty listing: an empty `Rreaddir` is
                // end-of-directory, and answering one here would tell a
                // resuming client it had seen every entry.
                return Err(FsError::refused(FsErrorCode::Einval));
            }
        }
        Ok(())
    }

    /// The next entry the profile can serve, or `None` at the end.
    ///
    /// `.` and `..` are never returned: gate 1 refuses both as path components,
    /// so a client that walked to one would be refused, and a listing that named
    /// them would advertise names this namespace does not have.
    ///
    /// # Errors
    ///
    /// [`FsErrorCode::Einval`] for an entry name that is not valid UTF-8, which
    /// fails the **whole** enumeration — see this module's own documentation for
    /// why it is not skipped — and any translated host failure.
    pub fn next_entry(&mut self) -> Result<Option<HostEntry>, FsError> {
        let mut skipped = 0_u64;
        loop {
            if skipped > self.skip_budget {
                // A bound on work, not a statement about the directory: the
                // caller asked for one entry and this call has already passed
                // over more unservable ones than the negotiated traversal-entry
                // limit permits.
                return Err(FsError::Limit(LimitField::MaxTraversalEntries));
            }
            let Some(entry) = self.dir.read() else {
                return Ok(None);
            };
            let entry = entry.map_err(host_error)?;
            let raw = entry.file_name();
            let name = entry_name(raw)?;
            if name == "." || name == ".." {
                // The two fixed entries are not charged to the skip budget: a
                // negotiated ceiling of one or two would otherwise refuse every
                // listing before a single entry was served.
                continue;
            }
            // The kind and the identity are asked of the host by name relative
            // to this directory's own descriptor, not taken from the `d_type`
            // byte: `d_type` is `DT_UNKNOWN` on several filesystems, and a
            // profile that trusted it would serve a special file on those.
            let fd = self.dir.fd().map_err(host_error)?;
            let stat = match rustix::fs::statat(fd, raw, AtFlags::SYMLINK_NOFOLLOW) {
                Ok(stat) => stat,
                // The entry was removed between `readdir` and `statat`.  A live
                // filesystem is what the contract says enumeration observes, so
                // this is an ordinary outcome and not a failure of the listing.
                Err(rustix::io::Errno::NOENT) => {
                    skipped += 1;
                    continue;
                }
                Err(errno) => return Err(host_error(errno)),
            };
            let identity = FileIdentity::from_stat(&stat);
            // A special file is left out rather than refused: the profile
            // denies it everywhere else too, so its absence agrees with every
            // other answer a caller could get about it.
            if check_exportable(identity.kind()).is_err() {
                skipped += 1;
                continue;
            }
            // An entry on another filesystem is a mount point.  Walking into it
            // is `EXDEV`, so naming it in a listing would advertise a node no
            // operation can reach.
            if check_same_device(self.root, identity).is_err() {
                skipped += 1;
                continue;
            }
            self.position = self.position.saturating_add(1);
            return Ok(Some(HostEntry {
                name: name.to_owned(),
                kind: identity.kind(),
                qid_path: identity.qid_path(),
                cookie: self.position,
            }));
        }
    }
}

impl Handle {
    /// This descriptor's metadata.
    ///
    /// Asked of the open file, not of the name it was reached by, so a fid whose
    /// name was unlinked or replaced still answers for the file it was resolved
    /// to.
    ///
    /// # Errors
    ///
    /// A translated host failure.
    pub fn metadata(&self) -> Result<Metadata, FsError> {
        let stat = rustix::fs::fstat(self.as_fd()).map_err(host_error)?;
        Ok(Metadata::from_stat(&stat))
    }

    /// Read from this descriptor at an absolute offset.
    ///
    /// **Positioned, never seek-then-read.** A 9P `Tread` carries its own
    /// offset and several may be outstanding at once on one fid, so a shared
    /// file position would let two concurrent reads of one fid each move the
    /// other's offset and return bytes neither asked for.
    ///
    /// A short read is an ordinary result and is not an error: it is what the
    /// end of a file looks like, and the 9P profile says so too.
    ///
    /// # Errors
    ///
    /// A translated host failure. `EINTR` is retried rather than
    /// surfaced, exactly as everywhere else in this crate.
    pub fn read_at(&self, offset: u64, out: &mut [u8]) -> Result<usize, FsError> {
        // `pread` takes the buffer by value, so the closure cannot capture it:
        // a reborrow inside the loop is what makes the `EINTR` retry expressible
        // without a second buffer.
        loop {
            match rustix::io::pread(self.as_fd(), &mut *out, offset) {
                Err(errno) if errno == rustix::io::Errno::INTR => {}
                other => return other.map_err(host_error),
            }
        }
    }
}

impl ExportRoot {
    /// Metadata for `path`, **without opening it**.
    ///
    /// This is the gate-4 obligation gate 2 recorded: `Tgetattr` is governed by
    /// `list`, so a `list`-without-`read` grant must be able to stat a file it
    /// may not read, and [`Intent::Inspect`] cannot serve that because it opens
    /// the file read-only on both hosts.
    ///
    /// The export root itself is answered from the retained root descriptor.
    /// Every other path is answered by resolving its **parent** through the
    /// ordinary anchored walk and asking the host about the final component
    /// relative to that descriptor, with `AT_SYMLINK_NOFOLLOW`, in one syscall.
    ///
    /// A final component that is a symbolic link is refused with `ELOOP` when
    /// the `symlinks` feature is off, which is what the walk itself does with
    /// one; with the feature on it is followed by the ordinary resolution, which
    /// does require read permission on what it reaches. That asymmetry is
    /// deliberate and is recorded rather than hidden: the profile advertises no
    /// symbolic links by default, so the metadata-only path is the only one gate
    /// 4 actually uses.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without the `list` capability, and any
    /// confinement refusal or translated host failure.
    pub fn metadata(&self, path: &VirtualPath) -> Result<Metadata, FsError> {
        self.authorize(Primitive::Getattr)?;
        self.metadata_unchecked(path)
    }

    /// The metadata lookup without the capability check.
    ///
    /// Separate so an operation that has already authorized a *different*
    /// primitive — an open, which needs the node's kind before it can classify
    /// itself — does not have to hold `list` as well.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::metadata`], less the capability refusal.
    pub fn metadata_unchecked(&self, path: &VirtualPath) -> Result<Metadata, FsError> {
        let Some(name) = path.file_name() else {
            // The export root.  It has no parent inside the export, and its own
            // descriptor is the authority for it.
            let handle = self.resolve(path, Intent::Inspect)?;
            return handle.metadata();
        };
        let parent = self.resolve_parent(path)?;
        let stat = match rustix::fs::statat(parent.as_fd(), name, AtFlags::SYMLINK_NOFOLLOW) {
            Ok(stat) => stat,
            Err(errno) => return Err(host_error(errno)),
        };
        let identity = FileIdentity::from_stat(&stat);
        if identity.kind() == FileKind::Symlink {
            // Rule 3, unchanged, and decided **before** the exportable-kind
            // check: a symbolic link is not an exportable *destination*, so
            // `check_exportable` answers `ENOTSUP` for one, and taking that
            // answer here would report a link the feature refuses as a node the
            // profile does not implement.  With the feature off the walk's own
            // `ELOOP` is the right answer; with it on the walk is also what
            // re-roots the target, and this cannot reproduce that without
            // repeating it.
            return self
                .resolve(path, Intent::Inspect)
                .and_then(|handle| handle.metadata());
        }
        check_exportable(identity.kind())?;
        check_same_device(self.identity(), identity)?;
        Ok(Metadata::from_stat(&stat))
    }

    /// Read a symbolic link's target, without following it.
    ///
    /// The parent is resolved by the ordinary anchored walk and the final
    /// component is read relative to that descriptor with `readlinkat`, which
    /// never follows. The target is the host's own bytes and is **not**
    /// resolved, re-rooted or validated as a virtual path here: it is text a
    /// caller asked to see, and the re-rooting that makes an absolute target
    /// mean the exported root happens on the next traversal, in the resolver.
    ///
    /// A target that is not valid UTF-8 is [`FsErrorCode::Einval`] and an empty
    /// one [`FsErrorCode::Enoent`] — gate 2's own boundary, unchanged, and the
    /// outward half of the refuse-never-substitute rule: no `from_utf8_lossy`
    /// is reachable from here.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `read` or without the `symlinks`
    /// feature; [`FsErrorCode::Einval`] for the export root or a target that is
    /// not UTF-8; [`FsErrorCode::Enoent`] for an empty target; or any
    /// confinement refusal.
    pub fn read_link(&self, path: &VirtualPath) -> Result<String, FsError> {
        self.authorize(Primitive::Readlink)?;
        let name = path
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let parent = self.resolve_parent(path)?;
        let target =
            rustix::fs::readlinkat(parent.as_fd(), name, Vec::new()).map_err(host_error)?;
        let bytes = target.to_bytes();
        if bytes.is_empty() {
            return Err(FsError::refused(FsErrorCode::Enoent));
        }
        core::str::from_utf8(bytes)
            .map(str::to_owned)
            .map_err(|_| FsError::refused(FsErrorCode::Einval))
    }

    /// Open a directory for enumeration and take its host directory stream.
    ///
    /// The descriptor is resolved by [`ExportRoot::open_directory`], so the
    /// `list` capability, the anchoring, the mount boundary and the special-file
    /// refusal are all applied exactly as they are for any other open.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::open_directory`], plus a translated host failure from
    /// taking the directory stream.
    pub fn read_directory(
        &self,
        path: &VirtualPath,
        skip_budget: u64,
    ) -> Result<DirReader, FsError> {
        let handle = self.open_directory(path)?;
        self.reader_for(&handle, skip_budget)
    }

    /// The directory stream for an already-resolved directory descriptor.
    ///
    /// Used by the endpoint, which resolves a directory once when a fid is
    /// opened and enumerates it across many `Treaddir` requests.
    ///
    /// `skip_budget` bounds how many unservable entries one `next_entry` may
    /// pass over; the contract's recursive-traversal entry limit is what a
    /// caller passes.
    ///
    /// # Errors
    ///
    /// [`FsErrorCode::Enotdir`] when the handle is not a directory, or a
    /// translated host failure.
    pub fn reader_for(&self, handle: &Handle, skip_budget: u64) -> Result<DirReader, FsError> {
        if handle.kind() != FileKind::Directory {
            return Err(FsError::refused(FsErrorCode::Enotdir));
        }
        // `read_from` duplicates the descriptor, so the caller keeps its handle
        // and both refer to the one file this crate resolved.  No name is
        // re-resolved.
        let dir = Dir::read_from(handle.as_fd()).map_err(host_error)?;
        Ok(DirReader {
            dir,
            position: 0,
            root: self.identity(),
            skip_budget,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::entry_name;
    use tunnel_fs_core::FsErrorCode;

    /// The outward refusal, in the only form this host can exercise.
    ///
    /// APFS enforces UTF-8 on file names, so no directory on this machine can
    /// hold one that is not — the integration case is `#[ignore]`d with that
    /// reason rather than printing a skip and passing.  The decision itself is
    /// still testable, and this is it: a lone continuation byte is refused with
    /// `EINVAL`, and nothing resembling `from_utf8_lossy`'s U+FFFD comes back.
    #[test]
    fn a_name_that_is_not_utf8_is_refused_and_never_repaired() {
        let error =
            entry_name(c"bad-\x80-name").expect_err("a lone continuation byte is not UTF-8");
        assert_eq!(error.code(), FsErrorCode::Einval);
    }

    #[test]
    fn an_ordinary_name_survives_byte_for_byte() {
        assert_eq!(
            entry_name(c"caf\u{e9} \u{1f600}.txt").expect("valid UTF-8"),
            "caf\u{e9} \u{1f600}.txt"
        );
    }
}
