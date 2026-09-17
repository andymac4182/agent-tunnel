//! The OS-confined resolver.
//!
//! One rule governs everything in this file: **act on the descriptor you
//! resolved, never on the path you resolved it from.** Every operation here
//! ends by handing back an open descriptor, and every check is taken either on
//! an open descriptor or on the anchored directory descriptor the next step
//! opens from. No function in this crate passes a caller-derived path to a
//! path-taking syscall, because such a syscall re-resolves the whole path from
//! the process root and reintroduces every race the anchoring exists to remove.

use std::path::Path;

use rustix::fd::{AsFd, BorrowedFd, OwnedFd};
use rustix::fs::{AtFlags, Mode, OFlags};
use tunnel_fs_core::{
    CapabilitySet, Feature, FeatureSet, FsError, FsErrorCode, PathBounds, Primitive, VirtualPath,
};

use crate::identity::{FileIdentity, FileKind};
use crate::policy::{
    MAX_LINK_HOPS, check_exportable, check_hard_link_write, check_same_device, host_error,
    lost_race,
};

/// The test-only hook that occupies the window between inspecting a name and
/// opening it.
///
/// This module exists **only** under the `race-window-hook` feature, which no
/// shipped build enables: with the feature off there is no hook, no
/// thread-local and no call site.  It is here because the guards that survive a
/// component being swapped mid-walk — `O_NOFOLLOW` and the post-open identity
/// comparison — protect a window a few microseconds wide, and a test that
/// merely races threads cannot be relied on to land inside it.  Rather than
/// claim those guards are load-bearing without evidence, this lets a test step
/// into the window deliberately.
#[cfg(feature = "race-window-hook")]
pub mod race_window {
    use std::cell::Cell;

    thread_local! {
        static HOOK: Cell<Option<fn()>> = const { Cell::new(None) };
    }

    /// Run `hook` on this thread between each component's inspection and its
    /// open.
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

/// What a caller intends to do with the descriptor it is resolving.
///
/// The intent is applied **in** the resolving open, not by reopening the name
/// afterwards, so the descriptor a caller writes through is the one whose
/// identity, kind and link count were checked.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum Intent {
    /// Identity and metadata only.  Opened read-only.
    Inspect,
    /// Read content.
    Read,
    /// Change content.  Never carries `O_TRUNC`: truncation happens through
    /// the descriptor after the hard-link rule has been applied to it, so a
    /// refused write cannot have already discarded the file.
    Write,
    /// Read and change content through one descriptor.
    ///
    /// A separate intent rather than `Write` with a flag, because 9P's
    /// `O_RDWR` is one fid a client may both `Tread` and `Twrite`, and a
    /// descriptor opened `O_WRONLY` would answer `EBADF` to the first. It
    /// carries `O_TRUNC` no more than [`Intent::Write`] does, for the same
    /// reason.
    ReadWrite,
}

impl Intent {
    fn flags(self) -> OFlags {
        match self {
            Self::Inspect | Self::Read => OFlags::RDONLY,
            Self::Write => OFlags::WRONLY,
            Self::ReadWrite => OFlags::RDWR,
        }
    }
}

/// An open descriptor inside the export, with the identity it was verified at.
#[derive(Debug)]
pub struct Handle {
    descriptor: OwnedFd,
    identity: FileIdentity,
}

impl Handle {
    /// The descriptor.  Operate on this, never on the path it came from.
    #[must_use]
    pub fn as_fd(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// The identity the host reported for this descriptor.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// The node kind.
    #[must_use]
    pub const fn kind(&self) -> FileKind {
        self.identity.kind()
    }

    /// Re-read the identity **of this descriptor**.
    ///
    /// Not a re-resolution: it asks the host about the open file, not about
    /// the name it was reached by. A fid whose name was unlinked, renamed or
    /// replaced by a symbolic link still answers with the file it was
    /// resolved to, which is the observable form of "act on the descriptor you
    /// resolved".  The link count it returns is also the fresh one the
    /// hard-link rule needs before a later write.
    ///
    /// # Errors
    ///
    /// A translated host failure.
    pub fn current_identity(&self) -> Result<FileIdentity, FsError> {
        identity_of(&self.descriptor)
    }

    /// Adopt a descriptor an anchored `*at` syscall in this crate produced.
    ///
    /// The identity comes from `fstat` on that descriptor and from nowhere
    /// else, which is the same authority every other [`Handle`] in this crate
    /// carries: it describes the file the syscall reached, not the name it was
    /// asked about. Kept `pub(crate)` because the caller has to be a function
    /// that just performed such a syscall — adopting a descriptor from anywhere
    /// else would be a handle with no anchoring behind it.
    ///
    /// # Errors
    ///
    /// A translated host failure from the `fstat`.
    pub(crate) fn from_verified(descriptor: OwnedFd) -> Result<Self, FsError> {
        let identity = identity_of(&descriptor)?;
        Ok(Self {
            descriptor,
            identity,
        })
    }
}

/// One export: a retained root directory descriptor, its grant and its
/// features.
///
/// The root is opened once, at construction, from the operator-configured host
/// path. That host path is never stored and never used again: every later
/// resolution starts from this descriptor, so moving or replacing the root
/// directory afterwards cannot redirect the export.
#[derive(Debug)]
pub struct ExportRoot {
    root: OwnedFd,
    identity: FileIdentity,
    grant: CapabilitySet,
    features: FeatureSet,
    bounds: PathBounds,
    /// Whether the `openat2` path may be used at all.
    ///
    /// It needs `/proc/self/fd` to turn its `O_PATH` result into a usable
    /// descriptor, and a Linux host can be running without `/proc` mounted.
    /// Rather than let every read and write report `ENOENT` — file-absent —
    /// because a reopen could not find a procfs path, this is probed once at
    /// construction and the per-component walk is used when it is unavailable.
    /// That walk needs no procfs and is the same mechanism macOS uses, so the
    /// export stays confined either way.
    #[cfg(target_os = "linux")]
    anchored_open: bool,
}

impl ExportRoot {
    /// Open `host_root` as an export root.
    ///
    /// `host_root` is operator configuration, not consumer input, so it is the
    /// one path in this crate opened by name. Symbolic links in it are the
    /// operator's own; the export is whatever directory this open reached, and
    /// that descriptor is what confines every later resolution.
    ///
    /// # Errors
    ///
    /// A host failure translated into the closed vocabulary, or
    /// [`FsErrorCode::Enotdir`] if the root is not a directory.
    pub fn open(
        host_root: &Path,
        grant: CapabilitySet,
        features: FeatureSet,
        bounds: PathBounds,
    ) -> Result<Self, FsError> {
        let root = retry(|| {
            rustix::fs::open(
                host_root,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
                Mode::empty(),
            )
        })
        .map_err(host_error)?;
        let identity = identity_of(&root)?;
        if identity.kind() != FileKind::Directory {
            return Err(FsError::refused(FsErrorCode::Enotdir));
        }
        Ok(Self {
            root,
            identity,
            grant,
            features,
            bounds,
            #[cfg(target_os = "linux")]
            anchored_open: procfs_available(),
        })
    }

    /// The grant this export enforces.
    #[must_use]
    pub const fn grant(&self) -> CapabilitySet {
        self.grant
    }

    /// The features this export advertises.
    #[must_use]
    pub const fn features(&self) -> FeatureSet {
        self.features
    }

    /// The path bounds this export negotiated.
    #[must_use]
    pub const fn bounds(&self) -> PathBounds {
        self.bounds
    }

    /// The identity of the root directory.
    #[must_use]
    pub const fn identity(&self) -> FileIdentity {
        self.identity
    }

    /// Whether the grant and features permit `primitive`.
    ///
    /// This is the gate-1 decision, applied unchanged: it is the same
    /// [`Primitive::is_permitted`] table, so `Tlink` without the `hardLinks`
    /// feature and `Tsymlink`/`Treadlink` without `symlinks` are refused here
    /// before any host call.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`], which renders as `EPERM` with a
    /// not-started outcome.
    pub fn authorize(&self, primitive: Primitive) -> Result<(), FsError> {
        if primitive.is_permitted(self.grant, self.features) {
            Ok(())
        } else {
            Err(FsError::NotPermitted)
        }
    }

    /// Resolve `path` to an open descriptor.
    ///
    /// # Errors
    ///
    /// Any confinement refusal or translated host failure.
    pub fn resolve(&self, path: &VirtualPath, intent: Intent) -> Result<Handle, FsError> {
        self.walk(path, intent)
    }

    /// Resolve the parent directory of `path`.
    ///
    /// The caller operates on `path.file_name()` relative to the returned
    /// descriptor. This is how create, unlink, rename and link reach a name
    /// without ever handing a whole path to the host.
    ///
    /// # Errors
    ///
    /// [`FsErrorCode::Einval`] when `path` is the root, which has no parent
    /// inside the export; otherwise any confinement refusal or host failure.
    pub fn resolve_parent(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        let parent = path.parent().ok_or(FsError::refused(FsErrorCode::Einval))?;
        let handle = self.walk(&parent, Intent::Inspect)?;
        if handle.kind() == FileKind::Directory {
            Ok(handle)
        } else {
            Err(FsError::refused(FsErrorCode::Enotdir))
        }
    }

    /// Open a file for reading.
    ///
    /// The hard-link rule is deliberately **not** applied: reading a multiply
    /// linked inode discloses nothing the read grant does not already permit.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without the `read` capability,
    /// [`FsErrorCode::Eisdir`] for a directory, or any confinement refusal.
    pub fn open_read(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        self.authorize(Primitive::OpenRead)?;
        let handle = self.resolve(path, Intent::Read)?;
        if handle.kind() == FileKind::Directory {
            return Err(FsError::refused(FsErrorCode::Eisdir));
        }
        Ok(handle)
    }

    /// Open a directory for enumeration.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `list`, or
    /// [`FsErrorCode::Enotdir`] when the target is a file.
    pub fn open_directory(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        self.authorize(Primitive::OpenDir)?;
        let handle = self.resolve(path, Intent::Inspect)?;
        if handle.kind() == FileKind::Directory {
            Ok(handle)
        } else {
            Err(FsError::refused(FsErrorCode::Enotdir))
        }
    }

    /// Open a file for writing, applying the hard-link rule of the contract.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `write`; `EPERM` when `hardLinks` is
    /// not advertised and the resolved regular file has `st_nlink > 1`;
    /// [`FsErrorCode::Eisdir`] for a directory; or any confinement refusal.
    pub fn open_write(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        self.open_for_size_change_with(path, Primitive::OpenWrite, Intent::Write)
    }

    /// Open a file for reading **and** writing, applying the hard-link rule.
    ///
    /// The same decision as [`ExportRoot::open_write`] under the same
    /// primitive: the grant that permits writing is what `O_RDWR` needs beyond
    /// a read, and the read half adds no authority a `read` grant does not
    /// already carry — which the caller has checked, because `OpenRead` is one
    /// of the primitives an `O_RDWR` `Tlopen` decodes to.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::open_write`].
    pub fn open_read_write(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        self.open_for_size_change_with(path, Primitive::OpenWrite, Intent::ReadWrite)
    }

    /// Open a file for writing and truncate it to zero.
    ///
    /// The truncation is applied to the descriptor **after** the hard-link
    /// rule has refused or permitted it, so a refusal cannot follow a
    /// truncation that already happened. This is why [`Intent::Write`] never
    /// carries `O_TRUNC`.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::open_write`], under [`Primitive::OpenTruncate`].
    pub fn open_truncate(&self, path: &VirtualPath) -> Result<Handle, FsError> {
        let handle = self.open_for_size_change(path, Primitive::OpenTruncate)?;
        rustix::fs::ftruncate(handle.as_fd(), 0).map_err(host_error)?;
        Ok(handle)
    }

    /// Change a file's size, the `Tsetattr` case rule 4 covers.
    ///
    /// # Errors
    ///
    /// As [`ExportRoot::open_write`], under [`Primitive::SetattrSize`].
    pub fn set_size(&self, path: &VirtualPath, size: u64) -> Result<(), FsError> {
        let handle = self.open_for_size_change(path, Primitive::SetattrSize)?;
        rustix::fs::ftruncate(handle.as_fd(), size).map_err(host_error)
    }

    fn open_for_size_change(
        &self,
        path: &VirtualPath,
        primitive: Primitive,
    ) -> Result<Handle, FsError> {
        self.open_for_size_change_with(path, primitive, Intent::Write)
    }

    pub(crate) fn open_for_size_change_with(
        &self,
        path: &VirtualPath,
        primitive: Primitive,
        intent: Intent,
    ) -> Result<Handle, FsError> {
        self.authorize(primitive)?;
        let handle = self.resolve(path, intent)?;
        if handle.kind() == FileKind::Directory {
            return Err(FsError::refused(FsErrorCode::Eisdir));
        }
        check_hard_link_write(
            primitive,
            handle.identity(),
            self.features.has(Feature::HardLinks),
        )?;
        Ok(handle)
    }

    /// Rename inside this export.
    ///
    /// Both endpoints are resolved independently to anchored parent
    /// descriptors, so neither side can be steered outside the root by a
    /// symbolic link, and there is no spelling of a destination in another
    /// export: a [`VirtualPath`] cannot name one.
    ///
    /// # Errors
    ///
    /// [`FsError::NotPermitted`] without `write` **and** `delete` plus the
    /// `atomicRename` feature, [`FsErrorCode::Einval`] for a root endpoint, or
    /// any confinement refusal.
    pub fn rename(&self, from: &VirtualPath, to: &VirtualPath) -> Result<(), FsError> {
        self.authorize(Primitive::Rename)?;
        let from_name = from
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let to_name = to
            .file_name()
            .ok_or(FsError::refused(FsErrorCode::Einval))?;
        let from_parent = self.resolve_parent(from)?;
        let to_parent = self.resolve_parent(to)?;
        rustix::fs::renameat(from_parent.as_fd(), from_name, to_parent.as_fd(), to_name)
            .map_err(host_error)
    }

    /// Whether two virtual paths name one host file.
    ///
    /// This is the answer to every two-spellings-one-file class the contract
    /// tabulates — ASCII case, Unicode case pairs, NFC versus NFD — and it is
    /// obtained by resolving both and asking the host which inode each
    /// reached. No case fold, no normalisation and no string comparison takes
    /// part in it.
    ///
    /// # Errors
    ///
    /// Any confinement refusal or host failure from either resolution;
    /// notably [`FsErrorCode::Enoent`] when one spelling does not exist, which
    /// is itself the host's answer that they are not one file.
    pub fn same_file(&self, left: &VirtualPath, right: &VirtualPath) -> Result<bool, FsError> {
        let left = self.resolve(left, Intent::Inspect)?;
        let right = self.resolve(right, Intent::Inspect)?;
        Ok(left.identity().is_same_file(right.identity()))
    }

    /// Resolve using `openat2` where the host has it, and the per-component
    /// walk everywhere else.
    #[cfg(target_os = "linux")]
    fn walk(&self, path: &VirtualPath, intent: Intent) -> Result<Handle, FsError> {
        if !self.anchored_open {
            return self.walk_components(path, intent);
        }
        match self.walk_openat2(path, intent) {
            // `openat2` arrived in Linux 5.6, and a seccomp filter can refuse
            // it on a kernel that has it. Both are the contract's named
            // fallback case, not a failure of the request, and the fallback is
            // not a weaker mechanism: it is the same per-component walk macOS
            // and the BSDs use as their only mechanism, with the same
            // anchoring, the same re-rooting and the same guards. What the
            // fallback loses is the kernel taking the decisions in one
            // syscall, not any part of the confinement.
            Err(errno) if errno == rustix::io::Errno::NOSYS || errno == rustix::io::Errno::PERM => {
                self.walk_components(path, intent)
            }
            // `RESOLVE_IN_ROOT` answers `EAGAIN` when a rename or a mount moved
            // part of the path while the kernel was walking it. That is the
            // race, not a malformed request, so it takes the same uniform
            // answer as a component that changed under the per-component walk
            // rather than falling through to `EINVAL`.
            Err(errno) if errno == rustix::io::Errno::AGAIN => Err(lost_race()),
            Err(errno) => Err(host_error(errno)),
            Ok(handle) => handle,
        }
    }

    #[cfg(not(target_os = "linux"))]
    fn walk(&self, path: &VirtualPath, intent: Intent) -> Result<Handle, FsError> {
        self.walk_components(path, intent)
    }

    /// The Linux anchoring primitive the contract names.
    ///
    /// The `resolve` flag follows the `symlinks` feature and the two are
    /// mutually exclusive: `RESOLVE_NO_SYMLINKS` with the feature off, so a
    /// link met during the walk fails with `ELOOP` rather than being followed,
    /// and `RESOLVE_IN_ROOT` with it on, so an absolute link target is
    /// re-rooted at the export root. `RESOLVE_BENEATH` is **not** used: it
    /// answers `EXDEV` to an absolute link target instead of re-rooting it, so
    /// it cannot satisfy the re-rooting rule.
    ///
    /// The outer `Result` is the host errno, so the caller can recognise the
    /// fallback cases before they are flattened into the closed vocabulary.
    ///
    /// **Not exercised by this crate's tests.** The only host available is
    /// macOS; this path compiles but has not been run.
    #[cfg(target_os = "linux")]
    fn walk_openat2(
        &self,
        path: &VirtualPath,
        intent: Intent,
    ) -> Result<Result<Handle, FsError>, rustix::io::Errno> {
        use rustix::fs::ResolveFlags;

        // `NO_XDEV` is what makes the mount-point refusal a property of the
        // whole walk rather than of its last component: without it, a bind
        // mount of an outside directory underneath a mount inside the root
        // would be refused by the per-component walk and handed back here,
        // because comparing the final `st_dev` with the root's cannot see a
        // boundary that was crossed and then crossed back. `NO_MAGICLINKS`
        // refuses the `/proc` links that are re-openings of an existing
        // descriptor rather than names, which `RESOLVE_IN_ROOT` would
        // otherwise follow.
        let boundaries = ResolveFlags::NO_XDEV | ResolveFlags::NO_MAGICLINKS;
        let resolve = boundaries
            | if self.features.has(Feature::Symlinks) {
                ResolveFlags::IN_ROOT
            } else {
                ResolveFlags::NO_SYMLINKS
            };
        let relative = relative_spelling(path);
        // `O_PATH` first: it opens no device, blocks on no FIFO and starts no
        // driver, so the node kind is decided before anything is really
        // opened.
        let located = rustix::fs::openat2(
            &self.root,
            relative.as_str(),
            OFlags::PATH | OFlags::CLOEXEC,
            Mode::empty(),
            resolve,
        )?;
        Ok(self.finish_linux(located, intent))
    }

    #[cfg(target_os = "linux")]
    fn finish_linux(&self, located: OwnedFd, intent: Intent) -> Result<Handle, FsError> {
        use std::os::fd::AsRawFd;

        let identity = identity_of(&located)?;
        check_exportable(identity.kind())?;
        check_same_device(self.identity, identity)?;
        // Upgrade the `O_PATH` descriptor to a usable one, for a directory as
        // well as a file: an `O_PATH` directory descriptor answers `EBADF` to
        // `getdents`, so returning one would leave `open_directory` unable to
        // do the one thing it exists for. This reopens the **descriptor**,
        // through the kernel's own name for it, not the caller's path, so no
        // component is re-resolved; the identity check below is what makes
        // that claim testable rather than assumed.
        let flags = if identity.kind() == FileKind::Directory {
            OFlags::RDONLY | OFlags::DIRECTORY
        } else {
            intent.flags() | OFlags::NONBLOCK
        };
        let procfs = format!("/proc/self/fd/{}", located.as_raw_fd());
        let opened =
            retry(|| rustix::fs::open(procfs.as_str(), flags | OFlags::CLOEXEC, Mode::empty()))
                .map_err(host_error)?;
        let reopened = identity_of(&opened)?;
        if !reopened.is_same_file(identity) {
            return Err(lost_race());
        }
        Ok(Handle {
            descriptor: opened,
            identity: reopened,
        })
    }

    /// Per-component anchored traversal.
    ///
    /// This is the macOS and BSD mechanism the contract names, and the Linux
    /// fallback for a kernel without `openat2`. Each step opens one component
    /// from the descriptor of its parent with `O_NOFOLLOW`; symbolic links are
    /// re-rooted by this code rather than by the kernel, bounded at
    /// [`MAX_LINK_HOPS`] so a cycle is refused by count rather than by
    /// hanging.
    fn walk_components(&self, path: &VirtualPath, intent: Intent) -> Result<Handle, FsError> {
        // The ancestor stack, root first. `..` in a link target pops it and
        // never below the root, which is what re-rooting means here: no `..`
        // can reach above the export because there is nothing above it to
        // reach.
        let mut ancestors: Vec<OwnedFd> = Vec::with_capacity(path.component_count() + 1);
        ancestors.push(self.root.try_clone().map_err(io_error)?);

        // Remaining components, innermost last, so a step is a `pop`.
        let mut pending: Vec<String> = path.components().map(str::to_owned).collect();
        pending.reverse();

        let mut hops: u32 = 0;
        let mut steps: usize = 0;
        // Set when a symbolic link's target ends in `/`. POSIX requires such a
        // target to name a directory, and dropping the separator would let
        // `link -> file/` resolve to a regular file where the host itself
        // answers `ENOTDIR`.
        let mut require_directory = false;
        let step_budget = self
            .bounds
            .max_components()
            .saturating_mul(MAX_LINK_HOPS as usize + 1);

        while let Some(name) = pending.pop() {
            steps += 1;
            if steps > step_budget {
                return Err(FsError::refused(FsErrorCode::Eloop));
            }

            // `.` and `..` cannot occur in a `VirtualPath` — gate 1 refuses
            // both — so these two arms exist only for a host link target,
            // which this code, not the caller, is interpreting.
            if name == "." {
                continue;
            }
            if name == ".." {
                if ancestors.len() > 1 {
                    ancestors.pop();
                }
                continue;
            }

            let parent = ancestors.last().expect("the root is never popped");
            // Look before opening: a FIFO opened for reading blocks, and a
            // device node opened at all can have a side effect. The open
            // below is still what decides, and the identity comparison after
            // it is what makes this look safe rather than authoritative.
            let seen =
                retry(|| rustix::fs::statat(parent, name.as_str(), AtFlags::SYMLINK_NOFOLLOW))
                    .map_err(host_error)?;
            let seen = FileIdentity::from_stat(&seen);
            // The TOCTOU window itself, held open on demand.  Compiled out
            // entirely unless the `race-window-hook` feature is on, which only
            // this crate's own race tests turn on: they need to occupy the
            // instant between the name being inspected and the descriptor
            // being opened, and a nanosecond-wide window cannot be hit
            // reliably by racing threads alone.
            #[cfg(feature = "race-window-hook")]
            race_window::fire();
            let last = pending.is_empty();

            match seen.kind() {
                FileKind::Symlink => {
                    if !self.features.has(Feature::Symlinks) {
                        // Rule 3: with the feature off a link met during
                        // traversal fails the walk rather than being followed.
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
                    hops += 1;
                    if hops > MAX_LINK_HOPS {
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
                    let target =
                        retry(|| rustix::fs::readlinkat(parent, name.as_str(), Vec::new()))
                            .map_err(host_error)?;
                    let target = target
                        .to_str()
                        .map_err(|_| FsError::refused(FsErrorCode::Einval))?
                        .to_owned();
                    if target.is_empty() {
                        return Err(FsError::refused(FsErrorCode::Enoent));
                    }
                    if last && target.ends_with('/') {
                        require_directory = true;
                    }
                    if target.starts_with('/') {
                        // An absolute target is resolved against the exported
                        // virtual root, never the host root.
                        ancestors.truncate(1);
                    }
                    let parts: Vec<&str> =
                        target.split('/').filter(|part| !part.is_empty()).collect();
                    if parts.len() > self.bounds.max_components() {
                        return Err(FsError::refused(FsErrorCode::Enametoolong));
                    }
                    for part in parts.into_iter().rev() {
                        pending.push(part.to_owned());
                    }
                }
                FileKind::Directory => {
                    // Before the open, for the same reason as in the other
                    // arm: a mount point crossed even momentarily is a
                    // directory on another filesystem, whose own driver would
                    // see the open.
                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                            Mode::empty(),
                        )
                    })
                    .map_err(component_open_error)?;
                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    check_same_device(self.identity, identity)?;
                    if last {
                        return Ok(Handle {
                            descriptor: opened,
                            identity,
                        });
                    }
                    if ancestors.len() > self.bounds.max_components() {
                        return Err(FsError::refused(FsErrorCode::Enametoolong));
                    }
                    ancestors.push(opened);
                }
                kind => {
                    if !last || require_directory {
                        return Err(FsError::refused(FsErrorCode::Enotdir));
                    }
                    // Refuse a FIFO, a socket or a device node without opening
                    // it at all.
                    check_exportable(kind)?;
                    // Decide the device boundary before the open too, not only
                    // after it: opening a file on a FUSE or network filesystem
                    // runs that filesystem's own open handler, and an export
                    // must not reach into another device even for the instant
                    // it takes to refuse.
                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            intent.flags() | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,
                            Mode::empty(),
                        )
                    })
                    .map_err(component_open_error)?;
                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    // Decided again on the descriptor, which is the only
                    // authority: the check above was taken on a name.
                    check_exportable(identity.kind())?;
                    check_same_device(self.identity, identity)?;
                    return Ok(Handle {
                        descriptor: opened,
                        identity,
                    });
                }
            }
        }

        // Every component was consumed by a `.` or `..` in a link target, or
        // the path was the root: the answer is the deepest directory reached.
        let descriptor = ancestors.pop().expect("the root is never popped");
        let identity = identity_of(&descriptor)?;
        Ok(Handle {
            descriptor,
            identity,
        })
    }
}

fn identity_of<Fd: AsFd>(descriptor: Fd) -> Result<FileIdentity, FsError> {
    let stat = retry(|| rustix::fs::fstat(&descriptor)).map_err(host_error)?;
    Ok(FileIdentity::from_stat(&stat))
}

/// Repeat a host call that a signal interrupted.
///
/// `EINTR` is not a filesystem answer, and the closed vocabulary has no code
/// for it: mapping it to `EINVAL` would report a delivered signal as a
/// malformed request. Every host call in this crate is short and restartable,
/// so the only correct response is to make it again.
pub(crate) fn retry<T>(mut call: impl FnMut() -> rustix::io::Result<T>) -> rustix::io::Result<T> {
    loop {
        match call() {
            Err(errno) if errno == rustix::io::Errno::INTR => {}
            outcome => return outcome,
        }
    }
}

/// A component open that failed, with the two errnos that can only mean "the
/// name changed under us" folded into the uniform race answer.
///
/// The open is reached only after `statat` said the entry was a directory (with
/// `O_DIRECTORY | O_NOFOLLOW`) or an exportable non-directory (with
/// `O_NOFOLLOW`). `ELOOP` therefore means a symbolic link appeared where one had
/// not been, and `ENOTDIR` that a directory stopped being one — both are the
/// race, not a property of what the caller asked for. Folding them keeps the
/// contract's claim that a component changing under the resolver answers
/// `ENOENT` true for every component kind, rather than leaking which kind of
/// swap a concurrent writer performed.
fn component_open_error(errno: rustix::io::Errno) -> FsError {
    if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::NOTDIR {
        lost_race()
    } else {
        host_error(errno)
    }
}

fn io_error(_: std::io::Error) -> FsError {
    // Deliberately field-free: a `std::io::Error` can carry an OS message, and
    // that message is a host detail.
    FsError::refused(FsErrorCode::Einval)
}

/// Whether `/proc/self/fd` can be opened, which the `openat2` path needs to
/// upgrade its `O_PATH` result.
#[cfg(target_os = "linux")]
fn procfs_available() -> bool {
    retry(|| {
        rustix::fs::open(
            "/proc/self/fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
    })
    .is_ok()
}

/// The export-relative spelling of a virtual path, for `openat2`.
///
/// The leading `/` is removed so the path is resolved against the root
/// descriptor rather than the host root; the export root itself is `.`.
#[cfg(target_os = "linux")]
fn relative_spelling(path: &VirtualPath) -> String {
    let text = path.as_str();
    let trimmed = text.strip_prefix('/').unwrap_or(text);
    if trimmed.is_empty() {
        ".".to_owned()
    } else {
        trimmed.to_owned()
    }
}
