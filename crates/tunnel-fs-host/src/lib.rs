#![forbid(unsafe_code)]
//! The OS-confined filesystem resolver defined by `docs/filesystem-api.md`.
//!
//! This crate implements **implementation gate 2 only**: anchored traversal
//! that cannot leave an exported root, the symbolic-link policy, the hard-link
//! write rule, file identity, the mount-point boundary and the special-file
//! refusal.  It builds on [`tunnel_fs_core`] and widens nothing there: a
//! [`tunnel_fs_core::VirtualPath`] still means "this text cannot itself express
//! an escape", and this crate is what turns that into "this descriptor is
//! inside the export".
//!
//! # The one rule
//!
//! Act on the descriptor you resolved, never on the path you resolved it from.
//! No function here passes caller-derived text to a path-taking syscall.  The
//! sole path opened by name is the operator-configured export root, once, at
//! construction.
//!
//! # Hosts
//!
//! | Host | Mechanism | Exercised |
//! | --- | --- | --- |
//! | macOS and other BSDs | Per-component `openat` with `O_NOFOLLOW`, links re-rooted by this crate, bounded at [`policy::MAX_LINK_HOPS`] | Yes — every test in this crate runs here |
//! | Linux | `openat2` with `RESOLVE_NO_SYMLINKS` or `RESOLVE_IN_ROOT`, falling back to the same per-component walk on a kernel without it | **Compiled, not run.** No Linux host was available |
//! | Windows | **Filesystem exports are unsupported.** See below |
//!
//! ## Windows
//!
//! The contract requires either the `NtCreateFile` anchoring it names or an
//! explicit statement that filesystem exports are unsupported on Windows.  This
//! implementation takes the second option, deliberately and in one place:
//! [`ExportRoot::open`] does not exist on a non-Unix host, and
//! [`unsupported_host_reason`] states why.  A Windows device may still be
//! enrolled and may still export other services; it cannot export a filesystem.
//!
//! The reason is that the anchoring primitive is only half of what Windows
//! needs.  `NtCreateFile` with a `RootDirectory` handle and
//! `FILE_OPEN_REPARSE_POINT` would anchor traversal, but the namespace rules
//! this contract is built on — a byte-exact name, one spelling per file, a
//! link count that means what POSIX means by it — do not hold there: 8.3 short
//! names alias every long name on a volume with generation enabled, and the
//! two-spellings-one-file classes would have to be decided against a different
//! identity primitive.  Declaring it unsupported is honest; a half-anchored
//! Windows provider would not be.
//!
//! # Payload-free
//!
//! Every error this crate produces is a field-free [`tunnel_fs_core::FsError`].
//! A host errno is translated by meaning, not passed through, and a
//! [`identity::FileIdentity`] has a redacting `Debug` and no accessor for the
//! device or inode number it holds, so a resolved handle cannot put a host
//! detail into a log line.

pub mod identity;
pub mod policy;

#[cfg(unix)]
pub mod resolver;

pub use identity::{FileIdentity, FileKind};
pub use policy::{MAX_LINK_HOPS, code_from_errno};

#[cfg(unix)]
pub use resolver::{ExportRoot, Handle, Intent};

/// Why this host cannot serve a filesystem export, or `None` when it can.
///
/// A caller — discovery, in gate 4 — uses this to answer `403` for a
/// filesystem export on a host where the confinement model does not hold,
/// rather than admitting a session that would have to guess.
#[must_use]
pub const fn unsupported_host_reason() -> Option<&'static str> {
    #[cfg(unix)]
    {
        None
    }
    #[cfg(not(unix))]
    {
        Some("filesystem exports are unsupported on this host")
    }
}
