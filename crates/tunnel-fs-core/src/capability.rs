//! Capabilities, enforceable primitives and derived client operations.
//!
//! `docs/filesystem-api.md` is emphatic that the server sees 9P primitives and
//! their flags, never a trusted `copy` or `readFile` label.  This module keeps
//! that separation in the type system:
//!
//! * [`Capability`] is the grant vocabulary an operator configures: exactly
//!   read, write, list and delete.
//! * [`Primitive`] is what the provider enforces on each dispatch.
//! * [`ClientOperation`] is the advertised descriptor label, and it is
//!   *derived* — [`ClientOperation::is_available`] recomputes it from the
//!   primitives the grant permits and the features the provider implements.
//!   There is no way to advertise an operation that the primitive checks would
//!   then refuse, and no way to grant a label without its primitives.
//!
//! Default is deny.  [`CapabilitySet::DENY`] is [`Default`], there is no
//! `ALL` constant and no wildcard, so every capability a session holds was
//! named individually by an operator.

use core::fmt;

/// The four grantable capabilities.
///
/// Deliberately closed.  Adding a fifth is a contract change, not a
/// configuration change.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Capability {
    /// Read file content and link targets.
    Read,
    /// Create, modify, truncate and set metadata.
    Write,
    /// Traverse for metadata and enumerate directories.
    List,
    /// Remove a name from a directory.
    Delete,
}

impl Capability {
    /// The stable configuration and diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Read => "read",
            Self::Write => "write",
            Self::List => "list",
            Self::Delete => "delete",
        }
    }

    /// Every capability, in a fixed order.
    ///
    /// This is an enumeration for exhaustive tests and configuration parsing.
    /// It is **not** a grant: building a [`CapabilitySet`] from it still names
    /// each capability explicitly.
    pub const ALL: [Self; 4] = [Self::Read, Self::Write, Self::List, Self::Delete];

    /// Parse the exact configuration spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    /// The bit this capability occupies in a [`CapabilitySet`].
    const fn bit(self) -> u8 {
        match self {
            Self::Read => 0b0001,
            Self::Write => 0b0010,
            Self::List => 0b0100,
            Self::Delete => 0b1000,
        }
    }
}

impl fmt::Display for Capability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A set of granted capabilities.
///
/// `Default` is [`CapabilitySet::DENY`].  There is no constructor that grants
/// everything, so a configuration bug cannot widen a grant by omission.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct CapabilitySet(u8);

impl CapabilitySet {
    /// The empty grant.  A session offered this is refused at attach.
    pub const DENY: Self = Self(0);

    /// Build a set from an explicit list.
    #[must_use]
    pub fn from_slice(capabilities: &[Capability]) -> Self {
        let mut bits = 0u8;
        for capability in capabilities {
            bits |= capability.bit();
        }
        Self(bits)
    }

    /// Add one capability.
    #[must_use]
    pub const fn with(self, capability: Capability) -> Self {
        Self(self.0 | capability.bit())
    }

    /// Remove one capability.
    #[must_use]
    pub const fn without(self, capability: Capability) -> Self {
        Self(self.0 & !capability.bit())
    }

    /// Whether this set grants `capability`.
    #[must_use]
    pub const fn allows(self, capability: Capability) -> bool {
        self.0 & capability.bit() != 0
    }

    /// Whether this set grants every capability in `required`.
    #[must_use]
    pub const fn allows_all(self, required: Self) -> bool {
        self.0 & required.0 == required.0
    }

    /// Whether nothing is granted.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// How many capabilities are granted.
    #[must_use]
    pub const fn len(self) -> u32 {
        self.0.count_ones()
    }

    /// Whether any mutating capability is granted.
    ///
    /// This is the source of the descriptor's `root.readOnly`, so the
    /// advertised flag cannot disagree with the enforced grant.
    #[must_use]
    pub const fn is_read_only(self) -> bool {
        !self.allows(Capability::Write) && !self.allows(Capability::Delete)
    }

    /// The granted capabilities, in [`Capability::ALL`] order.
    pub fn iter(self) -> impl Iterator<Item = Capability> {
        Capability::ALL
            .into_iter()
            .filter(move |capability| self.allows(*capability))
    }
}

/// An optional provider feature a derived operation may additionally require.
///
/// These correspond one for one to boolean fields of the descriptor's
/// `features` object.  Every one defaults to absent.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Feature {
    /// Rename is a single native in-filesystem operation.
    AtomicRename,
    /// Append positioning is atomic per write.
    NativeAppend,
    /// Exclusive create is a real primitive, not an exists-then-create race.
    ExclusiveCreate,
    /// Symbolic links may be created, read and resolved.
    Symlinks,
    /// Hard links may be created.
    HardLinks,
    /// Birth time is observable.
    BirthTime,
    /// Durable writes are available and tested.
    Fsync,
}

impl Feature {
    /// The descriptor's field spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AtomicRename => "atomicRename",
            Self::NativeAppend => "nativeAppend",
            Self::ExclusiveCreate => "exclusiveCreate",
            Self::Symlinks => "symlinks",
            Self::HardLinks => "hardLinks",
            Self::BirthTime => "birthTime",
            Self::Fsync => "fsync",
        }
    }

    /// Every feature that can gate an operation.
    pub const ALL: [Self; 7] = [
        Self::AtomicRename,
        Self::NativeAppend,
        Self::ExclusiveCreate,
        Self::Symlinks,
        Self::HardLinks,
        Self::BirthTime,
        Self::Fsync,
    ];
}

impl fmt::Display for Feature {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A set of implemented provider features.  `Default` implements none.
#[derive(Clone, Copy, Debug, Default, Eq, Hash, PartialEq)]
pub struct FeatureSet(u8);

impl FeatureSet {
    /// No optional feature is implemented.
    pub const NONE: Self = Self(0);

    /// Build a set from an explicit list.
    #[must_use]
    pub fn from_slice(features: &[Feature]) -> Self {
        let mut bits = 0u8;
        for feature in features {
            bits |= 1u8 << (*feature as u8);
        }
        Self(bits)
    }

    /// Add one feature.
    #[must_use]
    pub const fn with(self, feature: Feature) -> Self {
        Self(self.0 | (1u8 << (feature as u8)))
    }

    /// Remove one feature.
    #[must_use]
    pub const fn without(self, feature: Feature) -> Self {
        Self(self.0 & !(1u8 << (feature as u8)))
    }

    /// Whether `feature` is implemented.
    #[must_use]
    pub const fn has(self, feature: Feature) -> bool {
        self.0 & (1u8 << (feature as u8)) != 0
    }
}

/// A 9P2000.L primitive family, at the granularity the provider authorises.
///
/// Flag-bearing opcodes are split into separate variants — `OpenRead`,
/// `OpenWrite`, `OpenTruncate` — because the contract requires `.L` flags to be
/// decoded and checked explicitly rather than after the fact.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum Primitive {
    /// `Tversion`: dialect and `msize` negotiation.
    Version,
    /// `Tattach`: bind the session to its fixed export root.
    Attach,
    /// `Tflush`: cancellation, never rollback.
    Flush,
    /// `Tclunk`: release a fid.  Cleanup cannot broaden authority.
    Clunk,
    /// `Twalk`: confined traversal.
    Walk,
    /// `Tgetattr`: metadata disclosure.
    Getattr,
    /// `Treaddir`: directory enumeration.
    Readdir,
    /// `Treadlink`: read a symbolic link target.
    Readlink,
    /// `Tlopen` without any write flag.
    OpenRead,
    /// `Tlopen` on a directory, in preparation for `Treaddir`.
    ///
    /// Split from [`Primitive::OpenRead`] so that enumerating a directory needs
    /// `list` rather than `read`: a grant that may enumerate names must not
    /// thereby be able to read file content.
    OpenDir,
    /// `Tlopen` with a write or append flag.
    OpenWrite,
    /// `Tlopen` or `Tlcreate` with `O_TRUNC`.
    OpenTruncate,
    /// `Tlcreate`: create a new regular file.
    Create,
    /// `Tread`.
    Read,
    /// `Twrite`.
    Write,
    /// `Tmkdir`.
    Mkdir,
    /// `Tunlinkat` or `Tremove` on a non-directory.
    Unlink,
    /// `Tunlinkat` with `AT_REMOVEDIR`, or `Tremove` on a directory.
    RemoveDir,
    /// `Trenameat` or `Trename`, both endpoints inside one export.
    Rename,
    /// `Tsetattr` changing size.
    SetattrSize,
    /// `Tsetattr` changing mode.
    SetattrMode,
    /// `Tsetattr` changing access or modification times.
    SetattrTimes,
    /// `Tsymlink`.
    Symlink,
    /// `Tlink`.
    Link,
}

impl Primitive {
    /// Every primitive this profile defines.  Anything not listed is denied.
    pub const ALL: [Self; 24] = [
        Self::Version,
        Self::Attach,
        Self::Flush,
        Self::Clunk,
        Self::Walk,
        Self::Getattr,
        Self::Readdir,
        Self::Readlink,
        Self::OpenRead,
        Self::OpenDir,
        Self::OpenWrite,
        Self::OpenTruncate,
        Self::Create,
        Self::Read,
        Self::Write,
        Self::Mkdir,
        Self::Unlink,
        Self::RemoveDir,
        Self::Rename,
        Self::SetattrSize,
        Self::SetattrMode,
        Self::SetattrTimes,
        Self::Symlink,
        Self::Link,
    ];

    /// The diagnostic spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Version => "Tversion",
            Self::Attach => "Tattach",
            Self::Flush => "Tflush",
            Self::Clunk => "Tclunk",
            Self::Walk => "Twalk",
            Self::Getattr => "Tgetattr",
            Self::Readdir => "Treaddir",
            Self::Readlink => "Treadlink",
            Self::OpenRead => "Tlopen:read",
            Self::OpenDir => "Tlopen:dir",
            Self::OpenWrite => "Tlopen:write",
            Self::OpenTruncate => "Tlopen:trunc",
            Self::Create => "Tlcreate",
            Self::Read => "Tread",
            Self::Write => "Twrite",
            Self::Mkdir => "Tmkdir",
            Self::Unlink => "Tunlinkat",
            Self::RemoveDir => "Tunlinkat:dir",
            Self::Rename => "Trenameat",
            Self::SetattrSize => "Tsetattr:size",
            Self::SetattrMode => "Tsetattr:mode",
            Self::SetattrTimes => "Tsetattr:times",
            Self::Symlink => "Tsymlink",
            Self::Link => "Tlink",
        }
    }

    /// Whether this primitive is session lifecycle rather than filesystem work.
    ///
    /// Lifecycle primitives require no capability, but they are reachable only
    /// inside a session, and a session is admitted only for a non-empty grant.
    #[must_use]
    pub const fn is_session_lifecycle(self) -> bool {
        matches!(
            self,
            Self::Version | Self::Attach | Self::Flush | Self::Clunk
        )
    }

    /// Whether performing this primitive can change the host.
    ///
    /// This is what decides whether a refusal needs an [`crate::Outcome`] at
    /// all, and it is deliberately narrower than "needs `write` or `delete`".
    /// [`Primitive::OpenWrite`] is **not** here: opening a file for writing
    /// changes nothing, so a failure after it is still `not_started`, where a
    /// failure after [`Primitive::OpenTruncate`] is not — the truncation has
    /// already discarded the content. That difference is the reason the two are
    /// separate primitives rather than one with a flag.
    ///
    /// `Tread`, `Treaddir`, `Tgetattr`, `Treadlink` and the session lifecycle
    /// primitives are all observation and are all absent.
    #[must_use]
    pub const fn is_mutating(self) -> bool {
        matches!(
            self,
            Self::OpenTruncate
                | Self::Create
                | Self::Write
                | Self::Mkdir
                | Self::Unlink
                | Self::RemoveDir
                | Self::Rename
                | Self::SetattrSize
                | Self::SetattrMode
                | Self::SetattrTimes
                | Self::Symlink
                | Self::Link
        )
    }

    /// Every capability this primitive requires, as a conjunction.
    ///
    /// `Rename` requires both `Write` and `Delete`: it creates a name at the
    /// destination and removes one at the source, and a grant that may create
    /// but not remove must not be able to remove a name by renaming it away.
    ///
    /// `Walk` requires **no** capability, which is a recorded decision rather
    /// than an oversight, and it has a disclosure cost.  Requiring `List` to
    /// walk would make a read-by-name grant — `read` without `list`, the shape
    /// a caller wants when it knows its paths and must not enumerate — unable
    /// to reach any file at all, since every open begins with a walk.  The cost
    /// is that `Rwalk` returns qids, so a grant holding only `write` or only
    /// `delete` can probe whether a name exists and whether it is a file or a
    /// directory.  Those qids are the **only** metadata such a grant may
    /// observe: `Tgetattr` and `Treaddir` both require `List`, so size, times,
    /// mode, link count and directory contents stay unreachable.
    #[must_use]
    pub fn required_capabilities(self) -> CapabilitySet {
        use Capability::{Delete, List, Read, Write};
        match self {
            Self::Version | Self::Attach | Self::Flush | Self::Clunk | Self::Walk => {
                CapabilitySet::DENY
            }
            Self::Getattr | Self::Readdir | Self::OpenDir => CapabilitySet::DENY.with(List),
            Self::Readlink | Self::OpenRead | Self::Read => CapabilitySet::DENY.with(Read),
            Self::OpenWrite
            | Self::OpenTruncate
            | Self::Create
            | Self::Write
            | Self::Mkdir
            | Self::SetattrSize
            | Self::SetattrMode
            | Self::SetattrTimes
            | Self::Symlink
            | Self::Link => CapabilitySet::DENY.with(Write),
            Self::Unlink | Self::RemoveDir => CapabilitySet::DENY.with(Delete),
            Self::Rename => CapabilitySet::DENY.with(Write).with(Delete),
        }
    }

    /// The provider feature this primitive additionally requires, if any.
    #[must_use]
    pub const fn required_feature(self) -> Option<Feature> {
        match self {
            Self::Symlink | Self::Readlink => Some(Feature::Symlinks),
            Self::Link => Some(Feature::HardLinks),
            Self::Rename => Some(Feature::AtomicRename),
            _ => None,
        }
    }

    /// Whether `grant` and `features` permit this primitive.
    ///
    /// The empty grant permits nothing at all, including lifecycle primitives:
    /// a session is never admitted for it.
    #[must_use]
    pub fn is_permitted(self, grant: CapabilitySet, features: FeatureSet) -> bool {
        if grant.is_empty() {
            return false;
        }
        if let Some(feature) = self.required_feature()
            && !features.has(feature)
        {
            return false;
        }
        grant.allows_all(self.required_capabilities())
    }
}

impl fmt::Display for Primitive {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A derived client operation, as advertised in the descriptor's `operations`.
///
/// These are labels for the shared client and the framework adapters.  They are
/// never enforced directly; [`ClientOperation::primitives`] is the definition,
/// and availability is recomputed from it.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum ClientOperation {
    /// Whole-file read into a bounded buffer.
    ReadFile,
    /// Streamed read.
    ReadStream,
    /// Create or truncate and write.
    WriteFile,
    /// Streamed create or truncate and write.
    WriteStream,
    /// Append to an existing file.
    AppendFile,
    /// Metadata for one path.
    Stat,
    /// Enumerate immediate children.
    ReadDirectory,
    /// Create a directory.
    Mkdir,
    /// Remove a file or directory.
    Remove,
    /// Bounded composed read and write inside one export.
    Copy,
    /// Native in-export rename.
    Rename,
    /// Change mode bits.
    Chmod,
    /// Change access and modification times.
    Utimes,
    /// Create a symbolic link.
    Symlink,
    /// Create a hard link.
    Link,
    /// Read a symbolic link target.
    Readlink,
    /// Resolve a path inside the export.
    Realpath,
}

impl ClientOperation {
    /// Every operation name the descriptor schema allows, in schema order.
    pub const ALL: [Self; 17] = [
        Self::ReadFile,
        Self::ReadStream,
        Self::WriteFile,
        Self::WriteStream,
        Self::AppendFile,
        Self::Stat,
        Self::ReadDirectory,
        Self::Mkdir,
        Self::Remove,
        Self::Copy,
        Self::Rename,
        Self::Chmod,
        Self::Utimes,
        Self::Symlink,
        Self::Link,
        Self::Readlink,
        Self::Realpath,
    ];

    /// The descriptor's exact `operations` spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadFile => "readFile",
            Self::ReadStream => "readStream",
            Self::WriteFile => "writeFile",
            Self::WriteStream => "writeStream",
            Self::AppendFile => "appendFile",
            Self::Stat => "stat",
            Self::ReadDirectory => "readDirectory",
            Self::Mkdir => "mkdir",
            Self::Remove => "remove",
            Self::Copy => "copy",
            Self::Rename => "rename",
            Self::Chmod => "chmod",
            Self::Utimes => "utimes",
            Self::Symlink => "symlink",
            Self::Link => "link",
            Self::Readlink => "readlink",
            Self::Realpath => "realpath",
        }
    }

    /// Parse the exact descriptor spelling; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|value| value.as_str() == text)
    }

    /// The primitives this operation is composed of.
    ///
    /// Every one must be permitted for the operation to be advertised.  This is
    /// the contract's rule that a grant allowing `copy` necessarily permits its
    /// underlying read, create and write actions, and that no copy-only,
    /// grep-only or framework-only access can be promised.
    #[must_use]
    pub const fn primitives(self) -> &'static [Primitive] {
        use Primitive as P;
        match self {
            Self::ReadFile | Self::ReadStream => &[P::Walk, P::OpenRead, P::Read, P::Clunk],
            Self::WriteFile | Self::WriteStream => &[
                P::Walk,
                P::Create,
                P::OpenWrite,
                P::OpenTruncate,
                P::Write,
                P::Clunk,
            ],
            Self::AppendFile => &[P::Walk, P::OpenWrite, P::Write, P::Clunk],
            Self::Stat => &[P::Walk, P::Getattr, P::Clunk],
            Self::ReadDirectory => &[P::Walk, P::OpenDir, P::Readdir, P::Clunk],
            Self::Mkdir => &[P::Walk, P::Mkdir, P::Clunk],
            // `remove` and `copy` are recursive in the shared-client contract,
            // so both traverse directories and both need `list` as well.  An
            // earlier composition omitted the traversal primitives, which
            // advertised `remove` under `delete` alone and `copy` under
            // read+write with no `list` — operations the provider would then
            // have refused part-way through a directory.
            Self::Remove => &[
                P::Walk,
                P::OpenDir,
                P::Readdir,
                P::Unlink,
                P::RemoveDir,
                P::Clunk,
            ],
            Self::Copy => &[
                P::Walk,
                P::OpenDir,
                P::Readdir,
                P::OpenRead,
                P::Read,
                P::Mkdir,
                P::Create,
                P::OpenWrite,
                P::Write,
                P::Clunk,
            ],
            Self::Rename => &[P::Walk, P::Rename, P::Clunk],
            Self::Chmod => &[P::Walk, P::SetattrMode, P::Clunk],
            Self::Utimes => &[P::Walk, P::SetattrTimes, P::Clunk],
            Self::Symlink => &[P::Walk, P::Symlink, P::Clunk],
            Self::Link => &[P::Walk, P::Link, P::Clunk],
            Self::Readlink => &[P::Walk, P::Readlink, P::Clunk],
            Self::Realpath => &[P::Walk, P::Getattr, P::Clunk],
        }
    }

    /// The conjunction of every capability this operation's primitives need.
    #[must_use]
    pub fn required_capabilities(self) -> CapabilitySet {
        let mut required = CapabilitySet::DENY;
        for primitive in self.primitives() {
            for capability in primitive.required_capabilities().iter() {
                required = required.with(capability);
            }
        }
        required
    }

    /// Whether this operation may be advertised for `grant` and `features`.
    ///
    /// True only when **every** composing primitive is permitted.  There is no
    /// partial advertisement and no best-effort degradation.
    #[must_use]
    pub fn is_available(self, grant: CapabilitySet, features: FeatureSet) -> bool {
        self.primitives()
            .iter()
            .all(|primitive| primitive.is_permitted(grant, features))
    }

    /// Every operation that may be advertised, in schema order.
    #[must_use]
    pub fn derive_all(grant: CapabilitySet, features: FeatureSet) -> Vec<Self> {
        Self::ALL
            .into_iter()
            .filter(|operation| operation.is_available(grant, features))
            .collect()
    }
}

impl fmt::Display for ClientOperation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}
