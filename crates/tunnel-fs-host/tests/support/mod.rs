//! Fixtures for the gate-2 tests.
//!
//! Every test builds its own temporary tree, entirely with synthetic content,
//! and removes it again.  Nothing here reads, writes or links anything outside
//! the directory it created: the "outside the export" side of every escape test
//! is a sibling directory **inside** that same temporary tree, so an escape the
//! resolver failed to refuse would reach a file this test wrote, not a file of
//! the user's.

#![allow(dead_code)]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use tunnel_fs_core::{Capability, CapabilitySet, Feature, FeatureSet, PathBounds, VirtualPath};
use tunnel_fs_host::ExportRoot;

static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A temporary tree holding `export/` (the export root) and `outside/` (what an
/// escape would reach), removed when it drops.
pub struct Fixture {
    base: PathBuf,
}

impl Fixture {
    /// Create `<tmp>/tfsh-<pid>-<n>/{export,outside}`.
    ///
    /// The name is kept short because a unix-domain socket path is capped at
    /// about 104 bytes on macOS and the temporary directory itself is already
    /// long.
    pub fn new() -> Self {
        let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
        let base = std::env::temp_dir().join(format!("tfsh-{}-{unique}", std::process::id()));
        fs::create_dir_all(base.join("export")).expect("create export root");
        fs::create_dir_all(base.join("outside")).expect("create outside tree");
        fs::write(base.join("outside/secret.txt"), b"synthetic-outside").expect("write outside");
        Self { base }
    }

    /// The temporary tree's own directory.
    pub fn base(&self) -> &Path {
        &self.base
    }

    /// The host path of the export root.
    pub fn export(&self) -> PathBuf {
        self.base.join("export")
    }

    /// The host path of the directory outside the export.
    pub fn outside(&self) -> PathBuf {
        self.base.join("outside")
    }

    /// A host path inside the export, for building fixtures only.  The
    /// resolver is never given one of these.
    /// A leading `/` is stripped so a virtual path can be handed straight to a
    /// fixture builder without becoming an absolute host path.
    pub fn inside(&self, relative: &str) -> PathBuf {
        self.export().join(relative.trim_start_matches('/'))
    }

    /// Create a directory inside the export.
    pub fn dir(&self, relative: &str) {
        fs::create_dir_all(self.inside(relative)).expect("create fixture directory");
    }

    /// Create a file inside the export.
    pub fn file(&self, relative: &str, contents: &[u8]) {
        if let Some(parent) = self.inside(relative).parent() {
            fs::create_dir_all(parent).expect("create fixture parent");
        }
        fs::write(self.inside(relative), contents).expect("write fixture file");
    }

    /// Create a symbolic link inside the export, with an arbitrary target.
    pub fn link(&self, relative: &str, target: &str) {
        let at = self.inside(relative);
        let _ = fs::remove_file(&at);
        std::os::unix::fs::symlink(target, at).expect("create fixture symlink");
    }

    /// Open the export with the given grant, features and bounds.
    pub fn open(
        &self,
        grant: CapabilitySet,
        features: FeatureSet,
        bounds: PathBounds,
    ) -> ExportRoot {
        ExportRoot::open(&self.export(), grant, features, bounds).expect("open export root")
    }

    /// Open the export with every capability and no optional feature.
    pub fn open_default(&self) -> ExportRoot {
        self.open(full_grant(), FeatureSet::NONE, bounds())
    }

    /// Open the export with every capability and the `symlinks` feature.
    pub fn open_with_symlinks(&self) -> ExportRoot {
        self.open(
            full_grant(),
            FeatureSet::from_slice(&[Feature::Symlinks]),
            bounds(),
        )
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        // Best effort: a test that left something undeletable must not turn a
        // real result into a panic in a destructor.
        let _ = fs::remove_dir_all(&self.base);
    }
}

/// The contract's initial negotiated path bounds.
pub fn bounds() -> PathBounds {
    PathBounds::new(4096, 256).expect("valid bounds")
}

/// All four capabilities.
pub fn full_grant() -> CapabilitySet {
    CapabilitySet::from_slice(&[
        Capability::Read,
        Capability::Write,
        Capability::List,
        Capability::Delete,
    ])
}

/// Parse a virtual path at the standard bounds.
pub fn vpath(text: &str) -> VirtualPath {
    VirtualPath::parse(text, bounds()).expect("valid virtual path")
}
