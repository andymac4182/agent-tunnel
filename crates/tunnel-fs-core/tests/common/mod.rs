//! Shared fixtures and a dependency-free deterministic generator.
//!
//! The workspace pins no property-testing crate, so the generative tests here
//! use the same style as `tunnel-http-forward`: a seeded xorshift generator and
//! exhaustive enumeration, both reproducible from the seed printed on failure.

#![allow(dead_code)]

use tunnel_fs_core::{
    Availability, Capability, CapabilitySet, CaseSensitivity, Descriptor, ExportIdentity,
    FeatureSet, Identifier, Limits, PathBounds,
};

/// The profile-default path bounds: 4096 bytes, 256 components.
#[must_use]
pub fn default_bounds() -> PathBounds {
    Limits::PROFILE_DEFAULT.path_bounds()
}

/// An identifier that is known valid.
#[must_use]
pub fn identifier(text: &str) -> Identifier {
    Identifier::parse(text).expect("fixture identifier is valid")
}

/// The export identity used by the golden descriptor fixture.
#[must_use]
pub fn example_identity() -> ExportIdentity {
    ExportIdentity {
        device_id: identifier("device-123"),
        service_id: identifier("workspace"),
        grant_revision: identifier("opaque-example-revision"),
    }
}

/// The read-only grant the checked-in descriptor example corresponds to.
#[must_use]
pub fn example_grant() -> CapabilitySet {
    CapabilitySet::from_slice(&[Capability::Read, Capability::List])
}

/// The descriptor the checked-in example document describes.
#[must_use]
pub fn example_descriptor() -> Descriptor {
    Descriptor::new(
        example_identity(),
        Availability::Online,
        CaseSensitivity::Sensitive,
        example_grant(),
        FeatureSet::NONE,
        Limits::PROFILE_DEFAULT,
    )
}

/// A reproducible xorshift64* generator.
pub struct Rng(u64);

impl Rng {
    /// Seed the generator.  A zero seed is replaced, since xorshift fixes it.
    #[must_use]
    pub const fn new(seed: u64) -> Self {
        Self(if seed == 0 {
            0x9E37_79B9_7F4A_7C15
        } else {
            seed
        })
    }

    /// The next raw value.
    pub const fn next_u64(&mut self) -> u64 {
        let mut state = self.0;
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        self.0 = state;
        state.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// A value in `0..bound`.  `bound` must be non-zero.
    pub const fn below(&mut self, bound: usize) -> usize {
        (self.next_u64() % (bound as u64)) as usize
    }

    /// Pick one element.
    pub fn pick<'a, T>(&mut self, options: &'a [T]) -> &'a T {
        &options[self.below(options.len())]
    }
}

/// The building blocks a generated path is assembled from.
///
/// Every escape class the contract names is represented, mixed with ordinary
/// and awkward-but-legal components, so a generated path exercises acceptance
/// and rejection rather than only rejection.
pub const PATH_FRAGMENTS: [&str; 40] = [
    // Ordinary.
    "a",
    "notes",
    "dir",
    "file.txt",
    "MixedCase",
    "with space",
    "dash-and_underscore",
    "unicode-\u{e9}\u{fc}\u{4e2d}",
    "percent%20literal",
    "hash#literal",
    "question?literal",
    "star*literal",
    "quote\"literal",
    "pipe|literal",
    "tilde~",
    "0123456789",
    // Separators and traversal.
    "/",
    "//",
    "..",
    ".",
    "...",
    "..\u{2f}..",
    // Absolute and host syntax.
    "\\",
    "C:",
    "C:\\Windows",
    "\\\\server\\share",
    "stream:name",
    // Control and NUL.
    "\u{0}",
    "bel\u{7}",
    "newline\n",
    "tab\t",
    "\u{7f}",
    // Windows device names.
    "CON",
    "con",
    "NUL.txt",
    "COM1",
    "lpt9.log",
    "CONIN$",
    // Trimmed endings.
    "trailing.",
    "trailing ",
];
