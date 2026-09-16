//! The confined virtual path namespace.
//!
//! A [`VirtualPath`] is an absolute, already-validated path inside one export's
//! virtual root.  Validation **rejects**; it never rewrites.  There is no
//! normalising constructor, so a caller cannot obtain a `VirtualPath` whose
//! text still contains a `.` component, a `..` component, an empty component,
//! a backslash, a colon, a NUL, a control character, a Windows device name or
//! a component that a host would silently trim.  Anything a resolver would
//! have to *fix* is refused instead, because lexical rewriting of an attacker-
//! supplied path is the classic source of confinement bugs.
//!
//! This module performs **no** filesystem access.  It is the lexical half of
//! confinement only.  Symlinks, hard links, mount points, bind mounts and
//! TOCTOU races are not visible here and are the separate obligation of the
//! OS-confined resolver (implementation gate 2 of `docs/filesystem-api.md`).
//! A `VirtualPath` therefore means "this text cannot itself express an escape",
//! never "this path is safe to open".
//!
//! Neither [`VirtualPath`] nor [`PathRule`] can print path text through
//! `Debug`: `VirtualPath`'s `Debug` is a manual redacting implementation and it
//! has no `Display`.  Path text leaves this type only through the explicit
//! [`VirtualPath::as_str`] accessor.

use core::fmt;

/// Largest single path component, in UTF-8 bytes.
///
/// Matches the `NAME_MAX` that every supported host filesystem provides.  It
/// is a fixed property of the namespace, not a negotiated limit, so it does
/// not appear in the descriptor's `limits` object.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// The virtual root, the only path whose text ends in `/`.
pub const ROOT: &str = "/";

/// Why a candidate path was refused.
///
/// Field-free and `Copy`, so a derived `Debug` cannot carry path bytes.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum PathRule {
    /// The candidate was the empty string.
    Empty,
    /// The candidate did not begin with `/`.
    MissingLeadingSlash,
    /// The candidate exceeded the negotiated `maxPathBytes`.
    TooLongBytes,
    /// The candidate exceeded the negotiated `maxPathComponents`.
    TooManyComponents,
    /// One component exceeded [`MAX_COMPONENT_BYTES`].
    ComponentTooLong,
    /// A repeated or trailing `/` produced a zero-length component.
    EmptyComponent,
    /// A `.` component.  Refused rather than folded away.
    DotComponent,
    /// A `..` component.  Refused rather than resolved.
    DotDotComponent,
    /// An interior NUL, which truncates the path in every C-string host API.
    Nul,
    /// A C0 control character or `DEL`.
    ControlCharacter,
    /// A backslash, which is a separator on Windows hosts.
    Backslash,
    /// A colon, which expresses a drive letter and an NTFS alternate data
    /// stream.  Refusing it narrows the namespace on POSIX hosts deliberately.
    Colon,
    /// A reserved Windows device name such as `CON` or `COM1`, matched
    /// ASCII-case-insensitively against the component's stem.
    WindowsDeviceName,
    /// A component ending in `.` or a space, which Windows silently trims, so
    /// two distinct virtual paths would name one host file.
    TrailingSpaceOrDot,
}

impl PathRule {
    /// The stable diagnostic token for this rule.  Carries no path bytes.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Empty => "PATH_EMPTY",
            Self::MissingLeadingSlash => "PATH_NOT_ABSOLUTE",
            Self::TooLongBytes => "PATH_TOO_LONG",
            Self::TooManyComponents => "PATH_TOO_MANY_COMPONENTS",
            Self::ComponentTooLong => "PATH_COMPONENT_TOO_LONG",
            Self::EmptyComponent => "PATH_EMPTY_COMPONENT",
            Self::DotComponent => "PATH_DOT_COMPONENT",
            Self::DotDotComponent => "PATH_DOTDOT_COMPONENT",
            Self::Nul => "PATH_NUL",
            Self::ControlCharacter => "PATH_CONTROL_CHARACTER",
            Self::Backslash => "PATH_BACKSLASH",
            Self::Colon => "PATH_COLON",
            Self::WindowsDeviceName => "PATH_RESERVED_DEVICE_NAME",
            Self::TrailingSpaceOrDot => "PATH_TRAILING_SPACE_OR_DOT",
        }
    }

    /// Every rule, for exhaustive tests and diagnostics tables.
    pub const ALL: [Self; 14] = [
        Self::Empty,
        Self::MissingLeadingSlash,
        Self::TooLongBytes,
        Self::TooManyComponents,
        Self::ComponentTooLong,
        Self::EmptyComponent,
        Self::DotComponent,
        Self::DotDotComponent,
        Self::Nul,
        Self::ControlCharacter,
        Self::Backslash,
        Self::Colon,
        Self::WindowsDeviceName,
        Self::TrailingSpaceOrDot,
    ];

    /// Parse the exact diagnostic token; anything else is `None`.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|rule| rule.as_str() == text)
    }
}

impl fmt::Display for PathRule {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// Reserved Windows device stems, upper case.
///
/// A component whose stem — the text before its first `.` — equals one of
/// these ASCII-case-insensitively is refused on every host, not only Windows,
/// so one export's namespace does not change meaning when the device that
/// serves it changes operating system.
pub const RESERVED_DEVICE_STEMS: [&str; 26] = [
    "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM0", "COM1", "COM2", "COM3", "COM4",
    "COM5", "COM6", "COM7", "COM8", "COM9", "LPT0", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6",
    "LPT7", "LPT8", "LPT9",
];

/// The bounds a path is checked against.
///
/// Both are negotiated per session and appear in the descriptor, so they are
/// passed in rather than baked in.  Neither may be zero; [`PathBounds::new`]
/// refuses that, so there is no "0 means unlimited" reading.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PathBounds {
    max_bytes: usize,
    max_components: usize,
}

impl PathBounds {
    /// Build bounds, refusing zero in either field.
    #[must_use]
    pub const fn new(max_bytes: usize, max_components: usize) -> Option<Self> {
        if max_bytes == 0 || max_components == 0 {
            return None;
        }
        Some(Self {
            max_bytes,
            max_components,
        })
    }

    /// The maximum whole-path length in UTF-8 bytes.
    #[must_use]
    pub const fn max_bytes(self) -> usize {
        self.max_bytes
    }

    /// The maximum number of components.
    #[must_use]
    pub const fn max_components(self) -> usize {
        self.max_components
    }
}

/// An absolute, validated path inside one export's virtual root.
///
/// Construct with [`VirtualPath::parse`].  There is no `From<String>`, no
/// `Deref<Target = str>` and no `Display`, so path text cannot reach a log line
/// or a formatted error by accident.
#[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct VirtualPath {
    text: String,
    components: usize,
}

impl VirtualPath {
    /// The virtual root.
    #[must_use]
    pub fn root() -> Self {
        Self {
            text: ROOT.to_owned(),
            components: 0,
        }
    }

    /// Validate `candidate` against `bounds`.
    ///
    /// Returns the first rule the candidate violates.  Rules are checked in a
    /// fixed order so the answer is deterministic for a given input, which the
    /// error vocabulary depends on.
    ///
    /// # Errors
    ///
    /// Returns the [`PathRule`] that refused the candidate.
    pub fn parse(candidate: &str, bounds: PathBounds) -> Result<Self, PathRule> {
        if candidate.is_empty() {
            return Err(PathRule::Empty);
        }
        if candidate.len() > bounds.max_bytes() {
            return Err(PathRule::TooLongBytes);
        }
        if !candidate.starts_with('/') {
            return Err(PathRule::MissingLeadingSlash);
        }

        // Byte-level refusals first, so a component split can never be
        // confused by a separator the host would interpret differently.
        for byte in candidate.bytes() {
            match byte {
                0 => return Err(PathRule::Nul),
                b'\\' => return Err(PathRule::Backslash),
                b':' => return Err(PathRule::Colon),
                0x01..=0x1F | 0x7F => return Err(PathRule::ControlCharacter),
                _ => {}
            }
        }

        if candidate == ROOT {
            return Ok(Self::root());
        }

        let body = &candidate[1..];
        let mut components = 0usize;
        for component in body.split('/') {
            components += 1;
            if components > bounds.max_components() {
                return Err(PathRule::TooManyComponents);
            }
            check_component(component)?;
        }

        Ok(Self {
            text: candidate.to_owned(),
            components,
        })
    }

    /// The validated path text.
    ///
    /// This is the only way to read the text.  Callers that put the result in a
    /// log line, a `Debug` rendering or an error message violate the
    /// payload-free rule in `docs/filesystem-api.md`.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The path's components, root first.  Empty for the root itself.
    pub fn components(&self) -> impl Iterator<Item = &str> {
        self.text
            .strip_prefix('/')
            .filter(|body| !body.is_empty())
            .into_iter()
            .flat_map(|body| body.split('/'))
    }

    /// How many components the path has.  Zero for the root.
    #[must_use]
    pub const fn component_count(&self) -> usize {
        self.components
    }

    /// Whether this is the virtual root.
    #[must_use]
    pub const fn is_root(&self) -> bool {
        self.components == 0
    }

    /// The final component, or `None` for the root.
    #[must_use]
    pub fn file_name(&self) -> Option<&str> {
        if self.is_root() {
            return None;
        }
        self.text.rsplit('/').next().filter(|name| !name.is_empty())
    }

    /// The parent path, or `None` for the root.
    #[must_use]
    pub fn parent(&self) -> Option<Self> {
        if self.is_root() {
            return None;
        }
        let cut = self.text.rfind('/').unwrap_or(0);
        if cut == 0 {
            return Some(Self::root());
        }
        Some(Self {
            text: self.text[..cut].to_owned(),
            components: self.components - 1,
        })
    }

    /// Append one already-validated component.
    ///
    /// The component is checked with the same rules `parse` applies, and the
    /// result is re-checked against `bounds`, so building a path piecewise
    /// cannot reach a path `parse` would have refused.
    ///
    /// # Errors
    ///
    /// Returns the [`PathRule`] that refused the component or the result.
    pub fn join(&self, component: &str, bounds: PathBounds) -> Result<Self, PathRule> {
        check_component(component)?;
        let mut text = String::with_capacity(self.text.len() + 1 + component.len());
        text.push_str(&self.text);
        if !self.is_root() {
            text.push('/');
        }
        text.push_str(component);
        Self::parse(&text, bounds)
    }

    /// Whether `self` is `other` or lies beneath it.
    ///
    /// Component-wise, never a string prefix test: `/ab` is not beneath `/a`.
    #[must_use]
    pub fn is_within(&self, other: &Self) -> bool {
        let mut mine = self.components();
        for theirs in other.components() {
            match mine.next() {
                Some(component) if component == theirs => {}
                _ => return false,
            }
        }
        true
    }

    /// A collision key for an ASCII-case-insensitive host.
    ///
    /// Two paths that a case-insensitive host would resolve to one file share a
    /// key.  The fold is **ASCII only**: it does not implement Unicode simple
    /// or full case folding, and it does not apply NFC or NFD normalisation, so
    /// it does not detect every collision an HFS+ or APFS volume can produce.
    /// That residue is named in `docs/filesystem-api.md` and is the resolver's
    /// obligation, not this key's.
    #[must_use]
    pub fn ascii_case_fold_key(&self) -> String {
        self.text.to_ascii_lowercase()
    }
}

/// Redacting `Debug`: shape only, never path text.
impl fmt::Debug for VirtualPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "VirtualPath(<redacted> bytes={} components={})",
            self.text.len(),
            self.components
        )
    }
}

/// Validate one path component under the same rules `parse` applies.
fn check_component(component: &str) -> Result<(), PathRule> {
    if component.is_empty() {
        return Err(PathRule::EmptyComponent);
    }
    if component.len() > MAX_COMPONENT_BYTES {
        return Err(PathRule::ComponentTooLong);
    }
    if component == "." {
        return Err(PathRule::DotComponent);
    }
    if component == ".." {
        return Err(PathRule::DotDotComponent);
    }
    for byte in component.bytes() {
        match byte {
            0 => return Err(PathRule::Nul),
            b'\\' => return Err(PathRule::Backslash),
            b':' => return Err(PathRule::Colon),
            b'/' => return Err(PathRule::EmptyComponent),
            0x01..=0x1F | 0x7F => return Err(PathRule::ControlCharacter),
            _ => {}
        }
    }
    if component.ends_with('.') || component.ends_with(' ') {
        return Err(PathRule::TrailingSpaceOrDot);
    }
    if is_reserved_device_stem(component) {
        return Err(PathRule::WindowsDeviceName);
    }
    Ok(())
}

/// Whether a component's stem is a reserved Windows device name.
fn is_reserved_device_stem(component: &str) -> bool {
    let stem = component.split('.').next().unwrap_or(component);
    RESERVED_DEVICE_STEMS
        .iter()
        .any(|reserved| stem.eq_ignore_ascii_case(reserved))
}
