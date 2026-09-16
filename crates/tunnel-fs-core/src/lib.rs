#![forbid(unsafe_code)]
//! The pure filesystem-export core defined by `docs/filesystem-api.md`.
//!
//! This crate implements **implementation gate 1 only**: the confined virtual
//! path namespace, the capability and primitive authorization model, the
//! negotiated limits, the payload-free error vocabulary and the
//! `agent-tunnel.fs.v1` descriptor.  It is independent of the 9P codec, the
//! WebSocket upgrade, Axum, the relay, the device daemon, Tokio, clocks and the
//! real filesystem.  Nothing in it performs I/O.
//!
//! # What this crate proves, and what it does not
//!
//! It proves the **lexical** half of confinement: that no path a caller can
//! construct through [`path::VirtualPath`] contains a `..`, a `.`, an empty
//! component, a backslash, a colon, a NUL, a control character, a reserved
//! Windows device name or a component a host would silently trim, and that a
//! path is refused rather than rewritten.  It proves that capabilities default
//! to deny, that no advertised operation can exceed its primitive grant, and
//! that every limit is bounded with no unlimited sentinel.
//!
//! It does **not** prove confinement against the operating system.  Symbolic
//! links, hard links, mount points, bind mounts, case-insensitive collisions
//! beyond the ASCII fold, and every TOCTOU race between resolving a path and
//! acting on it are invisible to a crate that never opens a file.  Those are
//! the obligation of the OS-confined resolver in implementation gate 2, which
//! must use `openat2`/`O_NOFOLLOW`-style anchored traversal and must treat a
//! [`path::VirtualPath`] as "this text cannot express an escape", never as
//! "this path is safe to open".
//!
//! # Payload-free by construction
//!
//! No error type here owns a path, a file name or file content.  Every error is
//! `Copy` over field-free enums, and [`path::VirtualPath`] has a redacting
//! `Debug` and no `Display`, so path text reaches a caller only through the
//! explicit [`path::VirtualPath::as_str`] accessor.

pub mod capability;
pub mod descriptor;
pub mod error;
pub mod limits;
pub mod path;

pub use capability::{Capability, CapabilitySet, ClientOperation, Feature, FeatureSet, Primitive};
pub use descriptor::{
    Availability, CaseSensitivity, Descriptor, ExportIdentity, Identifier, IdentifierRule,
    MAX_IDENTIFIER_BYTES, NON_BASELINE_FEATURES, ROOT_PATH, ROOT_PATH_STYLE, SCHEMA_VERSION,
    TRANSPORT_DIALECT, TRANSPORT_SUBPROTOCOL, TRANSPORT_TYPE,
};
pub use error::{FsError, FsErrorCode, Outcome, SessionErrorCode};
pub use limits::{
    DEFAULT_OPERATION_TIMEOUT_SECONDS_CEILING, LimitError, LimitField, LimitRule, Limits,
    MAX_BUFFERED_FILE_BYTES_CEILING, MAX_FIDS_CEILING, MAX_INFLIGHT_REQUESTS_CEILING,
    MAX_MESSAGE_BYTES_CEILING, MAX_OPERATION_TIMEOUT_SECONDS_CEILING, MAX_PATH_BYTES_CEILING,
    MAX_PATH_COMPONENTS_CEILING, MAX_QUEUED_BYTES_CEILING, MAX_TOTAL_BUFFERED_BYTES_CEILING,
    MAX_TRAVERSAL_DEPTH_CEILING, MAX_TRAVERSAL_ENTRIES_CEILING, MIN_MESSAGE_BYTES,
    REQUEST_TIMEOUT_SECONDS_CEILING, SESSION_IDLE_SECONDS_CEILING,
};
pub use path::{
    MAX_COMPONENT_BYTES, PathBounds, PathRule, RESERVED_DEVICE_STEMS, ROOT, VirtualPath,
};

/// Whether a session may be admitted for `grant`.
///
/// Default deny: the empty grant admits nothing, so an export whose
/// configuration named no capability is unreachable rather than permissive.
#[must_use]
pub const fn admits_session(grant: CapabilitySet) -> bool {
    !grant.is_empty()
}
