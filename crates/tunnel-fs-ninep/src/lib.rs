#![forbid(unsafe_code)]
//! The 9P2000.L codec and session state machine defined by
//! `docs/filesystem-api.md`.
//!
//! This crate implements **implementation gate 3 only**: the message encoding
//! and decoding this product actually uses, `msize` negotiation, an incremental
//! split-tolerant decoder, tag and fid quotas, and the session lifecycle as a
//! pure state machine.  It depends on nothing but the gate-1 core.  There is no
//! socket, no relay wiring, no filesystem access, no async runtime and no clock
//! here, and no test in it opens a file or a port.
//!
//! # Where it sits
//!
//! ```text
//!   gate 4 endpoint  ──uses──▶  [Session]  ──names──▶  VirtualPath (gate 1)
//!          │                        │                        │
//!          │                        └── Primitives ──────────▶ grant check
//!          │                                                  (gate 1)
//!          └──bytes──▶ [FrameDecoder] / [decode_exact] ──▶ [Frame]
//!                                                            │
//!                         gate 2 resolver ◀── VirtualPath ───┘
//! ```
//!
//! It defines the interface to both neighbours without wiring either:
//!
//! * **To gate 2.** [`session::RequestPaths`] hands the resolver already
//!   validated [`tunnel_fs_core::VirtualPath`]s — one for a node, two for a
//!   walk, a parent and a child for a create or remove, and an independent pair
//!   for a rename or a link, because the contract confines both endpoints
//!   separately.  Nothing here ever hands the resolver a raw wire string.
//! * **To gate 4.** [`session::Session::request`] returns
//!   [`session::Accepted`], whose [`flags::Primitives`] are the exact gate-1
//!   primitives the request needs — with the `.L` flags already decoded, so
//!   `Tlopen` has become read, directory, write and truncate decisions and
//!   `Tsetattr` has become size, mode and time decisions.  Gate 4 authorizes
//!   those against the **live** grant, resolves the paths, then reports back
//!   through [`session::Session::complete`] or [`session::Session::fail`].
//!
//! # Non-UTF-8 names are settled here
//!
//! The contract assigns non-UTF-8 input to this gate, because gate 1's
//! `VirtualPath` is a `&str` by construction and a byte sequence that is not
//! UTF-8 cannot reach path validation at all.  [`wire::Reader::string`] is the
//! answer: **every** `string[s]` field in the profile, in both directions, is
//! required to be valid UTF-8 and is otherwise refused with
//! [`CodecError::StringNotUtf8`] naming the field.  There is no
//! `from_utf8_lossy` in this crate — a U+FFFD substitution would turn one host
//! name into a different one, and hand gate 2 a path naming a file the caller
//! never asked for.  The rule covers `Rreadlink`'s target and the names inside
//! an `Rreaddir` block as well as request names, so a host filename that cannot
//! be represented produces an explicit refusal on the way *out* too, never a
//! transliteration.
//!
//! # Payload-free by construction
//!
//! Every error is `Copy` over field-free enums, apart from the two framing
//! bytes an unknown or denied opcode carries — which came from the peer's own
//! fixed header, not from a payload.  No error can hold a name, a path, file
//! content, a link target or a host detail.
//!
//! # What this crate cannot prove
//!
//! Anything that needs a socket, a clock or a filesystem: real WebSocket
//! fragmentation, tunnel DATA-frame interleaving, deadlines, idle timeouts,
//! queued-byte accounting, and whether a mutation actually happened.  Those are
//! gates 4 and 5.

pub mod codec;
pub mod error;
pub mod flags;
pub mod message;
pub mod readdir;
pub mod session;
pub mod wire;

pub use codec::{
    COUNTED_REPLY_OVERHEAD, DIALECT, Frame, FrameDecoder, MAX_MESSAGE_BYTES, MIN_MSIZE,
    WRITE_REQUEST_OVERHEAD, decode_exact, negotiate,
};
pub use error::{Answer, CodecError, SessionError, StringField};
pub use flags::{
    AT_REMOVEDIR, GETATTR_ALL, GETATTR_BASIC, Primitives, SETATTR_ALLOWED, create_primitives,
    getattr_primitives, open_primitives, open_primitives_from_flags, setattr_primitives,
    unlinkat_primitives,
};
pub use message::{Attributes, KNOWN_OUTSIDE_PROFILE, Message, MessageType};
pub use readdir::{DirEntry, ENTRY_OVERHEAD, pack_entries, parse_entries};
pub use session::{Accepted, FidState, OpenMode, Phase, RequestPaths, Session};
pub use wire::{
    HEADER_LEN, MAX_WALK_NAMES, NOFID, NONUNAME, NOTAG, QID_LEN, Qid, QidKind, Reader, Writer,
};
