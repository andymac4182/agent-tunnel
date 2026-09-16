#!/usr/bin/env python3
"""Delete one filesystem guard at a time, run the tests it should protect, and
restore it.

This is the red-then-green evidence behind the filesystem implementation gates
of `docs/filesystem-api.md`.  Two suites live here:

* `gate2` — the OS-confined resolver in `crates/tunnel-fs-host`.
* `gate3` — the 9P2000.L codec and session state machine in
  `crates/tunnel-fs-ninep`.

A guard whose deletion leaves every test green is **not** load-bearing on its
own, and this script prints that outcome rather than hiding it: several of the
resolver's guards mask one another and are red only in pairs or as a triple,
which is why those combinations are cases here in their own right, and the same
honesty applies to gate 3's.

    python3 scripts/fs-guard-deletion.py                 # every case
    python3 scripts/fs-guard-deletion.py --list          # names only
    python3 scripts/fs-guard-deletion.py --suite gate3   # one suite
    python3 scripts/fs-guard-deletion.py --case "32-hop" # substring filter

Exit status is 0 when every case produced a usable result, and 1 when any case
could not be applied or did not build — see `run_tests` below, which refuses to
call a failed build a red test.  An earlier round of this evidence was wrong in
exactly that way: the harness restored the crate with a checkout between runs,
which also reverted an uncommitted cargo feature the tests needed, so three
cases reported "RED" for a build that never compiled.  That refusal is the
reason the numbers in task rows M4-08 and M4-09 can be trusted, so do not remove
it.

The working tree must be clean before running: every case is restored by
checking the crate out again, which would discard uncommitted work there.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
CRATE = REPO / "crates" / "tunnel-fs-host"
RESOLVER = CRATE / "src" / "resolver.rs"
POLICY = CRATE / "src" / "policy.rs"
IDENTITY = CRATE / "src" / "identity.rs"

NINEP = REPO / "crates" / "tunnel-fs-ninep"
NINEP_WIRE = NINEP / "src" / "wire.rs"
NINEP_CODEC = NINEP / "src" / "codec.rs"
NINEP_MESSAGE = NINEP / "src" / "message.rs"
NINEP_FLAGS = NINEP / "src" / "flags.rs"
NINEP_SESSION = NINEP / "src" / "session.rs"
NINEP_READDIR = NINEP / "src" / "readdir.rs"

# The tests need the hook that holds the TOCTOU window open; without it the
# four window guards cannot be measured at all.
CARGO_TEST = [
    "cargo",
    "test",
    "-p",
    "tunnel-fs-host",
    "--locked",
    "--features",
    "race-window-hook",
]

# An edit is (file, exact text to remove or replace, replacement).
Edit = tuple[Path, str, str]

DIR_NOFOLLOW: Edit = (
    RESOLVER,
    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,\n"
    "                            Mode::empty(),",
    "OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,\n"
    "                            Mode::empty(),",
)
FILE_NOFOLLOW: Edit = (
    RESOLVER,
    "intent.flags() | OFlags::NOFOLLOW | OFlags::CLOEXEC | OFlags::NONBLOCK,",
    "intent.flags() | OFlags::CLOEXEC | OFlags::NONBLOCK,",
)
DIR_IDENTITY: Edit = (
    RESOLVER,
    """                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    check_same_device(self.identity, identity)?;
                    if last {""",
    """                    let identity = identity_of(&opened)?;
                    check_same_device(self.identity, identity)?;
                    if last {""",
)
FILE_IDENTITY: Edit = (
    RESOLVER,
    """                    let identity = identity_of(&opened)?;
                    if !identity.is_same_file(seen) {
                        return Err(lost_race());
                    }
                    // Decided again on the descriptor, which is the only
                    // authority: the check above was taken on a name.""",
    """                    let identity = identity_of(&opened)?;""",
)
DIR_POST_DEVICE: Edit = (
    RESOLVER,
    "                    check_same_device(self.identity, identity)?;\n                    if last {",
    "                    if last {",
)
DIR_PRE_DEVICE: Edit = (
    RESOLVER,
    """                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            OFlags::RDONLY | OFlags::DIRECTORY""",
    """                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            OFlags::RDONLY | OFlags::DIRECTORY""",
)
FILE_PRE_DEVICE: Edit = (
    RESOLVER,
    """                    check_same_device(self.identity, seen)?;
                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            intent.flags()""",
    """                    let opened = retry(|| {
                        rustix::fs::openat(
                            parent,
                            name.as_str(),
                            intent.flags()""",
)
PRE_OPEN_KIND: Edit = (RESOLVER, "                    check_exportable(kind)?;\n", "")
POST_OPEN_KIND: Edit = (RESOLVER, "                    check_exportable(identity.kind())?;\n", "")

GATE2_CASES: list[tuple[str, list[Edit]]] = [
    (
        "symlink feature refusal (rule 3)",
        [
            (
                RESOLVER,
                """                    if !self.features.has(Feature::Symlinks) {
                        // Rule 3: with the feature off a link met during
                        // traversal fails the walk rather than being followed.
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
""",
                "",
            )
        ],
    ),
    (
        "32-hop link budget",
        [
            (
                RESOLVER,
                """                    hops += 1;
                    if hops > MAX_LINK_HOPS {
                        return Err(FsError::refused(FsErrorCode::Eloop));
                    }
""",
                "                    hops += 1;\n",
            )
        ],
    ),
    (
        "absolute link target re-rooting",
        [(RESOLVER, "                        ancestors.truncate(1);", "                        let _ = &ancestors;")],
    ),
    (
        "`..` clamped at the root",
        [
            (
                RESOLVER,
                """                if ancestors.len() > 1 {
                    ancestors.pop();
                }""",
                "                ancestors.pop();",
            )
        ],
    ),
    (
        "link-target component bound",
        [
            (
                RESOLVER,
                """                    if parts.len() > self.bounds.max_components() {
                        return Err(FsError::refused(FsErrorCode::Enametoolong));
                    }
""",
                "",
            )
        ],
    ),
    (
        "trailing-separator link target rule",
        [
            (
                RESOLVER,
                """                    if last && target.ends_with('/') {
                        require_directory = true;
                    }
""",
                "",
            )
        ],
    ),
    (
        "uniform race answer (ELOOP/ENOTDIR fold)",
        [
            (
                RESOLVER,
                """    if errno == rustix::io::Errno::LOOP || errno == rustix::io::Errno::NOTDIR {
        lost_race()
    } else {
        host_error(errno)
    }""",
                "    host_error(errno)",
            )
        ],
    ),
    ("mount boundary after the directory open", [DIR_POST_DEVICE]),
    ("mount boundary before the directory open", [DIR_PRE_DEVICE]),
    ("mount boundary before the file open", [FILE_PRE_DEVICE]),
    (
        "all three mount-boundary checks together",
        [DIR_PRE_DEVICE, FILE_PRE_DEVICE, DIR_POST_DEVICE],
    ),
    ("special-file refusal before the open", [PRE_OPEN_KIND]),
    ("special-file refusal on the descriptor", [POST_OPEN_KIND]),
    ("both special-file refusals", [PRE_OPEN_KIND, POST_OPEN_KIND]),
    ("O_NOFOLLOW on a directory component", [DIR_NOFOLLOW]),
    ("O_NOFOLLOW on the final file open", [FILE_NOFOLLOW]),
    ("post-open identity check on a directory", [DIR_IDENTITY]),
    ("post-open identity check on a file", [FILE_IDENTITY]),
    ("directory O_NOFOLLOW and its identity check together", [DIR_NOFOLLOW, DIR_IDENTITY]),
    ("file O_NOFOLLOW and its identity check together", [FILE_NOFOLLOW, FILE_IDENTITY]),
    (
        "hard-link write refusal (rule 4)",
        [
            (
                RESOLVER,
                """        check_hard_link_write(
            primitive,
            handle.identity(),
            self.features.has(Feature::HardLinks),
        )?;
""",
                "",
            )
        ],
    ),
    (
        "hard-link rule excludes directories",
        [
            (
                IDENTITY,
                "matches!(self.kind, FileKind::RegularFile) && self.links > 1",
                "self.links > 1",
            )
        ],
    ),
    (
        "grant check before resolution",
        [
            (
                RESOLVER,
                """        self.authorize(primitive)?;
        let handle = self.resolve(path, Intent::Write)?;""",
                "        let handle = self.resolve(path, Intent::Write)?;",
            )
        ],
    ),
    (
        "host errno translated by meaning",
        [
            (
                POLICY,
                """    if errno == Errno::NOENT {
        FsErrorCode::Enoent""",
                """    if errno == Errno::NOENT {
        FsErrorCode::Einval""",
            )
        ],
    ),
    (
        "EINTR retried rather than reported",
        [
            (
                RESOLVER,
                "            Err(errno) if errno == rustix::io::Errno::INTR => {}",
                "            Err(errno) if errno == rustix::io::Errno::INTR && false => {}",
            )
        ],
    ),
]

# --------------------------------------------------------------------- gate 3
#
# The codec and session machine in `crates/tunnel-fs-ninep`.  Every edit below
# removes or defeats one refusal, leaving something that still compiles: a
# deletion that will not build is not evidence, and `run_tests` refuses to
# report one as red.

GATE3_CASES: list[tuple[str, list[Edit]]] = [
    (
        "UTF-8 refusal on every string[s] (the non-UTF-8 gate)",
        [
            (
                NINEP_WIRE,
                "        core::str::from_utf8(bytes).map_err(|_| CodecError::StringNotUtf8(field))",
                "        let _ = field;\n        Ok(core::str::from_utf8(bytes).unwrap_or(\"\"))",
            )
        ],
    ),
    (
        "declared size below the seven-byte header",
        [
            (
                NINEP_CODEC,
                """    if size < HEADER_LEN as u32 {
        return Err(CodecError::FrameBelowHeader);
    }
""",
                "",
            )
        ],
    ),
    (
        "declared size above the profile ceiling",
        [
            (
                NINEP_CODEC,
                """    if size > MAX_MESSAGE_BYTES {
        return Err(CodecError::FrameAboveCeiling);
    }
""",
                "",
            )
        ],
    ),
    (
        "declared size above the negotiated msize",
        [
            (
                NINEP_CODEC,
                """    if size > msize {
        return Err(CodecError::FrameAboveMsize);
    }
    Ok(())
}""",
                """    let _ = msize;
    Ok(())
}""",
            )
        ],
    ),
    (
        "encoded frame above the negotiated msize",
        [
            (
                NINEP_CODEC,
                """        if size > msize {
            return Err(CodecError::FrameAboveMsize);
        }
""",
                "",
            )
        ],
    ),
    (
        "trailing bytes after a decoded body",
        [
            (
                NINEP_WIRE,
                """        if self.remaining() == 0 {
            Ok(())
        } else {
            Err(CodecError::TrailingBytes)
        }""",
                "        Ok(())",
            )
        ],
    ),
    (
        "the reserved-tag rule (NOTAG)",
        [
            (
                NINEP_CODEC,
                """    match (version_handshake, tag == NOTAG) {
        (true, true) | (false, false) => Ok(()),
        (true, false) => Err(CodecError::NotagRequired),
        (false, true) => Err(CodecError::NotagNotPermitted),
    }""",
                "    let _ = (version_handshake, tag);\n    Ok(())",
            )
        ],
    ),
    (
        "opcodes outside the profile",
        [
            (
                NINEP_MESSAGE,
                """        if KNOWN_OUTSIDE_PROFILE.contains(&code) {
            return Err(CodecError::MessageTypeNotInProfile(code));
        }
""",
                "",
            )
        ],
    ),
    (
        "MAXWELEM bound when decoding a Twalk",
        [
            (
                NINEP_MESSAGE,
                """                let count = usize::from(reader.u16()?);
                if count > MAX_WALK_NAMES {
                    return Err(CodecError::TooManyWalkNames);
                }
                // Bounded by MAX_WALK_NAMES before a single element is
                // reserved, so a declared count cannot drive an allocation.
                let mut names = Vec::with_capacity(count);""",
                """                let count = usize::from(reader.u16()?);
                let mut names = Vec::new();""",
            )
        ],
    ),
    (
        "the count check before a counted payload is copied",
        [
            (
                NINEP_MESSAGE,
                """    if count > reader.remaining() {
        return Err(CodecError::TruncatedBody);
    }
""",
                "",
            )
        ],
    ),
    (
        "qid type bits outside the profile",
        [
            (
                NINEP_WIRE,
                """            _ => Err(CodecError::QidTypeNotInProfile),""",
                """            _ => Ok(Self::File),""",
            )
        ],
    ),
    (
        "the closed Rlerror errno vocabulary",
        [
            (
                NINEP_MESSAGE,
                "                    .ok_or(CodecError::ErrnoNotInVocabulary)?;",
                "                    .unwrap_or(FsErrorCode::Einval);",
            )
        ],
    ),
    (
        "a Tread count that could not fit its own reply",
        [
            (
                NINEP_CODEC,
                """    if over {
        return Err(CodecError::CountAboveMsize);
    }
""",
                "",
            )
        ],
    ),
    (
        "the dialect check in msize negotiation",
        [
            (
                NINEP_CODEC,
                """    if offered_version != DIALECT {
        return Err(SessionError::UnsupportedDialect);
    }
""",
                "",
            )
        ],
    ),
    (
        "the msize floor in negotiation",
        [
            (
                NINEP_CODEC,
                """    if negotiated < MIN_MSIZE {
        return Err(SessionError::MsizeBelowFloor);
    }
""",
                "",
            )
        ],
    ),
    (
        "msize reduction (min of the two offers)",
        [
            (
                NINEP_CODEC,
                "    let negotiated = offered_msize.min(maximum).min(MAX_MESSAGE_BYTES);",
                "    let negotiated = offered_msize;\n    let _ = maximum;",
            )
        ],
    ),
    (
        "the decoder's error latch (sticky failures)",
        [
            (
                NINEP_CODEC,
                """            Err(error) => {
                self.state = State::Failed(error);
                Err(error)
            }""",
                """            Err(error) => Err(error),""",
            )
        ],
    ),
    (
        "apply_msize refusing to raise the bound",
        [
            (
                NINEP_CODEC,
                """        if msize > self.msize {
            return Err(SessionError::MsizeNotAReduction);
        }
""",
                "",
            )
        ],
    ),
    (
        "the Tlopen allowed-flag mask",
        [
            (
                NINEP_FLAGS,
                """    if flags & !OPEN_FLAGS_ALLOWED != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
""",
                "",
            )
        ],
    ),
    (
        "the invalid access mode 3",
        [
            (
                NINEP_FLAGS,
                """    let access = flags & O_ACCMODE;
    if access == O_ACCMODE {
        return Err(SessionError::FlagNotInProfile);
    }
    let writing""",
                """    let access = flags & O_ACCMODE;
    let writing""",
            )
        ],
    ),
    (
        "refusing a writable or truncating directory open",
        [
            (
                NINEP_FLAGS,
                """    if directory && mutating {
        // A directory is opened to be enumerated.  `O_WRONLY|O_DIRECTORY` is
        // `EISDIR` on Linux; refusing it here keeps the decision in one place.
        return Err(SessionError::FlagNotInProfile);
    }
""",
                "    let _ = mutating;\n",
            )
        ],
    ),
    (
        "refusing O_TRUNC or O_APPEND on a read-only open",
        [
            (
                NINEP_FLAGS,
                """    if !writing && flags & (O_TRUNC | O_APPEND) != 0 {
        // Truncating or appending through a read-only descriptor is not a
        // thing the host will do, and accepting it would advertise an
        // authorization decision the provider could not honour.
        return Err(SessionError::FlagNotInProfile);
    }
""",
                "",
            )
        ],
    ),
    (
        "the Tsetattr mask (ownership fields refused)",
        [
            (
                NINEP_FLAGS,
                """    if valid == 0 || valid & !SETATTR_ALLOWED != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
""",
                "",
            )
        ],
    ),
    (
        "the Tunlinkat flag split",
        [
            (
                NINEP_FLAGS,
                """        _ => Err(SessionError::FlagNotInProfile),
    }
}

/// Validate a `Tgetattr` `request_mask`.""",
                """        _ => Ok(Primitives::one(Primitive::Unlink)),
    }
}

/// Validate a `Tgetattr` `request_mask`.""",
            )
        ],
    ),
    (
        "the Tgetattr request mask",
        [
            (
                NINEP_FLAGS,
                """    if request_mask == 0 || request_mask & !GETATTR_ALL != 0 {
        return Err(SessionError::FlagNotInProfile);
    }
""",
                "",
            )
        ],
    ),
    (
        "the grant check on every request",
        [
            (
                NINEP_SESSION,
                """        for primitive in accepted.primitives.iter() {
            if !primitive.is_permitted(self.grant, self.features) {
                return Err(SessionError::NotPermitted);
            }
        }
""",
                "",
            )
        ],
    ),
    (
        "the tag quota",
        [
            (
                NINEP_SESSION,
                """        if self.tags.len() >= quota {
            return Err(SessionError::TagQuotaExhausted);
        }
""",
                "",
            )
        ],
    ),
    (
        "the fid quota",
        [
            (
                NINEP_SESSION,
                """        if self.live_fids() >= quota {
            return Err(SessionError::FidQuotaExhausted);
        }
""",
                "",
            )
        ],
    ),
    (
        "refusing a fid that is already allocated or reserved",
        [
            (
                NINEP_SESSION,
                """        if self.fids.contains_key(&fid) || self.reserved_fids.contains_key(&fid) {
            return Err(SessionError::FidInUse);
        }
""",
                "",
            )
        ],
    ),
    (
        "refusing a duplicate outstanding tag",
        [
            (
                NINEP_SESSION,
                """        if let Some(existing) = self.tags.get(&frame.tag) {
            return Err(if !existing.flushed_by.is_empty() || existing.answered {
                SessionError::TagReservedByFlush
            } else {
                SessionError::TagInUse
            });
        }
""",
                "",
            )
        ],
    ),
    (
        "the Tattach field refusals",
        [
            (
                NINEP_SESSION,
                """                if *afid != NOFID || !uname.is_empty() || !aname.is_empty() || *n_uname != NONUNAME
                {
                    return Err(SessionError::AttachFieldNotPermitted);
                }
""",
                "",
            )
        ],
    ),
    (
        "refusing a repeated Tversion",
        [
            (
                NINEP_SESSION,
                """                if self.phase != Phase::AwaitingVersion || self.pending_msize.is_some() {
                    return Err(SessionError::RepeatedVersion);
                }
                let negotiated = negotiate(*msize, version, self.msize)?;""",
                """                let negotiated = negotiate(*msize, version, self.msize)?;""",
            )
        ],
    ),
    (
        "refusing a repeated Tattach",
        [
            (
                NINEP_SESSION,
                "                    Phase::Attached => return Err(SessionError::RepeatedAttach),",
                "                    Phase::Attached => {}",
            )
        ],
    ),
    (
        "the phase gate before attach",
        [
            (
                NINEP_SESSION,
                """            Phase::AwaitingVersion => return Err(SessionError::BeforeVersion),
            Phase::Versioned => return Err(SessionError::BeforeAttach),
            Phase::Attached => {}
            Phase::Closed => return Err(SessionError::Closed),""",
                """            Phase::Closed => return Err(SessionError::Closed),
            _ => {}""",
            )
        ],
    ),
    (
        "refusing a walk from an open fid",
        [
            (
                NINEP_SESSION,
                """                if origin.open.is_some() {
                    // 9P: a walk from an open fid is illegal.  The fid's
                    // position and its open mode would otherwise disagree.
                    return Err(SessionError::FidIsOpen);
                }
""",
                "",
            )
        ],
    ),
    (
        "refusing a second open of one fid",
        [
            (
                NINEP_SESSION,
                """                let state = self.require_fid(*fid)?;
                if state.open.is_some() {
                    return Err(SessionError::FidIsOpen);
                }
                let directory = state.is_directory();""",
                """                let state = self.require_fid(*fid)?;
                let directory = state.is_directory();""",
            )
        ],
    ),
    (
        "the open-mode check on Tread and Twrite",
        [
            (
                NINEP_SESSION,
                """                if !open.read {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Read), &state.path),""",
                """                Ok((
                    node(Primitives::one(Primitive::Read), &state.path),""",
            ),
            (
                NINEP_SESSION,
                """                if !open.write {
                    return Err(SessionError::FidNotOpen);
                }
                Ok((
                    node(Primitives::one(Primitive::Write), &state.path),""",
                """                Ok((
                    node(Primitives::one(Primitive::Write), &state.path),""",
            ),
        ],
    ),
    (
        "refusing a byte read of a directory fid",
        [
            (
                NINEP_SESSION,
                """                if open.directory {
                    // A directory is enumerated with `Treaddir`, which returns
                    // records.  A byte read of one would hand the caller the
                    // host's own directory layout.
                    return Err(SessionError::FidWrongKind);
                }
""",
                "",
            )
        ],
    ),
    (
        "refusing Treaddir on a file fid",
        [
            (
                NINEP_SESSION,
                """                if !open.directory {
                    return Err(SessionError::FidWrongKind);
                }
""",
                "",
            )
        ],
    ),
    (
        "a partial walk binding nothing",
        [
            (
                NINEP_SESSION,
                """                if qids.len() < *names {
                    // A partial walk binds nothing.  The reservation is
                    // released, and `newfid` is as unused as before.
                    if *reserved {
                        self.reserved_fids.remove(newfid);
                    }
                    return Ok(());
                }
""",
                "",
            )
        ],
    ),
    (
        "refusing an Rwalk longer than its Twalk",
        [
            (
                NINEP_SESSION,
                """                if qids.len() > *names {
                    return Err(SessionError::MalformedReply);
                }
""",
                "",
            )
        ],
    ),
    (
        "the reply-type match in complete",
        [
            (
                NINEP_SESSION,
                """        if reply_for(state.message_type) != frame.message_type() {
            return Err(SessionError::UnexpectedReply);
        }
""",
                "",
            )
        ],
    ),
    (
        # The reply-type match and `apply_effect`'s catch-all mask one another:
        # with the match gone, a mismatched reply still falls through to the
        # catch-all.  Proven as a pair, and said so rather than claimed singly.
        "the reply-type match and the effect pairing together",
        [
            (
                NINEP_SESSION,
                """        if reply_for(state.message_type) != frame.message_type() {
            return Err(SessionError::UnexpectedReply);
        }
""",
                "",
            ),
            (
                NINEP_SESSION,
                """            // Every other pairing means the reply's type did not match its
            // request's, which `complete` already refused.
            _ => Err(SessionError::UnexpectedReply),""",
                """            _ => Ok(()),""",
            ),
        ],
    ),
    (
        "the Rversion msize check",
        [
            (
                NINEP_SESSION,
                """        if *msize != expected || version != DIALECT {
            return Err(SessionError::MalformedReply);
        }
""",
                "",
            )
        ],
    ),
    (
        "releasing a reservation when a request fails",
        [
            (
                NINEP_SESSION,
                "            other => self.undo_reservation(other),",
                "            other => {\n                let _ = other;\n            }",
            )
        ],
    ),
    # --- guards added by review round 2 ---------------------------------
    (
        "an Rflush matching only a flush its target actually carries",
        [
            (
                NINEP_SESSION,
                """        if !target.flushed_by.contains(&flush_tag) {
            return;
        }
""",
                "",
            )
        ],
    ),
    (
        "the last outstanding flush being the one that releases the tag",
        [
            (
                NINEP_SESSION,
                """            .filter(|candidate| *candidate != flush_tag && self.tags.contains_key(candidate))""",
                """            .filter(|candidate| *candidate != flush_tag && false)""",
            )
        ],
    ),
    (
        "every outstanding flush holding its target reserved",
        [
            (
                NINEP_SESSION,
                """        if state
            .flushed_by
            .iter()
            .any(|flush_tag| self.tags.contains_key(flush_tag))
        {""",
                """        if state
            .flushed_by
            .iter()
            .take(0)
            .any(|flush_tag| self.tags.contains_key(flush_tag))
        {""",
            )
        ],
    ),
    (
        "the fid generation on a late in-place walk",
        [
            (
                NINEP_SESSION,
                """                } else if !matches!(
                    self.fids.get(newfid),
                    Some(state) if state.generation == *origin_generation
                ) {""",
                """                } else if !self.fids.contains_key(newfid) {""",
            )
        ],
    ),
    (
        "the fid generation on a zero-element clone's origin",
        [
            (
                NINEP_SESSION,
                """                        Some(state) if state.generation == *origin_generation => state.qid,""",
                """                        Some(state) => state.qid,""",
            )
        ],
    ),
    (
        "the fid generation on a late Rlopen",
        [
            (
                NINEP_SESSION,
                """                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };
                let mut mode = *mode;""",
                """                let Some(state) = self.fids.get_mut(fid) else {
                    return Ok(());
                };
                let _ = generation;
                let mut mode = *mode;""",
            )
        ],
    ),
    (
        "the fid generation on a late Rlcreate",
        [
            (
                NINEP_SESSION,
                """                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };""",
                """                let Some(state) = self.fids.get_mut(fid) else {
                    return Ok(());
                };
                let _ = generation;""",
            )
        ],
    ),
    # --- guards added by review round 1 ----------------------------------
    (
        "the flushed request's reservation released with its tag",
        [
            (
                NINEP_SESSION,
                """        if let Some(target) = self.tags.remove(&flushed)
            && !target.answered
        {""",
                """        if let Some(target) = self.tags.remove(&flushed)
            && !target.answered
            && false
        {""",
            )
        ],
    ),
    (
        "the reservation released on every reply path",
        [
            (
                NINEP_SESSION,
                """        self.undo_reservation(&state.effect);
        self.retire_tag(frame.tag, &state);
        applied""",
                """        self.retire_tag(frame.tag, &state);
        applied""",
            )
        ],
    ),
    (
        "an in-place walk binding only a still-bound fid",
        [
            (
                NINEP_SESSION,
                """                } else if !matches!(
                    self.fids.get(newfid),
                    Some(state) if state.generation == *origin_generation
                ) {
                    // A walk in place reserves nothing, so it may bind only the
                    // **binding** it was admitted against.  Re-creating a fid
                    // clunked while the walk was outstanding would put a number
                    // back into the table that the quota had already released,
                    // and `live_fids()` could then exceed `maxFids`; moving a
                    // number the client has since re-bound to something else
                    // would leave this session's path and gate 4's descriptor
                    // for that fid disagreeing.
                    return Ok(());
                }""",
                "                }",
            )
        ],
    ),
    (
        # Defensive, and deliberately kept though no test reaches it: every
        # path that releases a reservation releases its tag in the same step,
        # so a reservation cannot vanish while its request is outstanding.
        # Listed so that fact is measured rather than assumed — the same
        # treatment gate 2's `EINTR` retry gets.
        "a reserved walk binding only a live reservation",
        [
            (
                NINEP_SESSION,
                """                    if self.reserved_fids.remove(newfid).is_none() {
                        // The reservation was released — flushed, or the
                        // request already failed — so there is nothing to bind.
                        return Ok(());
                    }""",
                "                    self.reserved_fids.remove(newfid);",
            )
        ],
    ),
    (
        "a zero-element walk whose origin is gone applying nothing",
        [
            (
                NINEP_SESSION,
                """                    match self.fids.get(origin) {
                        Some(state) if state.generation == *origin_generation => state.qid,
                        // Gone, or the number carries a different binding now:
                        // either way there is nothing left to clone.
                        _ => return Ok(()),
                    }""",
                "                    self.require_fid(*origin)?.qid",
            )
        ],
    ),
    (
        "an Rlopen for a clunked fid applying nothing",
        [
            (
                NINEP_SESSION,
                """                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };
                let mut mode = *mode;""",
                """                let state = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                    .ok_or(SessionError::UnknownFid)?;
                let mut mode = *mode;""",
            )
        ],
    ),
    (
        "an Rlcreate for a clunked fid applying nothing",
        [
            (
                NINEP_SESSION,
                """                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };
                // A create rebinds the fid to the child it made, so the number
                // now carries a new binding.""",
                """                let state = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                    .ok_or(SessionError::UnknownFid)?;""",
            )
        ],
    ),
    (
        "refusing a pipelined second Tversion",
        [
            (
                NINEP_SESSION,
                "                if self.phase != Phase::AwaitingVersion || self.pending_msize.is_some() {",
                "                if self.phase != Phase::AwaitingVersion {",
            )
        ],
    ),
    (
        "refusing a pipelined second Tattach",
        [
            (
                NINEP_SESSION,
                """                if self.attach_outstanding() {
                    return Err(SessionError::RepeatedAttach);
                }
""",
                "",
            )
        ],
    ),
    (
        "the reply byte bound on Rread and Rreaddir",
        [
            (
                NINEP_SESSION,
                """                if data.len() > *limit as usize {
                    return Err(SessionError::MalformedReply);
                }
""",
                "                let _ = limit;\n",
            )
        ],
    ),
    (
        "the reply byte bound on Rwrite",
        [
            (
                NINEP_SESSION,
                """                if count > limit {
                    return Err(SessionError::MalformedReply);
                }
""",
                "                let _ = limit;\n",
            )
        ],
    ),
    (
        "refusing an Rwalk with no qids for a nonempty Twalk",
        [
            (
                NINEP_SESSION,
                """                if qids.is_empty() && *names > 0 {""",
                """                if false && qids.is_empty() && *names > 0 {""",
            )
        ],
    ),
    (
        "the directory-entry type byte agreeing with its qid",
        [
            (
                NINEP_READDIR,
                """    if byte == expected {
        Ok(())
    } else {
        Err(CodecError::MalformedDirEntry)
    }""",
                "    let _ = (byte, expected);\n    Ok(())",
            )
        ],
    ),
    (
        "packing an entry whole or not at all",
        [
            (
                NINEP_READDIR,
                """        if out.len() + entry.encoded_len() > limit {
            break;
        }
""",
                "        let _ = limit;\n",
            )
        ],
    ),
]


@dataclass
class Suite:
    """One crate's guards and the command that measures them."""

    name: str
    crate: Path
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit]]] = field(default_factory=list)


SUITES: list[Suite] = [
    Suite("gate2", CRATE, CARGO_TEST, GATE2_CASES),
    Suite(
        "gate3",
        NINEP,
        ["cargo", "test", "-p", "tunnel-fs-ninep", "--locked"],
        GATE3_CASES,
    ),
]


def cargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def run_tests(suite: Suite) -> tuple[str, list[str]]:
    """Run one suite's crate tests and classify the outcome.

    A build that did not compile is **never** reported as a red test.  A
    deleted guard can leave the crate unbuildable — an unused import, a binding
    that is now dead — and counting that as evidence would credit the guard for
    a failure that says nothing about confinement.
    """
    try:
        done = subprocess.run(
            suite.cargo_test,
            cwd=REPO,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "RED (hung)", []
    combined = done.stdout + done.stderr
    if "error[" in combined or "error: could not compile" in combined:
        return "BUILD FAILED (not evidence)", []
    failures = sorted(
        {
            line.strip().removeprefix("test ").removesuffix(" ... FAILED")
            for line in done.stdout.splitlines()
            if line.strip().endswith("... FAILED")
        }
    )
    if done.returncode == 0:
        return "still green", []
    return "RED", failures


def restore(suite: Suite) -> None:
    subprocess.run(
        ["git", "checkout", "--", str(suite.crate.relative_to(REPO))],
        cwd=REPO,
        check=True,
    )


def require_clean_tree(suites: list[Suite]) -> None:
    for suite in suites:
        relative = str(suite.crate.relative_to(REPO))
        changed = subprocess.run(
            ["git", "status", "--porcelain", "--", relative],
            cwd=REPO,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.strip()
        if changed:
            sys.exit(
                "fs-guard-deletion: refusing to run with uncommitted changes "
                f"under {relative}; each case is restored by checking the crate "
                "out again, which would discard them."
            )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument(
        "--suite",
        help="run only this suite (gate2 or gate3); default is both",
    )
    arguments = parser.parse_args()

    suites = [
        suite
        for suite in SUITES
        if not arguments.suite or suite.name == arguments.suite
    ]
    if not suites:
        sys.exit(f"fs-guard-deletion: no suite named {arguments.suite!r}")

    selected: list[tuple[Suite, str, list[Edit]]] = [
        (suite, name, edits)
        for suite in suites
        for name, edits in suite.cases
        if not arguments.case or arguments.case in name
    ]
    if arguments.list:
        for suite, name, _ in selected:
            print(f"{suite.name}: {name}")
        return 0
    if not selected:
        sys.exit(f"fs-guard-deletion: no case matches {arguments.case!r}")

    require_clean_tree(suites)

    results: list[tuple[str, str, str, list[str]]] = []
    for suite, name, edits in selected:
        applied = True
        for path, old, new in edits:
            text = path.read_text()
            if old not in text:
                applied = False
                break
            path.write_text(text.replace(old, new, 1))
        if not applied:
            restore(suite)
            results.append((suite.name, name, "COULD NOT DELETE: guard text not found", []))
            print(f"[{suite.name}] {name}: guard text not found", flush=True)
            continue
        outcome, failures = run_tests(suite)
        restore(suite)
        results.append((suite.name, name, outcome, failures))
        print(
            f"[{suite.name}] {name}: {outcome} {failures if failures else ''}".rstrip(),
            flush=True,
        )

    print("\n=== summary ===")
    for suite_name, name, outcome, failures in results:
        detail = f" -> {', '.join(failures)}" if failures else ""
        print(f"- [{suite_name}] {name}: {outcome}{detail}")
    for suite in suites:
        rows = [row for row in results if row[0] == suite.name]
        if not rows:
            continue
        red = sum(1 for row in rows if row[2] == "RED")
        print(f"\n{suite.name}: {red} of {len(rows)} deletions turned a test red")

    unusable = [
        f"[{suite_name}] {name}"
        for suite_name, name, outcome, _ in results
        if outcome.startswith("BUILD") or outcome.startswith("COULD")
    ]
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
