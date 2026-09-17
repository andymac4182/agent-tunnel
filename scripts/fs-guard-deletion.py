#!/usr/bin/env python3
"""Delete one filesystem guard at a time, run the tests it should protect, and
restore it.

This is the red-then-green evidence behind the filesystem implementation gates
of `docs/filesystem-api.md`.  Two suites live here:

* `gate2` — the OS-confined resolver in `crates/tunnel-fs-host`.
* `gate3` — the 9P2000.L codec and session state machine in
  `crates/tunnel-fs-ninep`.
* `gate4` — the endpoint, the dispatcher and the read path, which spans four
  crates: the resolver's metadata and enumeration additions, the provider, the
  relay route and the connector's export.
* `gate5` — write grants and partial failure: the resolver's mutating
  primitives, the hard-link write rule on a real write, and the dispatcher's
  outcome ledger.
* `gate6-e2e` — the validator of the end-to-end gate that drives the real
  TypeScript client against real relay and device sockets.  The gate itself is
  a cluster run and cannot be repeated once per case, so what is measured is
  its **rule list**, against the mutation table that claims every rule of it is
  load-bearing.  Its edits replace a condition with `true` rather than remove
  it: the rules are a fixed-length array, and removing one stops the crate
  compiling, which this script refuses to call a red test.
* `gate6-adapters` — the four native SDK adapters in `packages/client`.  This
  one is **TypeScript**, so its runner is `node --test` rather than `cargo`
  and its not-evidence check is a module that failed to load rather than a
  crate that failed to build.  It needs no install: the suite is the offline
  one, which runs with `node_modules` deleted.

A guard whose deletion leaves every test green is **not** load-bearing on its
own, and this script prints that outcome rather than hiding it: several of the
resolver's guards mask one another and are red only in pairs or as a triple,
which is why those combinations are cases here in their own right, and the same
honesty applies to gate 3's.

    python3 scripts/fs-guard-deletion.py                 # every case
    python3 scripts/fs-guard-deletion.py --list          # names only
    python3 scripts/fs-guard-deletion.py --suite gate3   # one suite
    python3 scripts/fs-guard-deletion.py --suite gate6-adapters
    python3 scripts/fs-guard-deletion.py --case "32-hop" # substring filter

Exit status is 0 when every case produced a usable result, and 1 when any case
could not be applied or did not build.  **Two refusals keep the numbers honest
and neither may be removed.** Both were added after a round of this evidence
turned out to be wrong in exactly the way the refusal now prevents, and the
numbers in task rows M4-08 and M4-09 rest on them:

1. `run_tests` will not call a failed build a red test.  An early harness
   restored the crate with a checkout between runs, which also reverted an
   uncommitted cargo feature the tests needed, so three cases reported "RED"
   for a build that never compiled.
2. A case whose `old` text is **not unique** in its file is refused outright
   rather than applied to the first match.  `str.replace(old, new, 1)` edits
   whichever match comes first, so an ambiguous case deletes some *other*
   guard and reports a red for it under the wrong name.  That happened twice:
   the `Rlcreate` generation case's text was also the opening of the `Rlopen`
   arm, and the `Rflush` membership case's text appears in `cancel_flush` too.
   Both are anchored now, and the check caught the second one itself.

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

PROVIDER = REPO / "crates" / "tunnel-fs-provider"
PROVIDER_SRC = PROVIDER / "src" / "provider.rs"
PROVIDER_RECORD = PROVIDER / "src" / "record.rs"
METADATA = CRATE / "src" / "metadata.rs"
RELAY = REPO / "crates" / "tunnel-relay"
RELAY_FS = RELAY / "src" / "http" / "fs.rs"
CLIENT = REPO / "crates" / "tunnel-client"
CLIENT_FS = CLIENT / "src" / "fs_export.rs"

CLIENT_PKG = REPO / "packages" / "client"
ADAPTER_FILES = CLIENT_PKG / "src" / "adapters" / "files-sdk.ts"
ADAPTER_MASTRA = CLIENT_PKG / "src" / "adapters" / "mastra.ts"
ADAPTER_OUTCOMES = CLIENT_PKG / "src" / "adapters" / "outcomes.ts"

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

PAIR_IDENTITY: Edit = (
    NINEP_SESSION,
    """        self.tags
            .get(&flush_tag)
            .is_some_and(|state| state.flushing == Some(victim))""",
    """        let _ = victim;
        self.tags.contains_key(&flush_tag)""",
)
CANCEL_FLUSH: Edit = (
    NINEP_SESSION,
    """            if let Some(victim) = target.flushing {
                // The tag just removed was itself a `Tflush`, so removing it
                // **cancels** that flush and it must leave its own victim's
                // set — otherwise the victim keeps a member no reply will ever
                // answer.
                self.cancel_flush(victim, flushed);
            }
""",
    "",
)

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
    # --- guards added by review round 3 ---------------------------------
    (
        # Masked by the set staying accurate: with a cancelled flush removed
        # from its victim's set there is no stale number left for a reused tag
        # to be mistaken for.  Proven as a pair below, and listed singly so the
        # masking is measured rather than asserted.
        "a flush identified by its pair, not by its tag number",
        [PAIR_IDENTITY],
    ),
    (
        "a cancelled flush leaving its own victim's set",
        [CANCEL_FLUSH],
    ),
    (
        "a failed flush cancelling rather than releasing its victim",
        [
            (
                NINEP_SESSION,
                """                FlushOutcome::Cancelled => self.cancel_flush(flushed, tag),""",
                """                FlushOutcome::Cancelled => self.release_flushed(flushed, tag),""",
            )
        ],
    ),
    (
        "the pair identity and the cancelled-flush removal together",
        [PAIR_IDENTITY, CANCEL_FLUSH],
    ),
    (
        "collecting an answered tag whose only flush was cancelled",
        [
            (
                NINEP_SESSION,
                """        if !target.flushed_by.is_empty() || !answered {
            return;
        }""",
                """        if true || !target.flushed_by.is_empty() || !answered {
            return;
        }""",
            )
        ],
    ),
    (
        "the fid generation on a late Rclunk or Rremove",
        [
            (
                NINEP_SESSION,
                """        if self
            .fids
            .get(&fid)
            .is_some_and(|state| state.generation == generation)
        {
            self.fids.remove(&fid);
        }""",
                """        let _ = generation;
        self.fids.remove(&fid);""",
            )
        ],
    ),
    # --- guards added by review round 2 ---------------------------------
    (
        "an Rflush matching only a flush its target actually carries",
        [
            (
                NINEP_SESSION,
                # Anchored on the following line: the membership check itself
                # appears in `cancel_flush` too, and `require_unique` refuses
                # an ambiguous case rather than editing whichever comes first.
                """        if !target.flushed_by.contains(&flush_tag) {
            return;
        }
        let remaining = self.live_flushes_of(flushed, flush_tag);""",
                """        let remaining = self.live_flushes_of(flushed, flush_tag);""",
            )
        ],
    ),
    (
        "the last outstanding flush being the one that releases the tag",
        [
            (
                NINEP_SESSION,
                """                .filter(|candidate| {
                    *candidate != excluded && self.is_live_flush_of(*candidate, victim)
                })""",
                """                .filter(|candidate| *candidate != excluded && false)""",
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
            .any(|flush_tag| self.is_live_flush_of(*flush_tag, tag))
        {""",
                """        if state
            .flushed_by
            .iter()
            .take(0)
            .any(|flush_tag| self.is_live_flush_of(*flush_tag, tag))
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
                # Anchored on the preceding line: without it this text is also
                # the opening of the `Rlopen` arm, so the edit landed there
                # instead and this case silently measured that guard twice.
                # `require_unique` now refuses such a case outright; the anchor
                # is what makes this one measure what it names.
                """                let fresh = self.fresh_generation();
                let Some(state) = self
                    .fids
                    .get_mut(fid)
                    .filter(|state| state.generation == *generation)
                else {
                    return Ok(());
                };""",
                """                let fresh = self.fresh_generation();
                let Some(state) = self.fids.get_mut(fid) else {
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
                """            if !target.answered {
                // An `Rflush` releases the tag it flushed""",
                """            if false && !target.answered {
                // An `Rflush` releases the tag it flushed""",
            )
        ],
    ),
    (
        "the reservation released on every reply path",
        [
            (
                NINEP_SESSION,
                """        self.undo_reservation(&state.effect);
        self.retire_tag(frame.tag, &state, FlushOutcome::Answered);
        applied""",
                """        self.retire_tag(frame.tag, &state, FlushOutcome::Answered);
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


# The gate-4 suite spans four crates, so it runs their tests together.  The
# relay and the connector are large crates and each case rebuilds one of them;
# that is the cost of measuring a guard where it lives rather than asserting it
# from a distance.
GATE4_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-fs-host",
    "-p",
    "tunnel-fs-provider",
    "-p",
    "tunnel-relay",
    "-p",
    "tunnel-client",
    "--lib",
    "--tests",
]

GATE4_CASES: list[tuple[str, list[Edit]]] = [
    (
        "drop a reply whose tag was flushed",
        [
            (
                PROVIDER_SRC,
                """        if queued.flushed {
            self.stats.dropped_after_flush += 1;
            return Vec::new();
        }
""",
                "",
            )
        ],
    ),
    (
        # The mark lives on the queue **entry**, not on the tag number.  This
        # case restores the per-number set the first round shipped: a client
        # that flushes a tag, re-issues on the released number and flushes that
        # too has both requests legitimately flushed, and a mark held per number
        # can only be spent once — the second is performed and its reply closes
        # a well-behaved client's session with 1002.
        "the flush mark is per queue entry, not per tag number",
        [
            (
                PROVIDER_SRC,
                """        for queued in &mut self.queue {
            if queued.tag == oldtag {
                queued.flushed = true;
            }
        }""",
                """        if let Some(queued) = self
            .queue
            .iter_mut()
            .find(|queued| queued.tag == oldtag)
        {
            queued.flushed = true;
        }""",
            )
        ],
    ),
    (
        "close on a moved grant revision",
        [
            (
                PROVIDER_SRC,
                """        if live.revision != self.admitted_revision {
            self.stats.revision_closures += 1;
            self.close();
            return vec![Outbound::Close(SessionErrorCode::CapabilitiesChanged)];
        }
""",
                "",
            )
        ],
    ),
    (
        "close on an expired authorization snapshot",
        [
            (
                PROVIDER_SRC,
                """        if !live.fresh {
            self.stats.freshness_closures += 1;
            self.close();
            return vec![Outbound::Close(SessionErrorCode::AuthExpired)];
        }
""",
                "",
            )
        ],
    ),
    (
        "recheck each primitive against the live grant",
        [
            (
                PROVIDER_SRC,
                """        for primitive in queued.accepted.primitives.iter() {
            if !primitive.is_permitted(live.grant, self.features) {""",
                """        for primitive in queued.accepted.primitives.iter() {
            if false && !primitive.is_permitted(live.grant, self.features) {""",
            )
        ],
    ),
    (
        "re-classify Tlopen with the resolver's kind",
        [
            (
                PROVIDER_SRC,
                "        let required = open_primitives(flags, kind == FileKind::Directory)\n"
                "            .map_err(|_| FsError::refused(FsErrorCode::Enotsup))?;",
                "        let _ = kind;\n"
                "        let required = admitted;",
            )
        ],
    ),
    (
        "refuse a writing open before the host is touched",
        [
            (
                PROVIDER_SRC,
                """        if required.iter().any(|primitive| {
            matches!(
                primitive,
                Primitive::OpenWrite | Primitive::OpenTruncate | Primitive::Create
            )
        }) {
            self.stats.mutations_refused += 1;
            return Err(FsError::refused(FsErrorCode::Enotsup));
        }
""",
                "",
            )
        ],
    ),
    (
        "key the descriptor cache by fid generation",
        [
            (
                PROVIDER_SRC,
                """    fn cached(&self, fid: u32) -> Option<&OpenFid> {
        let generation = self.session.fid(fid)?.generation();
        self.open
            .get(&fid)
            .filter(|entry| entry.generation == generation)
    }""",
                """    fn cached(&self, fid: u32) -> Option<&OpenFid> {
        self.open.get(&fid)
    }""",
            )
        ],
    ),
    (
        "prune a descriptor whose binding has gone",
        [
            (
                PROVIDER_SRC,
                """        if self
            .open
            .get(&fid)
            .is_some_and(|entry| Some(entry.generation) != live)
        {
            self.open.remove(&fid);
        }""",
                "        let _ = live;",
            )
        ],
    ),
    (
        "release a descriptor only for its own generation",
        [
            (
                PROVIDER_SRC,
                """        if self
            .open
            .get(&fid)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.open.remove(&fid);
        }""",
                """        let _ = generation;
        self.open.remove(&fid);""",
            )
        ],
    ),
    (
        # All three of the descriptor cache's generation guards at once, and
        # **still green** — measured, not assumed, and the reason is worth more
        # than a red would have been.  Gate 3's session is what makes them
        # unreachable: it records a fid's open state per *binding*, refuses a
        # `Tread` on a fid it does not hold open at the current one, and applies
        # a reply only to the binding it was admitted against.  So no path can
        # consult a stale entry: the session refuses first, and an `Rlopen` for
        # a re-bound number overwrites the entry rather than reading it.  The
        # cache's keying is therefore **defence in depth behind gate 3's own
        # stamp**, which is what the obligation asked for and is not the same
        # claim as "load-bearing".
        "all three descriptor-cache generation guards, together",
        [
            (
                PROVIDER_SRC,
                """    fn cached(&self, fid: u32) -> Option<&OpenFid> {
        let generation = self.session.fid(fid)?.generation();
        self.open
            .get(&fid)
            .filter(|entry| entry.generation == generation)
    }""",
                """    fn cached(&self, fid: u32) -> Option<&OpenFid> {
        self.open.get(&fid)
    }""",
            ),
            (
                PROVIDER_SRC,
                """        if self
            .open
            .get(&fid)
            .is_some_and(|entry| Some(entry.generation) != live)
        {
            self.open.remove(&fid);
        }""",
                "        let _ = live;",
            ),
            (
                PROVIDER_SRC,
                """        if self
            .open
            .get(&fid)
            .is_some_and(|entry| entry.generation == generation)
        {
            self.open.remove(&fid);
        }""",
                """        let _ = generation;
        self.open.remove(&fid);""",
            ),
        ],
    ),
    (
        "the record decoder latches its first violation",
        [
            (
                PROVIDER_RECORD,
                """    fn latch(&mut self, error: RecordError) -> RecordError {
        self.latched = Some(error);
        self.buffer.clear();
        error
    }""",
                """    fn latch(&mut self, error: RecordError) -> RecordError {
        self.buffer.clear();
        error
    }""",
            )
        ],
    ),
    (
        "the record decoder bounds a declared length before allocating",
        [
            (
                PROVIDER_RECORD,
                """        if length > MAX_RECORD_BYTES {
            return Err(self.latch(RecordError::TooLong));
        }
""",
                "",
            )
        ],
    ),
    (
        "a close record must name a code in the vocabulary",
        [
            (
                PROVIDER_RECORD,
                """                let Some(code) = payload.first().copied().and_then(close_code) else {
                    return Err(self.latch(RecordError::MalformedClose));
                };""",
                """                let code = payload
                    .first()
                    .copied()
                    .and_then(close_code)
                    .unwrap_or(SessionErrorCode::SessionLost);""",
            )
        ],
    ),
    (
        "metadata is governed by list",
        [
            (
                METADATA,
                """    pub fn metadata(&self, path: &VirtualPath) -> Result<Metadata, FsError> {
        self.authorize(Primitive::Getattr)?;""",
                """    pub fn metadata(&self, path: &VirtualPath) -> Result<Metadata, FsError> {""",
            )
        ],
    ),
    (
        "a link is decided before the exportable-kind check",
        [
            (
                METADATA,
                """        if identity.kind() == FileKind::Symlink {""",
                """        check_exportable(identity.kind())?;
        if identity.kind() == FileKind::Symlink {""",
            )
        ],
    ),
    (
        "an unrepresentable entry name is refused, never repaired",
        [
            (
                METADATA,
                "    core::str::from_utf8(raw.to_bytes()).map_err(|_| FsError::refused(FsErrorCode::Einval))",
                r'    Ok(core::str::from_utf8(raw.to_bytes()).unwrap_or("\u{fffd}"))',
            )
        ],
    ),
    (
        "a special file is left out of a listing",
        [
            (
                METADATA,
                """            if check_exportable(identity.kind()).is_err() {
                skipped += 1;
                continue;
            }
""",
                "",
            )
        ],
    ),
    (
        "a resume cookie is bounded by the traversal budget",
        [
            (
                METADATA,
                """        if cookie > budget {
            return Err(FsError::refused(FsErrorCode::Einval));
        }
""",
                "",
            )
        ],
    ),
    (
        # Deleted by turning the refusal into a `break` rather than by removing
        # the test: removing it leaves `while self.position < cookie` spinning
        # on a reader that will never advance, and the harness reports that as
        # `RED (hung)` after a ten-minute timeout.  A hang *is* evidence the
        # guard is load-bearing, but it is expensive evidence and it names the
        # wrong failure; breaking out reaches the same conclusion in a second,
        # by letting `seek` claim success at a position the directory does not
        # have.
        "a cookie past the end of a directory is refused",
        [
            (
                METADATA,
                """                return Err(FsError::refused(FsErrorCode::Einval));
            }
        }
        Ok(())
    }""",
                """                break;
            }
        }
        Ok(())
    }""",
            )
        ],
    ),
    (
        "the relay derives each capability from its own operation",
        [
            (
                RELAY_FS,
                "        (crate::FS_LIST_OPERATION, Capability::List),\n",
                "",
            )
        ],
    ),
    (
        "a stale grant revision does not match",
        [
            (
                RELAY_FS,
                "        .is_none_or(|value| value.trim() == revision.to_string())",
                "        .is_none_or(|_| true)",
            )
        ],
    ),
    (
        "the case behaviour is parsed and never guessed",
        [
            (
                RELAY_FS,
                """        _ => None,
    }
}""",
                """        _ => Some(CaseSensitivity::Sensitive),
    }
}""",
            )
        ],
    ),
    (
        "the connector's allowlist narrows the relay's capabilities",
        [
            (
                CLIENT_FS,
                """        if left.allows(capability) && right.allows(capability) {""",
                """        if left.allows(capability) {""",
            )
        ],
    ),
    (
        "an unknown capability name is ignored, not admitted",
        [
            (
                CLIENT_FS,
                """        if let Some(capability) = Capability::parse(name.trim()) {
            set = set.with(capability);
        }""",
                """        if let Some(capability) = Capability::parse(name.trim()) {
            set = set.with(capability);
        } else if !name.trim().is_empty() {
            set = set.with(Capability::Read);
        }""",
            )
        ],
    ),
]


# The test command for gate 5.  Narrower than gate 4's: every guard below lives
# in the resolver's write module or in the dispatcher, and the tests that
# measure them are in those two crates.  The relay and the connector are
# unchanged by this gate except for the connector's settling of the mutation
# ledger, which has no unit test and is recorded as unmeasured rather than
# listed here with a green it did not earn.
GATE5_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-fs-host",
    "-p",
    "tunnel-fs-provider",
    "--features",
    # The window between a creating syscall and the identity read that follows
    # it is microseconds wide; without this hook the rule that a failure *after*
    # an effect is `unknown` could only be asserted, not measured.
    "tunnel-fs-provider/post-effect-hook",
    "--lib",
    "--tests",
    "--no-fail-fast",
]

WRITE = CRATE / "src" / "write.rs"

GATE5_CASES: list[tuple[str, list[Edit]]] = [
    (
        "a create is exclusive whatever the request asked for",
        [
            (
                WRITE,
                """                OFlags::CREATE
                    | OFlags::EXCL
                    | if readable {""",
                """                OFlags::CREATE
                    | if readable {""",
            )
        ],
    ),
    (
        "a mode outside the permission bits is refused, not masked",
        [
            (
                WRITE,
                """    if mode & !MODE_BITS_ALLOWED != 0 {
        return Err(FsError::refused(FsErrorCode::Einval));
    }
""",
                "    let mode = mode & MODE_BITS_ALLOWED;\n",
            )
        ],
    ),
    (
        # This one deletion reaches **two** pinned claims, and both are now
        # reported: the multiply-linked file becomes writable, and the
        # truncating open — which lives in its own test rather than in the
        # refusal loop — then truncates it, so the content-intact assertion
        # fails too.  An earlier round put the truncating case last inside a
        # loop, where the first iteration's panic meant it was never reached
        # and the red was credited to a different assertion entirely; the
        # suite also ran with the default fail-fast, so only the first failing
        # binary was reported.  Both are fixed, and the content assertion is
        # the only form in which "truncation happens through the descriptor
        # **after** the rule permitted it" is measurable by deletion — the
        # alternative ordering is `O_TRUNC` on the resolving open, which is a
        # different implementation rather than a deletion.
        "the hard-link write rule, and the truncation that follows it",
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
        "the hard-link rule consults the link count the descriptor reports now",
        [
            (
                WRITE,
                """        let identity = handle.current_identity()?;
        if identity.kind() == FileKind::Directory {""",
                """        let identity = handle.identity();
        if identity.kind() == FileKind::Directory {""",
            )
        ],
    ),
    (
        "a failed mutation is reported failed, not not-started",
        [
            (
                POLICY,
                """    FsError::Filesystem {
        code: code_from_errno(errno),
        outcome: Outcome::Failed,
    }
}""",
                """    host_error(errno)
}""",
            )
        ],
    ),
    (
        "an applied effect opens the ledger the connector settles",
        [
            (
                PROVIDER_SRC,
                """            // The ledger opens here and is settled by the connector. Between
            // these two points the effect has happened and the consumer has not
            // been told, which is the only window in which `unknown` is the
            // truthful answer.
            self.undelivered_effect = true;""",
                "",
            )
        ],
    ),
    (
        "a session that ends holding an effect reports it unknown",
        [
            (
                PROVIDER_SRC,
                """        self.note_effect_undelivered();
        self.session.close();""",
                "        self.session.close();",
            )
        ],
    ),
    (
        "a failure after an applied field is escalated to partial",
        [
            (
                PROVIDER_SRC,
                """    fn escalate(error: FsError, applied: bool) -> FsError {
        if !applied {
            return error;
        }""",
                """    fn escalate(error: FsError, applied: bool) -> FsError {
        if !applied || applied {
            return error;
        }""",
            )
        ],
    ),
    (
        "O_APPEND is refused because the hosts disagree about it",
        [
            (
                PROVIDER_SRC,
                """    if flags & O_APPEND == 0 {
        Ok(())
    } else {
        Err(FsError::refused(FsErrorCode::Enotsup))
    }""",
                "    let _ = flags;\n    Ok(())",
            )
        ],
    ),
    (
        "a remove decides the node's kind rather than assuming it",
        [
            (
                PROVIDER_SRC,
                "        let directory = metadata.kind() == FileKind::Directory;",
                "        let directory = false;",
            )
        ],
    ),
    (
        # **The one generation guard this gate makes load-bearing.**  Gate 4
        # measured its three descriptor-cache generation guards as green alone
        # and recorded them as defence in depth behind gate 3's own stamp; this
        # gate does not change that, because the dispatcher still performs one
        # request at a time.  What it adds is a *fourth* generation-keyed
        # decision that is not masked: `Tlcreate` rebinds its fid, so the
        # session stamps a fresh generation when the reply is applied, and a
        # descriptor filed under the generation the request arrived with is
        # immediately unreachable — the created file cannot be written through
        # the very fid that made it.
        "a created fid's descriptor is keyed by the generation the create made",
        [
            (
                PROVIDER_SRC,
                """                CacheEffect::InsertCreated(entry) => {
                    let generation = self
                        .session
                        .fid(fid)
                        .map_or(queued.generation, tunnel_fs_ninep::FidState::generation);
                    self.insert(fid, generation, entry);
                }""",
                """                CacheEffect::InsertCreated(entry) => {
                    self.insert(fid, queued.generation, entry);
                }""",
            )
        ],
    ),
    (
        # The post-effect mapping for `mkdirat`: with it gone the race answer
        # keeps its own `not_started`, and a directory that exists is reported
        # as a request that never began.
        "a mkdir that loses its identity read is unknown, not not-started",
        [
            (
                WRITE,
                """        identify_after_effect(&parent, name, FileKind::Directory)
            .and_then(|identity| check_same_device(self.identity(), identity).map(|()| identity))
            .map_err(after_effect)""",
                """        identify_after_effect(&parent, name, FileKind::Directory)
            .and_then(|identity| check_same_device(self.identity(), identity).map(|()| identity))""",
            )
        ],
    ),
    (
        "a symlink that loses its identity read is unknown, not not-started",
        [
            (
                WRITE,
                "        identify_after_effect(&parent, name, FileKind::Symlink).map_err(after_effect)",
                "        identify_after_effect(&parent, name, FileKind::Symlink)",
            )
        ],
    ),
    (
        # The effecting syscall of a size change. Routed through `host_error`
        # it reports `not_started` for a call that was made.
        "a failed ftruncate on an unopened fid is failed, not not-started",
        [
            (
                RESOLVER,
                """        // As in [`ExportRoot::open_truncate`]: the effecting syscall reports
        // `failed`, never `not_started`.
        handle.set_size(size)""",
                "        rustix::fs::ftruncate(handle.as_fd(), size).map_err(host_error)",
            )
        ],
    ),
    (
        "a rename inspects its destination as well as its source",
        [
            (
                WRITE,
                "        inspect_replaceable(&to_parent, to_name)?;\n",
                "",
            )
        ],
    ),
    (
        # The other direction from every other mode case: this one is red when
        # the file-type bits are *refused* rather than discarded, because the
        # reference client sends them on every chmod.
        "a Tsetattr mode discards the file-type bits rather than refusing them",
        [
            (
                WRITE,
                "        let mode = mode_of(mode & !MODE_TYPE_BITS)?;",
                "        let mode = mode_of(mode)?;",
            )
        ],
    ),
    (
        # The timestamp half of `Tsetattr`. Dropping the field-without-`_SET`
        # case answers `Rsetattr` for a `touch` that did not happen.
        "a timestamp field without its _SET companion is applied, not dropped",
        [
            (
                PROVIDER_SRC,
                """    if valid & explicit == 0 {""",
                """    if valid & explicit == 0 && valid == u32::MAX {""",
            )
        ],
    ),
    (
        "an applied Tsetattr field is counted partial rather than unknown",
        [
            (
                PROVIDER_SRC,
                """                Outcome::Partial => {
                    self.stats.mutations_dispatched += 1;
                    self.stats.mutations_applied += 1;
                    self.stats.mutation_partial += 1;
                    self.undelivered_effect = true;
                }""",
                """                Outcome::Partial => {
                    self.stats.mutations_dispatched += 1;
                    self.stats.mutations_applied += 1;
                    self.undelivered_effect = true;
                    self.note_effect_undelivered();
                }""",
            )
        ],
    ),
    (
        "a name-removing operation refuses a special file",
        [
            (
                WRITE,
                """    check_exportable(identity.kind())?;
    // A mount point is not this export's to remove even when its name is.
    let parent_identity = parent.current_identity()?;
    check_same_device(parent_identity, identity)""",
                """    let _ = parent;
    Ok(())""",
            )
        ],
    ),
]


# The offline suite `docs/testing.md` documents for this package — the same
# glob `npm test` runs, with the reporter swapped for TAP so a failing case can
# **name** the tests it turned red, as the cargo suites do.  (`npm test -- …`
# appends a second `--test-reporter`, which node ignores.)  It needs no install,
# so a case here cannot be reported red for a missing dependency.
GATE6_TEST = [
    "node",
    "--test",
    "--test-reporter=tap",
    "test/**/*.test.ts",
]

GATE6_CASES: list[tuple[str, list[Edit]]] = [
    (
        "list stat fan-out bounded below the tag quota",
        [
            (
                ADAPTER_FILES,
                "    Math.floor(remote.descriptor.limits.maxInflightRequests / 4),",
                "    Number.POSITIVE_INFINITY,",
            )
        ],
    ),
    (
        "a failed stat stops the rest of the fan-out",
        [
            (
                ADAPTER_OUTCOMES,
                "      if (failed) {\n        return;\n      }\n",
                "",
            )
        ],
    ),
    (
        "files-sdk upload floor",
        [
            (
                ADAPTER_FILES,
                "          throw withAppliedFloor(error, 'upload', path, applied);",
                "          throw error;",
            )
        ],
    ),
    (
        "files-sdk copy floor",
        [
            (
                ADAPTER_FILES,
                "          throw withAppliedFloor(error, 'copy', destination, applied);",
                "          throw error;",
            )
        ],
    ),
    (
        "files-sdk move floor",
        [
            (
                ADAPTER_FILES,
                "          throw withAppliedFloor(error, 'move', destination, applied);",
                "          throw error;",
            )
        ],
    ),
    (
        "a confirmed upload survives its courtesy stat",
        [
            (
                ADAPTER_FILES,
                "        } catch {\n          return result;\n        }",
                "        } catch (error) {\n          throw error;\n        }",
            )
        ],
    ),
    (
        "mastra writeFile floor",
        [
            (
                ADAPTER_MASTRA,
                "        throw withAppliedFloor(error, 'writeFile', virtual, applied);",
                "        throw error;",
            )
        ],
    ),
    (
        "mastra copyFile floor",
        [
            (
                ADAPTER_MASTRA,
                "        throw withAppliedFloor(error, 'copyFile', destination, applied);",
                "        throw error;",
            )
        ],
    ),
    (
        "mastra readdir nested names carry their subpath",
        [
            (
                ADAPTER_MASTRA,
                "          const record = toEntry(entry, `${prefix}${entry.name}`);",
                "          const record = toEntry(entry, entry.name);",
            )
        ],
    ),
    (
        "mastra readdir keeps directories under an extension filter",
        [
            (
                ADAPTER_MASTRA,
                "          if (record.type === 'directory' || matchesExtension(entry.name, extensions)) {",
                "          if (matchesExtension(entry.name, extensions)) {",
            )
        ],
    ),
    (
        "mastra readdir matches an extension by equality, not by suffix",
        [
            (
                ADAPTER_MASTRA,
                "  return extensions.some((pattern) => pattern === extension || pattern === extension.slice(1));",
                "  return extensions.some((pattern) => name.endsWith(pattern));",
            )
        ],
    ),
    (
        "mastra reduces a foreign exception to its name",
        [
            (
                ADAPTER_MASTRA,
                "      const raised = new E.FilesystemError(summarize(error), 'TUNNEL_INTERNAL', path);",
                "      return error instanceof Error ? error : new Error(String(error));\n"
                "      const raised = new E.FilesystemError(summarize(error), 'TUNNEL_INTERNAL', path);",
            )
        ],
    ),
]


HARNESS = REPO / "crates" / "tunnel-test-harness"
HARNESS_E2E = HARNESS / "src" / "production_cluster" / "fs_client_e2e.rs"

# Gate 6's end-to-end half is a **cluster** gate: it needs Redis, three relays,
# a device connector and `node`, and it takes minutes.  That is not a shape this
# script can run once per case, so what it measures here is the other half of
# what makes that gate a gate — its **validator**, and the mutation table in the
# same file that asserts every rule of it is load-bearing.  Deleting a rule must
# turn that table red, because the table's whole claim is that no rule is
# decorative; a rule whose deletion leaves it green is a rule the evidence never
# needed.
#
# The edits **replace a condition with `true`** rather than remove the tuple.
# The rule list is a fixed-length array, so removing an entry changes its length
# and the crate stops compiling — and this script refuses to call a failed build
# a red test, so such a case would measure nothing at all.
GATE6_E2E_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_client_e2e",
]

GATE6_E2E_CASES: list[tuple[str, list[Edit]]] = [
    (
        "a case the driver could not run is not a case that passed",
        [(HARNESS_E2E, "            evidence.driver_failures.is_empty(),", "            true,")],
    ),
    (
        "node could not have skipped certificate verification",
        [
            (
                HARNESS_E2E,
                '            evidence.node_tls_reject_unauthorized == "unset"\n'
                '                && evidence.probe_tls_reject_unauthorized == "unset",',
                "            true,",
            )
        ],
    ),
    (
        "an unverifiable certificate is refused by the same client",
        [
            (
                HARNESS_E2E,
                '            evidence.probe_extra_ca == "unset"\n'
                '                && evidence.probe_code == "INSECURE_ENDPOINT"\n'
                "                && !evidence.probe_retryable,",
                "            true,",
            )
        ],
    ),
    (
        "a superseded grant revision is refused at the upgrade",
        [
            (
                HARNESS_E2E,
                "            evidence.revision_upgrade_status == 409\n"
                '                && evidence.revision_upgrade_code == "CAPABILITIES_CHANGED",',
                "            true,",
            )
        ],
    ),
    (
        "the read spanned more than four messages",
        [
            (
                HARNESS_E2E,
                "            evidence.read_messages >= MIN_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "the write spanned more than four messages, each acknowledged",
        [
            (
                HARNESS_E2E,
                "            evidence.write_messages >= MIN_MESSAGES\n"
                "                && evidence.write_acknowledgements == evidence.write_messages,",
                "            true,",
            )
        ],
    ),
    (
        "a refused mutation is reported at the wire's floor and no lower",
        [
            (
                HARNESS_E2E,
                '            evidence.read_only_device_outcomes == ["failed", "failed", "failed", "not_started"],',
                "            true,",
            )
        ],
    ),
    (
        "the device applied nothing under a read-only grant",
        [
            (
                HARNESS_E2E,
                "            !evidence.read_only_device_applied_anything\n"
                "                && evidence.read_only_ledger_after.bytes_written\n"
                "                    == evidence.read_only_ledger_before.bytes_written\n"
                "                && evidence.read_only_ledger_after.mutations_dispatched\n"
                "                    == evidence.read_only_ledger_before.mutations_dispatched,",
                "            true,",
            )
        ],
    ),
    (
        "every dispatched unanswered mutation is unknown",
        [
            (
                HARNESS_E2E,
                "            evidence.unknown_requests == UNKNOWN_WRITES\n"
                "                && evidence.unknown_classified_unknown == UNKNOWN_WRITES,",
                "            true,",
            )
        ],
    ),
    (
        "the ledger reading covers exactly one exchange",
        [
            (
                HARNESS_E2E,
                "            evidence.ledger_before == DeviceLedger::default() && ledger.exchanges == 1,",
                "            true,",
            )
        ],
    ),
    (
        "the host holds exactly what the device's ledger says it wrote",
        [
            (
                HARNESS_E2E,
                "            evidence.unknown_host_matches_ledger\n"
                "                && evidence.unknown_host_pattern_matches\n"
                "                && evidence.ledger_identity_holds\n"
                "                && ledger.mutations_dispatched >= ledger.mutations_applied,",
                "            true,",
            )
        ],
    ),
    (
        "the adapter's write reached the host",
        [
            (
                HARNESS_E2E,
                "                && evidence.adapter_host_write_matches\n"
                "                && evidence.adapter_listing_names == 2",
                "                && evidence.adapter_listing_names == 2",
            )
        ],
    ),
    (
        "the driver loaded this repository's own client module",
        [
            (
                HARNESS_E2E,
                "            evidence.client_module_is_the_package && !evidence.client_module_path.is_empty(),",
                "            true,",
            )
        ],
    ),
    (
        "the session ran against the relay this gate arranged",
        [
            (
                HARNESS_E2E,
                "            !evidence.owner_node.is_empty() && evidence.owner_node == evidence.expected_owner_node,",
                "            true,",
            )
        ],
    ),
]

@dataclass
class Suite:
    """One suite's guards and the command that measures them.

    `crates` is a list because gate 4 is not one crate: it spans the resolver's
    additions, the provider, the relay route and the connector's export, and a
    guard in one of them is measured by tests in another.  Restoring after each
    case therefore checks out every crate the suite can edit.
    """

    name: str
    crates: list[Path]
    cargo_test: list[str]
    cases: list[tuple[str, list[Edit]]] = field(default_factory=list)
    #: `cargo` classifies a compile error as not-evidence; `node` classifies a
    #: module that failed to load the same way, and reads TAP rather than
    #: libtest output.  The field exists because gate 6 is TypeScript and
    #: calling a `SyntaxError` a red test would credit a guard for a failure
    #: that says nothing about behaviour.
    runner: str = "cargo"
    #: Where the command runs.  The cargo suites run at the repository root;
    #: `npm test` runs in the package.
    cwd: Path = REPO


SUITES: list[Suite] = [
    Suite("gate2", [CRATE], CARGO_TEST, GATE2_CASES),
    Suite(
        "gate3",
        [NINEP],
        ["cargo", "test", "-p", "tunnel-fs-ninep", "--locked"],
        GATE3_CASES,
    ),
    Suite("gate4", [CRATE, PROVIDER, RELAY, CLIENT], GATE4_TEST, GATE4_CASES),
    Suite("gate5", [CRATE, PROVIDER], GATE5_TEST, GATE5_CASES),
    Suite(
        "gate6-adapters",
        [CLIENT_PKG / "src"],
        GATE6_TEST,
        GATE6_CASES,
        runner="node",
        cwd=CLIENT_PKG,
    ),
    Suite("gate6-e2e", [HARNESS / "src"], GATE6_E2E_TEST, GATE6_E2E_CASES),
]


def cargo_env() -> dict[str, str]:
    env = dict(os.environ)
    env.setdefault("CARGO_PROFILE_DEV_DEBUG", "0")
    env.setdefault("CARGO_PROFILE_TEST_DEBUG", "0")
    env.setdefault("CARGO_INCREMENTAL", "0")
    return env


def run_node_tests(suite: Suite) -> tuple[str, list[str]]:
    """Run one TypeScript suite and classify the outcome.

    The same refusal as the cargo runner, in the form this runtime takes it: a
    **module that failed to load** is never reported as a red test.  Node strips
    types rather than checking them, so a deleted guard cannot produce a type
    error here — but it can produce a syntax error or leave an import
    unresolvable, and counting either as evidence would credit the guard for a
    failure that says nothing about behaviour.  A run in which no test executed
    at all is treated the same way.
    """
    try:
        done = subprocess.run(
            suite.cargo_test,
            cwd=suite.cwd,
            env=cargo_env(),
            capture_output=True,
            text=True,
            timeout=600,
        )
    except subprocess.TimeoutExpired:
        return "RED (hung)", []
    combined = done.stdout + done.stderr
    # A load failure is diagnosed from node's own machinery, not from the word
    # appearing anywhere in the run: a genuinely red test whose failure message
    # happens to quote `SyntaxError` would otherwise be withheld credit it
    # earned.  `ERR_*` codes are node's own and never appear in a passing run;
    # `SyntaxError` counts only when node names it as the failing construct.
    load_markers = ("ERR_MODULE_NOT_FOUND", "Cannot find module", "ERR_UNSUPPORTED")
    failed_to_load = any(marker in combined for marker in load_markers) or any(
        line.lstrip().startswith(("SyntaxError:", "[SyntaxError", "throw new SyntaxError"))
        for line in combined.splitlines()
    )
    if failed_to_load:
        return "MODULE FAILED TO LOAD (not evidence)", []
    if "# pass 0" in done.stdout or "# tests 0" in done.stdout:
        return "NO TEST RAN (not evidence)", []
    failures = sorted(
        {
            line.split(" - ", 1)[1].strip()
            for line in done.stdout.splitlines()
            if line.strip().startswith("not ok ") and " - " in line
        }
    )
    if done.returncode == 0:
        return "still green", []
    return "RED", failures


def run_tests(suite: Suite) -> tuple[str, list[str]]:
    """Run one suite's tests and classify the outcome.

    A build that did not compile is **never** reported as a red test.  A
    deleted guard can leave the crate unbuildable — an unused import, a binding
    that is now dead — and counting that as evidence would credit the guard for
    a failure that says nothing about confinement.
    """
    if suite.runner == "node":
        return run_node_tests(suite)
    try:
        done = subprocess.run(
            suite.cargo_test,
            cwd=suite.cwd,
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
        ["git", "checkout", "--"]
        + [str(crate.relative_to(REPO)) for crate in suite.crates],
        cwd=REPO,
        check=True,
    )


def require_clean_tree(suites: list[Suite]) -> None:
    for suite in suites:
        for crate in suite.crates:
            relative = str(crate.relative_to(REPO))
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
                    f"under {relative}; each case is restored by checking the "
                    "crate out again, which would discard them."
                )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--list", action="store_true", help="print case names and exit")
    parser.add_argument("--case", help="run only cases whose name contains this text")
    parser.add_argument(
        "--suite",
        help=(
            "run only this suite (gate2, gate3, gate4, gate5 or "
            "gate6-adapters); default is all"
        ),
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
        problem = None
        for path, old, new in edits:
            text = path.read_text()
            occurrences = text.count(old)
            if occurrences == 0:
                problem = "guard text not found"
                break
            if occurrences > 1:
                # Refusing is the whole point: `str.replace(old, new, 1)` would
                # silently edit the FIRST match, so a case whose text is not
                # unique measures some other guard — and reports a red for it
                # under this case's name.  That happened: the `Rlcreate`
                # generation case's text was also the opening of the `Rlopen`
                # arm, so it deleted the `Rlopen` guard a second time and the
                # real `Rlcreate` guard had never been deleted at all.  A count
                # inflated that way is false evidence, and false evidence is
                # worse than a missing case.
                problem = f"guard text is ambiguous: {occurrences} occurrences"
                break
            path.write_text(text.replace(old, new, 1))
        if problem is not None:
            restore(suite)
            results.append((suite.name, name, f"COULD NOT DELETE: {problem}", []))
            print(f"[{suite.name}] {name}: {problem}", flush=True)
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

    # Every "not evidence" outcome must reach this list, or a suite whose cases
    # all failed to build would exit 0 and read as a clean run.  The node
    # runner's two spellings are here for that reason: an earlier version left
    # them out and a deliberately broken case exited 0.
    unusable = [
        f"[{suite_name}] {name}"
        for suite_name, name, outcome, _ in results
        if outcome.startswith(("BUILD", "COULD", "MODULE", "NO TEST"))
    ]
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
