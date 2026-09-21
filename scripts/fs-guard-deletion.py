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
* `gate7-rotation` — the validator of the gate that carries a live 9P session
  across a real scheduled data-socket rotation.  Measured the same way as
  `gate6-e2e`, and for the same reason: the gate is a cluster run.
* `gate9-epoch-change` — the validator of the gate that holds a 9P session
  across a real control-epoch change with a request outstanding.
* `gate8-consumer-loss` — the validator of the gate that loses a 9P consumer
  with a request outstanding and then proves a replacement session restores no
  fids.  Measured the same way, and for the same reason.
* `gate10-process-restart` — the validator of the gate that holds a 9P
  mutation outstanding while the connector's real process is killed, and reads
  the effect count back out of a journal that outlives it.
* `gate13-write-restart` — the validator of the gate that holds a **`Twrite`**
  outstanding while the connector's real process is killed, and classifies the
  bytes it left behind from the export's own host file.  Its region predicate
  admits a **torn** write, which the contract permits and gate 10's
  directory-entry effect cannot express.
* `gate11-data-recovery` — the validator of the gate that holds a 9P read
  outstanding while the device's data socket is destroyed at the transport and
  the product's own retained recovery replaces it.  Measured the same way, and
  for the same reason.

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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from guard_outcomes import unusable as unusable_outcomes  # noqa: E402

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
RELAY_ACTOR = RELAY / "src" / "actor.rs"
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
        # Re-anchored by task row **M4-18**.  The rule is unchanged and the
        # guard was never lost: `ExportRoot::open_for_size_change_with` still
        # takes the grant decision before it resolves anything, so a caller
        # without the primitive is refused before a single component of the
        # path is opened.  What moved was the *line beneath it*: gates 4 and 5
        # generalised `self.resolve(path, Intent::Write)?` to
        # `self.resolve(path, intent)?` so one helper could serve `OpenWrite`,
        # `OpenTruncate`, `SetattrSize` and the read-write open.  The case's
        # pinned text stopped matching and the script refused to apply it,
        # which is exactly what it should do — an unapplied edit is not a
        # result.  The anchor is the current spelling; the deletion is the same
        # deletion it always was.
        "grant check before resolution",
        [
            (
                RESOLVER,
                """        self.authorize(primitive)?;
        let handle = self.resolve(path, intent)?;""",
                "        let handle = self.resolve(path, intent)?;",
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
        # Re-aimed by task row **M4-18**, which is a different act from the
        # re-anchoring above and is recorded as one.
        #
        # This case used to delete gate 4's blanket refusal of `OpenWrite`,
        # `OpenTruncate` and `Create` before the host was touched.  Gate 5
        # **implemented** those writes and removed that block on purpose, so
        # the old text is gone by design: the case was obsolete, not stale, and
        # re-anchoring it was impossible because the rule it deleted no longer
        # exists.
        #
        # What survives of gate 4's claim is the accounting, and
        # `ProviderStats::mutations_refused` says so in its own words: "Every
        # one of these is `Outcome::NotStarted`, which is the claim gate 4
        # could make about *every* refusal it produced and gate 5 can no
        # longer."  The rule now is that a refusal taken **before** the
        # effecting syscall is counted as a refusal and never as a dispatched
        # failure — the distinction that lets a consumer tell "the host was
        # never asked" from "the host was asked and changed nothing".
        #
        # The arm is emptied rather than removed, because `error.outcome()` is
        # matched exhaustively and a missing arm would not compile, and a build
        # failure is not evidence.  Its sibling — gate 5's "a failed mutation
        # is reported failed, not not-started" — defeats the `Outcome::Failed`
        # arm; this one defeats the `NotStarted` arm, which had no case at all
        # until now.
        "a refusal before the host is counted not-started, never dispatched",
        [
            (
                PROVIDER_SRC,
                "                Outcome::NotStarted => self.stats.mutations_refused += 1,",
                "                Outcome::NotStarted => {}",
            )
        ],
    ),
    (
        # Task row **M4-16**.  The sibling above counts a mutation refused
        # *after* the queue wait; this one counts a mutation refused at
        # **admission**, by gate 3's session inside `Provider::accept`, which
        # is where every capability refusal under a read-only grant is taken.
        # Deleting it restores the defect exactly: the ledger reads zero while
        # an export is being hammered by an unauthorized consumer.
        "a mutation refused at admission is counted",
        [
            (
                PROVIDER_SRC,
                """        if self
            .session
            .required_primitives(frame)
            .is_some_and(|primitives| primitives.iter().any(Primitive::is_mutating))
        {
            self.stats.mutations_refused += 1;
        }""",
                "        let _ = frame;",
            )
        ],
    ),
    (
        # The other half of M4-16, and the one a naive fix fails.  Counting
        # every classifiable refusal — rather than only the refusals whose
        # decoded primitives are mutating — reads `Tlopen` by opcode, and a
        # `Tlopen` carrying `O_WRONLY` alone destroys nothing.  The rule is
        # gate 5's own `Primitive::is_mutating`, and this defeats it while
        # leaving the counter moving, so only the cases that assert a
        # *non*-mutating refusal is **not** counted can catch it.
        # The substitution widens the predicate to "classified at all", which
        # is broader than the naive opcode fix rather than equal to it -- it
        # subsumes that fix, so reddening under it is the stronger signal, but
        # the name promises something narrower than the mutation actually is.
        "an admission refusal is classified from its primitives, not its opcode",
        [
            (
                PROVIDER_SRC,
                """            .required_primitives(frame)
            .is_some_and(|primitives| primitives.iter().any(Primitive::is_mutating))""",
                """            .required_primitives(frame)
            .is_some()""",
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
    # M4-25.  The contract requires an authorization invalidation to close the
    # consumer session with 1008, and the consumer learns that code from the
    # stream's reset watch alone: once `invalidate_stream_challenge` cancels
    # the registration, the connector's own RESET can never be delivered in
    # order.  Deleting the publication leaves `pump` exiting through
    # `closed.cancelled()` with nothing to map and the socket closing
    # codeless -- which is exactly what `verify-m4-fs-real-path` measured as
    # `revoked_session_close_code=None` before this fix.
    (
        "publish the authorization reset before cancelling the consumer",
        [
            (
                RELAY_ACTOR,
                """            let publishes_invalidation = matches!(
                reason,
                "authorization expired" | "authorization changed" | "grant unavailable"
            );
            let discarded = if publishes_invalidation {
                stream.http.as_mut().map_or(0, |http| {
                    http.accept_reset(tunnel_protocol::reset_reason::AUTHORIZATION_EXPIRED)
                })
            } else {
                0
            };
            release_m2_bytes(&session.queue_budget, stream, discarded);
""",
                "",
            )
        ],
    ),
    # The other half of the same rule: `accept_reset` discards the stream's
    # undelivered device->owner bytes, and their charge is the caller's to
    # return.  Dropping the release leaks the session queue budget for the
    # session's whole life, which is a slow denial of service rather than a
    # wrong close code -- so it needs its own case, because the close-code
    # guard above stays green without it.
    # M4-25, the half review caught: only the three reasons that are the
    # authority *answering* that the authorization is gone may publish a
    # reset.  The others are failures to reach an authority -- a catalog read
    # that returned Err, a control send that failed, a challenge mismatch --
    # and closing the consumer 1008 for those tells it its grant is dead and
    # to stop retrying, turning a transient outage into a revocation.
    # Deleting the gate is the regression this stack briefly shipped, so it
    # gets a case of its own.
    (
        "publish a reset only for an invalidation, never for an unavailable authority",
        [
            (
                RELAY_ACTOR,
                """            let publishes_invalidation = matches!(
                reason,
                "authorization expired" | "authorization changed" | "grant unavailable"
            );""",
                "            let publishes_invalidation = true;",
            )
        ],
    ),
    (
        "return the bytes the invalidation discarded to the session budget",
        [
            (
                RELAY_ACTOR,
                "            release_m2_bytes(&session.queue_budget, stream, discarded);",
                "            let _ = discarded;",
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
HARNESS_ROTATION = HARNESS / "src" / "production_cluster" / "fs_rotation.rs"
HARNESS_LOSS = HARNESS / "src" / "production_cluster" / "fs_consumer_loss.rs"
HARNESS_EPOCH = HARNESS / "src" / "production_cluster" / "fs_epoch_change.rs"
HARNESS_RESTART = HARNESS / "src" / "production_cluster" / "fs_process_restart.rs"
HARNESS_RECOVERY = HARNESS / "src" / "production_cluster" / "fs_data_recovery.rs"
HARNESS_ROTATION_WRITE = (
    HARNESS / "src" / "production_cluster" / "fs_rotation_write.rs"
)
HARNESS_WRITE_RESTART = (
    HARNESS / "src" / "production_cluster" / "fs_write_restart.rs"
)

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
    "production_cluster::fs_client_e2e::",
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

#: Cases whose **green result is the documented finding**, not a lost guard.
#:
#: This is the exact analogue of `scripts/acp-guard-deletion.py`'s
#: `expect_build_failure`: a third kind of evidence that is reported on its own
#: line and never counted in a red total, because it is not a red test and must
#: not inflate one.
#:
#: A case belongs here only when the suite already argues, in the case's own
#: comment, *why* nothing can go red -- that the rule is defence in depth
#: behind a guard that refuses first.  "It did not go red and I am not sure
#: why" is a stale case (M4-18), which is a different thing and must not be
#: hidden here.
#:
#: A case in this set that **does** go red is an unusable outcome, not a
#: success: it would mean the rule became load-bearing and the comment
#: explaining the green is now wrong.
#: Every entry here must be traceable to a written reason.  The gate-4 five are
#: the five that task row **M4-11** already records and explains, in those
#: words: "the descriptor cache's three generation guards are green
#: individually **and as a triple**, because gate 3's session is already
#: authoritative about a fid's open state per binding and refuses every path
#: that could reach a stale entry ... and the `Treaddir` resume budget answers
#: the same code as the end-of-directory refusal beside it, so no test can tell
#: them apart".
#:
#: They are listed here, rather than left to the row, so the harness's exit
#: status agrees with the row: before this, five documented findings and one
#: real defect all produced the same non-zero exit for different reasons.
EXPECT_GREEN: frozenset[str] = frozenset(
    {
        # The descriptor cache's generation keying, individually and as a
        # triple.  Gate 3's session refuses a `Tread` on a fid it does not hold
        # open at the current binding, so no path can reach a stale entry; the
        # keying is defence in depth behind that stamp.  The combined case
        # carries the full argument in its own comment in GATE4_CASES.
        "key the descriptor cache by fid generation",
        "prune a descriptor whose binding has gone",
        "release a descriptor only for its own generation",
        "all three descriptor-cache generation guards, together",
        # The `Treaddir` resume budget answers the same error code as the
        # end-of-directory refusal beside it, so no test can distinguish them;
        # what it bounds is the *work* a resume may demand, not the answer.
        "a resume cookie is bounded by the traversal budget",
        # gate12's two, on gate7's recorded precedent and for its reason: the
        # composite in-flight rule beside each of these already subsumes it,
        # because `exchange_in_flight_at_freeze()` is false unless
        # `attempt_active` is set **and** the phase is one of `FROZEN_PHASES`.
        # Both are kept because they name the violated condition precisely
        # when a run fails, which a composite cannot.
        "a rotation attempt was active when the owner was sampled for the write",
        "a rotation attempt was active when the owner was sampled for the flush",
        # gate8, gate9 **and gate10**, which share this case name because they
        # share the construction.  The composite in-flight rule beside it already
        # subsumes this one: `request_outstanding_at_loss()` — and gate 9's
        # `request_outstanding_at_change()` — is false unless the emit cursor
        # advanced **and** the receive cursor did not, so the composite
        # rejects the very mutation this rule would have caught.  It is kept
        # because it names the violated condition precisely when a run fails,
        # and the predicate's own clause is held directly by the two cases
        # that defeat the predicate itself, which all three suites carry.
        "the relay had dispatched a record toward the device",
        # gate10's spelling of the same rule.  Its composite,
        # `request_outstanding_at_kill()`, subsumes it for the same reason, and
        # `the_in_flight_predicate_needs_both_halves` defeats the predicate in
        # each direction directly.
        "the relay had dispatched a 9P record toward the device when the process was killed",
        # gate11's spelling of the same rule.  Its composite,
        # `request_outstanding_at_failure()`, subsumes it for the same reason,
        # and `the_in_flight_predicate_needs_both_halves` defeats the predicate
        # in each direction directly.
        "the relay had dispatched a 9P record toward the device when the data socket failed",
        # gate2.  Task row **M4-08** explains all nine in those words: "each
        # `O_NOFOLLOW` and its sibling identity check mask one another and are
        # proven in pairs, and the three mount-boundary checks mask one another
        # and are proven as a triple", the two special-file checks likewise
        # being proven "as a pair", and "`EINTR` retry has no test at all".
        # The row also says which single window guard *is* load-bearing — the
        # **file** post-open identity comparison — and that one is red, which
        # is the check that this set is not simply swallowing the group.
        "mount boundary after the directory open",
        "mount boundary before the directory open",
        "mount boundary before the file open",
        "special-file refusal before the open",
        "special-file refusal on the descriptor",
        "O_NOFOLLOW on a directory component",
        "O_NOFOLLOW on the final file open",
        "post-open identity check on a directory",
        # No test reaches it at all, stated plainly in M4-08 and listed here so
        # that fact is measured rather than assumed -- the treatment gate3's
        # reserved-walk case explicitly cites as "the same treatment gate 2's
        # `EINTR` retry gets".
        "EINTR retried rather than reported",
        # gate3.  Both already carry their reason in their own case comment
        # above: the flush guard is masked by the set staying accurate and is
        # proven as a pair, and the reserved-walk guard is defensive and
        # deliberately kept though no test reaches it, "listed so that fact is
        # measured rather than assumed".
        "a flush identified by its pair, not by its tag number",
        "a reserved walk binding only a live reservation",
        # gate3.  These two were first left out of this set on the grounds that
        # they "carry no written explanation anywhere".  That was wrong about
        # the first and incomplete about the second, and review caught it.
        #
        # The reply-type match is explained four lines below its own case, by
        # the pair case that follows it: "The reply-type match and
        # `apply_effect`'s catch-all mask one another: with the match gone, a
        # mismatched reply still falls through to the catch-all.  Proven as a
        # pair."  That is the same shape the flush case above is marked on, so
        # refusing this one was an inconsistency, not caution.
        "the reply-type match in complete",
        # The count check has no prose reason, but the fact is one read away and
        # was verified rather than inferred: `read_counted`
        # (`crates/tunnel-fs-ninep/src/message.rs:1033-1039`) pre-checks
        # `count > reader.remaining()` and then calls `reader.raw(count)`, which
        # delegates to `Reader::take` (`wire.rs:161-168`) -- and `take` returns
        # the identical `CodecError::TruncatedBody` on a short body.  The
        # pre-check is provably defence in depth, so its green is a documented
        # green like the others; the citation is the code rather than a row.
        "the count check before a counted payload is copied",
        # The two gate-7 freeze-sample guards.  `verify-m4-fs-rotation`
        # asserts the in-flight condition as a **composite**: at a frozen
        # phase, with a rotation attempt active, the connector's immutable
        # fence for the filesystem stream exceeds that stream's contiguous
        # receive cursor.  The composite rule already requires both
        # conjuncts, so deleting either one alone leaves the composite
        # asserting it and nothing can go red.  That is defence in depth
        # behind a guard that refuses first, which is exactly what this set
        # is for -- and it is why the honest word for these two is
        # **documented green**, not "unusable": the guards were successfully
        # deleted and nothing went red, which is a finding about the rules
        # and not an infrastructure refusal.
        #
        # If either is ever wanted as an independent rule, narrow it so it
        # reddens alone rather than leaving it here.
        "the owner was actually frozen when it was sampled",
        "a rotation attempt was active at the sample",
    }
)


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


# `gate7-rotation` — the validator of the gate that carries a live 9P session
# across a real scheduled data-socket rotation.  Like `gate6-e2e` this is a
# cluster run that cannot be repeated once per case, so what is measured is its
# **rule list** against the mutation table in the same file.  The edits replace
# a condition with `true` for the same reason: the rule list is a fixed-length
# array and removing an entry stops the crate compiling, which this script
# refuses to call a red test.
#
# The first three cases are the ones that matter most.  This gate's whole claim
# is that the rotation was **concurrent** with a 9P exchange rather than
# sequential with it, and that the *operation* survived rather than merely the
# session.  A rule whose deletion leaves the table green would be a rule the
# claim never rested on.
#
# **Two of the twenty-one are masked, and this says so rather than hiding it.**
# Both are declared in `EXPECT_GREEN` above, which is the mechanism for exactly
# this claim: their green is the documented finding, so the suite reports them
# on their own line and exits 0 rather than treating a defeated-but-green guard
# as an unusable outcome.
# "the owner was actually frozen when it was sampled" and "a rotation attempt
# was active at the sample" are each **still green** when defeated alone, at
# 19 of 21 red.  They are not load-bearing on their own because the composite
# rule above them already subsumes both: `exchange_in_flight_at_freeze()`
# returns false unless `attempt_active` is set **and** the phase is one of
# `FROZEN_PHASES`, so the composite rejects every mutation these two would
# have caught.  They are kept because they name the violated condition
# precisely when a run fails, which a composite cannot; the two cases below
# that defeat the predicate's own clauses are what hold those conditions.
GATE7_ROTATION_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    # The trailing `::` is load-bearing: without it this filter is a
    # **prefix** of `production_cluster::fs_rotation_write`, so gate 12's six
    # cases were also selected by gate 7's suite.  That is the ambiguity this
    # script refuses at the level of guard *text*, arriving one level up at
    # the level of the test *filter*: a gate must measure its own rules.
    #
    # **Every module filter in this file carries the `::` for that reason, not
    # only this one.**  Only this filter had an actual collision; the others
    # were one module name away from the same defect, and the next module named
    # as an extension of an existing one would have re-created it silently.
    # `every_module_filter_is_anchored` holds the rule so it cannot rot back.
    "production_cluster::fs_rotation::",
]

GATE7_ROTATION_CASES: list[tuple[str, list[Edit]]] = [
    (
        "the rotation was concurrent with the exchange, not merely nearby",
        [
            (
                HARNESS_ROTATION,
                "            evidence.exchange_in_flight_at_freeze"
                " && evidence.freeze.exchange_in_flight_at_freeze(),",
                "            true,",
            )
        ],
    ),
    (
        "the owner was actually frozen when it was sampled",
        [
            (
                HARNESS_ROTATION,
                "            FROZEN_PHASES.contains(&evidence.freeze.phase.as_str()),",
                "            true,",
            )
        ],
    ),
    (
        "a rotation attempt was active at the sample",
        [
            (
                HARNESS_ROTATION,
                "            evidence.freeze.attempt_active,",
                "            true,",
            )
        ],
    ),
    (
        "the held reply carried the tag that was outstanding across the freeze",
        [
            (
                HARNESS_ROTATION,
                "            evidence.held_reply_tag_matched,",
                "            true,",
            )
        ],
    ),
    (
        "the held reply was an Rread rather than an error",
        [
            (
                HARNESS_ROTATION,
                "            evidence.held_reply_was_rread,",
                "            true,",
            )
        ],
    ),
    (
        "the transfer spanning the rotation delivered every byte exactly once",
        [
            (
                HARNESS_ROTATION,
                "            evidence.transfer_bytes == evidence.transfer_expected_bytes\n"
                "                && evidence.transfer_expected_bytes == ROTATION_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "the transfer's checksum matched",
        [
            (
                HARNESS_ROTATION,
                "            evidence.transfer_checksum_matches,",
                "            true,",
            )
        ],
    ),
    (
        "the transfer spanned many Rread messages rather than one",
        [
            (
                HARNESS_ROTATION,
                "            evidence.transfer_messages >= MIN_READ_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "a scheduled rotation actually completed",
        [
            (
                HARNESS_ROTATION,
                "            evidence.rotations_completed_after > evidence.rotations_completed_before,",
                "            true,",
            )
        ],
    ),
    (
        "the active data generation advanced",
        [
            (
                HARNESS_ROTATION,
                "            evidence.generation_after > evidence.generation_before,",
                "            true,",
            )
        ],
    ),
    (
        "a clean rotation replayed no frames",
        [
            (
                HARNESS_ROTATION,
                "            evidence.total_replayed_frames == 0,",
                "            true,",
            )
        ],
    ),
    (
        "the rotation was not forced into recovery",
        [
            (
                HARNESS_ROTATION,
                "            !evidence.deadline_forced_retirement"
                " && evidence.rotation_recovery_reason.is_none(),",
                "            true,",
            )
        ],
    ),
    (
        "the same-owner contract: the session identity was unchanged",
        [
            (
                HARNESS_ROTATION,
                "            evidence.session_id_stable,",
                "            true,",
            )
        ],
    ),
    (
        "the same-owner contract: the epoch was unchanged",
        [
            (HARNESS_ROTATION, "            evidence.epoch_stable,", "            true,")
        ],
    ),
    (
        "the fid opened before the rotation still answered after it",
        [
            (
                HARNESS_ROTATION,
                "            evidence.fid_survived_getattr,",
                "            true,",
            )
        ],
    ),
    (
        "that fid still named the same file",
        [
            (
                HARNESS_ROTATION,
                "            evidence.fid_survived_getattr_size == ROTATION_FILE_BYTES as u64,",
                "            true,",
            )
        ],
    ),
    (
        "the attach fid established before the rotation still walked after it",
        [
            (
                HARNESS_ROTATION,
                "            evidence.attach_fid_survived_walk,",
                "            true,",
            )
        ],
    ),
    (
        "the relay did not reconstruct the session: exactly one Tattach",
        [
            (
                HARNESS_ROTATION,
                "            evidence.attach_count == 1,",
                "            true,",
            )
        ],
    ),
    (
        "a tag allocated after the rotation correlated correctly",
        [
            (
                HARNESS_ROTATION,
                "            evidence.post_rotation_tag_correlated,",
                "            true,",
            )
        ],
    ),
    (
        "the in-flight predicate requires an unreceived record",
        [
            (
                HARNESS_ROTATION,
                "            && self\n"
                "                .connector_fence\n"
                "                .is_some_and(|fence| fence > self.relay_recv_contiguous)",
                "",
            )
        ],
    ),
    (
        "the in-flight predicate requires a frozen phase",
        [
            (
                HARNESS_ROTATION,
                "            && FROZEN_PHASES.contains(&self.phase.as_str())",
                "",
            )
        ],
    ),
]

# `gate8-consumer-loss` — the validator of the gate that loses a 9P consumer
# with a request outstanding.  Like `gate6-e2e` and `gate7-rotation` this is a
# cluster run that cannot be repeated once per case, so what is measured is its
# **rule list** against the mutation table in the same file.  The edits replace
# a condition with `true` for the same reason: the rule list is a fixed-length
# array and removing an entry stops the crate compiling, which this script
# refuses to call a red test.
#
# This gate's claim has three parts, and the cases are ordered by them.  First,
# that the loss was **concurrent** with a 9P exchange rather than sequential
# with it.  Second, that the session was **cleaned up** — the lost stream gone,
# the device's own session untouched.  Third, and the part the contract turns
# on, that a replacement session **restores no fids**: `docs/protocol.md` says
# the first filesystem profile restores no fids across a consumer WebSocket
# reconnect, so a rule whose deletion leaves the table green would be a rule
# that clause never rested on.
#
# **One of the twenty-three is masked, and this says so rather than hiding it.**
# "the relay had dispatched a record toward the device" is **still green** when
# defeated alone, at 22 of 23 red.  It is not load-bearing on its own because
# the composite rule below it already subsumes it:
# `request_outstanding_at_loss()` returns false unless `emitted_at_loss >
# emitted_before` **and** the receive cursor is unmoved, so the composite
# rejects the very mutation this rule would have caught.  It is kept because it
# names the violated condition precisely when a run fails, which a composite
# cannot; the predicate's own unit test holds that clause directly.  It is
# declared in `EXPECT_GREEN` above, which is the mechanism for exactly this
# claim, so the suite reports it on its own line and exits 0 rather than
# treating a defeated-but-green guard as an unusable outcome.
GATE8_LOSS_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_consumer_loss::",
]

GATE8_LOSS_CASES: list[tuple[str, list[Edit]]] = [
    # 1. The concurrency claim.
    (
        "the loss was concurrent with the exchange, not merely nearby",
        [
            (
                HARNESS_LOSS,
                "            evidence.request_outstanding_at_loss"
                " && evidence.loss.request_outstanding_at_loss(),",
                "            true,",
            )
        ],
    ),
    (
        "the relay had dispatched a record toward the device",
        [
            (
                HARNESS_LOSS,
                "            evidence.loss.emitted_at_loss > evidence.loss.emitted_before,",
                "            true,",
            )
        ],
    ),
    (
        "the predicate requires the request to have been dispatched",
        [
            (
                HARNESS_LOSS,
                "        self.emitted_at_loss > self.emitted_before",
                "        true",
            )
        ],
    ),
    (
        "the predicate requires no answer to have been received",
        [
            (
                HARNESS_LOSS,
                "            && self.recv_contiguous_at_loss == self.recv_contiguous_before",
                "",
            )
        ],
    ),
    (
        "a stream was identified at the loss",
        [(HARNESS_LOSS, "            evidence.loss.stream_id > 0,", "            true,")],
    ),
    (
        "the fid served a real read before anything was perturbed",
        [(HARNESS_LOSS, "            evidence.prefix_bytes > 0,", "            true,")],
    ),
    # 2. Session cleanup.
    (
        "the lost consumer's stream was deregistered",
        [
            (
                HARNESS_LOSS,
                "            evidence.lost_stream_deregistered,",
                "            true,",
            )
        ],
    ),
    (
        "the device's own session survived the loss of one consumer",
        [
            (
                HARNESS_LOSS,
                "            evidence.device_session_survived,",
                "            true,",
            )
        ],
    ),
    (
        "the device session kept its identity",
        [(HARNESS_LOSS, "            evidence.session_id_stable,", "            true,")],
    ),
    (
        "losing a consumer did not change the epoch",
        [
            (
                HARNESS_LOSS,
                "            evidence.epoch_after == evidence.epoch_before,",
                "            true,",
            )
        ],
    ),
    # 3. The contract clause: no fid is restored across a consumer reconnect.
    (
        "a pre-attach probe was closed rather than served",
        [
            (
                HARNESS_LOSS,
                "            !evidence.pre_attach_probe_answered,",
                "            true,",
            )
        ],
    ),
    (
        "that close was the profile's protocol violation",
        [
            (
                HARNESS_LOSS,
                "            evidence.pre_attach_probe_close_code"
                " == Some(PROTOCOL_VIOLATION_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session reached 9P on its own terms",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_msize > 0"
                " && evidence.second_session_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the lost session's file fid was not restored",
        [
            (
                HARNESS_LOSS,
                "            evidence.stale_file_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the file fid was refused as a fid this session does not hold",
        [
            (
                HARNESS_LOSS,
                "            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the lost session's attach fid was not restored",
        [
            (
                HARNESS_LOSS,
                "            evidence.stale_attach_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the attach fid was refused as a fid this session does not hold",
        [
            (
                HARNESS_LOSS,
                "            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session established its own root",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_attached,",
                "            true,",
            )
        ],
    ),
    # The export is undamaged, so the refusals above are fid scoping.
    (
        "the replacement session read the whole file back",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_bytes == evidence.second_session_expected_bytes\n"
                "                && evidence.second_session_expected_bytes == LOSS_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer's checksum matched",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_checksum_matches,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer spanned many messages",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_messages >= MIN_READ_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "the file was undamaged by the lost session",
        [
            (
                HARNESS_LOSS,
                "            evidence.second_session_getattr_size == LOSS_FILE_BYTES as u64,",
                "            true,",
            )
        ],
    ),
    (
        "each session attached exactly once",
        [(HARNESS_LOSS, "            evidence.attach_count == 2,", "            true,")],
    ),
]

# ---------------------------------------------------------------------------
# `gate9-epoch-change` — the validator of the gate that holds a 9P session
# across a real control-epoch change with a request outstanding.  Like
# `gate7-rotation` and `gate8-consumer-loss` this is a harness-side validator,
# so each case defeats one rule and the suite's own unit tests must go red.
#
# Two rules here have no counterpart in gate 8 and are the reason this gate
# exists as its own suite rather than as a case inside that one:
#
#   * the **epoch** rules, which are what make the event an epoch change at
#     all rather than a connector that happened to restart; and
#   * "the pending call was failed explicitly", which gate 8 could not test
#     because its consumer was gone and had nobody to be failed to.
# ---------------------------------------------------------------------------

GATE9_EPOCH_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_epoch_change::",
]

GATE9_EPOCH_CASES: list[tuple[str, list[Edit]]] = [
    # 1. The concurrency claim.
    (
        "the change was concurrent with the exchange, not merely nearby",
        [
            (
                HARNESS_EPOCH,
                "            evidence.request_outstanding_at_change\n"
                "                && evidence.change.request_outstanding_at_change(),",
                "            true,",
            )
        ],
    ),
    (
        "the relay had dispatched a record toward the device",
        [
            (
                HARNESS_EPOCH,
                "            evidence.change.emitted_at_change"
                " > evidence.change.emitted_before,",
                "            true,",
            )
        ],
    ),
    (
        "a stream was identified for the held exchange",
        [
            (
                HARNESS_EPOCH,
                "            evidence.change.stream_id > 0,",
                "            true,",
            )
        ],
    ),
    # 2. The event itself.  A gate that did not hold these would prove only
    #    that a connector restarted near a filesystem session.
    (
        "the owner claim took a strictly greater epoch",
        [
            (
                HARNESS_EPOCH,
                "            evidence.epoch_after > evidence.epoch_before,",
                "            true,",
            )
        ],
    ),
    (
        "an epoch was actually observed before the change",
        [
            (
                HARNESS_EPOCH,
                "            evidence.epoch_before > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the device session identity changed",
        [
            (
                HARNESS_EPOCH,
                "            !evidence.session_id_before.is_empty()\n"
                "                && !evidence.session_id_after.is_empty()\n"
                "                && evidence.session_id_before != evidence.session_id_after,",
                "            true,",
            )
        ],
    ),
    (
        "the device itself was told a strictly greater epoch",
        [
            (
                HARNESS_EPOCH,
                "            evidence.device_epoch_after > evidence.device_epoch_before\n"
                "                && evidence.device_epoch_before > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the device's own view agrees with the catalog's",
        [
            (
                HARNESS_EPOCH,
                "            evidence.device_epoch_after == evidence.epoch_after,",
                "            true,",
            )
        ],
    ),
    (
        "the owner was released between the two connectors",
        [
            (
                HARNESS_EPOCH,
                "            evidence.owner_released_between,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement connector reached active",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_connector_active,",
                "            true,",
            )
        ],
    ),
    # 3. The clause's own obligation: fail pending calls explicitly.  This is
    #    the rule M4-28 was found by; without these three a codeless close
    #    would pass again.
    (
        "the pending call was failed explicitly rather than left hanging",
        [
            (
                HARNESS_EPOCH,
                "            evidence.pending_call_closed,",
                "            true,",
            )
        ],
    ),
    (
        "that failure carried the profile's close code",
        [
            (
                HARNESS_EPOCH,
                "            evidence.pending_call_close_code == Some(DEVICE_GONE_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "the held Tread was not answered across the epoch change",
        [
            (
                HARNESS_EPOCH,
                "            !evidence.pending_call_answered,",
                "            true,",
            )
        ],
    ),
    (
        "the held exchange's stream was deregistered",
        [
            (
                HARNESS_EPOCH,
                "            evidence.held_stream_deregistered,",
                "            true,",
            )
        ],
    ),
    # 4. The contract clause proper: no fid is restored.
    (
        "a pre-attach probe was closed rather than served",
        [
            (
                HARNESS_EPOCH,
                "            !evidence.pre_attach_probe_answered,",
                "            true,",
            )
        ],
    ),
    (
        "that close was the profile's protocol violation",
        [
            (
                HARNESS_EPOCH,
                "            evidence.pre_attach_probe_close_code"
                " == Some(PROTOCOL_VIOLATION_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session reached 9P on its own terms",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_msize > 0"
                " && evidence.second_session_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the earlier session's file fid was not restored",
        [
            (
                HARNESS_EPOCH,
                "            evidence.stale_file_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the file fid refusal named an unallocated fid",
        [
            (
                HARNESS_EPOCH,
                "            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the earlier session's attach fid was not restored",
        [
            (
                HARNESS_EPOCH,
                "            evidence.stale_attach_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the attach fid refusal named an unallocated fid",
        [
            (
                HARNESS_EPOCH,
                "            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session established its own root",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_attached,",
                "            true,",
            )
        ],
    ),
    # 5. The export is undamaged, so the refusals above are fid scoping and
    #    not a replacement connector that never served this export.
    (
        "the replacement session read the whole file back",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_bytes"
                " == evidence.second_session_expected_bytes\n"
                "                && evidence.second_session_expected_bytes == EPOCH_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer's checksum matched",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_checksum_matches,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer spanned many Rread messages",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_messages >= MIN_READ_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "the file was undamaged by the held session",
        [
            (
                HARNESS_EPOCH,
                "            evidence.second_session_getattr_size == EPOCH_FILE_BYTES as u64,",
                "            true,",
            )
        ],
    ),
    (
        "each attached session attached exactly once",
        [
            (
                HARNESS_EPOCH,
                "            evidence.attach_count == 2,",
                "            true,",
            )
        ],
    ),
    # 6. The predicate's own clauses, which is what holds the composite rule
    #    above when the emit-cursor case is subsumed by it.
    (
        "the predicate requires the request to have been dispatched",
        [
            (
                HARNESS_EPOCH,
                "        self.emitted_at_change > self.emitted_before",
                "        true",
            )
        ],
    ),
    (
        "the predicate requires the reply not to have arrived",
        [
            (
                HARNESS_EPOCH,
                "            && self.recv_contiguous_at_change == self.recv_contiguous_before",
                "",
            )
        ],
    ),
]

# ---------------------------------------------------------------------------
# `gate10-process-restart` — the validator of the gate that holds a 9P
# **mutation** outstanding while the connector's real operating-system process
# is killed and replaced.  Like `gate7-rotation`, `gate8-consumer-loss` and
# `gate9-epoch-change` this is a harness-side validator, so each case defeats
# one rule and the suite's own unit tests must go red.
#
# Three groups here have no counterpart in gate 9 and are why this gate exists
# as its own suite rather than as a case inside that one:
#
#   * the **journal** rules, which are what make the held call's outcome
#     measurable at all — an in-memory count dies with the process, so without
#     a record taken from the host directory "the count did not increase" would
#     be true of nothing;
#   * the **outcome** rules, which hold that an ambiguous mutation classifies
#     as `Outcome::Unknown` and that `Unknown` is not settled, read out of the
#     library rather than restated here; and
#   * the **process** rules, which are what make the event a restart of a real
#     operating-system process — a recorded pid that exited on a signal, and a
#     replacement under a different one — rather than an in-process handle
#     being dropped and remade, which is gate 9.
# ---------------------------------------------------------------------------

GATE10_RESTART_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_process_restart::",
]

GATE10_RESTART_CASES: list[tuple[str, list[Edit]]] = [
    (
        "the production cluster ran three relays",
        [
            (
                HARNESS_RESTART,
                "            evidence.relay_count == 3,",
                "            true,",
            )
        ],
    ),
    (
        "the owning relay was identified",
        [
            (
                HARNESS_RESTART,
                "            !evidence.owner_node.is_empty(),",
                "            true,",
            )
        ],
    ),
    (
        "the server selected the filesystem subprotocol",
        [
            (
                HARNESS_RESTART,
                "            evidence.selected_subprotocol == SUBPROTOCOL,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated the 9P2000.L dialect",
        [
            (
                HARNESS_RESTART,
                "            evidence.negotiated_dialect == DIALECT,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated a bounded msize",
        [
            (
                HARNESS_RESTART,
                "            evidence.negotiated_msize > 0 && evidence.negotiated_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the session served a real read before anything was perturbed",
        [
            (
                HARNESS_RESTART,
                "            evidence.prefix_bytes > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the mutation path worked before the held mutation was issued",
        [
            (
                HARNESS_RESTART,
                "            evidence.journal_entries_before_held == 1,",
                "            true,",
            )
        ],
    ),
    (
        "the relay had dispatched a 9P record toward the device when the process was killed",
        [
            (
                HARNESS_RESTART,
                "            evidence.restart.emitted_at_kill > evidence.restart.emitted_before,",
                "            true,",
            )
        ],
    ),
    (
        "the relay had received no answer to that record when the process was killed: the 9P mutation was outstanding across the restart",
        [
            (
                HARNESS_RESTART,
                "            evidence.request_outstanding_at_kill && evidence.restart.request_outstanding_at_kill(),",
                "            true,",
            )
        ],
    ),
    (
        "a stream was identified for the held exchange",
        [
            (
                HARNESS_RESTART,
                "            evidence.restart.stream_id > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the held mutation had reached the device and been performed before the process was killed, so the lost answer is an unknown and not a refusal that never dispatched",
        [
            (
                HARNESS_RESTART,
                "            evidence.held_effect_present_before_kill,",
                "            true,",
            )
        ],
    ),
    (
        "the journal, read from the host directory, held both effects at the kill",
        [
            (
                HARNESS_RESTART,
                "            evidence.journal_entries_before_kill == EXPECTED_JOURNAL_ENTRIES,",
                "            true,",
            )
        ],
    ),
    (
        "a first connector process was identified",
        [
            (
                HARNESS_RESTART,
                "            evidence.first_pid > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the first connector process exited",
        [
            (
                HARNESS_RESTART,
                "            evidence.first_process_exited,",
                "            true,",
            )
        ],
    ),
    (
        "the first connector process was killed rather than stopped gracefully",
        [
            (
                HARNESS_RESTART,
                "            evidence.first_process_killed_by_signal,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement is a different process",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_pid > 0 && evidence.second_pid != evidence.first_pid,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement process served the device",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_process_active,",
                "            true,",
            )
        ],
    ),
    (
        "the owner was released between the two processes",
        [
            (
                HARNESS_RESTART,
                "            evidence.owner_released_between,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement claim took a strictly greater epoch",
        [
            (
                HARNESS_RESTART,
                "            evidence.epoch_after > evidence.epoch_before,",
                "            true,",
            )
        ],
    ),
    (
        "an epoch was actually observed before the restart",
        [
            (
                HARNESS_RESTART,
                "            evidence.epoch_before > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the device session identity changed across the restart",
        [
            (
                HARNESS_RESTART,
                "            !evidence.session_id_before.is_empty()\n"
                "                && !evidence.session_id_after.is_empty()\n"
                "                && evidence.session_id_before != evidence.session_id_after,",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was failed rather than left hanging",
        [
            (
                HARNESS_RESTART,
                "            evidence.pending_call_closed,",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was failed explicitly, with a close code",
        [
            (
                HARNESS_RESTART,
                "            evidence.pending_call_close_code == Some(DEVICE_GONE_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was not served a normal reply from a session the contract invalidates",
        [
            (
                HARNESS_RESTART,
                "            !evidence.pending_call_answered,",
                "            true,",
            )
        ],
    ),
    (
        "a mutation the journal proves was performed was not reported to the caller as an error, which is a settled outcome a caller may resubmit after",
        [
            (
                HARNESS_RESTART,
                "            !evidence.pending_call_errored,",
                "            true,",
            )
        ],
    ),
    (
        "the held mutation classifies as an unknown outcome",
        [
            (
                HARNESS_RESTART,
                "            evidence.held_call_outcome == Some(Outcome::Unknown),",
                "            true,",
            )
        ],
    ),
    (
        "the held exchange's stream was deregistered at the owner",
        [
            (
                HARNESS_RESTART,
                "            evidence.held_stream_deregistered,",
                "            true,",
            )
        ],
    ),
    (
        "a replacement session that speaks before attaching is closed with the profile's protocol violation",
        [
            (
                HARNESS_RESTART,
                "            evidence.pre_attach_probe_close_code == Some(PROTOCOL_VIOLATION_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "that session was closed rather than served",
        [
            (
                HARNESS_RESTART,
                "            !evidence.pre_attach_probe_answered,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session negotiated a bounded msize",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_msize > 0 && evidence.second_session_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session established its own root",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_attached,",
                "            true,",
            )
        ],
    ),
    (
        "the earlier session's file fid is unbound after the restart",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_file_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the stale file fid refusal carried the errno for a fid this session never allocated",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the earlier session's attach fid is unbound after the restart",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_attach_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the stale attach fid refusal carried the errno for a fid this session never allocated",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_attach_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the fid the outstanding mutation was issued on is unbound after the restart",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_journal_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the stale mutation fid refusal carried the errno for a fid this session never allocated",
        [
            (
                HARNESS_RESTART,
                "            evidence.stale_journal_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "a caller that retries the mutation anyway is refused above the dispatch boundary",
        [
            (
                HARNESS_RESTART,
                "            evidence.retry_refused_above_dispatch,",
                "            true,",
            )
        ],
    ),
    (
        "that retry was refused for its fid and never reached the provider",
        [
            (
                HARNESS_RESTART,
                "            evidence.retry_refusal_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the refused retry moved no effect",
        [
            (
                HARNESS_RESTART,
                "            evidence.journal_entries_after_retry == evidence.journal_entries_before_kill,",
                "            true,",
            )
        ],
    ),
    (
        "the effect happened exactly once across both process generations",
        [
            (
                HARNESS_RESTART,
                "            evidence.journal_entries_final == EXPECTED_JOURNAL_ENTRIES,",
                "            true,",
            )
        ],
    ),
    (
        "the held effect appears exactly once",
        [
            (
                HARNESS_RESTART,
                "            evidence.held_effect_exactly_once,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session's own view of the journal agrees with the host's",
        [
            (
                HARNESS_RESTART,
                "            evidence.journal_entries_over_ninep == evidence.journal_entries_final,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session read the whole file back",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_bytes == evidence.second_session_expected_bytes\n"
                "                && evidence.second_session_expected_bytes == RESTART_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "the bytes it read match byte for byte",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_checksum_matches,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer needed many messages rather than one",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_messages > MIN_READ_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "the file is the size it always was",
        [
            (
                HARNESS_RESTART,
                "            evidence.second_session_getattr_size == RESTART_FILE_BYTES as u64,",
                "            true,",
            )
        ],
    ),
    (
        "exactly one Tattach per attached session, and never a reconstructed one",
        [
            (
                HARNESS_RESTART,
                "            evidence.attach_count == 2,",
                "            true,",
            )
        ],
    ),
]

# ---------------------------------------------------------------------------
# `gate11-data-recovery` — the validator of the gate that holds a 9P read
# outstanding while the device's data socket is destroyed at the transport and
# the product's own retained recovery replaces it.  Like `gate7-rotation`,
# `gate8-consumer-loss`, `gate9-epoch-change` and `gate10-process-restart` this
# is a harness-side validator, so each case defeats one rule and the suite's
# own unit tests must go red.
#
# Two groups here have no counterpart in the other four, and are why this gate
# is its own suite rather than a case inside gate 7:
#
#   * the **failure-not-rotation** rules, which are what separate the event the
#     contract licenses from the clean attempt gate 7 drives — a different
#     physical carrier, a strictly greater generation, a completed-rotation
#     count that does not move, and the dead socket's absence at the proxy;
#   * the **same-owner qualifier** rules, which are the *antecedent* of the
#     contract clause rather than part of it.  The profile permits preserving a
#     filesystem session across a failed data socket "only while the same
#     control owner and all ordered stream state are retained", so a gate that
#     observed a surviving fid without them would have recorded the violation
#     and called it the contract.  Each conjunct is separately load-bearing,
#     which the gate's own second unit test defeats one at a time.
#
# Those qualifier rules are **not** stated twice.  Writing each one as its own
# validator rule *as well* was tried, and this suite reported all thirteen
# `still green` when defeated: the antecedent conjunction already rejects every
# run they would have rejected, so none of them could ever be the rule that
# failed a run.  They were removed rather than exempted as documented-green, and
# the property moved to where it can be defeated — the last **fourteen** cases
# here delete one conjunct of `same_owner_contract_qualifiers_held` each, and the
# gate's own `every_same_owner_qualifier_defeats_the_antecedent_on_its_own` is
# what goes red.
#
# That antecedent is written as an **array** rather than as a `&&` chain, and
# this suite is the reason.  As a chain the head conjunct carries no `&&`, so it
# did not match the single edit shape these cases key on and was the one
# conjunct the suite could not defeat — the unfalsifiable-rule problem the
# thirteen removals were meant to cure, reappearing at the one line the edit
# shape could not reach.  Every element of the array has an identical shape, so
# the head is reached like the rest.
# ---------------------------------------------------------------------------

GATE11_RECOVERY_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_data_recovery::",
]

GATE11_RECOVERY_CASES: list[tuple[str, list[Edit]]] = [
    (
        'the production cluster ran three relays',
        [(HARNESS_RECOVERY, '            evidence.relay_count == 3,', '            true,')],
    ),
    (
        'the owning relay was identified',
        [(HARNESS_RECOVERY, '            !evidence.owner_node.is_empty(),', '            true,')],
    ),
    (
        'the server selected the filesystem subprotocol',
        [(HARNESS_RECOVERY, '            evidence.selected_subprotocol == SUBPROTOCOL,', '            true,')],
    ),
    (
        'Tversion negotiated the 9P2000.L dialect',
        [(HARNESS_RECOVERY, '            evidence.negotiated_dialect == DIALECT,', '            true,')],
    ),
    (
        'Tversion negotiated a bounded msize',
        [(HARNESS_RECOVERY, '            evidence.negotiated_msize > 0 && evidence.negotiated_msize <= OFFERED_MSIZE,', '            true,')],
    ),
    (
        'the fid served a real read before anything was perturbed',
        [(HARNESS_RECOVERY, '            evidence.prefix_bytes > 0,', '            true,')],
    ),
    (
        'the relay had dispatched a 9P record toward the device when the data socket failed',
        [(HARNESS_RECOVERY, '            evidence.failure.emitted_at_failure > evidence.failure.emitted_before,', '            true,')],
    ),
    (
        'the relay had received no answer to that record when the data socket failed: the 9P exchange was outstanding across the failure',
        [(HARNESS_RECOVERY, '            evidence.request_outstanding_at_failure\n                && evidence.failure.request_outstanding_at_failure(),', '            true,')],
    ),
    (
        'the held exchange ran on a registered consumer stream',
        [(HARNESS_RECOVERY, '            evidence.failure.stream_id > 0,', '            true,')],
    ),
    (
        'the data carrier really was replaced: a different physical connection',
        [(HARNESS_RECOVERY, '            !evidence.connection_id_before.is_empty()\n                && !evidence.connection_id_after.is_empty()\n                && evidence.connection_id_after != evidence.connection_id_before,', '            true,')],
    ),
    (
        'the replacement carrier took a strictly greater generation',
        [(HARNESS_RECOVERY, '            evidence.generation_after > evidence.generation_before,', '            true,')],
    ),
    (
        "no scheduled rotation completed: the generation change was the failure's, not the timer's",
        [(HARNESS_RECOVERY, '            evidence.rotations_completed_before == 0 && evidence.rotations_completed_after == 0,', '            true,')],
    ),
    (
        'the failed data socket was gone at the transport, not only in diagnostics',
        [(HARNESS_RECOVERY, '            evidence.failed_connection_closed_at_proxy,', '            true,')],
    ),
    (
        'a replacement device data socket was dialled through the proxy',
        [(HARNESS_RECOVERY, '            evidence.replacement_connection_observed_at_proxy,', '            true,')],
    ),
    (
        'the same control owner and all ordered stream state were retained, which is the only condition under which the profile permits preserving this filesystem session across a failed data socket',
        [(HARNESS_RECOVERY, '            evidence.same_owner_contract_qualifiers_held(),', '            true,')],
    ),
    (
        'the reply outstanding when the socket died came back on the same consumer session',
        [(HARNESS_RECOVERY, '            evidence.held_reply_was_rread,', '            true,')],
    ),
    (
        'it carried the tag that was outstanding across the failure',
        [(HARNESS_RECOVERY, '            evidence.held_reply_tag_matched,', '            true,')],
    ),
    (
        'that reply carried data rather than an empty read',
        [(HARNESS_RECOVERY, '            evidence.held_reply_bytes > 0,', '            true,')],
    ),
    (
        'the whole file was read on one fid across the failure',
        [(HARNESS_RECOVERY, '            evidence.transfer_bytes == evidence.transfer_expected_bytes\n                && evidence.transfer_expected_bytes == RECOVERY_FILE_BYTES,', '            true,')],
    ),
    (
        "that transfer's checksum matched the synthetic content: no byte was lost, duplicated or reordered across the failure",
        [(HARNESS_RECOVERY, '            evidence.transfer_checksum_matches,', '            true,')],
    ),
    (
        'that transfer spanned many Rread messages rather than one',
        [(HARNESS_RECOVERY, '            evidence.transfer_messages >= MIN_READ_MESSAGES,', '            true,')],
    ),
    (
        'the fid opened before the failure still answered afterwards',
        [(HARNESS_RECOVERY, '            evidence.fid_survived_getattr,', '            true,')],
    ),
    (
        'and still named the same file',
        [(HARNESS_RECOVERY, '            evidence.fid_survived_getattr_size == RECOVERY_FILE_BYTES as u64,', '            true,')],
    ),
    (
        'the attach fid established before the failure still walked',
        [(HARNESS_RECOVERY, '            evidence.attach_fid_survived_walk,', '            true,')],
    ),
    (
        'a tag allocated after the recovery correlated on the replacement carrier',
        [(HARNESS_RECOVERY, '            evidence.post_recovery_tag_correlated,', '            true,')],
    ),
    (
        'exactly one Tattach across the run: no fid was reconstructed',
        [(HARNESS_RECOVERY, '            evidence.attach_count == 1,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.catalog_owner_session_stable",
        [(HARNESS_RECOVERY, '            self.catalog_owner_session_stable,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.catalog_epoch_after == self.catalog_epoch_before",
        [(HARNESS_RECOVERY, '            self.catalog_epoch_after == self.catalog_epoch_before,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.owner_session_id_stable",
        [(HARNESS_RECOVERY, '            self.owner_session_id_stable,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.owner_epoch_after == self.owner_epoch_before",
        [(HARNESS_RECOVERY, '            self.owner_epoch_after == self.owner_epoch_before,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.control_carrier_unchanged",
        [(HARNESS_RECOVERY, '            self.control_carrier_unchanged,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.recovery_attempted",
        [(HARNESS_RECOVERY, '            self.recovery_attempted,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.owner_recovery_reason.as_deref() == Some(OLD_TRANSPORT_LOST)",
        [(HARNESS_RECOVERY, '            self.owner_recovery_reason.as_deref() == Some(OLD_TRANSPORT_LOST),', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.recovery_released_failed_carrier",
        [(HARNESS_RECOVERY, '            self.recovery_released_failed_carrier,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.recovery_successor_is_active_carrier",
        [(HARNESS_RECOVERY, '            self.recovery_successor_is_active_carrier,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.replayed_frames_after > self.replayed_frames_before",
        [(HARNESS_RECOVERY, '            self.replayed_frames_after > self.replayed_frames_before,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.operation_id_stable",
        [(HARNESS_RECOVERY, '            self.operation_id_stable,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.stream_remained_registered",
        [(HARNESS_RECOVERY, '            self.stream_remained_registered,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.sole_consumer_stream_at_owner",
        [(HARNESS_RECOVERY, '            self.sole_consumer_stream_at_owner,', '            true,')],
    ),
    (
        "the same-owner antecedent's conjunct: self.stream_not_terminal",
        [(HARNESS_RECOVERY, '            self.stream_not_terminal,', '            true,')],
    ),
]



# `gate12-rotation-write` — the validator of the gate that holds a **Twrite**
# across one real scheduled rotation and a **Tflush** across the next.  Like
# `gate7-rotation` this is a cluster run that cannot be repeated once per case,
# so what is measured is its **rule list** against the mutation table in the
# same file.  The edits replace a condition with `true` for the same reason:
# the rule list is a fixed-length array and removing an entry stops the crate
# compiling, which this script refuses to call a red test.
#
# The cases that matter most are the ones that make this gate a *write* gate
# rather than a second read gate: that the host directory discriminated a
# written region from an untouched one **in both directions and before the
# event**, that it showed the write performed before the freeze, and that a
# clean scheduled rotation left no ambiguous write.  Without those the gate
# would prove only that a rotation happened near a mutation.
#
# **Two of the forty-one are masked, and this says so rather than hiding it**,
# on exactly gate 7's recorded precedent and for the same reason: the two
# `attempt_active` rules are each still green when defeated alone, because the
# composite rule beside each of them already subsumes it —
# `exchange_in_flight_at_freeze()` returns false unless `attempt_active` is set
# **and** the phase is one of `FROZEN_PHASES`.  They are kept because they name
# the violated condition precisely when a run fails, which a composite cannot.
#
# A rule reading `held_region_before_freeze != RegionState::Torn` was
# **removed** rather than listed here: `held_write_performed_before_freeze()`
# is `== RegionState::Written`, so the torn rule could never have failed a run.
# Its property is held by `a_partly_applied_write_is_torn_and_is_neither_of_
# the_others`, which defeats all four classifications directly, and the removal
# is recorded in M4-06.
GATE12_ROTATION_WRITE_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_rotation_write::",
]

GATE12_ROTATION_WRITE_CASES: list[tuple[str, list[Edit]]] = [
    (
        "the production cluster ran three relays",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.relay_count == 3,",
                "            true,",
            )
        ],
    ),
    (
        "the owning relay was identified",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            !evidence.owner_node.is_empty(),",
                "            true,",
            )
        ],
    ),
    (
        "the server selected the filesystem subprotocol",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.selected_subprotocol == SUBPROTOCOL,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated the 9P2000.L dialect",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.negotiated_dialect == DIALECT,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated a bounded msize",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.negotiated_msize > 0 && evidence.negotiated_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the host directory discriminated a written region from an untouched one, in both directions, before the event",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.journal_discriminated_both_directions(),",
                "            true,",
            )
        ],
    ),
    (
        "a rotation attempt was active when the owner was sampled for the write",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.write_freeze.attempt_active,",
                "            true,",
            )
        ],
    ),
    (
        "the connector's fence covered a record the owner had not received: the Twrite was in flight when the first attempt's fences were fixed",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.write_exchange_in_flight_at_freeze\n                && evidence.write_freeze.exchange_in_flight_at_freeze(),",
                "            true,",
            )
        ],
    ),
    (
        "the first attempt named a candidate generation above the old one",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence\n                .write_freeze\n                .candidate_generation\n                .is_some_and(|candidate| candidate > evidence.write_freeze.old_generation),",
                "            true,",
            )
        ],
    ),
    (
        "the host directory showed the held write performed before the freeze",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_write_performed_before_freeze(),",
                "            true,",
            )
        ],
    ),
    (
        "the reply held across the first rotation carried the tag that was outstanding",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_write_reply_tag_matched,",
                "            true,",
            )
        ],
    ),
    (
        "the reply held across the first rotation was an Rwrite",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_write_reply_was_rwrite,",
                "            true,",
            )
        ],
    ),
    (
        "the Rwrite acknowledged exactly the bytes the Twrite carried",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_write_acknowledged_bytes == HELD_PAYLOAD_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "the held write was answered",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_write_answered,",
                "            true,",
            )
        ],
    ),
    (
        "a clean scheduled rotation left no ambiguous write",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            !evidence.held_write_ambiguous,",
                "            true,",
            )
        ],
    ),
    (
        "the held write's effect was still whole after the rotation committed",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.held_region_after_rotation == RegionState::Written,",
                "            true,",
            )
        ],
    ),
    (
        "the host file was exactly its seeded length",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.image_bytes == evidence.image_expected_bytes\n                && evidence.image_expected_bytes == TARGET_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "no byte outside the two written regions changed",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.image_checksum_matches,",
                "            true,",
            )
        ],
    ),
    (
        "a rotation attempt was active when the owner was sampled for the flush",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.flush_freeze.attempt_active,",
                "            true,",
            )
        ],
    ),
    (
        "the connector's fence covered a record the owner had not received: the flush exchange was in flight when the second attempt's fences were fixed",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.flush_exchange_in_flight_at_freeze\n                && evidence.flush_freeze.exchange_in_flight_at_freeze(),",
                "            true,",
            )
        ],
    ),
    (
        "the second attempt named a candidate generation above the old one",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence\n                .flush_freeze\n                .candidate_generation\n                .is_some_and(|candidate| candidate > evidence.flush_freeze.old_generation),",
                "            true,",
            )
        ],
    ),
    (
        "the flush held across the second rotation was answered on its own tag",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.rflush_observed,",
                "            true,",
            )
        ],
    ),
    (
        "the flush named a victim other than itself",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.flushed_victim_tag != evidence.flush_tag,",
                "            true,",
            )
        ],
    ),
    (
        "the flushed tag was never answered at all, across the rotation",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            !evidence.flushed_victim_reply_observed,",
                "            true,",
            )
        ],
    ),
    (
        "no reply for the flushed tag followed its Rflush",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.flushed_replies_after_rflush == 0,",
                "            true,",
            )
        ],
    ),
    (
        "the flush cancelled its victim and nothing else: every pipelined read queued ahead of it was still answered",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.flush_pipeline_replies == FLUSH_PIPELINE_DEPTH,",
                "            true,",
            )
        ],
    ),
    (
        "a scheduled rotation completed while the write was held",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.rotations_completed_after_write > evidence.rotations_completed_before,",
                "            true,",
            )
        ],
    ),
    (
        "a second scheduled rotation completed while the flush was held",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.rotations_completed_after_flush > evidence.rotations_completed_after_write,",
                "            true,",
            )
        ],
    ),
    (
        "the active data generation advanced",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.generation_after > evidence.generation_before,",
                "            true,",
            )
        ],
    ),
    (
        "a clean rotation replayed no frames",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.total_replayed_frames == 0,",
                "            true,",
            )
        ],
    ),
    (
        "neither rotation was forced into recovery by its deadline",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            !evidence.deadline_forced_retirement && evidence.rotation_recovery_reason.is_none(),",
                "            true,",
            )
        ],
    ),
    (
        "the session identity was unchanged across both rotations",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.session_id_stable,",
                "            true,",
            )
        ],
    ),
    (
        "the session epoch was unchanged across both rotations",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.epoch_stable,",
                "            true,",
            )
        ],
    ),
    (
        "the fid opened before the rotations still answered after them",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.fid_survived_read,",
                "            true,",
            )
        ],
    ),
    (
        "that fid read the held write's bytes back",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.fid_read_back_matches_payload,",
                "            true,",
            )
        ],
    ),
    (
        "the relay did not reconstruct the session: exactly one Tattach was sent",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.attach_count == 1,",
                "            true,",
            )
        ],
    ),
    (
        "a tag allocated after the rotations correlated correctly",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            evidence.post_rotation_tag_correlated,",
                "            true,",
            )
        ],
    ),
    (
        "the journal's negative direction: the region was untouched before the write",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            self.held_region_before_send == RegionState::Untouched,",
                "            true,",
            )
        ],
    ),
    (
        "the journal's positive direction: a prefix write read back written",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            self.prefix_region_after_write == RegionState::Written,",
                "            true,",
            )
        ],
    ),
    (
        "the prefix write's acknowledged count",
        [
            (
                HARNESS_ROTATION_WRITE,
                "            self.prefix_acknowledged_bytes == PREFIX_PAYLOAD_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "the ambiguity derivation needs the journal",
        [
            (
                HARNESS_ROTATION_WRITE,
                "    evidence.held_write_performed_before_freeze() && !evidence.held_write_answered\n",
                "    !evidence.held_write_answered\n",
            )
        ],
    ),
]



# `gate13-write-restart` — the validator of the gate that holds a **`Twrite`**
# outstanding while the connector's real operating-system process is killed and
# replaced.  Like every gate from `gate7-rotation` on this is a cluster run that
# cannot be repeated once per case, so what is measured is its **rule list**
# against the mutation table in the same file, and the edits replace a condition
# with `true` because the rule list is a fixed-length array whose entries cannot
# be removed without stopping the crate compiling.
#
# This suite exists apart from `gate10-process-restart` for the reason the
# module does.  Gate 10's held operation is a `Tlcreate`, whose effect is a
# directory entry: it happened or it did not.  This one's is a `Twrite`, whose
# effect is bytes at an offset and which `docs/filesystem-api.md` explicitly
# permits to **apply partially**.  So the cases that carry this gate are the
# ones gate 10 has no vocabulary for:
#
#   * `the held write had reached the device ...`, whose predicate admits
#     `Written` **and** `Torn`.  Tightening it to `Written` would assert a
#     promise the contract withholds, and
#     `a_torn_held_region_is_accepted_by_every_rule_that_reads_it` is the unit
#     test that goes red if anyone does;
#   * `the bytes the kill left behind were neither completed nor rolled back
#     ...`, which is "does not blindly resubmit the operation in the new
#     session" observed on the effect surface rather than on a reply; and
#   * `the held write classifies as an unknown outcome`, where the caller's
#     entitlement is the same for a torn region as for a whole one because
#     `Outcome::Partial` is defined in terms of an *acknowledged* effect and
#     this caller was acknowledged nothing.
#
# No `!is_settled()` companion rule is listed here because none is written:
# that is the rule gate 10 removed as unable to fail, and the library property
# is held directly by `an_unknown_outcome_is_not_settled_and_a_failed_one_is`.
GATE13_WRITE_RESTART_TEST = [
    "cargo",
    "test",
    "--offline",
    "-p",
    "tunnel-test-harness",
    "--lib",
    "--locked",
    "production_cluster::fs_write_restart::",
]

GATE13_WRITE_RESTART_CASES: list[tuple[str, list[Edit]]] = [
    (
        "the production cluster ran three relays",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.relay_count == 3,",
                "            true,",
            )
        ],
    ),
    (
        "the owning relay was identified",
        [
            (
                HARNESS_WRITE_RESTART,
                "            !evidence.owner_node.is_empty(),",
                "            true,",
            )
        ],
    ),
    (
        "the server selected the filesystem subprotocol",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.selected_subprotocol == SUBPROTOCOL,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated the 9P2000.L dialect",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.negotiated_dialect == DIALECT,",
                "            true,",
            )
        ],
    ),
    (
        "Tversion negotiated a bounded msize",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.negotiated_msize > 0 && evidence.negotiated_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the session served a real read before anything was perturbed",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.prefix_bytes > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the host file discriminated a written region from an untouched one, in bothdirections, before the event",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.journal_discriminated_both_directions(),",
                "            true,",
            )
        ],
    ),
    (
        "the relay had dispatched a 9P record toward the device when the process was killed",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.restart.emitted_at_kill > evidence.restart.emitted_before,",
                "            true,",
            )
        ],
    ),
    (
        "the relay had received no answer to that record when the process was killed: theTwrite was outstanding across the restart",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.request_outstanding_at_kill && evidence.restart.request_outstanding_at_kill(),",
                "            true,",
            )
        ],
    ),
    (
        "a stream was identified for the held exchange",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.restart.stream_id > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the held write had reached the device before the process was killed, so the lostanswer is an unknown and not a refusal that never dispatched",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.held_write_reached_the_device(),",
                "            true,",
            )
        ],
    ),
    (
        "a first connector process was identified",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.first_pid > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the first connector process exited",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.first_process_exited,",
                "            true,",
            )
        ],
    ),
    (
        "the first connector process was killed rather than stopped gracefully",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.first_process_killed_by_signal,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement is a different process",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_pid > 0 && evidence.second_pid != evidence.first_pid,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement process served the device",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_process_active,",
                "            true,",
            )
        ],
    ),
    (
        "the owner was released between the two processes",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.owner_released_between,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement claim took a strictly greater epoch",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.epoch_after > evidence.epoch_before,",
                "            true,",
            )
        ],
    ),
    (
        "an epoch was actually observed before the restart",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.epoch_before > 0,",
                "            true,",
            )
        ],
    ),
    (
        "the device session identity changed across the restart",
        [
            (
                HARNESS_WRITE_RESTART,
                "            !evidence.session_id_before.is_empty()\n"
                "                && !evidence.session_id_after.is_empty()\n"
                "                && evidence.session_id_before != evidence.session_id_after,",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was failed rather than left hanging",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.pending_call_closed,",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was failed explicitly, with a close code",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.pending_call_close_code == Some(DEVICE_GONE_CLOSE),",
                "            true,",
            )
        ],
    ),
    (
        "the pending call was not served a normal reply from a session the contractinvalidates",
        [
            (
                HARNESS_WRITE_RESTART,
                "            !evidence.pending_call_answered,",
                "            true,",
            )
        ],
    ),
    (
        "a write the host file proves reached the device was not reported to the caller as anerror, which is a settled outcome a caller may resubmit after",
        [
            (
                HARNESS_WRITE_RESTART,
                "            !evidence.pending_call_errored,",
                "            true,",
            )
        ],
    ),
    (
        "the held write classifies as an unknown outcome",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.held_call_outcome == Some(Outcome::Unknown),",
                "            true,",
            )
        ],
    ),
    (
        "the held exchange's stream was deregistered at the owner",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.held_stream_deregistered,",
                "            true,",
            )
        ],
    ),
    (
        "the bytes the kill left behind were neither completed nor rolled back by therestart or by a caller's retry",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.region_unchanged_since_the_kill(),",
                "            true,",
            )
        ],
    ),
    (
        "the earlier session's file fid is unbound after the restart",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.stale_file_fid_refused,",
                "            true,",
            )
        ],
    ),
    (
        "the stale file fid refusal carried the errno for a fid this session never allocated",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.stale_file_fid_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "a caller that retries the write anyway is refused above the dispatch boundary",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.retry_refused_above_dispatch,",
                "            true,",
            )
        ],
    ),
    (
        "that retry was refused for its fid and never reached the provider",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.retry_refusal_errno == Some(UNKNOWN_FID_ERRNO),",
                "            true,",
            )
        ],
    ),
    (
        "the host file was exactly its seeded length",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.image_bytes == evidence.image_expected_bytes\n"
                "                && evidence.image_expected_bytes == TARGET_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "no byte outside the held region changed",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.image_outside_held_region_matches,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session negotiated a bounded msize",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_session_msize > 0 && evidence.second_session_msize <= OFFERED_MSIZE,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session established its own root",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_session_attached,",
                "            true,",
            )
        ],
    ),
    (
        "the replacement session read the whole file back",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_session_bytes == evidence.second_session_expected_bytes\n"
                "                && evidence.second_session_expected_bytes == TARGET_FILE_BYTES,",
                "            true,",
            )
        ],
    ),
    (
        "that transfer needed many messages rather than one",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_session_messages > MIN_READ_MESSAGES,",
                "            true,",
            )
        ],
    ),
    (
        "the export's own view of the file is byte for byte the host's",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.ninep_image_matches_host,",
                "            true,",
            )
        ],
    ),
    (
        "the export classifies the held region exactly as the host does",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.held_region_over_ninep == evidence.held_region_before_kill,",
                "            true,",
            )
        ],
    ),
    (
        "the file is the size it always was",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.second_session_getattr_size == TARGET_FILE_BYTES as u64,",
                "            true,",
            )
        ],
    ),
    (
        "exactly one Tattach per attached session, and never a reconstructed one",
        [
            (
                HARNESS_WRITE_RESTART,
                "            evidence.attach_count == 2,",
                "            true,",
            )
        ],
    ),
]


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
    Suite(
        "gate7-rotation",
        [HARNESS / "src"],
        GATE7_ROTATION_TEST,
        GATE7_ROTATION_CASES,
    ),
    Suite(
        "gate8-consumer-loss",
        [HARNESS / "src"],
        GATE8_LOSS_TEST,
        GATE8_LOSS_CASES,
    ),
    Suite(
        "gate9-epoch-change",
        [HARNESS / "src"],
        GATE9_EPOCH_TEST,
        GATE9_EPOCH_CASES,
    ),
    Suite(
        "gate10-process-restart",
        [HARNESS / "src"],
        GATE10_RESTART_TEST,
        GATE10_RESTART_CASES,
    ),
    Suite(
        "gate11-data-recovery",
        [HARNESS / "src"],
        GATE11_RECOVERY_TEST,
        GATE11_RECOVERY_CASES,
    ),
    Suite(
        "gate12-rotation-write",
        [HARNESS / "src"],
        GATE12_ROTATION_WRITE_TEST,
        GATE12_ROTATION_WRITE_CASES,
    ),
    Suite(
        "gate13-write-restart",
        [HARNESS / "src"],
        GATE13_WRITE_RESTART_TEST,
        GATE13_WRITE_RESTART_CASES,
    ),
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
        # M8-C06, finished here: a run that timed out names no failing test,
        # which is the same observation as the no-named-failure case.  The old
        # "RED (hung)" spelling was counted in neither the red tally nor the
        # unusable list.  A guard whose deletion genuinely hangs is still
        # evidence, but expensive and unnamed -- see the `break`-rather-than-
        # delete note on the readdir cookie case.
        return "NOT EVIDENCE (timed out)", []
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
        # M8-C06, finished here: a run that timed out names no failing test,
        # which is the same observation as the no-named-failure case.  The old
        # "RED (hung)" spelling was counted in neither the red tally nor the
        # unusable list.  A guard whose deletion genuinely hangs is still
        # evidence, but expensive and unnamed -- see the `break`-rather-than-
        # delete note on the readdir cookie case.
        return "NOT EVIDENCE (timed out)", []
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
            "run only this suite (gate2, gate3, gate4, gate5, "
            "gate6-adapters, gate6-e2e, gate7-rotation, gate8-consumer-loss, "
            "gate9-epoch-change, gate10-process-restart, "
            "gate11-data-recovery, gate12-rotation-write or "
            "gate13-write-restart); "
            "default is all"
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
        if name in EXPECT_GREEN:
            outcome = (
                "DOCUMENTED GREEN"
                if outcome == "still green"
                else f"EXPECTED A DOCUMENTED GREEN, GOT: {outcome}"
            )
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
        documented = sum(1 for row in rows if row[2] == "DOCUMENTED GREEN")
        measurable = len(rows) - documented
        print(f"\n{suite.name}: {red} of {measurable} deletions turned a test red")
        if documented:
            print(
                f"{suite.name}: {documented} further case(s) are DOCUMENTED GREEN -- "
                "defence in depth behind a guard that refuses first, reported "
                "separately and never counted as a red test"
            )

    # Shared with scripts/acp-guard-deletion.py, and an allow list rather than
    # the deny list of prefixes this used to carry (task row M8-C08).  That
    # list -- BUILD, COULD, MODULE, NO TEST -- failed open: "still green",
    # which this file returns in two places and which means the guard was
    # defeated and NOTHING went red, matched none of them, so a run in which
    # every guard stayed green printed "0 of N" and exited 0.  Now anything
    # that is not RED or REFUSED BY COMPILER fails closed and is named.
    unusable = unusable_outcomes(
        (suite_name, name, outcome) for suite_name, name, outcome, _ in results
    )
    if unusable:
        print("\nno usable result for: " + ", ".join(unusable))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
