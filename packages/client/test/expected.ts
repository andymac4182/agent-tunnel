/**
 * What each checked-in fixture is *supposed to say* — one entry per fixture, as
 * a decoded message.
 *
 * ## Where these values came from, precisely
 *
 * They were transcribed **by hand from the fixtures' own hex bytes**, laid out
 * against the field order in the 9P2000.L definition, with the fixture headers
 * and `fixtures/README.md` supplying the message type, tag, length and the
 * properties the bytes are meant to pin. They were **not** read from
 * `crates/tunnel-fs-ninep/tests/common/mod.rs`, which was never opened, and not
 * dumped from this decoder's own output. That is why they necessarily coincide
 * with the Rust fixture source: the bytes are the same bytes.
 *
 * It is a hand transcription, and four of the entries were wrong on the first
 * run — `Tsetattr`'s `size` was read as 4 where the bytes say 1024, and the
 * wide name's UTF-16 and code-point counts were both off by one. Those are
 * recorded rather than quietly fixed, because they bound what this table
 * proves: it is a careful reading of the bytes, not a source independent of
 * them.
 *
 * ## What it therefore can and cannot catch
 *
 * This table is the half of the cross-check that a round trip cannot do. A
 * decode-then-re-encode agrees with the fixture even when two field offsets are
 * swapped, as long as the widths match; naming the intended values catches
 * that. The round trip catches the opposite failure, a decoder that reads
 * fields the encoder does not write back identically.
 *
 * **It cannot catch a transposition between two fields that hold the same
 * value in the fixture** — `Rgetattr`'s `uid` and `gid` are both 1000,
 * `Tsetattr`'s are both 0, its `atimeNsec` and `mtimeNsec` are both 0, and
 * `Tattach`'s `uname` and `aname` are both empty. A swap of any such pair is
 * invisible here *and* in the Rust's own fixture comparison. The
 * fixture-independent layout tests in `boundaries.test.ts` cover exactly those
 * pairs with distinct sentinels.
 */

import type { Message } from '../src/ninep/codec.ts';
import { constants as C } from '../src/ninep/codec.ts';

/** The synthetic directory qid the fixtures reuse for the root. */
const DIR_QID = { type: C.QTDIR, version: 1, path: 0x1122334455667788n };
/** The synthetic regular-file qid. */
const FILE_QID = { type: C.QTFILE, version: 7, path: 0x0123456789abcdefn };
/** The synthetic symbolic-link qid. */
const LINK_QID = { type: C.QTSYMLINK, version: 0, path: 0x00ff00ff00ff00ffn };

/**
 * A name carrying a two-byte and a four-byte code point, so an implementation
 * that counted UTF-16 units would produce a different `string[s]` length. It is
 * 7 UTF-16 units, 6 code points and **10 UTF-8 bytes**.
 */
export const WIDE_NAME = 'café-\u{1F5C2}';

/** `Tread`'s offset and `Rgetattr`'s size are above 2^32 on purpose. */
const ABOVE_32_BIT = 4294967296n;

function ascending(): Uint8Array {
  return Uint8Array.from({ length: 256 }, (_unused, index) => index);
}

function descending(): Uint8Array {
  return Uint8Array.from({ length: 256 }, (_unused, index) => 255 - index);
}

export const EXPECTED: Record<string, Message> = {
  rattach: { kind: 'Rattach', tag: 1, qid: DIR_QID },
  rclunk: { kind: 'Rclunk', tag: 19 },
  rflush: { kind: 'Rflush', tag: 2 },
  rgetattr: {
    kind: 'Rgetattr',
    tag: 8,
    valid: BigInt(C.GETATTR_BASIC),
    qid: FILE_QID,
    mode: 0o100644,
    uid: 1000,
    gid: 1000,
    nlink: 1n,
    rdev: 0n,
    size: ABOVE_32_BIT,
    blksize: 4096n,
    blocks: 8n,
    atimeSec: 0x69800e80n,
    atimeNsec: 123456789n,
    mtimeSec: 0x69800e81n,
    mtimeNsec: 987654321n,
    ctimeSec: 0x69800e82n,
    ctimeNsec: 1n,
    btimeSec: 0n,
    btimeNsec: 0n,
    gen: 0n,
    dataVersion: 0n,
  },
  rlcreate: { kind: 'Rlcreate', tag: 5, qid: FILE_QID, iounit: 8192 },
  'rlerror-enoent': { kind: 'Rlerror', tag: 21, ecode: C.ERRNO_BY_NAME.ENOENT },
  'rlerror-eperm': { kind: 'Rlerror', tag: 22, ecode: C.ERRNO_BY_NAME.EPERM },
  rlink: { kind: 'Rlink', tag: 11 },
  rlopen: { kind: 'Rlopen', tag: 4, qid: FILE_QID, iounit: 8192 },
  rmkdir: { kind: 'Rmkdir', tag: 12, qid: DIR_QID },
  rread: { kind: 'Rread', tag: 17, data: ascending() },
  rreaddir: {
    kind: 'Rreaddir',
    tag: 10,
    entries: [
      { qid: DIR_QID, offset: 1n, type: C.DT_DIR, name: 'notes' },
      { qid: FILE_QID, offset: 2n, type: C.DT_REG, name: WIDE_NAME },
      { qid: LINK_QID, offset: 3n, type: C.DT_LNK, name: 'shortcut' },
    ],
  },
  rreadlink: { kind: 'Rreadlink', tag: 7, target: 'projects/draft.txt' },
  rremove: { kind: 'Rremove', tag: 20 },
  rrename: { kind: 'Rrename', tag: 13 },
  rrenameat: { kind: 'Rrenameat', tag: 14 },
  rsetattr: { kind: 'Rsetattr', tag: 9 },
  rsymlink: { kind: 'Rsymlink', tag: 6, qid: LINK_QID },
  runlinkat: { kind: 'Runlinkat', tag: 15 },
  rversion: { kind: 'Rversion', tag: C.NOTAG, msize: C.MSIZE_CEILING, version: C.VERSION },
  rwalk: { kind: 'Rwalk', tag: 3, wqids: [DIR_QID, FILE_QID] },
  rwrite: { kind: 'Rwrite', tag: 18, count: 256 },

  tattach: {
    kind: 'Tattach',
    tag: 1,
    fid: 0,
    afid: C.NOFID,
    uname: '',
    aname: '',
    nUname: C.NONUNAME,
  },
  tclunk: { kind: 'Tclunk', tag: 19, fid: 1 },
  tflush: { kind: 'Tflush', tag: 2, oldtag: 1 },
  tgetattr: { kind: 'Tgetattr', tag: 8, fid: 1, requestMask: BigInt(C.GETATTR_BASIC) },
  tlcreate: {
    kind: 'Tlcreate',
    tag: 5,
    fid: 2,
    name: 'draft.txt',
    flags: C.O_WRONLY,
    mode: 0o644,
    gid: 1000,
  },
  tlink: { kind: 'Tlink', tag: 11, dfid: 0, fid: 1, name: 'hardlink.txt' },
  tlopen: { kind: 'Tlopen', tag: 4, fid: 1, flags: C.O_RDONLY },
  tmkdir: { kind: 'Tmkdir', tag: 12, dfid: 0, name: 'archive', mode: 0o755, gid: 1000 },
  tread: { kind: 'Tread', tag: 17, fid: 1, offset: ABOVE_32_BIT, count: 4096 },
  treaddir: { kind: 'Treaddir', tag: 10, fid: 2, offset: 0n, count: 4096 },
  treadlink: { kind: 'Treadlink', tag: 7, fid: 3 },
  tremove: { kind: 'Tremove', tag: 20, fid: 2 },
  trename: { kind: 'Trename', tag: 13, fid: 1, dfid: 0, name: 'renamed.txt' },
  trenameat: {
    kind: 'Trenameat',
    tag: 14,
    olddirfid: 0,
    oldname: 'draft.txt',
    newdirfid: 2,
    newname: 'final.txt',
  },
  tsetattr: {
    kind: 'Tsetattr',
    tag: 9,
    fid: 1,
    valid:
      C.SETATTR_MODE |
      C.SETATTR_SIZE |
      C.SETATTR_ATIME |
      C.SETATTR_MTIME |
      C.SETATTR_ATIME_SET |
      C.SETATTR_MTIME_SET,
    mode: 0o600,
    uid: 0,
    gid: 0,
    size: 1024n,
    atimeSec: 0x69800e80n,
    atimeNsec: 0n,
    mtimeSec: 0x69800e81n,
    mtimeNsec: 0n,
  },
  tsymlink: {
    kind: 'Tsymlink',
    tag: 6,
    fid: 0,
    name: 'shortcut',
    symtgt: 'projects/draft.txt',
    gid: 1000,
  },
  tunlinkat: { kind: 'Tunlinkat', tag: 15, dirfid: 0, name: 'draft.txt', flags: 0 },
  'tunlinkat-removedir': {
    kind: 'Tunlinkat',
    tag: 16,
    dirfid: 0,
    name: 'archive',
    flags: C.AT_REMOVEDIR,
  },
  tversion: { kind: 'Tversion', tag: C.NOTAG, msize: C.MSIZE_CEILING, version: C.VERSION },
  twalk: { kind: 'Twalk', tag: 3, fid: 0, newfid: 1, wnames: ['projects', WIDE_NAME] },
  twrite: { kind: 'Twrite', tag: 18, fid: 1, offset: ABOVE_32_BIT, data: descending() },
};
