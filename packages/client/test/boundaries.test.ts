/**
 * The boundary and refusal behaviour `docs/filesystem-api.md` pins, so far as
 * it is expressible without a socket: the size-check order, the `msize`
 * boundaries, the UTF-8 refusal, malformed-frame rejection, and the flag and
 * mask sets.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import {
  FrameDecoder,
  checkDeclaredSize,
  checkReadCount,
  constants as C,
  decodeExact,
  encode,
  negotiateMsize,
} from '../src/ninep/codec.ts';
import type { Message } from '../src/ninep/codec.ts';

/** An `Rread` padded to exactly `size` bytes. */
function rreadOfSize(size: number): Message {
  return { kind: 'Rread', tag: 1, data: new Uint8Array(size - C.HEADER_BYTES - 4) };
}

describe('msize negotiation reduces only', () => {
  it('255 is refused, 256 is accepted', () => {
    assert.throws(() => negotiateMsize(255), { reason: 'MsizeBelowFloor' });
    assert.equal(negotiateMsize(256), 256);
  });

  it('65,536 is accepted and 65,537 is reduced to it', () => {
    assert.equal(negotiateMsize(65536), 65536);
    assert.equal(negotiateMsize(65537), 65536);
  });

  it('never raises an offer above the server maximum', () => {
    assert.equal(negotiateMsize(65536, 4096), 4096);
    assert.equal(negotiateMsize(1024, 4096), 1024);
  });

  it('a Tversion below the floor or above the ceiling is refused on the wire', () => {
    const bytes = encode({
      kind: 'Tversion',
      tag: C.NOTAG,
      msize: C.MSIZE_FLOOR,
      version: C.VERSION,
    });
    const view = new DataView(bytes.buffer);
    view.setUint32(C.HEADER_BYTES, 255, true);
    assert.throws(() => decodeExact(bytes), { reason: 'MsizeBelowFloor' });
    view.setUint32(C.HEADER_BYTES, C.MSIZE_CEILING + 1, true);
    assert.throws(() => decodeExact(bytes), { reason: 'OverCeiling' });
    view.setUint32(C.HEADER_BYTES, C.MSIZE_FLOOR, true);
    assert.doesNotThrow(() => decodeExact(bytes));
  });

  it('another dialect terminates rather than answering version "unknown"', () => {
    assert.throws(
      () => encode({ kind: 'Tversion', tag: C.NOTAG, msize: 65536, version: '9P2000' }),
      { reason: 'UnsupportedVersion' },
    );
    assert.throws(
      () => encode({ kind: 'Rversion', tag: C.NOTAG, msize: 65536, version: 'unknown' }),
      { reason: 'UnsupportedVersion' },
    );
  });
});

describe('the three size checks, in their fixed order', () => {
  it('below the seven-byte header floor reports the floor', () => {
    for (const size of [0, 1, 6]) {
      assert.throws(() => checkDeclaredSize(size, C.MSIZE_CEILING), { reason: 'HeaderFloor' });
    }
    assert.doesNotThrow(() => checkDeclaredSize(C.HEADER_BYTES, C.MSIZE_CEILING));
  });

  it('at msize 65,536 a frame one byte above reports the CEILING, not the negotiated bound', () => {
    // The visible consequence of the fixed order: it is over both, and the
    // ceiling is checked first, so one input has one answer.
    assert.throws(() => checkDeclaredSize(65537, 65536), { reason: 'OverCeiling' });
  });

  it('at a reduced msize a frame one byte above reports the negotiated bound', () => {
    assert.throws(() => checkDeclaredSize(4097, 4096), { reason: 'OverMsize' });
    assert.doesNotThrow(() => checkDeclaredSize(4096, 4096));
  });

  it('a frame exactly at msize is accepted and one byte above is refused, in both directions', () => {
    for (const msize of [256, 1024, 4096, 65536]) {
      const atLimit = rreadOfSize(msize);
      const bytes = encode(atLimit, { msize });
      assert.equal(bytes.byteLength, msize);
      assert.doesNotThrow(() => decodeExact(bytes, { msize }));

      const overByOne = rreadOfSize(msize + 1);
      const expected = msize === C.MSIZE_CEILING ? 'OverCeiling' : 'OverMsize';
      assert.throws(() => encode(overByOne, { msize }), { reason: expected }, `encode ${msize}`);

      // And on the way in: build it at the ceiling, then decode under `msize`.
      if (msize < C.MSIZE_CEILING) {
        const wide = encode(overByOne, { msize: C.MSIZE_CEILING });
        assert.throws(() => decodeExact(wide, { msize }), { reason: 'OverMsize' });
      }
    }
  });

  it('a count[4] must leave room for its own framing', () => {
    // A `Tread` asking for exactly `msize` bytes is refused: the `Rread`
    // carrying them would be `msize + 11`.
    assert.throws(() => checkReadCount(65536, 65536), {
      reason: 'CountLeavesNoRoomForFraming',
    });
    assert.throws(() => checkReadCount(65526, 65536), {
      reason: 'CountLeavesNoRoomForFraming',
    });
    assert.doesNotThrow(() => checkReadCount(65525, 65536));
    assert.equal(encode(rreadOfSize(65536)).byteLength, 65525 + 11);
  });
});

describe('malformed frames', () => {
  const tclunk = encode({ kind: 'Tclunk', tag: 3, fid: 1 });

  it('a declared size that disagrees with the buffer is refused in both directions', () => {
    const shorter = tclunk.slice();
    new DataView(shorter.buffer).setUint32(0, tclunk.byteLength - 1, true);
    assert.throws(() => decodeExact(shorter), { reason: 'TrailingBytes' });

    const longer = tclunk.slice();
    new DataView(longer.buffer).setUint32(0, tclunk.byteLength + 1, true);
    assert.throws(() => decodeExact(longer), { reason: 'TruncatedBody' });
  });

  it('two messages packed into one binary message are TrailingBytes', () => {
    const packed = new Uint8Array(tclunk.byteLength * 2);
    packed.set(tclunk, 0);
    packed.set(tclunk, tclunk.byteLength);
    assert.throws(() => decodeExact(packed), { reason: 'TrailingBytes' });
  });

  it('half a message is TruncatedBody at every cut', () => {
    for (let cut = 0; cut < tclunk.byteLength; cut += 1) {
      assert.throws(() => decodeExact(tclunk.subarray(0, cut)), { reason: 'TruncatedBody' }, `cut ${cut}`);
    }
  });

  it('a body with bytes left over is refused rather than ignored', () => {
    const padded = new Uint8Array(tclunk.byteLength + 4);
    padded.set(tclunk, 0);
    new DataView(padded.buffer).setUint32(0, padded.byteLength, true);
    assert.throws(() => decodeExact(padded), { reason: 'TrailingBytes' });
  });

  it('the stream decoder latches its first framing error', () => {
    const decoder = new FrameDecoder();
    const bad = tclunk.slice();
    bad[4] = 0xfe; // not a 9P opcode at all
    assert.throws(() => decoder.push(bad), { reason: 'UnknownMessageType' });
    assert.equal(decoder.isLatched, true);
    // A well-formed frame arriving after one is not decoded.
    assert.throws(() => decoder.push(tclunk), { reason: 'DecoderLatched' });
  });
});

describe('opcodes outside the profile', () => {
  it('all 215 non-profile opcodes are refused by one of the two reasons', () => {
    const bytes = encode({ kind: 'Tclunk', tag: 3, fid: 1 });
    let notInProfile = 0;
    let unknown = 0;
    for (let opcode = 0; opcode < 256; opcode += 1) {
      if (C.NAME_BY_OPCODE.has(opcode)) {
        continue;
      }
      bytes[4] = opcode;
      const expected = C.KNOWN_OPCODES_NOT_IN_PROFILE.has(opcode)
        ? 'MessageTypeNotInProfile'
        : 'UnknownMessageType';
      assert.throws(() => decodeExact(bytes), { reason: expected }, `opcode ${opcode}`);
      if (expected === 'MessageTypeNotInProfile') {
        notInProfile += 1;
      } else {
        unknown += 1;
      }
    }
    assert.equal(notInProfile + unknown, 215);
    assert.equal(C.NAME_BY_OPCODE.size, 41);
    // Pinned to the Rust `KNOWN_OUTSIDE_PROFILE`'s own count, which is where
    // the two implementations first disagreed. See the note on the constant.
    assert.equal(notInProfile, 25);
    assert.equal(unknown, 190);
  });

  it('Tlerror (6) and Terror (106) are reserved slots, not opcodes a peer can send', () => {
    const bytes = encode({ kind: 'Tclunk', tag: 3, fid: 1 });
    for (const reserved of [6, 106]) {
      bytes[4] = reserved;
      assert.throws(() => decodeExact(bytes), { reason: 'UnknownMessageType' }, `opcode ${reserved}`);
    }
    // Their siblings, which are real messages, are classified the other way.
    for (const real of [7, 107]) {
      bytes[4] = real;
      const expected = real === 7 ? undefined : 'MessageTypeNotInProfile';
      if (expected === undefined) {
        assert.ok(C.NAME_BY_OPCODE.has(real), 'Rlerror is in the profile');
      } else {
        assert.throws(() => decodeExact(bytes), { reason: expected }, `opcode ${real}`);
      }
    }
  });
});

describe('NOTAG', () => {
  it('is required by Tversion and Rversion, on encode and on decode', () => {
    assert.throws(() => encode({ kind: 'Tversion', tag: 0, msize: 65536, version: C.VERSION }), {
      reason: 'NotagRequired',
    });
    const bytes = encode({ kind: 'Tversion', tag: C.NOTAG, msize: 65536, version: C.VERSION });
    new DataView(bytes.buffer).setUint16(5, 0, true);
    assert.throws(() => decodeExact(bytes), { reason: 'NotagRequired' });
  });

  it('is forbidden everywhere else, on encode and on decode', () => {
    assert.throws(() => encode({ kind: 'Tclunk', tag: C.NOTAG, fid: 1 }), {
      reason: 'NotagForbidden',
    });
    const bytes = encode({ kind: 'Tclunk', tag: 1, fid: 1 });
    new DataView(bytes.buffer).setUint16(5, C.NOTAG, true);
    assert.throws(() => decodeExact(bytes), { reason: 'NotagForbidden' });
  });
});

describe('the UTF-8 refusal, by field and never by substitution', () => {
  /** Replace a `string[s]` payload in `bytes` at `at` with raw invalid bytes. */
  function corruptStringAt(bytes: Uint8Array, at: number, invalid: number[]): Uint8Array {
    const declared = new DataView(bytes.buffer, bytes.byteOffset).getUint16(at, true);
    assert.equal(declared, invalid.length, 'replacement must be the same byte length');
    const out = bytes.slice();
    out.set(invalid, at + 2);
    return out;
  }

  const invalidSequences: Record<string, number[]> = {
    'lone continuation byte': [0x80],
    'unfinished two-byte sequence': [0xc3],
    'overlong encoding of "/"': [0xc0, 0xaf],
    'surrogate half U+D800': [0xed, 0xa0, 0x80],
    'byte never valid in UTF-8': [0xff],
  };

  it('refuses a request name that is not valid UTF-8, naming the field', () => {
    for (const [label, invalid] of Object.entries(invalidSequences)) {
      const bytes = encode({
        kind: 'Tmkdir',
        tag: 1,
        dfid: 0,
        name: 'x'.repeat(invalid.length),
        mode: 0o755,
        gid: 1000,
      });
      const corrupted = corruptStringAt(bytes, C.HEADER_BYTES + 4, invalid);
      assert.throws(
        () => decodeExact(corrupted),
        (error: Error & { reason: string; field: string }) => {
          assert.equal(error.reason, 'InvalidUtf8', label);
          assert.equal(error.field, 'name', label);
          return true;
        },
      );
    }
  });

  it("refuses an Rreadlink target, so the rule covers a reply stream too", () => {
    const bytes = encode({ kind: 'Rreadlink', tag: 1, target: 'xx' });
    const corrupted = corruptStringAt(bytes, C.HEADER_BYTES, [0xc3, 0x28]);
    assert.throws(() => decodeExact(corrupted), { reason: 'InvalidUtf8', field: 'target' });
  });

  it('refuses a name inside an Rreaddir block', () => {
    const bytes = encode({
      kind: 'Rreaddir',
      tag: 1,
      entries: [
        {
          qid: { type: C.QTFILE, version: 0, path: 1n },
          offset: 1n,
          type: C.DT_REG,
          name: 'xx',
        },
      ],
    });
    const at = C.HEADER_BYTES + 4 + 13 + 8 + 1;
    const corrupted = corruptStringAt(bytes, at, [0xc3, 0x28]);
    assert.throws(() => decodeExact(corrupted), {
      reason: 'InvalidUtf8',
      field: 'entry.name',
    });
  });

  it('never produces the replacement character', () => {
    const bytes = encode({ kind: 'Rreadlink', tag: 1, target: 'xx' });
    const corrupted = corruptStringAt(bytes, C.HEADER_BYTES, [0xff, 0xfe]);
    let decoded: unknown;
    try {
      decoded = decodeExact(corrupted);
    } catch {
      decoded = undefined;
    }
    assert.equal(decoded, undefined);
    assert.ok(!JSON.stringify(decoded ?? null).includes('�'));
  });

  it('leaves Tread/Rread data and the Rreaddir block bytes untouched by the text rule', () => {
    // File content is bytes, not text: an arbitrary byte string round-trips.
    const data = Uint8Array.from({ length: 256 }, (_unused, index) => 255 - index);
    const bytes = encode({ kind: 'Rread', tag: 1, data });
    assert.deepEqual((decodeExact(bytes) as { data: Uint8Array }).data, data);
  });
});

describe('Twalk bounds', () => {
  const names = (count: number) => Array.from({ length: count }, (_unused, i) => `n${i}`);

  it('16 names is accepted and 17 is refused, on encode and decode', () => {
    const at = encode({ kind: 'Twalk', tag: 1, fid: 0, newfid: 1, wnames: names(16) });
    assert.deepEqual((decodeExact(at) as { wnames: string[] }).wnames, names(16));
    assert.throws(
      () => encode({ kind: 'Twalk', tag: 1, fid: 0, newfid: 1, wnames: names(17) }),
      { reason: 'TooManyWalkElements' },
    );
  });

  it('a declared count above MAXWELEM is refused before any element is reserved', () => {
    const bytes = encode({ kind: 'Twalk', tag: 1, fid: 0, newfid: 1, wnames: [] });
    new DataView(bytes.buffer).setUint16(C.HEADER_BYTES + 8, 0xffff, true);
    assert.throws(() => decodeExact(bytes), { reason: 'TooManyWalkElements', field: 'nwname' });
  });

  it('an Rwalk with more qids than MAXWELEM is a malformed reply', () => {
    const bytes = encode({ kind: 'Rwalk', tag: 1, wqids: [] });
    new DataView(bytes.buffer).setUint16(C.HEADER_BYTES, 17, true);
    assert.throws(() => decodeExact(bytes), { reason: 'TooManyWalkElements', field: 'nwqid' });
  });
});

describe('the .L flag and mask sets refuse rather than ignore', () => {
  const tlopen = (flags: number): Message => ({ kind: 'Tlopen', tag: 1, fid: 1, flags });

  it('Tlopen accepts only the access mode, O_TRUNC, O_APPEND, O_DIRECTORY and O_NOFOLLOW', () => {
    for (const flags of [
      C.O_RDONLY,
      C.O_WRONLY,
      C.O_RDWR,
      C.O_WRONLY | C.O_TRUNC,
      C.O_RDWR | C.O_APPEND,
      C.O_RDONLY | C.O_DIRECTORY,
      C.O_RDONLY | C.O_NOFOLLOW,
    ]) {
      assert.doesNotThrow(() => encode(tlopen(flags)), `flags ${flags}`);
    }
  });

  it('refuses O_CREAT and O_EXCL, because creation is Tlcreate', () => {
    assert.throws(() => encode(tlopen(C.O_WRONLY | C.O_CREAT)), { reason: 'FlagNotInProfile' });
    assert.throws(() => encode(tlopen(C.O_WRONLY | C.O_EXCL)), { reason: 'FlagNotInProfile' });
  });

  it('refuses access mode 3, a read-only mutating open, and a writable O_DIRECTORY', () => {
    assert.throws(() => encode(tlopen(3)), { reason: 'FlagNotInProfile', field: 'flags.accmode' });
    assert.throws(() => encode(tlopen(C.O_RDONLY | C.O_TRUNC)), {
      field: 'flags.readonly-mutating',
    });
    assert.throws(() => encode(tlopen(C.O_RDONLY | C.O_APPEND)), {
      field: 'flags.readonly-mutating',
    });
    assert.throws(() => encode(tlopen(C.O_WRONLY | C.O_DIRECTORY)), {
      field: 'flags.directory-mutating',
    });
    assert.throws(() => encode(tlopen(C.O_WRONLY | C.O_DIRECTORY | C.O_TRUNC)), {
      field: 'flags.directory-mutating',
    });
    // A read-only truncating O_DIRECTORY violates two rules; the read-only one
    // is checked first, so one input has one answer here too.
    assert.throws(() => encode(tlopen(C.O_RDONLY | C.O_DIRECTORY | C.O_TRUNC)), {
      field: 'flags.readonly-mutating',
    });
  });

  it("Tsetattr's mask excludes uid, gid and ctime, and an empty mask is refused", () => {
    const setattr = (valid: number): Message => ({
      kind: 'Tsetattr',
      tag: 1,
      fid: 1,
      valid,
      mode: 0o600,
      uid: 0,
      gid: 0,
      size: 0n,
      atimeSec: 0n,
      atimeNsec: 0n,
      mtimeSec: 0n,
      mtimeNsec: 0n,
    });
    assert.throws(() => encode(setattr(0)), { reason: 'EmptyMask' });
    for (const excluded of [C.SETATTR_UID, C.SETATTR_GID, C.SETATTR_CTIME]) {
      assert.throws(() => encode(setattr(C.SETATTR_MODE | excluded)), {
        reason: 'MaskNotInProfile',
      });
    }
    assert.doesNotThrow(() => encode(setattr(C.TSETATTR_VALID_MASK)));
  });

  it("Tgetattr's request_mask is bounded and may not be zero", () => {
    const getattr = (requestMask: bigint): Message => ({
      kind: 'Tgetattr',
      tag: 1,
      fid: 1,
      requestMask,
    });
    assert.throws(() => encode(getattr(0n)), { reason: 'EmptyMask' });
    assert.throws(() => encode(getattr(BigInt(C.GETATTR_ALL) + 1n)), {
      reason: 'MaskNotInProfile',
    });
    assert.doesNotThrow(() => encode(getattr(BigInt(C.GETATTR_BASIC))));
    assert.doesNotThrow(() => encode(getattr(BigInt(C.GETATTR_ALL))));
  });

  it('Tunlinkat accepts only AT_REMOVEDIR', () => {
    const unlink = (flags: number): Message => ({
      kind: 'Tunlinkat',
      tag: 1,
      dirfid: 0,
      name: 'x',
      flags,
    });
    assert.doesNotThrow(() => encode(unlink(0)));
    assert.doesNotThrow(() => encode(unlink(C.AT_REMOVEDIR)));
    assert.throws(() => encode(unlink(1)), { reason: 'FlagNotInProfile' });
    assert.throws(() => encode(unlink(C.AT_REMOVEDIR | 1)), { reason: 'FlagNotInProfile' });
  });

  it('the flag numbers are Linux values, written out', () => {
    assert.equal(C.O_TRUNC, 0o1000);
    assert.equal(C.O_APPEND, 0o2000);
    assert.equal(C.O_DIRECTORY, 0o200000);
    assert.equal(C.O_NOFOLLOW, 0o400000);
    assert.equal(C.AT_REMOVEDIR, 0x200);
    assert.equal(C.GETATTR_BASIC, 0x7ff);
    assert.equal(C.GETATTR_ALL, 0x3fff);
    assert.equal(C.TSETATTR_VALID_MASK, 0x1b9);
  });
});
