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
  NinepError,
  checkDeclaredSize,
  constants as C,
  decodeExact,
  encode,
  negotiateMsize,
} from '../src/ninep/codec.ts';
import type { Message } from '../src/ninep/codec.ts';
import * as profile from '../src/ninep/profile.ts';
import { ProfileRefusal } from '../src/ninep/profile.ts';

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

  /**
   * The count rule, exercised through `encode` and `decodeExact` rather than
   * through a helper. The first version of this suite called a helper that the
   * codec itself never invoked, so the rule was documented and unenforced: a
   * `Tread` with `count` 0xffffffff decoded happily at `msize` 4096.
   */
  describe('a count[4] must leave room for its own framing', () => {
    // A `Tread`/`Treaddir` reply is `count + 11`; an `Rwrite` may not
    // acknowledge more than a `Twrite` could have carried, which is
    // `msize - 23`.
    const cases: { kind: 'Tread' | 'Treaddir' | 'Rwrite'; overhead: number }[] = [
      { kind: 'Tread', overhead: 11 },
      { kind: 'Treaddir', overhead: 11 },
      { kind: 'Rwrite', overhead: 23 },
    ];

    const build = (kind: 'Tread' | 'Treaddir' | 'Rwrite', count: number): Message =>
      kind === 'Rwrite'
        ? { kind, tag: 1, count }
        : { kind, tag: 1, fid: 1, offset: 0n, count };

    for (const { kind, overhead } of cases) {
      for (const msize of [256, 4096, 65536]) {
        const limit = msize - overhead;

        it(`${kind} accepts count ${limit} at msize ${msize}, in both directions`, () => {
          const bytes = encode(build(kind, limit), { msize });
          assert.deepEqual(decodeExact(bytes, { msize }), build(kind, limit));
        });

        it(`${kind} refuses count ${limit + 1} at msize ${msize}, in both directions`, () => {
          assert.throws(() => encode(build(kind, limit + 1), { msize }), {
            reason: 'CountAboveMsize',
            field: 'count',
          });
          // And on the wire: encode at a wider msize, then decode under this
          // one. At the ceiling there is no wider msize, so patch the count in.
          const wide =
            msize < C.MSIZE_CEILING
              ? encode(build(kind, limit + 1), { msize: C.MSIZE_CEILING })
              : (() => {
                  const bytes = encode(build(kind, limit), { msize });
                  const at = kind === 'Rwrite' ? C.HEADER_BYTES : C.HEADER_BYTES + 12;
                  new DataView(bytes.buffer).setUint32(at, limit + 1, true);
                  return bytes;
                })();
          assert.throws(() => decodeExact(wide, { msize }), { reason: 'CountAboveMsize' });
        });
      }
    }

    it('refuses the three probes that passed before the rule was wired up', () => {
      // Tread count = 0xffffffff at msize 4096.
      const tread = encode({ kind: 'Tread', tag: 1, fid: 1, offset: 0n, count: 0 });
      new DataView(tread.buffer).setUint32(C.HEADER_BYTES + 12, 0xffffffff, true);
      assert.throws(() => decodeExact(tread, { msize: 4096 }), { reason: 'CountAboveMsize' });

      // Treaddir count = 4096 at msize 4096 — exactly msize, so 11 bytes over.
      assert.throws(
        () => encode({ kind: 'Treaddir', tag: 1, fid: 1, offset: 0n, count: 4096 }, { msize: 4096 }),
        { reason: 'CountAboveMsize' },
      );

      // Rwrite count = 0xffffffff at msize 256.
      const rwrite = encode({ kind: 'Rwrite', tag: 1, count: 0 });
      new DataView(rwrite.buffer).setUint32(C.HEADER_BYTES, 0xffffffff, true);
      assert.throws(() => decodeExact(rwrite, { msize: 256 }), { reason: 'CountAboveMsize' });
    });

    it('an Rread frame is exactly count + 11', () => {
      assert.equal(encode(rreadOfSize(65536)).byteLength, 65525 + 11);
    });
  });
});

describe('Writer range checks', () => {
  it('refuses an out-of-range integer rather than truncating it', () => {
    // `DataView` truncates silently, so without these checks `encode(x)` would
    // decode to something other than `x`.
    assert.throws(() => encode({ kind: 'Tclunk', tag: 1, fid: 2 ** 32 }), {
      reason: 'FieldOutOfRange',
      field: 'fid',
    });
    assert.throws(() => encode({ kind: 'Tclunk', tag: 1, fid: -1 }), {
      reason: 'FieldOutOfRange',
      field: 'fid',
    });
    assert.throws(() => encode({ kind: 'Tclunk', tag: 1, fid: 1.5 }), {
      reason: 'FieldOutOfRange',
      field: 'fid',
    });
    assert.throws(() => encode({ kind: 'Tflush', tag: 1, oldtag: 70000 }), {
      reason: 'FieldOutOfRange',
      field: 'oldtag',
    });
    assert.throws(() => encode({ kind: 'Tread', tag: 1, fid: 1, offset: -1n, count: 16 }), {
      reason: 'FieldOutOfRange',
      field: 'offset',
    });
    assert.throws(() => encode({ kind: 'Tread', tag: 1, fid: 1, offset: 1n << 64n, count: 16 }), {
      reason: 'FieldOutOfRange',
      field: 'offset',
    });
    assert.throws(
      () =>
        encode({
          kind: 'Rattach',
          tag: 1,
          qid: { type: C.QTDIR, version: 2 ** 32, path: 1n },
        }),
      { reason: 'FieldOutOfRange', field: 'qid.version' },
    );
  });

  it('a Tclunk fid of -1 does not silently become NOFID', () => {
    assert.throws(() => encode({ kind: 'Tclunk', tag: 1, fid: -1 }), {
      reason: 'FieldOutOfRange',
    });
    // The value that *is* NOFID still encodes, so the refusal is about range
    // and not about the sentinel.
    const bytes = encode({ kind: 'Tclunk', tag: 1, fid: C.NOFID });
    assert.equal((decodeExact(bytes) as { fid: number }).fid, C.NOFID);
  });

  it('every field at its exact width is accepted', () => {
    const bytes = encode({
      kind: 'Tread',
      tag: 0xfffe,
      fid: 0xffffffff,
      offset: 0xffff_ffff_ffff_ffffn,
      count: 65525,
    });
    const decoded = decodeExact(bytes) as { fid: number; offset: bigint };
    assert.equal(decoded.fid, 0xffffffff);
    assert.equal(decoded.offset, 0xffff_ffff_ffff_ffffn);
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

  it('a short buffer that still carries a declared size is judged by that size', () => {
    // Aligned with the Rust, which reads `size[4]` and reports its header-floor
    // error rather than a generic truncation. A 4-to-6-byte buffer declaring
    // `size < 7` is below the floor; one declaring a sound size just ran out.
    const belowFloor = Uint8Array.of(3, 0, 0, 0, 0, 0);
    assert.throws(() => decodeExact(belowFloor), { reason: 'HeaderFloor', field: 'size' });

    const soundButShort = Uint8Array.of(11, 0, 0, 0, 0, 0);
    assert.throws(() => decodeExact(soundButShort), { reason: 'TruncatedBody' });

    // Fewer than four bytes carry no declared size at all.
    for (const length of [0, 1, 2, 3]) {
      assert.throws(() => decodeExact(new Uint8Array(length)), {
        reason: 'TruncatedBody',
        field: 'size',
      });
    }
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
    // Derived from this implementation's own table, not asserted against the
    // Rust's count: the cross-check is that the two tables agree on which
    // opcodes they hold, and pinning a literal 25 here would only be alignment
    // to the Rust. That the two now agree at 25 is the finding, not the test.
    assert.equal(notInProfile, C.KNOWN_OPCODES_NOT_IN_PROFILE.size);
    assert.equal(unknown, 215 - C.KNOWN_OPCODES_NOT_IN_PROFILE.size);
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

  it('never produces the replacement character: no string is returned at all', () => {
    // The earlier version of this test ran its U+FFFD search on
    // `JSON.stringify(null)`, because decoding had thrown — it could not have
    // failed. The substantive claim is that no string comes back, so assert
    // that directly, and separately prove U+FFFD is not simply unreachable.
    const bytes = encode({ kind: 'Rreadlink', tag: 1, target: 'xx' });
    const corrupted = corruptStringAt(bytes, C.HEADER_BYTES, [0xff, 0xfe]);

    let decoded: unknown = 'not-assigned';
    let caught: unknown;
    try {
      decoded = decodeExact(corrupted);
    } catch (error) {
      caught = error;
    }
    assert.equal(decoded, 'not-assigned', 'decodeExact must not return a value');
    assert.ok(caught instanceof NinepError);
    assert.equal((caught as NinepError).reason, 'InvalidUtf8');
    assert.equal((caught as NinepError).field, 'target');

    // And the decoder *can* return U+FFFD when it is genuinely in the bytes, so
    // the assertion above is about refusal and not about an unreachable path.
    const legitimate = encode({ kind: 'Rreadlink', tag: 1, target: '�' });
    assert.equal((decodeExact(legitimate) as { target: string }).target, '�');
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

describe('the .L flag and mask rules are Rlerror-answerable, not framing failures', () => {
  /*
   * This suite moved out of the codec. The first version of this file checked
   * the flag and mask sets inside `encode`/`decodeExact`, where every failure
   * is a `NinepError` — which this client's own taxonomy defines as a framing
   * failure answered by closing with 1002.
   *
   * That was a WIRE-VISIBLE disagreement with the Rust, not a diagnostic one.
   * In `crates/tunnel-fs-ninep` the flag decoding lives in `session.rs`, not in
   * the codec: `Tlopen` with `O_CREAT` decodes cleanly, the session answers
   * `Rlerror(ENOTSUP)` on its own tag and stays open. The contract names "a
   * flag the profile denies" among the refusals a correct client can recover
   * from. Closing the session instead would take down every other outstanding
   * tag on it.
   *
   * So the codec now decodes `flags[4]` and the mask words as opaque integers,
   * and these checks live in `src/ninep/profile.ts` behind a separate
   * `ProfileRefusal` type that carries the errno an `Rlerror` would.
   */

  it('a denied flag decodes cleanly through the codec and does NOT close the session', () => {
    const bytes = encode({ kind: 'Tlopen', tag: 1, fid: 1, flags: C.O_WRONLY | C.O_CREAT });
    const decoded = decodeExact(bytes) as { flags: number };
    assert.equal(decoded.flags, C.O_WRONLY | C.O_CREAT);
    // The refusal is the session's, and it is answerable.
    let caught: unknown;
    try {
      profile.checkTlopenFlags(decoded.flags);
    } catch (error) {
      caught = error;
    }
    assert.ok(caught instanceof ProfileRefusal, 'expected a ProfileRefusal');
    assert.equal(caught.errno, 'ENOTSUP');
    assert.equal(caught.reason, 'FlagNotInProfile');
    // The distinction that matters: this is NOT a framing failure, so it does
    // not take the session down with a 1002 close.
    assert.ok(!(caught instanceof NinepError), 'must not be a framing failure');
  });

  const tlopen = (flags: number) => () => profile.checkTlopenFlags(flags);

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
      assert.doesNotThrow(tlopen(flags), `flags ${flags}`);
    }
  });

  it('refuses O_CREAT and O_EXCL, because creation is Tlcreate', () => {
    assert.throws(tlopen(C.O_WRONLY | C.O_CREAT), { reason: 'FlagNotInProfile', errno: 'ENOTSUP' });
    assert.throws(tlopen(C.O_WRONLY | C.O_EXCL), { reason: 'FlagNotInProfile', errno: 'ENOTSUP' });
  });

  it('refuses access mode 3, a read-only mutating open, and a writable O_DIRECTORY', () => {
    assert.throws(tlopen(3), { reason: 'FlagNotInProfile', field: 'flags.accmode' });
    assert.throws(tlopen(C.O_RDONLY | C.O_TRUNC), { field: 'flags.readonly-mutating' });
    assert.throws(tlopen(C.O_RDONLY | C.O_APPEND), { field: 'flags.readonly-mutating' });
    assert.throws(tlopen(C.O_WRONLY | C.O_DIRECTORY), { field: 'flags.directory-mutating' });
    assert.throws(tlopen(C.O_WRONLY | C.O_DIRECTORY | C.O_TRUNC), {
      field: 'flags.directory-mutating',
    });
    // A read-only truncating O_DIRECTORY violates two rules; the read-only one
    // is checked first, so one input has one answer here too.
    assert.throws(tlopen(C.O_RDONLY | C.O_DIRECTORY | C.O_TRUNC), {
      field: 'flags.readonly-mutating',
    });
  });

  it("Tsetattr's mask excludes uid, gid and ctime, and an empty mask is refused", () => {
    assert.throws(() => profile.checkTsetattrMask(0), { reason: 'EmptyMask' });
    for (const excluded of [C.SETATTR_UID, C.SETATTR_GID, C.SETATTR_CTIME]) {
      assert.throws(() => profile.checkTsetattrMask(C.SETATTR_MODE | excluded), {
        reason: 'MaskNotInProfile',
        errno: 'ENOTSUP',
      });
    }
    assert.doesNotThrow(() => profile.checkTsetattrMask(C.TSETATTR_VALID_MASK));
    // And the codec carries an excluded bit through untouched, as the Rust does.
    const bytes = encode({
      kind: 'Tsetattr',
      tag: 1,
      fid: 1,
      valid: C.SETATTR_MODE | C.SETATTR_UID,
      mode: 0o600,
      uid: 0,
      gid: 0,
      size: 0n,
      atimeSec: 0n,
      atimeNsec: 0n,
      mtimeSec: 0n,
      mtimeNsec: 0n,
    });
    assert.equal((decodeExact(bytes) as { valid: number }).valid, C.SETATTR_MODE | C.SETATTR_UID);
  });

  it("Tgetattr's request_mask is bounded and may not be zero", () => {
    assert.throws(() => profile.checkTgetattrMask(0n), { reason: 'EmptyMask' });
    assert.throws(() => profile.checkTgetattrMask(BigInt(C.GETATTR_ALL) + 1n), {
      reason: 'MaskNotInProfile',
    });
    assert.doesNotThrow(() => profile.checkTgetattrMask(BigInt(C.GETATTR_BASIC)));
    assert.doesNotThrow(() => profile.checkTgetattrMask(BigInt(C.GETATTR_ALL)));
  });

  it('Tunlinkat accepts only AT_REMOVEDIR', () => {
    assert.doesNotThrow(() => profile.checkTunlinkatFlags(0));
    assert.doesNotThrow(() => profile.checkTunlinkatFlags(C.AT_REMOVEDIR));
    assert.throws(() => profile.checkTunlinkatFlags(1), { reason: 'FlagNotInProfile' });
    assert.throws(() => profile.checkTunlinkatFlags(C.AT_REMOVEDIR | 1), {
      reason: 'FlagNotInProfile',
    });
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

describe('field layout, independent of the fixtures', () => {
  /*
   * The fixtures cannot catch a transposed `uid`/`gid` in `Rgetattr`: both are
   * 1000 there, both are 0 in `Tsetattr`, `atimeNsec` and `mtimeNsec` are both
   * 0, and `Tattach`'s `uname` and `aname` are both empty. A swap of any such
   * pair is invisible to a fixture comparison on either side.
   *
   * These build the three messages with all-distinct sentinels and assert the
   * bytes at the offsets the 9P2000.L definition gives, so the layout is pinned
   * by the spec rather than by a fixture that cannot see the difference.
   */
  const u32At = (bytes: Uint8Array, at: number): number =>
    new DataView(bytes.buffer, bytes.byteOffset).getUint32(at, true);
  const u64At = (bytes: Uint8Array, at: number): bigint =>
    new DataView(bytes.buffer, bytes.byteOffset).getBigUint64(at, true);

  it('Rgetattr: valid[8] qid[13] mode[4] uid[4] gid[4] then sixteen 8-byte fields', () => {
    const bytes = encode({
      kind: 'Rgetattr',
      tag: 1,
      valid: 0x11n,
      qid: { type: C.QTFILE, version: 0x22, path: 0x33n },
      mode: 0x44,
      uid: 0x55,
      gid: 0x66,
      nlink: 0x77n,
      rdev: 0x88n,
      size: 0x99n,
      blksize: 0xaan,
      blocks: 0xbbn,
      atimeSec: 0xccn,
      atimeNsec: 0xddn,
      mtimeSec: 0xeen,
      mtimeNsec: 0xffn,
      ctimeSec: 0x111n,
      ctimeNsec: 0x222n,
      btimeSec: 0x333n,
      btimeNsec: 0x444n,
      gen: 0x555n,
      dataVersion: 0x666n,
    });
    assert.equal(bytes.byteLength, 7 + 153);
    let at = C.HEADER_BYTES;
    assert.equal(u64At(bytes, at), 0x11n, 'valid');
    at += 8;
    assert.equal(bytes[at], C.QTFILE, 'qid.type');
    assert.equal(u32At(bytes, at + 1), 0x22, 'qid.version');
    assert.equal(u64At(bytes, at + 5), 0x33n, 'qid.path');
    at += 13;
    assert.equal(u32At(bytes, at), 0x44, 'mode');
    assert.equal(u32At(bytes, at + 4), 0x55, 'uid');
    assert.equal(u32At(bytes, at + 8), 0x66, 'gid');
    at += 12;
    const tail = [0x77n, 0x88n, 0x99n, 0xaan, 0xbbn, 0xccn, 0xddn, 0xeen, 0xffn,
      0x111n, 0x222n, 0x333n, 0x444n, 0x555n, 0x666n];
    tail.forEach((expected, index) => {
      assert.equal(u64At(bytes, at + index * 8), expected, `tail field ${index}`);
    });
    // uid and gid are distinct here, so a transposition would be caught.
    assert.notEqual(u32At(bytes, C.HEADER_BYTES + 8 + 13 + 4), u32At(bytes, C.HEADER_BYTES + 8 + 13 + 8));
  });

  it('Tsetattr: fid[4] valid[4] mode[4] uid[4] gid[4] size[8] then four 8-byte times', () => {
    const bytes = encode({
      kind: 'Tsetattr',
      tag: 1,
      fid: 0x11,
      valid: C.TSETATTR_VALID_MASK,
      mode: 0x33,
      uid: 0x44,
      gid: 0x55,
      size: 0x66n,
      atimeSec: 0x77n,
      atimeNsec: 0x88n,
      mtimeSec: 0x99n,
      mtimeNsec: 0xaan,
    });
    assert.equal(bytes.byteLength, 67);
    const at = C.HEADER_BYTES;
    assert.equal(u32At(bytes, at), 0x11, 'fid');
    assert.equal(u32At(bytes, at + 4), C.TSETATTR_VALID_MASK, 'valid');
    assert.equal(u32At(bytes, at + 8), 0x33, 'mode');
    assert.equal(u32At(bytes, at + 12), 0x44, 'uid');
    assert.equal(u32At(bytes, at + 16), 0x55, 'gid');
    assert.equal(u64At(bytes, at + 20), 0x66n, 'size');
    assert.equal(u64At(bytes, at + 28), 0x77n, 'atime_sec');
    assert.equal(u64At(bytes, at + 36), 0x88n, 'atime_nsec');
    assert.equal(u64At(bytes, at + 44), 0x99n, 'mtime_sec');
    assert.equal(u64At(bytes, at + 52), 0xaan, 'mtime_nsec');
  });

  it('Tattach: fid[4] afid[4] uname[s] aname[s] n_uname[4], with uname != aname', () => {
    const bytes = encode({
      kind: 'Tattach',
      tag: 1,
      fid: 0x11,
      afid: 0x22,
      uname: 'uuu',
      aname: 'aaaaa',
      nUname: 0x33,
    });
    const at = C.HEADER_BYTES;
    assert.equal(u32At(bytes, at), 0x11, 'fid');
    assert.equal(u32At(bytes, at + 4), 0x22, 'afid');
    const unameLen = new DataView(bytes.buffer, bytes.byteOffset).getUint16(at + 8, true);
    assert.equal(unameLen, 3, 'uname length precedes aname');
    const anameAt = at + 10 + unameLen;
    assert.equal(
      new DataView(bytes.buffer, bytes.byteOffset).getUint16(anameAt, true),
      5,
      'aname length',
    );
    assert.equal(u32At(bytes, anameAt + 2 + 5), 0x33, 'n_uname');
    // Round-trips with the two strings distinguishable.
    const decoded = decodeExact(bytes) as { uname: string; aname: string };
    assert.equal(decoded.uname, 'uuu');
    assert.equal(decoded.aname, 'aaaaa');
  });
});
