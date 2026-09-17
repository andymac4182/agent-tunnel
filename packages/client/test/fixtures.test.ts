/**
 * The cross-check: every checked-in gate-3 fixture, read by a second
 * implementation, in both directions.
 *
 * Gate 3 recorded the fixtures as explicitly NOT proven — "no second
 * implementation has read them". This file is that second implementation.
 */

import { strict as assert } from 'node:assert';
import { describe, it } from 'node:test';

import { FrameDecoder, constants as C, decodeExact, encode } from '../src/ninep/codec.ts';
import { EXPECTED, WIDE_NAME } from './expected.ts';
import { loadFixtures, loadIndex } from './fixtures.ts';

const fixtures = loadFixtures();

describe('fixture corpus', () => {
  it('index.txt and the directory agree', () => {
    assert.deepEqual(
      loadIndex().slice().sort(),
      fixtures.map((fixture) => `${fixture.id}.hex`).sort(),
    );
  });

  it('every message type in the profile has a fixture', () => {
    const covered = new Set(
      fixtures.map((fixture) => decodeExact(fixture.bytes).kind as string),
    );
    const missing = Object.keys(C.MESSAGE_TYPES).filter((name) => !covered.has(name));
    assert.deepEqual(missing, [], 'message types with no fixture');
    assert.equal(covered.size, 41, 'the profile is 41 message types');
  });

  it('there is an expectation for every fixture and no orphan expectations', () => {
    assert.deepEqual(
      Object.keys(EXPECTED).sort(),
      fixtures.map((fixture) => fixture.id).sort(),
    );
  });
});

for (const fixture of fixtures) {
  describe(`fixture ${fixture.id}`, () => {
    it('decodes to the fields the README and contract say it carries', () => {
      const decoded = decodeExact(fixture.bytes, { msize: fixture.declaredMsize });
      assert.deepEqual(decoded, EXPECTED[fixture.id]);
    });

    it('agrees with its own header comment', () => {
      const decoded = decodeExact(fixture.bytes, { msize: fixture.declaredMsize });
      assert.equal(decoded.kind, fixture.declaredType);
      assert.equal(C.MESSAGE_TYPES[decoded.kind], fixture.declaredOpcode);
      assert.equal(decoded.tag, fixture.declaredTag);
      assert.equal(fixture.bytes.byteLength, fixture.declaredSize);
      assert.equal(fixture.declaredMsize, C.MSIZE_CEILING);
      assert.equal(fixture.declaredName, fixture.id);
    });

    it('re-encodes byte for byte', () => {
      const decoded = decodeExact(fixture.bytes, { msize: fixture.declaredMsize });
      assert.deepEqual(encode(decoded, { msize: fixture.declaredMsize }), fixture.bytes);
    });

    it('re-encodes byte for byte from the hand-written expectation alone', () => {
      // Not a round trip: this encodes the table in `expected.ts`, so a decoder
      // bug cannot cancel an encoder bug here.
      assert.deepEqual(
        encode(EXPECTED[fixture.id]!, { msize: fixture.declaredMsize }),
        fixture.bytes,
      );
    });

    it('is rejected one byte short and with one byte of trailing padding', () => {
      assert.throws(
        () => decodeExact(fixture.bytes.subarray(0, fixture.bytes.byteLength - 1)),
        { reason: 'TruncatedBody' },
      );
      const padded = new Uint8Array(fixture.bytes.byteLength + 1);
      padded.set(fixture.bytes, 0);
      assert.throws(() => decodeExact(padded), { reason: 'TrailingBytes' });
    });
  });
}

describe('what the bytes pin, per fixtures/README.md', () => {
  it('64-bit fields decode as BigInt, including values above 2^32', () => {
    const tread = decodeExact(
      fixtures.find((fixture) => fixture.id === 'tread')!.bytes,
    );
    assert.equal(tread.kind, 'Tread');
    assert.equal(typeof (tread as { offset: bigint }).offset, 'bigint');
    assert.ok((tread as { offset: bigint }).offset > 0xffffffffn);

    const rgetattr = decodeExact(
      fixtures.find((fixture) => fixture.id === 'rgetattr')!.bytes,
    );
    assert.equal(typeof (rgetattr as { size: bigint }).size, 'bigint');
    assert.ok((rgetattr as { size: bigint }).size > 0xffffffffn);
    // The value the README says a `number` client would not survive is exactly
    // representable as a double, so "a number would fail" is a claim about the
    // *type* it is decoded into, not about precision loss at this value.
    assert.equal(Number((rgetattr as { size: bigint }).size), 2 ** 32);
  });

  it('string[s] is a 16-bit BYTE count of UTF-8, not a character or UTF-16 count', () => {
    assert.equal(WIDE_NAME.length, 7, 'UTF-16 code units');
    assert.equal([...WIDE_NAME].length, 6, 'code points');
    assert.equal(new TextEncoder().encode(WIDE_NAME).byteLength, 10, 'UTF-8 bytes');

    const twalk = decodeExact(fixtures.find((fixture) => fixture.id === 'twalk')!.bytes);
    assert.deepEqual((twalk as { wnames: string[] }).wnames, ['projects', WIDE_NAME]);
    // The declared length in the frame is the byte count, read straight out.
    const bytes = fixtures.find((fixture) => fixture.id === 'twalk')!.bytes;
    const declared = new DataView(bytes.buffer, bytes.byteOffset).getUint16(
      bytes.byteLength - 12,
      true,
    );
    assert.equal(declared, 10);
  });

  it('only QTFILE, QTDIR and QTSYMLINK appear, and nothing else would be accepted', () => {
    const seen = new Set<number>();
    for (const fixture of fixtures) {
      const message = decodeExact(fixture.bytes) as unknown as Record<string, unknown>;
      if (message.qid !== undefined) {
        seen.add((message.qid as { type: number }).type);
      }
      for (const qid of (message.wqids as { type: number }[] | undefined) ?? []) {
        seen.add(qid.type);
      }
      for (const entry of (message.entries as { qid: { type: number } }[] | undefined) ?? []) {
        seen.add(entry.qid.type);
      }
    }
    assert.deepEqual([...seen].sort((a, b) => a - b), [C.QTFILE, C.QTSYMLINK, C.QTDIR]);

    // A bit outside the three is refused, not masked off.
    const rattach = fixtures.find((fixture) => fixture.id === 'rattach')!.bytes.slice();
    for (let byte = 0; byte < 256; byte += 1) {
      rattach[7] = byte;
      if (C.QID_TYPES.has(byte)) {
        assert.doesNotThrow(() => decodeExact(rattach));
      } else {
        assert.throws(() => decodeExact(rattach), { reason: 'QidType' }, `qid type ${byte}`);
      }
    }
  });

  it("Rreaddir's block has no count of its own and a part-record is malformed", () => {
    const bytes = fixtures.find((fixture) => fixture.id === 'rreaddir')!.bytes;
    const message = decodeExact(bytes) as { entries: unknown[] };
    assert.equal(message.entries.length, 3);

    // Shrink the declared block count by one byte and keep the frame consistent:
    // the last record now ends part-way through its name.
    const truncated = bytes.slice(0, bytes.byteLength - 1);
    const view = new DataView(truncated.buffer);
    view.setUint32(0, truncated.byteLength, true);
    view.setUint32(C.HEADER_BYTES, truncated.byteLength - C.HEADER_BYTES - 4, true);
    assert.throws(() => decodeExact(truncated), { reason: 'MalformedDirentBlock' });
  });

  it("an Rreaddir record's type byte must agree with its qid", () => {
    const bytes = fixtures.find((fixture) => fixture.id === 'rreaddir')!.bytes.slice();
    // The first record's dirent byte sits after `qid[13] offset[8]` of the block.
    const at = C.HEADER_BYTES + 4 + 13 + 8;
    assert.equal(bytes[at], C.DT_DIR);
    bytes[at] = C.DT_REG;
    assert.throws(() => decodeExact(bytes), { reason: 'DirentTypeDisagreesWithQid' });
  });

  it('Rlerror carries a Linux errno from the closed fourteen-code vocabulary', () => {
    const bytes = fixtures.find((fixture) => fixture.id === 'rlerror-enoent')!.bytes.slice();
    assert.equal(C.ERRNO_NAME_BY_NUMBER.size, 14);
    const view = new DataView(bytes.buffer);
    for (const errno of [0, 3, 4, 5, 11, 28, 38, 96, 0xffffffff]) {
      view.setUint32(C.HEADER_BYTES, errno, true);
      assert.throws(() => decodeExact(bytes), { reason: 'ErrnoNotInVocabulary' }, `errno ${errno}`);
    }
    for (const errno of C.ERRNO_NAME_BY_NUMBER.keys()) {
      view.setUint32(C.HEADER_BYTES, errno, true);
      assert.doesNotThrow(() => decodeExact(bytes), `errno ${errno}`);
    }
  });

  it('every integer is little-endian: a byte-swapped frame does not decode the same', () => {
    // `Tclunk`'s fid is the whole body, so swapping it is unambiguous.
    const bytes = fixtures.find((fixture) => fixture.id === 'tclunk')!.bytes.slice();
    assert.equal((decodeExact(bytes) as { fid: number }).fid, 1);
    bytes.set([0, 0, 0, 1], C.HEADER_BYTES);
    assert.equal((decodeExact(bytes) as { fid: number }).fid, 0x01000000);
  });
});

describe('the whole corpus over a tunnel byte stream', () => {
  const stream = (() => {
    const total = fixtures.reduce((sum, fixture) => sum + fixture.bytes.byteLength, 0);
    const out = new Uint8Array(total);
    let at = 0;
    for (const fixture of fixtures) {
      out.set(fixture.bytes, at);
      at += fixture.bytes.byteLength;
    }
    return out;
  })();

  it('decodes as one ordered stream, whole', () => {
    const decoder = new FrameDecoder();
    const { messages, error } = decoder.push(stream);
    assert.equal(error, undefined);
    assert.equal(messages.length, fixtures.length);
    assert.equal(decoder.retainedBytes, 0);
    messages.forEach((message, index) => {
      assert.deepEqual(message, EXPECTED[fixtures[index]!.id]);
    });
  });

  it('decodes identically at every single split point, content included', () => {
    // This compared only `messages.length` before. A subarray or byteOffset bug
    // producing wrong-but-complete frames would have passed it, while the docs
    // claimed the corpus "decodes identically" at every cut. Compare content.
    const expected = fixtures.map((fixture) => EXPECTED[fixture.id]);
    for (let cut = 0; cut <= stream.byteLength; cut += 1) {
      const decoder = new FrameDecoder();
      const first = decoder.push(stream.subarray(0, cut)).messages;
      // Asserted after the FIRST push, where it is not vacuous: the decoder is
      // mid-frame for most cuts and is genuinely holding a partial frame.
      assert.ok(
        decoder.retainedBytes <= C.MSIZE_CEILING,
        `retained ${decoder.retainedBytes} at cut ${cut}`,
      );
      const messages = [...first, ...decoder.push(stream.subarray(cut)).messages];
      assert.deepEqual(messages, expected, `cut at ${cut}`);
      assert.equal(decoder.retainedBytes, 0, `nothing retained after cut ${cut}`);
    }
  });

  it('holds a genuinely partial frame at a mid-frame cut, so the bound above is not vacuous', () => {
    // The largest fixture is `twrite` at 279 bytes; cutting inside it leaves
    // real retained bytes rather than zero.
    const cut = stream.byteLength - 100;
    const decoder = new FrameDecoder();
    decoder.push(stream.subarray(0, cut));
    assert.ok(decoder.retainedBytes > 0, 'expected the decoder to be mid-frame');
    assert.ok(decoder.retainedBytes <= C.MSIZE_CEILING);
  });

  it('decodes identically one byte at a time', () => {
    const decoder = new FrameDecoder();
    const messages: unknown[] = [];
    for (const byte of stream) {
      messages.push(...decoder.push(Uint8Array.of(byte)).messages);
    }
    assert.equal(messages.length, fixtures.length);
    messages.forEach((message, index) => {
      assert.deepEqual(message, EXPECTED[fixtures[index]!.id]);
    });
  });

  it('refuses the same stream through decodeExact, which wants exactly one message', () => {
    assert.throws(() => decodeExact(stream), { reason: 'TrailingBytes' });
  });
});
