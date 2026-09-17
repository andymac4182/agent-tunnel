/**
 * The generated corpus the two 9P2000.L codecs are run against.
 *
 * `docs/testing.md` asks for "the incremental Rust and TypeScript codecs with
 * the same corpus" and for accepted values to be compared. Gate 3's residue is
 * explicit that its fixture cross-check is **not** that: a fixed corpus of 43
 * hand-built messages, checked on each side separately, generates no input.
 *
 * This generates input. It is deliberately **not** a mutation fuzzer over the
 * fixtures alone: a corpus built only by flipping bytes in valid frames spends
 * almost all of its cases in the truncation and unknown-opcode paths and almost
 * none inside a field. So the generator knows the wire *shape* of all 41
 * message types — the field order, not either codec's rules — and draws each
 * field from a pool of values chosen to sit on the boundaries the contract
 * pins. It then mutates a share of what it built, and mixes in pure noise.
 *
 * Nothing here imports the codec under test. The frames are laid out by a
 * byte writer of this file's own, so a rule either implementation gets wrong
 * cannot also be wrong in the generator and cancel out.
 */

import { Prng } from './prng.ts';

/** One case: bytes to decode, and the `msize` in force when they are decoded. */
export interface ExactCase {
  id: number;
  msize: number;
  transport: 'exact';
  /** Lower-case hex. */
  bytes: string;
}

/** One case for the stream decoder: the same bytes, delivered in chunks. */
export interface StreamCase {
  id: number;
  msize: number;
  transport: 'stream';
  /** Lower-case hex, one entry per push. */
  chunks: string[];
}

export type Case = ExactCase | StreamCase;

export const CORPUS_SEED = 0x5ca1ab1e9f2000n;
export const CORPUS_CASES = 4096;

/* ------------------------------------------------------------------ *
 * A byte writer that enforces nothing.
 * ------------------------------------------------------------------ */

class Raw {
  private parts: number[] = [];

  u8(value: number): void {
    this.parts.push(value & 0xff);
  }

  u16(value: number): void {
    this.u8(value);
    this.u8(value >>> 8);
  }

  u32(value: number): void {
    this.u16(value & 0xffff);
    this.u16((value >>> 16) & 0xffff);
  }

  u64(value: bigint): void {
    for (let index = 0n; index < 8n; index += 1n) {
      this.u8(Number((value >> (index * 8n)) & 0xffn));
    }
  }

  raw(bytes: Uint8Array): void {
    for (const byte of bytes) {
      this.parts.push(byte);
    }
  }

  get length(): number {
    return this.parts.length;
  }

  finish(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

/* ------------------------------------------------------------------ *
 * Value pools: the boundaries the contract pins, plus noise.
 * ------------------------------------------------------------------ */

const U32_POOL = [
  0, 1, 2, 3, 7, 11, 23, 63, 64, 255, 256, 4095, 4096, 4085, 65524, 65525, 65529, 65535, 65536,
  65537, 0x7fffffff, 0xfffffffe, 0xffffffff,
];

const U64_POOL = [
  0n,
  1n,
  255n,
  4096n,
  0xffffffffn,
  0x100000000n,
  0x1fffffffffffffn,
  0x20000000000000n,
  0x7fffffffffffffffn,
  0xfffffffffffffffen,
  0xffffffffffffffffn,
];

const TAG_POOL = [0, 1, 2, 63, 64, 0x1234, 0xfffe, 0xffff];

const QID_TYPE_POOL = [0x00, 0x02, 0x80, 0x01, 0x03, 0x08, 0x40, 0x81, 0x82, 0xff];

/**
 * Strings are emitted as raw length-prefixed bytes, so a sequence that is not
 * valid UTF-8 is expressible. That is the point: the contract's refusal is by
 * field and never by substitution, and both codecs must refuse the same bytes.
 */
const STRING_POOL: Uint8Array[] = [
  new Uint8Array(0),
  new TextEncoder().encode('notes.txt'),
  new TextEncoder().encode('9P2000.L'),
  new TextEncoder().encode('9P2000'),
  new TextEncoder().encode('9P2000.u'),
  new TextEncoder().encode(''),
  new TextEncoder().encode('.'),
  new TextEncoder().encode('..'),
  new TextEncoder().encode('café'),
  new TextEncoder().encode('\u{1d11e}'),
  new TextEncoder().encode('\u{fffd}'),
  new TextEncoder().encode('a/b'),
  new TextEncoder().encode('CON'),
  new TextEncoder().encode('x'.repeat(255)),
  new TextEncoder().encode('x'.repeat(300)),
  Uint8Array.from([0x80]),
  Uint8Array.from([0xc3]),
  Uint8Array.from([0xc3, 0x28]),
  Uint8Array.from([0xe0, 0x80, 0x80]),
  Uint8Array.from([0xed, 0xa0, 0x80]),
  Uint8Array.from([0xf8, 0x88, 0x80, 0x80]),
  Uint8Array.from([0x61, 0x00, 0x62]),
  Uint8Array.from([0xff, 0xfe]),
];

const MSIZE_POOL = [256, 512, 4096, 65536];

/** The 41 profile opcodes, plus known-outside and unknown bytes. */
const PROFILE_OPCODES = [
  7, 12, 13, 14, 15, 16, 17, 20, 21, 22, 23, 24, 25, 26, 27, 40, 41, 70, 71, 72, 73, 74, 75, 76, 77,
  100, 101, 104, 105, 108, 109, 110, 111, 116, 117, 118, 119, 120, 121, 122, 123,
];

const OTHER_OPCODES = [0, 1, 5, 6, 8, 9, 18, 30, 50, 52, 54, 102, 103, 106, 107, 112, 114, 124, 126, 200, 255];

type Field =
  | 'u8'
  | 'u16'
  | 'u32'
  | 'u64'
  | 'string'
  | 'qid'
  | 'counted'
  | 'walknames'
  | 'walkqids'
  | 'dirblock';

/**
 * The wire shape of every profile message, in field order.
 *
 * Transcribed from the 9P2000.L definition, not from either implementation.
 * A `counted` field is `count[4]` followed by that many raw bytes; `dirblock`
 * is `count[4]` followed by a packed `qid[13] offset[8] type[1] name[s]` array.
 */
const SHAPES = new Map<number, Field[]>([
  [7, ['u32']], // Rlerror ecode
  [12, ['u32', 'u32']], // Tlopen fid flags
  [13, ['qid', 'u32']], // Rlopen
  [14, ['u32', 'string', 'u32', 'u32', 'u32']], // Tlcreate
  [15, ['qid', 'u32']], // Rlcreate
  [16, ['u32', 'string', 'string', 'u32']], // Tsymlink
  [17, ['qid']], // Rsymlink
  [20, ['u32', 'u32', 'string']], // Trename
  [21, []], // Rrename
  [22, ['u32']], // Treadlink
  [23, ['string']], // Rreadlink
  [24, ['u32', 'u64']], // Tgetattr
  [
    25,
    [
      'u64',
      'qid',
      'u32',
      'u32',
      'u32',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
      'u64',
    ],
  ], // Rgetattr
  [26, ['u32', 'u32', 'u32', 'u32', 'u32', 'u64', 'u64', 'u64', 'u64', 'u64']], // Tsetattr
  [27, []], // Rsetattr
  [40, ['u32', 'u64', 'u32']], // Treaddir
  [41, ['dirblock']], // Rreaddir
  [70, ['u32', 'u32', 'string']], // Tlink
  [71, []], // Rlink
  [72, ['u32', 'string', 'u32', 'u32']], // Tmkdir
  [73, ['qid']], // Rmkdir
  [74, ['u32', 'string', 'u32', 'string']], // Trenameat
  [75, []], // Rrenameat
  [76, ['u32', 'string', 'u32']], // Tunlinkat
  [77, []], // Runlinkat
  [100, ['u32', 'string']], // Tversion
  [101, ['u32', 'string']], // Rversion
  [104, ['u32', 'u32', 'string', 'string', 'u32']], // Tattach
  [105, ['qid']], // Rattach
  [108, ['u16']], // Tflush
  [109, []], // Rflush
  [110, ['u32', 'u32', 'walknames']], // Twalk
  [111, ['walkqids']], // Rwalk
  [116, ['u32', 'u64', 'u32']], // Tread
  [117, ['counted']], // Rread
  [118, ['u32', 'u64', 'counted']], // Twrite
  [119, ['u32']], // Rwrite
  [120, ['u32']], // Tclunk
  [121, []], // Rclunk
  [122, ['u32']], // Tremove
  [123, []], // Rremove
]);

function writeString(rng: Prng, out: Raw): void {
  const value = rng.pick(STRING_POOL);
  // The declared length usually tells the truth. When it does not, the frame
  // is one where a `string[s]` runs off the end of its body or leaves bytes
  // behind, which is a boundary both codecs must take the same way.
  const declared = rng.chance(1, 12) ? rng.pick([0, 1, value.length + 1, 0xffff]) : value.length;
  out.u16(declared);
  out.raw(value);
}

function writeQid(rng: Prng, out: Raw): void {
  out.u8(rng.pick(QID_TYPE_POOL));
  out.u32(rng.pick(U32_POOL));
  out.u64(rng.pick(U64_POOL));
}

function writeField(rng: Prng, field: Field, out: Raw): void {
  switch (field) {
    case 'u8':
      out.u8(rng.below(256));
      return;
    case 'u16':
      out.u16(rng.pick(TAG_POOL));
      return;
    case 'u32':
      out.u32(rng.pick(U32_POOL));
      return;
    case 'u64':
      out.u64(rng.pick(U64_POOL));
      return;
    case 'string':
      writeString(rng, out);
      return;
    case 'qid':
      writeQid(rng, out);
      return;
    case 'counted': {
      const length = rng.pick([0, 1, 7, 64, 249, 250, 300, 4085, 4086]);
      const declared = rng.chance(1, 10) ? rng.pick(U32_POOL) : length;
      out.u32(declared);
      out.raw(rng.bytes(length));
      return;
    }
    case 'walknames': {
      const count = rng.pick([0, 1, 2, 15, 16, 17, 64, 0xffff]);
      const emitted = Math.min(count, 17);
      out.u16(count);
      for (let index = 0; index < emitted; index += 1) {
        writeString(rng, out);
      }
      return;
    }
    case 'walkqids': {
      const count = rng.pick([0, 1, 2, 15, 16, 17, 0xffff]);
      const emitted = Math.min(count, 17);
      out.u16(count);
      for (let index = 0; index < emitted; index += 1) {
        writeQid(rng, out);
      }
      return;
    }
    case 'dirblock': {
      const entries = rng.below(4);
      const block = new Raw();
      for (let index = 0; index < entries; index += 1) {
        const type = rng.pick(QID_TYPE_POOL);
        block.u8(type);
        block.u32(rng.pick(U32_POOL));
        block.u64(rng.pick(U64_POOL));
        block.u64(rng.pick(U64_POOL));
        // The dirent byte usually agrees with the qid, because the contract
        // requires it to; sometimes it does not, which is the rule under test.
        const agreeing = type === 0x80 ? 4 : type === 0x02 ? 10 : 8;
        block.u8(rng.chance(1, 6) ? rng.pick([0, 4, 8, 10, 14, 255]) : agreeing);
        writeString(rng, block);
      }
      let bytes = block.finish();
      if (rng.chance(1, 8) && bytes.length > 0) {
        // A block that ends part-way through a record.
        bytes = bytes.subarray(0, rng.below(bytes.length));
      }
      const declared = rng.chance(1, 12) ? rng.pick(U32_POOL) : bytes.length;
      out.u32(declared);
      out.raw(bytes);
      return;
    }
    default: {
      const exhaustive: never = field;
      return exhaustive;
    }
  }
}

/** One structurally shaped frame: a real header, a body laid out by its shape. */
function buildFrame(rng: Prng): Uint8Array {
  const inProfile = rng.chance(9, 10);
  const opcode = inProfile ? rng.pick(PROFILE_OPCODES) : rng.pick(OTHER_OPCODES);
  const shape = SHAPES.get(opcode) ?? [];
  const body = new Raw();
  for (const field of shape) {
    writeField(rng, field, body);
  }
  const bodyBytes = body.finish();
  const out = new Raw();
  const honest = 7 + bodyBytes.length;
  // The declared size usually tells the truth. When it lies, it lies in a way
  // that lands on one of the three size checks the contract fixes the order of.
  const size = rng.chance(1, 8)
    ? rng.pick([0, 1, 6, 7, honest - 1, honest + 1, 65536, 65537, 0xffffffff])
    : honest;
  out.u32(size);
  out.u8(opcode);
  out.u16(rng.pick(TAG_POOL));
  out.raw(bodyBytes);
  return out.finish();
}

function mutate(rng: Prng, bytes: Uint8Array): Uint8Array {
  const copy = Uint8Array.from(bytes);
  const operations = 1 + rng.below(3);
  for (let index = 0; index < operations; index += 1) {
    if (copy.length === 0) {
      break;
    }
    const at = rng.below(copy.length);
    switch (rng.below(4)) {
      case 0:
        copy[at] = rng.below(256);
        break;
      case 1:
        copy[at] = (copy[at] ?? 0) ^ (1 << rng.below(8));
        break;
      case 2:
        copy[at] = 0xff;
        break;
      default:
        copy[at] = 0;
        break;
    }
  }
  if (rng.chance(1, 4) && copy.length > 1) {
    return copy.subarray(0, rng.below(copy.length));
  }
  return copy;
}

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

export function unhex(text: string): Uint8Array {
  const out = new Uint8Array(text.length / 2);
  for (let index = 0; index < out.length; index += 1) {
    out[index] = Number.parseInt(text.slice(index * 2, index * 2 + 2), 16);
  }
  return out;
}

/**
 * Generate the corpus. Deterministic in `seed` and `count`: the same pair
 * produces the same bytes on any host, which is what makes a failing case
 * reproducible from the seed the corpus file records.
 */
export function generateCorpus(seed: bigint, count: number): Case[] {
  const rng = new Prng(seed);
  const cases: Case[] = [];
  for (let id = 0; id < count; id += 1) {
    const msize = rng.pick(MSIZE_POOL);
    const family = rng.below(100);
    if (family < 55) {
      cases.push({ id, msize, transport: 'exact', bytes: hex(buildFrame(rng)) });
    } else if (family < 80) {
      cases.push({ id, msize, transport: 'exact', bytes: hex(mutate(rng, buildFrame(rng))) });
    } else if (family < 85) {
      cases.push({ id, msize, transport: 'exact', bytes: hex(rng.bytes(rng.below(40))) });
    } else if (family < 90) {
      // Two frames in one binary message, which the consumer rule refuses and
      // the stream rule accepts. Both sides must draw that line in one place.
      const first = buildFrame(rng);
      const second = buildFrame(rng);
      const joined = new Uint8Array(first.length + second.length);
      joined.set(first, 0);
      joined.set(second, first.length);
      cases.push({ id, msize, transport: 'exact', bytes: hex(joined) });
    } else {
      const frames: Uint8Array[] = [];
      const frameCount = 1 + rng.below(3);
      for (let index = 0; index < frameCount; index += 1) {
        frames.push(rng.chance(1, 5) ? mutate(rng, buildFrame(rng)) : buildFrame(rng));
      }
      const total = frames.reduce((sum, frame) => sum + frame.length, 0);
      const stream = new Uint8Array(total);
      let offset = 0;
      for (const frame of frames) {
        stream.set(frame, offset);
        offset += frame.length;
      }
      const chunks: string[] = [];
      let cursor = 0;
      while (cursor < stream.length) {
        const size = 1 + rng.below(Math.max(1, Math.min(32, stream.length - cursor)));
        chunks.push(hex(stream.subarray(cursor, cursor + size)));
        cursor += size;
      }
      if (chunks.length === 0) {
        chunks.push('');
      }
      cases.push({ id, msize, transport: 'stream', chunks });
    }
  }
  return cases;
}

/** The corpus file's own format: a header line, then one JSON case per line. */
export function serializeCorpus(seed: bigint, cases: Case[]): string {
  const header = JSON.stringify({
    corpus: 'agent-tunnel.9p.v1 shared codec corpus',
    seed: `0x${seed.toString(16)}`,
    cases: cases.length,
  });
  return [header, ...cases.map((value) => JSON.stringify(value))].join('\n') + '\n';
}
