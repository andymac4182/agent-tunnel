/**
 * An independent 9P2000.L encoder and decoder for the `agent-tunnel.9p.v1`
 * profile.
 *
 * Written from the protocol definition and `docs/filesystem-api.md`, not from
 * `crates/tunnel-fs-ninep`. It exists to disagree with the Rust codec if the
 * two read the contract differently; a transliteration would prove nothing.
 */

import * as C from './constants.ts';
import { NinepError, fail } from './errors.ts';
import { Reader, Writer } from './buffer.ts';
import type { DirEntry, Message, Qid } from './messages.ts';

export { NinepError } from './errors.ts';
export type { NinepErrorReason } from './errors.ts';
export type { DirEntry, Message, Qid } from './messages.ts';
export * as constants from './constants.ts';

/* ------------------------------------------------------------------ *
 * Field-level rules the contract pins.
 * ------------------------------------------------------------------ */

function checkQid(qid: Qid, field: string): void {
  // A bit outside the three emitted types is refused, never masked off:
  // masking would let a peer's claim about a node silently disappear.
  if (!C.QID_TYPES.has(qid.type)) {
    fail('QidType', field);
  }
}

function checkTag(kind: C.MessageName, tag: number): void {
  if (!Number.isInteger(tag) || tag < 0 || tag > 0xffff) {
    fail('TagOutOfRange', 'tag');
  }
  const isVersion = kind === 'Tversion' || kind === 'Rversion';
  if (isVersion && tag !== C.NOTAG) {
    fail('NotagRequired', 'tag');
  }
  if (!isVersion && tag === C.NOTAG) {
    fail('NotagForbidden', 'tag');
  }
}

function checkVersion(version: string): void {
  // The WebSocket subprotocol selected the dialect before a byte of 9P was
  // sent, so another dialect is a peer that ignored the handshake, not a
  // negotiation step. There is no `version = "unknown"` reply in this profile.
  if (version !== C.VERSION) {
    fail('UnsupportedVersion', 'version');
  }
}

function checkNegotiatedMsize(msize: number): void {
  if (msize < C.MSIZE_FLOOR) {
    fail('MsizeBelowFloor', 'msize');
  }
  if (msize > C.MSIZE_CEILING) {
    fail('OverCeiling', 'msize');
  }
}

/**
 * A requested or returned `count[4]` must leave room for its own framing.
 *
 * A `Tread` or `Treaddir` asking for exactly `msize` bytes cannot be answered:
 * the reply carrying them would be `msize + 11`. An `Rwrite` may not
 * acknowledge more bytes than a `Twrite` could have carried, which is
 * `msize - 23`. Silently shortening a reply instead would be
 * indistinguishable to the caller from a short read at end of file.
 *
 * This is framing, not a profile refusal: the count is a property of the frame
 * the peer sent, and there is nothing to negotiate about it.
 */
function checkCounts(message: Message, msize: number): void {
  const replyLimit = Math.max(0, msize - C.COUNTED_REPLY_OVERHEAD);
  const writeLimit = Math.max(0, msize - C.WRITE_REQUEST_OVERHEAD);
  switch (message.kind) {
    case 'Tread':
    case 'Treaddir':
      if (message.count > replyLimit) {
        fail('CountAboveMsize', 'count');
      }
      return;
    case 'Rwrite':
      if (message.count > writeLimit) {
        fail('CountAboveMsize', 'count');
      }
      return;
    default:
      return;
  }
}

function checkErrno(ecode: number): void {
  // Closed in both directions: a provider may not widen the vocabulary on the
  // way out, and a client may not be made to handle a code outside the fourteen.
  if (!C.ERRNO_NAME_BY_NUMBER.has(ecode)) {
    fail('ErrnoNotInVocabulary', 'ecode');
  }
}

/* ------------------------------------------------------------------ *
 * qid and dirent
 * ------------------------------------------------------------------ */

function readQid(reader: Reader, field: string): Qid {
  const qid: Qid = {
    type: reader.u8(`${field}.type`),
    version: reader.u32(`${field}.version`),
    path: reader.u64(`${field}.path`),
  };
  checkQid(qid, field);
  return qid;
}

function writeQid(writer: Writer, qid: Qid, field: string): void {
  checkQid(qid, field);
  writer.u8(qid.type, `${field}.type`);
  writer.u32(qid.version, `${field}.version`);
  writer.u64(qid.path, `${field}.path`);
}

/**
 * The `Rreaddir` payload is a packed array with no count of its own: the block
 * ends when the declared `count` does, and a block that ends part-way through a
 * record is malformed. Entries are whole or left out entirely.
 */
export function decodeDirEntries(block: Uint8Array): DirEntry[] {
  const reader = new Reader(block);
  const entries: DirEntry[] = [];
  while (reader.remaining > 0) {
    let entry: DirEntry;
    try {
      const qid = readQid(reader, 'entry.qid');
      const offset = reader.u64('entry.offset');
      const type = reader.u8('entry.type');
      const name = reader.string('entry.name');
      entry = { qid, offset, type, name };
    } catch (error) {
      if (error instanceof NinepError && error.reason === 'TruncatedBody') {
        // A record the block cut short. Dropping its tail would invent a name.
        fail('MalformedDirentBlock', 'entries');
      }
      throw error;
    }
    // Two sources that can disagree is one too many: the dirent byte is
    // *required to agree* with the qid rather than one being preferred.
    if (C.DIRENT_BY_QID_TYPE.get(entry.qid.type) !== entry.type) {
      fail('DirentTypeDisagreesWithQid', 'entry.type');
    }
    entries.push(entry);
  }
  return entries;
}

export function encodeDirEntries(entries: DirEntry[]): Uint8Array {
  const writer = new Writer();
  for (const entry of entries) {
    if (C.DIRENT_BY_QID_TYPE.get(entry.qid.type) !== entry.type) {
      fail('DirentTypeDisagreesWithQid', 'entry.type');
    }
    writeQid(writer, entry.qid, 'entry.qid');
    writer.u64(entry.offset, 'entry.offset');
    writer.u8(entry.type, 'entry.type');
    writer.string(entry.name, 'entry.name');
  }
  return writer.finish();
}

/* ------------------------------------------------------------------ *
 * Bodies
 * ------------------------------------------------------------------ */

function decodeBody(kind: C.MessageName, tag: number, reader: Reader): Message {
  switch (kind) {
    case 'Tversion':
    case 'Rversion': {
      const msize = reader.u32('msize');
      const version = reader.string('version');
      checkVersion(version);
      checkNegotiatedMsize(msize);
      return { kind, tag, msize, version };
    }
    case 'Tattach':
      return {
        kind,
        tag,
        fid: reader.u32('fid'),
        afid: reader.u32('afid'),
        uname: reader.string('uname'),
        aname: reader.string('aname'),
        nUname: reader.u32('n_uname'),
      };
    case 'Rattach':
    case 'Rsymlink':
    case 'Rmkdir':
      return { kind, tag, qid: readQid(reader, 'qid') };
    case 'Rlerror': {
      const ecode = reader.u32('ecode');
      checkErrno(ecode);
      return { kind, tag, ecode };
    }
    case 'Tflush':
      return { kind, tag, oldtag: reader.u16('oldtag') };
    case 'Twalk': {
      const fid = reader.u32('fid');
      const newfid = reader.u32('newfid');
      const nwname = reader.u16('nwname');
      // Checked *before* a single element is reserved, so a declared count
      // cannot drive an allocation.
      if (nwname > C.MAXWELEM) {
        fail('TooManyWalkElements', 'nwname');
      }
      const wnames: string[] = [];
      for (let index = 0; index < nwname; index += 1) {
        wnames.push(reader.string(`wname[${index}]`));
      }
      return { kind, tag, fid, newfid, wnames };
    }
    case 'Rwalk': {
      const nwqid = reader.u16('nwqid');
      if (nwqid > C.MAXWELEM) {
        fail('TooManyWalkElements', 'nwqid');
      }
      const wqids: Qid[] = [];
      for (let index = 0; index < nwqid; index += 1) {
        wqids.push(readQid(reader, `wqid[${index}]`));
      }
      return { kind, tag, wqids };
    }
    case 'Tlopen': {
      const fid = reader.u32('fid');
      const flags = reader.u32('flags');
      return { kind, tag, fid, flags };
    }
    case 'Rlopen':
    case 'Rlcreate':
      return {
        kind,
        tag,
        qid: readQid(reader, 'qid'),
        iounit: reader.u32('iounit'),
      };
    case 'Tlcreate': {
      const fid = reader.u32('fid');
      const entryName = reader.string('name');
      const flags = reader.u32('flags');
      const mode = reader.u32('mode');
      const gid = reader.u32('gid');
      return { kind, tag, fid, name: entryName, flags, mode, gid };
    }
    case 'Tsymlink':
      return {
        kind,
        tag,
        fid: reader.u32('fid'),
        name: reader.string('name'),
        symtgt: reader.string('symtgt'),
        gid: reader.u32('gid'),
      };
    case 'Treadlink':
    case 'Tclunk':
    case 'Tremove':
      return { kind, tag, fid: reader.u32('fid') };
    case 'Rreadlink':
      return { kind, tag, target: reader.string('target') };
    case 'Tgetattr': {
      const fid = reader.u32('fid');
      const requestMask = reader.u64('request_mask');
      return { kind, tag, fid, requestMask };
    }
    case 'Rgetattr':
      return {
        kind,
        tag,
        valid: reader.u64('valid'),
        qid: readQid(reader, 'qid'),
        mode: reader.u32('mode'),
        uid: reader.u32('uid'),
        gid: reader.u32('gid'),
        nlink: reader.u64('nlink'),
        rdev: reader.u64('rdev'),
        size: reader.u64('size'),
        blksize: reader.u64('blksize'),
        blocks: reader.u64('blocks'),
        atimeSec: reader.u64('atime_sec'),
        atimeNsec: reader.u64('atime_nsec'),
        mtimeSec: reader.u64('mtime_sec'),
        mtimeNsec: reader.u64('mtime_nsec'),
        ctimeSec: reader.u64('ctime_sec'),
        ctimeNsec: reader.u64('ctime_nsec'),
        btimeSec: reader.u64('btime_sec'),
        btimeNsec: reader.u64('btime_nsec'),
        gen: reader.u64('gen'),
        dataVersion: reader.u64('data_version'),
      };
    case 'Tsetattr': {
      const fid = reader.u32('fid');
      const valid = reader.u32('valid');
      return {
        kind,
        tag,
        fid,
        valid,
        mode: reader.u32('mode'),
        uid: reader.u32('uid'),
        gid: reader.u32('gid'),
        size: reader.u64('size'),
        atimeSec: reader.u64('atime_sec'),
        atimeNsec: reader.u64('atime_nsec'),
        mtimeSec: reader.u64('mtime_sec'),
        mtimeNsec: reader.u64('mtime_nsec'),
      };
    }
    case 'Treaddir':
    case 'Tread':
      return {
        kind,
        tag,
        fid: reader.u32('fid'),
        offset: reader.u64('offset'),
        count: reader.u32('count'),
      };
    case 'Rreaddir': {
      const count = reader.u32('count');
      const block = reader.raw(count, 'data');
      return { kind, tag, entries: decodeDirEntries(block) };
    }
    case 'Tlink':
      return {
        kind,
        tag,
        dfid: reader.u32('dfid'),
        fid: reader.u32('fid'),
        name: reader.string('name'),
      };
    case 'Tmkdir':
      return {
        kind,
        tag,
        dfid: reader.u32('dfid'),
        name: reader.string('name'),
        mode: reader.u32('mode'),
        gid: reader.u32('gid'),
      };
    case 'Trename':
      return {
        kind,
        tag,
        fid: reader.u32('fid'),
        dfid: reader.u32('dfid'),
        name: reader.string('name'),
      };
    case 'Trenameat':
      return {
        kind,
        tag,
        olddirfid: reader.u32('olddirfid'),
        oldname: reader.string('oldname'),
        newdirfid: reader.u32('newdirfid'),
        newname: reader.string('newname'),
      };
    case 'Tunlinkat': {
      const dirfid = reader.u32('dirfid');
      const entryName = reader.string('name');
      const flags = reader.u32('flags');
      return { kind, tag, dirfid, name: entryName, flags };
    }
    case 'Rread': {
      const count = reader.u32('count');
      // `data` is file content, deliberately not text-checked.
      return { kind, tag, data: reader.raw(count, 'data') };
    }
    case 'Twrite': {
      const fid = reader.u32('fid');
      const offset = reader.u64('offset');
      const count = reader.u32('count');
      return { kind, tag, fid, offset, data: reader.raw(count, 'data') };
    }
    case 'Rwrite':
      return { kind, tag, count: reader.u32('count') };
    case 'Rflush':
    case 'Rsetattr':
    case 'Rlink':
    case 'Rrename':
    case 'Rrenameat':
    case 'Runlinkat':
    case 'Rclunk':
    case 'Rremove':
      return { kind, tag };
    default: {
      const exhaustive: never = kind;
      return exhaustive;
    }
  }
}

function encodeBody(message: Message, writer: Writer): void {
  switch (message.kind) {
    case 'Tversion':
    case 'Rversion':
      checkVersion(message.version);
      checkNegotiatedMsize(message.msize);
      writer.u32(message.msize, 'msize');
      writer.string(message.version, 'version');
      return;
    case 'Tattach':
      writer.u32(message.fid, 'fid');
      writer.u32(message.afid, 'afid');
      writer.string(message.uname, 'uname');
      writer.string(message.aname, 'aname');
      writer.u32(message.nUname, 'nUname');
      return;
    case 'Rattach':
    case 'Rsymlink':
    case 'Rmkdir':
      writeQid(writer, message.qid, 'qid');
      return;
    case 'Rlerror':
      checkErrno(message.ecode);
      writer.u32(message.ecode, 'ecode');
      return;
    case 'Tflush':
      writer.u16(message.oldtag, 'oldtag');
      return;
    case 'Twalk':
      if (message.wnames.length > C.MAXWELEM) {
        fail('TooManyWalkElements', 'nwname');
      }
      writer.u32(message.fid, 'fid');
      writer.u32(message.newfid, 'newfid');
      writer.u16(message.wnames.length, 'nwname');
      message.wnames.forEach((wname, index) => writer.string(wname, `wname[${index}]`));
      return;
    case 'Rwalk':
      if (message.wqids.length > C.MAXWELEM) {
        fail('TooManyWalkElements', 'nwqid');
      }
      writer.u16(message.wqids.length, 'nwqid');
      message.wqids.forEach((qid, index) => writeQid(writer, qid, `wqid[${index}]`));
      return;
    case 'Tlopen':
      writer.u32(message.fid, 'fid');
      writer.u32(message.flags, 'flags');
      return;
    case 'Rlopen':
    case 'Rlcreate':
      writeQid(writer, message.qid, 'qid');
      writer.u32(message.iounit, 'iounit');
      return;
    case 'Tlcreate':
      writer.u32(message.fid, 'fid');
      writer.string(message.name, 'name');
      writer.u32(message.flags, 'flags');
      writer.u32(message.mode, 'mode');
      writer.u32(message.gid, 'gid');
      return;
    case 'Tsymlink':
      writer.u32(message.fid, 'fid');
      writer.string(message.name, 'name');
      writer.string(message.symtgt, 'symtgt');
      writer.u32(message.gid, 'gid');
      return;
    case 'Treadlink':
    case 'Tclunk':
    case 'Tremove':
      writer.u32(message.fid, 'fid');
      return;
    case 'Rreadlink':
      writer.string(message.target, 'target');
      return;
    case 'Tgetattr':
      writer.u32(message.fid, 'fid');
      writer.u64(message.requestMask, 'requestMask');
      return;
    case 'Rgetattr':
      writer.u64(message.valid, 'valid');
      writeQid(writer, message.qid, 'qid');
      writer.u32(message.mode, 'mode');
      writer.u32(message.uid, 'uid');
      writer.u32(message.gid, 'gid');
      writer.u64(message.nlink, 'nlink');
      writer.u64(message.rdev, 'rdev');
      writer.u64(message.size, 'size');
      writer.u64(message.blksize, 'blksize');
      writer.u64(message.blocks, 'blocks');
      writer.u64(message.atimeSec, 'atimeSec');
      writer.u64(message.atimeNsec, 'atimeNsec');
      writer.u64(message.mtimeSec, 'mtimeSec');
      writer.u64(message.mtimeNsec, 'mtimeNsec');
      writer.u64(message.ctimeSec, 'ctimeSec');
      writer.u64(message.ctimeNsec, 'ctimeNsec');
      writer.u64(message.btimeSec, 'btimeSec');
      writer.u64(message.btimeNsec, 'btimeNsec');
      writer.u64(message.gen, 'gen');
      writer.u64(message.dataVersion, 'dataVersion');
      return;
    case 'Tsetattr':
      writer.u32(message.fid, 'fid');
      writer.u32(message.valid, 'valid');
      writer.u32(message.mode, 'mode');
      writer.u32(message.uid, 'uid');
      writer.u32(message.gid, 'gid');
      writer.u64(message.size, 'size');
      writer.u64(message.atimeSec, 'atimeSec');
      writer.u64(message.atimeNsec, 'atimeNsec');
      writer.u64(message.mtimeSec, 'mtimeSec');
      writer.u64(message.mtimeNsec, 'mtimeNsec');
      return;
    case 'Treaddir':
    case 'Tread':
      writer.u32(message.fid, 'fid');
      writer.u64(message.offset, 'offset');
      writer.u32(message.count, 'count');
      return;
    case 'Rreaddir': {
      const block = encodeDirEntries(message.entries);
      writer.u32(block.byteLength, 'count');
      writer.raw(block);
      return;
    }
    case 'Tlink':
      writer.u32(message.dfid, 'dfid');
      writer.u32(message.fid, 'fid');
      writer.string(message.name, 'name');
      return;
    case 'Tmkdir':
      writer.u32(message.dfid, 'dfid');
      writer.string(message.name, 'name');
      writer.u32(message.mode, 'mode');
      writer.u32(message.gid, 'gid');
      return;
    case 'Trename':
      writer.u32(message.fid, 'fid');
      writer.u32(message.dfid, 'dfid');
      writer.string(message.name, 'name');
      return;
    case 'Trenameat':
      writer.u32(message.olddirfid, 'olddirfid');
      writer.string(message.oldname, 'oldname');
      writer.u32(message.newdirfid, 'newdirfid');
      writer.string(message.newname, 'newname');
      return;
    case 'Tunlinkat':
      writer.u32(message.dirfid, 'dirfid');
      writer.string(message.name, 'name');
      writer.u32(message.flags, 'flags');
      return;
    case 'Rread':
      writer.u32(message.data.byteLength, 'count');
      writer.raw(message.data);
      return;
    case 'Twrite':
      writer.u32(message.fid, 'fid');
      writer.u64(message.offset, 'offset');
      writer.u32(message.data.byteLength, 'count');
      writer.raw(message.data);
      return;
    case 'Rwrite':
      writer.u32(message.count, 'count');
      return;
    case 'Rflush':
    case 'Rsetattr':
    case 'Rlink':
    case 'Rrename':
    case 'Rrenameat':
    case 'Runlinkat':
    case 'Rclunk':
    case 'Rremove':
      return;
    default: {
      const exhaustive: never = message;
      return exhaustive;
    }
  }
}

/* ------------------------------------------------------------------ *
 * Framing
 * ------------------------------------------------------------------ */

export interface DecodeOptions {
  /** The negotiated `msize`. Defaults to the profile ceiling. */
  msize?: number;
}

/**
 * The three size checks, in the one fixed order the contract pins, so that one
 * input has one answer: the seven-byte header floor, then the absolute 65,536
 * ceiling, then the negotiated `msize`.
 *
 * The visible consequence, asserted in the tests: at `msize` 65,536 a frame one
 * byte above reports the **ceiling**, because it is over both.
 */
export function checkDeclaredSize(size: number, msize: number): void {
  if (size < C.HEADER_BYTES) {
    fail('HeaderFloor', 'size');
  }
  if (size > C.MSIZE_CEILING) {
    fail('OverCeiling', 'size');
  }
  if (size > msize) {
    fail('OverMsize', 'size');
  }
}

/** Decode one complete message from `bytes`, which must be exactly that message. */
function decodeFrame(bytes: Uint8Array, msize: number): Message {
  const reader = new Reader(bytes);
  const size = reader.u32('size');
  checkDeclaredSize(size, msize);
  if (size !== bytes.byteLength) {
    fail('SizeDisagreesWithBuffer', 'size');
  }
  const opcode = reader.u8('type');
  const kind = C.NAME_BY_OPCODE.get(opcode);
  if (kind === undefined) {
    // Static protocol knowledge, so the split discloses nothing about the
    // export: it only tells an implementer whether it mistyped an opcode or
    // reached for one the profile denies.
    if (C.KNOWN_OPCODES_NOT_IN_PROFILE.has(opcode)) {
      fail('MessageTypeNotInProfile', 'type');
    }
    fail('UnknownMessageType', 'type');
  }
  const tag = reader.u16('tag');
  checkTag(kind, tag);
  const message = decodeBody(kind, tag, reader);
  reader.end('body');
  checkCounts(message, msize);
  return message;
}

/**
 * The consumer WebSocket rule: exactly one complete 9P message per binary
 * message. Two packed into one are `TrailingBytes`; half of one is
 * `TruncatedBody`, at every cut.
 */
export function decodeExact(bytes: Uint8Array, options: DecodeOptions = {}): Message {
  const msize = options.msize ?? C.MSIZE_CEILING;
  if (bytes.byteLength < 4) {
    // Not even a `size[4]`. On this transport there is no "wait for more": the
    // binary message is the whole frame.
    fail('TruncatedBody', 'size');
  }
  // A 4-to-6-byte buffer still carries a declared size, so read it and let the
  // size checks speak first: a buffer declaring `size < 7` is below the header
  // floor, which is a more precise answer than "truncated" and is the answer
  // the Rust codec gives. Only a buffer whose declared size is sound but whose
  // bytes ran out is `TruncatedBody`.
  const reader = new Reader(bytes);
  const size = reader.u32('size');
  checkDeclaredSize(size, msize);
  if (size > bytes.byteLength) {
    fail('TruncatedBody', 'body');
  }
  if (size < bytes.byteLength) {
    fail('TrailingBytes', 'frame');
  }
  return decodeFrame(bytes, msize);
}

export function encode(message: Message, options: DecodeOptions = {}): Uint8Array {
  const msize = options.msize ?? C.MSIZE_CEILING;
  checkTag(message.kind, message.tag);
  checkCounts(message, msize);
  const body = new Writer();
  encodeBody(message, body);
  const bodyBytes = body.finish();
  const size = C.HEADER_BYTES + bodyBytes.byteLength;
  checkDeclaredSize(size, msize);
  const writer = new Writer();
  writer.u32(size);
  writer.u8(C.MESSAGE_TYPES[message.kind]);
  writer.u16(message.tag, 'tag');
  writer.raw(bodyBytes);
  return writer.finish();
}

/**
 * The relay and device rule: an ordered byte stream over tunnel DATA frames,
 * where a record may span frames and several may share one. Kept separate from
 * `decodeExact` rather than being one function with a flag, because conflating
 * the two transports is a real bug and not a convenience.
 *
 * The first error is **latched**: a stream that produced one framing violation
 * has no trustworthy boundary to resynchronise on, so a well-formed frame
 * arriving after one is not decoded.
 */
export class FrameDecoder {
  private readonly msize: number;
  private retained: Uint8Array = new Uint8Array(0);
  private latched: NinepError | undefined;

  constructor(options: DecodeOptions = {}) {
    this.msize = options.msize ?? C.MSIZE_CEILING;
  }

  /**
   * Bytes held pending a complete frame, **between** pushes. It is bounded by
   * `msize`, because anything that could complete a frame is decoded and
   * dropped before `push` returns, and a declared size above `msize` latches
   * an error rather than accumulating.
   *
   * It is *not* a bound on peak memory during one `push`: a caller handing over
   * a 10 MiB chunk has already allocated it, and this class concatenates that
   * chunk onto the retained bytes before it can read the next declared size.
   * Bounding the peak is the transport's job, above this decoder.
   */
  get retainedBytes(): number {
    return this.retained.byteLength;
  }

  get isLatched(): boolean {
    return this.latched !== undefined;
  }

  push(chunk: Uint8Array): Message[] {
    if (this.latched !== undefined) {
      fail('DecoderLatched');
    }
    const merged = new Uint8Array(this.retained.byteLength + chunk.byteLength);
    merged.set(this.retained, 0);
    merged.set(chunk, this.retained.byteLength);
    this.retained = merged;

    const out: Message[] = [];
    try {
      for (;;) {
        if (this.retained.byteLength < C.HEADER_BYTES) {
          return out;
        }
        const size = new DataView(
          this.retained.buffer,
          this.retained.byteOffset,
          this.retained.byteLength,
        ).getUint32(0, true);
        checkDeclaredSize(size, this.msize);
        if (this.retained.byteLength < size) {
          return out;
        }
        out.push(decodeFrame(this.retained.subarray(0, size), this.msize));
        this.retained = this.retained.subarray(size);
      }
    } catch (error) {
      if (error instanceof NinepError) {
        this.latched = error;
        this.retained = new Uint8Array(0);
      }
      throw error;
    }
  }
}

/**
 * `msize` negotiation: `min(offered, maximum)`, never raising. 255 is refused,
 * 256 accepted, 65,536 accepted, 65,537 reduced to 65,536.
 */
export function negotiateMsize(offered: number, maximum: number = C.MSIZE_CEILING): number {
  if (offered < C.MSIZE_FLOOR) {
    fail('MsizeBelowFloor', 'msize');
  }
  return Math.min(offered, maximum);
}

