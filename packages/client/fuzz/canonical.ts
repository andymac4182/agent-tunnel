/**
 * The canonical form of a decoded message, and this side's verdict on one case.
 *
 * The two implementations have different in-memory shapes — the Rust holds an
 * `Rlerror`'s code as an enum and an `Rreaddir`'s payload as an unparsed block,
 * this side holds an errno number and parsed entries — so "the accepted values
 * agree" needs a spelling both can produce. This is it: one line per message,
 * every field named in wire order, every string and byte string as hex so no
 * escaping question can make two different values render the same.
 *
 * The same rendering is written out by hand in
 * `crates/tunnel-fs-ninep/tests/shared_fuzz.rs`. Two hand-written renderers is
 * deliberate: a shared one would be a third implementation both sides trusted,
 * and a field either codec drops would then be dropped from the comparison too.
 */

import { decodeExact, FrameDecoder, NinepError } from '../src/ninep/codec.ts';
import type { Message, Qid } from '../src/ninep/messages.ts';
import type { Case } from './corpus.ts';
import { unhex } from './corpus.ts';

function hex(bytes: Uint8Array): string {
  let out = '';
  for (const byte of bytes) {
    out += byte.toString(16).padStart(2, '0');
  }
  return out;
}

function text(value: string): string {
  return `h:${hex(new TextEncoder().encode(value))}`;
}

function qid(value: Qid): string {
  return `q:${value.type}:${value.version}:${value.path}`;
}

/** One message as a single line, fields in wire order. */
export function canonical(message: Message): string {
  const parts: string[] = [message.kind, `tag=${message.tag}`];
  const add = (name: string, value: string | number | bigint): void => {
    parts.push(`${name}=${String(value)}`);
  };
  switch (message.kind) {
    case 'Rlerror':
      add('ecode', message.ecode);
      break;
    case 'Tversion':
    case 'Rversion':
      add('msize', message.msize);
      add('version', text(message.version));
      break;
    case 'Tattach':
      add('fid', message.fid);
      add('afid', message.afid);
      add('uname', text(message.uname));
      add('aname', text(message.aname));
      add('n_uname', message.nUname);
      break;
    case 'Rattach':
    case 'Rsymlink':
    case 'Rmkdir':
      add('qid', qid(message.qid));
      break;
    case 'Tflush':
      add('oldtag', message.oldtag);
      break;
    case 'Twalk':
      add('fid', message.fid);
      add('newfid', message.newfid);
      add('wnames', `[${message.wnames.map(text).join(',')}]`);
      break;
    case 'Rwalk':
      add('wqids', `[${message.wqids.map(qid).join(',')}]`);
      break;
    case 'Tlopen':
      add('fid', message.fid);
      add('flags', message.flags);
      break;
    case 'Rlopen':
    case 'Rlcreate':
      add('qid', qid(message.qid));
      add('iounit', message.iounit);
      break;
    case 'Tlcreate':
      add('fid', message.fid);
      add('name', text(message.name));
      add('flags', message.flags);
      add('mode', message.mode);
      add('gid', message.gid);
      break;
    case 'Tsymlink':
      add('fid', message.fid);
      add('name', text(message.name));
      add('target', text(message.symtgt));
      add('gid', message.gid);
      break;
    case 'Treadlink':
    case 'Tclunk':
    case 'Tremove':
      add('fid', message.fid);
      break;
    case 'Rreadlink':
      add('target', text(message.target));
      break;
    case 'Tgetattr':
      add('fid', message.fid);
      add('request_mask', message.requestMask);
      break;
    case 'Rgetattr':
      add('valid', message.valid);
      add('qid', qid(message.qid));
      add('mode', message.mode);
      add('uid', message.uid);
      add('gid', message.gid);
      add('nlink', message.nlink);
      add('rdev', message.rdev);
      add('size', message.size);
      add('blksize', message.blksize);
      add('blocks', message.blocks);
      add('atime_sec', message.atimeSec);
      add('atime_nsec', message.atimeNsec);
      add('mtime_sec', message.mtimeSec);
      add('mtime_nsec', message.mtimeNsec);
      add('ctime_sec', message.ctimeSec);
      add('ctime_nsec', message.ctimeNsec);
      add('btime_sec', message.btimeSec);
      add('btime_nsec', message.btimeNsec);
      add('gen', message.gen);
      add('data_version', message.dataVersion);
      break;
    case 'Tsetattr':
      add('fid', message.fid);
      add('valid', message.valid);
      add('mode', message.mode);
      add('uid', message.uid);
      add('gid', message.gid);
      add('size', message.size);
      add('atime_sec', message.atimeSec);
      add('atime_nsec', message.atimeNsec);
      add('mtime_sec', message.mtimeSec);
      add('mtime_nsec', message.mtimeNsec);
      break;
    case 'Treaddir':
    case 'Tread':
      add('fid', message.fid);
      add('offset', message.offset);
      add('count', message.count);
      break;
    case 'Rreaddir':
      add(
        'entries',
        `[${message.entries
          .map((entry) => `${qid(entry.qid)}|${entry.offset}|${text(entry.name)}`)
          .join(',')}]`,
      );
      break;
    case 'Tlink':
      add('dfid', message.dfid);
      add('fid', message.fid);
      add('name', text(message.name));
      break;
    case 'Tmkdir':
      add('dfid', message.dfid);
      add('name', text(message.name));
      add('mode', message.mode);
      add('gid', message.gid);
      break;
    case 'Trename':
      add('fid', message.fid);
      add('dfid', message.dfid);
      add('name', text(message.name));
      break;
    case 'Trenameat':
      add('olddirfid', message.olddirfid);
      add('oldname', text(message.oldname));
      add('newdirfid', message.newdirfid);
      add('newname', text(message.newname));
      break;
    case 'Tunlinkat':
      add('dirfid', message.dirfid);
      add('name', text(message.name));
      add('flags', message.flags);
      break;
    case 'Rread':
      add('data', `h:${hex(message.data)}`);
      break;
    case 'Twrite':
      add('fid', message.fid);
      add('offset', message.offset);
      add('data', `h:${hex(message.data)}`);
      break;
    case 'Rwrite':
      add('count', message.count);
      break;
    case 'Rflush':
    case 'Rsetattr':
    case 'Rlink':
    case 'Rrename':
    case 'Rrenameat':
    case 'Runlinkat':
    case 'Rclunk':
    case 'Rremove':
      break;
    default: {
      const exhaustive: never = message;
      return exhaustive;
    }
  }
  return parts.join(' ');
}

/**
 * This side's refusal reasons, mapped onto the Rust `CodecError` spelling.
 *
 * The comparison is over the *shared* vocabulary, so the two sides are being
 * asked whether they refused for the same reason and not merely whether they
 * both refused. A reason with no Rust counterpart keeps its own name, which is
 * how a layering difference shows up as a mismatch instead of hiding inside
 * "both refused".
 */
const SHARED_REASON = new Map<string, string>([
  ['HeaderFloor', 'FrameBelowHeader'],
  ['OverCeiling', 'FrameAboveCeiling'],
  ['OverMsize', 'FrameAboveMsize'],
  ['TruncatedBody', 'TruncatedBody'],
  ['TrailingBytes', 'TrailingBytes'],
  ['UnknownMessageType', 'UnknownMessageType'],
  ['MessageTypeNotInProfile', 'MessageTypeNotInProfile'],
  ['NotagRequired', 'NotagRequired'],
  ['NotagForbidden', 'NotagNotPermitted'],
  ['InvalidUtf8', 'StringNotUtf8'],
  ['QidType', 'QidTypeNotInProfile'],
  ['DirentTypeDisagreesWithQid', 'MalformedDirEntry'],
  ['MalformedDirentBlock', 'MalformedDirEntry'],
  ['ErrnoNotInVocabulary', 'ErrnoNotInVocabulary'],
  ['TooManyWalkElements', 'TooManyWalkNames'],
  ['CountAboveMsize', 'CountAboveMsize'],
  ['SizeDisagreesWithBuffer', 'SizeDisagreesWithBuffer'],
]);

function sharedReason(error: NinepError): string {
  return SHARED_REASON.get(error.reason) ?? error.reason;
}

export type Verdict =
  | { id: number; verdict: 'accept'; value: string }
  | { id: number; verdict: 'refuse'; reason: string }
  | { id: number; verdict: 'stream'; values: string[]; reason: string | null };

/** Run one case through this side's codec. */
export function runCase(entry: Case): Verdict {
  if (entry.transport === 'exact') {
    try {
      return { id: entry.id, verdict: 'accept', value: canonical(decodeExact(unhex(entry.bytes), { msize: entry.msize })) };
    } catch (error) {
      if (error instanceof NinepError) {
        return { id: entry.id, verdict: 'refuse', reason: sharedReason(error) };
      }
      throw error;
    }
  }
  const decoder = new FrameDecoder({ msize: entry.msize });
  const values: string[] = [];
  for (const chunk of entry.chunks) {
    const { messages, error } = decoder.push(unhex(chunk));
    for (const message of messages) {
      values.push(canonical(message));
    }
    if (error !== undefined) {
      // Stop at the first framing violation — after recording the frames that
      // push completed, which is the half this side used to lose. What either
      // decoder reports on a *later* push is a diagnostic with no wire meaning:
      // the session is closed with 1002 either way.
      return { id: entry.id, verdict: 'stream', values, reason: sharedReason(error) };
    }
  }
  return { id: entry.id, verdict: 'stream', values, reason: null };
}

/** The verdict file's format: one JSON verdict per line, in case order. */
export function serializeVerdicts(verdicts: Verdict[]): string {
  return verdicts.map((verdict) => JSON.stringify(verdict)).join('\n') + '\n';
}
