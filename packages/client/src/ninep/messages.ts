import type { MessageName } from './constants.ts';

/** `qid[13]` is `type[1] version[4] path[8]`. */
export interface Qid {
  type: number;
  version: number;
  path: bigint;
}

/** One packed `Rreaddir` record: `qid[13] offset[8] type[1] name[s]`. */
export interface DirEntry {
  qid: Qid;
  /** An opaque directory cookie. Nothing here interprets or orders by it. */
  offset: bigint;
  /** The `dirent` type byte, required to agree with `qid.type`. */
  type: number;
  name: string;
}

interface Base<N extends MessageName> {
  /**
   * The message-type discriminator. Deliberately NOT called `name`: several
   * `.L` messages carry a `name[s]` field of their own, and one object cannot
   * hold both.
   */
  kind: N;
  tag: number;
}

export type Message =
  | (Base<'Tversion'> & { msize: number; version: string })
  | (Base<'Rversion'> & { msize: number; version: string })
  | (Base<'Tattach'> & {
      fid: number;
      afid: number;
      uname: string;
      aname: string;
      nUname: number;
    })
  | (Base<'Rattach'> & { qid: Qid })
  | (Base<'Rlerror'> & { ecode: number })
  | (Base<'Tflush'> & { oldtag: number })
  | Base<'Rflush'>
  | (Base<'Twalk'> & { fid: number; newfid: number; wnames: string[] })
  | (Base<'Rwalk'> & { wqids: Qid[] })
  | (Base<'Tlopen'> & { fid: number; flags: number })
  | (Base<'Rlopen'> & { qid: Qid; iounit: number })
  | (Base<'Tlcreate'> & {
      fid: number;
      name: string;
      flags: number;
      mode: number;
      gid: number;
    })
  | (Base<'Rlcreate'> & { qid: Qid; iounit: number })
  | (Base<'Tsymlink'> & { fid: number; name: string; symtgt: string; gid: number })
  | (Base<'Rsymlink'> & { qid: Qid })
  | (Base<'Treadlink'> & { fid: number })
  | (Base<'Rreadlink'> & { target: string })
  | (Base<'Tgetattr'> & { fid: number; requestMask: bigint })
  | (Base<'Rgetattr'> & {
      valid: bigint;
      qid: Qid;
      mode: number;
      uid: number;
      gid: number;
      nlink: bigint;
      rdev: bigint;
      size: bigint;
      blksize: bigint;
      blocks: bigint;
      atimeSec: bigint;
      atimeNsec: bigint;
      mtimeSec: bigint;
      mtimeNsec: bigint;
      ctimeSec: bigint;
      ctimeNsec: bigint;
      btimeSec: bigint;
      btimeNsec: bigint;
      gen: bigint;
      dataVersion: bigint;
    })
  | (Base<'Tsetattr'> & {
      fid: number;
      valid: number;
      mode: number;
      uid: number;
      gid: number;
      size: bigint;
      atimeSec: bigint;
      atimeNsec: bigint;
      mtimeSec: bigint;
      mtimeNsec: bigint;
    })
  | Base<'Rsetattr'>
  | (Base<'Treaddir'> & { fid: number; offset: bigint; count: number })
  | (Base<'Rreaddir'> & { entries: DirEntry[] })
  | (Base<'Tlink'> & { dfid: number; fid: number; name: string })
  | Base<'Rlink'>
  | (Base<'Tmkdir'> & { dfid: number; name: string; mode: number; gid: number })
  | (Base<'Rmkdir'> & { qid: Qid })
  | (Base<'Trename'> & { fid: number; dfid: number; name: string })
  | Base<'Rrename'>
  | (Base<'Trenameat'> & {
      olddirfid: number;
      oldname: string;
      newdirfid: number;
      newname: string;
    })
  | Base<'Rrenameat'>
  | (Base<'Tunlinkat'> & { dirfid: number; name: string; flags: number })
  | Base<'Runlinkat'>
  | (Base<'Tread'> & { fid: number; offset: bigint; count: number })
  | (Base<'Rread'> & { data: Uint8Array })
  | (Base<'Twrite'> & { fid: number; offset: bigint; data: Uint8Array })
  | (Base<'Rwrite'> & { count: number })
  | (Base<'Tclunk'> & { fid: number })
  | Base<'Rclunk'>
  | (Base<'Tremove'> & { fid: number })
  | Base<'Rremove'>;

export type MessageOf<N extends MessageName> = Extract<Message, { kind: N }>;
