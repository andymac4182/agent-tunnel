/**
 * A tiny in-memory 9P2000.L provider for the harness.
 *
 * It answers the primitives the shared client composes from, over the real
 * socket, so a `readFile` or a `copy` is a real round trip of real bytes. It is
 * **not** `crates/tunnel-fs-provider`: it has no grant, no resolver, no host
 * and no confinement, and it enforces none of the authorization the real
 * provider exists to enforce. Its job is to be a peer that speaks the wire
 * correctly, so that what a test observes is the client's behaviour.
 */

import { constants as C } from '../../src/ninep/codec.ts';
import type { DirEntry, Message, Qid } from '../../src/ninep/messages.ts';
import type { ServerConnection } from './endpoint.ts';

interface Node {
  kind: 'file' | 'directory';
  bytes: Uint8Array;
  children: Map<string, Node>;
  mode: number;
  mtimeMs: number;
}

function file(bytes: Uint8Array): Node {
  return { kind: 'file', bytes, children: new Map(), mode: 0o644, mtimeMs: 1_700_000_000_000 };
}

function directory(): Node {
  return {
    kind: 'directory',
    bytes: new Uint8Array(0),
    children: new Map(),
    mode: 0o755,
    mtimeMs: 1_700_000_000_000,
  };
}

let nextPath = 1n;

export class FakeProvider {
  readonly root = directory();
  private readonly fids = new Map<number, { node: Node; parent: Node | undefined; name: string }>();
  private readonly qids = new Map<Node, Qid>();
  /** Requests the provider deliberately never answers, by message kind. */
  swallow: Set<Message['kind']> = new Set();
  /** Replies with fewer bytes than asked, once, for the short-write case. */
  shortWriteTo: number | undefined;
  /**
   * Answer `Rlerror` to a message kind once this many of it have succeeded.
   *
   * For the composites: a recursive `mkdir` that made one directory and was
   * then refused has **applied** something, and the client's floor must say so.
   * Constructing that needs a peer that fails the second request and not the
   * first, which no seeding arrangement produces on its own.
   */
  failAfter = new Map<Message['kind'], { after: number; ecode: number }>();
  private succeeded = new Map<Message['kind'], number>();

  constructor(seed: Record<string, string | Uint8Array> = {}) {
    for (const [name, content] of Object.entries(seed)) {
      const bytes = typeof content === 'string' ? new TextEncoder().encode(content) : content;
      this.place(name, file(bytes));
    }
  }

  /** Put a node at an absolute path, creating parents as directories. */
  place(path: string, node: Node): void {
    const parts = path.replace(/^\//u, '').split('/');
    let at = this.root;
    for (const part of parts.slice(0, -1)) {
      const next = at.children.get(part) ?? directory();
      at.children.set(part, next);
      at = next;
    }
    at.children.set(parts[parts.length - 1] ?? '', node);
  }

  /** The bytes at a path, for a test to check what the client actually wrote. */
  read(path: string): Uint8Array | undefined {
    const parts = path.replace(/^\//u, '').split('/');
    let at: Node | undefined = this.root;
    for (const part of parts) {
      at = at?.children.get(part);
    }
    return at?.bytes;
  }

  has(path: string): boolean {
    const parts = path.replace(/^\//u, '').split('/');
    let at: Node | undefined = this.root;
    for (const part of parts) {
      at = at?.children.get(part);
    }
    return at !== undefined;
  }

  private qid(node: Node): Qid {
    const existing = this.qids.get(node);
    if (existing !== undefined) {
      return existing;
    }
    const fresh: Qid = {
      type: node.kind === 'directory' ? C.QTDIR : C.QTFILE,
      version: 0,
      path: nextPath++,
    };
    this.qids.set(node, fresh);
    return fresh;
  }

  /** The handler to pass as `onRequest`. */
  handle = (message: Message, connection: ServerConnection): void => {
    if (this.swallow.has(message.kind)) {
      return;
    }
    const error = (ecode: number): void => {
      connection.send({ kind: 'Rlerror', tag: message.tag, ecode });
    };
    const scheduled = this.failAfter.get(message.kind);
    if (scheduled !== undefined) {
      const done = this.succeeded.get(message.kind) ?? 0;
      if (done >= scheduled.after) {
        error(scheduled.ecode);
        return;
      }
      this.succeeded.set(message.kind, done + 1);
    }
    switch (message.kind) {
      case 'Tversion':
        connection.send({
          kind: 'Rversion',
          tag: C.NOTAG,
          msize: Math.min(message.msize, 65536),
          version: C.VERSION,
        });
        return;
      case 'Tattach':
        this.fids.set(message.fid, { node: this.root, parent: undefined, name: '/' });
        connection.send({ kind: 'Rattach', tag: message.tag, qid: this.qid(this.root) });
        return;
      case 'Twalk': {
        const from = this.fids.get(message.fid);
        if (from === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        let at = from.node;
        let parent = from.parent;
        let name = from.name;
        const qids: Qid[] = [];
        for (const part of message.wnames) {
          const next = at.children.get(part);
          if (next === undefined) {
            break;
          }
          parent = at;
          at = next;
          name = part;
          qids.push(this.qid(next));
        }
        if (qids.length < message.wnames.length && qids.length === 0) {
          error(C.ERRNO_BY_NAME.ENOENT);
          return;
        }
        if (qids.length === message.wnames.length) {
          this.fids.set(message.newfid, { node: at, parent, name });
        }
        connection.send({ kind: 'Rwalk', tag: message.tag, wqids: qids });
        return;
      }
      case 'Tlopen': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        if ((message.flags & C.O_TRUNC) !== 0) {
          entry.node.bytes = new Uint8Array(0);
        }
        connection.send({
          kind: 'Rlopen',
          tag: message.tag,
          qid: this.qid(entry.node),
          iounit: 0,
        });
        return;
      }
      case 'Tlcreate': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined || entry.node.kind !== 'directory') {
          error(C.ERRNO_BY_NAME.ENOTDIR);
          return;
        }
        if (entry.node.children.has(message.name)) {
          // Always exclusive, whatever the flag word said.
          error(C.ERRNO_BY_NAME.EEXIST);
          return;
        }
        const created = file(new Uint8Array(0));
        entry.node.children.set(message.name, created);
        // `Tlcreate` rebinds the parent fid to the file it made.
        this.fids.set(message.fid, {
          node: created,
          parent: entry.node,
          name: message.name,
        });
        connection.send({
          kind: 'Rlcreate',
          tag: message.tag,
          qid: this.qid(created),
          iounit: 0,
        });
        return;
      }
      case 'Tread': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        const from = Number(message.offset);
        connection.send({
          kind: 'Rread',
          tag: message.tag,
          data: entry.node.bytes.subarray(from, from + message.count),
        });
        return;
      }
      case 'Twrite': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        let take = message.data.byteLength;
        if (this.shortWriteTo !== undefined) {
          take = Math.min(take, this.shortWriteTo);
          this.shortWriteTo = undefined;
        }
        const at = Number(message.offset);
        const grown = new Uint8Array(Math.max(entry.node.bytes.byteLength, at + take));
        grown.set(entry.node.bytes, 0);
        grown.set(message.data.subarray(0, take), at);
        entry.node.bytes = grown;
        connection.send({ kind: 'Rwrite', tag: message.tag, count: take });
        return;
      }
      case 'Tgetattr': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        const node = entry.node;
        connection.send({
          kind: 'Rgetattr',
          tag: message.tag,
          valid: BigInt(C.GETATTR_BASIC),
          qid: this.qid(node),
          mode: node.mode,
          // Zero, always: the real provider discloses no host identity either.
          uid: 0,
          gid: 0,
          nlink: 1n,
          rdev: 0n,
          size: BigInt(node.bytes.byteLength),
          blksize: 4096n,
          blocks: 1n,
          atimeSec: BigInt(Math.floor(node.mtimeMs / 1000)),
          atimeNsec: 0n,
          mtimeSec: BigInt(Math.floor(node.mtimeMs / 1000)),
          mtimeNsec: 0n,
          ctimeSec: BigInt(Math.floor(node.mtimeMs / 1000)),
          ctimeNsec: 0n,
          btimeSec: 0n,
          btimeNsec: 0n,
          gen: 0n,
          dataVersion: 0n,
        });
        return;
      }
      case 'Treaddir': {
        const entry = this.fids.get(message.fid);
        if (entry === undefined || entry.node.kind !== 'directory') {
          error(C.ERRNO_BY_NAME.ENOTDIR);
          return;
        }
        const names = [...entry.node.children.entries()];
        const from = Number(message.offset);
        const entries: DirEntry[] = [];
        for (let index = from; index < names.length; index += 1) {
          const [name, node] = names[index] as [string, Node];
          const qid = this.qid(node);
          entries.push({
            qid,
            offset: BigInt(index + 1),
            type: node.kind === 'directory' ? 4 : 8,
            name,
          });
        }
        connection.send({ kind: 'Rreaddir', tag: message.tag, entries });
        return;
      }
      case 'Tmkdir': {
        const entry = this.fids.get(message.dfid);
        if (entry === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        if (entry.node.children.has(message.name)) {
          error(C.ERRNO_BY_NAME.EEXIST);
          return;
        }
        const made = directory();
        entry.node.children.set(message.name, made);
        connection.send({ kind: 'Rmkdir', tag: message.tag, qid: this.qid(made) });
        return;
      }
      case 'Tunlinkat': {
        const entry = this.fids.get(message.dirfid);
        if (entry === undefined || !entry.node.children.has(message.name)) {
          error(C.ERRNO_BY_NAME.ENOENT);
          return;
        }
        entry.node.children.delete(message.name);
        connection.send({ kind: 'Runlinkat', tag: message.tag });
        return;
      }
      case 'Trename': {
        const entry = this.fids.get(message.fid);
        const target = this.fids.get(message.dfid);
        if (entry === undefined || target === undefined || entry.parent === undefined) {
          error(C.ERRNO_BY_NAME.EINVAL);
          return;
        }
        entry.parent.children.delete(entry.name);
        target.node.children.set(message.name, entry.node);
        connection.send({ kind: 'Rrename', tag: message.tag });
        return;
      }
      case 'Tsetattr':
        connection.send({ kind: 'Rsetattr', tag: message.tag });
        return;
      case 'Tclunk':
        this.fids.delete(message.fid);
        connection.send({ kind: 'Rclunk', tag: message.tag });
        return;
      case 'Tflush':
        connection.send({ kind: 'Rflush', tag: message.tag });
        return;
      default:
        error(C.ERRNO_BY_NAME.ENOTSUP);
    }
  };
}
