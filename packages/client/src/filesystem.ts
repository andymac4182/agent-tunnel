/**
 * `connectFilesystem`, and the shared client API of `docs/filesystem-api.md`.
 *
 * The descriptor fetch, the authenticated upgrade, the session, the bytes and
 * the limits. Composite operations — `copy`, a recursive `remove`,
 * `writeFile`'s create-or-truncate — are composed **here** from the primitives
 * gate 5 ships, which is where the contract puts them: "composite operations
 * are the shared client's to compose from these primitives and stay gate 6's".
 *
 * Nothing in this file retries anything. "Do not automatically retry mutations,
 * reads, or reconnect the shared client in the baseline": a failed operation is
 * reported with its outcome, and starting again is the caller's decision.
 */

import { constants as C } from './ninep/codec.ts';
import type { DirEntry, Message, Qid } from './ninep/messages.ts';
import {
  discoveryCode,
  GRANT_REVISION_HEADER,
  LIMIT_CEILINGS,
  SUBPROTOCOL,
  validateDescriptor,
  type Descriptor,
  type Operation,
} from './descriptor.ts';
import { FilesystemError, mergeOutcome, type Outcome } from './errors.ts';
import {
  splitParent,
  validateComponentForJoin,
  validatePath,
  type PathBounds,
} from './paths.ts';
import { ConsumerSession, ROOT_FID, type Lifecycle } from './session.ts';
import {
  isTlsVerificationFailure,
  requireSecureEndpoint,
  upgrade,
  UpgradeRejected,
  type BinaryTransport,
  type CloseInfo,
} from './websocket.ts';

export interface ConnectOptions {
  /** The canonical `https://…/fs` endpoint. Never a bare WebSocket URL. */
  endpoint: string;
  /**
   * An access-token supplier, called for each explicit connect.
   *
   * A supplier rather than a string, so the token is fresh and is never put in
   * a config file. It is read once per connect and is never stored on the
   * returned object: the client "exposes its immutable effective descriptor and
   * lifecycle state, never raw tokens or raw host paths".
   */
  token: () => string | Promise<string>;
  /** Cap the negotiated `msize` below the descriptor's, for testing and tuning. */
  maxMessageBytes?: number | undefined;
  /** The loopback development harness of the contract. Off by default. */
  allowInsecureLoopback?: boolean | undefined;
  signal?: AbortSignal | undefined;
}

export interface Stat {
  kind: 'file' | 'directory' | 'symlink';
  /** `BigInt`, because a 64-bit size does not fit a JavaScript number. */
  size: bigint;
  mode: number;
  /** Milliseconds since the epoch, for callers that want a `Date`. */
  modifiedAtMs: number;
  accessedAtMs: number;
  changedAtMs: number;
  /** Absent unless the `birthTime` feature is advertised and the host has one. */
  createdAtMs: number | undefined;
  /** The provider's scoped qid. Not a host inode: it discloses none. */
  qid: Qid;
}

export interface DirectoryEntry {
  name: string;
  kind: 'file' | 'directory' | 'symlink';
}

export interface ReadOptions {
  signal?: AbortSignal | undefined;
  offset?: bigint | undefined;
  length?: number | undefined;
}

export interface WriteOptions {
  signal?: AbortSignal | undefined;
  /** `false` uses exclusive creation, never an exists-then-create race. */
  overwrite?: boolean | undefined;
}

const KIND_BY_QID = new Map<number, 'file' | 'directory' | 'symlink'>([
  [C.QTFILE, 'file'],
  [C.QTDIR, 'directory'],
  [C.QTSYMLINK, 'symlink'],
]);

/**
 * The internal materialization budget.
 *
 * `maxTotalBufferedBytes` "covers concurrent client/adapter-owned
 * materialization buffers, conversion copies and retained caches", and a
 * reservation is released when the result's ownership transfers to the caller.
 * A returned `Uint8Array` therefore stops being charged — which is a real limit
 * of this accounting and is stated rather than papered over: **this client
 * cannot bound what an application retains.**
 */
export class MaterializationBudget {
  private used = 0;
  private readonly perFile: number;
  private readonly total: number;

  constructor(perFile: number, total: number) {
    this.perFile = perFile;
    this.total = total;
  }

  get outstanding(): number {
    return this.used;
  }

  /**
   * Grow one materialization from `from` bytes to `to`.
   *
   * The per-file ceiling is checked against the **running total**, not against
   * the increment: a 4 KiB file read 245 bytes at a time is still a 4 KiB
   * materialization, and checking each chunk would have let any file through
   * one message at a time. That is what "enforce while reading even if size
   * grows" means, and a preceding `stat` cannot do it.
   */
  grow(from: number, to: number, operation: string, path?: string): void {
    this.reserve(to - from, operation, path, to);
    // The earlier reservation is subsumed by the new one rather than held
    // twice.
    this.used -= from;
  }

  reserve(bytes: number, operation: string, path?: string, materialized = bytes): void {
    if (materialized > this.perFile) {
      throw new FilesystemError({
        code: 'EFBIG',
        operation,
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    if (this.used + bytes > this.total) {
      // Enforced **before** allocating, which is what the contract asks for:
      // concurrent reads cannot each reserve the full limit independently.
      throw new FilesystemError({
        code: 'RESOURCE_EXHAUSTED',
        operation,
        path,
        outcome: 'not_started',
        retryable: true,
      });
    }
    this.used += bytes;
  }

  release(bytes: number): void {
    this.used = Math.max(0, this.used - bytes);
  }
}

/** The connected client. A closed one is not reusable and never reconnects. */
export class RemoteFilesystem {
  private readonly bounds: PathBounds;
  readonly budget: MaterializationBudget;
  readonly descriptor: Descriptor;
  private readonly session: ConsumerSession;
  private readonly transport: BinaryTransport;

  constructor(descriptor: Descriptor, session: ConsumerSession, transport: BinaryTransport) {
    this.descriptor = descriptor;
    this.session = session;
    this.transport = transport;
    this.bounds = {
      maxPathBytes: descriptor.limits.maxPathBytes,
      maxPathComponents: descriptor.limits.maxPathComponents,
    };
    this.budget = new MaterializationBudget(
      descriptor.limits.maxBufferedFileBytes,
      descriptor.limits.maxTotalBufferedBytes,
    );
  }

  get state(): Lifecycle {
    return this.session.state;
  }

  /** How the session ended, once it has. The code, not a verdict about effects. */
  get closedWith(): CloseInfo | undefined {
    return this.session.closedWith;
  }

  /** The negotiated `msize`, which may be below the descriptor's. */
  get msize(): number {
    return this.session.msize;
  }

  /** Whether an operation is advertised. Derived on the device from primitives. */
  supports(operation: Operation): boolean {
    return this.descriptor.operations.includes(operation);
  }

  private require(operation: Operation, path?: string): void {
    if (!this.supports(operation)) {
      // "Implement only when advertised; unsupported operations fail rather
      // than invent semantics."
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation,
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
  }

  /* ---------------------------------------------------------------- *
   * Primitives
   * ---------------------------------------------------------------- */

  /**
   * Walk to a path, binding a fresh fid.
   *
   * `MAXWELEM` bounds one `Twalk` at 16 names, so a deeper path is several
   * walks — each from the fid the last one bound, which is what keeps the
   * traversal confined to one export. A **partial** walk binds nothing, so the
   * fid is released and the path reported absent.
   */
  private async walk(path: string, signal?: AbortSignal): Promise<number> {
    const components = validatePath(path, this.bounds);
    const fid = this.session.allocateFid();
    let from = ROOT_FID;
    let bound = false;
    try {
      if (components.length === 0) {
        const reply = await this.session.request(
          { kind: 'Twalk', tag: 0, fid: ROOT_FID, newfid: fid, wnames: [] },
          { signal },
        );
        if (reply.kind !== 'Rwalk') {
          throw this.unexpected('walk', path);
        }
        return fid;
      }
      for (let at = 0; at < components.length; at += C.MAXWELEM) {
        const names = components.slice(at, at + C.MAXWELEM);
        const reply = await this.session.request(
          { kind: 'Twalk', tag: 0, fid: bound ? fid : from, newfid: fid, wnames: names },
          { signal },
        );
        if (reply.kind !== 'Rwalk') {
          throw this.unexpected('walk', path);
        }
        if (reply.wqids.length < names.length) {
          // A partial walk binds nothing: the name that failed is the one that
          // is absent, and this side must not pretend a fid exists.
          throw new FilesystemError({
            code: 'ENOENT',
            operation: 'walk',
            path,
            outcome: 'not_started',
            retryable: false,
          });
        }
        bound = true;
        from = fid;
      }
      return fid;
    } catch (error) {
      if (bound) {
        await this.clunkQuietly(fid);
      } else {
        this.session.releaseFid(fid);
      }
      throw error;
    }
  }

  private async clunkQuietly(fid: number): Promise<void> {
    if (fid === ROOT_FID || this.state === 'closed') {
      this.session.releaseFid(fid);
      return;
    }
    try {
      await this.session.request({ kind: 'Tclunk', tag: 0, fid });
    } catch {
      // A failed clunk still releases the fid on the device — 9P's own rule —
      // so holding the number here would leak it against this side's quota.
    }
    this.session.releaseFid(fid);
  }

  private unexpected(operation: string, path?: string): FilesystemError {
    return new FilesystemError({
      code: 'EINVAL',
      operation,
      path,
      outcome: 'not_started',
      retryable: false,
    });
  }

  private async getattr(fid: number, signal?: AbortSignal): Promise<Stat> {
    const reply = await this.session.request(
      { kind: 'Tgetattr', tag: 0, fid, requestMask: BigInt(C.GETATTR_BASIC) },
      { signal },
    );
    if (reply.kind !== 'Rgetattr') {
      throw this.unexpected('stat');
    }
    const kind = KIND_BY_QID.get(reply.qid.type) ?? 'file';
    const birth = (reply.valid & BigInt(C.GETATTR_BTIME)) !== 0n;
    return {
      kind,
      size: reply.size,
      mode: reply.mode,
      modifiedAtMs: msFrom(reply.mtimeSec, reply.mtimeNsec),
      accessedAtMs: msFrom(reply.atimeSec, reply.atimeNsec),
      changedAtMs: msFrom(reply.ctimeSec, reply.ctimeNsec),
      // Absent rather than 1970: "a provider that set `btime` and reported zero
      // would be reporting a birth time of 1970 as a birth time", and a client
      // that read the field regardless would repeat the lie.
      createdAtMs:
        birth && this.descriptor.features.birthTime
          ? msFrom(reply.btimeSec, reply.btimeNsec)
          : undefined,
      qid: reply.qid,
    };
  }

  /* ---------------------------------------------------------------- *
   * The shared API
   * ---------------------------------------------------------------- */

  async stat(path: string, options: { signal?: AbortSignal | undefined } = {}): Promise<Stat> {
    this.require('stat', path);
    const fid = await this.walk(path, options.signal);
    try {
      return await this.getattr(fid, options.signal);
    } finally {
      await this.clunkQuietly(fid);
    }
  }

  /**
   * Read a whole file into memory.
   *
   * The materialization ceiling is enforced **while reading**, not from a
   * preceding `stat`: "enforce while reading even if size grows". A file that
   * grows past the limit under the read fails rather than returning a prefix
   * that looks whole.
   */
  async readFile(path: string, options: ReadOptions = {}): Promise<Uint8Array> {
    this.require('readFile', path);
    const chunks: Uint8Array[] = [];
    let total = 0;
    let reserved = 0;
    try {
      for await (const chunk of this.readStream(path, options)) {
        total += chunk.byteLength;
        if (total > reserved) {
          this.budget.grow(reserved, total, 'readFile', path);
          reserved = total;
        }
        chunks.push(chunk);
      }
      const out = new Uint8Array(total);
      let at = 0;
      for (const chunk of chunks) {
        out.set(chunk, at);
        at += chunk.byteLength;
      }
      return out;
    } finally {
      // Ownership of the result transfers to the caller, so the reservation is
      // released — and a sequential read therefore reuses the quota. What the
      // caller then retains is outside this bound, deliberately and
      // unavoidably.
      this.budget.release(reserved);
    }
  }

  /** Bounded byte chunks. Streaming bypasses the per-file ceiling, not the queue. */
  async *readStream(path: string, options: ReadOptions = {}): AsyncGenerator<Uint8Array> {
    this.require('readStream', path);
    const fid = await this.walk(path, options.signal);
    let opened = false;
    try {
      const open = await this.session.request(
        { kind: 'Tlopen', tag: 0, fid, flags: C.O_RDONLY },
        { signal: options.signal },
      );
      if (open.kind !== 'Rlopen') {
        throw this.unexpected('readStream', path);
      }
      opened = true;
      let offset = options.offset ?? 0n;
      let remaining = options.length ?? Number.POSITIVE_INFINITY;
      const chunk = this.session.msize - C.COUNTED_REPLY_OVERHEAD;
      for (;;) {
        if (remaining <= 0) {
          return;
        }
        const count = Math.min(chunk, remaining === Number.POSITIVE_INFINITY ? chunk : remaining);
        const reply = await this.session.request(
          { kind: 'Tread', tag: 0, fid, offset, count },
          { signal: options.signal },
        );
        if (reply.kind !== 'Rread') {
          throw this.unexpected('readStream', path);
        }
        if (reply.data.byteLength === 0) {
          // End of file. A short read that is not empty is ordinary and is not
          // an end of file, which is why this tests for zero and not for
          // "fewer bytes than asked".
          return;
        }
        offset += BigInt(reply.data.byteLength);
        if (remaining !== Number.POSITIVE_INFINITY) {
          remaining -= reply.data.byteLength;
        }
        yield reply.data;
      }
    } finally {
      if (opened || this.state !== 'closed') {
        await this.clunkQuietly(fid);
      }
    }
  }

  /** Immediate children, paged by the opaque directory cookie. */
  async *readDirectory(
    path: string,
    options: { signal?: AbortSignal | undefined } = {},
  ): AsyncGenerator<DirectoryEntry> {
    this.require('readDirectory', path);
    const fid = await this.walk(path, options.signal);
    try {
      const open = await this.session.request(
        { kind: 'Tlopen', tag: 0, fid, flags: C.O_RDONLY | C.O_DIRECTORY },
        { signal: options.signal },
      );
      if (open.kind !== 'Rlopen') {
        throw this.unexpected('readDirectory', path);
      }
      let cookie = 0n;
      let seen = 0;
      for (;;) {
        const reply = await this.session.request(
          {
            kind: 'Treaddir',
            tag: 0,
            fid,
            offset: cookie,
            count: this.session.msize - C.COUNTED_REPLY_OVERHEAD,
          },
          { signal: options.signal },
        );
        if (reply.kind !== 'Rreaddir') {
          throw this.unexpected('readDirectory', path);
        }
        if (reply.entries.length === 0) {
          return;
        }
        for (const entry of reply.entries) {
          cookie = entry.offset;
          if (entry.name === '.' || entry.name === '..') {
            continue;
          }
          seen += 1;
          if (seen > this.descriptor.limits.maxTraversalEntries) {
            // "Exceeding traversal limits fails explicitly, not with a false
            // complete page."
            throw new FilesystemError({
              code: 'EFBIG',
              operation: 'readDirectory',
              path,
              outcome: 'not_started',
              retryable: false,
            });
          }
          yield { name: entry.name, kind: KIND_BY_QID.get(entry.qid.type) ?? 'file' };
        }
      }
    } finally {
      await this.clunkQuietly(fid);
    }
  }

  /**
   * Create or truncate, with no parent creation.
   *
   * `overwrite: false` is `Tlcreate`, which this profile makes exclusive
   * whatever the flag word says — never an exists-then-create race.
   * `overwrite: true` tries the same create first and falls back to a
   * truncating open **only** on `EEXIST`, so the common path takes no
   * preliminary `stat` either.
   */
  async writeFile(path: string, bytes: Uint8Array, options: WriteOptions = {}): Promise<void> {
    this.require('writeFile', path);
    await this.writeInto('writeFile', path, [bytes], options);
  }

  /** The same, over an iterable of chunks, reporting acknowledged bytes. */
  async writeStream(
    path: string,
    chunks: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
    options: WriteOptions = {},
  ): Promise<void> {
    this.require('writeStream', path);
    await this.writeInto('writeStream', path, chunks, options);
  }

  private async writeInto(
    operation: 'writeFile' | 'writeStream' | 'copy',
    path: string,
    chunks: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
    options: WriteOptions,
  ): Promise<void> {
    const overwrite = options.overwrite ?? true;
    const { parent, name } = splitParent(path, this.bounds);
    const parentFid = await this.walk(parent, options.signal);
    // `undefined` means "nothing is bound to clunk". It is not `parentFid`
    // between the clunk below and the re-walk that replaces it: if that walk
    // throws, the `finally` would otherwise clunk and release a fid this side
    // has already given back — two `Tclunk`s for one fid on the wire, the
    // number free twice in the pool, and the next two operations handed the
    // same fid, which the device answers `EINVAL` for one of them while this
    // side's fid quota silently stops counting.
    let fid: number | undefined = parentFid;
    let acknowledged = 0;
    let outcome: Outcome = 'not_started';
    try {
      try {
        const created = await this.session.request(
          {
            kind: 'Tlcreate',
            tag: 0,
            fid: parentFid,
            name,
            flags: C.O_WRONLY,
            mode: 0o644,
            gid: 0,
          },
          { signal: options.signal },
        );
        if (created.kind !== 'Rlcreate') {
          throw this.unexpected(operation, path);
        }
        // `Tlcreate` rebinds the parent fid to the file it made — and **the
        // file now exists**, so from here nothing this composite does can be
        // reported `not_started`. Without this floor, a `copy` whose source
        // turns out to be absent reports `not_started` with an empty
        // destination already created, and an abort between the `Rlcreate` and
        // the first `Twrite` does the same. That is the class gate 5 spent a
        // round removing on the device side, and a client must not put it back.
        //
        // The floor is **`partial`**, not `failed`. A composite that provably
        // applied one of its steps and not the rest is what `partial` names;
        // `failed` is the single request whose effecting call was refused, and
        // using it here would spell those two situations the same way.
        outcome = mergeOutcome(outcome, 'partial');
      } catch (error) {
        const failed = error as FilesystemError;
        if (!overwrite || failed.code !== 'EEXIST') {
          throw failed;
        }
        // An `Rlerror(EEXIST)` means the create was refused and made nothing,
        // so the floor above was never reached on this path.
        await this.clunkQuietly(parentFid);
        fid = undefined;
        fid = await this.walk(path, options.signal);
        const opened = await this.session.request(
          { kind: 'Tlopen', tag: 0, fid, flags: C.O_WRONLY | C.O_TRUNC },
          { signal: options.signal },
        );
        if (opened.kind !== 'Rlopen') {
          throw this.unexpected(operation, path);
        }
        // A truncating open **carries an effect** — the file is now empty — so
        // from here nothing can be reported `not_started`, and for the same
        // reason as the create above the floor is `partial`.
        outcome = mergeOutcome(outcome, 'partial');
      }
      const target = fid;
      if (target === undefined) {
        throw this.unexpected(operation, path);
      }
      const limit = this.session.msize - C.WRITE_REQUEST_OVERHEAD;
      let offset = 0n;
      for await (const chunk of asAsync(chunks)) {
        let at = 0;
        while (at < chunk.byteLength) {
          const slice = chunk.subarray(at, at + limit);
          const reply = await this.session.request(
            { kind: 'Twrite', tag: 0, fid: target, offset, data: slice },
            { signal: options.signal },
          );
          if (reply.kind !== 'Rwrite') {
            throw this.unexpected(operation, path);
          }
          // A short write is ordinary: the acknowledged count is the lower
          // bound `bytesAcknowledged` is built from, and the remainder is sent
          // as a fresh write rather than replayed.
          acknowledged += reply.count;
          offset += BigInt(reply.count);
          at += reply.count;
          if (reply.count === 0) {
            throw new FilesystemError({
              code: 'EFBIG',
              operation,
              path,
              outcome: mergeOutcome(outcome, acknowledged > 0 ? 'partial' : 'failed'),
              retryable: false,
              bytesAcknowledged: acknowledged,
            });
          }
          outcome = mergeOutcome(outcome, 'partial');
        }
      }
    } catch (error) {
      if (!(error instanceof FilesystemError)) {
        // Not one of ours: a `PathRefusal`, or — the case that matters here —
        // an exception thrown by the caller's **own** chunk source, which
        // `writeStream` and `copy` both iterate inside this `try`.
        //
        // If nothing has been applied it is passed through untouched: it is the
        // caller's error and none of this client's business. If something has,
        // it is wrapped, because a created file plus an error carrying no
        // `outcome` is exactly the ambiguity a retry wrapper misreads as "safe
        // to try again".
        const floor = mergeOutcome(outcome, acknowledged > 0 ? 'partial' : 'not_started');
        if (floor === 'not_started') {
          throw error;
        }
        throw new FilesystemError({
          code: 'EINVAL',
          operation,
          path,
          outcome: floor,
          retryable: false,
          bytesAcknowledged: acknowledged,
          cause: error,
        });
      }
      const failed = error;
      // The composite's own outcome is merged with the failing step's, and the
      // merge only ever strengthens: a write that acknowledged bytes and then
      // lost its session is `partial`-or-worse and can never be reported
      // `not_started`.
      throw new FilesystemError({
        code: failed.code,
        operation,
        path,
        outcome: mergeOutcome(
          mergeOutcome(outcome, acknowledged > 0 ? 'partial' : 'not_started'),
          failed.outcome,
        ),
        retryable: false,
        bytesAcknowledged: acknowledged,
        closeCode: failed.closeCode,
      });
    } finally {
      if (fid !== undefined) {
        await this.clunkQuietly(fid);
      }
    }
  }

  /** Atomic append positioning per write, if advertised. It is not. */
  async appendFile(path: string, _bytes: Uint8Array): Promise<void> {
    this.require('appendFile', path);
    if (!this.descriptor.features.nativeAppend) {
      // Gate 5 refuses `O_APPEND` with `ENOTSUP` and does not advertise
      // `nativeAppend`, because the two hosts disagree about whether `pwrite`
      // honours its offset on an appending descriptor. Emulating it with a
      // stat and a positioned write is exactly the race the contract forbids,
      // so this refuses instead.
      throw new FilesystemError({
        code: 'ENOTSUP',
        operation: 'appendFile',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    throw new FilesystemError({
      code: 'ENOTSUP',
      operation: 'appendFile',
      path,
      outcome: 'not_started',
      retryable: false,
    });
  }

  /**
   * Create a directory, and its parents when asked.
   *
   * A recursive `mkdir` is a **composite**, so it carries the same floor
   * `writeFile` does: once any `Rmkdir` has arrived, a directory exists that did
   * not before, and no later failure may be reported `not_started`. Without it,
   * `mkdir('/a/b', { recursive: true })` interrupted after `/a` was made told
   * the caller nothing had happened, with `/a` standing in the export.
   */
  async mkdir(path: string, options: { recursive?: boolean | undefined; signal?: AbortSignal | undefined } = {}): Promise<void> {
    this.require('mkdir', path);
    const components = validatePath(path, this.bounds);
    const recursive = options.recursive === true;
    const targets = recursive ? components.map((_, index) => index + 1) : [components.length];
    let made = 0;
    for (const depth of targets) {
      const at = `/${components.slice(0, depth).join('/')}`;
      const { parent, name } = splitParent(at, this.bounds);
      let parentFid: number;
      try {
        parentFid = await this.walk(parent, options.signal);
      } catch (error) {
        throw this.withCompositeFloor(error, 'mkdir', path, made > 0);
      }
      try {
        await this.session.request(
          { kind: 'Tmkdir', tag: 0, dfid: parentFid, name, mode: 0o755, gid: 0 },
          { signal: options.signal },
        );
        made += 1;
      } catch (error) {
        const failed = error as FilesystemError;
        // Only `recursive` may ignore an existing directory, and it ignores
        // nothing else: a permission failure is still a failure. A plain
        // `mkdir` of a name that exists is `EEXIST`, which is what a caller
        // that did not ask for the chain needs to be told.
        //
        // An ignored `EEXIST` made nothing, so it does not move the floor.
        if (!(recursive && failed.code === 'EEXIST')) {
          throw this.withCompositeFloor(failed, 'mkdir', path, made > 0);
        }
      } finally {
        await this.clunkQuietly(parentFid);
      }
    }
  }

  /**
   * Re-report a composite's failure with the floor its own progress sets.
   *
   * `applied` means this operation has provably changed the export already, so
   * the result cannot be `not_started` however the step that failed describes
   * itself. The merge is gate 1's and only ever strengthens, so a step that was
   * `unknown` stays `unknown`.
   */
  private withCompositeFloor(
    error: unknown,
    operation: string,
    path: string,
    applied: boolean,
  ): unknown {
    if (!applied) {
      // Nothing has been applied, so there is no floor to impose and nothing
      // is gained by rewriting whatever this is.
      return error;
    }
    if (!(error instanceof FilesystemError)) {
      // Something that carries no outcome at all — a `PathRefusal`, or an
      // exception out of a caller's own chunk source — escaping an operation
      // that **has** changed the export. A retry wrapper reading `outcome`
      // would see `undefined` and be free to try again over an applied
      // mutation, which is the failure this whole class of fix exists to
      // prevent. It is wrapped so the outcome exists, with the original kept as
      // `cause` so nothing is lost by wrapping it.
      // `partial` is written out rather than merged because this branch is
      // only reached once something applied, so it is the same floor the merge
      // below would produce; if the vocabulary ever changes, both must move.
      const code =
        error instanceof Error && error.name === 'AbortError'
          ? 'ABORTED'
          : 'EINVAL';
      return new FilesystemError({
        code,
        operation,
        path,
        outcome: 'partial',
        retryable: false,
        cause: error,
      });
    }
    return new FilesystemError({
      code: error.code,
      operation,
      path: error.path ?? path,
      outcome: mergeOutcome(error.outcome, 'partial'),
      retryable: false,
      bytesAcknowledged: error.bytesAcknowledged,
      closeCode: error.closeCode,
      cause: error.cause,
    });
  }

  /**
   * Remove a name. Nonrecursive by default; recursive traversal is bounded.
   *
   * `force` suppresses **only** absence, and nothing else: a permission failure
   * or a non-empty directory is still an error, because suppressing those would
   * report a removal that did not happen.
   */
  async remove(
    path: string,
    options: { recursive?: boolean | undefined; force?: boolean | undefined; signal?: AbortSignal | undefined } = {},
    depth = 0,
    progress: { entries: number; removed: number } = { entries: 0, removed: 0 },
  ): Promise<void> {
    try {
      await this.removeInner(path, options, depth, progress);
    } catch (error) {
      // A recursive removal is a composite, and its outcome is the
      // **composite's**, not the last request's. Removing two of three children
      // and then meeting an `EACCES` is not `not_started`: two names are gone.
      // The counter is shared by reference down the recursion, so the floor is
      // the same fact at every level.
      throw this.withCompositeFloor(error, 'remove', path, progress.removed > 0);
    }
  }

  private async removeInner(
    path: string,
    options: { recursive?: boolean | undefined; force?: boolean | undefined; signal?: AbortSignal | undefined },
    depth: number,
    progress: { entries: number; removed: number },
  ): Promise<void> {
    this.require('remove', path);
    if (depth > this.descriptor.limits.maxTraversalDepth) {
      throw new FilesystemError({
        code: 'ELOOP',
        operation: 'remove',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    let kind: Stat['kind'];
    try {
      kind = (await this.stat(path, { signal: options.signal })).kind;
    } catch (error) {
      const failed = error as FilesystemError;
      if (options.force === true && failed.code === 'ENOENT') {
        return;
      }
      throw failed;
    }
    if (kind === 'directory' && options.recursive === true) {
      const children: DirectoryEntry[] = [];
      for await (const entry of this.readDirectory(path, { signal: options.signal })) {
        children.push(entry);
      }
      for (const child of children) {
        // The traversal-entry limit bounds the **whole** recursive removal, not
        // one directory's pages: a tree of ten thousand single-entry
        // directories is ten thousand entries however they are spread. The
        // counter is threaded through the recursion for that reason.
        progress.entries += 1;
        if (progress.entries > this.descriptor.limits.maxTraversalEntries) {
          throw new FilesystemError({
            code: 'EFBIG',
            operation: 'remove',
            path,
            // Decided by what has actually been removed, not by how deep the
            // traversal is. Removal is **post-order**, so a budget that fires
            // during the descent has sent no `Tunlinkat` at all: reporting
            // `partial` there — as an earlier round did, keyed on depth —
            // claimed an effect that had not happened. The wrapper above
            // supplies the floor once one has.
            outcome: 'not_started',
            retryable: false,
          });
        }
        const childPath = `${path === '/' ? '' : path}/${child.name}`;
        // **The name came from the device, not from the caller.** A `Treaddir`
        // lists whatever the host holds, and the provider skips only `.`, `..`,
        // special files and foreign mounts — so an ordinary host file named
        // `notes.` or `CON` is listed and is then refused by this namespace's
        // own rules on the way back. Left alone, that refusal is a
        // `PathRefusal` with no outcome, thrown after earlier siblings were
        // already unlinked.
        //
        // It is converted here, at the name, rather than being caught further
        // out: the failure is that this export holds a name this profile cannot
        // address, which is `EINVAL` and is `not_started` **for this child**,
        // and the composite's own floor is then applied above by whatever has
        // been removed already.
        try {
          validateComponentForJoin(child.name);
        } catch (error) {
          throw new FilesystemError({
            code: 'EINVAL',
            operation: 'remove',
            path: childPath,
            outcome: 'not_started',
            retryable: false,
            cause: error,
          });
        }
        await this.removeInner(childPath, options, depth + 1, progress);
      }
    }
    const { parent, name } = splitParent(path, this.bounds);
    const parentFid = await this.walk(parent, options.signal);
    try {
      await this.session.request(
        {
          kind: 'Tunlinkat',
          tag: 0,
          dirfid: parentFid,
          name,
          flags: kind === 'directory' ? C.AT_REMOVEDIR : 0,
        },
        { signal: options.signal },
      );
      progress.removed += 1;
    } catch (error) {
      const failed = error as FilesystemError;
      if (options.force === true && failed.code === 'ENOENT') {
        return;
      }
      throw failed;
    } finally {
      await this.clunkQuietly(parentFid);
    }
  }

  /**
   * Native in-export rename. Never copy-and-delete.
   *
   * `Trenameat` needs the `atomicRename` feature, so an export without it is
   * renamed through `Trename`, which names the source by **fid** — the same
   * confinement, one fewer name to resolve.
   */
  async rename(source: string, destination: string, options: { signal?: AbortSignal | undefined } = {}): Promise<void> {
    this.require('rename', source);
    const target = splitParent(destination, this.bounds);
    if (this.descriptor.features.atomicRename) {
      const from = splitParent(source, this.bounds);
      const oldParent = await this.walk(from.parent, options.signal);
      // The second walk is inside its own guard: a fid bound before a `try` and
      // released only inside it leaks on both sides when the step between them
      // throws — the same shape as the `writeInto` fallback, one operation
      // later. A rename to a directory that does not exist used to leak the
      // source parent's fid, permanently, once per attempt.
      let newParent: number;
      try {
        newParent = await this.walk(target.parent, options.signal);
      } catch (error) {
        await this.clunkQuietly(oldParent);
        throw error;
      }
      try {
        await this.session.request(
          {
            kind: 'Trenameat',
            tag: 0,
            olddirfid: oldParent,
            oldname: from.name,
            newdirfid: newParent,
            newname: target.name,
          },
          { signal: options.signal },
        );
      } finally {
        await this.clunkQuietly(oldParent);
        await this.clunkQuietly(newParent);
      }
      return;
    }
    const fid = await this.walk(source, options.signal);
    let newParent: number;
    try {
      newParent = await this.walk(target.parent, options.signal);
    } catch (error) {
      await this.clunkQuietly(fid);
      throw error;
    }
    try {
      await this.session.request(
        { kind: 'Trename', tag: 0, fid, dfid: newParent, name: target.name },
        { signal: options.signal },
      );
    } finally {
      await this.clunkQuietly(fid);
      await this.clunkQuietly(newParent);
    }
  }

  /**
   * A bounded composed read and write in one export.
   *
   * No server-side copy and no atomicity claim: this is exactly a read and a
   * write, it can partially apply, and its failure says so.
   */
  async copy(source: string, destination: string, options: WriteOptions = {}): Promise<void> {
    this.require('copy', source);
    // **Both** paths are validated here, before anything is created. The read
    // is lazy, so a source the namespace refuses would otherwise be refused
    // *after* the destination existed — an effect this operation would then
    // report with a `PathRefusal` that has no outcome field to carry it.
    validatePath(source, this.bounds);
    validatePath(destination, this.bounds);
    await this.writeInto('copy', destination, this.readStream(source, { signal: options.signal }), options);
  }

  async readlink(path: string, options: { signal?: AbortSignal | undefined } = {}): Promise<string> {
    this.require('readlink', path);
    const fid = await this.walk(path, options.signal);
    try {
      const reply = await this.session.request({ kind: 'Treadlink', tag: 0, fid }, options);
      if (reply.kind !== 'Rreadlink') {
        throw this.unexpected('readlink', path);
      }
      return reply.target;
    } finally {
      await this.clunkQuietly(fid);
    }
  }

  async symlink(target: string, path: string, options: { signal?: AbortSignal | undefined } = {}): Promise<void> {
    this.require('symlink', path);
    const { parent, name } = splitParent(path, this.bounds);
    const parentFid = await this.walk(parent, options.signal);
    try {
      await this.session.request(
        { kind: 'Tsymlink', tag: 0, fid: parentFid, name, symtgt: target, gid: 0 },
        options,
      );
    } finally {
      await this.clunkQuietly(parentFid);
    }
  }

  async chmod(path: string, mode: number, options: { signal?: AbortSignal | undefined } = {}): Promise<void> {
    this.require('chmod', path);
    if ((mode & ~0o777) !== 0) {
      // Refused, never masked: set-user-ID, set-group-ID and the sticky bit
      // are not bits this profile grants, and quietly dropping them would
      // report a mode that was not applied.
      throw new FilesystemError({
        code: 'EINVAL',
        operation: 'chmod',
        path,
        outcome: 'not_started',
        retryable: false,
      });
    }
    const fid = await this.walk(path, options.signal);
    try {
      await this.session.request(
        {
          kind: 'Tsetattr',
          tag: 0,
          fid,
          valid: C.SETATTR_MODE,
          mode,
          uid: 0,
          gid: 0,
          size: 0n,
          atimeSec: 0n,
          atimeNsec: 0n,
          mtimeSec: 0n,
          mtimeNsec: 0n,
        },
        options,
      );
    } finally {
      await this.clunkQuietly(fid);
    }
  }

  async utimes(
    path: string,
    accessedAtMs: number,
    modifiedAtMs: number,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<void> {
    this.require('utimes', path);
    const fid = await this.walk(path, options.signal);
    try {
      await this.session.request(
        {
          kind: 'Tsetattr',
          tag: 0,
          fid,
          valid:
            C.SETATTR_ATIME | C.SETATTR_ATIME_SET | C.SETATTR_MTIME | C.SETATTR_MTIME_SET,
          mode: 0,
          uid: 0,
          gid: 0,
          size: 0n,
          atimeSec: BigInt(Math.floor(accessedAtMs / 1000)),
          atimeNsec: BigInt((accessedAtMs % 1000) * 1_000_000),
          mtimeSec: BigInt(Math.floor(modifiedAtMs / 1000)),
          mtimeNsec: BigInt((modifiedAtMs % 1000) * 1_000_000),
        },
        options,
      );
    } finally {
      await this.clunkQuietly(fid);
    }
  }

  /**
   * Close.
   *
   * It rejects every pending operation **locally** and closes the socket. It
   * does **not** send `Tflush` for what is outstanding, and it does not clunk
   * the fids it still holds within a deadline, which is what item 6 of the
   * contract's 9P binding asks of a graceful close. That is a named gap rather
   * than a claim: the session ends either way, the device releases every fid
   * with the stream, and a client that flushed and clunked on the way out would
   * be describing an orderly shutdown this one does not perform. See the gate-6
   * residue in `docs/filesystem-api.md`.
   *
   * What it does guarantee: the object cannot be reused, and there is no
   * reconnect behind the caller's back, so a later call fails rather than
   * quietly opening a second session under a token this object no longer holds.
   */
  async close(): Promise<void> {
    this.session.close();
    if (this.transport.isOpen) {
      this.transport.close(1000, 'client-close');
    }
    await Promise.resolve();
  }
}

/** Refuse before acting when the caller has already cancelled. */
function throwIfAborted(signal: AbortSignal | undefined, operation: string): void {
  if (signal?.aborted === true) {
    throw new FilesystemError({
      code: 'ABORTED',
      operation,
      outcome: 'not_started',
      retryable: false,
    });
  }
}

function msFrom(seconds: bigint, nanoseconds: bigint): number {
  // A 64-bit second count does not fit a `number`, so the conversion is
  // checked rather than rounded: "numeric size/time conversion must fail on
  // unrepresentable values rather than round or wrap".
  const ms = seconds * 1000n + nanoseconds / 1_000_000n;
  if (ms > BigInt(Number.MAX_SAFE_INTEGER) || ms < BigInt(Number.MIN_SAFE_INTEGER)) {
    throw new FilesystemError({
      code: 'EINVAL',
      operation: 'stat:time',
      outcome: 'not_started',
      retryable: false,
    });
  }
  return Number(ms);
}

async function* asAsync(
  chunks: Iterable<Uint8Array> | AsyncIterable<Uint8Array>,
): AsyncGenerator<Uint8Array> {
  if (Symbol.asyncIterator in chunks) {
    yield* chunks as AsyncIterable<Uint8Array>;
    return;
  }
  yield* chunks as Iterable<Uint8Array>;
}

/* ------------------------------------------------------------------ *
 * Discovery and connect
 * ------------------------------------------------------------------ */

/** Fetch and validate the descriptor. No session is opened. */
export async function fetchDescriptor(options: ConnectOptions): Promise<Descriptor> {
  const url = new URL(options.endpoint);
  requireSecureEndpoint(url, options.allowInsecureLoopback ?? false);
  throwIfAborted(options.signal, 'descriptor');
  const token = await options.token();
  // A token supplier can await anything — a network call to an identity
  // provider, most often — so the signal is checked on both sides of it rather
  // than only before.
  throwIfAborted(options.signal, 'descriptor');
  let response: Response;
  try {
    response = await fetch(url, {
      method: 'GET',
      headers: { Authorization: `Bearer ${token}`, Accept: 'application/json' },
      // "Do not follow cross-origin redirects or trust an arbitrary WS URL
      // returned in JSON": no redirect is followed at all, which is the simpler
      // rule and the one that cannot be got around by a same-origin hop.
      redirect: 'manual',
      signal: options.signal ?? null,
    });
  } catch (error) {
    // A transport failure reached callers as whatever `fetch` threw — a bare
    // `TypeError` — so a caller branching on `error.code` saw nothing. Every
    // failure out of this function is a `FilesystemError`, and a certificate
    // this side could not verify is **not** an outage: it is reported
    // `INSECURE_ENDPOINT` and is never retryable, because retrying reaches the
    // same untrusted peer.
    if ((error as { name?: unknown }).name === 'AbortError') {
      throw new FilesystemError({
        code: 'ABORTED',
        operation: 'descriptor',
        outcome: 'not_started',
        retryable: false,
      });
    }
    const cause = (error as { cause?: unknown }).cause ?? error;
    const tls = isTlsVerificationFailure(cause);
    throw new FilesystemError({
      code: tls ? 'INSECURE_ENDPOINT' : 'BACKEND_UNAVAILABLE',
      operation: tls ? 'descriptor:tls' : 'descriptor:connect',
      outcome: 'not_started',
      retryable: !tls,
    });
  }
  if (response.status !== 200) {
    const body: unknown = await response.json().catch(() => undefined);
    throw new FilesystemError({
      code: discoveryCode(response.status, body),
      operation: 'descriptor',
      outcome: 'not_started',
      retryable: response.status === 429 || response.status === 503,
    });
  }
  const type = response.headers.get('content-type') ?? '';
  if (!type.toLowerCase().startsWith('application/json')) {
    throw new FilesystemError({
      code: 'MALFORMED_DESCRIPTOR',
      operation: 'descriptor:content-type',
      outcome: 'not_started',
      retryable: false,
    });
  }
  return validateDescriptor(await response.json());
}

/**
 * Connect: descriptor, then upgrade at the **same** URL with that descriptor's
 * grant revision, then version and attach.
 *
 * "Node clients send the descriptor's `grantRevision` as
 * `X-Agent-Tunnel-Grant-Revision`; mismatch returns 409 `CAPABILITIES_CHANGED`,
 * requiring a fresh descriptor." Sending it is what makes a cached descriptor
 * unable to authorize access: this client never reuses one across a connect,
 * and a revision that moved between the two requests is refused by the relay
 * rather than papered over here.
 */
export async function connectFilesystem(options: ConnectOptions): Promise<RemoteFilesystem> {
  const descriptor = await fetchDescriptor(options);
  if (descriptor.availability !== 'online') {
    throw new FilesystemError({
      code: 'DEVICE_OFFLINE',
      operation: 'connect',
      outcome: 'not_started',
      retryable: true,
    });
  }
  const url = new URL(options.endpoint);
  throwIfAborted(options.signal, 'connect');
  const token = await options.token();
  throwIfAborted(options.signal, 'connect');
  const msize = Math.min(
    descriptor.limits.maxMessageBytes,
    options.maxMessageBytes ?? LIMIT_CEILINGS.maxMessageBytes,
  );
  // The descriptor's own single-request deadline bounds the handshake as well.
  // Every step of this function is now bounded and cancellable: the fetch by
  // the caller's signal, the upgrade by both, and the `Tversion` by the
  // session's request timer. A peer that answers the 101 and then says nothing
  // used to hold this call open for ever.
  const handshakeTimeoutMs = descriptor.limits.requestTimeoutSeconds * 1000;

  let session: ConsumerSession | undefined;
  let transport: BinaryTransport;
  try {
    transport = await upgrade({
      url,
      subprotocol: SUBPROTOCOL,
      headers: {
        Authorization: `Bearer ${token}`,
        [GRANT_REVISION_HEADER]: descriptor.grantRevision,
      },
      maxMessageBytes: msize,
      allowInsecureLoopback: options.allowInsecureLoopback ?? false,
      timeoutMs: handshakeTimeoutMs,
      signal: options.signal,
      handlers: {
        onMessage: (bytes) => session?.onMessage(bytes),
        onClose: (info) => session?.onClose(info),
      },
    });
  } catch (error) {
    if (error instanceof UpgradeRejected) {
      let body: unknown;
      try {
        body = JSON.parse(error.body);
      } catch {
        body = undefined;
      }
      throw new FilesystemError({
        code: discoveryCode(error.status, body),
        operation: 'upgrade',
        outcome: 'not_started',
        retryable: error.status === 429 || error.status === 503,
      });
    }
    throw error;
  }

  session = new ConsumerSession(transport, {
    msize,
    maxInflightRequests: descriptor.limits.maxInflightRequests,
    maxFids: descriptor.limits.maxFids,
    requestTimeoutMs: handshakeTimeoutMs,
  });
  try {
    await session.open({ signal: options.signal });
  } catch (error) {
    // A handshake that did not complete leaves no client, so the socket is not
    // left open behind the rejection.
    if (transport.isOpen) {
      transport.close(1002, 'handshake');
    }
    throw error;
  }
  return new RemoteFilesystem(descriptor, session, transport);
}

/** Exposed for tests and adapters that already hold a transport. */
export async function attachSession(
  descriptor: Descriptor,
  transport: BinaryTransport,
  session: ConsumerSession,
): Promise<RemoteFilesystem> {
  await session.open();
  return new RemoteFilesystem(descriptor, session, transport);
}

export type { Descriptor, Message, DirEntry };
