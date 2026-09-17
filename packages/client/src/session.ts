/**
 * The consumer's side of the 9P session: lifecycle, tags, fids, flush, the
 * close codes, and the outcome an in-flight request is classified with.
 *
 * The device's state machine is `crates/tunnel-fs-ninep`'s `Session`. This is
 * the other end of the same rules, and it is **not** a port of it: it tracks
 * what a client must track to keep its own promises — which tag is outstanding,
 * which fid it has bound, how far a mutation got — where the device's tracks
 * what a server must enforce.
 *
 * # The obligation gate 5 named for this side
 *
 * "There is no wire field for an outcome: the shared client is what classifies
 * an in-flight mutation from its own dispatch and reply history, and that is
 * gate 6's." [`classifyOutcome`] is that classification, and
 * [`isMutatingRequest`] is the input it turns on — the same split gate 5 pins
 * with `Primitive::is_mutating`, including that a `Tlopen` which only opens for
 * writing carries no effect while one that truncates does.
 */

import {
  constants as C,
  decodeExact,
  encode,
  negotiateMsize,
  negotiateVersion,
  NinepError,
} from './ninep/codec.ts';
import type { Message, MessageOf, Qid } from './ninep/messages.ts';
import {
  ERRNO_TO_CODE,
  FilesystemError,
  mergeOutcome,
  sessionCodeForClose,
  sessionCodeRetryable,
  type Outcome,
  type SessionErrorCode,
} from './errors.ts';
import type { BinaryTransport, CloseInfo } from './websocket.ts';

export type Lifecycle = 'connecting' | 'ready' | 'closed';

/** The fid a `Tattach` binds. Fid 0 is the root for the life of the session. */
export const ROOT_FID = 0;

export interface SessionLimits {
  msize: number;
  maxInflightRequests: number;
  maxFids: number;
  /** The per-request deadline, in milliseconds. Zero disables it. */
  requestTimeoutMs: number;
}

/**
 * What a client knows about one request it sent.
 *
 * `dispatched` is the whole point: it is set when the bytes reach the
 * transport, because that is the last moment at which this side can still say
 * "nothing can have happened". Everything after it is ambiguous, and the
 * ambiguity is what `unknown` names.
 */
interface Outstanding {
  tag: number;
  request: Message;
  mutating: boolean;
  dispatched: boolean;
  /** Bytes a reply has confirmed, for a `Twrite`. A lower bound, never a total. */
  bytesAcknowledged: number;
  /** Flushes outstanding against this tag, by their own tags. */
  flushedBy: Set<number>;
  resolve: (message: Message) => void;
  reject: (error: FilesystemError) => void;
  timer: ReturnType<typeof setTimeout> | undefined;
}

/**
 * Which requests can have changed something.
 *
 * `Tlopen` splits on its flags, which is gate 5's own distinction: opening a
 * file for writing changes nothing, so a failure after it is still
 * `not_started`, where a failure after a truncation is not. Getting this wrong
 * in the safe direction costs a caller a spurious `unknown`; getting it wrong
 * in the other direction tells a caller nothing happened when something did.
 */
export function isMutatingRequest(message: Message): boolean {
  switch (message.kind) {
    case 'Tlcreate':
    case 'Twrite':
    case 'Tmkdir':
    case 'Tunlinkat':
    case 'Tremove':
    case 'Trename':
    case 'Trenameat':
    case 'Tsetattr':
    case 'Tsymlink':
    case 'Tlink':
      return true;
    case 'Tlopen':
      return (message.flags & C.O_TRUNC) !== 0;
    default:
      return false;
  }
}

/**
 * The outcome of a request that ended without its reply.
 *
 * | What this side knows | Outcome |
 * | --- | --- |
 * | The bytes never reached the transport | `not_started` |
 * | It was dispatched and mutates nothing | `failed` |
 * | It was dispatched, mutates, and no reply arrived | `unknown` |
 * | A reply had already acknowledged some bytes | `partial`, merged |
 *
 * The third row is the one that matters and it is deliberately conservative: a
 * dispatched mutation whose reply never came **may** have been performed, the
 * device's own ledger says so on its side, and no close code can tell this side
 * which. Reporting `failed` would invite a retry onto a mutation that already
 * applied.
 */
export function classifyOutcome(record: {
  mutating: boolean;
  dispatched: boolean;
  bytesAcknowledged: number;
}): Outcome {
  if (!record.dispatched) {
    return 'not_started';
  }
  const base: Outcome = record.mutating ? 'unknown' : 'failed';
  return record.bytesAcknowledged > 0 ? mergeOutcome(base, 'partial') : base;
}

/** The reply type each request expects. An `Rlerror` is always permitted too. */
const REPLY_OF: Record<string, string> = {
  Tversion: 'Rversion',
  Tattach: 'Rattach',
  Tflush: 'Rflush',
  Twalk: 'Rwalk',
  Tlopen: 'Rlopen',
  Tlcreate: 'Rlcreate',
  Tsymlink: 'Rsymlink',
  Treadlink: 'Rreadlink',
  Tgetattr: 'Rgetattr',
  Tsetattr: 'Rsetattr',
  Treaddir: 'Rreaddir',
  Tlink: 'Rlink',
  Tmkdir: 'Rmkdir',
  Trename: 'Rrename',
  Trenameat: 'Rrenameat',
  Tunlinkat: 'Runlinkat',
  Tread: 'Rread',
  Twrite: 'Rwrite',
  Tclunk: 'Rclunk',
  Tremove: 'Rremove',
};

export class ConsumerSession {
  private lifecycle: Lifecycle = 'connecting';
  private readonly outstanding = new Map<number, Outstanding>();
  /** Tags taken, including those held only until a flush is answered. */
  private readonly heldTags = new Set<number>();
  /** Flushes outstanding against a tag, by victim. The tag is held until empty. */
  private readonly flushesAgainst = new Map<number, Set<number>>();
  private nextTag = 0;
  private readonly freeFids: number[] = [];
  private nextFid = ROOT_FID + 1;
  private liveFids = 0;
  private versionSent = false;
  private attachSent = false;
  private closeInfo: CloseInfo | undefined;
  private negotiated: number;
  /** Set when the session ends, so a later call fails with the same reason. */
  private endReason: { code: SessionErrorCode; closeCode: number | undefined } | undefined;

  private readonly transport: BinaryTransport;
  private readonly limits: SessionLimits;

  constructor(transport: BinaryTransport, limits: SessionLimits) {
    this.transport = transport;
    this.limits = limits;
    this.negotiated = limits.msize;
  }

  get state(): Lifecycle {
    return this.lifecycle;
  }

  get msize(): number {
    return this.negotiated;
  }

  /** Outstanding requests, for the tests that check the quota is real. */
  get inflight(): number {
    return this.outstanding.size;
  }

  /** Tags held, including those waiting only on a flush reply. */
  get tagsHeld(): number {
    return this.heldTags.size;
  }

  get openFids(): number {
    return this.liveFids;
  }

  /** One complete binary message arrived. */
  onMessage(bytes: Uint8Array): void {
    let message: Message;
    try {
      // The consumer rule: exactly one complete 9P message per binary message.
      // `decodeExact` is what refuses two packed into one and half of one.
      message = decodeExact(bytes, { msize: this.negotiated });
    } catch (error) {
      if (error instanceof NinepError) {
        // Every framing failure closes 1002 and is never answered: the tag that
        // would correlate a reply is part of the frame that failed to decode.
        this.failSession('PROTOCOL_VIOLATION', 1002, `framing:${error.reason}`);
        return;
      }
      throw error;
    }
    this.apply(message);
  }

  /** The transport closed. */
  onClose(info: CloseInfo): void {
    this.closeInfo = info;
    const code = info.local && info.code === 1000 ? 'SESSION_LOST' : sessionCodeForClose(info.code);
    this.failSession(code, info.code, 'close');
  }

  private apply(message: Message): void {
    const tag = message.tag;
    const record = this.outstanding.get(tag);
    if (record === undefined) {
      if (this.heldTags.has(tag)) {
        // A tag held only until its flush is answered: the original reply beat
        // the `Rflush`, which 9P explicitly permits. Honour it by dropping it,
        // not by closing — "respect a normal reply arriving before `Rflush`".
        //
        // If nothing is still waiting to flush it, this reply is the last word
        // on that tag and the number is released here. Without that, a tag
        // whose flush could never be sent — the quota was full — stayed held
        // for the life of the session, one slot lost per occurrence.
        if ((this.flushesAgainst.get(tag)?.size ?? 0) === 0) {
          this.flushesAgainst.delete(tag);
          this.heldTags.delete(tag);
        }
        return;
      }
      this.failSession('PROTOCOL_VIOLATION', 1002, 'reply-for-unknown-tag');
      return;
    }
    if (message.kind !== 'Rlerror') {
      const expected = REPLY_OF[record.request.kind];
      if (expected !== message.kind) {
        this.failSession('PROTOCOL_VIOLATION', 1002, 'reply-type-mismatch');
        return;
      }
      const boundsError = this.checkReplyBounds(record.request, message);
      if (boundsError !== undefined) {
        this.failSession('PROTOCOL_VIOLATION', 1002, boundsError);
        return;
      }
    }
    this.retire(record);
    if (message.kind === 'Rlerror') {
      const code = ERRNO_TO_CODE.get(message.ecode);
      record.reject(
        new FilesystemError({
          code: code ?? 'EINVAL',
          operation: record.request.kind,
          // An `Rlerror` is a reply, so the request reached the device and the
          // device answered it: `failed` rather than `unknown`.
          //
          // **`failed` here is the wire's floor, not the device's ledger.**
          // Gate 5 records that some `Rlerror`s the device sends are `unknown`
          // on its side — a `Tmkdir`, `Tsymlink`, `Tlcreate` or truncating open
          // whose post-effect identity read failed, where the node exists and
          // the reply says only that something went wrong — and that a
          // composite `Tsetattr` whose later field failed is `partial`. Nothing
          // on the wire carries that distinction, so a consumer cannot recover
          // it and must not invent it. A caller that needs the device's own
          // verdict reads `ConnectionStatus::fs` on the device; a caller that
          // has only this error treats `failed` on a mutation as "at least this
          // much", and never as proof that nothing applied.
          outcome: record.mutating ? 'failed' : 'not_started',
          retryable: false,
        }),
      );
      return;
    }
    record.resolve(message);
  }

  /**
   * A reply is checked against its own request's bounds.
   *
   * Three of the rules `crates/tunnel-fs-ninep` applies in the other direction:
   * an `Rread` may not carry more than the `count` asked for, an `Rwrite` may
   * not acknowledge more than the `Twrite` carried, and a zero-qid `Rwalk` for
   * a non-empty `Twalk` is not a successful clone. A short read or a short
   * write stays ordinary.
   *
   * **`Rreaddir` is deliberately not in that list**, and the comment here used
   * to claim it was. Its `count[4]` bounds the packed block, which the codec
   * has already consumed into entries by the time this runs, and the block's
   * own byte length is not retained; the framing bound that does apply to it —
   * `count` leaving room for its own reply inside `msize` — is enforced in the
   * codec for both directions.
   */
  private checkReplyBounds(request: Message, reply: Message): string | undefined {
    if (reply.kind === 'Rread' && request.kind === 'Tread') {
      return reply.data.byteLength > request.count ? 'rread-above-count' : undefined;
    }
    if (reply.kind === 'Rwrite' && request.kind === 'Twrite') {
      return reply.count > request.data.byteLength ? 'rwrite-above-twrite' : undefined;
    }
    if (reply.kind === 'Rwalk' && request.kind === 'Twalk') {
      if (reply.wqids.length > request.wnames.length) {
        return 'rwalk-longer-than-twalk';
      }
      if (request.wnames.length > 0 && reply.wqids.length === 0) {
        return 'rwalk-zero-qids';
      }
    }
    return undefined;
  }

  private retire(record: Outstanding): void {
    if (record.timer !== undefined) {
      clearTimeout(record.timer);
    }
    this.outstanding.delete(record.tag);
    if (record.flushedBy.size === 0 && (this.flushesAgainst.get(record.tag)?.size ?? 0) === 0) {
      // A tag is released only when nothing is still waiting to flush it.
      this.heldTags.delete(record.tag);
    }
  }

  private allocateTag(): number {
    if (this.heldTags.size >= this.limits.maxInflightRequests) {
      // Refused here rather than sent. The device answers a request beyond the
      // tag quota by closing 1013, because there is no tag left to carry an
      // `Rlerror` — so a client that sent one would lose the whole session over
      // its own accounting.
      throw new FilesystemError({
        code: 'RESOURCE_EXHAUSTED',
        operation: 'session:tags',
        outcome: 'not_started',
        retryable: true,
      });
    }
    for (let attempt = 0; attempt <= 0xffff; attempt += 1) {
      const candidate = this.nextTag;
      this.nextTag = (this.nextTag + 1) % C.NOTAG; // NOTAG is reserved.
      if (!this.heldTags.has(candidate)) {
        this.heldTags.add(candidate);
        return candidate;
      }
    }
    throw new FilesystemError({
      code: 'RESOURCE_EXHAUSTED',
      operation: 'session:tags',
      outcome: 'not_started',
      retryable: true,
    });
  }

  /** Take a fid number. Bound only when its reply arrives. */
  allocateFid(): number {
    if (this.liveFids >= this.limits.maxFids) {
      throw new FilesystemError({
        code: 'RESOURCE_EXHAUSTED',
        operation: 'session:fids',
        outcome: 'not_started',
        retryable: true,
      });
    }
    this.liveFids += 1;
    const reused = this.freeFids.pop();
    if (reused !== undefined) {
      return reused;
    }
    const fid = this.nextFid;
    this.nextFid += 1;
    return fid;
  }

  /** Give a fid number back after it has been clunked or its walk failed. */
  releaseFid(fid: number): void {
    if (fid === ROOT_FID) {
      return;
    }
    this.liveFids = Math.max(0, this.liveFids - 1);
    this.freeFids.push(fid);
  }

  /**
   * The version handshake and the attach, in that order and once each.
   *
   * Both steps are bounded. The `Tversion` occupies no tag slot, and an earlier
   * round used that to skip the request timer for it as well — so a peer that
   * answered the HTTP 101 and then said nothing left `connectFilesystem`
   * hanging with no deadline anywhere in the path. The contract requires an
   * `AbortSignal` **plus** a bounded deadline on every network operation, and a
   * handshake is one.
   */
  async open(options: { signal?: AbortSignal | undefined } = {}): Promise<Qid> {
    if (this.versionSent || this.attachSent) {
      throw new FilesystemError({
        code: 'PROTOCOL_VIOLATION',
        operation: 'session:open',
        outcome: 'not_started',
        retryable: false,
      });
    }
    if (options.signal?.aborted === true) {
      throw new FilesystemError({
        code: 'ABORTED',
        operation: 'session:open',
        outcome: 'not_started',
        retryable: false,
      });
    }
    const onAbort = (): void => {
      // `Aborted` maps to no close code, so the socket is closed normally; what
      // matters is that the pending handshake is answered rather than left.
      this.failSession('ABORTED', undefined, 'connect-aborted');
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });
    try {
      return await this.handshake();
    } finally {
      options.signal?.removeEventListener('abort', onAbort);
    }
  }

  private async handshake(): Promise<Qid> {
    this.versionSent = true;
    const reply = await this.sendRaw(
      {
        kind: 'Tversion',
        tag: C.NOTAG,
        msize: this.limits.msize,
        version: C.VERSION,
      },
      C.NOTAG,
    );
    if (reply.kind !== 'Rversion') {
      this.failSession('PROTOCOL_VIOLATION', 1002, 'version-reply');
      throw this.endError('session:open');
    }
    // Negotiation reduces only, and the dialect was already chosen by the
    // subprotocol: a server naming another one ignored the handshake.
    //
    // **An `Rversion` above this side's offer is refused, not reduced.** 9P
    // requires the server's value to be at most the client's, so a larger one
    // is a peer that did not negotiate; clamping it silently would leave this
    // side and that peer disagreeing about the frame bound until the first
    // over-size message closed the session with 1002 in the middle of somebody's
    // read. Refusing at the handshake puts the failure where it belongs.
    if (reply.msize > this.limits.msize) {
      this.failSession('PROTOCOL_VIOLATION', 1002, 'rversion-above-offer');
      throw this.endError('session:open');
    }
    try {
      negotiateVersion(reply.version);
      this.negotiated = negotiateMsize(reply.msize, this.limits.msize);
    } catch {
      this.failSession('PROTOCOL_VIOLATION', 1002, 'version-negotiation');
      throw this.endError('session:open');
    }
    this.attachSent = true;
    const attached = await this.request({
      kind: 'Tattach',
      tag: 0,
      fid: ROOT_FID,
      afid: C.NOFID,
      uname: '',
      aname: '',
      nUname: C.NONUNAME,
    });
    if (attached.kind !== 'Rattach') {
      this.failSession('PROTOCOL_VIOLATION', 1002, 'attach-reply');
      throw this.endError('session:open');
    }
    this.lifecycle = 'ready';
    return attached.qid;
  }

  /**
   * Send one request and await its reply.
   *
   * An `AbortSignal` cancels by flushing the tag, which is 9P's cancellation
   * and not a rollback. A signal already aborted refuses before anything is
   * sent, which is the only case in which cancellation can promise that
   * nothing happened.
   */
  request<K extends Message['kind']>(
    message: MessageOf<K>,
    options: { signal?: AbortSignal | undefined } = {},
  ): Promise<Message> {
    if (this.lifecycle === 'closed') {
      return Promise.reject(this.endError(message.kind));
    }
    if (options.signal?.aborted === true) {
      return Promise.reject(
        new FilesystemError({
          code: 'ABORTED',
          operation: message.kind,
          outcome: 'not_started',
          retryable: false,
        }),
      );
    }
    let tag: number;
    try {
      tag = this.allocateTag();
    } catch (error) {
      return Promise.reject(error as FilesystemError);
    }
    const sent = this.sendRaw({ ...message, tag } as Message, tag);
    const signal = options.signal;
    if (signal !== undefined) {
      const onAbort = (): void => {
        void this.abort(tag);
      };
      signal.addEventListener('abort', onAbort, { once: true });
      return sent.finally(() => {
        signal.removeEventListener('abort', onAbort);
      });
    }
    return sent;
  }

  private sendRaw(message: Message, tag: number): Promise<Message> {
    const mutating = isMutatingRequest(message);
    return new Promise<Message>((resolve, reject) => {
      const record: Outstanding = {
        tag,
        request: message,
        mutating,
        dispatched: false,
        bytesAcknowledged: 0,
        flushedBy: new Set(),
        resolve,
        reject,
        timer: undefined,
      };
      if (tag !== C.NOTAG) {
        this.outstanding.set(tag, record);
      } else {
        // The version handshake occupies no tag slot, but it is still tracked
        // so that a session lost during it fails rather than hanging.
        this.outstanding.set(tag, record);
        this.heldTags.delete(tag);
      }
      let bytes: Uint8Array;
      try {
        bytes = encode(message, { msize: this.negotiated });
      } catch (error) {
        this.retire(record);
        this.heldTags.delete(tag);
        reject(
          new FilesystemError({
            code: error instanceof NinepError && error.reason === 'CountAboveMsize' ? 'EFBIG' : 'EINVAL',
            operation: message.kind,
            // Nothing left this process, so nothing can have happened.
            outcome: 'not_started',
            retryable: false,
          }),
        );
        return;
      }
      try {
        this.transport.send(bytes);
      } catch {
        this.retire(record);
        reject(
          new FilesystemError({
            code: 'SESSION_LOST',
            operation: message.kind,
            outcome: 'not_started',
            retryable: false,
          }),
        );
        return;
      }
      // The bytes are on the transport. From here nothing this side observes
      // can prove the request did not happen.
      record.dispatched = true;
      if (this.limits.requestTimeoutMs > 0) {
        // `NOTAG` included: the version handshake is a network operation like
        // any other, and it is the one a silent peer holds open for ever.
        record.timer = setTimeout(() => {
          this.expire(record);
        }, this.limits.requestTimeoutMs);
        record.timer.unref?.();
      }
    });
  }

  /**
   * A request deadline elapsed.
   *
   * The session is **not** closed: one operation's deadline is not the
   * session's, and the other outstanding tags on the same connection continue.
   * The tag is flushed, which is 9P's own cancellation, and is held until that
   * flush is answered.
   */
  private expire(record: Outstanding): void {
    if (!this.outstanding.has(record.tag)) {
      return;
    }
    if (record.tag === C.NOTAG) {
      // The version handshake cannot be flushed — `Tflush` names a tag, and
      // `NOTAG` is not one — and a peer that will not answer `Tversion` has no
      // session to preserve. `DEADLINE_EXCEEDED` closes 1011.
      this.failSession('DEADLINE_EXCEEDED', 1011, 'version-deadline');
      return;
    }
    this.retire(record);
    // The tag stays held until the flush this deadline sends is answered: a
    // reply for it may still arrive, and a re-issue on that number would then
    // collect the wrong one.
    this.heldTags.add(record.tag);
    void this.flush(record.tag);
    record.reject(
      new FilesystemError({
        code: 'DEADLINE_EXCEEDED',
        operation: record.request.kind,
        outcome: classifyOutcome(record),
        retryable: false,
        bytesAcknowledged: record.mutating ? record.bytesAcknowledged : undefined,
      }),
    );
  }

  /**
   * Cancel one outstanding request.
   *
   * The request is **not** rejected here. 9P permits the original reply to
   * arrive before the `Rflush`, and the contract says to respect it: a read
   * that completed before the cancellation reached the device really did
   * complete, and answering the caller "aborted" would throw away a result the
   * device performed. The rejection happens when the `Rflush` comes back and
   * the request is still outstanding.
   *
   * "`Tflush` is cancellation, not rollback", and "cancellation after dispatch
   * never promises no side effect" — so that rejection carries the outcome
   * this side can justify, which for a dispatched mutation is `unknown`.
   */
  async abort(tag: number): Promise<void> {
    if (!this.outstanding.has(tag)) {
      return;
    }
    await this.flush(tag);
  }

  /**
   * `Tflush`, with the victim's tag held until its **last** flush is answered.
   *
   * Several flushes of one request are legal, and releasing the tag on the
   * first would let the client re-issue on that number and then let the second
   * `Rflush` silently cancel the new request. That is the defect gate 3
   * recorded on the device side; the rule is the same here.
   */
  private async flush(victim: number): Promise<void> {
    let flushTag: number;
    try {
      flushTag = this.allocateTag();
    } catch {
      // No tag to flush with, because the quota is full. The victim's tag stays
      // held rather than being reused — reusing it would let a late reply for
      // the old request land on a new one — and it is released when that late
      // reply arrives, or when the session ends. It is **not** held for ever,
      // which is what an earlier round did.
      return;
    }
    const flushes = this.flushesAgainst.get(victim) ?? new Set<number>();
    flushes.add(flushTag);
    this.flushesAgainst.set(victim, flushes);
    this.outstanding.get(victim)?.flushedBy.add(flushTag);
    try {
      await this.sendRaw({ kind: 'Tflush', tag: flushTag, oldtag: victim }, flushTag);
    } catch {
      // The flush itself failed — the session ended under it, or the frame was
      // refused. `failSession` has answered every caller either way, but this
      // flush is no longer outstanding and must leave both records: a stale
      // entry in the victim's set keeps its tag reserved and blocks the release
      // above, which is the same leak by another route.
      flushes.delete(flushTag);
      this.outstanding.get(victim)?.flushedBy.delete(flushTag);
      if (flushes.size === 0) {
        this.flushesAgainst.delete(victim);
      }
      return;
    }
    flushes.delete(flushTag);
    const victimRecord = this.outstanding.get(victim);
    if (victimRecord !== undefined) {
      victimRecord.flushedBy.delete(flushTag);
      if (victimRecord.flushedBy.size > 0) {
        return;
      }
      this.retire(victimRecord);
      this.flushesAgainst.delete(victim);
      victimRecord.reject(
        new FilesystemError({
          code: 'ABORTED',
          operation: victimRecord.request.kind,
          outcome: classifyOutcome(victimRecord),
          retryable: false,
          bytesAcknowledged: victimRecord.mutating ? victimRecord.bytesAcknowledged : undefined,
        }),
      );
      return;
    }
    // The victim was already answered — either by its own reply arriving
    // first, or by a deadline. Its tag is released once the last flush against
    // it has been answered, and not before.
    if (flushes.size === 0) {
      this.flushesAgainst.delete(victim);
      this.heldTags.delete(victim);
    }
  }

  /** Record bytes a reply confirmed, so a later failure can say `partial`. */
  noteAcknowledged(tag: number, bytes: number): void {
    const record = this.outstanding.get(tag);
    if (record !== undefined) {
      record.bytesAcknowledged += bytes;
    }
  }

  /** End the session, answering every outstanding caller with its own outcome. */
  private failSession(code: SessionErrorCode, closeCode: number | undefined, detail: string): void {
    if (this.lifecycle === 'closed') {
      return;
    }
    this.lifecycle = 'closed';
    this.endReason = { code, closeCode };
    const records = [...this.outstanding.values()];
    this.outstanding.clear();
    this.heldTags.clear();
    this.flushesAgainst.clear();
    for (const record of records) {
      if (record.timer !== undefined) {
        clearTimeout(record.timer);
      }
      record.reject(
        new FilesystemError({
          code,
          operation: `${record.request.kind}:${detail}`,
          // The classification, per request, from this side's own dispatch and
          // reply history. A close code cannot say this: the same 1008 ends a
          // session with nothing in flight and one with a half-written file.
          outcome: classifyOutcome(record),
          retryable: sessionCodeRetryable(code),
          bytesAcknowledged: record.mutating ? record.bytesAcknowledged : undefined,
          closeCode,
        }),
      );
    }
    if (this.transport.isOpen) {
      this.transport.close(closeCode ?? 1000, detail);
    }
  }

  private endError(operation: string): FilesystemError {
    const reason = this.endReason ?? { code: 'SESSION_LOST' as const, closeCode: undefined };
    return new FilesystemError({
      code: reason.code,
      operation,
      outcome: 'not_started',
      retryable: sessionCodeRetryable(reason.code),
      closeCode: reason.closeCode,
    });
  }

  /** The close the peer sent, once it has. */
  get closedWith(): CloseInfo | undefined {
    return this.closeInfo;
  }

  /**
   * Close gracefully: cancel what is pending, then close the socket.
   *
   * A closed session is not reusable and never reconnects behind the caller's
   * back, which is the contract's own rule and the reason there is no `reopen`.
   */
  close(): void {
    this.failSession('SESSION_LOST', 1000, 'client-close');
  }
}
