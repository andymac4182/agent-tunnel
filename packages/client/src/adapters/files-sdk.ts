/**
 * The Files SDK adapter: one granted export, seen as an object store.
 *
 * `files-sdk` 2.4.0's extension seam is `Adapter<Raw>`, handed to
 * `new Files({ adapter })`. This module implements it over the shared client,
 * with **type-only** imports of the upstream declarations — so `tsc` checks the
 * adapter against the installed package's own `.d.ts` (that is the contract
 * compilation [testing.md](../../../../docs/testing.md) asks for) while nothing
 * of `files-sdk` is loaded at run time and this package keeps its zero runtime
 * dependencies.
 *
 * ## The error class is injected, and that is not only about dependencies
 *
 * `FilesError` is a runtime class, and the SDK's retry gate is
 * `error.code === "Provider" && !(error.aborted || error.permanent)` over a
 * value produced by `FilesError.wrap(cause)` — which returns `cause` unchanged
 * **only** when `cause instanceof FilesError`, and otherwise builds a fresh
 * `Provider` error with `permanent` unset. An adapter that threw its own error
 * type would therefore have every failure, including an `unknown` mutation,
 * classified as retryable. So a real `FilesError` is required, `instanceof` is
 * identity-sensitive, and the honest way to get the consumer's own copy of the
 * class is to be handed it:
 *
 * ```ts
 * import { Files, FilesError } from 'files-sdk';
 * const adapter = createFilesAdapter({ remote, FilesError });
 * const files = new Files({ adapter, retries: 0 });
 * ```
 *
 * **`FilesError` must come from the same module instance as `Files`** — one
 * `import { Files, FilesError } from 'files-sdk'`, not a second installed copy.
 * This adapter **cannot check that**: a `FilesError` from another copy is a
 * perfectly good class with the right shape, and the wrapper would quietly
 * rebuild everything it produced, an `unknown` mutation included, as a
 * retryable `Provider` error. The injection moves the identity requirement to
 * the consumer; nothing here detects a violation of it at run time.
 *
 * ## `partial` and `unknown`
 *
 * `FilesError` has five codes and no outcome vocabulary. The mapping is:
 * **every** ambiguous mutation becomes a `Provider` error with
 * `permanent: true`, carrying the shared client's `FilesystemError` as `cause`,
 * where `cause.outcome` still distinguishes `partial` from `unknown`. `applied`
 * is never set: upstream it means a conditional mutation **did** commit, which
 * is a stronger claim than "may have happened" and is not ours to make.
 *
 * The distinction between `partial` and `unknown` is therefore **not
 * expressible** in Files SDK's own error shape, and this adapter does not
 * pretend otherwise: it is recoverable from `cause` and from nowhere else.
 *
 * More simply still: this adapter never produces a retryable error at all.
 * `permanent: true` is set on every `Provider` error it builds, including
 * reads and session losses, because the shared client never reconnects behind
 * the caller's back — so no second attempt through a closed client could
 * succeed, and "the adapter must also prevent retry if the application enables
 * SDK retries" becomes structural rather than a case analysis that could miss
 * one.
 */

import type {
  Adapter,
  AdapterDownloadOptions,
  Body,
  DeleteOptions,
  FilesError as FilesErrorType,
  ListOptions,
  ListResult,
  OperationOptions,
  StoredFile,
  UploadOptions,
  UploadResult,
} from 'files-sdk';

import type { RemoteFilesystem, Stat } from '../filesystem.ts';
import { FilesystemError } from '../errors.ts';
import { PathRefusal, type PathBounds } from '../paths.ts';
import { isAborted, isAmbiguous, mapBounded, summarize, withAppliedFloor } from './outcomes.ts';
import { checkPrefix, KeyRefusal, keyForPath, pathForKey } from './keys.ts';

/**
 * The consumer's own `FilesError` class.
 *
 * Declared through `ConstructorParameters` of the real one, so a change to its
 * signature in a future pin is a type error here rather than a wrong call.
 */
export type FilesErrorConstructor = new (
  ...args: ConstructorParameters<typeof FilesErrorType>
) => FilesErrorType;

export interface FilesAdapterOptions {
  /** The shared client. Borrowed, never reconfigured, and never closed by this. */
  remote: RemoteFilesystem;
  /** `FilesError`, imported from the consumer's own `files-sdk`. */
  FilesError: FilesErrorConstructor;
  /** The adapter name Files SDK reports. */
  name?: string | undefined;
  /** Page size when a caller names none. Capped at `MAX_PAGE`. */
  defaultPageSize?: number | undefined;
}

/** "Defaults: page size 100, maximum 1,000". */
export const DEFAULT_PAGE = 100;
export const MAX_PAGE = 1000;
/** "at most 16 live cursors per adapter, 60-second idle expiry". */
export const MAX_LIVE_CURSORS = 16;
export const CURSOR_IDLE_MS = 60_000;

interface Cursor {
  /** Bound to the query: a cursor is valid for its own prefix and delimiter. */
  prefix: string;
  delimiter: string | undefined;
  /** Bound to the grant: a revision change ends the session and the cursor. */
  grantRevision: string;
  /** The live, bounded traversal. Resuming is continuing it, not restarting. */
  walk: AsyncGenerator<string>;
  touchedAtMs: number;
}

/** The adapter's own view of what a list page is building. */
interface Page {
  items: string[];
  prefixes: string[];
}

/**
 * What this factory returns: the upstream interface, plus the one method the
 * upstream interface has no place for.
 *
 * "Adapter destruction releases only its own pending work, fids, cursors, and
 * references; the application calls `remote.close()` after all borrowers stop."
 * `Adapter` has no lifecycle method at all, so releasing is an extra method
 * rather than an overload of one of its own — and a `Files` instance never
 * calls it, which is the point: closing one borrower must not be able to close
 * a connection another borrower is still using.
 */
export type FilesAdapter = Adapter<RemoteFilesystem> & {
  /** Drop this adapter's live pagination cursors. Never touches the client. */
  release(): void;
};

export function createFilesAdapter(options: FilesAdapterOptions): FilesAdapter {
  const remote = options.remote;
  const Failure = options.FilesError;
  const bounds: PathBounds = {
    maxPathBytes: remote.descriptor.limits.maxPathBytes,
    maxPathComponents: remote.descriptor.limits.maxPathComponents,
  };
  const cursors = new Map<string, Cursor>();
  let nextCursor = 0;
  /**
   * How many `stat` calls a listing may have in flight.
   *
   * A quarter of the session's own tag quota, floored at one: enough to make a
   * page of a hundred keys quick, far enough below the quota that this
   * adapter's listing cannot exhaust the tags another borrower of the same
   * client is using. It is derived from the descriptor rather than fixed,
   * because negotiation may reduce the quota.
   */
  const statConcurrency = Math.max(
    1,
    Math.floor(remote.descriptor.limits.maxInflightRequests / 4),
  );

  /* ------------------------------------------------------------------ *
   * Errors
   * ------------------------------------------------------------------ */

  const provider = (message: string, cause: unknown, aborted = false): FilesErrorType =>
    // `permanent` is always true. See the module comment: this adapter emits no
    // retryable error, because nothing it could fail at would succeed on a
    // second attempt through a client that does not reconnect.
    new Failure('Provider', message, cause, { permanent: true, aborted });

  const translate = (error: unknown): FilesErrorType => {
    if (error instanceof KeyRefusal || error instanceof PathRefusal) {
      return provider(summarize(error), error);
    }
    if (!(error instanceof FilesystemError)) {
      return provider(summarize(error), error, isAborted(error));
    }
    if (isAmbiguous(error)) {
      // The one mapping this whole module exists to get right. `applied` stays
      // unset; `cause.outcome` is where `partial` and `unknown` survive.
      //
      // `aborted` is carried through even here. Nothing retries an ambiguous
      // failure either way — `canRetry` refuses on `permanent` alone, and the
      // wrapper substitutes its own abort error when the caller's signal fired
      // — but an `ABORTED` client error merged up to `partial` is still an
      // abort, and reporting `aborted: false` for one would be a field that
      // disagrees with what happened.
      return provider(summarize(error), error, isAborted(error));
    }
    switch (error.code) {
      case 'ENOENT':
        return new Failure('NotFound', summarize(error), error, { permanent: true });
      case 'EACCES':
      case 'EPERM':
        return new Failure('Unauthorized', summarize(error), error, { permanent: true });
      case 'EROFS':
        return new Failure('ReadOnly', summarize(error), error, { permanent: true });
      case 'EEXIST':
      case 'ENOTEMPTY':
      case 'EISDIR':
      case 'ENOTDIR':
        return new Failure('Conflict', summarize(error), error, { permanent: true });
      default:
        return provider(summarize(error), error, error.code === 'ABORTED');
    }
  };

  const rethrow = (error: unknown): never => {
    throw translate(error);
  };

  /**
   * Create the directories a key implies, and report whether that changed
   * anything.
   *
   * "Upload creates parent directories as needed", and `copy` and `move` need
   * the same for their destination. Each is therefore a **composite at this
   * layer**, not only inside the shared client: a directory made here and a
   * failure afterwards is a change to the export that the failing step knows
   * nothing about. The count is what decides the floor, and it comes from
   * `mkdir` itself rather than from a preliminary `stat`.
   */
  const ensureParent = async (path: string, opts: OperationOptions | undefined): Promise<boolean> => {
    const parent = path.slice(0, path.lastIndexOf('/')) || '/';
    if (parent === '/' || !remote.supports('mkdir')) {
      return false;
    }
    return (await remote.mkdir(parent, { recursive: true, ...signalOf(opts) })) > 0;
  };

  /* ------------------------------------------------------------------ *
   * Bodies
   * ------------------------------------------------------------------ */

  async function* bodyChunks(body: Body): AsyncGenerator<Uint8Array> {
    if (typeof body === 'string') {
      yield new TextEncoder().encode(body);
      return;
    }
    if (body instanceof Uint8Array) {
      yield body;
      return;
    }
    if (body instanceof ArrayBuffer) {
      yield new Uint8Array(body);
      return;
    }
    if (ArrayBuffer.isView(body)) {
      yield new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
      return;
    }
    if (body instanceof Blob) {
      yield new Uint8Array(await body.arrayBuffer());
      return;
    }
    const reader = (body as ReadableStream<Uint8Array>).getReader();
    try {
      for (;;) {
        const next = await reader.read();
        if (next.done === true) {
          return;
        }
        if (next.value !== undefined) {
          yield next.value;
        }
      }
    } finally {
      reader.releaseLock();
    }
  }

  /* ------------------------------------------------------------------ *
   * Metadata
   * ------------------------------------------------------------------ */

  const sizeOf = (stat: Stat, operation: string, key: string): number => {
    // "Sizes outside JS safe integer range fail explicitly." A `BigInt` that
    // does not fit a `number` is a file this object view cannot describe, and
    // rounding it would be a size that is not the size.
    if (stat.size > BigInt(Number.MAX_SAFE_INTEGER)) {
      throw new FilesystemError({
        code: 'EFBIG',
        operation,
        path: `/${key}`,
        outcome: 'not_started',
        retryable: false,
      });
    }
    return Number(stat.size);
  };

  /**
   * Build the `StoredFile` a `head` or a `download` answers with.
   *
   * The body accessors are lazy, which is upstream's own documented behaviour
   * for `head` ("those accessors lazily issue a full GET on first use"), and
   * each of them reads through the shared client's materialization budget — so
   * the ceiling is enforced against the **bytes that actually arrive**, not
   * against the `size` this stat observed. A file that grows under the read
   * fails rather than returning a prefix that looks whole.
   */
  const storedFile = (
    key: string,
    path: string,
    stat: Stat,
    size: number,
    range: { offset: bigint; length: number | undefined } | undefined,
  ): StoredFile => {
    const readOptions = range === undefined ? {} : { offset: range.offset, ...(range.length === undefined ? {} : { length: range.length }) };
    const bytes = async (): Promise<Uint8Array> => {
      try {
        return await remote.readFile(path, readOptions);
      } catch (error) {
        return rethrow(error);
      }
    };
    const name = key.split('/').pop() ?? key;
    return {
      name,
      key,
      size,
      // "report `application/octet-stream` unless a separately documented
      // inference policy applies". There is none, so there is one answer.
      type: 'application/octet-stream',
      lastModified: stat.modifiedAtMs,
      arrayBuffer: async () => {
        const read = await bytes();
        return read.buffer.slice(read.byteOffset, read.byteOffset + read.byteLength) as ArrayBuffer;
      },
      text: async () => new TextDecoder().decode(await bytes()),
      blob: async () => new Blob([await bytes()]),
      stream: () => {
        const iterator = remote.readStream(path, readOptions)[Symbol.asyncIterator]();
        return new ReadableStream<Uint8Array>({
          async pull(controller) {
            try {
              const next = await iterator.next();
              if (next.done === true) {
                controller.close();
                return;
              }
              controller.enqueue(next.value);
            } catch (error) {
              controller.error(translate(error));
            }
          },
          async cancel() {
            await iterator.return?.(undefined);
          },
        });
      },
      // No ETag and no user metadata: "Do not invent stored MIME metadata, HTTP
      // cache directives, custom object metadata, or strong ETags from an
      // ordinary stat." An absent `etag` is what makes every conditional
      // primitive unusable, which is the intent.
    };
  };

  /* ------------------------------------------------------------------ *
   * Listing
   * ------------------------------------------------------------------ */

  /**
   * A bounded, lazy, depth-first walk yielding regular-file keys.
   *
   * Directories are prefixes, so they are not yielded: "empty directories are
   * intentionally not object entries". The traversal entry and depth budgets
   * are the descriptor's and are enforced across the whole walk, not per
   * directory — and exceeding one **fails**, because a page that stopped
   * quietly at a budget would be a false complete page.
   */
  async function* walkKeys(prefix: string, delimiter: string | undefined): AsyncGenerator<string> {
    const limits = remote.descriptor.limits;
    let entries = 0;
    const stack: Array<{ path: string; depth: number }> = [{ path: '/', depth: 0 }];
    while (stack.length > 0) {
      const at = stack.pop() as { path: string; depth: number };
      if (at.depth > limits.maxTraversalDepth) {
        throw new FilesystemError({
          code: 'ELOOP',
          operation: 'list',
          outcome: 'not_started',
          retryable: false,
        });
      }
      const children: Array<{ name: string; kind: 'file' | 'directory' | 'symlink' }> = [];
      for await (const entry of remote.readDirectory(at.path)) {
        entries += 1;
        if (entries > limits.maxTraversalEntries) {
          throw new FilesystemError({
            code: 'EFBIG',
            operation: 'list',
            outcome: 'not_started',
            retryable: false,
          });
        }
        children.push(entry);
      }
      // Reversed, so a `pop()`-driven stack visits names in the order the
      // device listed them. There is no sort: "no stable snapshot/order
      // guarantee during host directory changes", and sorting a page would
      // imply one.
      for (let index = children.length - 1; index >= 0; index -= 1) {
        const child = children[index] as { name: string; kind: 'file' | 'directory' | 'symlink' };
        const childPath = at.path === '/' ? `/${child.name}` : `${at.path}/${child.name}`;
        const key = keyForPath(childPath);
        if (child.kind === 'directory') {
          // With a delimiter, a directory whose key already reaches past the
          // prefix is a common prefix and is **not** descended into. That is
          // the prune that makes a delimited listing bounded rather than a
          // whole-tree walk that folds at the end.
          if (delimiter !== undefined && key.length >= prefix.length && key.startsWith(prefix)) {
            yield `${key}/`;
            continue;
          }
          // Prune a subtree that cannot contain the prefix at all.
          if (!prefix.startsWith(key) && !key.startsWith(prefix)) {
            continue;
          }
          stack.push({ path: childPath, depth: at.depth + 1 });
          continue;
        }
        if (child.kind !== 'file') {
          // "Do not follow symlink entries during object enumeration or object
          // operations in the first profile." A link is not an object here.
          continue;
        }
        if (key.startsWith(prefix)) {
          yield key;
        }
      }
    }
  }

  const expireCursors = (): void => {
    const now = Date.now();
    for (const [token, cursor] of cursors) {
      if (now - cursor.touchedAtMs > CURSOR_IDLE_MS) {
        cursors.delete(token);
      }
    }
  };

  /* ------------------------------------------------------------------ *
   * The adapter
   * ------------------------------------------------------------------ */

  const adapter: FilesAdapter = {
    name: options.name ?? 'agent-tunnel',

    release(): void {
      cursors.clear();
    },

    // "may expose only the already-scoped Agent Tunnel client/session, never
    // device credentials, host directory handles, or an unconstrained
    // service-selection escape hatch". The shared client is exactly that: one
    // export, one grant, and no method that reaches another.
    raw: remote,

    supportsRange: true,
    supportsDelimiter: true,
    supportsMetadata: false,
    supportsCacheControl: false,
    supportsServerSideCopy: false,
    // "Never fabricate an HTTP URL, expose a host file URL, or embed an access
    // token in a URL."
    signedUrl: { supported: false },
    // `conditional` is absent entirely, so every compare-and-set call fails
    // before provider I/O rather than being emulated by a stat and a write.

    async upload(key: string, body: Body, opts?: Omit<UploadOptions, 'condition'>): Promise<UploadResult> {
      try {
        if (opts?.metadata !== undefined && Object.keys(opts.metadata).length > 0) {
          throw new FilesystemError({
            code: 'ENOTSUP',
            operation: 'upload:metadata',
            outcome: 'not_started',
            retryable: false,
          });
        }
        if (opts?.cacheControl !== undefined) {
          throw new FilesystemError({
            code: 'ENOTSUP',
            operation: 'upload:cacheControl',
            outcome: 'not_started',
            retryable: false,
          });
        }
        const path = pathForKey(key, bounds);
        const applied = await ensureParent(path, opts);
        let size = 0;
        const counted = async function* (): AsyncGenerator<Uint8Array> {
          for await (const chunk of bodyChunks(body)) {
            size += chunk.byteLength;
            yield chunk;
          }
        };
        try {
          await remote.writeStream(path, counted(), signalOf(opts));
        } catch (error) {
          throw withAppliedFloor(error, 'upload', path, applied);
        }
        const result: UploadResult = {
          key,
          size,
          contentType: opts?.contentType ?? 'application/octet-stream',
        };
        if (!remote.supports('stat')) {
          return result;
        }
        // **The write has been confirmed.** This `stat` is a courtesy: it fills
        // in `lastModified`, which is optional in `UploadResult` because not
        // every provider has one. A failure of it cannot fail the upload —
        // reporting a completed write as an error, and worse as an error whose
        // outcome is the stat's own `not_started`, would tell a caller the key
        // was never written when it holds exactly what was sent.
        try {
          const stat = await remote.stat(path, signalOf(opts));
          return { ...result, lastModified: stat.modifiedAtMs };
        } catch {
          return result;
        }
      } catch (error) {
        return rethrow(error);
      }
    },

    async download(key: string, opts?: AdapterDownloadOptions): Promise<StoredFile> {
      try {
        const path = pathForKey(key, bounds);
        const stat = await remote.stat(path, signalOf(opts));
        if (stat.kind !== 'file') {
          throw new FilesystemError({
            code: 'EISDIR',
            operation: 'download',
            path,
            outcome: 'not_started',
            retryable: false,
          });
        }
        const total = sizeOf(stat, 'download', key);
        if (opts?.range === undefined) {
          return storedFile(key, path, stat, total, undefined);
        }
        const { start, end } = opts.range;
        if (!Number.isInteger(start) || start < 0 || (end !== undefined && (!Number.isInteger(end) || end < start))) {
          throw new FilesystemError({
            code: 'EINVAL',
            operation: 'download:range',
            path,
            outcome: 'not_started',
            retryable: false,
          });
        }
        // Upstream's `end` is **inclusive**, deliberately unlike `slice`. The
        // shared client takes an offset and a length, so the conversion is
        // `end - start + 1` and is written once, here.
        const length = end === undefined ? undefined : end - start + 1;
        const ranged = length === undefined ? Math.max(0, total - start) : Math.min(length, Math.max(0, total - start));
        return storedFile(key, path, stat, ranged, { offset: BigInt(start), length });
      } catch (error) {
        return rethrow(error);
      }
    },

    async head(key: string, opts?: OperationOptions): Promise<StoredFile> {
      try {
        const path = pathForKey(key, bounds);
        const stat = await remote.stat(path, signalOf(opts));
        if (stat.kind !== 'file') {
          throw new FilesystemError({
            code: 'EISDIR',
            operation: 'head',
            path,
            outcome: 'not_started',
            retryable: false,
          });
        }
        return storedFile(key, path, stat, sizeOf(stat, 'head', key), undefined);
      } catch (error) {
        return rethrow(error);
      }
    },

    async exists(key: string, opts?: OperationOptions): Promise<boolean> {
      try {
        const path = pathForKey(key, bounds);
        const stat = await remote.stat(path, signalOf(opts));
        return stat.kind === 'file';
      } catch (error) {
        // "`exists` converts only **confirmed** absence into false." A denial,
        // an offline device and an invalid key all throw: reporting them as an
        // ordinary absent object would tell a caller the export does not hold
        // something it may very well hold.
        if (error instanceof FilesystemError && error.code === 'ENOENT') {
          return false;
        }
        return rethrow(error);
      }
    },

    async delete(key: string, opts?: DeleteOptions): Promise<void> {
      try {
        const path = pathForKey(key, bounds);
        const stat = await remote.stat(path, signalOf(opts));
        if (stat.kind !== 'file') {
          // "directory deletion is not an object delete". Reporting this as
          // `NotFound` would be the silent no-op the contract forbids, so it is
          // a type conflict and says so.
          throw new FilesystemError({
            code: 'EISDIR',
            operation: 'delete',
            path,
            outcome: 'not_started',
            retryable: false,
          });
        }
        await remote.remove(path, signalOf(opts));
      } catch (error) {
        rethrow(error);
      }
    },

    async copy(from: string, to: string, opts?: OperationOptions): Promise<void> {
      try {
        const source = pathForKey(from, bounds);
        const destination = pathForKey(to, bounds);
        const applied = await ensureParent(destination, opts);
        try {
          await remote.copy(source, destination, signalOf(opts));
        } catch (error) {
          throw withAppliedFloor(error, 'copy', destination, applied);
        }
      } catch (error) {
        rethrow(error);
      }
    },

    /**
     * Implemented **explicitly**, because upstream otherwise composes `copy`
     * then `delete` — which for this endpoint would replace one native rename
     * with a read, a write and an unlink, and would leave a duplicate behind on
     * a failure between them.
     */
    async move(from: string, to: string, opts?: OperationOptions): Promise<void> {
      try {
        const source = pathForKey(from, bounds);
        const destination = pathForKey(to, bounds);
        const applied = await ensureParent(destination, opts);
        try {
          await remote.rename(source, destination, signalOf(opts));
        } catch (error) {
          throw withAppliedFloor(error, 'move', destination, applied);
        }
      } catch (error) {
        rethrow(error);
      }
    },

    async list(opts?: ListOptions): Promise<ListResult> {
      try {
        expireCursors();
        const prefix = opts?.prefix ?? '';
        const delimiter = opts?.delimiter;
        if (delimiter !== undefined && delimiter !== '/') {
          // "Accept `/` delimiter only; report unsupported nonempty
          // delimiters." Advertising `supportsDelimiter` means upstream will
          // not gate this, so the refusal has to happen here.
          throw new FilesystemError({
            code: 'ENOTSUP',
            operation: 'list:delimiter',
            outcome: 'not_started',
            retryable: false,
          });
        }
        checkPrefix(prefix, bounds);
        const limit = Math.min(opts?.limit ?? options.defaultPageSize ?? DEFAULT_PAGE, MAX_PAGE);
        if (!Number.isInteger(limit) || limit <= 0) {
          throw new FilesystemError({
            code: 'EINVAL',
            operation: 'list:limit',
            outcome: 'not_started',
            retryable: false,
          });
        }

        let token = opts?.cursor;
        let cursor: Cursor;
        if (token === undefined) {
          cursor = {
            prefix,
            delimiter,
            grantRevision: remote.descriptor.grantRevision,
            walk: walkKeys(prefix, delimiter),
            touchedAtMs: Date.now(),
          };
        } else {
          const live = cursors.get(token);
          if (live === undefined) {
            // "Reject expired/wrong-session/wrong-query cursors; never silently
            // restart pagination." Starting again here would return page one
            // as though it were page four.
            throw new FilesystemError({
              code: 'EINVAL',
              operation: 'list:cursor',
              outcome: 'not_started',
              retryable: false,
            });
          }
          if (
            live.prefix !== prefix ||
            live.delimiter !== delimiter ||
            live.grantRevision !== remote.descriptor.grantRevision
          ) {
            cursors.delete(token);
            throw new FilesystemError({
              code: 'EINVAL',
              operation: 'list:cursor-query',
              outcome: 'not_started',
              retryable: false,
            });
          }
          cursor = live;
          cursors.delete(token);
        }

        const page: Page = { items: [], prefixes: [] };
        let exhausted = false;
        while (page.items.length + page.prefixes.length < limit) {
          const next = await cursor.walk.next();
          if (next.done === true) {
            exhausted = true;
            break;
          }
          const key = next.value;
          if (key.endsWith('/')) {
            if (!page.prefixes.includes(key)) {
              page.prefixes.push(key);
            }
            continue;
          }
          page.items.push(key);
        }

        // **Bounded, not `Promise.all`.** Each `stat` is a walk, a getattr and
        // a clunk, and the session refuses a request beyond
        // `maxInflightRequests` locally with `RESOURCE_EXHAUSTED` — the profile
        // pins that at 64. A page of 100 fanned out at once therefore could not
        // be produced at all on a directory with more than that many keys, and
        // the default page size would have been a number this adapter can never
        // fulfil. The pool is a quarter of the quota so that a second borrower
        // of the same client is not starved by one listing.
        const items = await mapBounded(page.items, statConcurrency, async (key) => {
          const path = `/${key}`;
          const stat = await remote.stat(path, signalOf(opts));
          return storedFile(key, path, stat, sizeOf(stat, 'list', key), undefined);
        });

        if (exhausted) {
          return delimiter === undefined || page.prefixes.length === 0
            ? { items }
            : { items, prefixes: page.prefixes };
        }
        if (cursors.size >= MAX_LIVE_CURSORS) {
          throw new FilesystemError({
            code: 'EINVAL',
            operation: 'list:cursors',
            outcome: 'not_started',
            retryable: false,
          });
        }
        nextCursor += 1;
        // Opaque, session-local and unguessable enough not to be a handle a
        // caller can construct; it is a key into this adapter's own map, so it
        // is meaningless to any other adapter, principal or session by
        // construction rather than by a check.
        token = `${nextCursor}-${cryptoToken()}`;
        cursor.touchedAtMs = Date.now();
        cursors.set(token, cursor);
        return delimiter === undefined || page.prefixes.length === 0
          ? { items, cursor: token }
          : { items, prefixes: page.prefixes, cursor: token };
      } catch (error) {
        return rethrow(error);
      }
    },

    /**
     * Required by the interface and permanently unsupported here.
     *
     * "The raw WebSocket endpoint cannot serve an image/PDF attachment to an
     * arbitrary model HTTP fetcher", and there is no URL this could return that
     * would not be either a lie or a credential.
     */
    async url(): Promise<string> {
      throw provider('ENOTSUP (url)', undefined);
    },

    async signedUploadUrl(): Promise<never> {
      throw provider('ENOTSUP (signedUploadUrl)', undefined);
    },
  };

  return adapter;
}

function signalOf(opts: OperationOptions | undefined): { signal?: AbortSignal } {
  return opts?.signal === undefined ? {} : { signal: opts.signal };
}

function cryptoToken(): string {
  const bytes = new Uint8Array(12);
  globalThis.crypto.getRandomValues(bytes);
  return Array.from(bytes, (byte) => byte.toString(16).padStart(2, '0')).join('');
}
